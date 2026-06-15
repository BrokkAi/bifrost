//! Whole-workspace inverted edge builder for C#.
//!
//! Walks each file once and resolves every reference to the callee fqn it names,
//! via the shared [`build_edges`] driver. Like Java, C# references resolve
//! through type-name resolution ([`CSharpAnalyzer::resolve_visible_type`], which
//! honors `using` directives and the file's namespace) plus a
//! [`LocalInferenceEngine`] seeded with every local/parameter's declared type so
//! a member access's receiver can be typed:
//!
//! - a type reference (`Foo x`, `new Foo()`, `List<Foo>`) resolves to the type;
//! - `recv.Member(..)` resolves `recv`'s type to `Owner`, giving `Owner.Member`;
//! - `Type.Member(..)` (static) resolves the type directly;
//! - a bare `Member(..)` attributes to the enclosing class.
//!
//! The enclosing class is taken from a per-file class-range index (the analyzer's
//! own fqns), so unqualified calls attribute to the right class without
//! re-deriving the namespace. Receivers needing return-type inference (method
//! chains) are an unhandled recall gap, not a wrong edge.

use super::extractor::{is_declaration_name, member_access_name, member_access_receiver};
use super::resolver::{
    first_type_child, is_type_reference_node, node_text, normalize_type_text, reference_type_text,
    resolve_csharp_analyzer,
};
use crate::analyzer::usages::inverted_edges::{
    ClassRangeIndex, EdgeCollector, UsageEdges, build_edges, first_precise,
};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::{CSharpAnalyzer, IAnalyzer, Language, ProjectFile};
use crate::hash::{HashMap, HashSet};
use crate::text_utils::compute_line_starts;
use rayon::prelude::*;
use tree_sitter::{Node, Parser, Tree};

/// A C# file parsed once for the inverted scan: source, tree, and line starts.
struct ParsedFile {
    source: String,
    tree: Tree,
    line_starts: Vec<usize>,
}

/// Build the whole C# `caller -> callee` edge set in a single inverted pass over
/// the workspace. Returns `None` when there are no C# files. `nodes`/`keep_file`
/// mirror the Go builder.
pub(crate) fn build_csharp_usage_edges<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdges>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let csharp = resolve_csharp_analyzer(analyzer)?;
    let files: Vec<ProjectFile> = analyzer
        .project()
        .analyzable_files(Language::CSharp)
        .ok()?
        .into_iter()
        .collect();
    let parsed: HashMap<ProjectFile, ParsedFile> = files
        .par_iter()
        .filter(|file| keep_file(file))
        .filter_map(|file| {
            let source = file.read_to_string().ok()?;
            if source.is_empty() {
                return None;
            }
            let mut parser = Parser::new();
            parser
                .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
                .ok()?;
            let tree = parser.parse(source.as_str(), None)?;
            let line_starts = compute_line_starts(&source);
            Some((
                file.clone(),
                ParsedFile {
                    source,
                    tree,
                    line_starts,
                },
            ))
        })
        .collect();

    Some(build_edges(
        analyzer,
        &files,
        nodes,
        keep_file,
        |file| parsed.get(file).map(|parsed| parsed.line_starts.as_slice()),
        |file, collector| {
            let Some(parsed) = parsed.get(file) else {
                return;
            };
            let mut ctx = CsScan {
                csharp,
                file,
                source: parsed.source.as_str(),
                class_ranges: ClassRangeIndex::build(analyzer, file),
                collector,
            };
            let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
            walk(parsed.tree.root_node(), &mut ctx, &mut bindings);
        },
    ))
}

struct CsScan<'a, 'b> {
    csharp: &'a CSharpAnalyzer,
    file: &'a ProjectFile,
    source: &'a str,
    class_ranges: ClassRangeIndex,
    collector: &'a mut EdgeCollector<'b>,
}

impl CsScan<'_, '_> {
    /// Resolve a type reference's text to its fqn via the file's visible types.
    fn resolve_type_fqn(&self, text: &str) -> Option<String> {
        let normalized = normalize_type_text(text);
        if normalized.is_empty() {
            return None;
        }
        self.csharp
            .resolve_visible_type(self.file, &normalized)
            .map(|unit| unit.fq_name())
    }

    /// The fqn of the smallest class declaration containing `byte`.
    fn enclosing_class(&self, byte: usize) -> Option<&str> {
        self.class_ranges.enclosing(byte)
    }

    fn record(&mut self, callee: String, node: Node<'_>) {
        self.collector
            .record(callee, node.start_byte(), node.end_byte());
    }
}

const SCOPE_NODES: &[&str] = &[
    "method_declaration",
    "constructor_declaration",
    "destructor_declaration",
    "operator_declaration",
    "accessor_declaration",
    "local_function_statement",
    "lambda_expression",
    "block",
    "for_statement",
    "for_each_statement",
    "using_statement",
    "catch_clause",
];

fn walk(node: Node<'_>, ctx: &mut CsScan<'_, '_>, bindings: &mut LocalInferenceEngine<String>) {
    let enters_scope = SCOPE_NODES.contains(&node.kind());
    if enters_scope {
        bindings.enter_scope();
    }
    seed_declaration(node, ctx, bindings);
    record_reference(node, ctx, bindings);

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk(child, ctx, bindings);
    }

    if enters_scope {
        bindings.exit_scope();
    }
}

fn record_reference(
    node: Node<'_>,
    ctx: &mut CsScan<'_, '_>,
    bindings: &LocalInferenceEngine<String>,
) {
    match node.kind() {
        // A type reference (`Foo x`, `new Foo()`, generics) resolves to the type
        // node. `new Foo()`'s type child is itself a type reference, so it is
        // covered here without a separate object-creation case.
        "identifier" | "type" => {
            if is_declaration_name(node) || !is_type_reference_node(node) {
                // An unqualified `Member(..)` call attributes to the enclosing class.
                if is_unqualified_invocation_target(node) {
                    let name = node_text(node, ctx.source);
                    if let Some(owner) = ctx.enclosing_class(node.start_byte()) {
                        ctx.record(format!("{owner}.{name}"), node);
                    }
                }
                return;
            }
            let reference = reference_type_text(node, ctx.source);
            if let Some(fqn) = ctx.resolve_type_fqn(&reference) {
                ctx.record(fqn, node);
            }
        }
        "member_access_expression" => {
            let (Some(name_node), Some(receiver)) =
                (member_access_name(node), member_access_receiver(node))
            else {
                return;
            };
            let name = node_text(name_node, ctx.source);
            if name.is_empty() {
                return;
            }
            if let Some(owner) = receiver_type_fqn(receiver, ctx, bindings) {
                ctx.record(format!("{owner}.{name}"), name_node);
            }
        }
        _ => {}
    }
}

/// True when `node` is the bare callee of an `Foo(..)` invocation (no receiver).
fn is_unqualified_invocation_target(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "invocation_expression"
            && parent.child_by_field_name("function") == Some(node)
    })
}

/// The fqn of a receiver expression's type, for the shapes that resolve without
/// return-type inference.
fn receiver_type_fqn(
    receiver: Node<'_>,
    ctx: &CsScan<'_, '_>,
    bindings: &LocalInferenceEngine<String>,
) -> Option<String> {
    match receiver.kind() {
        "identifier" => {
            let name = node_text(receiver, ctx.source);
            // A typed local resolves to its type; otherwise the name may be a
            // static type, unless it is a known (shadowed) untyped local.
            first_precise(bindings, name).or_else(|| {
                (!bindings.is_shadowed(name))
                    .then(|| ctx.resolve_type_fqn(name))
                    .flatten()
            })
        }
        "this" | "base" => ctx
            .enclosing_class(receiver.start_byte())
            .map(str::to_string),
        "qualified_name" | "generic_name" => ctx.resolve_type_fqn(node_text(receiver, ctx.source)),
        _ => None,
    }
}

fn seed_declaration(
    node: Node<'_>,
    ctx: &CsScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<String>,
) {
    match node.kind() {
        "parameter" => {
            let (Some(name), Some(type_node)) = (
                node.child_by_field_name("name"),
                node.child_by_field_name("type"),
            ) else {
                return;
            };
            seed_typed(
                name,
                ctx.resolve_type_fqn(node_text(type_node, ctx.source)),
                ctx,
                bindings,
            );
        }
        "variable_declaration" => seed_variable_declaration(node, ctx, bindings),
        _ => {}
    }
}

fn seed_variable_declaration(
    node: Node<'_>,
    ctx: &CsScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    let type_text = node_text(type_node, ctx.source);
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "variable_declarator" {
            continue;
        }
        let Some(name) = child.child_by_field_name("name") else {
            continue;
        };
        // `var x = new Foo()` infers from the initializer; other `var` is unknown.
        let resolved = if type_text == "var" {
            object_created_type(child)
                .and_then(|type_node| ctx.resolve_type_fqn(node_text(type_node, ctx.source)))
        } else {
            ctx.resolve_type_fqn(type_text)
        };
        seed_typed(name, resolved, ctx, bindings);
    }
}

fn seed_typed(
    name: Node<'_>,
    resolved: Option<String>,
    ctx: &CsScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let binding_name = node_text(name, ctx.source);
    if binding_name.is_empty() {
        return;
    }
    match resolved {
        Some(fqn) => bindings.seed_symbol(binding_name.to_string(), fqn),
        None => bindings.declare_shadow(binding_name.to_string()),
    }
}

/// The type node of a `new Foo()` initializer reachable from a declarator.
fn object_created_type(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() == "object_creation_expression" {
        return node
            .child_by_field_name("type")
            .or_else(|| first_type_child(node));
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find_map(object_created_type)
}
