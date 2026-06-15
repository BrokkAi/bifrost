//! Whole-workspace inverted edge builder for C++.
//!
//! Walks each file once and resolves every reference to the callee fqn it names,
//! via the shared [`build_edges`] driver. C++ node fqns are dotted: a namespace +
//! class + member reads `example.Service.run`, a free function `example.freeHelper`,
//! and a class `example.Service`. References resolve through the forward scanner's
//! visibility primitives ([`VisibilityIndex::resolve_type`] / [`resolve_named`],
//! which honor the include closure and namespaces) plus a [`LocalInferenceEngine`]
//! (typed by [`CodeUnit`], like the forward scan) seeded with every local's and
//! parameter's declared type so a method call's receiver can be typed:
//!
//! - a type reference (`Foo x`, `new Foo()`, a base class) resolves to the class;
//! - `recv.m(..)` / `recv->m(..)` (`field_expression` under a call) types `recv`
//!   and gives `Owner.m`;
//! - `X::m(..)` (`qualified_identifier`) resolves `X` and gives `Owner.m`;
//! - a bare `m(..)` is a free function (`Namespace.m`); `this->m(..)` and other
//!   unqualified member calls attribute to the enclosing class.
//!
//! The enclosing class is taken from a per-file class-range index (the analyzer's
//! own fqns), so `this->`/unqualified calls attribute to the right class without
//! re-deriving the namespace. A receiver that can't be typed (method chains,
//! return-type inference) is a recall gap, never a wrong edge — mirroring the
//! receiver shapes the forward C++ scan proves.

use super::resolver::{
    VisibilityIndex, collect_include_closure, extract_variable_name, first_type_child,
    is_declaration_name, is_declarator_node, normalize_type_text, resolve_cpp_analyzer,
};
use crate::analyzer::usages::inverted_edges::{
    ClassRangeIndex, EdgeCollector, UsageEdges, build_edges, first_precise,
};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::{
    CodeUnit, IAnalyzer, Language, ProjectFile, cpp_node_text as node_text,
    normalize_cpp_whitespace,
};
use crate::hash::{HashMap, HashSet};
use crate::text_utils::compute_line_starts;
use rayon::prelude::*;
use tree_sitter::{Node, Parser, Tree};

/// A C++ file parsed once for the inverted scan: source, tree, and line starts.
struct ParsedFile {
    source: String,
    tree: Tree,
    line_starts: Vec<usize>,
}

/// Build the whole C++ `caller -> callee` edge set in a single inverted pass over
/// the workspace. Returns `None` when there are no C++ files. `nodes`/`keep_file`
/// mirror the Go builder.
pub(crate) fn build_cpp_usage_edges<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdges>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let cpp = resolve_cpp_analyzer(analyzer)?;
    let files: Vec<ProjectFile> = analyzer
        .project()
        .analyzable_files(Language::Cpp)
        .ok()?
        .into_iter()
        .collect();

    // Resolution honors each caller file's include closure, so the visibility
    // index is seeded with every in-scope caller file as a root (mirroring the
    // forward scan, which builds it from the query's candidate files).
    let roots: HashSet<ProjectFile> = {
        let mut roots = HashSet::default();
        for file in files.iter().filter(|file| keep_file(file)) {
            collect_include_closure(cpp, analyzer, file, &mut roots);
        }
        roots
    };
    let visibility = VisibilityIndex::build(cpp, analyzer, &roots);

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
                .set_language(&tree_sitter_cpp::LANGUAGE.into())
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
            let mut ctx = CppScan {
                visibility: &visibility,
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

struct CppScan<'a, 'b> {
    visibility: &'a VisibilityIndex,
    file: &'a ProjectFile,
    source: &'a str,
    class_ranges: ClassRangeIndex,
    collector: &'a mut EdgeCollector<'b>,
}

impl CppScan<'_, '_> {
    /// Resolve a type reference's text to a class `CodeUnit`.
    fn resolve_type(&self, text: &str) -> Option<CodeUnit> {
        self.visibility.resolve_type(self.file, text)
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
    "compound_statement",
    "function_definition",
    "lambda_expression",
    "for_statement",
    "while_statement",
    "if_statement",
];

fn walk(node: Node<'_>, ctx: &mut CppScan<'_, '_>, bindings: &mut LocalInferenceEngine<CodeUnit>) {
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
    ctx: &mut CppScan<'_, '_>,
    bindings: &LocalInferenceEngine<CodeUnit>,
) {
    match node.kind() {
        // A type reference (`Foo x`, base class, `new Foo()`'s type child) resolves
        // to the class. `new Foo()` reaches its type via this case (its type child
        // is itself one of these nodes), so there is no separate construction case.
        "type_identifier" | "qualified_identifier" | "template_type" => {
            if is_declaration_name(node) || is_nested_type_node(node) {
                return;
            }
            // A `X::m(..)` static/scoped call appears as a `qualified_identifier`
            // function: resolve the `X` qualifier as a type and emit `Owner.m`.
            if let Some(owner) = scoped_call_owner(node, ctx) {
                let member = scoped_call_member(node, ctx.source);
                if !member.is_empty() {
                    ctx.record(format!("{owner}.{member}"), node);
                    return;
                }
            }
            if let Some(unit) = ctx.resolve_type(node_text(node, ctx.source)) {
                ctx.record(unit.fq_name(), node);
            }
        }
        "call_expression" => record_call(node, ctx, bindings),
        _ => {}
    }
}

fn record_call(
    node: Node<'_>,
    ctx: &mut CppScan<'_, '_>,
    bindings: &LocalInferenceEngine<CodeUnit>,
) {
    let Some(function) = node.child_by_field_name("function") else {
        return;
    };
    match function.kind() {
        // `obj.m()` / `ptr->m()`: type the receiver, emit `Owner.m`.
        "field_expression" => {
            let Some(field) = function.child_by_field_name("field") else {
                return;
            };
            let name = node_text(field, ctx.source);
            if name.is_empty() {
                return;
            }
            let Some(receiver) = function
                .child_by_field_name("argument")
                .or_else(|| function.named_child(0))
            else {
                return;
            };
            if let Some(owner) = receiver_type_fqn(receiver, ctx, bindings) {
                ctx.record(format!("{owner}.{name}"), field);
            }
        }
        // A bare `m(..)` is either a free function or an unqualified member call on
        // the enclosing class (`this`). `qualified_identifier` (`X::m`) is handled
        // by the type-reference case above.
        "identifier" => {
            let name = node_text(function, ctx.source);
            if name.is_empty() {
                return;
            }
            // Free function in the visible set.
            if let Some(unit) = ctx.visibility.resolve_named(
                ctx.file,
                name,
                super::resolver::TargetKind::FreeFunction,
            ) {
                ctx.record(unit.fq_name(), function);
                return;
            }
            // Otherwise an unqualified member call (`this`/inherited).
            if let Some(owner) = ctx.enclosing_class(function.start_byte()) {
                ctx.record(format!("{owner}.{name}"), function);
            }
        }
        _ => {}
    }
}

/// True when `node` is nested inside a larger qualified/scoped type node, so the
/// outer node already covers the reference (avoids double counting / partial text).
fn is_nested_type_node(node: Node<'_>) -> bool {
    node.parent()
        .is_some_and(|parent| parent.kind() == "qualified_identifier")
}

/// If `node` is the `function` of a `X::m(..)` call, the fqn of `X`'s type.
fn scoped_call_owner(node: Node<'_>, ctx: &CppScan<'_, '_>) -> Option<String> {
    if node.kind() != "qualified_identifier" {
        return None;
    }
    let parent = node.parent()?;
    if parent.kind() != "call_expression" || parent.child_by_field_name("function") != Some(node) {
        return None;
    }
    let scope = node.child_by_field_name("scope")?;
    ctx.resolve_type(node_text(scope, ctx.source))
        .map(|unit| unit.fq_name())
}

/// The trailing member name of a `X::m` qualified identifier.
fn scoped_call_member(node: Node<'_>, source: &str) -> String {
    node.child_by_field_name("name")
        .map(|name| node_text(name, source).to_string())
        .unwrap_or_default()
}

/// The fqn of a receiver expression's type, for the shapes that resolve without
/// return-type inference.
fn receiver_type_fqn(
    receiver: Node<'_>,
    ctx: &CppScan<'_, '_>,
    bindings: &LocalInferenceEngine<CodeUnit>,
) -> Option<String> {
    match receiver.kind() {
        "identifier" => {
            let name = node_text(receiver, ctx.source);
            // A typed local resolves to its type; otherwise the name may itself be a
            // type, unless it is a known (shadowed) untyped local — never reinterpret
            // a value as a static type.
            binding_type(bindings, name).or_else(|| {
                (!bindings.is_shadowed(name))
                    .then(|| ctx.resolve_type(name))
                    .flatten()
                    .map(|unit| unit.fq_name())
            })
        }
        "this" => ctx
            .enclosing_class(receiver.start_byte())
            .map(str::to_string),
        // `(*p).m()` / `(p).m()` unwrap to the inner receiver.
        "parenthesized_expression" | "pointer_expression" => receiver
            .child_by_field_name("argument")
            .or_else(|| receiver.named_child(0))
            .and_then(|inner| receiver_type_fqn(inner, ctx, bindings)),
        _ => None,
    }
}

fn binding_type(bindings: &LocalInferenceEngine<CodeUnit>, name: &str) -> Option<String> {
    first_precise(bindings, name).map(|unit| unit.fq_name())
}

fn seed_declaration(
    node: Node<'_>,
    ctx: &CppScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<CodeUnit>,
) {
    match node.kind() {
        "parameter_declaration" | "optional_parameter_declaration" => {
            seed_typed_binding(node, ctx, bindings)
        }
        "declaration" | "field_declaration" => seed_variable_declaration(node, ctx, bindings),
        _ => {}
    }
}

fn seed_typed_binding(
    node: Node<'_>,
    ctx: &CppScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<CodeUnit>,
) {
    let Some(declarator) = node.child_by_field_name("declarator") else {
        return;
    };
    let Some(name) = extract_variable_name(declarator, ctx.source) else {
        return;
    };
    let type_text = node
        .child_by_field_name("type")
        .or_else(|| first_type_child(node))
        .map(|type_node| normalize_type_text(node_text(type_node, ctx.source)));
    seed_binding(&name, type_text.as_deref(), None, ctx, bindings);
}

fn seed_variable_declaration(
    node: Node<'_>,
    ctx: &CppScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<CodeUnit>,
) {
    let type_text = node
        .child_by_field_name("type")
        .or_else(|| first_type_child(node))
        .map(|type_node| normalize_type_text(node_text(type_node, ctx.source)));
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        let declarator = if child.kind() == "init_declarator" {
            child.child_by_field_name("declarator")
        } else if is_declarator_node(child) {
            Some(child)
        } else {
            None
        };
        let Some(declarator) = declarator else {
            continue;
        };
        if declarator.kind() == "function_declarator" {
            continue;
        }
        let Some(name) = extract_variable_name(declarator, ctx.source) else {
            continue;
        };
        let value = child.child_by_field_name("value");
        seed_binding(&name, type_text.as_deref(), value, ctx, bindings);
    }
}

fn seed_binding(
    name: &str,
    type_text: Option<&str>,
    value: Option<Node<'_>>,
    ctx: &CppScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<CodeUnit>,
) {
    if name.is_empty() {
        return;
    }
    // A declared type resolves directly; `auto x = new Foo()` infers from the
    // initializer. A declared-but-unresolved local is shadowed so a later
    // member access never falls back to static type resolution on its name.
    let resolved = type_text
        .filter(|text| *text != "auto")
        .and_then(|text| ctx.resolve_type(text))
        .or_else(|| value.and_then(|value| infer_type_from_value(value, ctx)));
    match resolved {
        Some(unit) => bindings.seed_symbol(name.to_string(), unit),
        None => bindings.declare_shadow(name.to_string()),
    }
}

/// Infer a class type from an initializer expression for `auto`/untyped locals.
fn infer_type_from_value(node: Node<'_>, ctx: &CppScan<'_, '_>) -> Option<CodeUnit> {
    match node.kind() {
        "new_expression" => {
            let text = normalize_cpp_whitespace(node_text(node, ctx.source));
            let rest = text.strip_prefix("new ").unwrap_or(text.as_str());
            ctx.resolve_type(rest.split(['(', '{']).next().unwrap_or(rest))
        }
        "call_expression" => node
            .child_by_field_name("function")
            .and_then(|function| ctx.resolve_type(node_text(function, ctx.source))),
        _ => None,
    }
}
