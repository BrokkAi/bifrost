//! Whole-workspace inverted edge builder for Scala.
//!
//! Walks each file once and resolves every reference to the callee fqn it names,
//! via the shared [`build_edges`] driver. Scala has no single `resolve_type_name`
//! primitive, so name->fqn resolution is rebuilt here by mirroring the forward
//! scanner's [`Visibility`](super::resolver): a per-file [`NameResolver`] maps a
//! source-visible type/object name to the analyzer's own fqn, honoring the file's
//! package and its imports. A [`LocalInferenceEngine`] seeded with typed params
//! and `val x = new Foo()` lets a method call's receiver be typed:
//!
//! - a type reference (`x: Foo`, `new Foo`, `def f(): Foo`) resolves to the type;
//! - `recv.method(..)` types `recv` to `Owner`, giving `Owner.method`;
//! - `this`/an unqualified `method(..)` attributes to the enclosing class.
//!
//! Scala object fqns keep their `$` object-encoding suffix (`example.Helpers$`,
//! method `example.Helpers$.help`), so type/object fqns come straight from the
//! analyzer's declarations rather than being rebuilt from `package.name` text —
//! a string-rebuilt name would drop the `$` and silently match no node. The
//! enclosing class is taken from a per-file class-range index (the analyzer's own
//! fqns) so `this`/unqualified calls attribute to the right class (and the right
//! `$`-encoded object). Receivers needing return-type inference (method chains)
//! are an unhandled recall gap, not a wrong edge.

use super::resolver::{package_name_of, scala_display_name, scala_normalized_fq_name};
use super::shared::ScalaEdgeGraph;
use super::syntax::{node_text, scala_import_path};
use crate::analyzer::usages::inverted_edges::{
    ClassRangeIndex, EdgeCollector, UsageEdges, build_edges, first_precise,
};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::usages::parsed_tree::ParsedTreeFile;
use crate::analyzer::{IAnalyzer, ImportAnalysisProvider, ProjectFile, ScalaAnalyzer};
use crate::hash::{HashMap, HashSet};
use tree_sitter::Node;

/// A Scala file parsed once for the inverted scan: source, tree, and line starts.
pub(super) type ParsedScalaFile = ParsedTreeFile;

/// Every class/object/trait/enum the project declares, indexed for the per-file
/// name->fqn rebuild. Built once and shared across all files' scans.
pub(super) struct ProjectTypes {
    /// `(package, source_name) -> fqn` — a type reachable by simple name from a
    /// file in the same package (or via a wildcard import of that package).
    by_package: HashMap<(String, String), String>,
    /// `normalized_fqn -> fqn` — resolve a non-wildcard import path (whose text is
    /// `$`-free) to the analyzer's own `$`-encoded fqn.
    by_normalized_fqn: HashMap<String, String>,
}

impl ProjectTypes {
    pub(super) fn build(scala: &ScalaAnalyzer) -> Self {
        let mut by_package = HashMap::default();
        let mut by_normalized_fqn = HashMap::default();
        for unit in scala.all_declarations().filter(|unit| unit.is_class()) {
            let fqn = unit.fq_name();
            by_package.insert(
                (unit.package_name().to_string(), scala_display_name(unit)),
                fqn.clone(),
            );
            by_normalized_fqn.insert(scala_normalized_fq_name(&fqn), fqn);
        }
        Self {
            by_package,
            by_normalized_fqn,
        }
    }
}

/// Per-file map from a source-visible type/object name to the analyzer's fqn,
/// mirroring the forward scanner's [`Visibility`](super::resolver).
struct NameResolver {
    names: HashMap<String, String>,
}

impl NameResolver {
    fn for_file(scala: &ScalaAnalyzer, file: &ProjectFile, types: &ProjectTypes) -> Self {
        let mut names = HashMap::default();

        // Types in the file's own package are reachable by simple name.
        if let Some(package) = package_name_of(scala, file) {
            for ((decl_package, simple), fqn) in &types.by_package {
                if *decl_package == package {
                    names.insert(simple.clone(), fqn.clone());
                }
            }
        }

        for import in scala.import_info_of(file) {
            let Some(path) = scala_import_path(import) else {
                continue;
            };
            if import.is_wildcard {
                // `import pkg._` exposes every type in `pkg` by simple name.
                for ((decl_package, simple), fqn) in &types.by_package {
                    if *decl_package == path {
                        names.insert(simple.clone(), fqn.clone());
                    }
                }
                continue;
            }
            // `import pkg.Type [as Alias]` binds the (possibly renamed) local name.
            let normalized = scala_normalized_fq_name(&path);
            if let Some(fqn) = types.by_normalized_fqn.get(&normalized) {
                let local_name = import
                    .identifier
                    .clone()
                    .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(&path).to_string());
                names.insert(local_name, fqn.clone());
            }
        }

        Self { names }
    }

    /// Resolve a type/object source name (stripping generics) to its fqn.
    fn resolve(&self, raw: &str) -> Option<String> {
        let simple = simple_type_name(raw)?;
        self.names.get(simple).cloned()
    }
}

/// The leading simple name of a (possibly generic/qualified) type text.
fn simple_type_name(type_text: &str) -> Option<&str> {
    type_text
        .split(['[', '(', '{', '.', ' ', '<'])
        .next()
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

/// Build the whole Scala `caller -> callee` edge set in a single inverted pass
/// over the workspace.
/// `nodes`/`keep_file` mirror the Go builder.
pub(super) fn build_scala_edges<F>(
    analyzer: &dyn IAnalyzer,
    graph: &ScalaEdgeGraph<'_>,
    nodes: &HashSet<String>,
    keep_file: F,
) -> UsageEdges
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    build_edges(
        analyzer,
        &graph.files,
        nodes,
        keep_file,
        |file| {
            graph
                .parsed
                .get(file)
                .map(|parsed| parsed.line_starts.as_slice())
        },
        |file, collector| {
            let Some(parsed) = graph.parsed.get(file) else {
                return;
            };
            let resolver = NameResolver::for_file(graph.scala, file, &graph.types);
            let mut ctx = ScalaScan {
                source: parsed.source.as_str(),
                resolver: &resolver,
                class_ranges: ClassRangeIndex::build(analyzer, file),
                collector,
            };
            let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
            walk(parsed.tree.root_node(), &mut ctx, &mut bindings);
        },
    )
}

struct ScalaScan<'a, 'b> {
    source: &'a str,
    resolver: &'a NameResolver,
    class_ranges: ClassRangeIndex,
    collector: &'a mut EdgeCollector<'b>,
}

impl ScalaScan<'_, '_> {
    /// The fqn of the smallest class/object declaration containing `byte`.
    fn enclosing_class(&self, byte: usize) -> Option<&str> {
        self.class_ranges.enclosing(byte)
    }

    fn record(&mut self, callee: String, node: Node<'_>) {
        self.collector
            .record(callee, node.start_byte(), node.end_byte());
    }
}

const SCOPE_NODES: &[&str] = &[
    "class_definition",
    "object_definition",
    "trait_definition",
    "enum_definition",
    "function_definition",
    "block",
    "indented_block",
    "case_clause",
    "lambda_expression",
];

fn walk(node: Node<'_>, ctx: &mut ScalaScan<'_, '_>, bindings: &mut LocalInferenceEngine<String>) {
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
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<String>,
) {
    match node.kind() {
        // A type reference in any type position: param/return types, `extends`,
        // and the type child of `new Foo()`. Construction is covered here without
        // a separate `instance_expression` case (avoids double counting).
        "type_identifier" => {
            // The qualifier of a `stable_type_identifier` (`pkg.Type`) is resolved
            // via the leaf type, so skip non-leaf qualifier positions.
            if node
                .parent()
                .is_some_and(|parent| parent.kind() == "stable_type_identifier")
                && node
                    .parent()
                    .and_then(|parent| parent.child_by_field_name("name"))
                    != Some(node)
            {
                return;
            }
            if let Some(fqn) = ctx.resolver.resolve(node_text(node, ctx.source)) {
                ctx.record(fqn, node);
            }
        }
        "call_expression" => {
            let Some(function) = node.child_by_field_name("function") else {
                return;
            };
            match function.kind() {
                // `recv.method(..)` — type the receiver, then `Owner.method`.
                "field_expression" => {
                    let (Some(receiver), Some(field)) = (
                        function.child_by_field_name("value"),
                        function.child_by_field_name("field"),
                    ) else {
                        return;
                    };
                    let name = node_text(field, ctx.source);
                    if name.is_empty() {
                        return;
                    }
                    if let Some(owner) = receiver_type_fqn(receiver, ctx, bindings) {
                        ctx.record(format!("{owner}.{name}"), field);
                    }
                }
                // `method(..)` — unqualified, attributes to the enclosing class.
                "identifier" => {
                    let name = node_text(function, ctx.source);
                    if name.is_empty() {
                        return;
                    }
                    if let Some(owner) = ctx.enclosing_class(function.start_byte()) {
                        ctx.record(format!("{owner}.{name}"), function);
                    }
                }
                _ => {}
            }
        }
        _ => {}
    }
}

/// The fqn of a receiver expression's type, for the shapes that resolve without
/// return-type inference.
fn receiver_type_fqn(
    receiver: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<String>,
) -> Option<String> {
    match receiver.kind() {
        // `this` is a plain `identifier` in tree-sitter-scala (not its own node).
        "identifier" => {
            let name = node_text(receiver, ctx.source);
            if name == "this" {
                return ctx
                    .enclosing_class(receiver.start_byte())
                    .map(str::to_string);
            }
            // A typed local resolves to its type; otherwise the name may be an
            // object/type, unless it is a known (shadowed) untyped local.
            first_precise(bindings, name).or_else(|| {
                (!bindings.is_shadowed(name))
                    .then(|| ctx.resolver.resolve(name))
                    .flatten()
            })
        }
        _ => None,
    }
}

fn seed_declaration(
    node: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<String>,
) {
    match node.kind() {
        "function_definition" => seed_parameters(node, ctx, bindings),
        "val_definition" | "var_definition" => seed_value_definition(node, ctx, bindings),
        _ => {}
    }
}

fn seed_parameters(
    node: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "parameters" {
            continue;
        }
        let mut inner = child.walk();
        for parameter in child.named_children(&mut inner) {
            if parameter.kind() == "parameter" {
                seed_parameter(parameter, ctx, bindings);
            }
        }
    }
}

fn seed_parameter(
    parameter: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let Some(name) = parameter.child_by_field_name("name") else {
        return;
    };
    let binding_name = node_text(name, ctx.source).trim();
    if binding_name.is_empty() {
        return;
    }
    let resolved = parameter
        .child_by_field_name("type")
        .and_then(|type_node| ctx.resolver.resolve(node_text(type_node, ctx.source)));
    seed_typed(binding_name, resolved, bindings);
}

fn seed_value_definition(
    node: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<String>,
) {
    // Prefer the declared type; otherwise infer from a `new Foo()` initializer.
    let resolved = node
        .child_by_field_name("type")
        .and_then(|type_node| ctx.resolver.resolve(node_text(type_node, ctx.source)))
        .or_else(|| {
            node.child_by_field_name("value")
                .and_then(|value| constructed_type(value, ctx))
        });
    let Some(pattern) = node.child_by_field_name("pattern") else {
        return;
    };
    for name in pattern_names(pattern, ctx.source) {
        seed_typed(name, resolved.clone(), bindings);
    }
}

/// The fqn of the type constructed by a `new Foo()` value expression.
fn constructed_type(node: Node<'_>, ctx: &ScalaScan<'_, '_>) -> Option<String> {
    if node.kind() == "instance_expression" {
        let mut cursor = node.walk();
        return node
            .named_children(&mut cursor)
            .find(|child| child.kind() == "type_identifier" || child.kind() == "generic_type")
            .and_then(|type_node| ctx.resolver.resolve(node_text(type_node, ctx.source)));
    }
    None
}

fn pattern_names<'a>(node: Node<'_>, source: &'a str) -> Vec<&'a str> {
    match node.kind() {
        "identifier" | "operator_identifier" => {
            let name = node_text(node, source).trim();
            if name.is_empty() {
                Vec::new()
            } else {
                vec![name]
            }
        }
        _ => {
            let mut names = Vec::new();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                names.extend(pattern_names(child, source));
            }
            names
        }
    }
}

fn seed_typed(name: &str, resolved: Option<String>, bindings: &mut LocalInferenceEngine<String>) {
    match resolved {
        Some(fqn) => bindings.seed_symbol(name.to_string(), fqn),
        None => bindings.declare_shadow(name.to_string()),
    }
}
