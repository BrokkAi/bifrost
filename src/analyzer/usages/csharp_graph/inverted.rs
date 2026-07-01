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
    argument_count, first_type_child, is_type_reference_node, method_unit_return_type_fq_name,
    node_text, normalize_type_text, reference_type_text, signature_arity,
};
use crate::analyzer::usages::inverted_edges::{
    ClassRangeIndex, EdgeCollector, UsageEdges, build_edges, first_precise, parse_and_collect,
};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::{CSharpAnalyzer, CodeUnit, IAnalyzer, ProjectFile};
use crate::hash::{HashMap, HashSet};
use std::sync::Mutex;
use tree_sitter::Node;

type MethodReturnCacheKey = (String, String, usize);
type MethodReturnCache = Mutex<HashMap<MethodReturnCacheKey, Option<String>>>;
type MethodDeclarationIndex = HashMap<MethodReturnCacheKey, Vec<CodeUnit>>;

fn csharp_method_declaration_index(
    analyzer: &dyn IAnalyzer,
    csharp: &CSharpAnalyzer,
) -> MethodDeclarationIndex {
    let mut index: MethodDeclarationIndex = HashMap::default();
    for unit in csharp
        .get_all_declarations()
        .into_iter()
        .filter(|unit| unit.is_function())
    {
        let Some(owner) = analyzer.parent_of(&unit) else {
            continue;
        };
        index
            .entry((
                owner.fq_name(),
                unit.identifier().to_string(),
                signature_arity(unit.signature()),
            ))
            .or_default()
            .push(unit);
    }
    index
}

pub(super) fn build_csharp_edges<F>(
    analyzer: &dyn IAnalyzer,
    csharp: &CSharpAnalyzer,
    files: &[ProjectFile],
    nodes: &HashSet<String>,
    keep_file: F,
) -> UsageEdges
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let language = tree_sitter_c_sharp::LANGUAGE.into();
    let class_units: HashMap<String, CodeUnit> = csharp
        .get_all_declarations()
        .into_iter()
        .filter(|unit| unit.is_class())
        .map(|unit| (unit.fq_name(), unit))
        .collect();
    let method_declarations = csharp_method_declaration_index(analyzer, csharp);
    let method_return_cache: MethodReturnCache = Mutex::new(HashMap::default());
    build_edges(files, keep_file, |file| {
        parse_and_collect(analyzer, file, nodes, &language, |parsed, collector| {
            let mut ctx = CsScan {
                analyzer,
                csharp,
                file,
                source: parsed.source.as_str(),
                class_ranges: ClassRangeIndex::build(analyzer, file),
                class_units: &class_units,
                method_declarations: &method_declarations,
                method_return_cache: &method_return_cache,
                collector,
            };
            let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
            walk(parsed.tree.root_node(), &mut ctx, &mut bindings);
        })
    })
}

struct CsScan<'a, 'b> {
    analyzer: &'a dyn IAnalyzer,
    csharp: &'a CSharpAnalyzer,
    file: &'a ProjectFile,
    source: &'a str,
    class_ranges: ClassRangeIndex,
    class_units: &'a HashMap<String, CodeUnit>,
    method_declarations: &'a MethodDeclarationIndex,
    method_return_cache: &'a MethodReturnCache,
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
                .or_else(|| var_initializer_type(child, ctx, bindings))
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

fn var_initializer_type(
    declarator: Node<'_>,
    ctx: &CsScan<'_, '_>,
    bindings: &LocalInferenceEngine<String>,
) -> Option<String> {
    let initializer = variable_declarator_initializer(declarator)?;
    expression_type_fqn(initializer, ctx, bindings)
}

fn variable_declarator_initializer(declarator: Node<'_>) -> Option<Node<'_>> {
    declarator
        .child_by_field_name("value")
        .or_else(|| declarator.child_by_field_name("initializer"))
        .or_else(|| {
            let mut cursor = declarator.walk();
            declarator
                .named_children(&mut cursor)
                .find(|child| child.kind() == "equals_value_clause")
                .and_then(|clause| {
                    clause
                        .child_by_field_name("value")
                        .or_else(|| clause.named_child(0))
                })
        })
        .or_else(|| {
            let name = declarator.child_by_field_name("name")?;
            let mut cursor = declarator.walk();
            declarator
                .named_children(&mut cursor)
                .find(|child| child.start_byte() > name.end_byte())
        })
}

fn expression_type_fqn(
    expression: Node<'_>,
    ctx: &CsScan<'_, '_>,
    bindings: &LocalInferenceEngine<String>,
) -> Option<String> {
    match expression.kind() {
        "object_creation_expression" => object_created_type(expression)
            .and_then(|type_node| ctx.resolve_type_fqn(node_text(type_node, ctx.source))),
        "invocation_expression" => invocation_return_type_fqn(expression, ctx, bindings),
        "identifier" => {
            let name = node_text(expression, ctx.source);
            first_precise(bindings, name)
        }
        _ => None,
    }
}

fn invocation_return_type_fqn(
    invocation: Node<'_>,
    ctx: &CsScan<'_, '_>,
    bindings: &LocalInferenceEngine<String>,
) -> Option<String> {
    let function = invocation.child_by_field_name("function")?;
    match function.kind() {
        "identifier" => {
            let name = node_text(function, ctx.source);
            let owner_fqn = ctx.enclosing_class(invocation.start_byte())?;
            let owner = class_unit_for_fqn(ctx, owner_fqn)?;
            method_return_type_for_call(ctx, &owner, name, argument_count(invocation, ctx.source))
        }
        "member_access_expression" => {
            let receiver = member_access_receiver(function)?;
            let name = member_access_name(function)?;
            let owner_fqn = receiver_type_fqn(receiver, ctx, bindings)?;
            let owner = class_unit_for_fqn(ctx, &owner_fqn)?;
            method_return_type_for_call(
                ctx,
                &owner,
                node_text(name, ctx.source),
                argument_count(invocation, ctx.source),
            )
        }
        _ => None,
    }
}

fn method_return_type_for_call(
    ctx: &CsScan<'_, '_>,
    owner: &CodeUnit,
    method_name: &str,
    arity: usize,
) -> Option<String> {
    let cache_key = (owner.fq_name(), method_name.to_string(), arity);
    if let Some(cached) = ctx
        .method_return_cache
        .lock()
        .expect("csharp return type cache poisoned")
        .get(&cache_key)
        .cloned()
    {
        return cached;
    }
    let mut resolved = csharp_method_return_types_for_owner(ctx, owner, method_name, arity);
    resolved.sort();
    resolved.dedup();
    let resolved = (resolved.len() == 1).then(|| resolved.remove(0));
    ctx.method_return_cache
        .lock()
        .expect("csharp return type cache poisoned")
        .insert(cache_key, resolved.clone());
    resolved
}

fn csharp_method_return_types_for_owner(
    ctx: &CsScan<'_, '_>,
    owner: &CodeUnit,
    method_name: &str,
    arity: usize,
) -> Vec<String> {
    let mut owners = vec![owner.clone()];
    if let Some(provider) = ctx.analyzer.type_hierarchy_provider() {
        owners.extend(provider.get_ancestors(owner));
    }
    let mut returns = Vec::new();
    for candidate in owners {
        if let Some(methods) =
            ctx.method_declarations
                .get(&(candidate.fq_name(), method_name.to_string(), arity))
        {
            returns.extend(methods.iter().filter_map(|method| {
                method_unit_return_type_fq_name(ctx.csharp, &candidate, method)
            }));
        }
    }
    returns
}

fn class_unit_for_fqn(ctx: &CsScan<'_, '_>, fqn: &str) -> Option<CodeUnit> {
    ctx.class_units.get(fqn).cloned()
}
