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

use super::extractor::{LexicalScopeResolution, enclosing_lexical_scope_components};
use super::resolver::{
    DesignatedInitializerOwner, LexicalCallableValueResolution, TargetKind, VisibilityIndex,
    VisibleMemberResolution, constructor_style_local_declaration, designated_initializer_owner,
    extract_variable_name, first_type_child, infer_cpp_initializer_type, is_declaration_name,
    is_declarator_node, normalize_type_text, out_of_line_member_definition_owner,
    recovered_macro_function_return_type, type_owner_of,
};
use super::syntax::explicit_qualified_callable_value;
use crate::analyzer::usages::common::{TreeWalkAction, walk_tree_iterative};
use crate::analyzer::usages::inverted_edges::{
    ClassRangeIndex, EdgeCollector, UsageEdgeBuildOutput, build_edge_output,
    classify_reference_node, first_precise, parse_and_collect,
};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile, cpp_node_text as node_text};
use crate::hash::HashSet;
use tree_sitter::Node;

/// Build the whole C++ `caller -> callee` edge set in a single inverted pass over
/// the resolver-owned file set. `nodes`/`keep_file` mirror the Go builder.
pub(super) fn build_cpp_edges<Output, F>(
    analyzer: &dyn IAnalyzer,
    files: &[ProjectFile],
    visibility: &VisibilityIndex,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Output
where
    Output: UsageEdgeBuildOutput<String>,
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let language = tree_sitter_cpp::LANGUAGE.into();
    build_edge_output(files, keep_file, |file| {
        parse_and_collect(analyzer, file, nodes, &language, |parsed, collector| {
            let mut ctx = CppScan {
                analyzer,
                visibility,
                file,
                source: parsed.source.as_str(),
                class_ranges: ClassRangeIndex::build(analyzer, file),
                collector,
            };
            let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
            walk(parsed.tree.root_node(), &mut ctx, &mut bindings);
        })
    })
}

struct CppScan<'a, 'b> {
    analyzer: &'a dyn IAnalyzer,
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
        self.collector.record_kind(
            callee,
            classify_reference_node(node),
            node.start_byte(),
            node.end_byte(),
        );
    }

    fn record_unproven(&mut self, name: &str, node: Node<'_>) {
        self.collector
            .record_unproven_name(name, node.start_byte(), node.end_byte());
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
    let mut state = (ctx, bindings);
    walk_tree_iterative(
        node,
        &mut state,
        |node, (ctx, bindings)| {
            if walk_enter(node, ctx, bindings) {
                TreeWalkAction::DescendWithExit
            } else {
                TreeWalkAction::Descend
            }
        },
        |(_, bindings)| bindings.exit_scope(),
    );
}

fn walk_enter(
    node: Node<'_>,
    ctx: &mut CppScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<CodeUnit>,
) -> bool {
    let enters_scope = SCOPE_NODES.contains(&node.kind());
    if enters_scope {
        bindings.enter_scope();
    }
    seed_declaration(node, ctx, bindings);
    record_reference(node, ctx, bindings);
    enters_scope
}

fn record_reference(
    node: Node<'_>,
    ctx: &mut CppScan<'_, '_>,
    bindings: &LocalInferenceEngine<CodeUnit>,
) {
    if let Some(value) = explicit_qualified_callable_value(node) {
        record_qualified_callable_value(
            value.qualified,
            value.global,
            &value.owner_components,
            value.member,
            ctx,
        );
        return;
    }
    if matches!(node.kind(), "identifier" | "field_identifier")
        && let Some(designator_owner) =
            designated_initializer_owner(ctx.visibility, ctx.file, ctx.source, node)
    {
        let name = node_text(node, ctx.source);
        match designator_owner {
            DesignatedInitializerOwner::Resolved(owner) => {
                if let Some(field) = ctx
                    .visibility
                    .visible_members_for_owner_name(ctx.file, &owner, name)
                    .into_iter()
                    .find(|unit| unit.is_field())
                {
                    ctx.record(field.fq_name(), node);
                }
            }
            DesignatedInitializerOwner::Unresolved => ctx.record_unproven(name, node),
        }
        return;
    }
    match node.kind() {
        "namespace_identifier" if recovered_macro_function_return_type(node).is_some() => {
            if let Some(unit) = ctx.resolve_type(node_text(node, ctx.source)) {
                ctx.record(unit.fq_name(), node);
            }
        }
        // A type reference (`Foo x`, base class, `new Foo()`'s type child) resolves
        // to the class. `new Foo()` reaches its type via this case (its type child
        // is itself one of these nodes), so there is no separate construction case.
        "type_identifier" | "qualified_identifier" | "template_type" => {
            if is_declaration_name(node) {
                if let Some((scope, owner)) =
                    out_of_line_member_definition_owner(ctx.visibility, ctx.file, ctx.source, node)
                {
                    ctx.record(owner.fq_name(), scope);
                }
                return;
            }
            if is_nested_type_node(node) {
                return;
            }
            // A `X::m(..)` static/scoped call appears as a `qualified_identifier`
            // function: resolve the `X` qualifier as a type and emit `Owner.m`.
            if let Some(function) = scoped_free_function(node, ctx) {
                ctx.record(function.fq_name(), node);
                return;
            }
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

fn record_qualified_callable_value(
    qualified: Node<'_>,
    global: bool,
    owner_components: &[Node<'_>],
    member_node: Node<'_>,
    ctx: &mut CppScan<'_, '_>,
) {
    let member_name = node_text(member_node, ctx.source);
    if member_name.is_empty() {
        return;
    }
    let owner_components = owner_components
        .iter()
        .map(|component| node_text(*component, ctx.source))
        .map(str::to_string)
        .collect::<Vec<_>>();
    let lexical_scope = if global {
        Vec::new()
    } else {
        match enclosing_lexical_scope_components(
            qualified,
            ctx.analyzer,
            ctx.visibility,
            ctx.file,
            ctx.source,
        ) {
            LexicalScopeResolution::Resolved(scope) => scope,
            LexicalScopeResolution::Ambiguous | LexicalScopeResolution::Missing => {
                ctx.record_unproven(member_name, member_node);
                return;
            }
        }
    };
    let owner = match ctx.visibility.resolve_callable_value_components_lexically(
        ctx.analyzer,
        ctx.file,
        &owner_components,
        member_name,
        global,
        &lexical_scope,
    ) {
        LexicalCallableValueResolution::Type(owner) => owner,
        LexicalCallableValueResolution::FreeFunction(function) => {
            ctx.record(function.fq_name(), member_node);
            return;
        }
        LexicalCallableValueResolution::Ambiguous | LexicalCallableValueResolution::Missing => {
            ctx.record_unproven(member_name, member_node);
            return;
        }
    };
    match ctx
        .visibility
        .visible_member_for_owner_name(ctx.file, &owner, member_name)
    {
        VisibleMemberResolution::Callable(callables) => {
            if let Some(callable) = callables.first() {
                ctx.record(callable.fq_name(), member_node);
            }
        }
        // Fields are intentionally absent from the workspace usage-graph node
        // catalog. A proven non-callable member is therefore a negative for this
        // callable edge pass, not an unresolved terminal-name fanout.
        VisibleMemberResolution::NonCallable => {}
        VisibleMemberResolution::AmbiguousKind | VisibleMemberResolution::Missing => {
            ctx.record_unproven(member_name, member_node);
        }
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
            if receiver_is_self_like(receiver) {
                return;
            }
            if let Some(owner) = receiver_type_fqn(receiver, ctx, bindings) {
                ctx.record(format!("{owner}.{name}"), field);
            } else {
                ctx.record_unproven(name, field);
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
            if let Some(unit) =
                ctx.visibility
                    .resolve_named(ctx.file, name, TargetKind::FreeFunction)
            {
                if type_owner_of(ctx.analyzer, &unit).is_some() {
                    return;
                }
                ctx.record(unit.fq_name(), function);
            }
            // Otherwise this is an unqualified member call (`this`/inherited).
            // That belongs to editor references, not the usage_graph edge surface.
        }
        _ => {}
    }
}

fn receiver_is_self_like(receiver: Node<'_>) -> bool {
    match receiver.kind() {
        "this" => true,
        "parenthesized_expression" | "pointer_expression" => receiver
            .child_by_field_name("argument")
            .or_else(|| receiver.named_child(0))
            .is_some_and(receiver_is_self_like),
        _ => false,
    }
}

/// True when `node` is nested inside a larger qualified/scoped type node, so the
/// outer node already covers the reference (avoids double counting / partial text).
fn is_nested_type_node(node: Node<'_>) -> bool {
    node.parent()
        .is_some_and(|parent| parent.kind() == "qualified_identifier")
}

/// If `node` is the `function` of a namespace-qualified free-function call, its target.
fn scoped_free_function(node: Node<'_>, ctx: &CppScan<'_, '_>) -> Option<CodeUnit> {
    if node.kind() != "qualified_identifier" {
        return None;
    }
    let parent = node.parent()?;
    if parent.kind() != "call_expression" || parent.child_by_field_name("function") != Some(node) {
        return None;
    }
    ctx.visibility.resolve_named(
        ctx.file,
        node_text(node, ctx.source),
        TargetKind::FreeFunction,
    )
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
        if declarator.kind() == "function_declarator"
            && !constructor_style_local_declaration(
                ctx.visibility,
                ctx.file,
                ctx.source,
                declarator,
                type_text.as_deref(),
                bindings,
            )
        {
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
    infer_cpp_initializer_type(ctx.analyzer, ctx.visibility, ctx.file, ctx.source, node)
}
