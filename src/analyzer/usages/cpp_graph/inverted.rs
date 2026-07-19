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
//!   unqualified member calls attribute to the enclosing class;
//! - a chained receiver (`p->get()->m()`) follows the uniquely resolved persisted
//!   callable return type before recording `Owner.m`.
//!
//! The enclosing class is taken from a per-file class-range index (the analyzer's
//! own fqns), so `this->`/unqualified calls attribute to the right class without
//! re-deriving the namespace. Ambiguous receiver or return identities fail closed.

use super::extractor::{
    LexicalScopeResolution, enclosing_lexical_scope_components, initialized_ordinary_type_imports,
    ordinary_using_declaration_type_node, resolve_ordinary_using_declaration_owner,
    resolve_type_node_lexically, resolve_using_enum_declaration_owner,
    using_enum_declaration_type_node,
};
use super::resolver::{
    DesignatedInitializerOwner, EnclosingMemberOwnerResolution, LexicalCallableValueResolution,
    LexicalTypeResolution, OrdinaryTypeImportCell, TargetKind, VisibilityIndex,
    VisibleMemberResolution, constructor_style_local_declaration, cpp_callable_arity,
    declarator_name_node, designated_initializer_owner, extract_variable_name, first_type_child,
    infer_cpp_initializer_binding, infer_cpp_initializer_type, is_declaration_name,
    is_declarator_node, is_nested_type_node, normalize_type_text,
    out_of_line_member_definition_owner, recovered_macro_function_return_type,
    recovered_qualified_declarator_type, resolve_declaring_member_owner, same_visible_symbol,
    type_owner_of,
};
use super::syntax::explicit_qualified_callable_value;
use crate::analyzer::usages::common::{TreeWalkAction, walk_tree_iterative};
use crate::analyzer::usages::inverted_edges::{
    ClassRangeIndex, EdgeCollector, UsageEdgeBuildOutput, build_edge_output,
    classify_reference_node, first_precise, parse_and_collect,
};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile, cpp_node_text as node_text};
use crate::hash::{HashMap, HashSet};
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
            let ordinary_type_imports = initialized_ordinary_type_imports(
                parsed.tree.root_node(),
                analyzer,
                visibility,
                file,
                parsed.source.as_str(),
            );
            let mut ctx = CppScan {
                analyzer,
                visibility,
                file,
                source: parsed.source.as_str(),
                ordinary_type_imports,
                class_ranges: ClassRangeIndex::build(analyzer, file),
                declaring_member_cache: HashMap::default(),
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
    ordinary_type_imports: OrdinaryTypeImportCell,
    class_ranges: ClassRangeIndex,
    declaring_member_cache: HashMap<CodeUnit, HashMap<String, EnclosingMemberOwnerResolution>>,
    collector: &'a mut EdgeCollector<'b>,
}

impl CppScan<'_, '_> {
    /// Resolve a type reference's text to a class `CodeUnit`.
    fn resolve_type(&self, text: &str) -> Option<CodeUnit> {
        self.visibility.resolve_type(self.file, text)
    }

    fn resolve_type_node_result(
        &self,
        node: Node<'_>,
    ) -> std::result::Result<Option<CodeUnit>, ()> {
        self.visibility
            .resolve_type_node_result(self.file, node, self.source)
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
    if node.kind() == "using_declaration" {
        let (resolution, type_node) =
            if let Some(type_node) = using_enum_declaration_type_node(node) {
                (
                    resolve_using_enum_declaration_owner(
                        node,
                        ctx.analyzer,
                        ctx.visibility,
                        &ctx.ordinary_type_imports,
                        ctx.file,
                        ctx.source,
                    ),
                    type_node,
                )
            } else if let Some(type_node) = ordinary_using_declaration_type_node(node) {
                (
                    resolve_ordinary_using_declaration_owner(
                        node,
                        ctx.analyzer,
                        ctx.visibility,
                        ctx.file,
                        ctx.source,
                    ),
                    type_node,
                )
            } else {
                return;
            };
        match resolution {
            LexicalTypeResolution::Resolved { unit, .. } => ctx.record(unit.fq_name(), type_node),
            LexicalTypeResolution::Ambiguous | LexicalTypeResolution::Missing => {
                ctx.record_unproven(node_text(type_node, ctx.source), type_node);
            }
        }
        return;
    }
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
        "namespace_identifier"
            if recovered_macro_function_return_type(node).is_some()
                || recovered_qualified_declarator_type(node) =>
        {
            record_type_reference(node, ctx);
        }
        // A type reference (`Foo x`, base class, `new Foo()`'s type child) resolves
        // to the class. `new Foo()` reaches its type via this case (its type child
        // is itself one of these nodes), so there is no separate construction case.
        "type_identifier" | "qualified_identifier" | "scoped_type_identifier" | "template_type" => {
            if is_declaration_name(node) {
                if let Some(owners) = out_of_line_member_definition_owner(
                    ctx.analyzer,
                    ctx.visibility,
                    ctx.file,
                    ctx.source,
                    node,
                ) {
                    for (owner_node, owner) in owners.owners {
                        ctx.record(owner.fq_name(), owner_node);
                    }
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
            record_type_reference(node, ctx);
        }
        "call_expression" => record_call(node, ctx, bindings),
        _ => {}
    }
}

fn record_type_reference(node: Node<'_>, ctx: &mut CppScan<'_, '_>) {
    match resolve_type_node_lexically(
        node,
        ctx.analyzer,
        ctx.visibility,
        &ctx.ordinary_type_imports,
        ctx.file,
        ctx.source,
    ) {
        LexicalTypeResolution::Resolved { unit, .. } => ctx.record(unit.fq_name(), node),
        LexicalTypeResolution::Ambiguous | LexicalTypeResolution::Missing => {}
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
    let Some(call_arity) = ctx
        .visibility
        .call_arity_evidence(ctx.file, node, ctx.source)
        .exact()
    else {
        let name_node = function
            .child_by_field_name("field")
            .or_else(|| function.child_by_field_name("name"))
            .unwrap_or(function);
        let name = node_text(name_node, ctx.source);
        if !name.is_empty() {
            ctx.record_unproven(name, name_node);
        }
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
            if let Some(receiver_owner) = receiver_type_unit(receiver, ctx, bindings, 32) {
                match resolve_declaring_member_owner_cached(ctx, &receiver_owner, name) {
                    EnclosingMemberOwnerResolution::Owner(owner) => {
                        match ctx
                            .visibility
                            .visible_member_for_owner_name(ctx.file, &owner, name)
                        {
                            VisibleMemberResolution::Callable(callables) => {
                                if let Some(callable) = callables.iter().find(|callable| {
                                    cpp_callable_arity(ctx.analyzer, callable).accepts(call_arity)
                                }) {
                                    ctx.record(callable.fq_name(), field);
                                }
                            }
                            VisibleMemberResolution::AmbiguousKind => {
                                ctx.record_unproven(name, field);
                            }
                            VisibleMemberResolution::NonCallable
                            | VisibleMemberResolution::Missing => {}
                        }
                    }
                    EnclosingMemberOwnerResolution::Ambiguous => {
                        ctx.record_unproven(name, field);
                    }
                    EnclosingMemberOwnerResolution::Missing => {}
                }
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
            if bindings.is_shadowed(name) {
                return;
            }
            if let Some(enclosing_owner) = enclosing_callable_owner(function, ctx) {
                match resolve_declaring_member_owner_cached(ctx, &enclosing_owner, name) {
                    EnclosingMemberOwnerResolution::Owner(owner)
                        if !same_visible_symbol(&owner, &enclosing_owner) =>
                    {
                        match ctx
                            .visibility
                            .visible_member_for_owner_name(ctx.file, &owner, name)
                        {
                            VisibleMemberResolution::Callable(callables) => {
                                if let Some(callable) = callables.first() {
                                    ctx.record(callable.fq_name(), function);
                                }
                            }
                            VisibleMemberResolution::AmbiguousKind => {
                                ctx.record_unproven(name, function);
                            }
                            VisibleMemberResolution::NonCallable
                            | VisibleMemberResolution::Missing => {}
                        }
                        return;
                    }
                    EnclosingMemberOwnerResolution::Owner(_) => return,
                    EnclosingMemberOwnerResolution::Ambiguous => {
                        ctx.record_unproven(name, function);
                        return;
                    }
                    EnclosingMemberOwnerResolution::Missing => {}
                }
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
            // Direct/self member calls are intentionally omitted above; unique inherited
            // callable owners are recorded, while an unresolved bare name adds no edge.
        }
        _ => {}
    }
}

fn resolve_declaring_member_owner_cached(
    ctx: &mut CppScan<'_, '_>,
    receiver_owner: &CodeUnit,
    name: &str,
) -> EnclosingMemberOwnerResolution {
    if let Some(cached) = ctx
        .declaring_member_cache
        .get(receiver_owner)
        .and_then(|by_name| by_name.get(name))
        .cloned()
    {
        return cached;
    }
    let resolution = resolve_declaring_member_owner(
        ctx.analyzer,
        ctx.visibility,
        ctx.file,
        receiver_owner,
        name,
    );
    ctx.declaring_member_cache
        .entry(receiver_owner.clone())
        .or_default()
        .insert(name.to_string(), resolution.clone());
    resolution
}

fn enclosing_callable_owner(node: Node<'_>, ctx: &CppScan<'_, '_>) -> Option<CodeUnit> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "function_definition" {
            let declarator = parent.child_by_field_name("declarator")?;
            let function = declarator_name_node(declarator)?;
            if let Some(owners) = out_of_line_member_definition_owner(
                ctx.analyzer,
                ctx.visibility,
                ctx.file,
                ctx.source,
                function,
            ) && let Some((_, owner)) = owners.innermost()
            {
                return Some(owner.clone());
            }
            break;
        }
        current = parent.parent();
    }
    ctx.enclosing_class(node.start_byte()).and_then(|fqn| {
        ctx.analyzer
            .definitions(fqn)
            .find(|candidate| candidate.is_class())
    })
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

fn receiver_type_unit(
    receiver: Node<'_>,
    ctx: &CppScan<'_, '_>,
    bindings: &LocalInferenceEngine<CodeUnit>,
    remaining_call_depth: usize,
) -> Option<CodeUnit> {
    match receiver.kind() {
        "identifier" => {
            let name = node_text(receiver, ctx.source);
            // A typed local resolves to its type; otherwise the name may itself be a
            // type, unless it is a known (shadowed) untyped local — never reinterpret
            // a value as a static type.
            first_precise(bindings, name).or_else(|| {
                (!bindings.is_shadowed(name))
                    .then(|| ctx.resolve_type(name))
                    .flatten()
            })
        }
        "this" => ctx.enclosing_class(receiver.start_byte()).and_then(|fqn| {
            ctx.analyzer
                .definitions(fqn)
                .find(|candidate| candidate.is_class())
        }),
        // `(*p).m()` / `(p).m()` unwrap to the inner receiver.
        "parenthesized_expression" | "pointer_expression" => receiver
            .child_by_field_name("argument")
            .or_else(|| receiver.named_child(0))
            .and_then(|inner| receiver_type_unit(inner, ctx, bindings, remaining_call_depth)),
        "call_expression" if remaining_call_depth > 0 => infer_cpp_initializer_binding(
            ctx.analyzer,
            ctx.visibility,
            ctx.file,
            ctx.source,
            receiver,
            Some(&|inner, _source| {
                receiver_type_unit(inner, ctx, bindings, remaining_call_depth - 1)
                    .into_iter()
                    .collect()
            }),
        )
        .and_then(|binding| binding.unit),
        _ => None,
    }
}

fn seed_declaration(
    node: Node<'_>,
    ctx: &mut CppScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<CodeUnit>,
) {
    if crate::analyzer::cpp::is_direct_recovered_exported_class_field_declaration(node, ctx.source)
    {
        return;
    }
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
    let type_node = node
        .child_by_field_name("type")
        .or_else(|| first_type_child(node));
    seed_binding(&name, type_node, None, ctx, bindings);
}

fn seed_variable_declaration(
    node: Node<'_>,
    ctx: &CppScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<CodeUnit>,
) {
    let type_node = node
        .child_by_field_name("type")
        .or_else(|| first_type_child(node));
    let type_text =
        type_node.map(|type_node| normalize_type_text(node_text(type_node, ctx.source)));
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
        seed_binding(&name, type_node, value, ctx, bindings);
    }
}

fn seed_binding(
    name: &str,
    type_node: Option<Node<'_>>,
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
    let declared_type =
        type_node.filter(|node| normalize_type_text(node_text(*node, ctx.source)) != "auto");
    let resolved = match declared_type {
        Some(node) => match ctx.resolve_type_node_result(node) {
            Ok(Some(unit)) => Some(unit),
            Ok(None) => ctx.resolve_type(node_text(node, ctx.source)),
            Err(()) => None,
        },
        None => value.and_then(|value| infer_type_from_value(value, ctx)),
    };
    match resolved {
        Some(unit) => bindings.seed_symbol(name.to_string(), unit),
        None => bindings.declare_shadow(name.to_string()),
    }
}

/// Infer a class type from an initializer expression for `auto`/untyped locals.
fn infer_type_from_value(node: Node<'_>, ctx: &CppScan<'_, '_>) -> Option<CodeUnit> {
    infer_cpp_initializer_type(ctx.analyzer, ctx.visibility, ctx.file, ctx.source, node)
}
