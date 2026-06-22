use crate::analyzer::usages::csharp_graph::hits::push_hit;
use crate::analyzer::usages::csharp_graph::resolver::{
    TargetKind, TargetSpec, argument_count, binding_scope_node, first_type_child,
    is_type_reference_node, member_name_is_locally_bound, node_text, normalize_type_text,
    receiver_targets_owner, reference_type_text, resolves_to_target, same_node,
    seed_bindings_before, unqualified_member_resolves_to_owner,
};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::{CSharpAnalyzer, CodeUnit, IAnalyzer, ProjectFile};
use crate::hash::HashMap;
use crate::text_utils::compute_line_starts;
use std::collections::BTreeSet;
use tree_sitter::{Node, Parser};

pub(super) struct ScanState<'a> {
    pub(super) max_usages: usize,
    pub(super) hits: &'a mut BTreeSet<UsageHit>,
    pub(super) saw_unproven_match: &'a mut bool,
    pub(super) limit_exceeded: &'a mut bool,
}

pub(super) fn scan_file(
    csharp: &CSharpAnalyzer,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    spec: &TargetSpec,
    state: &mut ScanState<'_>,
) {
    if *state.limit_exceeded {
        return;
    }
    let Ok(source) = file.read_to_string() else {
        return;
    };
    if source.is_empty() {
        return;
    }
    if crate::analyzer::common::is_unparseable_source(&source) {
        return;
    }

    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
        .is_err()
    {
        return;
    }
    let Some(tree) = parser.parse(source.as_str(), None) else {
        return;
    };
    let line_starts = compute_line_starts(&source);

    let mut ctx = ScanCtx {
        csharp,
        analyzer,
        file,
        source: &source,
        line_starts: &line_starts,
        spec,
        hits: state.hits,
        saw_unproven_match: state.saw_unproven_match,
        max_usages: state.max_usages,
        limit_exceeded: state.limit_exceeded,
        enclosing_cache: HashMap::default(),
    };
    scan_node(tree.root_node(), &mut ctx);
}

pub(super) struct ScanCtx<'a> {
    pub(super) csharp: &'a CSharpAnalyzer,
    pub(super) analyzer: &'a dyn IAnalyzer,
    pub(super) file: &'a ProjectFile,
    pub(super) source: &'a str,
    pub(super) line_starts: &'a [usize],
    pub(super) spec: &'a TargetSpec,
    pub(super) hits: &'a mut BTreeSet<UsageHit>,
    pub(super) saw_unproven_match: &'a mut bool,
    pub(super) max_usages: usize,
    pub(super) limit_exceeded: &'a mut bool,
    pub(super) enclosing_cache: HashMap<(usize, usize), Option<CodeUnit>>,
}

fn scan_node(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if *ctx.limit_exceeded {
        return;
    }

    match ctx.spec.kind {
        TargetKind::Type => scan_type_reference(node, ctx),
        TargetKind::Constructor => scan_constructor_reference(node, ctx),
        TargetKind::Method | TargetKind::Field => {
            scan_member_reference(node, ctx);
            scan_unqualified_member_reference(node, ctx);
        }
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_node(child, ctx);
        if *ctx.limit_exceeded {
            return;
        }
    }
}

fn scan_type_reference(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if !matches!(node.kind(), "identifier" | "type")
        || is_declaration_name(node)
        || !is_type_reference_node(node)
    {
        return;
    }
    if normalize_type_text(node_text(node, ctx.source)) != ctx.spec.member_name {
        return;
    }
    let reference = reference_type_text(node, ctx.source);
    if resolves_to_target(ctx.csharp, ctx.file, &reference, &ctx.spec.target) {
        push_hit(node, ctx);
    }
}

fn scan_constructor_reference(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node.kind() != "object_creation_expression" {
        return;
    }
    let Some(type_node) = node
        .child_by_field_name("type")
        .or_else(|| first_type_child(node))
    else {
        return;
    };
    if !resolves_to_target(
        ctx.csharp,
        ctx.file,
        node_text(type_node, ctx.source),
        &ctx.spec.owner,
    ) {
        return;
    }
    if ctx
        .spec
        .method_arity
        .is_some_and(|arity| argument_count(node, ctx.source) != arity)
    {
        return;
    }
    push_hit(type_node, ctx);
}

fn scan_member_reference(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node.kind() != "member_access_expression" {
        return;
    }
    let Some(name_node) = member_access_name(node) else {
        return;
    };
    if node_text(name_node, ctx.source) != ctx.spec.member_name {
        return;
    }
    if ctx.spec.kind == TargetKind::Method
        && let Some(invocation) = enclosing_invocation(node)
        && ctx
            .spec
            .method_arity
            .is_some_and(|arity| argument_count(invocation, ctx.source) != arity)
    {
        return;
    }

    let Some(receiver_node) = member_access_receiver(node) else {
        *ctx.saw_unproven_match = true;
        return;
    };
    let receiver = node_text(receiver_node, ctx.source);
    if receiver.is_empty() {
        *ctx.saw_unproven_match = true;
        return;
    }

    if resolves_to_target(ctx.csharp, ctx.file, receiver, &ctx.spec.owner) {
        push_hit(name_node, ctx);
        return;
    }

    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    seed_bindings_before(
        binding_scope_node(node),
        node.start_byte(),
        ctx.csharp,
        ctx.file,
        ctx.source,
        &mut bindings,
    );
    match receiver_targets_owner(
        receiver_node,
        receiver,
        &ctx.spec.owner,
        ctx.csharp,
        ctx.file,
        ctx.source,
        &bindings,
    ) {
        crate::analyzer::usages::local_inference::SymbolResolution::Precise(targets)
            if targets
                .iter()
                .any(|target| target == &ctx.spec.owner.fq_name()) =>
        {
            push_hit(name_node, ctx);
        }
        crate::analyzer::usages::local_inference::SymbolResolution::Ambiguous => {
            *ctx.saw_unproven_match = true;
        }
        crate::analyzer::usages::local_inference::SymbolResolution::Unknown
        | crate::analyzer::usages::local_inference::SymbolResolution::Precise(_) => {
            *ctx.saw_unproven_match = true;
        }
    }
}

fn scan_unqualified_member_reference(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node.kind() != "identifier" || is_declaration_name(node) {
        return;
    }
    if node_text(node, ctx.source) != ctx.spec.member_name {
        return;
    }
    if node
        .parent()
        .is_some_and(|parent| parent.kind() == "member_access_expression")
    {
        return;
    }
    match ctx.spec.kind {
        TargetKind::Method
            if node
                .parent()
                .is_some_and(|parent| parent.kind() == "invocation_expression") =>
        {
            *ctx.saw_unproven_match = true;
        }
        TargetKind::Field if !is_type_reference_node(node) => {
            // `nameof(Field)` is a compile-time string, not a member reference.
            if is_nameof_argument(node, ctx.source) {
                return;
            }
            let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
            seed_bindings_before(
                binding_scope_node(node),
                node.start_byte(),
                ctx.csharp,
                ctx.file,
                ctx.source,
                &mut bindings,
            );
            // A local or parameter of the same name is provably not the field. Skip
            // it silently — treating it as an unproven match would force the whole
            // file's result to a fallback and discard genuinely proven hits.
            if member_name_is_locally_bound(&ctx.spec.member_name, &bindings) {
                return;
            }
            if unqualified_member_resolves_to_owner(
                node,
                &ctx.spec.member_name,
                &ctx.spec.owner,
                ctx.csharp,
                ctx.file,
                ctx.source,
                &bindings,
            ) {
                push_hit(node, ctx);
            } else {
                *ctx.saw_unproven_match = true;
            }
        }
        _ => {}
    }
}

/// Whether `node` is the bare-identifier argument of a `nameof(...)` expression.
/// Walks up through the argument wrappers to the nearest invocation and checks the
/// invoked expression is `nameof`. `nameof(X)` evaluates to a compile-time string,
/// so its argument is not a runtime member reference.
fn is_nameof_argument(node: Node<'_>, source: &str) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "argument" | "argument_list" => current = parent,
            "invocation_expression" => {
                return parent
                    .child_by_field_name("function")
                    .or_else(|| parent.named_child(0))
                    .is_some_and(|function| node_text(function, source) == "nameof");
            }
            _ => return false,
        }
    }
    false
}

pub(in crate::analyzer::usages) fn is_declaration_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if matches!(
        parent.kind(),
        "class_declaration"
            | "interface_declaration"
            | "struct_declaration"
            | "enum_declaration"
            | "enum_member_declaration"
            | "record_declaration"
            | "record_struct_declaration"
            | "method_declaration"
            | "constructor_declaration"
            | "property_declaration"
            | "variable_declarator"
            | "using_directive"
    ) && parent
        .child_by_field_name("name")
        .is_some_and(|name| same_node(name, node))
    {
        return true;
    }
    false
}

pub(in crate::analyzer::usages) fn member_access_receiver(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("expression")
        .or_else(|| node.named_child(0))
}

pub(in crate::analyzer::usages) fn member_access_name(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("name").or_else(|| {
        let mut cursor = node.walk();
        let mut last = None;
        for child in node.named_children(&mut cursor) {
            if child.kind() == "identifier" {
                last = Some(child);
            }
        }
        last
    })
}

fn enclosing_invocation(node: Node<'_>) -> Option<Node<'_>> {
    let parent = node.parent()?;
    (parent.kind() == "invocation_expression").then_some(parent)
}
