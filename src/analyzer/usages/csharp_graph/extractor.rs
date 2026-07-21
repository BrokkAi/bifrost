use crate::analyzer::usages::csharp_graph::hits::{push_hit, push_unproven_hit};
use crate::analyzer::usages::csharp_graph::resolver::{
    TargetKind, TargetSpec, UnqualifiedMethodGroupResolution,
    applicable_member_candidates_for_owner, argument_count, binding_scope_node,
    class_unit_for_fq_name, enclosing_declared_type, extension_visibility_site_key,
    first_type_child, is_type_reference_node, member_name_is_locally_bound,
    nearest_member_candidates_for_owner, node_text, normalize_type_text,
    object_initializer_for_label, object_initializer_owner_type_node, receiver_targets_owner,
    reference_type_text, resolve_type_fq_name_at, resolve_unqualified_method_group_for_owner,
    resolves_to_target, resolves_to_target_at, same_node, seed_visible_bindings_at,
    type_identity_matches, unqualified_member_has_local_binding,
    unqualified_member_has_structured_shadow, unqualified_member_resolves_to_owner,
    usage_class_field_receiver_type, usage_visible_extension_method_candidates,
};
use crate::analyzer::usages::inverted_edges::ClassRangeIndex;
use crate::analyzer::usages::local_inference::SymbolResolution;
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::{
    CSharpAnalyzer, CodeUnit, IAnalyzer, ProjectFile, csharp_attribute_terminal_name,
    csharp_attribute_type_names, csharp_conditional_member_access,
    csharp_constant_pattern_type_candidate, csharp_member_access_type_receiver, csharp_member_name,
    csharp_nameof_type_candidates, csharp_type_leftmost_identifier, csharp_type_reference_root,
    csharp_type_terminal_identifier, csharp_unqualified_invocation_for_name,
};
use crate::hash::HashMap;
use crate::text_utils::compute_line_starts;
use std::collections::BTreeSet;
use tree_sitter::{Node, Parser, Tree};

pub(super) struct ScanState<'a> {
    pub(super) max_usages: usize,
    pub(super) hits: &'a mut BTreeSet<UsageHit>,
    pub(super) unproven_hits: &'a mut BTreeSet<UsageHit>,
    pub(super) limit_exceeded: &'a mut bool,
}

pub(super) struct PreparedCSharpFile {
    source: String,
    tree: Tree,
    line_starts: Vec<usize>,
    class_ranges: ClassRangeIndex,
}

pub(super) fn prepare_file(
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
) -> Option<PreparedCSharpFile> {
    let Ok(source) = file.read_to_string() else {
        return None;
    };
    if source.is_empty() {
        return None;
    }
    if crate::analyzer::common::is_unparseable_source(&source) {
        return None;
    }

    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
        .is_err()
    {
        return None;
    }
    let tree = parser.parse(source.as_str(), None)?;
    let line_starts = compute_line_starts(&source);
    let class_ranges = ClassRangeIndex::build(csharp, file);
    Some(PreparedCSharpFile {
        source,
        tree,
        line_starts,
        class_ranges,
    })
}

pub(super) fn scan_prepared_file(
    csharp: &CSharpAnalyzer,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    prepared: &PreparedCSharpFile,
    spec: &TargetSpec,
    state: &mut ScanState<'_>,
) {
    if *state.limit_exceeded {
        return;
    }

    let mut ctx = ScanCtx {
        csharp,
        analyzer,
        file,
        source: &prepared.source,
        line_starts: &prepared.line_starts,
        spec,
        hits: state.hits,
        unproven_hits: state.unproven_hits,
        max_usages: state.max_usages,
        limit_exceeded: state.limit_exceeded,
        enclosing_cache: HashMap::default(),
        nearest_member_target_cache: HashMap::default(),
        extension_target_cache: HashMap::default(),
        class_ranges: prepared.class_ranges.clone(),
    };
    scan_node(prepared.tree.root_node(), &mut ctx);
}

pub(super) struct ScanCtx<'a> {
    pub(super) csharp: &'a CSharpAnalyzer,
    pub(super) analyzer: &'a dyn IAnalyzer,
    pub(super) file: &'a ProjectFile,
    pub(super) source: &'a str,
    pub(super) line_starts: &'a [usize],
    pub(super) spec: &'a TargetSpec,
    pub(super) hits: &'a mut BTreeSet<UsageHit>,
    pub(super) unproven_hits: &'a mut BTreeSet<UsageHit>,
    pub(super) max_usages: usize,
    pub(super) limit_exceeded: &'a mut bool,
    pub(super) enclosing_cache: HashMap<(usize, usize), Option<CodeUnit>>,
    nearest_member_target_cache:
        HashMap<(String, Option<usize>, Option<usize>), TargetMemberResolution>,
    extension_target_cache: HashMap<ExtensionTargetCacheKey, TargetMemberResolution>,
    pub(super) class_ranges: ClassRangeIndex,
}

type ExtensionTargetCacheKey = (Vec<String>, usize, Option<usize>, usize, usize);

#[derive(Clone, Copy, PartialEq, Eq)]
enum TargetMemberResolution {
    MatchesTarget,
    KnownOther,
    NotFound,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TypeCandidateRole {
    Ordinary,
    Nameof,
    Pattern,
    Receiver,
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
    if node.kind() == "attribute" {
        scan_attribute_reference(node, ctx);
        return;
    }
    if let Some(candidate) = csharp_constant_pattern_type_candidate(node) {
        scan_structured_type_candidate(candidate, TypeCandidateRole::Pattern, true, ctx);
    }
    if let Some(receiver) = csharp_member_access_type_receiver(node) {
        scan_structured_type_candidate(receiver, TypeCandidateRole::Receiver, true, ctx);
    }
    if let Some((operand, qualified_owner)) = csharp_nameof_type_candidates(node, ctx.source)
        && !scan_structured_type_candidate(operand, TypeCandidateRole::Nameof, false, ctx)
        && let Some(owner) = qualified_owner
    {
        scan_structured_type_candidate(owner, TypeCandidateRole::Nameof, false, ctx);
    }
    let Some(root) = csharp_type_reference_root(node) else {
        return;
    };
    if !same_node(root, node) || is_declaration_name(root) {
        return;
    }
    scan_structured_type_candidate(root, TypeCandidateRole::Ordinary, true, ctx);
}

fn scan_structured_type_candidate(
    candidate: Node<'_>,
    role: TypeCandidateRole,
    filter_by_target_name: bool,
    ctx: &mut ScanCtx<'_>,
) -> bool {
    let Some(terminal) = csharp_type_terminal_identifier(candidate) else {
        return false;
    };
    let raw_name = normalize_type_text(node_text(terminal, ctx.source));
    if filter_by_target_name
        && raw_name != ctx.spec.member_name
        && !ctx
            .csharp
            .using_aliases_of(ctx.file)
            .contains_key(&raw_name)
    {
        return false;
    }

    if role != TypeCandidateRole::Ordinary {
        let Some(leftmost) = csharp_type_leftmost_identifier(candidate) else {
            return false;
        };
        let left_name = normalize_type_text(node_text(leftmost, ctx.source));
        let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
        seed_visible_bindings_at(
            binding_scope_node(candidate),
            candidate,
            ctx.csharp,
            ctx.file,
            ctx.source,
            &mut bindings,
        );
        if member_name_is_locally_bound(&left_name, &bindings)
            || unqualified_member_has_structured_shadow(leftmost, ctx.source)
            || !usage_class_field_receiver_type(
                leftmost,
                &left_name,
                ctx.analyzer,
                ctx.csharp,
                ctx.file,
                ctx.source,
            )
            .is_unknown()
        {
            return false;
        }
    }

    let reference = reference_type_text(candidate, ctx.source);
    match resolve_type_fq_name_at(
        ctx.csharp,
        ctx.file,
        &ctx.class_ranges,
        &reference,
        candidate,
        ctx.source,
    ) {
        Some(resolved) if type_identity_matches(&resolved, &ctx.spec.target.fq_name()) => {
            push_hit(candidate, ctx);
            true
        }
        Some(resolved)
            if role == TypeCandidateRole::Receiver
                && csharp_receiver_member_selects_visible_target(
                    candidate, &reference, &resolved, ctx,
                ) =>
        {
            push_hit(candidate, ctx);
            true
        }
        Some(_) => true,
        None if role == TypeCandidateRole::Receiver => {
            push_unproven_hit(candidate, ctx);
            false
        }
        None => false,
    }
}

fn csharp_receiver_member_selects_visible_target(
    receiver: Node<'_>,
    reference: &str,
    resolved_fqn: &str,
    ctx: &mut ScanCtx<'_>,
) -> bool {
    let Some(visible) = ctx.csharp.resolve_usage_visible_type(ctx.file, reference) else {
        return false;
    };
    if !type_identity_matches(&visible.fq_name(), &ctx.spec.target.fq_name()) {
        return false;
    }
    let Some(access) = receiver.parent().filter(|parent| {
        parent.kind() == "member_access_expression"
            && member_access_receiver(*parent).is_some_and(|node| same_node(node, receiver))
    }) else {
        return false;
    };
    let Some(member) = member_access_name(access).and_then(csharp_member_name) else {
        return false;
    };
    let member = node_text(member.identifier, ctx.source);
    let Some(resolved_owner) = class_unit_for_fq_name(ctx.csharp, resolved_fqn) else {
        return false;
    };
    nearest_member_candidates_for_owner(ctx.analyzer, ctx.csharp, &resolved_owner, member, None)
        .is_empty()
        && !nearest_member_candidates_for_owner(ctx.analyzer, ctx.csharp, &visible, member, None)
            .is_empty()
}

fn scan_attribute_reference(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    let Some(raw_terminal) = csharp_attribute_terminal_name(name, ctx.source) else {
        return;
    };
    let terminal = raw_terminal.strip_prefix('@').unwrap_or(raw_terminal);
    let target_name = ctx.spec.member_name.as_str();
    let exact_or_shorthand = terminal == target_name
        || target_name
            .strip_suffix("Attribute")
            .is_some_and(|stem| stem == terminal);
    let aliases = ctx.csharp.using_aliases_of(ctx.file);
    let alias = aliases.contains_key(raw_terminal) || aliases.contains_key(terminal);
    if !exact_or_shorthand && !alias {
        return;
    }
    let names = csharp_attribute_type_names(name, ctx.source);
    if ctx
        .csharp
        .usage_unambiguous_attribute_type_candidates(ctx.file, &names)
        .into_iter()
        .any(|candidate| type_identity_matches(&candidate.fq_name(), &ctx.spec.target.fq_name()))
    {
        push_hit(name, ctx);
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
    let reference = reference_type_text(type_node, ctx.source);
    let resolved = resolves_to_target_at(
        ctx.file,
        &ctx.class_ranges,
        &reference,
        type_node,
        ctx.source,
        &ctx.spec.owner,
        ctx.csharp,
    );
    if !resolved {
        return;
    }
    if ctx
        .spec
        .callable_arity
        .is_some_and(|arity| !arity.accepts(argument_count(node, ctx.source)))
    {
        return;
    }
    push_hit(type_node, ctx);
}

fn scan_member_reference(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let access = match node.kind() {
        "member_access_expression" => member_access_receiver(node).zip(member_access_name(node)),
        "conditional_access_expression" => {
            csharp_conditional_member_access(node).map(|access| (access.receiver, access.name))
        }
        _ => None,
    };
    let Some((receiver_node, name_node)) = access else {
        return;
    };
    let Some(name) = csharp_member_name(name_node) else {
        return;
    };
    if node_text(name.identifier, ctx.source) != ctx.spec.member_name
        || (ctx.spec.kind == TargetKind::Method
            && !ctx
                .spec
                .accepts_explicit_generic_arity(name.explicit_generic_arity))
    {
        return;
    }
    // `nameof(receiver.Member)` is a compile-time string, not a member reference.
    if is_nameof_argument(node, ctx.source) {
        return;
    }
    let call_arity =
        enclosing_invocation(node).map(|invocation| argument_count(invocation, ctx.source));
    let ordinary_call_arity_matches = call_arity.is_none_or(|call_arity| {
        ctx.spec
            .callable_arity
            .is_none_or(|arity| arity.accepts(call_arity))
    });
    if ctx.spec.kind == TargetKind::Method
        && !ctx.spec.is_extension_method()
        && !ordinary_call_arity_matches
    {
        return;
    }

    let receiver = node_text(receiver_node, ctx.source);
    if receiver.is_empty() {
        push_unproven_hit(name.identifier, ctx);
        return;
    }

    if resolves_to_target(ctx.csharp, ctx.file, receiver, &ctx.spec.owner) {
        if ctx.spec.kind == TargetKind::Method && !ordinary_call_arity_matches {
            return;
        }
        push_hit(name.identifier, ctx);
        return;
    }

    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    seed_visible_bindings_at(
        binding_scope_node(node),
        node,
        ctx.csharp,
        ctx.file,
        ctx.source,
        &mut bindings,
    );
    if ctx.spec.kind == TargetKind::Method && ctx.spec.is_extension_method() {
        match receiver_targets_owner(
            receiver_node,
            ctx.analyzer,
            ctx.csharp,
            ctx.file,
            ctx.source,
            &bindings,
        ) {
            SymbolResolution::Precise(targets) => {
                let receiver_type_names = targets.into_iter().collect::<Vec<_>>();
                if extension_call_resolution(
                    node,
                    name.identifier,
                    name.explicit_generic_arity,
                    &receiver_type_names,
                    ctx,
                ) == TargetMemberResolution::MatchesTarget
                {
                    push_hit(name.identifier, ctx);
                }
            }
            SymbolResolution::Ambiguous | SymbolResolution::Unknown => {
                if extension_call_resolution(
                    node,
                    name.identifier,
                    name.explicit_generic_arity,
                    &[],
                    ctx,
                ) == TargetMemberResolution::MatchesTarget
                {
                    push_unproven_hit(name.identifier, ctx);
                }
            }
        }
        return;
    }
    match receiver_targets_owner(
        receiver_node,
        ctx.analyzer,
        ctx.csharp,
        ctx.file,
        ctx.source,
        &bindings,
    ) {
        SymbolResolution::Precise(targets)
            if targets.iter().any(|target| {
                receiver_fqn_target_member_resolution(
                    target,
                    name.explicit_generic_arity,
                    call_arity,
                    ctx,
                ) == TargetMemberResolution::MatchesTarget
            }) =>
        {
            push_hit(name.identifier, ctx);
        }
        SymbolResolution::Ambiguous => {
            push_unproven_hit(name.identifier, ctx);
        }
        SymbolResolution::Unknown => {
            push_unproven_hit(name.identifier, ctx);
        }
        SymbolResolution::Precise(_) => {}
    }
}

fn extension_call_resolution(
    member_access: Node<'_>,
    name: Node<'_>,
    explicit_generic_arity: Option<usize>,
    receiver_type_names: &[String],
    ctx: &mut ScanCtx<'_>,
) -> TargetMemberResolution {
    let Some(invocation) = enclosing_invocation(member_access) else {
        return TargetMemberResolution::NotFound;
    };
    let call_arity = argument_count(invocation, ctx.source);
    let mut normalized_receivers = receiver_type_names.to_vec();
    normalized_receivers.sort();
    normalized_receivers.dedup();
    let (scope_start, scope_end) = extension_visibility_site_key(name);
    let cache_key = (
        normalized_receivers,
        call_arity,
        explicit_generic_arity,
        scope_start,
        scope_end,
    );
    if let Some(resolution) = ctx.extension_target_cache.get(&cache_key) {
        return *resolution;
    }
    let ordinary_member_is_applicable = receiver_type_names.iter().any(|receiver_fqn| {
        class_unit_for_fq_name(ctx.csharp, receiver_fqn).is_some_and(|owner| {
            applicable_member_candidates_for_owner(
                ctx.analyzer,
                ctx.csharp,
                &owner,
                &ctx.spec.member_name,
                explicit_generic_arity,
                call_arity,
            )
            .into_iter()
            .any(|candidate| candidate.is_function())
        })
    });
    if ordinary_member_is_applicable {
        ctx.extension_target_cache
            .insert(cache_key, TargetMemberResolution::KnownOther);
        return TargetMemberResolution::KnownOther;
    }
    let candidates = usage_visible_extension_method_candidates(
        ctx.csharp,
        ctx.analyzer,
        ctx.source,
        name,
        receiver_type_names,
        &ctx.spec.member_name,
        Some(call_arity),
        explicit_generic_arity,
        false,
    );
    let resolution = if candidates.contains(&ctx.spec.target) {
        TargetMemberResolution::MatchesTarget
    } else if candidates.is_empty() {
        TargetMemberResolution::NotFound
    } else {
        TargetMemberResolution::KnownOther
    };
    ctx.extension_target_cache.insert(cache_key, resolution);
    resolution
}

fn scan_unqualified_member_reference(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node.kind() != "identifier" || is_declaration_name(node) {
        return;
    }
    if node_text(node, ctx.source) != ctx.spec.member_name {
        return;
    }
    if identifier_is_member_access_name(node) {
        return;
    }
    match ctx.spec.kind {
        TargetKind::Method if csharp_unqualified_invocation_for_name(node).is_some() => {
            let (invocation, explicit_generic_arity) =
                csharp_unqualified_invocation_for_name(node).expect("call shape was checked");
            match unqualified_method_call_resolution(node, invocation, explicit_generic_arity, ctx)
            {
                TargetMemberResolution::MatchesTarget => push_hit(node, ctx),
                TargetMemberResolution::KnownOther => {}
                TargetMemberResolution::NotFound => push_unproven_hit(node, ctx),
            }
        }
        TargetKind::Method if is_unqualified_method_group_value(node, ctx.source) => {
            let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
            seed_visible_bindings_at(
                binding_scope_node(node),
                node,
                ctx.csharp,
                ctx.file,
                ctx.source,
                &mut bindings,
            );
            if unqualified_member_has_local_binding(node, ctx.source, &bindings)
                || unqualified_member_has_structured_shadow(node, ctx.source)
            {
                return;
            }
            let Some(owner_fqn) = ctx
                .class_ranges
                .enclosing(node.start_byte())
                .map(str::to_string)
            else {
                return;
            };
            let Some(owner) = class_unit_for_fq_name(ctx.csharp, &owner_fqn) else {
                return;
            };
            match resolve_unqualified_method_group_for_owner(
                ctx.analyzer,
                ctx.csharp,
                &owner,
                node_text(node, ctx.source),
            ) {
                UnqualifiedMethodGroupResolution::Unique(candidate)
                    if candidate == ctx.spec.target =>
                {
                    push_hit(node, ctx);
                }
                UnqualifiedMethodGroupResolution::Ambiguous(candidates)
                    if candidates.contains(&ctx.spec.target) =>
                {
                    push_unproven_hit(node, ctx);
                }
                UnqualifiedMethodGroupResolution::Unique(_)
                | UnqualifiedMethodGroupResolution::Ambiguous(_)
                | UnqualifiedMethodGroupResolution::NoMember => {}
            }
        }
        TargetKind::Field if !is_type_reference_node(node) => {
            // `nameof(Field)` is a compile-time string, not a member reference.
            if is_nameof_argument(node, ctx.source) {
                return;
            }
            let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
            seed_visible_bindings_at(
                binding_scope_node(node),
                node,
                ctx.csharp,
                ctx.file,
                ctx.source,
                &mut bindings,
            );
            match object_initializer_label_owner_resolution(node, ctx) {
                LabelOwnerResolution::MatchesTarget => {
                    push_hit(node, ctx);
                    return;
                }
                LabelOwnerResolution::KnownOther => return,
                LabelOwnerResolution::Unknown => {
                    push_unproven_hit(node, ctx);
                    return;
                }
                LabelOwnerResolution::NotLabel => {}
            }
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
                ctx.analyzer,
                ctx.csharp,
                ctx.file,
                ctx.source,
                &bindings,
            ) {
                push_hit(node, ctx);
            } else {
                push_unproven_hit(node, ctx);
            }
        }
        _ => {}
    }
}

pub(super) fn is_unqualified_method_group_value(node: Node<'_>, source: &str) -> bool {
    if node.kind() != "identifier"
        || is_declaration_name(node)
        || is_type_reference_node(node)
        || is_nameof_argument(node, source)
    {
        return false;
    }
    containing_method_group_value_context(node)
}

fn containing_method_group_value_context(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "argument" => return parent.child_by_field_name("name") != Some(node),
            "assignment_expression" => {
                return parent.child_by_field_name("right") == Some(current)
                    && parent
                        .child_by_field_name("operator")
                        .is_some_and(|operator| matches!(operator.kind(), "=" | "+=" | "-="));
            }
            "variable_declarator" => {
                return parent.child_by_field_name("name") != Some(current)
                    && parent.named_child(parent.named_child_count().saturating_sub(1))
                        == Some(current);
            }
            "property_declaration" => {
                return parent.child_by_field_name("value") == Some(current);
            }
            _ => {}
        }
        if transparent_expression_parent(current, parent) {
            current = parent;
        } else {
            return false;
        }
    }
    false
}

fn transparent_expression_parent(current: Node<'_>, parent: Node<'_>) -> bool {
    matches!(
        parent.kind(),
        "parenthesized_expression" | "checked_expression"
    ) || (parent.kind() == "cast_expression"
        && parent.child_by_field_name("value") == Some(current))
        || (parent.kind() == "postfix_unary_expression"
            && parent.named_child(0) == Some(current)
            && parent
                .child(parent.child_count().saturating_sub(1))
                .is_some_and(|operator| operator.kind() == "!"))
}

fn unqualified_method_call_resolution(
    node: Node<'_>,
    invocation: Node<'_>,
    explicit_generic_arity: Option<usize>,
    ctx: &mut ScanCtx<'_>,
) -> TargetMemberResolution {
    if !ctx
        .spec
        .accepts_explicit_generic_arity(explicit_generic_arity)
    {
        return TargetMemberResolution::NotFound;
    }
    if ctx
        .spec
        .callable_arity
        .is_some_and(|arity| !arity.accepts(argument_count(invocation, ctx.source)))
    {
        // A signature-specific target is incompatible, but FQN-grouped callers
        // still need conservative cross-overload evidence rather than a proof of
        // absence for the sibling declaration.
        return TargetMemberResolution::NotFound;
    }
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    seed_visible_bindings_at(
        binding_scope_node(node),
        node,
        ctx.csharp,
        ctx.file,
        ctx.source,
        &mut bindings,
    );
    if unqualified_member_has_local_binding(node, ctx.source, &bindings)
        || unqualified_member_has_structured_shadow(node, ctx.source)
    {
        return TargetMemberResolution::KnownOther;
    }
    enclosing_declared_type(node, ctx.csharp, ctx.file, ctx.source)
        .map(|enclosing| {
            receiver_fqn_target_member_resolution(
                &enclosing.fq_name(),
                explicit_generic_arity,
                Some(argument_count(invocation, ctx.source)),
                ctx,
            )
        })
        .unwrap_or(TargetMemberResolution::NotFound)
}

fn receiver_fqn_target_member_resolution(
    receiver_fqn: &str,
    explicit_generic_arity: Option<usize>,
    call_arity: Option<usize>,
    ctx: &mut ScanCtx<'_>,
) -> TargetMemberResolution {
    let key = (receiver_fqn.to_string(), explicit_generic_arity, call_arity);
    if let Some(resolution) = ctx.nearest_member_target_cache.get(&key) {
        return *resolution;
    }
    let resolution = class_unit_for_fq_name(ctx.csharp, receiver_fqn)
        .map(|receiver_owner| {
            call_arity.map_or_else(
                || {
                    nearest_member_candidates_for_owner(
                        ctx.analyzer,
                        ctx.csharp,
                        &receiver_owner,
                        &ctx.spec.member_name,
                        explicit_generic_arity,
                    )
                },
                |arity| {
                    applicable_member_candidates_for_owner(
                        ctx.analyzer,
                        ctx.csharp,
                        &receiver_owner,
                        &ctx.spec.member_name,
                        explicit_generic_arity,
                        arity,
                    )
                },
            )
        })
        .map(|candidates| {
            if candidates.contains(&ctx.spec.target) {
                TargetMemberResolution::MatchesTarget
            } else if candidates.is_empty() {
                TargetMemberResolution::NotFound
            } else {
                TargetMemberResolution::KnownOther
            }
        })
        .unwrap_or(TargetMemberResolution::NotFound);
    ctx.nearest_member_target_cache.insert(key, resolution);
    resolution
}

fn identifier_is_member_access_name(node: Node<'_>) -> bool {
    let name_node = node
        .parent()
        .filter(|parent| parent.kind() == "generic_name")
        .unwrap_or(node);
    name_node
        .parent()
        .is_some_and(|parent| match parent.kind() {
            "member_access_expression" => member_access_name(parent) == Some(name_node),
            "member_binding_expression" => parent.child_by_field_name("name") == Some(name_node),
            _ => false,
        })
}

enum LabelOwnerResolution {
    NotLabel,
    MatchesTarget,
    KnownOther,
    Unknown,
}

fn object_initializer_label_owner_resolution(
    node: Node<'_>,
    ctx: &mut ScanCtx<'_>,
) -> LabelOwnerResolution {
    let Some(initializer) = object_initializer_for_label(node) else {
        return LabelOwnerResolution::NotLabel;
    };
    let Some(type_node) = object_initializer_owner_type_node(initializer) else {
        return LabelOwnerResolution::Unknown;
    };
    let Some(receiver_fqn) = resolve_type_fq_name_at(
        ctx.csharp,
        ctx.file,
        &ctx.class_ranges,
        &reference_type_text(type_node, ctx.source),
        type_node,
        ctx.source,
    ) else {
        return LabelOwnerResolution::Unknown;
    };
    match receiver_fqn_target_member_resolution(&receiver_fqn, None, None, ctx) {
        TargetMemberResolution::MatchesTarget => LabelOwnerResolution::MatchesTarget,
        TargetMemberResolution::KnownOther => LabelOwnerResolution::KnownOther,
        TargetMemberResolution::NotFound => LabelOwnerResolution::Unknown,
    }
}

/// Whether `node` is the argument of a `nameof(...)` expression.
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
            _ if transparent_expression_parent(current, parent) => current = parent,
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
