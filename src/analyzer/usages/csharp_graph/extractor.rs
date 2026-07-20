use crate::analyzer::usages::csharp_graph::hits::{push_hit, push_unproven_hit};
use crate::analyzer::usages::csharp_graph::resolver::{
    TargetKind, TargetSpec, UnqualifiedMethodGroupResolution, argument_count, binding_scope_node,
    class_unit_for_fq_name, enclosing_declared_type, expression_resolves_to_type,
    extension_visibility_site_key, first_type_child, is_type_reference_node,
    member_name_is_locally_bound, nearest_member_candidates_for_owner, node_text,
    normalize_type_text, object_initializer_for_label, receiver_targets_owner, reference_type_node,
    reference_type_text, resolve_unqualified_method_group_for_owner, resolves_to_target,
    resolves_to_target_at, same_node, seed_visible_bindings_at, type_identity_matches,
    unqualified_member_has_local_binding, unqualified_member_has_structured_shadow,
    unqualified_member_resolves_to_owner, usage_class_field_receiver_type,
    usage_visible_extension_method_candidates,
};
use crate::analyzer::usages::inverted_edges::ClassRangeIndex;
use crate::analyzer::usages::local_inference::SymbolResolution;
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::{
    CSharpAnalyzer, CodeUnit, IAnalyzer, ProjectFile, csharp_attribute_terminal_name,
    csharp_attribute_type_names, csharp_callable_arity, csharp_conditional_member_access,
    csharp_member_name, csharp_unqualified_invocation_for_name,
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
    nearest_member_target_cache: HashMap<(String, Option<usize>), TargetMemberResolution>,
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
    if !matches!(node.kind(), "identifier" | "type") || is_declaration_name(node) {
        return;
    }
    if !is_type_reference_node(node) {
        scan_static_type_qualifier(node, ctx);
        return;
    }
    let raw_name = normalize_type_text(node_text(node, ctx.source));
    if raw_name != ctx.spec.member_name
        && !ctx
            .csharp
            .using_aliases_of(ctx.file)
            .contains_key(&raw_name)
    {
        return;
    }
    let reference_node = reference_type_node(node);
    let reference = reference_type_text(reference_node, ctx.source);
    if type_reference_resolves_to_target(node, ctx, &reference) {
        push_hit(reference_node, ctx);
    }
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

fn scan_static_type_qualifier(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node.kind() != "identifier" || !is_member_access_expression_receiver(node) {
        return;
    }
    let raw_name = normalize_type_text(node_text(node, ctx.source));
    if raw_name != ctx.spec.member_name
        && !ctx
            .csharp
            .using_aliases_of(ctx.file)
            .contains_key(&raw_name)
    {
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
    if !bindings.resolve_symbol(&raw_name).is_unknown()
        || !usage_class_field_receiver_type(node, &raw_name, ctx.csharp, ctx.file, ctx.source)
            .is_unknown()
    {
        return;
    }

    if type_reference_resolves_to_target(node, ctx, &raw_name) {
        push_hit(node, ctx);
    } else {
        push_unproven_hit(node, ctx);
    }
}

fn is_member_access_expression_receiver(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "member_access_expression"
            && member_access_receiver(parent).is_some_and(|receiver| same_node(receiver, node))
    })
}

fn type_reference_resolves_to_target(node: Node<'_>, ctx: &ScanCtx<'_>, reference: &str) -> bool {
    resolves_to_target_at(
        ctx.file,
        &ctx.class_ranges,
        reference,
        node,
        ctx.source,
        &ctx.spec.target,
        ctx.csharp,
    )
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
    let ordinary_call_arity_matches = enclosing_invocation(node).is_none_or(|invocation| {
        ctx.spec
            .callable_arity
            .is_none_or(|arity| arity.accepts(argument_count(invocation, ctx.source)))
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
        match receiver_targets_owner(receiver_node, ctx.csharp, ctx.file, ctx.source, &bindings) {
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
    match receiver_targets_owner(receiver_node, ctx.csharp, ctx.file, ctx.source, &bindings) {
        SymbolResolution::Precise(targets)
            if targets.iter().any(|target| {
                receiver_fqn_target_member_resolution(target, name.explicit_generic_arity, ctx)
                    == TargetMemberResolution::MatchesTarget
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
            nearest_member_candidates_for_owner(
                ctx.analyzer,
                ctx.csharp,
                &owner,
                &ctx.spec.member_name,
                explicit_generic_arity,
            )
            .into_iter()
            .any(|candidate| {
                candidate.is_function()
                    && csharp_callable_arity(ctx.analyzer, &candidate).accepts(call_arity)
            })
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
        TargetKind::Method if is_unqualified_method_group_argument(node, ctx.source) => {
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
            match object_initializer_label_owner_resolution(node, ctx, &bindings) {
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

pub(super) fn is_unqualified_method_group_argument(node: Node<'_>, source: &str) -> bool {
    if node.kind() != "identifier"
        || is_declaration_name(node)
        || is_type_reference_node(node)
        || is_nameof_argument(node, source)
    {
        return false;
    }
    let Some(argument) = containing_argument_through_transparent_expressions(node) else {
        return false;
    };
    argument.child_by_field_name("name") != Some(node)
}

fn containing_argument_through_transparent_expressions(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "argument" {
            return Some(parent);
        }
        if transparent_expression_parent(current, parent) {
            current = parent;
        } else {
            return None;
        }
    }
    None
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
            receiver_fqn_target_member_resolution(&enclosing.fq_name(), explicit_generic_arity, ctx)
        })
        .unwrap_or(TargetMemberResolution::NotFound)
}

fn receiver_fqn_target_member_resolution(
    receiver_fqn: &str,
    explicit_generic_arity: Option<usize>,
    ctx: &mut ScanCtx<'_>,
) -> TargetMemberResolution {
    let key = (receiver_fqn.to_string(), explicit_generic_arity);
    if let Some(resolution) = ctx.nearest_member_target_cache.get(&key) {
        return *resolution;
    }
    let resolution = class_unit_for_fq_name(ctx.csharp, receiver_fqn)
        .map(|receiver_owner| {
            nearest_member_candidates_for_owner(
                ctx.analyzer,
                ctx.csharp,
                &receiver_owner,
                &ctx.spec.member_name,
                explicit_generic_arity,
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
    ctx: &ScanCtx<'_>,
    bindings: &LocalInferenceEngine<String>,
) -> LabelOwnerResolution {
    let Some(initializer) = object_initializer_for_label(node) else {
        return LabelOwnerResolution::NotLabel;
    };
    let Some(object_creation) = initializer.parent() else {
        return LabelOwnerResolution::Unknown;
    };
    if object_creation.kind() != "object_creation_expression" {
        return LabelOwnerResolution::Unknown;
    }
    let Some(type_node) = object_creation
        .child_by_field_name("type")
        .or_else(|| first_type_child(object_creation))
    else {
        return LabelOwnerResolution::Unknown;
    };
    match expression_resolves_to_type(
        type_node,
        &ctx.spec.owner,
        ctx.csharp,
        ctx.file,
        ctx.source,
        bindings,
    ) {
        crate::analyzer::usages::local_inference::SymbolResolution::Precise(_) => {
            LabelOwnerResolution::MatchesTarget
        }
        crate::analyzer::usages::local_inference::SymbolResolution::Unknown
            if resolves_to_target_at(
                ctx.file,
                &ctx.class_ranges,
                &reference_type_text(type_node, ctx.source),
                type_node,
                ctx.source,
                &ctx.spec.owner,
                ctx.csharp,
            ) =>
        {
            LabelOwnerResolution::MatchesTarget
        }
        crate::analyzer::usages::local_inference::SymbolResolution::Unknown
            if ctx
                .csharp
                .resolve_usage_visible_type(ctx.file, &reference_type_text(type_node, ctx.source))
                .is_some() =>
        {
            LabelOwnerResolution::KnownOther
        }
        crate::analyzer::usages::local_inference::SymbolResolution::Unknown => {
            LabelOwnerResolution::Unknown
        }
        crate::analyzer::usages::local_inference::SymbolResolution::Ambiguous => {
            LabelOwnerResolution::Unknown
        }
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
