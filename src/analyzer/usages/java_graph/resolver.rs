pub(super) use crate::analyzer::usages::common::node_text;
use crate::analyzer::usages::java_graph::extractor::ScanCtx;
use crate::analyzer::usages::java_graph::hits::enclosing_context;
use crate::analyzer::usages::java_graph::return_type::{
    FileReturnCache, JavaReturnTypeContext, LexicalTypeResolution, METHOD_RECEIVER_CHAIN_LIMIT,
    MethodReturnCache, is_java_nominal_type_node, java_lexical_type_from_node,
    java_type_name_from_node, method_return_type_for_owner_fqns,
};
use crate::analyzer::usages::local_inference::LocalInferenceEngine;
use crate::analyzer::usages::receiver_analysis::ReceiverAnalysisOutcome;
use crate::analyzer::{CallableArity, CodeUnit, IAnalyzer, JavaAnalyzer, ProjectFile};
use crate::hash::HashSet;
use tree_sitter::Node;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum TargetKind {
    Type,
    Constructor,
    Method,
    Field,
}

pub(super) struct TargetSpec {
    pub(super) target: CodeUnit,
    pub(super) targets: HashSet<CodeUnit>,
    pub(super) kind: TargetKind,
    pub(super) owner: CodeUnit,
    pub(super) receiver_owner_fq_names: HashSet<String>,
    pub(super) declaration_owner_fq_names: HashSet<String>,
    pub(super) member_name: String,
    pub(super) callable_arities: Option<HashSet<CallableArity>>,
}

impl TargetSpec {
    pub(super) fn from_targets(analyzer: &JavaAnalyzer, targets: &[CodeUnit]) -> Option<Self> {
        let mut spec = Self::from_target(analyzer, targets.first()?)?;
        spec.targets.extend(targets.iter().cloned());
        if let Some(arities) = spec.callable_arities.as_mut() {
            for target in &targets[1..] {
                if target.fq_name() == spec.target.fq_name() && target.is_function() {
                    arities.insert(java_callable_arity(analyzer, target));
                }
            }
        }
        Some(spec)
    }

    pub(super) fn from_target(analyzer: &JavaAnalyzer, target: &CodeUnit) -> Option<Self> {
        if target.is_class() {
            let fq_name = target.fq_name();
            return Some(Self {
                target: target.clone(),
                targets: HashSet::from_iter([target.clone()]),
                kind: TargetKind::Type,
                owner: target.clone(),
                receiver_owner_fq_names: [fq_name.clone()].into_iter().collect(),
                declaration_owner_fq_names: [fq_name].into_iter().collect(),
                member_name: target.identifier().to_string(),
                callable_arities: None,
            });
        }

        let owner = analyzer.parent_of(target)?;
        let kind = if target.is_field() {
            TargetKind::Field
        } else if target.identifier() == owner.identifier() {
            TargetKind::Constructor
        } else {
            TargetKind::Method
        };

        let owner_sets = target_owner_sets(analyzer, target, &owner, kind);

        Some(Self {
            target: target.clone(),
            targets: HashSet::from_iter([target.clone()]),
            kind,
            receiver_owner_fq_names: owner_sets.receiver,
            declaration_owner_fq_names: owner_sets.declarations,
            member_name: target.identifier().to_string(),
            callable_arities: (kind == TargetKind::Method || kind == TargetKind::Constructor)
                .then(|| HashSet::from_iter([java_callable_arity(analyzer, target)])),
            owner,
        })
    }
}

/// Return the receiver type of a constructor method reference such as
/// `Request::new`. Tree-sitter models `new` as an unnamed keyword child, so it
/// cannot be recovered through the named-child method-reference helper used for
/// ordinary `Type::method` references.
pub(super) fn constructor_method_reference_receiver(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "method_reference" {
        return None;
    }
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();
    if !children.iter().any(|child| child.kind() == "new") {
        return None;
    }
    children.into_iter().find(|child| child.is_named())
}

struct TargetOwnerSets {
    receiver: HashSet<String>,
    declarations: HashSet<String>,
}

fn target_owner_sets(
    analyzer: &JavaAnalyzer,
    target: &CodeUnit,
    owner: &CodeUnit,
    kind: TargetKind,
) -> TargetOwnerSets {
    let mut receiver = HashSet::from_iter([owner.fq_name()]);
    let mut declarations = HashSet::from_iter([owner.fq_name()]);
    if kind != TargetKind::Method {
        return TargetOwnerSets {
            receiver,
            declarations,
        };
    }
    let Some(provider) = analyzer.type_hierarchy_provider() else {
        return TargetOwnerSets {
            receiver,
            declarations,
        };
    };

    for descendant in provider.get_descendants(owner) {
        if java_owner_declares_matching_method(analyzer, &descendant, target) {
            receiver.insert(descendant.fq_name());
            declarations.insert(descendant.fq_name());
        }
    }
    for ancestor in provider.get_ancestors(owner) {
        if java_owner_declares_matching_method(analyzer, &ancestor, target) {
            declarations.insert(ancestor.fq_name());
        }
    }
    TargetOwnerSets {
        receiver,
        declarations,
    }
}

fn java_owner_declares_matching_method(
    analyzer: &JavaAnalyzer,
    owner: &CodeUnit,
    target: &CodeUnit,
) -> bool {
    analyzer
        .global_usage_definition_index()
        .by_fqn(&format!("{}.{}", owner.fq_name(), target.identifier()))
        .iter()
        .any(|unit| unit.is_function() && java_method_signatures_match(analyzer, target, unit))
}

pub(super) fn java_method_signatures_match(
    analyzer: &JavaAnalyzer,
    target: &CodeUnit,
    candidate: &CodeUnit,
) -> bool {
    match (target.signature(), candidate.signature()) {
        (Some(target), Some(candidate)) => {
            normalize_java_signature(target) == normalize_java_signature(candidate)
        }
        _ => java_callable_arity(analyzer, target) == java_callable_arity(analyzer, candidate),
    }
}

pub(super) fn java_callable_arity(analyzer: &JavaAnalyzer, unit: &CodeUnit) -> CallableArity {
    analyzer
        .signature_metadata(unit)
        .first()
        .and_then(|metadata| metadata.callable_arity())
        .unwrap_or_else(|| CallableArity::exact(signature_arity(unit.signature())))
}

fn normalize_java_signature(signature: &str) -> String {
    signature.chars().filter(|ch| !ch.is_whitespace()).collect()
}

pub(in crate::analyzer::usages) fn signature_arity(signature: Option<&str>) -> usize {
    let Some(signature) = signature else {
        return 0;
    };
    let inner = signature
        .strip_prefix('(')
        .and_then(|rest| rest.strip_suffix(')'))
        .unwrap_or(signature)
        .trim();
    if inner.is_empty() {
        return 0;
    }
    inner.split(',').count()
}

pub(super) fn seed_class_binding(
    java: &JavaAnalyzer,
    file: &ProjectFile,
    spec: &TargetSpec,
    bindings: &mut LocalInferenceEngine<String>,
) {
    if spec.kind == TargetKind::Type
        || java
            .resolve_usage_type_name(file, spec.owner.identifier())
            .is_some_and(|resolved| resolved.fq_name() == spec.owner.fq_name())
    {
        bindings.seed_symbol(spec.owner.identifier().to_string(), spec.owner.fq_name());
    }
}

impl JavaReturnTypeContext for ScanCtx<'_> {
    fn java(&self) -> &JavaAnalyzer {
        self.java
    }

    fn file(&self) -> &ProjectFile {
        self.file
    }

    fn source(&self) -> &str {
        self.source
    }

    fn root(&self) -> Node<'_> {
        self.root
    }

    fn method_return_cache(&self) -> &MethodReturnCache {
        self.method_return_cache
    }

    fn file_return_cache(&self) -> &FileReturnCache {
        self.file_return_cache
    }
}

pub(super) fn receiver_matches_target(receiver: Node<'_>, ctx: &mut ScanCtx<'_>) -> bool {
    match receiver.kind() {
        "identifier" => {
            let name = node_text(receiver, ctx.source);
            ctx.bindings
                .resolve_symbol(name)
                .as_precise()
                .is_some_and(|targets| {
                    targets
                        .iter()
                        .any(|target| ctx.spec.receiver_owner_fq_names.contains(target))
                })
        }
        "type_identifier" | "scoped_type_identifier" | "generic_type" => {
            resolve_type_from_node(receiver, ctx).is_some_and(|resolved| {
                ctx.spec
                    .receiver_owner_fq_names
                    .contains(&resolved.fq_name())
            })
        }
        "object_creation_expression" => receiver
            .child_by_field_name("type")
            .and_then(|type_node| resolve_type_from_node(type_node, ctx))
            .is_some_and(|resolved| {
                ctx.spec
                    .receiver_owner_fq_names
                    .contains(&resolved.fq_name())
            }),
        "method_invocation" => {
            method_invocation_return_type(receiver, ctx).is_some_and(|resolved| {
                ctx.spec
                    .receiver_owner_fq_names
                    .contains(&resolved.fq_name())
            })
        }
        "this" => {
            owner_matches_target_context(receiver, ctx)
                || anonymous_creation_context_matches_target(receiver, ctx)
        }
        "super" => {
            owner_matches_target_context(receiver, ctx)
                || anonymous_creation_context_matches_target(receiver, ctx)
        }
        _ => false,
    }
}

pub(super) fn has_proven_static_import(ctx: &ScanCtx<'_>) -> bool {
    let target_fq_name = ctx.spec.owner.fq_name();
    let mut target_visible = false;

    for import in ctx.analyzer.import_statements(ctx.file) {
        let trimmed = import.trim();
        if !trimmed.starts_with("import static ") {
            continue;
        }
        let path = trimmed
            .strip_prefix("import static ")
            .unwrap_or(trimmed)
            .trim_end_matches(';')
            .trim();

        if let Some(owner) = path.strip_suffix(".*") {
            if owner == target_fq_name {
                target_visible = true;
            } else if java_static_import_owner_matches_target(owner, ctx) {
                return false;
            }
            continue;
        }

        let Some((owner, member)) = path.rsplit_once('.') else {
            continue;
        };
        if member != ctx.spec.member_name {
            continue;
        }
        if owner == target_fq_name {
            target_visible = true;
        } else if java_static_import_owner_matches_target(owner, ctx) {
            return false;
        }
    }

    target_visible
}

fn java_static_import_owner_matches_target(owner_fq_name: &str, ctx: &ScanCtx<'_>) -> bool {
    ctx.java
        .global_usage_definition_index()
        .by_fqn(&format!("{owner_fq_name}.{}", ctx.spec.member_name))
        .iter()
        .any(|candidate| java_static_import_candidate_matches_target(candidate, ctx))
}

fn java_static_import_candidate_matches_target(candidate: &CodeUnit, ctx: &ScanCtx<'_>) -> bool {
    match ctx.spec.kind {
        TargetKind::Field => candidate.is_field(),
        TargetKind::Method => {
            candidate.is_function() && java_static_import_callable_matches_target(candidate, ctx)
        }
        TargetKind::Type | TargetKind::Constructor => false,
    }
}

fn java_static_import_callable_matches_target(candidate: &CodeUnit, ctx: &ScanCtx<'_>) -> bool {
    if java_method_signatures_match(ctx.java, &ctx.spec.target, candidate) {
        return true;
    }
    let Some(expected_arities) = ctx.spec.callable_arities.as_ref() else {
        return false;
    };
    let candidate_arity = java_callable_arity(ctx.java, candidate);
    expected_arities.contains(&candidate_arity)
}

pub(super) fn bare_method_context_matches_target(node: Node<'_>, ctx: &mut ScanCtx<'_>) -> bool {
    let context = enclosing_context(node, ctx);
    let Some(owner) = context.owner.as_ref() else {
        return false;
    };
    if owner.fq_name() == ctx.spec.owner.fq_name() {
        return true;
    }
    if java_owner_declares_matching_method(ctx.java, owner, &ctx.spec.target) {
        return false;
    }
    nearest_declaring_ancestor_matches_target(ctx, owner, |ancestor| {
        java_owner_declares_matching_method(ctx.java, ancestor, &ctx.spec.target)
    })
}

pub(super) fn bare_field_context_matches_target(node: Node<'_>, ctx: &mut ScanCtx<'_>) -> bool {
    let context = enclosing_context(node, ctx);
    let Some(owner) = context.owner.as_ref() else {
        return false;
    };
    if owner.fq_name() == ctx.spec.owner.fq_name() {
        return true;
    }
    if ctx
        .java
        .global_usage_definition_index()
        .by_fqn(&format!("{}.{}", owner.fq_name(), ctx.spec.member_name))
        .iter()
        .any(CodeUnit::is_field)
    {
        return false;
    }
    nearest_declaring_ancestor_matches_target(ctx, owner, |ancestor| {
        ctx.java
            .global_usage_definition_index()
            .by_fqn(&format!("{}.{}", ancestor.fq_name(), ctx.spec.member_name))
            .iter()
            .any(CodeUnit::is_field)
    })
}

fn nearest_declaring_ancestor_matches_target(
    ctx: &ScanCtx<'_>,
    owner: &CodeUnit,
    mut declares_target_member: impl FnMut(&CodeUnit) -> bool,
) -> bool {
    let Some(provider) = ctx.analyzer.type_hierarchy_provider() else {
        return false;
    };
    let mut seen = HashSet::from_iter([owner.clone()]);
    let mut level = provider.get_direct_ancestors(owner);
    while !level.is_empty() {
        let mut declaring_owners = Vec::new();
        let mut next_level = Vec::new();
        for ancestor in level {
            if !seen.insert(ancestor.clone()) {
                continue;
            }
            if declares_target_member(&ancestor) {
                declaring_owners.push(ancestor.clone());
            }
            next_level.extend(provider.get_direct_ancestors(&ancestor));
        }
        if !declaring_owners.is_empty() {
            let class_owners = declaring_owners
                .iter()
                .filter(|owner| !ctx.java.is_interface(owner))
                .collect::<Vec<_>>();
            let preferred = if class_owners.is_empty() {
                declaring_owners.iter().collect::<Vec<_>>()
            } else {
                class_owners
            };
            return preferred.len() == 1 && preferred[0].fq_name() == ctx.spec.owner.fq_name();
        }
        level = next_level;
    }
    false
}

pub(super) fn same_owner_context(node: Node<'_>, ctx: &mut ScanCtx<'_>) -> bool {
    enclosing_context(node, ctx)
        .owner
        .as_ref()
        .is_some_and(|owner| owner.fq_name() == ctx.spec.owner.fq_name())
}

pub(super) fn owner_matches_target_context(node: Node<'_>, ctx: &mut ScanCtx<'_>) -> bool {
    let context = enclosing_context(node, ctx);
    let Some(owner) = context.owner.as_ref() else {
        return false;
    };
    if ctx.spec.receiver_owner_fq_names.contains(&owner.fq_name()) {
        return true;
    }
    ctx.analyzer
        .type_hierarchy_provider()
        .is_some_and(|provider| {
            provider.get_ancestors(owner).iter().any(|ancestor| {
                ctx.spec
                    .receiver_owner_fq_names
                    .contains(&ancestor.fq_name())
            })
        })
}

fn anonymous_creation_context_matches_target(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "object_creation_expression"
            && let Some(type_node) = parent.child_by_field_name("type")
            && resolve_type_from_node(type_node, ctx)
                .is_some_and(|resolved| resolved.fq_name() == ctx.spec.owner.fq_name())
        {
            return true;
        }
        current = parent.parent();
    }
    false
}

pub(super) fn argument_list_arity(node: Node<'_>) -> usize {
    let Some(arguments) = node.child_by_field_name("arguments") else {
        return 0;
    };
    let mut cursor = arguments.walk();
    arguments
        .children(&mut cursor)
        .filter(|child| child.is_named() && !child.is_extra())
        .count()
}

pub(super) fn resolve_type_from_node(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<CodeUnit> {
    if matches!(node.kind(), "scoped_type_identifier" | "scoped_identifier")
        && let Some(resolved) = resolve_nested_type_from_scoped_node(node, ctx)
    {
        return Some(resolved);
    }

    resolve_non_nested_type_from_node(node, ctx)
}

pub(super) fn resolve_non_nested_type_from_node(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
) -> Option<CodeUnit> {
    match java_lexical_type_from_node(ctx.java, ctx.analyzer, ctx.file, ctx.source, node) {
        LexicalTypeResolution::Resolved(unit) => return Some(unit),
        LexicalTypeResolution::Blocked => return None,
        LexicalTypeResolution::NotFound => {}
    }

    let type_name = java_type_name_from_node(node, ctx.source)?;
    ctx.java.resolve_usage_type_name(ctx.file, &type_name)
}

/// Resolves each semantic class segment in a Java type reference, preserving the
/// exact token that named that segment. For example, `Service.Repository`
/// yields the `Service` token paired with `example.Service`, followed by the
/// `Repository` token paired with `example.Service.Repository`.
///
/// Package components deliberately do not appear: they cannot resolve to a
/// class identity on their own. Callers provide their resolution context so the
/// forward scanner and persisted edge builder use the same structured walk.
pub(super) fn resolve_type_segments<'tree, ResolveNode, ResolveNested>(
    node: Node<'tree>,
    source: &str,
    mut resolve_node: ResolveNode,
    mut resolve_nested: ResolveNested,
) -> Vec<(CodeUnit, Node<'tree>)>
where
    ResolveNode: FnMut(Node<'tree>) -> Option<CodeUnit>,
    ResolveNested: FnMut(&CodeUnit, &str) -> Option<CodeUnit>,
{
    let mut prefixes = Vec::new();
    let mut current = node;
    loop {
        while matches!(
            current.kind(),
            "array_type" | "annotated_type" | "generic_type"
        ) {
            let Some(nominal) = nominal_type_child(current) else {
                return Vec::new();
            };
            current = nominal;
        }
        match current.kind() {
            "identifier" | "type_identifier" => {
                prefixes.push((current, current));
                break;
            }
            "scoped_identifier" | "scoped_type_identifier" => {
                let mut cursor = current.walk();
                let typed_children: Vec<_> = current
                    .named_children(&mut cursor)
                    .filter(|child| is_java_nominal_type_node(child.kind()))
                    .collect();
                let Some((name, qualifier)) = typed_children.split_last() else {
                    return Vec::new();
                };
                let Some(terminal) = terminal_type_node(*name) else {
                    return Vec::new();
                };
                prefixes.push((current, terminal));
                let Some(qualifier) = qualifier.last().copied() else {
                    break;
                };
                current = qualifier;
            }
            _ => return Vec::new(),
        }
    }
    prefixes.reverse();

    let mut segments = Vec::new();
    for (prefix, terminal) in prefixes {
        let name = node_text(terminal, source);
        if name.is_empty() {
            continue;
        }
        let resolved = segments
            .last()
            .and_then(|(owner, _)| resolve_nested(owner, name))
            .or_else(|| resolve_node(prefix));
        if let Some(resolved) = resolved {
            if segments.last().is_none_or(|(owner, _)| *owner != resolved) {
                segments.push((resolved, terminal));
            }
        } else if !segments.is_empty() {
            // Initial unresolved prefixes may be package components (for
            // example, `app` in `app.Service.Repository`), but an unresolved
            // segment after a class identity invalidates the remaining nested
            // path. Continuing would let a later name resolve from the stale
            // owner and create a false edge.
            break;
        }
    }
    segments
}

fn nominal_type_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| is_java_nominal_type_node(child.kind()))
}

fn terminal_type_node(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node;
    loop {
        match current.kind() {
            "identifier" | "type_identifier" => return Some(current),
            "array_type" | "annotated_type" | "generic_type" => {
                current = nominal_type_child(current)?;
            }
            "scoped_identifier" | "scoped_type_identifier" => {
                let mut cursor = current.walk();
                current = current
                    .named_children(&mut cursor)
                    .filter(|child| is_java_nominal_type_node(child.kind()))
                    .last()?;
            }
            _ => return None,
        }
    }
}

fn resolve_nested_type_from_scoped_node(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<CodeUnit> {
    let mut cursor = node.walk();
    let typed_children: Vec<_> = node
        .named_children(&mut cursor)
        .filter(|child| {
            matches!(
                child.kind(),
                "identifier"
                    | "type_identifier"
                    | "scoped_identifier"
                    | "scoped_type_identifier"
                    | "generic_type"
            )
        })
        .collect();
    let (name, qualifier) = typed_children.split_last()?;
    let qualifier = qualifier.last().copied()?;
    let qualifier_type = resolve_type_from_node(qualifier, ctx)?;
    let name = node_text(*name, ctx.source);
    if name.is_empty() {
        return None;
    }

    nested_type_for_owner(&qualifier_type, name, ctx)
}

pub(super) fn nested_type_for_owner(
    owner: &CodeUnit,
    name: &str,
    ctx: &ScanCtx<'_>,
) -> Option<CodeUnit> {
    resolve_nested_type_for_owner(ctx.analyzer, owner, name)
}

pub(super) fn resolve_nested_type_for_owner(
    analyzer: &dyn IAnalyzer,
    owner: &CodeUnit,
    name: &str,
) -> Option<CodeUnit> {
    let nested = |candidate: &CodeUnit| {
        analyzer
            .global_usage_definition_index()
            .by_fqn(&format!("{}.{}", candidate.fq_name(), name))
            .iter()
            .find(|unit| unit.is_class())
            .cloned()
    };
    nested(owner).or_else(|| {
        analyzer
            .type_hierarchy_provider()?
            .get_ancestors(owner)
            .into_iter()
            .find_map(|ancestor| nested(&ancestor))
    })
}

pub(super) fn infer_type_from_value(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<CodeUnit> {
    match node.kind() {
        "object_creation_expression" => node
            .child_by_field_name("type")
            .and_then(|type_node| resolve_type_from_node(type_node, ctx)),
        "method_invocation" => method_invocation_return_type(node, ctx),
        "identifier" => {
            let name = node_text(node, ctx.source);
            let targets = ctx.bindings.resolve_symbol(name);
            let fq_name = targets.as_precise()?.iter().next()?;
            class_definition(ctx, fq_name)
        }
        _ => None,
    }
}

fn method_invocation_return_type(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<CodeUnit> {
    method_invocation_return_type_at_depth(node, ctx, 0)
}

fn method_invocation_return_type_at_depth(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
    depth: usize,
) -> Option<CodeUnit> {
    if depth > METHOD_RECEIVER_CHAIN_LIMIT {
        return None;
    }
    let name_node = node.child_by_field_name("name")?;
    let name = node_text(name_node, ctx.source);
    if name.is_empty() {
        return None;
    }
    let owner = match node.child_by_field_name("object") {
        Some(object) => receiver_type_from_node_at_depth(object, ctx, depth + 1)?,
        None => enclosing_owner(node, ctx)?,
    };
    method_return_type_for_call(&owner, name, argument_list_arity(node), ctx)
}

fn receiver_type_from_node_at_depth(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
    depth: usize,
) -> Option<CodeUnit> {
    if depth > METHOD_RECEIVER_CHAIN_LIMIT {
        return None;
    }
    match node.kind() {
        "identifier" => {
            let name = node_text(node, ctx.source);
            let targets = ctx.bindings.resolve_symbol(name);
            if let Some(fq_name) = targets
                .as_precise()
                .and_then(|targets| (targets.len() == 1).then(|| targets.iter().next().unwrap()))
            {
                return class_definition(ctx, fq_name);
            }
            (!ctx.bindings.is_shadowed(name))
                .then(|| resolve_type_from_node(node, ctx))
                .flatten()
        }
        "type_identifier" | "scoped_type_identifier" | "generic_type" => {
            resolve_type_from_node(node, ctx)
        }
        "object_creation_expression" => node
            .child_by_field_name("type")
            .and_then(|type_node| resolve_type_from_node(type_node, ctx)),
        "method_invocation" => method_invocation_return_type_at_depth(node, ctx, depth),
        "this" | "super" => enclosing_owner(node, ctx),
        _ => None,
    }
}

fn method_return_type_for_call(
    owner: &CodeUnit,
    method_name: &str,
    arity: usize,
    ctx: &ScanCtx<'_>,
) -> Option<CodeUnit> {
    let cache_key = (owner.fq_name(), method_name.to_string(), arity);
    if let Some(cached) = ctx
        .method_call_return_cache
        .borrow()
        .get(&cache_key)
        .cloned()
    {
        return single_return_class(ctx, cached);
    }

    let mut owners = vec![cache_key.0.clone()];
    if let Some(provider) = ctx.analyzer.type_hierarchy_provider() {
        owners.extend(
            provider
                .get_ancestors(owner)
                .into_iter()
                .map(|ancestor| ancestor.fq_name()),
        );
    }
    let outcome = method_return_type_for_owner_fqns(
        owners.iter().map(String::as_str),
        method_name,
        arity,
        ctx,
    );
    ctx.method_call_return_cache
        .borrow_mut()
        .insert(cache_key, outcome.clone());
    single_return_class(ctx, outcome)
}

fn single_return_class(
    ctx: &ScanCtx<'_>,
    outcome: ReceiverAnalysisOutcome<String>,
) -> Option<CodeUnit> {
    match outcome {
        ReceiverAnalysisOutcome::Precise(values) if values.len() == 1 => {
            class_definition(ctx, &values[0])
        }
        ReceiverAnalysisOutcome::Precise(_)
        | ReceiverAnalysisOutcome::Ambiguous(_)
        | ReceiverAnalysisOutcome::Unsupported { .. }
        | ReceiverAnalysisOutcome::ExceededBudget { .. }
        | ReceiverAnalysisOutcome::Unknown => None,
    }
}

fn class_definition(ctx: &ScanCtx<'_>, fq_name: &str) -> Option<CodeUnit> {
    ctx.analyzer
        .global_usage_definition_index()
        .by_fqn(fq_name)
        .iter()
        .find(|unit| unit.is_class())
        .cloned()
}

fn enclosing_owner(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<CodeUnit> {
    let owner = ctx.class_ranges.enclosing(node.start_byte())?;
    class_definition(ctx, owner)
}

pub(super) fn is_ignored_type_context(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    matches!(
        parent.kind(),
        "package_declaration" | "import_declaration" | "class_declaration"
    ) && parent.child_by_field_name("name") == Some(node)
}

pub(super) fn is_declaration_name(node: Node<'_>) -> bool {
    node.parent()
        .and_then(|parent| parent.child_by_field_name("name"))
        == Some(node)
}
