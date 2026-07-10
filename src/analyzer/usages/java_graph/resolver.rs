pub(super) use crate::analyzer::usages::common::node_text;
use crate::analyzer::usages::java_graph::extractor::ScanCtx;
use crate::analyzer::usages::java_graph::hits::enclosing_context;
use crate::analyzer::usages::java_graph::return_type::{
    FileReturnCache, JavaReturnTypeContext, METHOD_RECEIVER_CHAIN_LIMIT, MethodReturnCache,
    method_return_type_for_owner_fqns,
};
use crate::analyzer::usages::local_inference::LocalInferenceEngine;
use crate::analyzer::usages::receiver_analysis::ReceiverAnalysisOutcome;
use crate::analyzer::{CodeUnit, IAnalyzer, JavaAnalyzer, ProjectFile};
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
    pub(super) kind: TargetKind,
    pub(super) owner: CodeUnit,
    pub(super) receiver_owner_fq_names: HashSet<String>,
    pub(super) declaration_owner_fq_names: HashSet<String>,
    pub(super) member_name: String,
    pub(super) method_arity: Option<usize>,
}

impl TargetSpec {
    pub(super) fn from_target(analyzer: &JavaAnalyzer, target: &CodeUnit) -> Option<Self> {
        if target.is_class() {
            let fq_name = target.fq_name();
            return Some(Self {
                target: target.clone(),
                kind: TargetKind::Type,
                owner: target.clone(),
                receiver_owner_fq_names: [fq_name.clone()].into_iter().collect(),
                declaration_owner_fq_names: [fq_name].into_iter().collect(),
                member_name: target.identifier().to_string(),
                method_arity: None,
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
            kind,
            receiver_owner_fq_names: owner_sets.receiver,
            declaration_owner_fq_names: owner_sets.declarations,
            member_name: target.identifier().to_string(),
            method_arity: (kind == TargetKind::Method || kind == TargetKind::Constructor)
                .then(|| signature_arity(target.signature())),
            owner,
        })
    }
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
        .get_definitions(&format!("{}.{}", owner.fq_name(), target.identifier()))
        .into_iter()
        .any(|unit| unit.is_function() && java_method_signatures_match(target, &unit))
}

pub(super) fn java_method_signatures_match(target: &CodeUnit, candidate: &CodeUnit) -> bool {
    match (target.signature(), candidate.signature()) {
        (Some(target), Some(candidate)) => {
            normalize_java_signature(target) == normalize_java_signature(candidate)
        }
        _ => signature_arity(target.signature()) == signature_arity(candidate.signature()),
    }
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
            .resolve_type_name_in_file(file, spec.owner.identifier())
            .is_some_and(|resolved| resolved == spec.owner)
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

    fn root(&self) -> Node<'_> {
        self.root
    }

    fn resolve_type_fqn(&self, node: Node<'_>) -> Option<String> {
        resolve_type_from_node(node, self).map(|unit| unit.fq_name())
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
            } else {
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
        } else {
            return false;
        }
    }

    target_visible
}

pub(super) fn same_owner_context(node: Node<'_>, ctx: &mut ScanCtx<'_>) -> bool {
    enclosing_context(node, ctx)
        .owner
        .as_ref()
        .is_some_and(|owner| owner == &ctx.spec.owner)
}

fn owner_matches_target_context(node: Node<'_>, ctx: &mut ScanCtx<'_>) -> bool {
    let context = enclosing_context(node, ctx);
    let Some(owner) = context.owner.as_ref() else {
        return false;
    };
    if ctx.spec.receiver_owner_fq_names.contains(&owner.fq_name()) {
        return true;
    }
    ctx.analyzer
        .type_hierarchy_provider()
        .is_some_and(|provider| provider.get_ancestors(owner).contains(&ctx.spec.owner))
}

fn anonymous_creation_context_matches_target(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "object_creation_expression"
            && let Some(type_node) = parent.child_by_field_name("type")
            && resolve_type_from_node(type_node, ctx)
                .is_some_and(|resolved| resolved == ctx.spec.owner)
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
    arguments.named_children(&mut cursor).count()
}

pub(super) fn resolve_type_from_node(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<CodeUnit> {
    if node.kind() == "scoped_type_identifier"
        && let Some(resolved) = resolve_nested_type_from_scoped_node(node, ctx)
    {
        return Some(resolved);
    }

    let raw = node_text(node, ctx.source);
    if raw.is_empty() {
        return None;
    }
    let normalized = raw
        .split('<')
        .next()
        .unwrap_or(raw)
        .trim()
        .trim_end_matches("[]")
        .trim();
    ctx.java.resolve_type_name_in_file(ctx.file, normalized)
}

fn resolve_nested_type_from_scoped_node(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<CodeUnit> {
    let mut cursor = node.walk();
    let typed_children: Vec<_> = node
        .named_children(&mut cursor)
        .filter(|child| {
            matches!(
                child.kind(),
                "type_identifier" | "scoped_type_identifier" | "generic_type"
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

    let nested = |owner: &CodeUnit| {
        ctx.analyzer
            .definitions(&format!("{}.{}", owner.fq_name(), name))
            .find(|unit| unit.is_class())
    };
    nested(&qualifier_type).or_else(|| {
        ctx.analyzer
            .type_hierarchy_provider()?
            .get_ancestors(&qualifier_type)
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
            ctx.analyzer
                .get_definitions(fq_name)
                .into_iter()
                .find(|unit| unit.is_class())
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
        .get_definitions(fq_name)
        .into_iter()
        .find(|unit| unit.is_class())
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
