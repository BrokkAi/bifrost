pub(super) use crate::analyzer::usages::common::node_text;
use crate::analyzer::usages::java_graph::extractor::ScanCtx;
use crate::analyzer::usages::java_graph::hits::enclosing_context;
use crate::analyzer::usages::local_inference::LocalInferenceEngine;
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
            .cloned()
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
