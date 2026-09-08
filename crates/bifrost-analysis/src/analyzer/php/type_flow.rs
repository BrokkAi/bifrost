//! Conservative PHP class-set seeds and nominal member lookup.
//!
//! Syntax answers come only from the exact prepared tree that produced the
//! semantic procedure. Namespace and alias resolution uses PHP's structured
//! file-context index; external identities come from the active semantic-model
//! overlay and retain its canonical symbol identity.

use std::sync::Arc;

use brokk_bifrost_core::analyzer::prepared_syntax::{PreparedSyntaxSource, PreparedSyntaxTree};
use brokk_bifrost_php::aliases::{PhpFileContextIndex, resolve_php_type};
use brokk_bifrost_php::graph::syntax::{object_creation_type, variable_identifier};
use tree_sitter::Node;

use super::PhpAnalyzer;
use crate::analyzer::lexical_definitions::formal_parameter_slots_for_owner_with_nodes;
use crate::analyzer::semantic::type_flow::{
    ClassHierarchy, ClassIdentity, ClassSeed, ExternalClassCache, ExternalMemberDeclaration,
    MemberAccessKind, MemberAccessQuery, MemberDeclaration, MemberLookup, MemberLookupHit,
    TypeFlowAdapter, UnknownReason, external_class_identity, file_for_locator,
    validate_prepared_syntax_for_procedure,
};
use crate::analyzer::semantic::{
    AdapterSemanticsVersion, AllocationKind, AllocationSite, CandidateCoverage, MemoryLocationKind,
    ProcedureHandle, SemanticCallSite, SemanticValue, SemanticValueKind, SourceMappingKind,
    SourceSpan,
};
use crate::analyzer::semantic_model::{
    SemanticModelOverlay, SemanticModelSymbol, SemanticModelSymbolKind,
    semantic_model_callable_family_id,
};
use crate::analyzer::usages::get_type::{
    TypeLookupStatus, TypeLookupType, resolve_type_at_reference_site_with_budget,
};
use crate::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use crate::analyzer::usages::reference_site::{ResolvedReferenceSite, node_range};
use crate::analyzer::{
    AnalyzerQueryScope, CodeUnit, CodeUnitIndex, Language, ProjectFile, QueryScope,
    TypeHierarchyProvider, WorkspaceAnalyzer, resolve_analyzer,
};
use crate::hash::HashSet;
use crate::path_utils::rel_path_string;

pub(crate) struct PhpTypeFlowAdapter;

fn php_analyzer(workspace: &WorkspaceAnalyzer) -> &PhpAnalyzer {
    resolve_analyzer::<PhpAnalyzer>(workspace.analyzer())
        .expect("PhpTypeFlowAdapter serves only workspaces that analyze PHP")
}

fn overlay_of(workspace: &WorkspaceAnalyzer) -> Option<Arc<SemanticModelOverlay>> {
    workspace
        .analyzer()
        .active_semantic_model_snapshot()
        .and_then(|snapshot| snapshot.semantic_model_overlay().cloned())
}

fn prepared_for_procedure(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    file: &ProjectFile,
) -> Result<Arc<PreparedSyntaxTree>, UnknownReason> {
    let php = php_analyzer(workspace);
    let scope = AnalyzerQueryScope::new(php);
    let prepared = php
        .inner
        .prepared_syntax(scope.token(), file)
        .ok_or(UnknownReason::UncertainFlow)?;
    validate_prepared_syntax_for_procedure(workspace, procedure, file, prepared)
}

fn current_indexed_prepared(
    php: &PhpAnalyzer,
    file: &ProjectFile,
) -> Option<Arc<PreparedSyntaxTree>> {
    let scope = AnalyzerQueryScope::new(php);
    let prepared = php.inner.prepared_syntax(scope.token(), file)?;
    (matches!(prepared.backing(), PreparedSyntaxSource::Indexed(_))
        && php.indexed_source_matches(file, prepared.source()))
    .then_some(prepared)
}

fn node_at_span(prepared: &PreparedSyntaxTree, span: SourceSpan) -> Option<Node<'_>> {
    prepared
        .tree()
        .root_node()
        .named_descendant_for_byte_range(span.start_byte() as usize, span.end_byte() as usize)
}

fn node_text<'source>(node: Node<'_>, source: &'source str) -> Option<&'source str> {
    node.utf8_text(source.as_bytes()).ok()
}

fn nearest_call(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if matches!(
            candidate.kind(),
            "function_call_expression"
                | "member_call_expression"
                | "nullsafe_member_call_expression"
                | "scoped_call_expression"
                | "object_creation_expression"
        ) {
            return Some(candidate);
        }
        current = candidate.parent();
    }
    None
}

fn nearest_callable(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if matches!(
            candidate.kind(),
            "function_definition" | "method_declaration" | "anonymous_function" | "arrow_function"
        ) {
            return Some(candidate);
        }
        current = candidate.parent();
    }
    None
}

fn declaration_node<'tree>(
    php: &PhpAnalyzer,
    prepared: &'tree PreparedSyntaxTree,
    unit: &CodeUnit,
) -> Option<Node<'tree>> {
    php.ranges(unit).into_iter().find_map(|range| {
        let mut node = prepared
            .tree()
            .root_node()
            .named_descendant_for_byte_range(range.start_byte, range.end_byte)?;
        loop {
            if matches!(
                node.kind(),
                "class_declaration"
                    | "interface_declaration"
                    | "trait_declaration"
                    | "enum_declaration"
                    | "method_declaration"
                    | "property_declaration"
            ) {
                return Some(node);
            }
            node = node.parent()?;
        }
    })
}

fn runtime_workspace_class(
    workspace: &WorkspaceAnalyzer,
    php: &PhpAnalyzer,
    unit: &CodeUnit,
) -> bool {
    let Some(prepared) = current_indexed_prepared(php, unit.source()) else {
        return false;
    };
    declaration_node(php, &prepared, unit)
        .is_some_and(|node| node.kind() == "class_declaration" && !node.has_error())
        && workspace
            .analyzer()
            .indexed_source_matches(unit.source(), prepared.source())
}

fn workspace_class_is_final(php: &PhpAnalyzer, unit: &CodeUnit) -> bool {
    let Some(prepared) = current_indexed_prepared(php, unit.source()) else {
        return false;
    };
    let Some(declaration) = declaration_node(php, &prepared, unit) else {
        return false;
    };
    let mut cursor = declaration.walk();
    declaration
        .named_children(&mut cursor)
        .any(|child| child.kind() == "final_modifier")
}

fn identity_from_lookup(
    workspace: &WorkspaceAnalyzer,
    lookup: &TypeLookupType,
) -> Result<Option<ClassIdentity>, UnknownReason> {
    match lookup.definitions.as_slice() {
        [unit] => {
            let php = php_analyzer(workspace);
            if runtime_workspace_class(workspace, php, unit) {
                Ok(Some(ClassIdentity::Workspace(unit.clone())))
            } else {
                Err(UnknownReason::OpenTypeBound)
            }
        }
        [] => {
            let mut cache = ExternalClassCache::default();
            Ok(external_class_identity(
                overlay_of(workspace).as_deref(),
                Language::Php,
                &lookup.fqn,
                lookup.semantic_model_id.as_deref(),
                &mut cache,
            ))
        }
        _ => Err(UnknownReason::AmbiguousCallee),
    }
}

fn reference_site(
    file: &ProjectFile,
    expression: Node<'_>,
    focus: Node<'_>,
    source: &str,
) -> Option<ResolvedReferenceSite> {
    Some(ResolvedReferenceSite {
        path: rel_path_string(file),
        text: node_text(expression, source)?.to_owned(),
        range: node_range(expression),
        focus_start_byte: focus.start_byte(),
        focus_end_byte: focus.end_byte(),
    })
}

fn resolve_constructor(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    creation: Node<'_>,
) -> ClassSeed {
    if creation.has_error() || creation.is_missing() {
        return ClassSeed::Unknown(UnknownReason::UncertainFlow);
    }
    let Some(class) = object_creation_type(creation) else {
        return ClassSeed::Unknown(UnknownReason::OpenTypeBound);
    };
    if !matches!(
        class.kind(),
        "name" | "qualified_name" | "fully_qualified_name" | "relative_scope"
    ) {
        return ClassSeed::Unknown(UnknownReason::UnresolvedCall);
    }
    let late_bound =
        node_text(class, prepared.source()).is_some_and(|name| name.eq_ignore_ascii_case("static"));
    let Some(site) = reference_site(file, creation, class, prepared.source()) else {
        return ClassSeed::Unknown(UnknownReason::UncertainFlow);
    };
    let outcome = resolve_type_at_reference_site_with_budget(
        workspace.analyzer(),
        file,
        prepared.source(),
        Some(prepared.tree()),
        site,
        ReceiverAnalysisBudget::default(),
    );
    if !workspace
        .analyzer()
        .indexed_source_matches(file, prepared.source())
        || procedure.artifact().key().language() != prepared.dialect()
    {
        return ClassSeed::Unknown(UnknownReason::UncertainFlow);
    }
    match outcome.status {
        TypeLookupStatus::ExceededBudget(_) => ClassSeed::Unknown(UnknownReason::SemanticBudget),
        TypeLookupStatus::Ambiguous => ClassSeed::Unknown(UnknownReason::AmbiguousCallee),
        TypeLookupStatus::Resolved => {
            let [lookup] = outcome.types.as_slice() else {
                return ClassSeed::Unknown(UnknownReason::AmbiguousCallee);
            };
            match identity_from_lookup(workspace, lookup) {
                Ok(Some(identity)) if late_bound => ClassSeed::ClassWithOpenBound(identity),
                Ok(Some(identity)) => ClassSeed::Class(identity),
                Ok(None) => ClassSeed::Unknown(UnknownReason::ExternalNotModeled),
                Err(reason) => ClassSeed::Unknown(reason),
            }
        }
        TypeLookupStatus::NoType
        | TypeLookupStatus::UnsupportedLanguage
        | TypeLookupStatus::InvalidLocation
        | TypeLookupStatus::NotFound => ClassSeed::Unknown(UnknownReason::ExternalNotModeled),
    }
}

#[derive(Debug)]
enum NominalIdentity {
    Resolved(ClassIdentity),
    Missing,
    Ambiguous,
}

fn nominal_identity(workspace: &WorkspaceAnalyzer, fqn: &str) -> NominalIdentity {
    let php = php_analyzer(workspace);
    let mut candidates = php
        .definitions(fqn)
        .filter(|unit| runtime_workspace_class(workspace, php, unit))
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.dedup();
    match candidates.as_slice() {
        [unit] => NominalIdentity::Resolved(ClassIdentity::Workspace(unit.clone())),
        [] => {
            let mut cache = ExternalClassCache::default();
            external_class_identity(
                overlay_of(workspace).as_deref(),
                Language::Php,
                fqn,
                None,
                &mut cache,
            )
            .map(NominalIdentity::Resolved)
            .unwrap_or(NominalIdentity::Missing)
        }
        _ => NominalIdentity::Ambiguous,
    }
}

fn declared_parameter_seed(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    ordinal: u32,
) -> ClassSeed {
    let semantics = procedure.semantics();
    let Some(file) = file_for_locator(workspace, semantics.locator()) else {
        return ClassSeed::NotApplicable;
    };
    let prepared = match prepared_for_procedure(workspace, procedure, &file) {
        Ok(prepared) => prepared,
        Err(reason) => return ClassSeed::Unknown(reason),
    };
    let Some(node) = node_at_span(&prepared, semantics.locator().anchor().span()) else {
        return ClassSeed::Unknown(UnknownReason::UncertainFlow);
    };
    let Some(callable) = nearest_callable(node) else {
        return ClassSeed::NotApplicable;
    };
    let Some(slots) =
        formal_parameter_slots_for_owner_with_nodes(Language::Php, callable, prepared.source())
    else {
        return ClassSeed::NotApplicable;
    };
    let Some((_slot, declaration)) = slots.get(ordinal as usize) else {
        return ClassSeed::NotApplicable;
    };
    let Some(type_node) = declaration.child_by_field_name("type") else {
        return ClassSeed::NotApplicable;
    };
    let Some(contexts) =
        PhpFileContextIndex::from_tree(prepared.tree().root_node(), prepared.source(), || true)
    else {
        return ClassSeed::Unknown(UnknownReason::UncertainFlow);
    };
    let context = contexts.context_at(type_node.start_byte());
    let mut arms = Vec::new();
    if type_node.kind() == "union_type" {
        for index in 0..type_node.named_child_count() {
            let Some(child) = type_node.named_child(index) else {
                return ClassSeed::Unknown(UnknownReason::UncertainFlow);
            };
            arms.push(child);
        }
    } else {
        arms.push(type_node);
    }

    let mut identities = Vec::new();
    let mut saw_nominal = false;
    let mut saw_scalar = false;
    let mut saw_missing = false;
    for arm in arms {
        if let Some(fqn) = super::resolve_php_type_node(arm, prepared.source(), context, || true) {
            saw_nominal = true;
            match nominal_identity(workspace, &fqn) {
                NominalIdentity::Resolved(identity) => identities.push(identity),
                NominalIdentity::Missing => saw_missing = true,
                NominalIdentity::Ambiguous => {
                    return ClassSeed::Unknown(UnknownReason::AmbiguousCallee);
                }
            }
        } else if super::php_dynamic_type_keyword_node(arm, prepared.source(), || true).is_some()
            || arm.kind() == "primitive_type"
        {
            saw_scalar = true;
        } else {
            saw_missing = true;
        }
    }
    identities.sort_by(|left, right| left.qualified_name().cmp(right.qualified_name()));
    identities.dedup();
    match identities.len() {
        0 if saw_scalar && !saw_nominal && !saw_missing => {
            ClassSeed::Unknown(UnknownReason::ScalarReceiver)
        }
        0 => ClassSeed::Unknown(UnknownReason::OpenTypeBound),
        1 => ClassSeed::ClassWithOpenBound(
            identities
                .pop()
                .expect("a one-element identity list has one identity"),
        ),
        _ => ClassSeed::classes_with_open_bound(identities),
    }
}

fn member_matches_kind(php: &PhpAnalyzer, unit: &CodeUnit, kind: MemberAccessKind) -> bool {
    let metadata = php.signature_metadata(unit);
    let [metadata] = metadata.as_slice() else {
        return false;
    };
    match kind {
        MemberAccessKind::Call => {
            unit.is_function()
                && metadata.callable_modifiers_recorded()
                && !metadata.callable_is_static()
        }
        MemberAccessKind::Load => unit.is_field() && !metadata.field_is_static(),
    }
}

fn member_name_matches(kind: MemberAccessKind, actual: &str, requested: &str) -> bool {
    match kind {
        MemberAccessKind::Call => actual.eq_ignore_ascii_case(requested),
        MemberAccessKind::Load => actual == requested,
    }
}

fn workspace_member_at_level(
    php: &PhpAnalyzer,
    owners: &[CodeUnit],
    kind: MemberAccessKind,
    member: &str,
) -> (Vec<CodeUnit>, bool) {
    let mut matched = Vec::new();
    let mut incompatible = false;
    for owner in owners {
        for child in php.direct_children(owner) {
            if !member_name_matches(kind, child.terminal_name(), member) {
                continue;
            }
            if member_matches_kind(php, &child, kind) {
                matched.push(child);
            } else {
                incompatible = true;
            }
        }
    }
    matched.sort();
    matched.dedup();
    (matched, incompatible)
}

fn workspace_magic_present(php: &PhpAnalyzer, owners: &[CodeUnit], kind: MemberAccessKind) -> bool {
    let names: &[&str] = match kind {
        MemberAccessKind::Call => &["__call", "__callStatic"],
        MemberAccessKind::Load => &["__get", "__set"],
    };
    owners.iter().any(|owner| {
        php.direct_children(owner).iter().any(|child| {
            child.is_function()
                && names
                    .iter()
                    .any(|name| child.terminal_name().eq_ignore_ascii_case(name))
        })
    })
}

fn resolved_external_bases(
    workspace: &WorkspaceAnalyzer,
    php: &PhpAnalyzer,
    unit: &CodeUnit,
    workspace_ancestors: &[CodeUnit],
) -> (Vec<ClassIdentity>, bool) {
    let overlay = overlay_of(workspace);
    let mut external_cache = ExternalClassCache::default();
    let mut external = Vec::new();
    let mut unresolved = false;
    for owner in std::iter::once(unit).chain(workspace_ancestors.iter()) {
        let Some(prepared) = current_indexed_prepared(php, owner.source()) else {
            unresolved = true;
            continue;
        };
        let Some(start) = php.ranges(owner).iter().map(|range| range.start_byte).min() else {
            unresolved = true;
            continue;
        };
        let Some(contexts) =
            PhpFileContextIndex::from_tree(prepared.tree().root_node(), prepared.source(), || true)
        else {
            unresolved = true;
            continue;
        };
        let context = contexts.context_at(start);
        let direct = php.get_direct_ancestors(owner);
        for raw in php.inner.raw_supertypes_of(owner) {
            let Some(fqn) = resolve_php_type(&raw, context) else {
                unresolved = true;
                continue;
            };
            if direct.iter().any(|ancestor| ancestor.fq_name_str() == fqn) {
                continue;
            }
            match external_class_identity(
                overlay.as_deref(),
                Language::Php,
                &fqn,
                None,
                &mut external_cache,
            ) {
                Some(identity) => external.push(identity),
                None => unresolved = true,
            }
        }
    }
    external.sort_by(|left, right| left.qualified_name().cmp(right.qualified_name()));
    external.dedup();
    (external, unresolved)
}

fn external_member_has_kind(symbol: &SemanticModelSymbol, kind: MemberAccessKind) -> bool {
    symbol.language == "php"
        && symbol.owner_id.is_some()
        && matches!(
            (kind, symbol.kind),
            (MemberAccessKind::Call, SemanticModelSymbolKind::Method)
                | (
                    MemberAccessKind::Load,
                    SemanticModelSymbolKind::Field | SemanticModelSymbolKind::Property
                )
        )
}

fn external_member_lookup(
    overlay: &SemanticModelOverlay,
    owner_id: &str,
    kind: MemberAccessKind,
    member: &str,
) -> MemberLookup {
    let owners = overlay.symbols_with_id(owner_id).records;
    let [owner] = owners.as_slice() else {
        return MemberLookup::Unknown(UnknownReason::PackIncomplete);
    };
    if owner.language != "php"
        || owner.kind != SemanticModelSymbolKind::Class
        || owner.provenance.ambiguous
    {
        return MemberLookup::Unknown(UnknownReason::PackIncomplete);
    }
    let surface = overlay.owner_surface(owner);
    let member_surface_is_gapped = surface.closure.iter().any(|candidate_owner| {
        overlay
            .gapped_member_surface(&candidate_owner.qualified_name, member)
            .is_some()
    });
    let mut incompatible = false;
    for candidate_owner in &surface.closure {
        let records = overlay
            .members_of(&candidate_owner.id)
            .records
            .into_iter()
            .filter(|symbol| member_name_matches(kind, &symbol.name, member))
            .collect::<Vec<_>>();
        if records.is_empty() {
            continue;
        }
        let relevant = records
            .iter()
            .copied()
            .filter(|symbol| external_member_has_kind(symbol, kind))
            .collect::<Vec<_>>();
        incompatible |= relevant.is_empty();
        if relevant.is_empty() {
            continue;
        }
        if relevant
            .iter()
            .any(|symbol| symbol.is_static || symbol.provenance.ambiguous)
        {
            return MemberLookup::Unknown(UnknownReason::PackIncomplete);
        }
        let family_complete = match kind {
            MemberAccessKind::Call => semantic_model_callable_family_id(&relevant).is_some(),
            MemberAccessKind::Load => relevant.len() == 1,
        };
        if !family_complete && relevant.len() > 1 {
            return MemberLookup::Unknown(UnknownReason::PackIncomplete);
        }
        let exhaustive = surface.gaps.is_empty() && !member_surface_is_gapped && family_complete;
        return MemberLookup::Present(MemberLookupHit::new(
            MemberDeclaration::External(ExternalMemberDeclaration::new(
                relevant
                    .into_iter()
                    .map(|symbol| symbol.id.clone().into_boxed_str()),
            )),
            if exhaustive {
                CandidateCoverage::Exhaustive
            } else {
                CandidateCoverage::Open
            },
        ));
    }
    if incompatible {
        return MemberLookup::Unknown(UnknownReason::PackIncomplete);
    }
    let magic: &[&str] = match kind {
        MemberAccessKind::Call => &["__call", "__callStatic"],
        MemberAccessKind::Load => &["__get", "__set"],
    };
    let has_magic = surface.closure.iter().any(|candidate_owner| {
        overlay
            .members_of(&candidate_owner.id)
            .records
            .iter()
            .any(|symbol| {
                symbol.language == "php"
                    && symbol.kind == SemanticModelSymbolKind::Method
                    && !symbol.is_static
                    && magic
                        .iter()
                        .any(|name| symbol.name.eq_ignore_ascii_case(name))
            })
    });
    if has_magic {
        MemberLookup::Unknown(UnknownReason::DynamicAttributes)
    } else if surface.gaps.is_empty() && !member_surface_is_gapped {
        MemberLookup::Absent
    } else {
        MemberLookup::Unknown(UnknownReason::PackIncomplete)
    }
}

fn workspace_member_lookup(
    workspace: &WorkspaceAnalyzer,
    unit: &CodeUnit,
    kind: MemberAccessKind,
    member: &str,
) -> MemberLookup {
    let php = php_analyzer(workspace);
    if current_indexed_prepared(php, unit.source()).is_none() {
        return MemberLookup::Unknown(UnknownReason::UncertainFlow);
    }
    let workspace_ancestors = php.get_ancestors(unit);
    let open_workspace_surface = workspace_ancestors
        .iter()
        .any(|ancestor| !runtime_workspace_class(workspace, php, ancestor));
    let (external_bases, unresolved) =
        resolved_external_bases(workspace, php, unit, &workspace_ancestors);
    let mut seen = HashSet::default();
    let mut level = vec![unit.clone()];
    let mut depth = 0_usize;
    let mut incompatible = false;
    while !level.is_empty() {
        level.retain(|owner| seen.insert(owner.clone()));
        let (matches, wrong_kind) = workspace_member_at_level(php, &level, kind, member);
        incompatible |= wrong_kind;
        match matches.as_slice() {
            [declaration] => {
                return MemberLookup::Present(MemberLookupHit::new(
                    MemberDeclaration::Workspace(declaration.clone()),
                    if depth == 0
                        || (!unresolved && !open_workspace_surface && external_bases.is_empty())
                    {
                        CandidateCoverage::Exhaustive
                    } else {
                        CandidateCoverage::Open
                    },
                ));
            }
            [] => {}
            _ => return MemberLookup::Unknown(UnknownReason::AmbiguousCallee),
        }
        level = level
            .iter()
            .flat_map(|owner| php.get_direct_ancestors(owner))
            .collect();
        level.sort();
        level.dedup();
        depth += 1;
    }

    let all_workspace_owners = std::iter::once(unit.clone())
        .chain(workspace_ancestors.iter().cloned())
        .collect::<Vec<_>>();
    if workspace_magic_present(php, &all_workspace_owners, kind) {
        return MemberLookup::Unknown(UnknownReason::DynamicAttributes);
    }
    let overlay = overlay_of(workspace);
    for base in external_bases {
        let ClassIdentity::External { symbol_id, .. } = base else {
            unreachable!("resolved external bases retain external identities")
        };
        let Some(overlay) = overlay.as_deref() else {
            return MemberLookup::Unknown(UnknownReason::ExternalNotModeled);
        };
        match external_member_lookup(overlay, &symbol_id, kind, member) {
            present @ MemberLookup::Present(_) => return present,
            MemberLookup::Absent => {}
            MemberLookup::Unknown(reason) => return MemberLookup::Unknown(reason),
        }
    }
    if incompatible {
        MemberLookup::Unknown(UnknownReason::UncertainFlow)
    } else if unresolved || open_workspace_surface {
        MemberLookup::Unknown(UnknownReason::UnresolvedBase)
    } else {
        MemberLookup::Absent
    }
}

fn accessed_member(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    site: MemberAccessQuery<'_>,
) -> Option<Box<str>> {
    let semantics = procedure.semantics();
    match site {
        MemberAccessQuery::Call(call) => {
            let callee = semantics.value(call.callee)?;
            let mapping = semantics.source_mapping(callee.source)?;
            if mapping.kind != SourceMappingKind::Exact {
                return None;
            }
            let file = file_for_locator(workspace, &mapping.locator)?;
            let prepared = prepared_for_procedure(workspace, procedure, &file).ok()?;
            let node = node_at_span(&prepared, mapping.locator.anchor().span())?;
            let call = nearest_call(node)?;
            if !matches!(
                call.kind(),
                "member_call_expression" | "nullsafe_member_call_expression"
            ) {
                return None;
            }
            let name = call.child_by_field_name("name")?;
            (name.kind() == "name")
                .then(|| node_text(name, prepared.source()))
                .flatten()
                .filter(|name| !name.is_empty())
                .map(Box::from)
        }
        MemberAccessQuery::Load(location) => {
            let MemoryLocationKind::Field { member, .. } = &location.kind else {
                return None;
            };
            let file = file_for_locator(workspace, member)?;
            let prepared = prepared_for_procedure(workspace, procedure, &file).ok()?;
            let node = node_at_span(&prepared, member.anchor().span())?;
            if node.kind() == "variable_name" {
                let mut ancestor = node.parent();
                while let Some(candidate) = ancestor {
                    if matches!(
                        candidate.kind(),
                        "property_declaration" | "property_promotion_parameter"
                    ) {
                        let name = variable_identifier(node, prepared.source());
                        return (!name.is_empty()).then(|| Box::from(name));
                    }
                    if matches!(
                        candidate.kind(),
                        "function_definition"
                            | "method_declaration"
                            | "anonymous_function"
                            | "arrow_function"
                    ) {
                        break;
                    }
                    ancestor = candidate.parent();
                }
            }
            let mut current = Some(node);
            while let Some(candidate) = current {
                if matches!(
                    candidate.kind(),
                    "member_access_expression" | "nullsafe_member_access_expression"
                ) {
                    let name = candidate.child_by_field_name("name")?;
                    return (name.kind() == "name")
                        .then(|| node_text(name, prepared.source()))
                        .flatten()
                        .filter(|name| !name.is_empty())
                        .map(Box::from);
                }
                if matches!(
                    candidate.kind(),
                    "function_definition"
                        | "method_declaration"
                        | "anonymous_function"
                        | "arrow_function"
                ) {
                    return None;
                }
                current = candidate.parent();
            }
            None
        }
    }
}

impl TypeFlowAdapter for PhpTypeFlowAdapter {
    fn language(&self) -> Language {
        Language::Php
    }

    fn semantics_version(&self) -> AdapterSemanticsVersion {
        AdapterSemanticsVersion::hash_bytes("php-type-flow", b"php-type-flow-v1")
            .expect("adapter name is non-empty")
    }

    fn constructed_class(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        call: &SemanticCallSite,
    ) -> ClassSeed {
        let semantics = procedure.semantics();
        let Some(callee) = semantics.value(call.callee) else {
            return ClassSeed::Unknown(UnknownReason::UncertainFlow);
        };
        let Some(mapping) = semantics.source_mapping(callee.source) else {
            return ClassSeed::Unknown(UnknownReason::UncertainFlow);
        };
        if mapping.kind != SourceMappingKind::Exact {
            return ClassSeed::NotApplicable;
        }
        let Some(file) = file_for_locator(workspace, &mapping.locator) else {
            return ClassSeed::NotApplicable;
        };
        let prepared = match prepared_for_procedure(workspace, procedure, &file) {
            Ok(prepared) => prepared,
            Err(reason) => return ClassSeed::Unknown(reason),
        };
        let Some(node) = node_at_span(&prepared, mapping.locator.anchor().span()) else {
            return ClassSeed::Unknown(UnknownReason::UncertainFlow);
        };
        let Some(candidate) = nearest_call(node) else {
            return ClassSeed::NotApplicable;
        };
        if candidate.kind() != "object_creation_expression" {
            return ClassSeed::NotApplicable;
        }
        let Some(class) = object_creation_type(candidate) else {
            return ClassSeed::Unknown(UnknownReason::OpenTypeBound);
        };
        if !(class.start_byte() <= node.start_byte() && class.end_byte() >= node.end_byte()) {
            return ClassSeed::NotApplicable;
        }
        resolve_constructor(workspace, procedure, &file, &prepared, candidate)
    }

    fn constant_class(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        value: &SemanticValue,
    ) -> ClassSeed {
        let Some(mapping) = procedure.semantics().source_mapping(value.source) else {
            return ClassSeed::Unknown(UnknownReason::UncertainFlow);
        };
        if mapping.kind != SourceMappingKind::Exact {
            return ClassSeed::Unknown(UnknownReason::UncertainFlow);
        }
        let Some(file) = file_for_locator(workspace, &mapping.locator) else {
            return ClassSeed::NotApplicable;
        };
        if let Err(reason) = prepared_for_procedure(workspace, procedure, &file) {
            return ClassSeed::Unknown(reason);
        }
        ClassSeed::Unknown(UnknownReason::ScalarReceiver)
    }

    fn retained_value_class(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        value: &SemanticValue,
    ) -> ClassSeed {
        if !matches!(
            value.kind,
            SemanticValueKind::Callable | SemanticValueKind::Temporary
        ) {
            return ClassSeed::NotApplicable;
        }
        let Some(mapping) = procedure.semantics().source_mapping(value.source) else {
            return ClassSeed::NotApplicable;
        };
        if mapping.kind != SourceMappingKind::Exact {
            return ClassSeed::NotApplicable;
        }
        let Some(file) = file_for_locator(workspace, &mapping.locator) else {
            return ClassSeed::NotApplicable;
        };
        let prepared = match prepared_for_procedure(workspace, procedure, &file) {
            Ok(prepared) => prepared,
            Err(reason) => return ClassSeed::Unknown(reason),
        };
        let Some(node) = node_at_span(&prepared, mapping.locator.anchor().span()) else {
            return ClassSeed::NotApplicable;
        };
        match node.kind() {
            "array_creation_expression" => ClassSeed::Unknown(UnknownReason::ScalarReceiver),
            "anonymous_function" | "arrow_function" => {
                ClassSeed::Unknown(UnknownReason::ExternalNotModeled)
            }
            _ => ClassSeed::NotApplicable,
        }
    }

    fn allocation_class(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        allocation: &AllocationSite,
    ) -> ClassSeed {
        let shared_with_call = procedure.semantics().call_sites().iter().any(|call| {
            call.result == Some(allocation.result)
                || call.normal_results.contains(&allocation.result)
        });
        if shared_with_call {
            ClassSeed::NotApplicable
        } else if allocation.kind == AllocationKind::Array {
            let Some(mapping) = procedure.semantics().source_mapping(allocation.source) else {
                return ClassSeed::Unknown(UnknownReason::UncertainFlow);
            };
            if mapping.kind != SourceMappingKind::Exact {
                return ClassSeed::Unknown(UnknownReason::UncertainFlow);
            }
            let Some(file) = file_for_locator(workspace, &mapping.locator) else {
                return ClassSeed::Unknown(UnknownReason::UncertainFlow);
            };
            match prepared_for_procedure(workspace, procedure, &file) {
                Ok(_) => ClassSeed::Unknown(UnknownReason::ScalarReceiver),
                Err(reason) => ClassSeed::Unknown(reason),
            }
        } else {
            ClassSeed::Unknown(UnknownReason::UncertainFlow)
        }
    }

    fn declared_parameter_class(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        ordinal: u32,
    ) -> ClassSeed {
        declared_parameter_seed(workspace, procedure, ordinal)
    }

    fn accessed_member(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        site: MemberAccessQuery<'_>,
    ) -> Option<Box<str>> {
        accessed_member(workspace, procedure, site)
    }

    fn member_lookup(
        &self,
        workspace: &WorkspaceAnalyzer,
        kind: MemberAccessKind,
        class: &ClassIdentity,
        member: &str,
    ) -> MemberLookup {
        match class {
            ClassIdentity::Workspace(unit) => {
                workspace_member_lookup(workspace, unit, kind, member)
            }
            ClassIdentity::External { symbol_id, .. } => {
                let Some(overlay) = overlay_of(workspace) else {
                    return MemberLookup::Unknown(UnknownReason::ExternalNotModeled);
                };
                external_member_lookup(&overlay, symbol_id, kind, member)
            }
        }
    }

    fn enclosing_class(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
    ) -> Option<ClassIdentity> {
        let file = file_for_locator(workspace, procedure.semantics().locator())?;
        let span = procedure.semantics().locator().anchor().span();
        let range = crate::analyzer::Range {
            start_byte: span.start_byte() as usize,
            end_byte: span.end_byte() as usize,
            start_line: span.start().line() as usize,
            end_line: span.end().line() as usize,
        };
        let mut unit = workspace.analyzer().enclosing_code_unit(&file, &range)?;
        loop {
            if unit.is_class() && runtime_workspace_class(workspace, php_analyzer(workspace), &unit)
            {
                return Some(ClassIdentity::Workspace(unit));
            }
            unit = workspace.analyzer().parent_of(&unit)?;
        }
    }

    fn class_hierarchy(
        &self,
        workspace: &WorkspaceAnalyzer,
        class: &ClassIdentity,
    ) -> ClassHierarchy {
        let ClassIdentity::Workspace(unit) = class else {
            return ClassHierarchy::unknown();
        };
        let php = php_analyzer(workspace);
        if !runtime_workspace_class(workspace, php, unit) {
            return ClassHierarchy::unknown();
        }
        let mut workspace_ancestors = php.get_ancestors(unit);
        workspace_ancestors.sort();
        workspace_ancestors.dedup();
        let open_workspace_surface = workspace_ancestors
            .iter()
            .any(|ancestor| !runtime_workspace_class(workspace, php, ancestor));
        let (external_ancestors, mut unresolved_base) =
            resolved_external_bases(workspace, php, unit, &workspace_ancestors);
        unresolved_base |= open_workspace_surface;
        let workspace_owners = std::iter::once(unit.clone())
            .chain(workspace_ancestors.iter().cloned())
            .collect::<Vec<_>>();
        let mut dynamic_attributes =
            workspace_magic_present(php, &workspace_owners, MemberAccessKind::Call)
                || workspace_magic_present(php, &workspace_owners, MemberAccessKind::Load);
        if let Some(overlay) = overlay_of(workspace) {
            for external in &external_ancestors {
                let ClassIdentity::External { symbol_id, .. } = external else {
                    unreachable!("external ancestors retain external identities")
                };
                let owners = overlay.symbols_with_id(symbol_id).records;
                let [owner] = owners.as_slice() else {
                    unresolved_base = true;
                    continue;
                };
                let surface = overlay.owner_surface(owner);
                unresolved_base |= !surface.gaps.is_empty();
                dynamic_attributes |= surface.closure.iter().any(|candidate_owner| {
                    overlay
                        .members_of(&candidate_owner.id)
                        .records
                        .iter()
                        .any(|symbol| {
                            symbol.language == "php"
                                && symbol.kind == SemanticModelSymbolKind::Method
                                && ["__call", "__callStatic", "__get", "__set"]
                                    .iter()
                                    .any(|name| symbol.name.eq_ignore_ascii_case(name))
                        })
                });
            }
        }
        let descendants = workspace_class_is_final(php, unit).then(Vec::new);
        let mut ancestors = workspace_ancestors
            .into_iter()
            .map(ClassIdentity::Workspace)
            .chain(external_ancestors)
            .collect::<Vec<_>>();
        ancestors.sort_by(|left, right| left.qualified_name().cmp(right.qualified_name()));
        ancestors.dedup();
        ClassHierarchy {
            ancestors,
            descendants,
            unresolved_base,
            dynamic_attributes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PhpTypeFlowAdapter, php_analyzer, prepared_for_procedure};
    use crate::analyzer::semantic::{
        CancellationToken, ClassIdentity, SemanticBudget, SemanticRequest, TypeFlowAdapter,
        UnknownReason,
    };
    use crate::analyzer::{AnalyzerConfig, CodeUnitIndex, Language};
    use crate::inline_project::InlineTestProject;

    #[test]
    fn prepared_syntax_validator_accepts_exact_php_and_rejects_changed_content() {
        let project = InlineTestProject::with_language(Language::Php)
            .file("app.php", "<?php\nfunction target(): int { return 1; }\n")
            .build();
        let file = project.file("app.php");
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("PHP semantic materialization succeeds")
            .available_value()
            .cloned()
            .expect("PHP semantic artifact is available");
        let procedure = artifact
            .procedures()
            .first()
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("fixture has one procedure");

        assert!(prepared_for_procedure(&workspace, &procedure, &file).is_ok());

        std::fs::write(
            file.abs_path(),
            "<?php\nfunction target(): int { return 2; }\n",
        )
        .expect("change fixture content");
        let changed_workspace = project.workspace_analyzer(AnalyzerConfig::default());
        assert_eq!(
            prepared_for_procedure(&changed_workspace, &procedure, &file)
                .expect_err("changed content cannot validate an old artifact"),
            UnknownReason::UncertainFlow
        );
    }

    #[test]
    fn only_a_structurally_final_php_class_has_a_closed_descendant_inventory() {
        let project = InlineTestProject::with_language(Language::Php)
            .file(
                "app.php",
                "<?php\nclass OpenClass {}\nfinal class FinalClass {}\n",
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let php = php_analyzer(&workspace);
        let one_class = |name: &str| {
            let classes = php
                .definitions(name)
                .filter(|unit| unit.is_class())
                .collect::<Vec<_>>();
            assert_eq!(
                classes.len(),
                1,
                "fixture has one {name} class: {classes:#?}"
            );
            ClassIdentity::Workspace(classes[0].clone())
        };

        let open = PhpTypeFlowAdapter.class_hierarchy(&workspace, &one_class("OpenClass"));
        assert_eq!(open.descendants, None);
        let final_class = PhpTypeFlowAdapter.class_hierarchy(&workspace, &one_class("FinalClass"));
        assert_eq!(final_class.descendants, Some(Vec::new()));
    }
}
