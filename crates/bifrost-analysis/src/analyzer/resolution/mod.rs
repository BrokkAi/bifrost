//! Compositional name and member resolution over immutable file-local facts.
//!
//! This module owns the operation-local algebra and stitcher. Persistence and
//! language lowering are deliberately separate: both the preload test source
//! and the eventual SQL source present the same normalized fragment contract.

mod batch;
mod common_fact_lowering;
mod completion_reasons;
mod demand_overlay;
mod engine;
mod fact_lowering;
mod fact_reference_edges;
mod fact_resolution;
mod fact_source;
mod local_identity;
mod model;
mod mounted;
mod remount;
mod saturation;
pub mod seam_profile;
pub mod seed_key_profile;
mod selected_context;
#[cfg(test)]
pub(crate) mod test_support;
mod typed_fact_lowering;
mod universe;
pub use universe::UniverseEntry;
pub(crate) use universe::{has_table as universe_has_table, lookup as universe_lookup};

use crate::hash::{HashMap, HashSet};

fn write_profile_line(
    output: &std::sync::Mutex<std::fs::File>,
    line: &str,
    poison_message: &str,
    profile_name: &str,
) {
    use std::io::Write;

    let mut output = output.lock().expect(poison_message);
    if let Err(error) = writeln!(output, "{line}").and_then(|()| output.flush()) {
        eprintln!("Bifrost {profile_name} could not write a line: {error}");
    }
}

pub(crate) use engine::cancelled_completion;
pub(crate) use fact_source::{ResolutionIdentityDomain, language_identity_domain};

pub(crate) fn with_bounded_resolution_session<T>(
    budget: brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget,
    cancellation: &crate::CancellationToken,
    operation: impl FnOnce(
        &brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession,
    ) -> crate::analyzer::store::Result<T>,
) -> crate::analyzer::store::Result<
    brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution<T>,
> {
    use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

    let session = ResolutionSession::bounded(budget, Some(cancellation));
    let answer = operation(&session)?;
    Ok(session.finish(answer))
}

pub(crate) fn callable_receiver_is_incomplete(
    origin: Option<
        brokk_bifrost_core::analyzer::resolution_facts::ResolutionCallableReceiverOrigin,
    >,
    completion: &ResolutionCompletion,
) -> bool {
    origin.is_some() && completion != &ResolutionCompletion::Complete
}

pub(super) fn assert_fresh_metrics_sink<T>(sink: &T, message: &str)
where
    T: std::fmt::Debug + PartialEq + Default,
{
    assert_eq!(sink, &T::default(), "{message}");
}

pub(super) fn add_estimated_map_values(
    base: usize,
    values: impl IntoIterator<Item = usize>,
) -> usize {
    values.into_iter().fold(base, usize::saturating_add)
}

pub(super) fn poll_resolution_work(
    cancellation: &crate::CancellationToken,
    work: &mut usize,
) -> bool {
    *work = work
        .checked_add(1)
        .expect("resolution cancellation work must fit usize");
    work.is_multiple_of(engine::CANCELLATION_QUANTUM) && cancellation.is_cancelled()
}

pub(super) fn observe_resolution_row(
    cancellation: &crate::CancellationToken,
    work: &mut usize,
) -> bool {
    poll_resolution_work(cancellation, work) | cancellation.is_cancelled()
}

pub(crate) fn lookup_definition_node(
    source: &dyn batch::BatchResolutionFragmentSource,
    definition: SemanticId,
    cancellation: &crate::CancellationToken,
) -> crate::analyzer::store::Result<Option<BindingNodeId>> {
    source.lookup_definition_node(definition, cancellation)
}

pub(super) fn closed_endpoint(
    node: BindingNodeId,
    symbols: impl Into<Box<[SemanticId]>>,
) -> EndpointSignature {
    EndpointSignature::new(
        node,
        StackPattern::closed(symbols),
        StackPattern::closed(Vec::new()),
    )
}

fn endpoint_has_empty_scopes(endpoint: &model::EndpointSignature) -> bool {
    endpoint.scopes().fixed().is_empty() && endpoint.scopes().tail().is_none()
}

pub(crate) fn reference_inventory_completion_with_session(
    completion: ResolutionCompletion,
    cancellation: &crate::CancellationToken,
    session: &brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession,
) -> ResolutionCompletion {
    if let ResolutionCompletion::Incomplete(reasons) = &completion {
        for _ in reasons.iter() {
            if !session.scope_step() || cancellation.is_cancelled() {
                return completion.combine(&cancelled_completion());
            }
        }
    }
    if cancellation.is_cancelled() || !session.observe_cancellation() {
        completion.combine(&cancelled_completion())
    } else {
        completion
    }
}

pub(super) fn open_endpoint(
    node: BindingNodeId,
    symbols: impl Into<Box<[SemanticId]>>,
    variable: StackVariableId,
) -> EndpointSignature {
    EndpointSignature::new(
        node,
        StackPattern::open(symbols, variable),
        StackPattern::closed(Vec::new()),
    )
}

pub(super) fn required_positioned_identifier(
    identifier: Option<&brokk_bifrost_core::analyzer::resolution_facts::PositionedIdentifierFact>,
    site: brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId,
) -> &brokk_bifrost_core::analyzer::resolution_facts::PositionedIdentifierFact {
    identifier.unwrap_or_else(|| panic!("site {site} has no positioned identifier"))
}

pub(super) const fn qualifier_compatibility_rank(
    compatibility: brokk_bifrost_core::analyzer::resolution_facts::ResolutionMemberQualifierCompatibility,
) -> u8 {
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionMemberQualifierCompatibility;

    match compatibility {
        ResolutionMemberQualifierCompatibility::RuntimeOnly => 0,
        ResolutionMemberQualifierCompatibility::TypeOnly => 1,
        ResolutionMemberQualifierCompatibility::RuntimeOrType => 2,
    }
}

pub(super) fn assert_reference_identifier(
    identifier: &brokk_bifrost_core::analyzer::resolution_facts::PositionedIdentifierFact,
) {
    assert_eq!(
        identifier.role,
        brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole::Reference
    );
}

pub(super) fn charge_summary_step(
    session: Option<&brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession>,
) -> bool {
    session.is_none_or(
        brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession::summary_step,
    )
}

pub(super) fn required_resolution_name<'a>(
    names: &HashMap<brokk_bifrost_core::analyzer::resolution_facts::ResolutionNameId, &'a str>,
    id: brokk_bifrost_core::analyzer::resolution_facts::ResolutionNameId,
) -> &'a str {
    names
        .get(&id)
        .copied()
        .unwrap_or_else(|| panic!("unknown resolution name {id}"))
}

pub(super) fn required_resolution_scope(
    scopes: &HashMap<
        brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId,
        brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeFact,
    >,
    id: brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId,
) -> brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeFact {
    *scopes
        .get(&id)
        .unwrap_or_else(|| panic!("unknown resolution scope {id}"))
}

#[cfg(test)]
fn runtime_type_for_test(value: &str) -> ResolutionSlotValue {
    ResolutionSlotValue::runtime(
        ResolutionTypeRef::new(SemanticId::for_test(value), 0),
        false,
    )
}

#[cfg(test)]
fn positioned_identifier_for_test(
    site: u32,
    name: u32,
    role: brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole,
    namespace: brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace,
) -> brokk_bifrost_core::analyzer::resolution_facts::PositionedIdentifierFact {
    test_support::identifier(site, name, role, namespace, None)
}

#[cfg(test)]
fn partial_path_id_for_test(value: &str) -> PartialPathId {
    PartialPathId::for_test(value)
}
pub(crate) use fact_lowering::jvm_type_prefix_gap_origin_is_safe;

static GO_UNIVERSE_IDENTITY_DIGESTS: std::sync::LazyLock<HashSet<[u8; 32]>> =
    std::sync::LazyLock::new(|| {
        universe::go_entries()
            .map(universe::identity_digest)
            .collect()
    });

pub(crate) fn go_universe_identity_digest(
    namespace: brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace,
    spelling: &str,
) -> Option<[u8; 32]> {
    universe::lookup(
        brokk_bifrost_core::analyzer::Language::Go,
        namespace,
        spelling,
    )
    .map(universe::identity_digest)
}

fn never_cancelled() -> bool {
    false
}

/// Recognize one selected Go universe identity without projecting it as a
/// source declaration. The Go universe is a fixed language table, and each
/// entry is compared through the same shared identity used during binding.
pub(crate) fn is_go_universe_identity(
    source: &impl BatchResolutionFragmentSource,
    identity: SemanticId,
    cancellation: &crate::CancellationToken,
) -> crate::analyzer::store::Result<Option<bool>> {
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    if !source.supports_go_universe() {
        return Ok(Some(false));
    }
    let Some(digest) = source.shared_name_digest_for_identity(identity, cancellation)? else {
        return if cancellation.is_cancelled() {
            Ok(None)
        } else {
            Ok(Some(false))
        };
    };
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    Ok(Some(GO_UNIVERSE_IDENTITY_DIGESTS.contains(&digest)))
}

fn required_resolution_site(
    sites: &crate::hash::HashMap<
        brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId,
        brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteFact,
    >,
    id: brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId,
) -> brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteFact {
    *sites
        .get(&id)
        .unwrap_or_else(|| panic!("unknown resolution site {id}"))
}

pub(super) const fn resolution_member_kind_rank(
    kind: brokk_bifrost_core::analyzer::resolution_facts::ResolutionMemberKind,
) -> u8 {
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionMemberKind;

    match kind {
        ResolutionMemberKind::NestedType => 0,
        ResolutionMemberKind::Method => 1,
        ResolutionMemberKind::Constructor => 2,
        ResolutionMemberKind::Field => 3,
        ResolutionMemberKind::AssociatedType => 4,
    }
}

pub(super) const fn binding_projection_kind_rank(
    kind: brokk_bifrost_core::analyzer::resolution_facts::BindingProjectionKind,
) -> u8 {
    use brokk_bifrost_core::analyzer::resolution_facts::BindingProjectionKind;

    match kind {
        BindingProjectionKind::TargetTypeIdentity => 0,
        BindingProjectionKind::TargetDeclaredValueType => 1,
        BindingProjectionKind::TargetCallableResultType => 2,
        BindingProjectionKind::TargetConstructorOwnerType => 3,
        BindingProjectionKind::TargetTypeOrDeclaredValueType => 4,
        BindingProjectionKind::TargetMemberOwnerType => 5,
        BindingProjectionKind::TargetNominalTypeIdentity => 6,
        BindingProjectionKind::TargetCallableLaterResultType => 7,
    }
}

pub(super) const fn declaration_type_role_rank(
    role: brokk_bifrost_core::analyzer::resolution_facts::DeclarationTypeRole,
) -> u8 {
    use brokk_bifrost_core::analyzer::resolution_facts::DeclarationTypeRole;

    match role {
        DeclarationTypeRole::Value => 0,
        DeclarationTypeRole::Parameter => 1,
        DeclarationTypeRole::Return => 2,
        DeclarationTypeRole::Identity => 3,
        DeclarationTypeRole::NominalIdentity => 4,
        DeclarationTypeRole::CallableFirstResult => 5,
    }
}

pub use batch::{
    BatchCandidateCompletionOutcome, BatchCandidateMatch, BatchCandidateOutcome,
    BatchCandidateRequest, BatchDefinitionNode, BatchEndpointClassification, BatchReferenceSeed,
    BatchResolutionEngine, BatchResolutionFragmentSource, BatchedReferenceAnswer,
    CandidatePathIdentity, FactReferenceSiteMetadata, MAX_REFERENCE_SEEDS_PER_BATCH,
    ReferenceBatchAnswer, ReferenceLocalPathEvidence, ReferenceSeed, ReferenceSeedBatch,
    ReferenceSeedReadOutcome, ReferenceSeedReadTerminal, ResolutionBatchMetrics,
    ResolutionBatchSummary, ReverseCandidateGapExclusionPlan, ReverseCandidateGapIdentity,
    ReverseReferenceSeedRequest, SeedReadAuthority, SeededPartialPath, SeededReferenceRequest,
};
pub(crate) use batch::{
    ForwardCandidateArtifactCache, MAX_REVERSE_TARGETS_PER_BATCH, MAX_SOURCE_ROWS_PER_BATCH,
    ReverseCandidateGapCoverage, ReverseCandidateGapCoverageBuilder,
    ReverseCandidateGapCoverageView, ReverseCandidateGapLocation, ReverseCandidateGapRow,
    SelectedContextPathFragmentSource,
};
pub use common_fact_lowering::LoweredDeferredMemberOwner;
pub(crate) use common_fact_lowering::{
    LoweredReferenceLookupIdentity, LoweredRootImportProvenance,
};
pub use completion_reasons::CompletionReasons;
pub(crate) use demand_overlay::DemandSelectedOverlayBlueprint;
pub use engine::{
    PreloadedFragment, PreloadedFragmentSource, ReferenceSearchAnswer, ResolutionEngine,
    ResolutionFragmentSource, ResolutionQuery,
};
#[cfg(any(test, feature = "test-support"))]
pub(crate) use fact_lowering::fixture_names::{
    FixtureRootImportAnchors, record as record_fixture_identity_catalog,
};
pub(crate) use fact_lowering::package::{
    LoweredGoPackageImport, LoweredPackageMember, LoweredPackageReference, package_domain_semantic,
};
pub use fact_lowering::{
    LoweredCandidateDirection, LoweredCoverageGap, LoweredResolutionFragment, LoweredSemanticRole,
    LoweredSemanticSite, LoweringCoverageFrontier, LoweringGapOrigin,
};
#[cfg(any(test, feature = "test-support"))]
pub(crate) use fact_lowering::{
    catalog_node, catalog_semantic, lower_for_test, lower_lexical_for_test,
};
pub(crate) use fact_lowering::{
    definition_node, definition_node_identity, definition_semantic, gap_reason_semantic,
    hierarchy_terminal_node_identity, lookup_semantic, mounted_site_node, mounted_site_semantic,
    placement_gap_path_id, reference_node_identity, reference_semantic, root_export_path_id,
    scope_head_node, scope_head_node_identity, structured_import_gap_path_id,
};
pub(crate) use fact_lowering::{
    root_export_token, root_import_anchor_for_identity, root_import_anchor_semantic_identity,
    root_import_token,
};
pub(crate) use fact_reference_edges::NativeReferenceEdgeBatchProjector;
#[cfg(any(test, feature = "test-support"))]
pub(crate) use fact_reference_edges::validate_selected_reference_edge_coverage;
pub use fact_reference_edges::{
    FactCallableReceiverTargetAdmission, FactCallableReceiverTargetProjection,
    FactReferenceBindingShape, FactReferenceEdgeBatch, FactReferenceEdgeCatalog,
    FactReferenceEdgeDeclarationDomain, FactReferenceEdgeDomainStatus, FactReferenceEdgeGap,
    FactReferenceEdgeGapDomain, FactReferenceEdgeSelectedFragment, FactReferenceEdgeSummary,
    FactReferenceGraphAdmission, FactReferenceProjectionStatus, FactReferenceTargetProjection,
    classify_fact_reference_binding, fact_callable_receiver_target_admission,
    project_fact_callable_receiver_target, project_fact_reference_edge_batch,
    project_fact_reference_targets, stage_selected_reference_edge_batches,
};
#[cfg(any(test, feature = "test-support"))]
pub use fact_reference_edges::{
    SelectedReferenceInverseIndex, SelectedReferenceInverseIndexBuildOutcome,
    build_selected_reference_inverse_index,
};
#[cfg(any(test, feature = "test-support"))]
pub use fact_resolution::PreloadedFactResolutionService;
pub(crate) use fact_resolution::call_applicability::{
    ArgumentFormalBinding, CallApplicabilityAdapter, CandidateAssessment, ConversionEvidence,
    ConversionKind, MappingAssessment, PartialOrder, TypeInCallPosition, map_call_shape,
};
pub(crate) use fact_resolution::{
    AnswerMap, CallCandidateApplicability, DemandAcyclicOutcome, DemandClosureDischarges,
    DemandRootDiscovery, DemandRootPlan, DemandRootProvider, DemandRootUnavailableReason,
    FactDemandResolution, FactEvaluation, InternedFactRow, StateMap,
};
pub use fact_resolution::{
    FactBatchedReferenceAnswer, FactCallableCandidateApplicability, FactCallableReceiverChannels,
    FactCallableReceiverDisposition, FactCallableReceiverTargetDisposition, FactReadSession,
    FactReferenceBatchAnswer, FactReferenceReceiverGap, FactResolutionAnswer,
    FactResolutionBatchSummary, FactReverseReferenceBinding, FactReverseResolutionMetrics,
    FactTargetReferenceAnswer, FactTargetReferenceBatchAnswer, SelectedFactResolutionEngine,
    SelectedFactResolutionSnapshot,
};
pub(crate) use fact_resolution::{
    FactIntrinsicTypeDescriptor, FactMemberRouteKind, FactProjectedTypeNode,
    FactProjectedTypeNodeForm, FactProjectedTypeShape, FactResolutionOperation,
    ForwardOperationArtifactContext, GoReceiverSlotTypeOverlay, PolledCompletionAccumulator,
    SelectedFactOperationBlueprint, SelectedFactOperationBlueprintConstruction,
};
#[cfg(any(test, feature = "test-support"))]
pub use fact_resolution::{
    reset_reverse_fact_evaluation_count_for_test, reverse_fact_evaluation_count_for_test,
};
#[cfg(test)]
pub(crate) use fact_resolution::{
    reset_selected_fact_operation_construction_count_for_test,
    selected_fact_operation_construction_count_for_test,
};
pub(crate) use fact_source::{
    CompanionTypeRelation, DeclarationAccessDecision, DeclarationAccessRequest,
    DeclarationAccessRow, JvmDeclarationAccessRules, JvmImplicitRootProvider, ReasonOwnerRow,
    RustDeclarationContextSource, RustReferenceContextSource, SelectedDeclarationAccessSource,
    SubclassAccessContext, language_direct_member_miss_stays_open, language_has_jvm_semantics,
    language_implicit_root_providers, language_jvm_declaration_access_rules,
    language_type_qualifiers_search_companion_members, visit_mapped_typed_pages,
};
pub use fact_source::{
    DeferredMemberOwnerLookupName, FactPageVisitor, FactReadOutcome, FactReadTerminal, FactRequest,
    FactResolutionSource, GoInterfaceMethod, GoMemberDeclaration, GoMemberDeclarationKind,
    GoStructField, JavaAccessEndpoint, JavaInheritanceDeclaration, JavaInheritanceDeclarationKind,
    JvmAccessEndpoint, LoweredIntrinsicTypeDescriptor, LoweredRustDeclarationAuthority,
    LoweredRustReferenceContext, MAX_FACT_REQUESTS_PER_BATCH, MAX_FACT_ROWS_PER_PAGE,
    MAX_TYPED_FACT_REQUESTS_PER_BATCH, MAX_TYPED_FACT_ROWS_PER_PAGE, NamedArgumentLabel,
    NamedArgumentLabelRead, QualifiedRouteSlotLookup, RustImplementedTraits, SelectedFactRow,
    SelectedGapReasonProvenance, SelectedQualifiedRoute, SelectedTypeFrontierCompletion,
    SelectedTypedFactSource, SelectedTypedRow, TypedFactPageVisitor, TypedFactReadOutcome,
    TypedFactReadTerminal, TypedFactRequest,
};
pub(crate) use local_identity::ResolutionRegisteredIdentities;
pub(crate) use local_identity::SUPPLEMENTAL_LOCAL_KEY_BASE;
#[cfg(any(test, feature = "test-support"))]
pub(crate) use local_identity::test_shared_names;
pub(crate) use local_identity::{
    MountRebaser, MountRebaserRegistration, ResolutionIdentityCatalog,
    ResolutionIdentityCatalogBuilder, ResolutionLocalKey, ResolutionLookupSemanticRecipe,
    ResolutionNodeIdentity, ResolutionPathIdentity, ResolutionSemanticIdentity,
    ResolutionSemanticIdentitySpace, ResolutionStackVariableIdentity,
    SelectedLocalIdentityProvenance, SelectedNodeMount, SelectedNodeProvenance,
    SelectedResolutionFragmentDigest, SelectedResolutionMount, SelectedResolutionMountOrdinal,
    SelectedSemanticLocator, SelectedSemanticMount, SelectedSemanticProvenance,
    SelectedStageIdentityProvenance, selected_resolution_fragment_id,
};
pub use local_identity::{PerRequestSharedNames, SharedNameInterner};
pub use model::{
    BindingCandidateAdmission, BindingFragmentId, BindingNodeId, BindingNodeKind, CompletionReason,
    DerivationKey, EndpointSignature, GoDefinitionNamespaces, PartialPath, PartialPathId,
    PartialScopedSymbol, PrecedenceStep, ResolutionAnswer, ResolutionCompletion,
    ResolutionIncompleteReason, ResolutionSlotValue, ResolutionTypeRef, ResolutionWitness,
    ScopeStackPattern, SemanticId, SharedNameId, StackPattern, StackVariable, StackVariableId,
    SymbolStackPattern, TypeTransferRule, TypeTransferValueTransform, TypedFrontierState,
    WitnessStep,
};
pub(crate) use model::{ResolutionCompletionAccumulator, combine_completion_with_poll};
#[cfg(any(test, feature = "test-support"))]
pub(crate) use mounted::OperationBlind;
pub(crate) use mounted::{Mounted, SpliceMount, into_interior, out_of_interior};
pub(crate) use remount::retarget_lexical;
pub(crate) use seam_profile::SeamProfiled;
pub(crate) use selected_context::{
    CatalogRootImportAnchors, SelectedContextIdentities, SelectedContextOverlay,
    SelectedContextOverlayCompilation, SelectedContextPathPublication,
    SelectedContextPathPublicationOutcome, SelectedContextPathSource, SelectedContextPathToken,
    SelectedJvmBridgeEvidence, SelectedJvmBridgeProvenance, SelectedJvmBridgeVisibility,
    SelectedResolutionContextInputs, SelectedResolutionContextSet,
    SelectedResolutionContextValidationOutcome, SelectedResolutionMountContext,
    SelectedRootBridgeDescriptor, SelectedRootBridgeProjection, SelectedRootImportAnchors,
    SelectedRootPathHalf, classify_selected_root_path_half, compile_selected_context_overlay,
    compile_selected_context_overlay_in_session, compile_selected_root_bridge,
    visit_selected_root_export_half_pages, visit_selected_root_import_half_pages,
    visit_selected_root_import_half_pages_with_targets,
};
pub(crate) use selected_context::{
    SelectedGoImportBindingDescriptor, SelectedPackageBridgeDescriptor,
};
pub(crate) use typed_fact_lowering::call_semantic_identity;
pub use typed_fact_lowering::{
    LoweredBindingProjection, LoweredCallApplicabilityObligation, LoweredCallArgumentProperty,
    LoweredCallableParameterApplicability, LoweredCallableParameterProperty,
    LoweredCallableResultBinding, LoweredCallableResultTypeProperty,
    LoweredCallableSignatureProperty, LoweredConstructionRequirementProperty,
    LoweredDeclarationTypeProperty, LoweredDeclarationVisibilityProperty,
    LoweredDeclaredTypeArgument, LoweredDefinitionPropertyGap, LoweredGenericFormal,
    LoweredGenericTypeAliasParameter, LoweredIntrinsicSeed, LoweredMemberOwnerProperty,
    LoweredMemberScopeProperty, LoweredQualifiedSeededRoute, LoweredSupertypeProperty,
    LoweredTypeArgument, LoweredTypeComponent, LoweredTypeTransfer, LoweredTypedFragment,
    LoweredTypedFrontier, LoweredUnderlyingType,
};
#[cfg(test)]
pub(crate) fn rich_java_resolution_facts_for_test()
-> brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts {
    const SOURCE: &str = r#"
package com.acme;
import dep.A;
import dep.*;
import static dep.Owner.FIELD;
import static dep.Owner.*;

public class Outer extends HierarchyBase {
    public class Nested {}
    public static int FIELD;
    public int qualifiedField;

    public static int method(int parameter) {
        return parameter;
    }

    public int use(A value) {
        int sourceOrderLocal = FIELD;
        this.qualifiedField = sourceOrderLocal;
        return method(value.hashCode());
    }
}
"#;
    let root = std::env::current_dir().expect("test working directory");
    let file = brokk_bifrost_core::analyzer::ProjectFile::new(root, "RichResolution.java");
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .expect("Java grammar must match the shared tree-sitter runtime");
    let tree = parser
        .parse(SOURCE, None)
        .expect("rich Java resolution fixture must parse");
    brokk_bifrost_jvm::java::declarations::parse_java_file(&file, SOURCE, &tree).resolution_facts
}

/// One source-lowered resolution artifact and the complete content identity
/// catalog needed to persist its mounted in-memory IDs as local recipes.
#[derive(Debug)]
pub(crate) struct LoweredResolutionFactsWithIdentityCatalog {
    lexical: LoweredResolutionFragment,
    typed: LoweredTypedFragment,
    common: common_fact_lowering::LoweredCommonFacts,
    identities: Box<ResolutionIdentityCatalog>,
}

fn binder_namespace_matches_kind(
    kind: brokk_bifrost_core::analyzer::resolution_facts::ResolutionBinderKind,
    namespace: brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace,
) -> bool {
    use brokk_bifrost_core::analyzer::resolution_facts::{
        ResolutionBinderKind, ResolutionNamespace,
    };

    match kind {
        ResolutionBinderKind::Type => namespace == ResolutionNamespace::Type,
        ResolutionBinderKind::Callable => namespace == ResolutionNamespace::Callable,
        ResolutionBinderKind::Constructor => namespace == ResolutionNamespace::Constructor,
        ResolutionBinderKind::Field
        | ResolutionBinderKind::Local
        | ResolutionBinderKind::Parameter
        | ResolutionBinderKind::Pattern => namespace == ResolutionNamespace::Value,
        ResolutionBinderKind::Import => namespace != ResolutionNamespace::TypeOrValue,
        ResolutionBinderKind::Macro => namespace == ResolutionNamespace::Macro,
    }
}

fn declaration_namespace_matches_site_kind(
    kind: brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind,
    namespace: brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace,
) -> bool {
    use brokk_bifrost_core::analyzer::resolution_facts::{ResolutionNamespace, ResolutionSiteKind};

    match namespace {
        ResolutionNamespace::Type => matches!(
            kind,
            ResolutionSiteKind::TypeDeclaration | ResolutionSiteKind::TypeAliasDeclaration
        ),
        ResolutionNamespace::Value => kind == ResolutionSiteKind::ValueDeclaration,
        ResolutionNamespace::Callable => kind == ResolutionSiteKind::CallableDeclaration,
        ResolutionNamespace::Constructor => kind == ResolutionSiteKind::ConstructorDeclaration,
        ResolutionNamespace::Macro => kind == ResolutionSiteKind::MacroDeclaration,
        ResolutionNamespace::Constant => kind == ResolutionSiteKind::ValueDeclaration,
        ResolutionNamespace::TypeOrValue | ResolutionNamespace::Package => false,
    }
}

fn producer_declares_definition_namespace(
    facts: &brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts,
    declaration: brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId,
    namespace: brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace,
    hoisting: brokk_bifrost_core::analyzer::structural::resolution::HoistingClass,
) -> bool {
    facts.additional_definition_namespaces.iter().any(|fact| {
        fact.declaration == declaration && fact.namespace == namespace && fact.hoisting == hoisting
    })
}

fn binder_namespace_is_declared(
    facts: &brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts,
    binder: brokk_bifrost_core::analyzer::resolution_facts::ResolutionBinderFact,
    namespace: brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace,
) -> bool {
    binder_namespace_matches_kind(binder.kind, namespace)
        || producer_declares_definition_namespace(
            facts,
            binder.declaration,
            namespace,
            binder.hoisting,
        )
}

fn declaration_namespace_is_declared(
    facts: &brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts,
    declaration: brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId,
    kind: brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind,
    primary_namespace: brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace,
    namespace: brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace,
) -> bool {
    (primary_namespace == namespace && declaration_namespace_matches_site_kind(kind, namespace))
        || facts
            .additional_definition_namespaces
            .iter()
            .any(|fact| fact.declaration == declaration && fact.namespace == namespace)
}

#[cfg(test)]
impl LoweredResolutionFactsWithIdentityCatalog {
    pub(crate) fn clone_for_stage_admission_test(&self) -> Self {
        Self {
            lexical: fact_lowering::LoweredResolutionFragment::new(
                self.lexical.fragment(),
                self.lexical.language(),
                self.lexical.nodes().to_vec(),
                self.lexical.paths().to_vec(),
                self.lexical.semantics().to_vec(),
                self.lexical.gaps().to_vec(),
            ),
            typed: self.typed.clone(),
            common: self.common.clone(),
            identities: self.identities.clone(),
        }
    }

    /// Constructor extension of a real capsule, before publication. The parsed
    /// macro itself need not emit a stack variable.
    pub(crate) fn with_open_variable_for_publication_test(mut self) -> Self {
        let variable = self.identities.register_variable_for_publication_test();
        let selected = self
            .identities
            .paths()
            .iter()
            .min_by_key(|(_, identity)| *identity)
            .unwrap()
            .0;
        let mut paths = self.lexical.paths().to_vec();
        let (_, path) = paths
            .iter_mut()
            .find(|(identity, _)| *identity == selected)
            .unwrap();
        let endpoint = |value: &EndpointSignature| {
            EndpointSignature::new_scoped(
                value.node(),
                StackPattern::open(value.symbols().fixed().to_vec(), variable),
                value.scopes().clone(),
            )
        };
        *path = PartialPath::new(
            endpoint(path.start()),
            endpoint(path.end()),
            path.precedence().to_vec(),
            path.witness().to_vec(),
            path.completion().clone(),
        );
        self.lexical = fact_lowering::LoweredResolutionFragment::new(
            self.lexical.fragment(),
            self.lexical.language(),
            self.lexical.nodes().to_vec(),
            paths,
            self.lexical.semantics().to_vec(),
            self.lexical.gaps().to_vec(),
        );
        self.rekey_dense()
    }

    pub(crate) fn with_changed_reference_end_for_publication_test(&self) -> Self {
        let mut semantics = self.lexical.semantics().to_vec();
        let index = semantics
            .iter()
            .position(|site| site.site_metadata().is_some())
            .expect("fixture has an actual reference");
        let site = &semantics[index];
        let metadata = site.site_metadata().unwrap();
        let changed = FactReferenceSiteMetadata::new(
            metadata.site(),
            metadata.namespace(),
            metadata.site_kind(),
            metadata.start_byte(),
            metadata.end_byte() + 1,
            metadata.unqualified(),
            metadata.reference_owner(),
            metadata.callable_receiver_origin(),
        )
        .with_go_spelling_namespace(metadata.go_spelling_namespace())
        .with_go_package_qualifier(metadata.go_package_qualifier());
        semantics[index] = fact_lowering::LoweredSemanticSite::new(
            site.site(),
            site.namespace(),
            site.role(),
            site.semantic(),
            site.node(),
            Some(changed),
        )
        .with_go_definition_namespaces(site.go_definition_namespaces());
        let lexical = fact_lowering::LoweredResolutionFragment::new(
            self.lexical.fragment(),
            self.lexical.language(),
            self.lexical.nodes().to_vec(),
            self.lexical.paths().to_vec(),
            semantics,
            self.lexical.gaps().to_vec(),
        );
        Self {
            lexical,
            typed: self.typed.clone(),
            common: self.common.clone(),
            identities: self.identities.clone(),
        }
        .rekey_dense()
    }

    pub(crate) fn with_generic_node_payloads_for_publication_test(mut self) -> Self {
        let local = self
            .identities
            .semantics()
            .iter()
            .find(|(_, identity)| identity.shared_name().is_none())
            .unwrap()
            .0;
        let shared = self
            .identities
            .semantics()
            .iter()
            .find(|(_, identity)| identity.shared_name().is_some())
            .unwrap()
            .0;
        let scope = self.identities.register_node_for_publication_test(0);
        let catalog_only = self.identities.register_node_for_publication_test(1);
        let mut nodes = self.lexical.nodes().to_vec();
        nodes.push((scope, BindingNodeKind::Scope));
        let kinds = [
            BindingNodeKind::PushSymbol(local),
            BindingNodeKind::PopSymbol(local),
            BindingNodeKind::PushScopedSymbol(local),
            BindingNodeKind::PopScopedSymbol(local),
            BindingNodeKind::PushSymbol(shared),
            BindingNodeKind::PopSymbol(shared),
            BindingNodeKind::PushScopedSymbol(shared),
            BindingNodeKind::PopScopedSymbol(shared),
            BindingNodeKind::DropScopes,
            BindingNodeKind::JumpToScope(scope),
            BindingNodeKind::JumpToScope(catalog_only),
            BindingNodeKind::JumpToScope(BindingNodeId::universal_root()),
        ];
        for (index, kind) in kinds.into_iter().enumerate() {
            nodes.push((
                self.identities
                    .register_node_for_publication_test(u8::try_from(index + 2).unwrap()),
                kind,
            ));
        }
        self.lexical = fact_lowering::LoweredResolutionFragment::new(
            self.lexical.fragment(),
            self.lexical.language(),
            nodes,
            self.lexical.paths().to_vec(),
            self.lexical.semantics().to_vec(),
            self.lexical.gaps().to_vec(),
        );
        self.rekey_dense()
    }
}

impl LoweredResolutionFactsWithIdentityCatalog {
    /// One lexical-only artifact for a fixture, dense-rekeyed like any other.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn from_lexical_for_test(
        lexical: LoweredResolutionFragment,
        common: common_fact_lowering::LoweredCommonFacts,
        identities: local_identity::ResolutionIdentityCatalog,
        language: brokk_bifrost_core::analyzer::Language,
    ) -> Self {
        let fragment = lexical.fragment();
        Self {
            lexical,
            typed: LoweredTypedFragment::empty(fragment, language),
            common,
            identities: Box::new(identities),
        }
        .rekey_dense()
    }

    pub(crate) const fn lexical(&self) -> &LoweredResolutionFragment {
        &self.lexical
    }

    pub(crate) const fn typed(&self) -> &LoweredTypedFragment {
        &self.typed
    }

    pub(crate) const fn common(&self) -> &common_fact_lowering::LoweredCommonFacts {
        &self.common
    }

    pub(crate) const fn identities(&self) -> &ResolutionIdentityCatalog {
        &self.identities
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        LoweredResolutionFragment,
        LoweredTypedFragment,
        Box<ResolutionIdentityCatalog>,
    ) {
        (self.lexical, self.typed, self.identities)
    }
}

fn assert_lookup_recipes_reach_emitted_artifact(
    lexical: &LoweredResolutionFragment,
    typed: &LoweredTypedFragment,
    common: &common_fact_lowering::LoweredCommonFacts,
    identities: &ResolutionIdentityCatalog,
) {
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
    let mut emitted = HashSet::default();
    for (_, path) in lexical.paths() {
        for endpoint in [path.start(), path.end()] {
            emitted.extend(
                endpoint
                    .symbols()
                    .fixed()
                    .iter()
                    .map(|symbol| symbol.symbol()),
            );
        }
    }
    for gap in lexical.gaps() {
        if let LoweringCoverageFrontier::Candidate {
            lookup: Some(lookup),
            ..
        } = gap.frontier()
        {
            emitted.insert(lookup);
        }
    }
    for route in typed.qualified_routes() {
        emitted.extend([route.lookup(), route.source_lookup()]);
        let member = identities
            .lookup_recipe(route.lookup())
            .expect("member lookup recipe");
        let source = identities
            .lookup_recipe(route.source_lookup())
            .expect("source lookup recipe");
        assert_eq!(member.namespace(), route.namespace());
        assert_eq!(member.identity_domain(), source.identity_domain());
        assert_eq!(member.spelling(), source.spelling());
        assert!(
            source.namespace() == member.namespace()
                || (source.namespace() == ResolutionNamespace::Value
                    && member.namespace() == ResolutionNamespace::Callable),
            "source and member lookup recipes must retain an admitted namespace pair: {source:?}, {member:?}"
        );
    }
    emitted.extend(
        common
            .deferred_member_owners
            .iter()
            .map(|owner| owner.lookup),
    );
    emitted.extend(
        common
            .declared_root_routes
            .iter()
            .map(|route| route.segment),
    );
    emitted.extend(
        common
            .reference_lookup_identities
            .iter()
            .map(|row| row.lookup),
    );
    // The spelled impl-header paths crate derivation walks. A bare `Self`
    // subject has no lexical route, so its lookup is emitted only here.
    for implementation in &common.trait_implementations {
        for path in [&implementation.subject, &implementation.implemented_trait] {
            emitted.extend(path.segments.iter().copied());
            emitted.insert(path.terminal);
        }
    }
    // Protected package stack markers are shared structural identities, not
    // lookup spellings. Their explicit metadata is the only exemption from
    // exact lookup-recipe coverage below.
    let package_domains = common
        .package_references
        .iter()
        .map(|row| row.domain)
        .chain(common.package_members.iter().map(|row| row.domain))
        .collect::<HashSet<_>>();
    for &domain in &package_domains {
        assert!(
            emitted.contains(&domain),
            "package domain must reach an emitted path"
        );
        assert_eq!(
            identities
                .semantic_identity(domain)
                .map(|identity| identity.space()),
            Some(ResolutionSemanticIdentitySpace::Shared)
        );
        assert!(
            identities.lookup_recipe(domain).is_none(),
            "package domains are not lookup spellings"
        );
    }
    let mut emitted_shared = HashSet::default();
    for semantic in emitted {
        let identity = identities
            .semantic_identity(semantic)
            .unwrap_or_else(|| panic!("emitted semantic lacks an identity: {semantic}"));
        if identity.space() == ResolutionSemanticIdentitySpace::Shared
            && !package_domains.contains(&semantic)
        {
            assert!(
                identities.lookup_recipe(semantic).is_some(),
                "emitted Shared semantic lacks a lookup recipe: {semantic}"
            );
            emitted_shared.insert(semantic);
        }
    }
    let registered = identities
        .lookup_recipes()
        .iter()
        .map(|(semantic, _)| *semantic)
        .collect::<HashSet<_>>();
    assert_eq!(
        registered, emitted_shared,
        "lookup recipe catalog must exactly cover every emitted Shared lookup position"
    );
}

fn assert_precedence_namespaces_reach_emitted_artifact(
    lexical: &LoweredResolutionFragment,
    identities: &ResolutionIdentityCatalog,
) {
    let emitted = lexical
        .paths()
        .iter()
        .flat_map(|(_, path)| path.precedence().iter().copied())
        .collect::<HashSet<_>>();
    let registered = identities
        .precedence_namespaces()
        .keys()
        .chain(identities.go_spelling_choices().keys())
        .copied()
        .collect::<HashSet<_>>();
    assert_eq!(
        registered, emitted,
        "precedence namespace catalog must exactly cover every emitted precedence step"
    );
}

/// Lower one blob's facts for preparation.
///
/// What this returns is walked by `resolution_prepare` and then dropped: its
/// rows carry each shared name's interning digest and the single writer turns
/// that into `resolution_identities.id`. So the runtime ids of its shared
/// names never leave it and are numbered per preparation, in the range that
/// says "no store row names this".
pub(crate) fn lower_resolution_facts_with_identity_catalog(
    fragment: BindingFragmentId,
    language: brokk_bifrost_core::analyzer::Language,
    facts: &brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts,
) -> LoweredResolutionFactsWithIdentityCatalog {
    lower_resolution_facts_for_selection(
        fragment,
        &local_identity::PerRequestSharedNames::new(),
        language,
        facts,
    )
}

/// Lower one blob's facts for the engine.
///
/// The catalog this returns is what a request meets, so its shared names carry
/// the ids the store interned them at and compare with the ids the rows hold.
pub(crate) fn lower_resolution_facts_for_selection(
    fragment: BindingFragmentId,
    names: &dyn local_identity::SharedNameInterner,
    language: brokk_bifrost_core::analyzer::Language,
    facts: &brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts,
) -> LoweredResolutionFactsWithIdentityCatalog {
    let mut identities = ResolutionIdentityCatalogBuilder::new(fragment, names);
    let lexical = fact_lowering::lower_file_resolution_facts_with_identities(
        &mut identities,
        language,
        facts,
    );
    let typed = typed_fact_lowering::lower_typed_resolution_facts_with_identities(
        &mut identities,
        language,
        facts,
    );
    let common =
        common_fact_lowering::lower_common_resolution_facts(&mut identities, language, facts);
    finish_lowered_resolution_facts(lexical, typed, common, identities)
}

#[cfg(test)]
pub(crate) fn lower_resolution_paths_with_identity_catalog_for_test(
    mut identities: ResolutionIdentityCatalogBuilder,
    language: brokk_bifrost_core::analyzer::Language,
    nodes: Vec<(BindingNodeId, BindingNodeKind)>,
    paths: Vec<(PartialPathId, PartialPath)>,
) -> LoweredResolutionFactsWithIdentityCatalog {
    let fragment = identities.fragment();
    let lexical = LoweredResolutionFragment::new_for_test(fragment, language, nodes, paths);
    let facts = brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts::default();
    let typed = typed_fact_lowering::lower_typed_resolution_facts_with_identities(
        &mut identities,
        language,
        &facts,
    );
    let common =
        common_fact_lowering::lower_common_resolution_facts(&mut identities, language, &facts);
    finish_lowered_resolution_facts(lexical, typed, common, identities)
}

fn finish_lowered_resolution_facts(
    lexical: fact_lowering::LoweredResolutionFragment,
    typed: typed_fact_lowering::LoweredTypedFragment,
    common: common_fact_lowering::LoweredCommonFacts,
    identities: local_identity::ResolutionIdentityCatalogBuilder,
) -> LoweredResolutionFactsWithIdentityCatalog {
    let identities = identities.finish();
    assert_lookup_recipes_reach_emitted_artifact(&lexical, &typed, &common, &identities);
    assert_precedence_namespaces_reach_emitted_artifact(&lexical, &identities);
    LoweredResolutionFactsWithIdentityCatalog {
        lexical,
        typed,
        common,
        identities: Box::new(identities),
    }
    .rekey_dense()
}

/// Recompute one synthetic site-local typed frontier for private persistence
/// contract tests. Production callers consume the normalized lowered row
/// instead of reconstructing its identity.
#[cfg(any(test, feature = "test-support"))]
pub fn site_type_frontier_semantic_for_test(
    fragment: BindingFragmentId,
    site: brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId,
) -> SemanticId {
    fact_lowering::fixture_names::site_type_frontier_semantic(fragment, site)
}

#[cfg(test)]
pub(crate) use fact_resolution::SelectedContextTestOracle;
