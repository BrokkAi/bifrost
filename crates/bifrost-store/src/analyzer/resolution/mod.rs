//! Compositional name and member resolution over immutable file-local facts.
//!
//! This module owns the operation-local algebra and stitcher. Persistence and
//! language lowering are deliberately separate: both the preload test source
//! and the eventual SQL source present the same normalized fragment contract.

#[doc(hidden)]
pub mod batch;
mod canonical_identity;
#[doc(hidden)]
pub mod common_fact_lowering;
#[doc(hidden)]
pub mod completion_reasons;
#[doc(hidden)]
pub mod demand_overlay;
#[doc(hidden)]
pub mod engine;
#[doc(hidden)]
pub mod fact_lowering;

#[doc(hidden)]
pub mod fact_resolution;
#[doc(hidden)]
pub mod fact_source;
#[doc(hidden)]
pub mod local_identity;

#[doc(hidden)]
pub mod local_writes;
#[doc(hidden)]
pub mod model;
#[doc(hidden)]
pub mod mounted;
#[doc(hidden)]
pub mod precedence;
#[doc(hidden)]
pub mod remount;
mod saturation;
pub mod seam_profile;
pub mod seed_key_profile;
#[doc(hidden)]
pub mod selected_context;
#[cfg(any(test, feature = "test-support"))]
pub(crate) mod temporal_binding;
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support;
#[doc(hidden)]
pub mod typed_fact_lowering;
#[doc(hidden)]
pub mod universe;
#[doc(hidden)]
pub mod worker_transport;
pub use universe::UniverseEntry;

pub(crate) use universe::has_table as universe_has_table;
pub(crate) use universe::is_entry_digest as universe_is_entry_digest;
#[doc(hidden)]
pub use universe::lookup as universe_lookup;
#[doc(hidden)]
pub use universe::projects_intrinsic_definitions;

use crate::hash::HashMap;
use crate::hash::HashSet;

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

#[doc(hidden)]
pub use engine::cancelled_completion;

pub(crate) use fact_resolution::{
    QualifiedMemberId, QualifiedMemberInput, QualifiedMemberProvider, TypedConstructionInput,
    completion_without_unsupported_semantic,
};

pub(crate) use fact_source::language_identity_domain;
pub(crate) use fact_source::{QualifiedMemberRegistration, ResolutionIdentityDomain};

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

#[doc(hidden)]
pub fn callable_receiver_is_incomplete(
    origin: Option<
        brokk_bifrost_core::analyzer::resolution_facts::ResolutionCallableReceiverOrigin,
    >,
    completion: &ResolutionCompletion,
) -> bool {
    origin.is_some() && completion != &ResolutionCompletion::Complete
}

/// Whether a callable reference's forward confirmation failed to decide what
/// the call names, rather than deciding against a reverse target.
///
/// An empty forward target set disproves a name-nominated reverse candidate
/// only when the receiver was decided. A receiver that is an independent
/// declared bound, or one the route could not type (a bare generic parameter,
/// an inference failure), is more uncertain than a receiver whose named type
/// simply lacks the member. Its structurally matching site must stay unproven
/// instead of being dropped as a complete negative; dropping it published a
/// false "dead" for the target.
///
/// The receiver origin keeps the incomplete arm narrow. Rust crate-root rows
/// nominate every structured component of a qualified route, and forward
/// confirmation rejects the prefix components with an unowned gap. Those
/// components carry no callable receiver origin, so they stay disproved; only
/// a site whose source syntax supplied a receiver that the route could not
/// resolve is retained.
#[doc(hidden)]
pub fn undecided_callable_receiver(answer: &FactResolutionAnswer) -> bool {
    answer.binding().targets().is_empty()
        && (answer.type_bound_receiver()
            || callable_receiver_is_incomplete(
                answer.callable_receiver_origin(),
                answer.binding().completion(),
            ))
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

#[doc(hidden)]
pub fn charge_summary_step(
    session: Option<&brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession>,
) -> bool {
    session.is_none_or(
        brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession::summary_step,
    )
}

pub(super) fn charge_round_step(
    session: Option<&brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession>,
) -> bool {
    session.is_none_or(
        brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession::round_step,
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

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn positioned_identifier_for_test(
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
pub(crate) use fact_lowering::jvm_terminal_type_gap_origin_is_safe;
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

/// Identify a fixed language-universe rule from its selected scalar identity.
/// No source spelling or parser-backed declaration is inferred.
pub(crate) fn universe_entry_for_identity(
    source: &impl BatchResolutionFragmentSource,
    identity: SemanticId,
    cancellation: &crate::CancellationToken,
) -> crate::analyzer::store::Result<Option<universe::UniverseEntry>> {
    let Some(digest) = source.shared_name_digest_for_identity(identity, cancellation)? else {
        return Ok(None);
    };
    Ok(universe::entry_for_digest(digest))
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
        BindingProjectionKind::NonInvokingMemberReference => 8,
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
        DeclarationTypeRole::ObservedValue => 6,
    }
}

pub use batch::BatchCandidateCompletionOutcome;
pub use batch::BatchCandidateMatch;
pub use batch::BatchCandidateOutcome;
pub use batch::BatchCandidateRequest;
pub use batch::BatchDefinitionNode;
pub use batch::BatchEndpointClassification;
pub use batch::BatchReferenceSeed;
pub use batch::BatchResolutionEngine;
pub use batch::BatchResolutionFragmentSource;
pub use batch::BatchedReferenceAnswer;
pub use batch::CandidatePathIdentity;
pub use batch::ClassificationMemberOwnerReader;
pub use batch::FactReferenceSiteMetadata;
pub use batch::MAX_REFERENCE_SEEDS_PER_BATCH;
pub use batch::ReferenceBatchAnswer;
pub use batch::ReferenceLocalPathEvidence;
pub use batch::ReferenceSeed;
pub use batch::ReferenceSeedBatch;
pub use batch::ReferenceSeedReadOutcome;
pub use batch::ReferenceSeedReadTerminal;
pub use batch::ResolutionBatchMetrics;
pub use batch::ResolutionBatchSummary;
pub use batch::ReverseCandidateGapExclusionPlan;
pub use batch::ReverseCandidateGapIdentity;
pub use batch::ReverseReferenceSeedRequest;
pub use batch::SeedReadAuthority;
pub use batch::SeededPartialPath;
pub use batch::SeededPathKey;
pub use batch::SeededReferenceRequest;

pub(crate) use batch::ForwardCandidateArtifactCache;
pub(crate) use batch::MAX_REVERSE_TARGETS_PER_BATCH;
pub(crate) use batch::MAX_SOURCE_ROWS_PER_BATCH;
pub(crate) use batch::ReverseCandidateGapCoverage;
pub(crate) use batch::ReverseCandidateGapCoverageBuilder;
pub(crate) use batch::ReverseCandidateGapCoverageView;
pub(crate) use batch::ReverseCandidateGapLocation;
pub(crate) use batch::ReverseCandidateGapRow;
pub(crate) use batch::SelectedContextPathFragmentSource;

pub use canonical_identity::ResolutionIdentityDigestKey;

pub(crate) use canonical_identity::CanonicalIdentityDescriptor;
pub(crate) use canonical_identity::CanonicalIdentityHasher;
pub(crate) use canonical_identity::CanonicalIdentityNumbers;
pub(crate) use canonical_identity::CanonicalIdentityPart;
pub(crate) use canonical_identity::mounted_identity_digest;
pub(crate) use canonical_identity::selected_identity_content_digest;

pub use common_fact_lowering::LoweredDeferredMemberOwner;

pub(crate) use common_fact_lowering::LoweredReferenceLookupIdentity;
pub(crate) use common_fact_lowering::LoweredRootImportProvenance;

pub use completion_reasons::CompletionReasons;

pub(crate) use demand_overlay::DemandSelectedOverlayBlueprint;

pub use engine::PreloadedFragment;
pub use engine::PreloadedFragmentSource;
pub use engine::ReferenceSearchAnswer;
pub use engine::ResolutionEngine;
pub use engine::ResolutionFragmentSource;
pub use engine::ResolutionQuery;

#[cfg(any(test, feature = "test-support"))]
pub(crate) use fact_lowering::fixture_names::FixtureRootImportAnchors;
#[cfg(any(test, feature = "test-support"))]
pub(crate) use fact_lowering::fixture_names::record as record_fixture_identity_catalog;
#[cfg(any(test, feature = "test-support"))]
pub(crate) use fact_lowering::fixture_names::record_selected as record_fixture_selected_identity_catalog;

pub(crate) use fact_lowering::gap_reason_semantic_identity;

pub(crate) use fact_lowering::package::LoweredGoPackageImport;
pub(crate) use fact_lowering::package::LoweredPackageMember;
pub(crate) use fact_lowering::package::LoweredPackageReference;
pub(crate) use fact_lowering::package::package_domain_semantic;

pub use fact_lowering::LoweredCandidateDirection;
pub use fact_lowering::LoweredCoverageGap;
pub use fact_lowering::LoweredResolutionFragment;
pub use fact_lowering::LoweredSemanticRole;
pub use fact_lowering::LoweredSemanticSite;
pub use fact_lowering::LoweringCoverageFrontier;
pub use fact_lowering::LoweringGapOrigin;

#[doc(hidden)]
pub use fact_lowering::alias_lookup_surface_node_identities;
pub(crate) use fact_lowering::definition_node;
pub(crate) use fact_lowering::definition_node_identity;
pub(crate) use fact_lowering::definition_semantic;
pub(crate) use fact_lowering::gap_reason_semantic;
pub(crate) use fact_lowering::hierarchy_terminal_node_identity;
pub(crate) use fact_lowering::lookup_semantic;
pub(crate) use fact_lowering::mounted_site_node;
pub(crate) use fact_lowering::mounted_site_semantic;
pub(crate) use fact_lowering::placement_gap_path_id;
pub(crate) use fact_lowering::reference_node_identity;
pub(crate) use fact_lowering::reference_semantic;
pub(crate) use fact_lowering::root_export_path_id;
pub(crate) use fact_lowering::scope_head_node;
pub(crate) use fact_lowering::scope_head_node_identity;
pub(crate) use fact_lowering::structured_import_gap_path_id;

#[cfg(any(test, feature = "test-support"))]
pub(crate) use fact_lowering::catalog_node;
#[cfg(any(test, feature = "test-support"))]
pub(crate) use fact_lowering::catalog_semantic;
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub use fact_lowering::lower_for_test;
#[cfg(any(test, feature = "test-support"))]
pub(crate) use fact_lowering::lower_lexical_for_test;

pub(crate) use fact_lowering::root_export_token;
pub(crate) use fact_lowering::root_import_anchor_for_identity;
pub(crate) use fact_lowering::root_import_anchor_semantic_identity;
pub(crate) use fact_lowering::root_import_token;

#[cfg(any(test, feature = "test-support"))]
pub use fact_resolution::PreloadedFactResolutionService;

#[doc(hidden)]
pub use fact_resolution::call_applicability::ArgumentFormalBinding;
#[doc(hidden)]
pub use fact_resolution::call_applicability::CallApplicabilityAdapter;
#[doc(hidden)]
pub use fact_resolution::call_applicability::CandidateAssessment;
#[doc(hidden)]
pub use fact_resolution::call_applicability::ConversionEvidence;
#[doc(hidden)]
pub use fact_resolution::call_applicability::ConversionKind;
#[doc(hidden)]
pub use fact_resolution::call_applicability::ImplicitReceiverLookup;
#[doc(hidden)]
pub use fact_resolution::call_applicability::ImplicitReceiverScopeKind;
#[doc(hidden)]
pub use fact_resolution::call_applicability::IntrinsicCallType;
#[doc(hidden)]
pub use fact_resolution::call_applicability::MappingAssessment;
#[doc(hidden)]
pub use fact_resolution::call_applicability::PartialOrder;
#[doc(hidden)]
pub use fact_resolution::call_applicability::TypeInCallPosition;
#[doc(hidden)]
pub use fact_resolution::call_applicability::map_call_shape;
#[doc(hidden)]
pub use fact_resolution::call_applicability::map_scala_call_shape;
#[doc(hidden)]
pub use fact_resolution::call_applicability::unresolved_argument_conversion_completion;

#[doc(hidden)]
pub use fact_resolution::AnswerMap;
pub(crate) use fact_resolution::CALLER_ENVIRONMENT;
pub(crate) use fact_resolution::CallCandidateApplicability;
#[doc(hidden)]
pub use fact_resolution::CallTypeSubstitution;
pub(crate) use fact_resolution::DemandAcyclicOutcome;
pub(crate) use fact_resolution::DemandClosureDischarges;
pub(crate) use fact_resolution::DemandMemberSelection;
pub(crate) use fact_resolution::DemandMemberSelectionOutcome;
pub(crate) use fact_resolution::DemandMemberSelectionRequest;
pub(crate) use fact_resolution::DemandReferenceKey;
pub(crate) use fact_resolution::DemandRelationKey;
pub(crate) use fact_resolution::DemandRootDiscovery;
pub(crate) use fact_resolution::DemandRootPlan;
pub(crate) use fact_resolution::DemandRootProvider;
pub(crate) use fact_resolution::DemandRootUnavailableReason;
pub(crate) use fact_resolution::EnvironmentId;
pub(crate) use fact_resolution::FactDemandResolution;
#[doc(hidden)]
pub use fact_resolution::FactEvaluation;
#[doc(hidden)]
pub use fact_resolution::InternedFactRow;
pub(crate) use fact_resolution::SelectedDemandState;
#[doc(hidden)]
pub use fact_resolution::StateMap;

pub use fact_resolution::FactBatchedReferenceAnswer;
pub use fact_resolution::FactCallableCandidateApplicability;
pub use fact_resolution::FactCallableReceiverChannels;
pub use fact_resolution::FactCallableReceiverDisposition;
pub use fact_resolution::FactCallableReceiverTargetDisposition;
pub use fact_resolution::FactReadSession;
pub use fact_resolution::FactReferenceBatchAnswer;
pub use fact_resolution::FactReferenceReceiverGap;
pub use fact_resolution::FactResolutionAnswer;
pub use fact_resolution::FactResolutionBatchSummary;
pub use fact_resolution::FactReverseReferenceBinding;
pub use fact_resolution::FactReverseResolutionMetrics;
pub use fact_resolution::FactTargetReferenceAnswer;
pub use fact_resolution::FactTargetReferenceBatchAnswer;
pub use fact_resolution::SelectedFactResolutionEngine;
pub use fact_resolution::SelectedFactResolutionSnapshot;

#[doc(hidden)]
pub use fact_resolution::FactIntrinsicTypeDescriptor;
#[doc(hidden)]
pub use fact_resolution::FactMemberRouteKind;
#[doc(hidden)]
pub use fact_resolution::FactProjectedTypeNode;
#[doc(hidden)]
pub use fact_resolution::FactProjectedTypeNodeForm;
#[doc(hidden)]
pub use fact_resolution::FactProjectedTypeShape;
pub(crate) use fact_resolution::FactResolutionOperation;
pub(crate) use fact_resolution::ForwardOperationArtifactContext;
pub(crate) use fact_resolution::GoReceiverSlotTypeOverlay;
pub(crate) use fact_resolution::PolledCompletionAccumulator;
pub(crate) use fact_resolution::SelectedFactOperationBlueprint;
#[doc(hidden)]
pub use fact_resolution::SelectedFactOperationBlueprintConstruction;

#[cfg(any(test, feature = "test-support"))]
pub use fact_resolution::reset_reverse_fact_evaluation_count_for_test;
#[cfg(any(test, feature = "test-support"))]
pub use fact_resolution::reverse_fact_evaluation_count_for_test;
pub(crate) use fact_resolution::{
    CloseContinuationId, CloseProgress, CloseResume, HierarchyCursorScope,
    HierarchyLinearizationPolicy, HierarchyOrderBudget, HierarchyOrderDecision,
    HierarchyOrderFrontier, HierarchyOrderHead, HierarchyOrderOutcome, HierarchyOrderOutcomeId,
    HierarchyOrderPolicyId, HierarchyOrderRequest, HierarchyOrderStatus, HierarchyOrderedOwner,
    HierarchyProvenanceView, HierarchyProviderAuthority, HierarchyProviderKey,
    HierarchyProviderObservation, HierarchyProviderOperand, HierarchyProviderVisit,
    HierarchySelectionProvenance, HierarchySequenceId, HierarchySequenceRole,
    HierarchyTailMembership, ProviderObservationStore, RootClosure,
};

#[cfg(test)]
pub(crate) use fact_resolution::reset_selected_fact_operation_construction_count_for_test;
#[cfg(test)]
pub(crate) use fact_resolution::selected_fact_operation_construction_count_for_test;

pub(crate) use fact_source::CompanionTypeRelation;
pub(crate) use fact_source::DeclarationAccessDecision;
pub(crate) use fact_source::DeclarationAccessRequest;
pub(crate) use fact_source::DeclarationAccessRow;
pub use fact_source::JvmAliasProperty;
pub(crate) use fact_source::JvmDeclarationAccessRules;
#[doc(hidden)]
pub use fact_source::JvmImplicitRootProvider;
pub(crate) use fact_source::ReasonOwnerRow;
pub(crate) use fact_source::RustDeclarationContextSource;
pub(crate) use fact_source::RustReferenceContextSource;
pub(crate) use fact_source::SelectedDeclarationAccessSource;
pub(crate) use fact_source::SubclassAccessContext;
pub(crate) use fact_source::language_callables_occupy_value_namespace;
pub(crate) use fact_source::language_has_jvm_semantics;
#[doc(hidden)]
pub use fact_source::language_implicit_root_member_names;
#[doc(hidden)]
pub use fact_source::language_implicit_root_providers;
pub(crate) use fact_source::language_implicit_root_providers_in_namespace;
pub(crate) use fact_source::language_import_owner_steps_bind_singletons;
pub(crate) use fact_source::language_jvm_declaration_access_rules;
pub(crate) use fact_source::language_jvm_import_binary_owner;
pub(crate) use fact_source::language_jvm_package_requires_directory_agreement;
pub(crate) use fact_source::language_type_qualifiers_search_companion_members;
pub(crate) use fact_source::visit_mapped_typed_pages;
pub use fact_source::{
    ClassCreationKind, ConditionalTypeSeed, ImplicitBaseAuthority, ImplicitBaseInputs,
    ImplicitRootObject,
};

pub use fact_source::DeferredMemberOwnerLookupName;
pub use fact_source::DeferredMemberOwnerProof;
pub use fact_source::ExternalMemberCoordinate;
pub use fact_source::ExternalMemberIdentity;
pub use fact_source::ExternalOwnerIdentity;
pub use fact_source::FactPageVisitor;
pub use fact_source::FactReadOutcome;
pub use fact_source::FactReadTerminal;
pub use fact_source::FactRequest;
pub use fact_source::FactResolutionSource;
pub use fact_source::GoInterfaceMethod;
pub use fact_source::GoMemberDeclaration;
pub use fact_source::GoMemberDeclarationKind;
pub use fact_source::GoStructField;
pub use fact_source::JavaAccessEndpoint;
pub use fact_source::JavaInheritanceDeclaration;
pub use fact_source::JavaInheritanceDeclarationKind;
pub use fact_source::JvmAccessEndpoint;
pub use fact_source::LoweredIntrinsicTypeDescriptor;
pub use fact_source::LoweredRustDeclarationAuthority;
pub use fact_source::LoweredRustReferenceContext;
pub use fact_source::MAX_FACT_REQUESTS_PER_BATCH;
pub use fact_source::MAX_FACT_ROWS_PER_PAGE;
pub use fact_source::MAX_TYPED_FACT_REQUESTS_PER_BATCH;
pub use fact_source::MAX_TYPED_FACT_ROWS_PER_PAGE;
pub use fact_source::NamedArgumentLabel;
pub use fact_source::NamedArgumentLabelRead;
pub use fact_source::QualifiedRouteSlotLookup;
pub use fact_source::RustImplementedTraits;
pub use fact_source::SelectedFactRow;
pub use fact_source::SelectedGapReasonProvenance;
pub use fact_source::SelectedInvocationRole;
pub use fact_source::SelectedQualifiedRoute;
pub use fact_source::SelectedTypeFrontierCompletion;
pub use fact_source::SelectedTypedFactSource;
pub use fact_source::SelectedTypedRow;
pub use fact_source::SelectedTypedRowIdentity;
pub use fact_source::SelectedTypedRowKey;
pub use fact_source::TypedFactPageVisitor;
pub use fact_source::TypedFactReadOutcome;
pub use fact_source::TypedFactReadTerminal;
pub use fact_source::TypedFactRequest;
pub use fact_source::{FactModelMember, FactModelMemberSelection};

pub(crate) use local_identity::SUPPLEMENTAL_LOCAL_KEY_BASE;

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub use local_identity::test_shared_names;

pub(crate) use local_identity::MountRebaser;
pub(crate) use local_identity::MountRebaserRegistration;
pub(crate) use local_identity::ResolutionIdentityCatalog;
pub(crate) use local_identity::ResolutionIdentityCatalogBuilder;
pub(crate) use local_identity::ResolutionLocalKey;
#[doc(hidden)]
pub use local_identity::ResolutionLookupSemanticRecipe;
pub(crate) use local_identity::ResolutionNodeIdentity;
pub(crate) use local_identity::ResolutionPathIdentity;
pub(crate) use local_identity::ResolutionSemanticIdentity;
pub(crate) use local_identity::ResolutionSemanticIdentitySpace;
pub(crate) use local_identity::ResolutionStackVariableIdentity;
pub(crate) use local_identity::SelectedLocalIdentityProvenance;
pub(crate) use local_identity::SelectedNodeMount;
pub(crate) use local_identity::SelectedNodeProvenance;
pub(crate) use local_identity::SelectedResolutionFragmentDigest;
pub(crate) use local_identity::SelectedResolutionMount;
#[doc(hidden)]
pub use local_identity::SelectedResolutionMountOrdinal;
#[doc(hidden)]
pub use local_identity::SelectedSemanticLocator;
pub(crate) use local_identity::SelectedSemanticMount;
#[doc(hidden)]
pub use local_identity::SelectedSemanticProvenance;
pub(crate) use local_identity::SelectedStageIdentityProvenance;
pub(crate) use local_identity::selected_resolution_fragment_id;

pub use local_identity::PerRequestSharedNames;
pub use local_identity::SharedNameInterner;

pub(crate) use local_identity::ResolutionIdentityTranslation;
pub(crate) use local_identity::ResolutionRegisteredIdentities;

pub use model::BindingCandidateAdmission;
pub use model::BindingFragmentId;
pub use model::BindingNodeId;
pub use model::BindingNodeKind;
pub use model::CompletionReason;
pub use model::DerivationKey;
pub use model::EndpointSignature;
pub use model::GoDefinitionNamespaces;
pub use model::PartialPath;
pub use model::PartialPathId;
pub use model::PartialScopedSymbol;
pub use model::PrecedenceStep;
pub use model::ResolutionAnswer;
pub use model::ResolutionCompletion;
pub use model::ResolutionIncompleteReason;
pub use model::ResolutionSlotValue;
pub use model::ResolutionTypeRef;
pub use model::ResolutionValueObligation;
pub use model::ResolutionWitness;
pub use model::ScopeStackPattern;
pub use model::SemanticId;
pub use model::SharedNameId;
pub use model::StackPattern;
pub use model::StackVariable;
pub use model::StackVariableId;
pub use model::SymbolStackPattern;
pub use model::TypeTransferRule;
pub use model::TypeTransferValueTransform;
pub use model::TypedFrontierState;
pub use model::WitnessStep;

pub(crate) use model::BindingOrigin;
pub(crate) use model::GoBindingClassification;
pub(crate) use model::UnindexedExternalFrontier;
pub(crate) use model::binding_origin_rank;
pub(crate) use model::classify_binding_namespace;
pub(crate) use model::classify_go_binding;

pub(crate) use model::ResolutionCompletionAccumulator;
pub(crate) use model::combine_completion_with_poll;

#[cfg(any(test, feature = "test-support"))]
pub(crate) use mounted::OperationBlind;

pub(crate) use mounted::Mounted;
pub(crate) use mounted::SpliceMount;
pub(crate) use mounted::into_interior;
pub(crate) use mounted::out_of_interior;

pub(crate) use remount::retarget_lexical;

#[doc(hidden)]
pub use seam_profile::SeamProfiled;

pub(crate) use selected_context::CatalogRootImportAnchors;
pub(crate) use selected_context::SelectedContextIdentities;
pub(crate) use selected_context::SelectedContextOverlay;
pub(crate) use selected_context::SelectedContextOverlayCompilation;
pub(crate) use selected_context::SelectedContextPathPublication;
pub(crate) use selected_context::SelectedContextPathPublicationOutcome;
pub(crate) use selected_context::SelectedContextPathSource;
pub(crate) use selected_context::SelectedContextPathToken;
pub(crate) use selected_context::SelectedJvmBridgeEvidence;
pub(crate) use selected_context::SelectedJvmBridgeProvenance;
pub(crate) use selected_context::SelectedJvmBridgeVisibility;
pub(crate) use selected_context::SelectedResolutionContextInputs;
#[doc(hidden)]
pub use selected_context::SelectedResolutionContextSet;
#[doc(hidden)]
pub use selected_context::SelectedResolutionContextValidationOutcome;
pub(crate) use selected_context::SelectedResolutionMountContext;
pub(crate) use selected_context::SelectedRootBridgeDescriptor;
pub(crate) use selected_context::SelectedRootBridgeProjection;
pub(crate) use selected_context::SelectedRootImportAnchors;
pub(crate) use selected_context::SelectedRootPathHalf;
pub(crate) use selected_context::classify_selected_root_path_half;
pub(crate) use selected_context::compile_selected_context_overlay;
pub(crate) use selected_context::compile_selected_context_overlay_in_session;
pub(crate) use selected_context::compile_selected_root_bridge;
pub(crate) use selected_context::selected_root_source_anchor;
pub(crate) use selected_context::visit_selected_root_export_half_pages;
pub(crate) use selected_context::visit_selected_root_import_half_pages;
pub(crate) use selected_context::visit_selected_root_import_half_pages_with_targets;

pub(crate) use selected_context::SelectedGoImportBindingDescriptor;
pub(crate) use selected_context::SelectedPackageBridgeDescriptor;

pub use typed_fact_lowering::ExternalMemberCoverage;
pub use typed_fact_lowering::LoweredBindingProjection;
pub use typed_fact_lowering::LoweredCallApplicabilityObligation;
pub use typed_fact_lowering::LoweredCallArgumentProperty;
pub use typed_fact_lowering::LoweredCallableParameterApplicability;
pub use typed_fact_lowering::LoweredCallableParameterProperty;
pub use typed_fact_lowering::LoweredCallableResultBinding;
pub use typed_fact_lowering::LoweredCallableResultTypeProperty;
pub use typed_fact_lowering::LoweredCallableReturn;
pub use typed_fact_lowering::LoweredCallableSignatureProperty;
pub use typed_fact_lowering::LoweredConstructionRequirementProperty;
pub use typed_fact_lowering::LoweredDeclarationTypeProperty;
pub use typed_fact_lowering::LoweredDeclarationValue;
pub use typed_fact_lowering::LoweredDeclarationVisibilityProperty;
pub use typed_fact_lowering::LoweredDeclaredTypeArgument;
pub use typed_fact_lowering::LoweredDefinitionPropertyGap;
pub use typed_fact_lowering::LoweredGenericFormal;
pub use typed_fact_lowering::LoweredGenericFormalDefault;
pub use typed_fact_lowering::LoweredGenericTypeAliasParameter;
pub use typed_fact_lowering::LoweredIntrinsicSeed;
pub use typed_fact_lowering::LoweredMemberOwnerProperty;
pub use typed_fact_lowering::LoweredMemberScopeProperty;
pub use typed_fact_lowering::LoweredQualifiedSeededRoute;
pub use typed_fact_lowering::LoweredSourceSupertypeProperty;
pub use typed_fact_lowering::LoweredSupertypeProperty;
pub use typed_fact_lowering::LoweredSupertypeTarget;
pub use typed_fact_lowering::LoweredTypeArgument;
pub use typed_fact_lowering::LoweredTypeComponent;
pub use typed_fact_lowering::LoweredTypeProduction;
pub use typed_fact_lowering::LoweredTypeTransfer;
pub use typed_fact_lowering::LoweredTypedFragment;
pub use typed_fact_lowering::LoweredTypedFrontier;
pub use typed_fact_lowering::LoweredUnderlyingType;

pub(crate) use typed_fact_lowering::call_semantic_identity;
pub(crate) use typed_fact_lowering::validate_type_identity_transfer;

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn rich_java_resolution_facts_for_test()
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
#[doc(hidden)]
pub struct LoweredResolutionFactsWithIdentityCatalog {
    #[doc(hidden)]
    pub lexical: LoweredResolutionFragment,
    #[doc(hidden)]
    pub typed: LoweredTypedFragment,
    #[doc(hidden)]
    pub common: common_fact_lowering::LoweredCommonFacts,
    #[doc(hidden)]
    pub identities: Box<ResolutionIdentityCatalog>,
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
        ResolutionBinderKind::Alias { .. } | ResolutionBinderKind::Import => {
            namespace != ResolutionNamespace::TypeOrValue
        }
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
        ResolutionNamespace::Value => kind.is_value_declaration(),
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

#[cfg(any(test, feature = "test-support"))]
impl LoweredResolutionFactsWithIdentityCatalog {
    #[doc(hidden)]
    pub fn clone_for_stage_admission_test(&self) -> Self {
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
    #[doc(hidden)]
    pub fn with_open_variable_for_publication_test(mut self) -> Self {
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

    #[doc(hidden)]
    pub fn with_changed_reference_end_for_publication_test(&self) -> Self {
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
            metadata.receiver_origin(),
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

    #[doc(hidden)]
    pub fn with_generic_node_payloads_for_publication_test(mut self) -> Self {
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

    #[doc(hidden)]
    pub const fn lexical(&self) -> &LoweredResolutionFragment {
        &self.lexical
    }

    #[doc(hidden)]
    pub const fn typed(&self) -> &LoweredTypedFragment {
        &self.typed
    }

    #[doc(hidden)]
    pub const fn common(&self) -> &common_fact_lowering::LoweredCommonFacts {
        &self.common
    }

    #[doc(hidden)]
    pub const fn identities(&self) -> &ResolutionIdentityCatalog {
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
#[doc(hidden)]
pub fn lower_resolution_facts_with_identity_catalog(
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
#[doc(hidden)]
pub fn lower_resolution_facts_for_selection(
    fragment: BindingFragmentId,
    names: &dyn local_identity::SharedNameInterner,
    language: brokk_bifrost_core::analyzer::Language,
    facts: &brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts,
) -> LoweredResolutionFactsWithIdentityCatalog {
    common_fact_lowering::validate_binding_facts(facts);
    let mut identities = ResolutionIdentityCatalogBuilder::new(fragment, names);
    let mut lexical = fact_lowering::lower_file_resolution_facts_with_identities(
        &mut identities,
        language,
        facts,
    );
    let normalized = local_writes::attach_local_writes(facts, &lexical, &mut identities);
    let facts = normalized.as_ref();
    if matches!(normalized, std::borrow::Cow::Owned(_)) {
        // New join slots and failed attachment gaps must be published by both
        // lexical coverage and typed lowering, under the same identity catalog.
        lexical = fact_lowering::lower_file_resolution_facts_with_identities(
            &mut identities,
            language,
            facts,
        );
    }
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

pub(crate) use fact_resolution::GoInterfaceSatisfaction;
pub(crate) use fact_resolution::GoMethodSatisfaction;

#[doc(hidden)]
pub mod diagnostic_kinds;
#[doc(hidden)]
pub mod file_paths;
#[doc(hidden)]
pub mod lexical_definition;
#[doc(hidden)]
pub mod reference_vocabulary;
#[doc(hidden)]
pub mod registry_vocabulary;
#[doc(hidden)]
pub mod trace_vocabulary;

mod diagnostics;
pub use diagnostics::ResolutionDiagnostics;
pub use engine::resolution_diagnostics;

#[cfg(test)]
pub(crate) use fact_resolution::EXPLICIT_HIERARCHY_EDGES;
#[cfg(test)]
pub(crate) use fact_resolution::with_test_member_order;

pub(crate) use fact_resolution::{
    DEFAULT_HIERARCHY_POLICY, HierarchyEdgeProvider, HierarchyLookupShape, HierarchyPolicy,
    HierarchyPolicyId, HierarchyRequestIdentity, ImplicitBaseFact, ImplicitBaseRead,
};

pub use selected_context::ExternalOwnerLanguage;
