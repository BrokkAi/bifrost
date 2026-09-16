//! Storage-neutral, query-local execution of lowered resolution facts.
//!
//! This module joins selected lexical and typed rows to the batch stitching
//! engine. It never parses source or stores a resolved reference-to-definition
//! pair. A read session retains only fully exhausted demanded relations; every
//! binding/type fixed point and transfer classification is operation-local and
//! dropped with the answer.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, VecDeque};
use std::hash::Hash;
use std::marker::PhantomData;
use std::ops::Range;
#[cfg(test)]
use std::rc::Rc;

use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::resolution_facts::{
    BindingProjectionKind, DeclarationTypeRole, IntrinsicTypeKind,
    ResolutionCallableReceiverOrigin, ResolutionConstructionRequirementKind,
    ResolutionEngineRuleKind, ResolutionGapKind, ResolutionMemberAccess, ResolutionMemberKind,
    ResolutionMemberQualifierCompatibility, ResolutionNamespace, ResolutionSupertypeKind,
    ResolutionTypeTransferKind,
};
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;

use crate::CancellationToken;
use crate::analyzer::store::{Result as StoreResult, StoreError};
use crate::analyzer::structural::{CandidateOutcome, PrecedenceTier, RejectionReason};
use crate::hash::{HashMap, HashSet};

use super::batch::{
    BatchCandidateRequest, BatchResolutionEngine, BatchResolutionFragmentSource,
    CancellationEvidenceLedger, CandidatePathIdentity, FactReferenceSiteMetadata,
    MAX_SOURCE_ROWS_PER_BATCH, ReferenceSeed, ReferenceSeedBatch, ReferenceSeedReadTerminal,
    ResolutionBatchMetrics, SeededPartialPath, SeededReferenceRequest,
    read_forward_candidate_artifacts,
};
use super::completion_reasons::CompletionReasons;
use super::coverage::LoweringGapOrigin;
use super::engine::{
    CANCELLATION_QUANTUM, ResolutionQuery, apply_type_transfer_rules, endpoint_is_balanced,
};
use super::fact_source::{
    FactResolutionSource, MAX_TYPED_FACT_REQUESTS_PER_BATCH, QualifiedRouteSlotLookup,
    SelectedGapReasonProvenance, SelectedQualifiedRoute as SourceSelectedQualifiedRoute,
    SelectedTypeFrontierCompletion, SelectedTypedFactSource, SelectedTypedRow,
    TypedFactPageVisitor, TypedFactReadOutcome, TypedFactReadTerminal, TypedFactRequest,
};
use super::model::{
    AlphaRenamingId, BindingFragmentId, BindingNodeId, EndpointSignature, PartialPath,
    PartialPathId, PrecedenceStep, ResolutionAnswer, ResolutionCompletion,
    ResolutionIncompleteReason, ResolutionSlotValue, ResolutionTypeRef, ResolutionWitness,
    SemanticId, StackPattern, TypeTransferRule, TypeTransferValueTransform, TypedFrontierState,
    WitnessStep, clone_completion_with_poll as clone_resolution_completion_with_poll,
};
use super::typed_fact_lowering::{
    LoweredBindingProjection, LoweredCallApplicabilityObligation, LoweredCallableSignatureProperty,
    LoweredConstructionRequirementProperty, LoweredDeclarationTypeProperty,
    LoweredDeclarationVisibilityProperty, LoweredDefinitionPropertyGap, LoweredIntrinsicSeed,
    LoweredMemberOwnerProperty, LoweredMemberScopeProperty, LoweredSupertypeProperty,
    LoweredTypeTransfer,
};

/// One typed projection frontier together with the producer interpretation
/// that created it.
///
/// The slot and its values are not sufficient to identify the semantic
/// property being projected: callable results, constructor owners, declared
/// value types, and nominal type identities can share the same frontier role.
/// Keep the selected [`BindingProjectionKind`] beside the evaluated frontier
/// so consumers never have to infer it from names or slot roles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactProjectedFrontier {
    state: TypedFrontierState,
    kind: BindingProjectionKind,
}

impl FactProjectedFrontier {
    pub(crate) fn new(state: TypedFrontierState, kind: BindingProjectionKind) -> Self {
        Self { state, kind }
    }

    pub const fn state(&self) -> &TypedFrontierState {
        &self.state
    }

    pub const fn kind(&self) -> BindingProjectionKind {
        self.kind
    }

    pub const fn slot(&self) -> SemanticId {
        self.state.slot()
    }

    pub fn possible_values(&self) -> &[ResolutionSlotValue] {
        self.state.possible_values()
    }

    pub fn completion(&self) -> &ResolutionCompletion {
        self.state.completion()
    }

    fn with_completion(mut self, completion: ResolutionCompletion) -> Self {
        self.state = self.state.with_completion(completion);
        self
    }
}

/// Why one callable receiver cannot yet be assigned to an edge channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactReferenceReceiverGap {
    MissingOrigin,
    UnresolvedReceiver,
    AmbiguousReceiver,
}

/// Positive operation-local receiver channels retained for one callable target.
///
/// Open receiver evidence may add another channel, but it cannot retract a
/// compatible route that full evaluation already selected. This set therefore
/// stays separate from [`FactCallableReceiverDisposition::gap`], just as a
/// resolution answer retains best-effort targets separately from its
/// completion evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactCallableReceiverChannels {
    None,
    SelfReceiver,
    External,
    SelfAndExternal,
}

impl FactCallableReceiverChannels {
    pub const fn includes_self_receiver(self) -> bool {
        matches!(self, Self::SelfReceiver | Self::SelfAndExternal)
    }

    pub const fn includes_external(self) -> bool {
        matches!(self, Self::External | Self::SelfAndExternal)
    }

    const fn with_self_receiver(self) -> Self {
        match self {
            Self::None => Self::SelfReceiver,
            Self::External => Self::SelfAndExternal,
            Self::SelfReceiver | Self::SelfAndExternal => self,
        }
    }

    const fn with_external(self) -> Self {
        match self {
            Self::None => Self::External,
            Self::SelfReceiver => Self::SelfAndExternal,
            Self::External | Self::SelfAndExternal => self,
        }
    }
}

/// Receiver-channel evidence selected for one callable target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactCallableReceiverDisposition {
    channels: FactCallableReceiverChannels,
    gap: Option<FactReferenceReceiverGap>,
}

impl FactCallableReceiverDisposition {
    pub(crate) const fn from_parts(
        channels: FactCallableReceiverChannels,
        gap: Option<FactReferenceReceiverGap>,
    ) -> Self {
        assert!(
            !matches!(channels, FactCallableReceiverChannels::None) || gap.is_some(),
            "an empty receiver channel set requires explicit incomplete evidence"
        );
        assert!(
            !matches!(channels, FactCallableReceiverChannels::SelfAndExternal)
                || matches!(gap, Some(FactReferenceReceiverGap::AmbiguousReceiver)),
            "both positive receiver channels require ambiguity evidence"
        );
        assert!(
            !matches!(gap, Some(FactReferenceReceiverGap::AmbiguousReceiver))
                || matches!(channels, FactCallableReceiverChannels::SelfAndExternal),
            "receiver ambiguity requires both positive channels"
        );
        assert!(
            !matches!(gap, Some(FactReferenceReceiverGap::MissingOrigin))
                || matches!(channels, FactCallableReceiverChannels::None),
            "a missing receiver origin cannot publish a positive channel"
        );
        Self { channels, gap }
    }

    const fn empty() -> Self {
        Self {
            channels: FactCallableReceiverChannels::None,
            gap: None,
        }
    }

    const fn self_receiver() -> Self {
        Self::from_parts(FactCallableReceiverChannels::SelfReceiver, None)
    }

    const fn external() -> Self {
        Self::from_parts(FactCallableReceiverChannels::External, None)
    }

    const fn unresolved(gap: FactReferenceReceiverGap) -> Self {
        Self::from_parts(FactCallableReceiverChannels::None, Some(gap))
    }

    pub const fn channels(self) -> FactCallableReceiverChannels {
        self.channels
    }

    pub const fn gap(self) -> Option<FactReferenceReceiverGap> {
        self.gap
    }

    fn observe_self_receiver(&mut self) {
        self.channels = self.channels.with_self_receiver();
        self.refresh_ambiguity();
    }

    fn observe_external(&mut self) {
        self.channels = self.channels.with_external();
        self.refresh_ambiguity();
    }

    fn mark_unresolved(&mut self) {
        if self.channels == FactCallableReceiverChannels::SelfAndExternal {
            self.gap = Some(FactReferenceReceiverGap::AmbiguousReceiver);
        } else if self.gap.is_none() {
            self.gap = Some(FactReferenceReceiverGap::UnresolvedReceiver);
        }
    }

    fn refresh_ambiguity(&mut self) {
        if self.channels == FactCallableReceiverChannels::SelfAndExternal {
            self.gap = Some(FactReferenceReceiverGap::AmbiguousReceiver);
        }
    }
}

/// Receiver disposition for one canonical target of a callable answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactCallableReceiverTargetDisposition {
    target: SemanticId,
    disposition: FactCallableReceiverDisposition,
}

impl FactCallableReceiverTargetDisposition {
    pub(crate) const fn new(
        target: SemanticId,
        disposition: FactCallableReceiverDisposition,
    ) -> Self {
        Self {
            target,
            disposition,
        }
    }

    pub const fn target(self) -> SemanticId {
        self.target
    }

    pub const fn disposition(self) -> FactCallableReceiverDisposition {
        self.disposition
    }
}

/// Binding plus the typed projection states produced for one source reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactResolutionAnswer {
    site_metadata: Option<FactReferenceSiteMetadata>,
    callable_receiver_dispositions: Box<[FactCallableReceiverTargetDisposition]>,
    binding: ResolutionAnswer,
    projected_frontiers: Box<[FactProjectedFrontier]>,
    completion: ResolutionCompletion,
}

impl FactResolutionAnswer {
    pub const fn site_metadata(&self) -> Option<FactReferenceSiteMetadata> {
        self.site_metadata
    }

    /// The source declaration containing this reference occurrence.
    pub const fn reference_owner(&self) -> Option<Option<SemanticId>> {
        match self.site_metadata {
            Some(metadata) => metadata.reference_owner(),
            None => None,
        }
    }

    /// The source-syntax route that supplied this callable receiver.
    pub const fn callable_receiver_origin(&self) -> Option<ResolutionCallableReceiverOrigin> {
        match self.site_metadata {
            Some(metadata) => metadata.callable_receiver_origin(),
            None => None,
        }
    }

    /// Canonical per-target receiver dispositions for a callable answer.
    pub fn callable_receiver_dispositions(&self) -> &[FactCallableReceiverTargetDisposition] {
        &self.callable_receiver_dispositions
    }

    pub const fn binding(&self) -> &ResolutionAnswer {
        &self.binding
    }

    pub fn projected_frontiers(&self) -> &[FactProjectedFrontier] {
        &self.projected_frontiers
    }

    /// Completeness of binding and every requested projection.
    pub const fn completion(&self) -> &ResolutionCompletion {
        &self.completion
    }
}

#[derive(Debug, Default)]
struct ExactCompletionAccumulator {
    state: ExactCompletionState,
}

#[derive(Debug, Default)]
enum ExactCompletionState {
    #[default]
    Complete,
    Single(Vec<ResolutionIncompleteReason>),
    Union(BTreeSet<ResolutionIncompleteReason>),
}

#[derive(Debug, Default)]
struct TypedStateAccumulator {
    values: BTreeSet<ResolutionSlotValue>,
    completion: ExactCompletionAccumulator,
}

impl ExactCompletionAccumulator {
    fn include<P>(&mut self, completion: &ResolutionCompletion, cancelled: &mut P) -> Option<()>
    where
        P: FnMut() -> bool,
    {
        let ResolutionCompletion::Incomplete(incoming) = completion else {
            return Some(());
        };
        let state = std::mem::take(&mut self.state);
        self.state = match state {
            ExactCompletionState::Complete => {
                if cancelled() {
                    return None;
                }
                let mut reasons = Vec::with_capacity(incoming.len());
                for &reason in incoming.iter() {
                    if cancelled() {
                        return None;
                    }
                    reasons.push(reason);
                }
                ExactCompletionState::Single(reasons)
            }
            ExactCompletionState::Single(existing) => {
                assert!(
                    !existing.is_empty() || !incoming.is_empty(),
                    "incomplete resolution requires a reason"
                );
                let mut reasons = BTreeSet::new();
                for reason in existing {
                    if cancelled() {
                        return None;
                    }
                    reasons.insert(reason);
                }
                for &reason in incoming.iter() {
                    if cancelled() {
                        return None;
                    }
                    reasons.insert(reason);
                }
                ExactCompletionState::Union(reasons)
            }
            ExactCompletionState::Union(mut reasons) => {
                for &reason in incoming.iter() {
                    if cancelled() {
                        return None;
                    }
                    reasons.insert(reason);
                }
                ExactCompletionState::Union(reasons)
            }
        };
        Some(())
    }

    fn include_reason<P>(
        &mut self,
        reason: ResolutionIncompleteReason,
        cancelled: &mut P,
    ) -> Option<()>
    where
        P: FnMut() -> bool,
    {
        self.include(
            &ResolutionCompletion::Incomplete(vec![reason].into_boxed_slice().into()),
            cancelled,
        )
    }

    fn finish<P>(self, cancelled: &mut P) -> Option<ResolutionCompletion>
    where
        P: FnMut() -> bool,
    {
        match self.state {
            ExactCompletionState::Complete => Some(ResolutionCompletion::Complete),
            ExactCompletionState::Single(reasons) => Some(ResolutionCompletion::Incomplete(
                reasons.into_boxed_slice().into(),
            )),
            ExactCompletionState::Union(mut reasons) => {
                let mut canonical = Vec::with_capacity(reasons.len());
                while let Some(reason) = reasons.pop_first() {
                    if cancelled() {
                        return None;
                    }
                    canonical.push(reason);
                }
                assert!(
                    !canonical.is_empty(),
                    "combining incomplete completions requires at least one reason"
                );
                Some(ResolutionCompletion::Incomplete(
                    canonical.into_boxed_slice().into(),
                ))
            }
        }
    }
}

/// Operation-local cancellation evidence with an explicit shared-source
/// representation.
///
/// Raw evidence keeps the historical `BTreeSet` insertion and drain schedule.
/// Operation-local cancellation evidence, preserving the donor raw polling schedule.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct CancellationReasonCollection(BTreeSet<ResolutionIncompleteReason>);
impl CancellationReasonCollection {
    #[cfg(test)]
    fn contains(&self, reason: &ResolutionIncompleteReason) -> bool {
        self.0.contains(reason)
    }
    fn include_reason_with_poll(
        &mut self,
        reason: ResolutionIncompleteReason,
        cancellation: &CancellationToken,
        work: &mut usize,
        cancellation_observed: &mut bool,
    ) {
        *cancellation_observed |= poll_cancelled(cancellation, work);
        self.0.insert(reason);
        *cancellation_observed |= reason == ResolutionIncompleteReason::Cancelled;
        *cancellation_observed |= cancellation.is_cancelled();
    }
    fn include_reason_after_poll(
        &mut self,
        reason: ResolutionIncompleteReason,
        cancellation: &CancellationToken,
        _work: &mut usize,
        cancellation_observed: &mut bool,
    ) {
        self.0.insert(reason);
        *cancellation_observed |= reason == ResolutionIncompleteReason::Cancelled;
        *cancellation_observed |= cancellation.is_cancelled();
    }
    fn include_completion_with_poll(
        &mut self,
        completion: &ResolutionCompletion,
        cancellation: &CancellationToken,
        work: &mut usize,
        cancellation_observed: &mut bool,
    ) {
        let ResolutionCompletion::Incomplete(incoming) = completion else {
            *cancellation_observed |= cancellation.is_cancelled();
            return;
        };
        for &reason in incoming.iter() {
            *cancellation_observed |= poll_cancelled(cancellation, work);
            self.0.insert(reason);
        }
        *cancellation_observed |= self.0.contains(&ResolutionIncompleteReason::Cancelled);
        *cancellation_observed |= cancellation.is_cancelled();
    }
    fn merge_with_poll(
        &mut self,
        mut incoming: Self,
        cancellation: &CancellationToken,
        work: &mut usize,
        cancellation_observed: &mut bool,
    ) {
        while let Some(reason) = incoming.0.pop_first() {
            *cancellation_observed |= poll_cancelled(cancellation, work);
            self.0.insert(reason);
        }
        *cancellation_observed |= cancellation.is_cancelled();
    }
}
fn equal_completion_reasons_with_poll(
    left: &ResolutionCompletion,
    right: &ResolutionCompletion,
    cancellation: &CancellationToken,
    work: &mut usize,
    cancellation_observed: &mut bool,
) -> bool {
    match (left, right) {
        (ResolutionCompletion::Complete, ResolutionCompletion::Complete) => true,
        (ResolutionCompletion::Incomplete(left), ResolutionCompletion::Incomplete(right))
            if left.len() == right.len() =>
        {
            let mut equal = true;
            for (&left, &right) in left.iter().zip(right.iter()) {
                *cancellation_observed |= poll_cancelled(cancellation, work);
                equal &= left == right;
            }
            equal
        }
        _ => false,
    }
}

fn include_completion_reasons_with_poll(
    target: &mut CancellationReasonCollection,
    completion: &ResolutionCompletion,
    cancellation: &CancellationToken,
    work: &mut usize,
    cancellation_observed: &mut bool,
) {
    target.include_completion_with_poll(completion, cancellation, work, cancellation_observed);
}

type FragmentSemanticKey = (BindingFragmentId, SemanticId);
type SupertypeKey = (
    BindingFragmentId,
    SemanticId,
    ResolutionSupertypeKind,
    SemanticId,
    SemanticId,
);
type TransferKey = (BindingFragmentId, SemanticId);
type QualifiedRouteKey = (BindingFragmentId, SemanticId, u32);
type DeclarationTypeKey = (BindingFragmentId, SemanticId, DeclarationTypeRole);
type MemberOwnerKey = (
    BindingFragmentId,
    SemanticId,
    SemanticId,
    BindingNodeId,
    ResolutionMemberKind,
    ResolutionMemberAccess,
    ResolutionMemberQualifierCompatibility,
);
type ConstructionRequirementKey = (
    BindingFragmentId,
    SemanticId,
    ResolutionConstructionRequirementKind,
    SemanticId,
);
type DefinitionPropertyGapKey = (BindingFragmentId, SemanticId, SemanticId, SemanticId);

#[derive(Debug)]
struct CachedFactRelation<K> {
    row_keys: Vec<K>,
    evidence: usize,
}

struct InternedFactRow<R> {
    index: usize,
    _row: PhantomData<fn() -> R>,
}

impl<R> InternedFactRow<R> {
    const fn new(index: usize) -> Self {
        Self {
            index,
            _row: PhantomData,
        }
    }

    fn get<'session>(self, session: &'session FactReadSession<'_>) -> &'session R
    where
        R: SessionInternedFactRow,
    {
        session.interned_row(self)
    }
}

impl<R> Clone for InternedFactRow<R> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<R> Copy for InternedFactRow<R> {}

impl<R> std::fmt::Debug for InternedFactRow<R> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("InternedFactRow")
            .field(&self.index)
            .finish()
    }
}

impl<R> PartialEq for InternedFactRow<R> {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index
    }
}

impl<R> Eq for InternedFactRow<R> {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ObservedFactRelation {
    Primary(SemanticId),
    Secondary(SemanticId),
    Tertiary(SemanticId),
    Quaternary(SemanticId),
    Composite(QualifiedRouteSlotLookup),
    Node(BindingNodeId),
    Inventory,
}

#[derive(Debug)]
struct FactRowInterner<K, R> {
    rows: Vec<R>,
    rows_by_key: HashMap<K, InternedFactRow<R>>,
    observed_keys_by_relation: HashMap<ObservedFactRelation, BTreeSet<K>>,
    exhausted_relations: HashSet<ObservedFactRelation>,
    // A late monotonic cancellation can interrupt one variable-membership
    // publication. This poisons the family for the rest of the operation;
    // neither the orphan row nor any later absence becomes usable coverage.
    incomplete_membership_rows: HashSet<K>,
}

impl<K, R> Default for FactRowInterner<K, R> {
    fn default() -> Self {
        Self {
            rows: Vec::new(),
            rows_by_key: HashMap::default(),
            observed_keys_by_relation: HashMap::default(),
            exhausted_relations: HashSet::default(),
            incomplete_membership_rows: HashSet::default(),
        }
    }
}

impl<K, R> FactRowInterner<K, R>
where
    K: Copy + Eq + Hash,
{
    fn get(&self, key: &K) -> Option<(InternedFactRow<R>, &R)> {
        let row = *self.rows_by_key.get(key)?;
        Some((row, self.row(row)))
    }

    fn row(&self, row: InternedFactRow<R>) -> &R {
        self.rows
            .get(row.index)
            .expect("interned fact-row index must belong to its family arena")
    }

    fn intern(&mut self, key: K, row: R) -> InternedFactRow<R> {
        if let Some(&interned) = self.rows_by_key.get(&key) {
            return interned;
        }
        let interned = InternedFactRow::new(self.rows.len());
        self.rows.push(row);
        assert!(
            self.rows_by_key.insert(key, interned).is_none(),
            "one natural fact identity is interned once"
        );
        interned
    }
}

fn observed_keys_are_returned_with_poll<K: Ord>(
    observed: &BTreeSet<K>,
    returned: &[K],
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<bool> {
    let mut returned_index = 0_usize;
    for observed_key in observed {
        loop {
            if poll_cancelled(cancellation, work) {
                return None;
            }
            let Some(returned_key) = returned.get(returned_index) else {
                return Some(false);
            };
            match returned_key.cmp(observed_key) {
                std::cmp::Ordering::Less => {
                    returned_index = returned_index
                        .checked_add(1)
                        .expect("returned fact-row index must fit usize");
                }
                std::cmp::Ordering::Equal => {
                    returned_index = returned_index
                        .checked_add(1)
                        .expect("returned fact-row index must fit usize");
                    break;
                }
                std::cmp::Ordering::Greater => return Some(false),
            }
        }
    }
    Some(true)
}

#[derive(Debug)]
struct ExhaustedFactRelations<Q, K> {
    by_request: HashMap<Q, CachedFactRelation<K>>,
    evidence: Vec<ResolutionCompletion>,
}

impl<Q, K> Default for ExhaustedFactRelations<Q, K> {
    fn default() -> Self {
        Self {
            by_request: HashMap::default(),
            evidence: Vec::new(),
        }
    }
}

#[derive(Debug, Default)]
struct FactReadCache {
    projection_rows:
        FactRowInterner<FragmentSemanticKey, SelectedTypedRow<LoweredBindingProjection>>,
    projections_by_reference: ExhaustedFactRelations<SemanticId, FragmentSemanticKey>,
    projections_by_output: ExhaustedFactRelations<SemanticId, FragmentSemanticKey>,
    route_rows: FactRowInterner<QualifiedRouteKey, SourceSelectedQualifiedRoute>,
    routes_by_reference: ExhaustedFactRelations<SemanticId, QualifiedRouteKey>,
    gap_reason_provenance_rows: FactRowInterner<FragmentSemanticKey, SelectedGapReasonProvenance>,
    gap_reason_provenance_by_reason: ExhaustedFactRelations<SemanticId, FragmentSemanticKey>,
    transfer_rows: FactRowInterner<TransferKey, SelectedTypedRow<LoweredTypeTransfer>>,
    #[cfg(test)]
    transfers_by_source: ExhaustedFactRelations<SemanticId, TransferKey>,
    transfers_by_target: ExhaustedFactRelations<SemanticId, TransferKey>,
    intrinsic_rows: FactRowInterner<FragmentSemanticKey, SelectedTypedRow<LoweredIntrinsicSeed>>,
    intrinsics_by_slot: ExhaustedFactRelations<SemanticId, FragmentSemanticKey>,
    intrinsics_by_type_identity: ExhaustedFactRelations<SemanticId, FragmentSemanticKey>,
    frontier_completion_rows: FactRowInterner<FragmentSemanticKey, SelectedTypeFrontierCompletion>,
    frontier_completions: ExhaustedFactRelations<SemanticId, FragmentSemanticKey>,
    declaration_type_rows:
        FactRowInterner<DeclarationTypeKey, SelectedTypedRow<LoweredDeclarationTypeProperty>>,
    declaration_types_by_definition: ExhaustedFactRelations<SemanticId, DeclarationTypeKey>,
    declaration_visibility_rows: FactRowInterner<
        FragmentSemanticKey,
        SelectedTypedRow<LoweredDeclarationVisibilityProperty>,
    >,
    declaration_visibilities_by_definition: ExhaustedFactRelations<SemanticId, FragmentSemanticKey>,
    member_scope_rows:
        FactRowInterner<FragmentSemanticKey, SelectedTypedRow<LoweredMemberScopeProperty>>,
    member_scopes_by_definition: ExhaustedFactRelations<SemanticId, FragmentSemanticKey>,
    member_owner_rows:
        FactRowInterner<MemberOwnerKey, SelectedTypedRow<LoweredMemberOwnerProperty>>,
    member_owners_by_definition: ExhaustedFactRelations<SemanticId, MemberOwnerKey>,
    construction_requirement_rows: FactRowInterner<
        ConstructionRequirementKey,
        SelectedTypedRow<LoweredConstructionRequirementProperty>,
    >,
    construction_requirements_by_definition:
        ExhaustedFactRelations<SemanticId, ConstructionRequirementKey>,
    supertype_rows: FactRowInterner<SupertypeKey, SelectedTypedRow<LoweredSupertypeProperty>>,
    supertypes_by_definition: ExhaustedFactRelations<SemanticId, SupertypeKey>,
    property_gap_rows:
        FactRowInterner<DefinitionPropertyGapKey, SelectedTypedRow<LoweredDefinitionPropertyGap>>,
    property_gaps_by_definition: ExhaustedFactRelations<SemanticId, DefinitionPropertyGapKey>,
    call_rows:
        FactRowInterner<FragmentSemanticKey, SelectedTypedRow<LoweredCallApplicabilityObligation>>,
    calls_by_reference: ExhaustedFactRelations<SemanticId, FragmentSemanticKey>,
    signature_rows:
        FactRowInterner<FragmentSemanticKey, SelectedTypedRow<LoweredCallableSignatureProperty>>,
    signatures_by_definition: ExhaustedFactRelations<SemanticId, FragmentSemanticKey>,
}

trait SessionInternedFactRow: Sized {
    fn from_cache(cache: &FactReadCache, row: InternedFactRow<Self>) -> &Self;
}

macro_rules! session_interned_fact_row {
    ($row:ty, $field:ident) => {
        impl SessionInternedFactRow for $row {
            fn from_cache(cache: &FactReadCache, row: InternedFactRow<Self>) -> &Self {
                cache.$field.row(row)
            }
        }
    };
}

session_interned_fact_row!(SelectedTypedRow<LoweredBindingProjection>, projection_rows);
session_interned_fact_row!(SourceSelectedQualifiedRoute, route_rows);
session_interned_fact_row!(SelectedGapReasonProvenance, gap_reason_provenance_rows);
session_interned_fact_row!(SelectedTypedRow<LoweredTypeTransfer>, transfer_rows);
session_interned_fact_row!(SelectedTypedRow<LoweredIntrinsicSeed>, intrinsic_rows);
session_interned_fact_row!(SelectedTypeFrontierCompletion, frontier_completion_rows);
session_interned_fact_row!(
    SelectedTypedRow<LoweredDeclarationTypeProperty>,
    declaration_type_rows
);
session_interned_fact_row!(
    SelectedTypedRow<LoweredDeclarationVisibilityProperty>,
    declaration_visibility_rows
);
session_interned_fact_row!(
    SelectedTypedRow<LoweredMemberScopeProperty>,
    member_scope_rows
);
session_interned_fact_row!(
    SelectedTypedRow<LoweredMemberOwnerProperty>,
    member_owner_rows
);
session_interned_fact_row!(
    SelectedTypedRow<LoweredConstructionRequirementProperty>,
    construction_requirement_rows
);
session_interned_fact_row!(SelectedTypedRow<LoweredSupertypeProperty>, supertype_rows);
session_interned_fact_row!(
    SelectedTypedRow<LoweredDefinitionPropertyGap>,
    property_gap_rows
);
session_interned_fact_row!(
    SelectedTypedRow<LoweredCallApplicabilityObligation>,
    call_rows
);
session_interned_fact_row!(
    SelectedTypedRow<LoweredCallableSignatureProperty>,
    signature_rows
);

/// One borrowing, operation-local view over immutable selected resolution facts.
///
/// The session owns no resolved answers or derived fixed-point state. It may
/// retain only source rows whose entire selected relation returned
/// [`TypedFactReadTerminal::Exhausted`]. A stopped, source-cancelled, or failed
/// read installs neither rows nor negative coverage. A later token edge while
/// installing an already exhausted relation may leave an inert orphan row;
/// no relation marker is published, and an incomplete-membership poison makes
/// the family unusable for the rest of that monotonic-cancelled operation. A
/// fresh top-level session retries from the source. Transfer closure and cycle
/// classification are derived afresh by each evaluation from exhausted selected
/// incoming-transfer relations. Neither result enters the relation cache.
pub struct FactReadSession<'a> {
    lexical_source: &'a dyn BatchResolutionFragmentSource,
    typed_source: &'a dyn SelectedTypedFactSource,
    callable_static_import_boundaries: &'a [BindingNodeId],
    cancellation: &'a CancellationToken,
    cache: FactReadCache,
}

impl<'a> FactReadSession<'a> {
    /// Borrow any composite selected source for one resolution operation.
    ///
    pub fn new(source: &'a dyn FactResolutionSource, cancellation: &'a CancellationToken) -> Self {
        Self::from_split_sources(source, source, cancellation)
    }

    /// Resolve one reference through this operation's immutable fact cache.
    pub fn resolve_reference(
        &mut self,
        reference: SemanticId,
    ) -> StoreResult<FactResolutionAnswer> {
        let mut hierarchy = HierarchyOperationArena::default();
        FactEvaluation::new(self, &mut hierarchy, reference).run()
    }

    fn from_split_sources(
        lexical_source: &'a dyn BatchResolutionFragmentSource,
        typed_source: &'a dyn SelectedTypedFactSource,
        cancellation: &'a CancellationToken,
    ) -> Self {
        Self::from_split_sources_with_callable_static_import_boundaries(
            lexical_source,
            typed_source,
            &[],
            cancellation,
        )
    }

    #[cfg(test)]
    pub(crate) fn from_split_sources_for_test(
        lexical_source: &'a dyn BatchResolutionFragmentSource,
        typed_source: &'a dyn SelectedTypedFactSource,
        cancellation: &'a CancellationToken,
    ) -> Self {
        Self::from_split_sources(lexical_source, typed_source, cancellation)
    }

    fn from_split_sources_with_callable_static_import_boundaries(
        lexical_source: &'a dyn BatchResolutionFragmentSource,
        typed_source: &'a dyn SelectedTypedFactSource,
        callable_static_import_boundaries: &'a [BindingNodeId],
        cancellation: &'a CancellationToken,
    ) -> Self {
        debug_assert!(
            callable_static_import_boundaries
                .windows(2)
                .all(|pair| pair[0] < pair[1]),
            "callable static-import boundaries must be canonical"
        );
        Self {
            lexical_source,
            typed_source,
            callable_static_import_boundaries,
            cancellation,
            cache: FactReadCache::default(),
        }
    }

    fn interned_row<R>(&self, row: InternedFactRow<R>) -> &R
    where
        R: SessionInternedFactRow,
    {
        R::from_cache(&self.cache, row)
    }

    fn is_callable_static_import_boundary(&self, node: BindingNodeId) -> bool {
        self.callable_static_import_boundaries
            .binary_search(&node)
            .is_ok()
    }

    fn cancelled_rows<R>(
        &self,
        evidence: CancellationEvidenceLedger,
        work: &mut usize,
    ) -> SessionFactRead<R> {
        let (evidence, _) = evidence.finish(true, self.cancellation, work);
        SessionFactRead::Cancelled(evidence)
    }
}

impl FactEvaluation<'_, '_> {
    fn seal_hierarchy_summaries(
        &mut self,
        shape: HierarchyLookupShape,
        owners: &BTreeSet<SemanticId>,
        cycles: &HashMap<SemanticId, PartialPathId>,
        expanded: &HashSet<SemanticId>,
    ) -> bool {
        let mut staged = HashMap::<HierarchyNodeKey, HierarchyStructuralSummary>::default();

        // A reached malformed SCC is one terminal structural operand. Its
        // members and exits cannot contribute candidates. Retain only exact
        // internal-edge operands and one canonical cycle atom; member-local
        // candidate evidence and outgoing edge/frontier evidence are suppressed.
        let mut components = BTreeMap::<PartialPathId, BTreeSet<SemanticId>>::new();
        for (&owner, &cycle) in cycles {
            if self.poll_cancelled() {
                return false;
            }
            if owners.contains(&owner) {
                components.entry(cycle).or_default().insert(owner);
            }
        }
        for (cycle, component) in components {
            let mut component_expanded = true;
            for owner in &component {
                if self.poll_cancelled() {
                    return false;
                }
                component_expanded &= expanded.contains(owner);
            }
            if !component_expanded {
                continue;
            }
            let mut evidence = HierarchyEvidence::Complete;
            for &owner in &component {
                if self.poll_cancelled() {
                    return false;
                }
                let edge_node = self
                    .hierarchy
                    .edge_node_snapshot(owner)
                    .expect("a sealed hierarchy SCC member has immutable owner edges");
                for edge_ordinal in 0..edge_node.edge_count {
                    if self.poll_cancelled() {
                        return false;
                    }
                    let edge = self.hierarchy.edge_snapshot(owner, edge_ordinal);
                    let mut internal = false;
                    for target_ordinal in 0..edge.target_count {
                        if self.poll_cancelled() {
                            return false;
                        }
                        let target =
                            self.hierarchy
                                .edge_target(owner, edge_ordinal, target_ordinal);
                        internal |= component.contains(&target);
                    }
                    if !internal {
                        continue;
                    }
                    evidence = self.hierarchy_union(evidence, edge.residual_evidence);
                    evidence = self.hierarchy_union(evidence, edge.hierarchy_evidence);
                }
            }
            let Some(cycle_evidence) = self.hierarchy_derived_one(
                hierarchy_cycle_atom_identity(cycle),
                ResolutionCompletion::incomplete([ResolutionIncompleteReason::CyclicExpansion(
                    cycle,
                )]),
            ) else {
                return false;
            };
            evidence = self.hierarchy_union(evidence, cycle_evidence);
            let summary = HierarchyStructuralSummary {
                candidate_distance: None,
                candidates: None,
                evidence,
                transfer: HierarchyEvidence::Complete,
                retains_global_evidence: false,
            };
            for owner in component {
                if self.poll_cancelled() {
                    return false;
                }
                staged.insert(HierarchyNodeKey { shape, owner }, summary.clone());
            }
        }

        // A structural candidate is a cutoff, independent of later qualifier
        // compatibility. The origin-specific replay owns this selected local
        // candidate's lexical completion boxes, so they are not duplicated in
        // the structural completion.
        for &owner in owners {
            if self.poll_cancelled() {
                return false;
            }
            let key = HierarchyNodeKey { shape, owner };
            if staged.contains_key(&key)
                || self.hierarchy.contains_summary(key)
                || cycles.contains_key(&owner)
            {
                continue;
            }
            let Some(local) = self.hierarchy.local_snapshot(key) else {
                continue;
            };
            if local.has_direct_definitions {
                let candidate = self.hierarchy.candidates.here(owner);
                staged.insert(
                    key,
                    HierarchyStructuralSummary {
                        candidate_distance: Some(0),
                        candidates: Some(candidate),
                        evidence: local.cutoff_evidence,
                        transfer: local.transfer,
                        retains_global_evidence: local.candidate_inventory_observed,
                    },
                );
            }
        }

        let mut waiting = HashMap::<HierarchyNodeKey, BTreeSet<HierarchyNodeKey>>::default();
        let mut reverse = HashMap::<HierarchyNodeKey, BTreeSet<HierarchyNodeKey>>::default();
        for &owner in owners {
            if self.poll_cancelled() {
                return false;
            }
            let key = HierarchyNodeKey { shape, owner };
            if staged.contains_key(&key)
                || self.hierarchy.contains_summary(key)
                || cycles.contains_key(&owner)
                || !expanded.contains(&owner)
            {
                continue;
            }
            let edge_node = self
                .hierarchy
                .edge_node_snapshot(owner)
                .expect("an expanded hierarchy owner has immutable owner edges");
            let mut dependencies = BTreeSet::new();
            for edge_ordinal in 0..edge_node.edge_count {
                if self.poll_cancelled() {
                    return false;
                }
                let edge = self.hierarchy.edge_snapshot(owner, edge_ordinal);
                for target_ordinal in 0..edge.target_count {
                    if self.poll_cancelled() {
                        return false;
                    }
                    let target = self
                        .hierarchy
                        .edge_target(owner, edge_ordinal, target_ordinal);
                    let target_key = HierarchyNodeKey {
                        shape,
                        owner: target,
                    };
                    if !staged.contains_key(&target_key)
                        && !self.hierarchy.contains_summary(target_key)
                    {
                        dependencies.insert(target_key);
                    }
                    reverse.entry(target_key).or_default().insert(key);
                }
            }
            waiting.insert(key, dependencies);
        }
        let mut ready = BTreeSet::new();
        for (&key, dependencies) in &waiting {
            if self.poll_cancelled() {
                return false;
            }
            if dependencies.is_empty() {
                ready.insert(key);
            }
        }
        while let Some(key) = ready.pop_first() {
            if self.poll_cancelled() {
                return false;
            }
            let dependencies = waiting
                .remove(&key)
                .expect("a ready hierarchy summary has a waiting entry");
            assert!(dependencies.is_empty());
            let local = self
                .hierarchy
                .local_snapshot(key)
                .expect("a sealed hierarchy owner has local evidence");
            let edge_node = self
                .hierarchy
                .edge_node_snapshot(key.owner)
                .expect("a sealed hierarchy owner has immutable owner edges");
            let mut evidence = local.evidence;
            let mut transfer = local.transfer;
            let shifted_edge_evidence = self.hierarchy_shift(edge_node.evidence, 1);
            evidence = self.hierarchy_union(evidence, shifted_edge_evidence);
            let mut nearest = None;
            let mut candidates = None;
            let mut retains_global_evidence = local.candidate_inventory_observed;
            for edge_ordinal in 0..edge_node.edge_count {
                if self.poll_cancelled() {
                    return false;
                }
                let edge = self.hierarchy.edge_snapshot(key.owner, edge_ordinal);
                let shifted_residual_evidence = self.hierarchy_shift(edge.residual_evidence, 1);
                evidence = self.hierarchy_union(evidence, shifted_residual_evidence);
                if edge.target_count == 0 {
                    let shifted_hierarchy_evidence =
                        self.hierarchy_shift(edge.hierarchy_evidence, 1);
                    evidence = self.hierarchy_union(evidence, shifted_hierarchy_evidence);
                } else {
                    let shifted_transfer = self.hierarchy_transfer_shift(edge.transfer, 1);
                    transfer = self.hierarchy_transfer_union(transfer, shifted_transfer);
                }
                for target_ordinal in 0..edge.target_count {
                    if self.poll_cancelled() {
                        return false;
                    }
                    let target =
                        self.hierarchy
                            .edge_target(key.owner, edge_ordinal, target_ordinal);
                    let target_key = HierarchyNodeKey {
                        shape,
                        owner: target,
                    };
                    let child = staged
                        .get(&target_key)
                        .cloned()
                        .or_else(|| self.hierarchy.summary(target_key).cloned())
                        .expect("a ready hierarchy summary has every child summary");
                    retains_global_evidence |= child.retains_global_evidence;
                    let shifted_child_evidence = self.hierarchy_shift(child.evidence, 2);
                    evidence = self.hierarchy_union(evidence, shifted_child_evidence);
                    let shifted_child_transfer = self.hierarchy_transfer_shift(child.transfer, 2);
                    transfer = self.hierarchy_transfer_union(transfer, shifted_child_transfer);
                    let Some(child_distance) = child.candidate_distance else {
                        continue;
                    };
                    let distance = child_distance
                        .checked_add(1)
                        .expect("hierarchy candidate distance must fit u32");
                    if nearest.is_none_or(|current| distance < current) {
                        nearest = Some(distance);
                        candidates = None;
                    }
                    if nearest == Some(distance) {
                        let child_candidates = child
                            .candidates
                            .expect("a finite child distance has candidate expressions");
                        let via =
                            self.hierarchy
                                .candidates
                                .via(edge.reference, target, child_candidates);
                        candidates = self.hierarchy.candidates.union(candidates, Some(via));
                    }
                }
            }
            staged.insert(
                key,
                HierarchyStructuralSummary {
                    candidate_distance: nearest,
                    candidates,
                    evidence,
                    transfer,
                    retains_global_evidence,
                },
            );
            for parent in reverse.get(&key).into_iter().flatten() {
                if self.poll_cancelled() {
                    return false;
                }
                let Some(dependencies) = waiting.get_mut(parent) else {
                    continue;
                };
                dependencies.remove(&key);
                if dependencies.is_empty() {
                    ready.insert(*parent);
                }
            }
        }
        assert!(
            waiting.is_empty(),
            "expanded acyclic hierarchy owners must seal after SCC terminals"
        );
        if self.poll_cancelled() {
            return false;
        }
        if self.cancellation.is_cancelled() {
            self.cancellation_observed = true;
            return false;
        }
        let generation = self.hierarchy.begin_publication();
        for (key, summary) in staged {
            if self.poll_cancelled() {
                return false;
            }
            self.hierarchy.stage_summary(generation, key, summary);
        }
        if self.cancellation.is_cancelled() {
            self.cancellation_observed = true;
            return false;
        }
        self.hierarchy.commit_publication(generation);
        true
    }
}
impl<'a> FactReadSession<'a> {
    #[allow(clippy::too_many_arguments)]
    fn read_keyed_rows<Q, K, R, C, CM, V, D, N, RI, RR, O, L, E>(
        &mut self,
        requested: &[Q],
        cache_parts: C,
        cache_parts_mut: CM,
        mut visit: V,
        relation_identities: D,
        natural_identity: N,
        requested_relation_identity: RI,
        row_relation_identities: RR,
        observe_evidence: O,
        clone_row: L,
        rows_equal: E,
    ) -> StoreResult<SessionFactRead<R>>
    where
        Q: Copy + Eq + Hash + Ord,
        K: Copy + Eq + Hash + Ord,
        R: SessionInternedFactRow,
        C: for<'cache> Fn(
            &'cache FactReadCache,
        ) -> (
            &'cache FactRowInterner<K, R>,
            &'cache ExhaustedFactRelations<Q, K>,
        ),
        CM: for<'cache> Fn(
            &'cache mut FactReadCache,
        ) -> (
            &'cache mut FactRowInterner<K, R>,
            &'cache mut ExhaustedFactRelations<Q, K>,
        ),
        V: FnMut(
            TypedFactRequest<'_, Q>,
            &mut TypedFactPageVisitor<'_, R>,
        ) -> StoreResult<TypedFactReadOutcome>,
        D: Fn(&R, &CancellationToken, &mut usize) -> Option<Vec<Q>>,
        N: Fn(&R) -> K,
        RI: Fn(Q) -> ObservedFactRelation,
        RR: Fn(&R, &CancellationToken, &mut usize) -> Option<Vec<ObservedFactRelation>>,
        O: Fn(&R, &mut CancellationEvidenceLedger, &CancellationToken, &mut usize) -> bool,
        L: Fn(&R, &CancellationToken, &mut usize) -> Option<R>,
        E: Fn(&R, &R, &mut dyn FnMut() -> bool) -> Option<bool>,
    {
        let mut work = 0_usize;
        let mut canonical_requests = BTreeSet::new();
        for &request in requested {
            if poll_cancelled(self.cancellation, &mut work) {
                return Ok(self.cancelled_rows(CancellationEvidenceLedger::default(), &mut work));
            }
            canonical_requests.insert(request);
        }

        let mut evidence = CancellationEvidenceLedger::default();
        let mut result = BTreeMap::<K, InternedFactRow<R>>::new();
        let mut missing = Vec::new();
        {
            let cache = &self.cache;
            let (rows, relations) = cache_parts(cache);
            for &request in &canonical_requests {
                let Some(relation) = relations.by_request.get(&request) else {
                    missing.push(request);
                    continue;
                };
                let relation_evidence =
                    relations
                        .evidence
                        .get(relation.evidence)
                        .unwrap_or_else(|| {
                            panic!("exhausted fact relation names missing interned evidence")
                        });
                if evidence.include(relation_evidence, self.cancellation, &mut work) {
                    return Ok(self.cancelled_rows(evidence, &mut work));
                }
                for &key in relation.row_keys.iter() {
                    let (interned, row) = rows.get(&key).unwrap_or_else(|| {
                        panic!("exhausted fact relation names missing interned row")
                    });
                    if observe_evidence(row, &mut evidence, self.cancellation, &mut work) {
                        return Ok(self.cancelled_rows(evidence, &mut work));
                    }
                    if let Some(existing) = result.insert(key, interned) {
                        assert_eq!(
                            existing, interned,
                            "one natural fact identity must name one interned row"
                        );
                    }
                }
            }
        }
        if evidence.cancellation_observed() || self.cancellation.is_cancelled() {
            return Ok(self.cancelled_rows(evidence, &mut work));
        }

        let mut staged = BTreeMap::<K, (R, BTreeSet<Q>, Vec<ObservedFactRelation>)>::new();
        for chunk in missing.chunks(MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
            if poll_cancelled(self.cancellation, &mut work) {
                return Ok(self.cancelled_rows(evidence, &mut work));
            }
            let chunk_set = chunk.iter().copied().collect::<BTreeSet<_>>();
            let mut seen_identities = HashSet::default();
            let mut chunk_rows = Vec::new();
            let mut callback = |page: &[R]| {
                for row in page {
                    let identity = natural_identity(row);
                    if !seen_identities.insert(identity) {
                        return Err(StoreError::new(
                            "typed source repeated one natural identity in a single read",
                        ));
                    }
                    if observe_evidence(row, &mut evidence, self.cancellation, &mut work) {
                        return Ok(false);
                    }
                    let Some(row_requests) = relation_identities(row, self.cancellation, &mut work)
                    else {
                        return Ok(false);
                    };
                    let mut matches_current_chunk = false;
                    let mut associated_requests = BTreeSet::new();
                    for request in row_requests {
                        if poll_cancelled(self.cancellation, &mut work) {
                            return Ok(false);
                        }
                        if chunk_set.contains(&request) {
                            matches_current_chunk = true;
                            associated_requests.insert(request);
                        }
                    }
                    if !matches_current_chunk {
                        return Err(StoreError::new(
                            "typed source emitted a row outside its requested relation",
                        ));
                    }
                    let Some(row) = clone_row(row, self.cancellation, &mut work) else {
                        return Ok(false);
                    };
                    let Some(observed_relations) =
                        row_relation_identities(&row, self.cancellation, &mut work)
                    else {
                        return Ok(false);
                    };
                    chunk_rows.push((identity, row, associated_requests, observed_relations));
                }
                Ok(true)
            };
            let outcome = {
                let mut visitor = TypedFactPageVisitor::new(&mut callback);
                visit(TypedFactRequest::new(chunk), &mut visitor)?
            };
            evidence.include(outcome.evidence(), self.cancellation, &mut work);
            match outcome.terminal() {
                TypedFactReadTerminal::Exhausted => {}
                TypedFactReadTerminal::Cancelled => {
                    return Ok(self.cancelled_rows(evidence, &mut work));
                }
                TypedFactReadTerminal::Stopped => {
                    if evidence.cancellation_observed() || self.cancellation.is_cancelled() {
                        return Ok(self.cancelled_rows(evidence, &mut work));
                    }
                    return Err(StoreError::new(
                        "typed source stopped an operation-owned always-live visitor",
                    ));
                }
            }
            if evidence.cancellation_observed() || self.cancellation.is_cancelled() {
                return Ok(self.cancelled_rows(evidence, &mut work));
            }

            // Source cursor order is deliberately opaque. Only an exhausted
            // relation may be canonicalized and merged into the operation
            // transaction; a stopped or cancelled prefix never becomes cache
            // state. Equal rows may recur across separate request chunks when
            // one natural row belongs to more than one requested relation.
            for (identity, row, associated_requests, observed_relations) in chunk_rows {
                if poll_cancelled(self.cancellation, &mut work) {
                    return Ok(self.cancelled_rows(evidence, &mut work));
                }
                if let Some((staged_row, staged_requests, _)) = staged.get_mut(&identity) {
                    let mut cancelled = || poll_cancelled(self.cancellation, &mut work);
                    let Some(equal) = rows_equal(staged_row, &row, &mut cancelled) else {
                        return Ok(self.cancelled_rows(evidence, &mut work));
                    };
                    if !equal {
                        return Err(StoreError::new(
                            "typed source repeated one natural identity with conflicting payload across request chunks",
                        ));
                    }
                    staged_requests.extend(associated_requests);
                } else {
                    staged.insert(identity, (row, associated_requests, observed_relations));
                }
            }
        }

        // Validate every cross-direction interner hit before taking the sole
        // mutable cache guard. Cancellation or conflict leaves the complete
        // staged transaction unpublished.
        {
            let cache = &self.cache;
            let (rows, _) = cache_parts(cache);
            for (identity, (row, _, observed_relations)) in &staged {
                if poll_cancelled(self.cancellation, &mut work) {
                    return Ok(self.cancelled_rows(evidence, &mut work));
                }
                for &relation in observed_relations {
                    if rows.exhausted_relations.contains(&relation)
                        && !rows
                            .observed_keys_by_relation
                            .get(&relation)
                            .is_some_and(|keys| keys.contains(identity))
                    {
                        return Err(StoreError::new(
                            "typed source emitted a row omitted by an already exhausted access direction",
                        ));
                    }
                }
                let Some((_, existing)) = rows.get(identity) else {
                    continue;
                };
                let mut cancelled = || poll_cancelled(self.cancellation, &mut work);
                let Some(equal) = rows_equal(existing, row, &mut cancelled) else {
                    return Ok(self.cancelled_rows(evidence, &mut work));
                };
                if !equal {
                    return Err(StoreError::new(
                        "typed source access directions disagree on one natural row",
                    ));
                }
            }
        }
        if self.cancellation.is_cancelled() {
            return Ok(self.cancelled_rows(evidence, &mut work));
        }

        let (aggregate_evidence, cancelled) = evidence.finish(false, self.cancellation, &mut work);
        if cancelled || self.cancellation.is_cancelled() {
            let mut cancelled_evidence = CancellationEvidenceLedger::default();
            cancelled_evidence.include(&aggregate_evidence, self.cancellation, &mut work);
            return Ok(self.cancelled_rows(cancelled_evidence, &mut work));
        }
        let mut cancelled = || poll_cancelled(self.cancellation, &mut work);
        let Some(cached_evidence) =
            clone_resolution_completion_with_poll(&aggregate_evidence, &mut cancelled)
        else {
            let mut cancelled_evidence = CancellationEvidenceLedger::default();
            cancelled_evidence.include(&aggregate_evidence, self.cancellation, &mut work);
            return Ok(self.cancelled_rows(cancelled_evidence, &mut work));
        };
        let mut cached_evidence = Some(cached_evidence);
        let mut shared_evidence = None;
        let mut keys_by_request = BTreeMap::new();
        let mut staged_observed_keys_by_relation =
            HashMap::<ObservedFactRelation, BTreeSet<K>>::default();
        for &request in &missing {
            if poll_cancelled(self.cancellation, &mut work) {
                let mut cancelled_evidence = CancellationEvidenceLedger::default();
                cancelled_evidence.include(&aggregate_evidence, self.cancellation, &mut work);
                return Ok(self.cancelled_rows(cancelled_evidence, &mut work));
            }
            keys_by_request.insert(request, Vec::new());
        }
        for (&identity, (_, requests, observed_relations)) in &staged {
            if poll_cancelled(self.cancellation, &mut work) {
                let mut cancelled_evidence = CancellationEvidenceLedger::default();
                cancelled_evidence.include(&aggregate_evidence, self.cancellation, &mut work);
                return Ok(self.cancelled_rows(cancelled_evidence, &mut work));
            }
            for request in requests {
                if poll_cancelled(self.cancellation, &mut work) {
                    let mut cancelled_evidence = CancellationEvidenceLedger::default();
                    cancelled_evidence.include(&aggregate_evidence, self.cancellation, &mut work);
                    return Ok(self.cancelled_rows(cancelled_evidence, &mut work));
                }
                keys_by_request
                    .get_mut(request)
                    .expect("a staged row belongs to one missing request")
                    .push(identity);
            }
            for &relation in observed_relations {
                if poll_cancelled(self.cancellation, &mut work) {
                    let mut cancelled_evidence = CancellationEvidenceLedger::default();
                    cancelled_evidence.include(&aggregate_evidence, self.cancellation, &mut work);
                    return Ok(self.cancelled_rows(cancelled_evidence, &mut work));
                }
                staged_observed_keys_by_relation
                    .entry(relation)
                    .or_default()
                    .insert(identity);
            }
        }

        // Validate the complete multi-request transaction before installing
        // any row or positive/negative relation marker. Otherwise request
        // order could let an early empty relation commit before a later row
        // reveals that the same parent belonged to it.
        {
            let cache = &self.cache;
            let (rows, _) = cache_parts(cache);
            if !rows.incomplete_membership_rows.is_empty() {
                return Err(StoreError::new(
                    "typed fact family has incomplete observed-relation membership",
                ));
            }
            for (&request, keys) in &keys_by_request {
                if poll_cancelled(self.cancellation, &mut work) {
                    let mut cancelled_evidence = CancellationEvidenceLedger::default();
                    cancelled_evidence.include(&aggregate_evidence, self.cancellation, &mut work);
                    return Ok(self.cancelled_rows(cancelled_evidence, &mut work));
                }
                let relation = requested_relation_identity(request);
                for observed in [
                    rows.observed_keys_by_relation.get(&relation),
                    staged_observed_keys_by_relation.get(&relation),
                ]
                .into_iter()
                .flatten()
                {
                    let Some(observed_complete) = observed_keys_are_returned_with_poll(
                        observed,
                        keys,
                        self.cancellation,
                        &mut work,
                    ) else {
                        let mut cancelled_evidence = CancellationEvidenceLedger::default();
                        cancelled_evidence.include(
                            &aggregate_evidence,
                            self.cancellation,
                            &mut work,
                        );
                        return Ok(self.cancelled_rows(cancelled_evidence, &mut work));
                    };
                    if !observed_complete {
                        return Err(StoreError::new(
                            "typed source exhausted a relation while omitting an already observed row",
                        ));
                    }
                }
            }
        }

        for (request, keys) in keys_by_request {
            if poll_cancelled(self.cancellation, &mut work) {
                let mut cancelled_evidence = CancellationEvidenceLedger::default();
                cancelled_evidence.include(&aggregate_evidence, self.cancellation, &mut work);
                return Ok(self.cancelled_rows(cancelled_evidence, &mut work));
            }
            // A relation is the request-local commit marker. Rows may be
            // interned before cancellation is observed, but the relation is
            // published only after every one of its keys names an interned
            // row. A late monotonic cancellation can also leave one row in
            // `incomplete_membership_rows`; the family-wide gate above makes
            // that operation-local cache inert instead of exposing a partial
            // membership or absence. A fresh top-level session retries the
            // unmarked request and validates every membership before use.
            let request_cancelled = {
                let cache = &mut self.cache;
                let (rows, relations) = cache_parts_mut(cache);
                let mut request_cancelled = false;
                let mut installed_row_count = 0_usize;
                for &identity in &keys {
                    if poll_cancelled(self.cancellation, &mut work) {
                        request_cancelled = true;
                        break;
                    }
                    let (interned, observed_relations) =
                        if let Some((row, row_requests, observed_relations)) =
                            staged.remove(&identity)
                        {
                            assert!(
                                row_requests.contains(&request),
                                "a request-local fact relation can install only its own rows"
                            );
                            (rows.intern(identity, row), observed_relations)
                        } else {
                            (
                                rows.get(&identity)
                                    .map(|(interned, _)| interned)
                                    .unwrap_or_else(|| {
                                        panic!("a shared staged row must already be interned")
                                    }),
                                Vec::new(),
                            )
                        };
                    if !observed_relations.is_empty() {
                        assert!(
                            rows.incomplete_membership_rows.insert(identity),
                            "one fact row publishes observed memberships once"
                        );
                    }
                    for relation in observed_relations {
                        if poll_cancelled(self.cancellation, &mut work) {
                            request_cancelled = true;
                            break;
                        }
                        rows.observed_keys_by_relation
                            .entry(relation)
                            .or_default()
                            .insert(identity);
                    }
                    if request_cancelled {
                        break;
                    }
                    rows.incomplete_membership_rows.remove(&identity);
                    if let Some(existing) = result.insert(identity, interned) {
                        assert_eq!(
                            existing, interned,
                            "one natural fact identity must name one interned row"
                        );
                    }
                    installed_row_count = installed_row_count
                        .checked_add(1)
                        .expect("one request's installed fact-row count must fit usize");
                }
                if !request_cancelled && poll_cancelled(self.cancellation, &mut work) {
                    request_cancelled = true;
                }
                if !request_cancelled {
                    assert_eq!(
                        installed_row_count,
                        keys.len(),
                        "an exhausted fact relation names every request-local staged row"
                    );
                    let evidence = *shared_evidence.get_or_insert_with(|| {
                        let evidence = cached_evidence
                            .take()
                            .expect("one multi-request fact read interns its evidence once");
                        let index = relations.evidence.len();
                        relations.evidence.push(evidence);
                        index
                    });
                    assert!(
                        relations
                            .by_request
                            .insert(
                                request,
                                CachedFactRelation {
                                    row_keys: keys,
                                    evidence,
                                },
                            )
                            .is_none(),
                        "an unexhausted fact relation is installed exactly once"
                    );
                    assert!(
                        rows.exhausted_relations
                            .insert(requested_relation_identity(request)),
                        "one fact relation is marked exhausted exactly once"
                    );
                }
                request_cancelled
            };
            if request_cancelled {
                let mut cancelled_evidence = CancellationEvidenceLedger::default();
                cancelled_evidence.include(&aggregate_evidence, self.cancellation, &mut work);
                return Ok(self.cancelled_rows(cancelled_evidence, &mut work));
            }
        }
        assert!(
            staged.is_empty(),
            "every staged fact row belongs to one installed exhausted relation"
        );
        if self.cancellation.is_cancelled() {
            // The source relations exhausted before this token edge, so the
            // immutable cache remains valid. Publication still fails closed.
            let mut cancelled_evidence = CancellationEvidenceLedger::default();
            cancelled_evidence.include(&aggregate_evidence, self.cancellation, &mut work);
            return Ok(self.cancelled_rows(cancelled_evidence, &mut work));
        }
        let mut rows = Vec::with_capacity(result.len());
        while let Some((_, row)) = result.pop_first() {
            if poll_cancelled(self.cancellation, &mut work) {
                let mut cancelled_evidence = CancellationEvidenceLedger::default();
                cancelled_evidence.include(&aggregate_evidence, self.cancellation, &mut work);
                return Ok(self.cancelled_rows(cancelled_evidence, &mut work));
            }
            rows.push(row);
        }
        Ok(SessionFactRead::Exhausted {
            rows,
            evidence: aggregate_evidence,
        })
    }

    fn projections_for_references(
        &mut self,
        references: &[SemanticId],
    ) -> StoreResult<SessionFactRead<SelectedTypedRow<LoweredBindingProjection>>> {
        self.read_keyed_rows(
            references,
            |cache| (&cache.projection_rows, &cache.projections_by_reference),
            |cache| {
                (
                    &mut cache.projection_rows,
                    &mut cache.projections_by_reference,
                )
            },
            |request, visitor| {
                self.typed_source
                    .visit_binding_projection_pages_for_references(
                        request,
                        self.cancellation,
                        visitor,
                    )
            },
            |row, _, _| Some(vec![row.row().reference()]),
            SelectedTypedRow::<LoweredBindingProjection>::natural_identity,
            ObservedFactRelation::Primary,
            |row, _, _| {
                Some(vec![
                    ObservedFactRelation::Primary(row.row().reference()),
                    ObservedFactRelation::Secondary(row.row().output_slot()),
                ])
            },
            observe_no_session_row_evidence,
            clone_selected_copy_session_row,
            copy_session_rows_equal,
        )
    }

    fn projections_for_outputs(
        &mut self,
        outputs: &[SemanticId],
    ) -> StoreResult<SessionFactRead<SelectedTypedRow<LoweredBindingProjection>>> {
        self.read_keyed_rows(
            outputs,
            |cache| (&cache.projection_rows, &cache.projections_by_output),
            |cache| (&mut cache.projection_rows, &mut cache.projections_by_output),
            |request, visitor| {
                self.typed_source
                    .visit_binding_projection_pages_for_outputs(request, self.cancellation, visitor)
            },
            |row, _, _| Some(vec![row.row().output_slot()]),
            SelectedTypedRow::<LoweredBindingProjection>::natural_identity,
            ObservedFactRelation::Secondary,
            |row, _, _| {
                Some(vec![
                    ObservedFactRelation::Primary(row.row().reference()),
                    ObservedFactRelation::Secondary(row.row().output_slot()),
                ])
            },
            observe_no_session_row_evidence,
            clone_selected_copy_session_row,
            copy_session_rows_equal,
        )
    }

    fn routes_for_references(
        &mut self,
        references: &[SemanticId],
    ) -> StoreResult<SessionFactRead<SourceSelectedQualifiedRoute>> {
        self.read_keyed_rows(
            references,
            |cache| (&cache.route_rows, &cache.routes_by_reference),
            |cache| (&mut cache.route_rows, &mut cache.routes_by_reference),
            |request, visitor| {
                self.typed_source
                    .visit_qualified_route_pages_for_references(request, self.cancellation, visitor)
            },
            |row, _, _| Some(vec![row.row().reference()]),
            |row| row.natural_identity(),
            ObservedFactRelation::Primary,
            qualified_route_observed_relations,
            observe_route_evidence,
            clone_copy_session_row,
            copy_session_rows_equal,
        )
    }

    fn gap_reason_provenance_for_reasons(
        &mut self,
        reasons: &[SemanticId],
    ) -> StoreResult<SessionFactRead<SelectedGapReasonProvenance>> {
        self.read_keyed_rows(
            reasons,
            |cache| {
                (
                    &cache.gap_reason_provenance_rows,
                    &cache.gap_reason_provenance_by_reason,
                )
            },
            |cache| {
                (
                    &mut cache.gap_reason_provenance_rows,
                    &mut cache.gap_reason_provenance_by_reason,
                )
            },
            |request, visitor| {
                self.typed_source
                    .visit_gap_reason_provenance_pages_for_reasons(
                        request,
                        self.cancellation,
                        visitor,
                    )
            },
            |row, _, _| Some(vec![row.reason()]),
            |row| row.natural_identity(),
            ObservedFactRelation::Primary,
            |row, _, _| Some(vec![ObservedFactRelation::Primary(row.reason())]),
            observe_no_session_row_evidence,
            clone_copy_session_row,
            copy_session_rows_equal,
        )
    }

    fn transfers_to_targets(
        &mut self,
        targets: &[SemanticId],
    ) -> StoreResult<SessionFactRead<SelectedTypedRow<LoweredTypeTransfer>>> {
        self.read_keyed_rows(
            targets,
            |cache| (&cache.transfer_rows, &cache.transfers_by_target),
            |cache| (&mut cache.transfer_rows, &mut cache.transfers_by_target),
            |request, visitor| {
                self.typed_source.visit_type_transfer_pages_to_targets(
                    request,
                    self.cancellation,
                    visitor,
                )
            },
            |row, _, _| Some(vec![row.row().rule().target_slot()]),
            SelectedTypedRow::<LoweredTypeTransfer>::natural_identity,
            ObservedFactRelation::Secondary,
            |row, _, _| {
                Some(vec![
                    ObservedFactRelation::Primary(row.row().source_slot()),
                    ObservedFactRelation::Secondary(row.row().rule().target_slot()),
                ])
            },
            observe_transfer_evidence,
            clone_session_transfer,
            transfer_session_rows_equal,
        )
    }

    fn intrinsics_for_slots(
        &mut self,
        slots: &[SemanticId],
    ) -> StoreResult<SessionFactRead<SelectedTypedRow<LoweredIntrinsicSeed>>> {
        self.read_keyed_rows(
            slots,
            |cache| (&cache.intrinsic_rows, &cache.intrinsics_by_slot),
            |cache| (&mut cache.intrinsic_rows, &mut cache.intrinsics_by_slot),
            |request, visitor| {
                self.typed_source.visit_intrinsic_seed_pages_for_slots(
                    request,
                    self.cancellation,
                    visitor,
                )
            },
            |row, _, _| Some(vec![row.row().frontier().slot()]),
            SelectedTypedRow::<LoweredIntrinsicSeed>::natural_identity,
            ObservedFactRelation::Primary,
            intrinsic_observed_relations_with_poll,
            observe_intrinsic_evidence,
            clone_session_intrinsic,
            intrinsic_session_rows_equal,
        )
    }

    fn intrinsics_for_type_identities(
        &mut self,
        type_identities: &[SemanticId],
    ) -> StoreResult<SessionFactRead<SelectedTypedRow<LoweredIntrinsicSeed>>> {
        self.read_keyed_rows(
            type_identities,
            |cache| (&cache.intrinsic_rows, &cache.intrinsics_by_type_identity),
            |cache| {
                (
                    &mut cache.intrinsic_rows,
                    &mut cache.intrinsics_by_type_identity,
                )
            },
            |request, visitor| {
                self.typed_source
                    .visit_intrinsic_seed_pages_for_type_identities(
                        request,
                        self.cancellation,
                        visitor,
                    )
            },
            intrinsic_type_identities_with_poll,
            SelectedTypedRow::<LoweredIntrinsicSeed>::natural_identity,
            ObservedFactRelation::Secondary,
            intrinsic_observed_relations_with_poll,
            observe_intrinsic_evidence,
            clone_session_intrinsic,
            intrinsic_session_rows_equal,
        )
    }

    fn frontier_completions(
        &mut self,
        frontiers: &[SemanticId],
    ) -> StoreResult<SessionFactRead<SelectedTypeFrontierCompletion>> {
        self.read_keyed_rows(
            frontiers,
            |cache| (&cache.frontier_completion_rows, &cache.frontier_completions),
            |cache| {
                (
                    &mut cache.frontier_completion_rows,
                    &mut cache.frontier_completions,
                )
            },
            |request, visitor| {
                self.typed_source.visit_type_frontier_completion_pages(
                    request,
                    self.cancellation,
                    visitor,
                )
            },
            |row, _, _| Some(vec![row.frontier()]),
            SelectedTypeFrontierCompletion::natural_identity,
            ObservedFactRelation::Primary,
            |row, _, _| Some(vec![ObservedFactRelation::Primary(row.frontier())]),
            observe_frontier_completion_evidence,
            clone_session_frontier_completion,
            frontier_completion_session_rows_equal,
        )
    }

    fn declaration_types_for_definitions(
        &mut self,
        definitions: &[SemanticId],
    ) -> StoreResult<SessionFactRead<SelectedTypedRow<LoweredDeclarationTypeProperty>>> {
        self.read_keyed_rows(
            definitions,
            |cache| {
                (
                    &cache.declaration_type_rows,
                    &cache.declaration_types_by_definition,
                )
            },
            |cache| {
                (
                    &mut cache.declaration_type_rows,
                    &mut cache.declaration_types_by_definition,
                )
            },
            |request, visitor| {
                self.typed_source
                    .visit_declaration_type_pages_for_definitions(
                        request,
                        self.cancellation,
                        visitor,
                    )
            },
            |row, _, _| Some(vec![row.row().definition()]),
            SelectedTypedRow::<LoweredDeclarationTypeProperty>::natural_identity,
            ObservedFactRelation::Primary,
            |row, _, _| {
                Some(vec![
                    ObservedFactRelation::Primary(row.row().definition()),
                    ObservedFactRelation::Secondary(row.row().slot()),
                ])
            },
            observe_no_session_row_evidence,
            clone_selected_copy_session_row,
            copy_session_rows_equal,
        )
    }

    fn declaration_visibilities_for_definitions(
        &mut self,
        definitions: &[SemanticId],
    ) -> StoreResult<SessionFactRead<SelectedTypedRow<LoweredDeclarationVisibilityProperty>>> {
        self.read_keyed_rows(
            definitions,
            |cache| {
                (
                    &cache.declaration_visibility_rows,
                    &cache.declaration_visibilities_by_definition,
                )
            },
            |cache| {
                (
                    &mut cache.declaration_visibility_rows,
                    &mut cache.declaration_visibilities_by_definition,
                )
            },
            |request, visitor| {
                self.typed_source
                    .visit_declaration_visibility_pages_for_definitions(
                        request,
                        self.cancellation,
                        visitor,
                    )
            },
            |row, _, _| Some(vec![row.row().definition()]),
            SelectedTypedRow::<LoweredDeclarationVisibilityProperty>::natural_identity,
            ObservedFactRelation::Primary,
            |row, _, _| Some(vec![ObservedFactRelation::Primary(row.row().definition())]),
            observe_no_session_row_evidence,
            clone_selected_copy_session_row,
            copy_session_rows_equal,
        )
    }

    fn member_scopes_for_definitions(
        &mut self,
        definitions: &[SemanticId],
    ) -> StoreResult<SessionFactRead<SelectedTypedRow<LoweredMemberScopeProperty>>> {
        self.read_keyed_rows(
            definitions,
            |cache| (&cache.member_scope_rows, &cache.member_scopes_by_definition),
            |cache| {
                (
                    &mut cache.member_scope_rows,
                    &mut cache.member_scopes_by_definition,
                )
            },
            |request, visitor| {
                self.typed_source.visit_member_scope_pages_for_definitions(
                    request,
                    self.cancellation,
                    visitor,
                )
            },
            |row, _, _| Some(vec![row.row().definition()]),
            SelectedTypedRow::<LoweredMemberScopeProperty>::natural_identity,
            ObservedFactRelation::Primary,
            member_scope_observed_relations,
            observe_no_session_row_evidence,
            clone_selected_copy_session_row,
            copy_session_rows_equal,
        )
    }

    fn member_owners_for_definitions(
        &mut self,
        definitions: &[SemanticId],
    ) -> StoreResult<SessionFactRead<SelectedTypedRow<LoweredMemberOwnerProperty>>> {
        self.read_keyed_rows(
            definitions,
            |cache| (&cache.member_owner_rows, &cache.member_owners_by_definition),
            |cache| {
                (
                    &mut cache.member_owner_rows,
                    &mut cache.member_owners_by_definition,
                )
            },
            |request, visitor| {
                self.typed_source.visit_member_owner_pages_for_definitions(
                    request,
                    self.cancellation,
                    visitor,
                )
            },
            |row, _, _| Some(vec![row.row().definition()]),
            SelectedTypedRow::<LoweredMemberOwnerProperty>::natural_identity,
            ObservedFactRelation::Primary,
            |row, _, _| {
                Some(vec![
                    ObservedFactRelation::Primary(row.row().definition()),
                    ObservedFactRelation::Secondary(row.row().owner_definition()),
                ])
            },
            observe_no_session_row_evidence,
            clone_selected_copy_session_row,
            copy_session_rows_equal,
        )
    }

    fn construction_requirements_for_definitions(
        &mut self,
        definitions: &[SemanticId],
    ) -> StoreResult<SessionFactRead<SelectedTypedRow<LoweredConstructionRequirementProperty>>>
    {
        self.read_keyed_rows(
            definitions,
            |cache| {
                (
                    &cache.construction_requirement_rows,
                    &cache.construction_requirements_by_definition,
                )
            },
            |cache| {
                (
                    &mut cache.construction_requirement_rows,
                    &mut cache.construction_requirements_by_definition,
                )
            },
            |request, visitor| {
                self.typed_source
                    .visit_construction_requirement_pages_for_definitions(
                        request,
                        self.cancellation,
                        visitor,
                    )
            },
            |row, _, _| Some(vec![row.row().definition()]),
            SelectedTypedRow::<LoweredConstructionRequirementProperty>::natural_identity,
            ObservedFactRelation::Primary,
            |row, _, _| Some(vec![ObservedFactRelation::Primary(row.row().definition())]),
            observe_no_session_row_evidence,
            clone_selected_copy_session_row,
            copy_session_rows_equal,
        )
    }

    fn supertypes_for_definitions(
        &mut self,
        definitions: &[SemanticId],
    ) -> StoreResult<SessionFactRead<SelectedTypedRow<LoweredSupertypeProperty>>> {
        self.read_keyed_rows(
            definitions,
            |cache| (&cache.supertype_rows, &cache.supertypes_by_definition),
            |cache| {
                (
                    &mut cache.supertype_rows,
                    &mut cache.supertypes_by_definition,
                )
            },
            |request, visitor| {
                self.typed_source.visit_supertype_pages_for_definitions(
                    request,
                    self.cancellation,
                    visitor,
                )
            },
            |row, _, _| Some(vec![row.row().definition()]),
            SelectedTypedRow::<LoweredSupertypeProperty>::natural_identity,
            ObservedFactRelation::Primary,
            supertype_observed_relations,
            observe_no_session_row_evidence,
            clone_selected_copy_session_row,
            copy_session_rows_equal,
        )
    }

    fn property_gaps_for_definitions(
        &mut self,
        definitions: &[SemanticId],
    ) -> StoreResult<SessionFactRead<SelectedTypedRow<LoweredDefinitionPropertyGap>>> {
        self.read_keyed_rows(
            definitions,
            |cache| (&cache.property_gap_rows, &cache.property_gaps_by_definition),
            |cache| {
                (
                    &mut cache.property_gap_rows,
                    &mut cache.property_gaps_by_definition,
                )
            },
            |request, visitor| {
                self.typed_source
                    .visit_definition_property_gap_pages_for_definitions(
                        request,
                        self.cancellation,
                        visitor,
                    )
            },
            |row, _, _| Some(vec![row.row().definition()]),
            SelectedTypedRow::<LoweredDefinitionPropertyGap>::natural_identity,
            ObservedFactRelation::Primary,
            |row, _, _| Some(vec![ObservedFactRelation::Primary(row.row().definition())]),
            observe_property_gap_evidence,
            clone_selected_copy_session_row,
            copy_session_rows_equal,
        )
    }

    fn calls_for_references(
        &mut self,
        references: &[SemanticId],
    ) -> StoreResult<SessionFactRead<SelectedTypedRow<LoweredCallApplicabilityObligation>>> {
        self.read_keyed_rows(
            references,
            |cache| (&cache.call_rows, &cache.calls_by_reference),
            |cache| (&mut cache.call_rows, &mut cache.calls_by_reference),
            |request, visitor| {
                self.typed_source
                    .visit_call_applicability_pages_for_callee_references(
                        request,
                        self.cancellation,
                        visitor,
                    )
            },
            |row, _, _| Some(vec![row.row().callee_reference()]),
            SelectedTypedRow::<LoweredCallApplicabilityObligation>::natural_identity,
            ObservedFactRelation::Primary,
            |row, _, _| {
                Some(vec![ObservedFactRelation::Primary(
                    row.row().callee_reference(),
                )])
            },
            observe_call_evidence,
            clone_session_call,
            call_session_rows_equal,
        )
    }

    fn signatures_for_definitions(
        &mut self,
        definitions: &[SemanticId],
    ) -> StoreResult<SessionFactRead<SelectedTypedRow<LoweredCallableSignatureProperty>>> {
        self.read_keyed_rows(
            definitions,
            |cache| (&cache.signature_rows, &cache.signatures_by_definition),
            |cache| {
                (
                    &mut cache.signature_rows,
                    &mut cache.signatures_by_definition,
                )
            },
            |request, visitor| {
                self.typed_source
                    .visit_callable_signature_pages_for_definitions(
                        request,
                        self.cancellation,
                        visitor,
                    )
            },
            |row, _, _| Some(vec![row.row().definition()]),
            SelectedTypedRow::<LoweredCallableSignatureProperty>::natural_identity,
            ObservedFactRelation::Primary,
            |row, _, _| Some(vec![ObservedFactRelation::Primary(row.row().definition())]),
            observe_signature_evidence,
            clone_session_signature,
            signature_session_rows_equal,
        )
    }
}

enum SessionFactRead<R> {
    Exhausted {
        rows: Vec<InternedFactRow<R>>,
        evidence: ResolutionCompletion,
    },
    Cancelled(ResolutionCompletion),
}

fn observe_no_session_row_evidence<R>(
    _row: &R,
    evidence: &mut CancellationEvidenceLedger,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> bool {
    evidence.observe_row(cancellation, work)
}

fn observe_session_completion(
    completion: &ResolutionCompletion,
    evidence: &mut CancellationEvidenceLedger,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> bool {
    evidence.include(completion, cancellation, work)
}

fn observe_transfer_evidence(
    row: &SelectedTypedRow<LoweredTypeTransfer>,
    evidence: &mut CancellationEvidenceLedger,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> bool {
    observe_session_completion(row.row().rule().completion(), evidence, cancellation, work)
}

fn observe_intrinsic_evidence(
    row: &SelectedTypedRow<LoweredIntrinsicSeed>,
    evidence: &mut CancellationEvidenceLedger,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> bool {
    observe_session_completion(
        row.row().frontier().completion(),
        evidence,
        cancellation,
        work,
    )
}

fn intrinsic_type_identities_with_poll(
    row: &SelectedTypedRow<LoweredIntrinsicSeed>,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<Vec<SemanticId>> {
    let mut identities = BTreeSet::new();
    for value in row.row().frontier().possible_values() {
        if poll_cancelled(cancellation, work) {
            return None;
        }
        identities.insert(value.ty().identity());
    }
    let mut canonical = Vec::new();
    for identity in identities {
        if poll_cancelled(cancellation, work) {
            return None;
        }
        canonical.push(identity);
    }
    Some(canonical)
}

fn intrinsic_observed_relations_with_poll(
    row: &SelectedTypedRow<LoweredIntrinsicSeed>,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<Vec<ObservedFactRelation>> {
    let identities = intrinsic_type_identities_with_poll(row, cancellation, work)?;
    let mut relations = Vec::new();
    relations.push(ObservedFactRelation::Primary(row.row().frontier().slot()));
    for identity in identities {
        if poll_cancelled(cancellation, work) {
            return None;
        }
        relations.push(ObservedFactRelation::Secondary(identity));
    }
    Some(relations)
}

fn qualified_route_observed_relations(
    row: &SourceSelectedQualifiedRoute,
    _cancellation: &CancellationToken,
    _work: &mut usize,
) -> Option<Vec<ObservedFactRelation>> {
    Some(vec![
        ObservedFactRelation::Primary(row.row().reference()),
        ObservedFactRelation::Composite(QualifiedRouteSlotLookup::new(
            row.row().qualifier_slot(),
            row.row().lookup(),
        )),
        ObservedFactRelation::Secondary(row.row().qualifier_slot()),
        ObservedFactRelation::Tertiary(row.row().lookup()),
        ObservedFactRelation::Quaternary(row.row().coarse_gap_reason()),
        ObservedFactRelation::Inventory,
    ])
}

fn member_scope_observed_relations(
    row: &SelectedTypedRow<LoweredMemberScopeProperty>,
    _cancellation: &CancellationToken,
    _work: &mut usize,
) -> Option<Vec<ObservedFactRelation>> {
    Some(vec![
        ObservedFactRelation::Primary(row.row().definition()),
        ObservedFactRelation::Node(row.row().scope_head()),
        ObservedFactRelation::Inventory,
    ])
}

fn supertype_observed_relations(
    row: &SelectedTypedRow<LoweredSupertypeProperty>,
    _cancellation: &CancellationToken,
    _work: &mut usize,
) -> Option<Vec<ObservedFactRelation>> {
    Some(vec![
        ObservedFactRelation::Primary(row.row().definition()),
        ObservedFactRelation::Secondary(row.row().reference()),
        ObservedFactRelation::Tertiary(row.row().frontier()),
    ])
}

fn observe_frontier_completion_evidence(
    row: &SelectedTypeFrontierCompletion,
    evidence: &mut CancellationEvidenceLedger,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> bool {
    observe_session_completion(row.completion(), evidence, cancellation, work)
}

fn observe_route_evidence(
    row: &SourceSelectedQualifiedRoute,
    evidence: &mut CancellationEvidenceLedger,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> bool {
    evidence.include_reason(ResolutionIncompleteReason::UnsupportedSemantic(
        row.row().coarse_gap_reason(),
    ));
    evidence.observe_row(cancellation, work)
}

fn observe_property_gap_evidence(
    row: &SelectedTypedRow<LoweredDefinitionPropertyGap>,
    evidence: &mut CancellationEvidenceLedger,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> bool {
    evidence.include_reason(ResolutionIncompleteReason::UnsupportedSemantic(
        row.row().reason_semantic(),
    ));
    evidence.observe_row(cancellation, work)
}

fn observe_call_evidence(
    row: &SelectedTypedRow<LoweredCallApplicabilityObligation>,
    evidence: &mut CancellationEvidenceLedger,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> bool {
    observe_session_completion(row.row().completion(), evidence, cancellation, work)
}

fn observe_signature_evidence(
    row: &SelectedTypedRow<LoweredCallableSignatureProperty>,
    evidence: &mut CancellationEvidenceLedger,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> bool {
    observe_session_completion(row.row().completion(), evidence, cancellation, work)
}

fn clone_copy_session_row<R: Copy>(
    row: &R,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<R> {
    (!poll_cancelled(cancellation, work)).then_some(*row)
}

fn clone_selected_copy_session_row<R: Copy>(
    row: &SelectedTypedRow<R>,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<SelectedTypedRow<R>> {
    (!poll_cancelled(cancellation, work)).then(|| SelectedTypedRow::new(row.fragment(), *row.row()))
}

fn clone_session_transfer(
    row: &SelectedTypedRow<LoweredTypeTransfer>,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<SelectedTypedRow<LoweredTypeTransfer>> {
    let fragment = row.fragment();
    let mut cancelled = || poll_cancelled(cancellation, work);
    clone_type_transfer_with_poll(row.row(), &mut cancelled)
        .map(|row| SelectedTypedRow::new(fragment, row))
}

fn clone_session_intrinsic(
    row: &SelectedTypedRow<LoweredIntrinsicSeed>,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<SelectedTypedRow<LoweredIntrinsicSeed>> {
    let fragment = row.fragment();
    let mut cancelled = || poll_cancelled(cancellation, work);
    clone_intrinsic_seed_with_poll(row.row(), &mut cancelled)
        .map(|row| SelectedTypedRow::new(fragment, row))
}

fn clone_session_frontier_completion(
    row: &SelectedTypeFrontierCompletion,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<SelectedTypeFrontierCompletion> {
    let fragment = row.fragment();
    let frontier = row.frontier();
    let mut cancelled = || poll_cancelled(cancellation, work);
    clone_resolution_completion_with_poll(row.completion(), &mut cancelled)
        .map(|completion| SelectedTypeFrontierCompletion::new(fragment, frontier, completion))
}

fn clone_session_call(
    row: &SelectedTypedRow<LoweredCallApplicabilityObligation>,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<SelectedTypedRow<LoweredCallApplicabilityObligation>> {
    let fragment = row.fragment();
    let mut cancelled = || poll_cancelled(cancellation, work);
    clone_call_obligation_with_poll(row.row(), &mut cancelled)
        .map(|row| SelectedTypedRow::new(fragment, row))
}

fn clone_session_signature(
    row: &SelectedTypedRow<LoweredCallableSignatureProperty>,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<SelectedTypedRow<LoweredCallableSignatureProperty>> {
    let fragment = row.fragment();
    let mut cancelled = || poll_cancelled(cancellation, work);
    row.row()
        .clone_with_poll(&mut cancelled)
        .map(|row| SelectedTypedRow::new(fragment, row))
}

fn copy_session_rows_equal<R: PartialEq>(
    left: &R,
    right: &R,
    cancelled: &mut dyn FnMut() -> bool,
) -> Option<bool> {
    (!cancelled()).then(|| left == right)
}

fn transfer_session_rows_equal(
    left: &SelectedTypedRow<LoweredTypeTransfer>,
    right: &SelectedTypedRow<LoweredTypeTransfer>,
    cancelled: &mut dyn FnMut() -> bool,
) -> Option<bool> {
    if cancelled() {
        return None;
    }
    let left_rule = left.row().rule();
    let right_rule = right.row().rule();
    if left.fragment() != right.fragment()
        || left.row().source_slot() != right.row().source_slot()
        || left.row().kind() != right.row().kind()
        || left_rule.semantic() != right_rule.semantic()
        || left_rule.target_slot() != right_rule.target_slot()
        || left_rule.indirection_delta() != right_rule.indirection_delta()
        || left_rule.value_transform() != right_rule.value_transform()
    {
        return Some(false);
    }
    completions_equal_with_poll(left_rule.completion(), right_rule.completion(), cancelled)
}

fn intrinsic_session_rows_equal(
    left: &SelectedTypedRow<LoweredIntrinsicSeed>,
    right: &SelectedTypedRow<LoweredIntrinsicSeed>,
    cancelled: &mut dyn FnMut() -> bool,
) -> Option<bool> {
    if cancelled() {
        return None;
    }
    if left.fragment() != right.fragment()
        || left.row().kind() != right.row().kind()
        || left.row().frontier().slot() != right.row().frontier().slot()
        || left.row().frontier().possible_values().len()
            != right.row().frontier().possible_values().len()
    {
        return Some(false);
    }
    for (left, right) in left
        .row()
        .frontier()
        .possible_values()
        .iter()
        .zip(right.row().frontier().possible_values())
    {
        if cancelled() {
            return None;
        }
        if left != right {
            return Some(false);
        }
    }
    completions_equal_with_poll(
        left.row().frontier().completion(),
        right.row().frontier().completion(),
        cancelled,
    )
}

fn frontier_completion_session_rows_equal(
    left: &SelectedTypeFrontierCompletion,
    right: &SelectedTypeFrontierCompletion,
    cancelled: &mut dyn FnMut() -> bool,
) -> Option<bool> {
    if cancelled() {
        return None;
    }
    if left.fragment() != right.fragment() || left.frontier() != right.frontier() {
        return Some(false);
    }
    completions_equal_with_poll(left.completion(), right.completion(), cancelled)
}

fn call_session_rows_equal(
    left: &SelectedTypedRow<LoweredCallApplicabilityObligation>,
    right: &SelectedTypedRow<LoweredCallApplicabilityObligation>,
    cancelled: &mut dyn FnMut() -> bool,
) -> Option<bool> {
    let left_row = left.row();
    let right_row = right.row();
    if cancelled() {
        return None;
    }
    if left.fragment() != right.fragment()
        || left_row.call() != right_row.call()
        || left_row.callee_reference() != right_row.callee_reference()
        || left_row.receiver_slot() != right_row.receiver_slot()
        || left_row.result_slot() != right_row.result_slot()
        || left_row.explicit_type_argument_count() != right_row.explicit_type_argument_count()
        || left_row.applicability_reason() != right_row.applicability_reason()
        || left_row.argument_slots().len() != right_row.argument_slots().len()
    {
        return Some(false);
    }
    for (&left, &right) in left_row
        .argument_slots()
        .iter()
        .zip(right_row.argument_slots())
    {
        if cancelled() {
            return None;
        }
        if left != right {
            return Some(false);
        }
    }
    completions_equal_with_poll(left_row.completion(), right_row.completion(), cancelled)
}

fn signature_session_rows_equal(
    left: &SelectedTypedRow<LoweredCallableSignatureProperty>,
    right: &SelectedTypedRow<LoweredCallableSignatureProperty>,
    cancelled: &mut dyn FnMut() -> bool,
) -> Option<bool> {
    let left_row = left.row();
    let right_row = right.row();
    if cancelled() {
        return None;
    }
    if left.fragment() != right.fragment()
        || left_row.definition() != right_row.definition()
        || left_row.type_parameter_count() != right_row.type_parameter_count()
        || left_row.parameters().len() != right_row.parameters().len()
    {
        return Some(false);
    }
    for (left, right) in left_row.parameters().iter().zip(right_row.parameters()) {
        if cancelled() {
            return None;
        }
        if left != right {
            return Some(false);
        }
    }
    completions_equal_with_poll(left_row.completion(), right_row.completion(), cancelled)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct HierarchyLookupShape {
    lookup: SemanticId,
    namespace: ResolutionNamespace,
    category: QualifierCategory,
    receiver_indirection: i64,
}

impl HierarchyLookupShape {
    const fn new(
        lookup: SemanticId,
        namespace: ResolutionNamespace,
        category: QualifierCategory,
        receiver_indirection: i64,
    ) -> Self {
        Self {
            lookup,
            namespace,
            category,
            receiver_indirection,
        }
    }

    const fn inherited_member_kind(self) -> Option<ResolutionMemberKind> {
        match self.namespace {
            ResolutionNamespace::Value => Some(ResolutionMemberKind::Field),
            ResolutionNamespace::Type => Some(ResolutionMemberKind::NestedType),
            ResolutionNamespace::Callable
            | ResolutionNamespace::Constructor
            | ResolutionNamespace::Macro
            | ResolutionNamespace::Constant
            | ResolutionNamespace::TypeOrValue => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct HierarchyNodeKey {
    shape: HierarchyLookupShape,
    owner: SemanticId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct HierarchyEvidenceAtom {
    identity: SemanticId,
    completion: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum HierarchyEvidenceExprNode {
    Atom(HierarchyEvidenceAtom),
    Shift { ticks: u32, child: usize },
    Union { left: usize, right: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HierarchyEvidence {
    Complete,
    One {
        tick: u32,
        atom: HierarchyEvidenceAtom,
    },
    Many(usize),
}

#[derive(Debug, Default)]
struct HierarchyEvidenceArena {
    completions: Vec<ResolutionCompletion>,
    completion_by_atom: HashMap<SemanticId, usize>,
    expressions: Vec<HierarchyEvidenceExprNode>,
    expression_ids: HashMap<HierarchyEvidenceExprNode, usize>,
}

impl HierarchyEvidenceArena {
    fn one(
        &mut self,
        identity: SemanticId,
        completion: ResolutionCompletion,
        cancelled: &mut dyn FnMut() -> bool,
    ) -> Option<HierarchyEvidence> {
        if matches!(completion, ResolutionCompletion::Complete) {
            return Some(HierarchyEvidence::Complete);
        }
        let completion_id = if let Some(&completion_id) = self.completion_by_atom.get(&identity) {
            if !completions_equal_with_poll(
                &self.completions[completion_id],
                &completion,
                cancelled,
            )? {
                panic!("one hierarchy evidence atom has conflicting exact completion boxes");
            }
            completion_id
        } else {
            let completion_id = self.completions.len();
            self.completions.push(completion);
            assert!(
                self.completion_by_atom
                    .insert(identity, completion_id)
                    .is_none(),
                "one hierarchy evidence atom owns one exact completion box"
            );
            completion_id
        };
        Some(HierarchyEvidence::One {
            tick: 0,
            atom: HierarchyEvidenceAtom {
                identity,
                completion: completion_id,
            },
        })
    }

    fn shift(&mut self, evidence: HierarchyEvidence, ticks: u32) -> HierarchyEvidence {
        if ticks == 0 {
            return evidence;
        }
        match evidence {
            HierarchyEvidence::Complete => HierarchyEvidence::Complete,
            HierarchyEvidence::One { tick, atom } => HierarchyEvidence::One {
                tick: tick
                    .checked_add(ticks)
                    .expect("hierarchy evidence tick must fit u32"),
                atom,
            },
            HierarchyEvidence::Many(child) => {
                let node =
                    self.intern_expression(HierarchyEvidenceExprNode::Shift { ticks, child });
                HierarchyEvidence::Many(node)
            }
        }
    }

    fn union(&mut self, left: HierarchyEvidence, right: HierarchyEvidence) -> HierarchyEvidence {
        match (left, right) {
            (HierarchyEvidence::Complete, evidence) | (evidence, HierarchyEvidence::Complete) => {
                evidence
            }
            (
                HierarchyEvidence::One {
                    tick: left_tick,
                    atom: left_atom,
                },
                HierarchyEvidence::One {
                    tick: right_tick,
                    atom: right_atom,
                },
            ) if left_atom.identity == right_atom.identity => {
                assert_eq!(
                    left_atom.completion, right_atom.completion,
                    "one hierarchy evidence atom has one exact completion box"
                );
                HierarchyEvidence::One {
                    tick: left_tick.min(right_tick),
                    atom: left_atom,
                }
            }
            (left, right) => {
                let left = self.union_child(left);
                let right = self.union_child(right);
                match (left, right) {
                    (None, None) => HierarchyEvidence::Complete,
                    (Some(child), None) | (None, Some(child)) => HierarchyEvidence::Many(child),
                    (Some(left), Some(right)) if left == right => HierarchyEvidence::Many(left),
                    (Some(left), Some(right)) => {
                        let (left, right) = if left < right {
                            (left, right)
                        } else {
                            (right, left)
                        };
                        HierarchyEvidence::Many(
                            self.intern_expression(HierarchyEvidenceExprNode::Union {
                                left,
                                right,
                            }),
                        )
                    }
                }
            }
        }
    }

    fn union_child(&mut self, evidence: HierarchyEvidence) -> Option<usize> {
        let child = match evidence {
            HierarchyEvidence::Complete => return None,
            HierarchyEvidence::One { tick, atom } => {
                let atom = self.intern_expression(HierarchyEvidenceExprNode::Atom(atom));
                if tick == 0 {
                    atom
                } else {
                    self.intern_expression(HierarchyEvidenceExprNode::Shift {
                        ticks: tick,
                        child: atom,
                    })
                }
            }
            HierarchyEvidence::Many(child) => child,
        };
        Some(child)
    }

    fn intern_expression(&mut self, node: HierarchyEvidenceExprNode) -> usize {
        if let Some(&id) = self.expression_ids.get(&node) {
            return id;
        }
        let id = self.expressions.len();
        self.expressions.push(node.clone());
        assert!(
            self.expression_ids.insert(node, id).is_none(),
            "one hierarchy evidence expression is interned once"
        );
        id
    }

    fn truncate(
        &mut self,
        evidence: &HierarchyEvidence,
        cutoff_tick: u32,
        cancelled: &mut dyn FnMut() -> bool,
    ) -> Option<HierarchyEvidence> {
        match evidence {
            HierarchyEvidence::Complete => return Some(HierarchyEvidence::Complete),
            HierarchyEvidence::One { tick, atom } => {
                return Some(if *tick <= cutoff_tick {
                    HierarchyEvidence::One {
                        tick: 0,
                        atom: *atom,
                    }
                } else {
                    HierarchyEvidence::Complete
                });
            }
            HierarchyEvidence::Many(_) => {}
        }
        let HierarchyEvidence::Many(root) = evidence else {
            unreachable!("complete and sole hierarchy evidence returned above")
        };
        let mut pending = BinaryHeap::from([Reverse((0_u32, *root))]);
        let mut minimum_shift_by_node = HashMap::<usize, u32>::default();
        let mut atoms = HashMap::<SemanticId, (u32, HierarchyEvidenceAtom)>::default();
        while let Some(Reverse((inherited_shift, node_id))) = pending.pop() {
            if inherited_shift > cutoff_tick {
                break;
            }
            if cancelled() {
                return None;
            }
            if minimum_shift_by_node
                .get(&node_id)
                .is_some_and(|&minimum| minimum <= inherited_shift)
            {
                continue;
            }
            minimum_shift_by_node.insert(node_id, inherited_shift);
            match self.expressions[node_id].clone() {
                HierarchyEvidenceExprNode::Atom(atom) => {
                    if let Some((tick, previous)) = atoms.get_mut(&atom.identity) {
                        assert_eq!(
                            previous.completion, atom.completion,
                            "one truncated hierarchy atom has one exact completion box"
                        );
                        *tick = (*tick).min(inherited_shift);
                    } else {
                        atoms.insert(atom.identity, (inherited_shift, atom));
                    }
                }
                HierarchyEvidenceExprNode::Shift { ticks, child } => {
                    let shifted = inherited_shift
                        .checked_add(ticks)
                        .expect("truncated hierarchy evidence tick must fit u32");
                    if shifted <= cutoff_tick {
                        pending.push(Reverse((shifted, child)));
                    }
                }
                HierarchyEvidenceExprNode::Union { left, right } => {
                    pending.push(Reverse((inherited_shift, left)));
                    pending.push(Reverse((inherited_shift, right)));
                }
            }
        }
        let mut ordered = BTreeMap::new();
        for (identity, (tick, atom)) in atoms.drain() {
            if cancelled() {
                return None;
            }
            if tick <= cutoff_tick {
                ordered.insert((tick, identity), atom);
            }
        }
        let mut truncated = HierarchyEvidence::Complete;
        while let Some((_, atom)) = ordered.pop_first() {
            if cancelled() {
                return None;
            }
            truncated = self.union(truncated, HierarchyEvidence::One { tick: 0, atom });
        }
        Some(truncated)
    }

    fn flatten(
        &self,
        evidence: &HierarchyEvidence,
        cutoff_tick: u32,
        cancelled: &mut dyn FnMut() -> bool,
    ) -> Option<ResolutionCompletion> {
        match evidence {
            HierarchyEvidence::Complete => return Some(ResolutionCompletion::Complete),
            HierarchyEvidence::One { tick, atom } if *tick <= cutoff_tick => {
                let mut poll = || cancelled();
                return clone_resolution_completion_with_poll(
                    &self.completions[atom.completion],
                    &mut poll,
                );
            }
            HierarchyEvidence::One { .. } => return Some(ResolutionCompletion::Complete),
            HierarchyEvidence::Many(_) => {}
        }

        let HierarchyEvidence::Many(root) = evidence else {
            unreachable!("complete and sole hierarchy evidence returned above")
        };
        let mut pending = BinaryHeap::from([Reverse((0_u32, *root))]);
        let mut minimum_shift_by_node = HashMap::<usize, u32>::default();
        let mut atoms = HashMap::<SemanticId, (u32, usize)>::default();
        while let Some(Reverse((inherited_shift, node))) = pending.pop() {
            if inherited_shift > cutoff_tick {
                break;
            }
            if cancelled() {
                return None;
            }
            if minimum_shift_by_node
                .get(&node)
                .is_some_and(|&minimum| minimum <= inherited_shift)
            {
                continue;
            }
            minimum_shift_by_node.insert(node, inherited_shift);
            match &self.expressions[node] {
                HierarchyEvidenceExprNode::Atom(atom) => {
                    if let Some((previous_tick, previous_completion)) =
                        atoms.get_mut(&atom.identity)
                    {
                        assert_eq!(
                            *previous_completion, atom.completion,
                            "one shifted hierarchy atom has one exact completion box"
                        );
                        *previous_tick = (*previous_tick).min(inherited_shift);
                    } else {
                        atoms.insert(atom.identity, (inherited_shift, atom.completion));
                    }
                }
                HierarchyEvidenceExprNode::Shift { ticks, child } => {
                    let shifted = inherited_shift
                        .checked_add(*ticks)
                        .expect("flattened hierarchy evidence tick must fit u32");
                    if shifted <= cutoff_tick {
                        pending.push(Reverse((shifted, *child)));
                    }
                }
                HierarchyEvidenceExprNode::Union { left, right } => {
                    pending.push(Reverse((inherited_shift, *left)));
                    pending.push(Reverse((inherited_shift, *right)));
                }
            }
        }
        let mut ordered_atoms = BTreeMap::new();
        for (identity, (tick, completion_id)) in atoms.drain() {
            if cancelled() {
                return None;
            }
            // Evidence after the structural cutoff was never inspected by the
            // lookup and cannot make its negative or selected layer less exact.
            if tick > cutoff_tick {
                continue;
            }
            assert!(
                ordered_atoms
                    .insert((tick, identity), completion_id)
                    .is_none(),
                "one hierarchy atom identity owns one minimum tick"
            );
        }
        if ordered_atoms.is_empty() {
            return Some(ResolutionCompletion::Complete);
        }
        if ordered_atoms.len() == 1 {
            let (_, completion_id) = ordered_atoms
                .pop_first()
                .expect("the one in-cutoff hierarchy evidence atom was just observed");
            let mut poll = || cancelled();
            return clone_resolution_completion_with_poll(
                &self.completions[completion_id],
                &mut poll,
            );
        }
        debug_assert!(ordered_atoms.len() >= 2);
        let mut reasons = BTreeSet::new();
        while let Some((_, completion_id)) = ordered_atoms.pop_first() {
            if cancelled() {
                return None;
            }
            let ResolutionCompletion::Incomplete(completion_reasons) =
                &self.completions[completion_id]
            else {
                unreachable!("complete boxes are neutral and never interned as evidence atoms")
            };
            for &reason in completion_reasons.iter() {
                if cancelled() {
                    return None;
                }
                reasons.insert(reason);
            }
        }
        assert!(
            !reasons.is_empty(),
            "combining multiple incomplete hierarchy operands must retain at least one reason"
        );
        let mut completion_reasons = Vec::with_capacity(reasons.len());
        while let Some(reason) = reasons.pop_first() {
            if cancelled() {
                return None;
            }
            completion_reasons.push(reason);
        }
        let completion_reasons = CompletionReasons::from(completion_reasons);
        Some(ResolutionCompletion::Incomplete(completion_reasons))
    }
}

#[derive(Debug, Clone)]
struct HierarchyLocalNode {
    direct_definitions: Box<[SemanticId]>,
    evidence: HierarchyEvidence,
    cutoff_evidence: HierarchyEvidence,
    transfer: HierarchyEvidence,
    // True only after this exact owner/shape had a lexical candidate request
    // in a fully exhausted batch. A missing member scope has no ownership of
    // the source-wide unconditional candidate-inventory operand.
    candidate_inventory_observed: bool,
}

#[derive(Debug)]
struct StagedHierarchyLocalNode {
    key: HierarchyNodeKey,
    scope_head: Option<BindingNodeId>,
    hierarchy_reasons: BTreeSet<SemanticId>,
    evidence: HierarchyEvidence,
    cutoff_evidence: HierarchyEvidence,
    transfer: HierarchyEvidence,
    direct_definitions: BTreeSet<SemanticId>,
}

#[derive(Debug, Clone)]
struct HierarchyEdge {
    reference: SemanticId,
    targets: Box<[SemanticId]>,
    residual_evidence: HierarchyEvidence,
    hierarchy_evidence: HierarchyEvidence,
    transfer: HierarchyEvidence,
}

#[derive(Debug, Clone)]
struct HierarchyEdgeNode {
    edges: Box<[HierarchyEdge]>,
    evidence: HierarchyEvidence,
}

#[derive(Debug, Clone)]
struct HierarchyStructuralSummary {
    candidate_distance: Option<u32>,
    candidates: Option<usize>,
    evidence: HierarchyEvidence,
    transfer: HierarchyEvidence,
    retains_global_evidence: bool,
}

#[derive(Debug, Clone)]
struct HierarchyLocalSnapshot {
    has_direct_definitions: bool,
    evidence: HierarchyEvidence,
    cutoff_evidence: HierarchyEvidence,
    transfer: HierarchyEvidence,
    candidate_inventory_observed: bool,
}

#[derive(Debug, Clone)]
struct HierarchyEdgeNodeSnapshot {
    edge_count: usize,
    evidence: HierarchyEvidence,
}

#[derive(Debug, Clone)]
struct HierarchyEdgeSnapshot {
    reference: SemanticId,
    target_count: usize,
    residual_evidence: HierarchyEvidence,
    hierarchy_evidence: HierarchyEvidence,
    transfer: HierarchyEvidence,
}

#[derive(Debug)]
enum ExactMemberOwnerMetadata {
    Missing,
    Conflicting,
    Unique(InternedFactRow<SelectedTypedRow<LoweredMemberOwnerProperty>>),
}

#[derive(Debug)]
struct HierarchyPublished<T> {
    // Source-sized publication is cooperatively polled. Rows staged under an
    // uncommitted generation are inert, so a cancelled loop cannot expose a
    // partial topology/summary cache; one O(log n) generation insert commits
    // the whole validated batch atomically.
    generation: u64,
    value: T,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct HierarchyDerivedWork {
    closure_owner_visits: usize,
    closure_arc_visits: usize,
    scc_owner_visits: usize,
    scc_arc_visits: usize,
    summary_owner_visits: usize,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct HierarchyMetadataWork {
    row_visits: usize,
    definition_classifications: usize,
    match_checks: usize,
    replay_step_copies: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum HierarchyCandidateExprNode {
    Here(SemanticId),
    Via {
        reference: SemanticId,
        target: SemanticId,
        child: usize,
    },
    Union {
        left: usize,
        right: usize,
    },
}

#[derive(Debug, Default)]
struct HierarchyCandidateArena {
    nodes: Vec<HierarchyCandidateExprNode>,
    digests: Vec<SemanticId>,
    ids: HashMap<HierarchyCandidateExprNode, usize>,
}

impl HierarchyCandidateArena {
    fn intern(&mut self, node: HierarchyCandidateExprNode) -> usize {
        if let Some(&id) = self.ids.get(&node) {
            return id;
        }
        let id = self.nodes.len();
        let mut hasher = CanonicalHasher::new(b"bifrost-resolution-hierarchy-candidate-expr:v1");
        match node {
            HierarchyCandidateExprNode::Here(owner) => {
                hasher.field("kind", b"here");
                hasher.field("owner", &owner.as_bytes());
            }
            HierarchyCandidateExprNode::Via {
                reference,
                target,
                child,
            } => {
                hasher.field("kind", b"via");
                hasher.field("reference", &reference.as_bytes());
                hasher.field("target", &target.as_bytes());
                hasher.field("child", &self.digests[child].as_bytes());
            }
            HierarchyCandidateExprNode::Union { left, right } => {
                hasher.field("kind", b"union");
                hasher.field("left", &self.digests[left].as_bytes());
                hasher.field("right", &self.digests[right].as_bytes());
            }
        }
        self.nodes.push(node);
        self.digests.push(SemanticId::from_digest(hasher.finish()));
        self.ids.insert(node, id);
        id
    }

    fn here(&mut self, owner: SemanticId) -> usize {
        self.intern(HierarchyCandidateExprNode::Here(owner))
    }

    fn via(&mut self, reference: SemanticId, target: SemanticId, child: usize) -> usize {
        self.intern(HierarchyCandidateExprNode::Via {
            reference,
            target,
            child,
        })
    }

    fn union(&mut self, left: Option<usize>, right: Option<usize>) -> Option<usize> {
        match (left, right) {
            (None, other) | (other, None) => other,
            (Some(left), Some(right)) if left == right => Some(left),
            (Some(left), Some(right)) => {
                let (left, right) = if (self.digests[left], left) < (self.digests[right], right) {
                    (left, right)
                } else {
                    (right, left)
                };
                Some(self.intern(HierarchyCandidateExprNode::Union { left, right }))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct HierarchyRoot {
    owner: SemanticId,
    value: ResolutionSlotValue,
    route_ordinal: usize,
}

#[derive(Debug)]
struct HierarchySelectedOwner {
    owner: SemanticId,
    root: HierarchyRoot,
    ancestry: Box<[SemanticId]>,
}

#[derive(Debug)]
struct HierarchySelection {
    owners: Box<[HierarchySelectedOwner]>,
    evidence: HierarchyEvidence,
    transfer: HierarchyEvidence,
    retains_global_evidence: bool,
}

enum HierarchySelectionState {
    Pending,
    Ready(HierarchySelection),
}

#[derive(Debug)]
struct HierarchyOwnerSelection {
    candidates: Box<[HierarchySelectedCandidateExpression]>,
    evidence: HierarchyEvidence,
    // Forward point resolution owns the selected owner's local hierarchy
    // operand at the inclusive candidate cutoff.
    transfer: HierarchyEvidence,
    retains_global_evidence: bool,
}

#[derive(Debug, Clone, Copy)]
struct HierarchySelectedCandidateExpression {
    expression: usize,
    root: HierarchyRoot,
}

#[derive(Debug, Clone)]
struct SelectedQualifiedOrigin {
    identity: SemanticId,
    owner: SemanticId,
    route_ordinal: usize,
    value: ResolutionSlotValue,
    shape: HierarchyLookupShape,
    hierarchy_owned: bool,
    ancestry: Box<[SemanticId]>,
}

struct QualifiedOriginSelection {
    origins: Vec<SelectedQualifiedOrigin>,
    hierarchy_used: bool,
    hierarchy_evidence: HierarchyEvidence,
    hierarchy_retains_global_evidence: bool,
    transferred_hierarchy_reasons: BTreeSet<SemanticId>,
    observed_qualifier_slots: BTreeSet<SemanticId>,
    hierarchy_qualifier_slots: BTreeSet<SemanticId>,
    nonhierarchy_qualifier_slots: BTreeSet<SemanticId>,
}

struct QualifiedOwnerProperties {
    scopes: HashMap<SemanticId, BindingNodeId>,
    property_gaps: HashMap<SemanticId, Vec<(ResolutionGapKind, SemanticId)>>,
    declaration_visibilities: HashMap<SemanticId, DeclaredVisibility>,
    construction_owners: HashSet<SemanticId>,
}

struct QualifiedQualifierSelection {
    origin_selection: QualifiedOriginSelection,
    hierarchy_completions: HashMap<SemanticId, ResolutionCompletion>,
    completion: ResolutionCompletion,
}

#[derive(Debug, Clone)]
struct QualifiedReplayOrigin {
    identity: SemanticId,
    owner: SemanticId,
    value: ResolutionSlotValue,
    shape: HierarchyLookupShape,
    hierarchy_owned: bool,
    category: QualifierCategory,
    expected_kind: Option<ResolutionMemberKind>,
    qualifier_slot: SemanticId,
    precedence_ordinal: u32,
    origin_ordinal: usize,
    ancestry: Box<[SemanticId]>,
    scope_head: BindingNodeId,
}

struct QualifiedReplayPlan {
    alternatives: Vec<SeededPartialPath>,
    origins: Vec<QualifiedReplayOrigin>,
    groups: HashMap<SemanticId, Range<usize>>,
    hierarchy_qualifier_completions: HashMap<SemanticId, ResolutionCompletion>,
    transferred_hierarchy_reasons: BTreeSet<SemanticId>,
    hierarchy_completion: ResolutionCompletion,
    omitted_completion: ResolutionCompletion,
    origin_omission_completion: ResolutionCompletion,
    hierarchy_only: bool,
}

struct QualifiedReplayResult {
    targets: Vec<SemanticId>,
    witnesses: Vec<ResolutionWitness>,
    completion: ResolutionCompletion,
}

struct PreparedQualifiedAnswer {
    targets: Box<[SemanticId]>,
    witnesses: Box<[ResolutionWitness]>,
    completion: ResolutionCompletion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct HierarchyAncestryKey {
    parent: Option<usize>,
    reference: SemanticId,
}

#[derive(Debug, Clone, Copy)]
struct HierarchyAncestryNode {
    key: HierarchyAncestryKey,
    digest: SemanticId,
}

#[derive(Debug, Default)]
struct HierarchyOperationArena {
    local_nodes: HashMap<HierarchyNodeKey, HierarchyLocalNode>,
    edge_nodes: HashMap<SemanticId, HierarchyEdgeNode>,
    reference_answers: HashMap<SemanticId, ResolutionAnswer>,
    /// Unfiltered route-free reference atoms retained only to hash-cons the
    /// operation-level cancellation ledger. Edge semantics build their own
    /// exact residual after filtering the edge-owned transfer identities.
    reference_cancellation_evidence: HashMap<SemanticId, HierarchyEvidence>,
    member_owner_metadata: HashMap<SemanticId, ExactMemberOwnerMetadata>,
    summaries: BTreeMap<HierarchyNodeKey, HierarchyPublished<HierarchyStructuralSummary>>,
    closure_sealed_owners: BTreeMap<SemanticId, HierarchyPublished<()>>,
    cycle_by_owner: BTreeMap<SemanticId, HierarchyPublished<PartialPathId>>,
    committed_publications: BTreeSet<u64>,
    next_publication_generation: u64,
    derived_work: HierarchyDerivedWork,
    metadata_work: HierarchyMetadataWork,
    candidates: HierarchyCandidateArena,
    global_evidence: Option<HierarchyEvidence>,
    // Successful selection applies a structural cutoff, but cancellation is
    // atomic across the whole top-level operation. Preserve every fully
    // decoded hierarchy operand by its source identity so a later evaluation
    // that reuses cached state cannot lose evidence cut off by an earlier
    // successful answer. Cancellation itself is an additional incomplete
    // operand, so the public combination is necessarily canonical; retaining
    // the identity-deduplicated reason union here is therefore exact even when
    // a sole source box was noncanonical.
    cancellation_atom_ids: HashSet<SemanticId>,
    cancellation_support_completions: HashMap<SemanticId, ResolutionCompletion>,
    cancellation_reasons: CancellationReasonCollection,
    evidence: HierarchyEvidenceArena,
    transfers: HierarchyEvidenceArena,
    ancestry_nodes: Vec<HierarchyAncestryNode>,
    ancestry_ids: HashMap<HierarchyAncestryKey, usize>,
}

impl HierarchyOperationArena {
    fn local_snapshot(&self, key: HierarchyNodeKey) -> Option<HierarchyLocalSnapshot> {
        self.local_nodes
            .get(&key)
            .map(|node| HierarchyLocalSnapshot {
                has_direct_definitions: !node.direct_definitions.is_empty(),
                evidence: node.evidence.clone(),
                cutoff_evidence: node.cutoff_evidence.clone(),
                transfer: node.transfer.clone(),
                candidate_inventory_observed: node.candidate_inventory_observed,
            })
    }

    fn edge_node_snapshot(&self, owner: SemanticId) -> Option<HierarchyEdgeNodeSnapshot> {
        self.edge_nodes
            .get(&owner)
            .map(|node| HierarchyEdgeNodeSnapshot {
                edge_count: node.edges.len(),
                evidence: node.evidence.clone(),
            })
    }

    fn edge_snapshot(&self, owner: SemanticId, ordinal: usize) -> HierarchyEdgeSnapshot {
        let edge = &self
            .edge_nodes
            .get(&owner)
            .expect("a hierarchy edge owner is cached")
            .edges[ordinal];
        HierarchyEdgeSnapshot {
            reference: edge.reference,
            target_count: edge.targets.len(),
            residual_evidence: edge.residual_evidence.clone(),
            hierarchy_evidence: edge.hierarchy_evidence.clone(),
            transfer: edge.transfer.clone(),
        }
    }

    fn edge_target(&self, owner: SemanticId, edge: usize, target: usize) -> SemanticId {
        self.edge_nodes[&owner].edges[edge].targets[target]
    }

    fn begin_publication(&mut self) -> u64 {
        self.next_publication_generation = self
            .next_publication_generation
            .checked_add(1)
            .expect("hierarchy publication generation must fit u64");
        self.next_publication_generation
    }

    fn is_published(&self, generation: u64) -> bool {
        self.committed_publications.contains(&generation)
    }

    fn summary(&self, key: HierarchyNodeKey) -> Option<&HierarchyStructuralSummary> {
        let published = self.summaries.get(&key)?;
        self.is_published(published.generation)
            .then_some(&published.value)
    }

    fn contains_summary(&self, key: HierarchyNodeKey) -> bool {
        self.summary(key).is_some()
    }

    fn closure_contains(&self, owner: SemanticId) -> bool {
        self.closure_sealed_owners
            .get(&owner)
            .is_some_and(|published| self.is_published(published.generation))
    }

    fn cycle(&self, owner: SemanticId) -> Option<PartialPathId> {
        let published = self.cycle_by_owner.get(&owner)?;
        self.is_published(published.generation)
            .then_some(published.value)
    }

    fn stage_summary(
        &mut self,
        generation: u64,
        key: HierarchyNodeKey,
        summary: HierarchyStructuralSummary,
    ) {
        if let Some(previous) = self.summaries.get(&key) {
            assert!(
                !self.is_published(previous.generation),
                "one immutable hierarchy structural summary is published once"
            );
        }
        self.summaries.insert(
            key,
            HierarchyPublished {
                generation,
                value: summary,
            },
        );
    }

    fn stage_closure_owner(&mut self, generation: u64, owner: SemanticId) {
        if let Some(previous) = self.closure_sealed_owners.get(&owner) {
            assert!(
                !self.is_published(previous.generation),
                "one hierarchy owner closure is published once"
            );
        }
        self.closure_sealed_owners.insert(
            owner,
            HierarchyPublished {
                generation,
                value: (),
            },
        );
    }

    fn stage_cycle(&mut self, generation: u64, owner: SemanticId, cycle: PartialPathId) {
        if let Some(previous) = self.cycle_by_owner.get(&owner) {
            assert!(
                !self.is_published(previous.generation),
                "one newly sealed hierarchy owner belongs to one maximal SCC"
            );
        }
        self.cycle_by_owner.insert(
            owner,
            HierarchyPublished {
                generation,
                value: cycle,
            },
        );
    }

    fn commit_publication(&mut self, generation: u64) {
        assert!(
            self.committed_publications.insert(generation),
            "one hierarchy publication generation commits once"
        );
    }

    fn extend_ancestry(&mut self, parent: Option<usize>, reference: SemanticId) -> usize {
        let key = HierarchyAncestryKey { parent, reference };
        if let Some(&id) = self.ancestry_ids.get(&key) {
            return id;
        }
        let mut hasher = CanonicalHasher::new(b"bifrost-resolution-hierarchy-ancestry:v1");
        if let Some(parent) = parent {
            hasher.field("parent", &self.ancestry_nodes[parent].digest.as_bytes());
        }
        hasher.field("reference", &reference.as_bytes());
        let node = HierarchyAncestryNode {
            key,
            digest: SemanticId::from_digest(hasher.finish()),
        };
        let id = self.ancestry_nodes.len();
        self.ancestry_nodes.push(node);
        assert!(
            self.ancestry_ids.insert(key, id).is_none(),
            "one hierarchy ancestry head is interned once"
        );
        id
    }

    fn ancestry_references(
        &self,
        mut head: Option<usize>,
        cancelled: &mut dyn FnMut() -> bool,
    ) -> Option<Vec<SemanticId>> {
        let mut reversed_references = Vec::new();
        while let Some(id) = head {
            if cancelled() {
                return None;
            }
            let node = self.ancestry_nodes[id];
            reversed_references.push(node.key.reference);
            head = node.key.parent;
        }
        let mut left = 0_usize;
        let mut right = reversed_references.len();
        while left < right {
            if cancelled() {
                return None;
            }
            right -= 1;
            if left >= right {
                break;
            }
            reversed_references.swap(left, right);
            left += 1;
        }
        Some(reversed_references)
    }

    fn candidate_routes(
        &mut self,
        root: Option<usize>,
        cancelled: &mut dyn FnMut() -> bool,
    ) -> Option<Vec<(SemanticId, Box<[SemanticId]>)>> {
        let Some(root) = root else {
            return Some(Vec::new());
        };
        let mut pending = vec![(root, None)];
        let mut visited = HashSet::default();
        let mut selected = BTreeMap::<SemanticId, Option<usize>>::new();
        while let Some((node_id, ancestry)) = pending.pop() {
            if cancelled() {
                return None;
            }
            if !visited.insert(node_id) {
                continue;
            }
            match self.candidates.nodes[node_id] {
                HierarchyCandidateExprNode::Here(owner) => {
                    selected.entry(owner).or_insert(ancestry);
                }
                HierarchyCandidateExprNode::Via {
                    reference,
                    target: _,
                    child,
                } => {
                    let ancestry = Some(self.extend_ancestry(ancestry, reference));
                    pending.push((child, ancestry));
                }
                HierarchyCandidateExprNode::Union { left, right } => {
                    let (first, second) = if (self.candidates.digests[left], left)
                        < (self.candidates.digests[right], right)
                    {
                        (left, right)
                    } else {
                        (right, left)
                    };
                    pending.push((second, ancestry));
                    pending.push((first, ancestry));
                }
            }
        }
        let mut routes = Vec::with_capacity(selected.len());
        while let Some((owner, ancestry)) = selected.pop_first() {
            if cancelled() {
                return None;
            }
            let references = self.ancestry_references(ancestry, cancelled)?;
            routes.push((owner, references.into_boxed_slice()));
        }
        Some(routes)
    }
}

fn clone_type_transfer_with_poll(
    row: &LoweredTypeTransfer,
    cancelled: &mut dyn FnMut() -> bool,
) -> Option<LoweredTypeTransfer> {
    let rule = row.rule();
    let completion = {
        let mut poll = || cancelled();
        clone_resolution_completion_with_poll(rule.completion(), &mut poll)?
    };
    Some(LoweredTypeTransfer::new(
        row.source_slot(),
        row.kind(),
        TypeTransferRule::new(
            rule.semantic(),
            rule.target_slot(),
            rule.indirection_delta(),
            rule.value_transform(),
            completion,
        ),
    ))
}

fn clone_intrinsic_seed_with_poll(
    row: &LoweredIntrinsicSeed,
    cancelled: &mut dyn FnMut() -> bool,
) -> Option<LoweredIntrinsicSeed> {
    let frontier = row.frontier();
    if cancelled() {
        return None;
    }
    let mut values = Vec::with_capacity(frontier.possible_values().len());
    for &value in frontier.possible_values() {
        if cancelled() {
            return None;
        }
        values.push(value);
    }
    let completion = {
        let mut poll = || cancelled();
        clone_resolution_completion_with_poll(frontier.completion(), &mut poll)?
    };
    Some(LoweredIntrinsicSeed::new(
        row.kind(),
        TypedFrontierState::from_canonical_parts(
            frontier.slot(),
            values.into_boxed_slice(),
            completion,
            cancelled,
        )?,
    ))
}

fn clone_call_obligation_with_poll(
    row: &LoweredCallApplicabilityObligation,
    cancelled: &mut dyn FnMut() -> bool,
) -> Option<LoweredCallApplicabilityObligation> {
    if cancelled() {
        return None;
    }
    let mut arguments = Vec::with_capacity(row.argument_slots().len());
    for &argument in row.argument_slots() {
        if cancelled() {
            return None;
        }
        arguments.push(argument);
    }
    let mut eligible_rules = Vec::with_capacity(row.eligible_rules().len());
    for &rule in row.eligible_rules() {
        if cancelled() {
            return None;
        }
        eligible_rules.push(rule);
    }
    let completion = {
        let mut poll = || cancelled();
        clone_resolution_completion_with_poll(row.completion(), &mut poll)?
    };
    Some(LoweredCallApplicabilityObligation::new(
        row.call(),
        row.callee_reference(),
        row.receiver_slot(),
        row.result_slot(),
        arguments,
        eligible_rules,
        row.explicit_type_argument_count(),
        row.applicability_reason(),
        completion,
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Demand {
    Reference(SemanticId),
    Slot(SemanticId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallCandidateApplicability {
    ProvenApplicable,
    ArityMismatch,
    Unresolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum QualifierCategory {
    Type,
    Runtime,
}

impl QualifierCategory {
    const fn of(value: ResolutionSlotValue) -> Self {
        match value {
            ResolutionSlotValue::TypeObject(_) => Self::Type,
            ResolutionSlotValue::Runtime { .. } => Self::Runtime,
        }
    }
}

type SelectedTransferGroups<T> = HashMap<SemanticId, (BindingFragmentId, Vec<T>)>;
type SelectedFrontierCompletions<T> = HashMap<SemanticId, T>;
type SelectedTransferGrouping<T, C> = (SelectedTransferGroups<T>, SelectedFrontierCompletions<C>);
type InternedSelectedTransferGrouping = SelectedTransferGrouping<
    InternedFactRow<SelectedTypedRow<LoweredTypeTransfer>>,
    InternedFactRow<SelectedTypeFrontierCompletion>,
>;

fn group_selected_transfer_sources(
    session: &FactReadSession<'_>,
    transfer_rows: Vec<InternedFactRow<SelectedTypedRow<LoweredTypeTransfer>>>,
    completion_rows: Vec<InternedFactRow<SelectedTypeFrontierCompletion>>,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> StoreResult<Option<InternedSelectedTransferGrouping>> {
    group_selected_transfer_sources_by(
        transfer_rows,
        completion_rows,
        |transfer| {
            let transfer = transfer.get(session);
            (transfer.row().source_slot(), transfer.fragment())
        },
        |completion| {
            let completion = completion.get(session);
            (completion.frontier(), completion.fragment())
        },
        cancellation,
        work,
    )
}

fn group_selected_transfer_sources_by<T, C>(
    transfer_rows: Vec<T>,
    completion_rows: Vec<C>,
    transfer_metadata: impl Fn(&T) -> (SemanticId, BindingFragmentId),
    completion_metadata: impl Fn(&C) -> (SemanticId, BindingFragmentId),
    cancellation: &CancellationToken,
    work: &mut usize,
) -> StoreResult<Option<SelectedTransferGrouping<T, C>>> {
    let mut transfers_by_source = SelectedTransferGroups::default();
    for transfer in transfer_rows {
        if poll_cancelled(cancellation, work) {
            return Ok(None);
        }
        let (source, fragment) = transfer_metadata(&transfer);
        let (owner, rows) = transfers_by_source
            .entry(source)
            .or_insert_with(|| (fragment, Vec::new()));
        if *owner != fragment {
            return Err(StoreError::new(format!(
                "selected transfer source {source} has conflicting fragment owners {owner:?} and {fragment:?}"
            )));
        }
        rows.push(transfer);
    }

    let mut frontier_completions = SelectedFrontierCompletions::default();
    let mut completion_fragments = HashMap::default();
    for completion in completion_rows {
        if poll_cancelled(cancellation, work) {
            return Ok(None);
        }
        let (frontier, fragment) = completion_metadata(&completion);
        if let Some(previous) = frontier_completions.insert(frontier, completion) {
            let previous_fragment = completion_metadata(&previous).1;
            return Err(StoreError::new(format!(
                "selected frontier {frontier} has multiple completion owners {:?} and {:?}",
                previous_fragment, fragment,
            )));
        }
        assert!(completion_fragments.insert(frontier, fragment).is_none());
    }

    let mut sources = BTreeSet::new();
    for &source in transfers_by_source.keys() {
        if poll_cancelled(cancellation, work) {
            return Ok(None);
        }
        sources.insert(source);
    }
    while let Some(source) = sources.pop_first() {
        if poll_cancelled(cancellation, work) {
            return Ok(None);
        }
        let (transfer_fragment, _) = &transfers_by_source[&source];
        let _completion = frontier_completions.get(&source).ok_or_else(|| {
            StoreError::new(format!(
                "selected transfer source {source} has no exhausted frontier completion row"
            ))
        })?;
        let completion_fragment = completion_fragments[&source];
        if completion_fragment != *transfer_fragment {
            return Err(StoreError::new(format!(
                "selected transfer source {source} fragment {transfer_fragment:?} disagrees with frontier completion fragment {:?}",
                completion_fragment,
            )));
        }
    }
    Ok(Some((transfers_by_source, frontier_completions)))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EvaluationSnapshot {
    // `lexical_answers` is a transparent memo of the immutable preload, while
    // `work` only schedules cancellation polls. `cancellation_reasons` and
    // `cancellation_observed` are operational records used only if publication
    // is cancelled. None changes the semantic transition or belongs in exact
    // cycle equality.
    references: Box<[SemanticId]>,
    slots: Box<[SemanticId]>,
    answers: Box<[(SemanticId, ResolutionAnswer)]>,
    states: Box<[(SemanticId, TypedFrontierState)]>,
}

struct EvaluationRound {
    answers: HashMap<SemanticId, ResolutionAnswer>,
    states: HashMap<SemanticId, TypedFrontierState>,
    demands_stable: bool,
    stable: bool,
}

struct EvaluationCheckpoint<'a> {
    evaluation: FactEvaluationState<'a>,
    answers: HashMap<SemanticId, ResolutionAnswer>,
    states: HashMap<SemanticId, TypedFrontierState>,
}

impl<'a> EvaluationCheckpoint<'a> {
    fn try_clone(&mut self, workspace: &mut FactEvaluation<'_, 'a>) -> Option<Self> {
        let Self {
            evaluation,
            answers,
            states,
        } = self;
        let (checkpoint, replay_metrics) =
            workspace.with_checkpoint_state(evaluation, |workspace| {
                let mut replay_metrics = ResolutionBatchMetrics::default();
                workspace.move_binding_metrics_to(&mut replay_metrics);
                (workspace.checkpoint(answers, states), replay_metrics)
            });
        workspace.binding_metrics.accumulate(replay_metrics);
        checkpoint
    }

    fn snapshot(&mut self, workspace: &mut FactEvaluation<'_, 'a>) -> Option<EvaluationSnapshot> {
        debug_assert!(
            self.evaluation.demands.is_empty(),
            "cycle snapshots require a fully expanded demand queue"
        );
        let Self {
            evaluation,
            answers,
            states,
        } = self;
        workspace.with_checkpoint_state(evaluation, |workspace| workspace.snapshot(answers, states))
    }

    fn advance(&mut self, workspace: &mut FactEvaluation<'_, 'a>) -> StoreResult<bool> {
        if self.evaluation.cancellation.is_cancelled() {
            return Ok(false);
        }
        let Self {
            evaluation,
            answers,
            states,
        } = self;
        let (round, replay_metrics) = workspace.with_checkpoint_state(evaluation, |workspace| {
            let round = workspace.evaluate_round(answers, states);
            let mut replay_metrics = ResolutionBatchMetrics::default();
            workspace.move_binding_metrics_to(&mut replay_metrics);
            (round, replay_metrics)
        });
        workspace.binding_metrics.accumulate(replay_metrics);
        let Some(round) = round? else {
            return Ok(false);
        };
        assert!(
            !round.stable,
            "a replayed cycle transition must remain non-stable"
        );
        assert!(
            round.demands_stable,
            "a replayed cycle transition must remain in one closed demand epoch"
        );
        self.answers = round.answers;
        self.states = round.states;
        Ok(true)
    }
}

/// Brent's constant-checkpoint cycle detector over exact configurations.
///
/// Only `checkpoint` survives a round. The current snapshot is either moved
/// into that checkpoint or dropped, so retained memory does not grow with the
/// number of rounds. Equality is structural; no digest or iteration limit has
/// semantic authority.
struct ExactCycleDetector {
    checkpoint: EvaluationSnapshot,
    power: usize,
    distance: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CycleObservation {
    Continue,
    Repeated(usize),
    Cancelled,
}

impl ExactCycleDetector {
    fn new(checkpoint: EvaluationSnapshot) -> Self {
        Self {
            checkpoint,
            power: 1,
            distance: 0,
        }
    }

    fn observe(
        &mut self,
        current: EvaluationSnapshot,
        cancellation: &CancellationToken,
        work: &mut usize,
    ) -> CycleObservation {
        self.distance = self
            .distance
            .checked_add(1)
            .expect("cycle-certificate distance must fit usize");
        let Some(repeated) = snapshots_equal_with_poll(&self.checkpoint, &current, || {
            poll_cancelled(cancellation, work)
        }) else {
            return CycleObservation::Cancelled;
        };
        if repeated {
            return CycleObservation::Repeated(self.distance);
        }
        if self.distance == self.power {
            self.checkpoint = current;
            self.power = self
                .power
                .checked_mul(2)
                .expect("cycle-certificate power must fit usize");
            self.distance = 0;
        }
        CycleObservation::Continue
    }
}

struct ExactCycleCertificate<'a> {
    origin: EvaluationCheckpoint<'a>,
    detector: ExactCycleDetector,
}

impl<'a> ExactCycleCertificate<'a> {
    fn new(origin: EvaluationCheckpoint<'a>, current: EvaluationSnapshot) -> Self {
        debug_assert!(
            origin.evaluation.demands.is_empty(),
            "a cycle epoch starts after demand expansion"
        );
        Self {
            origin,
            detector: ExactCycleDetector::new(current),
        }
    }

    fn observe(
        &mut self,
        evaluation: &mut FactEvaluation<'_, '_>,
        current: EvaluationSnapshot,
    ) -> CycleObservation {
        debug_assert!(evaluation.demands.is_empty());
        self.detector
            .observe(current, evaluation.cancellation, &mut evaluation.work)
    }

    fn replay_cycle_entry(
        &mut self,
        cycle_length: usize,
        workspace: &mut FactEvaluation<'_, 'a>,
    ) -> StoreResult<Option<EvaluationCheckpoint<'a>>> {
        let mut generic_replay_metrics = ResolutionBatchMetrics::default();
        let outcome = replay_cycle_entry(
            &mut self.origin,
            cycle_length,
            workspace,
            &mut generic_replay_metrics,
            |checkpoint, workspace, _replay_metrics| Ok(checkpoint.try_clone(workspace)),
            |checkpoint, workspace, _replay_metrics| checkpoint.advance(workspace),
            |left, right, workspace, _replay_metrics| {
                let Some(left_snapshot) = left.snapshot(workspace) else {
                    return Ok(None);
                };
                let Some(right_snapshot) = right.snapshot(workspace) else {
                    return Ok(None);
                };
                let cancellation = left.evaluation.cancellation;
                let equal = snapshots_equal_with_poll(&left_snapshot, &right_snapshot, || {
                    poll_cancelled(cancellation, &mut left.evaluation.work)
                });
                Ok(equal)
            },
        )?;

        // Both Brent cursors can cross independent source boundaries before
        // one observes cancellation. Preserve every cursor ledger regardless
        // of which cursor becomes the cycle entry; discarded replay state is
        // operational evidence, not semantic fixed-point state.
        let mut replay_reasons = CancellationReasonCollection::default();
        self.origin
            .evaluation
            .move_cancellation_reasons_to(&mut replay_reasons);
        for mut discarded in outcome.discarded {
            discarded
                .evaluation
                .move_cancellation_reasons_to(&mut replay_reasons);
        }
        if let Some(mut entry) = outcome.entry {
            entry.evaluation.merge_cancellation_reasons(replay_reasons);
            Ok(Some(entry))
        } else {
            self.origin
                .evaluation
                .merge_cancellation_reasons(replay_reasons);
            Ok(None)
        }
    }

    fn take_cancellation_reasons(&mut self) -> CancellationReasonCollection {
        std::mem::take(&mut self.origin.evaluation.cancellation_reasons)
    }
}

/// Locate the canonical entry of an exactly detected cycle.
///
/// The leading cursor starts one period ahead. Their first exact meeting is
/// the cycle entry, which is equal to the first repeated configuration the old
/// retained-history scan returned. `advance == false` propagates cooperative
/// cancellation without manufacturing a cycle result.
fn replay_cycle_entry<T, C, E>(
    origin: &mut T,
    cycle_length: usize,
    context: &mut C,
    replay_metrics: &mut ResolutionBatchMetrics,
    mut clone_state: impl FnMut(&mut T, &mut C, &mut ResolutionBatchMetrics) -> Result<Option<T>, E>,
    mut advance: impl FnMut(&mut T, &mut C, &mut ResolutionBatchMetrics) -> Result<bool, E>,
    mut equivalent: impl FnMut(
        &mut T,
        &mut T,
        &mut C,
        &mut ResolutionBatchMetrics,
    ) -> Result<Option<bool>, E>,
) -> Result<ReplayCycleEntry<T>, E> {
    assert!(cycle_length > 0, "a detected cycle has positive length");
    let Some(mut trailing) = clone_state(origin, context, replay_metrics)? else {
        return Ok(ReplayCycleEntry::cancelled(Vec::new()));
    };
    let Some(mut leading) = clone_state(origin, context, replay_metrics)? else {
        return Ok(ReplayCycleEntry::cancelled(vec![trailing]));
    };
    for _ in 0..cycle_length {
        if !advance(&mut leading, context, replay_metrics)? {
            return Ok(ReplayCycleEntry::cancelled(vec![trailing, leading]));
        }
    }
    loop {
        let Some(matches) = equivalent(&mut trailing, &mut leading, context, replay_metrics)?
        else {
            return Ok(ReplayCycleEntry::cancelled(vec![trailing, leading]));
        };
        if matches {
            return Ok(ReplayCycleEntry {
                entry: Some(trailing),
                discarded: vec![leading],
            });
        }
        if !advance(&mut trailing, context, replay_metrics)? {
            return Ok(ReplayCycleEntry::cancelled(vec![trailing, leading]));
        }
        if !advance(&mut leading, context, replay_metrics)? {
            return Ok(ReplayCycleEntry::cancelled(vec![trailing, leading]));
        }
    }
}

struct ReplayCycleEntry<T> {
    entry: Option<T>,
    discarded: Vec<T>,
}

impl<T> ReplayCycleEntry<T> {
    fn cancelled(discarded: Vec<T>) -> Self {
        Self {
            entry: None,
            discarded,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct ExplicitReceiverTargetEvidence {
    values: BTreeSet<ResolutionSlotValue>,
    category_open: bool,
}

#[derive(Debug)]
enum SemanticDischargeProof {
    Proven(BTreeSet<SemanticId>),
    Unproven,
    Cancelled,
}

struct FactEvaluationState<'a> {
    root: SemanticId,
    root_seed: Option<ReferenceSeed>,
    root_site_metadata: Option<FactReferenceSiteMetadata>,
    root_is_callable: bool,
    root_explicit_receiver_evidence: BTreeMap<SemanticId, ExplicitReceiverTargetEvidence>,
    cancellation: &'a CancellationToken,
    demands: VecDeque<Demand>,
    demanded_references: HashSet<SemanticId>,
    demanded_slots: HashSet<SemanticId>,
    forced_reference_gaps: HashMap<SemanticId, ResolutionCompletion>,
    forced_slot_gaps: HashMap<SemanticId, ResolutionCompletion>,
    // Immutable source seed outcomes are independent of fixed-point state.
    // Cache affirmative seeds and exhausted absence so qualified references
    // are read once even when later rounds reevaluate their dynamic routes.
    qualified_reference_seeds: HashMap<SemanticId, Option<ReferenceSeed>>,
    lexical_answers: HashMap<SemanticId, ResolutionAnswer>,
    // Operational evidence only: successful fixed-point answers never read
    // this set, so transient round gaps cannot affect noncancelled semantics.
    cancellation_reasons: CancellationReasonCollection,
    cancellation_observed: bool,
    // Exact-cycle replay moves each cursor's telemetry into the original
    // operation collector after every replay transition. Metrics remain
    // operational and never enter semantic snapshots.
    binding_metrics: ResolutionBatchMetrics,
    work: usize,
}

impl FactEvaluationState<'_> {
    fn merge_cancellation_reasons(&mut self, reasons: CancellationReasonCollection) {
        let cancellation = self.cancellation;
        let mut work = self.work;
        let mut cancellation_observed = self.cancellation_observed;
        self.cancellation_reasons.merge_with_poll(
            reasons,
            cancellation,
            &mut work,
            &mut cancellation_observed,
        );
        self.work = work;
        self.cancellation_observed = cancellation_observed;
    }

    fn move_cancellation_reasons_to(&mut self, target: &mut CancellationReasonCollection) {
        let reasons = std::mem::take(&mut self.cancellation_reasons);
        self.merge_cancellation_reasons_into(target, reasons);
    }

    fn merge_cancellation_reasons_into(
        &mut self,
        target: &mut CancellationReasonCollection,
        reasons: CancellationReasonCollection,
    ) {
        let cancellation = self.cancellation;
        target.merge_with_poll(
            reasons,
            cancellation,
            &mut self.work,
            &mut self.cancellation_observed,
        );
    }
}

struct FactEvaluation<'resources, 'source> {
    session: &'resources mut FactReadSession<'source>,
    hierarchy: &'resources mut HierarchyOperationArena,
    root: SemanticId,
    root_seed: Option<ReferenceSeed>,
    root_site_metadata: Option<FactReferenceSiteMetadata>,
    root_is_callable: bool,
    root_explicit_receiver_evidence: BTreeMap<SemanticId, ExplicitReceiverTargetEvidence>,
    cancellation: &'source CancellationToken,
    demands: VecDeque<Demand>,
    demanded_references: HashSet<SemanticId>,
    demanded_slots: HashSet<SemanticId>,
    forced_reference_gaps: HashMap<SemanticId, ResolutionCompletion>,
    forced_slot_gaps: HashMap<SemanticId, ResolutionCompletion>,
    qualified_reference_seeds: HashMap<SemanticId, Option<ReferenceSeed>>,
    lexical_answers: HashMap<SemanticId, ResolutionAnswer>,
    cancellation_reasons: CancellationReasonCollection,
    cancellation_observed: bool,
    binding_metrics: ResolutionBatchMetrics,
    work: usize,
}

impl<'resources, 'source> FactEvaluation<'resources, 'source> {
    fn new(
        session: &'resources mut FactReadSession<'source>,
        hierarchy: &'resources mut HierarchyOperationArena,
        root: SemanticId,
    ) -> Self {
        Self::base(session, hierarchy, root, None, None)
    }

    fn base(
        session: &'resources mut FactReadSession<'source>,
        hierarchy: &'resources mut HierarchyOperationArena,
        root: SemanticId,
        root_seed: Option<ReferenceSeed>,
        root_site_metadata: Option<FactReferenceSiteMetadata>,
    ) -> Self {
        assert!(
            root_seed
                .as_ref()
                .is_none_or(|seed| seed.reference() == root),
            "source-issued root seed must name the evaluated reference"
        );
        let cancellation = session.cancellation;
        Self {
            session,
            hierarchy,
            root,
            root_seed,
            root_site_metadata,
            root_is_callable: root_site_metadata
                .is_some_and(|metadata| metadata.namespace() == ResolutionNamespace::Callable),
            root_explicit_receiver_evidence: BTreeMap::new(),
            cancellation,
            demands: VecDeque::new(),
            demanded_references: HashSet::default(),
            demanded_slots: HashSet::default(),
            forced_reference_gaps: HashMap::default(),
            forced_slot_gaps: HashMap::default(),
            qualified_reference_seeds: HashMap::default(),
            lexical_answers: HashMap::default(),
            cancellation_reasons: CancellationReasonCollection::default(),
            cancellation_observed: cancellation.is_cancelled(),
            binding_metrics: ResolutionBatchMetrics::default(),
            work: 0,
        }
    }

    fn swap_checkpoint_state(&mut self, checkpoint: &mut FactEvaluationState<'source>) {
        std::mem::swap(&mut self.root, &mut checkpoint.root);
        std::mem::swap(&mut self.root_seed, &mut checkpoint.root_seed);
        std::mem::swap(
            &mut self.root_site_metadata,
            &mut checkpoint.root_site_metadata,
        );
        std::mem::swap(&mut self.root_is_callable, &mut checkpoint.root_is_callable);
        std::mem::swap(
            &mut self.root_explicit_receiver_evidence,
            &mut checkpoint.root_explicit_receiver_evidence,
        );
        debug_assert!(std::ptr::eq(self.cancellation, checkpoint.cancellation));
        std::mem::swap(&mut self.demands, &mut checkpoint.demands);
        std::mem::swap(
            &mut self.demanded_references,
            &mut checkpoint.demanded_references,
        );
        std::mem::swap(&mut self.demanded_slots, &mut checkpoint.demanded_slots);
        std::mem::swap(
            &mut self.forced_reference_gaps,
            &mut checkpoint.forced_reference_gaps,
        );
        std::mem::swap(&mut self.forced_slot_gaps, &mut checkpoint.forced_slot_gaps);
        std::mem::swap(
            &mut self.qualified_reference_seeds,
            &mut checkpoint.qualified_reference_seeds,
        );
        std::mem::swap(&mut self.lexical_answers, &mut checkpoint.lexical_answers);
        std::mem::swap(
            &mut self.cancellation_reasons,
            &mut checkpoint.cancellation_reasons,
        );
        std::mem::swap(
            &mut self.cancellation_observed,
            &mut checkpoint.cancellation_observed,
        );
        std::mem::swap(&mut self.binding_metrics, &mut checkpoint.binding_metrics);
        std::mem::swap(&mut self.work, &mut checkpoint.work);
    }

    fn with_checkpoint_state<T>(
        &mut self,
        checkpoint: &mut FactEvaluationState<'source>,
        operation: impl FnOnce(&mut Self) -> T,
    ) -> T {
        self.swap_checkpoint_state(checkpoint);
        let result = operation(self);
        self.swap_checkpoint_state(checkpoint);
        result
    }

    fn move_binding_metrics_to(&mut self, target: &mut ResolutionBatchMetrics) {
        target.accumulate(std::mem::take(&mut self.binding_metrics));
    }

    fn merge_cancellation_reasons(&mut self, reasons: CancellationReasonCollection) {
        let cancellation = self.cancellation;
        let mut work = self.work;
        let mut cancellation_observed = self.cancellation_observed;
        self.cancellation_reasons.merge_with_poll(
            reasons,
            cancellation,
            &mut work,
            &mut cancellation_observed,
        );
        self.work = work;
        self.cancellation_observed = cancellation_observed;
    }

    fn poll_cancellation_ledger(&mut self) {
        self.cancellation_observed |= poll_cancelled(self.cancellation, &mut self.work);
    }

    fn poll_cancelled(&mut self) -> bool {
        if self.cancellation_observed {
            return true;
        }
        let cancelled = poll_cancelled(self.cancellation, &mut self.work);
        self.cancellation_observed |= cancelled;
        cancelled
    }

    const fn root_reference_owner(&self) -> Option<Option<SemanticId>> {
        match self.root_site_metadata {
            Some(metadata) => metadata.reference_owner(),
            None => None,
        }
    }

    const fn root_callable_receiver_origin(&self) -> Option<ResolutionCallableReceiverOrigin> {
        match self.root_site_metadata {
            Some(metadata) => metadata.callable_receiver_origin(),
            None => None,
        }
    }

    fn initialize_root_demands(&mut self) -> StoreResult<bool> {
        if self.cancellation_observed || self.cancellation.is_cancelled() {
            self.cancellation_observed = true;
            return Ok(false);
        }
        self.demand_reference(self.root);
        let read = self.session.projections_for_references(&[self.root])?;
        let Some(projections) = self.accept_session_read(read) else {
            return Ok(false);
        };
        for projection in projections {
            self.poll_cancellation_ledger();
            if self.cancellation_observed {
                return Ok(false);
            }
            let projection = projection.get(self.session);
            self.root_is_callable |=
                projection.row().kind() == BindingProjectionKind::TargetCallableResultType;
            self.demand_slot(projection.row().output_slot());
        }
        Ok(true)
    }

    fn run(&mut self) -> StoreResult<FactResolutionAnswer> {
        if !self.initialize_root_demands()? {
            return Ok(self.cancelled_answer(None));
        }
        if self.cancellation_observed || self.cancellation.is_cancelled() {
            return Ok(self.cancelled_answer(None));
        }

        let mut states = HashMap::default();
        let mut answers = HashMap::default();
        let mut cycle = None;
        loop {
            let Some(round) = self.evaluate_round(&answers, &states)? else {
                return Ok(self.cancelled_answer(None));
            };
            if round.stable {
                if !self.force_unresolved_dependencies(&round.answers, &round.states, &mut cycle) {
                    let Some(answer) = self.finish(round.answers, round.states)? else {
                        return Ok(self.cancelled_answer(None));
                    };
                    return Ok(self.publish(answer));
                }
                answers = round.answers;
                states = round.states;
                continue;
            }

            // A demand-growing transition belongs to the previous demand
            // epoch. Its checkpoint cannot be replay authority for the newly
            // discovered predecessor closure or its immutable lexical memo.
            if !round.demands_stable {
                cycle = None;
                answers = round.answers;
                states = round.states;
                continue;
            }

            let Some(current) = self.snapshot(&round.answers, &round.states) else {
                return Ok(self.cancelled_answer(None));
            };
            if let Some(certificate) = &mut cycle {
                match certificate.observe(self, current) {
                    CycleObservation::Continue => {}
                    CycleObservation::Cancelled => return Ok(self.cancelled_answer(None)),
                    CycleObservation::Repeated(cycle_length) => {
                        let Some(mut entry) = certificate.replay_cycle_entry(cycle_length, self)?
                        else {
                            let reasons = certificate.take_cancellation_reasons();
                            self.merge_cancellation_reasons(reasons);
                            return Ok(self.cancelled_answer(None));
                        };
                        let replay_reasons =
                            std::mem::take(&mut entry.evaluation.cancellation_reasons);
                        self.merge_cancellation_reasons(replay_reasons);
                        let Some(answer) =
                            self.finish_with_cycle_gap(entry.answers, entry.states)?
                        else {
                            return Ok(self.cancelled_answer(None));
                        };
                        return Ok(self.publish(answer));
                    }
                }
            } else {
                let Some(origin) = self.checkpoint(&round.answers, &round.states) else {
                    return Ok(self.cancelled_answer(None));
                };
                cycle = Some(ExactCycleCertificate::new(origin, current));
            }
            answers = round.answers;
            states = round.states;
        }
    }

    /// Evaluate one whole binding/type round.
    ///
    /// The Brent certificate below bounds retained history, not evaluation
    /// work: an acyclic dependency chain can still cause every ordinary round
    /// to revisit every demanded fact, for O(N^2) CPU. A dependency-directed
    /// worklist remains a separate benchmark-gated milestone.
    fn evaluate_round(
        &mut self,
        previous_answers: &HashMap<SemanticId, ResolutionAnswer>,
        previous_states: &HashMap<SemanticId, TypedFrontierState>,
    ) -> StoreResult<Option<EvaluationRound>> {
        if !self.expand_demands()? {
            return Ok(None);
        }
        if self.poll_cancelled() {
            return Ok(None);
        }
        let demand_epoch = (self.demanded_references.len(), self.demanded_slots.len());

        let answers = self.evaluate_references(previous_states)?;
        if self.poll_cancelled() {
            return Ok(None);
        }
        // Callable applicability can discover declaration-backed parameter
        // slots while evaluating references. Close those newly demanded
        // predecessors before state evaluation classifies transfer SCCs or
        // proves a slot has no producer.
        if !self.expand_demands()? {
            return Ok(None);
        }
        if self.poll_cancelled() {
            return Ok(None);
        }
        let Some(states) = self.evaluate_states(previous_states, &answers)? else {
            return Ok(None);
        };
        if !self.expand_demands()? {
            return Ok(None);
        }
        if self.poll_cancelled() {
            return Ok(None);
        }

        let demands_stable =
            demand_epoch == (self.demanded_references.len(), self.demanded_slots.len());
        let stable = if demands_stable {
            let Some(stable_states) = state_maps_equal_with_poll(
                previous_states,
                &states,
                self.cancellation,
                &mut self.work,
            ) else {
                return Ok(None);
            };
            if !stable_states {
                false
            } else {
                let Some(stable_answers) = answer_maps_equal_with_poll(
                    previous_answers,
                    &answers,
                    self.cancellation,
                    &mut self.work,
                ) else {
                    return Ok(None);
                };
                stable_answers
            }
        } else {
            false
        };
        Ok(Some(EvaluationRound {
            answers,
            states,
            demands_stable,
            stable,
        }))
    }

    fn snapshot(
        &mut self,
        answers: &HashMap<SemanticId, ResolutionAnswer>,
        states: &HashMap<SemanticId, TypedFrontierState>,
    ) -> Option<EvaluationSnapshot> {
        debug_assert!(self.demands.is_empty());
        snapshot_with_poll(
            &self.demanded_references,
            &self.demanded_slots,
            answers,
            states,
            self.cancellation,
            &mut self.work,
        )
    }

    fn checkpoint(
        &mut self,
        answers: &HashMap<SemanticId, ResolutionAnswer>,
        states: &HashMap<SemanticId, TypedFrontierState>,
    ) -> Option<EvaluationCheckpoint<'source>> {
        debug_assert!(self.demands.is_empty());
        let demanded_references = clone_semantic_set_with_poll(
            &self.demanded_references,
            self.cancellation,
            &mut self.work,
        )?;
        let demanded_slots =
            clone_semantic_set_with_poll(&self.demanded_slots, self.cancellation, &mut self.work)?;
        let forced_reference_gaps = clone_completion_map_with_poll(
            &self.forced_reference_gaps,
            self.cancellation,
            &mut self.work,
        )?;
        let forced_slot_gaps = clone_completion_map_with_poll(
            &self.forced_slot_gaps,
            self.cancellation,
            &mut self.work,
        )?;
        let mut qualified_reference_seeds = HashMap::default();
        for (&reference, seed) in &self.qualified_reference_seeds {
            if poll_cancelled(self.cancellation, &mut self.work) {
                return None;
            }
            let seed = match seed {
                Some(seed) => Some(ReferenceSeed::new_with_site_metadata(
                    seed.fragment(),
                    seed.query(),
                    seed.node(),
                    seed.site_metadata(),
                    clone_completion_with_poll(
                        seed.completion(),
                        self.cancellation,
                        &mut self.work,
                    )?,
                )),
                None => None,
            };
            assert!(
                qualified_reference_seeds.insert(reference, seed).is_none(),
                "one qualified reference has one cached source-seed outcome"
            );
        }
        let lexical_answers =
            clone_answer_map_with_poll(&self.lexical_answers, self.cancellation, &mut self.work)?;
        let answers = clone_answer_map_with_poll(answers, self.cancellation, &mut self.work)?;
        let states = clone_state_map_with_poll(states, self.cancellation, &mut self.work)?;
        let mut root_explicit_receiver_evidence = BTreeMap::new();
        for (&target, evidence) in &self.root_explicit_receiver_evidence {
            if poll_cancelled(self.cancellation, &mut self.work) {
                return None;
            }
            let mut values = BTreeSet::new();
            for &value in &evidence.values {
                if poll_cancelled(self.cancellation, &mut self.work) {
                    return None;
                }
                values.insert(value);
            }
            assert!(
                root_explicit_receiver_evidence
                    .insert(
                        target,
                        ExplicitReceiverTargetEvidence {
                            values,
                            category_open: evidence.category_open,
                        },
                    )
                    .is_none(),
                "one explicit receiver target has one checkpoint evidence record"
            );
        }
        if self.cancellation.is_cancelled() {
            return None;
        }
        Some(EvaluationCheckpoint {
            evaluation: FactEvaluationState {
                root: self.root,
                root_seed: match &self.root_seed {
                    Some(seed) => Some(ReferenceSeed::new_with_site_metadata(
                        seed.fragment(),
                        seed.query(),
                        seed.node(),
                        seed.site_metadata(),
                        clone_completion_with_poll(
                            seed.completion(),
                            self.cancellation,
                            &mut self.work,
                        )?,
                    )),
                    None => None,
                },
                root_site_metadata: self.root_site_metadata,
                root_is_callable: self.root_is_callable,
                root_explicit_receiver_evidence,
                cancellation: self.cancellation,
                demands: VecDeque::new(),
                demanded_references,
                demanded_slots,
                forced_reference_gaps,
                forced_slot_gaps,
                qualified_reference_seeds,
                lexical_answers,
                cancellation_reasons: CancellationReasonCollection::default(),
                cancellation_observed: false,
                binding_metrics: ResolutionBatchMetrics::default(),
                work: self.work,
            },
            answers,
            states,
        })
    }

    fn publish(&mut self, answer: FactResolutionAnswer) -> FactResolutionAnswer {
        if self.cancellation_observed || self.cancellation.is_cancelled() {
            self.cancelled_answer(Some(answer.completion()))
        } else {
            answer
        }
    }

    fn observe_cancellation_completion(&mut self, completion: &ResolutionCompletion) {
        include_completion_reasons_with_poll(
            &mut self.cancellation_reasons,
            completion,
            self.cancellation,
            &mut self.work,
            &mut self.cancellation_observed,
        );
    }

    fn observe_resolution_answer_cancellation_evidence(&mut self, answer: &ResolutionAnswer) {
        self.observe_cancellation_completion(answer.completion());
        for witness in answer.witnesses() {
            self.poll_cancellation_ledger();
            self.observe_cancellation_completion(witness.completion());
        }
    }

    fn observe_hierarchy_raw_cancellation_completion(&mut self, completion: &ResolutionCompletion) {
        // A hierarchy source operand can outlive the evaluation that decoded
        // it. Retain its complete reason union both locally and in the shared
        // operation arena before making any cancellation/publication choice.
        self.observe_cancellation_completion(completion);
        if let ResolutionCompletion::Incomplete(reasons) = completion {
            for &reason in reasons.iter() {
                // The returned box is indivisible. Observe cancellation,
                // but finish draining all of its reasons into the shared
                // ledger.
                self.hierarchy
                    .cancellation_reasons
                    .include_reason_with_poll(
                        reason,
                        self.cancellation,
                        &mut self.work,
                        &mut self.cancellation_observed,
                    );
            }
        }
    }

    fn observe_hierarchy_raw_resolution_answer_cancellation_evidence(
        &mut self,
        answer: &ResolutionAnswer,
    ) {
        self.observe_hierarchy_raw_cancellation_completion(answer.completion());
        for witness in answer.witnesses() {
            self.poll_cancellation_ledger();
            self.observe_hierarchy_raw_cancellation_completion(witness.completion());
        }
    }

    fn accept_session_read<R>(
        &mut self,
        read: SessionFactRead<R>,
    ) -> Option<Vec<InternedFactRow<R>>> {
        match read {
            SessionFactRead::Exhausted { rows, evidence } => {
                self.observe_cancellation_completion(&evidence);
                (!self.cancellation_observed).then_some(rows)
            }
            SessionFactRead::Cancelled(evidence) => {
                self.observe_cancellation_completion(&evidence);
                self.cancellation_reasons.include_reason_after_poll(
                    ResolutionIncompleteReason::Cancelled,
                    self.cancellation,
                    &mut self.work,
                    &mut self.cancellation_observed,
                );
                self.cancellation_observed = true;
                None
            }
        }
    }

    fn accept_hierarchy_session_read<R>(
        &mut self,
        identity: SemanticId,
        read: SessionFactRead<R>,
    ) -> Option<Vec<InternedFactRow<R>>> {
        match read {
            SessionFactRead::Exhausted { rows, evidence } => {
                self.observe_hierarchy_support_completion(identity, &evidence);
                (!self.cancellation_observed).then_some(rows)
            }
            SessionFactRead::Cancelled(evidence) => {
                self.observe_cancelled_hierarchy_support_completion(&evidence);
                None
            }
        }
    }

    fn completion_after_hierarchy_transfer(
        &mut self,
        completion: &ResolutionCompletion,
        transferred_hierarchy_reasons: &BTreeSet<SemanticId>,
    ) -> Option<ResolutionCompletion> {
        let ResolutionCompletion::Incomplete(reasons) = completion else {
            return Some(ResolutionCompletion::Complete);
        };
        let cancellation = self.cancellation;
        let work = &mut self.work;
        let cancellation_observed = &mut self.cancellation_observed;
        let mut retained = Vec::with_capacity(reasons.len());
        let mut transferred = false;
        for &reason in reasons.iter() {
            *cancellation_observed |= poll_cancelled(cancellation, work);
            let handled = matches!(
                reason,
                ResolutionIncompleteReason::UnsupportedSemantic(semantic)
                    if transferred_hierarchy_reasons.contains(&semantic)
            );
            transferred |= handled;
            if !handled {
                retained.push(reason);
            }
        }
        *cancellation_observed |= cancellation.is_cancelled();
        if *cancellation_observed {
            return None;
        }
        Some(if transferred && retained.is_empty() {
            ResolutionCompletion::Complete
        } else {
            ResolutionCompletion::Incomplete(retained.into_boxed_slice().into())
        })
    }

    fn include_semantic_completion(
        &mut self,
        target: &mut ExactCompletionAccumulator,
        completion: &ResolutionCompletion,
    ) -> bool {
        self.observe_cancellation_completion(completion);
        if self.cancellation_observed {
            return false;
        }
        let included = target.include(completion, &mut || self.poll_cancelled());
        if included.is_none() {
            self.cancellation_observed = true;
            return false;
        }
        true
    }

    fn include_semantic_reason(
        &mut self,
        target: &mut ExactCompletionAccumulator,
        reason: ResolutionIncompleteReason,
    ) -> bool {
        self.cancellation_reasons.include_reason_with_poll(
            reason,
            self.cancellation,
            &mut self.work,
            &mut self.cancellation_observed,
        );
        if self.cancellation_observed {
            return false;
        }
        let included = target.include_reason(reason, &mut || self.poll_cancelled());
        if included.is_none() {
            self.cancellation_observed = true;
            return false;
        }
        true
    }

    fn finish_semantic_completion(
        &mut self,
        completion: ExactCompletionAccumulator,
    ) -> Option<ResolutionCompletion> {
        self.cancellation_observed |= self.cancellation.is_cancelled();
        if self.cancellation_observed {
            return None;
        }
        let finished = completion.finish(&mut || self.poll_cancelled());
        if finished.is_none() {
            self.cancellation_observed = true;
        }
        finished
    }

    fn clone_root_seed_with_poll(&mut self) -> Option<ReferenceSeed> {
        let seed = self
            .root_seed
            .as_ref()
            .expect("a root seed clone requires an installed source seed");
        let fragment = seed.fragment();
        let query = seed.query();
        let node = seed.node();
        let Some(completion) =
            clone_completion_with_poll(seed.completion(), self.cancellation, &mut self.work)
        else {
            self.cancellation_observed = true;
            return None;
        };
        Some(ReferenceSeed::new_with_site_metadata(
            fragment,
            query,
            node,
            seed.site_metadata(),
            completion,
        ))
    }

    fn install_root_site_metadata(&mut self, site_metadata: Option<FactReferenceSiteMetadata>) {
        if let (Some(existing), Some(incoming)) = (self.root_site_metadata, site_metadata) {
            assert_eq!(
                existing, incoming,
                "one source reference has one immutable site metadata row"
            );
        } else if self.root_site_metadata.is_none() {
            self.root_site_metadata = site_metadata;
        }
        self.root_is_callable |= site_metadata
            .is_some_and(|metadata| metadata.namespace() == ResolutionNamespace::Callable);
    }

    fn clone_qualified_reference_seed_with_poll(
        &mut self,
        reference: SemanticId,
    ) -> Option<Option<ReferenceSeed>> {
        let cached = self
            .qualified_reference_seeds
            .get(&reference)
            .unwrap_or_else(|| {
                panic!("qualified reference {reference} has no exhausted seed outcome")
            });
        let Some(seed) = cached else {
            return Some(None);
        };
        let fragment = seed.fragment();
        let query = seed.query();
        let node = seed.node();
        let Some(completion) =
            clone_completion_with_poll(seed.completion(), self.cancellation, &mut self.work)
        else {
            self.cancellation_observed = true;
            return None;
        };
        Some(Some(ReferenceSeed::new_with_site_metadata(
            fragment,
            query,
            node,
            seed.site_metadata(),
            completion,
        )))
    }

    fn cancelled_answer(
        &mut self,
        completion: Option<&ResolutionCompletion>,
    ) -> FactResolutionAnswer {
        if let Some(completion) = completion {
            self.observe_cancellation_completion(completion);
        }
        let cancellation = self.cancellation;
        match &self.hierarchy.cancellation_reasons {
            CancellationReasonCollection(reasons) => {
                for &reason in reasons {
                    self.cancellation_reasons.include_reason_with_poll(
                        reason,
                        cancellation,
                        &mut self.work,
                        &mut self.cancellation_observed,
                    );
                }
            }
        }
        self.cancellation_reasons
            .0
            .insert(ResolutionIncompleteReason::Cancelled);
        self.cancellation_observed = true;
        let cancellation_reasons = std::mem::take(&mut self.cancellation_reasons);
        let (binding_completion, aggregate_completion) = match cancellation_reasons {
            CancellationReasonCollection(reasons) => {
                let mut reasons = reasons;
                let mut binding_reasons = Vec::with_capacity(reasons.len());
                let mut aggregate_reasons = Vec::with_capacity(reasons.len());
                while let Some(reason) = reasons.pop_first() {
                    self.poll_cancellation_ledger();
                    binding_reasons.push(reason);
                    self.poll_cancellation_ledger();
                    aggregate_reasons.push(reason);
                }
                debug_assert!(binding_reasons.windows(2).all(|pair| pair[0] < pair[1]));
                debug_assert!(aggregate_reasons.windows(2).all(|pair| pair[0] < pair[1]));
                (
                    ResolutionCompletion::Incomplete(binding_reasons.into_boxed_slice().into()),
                    ResolutionCompletion::Incomplete(aggregate_reasons.into_boxed_slice().into()),
                )
            }
        };
        FactResolutionAnswer {
            site_metadata: self.root_site_metadata,
            callable_receiver_dispositions: Box::new([]),
            binding: ResolutionAnswer::new(Vec::new(), Vec::new(), binding_completion),
            projected_frontiers: Box::new([]),
            completion: aggregate_completion,
        }
    }

    fn force_unresolved_dependencies(
        &mut self,
        answers: &HashMap<SemanticId, ResolutionAnswer>,
        states: &HashMap<SemanticId, TypedFrontierState>,
        cycle: &mut Option<ExactCycleCertificate<'source>>,
    ) -> bool {
        let missing_references = self
            .demanded_references
            .iter()
            .copied()
            .filter(|reference| !answers.contains_key(reference))
            .collect::<Vec<_>>();
        let missing_slots = self
            .demanded_slots
            .iter()
            .copied()
            .filter(|slot| !states.contains_key(slot))
            .collect::<Vec<_>>();
        if missing_references.is_empty() && missing_slots.is_empty() {
            return false;
        }

        let mut added = false;
        for reference in missing_references {
            added |= self
                .forced_reference_gaps
                .insert(
                    reference,
                    incomplete(service_reason(
                        b"unresolved-reference-dependency",
                        &[reference.as_bytes().as_slice()],
                    )),
                )
                .is_none();
        }
        for slot in missing_slots {
            added |= self
                .forced_slot_gaps
                .insert(
                    slot,
                    incomplete(service_reason(
                        b"unresolved-slot-dependency",
                        &[slot.as_bytes().as_slice()],
                    )),
                )
                .is_none();
        }
        assert!(
            added,
            "unresolved dependency gaps must make fixed-point progress"
        );
        // Forced evidence changes the transition itself. A pre-gap checkpoint
        // cannot certify a post-gap cycle, so this is an exact epoch boundary.
        *cycle = None;
        true
    }

    fn demand_reference(&mut self, reference: SemanticId) {
        if self.demanded_references.insert(reference) {
            self.demands.push_back(Demand::Reference(reference));
        }
    }

    fn demand_slot(&mut self, slot: SemanticId) {
        if self.demanded_slots.insert(slot) {
            self.demands.push_back(Demand::Slot(slot));
        }
    }

    fn expand_demands(&mut self) -> StoreResult<bool> {
        while !self.demands.is_empty() {
            let mut references = BTreeSet::new();
            let mut slots = BTreeSet::new();
            while let Some(demand) = self.demands.pop_front() {
                if self.poll_cancelled() {
                    return Ok(false);
                }
                match demand {
                    Demand::Reference(reference) => {
                        references.insert(reference);
                    }
                    Demand::Slot(slot) => {
                        slots.insert(slot);
                    }
                }
            }

            if !references.is_empty() {
                let mut ordered_references = Vec::with_capacity(references.len());
                while let Some(reference) = references.pop_first() {
                    if self.poll_cancelled() {
                        return Ok(false);
                    }
                    ordered_references.push(reference);
                }
                let references = ordered_references;
                let read = self.session.routes_for_references(&references)?;
                let Some(routes) = self.accept_session_read(read) else {
                    return Ok(false);
                };
                for route in routes {
                    if self.poll_cancelled() {
                        return Ok(false);
                    }
                    self.demand_slot(route.get(self.session).row().qualifier_slot());
                }
                let read = self.session.calls_for_references(&references)?;
                let Some(calls) = self.accept_session_read(read) else {
                    return Ok(false);
                };
                for call in calls {
                    let argument_count = call.get(self.session).row().argument_slots().len();
                    for argument_index in 0..argument_count {
                        if self.poll_cancelled() {
                            return Ok(false);
                        }
                        let slot = call.get(self.session).row().argument_slots()[argument_index];
                        self.demand_slot(slot);
                    }
                }
            }

            if !slots.is_empty() {
                let mut ordered_slots = Vec::with_capacity(slots.len());
                while let Some(slot) = slots.pop_first() {
                    if self.poll_cancelled() {
                        return Ok(false);
                    }
                    ordered_slots.push(slot);
                }
                let slots = ordered_slots;
                let read = self.session.projections_for_outputs(&slots)?;
                let Some(projections) = self.accept_session_read(read) else {
                    return Ok(false);
                };
                for projection in projections {
                    if self.poll_cancelled() {
                        return Ok(false);
                    }
                    self.demand_reference(projection.get(self.session).row().reference());
                }
                let read = self.session.transfers_to_targets(&slots)?;
                let Some(transfers) = self.accept_session_read(read) else {
                    return Ok(false);
                };
                for transfer in transfers {
                    if self.poll_cancelled() {
                        return Ok(false);
                    }
                    self.demand_slot(transfer.get(self.session).row().source_slot());
                }
            }
        }
        Ok(true)
    }

    fn ensure_qualified_reference_seeds(
        &mut self,
        routes_by_reference: &HashMap<
            SemanticId,
            Vec<InternedFactRow<SourceSelectedQualifiedRoute>>,
        >,
    ) -> StoreResult<bool> {
        let mut missing = BTreeSet::new();
        for &reference in routes_by_reference.keys() {
            if self.poll_cancelled() {
                return Ok(false);
            }
            let injected_root = reference == self.root && self.root_seed.is_some();
            let answer_already_owned = self.forced_reference_gaps.contains_key(&reference)
                || self.lexical_answers.contains_key(&reference);
            if !injected_root
                && !answer_already_owned
                && !self.qualified_reference_seeds.contains_key(&reference)
            {
                missing.insert(reference);
            }
        }
        let mut ordered_missing = Vec::with_capacity(missing.len());
        while let Some(reference) = missing.pop_first() {
            if self.poll_cancelled() {
                return Ok(false);
            }
            ordered_missing.push(reference);
        }

        for reference_chunk in ordered_missing.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
            if self.poll_cancelled() {
                return Ok(false);
            }
            let mut queries = Vec::with_capacity(reference_chunk.len());
            for &reference in reference_chunk {
                if self.poll_cancelled() {
                    return Ok(false);
                }
                queries.push(ResolutionQuery::new(reference));
            }
            let outcome = self
                .session
                .lexical_source
                .lookup_reference_seeds(&queries, self.cancellation)?;
            let (rows, terminal, evidence) = outcome.into_parts();
            self.observe_cancellation_completion(&evidence);
            if terminal == ReferenceSeedReadTerminal::Cancelled {
                assert!(
                    rows.is_empty(),
                    "a cancelled plural reference-seed read publishes no rows"
                );
                self.cancellation_observed = true;
                return Ok(false);
            }
            assert_eq!(terminal, ReferenceSeedReadTerminal::Exhausted);
            if rows.len() != queries.len() {
                return Err(StoreError::new(format!(
                    "exhausted qualified reference seed read returned {} rows for {} queries",
                    rows.len(),
                    queries.len()
                )));
            }

            let mut staged = Vec::with_capacity(rows.len());
            let mut staged_absences = Vec::new();
            for (ordinal, row) in rows.into_vec().into_iter().enumerate() {
                // The exhausted outcome owns every row. Continue validating
                // and ledgering its full evidence after the token edge, then
                // discard the whole staged publication below.
                self.poll_cancellation_ledger();
                if row.request_ordinal() != ordinal || row.query() != queries[ordinal] {
                    return Err(StoreError::new(format!(
                        "qualified reference seed row ({}, {:?}) disagrees with request ({ordinal}, {:?})",
                        row.request_ordinal(),
                        row.query(),
                        queries[ordinal]
                    )));
                }
                let reference = row.query().reference();
                let seed = row.into_seed();
                if let Some(seed) = &seed {
                    self.observe_cancellation_completion(seed.completion());
                } else {
                    staged_absences.push(reference);
                }
                staged.push((reference, seed));
            }
            self.poll_cancellation_ledger();
            if self.cancellation_observed || self.cancellation.is_cancelled() {
                self.cancellation_observed = true;
                return Ok(false);
            }
            for (reference, seed) in staged {
                assert!(
                    self.qualified_reference_seeds
                        .insert(reference, seed)
                        .is_none(),
                    "one qualified reference seed outcome is published once"
                );
            }
            // `None` is semantic negative evidence only after Exhausted wins
            // the atomic publication gate. Once cached, retain the derived
            // absence for a later cancellation even if no dynamic round has
            // consumed it yet.
            for reference in staged_absences {
                self.poll_cancellation_ledger();
                self.observe_cancellation_completion(&incomplete(service_reason(
                    b"missing-qualified-reference-seed",
                    &[reference.as_bytes().as_slice()],
                )));
            }
            if self.cancellation_observed || self.cancellation.is_cancelled() {
                self.cancellation_observed = true;
                return Ok(false);
            }
        }
        Ok(!self.poll_cancelled())
    }

    fn evaluate_references(
        &mut self,
        previous_states: &HashMap<SemanticId, TypedFrontierState>,
    ) -> StoreResult<HashMap<SemanticId, ResolutionAnswer>> {
        self.root_explicit_receiver_evidence.clear();
        let mut references = self.demanded_references.iter().copied().collect::<Vec<_>>();
        references.sort_unstable();
        let route_read = self.session.routes_for_references(&references)?;
        let Some(route_rows) = self.accept_session_read(route_read) else {
            return Ok(HashMap::default());
        };
        let mut routes_by_reference =
            HashMap::<SemanticId, Vec<InternedFactRow<SourceSelectedQualifiedRoute>>>::default();
        for route in route_rows {
            routes_by_reference
                .entry(route.get(self.session).row().reference())
                .or_default()
                .push(route);
        }
        if !self.ensure_qualified_reference_seeds(&routes_by_reference)? {
            return Ok(HashMap::default());
        }
        let call_read = self.session.calls_for_references(&references)?;
        let Some(call_rows) = self.accept_session_read(call_read) else {
            return Ok(HashMap::default());
        };
        let mut calls_by_reference = HashMap::default();
        for call in call_rows {
            assert!(
                calls_by_reference
                    .insert(call.get(self.session).row().callee_reference(), call)
                    .is_none(),
                "one selected callee reference has at most one call obligation"
            );
        }
        let mut answers = HashMap::default();
        for &reference in &references {
            if self.poll_cancelled() {
                break;
            }
            let answer = if let Some(forced) = self.forced_reference_gaps.get(&reference) {
                let answer = ResolutionAnswer::new(Vec::new(), Vec::new(), forced.clone());
                self.observe_resolution_answer_cancellation_evidence(&answer);
                if self.cancellation_observed {
                    break;
                }
                Some(answer)
            } else if let Some(routes) = routes_by_reference.get(&reference) {
                let answer = self.resolve_qualified(reference, routes, previous_states)?;
                if let Some(answer) = &answer {
                    self.observe_resolution_answer_cancellation_evidence(answer);
                    if self.cancellation_observed {
                        break;
                    }
                }
                answer
            } else if self.lexical_answers.contains_key(&reference) {
                let answer = {
                    let cached = self
                        .lexical_answers
                        .get(&reference)
                        .expect("the cached lexical answer was just observed");
                    clone_answer_with_poll(cached, self.cancellation, &mut self.work)
                };
                let Some(answer) = answer else {
                    self.cancellation_observed = true;
                    break;
                };
                self.observe_resolution_answer_cancellation_evidence(&answer);
                if self.cancellation_observed {
                    break;
                }
                Some(answer)
            } else {
                let answer = if reference == self.root {
                    let query = ResolutionQuery::new(reference);
                    let seed = if self.root_seed.is_some() {
                        let Some(seed) = self.clone_root_seed_with_poll() else {
                            break;
                        };
                        Some(seed)
                    } else if self.cancellation.is_cancelled() {
                        None
                    } else {
                        self.session
                            .lexical_source
                            .reference_seed(query, self.cancellation)?
                    };
                    if let Some(seed) = seed {
                        if seed.query() != query {
                            return Err(StoreError::new(format!(
                                "unqualified reference seed {:?} disagrees with request {:?}",
                                seed.query(),
                                query,
                            )));
                        }
                        let site_metadata = seed.site_metadata();
                        let engine = BatchResolutionEngine::new(self.session.lexical_source);
                        let seed_batch = ReferenceSeedBatch::new([seed]);
                        let batch =
                            engine.resolve_reference_batch(&seed_batch, self.cancellation)?;
                        let (batch_answers, batch_completion, metrics) = batch.into_parts();
                        self.binding_metrics.accumulate(metrics);
                        self.observe_cancellation_completion(&batch_completion);
                        let mut batch_answers = batch_answers.into_vec().into_iter();
                        let (returned_reference, answer) = batch_answers
                            .next()
                            .expect("an issued arity-one seed must return one answer")
                            .into_parts();
                        assert_eq!(
                            returned_reference, reference,
                            "an issued arity-one seed must return its reference answer"
                        );
                        assert!(
                            batch_answers.next().is_none(),
                            "an issued arity-one seed must not return extra answers"
                        );
                        self.observe_resolution_answer_cancellation_evidence(&answer);
                        if self.cancellation_observed {
                            break;
                        }
                        self.install_root_site_metadata(site_metadata);
                        answer
                    } else {
                        ResolutionAnswer::new(
                            Vec::new(),
                            Vec::new(),
                            if self.cancellation.is_cancelled() {
                                incomplete_cancelled()
                            } else {
                                incomplete(reference)
                            },
                        )
                    }
                } else {
                    let engine = BatchResolutionEngine::new(self.session.lexical_source);
                    let (answer, metrics) = engine.resolve_reference_with_metrics(
                        ResolutionQuery::new(reference),
                        self.cancellation,
                    )?;
                    self.binding_metrics.accumulate(metrics);
                    answer
                };
                self.observe_resolution_answer_cancellation_evidence(&answer);
                if self.cancellation_observed {
                    break;
                }
                let Some(cached_answer) =
                    clone_answer_with_poll(&answer, self.cancellation, &mut self.work)
                else {
                    self.cancellation_observed = true;
                    break;
                };
                self.lexical_answers.insert(reference, cached_answer);
                Some(answer)
            };
            if let Some(answer) = answer {
                answers.insert(reference, answer);
            }
        }

        if self.cancellation_observed {
            return Ok(answers);
        }
        let mut signature_definitions = BTreeSet::new();
        for (&reference, obligation) in &calls_by_reference {
            if self.poll_cancelled() {
                return Ok(answers);
            }
            if obligation.get(self.session).row().callee_reference() != reference {
                unreachable!("call obligation map is keyed by callee reference");
            }
            for &target in answers
                .get(&reference)
                .into_iter()
                .flat_map(ResolutionAnswer::targets)
            {
                signature_definitions.insert(target);
            }
        }
        let signature_definitions = signature_definitions.into_iter().collect::<Vec<_>>();
        let signature_read = self
            .session
            .signatures_for_definitions(&signature_definitions)?;
        let Some(signature_rows) = self.accept_session_read(signature_read) else {
            return Ok(answers);
        };
        let mut signatures = HashMap::default();
        for signature in signature_rows {
            assert!(
                signatures
                    .insert(signature.get(self.session).row().definition(), signature)
                    .is_none(),
                "one selected definition has at most one callable signature"
            );
        }
        for reference in references {
            let Some(obligation) = calls_by_reference.get(&reference) else {
                continue;
            };
            let Some(answer) = answers.remove(&reference) else {
                continue;
            };
            let obligation = obligation.get(self.session).row().clone();
            let Some(answer) =
                self.apply_call_applicability(answer, &obligation, &signatures, previous_states)?
            else {
                break;
            };
            self.observe_resolution_answer_cancellation_evidence(&answer);
            if self.cancellation_observed {
                break;
            }
            answers.insert(reference, answer);
        }
        let Some(visibility_completion_by_target) =
            self.declaration_visibility_completions_for_answers(&answers)?
        else {
            return Ok(answers);
        };
        if !self
            .apply_declaration_visibility_to_answers(&mut answers, &visibility_completion_by_target)
        {
            return Ok(answers);
        }
        Ok(answers)
    }

    /// Refine the already shadow-selected callable candidates.
    ///
    /// This is deliberately query-local. Signatures remain declaration
    /// properties, calls remain reference-local obligations, and no selected
    /// reference-to-definition pair survives the operation.
    fn apply_call_applicability(
        &mut self,
        answer: ResolutionAnswer,
        obligation: &LoweredCallApplicabilityObligation,
        signatures: &HashMap<
            SemanticId,
            InternedFactRow<SelectedTypedRow<LoweredCallableSignatureProperty>>,
        >,
        previous_states: &HashMap<SemanticId, TypedFrontierState>,
    ) -> StoreResult<Option<ResolutionAnswer>> {
        let applicability_reason = obligation.applicability_reason();
        let call_inventory_complete =
            completion_without_unsupported_semantic(obligation.completion(), applicability_reason)
                == ResolutionCompletion::Complete;
        let (answer_targets, answer_witnesses, answer_completion) = answer.into_parts();
        let mut completion = answer_completion.combine(obligation.completion());
        let mut targets = Vec::new();
        let mut proven_count = 0_usize;
        let mut unresolved_count = 0_usize;

        for &target in answer_targets.iter() {
            if self.poll_cancelled() {
                self.observe_cancellation_completion(&completion);
                return Ok(None);
            }
            let Some(signature) = signatures.get(&target) else {
                targets.push(target);
                unresolved_count = unresolved_count
                    .checked_add(1)
                    .expect("unresolved call candidate count must fit usize");
                completion = completion.combine(&incomplete(service_reason(
                    b"missing-callable-signature",
                    &[
                        obligation.callee_reference().as_bytes().as_slice(),
                        target.as_bytes().as_slice(),
                    ],
                )));
                continue;
            };

            let signature = {
                let signature = signature.get(self.session);
                let mut cancelled = || poll_cancelled(self.cancellation, &mut self.work);
                let Some(signature) = signature.row().clone_with_poll(&mut cancelled) else {
                    self.cancellation_observed = true;
                    self.observe_cancellation_completion(&completion);
                    return Ok(None);
                };
                signature
            };
            for parameter in signature.parameters() {
                self.demand_slot(parameter.slot());
            }
            completion = completion.combine(signature.completion());
            let Some(classification) = self.classify_call_candidate(
                obligation,
                &signature,
                call_inventory_complete,
                previous_states,
                &mut completion,
            ) else {
                self.observe_cancellation_completion(&completion);
                return Ok(None);
            };
            match classification {
                CallCandidateApplicability::ProvenApplicable => {
                    targets.push(target);
                    proven_count = proven_count
                        .checked_add(1)
                        .expect("proven call candidate count must fit usize");
                }
                CallCandidateApplicability::ArityMismatch => {}
                CallCandidateApplicability::Unresolved => {
                    targets.push(target);
                    unresolved_count = unresolved_count
                        .checked_add(1)
                        .expect("unresolved call candidate count must fit usize");
                }
            }
        }

        debug_assert!(targets.windows(2).all(|pair| pair[0] < pair[1]));
        let mut discharge_applicability =
            proven_count == 1 && unresolved_count == 0 && targets.len() == 1;
        let mut discharged_semantics = BTreeSet::new();
        if discharge_applicability {
            discharged_semantics.insert(applicability_reason);
            if !obligation.argument_slots().is_empty()
                && obligation
                    .eligible_rules()
                    .contains(&ResolutionEngineRuleKind::DirectOwnerExactPrimitiveDominance)
            {
                let target = targets[0];
                let signature = signatures[&target].get(self.session).row().clone();
                match self.prove_direct_owner_exact_primitive_dominance(
                    target,
                    obligation,
                    &signature,
                    previous_states,
                    &completion,
                )? {
                    SemanticDischargeProof::Proven(reasons) => {
                        discharged_semantics.extend(reasons);
                    }
                    SemanticDischargeProof::Unproven => {}
                    SemanticDischargeProof::Cancelled => return Ok(None),
                }
            }
        } else if answer_targets.is_empty()
            && answer_witnesses.is_empty()
            && unresolved_count == 0
            && obligation
                .eligible_rules()
                .contains(&ResolutionEngineRuleKind::DefaultConstruction)
        {
            match self.prove_default_construction(
                obligation,
                call_inventory_complete,
                previous_states,
                &completion,
            )? {
                SemanticDischargeProof::Proven(reasons) => {
                    discharge_applicability = true;
                    discharged_semantics.insert(applicability_reason);
                    discharged_semantics.extend(reasons);
                }
                SemanticDischargeProof::Unproven => {}
                SemanticDischargeProof::Cancelled => return Ok(None),
            }
        }
        if discharge_applicability {
            let Some(filtered) = completion_without_unsupported_semantics_with_poll(
                &completion,
                &discharged_semantics,
                &mut || self.poll_cancelled(),
            ) else {
                return Ok(None);
            };
            completion = filtered;
        }
        let mut witnesses = Vec::with_capacity(answer_witnesses.len());
        for witness in answer_witnesses.into_vec() {
            if self.poll_cancelled() {
                return Ok(None);
            }
            if targets.binary_search(&witness.target()).is_err() {
                continue;
            }
            if discharge_applicability {
                let (reference, target, steps, witness_completion) = witness.into_parts();
                let Some(witness_completion) = completion_without_unsupported_semantics_with_poll(
                    &witness_completion,
                    &discharged_semantics,
                    &mut || self.poll_cancelled(),
                ) else {
                    return Ok(None);
                };
                witnesses.push(super::model::ResolutionWitness::new(
                    reference,
                    target,
                    steps,
                    witness_completion,
                ));
            } else {
                witnesses.push(witness);
            }
        }
        Ok(Some(ResolutionAnswer::new(targets, witnesses, completion)))
    }

    /// Prove a producer-authorized targetless default-constructor fallback
    /// without fabricating a declaration. The `ImplicitConstructor` marker is
    /// conservative direct-construction proof eligibility, not a complete
    /// inventory of constructor existence. This operation also closes access,
    /// enclosing-instance requirements, and every explicitly represented
    /// superclass marker. Abstract superclass chains therefore remain
    /// incomplete until constructor existence and root instantiability have
    /// separate source-owned rows.
    fn prove_default_construction(
        &mut self,
        obligation: &LoweredCallApplicabilityObligation,
        call_inventory_complete: bool,
        previous_states: &HashMap<SemanticId, TypedFrontierState>,
        call_completion: &ResolutionCompletion,
    ) -> StoreResult<SemanticDischargeProof> {
        if !call_inventory_complete
            || obligation.receiver_slot().is_some()
            || obligation.explicit_type_argument_count() != 0
            || !obligation.argument_slots().is_empty()
        {
            return Ok(SemanticDischargeProof::Unproven);
        }

        let route_read = self
            .session
            .routes_for_references(&[obligation.callee_reference()])?;
        let Some(routes) = self.accept_session_read(route_read) else {
            return Ok(SemanticDischargeProof::Cancelled);
        };
        let [route] = routes.as_slice() else {
            return Ok(SemanticDischargeProof::Unproven);
        };
        let route = *route.get(self.session);
        if route.row().namespace() != ResolutionNamespace::Constructor
            || route.row().projection_kind() != BindingProjectionKind::TargetConstructorOwnerType
            || route.row().projection_output_slot() != obligation.result_slot()
        {
            return Ok(SemanticDischargeProof::Unproven);
        }

        self.demand_slot(route.row().qualifier_slot());
        let Some(qualifier) = previous_states.get(&route.row().qualifier_slot()) else {
            return Ok(SemanticDischargeProof::Unproven);
        };
        let [ResolutionSlotValue::TypeObject(constructed)] = qualifier.possible_values() else {
            return Ok(SemanticDischargeProof::Unproven);
        };
        if constructed.indirection() != 0 {
            return Ok(SemanticDischargeProof::Unproven);
        }

        let mut owner = constructed.identity();
        let mut visited = HashSet::default();
        let mut dependency_slots = BTreeSet::from([route.row().qualifier_slot()]);
        let mut discharged = BTreeSet::new();
        loop {
            if self.poll_cancelled() {
                return Ok(SemanticDischargeProof::Cancelled);
            }
            if !visited.insert(owner) {
                return Ok(SemanticDischargeProof::Unproven);
            }

            let visibility_read = self
                .session
                .declaration_visibilities_for_definitions(&[owner])?;
            let Some(visibilities) = self.accept_session_read(visibility_read) else {
                return Ok(SemanticDischargeProof::Cancelled);
            };
            let visibility_proven = match visibilities.as_slice() {
                [visibility] => {
                    let visibility = visibility.get(self.session);
                    visibility.row().definition() == owner
                        && visibility.row().visibility() == DeclaredVisibility::Public
                }
                _ => false,
            };
            if !visibility_proven {
                return Ok(SemanticDischargeProof::Unproven);
            }

            let requirement_read = self
                .session
                .construction_requirements_for_definitions(&[owner])?;
            let Some(requirements) = self.accept_session_read(requirement_read) else {
                return Ok(SemanticDischargeProof::Cancelled);
            };
            if !requirements.is_empty() {
                return Ok(SemanticDischargeProof::Unproven);
            }

            let gap_read = self.session.property_gaps_for_definitions(&[owner])?;
            let Some(gaps) = self.accept_session_read(gap_read) else {
                return Ok(SemanticDischargeProof::Cancelled);
            };
            let gaps = gaps
                .into_iter()
                .map(|gap| {
                    let gap = gap.get(self.session);
                    (
                        gap.row().kind(),
                        gap.row().reason_semantic(),
                        gap.row().frontier(),
                    )
                })
                .collect::<Vec<_>>();
            let implicit = gaps
                .iter()
                .filter(|gap| gap.0 == ResolutionGapKind::ImplicitConstructor)
                .collect::<Vec<_>>();
            let [implicit] = implicit.as_slice() else {
                return Ok(SemanticDischargeProof::Unproven);
            };
            discharged.insert(implicit.1);
            for gap in &gaps {
                if gap.0 == ResolutionGapKind::UnsupportedVisibility {
                    return Ok(SemanticDischargeProof::Unproven);
                }
                if gap.0 == ResolutionGapKind::UnsupportedHierarchyTraversal {
                    discharged.insert(gap.1);
                }
            }

            let supertype_read = self.session.supertypes_for_definitions(&[owner])?;
            let Some(supertypes) = self.accept_session_read(supertype_read) else {
                return Ok(SemanticDischargeProof::Cancelled);
            };
            let supertypes = supertypes
                .into_iter()
                .map(|row| {
                    let row = row.get(self.session);
                    (row.row().kind(), row.row().frontier())
                })
                .collect::<Vec<_>>();
            let superclasses = supertypes
                .iter()
                .filter(|row| row.0 == ResolutionSupertypeKind::Superclass)
                .collect::<Vec<_>>();
            match superclasses.as_slice() {
                [] => {
                    let supertype_frontiers =
                        supertypes.iter().map(|row| row.1).collect::<BTreeSet<_>>();
                    let implicit_root_count = gaps
                        .iter()
                        .filter(|gap| {
                            gap.0 == ResolutionGapKind::UnsupportedHierarchyTraversal
                                && !supertype_frontiers.contains(&gap.2)
                        })
                        .count();
                    if implicit_root_count != 1 {
                        return Ok(SemanticDischargeProof::Unproven);
                    }
                    break;
                }
                [superclass] => {
                    let superclass_frontier = superclass.1;
                    let edge_gap_count = gaps
                        .iter()
                        .filter(|gap| {
                            gap.0 == ResolutionGapKind::UnsupportedHierarchyTraversal
                                && gap.2 == superclass_frontier
                        })
                        .count();
                    if edge_gap_count != 1 {
                        return Ok(SemanticDischargeProof::Unproven);
                    }
                    self.demand_slot(superclass_frontier);
                    let Some(state) = previous_states.get(&superclass_frontier) else {
                        return Ok(SemanticDischargeProof::Unproven);
                    };
                    let [ResolutionSlotValue::TypeObject(superclass_type)] =
                        state.possible_values()
                    else {
                        return Ok(SemanticDischargeProof::Unproven);
                    };
                    if superclass_type.indirection() != 0 {
                        return Ok(SemanticDischargeProof::Unproven);
                    }
                    dependency_slots.insert(superclass_frontier);
                    owner = superclass_type.identity();
                }
                _ => return Ok(SemanticDischargeProof::Unproven),
            }
        }

        let mut all_discharged = discharged.clone();
        all_discharged.insert(obligation.applicability_reason());
        let Some(residual_call_completion) = completion_without_unsupported_semantics_with_poll(
            call_completion,
            &all_discharged,
            &mut || self.poll_cancelled(),
        ) else {
            return Ok(SemanticDischargeProof::Cancelled);
        };
        if residual_call_completion != ResolutionCompletion::Complete {
            return Ok(SemanticDischargeProof::Unproven);
        }
        for dependency_slot in dependency_slots {
            if self.poll_cancelled() {
                return Ok(SemanticDischargeProof::Cancelled);
            }
            let Some(residual) = completion_without_unsupported_semantics_with_poll(
                previous_states[&dependency_slot].completion(),
                &discharged,
                &mut || self.poll_cancelled(),
            ) else {
                return Ok(SemanticDischargeProof::Cancelled);
            };
            if residual != ResolutionCompletion::Complete {
                return Ok(SemanticDischargeProof::Unproven);
            }
        }
        Ok(SemanticDischargeProof::Proven(discharged))
    }

    /// The first Java overload-dominance theorem implemented here is
    /// intentionally narrow: one directly owned, fixed-arity, non-generic
    /// method whose parameter identities exactly equal primitive argument
    /// identities dominates only the receiver owner's still-open ancestor
    /// alternatives. Conversions, generic inference, varargs, sibling
    /// overloads, and any other open route remain unresolved.
    fn prove_direct_owner_exact_primitive_dominance(
        &mut self,
        target: SemanticId,
        obligation: &LoweredCallApplicabilityObligation,
        signature: &LoweredCallableSignatureProperty,
        previous_states: &HashMap<SemanticId, TypedFrontierState>,
        call_completion: &ResolutionCompletion,
    ) -> StoreResult<SemanticDischargeProof> {
        if signature.definition() != target
            || signature.completion() != &ResolutionCompletion::Complete
            || obligation.explicit_type_argument_count() != 0
            || signature.type_parameter_count() != 0
            || obligation.argument_slots().len() != signature.parameters().len()
            || signature
                .parameters()
                .iter()
                .any(|parameter| parameter.repeated())
        {
            return Ok(SemanticDischargeProof::Unproven);
        }
        let Some(receiver_slot) = obligation.receiver_slot() else {
            return Ok(SemanticDischargeProof::Unproven);
        };
        let Some(receiver) = previous_states.get(&receiver_slot) else {
            return Ok(SemanticDischargeProof::Unproven);
        };
        let [
            ResolutionSlotValue::Runtime {
                ty: receiver_type, ..
            },
        ] = receiver.possible_values()
        else {
            return Ok(SemanticDischargeProof::Unproven);
        };
        if receiver_type.indirection() != 0 {
            return Ok(SemanticDischargeProof::Unproven);
        }

        let route_read = self
            .session
            .routes_for_references(&[obligation.callee_reference()])?;
        let Some(routes) = self.accept_session_read(route_read) else {
            return Ok(SemanticDischargeProof::Cancelled);
        };
        let route_matches = match routes.as_slice() {
            [route] => {
                let route = route.get(self.session);
                route.row().namespace() == ResolutionNamespace::Callable
                    && route.row().qualifier_slot() == receiver_slot
                    && route.row().projection_kind()
                        == BindingProjectionKind::TargetCallableResultType
            }
            _ => false,
        };
        if !route_matches {
            return Ok(SemanticDischargeProof::Unproven);
        }

        let owner_read = self.session.member_owners_for_definitions(&[target])?;
        let Some(owners) = self.accept_session_read(owner_read) else {
            return Ok(SemanticDischargeProof::Cancelled);
        };
        let owner_matches = match owners.as_slice() {
            [owner] => {
                let owner = owner.get(self.session);
                owner.row().definition() == target
                    && owner.row().owner_definition() == receiver_type.identity()
                    && owner.row().kind() == ResolutionMemberKind::Method
                    && qualifier_compatible(
                        owner.row().qualifier_compatibility(),
                        QualifierCategory::Runtime,
                    )
            }
            _ => false,
        };
        if !owner_matches {
            return Ok(SemanticDischargeProof::Unproven);
        }

        let visibility_read = self
            .session
            .declaration_visibilities_for_definitions(&[target])?;
        let Some(visibilities) = self.accept_session_read(visibility_read) else {
            return Ok(SemanticDischargeProof::Cancelled);
        };
        let visibility_matches = match visibilities.as_slice() {
            [visibility] => {
                let visibility = visibility.get(self.session);
                visibility.row().definition() == target
                    && visibility.row().visibility() == DeclaredVisibility::Public
            }
            _ => false,
        };
        if !visibility_matches {
            return Ok(SemanticDischargeProof::Unproven);
        }

        let gap_read = self
            .session
            .property_gaps_for_definitions(&[receiver_type.identity()])?;
        let Some(gaps) = self.accept_session_read(gap_read) else {
            return Ok(SemanticDischargeProof::Cancelled);
        };
        let hierarchy_reasons = gaps
            .iter()
            .filter_map(|gap| {
                let gap = gap.get(self.session);
                (gap.row().kind() == ResolutionGapKind::UnsupportedHierarchyTraversal)
                    .then(|| gap.row().reason_semantic())
            })
            .collect::<BTreeSet<_>>();
        let Some(receiver_residual) = completion_without_unsupported_semantics_with_poll(
            receiver.completion(),
            &hierarchy_reasons,
            &mut || self.poll_cancelled(),
        ) else {
            return Ok(SemanticDischargeProof::Cancelled);
        };
        if receiver_residual != ResolutionCompletion::Complete {
            return Ok(SemanticDischargeProof::Unproven);
        }

        let mut primitive_identities = BTreeSet::new();
        for (&argument_slot, parameter) in obligation
            .argument_slots()
            .iter()
            .zip(signature.parameters())
        {
            if self.poll_cancelled() {
                return Ok(SemanticDischargeProof::Cancelled);
            }
            let Some(argument_type) = previous_states
                .get(&argument_slot)
                .and_then(exact_singleton_runtime_type)
            else {
                return Ok(SemanticDischargeProof::Unproven);
            };
            let Some(parameter_type) = previous_states
                .get(&parameter.slot())
                .and_then(exact_singleton_runtime_type)
            else {
                return Ok(SemanticDischargeProof::Unproven);
            };
            if argument_type != parameter_type || argument_type.indirection() != 0 {
                return Ok(SemanticDischargeProof::Unproven);
            }
            primitive_identities.insert(argument_type.identity());
        }
        if primitive_identities.is_empty() {
            return Ok(SemanticDischargeProof::Unproven);
        }
        let primitive_identities = primitive_identities.into_iter().collect::<Vec<_>>();
        let intrinsic_read = self
            .session
            .intrinsics_for_type_identities(&primitive_identities)?;
        let Some(intrinsics) = self.accept_session_read(intrinsic_read) else {
            return Ok(SemanticDischargeProof::Cancelled);
        };
        let requested = primitive_identities
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let mut proven_primitives = BTreeSet::new();
        for intrinsic in intrinsics {
            if self.poll_cancelled() {
                return Ok(SemanticDischargeProof::Cancelled);
            }
            let (kind, value_count) = {
                let intrinsic = intrinsic.get(self.session).row();
                (
                    intrinsic.kind(),
                    intrinsic.frontier().possible_values().len(),
                )
            };
            for value_index in 0..value_count {
                if self.poll_cancelled() {
                    return Ok(SemanticDischargeProof::Cancelled);
                }
                let value = intrinsic
                    .get(self.session)
                    .row()
                    .frontier()
                    .possible_values()[value_index];
                let identity = value.ty().identity();
                if !requested.contains(&identity) {
                    return Err(StoreError::new(format!(
                        "primitive identity read returned unrequested type {identity}"
                    )));
                }
                if kind != IntrinsicTypeKind::Primitive {
                    return Ok(SemanticDischargeProof::Unproven);
                }
                proven_primitives.insert(identity);
            }
        }
        if proven_primitives != requested {
            return Ok(SemanticDischargeProof::Unproven);
        }

        let mut all_discharged = hierarchy_reasons.clone();
        all_discharged.insert(obligation.applicability_reason());
        let Some(residual_call_completion) = completion_without_unsupported_semantics_with_poll(
            call_completion,
            &all_discharged,
            &mut || self.poll_cancelled(),
        ) else {
            return Ok(SemanticDischargeProof::Cancelled);
        };
        if residual_call_completion != ResolutionCompletion::Complete {
            return Ok(SemanticDischargeProof::Unproven);
        }
        Ok(SemanticDischargeProof::Proven(hierarchy_reasons))
    }

    fn classify_call_candidate(
        &mut self,
        obligation: &LoweredCallApplicabilityObligation,
        signature: &LoweredCallableSignatureProperty,
        call_inventory_complete: bool,
        previous_states: &HashMap<SemanticId, TypedFrontierState>,
        completion: &mut ResolutionCompletion,
    ) -> Option<CallCandidateApplicability> {
        if !call_inventory_complete
            || signature.completion() != &ResolutionCompletion::Complete
            || obligation.explicit_type_argument_count() != 0
            || signature.type_parameter_count() != 0
            || signature
                .parameters()
                .iter()
                .any(|parameter| parameter.repeated())
        {
            return Some(CallCandidateApplicability::Unresolved);
        }
        if obligation.argument_slots().len() != signature.parameters().len() {
            return Some(CallCandidateApplicability::ArityMismatch);
        }
        if obligation.argument_slots().is_empty() {
            return Some(CallCandidateApplicability::ProvenApplicable);
        }

        let mut identical_runtime_types = true;
        for (&argument_slot, parameter) in obligation
            .argument_slots()
            .iter()
            .zip(signature.parameters())
        {
            if self.poll_cancelled() {
                return None;
            }
            let argument_type = previous_states.get(&argument_slot).and_then(|state| {
                *completion = completion.combine(state.completion());
                exact_singleton_runtime_type(state)
            });
            let parameter_type = previous_states.get(&parameter.slot()).and_then(|state| {
                *completion = completion.combine(state.completion());
                exact_singleton_runtime_type(state)
            });
            if argument_type.is_none()
                || parameter_type.is_none()
                || argument_type != parameter_type
            {
                // A language-specific conversion may still make this
                // candidate applicable. This tranche never guesses one.
                identical_runtime_types = false;
            }
        }
        Some(if identical_runtime_types {
            CallCandidateApplicability::ProvenApplicable
        } else {
            CallCandidateApplicability::Unresolved
        })
    }

    fn hierarchy_one(
        &mut self,
        identity: SemanticId,
        completion: ResolutionCompletion,
    ) -> Option<HierarchyEvidence> {
        if let ResolutionCompletion::Incomplete(reasons) = &completion {
            let cancellation = self.cancellation;
            let work = &mut self.work;
            let cancellation_observed = &mut self.cancellation_observed;
            let hierarchy = &mut *self.hierarchy;
            if hierarchy.cancellation_atom_ids.insert(identity) {
                for &reason in reasons.iter() {
                    hierarchy.cancellation_reasons.include_reason_with_poll(
                        reason,
                        cancellation,
                        work,
                        cancellation_observed,
                    );
                }
                *cancellation_observed |= cancellation.is_cancelled();
            }
        }
        let cancellation = self.cancellation;
        let work = &mut self.work;
        let evidence = self.hierarchy.evidence.one(identity, completion, &mut || {
            poll_cancelled(cancellation, work)
        });
        if evidence.is_none() {
            self.cancellation_observed = true;
        }
        evidence
    }

    fn hierarchy_derived_one(
        &mut self,
        identity: SemanticId,
        completion: ResolutionCompletion,
    ) -> Option<HierarchyEvidence> {
        // Derived operands are just as real for cancellation fallback as raw
        // decoded source boxes. Ledger the complete box before interning it so
        // a later token edge cannot erase already-established failure evidence.
        self.observe_cancellation_completion(&completion);
        self.hierarchy_one(identity, completion)
    }

    fn observe_hierarchy_support_completion(
        &mut self,
        identity: SemanticId,
        completion: &ResolutionCompletion,
    ) {
        self.observe_hierarchy_raw_cancellation_completion(completion);
        self.publish_hierarchy_support_completion(identity, completion);
    }

    fn publish_hierarchy_support_completion(
        &mut self,
        identity: SemanticId,
        completion: &ResolutionCompletion,
    ) {
        let contains_cancelled = match completion {
            ResolutionCompletion::Complete => false,
            ResolutionCompletion::Incomplete(reasons) => {
                reasons.contains(&ResolutionIncompleteReason::Cancelled)
            }
        };
        assert!(
            !contains_cancelled,
            "only an exhausted hierarchy support read can publish its exact completion"
        );
        let existing = self
            .hierarchy
            .cancellation_support_completions
            .get(&identity);
        if let Some(existing) = existing {
            let equal = equal_completion_reasons_with_poll(
                existing,
                completion,
                self.cancellation,
                &mut self.work,
                &mut self.cancellation_observed,
            );
            assert!(
                equal,
                "one hierarchy support-read identity has conflicting exact completion boxes"
            );
            self.cancellation_observed |= self.cancellation.is_cancelled();
            return;
        }
        if self.cancellation_observed || self.cancellation.is_cancelled() {
            self.cancellation_observed = true;
            return;
        }

        let retained = match completion {
            ResolutionCompletion::Complete => ResolutionCompletion::Complete,
            ResolutionCompletion::Incomplete(reasons) => {
                let mut retained = Vec::with_capacity(reasons.len());
                for &reason in reasons.iter() {
                    self.poll_cancellation_ledger();
                    retained.push(reason);
                }
                ResolutionCompletion::Incomplete(retained.into_boxed_slice().into())
            }
        };
        self.cancellation_observed |= self.cancellation.is_cancelled();
        if self.cancellation_observed {
            return;
        }
        let hierarchy = &mut *self.hierarchy;
        assert!(
            hierarchy
                .cancellation_support_completions
                .insert(identity, retained)
                .is_none(),
            "one hierarchy support-read completion is retained once"
        );
    }

    fn observe_cancelled_hierarchy_support_completion(
        &mut self,
        completion: &ResolutionCompletion,
    ) {
        // A cancelled replay is operational evidence, not a second semantic
        // outcome for the immutable support-read identity. Preserve the full
        // returned box in both cancellation ledgers without installing or
        // comparing it against an earlier exhausted support completion.
        self.observe_hierarchy_raw_cancellation_completion(completion);
        self.cancellation_observed = true;
    }

    fn cached_hierarchy_reference_parts(
        &mut self,
        reference: SemanticId,
        transferred_reasons: &BTreeSet<SemanticId>,
    ) -> Option<(Box<[SemanticId]>, ResolutionCompletion)> {
        if self.poll_cancelled() {
            return None;
        }
        let (target_count, reason_count) = {
            let hierarchy = &*self.hierarchy;
            let answer = hierarchy
                .reference_answers
                .get(&reference)
                .expect("every route-free hierarchy edge has a cached answer");
            let reason_count = match answer.completion() {
                ResolutionCompletion::Complete => None,
                ResolutionCompletion::Incomplete(reasons) => Some(reasons.len()),
            };
            (answer.targets().len(), reason_count)
        };
        let mut targets = Vec::with_capacity(target_count);
        for index in 0..target_count {
            if self.poll_cancelled() {
                return None;
            }
            targets.push(self.hierarchy.reference_answers[&reference].targets()[index]);
        }
        let Some(reason_count) = reason_count else {
            return Some((targets.into_boxed_slice(), ResolutionCompletion::Complete));
        };
        let mut retained = Vec::with_capacity(reason_count);
        let mut removed = false;
        for index in 0..reason_count {
            if self.poll_cancelled() {
                return None;
            }
            let reason = {
                let hierarchy = &*self.hierarchy;
                let ResolutionCompletion::Incomplete(reasons) =
                    hierarchy.reference_answers[&reference].completion()
                else {
                    unreachable!("a cached hierarchy answer completion is immutable")
                };
                *reasons
                    .get(index)
                    .expect("cached reason index is in bounds")
            };
            if let ResolutionIncompleteReason::UnsupportedSemantic(semantic) = reason
                && transferred_reasons.contains(&semantic)
            {
                removed = true;
            } else {
                retained.push(reason);
            }
        }
        if self.poll_cancelled() {
            return None;
        }
        let completion = if removed && retained.is_empty() {
            ResolutionCompletion::Complete
        } else {
            ResolutionCompletion::Incomplete(retained.into_boxed_slice().into())
        };
        Some((targets.into_boxed_slice(), completion))
    }

    fn accept_hierarchy_owned_reference_answers(
        &mut self,
        support_identity: SemanticId,
        completion: &ResolutionCompletion,
        answers: &[(SemanticId, ResolutionAnswer)],
    ) -> bool {
        // Batch completion does not subsume answer or witness completion.
        // Drain every fully returned logical operand before cancellation can
        // discard the answer vector or semantic support publication.
        self.observe_hierarchy_raw_cancellation_completion(completion);
        for (_, answer) in answers {
            self.poll_cancellation_ledger();
            self.observe_hierarchy_raw_resolution_answer_cancellation_evidence(answer);
        }
        if completion.contains_reason(ResolutionIncompleteReason::Cancelled)
            || self.cancellation_observed
            || self.cancellation.is_cancelled()
        {
            self.cancellation_observed = true;
            return false;
        }
        self.publish_hierarchy_support_completion(support_identity, completion);
        !self.cancellation_observed && !self.cancellation.is_cancelled()
    }

    fn observe_hierarchy_qualifier_completion(
        &mut self,
        qualifier_slot: SemanticId,
        completion: &ResolutionCompletion,
    ) {
        self.observe_cancellation_completion(completion);
        let ResolutionCompletion::Incomplete(reasons) = completion else {
            return;
        };
        for &reason in reasons.iter() {
            // The qualifier state is a fully returned source operand.
            // Finish retaining its whole reason union even if a token
            // edge arrives during this second cancellation-only pass.
            self.poll_cancellation_ledger();
            let identity = hierarchy_qualifier_cancellation_atom_identity(qualifier_slot, reason);
            let hierarchy = &mut *self.hierarchy;
            if hierarchy.cancellation_atom_ids.insert(identity) {
                hierarchy.cancellation_reasons.include_reason_after_poll(
                    reason,
                    self.cancellation,
                    &mut self.work,
                    &mut self.cancellation_observed,
                );
            }
        }
        self.cancellation_observed |= self.cancellation.is_cancelled();
    }

    fn hierarchy_union(
        &mut self,
        left: HierarchyEvidence,
        right: HierarchyEvidence,
    ) -> HierarchyEvidence {
        self.hierarchy.evidence.union(left, right)
    }

    fn hierarchy_transfer_union(
        &mut self,
        left: HierarchyEvidence,
        right: HierarchyEvidence,
    ) -> HierarchyEvidence {
        self.hierarchy.transfers.union(left, right)
    }

    fn hierarchy_transfer_shift(
        &mut self,
        transfer: HierarchyEvidence,
        ticks: u32,
    ) -> HierarchyEvidence {
        self.hierarchy.transfers.shift(transfer, ticks)
    }

    fn hierarchy_transfer_one(&mut self, reason: SemanticId) -> Option<HierarchyEvidence> {
        let cancellation = self.cancellation;
        let work = &mut self.work;
        let transfer = self
            .hierarchy
            .transfers
            .one(reason, incomplete(reason), &mut || {
                poll_cancelled(cancellation, work)
            });
        if transfer.is_none() {
            self.cancellation_observed = true;
        }
        transfer
    }

    fn hierarchy_transfer_from_completion(
        &mut self,
        completion: &ResolutionCompletion,
        hierarchy_reasons: &BTreeSet<SemanticId>,
    ) -> Option<HierarchyEvidence> {
        let mut transfer = HierarchyEvidence::Complete;
        let ResolutionCompletion::Incomplete(reasons) = completion else {
            return Some(transfer);
        };
        for &reason in reasons.iter() {
            if self.poll_cancelled() {
                return None;
            }
            let ResolutionIncompleteReason::UnsupportedSemantic(reason) = reason else {
                continue;
            };
            if !hierarchy_reasons.contains(&reason) {
                continue;
            }
            let atom = self.hierarchy_transfer_one(reason)?;
            transfer = self.hierarchy_transfer_union(transfer, atom);
        }
        Some(transfer)
    }

    fn register_hierarchy_global_evidence(
        &mut self,
        label: &[u8],
        completion: ResolutionCompletion,
    ) -> bool {
        let Some(evidence) = self.hierarchy_one(hierarchy_global_atom_identity(label), completion)
        else {
            return false;
        };
        let hierarchy = &mut *self.hierarchy;
        let previous = hierarchy
            .global_evidence
            .take()
            .unwrap_or(HierarchyEvidence::Complete);
        let combined = hierarchy.evidence.union(previous, evidence);
        hierarchy.global_evidence = Some(combined);
        true
    }

    fn hierarchy_shift(&mut self, evidence: HierarchyEvidence, ticks: u32) -> HierarchyEvidence {
        self.hierarchy.evidence.shift(evidence, ticks)
    }

    fn ensure_hierarchy_member_owner_metadata(
        &mut self,
        definitions: &[SemanticId],
    ) -> StoreResult<bool> {
        debug_assert!(definitions.windows(2).all(|pair| pair[0] < pair[1]));
        let mut missing = Vec::new();
        for &definition in definitions {
            if self.poll_cancelled() {
                return Ok(false);
            }
            if !self
                .hierarchy
                .member_owner_metadata
                .contains_key(&definition)
            {
                missing.push(definition);
            }
        }
        for definition_chunk in missing.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
            if self.poll_cancelled() {
                return Ok(false);
            }
            let support_identity =
                hierarchy_support_read_identity(b"member-owner-by-definition", definition_chunk);
            let owner_read = self
                .session
                .member_owners_for_definitions(definition_chunk)?;
            let (mut rows, evidence) = match owner_read {
                SessionFactRead::Exhausted { rows, evidence } => (rows, evidence),
                SessionFactRead::Cancelled(evidence) => {
                    self.observe_cancelled_hierarchy_support_completion(&evidence);
                    return Ok(false);
                }
            };
            self.observe_hierarchy_support_completion(support_identity, &evidence);
            let mut staged = HashMap::default();
            for &definition in definition_chunk {
                self.poll_cancellation_ledger();
                self.hierarchy.metadata_work.definition_classifications += 1;
                assert!(
                    staged
                        .insert(definition, ExactMemberOwnerMetadata::Missing)
                        .is_none(),
                    "one hierarchy definition has one exact metadata classification"
                );
            }
            // The returned relation is source-sized even though the request is
            // bounded. Drain it under polling after a token edge as well, so a
            // hostile conflicting-row vector is never dropped in one opaque
            // source-sized destructor span.
            while let Some(row) = rows.pop() {
                self.poll_cancellation_ledger();
                if self.cancellation_observed {
                    continue;
                }
                let definition = row.get(self.session).row().definition();
                assert!(
                    definition_chunk.binary_search(&definition).is_ok(),
                    "member-owner metadata belongs to one requested hierarchy definition"
                );
                self.hierarchy.metadata_work.row_visits += 1;
                let metadata = staged
                    .get_mut(&definition)
                    .expect("member-owner metadata belongs to one requested definition");
                match metadata {
                    ExactMemberOwnerMetadata::Missing => {
                        *metadata = ExactMemberOwnerMetadata::Unique(row);
                    }
                    ExactMemberOwnerMetadata::Unique(_) => {
                        *metadata = ExactMemberOwnerMetadata::Conflicting;
                    }
                    ExactMemberOwnerMetadata::Conflicting => {}
                }
            }
            if self.cancellation_observed || self.cancellation.is_cancelled() {
                self.cancellation_observed = true;
                return Ok(false);
            }
            let hierarchy = &mut *self.hierarchy;
            for &definition in definition_chunk {
                let metadata = staged
                    .remove(&definition)
                    .expect("one requested definition was classified");
                assert!(
                    hierarchy
                        .member_owner_metadata
                        .insert(definition, metadata)
                        .is_none(),
                    "one hierarchy definition is classified once per operation"
                );
            }
            assert!(staged.is_empty());
        }
        Ok(true)
    }

    fn stage_hierarchy_local_nodes(
        &mut self,
        chunk: &[HierarchyNodeKey],
    ) -> StoreResult<Option<Vec<StagedHierarchyLocalNode>>> {
        let owners = chunk.iter().map(|key| key.owner).collect::<Vec<_>>();
        let scope_support_identity =
            hierarchy_support_read_identity(b"member-scope-by-definition", &owners);
        let scope_read = self.session.member_scopes_for_definitions(&owners)?;
        let (scope_rows, scope_completion) = match scope_read {
            SessionFactRead::Exhausted { rows, evidence } => (rows, evidence),
            SessionFactRead::Cancelled(evidence) => {
                self.observe_cancelled_hierarchy_support_completion(&evidence);
                return Ok(None);
            }
        };
        self.observe_hierarchy_support_completion(scope_support_identity, &scope_completion);
        if self.cancellation_observed {
            return Ok(None);
        }
        let mut scopes = HashMap::default();
        for scope in scope_rows {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let scope = scope.get(self.session);
            assert!(
                scopes
                    .insert(scope.row().definition(), scope.row().scope_head())
                    .is_none(),
                "one selected definition has at most one member scope"
            );
        }

        let gap_support_identity =
            hierarchy_support_read_identity(b"property-gap-by-definition", &owners);
        let gap_read = self.session.property_gaps_for_definitions(&owners)?;
        let gap_rows = match gap_read {
            SessionFactRead::Exhausted { rows, evidence } => {
                self.observe_hierarchy_support_completion(gap_support_identity, &evidence);
                rows
            }
            SessionFactRead::Cancelled(evidence) => {
                self.observe_cancelled_hierarchy_support_completion(&evidence);
                return Ok(None);
            }
        };
        if self.cancellation_observed {
            return Ok(None);
        }
        let mut hierarchy_reasons = HashMap::<SemanticId, BTreeSet<SemanticId>>::default();
        for gap in gap_rows {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let gap = gap.get(self.session).row();
            let kind = gap.kind();
            let reason = gap.reason_semantic();
            let definition = gap.definition();
            if kind == ResolutionGapKind::UnsupportedHierarchyTraversal {
                self.observe_cancellation_completion(&incomplete(reason));
                hierarchy_reasons
                    .entry(definition)
                    .or_default()
                    .insert(reason);
            }
        }

        let mut staged = Vec::with_capacity(chunk.len());
        for &key in chunk {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let scope_head = scopes.get(&key.owner).copied();
            let reasons = hierarchy_reasons.remove(&key.owner).unwrap_or_default();
            let mut evidence = HierarchyEvidence::Complete;
            if scope_head.is_none() {
                let reason = service_reason(
                    b"missing-member-scope",
                    &[
                        key.shape.lookup.as_bytes().as_slice(),
                        key.shape.namespace.identity_label().as_bytes(),
                        match key.shape.category {
                            QualifierCategory::Type => b"type",
                            QualifierCategory::Runtime => b"runtime",
                        },
                        &key.shape.receiver_indirection.to_le_bytes(),
                        key.owner.as_bytes().as_slice(),
                    ],
                );
                let Some(missing_evidence) = self.hierarchy_derived_one(
                    hierarchy_node_atom_identity(b"missing-member-scope", key),
                    incomplete(reason),
                ) else {
                    return Ok(None);
                };
                evidence = self.hierarchy_union(evidence, missing_evidence);
            }
            staged.push(StagedHierarchyLocalNode {
                key,
                scope_head,
                hierarchy_reasons: reasons,
                evidence,
                cutoff_evidence: HierarchyEvidence::Complete,
                transfer: HierarchyEvidence::Complete,
                direct_definitions: BTreeSet::new(),
            });
        }
        assert!(
            hierarchy_reasons.is_empty(),
            "property gaps returned an owner outside the requested local-node chunk"
        );
        Ok(Some(staged))
    }

    fn ensure_hierarchy_local_nodes(&mut self, keys: &[HierarchyNodeKey]) -> StoreResult<bool> {
        let mut missing = BTreeSet::new();
        for &key in keys {
            if self.poll_cancelled() {
                return Ok(false);
            }
            if !self.hierarchy.local_nodes.contains_key(&key) {
                missing.insert(key);
            }
        }
        let mut ordered_missing = Vec::with_capacity(missing.len());
        while let Some(key) = missing.pop_first() {
            if self.poll_cancelled() {
                return Ok(false);
            }
            ordered_missing.push(key);
        }
        let mut missing_cursor = 0_usize;
        while missing_cursor < ordered_missing.len() {
            let shape = ordered_missing[missing_cursor].shape;
            let chunk_len = ordered_missing[missing_cursor..]
                .iter()
                .take(MAX_SOURCE_ROWS_PER_BATCH)
                .take_while(|key| key.shape == shape)
                .count();
            let chunk_end = missing_cursor + chunk_len;
            let chunk = &ordered_missing[missing_cursor..chunk_end];
            missing_cursor = chunk_end;
            if self.poll_cancelled() {
                return Ok(false);
            }
            debug_assert!(chunk.windows(2).all(|pair| pair[0] < pair[1]));
            debug_assert!(chunk.iter().all(|key| key.shape == chunk[0].shape));
            let Some(mut staged) = self.stage_hierarchy_local_nodes(chunk)? else {
                return Ok(false);
            };
            let mut request_to_staged = Vec::new();
            let mut requests = Vec::new();
            for (staged_ordinal, local) in staged.iter().enumerate() {
                if self.poll_cancelled() {
                    return Ok(false);
                }
                let Some(scope_head) = local.scope_head else {
                    continue;
                };
                let request_ordinal = requests.len();
                requests.push(BatchCandidateRequest::new(
                    request_ordinal,
                    closed_endpoint(scope_head, [local.key.shape.lookup]),
                ));
                request_to_staged.push(staged_ordinal);
            }

            let mut matches = Vec::new();
            if !requests.is_empty() {
                let (returned_matches, unconditional, branches) = read_forward_candidate_artifacts(
                    self.session.lexical_source,
                    &requests,
                    self.cancellation,
                    None,
                    &mut self.work,
                    &mut self.cancellation_observed,
                )?;
                self.observe_cancellation_completion(&unconditional);
                for completion in branches.iter() {
                    self.observe_cancellation_completion(completion);
                }
                if self.cancellation_observed || self.cancellation.is_cancelled() {
                    self.cancellation_observed = true;
                    return Ok(false);
                }
                matches = returned_matches;
                if !self
                    .register_hierarchy_global_evidence(b"local-candidate-inventory", unconditional)
                {
                    return Ok(false);
                }
                assert_eq!(
                    branches.len(),
                    requests.len(),
                    "candidate source returns one branch completion per local request"
                );
                for (request_ordinal, mut completion) in branches.into_vec().into_iter().enumerate()
                {
                    if self.poll_cancelled() {
                        return Ok(false);
                    }
                    let staged_ordinal = request_to_staged[request_ordinal];
                    let Some(transfer) = self.hierarchy_transfer_from_completion(
                        &completion,
                        &staged[staged_ordinal].hierarchy_reasons,
                    ) else {
                        return Ok(false);
                    };
                    staged[staged_ordinal].transfer = self.hierarchy_transfer_union(
                        staged[staged_ordinal].transfer.clone(),
                        transfer,
                    );
                    let Some(filtered_completion) =
                        completion_without_unsupported_semantics_with_poll(
                            &completion,
                            &staged[staged_ordinal].hierarchy_reasons,
                            &mut || self.poll_cancelled(),
                        )
                    else {
                        return Ok(false);
                    };
                    completion = filtered_completion;
                    let scope_head = staged[staged_ordinal]
                        .scope_head
                        .expect("one candidate request has one member scope");
                    let Some(branch_evidence) = self.hierarchy_one(
                        hierarchy_local_branch_atom_identity(
                            scope_head,
                            staged[staged_ordinal].key.shape.lookup,
                        ),
                        completion,
                    ) else {
                        return Ok(false);
                    };
                    staged[staged_ordinal].evidence = self
                        .hierarchy_union(staged[staged_ordinal].evidence.clone(), branch_evidence);
                }
            }

            let mut candidate_set = BTreeSet::new();
            for matched in &matches {
                if self.poll_cancelled() {
                    return Ok(false);
                }
                candidate_set.insert(matched.candidate());
            }
            let mut hydrated = HashMap::default();
            let mut candidates = Vec::with_capacity(candidate_set.len());
            while let Some(candidate) = candidate_set.pop_first() {
                if self.poll_cancelled() {
                    return Ok(false);
                }
                candidates.push(candidate);
            }
            for candidate_chunk in candidates.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
                if self.poll_cancelled() {
                    return Ok(false);
                }
                let returned = self
                    .session
                    .lexical_source
                    .hydrate_candidate_paths(candidate_chunk, self.cancellation)?;
                for (_, path) in &returned {
                    if self.poll_cancelled() {
                        return Ok(false);
                    }
                    self.observe_cancellation_completion(path.completion());
                }
                if self.cancellation_observed || self.cancellation.is_cancelled() {
                    self.cancellation_observed = true;
                    return Ok(false);
                }
                let requested = candidate_chunk.iter().copied().collect::<BTreeSet<_>>();
                let mut observed = BTreeSet::new();
                for (identity, path) in returned {
                    if self.poll_cancelled() {
                        return Ok(false);
                    }
                    if !requested.contains(&identity) || !observed.insert(identity) {
                        return Err(StoreError::new(format!(
                            "hierarchy hydration returned unrequested or duplicate candidate {identity:?}"
                        )));
                    }
                    assert!(
                        hydrated.insert(identity, path).is_none(),
                        "one hierarchy candidate is hydrated once"
                    );
                }
                if observed != requested {
                    return Err(StoreError::new(format!(
                        "hierarchy hydration omitted candidates: requested {requested:?}, returned {observed:?}"
                    )));
                }
            }

            let mut candidate_evidence =
                HashMap::<CandidatePathIdentity, HierarchyEvidence>::default();
            let mut match_ends = Vec::with_capacity(matches.len());
            let mut end_nodes = BTreeSet::new();
            for matched in &matches {
                if self.poll_cancelled() {
                    return Ok(false);
                }
                let staged_ordinal = request_to_staged[matched.request_ordinal()];
                let candidate = hydrated.get(&matched.candidate()).ok_or_else(|| {
                    StoreError::new(format!(
                        "matched hierarchy candidate {:?} was not hydrated",
                        matched.candidate()
                    ))
                })?;
                let Some(transfer) = self.hierarchy_transfer_from_completion(
                    candidate.completion(),
                    &staged[staged_ordinal].hierarchy_reasons,
                ) else {
                    return Ok(false);
                };
                staged[staged_ordinal].transfer = self
                    .hierarchy_transfer_union(staged[staged_ordinal].transfer.clone(), transfer);
                let evidence_key = matched.candidate();
                let evidence = if let Some(evidence) = candidate_evidence.get(&evidence_key) {
                    evidence.clone()
                } else {
                    let Some(completion) = completion_without_unsupported_semantics_with_poll(
                        candidate.completion(),
                        &staged[staged_ordinal].hierarchy_reasons,
                        &mut || self.poll_cancelled(),
                    ) else {
                        return Ok(false);
                    };
                    let Some(evidence) = self.hierarchy_one(
                        hierarchy_local_candidate_atom_identity(matched.candidate()),
                        completion,
                    ) else {
                        return Ok(false);
                    };
                    candidate_evidence.insert(evidence_key, evidence.clone());
                    evidence
                };
                staged[staged_ordinal].evidence =
                    self.hierarchy_union(staged[staged_ordinal].evidence.clone(), evidence);
                let endpoint = requests[matched.request_ordinal()].endpoint();
                let Some(identity) = PartialPath::new_with_poll(
                    endpoint.clone(),
                    endpoint.clone(),
                    Vec::<PrecedenceStep>::new().into_boxed_slice(),
                    Vec::<WitnessStep>::new().into_boxed_slice(),
                    ResolutionCompletion::Complete,
                    &mut || self.poll_cancelled(),
                ) else {
                    return Ok(false);
                };
                let composition = identity.concatenate_with_poll(
                    candidate,
                    AlphaRenamingId::hash_bytes(matched.candidate().path().as_bytes()),
                    &mut || self.poll_cancelled(),
                );
                let Some(composition) = composition else {
                    return Ok(false);
                };
                let end = match composition {
                    Ok(path) if endpoint_is_balanced(path.end()) => Some(path.end().node()),
                    Ok(_) | Err(_) => None,
                };
                if let Some(end) = end {
                    end_nodes.insert(end);
                }
                match_ends.push((staged_ordinal, end));
            }

            let mut ordered_end_nodes = Vec::with_capacity(end_nodes.len());
            while let Some(node) = end_nodes.pop_first() {
                if self.poll_cancelled() {
                    return Ok(false);
                }
                ordered_end_nodes.push(node);
            }
            let end_nodes = ordered_end_nodes;
            let mut classifications = HashMap::default();
            for node_chunk in end_nodes.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
                if self.poll_cancelled() {
                    return Ok(false);
                }
                let returned = self
                    .session
                    .lexical_source
                    .classify_endpoint_nodes(node_chunk, self.cancellation)?;
                if self.cancellation.is_cancelled() {
                    self.cancellation_observed = true;
                    return Ok(false);
                }
                let requested = node_chunk.iter().copied().collect::<BTreeSet<_>>();
                let mut observed = BTreeSet::new();
                for classification in returned {
                    if self.poll_cancelled() {
                        return Ok(false);
                    }
                    if !requested.contains(&classification.node())
                        || !observed.insert(classification.node())
                    {
                        return Err(StoreError::new(format!(
                            "hierarchy endpoint classification returned unrequested or duplicate node {}",
                            classification.node()
                        )));
                    }
                    classifications.insert(classification.node(), classification);
                }
                if observed != requested {
                    return Err(StoreError::new(format!(
                        "hierarchy endpoint classification omitted nodes: requested {requested:?}, returned {observed:?}"
                    )));
                }
            }

            let mut possible_definitions = BTreeSet::new();
            let mut classified_matches = Vec::new();
            for (staged_ordinal, end) in match_ends {
                if self.poll_cancelled() {
                    return Ok(false);
                }
                let definition = end.and_then(|node| {
                    classifications
                        .get(&node)
                        .expect("every balanced hierarchy endpoint was classified")
                        .definition()
                });
                if let Some(definition) = definition {
                    possible_definitions.insert(definition);
                }
                classified_matches.push((staged_ordinal, definition));
            }
            let mut ordered_definitions = Vec::with_capacity(possible_definitions.len());
            while let Some(definition) = possible_definitions.pop_first() {
                if self.poll_cancelled() {
                    return Ok(false);
                }
                ordered_definitions.push(definition);
            }
            let possible_definitions = ordered_definitions;
            if !self.ensure_hierarchy_member_owner_metadata(&possible_definitions)? {
                return Ok(false);
            }
            let expected_kind = chunk[0]
                .shape
                .inherited_member_kind()
                .expect("hierarchy local lookup is used only for inherited member namespaces");
            for (staged_ordinal, definition) in classified_matches {
                if self.poll_cancelled() {
                    return Ok(false);
                }
                let Some(definition) = definition else {
                    continue;
                };
                self.hierarchy.metadata_work.match_checks += 1;
                let metadata = {
                    let hierarchy = &*self.hierarchy;
                    match hierarchy.member_owner_metadata.get(&definition) {
                        Some(ExactMemberOwnerMetadata::Unique(property)) => Some(*property),
                        _ => None,
                    }
                };
                let metadata_matches = metadata.is_some_and(|property| {
                    let property = property.get(self.session);
                    property.row().owner_definition() == staged[staged_ordinal].key.owner
                        && Some(property.row().owner_scope_head())
                            == staged[staged_ordinal].scope_head
                        && property.row().kind() == expected_kind
                });
                // Once lexical structure reaches a balanced definition, this
                // owner shadows its supertypes even if selected member-owner
                // metadata is missing or inconsistent. Fail closed at this
                // layer and retain an exact structural gap instead of forging
                // an inherited success.
                staged[staged_ordinal].direct_definitions.insert(definition);
                if !metadata_matches {
                    let key = staged[staged_ordinal].key;
                    let reason = hierarchy_member_owner_reason(key, definition);
                    let Some(evidence) = self.hierarchy_derived_one(
                        hierarchy_member_owner_atom_identity(key, definition),
                        incomplete(reason),
                    ) else {
                        return Ok(false);
                    };
                    let cutoff_evidence = evidence.clone();
                    staged[staged_ordinal].evidence =
                        self.hierarchy_union(staged[staged_ordinal].evidence.clone(), evidence);
                    staged[staged_ordinal].cutoff_evidence = self.hierarchy_union(
                        staged[staged_ordinal].cutoff_evidence.clone(),
                        cutoff_evidence,
                    );
                }
            }
            if self.poll_cancelled() {
                return Ok(false);
            }
            let mut nodes = Vec::with_capacity(staged.len());
            for mut local in staged {
                let mut direct_definitions = Vec::with_capacity(local.direct_definitions.len());
                while let Some(definition) = local.direct_definitions.pop_first() {
                    if self.poll_cancelled() {
                        return Ok(false);
                    }
                    direct_definitions.push(definition);
                }
                let node = HierarchyLocalNode {
                    direct_definitions: direct_definitions.into_boxed_slice(),
                    evidence: local.evidence,
                    cutoff_evidence: local.cutoff_evidence,
                    transfer: local.transfer,
                    candidate_inventory_observed: local.scope_head.is_some(),
                };
                nodes.push((local.key, node));
            }
            if self.poll_cancelled() {
                return Ok(false);
            }
            let hierarchy = &mut *self.hierarchy;
            for (key, node) in nodes {
                assert!(
                    hierarchy.local_nodes.insert(key, node).is_none(),
                    "one hierarchy local node is published once after its whole batch validates"
                );
            }
        }
        Ok(!self.poll_cancelled())
    }

    fn ensure_hierarchy_reference_answers(
        &mut self,
        references: &[SemanticId],
    ) -> StoreResult<bool> {
        let mut lexical_answers = HashMap::<SemanticId, ResolutionAnswer>::default();
        let mut cached_references = HashSet::default();
        let mut reference_cancellation_evidence = HashMap::default();
        let mut missing_references = Vec::new();
        for &reference in references {
            if self.poll_cancelled() {
                return Ok(false);
            }
            let cached = {
                let hierarchy = &*self.hierarchy;
                (
                    hierarchy.reference_answers.contains_key(&reference),
                    hierarchy
                        .reference_cancellation_evidence
                        .get(&reference)
                        .cloned(),
                )
            };
            match cached {
                (true, Some(evidence)) => {
                    cached_references.insert(reference);
                    reference_cancellation_evidence.insert(reference, evidence);
                }
                (false, None) => missing_references.push(reference),
                _ => panic!("one cached hierarchy reference owns both answer and evidence"),
            }
        }
        for reference_chunk in missing_references.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
            let seed_support_identity =
                hierarchy_support_read_identity(b"reference-seed-by-reference", reference_chunk);
            let queries = reference_chunk
                .iter()
                .copied()
                .map(ResolutionQuery::new)
                .collect::<Vec<_>>();
            let outcome = self
                .session
                .lexical_source
                .lookup_reference_seeds(&queries, self.cancellation)?;
            let (rows, terminal, evidence) = outcome.into_parts();
            if terminal == ReferenceSeedReadTerminal::Cancelled {
                self.observe_cancelled_hierarchy_support_completion(&evidence);
                return Ok(false);
            }
            assert_eq!(terminal, ReferenceSeedReadTerminal::Exhausted);
            self.observe_hierarchy_raw_cancellation_completion(&evidence);
            for row in rows.iter() {
                self.poll_cancellation_ledger();
                if let Some(seed) = row.seed() {
                    self.observe_hierarchy_raw_cancellation_completion(seed.completion());
                }
            }
            if rows.len() != queries.len() {
                return Err(StoreError::new(format!(
                    "exhausted hierarchy reference seed read returned {} rows for {} queries",
                    rows.len(),
                    queries.len()
                )));
            }
            let mut staged_seeds = Vec::new();
            let mut staged_absences = Vec::new();
            for (ordinal, row) in rows.into_vec().into_iter().enumerate() {
                if row.request_ordinal() != ordinal || row.query() != queries[ordinal] {
                    return Err(StoreError::new(format!(
                        "hierarchy reference seed row ({}, {:?}) disagrees with request ({ordinal}, {:?})",
                        row.request_ordinal(),
                        row.query(),
                        queries[ordinal]
                    )));
                }
                let reference = row.query().reference();
                if let Some(seed) = row.into_seed() {
                    staged_seeds.push(seed);
                } else {
                    staged_absences.push(reference);
                }
            }
            self.publish_hierarchy_support_completion(seed_support_identity, &evidence);
            if self.cancellation_observed || self.cancellation.is_cancelled() {
                self.cancellation_observed = true;
                return Ok(false);
            }
            let mut seeds_by_fragment = BTreeMap::<BindingFragmentId, Vec<ReferenceSeed>>::new();
            for seed in staged_seeds {
                self.poll_cancellation_ledger();
                seeds_by_fragment
                    .entry(seed.fragment())
                    .or_default()
                    .push(seed);
            }
            for reference in staged_absences {
                self.poll_cancellation_ledger();
                let completion = incomplete(reference);
                self.observe_hierarchy_raw_cancellation_completion(&completion);
                assert!(
                    lexical_answers
                        .insert(
                            reference,
                            ResolutionAnswer::new(Vec::new(), Vec::new(), completion,),
                        )
                        .is_none(),
                    "one route-free hierarchy reference has one seed outcome"
                );
            }
            if self.cancellation_observed {
                return Ok(false);
            }
            for (fragment, seeds) in seeds_by_fragment {
                if self.poll_cancelled() {
                    return Ok(false);
                }
                let batch_references = seeds
                    .iter()
                    .map(ReferenceSeed::reference)
                    .collect::<Vec<_>>();
                debug_assert!(
                    batch_references.windows(2).all(|pair| pair[0] < pair[1]),
                    "one hierarchy reference batch is canonically ordered"
                );
                let batch_support_identity = hierarchy_support_fragment_batch_identity(
                    b"owned-reference-batch",
                    fragment,
                    &batch_references,
                );
                let engine = BatchResolutionEngine::new(self.session.lexical_source);
                let seed_batch = ReferenceSeedBatch::new(seeds);
                let answer = engine.resolve_owned_reference_batch(seed_batch, self.cancellation)?;
                let (answers, completion, metrics) = answer.into_parts();
                self.binding_metrics.accumulate(metrics);
                let answers = answers
                    .into_vec()
                    .into_iter()
                    .map(|answer| answer.into_parts())
                    .collect::<Vec<_>>();
                if !self.accept_hierarchy_owned_reference_answers(
                    batch_support_identity,
                    &completion,
                    &answers,
                ) {
                    return Ok(false);
                }
                for (reference, answer) in answers {
                    if self.poll_cancelled() {
                        return Ok(false);
                    }
                    assert!(
                        lexical_answers.insert(reference, answer).is_none(),
                        "one route-free hierarchy reference is resolved once"
                    );
                }
            }
        }
        if self.cancellation_observed {
            return Ok(false);
        }
        assert_eq!(
            lexical_answers.len() + cached_references.len(),
            references.len(),
            "every route-free hierarchy reference has one immutable lexical answer"
        );
        // A fully resolved route-free supertype reference is one logical
        // raw cancellation operand at the hierarchy boundary. Keep its
        // unfiltered inner lexical union atomic and hash-consed across
        // diamonds. Each edge builds a separately filtered semantic
        // residual below from the cached answer.
        for &reference in &missing_references {
            if self.poll_cancelled() {
                return Ok(false);
            }
            let answer = &lexical_answers[&reference];
            let Some(completion) =
                clone_resolution_completion_with_poll(answer.completion(), &mut || {
                    self.poll_cancelled()
                })
            else {
                return Ok(false);
            };
            let Some(evidence) =
                self.hierarchy_one(hierarchy_reference_atom_identity(reference), completion)
            else {
                return Ok(false);
            };
            reference_cancellation_evidence.insert(reference, evidence);
        }
        if self.poll_cancelled() {
            return Ok(false);
        }
        for reference_chunk in missing_references.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
            if self.poll_cancelled() {
                return Ok(false);
            }
            let hierarchy = &mut *self.hierarchy;
            for &reference in reference_chunk {
                let answer = lexical_answers
                    .remove(&reference)
                    .expect("one newly resolved hierarchy reference answer is staged");
                assert!(
                    hierarchy
                        .reference_answers
                        .insert(reference, answer)
                        .is_none(),
                    "one immutable hierarchy reference answer is published once"
                );
                assert!(
                    hierarchy
                        .reference_cancellation_evidence
                        .insert(
                            reference,
                            reference_cancellation_evidence[&reference].clone(),
                        )
                        .is_none(),
                    "one immutable hierarchy reference evidence atom is published once"
                );
            }
        }
        assert!(lexical_answers.is_empty());
        Ok(!self.poll_cancelled())
    }

    fn ensure_hierarchy_edge_nodes(&mut self, owners: &[SemanticId]) -> StoreResult<bool> {
        let mut missing = BTreeSet::new();
        for &owner in owners {
            if self.poll_cancelled() {
                return Ok(false);
            }
            if !self.hierarchy.edge_nodes.contains_key(&owner) {
                missing.insert(owner);
            }
        }
        let mut ordered_missing = Vec::with_capacity(missing.len());
        while let Some(key) = missing.pop_first() {
            if self.poll_cancelled() {
                return Ok(false);
            }
            ordered_missing.push(key);
        }
        let mut missing_cursor = 0_usize;
        while missing_cursor < ordered_missing.len() {
            let chunk_len = ordered_missing[missing_cursor..]
                .len()
                .min(MAX_SOURCE_ROWS_PER_BATCH);
            let chunk_end = missing_cursor + chunk_len;
            let chunk = &ordered_missing[missing_cursor..chunk_end];
            missing_cursor = chunk_end;
            let owners = chunk.to_vec();

            let supertype_support_identity =
                hierarchy_support_read_identity(b"supertype-by-definition", &owners);
            let supertype_read = self.session.supertypes_for_definitions(&owners)?;
            let (supertype_rows, supertype_completion) = match supertype_read {
                SessionFactRead::Exhausted { rows, evidence } => (rows, evidence),
                SessionFactRead::Cancelled(evidence) => {
                    self.observe_cancelled_hierarchy_support_completion(&evidence);
                    return Ok(false);
                }
            };
            self.observe_hierarchy_support_completion(
                supertype_support_identity,
                &supertype_completion,
            );
            if self.cancellation_observed {
                return Ok(false);
            }
            let mut properties = HashMap::<
                SemanticId,
                Vec<InternedFactRow<SelectedTypedRow<LoweredSupertypeProperty>>>,
            >::default();
            let mut references = BTreeSet::new();
            let mut explicit_frontiers = HashSet::default();
            for property in supertype_rows {
                if self.poll_cancelled() {
                    return Ok(false);
                }
                let row = property.get(self.session);
                references.insert(row.row().reference());
                explicit_frontiers.insert((row.row().definition(), row.row().frontier()));
                properties
                    .entry(row.row().definition())
                    .or_default()
                    .push(property);
            }

            let gap_support_identity =
                hierarchy_support_read_identity(b"property-gap-by-definition", &owners);
            let gap_read = self.session.property_gaps_for_definitions(&owners)?;
            let gap_rows = match gap_read {
                SessionFactRead::Exhausted { rows, evidence } => {
                    self.observe_hierarchy_support_completion(gap_support_identity, &evidence);
                    rows
                }
                SessionFactRead::Cancelled(evidence) => {
                    self.observe_cancelled_hierarchy_support_completion(&evidence);
                    return Ok(false);
                }
            };
            if self.cancellation_observed {
                return Ok(false);
            }
            let mut gap_evidence =
                HashMap::<(SemanticId, SemanticId), Vec<(SemanticId, HierarchyEvidence)>>::default(
                );
            let mut implicit_gap_evidence =
                HashMap::<SemanticId, Vec<HierarchyEvidence>>::default();
            for gap in gap_rows {
                if self.poll_cancelled() {
                    return Ok(false);
                }
                let (kind, reason, definition, frontier, atom_identity) = {
                    let gap = gap.get(self.session);
                    (
                        gap.row().kind(),
                        gap.row().reason_semantic(),
                        gap.row().definition(),
                        gap.row().frontier(),
                        hierarchy_gap_atom_identity(gap),
                    )
                };
                if kind != ResolutionGapKind::UnsupportedHierarchyTraversal {
                    continue;
                }
                let completion = incomplete(reason);
                self.observe_cancellation_completion(&completion);
                let Some(evidence) = self.hierarchy_one(atom_identity, completion) else {
                    return Ok(false);
                };
                let key = (definition, frontier);
                if explicit_frontiers.contains(&key) {
                    gap_evidence
                        .entry(key)
                        .or_default()
                        .push((reason, evidence));
                } else {
                    implicit_gap_evidence
                        .entry(definition)
                        .or_default()
                        .push(evidence);
                }
            }

            let mut ordered_references = Vec::with_capacity(references.len());
            while let Some(reference) = references.pop_first() {
                if self.poll_cancelled() {
                    return Ok(false);
                }
                ordered_references.push(reference);
            }
            let references = ordered_references;
            let mut qualified = HashSet::default();
            let mut route_evidence = HashMap::<SemanticId, Vec<HierarchyEvidence>>::default();
            for reference_chunk in references.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
                let route_support_identity = hierarchy_support_read_identity(
                    b"qualified-route-by-reference",
                    reference_chunk,
                );
                let route_read = self.session.routes_for_references(reference_chunk)?;
                let route_rows = match route_read {
                    SessionFactRead::Exhausted { rows, evidence } => {
                        self.observe_hierarchy_support_completion(
                            route_support_identity,
                            &evidence,
                        );
                        rows
                    }
                    SessionFactRead::Cancelled(evidence) => {
                        self.observe_cancelled_hierarchy_support_completion(&evidence);
                        return Ok(false);
                    }
                };
                if self.cancellation_observed {
                    return Ok(false);
                }
                for route in route_rows {
                    if self.poll_cancelled() {
                        return Ok(false);
                    }
                    let route = *route.get(self.session);
                    let edge_reference = route.row().reference();
                    qualified.insert(edge_reference);
                    let completion = incomplete(route.row().coarse_gap_reason());
                    self.observe_cancellation_completion(&completion);
                    let Some(evidence) =
                        self.hierarchy_one(hierarchy_route_atom_identity(&route), completion)
                    else {
                        return Ok(false);
                    };
                    route_evidence
                        .entry(edge_reference)
                        .or_default()
                        .push(evidence);
                }
            }
            let mut route_free_references = Vec::new();
            for &reference in &references {
                if self.poll_cancelled() {
                    return Ok(false);
                }
                if !qualified.contains(&reference) {
                    route_free_references.push(reference);
                }
            }
            if !self.ensure_hierarchy_reference_answers(&route_free_references)? {
                return Ok(false);
            }

            let mut staged = Vec::with_capacity(chunk.len());
            for &owner in chunk {
                if self.poll_cancelled() {
                    return Ok(false);
                }
                let mut node_evidence = HierarchyEvidence::Complete;
                for evidence in implicit_gap_evidence.remove(&owner).unwrap_or_default() {
                    if self.poll_cancelled() {
                        return Ok(false);
                    }
                    node_evidence = self.hierarchy_union(node_evidence, evidence);
                }
                let mut ordered_edges = BTreeMap::new();
                for property in properties.remove(&owner).unwrap_or_default() {
                    if self.poll_cancelled() {
                        return Ok(false);
                    }
                    let row = *property.get(self.session).row();
                    let mut hierarchy_evidence = HierarchyEvidence::Complete;
                    let mut transfer = HierarchyEvidence::Complete;
                    let mut transferred_reasons = BTreeSet::new();
                    for (reason, evidence) in gap_evidence
                        .remove(&(owner, row.frontier()))
                        .unwrap_or_default()
                    {
                        if self.poll_cancelled() {
                            return Ok(false);
                        }
                        hierarchy_evidence = self.hierarchy_union(hierarchy_evidence, evidence);
                        let Some(reason_transfer) = self.hierarchy_transfer_one(reason) else {
                            return Ok(false);
                        };
                        transferred_reasons.insert(reason);
                        transfer = self.hierarchy_transfer_union(transfer, reason_transfer);
                    }
                    for evidence in route_evidence
                        .get(&row.reference())
                        .into_iter()
                        .flatten()
                        .cloned()
                    {
                        if self.poll_cancelled() {
                            return Ok(false);
                        }
                        hierarchy_evidence = self.hierarchy_union(hierarchy_evidence, evidence);
                    }
                    if matches!(hierarchy_evidence, HierarchyEvidence::Complete) {
                        let reason = service_reason(
                            b"unresolved-supertype-edge",
                            &[
                                row.definition().as_bytes().as_slice(),
                                row.reference().as_bytes().as_slice(),
                                row.frontier().as_bytes().as_slice(),
                            ],
                        );
                        let completion = incomplete(reason);
                        let Some(evidence) = self.hierarchy_derived_one(
                            hierarchy_edge_atom_identity(
                                b"unresolved-supertype-edge",
                                row.definition(),
                                row.reference(),
                                row.frontier(),
                            ),
                            completion,
                        ) else {
                            return Ok(false);
                        };
                        hierarchy_evidence = evidence;
                    }
                    let route_free = !qualified.contains(&row.reference());
                    let (targets, residual_evidence) = if route_free {
                        let Some((targets, residual_completion)) = self
                            .cached_hierarchy_reference_parts(
                                row.reference(),
                                &transferred_reasons,
                            )
                        else {
                            return Ok(false);
                        };
                        let Some(residual_evidence) = self.hierarchy_one(
                            hierarchy_edge_atom_identity(
                                b"resolved-reference-residual",
                                owner,
                                row.reference(),
                                row.frontier(),
                            ),
                            residual_completion,
                        ) else {
                            return Ok(false);
                        };
                        (targets, residual_evidence)
                    } else {
                        (
                            Vec::<SemanticId>::new().into_boxed_slice(),
                            HierarchyEvidence::Complete,
                        )
                    };
                    let identity = (row.reference(), row.frontier());
                    assert!(
                        ordered_edges
                            .insert(
                                identity,
                                HierarchyEdge {
                                    reference: row.reference(),
                                    targets,
                                    residual_evidence,
                                    hierarchy_evidence,
                                    transfer,
                                },
                            )
                            .is_none(),
                        "one selected supertype edge has one reference/frontier identity"
                    );
                }
                let mut edges = Vec::with_capacity(ordered_edges.len());
                while let Some((_, edge)) = ordered_edges.pop_first() {
                    if self.poll_cancelled() {
                        return Ok(false);
                    }
                    edges.push(edge);
                }
                staged.push((
                    owner,
                    HierarchyEdgeNode {
                        edges: edges.into_boxed_slice(),
                        evidence: node_evidence,
                    },
                ));
            }
            assert!(properties.is_empty());
            assert!(implicit_gap_evidence.is_empty());
            assert!(gap_evidence.is_empty());
            if self.poll_cancelled() {
                return Ok(false);
            }
            let hierarchy = &mut *self.hierarchy;
            for (owner, node) in staged {
                assert!(
                    hierarchy.edge_nodes.insert(owner, node).is_none(),
                    "one immutable hierarchy edge node is published once after its whole batch validates"
                );
            }
        }
        Ok(!self.poll_cancelled())
    }

    fn cached_hierarchy_candidate_expressions(
        &mut self,
        shape: HierarchyLookupShape,
        roots: &[HierarchyRoot],
    ) -> StoreResult<Option<HierarchyOwnerSelection>> {
        let mut canonical_roots = BTreeSet::new();
        for &root in roots {
            if self.poll_cancelled() {
                return Ok(None);
            }
            canonical_roots.insert(root);
        }
        let mut summaries = Vec::with_capacity(canonical_roots.len());
        while let Some(root) = canonical_roots.pop_first() {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let Some(summary) = self
                .hierarchy
                .summary(HierarchyNodeKey {
                    shape,
                    owner: root.owner,
                })
                .cloned()
            else {
                return Ok(None);
            };
            summaries.push((root, summary));
        }
        let mut cutoff_depth = None;
        for (_, summary) in &summaries {
            if self.poll_cancelled() {
                return Ok(None);
            }
            if let Some(distance) = summary.candidate_distance {
                cutoff_depth =
                    Some(cutoff_depth.map_or(distance, |current: u32| current.min(distance)));
            }
        }
        let cutoff_tick = cutoff_depth
            .map(|depth| {
                depth
                    .checked_mul(2)
                    .expect("cached hierarchy cutoff tick must fit u32")
            })
            .unwrap_or(u32::MAX);
        let mut evidence = HierarchyEvidence::Complete;
        let mut transfer = HierarchyEvidence::Complete;
        let mut candidates = Vec::new();
        let mut retains_global_evidence = false;
        for (root, summary) in summaries {
            if self.poll_cancelled() {
                return Ok(None);
            }
            evidence = self.hierarchy_union(evidence, summary.evidence.clone());
            transfer = self.hierarchy_transfer_union(transfer, summary.transfer.clone());
            retains_global_evidence |= summary.retains_global_evidence;
            if summary.candidate_distance != cutoff_depth {
                continue;
            }
            if let Some(expression) = summary.candidates {
                candidates.push(HierarchySelectedCandidateExpression { expression, root });
            }
        }
        let truncated_evidence = {
            let cancellation = self.cancellation;
            let work = &mut self.work;
            self.hierarchy
                .evidence
                .truncate(&evidence, cutoff_tick, &mut || {
                    poll_cancelled(cancellation, work)
                })
        };
        let Some(evidence) = truncated_evidence else {
            self.cancellation_observed = true;
            return Ok(None);
        };
        // Preserve the donor traversal's cancellation polls and arena effects even
        // though only the later reverse consumer retains this transfer value.
        match cutoff_depth {
            None => transfer.clone(),
            Some(0) => HierarchyEvidence::Complete,
            Some(depth) => {
                let traversed_cutoff_tick = depth
                    .checked_mul(2)
                    .and_then(|tick| tick.checked_sub(1))
                    .expect("a positive hierarchy depth has one preceding traversal tick");
                let cancellation = self.cancellation;
                let work = &mut self.work;
                let traversed = self.hierarchy.transfers.truncate(
                    &transfer,
                    traversed_cutoff_tick,
                    &mut || poll_cancelled(cancellation, work),
                );
                let Some(traversed) = traversed else {
                    self.cancellation_observed = true;
                    return Ok(None);
                };
                traversed
            }
        };
        let truncated_transfer = {
            let cancellation = self.cancellation;
            let work = &mut self.work;
            self.hierarchy
                .transfers
                .truncate(&transfer, cutoff_tick, &mut || {
                    poll_cancelled(cancellation, work)
                })
        };
        let Some(transfer) = truncated_transfer else {
            self.cancellation_observed = true;
            return Ok(None);
        };
        Ok(Some(HierarchyOwnerSelection {
            candidates: candidates.into_boxed_slice(),
            evidence,
            transfer,
            retains_global_evidence,
        }))
    }

    fn materialize_hierarchy_candidate_expressions(
        &mut self,
        selection: HierarchyOwnerSelection,
    ) -> StoreResult<HierarchySelectionState> {
        let mut owners = Vec::new();
        let mut previous_owner_key = None;
        for selected in selection.candidates.into_vec() {
            if self.poll_cancelled() {
                return Ok(HierarchySelectionState::Pending);
            }
            let routes = {
                let cancellation = self.cancellation;
                let work = &mut self.work;
                self.hierarchy
                    .candidate_routes(Some(selected.expression), &mut || {
                        poll_cancelled(cancellation, work)
                    })
            };
            let Some(routes) = routes else {
                self.cancellation_observed = true;
                return Ok(HierarchySelectionState::Pending);
            };
            for (owner, ancestry) in routes {
                if self.poll_cancelled() {
                    return Ok(HierarchySelectionState::Pending);
                }
                let owner_key = (selected.root, owner);
                debug_assert!(previous_owner_key.is_none_or(|previous| previous < owner_key));
                previous_owner_key = Some(owner_key);
                owners.push(HierarchySelectedOwner {
                    owner,
                    root: selected.root,
                    ancestry,
                });
            }
        }
        Ok(HierarchySelectionState::Ready(HierarchySelection {
            owners: owners.into_boxed_slice(),
            evidence: selection.evidence,
            transfer: selection.transfer,
            retains_global_evidence: selection.retains_global_evidence,
        }))
    }

    fn ensure_hierarchy_owner_closure(
        &mut self,
        roots: &BTreeSet<SemanticId>,
    ) -> StoreResult<bool> {
        let mut pending = BTreeSet::new();
        for &root in roots {
            if self.poll_cancelled() {
                return Ok(false);
            }
            if !self.hierarchy.closure_contains(root) {
                pending.insert(root);
            }
        }
        let mut staged_owners = BTreeSet::new();
        let mut adjacency = BTreeMap::<SemanticId, BTreeSet<SemanticId>>::new();
        while !pending.is_empty() {
            let mut batch =
                Vec::with_capacity(pending.len().min(MAX_TYPED_FACT_REQUESTS_PER_BATCH));
            while batch.len() < MAX_TYPED_FACT_REQUESTS_PER_BATCH {
                let Some(owner) = pending.pop_first() else {
                    break;
                };
                if staged_owners.insert(owner) {
                    batch.push(owner);
                }
            }
            if batch.is_empty() {
                continue;
            }
            if !self.ensure_hierarchy_edge_nodes(&batch)? {
                return Ok(false);
            }
            for owner in batch {
                if self.poll_cancelled() {
                    return Ok(false);
                }
                self.hierarchy.derived_work.closure_owner_visits += 1;
                let edge_node = self
                    .hierarchy
                    .edge_node_snapshot(owner)
                    .expect("a closure owner has immutable hierarchy edges");
                let targets = adjacency.entry(owner).or_default();
                for edge_ordinal in 0..edge_node.edge_count {
                    // Poll once per edge even when its resolved target set is empty.
                    if self.poll_cancelled() {
                        return Ok(false);
                    }
                    let edge = self.hierarchy.edge_snapshot(owner, edge_ordinal);
                    for target_ordinal in 0..edge.target_count {
                        if self.poll_cancelled() {
                            return Ok(false);
                        }
                        let target =
                            self.hierarchy
                                .edge_target(owner, edge_ordinal, target_ordinal);
                        self.hierarchy.derived_work.closure_arc_visits += 1;
                        if self.hierarchy.closure_contains(target) {
                            continue;
                        }
                        targets.insert(target);
                        if !staged_owners.contains(&target) {
                            pending.insert(target);
                        }
                    }
                }
            }
        }
        let mut metrics = self.hierarchy.derived_work;
        let cycles = hierarchy_iterative_scc_terminals(
            &staged_owners,
            &adjacency,
            &mut metrics,
            &mut || self.poll_cancelled(),
        );
        self.hierarchy.derived_work = metrics;
        let Some(cycles) = cycles else {
            return Ok(false);
        };
        if self.poll_cancelled() {
            return Ok(false);
        }
        if self.cancellation.is_cancelled() {
            self.cancellation_observed = true;
            return Ok(false);
        }
        let generation = self.hierarchy.begin_publication();
        for owner in staged_owners {
            if self.poll_cancelled() {
                return Ok(false);
            }
            self.hierarchy.stage_closure_owner(generation, owner);
        }
        for (owner, cycle) in cycles {
            if self.poll_cancelled() {
                return Ok(false);
            }
            self.hierarchy.stage_cycle(generation, owner, cycle);
        }
        if self.cancellation.is_cancelled() {
            self.cancellation_observed = true;
            return Ok(false);
        }
        self.hierarchy.commit_publication(generation);
        Ok(true)
    }

    fn ensure_hierarchy_shape_summaries(
        &mut self,
        shape: HierarchyLookupShape,
        roots: &BTreeSet<SemanticId>,
    ) -> StoreResult<bool> {
        let mut pending = BTreeSet::new();
        for &root in roots {
            if self.poll_cancelled() {
                return Ok(false);
            }
            pending.insert(root);
        }
        let mut owners = BTreeSet::new();
        while let Some(owner) = pending.pop_first() {
            if self.poll_cancelled() {
                return Ok(false);
            }
            let key = HierarchyNodeKey { shape, owner };
            if self.hierarchy.contains_summary(key) {
                continue;
            }
            assert!(
                self.hierarchy.closure_contains(owner),
                "shape summary construction only walks an exhausted owner closure"
            );
            if !owners.insert(owner) {
                continue;
            }
            let cycle = self.hierarchy.cycle(owner);
            let edge_node = self
                .hierarchy
                .edge_node_snapshot(owner)
                .expect("a closure-sealed owner has immutable hierarchy edges");
            for edge_ordinal in 0..edge_node.edge_count {
                if self.poll_cancelled() {
                    return Ok(false);
                }
                let edge = self.hierarchy.edge_snapshot(owner, edge_ordinal);
                for target_ordinal in 0..edge.target_count {
                    if self.poll_cancelled() {
                        return Ok(false);
                    }
                    let target = self
                        .hierarchy
                        .edge_target(owner, edge_ordinal, target_ordinal);
                    assert!(
                        self.hierarchy.closure_contains(target),
                        "an exhausted owner closure cannot exit to an unsealed target"
                    );
                    // A malformed SCC is a semantic terminal. Its complete
                    // owner-only edge closure is already cached, but a lookup
                    // must hydrate only the other members needed to retain
                    // internal-edge evidence. Never enqueue an SCC exit: its
                    // local inventory and outgoing evidence are behind the
                    // terminal and belong only to cancellation observation.
                    if let Some(cycle) = cycle
                        && self.hierarchy.cycle(target) != Some(cycle)
                    {
                        continue;
                    }
                    pending.insert(target);
                }
            }
        }
        if owners.is_empty() {
            return Ok(!self.poll_cancelled());
        }
        let mut cycles = HashMap::default();
        for &owner in &owners {
            if self.poll_cancelled() {
                return Ok(false);
            }
            if let Some(cycle) = self.hierarchy.cycle(owner) {
                cycles.insert(owner, cycle);
            }
        }
        let mut local_keys = Vec::with_capacity(owners.len().saturating_sub(cycles.len()));
        for &owner in &owners {
            if self.poll_cancelled() {
                return Ok(false);
            }
            if !cycles.contains_key(&owner) {
                local_keys.push(HierarchyNodeKey { shape, owner });
            }
        }
        if !self.ensure_hierarchy_local_nodes(&local_keys)? {
            return Ok(false);
        }
        let mut expanded = HashSet::default();
        for &owner in &owners {
            if self.poll_cancelled() {
                return Ok(false);
            }
            expanded.insert(owner);
        }
        self.hierarchy.derived_work.summary_owner_visits += owners.len();
        Ok(self.seal_hierarchy_summaries(shape, &owners, &cycles, &expanded))
    }

    fn select_hierarchy_owners(
        &mut self,
        shape: HierarchyLookupShape,
        roots: &[HierarchyRoot],
    ) -> StoreResult<HierarchySelectionState> {
        let Some(selection) = self.select_hierarchy_candidate_expressions(shape, roots)? else {
            return Ok(HierarchySelectionState::Pending);
        };
        self.materialize_hierarchy_candidate_expressions(selection)
    }

    /// Select only structural candidate owners for reverse prevalidation.
    ///
    /// Forward replay needs one canonical ancestry per logical origin. Reverse
    /// narrowing needs only membership of the requested target owner, so it
    /// must not materialize the same depth-sized witness prefix for every
    /// route/value obligation. Exact owner membership is memoized per
    /// candidate-expression node without copying descendant owner sets. This
    /// is also the single direct-root, closure, global-cutoff, evidence, and
    /// transfer authority used by forward ancestry replay.
    fn select_hierarchy_candidate_expressions(
        &mut self,
        shape: HierarchyLookupShape,
        roots: &[HierarchyRoot],
    ) -> StoreResult<Option<HierarchyOwnerSelection>> {
        assert!(shape.inherited_member_kind().is_some());
        let mut canonical_roots = BTreeSet::new();
        let mut root_owners = BTreeSet::new();
        for &root in roots {
            if self.poll_cancelled() {
                return Ok(None);
            }
            canonical_roots.insert(root);
            root_owners.insert(root.owner);
        }
        let mut root_keys = Vec::with_capacity(root_owners.len());
        for &owner in &root_owners {
            if self.poll_cancelled() {
                return Ok(None);
            }
            root_keys.push(HierarchyNodeKey { shape, owner });
        }
        if !self.ensure_hierarchy_local_nodes(&root_keys)? {
            return Ok(None);
        }

        let mut direct_owners = BTreeSet::new();
        let mut direct_evidence = HierarchyEvidence::Complete;
        let mut direct_transfer = HierarchyEvidence::Complete;
        let mut retains_global_evidence = false;
        for &owner in &root_owners {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let local = self
                .hierarchy
                .local_snapshot(HierarchyNodeKey { shape, owner })
                .expect("an ensured reverse hierarchy root has local structure");
            retains_global_evidence |= local.candidate_inventory_observed;
            direct_transfer = self.hierarchy_transfer_union(direct_transfer, local.transfer);
            if !local.has_direct_definitions {
                direct_evidence = self.hierarchy_union(direct_evidence, local.evidence);
            } else {
                direct_owners.insert(owner);
                direct_evidence = self.hierarchy_union(direct_evidence, local.cutoff_evidence);
            }
        }
        if !direct_owners.is_empty() {
            let evidence = {
                let cancellation = self.cancellation;
                let work = &mut self.work;
                self.hierarchy
                    .evidence
                    .truncate(&direct_evidence, 0, &mut || {
                        poll_cancelled(cancellation, work)
                    })
            };
            let Some(evidence) = evidence else {
                self.cancellation_observed = true;
                return Ok(None);
            };
            let transfer = {
                let cancellation = self.cancellation;
                let work = &mut self.work;
                self.hierarchy
                    .transfers
                    .truncate(&direct_transfer, 0, &mut || {
                        poll_cancelled(cancellation, work)
                    })
            };
            let Some(transfer) = transfer else {
                self.cancellation_observed = true;
                return Ok(None);
            };
            let mut selected = Vec::new();
            for root in canonical_roots {
                if self.poll_cancelled() {
                    return Ok(None);
                }
                if direct_owners.contains(&root.owner) {
                    let expression = self.hierarchy.candidates.here(root.owner);
                    selected.push(HierarchySelectedCandidateExpression { expression, root });
                }
            }
            return Ok(Some(HierarchyOwnerSelection {
                candidates: selected.into_boxed_slice(),
                evidence,
                transfer,
                retains_global_evidence,
            }));
        }

        if let Some(cached) = self.cached_hierarchy_candidate_expressions(shape, roots)? {
            return Ok(Some(cached));
        }
        if !self.ensure_hierarchy_owner_closure(&root_owners)?
            || !self.ensure_hierarchy_shape_summaries(shape, &root_owners)?
        {
            return Ok(None);
        }
        Ok(Some(
            self.cached_hierarchy_candidate_expressions(shape, roots)?
                .expect("an exhausted hierarchy closure publishes every root summary"),
        ))
    }

    fn select_qualified_origins(
        &mut self,
        routes: &[SourceSelectedQualifiedRoute],
        previous_states: &HashMap<SemanticId, TypedFrontierState>,
    ) -> StoreResult<Option<QualifiedOriginSelection>> {
        let mut origins = Vec::new();
        let mut hierarchy_roots =
            BTreeMap::<(u32, HierarchyLookupShape), Vec<HierarchyRoot>>::new();
        let mut observed_qualifier_slots = BTreeSet::new();
        let mut hierarchy_qualifier_slots = BTreeSet::new();
        let mut nonhierarchy_qualifier_slots = BTreeSet::new();
        for (route_ordinal, route) in routes.iter().enumerate() {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let Some(qualifier) = previous_states.get(&route.row().qualifier_slot()) else {
                return Ok(None);
            };
            if observed_qualifier_slots.insert(route.row().qualifier_slot()) {
                self.observe_hierarchy_qualifier_completion(
                    route.row().qualifier_slot(),
                    qualifier.completion(),
                );
                if self.cancellation_observed {
                    return Ok(None);
                }
            }
            for value in qualifier.possible_values().iter().copied() {
                if self.poll_cancelled() {
                    return Ok(None);
                }
                let ty = value.ty();
                let shape = HierarchyLookupShape::new(
                    route.row().lookup(),
                    route.row().namespace(),
                    QualifierCategory::of(value),
                    i64::from(ty.indirection()),
                );
                if shape.inherited_member_kind().is_some() && ty.indirection() == 0 {
                    hierarchy_qualifier_slots.insert(route.row().qualifier_slot());
                    hierarchy_roots
                        .entry((route.row().precedence_ordinal(), shape))
                        .or_default()
                        .push(HierarchyRoot {
                            owner: ty.identity(),
                            value,
                            route_ordinal,
                        });
                } else {
                    nonhierarchy_qualifier_slots.insert(route.row().qualifier_slot());
                    let ancestry: Box<[SemanticId]> = Box::new([]);
                    let Some(identity) = qualified_origin_identity(
                        route,
                        shape,
                        ty.identity(),
                        value,
                        &ancestry,
                        &mut || self.poll_cancelled(),
                    ) else {
                        return Ok(None);
                    };
                    origins.push(SelectedQualifiedOrigin {
                        identity,
                        owner: ty.identity(),
                        route_ordinal,
                        value,
                        shape,
                        hierarchy_owned: false,
                        ancestry,
                    });
                }
            }
        }
        let hierarchy_used = !hierarchy_roots.is_empty();
        let mut hierarchy_evidence = HierarchyEvidence::Complete;
        let mut hierarchy_transfer = HierarchyEvidence::Complete;
        let mut hierarchy_retains_global_evidence = false;
        let mut selected_hierarchy_precedence = None;
        for ((precedence_ordinal, shape), roots) in hierarchy_roots {
            if selected_hierarchy_precedence.is_some_and(|selected| precedence_ordinal > selected) {
                break;
            }
            let HierarchySelectionState::Ready(selection) =
                self.select_hierarchy_owners(shape, &roots)?
            else {
                return Ok(None);
            };
            hierarchy_evidence = self.hierarchy_union(hierarchy_evidence, selection.evidence);
            hierarchy_transfer =
                self.hierarchy_transfer_union(hierarchy_transfer, selection.transfer);
            hierarchy_retains_global_evidence |= selection.retains_global_evidence;
            let selected_owners = selection.owners.into_vec();
            if !selected_owners.is_empty() {
                assert!(
                    selected_hierarchy_precedence
                        .is_none_or(|selected| selected == precedence_ordinal),
                    "qualified hierarchy selection stops after one lexical precedence tier"
                );
                selected_hierarchy_precedence = Some(precedence_ordinal);
            }
            for selected in selected_owners {
                if self.poll_cancelled() {
                    return Ok(None);
                }
                let route = &routes[selected.root.route_ordinal];
                let Some(identity) = qualified_origin_identity(
                    route,
                    shape,
                    selected.owner,
                    selected.root.value,
                    &selected.ancestry,
                    &mut || self.poll_cancelled(),
                ) else {
                    return Ok(None);
                };
                origins.push(SelectedQualifiedOrigin {
                    identity,
                    owner: selected.owner,
                    route_ordinal: selected.root.route_ordinal,
                    value: selected.root.value,
                    shape,
                    hierarchy_owned: true,
                    ancestry: selected.ancestry,
                });
            }
        }
        let hierarchy_transfer_completion = {
            let cancellation = self.cancellation;
            let work = &mut self.work;
            self.hierarchy
                .transfers
                .flatten(&hierarchy_transfer, u32::MAX, &mut || {
                    poll_cancelled(cancellation, work)
                })
        };
        let Some(hierarchy_transfer_completion) = hierarchy_transfer_completion else {
            self.cancellation_observed = true;
            return Ok(None);
        };
        let mut transferred_hierarchy_reasons = BTreeSet::new();
        if let ResolutionCompletion::Incomplete(reasons) = hierarchy_transfer_completion {
            for reason in reasons.into_vec() {
                if self.poll_cancelled() {
                    return Ok(None);
                }
                let ResolutionIncompleteReason::UnsupportedSemantic(reason) = reason else {
                    unreachable!("hierarchy transfer expressions contain only semantic reasons")
                };
                transferred_hierarchy_reasons.insert(reason);
            }
        }
        Ok(Some(QualifiedOriginSelection {
            origins,
            hierarchy_used,
            hierarchy_evidence,
            hierarchy_retains_global_evidence,
            transferred_hierarchy_reasons,
            observed_qualifier_slots,
            hierarchy_qualifier_slots,
            nonhierarchy_qualifier_slots,
        }))
    }

    fn prepare_qualified_qualifiers(
        &mut self,
        selection: QualifiedOriginSelection,
        previous_states: &HashMap<SemanticId, TypedFrontierState>,
    ) -> StoreResult<Option<QualifiedQualifierSelection>> {
        let QualifiedOriginSelection {
            origins,
            hierarchy_used,
            hierarchy_evidence,
            hierarchy_retains_global_evidence,
            transferred_hierarchy_reasons,
            observed_qualifier_slots,
            hierarchy_qualifier_slots,
            nonhierarchy_qualifier_slots,
        } = selection;

        // A typed qualifier can carry source-wide coverage operands that are
        // unrelated to the member path selected below. Transfer only reasons
        // whose persisted provenance says they are Java hierarchy fallbacks;
        // placement, implicit-receiver, visibility, and arbitrary service
        // evidence remain exact qualifier operands. The cached session read
        // canonicalizes and issues these reason keys in bounded source calls.
        let mut qualifier_hierarchy_reasons = BTreeSet::new();
        if hierarchy_used {
            let mut qualifier_semantics = BTreeSet::new();
            for &qualifier_slot in &hierarchy_qualifier_slots {
                if self.poll_cancelled() {
                    return Ok(None);
                }
                let ResolutionCompletion::Incomplete(reasons) =
                    previous_states[&qualifier_slot].completion()
                else {
                    continue;
                };
                for &reason in reasons.iter() {
                    if self.poll_cancelled() {
                        return Ok(None);
                    }
                    if let ResolutionIncompleteReason::UnsupportedSemantic(semantic) = reason
                        && transferred_hierarchy_reasons.contains(&semantic)
                    {
                        qualifier_semantics.insert(semantic);
                    }
                }
            }
            let mut qualifier_semantics_vec = Vec::with_capacity(qualifier_semantics.len());
            for &semantic in &qualifier_semantics {
                if self.poll_cancelled() {
                    return Ok(None);
                }
                qualifier_semantics_vec.push(semantic);
            }
            let mut classified_provenance = HashMap::default();
            for chunk in qualifier_semantics_vec.chunks(MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
                if self.poll_cancelled() {
                    return Ok(None);
                }
                let provenance_support_identity =
                    hierarchy_support_read_identity(b"gap-reason-provenance-by-reason", chunk);
                let provenance_read = self.session.gap_reason_provenance_for_reasons(chunk)?;
                let Some(provenance_rows) = self
                    .accept_hierarchy_session_read(provenance_support_identity, provenance_read)
                else {
                    return Ok(None);
                };
                for provenance in provenance_rows {
                    if self.poll_cancelled() {
                        return Ok(None);
                    }
                    let provenance = *provenance.get(self.session);
                    assert!(
                        qualifier_semantics.contains(&provenance.reason()),
                        "gap provenance must belong to one requested qualifier reason"
                    );
                    assert!(
                        classified_provenance
                            .insert(provenance.reason(), provenance.origin())
                            .is_none(),
                        "one semantic gap reason has one selected provenance"
                    );
                    if provenance.origin()
                        == LoweringGapOrigin::Extracted(
                            ResolutionGapKind::UnsupportedHierarchyTraversal,
                        )
                        && transferred_hierarchy_reasons.contains(&provenance.reason())
                    {
                        qualifier_hierarchy_reasons.insert(provenance.reason());
                    }
                }
            }
        }

        let mut hierarchy_completions = HashMap::default();
        let mut qualifier_reasons = ExactCompletionAccumulator::default();
        for &qualifier_slot in &observed_qualifier_slots {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let raw_completion = previous_states[&qualifier_slot].completion();
            if hierarchy_qualifier_slots.contains(&qualifier_slot) {
                let Some(completion) = completion_without_unsupported_semantics_with_poll(
                    raw_completion,
                    &qualifier_hierarchy_reasons,
                    &mut || self.poll_cancelled(),
                ) else {
                    return Ok(None);
                };
                if nonhierarchy_qualifier_slots.contains(&qualifier_slot) {
                    self.include_semantic_completion(&mut qualifier_reasons, raw_completion);
                } else {
                    self.include_semantic_completion(&mut qualifier_reasons, &completion);
                }
                assert!(
                    hierarchy_completions
                        .insert(qualifier_slot, completion)
                        .is_none(),
                    "one hierarchy qualifier slot owns one transferred completion"
                );
            } else {
                self.include_semantic_completion(&mut qualifier_reasons, raw_completion);
            }
        }
        let Some(completion) = self.finish_semantic_completion(qualifier_reasons) else {
            return Ok(None);
        };

        let mut ordered_origins = BTreeMap::new();
        for origin in origins {
            if self.poll_cancelled() {
                return Ok(None);
            }
            ordered_origins
                .entry((
                    origin.owner,
                    origin.route_ordinal,
                    origin.value,
                    origin.shape,
                    origin.identity,
                ))
                .or_insert(origin);
        }
        let mut origins = Vec::with_capacity(ordered_origins.len());
        while let Some((_, origin)) = ordered_origins.pop_first() {
            if self.poll_cancelled() {
                return Ok(None);
            }
            origins.push(origin);
        }

        Ok(Some(QualifiedQualifierSelection {
            origin_selection: QualifiedOriginSelection {
                origins,
                hierarchy_used,
                hierarchy_evidence,
                hierarchy_retains_global_evidence,
                transferred_hierarchy_reasons,
                observed_qualifier_slots,
                hierarchy_qualifier_slots,
                nonhierarchy_qualifier_slots,
            },
            hierarchy_completions,
            completion,
        }))
    }

    fn load_qualified_owner_properties(
        &mut self,
        origins: &[SelectedQualifiedOrigin],
    ) -> StoreResult<Option<QualifiedOwnerProperties>> {
        let mut selected_owners = BTreeSet::new();
        for origin in origins {
            if self.poll_cancelled() {
                return Ok(None);
            }
            selected_owners.insert(origin.owner);
        }
        let mut owners = Vec::with_capacity(selected_owners.len());
        while let Some(owner) = selected_owners.pop_first() {
            if self.poll_cancelled() {
                return Ok(None);
            }
            owners.push(owner);
        }

        let scope_support_identity =
            hierarchy_support_read_identity(b"member-scope-by-definition", &owners);
        let scope_read = self.session.member_scopes_for_definitions(&owners)?;
        let Some(scope_rows) =
            self.accept_hierarchy_session_read(scope_support_identity, scope_read)
        else {
            return Ok(None);
        };
        let mut scopes = HashMap::default();
        for scope in scope_rows {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let scope = scope.get(self.session);
            assert!(
                scopes
                    .insert(scope.row().definition(), scope.row().scope_head())
                    .is_none(),
                "one selected definition has at most one member scope"
            );
        }

        let gap_support_identity =
            hierarchy_support_read_identity(b"property-gap-by-definition", &owners);
        let gap_read = self.session.property_gaps_for_definitions(&owners)?;
        let Some(gap_rows) = self.accept_hierarchy_session_read(gap_support_identity, gap_read)
        else {
            return Ok(None);
        };
        let mut property_gaps =
            HashMap::<SemanticId, Vec<(ResolutionGapKind, SemanticId)>>::default();
        for gap in gap_rows {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let gap = gap.get(self.session);
            property_gaps
                .entry(gap.row().definition())
                .or_default()
                .push((gap.row().kind(), gap.row().reason_semantic()));
        }

        let visibility_support_identity =
            hierarchy_support_read_identity(b"declaration-visibility-by-definition", &owners);
        let visibility_read = self
            .session
            .declaration_visibilities_for_definitions(&owners)?;
        let Some(visibility_rows) =
            self.accept_hierarchy_session_read(visibility_support_identity, visibility_read)
        else {
            return Ok(None);
        };
        let mut declaration_visibilities = HashMap::<SemanticId, DeclaredVisibility>::default();
        for visibility in visibility_rows {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let visibility = visibility.get(self.session);
            assert!(
                declaration_visibilities
                    .insert(visibility.row().definition(), visibility.row().visibility())
                    .is_none(),
                "one selected declaration has at most one visibility row"
            );
        }

        let construction_support_identity =
            hierarchy_support_read_identity(b"construction-requirement-by-definition", &owners);
        let construction_read = self
            .session
            .construction_requirements_for_definitions(&owners)?;
        let Some(construction_rows) =
            self.accept_hierarchy_session_read(construction_support_identity, construction_read)
        else {
            return Ok(None);
        };
        let mut construction_owners = HashSet::default();
        for row in construction_rows {
            if self.poll_cancelled() {
                return Ok(None);
            }
            construction_owners.insert(row.get(self.session).row().definition());
        }

        Ok(Some(QualifiedOwnerProperties {
            scopes,
            property_gaps,
            declaration_visibilities,
            construction_owners,
        }))
    }

    fn prepare_qualified_answer(
        &mut self,
        answer: ResolutionAnswer,
        plan: &QualifiedReplayPlan,
    ) -> StoreResult<Option<PreparedQualifiedAnswer>> {
        self.observe_cancellation_completion(answer.completion());
        for witness in answer.witnesses() {
            self.poll_cancellation_ledger();
            self.observe_cancellation_completion(witness.completion());
        }
        if self.cancellation_observed {
            return Ok(None);
        }

        let mut target_definition_set = BTreeSet::new();
        target_definition_set.extend(answer.targets());
        target_definition_set.extend(answer.witnesses().iter().map(ResolutionWitness::target));
        let mut target_definitions = Vec::with_capacity(target_definition_set.len());
        while let Some(target) = target_definition_set.pop_first() {
            if self.poll_cancelled() {
                return Ok(None);
            }
            target_definitions.push(target);
        }
        if !self.ensure_hierarchy_member_owner_metadata(&target_definitions)? {
            return Ok(None);
        }

        let (targets, witnesses, completion) = answer.into_parts();
        let completion = if plan.hierarchy_only {
            let Some(completion) = self.completion_after_hierarchy_transfer(
                &completion,
                &plan.transferred_hierarchy_reasons,
            ) else {
                return Ok(None);
            };
            completion
        } else {
            completion
        };
        Ok(Some(PreparedQualifiedAnswer {
            targets,
            witnesses,
            completion,
        }))
    }

    fn replay_qualified_witnesses(
        &mut self,
        reference: SemanticId,
        previous_states: &HashMap<SemanticId, TypedFrontierState>,
        answer: PreparedQualifiedAnswer,
        plan: &QualifiedReplayPlan,
    ) -> StoreResult<Option<QualifiedReplayResult>> {
        let PreparedQualifiedAnswer {
            targets: answer_targets,
            witnesses: answer_witnesses,
            completion: answer_completion,
        } = answer;
        let mut compatibility_reasons = ExactCompletionAccumulator::default();
        let mut compatible_targets = BTreeSet::new();
        let mut compatible_witnesses = Vec::new();
        let mut receiver_category_closure = HashMap::default();
        for witness in answer_witnesses.into_vec() {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let (witness_reference, target, steps, witness_completion) = witness.into_parts();
            let mut representative_identity = None;
            for step in steps.iter() {
                if self.poll_cancelled() {
                    return Ok(None);
                }
                let WitnessStep::Candidate { semantic, .. } = step else {
                    continue;
                };
                if plan.groups.contains_key(semantic) {
                    assert!(
                        representative_identity.replace(*semantic).is_none(),
                        "one shared qualified suffix carries one representative origin"
                    );
                }
            }
            let representative_identity =
                representative_identity.expect("every qualified suffix tags its replay group");
            let replay_origins = &plan.origins[plan.groups[&representative_identity].clone()];
            let representative = &replay_origins[0];
            let witness_completion = if representative.hierarchy_owned {
                let Some(completion) = self.completion_after_hierarchy_transfer(
                    &witness_completion,
                    &plan.transferred_hierarchy_reasons,
                ) else {
                    return Ok(None);
                };
                completion
            } else {
                witness_completion
            };
            let prefix_len = representative
                .ancestry
                .len()
                .checked_add(2)
                .expect("qualified replay prefix length must fit usize");
            assert!(
                steps.len() > prefix_len,
                "a completed qualified suffix retains its target outcome"
            );
            assert!(
                matches!(
                    steps.first(),
                    Some(WitnessStep::Candidate {
                        semantic,
                        outcome: CandidateOutcome::Selected,
                    }) if *semantic == representative.identity
                ),
                "the representative qualified origin is the first prefix witness"
            );
            assert!(
                matches!(
                    steps.get(prefix_len - 1),
                    Some(WitnessStep::Node(scope)) if *scope == representative.scope_head
                ),
                "the representative qualified prefix ends at its selected member scope"
            );
            let suffix = &steps[prefix_len..];
            let engine_selected = matches!(
                suffix.last(),
                Some(WitnessStep::Candidate {
                    semantic,
                    outcome: CandidateOutcome::Selected,
                }) if *semantic == target
            );
            assert!(
                matches!(
                    suffix.last(),
                    Some(WitnessStep::Candidate { semantic, .. }) if *semantic == target
                ),
                "the binding engine appends one target outcome to every suffix"
            );

            for origin in replay_origins {
                if self.poll_cancelled() {
                    return Ok(None);
                }
                let selected = engine_selected
                    && origin.precedence_ordinal == representative.precedence_ordinal;
                self.hierarchy.metadata_work.match_checks += 1;
                let property = match self.hierarchy.member_owner_metadata.get(&target) {
                    Some(ExactMemberOwnerMetadata::Unique(property)) => Some(*property),
                    Some(
                        ExactMemberOwnerMetadata::Missing | ExactMemberOwnerMetadata::Conflicting,
                    ) => None,
                    None => panic!("every replay target has exact member-owner metadata"),
                }
                .map(|property| *property.get(self.session).row());
                let Some(property) = property else {
                    if selected {
                        self.include_semantic_reason(
                            &mut compatibility_reasons,
                            ResolutionIncompleteReason::UnsupportedSemantic(
                                hierarchy_member_owner_reason(
                                    HierarchyNodeKey {
                                        shape: origin.shape,
                                        owner: origin.owner,
                                    },
                                    target,
                                ),
                            ),
                        );
                    }
                    continue;
                };
                let owner_matched = property.owner_definition() == origin.owner
                    && property.owner_scope_head() == origin.scope_head
                    && origin
                        .expected_kind
                        .is_none_or(|expected_kind| property.kind() == expected_kind);
                if !owner_matched {
                    if selected {
                        self.include_semantic_reason(
                            &mut compatibility_reasons,
                            ResolutionIncompleteReason::UnsupportedSemantic(
                                hierarchy_member_owner_reason(
                                    HierarchyNodeKey {
                                        shape: origin.shape,
                                        owner: origin.owner,
                                    },
                                    target,
                                ),
                            ),
                        );
                    }
                    continue;
                }
                if !qualifier_compatible(property.qualifier_compatibility(), origin.category) {
                    if selected {
                        self.include_semantic_reason(
                            &mut compatibility_reasons,
                            ResolutionIncompleteReason::UnsupportedSemantic(service_reason(
                                b"post-shadow-qualifier-incompatibility",
                                &[
                                    reference.as_bytes().as_slice(),
                                    target.as_bytes().as_slice(),
                                ],
                            )),
                        );
                    }
                    continue;
                }
                let qualifier_completion = if origin.hierarchy_owned {
                    plan.hierarchy_qualifier_completions
                        .get(&origin.qualifier_slot)
                        .expect("every hierarchy origin has one transferred qualifier completion")
                } else {
                    previous_states[&origin.qualifier_slot].completion()
                };
                if selected {
                    compatible_targets.insert(target);
                    if reference == self.root
                        && self.root_callable_receiver_origin()
                            == Some(ResolutionCallableReceiverOrigin::ExplicitExpression)
                    {
                        let category_closed =
                            if matches!(qualifier_completion, ResolutionCompletion::Complete) {
                                true
                            } else if let Some(&closed) =
                                receiver_category_closure.get(&origin.qualifier_slot)
                            {
                                closed
                            } else {
                                let Some(closed) = self.explicit_receiver_runtime_category_closed(
                                    origin.qualifier_slot,
                                    previous_states,
                                )?
                                else {
                                    return Ok(None);
                                };
                                receiver_category_closure.insert(origin.qualifier_slot, closed);
                                closed
                            };
                        let evidence = self
                            .root_explicit_receiver_evidence
                            .entry(target)
                            .or_default();
                        evidence.values.insert(origin.value);
                        evidence.category_open |= !category_closed;
                    }
                }
                let mut fan_steps = Vec::with_capacity(origin.ancestry.len() + 2 + suffix.len());
                fan_steps.push(WitnessStep::Candidate {
                    semantic: origin.identity,
                    outcome: CandidateOutcome::Selected,
                });
                self.hierarchy.metadata_work.replay_step_copies += 1;
                for &supertype_reference in origin.ancestry.iter() {
                    if self.poll_cancelled() {
                        return Ok(None);
                    }
                    fan_steps.push(WitnessStep::Candidate {
                        semantic: supertype_reference,
                        outcome: CandidateOutcome::Selected,
                    });
                    self.hierarchy.metadata_work.replay_step_copies += 1;
                }
                fan_steps.push(WitnessStep::Node(origin.scope_head));
                self.hierarchy.metadata_work.replay_step_copies += 1;
                for &step in suffix {
                    if self.poll_cancelled() {
                        return Ok(None);
                    }
                    fan_steps.push(step);
                    self.hierarchy.metadata_work.replay_step_copies += 1;
                }
                if engine_selected && !selected {
                    *fan_steps
                        .last_mut()
                        .expect("one fanned qualified witness has a target outcome") =
                        WitnessStep::Candidate {
                            semantic: target,
                            outcome: CandidateOutcome::Rejected(RejectionReason::ShadowedByNearer),
                        };
                }
                let mut witness_reasons = ExactCompletionAccumulator::default();
                self.include_semantic_completion(&mut witness_reasons, &witness_completion);
                self.include_semantic_completion(&mut witness_reasons, qualifier_completion);
                self.include_semantic_completion(&mut witness_reasons, &plan.hierarchy_completion);
                let Some(completion) = self.finish_semantic_completion(witness_reasons) else {
                    return Ok(None);
                };
                compatible_witnesses.push((
                    target,
                    ResolutionWitness::new(
                        witness_reference,
                        target,
                        fan_steps.into_boxed_slice(),
                        completion,
                    ),
                ));
            }
        }

        let Some(compatibility_completion) = self.finish_semantic_completion(compatibility_reasons)
        else {
            return Ok(None);
        };
        let mut witnesses = Vec::new();
        for (target, witness) in compatible_witnesses {
            if self.poll_cancelled() {
                return Ok(None);
            }
            if compatible_targets.contains(&target) {
                witnesses.push(witness);
            }
        }
        let mut targets = Vec::with_capacity(compatible_targets.len());
        while let Some(target) = compatible_targets.pop_first() {
            if self.poll_cancelled() {
                return Ok(None);
            }
            debug_assert!(answer_targets.binary_search(&target).is_ok());
            targets.push(target);
        }
        let mut reasons = ExactCompletionAccumulator::default();
        self.include_semantic_completion(&mut reasons, &answer_completion);
        self.include_semantic_completion(&mut reasons, &compatibility_completion);
        self.include_semantic_completion(&mut reasons, &plan.hierarchy_completion);
        let Some(completion) = self.finish_semantic_completion(reasons) else {
            return Ok(None);
        };
        Ok(Some(QualifiedReplayResult {
            targets,
            witnesses,
            completion,
        }))
    }

    fn resolve_qualified(
        &mut self,
        reference: SemanticId,
        routes: &[InternedFactRow<SourceSelectedQualifiedRoute>],
        previous_states: &HashMap<SemanticId, TypedFrontierState>,
    ) -> StoreResult<Option<ResolutionAnswer>> {
        assert!(!routes.is_empty());
        let routes = routes
            .iter()
            .map(|route| *route.get(self.session))
            .collect::<Vec<_>>();
        let issued_root = if reference == self.root && self.root_seed.is_some() {
            let Some(seed) = self.clone_root_seed_with_poll() else {
                return Ok(None);
            };
            Some(seed)
        } else {
            None
        };
        let seed = if let Some(seed) = issued_root {
            Some(seed)
        } else {
            let Some(seed) = self.clone_qualified_reference_seed_with_poll(reference) else {
                return Ok(None);
            };
            seed
        };
        let Some(seed) = seed else {
            if self.cancellation.is_cancelled() {
                return Ok(Some(ResolutionAnswer::new(
                    Vec::new(),
                    Vec::new(),
                    incomplete_cancelled(),
                )));
            }
            return Ok(Some(ResolutionAnswer::new(
                Vec::new(),
                Vec::new(),
                incomplete(service_reason(
                    b"missing-qualified-reference-seed",
                    &[reference.as_bytes().as_slice()],
                )),
            )));
        };
        self.observe_cancellation_completion(seed.completion());
        if self.cancellation_observed {
            return Ok(None);
        }
        let mut selected_coarse_reasons = BTreeSet::new();
        for route in &routes {
            if self.poll_cancelled() {
                return Ok(None);
            }
            if seed.reference() != reference
                || route.row().reference() != reference
                || seed.fragment() != route.fragment()
                || seed.node() != route.reference_node()
            {
                return Err(StoreError::new(format!(
                    "qualified reference seed ({:?}, {}, {}) disagrees with selected route ({:?}, {}, {})",
                    seed.fragment(),
                    seed.reference(),
                    seed.node(),
                    route.fragment(),
                    route.row().reference(),
                    route.reference_node(),
                )));
            }
            selected_coarse_reasons.insert(route.row().coarse_gap_reason());
        }
        if reference == self.root {
            self.install_root_site_metadata(seed.site_metadata());
        }
        let Some(seed_completion) = completion_without_unsupported_semantics_with_poll(
            seed.completion(),
            &selected_coarse_reasons,
            &mut || self.poll_cancelled(),
        ) else {
            return Ok(None);
        };
        let seed = ReferenceSeed::new_with_site_metadata(
            seed.fragment(),
            seed.query(),
            seed.node(),
            seed.site_metadata(),
            seed_completion,
        );

        let Some(qualifiers) = self.select_qualified_origins(&routes, previous_states)? else {
            return Ok(None);
        };
        let Some(QualifiedQualifierSelection {
            origin_selection:
                QualifiedOriginSelection {
                    origins: selected_origins,
                    hierarchy_used,
                    mut hierarchy_evidence,
                    hierarchy_retains_global_evidence,
                    transferred_hierarchy_reasons,
                    ..
                },
            hierarchy_completions: hierarchy_qualifier_completions,
            completion: qualifier_completion,
        }) = self.prepare_qualified_qualifiers(qualifiers, previous_states)?
        else {
            return Ok(None);
        };

        let Some(QualifiedOwnerProperties {
            scopes,
            property_gaps,
            declaration_visibilities,
            construction_owners,
        }) = self.load_qualified_owner_properties(&selected_origins)?
        else {
            return Ok(None);
        };

        let mut grouped_origins = BTreeMap::<(SemanticId, HierarchyLookupShape), Vec<usize>>::new();
        let mut origin_omissions = ExactCompletionAccumulator::default();
        for (origin_ordinal, origin) in selected_origins.iter().enumerate() {
            if self.poll_cancelled() {
                return Ok(None);
            }
            if !scopes.contains_key(&origin.owner) {
                self.include_semantic_reason(
                    &mut origin_omissions,
                    ResolutionIncompleteReason::UnsupportedSemantic(service_reason(
                        b"missing-member-scope",
                        &[
                            reference.as_bytes().as_slice(),
                            origin.shape.lookup.as_bytes().as_slice(),
                            origin.shape.namespace.identity_label().as_bytes(),
                            match origin.shape.category {
                                QualifierCategory::Type => b"type",
                                QualifierCategory::Runtime => b"runtime",
                            },
                            &origin.shape.receiver_indirection.to_le_bytes(),
                            origin.owner.as_bytes().as_slice(),
                        ],
                    )),
                );
                continue;
            }
            grouped_origins
                .entry((origin.owner, origin.shape))
                .or_default()
                .push(origin_ordinal);
        }

        let mut alternatives = Vec::with_capacity(grouped_origins.len());
        let mut replay_origins_arena = Vec::<QualifiedReplayOrigin>::new();
        let mut replay_groups = HashMap::<SemanticId, Range<usize>>::default();
        let mut all_origin_identities = HashSet::default();
        let mut replay_has_hierarchy_origin = false;
        let mut replay_has_nonhierarchy_origin = false;
        for ((owner, shape), origin_ordinals) in grouped_origins {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let scope_head = scopes[&owner];

            let mut alternative_reasons = ExactCompletionAccumulator::default();
            let Some(property_completion) = self.member_lookup_property_completion(
                owner,
                shape.namespace,
                declaration_visibilities.get(&owner).copied(),
                property_gaps.get(&owner).map_or(&[], Vec::as_slice),
                construction_owners.contains(&owner),
            )?
            else {
                return Ok(None);
            };
            self.include_semantic_completion(&mut alternative_reasons, &property_completion);
            if shape.receiver_indirection != 0 {
                self.include_semantic_reason(
                    &mut alternative_reasons,
                    ResolutionIncompleteReason::UnsupportedSemantic(service_reason(
                        b"unsupported-member-indirection",
                        &[
                            reference.as_bytes().as_slice(),
                            shape.lookup.as_bytes().as_slice(),
                            shape.namespace.identity_label().as_bytes(),
                            match shape.category {
                                QualifierCategory::Type => b"type",
                                QualifierCategory::Runtime => b"runtime",
                            },
                            &shape.receiver_indirection.to_le_bytes(),
                            owner.as_bytes().as_slice(),
                        ],
                    )),
                );
            }
            let Some(completion) = self.finish_semantic_completion(alternative_reasons) else {
                return Ok(None);
            };

            let mut replay_origins = Vec::with_capacity(origin_ordinals.len());
            for origin_ordinal in origin_ordinals {
                if self.poll_cancelled() {
                    return Ok(None);
                }
                let origin = &selected_origins[origin_ordinal];
                let route = &routes[origin.route_ordinal];
                let category = QualifierCategory::of(origin.value);
                if origin.hierarchy_owned {
                    replay_has_hierarchy_origin = true;
                } else {
                    replay_has_nonhierarchy_origin = true;
                }
                assert!(
                    all_origin_identities.insert(origin.identity),
                    "one qualified hierarchy origin has one exact identity"
                );
                let mut ancestry = Vec::with_capacity(origin.ancestry.len());
                for &supertype_reference in origin.ancestry.iter() {
                    if self.poll_cancelled() {
                        return Ok(None);
                    }
                    ancestry.push(supertype_reference);
                }
                replay_origins.push(QualifiedReplayOrigin {
                    identity: origin.identity,
                    owner,
                    value: origin.value,
                    shape,
                    hierarchy_owned: origin.hierarchy_owned,
                    category,
                    expected_kind: shape.inherited_member_kind(),
                    qualifier_slot: route.row().qualifier_slot(),
                    precedence_ordinal: route.row().precedence_ordinal(),
                    origin_ordinal,
                    ancestry: ancestry.into_boxed_slice(),
                    scope_head,
                });
            }
            let mut ordered_origins = BTreeMap::new();
            for origin in replay_origins {
                if self.poll_cancelled() {
                    return Ok(None);
                }
                assert!(
                    ordered_origins
                        .insert((origin.precedence_ordinal, origin.identity), origin)
                        .is_none(),
                    "one qualified replay origin has one precedence identity"
                );
            }
            let mut replay_origins = Vec::with_capacity(ordered_origins.len());
            while let Some((_, origin)) = ordered_origins.pop_first() {
                if self.poll_cancelled() {
                    return Ok(None);
                }
                replay_origins.push(origin);
            }
            let representative_origin = &replay_origins[0];
            let representative_identity = representative_origin.identity;
            let representative = &selected_origins[representative_origin.origin_ordinal];
            let representative_route = &routes[representative.route_ordinal];
            let Some(path) = qualified_seed_path(
                &seed,
                representative_route,
                scope_head,
                representative_origin.identity,
                &representative_origin.ancestry,
                completion,
                &mut || self.poll_cancelled(),
            ) else {
                return Ok(None);
            };
            let Some(alternative) = SeededPartialPath::new_with_poll(
                qualified_seed_path_id(
                    representative_route,
                    scope_head,
                    representative.value,
                    representative_origin.identity,
                ),
                path,
                &mut || self.poll_cancelled(),
            ) else {
                return Ok(None);
            };
            alternatives.push(alternative);
            let replay_range_start = replay_origins_arena.len();
            replay_origins_arena.extend(replay_origins);
            let replay_range = replay_range_start..replay_origins_arena.len();
            assert!(
                replay_groups
                    .insert(representative_identity, replay_range)
                    .is_none(),
                "one representative suffix owns one origin fanout"
            );
        }
        let Some(origin_omission_completion) = self.finish_semantic_completion(origin_omissions)
        else {
            return Ok(None);
        };
        let mut omitted_reasons = ExactCompletionAccumulator::default();
        self.include_semantic_completion(&mut omitted_reasons, &qualifier_completion);
        self.include_semantic_completion(&mut omitted_reasons, &origin_omission_completion);
        let Some(omitted_completion) = self.finish_semantic_completion(omitted_reasons) else {
            return Ok(None);
        };
        if hierarchy_used && hierarchy_retains_global_evidence && alternatives.is_empty() {
            let global_evidence = self
                .hierarchy
                .global_evidence
                .clone()
                .unwrap_or(HierarchyEvidence::Complete);
            hierarchy_evidence = self.hierarchy_union(hierarchy_evidence, global_evidence);
        }
        let hierarchy_completion = {
            let cancellation = self.cancellation;
            let work = &mut self.work;
            self.hierarchy
                .evidence
                .flatten(&hierarchy_evidence, u32::MAX, &mut || {
                    poll_cancelled(cancellation, work)
                })
        };
        let Some(hierarchy_completion) = hierarchy_completion else {
            self.cancellation_observed = true;
            return Ok(None);
        };
        let mut replay_plan = QualifiedReplayPlan {
            alternatives,
            origins: replay_origins_arena,
            groups: replay_groups,
            hierarchy_qualifier_completions,
            transferred_hierarchy_reasons,
            hierarchy_completion,
            omitted_completion,
            origin_omission_completion,
            hierarchy_only: replay_has_hierarchy_origin && !replay_has_nonhierarchy_origin,
        };
        let answer = if replay_plan.alternatives.is_empty() {
            let mut reasons = ExactCompletionAccumulator::default();
            self.include_semantic_completion(&mut reasons, seed.completion());
            let Some(completion) = self.finish_semantic_completion(reasons) else {
                return Ok(None);
            };
            ResolutionAnswer::new(Vec::new(), Vec::new(), completion)
        } else {
            let Some(request) = SeededReferenceRequest::new_with_poll(
                seed,
                std::mem::take(&mut replay_plan.alternatives),
                &mut || self.poll_cancelled(),
            ) else {
                return Ok(None);
            };
            let engine = BatchResolutionEngine::new(self.session.lexical_source);
            let (answer, metrics) =
                engine.resolve_seeded_reference_with_metrics(&request, self.cancellation)?;
            self.binding_metrics.accumulate(metrics);
            answer
        };
        let Some(answer) = self.prepare_qualified_answer(answer, &replay_plan)? else {
            return Ok(None);
        };
        let Some(QualifiedReplayResult {
            targets,
            witnesses,
            completion: replay_completion,
        }) = self.replay_qualified_witnesses(reference, previous_states, answer, &replay_plan)?
        else {
            return Ok(None);
        };
        let mut reasons = ExactCompletionAccumulator::default();
        self.include_semantic_completion(&mut reasons, &replay_completion);
        self.include_semantic_completion(&mut reasons, &replay_plan.omitted_completion);
        if reference == self.root
            && self.root_callable_receiver_origin()
                == Some(ResolutionCallableReceiverOrigin::ExplicitExpression)
            && !matches!(
                replay_plan.origin_omission_completion,
                ResolutionCompletion::Complete
            )
        {
            let cancellation = self.cancellation;
            let cancellation_observed = &mut self.cancellation_observed;
            let work = &mut self.work;
            for evidence in self.root_explicit_receiver_evidence.values_mut() {
                let cancelled = *cancellation_observed || poll_cancelled(cancellation, work);
                *cancellation_observed |= cancelled;
                if cancelled {
                    return Ok(None);
                }
                evidence.category_open = true;
            }
        }
        let Some(completion) = self.finish_semantic_completion(reasons) else {
            return Ok(None);
        };
        Ok(Some(ResolutionAnswer::new(targets, witnesses, completion)))
    }

    fn member_lookup_property_completion(
        &mut self,
        owner: SemanticId,
        namespace: ResolutionNamespace,
        visibility: Option<DeclaredVisibility>,
        property_gaps: &[(ResolutionGapKind, SemanticId)],
        has_construction_requirement: bool,
    ) -> StoreResult<Option<ResolutionCompletion>> {
        let mut reasons = ExactCompletionAccumulator::default();
        let mut visibility_reasons = BTreeSet::new();
        for gap in property_gaps {
            if self.poll_cancelled() {
                return Ok(None);
            }
            if gap.0 == ResolutionGapKind::UnsupportedVisibility {
                visibility_reasons.insert(gap.1);
            }
            let relevant = gap.0 == ResolutionGapKind::UnsupportedVisibility
                || gap.0 == ResolutionGapKind::ImplicitConstructor
                    && namespace == ResolutionNamespace::Constructor;
            if relevant {
                self.include_semantic_reason(
                    &mut reasons,
                    ResolutionIncompleteReason::UnsupportedSemantic(gap.1),
                );
            }
        }
        if let Some(visibility) = visibility {
            let expected_reason_count = usize::from(visibility != DeclaredVisibility::Public);
            if visibility_reasons.len() != expected_reason_count {
                return Err(StoreError::new(format!(
                    "selected declaration {owner} visibility {visibility} disagrees with exact unsupported-visibility evidence {visibility_reasons:?}"
                )));
            }
        }
        if namespace == ResolutionNamespace::Constructor && has_construction_requirement {
            self.include_semantic_reason(
                &mut reasons,
                ResolutionIncompleteReason::UnsupportedSemantic(service_reason(
                    b"unsupported-construction-requirement",
                    &[owner.as_bytes().as_slice()],
                )),
            );
        }
        Ok(self.finish_semantic_completion(reasons))
    }

    fn declaration_visibility_completions_for_answers(
        &mut self,
        answers: &HashMap<SemanticId, ResolutionAnswer>,
    ) -> StoreResult<Option<HashMap<SemanticId, ResolutionCompletion>>> {
        let mut targets = BTreeSet::new();
        for answer in answers.values() {
            if self.poll_cancelled() {
                return Ok(None);
            }
            for &target in answer.targets() {
                if self.poll_cancelled() {
                    return Ok(None);
                }
                targets.insert(target);
            }
        }
        let mut ordered_targets = Vec::with_capacity(targets.len());
        while let Some(target) = targets.pop_first() {
            if self.poll_cancelled() {
                return Ok(None);
            }
            ordered_targets.push(target);
        }
        let targets = ordered_targets;
        let visibility_read = self
            .session
            .declaration_visibilities_for_definitions(&targets)?;
        let Some(visibility_rows) = self.accept_session_read(visibility_read) else {
            return Ok(None);
        };
        let mut declaration_visibilities = HashMap::default();
        for visibility in visibility_rows {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let visibility = visibility.get(self.session);
            assert!(
                declaration_visibilities
                    .insert(visibility.row().definition(), visibility.row().visibility())
                    .is_none(),
                "one selected declaration has at most one visibility row"
            );
        }
        let gap_read = self.session.property_gaps_for_definitions(&targets)?;
        let Some(gap_rows) = self.accept_session_read(gap_read) else {
            return Ok(None);
        };
        let mut property_gaps =
            HashMap::<SemanticId, Vec<(ResolutionGapKind, SemanticId)>>::default();
        for gap in gap_rows {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let gap = gap.get(self.session);
            property_gaps
                .entry(gap.row().definition())
                .or_default()
                .push((gap.row().kind(), gap.row().reason_semantic()));
        }

        let mut visibility_completion_by_target = HashMap::default();
        for &target in &targets {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let Some(target_visibility) = declaration_visibilities.get(&target) else {
                continue;
            };
            let mut visibility_reasons = BTreeSet::new();
            for gap in property_gaps.get(&target).into_iter().flatten() {
                if self.poll_cancelled() {
                    return Ok(None);
                }
                if gap.0 == ResolutionGapKind::UnsupportedVisibility {
                    visibility_reasons.insert(gap.1);
                }
            }
            let expected_reason_count =
                usize::from(*target_visibility != DeclaredVisibility::Public);
            if visibility_reasons.len() != expected_reason_count {
                return Err(StoreError::new(format!(
                    "selected member target {target} visibility {} disagrees with exact unsupported-visibility evidence {visibility_reasons:?}",
                    target_visibility
                )));
            }
            let mut target_reasons = ExactCompletionAccumulator::default();
            for reason in visibility_reasons {
                self.include_semantic_reason(
                    &mut target_reasons,
                    ResolutionIncompleteReason::UnsupportedSemantic(reason),
                );
            }
            let Some(completion) = self.finish_semantic_completion(target_reasons) else {
                return Ok(None);
            };
            visibility_completion_by_target.insert(target, completion);
        }
        Ok(Some(visibility_completion_by_target))
    }

    fn apply_declaration_visibility_to_answers(
        &mut self,
        answers: &mut HashMap<SemanticId, ResolutionAnswer>,
        visibility_completion_by_target: &HashMap<SemanticId, ResolutionCompletion>,
    ) -> bool {
        let mut references = BTreeSet::new();
        for &reference in answers.keys() {
            if self.poll_cancelled() {
                return false;
            }
            references.insert(reference);
        }
        while let Some(reference) = references.pop_first() {
            if self.poll_cancelled() {
                return false;
            }
            let answer = answers
                .remove(&reference)
                .expect("the ordered reference came from this answer map");
            let (answer_targets, answer_witnesses, answer_completion) = answer.into_parts();
            let mut answer_reasons = ExactCompletionAccumulator::default();
            self.include_semantic_completion(&mut answer_reasons, &answer_completion);
            for &target in answer_targets.iter() {
                if self.poll_cancelled() {
                    return false;
                }
                if let Some(completion) = visibility_completion_by_target.get(&target) {
                    self.include_semantic_completion(&mut answer_reasons, completion);
                }
            }
            let mut witnesses = Vec::with_capacity(answer_witnesses.len());
            for witness in answer_witnesses.into_vec() {
                if self.poll_cancelled() {
                    return false;
                }
                let (witness_reference, target, steps, witness_completion) = witness.into_parts();
                let mut witness_reasons = ExactCompletionAccumulator::default();
                self.include_semantic_completion(&mut witness_reasons, &witness_completion);
                if let Some(visibility_completion) = visibility_completion_by_target.get(&target) {
                    self.include_semantic_completion(&mut witness_reasons, visibility_completion);
                }
                let Some(completion) = self.finish_semantic_completion(witness_reasons) else {
                    return false;
                };
                witnesses.push(super::model::ResolutionWitness::new(
                    witness_reference,
                    target,
                    steps,
                    completion,
                ));
            }
            let Some(completion) = self.finish_semantic_completion(answer_reasons) else {
                return false;
            };
            answers.insert(
                reference,
                ResolutionAnswer::new(answer_targets, witnesses, completion),
            );
        }
        !self.poll_cancelled()
    }

    fn load_constructor_qualifier_slots(
        &mut self,
        projection_outputs_by_reference: &HashMap<SemanticId, SemanticId>,
    ) -> StoreResult<Option<HashMap<SemanticId, SemanticId>>> {
        let mut qualifier_slots_by_output = HashMap::default();
        if projection_outputs_by_reference.is_empty() {
            return Ok(Some(qualifier_slots_by_output));
        }
        let mut constructor_references = projection_outputs_by_reference
            .keys()
            .copied()
            .collect::<Vec<_>>();
        constructor_references.sort_unstable();
        let route_read = self
            .session
            .routes_for_references(&constructor_references)?;
        let Some(routes) = self.accept_session_read(route_read) else {
            return Ok(None);
        };
        for route in routes {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let route = *route.get(self.session);
            let Some(&output) = projection_outputs_by_reference.get(&route.row().reference())
            else {
                return Err(StoreError::new(format!(
                    "selected constructor route names an unrequested reference {}",
                    route.row().reference()
                )));
            };
            if route.row().projection_kind() != BindingProjectionKind::TargetConstructorOwnerType
                || route.row().projection_output_slot() != output
            {
                return Err(StoreError::new(format!(
                    "selected constructor route disagrees with projection ({}, {output})",
                    route.row().reference()
                )));
            }
            if qualifier_slots_by_output
                .insert(output, route.row().qualifier_slot())
                .is_some()
            {
                return Err(StoreError::new(format!(
                    "selected constructor projection {output} has multiple qualified routes"
                )));
            }
        }
        for (&reference, &output) in projection_outputs_by_reference {
            if !qualifier_slots_by_output.contains_key(&output) {
                return Err(StoreError::new(format!(
                    "selected constructor projection ({reference}, {output}) has no qualified route"
                )));
            }
        }
        Ok(Some(qualifier_slots_by_output))
    }

    fn evaluate_states(
        &mut self,
        previous_states: &HashMap<SemanticId, TypedFrontierState>,
        answers: &HashMap<SemanticId, ResolutionAnswer>,
    ) -> StoreResult<Option<HashMap<SemanticId, TypedFrontierState>>> {
        let mut states = BTreeMap::new();
        let mut ordered_slots = BTreeSet::new();
        for &slot in &self.demanded_slots {
            self.cancellation_observed |= poll_cancelled(self.cancellation, &mut self.work);
            if self.cancellation_observed {
                return Ok(None);
            }
            ordered_slots.insert(slot);
        }
        let mut slots = Vec::with_capacity(ordered_slots.len());
        while let Some(slot) = ordered_slots.pop_first() {
            if self.poll_cancelled() {
                return Ok(None);
            }
            slots.push(slot);
        }

        let intrinsic_read = self.session.intrinsics_for_slots(&slots)?;
        let Some(intrinsic_rows) = self.accept_session_read(intrinsic_read) else {
            return Ok(None);
        };
        let mut intrinsics = HashMap::default();
        for intrinsic in intrinsic_rows {
            let slot = intrinsic.get(self.session).row().frontier().slot();
            assert!(
                intrinsics.insert(slot, intrinsic).is_none(),
                "one selected slot has at most one intrinsic seed"
            );
        }
        let projection_read = self.session.projections_for_outputs(&slots)?;
        let Some(projection_rows) = self.accept_session_read(projection_read) else {
            return Ok(None);
        };
        let mut projections = HashMap::default();
        let mut constructor_projection_outputs_by_reference = HashMap::default();
        for projection in projection_rows {
            let projection = *projection.get(self.session).row();
            if projection.kind() == BindingProjectionKind::TargetConstructorOwnerType {
                assert!(
                    constructor_projection_outputs_by_reference
                        .insert(projection.reference(), projection.output_slot())
                        .is_none(),
                    "one selected constructor reference has one result projection"
                );
            }
            assert!(
                projections
                    .insert(projection.output_slot(), projection)
                    .is_none(),
                "one selected slot has at most one binding projection"
            );
        }
        let Some(constructor_qualifier_slots_by_output) =
            self.load_constructor_qualifier_slots(&constructor_projection_outputs_by_reference)?
        else {
            return Ok(None);
        };
        let incoming_read = self.session.transfers_to_targets(&slots)?;
        let Some(incoming_rows) = self.accept_session_read(incoming_read) else {
            return Ok(None);
        };
        let mut incoming_targets = HashSet::default();
        let mut closure_sources = BTreeSet::new();
        let mut closure_transfer_rows = Vec::with_capacity(incoming_rows.len());
        let mut transfer_edges = Vec::with_capacity(incoming_rows.len());
        for transfer in &incoming_rows {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let transfer_row = transfer.get(self.session);
            let source = transfer_row.row().source_slot();
            let target = transfer_row.row().rule().target_slot();
            assert!(
                self.demanded_slots.contains(&source),
                "an exhausted demanded-slot predecessor closure contains every transfer source"
            );
            assert!(
                self.demanded_slots.contains(&target),
                "an incoming transfer row must target the demanded closure"
            );
            closure_sources.insert(source);
            incoming_targets.insert(target);
            closure_transfer_rows.push(*transfer);
            transfer_edges.push(TransferEdge {
                source,
                target,
                indirection_delta: transfer_row.row().rule().indirection_delta(),
            });
        }

        // Validate exact selected frontier ownership for every source in the
        // exhausted incoming closure before deriving SCC evidence. This is
        // the point evaluator's sole transfer authority; an opposite source-
        // direction relation is validated only if another consumer actually
        // observes it through this same operation session.
        let mut closure_source_rows = Vec::with_capacity(closure_sources.len());
        while let Some(source) = closure_sources.pop_first() {
            if self.poll_cancelled() {
                return Ok(None);
            }
            closure_source_rows.push(source);
        }
        let completion_read = self.session.frontier_completions(&closure_source_rows)?;
        let Some(closure_completion_rows) = self.accept_session_read(completion_read) else {
            return Ok(None);
        };
        let Some((transfers_by_source, frontier_completions)) = group_selected_transfer_sources(
            self.session,
            closure_transfer_rows,
            closure_completion_rows,
            self.cancellation,
            &mut self.work,
        )?
        else {
            self.cancellation_observed = true;
            return Ok(None);
        };
        let Some(transfer_cycles) =
            classify_transfer_cycles(&transfer_edges, &mut || self.poll_cancelled())
        else {
            self.cancellation_observed = true;
            return Ok(None);
        };

        let mut sources = previous_states.keys().copied().collect::<Vec<_>>();
        sources.sort_unstable();

        let mut target_definitions = BTreeSet::new();
        for answer in answers.values() {
            for &target in answer.targets() {
                if self.poll_cancelled() {
                    return Ok(None);
                }
                target_definitions.insert(target);
            }
        }
        let target_definitions = target_definitions.into_iter().collect::<Vec<_>>();
        let owner_read = self
            .session
            .member_owners_for_definitions(&target_definitions)?;
        let Some(owner_rows) = self.accept_session_read(owner_read) else {
            return Ok(None);
        };
        let mut member_owners =
            HashMap::<SemanticId, Vec<(ResolutionMemberKind, SemanticId)>>::default();
        for owner in owner_rows {
            let owner = owner.get(self.session);
            member_owners
                .entry(owner.row().definition())
                .or_default()
                .push((owner.row().kind(), owner.row().owner_definition()));
        }
        let scope_read = self
            .session
            .member_scopes_for_definitions(&target_definitions)?;
        let Some(scope_rows) = self.accept_session_read(scope_read) else {
            return Ok(None);
        };
        let member_scopes = scope_rows
            .into_iter()
            .map(|scope| scope.get(self.session).row().definition())
            .collect::<HashSet<_>>();
        let declaration_read = self
            .session
            .declaration_types_for_definitions(&target_definitions)?;
        let Some(declaration_rows) = self.accept_session_read(declaration_read) else {
            return Ok(None);
        };
        let mut declaration_types =
            HashMap::<SemanticId, Vec<(DeclarationTypeRole, SemanticId)>>::default();
        for property in declaration_rows {
            let property = property.get(self.session);
            declaration_types
                .entry(property.row().definition())
                .or_default()
                .push((property.row().role(), property.row().slot()));
        }

        for slot in &slots {
            if let Some(seed) = intrinsics.get(slot) {
                let seed = seed.get(self.session);
                if !merge_state_values(
                    &mut states,
                    seed.row().frontier().slot(),
                    seed.row().frontier().possible_values().iter().copied(),
                    seed.row().frontier().completion(),
                    None,
                    self.cancellation,
                    &mut self.work,
                    &mut self.cancellation_observed,
                    &mut self.cancellation_reasons,
                ) {
                    return Ok(None);
                }
            }
            if transfer_cycles.finite_slot(*slot) {
                // The least fixed point of a value-preserving/category-finite
                // cycle is the empty state until an external producer adds a
                // value. Seeding that bottom lets a closed zero-effect SCC be
                // structurally subsumed instead of appearing unresolved.
                if !merge_state_values(
                    &mut states,
                    *slot,
                    std::iter::empty(),
                    &ResolutionCompletion::Complete,
                    None,
                    self.cancellation,
                    &mut self.work,
                    &mut self.cancellation_observed,
                    &mut self.cancellation_reasons,
                ) {
                    return Ok(None);
                }
            }
            if let Some(reason) = transfer_cycles.productive_slot_reason(*slot)
                && !merge_state_values(
                    &mut states,
                    *slot,
                    std::iter::empty(),
                    &incomplete(reason),
                    None,
                    self.cancellation,
                    &mut self.work,
                    &mut self.cancellation_observed,
                    &mut self.cancellation_reasons,
                )
            {
                return Ok(None);
            }
            if let Some(forced) = self.forced_slot_gaps.get(slot) {
                if !merge_state_values(
                    &mut states,
                    *slot,
                    std::iter::empty(),
                    forced,
                    None,
                    self.cancellation,
                    &mut self.work,
                    &mut self.cancellation_observed,
                    &mut self.cancellation_reasons,
                ) {
                    return Ok(None);
                }
            } else if !intrinsics.contains_key(slot)
                && !projections.contains_key(slot)
                && !incoming_targets.contains(slot)
                && !merge_state_values(
                    &mut states,
                    *slot,
                    std::iter::empty(),
                    &incomplete(service_reason(
                        b"missing-slot-producer",
                        &[slot.as_bytes().as_slice()],
                    )),
                    None,
                    self.cancellation,
                    &mut self.work,
                    &mut self.cancellation_observed,
                    &mut self.cancellation_reasons,
                )
            {
                return Ok(None);
            }
        }

        for slot in &slots {
            let Some(projection) = projections.get(slot) else {
                continue;
            };
            let Some(answer) = answers.get(&projection.reference()) else {
                continue;
            };
            if let Some(state) = self.project_binding(
                *projection,
                answer,
                previous_states,
                &member_owners,
                &member_scopes,
                &declaration_types,
                constructor_qualifier_slots_by_output
                    .get(&projection.output_slot())
                    .copied(),
            ) {
                let (slot, values, completion) = state.into_parts();
                if !merge_state_values(
                    &mut states,
                    slot,
                    values.into_vec(),
                    &completion,
                    None,
                    self.cancellation,
                    &mut self.work,
                    &mut self.cancellation_observed,
                    &mut self.cancellation_reasons,
                ) {
                    return Ok(None);
                }
            }
        }

        for source in sources {
            if self.poll_cancelled() {
                break;
            }
            let Some((transfer_fragment, transfers)) = transfers_by_source.get(&source) else {
                continue;
            };
            let source_completion = frontier_completions
                .get(&source)
                .expect("selected transfer grouping validates one source completion");
            assert_eq!(
                source_completion.get(self.session).fragment(),
                *transfer_fragment,
                "selected transfer grouping preserves exact source/completion ownership"
            );
            let mut rules = Vec::with_capacity(transfers.len());
            let mut blocked_rules = Vec::new();
            let mut expected_targets = Vec::with_capacity(transfers.len());
            for transfer in transfers {
                if self.poll_cancelled() {
                    return Ok(None);
                }
                let transfer = transfer.get(self.session);
                let rule = transfer.row().rule();
                let mut cancelled = || poll_cancelled(self.cancellation, &mut self.work);
                let Some(completion) =
                    clone_resolution_completion_with_poll(rule.completion(), &mut cancelled)
                else {
                    self.cancellation_observed = true;
                    return Ok(None);
                };
                expected_targets.push(rule.target_slot());
                let rule = TypeTransferRule::new(
                    rule.semantic(),
                    rule.target_slot(),
                    rule.indirection_delta(),
                    rule.value_transform(),
                    completion,
                );
                if let Some(reason) =
                    transfer_cycles.productive_edge_reason(source, rule.target_slot())
                {
                    blocked_rules.push((rule, reason));
                } else {
                    rules.push(rule);
                }
            }
            let mut cancelled = || poll_cancelled(self.cancellation, &mut self.work);
            let Some(source_completion) = clone_resolution_completion_with_poll(
                source_completion.get(self.session).completion(),
                &mut cancelled,
            ) else {
                self.cancellation_observed = true;
                return Ok(None);
            };
            let mut observed_targets = HashSet::default();
            for (rule, reason) in blocked_rules {
                if self.poll_cancelled() {
                    return Ok(None);
                }
                let target = rule.target_slot();
                observed_targets.insert(target);
                if !self.demanded_slots.contains(&target) {
                    continue;
                }
                // A productive internal transform is evidence, not a value
                // producer. Do not apply even a currently representable
                // adjustment (or special-case ToNoValue): its exact empty
                // alternative combines source state, selected frontier, rule,
                // and the stable component reason.
                let mut completion = ExactCompletionAccumulator::default();
                if !self.include_semantic_completion(
                    &mut completion,
                    previous_states[&source].completion(),
                ) || !self.include_semantic_completion(&mut completion, &source_completion)
                    || !self.include_semantic_completion(&mut completion, rule.completion())
                    || !self.include_semantic_reason(
                        &mut completion,
                        ResolutionIncompleteReason::UnsupportedSemantic(reason),
                    )
                {
                    return Ok(None);
                }
                let Some(completion) = self.finish_semantic_completion(completion) else {
                    return Ok(None);
                };
                if !merge_state_values(
                    &mut states,
                    target,
                    std::iter::empty(),
                    &completion,
                    None,
                    self.cancellation,
                    &mut self.work,
                    &mut self.cancellation_observed,
                    &mut self.cancellation_reasons,
                ) {
                    return Ok(None);
                }
            }
            let (alternatives, aggregate_completion) = apply_type_transfer_rules(
                &previous_states[&source],
                rules,
                source_completion,
                self.cancellation,
            )?;
            self.observe_cancellation_completion(&aggregate_completion);
            for alternative in &alternatives {
                self.observe_cancellation_completion(alternative.completion());
            }
            if self.cancellation_observed {
                return Ok(None);
            }
            for alternative in alternatives {
                let target = alternative.slot();
                observed_targets.insert(target);
                if !self.demanded_slots.contains(&target) {
                    continue;
                }
                let (slot, values, completion) = alternative.into_parts();
                if !merge_state_values(
                    &mut states,
                    slot,
                    values.into_vec(),
                    &completion,
                    None,
                    self.cancellation,
                    &mut self.work,
                    &mut self.cancellation_observed,
                    &mut self.cancellation_reasons,
                ) {
                    return Ok(None);
                }
            }
            // An expected target with no emitted row must retain the source's
            // aggregate read/cancellation coverage. Otherwise a zero-output
            // transfer could silently turn unavailable evidence into absence.
            for target in expected_targets {
                if self.demanded_slots.contains(&target)
                    && !observed_targets.contains(&target)
                    && !merge_state_values(
                        &mut states,
                        target,
                        std::iter::empty(),
                        &aggregate_completion,
                        None,
                        self.cancellation,
                        &mut self.work,
                        &mut self.cancellation_observed,
                        &mut self.cancellation_reasons,
                    )
                {
                    return Ok(None);
                }
            }
        }
        Ok(finish_state_accumulators(
            states,
            self.cancellation,
            &mut self.work,
            &mut self.cancellation_observed,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn project_binding(
        &mut self,
        projection: LoweredBindingProjection,
        answer: &ResolutionAnswer,
        previous_states: &HashMap<SemanticId, TypedFrontierState>,
        member_owners: &HashMap<SemanticId, Vec<(ResolutionMemberKind, SemanticId)>>,
        member_scopes: &HashSet<SemanticId>,
        declaration_types: &HashMap<SemanticId, Vec<(DeclarationTypeRole, SemanticId)>>,
        constructor_qualifier_slot: Option<SemanticId>,
    ) -> Option<TypedFrontierState> {
        if projection.kind() == BindingProjectionKind::TargetConstructorOwnerType {
            let qualifier_slot = constructor_qualifier_slot
                .expect("selected constructor projection has one exact qualified route");
            assert!(
                self.demanded_slots.contains(&qualifier_slot),
                "constructor result projection demands its nominal type qualifier"
            );
            let qualifier = previous_states.get(&qualifier_slot)?;
            let mut completion = answer.completion().clone();
            let mut qualifier_types = BTreeSet::new();
            for &value in qualifier.possible_values() {
                if self.poll_cancelled() {
                    return None;
                }
                match value {
                    ResolutionSlotValue::TypeObject(ty) => {
                        qualifier_types.insert(ty);
                    }
                    ResolutionSlotValue::Runtime { ty, .. } => {
                        completion = completion.combine(&incomplete(service_reason(
                            b"invalid-constructor-qualifier-category",
                            &[
                                qualifier_slot.as_bytes().as_slice(),
                                ty.identity().as_bytes().as_slice(),
                            ],
                        )));
                    }
                }
            }

            // Java construction syntax owns the expression's nominal type.
            // Constructor selection validates that type but cannot choose it:
            // an ambiguous type qualifier must retain every structured
            // alternative even when only one alternative has an explicit
            // constructor target.
            for &target in answer.targets() {
                if self.poll_cancelled() {
                    return None;
                }
                let owners = member_owners
                    .get(&target)
                    .into_iter()
                    .flatten()
                    .filter(|property| property.0 == ResolutionMemberKind::Constructor)
                    .map(|property| property.1)
                    .collect::<BTreeSet<_>>();
                if owners.len() != 1 {
                    completion = completion.combine(&incomplete(service_reason(
                        b"missing-constructor-owner-property",
                        &[target.as_bytes().as_slice()],
                    )));
                    continue;
                }
                let owner = *owners
                    .first()
                    .expect("one constructor owner was asserted above");
                let owner_type = ResolutionTypeRef::new(owner, 0);
                if !qualifier_types.contains(&owner_type) {
                    completion = completion.combine(&incomplete(service_reason(
                        b"constructor-owner-qualifier-mismatch",
                        &[
                            target.as_bytes().as_slice(),
                            owner.as_bytes().as_slice(),
                            qualifier_slot.as_bytes().as_slice(),
                        ],
                    )));
                }
            }
            self.observe_cancellation_completion(&completion);
            if self.cancellation_observed {
                return None;
            }
            return Some(TypedFrontierState::new(
                projection.output_slot(),
                qualifier_types
                    .into_iter()
                    .map(|ty| ResolutionSlotValue::runtime(ty, false))
                    .collect::<Vec<_>>(),
                completion,
            ));
        }

        let mut values = Vec::new();
        let mut completion = ResolutionCompletion::Complete;
        let mut pending = false;
        for &target in answer.targets() {
            match projection.kind() {
                BindingProjectionKind::TargetTypeIdentity => {
                    values.push(ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                        target, 0,
                    )));
                }
                BindingProjectionKind::TargetDeclaredValueType => {
                    self.project_declaration_slots(
                        target,
                        &[DeclarationTypeRole::Value, DeclarationTypeRole::Parameter],
                        previous_states,
                        declaration_types,
                        &mut values,
                        &mut completion,
                        &mut pending,
                    );
                }
                BindingProjectionKind::TargetCallableResultType => {
                    self.project_declaration_slots(
                        target,
                        &[DeclarationTypeRole::Return],
                        previous_states,
                        declaration_types,
                        &mut values,
                        &mut completion,
                        &mut pending,
                    );
                }
                BindingProjectionKind::TargetConstructorOwnerType => {
                    unreachable!("constructor projection is handled before target iteration")
                }
                BindingProjectionKind::TargetTypeOrDeclaredValueType => {
                    if member_scopes.contains(&target) {
                        values.push(ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                            target, 0,
                        )));
                    } else {
                        self.project_declaration_slots(
                            target,
                            &[DeclarationTypeRole::Value, DeclarationTypeRole::Parameter],
                            previous_states,
                            declaration_types,
                            &mut values,
                            &mut completion,
                            &mut pending,
                        );
                    }
                }
            }
        }
        // A complete empty callable result is meaningful only after the
        // binding answer itself proves one applicable candidate. Applicability
        // has no projection-local escape hatch.
        completion = completion.combine(answer.completion());
        self.observe_cancellation_completion(&completion);
        (!pending).then(|| TypedFrontierState::new(projection.output_slot(), values, completion))
    }

    #[allow(clippy::too_many_arguments)]
    fn project_declaration_slots(
        &mut self,
        target: SemanticId,
        roles: &[DeclarationTypeRole],
        previous_states: &HashMap<SemanticId, TypedFrontierState>,
        declaration_types: &HashMap<SemanticId, Vec<(DeclarationTypeRole, SemanticId)>>,
        values: &mut Vec<ResolutionSlotValue>,
        completion: &mut ResolutionCompletion,
        pending: &mut bool,
    ) {
        let properties = declaration_types
            .get(&target)
            .into_iter()
            .flatten()
            .filter(|property| roles.contains(&property.0))
            .copied()
            .collect::<Vec<_>>();
        if properties.is_empty() {
            *completion = completion.combine(&incomplete(service_reason(
                b"missing-declaration-type-property",
                &[target.as_bytes().as_slice()],
            )));
            return;
        }
        for property in properties {
            self.demand_slot(property.1);
            let Some(state) = previous_states.get(&property.1) else {
                *pending = true;
                continue;
            };
            values.extend_from_slice(state.possible_values());
            *completion = completion.combine(state.completion());
        }
    }

    fn root_enclosing_type(&mut self) -> StoreResult<Option<SemanticId>> {
        let Some(Some(owner)) = self.root_reference_owner() else {
            return Ok(None);
        };
        let scope_read = self.session.member_scopes_for_definitions(&[owner])?;
        let Some(scopes) = self.accept_session_read(scope_read) else {
            return Ok(None);
        };
        let owner_read = self.session.member_owners_for_definitions(&[owner])?;
        let Some(owners) = self.accept_session_read(owner_read) else {
            return Ok(None);
        };
        if scopes.len() == 1 && scopes[0].get(self.session).row().definition() == owner {
            return Ok(Some(owner));
        }
        if !scopes.is_empty()
            || owners.len() != 1
            || owners[0].get(self.session).row().definition() != owner
        {
            return Ok(None);
        }
        Ok(Some(owners[0].get(self.session).row().owner_definition()))
    }

    fn implicit_receiver_dispositions(
        &mut self,
        binding: &ResolutionAnswer,
    ) -> Option<HashMap<SemanticId, FactCallableReceiverDisposition>> {
        let mut dispositions = HashMap::<SemanticId, FactCallableReceiverDisposition>::default();
        for witness in binding.witnesses() {
            if self.poll_cancelled() {
                return None;
            }
            let target = witness.target();
            let selected_target = matches!(
                witness.steps().last(),
                Some(WitnessStep::Candidate {
                    semantic,
                    outcome: CandidateOutcome::Selected,
                }) if *semantic == target
            );
            if !selected_target {
                continue;
            }
            let mut external = false;
            for step in witness.steps() {
                if self.poll_cancelled() {
                    return None;
                }
                if matches!(
                    step,
                    WitnessStep::Node(node)
                        if self.session.is_callable_static_import_boundary(*node)
                ) {
                    external = true;
                }
            }
            let disposition = if external {
                FactCallableReceiverDisposition::external()
            } else {
                FactCallableReceiverDisposition::self_receiver()
            };
            dispositions
                .entry(target)
                .and_modify(|selected| {
                    if external {
                        selected.observe_external();
                    } else {
                        selected.observe_self_receiver();
                    }
                })
                .or_insert(disposition);
        }
        Some(dispositions)
    }

    /// Prove only the category of an explicit receiver, not its owner or
    /// member route. A selected Java Receiver/Preserve edge whose sole source
    /// is a runtime-only binding projection can gain more runtime values when
    /// its typed frontier completes, but it cannot gain a type-object
    /// alternative. For a TypeOrValue projection, the immutable lexical
    /// answer must additionally prove its exact target set and an exhausted
    /// member-scope read must classify every target as value-like. This is
    /// enough to close the external receiver channel while every owner,
    /// hierarchy, declared-type, and applicability reason remains live.
    fn explicit_receiver_runtime_category_closed(
        &mut self,
        receiver_slot: SemanticId,
        previous_states: &HashMap<SemanticId, TypedFrontierState>,
    ) -> StoreResult<Option<bool>> {
        let Some(receiver) = previous_states.get(&receiver_slot) else {
            return Ok(Some(false));
        };
        if receiver.possible_values().is_empty()
            || receiver
                .possible_values()
                .iter()
                .any(|value| !matches!(value, ResolutionSlotValue::Runtime { .. }))
        {
            return Ok(Some(false));
        }

        let transfer_read = self.session.transfers_to_targets(&[receiver_slot])?;
        let Some(transfers) = self.accept_session_read(transfer_read) else {
            return Ok(None);
        };
        let [transfer] = transfers.as_slice() else {
            return Ok(Some(false));
        };
        let (source_slot, transfer_matches) = {
            let transfer = transfer.get(self.session);
            let transfer = transfer.row();
            (
                transfer.source_slot(),
                transfer.kind() == ResolutionTypeTransferKind::Receiver
                    && transfer.rule().target_slot() == receiver_slot
                    && transfer.rule().indirection_delta() == 0
                    && transfer.rule().value_transform() == TypeTransferValueTransform::Preserve
                    && transfer.rule().completion() == &ResolutionCompletion::Complete,
            )
        };
        if !transfer_matches {
            return Ok(Some(false));
        }

        let projection_read = self.session.projections_for_outputs(&[source_slot])?;
        let Some(projections) = self.accept_session_read(projection_read) else {
            return Ok(None);
        };
        let [projection] = projections.as_slice() else {
            return Ok(Some(false));
        };
        let projection = *projection.get(self.session).row();
        if matches!(
            projection.kind(),
            BindingProjectionKind::TargetDeclaredValueType
                | BindingProjectionKind::TargetCallableResultType
                | BindingProjectionKind::TargetConstructorOwnerType
        ) {
            return Ok(Some(true));
        }
        if projection.kind() != BindingProjectionKind::TargetTypeOrDeclaredValueType {
            return Ok(Some(false));
        }

        let targets = {
            let Some(answer) = self.lexical_answers.get(&projection.reference()) else {
                return Ok(Some(false));
            };
            if answer.completion() != &ResolutionCompletion::Complete || answer.targets().is_empty()
            {
                return Ok(Some(false));
            }
            answer.targets().to_vec()
        };
        if self.poll_cancelled() {
            return Ok(None);
        }
        let scope_read = self.session.member_scopes_for_definitions(&targets)?;
        let Some(scopes) = self.accept_session_read(scope_read) else {
            return Ok(None);
        };
        Ok(Some(scopes.is_empty()))
    }

    fn explicit_receiver_disposition(
        &mut self,
        target: SemanticId,
        enclosing_type: Option<SemanticId>,
    ) -> Option<FactCallableReceiverDisposition> {
        let Some(evidence) = self.root_explicit_receiver_evidence.get(&target) else {
            return Some(FactCallableReceiverDisposition::unresolved(
                FactReferenceReceiverGap::UnresolvedReceiver,
            ));
        };
        let mut disposition = FactCallableReceiverDisposition::empty();
        let cancellation = self.cancellation;
        let cancellation_observed = &mut self.cancellation_observed;
        let work = &mut self.work;
        for value in evidence.values.iter().copied() {
            let cancelled = *cancellation_observed || poll_cancelled(cancellation, work);
            *cancellation_observed |= cancelled;
            if cancelled {
                return None;
            }
            match value {
                ResolutionSlotValue::TypeObject(ty) => match enclosing_type {
                    Some(enclosing_type)
                        if ty.identity() == enclosing_type && ty.indirection() == 0 =>
                    {
                        disposition.observe_self_receiver();
                    }
                    Some(_) => disposition.observe_external(),
                    None => disposition.mark_unresolved(),
                },
                ResolutionSlotValue::Runtime { .. } => disposition.observe_external(),
            }
        }
        if evidence.category_open || evidence.values.is_empty() {
            disposition.mark_unresolved();
        }
        Some(disposition)
    }

    fn callable_receiver_dispositions(
        &mut self,
        binding: &ResolutionAnswer,
    ) -> StoreResult<Option<Box<[FactCallableReceiverTargetDisposition]>>> {
        if !self.root_is_callable || binding.targets().is_empty() {
            return Ok(Some(Box::new([])));
        }
        let enclosing_type = if self.root_callable_receiver_origin()
            == Some(ResolutionCallableReceiverOrigin::ExplicitExpression)
        {
            self.root_enclosing_type()?
        } else {
            None
        };
        if self.cancellation_observed || self.cancellation.is_cancelled() {
            self.cancellation_observed = true;
            return Ok(None);
        }
        let implicit_dispositions = if self.root_callable_receiver_origin()
            == Some(ResolutionCallableReceiverOrigin::Implicit)
        {
            let Some(dispositions) = self.implicit_receiver_dispositions(binding) else {
                return Ok(None);
            };
            Some(dispositions)
        } else {
            None
        };

        let mut dispositions = Vec::with_capacity(binding.targets().len());
        for &target in binding.targets() {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let disposition = match self.root_callable_receiver_origin() {
                None => FactCallableReceiverDisposition::unresolved(
                    FactReferenceReceiverGap::MissingOrigin,
                ),
                Some(ResolutionCallableReceiverOrigin::CurrentInstance) => {
                    FactCallableReceiverDisposition::self_receiver()
                }
                Some(ResolutionCallableReceiverOrigin::Super) => {
                    FactCallableReceiverDisposition::external()
                }
                Some(ResolutionCallableReceiverOrigin::Implicit) => implicit_dispositions
                    .as_ref()
                    .expect("implicit calls precompute receiver dispositions")
                    .get(&target)
                    .copied()
                    .unwrap_or(FactCallableReceiverDisposition::unresolved(
                        FactReferenceReceiverGap::UnresolvedReceiver,
                    )),
                Some(ResolutionCallableReceiverOrigin::ExplicitExpression) => {
                    let Some(disposition) =
                        self.explicit_receiver_disposition(target, enclosing_type)
                    else {
                        return Ok(None);
                    };
                    disposition
                }
            };
            dispositions.push(FactCallableReceiverTargetDisposition::new(
                target,
                disposition,
            ));
        }
        debug_assert!(
            dispositions
                .iter()
                .map(|entry| entry.target)
                .eq(binding.targets().iter().copied()),
            "receiver disposition targets must stay aligned with binding targets"
        );
        Ok(Some(dispositions.into_boxed_slice()))
    }

    fn finish(
        &mut self,
        mut answers: HashMap<SemanticId, ResolutionAnswer>,
        mut states: HashMap<SemanticId, TypedFrontierState>,
    ) -> StoreResult<Option<FactResolutionAnswer>> {
        let binding = answers.remove(&self.root).unwrap_or_else(|| {
            ResolutionAnswer::new(
                Vec::new(),
                Vec::new(),
                incomplete(service_reason(
                    b"missing-root-answer",
                    &[self.root.as_bytes().as_slice()],
                )),
            )
        });
        self.observe_cancellation_completion(binding.completion());
        for witness in binding.witnesses() {
            self.poll_cancellation_ledger();
            self.observe_cancellation_completion(witness.completion());
        }
        if self.cancellation_observed {
            return Ok(None);
        }
        let mut projected_slots = BTreeMap::new();
        let projection_read = self.session.projections_for_references(&[self.root])?;
        let Some(projections) = self.accept_session_read(projection_read) else {
            return Ok(None);
        };
        for projection in projections {
            self.cancellation_observed |= poll_cancelled(self.cancellation, &mut self.work);
            if self.cancellation_observed {
                return Ok(None);
            }
            let projection = projection.get(self.session).row();
            let slot = projection.output_slot();
            assert!(
                projected_slots.insert(slot, projection.kind()).is_none(),
                "one selected slot has at most one binding projection"
            );
        }
        let mut completion = ExactCompletionAccumulator::default();
        if !self.include_semantic_completion(&mut completion, binding.completion()) {
            return Ok(None);
        }
        let mut projected_frontiers = Vec::new();
        while let Some((slot, kind)) = projected_slots.pop_first() {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let Some(state) = states.remove(&slot) else {
                continue;
            };
            if !self.include_semantic_completion(&mut completion, state.completion()) {
                return Ok(None);
            }
            projected_frontiers.push(FactProjectedFrontier::new(state, kind));
        }
        let Some(completion) = self.finish_semantic_completion(completion) else {
            return Ok(None);
        };
        if self.cancellation.is_cancelled() {
            self.cancellation_observed = true;
            return Ok(None);
        }
        let Some(callable_receiver_dispositions) = self.callable_receiver_dispositions(&binding)?
        else {
            return Ok(None);
        };
        Ok(Some(FactResolutionAnswer {
            site_metadata: self.root_site_metadata,
            callable_receiver_dispositions,
            binding,
            projected_frontiers: projected_frontiers.into_boxed_slice(),
            completion,
        }))
    }

    fn finish_with_cycle_gap(
        &mut self,
        answers: HashMap<SemanticId, ResolutionAnswer>,
        states: HashMap<SemanticId, TypedFrontierState>,
    ) -> StoreResult<Option<FactResolutionAnswer>> {
        let Some(mut answer) = self.finish(answers, states)? else {
            return Ok(None);
        };
        let cycle_reason = ResolutionIncompleteReason::UnsupportedSemantic(service_reason(
            b"typed-fixed-point-cycle",
            &[self.root.as_bytes().as_slice()],
        ));
        let (targets, witnesses, binding_completion) = answer.binding.into_parts();
        let mut binding_reasons = ExactCompletionAccumulator::default();
        self.include_semantic_completion(&mut binding_reasons, &binding_completion);
        self.include_semantic_reason(&mut binding_reasons, cycle_reason);
        let Some(binding_completion) = self.finish_semantic_completion(binding_reasons) else {
            return Ok(None);
        };
        answer.binding = ResolutionAnswer::new(targets, witnesses, binding_completion);

        let mut projected_frontiers = Vec::with_capacity(answer.projected_frontiers.len());
        for state in answer.projected_frontiers.into_vec() {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let mut state_reasons = ExactCompletionAccumulator::default();
            self.include_semantic_completion(&mut state_reasons, state.completion());
            self.include_semantic_reason(&mut state_reasons, cycle_reason);
            let Some(completion) = self.finish_semantic_completion(state_reasons) else {
                return Ok(None);
            };
            projected_frontiers.push(state.with_completion(completion));
        }
        answer.projected_frontiers = projected_frontiers.into_boxed_slice();

        let mut aggregate_reasons = ExactCompletionAccumulator::default();
        self.include_semantic_completion(&mut aggregate_reasons, &answer.completion);
        self.include_semantic_reason(&mut aggregate_reasons, cycle_reason);
        let Some(completion) = self.finish_semantic_completion(aggregate_reasons) else {
            return Ok(None);
        };
        answer.completion = completion;
        if matches!(
            answer.callable_receiver_origin(),
            Some(
                ResolutionCallableReceiverOrigin::Implicit
                    | ResolutionCallableReceiverOrigin::ExplicitExpression
            )
        ) {
            for disposition in answer.callable_receiver_dispositions.iter_mut() {
                if self.poll_cancelled() {
                    return Ok(None);
                }
                disposition.disposition.mark_unresolved();
            }
        }
        if self.cancellation.is_cancelled() {
            self.cancellation_observed = true;
            return Ok(None);
        }
        Ok(Some(answer))
    }
}

fn qualified_seed_path<P>(
    seed: &super::batch::ReferenceSeed,
    route: &SourceSelectedQualifiedRoute,
    scope_head: BindingNodeId,
    origin: SemanticId,
    ancestry: &[SemanticId],
    completion: ResolutionCompletion,
    cancelled: &mut P,
) -> Option<PartialPath>
where
    P: FnMut() -> bool,
{
    let mut witness = Vec::with_capacity(ancestry.len() + 2);
    witness.push(WitnessStep::Candidate {
        semantic: origin,
        outcome: CandidateOutcome::Selected,
    });
    for &reference in ancestry {
        if cancelled() {
            return None;
        }
        witness.push(WitnessStep::Candidate {
            semantic: reference,
            outcome: CandidateOutcome::Selected,
        });
    }
    witness.push(WitnessStep::Node(scope_head));
    PartialPath::new_with_poll(
        closed_endpoint(seed.node(), []),
        closed_endpoint(scope_head, [route.row().lookup()]),
        vec![PrecedenceStep {
            tier: PrecedenceTier::LexicalBinding,
            ordinal: route.row().precedence_ordinal(),
            semantic: route.row().reference(),
        }]
        .into_boxed_slice(),
        witness.into_boxed_slice(),
        completion,
        cancelled,
    )
}

fn qualified_seed_path_id(
    route: &SourceSelectedQualifiedRoute,
    scope_head: BindingNodeId,
    value: ResolutionSlotValue,
    origin: SemanticId,
) -> PartialPathId {
    let mut hasher = CanonicalHasher::new(b"bifrost-resolution-qualified-seed-path:v1");
    hasher.field("reference", &route.row().reference().as_bytes());
    hasher.field("qualifier_slot", &route.row().qualifier_slot().as_bytes());
    hasher.field("lookup", &route.row().lookup().as_bytes());
    hasher.field(
        "namespace",
        route.row().namespace().identity_label().as_bytes(),
    );
    hasher.field(
        "precedence_ordinal",
        &route.row().precedence_ordinal().to_le_bytes(),
    );
    hasher.field("scope_head", &scope_head.as_bytes());
    hasher.field("origin", &origin.as_bytes());
    hasher.field("receiver_type", &value.ty().identity().as_bytes());
    hasher.field("indirection", &value.ty().indirection().to_le_bytes());
    hasher.field(
        "category",
        match value {
            ResolutionSlotValue::TypeObject(_) => b"type",
            ResolutionSlotValue::Runtime { .. } => b"runtime",
        },
    );
    if let ResolutionSlotValue::Runtime { addressable, .. } = value {
        hasher.field("addressable", &[u8::from(addressable)]);
    }
    PartialPathId::in_fragment(route.fragment(), &hasher.finish())
}

fn qualified_origin_identity(
    route: &SourceSelectedQualifiedRoute,
    shape: HierarchyLookupShape,
    owner: SemanticId,
    value: ResolutionSlotValue,
    ancestry: &[SemanticId],
    cancelled: &mut dyn FnMut() -> bool,
) -> Option<SemanticId> {
    let mut hasher = CanonicalHasher::new(b"bifrost-resolution-qualified-origin:v1");
    hasher.field("fragment", &route.fragment().as_bytes());
    hasher.field("reference", &route.row().reference().as_bytes());
    hasher.field("reference-node", &route.reference_node().as_bytes());
    hasher.field("qualifier-slot", &route.row().qualifier_slot().as_bytes());
    hasher.field(
        "precedence-ordinal",
        &route.row().precedence_ordinal().to_le_bytes(),
    );
    hash_hierarchy_shape(&mut hasher, shape);
    hasher.field("owner", &owner.as_bytes());
    hasher.field("receiver-type", &value.ty().identity().as_bytes());
    hasher.field(
        "receiver-indirection",
        &value.ty().indirection().to_le_bytes(),
    );
    if let ResolutionSlotValue::Runtime { addressable, .. } = value {
        hasher.field("receiver-addressable", &[u8::from(addressable)]);
    }
    for &reference in ancestry {
        if cancelled() {
            return None;
        }
        hasher.field("supertype-reference", &reference.as_bytes());
    }
    Some(SemanticId::from_digest(hasher.finish()))
}

fn closed_endpoint<const N: usize>(
    node: BindingNodeId,
    symbols: [SemanticId; N],
) -> EndpointSignature {
    EndpointSignature::new(
        node,
        StackPattern::closed(symbols),
        StackPattern::closed(Vec::new()),
    )
}

fn hash_hierarchy_shape(hasher: &mut CanonicalHasher, shape: HierarchyLookupShape) {
    hasher.field("lookup", &shape.lookup.as_bytes());
    hasher.field("namespace", shape.namespace.identity_label().as_bytes());
    hasher.field(
        "category",
        match shape.category {
            QualifierCategory::Type => b"type",
            QualifierCategory::Runtime => b"runtime",
        },
    );
    hasher.field(
        "receiver_indirection",
        &shape.receiver_indirection.to_le_bytes(),
    );
}

fn hierarchy_node_atom_identity(label: &[u8], key: HierarchyNodeKey) -> SemanticId {
    let mut hasher = CanonicalHasher::new(b"bifrost-resolution-hierarchy-node-atom:v1");
    hasher.field("kind", label);
    hash_hierarchy_shape(&mut hasher, key.shape);
    hasher.field("owner", &key.owner.as_bytes());
    SemanticId::from_digest(hasher.finish())
}

fn hierarchy_global_atom_identity(label: &[u8]) -> SemanticId {
    let mut hasher = CanonicalHasher::new(b"bifrost-resolution-hierarchy-global-atom:v1");
    hasher.field("kind", label);
    SemanticId::from_digest(hasher.finish())
}

fn hierarchy_support_read_identity(label: &[u8], requests: &[SemanticId]) -> SemanticId {
    let mut hasher = CanonicalHasher::new(b"bifrost-resolution-hierarchy-support-read:v1");
    hasher.field("family", label);
    for &request in requests {
        hasher.field("request", &request.as_bytes());
    }
    SemanticId::from_digest(hasher.finish())
}

fn hierarchy_support_fragment_batch_identity(
    label: &[u8],
    fragment: BindingFragmentId,
    references: &[SemanticId],
) -> SemanticId {
    let mut hasher = CanonicalHasher::new(b"bifrost-resolution-hierarchy-support-batch:v1");
    hasher.field("family", label);
    hasher.field("fragment", &fragment.as_bytes());
    for &reference in references {
        hasher.field("reference", &reference.as_bytes());
    }
    SemanticId::from_digest(hasher.finish())
}

fn hierarchy_local_branch_atom_identity(
    scope_head: BindingNodeId,
    lookup: SemanticId,
) -> SemanticId {
    let mut hasher = CanonicalHasher::new(b"bifrost-resolution-hierarchy-local-branch-atom:v1");
    hasher.field("scope-head", &scope_head.as_bytes());
    hasher.field("lookup", &lookup.as_bytes());
    SemanticId::from_digest(hasher.finish())
}

fn hierarchy_local_candidate_atom_identity(candidate: CandidatePathIdentity) -> SemanticId {
    let mut hasher = CanonicalHasher::new(b"bifrost-resolution-hierarchy-local-candidate-atom:v1");
    hasher.field("fragment", &candidate.fragment().as_bytes());
    hasher.field("path", &candidate.path().as_bytes());
    SemanticId::from_digest(hasher.finish())
}

fn hierarchy_member_owner_atom_identity(
    key: HierarchyNodeKey,
    definition: SemanticId,
) -> SemanticId {
    let mut hasher = CanonicalHasher::new(b"bifrost-resolution-hierarchy-member-owner-atom:v1");
    hash_hierarchy_shape(&mut hasher, key.shape);
    hasher.field("owner", &key.owner.as_bytes());
    hasher.field("definition", &definition.as_bytes());
    SemanticId::from_digest(hasher.finish())
}

fn hierarchy_member_owner_reason(key: HierarchyNodeKey, definition: SemanticId) -> SemanticId {
    service_reason(
        b"missing-member-owner-property",
        &[
            key.shape.lookup.as_bytes().as_slice(),
            key.shape.namespace.identity_label().as_bytes(),
            match key.shape.category {
                QualifierCategory::Type => b"type",
                QualifierCategory::Runtime => b"runtime",
            },
            &key.shape.receiver_indirection.to_le_bytes(),
            key.owner.as_bytes().as_slice(),
            definition.as_bytes().as_slice(),
        ],
    )
}

fn hierarchy_gap_atom_identity(gap: &SelectedTypedRow<LoweredDefinitionPropertyGap>) -> SemanticId {
    let mut hasher = CanonicalHasher::new(b"bifrost-resolution-hierarchy-gap-atom:v1");
    hasher.field("fragment", &gap.fragment().as_bytes());
    hasher.field("definition", &gap.row().definition().as_bytes());
    hasher.field("source-site", &gap.row().source_site().get().to_le_bytes());
    hasher.field("frontier", &gap.row().frontier().as_bytes());
    hasher.field("reason", &gap.row().reason_semantic().as_bytes());
    SemanticId::from_digest(hasher.finish())
}

fn hierarchy_route_atom_identity(route: &SourceSelectedQualifiedRoute) -> SemanticId {
    let mut hasher = CanonicalHasher::new(b"bifrost-resolution-hierarchy-route-atom:v1");
    hasher.field("fragment", &route.fragment().as_bytes());
    hasher.field("reference", &route.row().reference().as_bytes());
    hasher.field(
        "precedence-ordinal",
        &route.row().precedence_ordinal().to_le_bytes(),
    );
    hasher.field("qualifier-slot", &route.row().qualifier_slot().as_bytes());
    hasher.field("lookup", &route.row().lookup().as_bytes());
    hasher.field("reason", &route.row().coarse_gap_reason().as_bytes());
    SemanticId::from_digest(hasher.finish())
}

fn hierarchy_qualifier_cancellation_atom_identity(
    qualifier_slot: SemanticId,
    reason: ResolutionIncompleteReason,
) -> SemanticId {
    let mut hasher =
        CanonicalHasher::new(b"bifrost-resolution-hierarchy-qualifier-cancellation-atom:v1");
    hasher.field("qualifier-slot", &qualifier_slot.as_bytes());
    match reason {
        ResolutionIncompleteReason::Cancelled => {
            hasher.field("reason-kind", b"cancelled");
        }
        ResolutionIncompleteReason::CyclicExpansion(path) => {
            hasher.field("reason-kind", b"cyclic-expansion");
            hasher.field("reason-path", &path.as_bytes());
        }
        ResolutionIncompleteReason::InconsistentPrecedence(semantic) => {
            hasher.field("reason-kind", b"inconsistent-precedence");
            hasher.field("reason-semantic", &semantic.as_bytes());
        }
        ResolutionIncompleteReason::OpenBoundary { semantic, status } => {
            hasher.field("reason-kind", b"open-boundary");
            hasher.field("reason-semantic", &semantic.as_bytes());
            hasher.field("reason-boundary", status.label().as_bytes());
        }
        ResolutionIncompleteReason::UnsupportedSemantic(semantic) => {
            hasher.field("reason-kind", b"unsupported-semantic");
            hasher.field("reason-semantic", &semantic.as_bytes());
        }
    }
    SemanticId::from_digest(hasher.finish())
}

fn hierarchy_edge_atom_identity(
    label: &[u8],
    owner: SemanticId,
    reference: SemanticId,
    frontier: SemanticId,
) -> SemanticId {
    let mut hasher = CanonicalHasher::new(b"bifrost-resolution-hierarchy-edge-atom:v1");
    hasher.field("kind", label);
    hasher.field("owner", &owner.as_bytes());
    hasher.field("reference", &reference.as_bytes());
    hasher.field("frontier", &frontier.as_bytes());
    SemanticId::from_digest(hasher.finish())
}

fn hierarchy_reference_atom_identity(reference: SemanticId) -> SemanticId {
    let mut hasher = CanonicalHasher::new(b"bifrost-resolution-hierarchy-reference-atom:v1");
    hasher.field("reference", &reference.as_bytes());
    SemanticId::from_digest(hasher.finish())
}

fn hierarchy_cycle_atom_identity(cycle: PartialPathId) -> SemanticId {
    let mut hasher = CanonicalHasher::new(b"bifrost-resolution-hierarchy-cycle-atom:v1");
    hasher.field("cycle", &cycle.as_bytes());
    SemanticId::from_digest(hasher.finish())
}

fn hierarchy_iterative_scc_terminals(
    owners: &BTreeSet<SemanticId>,
    adjacency: &BTreeMap<SemanticId, BTreeSet<SemanticId>>,
    metrics: &mut HierarchyDerivedWork,
    cancelled: &mut dyn FnMut() -> bool,
) -> Option<HashMap<SemanticId, PartialPathId>> {
    #[derive(Debug, Clone, Copy)]
    struct Frame {
        owner: SemanticId,
        parent: Option<SemanticId>,
        next_target: usize,
    }

    let mut ordered_adjacency = BTreeMap::<SemanticId, Box<[SemanticId]>>::new();
    for &owner in owners {
        if cancelled() {
            return None;
        }
        let mut ordered = Vec::new();
        for &target in adjacency.get(&owner).into_iter().flatten() {
            if cancelled() {
                return None;
            }
            assert!(
                owners.contains(&target),
                "Tarjan adjacency is closed over the staged owner set"
            );
            ordered.push(target);
        }
        ordered_adjacency.insert(owner, ordered.into_boxed_slice());
    }

    let mut next_index = 0_usize;
    let mut indices = HashMap::<SemanticId, usize>::default();
    let mut lowlinks = HashMap::<SemanticId, usize>::default();
    let mut active = HashSet::default();
    let mut component_stack = Vec::new();
    let mut cycles = HashMap::default();
    for &root in owners {
        if cancelled() {
            return None;
        }
        if indices.contains_key(&root) {
            continue;
        }
        indices.insert(root, next_index);
        lowlinks.insert(root, next_index);
        next_index += 1;
        metrics.scc_owner_visits += 1;
        component_stack.push(root);
        active.insert(root);
        let mut dfs = vec![Frame {
            owner: root,
            parent: None,
            next_target: 0,
        }];
        while !dfs.is_empty() {
            // This gate covers terminal owners with no outgoing targets too.
            if cancelled() {
                return None;
            }
            let frame_index = dfs.len() - 1;
            let owner = dfs[frame_index].owner;
            let targets = &ordered_adjacency[&owner];
            if dfs[frame_index].next_target < targets.len() {
                let target = targets[dfs[frame_index].next_target];
                dfs[frame_index].next_target += 1;
                metrics.scc_arc_visits += 1;
                if let std::collections::hash_map::Entry::Vacant(entry) = indices.entry(target) {
                    entry.insert(next_index);
                    lowlinks.insert(target, next_index);
                    next_index += 1;
                    metrics.scc_owner_visits += 1;
                    component_stack.push(target);
                    active.insert(target);
                    dfs.push(Frame {
                        owner: target,
                        parent: Some(owner),
                        next_target: 0,
                    });
                } else if active.contains(&target) {
                    let target_index = indices[&target];
                    let lowlink = lowlinks
                        .get_mut(&owner)
                        .expect("an active Tarjan owner has a lowlink");
                    *lowlink = (*lowlink).min(target_index);
                }
                continue;
            }

            let finished = dfs.pop().expect("the Tarjan DFS frame is nonempty");
            let owner_lowlink = lowlinks[&finished.owner];
            if let Some(parent) = finished.parent {
                let parent_lowlink = lowlinks
                    .get_mut(&parent)
                    .expect("a Tarjan parent has a lowlink");
                *parent_lowlink = (*parent_lowlink).min(owner_lowlink);
            }
            if owner_lowlink != indices[&finished.owner] {
                continue;
            }
            let mut component = BTreeSet::new();
            loop {
                if cancelled() {
                    return None;
                }
                let member = component_stack
                    .pop()
                    .expect("a Tarjan root has an active component member");
                active.remove(&member);
                component.insert(member);
                if member == finished.owner {
                    break;
                }
            }
            let cyclic = component.len() > 1
                || ordered_adjacency[&finished.owner]
                    .binary_search(&finished.owner)
                    .is_ok();
            if !cyclic {
                continue;
            }
            let mut hasher = CanonicalHasher::new(b"bifrost-resolution-hierarchy-scc:v1");
            hasher.field(
                "owner-count",
                &u64::try_from(component.len())
                    .expect("hierarchy SCC owner count fits u64")
                    .to_le_bytes(),
            );
            for &member in &component {
                if cancelled() {
                    return None;
                }
                hasher.field("owner", &member.as_bytes());
            }
            let cycle = PartialPathId::from_digest(hasher.finish());
            while let Some(member) = component.pop_first() {
                if cancelled() {
                    return None;
                }
                assert!(
                    cycles.insert(member, cycle).is_none(),
                    "one hierarchy owner belongs to one Tarjan component"
                );
            }
        }
    }
    Some(cycles)
}

fn qualifier_compatible(
    compatibility: ResolutionMemberQualifierCompatibility,
    category: QualifierCategory,
) -> bool {
    match compatibility {
        ResolutionMemberQualifierCompatibility::RuntimeOnly => {
            category == QualifierCategory::Runtime
        }
        ResolutionMemberQualifierCompatibility::TypeOnly => category == QualifierCategory::Type,
        ResolutionMemberQualifierCompatibility::RuntimeOrType => true,
    }
}

fn exact_singleton_runtime_type(state: &TypedFrontierState) -> Option<ResolutionTypeRef> {
    if state.completion() != &ResolutionCompletion::Complete {
        return None;
    }
    match state.possible_values() {
        [ResolutionSlotValue::Runtime { ty, .. }] => Some(*ty),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy)]
struct TransferEdge {
    source: SemanticId,
    target: SemanticId,
    indirection_delta: i64,
}

trait TransferCycleInput {
    fn transfer_edge(&self) -> TransferEdge;
}

impl TransferCycleInput for TransferEdge {
    fn transfer_edge(&self) -> TransferEdge {
        *self
    }
}

#[cfg(test)]
impl TransferCycleInput for Rc<SelectedTypedRow<LoweredTypeTransfer>> {
    fn transfer_edge(&self) -> TransferEdge {
        TransferEdge {
            source: self.row().source_slot(),
            target: self.row().rule().target_slot(),
            indirection_delta: self.row().rule().indirection_delta(),
        }
    }
}

#[cfg(test)]
impl TransferCycleInput for SelectedTypedRow<LoweredTypeTransfer> {
    fn transfer_edge(&self) -> TransferEdge {
        TransferEdge {
            source: self.row().source_slot(),
            target: self.row().rule().target_slot(),
            indirection_delta: self.row().rule().indirection_delta(),
        }
    }
}

#[derive(Debug, Default)]
struct TransferCycleClassification {
    finite_slots: HashSet<SemanticId>,
    productive_slots: HashMap<SemanticId, SemanticId>,
    productive_edges: HashMap<(SemanticId, SemanticId), SemanticId>,
}

impl TransferCycleClassification {
    fn finite_slot(&self, slot: SemanticId) -> bool {
        self.finite_slots.contains(&slot)
    }

    fn productive_slot_reason(&self, slot: SemanticId) -> Option<SemanticId> {
        self.productive_slots.get(&slot).copied()
    }

    fn productive_edge_reason(&self, source: SemanticId, target: SemanticId) -> Option<SemanticId> {
        self.productive_edges.get(&(source, target)).copied()
    }
}

/// Classify one exhausted demand-local incoming-transfer closure.
///
/// A zero-delta SCC has a finite value/category domain and may reach its least
/// fixed point normally. Any SCC containing a nonzero indirection transform
/// can generate an unbounded sequence, even when the net delta around one
/// particular cycle is zero. Every internal edge of such an SCC is therefore
/// blocked and receives the same stable, component-local incomplete evidence.
/// The input rows are the selected source's sole transfer authority. Every
/// graph walk is iterative and every semantic row/node transition polls the
/// caller, so cancellation returns no usable partial classification.
fn classify_transfer_cycles<T: TransferCycleInput>(
    transfers: &[T],
    cancelled: &mut dyn FnMut() -> bool,
) -> Option<TransferCycleClassification> {
    let mut edges = Vec::with_capacity(transfers.len());
    let mut nodes = BTreeSet::new();
    let mut forward: HashMap<SemanticId, Vec<SemanticId>> = HashMap::default();
    let mut reverse: HashMap<SemanticId, Vec<SemanticId>> = HashMap::default();
    for transfer in transfers {
        if cancelled() {
            return None;
        }
        let edge = transfer.transfer_edge();
        nodes.insert(edge.source);
        nodes.insert(edge.target);
        forward.entry(edge.source).or_default().push(edge.target);
        reverse.entry(edge.target).or_default().push(edge.source);
        edges.push(edge);
    }

    let mut visited = HashSet::default();
    let mut finish_order = Vec::with_capacity(nodes.len());
    for root in nodes.iter().copied() {
        if cancelled() {
            return None;
        }
        if visited.contains(&root) {
            continue;
        }
        let mut stack = vec![(root, false)];
        while let Some((node, exiting)) = stack.pop() {
            if cancelled() {
                return None;
            }
            if exiting {
                finish_order.push(node);
                continue;
            }
            if !visited.insert(node) {
                continue;
            }
            stack.push((node, true));
            if let Some(neighbors) = forward.get(&node) {
                for &neighbor in neighbors.iter().rev() {
                    if cancelled() {
                        return None;
                    }
                    stack.push((neighbor, false));
                }
            }
        }
    }

    let mut assigned = HashSet::default();
    let mut components = Vec::new();
    for root in finish_order.into_iter().rev() {
        if cancelled() {
            return None;
        }
        if !assigned.insert(root) {
            continue;
        }
        let mut component = BTreeSet::new();
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if cancelled() {
                return None;
            }
            component.insert(node);
            if let Some(neighbors) = reverse.get(&node) {
                for &neighbor in neighbors.iter().rev() {
                    if cancelled() {
                        return None;
                    }
                    if assigned.insert(neighbor) {
                        stack.push(neighbor);
                    }
                }
            }
        }
        let mut ordered_component = Vec::with_capacity(component.len());
        while let Some(slot) = component.pop_first() {
            if cancelled() {
                return None;
            }
            ordered_component.push(slot);
        }
        components.push(ordered_component);
    }

    let mut component_by_node = HashMap::default();
    for (component_id, component) in components.iter().enumerate() {
        for &slot in component {
            if cancelled() {
                return None;
            }
            assert!(
                component_by_node.insert(slot, component_id).is_none(),
                "one transfer slot belongs to one strongly connected component"
            );
        }
    }
    let mut cyclic = Vec::with_capacity(components.len());
    let mut productive = Vec::with_capacity(components.len());
    for component in &components {
        if cancelled() {
            return None;
        }
        cyclic.push(component.len() > 1);
        productive.push(false);
    }
    for edge in &edges {
        if cancelled() {
            return None;
        }
        let source_component = component_by_node[&edge.source];
        let target_component = component_by_node[&edge.target];
        if source_component != target_component {
            continue;
        }
        cyclic[source_component] |= edge.source == edge.target;
        productive[source_component] |= edge.indirection_delta != 0;
    }

    let mut classification = TransferCycleClassification::default();
    let mut productive_reasons = HashMap::default();
    for (component_id, component) in components.iter().enumerate() {
        if cancelled() {
            return None;
        }
        if !cyclic[component_id] {
            continue;
        }
        if productive[component_id] {
            let reason = productive_transfer_cycle_reason(component, cancelled)?;
            assert!(
                productive_reasons.insert(component_id, reason).is_none(),
                "one productive component owns one stable reason"
            );
            for &slot in component {
                if cancelled() {
                    return None;
                }
                assert!(
                    classification
                        .productive_slots
                        .insert(slot, reason)
                        .is_none(),
                    "one slot belongs to one productive component"
                );
            }
        } else {
            for &slot in component {
                if cancelled() {
                    return None;
                }
                classification.finite_slots.insert(slot);
            }
        }
    }
    for edge in edges {
        if cancelled() {
            return None;
        }
        let component_id = component_by_node[&edge.source];
        if component_id == component_by_node[&edge.target]
            && let Some(&reason) = productive_reasons.get(&component_id)
        {
            classification
                .productive_edges
                .insert((edge.source, edge.target), reason);
        }
    }
    (!cancelled()).then_some(classification)
}

fn productive_transfer_cycle_reason(
    component: &[SemanticId],
    cancelled: &mut dyn FnMut() -> bool,
) -> Option<SemanticId> {
    let mut hasher = CanonicalHasher::new(b"bifrost-resolution-productive-transfer-cycle:v1");
    for (index, slot) in component.iter().enumerate() {
        if cancelled() {
            return None;
        }
        hasher.field(&format!("slot-{index}"), &slot.as_bytes());
    }
    (!cancelled()).then(|| SemanticId::from_digest(hasher.finish()))
}

#[allow(clippy::too_many_arguments)]
fn merge_state_values(
    states: &mut BTreeMap<SemanticId, TypedStateAccumulator>,
    slot: SemanticId,
    values: impl IntoIterator<Item = ResolutionSlotValue>,
    completion: &ResolutionCompletion,
    extra_reason: Option<ResolutionIncompleteReason>,
    cancellation: &CancellationToken,
    work: &mut usize,
    cancellation_observed: &mut bool,
    cancellation_reasons: &mut CancellationReasonCollection,
) -> bool {
    include_completion_reasons_with_poll(
        cancellation_reasons,
        completion,
        cancellation,
        work,
        cancellation_observed,
    );
    let state = states.entry(slot).or_default();
    if *cancellation_observed {
        return false;
    }
    if state
        .completion
        .include(completion, &mut || {
            let observed = poll_cancelled(cancellation, work);
            *cancellation_observed |= observed;
            observed
        })
        .is_none()
    {
        *cancellation_observed = true;
        return false;
    }
    if let Some(reason) = extra_reason {
        cancellation_reasons.include_reason_with_poll(
            reason,
            cancellation,
            work,
            cancellation_observed,
        );
        if *cancellation_observed {
            return false;
        }
        if state
            .completion
            .include_reason(reason, &mut || {
                let observed = poll_cancelled(cancellation, work);
                *cancellation_observed |= observed;
                observed
            })
            .is_none()
        {
            *cancellation_observed = true;
            return false;
        }
    }
    for value in values {
        *cancellation_observed |= poll_cancelled(cancellation, work);
        if *cancellation_observed {
            return false;
        }
        state.values.insert(value);
    }
    *cancellation_observed |= cancellation.is_cancelled();
    !*cancellation_observed
}

fn finish_state_accumulators(
    mut accumulators: BTreeMap<SemanticId, TypedStateAccumulator>,
    cancellation: &CancellationToken,
    work: &mut usize,
    cancellation_observed: &mut bool,
) -> Option<HashMap<SemanticId, TypedFrontierState>> {
    let mut states = HashMap::default();
    while let Some((slot, mut accumulator)) = accumulators.pop_first() {
        *cancellation_observed |= poll_cancelled(cancellation, work);
        if *cancellation_observed {
            return None;
        }
        let mut values = Vec::with_capacity(accumulator.values.len());
        while let Some(value) = accumulator.values.pop_first() {
            *cancellation_observed |= poll_cancelled(cancellation, work);
            if *cancellation_observed {
                return None;
            }
            values.push(value);
        }
        let completion = accumulator.completion.finish(&mut || {
            let observed = poll_cancelled(cancellation, work);
            *cancellation_observed |= observed;
            observed
        })?;
        let state = TypedFrontierState::from_canonical_parts(
            slot,
            values.into_boxed_slice(),
            completion,
            || {
                let observed = poll_cancelled(cancellation, work);
                *cancellation_observed |= observed;
                observed
            },
        )?;
        assert!(
            states.insert(slot, state).is_none(),
            "one canonical typed state is published per slot"
        );
    }
    *cancellation_observed |= cancellation.is_cancelled();
    (!*cancellation_observed).then_some(states)
}

fn poll_cancelled(cancellation: &CancellationToken, work: &mut usize) -> bool {
    *work += 1;
    (*work).is_multiple_of(CANCELLATION_QUANTUM) && cancellation.is_cancelled()
}

fn answer_maps_equal_with_poll(
    left: &HashMap<SemanticId, ResolutionAnswer>,
    right: &HashMap<SemanticId, ResolutionAnswer>,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<bool> {
    if left.len() != right.len() {
        return Some(false);
    }
    for (semantic, left) in left {
        if poll_cancelled(cancellation, work) {
            return None;
        }
        let Some(right) = right.get(semantic) else {
            return Some(false);
        };
        let equal =
            answers_equal_with_poll(left, right, &mut || poll_cancelled(cancellation, work))?;
        if !equal {
            return Some(false);
        }
    }
    Some(true)
}

fn state_maps_equal_with_poll(
    left: &HashMap<SemanticId, TypedFrontierState>,
    right: &HashMap<SemanticId, TypedFrontierState>,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<bool> {
    if left.len() != right.len() {
        return Some(false);
    }
    for (slot, left) in left {
        if poll_cancelled(cancellation, work) {
            return None;
        }
        let Some(right) = right.get(slot) else {
            return Some(false);
        };
        let equal =
            states_equal_with_poll(left, right, &mut || poll_cancelled(cancellation, work))?;
        if !equal {
            return Some(false);
        }
    }
    Some(true)
}

#[cfg(test)]
fn snapshot(
    references: &HashSet<SemanticId>,
    slots: &HashSet<SemanticId>,
    answers: &HashMap<SemanticId, ResolutionAnswer>,
    states: &HashMap<SemanticId, TypedFrontierState>,
) -> EvaluationSnapshot {
    let cancellation = CancellationToken::new();
    let mut work = 0;
    snapshot_with_poll(references, slots, answers, states, &cancellation, &mut work)
        .expect("an uncancelled snapshot is total")
}

fn snapshot_with_poll(
    references: &HashSet<SemanticId>,
    slots: &HashSet<SemanticId>,
    answers: &HashMap<SemanticId, ResolutionAnswer>,
    states: &HashMap<SemanticId, TypedFrontierState>,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<EvaluationSnapshot> {
    if poll_cancelled(cancellation, work) {
        return None;
    }
    let references = ordered_semantics_with_poll(references, cancellation, work)?;
    let slots = ordered_semantics_with_poll(slots, cancellation, work)?;
    let answers = ordered_answers_with_poll(answers, cancellation, work)?;
    let states = ordered_states_with_poll(states, cancellation, work)?;
    if poll_cancelled(cancellation, work) {
        return None;
    }
    Some(EvaluationSnapshot {
        references,
        slots,
        answers,
        states,
    })
}

fn ordered_semantics_with_poll(
    semantics: &HashSet<SemanticId>,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<Box<[SemanticId]>> {
    let mut ordered = BTreeSet::new();
    for &semantic in semantics {
        if poll_cancelled(cancellation, work) {
            return None;
        }
        assert!(ordered.insert(semantic));
    }
    let mut output = Vec::with_capacity(ordered.len());
    for semantic in ordered {
        if poll_cancelled(cancellation, work) {
            return None;
        }
        output.push(semantic);
    }
    Some(output.into_boxed_slice())
}

fn ordered_answer_keys_with_poll(
    answers: &HashMap<SemanticId, ResolutionAnswer>,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<BTreeSet<SemanticId>> {
    let mut keys = BTreeSet::new();
    for &semantic in answers.keys() {
        if poll_cancelled(cancellation, work) {
            return None;
        }
        assert!(keys.insert(semantic));
    }
    Some(keys)
}

fn ordered_state_keys_with_poll(
    states: &HashMap<SemanticId, TypedFrontierState>,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<BTreeSet<SemanticId>> {
    let mut keys = BTreeSet::new();
    for &slot in states.keys() {
        if poll_cancelled(cancellation, work) {
            return None;
        }
        assert!(keys.insert(slot));
    }
    Some(keys)
}

fn ordered_answers_with_poll(
    answers: &HashMap<SemanticId, ResolutionAnswer>,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<Box<[(SemanticId, ResolutionAnswer)]>> {
    let keys = ordered_answer_keys_with_poll(answers, cancellation, work)?;
    let mut output = Vec::with_capacity(keys.len());
    for semantic in keys {
        if poll_cancelled(cancellation, work) {
            return None;
        }
        output.push((
            semantic,
            clone_answer_with_poll(&answers[&semantic], cancellation, work)?,
        ));
    }
    Some(output.into_boxed_slice())
}

fn ordered_states_with_poll(
    states: &HashMap<SemanticId, TypedFrontierState>,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<Box<[(SemanticId, TypedFrontierState)]>> {
    let keys = ordered_state_keys_with_poll(states, cancellation, work)?;
    let mut output = Vec::with_capacity(keys.len());
    for slot in keys {
        if poll_cancelled(cancellation, work) {
            return None;
        }
        output.push((
            slot,
            clone_state_with_poll(&states[&slot], cancellation, work)?,
        ));
    }
    Some(output.into_boxed_slice())
}

fn clone_completion_with_poll(
    completion: &ResolutionCompletion,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<ResolutionCompletion> {
    if poll_cancelled(cancellation, work) {
        return None;
    }
    let completion = clone_resolution_completion_with_poll(completion, &mut || {
        poll_cancelled(cancellation, work)
    })?;
    if cancellation.is_cancelled() {
        None
    } else {
        Some(completion)
    }
}

fn clone_answer_with_poll(
    answer: &ResolutionAnswer,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<ResolutionAnswer> {
    let mut targets = Vec::with_capacity(answer.targets().len());
    for &target in answer.targets() {
        if poll_cancelled(cancellation, work) {
            return None;
        }
        targets.push(target);
    }
    let mut witnesses = Vec::with_capacity(answer.witnesses().len());
    for witness in answer.witnesses() {
        if poll_cancelled(cancellation, work) {
            return None;
        }
        let mut steps = Vec::with_capacity(witness.steps().len());
        for &step in witness.steps() {
            if poll_cancelled(cancellation, work) {
                return None;
            }
            steps.push(step);
        }
        witnesses.push(super::model::ResolutionWitness::new(
            witness.reference(),
            witness.target(),
            steps,
            clone_completion_with_poll(witness.completion(), cancellation, work)?,
        ));
    }
    Some(ResolutionAnswer::new(
        targets,
        witnesses,
        clone_completion_with_poll(answer.completion(), cancellation, work)?,
    ))
}

fn clone_state_with_poll(
    state: &TypedFrontierState,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<TypedFrontierState> {
    let mut values = Vec::with_capacity(state.possible_values().len());
    for &value in state.possible_values() {
        if poll_cancelled(cancellation, work) {
            return None;
        }
        values.push(value);
    }
    let completion = clone_completion_with_poll(state.completion(), cancellation, work)?;
    let cloned = TypedFrontierState::from_canonical_parts(
        state.slot(),
        values.into_boxed_slice(),
        completion,
        || poll_cancelled(cancellation, work),
    )?;
    if cancellation.is_cancelled() {
        None
    } else {
        Some(cloned)
    }
}

fn clone_semantic_set_with_poll(
    semantics: &HashSet<SemanticId>,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<HashSet<SemanticId>> {
    let ordered = ordered_semantics_with_poll(semantics, cancellation, work)?;
    let mut cloned = HashSet::default();
    for semantic in ordered.iter().copied() {
        if poll_cancelled(cancellation, work) {
            return None;
        }
        assert!(cloned.insert(semantic));
    }
    Some(cloned)
}

fn clone_completion_map_with_poll(
    completions: &HashMap<SemanticId, ResolutionCompletion>,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<HashMap<SemanticId, ResolutionCompletion>> {
    let mut keys = BTreeSet::new();
    for &semantic in completions.keys() {
        if poll_cancelled(cancellation, work) {
            return None;
        }
        assert!(keys.insert(semantic));
    }
    let mut cloned = HashMap::default();
    for semantic in keys {
        if poll_cancelled(cancellation, work) {
            return None;
        }
        assert!(
            cloned
                .insert(
                    semantic,
                    clone_completion_with_poll(&completions[&semantic], cancellation, work)?,
                )
                .is_none()
        );
    }
    Some(cloned)
}

fn clone_answer_map_with_poll(
    answers: &HashMap<SemanticId, ResolutionAnswer>,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<HashMap<SemanticId, ResolutionAnswer>> {
    let keys = ordered_answer_keys_with_poll(answers, cancellation, work)?;
    let mut cloned = HashMap::default();
    for semantic in keys {
        if poll_cancelled(cancellation, work) {
            return None;
        }
        assert!(
            cloned
                .insert(
                    semantic,
                    clone_answer_with_poll(&answers[&semantic], cancellation, work)?,
                )
                .is_none()
        );
    }
    Some(cloned)
}

fn clone_state_map_with_poll(
    states: &HashMap<SemanticId, TypedFrontierState>,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<HashMap<SemanticId, TypedFrontierState>> {
    let keys = ordered_state_keys_with_poll(states, cancellation, work)?;
    let mut cloned = HashMap::default();
    for slot in keys {
        if poll_cancelled(cancellation, work) {
            return None;
        }
        assert!(
            cloned
                .insert(
                    slot,
                    clone_state_with_poll(&states[&slot], cancellation, work)?,
                )
                .is_none()
        );
    }
    Some(cloned)
}

fn snapshots_equal_with_poll(
    left: &EvaluationSnapshot,
    right: &EvaluationSnapshot,
    mut cancelled: impl FnMut() -> bool,
) -> Option<bool> {
    if cancelled() {
        return None;
    }
    if left.references.len() != right.references.len()
        || left.slots.len() != right.slots.len()
        || left.answers.len() != right.answers.len()
        || left.states.len() != right.states.len()
    {
        return Some(false);
    }
    for (left, right) in left.references.iter().zip(right.references.iter()) {
        if cancelled() {
            return None;
        }
        if left != right {
            return Some(false);
        }
    }
    for (left, right) in left.slots.iter().zip(right.slots.iter()) {
        if cancelled() {
            return None;
        }
        if left != right {
            return Some(false);
        }
    }
    for ((left_semantic, left_answer), (right_semantic, right_answer)) in
        left.answers.iter().zip(right.answers.iter())
    {
        if cancelled() {
            return None;
        }
        if left_semantic != right_semantic {
            return Some(false);
        }
        let equal = answers_equal_with_poll(left_answer, right_answer, &mut cancelled)?;
        if !equal {
            return Some(false);
        }
    }
    for ((left_slot, left_state), (right_slot, right_state)) in
        left.states.iter().zip(right.states.iter())
    {
        if cancelled() {
            return None;
        }
        if left_slot != right_slot {
            return Some(false);
        }
        let equal = states_equal_with_poll(left_state, right_state, &mut cancelled)?;
        if !equal {
            return Some(false);
        }
    }
    Some(true)
}

fn answers_equal_with_poll(
    left: &ResolutionAnswer,
    right: &ResolutionAnswer,
    cancelled: &mut impl FnMut() -> bool,
) -> Option<bool> {
    if left.targets().len() != right.targets().len()
        || left.witnesses().len() != right.witnesses().len()
    {
        return Some(false);
    }
    for (left, right) in left.targets().iter().zip(right.targets().iter()) {
        if cancelled() {
            return None;
        }
        if left != right {
            return Some(false);
        }
    }
    for (left, right) in left.witnesses().iter().zip(right.witnesses().iter()) {
        if cancelled() {
            return None;
        }
        if left.reference() != right.reference()
            || left.target() != right.target()
            || left.steps().len() != right.steps().len()
        {
            return Some(false);
        }
        for (left, right) in left.steps().iter().zip(right.steps().iter()) {
            if cancelled() {
                return None;
            }
            if left != right {
                return Some(false);
            }
        }
        let equal = completions_equal_with_poll(left.completion(), right.completion(), cancelled)?;
        if !equal {
            return Some(false);
        }
    }
    completions_equal_with_poll(left.completion(), right.completion(), cancelled)
}

fn states_equal_with_poll(
    left: &TypedFrontierState,
    right: &TypedFrontierState,
    cancelled: &mut impl FnMut() -> bool,
) -> Option<bool> {
    if left.slot() != right.slot() || left.possible_values().len() != right.possible_values().len()
    {
        return Some(false);
    }
    for (left, right) in left
        .possible_values()
        .iter()
        .zip(right.possible_values().iter())
    {
        if cancelled() {
            return None;
        }
        if left != right {
            return Some(false);
        }
    }
    completions_equal_with_poll(left.completion(), right.completion(), cancelled)
}

fn completions_equal_with_poll<P>(
    left: &ResolutionCompletion,
    right: &ResolutionCompletion,
    cancelled: &mut P,
) -> Option<bool>
where
    P: FnMut() -> bool + ?Sized,
{
    if cancelled() {
        return None;
    }
    match (left, right) {
        (ResolutionCompletion::Complete, ResolutionCompletion::Complete) => Some(true),
        (ResolutionCompletion::Incomplete(left), ResolutionCompletion::Incomplete(right)) => {
            left.equals_with_poll(right, cancelled)
        }
        _ => Some(false),
    }
}

fn completion_without_unsupported_semantic(
    completion: &ResolutionCompletion,
    semantic: SemanticId,
) -> ResolutionCompletion {
    let ResolutionCompletion::Incomplete(reasons) = completion else {
        return ResolutionCompletion::Complete;
    };
    let retained = reasons
        .iter()
        .copied()
        .filter(|reason| *reason != ResolutionIncompleteReason::UnsupportedSemantic(semantic))
        .collect::<Vec<_>>();
    if retained.is_empty() {
        ResolutionCompletion::Complete
    } else {
        ResolutionCompletion::incomplete(retained)
    }
}

fn completion_without_unsupported_semantics_with_poll(
    completion: &ResolutionCompletion,
    semantics: &BTreeSet<SemanticId>,
    cancelled: &mut dyn FnMut() -> bool,
) -> Option<ResolutionCompletion> {
    if cancelled() {
        return None;
    }
    let ResolutionCompletion::Incomplete(reasons) = completion else {
        return Some(ResolutionCompletion::Complete);
    };
    let mut retained = Vec::with_capacity(reasons.len());
    let mut removed = false;
    for &reason in reasons.iter() {
        if cancelled() {
            return None;
        }
        if let ResolutionIncompleteReason::UnsupportedSemantic(semantic) = reason
            && semantics.contains(&semantic)
        {
            removed = true;
        } else {
            retained.push(reason);
        }
    }
    if cancelled() {
        return None;
    }
    Some(if removed && retained.is_empty() {
        ResolutionCompletion::Complete
    } else {
        ResolutionCompletion::Incomplete(retained.into_boxed_slice().into())
    })
}

fn incomplete(reason: SemanticId) -> ResolutionCompletion {
    ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(reason)])
}

fn incomplete_cancelled() -> ResolutionCompletion {
    ResolutionCompletion::incomplete([ResolutionIncompleteReason::Cancelled])
}

fn service_reason(kind: &[u8], fields: &[&[u8]]) -> SemanticId {
    let mut hasher = CanonicalHasher::new(b"bifrost-resolution-fact-service-reason:v1");
    hasher.field("kind", kind);
    for (index, field) in fields.iter().enumerate() {
        hasher.field(&format!("field-{index}"), field);
    }
    SemanticId::from_digest(hasher.finish())
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use brokk_bifrost_core::analyzer::Language;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapFact;
    use brokk_bifrost_core::analyzer::resolution_facts::{
        BindingProjectionFact, DeclarationTypeSlotFact, FileResolutionFacts, IntrinsicTypeKind,
        IntrinsicTypeSeedFact, PositionedIdentifierFact, ResolutionBinderFact,
        ResolutionBinderKind, ResolutionCallFact, ResolutionCallableReceiverOriginFact,
        ResolutionCallableSignatureFact, ResolutionDeclarationVisibilityFact,
        ResolutionIdentifierRole, ResolutionMemberAccess, ResolutionMemberOwnerFact,
        ResolutionNameFact, ResolutionNameId, ResolutionScopeFact, ResolutionScopeId,
        ResolutionScopeKind, ResolutionSiteFact, ResolutionSiteId, ResolutionSiteKind,
        ResolutionTypeSlotFact, ResolutionTypeSlotId, ResolutionTypeSlotRole,
        ResolutionTypeTransferFact, ResolutionTypeTransferKind,
        ResolutionTypeTransferValueTransform, ResolutionVisibilityEligibilityFact,
    };
    use brokk_bifrost_core::analyzer::structural::resolution::HoistingClass;

    use super::super::batch::{
        BatchCandidateCompletionOutcome, BatchCandidateMatch, BatchCandidateOutcome,
        BatchDefinitionNode, BatchEndpointClassification, BatchReferenceSeed,
        ReferenceSeedReadOutcome, ReverseReferenceSeedRequest,
    };
    use super::super::fact_lowering::LoweredResolutionFragment;
    use super::super::fact_lowering::{LoweredSemanticRole, lower_file_resolution_facts};
    use super::super::fact_source::{
        FactPageVisitor, FactReadOutcome, FactResolutionSource, MAX_TYPED_FACT_REQUESTS_PER_BATCH,
        MAX_TYPED_FACT_ROWS_PER_PAGE, TypedFactReadTerminal,
    };
    use super::super::preloaded_fact_source::PreloadedFactSource;
    use super::super::typed_fact_lowering::lower_typed_resolution_facts;
    use super::super::typed_fact_lowering::{LoweredTypedFragment, LoweredTypedFrontier};
    use super::*;
    use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

    struct JavaFixture {
        service: PreloadedFactSource,
        lexical: LoweredResolutionFragment,
        typed: LoweredTypedFragment,
        references: HashMap<u32, SemanticId>,
        definitions: HashMap<u32, SemanticId>,
        int_type: SemanticId,
    }

    impl JavaFixture {
        fn resolve_reference(
            &self,
            reference: SemanticId,
            cancellation: &CancellationToken,
        ) -> StoreResult<FactResolutionAnswer> {
            FactReadSession::new(&self.service, cancellation).resolve_reference(reference)
        }
    }
    fn preloaded_session<'a>(
        service: &'a PreloadedFactSource,
        cancellation: &'a CancellationToken,
    ) -> FactReadSession<'a> {
        FactReadSession::new(service, cancellation)
    }
    fn split_preloaded_session<'a>(
        service: &'a PreloadedFactSource,
        lexical: &'a dyn BatchResolutionFragmentSource,
        cancellation: &'a CancellationToken,
    ) -> FactReadSession<'a> {
        FactReadSession::from_split_sources_for_test(lexical, service, cancellation)
    }
    fn fixture_value_route(
        fixture: &JavaFixture,
        reference: SemanticId,
    ) -> SourceSelectedQualifiedRoute {
        let mut routes = Vec::new();
        let mut callback = |page: &[SourceSelectedQualifiedRoute]| {
            routes.extend_from_slice(page);
            Ok(true)
        };
        let outcome = fixture
            .service
            .visit_qualified_route_pages_for_references(
                TypedFactRequest::new(&[reference]),
                &CancellationToken::new(),
                &mut TypedFactPageVisitor::new(&mut callback),
            )
            .expect("normalized route read succeeds");
        assert_eq!(outcome.terminal(), TypedFactReadTerminal::Exhausted);
        let mut shape = routes
            .iter()
            .map(|route| (route.row().precedence_ordinal(), route.row().namespace()))
            .collect::<Vec<_>>();
        shape.sort_unstable();
        assert_eq!(
            shape,
            [
                (0, ResolutionNamespace::Value),
                (1, ResolutionNamespace::Type)
            ],
            "the fixture retains both exact namespace routes: {routes:?}"
        );
        let reference_node = fixture
            .lexical
            .semantics()
            .iter()
            .find(|site| {
                site.semantic() == reference && site.role() == LoweredSemanticRole::Reference
            })
            .expect("the fixture reference has an exact lexical node")
            .node();
        let expected = fixture
            .typed
            .qualified_routes()
            .iter()
            .find(|route| {
                route.reference() == reference
                    && route.namespace() == ResolutionNamespace::Value
                    && route.precedence_ordinal() == 0
            })
            .expect("the normalized fixture owns a Value route at precedence zero");
        for route in &routes {
            assert_eq!(route.fragment(), fragment(), "selected routes: {routes:?}");
            assert_eq!(
                route.reference_node(),
                reference_node,
                "selected routes: {routes:?}"
            );
            let row = route.row();
            assert_eq!(row.reference(), reference, "selected routes: {routes:?}");
            assert_eq!(
                row.qualifier_slot(),
                expected.qualifier_slot(),
                "selected routes: {routes:?}"
            );
            assert_eq!(
                row.projection_output_slot(),
                expected.projection_output_slot(),
                "selected routes: {routes:?}"
            );
            assert_eq!(
                row.projection_kind(),
                expected.projection_kind(),
                "selected routes: {routes:?}"
            );
            assert_eq!(
                row.coarse_gap_reason(),
                expected.coarse_gap_reason(),
                "selected routes: {routes:?}"
            );
            assert!(
                fixture.typed.qualified_routes().contains(&row),
                "selected routes: {routes:?}"
            );
        }
        // The donor's canonical first route for this fixture is Value at
        // precedence zero. Preserve that selection without relying on page order.
        let selected = routes
            .iter()
            .filter(|route| {
                route.row().namespace() == ResolutionNamespace::Value
                    && route.row().precedence_ordinal() == 0
            })
            .collect::<Vec<_>>();
        assert_eq!(selected.len(), 1, "selected routes: {routes:?}");
        *selected[0]
    }

    fn fragment() -> BindingFragmentId {
        BindingFragmentId::hash_bytes(b"fact-resolution-java-fixture")
    }

    fn transfer_edges_for_session_rows(
        session: &FactReadSession<'_>,
        rows: &[InternedFactRow<SelectedTypedRow<LoweredTypeTransfer>>],
    ) -> Vec<TransferEdge> {
        rows.iter()
            .map(|row| {
                let row = row.get(session);
                TransferEdge {
                    source: row.row().source_slot(),
                    target: row.row().rule().target_slot(),
                    indirection_delta: row.row().rule().indirection_delta(),
                }
            })
            .collect()
    }

    fn synthetic_receiver_witness(
        label: &[u8],
        target: SemanticId,
        node: BindingNodeId,
        outcome: CandidateOutcome,
        completion: ResolutionCompletion,
    ) -> ResolutionWitness {
        ResolutionWitness::new(
            SemanticId::hash_bytes([b"receiver-witness-reference:".as_slice(), label].concat()),
            target,
            [
                WitnessStep::Node(node),
                WitnessStep::Candidate {
                    semantic: target,
                    outcome,
                },
            ],
            completion,
        )
    }

    fn classify_synthetic_implicit_receiver(
        target: SemanticId,
        callable_static_import_boundaries: &[BindingNodeId],
        witnesses: impl IntoIterator<Item = ResolutionWitness>,
        completion: ResolutionCompletion,
    ) -> FactCallableReceiverDisposition {
        let fixture = java_fixture();
        let cancellation = CancellationToken::new();
        let mut session =
            FactReadSession::from_split_sources_with_callable_static_import_boundaries(
                &fixture.service,
                &fixture.service,
                callable_static_import_boundaries,
                &cancellation,
            );
        let mut hierarchy = HierarchyOperationArena::default();
        let mut evaluation = FactEvaluation::new(&mut session, &mut hierarchy, target);
        let binding = ResolutionAnswer::new(
            [target],
            witnesses.into_iter().collect::<Vec<_>>().into_boxed_slice(),
            completion,
        );
        evaluation
            .implicit_receiver_dispositions(&binding)
            .expect("the synthetic receiver evaluation is not cancelled")
            .get(&target)
            .copied()
            .unwrap_or(FactCallableReceiverDisposition::unresolved(
                FactReferenceReceiverGap::UnresolvedReceiver,
            ))
    }

    fn classify_synthetic_explicit_receiver(
        target: SemanticId,
        enclosing_type: Option<SemanticId>,
        values: impl IntoIterator<Item = ResolutionSlotValue>,
        open: bool,
    ) -> FactCallableReceiverDisposition {
        let fixture = java_fixture();
        let cancellation = CancellationToken::new();
        let mut session = preloaded_session(&fixture.service, &cancellation);
        let mut hierarchy = HierarchyOperationArena::default();
        let mut evaluation = FactEvaluation::new(&mut session, &mut hierarchy, target);
        evaluation.root_explicit_receiver_evidence.insert(
            target,
            ExplicitReceiverTargetEvidence {
                values: values.into_iter().collect(),
                category_open: open,
            },
        );
        evaluation
            .explicit_receiver_disposition(target, enclosing_type)
            .expect("the synthetic explicit receiver evaluation is not cancelled")
    }

    fn classify_synthetic_root_receiver(
        target: SemanticId,
        root_is_callable: bool,
        origin: Option<ResolutionCallableReceiverOrigin>,
    ) -> Box<[FactCallableReceiverTargetDisposition]> {
        let fixture = java_fixture();
        let cancellation = CancellationToken::new();
        let mut session = preloaded_session(&fixture.service, &cancellation);
        let mut hierarchy = HierarchyOperationArena::default();
        let mut evaluation = FactEvaluation::new(&mut session, &mut hierarchy, target);
        evaluation.root_is_callable = root_is_callable;
        evaluation.root_site_metadata = Some(FactReferenceSiteMetadata::new(
            ResolutionSiteId::new(0),
            ResolutionNamespace::Callable,
            ResolutionSiteKind::CallableReference,
            0,
            0,
            origin.is_none_or(|origin| origin == ResolutionCallableReceiverOrigin::Implicit),
            None,
            origin,
        ));
        let binding = ResolutionAnswer::new([target], [], ResolutionCompletion::Complete);
        evaluation
            .callable_receiver_dispositions(&binding)
            .expect("the synthetic root receiver evaluation is infallible")
            .expect("the synthetic root receiver evaluation is not cancelled")
    }

    fn read_session_projections_with(
        session: &mut FactReadSession<'_>,
        references: &[SemanticId],
        visit: impl FnMut(
            TypedFactRequest<'_, SemanticId>,
            &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredBindingProjection>>,
        ) -> StoreResult<TypedFactReadOutcome>,
    ) -> StoreResult<SessionFactRead<SelectedTypedRow<LoweredBindingProjection>>> {
        session.read_keyed_rows(
            references,
            |cache| (&cache.projection_rows, &cache.projections_by_reference),
            |cache| {
                (
                    &mut cache.projection_rows,
                    &mut cache.projections_by_reference,
                )
            },
            visit,
            |row, _, _| Some(vec![row.row().reference()]),
            SelectedTypedRow::<LoweredBindingProjection>::natural_identity,
            ObservedFactRelation::Primary,
            |row, _, _| {
                Some(vec![
                    ObservedFactRelation::Primary(row.row().reference()),
                    ObservedFactRelation::Secondary(row.row().output_slot()),
                ])
            },
            observe_no_session_row_evidence,
            clone_selected_copy_session_row,
            copy_session_rows_equal,
        )
    }

    fn read_session_projection_outputs_with(
        session: &mut FactReadSession<'_>,
        outputs: &[SemanticId],
        visit: impl FnMut(
            TypedFactRequest<'_, SemanticId>,
            &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredBindingProjection>>,
        ) -> StoreResult<TypedFactReadOutcome>,
    ) -> StoreResult<SessionFactRead<SelectedTypedRow<LoweredBindingProjection>>> {
        session.read_keyed_rows(
            outputs,
            |cache| (&cache.projection_rows, &cache.projections_by_output),
            |cache| (&mut cache.projection_rows, &mut cache.projections_by_output),
            visit,
            |row, _, _| Some(vec![row.row().output_slot()]),
            SelectedTypedRow::<LoweredBindingProjection>::natural_identity,
            ObservedFactRelation::Secondary,
            |row, _, _| {
                Some(vec![
                    ObservedFactRelation::Primary(row.row().reference()),
                    ObservedFactRelation::Secondary(row.row().output_slot()),
                ])
            },
            observe_no_session_row_evidence,
            clone_selected_copy_session_row,
            copy_session_rows_equal,
        )
    }

    fn read_session_transfers_from_with(
        session: &mut FactReadSession<'_>,
        sources: &[SemanticId],
        visit: impl FnMut(
            TypedFactRequest<'_, SemanticId>,
            &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypeTransfer>>,
        ) -> StoreResult<TypedFactReadOutcome>,
    ) -> StoreResult<SessionFactRead<SelectedTypedRow<LoweredTypeTransfer>>> {
        session.read_keyed_rows(
            sources,
            |cache| (&cache.transfer_rows, &cache.transfers_by_source),
            |cache| (&mut cache.transfer_rows, &mut cache.transfers_by_source),
            visit,
            |row, _, _| Some(vec![row.row().source_slot()]),
            SelectedTypedRow::<LoweredTypeTransfer>::natural_identity,
            ObservedFactRelation::Primary,
            |row, _, _| {
                Some(vec![
                    ObservedFactRelation::Primary(row.row().source_slot()),
                    ObservedFactRelation::Secondary(row.row().rule().target_slot()),
                ])
            },
            observe_transfer_evidence,
            clone_session_transfer,
            transfer_session_rows_equal,
        )
    }

    fn read_session_transfers_to_with(
        session: &mut FactReadSession<'_>,
        targets: &[SemanticId],
        visit: impl FnMut(
            TypedFactRequest<'_, SemanticId>,
            &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypeTransfer>>,
        ) -> StoreResult<TypedFactReadOutcome>,
    ) -> StoreResult<SessionFactRead<SelectedTypedRow<LoweredTypeTransfer>>> {
        session.read_keyed_rows(
            targets,
            |cache| (&cache.transfer_rows, &cache.transfers_by_target),
            |cache| (&mut cache.transfer_rows, &mut cache.transfers_by_target),
            visit,
            |row, _, _| Some(vec![row.row().rule().target_slot()]),
            SelectedTypedRow::<LoweredTypeTransfer>::natural_identity,
            ObservedFactRelation::Secondary,
            |row, _, _| {
                Some(vec![
                    ObservedFactRelation::Primary(row.row().source_slot()),
                    ObservedFactRelation::Secondary(row.row().rule().target_slot()),
                ])
            },
            observe_transfer_evidence,
            clone_session_transfer,
            transfer_session_rows_equal,
        )
    }

    fn read_session_intrinsics_for_identities_with(
        session: &mut FactReadSession<'_>,
        type_identities: &[SemanticId],
        visit: impl FnMut(
            TypedFactRequest<'_, SemanticId>,
            &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredIntrinsicSeed>>,
        ) -> StoreResult<TypedFactReadOutcome>,
    ) -> StoreResult<SessionFactRead<SelectedTypedRow<LoweredIntrinsicSeed>>> {
        session.read_keyed_rows(
            type_identities,
            |cache| (&cache.intrinsic_rows, &cache.intrinsics_by_type_identity),
            |cache| {
                (
                    &mut cache.intrinsic_rows,
                    &mut cache.intrinsics_by_type_identity,
                )
            },
            visit,
            intrinsic_type_identities_with_poll,
            SelectedTypedRow::<LoweredIntrinsicSeed>::natural_identity,
            ObservedFactRelation::Secondary,
            intrinsic_observed_relations_with_poll,
            observe_intrinsic_evidence,
            clone_session_intrinsic,
            intrinsic_session_rows_equal,
        )
    }

    fn selected_transfer(
        owner: BindingFragmentId,
        semantic: SemanticId,
        source: SemanticId,
        target: SemanticId,
    ) -> SelectedTypedRow<LoweredTypeTransfer> {
        selected_transfer_with(
            owner,
            semantic,
            source,
            target,
            0,
            TypeTransferValueTransform::Preserve,
            ResolutionCompletion::Complete,
        )
    }

    type TestSelectedTransferGrouping = SelectedTransferGrouping<
        Rc<SelectedTypedRow<LoweredTypeTransfer>>,
        Rc<SelectedTypeFrontierCompletion>,
    >;

    fn group_test_selected_transfer_sources(
        transfer_rows: Vec<Rc<SelectedTypedRow<LoweredTypeTransfer>>>,
        completion_rows: Vec<Rc<SelectedTypeFrontierCompletion>>,
        cancellation: &CancellationToken,
        work: &mut usize,
    ) -> StoreResult<Option<TestSelectedTransferGrouping>> {
        group_selected_transfer_sources_by(
            transfer_rows,
            completion_rows,
            |transfer| (transfer.row().source_slot(), transfer.fragment()),
            |completion| (completion.frontier(), completion.fragment()),
            cancellation,
            work,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn selected_transfer_with(
        owner: BindingFragmentId,
        semantic: SemanticId,
        source: SemanticId,
        target: SemanticId,
        indirection_delta: i64,
        value_transform: TypeTransferValueTransform,
        completion: ResolutionCompletion,
    ) -> SelectedTypedRow<LoweredTypeTransfer> {
        SelectedTypedRow::new(
            owner,
            LoweredTypeTransfer::new(
                source,
                ResolutionTypeTransferKind::Assignment,
                TypeTransferRule::new(
                    semantic,
                    target,
                    indirection_delta,
                    value_transform,
                    completion,
                ),
            ),
        )
    }

    fn selected_intrinsic(
        owner: BindingFragmentId,
        slot: SemanticId,
        type_identities: &[SemanticId],
        kind: IntrinsicTypeKind,
    ) -> SelectedTypedRow<LoweredIntrinsicSeed> {
        let values = type_identities
            .iter()
            .copied()
            .map(|identity| ResolutionSlotValue::type_object(ResolutionTypeRef::new(identity, 0)))
            .collect::<Vec<_>>();
        SelectedTypedRow::new(
            owner,
            LoweredIntrinsicSeed::new(
                kind,
                TypedFrontierState::new(slot, values, ResolutionCompletion::Complete),
            ),
        )
    }

    #[test]
    fn fact_read_session_caches_only_fully_exhausted_projection_relations() {
        let fixture = java_fixture();
        let projection = fixture.typed.projections()[0];
        let reference = projection.reference();
        let selected = SelectedTypedRow::new(fragment(), projection);
        let cancellation = CancellationToken::new();
        let mut session = preloaded_session(&fixture.service, &cancellation);
        let source_calls = Cell::new(0_usize);

        let first =
            read_session_projections_with(&mut session, &[reference], |request, visitor| {
                source_calls.set(source_calls.get() + 1);
                assert_eq!(request.as_slice(), &[reference]);
                assert!(visitor.visit_page(std::slice::from_ref(&selected))?);
                Ok(TypedFactReadOutcome::exhausted(
                    ResolutionCompletion::Complete,
                ))
            })
            .expect("the injected source read is infallible");
        let first_row = match first {
            SessionFactRead::Exhausted { rows, .. } => {
                assert_eq!(rows.len(), 1);
                rows[0]
            }
            SessionFactRead::Cancelled(_) => panic!("a live exhausted read cannot cancel"),
        };
        let second = read_session_projections_with(&mut session, &[reference], |_, _| {
            panic!("an exhausted immutable relation must be served from the session cache")
        })
        .expect("the cache hit is infallible");
        let second_row = match second {
            SessionFactRead::Exhausted { rows, .. } => {
                assert_eq!(rows.len(), 1);
                rows[0]
            }
            SessionFactRead::Cancelled(_) => panic!("a live cache hit cannot cancel"),
        };
        assert_eq!(first_row, second_row);
        assert_eq!(source_calls.get(), 1);

        let mut failed_session = preloaded_session(&fixture.service, &cancellation);
        assert!(
            read_session_projections_with(&mut failed_session, &[reference], |_, visitor| {
                assert!(visitor.visit_page(std::slice::from_ref(&selected))?);
                Err(StoreError::new("injected typed source failure"))
            },)
            .is_err()
        );
        assert!(
            failed_session
                .cache
                .projections_by_reference
                .by_request
                .is_empty(),
            "a StoreError prefix cannot install positive rows or negative coverage"
        );

        let mut cancelled_session = preloaded_session(&fixture.service, &cancellation);
        let returned_gap = SemanticId::hash_bytes(b"session-returned-cancelled-gap");
        let cancelled =
            read_session_projections_with(&mut cancelled_session, &[reference], |_, _| {
                Ok(TypedFactReadOutcome::cancelled(
                    ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(returned_gap),
                    ]),
                ))
            })
            .expect("source-returned cancellation is semantic control flow");
        let SessionFactRead::Cancelled(evidence) = cancelled else {
            panic!("a source-returned Cancelled terminal cannot prove exhaustion")
        };
        assert_incomplete_with_reason(&evidence, returned_gap);
        assert!(evidence.contains_reason(ResolutionIncompleteReason::Cancelled));
        assert!(
            cancelled_session
                .cache
                .projections_by_reference
                .by_request
                .is_empty(),
            "a Cancelled read cannot cache absence or its row prefix"
        );
    }

    #[test]
    fn fact_read_session_canonicalizes_storage_cursor_order_and_rejects_duplicates() {
        let fixture = java_fixture();
        let cancellation = CancellationToken::new();
        let source = SemanticId::hash_bytes(b"typed-storage-cursor-source");
        let mut canonical = [
            selected_transfer(
                fragment(),
                SemanticId::hash_bytes(b"typed-storage-cursor-rule-a"),
                source,
                SemanticId::hash_bytes(b"typed-storage-cursor-target-a"),
            ),
            selected_transfer(
                fragment(),
                SemanticId::hash_bytes(b"typed-storage-cursor-rule-b"),
                source,
                SemanticId::hash_bytes(b"typed-storage-cursor-target-b"),
            ),
        ];
        canonical.sort_unstable_by_key(SelectedTypedRow::<LoweredTypeTransfer>::natural_identity);
        let storage_rows = [canonical[1].clone(), canonical[0].clone()];
        let mut session = preloaded_session(&fixture.service, &cancellation);

        let read = read_session_transfers_from_with(&mut session, &[source], |_, visitor| {
            assert!(visitor.visit_page(&storage_rows)?);
            Ok(TypedFactReadOutcome::exhausted(
                ResolutionCompletion::Complete,
            ))
        })
        .expect("deterministic storage-cursor order is a valid typed read");
        let SessionFactRead::Exhausted { rows, .. } = read else {
            panic!("a live exhausted typed read cannot cancel")
        };
        assert_eq!(
            rows.iter()
                .map(|row| row.get(&session).natural_identity())
                .collect::<Vec<_>>(),
            canonical
                .iter()
                .map(SelectedTypedRow::<LoweredTypeTransfer>::natural_identity)
                .collect::<Vec<_>>()
        );

        let mut duplicate_session = preloaded_session(&fixture.service, &cancellation);
        let duplicate_rows = [canonical[0].clone(), canonical[0].clone()];
        let error =
            read_session_transfers_from_with(&mut duplicate_session, &[source], |_, visitor| {
                assert!(visitor.visit_page(&duplicate_rows)?);
                Ok(TypedFactReadOutcome::exhausted(
                    ResolutionCompletion::Complete,
                ))
            })
            .err()
            .expect("one typed source invocation must reject duplicate natural identities");
        assert!(error.to_string().contains("repeated one natural identity"));
        let cache = &duplicate_session.cache;
        assert!(cache.transfer_rows.rows.is_empty());
        assert!(cache.transfers_by_source.by_request.is_empty());
    }

    #[test]
    fn fact_read_session_interns_one_intrinsic_for_every_matching_identity() {
        let fixture = java_fixture();
        let mut identities = vec![
            SemanticId::hash_bytes(b"multi-identity-intrinsic-a"),
            SemanticId::hash_bytes(b"multi-identity-intrinsic-b"),
        ];
        identities.sort_unstable();
        identities.dedup();
        assert_eq!(identities.len(), 2);
        let selected = selected_intrinsic(
            fragment(),
            SemanticId::hash_bytes(b"multi-identity-intrinsic-slot"),
            &identities,
            IntrinsicTypeKind::Primitive,
        );
        let cancellation = CancellationToken::new();
        let mut session = preloaded_session(&fixture.service, &cancellation);
        let source_calls = Cell::new(0_usize);

        let first = read_session_intrinsics_for_identities_with(
            &mut session,
            &[identities[1], identities[0]],
            |request, visitor| {
                source_calls.set(source_calls.get() + 1);
                assert_eq!(request.as_slice(), identities.as_slice());
                assert!(visitor.visit_page(std::slice::from_ref(&selected))?);
                Ok(TypedFactReadOutcome::exhausted(
                    ResolutionCompletion::Complete,
                ))
            },
        )
        .expect("the multi-identity intrinsic read is infallible");
        let first_row = match first {
            SessionFactRead::Exhausted { rows, evidence } => {
                assert_eq!(rows.len(), 1);
                assert_eq!(evidence, ResolutionCompletion::Complete);
                rows[0]
            }
            SessionFactRead::Cancelled(_) => panic!("a live exhausted read cannot cancel"),
        };
        {
            let cache = &session.cache;
            let first_relation = &cache.intrinsics_by_type_identity.by_request[&identities[0]];
            let second_relation = &cache.intrinsics_by_type_identity.by_request[&identities[1]];
            assert_eq!(
                first_relation.row_keys.as_slice(),
                second_relation.row_keys.as_slice()
            );
            assert_eq!(first_relation.row_keys.len(), 1);
        }

        let cached =
            read_session_intrinsics_for_identities_with(&mut session, &identities, |_, _| {
                panic!("both exhausted identities must reuse the operation cache")
            })
            .expect("the multi-identity cache hit is infallible");
        let SessionFactRead::Exhausted { rows, evidence } = cached else {
            panic!("a live cache hit cannot cancel")
        };
        assert_eq!(rows.len(), 1);
        assert_eq!(first_row, rows[0]);
        assert_eq!(evidence, ResolutionCompletion::Complete);
        assert_eq!(source_calls.get(), 1);
    }

    #[test]
    fn fact_read_session_deduplicates_one_intrinsic_across_request_chunks() {
        let fixture = java_fixture();
        let mut identities = (0_u32
            ..=u32::try_from(MAX_TYPED_FACT_REQUESTS_PER_BATCH)
                .expect("typed request bound fits u32"))
            .map(|ordinal| SemanticId::hash_bytes(ordinal.to_le_bytes()))
            .collect::<Vec<_>>();
        identities.sort_unstable();
        identities.dedup();
        assert_eq!(identities.len(), MAX_TYPED_FACT_REQUESTS_PER_BATCH + 1);
        let first_identity = identities[0];
        let last_identity = identities[MAX_TYPED_FACT_REQUESTS_PER_BATCH];
        let selected = selected_intrinsic(
            fragment(),
            SemanticId::hash_bytes(b"cross-chunk-intrinsic-slot"),
            &[first_identity, last_identity],
            IntrinsicTypeKind::Primitive,
        );
        let cancellation = CancellationToken::new();
        let mut session = preloaded_session(&fixture.service, &cancellation);
        let source_calls = Cell::new(0_usize);

        let read = read_session_intrinsics_for_identities_with(
            &mut session,
            &identities,
            |request, visitor| {
                source_calls.set(source_calls.get() + 1);
                if request.as_slice().contains(&first_identity)
                    || request.as_slice().contains(&last_identity)
                {
                    assert!(visitor.visit_page(std::slice::from_ref(&selected))?);
                }
                Ok(TypedFactReadOutcome::exhausted(
                    ResolutionCompletion::Complete,
                ))
            },
        )
        .expect("the cross-chunk intrinsic read is infallible");
        let SessionFactRead::Exhausted { rows, evidence } = read else {
            panic!("a live exhausted read cannot cancel")
        };
        assert_eq!(rows.len(), 1);
        assert_eq!(evidence, ResolutionCompletion::Complete);
        assert_eq!(source_calls.get(), 2);
        let cache = &session.cache;
        assert_eq!(
            cache.intrinsics_by_type_identity.by_request.len(),
            identities.len()
        );
        assert_eq!(cache.intrinsic_rows.rows.len(), 1);
        assert_eq!(
            cache.intrinsics_by_type_identity.by_request[&first_identity]
                .row_keys
                .as_slice(),
            cache.intrinsics_by_type_identity.by_request[&last_identity]
                .row_keys
                .as_slice()
        );
    }

    #[test]
    fn fact_read_session_rejects_cross_chunk_intrinsic_omissions_in_both_orders_and_conflict() {
        let fixture = java_fixture();
        let mut identities = (0_u32
            ..=u32::try_from(MAX_TYPED_FACT_REQUESTS_PER_BATCH)
                .expect("typed request bound fits u32"))
            .map(|ordinal| SemanticId::hash_bytes(ordinal.to_le_bytes()))
            .collect::<Vec<_>>();
        identities.sort_unstable();
        identities.dedup();
        assert_eq!(identities.len(), MAX_TYPED_FACT_REQUESTS_PER_BATCH + 1);
        let first_identity = identities[0];
        let last_identity = identities[MAX_TYPED_FACT_REQUESTS_PER_BATCH];
        let selected = selected_intrinsic(
            fragment(),
            SemanticId::hash_bytes(b"hostile-cross-chunk-intrinsic-slot"),
            &[first_identity, last_identity],
            IntrinsicTypeKind::Primitive,
        );
        let conflicting = selected_intrinsic(
            selected.fragment(),
            selected.row().frontier().slot(),
            &[first_identity, last_identity],
            IntrinsicTypeKind::LanguageBuiltin,
        );
        let cancellation = CancellationToken::new();

        let mut omitted_session = preloaded_session(&fixture.service, &cancellation);
        let omitted = read_session_intrinsics_for_identities_with(
            &mut omitted_session,
            &identities,
            |request, visitor| {
                if request.as_slice().contains(&first_identity) {
                    assert!(visitor.visit_page(std::slice::from_ref(&selected))?);
                }
                Ok(TypedFactReadOutcome::exhausted(
                    ResolutionCompletion::Complete,
                ))
            },
        );
        assert!(omitted.is_err());
        {
            let cache = &omitted_session.cache;
            assert!(cache.intrinsic_rows.rows.is_empty());
            assert!(cache.intrinsic_rows.observed_keys_by_relation.is_empty());
            assert!(cache.intrinsic_rows.exhausted_relations.is_empty());
            assert!(cache.intrinsics_by_type_identity.by_request.is_empty());
        }
        let corrected_calls = Cell::new(0_usize);
        let corrected = read_session_intrinsics_for_identities_with(
            &mut omitted_session,
            &identities,
            |request, visitor| {
                corrected_calls.set(corrected_calls.get() + 1);
                if request.as_slice().contains(&first_identity)
                    || request.as_slice().contains(&last_identity)
                {
                    assert!(visitor.visit_page(std::slice::from_ref(&selected))?);
                }
                Ok(TypedFactReadOutcome::exhausted(
                    ResolutionCompletion::Complete,
                ))
            },
        )
        .expect("the corrected same-session read is infallible");
        let SessionFactRead::Exhausted { rows, .. } = corrected else {
            panic!("a corrected live read cannot cancel")
        };
        assert_eq!(rows.len(), 1);
        assert_eq!(corrected_calls.get(), 2);

        let mut later_session = preloaded_session(&fixture.service, &cancellation);
        let omitted_earlier = read_session_intrinsics_for_identities_with(
            &mut later_session,
            &identities,
            |request, visitor| {
                if request.as_slice().contains(&last_identity) {
                    assert!(visitor.visit_page(std::slice::from_ref(&selected))?);
                }
                Ok(TypedFactReadOutcome::exhausted(
                    ResolutionCompletion::Complete,
                ))
            },
        );
        assert!(omitted_earlier.is_err());
        {
            let cache = &later_session.cache;
            assert!(cache.intrinsic_rows.rows.is_empty());
            assert!(cache.intrinsic_rows.observed_keys_by_relation.is_empty());
            assert!(cache.intrinsic_rows.exhausted_relations.is_empty());
            assert!(cache.intrinsics_by_type_identity.by_request.is_empty());
        }
        let corrected_calls = Cell::new(0_usize);
        let corrected = read_session_intrinsics_for_identities_with(
            &mut later_session,
            &identities,
            |request, visitor| {
                corrected_calls.set(corrected_calls.get() + 1);
                if request.as_slice().contains(&first_identity)
                    || request.as_slice().contains(&last_identity)
                {
                    assert!(visitor.visit_page(std::slice::from_ref(&selected))?);
                }
                Ok(TypedFactReadOutcome::exhausted(
                    ResolutionCompletion::Complete,
                ))
            },
        )
        .expect("the corrected inverse-order same-session read is infallible");
        let SessionFactRead::Exhausted { rows, .. } = corrected else {
            panic!("a corrected live read cannot cancel")
        };
        assert_eq!(rows.len(), 1);
        assert_eq!(corrected_calls.get(), 2);

        let mut conflicting_session = preloaded_session(&fixture.service, &cancellation);
        let conflict = read_session_intrinsics_for_identities_with(
            &mut conflicting_session,
            &identities,
            |request, visitor| {
                let row = if request.as_slice().contains(&first_identity) {
                    &selected
                } else {
                    assert!(request.as_slice().contains(&last_identity));
                    &conflicting
                };
                assert!(visitor.visit_page(std::slice::from_ref(row))?);
                Ok(TypedFactReadOutcome::exhausted(
                    ResolutionCompletion::Complete,
                ))
            },
        );
        assert!(conflict.is_err());
        let cache = &conflicting_session.cache;
        assert!(cache.intrinsic_rows.rows.is_empty());
        assert!(cache.intrinsic_rows.observed_keys_by_relation.is_empty());
        assert!(cache.intrinsic_rows.exhausted_relations.is_empty());
        assert!(cache.intrinsics_by_type_identity.by_request.is_empty());
    }

    #[test]
    fn fact_read_session_intrinsic_membership_cancellation_is_inert_and_retries_fresh() {
        let fixture = java_fixture();
        let mut identities = (0_u64..(CANCELLATION_QUANTUM as u64 * 2 + 17))
            .map(|ordinal| SemanticId::hash_bytes(ordinal.to_le_bytes()))
            .collect::<Vec<_>>();
        identities.sort_unstable();
        identities.dedup();
        assert!(identities.len() > CANCELLATION_QUANTUM);
        let requested = identities[0];
        let selected = selected_intrinsic(
            fragment(),
            SemanticId::hash_bytes(b"cancelled-intrinsic-membership-slot"),
            &identities,
            IntrinsicTypeKind::Primitive,
        );

        let mut observed_poison = None;
        for checks in 1..=4096 {
            let cancellation = CancellationToken::cancel_after_checks_for_test(checks);
            let mut session = preloaded_session(&fixture.service, &cancellation);
            let read = read_session_intrinsics_for_identities_with(
                &mut session,
                &[requested],
                |_, visitor| {
                    if visitor.visit_page(std::slice::from_ref(&selected))? {
                        Ok(TypedFactReadOutcome::exhausted(
                            ResolutionCompletion::Complete,
                        ))
                    } else {
                        Ok(TypedFactReadOutcome::stopped(
                            ResolutionCompletion::Complete,
                        ))
                    }
                },
            )
            .expect("cancellation is semantic control flow");
            let cache = &session.cache;
            if matches!(read, SessionFactRead::Cancelled(_))
                && !cache.intrinsic_rows.incomplete_membership_rows.is_empty()
                && !cache
                    .intrinsics_by_type_identity
                    .by_request
                    .contains_key(&requested)
            {
                assert_eq!(cache.intrinsic_rows.rows.len(), 1);
                observed_poison = Some(checks);
                break;
            }
        }
        assert!(
            observed_poison.is_some(),
            "one deterministic token budget must cancel during observed-membership publication"
        );

        let cancellation = CancellationToken::new();
        let mut session = preloaded_session(&fixture.service, &cancellation);
        let retried = read_session_intrinsics_for_identities_with(
            &mut session,
            &[requested],
            |_, visitor| {
                assert!(visitor.visit_page(std::slice::from_ref(&selected))?);
                Ok(TypedFactReadOutcome::exhausted(
                    ResolutionCompletion::Complete,
                ))
            },
        )
        .expect("a fresh session retries the complete intrinsic row");
        let SessionFactRead::Exhausted { rows, evidence } = retried else {
            panic!("a fresh live retry cannot cancel")
        };
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0]
                .get(&session)
                .row()
                .frontier()
                .possible_values()
                .len(),
            identities.len()
        );
        assert_eq!(evidence, ResolutionCompletion::Complete);
        let cache = &session.cache;
        assert!(cache.intrinsic_rows.incomplete_membership_rows.is_empty());
        assert!(
            cache
                .intrinsics_by_type_identity
                .by_request
                .contains_key(&requested)
        );
        assert_eq!(
            cache.intrinsic_rows.observed_keys_by_relation.len(),
            identities.len() + 1
        );
    }

    #[test]
    fn fact_read_session_cancellation_during_install_leaves_no_partial_relation_and_retries() {
        let fixture = java_fixture();
        let source = SemanticId::hash_bytes(b"session-install-cancellation-source");
        let mut selected = (0_u64..(CANCELLATION_QUANTUM as u64 * 2 + 17))
            .map(|ordinal| {
                selected_transfer(
                    fragment(),
                    SemanticId::hash_bytes(ordinal.to_le_bytes()),
                    source,
                    SemanticId::hash_bytes((ordinal + 10_000).to_le_bytes()),
                )
            })
            .collect::<Vec<_>>();
        selected.sort_unstable_by_key(SelectedTypedRow::<LoweredTypeTransfer>::natural_identity);
        assert!(selected.len() > CANCELLATION_QUANTUM);

        let mut observed_install_cancellation = None;
        for checks in 1..=4096 {
            let cancellation = CancellationToken::cancel_after_checks_for_test(checks);
            let mut session = preloaded_session(&fixture.service, &cancellation);
            let read =
                read_session_transfers_from_with(&mut session, &[source], |request, visitor| {
                    assert_eq!(request.as_slice(), &[source]);
                    for page in selected.chunks(MAX_TYPED_FACT_ROWS_PER_PAGE) {
                        if !visitor.visit_page(page)? {
                            return Ok(TypedFactReadOutcome::stopped(
                                ResolutionCompletion::Complete,
                            ));
                        }
                    }
                    Ok(TypedFactReadOutcome::exhausted(
                        ResolutionCompletion::Complete,
                    ))
                })
                .expect("cancellation is semantic control flow");
            let cache = &session.cache;
            let orphaned_rows = cache.transfer_rows.rows.len();
            let relation_installed = cache.transfers_by_source.by_request.contains_key(&source);
            if matches!(read, SessionFactRead::Cancelled(_))
                && !relation_installed
                && orphaned_rows > 0
                && orphaned_rows < selected.len()
            {
                assert!(
                    orphaned_rows <= CANCELLATION_QUANTUM,
                    "one cancellation quantum bounds request-local orphan installation"
                );
                observed_install_cancellation = Some((checks, orphaned_rows));
                break;
            }
        }
        let Some((_checks, _orphaned_rows)) = observed_install_cancellation else {
            panic!("one deterministic token budget must cancel during request-local installation")
        };

        let cancellation = CancellationToken::new();
        let mut session = preloaded_session(&fixture.service, &cancellation);
        let retried =
            read_session_transfers_from_with(&mut session, &[source], |request, visitor| {
                assert_eq!(request.as_slice(), &[source]);
                for page in selected.chunks(MAX_TYPED_FACT_ROWS_PER_PAGE) {
                    assert!(visitor.visit_page(page)?);
                }
                Ok(TypedFactReadOutcome::exhausted(
                    ResolutionCompletion::Complete,
                ))
            })
            .expect("a fresh live retry is infallible");
        let SessionFactRead::Exhausted { rows, evidence } = retried else {
            panic!("a fresh live retry must exhaust the full relation")
        };
        assert_eq!(rows.len(), selected.len());
        assert_eq!(evidence, ResolutionCompletion::Complete);
        let cache = &session.cache;
        assert_eq!(cache.transfer_rows.rows.len(), selected.len());
        assert_eq!(
            cache.transfers_by_source.by_request[&source].row_keys.len(),
            selected.len()
        );
    }

    #[test]
    fn fact_read_session_rejects_cross_direction_omissions_without_caching_absence() {
        let fixture = java_fixture();
        let source = SemanticId::hash_bytes(b"cross-direction-transfer-source");
        let target = SemanticId::hash_bytes(b"cross-direction-transfer-target");
        let transfer = selected_transfer(
            fragment(),
            SemanticId::hash_bytes(b"cross-direction-transfer"),
            source,
            target,
        );

        let cancellation = CancellationToken::new();
        let mut session = preloaded_session(&fixture.service, &cancellation);
        let first = read_session_transfers_from_with(&mut session, &[source], |_, visitor| {
            assert!(visitor.visit_page(std::slice::from_ref(&transfer))?);
            Ok(TypedFactReadOutcome::exhausted(
                ResolutionCompletion::Complete,
            ))
        })
        .expect("the injected source read is infallible");
        assert!(matches!(first, SessionFactRead::Exhausted { .. }));
        let omitted_target = read_session_transfers_to_with(&mut session, &[target], |_, _| {
            Ok(TypedFactReadOutcome::exhausted(
                ResolutionCompletion::Complete,
            ))
        });
        assert!(omitted_target.is_err());
        assert!(
            !session
                .cache
                .transfers_by_target
                .by_request
                .contains_key(&target)
        );

        let mut inverse_session = preloaded_session(&fixture.service, &cancellation);
        let first =
            read_session_transfers_to_with(&mut inverse_session, &[target], |_, visitor| {
                assert!(visitor.visit_page(std::slice::from_ref(&transfer))?);
                Ok(TypedFactReadOutcome::exhausted(
                    ResolutionCompletion::Complete,
                ))
            })
            .expect("the inverse injected source read is infallible");
        assert!(matches!(first, SessionFactRead::Exhausted { .. }));
        let omitted_source =
            read_session_transfers_from_with(&mut inverse_session, &[source], |_, _| {
                Ok(TypedFactReadOutcome::exhausted(
                    ResolutionCompletion::Complete,
                ))
            });
        assert!(omitted_source.is_err());
        assert!(
            !inverse_session
                .cache
                .transfers_by_source
                .by_request
                .contains_key(&source)
        );

        let mut projection_session = preloaded_session(&fixture.service, &cancellation);
        let reference = SemanticId::hash_bytes(b"cross-direction-projection-reference");
        let output = SemanticId::hash_bytes(b"cross-direction-projection-output");
        let projection = SelectedTypedRow::new(
            fragment(),
            LoweredBindingProjection::new(
                reference,
                output,
                BindingProjectionKind::TargetTypeIdentity,
            ),
        );
        let first =
            read_session_projections_with(&mut projection_session, &[reference], |_, visitor| {
                assert!(visitor.visit_page(std::slice::from_ref(&projection))?);
                Ok(TypedFactReadOutcome::exhausted(
                    ResolutionCompletion::Complete,
                ))
            })
            .expect("the projection source read is infallible");
        assert!(matches!(first, SessionFactRead::Exhausted { .. }));
        let omitted_output =
            read_session_projection_outputs_with(&mut projection_session, &[output], |_, _| {
                Ok(TypedFactReadOutcome::exhausted(
                    ResolutionCompletion::Complete,
                ))
            });
        assert!(omitted_output.is_err());
        assert!(
            !projection_session
                .cache
                .projections_by_output
                .by_request
                .contains_key(&output)
        );
    }

    #[test]
    fn fact_read_session_cached_empty_evidence_stops_at_the_cancellation_edge() {
        let fixture = java_fixture();
        let mut requests = (0_u64..(CANCELLATION_QUANTUM as u64 * 2 + 7))
            .map(|ordinal| SemanticId::hash_bytes(ordinal.to_le_bytes()))
            .collect::<Vec<_>>();
        requests.sort_unstable();
        requests.dedup();
        assert!(requests.len() > CANCELLATION_QUANTUM);

        let mut observed_cached_cancellation = false;
        for checks in 1..=32 {
            let cancellation = CancellationToken::cancel_after_checks_for_test(checks);
            let mut session = preloaded_session(&fixture.service, &cancellation);
            {
                let cache = &mut session.cache;
                for &request in &requests {
                    let reason = ResolutionIncompleteReason::UnsupportedSemantic(request);
                    let evidence = cache.projections_by_reference.evidence.len();
                    cache
                        .projections_by_reference
                        .evidence
                        .push(ResolutionCompletion::incomplete([reason]));
                    cache.projections_by_reference.by_request.insert(
                        request,
                        CachedFactRelation {
                            row_keys: Vec::new(),
                            evidence,
                        },
                    );
                    cache
                        .projection_rows
                        .exhausted_relations
                        .insert(ObservedFactRelation::Primary(request));
                }
            }
            let read = read_session_projections_with(&mut session, &requests, |_, _| {
                panic!("cached empty relations cannot consult the source")
            })
            .expect("cache cancellation is semantic control flow");
            let SessionFactRead::Cancelled(evidence) = read else {
                continue;
            };
            let observed_reason_count = match evidence {
                ResolutionCompletion::Complete => 0,
                ResolutionCompletion::Incomplete(reasons) => reasons
                    .iter()
                    .filter(|reason| {
                        matches!(reason, ResolutionIncompleteReason::UnsupportedSemantic(_))
                    })
                    .count(),
            };
            if observed_reason_count > 0 {
                assert_eq!(
                    observed_reason_count, 1,
                    "a cache-hit cancellation gate runs after the current relation evidence box"
                );
                observed_cached_cancellation = true;
                break;
            }
        }
        assert!(
            observed_cached_cancellation,
            "one deterministic token budget must cancel during cached empty evidence replay"
        );
    }

    #[test]
    fn fact_read_session_rejects_a_later_chunk_row_without_installing_coverage() {
        let fixture = java_fixture();
        let cancellation = CancellationToken::new();
        let mut session = preloaded_session(&fixture.service, &cancellation);
        let mut references = (0_u32
            ..=u32::try_from(MAX_TYPED_FACT_REQUESTS_PER_BATCH)
                .expect("typed request bound fits u32"))
            .map(|ordinal| SemanticId::hash_bytes(ordinal.to_le_bytes()))
            .collect::<Vec<_>>();
        references.sort_unstable();
        references.dedup();
        assert_eq!(references.len(), MAX_TYPED_FACT_REQUESTS_PER_BATCH + 1);
        let later_reference = references[MAX_TYPED_FACT_REQUESTS_PER_BATCH];
        let selected = SelectedTypedRow::new(
            fragment(),
            LoweredBindingProjection::new(
                later_reference,
                SemanticId::hash_bytes(b"later-chunk-output"),
                BindingProjectionKind::TargetTypeIdentity,
            ),
        );

        let result =
            read_session_projections_with(&mut session, &references, |request, visitor| {
                assert_eq!(request.len(), MAX_TYPED_FACT_REQUESTS_PER_BATCH);
                assert!(!request.as_slice().contains(&later_reference));
                let _ = visitor.visit_page(std::slice::from_ref(&selected))?;
                Ok(TypedFactReadOutcome::exhausted(
                    ResolutionCompletion::Complete,
                ))
            });
        assert!(result.is_err());
        let cache = &session.cache;
        assert!(cache.projection_rows.rows.is_empty());
        assert!(cache.projections_by_reference.by_request.is_empty());
    }

    #[test]
    fn generic_fact_read_session_derives_demand_local_transfer_classification() {
        let fixture = java_fixture();
        let cancellation = CancellationToken::new();
        let source: &dyn FactResolutionSource = &fixture.service;
        let mut session = FactReadSession::new(source, &cancellation);

        let actual = session
            .resolve_reference(fixture.references[&8])
            .expect("a generic selected source derives its SCC classification");
        let expected = fixture
            .resolve_reference(fixture.references[&8], &CancellationToken::new())
            .expect("preload point reads are infallible");
        assert_eq!(actual, expected);
    }

    #[test]
    fn selected_transfer_grouping_rejects_ambiguous_or_mismatched_fragment_ownership() {
        let first_fragment = BindingFragmentId::hash_bytes(b"selected-transfer-owner-first");
        let second_fragment = BindingFragmentId::hash_bytes(b"selected-transfer-owner-second");
        let source = SemanticId::hash_bytes(b"selected-transfer-owner-source");
        let target = SemanticId::hash_bytes(b"selected-transfer-owner-target");
        let first_transfer = Rc::new(selected_transfer(
            first_fragment,
            SemanticId::hash_bytes(b"selected-transfer-owner-rule-first"),
            source,
            target,
        ));
        let second_transfer = Rc::new(selected_transfer(
            second_fragment,
            SemanticId::hash_bytes(b"selected-transfer-owner-rule-second"),
            source,
            target,
        ));
        let first_completion = Rc::new(SelectedTypeFrontierCompletion::new(
            first_fragment,
            source,
            ResolutionCompletion::Complete,
        ));
        let second_completion = Rc::new(SelectedTypeFrontierCompletion::new(
            second_fragment,
            source,
            ResolutionCompletion::Complete,
        ));
        let cancellation = CancellationToken::new();

        let mut work = 0_usize;
        let mismatch = group_test_selected_transfer_sources(
            vec![Rc::clone(&first_transfer)],
            vec![Rc::clone(&second_completion)],
            &cancellation,
            &mut work,
        );
        assert!(mismatch.is_err());

        let mut work = 0_usize;
        let duplicate_transfer_owner = group_test_selected_transfer_sources(
            vec![Rc::clone(&first_transfer), second_transfer],
            vec![Rc::clone(&first_completion)],
            &cancellation,
            &mut work,
        );
        assert!(duplicate_transfer_owner.is_err());

        let mut work = 0_usize;
        let duplicate_completion_owner = group_test_selected_transfer_sources(
            vec![first_transfer],
            vec![first_completion, second_completion],
            &cancellation,
            &mut work,
        );
        assert!(duplicate_completion_owner.is_err());
    }

    #[test]
    fn selected_transfer_grouping_applies_independent_cross_fragment_sources() {
        let first_fragment = BindingFragmentId::hash_bytes(b"selected-transfer-valid-first");
        let second_fragment = BindingFragmentId::hash_bytes(b"selected-transfer-valid-second");
        let first_source = SemanticId::hash_bytes(b"selected-transfer-valid-source-first");
        let second_source = SemanticId::hash_bytes(b"selected-transfer-valid-source-second");
        let first_target = SemanticId::hash_bytes(b"selected-transfer-valid-target-first");
        let second_target = SemanticId::hash_bytes(b"selected-transfer-valid-target-second");
        let transfer_rows = vec![
            Rc::new(selected_transfer(
                first_fragment,
                SemanticId::hash_bytes(b"selected-transfer-valid-rule-first"),
                first_source,
                first_target,
            )),
            Rc::new(selected_transfer(
                second_fragment,
                SemanticId::hash_bytes(b"selected-transfer-valid-rule-second"),
                second_source,
                second_target,
            )),
        ];
        let completion_rows = vec![
            Rc::new(SelectedTypeFrontierCompletion::new(
                first_fragment,
                first_source,
                ResolutionCompletion::Complete,
            )),
            Rc::new(SelectedTypeFrontierCompletion::new(
                second_fragment,
                second_source,
                ResolutionCompletion::Complete,
            )),
        ];
        let cancellation = CancellationToken::new();
        let mut work = 0_usize;
        let Some((groups, completions)) = group_test_selected_transfer_sources(
            transfer_rows,
            completion_rows,
            &cancellation,
            &mut work,
        )
        .expect("independent selected fragments are valid") else {
            panic!("a live grouping cannot cancel")
        };

        let value_identity = SemanticId::hash_bytes(b"selected-transfer-valid-value");
        let mut applied_targets = BTreeSet::new();
        for source in [first_source, second_source] {
            let (_, rows) = &groups[&source];
            let state = TypedFrontierState::new(
                source,
                [ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                    value_identity,
                    0,
                ))],
                ResolutionCompletion::Complete,
            );
            let rules = rows
                .iter()
                .map(|row| row.row().rule().clone())
                .collect::<Vec<_>>();
            let (alternatives, completion) = apply_type_transfer_rules(
                &state,
                rules,
                completions[&source].completion().clone(),
                &cancellation,
            )
            .expect("validated selected transfer rules apply");
            assert_eq!(completion, ResolutionCompletion::Complete);
            assert_eq!(alternatives.len(), 1);
            applied_targets.insert(alternatives[0].slot());
        }
        assert_eq!(
            applied_targets,
            [first_target, second_target].into_iter().collect()
        );
    }

    fn name(id: u32, spelling: &str) -> ResolutionNameFact {
        ResolutionNameFact {
            id: ResolutionNameId::new(id),
            spelling: spelling.into(),
        }
    }

    fn scope(
        id: u32,
        parent: Option<u32>,
        owner: Option<u32>,
        kind: ResolutionScopeKind,
        start_byte: usize,
        end_byte: usize,
    ) -> ResolutionScopeFact {
        ResolutionScopeFact {
            id: ResolutionScopeId::new(id),
            parent: parent.map(ResolutionScopeId::new),
            owner: owner.map(ResolutionSiteId::new),
            kind,
            start_byte,
            end_byte,
        }
    }

    fn site(id: u32, scope: u32, kind: ResolutionSiteKind, position: usize) -> ResolutionSiteFact {
        ResolutionSiteFact {
            id: ResolutionSiteId::new(id),
            scope: ResolutionScopeId::new(scope),
            kind,
            start_byte: position,
            end_byte: position + 1,
        }
    }

    fn identifier(
        site: u32,
        name: u32,
        role: ResolutionIdentifierRole,
        namespace: ResolutionNamespace,
        qualifier: Option<u32>,
    ) -> PositionedIdentifierFact {
        PositionedIdentifierFact {
            site: ResolutionSiteId::new(site),
            name: ResolutionNameId::new(name),
            role,
            namespace,
            qualifier: qualifier.map(ResolutionTypeSlotId::new),
        }
    }

    fn binder(
        declaration: u32,
        scope: u32,
        kind: ResolutionBinderKind,
        hoisting: HoistingClass,
        activation_start: usize,
        activation_end: usize,
    ) -> ResolutionBinderFact {
        ResolutionBinderFact {
            declaration: ResolutionSiteId::new(declaration),
            scope: ResolutionScopeId::new(scope),
            kind,
            hoisting,
            activation_start,
            activation_end,
        }
    }

    fn slot(id: u32, site: u32, role: ResolutionTypeSlotRole) -> ResolutionTypeSlotFact {
        ResolutionTypeSlotFact {
            id: ResolutionTypeSlotId::new(id),
            site: ResolutionSiteId::new(site),
            role,
        }
    }

    fn transfer(
        input: u32,
        output: u32,
        kind: ResolutionTypeTransferKind,
        value_transform: ResolutionTypeTransferValueTransform,
    ) -> ResolutionTypeTransferFact {
        ResolutionTypeTransferFact {
            input: ResolutionTypeSlotId::new(input),
            output: ResolutionTypeSlotId::new(output),
            kind,
            indirection_delta: 0,
            value_transform,
        }
    }

    /// Normalized Java-shaped facts for `A a; a.f; a.b().c; new A()` where
    /// `b` returns `B`.
    fn java_chain_facts() -> FileResolutionFacts {
        FileResolutionFacts {
            names: vec![
                name(0, "A"),
                name(1, "B"),
                name(2, "a"),
                name(3, "b"),
                name(4, "c"),
                name(5, "f"),
                name(6, "int"),
            ],
            scopes: vec![
                scope(
                    0,
                    None,
                    None,
                    ResolutionScopeKind::CompilationUnit,
                    0,
                    1_000,
                ),
                scope(1, Some(0), Some(0), ResolutionScopeKind::TypeBody, 10, 190),
                scope(2, Some(0), Some(1), ResolutionScopeKind::TypeBody, 210, 390),
            ],
            sites: vec![
                site(0, 0, ResolutionSiteKind::TypeDeclaration, 1),
                site(1, 0, ResolutionSiteKind::TypeDeclaration, 201),
                site(2, 0, ResolutionSiteKind::ValueDeclaration, 600),
                site(3, 1, ResolutionSiteKind::CallableDeclaration, 20),
                site(4, 1, ResolutionSiteKind::ValueDeclaration, 30),
                site(5, 2, ResolutionSiteKind::ValueDeclaration, 220),
                site(6, 1, ResolutionSiteKind::ConstructorDeclaration, 40),
                site(7, 0, ResolutionSiteKind::TypeReference, 590),
                site(8, 0, ResolutionSiteKind::ValueReference, 610),
                site(9, 0, ResolutionSiteKind::MemberReference, 611),
                site(10, 0, ResolutionSiteKind::ValueReference, 620),
                site(11, 0, ResolutionSiteKind::MemberReference, 621),
                site(12, 0, ResolutionSiteKind::MemberReference, 622),
                site(13, 1, ResolutionSiteKind::TypeReference, 21),
                site(14, 1, ResolutionSiteKind::TypeReference, 31),
                site(15, 2, ResolutionSiteKind::TypeReference, 221),
                site(16, 0, ResolutionSiteKind::Call, 619),
                site(17, 0, ResolutionSiteKind::TypeReference, 630),
                site(18, 0, ResolutionSiteKind::ConstructorReference, 631),
                site(19, 0, ResolutionSiteKind::Call, 629),
            ],
            identifiers: vec![
                identifier(
                    0,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Type,
                    None,
                ),
                identifier(
                    1,
                    1,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Type,
                    None,
                ),
                identifier(
                    2,
                    2,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                    None,
                ),
                identifier(
                    3,
                    3,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Callable,
                    None,
                ),
                identifier(
                    4,
                    5,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                    None,
                ),
                identifier(
                    5,
                    4,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                    None,
                ),
                identifier(
                    6,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Constructor,
                    None,
                ),
                identifier(
                    7,
                    0,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Type,
                    None,
                ),
                identifier(
                    8,
                    2,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::TypeOrValue,
                    None,
                ),
                identifier(
                    9,
                    5,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::TypeOrValue,
                    Some(3),
                ),
                identifier(
                    10,
                    2,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::TypeOrValue,
                    None,
                ),
                identifier(
                    11,
                    3,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Callable,
                    Some(8),
                ),
                identifier(
                    12,
                    4,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::TypeOrValue,
                    Some(12),
                ),
                identifier(
                    13,
                    1,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Type,
                    None,
                ),
                identifier(
                    17,
                    0,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Type,
                    None,
                ),
                identifier(
                    18,
                    0,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Constructor,
                    Some(16),
                ),
            ],
            binders: vec![
                binder(
                    0,
                    0,
                    ResolutionBinderKind::Type,
                    HoistingClass::ScopeWide,
                    0,
                    1_000,
                ),
                binder(
                    1,
                    0,
                    ResolutionBinderKind::Type,
                    HoistingClass::ScopeWide,
                    0,
                    1_000,
                ),
                binder(
                    2,
                    0,
                    ResolutionBinderKind::Local,
                    HoistingClass::SourceOrder,
                    601,
                    1_000,
                ),
                binder(
                    3,
                    1,
                    ResolutionBinderKind::Callable,
                    HoistingClass::ScopeWide,
                    10,
                    190,
                ),
                binder(
                    4,
                    1,
                    ResolutionBinderKind::Field,
                    HoistingClass::ScopeWide,
                    10,
                    190,
                ),
                binder(
                    5,
                    2,
                    ResolutionBinderKind::Field,
                    HoistingClass::ScopeWide,
                    210,
                    390,
                ),
                binder(
                    6,
                    1,
                    ResolutionBinderKind::Constructor,
                    HoistingClass::ScopeWide,
                    10,
                    190,
                ),
            ],
            type_slots: vec![
                slot(0, 7, ResolutionTypeSlotRole::TargetTypeIdentity),
                slot(1, 2, ResolutionTypeSlotRole::DeclaredValue),
                slot(2, 8, ResolutionTypeSlotRole::ExpressionValue),
                slot(3, 9, ResolutionTypeSlotRole::Receiver),
                slot(4, 9, ResolutionTypeSlotRole::ExpressionValue),
                slot(5, 14, ResolutionTypeSlotRole::TargetTypeIdentity),
                slot(6, 4, ResolutionTypeSlotRole::DeclaredValue),
                slot(7, 10, ResolutionTypeSlotRole::ExpressionValue),
                slot(8, 16, ResolutionTypeSlotRole::Receiver),
                slot(9, 16, ResolutionTypeSlotRole::CallResult),
                slot(10, 13, ResolutionTypeSlotRole::TargetTypeIdentity),
                slot(11, 3, ResolutionTypeSlotRole::DeclaredValue),
                slot(12, 12, ResolutionTypeSlotRole::Receiver),
                slot(13, 12, ResolutionTypeSlotRole::ExpressionValue),
                slot(14, 15, ResolutionTypeSlotRole::TargetTypeIdentity),
                slot(15, 5, ResolutionTypeSlotRole::DeclaredValue),
                slot(16, 17, ResolutionTypeSlotRole::TargetTypeIdentity),
                slot(17, 19, ResolutionTypeSlotRole::CallResult),
            ],
            declaration_type_slots: vec![
                DeclarationTypeSlotFact {
                    declaration: ResolutionSiteId::new(2),
                    slot: ResolutionTypeSlotId::new(1),
                    role: DeclarationTypeRole::Value,
                },
                DeclarationTypeSlotFact {
                    declaration: ResolutionSiteId::new(4),
                    slot: ResolutionTypeSlotId::new(6),
                    role: DeclarationTypeRole::Value,
                },
                DeclarationTypeSlotFact {
                    declaration: ResolutionSiteId::new(3),
                    slot: ResolutionTypeSlotId::new(11),
                    role: DeclarationTypeRole::Return,
                },
                DeclarationTypeSlotFact {
                    declaration: ResolutionSiteId::new(5),
                    slot: ResolutionTypeSlotId::new(15),
                    role: DeclarationTypeRole::Value,
                },
            ],
            binding_projections: vec![
                BindingProjectionFact {
                    reference: ResolutionSiteId::new(7),
                    output: ResolutionTypeSlotId::new(0),
                    kind: BindingProjectionKind::TargetTypeIdentity,
                },
                BindingProjectionFact {
                    reference: ResolutionSiteId::new(8),
                    output: ResolutionTypeSlotId::new(2),
                    kind: BindingProjectionKind::TargetTypeOrDeclaredValueType,
                },
                BindingProjectionFact {
                    reference: ResolutionSiteId::new(9),
                    output: ResolutionTypeSlotId::new(4),
                    kind: BindingProjectionKind::TargetTypeOrDeclaredValueType,
                },
                BindingProjectionFact {
                    reference: ResolutionSiteId::new(10),
                    output: ResolutionTypeSlotId::new(7),
                    kind: BindingProjectionKind::TargetTypeOrDeclaredValueType,
                },
                BindingProjectionFact {
                    reference: ResolutionSiteId::new(11),
                    output: ResolutionTypeSlotId::new(9),
                    kind: BindingProjectionKind::TargetCallableResultType,
                },
                BindingProjectionFact {
                    reference: ResolutionSiteId::new(12),
                    output: ResolutionTypeSlotId::new(13),
                    kind: BindingProjectionKind::TargetTypeOrDeclaredValueType,
                },
                BindingProjectionFact {
                    reference: ResolutionSiteId::new(13),
                    output: ResolutionTypeSlotId::new(10),
                    kind: BindingProjectionKind::TargetTypeIdentity,
                },
                BindingProjectionFact {
                    reference: ResolutionSiteId::new(17),
                    output: ResolutionTypeSlotId::new(16),
                    kind: BindingProjectionKind::TargetTypeIdentity,
                },
                BindingProjectionFact {
                    reference: ResolutionSiteId::new(18),
                    output: ResolutionTypeSlotId::new(17),
                    kind: BindingProjectionKind::TargetConstructorOwnerType,
                },
            ],
            type_transfers: vec![
                transfer(
                    0,
                    1,
                    ResolutionTypeTransferKind::DeclaredType,
                    ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                ),
                transfer(
                    2,
                    3,
                    ResolutionTypeTransferKind::Receiver,
                    ResolutionTypeTransferValueTransform::Preserve,
                ),
                transfer(
                    5,
                    6,
                    ResolutionTypeTransferKind::DeclaredType,
                    ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                ),
                transfer(
                    7,
                    8,
                    ResolutionTypeTransferKind::Receiver,
                    ResolutionTypeTransferValueTransform::Preserve,
                ),
                transfer(
                    10,
                    11,
                    ResolutionTypeTransferKind::DeclaredType,
                    ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                ),
                transfer(
                    9,
                    12,
                    ResolutionTypeTransferKind::Receiver,
                    ResolutionTypeTransferValueTransform::Preserve,
                ),
                transfer(
                    14,
                    15,
                    ResolutionTypeTransferKind::DeclaredType,
                    ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                ),
            ],
            intrinsic_type_seeds: vec![
                IntrinsicTypeSeedFact {
                    output: ResolutionTypeSlotId::new(5),
                    name: ResolutionNameId::new(6),
                    kind: IntrinsicTypeKind::Primitive,
                    indirection: 0,
                },
                IntrinsicTypeSeedFact {
                    output: ResolutionTypeSlotId::new(14),
                    name: ResolutionNameId::new(6),
                    kind: IntrinsicTypeKind::Primitive,
                    indirection: 0,
                },
            ],
            calls: vec![
                ResolutionCallFact {
                    call: ResolutionSiteId::new(16),
                    callee: ResolutionSiteId::new(11),
                    receiver: Some(ResolutionTypeSlotId::new(8)),
                    result: ResolutionTypeSlotId::new(9),
                    explicit_type_argument_count: 0,
                },
                ResolutionCallFact {
                    call: ResolutionSiteId::new(19),
                    callee: ResolutionSiteId::new(18),
                    receiver: None,
                    result: ResolutionTypeSlotId::new(17),
                    explicit_type_argument_count: 0,
                },
            ],
            callable_receiver_origins: vec![ResolutionCallableReceiverOriginFact {
                reference: ResolutionSiteId::new(11),
                origin: ResolutionCallableReceiverOrigin::ExplicitExpression,
            }],
            callable_signatures: vec![
                ResolutionCallableSignatureFact {
                    callable: ResolutionSiteId::new(3),
                    type_parameter_count: 0,
                },
                ResolutionCallableSignatureFact {
                    callable: ResolutionSiteId::new(6),
                    type_parameter_count: 0,
                },
            ],
            member_owners: vec![
                ResolutionMemberOwnerFact {
                    member: ResolutionSiteId::new(3),
                    owner: ResolutionSiteId::new(0),
                    kind: ResolutionMemberKind::Method,
                    access: ResolutionMemberAccess::Instance,
                    qualifier_compatibility: ResolutionMemberQualifierCompatibility::RuntimeOnly,
                },
                ResolutionMemberOwnerFact {
                    member: ResolutionSiteId::new(4),
                    owner: ResolutionSiteId::new(0),
                    kind: ResolutionMemberKind::Field,
                    access: ResolutionMemberAccess::Instance,
                    qualifier_compatibility: ResolutionMemberQualifierCompatibility::RuntimeOnly,
                },
                ResolutionMemberOwnerFact {
                    member: ResolutionSiteId::new(5),
                    owner: ResolutionSiteId::new(1),
                    kind: ResolutionMemberKind::Field,
                    access: ResolutionMemberAccess::Instance,
                    qualifier_compatibility: ResolutionMemberQualifierCompatibility::RuntimeOnly,
                },
                ResolutionMemberOwnerFact {
                    member: ResolutionSiteId::new(6),
                    owner: ResolutionSiteId::new(0),
                    kind: ResolutionMemberKind::Constructor,
                    access: ResolutionMemberAccess::Type,
                    qualifier_compatibility: ResolutionMemberQualifierCompatibility::TypeOnly,
                },
            ],
            declaration_visibilities: [0, 1, 3, 4, 5, 6]
                .map(|declaration| ResolutionDeclarationVisibilityFact {
                    declaration: ResolutionSiteId::new(declaration),
                    visibility: DeclaredVisibility::Public,
                })
                .to_vec(),
            visibility_eligibilities: [0, 1, 3, 4, 5, 6]
                .map(|declaration| ResolutionVisibilityEligibilityFact {
                    declaration: ResolutionSiteId::new(declaration),
                })
                .to_vec(),
            ..FileResolutionFacts::default()
        }
    }

    fn java_fixture() -> JavaFixture {
        java_fixture_from_facts(java_chain_facts())
    }

    fn java_fixture_from_facts(facts: FileResolutionFacts) -> JavaFixture {
        let lexical = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        let references = lexical
            .semantics()
            .iter()
            .filter(|semantic| semantic.role() == LoweredSemanticRole::Reference)
            .map(|semantic| (semantic.site().get(), semantic.semantic()))
            .collect::<HashMap<_, _>>();
        let definitions = lexical
            .semantics()
            .iter()
            .filter(|semantic| semantic.role() == LoweredSemanticRole::Definition)
            .map(|semantic| (semantic.site().get(), semantic.semantic()))
            .collect::<HashMap<_, _>>();
        let typed = lower_typed_resolution_facts(fragment(), Language::Java, &facts);
        let int_type = typed.intrinsic_seeds()[0].frontier().possible_values()[0]
            .ty()
            .identity();
        JavaFixture {
            service: PreloadedFactSource::from_lowered_fragments(
                [lexical.clone()],
                [typed.clone()],
            ),
            lexical,
            typed,
            references,
            definitions,
            int_type,
        }
    }

    #[test]
    fn implicit_selected_local_witness_is_self_despite_unrelated_incompleteness() {
        let target = SemanticId::hash_bytes(b"implicit-local-target");
        let local = BindingNodeId::hash_bytes(b"implicit-local-node");
        let unrelated = SemanticId::hash_bytes(b"implicit-local-unrelated-property-gap");
        let completion = incomplete(unrelated);

        assert_eq!(
            classify_synthetic_implicit_receiver(
                target,
                &[],
                [synthetic_receiver_witness(
                    b"local-incomplete",
                    target,
                    local,
                    CandidateOutcome::Selected,
                    completion.clone(),
                )],
                completion,
            ),
            FactCallableReceiverDisposition::self_receiver(),
            "unrelated binding/property evidence cannot make a selected local route receiver-open"
        );
    }

    #[test]
    fn implicit_selected_static_import_boundary_is_external() {
        let target = SemanticId::hash_bytes(b"implicit-static-target");
        let boundary = BindingNodeId::hash_bytes(b"implicit-static-boundary");

        assert_eq!(
            classify_synthetic_implicit_receiver(
                target,
                &[boundary],
                [synthetic_receiver_witness(
                    b"static-selected",
                    target,
                    boundary,
                    CandidateOutcome::Selected,
                    ResolutionCompletion::Complete,
                )],
                ResolutionCompletion::Complete,
            ),
            FactCallableReceiverDisposition::external()
        );
    }

    #[test]
    fn implicit_rejected_static_import_does_not_taint_selected_local_route() {
        let target = SemanticId::hash_bytes(b"implicit-rejected-static-target");
        let local = BindingNodeId::hash_bytes(b"implicit-rejected-static-local");
        let boundary = BindingNodeId::hash_bytes(b"implicit-rejected-static-boundary");

        assert_eq!(
            classify_synthetic_implicit_receiver(
                target,
                &[boundary],
                [
                    synthetic_receiver_witness(
                        b"local-selected",
                        target,
                        local,
                        CandidateOutcome::Selected,
                        ResolutionCompletion::Complete,
                    ),
                    synthetic_receiver_witness(
                        b"static-rejected",
                        target,
                        boundary,
                        CandidateOutcome::Rejected(RejectionReason::ShadowedByNearer),
                        ResolutionCompletion::Complete,
                    ),
                ],
                ResolutionCompletion::Complete,
            ),
            FactCallableReceiverDisposition::self_receiver()
        );
    }

    #[test]
    fn implicit_mixed_selected_local_and_static_routes_are_ambiguous() {
        let target = SemanticId::hash_bytes(b"implicit-mixed-target");
        let local = BindingNodeId::hash_bytes(b"implicit-mixed-local");
        let boundary = BindingNodeId::hash_bytes(b"implicit-mixed-static-boundary");

        assert_eq!(
            classify_synthetic_implicit_receiver(
                target,
                &[boundary],
                [
                    synthetic_receiver_witness(
                        b"mixed-local-selected",
                        target,
                        local,
                        CandidateOutcome::Selected,
                        ResolutionCompletion::Complete,
                    ),
                    synthetic_receiver_witness(
                        b"mixed-static-selected",
                        target,
                        boundary,
                        CandidateOutcome::Selected,
                        ResolutionCompletion::Complete,
                    ),
                ],
                ResolutionCompletion::Complete,
            ),
            FactCallableReceiverDisposition {
                channels: FactCallableReceiverChannels::SelfAndExternal,
                gap: Some(FactReferenceReceiverGap::AmbiguousReceiver),
            }
        );
    }

    #[test]
    fn implicit_target_without_selected_witness_is_unresolved() {
        let target = SemanticId::hash_bytes(b"implicit-no-selected-target");
        let local = BindingNodeId::hash_bytes(b"implicit-no-selected-local");

        assert_eq!(
            classify_synthetic_implicit_receiver(
                target,
                &[],
                [synthetic_receiver_witness(
                    b"local-rejected",
                    target,
                    local,
                    CandidateOutcome::Rejected(RejectionReason::ShadowedByNearer),
                    ResolutionCompletion::Complete,
                )],
                ResolutionCompletion::Complete,
            ),
            FactCallableReceiverDisposition::unresolved(
                FactReferenceReceiverGap::UnresolvedReceiver
            )
        );
    }

    #[test]
    fn explicit_receiver_preserves_positive_channels_beside_open_evidence() {
        let target = SemanticId::hash_bytes(b"explicit-open-target");
        let enclosing = SemanticId::hash_bytes(b"explicit-open-enclosing");
        let external_type = SemanticId::hash_bytes(b"explicit-open-external-type");

        assert_eq!(
            classify_synthetic_explicit_receiver(
                target,
                Some(enclosing),
                [ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                    external_type,
                    0,
                ))],
                true,
            ),
            FactCallableReceiverDisposition::from_parts(
                FactCallableReceiverChannels::External,
                Some(FactReferenceReceiverGap::UnresolvedReceiver),
            ),
            "aggregate qualifier incompleteness cannot erase one selected external type-object route"
        );
        assert_eq!(
            classify_synthetic_explicit_receiver(
                target,
                None,
                [ResolutionSlotValue::runtime(
                    ResolutionTypeRef::new(enclosing, 0),
                    false,
                )],
                true,
            ),
            FactCallableReceiverDisposition::from_parts(
                FactCallableReceiverChannels::External,
                Some(FactReferenceReceiverGap::UnresolvedReceiver),
            ),
            "a selected runtime route is external even when the enclosing type is unavailable"
        );
        assert_eq!(
            classify_synthetic_explicit_receiver(
                target,
                Some(enclosing),
                [ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                    enclosing, 0,
                ))],
                true,
            ),
            FactCallableReceiverDisposition::from_parts(
                FactCallableReceiverChannels::SelfReceiver,
                Some(FactReferenceReceiverGap::UnresolvedReceiver),
            ),
            "open evidence stays separate from one selected own-type route"
        );
    }

    #[test]
    fn explicit_receiver_retains_both_selected_channels_as_ambiguous() {
        let target = SemanticId::hash_bytes(b"explicit-mixed-target");
        let enclosing = SemanticId::hash_bytes(b"explicit-mixed-enclosing");

        assert_eq!(
            classify_synthetic_explicit_receiver(
                target,
                Some(enclosing),
                [
                    ResolutionSlotValue::type_object(ResolutionTypeRef::new(enclosing, 0)),
                    ResolutionSlotValue::runtime(ResolutionTypeRef::new(enclosing, 0), false,),
                ],
                false,
            ),
            FactCallableReceiverDisposition::from_parts(
                FactCallableReceiverChannels::SelfAndExternal,
                Some(FactReferenceReceiverGap::AmbiguousReceiver),
            )
        );
    }

    #[test]
    fn explicit_receiver_classifies_closed_type_objects_and_missing_owner_evidence() {
        let target = SemanticId::hash_bytes(b"explicit-closed-target");
        let enclosing = SemanticId::hash_bytes(b"explicit-closed-enclosing");
        let external = SemanticId::hash_bytes(b"explicit-closed-external");
        let own_value = ResolutionSlotValue::type_object(ResolutionTypeRef::new(enclosing, 0));
        let external_value = ResolutionSlotValue::type_object(ResolutionTypeRef::new(external, 0));

        assert_eq!(
            classify_synthetic_explicit_receiver(target, Some(enclosing), [own_value], false),
            FactCallableReceiverDisposition::self_receiver()
        );
        assert_eq!(
            classify_synthetic_explicit_receiver(target, Some(enclosing), [external_value], false,),
            FactCallableReceiverDisposition::external()
        );
        assert_eq!(
            classify_synthetic_explicit_receiver(target, None, [own_value], false),
            FactCallableReceiverDisposition::unresolved(
                FactReferenceReceiverGap::UnresolvedReceiver
            )
        );
        assert_eq!(
            classify_synthetic_explicit_receiver(
                target,
                None,
                [
                    ResolutionSlotValue::runtime(ResolutionTypeRef::new(enclosing, 0), false,),
                    own_value,
                ],
                false,
            ),
            FactCallableReceiverDisposition::from_parts(
                FactCallableReceiverChannels::External,
                Some(FactReferenceReceiverGap::UnresolvedReceiver),
            ),
            "an unknown enclosing type cannot erase an independently selected runtime route"
        );
    }

    #[test]
    fn decisive_receiver_origins_and_cycle_gaps_preserve_channel_inventory() {
        let target = SemanticId::hash_bytes(b"decisive-receiver-origin-target");
        let current = classify_synthetic_root_receiver(
            target,
            true,
            Some(ResolutionCallableReceiverOrigin::CurrentInstance),
        );
        assert_eq!(current.len(), 1);
        assert_eq!(
            current[0].disposition(),
            FactCallableReceiverDisposition::self_receiver()
        );
        let super_receiver = classify_synthetic_root_receiver(
            target,
            true,
            Some(ResolutionCallableReceiverOrigin::Super),
        );
        assert_eq!(super_receiver.len(), 1);
        assert_eq!(
            super_receiver[0].disposition(),
            FactCallableReceiverDisposition::external()
        );
        let missing = classify_synthetic_root_receiver(target, true, None);
        assert_eq!(missing.len(), 1);
        assert_eq!(
            missing[0].disposition(),
            FactCallableReceiverDisposition::unresolved(FactReferenceReceiverGap::MissingOrigin)
        );
        assert!(
            classify_synthetic_root_receiver(target, false, None).is_empty(),
            "ordinary and constructor targets do not manufacture callable receiver gaps"
        );

        let mut external = FactCallableReceiverDisposition::external();
        external.mark_unresolved();
        assert_eq!(
            external,
            FactCallableReceiverDisposition::from_parts(
                FactCallableReceiverChannels::External,
                Some(FactReferenceReceiverGap::UnresolvedReceiver),
            )
        );
        let mut mixed = FactCallableReceiverDisposition::from_parts(
            FactCallableReceiverChannels::SelfAndExternal,
            Some(FactReferenceReceiverGap::AmbiguousReceiver),
        );
        mixed.mark_unresolved();
        assert_eq!(
            mixed,
            FactCallableReceiverDisposition::from_parts(
                FactCallableReceiverChannels::SelfAndExternal,
                Some(FactReferenceReceiverGap::AmbiguousReceiver),
            ),
            "a cycle gap cannot erase either known channel or weaken known ambiguity"
        );
    }

    fn only_projected_value(answer: &FactResolutionAnswer) -> ResolutionSlotValue {
        assert_eq!(answer.projected_frontiers().len(), 1);
        assert_eq!(answer.projected_frontiers()[0].possible_values().len(), 1);
        answer.projected_frontiers()[0].possible_values()[0]
    }

    fn assert_incomplete_with_reason(completion: &ResolutionCompletion, reason: SemanticId) {
        assert!(
            matches!(
                completion,
                ResolutionCompletion::Incomplete(reasons)
                    if reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(reason))
            ),
            "completion {completion:?} does not contain UnsupportedSemantic({reason})"
        );
    }

    #[test]
    fn java_simple_reference_projects_the_selected_declarations_runtime_type() {
        let fixture = java_fixture();
        let answer = fixture
            .resolve_reference(fixture.references[&8], &CancellationToken::new())
            .expect("preload reads are infallible");
        assert_eq!(answer.binding().targets(), &[fixture.definitions[&2]]);
        assert_eq!(
            answer.projected_frontiers()[0].kind(),
            BindingProjectionKind::TargetTypeOrDeclaredValueType
        );
        assert_eq!(
            only_projected_value(&answer),
            ResolutionSlotValue::runtime(ResolutionTypeRef::new(fixture.definitions[&0], 0), false,)
        );
        assert_eq!(answer.completion(), &ResolutionCompletion::Complete);
    }

    #[test]
    fn java_qualified_field_uses_runtime_owner_scope_and_declared_property() {
        let fixture = java_fixture();
        let answer = fixture
            .resolve_reference(fixture.references[&9], &CancellationToken::new())
            .expect("preload reads are infallible");
        assert_eq!(answer.binding().targets(), &[fixture.definitions[&4]]);
        assert_eq!(
            answer.projected_frontiers()[0].kind(),
            BindingProjectionKind::TargetTypeOrDeclaredValueType
        );
        assert_eq!(
            only_projected_value(&answer),
            ResolutionSlotValue::runtime(ResolutionTypeRef::new(fixture.int_type, 0), false)
        );
        assert_eq!(answer.completion(), &ResolutionCompletion::Complete);
    }

    #[test]
    fn java_chained_call_propagates_actual_return_values_into_member_lookup() {
        let fixture = java_fixture();
        let answer = fixture
            .resolve_reference(fixture.references[&12], &CancellationToken::new())
            .expect("preload reads are infallible");
        assert_eq!(answer.binding().targets(), &[fixture.definitions[&5]]);
        assert_eq!(
            answer.projected_frontiers()[0].kind(),
            BindingProjectionKind::TargetTypeOrDeclaredValueType
        );
        assert_eq!(
            only_projected_value(&answer),
            ResolutionSlotValue::runtime(ResolutionTypeRef::new(fixture.int_type, 0), false)
        );
        assert_eq!(answer.completion(), &ResolutionCompletion::Complete);
    }

    #[test]
    fn java_constructor_projects_selected_owner_as_runtime_value() {
        let fixture = java_fixture();
        let answer = fixture
            .resolve_reference(fixture.references[&18], &CancellationToken::new())
            .expect("preload reads are infallible");
        assert_eq!(answer.binding().targets(), &[fixture.definitions[&6]]);
        assert_eq!(
            answer.projected_frontiers()[0].kind(),
            BindingProjectionKind::TargetConstructorOwnerType
        );
        assert_eq!(
            only_projected_value(&answer),
            ResolutionSlotValue::runtime(ResolutionTypeRef::new(fixture.definitions[&0], 0), false,)
        );
        assert_eq!(answer.completion(), &ResolutionCompletion::Complete);
    }

    #[test]
    fn hierarchy_tarjan_work_is_linear_for_chain_ladder_and_cross_edge_dags() {
        fn owner(label: &[u8], ordinal: usize) -> SemanticId {
            SemanticId::hash_bytes(
                [
                    label,
                    &u64::try_from(ordinal)
                        .expect("test ordinal fits u64")
                        .to_le_bytes(),
                ]
                .concat(),
            )
        }

        let chain_len = 1_024_usize;
        let chain = (0..chain_len)
            .map(|ordinal| owner(b"hierarchy-work-chain", ordinal))
            .collect::<Vec<_>>();
        let chain_owners = chain.iter().copied().collect::<BTreeSet<_>>();
        let mut chain_adjacency = BTreeMap::new();
        for edge in chain.windows(2) {
            chain_adjacency
                .entry(edge[0])
                .or_insert_with(BTreeSet::new)
                .insert(edge[1]);
        }
        let mut chain_metrics = HierarchyDerivedWork::default();
        let chain_cycles = hierarchy_iterative_scc_terminals(
            &chain_owners,
            &chain_adjacency,
            &mut chain_metrics,
            &mut || false,
        )
        .expect("uncancelled iterative Tarjan completes");
        assert!(chain_cycles.is_empty());
        assert_eq!(chain_metrics.scc_owner_visits, chain_len);
        assert_eq!(chain_metrics.scc_arc_visits, chain_len - 1);

        let rows = 256_usize;
        let mut ladder_owners = BTreeSet::new();
        let mut ladder_adjacency = BTreeMap::new();
        for row in 0..rows {
            ladder_owners.insert(owner(b"hierarchy-work-ladder-left", row));
            ladder_owners.insert(owner(b"hierarchy-work-ladder-right", row));
            if row + 1 == rows {
                continue;
            }
            for (from_label, to_label) in [
                (
                    b"hierarchy-work-ladder-left".as_slice(),
                    b"hierarchy-work-ladder-left".as_slice(),
                ),
                (
                    b"hierarchy-work-ladder-left".as_slice(),
                    b"hierarchy-work-ladder-right".as_slice(),
                ),
                (
                    b"hierarchy-work-ladder-right".as_slice(),
                    b"hierarchy-work-ladder-left".as_slice(),
                ),
                (
                    b"hierarchy-work-ladder-right".as_slice(),
                    b"hierarchy-work-ladder-right".as_slice(),
                ),
            ] {
                ladder_adjacency
                    .entry(owner(from_label, row))
                    .or_insert_with(BTreeSet::new)
                    .insert(owner(to_label, row + 1));
            }
        }
        let mut ladder_metrics = HierarchyDerivedWork::default();
        let ladder_cycles = hierarchy_iterative_scc_terminals(
            &ladder_owners,
            &ladder_adjacency,
            &mut ladder_metrics,
            &mut || false,
        )
        .expect("uncancelled iterative Tarjan completes");
        assert!(ladder_cycles.is_empty());
        assert_eq!(ladder_metrics.scc_owner_visits, rows * 2);
        assert_eq!(ladder_metrics.scc_arc_visits, (rows - 1) * 4);

        let sink = owner(b"hierarchy-work-cross-edge", 0);
        let mut cross_owners = BTreeSet::from([sink]);
        let mut cross_adjacency = BTreeMap::new();
        for ordinal in 1..=512 {
            let root = owner(b"hierarchy-work-cross-edge", ordinal);
            cross_owners.insert(root);
            cross_adjacency.insert(root, BTreeSet::from([sink]));
        }
        let mut cross_metrics = HierarchyDerivedWork::default();
        let cross_cycles = hierarchy_iterative_scc_terminals(
            &cross_owners,
            &cross_adjacency,
            &mut cross_metrics,
            &mut || false,
        )
        .expect("uncancelled iterative Tarjan completes");
        assert!(cross_cycles.is_empty());
        assert_eq!(cross_metrics.scc_owner_visits, 513);
        assert_eq!(cross_metrics.scc_arc_visits, 512);
    }

    #[test]
    fn hierarchy_tarjan_polls_terminal_zero_target_owners() {
        let owners = (0_u64..=CANCELLATION_QUANTUM as u64)
            .map(|ordinal| SemanticId::hash_bytes(ordinal.to_le_bytes()))
            .collect::<BTreeSet<_>>();
        let mut metrics = HierarchyDerivedWork::default();
        let mut polls = 0_usize;
        let cycles =
            hierarchy_iterative_scc_terminals(&owners, &BTreeMap::new(), &mut metrics, &mut || {
                polls += 1;
                polls == 17
            });
        assert!(cycles.is_none());
        assert_eq!(polls, 17);
        assert!(metrics.scc_owner_visits < owners.len());
    }

    #[test]
    fn hierarchy_evidence_preserves_one_atom_across_unequal_diamond_depths() {
        let first = ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::hash_bytes(
            b"unequal-diamond-first",
        ));
        let second = ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::hash_bytes(
            b"unequal-diamond-second",
        ));
        let completion =
            ResolutionCompletion::Incomplete(vec![second, first, second].into_boxed_slice().into());
        let identity = SemanticId::hash_bytes(b"unequal-diamond-source-atom");
        let mut arena = HierarchyEvidenceArena::default();
        let atom = arena
            .one(identity, completion.clone(), &mut || false)
            .expect("atom construction is uncancelled");
        let near = arena.shift(atom.clone(), 2);
        let far = arena.shift(atom, 4);
        let diamond = arena.union(far, near);

        assert_eq!(
            arena
                .flatten(&diamond, u32::MAX, &mut || false)
                .expect("flatten is uncancelled"),
            completion
        );
    }

    #[test]
    fn hierarchy_reference_atom_deduplicates_across_shape_cutoffs_before_flatten() {
        let first = ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::hash_bytes(
            b"cross-shape-reference-first",
        ));
        let second = ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::hash_bytes(
            b"cross-shape-reference-second",
        ));
        let completion =
            ResolutionCompletion::Incomplete(vec![second, first, second].into_boxed_slice().into());
        let reference = SemanticId::hash_bytes(b"cross-shape-reference");
        let mut arena = HierarchyEvidenceArena::default();
        let atom = arena
            .one(
                hierarchy_reference_atom_identity(reference),
                completion.clone(),
                &mut || false,
            )
            .expect("atom construction is uncancelled");
        let type_shifted = arena.shift(atom.clone(), 1);
        let type_shape = arena
            .truncate(&type_shifted, 2, &mut || false)
            .expect("type-shape cutoff is uncancelled");
        let runtime_shifted = arena.shift(atom, 1);
        let runtime_shape = arena
            .truncate(&runtime_shifted, 2, &mut || false)
            .expect("runtime-shape cutoff is uncancelled");
        let outer = arena.union(type_shape, runtime_shape);
        assert_eq!(
            arena
                .flatten(&outer, u32::MAX, &mut || false)
                .expect("outer cross-shape flatten is uncancelled"),
            completion
        );
    }

    #[test]
    fn hierarchy_evidence_compact_dag_flatten_is_node_linear() {
        let reason = ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::hash_bytes(
            b"compact-evidence-dag-gap",
        ));
        let completion =
            ResolutionCompletion::Incomplete(vec![reason, reason].into_boxed_slice().into());
        let mut arena = HierarchyEvidenceArena::default();
        let mut expression = arena
            .one(
                SemanticId::hash_bytes(b"compact-evidence-dag-atom"),
                completion.clone(),
                &mut || false,
            )
            .expect("atom construction is uncancelled");
        for _ in 0..96 {
            let near = arena.shift(expression.clone(), 1);
            let far = arena.shift(expression, 2);
            expression = arena.union(near, far);
        }
        let node_count = arena.expressions.len();
        let mut polls = 0_usize;
        let flattened = arena
            .flatten(&expression, u32::MAX, &mut || {
                polls += 1;
                false
            })
            .expect("flatten is uncancelled");
        assert_eq!(flattened, completion);
        assert!(
            polls <= node_count * 4 + 8,
            "compact evidence DAG expanded by paths: polls={polls}, nodes={node_count}"
        );
    }

    #[test]
    fn hierarchy_evidence_large_sole_box_is_polled_and_preserved_verbatim() {
        let reasons = (0_u64..=CANCELLATION_QUANTUM as u64)
            .map(|ordinal| {
                ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::hash_bytes(
                    ordinal.to_le_bytes(),
                ))
            })
            .collect::<Vec<_>>();
        let completion = ResolutionCompletion::Incomplete(reasons.into_boxed_slice().into());
        let mut arena = HierarchyEvidenceArena::default();
        let evidence = arena
            .one(
                SemanticId::hash_bytes(b"large-sole-hierarchy-box"),
                completion.clone(),
                &mut || false,
            )
            .expect("atom construction is uncancelled");
        let mut polls = 0_usize;
        let flattened = arena
            .flatten(&evidence, u32::MAX, &mut || {
                polls += 1;
                false
            })
            .expect("flatten is uncancelled");
        assert_eq!(flattened, completion);
        assert!(polls > CANCELLATION_QUANTUM);

        let mut cancellation_polls = 0_usize;
        assert!(
            arena
                .flatten(&evidence, u32::MAX, &mut || {
                    cancellation_polls += 1;
                    cancellation_polls == 31
                })
                .is_none()
        );
        assert_eq!(cancellation_polls, 31);
    }

    #[test]
    fn hierarchy_evidence_two_empty_atoms_matches_public_combine_panic() {
        let empty = ResolutionCompletion::Incomplete(Vec::new().into());
        let mut arena = HierarchyEvidenceArena::default();
        let left = arena
            .one(
                SemanticId::hash_bytes(b"empty-hierarchy-atom-left"),
                empty.clone(),
                &mut || false,
            )
            .expect("atom construction is uncancelled");
        let right = arena
            .one(
                SemanticId::hash_bytes(b"empty-hierarchy-atom-right"),
                empty,
                &mut || false,
            )
            .expect("atom construction is uncancelled");
        let evidence = arena.union(left, right);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = arena.flatten(&evidence, u32::MAX, &mut || false);
            }))
            .is_err()
        );
    }

    #[test]
    fn hierarchy_publication_generation_hides_partial_state_until_atomic_commit() {
        let shape = HierarchyLookupShape::new(
            SemanticId::hash_bytes(b"atomic-hierarchy-lookup"),
            ResolutionNamespace::Value,
            QualifierCategory::Runtime,
            0,
        );
        let owner = SemanticId::hash_bytes(b"atomic-hierarchy-owner");
        let key = HierarchyNodeKey { shape, owner };
        let cycle = PartialPathId::hash_bytes(b"atomic-hierarchy-cycle");
        let summary = HierarchyStructuralSummary {
            candidate_distance: None,
            candidates: None,
            evidence: HierarchyEvidence::Complete,
            transfer: HierarchyEvidence::Complete,
            retains_global_evidence: false,
        };
        let mut arena = HierarchyOperationArena::default();

        let cancelled_generation = arena.begin_publication();
        arena.stage_summary(cancelled_generation, key, summary.clone());
        arena.stage_closure_owner(cancelled_generation, owner);
        arena.stage_cycle(cancelled_generation, owner, cycle);
        assert!(!arena.contains_summary(key));
        assert!(!arena.closure_contains(owner));
        assert_eq!(arena.cycle(owner), None);

        let retry_generation = arena.begin_publication();
        arena.stage_summary(retry_generation, key, summary);
        arena.stage_closure_owner(retry_generation, owner);
        arena.stage_cycle(retry_generation, owner, cycle);
        arena.commit_publication(retry_generation);
        assert!(arena.contains_summary(key));
        assert!(arena.closure_contains(owner));
        assert_eq!(arena.cycle(owner), Some(cycle));
    }

    #[test]
    fn hierarchy_selection_uses_one_global_minimum_across_all_roots() {
        let fixture = java_fixture();
        let cancellation = CancellationToken::new();
        let mut session = preloaded_session(&fixture.service, &cancellation);
        let mut hierarchy = HierarchyOperationArena::default();
        let mut evaluation =
            FactEvaluation::new(&mut session, &mut hierarchy, fixture.references[&8]);
        let shape = HierarchyLookupShape::new(
            SemanticId::hash_bytes(b"global-minimum-lookup"),
            ResolutionNamespace::Value,
            QualifierCategory::Runtime,
            0,
        );
        let far_root = SemanticId::hash_bytes(b"global-minimum-far-root");
        let near_root = SemanticId::hash_bytes(b"global-minimum-near-root");
        let far_candidate = SemanticId::hash_bytes(b"global-minimum-far-candidate");
        let near_candidate = SemanticId::hash_bytes(b"global-minimum-near-candidate");
        let far_reason = SemanticId::hash_bytes(b"global-minimum-far-reason");
        let near_reason = SemanticId::hash_bytes(b"global-minimum-near-reason");
        {
            let hierarchy = &mut *evaluation.hierarchy;
            let far_atom = hierarchy
                .evidence
                .one(far_reason, incomplete(far_reason), &mut || false)
                .expect("atom construction is uncancelled");
            let near_atom = hierarchy
                .evidence
                .one(near_reason, incomplete(near_reason), &mut || false)
                .expect("atom construction is uncancelled");
            let far_expression = hierarchy.candidates.here(far_candidate);
            let near_expression = hierarchy.candidates.here(near_candidate);
            let far_evidence = hierarchy.evidence.shift(far_atom, 4);
            let near_evidence = hierarchy.evidence.shift(near_atom, 2);
            let generation = hierarchy.begin_publication();
            hierarchy.stage_summary(
                generation,
                HierarchyNodeKey {
                    shape,
                    owner: far_root,
                },
                HierarchyStructuralSummary {
                    candidate_distance: Some(2),
                    candidates: Some(far_expression),
                    evidence: far_evidence,
                    transfer: HierarchyEvidence::Complete,
                    retains_global_evidence: true,
                },
            );
            hierarchy.stage_summary(
                generation,
                HierarchyNodeKey {
                    shape,
                    owner: near_root,
                },
                HierarchyStructuralSummary {
                    candidate_distance: Some(1),
                    candidates: Some(near_expression),
                    evidence: near_evidence,
                    transfer: HierarchyEvidence::Complete,
                    retains_global_evidence: true,
                },
            );
            hierarchy.commit_publication(generation);
        }
        let roots = [
            HierarchyRoot {
                owner: far_root,
                value: ResolutionSlotValue::runtime(ResolutionTypeRef::new(far_root, 0), false),
                route_ordinal: 0,
            },
            HierarchyRoot {
                owner: near_root,
                value: ResolutionSlotValue::runtime(ResolutionTypeRef::new(near_root, 0), false),
                route_ordinal: 1,
            },
        ];
        let selection = match evaluation
            .cached_hierarchy_selection(shape, &roots)
            .expect("cached hierarchy selection is infallible")
            .expect("both root summaries are cached")
        {
            HierarchySelectionState::Pending => panic!("uncancelled selection cannot be pending"),
            HierarchySelectionState::Ready(selection) => selection,
        };
        assert_eq!(selection.owners.len(), 1);
        assert_eq!(selection.owners[0].owner, near_candidate);
        assert_eq!(selection.owners[0].root.owner, near_root);
        assert_eq!(
            evaluation
                .hierarchy
                .evidence
                .flatten(&selection.evidence, u32::MAX, &mut || false)
                .expect("flatten is uncancelled"),
            incomplete(near_reason)
        );
    }

    fn detector_snapshot(label: u8) -> EvaluationSnapshot {
        let references = [SemanticId::hash_bytes([label])].into_iter().collect();
        snapshot(
            &references,
            &HashSet::default(),
            &HashMap::default(),
            &HashMap::default(),
        )
    }

    fn detected_period(labels: &[u8]) -> Option<usize> {
        let (&first, rest) = labels.split_first().expect("cycle fixture has an origin");
        let mut detector = ExactCycleDetector::new(detector_snapshot(first));
        let cancellation = CancellationToken::new();
        let mut work = 0;
        rest.iter().find_map(|&label| {
            match detector.observe(detector_snapshot(label), &cancellation, &mut work) {
                CycleObservation::Continue => None,
                CycleObservation::Repeated(period) => Some(period),
                CycleObservation::Cancelled => panic!("uncancelled detector fixture cancelled"),
            }
        })
    }

    #[test]
    fn exact_brent_certificate_detects_periods_one_two_and_three() {
        assert_eq!(detected_period(&[0, 0]), Some(1));
        assert_eq!(detected_period(&[0, 1, 0, 1]), Some(2));
        assert_eq!(detected_period(&[0, 1, 2, 0, 1, 2, 0]), Some(3));
    }

    #[test]
    fn exact_cycle_snapshot_includes_demand_growth() {
        let reference_a = SemanticId::hash_bytes(b"demand-a");
        let reference_b = SemanticId::hash_bytes(b"demand-b");
        let before = snapshot(
            &[reference_a].into_iter().collect(),
            &HashSet::default(),
            &HashMap::default(),
            &HashMap::default(),
        );
        let after = snapshot(
            &[reference_a, reference_b].into_iter().collect(),
            &HashSet::default(),
            &HashMap::default(),
            &HashMap::default(),
        );
        assert_ne!(before, after);

        let mut detector = ExactCycleDetector::new(before);
        let cancellation = CancellationToken::new();
        let mut work = 0;
        assert_eq!(
            detector.observe(after, &cancellation, &mut work),
            CycleObservation::Continue
        );
    }

    #[test]
    fn exact_cycle_snapshot_is_stable_under_map_and_set_permutation() {
        let reference_a = SemanticId::hash_bytes(b"permutation-reference-a");
        let reference_b = SemanticId::hash_bytes(b"permutation-reference-b");
        let slot_a = SemanticId::hash_bytes(b"permutation-slot-a");
        let slot_b = SemanticId::hash_bytes(b"permutation-slot-b");
        let target = SemanticId::hash_bytes(b"permutation-target");
        let answer = ResolutionAnswer::new([target], Vec::new(), ResolutionCompletion::Complete);
        let state = TypedFrontierState::new(
            slot_a,
            [ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                target, 0,
            ))],
            ResolutionCompletion::Complete,
        );

        let left_references = [reference_a, reference_b].into_iter().collect();
        let right_references = [reference_b, reference_a].into_iter().collect();
        let left_slots = [slot_a, slot_b].into_iter().collect();
        let right_slots = [slot_b, slot_a].into_iter().collect();
        let left_answers = [(reference_a, answer.clone()), (reference_b, answer.clone())]
            .into_iter()
            .collect();
        let right_answers = [(reference_b, answer.clone()), (reference_a, answer)]
            .into_iter()
            .collect();
        let left_states = [
            (slot_a, state.clone()),
            (
                slot_b,
                TypedFrontierState::new(slot_b, Vec::new(), ResolutionCompletion::Complete),
            ),
        ]
        .into_iter()
        .collect();
        let right_states = [
            (
                slot_b,
                TypedFrontierState::new(slot_b, Vec::new(), ResolutionCompletion::Complete),
            ),
            (slot_a, state),
        ]
        .into_iter()
        .collect();

        assert_eq!(
            snapshot(&left_references, &left_slots, &left_answers, &left_states,),
            snapshot(
                &right_references,
                &right_slots,
                &right_answers,
                &right_states,
            )
        );
    }

    #[test]
    fn exact_cycle_replay_returns_entry_instead_of_meeting_phase() {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        struct ReplayState(u8);

        let cycle_length =
            detected_period(&[0, 1, 2, 3, 2, 3]).expect("the nonzero-tail fixture must repeat");
        let mut origin = ReplayState(0);
        let mut context = ();
        let mut replay_metrics = ResolutionBatchMetrics::default();
        let entry = replay_cycle_entry(
            &mut origin,
            cycle_length,
            &mut context,
            &mut replay_metrics,
            |state, _, _| Ok::<_, ()>(Some(*state)),
            |state, _, _| {
                state.0 = match state.0 {
                    0 => 1,
                    1 => 2,
                    2 => 3,
                    3 => 2,
                    value => panic!("unexpected replay state {value}"),
                };
                Ok::<_, ()>(true)
            },
            |left, right, _, _| Ok(Some(left == right)),
        )
        .expect("infallible replay")
        .entry
        .expect("replay was not cancelled");
        assert_eq!(entry, ReplayState(2));
    }

    #[test]
    fn exact_cycle_replay_propagates_cancellation() {
        let mut advances = 0;
        let mut origin = 0_u8;
        let mut context = ();
        let mut replay_metrics = ResolutionBatchMetrics::default();
        let entry = replay_cycle_entry(
            &mut origin,
            2,
            &mut context,
            &mut replay_metrics,
            |state, _, _| Ok::<_, ()>(Some(*state)),
            |state, _, _| {
                advances += 1;
                if advances == 2 {
                    return Ok::<_, ()>(false);
                }
                *state = state.wrapping_add(1);
                Ok(true)
            },
            |left, right, _, _| Ok(Some(left == right)),
        )
        .expect("infallible replay");
        assert!(entry.entry.is_none());
    }

    #[test]
    fn exact_cycle_replay_returns_both_cursor_ledgers_on_adjacent_cancellation() {
        #[derive(Clone)]
        struct ReplayState {
            value: u8,
            reasons: BTreeSet<ResolutionIncompleteReason>,
        }

        let first = ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::hash_bytes(
            b"replay-trailing-gap",
        ));
        let second = ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::hash_bytes(
            b"replay-leading-gap",
        ));
        let mut advances = 0;
        let mut origin = ReplayState {
            value: 0,
            reasons: BTreeSet::new(),
        };
        let mut context = ();
        let mut replay_metrics = ResolutionBatchMetrics::default();
        let outcome = replay_cycle_entry(
            &mut origin,
            1,
            &mut context,
            &mut replay_metrics,
            |state, _, _| Ok::<_, ()>(Some(state.clone())),
            |state, _, _| {
                advances += 1;
                state.value = state.value.wrapping_add(1);
                match advances {
                    2 => {
                        state.reasons.insert(first);
                        Ok(true)
                    }
                    3 => {
                        state.reasons.insert(second);
                        state.reasons.insert(ResolutionIncompleteReason::Cancelled);
                        Ok(false)
                    }
                    _ => Ok(true),
                }
            },
            |left, right, _, _| Ok(Some(left.value == right.value)),
        )
        .expect("infallible replay");

        assert!(outcome.entry.is_none());
        let reasons = outcome
            .discarded
            .into_iter()
            .flat_map(|state| state.reasons)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            reasons,
            [first, second, ResolutionIncompleteReason::Cancelled]
                .into_iter()
                .collect()
        );
    }

    #[test]
    fn exact_cycle_replay_propagates_final_equivalence_cancellation() {
        let mut origin = 0_u8;
        let cancellation = CancellationToken::cancel_after_checks_for_test(1);
        let mut context = ();
        let mut replay_metrics = ResolutionBatchMetrics::default();
        let entry = replay_cycle_entry(
            &mut origin,
            1,
            &mut context,
            &mut replay_metrics,
            |state, _, _| Ok::<_, ()>(Some(*state)),
            |_state, _, _| Ok(true),
            |_left, _right, _, _| {
                assert!(cancellation.is_cancelled());
                Ok(None)
            },
        )
        .expect("infallible replay");
        assert!(entry.entry.is_none());
    }

    #[test]
    fn snapshot_cancellation_discards_the_partial_snapshot() {
        let reference = SemanticId::hash_bytes(b"snapshot-cancellation-reference");
        let references = [reference].into_iter().collect();
        let cancellation = CancellationToken::cancel_after_checks_for_test(1);
        let mut work = CANCELLATION_QUANTUM - 2;
        assert!(
            snapshot_with_poll(
                &references,
                &HashSet::default(),
                &HashMap::default(),
                &HashMap::default(),
                &cancellation,
                &mut work,
            )
            .is_none()
        );
    }

    #[test]
    fn forced_dependency_gaps_reset_the_cycle_epoch_with_exact_reasons() {
        let fixture = java_fixture();
        let cancellation = CancellationToken::new();
        let mut session = preloaded_session(&fixture.service, &cancellation);
        let mut hierarchy = HierarchyOperationArena::default();
        let mut evaluation =
            FactEvaluation::new(&mut session, &mut hierarchy, fixture.references[&8]);
        evaluation.demands.clear();
        evaluation.demanded_references.clear();
        evaluation.demanded_slots.clear();
        let reference = SemanticId::hash_bytes(b"missing-reference-dependency");
        let slot = SemanticId::hash_bytes(b"missing-slot-dependency");
        evaluation.demanded_references.insert(reference);
        evaluation.demanded_slots.insert(slot);
        let answers = HashMap::default();
        let states = HashMap::default();
        let current = snapshot(
            &evaluation.demanded_references,
            &evaluation.demanded_slots,
            &answers,
            &states,
        );
        let origin = evaluation
            .checkpoint(&answers, &states)
            .expect("uncancelled checkpoint");
        let mut cycle = Some(ExactCycleCertificate::new(origin, current));

        assert!(evaluation.force_unresolved_dependencies(&answers, &states, &mut cycle));
        assert!(cycle.is_none());
        assert_eq!(
            evaluation.forced_reference_gaps[&reference],
            incomplete(service_reason(
                b"unresolved-reference-dependency",
                &[reference.as_bytes().as_slice()],
            ))
        );
        assert_eq!(
            evaluation.forced_slot_gaps[&slot],
            incomplete(service_reason(
                b"unresolved-slot-dependency",
                &[slot.as_bytes().as_slice()],
            ))
        );
    }

    #[test]
    fn fact_evaluation_honors_cancellation_before_cycle_detection() {
        let fixture = java_fixture();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let answer = fixture
            .resolve_reference(fixture.references[&9], &cancellation)
            .expect("preload reads are infallible");
        assert!(answer.binding().targets().is_empty());
        assert!(answer.projected_frontiers().is_empty());
        assert_eq!(answer.completion(), &incomplete_cancelled());
    }

    #[test]
    fn final_publication_gate_replaces_a_finished_answer_atomically() {
        let fixture = java_fixture();
        let cancellation = CancellationToken::cancel_after_checks_for_test(1);
        let mut session = preloaded_session(&fixture.service, &cancellation);
        let mut hierarchy = HierarchyOperationArena::default();
        let mut evaluation =
            FactEvaluation::new(&mut session, &mut hierarchy, fixture.references[&8]);
        let finished = FactResolutionAnswer {
            site_metadata: None,
            callable_receiver_dispositions: Box::new([]),
            binding: ResolutionAnswer::new(
                [fixture.definitions[&2]],
                Vec::new(),
                ResolutionCompletion::Complete,
            ),
            projected_frontiers: Box::new([]),
            completion: ResolutionCompletion::Complete,
        };

        let published = evaluation.publish(finished);
        assert!(published.binding().targets().is_empty());
        assert!(published.projected_frontiers().is_empty());
        assert_eq!(published.completion(), &incomplete_cancelled());
    }

    #[test]
    fn cancellation_ledger_polls_and_retains_every_returned_reason() {
        let fixture = java_fixture();
        let cancellation = CancellationToken::new();
        let mut session = preloaded_session(&fixture.service, &cancellation);
        let mut hierarchy = HierarchyOperationArena::default();
        let mut evaluation =
            FactEvaluation::new(&mut session, &mut hierarchy, fixture.references[&8]);
        let expected = (0..=CANCELLATION_QUANTUM)
            .map(|ordinal| {
                ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::hash_bytes(
                    ordinal.to_le_bytes(),
                ))
            })
            .collect::<Vec<_>>();
        let returned = ResolutionCompletion::incomplete(expected.iter().copied());
        cancellation.cancel();

        evaluation.observe_cancellation_completion(&returned);
        let answer = evaluation.cancelled_answer(None);

        assert!(evaluation.work >= CANCELLATION_QUANTUM);
        for &reason in &expected {
            assert!(answer.binding().completion().contains_reason(reason));
            assert!(answer.completion().contains_reason(reason));
        }
        assert!(
            answer
                .completion()
                .contains_reason(ResolutionIncompleteReason::Cancelled)
        );
    }

    #[test]

    fn seeded_identity_distinguishes_runtime_addressability() {
        let fixture = java_fixture();
        let reference = fixture.references[&9];
        let route = fixture_value_route(&fixture, reference);
        let owner = fixture.definitions[&0];
        let scope = fixture
            .typed
            .member_scopes()
            .iter()
            .find(|row| row.definition() == owner)
            .expect("owner has a scope")
            .scope_head();
        let origin = SemanticId::hash_bytes(b"seeded-addressability-origin");

        assert_ne!(
            qualified_seed_path_id(
                &route,
                scope,
                ResolutionSlotValue::runtime(ResolutionTypeRef::new(owner, 0), false),
                origin,
            ),
            qualified_seed_path_id(
                &route,
                scope,
                ResolutionSlotValue::runtime(ResolutionTypeRef::new(owner, 0), true),
                origin,
            )
        );
    }

    #[test]
    fn qualified_path_construction_cancels_before_the_seeded_wrapper() {
        let fixture = java_fixture();
        let reference = fixture.references[&9];
        let route = fixture_value_route(&fixture, reference);
        let owner = fixture.definitions[&0];
        let scope = fixture
            .typed
            .member_scopes()
            .iter()
            .find(|row| row.definition() == owner)
            .expect("owner has a scope")
            .scope_head();
        let seed = fixture
            .service
            .reference_seed(ResolutionQuery::new(reference), &CancellationToken::new())
            .expect("preloaded seed lookup is infallible")
            .expect("qualified fixture reference has a source seed");
        let completion = ResolutionCompletion::Incomplete(
            (0_u64..=CANCELLATION_QUANTUM as u64)
                .map(|ordinal| {
                    ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::hash_bytes(
                        ordinal.to_le_bytes(),
                    ))
                })
                .collect::<Vec<_>>()
                .into_boxed_slice()
                .into(),
        );
        let mut polls = 0_usize;

        assert!(
            qualified_seed_path(
                &seed,
                &route,
                scope,
                SemanticId::hash_bytes(b"large-qualified-path-origin"),
                &[],
                completion,
                &mut || {
                    polls += 1;
                    polls > CANCELLATION_QUANTUM
                },
            )
            .is_none()
        );
        assert!(polls > CANCELLATION_QUANTUM);
    }

    #[test]
    fn transfer_sccs_subsume_finite_cycles_and_block_productive_cycles() {
        let first_owner = BindingFragmentId::hash_bytes(b"cycle-owner-first");
        let second_owner = BindingFragmentId::hash_bytes(b"cycle-owner-second");
        let a = SemanticId::hash_bytes(b"cycle-a");
        let b = SemanticId::hash_bytes(b"cycle-b");
        let finite = vec![
            Rc::new(selected_transfer(
                first_owner,
                SemanticId::hash_bytes(b"finite-a-b"),
                a,
                b,
            )),
            Rc::new(selected_transfer(
                second_owner,
                SemanticId::hash_bytes(b"finite-b-a"),
                b,
                a,
            )),
        ];
        let finite = classify_transfer_cycles(&finite, &mut || false)
            .expect("the finite classification is live");
        assert_eq!(finite.finite_slots, [a, b].into_iter().collect());
        assert!(finite.productive_slots.is_empty());
        assert!(finite.productive_edges.is_empty());

        let productive = vec![
            Rc::new(selected_transfer_with(
                first_owner,
                SemanticId::hash_bytes(b"productive-a-b"),
                a,
                b,
                1,
                TypeTransferValueTransform::Preserve,
                ResolutionCompletion::Complete,
            )),
            Rc::new(selected_transfer_with(
                second_owner,
                SemanticId::hash_bytes(b"productive-b-a"),
                b,
                a,
                -1,
                TypeTransferValueTransform::Preserve,
                ResolutionCompletion::Complete,
            )),
        ];
        let productive = classify_transfer_cycles(&productive, &mut || false)
            .expect("the productive classification is live");
        assert!(productive.finite_slots.is_empty());
        assert_eq!(productive.productive_slots.len(), 2);
        assert_eq!(productive.productive_edges.len(), 2);
        assert_eq!(
            productive.productive_slots[&a],
            productive.productive_slots[&b]
        );
        assert_ne!(
            productive.productive_slots[&a],
            service_reason(b"typed-fixed-point-cycle", &[a.as_bytes().as_slice()])
        );

        let mut work = 0_usize;
        let cancellation = CancellationToken::new();
        let grouped = group_test_selected_transfer_sources(
            productive
                .productive_edges
                .keys()
                .map(|&(source, target)| {
                    let (owner, semantic, delta) = if source == a {
                        (first_owner, b"productive-a-b".as_slice(), 1)
                    } else {
                        (second_owner, b"productive-b-a".as_slice(), -1)
                    };
                    Rc::new(selected_transfer_with(
                        owner,
                        SemanticId::hash_bytes(semantic),
                        source,
                        target,
                        delta,
                        TypeTransferValueTransform::Preserve,
                        ResolutionCompletion::Complete,
                    ))
                })
                .collect(),
            vec![
                Rc::new(SelectedTypeFrontierCompletion::new(
                    first_owner,
                    a,
                    ResolutionCompletion::Complete,
                )),
                Rc::new(SelectedTypeFrontierCompletion::new(
                    second_owner,
                    b,
                    ResolutionCompletion::Complete,
                )),
            ],
            &cancellation,
            &mut work,
        )
        .expect("cross-fragment cycle ownership is valid");
        assert!(grouped.is_some());
    }

    #[test]
    fn qualified_seed_normalization_is_source_neutral_and_route_exact() {
        let fixture = java_fixture();
        let reference = fixture.references[&9];
        let route_reason = fixture_value_route(&fixture, reference)
            .row()
            .coarse_gap_reason();
        let expected = fixture
            .resolve_reference(reference, &CancellationToken::new())
            .expect("the normalized preload seed is source-readable");
        assert!(!expected.completion().contains_reason(
            ResolutionIncompleteReason::UnsupportedSemantic(route_reason)
        ));
        let raw_lexical_source =
            ObservedBatchSource::with_reference_seed_gap(&fixture.service, reference, route_reason);
        let cancellation = CancellationToken::new();
        let mut session =
            split_preloaded_session(&fixture.service, &raw_lexical_source, &cancellation);

        let actual = session
            .resolve_reference(reference)
            .expect("the raw lexical seed is normalized at selected route ownership");

        assert_eq!(actual, expected);
        let scalar_queries = raw_lexical_source.reference_seed_queries.borrow();
        let expected_scalar_queries = [fixture.references[&7], fixture.references[&8]]
            .into_iter()
            .collect::<BTreeSet<_>>();
        assert_eq!(scalar_queries.len(), expected_scalar_queries.len());
        assert_eq!(
            scalar_queries.iter().copied().collect::<BTreeSet<_>>(),
            expected_scalar_queries
        );
        assert!(expected_scalar_queries.iter().all(|query| {
            scalar_queries
                .iter()
                .filter(|&&actual| actual == *query)
                .count()
                == 1
        }));
        assert!(!scalar_queries.contains(&reference));
        assert_eq!(
            raw_lexical_source.reference_seed_lookups.get(),
            scalar_queries.len()
        );
        assert_eq!(raw_lexical_source.reference_seed_batch_lookups.get(), 1);
        assert_eq!(
            raw_lexical_source
                .reference_seed_batch_sizes
                .borrow()
                .as_slice(),
            &[1]
        );
        assert_eq!(
            raw_lexical_source
                .reference_seed_batch_queries
                .borrow()
                .as_slice(),
            &[vec![reference]]
        );
    }

    #[test]
    fn qualified_seed_normalization_retains_non_owned_evidence() {
        let fixture = java_fixture();
        let reference = fixture.references[&9];
        let route_reason = fixture_value_route(&fixture, reference)
            .row()
            .coarse_gap_reason();
        let retained_reason = SemanticId::hash_bytes(b"qualified-seed-non-owned-gap");
        let raw_lexical_source = ObservedBatchSource::with_reference_seed_completion(
            &fixture.service,
            reference,
            ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(route_reason),
                ResolutionIncompleteReason::UnsupportedSemantic(retained_reason),
            ]),
        );
        let cancellation = CancellationToken::new();
        let mut session =
            split_preloaded_session(&fixture.service, &raw_lexical_source, &cancellation);

        let answer = session
            .resolve_reference(reference)
            .expect("non-owned seed evidence remains source-readable");

        assert_incomplete_with_reason(answer.completion(), retained_reason);
        assert!(!answer.completion().contains_reason(
            ResolutionIncompleteReason::UnsupportedSemantic(route_reason)
        ));
        assert!(answer.binding().witnesses().iter().all(|witness| {
            witness
                .completion()
                .contains_reason(ResolutionIncompleteReason::UnsupportedSemantic(
                    retained_reason,
                ))
                && !witness.completion().contains_reason(
                    ResolutionIncompleteReason::UnsupportedSemantic(route_reason),
                )
        }));
    }

    #[test]
    fn qualified_seed_normalization_requires_exact_selected_route_ownership() {
        let fixture = java_fixture();
        let reference = fixture.references[&9];

        for fault in [
            ReferenceSeedFault::Fragment,
            ReferenceSeedFault::Reference,
            ReferenceSeedFault::Node,
        ] {
            let source = ObservedBatchSource::with_reference_seed_fault(&fixture.service, fault);
            let cancellation = CancellationToken::new();
            let mut session = split_preloaded_session(&fixture.service, &source, &cancellation);

            let error = session
                .resolve_reference(reference)
                .expect_err("a seed/selected-route ownership mismatch is a store error");

            let expected = match fault {
                ReferenceSeedFault::Reference => "disagrees with request",
                ReferenceSeedFault::Fragment | ReferenceSeedFault::Node => {
                    "disagrees with selected route"
                }
            };
            assert!(error.to_string().contains(expected));
        }
    }

    #[test]
    fn unqualified_scalar_root_seed_requires_exact_query() {
        let fixture = java_fixture();
        let reference = fixture.references[&8];
        assert!(
            !fixture
                .typed
                .qualified_routes()
                .iter()
                .any(|route| route.reference() == reference),
            "the scalar-root contract law requires an unqualified reference"
        );
        let source = ObservedBatchSource::with_reference_seed_fault(
            &fixture.service,
            ReferenceSeedFault::Reference,
        );
        let cancellation = CancellationToken::new();
        let mut session = split_preloaded_session(&fixture.service, &source, &cancellation);

        let error = session
            .resolve_reference(reference)
            .expect_err("a scalar seed for another query is a store error");

        assert!(error.to_string().contains("unqualified reference seed"));
        assert!(error.to_string().contains("disagrees with request"));
        assert_eq!(source.reference_seed_lookups.get(), 1);
        assert_eq!(
            source.reference_seed_queries.borrow().as_slice(),
            &[reference]
        );
        assert_eq!(source.reference_seed_batch_lookups.get(), 0);
    }

    #[derive(Clone, Copy)]
    enum ReferenceSeedFault {
        Fragment,
        Reference,
        Node,
    }
    struct ObservedBatchSource<'a> {
        inner: &'a PreloadedFactSource,
        reference_seed_lookups: Cell<usize>,
        reference_seed_queries: RefCell<Vec<SemanticId>>,
        reference_seed_batch_lookups: Cell<usize>,
        reference_seed_batch_sizes: RefCell<Vec<usize>>,
        reference_seed_batch_queries: RefCell<Vec<Vec<SemanticId>>>,
        reference_seed_completion: Option<(SemanticId, ResolutionCompletion)>,
        reference_seed_fault: Option<ReferenceSeedFault>,
    }
    impl<'a> ObservedBatchSource<'a> {
        fn new(inner: &'a PreloadedFactSource) -> Self {
            Self {
                inner,
                reference_seed_lookups: Cell::new(0),
                reference_seed_queries: RefCell::new(Vec::new()),
                reference_seed_batch_lookups: Cell::new(0),
                reference_seed_batch_sizes: RefCell::new(Vec::new()),
                reference_seed_batch_queries: RefCell::new(Vec::new()),
                reference_seed_completion: None,
                reference_seed_fault: None,
            }
        }
        fn with_reference_seed_gap(
            inner: &'a PreloadedFactSource,
            reference: SemanticId,
            reason: SemanticId,
        ) -> Self {
            Self::with_reference_seed_completion(inner, reference, incomplete(reason))
        }
        fn with_reference_seed_completion(
            inner: &'a PreloadedFactSource,
            reference: SemanticId,
            completion: ResolutionCompletion,
        ) -> Self {
            let mut source = Self::new(inner);
            source.reference_seed_completion = Some((reference, completion));
            source
        }
        fn with_reference_seed_fault(
            inner: &'a PreloadedFactSource,
            fault: ReferenceSeedFault,
        ) -> Self {
            let mut source = Self::new(inner);
            source.reference_seed_fault = Some(fault);
            source
        }
        fn transform_reference_seed(&self, seed: ReferenceSeed) -> ReferenceSeed {
            let reference = seed.reference();
            let completion = match &self.reference_seed_completion {
                Some((selected, completion)) if *selected == reference => {
                    seed.completion().combine(completion)
                }
                _ => seed.completion().clone(),
            };
            let mut fragment = seed.fragment();
            let mut query = seed.query();
            let mut node = seed.node();
            match self.reference_seed_fault {
                Some(ReferenceSeedFault::Fragment) => {
                    fragment = BindingFragmentId::hash_bytes(b"hostile-qualified-seed-fragment")
                }
                Some(ReferenceSeedFault::Reference) => {
                    query = ResolutionQuery::new(SemanticId::hash_bytes(
                        b"hostile-qualified-seed-reference",
                    ))
                }
                Some(ReferenceSeedFault::Node) => {
                    node = BindingNodeId::hash_bytes(b"hostile-qualified-seed-node")
                }
                None => {}
            }
            ReferenceSeed::new_with_site_metadata(
                fragment,
                query,
                node,
                seed.site_metadata(),
                completion,
            )
        }
    }
    impl BatchResolutionFragmentSource for ObservedBatchSource<'_> {
        fn reference_seed(
            &self,
            query: ResolutionQuery,
            cancellation: &CancellationToken,
        ) -> StoreResult<Option<ReferenceSeed>> {
            self.reference_seed_lookups
                .set(self.reference_seed_lookups.get() + 1);
            let reference = query.reference();
            self.reference_seed_queries.borrow_mut().push(reference);
            let Some(seed) = self.inner.reference_seed(query, cancellation)? else {
                return Ok(None);
            };
            Ok(Some(self.transform_reference_seed(seed)))
        }
        fn lookup_reference_seeds(
            &self,
            queries: &[ResolutionQuery],
            cancellation: &CancellationToken,
        ) -> StoreResult<ReferenceSeedReadOutcome> {
            self.reference_seed_batch_lookups
                .set(self.reference_seed_batch_lookups.get() + 1);
            self.reference_seed_batch_sizes
                .borrow_mut()
                .push(queries.len());
            self.reference_seed_batch_queries
                .borrow_mut()
                .push(queries.iter().map(|query| query.reference()).collect());
            let outcome = self.inner.lookup_reference_seeds(queries, cancellation)?;
            if outcome.is_cancelled() {
                return Ok(outcome);
            }
            let (rows, terminal, evidence) = outcome.into_parts();
            assert_eq!(terminal, ReferenceSeedReadTerminal::Exhausted);
            let mut transformed = Vec::with_capacity(rows.len());
            for row in rows.into_vec() {
                let ordinal = row.request_ordinal();
                let original_query = row.query();
                let seed = row
                    .into_seed()
                    .map(|seed| self.transform_reference_seed(seed));
                let returned_query = seed.as_ref().map_or(original_query, ReferenceSeed::query);
                transformed.push(BatchReferenceSeed::new(ordinal, returned_query, seed));
            }
            debug_assert_eq!(evidence, ResolutionCompletion::Complete);
            Ok(ReferenceSeedReadOutcome::exhausted(transformed))
        }
        fn lookup_definition_node(
            &self,
            definition: SemanticId,
            cancellation: &CancellationToken,
        ) -> StoreResult<Option<BindingNodeId>> {
            BatchResolutionFragmentSource::lookup_definition_node(
                self.inner,
                definition,
                cancellation,
            )
        }
        fn lookup_definition_nodes(
            &self,
            definitions: &[SemanticId],
            cancellation: &CancellationToken,
        ) -> StoreResult<Vec<BatchDefinitionNode>> {
            BatchResolutionFragmentSource::lookup_definition_nodes(
                self.inner,
                definitions,
                cancellation,
            )
        }
        fn issue_reverse_reference_seeds(
            &self,
            requests: &[ReverseReferenceSeedRequest],
            cancellation: &CancellationToken,
        ) -> StoreResult<Vec<ReferenceSeed>> {
            BatchResolutionFragmentSource::issue_reverse_reference_seeds(
                self.inner,
                requests,
                cancellation,
            )
        }
        fn visit_reference_seed_batches(
            &self,
            maximum_batch_size: usize,
            cancellation: &CancellationToken,
            visitor: &mut dyn FnMut(&ReferenceSeedBatch) -> StoreResult<bool>,
        ) -> StoreResult<ResolutionCompletion> {
            BatchResolutionFragmentSource::visit_reference_seed_batches(
                self.inner,
                maximum_batch_size,
                cancellation,
                visitor,
            )
        }
        fn classify_endpoint_nodes(
            &self,
            nodes: &[BindingNodeId],
            cancellation: &CancellationToken,
        ) -> StoreResult<Vec<BatchEndpointClassification>> {
            BatchResolutionFragmentSource::classify_endpoint_nodes(self.inner, nodes, cancellation)
        }
        fn match_forward_candidates(
            &self,
            requests: &[BatchCandidateRequest],
            cancellation: &CancellationToken,
        ) -> StoreResult<BatchCandidateOutcome> {
            BatchResolutionFragmentSource::match_forward_candidates(
                self.inner,
                requests,
                cancellation,
            )
        }
        fn visit_forward_candidate_match_pages(
            &self,
            requests: &[BatchCandidateRequest],
            cancellation: &CancellationToken,
            visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
        ) -> StoreResult<BatchCandidateCompletionOutcome> {
            BatchResolutionFragmentSource::visit_forward_candidate_match_pages(
                self.inner,
                requests,
                cancellation,
                visitor,
            )
        }
        fn visit_forward_candidate_match_pages_limited(
            &self,
            requests: &[BatchCandidateRequest],
            maximum_page_rows: usize,
            resolution_session: Option<&ResolutionSession>,
            cancellation: &CancellationToken,
            visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
        ) -> StoreResult<BatchCandidateCompletionOutcome> {
            BatchResolutionFragmentSource::visit_forward_candidate_match_pages_limited(
                self.inner,
                requests,
                maximum_page_rows,
                resolution_session,
                cancellation,
                visitor,
            )
        }
        fn match_reverse_candidates(
            &self,
            requests: &[BatchCandidateRequest],
            cancellation: &CancellationToken,
        ) -> StoreResult<BatchCandidateOutcome> {
            BatchResolutionFragmentSource::match_reverse_candidates(
                self.inner,
                requests,
                cancellation,
            )
        }
        fn visit_reverse_candidate_match_pages(
            &self,
            requests: &[BatchCandidateRequest],
            cancellation: &CancellationToken,
            visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
        ) -> StoreResult<BatchCandidateCompletionOutcome> {
            BatchResolutionFragmentSource::visit_reverse_candidate_match_pages(
                self.inner,
                requests,
                cancellation,
                visitor,
            )
        }
        fn hydrate_candidate_paths(
            &self,
            candidates: &[CandidatePathIdentity],
            cancellation: &CancellationToken,
        ) -> StoreResult<Vec<(CandidatePathIdentity, PartialPath)>> {
            BatchResolutionFragmentSource::hydrate_candidate_paths(
                self.inner,
                candidates,
                cancellation,
            )
        }
        fn visit_type_transfer_rules(
            &self,
            source_slot: SemanticId,
            cancellation: &CancellationToken,
            visitor: &mut dyn FnMut(&TypeTransferRule) -> StoreResult<bool>,
        ) -> StoreResult<ResolutionCompletion> {
            BatchResolutionFragmentSource::visit_type_transfer_rules(
                self.inner,
                source_slot,
                cancellation,
                visitor,
            )
        }
    }
    struct CancelledFrontierSource<'a> {
        inner: &'a PreloadedFactSource,
        frontier: SemanticId,
        completion: ResolutionCompletion,
    }
    impl SelectedTypedFactSource for CancelledFrontierSource<'_> {
        fn visit_selected_fragment_pages(
            &self,
            cancellation: &CancellationToken,
            visitor: &mut FactPageVisitor<'_, BindingFragmentId>,
        ) -> StoreResult<FactReadOutcome> {
            self.inner
                .visit_selected_fragment_pages(cancellation, visitor)
        }
        fn read_selected_reverse_inventory_completion(
            &self,
            cancellation: &CancellationToken,
        ) -> StoreResult<TypedFactReadOutcome> {
            self.inner
                .read_selected_reverse_inventory_completion(cancellation)
        }
        fn visit_typed_frontier_pages(
            &self,
            slots: TypedFactRequest<'_, SemanticId>,
            cancellation: &CancellationToken,
            visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypedFrontier>>,
        ) -> StoreResult<TypedFactReadOutcome> {
            self.inner
                .visit_typed_frontier_pages(slots, cancellation, visitor)
        }
        fn visit_type_frontier_completion_pages(
            &self,
            frontiers: TypedFactRequest<'_, SemanticId>,
            cancellation: &CancellationToken,
            visitor: &mut TypedFactPageVisitor<'_, SelectedTypeFrontierCompletion>,
        ) -> StoreResult<TypedFactReadOutcome> {
            let mut callback = |page: &[SelectedTypeFrontierCompletion]| {
                let rows = page
                    .iter()
                    .map(|row| {
                        if row.frontier() == self.frontier {
                            SelectedTypeFrontierCompletion::new(
                                row.fragment(),
                                row.frontier(),
                                self.completion.clone(),
                            )
                        } else {
                            row.clone()
                        }
                    })
                    .collect::<Vec<_>>();
                visitor.visit_page(&rows)
            };
            self.inner.visit_type_frontier_completion_pages(
                frontiers,
                cancellation,
                &mut TypedFactPageVisitor::new(&mut callback),
            )
        }
        fn visit_type_transfer_pages_from_sources(
            &self,
            source_slots: TypedFactRequest<'_, SemanticId>,
            cancellation: &CancellationToken,
            visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypeTransfer>>,
        ) -> StoreResult<TypedFactReadOutcome> {
            self.inner
                .visit_type_transfer_pages_from_sources(source_slots, cancellation, visitor)
        }
        fn visit_type_transfer_pages_to_targets(
            &self,
            target_slots: TypedFactRequest<'_, SemanticId>,
            cancellation: &CancellationToken,
            visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypeTransfer>>,
        ) -> StoreResult<TypedFactReadOutcome> {
            self.inner
                .visit_type_transfer_pages_to_targets(target_slots, cancellation, visitor)
        }
        fn visit_intrinsic_seed_pages_for_slots(
            &self,
            slots: TypedFactRequest<'_, SemanticId>,
            cancellation: &CancellationToken,
            visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredIntrinsicSeed>>,
        ) -> StoreResult<TypedFactReadOutcome> {
            self.inner
                .visit_intrinsic_seed_pages_for_slots(slots, cancellation, visitor)
        }
        fn visit_intrinsic_seed_pages_for_type_identities(
            &self,
            type_identities: TypedFactRequest<'_, SemanticId>,
            cancellation: &CancellationToken,
            visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredIntrinsicSeed>>,
        ) -> StoreResult<TypedFactReadOutcome> {
            self.inner.visit_intrinsic_seed_pages_for_type_identities(
                type_identities,
                cancellation,
                visitor,
            )
        }
        fn visit_binding_projection_pages_for_references(
            &self,
            references: TypedFactRequest<'_, SemanticId>,
            cancellation: &CancellationToken,
            visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredBindingProjection>>,
        ) -> StoreResult<TypedFactReadOutcome> {
            self.inner.visit_binding_projection_pages_for_references(
                references,
                cancellation,
                visitor,
            )
        }
        fn visit_binding_projection_pages_for_outputs(
            &self,
            output_slots: TypedFactRequest<'_, SemanticId>,
            cancellation: &CancellationToken,
            visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredBindingProjection>>,
        ) -> StoreResult<TypedFactReadOutcome> {
            self.inner.visit_binding_projection_pages_for_outputs(
                output_slots,
                cancellation,
                visitor,
            )
        }
        fn visit_qualified_route_pages_for_references(
            &self,
            references: TypedFactRequest<'_, SemanticId>,
            cancellation: &CancellationToken,
            visitor: &mut TypedFactPageVisitor<'_, SourceSelectedQualifiedRoute>,
        ) -> StoreResult<TypedFactReadOutcome> {
            self.inner
                .visit_qualified_route_pages_for_references(references, cancellation, visitor)
        }
        fn visit_qualified_route_pages_for_slot_lookups(
            &self,
            requests: TypedFactRequest<'_, QualifiedRouteSlotLookup>,
            cancellation: &CancellationToken,
            visitor: &mut TypedFactPageVisitor<'_, SourceSelectedQualifiedRoute>,
        ) -> StoreResult<TypedFactReadOutcome> {
            self.inner
                .visit_qualified_route_pages_for_slot_lookups(requests, cancellation, visitor)
        }
        fn visit_qualified_route_pages_for_qualifier_slots(
            &self,
            qualifier_slots: TypedFactRequest<'_, SemanticId>,
            cancellation: &CancellationToken,
            visitor: &mut TypedFactPageVisitor<'_, SourceSelectedQualifiedRoute>,
        ) -> StoreResult<TypedFactReadOutcome> {
            self.inner.visit_qualified_route_pages_for_qualifier_slots(
                qualifier_slots,
                cancellation,
                visitor,
            )
        }
        fn visit_qualified_route_pages_for_lookups(
            &self,
            lookups: TypedFactRequest<'_, SemanticId>,
            cancellation: &CancellationToken,
            visitor: &mut TypedFactPageVisitor<'_, SourceSelectedQualifiedRoute>,
        ) -> StoreResult<TypedFactReadOutcome> {
            self.inner
                .visit_qualified_route_pages_for_lookups(lookups, cancellation, visitor)
        }
        fn visit_qualified_route_pages_for_gap_reasons(
            &self,
            reasons: TypedFactRequest<'_, SemanticId>,
            cancellation: &CancellationToken,
            visitor: &mut TypedFactPageVisitor<'_, SourceSelectedQualifiedRoute>,
        ) -> StoreResult<TypedFactReadOutcome> {
            self.inner
                .visit_qualified_route_pages_for_gap_reasons(reasons, cancellation, visitor)
        }
        fn visit_qualified_route_inventory_pages(
            &self,
            cancellation: &CancellationToken,
            visitor: &mut TypedFactPageVisitor<'_, SourceSelectedQualifiedRoute>,
        ) -> StoreResult<TypedFactReadOutcome> {
            self.inner
                .visit_qualified_route_inventory_pages(cancellation, visitor)
        }
        fn visit_declaration_type_pages_for_definitions(
            &self,
            definitions: TypedFactRequest<'_, SemanticId>,
            cancellation: &CancellationToken,
            visitor: &mut TypedFactPageVisitor<
                '_,
                SelectedTypedRow<LoweredDeclarationTypeProperty>,
            >,
        ) -> StoreResult<TypedFactReadOutcome> {
            self.inner.visit_declaration_type_pages_for_definitions(
                definitions,
                cancellation,
                visitor,
            )
        }
        fn visit_declaration_type_pages_for_slots(
            &self,
            slots: TypedFactRequest<'_, SemanticId>,
            cancellation: &CancellationToken,
            visitor: &mut TypedFactPageVisitor<
                '_,
                SelectedTypedRow<LoweredDeclarationTypeProperty>,
            >,
        ) -> StoreResult<TypedFactReadOutcome> {
            self.inner
                .visit_declaration_type_pages_for_slots(slots, cancellation, visitor)
        }
        fn visit_declaration_visibility_pages_for_definitions(
            &self,
            definitions: TypedFactRequest<'_, SemanticId>,
            cancellation: &CancellationToken,
            visitor: &mut TypedFactPageVisitor<
                '_,
                SelectedTypedRow<LoweredDeclarationVisibilityProperty>,
            >,
        ) -> StoreResult<TypedFactReadOutcome> {
            self.inner
                .visit_declaration_visibility_pages_for_definitions(
                    definitions,
                    cancellation,
                    visitor,
                )
        }
        fn visit_member_scope_pages_for_definitions(
            &self,
            definitions: TypedFactRequest<'_, SemanticId>,
            cancellation: &CancellationToken,
            visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredMemberScopeProperty>>,
        ) -> StoreResult<TypedFactReadOutcome> {
            self.inner
                .visit_member_scope_pages_for_definitions(definitions, cancellation, visitor)
        }
        fn visit_member_scope_pages_for_heads(
            &self,
            heads: TypedFactRequest<'_, BindingNodeId>,
            cancellation: &CancellationToken,
            visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredMemberScopeProperty>>,
        ) -> StoreResult<TypedFactReadOutcome> {
            self.inner
                .visit_member_scope_pages_for_heads(heads, cancellation, visitor)
        }
        fn visit_member_scope_inventory_pages(
            &self,
            cancellation: &CancellationToken,
            visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredMemberScopeProperty>>,
        ) -> StoreResult<TypedFactReadOutcome> {
            self.inner
                .visit_member_scope_inventory_pages(cancellation, visitor)
        }
        fn visit_member_owner_pages_for_definitions(
            &self,
            definitions: TypedFactRequest<'_, SemanticId>,
            cancellation: &CancellationToken,
            visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredMemberOwnerProperty>>,
        ) -> StoreResult<TypedFactReadOutcome> {
            self.inner
                .visit_member_owner_pages_for_definitions(definitions, cancellation, visitor)
        }
        fn visit_member_owner_pages_for_owners(
            &self,
            owner_definitions: TypedFactRequest<'_, SemanticId>,
            cancellation: &CancellationToken,
            visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredMemberOwnerProperty>>,
        ) -> StoreResult<TypedFactReadOutcome> {
            self.inner
                .visit_member_owner_pages_for_owners(owner_definitions, cancellation, visitor)
        }
        fn visit_construction_requirement_pages_for_definitions(
            &self,
            definitions: TypedFactRequest<'_, SemanticId>,
            cancellation: &CancellationToken,
            visitor: &mut TypedFactPageVisitor<
                '_,
                SelectedTypedRow<LoweredConstructionRequirementProperty>,
            >,
        ) -> StoreResult<TypedFactReadOutcome> {
            self.inner
                .visit_construction_requirement_pages_for_definitions(
                    definitions,
                    cancellation,
                    visitor,
                )
        }
        fn visit_supertype_pages_for_definitions(
            &self,
            definitions: TypedFactRequest<'_, SemanticId>,
            cancellation: &CancellationToken,
            visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredSupertypeProperty>>,
        ) -> StoreResult<TypedFactReadOutcome> {
            self.inner
                .visit_supertype_pages_for_definitions(definitions, cancellation, visitor)
        }
        fn visit_supertype_pages_for_references(
            &self,
            references: TypedFactRequest<'_, SemanticId>,
            cancellation: &CancellationToken,
            visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredSupertypeProperty>>,
        ) -> StoreResult<TypedFactReadOutcome> {
            self.inner
                .visit_supertype_pages_for_references(references, cancellation, visitor)
        }
        fn visit_supertype_pages_for_frontiers(
            &self,
            frontiers: TypedFactRequest<'_, SemanticId>,
            cancellation: &CancellationToken,
            visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredSupertypeProperty>>,
        ) -> StoreResult<TypedFactReadOutcome> {
            self.inner
                .visit_supertype_pages_for_frontiers(frontiers, cancellation, visitor)
        }
        fn visit_definition_property_gap_pages_for_definitions(
            &self,
            definitions: TypedFactRequest<'_, SemanticId>,
            cancellation: &CancellationToken,
            visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDefinitionPropertyGap>>,
        ) -> StoreResult<TypedFactReadOutcome> {
            self.inner
                .visit_definition_property_gap_pages_for_definitions(
                    definitions,
                    cancellation,
                    visitor,
                )
        }
        fn visit_call_applicability_pages_for_callee_references(
            &self,
            callee_references: TypedFactRequest<'_, SemanticId>,
            cancellation: &CancellationToken,
            visitor: &mut TypedFactPageVisitor<
                '_,
                SelectedTypedRow<LoweredCallApplicabilityObligation>,
            >,
        ) -> StoreResult<TypedFactReadOutcome> {
            self.inner
                .visit_call_applicability_pages_for_callee_references(
                    callee_references,
                    cancellation,
                    visitor,
                )
        }
        fn visit_callable_signature_pages_for_definitions(
            &self,
            definitions: TypedFactRequest<'_, SemanticId>,
            cancellation: &CancellationToken,
            visitor: &mut TypedFactPageVisitor<
                '_,
                SelectedTypedRow<LoweredCallableSignatureProperty>,
            >,
        ) -> StoreResult<TypedFactReadOutcome> {
            self.inner.visit_callable_signature_pages_for_definitions(
                definitions,
                cancellation,
                visitor,
            )
        }
        fn visit_gap_reason_provenance_pages_for_reasons(
            &self,
            reasons: TypedFactRequest<'_, SemanticId>,
            cancellation: &CancellationToken,
            visitor: &mut TypedFactPageVisitor<'_, SelectedGapReasonProvenance>,
        ) -> StoreResult<TypedFactReadOutcome> {
            self.inner
                .visit_gap_reason_provenance_pages_for_reasons(reasons, cancellation, visitor)
        }
    }

    #[test]
    fn fact_read_session_live_row_cancelled_evidence_wins_over_visitor_stop() {
        let fixture = java_fixture();
        let frontier = fixture.typed.frontiers()[0].slot();
        let gap = SemanticId::hash_bytes(b"session-live-row-cancelled-gap");
        let source = CancelledFrontierSource {
            inner: &fixture.service,
            frontier,
            completion: ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::Cancelled,
                ResolutionIncompleteReason::UnsupportedSemantic(gap),
            ]),
        };
        let cancellation = CancellationToken::new();
        let mut session =
            FactReadSession::from_split_sources(&fixture.service, &source, &cancellation);

        let read = session
            .frontier_completions(&[frontier])
            .expect("source-returned cancellation is semantic control flow");
        let SessionFactRead::Cancelled(evidence) = read else {
            panic!("row-owned Cancelled evidence must win over callback stop")
        };
        assert_incomplete_with_reason(&evidence, gap);
        assert!(evidence.contains_reason(ResolutionIncompleteReason::Cancelled));
        assert!(session.cache.frontier_completions.by_request.is_empty());
    }

    #[test]
    fn point_fact_answers_preserve_reference_site_metadata() {
        let fixture = java_fixture();
        let explicit_call = fixture.references[&11];
        let expected = fixture
            .lexical
            .semantics()
            .iter()
            .filter(|semantic| semantic.role() == LoweredSemanticRole::Reference)
            .map(|semantic| (semantic.semantic(), semantic.site_metadata()))
            .collect::<HashMap<_, _>>();
        let point = fixture
            .resolve_reference(explicit_call, &CancellationToken::new())
            .expect("preloaded point fact resolution succeeds");
        assert_eq!(point.site_metadata(), expected[&explicit_call]);
        assert_eq!(
            point.callable_receiver_origin(),
            point
                .site_metadata()
                .and_then(FactReferenceSiteMetadata::callable_receiver_origin)
        );
    }

    fn java_qualifier_cycle_slots(
        fixture: &JavaFixture,
    ) -> (BindingFragmentId, SemanticId, SemanticId, SemanticId) {
        let target = fixture_value_route(fixture, fixture.references[&9])
            .row()
            .qualifier_slot();
        let transfer = fixture
            .typed
            .transfers()
            .iter()
            .find(|row| row.rule().target_slot() == target)
            .expect("the qualified receiver has one incoming transfer");
        let source = transfer.source_slot();
        assert_eq!(
            fixture
                .typed
                .projections()
                .iter()
                .find(|row| row.reference() == fixture.references[&8])
                .unwrap()
                .output_slot(),
            source,
            "the preceding unqualified reference externally produces the cycle source"
        );
        (fragment(), source, target, transfer.rule().semantic())
    }
    fn selected_cycle_classification(
        source: &PreloadedFactSource,
        slots: &[SemanticId],
    ) -> TransferCycleClassification {
        let cancellation = CancellationToken::new();
        let mut session = FactReadSession::new(source, &cancellation);
        let SessionFactRead::Exhausted { rows, .. } = session
            .transfers_to_targets(slots)
            .expect("selected cycle rows read")
        else {
            panic!("live cycle rows exhaust")
        };
        let rows = rows
            .iter()
            .map(|row| row.get(&session).clone())
            .collect::<Vec<_>>();
        classify_transfer_cycles(&rows, &mut || false)
            .expect("a live selected cycle classification completes")
    }

    #[test]
    fn qualified_seed_filtering_cancels_atomically_and_retains_raw_evidence() {
        let fixture = java_fixture();
        let reference = fixture.references[&9];
        let route_reason = fixture_value_route(&fixture, reference)
            .row()
            .coarse_gap_reason();
        let mut semantics = BTreeSet::new();
        semantics.insert(route_reason);
        let mut reasons = Vec::new();
        reasons.push(ResolutionIncompleteReason::UnsupportedSemantic(
            route_reason,
        ));
        for ordinal in 0_u64..(CANCELLATION_QUANTUM as u64 * 2 + 17) {
            reasons.push(ResolutionIncompleteReason::UnsupportedSemantic(
                SemanticId::hash_bytes(
                    [
                        b"qualified-seed-retained-reason".as_slice(),
                        &ordinal.to_le_bytes(),
                    ]
                    .concat(),
                ),
            ));
        }
        let raw_completion =
            ResolutionCompletion::Incomplete(reasons.clone().into_boxed_slice().into());
        let mut polls = 0_usize;
        let cancel_at = CANCELLATION_QUANTUM + 3;
        assert!(
            completion_without_unsupported_semantics_with_poll(
                &raw_completion,
                &semantics,
                &mut || {
                    polls += 1;
                    polls == cancel_at
                },
            )
            .is_none(),
            "filtering a large returned completion polls before publishing its retained prefix"
        );
        assert_eq!(polls, cancel_at);

        let ResolutionIncompleteReason::UnsupportedSemantic(first_retained) = reasons[1] else {
            unreachable!("the fixture installs only unsupported-semantic reasons")
        };
        let ResolutionIncompleteReason::UnsupportedSemantic(last_retained) =
            reasons[reasons.len() - 1]
        else {
            unreachable!("the fixture installs only unsupported-semantic reasons")
        };
        let mut observed_atomic_cancellation = false;
        for checks in 1..=4096 {
            let source = ObservedBatchSource::with_reference_seed_completion(
                &fixture.service,
                reference,
                raw_completion.clone(),
            );
            let cancellation = CancellationToken::cancel_after_checks_for_test(checks);
            let mut session = split_preloaded_session(&fixture.service, &source, &cancellation);
            let answer = session
                .resolve_reference(reference)
                .expect("cancellation is semantic control flow");
            if answer
                .completion()
                .contains_reason(ResolutionIncompleteReason::Cancelled)
                && answer.completion().contains_reason(
                    ResolutionIncompleteReason::UnsupportedSemantic(route_reason),
                )
                && answer.completion().contains_reason(
                    ResolutionIncompleteReason::UnsupportedSemantic(first_retained),
                )
                && answer.completion().contains_reason(
                    ResolutionIncompleteReason::UnsupportedSemantic(last_retained),
                )
            {
                assert!(answer.binding().targets().is_empty());
                assert!(answer.binding().witnesses().is_empty());
                assert!(answer.projected_frontiers().is_empty());
                observed_atomic_cancellation = true;
                break;
            }
        }
        assert!(
            observed_atomic_cancellation,
            "one deterministic cancellation budget retains the full decoded seed box without publishing an answer prefix"
        );
    }

    #[test]
    fn finite_zero_delta_transfer_cycle_reaches_the_same_complete_fixed_point() {
        let baseline = java_fixture();
        let expected = baseline
            .resolve_reference(baseline.references[&9], &CancellationToken::new())
            .expect("baseline preload point reads are infallible");

        let mut fixture = java_fixture();
        let (owner, source, target, _) = java_qualifier_cycle_slots(&fixture);
        fixture.service.set_frontier_completion_for_test(
            owner,
            target,
            ResolutionCompletion::Complete,
        );
        let reverse = LoweredTypeTransfer::new(
            target,
            ResolutionTypeTransferKind::Assignment,
            TypeTransferRule::new(
                SemanticId::hash_bytes(b"finite-qualifier-cycle-reverse"),
                source,
                0,
                TypeTransferValueTransform::Preserve,
                ResolutionCompletion::Complete,
            ),
        );
        fixture.service.install_transfer_for_test(owner, reverse);
        let classification = selected_cycle_classification(&fixture.service, &[source, target]);
        assert_eq!(
            classification.finite_slots,
            [source, target].into_iter().collect()
        );
        assert!(classification.productive_slots.is_empty());

        let cancellation = CancellationToken::new();
        let mut session = preloaded_session(&fixture.service, &cancellation);
        let actual = session
            .resolve_reference(fixture.references[&9])
            .expect("finite cyclic preload point reads are infallible");
        let closure_rows = session.cache.transfer_rows.rows.to_vec();
        let full_classification = classify_transfer_cycles(&closure_rows, &mut || false)
            .expect("the installed closure classifies");
        assert_eq!(
            full_classification.finite_slots,
            [source, target].into_iter().collect()
        );
        assert!(full_classification.productive_slots.is_empty());
        assert_eq!(actual, expected);
        assert_eq!(actual.completion(), &ResolutionCompletion::Complete);
    }

    #[test]
    fn point_transfer_authority_excludes_unrelated_outgoing_rows() {
        let mut fixture = java_fixture();
        let (owner, source, target, forward_semantic) = java_qualifier_cycle_slots(&fixture);
        fixture.service.replace_transfer_for_test(
            forward_semantic,
            0,
            TypeTransferValueTransform::ToNoValue,
            ResolutionCompletion::Complete,
        );
        let expected = fixture
            .resolve_reference(fixture.references[&9], &CancellationToken::new())
            .expect("the demanded ToNoValue producer is source-readable");
        assert!(expected.binding().targets().is_empty());

        let decoy_target = SemanticId::hash_bytes(b"unrelated-outgoing-decoy-target");
        let decoy_rule = SemanticId::hash_bytes(b"unrelated-outgoing-decoy-rule");
        let decoy_gap = SemanticId::hash_bytes(b"unrelated-outgoing-decoy-gap");

        assert!(
            fixture
                .service
                .set_frontier_completion_for_test(
                    owner,
                    decoy_target,
                    ResolutionCompletion::Complete
                )
                .is_none()
        );
        fixture.service.install_transfer_for_test(
            owner,
            LoweredTypeTransfer::new(
                source,
                ResolutionTypeTransferKind::Assignment,
                TypeTransferRule::new(
                    decoy_rule,
                    decoy_target,
                    0,
                    TypeTransferValueTransform::ToNoValue,
                    incomplete(decoy_gap),
                ),
            ),
        );
        let cancellation = CancellationToken::new();
        let mut session = preloaded_session(&fixture.service, &cancellation);

        let actual = session
            .resolve_reference(fixture.references[&9])
            .expect("the selected incoming relation is complete");

        assert_eq!(actual, expected);
        assert!(
            !actual
                .completion()
                .contains_reason(ResolutionIncompleteReason::UnsupportedSemantic(decoy_gap))
        );
        let cache = &session.cache;
        assert!(cache.transfers_by_source.by_request.is_empty());
        assert!(cache.transfers_by_target.by_request.contains_key(&target));
        assert!(
            !cache
                .transfers_by_target
                .by_request
                .contains_key(&decoy_target)
        );
    }

    #[test]
    fn productive_internal_edges_publish_no_values_and_keep_exact_evidence() {
        for transform in [
            TypeTransferValueTransform::Preserve,
            TypeTransferValueTransform::ToNoValue,
        ] {
            let mut fixture = java_fixture();
            let (owner, source, target, forward_semantic) = java_qualifier_cycle_slots(&fixture);
            let (forward_delta, reverse_delta) = match transform {
                TypeTransferValueTransform::Preserve => (-1, 0),
                TypeTransferValueTransform::ToNoValue => (0, 1),
                TypeTransferValueTransform::ToRuntime { .. } => {
                    unreachable!("the productive-cycle law selects two explicit transforms")
                }
            };
            let source_state_gap = SemanticId::hash_bytes(b"productive-cycle-source-state-gap");
            let frontier_gap = SemanticId::hash_bytes(b"productive-cycle-frontier-gap");
            let rule_gap = SemanticId::hash_bytes(b"productive-cycle-rule-gap");
            let source_completion = fixture
                .service
                .frontier_completion_for_test(source)
                .combine(&incomplete(frontier_gap));
            fixture
                .service
                .set_frontier_completion_for_test(owner, source, source_completion);
            fixture.service.replace_transfer_for_test(
                forward_semantic,
                forward_delta,
                transform,
                incomplete(rule_gap),
            );
            fixture.service.install_transfer_for_test(
                owner,
                LoweredTypeTransfer::new(
                    target,
                    ResolutionTypeTransferKind::Assignment,
                    TypeTransferRule::new(
                        SemanticId::hash_bytes(b"productive-qualifier-cycle-reverse"),
                        source,
                        reverse_delta,
                        TypeTransferValueTransform::Preserve,
                        ResolutionCompletion::Complete,
                    ),
                ),
            );
            let external_target = SemanticId::hash_bytes(b"productive-cycle-external-target");
            let external_rule_gap = SemanticId::hash_bytes(b"productive-cycle-external-rule-gap");

            assert!(
                fixture
                    .service
                    .set_frontier_completion_for_test(
                        owner,
                        external_target,
                        ResolutionCompletion::Complete
                    )
                    .is_none()
            );
            fixture.service.install_transfer_for_test(
                owner,
                LoweredTypeTransfer::new(
                    source,
                    ResolutionTypeTransferKind::Assignment,
                    TypeTransferRule::new(
                        SemanticId::hash_bytes(b"productive-cycle-external-rule"),
                        external_target,
                        0,
                        TypeTransferValueTransform::Preserve,
                        incomplete(external_rule_gap),
                    ),
                ),
            );
            let classification = selected_cycle_classification(&fixture.service, &[source, target]);
            let component_reason = classification.productive_slots[&source];
            assert_eq!(classification.productive_slots[&target], component_reason);
            assert_eq!(classification.productive_edges.len(), 2);

            let observed_source = ObservedBatchSource::with_reference_seed_gap(
                &fixture.service,
                fixture.references[&8],
                source_state_gap,
            );
            let cancellation = CancellationToken::new();
            let mut session =
                split_preloaded_session(&fixture.service, &observed_source, &cancellation);
            let blocked = session
                .resolve_reference(fixture.references[&9])
                .expect("productive cyclic preload point reads are infallible");
            assert!(
                blocked.binding().targets().is_empty(),
                "a productive internal receiver edge cannot propagate a qualifier value for {transform:?}"
            );
            for reason in [source_state_gap, frontier_gap, rule_gap, component_reason] {
                assert_incomplete_with_reason(blocked.completion(), reason);
            }
            assert!(
                !blocked.completion().contains_reason(
                    ResolutionIncompleteReason::UnsupportedSemantic(forward_semantic)
                ),
                "a blocked productive edge is never run, so a counterfactual adjustment failure is not evidence"
            );
            assert!(
                !blocked.completion().contains_reason(
                    ResolutionIncompleteReason::UnsupportedSemantic(external_rule_gap)
                ),
                "an undemanded external outgoing edge cannot contaminate the productive target"
            );

            let external = fixture
                .resolve_reference(fixture.references[&8], &CancellationToken::new())
                .expect("external projection into a productive SCC remains executable");
            let source_state = external
                .projected_frontiers()
                .iter()
                .find(|state| state.slot() == source)
                .expect("the unqualified reference projects the cycle source")
                .clone();
            assert!(
                !source_state.possible_values().is_empty(),
                "the external acyclic producer must still apply"
            );
            assert_incomplete_with_reason(source_state.completion(), component_reason);

            let transfer_cancellation = CancellationToken::new();
            let mut transfer_session = preloaded_session(&fixture.service, &transfer_cancellation);
            let mut transfer_hierarchy = HierarchyOperationArena::default();
            let mut transfer_evaluation = FactEvaluation::new(
                &mut transfer_session,
                &mut transfer_hierarchy,
                fixture.references[&8],
            );
            transfer_evaluation.demand_slot(external_target);
            assert!(
                transfer_evaluation
                    .expand_demands()
                    .expect("the external transfer closure is source-readable")
            );
            let mut previous_states = HashMap::default();
            previous_states.insert(source, source_state.state().clone());
            let transferred = transfer_evaluation
                .evaluate_states(&previous_states, &HashMap::default())
                .expect("the external transfer state is source-readable")
                .expect("the external transfer state is not cancelled");
            let external_state = &transferred[&external_target];
            assert_eq!(
                external_state.possible_values(),
                source_state.possible_values(),
                "an external outgoing edge of a productive component applies normally"
            );
            assert_incomplete_with_reason(external_state.completion(), external_rule_gap);
        }
    }

    #[test]
    fn wide_predecessor_closure_reads_and_recurses_in_bounded_batches() {
        let fixture = java_fixture();
        let cancellation = CancellationToken::new();
        let mut session = preloaded_session(&fixture.service, &cancellation);
        let owner = BindingFragmentId::hash_bytes(b"wide-predecessor-owner");
        let mut rows = (0_u32
            ..=u32::try_from(MAX_TYPED_FACT_REQUESTS_PER_BATCH)
                .expect("typed request bound fits u32"))
            .map(|ordinal| {
                selected_transfer(
                    owner,
                    SemanticId::hash_bytes(
                        [b"wide-rule".as_slice(), &ordinal.to_le_bytes()].concat(),
                    ),
                    SemanticId::hash_bytes(
                        [b"wide-source".as_slice(), &ordinal.to_le_bytes()].concat(),
                    ),
                    SemanticId::hash_bytes(
                        [b"wide-target".as_slice(), &ordinal.to_le_bytes()].concat(),
                    ),
                )
            })
            .collect::<Vec<_>>();
        rows.sort_by_key(SelectedTypedRow::<LoweredTypeTransfer>::target_access_order);
        let targets = rows
            .iter()
            .map(|row| row.row().rule().target_slot())
            .collect::<Vec<_>>();
        let mut reversed_targets = targets.clone();
        reversed_targets.reverse();
        let target_batches = RefCell::new(Vec::new());
        let returned_pages = RefCell::new(Vec::new());
        let incoming =
            read_session_transfers_to_with(&mut session, &reversed_targets, |request, visitor| {
                target_batches
                    .borrow_mut()
                    .push(request.as_slice().to_vec());
                let requested = request.as_slice().iter().copied().collect::<HashSet<_>>();
                let page = rows
                    .iter()
                    .filter(|row| requested.contains(&row.row().rule().target_slot()))
                    .cloned()
                    .collect::<Vec<_>>();
                assert_eq!(page.len(), request.len());
                for chunk in page.chunks(MAX_TYPED_FACT_REQUESTS_PER_BATCH / 2) {
                    returned_pages.borrow_mut().push(chunk.len());
                    assert!(visitor.visit_page(chunk)?);
                }
                Ok(TypedFactReadOutcome::exhausted(
                    ResolutionCompletion::Complete,
                ))
            })
            .expect("the complete high-fan-in relation is valid");
        let SessionFactRead::Exhausted {
            rows: incoming_rows,
            ..
        } = incoming
        else {
            panic!("a live high-fan-in relation cannot cancel")
        };
        assert_eq!(incoming_rows.len(), MAX_TYPED_FACT_REQUESTS_PER_BATCH + 1);
        let target_batches = target_batches.into_inner();
        assert_eq!(
            target_batches.iter().map(Vec::len).collect::<Vec<_>>(),
            [MAX_TYPED_FACT_REQUESTS_PER_BATCH, 1]
        );
        assert_eq!(
            target_batches.into_iter().flatten().collect::<Vec<_>>(),
            targets
        );
        assert_eq!(
            returned_pages.into_inner(),
            [
                MAX_TYPED_FACT_REQUESTS_PER_BATCH / 2,
                MAX_TYPED_FACT_REQUESTS_PER_BATCH / 2,
                1,
            ],
            "the session stages the full relation across multiple source pages before certifying it"
        );

        let mut predecessors = incoming_rows
            .iter()
            .map(|row| row.get(&session).row().source_slot())
            .collect::<Vec<_>>();
        predecessors.sort_unstable();
        predecessors.dedup();
        assert_eq!(predecessors.len(), MAX_TYPED_FACT_REQUESTS_PER_BATCH + 1);
        let requested_batches = RefCell::new(Vec::new());
        let mut reversed_predecessors = predecessors.clone();
        reversed_predecessors.reverse();
        let recursive = read_session_transfers_to_with(
            &mut session,
            &reversed_predecessors,
            |request, _visitor| {
                requested_batches
                    .borrow_mut()
                    .push(request.as_slice().to_vec());
                Ok(TypedFactReadOutcome::exhausted(
                    ResolutionCompletion::Complete,
                ))
            },
        )
        .expect("empty predecessor relations exhaust in bounded batches");
        assert!(matches!(recursive, SessionFactRead::Exhausted { .. }));
        let requested_batches = requested_batches.into_inner();
        assert_eq!(
            requested_batches.iter().map(Vec::len).collect::<Vec<_>>(),
            [MAX_TYPED_FACT_REQUESTS_PER_BATCH, 1]
        );
        assert!(
            requested_batches
                .iter()
                .all(|batch| batch.windows(2).all(|pair| pair[0] < pair[1]))
        );
        assert_eq!(
            requested_batches.into_iter().flatten().collect::<Vec<_>>(),
            predecessors
        );

        let incoming_edges = transfer_edges_for_session_rows(&session, &incoming_rows);
        let classification = classify_transfer_cycles(&incoming_edges, &mut || false)
            .expect("the high-fan-in acyclic closure classifies");
        assert!(classification.finite_slots.is_empty());
        assert!(classification.productive_slots.is_empty());
        let mut polls = 0_usize;
        let cancellation_poll = incoming_edges.len() + 8;
        assert!(
            classify_transfer_cycles(&incoming_edges, &mut || {
                polls += 1;
                polls == cancellation_poll
            })
            .is_none(),
            "cancellation during iterative SCC traversal publishes no classification"
        );
        assert_eq!(polls, cancellation_poll);
    }

    #[test]
    fn expand_demands_exhausts_every_wide_selected_predecessor_relation() {
        let mut fixture = java_fixture();
        let owner = BindingFragmentId::hash_bytes(b"wide-expanded-predecessor-owner");
        let mut targets = Vec::with_capacity(MAX_TYPED_FACT_REQUESTS_PER_BATCH + 1);
        let mut sources = Vec::with_capacity(MAX_TYPED_FACT_REQUESTS_PER_BATCH + 1);
        for ordinal in 0_u32
            ..=u32::try_from(MAX_TYPED_FACT_REQUESTS_PER_BATCH)
                .expect("typed request bound fits u32")
        {
            let source = SemanticId::hash_bytes(
                [b"wide-expanded-source".as_slice(), &ordinal.to_le_bytes()].concat(),
            );
            let target = SemanticId::hash_bytes(
                [b"wide-expanded-target".as_slice(), &ordinal.to_le_bytes()].concat(),
            );
            fixture.service.install_transfer_for_test(
                owner,
                LoweredTypeTransfer::new(
                    source,
                    ResolutionTypeTransferKind::Assignment,
                    TypeTransferRule::new(
                        SemanticId::hash_bytes(
                            [b"wide-expanded-rule".as_slice(), &ordinal.to_le_bytes()].concat(),
                        ),
                        target,
                        0,
                        TypeTransferValueTransform::Preserve,
                        ResolutionCompletion::Complete,
                    ),
                ),
            );
            sources.push(source);
            targets.push(target);
        }
        let cancellation = CancellationToken::new();
        let mut session = preloaded_session(&fixture.service, &cancellation);
        let mut hierarchy = HierarchyOperationArena::default();
        let mut evaluation =
            FactEvaluation::new(&mut session, &mut hierarchy, fixture.references[&8]);
        for &target in targets.iter().rev() {
            evaluation.demand_slot(target);
        }

        assert!(
            evaluation
                .expand_demands()
                .expect("the selected predecessor closure is source-readable")
        );
        assert!(evaluation.demands.is_empty());
        assert_eq!(
            evaluation.demanded_slots.len(),
            2 * (MAX_TYPED_FACT_REQUESTS_PER_BATCH + 1)
        );
        assert!(
            targets
                .iter()
                .chain(&sources)
                .all(|slot| evaluation.demanded_slots.contains(slot))
        );
        let cache = &session.cache;
        assert_eq!(
            cache.transfers_by_target.by_request.len(),
            2 * (MAX_TYPED_FACT_REQUESTS_PER_BATCH + 1),
            "the demand worklist must exhaust both the initial targets and every newly discovered predecessor target"
        );
        assert!(
            targets
                .iter()
                .chain(&sources)
                .all(|slot| cache.transfers_by_target.by_request.contains_key(slot))
        );
        assert!(
            cache.transfers_by_source.by_request.is_empty(),
            "forward demand closure must not proactively read the opposite relation"
        );
    }

    #[test]
    fn incoming_transfer_cancel_stop_and_error_install_no_cycle_certificate() {
        let fixture = java_fixture();
        let target = SemanticId::hash_bytes(b"closure-retry-target");
        let source = SemanticId::hash_bytes(b"closure-retry-source");
        let row = selected_transfer(
            BindingFragmentId::hash_bytes(b"closure-retry-owner"),
            SemanticId::hash_bytes(b"closure-retry-rule"),
            source,
            target,
        );
        let returned_gap = SemanticId::hash_bytes(b"closure-returned-cancelled-gap");
        let cancellation = CancellationToken::new();

        let mut cancelled_session = preloaded_session(&fixture.service, &cancellation);
        let cancelled =
            read_session_transfers_to_with(&mut cancelled_session, &[target], |_, visitor| {
                assert!(visitor.visit_page(std::slice::from_ref(&row))?);
                Ok(TypedFactReadOutcome::cancelled(incomplete(returned_gap)))
            })
            .expect("source-returned cancellation is semantic control flow");
        let SessionFactRead::Cancelled(evidence) = cancelled else {
            panic!("Cancelled cannot certify an incoming relation")
        };
        assert_incomplete_with_reason(&evidence, returned_gap);
        assert!(evidence.contains_reason(ResolutionIncompleteReason::Cancelled));
        assert!(
            cancelled_session
                .cache
                .transfers_by_target
                .by_request
                .is_empty()
        );
        let corrected =
            read_session_transfers_to_with(&mut cancelled_session, &[target], |_, visitor| {
                assert!(visitor.visit_page(std::slice::from_ref(&row))?);
                Ok(TypedFactReadOutcome::exhausted(
                    ResolutionCompletion::Complete,
                ))
            })
            .expect("a live same-session retry can exhaust the relation");
        let SessionFactRead::Exhausted { rows, .. } = corrected else {
            panic!("the corrected live retry cannot cancel")
        };
        let edges = transfer_edges_for_session_rows(&cancelled_session, &rows);
        assert!(classify_transfer_cycles(&edges, &mut || false).is_some());

        for terminal in [
            TypedFactReadTerminal::Stopped,
            TypedFactReadTerminal::Exhausted,
        ] {
            let mut session = preloaded_session(&fixture.service, &cancellation);
            let failed = read_session_transfers_to_with(&mut session, &[target], |_, visitor| {
                assert!(visitor.visit_page(std::slice::from_ref(&row))?);
                match terminal {
                    TypedFactReadTerminal::Stopped => Ok(TypedFactReadOutcome::stopped(
                        ResolutionCompletion::Complete,
                    )),
                    TypedFactReadTerminal::Exhausted => {
                        Err(StoreError::new("scripted incoming-transfer failure"))
                    }
                    TypedFactReadTerminal::Cancelled => unreachable!(),
                }
            });
            assert!(failed.is_err());
            assert!(
                session.cache.transfers_by_target.by_request.is_empty(),
                "a stopped or failed incoming read installs no relation"
            );
        }
    }

    #[test]
    fn selected_frontier_completion_is_applied_before_transfer_rules() {
        let mut fixture = java_fixture();
        let gap = SemanticId::hash_bytes(b"selected-transfer-frontier-completion-gap");
        for frontier in fixture.typed.frontiers() {
            fixture.service.set_frontier_completion_for_test(
                fragment(),
                frontier.slot(),
                incomplete(gap),
            );
        }
        let cancellation = CancellationToken::new();
        let answer = fixture
            .resolve_reference(fixture.references[&9], &cancellation)
            .expect("preload point reads are infallible");

        assert_incomplete_with_reason(answer.completion(), gap);
    }
    impl FactEvaluation<'_, '_> {
        fn cached_hierarchy_selection(
            &mut self,
            shape: HierarchyLookupShape,
            roots: &[HierarchyRoot],
        ) -> StoreResult<Option<HierarchySelectionState>> {
            let Some(selection) = self.cached_hierarchy_candidate_expressions(shape, roots)? else {
                return Ok(None);
            };
            Ok(Some(
                self.materialize_hierarchy_candidate_expressions(selection)?,
            ))
        }
    }
    #[test]
    fn point_selected_transfer_cancellation_retains_returned_completion() {
        let mut fixture = java_fixture();
        let transfer_gap = SemanticId::hash_bytes(b"fact-reverse-returned-transfer-gap");
        let cancelled_completion = ResolutionCompletion::incomplete([
            ResolutionIncompleteReason::Cancelled,
            ResolutionIncompleteReason::UnsupportedSemantic(transfer_gap),
        ]);
        for transfer in fixture.typed.transfers() {
            let rule = transfer.rule();
            fixture.service.replace_transfer_for_test(
                rule.semantic(),
                rule.indirection_delta(),
                rule.value_transform(),
                cancelled_completion.clone(),
            );
        }
        let cancellation = CancellationToken::new();

        let answer = fixture
            .resolve_reference(fixture.references[&9], &cancellation)
            .expect("preload point reads are infallible");

        assert!(answer.binding().targets().is_empty());
        assert!(answer.binding().witnesses().is_empty());
        assert_incomplete_with_reason(answer.completion(), transfer_gap);
        assert!(
            answer
                .completion()
                .contains_reason(ResolutionIncompleteReason::Cancelled)
        );
    }

    #[test]
    fn java_ambiguous_constructor_qualifier_preserves_each_nominal_runtime_value() {
        let mut facts = java_chain_facts();
        let second_type = facts
            .identifiers
            .iter_mut()
            .find(|identifier| {
                identifier.site == ResolutionSiteId::new(1)
                    && identifier.role == ResolutionIdentifierRole::Declaration
                    && identifier.namespace == ResolutionNamespace::Type
            })
            .expect("the synthetic Java fixture has a second type declaration");
        second_type.name = ResolutionNameId::new(0);
        facts.gaps.push(ResolutionGapFact {
            site: ResolutionSiteId::new(1),
            kind: ResolutionGapKind::ImplicitConstructor,
        });
        let fixture = java_fixture_from_facts(facts);
        let mut expected_types = vec![fixture.definitions[&0], fixture.definitions[&1]];
        expected_types.sort_unstable();

        let qualifier = fixture
            .resolve_reference(fixture.references[&17], &CancellationToken::new())
            .expect("the ambiguous constructor qualifier is source-readable");
        assert_eq!(qualifier.binding().targets(), expected_types);

        let constructor_reference = fixture.references[&18];
        let constructor = fixture
            .resolve_reference(constructor_reference, &CancellationToken::new())
            .expect("the explicitly and implicitly constructed types are source-readable");
        assert_eq!(constructor.binding().targets(), &[fixture.definitions[&6]]);
        let result_slot = fixture
            .typed
            .projections()
            .iter()
            .find(|projection| {
                projection.reference() == constructor_reference
                    && projection.kind() == BindingProjectionKind::TargetConstructorOwnerType
            })
            .expect("the constructor has one nominal result projection")
            .output_slot();
        let mut expected_values = expected_types
            .into_iter()
            .map(|definition| {
                ResolutionSlotValue::runtime(ResolutionTypeRef::new(definition, 0), false)
            })
            .collect::<Vec<_>>();
        expected_values.sort_unstable();
        assert_eq!(constructor.projected_frontiers().len(), 1);
        assert_eq!(
            constructor.projected_frontiers()[0].kind(),
            BindingProjectionKind::TargetConstructorOwnerType
        );
        assert_eq!(constructor.projected_frontiers()[0].slot(), result_slot);
        assert_eq!(
            constructor.projected_frontiers()[0].possible_values(),
            expected_values
        );

        let implicit_constructor_reason = fixture
            .typed
            .property_gaps()
            .iter()
            .find(|gap| {
                gap.definition() == fixture.definitions[&1]
                    && gap.kind() == ResolutionGapKind::ImplicitConstructor
            })
            .expect("the second ambiguous type owns its implicit-constructor evidence")
            .reason_semantic();
        assert_incomplete_with_reason(
            constructor.binding().completion(),
            implicit_constructor_reason,
        );
        assert_incomplete_with_reason(
            constructor.projected_frontiers()[0].completion(),
            implicit_constructor_reason,
        );
        assert_incomplete_with_reason(constructor.completion(), implicit_constructor_reason);
    }

    #[test]
    fn owned_hierarchy_batch_drains_witness_only_evidence_before_publication_and_cache_reuse() {
        let fixture = java_fixture();
        let reference = SemanticId::hash_bytes(b"owned-hierarchy-batch-raw-reference");
        let target = SemanticId::hash_bytes(b"owned-hierarchy-batch-raw-target");
        let support_identity = SemanticId::hash_bytes(b"owned-hierarchy-batch-support");
        let batch_reason = ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::hash_bytes(
            b"owned-hierarchy-batch-aggregate",
        ));
        let answer_reason = ResolutionIncompleteReason::UnsupportedSemantic(
            SemanticId::hash_bytes(b"owned-hierarchy-batch-answer"),
        );
        let witness_only_reason = ResolutionIncompleteReason::UnsupportedSemantic(
            SemanticId::hash_bytes(b"owned-hierarchy-batch-shadowed-witness-only"),
        );
        let batch_completion = ResolutionCompletion::incomplete([batch_reason]);
        let returned_answer = ResolutionAnswer::new(
            [target],
            [ResolutionWitness::new(
                reference,
                target,
                Vec::<WitnessStep>::new(),
                ResolutionCompletion::incomplete([witness_only_reason]),
            )],
            ResolutionCompletion::incomplete([answer_reason]),
        );
        let returned_answers = vec![(reference, returned_answer.clone())];

        let run = |checks: Option<usize>| {
            let cancellation = checks.map_or_else(
                CancellationToken::new,
                CancellationToken::cancel_after_checks_for_test,
            );
            let mut session = preloaded_session(&fixture.service, &cancellation);
            let mut hierarchy = HierarchyOperationArena::default();
            let mut evaluation = FactEvaluation::new(&mut session, &mut hierarchy, reference);
            let accepted = evaluation.accept_hierarchy_owned_reference_answers(
                support_identity,
                &batch_completion,
                &returned_answers,
            );
            let support = evaluation
                .hierarchy
                .cancellation_support_completions
                .get(&support_identity)
                .cloned();
            let evaluation_reasons = evaluation.cancellation_reasons.clone();
            let hierarchy_reasons = evaluation.hierarchy.cancellation_reasons.clone();
            let cached_reference_count = evaluation.hierarchy.reference_answers.len();
            let cancelled_answer = (!accepted).then(|| evaluation.cancelled_answer(None));
            (
                accepted,
                support,
                evaluation_reasons,
                hierarchy_reasons,
                cached_reference_count,
                cancelled_answer,
            )
        };

        let first_support_budget = (1..128)
            .find(|&checks| run(Some(checks)).1.is_some())
            .expect("one bounded check budget reaches the atomic support publication");
        assert!(
            first_support_budget > 1,
            "the adjacent cancelled budget exists after a returned batch is staged"
        );
        let cancelled = run(Some(first_support_budget - 1));
        assert!(!cancelled.0);
        assert!(cancelled.1.is_none());
        assert_eq!(cancelled.4, 0);
        for reason in [batch_reason, answer_reason, witness_only_reason] {
            assert!(cancelled.2.contains(&reason));
            assert!(cancelled.3.contains(&reason));
        }
        let expected_cancelled = ResolutionCompletion::incomplete([
            batch_reason,
            answer_reason,
            witness_only_reason,
            ResolutionIncompleteReason::Cancelled,
        ]);
        let cancelled_answer = cancelled
            .5
            .expect("the adjacent prepublication budget observes cancellation");
        assert!(cancelled_answer.binding().targets().is_empty());
        assert!(cancelled_answer.binding().witnesses().is_empty());
        assert!(cancelled_answer.projected_frontiers().is_empty());
        assert_eq!(cancelled_answer.binding().completion(), &expected_cancelled);
        assert_eq!(cancelled_answer.completion(), &expected_cancelled);

        let published = run(Some(first_support_budget));
        assert_eq!(published.1.as_ref(), Some(&batch_completion));
        for reason in [batch_reason, answer_reason, witness_only_reason] {
            assert!(published.2.contains(&reason));
            assert!(published.3.contains(&reason));
        }

        let live = run(None);
        assert!(live.0);
        assert_eq!(live.1.as_ref(), Some(&batch_completion));
        assert!(live.5.is_none());
        for reason in [batch_reason, answer_reason, witness_only_reason] {
            assert!(live.2.contains(&reason));
            assert!(live.3.contains(&reason));
        }

        // A later evaluation can reuse the immutable reference answer without
        // replaying its shadowed witness. The shared operation ledger must
        // still restore that witness-only raw reason on cancellation.
        let reuse_cancellation = CancellationToken::new();
        let mut reuse_session = preloaded_session(&fixture.service, &reuse_cancellation);
        let mut reuse_hierarchy = HierarchyOperationArena::default();
        let mut first = FactEvaluation::new(&mut reuse_session, &mut reuse_hierarchy, reference);
        assert!(first.accept_hierarchy_owned_reference_answers(
            support_identity,
            &batch_completion,
            &returned_answers,
        ));
        assert!(
            first
                .hierarchy
                .reference_answers
                .insert(reference, returned_answer)
                .is_none()
        );
        drop(first);
        let cached = reuse_hierarchy
            .reference_answers
            .get(&reference)
            .cloned()
            .expect("the later evaluation hits the immutable hierarchy reference cache");
        assert_eq!(&cached, &returned_answers[0].1);
        reuse_cancellation.cancel();
        let mut reused = FactEvaluation::new(&mut reuse_session, &mut reuse_hierarchy, reference);
        let reused_cancelled = reused.cancelled_answer(None);
        assert_eq!(reused_cancelled.binding().completion(), &expected_cancelled);
        assert_eq!(reused_cancelled.completion(), &expected_cancelled);
    }

    #[test]
    fn convergent_roots_keep_distinct_origins_but_one_suffix_evidence_atom() {
        let fixture = java_fixture();
        let cancellation = CancellationToken::new();
        let mut session = preloaded_session(&fixture.service, &cancellation);
        let mut hierarchy = HierarchyOperationArena::default();
        let mut evaluation =
            FactEvaluation::new(&mut session, &mut hierarchy, fixture.references[&8]);
        let shape = HierarchyLookupShape::new(
            SemanticId::hash_bytes(b"convergent-root-lookup"),
            ResolutionNamespace::Value,
            QualifierCategory::Runtime,
            0,
        );
        let roots = [
            SemanticId::hash_bytes(b"convergent-root-a"),
            SemanticId::hash_bytes(b"convergent-root-b"),
        ];
        let references = [
            SemanticId::hash_bytes(b"convergent-edge-a"),
            SemanticId::hash_bytes(b"convergent-edge-b"),
        ];
        let shared = SemanticId::hash_bytes(b"convergent-shared-owner");
        let first = ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::hash_bytes(
            b"convergent-suffix-first",
        ));
        let second = ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::hash_bytes(
            b"convergent-suffix-second",
        ));
        let suffix_completion =
            ResolutionCompletion::Incomplete(vec![second, first, second].into_boxed_slice().into());
        {
            let hierarchy = &mut *evaluation.hierarchy;
            let suffix = hierarchy
                .evidence
                .one(
                    SemanticId::hash_bytes(b"convergent-shared-suffix-atom"),
                    suffix_completion.clone(),
                    &mut || false,
                )
                .expect("atom construction is uncancelled");
            let here = hierarchy.candidates.here(shared);
            let generation = hierarchy.begin_publication();
            for ordinal in 0..2 {
                let candidate = hierarchy.candidates.via(references[ordinal], shared, here);
                let evidence = hierarchy.evidence.shift(suffix.clone(), 2);
                hierarchy.stage_summary(
                    generation,
                    HierarchyNodeKey {
                        shape,
                        owner: roots[ordinal],
                    },
                    HierarchyStructuralSummary {
                        candidate_distance: Some(1),
                        candidates: Some(candidate),
                        evidence,
                        transfer: HierarchyEvidence::Complete,
                        retains_global_evidence: true,
                    },
                );
            }
            hierarchy.commit_publication(generation);
        }
        let root_values = [
            HierarchyRoot {
                owner: roots[0],
                value: ResolutionSlotValue::runtime(ResolutionTypeRef::new(roots[0], 0), false),
                route_ordinal: 0,
            },
            HierarchyRoot {
                owner: roots[1],
                value: ResolutionSlotValue::runtime(ResolutionTypeRef::new(roots[1], 0), false),
                route_ordinal: 1,
            },
        ];
        let selection = match evaluation
            .cached_hierarchy_selection(shape, &root_values)
            .expect("cached hierarchy selection is infallible")
            .expect("both root summaries are cached")
        {
            HierarchySelectionState::Pending => panic!("uncancelled selection cannot be pending"),
            HierarchySelectionState::Ready(selection) => selection,
        };
        assert_eq!(selection.owners.len(), 2);
        assert!(selection.owners.iter().all(|owner| owner.owner == shared));
        assert_ne!(selection.owners[0].root, selection.owners[1].root);
        assert_ne!(selection.owners[0].ancestry, selection.owners[1].ancestry);
        assert_eq!(
            evaluation
                .hierarchy
                .evidence
                .flatten(&selection.evidence, u32::MAX, &mut || false)
                .expect("flatten is uncancelled"),
            suffix_completion
        );
    }

    #[test]
    fn applicability_discharge_preserves_cancellation() {
        let applicability = SemanticId::hash_bytes(b"pending-call-applicability");
        let completion = ResolutionCompletion::incomplete([
            ResolutionIncompleteReason::UnsupportedSemantic(applicability),
            ResolutionIncompleteReason::Cancelled,
        ]);
        assert_eq!(
            completion_without_unsupported_semantic(&completion, applicability),
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::Cancelled])
        );
    }

    #[test]
    fn hierarchy_cancellation_evidence_is_invariant_to_owner_insertion_order() {
        let identities = [
            SemanticId::hash_bytes(b"hierarchy-owner-order-a"),
            SemanticId::hash_bytes(b"hierarchy-owner-order-b"),
        ];
        let completions = [
            incomplete(SemanticId::hash_bytes(b"hierarchy-owner-order-gap-a")),
            incomplete(SemanticId::hash_bytes(b"hierarchy-owner-order-gap-b")),
        ];
        let evaluate = |reversed: bool, cancel_after: usize| {
            let mut arena = HierarchyEvidenceArena::default();
            let mut operands = Vec::new();
            for ordinal in if reversed { [1, 0] } else { [0, 1] } {
                operands.push(
                    arena
                        .one(
                            identities[ordinal],
                            completions[ordinal].clone(),
                            &mut || false,
                        )
                        .expect("atom construction is uncancelled"),
                );
            }
            let evidence = arena.union(operands.remove(0), operands.remove(0));
            let mut polls = 0_usize;
            arena.flatten(&evidence, u32::MAX, &mut || {
                polls += 1;
                polls == cancel_after
            })
        };

        for cancel_after in 1..=12 {
            assert_eq!(
                evaluate(false, cancel_after),
                evaluate(true, cancel_after),
                "canonical evidence traversal changed at cancellation poll {cancel_after}"
            );
        }
    }

    #[test]
    fn repeated_point_reads_match_fresh_sessions_in_both_orders() {
        let fixture = java_fixture();
        let references = [
            fixture.references[&8],
            fixture.references[&9],
            fixture.references[&11],
            fixture.references[&18],
        ];
        let expected = references.map(|reference| {
            fixture
                .resolve_reference(reference, &CancellationToken::new())
                .expect("fresh point read")
        });
        for order in [[0, 1, 2, 3, 0, 3], [3, 2, 1, 0, 3, 0]] {
            let cancellation = CancellationToken::new();
            let mut session = FactReadSession::new(&fixture.service, &cancellation);
            for ordinal in order {
                assert_eq!(
                    session
                        .resolve_reference(references[ordinal])
                        .expect("reused point read"),
                    expected[ordinal]
                );
            }
        }
    }
}
