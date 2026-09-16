//! Bounded, file-major stitching over immutable fragment rows.
//!
//! This module is the batch seam for the preload checkpoint. Candidate
//! matching and path hydration are intentionally separate: a source first
//! returns globally keyed rows, then the engine hydrates each distinct path at
//! most once into an operation-local arena. The arena dies with the batch; it
//! is neither a workspace snapshot nor a cache.

use std::collections::{BTreeMap, BTreeSet};

use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::resolution_facts::{
    ResolutionCallableReceiverOrigin, ResolutionNamespace, ResolutionSiteId, ResolutionSiteKind,
};
use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

use crate::CancellationToken;
use crate::analyzer::store::{Result as StoreResult, StoreError};
use crate::hash::{HashMap, HashSet, map_with_capacity};

use super::engine::{
    CANCELLATION_QUANTUM, CompletedPath, IncompleteTerminalPath, ResolutionQuery,
    cancelled_completion, child_derivation, endpoint_is_balanced, identity_path,
    select_paths_with_cancellation_evidence,
};
use super::model::{
    AlphaRenamingId, BindingFragmentId, BindingNodeId, EndpointSignature, PartialPath,
    PartialPathId, ResolutionAnswer, ResolutionCompletion, ResolutionIncompleteReason, SemanticId,
    TypeTransferRule, clone_completion_with_poll, combine_completion_with_poll,
    completion_values_equal_with_poll,
};
use super::saturation::{CycleCompletenessCertifier, SaturationBranch, SaturationDecision};

/// Hard upper bound on reference seeds sharing one operation-local arena.
pub const MAX_REFERENCE_SEEDS_PER_BATCH: usize = 256;

/// Hard upper bound on definition seeds sharing one raw reverse traversal.
///
/// The fact-aware reverse executor uses a target batch only as an
/// operation-local narrowing step. Keeping the relation bounded makes the
/// later SQL shape explicit and prevents a selected workspace from becoming
/// one unbounded request rowset.
pub(crate) const MAX_REVERSE_TARGETS_PER_BATCH: usize = 64;

/// Hard upper bound on one immutable candidate-source relation read.
///
/// A reverse target batch bounds semantic roots, not the number of paths in a
/// worklist level. Classifications, candidate matches, and hydrations are
/// therefore paged independently so a high-fanout level cannot become one
/// unbounded source request.
pub(crate) const MAX_SOURCE_ROWS_PER_BATCH: usize = MAX_REFERENCE_SEEDS_PER_BATCH;

/// Stable candidate key used across match and hydration phases.
///
/// `PartialPathId` is producer-global today. Retaining the owning fragment in
/// this identity makes the file-major access pattern explicit and prevents a
/// future SQL row number from becoming part of the semantic identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CandidatePathIdentity {
    fragment: BindingFragmentId,
    path: PartialPathId,
}

impl CandidatePathIdentity {
    pub const fn new(fragment: BindingFragmentId, path: PartialPathId) -> Self {
        Self { fragment, path }
    }

    pub const fn fragment(self) -> BindingFragmentId {
        self.fragment
    }

    pub const fn path(self) -> PartialPathId {
        self.path
    }
}

/// Immutable source-local identity and syntax for one reference occurrence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FactReferenceSiteMetadata {
    site: ResolutionSiteId,
    namespace: ResolutionNamespace,
    site_kind: ResolutionSiteKind,
    start_byte: usize,
    end_byte: usize,
    unqualified: bool,
    reference_owner: Option<Option<SemanticId>>,
    callable_receiver_origin: Option<ResolutionCallableReceiverOrigin>,
}

impl FactReferenceSiteMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        site: ResolutionSiteId,
        namespace: ResolutionNamespace,
        site_kind: ResolutionSiteKind,
        start_byte: usize,
        end_byte: usize,
        unqualified: bool,
        reference_owner: Option<Option<SemanticId>>,
        callable_receiver_origin: Option<ResolutionCallableReceiverOrigin>,
    ) -> Self {
        assert!(
            start_byte <= end_byte,
            "reference site range must be ordered"
        );
        assert!(
            callable_receiver_origin.is_none() || namespace == ResolutionNamespace::Callable,
            "callable receiver origin requires the callable namespace"
        );
        assert!(
            callable_receiver_origin.is_none()
                || matches!(
                    site_kind,
                    ResolutionSiteKind::CallableReference | ResolutionSiteKind::MemberReference
                ),
            "callable receiver origin requires a terminal callable reference site"
        );
        assert!(
            callable_receiver_origin.is_none_or(|origin| {
                unqualified == (origin == ResolutionCallableReceiverOrigin::Implicit)
            }),
            "only an implicit callable receiver may be unqualified"
        );
        Self {
            site,
            namespace,
            site_kind,
            start_byte,
            end_byte,
            unqualified,
            reference_owner,
            callable_receiver_origin,
        }
    }

    pub const fn site(self) -> ResolutionSiteId {
        self.site
    }

    pub const fn namespace(self) -> ResolutionNamespace {
        self.namespace
    }

    pub const fn site_kind(self) -> ResolutionSiteKind {
        self.site_kind
    }

    pub const fn start_byte(self) -> usize {
        self.start_byte
    }

    pub const fn end_byte(self) -> usize {
        self.end_byte
    }

    pub const fn unqualified(self) -> bool {
        self.unqualified
    }

    /// The source declaration containing this reference occurrence.
    ///
    /// `None` means the producer did not publish ownership. `Some(None)`
    /// explicitly names the file root, while `Some(Some(_))` names the
    /// containing declaration.
    pub const fn reference_owner(self) -> Option<Option<SemanticId>> {
        self.reference_owner
    }

    pub const fn callable_receiver_origin(self) -> Option<ResolutionCallableReceiverOrigin> {
        self.callable_receiver_origin
    }
}

/// One reference and the already-enumerated node that starts its path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceSeed {
    fragment: BindingFragmentId,
    query: ResolutionQuery,
    node: BindingNodeId,
    site_metadata: Option<FactReferenceSiteMetadata>,
    completion: ResolutionCompletion,
}

/// One exact forward seed lookup result for a caller-owned query ordinal.
///
/// `None` is selected-context negative evidence only when the enclosing
/// [`ReferenceSeedReadOutcome`] is exhausted. Keeping the query beside the
/// optional seed lets the caller validate the full request/result bijection
/// before it groups affirmative seeds by their owning fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchReferenceSeed {
    request_ordinal: usize,
    query: ResolutionQuery,
    seed: Option<ReferenceSeed>,
}

impl BatchReferenceSeed {
    pub fn new(
        request_ordinal: usize,
        query: ResolutionQuery,
        seed: Option<ReferenceSeed>,
    ) -> Self {
        if let Some(seed) = &seed {
            assert_eq!(
                seed.query(),
                query,
                "a batch reference seed must answer its exact input query"
            );
        }
        Self {
            request_ordinal,
            query,
            seed,
        }
    }

    pub const fn request_ordinal(&self) -> usize {
        self.request_ordinal
    }

    pub const fn query(&self) -> ResolutionQuery {
        self.query
    }

    pub const fn seed(&self) -> Option<&ReferenceSeed> {
        self.seed.as_ref()
    }

    pub fn into_seed(self) -> Option<ReferenceSeed> {
        self.seed
    }
}

/// Whether one bounded plural forward-seed read proved its full relation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceSeedReadTerminal {
    /// Every input query has exactly one affirmative or absent outcome.
    Exhausted,
    /// Cancellation won before atomic publication; no outcome row is usable.
    Cancelled,
}

/// Atomic result of one bounded plural forward-seed read.
///
/// On success, `rows` is the exact input-ordinal bijection and each affirmative
/// row owns its semantic completion. The aggregate evidence is therefore
/// neutral. On cancellation, `rows` is empty and `evidence` retains every
/// fully decoded source completion (or decoded child prefix) without adding a
/// second `Cancelled` operand. The explicit terminal carries that operational
/// fact, and the evaluator adds its ordinary cancellation reason once at its
/// publication boundary. This preserves a sole source completion box exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceSeedReadOutcome {
    rows: Box<[BatchReferenceSeed]>,
    terminal: ReferenceSeedReadTerminal,
    evidence: ResolutionCompletion,
}

impl ReferenceSeedReadOutcome {
    pub fn exhausted(rows: impl Into<Box<[BatchReferenceSeed]>>) -> Self {
        let rows = rows.into();
        for (request_ordinal, row) in rows.iter().enumerate() {
            assert_eq!(
                row.request_ordinal, request_ordinal,
                "exhausted reference seed rows must preserve every input ordinal"
            );
        }
        Self {
            rows,
            terminal: ReferenceSeedReadTerminal::Exhausted,
            evidence: ResolutionCompletion::Complete,
        }
    }

    pub fn cancelled(evidence: ResolutionCompletion) -> Self {
        Self {
            rows: Box::new([]),
            terminal: ReferenceSeedReadTerminal::Cancelled,
            evidence,
        }
    }

    pub fn rows(&self) -> &[BatchReferenceSeed] {
        &self.rows
    }

    pub const fn terminal(&self) -> ReferenceSeedReadTerminal {
        self.terminal
    }

    pub const fn evidence(&self) -> &ResolutionCompletion {
        &self.evidence
    }

    pub const fn is_exhausted(&self) -> bool {
        matches!(self.terminal, ReferenceSeedReadTerminal::Exhausted)
    }

    pub const fn is_cancelled(&self) -> bool {
        matches!(self.terminal, ReferenceSeedReadTerminal::Cancelled)
    }

    pub fn into_parts(
        self,
    ) -> (
        Box<[BatchReferenceSeed]>,
        ReferenceSeedReadTerminal,
        ResolutionCompletion,
    ) {
        (self.rows, self.terminal, self.evidence)
    }
}

impl ReferenceSeed {
    pub const fn new(
        fragment: BindingFragmentId,
        query: ResolutionQuery,
        node: BindingNodeId,
        completion: ResolutionCompletion,
    ) -> Self {
        Self::new_with_site_metadata(fragment, query, node, None, completion)
    }

    pub(crate) const fn new_with_site_metadata(
        fragment: BindingFragmentId,
        query: ResolutionQuery,
        node: BindingNodeId,
        site_metadata: Option<FactReferenceSiteMetadata>,
        completion: ResolutionCompletion,
    ) -> Self {
        Self {
            fragment,
            query,
            node,
            site_metadata,
            completion,
        }
    }

    pub const fn fragment(&self) -> BindingFragmentId {
        self.fragment
    }

    pub const fn query(&self) -> ResolutionQuery {
        self.query
    }

    pub const fn reference(&self) -> SemanticId {
        self.query.reference()
    }

    pub const fn node(&self) -> BindingNodeId {
        self.node
    }

    pub const fn site_metadata(&self) -> Option<FactReferenceSiteMetadata> {
        self.site_metadata
    }

    /// The source declaration containing this reference occurrence.
    ///
    /// The outer option is `None` when the producer did not publish source
    /// ownership. `Some(None)` explicitly means the reference is outside any
    /// declaration, while `Some(Some(_))` names its containing definition.
    pub const fn reference_owner(&self) -> Option<Option<SemanticId>> {
        match self.site_metadata {
            Some(metadata) => metadata.reference_owner(),
            None => None,
        }
    }

    /// The source-syntax route that supplied a callable receiver.
    ///
    /// `None` means the producer did not publish receiver-origin metadata or
    /// this occurrence is not a callable reference. The origin is descriptive
    /// syntax only; selected binding and type facts determine whether an
    /// explicit expression denotes a type or a runtime value.
    pub const fn callable_receiver_origin(&self) -> Option<ResolutionCallableReceiverOrigin> {
        match self.site_metadata {
            Some(metadata) => metadata.callable_receiver_origin(),
            None => None,
        }
    }

    pub const fn completion(&self) -> &ResolutionCompletion {
        &self.completion
    }

    pub(super) fn clone_with_poll<P>(&self, cancelled: &mut P) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        Some(Self {
            fragment: self.fragment,
            query: self.query,
            node: self.node,
            site_metadata: self.site_metadata,
            completion: clone_completion_with_poll(&self.completion, cancelled)?,
        })
    }
}

/// One operation-local starting path for qualified or member lookup.
///
/// The identity is a stable semantic derivation key supplied by the caller.
/// It is never looked up in, hydrated from, or persisted to the fragment
/// source. Distinct alternatives need distinct identities; reusing an
/// identity is accepted only when it names the same canonical path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeededPartialPath {
    identity: PartialPathId,
    path: PartialPath,
}

impl SeededPartialPath {
    /// Canonicalize one caller-supplied starting path, stopping atomically on cancellation.
    pub fn new(
        identity: PartialPathId,
        path: PartialPath,
        cancellation: &CancellationToken,
    ) -> Option<Self> {
        Self::new_with_poll(identity, path, &mut || cancellation.is_cancelled())
    }

    pub(crate) fn new_with_poll<P>(
        identity: PartialPathId,
        path: PartialPath,
        cancelled: &mut P,
    ) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        Some(Self {
            identity,
            path: path.canonicalized_observations_with_poll(cancelled)?,
        })
    }

    pub const fn identity(&self) -> PartialPathId {
        self.identity
    }

    pub const fn path(&self) -> &PartialPath {
        &self.path
    }
}

/// One source-issued reference plus all transient starting alternatives.
///
/// Construction closes the semantic contract before the engine sees the
/// request: every alternative begins at the source-issued reference node with
/// balanced stacks, and every path carries both its own and the source seed's
/// completeness evidence. Input order and repeated identical rows cannot
/// affect stitching order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeededReferenceRequest {
    seed: ReferenceSeed,
    alternatives: Box<[SeededPartialPath]>,
}

impl SeededReferenceRequest {
    /// Validate and canonicalize all alternatives for a source-issued seed.
    /// Cancellation returns no partially constructed request.
    pub fn new(
        seed: ReferenceSeed,
        alternatives: impl IntoIterator<Item = SeededPartialPath>,
        cancellation: &CancellationToken,
    ) -> Option<Self> {
        Self::new_with_poll(seed, alternatives, &mut || cancellation.is_cancelled())
    }

    pub(crate) fn new_with_poll<P>(
        seed: ReferenceSeed,
        alternatives: impl IntoIterator<Item = SeededPartialPath>,
        cancelled: &mut P,
    ) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        let mut canonical = BTreeMap::<PartialPathId, SeededPartialPath>::new();
        let mut alternative_count = 0_usize;
        for mut alternative in alternatives {
            if cancelled() {
                return None;
            }
            alternative_count = alternative_count
                .checked_add(1)
                .expect("seeded alternative count must fit usize");
            assert_eq!(
                alternative.path().start().node(),
                seed.node(),
                "seeded path {} starts at {}, not source-issued reference node {}: {:?}",
                alternative.identity(),
                alternative.path().start().node(),
                seed.node(),
                alternative.path()
            );
            assert!(
                endpoint_is_balanced(alternative.path().start()),
                "seeded path {} must start with balanced stacks: {:?}",
                alternative.identity(),
                alternative.path().start()
            );
            alternative.path = alternative
                .path
                .with_seed_completion_with_poll(seed.completion(), cancelled)?;
            if let Some(existing) = canonical.get(&alternative.identity()) {
                let equal = existing
                    .path()
                    .equals_with_poll(alternative.path(), cancelled)?;
                assert!(
                    equal,
                    "seeded path identity {} names conflicting canonical paths: {:?} and {:?}",
                    alternative.identity(),
                    existing,
                    alternative
                );
            } else {
                canonical.insert(alternative.identity(), alternative);
            }
        }
        assert!(
            alternative_count > 0,
            "a seeded reference request requires at least one alternative"
        );
        let mut alternatives = Vec::with_capacity(canonical.len());
        while let Some((_, alternative)) = canonical.pop_first() {
            if cancelled() {
                return None;
            }
            alternatives.push(alternative);
        }
        Some(Self {
            seed,
            alternatives: alternatives.into_boxed_slice(),
        })
    }

    fn identity_with_poll<P>(seed: ReferenceSeed, cancelled: &mut P) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        let path_id = identity_seed_path_id(&seed);
        let path = identity_path(seed.node());
        let path = SeededPartialPath::new_with_poll(path_id, path, cancelled)?;
        Self::new_with_poll(seed, [path], cancelled)
    }

    pub const fn seed(&self) -> &ReferenceSeed {
        &self.seed
    }

    pub fn alternatives(&self) -> &[SeededPartialPath] {
        &self.alternatives
    }
}

/// A reverse-classified reference whose source-issued seed must be recovered.
///
/// Reverse stitching may discover a reference semantic through more than one
/// path. The engine deduplicates those discoveries before constructing this
/// request. Its fields and constructor stay resolution-private so callers
/// cannot use this seam to forge a seed; a fragment source must verify the
/// semantic and expected endpoint against its selected immutable facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReverseReferenceSeedRequest {
    reference: SemanticId,
    expected_node: BindingNodeId,
}

impl ReverseReferenceSeedRequest {
    pub(crate) const fn reference(self) -> SemanticId {
        self.reference
    }

    pub(crate) const fn expected_node(self) -> BindingNodeId {
        self.expected_node
    }
}

/// One bounded set of references owned by the same source fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceSeedBatch {
    fragment: BindingFragmentId,
    seeds: Box<[ReferenceSeed]>,
}

impl ReferenceSeedBatch {
    pub fn new(seeds: impl IntoIterator<Item = ReferenceSeed>) -> Self {
        Self::new_observing(seeds, || {})
    }

    pub(super) fn new_observing(
        seeds: impl IntoIterator<Item = ReferenceSeed>,
        mut observe: impl FnMut(),
    ) -> Self {
        let mut canonical = BTreeMap::new();
        let mut fragment = None;
        let mut count = 0_usize;
        for seed in seeds {
            observe();
            count = count
                .checked_add(1)
                .expect("reference seed count must fit usize");
            assert!(
                count <= MAX_REFERENCE_SEEDS_PER_BATCH,
                "reference seed batch has {count} entries; maximum is {MAX_REFERENCE_SEEDS_PER_BATCH}"
            );
            let owner = *fragment.get_or_insert(seed.fragment());
            assert_eq!(
                seed.fragment(),
                owner,
                "a reference seed batch must have one owning fragment"
            );
            let reference = seed.reference();
            assert!(
                canonical.insert(reference, seed).is_none(),
                "a reference seed batch cannot contain duplicate semantic {reference:?}"
            );
        }
        let fragment = fragment.expect("a reference seed batch cannot be empty");
        let mut seeds = Vec::with_capacity(canonical.len());
        while let Some((_, seed)) = canonical.pop_first() {
            observe();
            seeds.push(seed);
        }
        Self {
            fragment,
            seeds: seeds.into_boxed_slice(),
        }
    }

    pub const fn fragment(&self) -> BindingFragmentId {
        self.fragment
    }

    pub fn seeds(&self) -> &[ReferenceSeed] {
        &self.seeds
    }

    pub fn len(&self) -> usize {
        self.seeds.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seeds.is_empty()
    }
}

/// Endpoint lookup associated with one worklist state in the current level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchCandidateRequest {
    request_ordinal: usize,
    endpoint: EndpointSignature,
}

impl BatchCandidateRequest {
    pub fn new(request_ordinal: usize, endpoint: EndpointSignature) -> Self {
        Self {
            request_ordinal,
            endpoint,
        }
    }

    pub const fn request_ordinal(&self) -> usize {
        self.request_ordinal
    }

    pub const fn endpoint(&self) -> &EndpointSignature {
        &self.endpoint
    }
}

/// A sound coarse match. Exact stack unification remains in Rust composition.
///
/// `request_ordinal` associates the row with one batch request; `candidate` is
/// its duplicate/conflict identity. Bounded sources may emit these rows in a
/// deterministic storage-cursor order unrelated to either opaque mounted ID.
/// Consumers restore canonical `(request_ordinal, candidate)` order only after
/// the source has exhausted the relation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BatchCandidateMatch {
    candidate: CandidatePathIdentity,
    request_ordinal: usize,
}

/// Candidate rows plus unconditional operation evidence and branch-local
/// semantic coverage for each requested endpoint.
///
/// Operational read/decode failures remain [`StoreError`]. A semantic gap is
/// represented here even when the matching row set is empty. Source-wide and
/// direction-inventory evidence is unconditional; endpoint/keyed gaps describe
/// an omitted branch that may still lose to a higher-precedence affirmative.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchCandidateOutcome {
    matches: Vec<BatchCandidateMatch>,
    unconditional_completion: ResolutionCompletion,
    branch_completions: Box<[ResolutionCompletion]>,
}

/// Coverage returned once after a bounded stream of candidate-match pages.
///
/// Match pages own only affirmative rows. This value owns the complete
/// operation-wide and request-local semantic coverage even when cancellation
/// or a visitor returning `false` stops row emission early. A source must not
/// truncate these boxes to the emitted row prefix. When the engine divides one
/// logical direction operation across several request pages or worklist
/// rounds, every live call must repeat the exact same unconditional box. That
/// box contributes once to each seed/target answer that issued any candidate
/// request, never once per request state; branch boxes remain state-local.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchCandidateCompletionOutcome {
    unconditional_completion: ResolutionCompletion,
    branch_completions: Box<[ResolutionCompletion]>,
}

impl BatchCandidateCompletionOutcome {
    pub fn new(
        request_count: usize,
        unconditional_completion: ResolutionCompletion,
        branch_completions: impl IntoIterator<Item = ResolutionCompletion>,
    ) -> Self {
        Self::new_observing(
            request_count,
            unconditional_completion,
            branch_completions,
            || {},
        )
    }

    pub(super) fn new_observing(
        request_count: usize,
        unconditional_completion: ResolutionCompletion,
        branch_completions: impl IntoIterator<Item = ResolutionCompletion>,
        mut observe: impl FnMut(),
    ) -> Self {
        let mut canonical_branches = Vec::with_capacity(request_count);
        for completion in branch_completions {
            observe();
            if let ResolutionCompletion::Incomplete(reasons) = &completion {
                for &reason in reasons.iter() {
                    observe();
                    assert_ne!(
                        reason,
                        ResolutionIncompleteReason::Cancelled,
                        "candidate cancellation is unconditional operation evidence"
                    );
                }
            }
            canonical_branches.push(completion);
        }
        assert_eq!(
            canonical_branches.len(),
            request_count,
            "candidate outcome branch-completion count must equal request count"
        );
        Self {
            unconditional_completion,
            branch_completions: canonical_branches.into_boxed_slice(),
        }
    }

    pub fn unconditional_completion(&self) -> &ResolutionCompletion {
        &self.unconditional_completion
    }

    pub fn branch_completions(&self) -> &[ResolutionCompletion] {
        &self.branch_completions
    }

    pub(super) fn into_parts(self) -> (ResolutionCompletion, Box<[ResolutionCompletion]>) {
        (self.unconditional_completion, self.branch_completions)
    }
}

/// Exact natural identity of one persisted reverse-candidate coverage gap.
///
/// The fragment remains part of the public identity even though current gap
/// digests include it. Persistent stores key the row by both columns, and an
/// operation must not use a gap selected from one fragment to suppress a row
/// owned by another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReverseCandidateGapIdentity {
    fragment: BindingFragmentId,
    gap_id: SemanticId,
}

impl ReverseCandidateGapIdentity {
    pub const fn new(fragment: BindingFragmentId, gap_id: SemanticId) -> Self {
        Self { fragment, gap_id }
    }

    pub const fn fragment(self) -> BindingFragmentId {
        self.fragment
    }

    pub const fn gap_id(self) -> SemanticId {
        self.gap_id
    }
}

/// One exact operation-local set of reverse-candidate gaps transferred to a
/// richer semantic overlay.
///
/// Preparation is lazy because a persistent source may not have decoded its
/// sparse reverse coverage yet. Once prepared, the plan is bound to the exact
/// canonical raw-coverage fingerprint. The plan intentionally is not Clone:
/// one top-level operation owns and reuses one instance across all of its
/// bounded raw reverse batches.
#[derive(Debug)]
pub struct ReverseCandidateGapExclusionPlan {
    identities: Box<[ReverseCandidateGapIdentity]>,
    prepared: Option<PreparedReverseCandidateGapExclusions>,
}

impl ReverseCandidateGapExclusionPlan {
    pub fn new(identities: impl IntoIterator<Item = ReverseCandidateGapIdentity>) -> Self {
        Self {
            // Collection owns no semantic interpretation. Canonicalization,
            // deduplication, and validation happen under the operation token
            // in `prepare_for` before any prepared state is published.
            identities: identities.into_iter().collect(),
            prepared: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.identities.is_empty()
    }

    fn prepare_for(
        &mut self,
        coverage: &ReverseCandidateGapCoverage,
        cancellation: &CancellationToken,
    ) -> StoreResult<bool> {
        assert!(
            !self.identities.is_empty(),
            "an empty reverse-gap plan delegates to the raw source"
        );
        if let Some(prepared) = &self.prepared {
            if prepared.raw_fingerprint != coverage.fingerprint {
                return Err(StoreError::new(
                    "reverse candidate gap exclusion plan was prepared for different raw coverage",
                ));
            }
            return Ok(true);
        }
        if cancellation.is_cancelled() {
            return Ok(false);
        }

        let mut canonical_identities = BTreeSet::new();
        for &identity in self.identities.iter() {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            canonical_identities.insert(identity);
        }

        let mut inventory = ReverseCandidateReasonDecrements::default();
        let mut endpoints: HashMap<BindingNodeId, ReverseCandidateEndpointReasonDecrements> =
            map_with_capacity(canonical_identities.len());
        for identity in canonical_identities {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            let contribution = coverage.by_identity.get(&identity).ok_or_else(|| {
                StoreError::new(format!(
                    "selected reverse candidate coverage has no exact gap ({}, {})",
                    identity.fragment(),
                    identity.gap_id()
                ))
            })?;
            match contribution.location {
                ReverseCandidateGapLocation::Inventory => {
                    inventory.push(contribution.reason);
                }
                ReverseCandidateGapLocation::Endpoint { endpoint, lookup } => {
                    endpoints
                        .entry(endpoint)
                        .or_default()
                        .push(lookup, contribution.reason);
                }
            }
        }

        let filtered_inventory = if inventory.is_empty() {
            None
        } else {
            let Some(completion) = coverage
                .inventory
                .completion_after_excluding(&inventory.counts, cancellation)?
            else {
                return Ok(false);
            };
            Some(completion)
        };
        let mut filtered_endpoints = map_with_capacity(endpoints.len());
        for (endpoint, decrements) in endpoints {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            let raw = coverage.endpoints.get(&endpoint).unwrap_or_else(|| {
                panic!("an indexed reverse gap contribution must have its endpoint bucket")
            });
            let Some(filtered) = raw.completion_after_excluding(decrements, cancellation)? else {
                return Ok(false);
            };
            assert!(
                filtered_endpoints.insert(endpoint, filtered).is_none(),
                "one reverse endpoint exclusion overlay is prepared once"
            );
        }
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        let prepared = PreparedReverseCandidateGapExclusions {
            raw_fingerprint: coverage.fingerprint,
            inventory: filtered_inventory,
            endpoints: filtered_endpoints,
        };
        self.prepared = Some(prepared);
        Ok(true)
    }

    fn prepared_for<'plan>(
        &'plan self,
        coverage: &ReverseCandidateGapCoverage,
    ) -> StoreResult<&'plan PreparedReverseCandidateGapExclusions> {
        let prepared = self
            .prepared
            .as_ref()
            .expect("a reverse-gap plan is read only after successful preparation");
        if prepared.raw_fingerprint != coverage.fingerprint {
            return Err(StoreError::new(
                "reverse candidate gap exclusion plan was prepared for different raw coverage",
            ));
        }
        Ok(prepared)
    }
}

impl Default for ReverseCandidateGapExclusionPlan {
    fn default() -> Self {
        Self::new([])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReverseCandidateGapLocation {
    Inventory,
    Endpoint {
        endpoint: BindingNodeId,
        lookup: Option<SemanticId>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReverseCandidateGapRow {
    identity: ReverseCandidateGapIdentity,
    location: ReverseCandidateGapLocation,
    reason: ResolutionIncompleteReason,
}

impl ReverseCandidateGapRow {
    pub(crate) const fn new(
        identity: ReverseCandidateGapIdentity,
        location: ReverseCandidateGapLocation,
        reason: ResolutionIncompleteReason,
    ) -> Self {
        Self {
            identity,
            location,
            reason,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReverseCandidateGapCoverageFingerprint([u8; 32]);

#[derive(Debug, Clone, Copy)]
struct ReverseCandidateGapContribution {
    location: ReverseCandidateGapLocation,
    reason: ResolutionIncompleteReason,
}

#[derive(Debug, Clone)]
pub(crate) struct ReverseCandidateGapCoverage {
    fingerprint: ReverseCandidateGapCoverageFingerprint,
    by_identity: HashMap<ReverseCandidateGapIdentity, ReverseCandidateGapContribution>,
    inventory: ReverseCandidateReasonBucket,
    endpoints: HashMap<BindingNodeId, ReverseCandidateEndpointReasonBuckets>,
}

impl ReverseCandidateGapCoverage {
    pub(crate) fn empty() -> Self {
        ReverseCandidateGapCoverageBuilder::default()
            .finish(&CancellationToken::new())
            .expect("an empty reverse candidate coverage builder is valid")
            .0
    }

    pub(crate) fn inventory_completion(&self) -> &ResolutionCompletion {
        &self.inventory.completion
    }

    pub(crate) fn branch_completion_for_with_poll(
        &self,
        endpoint: &EndpointSignature,
        cancellation: &CancellationToken,
        work: &mut usize,
    ) -> (ResolutionCompletion, bool) {
        let Some(local) = self.endpoints.get(&endpoint.node()) else {
            return (
                ResolutionCompletion::Complete,
                poll_reverse_candidate_gap_work(cancellation, work),
            );
        };
        local.completion_for_with_poll(endpoint, cancellation, work)
    }

    pub(crate) fn filtered_inventory_completion<'coverage>(
        &'coverage self,
        prepared: &'coverage ReverseCandidateGapExclusionPlan,
    ) -> StoreResult<&'coverage ResolutionCompletion> {
        Ok(prepared
            .prepared_for(self)?
            .inventory
            .as_ref()
            .unwrap_or(&self.inventory.completion))
    }

    pub(crate) fn filtered_branch_completion_for_with_poll(
        &self,
        endpoint: &EndpointSignature,
        prepared: &ReverseCandidateGapExclusionPlan,
        cancellation: &CancellationToken,
        work: &mut usize,
    ) -> StoreResult<(ResolutionCompletion, bool)> {
        let prepared = prepared.prepared_for(self)?;
        let Some(raw) = self.endpoints.get(&endpoint.node()) else {
            return Ok((
                ResolutionCompletion::Complete,
                poll_reverse_candidate_gap_work(cancellation, work),
            ));
        };
        let local = prepared.endpoints.get(&endpoint.node());
        Ok(raw.completion_for_with_overlay(endpoint, local, cancellation, work))
    }

    pub(crate) fn prepare_exclusions(
        &self,
        plan: &mut ReverseCandidateGapExclusionPlan,
        cancellation: &CancellationToken,
    ) -> StoreResult<bool> {
        plan.prepare_for(self, cancellation)
    }
}

#[derive(Default)]
pub(crate) struct ReverseCandidateGapCoverageBuilder {
    rows: BTreeMap<ReverseCandidateGapIdentity, ReverseCandidateGapRow>,
}

impl ReverseCandidateGapCoverageBuilder {
    pub(crate) fn push(&mut self, row: ReverseCandidateGapRow) -> StoreResult<()> {
        assert_ne!(
            row.reason,
            ResolutionIncompleteReason::Cancelled,
            "persisted reverse candidate coverage cannot contain operation cancellation"
        );
        if self.rows.insert(row.identity, row).is_some() {
            return Err(StoreError::new(format!(
                "duplicate selected reverse candidate gap ({}, {})",
                row.identity.fragment(),
                row.identity.gap_id()
            )));
        }
        Ok(())
    }

    pub(crate) fn finish(
        self,
        cancellation: &CancellationToken,
    ) -> StoreResult<(ReverseCandidateGapCoverage, bool)> {
        let mut fingerprint =
            CanonicalHasher::new(b"bifrost-resolution-reverse-candidate-gap-coverage:v1");
        fingerprint.field(
            "row-count",
            &u64::try_from(self.rows.len())
                .expect("reverse candidate gap count fits u64")
                .to_be_bytes(),
        );
        let mut by_identity = map_with_capacity(self.rows.len());
        let mut inventory = ReverseCandidateReasonBucketBuilder::default();
        let mut endpoints: HashMap<BindingNodeId, ReverseCandidateEndpointReasonBucketBuilder> =
            map_with_capacity(self.rows.len());
        let mut work = 0_usize;
        let mut cancellation_observed = false;
        for (_, row) in self.rows {
            cancellation_observed |= poll_reverse_candidate_gap_work(cancellation, &mut work);
            assert!(
                by_identity
                    .insert(
                        row.identity,
                        ReverseCandidateGapContribution {
                            location: row.location,
                            reason: row.reason,
                        },
                    )
                    .is_none(),
                "the canonical reverse gap row map has unique identities"
            );
            hash_reverse_candidate_gap_row(&mut fingerprint, row);
            match row.location {
                ReverseCandidateGapLocation::Inventory => inventory.push(row.reason),
                ReverseCandidateGapLocation::Endpoint { endpoint, lookup } => {
                    endpoints
                        .entry(endpoint)
                        .or_default()
                        .push(lookup, row.reason);
                }
            }
        }
        let (inventory, observed) = inventory.finish(cancellation, &mut work);
        cancellation_observed |= observed;
        let mut finished_endpoints = map_with_capacity(endpoints.len());
        for (endpoint, local) in endpoints {
            cancellation_observed |= poll_reverse_candidate_gap_work(cancellation, &mut work);
            let (local, observed) = local.finish(cancellation, &mut work);
            cancellation_observed |= observed;
            assert!(
                finished_endpoints.insert(endpoint, local).is_none(),
                "one reverse candidate endpoint bucket is finished once"
            );
        }
        Ok((
            ReverseCandidateGapCoverage {
                fingerprint: ReverseCandidateGapCoverageFingerprint(fingerprint.finish()),
                by_identity,
                inventory,
                endpoints: finished_endpoints,
            },
            cancellation_observed | cancellation.is_cancelled(),
        ))
    }
}

#[derive(Debug, Clone)]
struct ReverseCandidateReasonBucket {
    counts: BTreeMap<ResolutionIncompleteReason, usize>,
    completion: ResolutionCompletion,
}

impl ReverseCandidateReasonBucket {
    fn completion_after_excluding(
        &self,
        excluded: &BTreeMap<ResolutionIncompleteReason, usize>,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<ResolutionCompletion>> {
        let mut reasons = Vec::with_capacity(self.counts.len());
        for (&reason, &count) in &self.counts {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let removed = excluded.get(&reason).copied().unwrap_or_default();
            if removed > count {
                return Err(StoreError::new(format!(
                    "reverse candidate gap exclusion removes {removed} copies of {reason:?}, but raw coverage contains {count}"
                )));
            }
            if removed < count {
                reasons.push(reason);
            }
        }
        for reason in excluded.keys() {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            if !self.counts.contains_key(reason) {
                return Err(StoreError::new(format!(
                    "reverse candidate gap exclusion names absent bucket reason {reason:?}"
                )));
            }
        }
        Ok(Some(if reasons.is_empty() {
            ResolutionCompletion::Complete
        } else {
            ResolutionCompletion::Incomplete(reasons.into_boxed_slice().into())
        }))
    }
}

#[derive(Default)]
struct ReverseCandidateReasonBucketBuilder {
    counts: BTreeMap<ResolutionIncompleteReason, usize>,
}

impl ReverseCandidateReasonBucketBuilder {
    fn push(&mut self, reason: ResolutionIncompleteReason) {
        self.counts
            .entry(reason)
            .and_modify(|count| {
                *count = count
                    .checked_add(1)
                    .expect("reverse candidate reason multiplicity must fit usize")
            })
            .or_insert(1);
    }

    fn finish(
        self,
        cancellation: &CancellationToken,
        work: &mut usize,
    ) -> (ReverseCandidateReasonBucket, bool) {
        let mut reasons = Vec::with_capacity(self.counts.len());
        let mut cancellation_observed = false;
        for &reason in self.counts.keys() {
            cancellation_observed |= poll_reverse_candidate_gap_work(cancellation, work);
            reasons.push(reason);
        }
        let completion = if reasons.is_empty() {
            ResolutionCompletion::Complete
        } else {
            ResolutionCompletion::Incomplete(reasons.into_boxed_slice().into())
        };
        (
            ReverseCandidateReasonBucket {
                counts: self.counts,
                completion,
            },
            cancellation_observed,
        )
    }
}

#[derive(Debug, Clone)]
struct ReverseCandidateEndpointReasonBuckets {
    unkeyed: ReverseCandidateReasonBucket,
    all_keyed: ReverseCandidateReasonBucket,
    by_lookup: HashMap<SemanticId, ReverseCandidateReasonBucket>,
}

impl ReverseCandidateEndpointReasonBuckets {
    fn completion_for_with_poll(
        &self,
        endpoint: &EndpointSignature,
        cancellation: &CancellationToken,
        work: &mut usize,
    ) -> (ResolutionCompletion, bool) {
        self.completion_for_with_overlay(endpoint, None, cancellation, work)
    }

    fn completion_for_with_overlay(
        &self,
        endpoint: &EndpointSignature,
        overlay: Option<&PreparedReverseCandidateEndpointBuckets>,
        cancellation: &CancellationToken,
        work: &mut usize,
    ) -> (ResolutionCompletion, bool) {
        let unkeyed = overlay
            .and_then(|local| local.unkeyed.as_ref())
            .unwrap_or(&self.unkeyed.completion);
        let mut completion = BatchCompletionLedger::default();
        let mut cancellation_observed = completion.include(unkeyed, cancellation, work);
        if let Some(first) = endpoint.symbols().fixed().first() {
            let lookup = first.symbol();
            let keyed = overlay
                .and_then(|local| local.by_lookup.get(&lookup))
                .or_else(|| self.by_lookup.get(&lookup).map(|local| &local.completion));
            if let Some(keyed) = keyed {
                cancellation_observed |= completion.include(keyed, cancellation, work);
            }
        } else if endpoint.symbols().tail().is_some() {
            let all_keyed = overlay
                .and_then(|local| local.all_keyed.as_ref())
                .unwrap_or(&self.all_keyed.completion);
            cancellation_observed |= completion.include(all_keyed, cancellation, work);
        }
        let (completion, observed) = completion.finish_semantic(cancellation, work);
        (completion, cancellation_observed | observed)
    }

    fn completion_after_excluding(
        &self,
        excluded: ReverseCandidateEndpointReasonDecrements,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<PreparedReverseCandidateEndpointBuckets>> {
        let unkeyed = if excluded.unkeyed.is_empty() {
            None
        } else {
            let Some(completion) = self
                .unkeyed
                .completion_after_excluding(&excluded.unkeyed.counts, cancellation)?
            else {
                return Ok(None);
            };
            Some(completion)
        };
        let all_keyed = if excluded.all_keyed.is_empty() {
            None
        } else {
            let Some(completion) = self
                .all_keyed
                .completion_after_excluding(&excluded.all_keyed.counts, cancellation)?
            else {
                return Ok(None);
            };
            Some(completion)
        };
        let mut by_lookup = map_with_capacity(excluded.by_lookup.len());
        for (lookup, excluded) in excluded.by_lookup {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let raw = self.by_lookup.get(&lookup).unwrap_or_else(|| {
                panic!("an indexed reverse gap contribution must have its lookup bucket")
            });
            let Some(completion) =
                raw.completion_after_excluding(&excluded.counts, cancellation)?
            else {
                return Ok(None);
            };
            assert!(
                by_lookup.insert(lookup, completion).is_none(),
                "one reverse candidate lookup overlay is prepared once"
            );
        }
        Ok(Some(PreparedReverseCandidateEndpointBuckets {
            unkeyed,
            all_keyed,
            by_lookup,
        }))
    }
}

#[derive(Default)]
struct ReverseCandidateEndpointReasonBucketBuilder {
    unkeyed: ReverseCandidateReasonBucketBuilder,
    all_keyed: ReverseCandidateReasonBucketBuilder,
    by_lookup: HashMap<SemanticId, ReverseCandidateReasonBucketBuilder>,
}

impl ReverseCandidateEndpointReasonBucketBuilder {
    fn push(&mut self, lookup: Option<SemanticId>, reason: ResolutionIncompleteReason) {
        if let Some(lookup) = lookup {
            self.all_keyed.push(reason);
            self.by_lookup.entry(lookup).or_default().push(reason);
        } else {
            self.unkeyed.push(reason);
        }
    }

    fn finish(
        self,
        cancellation: &CancellationToken,
        work: &mut usize,
    ) -> (ReverseCandidateEndpointReasonBuckets, bool) {
        let (unkeyed, mut cancellation_observed) = self.unkeyed.finish(cancellation, work);
        let (all_keyed, observed) = self.all_keyed.finish(cancellation, work);
        cancellation_observed |= observed;
        let mut by_lookup = map_with_capacity(self.by_lookup.len());
        for (lookup, local) in self.by_lookup {
            cancellation_observed |= poll_reverse_candidate_gap_work(cancellation, work);
            let (local, observed) = local.finish(cancellation, work);
            cancellation_observed |= observed;
            assert!(
                by_lookup.insert(lookup, local).is_none(),
                "one reverse candidate lookup bucket is finished once"
            );
        }
        (
            ReverseCandidateEndpointReasonBuckets {
                unkeyed,
                all_keyed,
                by_lookup,
            },
            cancellation_observed,
        )
    }
}

#[derive(Default)]
struct ReverseCandidateReasonDecrements {
    counts: BTreeMap<ResolutionIncompleteReason, usize>,
}

impl ReverseCandidateReasonDecrements {
    fn push(&mut self, reason: ResolutionIncompleteReason) {
        self.counts
            .entry(reason)
            .and_modify(|count| {
                *count = count
                    .checked_add(1)
                    .expect("reverse candidate exclusion multiplicity must fit usize")
            })
            .or_insert(1);
    }

    fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }
}

#[derive(Default)]
struct ReverseCandidateEndpointReasonDecrements {
    unkeyed: ReverseCandidateReasonDecrements,
    all_keyed: ReverseCandidateReasonDecrements,
    by_lookup: HashMap<SemanticId, ReverseCandidateReasonDecrements>,
}

impl ReverseCandidateEndpointReasonDecrements {
    fn push(&mut self, lookup: Option<SemanticId>, reason: ResolutionIncompleteReason) {
        if let Some(lookup) = lookup {
            self.all_keyed.push(reason);
            self.by_lookup.entry(lookup).or_default().push(reason);
        } else {
            self.unkeyed.push(reason);
        }
    }
}

#[derive(Debug)]
struct PreparedReverseCandidateGapExclusions {
    raw_fingerprint: ReverseCandidateGapCoverageFingerprint,
    inventory: Option<ResolutionCompletion>,
    endpoints: HashMap<BindingNodeId, PreparedReverseCandidateEndpointBuckets>,
}

#[derive(Debug)]
struct PreparedReverseCandidateEndpointBuckets {
    unkeyed: Option<ResolutionCompletion>,
    all_keyed: Option<ResolutionCompletion>,
    by_lookup: HashMap<SemanticId, ResolutionCompletion>,
}

fn poll_reverse_candidate_gap_work(cancellation: &CancellationToken, work: &mut usize) -> bool {
    *work = work
        .checked_add(1)
        .expect("reverse candidate gap work must fit usize");
    work.is_multiple_of(CANCELLATION_QUANTUM) && cancellation.is_cancelled()
}

fn hash_reverse_candidate_gap_row(fingerprint: &mut CanonicalHasher, row: ReverseCandidateGapRow) {
    let mut hasher = CanonicalHasher::new(b"bifrost-resolution-reverse-candidate-gap-row:v1");
    hasher.field("fragment", &row.identity.fragment().as_bytes());
    hasher.field("gap", &row.identity.gap_id().as_bytes());
    match row.location {
        ReverseCandidateGapLocation::Inventory => hasher.field("scope", b"inventory"),
        ReverseCandidateGapLocation::Endpoint { endpoint, lookup } => {
            hasher.field("scope", b"endpoint");
            hasher.field("endpoint", &endpoint.as_bytes());
            if let Some(lookup) = lookup {
                hasher.field("lookup-kind", b"keyed");
                hasher.field("lookup", &lookup.as_bytes());
            } else {
                hasher.field("lookup-kind", b"unkeyed");
            }
        }
    }
    match row.reason {
        ResolutionIncompleteReason::Cancelled => {
            panic!("persisted reverse candidate coverage cannot contain cancellation")
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
    fingerprint.field("row", &hasher.finish());
}

impl BatchCandidateOutcome {
    pub fn new(
        request_count: usize,
        matches: Vec<BatchCandidateMatch>,
        unconditional_completion: ResolutionCompletion,
        branch_completions: impl IntoIterator<Item = ResolutionCompletion>,
    ) -> Self {
        Self::new_observing(
            request_count,
            matches,
            unconditional_completion,
            branch_completions,
            || {},
        )
    }

    pub(super) fn new_observing(
        request_count: usize,
        matches: Vec<BatchCandidateMatch>,
        unconditional_completion: ResolutionCompletion,
        branch_completions: impl IntoIterator<Item = ResolutionCompletion>,
        observe: impl FnMut(),
    ) -> Self {
        let completion = BatchCandidateCompletionOutcome::new_observing(
            request_count,
            unconditional_completion,
            branch_completions,
            observe,
        );
        Self {
            matches,
            unconditional_completion: completion.unconditional_completion,
            branch_completions: completion.branch_completions,
        }
    }

    pub fn complete(request_count: usize, matches: Vec<BatchCandidateMatch>) -> Self {
        Self::new(
            request_count,
            matches,
            ResolutionCompletion::Complete,
            std::iter::repeat_n(ResolutionCompletion::Complete, request_count),
        )
    }

    pub fn matches(&self) -> &[BatchCandidateMatch] {
        &self.matches
    }

    pub fn unconditional_completion(&self) -> &ResolutionCompletion {
        &self.unconditional_completion
    }

    pub fn branch_completions(&self) -> &[ResolutionCompletion] {
        &self.branch_completions
    }

    fn into_parts(
        self,
    ) -> (
        Vec<BatchCandidateMatch>,
        ResolutionCompletion,
        Box<[ResolutionCompletion]>,
    ) {
        (
            self.matches,
            self.unconditional_completion,
            self.branch_completions,
        )
    }
}

/// Exact classification of one hydrated endpoint node, including the selected
/// typed owner when that node is a member-scope entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchEndpointClassification {
    node: BindingNodeId,
    reference: Option<SemanticId>,
    definition: Option<SemanticId>,
    member_scope_owner: Option<SemanticId>,
}

/// Exact selected-node lookup result for one requested definition semantic.
///
/// A row is returned even when the selected context has no node for the
/// semantic. This keeps absence distinct from operational cancellation, which
/// may instead stop a batch before every requested row is returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchDefinitionNode {
    definition: SemanticId,
    node: Option<BindingNodeId>,
}

impl BatchDefinitionNode {
    pub const fn new(definition: SemanticId, node: Option<BindingNodeId>) -> Self {
        Self { definition, node }
    }

    pub const fn definition(self) -> SemanticId {
        self.definition
    }

    pub const fn node(self) -> Option<BindingNodeId> {
        self.node
    }
}

impl BatchEndpointClassification {
    pub const fn new(
        node: BindingNodeId,
        reference: Option<SemanticId>,
        definition: Option<SemanticId>,
    ) -> Self {
        Self::new_with_member_scope_owner(node, reference, definition, None)
    }

    pub const fn new_with_member_scope_owner(
        node: BindingNodeId,
        reference: Option<SemanticId>,
        definition: Option<SemanticId>,
        member_scope_owner: Option<SemanticId>,
    ) -> Self {
        assert!(reference.is_none() || definition.is_none());
        assert!(
            member_scope_owner.is_none() || (reference.is_none() && definition.is_none()),
            "member-scope owner classification must be scope-only"
        );
        Self {
            node,
            reference,
            definition,
            member_scope_owner,
        }
    }

    pub const fn node(self) -> BindingNodeId {
        self.node
    }

    pub const fn definition(self) -> Option<SemanticId> {
        self.definition
    }

    pub const fn reference(self) -> Option<SemanticId> {
        self.reference
    }

    pub const fn member_scope_owner(self) -> Option<SemanticId> {
        self.member_scope_owner
    }
}

impl BatchCandidateMatch {
    pub const fn new(candidate: CandidatePathIdentity, request_ordinal: usize) -> Self {
        Self {
            candidate,
            request_ordinal,
        }
    }

    pub const fn candidate(self) -> CandidatePathIdentity {
        self.candidate
    }

    pub const fn request_ordinal(self) -> usize {
        self.request_ordinal
    }
}

/// Batch read side for immutable resolution facts.
///
/// A source is the closed-world authority for one exact selected context. Seed
/// enumeration must visit every selected reference exactly once globally, in a
/// batch carrying its true owning fragment and node. If references, fragments,
/// or semantic coverage may be absent, the relevant seed, candidate outcome,
/// or final enumeration completion must carry that incompleteness; returning
/// [`ResolutionCompletion::Complete`] certifies that omission is impossible.
/// Candidate matches must be a sound superset for every request, classification
/// and hydration must return exact bijections for their requested identities,
/// and reverse seed issuance must recover the exact source-owned seed for every
/// request. Operational read and decode failures are [`StoreError`], never an
/// empty or incomplete semantic answer.
///
/// This contract is deliberately independent of the single-query compatibility
/// source. A persistent source must implement these bounded, completion-aware
/// reads directly; satisfying an older visitor API is neither required nor a
/// proof that empty SQL results are semantically complete. Do not implement a
/// direction flag: forward and reverse candidate indexes have different SQL
/// shapes.
pub trait BatchResolutionFragmentSource {
    /// Look up the unique selected seed for one reference semantic.
    ///
    /// Cancellation may stop the lookup without manufacturing an absent
    /// reference. The engine rechecks the token before interpreting `None`.
    fn reference_seed(
        &self,
        query: ResolutionQuery,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<ReferenceSeed>>;

    /// Look up one bounded set of selected forward reference seeds.
    ///
    /// An exhausted result contains exactly one input-ordinal row for every
    /// query, including an explicit `None` when the selected context has no
    /// reference. A cancelled result contains no rows, so a caller cannot
    /// mistake an unread query for negative evidence, but retains all semantic
    /// evidence decoded before cancellation. Persistent and production preload
    /// sources must override this method with one bounded source read. This
    /// scalar compatibility default exists only for small hand-written sources.
    fn lookup_reference_seeds(
        &self,
        queries: &[ResolutionQuery],
        cancellation: &CancellationToken,
    ) -> StoreResult<ReferenceSeedReadOutcome> {
        assert!(
            queries.len() <= MAX_REFERENCE_SEEDS_PER_BATCH,
            "reference seed batch has {} queries; maximum is {MAX_REFERENCE_SEEDS_PER_BATCH}",
            queries.len()
        );
        if cancellation.is_cancelled() {
            return Ok(ReferenceSeedReadOutcome::cancelled(
                ResolutionCompletion::Complete,
            ));
        }

        let mut rows = Vec::with_capacity(queries.len());
        let mut evidence = BatchCompletionLedger::default();
        let mut work = 0_usize;
        for (request_ordinal, &query) in queries.iter().enumerate() {
            if cancellation.is_cancelled() {
                let (evidence, _) = evidence.finish_semantic(cancellation, &mut work);
                return Ok(ReferenceSeedReadOutcome::cancelled(evidence));
            }
            let seed = self.reference_seed(query, cancellation)?;
            let mut cancellation_observed = cancellation.is_cancelled();
            if let Some(seed) = &seed {
                cancellation_observed |=
                    evidence.include(seed.completion(), cancellation, &mut work);
            }
            if cancellation_observed || cancellation.is_cancelled() {
                let (evidence, _) = evidence.finish_semantic(cancellation, &mut work);
                return Ok(ReferenceSeedReadOutcome::cancelled(evidence));
            }
            rows.push(BatchReferenceSeed::new(request_ordinal, query, seed));
        }
        if cancellation.is_cancelled() {
            let (evidence, _) = evidence.finish_semantic(cancellation, &mut work);
            return Ok(ReferenceSeedReadOutcome::cancelled(evidence));
        }
        Ok(ReferenceSeedReadOutcome::exhausted(rows))
    }

    /// Look up the unique selected definition node for one semantic identity.
    ///
    /// This is the semantic-to-node seed for reverse traversal, not a candidate
    /// search. A source must reject duplicate selected definitions rather than
    /// choose one by row order. Cancellation may stop the lookup without
    /// manufacturing an absent definition; the engine rechecks the token before
    /// interpreting `None`.
    fn lookup_definition_node(
        &self,
        definition: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<BindingNodeId>>;

    /// Look up one bounded set of selected definition nodes.
    ///
    /// With a live token, the returned rows are an exact semantic bijection
    /// with `definitions`; row order is immaterial. Cancellation may return a
    /// valid partial bijection. Persistent sources should override this method
    /// with one relational read. The compatibility default keeps hand-written
    /// sources source-compatible without weakening the bounded caller shape.
    fn lookup_definition_nodes(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Vec<BatchDefinitionNode>> {
        assert!(
            definitions.len() <= MAX_REVERSE_TARGETS_PER_BATCH,
            "definition-node batch has {} entries; maximum is {MAX_REVERSE_TARGETS_PER_BATCH}",
            definitions.len()
        );
        let mut rows = Vec::with_capacity(definitions.len());
        for &definition in definitions {
            if cancellation.is_cancelled() {
                break;
            }
            let node = self.lookup_definition_node(definition, cancellation)?;
            if cancellation.is_cancelled() {
                break;
            }
            rows.push(BatchDefinitionNode::new(definition, node));
        }
        Ok(rows)
    }

    /// Issue exact seeds for one bounded set of reverse-classified references.
    ///
    /// The returned order is immaterial, but the result must contain exactly
    /// one source-issued seed for every request and no other seeds. The engine
    /// validates that bijection before it trusts fragment ownership or
    /// completeness carried by the seeds.
    fn issue_reverse_reference_seeds(
        &self,
        requests: &[ReverseReferenceSeedRequest],
        cancellation: &CancellationToken,
    ) -> StoreResult<Vec<ReferenceSeed>>;

    fn visit_reference_seed_batches(
        &self,
        maximum_batch_size: usize,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&ReferenceSeedBatch) -> StoreResult<bool>,
    ) -> StoreResult<ResolutionCompletion>;

    fn classify_endpoint_nodes(
        &self,
        nodes: &[BindingNodeId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Vec<BatchEndpointClassification>>;

    fn match_forward_candidates(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
    ) -> StoreResult<BatchCandidateOutcome>;

    /// Visit forward matches in bounded output pages.
    ///
    /// Every page must contain `1..=MAX_SOURCE_ROWS_PER_BATCH` rows. The
    /// concatenated stream uses one deterministic, duplicate-free source
    /// cursor order; it is not ordered by opaque mounted runtime IDs. Request
    /// ordinals are local to `requests`. Returning `false` or observing
    /// cancellation may stop row emission, but the source must still return
    /// the full completion outcome for every request rather than coverage for
    /// only the emitted prefix. Consumers validate uniqueness and restore
    /// canonical mounted-ID order only after an exhausted read.
    ///
    /// This compatibility implementation materializes the legacy outcome and
    /// is intentionally not the preload or persistent-source hot path.
    fn visit_forward_candidate_match_pages(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        let outcome = self.match_forward_candidates(requests, cancellation)?;
        visit_legacy_candidate_match_pages(outcome, requests.len(), cancellation, visitor)
    }

    /// Visit forward matches for a universal-root open-symbol request while
    /// permitting a source to return only the completion buckets consumed by
    /// the root stitcher. The default preserves the complete candidate
    /// contract for transient and preload sources.
    fn visit_forward_root_candidate_match_pages(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        self.visit_forward_candidate_match_pages(requests, cancellation, visitor)
    }

    /// Visit forward matches while capping each provider page for a caller
    /// that owns a tighter cooperative work limit.
    fn visit_forward_candidate_match_pages_limited(
        &self,
        requests: &[BatchCandidateRequest],
        maximum_page_rows: usize,
        _resolution_session: Option<&ResolutionSession>,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        assert!((1..=MAX_SOURCE_ROWS_PER_BATCH).contains(&maximum_page_rows));
        self.visit_forward_candidate_match_pages(requests, cancellation, visitor)
    }

    fn match_reverse_candidates(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
    ) -> StoreResult<BatchCandidateOutcome>;

    /// Visit reverse matches in bounded output pages.
    ///
    /// This has the same ordering, completion-ownership, and compatibility
    /// guarantees as [`Self::visit_forward_candidate_match_pages`].
    fn visit_reverse_candidate_match_pages(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        let outcome = self.match_reverse_candidates(requests, cancellation)?;
        visit_legacy_candidate_match_pages(outcome, requests.len(), cancellation, visitor)
    }

    /// Visit reverse matches for a universal-root open-symbol request while
    /// permitting a source to return only the completion buckets consumed by
    /// the root stitcher. The default preserves the complete candidate
    /// contract for transient and preload sources.
    fn visit_reverse_root_candidate_match_pages(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        self.visit_reverse_candidate_match_pages(requests, cancellation, visitor)
    }

    /// Visit raw reverse matches while transferring an exact set of selected
    /// reverse-gap rows to a richer operation-local overlay.
    ///
    /// This is deliberately opt-in. Existing reverse methods remain the raw
    /// lexical contract and never inherit exclusions from an earlier call.
    /// Implementations that cannot validate exact `(fragment, gap_id)` rows
    /// fail closed for a nonempty plan instead of subtracting reason values.
    fn visit_reverse_candidate_match_pages_with_gap_exclusions_shared(
        &self,
        requests: &[BatchCandidateRequest],
        exclusions: &mut ReverseCandidateGapExclusionPlan,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        if exclusions.is_empty() {
            return self.visit_reverse_candidate_match_pages(requests, cancellation, visitor);
        }
        if cancellation.is_cancelled() {
            return Ok(cancelled_candidate_completion_outcome(requests.len()));
        }
        Err(StoreError::new(
            "batch resolution source does not support exact reverse candidate gap exclusions",
        ))
    }

    fn visit_reverse_candidate_match_pages_with_gap_exclusions(
        &mut self,
        requests: &[BatchCandidateRequest],
        exclusions: &mut ReverseCandidateGapExclusionPlan,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        self.visit_reverse_candidate_match_pages_with_gap_exclusions_shared(
            requests,
            exclusions,
            cancellation,
            visitor,
        )
    }

    fn hydrate_candidate_paths(
        &self,
        candidates: &[CandidatePathIdentity],
        cancellation: &CancellationToken,
    ) -> StoreResult<Vec<(CandidatePathIdentity, PartialPath)>>;

    /// Visit normalized immutable copy rules for one typed source slot.
    ///
    /// The returned completion describes semantic coverage of the selected
    /// source even when no rule row exists. Each visited rule carries its own
    /// row-local completion. Returning `Complete` with no rows therefore
    /// certifies a closed-world negative; a source with a selected-fragment gap
    /// must return that gap instead. The visitor may stop iteration by returning
    /// `false`; the batch engine uses that only for cooperative cancellation.
    fn visit_type_transfer_rules(
        &self,
        source_slot: SemanticId,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&TypeTransferRule) -> StoreResult<bool>,
    ) -> StoreResult<ResolutionCompletion>;
}

/// Atomic result of adapting one selected-context delta to the batch source
/// contract.
///
/// Contextual reverse-inventory evidence remains separate from operational
/// cancellation. A point or broad operation must publish only the latter,
/// while a reverse operation combines the former exactly once at its top
fn cancelled_candidate_completion_outcome(request_count: usize) -> BatchCandidateCompletionOutcome {
    BatchCandidateCompletionOutcome::new(
        request_count,
        cancelled_completion(),
        std::iter::repeat_n(ResolutionCompletion::Complete, request_count),
    )
}

/// Adapt the old materialized candidate result to the bounded output contract.
///
/// This exists only for hand-written and not-yet-migrated sources. New sources
/// must implement the visitor seam directly so a single high-fanout endpoint
/// cannot allocate an unbounded returned row vector.
fn visit_legacy_candidate_match_pages(
    outcome: BatchCandidateOutcome,
    request_count: usize,
    cancellation: &CancellationToken,
    visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
) -> StoreResult<BatchCandidateCompletionOutcome> {
    let (matches, unconditional_completion, branch_completions) = outcome.into_parts();
    let completion = BatchCandidateCompletionOutcome {
        unconditional_completion,
        branch_completions,
    };
    let mut canonical = BTreeSet::new();
    let mut work = 0_usize;
    let mut returned_evidence = CancellationEvidenceLedger::default();
    returned_evidence.include(
        completion.unconditional_completion(),
        cancellation,
        &mut work,
    );
    let mut cancelled = returned_evidence.cancellation_observed() || cancellation.is_cancelled();
    if !cancelled {
        for matched in matches {
            if poll_reverse_completion(cancellation, &mut work) {
                cancelled = true;
                break;
            }
            if matched.request_ordinal() >= request_count {
                return Err(StoreError::new(format!(
                    "candidate {:?} names invalid batch request {} of {}",
                    matched.candidate(),
                    matched.request_ordinal(),
                    request_count
                )));
            }
            let identity = (matched.request_ordinal(), matched.candidate());
            if !canonical.insert(identity) {
                return Err(StoreError::new(format!(
                    "legacy candidate adapter repeated natural identity {identity:?}"
                )));
            }
        }
    }
    if cancelled {
        return Ok(completion);
    }

    let mut page = Vec::with_capacity(MAX_SOURCE_ROWS_PER_BATCH);
    while let Some((request_ordinal, candidate)) = canonical.pop_first() {
        if poll_reverse_completion(cancellation, &mut work) {
            break;
        }
        page.push(BatchCandidateMatch::new(candidate, request_ordinal));
        if page.len() == MAX_SOURCE_ROWS_PER_BATCH {
            if !visitor(&page)? {
                return Ok(completion);
            }
            page.clear();
        }
    }
    if !page.is_empty() {
        let _ = visitor(&page)?;
    }
    Ok(completion)
}

/// Deterministic work evidence for one batch operation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResolutionBatchMetrics {
    reference_seeds: usize,
    batches: usize,
    distinct_candidate_matches: usize,
    distinct_path_hydrations: usize,
    distinct_endpoint_classifications: usize,
    composition_attempts: usize,
    successful_stitches: usize,
    worklist_rounds: usize,
    peak_frontier_paths: usize,
    peak_candidate_matches: usize,
    peak_hydrated_paths: usize,
    peak_classified_endpoints: usize,
}

impl ResolutionBatchMetrics {
    pub const fn reference_seeds(self) -> usize {
        self.reference_seeds
    }

    pub const fn batches(self) -> usize {
        self.batches
    }

    pub const fn distinct_candidate_matches(self) -> usize {
        self.distinct_candidate_matches
    }

    pub const fn distinct_path_hydrations(self) -> usize {
        self.distinct_path_hydrations
    }

    pub const fn distinct_endpoint_classifications(self) -> usize {
        self.distinct_endpoint_classifications
    }

    pub const fn composition_attempts(self) -> usize {
        self.composition_attempts
    }

    /// Exact path concatenations accepted by structural composition.
    ///
    /// This is intentionally narrower than [`Self::composition_attempts`]
    /// and broader than successor publication: later canonicalization,
    /// saturation, or cancellation may still prevent an accepted stitch from
    /// entering the next frontier.
    pub const fn successful_stitches(self) -> usize {
        self.successful_stitches
    }

    pub const fn worklist_rounds(self) -> usize {
        self.worklist_rounds
    }

    pub const fn peak_frontier_paths(self) -> usize {
        self.peak_frontier_paths
    }

    pub const fn peak_candidate_matches(self) -> usize {
        self.peak_candidate_matches
    }

    pub const fn peak_hydrated_paths(self) -> usize {
        self.peak_hydrated_paths
    }

    pub const fn peak_classified_endpoints(self) -> usize {
        self.peak_classified_endpoints
    }

    pub(super) fn accumulate(&mut self, other: Self) {
        self.reference_seeds += other.reference_seeds;
        self.batches += other.batches;
        self.distinct_candidate_matches += other.distinct_candidate_matches;
        self.distinct_path_hydrations += other.distinct_path_hydrations;
        self.distinct_endpoint_classifications += other.distinct_endpoint_classifications;
        self.composition_attempts += other.composition_attempts;
        self.successful_stitches += other.successful_stitches;
        self.worklist_rounds += other.worklist_rounds;
        self.peak_frontier_paths = self.peak_frontier_paths.max(other.peak_frontier_paths);
        self.peak_candidate_matches = self
            .peak_candidate_matches
            .max(other.peak_candidate_matches);
        self.peak_hydrated_paths = self.peak_hydrated_paths.max(other.peak_hydrated_paths);
        self.peak_classified_endpoints = self
            .peak_classified_endpoints
            .max(other.peak_classified_endpoints);
    }
}

/// One canonical point answer within an atomically returned batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedReferenceAnswer {
    reference: SemanticId,
    answer: ResolutionAnswer,
}

impl BatchedReferenceAnswer {
    pub const fn reference(&self) -> SemanticId {
        self.reference
    }

    pub const fn answer(&self) -> &ResolutionAnswer {
        &self.answer
    }
}

/// Atomically returned point answers and their operation-local work evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceBatchAnswer {
    answers: Box<[BatchedReferenceAnswer]>,
    completion: ResolutionCompletion,
    metrics: ResolutionBatchMetrics,
}

impl ReferenceBatchAnswer {
    pub fn answers(&self) -> &[BatchedReferenceAnswer] {
        &self.answers
    }

    pub fn answer(&self, reference: SemanticId) -> Option<&ResolutionAnswer> {
        self.answers
            .binary_search_by_key(&reference, BatchedReferenceAnswer::reference)
            .ok()
            .map(|index| self.answers[index].answer())
    }

    pub fn completion(&self) -> &ResolutionCompletion {
        &self.completion
    }

    pub const fn metrics(&self) -> ResolutionBatchMetrics {
        self.metrics
    }
}

/// Completion and work evidence from a fragment-major batch stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionBatchSummary {
    completion: ResolutionCompletion,
    metrics: ResolutionBatchMetrics,
}

impl ResolutionBatchSummary {
    pub fn completion(&self) -> &ResolutionCompletion {
        &self.completion
    }

    pub const fn metrics(&self) -> ResolutionBatchMetrics {
        self.metrics
    }
}

#[derive(Debug)]
struct BatchWorkPath {
    seed: usize,
    path: PartialPath,
    derivation: AlphaRenamingId,
    saturation: SaturationBranch,
}

#[derive(Debug)]
struct SeedState {
    reference: SemanticId,
    completed: Vec<CompletedPath>,
    terminals: Vec<IncompleteTerminalPath>,
    completion: BatchCompletionLedger,
    observed_completion: CancellationEvidenceLedger,
    certifier: CycleCompletenessCertifier,
}

#[derive(Debug)]
struct PreparedSeed {
    reference: SemanticId,
    completion: BatchCompletionLedger,
    observed_completion: CancellationEvidenceLedger,
}

struct InitializedSeededBatch {
    metrics: ResolutionBatchMetrics,
    completion_work: usize,
    frontier: Vec<BatchWorkPath>,
    seeds: Vec<SeedState>,
    endpoint_definitions: HashMap<BindingNodeId, Option<SemanticId>>,
    cancelled: bool,
}

enum SeededBatchInitialization {
    Ready(InitializedSeededBatch),
    Cancelled(ReferenceBatchAnswer),
}

struct ForwardHydrationRequest {
    candidates: Vec<CandidatePathIdentity>,
}

struct ForwardHydrationContext<'a> {
    metrics: &'a mut ResolutionBatchMetrics,
    completion_work: &'a mut usize,
    seeds: &'a mut [SeedState],
    expandable: &'a [BatchWorkPath],
    matches: &'a [BatchCandidateMatch],
    arena: &'a mut HashMap<CandidatePathIdentity, PartialPath>,
    accounted_completions: &'a mut HashSet<(usize, CandidatePathIdentity)>,
    cancelled: &'a mut bool,
}

/// A source repeats `BatchCandidateCompletionOutcome::unconditional_completion`
/// for every bounded request page. That repetition is a consistency check, not
/// another semantic operand: one answer may have many expandable states, and
/// the same state family may span several source pages or worklist rounds. The
/// first exact semantic box is therefore retained once and attached once to
/// each seed/target that actually entered candidate matching.
///
/// Operational cancellation is allowed to augment a later returned box with
/// `Cancelled`. Source adapters canonicalize such a union, so that cancelled
/// repetition is compared by its non-cancellation reason set. Every live
/// repetition remains byte-for-byte exact; a disagreement is a store contract
/// failure and cannot publish a partial answer.
#[derive(Debug)]
struct OperationCandidateCompletionLedger {
    semantic_completion: Option<ResolutionCompletion>,
    accounted_answers: Vec<bool>,
}

impl OperationCandidateCompletionLedger {
    fn new(answer_count: usize) -> Self {
        Self {
            semantic_completion: None,
            accounted_answers: vec![false; answer_count],
        }
    }

    fn observe(
        &mut self,
        direction: &'static str,
        returned: ResolutionCompletion,
        answer_indices: impl IntoIterator<Item = usize>,
        cancellation: &CancellationToken,
        work: &mut usize,
    ) -> StoreResult<(Vec<usize>, bool)> {
        let (semantic, returned_cancelled, mut cancellation_observed) =
            split_candidate_unconditional_completion(returned, cancellation, work);
        if let Some(first) = &self.semantic_completion {
            let (consistent, observed) = if returned_cancelled {
                candidate_completion_reason_sets_equal(first, &semantic, cancellation, work)
            } else {
                candidate_completions_exactly_equal(first, &semantic, cancellation, work)
            };
            cancellation_observed |= observed;
            if !consistent {
                return Err(StoreError::new(format!(
                    "{direction} candidate source returned conflicting operation-wide unconditional completions: first {first:?}, repeated {semantic:?}, repeated_cancelled={returned_cancelled}"
                )));
            }
        } else {
            self.semantic_completion = Some(semantic);
        }

        let mut newly_accounted = Vec::new();
        for answer_index in answer_indices {
            cancellation_observed |= poll_reverse_completion(cancellation, work);
            assert!(
                answer_index < self.accounted_answers.len(),
                "{direction} candidate completion owner {answer_index} exceeds answer count {}",
                self.accounted_answers.len()
            );
            if !self.accounted_answers[answer_index] {
                self.accounted_answers[answer_index] = true;
                newly_accounted.push(answer_index);
            }
        }
        cancellation_observed |= cancellation.is_cancelled();
        Ok((newly_accounted, cancellation_observed))
    }

    fn semantic_completion(&self) -> &ResolutionCompletion {
        self.semantic_completion
            .as_ref()
            .expect("candidate completion is available after one observation")
    }
}

fn split_candidate_unconditional_completion(
    completion: ResolutionCompletion,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> (ResolutionCompletion, bool, bool) {
    let mut cancellation_observed = cancellation.is_cancelled();
    cancellation_observed |= poll_reverse_completion(cancellation, work);
    let ResolutionCompletion::Incomplete(reasons) = completion else {
        return (
            ResolutionCompletion::Complete,
            false,
            cancellation_observed | cancellation.is_cancelled(),
        );
    };

    let mut returned_cancelled = false;
    for &reason in reasons.iter() {
        cancellation_observed |= poll_reverse_completion(cancellation, work);
        returned_cancelled |= reason == ResolutionIncompleteReason::Cancelled;
    }
    if !returned_cancelled {
        return (
            ResolutionCompletion::Incomplete(reasons),
            false,
            cancellation_observed | cancellation.is_cancelled(),
        );
    }

    let mut semantic_reasons = Vec::with_capacity(reasons.len());
    for reason in reasons.into_vec() {
        let _ = poll_reverse_completion(cancellation, work);
        if reason != ResolutionIncompleteReason::Cancelled {
            semantic_reasons.push(reason);
        }
    }
    let semantic = if semantic_reasons.is_empty() {
        ResolutionCompletion::Complete
    } else {
        ResolutionCompletion::Incomplete(semantic_reasons.into_boxed_slice().into())
    };
    (semantic, true, true)
}

fn candidate_completions_exactly_equal(
    left: &ResolutionCompletion,
    right: &ResolutionCompletion,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> (bool, bool) {
    let mut cancellation_observed = cancellation.is_cancelled();
    cancellation_observed |= poll_reverse_completion(cancellation, work);
    let equal = match (left, right) {
        (ResolutionCompletion::Complete, ResolutionCompletion::Complete) => true,
        (ResolutionCompletion::Incomplete(left), ResolutionCompletion::Incomplete(right)) => {
            let mut equal = left.len() == right.len();
            for (index, right) in right.iter().enumerate() {
                cancellation_observed |= poll_reverse_completion(cancellation, work);
                equal &= left.get(index) == Some(right);
            }
            equal
        }

        (ResolutionCompletion::Complete, ResolutionCompletion::Incomplete(reasons))
        | (ResolutionCompletion::Incomplete(reasons), ResolutionCompletion::Complete) => {
            for _ in reasons.iter() {
                cancellation_observed |= poll_reverse_completion(cancellation, work);
            }

            false
        }
    };
    (equal, cancellation_observed | cancellation.is_cancelled())
}

fn candidate_completion_reason_sets_equal(
    left: &ResolutionCompletion,
    right: &ResolutionCompletion,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> (bool, bool) {
    let mut cancellation_observed = cancellation.is_cancelled();
    let mut canonical = |completion: &ResolutionCompletion| {
        let ResolutionCompletion::Incomplete(reasons) = completion else {
            cancellation_observed |= poll_reverse_completion(cancellation, work);
            return ResolutionCompletion::Complete;
        };

        let mut canonical = BTreeSet::new();
        for &reason in reasons.iter() {
            cancellation_observed |= poll_reverse_completion(cancellation, work);
            assert_ne!(
                reason,
                ResolutionIncompleteReason::Cancelled,
                "candidate semantic completion must exclude operational cancellation"
            );
            canonical.insert(reason);
        }
        if canonical.is_empty() {
            ResolutionCompletion::Complete
        } else {
            ResolutionCompletion::Incomplete(canonical.into_iter().collect::<Vec<_>>().into())
        }
    };
    let left = canonical(left);
    let right = canonical(right);
    let mut poll = || {
        cancellation_observed |= poll_reverse_completion(cancellation, work);
        false
    };
    let equal = completion_values_equal_with_poll(&left, &right, &mut poll)
        .expect("observational completion equality polling never aborts");
    (equal, cancellation_observed | cancellation.is_cancelled())
}

/// Exact operation-local semantic completion for one batch result.
///
/// Source and path completions may own arbitrarily many reasons. Raw boxes
/// that have crossed a source boundary are therefore drained in full while
/// the cancellation token is polled observationally. Cancellation can suppress
/// unpublished rows, but it cannot truncate semantic evidence
/// already returned for the target.
#[derive(Debug, Default)]
pub(super) struct BatchCompletionLedger {
    state: BatchCompletionState,
    cancellation_observed: bool,
}

#[derive(Debug, Default)]
enum BatchCompletionState {
    #[default]
    Complete,
    Single(Vec<ResolutionIncompleteReason>),
    Multiple {
        first: Vec<ResolutionIncompleteReason>,
        additional: Vec<ResolutionIncompleteReason>,
    },
}

fn raw_completion(reasons: Vec<ResolutionIncompleteReason>) -> ResolutionCompletion {
    ResolutionCompletion::Incomplete(reasons.into_boxed_slice().into())
}

fn observational_combine_completion(
    left: &ResolutionCompletion,
    right: &ResolutionCompletion,
    cancellation: &CancellationToken,
    work: &mut usize,
    cancellation_observed: &mut bool,
) -> ResolutionCompletion {
    let mut poll = || {
        *cancellation_observed |= poll_reverse_completion(cancellation, work);
        false
    };
    combine_completion_with_poll(left, right, &mut poll)
        .expect("observational completion union never aborts evidence retention")
}

impl BatchCompletionLedger {
    pub(super) fn include(
        &mut self,
        completion: &ResolutionCompletion,
        cancellation: &CancellationToken,
        work: &mut usize,
    ) -> bool {
        let mut cancellation_observed = cancellation.is_cancelled();
        cancellation_observed |= poll_reverse_completion(cancellation, work);
        let ResolutionCompletion::Incomplete(incoming) = completion else {
            self.cancellation_observed |= cancellation_observed;
            return self.cancellation_observed | cancellation.is_cancelled();
        };

        let state = std::mem::take(&mut self.state);
        self.state = match state {
            BatchCompletionState::Complete => {
                let mut reasons = Vec::with_capacity(incoming.len());
                for &reason in incoming.iter() {
                    cancellation_observed |= poll_reverse_completion(cancellation, work);
                    cancellation_observed |= reason == ResolutionIncompleteReason::Cancelled;
                    reasons.push(reason);
                }
                BatchCompletionState::Single(reasons)
            }
            BatchCompletionState::Single(first) => {
                assert!(
                    !first.is_empty() || !incoming.is_empty(),
                    "incomplete resolution requires a reason"
                );
                let mut additional = Vec::with_capacity(incoming.len());
                for &reason in incoming.iter() {
                    cancellation_observed |= poll_reverse_completion(cancellation, work);
                    cancellation_observed |= reason == ResolutionIncompleteReason::Cancelled;
                    additional.push(reason);
                }
                BatchCompletionState::Multiple { first, additional }
            }
            BatchCompletionState::Multiple {
                first,
                mut additional,
            } => {
                for &reason in incoming.iter() {
                    cancellation_observed |= poll_reverse_completion(cancellation, work);
                    cancellation_observed |= reason == ResolutionIncompleteReason::Cancelled;
                    additional.push(reason);
                }
                BatchCompletionState::Multiple { first, additional }
            }
        };
        self.cancellation_observed |= cancellation_observed | cancellation.is_cancelled();
        self.cancellation_observed
    }

    pub(super) fn include_reason(&mut self, reason: ResolutionIncompleteReason) {
        let state = std::mem::take(&mut self.state);
        self.state = match state {
            BatchCompletionState::Complete => BatchCompletionState::Single(vec![reason]),
            BatchCompletionState::Single(first) => BatchCompletionState::Multiple {
                first,
                additional: vec![reason],
            },
            BatchCompletionState::Multiple {
                first,
                mut additional,
            } => {
                additional.push(reason);
                BatchCompletionState::Multiple { first, additional }
            }
        };
        self.cancellation_observed |= reason == ResolutionIncompleteReason::Cancelled;
    }

    pub(super) fn finish_semantic(
        self,
        cancellation: &CancellationToken,
        work: &mut usize,
    ) -> (ResolutionCompletion, bool) {
        let mut cancellation_observed = self.cancellation_observed | cancellation.is_cancelled();
        let has_incomplete_operand = !matches!(&self.state, BatchCompletionState::Complete);
        let reasons = match self.state {
            BatchCompletionState::Complete => Vec::new(),
            BatchCompletionState::Single(single) => {
                let mut reasons = Vec::with_capacity(single.len());
                for reason in single {
                    cancellation_observed |= poll_reverse_completion(cancellation, work);
                    reasons.push(reason);
                }
                reasons
            }
            BatchCompletionState::Multiple { first, additional } => {
                let mut canonical = BTreeSet::new();
                for reason in first.into_iter().chain(additional) {
                    cancellation_observed |= poll_reverse_completion(cancellation, work);
                    canonical.insert(reason);
                }
                let mut reasons = Vec::with_capacity(canonical.len());
                while let Some(reason) = canonical.pop_first() {
                    cancellation_observed |= poll_reverse_completion(cancellation, work);
                    reasons.push(reason);
                }
                assert!(
                    !reasons.is_empty(),
                    "incomplete resolution requires a reason"
                );
                reasons
            }
        };
        cancellation_observed |= cancellation.is_cancelled();
        let completion = if has_incomplete_operand {
            ResolutionCompletion::Incomplete(reasons.into_boxed_slice().into())
        } else {
            ResolutionCompletion::Complete
        };
        (completion, cancellation_observed)
    }

    pub(super) fn finish(
        self,
        cancellation: &CancellationToken,
        work: &mut usize,
    ) -> (ResolutionCompletion, bool) {
        let (completion, mut cancellation_observed) = self.finish_semantic(cancellation, work);
        if !cancellation_observed {
            return (completion, false);
        }

        let mut reasons = match completion {
            ResolutionCompletion::Complete => Vec::new(),
            ResolutionCompletion::Incomplete(reasons) => reasons.into_vec(),
        };
        // Combining cancellation with a sole publicly constructible
        // noncanonical box must canonicalize just like `combine` does.
        let mut canonical = BTreeSet::new();
        canonical.insert(ResolutionIncompleteReason::Cancelled);
        for reason in reasons {
            cancellation_observed |= poll_reverse_completion(cancellation, work);
            canonical.insert(reason);
        }
        reasons = Vec::with_capacity(canonical.len());
        while let Some(reason) = canonical.pop_first() {
            cancellation_observed |= poll_reverse_completion(cancellation, work);
            reasons.push(reason);
        }
        let completion = raw_completion(reasons);
        (completion, cancellation_observed)
    }
}

/// Completion reasons that are semantically invisible on success.
///
/// A cancelled traversal must retain every reason from source-owned rows and
/// discarded paths, but combining those operands with successful output would
/// double-count public empty or noncanonical `Incomplete` boxes. This ledger
/// therefore records a canonical reason union only for the cancellation
/// fallback. Empty operands
/// contribute no reason; the fallback always adds `Cancelled`, so it remains
/// a valid incomplete completion.
#[derive(Debug, Default)]
pub(super) struct CancellationEvidenceLedger {
    state: CancellationEvidenceState,
    cancellation_observed: bool,
}

#[derive(Debug)]
enum CancellationEvidenceState {
    Raw(BTreeSet<ResolutionIncompleteReason>),
}

impl Default for CancellationEvidenceState {
    fn default() -> Self {
        Self::Raw(BTreeSet::new())
    }
}

impl CancellationEvidenceLedger {
    pub(super) fn include(
        &mut self,
        completion: &ResolutionCompletion,
        cancellation: &CancellationToken,
        work: &mut usize,
    ) -> bool {
        let mut cancellation_observed = cancellation.is_cancelled();
        cancellation_observed |= poll_reverse_completion(cancellation, work);
        if let ResolutionCompletion::Incomplete(incoming) = completion {
            let CancellationEvidenceState::Raw(reasons) = &mut self.state;
            for &reason in incoming.iter() {
                cancellation_observed |= poll_reverse_completion(cancellation, work);
                cancellation_observed |= reason == ResolutionIncompleteReason::Cancelled;
                reasons.insert(reason);
            }
        }
        self.cancellation_observed |= cancellation_observed | cancellation.is_cancelled();
        self.cancellation_observed
    }

    pub(super) fn include_reason(&mut self, reason: ResolutionIncompleteReason) {
        let state = std::mem::take(&mut self.state);
        self.state = match state {
            CancellationEvidenceState::Raw(mut reasons) => {
                reasons.insert(reason);
                CancellationEvidenceState::Raw(reasons)
            }
        };
        self.cancellation_observed |= reason == ResolutionIncompleteReason::Cancelled;
    }

    pub(super) fn observe_row(
        &mut self,
        cancellation: &CancellationToken,
        work: &mut usize,
    ) -> bool {
        self.cancellation_observed |= poll_reverse_completion(cancellation, work);
        self.cancellation_observed |= cancellation.is_cancelled();
        self.cancellation_observed
    }

    pub(super) const fn cancellation_observed(&self) -> bool {
        self.cancellation_observed
    }

    pub(super) fn finish(
        mut self,
        force_cancelled: bool,
        cancellation: &CancellationToken,
        work: &mut usize,
    ) -> (ResolutionCompletion, bool) {
        let mut cancellation_observed =
            force_cancelled | self.cancellation_observed | cancellation.is_cancelled();
        let state = std::mem::take(&mut self.state);
        let mut completion = match state {
            CancellationEvidenceState::Raw(mut reasons) => {
                if cancellation_observed {
                    reasons.insert(ResolutionIncompleteReason::Cancelled);
                }
                let mut canonical = Vec::with_capacity(reasons.len());
                while let Some(reason) = reasons.pop_first() {
                    cancellation_observed |= poll_reverse_completion(cancellation, work);
                    canonical.push(reason);
                }
                if canonical.is_empty() {
                    ResolutionCompletion::Complete
                } else {
                    raw_completion(canonical)
                }
            }
        };
        cancellation_observed |= cancellation.is_cancelled();
        if cancellation_observed
            && !completion.contains_reason(ResolutionIncompleteReason::Cancelled)
        {
            completion = observational_combine_completion(
                &completion,
                &raw_completion(vec![ResolutionIncompleteReason::Cancelled]),
                cancellation,
                work,
                &mut cancellation_observed,
            );
        }
        (completion, cancellation_observed)
    }
}

fn poll_reverse_completion(cancellation: &CancellationToken, work: &mut usize) -> bool {
    *work = work
        .checked_add(1)
        .expect("reverse completion work must fit usize");
    (*work).is_multiple_of(CANCELLATION_QUANTUM) && cancellation.is_cancelled()
}

fn include_forward_matched_hydrated_completions_after_cancellation(
    seeds: &mut [SeedState],
    expandable: &[BatchWorkPath],
    matches: &[BatchCandidateMatch],
    arena: &crate::hash::HashMap<CandidatePathIdentity, PartialPath>,
    accounted: &mut crate::hash::HashSet<(usize, CandidatePathIdentity)>,
    cancellation: &CancellationToken,
    work: &mut usize,
) {
    for matched in matches {
        let _ = poll_reverse_completion(cancellation, work);
        if matched.request_ordinal() >= expandable.len() {
            continue;
        }
        let seed = expandable[matched.request_ordinal()].seed;
        let key = (seed, matched.candidate());
        if accounted.contains(&key) {
            continue;
        }
        let Some(candidate) = arena.get(&matched.candidate()) else {
            continue;
        };
        let _ = seeds[seed]
            .observed_completion
            .include(candidate.completion(), cancellation, work);
        accounted.insert(key);
    }
}

fn include_forward_returned_hydrated_completions_after_cancellation(
    seeds: &mut [SeedState],
    expandable: &[BatchWorkPath],
    matches: &[BatchCandidateMatch],
    hydrated: &[(CandidatePathIdentity, PartialPath)],
    accounted: &mut crate::hash::HashSet<(usize, CandidatePathIdentity)>,
    cancellation: &CancellationToken,
    work: &mut usize,
) {
    for (identity, candidate) in hydrated {
        for matched in matches {
            let _ = poll_reverse_completion(cancellation, work);
            if matched.request_ordinal() >= expandable.len() || matched.candidate() != *identity {
                continue;
            }
            let seed = expandable[matched.request_ordinal()].seed;
            if accounted.insert((seed, *identity)) {
                let _ = seeds[seed].observed_completion.include(
                    candidate.completion(),
                    cancellation,
                    work,
                );
            }
        }
    }
}

fn include_forward_hydrated_completions_for_seed_indices_after_cancellation(
    seeds: &mut [SeedState],
    request_seed_indices: &[usize],
    matches: &[BatchCandidateMatch],
    arena: &crate::hash::HashMap<CandidatePathIdentity, PartialPath>,
    accounted: &mut crate::hash::HashSet<(usize, CandidatePathIdentity)>,
    cancellation: &CancellationToken,
    work: &mut usize,
) {
    for matched in matches {
        let _ = poll_reverse_completion(cancellation, work);
        let Some(&seed) = request_seed_indices.get(matched.request_ordinal()) else {
            continue;
        };
        let key = (seed, matched.candidate());
        if accounted.contains(&key) {
            continue;
        }
        let Some(candidate) = arena.get(&matched.candidate()) else {
            continue;
        };
        let _ = seeds[seed]
            .observed_completion
            .include(candidate.completion(), cancellation, work);
        accounted.insert(key);
    }
}

fn append_streamed_candidate_match_page(
    matches: &mut Vec<BatchCandidateMatch>,
    page: &[BatchCandidateMatch],
    request_count: usize,
    seen: &mut HashSet<(usize, CandidatePathIdentity)>,
    cancellation: &CancellationToken,
    work: &mut usize,
    cancellation_observed: &mut bool,
) -> StoreResult<bool> {
    if page.is_empty() || page.len() > MAX_SOURCE_ROWS_PER_BATCH {
        return Err(StoreError::new(format!(
            "candidate match page has {} rows; expected 1..={MAX_SOURCE_ROWS_PER_BATCH}",
            page.len()
        )));
    }
    for &matched in page {
        *cancellation_observed |= poll_reverse_completion(cancellation, work);
        if matched.request_ordinal() >= request_count {
            if *cancellation_observed || cancellation.is_cancelled() {
                continue;
            }
            return Err(StoreError::new(format!(
                "candidate {:?} names invalid batch request {} of {}",
                matched.candidate(),
                matched.request_ordinal(),
                request_count
            )));
        }
        let key = (matched.request_ordinal(), matched.candidate());
        if !*cancellation_observed && !seen.insert(key) {
            return Err(StoreError::new(format!(
                "candidate match pages repeated natural identity {key:?}"
            )));
        }
        matches.push(BatchCandidateMatch::new(
            matched.candidate(),
            matched.request_ordinal(),
        ));
    }
    *cancellation_observed |= cancellation.is_cancelled();
    Ok(!*cancellation_observed)
}

fn canonicalize_streamed_candidate_matches(
    matches: &mut Vec<BatchCandidateMatch>,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> StoreResult<bool> {
    let mut canonical = BTreeSet::new();
    for &matched in matches.iter() {
        if poll_reverse_completion(cancellation, work) {
            return Ok(false);
        }
        let identity = (matched.request_ordinal(), matched.candidate());
        if !canonical.insert(identity) {
            return Err(StoreError::new(format!(
                "candidate matches repeated natural identity {identity:?}"
            )));
        }
    }

    let mut ordered = Vec::with_capacity(canonical.len());
    while let Some((request_ordinal, candidate)) = canonical.pop_first() {
        if poll_reverse_completion(cancellation, work) {
            return Ok(false);
        }
        ordered.push(BatchCandidateMatch::new(candidate, request_ordinal));
    }
    if cancellation.is_cancelled() {
        return Ok(false);
    }
    *matches = ordered;
    Ok(true)
}

fn copy_returned_completion(
    completion: &ResolutionCompletion,
    cancellation: &CancellationToken,
    resolution_session: Option<&ResolutionSession>,
    work: &mut usize,
    cancelled: &mut bool,
) -> ResolutionCompletion {
    if let ResolutionCompletion::Incomplete(reasons) = completion {
        for _ in 0..reasons.clone_work_len() {
            if resolution_session.is_some_and(|session| !session.scope_step()) {
                *cancelled = true;
                break;
            }
        }
    }
    let mut ledger = BatchCompletionLedger::default();
    *cancelled |= ledger.include(completion, cancellation, work);
    let (completion, observed) = ledger.finish_semantic(cancellation, work);
    *cancelled |= observed;
    completion
}

pub(super) fn read_forward_candidate_artifacts<S: BatchResolutionFragmentSource + ?Sized>(
    source: &S,

    requests: &[BatchCandidateRequest],
    cancellation: &CancellationToken,
    resolution_session: Option<&ResolutionSession>,
    work: &mut usize,
    cancelled: &mut bool,
) -> StoreResult<(
    Vec<BatchCandidateMatch>,
    ResolutionCompletion,
    Box<[ResolutionCompletion]>,
)> {
    let mut candidates_by_request = vec![Vec::new(); requests.len()];
    let mut branch_completions = vec![None; requests.len()];
    let mut missing = Vec::new();
    let mut missing_to_requests = Vec::<Vec<usize>>::new();
    let mut missing_by_endpoint = HashMap::<EndpointSignature, usize>::default();
    let mut unconditional = None;

    for (request_ordinal, request) in requests.iter().enumerate() {
        if poll_reverse_completion(cancellation, work) {
            *cancelled = true;
            break;
        }
        let Some(endpoint) = request
            .endpoint()
            .clone_with_poll(&mut || poll_reverse_completion(cancellation, work))
        else {
            *cancelled = true;
            break;
        };
        if let Some(&missing_ordinal) = missing_by_endpoint.get(&endpoint) {
            missing_to_requests[missing_ordinal].push(request_ordinal);
        } else {
            let Some(endpoint_key) =
                endpoint.clone_with_poll(&mut || poll_reverse_completion(cancellation, work))
            else {
                *cancelled = true;
                break;
            };
            let missing_ordinal = missing.len();
            assert!(
                missing_by_endpoint
                    .insert(endpoint_key, missing_ordinal)
                    .is_none()
            );
            missing_to_requests.push(vec![request_ordinal]);
            missing.push(BatchCandidateRequest::new(missing_ordinal, endpoint));
        }
    }

    if *cancelled {
        return Ok((
            Vec::new(),
            unconditional.unwrap_or(ResolutionCompletion::Complete),
            branch_completions
                .into_iter()
                .map(|completion| completion.unwrap_or(ResolutionCompletion::Complete))
                .collect(),
        ));
    }

    let mut source_matches = Vec::new();
    if !missing.is_empty() {
        let mut seen_page_matches = HashSet::default();
        let maximum_page_rows = resolution_session.map_or(MAX_SOURCE_ROWS_PER_BATCH, |session| {
            session
                .scope_lookahead_limit()
                .clamp(1, MAX_SOURCE_ROWS_PER_BATCH)
        });
        let outcome = source.visit_forward_candidate_match_pages_limited(
            &missing,
            maximum_page_rows,
            resolution_session,
            cancellation,
            &mut |page| {
                if resolution_session
                    .is_some_and(|session| page.iter().any(|_| !session.scope_step()))
                {
                    *cancelled = true;
                    return Ok(false);
                }
                append_streamed_candidate_match_page(
                    &mut source_matches,
                    page,
                    missing.len(),
                    &mut seen_page_matches,
                    cancellation,
                    work,
                    cancelled,
                )
            },
        )?;
        let (returned_unconditional, branches) = outcome.into_parts();
        let source_branches = branches;
        assert_eq!(source_branches.len(), missing.len());

        // The completion outcome is atomic even if row visitation stopped.
        // Drain every returned box in full before touching affirmative rows.
        // Cancellation is observational during these copies: it suppresses
        // row publication but cannot truncate returned evidence.
        let copied_unconditional = copy_returned_completion(
            &returned_unconditional,
            cancellation,
            resolution_session,
            work,
            cancelled,
        );
        for (missing_ordinal, request_ordinals) in missing_to_requests.iter().enumerate() {
            for &request_ordinal in request_ordinals {
                let branch_completion = copy_returned_completion(
                    &source_branches[missing_ordinal],
                    cancellation,
                    resolution_session,
                    work,
                    cancelled,
                );
                branch_completions[request_ordinal] = Some(branch_completion);
            }
        }

        unconditional = Some(copied_unconditional);

        if !*cancelled
            && !canonicalize_streamed_candidate_matches(&mut source_matches, cancellation, work)?
        {
            *cancelled = true;
        }
        if !*cancelled {
            for matched in &source_matches {
                if poll_reverse_completion(cancellation, work) {
                    *cancelled = true;
                    break;
                }
                for &request_ordinal in &missing_to_requests[matched.request_ordinal()] {
                    if poll_reverse_completion(cancellation, work) {
                        *cancelled = true;
                        break;
                    }
                    candidates_by_request[request_ordinal].push(matched.candidate());
                }
                if *cancelled {
                    break;
                }
            }
        }
    }

    let unconditional = unconditional.unwrap_or_else(|| {
        assert!(
            requests.is_empty(),
            "nonempty forward requests require source unconditional evidence"
        );
        ResolutionCompletion::Complete
    });

    *cancelled |= cancellation.is_cancelled();

    if *cancelled {
        return Ok((
            Vec::new(),
            unconditional,
            branch_completions
                .into_iter()
                .map(|completion| completion.unwrap_or(ResolutionCompletion::Complete))
                .collect(),
        ));
    }

    let mut matches = Vec::new();
    for (request_ordinal, candidates) in candidates_by_request.into_iter().enumerate() {
        for candidate in candidates {
            if poll_reverse_completion(cancellation, work) {
                *cancelled = true;
                break;
            }
            matches.push(BatchCandidateMatch::new(candidate, request_ordinal));
        }
        if *cancelled {
            break;
        }
    }
    let branches = branch_completions
        .into_iter()
        .map(|completion| {
            completion.unwrap_or_else(|| {
                assert!(
                    *cancelled,
                    "a live candidate request has one branch completion"
                );
                ResolutionCompletion::Complete
            })
        })
        .collect::<Vec<_>>()
        .into_boxed_slice();
    Ok((matches, unconditional, branches))
}

fn align_endpoint_classifications_with_poll(
    requested: &[BindingNodeId],
    classified: Vec<BatchEndpointClassification>,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> StoreResult<Option<Vec<BatchEndpointClassification>>> {
    let mut by_node = BTreeMap::new();
    for classification in classified {
        if poll_reverse_completion(cancellation, work) {
            return Ok(None);
        }
        if by_node
            .insert(classification.node(), classification)
            .is_some()
        {
            return Err(StoreError::new(format!(
                "endpoint classification returned duplicate node {}",
                classification.node()
            )));
        }
    }

    let mut aligned = Vec::with_capacity(requested.len());
    for &node in requested {
        if poll_reverse_completion(cancellation, work) {
            return Ok(None);
        }
        let Some(classification) = by_node.remove(&node) else {
            return Err(StoreError::new(format!(
                "endpoint classification omitted requested node {node}; unrequested rows: {:?}",
                by_node.keys().collect::<Vec<_>>()
            )));
        };
        aligned.push(classification);
    }
    if !by_node.is_empty() {
        return Err(StoreError::new(format!(
            "endpoint classification returned unrequested rows: {:?}",
            by_node.keys().collect::<Vec<_>>()
        )));
    }
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    Ok(Some(aligned))
}

fn validate_hydration_with_poll(
    requested: &[CandidatePathIdentity],
    hydrated: &[(CandidatePathIdentity, PartialPath)],
    cancellation: &CancellationToken,
    work: &mut usize,
) -> StoreResult<Option<()>> {
    let mut returned = BTreeSet::new();
    for (identity, _) in hydrated {
        if poll_reverse_completion(cancellation, work) {
            return Ok(None);
        }
        if !returned.insert(*identity) {
            return Err(StoreError::new(format!(
                "candidate hydration returned duplicate identity {identity:?}"
            )));
        }
    }
    for identity in requested {
        if poll_reverse_completion(cancellation, work) {
            return Ok(None);
        }
        if !returned.remove(identity) {
            return Err(StoreError::new(format!(
                "candidate hydration omitted requested identity {identity:?}; unrequested rows: {returned:?}"
            )));
        }
    }
    if !returned.is_empty() {
        return Err(StoreError::new(format!(
            "candidate hydration returned unrequested identities: {returned:?}"
        )));
    }
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    Ok(Some(()))
}

/// Operation-local bounded stitching over immutable fragment rows.
pub struct BatchResolutionEngine<'a, S: BatchResolutionFragmentSource + ?Sized> {
    source: &'a S,
    resolution_session: Option<&'a ResolutionSession>,
}

impl<'a, S: BatchResolutionFragmentSource + ?Sized> BatchResolutionEngine<'a, S> {
    pub const fn new(source: &'a S) -> Self {
        Self {
            source,
            resolution_session: None,
        }
    }

    /// Attach the caller-owned session for one operation, bounded or unbounded.
    /// Pass its cancellation token (or the same compatible caller context) to
    /// evaluation. `ResolutionSession::finish(answer)` is authoritative for
    /// Complete, Exceeded, or Cancelled; a stopped engine answer alone is not a
    /// final bounded result. Keep the session alive through publication.
    pub const fn with_session(source: &'a S, session: &'a ResolutionSession) -> Self {
        Self {
            source,
            resolution_session: Some(session),
        }
    }

    fn source(&self) -> &S {
        self.source
    }

    fn charge_scope_steps(&self, count: usize) -> bool {
        self.resolution_session
            .is_none_or(|session| (0..count).all(|_| session.scope_step()))
    }

    fn charge_summary_step(&self) -> bool {
        self.resolution_session
            .is_none_or(ResolutionSession::summary_step)
    }

    /// Resolve one reference through the exact arity-one batch path.
    pub fn resolve_reference(
        &self,
        query: ResolutionQuery,
        cancellation: &CancellationToken,
    ) -> StoreResult<ResolutionAnswer> {
        self.resolve_reference_with_metrics(query, cancellation)
            .map(|(answer, _)| answer)
    }

    fn resolve_reference_with_metrics(
        &self,
        query: ResolutionQuery,
        cancellation: &CancellationToken,
    ) -> StoreResult<(ResolutionAnswer, ResolutionBatchMetrics)> {
        if cancellation.is_cancelled() {
            return Ok((
                empty_answer(cancelled_completion()),
                ResolutionBatchMetrics::default(),
            ));
        }
        if !self.charge_scope_steps(1) {
            return Ok((
                empty_answer(cancelled_completion()),
                ResolutionBatchMetrics::default(),
            ));
        }
        let seed = self.source().reference_seed(query, cancellation)?;
        let Some(seed) = seed else {
            return Ok((
                if cancellation.is_cancelled() {
                    empty_answer(cancelled_completion())
                } else {
                    empty_answer(ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(query.reference()),
                    ]))
                },
                ResolutionBatchMetrics::default(),
            ));
        };
        let mut work = 0_usize;
        let mut completion = BatchCompletionLedger::default();
        let cancelled = completion.include(seed.completion(), cancellation, &mut work);
        if cancelled || cancellation.is_cancelled() {
            let (completion, _) = completion.finish(cancellation, &mut work);
            return Ok((empty_answer(completion), ResolutionBatchMetrics::default()));
        }
        let request = SeededReferenceRequest::identity_with_poll(seed, &mut || {
            poll_reverse_completion(cancellation, &mut work)
        });
        let Some(request) = request else {
            let (completion, _) = completion.finish(cancellation, &mut work);
            return Ok((empty_answer(completion), ResolutionBatchMetrics::default()));
        };
        self.resolve_seeded_reference_with_metrics(&request, cancellation)
    }

    /// Resolve one reference from caller-supplied operation-local paths.
    ///
    /// All alternatives share one saturation quotient, completed-path set,
    /// and final precedence selection. Resolving each path independently and
    /// unioning the answers would make cross-owner shadowing impossible and is
    /// deliberately not an implementation of this operation.
    pub fn resolve_seeded_reference(
        &self,
        request: &SeededReferenceRequest,
        cancellation: &CancellationToken,
    ) -> StoreResult<ResolutionAnswer> {
        self.resolve_seeded_reference_with_metrics(request, cancellation)
            .map(|(answer, _)| answer)
    }

    fn resolve_seeded_reference_with_metrics(
        &self,
        request: &SeededReferenceRequest,
        cancellation: &CancellationToken,
    ) -> StoreResult<(ResolutionAnswer, ResolutionBatchMetrics)> {
        let batch =
            self.resolve_seeded_reference_requests(std::slice::from_ref(request), cancellation)?;
        assert_eq!(
            batch.answers.len(),
            1,
            "an arity-one seeded batch must return exactly one answer"
        );
        let mut answers = batch.answers.into_vec();
        Ok((
            answers
                .pop()
                .expect("an arity-one seeded batch has one asserted answer")
                .answer,
            batch.metrics,
        ))
    }

    /// Resolve one same-fragment seed batch with a single bounded arena.
    pub fn resolve_reference_batch(
        &self,
        batch: &ReferenceSeedBatch,
        cancellation: &CancellationToken,
    ) -> StoreResult<ReferenceBatchAnswer> {
        self.resolve_reference_batch_impl(batch, cancellation)
    }

    fn resolve_reference_batch_impl(
        &self,
        batch: &ReferenceSeedBatch,
        cancellation: &CancellationToken,
    ) -> StoreResult<ReferenceBatchAnswer> {
        let mut work = 0_usize;
        let (prepared, mut cancelled) =
            prepare_reference_seed_completions(batch.seeds(), cancellation, &mut work);
        if !self.charge_scope_steps(batch.len()) {
            return Ok(cancelled_prepared_seed_answers(
                prepared,
                ResolutionBatchMetrics {
                    reference_seeds: batch.len(),
                    batches: 1,
                    ..ResolutionBatchMetrics::default()
                },
                cancellation,
                &mut work,
            ));
        }
        let mut requests = Vec::with_capacity(batch.len());
        if !cancelled {
            for seed in batch.seeds() {
                let seed =
                    seed.clone_with_poll(&mut || poll_reverse_completion(cancellation, &mut work));
                let Some(seed) = seed else {
                    cancelled = true;
                    break;
                };
                let request = SeededReferenceRequest::identity_with_poll(seed, &mut || {
                    poll_reverse_completion(cancellation, &mut work)
                });
                let Some(request) = request else {
                    cancelled = true;
                    break;
                };
                requests.push(request);
            }
        }
        if cancelled || cancellation.is_cancelled() {
            return Ok(cancelled_prepared_seed_answers(
                prepared,
                ResolutionBatchMetrics {
                    reference_seeds: batch.len(),
                    batches: 1,
                    ..ResolutionBatchMetrics::default()
                },
                cancellation,
                &mut work,
            ));
        }
        self.resolve_seeded_reference_requests(&requests, cancellation)
    }

    fn initialize_seeded_reference_batch(
        &self,
        requests: &[SeededReferenceRequest],
        cancellation: &CancellationToken,
    ) -> SeededBatchInitialization {
        let metrics = ResolutionBatchMetrics {
            reference_seeds: requests.len(),
            batches: 1,
            ..ResolutionBatchMetrics::default()
        };
        if cancellation.is_cancelled() {
            return SeededBatchInitialization::Cancelled(cancelled_seeded_answers(
                requests,
                metrics,
                cancellation,
            ));
        }

        // Retain every caller/source-owned completion box before structural
        // initialization, so cancellation cannot lose a later request's
        // already-returned evidence.
        let mut completion_work = 0_usize;
        let mut cancelled = false;
        let mut prepared = Vec::with_capacity(requests.len());
        for request in requests {
            cancelled |= poll_reverse_completion(cancellation, &mut completion_work);
            let mut completion = BatchCompletionLedger::default();
            cancelled |= completion.include(
                request.seed().completion(),
                cancellation,
                &mut completion_work,
            );
            let mut observed_completion = CancellationEvidenceLedger::default();
            for alternative in request.alternatives() {
                cancelled |= observed_completion.include(
                    alternative.path().completion(),
                    cancellation,
                    &mut completion_work,
                );
            }
            prepared.push(PreparedSeed {
                reference: request.seed().reference(),
                completion,
                observed_completion,
            });
        }
        if cancelled || cancellation.is_cancelled() {
            return SeededBatchInitialization::Cancelled(cancelled_prepared_seed_answers(
                prepared,
                metrics,
                cancellation,
                &mut completion_work,
            ));
        }

        let mut frontier = Vec::new();
        let mut certifiers = Vec::with_capacity(requests.len());
        let mut endpoint_definitions = map_with_capacity(requests.len().saturating_mul(4));
        for (seed_index, request) in requests.iter().enumerate() {
            if poll_reverse_completion(cancellation, &mut completion_work) {
                cancelled = true;
                break;
            }
            let reference_seed = request.seed();
            let reference = reference_seed.reference();
            assert!(
                endpoint_definitions
                    .insert(reference_seed.node(), None)
                    .is_none(),
                "a reference batch cannot contain two semantics for node {}",
                reference_seed.node()
            );
            let certifier = CycleCompletenessCertifier::from_initial_paths_with_poll(
                request.alternatives().iter().map(SeededPartialPath::path),
                &mut || poll_reverse_completion(cancellation, &mut completion_work),
            );
            let Some(certifier) = certifier else {
                cancelled = true;
                break;
            };
            certifiers.push(certifier);
            for alternative in request.alternatives() {
                let path = alternative.path().clone_with_poll(&mut || {
                    poll_reverse_completion(cancellation, &mut completion_work)
                });
                let Some(path) = path else {
                    cancelled = true;
                    break;
                };
                frontier.push(BatchWorkPath {
                    seed: seed_index,
                    path,
                    derivation: seeded_derivation(reference, alternative.identity()),
                    saturation: SaturationBranch::default(),
                });
            }
            if cancelled {
                break;
            }
        }
        if cancelled || cancellation.is_cancelled() {
            return SeededBatchInitialization::Cancelled(cancelled_prepared_seed_answers(
                prepared,
                metrics,
                cancellation,
                &mut completion_work,
            ));
        }
        assert_eq!(certifiers.len(), prepared.len());
        let mut seeds = Vec::with_capacity(prepared.len());
        for (prepared, certifier) in prepared.into_iter().zip(certifiers) {
            cancelled |= poll_reverse_completion(cancellation, &mut completion_work);
            seeds.push(SeedState {
                reference: prepared.reference,
                completed: Vec::new(),
                terminals: Vec::new(),
                completion: prepared.completion,
                observed_completion: prepared.observed_completion,
                certifier,
            });
        }

        SeededBatchInitialization::Ready(InitializedSeededBatch {
            metrics,
            completion_work,
            frontier,
            seeds,
            endpoint_definitions,
            cancelled,
        })
    }

    fn retain_forward_hydration_cancellation(
        context: &mut ForwardHydrationContext<'_>,
        cancellation: &CancellationToken,
    ) {
        include_forward_matched_hydrated_completions_after_cancellation(
            context.seeds,
            context.expandable,
            context.matches,
            context.arena,
            context.accounted_completions,
            cancellation,
            context.completion_work,
        );
    }

    fn prepare_forward_hydration(
        &self,
        mut context: ForwardHydrationContext<'_>,

        cancellation: &CancellationToken,
    ) -> ForwardHydrationRequest {
        context.metrics.distinct_candidate_matches += context.matches.len();
        context.metrics.peak_candidate_matches = context
            .metrics
            .peak_candidate_matches
            .max(context.matches.len());

        let mut hydration_set = BTreeSet::new();
        for matched in context.matches {
            if poll_reverse_completion(cancellation, context.completion_work) {
                *context.cancelled = true;
                break;
            }
            if !context.arena.contains_key(&matched.candidate()) {
                hydration_set.insert(matched.candidate());
            }
        }
        if *context.cancelled {
            Self::retain_forward_hydration_cancellation(&mut context, cancellation);
            return ForwardHydrationRequest {
                candidates: Vec::new(),
            };
        }

        if *context.cancelled {
            Self::retain_forward_hydration_cancellation(&mut context, cancellation);
            return ForwardHydrationRequest {
                candidates: Vec::new(),
            };
        }

        let mut candidates = Vec::with_capacity(hydration_set.len());
        while let Some(candidate) = hydration_set.pop_first() {
            if poll_reverse_completion(cancellation, context.completion_work) {
                *context.cancelled = true;
                break;
            }
            candidates.push(candidate);
        }
        if *context.cancelled {
            Self::retain_forward_hydration_cancellation(&mut context, cancellation);
        }
        ForwardHydrationRequest { candidates }
    }

    fn hydrate_forward_candidates(
        &self,
        mut context: ForwardHydrationContext<'_>,
        request: &ForwardHydrationRequest,

        cancellation: &CancellationToken,
    ) -> StoreResult<()> {
        if request.candidates.is_empty() {
            return Ok(());
        }
        if !self.charge_scope_steps(request.candidates.len()) {
            *context.cancelled = true;
            Self::retain_forward_hydration_cancellation(&mut context, cancellation);
            return Ok(());
        }

        let mut missing_hydrations = Vec::new();

        missing_hydrations.extend_from_slice(&request.candidates);

        if *context.cancelled {
            Self::retain_forward_hydration_cancellation(&mut context, cancellation);
            return Ok(());
        }

        for requested in missing_hydrations.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
            let hydrated = self
                .source()
                .hydrate_candidate_paths(requested, cancellation)?;
            let mut hydration_cancelled = cancellation.is_cancelled();
            if !hydration_cancelled {
                hydration_cancelled = validate_hydration_with_poll(
                    requested,
                    &hydrated,
                    cancellation,
                    context.completion_work,
                )?
                .is_none();
            }
            if hydration_cancelled {
                include_forward_returned_hydrated_completions_after_cancellation(
                    context.seeds,
                    context.expandable,
                    context.matches,
                    &hydrated,
                    context.accounted_completions,
                    cancellation,
                    context.completion_work,
                );
                Self::retain_forward_hydration_cancellation(&mut context, cancellation);
                *context.cancelled = true;
                break;
            }

            if hydration_cancelled || cancellation.is_cancelled() {
                include_forward_returned_hydrated_completions_after_cancellation(
                    context.seeds,
                    context.expandable,
                    context.matches,
                    &hydrated,
                    context.accounted_completions,
                    cancellation,
                    context.completion_work,
                );
                Self::retain_forward_hydration_cancellation(&mut context, cancellation);
                *context.cancelled = true;
                break;
            }

            for (identity, path) in hydrated {
                hydration_cancelled |=
                    poll_reverse_completion(cancellation, context.completion_work);
                assert!(
                    context.arena.insert(identity, path).is_none(),
                    "a candidate path is hydrated at most once per batch"
                );
                context.metrics.distinct_path_hydrations += 1;
            }
            hydration_cancelled |= cancellation.is_cancelled();
            if hydration_cancelled {
                Self::retain_forward_hydration_cancellation(&mut context, cancellation);
                *context.cancelled = true;
                break;
            }
        }
        if !*context.cancelled {
            context.metrics.peak_hydrated_paths =
                context.metrics.peak_hydrated_paths.max(context.arena.len());
        }
        Ok(())
    }

    fn finish_seeded_reference_batch(
        &self,
        seeds: Vec<SeedState>,
        metrics: ResolutionBatchMetrics,
        cancellation: &CancellationToken,
        mut cancelled: bool,
        mut completion_work: usize,
    ) -> ReferenceBatchAnswer {
        cancelled |= cancellation.is_cancelled();
        let mut answer = select_seed_answers(
            seeds,
            metrics,
            cancellation,
            cancelled,
            &mut completion_work,
        );
        if cancellation.is_cancelled() {
            answer = mark_batch_cancelled(answer, cancellation, &mut completion_work);
        }
        answer
    }

    fn resolve_seeded_reference_requests(
        &self,
        requests: &[SeededReferenceRequest],
        cancellation: &CancellationToken,
    ) -> StoreResult<ReferenceBatchAnswer> {
        let InitializedSeededBatch {
            mut metrics,
            mut completion_work,
            mut frontier,
            mut seeds,
            mut endpoint_definitions,
            mut cancelled,
        } = match self.initialize_seeded_reference_batch(requests, cancellation) {
            SeededBatchInitialization::Ready(initialized) => initialized,
            SeededBatchInitialization::Cancelled(answer) => return Ok(answer),
        };
        let mut arena = map_with_capacity(requests.len().saturating_mul(4));
        let mut accounted_hydrated_completions = crate::hash::HashSet::default();
        let mut candidate_completion = OperationCandidateCompletionLedger::new(seeds.len());
        while !cancelled && !frontier.is_empty() {
            if cancellation.is_cancelled() {
                cancelled = true;
                break;
            }
            if !self.charge_summary_step() {
                cancelled = true;
                break;
            }
            metrics.worklist_rounds += 1;
            metrics.peak_frontier_paths = metrics.peak_frontier_paths.max(frontier.len());

            let current = std::mem::take(&mut frontier);
            let mut unclassified = BTreeSet::new();
            for state in &current {
                if poll_reverse_completion(cancellation, &mut completion_work) {
                    cancelled = true;
                    break;
                }
                let node = state.path.end().node();
                if !endpoint_definitions.contains_key(&node) {
                    unclassified.insert(node);
                }
            }
            if cancelled {
                break;
            }
            let mut to_classify = Vec::with_capacity(unclassified.len());
            while let Some(node) = unclassified.pop_first() {
                if poll_reverse_completion(cancellation, &mut completion_work) {
                    cancelled = true;
                    break;
                }
                to_classify.push(node);
            }
            if cancelled {
                break;
            }
            if !to_classify.is_empty() {
                if !self.charge_scope_steps(to_classify.len()) {
                    cancelled = true;
                    break;
                }
                let missing = to_classify;

                if cancelled {
                    break;
                }
                for requested in missing.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
                    let classified = self
                        .source()
                        .classify_endpoint_nodes(requested, cancellation)?;
                    if cancellation.is_cancelled() {
                        cancelled = true;
                        break;
                    }
                    let Some(classified) = align_endpoint_classifications_with_poll(
                        requested,
                        classified,
                        cancellation,
                        &mut completion_work,
                    )?
                    else {
                        cancelled = true;
                        break;
                    };

                    for classification in classified {
                        if poll_reverse_completion(cancellation, &mut completion_work) {
                            cancelled = true;
                            break;
                        }
                        assert!(
                            endpoint_definitions
                                .insert(classification.node(), classification.definition())
                                .is_none(),
                            "an endpoint is classified at most once per batch"
                        );
                        metrics.distinct_endpoint_classifications += 1;
                    }
                    if cancelled {
                        break;
                    }
                }
                if cancelled {
                    break;
                }
                metrics.peak_classified_endpoints = metrics
                    .peak_classified_endpoints
                    .max(endpoint_definitions.len());
            }

            let mut expandable = Vec::with_capacity(current.len());
            let mut expandable_seed_indices = Vec::with_capacity(current.len());
            for state in current {
                if poll_reverse_completion(cancellation, &mut completion_work) {
                    cancelled = true;
                    break;
                }
                if endpoint_is_balanced(state.path.end())
                    && let Some(target) = endpoint_definitions
                        .get(&state.path.end().node())
                        .copied()
                        .flatten()
                {
                    seeds[state.seed].completed.push(CompletedPath {
                        target,
                        path: state.path,
                    });
                } else {
                    expandable_seed_indices.push(state.seed);
                    expandable.push(state);
                }
            }
            if cancelled {
                break;
            }
            if expandable.is_empty() {
                continue;
            }

            let mut terminalized = HashSet::default();
            let mut matches = Vec::new();
            for (page_index, state_page) in expandable.chunks(MAX_SOURCE_ROWS_PER_BATCH).enumerate()
            {
                let request_base = page_index * MAX_SOURCE_ROWS_PER_BATCH;
                let mut request_page = Vec::with_capacity(state_page.len());
                for (request_ordinal, state) in state_page.iter().enumerate() {
                    let endpoint = state.path.end().clone_with_poll(&mut || {
                        poll_reverse_completion(cancellation, &mut completion_work)
                    });
                    let Some(endpoint) = endpoint else {
                        cancelled = true;
                        break;
                    };
                    request_page.push(BatchCandidateRequest::new(request_ordinal, endpoint));
                }
                if cancelled {
                    break;
                }
                let (page_matches, unconditional_completion, branch_completions) =
                    read_forward_candidate_artifacts(
                        self.source(),
                        &request_page,
                        cancellation,
                        self.resolution_session,
                        &mut completion_work,
                        &mut cancelled,
                    )?;
                for matched in page_matches {
                    if poll_reverse_completion(cancellation, &mut completion_work) {
                        cancelled = true;
                        break;
                    }
                    matches.push(BatchCandidateMatch::new(
                        matched.candidate(),
                        request_base + matched.request_ordinal(),
                    ));
                }
                let (newly_accounted_seeds, completion_cancelled) = candidate_completion.observe(
                    "forward",
                    unconditional_completion,
                    state_page.iter().map(|state| state.seed),
                    cancellation,
                    &mut completion_work,
                )?;
                cancelled |= completion_cancelled;
                for seed_index in newly_accounted_seeds {
                    cancelled |= seeds[seed_index].completion.include(
                        candidate_completion.semantic_completion(),
                        cancellation,
                        &mut completion_work,
                    );
                }
                let mut pending_terminals = Vec::new();
                for (page_ordinal, branch_completion) in branch_completions.iter().enumerate() {
                    let request_ordinal = request_base + page_ordinal;
                    let state = &expandable[request_ordinal];
                    let seed = &mut seeds[state.seed];
                    if matches!(branch_completion, ResolutionCompletion::Incomplete(_)) {
                        // Preserve exactly the operand the former terminal
                        // path contributed to cancellation evidence before any
                        // cancellable path clone or canonicalization.
                        let mut terminal_completion = BatchCompletionLedger::default();
                        cancelled |= terminal_completion.include(
                            state.path.completion(),
                            cancellation,
                            &mut completion_work,
                        );
                        cancelled |= terminal_completion.include(
                            branch_completion,
                            cancellation,
                            &mut completion_work,
                        );
                        let (terminal_completion, terminal_cancelled) =
                            terminal_completion.finish_semantic(cancellation, &mut completion_work);
                        cancelled |= terminal_cancelled;
                        cancelled |= seed.observed_completion.include(
                            &terminal_completion,
                            cancellation,
                            &mut completion_work,
                        );
                        pending_terminals.push((request_ordinal, page_ordinal));
                    }
                }
                if cancellation.is_cancelled() {
                    cancelled = true;
                }
                if cancelled {
                    break;
                }
                for (request_ordinal, page_ordinal) in pending_terminals {
                    let state = &expandable[request_ordinal];
                    let branch_completion = &branch_completions[page_ordinal];
                    let terminal_path = state.path.clone_with_poll(&mut || {
                        poll_reverse_completion(cancellation, &mut completion_work)
                    });
                    let Some(terminal_path) = terminal_path else {
                        cancelled = true;
                        break;
                    };
                    let terminal_path = terminal_path
                        .with_additional_completion_with_poll(branch_completion, &mut || {
                            poll_reverse_completion(cancellation, &mut completion_work)
                        });
                    let Some(terminal_path) = terminal_path else {
                        cancelled = true;
                        break;
                    };
                    seeds[state.seed]
                        .terminals
                        .push(IncompleteTerminalPath::new(terminal_path));
                    terminalized.insert(request_ordinal);
                }
                if cancelled {
                    break;
                }
                if cancelled || cancellation.is_cancelled() {
                    cancelled = true;
                    break;
                }
            }
            if cancelled {
                include_forward_matched_hydrated_completions_after_cancellation(
                    &mut seeds,
                    &expandable,
                    &matches,
                    &arena,
                    &mut accounted_hydrated_completions,
                    cancellation,
                    &mut completion_work,
                );
                break;
            }
            let hydration_request = self.prepare_forward_hydration(
                ForwardHydrationContext {
                    metrics: &mut metrics,
                    completion_work: &mut completion_work,
                    seeds: &mut seeds,
                    expandable: &expandable,
                    matches: &matches,
                    arena: &mut arena,
                    accounted_completions: &mut accounted_hydrated_completions,
                    cancelled: &mut cancelled,
                },
                cancellation,
            );
            if cancelled {
                break;
            }
            self.hydrate_forward_candidates(
                ForwardHydrationContext {
                    metrics: &mut metrics,
                    completion_work: &mut completion_work,
                    seeds: &mut seeds,
                    expandable: &expandable,
                    matches: &matches,
                    arena: &mut arena,
                    accounted_completions: &mut accounted_hydrated_completions,
                    cancelled: &mut cancelled,
                },
                &hydration_request,
                cancellation,
            )?;
            if cancelled {
                break;
            }
            // Each page is canonicalized request-major, and page bases are
            // increasing, so concatenating pages already restores the exact
            // state-major composition order without an unbounded final sort.
            let mut has_successor = HashSet::default();
            for matched in &matches {
                metrics.composition_attempts += 1;
                if poll_reverse_completion(cancellation, &mut completion_work) {
                    cancelled = true;
                    break;
                }
                let parent = &expandable[matched.request_ordinal()];
                let candidate = arena.get(&matched.candidate()).ok_or_else(|| {
                    StoreError::new(format!(
                        "candidate {:?} was matched but not hydrated",
                        matched.candidate()
                    ))
                })?;
                let derivation = child_derivation(parent.derivation, matched.candidate().path());
                let composition =
                    parent
                        .path
                        .concatenate_with_poll(candidate, derivation, &mut || {
                            poll_reverse_completion(cancellation, &mut completion_work)
                        });
                let path = match composition {
                    None => {
                        cancelled = true;
                        break;
                    }
                    Some(Ok(path)) => {
                        metrics.successful_stitches += 1;
                        path
                    }
                    Some(Err(_)) => continue,
                };
                let path = path.canonicalized_observations_with_poll(&mut || {
                    poll_reverse_completion(cancellation, &mut completion_work)
                });
                let Some(path) = path else {
                    cancelled = true;
                    break;
                };
                let seed = &mut seeds[parent.seed];
                if accounted_hydrated_completions.insert((parent.seed, matched.candidate())) {
                    cancelled |= seed.observed_completion.include(
                        path.completion(),
                        cancellation,
                        &mut completion_work,
                    );
                }
                if cancelled {
                    break;
                }
                let decision = seed.certifier.admit_with_poll(
                    &parent.saturation,
                    matched.candidate().path(),
                    &path,
                    &mut || poll_reverse_completion(cancellation, &mut completion_work),
                );
                let Some(decision) = decision else {
                    cancelled = true;
                    break;
                };
                match decision {
                    SaturationDecision::Expand(saturation) => {
                        has_successor.insert(matched.request_ordinal());
                        frontier.push(BatchWorkPath {
                            seed: parent.seed,
                            path,
                            derivation,
                            saturation,
                        });
                    }
                    SaturationDecision::Subsumed => {
                        has_successor.insert(matched.request_ordinal());
                    }
                    SaturationDecision::Uncertified(gap) => {
                        has_successor.insert(matched.request_ordinal());
                        let reason = ResolutionIncompleteReason::CyclicExpansion(gap.transition());
                        seed.observed_completion.include_reason(reason);
                        let completion = ResolutionCompletion::incomplete([reason]);
                        let path = path
                            .with_additional_completion_with_poll(&completion, &mut || {
                                poll_reverse_completion(cancellation, &mut completion_work)
                            });
                        let Some(path) = path else {
                            cancelled = true;
                            break;
                        };
                        seed.terminals.push(IncompleteTerminalPath::new(path));
                    }
                }
            }
            if cancellation.is_cancelled() {
                cancelled = true;
            }
            if cancelled {
                include_forward_matched_hydrated_completions_after_cancellation(
                    &mut seeds,
                    &expandable,
                    &matches,
                    &arena,
                    &mut accounted_hydrated_completions,
                    cancellation,
                    &mut completion_work,
                );
                break;
            }
            for (request_ordinal, state) in expandable.into_iter().enumerate() {
                if poll_reverse_completion(cancellation, &mut completion_work) {
                    cancelled = true;
                    break;
                }
                if !has_successor.contains(&request_ordinal)
                    && !terminalized.contains(&request_ordinal)
                    && matches!(state.path.completion(), ResolutionCompletion::Incomplete(_))
                {
                    seeds[state.seed]
                        .terminals
                        .push(IncompleteTerminalPath::new(state.path));
                }
            }
            if cancelled {
                include_forward_hydrated_completions_for_seed_indices_after_cancellation(
                    &mut seeds,
                    &expandable_seed_indices,
                    &matches,
                    &arena,
                    &mut accounted_hydrated_completions,
                    cancellation,
                    &mut completion_work,
                );
                break;
            }
        }

        Ok(self.finish_seeded_reference_batch(
            seeds,
            metrics,
            cancellation,
            cancelled,
            completion_work,
        ))
    }

    pub fn stream_all_reference_batches(
        &self,
        maximum_batch_size: usize,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&ReferenceBatchAnswer) -> StoreResult<()>,
    ) -> StoreResult<ResolutionBatchSummary> {
        assert!(
            (1..=MAX_REFERENCE_SEEDS_PER_BATCH).contains(&maximum_batch_size),
            "reference batch size must be in 1..={MAX_REFERENCE_SEEDS_PER_BATCH}"
        );
        let mut completion = BatchCompletionLedger::default();
        let mut returned_evidence = CancellationEvidenceLedger::default();
        let mut work = 0_usize;
        let mut metrics = ResolutionBatchMetrics::default();
        let enumeration_completion = self.source().visit_reference_seed_batches(
            maximum_batch_size,
            cancellation,
            &mut |batch| {
                for seed in batch.seeds() {
                    returned_evidence.include(seed.completion(), cancellation, &mut work);
                }
                if returned_evidence.cancellation_observed() || cancellation.is_cancelled() {
                    return Ok(false);
                }
                let answer = self.resolve_reference_batch(batch, cancellation)?;
                completion.include(answer.completion(), cancellation, &mut work);
                returned_evidence.include(answer.completion(), cancellation, &mut work);
                for item in answer.answers() {
                    returned_evidence.observe_row(cancellation, &mut work);
                    returned_evidence.include(item.answer().completion(), cancellation, &mut work);
                    for witness in item.answer().witnesses() {
                        returned_evidence.observe_row(cancellation, &mut work);
                        returned_evidence.include(witness.completion(), cancellation, &mut work);
                    }
                }
                if completion.cancellation_observed
                    || returned_evidence.cancellation_observed()
                    || cancellation.is_cancelled()
                {
                    return Ok(false);
                }
                metrics.accumulate(answer.metrics());
                visitor(&answer)?;
                returned_evidence.observe_row(cancellation, &mut work);
                if returned_evidence.cancellation_observed() || cancellation.is_cancelled() {
                    return Ok(false);
                }
                Ok(true)
            },
        )?;
        completion.include(&enumeration_completion, cancellation, &mut work);
        returned_evidence.include(&enumeration_completion, cancellation, &mut work);
        let semantic_cancelled = completion.cancellation_observed;
        let (semantic_completion, finish_cancelled) =
            completion.finish_semantic(cancellation, &mut work);
        let completion = if semantic_cancelled
            || finish_cancelled
            || returned_evidence.cancellation_observed()
            || cancellation.is_cancelled()
        {
            returned_evidence.include(&semantic_completion, cancellation, &mut work);
            returned_evidence.finish(true, cancellation, &mut work).0
        } else {
            semantic_completion
        };
        Ok(ResolutionBatchSummary {
            completion,
            metrics,
        })
    }
}

fn identity_seed_path_id(seed: &ReferenceSeed) -> PartialPathId {
    let mut hasher = CanonicalHasher::new(b"bifrost-resolution-identity-seed-path:v1");
    hasher.field("fragment", &seed.fragment().as_bytes());
    hasher.field("reference", &seed.reference().as_bytes());
    hasher.field("node", &seed.node().as_bytes());
    PartialPathId::from_digest(hasher.finish())
}

fn seeded_derivation(reference: SemanticId, seed: PartialPathId) -> AlphaRenamingId {
    let mut hasher = CanonicalHasher::new(b"bifrost-resolution-seeded-derivation:v1");
    hasher.field("reference", &reference.as_bytes());
    hasher.field("seed", &seed.as_bytes());
    AlphaRenamingId::from_digest(hasher.finish())
}

fn prepare_reference_seed_completions(
    seeds: &[ReferenceSeed],
    cancellation: &CancellationToken,
    work: &mut usize,
) -> (Vec<PreparedSeed>, bool) {
    let mut cancelled = cancellation.is_cancelled();
    let mut prepared = Vec::with_capacity(seeds.len());
    for seed in seeds {
        cancelled |= poll_reverse_completion(cancellation, work);
        let mut completion = BatchCompletionLedger::default();
        cancelled |= completion.include(seed.completion(), cancellation, work);
        prepared.push(PreparedSeed {
            reference: seed.reference(),
            completion,
            observed_completion: CancellationEvidenceLedger::default(),
        });
    }
    (prepared, cancelled || cancellation.is_cancelled())
}

fn select_seed_answers(
    seeds: Vec<SeedState>,
    metrics: ResolutionBatchMetrics,
    cancellation: &CancellationToken,
    force_cancelled: bool,
    completion_work: &mut usize,
) -> ReferenceBatchAnswer {
    let mut answers = Vec::with_capacity(seeds.len());
    let mut batch_completion = BatchCompletionLedger::default();
    let mut cancelled = force_cancelled | cancellation.is_cancelled();
    for seed in seeds {
        cancelled |= poll_reverse_completion(cancellation, completion_work);
        let (completion, observed_completion, completion_cancelled) = finish_seed_completions(
            seed.completion,
            seed.observed_completion,
            cancelled,
            cancellation,
            completion_work,
        );
        let answer = select_paths_with_cancellation_evidence(
            seed.reference,
            seed.completed,
            seed.terminals,
            completion,
            observed_completion,
            cancellation,
        );
        debug_assert!(
            !completion_cancelled
                || matches!(
                    answer.completion(),
                    ResolutionCompletion::Incomplete(reasons)
                        if reasons.get(0) == Some(&ResolutionIncompleteReason::Cancelled)
                ),
            "an observed seed cancellation must reach the selector fallback"
        );
        cancelled |= completion_cancelled;
        cancelled |= batch_completion.include(answer.completion(), cancellation, completion_work);
        answers.push(BatchedReferenceAnswer {
            reference: seed.reference,
            answer,
        });
    }
    let (answers, ordering_cancelled) =
        canonicalize_batch_answers(answers, cancellation, completion_work);
    cancelled |= ordering_cancelled | cancellation.is_cancelled();
    let (completion, completion_cancelled) = batch_completion.finish(cancellation, completion_work);
    cancelled |= completion_cancelled | cancellation.is_cancelled();
    let answer = ReferenceBatchAnswer {
        answers: answers.into_boxed_slice(),
        completion,
        metrics,
    };
    if cancelled {
        mark_batch_cancelled(answer, cancellation, completion_work)
    } else {
        answer
    }
}

fn finish_seed_completions(
    completion: BatchCompletionLedger,
    observed_completion: CancellationEvidenceLedger,
    force_cancelled: bool,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> (ResolutionCompletion, ResolutionCompletion, bool) {
    let (completion, completion_cancelled) = completion.finish_semantic(cancellation, work);
    let (observed_completion, observed_cancelled) =
        observed_completion.finish(force_cancelled || completion_cancelled, cancellation, work);
    let cancelled = force_cancelled
        || completion_cancelled
        || observed_cancelled
        || cancellation.is_cancelled();
    (completion, observed_completion, cancelled)
}

fn canonicalize_batch_answers(
    answers: Vec<BatchedReferenceAnswer>,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> (Vec<BatchedReferenceAnswer>, bool) {
    let mut cancelled = cancellation.is_cancelled();
    let mut canonical = BTreeMap::new();
    for answer in answers {
        cancelled |= poll_reverse_completion(cancellation, work);
        let reference = answer.reference;
        assert!(
            canonical.insert(reference, answer).is_none(),
            "a seeded batch cannot contain duplicate reference {reference:?}"
        );
    }
    let mut answers = Vec::with_capacity(canonical.len());
    while let Some((_, answer)) = canonical.pop_first() {
        cancelled |= poll_reverse_completion(cancellation, work);
        answers.push(answer);
    }
    (answers, cancelled | cancellation.is_cancelled())
}

fn mark_batch_cancelled(
    answer: ReferenceBatchAnswer,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> ReferenceBatchAnswer {
    let mut answers = Vec::with_capacity(answer.answers.len());
    for entry in answer.answers.into_vec() {
        let _ = poll_reverse_completion(cancellation, work);
        let (targets, witnesses, completion) = entry.answer.into_parts();
        let mut cancelled_completion = BatchCompletionLedger::default();
        let _ = cancelled_completion.include(&completion, cancellation, work);
        cancelled_completion.include_reason(ResolutionIncompleteReason::Cancelled);
        let (completion, _) = cancelled_completion.finish(cancellation, work);
        answers.push(BatchedReferenceAnswer {
            reference: entry.reference,
            answer: ResolutionAnswer::new(targets, witnesses, completion),
        });
    }
    let mut cancelled_completion = BatchCompletionLedger::default();
    let _ = cancelled_completion.include(&answer.completion, cancellation, work);
    cancelled_completion.include_reason(ResolutionIncompleteReason::Cancelled);
    let (completion, _) = cancelled_completion.finish(cancellation, work);
    ReferenceBatchAnswer {
        answers: answers.into_boxed_slice(),
        completion,
        metrics: answer.metrics,
    }
}

fn cancelled_seeded_answers(
    requests: &[SeededReferenceRequest],
    metrics: ResolutionBatchMetrics,
    cancellation: &CancellationToken,
) -> ReferenceBatchAnswer {
    let mut work = 0_usize;
    let prepared = requests
        .iter()
        .map(|request| {
            let mut completion = BatchCompletionLedger::default();
            let _ = completion.include(request.seed().completion(), cancellation, &mut work);
            let mut observed_completion = CancellationEvidenceLedger::default();
            for alternative in request.alternatives() {
                let _ = observed_completion.include(
                    alternative.path().completion(),
                    cancellation,
                    &mut work,
                );
            }
            PreparedSeed {
                reference: request.seed().reference(),
                completion,
                observed_completion,
            }
        })
        .collect();
    cancelled_prepared_seed_answers(prepared, metrics, cancellation, &mut work)
}

fn cancelled_prepared_seed_answers(
    prepared: Vec<PreparedSeed>,
    metrics: ResolutionBatchMetrics,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> ReferenceBatchAnswer {
    let mut batch_completion = BatchCompletionLedger::default();
    let mut answers = Vec::with_capacity(prepared.len());
    for seed in prepared {
        let (request_completion, observed_completion, _) = finish_seed_completions(
            seed.completion,
            seed.observed_completion,
            true,
            cancellation,
            work,
        );
        let mut cancelled_evidence = CancellationEvidenceLedger::default();
        let _ = cancelled_evidence.include(&request_completion, cancellation, work);
        let _ = cancelled_evidence.include(&observed_completion, cancellation, work);
        let (request_completion, _) = cancelled_evidence.finish(true, cancellation, work);
        let _ = batch_completion.include(&request_completion, cancellation, work);
        answers.push(BatchedReferenceAnswer {
            reference: seed.reference,
            answer: empty_answer(request_completion),
        });
    }
    let (answers, _) = canonicalize_batch_answers(answers, cancellation, work);
    let (completion, _) = batch_completion.finish(cancellation, work);
    ReferenceBatchAnswer {
        answers: answers.into_boxed_slice(),
        completion,
        metrics,
    }
}

fn empty_answer(completion: ResolutionCompletion) -> ResolutionAnswer {
    ResolutionAnswer::new(Vec::new(), Vec::new(), completion)
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use super::super::engine::{PreloadedFragment, PreloadedFragmentSource, ResolutionEngine};
    use super::super::model::{
        BindingNodeId, BindingNodeKind, PrecedenceStep, StackPattern, WitnessStep,
    };
    use super::*;
    use crate::analyzer::structural::PrecedenceTier;

    fn semantic(value: &str) -> SemanticId {
        SemanticId::hash_bytes(value)
    }

    fn fragment(value: &str) -> BindingFragmentId {
        BindingFragmentId::hash_bytes(value)
    }

    fn node(value: &str) -> BindingNodeId {
        BindingNodeId::hash_bytes(value)
    }

    fn path_id(value: &str) -> PartialPathId {
        PartialPathId::hash_bytes(value)
    }

    fn seeded_partial_path(identity: PartialPathId, path: PartialPath) -> SeededPartialPath {
        SeededPartialPath::new_with_poll(identity, path, &mut || false)
            .expect("live test seeded-path construction completes")
    }

    fn seeded_reference_request(
        seed: ReferenceSeed,
        alternatives: impl IntoIterator<Item = SeededPartialPath>,
    ) -> SeededReferenceRequest {
        SeededReferenceRequest::new_with_poll(seed, alternatives, &mut || false)
            .expect("live test seeded-request construction completes")
    }

    fn endpoint(node: BindingNodeId) -> EndpointSignature {
        EndpointSignature::new(
            node,
            StackPattern::closed(Vec::new()),
            StackPattern::closed(Vec::new()),
        )
    }

    #[test]
    fn reference_site_metadata_cloning_preserves_optional_transport() {
        let owner = semantic("reference-seed-owner");
        for (expected_owner, expected_origin) in [
            (None, None),
            (Some(None), Some(ResolutionCallableReceiverOrigin::Implicit)),
            (
                Some(Some(owner)),
                Some(ResolutionCallableReceiverOrigin::ExplicitExpression),
            ),
        ] {
            let metadata = FactReferenceSiteMetadata::new(
                ResolutionSiteId::new(7),
                ResolutionNamespace::Callable,
                ResolutionSiteKind::CallableReference,
                10,
                14,
                expected_origin != Some(ResolutionCallableReceiverOrigin::ExplicitExpression),
                expected_owner,
                expected_origin,
            );
            let seed = ReferenceSeed::new_with_site_metadata(
                fragment("reference-seed-owner-fragment"),
                ResolutionQuery::new(semantic("reference-seed-owner-reference")),
                node("reference-seed-owner-node"),
                Some(metadata),
                ResolutionCompletion::Complete,
            );
            let ordinary_clone = seed.clone();
            assert_eq!(ordinary_clone.site_metadata(), Some(metadata));
            assert_eq!(ordinary_clone.reference_owner(), expected_owner);
            assert_eq!(ordinary_clone.callable_receiver_origin(), expected_origin);
            let polled_clone = seed
                .clone_with_poll(&mut || false)
                .expect("uncancelled seed clone");
            assert_eq!(polled_clone.site_metadata(), Some(metadata));
            assert_eq!(polled_clone.reference_owner(), expected_owner);
            assert_eq!(polled_clone.callable_receiver_origin(), expected_origin);
        }

        let hand_built = ReferenceSeed::new(
            fragment("hand-built-reference-seed-fragment"),
            ResolutionQuery::new(semantic("hand-built-reference-seed-reference")),
            node("hand-built-reference-seed-node"),
            ResolutionCompletion::Complete,
        );
        assert_eq!(hand_built.site_metadata(), None);
        assert_eq!(hand_built.reference_owner(), None);
        assert_eq!(hand_built.callable_receiver_origin(), None);
    }

    #[test]
    fn endpoint_classification_rejects_member_owner_on_semantic_nodes() {
        let endpoint = node("member-owner-semantic-endpoint");
        let endpoint_semantic = semantic("member-owner-semantic");
        let owner = semantic("member-owner");
        for (reference, definition) in [
            (Some(endpoint_semantic), None),
            (None, Some(endpoint_semantic)),
        ] {
            assert!(
                std::panic::catch_unwind(|| {
                    BatchEndpointClassification::new_with_member_scope_owner(
                        endpoint,
                        reference,
                        definition,
                        Some(owner),
                    )
                })
                .is_err(),
                "member ownership must be exclusive with reference/definition classification"
            );
        }
    }

    fn path(
        start: BindingNodeId,
        end: BindingNodeId,
        completion: ResolutionCompletion,
    ) -> PartialPath {
        PartialPath::new(
            endpoint(start),
            endpoint(end),
            Vec::new(),
            [WitnessStep::Node(end)],
            completion,
        )
    }

    fn ranked_path(
        start: BindingNodeId,
        end: BindingNodeId,
        choice: SemanticId,
        tier: PrecedenceTier,
    ) -> PartialPath {
        PartialPath::new(
            endpoint(start),
            endpoint(end),
            [PrecedenceStep {
                tier,
                ordinal: 0,
                semantic: choice,
            }],
            [WitnessStep::Node(end)],
            ResolutionCompletion::Complete,
        )
    }

    struct SharedFixture {
        source: PreloadedFragmentSource,
        first_reference: SemanticId,
        second_reference: SemanticId,
        third_reference: SemanticId,
        target: SemanticId,
        first_node: BindingNodeId,
        target_node: BindingNodeId,
        first_entry: CandidatePathIdentity,
        shared_exit: CandidatePathIdentity,
    }

    fn shared_fixture(reverse_rows: bool) -> SharedFixture {
        let first_fragment = fragment("batch-fragment-a");
        let second_fragment = fragment("batch-fragment-b");
        let first_reference = semantic("batch-reference-a");
        let second_reference = semantic("batch-reference-b");
        let third_reference = semantic("batch-reference-c");
        let target = semantic("batch-target");
        let first_node = node("batch-reference-node-a");
        let second_node = node("batch-reference-node-b");
        let third_node = node("batch-reference-node-c");
        let seam = node("batch-shared-seam");
        let target_node = node("batch-target-node");
        let first_entry_id = path_id("batch-entry-a");
        let second_entry_id = path_id("batch-entry-b");
        let third_entry_id = path_id("batch-entry-c");
        let shared_exit_id = path_id("batch-shared-exit");

        let mut first_paths = vec![
            (
                first_entry_id,
                path(first_node, seam, ResolutionCompletion::Complete),
            ),
            (
                second_entry_id,
                path(second_node, seam, ResolutionCompletion::Complete),
            ),
        ];
        let mut second_paths = vec![
            (
                third_entry_id,
                path(third_node, target_node, ResolutionCompletion::Complete),
            ),
            (
                shared_exit_id,
                path(seam, target_node, ResolutionCompletion::Complete),
            ),
        ];
        if reverse_rows {
            first_paths.reverse();
            second_paths.reverse();
        }
        let mut fragments = vec![
            PreloadedFragment::new(
                first_fragment,
                [
                    (first_node, BindingNodeKind::Reference(first_reference)),
                    (second_node, BindingNodeKind::Reference(second_reference)),
                ],
                first_paths,
            ),
            PreloadedFragment::new(
                second_fragment,
                [
                    (third_node, BindingNodeKind::Reference(third_reference)),
                    (target_node, BindingNodeKind::Definition(target)),
                ],
                second_paths,
            ),
        ];
        if reverse_rows {
            fragments.reverse();
        }
        SharedFixture {
            source: PreloadedFragmentSource::from_fragments_with_boundaries([seam], fragments),
            first_reference,
            second_reference,
            third_reference,
            target,
            first_node,
            target_node,
            first_entry: CandidatePathIdentity::new(first_fragment, first_entry_id),
            shared_exit: CandidatePathIdentity::new(second_fragment, shared_exit_id),
        }
    }

    struct SeededFixture {
        source: PreloadedFragmentSource,
        owner: BindingFragmentId,
        reference: SemanticId,
        reference_node: BindingNodeId,
        first_owner: BindingNodeId,
        second_owner: BindingNodeId,
        first_target: SemanticId,
        second_target: SemanticId,
    }

    fn seeded_fixture(second_tier: PrecedenceTier) -> SeededFixture {
        let owner = fragment("seeded-fragment");
        let reference = semantic("seeded-reference");
        let first_target = semantic("seeded-first-target");
        let second_target = semantic("seeded-second-target");
        let choice = semantic("seeded-owner-choice");
        let reference_node = node("seeded-reference-node");
        let first_owner = node("seeded-first-owner");
        let second_owner = node("seeded-second-owner");
        let first_target_node = node("seeded-first-target-node");
        let second_target_node = node("seeded-second-target-node");
        let source = PreloadedFragmentSource::from_fragments_with_boundaries(
            [first_owner, second_owner],
            [PreloadedFragment::new(
                owner,
                [
                    (reference_node, BindingNodeKind::Reference(reference)),
                    (first_target_node, BindingNodeKind::Definition(first_target)),
                    (
                        second_target_node,
                        BindingNodeKind::Definition(second_target),
                    ),
                ],
                [
                    (
                        path_id("seeded-first-candidate"),
                        ranked_path(
                            first_owner,
                            first_target_node,
                            choice,
                            PrecedenceTier::LexicalBinding,
                        ),
                    ),
                    (
                        path_id("seeded-second-candidate"),
                        ranked_path(second_owner, second_target_node, choice, second_tier),
                    ),
                ],
            )],
        );
        SeededFixture {
            source,
            owner,
            reference,
            reference_node,
            first_owner,
            second_owner,
            first_target,
            second_target,
        }
    }

    fn seeded_alternatives(fixture: &SeededFixture) -> [SeededPartialPath; 2] {
        [
            seeded_partial_path(
                path_id("seeded-first-owner-alternative"),
                path(
                    fixture.reference_node,
                    fixture.first_owner,
                    ResolutionCompletion::Complete,
                ),
            ),
            seeded_partial_path(
                path_id("seeded-second-owner-alternative"),
                path(
                    fixture.reference_node,
                    fixture.second_owner,
                    ResolutionCompletion::Complete,
                ),
            ),
        ]
    }

    fn collect_reference_batches(
        source: &PreloadedFragmentSource,
        maximum_batch_size: usize,
    ) -> (Vec<BatchedReferenceAnswer>, ResolutionBatchSummary) {
        let mut answers = Vec::new();
        let summary = BatchResolutionEngine::new(source)
            .stream_all_reference_batches(
                maximum_batch_size,
                &CancellationToken::new(),
                &mut |batch| {
                    answers.extend_from_slice(batch.answers());
                    Ok(())
                },
            )
            .expect("preloaded batch source is infallible");
        answers.sort_unstable_by_key(BatchedReferenceAnswer::reference);
        assert!(
            answers
                .windows(2)
                .all(|pair| pair[0].reference() != pair[1].reference()),
            "preloaded reference enumeration is globally unique"
        );
        (answers, summary)
    }

    fn reference_seed(source: &PreloadedFragmentSource, query: ResolutionQuery) -> ReferenceSeed {
        source
            .reference_seed(query, &CancellationToken::new())
            .expect("preloaded seed lookup is infallible")
            .expect("fixture reference has a seed")
    }

    #[test]
    fn batch_answers_equal_individual_point_answers() {
        let fixture = shared_fixture(false);
        let queries = [fixture.first_reference, fixture.second_reference].map(ResolutionQuery::new);
        let batch =
            ReferenceSeedBatch::new(queries.map(|query| reference_seed(&fixture.source, query)));
        let cancellation = CancellationToken::new();

        let answer = BatchResolutionEngine::new(&fixture.source)
            .resolve_reference_batch(&batch, &cancellation)
            .expect("preloaded batch source is infallible");

        for query in queries {
            let individual = ResolutionEngine::new(&fixture.source)
                .resolve_reference(query, &cancellation)
                .expect("preloaded point source is infallible");
            assert_eq!(answer.answer(query.reference()), Some(&individual));
            let delegated = BatchResolutionEngine::new(&fixture.source)
                .resolve_reference(query, &cancellation)
                .expect("arity-one batch source is infallible");
            assert_eq!(delegated, individual);
        }
        assert_eq!(answer.completion(), &ResolutionCompletion::Complete);
    }

    #[test]
    fn seeded_owner_alternatives_share_one_final_shadow_selection() {
        let fixture = seeded_fixture(PrecedenceTier::ExplicitImport);
        let seed = reference_seed(&fixture.source, ResolutionQuery::new(fixture.reference));
        let request = seeded_reference_request(seed, seeded_alternatives(&fixture));

        let answer = BatchResolutionEngine::new(&fixture.source)
            .resolve_seeded_reference(&request, &CancellationToken::new())
            .expect("preloaded seeded lookup is infallible");

        assert_eq!(answer.targets(), &[fixture.first_target]);
        assert_eq!(answer.witnesses().len(), 2);
        assert_eq!(answer.completion(), &ResolutionCompletion::Complete);
    }

    #[test]
    fn equally_ranked_seeded_owner_alternatives_remain_ambiguous() {
        let fixture = seeded_fixture(PrecedenceTier::LexicalBinding);
        let seed = reference_seed(&fixture.source, ResolutionQuery::new(fixture.reference));
        let request = seeded_reference_request(seed, seeded_alternatives(&fixture));

        let answer = BatchResolutionEngine::new(&fixture.source)
            .resolve_seeded_reference(&request, &CancellationToken::new())
            .expect("preloaded seeded lookup is infallible");

        let mut expected = vec![fixture.first_target, fixture.second_target];
        expected.sort_unstable();
        assert_eq!(answer.targets(), expected);
        assert_eq!(answer.completion(), &ResolutionCompletion::Complete);
    }

    #[test]
    fn seeded_answer_is_invariant_to_alternative_order() {
        let fixture = seeded_fixture(PrecedenceTier::ExplicitImport);
        let seed = reference_seed(&fixture.source, ResolutionQuery::new(fixture.reference));
        let forward = seeded_reference_request(seed.clone(), seeded_alternatives(&fixture));
        let mut reversed = seeded_alternatives(&fixture);
        reversed.reverse();
        let reversed = seeded_reference_request(seed, reversed);
        let engine = BatchResolutionEngine::new(&fixture.source);

        let forward = engine
            .resolve_seeded_reference(&forward, &CancellationToken::new())
            .expect("preloaded seeded lookup is infallible");
        let reversed = engine
            .resolve_seeded_reference(&reversed, &CancellationToken::new())
            .expect("preloaded seeded lookup is infallible");

        assert_eq!(reversed, forward);
    }

    #[test]
    fn polled_seeded_request_matches_public_canonicalization_and_cancels_inside_one_path() {
        let fixture = seeded_fixture(PrecedenceTier::ExplicitImport);
        let first_reason =
            ResolutionIncompleteReason::UnsupportedSemantic(semantic("seeded-request-gap-b"));
        let second_reason =
            ResolutionIncompleteReason::UnsupportedSemantic(semantic("seeded-request-gap-a"));
        let seed = ReferenceSeed::new(
            fixture.owner,
            ResolutionQuery::new(fixture.reference),
            fixture.reference_node,
            ResolutionCompletion::Incomplete(
                vec![first_reason, second_reason, first_reason]
                    .into_boxed_slice()
                    .into(),
            ),
        );
        let first = seeded_partial_path(
            path_id("polled-seeded-request-first"),
            path(
                fixture.reference_node,
                fixture.first_owner,
                ResolutionCompletion::Complete,
            ),
        );
        let second = seeded_partial_path(
            path_id("polled-seeded-request-second"),
            path(
                fixture.reference_node,
                fixture.second_owner,
                ResolutionCompletion::Incomplete(
                    vec![second_reason, first_reason, second_reason]
                        .into_boxed_slice()
                        .into(),
                ),
            ),
        );
        let alternatives = vec![second, first.clone(), first];
        let expected = seeded_reference_request(seed.clone(), alternatives.clone());
        let actual = SeededReferenceRequest::new_with_poll(seed, alternatives, &mut || false)
            .expect("uncancelled seeded-request construction completes");
        assert_eq!(actual, expected);

        let large_completion = ResolutionCompletion::Incomplete(
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
        let seed = ReferenceSeed::new(
            fixture.owner,
            ResolutionQuery::new(fixture.reference),
            fixture.reference_node,
            ResolutionCompletion::Complete,
        );
        let alternative = seeded_partial_path(
            path_id("polled-seeded-request-large"),
            path(
                fixture.reference_node,
                fixture.first_owner,
                large_completion,
            ),
        );
        let mut polls = 0_usize;
        assert!(
            SeededReferenceRequest::new_with_poll(seed, [alternative], &mut || {
                polls += 1;
                polls > CANCELLATION_QUANTUM
            })
            .is_none()
        );
        assert!(polls > CANCELLATION_QUANTUM);
    }

    #[test]
    fn seeded_request_preserves_the_public_two_empty_incomplete_panic() {
        let fixture = seeded_fixture(PrecedenceTier::ExplicitImport);
        let empty = ResolutionCompletion::Incomplete(Vec::new().into_boxed_slice().into());
        let seed = ReferenceSeed::new(
            fixture.owner,
            ResolutionQuery::new(fixture.reference),
            fixture.reference_node,
            empty.clone(),
        );
        let alternative = seeded_partial_path(
            path_id("empty-incomplete-seeded-request"),
            path(fixture.reference_node, fixture.first_owner, empty),
        );

        assert!(
            std::panic::catch_unwind(|| {
                let _ = seeded_reference_request(seed, [alternative]);
            })
            .is_err()
        );
    }

    #[test]
    fn seeded_request_rejects_wrong_or_unbalanced_start() {
        let fixture = seeded_fixture(PrecedenceTier::ExplicitImport);
        let seed = reference_seed(&fixture.source, ResolutionQuery::new(fixture.reference));
        let wrong_node = seeded_partial_path(
            path_id("wrong-seed-node"),
            path(
                node("not-the-reference-node"),
                fixture.first_owner,
                ResolutionCompletion::Complete,
            ),
        );
        assert!(
            std::panic::catch_unwind(|| {
                seeded_reference_request(seed.clone(), [wrong_node]);
            })
            .is_err()
        );

        let unbalanced_start = EndpointSignature::new(
            fixture.reference_node,
            StackPattern::closed([semantic("unbalanced-symbol")]),
            StackPattern::closed(Vec::new()),
        );
        let unbalanced = seeded_partial_path(
            path_id("unbalanced-seed-start"),
            PartialPath::new(
                unbalanced_start,
                endpoint(fixture.first_owner),
                Vec::new(),
                Vec::new(),
                ResolutionCompletion::Complete,
            ),
        );
        assert!(
            std::panic::catch_unwind(|| {
                seeded_reference_request(seed, [unbalanced]);
            })
            .is_err()
        );
    }

    #[test]
    fn seeded_request_rejects_conflicting_reuse_of_an_identity() {
        let fixture = seeded_fixture(PrecedenceTier::ExplicitImport);
        let seed = reference_seed(&fixture.source, ResolutionQuery::new(fixture.reference));
        let shared_id = path_id("conflicting-seed-id");
        let alternatives = [
            seeded_partial_path(
                shared_id,
                path(
                    fixture.reference_node,
                    fixture.first_owner,
                    ResolutionCompletion::Complete,
                ),
            ),
            seeded_partial_path(
                shared_id,
                path(
                    fixture.reference_node,
                    fixture.second_owner,
                    ResolutionCompletion::Complete,
                ),
            ),
        ];

        assert!(std::panic::catch_unwind(|| seeded_reference_request(seed, alternatives)).is_err());
    }

    #[test]
    fn seeded_paths_combine_source_and_alternative_incompleteness() {
        let fixture = seeded_fixture(PrecedenceTier::ExplicitImport);
        let source_gap = semantic("seeded-source-gap");
        let path_gap = semantic("seeded-path-gap");
        let seed = ReferenceSeed::new(
            fixture.owner,
            ResolutionQuery::new(fixture.reference),
            fixture.reference_node,
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                source_gap,
            )]),
        );
        let alternative = seeded_partial_path(
            path_id("incomplete-seeded-alternative"),
            path(
                fixture.reference_node,
                fixture.first_owner,
                ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(path_gap),
                ]),
            ),
        );
        let request = seeded_reference_request(seed, [alternative]);
        let ResolutionCompletion::Incomplete(request_reasons) =
            request.alternatives()[0].path().completion()
        else {
            panic!("the normalized seed path must retain both gaps");
        };
        assert!(
            request_reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(source_gap))
        );
        assert!(
            request_reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(path_gap))
        );

        let answer = BatchResolutionEngine::new(&fixture.source)
            .resolve_seeded_reference(&request, &CancellationToken::new())
            .expect("semantic gaps are typed evidence");

        assert_eq!(answer.targets(), &[fixture.first_target]);
        let ResolutionCompletion::Incomplete(answer_reasons) = answer.completion() else {
            panic!("the seeded answer must retain both gaps");
        };
        assert!(
            answer_reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(source_gap))
        );
        assert!(
            answer_reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(path_gap))
        );
    }

    #[test]
    fn explicit_identity_seed_equals_point_and_batch_specializations() {
        let fixture = shared_fixture(false);
        let query = ResolutionQuery::new(fixture.first_reference);
        let seed = reference_seed(&fixture.source, query);
        let request = seeded_reference_request(
            seed.clone(),
            [seeded_partial_path(
                path_id("explicit-identity-seed"),
                identity_path(seed.node()),
            )],
        );
        let engine = BatchResolutionEngine::new(&fixture.source);

        let explicit = engine
            .resolve_seeded_reference(&request, &CancellationToken::new())
            .expect("preloaded seeded lookup is infallible");
        let point = engine
            .resolve_reference(query, &CancellationToken::new())
            .expect("preloaded point lookup is infallible");
        let batch = engine
            .resolve_reference_batch(&ReferenceSeedBatch::new([seed]), &CancellationToken::new())
            .expect("preloaded batch lookup is infallible");

        assert_eq!(explicit, point);
        assert_eq!(batch.answer(query.reference()), Some(&explicit));
    }

    #[test]
    fn shared_candidate_paths_are_hydrated_once_per_batch() {
        let fixture = shared_fixture(false);
        let batch = ReferenceSeedBatch::new(
            [fixture.first_reference, fixture.second_reference]
                .map(ResolutionQuery::new)
                .map(|query| reference_seed(&fixture.source, query)),
        );

        let answer = BatchResolutionEngine::new(&fixture.source)
            .resolve_reference_batch(&batch, &CancellationToken::new())
            .expect("preloaded batch source is infallible");

        assert_eq!(answer.metrics().distinct_candidate_matches(), 4);
        assert_eq!(answer.metrics().distinct_path_hydrations(), 3);
        assert_eq!(answer.metrics().composition_attempts(), 4);
        assert_eq!(answer.metrics().successful_stitches(), 4);
        assert_eq!(answer.metrics().worklist_rounds(), 3);
        assert_eq!(answer.metrics().peak_hydrated_paths(), 3);
        assert_eq!(
            answer.answer(fixture.first_reference).unwrap().targets(),
            &[fixture.target]
        );
        assert_eq!(
            answer.answer(fixture.second_reference).unwrap().targets(),
            &[fixture.target]
        );
    }

    #[test]
    fn row_order_and_reference_chunking_do_not_change_answers() {
        let forward = shared_fixture(false);
        let reversed = shared_fixture(true);
        let (one_at_a_time, one_summary) = collect_reference_batches(&forward.source, 1);
        let (two_at_a_time, two_summary) = collect_reference_batches(&forward.source, 2);
        let (reversed_rows, reversed_summary) = collect_reference_batches(&reversed.source, 2);

        assert_eq!(one_at_a_time, two_at_a_time);
        assert_eq!(two_at_a_time, reversed_rows);
        assert_eq!(one_summary.completion(), &ResolutionCompletion::Complete);
        assert_eq!(two_summary.completion(), &ResolutionCompletion::Complete);
        assert_eq!(
            reversed_summary.completion(),
            &ResolutionCompletion::Complete
        );
        assert_eq!(two_summary.metrics().reference_seeds(), 3);
        assert_eq!(two_summary.metrics().batches(), 2);
        assert_eq!(
            two_at_a_time
                .binary_search_by_key(&forward.third_reference, BatchedReferenceAnswer::reference,)
                .ok()
                .map(|index| two_at_a_time[index].answer())
                .unwrap()
                .targets(),
            &[forward.target]
        );
    }

    #[test]
    fn forward_and_reverse_matching_are_distinct_fragment_major_queries() {
        let fixture = shared_fixture(false);
        let cancellation = CancellationToken::new();
        let forward = fixture
            .source
            .match_forward_candidates(
                &[BatchCandidateRequest::new(0, endpoint(fixture.first_node))],
                &cancellation,
            )
            .expect("preloaded forward match is infallible");
        let reverse = fixture
            .source
            .match_reverse_candidates(
                &[BatchCandidateRequest::new(0, endpoint(fixture.target_node))],
                &cancellation,
            )
            .expect("preloaded reverse match is infallible");

        assert_eq!(forward.matches()[0].candidate(), fixture.first_entry);
        assert!(
            reverse
                .matches()
                .iter()
                .any(|matched| matched.candidate() == fixture.shared_exit)
        );
        assert!(!reverse.matches().contains(&forward.matches()[0]));
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TestFault {
        None,
        CancelOnReferenceSeedWithGap,
        CancelFirstReferenceSeedWithNoncanonicalGap,
        ReferenceSeedWithCancelledEvidence,
        CancelOnHydration,
        FailOnForwardMatch,
        FailOnSecondForwardMatch,
        EnumerationGapWithoutSeeds,

        EmptyForwardMatchWithGap,
        CancelOnForwardMatchWithGap,
        ForwardMatchWithGap,

        ReverseForwardCandidateStream,

        DuplicateForwardCandidate,
    }

    struct FaultingSource<'a> {
        inner: &'a PreloadedFragmentSource,
        fault: TestFault,
        forward_matches: Cell<usize>,
        reverse_matches: Cell<usize>,
        reference_seeds: Cell<usize>,
        reverse_seed_batches: Cell<usize>,
        reverse_seed_batch_sizes: RefCell<Vec<usize>>,
        reverse_seed_requests: RefCell<Vec<ReverseReferenceSeedRequest>>,
        hydrated_candidates: RefCell<Vec<CandidatePathIdentity>>,
        classified_batch_sizes: RefCell<Vec<usize>>,
        forward_match_batch_sizes: RefCell<Vec<usize>>,
        reverse_match_batch_sizes: RefCell<Vec<usize>>,
        forward_match_output_page_sizes: RefCell<Vec<usize>>,
        reverse_match_output_page_sizes: RefCell<Vec<usize>>,
        hydration_batch_sizes: RefCell<Vec<usize>>,
    }

    impl<'a> FaultingSource<'a> {
        fn new(inner: &'a PreloadedFragmentSource, fault: TestFault) -> Self {
            Self {
                inner,
                fault,
                forward_matches: Cell::new(0),
                reverse_matches: Cell::new(0),
                reference_seeds: Cell::new(0),
                reverse_seed_batches: Cell::new(0),
                reverse_seed_batch_sizes: RefCell::new(Vec::new()),
                reverse_seed_requests: RefCell::new(Vec::new()),
                hydrated_candidates: RefCell::new(Vec::new()),
                classified_batch_sizes: RefCell::new(Vec::new()),
                forward_match_batch_sizes: RefCell::new(Vec::new()),
                reverse_match_batch_sizes: RefCell::new(Vec::new()),
                forward_match_output_page_sizes: RefCell::new(Vec::new()),
                reverse_match_output_page_sizes: RefCell::new(Vec::new()),
                hydration_batch_sizes: RefCell::new(Vec::new()),
            }
        }
    }

    impl BatchResolutionFragmentSource for FaultingSource<'_> {
        fn reference_seed(
            &self,
            query: ResolutionQuery,
            cancellation: &CancellationToken,
        ) -> StoreResult<Option<ReferenceSeed>> {
            self.reference_seeds.set(self.reference_seeds.get() + 1);
            let seed = self.inner.reference_seed(query, cancellation)?;
            if self.fault == TestFault::CancelOnReferenceSeedWithGap {
                let seed = seed.map(|seed| {
                    ReferenceSeed::new(
                        seed.fragment(),
                        seed.query(),
                        seed.node(),
                        seed.completion()
                            .combine(&ResolutionCompletion::incomplete([
                                ResolutionIncompleteReason::UnsupportedSemantic(semantic(
                                    "cancelled-reference-seed-gap",
                                )),
                            ])),
                    )
                });
                cancellation.cancel();
                return Ok(seed);
            }
            if self.fault == TestFault::CancelFirstReferenceSeedWithNoncanonicalGap
                && self.reference_seeds.get() == 1
            {
                let high = ResolutionIncompleteReason::UnsupportedSemantic(semantic(
                    "plural-reference-seed-noncanonical-high",
                ));
                let low = ResolutionIncompleteReason::UnsupportedSemantic(semantic(
                    "plural-reference-seed-noncanonical-low",
                ));
                let seed = seed.map(|seed| {
                    ReferenceSeed::new(
                        seed.fragment(),
                        seed.query(),
                        seed.node(),
                        ResolutionCompletion::Incomplete(
                            vec![high, low, high].into_boxed_slice().into(),
                        ),
                    )
                });
                cancellation.cancel();
                return Ok(seed);
            }
            if self.fault == TestFault::ReferenceSeedWithCancelledEvidence {
                return Ok(seed.map(|seed| {
                    ReferenceSeed::new(
                        seed.fragment(),
                        seed.query(),
                        seed.node(),
                        seed.completion()
                            .combine(&ResolutionCompletion::incomplete([
                                ResolutionIncompleteReason::UnsupportedSemantic(semantic(
                                    "returned-cancelled-reference-seed-gap",
                                )),
                                ResolutionIncompleteReason::Cancelled,
                            ])),
                    )
                }));
            }
            Ok(seed)
        }

        fn lookup_definition_node(
            &self,
            definition: SemanticId,
            cancellation: &CancellationToken,
        ) -> StoreResult<Option<BindingNodeId>> {
            self.inner.lookup_definition_node(definition, cancellation)
        }

        fn issue_reverse_reference_seeds(
            &self,
            requests: &[ReverseReferenceSeedRequest],
            cancellation: &CancellationToken,
        ) -> StoreResult<Vec<ReferenceSeed>> {
            self.reverse_seed_batches
                .set(self.reverse_seed_batches.get() + 1);
            self.reverse_seed_batch_sizes
                .borrow_mut()
                .push(requests.len());
            self.reverse_seed_requests
                .borrow_mut()
                .extend_from_slice(requests);
            let seeds = self
                .inner
                .issue_reverse_reference_seeds(requests, cancellation)?;

            Ok(seeds)
        }

        fn visit_reference_seed_batches(
            &self,
            maximum_batch_size: usize,
            cancellation: &CancellationToken,
            visitor: &mut dyn FnMut(&ReferenceSeedBatch) -> StoreResult<bool>,
        ) -> StoreResult<ResolutionCompletion> {
            if self.fault == TestFault::EnumerationGapWithoutSeeds {
                return Ok(ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(semantic(
                        "enumeration-coverage-gap",
                    )),
                ]));
            }
            self.inner
                .visit_reference_seed_batches(maximum_batch_size, cancellation, visitor)
        }

        fn classify_endpoint_nodes(
            &self,
            nodes: &[BindingNodeId],
            cancellation: &CancellationToken,
        ) -> StoreResult<Vec<BatchEndpointClassification>> {
            self.classified_batch_sizes.borrow_mut().push(nodes.len());
            let classified = self.inner.classify_endpoint_nodes(nodes, cancellation)?;

            Ok(classified)
        }

        fn match_forward_candidates(
            &self,
            requests: &[BatchCandidateRequest],
            cancellation: &CancellationToken,
        ) -> StoreResult<BatchCandidateOutcome> {
            let call = self.forward_matches.get() + 1;
            self.forward_matches.set(call);
            self.forward_match_batch_sizes
                .borrow_mut()
                .push(requests.len());
            if self.fault == TestFault::FailOnForwardMatch {
                return Err(StoreError::new("injected seeded source failure"));
            }
            if self.fault == TestFault::FailOnSecondForwardMatch && call == 2 {
                return Err(StoreError::new("injected second-level source failure"));
            }
            if matches!(
                self.fault,
                TestFault::EmptyForwardMatchWithGap | TestFault::CancelOnForwardMatchWithGap
            ) {
                let completion = ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(semantic(
                        "candidate-coverage-gap",
                    )),
                ]);
                if self.fault == TestFault::CancelOnForwardMatchWithGap {
                    cancellation.cancel();
                }
                return Ok(BatchCandidateOutcome::new(
                    requests.len(),
                    Vec::new(),
                    ResolutionCompletion::Complete,
                    std::iter::repeat_n(completion, requests.len()),
                ));
            }
            let outcome = self
                .inner
                .match_forward_candidates(requests, cancellation)?;
            if self.fault == TestFault::ForwardMatchWithGap {
                let gap = ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(semantic(
                        "candidate-sibling-gap",
                    )),
                ]);
                let (matches, unconditional_completion, branch_completions) = outcome.into_parts();
                return Ok(BatchCandidateOutcome::new(
                    requests.len(),
                    matches,
                    unconditional_completion,
                    branch_completions
                        .into_vec()
                        .into_iter()
                        .map(|completion| completion.combine(&gap)),
                ));
            }
            Ok(outcome)
        }

        fn match_reverse_candidates(
            &self,
            requests: &[BatchCandidateRequest],
            cancellation: &CancellationToken,
        ) -> StoreResult<BatchCandidateOutcome> {
            let call = self.reverse_matches.get() + 1;
            self.reverse_matches.set(call);
            self.reverse_match_batch_sizes
                .borrow_mut()
                .push(requests.len());

            let outcome = self
                .inner
                .match_reverse_candidates(requests, cancellation)?;

            Ok(outcome)
        }

        fn visit_forward_candidate_match_pages(
            &self,
            requests: &[BatchCandidateRequest],
            cancellation: &CancellationToken,
            visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
        ) -> StoreResult<BatchCandidateCompletionOutcome> {
            if matches!(
                self.fault,
                TestFault::ReverseForwardCandidateStream | TestFault::DuplicateForwardCandidate
            ) {
                self.forward_matches.set(self.forward_matches.get() + 1);
                self.forward_match_batch_sizes
                    .borrow_mut()
                    .push(requests.len());
                let mut rows = Vec::new();
                let outcome = self.inner.visit_forward_candidate_match_pages(
                    requests,
                    cancellation,
                    &mut |page| {
                        rows.extend_from_slice(page);
                        Ok(true)
                    },
                )?;
                if self.fault == TestFault::ReverseForwardCandidateStream {
                    rows.reverse();
                } else if let Some(&first) = rows.first() {
                    rows.push(first);
                }
                for page in rows.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
                    self.forward_match_output_page_sizes
                        .borrow_mut()
                        .push(page.len());
                    if !visitor(page)? {
                        break;
                    }
                }
                return Ok(outcome);
            }

            if self.fault != TestFault::None {
                let outcome = self.match_forward_candidates(requests, cancellation)?;
                return visit_legacy_candidate_match_pages(
                    outcome,
                    requests.len(),
                    cancellation,
                    visitor,
                );
            }
            self.forward_matches.set(self.forward_matches.get() + 1);
            self.forward_match_batch_sizes
                .borrow_mut()
                .push(requests.len());
            self.inner
                .visit_forward_candidate_match_pages(requests, cancellation, &mut |page| {
                    self.forward_match_output_page_sizes
                        .borrow_mut()
                        .push(page.len());
                    visitor(page)
                })
        }

        fn visit_reverse_candidate_match_pages(
            &self,
            requests: &[BatchCandidateRequest],
            cancellation: &CancellationToken,
            visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
        ) -> StoreResult<BatchCandidateCompletionOutcome> {
            if self.fault != TestFault::None {
                let outcome = self.match_reverse_candidates(requests, cancellation)?;
                return visit_legacy_candidate_match_pages(
                    outcome,
                    requests.len(),
                    cancellation,
                    visitor,
                );
            }
            self.reverse_matches.set(self.reverse_matches.get() + 1);
            self.reverse_match_batch_sizes
                .borrow_mut()
                .push(requests.len());
            self.inner
                .visit_reverse_candidate_match_pages(requests, cancellation, &mut |page| {
                    self.reverse_match_output_page_sizes
                        .borrow_mut()
                        .push(page.len());
                    visitor(page)
                })
        }

        fn hydrate_candidate_paths(
            &self,
            candidates: &[CandidatePathIdentity],
            cancellation: &CancellationToken,
        ) -> StoreResult<Vec<(CandidatePathIdentity, PartialPath)>> {
            self.hydration_batch_sizes
                .borrow_mut()
                .push(candidates.len());
            let hydrated = self
                .inner
                .hydrate_candidate_paths(candidates, cancellation)?;
            self.hydrated_candidates
                .borrow_mut()
                .extend(candidates.iter().copied());
            if self.fault == TestFault::CancelOnHydration {
                cancellation.cancel();
            }
            Ok(hydrated)
        }

        fn visit_type_transfer_rules(
            &self,
            source_slot: SemanticId,
            cancellation: &CancellationToken,
            visitor: &mut dyn FnMut(&TypeTransferRule) -> StoreResult<bool>,
        ) -> StoreResult<ResolutionCompletion> {
            self.inner
                .visit_type_transfer_rules(source_slot, cancellation, visitor)
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TestCandidateDirection {
        Forward,
        Reverse,
    }

    struct RepeatingUnconditionalSource<'a> {
        inner: &'a PreloadedFragmentSource,
        direction: TestCandidateDirection,
        completion: ResolutionCompletion,
        calls: Cell<usize>,
        request_batch_sizes: RefCell<Vec<usize>>,
        conflict_on_call: Cell<Option<usize>>,
        conflicting_completion: Option<ResolutionCompletion>,
        cancel_on_call: Cell<Option<usize>>,
    }

    impl<'a> RepeatingUnconditionalSource<'a> {
        fn new(
            inner: &'a PreloadedFragmentSource,
            direction: TestCandidateDirection,
            completion: ResolutionCompletion,
        ) -> Self {
            Self {
                inner,
                direction,
                completion,
                calls: Cell::new(0),
                request_batch_sizes: RefCell::new(Vec::new()),
                conflict_on_call: Cell::new(None),
                conflicting_completion: None,
                cancel_on_call: Cell::new(None),
            }
        }

        fn with_one_conflict(mut self, call: usize, completion: ResolutionCompletion) -> Self {
            assert!(call > 0, "a candidate call ordinal is one-based");
            self.conflict_on_call.set(Some(call));
            self.conflicting_completion = Some(completion);
            self
        }

        fn with_one_cancellation(self, call: usize) -> Self {
            assert!(call > 0, "a candidate call ordinal is one-based");
            self.cancel_on_call.set(Some(call));
            self
        }

        fn replace_completion(
            &self,
            requests: &[BatchCandidateRequest],
            returned: BatchCandidateCompletionOutcome,
            cancellation: &CancellationToken,
        ) -> BatchCandidateCompletionOutcome {
            let call = self
                .calls
                .get()
                .checked_add(1)
                .expect("test candidate call count must fit usize");
            self.calls.set(call);
            self.request_batch_sizes.borrow_mut().push(requests.len());
            let (_, branches) = returned.into_parts();
            let mut completion = if self.conflict_on_call.get() == Some(call) {
                self.conflict_on_call.set(None);
                self.conflicting_completion
                    .clone()
                    .expect("a configured conflict has a completion")
            } else {
                self.completion.clone()
            };
            if self.cancel_on_call.get() == Some(call) {
                self.cancel_on_call.set(None);
                cancellation.cancel();
                completion = completion.combine(&cancelled_completion());
            }
            BatchCandidateCompletionOutcome::new(requests.len(), completion, branches)
        }
    }

    impl BatchResolutionFragmentSource for RepeatingUnconditionalSource<'_> {
        fn reference_seed(
            &self,
            query: ResolutionQuery,
            cancellation: &CancellationToken,
        ) -> StoreResult<Option<ReferenceSeed>> {
            self.inner.reference_seed(query, cancellation)
        }

        fn lookup_definition_node(
            &self,
            definition: SemanticId,
            cancellation: &CancellationToken,
        ) -> StoreResult<Option<BindingNodeId>> {
            self.inner.lookup_definition_node(definition, cancellation)
        }

        fn issue_reverse_reference_seeds(
            &self,
            requests: &[ReverseReferenceSeedRequest],
            cancellation: &CancellationToken,
        ) -> StoreResult<Vec<ReferenceSeed>> {
            self.inner
                .issue_reverse_reference_seeds(requests, cancellation)
        }

        fn visit_reference_seed_batches(
            &self,
            maximum_batch_size: usize,
            cancellation: &CancellationToken,
            visitor: &mut dyn FnMut(&ReferenceSeedBatch) -> StoreResult<bool>,
        ) -> StoreResult<ResolutionCompletion> {
            self.inner
                .visit_reference_seed_batches(maximum_batch_size, cancellation, visitor)
        }

        fn classify_endpoint_nodes(
            &self,
            nodes: &[BindingNodeId],
            cancellation: &CancellationToken,
        ) -> StoreResult<Vec<BatchEndpointClassification>> {
            self.inner.classify_endpoint_nodes(nodes, cancellation)
        }

        fn match_forward_candidates(
            &self,
            requests: &[BatchCandidateRequest],
            cancellation: &CancellationToken,
        ) -> StoreResult<BatchCandidateOutcome> {
            self.inner.match_forward_candidates(requests, cancellation)
        }

        fn visit_forward_candidate_match_pages(
            &self,
            requests: &[BatchCandidateRequest],
            cancellation: &CancellationToken,
            visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
        ) -> StoreResult<BatchCandidateCompletionOutcome> {
            let returned =
                self.inner
                    .visit_forward_candidate_match_pages(requests, cancellation, visitor)?;
            Ok(if self.direction == TestCandidateDirection::Forward {
                self.replace_completion(requests, returned, cancellation)
            } else {
                returned
            })
        }

        fn match_reverse_candidates(
            &self,
            requests: &[BatchCandidateRequest],
            cancellation: &CancellationToken,
        ) -> StoreResult<BatchCandidateOutcome> {
            self.inner.match_reverse_candidates(requests, cancellation)
        }

        fn visit_reverse_candidate_match_pages(
            &self,
            requests: &[BatchCandidateRequest],
            cancellation: &CancellationToken,
            visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
        ) -> StoreResult<BatchCandidateCompletionOutcome> {
            let returned =
                self.inner
                    .visit_reverse_candidate_match_pages(requests, cancellation, visitor)?;
            Ok(if self.direction == TestCandidateDirection::Reverse {
                self.replace_completion(requests, returned, cancellation)
            } else {
                returned
            })
        }

        fn hydrate_candidate_paths(
            &self,
            candidates: &[CandidatePathIdentity],
            cancellation: &CancellationToken,
        ) -> StoreResult<Vec<(CandidatePathIdentity, PartialPath)>> {
            self.inner.hydrate_candidate_paths(candidates, cancellation)
        }

        fn visit_type_transfer_rules(
            &self,
            source_slot: SemanticId,
            cancellation: &CancellationToken,
            visitor: &mut dyn FnMut(&TypeTransferRule) -> StoreResult<bool>,
        ) -> StoreResult<ResolutionCompletion> {
            self.inner
                .visit_type_transfer_rules(source_slot, cancellation, visitor)
        }
    }

    fn noncanonical_candidate_completion(label: &str) -> ResolutionCompletion {
        let high =
            ResolutionIncompleteReason::UnsupportedSemantic(semantic(&format!("{label}-high")));
        let low =
            ResolutionIncompleteReason::UnsupportedSemantic(semantic(&format!("{label}-low")));
        ResolutionCompletion::Incomplete(vec![high, low, high].into_boxed_slice().into())
    }

    fn paged_seeded_request_fixture() -> (PreloadedFragmentSource, SeededReferenceRequest) {
        let owner = fragment("operation-unconditional-paged-owner");
        let reference = semantic("operation-unconditional-paged-reference");
        let reference_node = node("operation-unconditional-paged-reference-node");
        let mut boundaries = Vec::with_capacity(MAX_SOURCE_ROWS_PER_BATCH + 1);
        let mut alternatives = Vec::with_capacity(MAX_SOURCE_ROWS_PER_BATCH + 1);
        for ordinal in 0..=MAX_SOURCE_ROWS_PER_BATCH {
            let boundary = node(&format!("operation-unconditional-boundary-{ordinal}"));
            boundaries.push(boundary);
            let lookup = semantic(&format!("operation-unconditional-lookup-{ordinal}"));
            alternatives.push(seeded_partial_path(
                path_id(&format!("operation-unconditional-seed-path-{ordinal}")),
                PartialPath::new(
                    endpoint(reference_node),
                    EndpointSignature::new(
                        boundary,
                        StackPattern::closed([lookup]),
                        StackPattern::closed(Vec::new()),
                    ),
                    Vec::new(),
                    [WitnessStep::Node(boundary)],
                    ResolutionCompletion::Complete,
                ),
            ));
        }
        let source = PreloadedFragmentSource::from_fragments_with_boundaries(
            boundaries,
            [PreloadedFragment::new(
                owner,
                [(reference_node, BindingNodeKind::Reference(reference))],
                [],
            )],
        );
        let seed = reference_seed(&source, ResolutionQuery::new(reference));
        let request = seeded_reference_request(seed, alternatives);
        (source, request)
    }

    #[test]
    fn forward_unconditional_completion_is_owned_once_across_one_seed_shapes() {
        let fixture = seeded_fixture(PrecedenceTier::LexicalBinding);
        let expected = noncanonical_candidate_completion("one-seed-many-shapes");
        let source = RepeatingUnconditionalSource::new(
            &fixture.source,
            TestCandidateDirection::Forward,
            expected.clone(),
        );
        let seed = reference_seed(&fixture.source, ResolutionQuery::new(fixture.reference));
        let request = seeded_reference_request(seed, seeded_alternatives(&fixture));

        let answer = BatchResolutionEngine::new(&source)
            .resolve_seeded_reference(&request, &CancellationToken::new())
            .expect("repeated operation completion is consistent");

        let mut expected_targets = vec![fixture.first_target, fixture.second_target];
        expected_targets.sort_unstable();
        assert_eq!(answer.targets(), expected_targets);
        assert_eq!(answer.completion(), &expected);
        assert_eq!(source.calls.get(), 1);
        assert_eq!(source.request_batch_sizes.borrow().as_slice(), &[2]);
    }

    #[test]
    fn forward_unconditional_completion_is_once_per_seed_across_shared_rounds() {
        let fixture = shared_fixture(false);
        let expected = noncanonical_candidate_completion("many-seeds-shared-rounds");
        let source = RepeatingUnconditionalSource::new(
            &fixture.source,
            TestCandidateDirection::Forward,
            expected.clone(),
        );
        let batch = ReferenceSeedBatch::new(
            [fixture.first_reference, fixture.second_reference]
                .map(ResolutionQuery::new)
                .map(|query| reference_seed(&fixture.source, query)),
        );

        let answer = BatchResolutionEngine::new(&source)
            .resolve_reference_batch(&batch, &CancellationToken::new())
            .expect("repeated operation completion is consistent");

        for reference in [fixture.first_reference, fixture.second_reference] {
            let answer = answer.answer(reference).expect("the seed has an answer");
            assert_eq!(answer.targets(), &[fixture.target]);
            assert_eq!(answer.completion(), &expected);
        }
        assert_eq!(source.calls.get(), 2);
        assert_eq!(
            source.request_batch_sizes.borrow().as_slice(),
            &[2, 1],
            "the second worklist round hash-conses both seeds onto one exact shared endpoint request"
        );
    }

    #[test]
    fn forward_unconditional_completion_is_owned_once_across_request_pages() {
        let (inner, request) = paged_seeded_request_fixture();
        let expected = noncanonical_candidate_completion("one-seed-many-pages");
        let source = RepeatingUnconditionalSource::new(
            &inner,
            TestCandidateDirection::Forward,
            expected.clone(),
        );

        let answer = BatchResolutionEngine::new(&source)
            .resolve_seeded_reference(&request, &CancellationToken::new())
            .expect("repeated operation completion is consistent");

        assert!(answer.targets().is_empty());
        assert_eq!(answer.completion(), &expected);
        assert_eq!(source.calls.get(), 2);
        assert_eq!(
            source.request_batch_sizes.borrow().as_slice(),
            &[MAX_SOURCE_ROWS_PER_BATCH, 1]
        );
    }

    #[test]
    fn legacy_candidate_adapter_rejects_duplicate_natural_identities() {
        let matched = BatchCandidateMatch::new(
            CandidatePathIdentity::new(
                fragment("legacy-adapter-duplicate-owner"),
                path_id("legacy-adapter-duplicate-path"),
            ),
            0,
        );
        let outcome = BatchCandidateOutcome::new(
            1,
            vec![matched, matched],
            ResolutionCompletion::Complete,
            [ResolutionCompletion::Complete],
        );

        let error =
            visit_legacy_candidate_match_pages(outcome, 1, &CancellationToken::new(), &mut |_| {
                Ok(true)
            })
            .expect_err("the legacy adapter must not silently deduplicate source rows");
        assert!(error.to_string().contains("repeated natural identity"));
    }

    #[test]
    fn conflicting_unconditional_completion_fails_closed_across_pages_and_rounds() {
        let stable = noncanonical_candidate_completion("conflict-stable");
        let conflicting = noncanonical_candidate_completion("conflict-different");

        let (paged_inner, paged_request) = paged_seeded_request_fixture();
        let paged = RepeatingUnconditionalSource::new(
            &paged_inner,
            TestCandidateDirection::Forward,
            stable.clone(),
        )
        .with_one_conflict(2, conflicting.clone());
        let page_error = BatchResolutionEngine::new(&paged)
            .resolve_seeded_reference(&paged_request, &CancellationToken::new())
            .expect_err("a page-local source conflict must fail closed");
        assert!(
            page_error
                .to_string()
                .contains("conflicting operation-wide unconditional completions"),
            "unexpected page conflict: {page_error}"
        );

        let round_fixture = shared_fixture(false);
        let rounds = RepeatingUnconditionalSource::new(
            &round_fixture.source,
            TestCandidateDirection::Forward,
            stable.clone(),
        )
        .with_one_conflict(2, conflicting);
        let query = ResolutionQuery::new(round_fixture.first_reference);
        let round_error = BatchResolutionEngine::new(&rounds)
            .resolve_reference(query, &CancellationToken::new())
            .expect_err("a later-round source conflict must fail closed");
        assert!(
            round_error
                .to_string()
                .contains("conflicting operation-wide unconditional completions"),
            "unexpected round conflict: {round_error}"
        );

        let retried = BatchResolutionEngine::new(&rounds)
            .resolve_reference(query, &CancellationToken::new())
            .expect("a failed operation cannot poison a fresh retry");
        assert_eq!(retried.targets(), &[round_fixture.target]);
        assert_eq!(retried.completion(), &stable);
    }

    #[test]
    fn unconditional_completion_survives_cancellation_and_fresh_retry() {
        let fixture = shared_fixture(false);
        let expected = noncanonical_candidate_completion("cancelled-operation-global");
        let source = RepeatingUnconditionalSource::new(
            &fixture.source,
            TestCandidateDirection::Forward,
            expected.clone(),
        )
        .with_one_cancellation(2);
        let query = ResolutionQuery::new(fixture.first_reference);
        let cancelled = BatchResolutionEngine::new(&source)
            .resolve_reference(query, &CancellationToken::new())
            .expect("cancellation is semantic evidence, not a store failure");

        assert!(cancelled.targets().is_empty());
        let ResolutionCompletion::Incomplete(cancelled_reasons) = cancelled.completion() else {
            panic!("a cancelled operation must remain incomplete");
        };
        assert!(cancelled_reasons.contains(&ResolutionIncompleteReason::Cancelled));
        let ResolutionCompletion::Incomplete(expected_reasons) = &expected else {
            unreachable!("the fixture completion is incomplete");
        };
        for reason in expected_reasons.iter() {
            assert!(cancelled_reasons.contains(reason));
        }

        let retried = BatchResolutionEngine::new(&source)
            .resolve_reference(query, &CancellationToken::new())
            .expect("a cancelled operation cannot poison a fresh retry");
        assert_eq!(retried.targets(), &[fixture.target]);
        assert_eq!(retried.completion(), &expected);
    }

    #[test]
    fn cancellation_discards_the_level_and_cannot_publish_a_complete_negative() {
        let fixture = shared_fixture(false);
        let source = FaultingSource::new(&fixture.source, TestFault::CancelOnHydration);
        let batch = ReferenceSeedBatch::new(
            [fixture.first_reference, fixture.second_reference]
                .map(ResolutionQuery::new)
                .map(|query| reference_seed(&fixture.source, query)),
        );

        let answer = BatchResolutionEngine::new(&source)
            .resolve_reference_batch(&batch, &CancellationToken::new())
            .expect("cancellation is a typed incomplete result");

        assert_eq!(answer.answers().len(), 2);
        assert!(answer.answers().iter().all(|entry| {
            entry.answer().targets().is_empty()
                && matches!(
                    entry.answer().completion(),
                    ResolutionCompletion::Incomplete(reasons)
                        if reasons.contains(&ResolutionIncompleteReason::Cancelled)
                )
        }));
        assert!(matches!(
            answer.completion(),
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::Cancelled)
        ));
    }

    #[test]
    fn seeded_cancellation_discards_all_owner_alternatives_atomically() {
        let fixture = seeded_fixture(PrecedenceTier::ExplicitImport);
        let source = FaultingSource::new(&fixture.source, TestFault::CancelOnHydration);
        let seed = reference_seed(&fixture.source, ResolutionQuery::new(fixture.reference));
        let request = seeded_reference_request(seed, seeded_alternatives(&fixture));
        let cancellation = CancellationToken::new();

        let answer = BatchResolutionEngine::new(&source)
            .resolve_seeded_reference(&request, &cancellation)
            .expect("cancellation is typed incompleteness");

        assert!(answer.targets().is_empty());
        assert!(answer.witnesses().is_empty());
        assert!(matches!(
            answer.completion(),
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::Cancelled)
        ));
    }

    #[test]
    fn seeded_initialization_cancellation_drains_every_alternative_completion() {
        let fixture = seeded_fixture(PrecedenceTier::ExplicitImport);
        let source = FaultingSource::new(&fixture.source, TestFault::None);
        let seed = reference_seed(&fixture.source, ResolutionQuery::new(fixture.reference));
        let alternatives = (0..=CANCELLATION_QUANTUM)
            .map(|ordinal| {
                let reason = ResolutionIncompleteReason::UnsupportedSemantic(semantic(&format!(
                    "seeded-initialization-gap-{ordinal}"
                )));
                seeded_partial_path(
                    path_id(&format!("seeded-initialization-path-{ordinal}")),
                    path(
                        fixture.reference_node,
                        fixture.first_owner,
                        ResolutionCompletion::incomplete([reason]),
                    ),
                )
            })
            .collect::<Vec<_>>();
        let request = seeded_reference_request(seed, alternatives);
        // The initial boundary remains live. Cancellation is first observed
        // while retaining the already-owned alternative completion boxes.
        let cancellation = CancellationToken::cancel_after_checks_for_test(2);

        let answer = BatchResolutionEngine::new(&source)
            .resolve_seeded_reference(&request, &cancellation)
            .expect("seed initialization cancellation is typed incompleteness");

        assert!(answer.targets().is_empty());
        assert!(answer.witnesses().is_empty());
        assert_eq!(source.forward_matches.get(), 0);
        let ResolutionCompletion::Incomplete(reasons) = answer.completion() else {
            panic!("cancelled seed initialization must be incomplete");
        };
        assert_eq!(reasons.get(0), Some(&ResolutionIncompleteReason::Cancelled));
        for ordinal in 0..=CANCELLATION_QUANTUM {
            assert!(
                reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(semantic(
                    &format!("seeded-initialization-gap-{ordinal}")
                )))
            );
        }
    }

    #[test]
    fn seeded_source_error_returns_no_publishable_answer() {
        let fixture = seeded_fixture(PrecedenceTier::ExplicitImport);
        let source = FaultingSource::new(&fixture.source, TestFault::FailOnForwardMatch);
        let seed = reference_seed(&fixture.source, ResolutionQuery::new(fixture.reference));
        let request = seeded_reference_request(seed, seeded_alternatives(&fixture));

        let result = BatchResolutionEngine::new(&source)
            .resolve_seeded_reference(&request, &CancellationToken::new());

        let error = result.expect_err("a source failure must fail the whole seeded operation");
        assert!(error.to_string().contains("injected seeded source failure"));
        assert_eq!(source.forward_matches.get(), 1);
        assert!(source.hydrated_candidates.borrow().is_empty());
    }

    #[test]
    fn source_error_after_a_completed_level_returns_no_publishable_batch() {
        let fixture = shared_fixture(false);
        let source = FaultingSource::new(&fixture.source, TestFault::FailOnSecondForwardMatch);
        let batch = ReferenceSeedBatch::new(
            [fixture.first_reference, fixture.second_reference]
                .map(ResolutionQuery::new)
                .map(|query| reference_seed(&fixture.source, query)),
        );

        let result = BatchResolutionEngine::new(&source)
            .resolve_reference_batch(&batch, &CancellationToken::new());

        assert!(result.is_err());
        assert_eq!(source.forward_matches.get(), 2);
    }

    #[test]
    fn semantic_incompleteness_propagates_through_batch_selection() {
        let owner = fragment("incomplete-fragment");
        let reference = semantic("incomplete-reference");
        let target = semantic("incomplete-target");
        let gap = semantic("incomplete-gap");
        let reference_node = node("incomplete-reference-node");
        let target_node = node("incomplete-target-node");
        let source = PreloadedFragmentSource::from_fragments([PreloadedFragment::new(
            owner,
            [
                (reference_node, BindingNodeKind::Reference(reference)),
                (target_node, BindingNodeKind::Definition(target)),
            ],
            [(
                path_id("incomplete-path"),
                path(
                    reference_node,
                    target_node,
                    ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(gap),
                    ]),
                ),
            )],
        )]);

        let answer = BatchResolutionEngine::new(&source)
            .resolve_reference_batch(
                &ReferenceSeedBatch::new([ReferenceSeed::new(
                    owner,
                    ResolutionQuery::new(reference),
                    reference_node,
                    ResolutionCompletion::Complete,
                )]),
                &CancellationToken::new(),
            )
            .expect("preloaded batch source is infallible");

        assert_eq!(answer.answer(reference).unwrap().targets(), &[target]);
        assert!(matches!(
            answer.answer(reference).unwrap().completion(),
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(gap))
        ));
        assert_eq!(
            answer.completion(),
            answer.answer(reference).unwrap().completion()
        );
    }

    #[test]
    fn higher_ranked_seed_route_discharges_an_endpoint_sibling_gap() {
        let owner = fragment("endpoint-terminal-fragment");
        let reference = semantic("endpoint-terminal-reference");
        let target = semantic("endpoint-terminal-target");
        let choice = semantic("endpoint-terminal-choice");
        let reference_node = node("endpoint-terminal-reference-node");
        let target_node = node("endpoint-terminal-target-node");
        let incomplete_endpoint = node("endpoint-terminal-incomplete-endpoint");
        let source = PreloadedFragmentSource::from_fragments([PreloadedFragment::new(
            owner,
            [
                (reference_node, BindingNodeKind::Reference(reference)),
                (target_node, BindingNodeKind::Definition(target)),
                (incomplete_endpoint, BindingNodeKind::Scope),
            ],
            [],
        )]);
        let faulting = FaultingSource::new(&source, TestFault::ForwardMatchWithGap);
        let seed = reference_seed(&source, ResolutionQuery::new(reference));
        let request = seeded_reference_request(
            seed,
            [
                seeded_partial_path(
                    path_id("endpoint-terminal-winning-route"),
                    ranked_path(
                        reference_node,
                        target_node,
                        choice,
                        PrecedenceTier::LexicalBinding,
                    ),
                ),
                seeded_partial_path(
                    path_id("endpoint-terminal-losing-route"),
                    ranked_path(
                        reference_node,
                        incomplete_endpoint,
                        choice,
                        PrecedenceTier::ExplicitImport,
                    ),
                ),
            ],
        );

        let answer = BatchResolutionEngine::new(&faulting)
            .resolve_seeded_reference(&request, &CancellationToken::new())
            .expect("faulting preload source is infallible");

        assert_eq!(answer.targets(), &[target]);
        assert_eq!(answer.completion(), &ResolutionCompletion::Complete);
    }

    #[test]
    fn batch_and_compatibility_discharge_the_same_losing_terminal_path() {
        let owner = fragment("terminal-parity-fragment");
        let reference = semantic("terminal-parity-reference");
        let target = semantic("terminal-parity-target");
        let choice = semantic("terminal-parity-choice");
        let gap = semantic("terminal-parity-gap");
        let reference_node = node("terminal-parity-reference-node");
        let target_node = node("terminal-parity-target-node");
        let dead_end = node("terminal-parity-dead-end");
        let losing = ranked_path(
            reference_node,
            dead_end,
            choice,
            PrecedenceTier::ExplicitImport,
        )
        .with_additional_completion(&ResolutionCompletion::incomplete([
            ResolutionIncompleteReason::UnsupportedSemantic(gap),
        ]));
        let source = PreloadedFragmentSource::from_fragments([PreloadedFragment::new(
            owner,
            [
                (reference_node, BindingNodeKind::Reference(reference)),
                (target_node, BindingNodeKind::Definition(target)),
                (dead_end, BindingNodeKind::Scope),
            ],
            [
                (
                    path_id("terminal-parity-winner"),
                    ranked_path(
                        reference_node,
                        target_node,
                        choice,
                        PrecedenceTier::LexicalBinding,
                    ),
                ),
                (path_id("terminal-parity-loser"), losing),
            ],
        )]);
        let cancellation = CancellationToken::new();

        let compatibility = ResolutionEngine::new(&source)
            .resolve_reference(ResolutionQuery::new(reference), &cancellation)
            .expect("preloaded compatibility source is infallible");
        let batch = BatchResolutionEngine::new(&source)
            .resolve_reference(ResolutionQuery::new(reference), &cancellation)
            .expect("preloaded batch source is infallible");

        assert_eq!(batch, compatibility);
        assert_eq!(batch.targets(), &[target]);
        assert_eq!(batch.completion(), &ResolutionCompletion::Complete);
    }

    #[test]
    fn zero_seed_enumeration_gap_makes_broad_summary_incomplete() {
        let fixture = shared_fixture(false);
        let source = FaultingSource::new(&fixture.source, TestFault::EnumerationGapWithoutSeeds);
        let mut staged_batches = 0;

        let summary = BatchResolutionEngine::new(&source)
            .stream_all_reference_batches(
                MAX_REFERENCE_SEEDS_PER_BATCH,
                &CancellationToken::new(),
                &mut |_| {
                    staged_batches += 1;
                    Ok(())
                },
            )
            .expect("semantic enumeration gaps are typed incompleteness");

        assert_eq!(staged_batches, 0);
        assert!(matches!(
            summary.completion(),
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(
                    semantic("enumeration-coverage-gap")
                ))
        ));
    }

    #[test]
    fn empty_candidate_match_with_gap_cannot_prove_a_negative() {
        let fixture = shared_fixture(false);
        let source = FaultingSource::new(&fixture.source, TestFault::EmptyForwardMatchWithGap);

        let answer = BatchResolutionEngine::new(&source)
            .resolve_reference(
                ResolutionQuery::new(fixture.first_reference),
                &CancellationToken::new(),
            )
            .expect("semantic candidate gaps are typed incompleteness");

        assert!(answer.targets().is_empty());
        assert!(matches!(
            answer.completion(),
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(
                    semantic("candidate-coverage-gap")
                ))
        ));
    }

    #[test]
    fn forward_match_cancellation_preserves_returned_gap_evidence() {
        let fixture = shared_fixture(false);
        let source = FaultingSource::new(&fixture.source, TestFault::CancelOnForwardMatchWithGap);

        let answer = BatchResolutionEngine::new(&source)
            .resolve_reference(
                ResolutionQuery::new(fixture.first_reference),
                &CancellationToken::new(),
            )
            .expect("cancellation and semantic gaps are typed incompleteness");

        assert!(answer.targets().is_empty());
        assert!(matches!(
            answer.completion(),
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::Cancelled)
                    && reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(
                        semantic("candidate-coverage-gap")
                    ))
        ));
    }

    #[test]
    fn reference_seed_cancellation_preserves_returned_gap_evidence() {
        let fixture = shared_fixture(false);
        let source = FaultingSource::new(&fixture.source, TestFault::CancelOnReferenceSeedWithGap);

        let answer = BatchResolutionEngine::new(&source)
            .resolve_reference(
                ResolutionQuery::new(fixture.first_reference),
                &CancellationToken::new(),
            )
            .expect("seed cancellation and gaps are typed incompleteness");

        assert!(answer.targets().is_empty());
        assert!(matches!(
            answer.completion(),
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::Cancelled)
                    && reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(
                        semantic("cancelled-reference-seed-gap")
                    ))
        ));
    }

    #[test]
    fn plural_reference_seed_default_is_atomic_and_preserves_a_sole_source_box() {
        let fixture = shared_fixture(false);
        let source = FaultingSource::new(
            &fixture.source,
            TestFault::CancelFirstReferenceSeedWithNoncanonicalGap,
        );
        let queries = [
            ResolutionQuery::new(fixture.first_reference),
            ResolutionQuery::new(fixture.second_reference),
        ];
        let high = ResolutionIncompleteReason::UnsupportedSemantic(semantic(
            "plural-reference-seed-noncanonical-high",
        ));
        let low = ResolutionIncompleteReason::UnsupportedSemantic(semantic(
            "plural-reference-seed-noncanonical-low",
        ));
        let exact =
            ResolutionCompletion::Incomplete(vec![high, low, high].into_boxed_slice().into());

        let cancelled = source
            .lookup_reference_seeds(&queries, &CancellationToken::new())
            .expect("the compatibility plural seed source is infallible");
        assert_eq!(cancelled.terminal(), ReferenceSeedReadTerminal::Cancelled);
        assert!(cancelled.rows().is_empty());
        assert_eq!(cancelled.evidence(), &exact);
        assert_eq!(
            source.reference_seeds.get(),
            1,
            "cancellation must suppress the entire remaining scalar prefix"
        );

        let retry = source
            .lookup_reference_seeds(&queries, &CancellationToken::new())
            .expect("a fresh token retries the same immutable source");
        assert_eq!(retry.terminal(), ReferenceSeedReadTerminal::Exhausted);
        assert_eq!(retry.evidence(), &ResolutionCompletion::Complete);
        assert_eq!(retry.rows().len(), queries.len());
        for (request_ordinal, (query, row)) in queries.into_iter().zip(retry.rows()).enumerate() {
            assert_eq!(row.request_ordinal(), request_ordinal);
            assert_eq!(row.query(), query);
            assert_eq!(row.seed().map(ReferenceSeed::query), Some(query));
        }
    }

    #[test]
    fn preloaded_plural_reference_seed_lookup_preserves_ordinals_and_explicit_absence() {
        let fixture = shared_fixture(false);
        let absent = semantic("plural-reference-seed-absent");
        let queries = [
            ResolutionQuery::new(fixture.second_reference),
            ResolutionQuery::new(absent),
            ResolutionQuery::new(fixture.first_reference),
        ];

        let outcome = fixture
            .source
            .lookup_reference_seeds(&queries, &CancellationToken::new())
            .expect("the preload plural seed source is infallible");
        assert_eq!(outcome.terminal(), ReferenceSeedReadTerminal::Exhausted);
        assert_eq!(outcome.evidence(), &ResolutionCompletion::Complete);
        assert_eq!(outcome.rows().len(), queries.len());
        for (request_ordinal, (query, row)) in queries.into_iter().zip(outcome.rows()).enumerate() {
            assert_eq!(row.request_ordinal(), request_ordinal);
            assert_eq!(row.query(), query);
            assert_eq!(
                row.seed().map(ReferenceSeed::query),
                (query.reference() != absent).then_some(query)
            );
        }

        let too_many = std::iter::repeat_n(
            ResolutionQuery::new(fixture.first_reference),
            MAX_REFERENCE_SEEDS_PER_BATCH + 1,
        )
        .collect::<Vec<_>>();
        assert!(
            std::panic::catch_unwind(|| {
                let _ = fixture
                    .source
                    .lookup_reference_seeds(&too_many, &CancellationToken::new());
            })
            .is_err(),
            "the plural preload source must enforce the public 256-query bound"
        );
    }

    #[test]
    fn returned_seed_cancelled_evidence_stops_before_path_construction() {
        let fixture = shared_fixture(false);
        let source = FaultingSource::new(
            &fixture.source,
            TestFault::ReferenceSeedWithCancelledEvidence,
        );
        let cancellation = CancellationToken::new();

        let answer = BatchResolutionEngine::new(&source)
            .resolve_reference(ResolutionQuery::new(fixture.first_reference), &cancellation)
            .expect("source-returned cancellation is typed incompleteness");

        assert!(
            !cancellation.is_cancelled(),
            "the source leaves the token live"
        );
        assert!(answer.targets().is_empty());
        assert!(answer.witnesses().is_empty());
        assert_eq!(source.forward_matches.get(), 0);
        assert!(matches!(
            answer.completion(),
            ResolutionCompletion::Incomplete(reasons)
                if reasons.get(0) == Some(&ResolutionIncompleteReason::Cancelled)
                    && reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(
                        semantic("returned-cancelled-reference-seed-gap")
                    ))
        ));
    }

    #[test]
    fn forward_pages_every_high_fanout_source_relation_without_changing_answer() {
        fn source(reverse_rows: bool) -> (PreloadedFragmentSource, SemanticId) {
            let owner = fragment("forward-paged-source");
            let reference = semantic("forward-paged-reference");
            let reference_node = node("forward-paged-reference-node");
            let mut nodes = vec![(reference_node, BindingNodeKind::Reference(reference))];
            let mut paths = Vec::new();
            for ordinal in 0..=MAX_SOURCE_ROWS_PER_BATCH {
                let seam = node(&format!("forward-paged-seam-{ordinal}"));
                let target = semantic(&format!("forward-paged-target-{ordinal}"));
                let target_node = node(&format!("forward-paged-target-node-{ordinal}"));
                nodes.push((seam, BindingNodeKind::Scope));
                nodes.push((target_node, BindingNodeKind::Definition(target)));
                paths.push((
                    path_id(&format!("forward-paged-entry-{ordinal}")),
                    path(reference_node, seam, ResolutionCompletion::Complete),
                ));
                paths.push((
                    path_id(&format!("forward-paged-exit-{ordinal}")),
                    path(seam, target_node, ResolutionCompletion::Complete),
                ));
            }
            if reverse_rows {
                paths.reverse();
            }
            (
                PreloadedFragmentSource::from_fragments([PreloadedFragment::new(
                    owner, nodes, paths,
                )]),
                reference,
            )
        }

        let (ordered_source, reference) = source(false);
        let recording = FaultingSource::new(&ordered_source, TestFault::None);
        let ordered = BatchResolutionEngine::new(&recording)
            .resolve_reference(ResolutionQuery::new(reference), &CancellationToken::new())
            .expect("preloaded forward reads are infallible");
        let storage_order =
            FaultingSource::new(&ordered_source, TestFault::ReverseForwardCandidateStream);
        let storage_order = BatchResolutionEngine::new(&storage_order)
            .resolve_reference(ResolutionQuery::new(reference), &CancellationToken::new())
            .expect("forward storage-cursor order is immaterial");
        assert_eq!(ordered, storage_order);

        let duplicate = FaultingSource::new(&ordered_source, TestFault::DuplicateForwardCandidate);
        let duplicate = BatchResolutionEngine::new(&duplicate)
            .resolve_reference(ResolutionQuery::new(reference), &CancellationToken::new())
            .expect_err("duplicate forward candidate identities must fail closed");
        assert!(duplicate.to_string().contains("repeated natural identity"));

        let (reversed, reversed_reference) = source(true);
        let reversed = BatchResolutionEngine::new(&reversed)
            .resolve_reference(
                ResolutionQuery::new(reversed_reference),
                &CancellationToken::new(),
            )
            .expect("reordered preloaded forward reads are infallible");

        assert_eq!(ordered, reversed);
        assert_eq!(ordered.targets().len(), MAX_SOURCE_ROWS_PER_BATCH + 1);
        assert_eq!(ordered.completion(), &ResolutionCompletion::Complete);
        for sizes in [
            &recording.classified_batch_sizes,
            &recording.forward_match_batch_sizes,
            &recording.hydration_batch_sizes,
        ] {
            assert!(
                sizes
                    .borrow()
                    .iter()
                    .all(|&size| size <= MAX_SOURCE_ROWS_PER_BATCH),
                "every forward source page must respect the explicit row cap: {:?}",
                sizes.borrow()
            );
            assert!(
                sizes.borrow().contains(&MAX_SOURCE_ROWS_PER_BATCH),
                "the law must exercise one full forward source page: {:?}",
                sizes.borrow()
            );
            assert!(
                sizes.borrow().contains(&1),
                "the law must exercise the forward page remainder: {:?}",
                sizes.borrow()
            );
        }
        assert!(
            recording
                .forward_match_output_page_sizes
                .borrow()
                .iter()
                .all(|&size| (1..=MAX_SOURCE_ROWS_PER_BATCH).contains(&size)),
            "every returned forward match page must respect the row cap: {:?}",
            recording.forward_match_output_page_sizes.borrow()
        );
        assert!(
            recording
                .forward_match_output_page_sizes
                .borrow()
                .contains(&MAX_SOURCE_ROWS_PER_BATCH),
            "one endpoint must emit one full forward output page"
        );
        assert!(
            recording
                .forward_match_output_page_sizes
                .borrow()
                .contains(&1),
            "one endpoint must emit the forward output remainder"
        );
    }

    #[test]
    fn reverse_completion_ledger_preserves_one_sided_public_shape() {
        let first =
            ResolutionIncompleteReason::UnsupportedSemantic(semantic("reverse-ledger-gap-b"));
        let second =
            ResolutionIncompleteReason::UnsupportedSemantic(semantic("reverse-ledger-gap-a"));
        let noncanonical =
            ResolutionCompletion::Incomplete(vec![first, second, first].into_boxed_slice().into());
        let cancellation = CancellationToken::new();

        let mut sole = BatchCompletionLedger::default();
        let mut work = 0;
        assert!(!sole.include(&noncanonical, &cancellation, &mut work));
        let (completion, observed_cancellation) = sole.finish(&cancellation, &mut work);
        assert!(!observed_cancellation);
        assert_eq!(completion, noncanonical);

        let additional = ResolutionCompletion::Incomplete(vec![second].into_boxed_slice().into());
        let mut union = BatchCompletionLedger::default();
        assert!(!union.include(&noncanonical, &cancellation, &mut work));
        assert!(!union.include(&additional, &cancellation, &mut work));
        let (completion, observed_cancellation) = union.finish(&cancellation, &mut work);
        assert!(!observed_cancellation);
        assert_eq!(completion, noncanonical.combine(&additional));

        assert!(
            std::panic::catch_unwind(|| {
                let cancellation = CancellationToken::new();
                let empty = ResolutionCompletion::Incomplete(Vec::new().into_boxed_slice().into());
                let mut ledger = BatchCompletionLedger::default();
                let mut work = 0;
                assert!(!ledger.include(&empty, &cancellation, &mut work));
                let _ = ledger.include(&empty, &cancellation, &mut work);
            })
            .is_err(),
            "two empty public Incomplete operands must preserve combine's construction panic"
        );
    }

    struct JavaOverlayLawSource {
        inner: PreloadedFragmentSource,
        reverse_gaps: Box<[(ReverseCandidateGapIdentity, ResolutionIncompleteReason)]>,
        raw_reverse_visits: Cell<usize>,
        filtered_reverse_visits: Cell<usize>,
        manual_forward_matches: Option<Box<[BatchCandidateMatch]>>,
        ignore_forward_stop: bool,
        forward_completion: ResolutionCompletion,
        foreign_hydration: Option<(CandidatePathIdentity, PartialPath)>,
    }

    impl JavaOverlayLawSource {
        fn new(inner: PreloadedFragmentSource) -> Self {
            Self {
                inner,
                reverse_gaps: Box::new([]),
                raw_reverse_visits: Cell::new(0),
                filtered_reverse_visits: Cell::new(0),
                manual_forward_matches: None,
                ignore_forward_stop: false,
                forward_completion: ResolutionCompletion::Complete,
                foreign_hydration: None,
            }
        }

        fn with_manual_forward_matches(
            mut self,
            matches: impl IntoIterator<Item = BatchCandidateMatch>,
            ignore_stop: bool,
        ) -> Self {
            self.manual_forward_matches = Some(matches.into_iter().collect());
            self.ignore_forward_stop = ignore_stop;
            self
        }

        fn add_forward_completion(
            &self,
            outcome: BatchCandidateCompletionOutcome,
        ) -> BatchCandidateCompletionOutcome {
            let request_count = outcome.branch_completions().len();
            let (unconditional, branches) = outcome.into_parts();
            BatchCandidateCompletionOutcome::new(
                request_count,
                unconditional.combine(&self.forward_completion),
                branches,
            )
        }

        fn add_reverse_gap_completion(
            &self,
            outcome: BatchCandidateCompletionOutcome,
            exclusions: Option<&ReverseCandidateGapExclusionPlan>,
            cancellation: &CancellationToken,
        ) -> StoreResult<BatchCandidateCompletionOutcome> {
            let mut excluded = BTreeSet::new();
            if let Some(exclusions) = exclusions {
                for &identity in exclusions.identities.iter() {
                    if !self
                        .reverse_gaps
                        .iter()
                        .any(|(candidate, _)| *candidate == identity)
                    {
                        return Err(StoreError::new(format!(
                            "selected reverse candidate coverage has no exact gap ({}, {})",
                            identity.fragment(),
                            identity.gap_id()
                        )));
                    }
                    excluded.insert(identity);
                }
            }
            let mut reasons = BTreeSet::new();
            for &(identity, reason) in self.reverse_gaps.iter() {
                if !excluded.contains(&identity) {
                    reasons.insert(reason);
                }
            }
            let gap_completion = if reasons.is_empty() {
                ResolutionCompletion::Complete
            } else {
                ResolutionCompletion::Incomplete(reasons.into_iter().collect::<Vec<_>>().into())
            };
            let request_count = outcome.branch_completions().len();
            let (unconditional, branches) = outcome.into_parts();
            let mut unconditional = unconditional.combine(&gap_completion);
            if cancellation.is_cancelled() {
                unconditional = unconditional.combine(&cancelled_completion());
            }
            Ok(BatchCandidateCompletionOutcome::new(
                request_count,
                unconditional,
                branches,
            ))
        }
    }

    impl BatchResolutionFragmentSource for JavaOverlayLawSource {
        fn reference_seed(
            &self,
            query: ResolutionQuery,
            cancellation: &CancellationToken,
        ) -> StoreResult<Option<ReferenceSeed>> {
            self.inner.reference_seed(query, cancellation)
        }

        fn lookup_definition_node(
            &self,
            definition: SemanticId,
            cancellation: &CancellationToken,
        ) -> StoreResult<Option<BindingNodeId>> {
            self.inner.lookup_definition_node(definition, cancellation)
        }

        fn lookup_definition_nodes(
            &self,
            definitions: &[SemanticId],
            cancellation: &CancellationToken,
        ) -> StoreResult<Vec<BatchDefinitionNode>> {
            self.inner
                .lookup_definition_nodes(definitions, cancellation)
        }

        fn issue_reverse_reference_seeds(
            &self,
            requests: &[ReverseReferenceSeedRequest],
            cancellation: &CancellationToken,
        ) -> StoreResult<Vec<ReferenceSeed>> {
            self.inner
                .issue_reverse_reference_seeds(requests, cancellation)
        }

        fn visit_reference_seed_batches(
            &self,
            maximum_batch_size: usize,
            cancellation: &CancellationToken,
            visitor: &mut dyn FnMut(&ReferenceSeedBatch) -> StoreResult<bool>,
        ) -> StoreResult<ResolutionCompletion> {
            self.inner
                .visit_reference_seed_batches(maximum_batch_size, cancellation, visitor)
        }

        fn classify_endpoint_nodes(
            &self,
            nodes: &[BindingNodeId],
            cancellation: &CancellationToken,
        ) -> StoreResult<Vec<BatchEndpointClassification>> {
            self.inner.classify_endpoint_nodes(nodes, cancellation)
        }

        fn match_forward_candidates(
            &self,
            requests: &[BatchCandidateRequest],
            cancellation: &CancellationToken,
        ) -> StoreResult<BatchCandidateOutcome> {
            if let Some(matches) = &self.manual_forward_matches {
                let unconditional = if cancellation.is_cancelled() {
                    self.forward_completion.combine(&cancelled_completion())
                } else {
                    self.forward_completion.clone()
                };
                return Ok(BatchCandidateOutcome::new(
                    requests.len(),
                    matches.to_vec(),
                    unconditional,
                    std::iter::repeat_n(ResolutionCompletion::Complete, requests.len()),
                ));
            }
            let outcome = self
                .inner
                .match_forward_candidates(requests, cancellation)?;
            let (matches, unconditional, branches) = outcome.into_parts();
            Ok(BatchCandidateOutcome::new(
                requests.len(),
                matches,
                unconditional.combine(&self.forward_completion),
                branches,
            ))
        }

        fn visit_forward_candidate_match_pages(
            &self,
            requests: &[BatchCandidateRequest],
            cancellation: &CancellationToken,
            visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
        ) -> StoreResult<BatchCandidateCompletionOutcome> {
            if let Some(matches) = &self.manual_forward_matches {
                for page in matches.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
                    let keep_going = visitor(page)?;
                    if !keep_going && !self.ignore_forward_stop {
                        break;
                    }
                }
                return Ok(BatchCandidateCompletionOutcome::new(
                    requests.len(),
                    self.forward_completion.clone(),
                    std::iter::repeat_n(ResolutionCompletion::Complete, requests.len()),
                ));
            }
            let outcome =
                self.inner
                    .visit_forward_candidate_match_pages(requests, cancellation, visitor)?;
            Ok(self.add_forward_completion(outcome))
        }

        fn match_reverse_candidates(
            &self,
            requests: &[BatchCandidateRequest],
            cancellation: &CancellationToken,
        ) -> StoreResult<BatchCandidateOutcome> {
            self.inner.match_reverse_candidates(requests, cancellation)
        }

        fn visit_reverse_candidate_match_pages(
            &self,
            requests: &[BatchCandidateRequest],
            cancellation: &CancellationToken,
            visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
        ) -> StoreResult<BatchCandidateCompletionOutcome> {
            self.raw_reverse_visits
                .set(self.raw_reverse_visits.get() + 1);
            let outcome =
                self.inner
                    .visit_reverse_candidate_match_pages(requests, cancellation, visitor)?;
            self.add_reverse_gap_completion(outcome, None, cancellation)
        }

        fn visit_reverse_candidate_match_pages_with_gap_exclusions_shared(
            &self,
            requests: &[BatchCandidateRequest],
            exclusions: &mut ReverseCandidateGapExclusionPlan,
            cancellation: &CancellationToken,
            visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
        ) -> StoreResult<BatchCandidateCompletionOutcome> {
            if exclusions.is_empty() {
                return self.visit_reverse_candidate_match_pages(requests, cancellation, visitor);
            }
            self.filtered_reverse_visits
                .set(self.filtered_reverse_visits.get() + 1);
            let outcome =
                self.inner
                    .visit_reverse_candidate_match_pages(requests, cancellation, visitor)?;
            self.add_reverse_gap_completion(outcome, Some(exclusions), cancellation)
        }

        fn hydrate_candidate_paths(
            &self,
            candidates: &[CandidatePathIdentity],
            cancellation: &CancellationToken,
        ) -> StoreResult<Vec<(CandidatePathIdentity, PartialPath)>> {
            let mut hydrated = self
                .inner
                .hydrate_candidate_paths(candidates, cancellation)?;
            if let Some(foreign) = &self.foreign_hydration {
                hydrated.push(foreign.clone());
            }
            Ok(hydrated)
        }

        fn visit_type_transfer_rules(
            &self,
            source_slot: SemanticId,
            cancellation: &CancellationToken,
            visitor: &mut dyn FnMut(&TypeTransferRule) -> StoreResult<bool>,
        ) -> StoreResult<ResolutionCompletion> {
            self.inner
                .visit_type_transfer_rules(source_slot, cancellation, visitor)
        }
    }

    #[test]
    fn successful_stitches_exclude_incompatible_coarse_matches() {
        let owner = fragment("successful-stitch-owner");
        let reference = semantic("successful-stitch-reference");
        let target = semantic("successful-stitch-target");
        let reference_node = node("successful-stitch-reference-node");
        let target_node = node("successful-stitch-target-node");
        let compatible_id = path_id("successful-stitch-compatible");
        let incompatible_id = path_id("successful-stitch-incompatible");
        let compatible = path(reference_node, target_node, ResolutionCompletion::Complete);
        let incompatible = PartialPath::new(
            EndpointSignature::new(
                reference_node,
                StackPattern::closed([semantic("successful-stitch-unexpected-symbol")]),
                StackPattern::closed(Vec::new()),
            ),
            endpoint(target_node),
            Vec::new(),
            [WitnessStep::Node(target_node)],
            ResolutionCompletion::Complete,
        );
        let inner = PreloadedFragmentSource::from_fragments([PreloadedFragment::new(
            owner,
            [
                (reference_node, BindingNodeKind::Reference(reference)),
                (target_node, BindingNodeKind::Definition(target)),
            ],
            [(compatible_id, compatible), (incompatible_id, incompatible)],
        )]);
        let source = JavaOverlayLawSource::new(inner).with_manual_forward_matches(
            [compatible_id, incompatible_id]
                .map(|path| BatchCandidateMatch::new(CandidatePathIdentity::new(owner, path), 0)),
            false,
        );
        let seed = source
            .reference_seed(ResolutionQuery::new(reference), &CancellationToken::new())
            .expect("manual coarse-match seed lookup is infallible")
            .expect("manual coarse-match fixture has one reference seed");

        let answer = BatchResolutionEngine::new(&source)
            .resolve_reference_batch(&ReferenceSeedBatch::new([seed]), &CancellationToken::new())
            .expect("manual coarse matches resolve");

        assert_eq!(answer.metrics().distinct_candidate_matches(), 2);
        assert_eq!(answer.metrics().distinct_path_hydrations(), 2);
        assert_eq!(answer.metrics().composition_attempts(), 2);
        assert_eq!(answer.metrics().successful_stitches(), 1);
        assert_eq!(answer.answer(reference).unwrap().targets(), &[target]);
    }

    #[test]
    fn public_seeded_construction_matches_identity_point_and_cancels_atomically() {
        let fixture = seeded_fixture(PrecedenceTier::LexicalBinding);
        let token = CancellationToken::new();
        let seed = reference_seed(&fixture.source, ResolutionQuery::new(fixture.reference));
        let identity = SeededPartialPath::new(
            path_id("public-identity"),
            identity_path(seed.node()),
            &token,
        )
        .unwrap();
        let request =
            SeededReferenceRequest::new(seed.clone(), [identity.clone()], &token).unwrap();
        let engine = BatchResolutionEngine::new(&fixture.source);
        assert_eq!(
            engine.resolve_seeded_reference(&request, &token).unwrap(),
            engine.resolve_reference(seed.query(), &token).unwrap()
        );
        token.cancel();
        assert!(
            SeededPartialPath::new(
                path_id("cancelled-identity"),
                identity_path(seed.node()),
                &token
            )
            .is_none()
        );
        assert!(SeededReferenceRequest::new(seed, [identity], &token).is_none());
    }

    #[test]
    fn bounded_preload_page_callback_stops_with_live_caller_token() {
        use brokk_bifrost_core::analyzer::usages::receiver_analysis::{
            ReceiverAnalysisBudget, ReceiverBudgetLimit,
        };
        use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;
        let reference = semantic("bounded-page-reference");
        let target = semantic("bounded-page-target");
        let start = node("bounded-page-start");
        let end = node("bounded-page-end");
        let source = PreloadedFragmentSource::from_fragments([PreloadedFragment::new(
            fragment("bounded-page-owner"),
            [
                (start, BindingNodeKind::Reference(reference)),
                (end, BindingNodeKind::Definition(target)),
            ],
            (0..8).map(|ordinal| {
                (
                    path_id(&format!("bounded-page-{ordinal}")),
                    path(start, end, ResolutionCompletion::Complete),
                )
            }),
        )]);
        let token = CancellationToken::new();
        let session = ResolutionSession::bounded(
            ReceiverAnalysisBudget {
                max_scope_nodes: 3,
                ..ReceiverAnalysisBudget::default()
            },
            Some(&token),
        );
        let mut page_sizes = Vec::new();
        let outcome = source
            .visit_forward_candidate_match_pages_limited(
                &[BatchCandidateRequest::new(0, endpoint(start))],
                session.scope_lookahead_limit(),
                Some(&session),
                &token,
                &mut |page| {
                    page_sizes.push(page.len());
                    Ok(!page.iter().any(|_| !session.scope_step()))
                },
            )
            .unwrap();
        assert_eq!(page_sizes, vec![2]);
        assert!(!token.is_cancelled());
        assert!(
            outcome
                .unconditional_completion()
                .contains_reason(ResolutionIncompleteReason::Cancelled)
        );
        assert!(matches!(session.finish(()), BoundedResolution::Exceeded {
            limit: ReceiverBudgetLimit::ScopeNodes, work
        } if work.scope_nodes == 3));
        assert_eq!(session.scope_lookahead_limit(), 1);

        // Every incomplete budget must remain explicit on the public point path.
        for limit in 0..32 {
            let session = ResolutionSession::bounded(
                ReceiverAnalysisBudget {
                    max_scope_nodes: limit,
                    ..ReceiverAnalysisBudget::default()
                },
                Some(&token),
            );
            let answer = BatchResolutionEngine::with_session(&source, &session)
                .resolve_reference(ResolutionQuery::new(reference), &token)
                .unwrap();
            match session.finish(answer) {
                BoundedResolution::Complete { value, .. } => assert_eq!(value.targets(), &[target]),
                BoundedResolution::Exceeded {
                    limit: ReceiverBudgetLimit::ScopeNodes,
                    ..
                } => {}
                outcome => panic!("live bounded point must complete or exceed scope: {outcome:?}"),
            }
            assert!(!token.is_cancelled());
        }
    }

    #[test]
    fn public_bounded_point_preserves_exceeded_outcome_and_caller_token() {
        use brokk_bifrost_core::analyzer::usages::receiver_analysis::{
            ReceiverAnalysisBudget, ReceiverBudgetLimit,
        };
        use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;
        let fixture = shared_fixture(false);
        let caller = CancellationToken::new();
        let session = ResolutionSession::bounded(
            ReceiverAnalysisBudget {
                max_scope_nodes: 0,
                ..ReceiverAnalysisBudget::default()
            },
            Some(&caller),
        );
        let answer = BatchResolutionEngine::with_session(&fixture.source, &session)
            .resolve_reference(
                ResolutionQuery::new(fixture.first_reference),
                session.cancellation().unwrap(),
            )
            .unwrap();
        assert!(answer.targets().is_empty());
        assert!(matches!(
            session.finish(answer),
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                ..
            }
        ));
        assert!(!caller.is_cancelled());
    }

    #[test]
    fn public_session_complete_summary_exhaustion_and_first_terminal_are_preserved() {
        use brokk_bifrost_core::analyzer::usages::receiver_analysis::{
            ReceiverAnalysisBudget, ReceiverAnalysisWork, ReceiverBudgetLimit,
        };
        use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;
        let fixture = shared_fixture(false);
        let query = ResolutionQuery::new(fixture.first_reference);
        let caller = CancellationToken::new();
        let complete_session =
            ResolutionSession::bounded(ReceiverAnalysisBudget::default(), Some(&caller));
        let answer = BatchResolutionEngine::with_session(&fixture.source, &complete_session)
            .resolve_reference(query, complete_session.cancellation().unwrap())
            .unwrap();
        let complete_work = match complete_session.finish(answer) {
            BoundedResolution::Complete { value, work } => {
                assert_eq!(value.targets(), &[fixture.target]);
                assert_eq!(value.completion(), &ResolutionCompletion::Complete);
                assert!(work.scope_nodes > 0 && work.summary_expansions > 0);
                work
            }
            outcome => panic!("sufficient budget must complete: {outcome:?}"),
        };
        let repeat = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), Some(&caller));
        let answer = BatchResolutionEngine::with_session(&fixture.source, &repeat)
            .resolve_reference(query, repeat.cancellation().unwrap())
            .unwrap();
        assert_eq!(repeat.finish(answer).work(), complete_work);

        let summary = ResolutionSession::bounded(
            ReceiverAnalysisBudget {
                max_summary_expansions: 0,
                ..ReceiverAnalysisBudget::default()
            },
            Some(&caller),
        );
        let answer = BatchResolutionEngine::with_session(&fixture.source, &summary)
            .resolve_reference(query, summary.cancellation().unwrap())
            .unwrap();
        let stopped_work = match summary.finish(answer) {
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::SummaryExpansions,
                work,
            } => {
                assert_eq!(work.summary_expansions, 0);
                assert!(work.scope_nodes > 0);
                work
            }
            outcome => panic!("summary limit must be explicit: {outcome:?}"),
        };
        caller.cancel();
        assert!(
            matches!(summary.finish(()), BoundedResolution::Exceeded { limit: ReceiverBudgetLimit::SummaryExpansions, work } if work == stopped_work)
        );
        assert!(!summary.scope_step());
        assert_eq!(summary.finish(()).work(), stopped_work);

        let cancelled = ResolutionSession::bounded(
            ReceiverAnalysisBudget {
                max_scope_nodes: 0,
                ..ReceiverAnalysisBudget::default()
            },
            Some(&caller),
        );
        let answer = BatchResolutionEngine::with_session(&fixture.source, &cancelled)
            .resolve_reference(query, cancelled.cancellation().unwrap())
            .unwrap();
        assert!(
            matches!(cancelled.finish(answer), BoundedResolution::Cancelled { work } if work == ReceiverAnalysisWork::default())
        );
        assert!(!cancelled.scope_step());
        assert!(
            matches!(cancelled.finish(()), BoundedResolution::Cancelled { work } if work == ReceiverAnalysisWork::default())
        );
    }
}
