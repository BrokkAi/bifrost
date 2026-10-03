//! Bounded, file-major stitching over immutable fragment rows.
//!
//! This module is the batch seam for the preload checkpoint. Candidate
//! matching and path hydration are intentionally separate: a source first
//! returns globally keyed rows, then the engine hydrates each distinct path at
//! most once into an operation-local arena. The arena dies with the batch; it
//! is neither a workspace snapshot nor a cache.

use std::collections::{BTreeMap, BTreeSet};

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::resolution_facts::{
    ResolutionCallableReceiverOrigin, ResolutionNamespace, ResolutionSiteId, ResolutionSiteKind,
};
use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

use crate::CancellationToken;
use crate::analyzer::store::{Result as StoreResult, StoreError};
use crate::hash::{HashMap, HashSet, map_with_capacity};

use super::completion_reasons::{CompletionReasonUnion, CompletionReasons};
use super::engine::{
    CANCELLATION_QUANTUM, CompletedBinding, CompletedPath, IncompleteTerminalPath,
    ReferenceSearchAnswer, ResolutionQuery, apply_type_transfer_rules, cancelled_completion,
    classify_completed_binding, endpoint_is_balanced, identity_path,
    select_paths_with_cancellation_evidence,
};
use super::local_identity::{ResolutionSemanticIdentity, SelectedResolutionMountOrdinal};
use super::model::{
    BindingFragmentId, BindingNodeId, DerivationKey, EndpointSignature, PartialPath, PartialPathId,
    ResolutionAnswer, ResolutionCompletion, ResolutionIncompleteReason, SemanticId, StackPattern,
    TypeTransferRule, TypedFrontierState, clone_completion_with_poll, combine_completion_with_poll,
    completion_values_equal_with_poll,
};
use super::saturation::{CycleCompletenessCertifier, SaturationBranch, SaturationDecision};
use super::selected_context::SelectedContextOverlay;

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
    go_spelling_namespace: Option<ResolutionNamespace>,
    go_package_qualifier: bool,
    callable_receiver_origin: Option<ResolutionCallableReceiverOrigin>,
}

impl FactReferenceSiteMetadata {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
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
            go_spelling_namespace: None,
            go_package_qualifier: false,
            callable_receiver_origin,
        }
    }

    /// The requested namespace for a source-owned Go spelling-scope lookup.
    pub const fn go_spelling_namespace(self) -> Option<ResolutionNamespace> {
        self.go_spelling_namespace
    }

    pub fn with_go_spelling_namespace(mut self, namespace: Option<ResolutionNamespace>) -> Self {
        if let Some(namespace) = namespace {
            assert!(
                self.unqualified,
                "Go spelling admission requires a lexical reference"
            );
            assert!(matches!(
                namespace,
                ResolutionNamespace::Type
                    | ResolutionNamespace::Value
                    | ResolutionNamespace::Callable
                    | ResolutionNamespace::TypeOrValue
            ));
            assert_eq!(
                namespace, self.namespace,
                "Go spelling request must retain its source namespace"
            );
        }
        assert!(!self.go_package_qualifier || namespace == Some(ResolutionNamespace::TypeOrValue));
        self.go_spelling_namespace = namespace;
        self
    }

    /// True only for a positioned prefix linked by a structured Go root reference.
    pub const fn go_package_qualifier(self) -> bool {
        self.go_package_qualifier
    }

    pub fn with_go_package_qualifier(mut self, qualifier: bool) -> Self {
        assert!(!qualifier || self.go_spelling_namespace == Some(ResolutionNamespace::TypeOrValue));
        self.go_package_qualifier = qualifier;
        self
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

impl BatchCandidateRequest {
    /// Whether one stored path endpoint can still unify with this request's.
    ///
    /// The index predicate in front of the full unification its callers run
    /// after hydration: it rejects only what cannot unify, and it decides the
    /// whole shared fixed prefix, not only its first cell. A row-backed
    /// candidate source can key a seek on the first cell alone
    /// (`resolution_paths_forward`), so it applies this to what the seek
    /// offers, exactly as the in-heap index does. Living here rather than in
    /// `engine.rs` is what lets one predicate serve both sources.
    pub(crate) fn admits_candidate(&self, offered: &EndpointSignature) -> bool {
        super::engine::endpoint_admits_candidate(self.endpoint(), offered)
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
    pub(crate) const fn new(
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
/// The key is a stable semantic derivation key supplied by the caller. It is
/// never looked up in, hydrated from, or persisted to the fragment source,
/// which is why it is a [`DerivationKey`] and not one of the five identities:
/// it names no mount, no row and no catalog entry. Distinct alternatives need
/// distinct keys; reusing one is accepted only when it names the same
/// canonical path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeededPartialPath {
    key: DerivationKey,
    path: PartialPath,
}

impl SeededPartialPath {
    pub(crate) fn new_with_poll<P>(
        key: DerivationKey,
        path: PartialPath,
        cancelled: &mut P,
    ) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        Some(Self {
            key,
            path: path.canonicalized_observations_with_poll(cancelled)?,
        })
    }

    pub const fn key(&self) -> DerivationKey {
        self.key
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
    pub(crate) fn new_with_poll<P>(
        seed: ReferenceSeed,
        alternatives: impl IntoIterator<Item = SeededPartialPath>,
        cancelled: &mut P,
    ) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        let mut canonical = BTreeMap::<DerivationKey, SeededPartialPath>::new();
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
                alternative.key(),
                alternative.path().start().node(),
                seed.node(),
                alternative.path()
            );
            assert!(
                endpoint_is_balanced(alternative.path().start()),
                "seeded path {} must start with balanced stacks: {:?}",
                alternative.key(),
                alternative.path().start()
            );
            alternative.path = alternative
                .path
                .with_seed_completion_with_poll(seed.completion(), cancelled)?;
            if let Some(existing) = canonical.get(&alternative.key()) {
                let equal = existing
                    .path()
                    .equals_with_poll(alternative.path(), cancelled)?;
                assert!(
                    equal,
                    "seeded path identity {} names conflicting canonical paths: {:?} and {:?}",
                    alternative.key(),
                    existing,
                    alternative
                );
            } else {
                canonical.insert(alternative.key(), alternative);
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

    pub(super) fn equals_with_poll<P>(&self, other: &Self, cancelled: &mut P) -> Option<bool>
    where
        P: FnMut() -> bool,
    {
        if cancelled() {
            return None;
        }
        if self.seed.fragment != other.seed.fragment
            || self.seed.query != other.seed.query
            || self.seed.node != other.seed.node
            || self.seed.site_metadata != other.seed.site_metadata
            || self.alternatives.len() != other.alternatives.len()
            || !completion_values_equal_with_poll(
                self.seed.completion(),
                other.seed.completion(),
                cancelled,
            )?
        {
            return Some(false);
        }
        for (left, right) in self.alternatives.iter().zip(other.alternatives.iter()) {
            if cancelled() {
                return None;
            }
            if left.key != right.key || !left.path.equals_with_poll(&right.path, cancelled)? {
                return Some(false);
            }
        }
        Some(true)
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
    pub(crate) const fn new(reference: SemanticId, expected_node: BindingNodeId) -> Self {
        Self {
            reference,
            expected_node,
        }
    }

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
    pub(crate) fn new(seeds: impl IntoIterator<Item = ReferenceSeed>) -> Self {
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

    pub(super) fn single(seed: ReferenceSeed) -> Self {
        Self::new([seed])
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

    pub(super) fn into_seeds(self) -> Box<[ReferenceSeed]> {
        self.seeds
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

/// The parts of a read's identity that belong to the selection rather than to
/// the reference it names.
///
/// A selected source answers under a selection, and two reads of one reference
/// under two selections are two different questions. These are the three
/// values that say which selection answered: its stage request identity, its
/// committed stage-content epoch, and which mounts the request may bind into.
/// The first two are what `candidate_coverage_fingerprint` already combines;
/// `.agents/docs/stack-graph-reader-statement-lifetime-2026-09-21.md` records
/// why the third has to be here as well, because every membership read joins
/// `temp.selected_resolution_scope_mounts` and a forward Rust request narrows
/// that relation for its own length.
///
/// Two things are keyed by it: the seed-key profile's reads, and the
/// demanded-reference memo below. A source that cannot name its selection
/// returns `None` from
/// [`BatchResolutionFragmentSource::selection_authority`] and is memoized for
/// nothing, because no key it produced could ever be a miss.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SeedReadAuthority {
    /// `SelectedResolutionMountInventory`'s stage request identity.
    pub request: u64,
    /// Its committed stage-content epoch.
    pub content_epoch: u64,
    /// Which mounts the request may currently bind into.
    pub scope: [u8; 32],
}

/// One demanded reference's lexical answer, as a reuse would have to name it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(super) struct DemandedReferenceKey {
    reference: SemanticId,
    request: u64,
    content_epoch: u64,
    scope: [u8; 32],
}

impl DemandedReferenceKey {
    pub(super) const fn new(reference: SemanticId, authority: SeedReadAuthority) -> Self {
        Self {
            reference,
            request: authority.request,
            content_epoch: authority.content_epoch,
            scope: authority.scope,
        }
    }
}

/// Exhausted immutable forward-stitch artifacts shared by repeated
/// state-dependent seeded requests in one top-level fact operation.
///
/// This cache deliberately stops below answer selection. An endpoint match,
/// hydrated persisted path, and endpoint-node classification depend only on
/// the selected source snapshot and their exact request key; a stitched
/// answer also depends on the caller's transient alternatives and must be
/// recomputed. Cancelled/partial reads are never published here.
///
/// # Retention
///
/// One of these per top-level fact operation: one crate stage on the graph
/// route, one request on the point route. It is a field of
/// `FactResolutionOperation` and is dropped with it, so nothing here outlives
/// the operation that filled it, and nothing here is shared between requests.
/// Every map is bounded by what that one operation touched:
/// `demanded_reference_answers` by the distinct references that operation
/// demanded, the other three by the endpoints, paths and nodes it read. That
/// is the "full result of one query, dropped with it" shape the heap rules
/// allow, and it is narrower than a query: a `usage_graph` request builds one
/// operation per crate stage and drops each before the next.
#[derive(Debug, Default)]
pub(super) struct ForwardCandidateArtifactCache {
    endpoint_matches: HashMap<EndpointSignature, CachedForwardEndpointMatch>,
    hydrated_paths: HashMap<CandidatePathIdentity, PartialPath>,
    endpoint_classifications: HashMap<BindingNodeId, BatchEndpointClassification>,
    unconditional_completion: Option<ResolutionCompletion>,
    /// The exhausted lexical answer of one demanded reference under one
    /// selection authority. A second root task demanding the same reference
    /// takes this instead of starting a second arity-one forward batch for it,
    /// which is where the repeated seed reads, candidate reads, hydrations and
    /// typed reads of the graph route were going. Only complete, live answers
    /// are published here: see `retain_demanded_reference_answer`.
    demanded_reference_answers: HashMap<DemandedReferenceKey, super::fact_resolution::SharedAnswer>,
}

impl ForwardCandidateArtifactCache {
    pub(super) fn demanded_reference_answer(
        &self,
        key: &DemandedReferenceKey,
    ) -> Option<&super::fact_resolution::SharedAnswer> {
        self.demanded_reference_answers.get(key)
    }

    /// Publish one demanded reference's exhausted answer.
    ///
    /// The caller has already established that the answer is complete and that
    /// its evaluation is live; this only refuses to overwrite, because one key
    /// has one answer and a second one would mean the key is not the whole
    /// identity of the question.
    pub(super) fn retain_demanded_reference_answer(
        &mut self,
        key: DemandedReferenceKey,
        answer: super::fact_resolution::SharedAnswer,
    ) {
        if let Some(existing) = self.demanded_reference_answers.get(&key) {
            assert_eq!(
                existing, &answer,
                "one demanded reference key has one exhausted answer: {key:?}"
            );
            return;
        }
        self.demanded_reference_answers.insert(key, answer);
    }

    /// How many demanded-reference answers this operation retained, and an
    /// estimate of their structural payload bytes.
    ///
    /// Walks every entry, so the caller must only ask when an instrument is
    /// on. Charges each answer its key, inline footprint, targets, witnesses,
    /// witness steps and ordered lookup alternatives with endpoint stacks.
    /// Excludes allocator overhead and shared completion reason lists (the
    /// seed-key profile counts those separately for seeds).
    pub(super) fn demanded_reference_memo_size(&self) -> (usize, usize) {
        let mut bytes = 0_usize;
        for (key, answer) in &self.demanded_reference_answers {
            bytes += size_of_val(key) + answer.structural_bytes();
        }
        (self.demanded_reference_answers.len(), bytes)
    }
}

#[cfg(test)]
impl ForwardCandidateArtifactCache {
    pub(super) fn artifact_counts(&self) -> (usize, usize, usize) {
        (
            self.endpoint_matches.len(),
            self.hydrated_paths.len(),
            self.endpoint_classifications.len(),
        )
    }

    pub(super) fn demanded_reference_entries(&self) -> usize {
        self.demanded_reference_answers.len()
    }
}

/// Report one operation's demanded-reference memo before it is dropped.
///
/// The operation itself has no other end-of-life hook, and the whole point of
/// the measurement is the size the memo reached, which only the drop knows.
/// With the instrument off this is one `OnceLock` load.
impl Drop for ForwardCandidateArtifactCache {
    fn drop(&mut self) {
        if !super::seed_key_profile::enabled() {
            return;
        }
        let (entries, bytes) = self.demanded_reference_memo_size();
        super::seed_key_profile::record_demanded_reference_memo(entries, bytes);
    }
}

#[derive(Debug)]
struct CachedForwardEndpointMatch {
    candidates: Box<[CandidatePathIdentity]>,
    branch_completion: ResolutionCompletion,
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
                if reasons.is_shared() {
                    let mut poll = || {
                        observe();
                        false
                    };
                    let contains_cancelled = reasons
                        .contains_with_poll(&ResolutionIncompleteReason::Cancelled, &mut poll)
                        .expect("observational completion membership never aborts");
                    assert!(
                        !contains_cancelled,
                        "candidate cancellation is unconditional operation evidence"
                    );
                } else {
                    for &reason in reasons.iter() {
                        observe();
                        assert_ne!(
                            reason,
                            ResolutionIncompleteReason::Cancelled,
                            "candidate cancellation is unconditional operation evidence"
                        );
                    }
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
    composite_partitions: Option<Box<CompositeReverseCandidateGapExclusionPlans>>,
}

#[derive(Debug)]
struct CompositeReverseCandidateGapExclusionPlans {
    transient_fragments: Box<[BindingFragmentId]>,
    persisted: ReverseCandidateGapExclusionPlan,
    transient: ReverseCandidateGapExclusionPlan,
}

impl ReverseCandidateGapExclusionPlan {
    pub fn new(identities: impl IntoIterator<Item = ReverseCandidateGapIdentity>) -> Self {
        Self {
            // Collection owns no semantic interpretation. Canonicalization,
            // deduplication, and validation happen under the operation token
            // in `prepare_for` before any prepared state is published.
            identities: identities.into_iter().collect(),
            prepared: None,
            composite_partitions: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.identities.is_empty()
    }

    pub(crate) fn identities(&self) -> &[ReverseCandidateGapIdentity] {
        &self.identities
    }

    pub(crate) fn needs_preparation_for_authority(&self, authority: [u8; 32]) -> StoreResult<bool> {
        if self.composite_partitions.is_some() {
            return Err(StoreError::new(
                "a composite reverse-gap exclusion plan cannot be rebound to one raw authority",
            ));
        }
        let Some(prepared) = &self.prepared else {
            return Ok(true);
        };
        if prepared.raw_fingerprint != ReverseCandidateGapCoverageFingerprint(authority) {
            return Err(StoreError::new(
                "reverse candidate gap exclusion plan was prepared for different raw coverage",
            ));
        }
        Ok(false)
    }

    fn from_canonical_identities(identities: Box<[ReverseCandidateGapIdentity]>) -> Self {
        Self {
            identities,
            prepared: None,
            composite_partitions: None,
        }
    }

    pub(crate) fn partition_for_transient_fragments(
        &mut self,
        transient_fragments: &HashSet<BindingFragmentId>,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<(&mut Self, &mut Self)>> {
        if self.prepared.is_some() {
            return Err(StoreError::new(
                "a raw reverse-gap exclusion plan cannot be rebound to composite authorities",
            ));
        }
        let mut canonical = BTreeSet::new();
        for &identity in self.identities.iter() {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            canonical.insert(identity);
        }
        let (persisted, transient): (Vec<_>, Vec<_>) = canonical
            .into_iter()
            .partition(|identity| !transient_fragments.contains(&identity.fragment()));
        let mut canonical_transient_fragments = Vec::with_capacity(transient_fragments.len());
        for &fragment in transient_fragments {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            canonical_transient_fragments.push(fragment);
        }
        canonical_transient_fragments.sort_unstable();
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        if let Some(partitions) = self.composite_partitions.as_ref() {
            if partitions.transient_fragments.as_ref() != canonical_transient_fragments.as_slice()
                || partitions.persisted.identities.as_ref() != persisted.as_slice()
                || partitions.transient.identities.as_ref() != transient.as_slice()
            {
                return Err(StoreError::new(
                    "reverse-gap exclusion plan was partitioned for different selected authorities",
                ));
            }
        } else {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            self.composite_partitions =
                Some(Box::new(CompositeReverseCandidateGapExclusionPlans {
                    transient_fragments: canonical_transient_fragments.into_boxed_slice(),
                    persisted: Self::from_canonical_identities(persisted.into_boxed_slice()),
                    transient: Self::from_canonical_identities(transient.into_boxed_slice()),
                }));
        }
        let partitions = self
            .composite_partitions
            .as_deref_mut()
            .expect("composite reverse-gap partitions were installed above");
        Ok(Some((&mut partitions.persisted, &mut partitions.transient)))
    }

    pub(crate) fn is_prepared_or_empty(&self) -> bool {
        self.identities.is_empty() || self.prepared.is_some()
    }

    fn prepare_for(
        &mut self,
        coverage: ReverseCandidateGapCoverageView<'_>,
        cancellation: &CancellationToken,
    ) -> StoreResult<bool> {
        if self.composite_partitions.is_some() {
            return Err(StoreError::new(
                "a composite reverse-gap exclusion plan cannot be prepared by one raw authority",
            ));
        }
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
            let contribution = coverage.contribution(identity).ok_or_else(|| {
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
        coverage: ReverseCandidateGapCoverageView<'_>,
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

    pub(crate) const fn identity(self) -> ReverseCandidateGapIdentity {
        self.identity
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

impl ReverseCandidateReasonBucket {
    fn estimated_retained_bytes(&self) -> usize {
        let Self {
            counts,
            completion: _,
        } = self;
        brokk_bifrost_core::hash::btree_map_slot_bytes(counts)
    }
}

impl ReverseCandidateEndpointReasonBuckets {
    fn estimated_retained_bytes(&self) -> usize {
        let Self {
            unkeyed,
            all_keyed,
            by_lookup,
        } = self;
        by_lookup
            .values()
            .map(ReverseCandidateReasonBucket::estimated_retained_bytes)
            .fold(
                unkeyed
                    .estimated_retained_bytes()
                    .saturating_add(all_keyed.estimated_retained_bytes())
                    .saturating_add(brokk_bifrost_core::hash::map_slot_bytes(by_lookup)),
                usize::saturating_add,
            )
    }
}

impl ReverseCandidateGapCoverage {
    /// Conservative retained-byte estimate for cache admission. The fields are
    /// destructured exhaustively so a new one cannot silently leave the weight
    /// behind.
    pub(crate) fn estimated_retained_bytes(&self) -> usize {
        let Self {
            fingerprint: _,
            by_identity,
            inventory,
            endpoints,
        } = self;
        endpoints
            .values()
            .map(ReverseCandidateEndpointReasonBuckets::estimated_retained_bytes)
            .fold(
                brokk_bifrost_core::hash::map_slot_bytes(by_identity)
                    .saturating_add(inventory.estimated_retained_bytes())
                    .saturating_add(brokk_bifrost_core::hash::map_slot_bytes(endpoints)),
                usize::saturating_add,
            )
    }

    pub(crate) fn empty() -> Self {
        ReverseCandidateGapCoverageBuilder::default()
            .finish(&CancellationToken::new())
            .expect("an empty reverse candidate coverage builder is valid")
            .0
    }

    fn view(&self) -> ReverseCandidateGapCoverageView<'_> {
        ReverseCandidateGapCoverageView {
            fingerprint: self.fingerprint,
            by_identity: &self.by_identity,
            inventory_by_identity: &self.by_identity,
            inventory: &self.inventory,
            endpoints: &self.endpoints,
        }
    }

    pub(crate) fn contains_identity(&self, identity: ReverseCandidateGapIdentity) -> bool {
        self.by_identity.contains_key(&identity)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.by_identity.len()
    }

    /// Borrow a complete direction-wide inventory and request-local endpoint
    /// buckets from the same selected authority. Neither map is cloned.
    pub(crate) fn with_inventory<'coverage>(
        &'coverage self,
        inventory: &'coverage Self,
        cancellation: &CancellationToken,
    ) -> StoreResult<(ReverseCandidateGapCoverageView<'coverage>, bool)> {
        assert_eq!(
            self.fingerprint, inventory.fingerprint,
            "candidate inventory and endpoint buckets must share one selected authority"
        );
        assert!(
            inventory.endpoints.is_empty() && self.inventory.counts.is_empty(),
            "candidate coverage parts must partition inventory and endpoint rows"
        );
        let mut work = 0;
        let mut cancelled = false;
        for identity in self.by_identity.keys() {
            cancelled |= poll_reverse_candidate_gap_work(cancellation, &mut work);
            if inventory.by_identity.contains_key(identity) {
                return Err(StoreError::new(format!(
                    "duplicate selected reverse candidate gap ({}, {})",
                    identity.fragment(),
                    identity.gap_id()
                )));
            }
        }
        Ok((
            ReverseCandidateGapCoverageView {
                fingerprint: self.fingerprint,
                by_identity: &self.by_identity,
                inventory_by_identity: &inventory.by_identity,
                inventory: &inventory.inventory,
                endpoints: &self.endpoints,
            },
            cancelled | cancellation.is_cancelled(),
        ))
    }

    pub(crate) fn inventory_completion(&self) -> &ResolutionCompletion {
        self.view().inventory_completion()
    }

    pub(crate) fn branch_completion_for_with_poll(
        &self,
        endpoint: &EndpointSignature,
        cancellation: &CancellationToken,
        work: &mut usize,
    ) -> (ResolutionCompletion, bool) {
        self.view()
            .branch_completion_for_with_poll(endpoint, cancellation, work)
    }

    pub(crate) fn filtered_inventory_completion<'coverage>(
        &'coverage self,
        prepared: &'coverage ReverseCandidateGapExclusionPlan,
    ) -> StoreResult<&'coverage ResolutionCompletion> {
        self.view().filtered_inventory_completion(prepared)
    }

    pub(crate) fn filtered_branch_completion_for_with_poll(
        &self,
        endpoint: &EndpointSignature,
        prepared: &ReverseCandidateGapExclusionPlan,
        cancellation: &CancellationToken,
        work: &mut usize,
    ) -> StoreResult<(ResolutionCompletion, bool)> {
        self.view()
            .filtered_branch_completion_for_with_poll(endpoint, prepared, cancellation, work)
    }

    pub(crate) fn prepare_exclusions(
        &self,
        plan: &mut ReverseCandidateGapExclusionPlan,
        cancellation: &CancellationToken,
    ) -> StoreResult<bool> {
        self.view().prepare_exclusions(plan, cancellation)
    }
}

/// A borrowed raw coverage view. Endpoint slices carry their selected
/// authority, never a fingerprint derived from the local slice alone.
#[derive(Clone, Copy)]
pub(crate) struct ReverseCandidateGapCoverageView<'coverage> {
    fingerprint: ReverseCandidateGapCoverageFingerprint,
    by_identity: &'coverage HashMap<ReverseCandidateGapIdentity, ReverseCandidateGapContribution>,
    inventory_by_identity:
        &'coverage HashMap<ReverseCandidateGapIdentity, ReverseCandidateGapContribution>,
    inventory: &'coverage ReverseCandidateReasonBucket,
    endpoints: &'coverage HashMap<BindingNodeId, ReverseCandidateEndpointReasonBuckets>,
}

impl<'coverage> ReverseCandidateGapCoverageView<'coverage> {
    fn contribution(
        self,
        identity: ReverseCandidateGapIdentity,
    ) -> Option<&'coverage ReverseCandidateGapContribution> {
        self.by_identity
            .get(&identity)
            .or_else(|| self.inventory_by_identity.get(&identity))
    }

    pub(crate) fn inventory_completion(self) -> &'coverage ResolutionCompletion {
        &self.inventory.completion
    }

    pub(crate) fn branch_completion_for_with_poll(
        self,
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

    pub(crate) fn filtered_inventory_completion(
        self,
        prepared: &'coverage ReverseCandidateGapExclusionPlan,
    ) -> StoreResult<&'coverage ResolutionCompletion> {
        Ok(prepared
            .prepared_for(self)?
            .inventory
            .as_ref()
            .unwrap_or(&self.inventory.completion))
    }

    pub(crate) fn filtered_branch_completion_for_with_poll(
        self,
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
        self,
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

struct ReverseCandidateGapCoverageParts {
    by_identity: HashMap<ReverseCandidateGapIdentity, ReverseCandidateGapContribution>,
    inventory: ReverseCandidateReasonBucket,
    endpoints: HashMap<BindingNodeId, ReverseCandidateEndpointReasonBuckets>,
}

impl ReverseCandidateGapCoverageParts {
    fn with_fingerprint(self, fingerprint: [u8; 32]) -> ReverseCandidateGapCoverage {
        ReverseCandidateGapCoverage {
            fingerprint: ReverseCandidateGapCoverageFingerprint(fingerprint),
            by_identity: self.by_identity,
            inventory: self.inventory,
            endpoints: self.endpoints,
        }
    }
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
        let (parts, cancelled) = self.aggregate(cancellation, |row| {
            hash_reverse_candidate_gap_row(&mut fingerprint, row);
        });
        Ok((parts.with_fingerprint(fingerprint.finish()), cancelled))
    }

    pub(crate) fn finish_with_authority(
        self,
        authority: [u8; 32],
        cancellation: &CancellationToken,
    ) -> StoreResult<(ReverseCandidateGapCoverage, bool)> {
        let (parts, cancelled) = self.aggregate(cancellation, |_| {});
        Ok((parts.with_fingerprint(authority), cancelled))
    }

    /// Aggregate every returned row even after cancellation so evidence is
    /// retained. The observer is only for callers deriving a row fingerprint;
    /// selected authorities already identify their immutable raw inventory.
    fn aggregate(
        self,
        cancellation: &CancellationToken,
        mut observe_row: impl FnMut(ReverseCandidateGapRow),
    ) -> (ReverseCandidateGapCoverageParts, bool) {
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
            observe_row(row);
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
        (
            ReverseCandidateGapCoverageParts {
                by_identity,
                inventory,
                endpoints: finished_endpoints,
            },
            cancellation_observed | cancellation.is_cancelled(),
        )
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

#[cfg(test)]
thread_local! {
    static REVERSE_CANDIDATE_GAP_HASH_ROWS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn hash_reverse_candidate_gap_row(fingerprint: &mut CanonicalHasher, row: ReverseCandidateGapRow) {
    #[cfg(test)]
    REVERSE_CANDIDATE_GAP_HASH_ROWS.with(|rows| rows.set(rows.get() + 1));
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
        ResolutionIncompleteReason::CyclicPrefixDependency(_) => {
            panic!("a cyclic prefix dependency publishes no candidate coverage")
        }
        ResolutionIncompleteReason::ReceiverBudgetExhausted(_) => {
            panic!("a receiver budget stop publishes no candidate coverage")
        }
        ResolutionIncompleteReason::TimeBudgetExceeded(_) => {
            panic!("a time budget stop publishes no candidate coverage")
        }
        ResolutionIncompleteReason::UnmountedFile { .. } => {
            panic!("an unmounted-file route publishes no candidate coverage")
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
    go_definition_namespaces: Option<super::model::GoDefinitionNamespaces>,
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
            go_definition_namespaces: None,
        }
    }

    pub const fn go_definition_namespaces(self) -> Option<super::model::GoDefinitionNamespaces> {
        self.go_definition_namespaces
    }

    pub const fn with_go_definition_namespaces(
        mut self,
        namespaces: Option<super::model::GoDefinitionNamespaces>,
    ) -> Self {
        assert!(
            namespaces.is_none() || self.definition.is_some(),
            "Go lexical namespace authority requires a definition endpoint"
        );
        self.go_definition_namespaces = namespaces;
        self
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
    /// The selection this source is currently answering under.
    ///
    /// An answer read from this source is a function of the question and of
    /// this value, so a caller that wants to reuse an answer inside one
    /// operation keys it by both. `None` is the honest answer for a source
    /// that has no selection to name: it memoizes nothing rather than
    /// inventing an authority under which two different selections would
    /// collide.
    ///
    /// Deliberately without a default. A wrapper that forgot to forward it
    /// would answer `None` for a source that does have a selection, which does
    /// not fail, does not warn, and silently turns the memo off for every
    /// caller behind that wrapper. Requiring it makes the compiler ask each of
    /// this trait's implementations the question once.
    fn selection_authority(&self) -> Option<SeedReadAuthority>;

    /// Admission applies to reverse result sites, never to forward dependency
    /// resolution or intermediate import paths.
    fn admits_reverse_reference(&self, _reference: SemanticId) -> bool {
        true
    }

    /// Restrict source-owned inventory evidence to the reverse search domain.
    /// Evidence on an actually traversed path remains unchanged.
    fn scope_reverse_inventory_completion(
        &self,
        completion: &ResolutionCompletion,
    ) -> ResolutionCompletion {
        completion.clone()
    }

    /// Look up the unique selected seed for one reference semantic.
    ///
    /// Cancellation may stop the lookup without manufacturing an absent
    /// reference. The engine rechecks the token before interpreting `None`.
    fn reference_seed(
        &self,
        query: ResolutionQuery,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<ReferenceSeed>>;

    /// Read the exact parser-derived spelling for an unqualified Go reference.
    /// The engine uses this only after all selected source scopes have been
    /// exhausted without a declaration. Sources without that syntax authority
    /// leave the universe lookup unavailable.
    fn go_lookup_spelling(
        &self,
        _reference: SemanticId,
        _namespace: ResolutionNamespace,
        _cancellation: &CancellationToken,
    ) -> StoreResult<Option<String>> {
        Ok(None)
    }

    /// Resolve a shared-name digest to the identity used by this request.
    /// Missing store rows receive the request's ordinary ephemeral identity;
    /// no producer fact or persisted definition is created.
    fn intern_shared_name_digest(
        &self,
        _digest: [u8; 32],
        _cancellation: &CancellationToken,
    ) -> StoreResult<Option<SemanticId>> {
        Ok(None)
    }

    fn supports_go_universe(&self) -> bool {
        false
    }

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

    /// Enumerate only admitted source fragments, retaining unrestricted lookup
    /// authority for definitions and dependencies outside that source domain.
    fn visit_reference_seed_batches_in_fragments(
        &self,
        fragments: &HashSet<BindingFragmentId>,
        maximum_batch_size: usize,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&ReferenceSeedBatch) -> StoreResult<bool>,
    ) -> StoreResult<ResolutionCompletion> {
        let _ = (fragments, maximum_batch_size, cancellation, visitor);
        Err(StoreError::new(
            "source does not support scoped reference enumeration",
        ))
    }

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
    ///
    /// `mounts` names the only mounts whose halves the caller can use, and
    /// `None` says every selected mount's halves are usable. A persisted
    /// source probes exactly the named ones, so the read costs what the
    /// request asks for rather than what the selection holds. A source that
    /// keeps its whole fragment set in memory has nothing to seek and answers
    /// from all of it; the caller drops the rest.
    ///
    /// `None` is not a shorthand for the whole selection spelled out. A caller
    /// that means "every mount" must say so, because listing them is a vector
    /// whose length is the workspace, built once per read.
    fn visit_forward_root_candidate_match_pages(
        &self,
        requests: &[BatchCandidateRequest],
        _mounts: Option<&[SelectedResolutionMountOrdinal]>,
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
    /// the root stitcher. `mounts` bounds the read exactly as it does for
    /// [`Self::visit_forward_root_candidate_match_pages`].
    fn visit_reverse_root_candidate_match_pages(
        &self,
        requests: &[BatchCandidateRequest],
        _mounts: Option<&[SelectedResolutionMountOrdinal]>,
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

/// A borrowed view of one immutable SQL context and its explicit base source.
/// No candidate bodies or candidate index survive an individual read.
pub(crate) struct SelectedContextPathFragmentSource<'a> {
    base: &'a dyn BatchResolutionFragmentSource,
    paths: &'a dyn super::SelectedContextPathSource,
    token: super::SelectedContextPathToken,
    session: Option<&'a ResolutionSession>,
}

impl<'a> SelectedContextPathFragmentSource<'a> {
    pub(crate) fn new(
        base: &'a dyn BatchResolutionFragmentSource,
        paths: &'a dyn super::SelectedContextPathSource,
        token: super::SelectedContextPathToken,
        session: Option<&'a ResolutionSession>,
    ) -> Self {
        Self {
            base,
            paths,
            token,
            session,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn visit_candidates(
        &self,
        requests: &[BatchCandidateRequest],
        maximum_page_rows: usize,
        session: Option<&ResolutionSession>,
        cancellation: &CancellationToken,
        visit_base: impl FnOnce(
            &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
        ) -> StoreResult<BatchCandidateCompletionOutcome>,
        visit_additions: impl FnOnce(
            BatchCandidateCompletionOutcome,
            &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
        ) -> StoreResult<BatchCandidateCompletionOutcome>,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        assert_canonical_candidate_requests(requests);
        assert!((1..=MAX_SOURCE_ROWS_PER_BATCH).contains(&maximum_page_rows));
        let session = session.or(self.session);
        let mut publisher = BoundedCandidatePagePublisher::new(visitor, maximum_page_rows);
        let mut seen = HashSet::default();
        let mut work = 0;
        let mut cancelled = cancellation.is_cancelled();
        let mut completion = visit_base(&mut |page| {
            if publisher.stopped() {
                return Err(StoreError::new(
                    "base source emitted after context visitor stopped",
                ));
            }
            assert!(!page.is_empty() && page.len() <= MAX_SOURCE_ROWS_PER_BATCH);
            let candidates = page
                .iter()
                .map(|row| row.candidate())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let Some(collisions) =
                self.paths
                    .hydrate_context_paths(self.token, &candidates, cancellation)?
            else {
                cancelled = true;
                return Ok(false);
            };
            if !collisions.is_empty() {
                return Err(StoreError::new(format!(
                    "selected context collides with base candidate paths: {collisions:?}"
                )));
            }
            for &row in page {
                if session.is_some_and(|session| !session.scope_step())
                    || poll_overlay_work(cancellation, &mut work)
                {
                    cancelled = true;
                    return Ok(false);
                }
                if row.request_ordinal() >= requests.len() || !seen.insert(row) {
                    return Err(StoreError::new(format!(
                        "invalid or repeated base candidate {row:?}"
                    )));
                }
                if !publisher.push(row, cancellation)? {
                    cancelled |= cancellation.is_cancelled();
                    return Ok(false);
                }
            }
            Ok(!publisher.stopped())
        })?;
        cancelled |= completion_contains_cancelled_with_poll(
            completion.unconditional_completion(),
            cancellation,
            &mut work,
        );
        if !publisher.stopped() && !cancelled {
            completion = visit_additions(completion, &mut |page| {
                // The SQL reader charges each offered addition once. Its one-row
                // internal pages feed this shared base/addition output buffer.
                for &row in page {
                    if row.request_ordinal() >= requests.len() || !seen.insert(row) {
                        return Err(StoreError::new(format!(
                            "invalid or repeated context candidate {row:?}"
                        )));
                    }
                    if !publisher.push(row, cancellation)? {
                        return Ok(false);
                    }
                }
                Ok(!publisher.stopped())
            })?;
            cancelled |= completion_contains_cancelled_with_poll(
                completion.unconditional_completion(),
                cancellation,
                &mut work,
            );
        }
        if !publisher.stopped() && !cancelled {
            publisher.finish(cancellation)?;
        }
        if cancelled || cancellation.is_cancelled() {
            Ok(include_overlay_candidate_cancellation(
                completion,
                cancellation,
                &mut work,
            ))
        } else {
            Ok(completion)
        }
    }
    fn materialize_forward_candidates(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
    ) -> StoreResult<BatchCandidateOutcome> {
        let mut staged = Vec::new();
        let mut seen = HashSet::default();
        let mut work = 0_usize;
        let mut cancellation_observed = false;
        let mut completion =
            self.visit_forward_candidate_match_pages(requests, cancellation, &mut |page| {
                for &matched in page {
                    if poll_overlay_work(cancellation, &mut work) {
                        cancellation_observed = true;
                        return Ok(false);
                    }
                    if !seen.insert(matched) {
                        return Err(StoreError::new(format!(
                            "forward candidate source repeated one natural identity: {matched:?}"
                        )));
                    }
                    staged.push(matched);
                }
                Ok(true)
            })?;
        cancellation_observed |= cancellation.is_cancelled();
        if cancellation_observed {
            staged.clear();
            completion =
                include_overlay_candidate_cancellation(completion, cancellation, &mut work);
        }
        materialize_overlay_candidate_outcome(
            requests.len(),
            staged,
            completion,
            cancellation,
            &mut work,
        )
    }

    fn materialize_reverse_candidates(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
    ) -> StoreResult<BatchCandidateOutcome> {
        let mut staged = Vec::new();
        let mut seen = HashSet::default();
        let mut work = 0_usize;
        let mut cancellation_observed = false;
        let mut completion =
            self.visit_reverse_candidate_match_pages(requests, cancellation, &mut |page| {
                for &matched in page {
                    if poll_overlay_work(cancellation, &mut work) {
                        cancellation_observed = true;
                        return Ok(false);
                    }
                    if !seen.insert(matched) {
                        return Err(StoreError::new(format!(
                            "reverse candidate source repeated one natural identity: {matched:?}"
                        )));
                    }
                    staged.push(matched);
                }
                Ok(true)
            })?;
        cancellation_observed |= cancellation.is_cancelled();
        if cancellation_observed {
            staged.clear();
            completion =
                include_overlay_candidate_cancellation(completion, cancellation, &mut work);
        }
        materialize_overlay_candidate_outcome(
            requests.len(),
            staged,
            completion,
            cancellation,
            &mut work,
        )
    }
}

impl BatchResolutionFragmentSource for SelectedContextPathFragmentSource<'_> {
    /// The overlay adds paths to what the base answers; it does not change
    /// which selection answers, so the base names the authority.
    fn selection_authority(&self) -> Option<SeedReadAuthority> {
        self.base.selection_authority()
    }

    fn admits_reverse_reference(&self, reference: SemanticId) -> bool {
        self.base.admits_reverse_reference(reference)
    }

    fn scope_reverse_inventory_completion(
        &self,
        completion: &ResolutionCompletion,
    ) -> ResolutionCompletion {
        self.base.scope_reverse_inventory_completion(completion)
    }

    fn reference_seed(
        &self,
        query: ResolutionQuery,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<ReferenceSeed>> {
        self.base.reference_seed(query, cancellation)
    }

    fn lookup_reference_seeds(
        &self,
        queries: &[ResolutionQuery],
        cancellation: &CancellationToken,
    ) -> StoreResult<ReferenceSeedReadOutcome> {
        self.base.lookup_reference_seeds(queries, cancellation)
    }

    fn lookup_definition_node(
        &self,
        definition: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<BindingNodeId>> {
        self.base.lookup_definition_node(definition, cancellation)
    }

    fn lookup_definition_nodes(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Vec<BatchDefinitionNode>> {
        self.base.lookup_definition_nodes(definitions, cancellation)
    }

    fn issue_reverse_reference_seeds(
        &self,
        requests: &[ReverseReferenceSeedRequest],
        cancellation: &CancellationToken,
    ) -> StoreResult<Vec<ReferenceSeed>> {
        self.base
            .issue_reverse_reference_seeds(requests, cancellation)
    }

    fn visit_reference_seed_batches(
        &self,
        maximum_batch_size: usize,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&ReferenceSeedBatch) -> StoreResult<bool>,
    ) -> StoreResult<ResolutionCompletion> {
        self.base
            .visit_reference_seed_batches(maximum_batch_size, cancellation, visitor)
    }

    fn visit_reference_seed_batches_in_fragments(
        &self,
        fragments: &HashSet<BindingFragmentId>,
        maximum_batch_size: usize,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&ReferenceSeedBatch) -> StoreResult<bool>,
    ) -> StoreResult<ResolutionCompletion> {
        self.base.visit_reference_seed_batches_in_fragments(
            fragments,
            maximum_batch_size,
            cancellation,
            visitor,
        )
    }

    fn visit_type_transfer_rules(
        &self,
        source_slot: SemanticId,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&TypeTransferRule) -> StoreResult<bool>,
    ) -> StoreResult<ResolutionCompletion> {
        self.base
            .visit_type_transfer_rules(source_slot, cancellation, visitor)
    }

    fn classify_endpoint_nodes(
        &self,
        nodes: &[BindingNodeId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Vec<BatchEndpointClassification>> {
        self.base.classify_endpoint_nodes(nodes, cancellation)
    }

    fn match_forward_candidates(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
    ) -> StoreResult<BatchCandidateOutcome> {
        self.materialize_forward_candidates(requests, cancellation)
    }
    fn visit_forward_candidate_match_pages(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        self.visit_candidates(
            requests,
            MAX_SOURCE_ROWS_PER_BATCH,
            self.session,
            cancellation,
            |emit| {
                self.base
                    .visit_forward_candidate_match_pages(requests, cancellation, emit)
            },
            |completion, emit| {
                self.paths.visit_context_forward_additions(
                    self.token,
                    requests,
                    completion,
                    1,
                    cancellation,
                    self.session,
                    emit,
                )
            },
            visitor,
        )
    }
    fn visit_forward_root_candidate_match_pages(
        &self,
        requests: &[BatchCandidateRequest],
        mounts: Option<&[SelectedResolutionMountOrdinal]>,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        self.visit_candidates(
            requests,
            MAX_SOURCE_ROWS_PER_BATCH,
            self.session,
            cancellation,
            |emit| {
                self.base.visit_forward_root_candidate_match_pages(
                    requests,
                    mounts,
                    cancellation,
                    emit,
                )
            },
            |completion, emit| {
                self.paths.visit_context_forward_additions(
                    self.token,
                    requests,
                    completion,
                    1,
                    cancellation,
                    self.session,
                    emit,
                )
            },
            visitor,
        )
    }

    fn match_reverse_candidates(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
    ) -> StoreResult<BatchCandidateOutcome> {
        self.materialize_reverse_candidates(requests, cancellation)
    }
    fn visit_reverse_candidate_match_pages(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        self.visit_candidates(
            requests,
            MAX_SOURCE_ROWS_PER_BATCH,
            self.session,
            cancellation,
            |emit| {
                self.base
                    .visit_reverse_candidate_match_pages(requests, cancellation, emit)
            },
            |completion, emit| {
                self.paths.visit_context_reverse_additions(
                    self.token,
                    requests,
                    completion,
                    1,
                    cancellation,
                    self.session,
                    emit,
                )
            },
            visitor,
        )
    }
    fn visit_reverse_root_candidate_match_pages(
        &self,
        requests: &[BatchCandidateRequest],
        mounts: Option<&[SelectedResolutionMountOrdinal]>,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        self.visit_candidates(
            requests,
            MAX_SOURCE_ROWS_PER_BATCH,
            self.session,
            cancellation,
            |emit| {
                self.base.visit_reverse_root_candidate_match_pages(
                    requests,
                    mounts,
                    cancellation,
                    emit,
                )
            },
            |completion, emit| {
                self.paths.visit_context_reverse_additions(
                    self.token,
                    requests,
                    completion,
                    1,
                    cancellation,
                    self.session,
                    emit,
                )
            },
            visitor,
        )
    }

    fn visit_forward_candidate_match_pages_limited(
        &self,
        requests: &[BatchCandidateRequest],
        maximum_page_rows: usize,
        session: Option<&ResolutionSession>,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        let session = session.or(self.session);
        self.visit_candidates(
            requests,
            maximum_page_rows,
            session,
            cancellation,
            |emit| {
                self.base.visit_forward_candidate_match_pages_limited(
                    requests,
                    maximum_page_rows,
                    session,
                    cancellation,
                    emit,
                )
            },
            |completion, emit| {
                self.paths.visit_context_forward_additions(
                    self.token,
                    requests,
                    completion,
                    1,
                    cancellation,
                    session,
                    emit,
                )
            },
            visitor,
        )
    }

    fn visit_reverse_candidate_match_pages_with_gap_exclusions_shared(
        &self,
        requests: &[BatchCandidateRequest],
        exclusions: &mut ReverseCandidateGapExclusionPlan,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        self.visit_candidates(
            requests,
            MAX_SOURCE_ROWS_PER_BATCH,
            self.session,
            cancellation,
            |emit| {
                self.base
                    .visit_reverse_candidate_match_pages_with_gap_exclusions_shared(
                        requests,
                        exclusions,
                        cancellation,
                        emit,
                    )
            },
            |completion, emit| {
                self.paths.visit_context_reverse_additions(
                    self.token,
                    requests,
                    completion,
                    1,
                    cancellation,
                    self.session,
                    emit,
                )
            },
            visitor,
        )
    }

    fn hydrate_candidate_paths(
        &self,
        candidates: &[CandidatePathIdentity],
        cancellation: &CancellationToken,
    ) -> StoreResult<Vec<(CandidatePathIdentity, PartialPath)>> {
        assert!(candidates.len() <= MAX_SOURCE_ROWS_PER_BATCH);
        let requested = candidates.iter().copied().collect::<HashSet<_>>();
        if requested.len() != candidates.len() {
            return Err(StoreError::new(format!(
                "context hydration repeated input identities: {candidates:?}"
            )));
        }
        let Some(context_rows) =
            self.paths
                .hydrate_context_paths(self.token, candidates, cancellation)?
        else {
            return Ok(Vec::new());
        };
        let mut rows = BTreeMap::new();
        for (candidate, path) in context_rows {
            if !requested.contains(&candidate) || rows.insert(candidate, path).is_some() {
                return Err(StoreError::new(format!(
                    "context hydration returned foreign or duplicate identity {candidate:?}"
                )));
            }
        }
        let remaining = candidates
            .iter()
            .copied()
            .filter(|candidate| !rows.contains_key(candidate))
            .collect::<Vec<_>>();
        if !remaining.is_empty() {
            for (candidate, path) in self
                .base
                .hydrate_candidate_paths(&remaining, cancellation)?
            {
                if !requested.contains(&candidate) || rows.insert(candidate, path).is_some() {
                    return Err(StoreError::new(format!(
                        "base hydration returned foreign or duplicate identity {candidate:?}"
                    )));
                }
            }
        }
        if !cancellation.is_cancelled() && rows.len() != candidates.len() {
            let missing = candidates
                .iter()
                .filter(|candidate| !rows.contains_key(candidate))
                .collect::<Vec<_>>();
            return Err(StoreError::new(format!(
                "context hydration omitted candidate identities: {missing:?}"
            )));
        }
        Ok(rows.into_iter().collect())
    }
}

/// Atomic result of adapting one selected-context delta to the batch source
/// contract.
///
/// Contextual reverse-inventory evidence remains separate from operational
/// cancellation. A point or broad operation must publish only the latter,
/// while a reverse operation combines the former exactly once at its top
/// level.
pub(super) enum SelectedContextOverlayFragmentSourceConstruction<'a> {
    Ready(Box<SelectedContextOverlayFragmentSource<'a>>),
    Cancelled {
        contextual_reverse_inventory_completion: ResolutionCompletion,
        cancellation_completion: ResolutionCompletion,
    },
}

/// Atomic result of validating and indexing one selected-context delta.
///
/// The ready blueprint is immutable and can open any number of operation-local
/// lexical sources. Contextual reverse-inventory evidence remains separate from
/// operational cancellation so a cancelled construction cannot publish a
/// partially indexed blueprint.
pub(super) enum SelectedContextOverlayFragmentSourceBlueprintConstruction {
    Ready(Box<SelectedContextOverlayFragmentSourceBlueprint>),
    Cancelled {
        contextual_reverse_inventory_completion: ResolutionCompletion,
        cancellation_completion: ResolutionCompletion,
    },
}

/// One immutable, validated selected-context overlay.
///
/// Candidate paths and their endpoint indexes are owned exactly once by this
/// blueprint. Each semantic operation borrows them through a freshly opened
/// [`SelectedContextOverlayFragmentSource`], which owns only its mutable reverse
/// gap exclusion preparation.
pub(super) struct SelectedContextOverlayFragmentSourceBlueprint {
    removed_candidate_paths: Box<[CandidatePathIdentity]>,
    removed_reverse_candidate_gaps: Box<[ReverseCandidateGapIdentity]>,
    added_candidate_paths: Box<[(CandidatePathIdentity, PartialPath)]>,
    boundary_nodes: Box<[BindingNodeId]>,
    callable_static_import_boundaries: Box<[BindingNodeId]>,
    shared_semantic_identities: Box<[ResolutionSemanticIdentity]>,
    added_forward: AddedCandidateIndex,
    added_reverse: AddedCandidateIndex,
    contextual_reverse_inventory_completion: ResolutionCompletion,
}

impl SelectedContextOverlayFragmentSourceBlueprint {
    fn retain_base_candidate(&self, candidate: CandidatePathIdentity) -> StoreResult<bool> {
        if self
            .added_candidate_paths
            .binary_search_by_key(&candidate, |(identity, _)| *identity)
            .is_ok()
        {
            return Err(StoreError::new(format!(
                "base candidate source conflicts with selected-context path {candidate:?}"
            )));
        }
        Ok(self
            .removed_candidate_paths
            .binary_search(&candidate)
            .is_err())
    }

    pub(super) fn filter_base_candidate_for_demand(
        &self,
        candidate: CandidatePathIdentity,
    ) -> StoreResult<bool> {
        self.retain_base_candidate(candidate)
    }

    /// A removed path is removed in both directions, so reverse base rows are
    /// retained by the same rule. Reverse gap exclusions are a caller-owned
    /// plan applied by the base visitor, not a per-row predicate, so they are
    /// deliberately not consulted here.
    pub(super) fn filter_base_reverse_candidate_for_demand(
        &self,
        candidate: CandidatePathIdentity,
    ) -> StoreResult<bool> {
        self.retain_base_candidate(candidate)
    }

    pub(super) fn from_selected_overlay(
        overlay: SelectedContextOverlay,
        cancellation: &CancellationToken,
    ) -> StoreResult<SelectedContextOverlayFragmentSourceBlueprintConstruction> {
        Self::from_selected_overlay_with_session(overlay, cancellation, None)
    }

    pub(super) fn from_selected_overlay_in_session(
        overlay: SelectedContextOverlay,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> StoreResult<SelectedContextOverlayFragmentSourceBlueprintConstruction> {
        Self::from_selected_overlay_with_session(overlay, cancellation, Some(session))
    }

    fn from_selected_overlay_with_session(
        overlay: SelectedContextOverlay,
        cancellation: &CancellationToken,
        session: Option<&ResolutionSession>,
    ) -> StoreResult<SelectedContextOverlayFragmentSourceBlueprintConstruction> {
        let (
            removed_candidate_paths,
            removed_reverse_candidate_gaps,
            added_candidate_paths,
            boundary_nodes,
            callable_static_import_boundaries,
            shared_semantic_identities,
            contextual_reverse_inventory_completion,
        ) = overlay.into_parts();
        Self::from_context_parts(
            removed_candidate_paths,
            removed_reverse_candidate_gaps,
            added_candidate_paths,
            boundary_nodes,
            callable_static_import_boundaries,
            shared_semantic_identities,
            contextual_reverse_inventory_completion,
            cancellation,
            session,
        )
    }

    pub(super) fn from_parts(
        removed_candidate_paths: Box<[CandidatePathIdentity]>,
        removed_reverse_candidate_gaps: Box<[ReverseCandidateGapIdentity]>,
        added_candidate_paths: Box<[(CandidatePathIdentity, PartialPath)]>,
        boundary_nodes: Box<[BindingNodeId]>,
        callable_static_import_boundaries: Box<[BindingNodeId]>,
        contextual_reverse_inventory_completion: ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> StoreResult<SelectedContextOverlayFragmentSourceBlueprintConstruction> {
        Self::from_context_parts(
            removed_candidate_paths,
            removed_reverse_candidate_gaps,
            added_candidate_paths,
            boundary_nodes,
            callable_static_import_boundaries,
            Box::new([]),
            contextual_reverse_inventory_completion,
            cancellation,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_context_parts(
        removed_candidate_paths: Box<[CandidatePathIdentity]>,
        removed_reverse_candidate_gaps: Box<[ReverseCandidateGapIdentity]>,
        added_candidate_paths: Box<[(CandidatePathIdentity, PartialPath)]>,
        boundary_nodes: Box<[BindingNodeId]>,
        callable_static_import_boundaries: Box<[BindingNodeId]>,
        shared_semantic_identities: Box<[ResolutionSemanticIdentity]>,
        contextual_reverse_inventory_completion: ResolutionCompletion,
        cancellation: &CancellationToken,
        session: Option<&ResolutionSession>,
    ) -> StoreResult<SelectedContextOverlayFragmentSourceBlueprintConstruction> {
        let cancelled = |contextual_reverse_inventory_completion| {
            SelectedContextOverlayFragmentSourceBlueprintConstruction::Cancelled {
                contextual_reverse_inventory_completion,
                cancellation_completion: cancelled_completion(),
            }
        };
        if cancellation.is_cancelled() {
            return Ok(cancelled(contextual_reverse_inventory_completion));
        }

        let mut work = 0_usize;
        let validation_work = removed_candidate_paths
            .len()
            .checked_add(removed_reverse_candidate_gaps.len())
            .and_then(|count| count.checked_add(boundary_nodes.len()))
            .and_then(|count| count.checked_add(callable_static_import_boundaries.len()))
            .and_then(|count| count.checked_add(shared_semantic_identities.len()))
            .expect("selected context validation work must fit usize");
        if session.is_some_and(|session| !(0..validation_work).all(|_| session.scope_step())) {
            return Ok(cancelled(contextual_reverse_inventory_completion));
        }
        if !validate_strict_overlay_order(
            "removed candidate path",
            &removed_candidate_paths,
            cancellation,
            &mut work,
        )? || !validate_strict_overlay_order(
            "removed reverse candidate gap",
            &removed_reverse_candidate_gaps,
            cancellation,
            &mut work,
        )? || !validate_strict_overlay_order(
            "generated boundary node",
            &boundary_nodes,
            cancellation,
            &mut work,
        )? || (!callable_static_import_boundaries.is_empty()
            && !validate_strict_overlay_order(
                "callable static-import boundary node",
                &callable_static_import_boundaries,
                cancellation,
                &mut work,
            )?)
        {
            return Ok(cancelled(contextual_reverse_inventory_completion));
        }
        if !shared_semantic_identities.is_empty()
            && !validate_strict_overlay_order(
                "shared semantic identity",
                &shared_semantic_identities,
                cancellation,
                &mut work,
            )?
        {
            return Ok(cancelled(contextual_reverse_inventory_completion));
        }
        for identity in &shared_semantic_identities {
            if session.is_some_and(|session| !session.scope_step()) {
                return Ok(cancelled(contextual_reverse_inventory_completion));
            }
            if poll_overlay_work(cancellation, &mut work) {
                return Ok(cancelled(contextual_reverse_inventory_completion));
            }
            if identity.space() != super::local_identity::ResolutionSemanticIdentitySpace::Shared {
                return Err(StoreError::new(format!(
                    "selected context semantic identity is not Shared: {identity:?}"
                )));
            }
        }

        for &boundary in callable_static_import_boundaries.iter() {
            if session.is_some_and(|session| !session.scope_step()) {
                return Ok(cancelled(contextual_reverse_inventory_completion));
            }
            if poll_overlay_work(cancellation, &mut work) {
                return Ok(cancelled(contextual_reverse_inventory_completion));
            }
            if boundary_nodes.binary_search(&boundary).is_err() {
                return Err(StoreError::new(format!(
                    "selected context callable static-import boundary is not a generated Java boundary node: {boundary:?}"
                )));
            }
        }

        let mut prior_added = None;
        for (candidate, _) in added_candidate_paths.iter() {
            if session.is_some_and(|session| !session.scope_step()) {
                return Ok(cancelled(contextual_reverse_inventory_completion));
            }
            if poll_overlay_work(cancellation, &mut work) {
                return Ok(cancelled(contextual_reverse_inventory_completion));
            }
            if prior_added.is_some_and(|prior| prior >= *candidate) {
                return Err(StoreError::new(format!(
                    "selected context overlay has noncanonical or duplicate added candidate path {candidate:?}"
                )));
            }
            if removed_candidate_paths.binary_search(candidate).is_ok() {
                return Err(StoreError::new(format!(
                    "selected context overlay both removes and adds candidate path {candidate:?}"
                )));
            }
            prior_added = Some(*candidate);
        }
        if let ResolutionCompletion::Incomplete(reasons) = &contextual_reverse_inventory_completion
        {
            if reasons.is_shared() {
                let mut poll = || {
                    if session.is_some_and(|session| !session.scope_step()) {
                        return true;
                    }
                    poll_overlay_work(cancellation, &mut work)
                };
                let Some(contains_cancelled) =
                    reasons.contains_with_poll(&ResolutionIncompleteReason::Cancelled, &mut poll)
                else {
                    return Ok(cancelled(contextual_reverse_inventory_completion));
                };
                if contains_cancelled {
                    return Err(StoreError::new(
                        "selected contextual inventory contains operation-local cancellation",
                    ));
                }
            } else {
                for &reason in reasons.iter() {
                    if session.is_some_and(|session| !session.scope_step()) {
                        return Ok(cancelled(contextual_reverse_inventory_completion));
                    }
                    if poll_overlay_work(cancellation, &mut work) {
                        return Ok(cancelled(contextual_reverse_inventory_completion));
                    }
                    if reason == ResolutionIncompleteReason::Cancelled {
                        return Err(StoreError::new(
                            "selected contextual inventory contains operation-local cancellation",
                        ));
                    }
                }
            }
        }

        let mut added_forward = AddedCandidateIndex::with_capacity(added_candidate_paths.len());
        let mut added_reverse = AddedCandidateIndex::with_capacity(added_candidate_paths.len());
        for (candidate, path) in added_candidate_paths.iter() {
            if session.is_some_and(|session| !session.scope_step()) {
                return Ok(cancelled(contextual_reverse_inventory_completion));
            }
            if poll_overlay_work(cancellation, &mut work) {
                return Ok(cancelled(contextual_reverse_inventory_completion));
            }
            added_forward.insert(path.start(), *candidate);
            added_reverse.insert(path.end(), *candidate);
        }
        if cancellation.is_cancelled() {
            return Ok(cancelled(contextual_reverse_inventory_completion));
        }

        Ok(
            SelectedContextOverlayFragmentSourceBlueprintConstruction::Ready(Box::new(Self {
                removed_candidate_paths,
                removed_reverse_candidate_gaps,
                added_candidate_paths,
                boundary_nodes,
                callable_static_import_boundaries,
                shared_semantic_identities,
                added_forward,
                added_reverse,
                contextual_reverse_inventory_completion,
            })),
        )
    }

    /// Open one operation-local source over this immutable overlay.
    ///
    /// Opening does not clone candidate paths or completion evidence. Only the
    /// copy-sized reverse-gap identities are copied into the operation's fresh
    /// mutable exclusion plan.
    pub(super) fn open<'a>(
        &'a self,
        base: &'a dyn BatchResolutionFragmentSource,
    ) -> SelectedContextOverlayFragmentSource<'a> {
        SelectedContextOverlayFragmentSource::from_blueprint(
            base,
            SelectedContextOverlayFragmentSourceBlueprintStorage::Borrowed(self),
            None,
        )
    }

    pub(super) fn open_in_session<'a>(
        &'a self,
        base: &'a dyn BatchResolutionFragmentSource,
        session: &'a ResolutionSession,
    ) -> SelectedContextOverlayFragmentSource<'a> {
        SelectedContextOverlayFragmentSource::from_blueprint(
            base,
            SelectedContextOverlayFragmentSourceBlueprintStorage::Borrowed(self),
            Some(session),
        )
    }

    pub(super) const fn contextual_reverse_inventory_completion(&self) -> &ResolutionCompletion {
        &self.contextual_reverse_inventory_completion
    }

    pub(super) const fn boundary_nodes(&self) -> &[BindingNodeId] {
        &self.boundary_nodes
    }

    pub(super) const fn shared_semantic_identities(&self) -> &[ResolutionSemanticIdentity] {
        &self.shared_semantic_identities
    }

    /// Borrow already validated paths for test-only demanded relation identity
    /// checks and hydration. Candidate matching remains owned by this source.
    pub(super) fn added_candidate_paths(&self) -> &[(CandidatePathIdentity, PartialPath)] {
        &self.added_candidate_paths
    }

    /// Borrow the canonical selected callable static-import boundary set.
    pub(super) fn callable_static_import_boundaries(&self) -> &[BindingNodeId] {
        &self.callable_static_import_boundaries
    }

    pub(super) fn is_callable_static_import_boundary(&self, node: BindingNodeId) -> bool {
        self.callable_static_import_boundaries
            .binary_search(&node)
            .is_ok()
    }
}

enum SelectedContextOverlayFragmentSourceBlueprintStorage<'a> {
    Owned(Box<SelectedContextOverlayFragmentSourceBlueprint>),
    Borrowed(&'a SelectedContextOverlayFragmentSourceBlueprint),
}

impl SelectedContextOverlayFragmentSourceBlueprintStorage<'_> {
    fn get(&self) -> &SelectedContextOverlayFragmentSourceBlueprint {
        match self {
            Self::Owned(blueprint) => blueprint,
            Self::Borrowed(blueprint) => blueprint,
        }
    }
}

/// One operation-local lexical overlay over an immutable batch source.
///
/// The raw source remains independently usable and unchanged. This adapter
/// borrows a selected delta and its endpoint indexes from an immutable
/// blueprint. It never retains placement metadata or a selected contextual
/// catalog.
pub(super) struct SelectedContextOverlayFragmentSource<'a> {
    base: &'a dyn BatchResolutionFragmentSource,
    blueprint: SelectedContextOverlayFragmentSourceBlueprintStorage<'a>,
    resolution_session: Option<&'a ResolutionSession>,
    reverse_gap_exclusions: ReverseCandidateGapExclusionPlan,
}

impl<'a> SelectedContextOverlayFragmentSource<'a> {
    pub(super) fn from_selected_overlay(
        base: &'a dyn BatchResolutionFragmentSource,
        overlay: SelectedContextOverlay,
        cancellation: &CancellationToken,
    ) -> StoreResult<SelectedContextOverlayFragmentSourceConstruction<'a>> {
        let construction = SelectedContextOverlayFragmentSourceBlueprint::from_selected_overlay(
            overlay,
            cancellation,
        )?;
        Ok(Self::from_blueprint_construction(base, construction))
    }

    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        base: &'a dyn BatchResolutionFragmentSource,
        removed_candidate_paths: Box<[CandidatePathIdentity]>,
        removed_reverse_candidate_gaps: Box<[ReverseCandidateGapIdentity]>,
        added_candidate_paths: Box<[(CandidatePathIdentity, PartialPath)]>,
        boundary_nodes: Box<[BindingNodeId]>,
        callable_static_import_boundaries: Box<[BindingNodeId]>,
        contextual_reverse_inventory_completion: ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> StoreResult<SelectedContextOverlayFragmentSourceConstruction<'a>> {
        let construction = SelectedContextOverlayFragmentSourceBlueprint::from_parts(
            removed_candidate_paths,
            removed_reverse_candidate_gaps,
            added_candidate_paths,
            boundary_nodes,
            callable_static_import_boundaries,
            contextual_reverse_inventory_completion,
            cancellation,
        )?;
        Ok(Self::from_blueprint_construction(base, construction))
    }

    fn from_blueprint_construction(
        base: &'a dyn BatchResolutionFragmentSource,
        construction: SelectedContextOverlayFragmentSourceBlueprintConstruction,
    ) -> SelectedContextOverlayFragmentSourceConstruction<'a> {
        match construction {
            SelectedContextOverlayFragmentSourceBlueprintConstruction::Ready(blueprint) => {
                SelectedContextOverlayFragmentSourceConstruction::Ready(Box::new(
                    Self::from_blueprint(
                        base,
                        SelectedContextOverlayFragmentSourceBlueprintStorage::Owned(blueprint),
                        None,
                    ),
                ))
            }
            SelectedContextOverlayFragmentSourceBlueprintConstruction::Cancelled {
                contextual_reverse_inventory_completion,
                cancellation_completion,
            } => SelectedContextOverlayFragmentSourceConstruction::Cancelled {
                contextual_reverse_inventory_completion,
                cancellation_completion,
            },
        }
    }

    fn from_blueprint(
        base: &'a dyn BatchResolutionFragmentSource,
        blueprint: SelectedContextOverlayFragmentSourceBlueprintStorage<'a>,
        resolution_session: Option<&'a ResolutionSession>,
    ) -> Self {
        let reverse_gap_exclusions = ReverseCandidateGapExclusionPlan::from_canonical_identities(
            blueprint
                .get()
                .removed_reverse_candidate_gaps
                .to_vec()
                .into_boxed_slice(),
        );
        Self {
            base,
            blueprint,
            resolution_session,
            reverse_gap_exclusions,
        }
    }

    fn blueprint(&self) -> &SelectedContextOverlayFragmentSourceBlueprint {
        self.blueprint.get()
    }

    /// Reverse-only Java package inventory evidence. The adapter deliberately
    /// never injects this into a candidate batch; the top-level reverse
    /// operation combines it once with the filtered raw inventory.
    pub(super) fn contextual_reverse_inventory_completion(&self) -> &ResolutionCompletion {
        self.blueprint().contextual_reverse_inventory_completion()
    }

    fn removed_candidate(&self, candidate: CandidatePathIdentity) -> bool {
        self.blueprint()
            .removed_candidate_paths
            .binary_search(&candidate)
            .is_ok()
    }

    fn added_candidate_path(&self, candidate: CandidatePathIdentity) -> Option<&PartialPath> {
        let blueprint = self.blueprint();
        blueprint
            .added_candidate_paths
            .binary_search_by_key(&candidate, |(identity, _)| *identity)
            .ok()
            .map(|index| &blueprint.added_candidate_paths[index].1)
    }

    #[allow(clippy::too_many_arguments)]
    fn visit_merged_candidate_match_pages(
        &self,
        added_index: &AddedCandidateIndex,
        requests: &[BatchCandidateRequest],
        maximum_page_rows: usize,
        resolution_session: Option<&ResolutionSession>,
        cancellation: &CancellationToken,
        visit_base: impl FnOnce(
            &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
        ) -> StoreResult<BatchCandidateCompletionOutcome>,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        assert_canonical_candidate_requests(requests);
        assert!((1..=MAX_SOURCE_ROWS_PER_BATCH).contains(&maximum_page_rows));
        let resolution_session = resolution_session.or(self.resolution_session);

        let mut work = 0_usize;
        let mut cancellation_observed = cancellation.is_cancelled();
        let mut seen = HashSet::default();
        let mut publisher = BoundedCandidatePagePublisher::new(visitor, maximum_page_rows);

        let completion = visit_base(&mut |page| {
            if publisher.stopped() {
                return Err(StoreError::new(
                    "base candidate source emitted rows after the overlay visitor stopped",
                ));
            }
            if page.is_empty() || page.len() > MAX_SOURCE_ROWS_PER_BATCH {
                return Err(StoreError::new(format!(
                    "base candidate source returned invalid output page length {}",
                    page.len()
                )));
            }
            for &matched in page {
                if resolution_session.is_some_and(|session| !session.scope_step()) {
                    cancellation_observed = true;
                    return Ok(false);
                }
                if poll_overlay_work(cancellation, &mut work) {
                    cancellation_observed = true;
                    return Ok(false);
                }
                let key = (matched.request_ordinal(), matched.candidate());
                if key.0 >= requests.len() {
                    return Err(StoreError::new(format!(
                        "base candidate {:?} names invalid request {} of {}",
                        key.1,
                        key.0,
                        requests.len()
                    )));
                }
                if !seen.insert(key) {
                    return Err(StoreError::new(format!(
                        "base candidate source repeated request {} candidate {:?}",
                        key.0, key.1
                    )));
                }
                if self.blueprint().retain_base_candidate(key.1)?
                    && !publisher.push(matched, cancellation)?
                {
                    cancellation_observed |= cancellation.is_cancelled();
                    return Ok(false);
                }
            }
            Ok(!publisher.stopped())
        })?;

        cancellation_observed |= completion_contains_cancelled_with_poll(
            completion.unconditional_completion(),
            cancellation,
            &mut work,
        );
        if !publisher.stopped() && !cancellation_observed {
            let mut cursor = AddedCandidateCursor::new(requests, added_index);
            while let Some((request_ordinal, candidate)) =
                cursor.next(cancellation, &mut work, &mut cancellation_observed)
            {
                if resolution_session.is_some_and(|session| !session.scope_step()) {
                    cancellation_observed = true;
                    break;
                }
                let key = (request_ordinal, candidate);
                if !seen.insert(key) {
                    return Err(StoreError::new(format!(
                        "selected context overlay repeated request {request_ordinal} candidate {candidate:?}"
                    )));
                }
                if !publisher.push(
                    BatchCandidateMatch::new(candidate, request_ordinal),
                    cancellation,
                )? {
                    cancellation_observed |= cancellation.is_cancelled();
                    break;
                }
            }
        }
        if !publisher.stopped() && !cancellation_observed {
            publisher.finish(cancellation)?;
            cancellation_observed |= cancellation.is_cancelled();
        }
        if cancellation_observed {
            Ok(include_overlay_candidate_cancellation(
                completion,
                cancellation,
                &mut work,
            ))
        } else {
            Ok(completion)
        }
    }

    /// Demand sources read base coverage for the entire request batch once,
    /// then page each immutable relation without reopening the base source.
    pub(super) fn visit_forward_additions_for_demand(
        &self,
        requests: &[BatchCandidateRequest],
        completion: BatchCandidateCompletionOutcome,
        maximum_page_rows: usize,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        assert_eq!(completion.branch_completions().len(), requests.len());
        self.visit_merged_candidate_match_pages(
            &self.blueprint().added_forward,
            requests,
            maximum_page_rows,
            self.resolution_session,
            cancellation,
            |_| Ok(completion),
            visitor,
        )
    }

    /// Reverse mirror of `visit_forward_additions_for_demand`, over the
    /// overlay's `added_reverse` index. The base is not reopened: the caller
    /// already paid one whole-batch reverse visit and supplies its coverage.
    pub(super) fn visit_reverse_additions_for_demand(
        &self,
        requests: &[BatchCandidateRequest],
        completion: BatchCandidateCompletionOutcome,
        maximum_page_rows: usize,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        assert_eq!(completion.branch_completions().len(), requests.len());
        self.visit_merged_candidate_match_pages(
            &self.blueprint().added_reverse,
            requests,
            maximum_page_rows,
            self.resolution_session,
            cancellation,
            |_| Ok(completion),
            visitor,
        )
    }

    fn materialize_forward_candidates(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
    ) -> StoreResult<BatchCandidateOutcome> {
        let mut staged = Vec::new();
        let mut seen = HashSet::default();
        let mut work = 0_usize;
        let mut cancellation_observed = false;
        let mut completion =
            self.visit_forward_candidate_match_pages(requests, cancellation, &mut |page| {
                for &matched in page {
                    if poll_overlay_work(cancellation, &mut work) {
                        cancellation_observed = true;
                        return Ok(false);
                    }
                    if !seen.insert(matched) {
                        return Err(StoreError::new(format!(
                            "forward candidate source repeated one natural identity: {matched:?}"
                        )));
                    }
                    staged.push(matched);
                }
                Ok(true)
            })?;
        cancellation_observed |= cancellation.is_cancelled();
        if cancellation_observed {
            staged.clear();
            completion =
                include_overlay_candidate_cancellation(completion, cancellation, &mut work);
        }
        materialize_overlay_candidate_outcome(
            requests.len(),
            staged,
            completion,
            cancellation,
            &mut work,
        )
    }

    fn materialize_reverse_candidates(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
    ) -> StoreResult<BatchCandidateOutcome> {
        let mut staged = Vec::new();
        let mut seen = HashSet::default();
        let mut work = 0_usize;
        let mut cancellation_observed = false;
        let mut completion =
            self.visit_reverse_candidate_match_pages(requests, cancellation, &mut |page| {
                for &matched in page {
                    if poll_overlay_work(cancellation, &mut work) {
                        cancellation_observed = true;
                        return Ok(false);
                    }
                    if !seen.insert(matched) {
                        return Err(StoreError::new(format!(
                            "reverse candidate source repeated one natural identity: {matched:?}"
                        )));
                    }
                    staged.push(matched);
                }
                Ok(true)
            })?;
        cancellation_observed |= cancellation.is_cancelled();
        if cancellation_observed {
            staged.clear();
            completion =
                include_overlay_candidate_cancellation(completion, cancellation, &mut work);
        }
        materialize_overlay_candidate_outcome(
            requests.len(),
            staged,
            completion,
            cancellation,
            &mut work,
        )
    }

    fn visit_reverse_candidate_match_pages_with_owned_exclusions(
        &self,
        requests: &[BatchCandidateRequest],
        exclusions: &mut ReverseCandidateGapExclusionPlan,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        self.visit_merged_candidate_match_pages(
            &self.blueprint().added_reverse,
            requests,
            MAX_SOURCE_ROWS_PER_BATCH,
            None,
            cancellation,
            |base_visitor| {
                self.base
                    .visit_reverse_candidate_match_pages_with_gap_exclusions_shared(
                        requests,
                        exclusions,
                        cancellation,
                        base_visitor,
                    )
            },
            visitor,
        )
    }
}

fn validate_strict_overlay_order<T: Ord + std::fmt::Debug>(
    label: &str,
    values: &[T],
    cancellation: &CancellationToken,
    work: &mut usize,
) -> StoreResult<bool> {
    for pair in values.windows(2) {
        if poll_overlay_work(cancellation, work) {
            return Ok(false);
        }
        if pair[0] >= pair[1] {
            return Err(StoreError::new(format!(
                "selected context overlay has noncanonical or duplicate {label} {:?}",
                pair[1]
            )));
        }
    }
    Ok(!cancellation.is_cancelled())
}

fn poll_overlay_work(cancellation: &CancellationToken, work: &mut usize) -> bool {
    *work = work
        .checked_add(1)
        .expect("selected context overlay work must fit usize");
    (*work).is_multiple_of(CANCELLATION_QUANTUM) && cancellation.is_cancelled()
}

fn assert_canonical_candidate_requests(requests: &[BatchCandidateRequest]) {
    assert!(
        requests.len() <= MAX_SOURCE_ROWS_PER_BATCH,
        "candidate request page has {} entries; maximum is {MAX_SOURCE_ROWS_PER_BATCH}",
        requests.len()
    );
    for (request_ordinal, request) in requests.iter().enumerate() {
        assert_eq!(
            request.request_ordinal(),
            request_ordinal,
            "candidate requests must use canonical local ordinals"
        );
    }
}

/// Coarse in-memory counterpart of the persisted universal-root first-symbol
/// probe. Every path remains in the node index for unkeyable requests. A
/// universal-root request with a fixed first symbol instead sees only the
/// equal-symbol bucket plus paths whose candidate endpoint has no fixed
/// symbol; exact stack composition filters the latter wildcard bucket.
struct AddedCandidateIndex {
    by_node: HashMap<BindingNodeId, Vec<CandidatePathIdentity>>,
    universal_root_by_first_symbol: HashMap<SemanticId, Vec<CandidatePathIdentity>>,
    universal_root_without_fixed_symbol: Vec<CandidatePathIdentity>,
}

impl AddedCandidateIndex {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            by_node: map_with_capacity(capacity),
            universal_root_by_first_symbol: map_with_capacity(capacity),
            universal_root_without_fixed_symbol: Vec::new(),
        }
    }

    fn insert(&mut self, endpoint: &EndpointSignature, candidate: CandidatePathIdentity) {
        self.by_node
            .entry(endpoint.node())
            .or_default()
            .push(candidate);
        if endpoint.node() != BindingNodeId::universal_root() {
            return;
        }
        match endpoint.symbols().fixed().first() {
            Some(first) => self
                .universal_root_by_first_symbol
                .entry(first.symbol())
                .or_default()
                .push(candidate),
            None => self.universal_root_without_fixed_symbol.push(candidate),
        }
    }

    fn candidates<'a>(&'a self, endpoint: &EndpointSignature) -> AddedCandidateSlices<'a> {
        if endpoint.node() == BindingNodeId::universal_root()
            && let Some(first) = endpoint.symbols().fixed().first()
        {
            return AddedCandidateSlices::Merged {
                keyed: self
                    .universal_root_by_first_symbol
                    .get(&first.symbol())
                    .map(Vec::as_slice)
                    .unwrap_or_default(),
                without_fixed: &self.universal_root_without_fixed_symbol,
            };
        }
        AddedCandidateSlices::One(
            self.by_node
                .get(&endpoint.node())
                .map(Vec::as_slice)
                .unwrap_or_default(),
        )
    }
}

enum AddedCandidateSlices<'a> {
    One(&'a [CandidatePathIdentity]),
    Merged {
        keyed: &'a [CandidatePathIdentity],
        without_fixed: &'a [CandidatePathIdentity],
    },
}

impl AddedCandidateSlices<'_> {
    fn next(
        &self,
        primary_ordinal: &mut usize,
        wildcard_ordinal: &mut usize,
    ) -> Option<CandidatePathIdentity> {
        match self {
            Self::One(candidates) => {
                let candidate = candidates.get(*primary_ordinal).copied();
                if candidate.is_some() {
                    *primary_ordinal += 1;
                }
                candidate
            }
            Self::Merged {
                keyed,
                without_fixed,
            } => match (
                keyed.get(*primary_ordinal).copied(),
                without_fixed.get(*wildcard_ordinal).copied(),
            ) {
                (Some(left), Some(right)) if left <= right => {
                    *primary_ordinal += 1;
                    Some(left)
                }
                (Some(_), Some(right)) => {
                    *wildcard_ordinal += 1;
                    Some(right)
                }
                (Some(left), None) => {
                    *primary_ordinal += 1;
                    Some(left)
                }
                (None, Some(right)) => {
                    *wildcard_ordinal += 1;
                    Some(right)
                }
                (None, None) => None,
            },
        }
    }
}

struct AddedCandidateCursor<'a> {
    requests: &'a [BatchCandidateRequest],
    index: &'a AddedCandidateIndex,
    request_ordinal: usize,
    primary_ordinal: usize,
    wildcard_ordinal: usize,
}

impl<'a> AddedCandidateCursor<'a> {
    const fn new(requests: &'a [BatchCandidateRequest], index: &'a AddedCandidateIndex) -> Self {
        Self {
            requests,
            index,
            request_ordinal: 0,
            primary_ordinal: 0,
            wildcard_ordinal: 0,
        }
    }

    fn next(
        &mut self,
        cancellation: &CancellationToken,
        work: &mut usize,
        cancellation_observed: &mut bool,
    ) -> Option<(usize, CandidatePathIdentity)> {
        while self.request_ordinal < self.requests.len() {
            if poll_overlay_work(cancellation, work) {
                *cancellation_observed = true;
                return None;
            }
            let candidates = self
                .index
                .candidates(self.requests[self.request_ordinal].endpoint());
            if let Some(candidate) =
                candidates.next(&mut self.primary_ordinal, &mut self.wildcard_ordinal)
            {
                return Some((self.request_ordinal, candidate));
            }
            self.request_ordinal += 1;
            self.primary_ordinal = 0;
            self.wildcard_ordinal = 0;
        }
        None
    }
}

struct BoundedCandidatePagePublisher<'a> {
    visitor: &'a mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    page: Vec<BatchCandidateMatch>,
    maximum_rows: usize,
    stopped: bool,
}

impl<'a> BoundedCandidatePagePublisher<'a> {
    fn new(
        visitor: &'a mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
        maximum_rows: usize,
    ) -> Self {
        assert!((1..=MAX_SOURCE_ROWS_PER_BATCH).contains(&maximum_rows));
        Self {
            visitor,
            page: Vec::with_capacity(maximum_rows),
            maximum_rows,
            stopped: false,
        }
    }

    fn push(
        &mut self,
        matched: BatchCandidateMatch,
        cancellation: &CancellationToken,
    ) -> StoreResult<bool> {
        if self.stopped {
            return Err(StoreError::new(
                "candidate page publisher received a row after its visitor stopped",
            ));
        }
        if cancellation.is_cancelled() {
            self.page.clear();
            return Ok(false);
        }
        self.page.push(matched);
        if self.page.len() == self.maximum_rows {
            if cancellation.is_cancelled() {
                self.page.clear();
                return Ok(false);
            }
            self.stopped = !(self.visitor)(&self.page)?;
            self.page.clear();
        }
        Ok(!self.stopped)
    }

    fn finish(&mut self, cancellation: &CancellationToken) -> StoreResult<()> {
        if !self.page.is_empty() {
            if cancellation.is_cancelled() {
                self.page.clear();
                return Ok(());
            }
            self.stopped = !(self.visitor)(&self.page)?;
            self.page.clear();
        }
        Ok(())
    }

    const fn stopped(&self) -> bool {
        self.stopped
    }
}

fn include_overlay_candidate_cancellation(
    completion: BatchCandidateCompletionOutcome,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> BatchCandidateCompletionOutcome {
    let request_count = completion.branch_completions().len();
    let (unconditional_completion, branch_completions) = completion.into_parts();
    let mut evidence = CancellationEvidenceLedger::default();
    let _ = evidence.include(&unconditional_completion, cancellation, work);
    let (unconditional_completion, _) = evidence.finish(true, cancellation, work);
    BatchCandidateCompletionOutcome::new_observing(
        request_count,
        unconditional_completion,
        branch_completions,
        || {
            let _ = poll_overlay_work(cancellation, work);
        },
    )
}

fn materialize_overlay_candidate_outcome(
    request_count: usize,
    staged: Vec<BatchCandidateMatch>,
    mut completion: BatchCandidateCompletionOutcome,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> StoreResult<BatchCandidateOutcome> {
    let mut canonical = BTreeSet::new();
    let mut cancellation_observed = completion_contains_cancelled_with_poll(
        completion.unconditional_completion(),
        cancellation,
        work,
    );
    if !cancellation_observed {
        for matched in staged {
            if poll_overlay_work(cancellation, work) {
                cancellation_observed = true;
                break;
            }
            assert!(
                canonical.insert((matched.request_ordinal(), matched.candidate())),
                "overlay candidate materialization received a duplicate after source validation"
            );
        }
    }
    let mut matches = Vec::with_capacity(canonical.len());
    while let Some((request_ordinal, candidate)) = canonical.pop_first() {
        if poll_overlay_work(cancellation, work) {
            cancellation_observed = true;
            break;
        }
        matches.push(BatchCandidateMatch::new(candidate, request_ordinal));
    }
    cancellation_observed |= cancellation.is_cancelled();
    if cancellation_observed {
        matches.clear();
        completion = include_overlay_candidate_cancellation(completion, cancellation, work);
    }
    let (unconditional_completion, branch_completions) = completion.into_parts();
    assert_eq!(
        branch_completions.len(),
        request_count,
        "overlay candidate completion must retain every request branch"
    );
    Ok(BatchCandidateOutcome {
        matches,
        unconditional_completion,
        branch_completions,
    })
}

fn completion_contains_cancelled_with_poll(
    completion: &ResolutionCompletion,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> bool {
    let mut cancellation_observed = cancellation.is_cancelled();
    if let ResolutionCompletion::Incomplete(reasons) = completion {
        if reasons.is_shared() {
            let mut poll = || {
                cancellation_observed |= poll_overlay_work(cancellation, work);
                false
            };
            let contains_cancelled = reasons
                .contains_with_poll(&ResolutionIncompleteReason::Cancelled, &mut poll)
                .expect("observational completion membership never aborts");
            cancellation_observed |= contains_cancelled;
        } else {
            for &reason in reasons.iter() {
                cancellation_observed |= poll_overlay_work(cancellation, work);
                cancellation_observed |= reason == ResolutionIncompleteReason::Cancelled;
            }
        }
    }
    cancellation_observed | cancellation.is_cancelled()
}

impl BatchResolutionFragmentSource for SelectedContextOverlayFragmentSource<'_> {
    /// As for the path overlay: the overlay rows belong to the base's
    /// selection and are visible for the length of one operation, so the
    /// base's authority is this source's.
    fn selection_authority(&self) -> Option<SeedReadAuthority> {
        self.base.selection_authority()
    }

    fn admits_reverse_reference(&self, reference: SemanticId) -> bool {
        self.base.admits_reverse_reference(reference)
    }

    fn scope_reverse_inventory_completion(
        &self,
        completion: &ResolutionCompletion,
    ) -> ResolutionCompletion {
        self.base.scope_reverse_inventory_completion(completion)
    }

    fn reference_seed(
        &self,
        query: ResolutionQuery,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<ReferenceSeed>> {
        self.base.reference_seed(query, cancellation)
    }

    fn lookup_reference_seeds(
        &self,
        queries: &[ResolutionQuery],
        cancellation: &CancellationToken,
    ) -> StoreResult<ReferenceSeedReadOutcome> {
        self.base.lookup_reference_seeds(queries, cancellation)
    }

    fn lookup_definition_node(
        &self,
        definition: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<BindingNodeId>> {
        self.base.lookup_definition_node(definition, cancellation)
    }

    fn lookup_definition_nodes(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Vec<BatchDefinitionNode>> {
        self.base.lookup_definition_nodes(definitions, cancellation)
    }

    fn issue_reverse_reference_seeds(
        &self,
        requests: &[ReverseReferenceSeedRequest],
        cancellation: &CancellationToken,
    ) -> StoreResult<Vec<ReferenceSeed>> {
        self.base
            .issue_reverse_reference_seeds(requests, cancellation)
    }

    fn visit_reference_seed_batches(
        &self,
        maximum_batch_size: usize,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&ReferenceSeedBatch) -> StoreResult<bool>,
    ) -> StoreResult<ResolutionCompletion> {
        self.base
            .visit_reference_seed_batches(maximum_batch_size, cancellation, visitor)
    }

    fn visit_reference_seed_batches_in_fragments(
        &self,
        fragments: &HashSet<BindingFragmentId>,
        maximum_batch_size: usize,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&ReferenceSeedBatch) -> StoreResult<bool>,
    ) -> StoreResult<ResolutionCompletion> {
        self.base.visit_reference_seed_batches_in_fragments(
            fragments,
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
        assert!(
            nodes.len() <= MAX_SOURCE_ROWS_PER_BATCH,
            "endpoint classification page has {} entries; maximum is {MAX_SOURCE_ROWS_PER_BATCH}",
            nodes.len()
        );
        if cancellation.is_cancelled() {
            return Ok(Vec::new());
        }

        let mut work = 0_usize;
        let mut requested = HashSet::default();
        let mut delegated = Vec::with_capacity(nodes.len());
        let mut staged = BTreeMap::new();
        for &node in nodes {
            if poll_overlay_work(cancellation, &mut work) {
                return Ok(staged.into_values().collect());
            }
            if !requested.insert(node) {
                return Err(StoreError::new(format!(
                    "endpoint classification requests duplicate node {node}"
                )));
            }
            if self.blueprint().boundary_nodes.binary_search(&node).is_ok() {
                staged.insert(node, BatchEndpointClassification::new(node, None, None));
            } else {
                delegated.push(node);
            }
        }

        let base_rows = if delegated.is_empty() || cancellation.is_cancelled() {
            Vec::new()
        } else {
            self.base
                .classify_endpoint_nodes(&delegated, cancellation)?
        };
        let delegated: HashSet<_> = delegated.into_iter().collect();
        for row in base_rows {
            if !delegated.contains(&row.node()) {
                return Err(StoreError::new(format!(
                    "base endpoint classification returned foreign node {}",
                    row.node()
                )));
            }
            if staged.insert(row.node(), row).is_some() {
                return Err(StoreError::new(format!(
                    "base endpoint classification returned duplicate node {}",
                    row.node()
                )));
            }
        }
        if !cancellation.is_cancelled() && staged.len() != nodes.len() {
            let missing: Vec<_> = nodes
                .iter()
                .copied()
                .filter(|node| !staged.contains_key(node))
                .collect();
            return Err(StoreError::new(format!(
                "base endpoint classification omitted requested nodes {missing:?}"
            )));
        }

        let mut classified = Vec::with_capacity(staged.len());
        for &node in nodes {
            if poll_overlay_work(cancellation, &mut work) {
                break;
            }
            if let Some(row) = staged.remove(&node) {
                classified.push(row);
            }
        }
        Ok(classified)
    }

    fn match_forward_candidates(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
    ) -> StoreResult<BatchCandidateOutcome> {
        self.materialize_forward_candidates(requests, cancellation)
    }

    fn visit_forward_candidate_match_pages(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        self.visit_merged_candidate_match_pages(
            &self.blueprint().added_forward,
            requests,
            MAX_SOURCE_ROWS_PER_BATCH,
            None,
            cancellation,
            |base_visitor| {
                self.base
                    .visit_forward_candidate_match_pages(requests, cancellation, base_visitor)
            },
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
        self.visit_merged_candidate_match_pages(
            &self.blueprint().added_forward,
            requests,
            maximum_page_rows,
            resolution_session,
            cancellation,
            |base_visitor| {
                self.base.visit_forward_candidate_match_pages_limited(
                    requests,
                    maximum_page_rows,
                    resolution_session,
                    cancellation,
                    base_visitor,
                )
            },
            visitor,
        )
    }

    fn match_reverse_candidates(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
    ) -> StoreResult<BatchCandidateOutcome> {
        self.materialize_reverse_candidates(requests, cancellation)
    }

    fn visit_reverse_candidate_match_pages(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        let mut exclusions = ReverseCandidateGapExclusionPlan::from_canonical_identities(
            self.blueprint()
                .removed_reverse_candidate_gaps
                .to_vec()
                .into_boxed_slice(),
        );
        self.visit_reverse_candidate_match_pages_with_owned_exclusions(
            requests,
            &mut exclusions,
            cancellation,
            visitor,
        )
    }

    fn visit_reverse_candidate_match_pages_with_gap_exclusions(
        &mut self,
        requests: &[BatchCandidateRequest],
        exclusions: &mut ReverseCandidateGapExclusionPlan,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        if !exclusions.is_empty() && !cancellation.is_cancelled() {
            return Err(StoreError::new(
                "selected context overlay does not compose a second nonempty reverse-gap exclusion plan",
            ));
        }
        let mut owned_exclusions = std::mem::take(&mut self.reverse_gap_exclusions);
        let result = self.visit_reverse_candidate_match_pages_with_owned_exclusions(
            requests,
            &mut owned_exclusions,
            cancellation,
            visitor,
        );
        self.reverse_gap_exclusions = owned_exclusions;
        result
    }

    fn hydrate_candidate_paths(
        &self,
        candidates: &[CandidatePathIdentity],
        cancellation: &CancellationToken,
    ) -> StoreResult<Vec<(CandidatePathIdentity, PartialPath)>> {
        assert!(
            candidates.len() <= MAX_SOURCE_ROWS_PER_BATCH,
            "candidate hydration page has {} entries; maximum is {MAX_SOURCE_ROWS_PER_BATCH}",
            candidates.len()
        );
        if cancellation.is_cancelled() {
            return Ok(Vec::new());
        }

        let mut work = 0_usize;
        let mut requested = HashSet::default();
        let mut delegated = Vec::with_capacity(candidates.len());
        let mut hydrated = BTreeMap::new();
        for &candidate in candidates {
            if poll_overlay_work(cancellation, &mut work) {
                return Ok(hydrated.into_iter().collect());
            }
            if !requested.insert(candidate) {
                return Err(StoreError::new(format!(
                    "candidate hydration requests duplicate identity {candidate:?}"
                )));
            }
            if self.removed_candidate(candidate) {
                return Err(StoreError::new(format!(
                    "candidate hydration requested selected-context-removed identity {candidate:?}"
                )));
            }
            let Some(path) = self.added_candidate_path(candidate) else {
                delegated.push(candidate);
                continue;
            };
            let mut clone_cancelled = false;
            let cloned = path.clone_with_poll(&mut || {
                clone_cancelled |= poll_overlay_work(cancellation, &mut work);
                clone_cancelled
            });
            let Some(cloned) = cloned else {
                return Ok(hydrated.into_iter().collect());
            };
            assert!(
                hydrated.insert(candidate, cloned).is_none(),
                "one selected-context candidate is hydrated once per request page"
            );
            if cancellation.is_cancelled() {
                return Ok(hydrated.into_iter().collect());
            }
        }

        let base_rows = if delegated.is_empty() || cancellation.is_cancelled() {
            Vec::new()
        } else {
            self.base
                .hydrate_candidate_paths(&delegated, cancellation)?
        };
        let delegated: HashSet<_> = delegated.into_iter().collect();
        for (candidate, path) in base_rows {
            if self.removed_candidate(candidate) {
                return Err(StoreError::new(format!(
                    "base hydration returned selected-context-removed identity {candidate:?}"
                )));
            }
            if self.added_candidate_path(candidate).is_some() {
                return Err(StoreError::new(format!(
                    "base hydration conflicts with selected-context identity {candidate:?}"
                )));
            }
            if !delegated.contains(&candidate) {
                return Err(StoreError::new(format!(
                    "base hydration returned foreign identity {candidate:?}"
                )));
            }
            if hydrated.insert(candidate, path).is_some() {
                return Err(StoreError::new(format!(
                    "base hydration returned duplicate identity {candidate:?}"
                )));
            }
        }
        if !cancellation.is_cancelled() && hydrated.len() != candidates.len() {
            let missing: Vec<_> = candidates
                .iter()
                .copied()
                .filter(|candidate| !hydrated.contains_key(candidate))
                .collect();
            return Err(StoreError::new(format!(
                "base hydration omitted requested candidate identities {missing:?}"
            )));
        }
        Ok(hydrated.into_iter().collect())
    }

    fn visit_type_transfer_rules(
        &self,
        source_slot: SemanticId,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&TypeTransferRule) -> StoreResult<bool>,
    ) -> StoreResult<ResolutionCompletion> {
        self.base
            .visit_type_transfer_rules(source_slot, cancellation, visitor)
    }
}

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
    pub(super) fn assert_fresh(&self) {
        assert_eq!(
            self,
            &Self::default(),
            "resolution batch metrics sink must be fresh and default-valued"
        );
    }

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

    pub(crate) fn accumulate(&mut self, other: Self) {
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

    pub(super) fn into_parts(self) -> (SemanticId, ResolutionAnswer) {
        (self.reference, self.answer)
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

    pub(super) fn into_parts(
        self,
    ) -> (
        Box<[BatchedReferenceAnswer]>,
        ResolutionCompletion,
        ResolutionBatchMetrics,
    ) {
        (self.answers, self.completion, self.metrics)
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
    saturation: SaturationBranch,
}

fn go_universe_seed_eligible(seed: &ReferenceSeed) -> bool {
    let Some(metadata) = seed.site_metadata() else {
        return false;
    };
    if metadata.go_spelling_namespace().is_none()
        || !metadata.unqualified()
        || metadata.go_package_qualifier()
    {
        return false;
    }
    // Seed-wide completion includes obligations outside lexical name lookup,
    // such as call applicability and reverse inventory. Universe lookup is
    // allowed only after the selected source scopes below are exhausted
    // without an incomplete scope search.
    true
}

#[derive(Debug)]
struct SeedState {
    reference: SemanticId,
    go_spelling_namespace: Option<ResolutionNamespace>,
    go_package_qualifier: bool,
    go_universe_seed_eligible: bool,
    completed: Vec<CompletedPath>,
    terminals: Vec<IncompleteTerminalPath>,
    incomplete_scope_search: bool,
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
    endpoint_definitions:
        HashMap<BindingNodeId, Option<(SemanticId, Option<super::model::GoDefinitionNamespaces>)>>,
    cancelled: bool,
}

enum SeededBatchInitialization {
    Ready(InitializedSeededBatch),
    Cancelled(ReferenceBatchAnswer),
}

// Opt-in execution protocol only. The eager production driver below remains
// independent. This frame handles lexical path cycles, not dynamic dependencies
// between evaluator tasks; those require an operation-owned scheduler.
pub(super) struct DemandForwardBatchFrame {
    initialized: InitializedSeededBatch,
    arena: HashMap<CandidatePathIdentity, PartialPath>,
    accounted_hydrated_completions: HashSet<(usize, CandidatePathIdentity)>,
    candidate_completion: OperationCandidateCompletionLedger,
    round: Option<DemandForwardRound>,
    terminal: bool,
}

struct DemandForwardRound {
    expandable: Vec<BatchWorkPath>,
    expandable_seed_indices: Vec<usize>,
    terminalized: HashSet<usize>,
    matches: Vec<BatchCandidateMatch>,
    request_base: usize,
    request_page: Vec<BatchCandidateRequest>,
}

pub(super) enum DemandForwardBatchStart {
    Running(Box<DemandForwardBatchFrame>),
    Ready(ReferenceBatchAnswer),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DemandForwardReadiness {
    /// Every exact endpoint in this page has an exhausted, immutable candidate
    /// relation under the operation's fixed selected authority. All discovered
    /// prefix dependencies have terminal FULL evaluator answers. The provider
    /// must not close a dynamic dependency SCC until its joint closure is
    /// certified; this prototype does not provide that scheduler.
    ///
    /// Discovering disjoint keys does not invalidate closed keys. Reopening a
    /// closed key is invalid prototype execution, not semantic incompleteness:
    /// flushing the cache cannot retract paths/certificates already consumed by
    /// a frame. Do not return Ready for a partial candidate snapshot.
    Ready,
    AwaitingDependencies,
}

pub(super) enum DemandForwardBatchPoll {
    Continue,
    AwaitingDependencies,
    Ready(ReferenceBatchAnswer),
}

impl DemandForwardBatchFrame {
    /// Preserve the ordinary root-batch admission schedule before suspension.
    pub(super) fn start_reference_batch<S: BatchResolutionFragmentSource + ?Sized>(
        engine: &BatchResolutionEngine<'_, S>,
        batch: &ReferenceSeedBatch,
        cancellation: &CancellationToken,
    ) -> DemandForwardBatchStart {
        if !engine.charge_scope_steps(batch.len()) {
            let mut work = 0_usize;
            let (prepared, _) =
                prepare_reference_seed_completions(batch.seeds(), cancellation, &mut work);
            return DemandForwardBatchStart::Ready(cancelled_prepared_seed_answers(
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
        Self::start_seeds(engine, batch.seeds(), cancellation)
    }

    /// Start one frame over seeds the caller has already read and charged.
    ///
    /// A root batch charges its seeds when it starts. Demanded references are
    /// charged one step each before their plural seed read, as the scalar
    /// read they replace was, so this admits them without a second charge.
    /// The seeds may come from several fragments: the frame answers each seed
    /// on its own, and nothing it reads is keyed by the fragment.
    pub(super) fn start_seeds<S: BatchResolutionFragmentSource + ?Sized>(
        engine: &BatchResolutionEngine<'_, S>,
        seeds: &[ReferenceSeed],
        cancellation: &CancellationToken,
    ) -> DemandForwardBatchStart {
        assert!(
            !seeds.is_empty(),
            "a forward frame starts with at least one seed"
        );
        assert!(
            seeds.len() <= MAX_REFERENCE_SEEDS_PER_BATCH,
            "a forward frame has {} seeds; maximum is {MAX_REFERENCE_SEEDS_PER_BATCH}",
            seeds.len()
        );
        let mut work = 0_usize;
        let (prepared, mut cancelled) =
            prepare_reference_seed_completions(seeds, cancellation, &mut work);
        let mut requests = Vec::with_capacity(seeds.len());
        if !cancelled {
            for seed in seeds {
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
            return DemandForwardBatchStart::Ready(cancelled_prepared_seed_answers(
                prepared,
                ResolutionBatchMetrics {
                    reference_seeds: seeds.len(),
                    batches: 1,
                    ..ResolutionBatchMetrics::default()
                },
                cancellation,
                &mut work,
            ));
        }
        Self::start(engine, &requests, cancellation)
    }

    /// Preserve the ordinary non-root query's seed read and its own admission
    /// charge. In particular, do not route through root-batch normalization.
    ///
    /// Production reads demanded references' seeds in plural and starts them
    /// with `start_seeds`; this one-reference form remains the frame's parity
    /// check against the eager scalar query.
    #[cfg(test)]
    pub(super) fn start_query<S: BatchResolutionFragmentSource + ?Sized>(
        engine: &BatchResolutionEngine<'_, S>,
        query: ResolutionQuery,
        cancellation: &CancellationToken,
    ) -> StoreResult<DemandForwardBatchStart> {
        let ready = |answer: ResolutionAnswer| {
            DemandForwardBatchStart::Ready(ReferenceBatchAnswer {
                completion: answer.completion().clone(),
                answers: Box::new([BatchedReferenceAnswer {
                    reference: query.reference(),
                    answer,
                }]),
                metrics: ResolutionBatchMetrics::default(),
            })
        };
        if cancellation.is_cancelled() {
            return Ok(ready(empty_answer(cancelled_completion())));
        }
        if !engine.charge_scope_steps(1) {
            return Ok(ready(empty_answer(cancelled_completion())));
        }
        let seed = engine.source().reference_seed(query, cancellation)?;
        let Some(seed) = seed else {
            return Ok(ready(if cancellation.is_cancelled() {
                empty_answer(cancelled_completion())
            } else {
                empty_answer(ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(query.reference()),
                ]))
            }));
        };
        let mut work = 0_usize;
        let mut completion = BatchCompletionLedger::default();
        let cancelled = completion.include(seed.completion(), cancellation, &mut work);
        if cancelled || cancellation.is_cancelled() {
            let (completion, _) = completion.finish(cancellation, &mut work);
            return Ok(ready(empty_answer(completion)));
        }
        let request = SeededReferenceRequest::identity_with_poll(seed, &mut || {
            poll_reverse_completion(cancellation, &mut work)
        });
        let Some(request) = request else {
            let (completion, _) = completion.finish(cancellation, &mut work);
            return Ok(ready(empty_answer(completion)));
        };
        Ok(Self::start(
            engine,
            std::slice::from_ref(&request),
            cancellation,
        ))
    }

    pub(super) fn start<S: BatchResolutionFragmentSource + ?Sized>(
        engine: &BatchResolutionEngine<'_, S>,
        requests: &[SeededReferenceRequest],
        cancellation: &CancellationToken,
    ) -> DemandForwardBatchStart {
        match engine.initialize_seeded_reference_batch(requests, cancellation) {
            SeededBatchInitialization::Cancelled(answer) => DemandForwardBatchStart::Ready(answer),
            SeededBatchInitialization::Ready(initialized) => {
                let seed_count = initialized.seeds.len();
                DemandForwardBatchStart::Running(Box::new(Self {
                    initialized,
                    arena: map_with_capacity(seed_count.saturating_mul(4)),
                    accounted_hydrated_completions: HashSet::default(),
                    candidate_completion: OperationCandidateCompletionLedger::new(seed_count),
                    round: None,
                    terminal: false,
                }))
            }
        }
    }

    // Ordinals are local to this exact bounded page. The full endpoint (node,
    // symbol stack and scope stack) is retained, not an initial-name demand.
    pub(super) fn pending_requests(&self) -> &[BatchCandidateRequest] {
        self.round
            .as_ref()
            .map_or(&[], |round| round.request_page.as_slice())
    }

    /// The reference whose path asks for this pending request's endpoint.
    pub(super) fn pending_request_reference(&self, request: &BatchCandidateRequest) -> SemanticId {
        let round = self
            .round
            .as_ref()
            .expect("a pending request belongs to the active round");
        assert!(
            round.request_page.contains(request),
            "a pending request belongs to the current page: {request:?}"
        );
        let state = &round.expandable[round.request_base + request.request_ordinal()];
        self.initialized.seeds[state.seed].reference
    }

    /// Stop an operation-owned task without changing its caller's token or
    /// reading a pending candidate relation. Returned evidence survives even
    /// when the scheduler's shared work budget, rather than the token, stopped.
    pub(super) fn cancel(mut self) -> ReferenceBatchAnswer {
        assert!(
            !self.terminal,
            "a terminal forward frame cannot be cancelled"
        );
        let cancellation = CancellationToken::new();
        if let Some(round) = &self.round {
            include_forward_matched_hydrated_completions_after_cancellation(
                &mut self.initialized.seeds,
                &round.expandable,
                &round.matches,
                &self.arena,
                &mut self.accounted_hydrated_completions,
                &cancellation,
                &mut self.initialized.completion_work,
            );
        }
        select_seed_answers(
            self.initialized.seeds,
            self.initialized.metrics,
            &cancellation,
            true,
            &mut self.initialized.completion_work,
        )
    }

    // Reborrow the SAME operation's source, work session and artifact cache.
    // Nothing is borrowed across polls, so the scheduler can move the frame.
    pub(super) fn poll<S: BatchResolutionFragmentSource + ?Sized>(
        &mut self,
        engine: &BatchResolutionEngine<'_, S>,
        artifact_cache: Option<&mut ForwardCandidateArtifactCache>,
        cancellation: &CancellationToken,
        readiness: &mut impl FnMut(&[BatchCandidateRequest]) -> StoreResult<DemandForwardReadiness>,
    ) -> StoreResult<DemandForwardBatchPoll> {
        assert!(!self.terminal, "a terminal forward frame cannot be resumed");
        let result = self.poll_active(engine, artifact_cache, cancellation, readiness);
        if result.is_err() {
            self.terminal = true;
        }
        result
    }

    fn poll_active<S: BatchResolutionFragmentSource + ?Sized>(
        &mut self,
        engine: &BatchResolutionEngine<'_, S>,
        mut artifact_cache: Option<&mut ForwardCandidateArtifactCache>,
        cancellation: &CancellationToken,
        readiness: &mut impl FnMut(&[BatchCandidateRequest]) -> StoreResult<DemandForwardReadiness>,
    ) -> StoreResult<DemandForwardBatchPoll> {
        if self.initialized.cancelled || cancellation.is_cancelled() {
            self.initialized.cancelled = true;
            return self.finish(engine, cancellation);
        }
        if self.round.is_none() {
            if self.initialized.frontier.is_empty() {
                return self.finish(engine, cancellation);
            }
            self.round = self.prepare_round(engine, artifact_cache.as_deref_mut(), cancellation)?;
            if self.initialized.cancelled {
                return self.finish(engine, cancellation);
            }
            return Ok(DemandForwardBatchPoll::Continue);
        }
        let round = self.round.as_ref().expect("the round is active");
        if round.request_base == round.expandable.len() {
            let round = self.round.take().expect("the round is active");
            self.finish_round(engine, round, artifact_cache, cancellation)?;
            if self.initialized.cancelled || self.initialized.frontier.is_empty() {
                return self.finish(engine, cancellation);
            }
            return Ok(DemandForwardBatchPoll::Continue);
        }
        if !self.fill_request_page(cancellation) {
            return self.finish(engine, cancellation);
        }
        let round = self.round.as_ref().expect("the round is active");
        // This gate precedes the ENTIRE artifact read, including cache-hit
        // evidence replay and exhausted-negative endpoint-cache publication.
        let ready = readiness(&round.request_page)?;
        if cancellation.is_cancelled() {
            self.initialized.cancelled = true;
            return self.finish(engine, cancellation);
        }
        if ready == DemandForwardReadiness::AwaitingDependencies {
            return Ok(DemandForwardBatchPoll::AwaitingDependencies);
        }
        self.read_page(engine, artifact_cache, cancellation)?;
        if self.initialized.cancelled {
            return self.finish(engine, cancellation);
        }
        let round = self.round.as_mut().expect("read page retains its round");
        round.request_base += round.request_page.len();
        round.request_page.clear();
        Ok(DemandForwardBatchPoll::Continue)
    }

    /// Build the page of endpoint keys this frame reads next.
    ///
    /// Returns false when building it observed cancellation, which latches
    /// the frame exactly as the inline page fill did.
    fn fill_request_page(&mut self, cancellation: &CancellationToken) -> bool {
        let Self {
            initialized, round, ..
        } = self;
        let Some(round) = round.as_mut() else {
            return true;
        };
        if round.request_base == round.expandable.len() || !round.request_page.is_empty() {
            return true;
        }
        let end = (round.request_base + MAX_SOURCE_ROWS_PER_BATCH).min(round.expandable.len());
        for (ordinal, state) in round.expandable[round.request_base..end].iter().enumerate() {
            let endpoint = state.path.end().clone_with_poll(&mut || {
                poll_reverse_completion(cancellation, &mut initialized.completion_work)
            });
            let Some(endpoint) = endpoint else {
                initialized.cancelled = true;
                return false;
            };
            round
                .request_page
                .push(BatchCandidateRequest::new(ordinal, endpoint));
        }
        true
    }

    /// The endpoint keys this frame asks the source for on its next poll.
    ///
    /// A scheduler round calls this on every frame it is about to poll so one
    /// candidate-match statement can carry the whole round's keys. Building
    /// the page is exactly the work the frame's own poll does, and the page
    /// the poll then reads is this one, so a frame the round leaves out is
    /// unaffected. Readiness is still the caller's per-frame decision.
    pub(super) fn round_request_page(
        &mut self,
        cancellation: &CancellationToken,
    ) -> &[BatchCandidateRequest] {
        if self.terminal || self.initialized.cancelled || cancellation.is_cancelled() {
            return &[];
        }
        if !self.fill_request_page(cancellation) {
            return &[];
        }
        self.pending_requests()
    }

    /// The endpoint nodes this frame classifies on its next poll.
    ///
    /// Empty unless the next poll prepares a round; the nodes the operation
    /// already classified are left out, because the frame takes those from the
    /// artifact cache without a statement.
    pub(super) fn round_endpoint_classifications(
        &self,
        artifact_cache: &ForwardCandidateArtifactCache,
        nodes: &mut Vec<BindingNodeId>,
    ) {
        if self.terminal || self.initialized.cancelled || self.round.is_some() {
            return;
        }
        for state in &self.initialized.frontier {
            let node = state.path.end().node();
            if !self.initialized.endpoint_definitions.contains_key(&node)
                && !artifact_cache.endpoint_classifications.contains_key(&node)
            {
                nodes.push(node);
            }
        }
    }

    /// The candidate paths this frame hydrates on its next poll.
    ///
    /// Empty unless the next poll finishes the round; the paths this frame's
    /// arena or the operation's cache already holds are left out.
    pub(super) fn round_candidate_hydrations(
        &self,
        artifact_cache: &ForwardCandidateArtifactCache,
        candidates: &mut Vec<CandidatePathIdentity>,
    ) {
        if self.terminal || self.initialized.cancelled {
            return;
        }
        let Some(round) = &self.round else {
            return;
        };
        if round.request_base != round.expandable.len() {
            return;
        }
        for matched in &round.matches {
            let candidate = matched.candidate();
            if !self.arena.contains_key(&candidate)
                && !artifact_cache.hydrated_paths.contains_key(&candidate)
            {
                candidates.push(candidate);
            }
        }
    }

    fn finish<S: BatchResolutionFragmentSource + ?Sized>(
        &mut self,
        engine: &BatchResolutionEngine<'_, S>,
        cancellation: &CancellationToken,
    ) -> StoreResult<DemandForwardBatchPoll> {
        if self.initialized.cancelled
            && let Some(round) = &self.round
        {
            include_forward_matched_hydrated_completions_after_cancellation(
                &mut self.initialized.seeds,
                &round.expandable,
                &round.matches,
                &self.arena,
                &mut self.accounted_hydrated_completions,
                cancellation,
                &mut self.initialized.completion_work,
            );
        }
        self.terminal = true;
        Ok(DemandForwardBatchPoll::Ready(
            engine.finish_seeded_reference_batch(
                std::mem::take(&mut self.initialized.seeds),
                self.initialized.metrics,
                cancellation,
                self.initialized.cancelled,
                self.initialized.completion_work,
            )?,
        ))
    }

    fn prepare_round<S: BatchResolutionFragmentSource + ?Sized>(
        &mut self,
        engine: &BatchResolutionEngine<'_, S>,
        mut artifact_cache: Option<&mut ForwardCandidateArtifactCache>,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<DemandForwardRound>> {
        let InitializedSeededBatch {
            metrics,
            completion_work,
            frontier,
            seeds,
            endpoint_definitions,
            cancelled,
        } = &mut self.initialized;
        if cancellation.is_cancelled() {
            *cancelled = true;
            return Ok(None);
        }
        if !engine.charge_summary_step() {
            *cancelled = true;
            return Ok(None);
        }
        metrics.worklist_rounds += 1;
        metrics.peak_frontier_paths = metrics.peak_frontier_paths.max(frontier.len());
        crate::profiling::note_with(|| {
            format!(
                "resolution::lexical_round references={:?} round={} frontier_paths={}",
                seeds.iter().map(|seed| seed.reference).collect::<Vec<_>>(),
                metrics.worklist_rounds,
                frontier.len(),
            )
        });

        let current = std::mem::take(frontier);
        let mut unclassified = BTreeSet::new();
        for state in &current {
            if poll_reverse_completion(cancellation, completion_work) {
                *cancelled = true;
                break;
            }
            let node = state.path.end().node();
            if !endpoint_definitions.contains_key(&node) {
                unclassified.insert(node);
            }
        }
        if *cancelled {
            return Ok(None);
        }
        let mut to_classify = Vec::with_capacity(unclassified.len());
        while let Some(node) = unclassified.pop_first() {
            if poll_reverse_completion(cancellation, completion_work) {
                *cancelled = true;
                break;
            }
            to_classify.push(node);
        }
        if *cancelled {
            return Ok(None);
        }
        if !to_classify.is_empty() {
            if !engine.charge_scope_steps(to_classify.len()) {
                *cancelled = true;
                return Ok(None);
            }
            let mut missing = Vec::new();
            if let Some(cache) = artifact_cache.as_deref() {
                for &node in &to_classify {
                    if poll_reverse_completion(cancellation, completion_work) {
                        *cancelled = true;
                        break;
                    }
                    if let Some(&classification) = cache.endpoint_classifications.get(&node) {
                        assert!(
                            endpoint_definitions
                                .insert(
                                    classification.node(),
                                    classification.definition().map(|target| (
                                        target,
                                        classification.go_definition_namespaces()
                                    ))
                                )
                                .is_none(),
                            "an endpoint is classified at most once per batch"
                        );
                        metrics.distinct_endpoint_classifications += 1;
                    } else {
                        missing.push(node);
                    }
                }
            } else {
                missing = to_classify;
            }
            if *cancelled {
                return Ok(None);
            }
            for requested in missing.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
                let classified = engine
                    .source()
                    .classify_endpoint_nodes(requested, cancellation)?;
                if cancellation.is_cancelled() {
                    *cancelled = true;
                    break;
                }
                let Some(classified) = align_endpoint_classifications_with_poll(
                    requested,
                    classified,
                    cancellation,
                    completion_work,
                )?
                else {
                    *cancelled = true;
                    break;
                };
                if let Some(cache) = artifact_cache.as_deref_mut() {
                    if cancellation.is_cancelled() {
                        *cancelled = true;
                        break;
                    }
                    for &classification in &classified {
                        if let Some(previous) = cache
                            .endpoint_classifications
                            .insert(classification.node(), classification)
                        {
                            assert_eq!(
                                previous, classification,
                                "one endpoint node has one immutable selected classification"
                            );
                        }
                    }
                }
                for classification in classified {
                    if poll_reverse_completion(cancellation, completion_work) {
                        *cancelled = true;
                        break;
                    }
                    assert!(
                        endpoint_definitions
                            .insert(
                                classification.node(),
                                classification.definition().map(|target| (
                                    target,
                                    classification.go_definition_namespaces()
                                ))
                            )
                            .is_none(),
                        "an endpoint is classified at most once per batch"
                    );
                    metrics.distinct_endpoint_classifications += 1;
                }
                if *cancelled {
                    break;
                }
            }
            if *cancelled {
                return Ok(None);
            }
            metrics.peak_classified_endpoints = metrics
                .peak_classified_endpoints
                .max(endpoint_definitions.len());
        }

        let mut expandable = Vec::with_capacity(current.len());
        let mut expandable_seed_indices = Vec::with_capacity(current.len());
        for state in current {
            if poll_reverse_completion(cancellation, completion_work) {
                *cancelled = true;
                break;
            }
            if endpoint_is_balanced(state.path.end())
                && let Some((target, namespaces)) = endpoint_definitions
                    .get(&state.path.end().node())
                    .copied()
                    .flatten()
            {
                let seed = &mut seeds[state.seed];
                match classify_completed_binding(
                    seed.go_spelling_namespace,
                    seed.go_package_qualifier,
                    namespaces,
                    target,
                    state.path,
                ) {
                    CompletedBinding::Complete(candidate) => seed.completed.push(candidate),
                    CompletedBinding::Incomplete(terminal) => {
                        seed.incomplete_scope_search = true;
                        seed.terminals.push(terminal);
                    }
                }
            } else {
                expandable_seed_indices.push(state.seed);
                expandable.push(state);
            }
        }
        if *cancelled {
            return Ok(None);
        }
        if expandable.is_empty() {
            return Ok(None);
        }

        Ok(Some(DemandForwardRound {
            expandable,
            expandable_seed_indices,
            terminalized: HashSet::default(),
            matches: Vec::new(),
            request_base: 0,
            request_page: Vec::new(),
        }))
    }

    fn read_page<S: BatchResolutionFragmentSource + ?Sized>(
        &mut self,
        engine: &BatchResolutionEngine<'_, S>,
        artifact_cache: Option<&mut ForwardCandidateArtifactCache>,
        cancellation: &CancellationToken,
    ) -> StoreResult<()> {
        let InitializedSeededBatch {
            completion_work,
            seeds,
            cancelled,
            ..
        } = &mut self.initialized;
        let candidate_completion = &mut self.candidate_completion;
        let round = self.round.as_mut().expect("read page has a prepared round");
        let DemandForwardRound {
            expandable,
            terminalized,
            matches,
            request_base,
            request_page,
            ..
        } = round;
        let request_base = *request_base;
        let state_page = &expandable[request_base..request_base + request_page.len()];
        let (page_matches, unconditional_completion, branch_completions) =
            read_forward_candidate_artifacts(
                engine.source(),
                artifact_cache,
                request_page,
                cancellation,
                engine.resolution_session,
                completion_work,
                cancelled,
            )?;
        for matched in page_matches {
            if poll_reverse_completion(cancellation, completion_work) {
                *cancelled = true;
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
            completion_work,
        )?;
        *cancelled |= completion_cancelled;
        for seed_index in newly_accounted_seeds {
            *cancelled |= seeds[seed_index].completion.include(
                candidate_completion.semantic_completion(),
                cancellation,
                completion_work,
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
                *cancelled |= terminal_completion.include(
                    state.path.completion(),
                    cancellation,
                    completion_work,
                );
                *cancelled |=
                    terminal_completion.include(branch_completion, cancellation, completion_work);
                let (terminal_completion, terminal_cancelled) =
                    terminal_completion.finish_semantic(cancellation, completion_work);
                *cancelled |= terminal_cancelled;
                *cancelled |= seed.observed_completion.include(
                    &terminal_completion,
                    cancellation,
                    completion_work,
                );
                pending_terminals.push((request_ordinal, page_ordinal));
            }
        }
        if cancellation.is_cancelled() {
            *cancelled = true;
        }
        if *cancelled {
            return Ok(());
        }
        for (request_ordinal, page_ordinal) in pending_terminals {
            let state = &expandable[request_ordinal];
            let branch_completion = &branch_completions[page_ordinal];
            let terminal_path = state
                .path
                .clone_with_poll(&mut || poll_reverse_completion(cancellation, completion_work));
            let Some(terminal_path) = terminal_path else {
                *cancelled = true;
                break;
            };
            let terminal_path = terminal_path
                .with_additional_completion_with_poll(branch_completion, &mut || {
                    poll_reverse_completion(cancellation, completion_work)
                });
            let Some(terminal_path) = terminal_path else {
                *cancelled = true;
                break;
            };
            seeds[state.seed]
                .terminals
                .push(IncompleteTerminalPath::new(terminal_path));
            terminalized.insert(request_ordinal);
        }
        if *cancelled {
            return Ok(());
        }
        if *cancelled || cancellation.is_cancelled() {
            *cancelled = true;
            return Ok(());
        }

        Ok(())
    }

    fn finish_round<S: BatchResolutionFragmentSource + ?Sized>(
        &mut self,
        engine: &BatchResolutionEngine<'_, S>,
        round: DemandForwardRound,
        artifact_cache: Option<&mut ForwardCandidateArtifactCache>,
        cancellation: &CancellationToken,
    ) -> StoreResult<()> {
        let InitializedSeededBatch {
            metrics,
            completion_work,
            frontier,
            seeds,
            cancelled,
            ..
        } = &mut self.initialized;
        let arena = &mut self.arena;
        let accounted_hydrated_completions = &mut self.accounted_hydrated_completions;
        let DemandForwardRound {
            expandable,
            expandable_seed_indices,
            terminalized,
            matches,
            ..
        } = round;
        let hydration_request = engine.prepare_forward_hydration(
            ForwardHydrationContext {
                metrics,
                completion_work,
                seeds,
                expandable: &expandable,
                matches: &matches,
                arena,
                accounted_completions: accounted_hydrated_completions,
                cancelled,
            },
            artifact_cache.is_some(),
            cancellation,
        );
        if *cancelled {
            return Ok(());
        }
        engine.hydrate_forward_candidates(
            ForwardHydrationContext {
                metrics,
                completion_work,
                seeds,
                expandable: &expandable,
                matches: &matches,
                arena,
                accounted_completions: accounted_hydrated_completions,
                cancelled,
            },
            &hydration_request,
            artifact_cache,
            cancellation,
        )?;
        if *cancelled {
            return Ok(());
        }
        // Each page is canonicalized request-major, and page bases are
        // increasing, so concatenating pages already restores the exact
        // state-major composition order without an unbounded final sort.
        let mut has_successor = HashSet::default();
        for matched in &matches {
            metrics.composition_attempts += 1;
            if poll_reverse_completion(cancellation, completion_work) {
                *cancelled = true;
                break;
            }
            let parent = &expandable[matched.request_ordinal()];
            let candidate = arena.get(&matched.candidate()).ok_or_else(|| {
                StoreError::new(format!(
                    "candidate {:?} was matched but not hydrated",
                    matched.candidate()
                ))
            })?;
            let composition = parent.path.concatenate_with_poll(candidate, &mut || {
                poll_reverse_completion(cancellation, completion_work)
            });
            let path = match composition {
                None => {
                    *cancelled = true;
                    break;
                }
                Some(Ok(path)) => {
                    metrics.successful_stitches += 1;
                    path
                }
                Some(Err(_)) => continue,
            };
            let path = path.canonicalized_observations_with_poll(&mut || {
                poll_reverse_completion(cancellation, completion_work)
            });
            let Some(path) = path else {
                *cancelled = true;
                break;
            };
            let seed = &mut seeds[parent.seed];
            if accounted_hydrated_completions.insert((parent.seed, matched.candidate())) {
                *cancelled |= seed.observed_completion.include(
                    path.completion(),
                    cancellation,
                    completion_work,
                );
            }
            if *cancelled {
                break;
            }
            let decision = seed.certifier.admit_with_poll(
                &parent.saturation,
                matched.candidate().path(),
                &path,
                &mut || poll_reverse_completion(cancellation, completion_work),
            );
            let Some(decision) = decision else {
                *cancelled = true;
                break;
            };
            match decision {
                SaturationDecision::Expand(saturation) => {
                    has_successor.insert(matched.request_ordinal());
                    frontier.push(BatchWorkPath {
                        seed: parent.seed,
                        path,
                        saturation,
                    });
                }
                SaturationDecision::Subsumed => {
                    has_successor.insert(matched.request_ordinal());
                }
                SaturationDecision::Uncertified(gap) => {
                    seed.incomplete_scope_search = true;
                    has_successor.insert(matched.request_ordinal());
                    let reason = ResolutionIncompleteReason::CyclicExpansion(gap.transition());
                    seed.observed_completion.include_reason(reason);
                    let completion = ResolutionCompletion::incomplete([reason]);
                    let path = path.with_additional_completion_with_poll(&completion, &mut || {
                        poll_reverse_completion(cancellation, completion_work)
                    });
                    let Some(path) = path else {
                        *cancelled = true;
                        break;
                    };
                    seed.terminals.push(IncompleteTerminalPath::new(path));
                }
            }
        }
        if cancellation.is_cancelled() {
            *cancelled = true;
        }
        if *cancelled {
            include_forward_matched_hydrated_completions_after_cancellation(
                seeds,
                &expandable,
                &matches,
                arena,
                accounted_hydrated_completions,
                cancellation,
                completion_work,
            );
            return Ok(());
        }
        for (request_ordinal, state) in expandable.into_iter().enumerate() {
            if poll_reverse_completion(cancellation, completion_work) {
                *cancelled = true;
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
        if *cancelled {
            include_forward_hydrated_completions_for_seed_indices_after_cancellation(
                seeds,
                &expandable_seed_indices,
                &matches,
                arena,
                accounted_hydrated_completions,
                cancellation,
                completion_work,
            );
            return Ok(());
        }
        Ok(())
    }
}

struct ForwardHydrationRequest {
    candidates: Vec<CandidatePathIdentity>,
    seed_owners: HashMap<CandidatePathIdentity, (HashSet<usize>, Vec<usize>)>,
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

#[derive(Debug)]
struct ReverseWorkPath {
    target: usize,
    path: PartialPath,
    saturation: SaturationBranch,
}

#[derive(Debug)]
struct ReverseTargetState {
    completion: BatchCompletionLedger,
    certifier: CycleCompletenessCertifier,
}

struct InitializedReverseCandidateBatch {
    targets: Vec<ReverseTargetState>,
    frontier: Vec<ReverseWorkPath>,
}

enum ReverseCandidateInitialization {
    Ready(InitializedReverseCandidateBatch),
    Cancelled(ReverseCandidateBatch),
}

// Raw reverse counterpart to the forward protocol. This owns one exact target
// batch and exclusion authority; it does not schedule dynamic task SCCs.
pub(super) struct ExperimentalReverseBatchFrame {
    definitions: Vec<(SemanticId, BindingNodeId)>,
    exclusions: ReverseCandidateGapExclusionPlan,
    reverse_target: Option<SemanticId>,
    finalization: ReverseCandidateFinalization,
    frontier: Vec<ReverseWorkPath>,
    frontier_observations: usize,
    endpoint_classifications: HashMap<BindingNodeId, BatchEndpointClassification>,
    arena: HashMap<CandidatePathIdentity, PartialPath>,
    frontier_ids_by_key: HashMap<(usize, DerivationKey), Vec<usize>>,
    lexical_frontier_ids_by_key: HashMap<(usize, DerivationKey), Vec<usize>>,
    accounted_hydrated_completions: HashSet<(usize, CandidatePathIdentity)>,
    candidate_completion: OperationCandidateCompletionLedger,
    round: Option<ExperimentalReverseRound>,
    terminal: bool,
}

struct ExperimentalReverseRound {
    expandable: Vec<ReverseWorkPath>,
    matches: Vec<BatchCandidateMatch>,
    request_base: usize,
    request_page: Vec<BatchCandidateRequest>,
    request_targets: Vec<usize>,
}

/// A readiness key includes direction, exact endpoint, target membership and
/// exclusion authority. Page-local ordinals alone are not global identities.
pub(super) struct ExperimentalReverseCandidatePage<'a> {
    pub(super) requests: &'a [BatchCandidateRequest],
    pub(super) target_indices: &'a [usize],
    pub(super) definitions: &'a [(SemanticId, BindingNodeId)],
    pub(super) exclusions: &'a ReverseCandidateGapExclusionPlan,
}

pub(super) enum ExperimentalReverseBatchStart {
    Running(Box<ExperimentalReverseBatchFrame>),
    Ready(ReverseCandidateBatch),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ExperimentalReverseReadiness {
    /// Exhaustive immutable coverage for these exact reverse keys. As with
    /// forward readiness, a closed key cannot later gain dependencies; dynamic
    /// dependency SCCs need joint closure before this permit can be returned.
    Ready,
    AwaitingDependencies,
}

pub(super) enum ExperimentalReverseBatchPoll {
    Continue,
    AwaitingDependencies,
    Ready(ReverseCandidateBatch),
}

impl ExperimentalReverseBatchFrame {
    pub(super) fn start<S: BatchResolutionFragmentSource + ?Sized>(
        engine: &BatchResolutionEngine<'_, S>,
        definitions: Vec<(SemanticId, BindingNodeId)>,
        exclusions: ReverseCandidateGapExclusionPlan,
        cancellation: &CancellationToken,
    ) -> ExperimentalReverseBatchStart {
        let InitializedReverseCandidateBatch { targets, frontier } =
            match BatchResolutionEngine::<S>::initialize_reverse_candidate_batch(
                &definitions,
                cancellation,
            ) {
                ReverseCandidateInitialization::Ready(initialized) => initialized,
                ReverseCandidateInitialization::Cancelled(answer) => {
                    return ExperimentalReverseBatchStart::Ready(answer);
                }
            };
        let capacity = definitions.len().saturating_mul(4);
        let candidate_completion = OperationCandidateCompletionLedger::new(targets.len());
        ExperimentalReverseBatchStart::Running(Box::new(Self {
            definitions,
            exclusions,
            reverse_target: engine.reverse_target,
            finalization: ReverseCandidateFinalization {
                targets,
                candidates: Vec::new(),
                frontiers: Vec::new(),
                lexical_frontiers: Vec::new(),
                composition_attempts: 0,
                completion_work: 0,
                cancelled: false,
            },
            frontier,
            frontier_observations: 0,
            endpoint_classifications: map_with_capacity(capacity),
            arena: map_with_capacity(capacity),
            frontier_ids_by_key: map_with_capacity(capacity),
            lexical_frontier_ids_by_key: map_with_capacity(capacity),
            accounted_hydrated_completions: HashSet::default(),
            candidate_completion,
            round: None,
            terminal: false,
        }))
    }

    pub(super) fn pending_requests(&self) -> &[BatchCandidateRequest] {
        self.round
            .as_ref()
            .map_or(&[], |round| round.request_page.as_slice())
    }

    pub(super) fn pending_page(&self) -> ExperimentalReverseCandidatePage<'_> {
        ExperimentalReverseCandidatePage {
            requests: self.pending_requests(),
            target_indices: self
                .round
                .as_ref()
                .map_or(&[], |round| round.request_targets.as_slice()),
            definitions: &self.definitions,
            exclusions: &self.exclusions,
        }
    }

    // Reborrow the same selected source/work session on every poll. Exclusive
    // source wrappers retain their own read caches; the readiness gate precedes
    // their complete reverse-candidate entry point, not just its visitor.
    pub(super) fn poll<S: BatchResolutionFragmentSource + ?Sized>(
        &mut self,
        engine: &mut BatchResolutionEngine<'_, S>,
        cancellation: &CancellationToken,
        readiness: &mut impl FnMut(
            ExperimentalReverseCandidatePage<'_>,
        ) -> StoreResult<ExperimentalReverseReadiness>,
    ) -> StoreResult<ExperimentalReverseBatchPoll> {
        assert!(!self.terminal, "a terminal reverse frame cannot resume");
        assert_eq!(
            self.reverse_target, engine.reverse_target,
            "a reverse frame retains its exact target admission authority"
        );
        let result = self.poll_active(engine, cancellation, readiness);
        if result.is_err() {
            self.terminal = true;
        }
        result
    }

    fn poll_active<S: BatchResolutionFragmentSource + ?Sized>(
        &mut self,
        engine: &mut BatchResolutionEngine<'_, S>,
        cancellation: &CancellationToken,
        readiness: &mut impl FnMut(
            ExperimentalReverseCandidatePage<'_>,
        ) -> StoreResult<ExperimentalReverseReadiness>,
    ) -> StoreResult<ExperimentalReverseBatchPoll> {
        if self.finalization.cancelled || cancellation.is_cancelled() {
            self.finalization.cancelled = true;
            return self.finish::<S>(cancellation);
        }
        if self.round.is_none() {
            if self.frontier.is_empty() {
                return self.finish::<S>(cancellation);
            }
            self.round = self.prepare_round(engine, cancellation)?;
            if self.finalization.cancelled {
                return self.finish::<S>(cancellation);
            }
            return Ok(ExperimentalReverseBatchPoll::Continue);
        }
        let round = self.round.as_mut().expect("active reverse round");
        if round.request_base == round.expandable.len() {
            let round = self.round.take().expect("active reverse round");
            self.finish_round(engine, round, cancellation)?;
            if self.finalization.cancelled || self.frontier.is_empty() {
                return self.finish::<S>(cancellation);
            }
            return Ok(ExperimentalReverseBatchPoll::Continue);
        }
        if round.request_page.is_empty() {
            let end = (round.request_base + MAX_SOURCE_ROWS_PER_BATCH).min(round.expandable.len());
            for (ordinal, state) in round.expandable[round.request_base..end].iter().enumerate() {
                let endpoint = state.path.start().clone_with_poll(&mut || {
                    self.frontier_observations = self
                        .frontier_observations
                        .checked_add(1)
                        .expect("reverse request clone work must fit usize");
                    self.frontier_observations
                        .is_multiple_of(CANCELLATION_QUANTUM)
                        && cancellation.is_cancelled()
                });
                let Some(endpoint) = endpoint else {
                    self.finalization.cancelled = true;
                    return self.finish::<S>(cancellation);
                };
                round
                    .request_page
                    .push(BatchCandidateRequest::new(ordinal, endpoint));
                round.request_targets.push(state.target);
            }
        }
        let ready = readiness(self.pending_page())?;
        if cancellation.is_cancelled() {
            self.finalization.cancelled = true;
            return self.finish::<S>(cancellation);
        }
        if ready == ExperimentalReverseReadiness::AwaitingDependencies {
            return Ok(ExperimentalReverseBatchPoll::AwaitingDependencies);
        }
        self.read_page(engine, cancellation)?;
        if self.finalization.cancelled {
            return self.finish::<S>(cancellation);
        }
        let round = self.round.as_mut().expect("read retains reverse round");
        round.request_base += round.request_page.len();
        round.request_page.clear();
        round.request_targets.clear();
        Ok(ExperimentalReverseBatchPoll::Continue)
    }

    fn finish<S: BatchResolutionFragmentSource + ?Sized>(
        &mut self,
        cancellation: &CancellationToken,
    ) -> StoreResult<ExperimentalReverseBatchPoll> {
        let state = &mut self.finalization;
        if state.cancelled
            && let Some(round) = &self.round
        {
            include_matched_hydrated_completions_after_cancellation(
                &mut state.targets,
                &round.expandable,
                &round.matches,
                &self.arena,
                &mut self.accounted_hydrated_completions,
                cancellation,
                &mut state.composition_attempts,
            );
        }
        self.terminal = true;
        BatchResolutionEngine::<S>::finish_reverse_candidate_batch(
            ReverseCandidateFinalization {
                targets: std::mem::take(&mut state.targets),
                candidates: std::mem::take(&mut state.candidates),
                frontiers: std::mem::take(&mut state.frontiers),
                lexical_frontiers: std::mem::take(&mut state.lexical_frontiers),
                completion_work: state.completion_work,
                composition_attempts: state.composition_attempts,
                cancelled: state.cancelled,
            },
            cancellation,
        )
        .map(ExperimentalReverseBatchPoll::Ready)
    }

    fn prepare_round<S: BatchResolutionFragmentSource + ?Sized>(
        &mut self,
        engine: &BatchResolutionEngine<'_, S>,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<ExperimentalReverseRound>> {
        let ReverseCandidateFinalization {
            targets,
            candidates,
            frontiers,
            lexical_frontiers,
            completion_work,
            cancelled,
            ..
        } = &mut self.finalization;
        let definitions = self.definitions.as_slice();
        let frontier = &mut self.frontier;
        let endpoint_classifications = &mut self.endpoint_classifications;
        let frontier_ids_by_key = &mut self.frontier_ids_by_key;
        let lexical_frontier_ids_by_key = &mut self.lexical_frontier_ids_by_key;
        let frontier_observations = &mut self.frontier_observations;
        let current = std::mem::take(frontier);
        engine.classify_reverse_frontiers(ReverseFrontierContext {
            definitions,
            current: &current,
            endpoint_classifications,
            frontiers,
            frontier_ids_by_key,
            lexical_frontiers,
            lexical_frontier_ids_by_key,
            cancellation,
            observations: frontier_observations,
            cancelled,
        })?;
        if *cancelled {
            return Ok(None);
        }
        let mut expandable = Vec::with_capacity(current.len());
        for state in current {
            // Match the established sequential completion fold: a path
            // admitted for expansion contributes once when composed and
            // once when its next worklist state is processed. The second
            // operand deliberately canonicalizes a publicly constructible
            // noncanonical box, while a Subsumed/Uncertified path remains
            // a sole operand.
            *cancelled |= targets[state.target].completion.include(
                state.path.completion(),
                cancellation,
                completion_work,
            );
            let classification = endpoint_classifications
                .get(&state.path.start().node())
                .copied()
                .expect("every current reverse endpoint was classified");
            if endpoint_is_balanced(state.path.start())
                && let Some(reference) = classification.reference()
            {
                if engine.reverse_target == Some(definitions[state.target].0)
                    && !engine.source().admits_reverse_reference(reference)
                {
                    continue;
                }
                candidates.push(ReverseCandidateReference {
                    target: state.target,
                    reference,
                    node: state.path.start().node(),
                });
            } else {
                expandable.push(state);
            }
        }
        if *cancelled {
            return Ok(None);
        }
        if expandable.is_empty() {
            return Ok(None);
        }

        Ok(Some(ExperimentalReverseRound {
            expandable,
            matches: Vec::new(),
            request_base: 0,
            request_page: Vec::new(),
            request_targets: Vec::new(),
        }))
    }

    fn read_page<S: BatchResolutionFragmentSource + ?Sized>(
        &mut self,
        engine: &mut BatchResolutionEngine<'_, S>,
        cancellation: &CancellationToken,
    ) -> StoreResult<()> {
        let ReverseCandidateFinalization {
            targets,
            composition_attempts,
            completion_work,
            cancelled,
            ..
        } = &mut self.finalization;
        let exclusions = &mut self.exclusions;
        let candidate_completion = &mut self.candidate_completion;
        let ExperimentalReverseRound {
            expandable,
            matches,
            request_base,
            request_page,
            ..
        } = self.round.as_mut().expect("prepared reverse page");
        let request_base = *request_base;
        let state_page = &expandable[request_base..request_base + request_page.len()];
        let mut seen_page_matches = HashSet::default();
        let outcome = engine
            .source
            .visit_reverse_candidate_match_pages_with_gap_exclusions(
                request_page,
                exclusions,
                cancellation,
                &mut |page| {
                    append_streamed_candidate_match_page(
                        matches,
                        page,
                        request_base,
                        state_page.len(),
                        &mut seen_page_matches,
                        cancellation,
                        composition_attempts,
                        cancelled,
                    )
                },
            )?;
        let (unconditional_completion, branch_completions) = outcome.into_parts();
        let (newly_accounted_targets, completion_cancelled) = candidate_completion.observe(
            "reverse",
            unconditional_completion,
            state_page.iter().map(|state| state.target),
            cancellation,
            completion_work,
        )?;
        *cancelled |= completion_cancelled;
        for target_index in newly_accounted_targets {
            let inventory_completion = engine
                .source()
                .scope_reverse_inventory_completion(candidate_completion.semantic_completion());
            *cancelled |= targets[target_index].completion.include(
                &inventory_completion,
                cancellation,
                completion_work,
            );
        }
        for (page_ordinal, branch_completion) in branch_completions.iter().enumerate() {
            let request_ordinal = request_base + page_ordinal;
            let target = expandable[request_ordinal].target;
            *cancelled |= targets[target].completion.include(
                branch_completion,
                cancellation,
                completion_work,
            );
        }
        if cancellation.is_cancelled() {
            *cancelled = true;
        }
        if *cancelled {
            return Ok(());
        }
        if *cancelled || cancellation.is_cancelled() {
            *cancelled = true;
            return Ok(());
        }

        Ok(())
    }

    fn finish_round<S: BatchResolutionFragmentSource + ?Sized>(
        &mut self,
        engine: &BatchResolutionEngine<'_, S>,
        round: ExperimentalReverseRound,
        cancellation: &CancellationToken,
    ) -> StoreResult<()> {
        let ReverseCandidateFinalization {
            targets,
            composition_attempts,
            completion_work,
            cancelled,
            ..
        } = &mut self.finalization;
        let frontier = &mut self.frontier;
        let arena = &mut self.arena;
        let accounted_hydrated_completions = &mut self.accounted_hydrated_completions;
        let ExperimentalReverseRound {
            expandable,
            mut matches,
            ..
        } = round;
        if !canonicalize_streamed_candidate_matches(
            &mut matches,
            cancellation,
            composition_attempts,
        )? {
            *cancelled = true;
            include_matched_hydrated_completions_after_cancellation(
                targets,
                &expandable,
                &matches,
                arena,
                accounted_hydrated_completions,
                cancellation,
                composition_attempts,
            );
            return Ok(());
        }

        let mut hydration_set = BTreeSet::new();
        for matched in &matches {
            if poll_reverse_completion(cancellation, composition_attempts) {
                *cancelled = true;
                break;
            }
            if !arena.contains_key(&matched.candidate()) {
                hydration_set.insert(matched.candidate());
            }
        }
        if *cancelled {
            include_matched_hydrated_completions_after_cancellation(
                targets,
                &expandable,
                &matches,
                arena,
                accounted_hydrated_completions,
                cancellation,
                composition_attempts,
            );
            return Ok(());
        }
        let mut to_hydrate = Vec::with_capacity(hydration_set.len());
        while let Some(candidate) = hydration_set.pop_first() {
            if poll_reverse_completion(cancellation, composition_attempts) {
                *cancelled = true;
                break;
            }
            to_hydrate.push(candidate);
        }
        if *cancelled {
            include_matched_hydrated_completions_after_cancellation(
                targets,
                &expandable,
                &matches,
                arena,
                accounted_hydrated_completions,
                cancellation,
                composition_attempts,
            );
            return Ok(());
        }
        if !to_hydrate.is_empty() {
            for requested in to_hydrate.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
                let hydrated = engine
                    .source()
                    .hydrate_candidate_paths(requested, cancellation)?;
                let mut hydration_cancelled = cancellation.is_cancelled();
                if !hydration_cancelled {
                    hydration_cancelled = validate_hydration_with_poll(
                        requested,
                        &hydrated,
                        cancellation,
                        composition_attempts,
                    )?
                    .is_none();
                }
                if hydration_cancelled {
                    include_returned_hydrated_completions_after_cancellation(
                        targets,
                        &expandable,
                        &matches,
                        &hydrated,
                        accounted_hydrated_completions,
                        cancellation,
                        composition_attempts,
                    );
                    include_matched_hydrated_completions_after_cancellation(
                        targets,
                        &expandable,
                        &matches,
                        arena,
                        accounted_hydrated_completions,
                        cancellation,
                        composition_attempts,
                    );
                    *cancelled = true;
                    break;
                }
                for (identity, path) in hydrated {
                    hydration_cancelled |=
                        poll_reverse_completion(cancellation, composition_attempts);
                    assert!(
                        arena.insert(identity, path).is_none(),
                        "a reverse candidate path is hydrated at most once per operation"
                    );
                }
                hydration_cancelled |= cancellation.is_cancelled();
                if hydration_cancelled {
                    include_matched_hydrated_completions_after_cancellation(
                        targets,
                        &expandable,
                        &matches,
                        arena,
                        accounted_hydrated_completions,
                        cancellation,
                        composition_attempts,
                    );
                    *cancelled = true;
                    break;
                }
            }
            if *cancelled {
                return Ok(());
            }
        }

        for matched in &matches {
            *composition_attempts += 1;
            if composition_attempts.is_multiple_of(CANCELLATION_QUANTUM)
                && cancellation.is_cancelled()
            {
                *cancelled = true;
                break;
            }
            let parent = &expandable[matched.request_ordinal()];
            let candidate = arena.get(&matched.candidate()).ok_or_else(|| {
                StoreError::new(format!(
                    "reverse candidate {:?} was matched but not hydrated",
                    matched.candidate()
                ))
            })?;
            let composition = candidate.concatenate_with_poll(&parent.path, &mut || {
                *composition_attempts = composition_attempts
                    .checked_add(1)
                    .expect("reverse path composition work must fit usize");
                composition_attempts.is_multiple_of(CANCELLATION_QUANTUM)
                    && cancellation.is_cancelled()
            });
            let path = match composition {
                None => {
                    *cancelled = true;
                    break;
                }
                Some(Ok(path)) => path,
                Some(Err(_)) => continue,
            };
            let Some(path) = path.canonicalized_observations_with_poll(&mut || {
                *composition_attempts = composition_attempts
                    .checked_add(1)
                    .expect("reverse observation canonicalization work must fit usize");
                composition_attempts.is_multiple_of(CANCELLATION_QUANTUM)
                    && cancellation.is_cancelled()
            }) else {
                *cancelled = true;
                break;
            };
            let target = &mut targets[parent.target];
            *cancelled |=
                target
                    .completion
                    .include(path.completion(), cancellation, completion_work);
            accounted_hydrated_completions.insert((parent.target, matched.candidate()));
            if *cancelled {
                break;
            }
            let decision = target.certifier.admit_with_poll(
                &parent.saturation,
                matched.candidate().path(),
                &path,
                &mut || {
                    *composition_attempts = composition_attempts
                        .checked_add(1)
                        .expect("reverse cycle certification work must fit usize");
                    composition_attempts.is_multiple_of(CANCELLATION_QUANTUM)
                        && cancellation.is_cancelled()
                },
            );
            let Some(decision) = decision else {
                *cancelled = true;
                break;
            };
            match decision {
                SaturationDecision::Expand(saturation) => frontier.push(ReverseWorkPath {
                    target: parent.target,
                    path,
                    saturation,
                }),
                SaturationDecision::Subsumed => {}
                SaturationDecision::Uncertified(gap) => {
                    target
                        .completion
                        .include_reason(ResolutionIncompleteReason::CyclicExpansion(
                            gap.transition(),
                        ));
                }
            }
        }
        if cancellation.is_cancelled() {
            *cancelled = true;
        }
        if *cancelled {
            include_matched_hydrated_completions_after_cancellation(
                targets,
                &expandable,
                &matches,
                arena,
                accounted_hydrated_completions,
                cancellation,
                composition_attempts,
            );
            return Ok(());
        }
        Ok(())
    }
}

struct ReverseFrontierContext<'a> {
    definitions: &'a [(SemanticId, BindingNodeId)],
    current: &'a [ReverseWorkPath],
    endpoint_classifications: &'a mut HashMap<BindingNodeId, BatchEndpointClassification>,
    frontiers: &'a mut Vec<ReverseCandidateFrontier>,
    frontier_ids_by_key: &'a mut HashMap<(usize, DerivationKey), Vec<usize>>,
    lexical_frontiers: &'a mut Vec<ReverseCandidateLexicalFrontier>,
    lexical_frontier_ids_by_key: &'a mut HashMap<(usize, DerivationKey), Vec<usize>>,
    cancellation: &'a CancellationToken,
    observations: &'a mut usize,
    cancelled: &'a mut bool,
}

struct ReverseCandidateFinalization {
    candidates: Vec<ReverseCandidateReference>,
    frontiers: Vec<ReverseCandidateFrontier>,
    lexical_frontiers: Vec<ReverseCandidateLexicalFrontier>,
    targets: Vec<ReverseTargetState>,
    completion_work: usize,
    composition_attempts: usize,
    cancelled: bool,
}

/// One candidate direction's operation-wide completion and per-answer owners.
///
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

    if reasons.is_shared() {
        let mut poll = || {
            cancellation_observed |= poll_reverse_completion(cancellation, work);
            false
        };
        let returned_cancelled = reasons
            .contains_with_poll(&ResolutionIncompleteReason::Cancelled, &mut poll)
            .expect("observational completion membership never aborts evidence retention");
        if !returned_cancelled {
            return (
                ResolutionCompletion::Incomplete(reasons),
                false,
                cancellation_observed | cancellation.is_cancelled(),
            );
        }
        let filtered = reasons
            .without_reasons_with_poll([ResolutionIncompleteReason::Cancelled], &mut poll)
            .expect("observational completion filtering never aborts evidence retention");
        let semantic = filtered
            .map(ResolutionCompletion::Incomplete)
            .unwrap_or(ResolutionCompletion::Complete);
        return (
            semantic,
            true,
            cancellation_observed | cancellation.is_cancelled(),
        );
    }

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
        (ResolutionCompletion::Incomplete(left), ResolutionCompletion::Incomplete(right))
            if !left.is_shared() && !right.is_shared() =>
        {
            let mut equal = left.len() == right.len();
            for (index, right) in right.iter().enumerate() {
                cancellation_observed |= poll_reverse_completion(cancellation, work);
                equal &= left.get(index) == Some(right);
            }
            equal
        }
        (ResolutionCompletion::Incomplete(left), ResolutionCompletion::Incomplete(right)) => {
            let mut poll = || {
                cancellation_observed |= poll_reverse_completion(cancellation, work);
                false
            };
            left.equals_with_poll(right, &mut poll)
                .expect("observational completion equality polling never aborts")
        }
        (ResolutionCompletion::Complete, ResolutionCompletion::Incomplete(reasons))
        | (ResolutionCompletion::Incomplete(reasons), ResolutionCompletion::Complete) => {
            if reasons.is_shared() {
                let completion = ResolutionCompletion::Incomplete(reasons.clone());
                let _ = observational_clone_completion(
                    &completion,
                    cancellation,
                    work,
                    &mut cancellation_observed,
                );
            } else {
                for _ in reasons.iter() {
                    cancellation_observed |= poll_reverse_completion(cancellation, work);
                }
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
        if !reasons.is_shared() {
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
            return if canonical.is_empty() {
                ResolutionCompletion::Complete
            } else {
                ResolutionCompletion::Incomplete(canonical.into_iter().collect::<Vec<_>>().into())
            };
        }

        assert!(
            !reasons.contains(&ResolutionIncompleteReason::Cancelled),
            "candidate semantic completion must exclude operational cancellation"
        );
        let mut poll = || {
            cancellation_observed |= poll_reverse_completion(cancellation, work);
            false
        };
        let filtered = reasons
            .without_reasons_with_poll([ResolutionIncompleteReason::Cancelled], &mut poll)
            .expect("observational completion filtering never aborts evidence retention");
        let Some(filtered) = filtered else {
            return ResolutionCompletion::Complete;
        };
        let canonical = filtered
            .union_with_poll(&filtered, &mut poll)
            .expect("observational completion union never aborts evidence retention");
        ResolutionCompletion::Incomplete(canonical)
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
/// the cancellation token is polled observationally. Factored boxes retain
/// their shared base and poll only the handle and sparse deltas; cancellation
/// can suppress unpublished rows, but it cannot truncate semantic evidence
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
    Shared(CompletionReasonUnion),
}

fn raw_completion(reasons: Vec<ResolutionIncompleteReason>) -> ResolutionCompletion {
    ResolutionCompletion::Incomplete(reasons.into_boxed_slice().into())
}

fn observational_clone_completion(
    completion: &ResolutionCompletion,
    cancellation: &CancellationToken,
    work: &mut usize,
    cancellation_observed: &mut bool,
) -> ResolutionCompletion {
    let mut poll = || {
        *cancellation_observed |= poll_reverse_completion(cancellation, work);
        false
    };
    clone_completion_with_poll(completion, &mut poll)
        .expect("observational completion cloning never aborts evidence retention")
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

        if incoming.is_shared() || matches!(&self.state, BatchCompletionState::Shared(_)) {
            let state = std::mem::take(&mut self.state);
            let mut poll = || {
                cancellation_observed |= poll_reverse_completion(cancellation, work);
                false
            };
            let reasons = match state {
                BatchCompletionState::Shared(mut reasons) => {
                    // A reverse target can accumulate thousands of sparse
                    // path gaps. Mutate only the incoming operand; rebuilding
                    // the accumulated additions on every path is quadratic.
                    reasons
                        .include_with_poll(incoming, &mut poll)
                        .expect("observational completion polling cannot abort evidence retention");
                    reasons
                }
                raw => {
                    let mut reasons = CompletionReasonUnion::from_shared_with_poll(
                        incoming, &mut poll,
                    )
                    .expect("observational completion polling cannot abort evidence retention");
                    let (first, additional) = match raw {
                        BatchCompletionState::Complete => (Vec::new(), Vec::new()),
                        BatchCompletionState::Single(first) => (first, Vec::new()),
                        BatchCompletionState::Multiple { first, additional } => (first, additional),
                        BatchCompletionState::Shared(_) => unreachable!("shared state was handled"),
                    };
                    for reason in first.into_iter().chain(additional) {
                        reasons.include_reason_with_poll(reason, &mut poll).expect(
                            "observational completion polling cannot abort evidence retention",
                        );
                    }
                    reasons
                }
            };
            cancellation_observed |= reasons
                .contains_with_poll(&ResolutionIncompleteReason::Cancelled, &mut || {
                    cancellation_observed |= poll_reverse_completion(cancellation, work);
                    false
                })
                .expect("observational membership polling cannot abort evidence retention");
            self.state = BatchCompletionState::Shared(reasons);
            self.cancellation_observed |= cancellation_observed | cancellation.is_cancelled();
            return self.cancellation_observed;
        }

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
            BatchCompletionState::Shared(_) => {
                unreachable!("shared completion operands use the factored union")
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
            BatchCompletionState::Shared(mut existing) => {
                existing
                    .include_reason_with_poll(reason, &mut || false)
                    .expect("non-cancellable completion union cannot abort");
                BatchCompletionState::Shared(existing)
            }
        };
        self.cancellation_observed |= reason == ResolutionIncompleteReason::Cancelled;
    }

    pub(super) fn is_complete(&self) -> bool {
        matches!(self.state, BatchCompletionState::Complete) && !self.cancellation_observed
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
            BatchCompletionState::Shared(reasons) => {
                let reasons = reasons
                    .finish_with_poll(&mut || {
                        cancellation_observed |= poll_reverse_completion(cancellation, work);
                        false
                    })
                    .expect("observational completion polling cannot abort evidence retention");
                return (
                    ResolutionCompletion::Incomplete(reasons),
                    cancellation_observed | cancellation.is_cancelled(),
                );
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
        if matches!(&completion, ResolutionCompletion::Incomplete(reasons) if reasons.is_shared()) {
            let completion = observational_combine_completion(
                &completion,
                &raw_completion(vec![ResolutionIncompleteReason::Cancelled]),
                cancellation,
                work,
                &mut cancellation_observed,
            );
            return (completion, cancellation_observed);
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
/// fallback. Shared source evidence retains its factored base. Empty operands
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
    Shared(CompletionReasonUnion),
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
            if incoming.is_shared() || matches!(&self.state, CancellationEvidenceState::Shared(_)) {
                let state = std::mem::take(&mut self.state);
                let reasons = match state {
                    CancellationEvidenceState::Raw(raw) => {
                        let mut reasons = {
                            let mut poll = || {
                                cancellation_observed |=
                                    poll_reverse_completion(cancellation, work);
                                false
                            };
                            CompletionReasonUnion::from_shared_with_poll(incoming, &mut poll)
                                .expect(
                                    "observational completion polling cannot abort evidence retention",
                                )
                        };
                        for reason in raw {
                            cancellation_observed |= poll_reverse_completion(cancellation, work);
                            cancellation_observed |=
                                reason == ResolutionIncompleteReason::Cancelled;
                            reasons
                                .include_reason_with_poll(reason, &mut || false)
                                .expect("observational completion polling cannot abort evidence retention");
                        }
                        reasons
                    }
                    CancellationEvidenceState::Shared(mut reasons) => {
                        let mut poll = || {
                            cancellation_observed |= poll_reverse_completion(cancellation, work);
                            false
                        };
                        reasons.include_with_poll(incoming, &mut poll).expect(
                            "observational completion polling cannot abort evidence retention",
                        );
                        reasons
                    }
                };
                let mut poll = || {
                    cancellation_observed |= poll_reverse_completion(cancellation, work);
                    false
                };
                cancellation_observed |= reasons
                    .contains_with_poll(&ResolutionIncompleteReason::Cancelled, &mut poll)
                    .expect("observational membership polling cannot abort evidence retention");
                self.state = CancellationEvidenceState::Shared(reasons);
            } else if let CancellationEvidenceState::Raw(reasons) = &mut self.state {
                for &reason in incoming.iter() {
                    cancellation_observed |= poll_reverse_completion(cancellation, work);
                    cancellation_observed |= reason == ResolutionIncompleteReason::Cancelled;
                    reasons.insert(reason);
                }
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
            CancellationEvidenceState::Shared(mut existing) => {
                existing
                    .include_reason_with_poll(reason, &mut || false)
                    .expect("non-cancellable completion union cannot abort");
                CancellationEvidenceState::Shared(existing)
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

    pub(super) fn absorb(
        &mut self,
        mut other: Self,
        cancellation: &CancellationToken,
        work: &mut usize,
    ) -> bool {
        self.cancellation_observed |= other.cancellation_observed | cancellation.is_cancelled();
        let left = std::mem::take(&mut self.state);
        let right = std::mem::take(&mut other.state);
        self.state = match (left, right) {
            (
                CancellationEvidenceState::Raw(mut left),
                CancellationEvidenceState::Raw(mut right),
            ) => {
                while let Some(reason) = right.pop_first() {
                    self.cancellation_observed |= poll_reverse_completion(cancellation, work);
                    self.cancellation_observed |= reason == ResolutionIncompleteReason::Cancelled;
                    left.insert(reason);
                }
                CancellationEvidenceState::Raw(left)
            }
            (
                CancellationEvidenceState::Shared(mut left),
                CancellationEvidenceState::Shared(right),
            ) => {
                let right = right
                    .finish_with_poll(&mut || {
                        self.cancellation_observed |= poll_reverse_completion(cancellation, work);
                        false
                    })
                    .expect("observational completion polling cannot abort evidence retention");
                left.include_with_poll(&right, &mut || {
                    self.cancellation_observed |= poll_reverse_completion(cancellation, work);
                    false
                })
                .expect("observational completion polling cannot abort evidence retention");
                CancellationEvidenceState::Shared(left)
            }
            (
                CancellationEvidenceState::Shared(mut left),
                CancellationEvidenceState::Raw(right),
            ) => {
                for reason in right {
                    self.cancellation_observed |= poll_reverse_completion(cancellation, work);
                    self.cancellation_observed |= reason == ResolutionIncompleteReason::Cancelled;
                    left.include_reason_with_poll(reason, &mut || false)
                        .expect("observational completion polling cannot abort evidence retention");
                }
                CancellationEvidenceState::Shared(left)
            }
            (
                CancellationEvidenceState::Raw(left),
                CancellationEvidenceState::Shared(mut right),
            ) => {
                for reason in left {
                    self.cancellation_observed |= poll_reverse_completion(cancellation, work);
                    self.cancellation_observed |= reason == ResolutionIncompleteReason::Cancelled;
                    right
                        .include_reason_with_poll(reason, &mut || false)
                        .expect("observational completion polling cannot abort evidence retention");
                }
                CancellationEvidenceState::Shared(right)
            }
        };
        self.cancellation_observed |= cancellation.is_cancelled();
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
            CancellationEvidenceState::Shared(mut reasons) => {
                if cancellation_observed {
                    reasons
                        .include_reason_with_poll(
                            ResolutionIncompleteReason::Cancelled,
                            &mut || {
                                cancellation_observed |=
                                    poll_reverse_completion(cancellation, work);
                                false
                            },
                        )
                        .expect("observational completion polling cannot abort evidence retention");
                }
                let reasons = reasons
                    .finish_with_poll(&mut || {
                        cancellation_observed |= poll_reverse_completion(cancellation, work);
                        false
                    })
                    .expect("observational completion polling cannot abort evidence retention");
                ResolutionCompletion::Incomplete(reasons)
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

fn include_cancelled_in_finished_completion(
    completion: &mut ResolutionCompletion,
    cancellation: &CancellationToken,
    work: &mut usize,
) {
    let current = std::mem::replace(completion, ResolutionCompletion::Complete);
    *completion = match current {
        ResolutionCompletion::Complete => ResolutionCompletion::Incomplete(
            vec![ResolutionIncompleteReason::Cancelled]
                .into_boxed_slice()
                .into(),
        ),
        ResolutionCompletion::Incomplete(reasons) if reasons.is_shared() => {
            let completion = ResolutionCompletion::Incomplete(reasons);
            let mut poll = || {
                let _ = poll_reverse_completion(cancellation, work);
                false
            };
            combine_completion_with_poll(
                &completion,
                &raw_completion(vec![ResolutionIncompleteReason::Cancelled]),
                &mut poll,
            )
            .expect("non-cancellable completion union cannot abort")
        }
        ResolutionCompletion::Incomplete(reasons)
            if reasons.get(0) == Some(&ResolutionIncompleteReason::Cancelled) =>
        {
            ResolutionCompletion::Incomplete(reasons)
        }
        ResolutionCompletion::Incomplete(reasons) => {
            let mut canonical = BTreeSet::new();
            canonical.insert(ResolutionIncompleteReason::Cancelled);
            for reason in reasons.into_vec() {
                let _ = poll_reverse_completion(cancellation, work);
                canonical.insert(reason);
            }
            let mut cancelled = Vec::with_capacity(canonical.len());
            while let Some(reason) = canonical.pop_first() {
                let _ = poll_reverse_completion(cancellation, work);
                cancelled.push(reason);
            }
            ResolutionCompletion::Incomplete(cancelled.into_boxed_slice().into())
        }
    };
}

/// A reverse-generated reference and the target traversal that reached it.
///
/// The public operation has one target today. Keeping the target ordinal on
/// candidate references lets a future multi-target operation deduplicate the
/// forward validation by reference without losing target membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ReverseCandidateReference {
    target: usize,
    reference: SemanticId,
    node: BindingNodeId,
}

impl ReverseCandidateReference {
    pub(super) const fn target(self) -> usize {
        self.target
    }

    pub(super) const fn reference(self) -> SemanticId {
        self.reference
    }

    pub(super) const fn node(self) -> BindingNodeId {
        self.node
    }
}

/// One exact reverse path at a source-classified member-scope endpoint where a
/// typed seeded route may join.
///
/// Only the full start signature is retained. Raw target completion is
/// accumulated separately, and both outer endpoints are balanced, so typed
/// narrowing needs only the exact middle-endpoint stack unification. Raw
/// reverse traversal keeps expanding after emitting this row.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct ReverseCandidateFrontier {
    target: usize,
    owner: SemanticId,
    start: EndpointSignature,
}

impl ReverseCandidateFrontier {
    pub(super) const fn target(&self) -> usize {
        self.target
    }

    pub(super) const fn owner(&self) -> SemanticId {
        self.owner
    }

    pub(super) const fn start(&self) -> &EndpointSignature {
        &self.start
    }

    pub(super) fn into_parts(self) -> (usize, SemanticId, EndpointSignature) {
        (self.target, self.owner, self.start)
    }
}

/// A raw reverse continuation without a typed member owner. This is an exact
/// source-coordinate completion seam, not a typed member candidate. Lexical
/// expansion continues normally after retaining its full endpoint signature.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct ReverseCandidateLexicalFrontier {
    target: usize,
    start: EndpointSignature,
}

impl ReverseCandidateLexicalFrontier {
    #[cfg(test)]
    pub(super) const fn target(&self) -> usize {
        self.target
    }

    #[cfg(test)]
    pub(super) const fn start(&self) -> &EndpointSignature {
        &self.start
    }

    pub(super) fn into_parts(self) -> (usize, EndpointSignature) {
        (self.target, self.start)
    }
}

fn reverse_frontier_key_with_poll<P>(
    target: usize,
    endpoint: &EndpointSignature,
    cancelled: &mut P,
) -> Option<DerivationKey>
where
    P: FnMut() -> bool,
{
    let mut hasher = CanonicalHasher::new(b"bifrost-resolution-reverse-frontier-key:v1");
    hasher.field("target", &(target as u64).to_le_bytes());
    hasher.field("node", &endpoint.node().as_bytes());
    hasher.field(
        "symbol-count",
        &(endpoint.symbols().fixed().len() as u64).to_le_bytes(),
    );
    for (index, symbol) in endpoint.symbols().fixed().iter().enumerate() {
        if cancelled() {
            return None;
        }
        hasher.field(&format!("symbol-{index}"), &symbol.symbol().as_bytes());
        match symbol.scopes() {
            Some(scopes) => {
                hasher.field(&format!("symbol-{index}-scope-kind"), b"scoped");
                hash_scope_stack_with_poll(
                    &mut hasher,
                    &format!("symbol-{index}-scope"),
                    scopes,
                    cancelled,
                )?;
            }
            None => hasher.field(&format!("symbol-{index}-scope-kind"), b"unscoped"),
        }
    }
    match endpoint.symbols().tail() {
        Some(tail) => hasher.field("symbol-tail", &tail.as_bytes()),
        None => hasher.field("symbol-tail", b"closed"),
    }
    hash_scope_stack_with_poll(&mut hasher, "scope", endpoint.scopes(), cancelled)?;
    Some(DerivationKey::new(hasher.finish()))
}

fn hash_scope_stack_with_poll<P>(
    hasher: &mut CanonicalHasher,
    prefix: &str,
    scopes: &StackPattern<BindingNodeId>,
    cancelled: &mut P,
) -> Option<()>
where
    P: FnMut() -> bool,
{
    hasher.field(
        &format!("{prefix}-count"),
        &(scopes.fixed().len() as u64).to_le_bytes(),
    );
    for (index, scope) in scopes.fixed().iter().enumerate() {
        if cancelled() {
            return None;
        }
        hasher.field(&format!("{prefix}-{index}"), &scope.as_bytes());
    }
    match scopes.tail() {
        Some(tail) => hasher.field(&format!("{prefix}-tail"), &tail.as_bytes()),
        None => hasher.field(&format!("{prefix}-tail"), b"closed"),
    }
    Some(())
}

fn include_matched_hydrated_completions_after_cancellation(
    targets: &mut [ReverseTargetState],
    expandable: &[ReverseWorkPath],
    matches: &[BatchCandidateMatch],
    arena: &crate::hash::HashMap<CandidatePathIdentity, PartialPath>,
    accounted: &mut crate::hash::HashSet<(usize, CandidatePathIdentity)>,
    cancellation: &CancellationToken,
    work: &mut usize,
) {
    for matched in matches {
        *work = work
            .checked_add(1)
            .expect("cancelled hydrated-match merge work must fit usize");
        if work.is_multiple_of(CANCELLATION_QUANTUM) {
            let _ = cancellation.is_cancelled();
        }
        if matched.request_ordinal() >= expandable.len() {
            // Cancellation evidence wins over malformed unpublished match
            // rows, but cleanup must never index an unvalidated ordinal.
            continue;
        }
        let target = expandable[matched.request_ordinal()].target;
        let key = (target, matched.candidate());
        if accounted.contains(&key) {
            continue;
        }
        let Some(candidate) = arena.get(&matched.candidate()) else {
            continue;
        };
        let _ = targets[target]
            .completion
            .include(candidate.completion(), cancellation, work);
        accounted.insert(key);
    }
}

fn include_returned_hydrated_completions_after_cancellation(
    targets: &mut [ReverseTargetState],
    expandable: &[ReverseWorkPath],
    matches: &[BatchCandidateMatch],
    hydrated: &[(CandidatePathIdentity, PartialPath)],
    accounted: &mut crate::hash::HashSet<(usize, CandidatePathIdentity)>,
    cancellation: &CancellationToken,
    work: &mut usize,
) {
    for (identity, candidate) in hydrated {
        for matched in matches {
            let _ = poll_reverse_completion(cancellation, work);
            if matched.candidate() != *identity {
                continue;
            }
            let target = expandable[matched.request_ordinal()].target;
            if accounted.insert((target, *identity)) {
                let _ =
                    targets[target]
                        .completion
                        .include(candidate.completion(), cancellation, work);
            }
        }
    }
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

fn canonicalize_reverse_candidates(
    candidates: Vec<ReverseCandidateReference>,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> StoreResult<Option<Vec<ReverseCandidateReference>>> {
    let mut candidate_nodes = map_with_capacity(candidates.len());
    let mut canonical = BTreeSet::new();
    for candidate in candidates {
        *work = work
            .checked_add(1)
            .expect("reverse candidate canonicalization work must fit usize");
        if (*work).is_multiple_of(CANCELLATION_QUANTUM) && cancellation.is_cancelled() {
            return Ok(None);
        }
        if let Some(existing) = candidate_nodes.get(&candidate.reference) {
            if *existing != candidate.node {
                return Err(StoreError::new(format!(
                    "reverse candidate semantic {} names multiple endpoint nodes: {} and {}",
                    candidate.reference, existing, candidate.node
                )));
            }
        } else {
            candidate_nodes.insert(candidate.reference, candidate.node);
        }
        canonical.insert(candidate);
    }

    let mut candidates = Vec::with_capacity(canonical.len());
    while let Some(candidate) = canonical.pop_first() {
        *work = work
            .checked_add(1)
            .expect("reverse candidate publication work must fit usize");
        if (*work).is_multiple_of(CANCELLATION_QUANTUM) && cancellation.is_cancelled() {
            return Ok(None);
        }
        candidates.push(candidate);
    }
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    Ok(Some(candidates))
}

#[allow(clippy::too_many_arguments)]
fn append_streamed_candidate_match_page(
    matches: &mut Vec<BatchCandidateMatch>,
    page: &[BatchCandidateMatch],
    request_base: usize,
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
            request_base + matched.request_ordinal(),
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

fn returned_completion_observes_cancellation(
    completion: &ResolutionCompletion,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> bool {
    let mut observed = cancellation.is_cancelled();
    observed |= poll_reverse_completion(cancellation, work);
    if let ResolutionCompletion::Incomplete(reasons) = completion {
        if reasons.is_shared() {
            let mut poll = || {
                observed |= poll_reverse_completion(cancellation, work);
                false
            };
            let contains_cancelled = reasons
                .contains_with_poll(&ResolutionIncompleteReason::Cancelled, &mut poll)
                .expect("observational completion membership never aborts");
            observed |= contains_cancelled;
        } else {
            for &reason in reasons.iter() {
                observed |= poll_reverse_completion(cancellation, work);
                observed |= reason == ResolutionIncompleteReason::Cancelled;
            }
        }
    }
    observed | cancellation.is_cancelled()
}

pub(super) fn read_forward_candidate_artifacts<S: BatchResolutionFragmentSource + ?Sized>(
    source: &S,
    artifact_cache: Option<&mut ForwardCandidateArtifactCache>,
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
    let mut hit_requests = Vec::new();
    let mut missing = Vec::new();
    let mut missing_to_requests = Vec::<Vec<usize>>::new();
    let mut missing_by_endpoint = HashMap::<EndpointSignature, usize>::default();
    let mut unconditional = None;

    if let Some(cache) = artifact_cache.as_deref() {
        if let Some(cached) = cache.unconditional_completion.as_ref() {
            unconditional = Some(copy_returned_completion(
                cached,
                cancellation,
                resolution_session,
                work,
                cancelled,
            ));
        }
        for (request_ordinal, request) in requests.iter().enumerate() {
            *cancelled |= poll_reverse_completion(cancellation, work);
            if let Some(cached) = cache.endpoint_matches.get(request.endpoint()) {
                // A cache hit is an already returned immutable source
                // operand. Retain its entire branch box before any
                // cancellable candidate replay so an interrupted hit cannot
                // substitute `Complete` for evidence that crossed the source
                // boundary in an earlier round.
                let branch_completion = copy_returned_completion(
                    &cached.branch_completion,
                    cancellation,
                    resolution_session,
                    work,
                    cancelled,
                );
                branch_completions[request_ordinal] = Some(branch_completion);
                if !*cancelled {
                    hit_requests.push(request_ordinal);
                }
            } else {
                if *cancelled {
                    continue;
                }
                let Some(endpoint) = request
                    .endpoint()
                    .clone_with_poll(&mut || poll_reverse_completion(cancellation, work))
                else {
                    *cancelled = true;
                    continue;
                };
                if let Some(&missing_ordinal) = missing_by_endpoint.get(&endpoint) {
                    missing_to_requests[missing_ordinal].push(request_ordinal);
                } else {
                    let Some(endpoint_key) = endpoint
                        .clone_with_poll(&mut || poll_reverse_completion(cancellation, work))
                    else {
                        *cancelled = true;
                        continue;
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
        }
    } else {
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
    }

    // Every hit branch and the source-wide cached operand are retained above.
    // Candidate identities may now be replayed without risking evidence loss
    // if cancellation wins partway through an arbitrarily wide match list.
    if !*cancelled && let Some(cache) = artifact_cache.as_deref() {
        for &request_ordinal in &hit_requests {
            let cached = cache
                .endpoint_matches
                .get(requests[request_ordinal].endpoint())
                .expect("a classified cache hit remains immutable for the operation");
            for &candidate in cached.candidates.iter() {
                if resolution_session.is_some_and(|session| !session.scope_step()) {
                    *cancelled = true;
                    break;
                }
                if poll_reverse_completion(cancellation, work) {
                    *cancelled = true;
                    break;
                }
                candidates_by_request[request_ordinal].push(candidate);
            }
            if *cancelled {
                break;
            }
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
    let mut source_unconditional = None;
    let mut source_branches: Box<[ResolutionCompletion]> = Box::new([]);
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
                    0,
                    missing.len(),
                    &mut seen_page_matches,
                    cancellation,
                    work,
                    cancelled,
                )
            },
        )?;
        let (returned_unconditional, branches) = outcome.into_parts();
        source_branches = branches;
        assert_eq!(source_branches.len(), missing.len());

        // The completion outcome is atomic even if row visitation stopped.
        // Drain every returned box in full before touching affirmative rows.
        // Cancellation is observational during these copies: it suppresses
        // rows/cache publication but cannot truncate returned evidence.
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

        if let Some(cached) = unconditional.take() {
            assert_candidate_unconditional_completions_agree(
                &cached,
                &copied_unconditional,
                cancellation,
                resolution_session,
                work,
                cancelled,
            )?;
        }
        unconditional = Some(copied_unconditional);
        source_unconditional = Some(returned_unconditional);

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
            "cached forward endpoint matches require cached unconditional evidence"
        );
        ResolutionCompletion::Complete
    });

    if !*cancelled
        && !cancellation.is_cancelled()
        && !missing.is_empty()
        && artifact_cache.is_some()
    {
        let mut staged = Vec::with_capacity(missing.len());
        for (missing_ordinal, request) in missing.iter().enumerate() {
            if poll_reverse_completion(cancellation, work) {
                *cancelled = true;
                break;
            }
            let request_ordinal = missing_to_requests[missing_ordinal][0];
            let Some(endpoint) = request
                .endpoint()
                .clone_with_poll(&mut || poll_reverse_completion(cancellation, work))
            else {
                *cancelled = true;
                break;
            };
            let mut candidates = Vec::with_capacity(candidates_by_request[request_ordinal].len());
            for &candidate in &candidates_by_request[request_ordinal] {
                if poll_reverse_completion(cancellation, work) {
                    *cancelled = true;
                    break;
                }
                candidates.push(candidate);
            }
            if *cancelled {
                break;
            }
            let branch_completion = copy_returned_completion(
                &source_branches[missing_ordinal],
                cancellation,
                resolution_session,
                work,
                cancelled,
            );
            if *cancelled {
                break;
            }
            staged.push((
                endpoint,
                CachedForwardEndpointMatch {
                    candidates: candidates.into_boxed_slice(),
                    branch_completion,
                },
            ));
        }
        if !*cancelled
            && !cancellation.is_cancelled()
            && let Some(cache) = artifact_cache
        {
            if cache.unconditional_completion.is_none() {
                cache.unconditional_completion = source_unconditional;
            }
            for (endpoint, cached) in staged {
                assert!(
                    cache.endpoint_matches.insert(endpoint, cached).is_none(),
                    "one missing endpoint artifact is published once"
                );
            }
        }
    }
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

/// One operation-local forward candidate source returns one unconditional
/// completion for every read it answers.
///
/// The source-wide completion is one stable operand across pages and worklist
/// rounds. A cancelled repeat may add only the operational `Cancelled` marker
/// and may canonicalize its semantic reasons; validate that identity without
/// short-circuiting on the token.
fn assert_candidate_unconditional_completions_agree(
    cached: &ResolutionCompletion,
    returned: &ResolutionCompletion,
    cancellation: &CancellationToken,
    resolution_session: Option<&ResolutionSession>,
    work: &mut usize,
    cancelled: &mut bool,
) -> StoreResult<()> {
    let cached_for_comparison =
        copy_returned_completion(cached, cancellation, resolution_session, work, cancelled);
    let returned_for_comparison =
        copy_returned_completion(returned, cancellation, resolution_session, work, cancelled);
    let (cached_semantic, cached_returned_cancelled, cached_observed) =
        split_candidate_unconditional_completion(cached_for_comparison, cancellation, work);
    let (returned_semantic, returned_cancelled, returned_observed) =
        split_candidate_unconditional_completion(returned_for_comparison, cancellation, work);
    *cancelled |= cached_observed | returned_observed;
    assert!(
        !cached_returned_cancelled,
        "cancelled candidate outcomes are never published in the artifact cache"
    );
    let (consistent, comparison_observed) = if returned_cancelled {
        candidate_completion_reason_sets_equal(
            &cached_semantic,
            &returned_semantic,
            cancellation,
            work,
        )
    } else {
        candidate_completions_exactly_equal(
            &cached_semantic,
            &returned_semantic,
            cancellation,
            work,
        )
    };
    *cancelled |= comparison_observed;
    if !consistent {
        return Err(StoreError::new(format!(
            "one operation-local forward candidate source returned conflicting unconditional completions: cached {cached_semantic:?}, repeated {returned_semantic:?}, repeated_cancelled={returned_cancelled}"
        )));
    }
    Ok(())
}

/// Read one scheduler round's union of endpoint keys in one statement set.
///
/// Every frame of a round asks the same statement for its own one or two
/// keys, so the round's whole width is spent one key at a time. This issues
/// that statement once for the union and publishes the rows to the operation's
/// artifact cache, which is where each frame's own poll then finds its own
/// keys. The frame keeps its readiness gate, its per-key scope charges and its
/// cancellation retention: only the statement is shared, and no frame's answer
/// is built from another frame's rows.
///
/// Nothing here charges the session. The frames charge for the keys they
/// contributed when they replay them, so a merged round costs the budget
/// exactly what the same frames cost unmerged.
///
/// Fewer than two distinct missing keys is not a round to merge: the one frame
/// that wants the key would pay for the statement anyway, and reading it here
/// would only move its charge from its own returned rows to a cache replay.
///
/// Retention: the union, the returned rows and the staged entries live for
/// this call. What outlives it is the operation's artifact cache, which
/// already held exactly these artifacts for its own lifetime.
pub(super) fn prefetch_forward_candidate_artifacts<S: BatchResolutionFragmentSource + ?Sized>(
    source: &S,
    artifact_cache: &mut ForwardCandidateArtifactCache,
    endpoints: Vec<EndpointSignature>,
    maximum_page_rows: usize,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> StoreResult<()> {
    let mut seen = HashSet::default();
    let mut distinct = Vec::new();
    for endpoint in endpoints {
        if artifact_cache.endpoint_matches.contains_key(&endpoint) {
            continue;
        }
        let Some(key) =
            endpoint.clone_with_poll(&mut || poll_reverse_completion(cancellation, work))
        else {
            return Ok(());
        };
        if !seen.insert(key) {
            continue;
        }
        distinct.push(endpoint);
    }
    if distinct.len() < 2 {
        return Ok(());
    }

    // The source answers one keyed request set per statement, so a union wider
    // than one batch is read in batch-sized request sets. Each is still the
    // whole round's keys for those endpoints instead of one key per frame.
    for group in distinct.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
        let mut missing = Vec::with_capacity(group.len());
        for endpoint in group {
            let Some(endpoint) =
                endpoint.clone_with_poll(&mut || poll_reverse_completion(cancellation, work))
            else {
                return Ok(());
            };
            missing.push(BatchCandidateRequest::new(missing.len(), endpoint));
        }
        let mut cancelled = false;
        let mut matches = Vec::new();
        let mut seen_page_matches = HashSet::default();
        let outcome = source.visit_forward_candidate_match_pages_limited(
            &missing,
            maximum_page_rows,
            None,
            cancellation,
            &mut |page| {
                append_streamed_candidate_match_page(
                    &mut matches,
                    page,
                    0,
                    missing.len(),
                    &mut seen_page_matches,
                    cancellation,
                    work,
                    &mut cancelled,
                )
            },
        )?;
        let (unconditional, branches) = outcome.into_parts();
        assert_eq!(branches.len(), missing.len());
        // A cancelled read publishes nothing. Its evidence is not lost: every
        // frame that wanted one of these keys still reads it itself, under its
        // own cancellation retention, and observes the same source.
        if cancelled || cancellation.is_cancelled() {
            return Ok(());
        }
        if !canonicalize_streamed_candidate_matches(&mut matches, cancellation, work)? {
            return Ok(());
        }

        let mut candidates_by_request = vec![Vec::new(); missing.len()];
        for matched in &matches {
            if poll_reverse_completion(cancellation, work) {
                return Ok(());
            }
            candidates_by_request[matched.request_ordinal()].push(matched.candidate());
        }
        let mut staged = Vec::with_capacity(missing.len());
        for (ordinal, request) in missing.iter().enumerate() {
            let Some(endpoint) = request
                .endpoint()
                .clone_with_poll(&mut || poll_reverse_completion(cancellation, work))
            else {
                return Ok(());
            };
            let branch_completion = copy_returned_completion(
                &branches[ordinal],
                cancellation,
                None,
                work,
                &mut cancelled,
            );
            if cancelled {
                return Ok(());
            }
            staged.push((
                endpoint,
                CachedForwardEndpointMatch {
                    candidates: std::mem::take(&mut candidates_by_request[ordinal])
                        .into_boxed_slice(),
                    branch_completion,
                },
            ));
        }
        if let Some(cached) = artifact_cache.unconditional_completion.as_ref() {
            assert_candidate_unconditional_completions_agree(
                cached,
                &unconditional,
                cancellation,
                None,
                work,
                &mut cancelled,
            )?;
        }
        if cancelled || cancellation.is_cancelled() {
            return Ok(());
        }
        if artifact_cache.unconditional_completion.is_none() {
            artifact_cache.unconditional_completion = Some(unconditional);
        }
        for (endpoint, cached) in staged {
            assert!(
                artifact_cache
                    .endpoint_matches
                    .insert(endpoint, cached)
                    .is_none(),
                "one missing endpoint artifact is published once"
            );
        }
    }
    Ok(())
}

/// Classify one scheduler round's union of endpoint nodes in one statement
/// set. Same contract as [`prefetch_forward_candidate_artifacts`]: publish to
/// the operation's cache, charge nothing, publish nothing on cancellation.
pub(super) fn prefetch_endpoint_classifications<S: BatchResolutionFragmentSource + ?Sized>(
    source: &S,
    artifact_cache: &mut ForwardCandidateArtifactCache,
    nodes: &[BindingNodeId],
    cancellation: &CancellationToken,
    work: &mut usize,
) -> StoreResult<()> {
    let mut unclassified = BTreeSet::new();
    for &node in nodes {
        if !artifact_cache.endpoint_classifications.contains_key(&node) {
            unclassified.insert(node);
        }
    }
    if unclassified.len() < 2 {
        return Ok(());
    }
    let missing = unclassified.into_iter().collect::<Vec<_>>();
    for requested in missing.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
        let classified = source.classify_endpoint_nodes(requested, cancellation)?;
        if cancellation.is_cancelled() {
            return Ok(());
        }
        let Some(classified) =
            align_endpoint_classifications_with_poll(requested, classified, cancellation, work)?
        else {
            return Ok(());
        };
        for classification in classified {
            if let Some(previous) = artifact_cache
                .endpoint_classifications
                .insert(classification.node(), classification)
            {
                assert_eq!(
                    previous, classification,
                    "one endpoint node has one immutable selected classification"
                );
            }
        }
    }
    Ok(())
}

/// Hydrate one scheduler round's union of candidate paths in one statement
/// set. Same contract as [`prefetch_forward_candidate_artifacts`]: publish to
/// the operation's cache, charge nothing, publish nothing on cancellation.
pub(super) fn prefetch_candidate_hydrations<S: BatchResolutionFragmentSource + ?Sized>(
    source: &S,
    artifact_cache: &mut ForwardCandidateArtifactCache,
    candidates: &[CandidatePathIdentity],
    cancellation: &CancellationToken,
    work: &mut usize,
) -> StoreResult<()> {
    let mut unhydrated = BTreeSet::new();
    for &candidate in candidates {
        if !artifact_cache.hydrated_paths.contains_key(&candidate) {
            unhydrated.insert(candidate);
        }
    }
    if unhydrated.len() < 2 {
        return Ok(());
    }
    let missing = unhydrated.into_iter().collect::<Vec<_>>();
    for requested in missing.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
        let hydrated = source.hydrate_candidate_paths(requested, cancellation)?;
        if cancellation.is_cancelled()
            || validate_hydration_with_poll(requested, &hydrated, cancellation, work)?.is_none()
        {
            return Ok(());
        }
        let mut observed = false;
        for (_, path) in &hydrated {
            observed |=
                returned_completion_observes_cancellation(path.completion(), cancellation, work);
        }
        if observed || cancellation.is_cancelled() {
            return Ok(());
        }
        for (identity, path) in hydrated {
            assert!(
                artifact_cache
                    .hydrated_paths
                    .insert(identity, path)
                    .is_none(),
                "one cache-miss candidate path is published once"
            );
        }
    }
    Ok(())
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

/// Read exact immutable candidate paths through the producer-owned artifact
/// cache without retaining a stitched answer. Every cached or source-returned
/// path completion is copied into the returned cancellation ledger before a
/// cancellable body clone or validation step. Cache publication is therefore
/// exhausted and atomic, while cancellation can discard all affirmative rows
/// without losing evidence that already crossed the source boundary.
pub(super) fn read_hydrated_candidate_artifacts<S: BatchResolutionFragmentSource + ?Sized>(
    source: &S,
    cache: &mut ForwardCandidateArtifactCache,
    requested: &[CandidatePathIdentity],
    cancellation: &CancellationToken,
    work: &mut usize,
    cancelled: &mut bool,
) -> StoreResult<(
    Vec<(CandidatePathIdentity, PartialPath)>,
    CancellationEvidenceLedger,
)> {
    assert!(
        requested.windows(2).all(|pair| pair[0] < pair[1]),
        "cached candidate hydration requests are strictly canonical"
    );
    let mut evidence = CancellationEvidenceLedger::default();
    let mut hits = Vec::new();
    let mut missing = Vec::new();
    for &identity in requested {
        *cancelled |= poll_reverse_completion(cancellation, work);
        if let Some(path) = cache.hydrated_paths.get(&identity) {
            evidence.include(path.completion(), cancellation, work);
            hits.push(identity);
        } else if !*cancelled {
            missing.push(identity);
        }
    }
    *cancelled |= evidence.cancellation_observed() | cancellation.is_cancelled();
    if *cancelled {
        return Ok((Vec::new(), evidence));
    }

    let mut paths = BTreeMap::new();
    for identity in hits {
        let cached = cache
            .hydrated_paths
            .get(&identity)
            .expect("a classified hydration hit remains immutable");
        let Some(path) =
            cached.clone_with_poll(&mut || poll_reverse_completion(cancellation, work))
        else {
            *cancelled = true;
            break;
        };
        assert!(paths.insert(identity, path).is_none());
    }
    if *cancelled || cancellation.is_cancelled() {
        *cancelled = true;
        return Ok((Vec::new(), evidence));
    }

    for chunk in missing.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
        if poll_reverse_completion(cancellation, work) {
            *cancelled = true;
            break;
        }
        let hydrated = source.hydrate_candidate_paths(chunk, cancellation)?;
        for (_, path) in &hydrated {
            evidence.include(path.completion(), cancellation, work);
        }
        *cancelled |= evidence.cancellation_observed() | cancellation.is_cancelled();
        if *cancelled {
            break;
        }
        let Some(()) = validate_hydration_with_poll(chunk, &hydrated, cancellation, work)? else {
            *cancelled = true;
            break;
        };
        let mut staged_cache = Vec::with_capacity(hydrated.len());
        for (identity, path) in &hydrated {
            let Some(path) =
                path.clone_with_poll(&mut || poll_reverse_completion(cancellation, work))
            else {
                *cancelled = true;
                break;
            };
            staged_cache.push((*identity, path));
        }
        if *cancelled || cancellation.is_cancelled() {
            *cancelled = true;
            break;
        }
        for (identity, path) in staged_cache {
            assert!(
                cache.hydrated_paths.insert(identity, path).is_none(),
                "one missing candidate hydration is published once"
            );
        }
        for (identity, path) in hydrated {
            assert!(
                paths.insert(identity, path).is_none(),
                "one requested candidate path is returned once"
            );
        }
    }
    *cancelled |= cancellation.is_cancelled();
    if *cancelled {
        return Ok((Vec::new(), evidence));
    }

    let mut aligned = Vec::with_capacity(requested.len());
    for identity in requested {
        if poll_reverse_completion(cancellation, work) {
            *cancelled = true;
            break;
        }
        aligned.push((
            *identity,
            paths
                .remove(identity)
                .expect("every requested candidate path was hydrated"),
        ));
    }
    assert!(
        *cancelled || paths.is_empty(),
        "candidate hydration returned no unrequested paths"
    );
    if *cancelled || cancellation.is_cancelled() {
        *cancelled = true;
        aligned.clear();
    }
    Ok((aligned, evidence))
}

/// Read exact endpoint-node classifications through the same producer-owned
/// artifact cache. Classifications carry no semantic completion operand, so a
/// cancelled read simply publishes no rows and no cache entry.
pub(super) fn read_endpoint_classification_artifacts<S: BatchResolutionFragmentSource + ?Sized>(
    source: &S,
    cache: &mut ForwardCandidateArtifactCache,
    requested: &[BindingNodeId],
    cancellation: &CancellationToken,
    work: &mut usize,
    cancelled: &mut bool,
) -> StoreResult<Vec<BatchEndpointClassification>> {
    assert!(
        requested.windows(2).all(|pair| pair[0] < pair[1]),
        "cached endpoint classification requests are strictly canonical"
    );
    let mut classifications = BTreeMap::new();
    let mut missing = Vec::new();
    for &node in requested {
        *cancelled |= poll_reverse_completion(cancellation, work);
        if let Some(&classification) = cache.endpoint_classifications.get(&node) {
            assert!(classifications.insert(node, classification).is_none());
        } else if !*cancelled {
            missing.push(node);
        }
    }
    if *cancelled || cancellation.is_cancelled() {
        *cancelled = true;
        return Ok(Vec::new());
    }

    for chunk in missing.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
        if poll_reverse_completion(cancellation, work) {
            *cancelled = true;
            break;
        }
        let returned = source.classify_endpoint_nodes(chunk, cancellation)?;
        if cancellation.is_cancelled() {
            *cancelled = true;
            break;
        }
        let Some(aligned) =
            align_endpoint_classifications_with_poll(chunk, returned, cancellation, work)?
        else {
            *cancelled = true;
            break;
        };
        for &classification in &aligned {
            assert!(
                cache
                    .endpoint_classifications
                    .insert(classification.node(), classification)
                    .is_none(),
                "one missing endpoint classification is published once"
            );
        }
        for classification in aligned {
            assert!(
                classifications
                    .insert(classification.node(), classification)
                    .is_none(),
                "one requested endpoint node is classified once"
            );
        }
    }
    *cancelled |= cancellation.is_cancelled();
    if *cancelled {
        return Ok(Vec::new());
    }

    let mut aligned = Vec::with_capacity(requested.len());
    for &node in requested {
        if poll_reverse_completion(cancellation, work) {
            *cancelled = true;
            break;
        }
        aligned.push(
            classifications
                .remove(&node)
                .expect("every requested endpoint node was classified"),
        );
    }
    assert!(
        *cancelled || classifications.is_empty(),
        "endpoint classification returned no unrequested rows"
    );
    if *cancelled || cancellation.is_cancelled() {
        *cancelled = true;
        aligned.clear();
    }
    Ok(aligned)
}

#[derive(Debug)]
pub(super) struct ReverseCandidateBatch {
    candidates: Vec<ReverseCandidateReference>,
    frontiers: Vec<ReverseCandidateFrontier>,
    lexical_frontiers: Vec<ReverseCandidateLexicalFrontier>,
    completions: Box<[ResolutionCompletion]>,
}

impl ReverseCandidateBatch {
    pub(super) fn into_parts(
        self,
    ) -> (
        Vec<ReverseCandidateReference>,
        Vec<ReverseCandidateFrontier>,
        Vec<ReverseCandidateLexicalFrontier>,
        Box<[ResolutionCompletion]>,
    ) {
        (
            self.candidates,
            self.frontiers,
            self.lexical_frontiers,
            self.completions,
        )
    }
}

/// Level-synchronous batch stitcher.
///
/// Each round completes or matches every current frontier state, performs one
/// fragment-major bulk hydration barrier, then composes the next level. No
/// result callback runs during these phases, so cancellation or a source error
/// cannot externally publish a prefix of the batch.
enum BatchResolutionEngineSource<'a, S: BatchResolutionFragmentSource + ?Sized> {
    Shared(&'a S),
    Exclusive(&'a mut S),
}

impl<S: BatchResolutionFragmentSource + ?Sized> BatchResolutionEngineSource<'_, S> {
    fn shared(&self) -> &S {
        match self {
            Self::Shared(source) => source,
            Self::Exclusive(source) => source,
        }
    }

    fn visit_reverse_candidate_match_pages_with_gap_exclusions(
        &mut self,
        requests: &[BatchCandidateRequest],
        exclusions: &mut ReverseCandidateGapExclusionPlan,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        match self {
            Self::Shared(source) => source
                .visit_reverse_candidate_match_pages_with_gap_exclusions_shared(
                    requests,
                    exclusions,
                    cancellation,
                    visitor,
                ),
            Self::Exclusive(source) => source
                .visit_reverse_candidate_match_pages_with_gap_exclusions(
                    requests,
                    exclusions,
                    cancellation,
                    visitor,
                ),
        }
    }
}

pub struct BatchResolutionEngine<'a, S: BatchResolutionFragmentSource + ?Sized> {
    source: BatchResolutionEngineSource<'a, S>,
    resolution_session: Option<&'a ResolutionSession>,
    reverse_target: Option<SemanticId>,
}

impl<'a, S: BatchResolutionFragmentSource + ?Sized> BatchResolutionEngine<'a, S> {
    pub const fn new(source: &'a S) -> Self {
        Self {
            source: BatchResolutionEngineSource::Shared(source),
            resolution_session: None,
            reverse_target: None,
        }
    }

    pub(crate) const fn new_exclusive(source: &'a mut S) -> Self {
        Self {
            source: BatchResolutionEngineSource::Exclusive(source),
            resolution_session: None,
            reverse_target: None,
        }
    }

    pub(crate) const fn maybe_bounded(
        source: &'a S,
        session: Option<&'a ResolutionSession>,
    ) -> Self {
        Self {
            source: BatchResolutionEngineSource::Shared(source),
            resolution_session: session,
            reverse_target: None,
        }
    }

    pub(super) fn for_reverse_target(mut self, target: SemanticId) -> Self {
        self.reverse_target = Some(target);
        self
    }

    fn source(&self) -> &S {
        self.source.shared()
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
        self.resolve_reference_with_artifact_cache_and_metrics(query, cancellation, None)
            .map(|(answer, _)| answer)
    }

    pub(super) fn resolve_reference_with_metrics(
        &self,
        query: ResolutionQuery,
        cancellation: &CancellationToken,
    ) -> StoreResult<(ResolutionAnswer, ResolutionBatchMetrics)> {
        self.resolve_reference_with_artifact_cache_and_metrics(query, cancellation, None)
    }

    pub(super) fn resolve_reference_cached(
        &self,
        query: ResolutionQuery,
        cancellation: &CancellationToken,
        cache: &mut ForwardCandidateArtifactCache,
    ) -> StoreResult<ResolutionAnswer> {
        self.resolve_reference_with_artifact_cache_and_metrics(query, cancellation, Some(cache))
            .map(|(answer, _)| answer)
    }

    pub(super) fn resolve_reference_cached_with_metrics(
        &self,
        query: ResolutionQuery,
        cancellation: &CancellationToken,
        cache: &mut ForwardCandidateArtifactCache,
    ) -> StoreResult<(ResolutionAnswer, ResolutionBatchMetrics)> {
        self.resolve_reference_with_artifact_cache_and_metrics(query, cancellation, Some(cache))
    }

    fn resolve_reference_with_artifact_cache_and_metrics(
        &self,
        query: ResolutionQuery,
        cancellation: &CancellationToken,
        cache: Option<&mut ForwardCandidateArtifactCache>,
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
        self.resolve_seeded_reference_with_artifact_cache_and_metrics(&request, cancellation, cache)
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
        self.resolve_seeded_reference_with_artifact_cache_and_metrics(request, cancellation, None)
            .map(|(answer, _)| answer)
    }

    pub(super) fn resolve_seeded_reference_with_metrics(
        &self,
        request: &SeededReferenceRequest,
        cancellation: &CancellationToken,
    ) -> StoreResult<(ResolutionAnswer, ResolutionBatchMetrics)> {
        self.resolve_seeded_reference_with_artifact_cache_and_metrics(request, cancellation, None)
    }

    pub(super) fn resolve_seeded_reference_cached(
        &self,
        request: &SeededReferenceRequest,
        cancellation: &CancellationToken,
        cache: &mut ForwardCandidateArtifactCache,
    ) -> StoreResult<ResolutionAnswer> {
        self.resolve_seeded_reference_with_artifact_cache_and_metrics(
            request,
            cancellation,
            Some(cache),
        )
        .map(|(answer, _)| answer)
    }

    pub(super) fn resolve_seeded_reference_cached_with_metrics(
        &self,
        request: &SeededReferenceRequest,
        cancellation: &CancellationToken,
        cache: &mut ForwardCandidateArtifactCache,
    ) -> StoreResult<(ResolutionAnswer, ResolutionBatchMetrics)> {
        self.resolve_seeded_reference_with_artifact_cache_and_metrics(
            request,
            cancellation,
            Some(cache),
        )
    }

    fn resolve_seeded_reference_with_artifact_cache_and_metrics(
        &self,
        request: &SeededReferenceRequest,
        cancellation: &CancellationToken,
        cache: Option<&mut ForwardCandidateArtifactCache>,
    ) -> StoreResult<(ResolutionAnswer, ResolutionBatchMetrics)> {
        let batch = self.resolve_seeded_reference_requests(
            std::slice::from_ref(request),
            cancellation,
            cache,
        )?;
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
        self.resolve_reference_batch_with_artifact_cache(batch, cancellation, None)
    }

    pub(super) fn resolve_reference_batch_cached(
        &self,
        batch: &ReferenceSeedBatch,
        cancellation: &CancellationToken,
        cache: &mut ForwardCandidateArtifactCache,
    ) -> StoreResult<ReferenceBatchAnswer> {
        self.resolve_reference_batch_with_artifact_cache(batch, cancellation, Some(cache))
    }

    fn resolve_reference_batch_with_artifact_cache(
        &self,
        batch: &ReferenceSeedBatch,
        cancellation: &CancellationToken,
        cache: Option<&mut ForwardCandidateArtifactCache>,
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
        self.resolve_seeded_reference_requests(&requests, cancellation, cache)
    }

    /// Resolve an operation-owned seed batch without cloning its seed rows.
    pub(super) fn resolve_owned_reference_batch(
        &self,
        batch: ReferenceSeedBatch,
        cancellation: &CancellationToken,
    ) -> StoreResult<ReferenceBatchAnswer> {
        self.resolve_owned_reference_batch_with_artifact_cache(batch, cancellation, None)
    }

    pub(super) fn resolve_owned_reference_batch_cached(
        &self,
        batch: ReferenceSeedBatch,
        cancellation: &CancellationToken,
        cache: &mut ForwardCandidateArtifactCache,
    ) -> StoreResult<ReferenceBatchAnswer> {
        self.resolve_owned_reference_batch_with_artifact_cache(batch, cancellation, Some(cache))
    }

    fn resolve_owned_reference_batch_with_artifact_cache(
        &self,
        batch: ReferenceSeedBatch,
        cancellation: &CancellationToken,
        cache: Option<&mut ForwardCandidateArtifactCache>,
    ) -> StoreResult<ReferenceBatchAnswer> {
        let seeds = batch.into_seeds().into_vec();
        let seed_count = seeds.len();
        let mut work = 0_usize;
        let (prepared, mut cancelled) =
            prepare_reference_seed_completions(&seeds, cancellation, &mut work);
        if !self.charge_scope_steps(seed_count) {
            return Ok(cancelled_prepared_seed_answers(
                prepared,
                ResolutionBatchMetrics {
                    reference_seeds: seed_count,
                    batches: 1,
                    ..ResolutionBatchMetrics::default()
                },
                cancellation,
                &mut work,
            ));
        }
        let mut requests = Vec::with_capacity(seeds.len());
        if !cancelled {
            for seed in seeds {
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
                    reference_seeds: seed_count,
                    batches: 1,
                    ..ResolutionBatchMetrics::default()
                },
                cancellation,
                &mut work,
            ));
        }
        self.resolve_seeded_reference_requests(&requests, cancellation, cache)
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
        for ((prepared, certifier), request) in prepared.into_iter().zip(certifiers).zip(requests) {
            cancelled |= poll_reverse_completion(cancellation, &mut completion_work);
            seeds.push(SeedState {
                reference: prepared.reference,
                go_spelling_namespace: request
                    .seed()
                    .site_metadata()
                    .and_then(FactReferenceSiteMetadata::go_spelling_namespace),
                go_package_qualifier: request
                    .seed()
                    .site_metadata()
                    .is_some_and(FactReferenceSiteMetadata::go_package_qualifier),
                go_universe_seed_eligible: go_universe_seed_eligible(request.seed()),
                completed: Vec::new(),
                terminals: Vec::new(),
                incomplete_scope_search: false,
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
        artifact_cache_enabled: bool,
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
                seed_owners: HashMap::default(),
            };
        }

        let mut seed_owners =
            HashMap::<CandidatePathIdentity, (HashSet<usize>, Vec<usize>)>::default();
        if artifact_cache_enabled {
            // Candidate rows are canonical request-major. This linear owner
            // index avoids rescanning the full relation per hydrated path.
            for matched in context.matches {
                if poll_reverse_completion(cancellation, context.completion_work) {
                    *context.cancelled = true;
                    break;
                }
                let seed = context.expandable[matched.request_ordinal()].seed;
                let (seen, owners) = seed_owners
                    .entry(matched.candidate())
                    .or_insert_with(|| (HashSet::default(), Vec::new()));
                if seen.insert(seed) {
                    owners.push(seed);
                }
            }
        }
        if *context.cancelled {
            Self::retain_forward_hydration_cancellation(&mut context, cancellation);
            return ForwardHydrationRequest {
                candidates: Vec::new(),
                seed_owners,
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
        ForwardHydrationRequest {
            candidates,
            seed_owners,
        }
    }

    fn hydrate_forward_candidates(
        &self,
        mut context: ForwardHydrationContext<'_>,
        request: &ForwardHydrationRequest,
        mut artifact_cache: Option<&mut ForwardCandidateArtifactCache>,
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
        if let Some(cache) = artifact_cache.as_deref() {
            let mut cached_hydrations = Vec::new();
            for &candidate in &request.candidates {
                *context.cancelled |=
                    poll_reverse_completion(cancellation, context.completion_work);
                if let Some(cached) = cache.hydrated_paths.get(&candidate) {
                    // Inspect each immutable path box exactly once before a
                    // cancellable clone. Cancellation maps its raw evidence
                    // through the linear seed-owner index below.
                    *context.cancelled |= returned_completion_observes_cancellation(
                        cached.completion(),
                        cancellation,
                        context.completion_work,
                    );
                    cached_hydrations.push(candidate);
                } else if !*context.cancelled {
                    missing_hydrations.push(candidate);
                }
            }
            if !*context.cancelled {
                for &candidate in &cached_hydrations {
                    let cached = cache
                        .hydrated_paths
                        .get(&candidate)
                        .expect("a classified hydration hit remains immutable");
                    let path = cached.clone_with_poll(&mut || {
                        poll_reverse_completion(cancellation, context.completion_work)
                    });
                    let Some(path) = path else {
                        *context.cancelled = true;
                        break;
                    };
                    assert!(
                        context.arena.insert(candidate, path).is_none(),
                        "one cached candidate path is installed once per batch"
                    );
                    context.metrics.distinct_path_hydrations += 1;
                }
            }
            if *context.cancelled {
                for &candidate in &cached_hydrations {
                    let cached = cache
                        .hydrated_paths
                        .get(&candidate)
                        .expect("a returned hydration hit remains immutable");
                    for &seed in &request
                        .seed_owners
                        .get(&candidate)
                        .expect("a matched candidate has one seed-owner index")
                        .1
                    {
                        let _ = poll_reverse_completion(cancellation, context.completion_work);
                        if context.accounted_completions.insert((seed, candidate)) {
                            let _ = context.seeds[seed].observed_completion.include(
                                cached.completion(),
                                cancellation,
                                context.completion_work,
                            );
                        }
                    }
                }
            }
        } else {
            missing_hydrations.extend_from_slice(&request.candidates);
        }
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
            if artifact_cache.is_some() {
                for (_, path) in &hydrated {
                    hydration_cancelled |= returned_completion_observes_cancellation(
                        path.completion(),
                        cancellation,
                        context.completion_work,
                    );
                }
            }
            let mut staged_cache_paths = Vec::with_capacity(hydrated.len());
            if artifact_cache.is_some() {
                for (identity, path) in &hydrated {
                    if poll_reverse_completion(cancellation, context.completion_work) {
                        hydration_cancelled = true;
                        break;
                    }
                    let Some(path) = path.clone_with_poll(&mut || {
                        poll_reverse_completion(cancellation, context.completion_work)
                    }) else {
                        hydration_cancelled = true;
                        break;
                    };
                    staged_cache_paths.push((*identity, path));
                }
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
            if let Some(cache) = artifact_cache.as_deref_mut() {
                for (identity, path) in staged_cache_paths {
                    assert!(
                        cache.hydrated_paths.insert(identity, path).is_none(),
                        "one cache-miss candidate path is published once"
                    );
                }
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
    ) -> StoreResult<ReferenceBatchAnswer> {
        cancelled |= cancellation.is_cancelled();
        let universe_candidates = if cancelled || !self.source().supports_go_universe() {
            Vec::new()
        } else {
            seeds
                .iter()
                .filter(|seed| {
                    seed.go_spelling_namespace.is_some()
                        && seed.go_universe_seed_eligible
                        && seed.completed.is_empty()
                        && !seed.incomplete_scope_search
                })
                .map(|seed| (seed.reference, seed.go_spelling_namespace.unwrap()))
                .collect::<Vec<_>>()
        };
        let mut answer = select_seed_answers(
            seeds,
            metrics,
            cancellation,
            cancelled,
            &mut completion_work,
        );
        if !cancelled {
            for (reference, namespace) in universe_candidates {
                if cancellation.is_cancelled() {
                    cancelled = true;
                    break;
                }
                let Some(resolved) = answer
                    .answers
                    .iter_mut()
                    .find(|item| item.reference == reference)
                else {
                    continue;
                };
                // The selected lexical walk exhausted its source scopes and
                // found no source candidate. Seed-wide gaps from unrelated
                // obligations do not change lookup in the selected file and
                // package scopes; incomplete lexical scope searches are
                // filtered out before this pass.
                if !resolved.answer.targets().is_empty() {
                    continue;
                }
                let Some(spelling) =
                    self.source()
                        .go_lookup_spelling(reference, namespace, cancellation)?
                else {
                    continue;
                };
                let Some(entry) = super::universe::lookup(Language::Go, namespace, &spelling)
                else {
                    continue;
                };
                let Some(target) = self.source().intern_shared_name_digest(
                    super::universe::identity_digest(entry),
                    cancellation,
                )?
                else {
                    continue;
                };
                resolved.answer =
                    ResolutionAnswer::new(vec![target], Vec::new(), ResolutionCompletion::Complete);
            }
        }
        if cancellation.is_cancelled() || cancelled {
            answer = mark_batch_cancelled(answer, cancellation, &mut completion_work);
        }
        Ok(answer)
    }

    fn resolve_seeded_reference_requests(
        &self,
        requests: &[SeededReferenceRequest],
        cancellation: &CancellationToken,
        mut artifact_cache: Option<&mut ForwardCandidateArtifactCache>,
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
            crate::profiling::note_with(|| {
                format!(
                    "resolution::eager_lexical_round references={:?} round={} frontier_paths={}",
                    seeds.iter().map(|seed| seed.reference).collect::<Vec<_>>(),
                    metrics.worklist_rounds,
                    frontier.len(),
                )
            });

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
                let mut missing = Vec::new();
                if let Some(cache) = artifact_cache.as_deref() {
                    for &node in &to_classify {
                        if poll_reverse_completion(cancellation, &mut completion_work) {
                            cancelled = true;
                            break;
                        }
                        if let Some(&classification) = cache.endpoint_classifications.get(&node) {
                            assert!(
                                endpoint_definitions
                                    .insert(
                                        classification.node(),
                                        classification.definition().map(|target| (
                                            target,
                                            classification.go_definition_namespaces()
                                        ))
                                    )
                                    .is_none(),
                                "an endpoint is classified at most once per batch"
                            );
                            metrics.distinct_endpoint_classifications += 1;
                        } else {
                            missing.push(node);
                        }
                    }
                } else {
                    missing = to_classify;
                }
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
                    if let Some(cache) = artifact_cache.as_deref_mut() {
                        if cancellation.is_cancelled() {
                            cancelled = true;
                            break;
                        }
                        for &classification in &classified {
                            if let Some(previous) = cache
                                .endpoint_classifications
                                .insert(classification.node(), classification)
                            {
                                assert_eq!(
                                    previous, classification,
                                    "one endpoint node has one immutable selected classification"
                                );
                            }
                        }
                    }
                    for classification in classified {
                        if poll_reverse_completion(cancellation, &mut completion_work) {
                            cancelled = true;
                            break;
                        }
                        assert!(
                            endpoint_definitions
                                .insert(
                                    classification.node(),
                                    classification.definition().map(|target| (
                                        target,
                                        classification.go_definition_namespaces()
                                    ))
                                )
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
                    && let Some((target, namespaces)) = endpoint_definitions
                        .get(&state.path.end().node())
                        .copied()
                        .flatten()
                {
                    let seed = &mut seeds[state.seed];
                    match classify_completed_binding(
                        seed.go_spelling_namespace,
                        seed.go_package_qualifier,
                        namespaces,
                        target,
                        state.path,
                    ) {
                        CompletedBinding::Complete(candidate) => seed.completed.push(candidate),
                        CompletedBinding::Incomplete(terminal) => {
                            seed.incomplete_scope_search = true;
                            seed.terminals.push(terminal);
                        }
                    }
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
                        artifact_cache.as_deref_mut(),
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
                artifact_cache.is_some(),
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
                artifact_cache.as_deref_mut(),
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
                let composition = parent.path.concatenate_with_poll(candidate, &mut || {
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
                            saturation,
                        });
                    }
                    SaturationDecision::Subsumed => {
                        has_successor.insert(matched.request_ordinal());
                    }
                    SaturationDecision::Uncertified(gap) => {
                        seed.incomplete_scope_search = true;
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

        self.finish_seeded_reference_batch(seeds, metrics, cancellation, cancelled, completion_work)
    }

    /// Advance one typed frontier through normalized file-local copy rules.
    ///
    /// The source is visited iteratively and the operation returns atomically.
    /// Incoming, selected-source, and row-local completeness evidence is
    /// propagated to every returned alternative. If cancellation is observed,
    /// partially visited alternatives are discarded so callers cannot publish a
    /// prefix as the complete set of possible transfers.
    pub fn transfer_types(
        &self,
        state: &TypedFrontierState,
        cancellation: &CancellationToken,
    ) -> StoreResult<(Vec<TypedFrontierState>, ResolutionCompletion)> {
        if cancellation.is_cancelled() {
            return Ok((
                Vec::new(),
                state.completion().combine(&cancelled_completion()),
            ));
        }

        let mut rules = Vec::new();
        let mut visited = 0_usize;
        let source_completion =
            self.source()
                .visit_type_transfer_rules(state.slot(), cancellation, &mut |rule| {
                    visited += 1;
                    if visited.is_multiple_of(CANCELLATION_QUANTUM) && cancellation.is_cancelled() {
                        return Ok(false);
                    }
                    rules.push(rule.clone());
                    Ok(true)
                })?;
        apply_type_transfer_rules(state, rules, source_completion, cancellation)
    }

    /// Find exact references to one definition.
    ///
    /// Reverse stitching is deliberately only a candidate generator. Every
    /// distinct generated reference is issued again by the source, grouped
    /// into bounded fragment-major batches, and resolved forward exactly once.
    /// A reference is returned only when full forward shadow selection retains
    /// `definition` as a target.
    pub fn references_to(
        &mut self,
        definition: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<ReferenceSearchAnswer> {
        if cancellation.is_cancelled() {
            return Ok(empty_reference_search(cancelled_completion()));
        }
        let Some(definition_node) = self
            .source()
            .lookup_definition_node(definition, cancellation)?
        else {
            let completion = if cancellation.is_cancelled() {
                cancelled_completion()
            } else {
                ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                    definition,
                )])
            };
            return Ok(empty_reference_search(completion));
        };
        if cancellation.is_cancelled() {
            return Ok(empty_reference_search(cancelled_completion()));
        }

        let reverse =
            self.reverse_candidate_references(&[(definition, definition_node)], cancellation)?;
        assert_eq!(
            reverse.completions.len(),
            1,
            "a single-target reverse query must have one completion"
        );
        let mut work = 0_usize;
        let mut completion = BatchCompletionLedger::default();
        let mut returned_evidence = CancellationEvidenceLedger::default();
        let mut reverse_completions = reverse.completions.into_vec();
        let reverse_completion = reverse_completions
            .pop()
            .expect("a single-target reverse completion was just asserted");
        completion.include(&reverse_completion, cancellation, &mut work);
        returned_evidence.include(&reverse_completion, cancellation, &mut work);
        if completion.cancellation_observed
            || returned_evidence.cancellation_observed()
            || cancellation.is_cancelled()
        {
            let completion = finish_cancelled_reference_search_completion(
                completion,
                returned_evidence,
                cancellation,
                &mut work,
            );
            return Ok(empty_reference_search(completion));
        }

        let mut candidate_nodes = BTreeMap::new();
        for candidate in reverse.candidates {
            returned_evidence.observe_row(cancellation, &mut work);
            if returned_evidence.cancellation_observed() || cancellation.is_cancelled() {
                let completion = finish_cancelled_reference_search_completion(
                    completion,
                    returned_evidence,
                    cancellation,
                    &mut work,
                );
                return Ok(empty_reference_search(completion));
            }
            assert_eq!(
                candidate.target, 0,
                "a single-target reverse query cannot produce another target ordinal"
            );
            if let Some(existing) = candidate_nodes.insert(candidate.reference, candidate.node)
                && existing != candidate.node
            {
                return Err(StoreError::new(format!(
                    "reverse candidate semantic {} names multiple endpoint nodes: {} and {}",
                    candidate.reference, existing, candidate.node
                )));
            }
        }
        let mut seeds = BTreeMap::new();
        while !candidate_nodes.is_empty() {
            let mut requests = Vec::with_capacity(MAX_REFERENCE_SEEDS_PER_BATCH);
            while requests.len() < MAX_REFERENCE_SEEDS_PER_BATCH {
                let Some((reference, node)) = candidate_nodes.pop_first() else {
                    break;
                };
                returned_evidence.observe_row(cancellation, &mut work);
                if returned_evidence.cancellation_observed() || cancellation.is_cancelled() {
                    let completion = finish_cancelled_reference_search_completion(
                        completion,
                        returned_evidence,
                        cancellation,
                        &mut work,
                    );
                    return Ok(empty_reference_search(completion));
                }
                requests.push(ReverseReferenceSeedRequest::new(reference, node));
            }
            let issued = self
                .source()
                .issue_reverse_reference_seeds(&requests, cancellation)?;
            for seed in &issued {
                returned_evidence.include(seed.completion(), cancellation, &mut work);
            }
            if returned_evidence.cancellation_observed() || cancellation.is_cancelled() {
                let completion = finish_cancelled_reference_search_completion(
                    completion,
                    returned_evidence,
                    cancellation,
                    &mut work,
                );
                return Ok(empty_reference_search(completion));
            }
            validate_reverse_reference_seeds(&requests, &issued)?;
            for seed in issued {
                returned_evidence.observe_row(cancellation, &mut work);
                let key = (seed.fragment(), seed.reference(), seed.node());
                assert!(
                    seeds.insert(key, seed).is_none(),
                    "one exact seed per reverse candidate is required"
                );
            }
        }

        let mut references = BTreeSet::new();
        let mut witness_groups = HashMap::default();
        while let Some((&(fragment, _, _), _)) = seeds.first_key_value() {
            let mut batch_seeds = Vec::with_capacity(MAX_REFERENCE_SEEDS_PER_BATCH);
            while batch_seeds.len() < MAX_REFERENCE_SEEDS_PER_BATCH
                && seeds
                    .first_key_value()
                    .is_some_and(|(&(next_fragment, _, _), _)| next_fragment == fragment)
            {
                let (_, seed) = seeds
                    .pop_first()
                    .expect("the observed fragment seed must remain available");
                batch_seeds.push(seed);
            }
            let answer = self.resolve_owned_reference_batch(
                ReferenceSeedBatch::new(batch_seeds),
                cancellation,
            )?;
            let (answers, batch_completion, _) = answer.into_parts();
            completion.include(&batch_completion, cancellation, &mut work);
            returned_evidence.include(&batch_completion, cancellation, &mut work);
            for answer in &answers {
                returned_evidence.observe_row(cancellation, &mut work);
                returned_evidence.include(answer.answer().completion(), cancellation, &mut work);
                for witness in answer.answer().witnesses() {
                    returned_evidence.observe_row(cancellation, &mut work);
                    returned_evidence.include(witness.completion(), cancellation, &mut work);
                }
            }
            if completion.cancellation_observed
                || returned_evidence.cancellation_observed()
                || cancellation.is_cancelled()
            {
                let completion = finish_cancelled_reference_search_completion(
                    completion,
                    returned_evidence,
                    cancellation,
                    &mut work,
                );
                return Ok(empty_reference_search(completion));
            }

            for answer in answers.into_vec() {
                let (reference, answer) = answer.into_parts();
                let (targets, witnesses, _) = answer.into_parts();
                let mut contains_definition = false;
                for target in targets {
                    returned_evidence.observe_row(cancellation, &mut work);
                    if returned_evidence.cancellation_observed() || cancellation.is_cancelled() {
                        let completion = finish_cancelled_reference_search_completion(
                            completion,
                            returned_evidence,
                            cancellation,
                            &mut work,
                        );
                        return Ok(empty_reference_search(completion));
                    }
                    if target == definition {
                        contains_definition = true;
                        break;
                    }
                }
                if !contains_definition {
                    continue;
                }
                assert!(
                    references.insert(reference),
                    "a reverse candidate is forward-validated exactly once"
                );
                let mut selected_witnesses = Vec::new();
                for witness in witnesses {
                    returned_evidence.observe_row(cancellation, &mut work);
                    if returned_evidence.cancellation_observed() || cancellation.is_cancelled() {
                        let completion = finish_cancelled_reference_search_completion(
                            completion,
                            returned_evidence,
                            cancellation,
                            &mut work,
                        );
                        return Ok(empty_reference_search(completion));
                    }
                    if witness.target() == definition {
                        selected_witnesses.push(witness);
                    }
                }
                assert!(
                    !selected_witnesses.is_empty(),
                    "selected reference {reference} has no witness for definition {definition}"
                );
                assert!(
                    witness_groups
                        .insert(reference, selected_witnesses)
                        .is_none(),
                    "one witness group is retained per selected reference"
                );
            }
        }

        let mut published_references = Vec::with_capacity(references.len());
        let mut published_witnesses = Vec::new();
        for reference in references {
            returned_evidence.observe_row(cancellation, &mut work);
            if returned_evidence.cancellation_observed() || cancellation.is_cancelled() {
                let completion = finish_cancelled_reference_search_completion(
                    completion,
                    returned_evidence,
                    cancellation,
                    &mut work,
                );
                return Ok(empty_reference_search(completion));
            }
            published_references.push(reference);
            let witnesses = witness_groups
                .remove(&reference)
                .expect("each selected reference owns one witness group");
            for witness in witnesses {
                returned_evidence.observe_row(cancellation, &mut work);
                if returned_evidence.cancellation_observed() || cancellation.is_cancelled() {
                    let completion = finish_cancelled_reference_search_completion(
                        completion,
                        returned_evidence,
                        cancellation,
                        &mut work,
                    );
                    return Ok(empty_reference_search(completion));
                }
                published_witnesses.push(witness);
            }
        }
        assert!(
            witness_groups.is_empty(),
            "every selected witness group must be published exactly once"
        );
        let (completion, completion_cancelled) =
            completion.finish_semantic(cancellation, &mut work);
        if completion_cancelled
            || returned_evidence.cancellation_observed()
            || cancellation.is_cancelled()
        {
            returned_evidence.include(&completion, cancellation, &mut work);
            let completion = returned_evidence.finish(true, cancellation, &mut work).0;
            return Ok(empty_reference_search(completion));
        }
        let answer =
            ReferenceSearchAnswer::new(published_references, published_witnesses, completion);
        if cancellation.is_cancelled() {
            returned_evidence.include(answer.completion(), cancellation, &mut work);
            let completion = returned_evidence.finish(true, cancellation, &mut work).0;
            return Ok(empty_reference_search(completion));
        }
        Ok(answer)
    }

    fn classify_reverse_frontiers(&self, context: ReverseFrontierContext<'_>) -> StoreResult<()> {
        let ReverseFrontierContext {
            definitions,
            current,
            endpoint_classifications,
            frontiers,
            frontier_ids_by_key,
            lexical_frontiers,
            lexical_frontier_ids_by_key,
            cancellation,
            observations,
            cancelled,
        } = context;
        let universal_root = BindingNodeId::universal_root();
        let mut unclassified = BTreeSet::new();
        for state in current {
            if poll_reverse_completion(cancellation, observations) {
                *cancelled = true;
                break;
            }
            let node = state.path.start().node();
            if !endpoint_classifications.contains_key(&node) {
                unclassified.insert(node);
            }
        }
        if *cancelled {
            return Ok(());
        }
        let mut to_classify = Vec::with_capacity(unclassified.len());
        while let Some(node) = unclassified.pop_first() {
            if poll_reverse_completion(cancellation, observations) {
                *cancelled = true;
                break;
            }
            to_classify.push(node);
        }
        if *cancelled {
            return Ok(());
        }
        for requested in to_classify.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
            let classified = self
                .source()
                .classify_endpoint_nodes(requested, cancellation)?;
            if cancellation.is_cancelled() {
                *cancelled = true;
                break;
            }
            let Some(classified) = align_endpoint_classifications_with_poll(
                requested,
                classified,
                cancellation,
                observations,
            )?
            else {
                *cancelled = true;
                break;
            };
            for classification in classified {
                if poll_reverse_completion(cancellation, observations) {
                    *cancelled = true;
                    break;
                }
                assert!(
                    endpoint_classifications
                        .insert(classification.node(), classification)
                        .is_none(),
                    "a reverse endpoint is classified at most once per operation"
                );
            }
            if *cancelled {
                break;
            }
        }
        if *cancelled {
            return Ok(());
        }

        // Observe every source-classified member-entry endpoint before lexical
        // expansion. The full start signature is the route-composition key;
        // precedence and witnesses do not affect typed-seed unification.
        for state in current {
            let classification = endpoint_classifications
                .get(&state.path.start().node())
                .copied()
                .expect("every current reverse endpoint was classified");
            if let Some(owner) = classification.member_scope_owner() {
                assert!(
                    endpoint_is_balanced(state.path.end()),
                    "a classified reverse member frontier must retain the balanced target endpoint"
                );
                assert_eq!(
                    state.path.end().node(),
                    definitions[state.target].1,
                    "a classified reverse member frontier must end at its scheduled target node"
                );
                // Non-identity paths recorded their completion before cycle
                // certification. Repeating it here would canonicalize a sole
                // public noncanonical operand.
                let mut clone_cancelled = || {
                    *observations = observations
                        .checked_add(1)
                        .expect("reverse frontier clone work must fit usize");
                    observations.is_multiple_of(CANCELLATION_QUANTUM) && cancellation.is_cancelled()
                };
                let Some(key) = reverse_frontier_key_with_poll(
                    state.target,
                    state.path.start(),
                    &mut clone_cancelled,
                ) else {
                    *cancelled = true;
                    break;
                };
                let mut duplicate = false;
                if let Some(frontier_ids) = frontier_ids_by_key.get(&(state.target, key)) {
                    for &frontier_id in frontier_ids {
                        if clone_cancelled() {
                            *cancelled = true;
                            break;
                        }
                        let Some(equal) = frontiers[frontier_id]
                            .start
                            .equals_with_poll(state.path.start(), &mut clone_cancelled)
                        else {
                            *cancelled = true;
                            break;
                        };
                        if equal {
                            assert_eq!(
                                frontiers[frontier_id].owner, owner,
                                "one endpoint classification must have one exact member-scope owner"
                            );
                            duplicate = true;
                            break;
                        }
                    }
                }
                if *cancelled {
                    break;
                }
                if !duplicate {
                    let Some(start) = state.path.start().clone_with_poll(&mut clone_cancelled)
                    else {
                        *cancelled = true;
                        break;
                    };
                    let frontier_id = frontiers.len();
                    frontiers.push(ReverseCandidateFrontier {
                        target: state.target,
                        owner,
                        start,
                    });
                    frontier_ids_by_key
                        .entry((state.target, key))
                        .or_default()
                        .push(frontier_id);
                }
            } else if state.path.start().node() != universal_root
                && classification.reference().is_none()
                && classification.definition().is_none()
                && (!state.path.start().symbols().fixed().is_empty()
                    || state.path.start().symbols().tail().is_some())
            {
                assert!(endpoint_is_balanced(state.path.end()));
                assert_eq!(state.path.end().node(), definitions[state.target].1);
                let mut clone_cancelled = || {
                    *observations = observations
                        .checked_add(1)
                        .expect("reverse lexical frontier clone work must fit usize");
                    observations.is_multiple_of(CANCELLATION_QUANTUM) && cancellation.is_cancelled()
                };
                let Some(key) = reverse_frontier_key_with_poll(
                    state.target,
                    state.path.start(),
                    &mut clone_cancelled,
                ) else {
                    *cancelled = true;
                    break;
                };
                let mut duplicate = false;
                if let Some(frontier_ids) = lexical_frontier_ids_by_key.get(&(state.target, key)) {
                    for &frontier_id in frontier_ids {
                        if clone_cancelled() {
                            *cancelled = true;
                            break;
                        }
                        let Some(equal) = lexical_frontiers[frontier_id]
                            .start
                            .equals_with_poll(state.path.start(), &mut clone_cancelled)
                        else {
                            *cancelled = true;
                            break;
                        };
                        if equal {
                            duplicate = true;
                            break;
                        }
                    }
                }
                if *cancelled {
                    break;
                }
                if !duplicate {
                    let Some(start) = state.path.start().clone_with_poll(&mut clone_cancelled)
                    else {
                        *cancelled = true;
                        break;
                    };
                    let frontier_id = lexical_frontiers.len();
                    lexical_frontiers.push(ReverseCandidateLexicalFrontier {
                        target: state.target,
                        start,
                    });
                    lexical_frontier_ids_by_key
                        .entry((state.target, key))
                        .or_default()
                        .push(frontier_id);
                }
            }
            if *cancelled {
                break;
            }
        }
        Ok(())
    }

    fn initialize_reverse_candidate_batch(
        definitions: &[(SemanticId, BindingNodeId)],
        cancellation: &CancellationToken,
    ) -> ReverseCandidateInitialization {
        assert!(
            !definitions.is_empty(),
            "a reverse candidate batch must contain at least one target"
        );
        assert!(
            definitions.len() <= MAX_REVERSE_TARGETS_PER_BATCH,
            "a reverse candidate batch has {} targets; maximum is {MAX_REVERSE_TARGETS_PER_BATCH}",
            definitions.len()
        );
        for (left_index, &(left_definition, left_node)) in definitions.iter().enumerate() {
            for &(right_definition, right_node) in &definitions[left_index + 1..] {
                assert_ne!(
                    left_definition, right_definition,
                    "a raw reverse batch must not schedule one definition twice"
                );
                assert_ne!(
                    left_node, right_node,
                    "distinct raw reverse definitions must name distinct selected nodes"
                );
            }
        }
        if cancellation.is_cancelled() {
            return ReverseCandidateInitialization::Cancelled(ReverseCandidateBatch {
                candidates: Vec::new(),
                frontiers: Vec::new(),
                lexical_frontiers: Vec::new(),
                completions: std::iter::repeat_n(cancelled_completion(), definitions.len())
                    .collect(),
            });
        }

        let mut targets = Vec::with_capacity(definitions.len());
        let mut frontier = Vec::with_capacity(definitions.len());
        for (target, &(_definition, node)) in definitions.iter().enumerate() {
            let seed = identity_path(node);
            targets.push(ReverseTargetState {
                completion: BatchCompletionLedger::default(),
                certifier: CycleCompletenessCertifier::new(&seed),
            });
            frontier.push(ReverseWorkPath {
                target,
                path: seed,
                saturation: SaturationBranch::default(),
            });
        }
        ReverseCandidateInitialization::Ready(InitializedReverseCandidateBatch {
            targets,
            frontier,
        })
    }

    fn finish_reverse_candidate_batch(
        mut finalization: ReverseCandidateFinalization,
        cancellation: &CancellationToken,
    ) -> StoreResult<ReverseCandidateBatch> {
        finalization.cancelled |= cancellation.is_cancelled();
        if finalization.cancelled {
            finalization.frontiers.clear();
            finalization.lexical_frontiers.clear();
            finalization.candidates.clear();
            for target in &mut finalization.targets {
                target
                    .completion
                    .include_reason(ResolutionIncompleteReason::Cancelled);
            }
        }

        if !finalization.cancelled {
            match canonicalize_reverse_candidates(
                std::mem::take(&mut finalization.candidates),
                cancellation,
                &mut finalization.composition_attempts,
            )? {
                Some(canonical) => finalization.candidates = canonical,
                None => finalization.cancelled = true,
            }
        }
        finalization.cancelled |= cancellation.is_cancelled();
        if finalization.cancelled {
            finalization.candidates.clear();
            finalization.frontiers.clear();
            finalization.lexical_frontiers.clear();
            for target in &mut finalization.targets {
                target
                    .completion
                    .include_reason(ResolutionIncompleteReason::Cancelled);
            }
        }

        let mut finish_observed_cancellation = false;
        let mut completions = Vec::with_capacity(finalization.targets.len());
        for target in finalization.targets {
            let (completion, observed_cancellation) = target
                .completion
                .finish(cancellation, &mut finalization.completion_work);
            finish_observed_cancellation |= observed_cancellation;
            completions.push(completion);
        }
        if finish_observed_cancellation || cancellation.is_cancelled() {
            finalization.candidates.clear();
            finalization.frontiers.clear();
            finalization.lexical_frontiers.clear();
            for completion in &mut completions {
                include_cancelled_in_finished_completion(
                    completion,
                    cancellation,
                    &mut finalization.completion_work,
                );
            }
        }
        // Cover cancellation arriving after the last canonical reason drain
        // but before the batch is moved to its caller.
        if cancellation.is_cancelled() {
            finalization.candidates.clear();
            finalization.frontiers.clear();
            finalization.lexical_frontiers.clear();
            for completion in &mut completions {
                include_cancelled_in_finished_completion(
                    completion,
                    cancellation,
                    &mut finalization.completion_work,
                );
            }
        }
        Ok(ReverseCandidateBatch {
            candidates: finalization.candidates,
            frontiers: finalization.frontiers,
            lexical_frontiers: finalization.lexical_frontiers,
            completions: completions.into_boxed_slice(),
        })
    }

    pub(super) fn reverse_candidate_references(
        &mut self,
        definitions: &[(SemanticId, BindingNodeId)],
        cancellation: &CancellationToken,
    ) -> StoreResult<ReverseCandidateBatch> {
        let mut exclusions = ReverseCandidateGapExclusionPlan::default();
        self.reverse_candidate_references_with_gap_exclusions(
            definitions,
            &mut exclusions,
            cancellation,
        )
    }

    pub(super) fn reverse_candidate_references_with_gap_exclusions(
        &mut self,
        definitions: &[(SemanticId, BindingNodeId)],
        exclusions: &mut ReverseCandidateGapExclusionPlan,
        cancellation: &CancellationToken,
    ) -> StoreResult<ReverseCandidateBatch> {
        let InitializedReverseCandidateBatch {
            mut targets,
            mut frontier,
        } = match Self::initialize_reverse_candidate_batch(definitions, cancellation) {
            ReverseCandidateInitialization::Ready(initialized) => initialized,
            ReverseCandidateInitialization::Cancelled(answer) => return Ok(answer),
        };
        let mut frontier_observations = 0_usize;
        let mut endpoint_classifications = map_with_capacity(definitions.len().saturating_mul(4));
        let mut arena = map_with_capacity(definitions.len().saturating_mul(4));
        let mut candidates = Vec::new();
        let mut frontiers: Vec<ReverseCandidateFrontier> = Vec::new();
        let mut frontier_ids_by_key: HashMap<(usize, DerivationKey), Vec<usize>> =
            map_with_capacity(definitions.len().saturating_mul(4));
        let mut lexical_frontiers = Vec::new();
        let mut lexical_frontier_ids_by_key =
            map_with_capacity(definitions.len().saturating_mul(4));
        let mut composition_attempts = 0_usize;
        let mut completion_work = 0_usize;
        let mut accounted_hydrated_completions = crate::hash::HashSet::default();
        let mut candidate_completion = OperationCandidateCompletionLedger::new(targets.len());
        let mut cancelled = false;
        while !frontier.is_empty() {
            if cancellation.is_cancelled() {
                cancelled = true;
                break;
            }

            let current = std::mem::take(&mut frontier);
            self.classify_reverse_frontiers(ReverseFrontierContext {
                definitions,
                current: &current,
                endpoint_classifications: &mut endpoint_classifications,
                frontiers: &mut frontiers,
                frontier_ids_by_key: &mut frontier_ids_by_key,
                lexical_frontiers: &mut lexical_frontiers,
                lexical_frontier_ids_by_key: &mut lexical_frontier_ids_by_key,
                cancellation,
                observations: &mut frontier_observations,
                cancelled: &mut cancelled,
            })?;
            if cancelled {
                break;
            }
            let mut expandable = Vec::with_capacity(current.len());
            for state in current {
                // Match the established sequential completion fold: a path
                // admitted for expansion contributes once when composed and
                // once when its next worklist state is processed. The second
                // operand deliberately canonicalizes a publicly constructible
                // noncanonical box, while a Subsumed/Uncertified path remains
                // a sole operand.
                cancelled |= targets[state.target].completion.include(
                    state.path.completion(),
                    cancellation,
                    &mut completion_work,
                );
                let classification = endpoint_classifications
                    .get(&state.path.start().node())
                    .copied()
                    .expect("every current reverse endpoint was classified");
                if endpoint_is_balanced(state.path.start())
                    && let Some(reference) = classification.reference()
                {
                    if self.reverse_target == Some(definitions[state.target].0)
                        && !self.source().admits_reverse_reference(reference)
                    {
                        continue;
                    }
                    candidates.push(ReverseCandidateReference {
                        target: state.target,
                        reference,
                        node: state.path.start().node(),
                    });
                } else {
                    expandable.push(state);
                }
            }
            if cancelled {
                break;
            }
            if expandable.is_empty() {
                continue;
            }

            let mut matches = Vec::new();
            for (page_index, state_page) in expandable.chunks(MAX_SOURCE_ROWS_PER_BATCH).enumerate()
            {
                let request_base = page_index * MAX_SOURCE_ROWS_PER_BATCH;
                let mut request_page = Vec::with_capacity(state_page.len());
                for (request_ordinal, state) in state_page.iter().enumerate() {
                    let mut clone_cancelled = || {
                        frontier_observations = frontier_observations
                            .checked_add(1)
                            .expect("reverse request clone work must fit usize");
                        frontier_observations.is_multiple_of(CANCELLATION_QUANTUM)
                            && cancellation.is_cancelled()
                    };
                    let Some(endpoint) = state.path.start().clone_with_poll(&mut clone_cancelled)
                    else {
                        cancelled = true;
                        break;
                    };
                    request_page.push(BatchCandidateRequest::new(request_ordinal, endpoint));
                }
                if cancelled {
                    break;
                }
                let mut seen_page_matches = HashSet::default();
                let outcome = self
                    .source
                    .visit_reverse_candidate_match_pages_with_gap_exclusions(
                        &request_page,
                        exclusions,
                        cancellation,
                        &mut |page| {
                            append_streamed_candidate_match_page(
                                &mut matches,
                                page,
                                request_base,
                                state_page.len(),
                                &mut seen_page_matches,
                                cancellation,
                                &mut composition_attempts,
                                &mut cancelled,
                            )
                        },
                    )?;
                let (unconditional_completion, branch_completions) = outcome.into_parts();
                let (newly_accounted_targets, completion_cancelled) = candidate_completion
                    .observe(
                        "reverse",
                        unconditional_completion,
                        state_page.iter().map(|state| state.target),
                        cancellation,
                        &mut completion_work,
                    )?;
                cancelled |= completion_cancelled;
                for target_index in newly_accounted_targets {
                    let inventory_completion = self.source().scope_reverse_inventory_completion(
                        candidate_completion.semantic_completion(),
                    );
                    cancelled |= targets[target_index].completion.include(
                        &inventory_completion,
                        cancellation,
                        &mut completion_work,
                    );
                }
                for (page_ordinal, branch_completion) in branch_completions.iter().enumerate() {
                    let request_ordinal = request_base + page_ordinal;
                    let target = expandable[request_ordinal].target;
                    cancelled |= targets[target].completion.include(
                        branch_completion,
                        cancellation,
                        &mut completion_work,
                    );
                }
                if cancellation.is_cancelled() {
                    cancelled = true;
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
                include_matched_hydrated_completions_after_cancellation(
                    &mut targets,
                    &expandable,
                    &matches,
                    &arena,
                    &mut accounted_hydrated_completions,
                    cancellation,
                    &mut composition_attempts,
                );
                break;
            }

            if !canonicalize_streamed_candidate_matches(
                &mut matches,
                cancellation,
                &mut composition_attempts,
            )? {
                cancelled = true;
                include_matched_hydrated_completions_after_cancellation(
                    &mut targets,
                    &expandable,
                    &matches,
                    &arena,
                    &mut accounted_hydrated_completions,
                    cancellation,
                    &mut composition_attempts,
                );
                break;
            }

            let mut hydration_set = BTreeSet::new();
            for matched in &matches {
                if poll_reverse_completion(cancellation, &mut composition_attempts) {
                    cancelled = true;
                    break;
                }
                if !arena.contains_key(&matched.candidate()) {
                    hydration_set.insert(matched.candidate());
                }
            }
            if cancelled {
                include_matched_hydrated_completions_after_cancellation(
                    &mut targets,
                    &expandable,
                    &matches,
                    &arena,
                    &mut accounted_hydrated_completions,
                    cancellation,
                    &mut composition_attempts,
                );
                break;
            }
            let mut to_hydrate = Vec::with_capacity(hydration_set.len());
            while let Some(candidate) = hydration_set.pop_first() {
                if poll_reverse_completion(cancellation, &mut composition_attempts) {
                    cancelled = true;
                    break;
                }
                to_hydrate.push(candidate);
            }
            if cancelled {
                include_matched_hydrated_completions_after_cancellation(
                    &mut targets,
                    &expandable,
                    &matches,
                    &arena,
                    &mut accounted_hydrated_completions,
                    cancellation,
                    &mut composition_attempts,
                );
                break;
            }
            if !to_hydrate.is_empty() {
                for requested in to_hydrate.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
                    let hydrated = self
                        .source()
                        .hydrate_candidate_paths(requested, cancellation)?;
                    let mut hydration_cancelled = cancellation.is_cancelled();
                    if !hydration_cancelled {
                        hydration_cancelled = validate_hydration_with_poll(
                            requested,
                            &hydrated,
                            cancellation,
                            &mut composition_attempts,
                        )?
                        .is_none();
                    }
                    if hydration_cancelled {
                        include_returned_hydrated_completions_after_cancellation(
                            &mut targets,
                            &expandable,
                            &matches,
                            &hydrated,
                            &mut accounted_hydrated_completions,
                            cancellation,
                            &mut composition_attempts,
                        );
                        include_matched_hydrated_completions_after_cancellation(
                            &mut targets,
                            &expandable,
                            &matches,
                            &arena,
                            &mut accounted_hydrated_completions,
                            cancellation,
                            &mut composition_attempts,
                        );
                        cancelled = true;
                        break;
                    }
                    for (identity, path) in hydrated {
                        hydration_cancelled |=
                            poll_reverse_completion(cancellation, &mut composition_attempts);
                        assert!(
                            arena.insert(identity, path).is_none(),
                            "a reverse candidate path is hydrated at most once per operation"
                        );
                    }
                    hydration_cancelled |= cancellation.is_cancelled();
                    if hydration_cancelled {
                        include_matched_hydrated_completions_after_cancellation(
                            &mut targets,
                            &expandable,
                            &matches,
                            &arena,
                            &mut accounted_hydrated_completions,
                            cancellation,
                            &mut composition_attempts,
                        );
                        cancelled = true;
                        break;
                    }
                }
                if cancelled {
                    break;
                }
            }

            for matched in &matches {
                composition_attempts += 1;
                if composition_attempts.is_multiple_of(CANCELLATION_QUANTUM)
                    && cancellation.is_cancelled()
                {
                    cancelled = true;
                    break;
                }
                let parent = &expandable[matched.request_ordinal()];
                let candidate = arena.get(&matched.candidate()).ok_or_else(|| {
                    StoreError::new(format!(
                        "reverse candidate {:?} was matched but not hydrated",
                        matched.candidate()
                    ))
                })?;
                let composition = candidate.concatenate_with_poll(&parent.path, &mut || {
                    composition_attempts = composition_attempts
                        .checked_add(1)
                        .expect("reverse path composition work must fit usize");
                    composition_attempts.is_multiple_of(CANCELLATION_QUANTUM)
                        && cancellation.is_cancelled()
                });
                let path = match composition {
                    None => {
                        cancelled = true;
                        break;
                    }
                    Some(Ok(path)) => path,
                    Some(Err(_)) => continue,
                };
                let Some(path) = path.canonicalized_observations_with_poll(&mut || {
                    composition_attempts = composition_attempts
                        .checked_add(1)
                        .expect("reverse observation canonicalization work must fit usize");
                    composition_attempts.is_multiple_of(CANCELLATION_QUANTUM)
                        && cancellation.is_cancelled()
                }) else {
                    cancelled = true;
                    break;
                };
                let target = &mut targets[parent.target];
                cancelled |= target.completion.include(
                    path.completion(),
                    cancellation,
                    &mut completion_work,
                );
                accounted_hydrated_completions.insert((parent.target, matched.candidate()));
                if cancelled {
                    break;
                }
                let decision = target.certifier.admit_with_poll(
                    &parent.saturation,
                    matched.candidate().path(),
                    &path,
                    &mut || {
                        composition_attempts = composition_attempts
                            .checked_add(1)
                            .expect("reverse cycle certification work must fit usize");
                        composition_attempts.is_multiple_of(CANCELLATION_QUANTUM)
                            && cancellation.is_cancelled()
                    },
                );
                let Some(decision) = decision else {
                    cancelled = true;
                    break;
                };
                match decision {
                    SaturationDecision::Expand(saturation) => frontier.push(ReverseWorkPath {
                        target: parent.target,
                        path,
                        saturation,
                    }),
                    SaturationDecision::Subsumed => {}
                    SaturationDecision::Uncertified(gap) => {
                        target.completion.include_reason(
                            ResolutionIncompleteReason::CyclicExpansion(gap.transition()),
                        );
                    }
                }
            }
            if cancellation.is_cancelled() {
                cancelled = true;
            }
            if cancelled {
                include_matched_hydrated_completions_after_cancellation(
                    &mut targets,
                    &expandable,
                    &matches,
                    &arena,
                    &mut accounted_hydrated_completions,
                    cancellation,
                    &mut composition_attempts,
                );
                break;
            }
        }

        Self::finish_reverse_candidate_batch(
            ReverseCandidateFinalization {
                candidates,
                frontiers,
                lexical_frontiers,
                targets,
                completion_work,
                composition_attempts,
                cancelled,
            },
            cancellation,
        )
    }

    /// Resolve every reference in deterministic fragment-major chunks.
    ///
    /// A visitor sees a batch only after all of its source calls, compositions,
    /// and shadow selection succeed. The callback is a staging boundary: it
    /// must not make results durable until this method returns successfully and
    /// its summary is acceptable to the consumer. The next batch is not
    /// started until the callback returns, so broad traversal retains neither
    /// every reference seed, a workspace graph, nor a whole-workspace answer
    /// list.
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

pub(super) fn validate_reverse_reference_seeds(
    requested: &[ReverseReferenceSeedRequest],
    issued: &[ReferenceSeed],
) -> StoreResult<()> {
    let mut expected = requested
        .iter()
        .map(|request| (request.reference(), request.expected_node()))
        .collect::<Vec<_>>();
    expected.sort_unstable();
    let mut returned = issued
        .iter()
        .map(|seed| (seed.reference(), seed.node()))
        .collect::<Vec<_>>();
    returned.sort_unstable();
    if returned != expected {
        return Err(StoreError::new(format!(
            "reverse reference seed mismatch: requested {expected:?}, returned {returned:?}"
        )));
    }
    Ok(())
}

fn identity_seed_path_id(seed: &ReferenceSeed) -> DerivationKey {
    let mut hasher = CanonicalHasher::new(b"bifrost-resolution-identity-seed-path:v1");
    hasher.field("fragment", &seed.fragment().as_bytes());
    hasher.field("reference", &seed.reference().as_bytes());
    hasher.field("node", &seed.node().as_bytes());
    DerivationKey::new(hasher.finish())
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

fn empty_reference_search(completion: ResolutionCompletion) -> ReferenceSearchAnswer {
    ReferenceSearchAnswer::new(Vec::new(), Vec::new(), completion)
}

fn finish_cancelled_reference_search_completion(
    completion: BatchCompletionLedger,
    mut returned_evidence: CancellationEvidenceLedger,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> ResolutionCompletion {
    let (semantic, _) = completion.finish_semantic(cancellation, work);
    returned_evidence.include(&semantic, cancellation, work);
    returned_evidence.finish(true, cancellation, work).0
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use super::super::engine::{PreloadedFragment, PreloadedFragmentSource, ResolutionEngine};
    use super::super::model::{
        BindingNodeId, BindingNodeKind, PrecedenceStep, ResolutionSlotValue, ResolutionTypeRef,
        StackPattern, StackVariableId, TypeTransferValueTransform, WitnessStep,
    };
    use super::*;
    use crate::analyzer::structural::PrecedenceTier;
    use brokk_bifrost_core::analyzer::usages::receiver_analysis::{
        ReceiverAnalysisBudget, ReceiverAnalysisWork, ReceiverBudgetLimit,
    };
    use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;

    fn semantic(value: &str) -> SemanticId {
        SemanticId::for_test(value)
    }

    fn runtime_type(value: &str) -> ResolutionSlotValue {
        ResolutionSlotValue::runtime(ResolutionTypeRef::new(semantic(value), 0), false)
    }

    fn fragment(value: &str) -> BindingFragmentId {
        BindingFragmentId::for_test(value)
    }

    fn node(value: &str) -> BindingNodeId {
        BindingNodeId::for_test(value)
    }

    fn path_id(value: &str) -> PartialPathId {
        PartialPathId::for_test(value)
    }

    /// One seeded alternative's derivation key, from a label. A seeded key
    /// names no mount and no catalog entry, so a fixture only needs two
    /// labels to give two keys.
    fn derivation_key(value: &str) -> DerivationKey {
        let mut hasher = CanonicalHasher::new(b"bifrost-fixture-derivation-key:v1");
        hasher.field("label", value.as_bytes());
        DerivationKey::new(hasher.finish())
    }

    fn seeded_partial_path(key: DerivationKey, path: PartialPath) -> SeededPartialPath {
        SeededPartialPath::new_with_poll(key, path, &mut || false)
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

    fn symbol_endpoint(
        node: BindingNodeId,
        symbols: impl Into<Box<[SemanticId]>>,
    ) -> EndpointSignature {
        EndpointSignature::new(
            node,
            StackPattern::closed(symbols),
            StackPattern::closed(Vec::new()),
        )
    }

    fn open_symbol_endpoint(
        node: BindingNodeId,
        symbols: impl Into<Box<[SemanticId]>>,
        tail: &str,
    ) -> EndpointSignature {
        EndpointSignature::new(
            node,
            StackPattern::open(symbols, StackVariableId::for_test(tail)),
            StackPattern::closed(Vec::new()),
        )
    }

    #[test]
    fn borrowed_inventory_coverage_matches_joint_exact_multiset_accounting() {
        let live = CancellationToken::new();
        let owner = fragment("borrowed-gap-owner");
        let boundary = node("borrowed-gap-boundary");
        let lookup = semantic("borrowed-gap-lookup");
        let reason =
            ResolutionIncompleteReason::UnsupportedSemantic(semantic("borrowed-gap-reason"));
        let rows = (0..4)
            .map(|index| {
                ReverseCandidateGapRow::new(
                    ReverseCandidateGapIdentity::new(
                        owner,
                        semantic(&format!("borrowed-gap-{index}")),
                    ),
                    if index < 2 {
                        ReverseCandidateGapLocation::Inventory
                    } else {
                        ReverseCandidateGapLocation::Endpoint {
                            endpoint: boundary,
                            lookup: Some(lookup),
                        }
                    },
                    reason,
                )
            })
            .collect::<Vec<_>>();
        let build = |rows: &[ReverseCandidateGapRow]| {
            let mut builder = ReverseCandidateGapCoverageBuilder::default();
            for &row in rows {
                builder.push(row).unwrap();
            }
            builder
        };
        let joint = build(&rows).finish(&live).unwrap().0;
        let inventory = build(&rows[..2])
            .finish_with_authority(joint.fingerprint.0, &live)
            .unwrap()
            .0;
        let endpoints = build(&rows[2..])
            .finish_with_authority(joint.fingerprint.0, &live)
            .unwrap()
            .0;
        let (split, cancelled) = endpoints.with_inventory(&inventory, &live).unwrap();
        assert!(!cancelled);
        assert!(std::ptr::eq(split.inventory, &inventory.inventory));
        assert!(std::ptr::eq(
            split.inventory_by_identity,
            &inventory.by_identity
        ));
        assert!(std::ptr::eq(split.endpoints, &endpoints.endpoints));
        for excluded in [
            vec![rows[0].identity, rows[2].identity],
            rows.iter().map(|row| row.identity).collect(),
        ] {
            let mut joint_plan = ReverseCandidateGapExclusionPlan::new(excluded.clone());
            let mut split_plan = ReverseCandidateGapExclusionPlan::new(excluded.clone());
            assert!(joint.prepare_exclusions(&mut joint_plan, &live).unwrap());
            assert!(split.prepare_exclusions(&mut split_plan, &live).unwrap());
            let expected = if excluded.len() == 4 {
                ResolutionCompletion::Complete
            } else {
                ResolutionCompletion::incomplete([reason])
            };
            assert_eq!(
                split.filtered_inventory_completion(&split_plan).unwrap(),
                &expected
            );
            assert_eq!(
                split.filtered_inventory_completion(&split_plan).unwrap(),
                joint.filtered_inventory_completion(&joint_plan).unwrap()
            );
            for (request, expected_branch) in [
                (symbol_endpoint(boundary, vec![lookup]), expected),
                (endpoint(boundary), ResolutionCompletion::Complete),
                (
                    symbol_endpoint(boundary, vec![semantic("other-lookup")]),
                    ResolutionCompletion::Complete,
                ),
            ] {
                let split_result = split
                    .filtered_branch_completion_for_with_poll(&request, &split_plan, &live, &mut 0)
                    .unwrap();
                assert_eq!(split_result, (expected_branch, false));
                assert_eq!(
                    split_result,
                    joint
                        .filtered_branch_completion_for_with_poll(
                            &request,
                            &joint_plan,
                            &live,
                            &mut 0
                        )
                        .unwrap()
                );
            }
        }
        let duplicate = [ReverseCandidateGapRow::new(
            rows[0].identity,
            rows[2].location,
            reason,
        )];
        let duplicate = build(&duplicate)
            .finish_with_authority(joint.fingerprint.0, &live)
            .unwrap()
            .0;
        assert!(
            duplicate
                .with_inventory(&inventory, &live)
                .err()
                .unwrap()
                .to_string()
                .contains("duplicate selected reverse candidate gap")
        );
    }

    #[test]
    #[should_panic(
        expected = "candidate inventory and endpoint buckets must share one selected authority"
    )]
    fn borrowed_inventory_coverage_rejects_another_selected_authority() {
        let live = CancellationToken::new();
        let inventory = ReverseCandidateGapCoverageBuilder::default()
            .finish_with_authority([1; 32], &live)
            .unwrap()
            .0;
        let endpoints = ReverseCandidateGapCoverageBuilder::default()
            .finish_with_authority([2; 32], &live)
            .unwrap()
            .0;
        endpoints.with_inventory(&inventory, &live).unwrap();
    }

    #[test]
    fn authority_gap_finalization_preserves_evidence_and_polls_without_hashing_rows() {
        let owner = fragment("authority-gap-owner");
        let boundary = node("authority-gap-boundary");
        let lookup = semantic("authority-gap-lookup");
        let inventory_reason =
            ResolutionIncompleteReason::UnsupportedSemantic(semantic("inventory-gap"));
        let endpoint_reason =
            ResolutionIncompleteReason::UnsupportedSemantic(semantic("endpoint-gap"));
        let rows = (0..515)
            .map(|index| {
                let (location, reason) = match index {
                    512 => (
                        ReverseCandidateGapLocation::Endpoint {
                            endpoint: boundary,
                            lookup: None,
                        },
                        endpoint_reason,
                    ),
                    513.. => (
                        ReverseCandidateGapLocation::Endpoint {
                            endpoint: boundary,
                            lookup: Some(lookup),
                        },
                        endpoint_reason,
                    ),
                    _ => (ReverseCandidateGapLocation::Inventory, inventory_reason),
                };
                ReverseCandidateGapRow::new(
                    ReverseCandidateGapIdentity::new(owner, semantic(&format!("gap-{index}"))),
                    location,
                    reason,
                )
            })
            .collect::<Vec<_>>();
        let build = || {
            let mut builder = ReverseCandidateGapCoverageBuilder::default();
            for &row in &rows {
                builder.push(row).unwrap();
            }
            builder
        };
        let live = CancellationToken::new();
        for checks in [1, 2, 4, 64] {
            REVERSE_CANDIDATE_GAP_HASH_ROWS.with(|count| count.set(0));
            let (hashed, hashed_cancelled) = build()
                .finish(&CancellationToken::cancel_after_checks_for_test(checks))
                .unwrap();
            assert_eq!(REVERSE_CANDIDATE_GAP_HASH_ROWS.with(Cell::get), rows.len());
            REVERSE_CANDIDATE_GAP_HASH_ROWS.with(|count| count.set(0));
            let (authorized, authorized_cancelled) = build()
                .finish_with_authority(
                    hashed.fingerprint.0,
                    &CancellationToken::cancel_after_checks_for_test(checks),
                )
                .unwrap();
            assert_eq!(REVERSE_CANDIDATE_GAP_HASH_ROWS.with(Cell::get), 0);
            assert_eq!(hashed_cancelled, authorized_cancelled);
            assert_eq!(hashed.fingerprint, authorized.fingerprint);
            for coverage in [&hashed, &authorized] {
                assert_eq!(coverage.by_identity.len(), rows.len());
                for row in &rows {
                    let contribution = &coverage.by_identity[&row.identity];
                    assert_eq!(contribution.location, row.location);
                    assert_eq!(contribution.reason, row.reason);
                }
                assert_eq!(coverage.inventory.counts[&inventory_reason], 512);
                assert_eq!(
                    coverage.inventory_completion(),
                    &ResolutionCompletion::Incomplete(vec![inventory_reason].into())
                );
                let branch = symbol_endpoint(boundary, vec![lookup]);
                let mut work = 0;
                assert_eq!(
                    coverage.branch_completion_for_with_poll(&branch, &live, &mut work),
                    (
                        ResolutionCompletion::Incomplete(vec![endpoint_reason].into()),
                        false
                    )
                );
                // Removing one of several equal reasons cannot erase its siblings.
                let mut partial = ReverseCandidateGapExclusionPlan::new([
                    rows[0].identity,
                    rows[512].identity,
                    rows[513].identity,
                ]);
                assert!(coverage.prepare_exclusions(&mut partial, &live).unwrap());
                assert_eq!(
                    coverage.filtered_inventory_completion(&partial).unwrap(),
                    coverage.inventory_completion()
                );
                assert_eq!(
                    coverage
                        .filtered_branch_completion_for_with_poll(
                            &branch, &partial, &live, &mut work
                        )
                        .unwrap(),
                    (
                        ResolutionCompletion::Incomplete(vec![endpoint_reason].into()),
                        false
                    )
                );
                let mut all =
                    ReverseCandidateGapExclusionPlan::new(rows.iter().map(|row| row.identity));
                assert!(coverage.prepare_exclusions(&mut all, &live).unwrap());
                assert_eq!(
                    coverage.filtered_inventory_completion(&all).unwrap(),
                    &ResolutionCompletion::Complete
                );
                assert_eq!(
                    coverage
                        .filtered_branch_completion_for_with_poll(&branch, &all, &live, &mut work)
                        .unwrap(),
                    (ResolutionCompletion::Complete, false)
                );
            }
        }
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
        first_fragment: BindingFragmentId,
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
            first_fragment,
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
                derivation_key("seeded-first-owner-alternative"),
                path(
                    fixture.reference_node,
                    fixture.first_owner,
                    ResolutionCompletion::Complete,
                ),
            ),
            seeded_partial_path(
                derivation_key("seeded-second-owner-alternative"),
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
            derivation_key("polled-seeded-request-first"),
            path(
                fixture.reference_node,
                fixture.first_owner,
                ResolutionCompletion::Complete,
            ),
        );
        let second = seeded_partial_path(
            derivation_key("polled-seeded-request-second"),
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
                    ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::for_test(
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
            derivation_key("polled-seeded-request-large"),
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
            derivation_key("empty-incomplete-seeded-request"),
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
            derivation_key("wrong-seed-node"),
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
            derivation_key("unbalanced-seed-start"),
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
        let shared_id = derivation_key("conflicting-seed-id");
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
            derivation_key("incomplete-seeded-alternative"),
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
                derivation_key("explicit-identity-seed"),
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
            .resolve_reference_batch(&ReferenceSeedBatch::single(seed), &CancellationToken::new())
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
        FailOnSecondReverseMatch,
        EnumerationGapWithoutSeeds,
        EmptyForwardMatchWithGap,
        CancelOnForwardMatchWithGap,
        ForwardMatchWithGap,
        EmptyReverseMatchWithGap,
        CancelOnReverseMatchWithGap,
        ReverseMatchWithGap,
        ReverseMatchWithCancelledEvidence,
        EmptyTypeTransferWithGap,
        MissingReverseSeed,
        WrongReverseSeedSemantic,
        WrongReverseSeedNode,
        ReverseSeedOrder,
        CancelOnReverseSeedIssueWithGap,
        CancelAfterMemberScopeClassification,
        CancelAfterFirstForwardMatchPage,
        CancelAfterFirstReverseMatchPage,
        ReverseForwardCandidateStream,
        ReverseReverseCandidateStream,
        DuplicateForwardCandidate,
        DuplicateReverseCandidate,
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
        fn selection_authority(&self) -> Option<SeedReadAuthority> {
            None
        }

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
            let mut seeds = self
                .inner
                .issue_reverse_reference_seeds(requests, cancellation)?;
            match self.fault {
                TestFault::MissingReverseSeed => {
                    seeds.pop();
                }
                TestFault::WrongReverseSeedSemantic if !seeds.is_empty() => {
                    let fragment = seeds[0].fragment();
                    let node = seeds[0].node();
                    let completion = seeds[0].completion().clone();
                    seeds[0] = ReferenceSeed::new(
                        fragment,
                        ResolutionQuery::new(semantic("wrong-issued-reference")),
                        node,
                        completion,
                    );
                }
                TestFault::WrongReverseSeedNode if !seeds.is_empty() => {
                    let fragment = seeds[0].fragment();
                    let query = seeds[0].query();
                    let completion = seeds[0].completion().clone();
                    seeds[0] = ReferenceSeed::new(
                        fragment,
                        query,
                        node("wrong-issued-reference-node"),
                        completion,
                    );
                }
                TestFault::ReverseSeedOrder => seeds.reverse(),
                _ => {}
            }
            if self.fault == TestFault::CancelOnReverseSeedIssueWithGap {
                for seed in &mut seeds {
                    *seed = ReferenceSeed::new(
                        seed.fragment(),
                        seed.query(),
                        seed.node(),
                        seed.completion()
                            .combine(&ResolutionCompletion::incomplete([
                                ResolutionIncompleteReason::UnsupportedSemantic(semantic(
                                    "cancelled-reverse-seed-gap",
                                )),
                            ])),
                    );
                }
                cancellation.cancel();
            }
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
            if self.fault == TestFault::CancelAfterMemberScopeClassification
                && classified
                    .iter()
                    .any(|row| row.member_scope_owner().is_some())
            {
                cancellation.cancel();
            }
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
            if self.fault == TestFault::FailOnSecondReverseMatch && call == 2 {
                return Err(StoreError::new(
                    "injected second-level reverse source failure",
                ));
            }
            if matches!(
                self.fault,
                TestFault::EmptyReverseMatchWithGap | TestFault::CancelOnReverseMatchWithGap
            ) {
                let completion = ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(semantic(
                        "reverse-candidate-coverage-gap",
                    )),
                ]);
                if self.fault == TestFault::CancelOnReverseMatchWithGap {
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
                .match_reverse_candidates(requests, cancellation)?;
            if self.fault == TestFault::ReverseMatchWithCancelledEvidence {
                let (matches, _, branch_completions) = outcome.into_parts();
                return Ok(BatchCandidateOutcome::new(
                    requests.len(),
                    matches,
                    cancelled_completion(),
                    branch_completions,
                ));
            }
            if self.fault == TestFault::ReverseMatchWithGap {
                let gap = ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(semantic(
                        "reverse-candidate-sibling-gap",
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
            if self.fault == TestFault::CancelAfterFirstForwardMatchPage {
                self.forward_matches.set(self.forward_matches.get() + 1);
                self.forward_match_batch_sizes
                    .borrow_mut()
                    .push(requests.len());
                let mut first = true;
                return self.inner.visit_forward_candidate_match_pages(
                    requests,
                    cancellation,
                    &mut |page| {
                        self.forward_match_output_page_sizes
                            .borrow_mut()
                            .push(page.len());
                        let keep_going = visitor(page)?;
                        if first {
                            first = false;
                            cancellation.cancel();
                            return Ok(false);
                        }
                        Ok(keep_going)
                    },
                );
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
            if matches!(
                self.fault,
                TestFault::ReverseReverseCandidateStream | TestFault::DuplicateReverseCandidate
            ) {
                self.reverse_matches.set(self.reverse_matches.get() + 1);
                self.reverse_match_batch_sizes
                    .borrow_mut()
                    .push(requests.len());
                let mut rows = Vec::new();
                let outcome = self.inner.visit_reverse_candidate_match_pages(
                    requests,
                    cancellation,
                    &mut |page| {
                        rows.extend_from_slice(page);
                        Ok(true)
                    },
                )?;
                if self.fault == TestFault::ReverseReverseCandidateStream {
                    rows.reverse();
                } else if let Some(&first) = rows.first() {
                    rows.push(first);
                }
                for page in rows.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
                    self.reverse_match_output_page_sizes
                        .borrow_mut()
                        .push(page.len());
                    if !visitor(page)? {
                        break;
                    }
                }
                return Ok(outcome);
            }
            if self.fault == TestFault::CancelAfterFirstReverseMatchPage {
                self.reverse_matches.set(self.reverse_matches.get() + 1);
                self.reverse_match_batch_sizes
                    .borrow_mut()
                    .push(requests.len());
                let mut first = true;
                return self.inner.visit_reverse_candidate_match_pages(
                    requests,
                    cancellation,
                    &mut |page| {
                        self.reverse_match_output_page_sizes
                            .borrow_mut()
                            .push(page.len());
                        let keep_going = visitor(page)?;
                        if first {
                            first = false;
                            cancellation.cancel();
                            return Ok(false);
                        }
                        Ok(keep_going)
                    },
                );
            }
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
            if self.fault == TestFault::EmptyTypeTransferWithGap {
                return Ok(ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(semantic(
                        "type-transfer-coverage-gap",
                    )),
                ]));
            }
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
        fn selection_authority(&self) -> Option<SeedReadAuthority> {
            None
        }

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

    fn drive_experimental_forward<S: BatchResolutionFragmentSource + ?Sized>(
        engine: &BatchResolutionEngine<'_, S>,
        requests: &[SeededReferenceRequest],
        cache: &mut ForwardCandidateArtifactCache,
        cancellation: &CancellationToken,
    ) -> StoreResult<ReferenceBatchAnswer> {
        drive_experimental_forward_start(
            engine,
            DemandForwardBatchFrame::start(engine, requests, cancellation),
            cache,
            cancellation,
        )
    }

    fn drive_experimental_reverse<S: BatchResolutionFragmentSource + ?Sized>(
        engine: &mut BatchResolutionEngine<'_, S>,
        definitions: &[(SemanticId, BindingNodeId)],
        exclusions: ReverseCandidateGapExclusionPlan,
        cancellation: &CancellationToken,
    ) -> StoreResult<ReverseCandidateBatch> {
        let mut frame = match ExperimentalReverseBatchFrame::start(
            engine,
            definitions.to_vec(),
            exclusions,
            cancellation,
        ) {
            ExperimentalReverseBatchStart::Running(frame) => frame,
            ExperimentalReverseBatchStart::Ready(answer) => return Ok(answer),
        };
        for _ in 0..10_000 {
            match frame.poll(engine, cancellation, &mut |_| {
                Ok(ExperimentalReverseReadiness::AwaitingDependencies)
            })? {
                ExperimentalReverseBatchPoll::Ready(answer) => return Ok(answer),
                ExperimentalReverseBatchPoll::Continue => continue,
                ExperimentalReverseBatchPoll::AwaitingDependencies => {}
            }
            let requests = frame.pending_requests().to_vec();
            let targets = frame.pending_page().target_indices.to_vec();
            let exclusions = frame.pending_page().exclusions.identities().to_vec();
            assert!(!requests.is_empty());
            assert!(requests.len() <= MAX_SOURCE_ROWS_PER_BATCH);
            assert_eq!(requests.len(), targets.len());
            let retained_work = (
                frame.frontier_observations,
                frame.finalization.completion_work,
                frame.finalization.composition_attempts,
                frame.arena.len(),
            );
            for _ in 0..3 {
                let mut tasks = vec![frame];
                frame = tasks.pop().unwrap();
                assert!(matches!(
                    frame.poll(engine, cancellation, &mut |page| {
                        assert_eq!(page.requests, requests);
                        assert_eq!(page.target_indices, targets);
                        assert_eq!(page.definitions, definitions);
                        assert_eq!(page.exclusions.identities(), exclusions);
                        Ok(ExperimentalReverseReadiness::AwaitingDependencies)
                    })?,
                    ExperimentalReverseBatchPoll::AwaitingDependencies
                ));
                assert_eq!(
                    (
                        frame.frontier_observations,
                        frame.finalization.completion_work,
                        frame.finalization.composition_attempts,
                        frame.arena.len(),
                    ),
                    retained_work,
                    "pending relations do not replay work or hydrate candidates"
                );
            }
            match frame.poll(engine, cancellation, &mut |page| {
                assert_eq!(page.requests, requests);
                Ok(ExperimentalReverseReadiness::Ready)
            })? {
                ExperimentalReverseBatchPoll::Ready(answer) => return Ok(answer),
                ExperimentalReverseBatchPoll::Continue => {}
                ExperimentalReverseBatchPoll::AwaitingDependencies => panic!("ready reverse page"),
            }
        }
        panic!("finite reverse fixture exceeded its driver guard");
    }

    #[test]
    fn experimental_reverse_frame_matches_eager_reads_results_and_cancellation() {
        let fixture = shared_fixture(false);
        let definitions = [(fixture.target, fixture.target_node)];
        for fault in [
            TestFault::None,
            TestFault::ReverseMatchWithGap,
            TestFault::CancelOnReverseMatchWithGap,
            TestFault::ReverseMatchWithCancelledEvidence,
            TestFault::CancelOnHydration,
            TestFault::ReverseReverseCandidateStream,
        ] {
            let eager_source = FaultingSource::new(&fixture.source, fault);
            let frame_source = FaultingSource::new(&fixture.source, fault);
            let eager_token = CancellationToken::new();
            let frame_token = CancellationToken::new();
            let eager = BatchResolutionEngine::new(&eager_source)
                .reverse_candidate_references(&definitions, &eager_token)
                .unwrap();
            let actual = drive_experimental_reverse(
                &mut BatchResolutionEngine::new(&frame_source),
                &definitions,
                ReverseCandidateGapExclusionPlan::default(),
                &frame_token,
            )
            .unwrap();
            assert_eq!(actual.into_parts(), eager.into_parts(), "fault: {fault:?}");
            assert_eq!(frame_token.is_cancelled(), eager_token.is_cancelled());
            assert_eq!(
                *frame_source.reverse_match_batch_sizes.borrow(),
                *eager_source.reverse_match_batch_sizes.borrow()
            );
            assert_eq!(
                *frame_source.classified_batch_sizes.borrow(),
                *eager_source.classified_batch_sizes.borrow()
            );
            assert_eq!(
                *frame_source.hydrated_candidates.borrow(),
                *eager_source.hydrated_candidates.borrow()
            );
            assert_eq!(
                *frame_source.hydration_batch_sizes.borrow(),
                *eager_source.hydration_batch_sizes.borrow()
            );
        }
        let source = FaultingSource::new(&fixture.source, TestFault::FailOnSecondReverseMatch);
        let error = drive_experimental_reverse(
            &mut BatchResolutionEngine::new(&source),
            &definitions,
            ReverseCandidateGapExclusionPlan::default(),
            &CancellationToken::new(),
        )
        .expect_err("a later reverse read failure publishes no answer");
        assert!(
            error
                .to_string()
                .contains("second-level reverse source failure")
        );
    }

    #[test]
    fn experimental_reverse_frame_retains_exact_gap_exclusion_authority() {
        let fixture = shared_fixture(false);
        let excluded = ReverseCandidateGapIdentity::new(
            fixture.first_fragment,
            semantic("experimental-reverse-excluded-gap"),
        );
        let retained = ReverseCandidateGapIdentity::new(
            fixture.first_fragment,
            semantic("experimental-reverse-retained-gap"),
        );
        let excluded_reason = ResolutionIncompleteReason::UnsupportedSemantic(excluded.gap_id());
        let retained_reason = ResolutionIncompleteReason::UnsupportedSemantic(retained.gap_id());
        let source = JavaOverlayLawSource::new(fixture.source)
            .with_reverse_gaps([(excluded, excluded_reason), (retained, retained_reason)]);
        let definitions = [(fixture.target, fixture.target_node)];
        let cancellation = CancellationToken::new();
        let eager = BatchResolutionEngine::new(&source)
            .reverse_candidate_references_with_gap_exclusions(
                &definitions,
                &mut ReverseCandidateGapExclusionPlan::new([excluded]),
                &cancellation,
            )
            .unwrap();
        let read_count = source.filtered_reverse_visits.get();
        let actual = drive_experimental_reverse(
            &mut BatchResolutionEngine::new(&source),
            &definitions,
            ReverseCandidateGapExclusionPlan::new([excluded]),
            &cancellation,
        )
        .unwrap();
        assert!(!actual.candidates.is_empty());
        assert!(actual.completions[0].contains_reason(retained_reason));
        assert!(!actual.completions[0].contains_reason(excluded_reason));
        assert_eq!(actual.into_parts(), eager.into_parts());
        assert_eq!(source.filtered_reverse_visits.get(), 2 * read_count);
        assert_eq!(source.raw_reverse_visits.get(), 0);
    }

    #[test]
    fn experimental_reverse_pending_later_page_retains_evidence_and_target_membership() {
        let target = semantic("experimental-paged-reverse-target");
        let target_node = node("experimental-paged-reverse-target-node");
        let disjoint = semantic("experimental-paged-reverse-disjoint-target");
        let disjoint_node = node("experimental-paged-reverse-disjoint-node");
        let boundaries = (0..=MAX_SOURCE_ROWS_PER_BATCH)
            .map(|ordinal| node(&format!("experimental-paged-reverse-boundary-{ordinal}")))
            .collect::<Vec<_>>();
        let inner = PreloadedFragmentSource::from_fragments_with_boundaries(
            boundaries.iter().copied(),
            [PreloadedFragment::new(
                fragment("experimental-paged-reverse-owner"),
                [
                    (target_node, BindingNodeKind::Definition(target)),
                    (disjoint_node, BindingNodeKind::Definition(disjoint)),
                ],
                boundaries.iter().enumerate().map(|(ordinal, &boundary)| {
                    (
                        path_id(&format!("experimental-paged-reverse-path-{ordinal}")),
                        path(boundary, target_node, ResolutionCompletion::Complete),
                    )
                }),
            )],
        );
        let gap = noncanonical_candidate_completion("experimental-reverse-prior-page-gap");
        let source =
            RepeatingUnconditionalSource::new(&inner, TestCandidateDirection::Reverse, gap.clone());
        let definitions = [(target, target_node), (disjoint, disjoint_node)];
        let cancellation = CancellationToken::new();
        let mut engine = BatchResolutionEngine::new(&source);
        let ExperimentalReverseBatchStart::Running(mut frame) =
            ExperimentalReverseBatchFrame::start(
                &engine,
                definitions.to_vec(),
                ReverseCandidateGapExclusionPlan::default(),
                &cancellation,
            )
        else {
            panic!("live reverse frame");
        };
        for _ in 0..10 {
            let result = frame
                .poll(&mut engine, &cancellation, &mut |page| {
                    assert_eq!(page.definitions, definitions);
                    assert_eq!(page.requests.len(), page.target_indices.len());
                    Ok(ExperimentalReverseReadiness::AwaitingDependencies)
                })
                .unwrap();
            if matches!(result, ExperimentalReverseBatchPoll::AwaitingDependencies) {
                break;
            }
            assert!(matches!(result, ExperimentalReverseBatchPoll::Continue));
        }
        assert_eq!(
            source.calls.get(),
            0,
            "suspension precedes the whole source read"
        );
        assert_eq!(frame.pending_page().target_indices, &[0, 1]);
        for _ in 0..10 {
            let result = frame
                .poll(&mut engine, &cancellation, &mut |_| {
                    Ok(if source.calls.get() < 2 {
                        ExperimentalReverseReadiness::Ready
                    } else {
                        ExperimentalReverseReadiness::AwaitingDependencies
                    })
                })
                .unwrap();
            if matches!(result, ExperimentalReverseBatchPoll::AwaitingDependencies) {
                break;
            }
            assert!(matches!(result, ExperimentalReverseBatchPoll::Continue));
        }
        assert_eq!(source.calls.get(), 2);
        assert_eq!(
            source.request_batch_sizes.borrow().as_slice(),
            &[2, MAX_SOURCE_ROWS_PER_BATCH]
        );
        assert_eq!(frame.pending_requests().len(), 1);
        assert_eq!(frame.pending_page().target_indices, &[0]);
        cancellation.cancel();
        let ExperimentalReverseBatchPoll::Ready(answer) = frame
            .poll(&mut engine, &cancellation, &mut |_| {
                panic!("cancelled frame must not discover or read its pending relation")
            })
            .unwrap()
        else {
            panic!("cancellation is terminal");
        };
        assert_eq!(source.calls.get(), 2);
        assert!(answer.candidates.is_empty());
        assert!(answer.frontiers.is_empty());
        assert!(answer.lexical_frontiers.is_empty());
        for completion in &answer.completions {
            assert_eq!(completion, &gap.combine(&cancelled_completion()));
        }
        let retry = CancellationToken::new();
        let eager = engine
            .reverse_candidate_references(&definitions, &retry)
            .unwrap();
        let actual = drive_experimental_reverse(
            &mut engine,
            &definitions,
            ReverseCandidateGapExclusionPlan::default(),
            &retry,
        )
        .unwrap();
        assert_eq!(actual.into_parts(), eager.into_parts());
    }

    fn drive_experimental_forward_start<S: BatchResolutionFragmentSource + ?Sized>(
        engine: &BatchResolutionEngine<'_, S>,
        start: DemandForwardBatchStart,
        cache: &mut ForwardCandidateArtifactCache,
        cancellation: &CancellationToken,
    ) -> StoreResult<ReferenceBatchAnswer> {
        let mut frame = match start {
            DemandForwardBatchStart::Running(frame) => frame,
            DemandForwardBatchStart::Ready(answer) => return Ok(answer),
        };
        for _ in 0..10_000 {
            match frame.poll(engine, Some(&mut *cache), cancellation, &mut |_| {
                Ok(DemandForwardReadiness::AwaitingDependencies)
            })? {
                DemandForwardBatchPoll::Ready(answer) => return Ok(answer),
                DemandForwardBatchPoll::Continue => continue,
                DemandForwardBatchPoll::AwaitingDependencies => {}
            }
            let pending = frame.pending_requests().to_vec();
            assert!(!pending.is_empty());
            assert!(pending.len() <= MAX_SOURCE_ROWS_PER_BATCH);
            assert!(
                pending
                    .iter()
                    .enumerate()
                    .all(|(ordinal, request)| request.request_ordinal() == ordinal)
            );
            let metrics = frame.initialized.metrics;
            let completion_work = frame.initialized.completion_work;
            let cache_counts = cache.artifact_counts();
            let charged = engine
                .resolution_session
                .map(|session| session.finish(()).work());
            for _ in 0..3 {
                // Move the entire task while no engine/cache borrow is held.
                let mut arena = vec![frame];
                frame = arena.pop().unwrap();
                assert!(matches!(
                    frame.poll(engine, Some(&mut *cache), cancellation, &mut |requests| {
                        assert_eq!(requests, pending);
                        Ok(DemandForwardReadiness::AwaitingDependencies)
                    })?,
                    DemandForwardBatchPoll::AwaitingDependencies
                ));
                assert_eq!(frame.pending_requests(), pending);
                assert_eq!(frame.initialized.metrics, metrics);
                assert_eq!(frame.initialized.completion_work, completion_work);
                assert_eq!(cache.artifact_counts(), cache_counts);
                assert_eq!(
                    engine
                        .resolution_session
                        .map(|session| session.finish(()).work()),
                    charged
                );
            }
            match frame.poll(engine, Some(&mut *cache), cancellation, &mut |requests| {
                assert_eq!(requests, pending);
                Ok(DemandForwardReadiness::Ready)
            })? {
                DemandForwardBatchPoll::Ready(answer) => return Ok(answer),
                DemandForwardBatchPoll::Continue => {}
                DemandForwardBatchPoll::AwaitingDependencies => {
                    panic!("ready page cannot await")
                }
            }
        }
        panic!("finite fixture exceeded its driver guard");
    }

    #[test]
    fn experimental_ordinary_starts_match_their_distinct_eager_admission_schedules() {
        let fixture = shared_fixture(false);
        let batch = ReferenceSeedBatch::new(
            [fixture.first_reference, fixture.second_reference]
                .map(|reference| reference_seed(&fixture.source, ResolutionQuery::new(reference))),
        );
        for max_scope_nodes in [0, 1, ReceiverAnalysisBudget::default().max_scope_nodes] {
            let budget = ReceiverAnalysisBudget {
                max_scope_nodes,
                ..ReceiverAnalysisBudget::default()
            };
            let cancellation = CancellationToken::new();
            let eager_session = ResolutionSession::bounded(budget, Some(&cancellation));
            let frame_session = ResolutionSession::bounded(budget, Some(&cancellation));
            let eager_engine =
                BatchResolutionEngine::maybe_bounded(&fixture.source, Some(&eager_session));
            let frame_engine =
                BatchResolutionEngine::maybe_bounded(&fixture.source, Some(&frame_session));
            let eager = eager_engine
                .resolve_reference_batch_with_artifact_cache(
                    &batch,
                    &cancellation,
                    Some(&mut ForwardCandidateArtifactCache::default()),
                )
                .unwrap();
            let actual = drive_experimental_forward_start(
                &frame_engine,
                DemandForwardBatchFrame::start_reference_batch(
                    &frame_engine,
                    &batch,
                    &cancellation,
                ),
                &mut ForwardCandidateArtifactCache::default(),
                &cancellation,
            )
            .unwrap();
            assert_eq!(actual, eager);
            assert_eq!(
                frame_session.finish(()).work(),
                eager_session.finish(()).work()
            );

            for reference in [
                fixture.first_reference,
                semantic("absent-experimental-query"),
            ] {
                let query = ResolutionQuery::new(reference);
                let eager_source = FaultingSource::new(&fixture.source, TestFault::None);
                let frame_source = FaultingSource::new(&fixture.source, TestFault::None);
                let eager_session = ResolutionSession::bounded(budget, Some(&cancellation));
                let frame_session = ResolutionSession::bounded(budget, Some(&cancellation));
                let eager_engine =
                    BatchResolutionEngine::maybe_bounded(&eager_source, Some(&eager_session));
                let frame_engine =
                    BatchResolutionEngine::maybe_bounded(&frame_source, Some(&frame_session));
                let (eager, metrics) = eager_engine
                    .resolve_reference_cached_with_metrics(
                        query,
                        &cancellation,
                        &mut ForwardCandidateArtifactCache::default(),
                    )
                    .unwrap();
                let actual = drive_experimental_forward_start(
                    &frame_engine,
                    DemandForwardBatchFrame::start_query(&frame_engine, query, &cancellation)
                        .unwrap(),
                    &mut ForwardCandidateArtifactCache::default(),
                    &cancellation,
                )
                .unwrap();
                assert_eq!(actual.answer(reference), Some(&eager));
                assert_eq!(actual.metrics, metrics);
                assert_eq!(
                    frame_session.finish(()).work(),
                    eager_session.finish(()).work()
                );
                assert_eq!(
                    frame_source.reference_seeds.get(),
                    eager_source.reference_seeds.get()
                );
            }
        }
    }

    #[test]
    fn experimental_disjoint_demands_do_not_reopen_closed_endpoint_relations() {
        let fixture = shared_fixture(false);
        let eager_source = FaultingSource::new(&fixture.source, TestFault::None);
        let frame_source = FaultingSource::new(&fixture.source, TestFault::None);
        let cancellation = CancellationToken::new();
        let eager_session =
            ResolutionSession::bounded(ReceiverAnalysisBudget::default(), Some(&cancellation));
        let frame_session =
            ResolutionSession::bounded(ReceiverAnalysisBudget::default(), Some(&cancellation));
        let eager_engine =
            BatchResolutionEngine::maybe_bounded(&eager_source, Some(&eager_session));
        let frame_engine =
            BatchResolutionEngine::maybe_bounded(&frame_source, Some(&frame_session));
        let mut eager_cache = ForwardCandidateArtifactCache::default();
        let mut frame_cache = ForwardCandidateArtifactCache::default();
        let mut first_closed = HashMap::default();
        for (round, reference) in [
            fixture.first_reference,
            fixture.third_reference,
            fixture.first_reference,
        ]
        .into_iter()
        .enumerate()
        {
            let query = ResolutionQuery::new(reference);
            let reads_before = frame_source.forward_matches.get();
            let hydrated_before = frame_source.hydrated_candidates.borrow().len();
            let (eager, metrics) = eager_engine
                .resolve_reference_cached_with_metrics(query, &cancellation, &mut eager_cache)
                .unwrap();
            let actual = drive_experimental_forward_start(
                &frame_engine,
                DemandForwardBatchFrame::start_query(&frame_engine, query, &cancellation).unwrap(),
                &mut frame_cache,
                &cancellation,
            )
            .unwrap();
            assert_eq!(actual.answer(reference), Some(&eager));
            assert_eq!(actual.metrics, metrics);
            assert_eq!(
                frame_session.finish(()).work(),
                eager_session.finish(()).work()
            );
            assert_eq!(
                frame_source.forward_matches.get(),
                eager_source.forward_matches.get()
            );
            if round == 0 {
                first_closed = frame_cache
                    .endpoint_matches
                    .iter()
                    .map(|(key, value)| {
                        (
                            key.clone(),
                            (value.candidates.clone(), value.branch_completion.clone()),
                        )
                    })
                    .collect::<HashMap<_, _>>();
                assert!(!first_closed.is_empty());
            } else {
                for (key, (candidates, completion)) in &first_closed {
                    let retained = &frame_cache.endpoint_matches[key];
                    assert_eq!(&retained.candidates, candidates);
                    assert_eq!(&retained.branch_completion, completion);
                }
            }
            if round == 1 {
                assert!(
                    frame_source.forward_matches.get() > reads_before,
                    "a newly demanded disjoint endpoint must read its own relation"
                );
            }
            if round == 2 {
                assert_eq!(
                    frame_source.forward_matches.get(),
                    reads_before,
                    "new disjoint demands do not invalidate the earlier closed key"
                );
                assert_eq!(
                    frame_source.hydrated_candidates.borrow().len(),
                    hydrated_before
                );
            }
        }
    }

    #[test]
    fn experimental_forward_frame_matches_eager_reads_work_and_warm_artifacts() {
        for tier in [
            PrecedenceTier::LexicalBinding,
            PrecedenceTier::PackageOrModule,
        ] {
            let fixture = seeded_fixture(tier);
            let seed = reference_seed(&fixture.source, ResolutionQuery::new(fixture.reference));
            let requests = [seeded_reference_request(
                seed,
                seeded_alternatives(&fixture),
            )];
            let eager_source = FaultingSource::new(&fixture.source, TestFault::None);
            let frame_source = FaultingSource::new(&fixture.source, TestFault::None);
            let mut eager_cache = ForwardCandidateArtifactCache::default();
            let mut frame_cache = ForwardCandidateArtifactCache::default();
            for _ in 0..2 {
                let cancellation = CancellationToken::new();
                let eager_session = ResolutionSession::bounded(
                    ReceiverAnalysisBudget::default(),
                    Some(&cancellation),
                );
                let frame_session = ResolutionSession::bounded(
                    ReceiverAnalysisBudget::default(),
                    Some(&cancellation),
                );
                let eager =
                    BatchResolutionEngine::maybe_bounded(&eager_source, Some(&eager_session))
                        .resolve_seeded_reference_requests(
                            &requests,
                            &cancellation,
                            Some(&mut eager_cache),
                        )
                        .unwrap();
                let actual = drive_experimental_forward(
                    &BatchResolutionEngine::maybe_bounded(&frame_source, Some(&frame_session)),
                    &requests,
                    &mut frame_cache,
                    &cancellation,
                )
                .unwrap();
                assert_eq!(actual, eager);
                assert_eq!(
                    frame_session.finish(()).work(),
                    eager_session.finish(()).work()
                );
                assert_eq!(
                    frame_source.forward_matches.get(),
                    eager_source.forward_matches.get()
                );
                assert_eq!(
                    *frame_source.forward_match_batch_sizes.borrow(),
                    *eager_source.forward_match_batch_sizes.borrow()
                );
                assert_eq!(
                    *frame_source.classified_batch_sizes.borrow(),
                    *eager_source.classified_batch_sizes.borrow()
                );
                assert_eq!(
                    *frame_source.hydrated_candidates.borrow(),
                    *eager_source.hydrated_candidates.borrow()
                );
            }
        }
    }

    #[test]
    fn experimental_forward_frame_preserves_exact_and_one_short_budgets() {
        let fixture = shared_fixture(false);
        let requests = [SeededReferenceRequest::identity_with_poll(
            reference_seed(
                &fixture.source,
                ResolutionQuery::new(fixture.first_reference),
            ),
            &mut || false,
        )
        .unwrap()];
        let cancellation = CancellationToken::new();
        let baseline_session =
            ResolutionSession::bounded(ReceiverAnalysisBudget::default(), Some(&cancellation));
        let baseline =
            BatchResolutionEngine::maybe_bounded(&fixture.source, Some(&baseline_session))
                .resolve_seeded_reference_requests(
                    &requests,
                    &cancellation,
                    Some(&mut ForwardCandidateArtifactCache::default()),
                )
                .unwrap();
        let work = baseline_session.finish(()).work();
        assert!(work.scope_nodes > 0 && work.summary_expansions > 0);
        for scope_limit in [work.scope_nodes, work.scope_nodes - 1, 0] {
            let budget = ReceiverAnalysisBudget {
                max_scope_nodes: scope_limit,
                max_summary_expansions: work.summary_expansions,
                ..ReceiverAnalysisBudget::default()
            };
            let eager_session = ResolutionSession::bounded(budget, Some(&cancellation));
            let frame_session = ResolutionSession::bounded(budget, Some(&cancellation));
            let eager = BatchResolutionEngine::maybe_bounded(&fixture.source, Some(&eager_session))
                .resolve_seeded_reference_requests(
                    &requests,
                    &cancellation,
                    Some(&mut ForwardCandidateArtifactCache::default()),
                )
                .unwrap();
            let actual = drive_experimental_forward(
                &BatchResolutionEngine::maybe_bounded(&fixture.source, Some(&frame_session)),
                &requests,
                &mut ForwardCandidateArtifactCache::default(),
                &cancellation,
            )
            .unwrap();
            assert_eq!(actual, eager);
            assert_eq!(
                frame_session.finish(()).work(),
                eager_session.finish(()).work()
            );
            if scope_limit == work.scope_nodes {
                assert_eq!(actual, baseline);
                assert!(matches!(
                    frame_session.finish(()),
                    BoundedResolution::Complete { .. }
                ));
            } else {
                assert!(
                    actual
                        .answers()
                        .iter()
                        .all(|answer| answer.answer().targets().is_empty())
                );
                assert!(matches!(
                    frame_session.finish(()),
                    BoundedResolution::Exceeded {
                        limit: ReceiverBudgetLimit::ScopeNodes,
                        ..
                    }
                ));
            }
        }
        assert!(!cancellation.is_cancelled());
    }

    #[test]
    fn experimental_forward_pending_later_page_retains_evidence_without_negative_cache() {
        let (inner, request) = paged_seeded_request_fixture();
        let gap = noncanonical_candidate_completion("frame-previous-page-gap");
        let source =
            RepeatingUnconditionalSource::new(&inner, TestCandidateDirection::Forward, gap.clone());
        let requests = [request];
        let cancellation = CancellationToken::new();
        let engine = BatchResolutionEngine::new(&source);
        let DemandForwardBatchStart::Running(mut frame) =
            DemandForwardBatchFrame::start(&engine, &requests, &cancellation)
        else {
            panic!("live frame");
        };
        let mut cache = ForwardCandidateArtifactCache::default();
        assert!(matches!(
            frame
                .poll(&engine, Some(&mut cache), &cancellation, &mut |_| {
                    panic!("round preparation does not enter the candidate readiness gate")
                })
                .unwrap(),
            DemandForwardBatchPoll::Continue
        ));
        assert!(matches!(
            frame
                .poll(&engine, Some(&mut cache), &cancellation, &mut |_| {
                    Ok(DemandForwardReadiness::AwaitingDependencies)
                })
                .unwrap(),
            DemandForwardBatchPoll::AwaitingDependencies
        ));
        assert_eq!(
            source.calls.get(),
            0,
            "first suspension precedes all candidate reads"
        );
        assert!(
            cache.endpoint_matches.is_empty(),
            "pending is not negative coverage"
        );
        assert_eq!(frame.pending_requests().len(), MAX_SOURCE_ROWS_PER_BATCH);
        for _ in 0..10 {
            let polled = frame
                .poll(&engine, Some(&mut cache), &cancellation, &mut |_| {
                    Ok(if source.calls.get() == 0 {
                        DemandForwardReadiness::Ready
                    } else {
                        DemandForwardReadiness::AwaitingDependencies
                    })
                })
                .unwrap();
            if matches!(polled, DemandForwardBatchPoll::AwaitingDependencies) {
                break;
            }
            assert!(matches!(polled, DemandForwardBatchPoll::Continue));
        }
        assert_eq!(source.calls.get(), 1);
        assert_eq!(frame.pending_requests().len(), 1);
        assert_eq!(cache.endpoint_matches.len(), MAX_SOURCE_ROWS_PER_BATCH);
        let pending = frame.pending_requests()[0].endpoint().clone();
        assert!(!cache.endpoint_matches.contains_key(&pending));
        let metrics = frame.initialized.metrics;
        let answer = frame.cancel();
        assert!(!cancellation.is_cancelled());
        assert_eq!(answer.metrics(), metrics);
        assert_eq!(source.calls.get(), 1);
        assert!(!cache.endpoint_matches.contains_key(&pending));
        assert!(
            answer
                .answers()
                .iter()
                .all(|answer| answer.answer().targets().is_empty())
        );
        let expected = gap.combine(&cancelled_completion());
        assert_eq!(answer.completion(), &expected);

        // The independent eager oracle starts with an unopened cache. A fresh
        // resumed driver reads both exact pages, not a poisoned empty relation.
        let retry_token = CancellationToken::new();
        let eager = engine
            .resolve_seeded_reference_requests(
                &requests,
                &retry_token,
                Some(&mut ForwardCandidateArtifactCache::default()),
            )
            .unwrap();
        let retry = drive_experimental_forward(
            &engine,
            &requests,
            &mut ForwardCandidateArtifactCache::default(),
            &retry_token,
        )
        .unwrap();
        assert_eq!(retry, eager);
    }

    #[test]
    fn experimental_forward_frame_retains_cancelled_source_evidence_and_errors() {
        let fixture = shared_fixture(false);
        let requests = [SeededReferenceRequest::identity_with_poll(
            reference_seed(
                &fixture.source,
                ResolutionQuery::new(fixture.first_reference),
            ),
            &mut || false,
        )
        .unwrap()];
        for fault in [
            TestFault::CancelOnForwardMatchWithGap,
            TestFault::CancelOnHydration,
        ] {
            let eager_source = FaultingSource::new(&fixture.source, fault);
            let frame_source = FaultingSource::new(&fixture.source, fault);
            let eager = BatchResolutionEngine::new(&eager_source)
                .resolve_seeded_reference_requests(
                    &requests,
                    &CancellationToken::new(),
                    Some(&mut ForwardCandidateArtifactCache::default()),
                )
                .unwrap();
            let actual = drive_experimental_forward(
                &BatchResolutionEngine::new(&frame_source),
                &requests,
                &mut ForwardCandidateArtifactCache::default(),
                &CancellationToken::new(),
            )
            .unwrap();
            assert_eq!(actual, eager);
            assert!(
                actual
                    .answers()
                    .iter()
                    .all(|answer| answer.answer().targets().is_empty())
            );
            assert!(
                matches!(actual.completion(), ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::Cancelled))
            );
        }
        let source = FaultingSource::new(&fixture.source, TestFault::FailOnSecondForwardMatch);
        let error = drive_experimental_forward(
            &BatchResolutionEngine::new(&source),
            &requests,
            &mut ForwardCandidateArtifactCache::default(),
            &CancellationToken::new(),
        )
        .expect_err("a later source failure publishes no partial answer");
        assert!(
            error
                .to_string()
                .contains("injected second-level source failure")
        );
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let source = FaultingSource::new(&fixture.source, TestFault::None);
        let answer = drive_experimental_forward(
            &BatchResolutionEngine::new(&source),
            &requests,
            &mut ForwardCandidateArtifactCache::default(),
            &cancellation,
        )
        .unwrap();
        assert!(
            answer
                .answers()
                .iter()
                .all(|answer| answer.answer().targets().is_empty())
        );
        assert_eq!(source.forward_matches.get(), 0);
        assert!(source.classified_batch_sizes.borrow().is_empty());
    }

    #[test]
    fn experimental_forward_frame_preserves_lexical_cycle_certificate() {
        let reference = semantic("frame-cycle-reference");
        let target = semantic("frame-cycle-target");
        let start = node("frame-cycle-start");
        let seam = node("frame-cycle-seam");
        let end = node("frame-cycle-end");
        let source = PreloadedFragmentSource::from_fragments_with_boundaries(
            [seam],
            [PreloadedFragment::new(
                fragment("frame-cycle-fragment"),
                [
                    (start, BindingNodeKind::Reference(reference)),
                    (end, BindingNodeKind::Definition(target)),
                ],
                [
                    (
                        path_id("frame-cycle-entry"),
                        path(start, seam, ResolutionCompletion::Complete),
                    ),
                    (
                        path_id("frame-cycle-loop"),
                        path(seam, seam, ResolutionCompletion::Complete),
                    ),
                    (
                        path_id("frame-cycle-exit"),
                        path(seam, end, ResolutionCompletion::Complete),
                    ),
                ],
            )],
        );
        let requests = [SeededReferenceRequest::identity_with_poll(
            reference_seed(&source, ResolutionQuery::new(reference)),
            &mut || false,
        )
        .unwrap()];
        let cancellation = CancellationToken::new();
        let engine = BatchResolutionEngine::new(&source);
        let eager = engine
            .resolve_seeded_reference_requests(
                &requests,
                &cancellation,
                Some(&mut ForwardCandidateArtifactCache::default()),
            )
            .unwrap();
        let actual = drive_experimental_forward(
            &engine,
            &requests,
            &mut ForwardCandidateArtifactCache::default(),
            &cancellation,
        )
        .unwrap();
        assert_eq!(actual, eager);
        assert_eq!(actual.answer(reference).unwrap().targets(), &[target]);
        assert_eq!(actual.completion(), &ResolutionCompletion::Complete);

        let definitions = [(target, end)];
        let mut engine = BatchResolutionEngine::new(&source);
        let eager = engine
            .reverse_candidate_references(&definitions, &cancellation)
            .unwrap();
        let actual = drive_experimental_reverse(
            &mut engine,
            &definitions,
            ReverseCandidateGapExclusionPlan::default(),
            &cancellation,
        )
        .unwrap();
        assert_eq!(actual.candidates.len(), 1);
        assert_eq!(actual.candidates[0].reference(), reference);
        assert_eq!(
            actual.completions.as_ref(),
            &[ResolutionCompletion::Complete]
        );
        assert_eq!(actual.into_parts(), eager.into_parts());
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
                derivation_key(&format!("operation-unconditional-seed-path-{ordinal}")),
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
    fn reverse_unconditional_completion_is_owned_once_across_states_and_rounds() {
        let fixture = shared_fixture(false);
        let expected = noncanonical_candidate_completion("reverse-many-states-rounds");
        let source = RepeatingUnconditionalSource::new(
            &fixture.source,
            TestCandidateDirection::Reverse,
            expected.clone(),
        );

        let answer = BatchResolutionEngine::new(&source)
            .references_to(fixture.target, &CancellationToken::new())
            .expect("repeated reverse operation completion is consistent");

        let mut expected_references = vec![
            fixture.first_reference,
            fixture.second_reference,
            fixture.third_reference,
        ];
        expected_references.sort_unstable();
        assert_eq!(answer.references(), expected_references);
        assert_eq!(answer.completion(), &expected);
        assert_eq!(source.calls.get(), 2);
        assert_eq!(source.request_batch_sizes.borrow().as_slice(), &[1, 1]);
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
    fn forward_candidate_artifact_cache_is_atomic_and_retains_exact_hit_evidence() {
        let inner = PreloadedFragmentSource::new([], []);
        let unconditional = noncanonical_candidate_completion("artifact-unconditional");
        let hit_branch = noncanonical_candidate_completion("artifact-hit-branch");
        let source = RepeatingUnconditionalSource::new(
            &inner,
            TestCandidateDirection::Forward,
            unconditional.clone(),
        )
        .with_one_cancellation(1);
        let hit_endpoint = endpoint(node("artifact-hit-endpoint"));
        let miss_endpoint = endpoint(node("artifact-miss-endpoint"));
        let requests = [
            BatchCandidateRequest::new(0, hit_endpoint.clone()),
            BatchCandidateRequest::new(1, miss_endpoint.clone()),
        ];
        let mut cache = ForwardCandidateArtifactCache {
            endpoint_matches: HashMap::from_iter([(
                hit_endpoint,
                CachedForwardEndpointMatch {
                    candidates: Box::new([]),
                    branch_completion: hit_branch.clone(),
                },
            )]),
            hydrated_paths: HashMap::default(),
            endpoint_classifications: HashMap::default(),
            unconditional_completion: Some(unconditional.clone()),
            demanded_reference_answers: HashMap::default(),
        };

        let cancelled_token = CancellationToken::new();
        let mut work = 0_usize;
        let mut cancelled = false;
        let (matches, cancelled_unconditional, cancelled_branches) =
            read_forward_candidate_artifacts(
                &source,
                Some(&mut cache),
                &requests,
                &cancelled_token,
                None,
                &mut work,
                &mut cancelled,
            )
            .expect("a cancelled cache miss is semantic evidence");
        assert!(cancelled);
        assert!(matches.is_empty());
        let ResolutionCompletion::Incomplete(cancelled_reasons) = cancelled_unconditional else {
            panic!("the scripted source adds cancellation to its raw unconditional box");
        };
        assert!(cancelled_reasons.contains(&ResolutionIncompleteReason::Cancelled));
        let ResolutionCompletion::Incomplete(unconditional_reasons) = &unconditional else {
            unreachable!("the injected unconditional box is incomplete");
        };
        for reason in unconditional_reasons.iter() {
            assert!(cancelled_reasons.contains(reason));
        }
        assert_eq!(cancelled_branches[0], hit_branch);
        assert_eq!(cancelled_branches[1], ResolutionCompletion::Complete);
        assert_eq!(cache.artifact_counts(), (1, 0, 0));

        let retry_token = CancellationToken::new();
        let mut retry_work = 0_usize;
        let mut retry_cancelled = false;
        let (retry_matches, retry_unconditional, retry_branches) =
            read_forward_candidate_artifacts(
                &source,
                Some(&mut cache),
                &requests,
                &retry_token,
                None,
                &mut retry_work,
                &mut retry_cancelled,
            )
            .expect("a fresh retry publishes the fully exhausted miss");
        assert!(!retry_cancelled);
        assert!(retry_matches.is_empty());
        assert_eq!(retry_unconditional, unconditional);
        assert_eq!(retry_branches[0], hit_branch);
        assert_eq!(retry_branches[1], ResolutionCompletion::Complete);
        assert_eq!(cache.artifact_counts(), (2, 0, 0));
        assert_eq!(source.calls.get(), 2);

        let mut hit_work = 0_usize;
        let mut hit_cancelled = false;
        let (hit_matches, hit_unconditional, hit_branches) = read_forward_candidate_artifacts(
            &source,
            Some(&mut cache),
            &requests,
            &CancellationToken::new(),
            None,
            &mut hit_work,
            &mut hit_cancelled,
        )
        .expect("an all-hit replay is source-free");
        assert!(!hit_cancelled);
        assert!(hit_matches.is_empty());
        assert_eq!(hit_unconditional, unconditional);
        assert_eq!(hit_branches[0], hit_branch);
        assert_eq!(hit_branches[1], ResolutionCompletion::Complete);
        assert_eq!(
            source.calls.get(),
            2,
            "all-hit replay performs no source read"
        );
    }

    #[test]
    fn bounded_forward_candidate_pages_and_cache_hits_stop_before_publication() {
        let fixture = shared_fixture(false);
        let requests = [BatchCandidateRequest::new(0, endpoint(fixture.first_node))];
        let mut cache = ForwardCandidateArtifactCache::default();
        let caller = CancellationToken::new();
        let stopped_session = ResolutionSession::bounded(
            ReceiverAnalysisBudget {
                max_scope_nodes: 0,
                ..ReceiverAnalysisBudget::default()
            },
            Some(&caller),
        );
        let mut work = 0_usize;
        let mut cancelled = false;
        let (matches, _, _) = read_forward_candidate_artifacts(
            &fixture.source,
            Some(&mut cache),
            &requests,
            stopped_session.cancellation().expect("bounded token"),
            Some(&stopped_session),
            &mut work,
            &mut cancelled,
        )
        .expect("a bounded candidate stop is not a source failure");
        assert!(cancelled);
        assert!(matches.is_empty());
        assert_eq!(cache.artifact_counts(), (0, 0, 0));
        assert!(!caller.is_cancelled());
        assert!(matches!(
            stopped_session.finish(()),
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                work: ReceiverAnalysisWork {
                    setup_nodes: 0,
                    summary_expansions: 0,
                    scope_nodes: 0,
                },
            }
        ));

        let exact_session = ResolutionSession::bounded(
            ReceiverAnalysisBudget {
                max_scope_nodes: 4,
                ..ReceiverAnalysisBudget::default()
            },
            Some(&caller),
        );
        let mut exact_work = 0_usize;
        let mut exact_cancelled = false;
        let (exact_matches, _, _) = read_forward_candidate_artifacts(
            &fixture.source,
            Some(&mut cache),
            &requests,
            exact_session.cancellation().expect("bounded token"),
            Some(&exact_session),
            &mut exact_work,
            &mut exact_cancelled,
        )
        .expect("an exact candidate budget retries from an empty cache");
        assert!(!exact_cancelled);
        assert_eq!(exact_matches.len(), 1);
        assert_eq!(cache.artifact_counts(), (1, 0, 0));
        assert!(matches!(
            exact_session.finish(()),
            BoundedResolution::Complete {
                work: ReceiverAnalysisWork {
                    setup_nodes: 0,
                    summary_expansions: 0,
                    scope_nodes: 4,
                },
                ..
            }
        ));

        let warm_session = ResolutionSession::bounded(
            ReceiverAnalysisBudget {
                max_scope_nodes: 1,
                ..ReceiverAnalysisBudget::default()
            },
            Some(&caller),
        );
        let mut warm_work = 0_usize;
        let mut warm_cancelled = false;
        let (warm_matches, _, _) = read_forward_candidate_artifacts(
            &fixture.source,
            Some(&mut cache),
            &requests,
            warm_session.cancellation().expect("bounded token"),
            Some(&warm_session),
            &mut warm_work,
            &mut warm_cancelled,
        )
        .expect("a warm exact candidate budget replays one cache row");
        assert!(!warm_cancelled);
        assert_eq!(warm_matches, exact_matches);
        assert!(matches!(
            warm_session.finish(()),
            BoundedResolution::Complete {
                work: ReceiverAnalysisWork {
                    setup_nodes: 0,
                    summary_expansions: 0,
                    scope_nodes: 1,
                },
                ..
            }
        ));
    }

    #[test]
    fn bounded_cached_candidate_completion_charges_before_evidence_copy() {
        let source = PreloadedFragmentSource::new([], []);
        let endpoint = endpoint(node("bounded-completion-endpoint"));
        let completion = noncanonical_candidate_completion("bounded-completion");
        let mut cache = ForwardCandidateArtifactCache {
            endpoint_matches: HashMap::from_iter([(
                endpoint.clone(),
                CachedForwardEndpointMatch {
                    candidates: Box::new([]),
                    branch_completion: ResolutionCompletion::Complete,
                },
            )]),
            hydrated_paths: HashMap::default(),
            endpoint_classifications: HashMap::default(),
            unconditional_completion: Some(completion.clone()),
            demanded_reference_answers: HashMap::default(),
        };
        let requests = [BatchCandidateRequest::new(0, endpoint)];
        let caller = CancellationToken::new();

        let stopped = ResolutionSession::bounded(
            ReceiverAnalysisBudget {
                max_scope_nodes: 2,
                ..ReceiverAnalysisBudget::default()
            },
            Some(&caller),
        );
        let mut work = 0_usize;
        let mut cancelled = false;
        let (matches, returned, branches) = read_forward_candidate_artifacts(
            &source,
            Some(&mut cache),
            &requests,
            stopped.cancellation().expect("bounded token"),
            Some(&stopped),
            &mut work,
            &mut cancelled,
        )
        .expect("completion budget stop is not a source failure");
        assert!(cancelled);
        assert!(matches.is_empty());
        assert_eq!(returned, completion);
        assert_eq!(branches.as_ref(), &[ResolutionCompletion::Complete]);
        assert_eq!(cache.artifact_counts(), (1, 0, 0));
        assert!(!caller.is_cancelled());
        assert!(matches!(
            stopped.finish(()),
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                work: ReceiverAnalysisWork {
                    setup_nodes: 0,
                    summary_expansions: 0,
                    scope_nodes: 2,
                },
            }
        ));

        let exact = ResolutionSession::bounded(
            ReceiverAnalysisBudget {
                max_scope_nodes: 3,
                ..ReceiverAnalysisBudget::default()
            },
            Some(&caller),
        );
        let mut retry_work = 0_usize;
        let mut retry_cancelled = false;
        let (retry_matches, retry_completion, retry_branches) = read_forward_candidate_artifacts(
            &source,
            Some(&mut cache),
            &requests,
            exact.cancellation().expect("bounded token"),
            Some(&exact),
            &mut retry_work,
            &mut retry_cancelled,
        )
        .expect("exact completion budget retries the unchanged cache");
        assert!(!retry_cancelled);
        assert!(retry_matches.is_empty());
        assert_eq!(retry_completion, completion);
        assert_eq!(retry_branches.as_ref(), &[ResolutionCompletion::Complete]);
        assert!(matches!(
            exact.finish(()),
            BoundedResolution::Complete {
                work: ReceiverAnalysisWork {
                    setup_nodes: 0,
                    summary_expansions: 0,
                    scope_nodes: 3,
                },
                ..
            }
        ));
    }

    #[test]
    fn cached_candidate_hit_cancellation_drains_every_noncanonical_branch_box() {
        let inner = PreloadedFragmentSource::new([], []);
        let unconditional = noncanonical_candidate_completion("hit-drain-unconditional");
        let first_branch = noncanonical_candidate_completion("hit-drain-first");
        let second_branch = noncanonical_candidate_completion("hit-drain-second");
        let first_endpoint = endpoint(node("hit-drain-first-endpoint"));
        let second_endpoint = endpoint(node("hit-drain-second-endpoint"));
        let mut cache = ForwardCandidateArtifactCache {
            endpoint_matches: HashMap::from_iter([
                (
                    first_endpoint.clone(),
                    CachedForwardEndpointMatch {
                        candidates: Box::new([]),
                        branch_completion: first_branch.clone(),
                    },
                ),
                (
                    second_endpoint.clone(),
                    CachedForwardEndpointMatch {
                        candidates: Box::new([]),
                        branch_completion: second_branch.clone(),
                    },
                ),
            ]),
            hydrated_paths: HashMap::default(),
            endpoint_classifications: HashMap::default(),
            unconditional_completion: Some(unconditional.clone()),
            demanded_reference_answers: HashMap::default(),
        };
        let requests = [
            BatchCandidateRequest::new(0, first_endpoint),
            BatchCandidateRequest::new(1, second_endpoint),
        ];

        let mut observed_cancellation = false;
        for checks in 1..=24 {
            let cancellation = CancellationToken::cancel_after_checks_for_test(checks);
            let mut work = 0_usize;
            let mut cancelled = false;
            let (matches, returned_unconditional, branches) = read_forward_candidate_artifacts(
                &inner,
                Some(&mut cache),
                &requests,
                &cancellation,
                None,
                &mut work,
                &mut cancelled,
            )
            .expect("cache-hit cancellation has no source failure");
            if !cancelled {
                continue;
            }
            observed_cancellation = true;
            assert!(matches.is_empty());
            assert_eq!(returned_unconditional, unconditional);
            assert_eq!(branches[0], first_branch);
            assert_eq!(branches[1], second_branch);
        }
        assert!(
            observed_cancellation,
            "the threshold sweep must interrupt cache-hit completion replay"
        );
    }

    #[test]
    fn cached_hydrated_path_clone_cancellation_retains_the_full_raw_path_box() {
        let fixture = seeded_fixture(PrecedenceTier::LexicalBinding);
        let seed = reference_seed(&fixture.source, ResolutionQuery::new(fixture.reference));
        let request = seeded_reference_request(seed, [seeded_alternatives(&fixture)[0].clone()]);
        let source = FaultingSource::new(&fixture.source, TestFault::None);
        let mut cache = ForwardCandidateArtifactCache::default();
        let engine = BatchResolutionEngine::new(&source);

        let warmed = engine
            .resolve_seeded_reference_cached(&request, &CancellationToken::new(), &mut cache)
            .expect("the initial producer stitch warms every immutable artifact");
        assert_eq!(warmed.targets(), &[fixture.first_target]);
        {
            assert_eq!(cache.artifact_counts(), (1, 1, 2));
            assert_eq!(
                cache.endpoint_classifications[&fixture.first_owner],
                BatchEndpointClassification::new(fixture.first_owner, None, None),
                "the seeded alternative's boundary endpoint is classified once"
            );
            let target_classifications = cache
                .endpoint_classifications
                .values()
                .filter(|classification| classification.definition() == Some(fixture.first_target))
                .count();
            assert_eq!(
                target_classifications, 1,
                "the hydrated candidate's definition endpoint is classified once"
            );
        }
        let source_counts = (
            source.forward_matches.get(),
            source.hydrated_candidates.borrow().len(),
            source.classified_batch_sizes.borrow().len(),
        );

        // Find a token budget that is strictly larger than every check in the
        // short all-hit replay. Replacing the one cached path with more than
        // that many cancellation quanta of witness steps then makes the same
        // budget expire inside `PartialPath::clone_with_poll`, rather than in
        // its completion preflight or in later composition work.
        let mut short_hit_budget = None;
        for checks in 1..=4096 {
            let answer = engine
                .resolve_seeded_reference_cached(
                    &request,
                    &CancellationToken::cancel_after_checks_for_test(checks),
                    &mut cache,
                )
                .expect("cache-hit cancellation is semantic control flow");
            if !answer
                .completion()
                .contains_reason(ResolutionIncompleteReason::Cancelled)
            {
                short_hit_budget = Some(checks);
                break;
            }
        }
        let short_hit_budget =
            short_hit_budget.expect("the bounded short cache-hit replay completes");
        assert_eq!(
            (
                source.forward_matches.get(),
                source.hydrated_candidates.borrow().len(),
                source.classified_batch_sizes.borrow().len(),
            ),
            source_counts,
            "calibrating cache hits performs no source work"
        );

        let path_gap = noncanonical_candidate_completion("cached-hydration-clone-gap");
        let long_witness_count = short_hit_budget
            .checked_add(1)
            .and_then(|checks| checks.checked_mul(CANCELLATION_QUANTUM))
            .and_then(|iterations| iterations.checked_mul(2))
            .expect("the bounded cache-hit clone witness count must fit usize");
        let (candidate, long_path) = {
            let (&candidate, cached) = cache
                .hydrated_paths
                .iter()
                .next()
                .expect("the warm stitch cached one hydrated path");
            let witnesses = (0..long_witness_count)
                .map(|ordinal| {
                    WitnessStep::Node(node(&format!("cached-hydration-clone-witness-{ordinal}")))
                })
                .collect::<Vec<_>>();
            (
                candidate,
                PartialPath::new(
                    cached.start().clone(),
                    cached.end().clone(),
                    cached.precedence().to_vec(),
                    witnesses,
                    path_gap.clone(),
                ),
            )
        };
        cache.hydrated_paths.insert(candidate, long_path.clone());

        let cancelled = engine
            .resolve_seeded_reference_cached(
                &request,
                &CancellationToken::cancel_after_checks_for_test(short_hit_budget),
                &mut cache,
            )
            .expect("interrupted cached hydration cloning is semantic control flow");
        assert!(cancelled.targets().is_empty());
        assert!(cancelled.witnesses().is_empty());
        assert!(
            cancelled
                .completion()
                .contains_reason(ResolutionIncompleteReason::Cancelled)
        );
        let ResolutionCompletion::Incomplete(path_reasons) = &path_gap else {
            unreachable!("the injected path completion is incomplete")
        };
        for reason in path_reasons.iter() {
            assert!(
                cancelled.completion().contains_reason(*reason),
                "an interrupted hit clone retains the complete cached raw path operand"
            );
        }
        assert_eq!(cache.hydrated_paths[&candidate], long_path);
        assert_eq!(cache.artifact_counts(), (1, 1, 2));
        assert_eq!(
            (
                source.forward_matches.get(),
                source.hydrated_candidates.borrow().len(),
                source.classified_batch_sizes.borrow().len(),
            ),
            source_counts,
            "an interrupted cache hit performs no source call"
        );

        let retried = engine
            .resolve_seeded_reference_cached(&request, &CancellationToken::new(), &mut cache)
            .expect("a fresh cache-hit retry is exact");
        assert_eq!(retried.targets(), &[fixture.first_target]);
        assert_eq!(retried.completion(), &path_gap);
        assert_eq!(cache.hydrated_paths[&candidate], long_path);
        assert_eq!(
            (
                source.forward_matches.get(),
                source.hydrated_candidates.borrow().len(),
                source.classified_batch_sizes.borrow().len(),
            ),
            source_counts,
            "the fresh retry also remains source-free"
        );
    }

    #[test]
    fn typed_transfer_matches_preloaded_compatibility_and_propagates_coverage() {
        let source_slot = semantic("batch-type-source");
        let first_slot = semantic("batch-type-first");
        let second_slot = semantic("batch-type-second");
        let row_gap = semantic("batch-type-row-gap");
        let source = PreloadedFragmentSource::new([], []).with_type_transfer_rules([
            (
                source_slot,
                TypeTransferRule::new(
                    semantic("batch-copy-rule"),
                    first_slot,
                    0,
                    TypeTransferValueTransform::Preserve,
                    ResolutionCompletion::Complete,
                ),
            ),
            (
                source_slot,
                TypeTransferRule::new(
                    semantic("batch-address-rule"),
                    second_slot,
                    2,
                    TypeTransferValueTransform::Preserve,
                    ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(row_gap),
                    ]),
                ),
            ),
        ]);
        let incoming_gap = semantic("batch-type-incoming-gap");
        let state = TypedFrontierState::new(
            source_slot,
            [
                ResolutionSlotValue::type_object(ResolutionTypeRef::new(semantic("Receiver"), 0)),
                ResolutionSlotValue::runtime(ResolutionTypeRef::new(semantic("Receiver"), 1), true),
            ],
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                incoming_gap,
            )]),
        );
        let cancellation = CancellationToken::new();

        let compatibility = ResolutionEngine::new(&source)
            .transfer_types(&state, &cancellation)
            .expect("preloaded compatibility transfer is infallible");
        let batched = BatchResolutionEngine::new(&source)
            .transfer_types(&state, &cancellation)
            .expect("preloaded batch transfer is infallible");

        assert_eq!(batched, compatibility);
        assert!(batched.0.iter().all(|alternative| matches!(
            alternative.completion(),
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(incoming_gap))
        )));
        let first = batched
            .0
            .iter()
            .find(|alternative| alternative.slot() == first_slot)
            .expect("first copy-rule alternative");
        assert!(matches!(
            first.completion(),
            ResolutionCompletion::Incomplete(reasons)
                if !reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(row_gap))
        ));
        let second = batched
            .0
            .iter()
            .find(|alternative| alternative.slot() == second_slot)
            .expect("second copy-rule alternative");
        assert!(matches!(
            second.completion(),
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(row_gap))
        ));
        assert!(matches!(
            batched.1,
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(row_gap))
        ));
    }

    #[test]
    fn empty_typed_transfer_retains_source_coverage_gap() {
        let source = PreloadedFragmentSource::default();
        let faulting = FaultingSource::new(&source, TestFault::EmptyTypeTransferWithGap);
        let state = TypedFrontierState::new(
            semantic("empty-batch-type-source"),
            [runtime_type("Receiver")],
            ResolutionCompletion::Complete,
        );

        let (alternatives, completion) = BatchResolutionEngine::new(&faulting)
            .transfer_types(&state, &CancellationToken::new())
            .expect("coverage gap is semantic evidence");

        assert!(alternatives.is_empty());
        assert!(matches!(
            completion,
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(
                    semantic("type-transfer-coverage-gap")
                ))
        ));
    }

    #[test]
    fn typed_transfer_cancellation_discards_partial_alternatives() {
        let source_slot = semantic("cancelled-batch-type-source");
        let incoming_gap = semantic("cancelled-batch-incoming-gap");
        let rule_gap = semantic("cancelled-batch-rule-gap");
        let source =
            PreloadedFragmentSource::new([], []).with_type_transfer_rules((0..64).map(|ordinal| {
                (
                    source_slot,
                    TypeTransferRule::new(
                        semantic(&format!("cancelled-rule-{ordinal}")),
                        semantic(&format!("cancelled-target-{ordinal}")),
                        0,
                        TypeTransferValueTransform::Preserve,
                        if ordinal == 0 {
                            ResolutionCompletion::incomplete([
                                ResolutionIncompleteReason::UnsupportedSemantic(rule_gap),
                            ])
                        } else {
                            ResolutionCompletion::Complete
                        },
                    ),
                )
            }));
        let state = TypedFrontierState::new(
            source_slot,
            [runtime_type("Receiver")],
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                incoming_gap,
            )]),
        );
        let cancellation = CancellationToken::cancel_after_checks_for_test(3);

        let (alternatives, completion) = BatchResolutionEngine::new(&source)
            .transfer_types(&state, &cancellation)
            .expect("cancellation is semantic incompleteness");

        assert!(alternatives.is_empty());
        assert!(matches!(
            completion,
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::Cancelled)
                    && reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(incoming_gap))
                    && reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(rule_gap))
        ));
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
                    derivation_key(&format!("seeded-initialization-path-{ordinal}")),
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
                &ReferenceSeedBatch::single(ReferenceSeed::new(
                    owner,
                    ResolutionQuery::new(reference),
                    reference_node,
                    ResolutionCompletion::Complete,
                )),
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
                    derivation_key("endpoint-terminal-winning-route"),
                    ranked_path(
                        reference_node,
                        target_node,
                        choice,
                        PrecedenceTier::LexicalBinding,
                    ),
                ),
                seeded_partial_path(
                    derivation_key("endpoint-terminal-losing-route"),
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
    fn reverse_batch_equals_compatibility_and_is_row_order_invariant() {
        let ordered = shared_fixture(false);
        let reversed = shared_fixture(true);
        let cancellation = CancellationToken::new();

        let compatibility = ResolutionEngine::new(&ordered.source)
            .references_to(ordered.target, &cancellation)
            .expect("preloaded compatibility source is infallible");
        let batched = BatchResolutionEngine::new(&ordered.source)
            .references_to(ordered.target, &cancellation)
            .expect("preloaded batch source is infallible");
        let reversed_rows = BatchResolutionEngine::new(&reversed.source)
            .references_to(reversed.target, &cancellation)
            .expect("reordered preloaded batch source is infallible");

        assert_eq!(batched, compatibility);
        assert_eq!(reversed_rows, compatibility);
        let mut expected = vec![
            ordered.first_reference,
            ordered.second_reference,
            ordered.third_reference,
        ];
        expected.sort_unstable();
        assert_eq!(batched.references(), expected);
        assert_eq!(batched.completion(), &ResolutionCompletion::Complete);
    }

    #[test]
    fn raw_reverse_pages_every_high_fanout_source_relation_without_changing_rows() {
        fn source(reverse_rows: bool) -> (PreloadedFragmentSource, SemanticId, BindingNodeId) {
            let owner = fragment("raw-reverse-paged-source");
            let target = semantic("raw-reverse-paged-target");
            let target_node = node("raw-reverse-paged-target-node");
            let mut nodes = vec![(target_node, BindingNodeKind::Definition(target))];
            let mut paths = Vec::new();
            for ordinal in 0..=MAX_SOURCE_ROWS_PER_BATCH {
                let reference = semantic(&format!("raw-reverse-paged-reference-{ordinal}"));
                let reference_node = node(&format!("raw-reverse-paged-reference-node-{ordinal}"));
                let seam = node(&format!("raw-reverse-paged-seam-{ordinal}"));
                nodes.push((reference_node, BindingNodeKind::Reference(reference)));
                nodes.push((seam, BindingNodeKind::Scope));
                paths.push((
                    path_id(&format!("raw-reverse-paged-entry-{ordinal}")),
                    path(reference_node, seam, ResolutionCompletion::Complete),
                ));
                paths.push((
                    path_id(&format!("raw-reverse-paged-exit-{ordinal}")),
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
                target,
                target_node,
            )
        }

        let (ordered_source, target, target_node) = source(false);
        let recording = FaultingSource::new(&ordered_source, TestFault::None);
        let ordered = BatchResolutionEngine::new(&recording)
            .reverse_candidate_references(&[(target, target_node)], &CancellationToken::new())
            .expect("preloaded raw reverse reads are infallible")
            .into_parts();
        let storage_order =
            FaultingSource::new(&ordered_source, TestFault::ReverseReverseCandidateStream);
        let storage_order = BatchResolutionEngine::new(&storage_order)
            .reverse_candidate_references(&[(target, target_node)], &CancellationToken::new())
            .expect("reverse storage-cursor order is immaterial")
            .into_parts();
        assert_eq!(ordered, storage_order);

        let duplicate = FaultingSource::new(&ordered_source, TestFault::DuplicateReverseCandidate);
        let duplicate = BatchResolutionEngine::new(&duplicate)
            .reverse_candidate_references(&[(target, target_node)], &CancellationToken::new())
            .expect_err("duplicate reverse candidate identities must fail closed");
        assert!(duplicate.to_string().contains("repeated natural identity"));

        let (reversed, reversed_target, reversed_target_node) = source(true);
        let reversed = BatchResolutionEngine::new(&reversed)
            .reverse_candidate_references(
                &[(reversed_target, reversed_target_node)],
                &CancellationToken::new(),
            )
            .expect("reordered preloaded raw reverse reads are infallible")
            .into_parts();

        assert_eq!(ordered, reversed);
        assert_eq!(ordered.0.len(), MAX_SOURCE_ROWS_PER_BATCH + 1);
        assert!(ordered.1.is_empty());
        assert_eq!(ordered.3.as_ref(), &[ResolutionCompletion::Complete]);
        for sizes in [
            &recording.classified_batch_sizes,
            &recording.reverse_match_batch_sizes,
            &recording.hydration_batch_sizes,
        ] {
            assert!(
                sizes
                    .borrow()
                    .iter()
                    .all(|&size| size <= MAX_SOURCE_ROWS_PER_BATCH),
                "every source page must respect the explicit row cap: {:?}",
                sizes.borrow()
            );
            assert!(
                sizes.borrow().contains(&MAX_SOURCE_ROWS_PER_BATCH),
                "the law must exercise one full source page: {:?}",
                sizes.borrow()
            );
        }
        assert!(
            recording.classified_batch_sizes.borrow().contains(&1),
            "the final classification page must contain the fanout remainder"
        );
        assert!(
            recording.reverse_match_batch_sizes.borrow().contains(&1),
            "the reverse matcher must receive the one-endpoint fanout request"
        );
        assert!(
            recording
                .reverse_match_output_page_sizes
                .borrow()
                .iter()
                .all(|&size| (1..=MAX_SOURCE_ROWS_PER_BATCH).contains(&size)),
            "every returned reverse match page must respect the row cap: {:?}",
            recording.reverse_match_output_page_sizes.borrow()
        );
        assert!(
            recording
                .reverse_match_output_page_sizes
                .borrow()
                .contains(&MAX_SOURCE_ROWS_PER_BATCH),
            "one endpoint must emit one full reverse output page"
        );
        assert!(
            recording
                .reverse_match_output_page_sizes
                .borrow()
                .contains(&1),
            "one endpoint must emit the reverse output remainder"
        );
        assert!(
            recording.hydration_batch_sizes.borrow().contains(&1),
            "the final hydration page must contain the fanout remainder"
        );
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
    fn cancellation_after_one_high_fanout_match_page_is_atomic_in_both_directions() {
        let forward_fragment = fragment("forward-output-page-cancellation");
        let forward_reference = semantic("forward-output-page-cancellation-reference");
        let forward_reference_node = node("forward-output-page-cancellation-reference-node");
        let mut forward_nodes = vec![(
            forward_reference_node,
            BindingNodeKind::Reference(forward_reference),
        )];
        let mut forward_paths = Vec::new();
        for ordinal in 0..=MAX_SOURCE_ROWS_PER_BATCH {
            let target = semantic(&format!(
                "forward-output-page-cancellation-target-{ordinal}"
            ));
            let target_node = node(&format!(
                "forward-output-page-cancellation-target-node-{ordinal}"
            ));
            forward_nodes.push((target_node, BindingNodeKind::Definition(target)));
            forward_paths.push((
                path_id(&format!("forward-output-page-cancellation-path-{ordinal}")),
                path(
                    forward_reference_node,
                    target_node,
                    ResolutionCompletion::Complete,
                ),
            ));
        }
        let forward_source = PreloadedFragmentSource::from_fragments([PreloadedFragment::new(
            forward_fragment,
            forward_nodes,
            forward_paths,
        )]);
        let forward =
            FaultingSource::new(&forward_source, TestFault::CancelAfterFirstForwardMatchPage);
        let forward_answer = BatchResolutionEngine::new(&forward)
            .resolve_reference(
                ResolutionQuery::new(forward_reference),
                &CancellationToken::new(),
            )
            .expect("cancelled preloaded forward output paging is infallible");
        assert!(forward_answer.targets().is_empty());
        assert!(forward_answer.witnesses().is_empty());
        assert!(
            forward_answer
                .completion()
                .contains_reason(ResolutionIncompleteReason::Cancelled)
        );
        assert_eq!(
            forward.forward_match_output_page_sizes.borrow().as_slice(),
            &[MAX_SOURCE_ROWS_PER_BATCH]
        );

        let reverse_fragment = fragment("reverse-output-page-cancellation");
        let reverse_target = semantic("reverse-output-page-cancellation-target");
        let reverse_target_node = node("reverse-output-page-cancellation-target-node");
        let mut reverse_nodes = vec![(
            reverse_target_node,
            BindingNodeKind::Definition(reverse_target),
        )];
        let mut reverse_paths = Vec::new();
        for ordinal in 0..=MAX_SOURCE_ROWS_PER_BATCH {
            let reference = semantic(&format!(
                "reverse-output-page-cancellation-reference-{ordinal}"
            ));
            let reference_node = node(&format!(
                "reverse-output-page-cancellation-reference-node-{ordinal}"
            ));
            reverse_nodes.push((reference_node, BindingNodeKind::Reference(reference)));
            reverse_paths.push((
                path_id(&format!("reverse-output-page-cancellation-path-{ordinal}")),
                path(
                    reference_node,
                    reverse_target_node,
                    ResolutionCompletion::Complete,
                ),
            ));
        }
        let reverse_source = PreloadedFragmentSource::from_fragments([PreloadedFragment::new(
            reverse_fragment,
            reverse_nodes,
            reverse_paths,
        )]);
        let reverse =
            FaultingSource::new(&reverse_source, TestFault::CancelAfterFirstReverseMatchPage);
        let reverse_answer = BatchResolutionEngine::new(&reverse)
            .reverse_candidate_references(
                &[(reverse_target, reverse_target_node)],
                &CancellationToken::new(),
            )
            .expect("cancelled preloaded reverse output paging is infallible");
        assert!(reverse_answer.candidates.is_empty());
        assert!(reverse_answer.frontiers.is_empty());
        assert!(
            reverse_answer.completions[0].contains_reason(ResolutionIncompleteReason::Cancelled)
        );
        assert_eq!(
            reverse.reverse_match_output_page_sizes.borrow().as_slice(),
            &[MAX_SOURCE_ROWS_PER_BATCH]
        );
    }

    #[test]
    fn reverse_seed_result_order_does_not_change_forward_validation() {
        let fixture = shared_fixture(false);
        let reordered = FaultingSource::new(&fixture.source, TestFault::ReverseSeedOrder);
        let cancellation = CancellationToken::new();

        let expected = BatchResolutionEngine::new(&fixture.source)
            .references_to(fixture.target, &cancellation)
            .expect("preloaded batch source is infallible");
        let actual = BatchResolutionEngine::new(&reordered)
            .references_to(fixture.target, &cancellation)
            .expect("reordered bulk seed issuance remains valid");

        assert_eq!(actual, expected);
        assert_eq!(reordered.reference_seeds.get(), 0);
        assert_eq!(reordered.reverse_seed_batches.get(), 1);
        assert_eq!(reordered.reverse_seed_batch_sizes.borrow().as_slice(), &[3]);
    }

    #[test]
    fn reverse_seed_issuance_is_bounded_before_fragment_major_validation() {
        let owner = fragment("reverse-seed-bound-fragment");
        let target = semantic("reverse-seed-bound-target");
        let target_node = node("reverse-seed-bound-target-node");
        let mut nodes = vec![(target_node, BindingNodeKind::Definition(target))];
        let mut paths = Vec::new();
        let mut expected = Vec::new();
        for ordinal in 0..=MAX_REFERENCE_SEEDS_PER_BATCH {
            let reference = semantic(&format!("reverse-seed-bound-reference-{ordinal}"));
            let reference_node = node(&format!("reverse-seed-bound-node-{ordinal}"));
            nodes.push((reference_node, BindingNodeKind::Reference(reference)));
            paths.push((
                path_id(&format!("reverse-seed-bound-path-{ordinal}")),
                path(reference_node, target_node, ResolutionCompletion::Complete),
            ));
            expected.push(reference);
        }
        expected.sort_unstable();
        let source =
            PreloadedFragmentSource::from_fragments([PreloadedFragment::new(owner, nodes, paths)]);
        let recording = FaultingSource::new(&source, TestFault::None);

        let answer = BatchResolutionEngine::new(&recording)
            .references_to(target, &CancellationToken::new())
            .expect("bounded preloaded seed issuance is infallible");

        assert_eq!(answer.references(), expected);
        assert_eq!(recording.reference_seeds.get(), 0);
        assert_eq!(recording.reverse_seed_batches.get(), 2);
        assert_eq!(
            recording.reverse_seed_batch_sizes.borrow().as_slice(),
            &[MAX_REFERENCE_SEEDS_PER_BATCH, 1]
        );
        assert_eq!(
            recording.reverse_seed_requests.borrow().len(),
            MAX_REFERENCE_SEEDS_PER_BATCH + 1
        );
    }

    #[test]
    fn reverse_seed_issuance_rejects_missing_or_mismatched_rows_atomically() {
        let fixture = shared_fixture(false);

        for fault in [
            TestFault::MissingReverseSeed,
            TestFault::WrongReverseSeedSemantic,
            TestFault::WrongReverseSeedNode,
        ] {
            let source = FaultingSource::new(&fixture.source, fault);
            let result = BatchResolutionEngine::new(&source)
                .references_to(fixture.target, &CancellationToken::new());

            let error = result.expect_err("invalid bulk seed issuance must fail closed");
            assert!(
                error
                    .to_string()
                    .contains("reverse reference seed mismatch"),
                "unexpected error for {fault:?}: {error}"
            );
            assert_eq!(source.reference_seeds.get(), 0);
            assert_eq!(source.reverse_seed_batches.get(), 1);
            assert_eq!(source.forward_matches.get(), 0);
        }
    }

    #[test]
    fn shared_reverse_candidates_are_hydrated_once_per_operation() {
        let fragment = fragment("reverse-shared-fragment");
        let reference = semantic("reverse-shared-reference");
        let target = semantic("reverse-shared-target");
        let member_owner = semantic("reverse-shared-member-owner");
        let reference_node = node("reverse-shared-reference-node");
        let seam = node("reverse-shared-seam");
        let target_node = node("reverse-shared-target-node");
        let entry_id = path_id("reverse-shared-entry");
        let first_exit_id = path_id("reverse-shared-first-exit");
        let second_exit_id = path_id("reverse-shared-second-exit");
        let entry = CandidatePathIdentity::new(fragment, entry_id);
        let first_exit = CandidatePathIdentity::new(fragment, first_exit_id);
        let second_exit = CandidatePathIdentity::new(fragment, second_exit_id);
        let mut source = PreloadedFragmentSource::from_fragments([PreloadedFragment::new(
            fragment,
            [
                (reference_node, BindingNodeKind::Reference(reference)),
                (seam, BindingNodeKind::Scope),
                (target_node, BindingNodeKind::Definition(target)),
            ],
            [
                (
                    entry_id,
                    path(reference_node, seam, ResolutionCompletion::Complete),
                ),
                (
                    first_exit_id,
                    path(seam, target_node, ResolutionCompletion::Complete),
                ),
                (
                    second_exit_id,
                    path(seam, target_node, ResolutionCompletion::Complete),
                ),
            ],
        )]);
        source.install_member_scope_owners([(seam, member_owner)]);
        let recording = FaultingSource::new(&source, TestFault::None);

        let candidates = BatchResolutionEngine::new(&recording)
            .reverse_candidate_references(&[(target, target_node)], &CancellationToken::new())
            .expect("preloaded reverse source is infallible");

        assert_eq!(
            candidates.candidates,
            [ReverseCandidateReference {
                target: 0,
                reference,
                node: reference_node,
            }]
        );
        assert_eq!(
            candidates.frontiers.len(),
            1,
            "two convergent reverse exits must retain one exact (target, full start signature) frontier"
        );
        assert_eq!(candidates.frontiers[0].target(), 0);
        assert_eq!(candidates.frontiers[0].owner(), member_owner);
        assert_eq!(candidates.frontiers[0].start().node(), seam);
        assert_eq!(
            candidates.completions.as_ref(),
            &[ResolutionCompletion::Complete]
        );
        let hydrated = recording.hydrated_candidates.borrow();
        for identity in [entry, first_exit, second_exit] {
            assert_eq!(
                hydrated
                    .iter()
                    .filter(|candidate| **candidate == identity)
                    .count(),
                1,
                "candidate {identity:?} must be hydrated exactly once: {hydrated:?}"
            );
        }
        drop(hydrated);

        let answer = BatchResolutionEngine::new(&recording)
            .references_to(target, &CancellationToken::new())
            .expect("preloaded reverse source is infallible");
        assert_eq!(answer.references(), &[reference]);
        assert_eq!(recording.reference_seeds.get(), 0);
        assert_eq!(recording.reverse_seed_batches.get(), 1);
        assert_eq!(recording.reverse_seed_batch_sizes.borrow().as_slice(), &[1]);
        assert_eq!(recording.reverse_seed_requests.borrow().len(), 1);
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

    #[test]
    fn reverse_completion_ledger_shares_common_evidence_across_sparse_answers() {
        let answers = 64;
        let deltas = (0..answers)
            .map(|ordinal| {
                ResolutionIncompleteReason::UnsupportedSemantic(semantic(&format!(
                    "reverse-ledger-delta-{ordinal}"
                )))
            })
            .collect::<Vec<_>>();
        let mut work_by_size = Vec::new();
        for count in [8, 512, 4_096] {
            let raw = ResolutionCompletion::incomplete((0..count).map(|ordinal| {
                ResolutionIncompleteReason::UnsupportedSemantic(semantic(&format!(
                    "reverse-ledger-common-{ordinal}"
                )))
            }));
            let ResolutionCompletion::Incomplete(raw) = raw else {
                unreachable!("the common ledger fixture is incomplete")
            };
            let cancellation = CancellationToken::new();
            let mut promotion_work = 0;
            let common = raw
                .to_shared_with_poll(&mut || {
                    promotion_work += 1;
                    false
                })
                .unwrap();
            assert_eq!(promotion_work, 2 * count);
            let mut work = 0;
            let mut ledger = BatchCompletionLedger::default();
            for &delta in &deltas {
                let local = common.union(&CompletionReasons::from(vec![delta]));
                assert!(!ledger.include(
                    &ResolutionCompletion::Incomplete(local),
                    &cancellation,
                    &mut work,
                ));
            }
            let (actual, observed) = ledger.finish(&cancellation, &mut work);
            assert!(!observed);
            let expected = ResolutionCompletion::incomplete(
                common.iter().copied().chain(deltas.iter().copied()),
            );
            assert_eq!(actual, expected);
            assert!(
                matches!(actual, ResolutionCompletion::Incomplete(reasons) if reasons.is_shared())
            );
            work_by_size.push(work);
        }
        // Promotion is linear once. Repeated unions copy sparse local deltas
        // and perform logarithmic cancellation membership probes, not base walks.
        assert!(
            work_by_size[2] <= work_by_size[0] * 2,
            "512-fold common-base growth must not multiply per-answer work: {work_by_size:?}"
        );
    }

    #[test]
    fn reverse_completion_ledger_growing_shared_deltas_do_not_rebuild_prior_operands() {
        let base = ResolutionCompletion::incomplete((0..64).map(|index| {
            ResolutionIncompleteReason::UnsupportedSemantic(semantic(&format!(
                "reverse-growing-common-{index}"
            )))
        }));
        let ResolutionCompletion::Incomplete(base_reasons) = &base else {
            unreachable!()
        };
        let shared = base_reasons.to_shared_with_poll(&mut || false).unwrap();
        let mut work_by_size = Vec::new();
        for count in [64, 256, 1_024] {
            let cancellation = CancellationToken::new();
            let mut ledger = BatchCompletionLedger::default();
            let mut work = 0;
            let mut expected = base_reasons.iter().copied().collect::<BTreeSet<_>>();
            for index in 0..count {
                let reason = ResolutionIncompleteReason::UnsupportedSemantic(semantic(&format!(
                    "reverse-growing-delta-{index}"
                )));
                expected.insert(reason);
                let operand = if index % 2 == 0 {
                    ResolutionCompletion::Incomplete(
                        shared.union(&CompletionReasons::from(vec![reason])),
                    )
                } else {
                    // Exercise the live diagnostic's factored/raw path. The
                    // repeated raw reason must not re-copy all earlier gaps.
                    ResolutionCompletion::Incomplete(vec![reason, reason].into())
                };
                assert!(!ledger.include(&operand, &cancellation, &mut work));
            }
            let (actual, cancelled) = ledger.finish(&cancellation, &mut work);
            assert!(!cancelled);
            assert_eq!(actual, ResolutionCompletion::incomplete(expected));
            assert!(
                matches!(actual, ResolutionCompletion::Incomplete(reasons) if reasons.is_shared())
            );
            work_by_size.push(work);
        }
        for pair in work_by_size.windows(2) {
            assert!(
                pair[1] <= pair[0] * 5,
                "fourfold input growth must not rebuild a quadratic prefix: {work_by_size:?}"
            );
        }
    }

    #[test]
    fn reverse_completion_ledger_mixed_shared_operands_preserve_full_cancelled_evidence() {
        let reasons = (0..32)
            .map(|index| {
                ResolutionIncompleteReason::UnsupportedSemantic(semantic(&format!(
                    "reverse-mixed-base-{index}"
                )))
            })
            .collect::<Vec<_>>();
        let shared = CompletionReasons::from(reasons.clone())
            .to_shared_with_poll(&mut || false)
            .unwrap();
        let excluded = shared.without_reasons([reasons[0], reasons[1]]).unwrap();
        let independent = CompletionReasons::from(vec![reasons[1], reasons[2], reasons[3]])
            .to_shared_with_poll(&mut || false)
            .unwrap();
        let final_reason =
            ResolutionIncompleteReason::UnsupportedSemantic(semantic("reverse-mixed-last-gap"));
        let operands = [
            ResolutionCompletion::Incomplete(vec![reasons[0], reasons[0], final_reason].into()),
            ResolutionCompletion::Incomplete(Vec::new().into_boxed_slice().into()),
            ResolutionCompletion::Incomplete(excluded),
            ResolutionCompletion::Incomplete(independent),
            ResolutionCompletion::Incomplete(vec![final_reason, reasons[0]].into()),
        ];
        for reversed in [false, true] {
            // Zero means a live token; thresholds exercise observation during
            // conversion, shared inclusion and final draining. Even after stop
            // all operands already returned by the source remain evidence.
            for checks in [0, 1, 3, 8, 16] {
                let cancellation = if checks == 0 {
                    CancellationToken::new()
                } else {
                    CancellationToken::cancel_after_checks_for_test(checks)
                };
                let mut ledger = BatchCompletionLedger::default();
                let mut work = 0;
                let mut expected = BTreeSet::new();
                for index in 0..operands.len() {
                    let operand = &operands[if reversed {
                        operands.len() - 1 - index
                    } else {
                        index
                    }];
                    if let ResolutionCompletion::Incomplete(reasons) = operand {
                        expected.extend(reasons.iter().copied());
                    }
                    ledger.include(operand, &cancellation, &mut work);
                }
                let (actual, observed) = ledger.finish(&cancellation, &mut work);
                if observed {
                    expected.insert(ResolutionIncompleteReason::Cancelled);
                }
                if checks == 0 {
                    assert!(!observed);
                } else if checks == 1 {
                    assert!(observed);
                }
                assert_eq!(actual, ResolutionCompletion::incomplete(expected));
                assert!(actual.contains_reason(final_reason));
            }
        }
    }

    #[test]
    fn shared_completion_ledgers_observe_cancelled_in_either_operand_order() {
        let raw = ResolutionCompletion::incomplete((0..4_096).map(|index| {
            ResolutionIncompleteReason::UnsupportedSemantic(semantic(&format!(
                "shared-cancelled-ledger-{index}"
            )))
        }));
        let ResolutionCompletion::Incomplete(reasons) = &raw else {
            unreachable!()
        };
        let shared =
            ResolutionCompletion::Incomplete(reasons.to_shared_with_poll(&mut || false).unwrap());
        let cancelled =
            ResolutionCompletion::Incomplete(vec![ResolutionIncompleteReason::Cancelled; 3].into());
        let expected = raw.combine(&cancelled);
        for operands in [[&shared, &cancelled], [&cancelled, &shared]] {
            let cancellation = CancellationToken::new();
            let mut work = 0;
            let mut semantic = BatchCompletionLedger::default();
            let mut evidence = CancellationEvidenceLedger::default();
            for operand in operands {
                semantic.include(operand, &cancellation, &mut work);
                evidence.include(operand, &cancellation, &mut work);
            }
            let (actual, observed) = semantic.finish(&cancellation, &mut work);
            assert!(observed);
            assert_eq!(actual, expected);
            let (actual, observed) = evidence.finish(false, &cancellation, &mut work);
            assert!(observed);
            assert_eq!(actual, expected);
            assert!(
                work < 200,
                "literal cancellation must not force a common-base scan: {work}"
            );
        }
    }

    #[test]
    fn cancellation_evidence_union_scales_with_distinct_sparse_additions() {
        fn expected(addition_count: usize) -> ResolutionCompletion {
            ResolutionCompletion::incomplete(
                (0..64)
                    .map(|index| {
                        ResolutionIncompleteReason::UnsupportedSemantic(semantic(&format!(
                            "cancel-evidence-common-{index}"
                        )))
                    })
                    .chain((0..addition_count).map(|index| {
                        ResolutionIncompleteReason::UnsupportedSemantic(semantic(&format!(
                            "cancel-evidence-addition-{index}"
                        )))
                    })),
            )
        }

        fn run(addition_count: usize) -> (ResolutionCompletion, usize, bool) {
            let common = ResolutionCompletion::Incomplete(
                CompletionReasons::from(
                    (0..64)
                        .map(|index| {
                            ResolutionIncompleteReason::UnsupportedSemantic(semantic(&format!(
                                "cancel-evidence-common-{index}"
                            )))
                        })
                        .collect::<Vec<_>>(),
                )
                .to_shared_with_poll(&mut || false)
                .expect("the common source evidence is nonempty"),
            );
            let ResolutionCompletion::Incomplete(common) = &common else {
                unreachable!("the common source evidence is incomplete")
            };
            let cancellation = CancellationToken::new();
            let mut ledger = CancellationEvidenceLedger::default();
            let mut work = 0_usize;
            for index in 0..addition_count {
                let addition = ResolutionIncompleteReason::UnsupportedSemantic(semantic(&format!(
                    "cancel-evidence-addition-{index}"
                )));
                let local = common.union(&CompletionReasons::from(vec![addition]));
                assert!(!ledger.include(
                    &ResolutionCompletion::Incomplete(local),
                    &cancellation,
                    &mut work,
                ));
            }
            let (completion, observed) = ledger.finish(false, &cancellation, &mut work);
            (completion, work, observed)
        }

        let (small, small_work, small_observed) = run(16);
        let (large, large_work, large_observed) = run(256);
        assert!(!small_observed && !large_observed);
        assert_eq!(small, expected(16));
        assert_eq!(large, expected(256));
        let ResolutionCompletion::Incomplete(large_reasons) = &large else {
            unreachable!("the distinct-addition evidence remains incomplete")
        };
        assert_eq!(large_reasons.len(), 320);
        assert!(
            large_work <= small_work.saturating_mul(24),
            "distinct sparse additions must not rescan the accumulated prefix: small={small_work}, large={large_work}"
        );
    }

    #[test]
    fn cancellation_evidence_absorb_preserves_mixed_shared_raw_and_cancelled_reasons() {
        let common = ResolutionCompletion::incomplete([
            ResolutionIncompleteReason::UnsupportedSemantic(semantic(
                "cancel-evidence-absorb-common-a",
            )),
            ResolutionIncompleteReason::UnsupportedSemantic(semantic(
                "cancel-evidence-absorb-common-b",
            )),
        ]);
        let ResolutionCompletion::Incomplete(common) = common else {
            unreachable!("the common source evidence is incomplete")
        };
        let common = common
            .to_shared_with_poll(&mut || false)
            .expect("the common source evidence is nonempty");
        let shared_reason = ResolutionIncompleteReason::UnsupportedSemantic(semantic(
            "cancel-evidence-absorb-shared",
        ));
        let raw_reason =
            ResolutionIncompleteReason::UnsupportedSemantic(semantic("cancel-evidence-absorb-raw"));
        let cancellation = CancellationToken::new();
        let mut work = 0_usize;
        let mut left = CancellationEvidenceLedger::default();
        let left_completion = ResolutionCompletion::Incomplete(
            common.union(&CompletionReasons::from(vec![shared_reason])),
        );
        assert!(!left.include(&left_completion, &cancellation, &mut work));

        let mut right = CancellationEvidenceLedger::default();
        let right_completion = ResolutionCompletion::incomplete([raw_reason]);
        assert!(!right.include(&right_completion, &cancellation, &mut work));
        left.absorb(right, &cancellation, &mut work);

        let mut empty = CancellationEvidenceLedger::default();
        let empty_completion =
            ResolutionCompletion::Incomplete(Vec::new().into_boxed_slice().into());
        assert!(!empty.include(&empty_completion, &cancellation, &mut work));
        left.absorb(empty, &cancellation, &mut work);

        left.include_reason(ResolutionIncompleteReason::Cancelled);
        let (actual, observed) = left.finish(false, &cancellation, &mut work);
        assert!(observed);
        assert_eq!(
            actual,
            ResolutionCompletion::incomplete(common.iter().copied().chain([
                shared_reason,
                raw_reason,
                ResolutionIncompleteReason::Cancelled
            ]),)
        );
    }

    #[test]
    fn reverse_cancellation_accounts_each_hydrated_candidate_completion_once() {
        let target_node = node("reverse-accounted-empty-target");
        let candidate_node = node("reverse-accounted-empty-candidate");
        let candidate_identity = CandidatePathIdentity::new(
            fragment("reverse-accounted-empty-fragment"),
            path_id("reverse-accounted-empty-path"),
        );
        let candidate = PartialPath::new(
            endpoint(candidate_node),
            endpoint(target_node),
            Vec::new(),
            Vec::new(),
            ResolutionCompletion::Incomplete(Vec::new().into_boxed_slice().into()),
        );
        let seed = identity_path(target_node);
        let expandable = [ReverseWorkPath {
            target: 0,
            path: seed.clone(),
            saturation: SaturationBranch::default(),
        }];
        let matches = [BatchCandidateMatch::new(candidate_identity, 0)];
        let mut arena = crate::hash::HashMap::default();
        arena.insert(candidate_identity, candidate);

        // A successful composition has already folded the candidate's empty
        // completion through the composed path before certification can
        // observe cancellation. Cleanup must not add that operand again.
        let cancellation = CancellationToken::new();
        let mut targets = [ReverseTargetState {
            completion: BatchCompletionLedger::default(),
            certifier: CycleCompletenessCertifier::new(&seed),
        }];
        let mut work = 0;
        assert!(!targets[0].completion.include(
            arena[&candidate_identity].completion(),
            &cancellation,
            &mut work,
        ));
        let mut accounted = [(0, candidate_identity)].into_iter().collect();
        cancellation.cancel();
        include_matched_hydrated_completions_after_cancellation(
            &mut targets,
            &expandable,
            &matches,
            &arena,
            &mut accounted,
            &cancellation,
            &mut work,
        );
        targets[0]
            .completion
            .include_reason(ResolutionIncompleteReason::Cancelled);
        let (completion, cancellation_observed) =
            std::mem::take(&mut targets[0].completion).finish(&cancellation, &mut work);
        assert!(cancellation_observed);
        assert_eq!(completion, cancelled_completion());

        // A returned row never reached by composition still contributes its
        // empty box exactly once before cancellation is combined with it.
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let mut targets = [ReverseTargetState {
            completion: BatchCompletionLedger::default(),
            certifier: CycleCompletenessCertifier::new(&seed),
        }];
        let mut accounted = crate::hash::HashSet::default();
        let mut work = 0;
        include_matched_hydrated_completions_after_cancellation(
            &mut targets,
            &expandable,
            &matches,
            &arena,
            &mut accounted,
            &cancellation,
            &mut work,
        );
        assert_eq!(accounted, [(0, candidate_identity)].into_iter().collect());
        targets[0]
            .completion
            .include_reason(ResolutionIncompleteReason::Cancelled);
        let (completion, cancellation_observed) =
            std::mem::take(&mut targets[0].completion).finish(&cancellation, &mut work);
        assert!(cancellation_observed);
        assert_eq!(completion, cancelled_completion());
    }

    #[test]
    fn reverse_post_match_cancelled_cleanup_retains_valid_cached_candidate_evidence() {
        let target_node = node("reverse-post-match-cancelled-target");
        let candidate_identity = CandidatePathIdentity::new(
            fragment("reverse-post-match-cancelled-fragment"),
            path_id("reverse-post-match-cancelled-path"),
        );
        let candidate_gap = semantic("reverse-post-match-cached-candidate-gap");
        let source_gap = semantic("reverse-post-match-source-gap");
        let candidate = PartialPath::new(
            endpoint(node("reverse-post-match-cancelled-candidate")),
            endpoint(target_node),
            Vec::new(),
            Vec::new(),
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                candidate_gap,
            )]),
        );
        let seed = identity_path(target_node);
        let expandable = [ReverseWorkPath {
            target: 0,
            path: seed.clone(),
            saturation: SaturationBranch::default(),
        }];
        let matches = [
            BatchCandidateMatch::new(candidate_identity, 0),
            BatchCandidateMatch::new(candidate_identity, usize::MAX),
        ];
        let mut arena = crate::hash::HashMap::default();
        arena.insert(candidate_identity, candidate);
        let cancellation = CancellationToken::new();
        let mut targets = [ReverseTargetState {
            completion: BatchCompletionLedger::default(),
            certifier: CycleCompletenessCertifier::new(&seed),
        }];
        let mut work = 0;
        assert!(targets[0].completion.include(
            &ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(source_gap),
                ResolutionIncompleteReason::Cancelled,
            ]),
            &cancellation,
            &mut work,
        ));
        let mut accounted = crate::hash::HashSet::default();

        include_matched_hydrated_completions_after_cancellation(
            &mut targets,
            &expandable,
            &matches,
            &arena,
            &mut accounted,
            &cancellation,
            &mut work,
        );
        targets[0]
            .completion
            .include_reason(ResolutionIncompleteReason::Cancelled);
        let (completion, cancellation_observed) =
            std::mem::take(&mut targets[0].completion).finish(&cancellation, &mut work);

        assert!(cancellation_observed);
        assert_eq!(accounted, [(0, candidate_identity)].into_iter().collect());
        assert!(completion.contains_reason(ResolutionIncompleteReason::Cancelled));
        assert!(
            completion.contains_reason(ResolutionIncompleteReason::UnsupportedSemantic(source_gap))
        );
        assert!(
            completion.contains_reason(ResolutionIncompleteReason::UnsupportedSemantic(
                candidate_gap
            ))
        );
    }

    #[test]
    fn source_returned_reverse_cancelled_evidence_is_atomic_with_a_live_token() {
        let fixture = shared_fixture(false);
        let source = FaultingSource::new(
            &fixture.source,
            TestFault::ReverseMatchWithCancelledEvidence,
        );
        let cancellation = CancellationToken::new();

        let raw = BatchResolutionEngine::new(&source)
            .reverse_candidate_references(&[(fixture.target, fixture.target_node)], &cancellation)
            .expect("source-returned cancellation is semantic operation evidence");

        assert!(!cancellation.is_cancelled());
        assert!(raw.candidates.is_empty());
        assert!(raw.frontiers.is_empty());
        assert!(
            raw.completions[0].contains_reason(ResolutionIncompleteReason::Cancelled),
            "returned Cancelled evidence must suppress every unpublished reverse row"
        );
    }

    #[test]
    fn reverse_member_frontier_classification_cancellation_is_atomic() {
        let fragment = fragment("reverse-frontier-classification-cancellation-fragment");
        let target = semantic("reverse-frontier-classification-cancellation-target");
        let target_node = node("reverse-frontier-classification-cancellation-target-node");
        let scope_head = node("reverse-frontier-classification-cancellation-head");
        let owner = semantic("reverse-frontier-classification-cancellation-owner");
        let path_gap = semantic("reverse-frontier-classification-cancellation-gap");
        let mut source = PreloadedFragmentSource::from_fragments([PreloadedFragment::new(
            fragment,
            [
                (scope_head, BindingNodeKind::Scope),
                (target_node, BindingNodeKind::Definition(target)),
            ],
            [(
                path_id("reverse-frontier-classification-cancellation-path"),
                path(
                    scope_head,
                    target_node,
                    ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(path_gap),
                    ]),
                ),
            )],
        )]);
        source.install_member_scope_owners([(scope_head, owner)]);
        let faulting =
            FaultingSource::new(&source, TestFault::CancelAfterMemberScopeClassification);
        let cancellation = CancellationToken::new();

        let raw = BatchResolutionEngine::new(&faulting)
            .reverse_candidate_references(&[(target, target_node)], &cancellation)
            .expect("source-returned endpoint cancellation is operational");

        assert!(cancellation.is_cancelled());
        assert!(raw.candidates.is_empty());
        assert!(raw.frontiers.is_empty());
        assert!(raw.completions[0].contains_reason(ResolutionIncompleteReason::Cancelled));
        assert!(
            raw.completions[0]
                .contains_reason(ResolutionIncompleteReason::UnsupportedSemantic(path_gap))
        );
    }

    #[test]
    fn raw_reverse_universal_root_tokens_are_not_lexical_lookup_frontiers() {
        let owner = fragment("root-token-not-lookup-owner");
        let reference = semantic("root-token-not-lookup-reference");
        let reference_node = node("root-token-not-lookup-reference");
        let target = semantic("root-token-not-lookup-target");
        let target_node = node("root-token-not-lookup-target");
        let scope = node("root-token-not-lookup-scope");
        let lookup = semantic("root-token-not-lookup-source-demand");
        let token = semantic("root-token-not-lookup-export-rewrite");
        let root = BindingNodeId::universal_root();
        let source_start = symbol_endpoint(scope, [lookup]);
        let root_start = symbol_endpoint(root, [token]);
        let make_path = |start, end| {
            PartialPath::new(
                start,
                end,
                Vec::new(),
                Vec::new(),
                ResolutionCompletion::Complete,
            )
        };
        let source = PreloadedFragmentSource::from_fragments_with_boundaries(
            [root],
            [PreloadedFragment::new(
                owner,
                [
                    (reference_node, BindingNodeKind::Reference(reference)),
                    (scope, BindingNodeKind::Scope),
                    (target_node, BindingNodeKind::Definition(target)),
                ],
                [
                    (
                        path_id("root-token-reference"),
                        make_path(endpoint(reference_node), source_start.clone()),
                    ),
                    (
                        path_id("root-token-export"),
                        make_path(source_start.clone(), root_start.clone()),
                    ),
                    (
                        path_id("root-token-definition"),
                        make_path(root_start, endpoint(target_node)),
                    ),
                ],
            )],
        );
        let raw = BatchResolutionEngine::new(&source)
            .reverse_candidate_references(&[(target, target_node)], &CancellationToken::new())
            .expect("root rewrite traversal does not require interpreting its token as a lookup");
        assert!(raw.frontiers.is_empty());
        assert_eq!(raw.lexical_frontiers.len(), 1);
        assert_eq!(raw.lexical_frontiers[0].start(), &source_start);
        assert_eq!(raw.candidates.len(), 1);
        assert_eq!(raw.candidates[0].reference(), reference);
        assert_eq!(raw.completions.as_ref(), &[ResolutionCompletion::Complete]);
    }

    #[test]
    fn raw_reverse_lexical_frontiers_preserve_alias_stacks_and_target_identity() {
        let owner = fragment("lexical-frontier-alias-owner");
        let reference = semantic("lexical-frontier-reference");
        let reference_node = node("lexical-frontier-reference");
        let alias_head = node("lexical-frontier-alias-head");
        let direct_head = node("lexical-frontier-direct-head");
        let alias = semantic("lexical-frontier-alias-lookup");
        let direct = semantic("lexical-frontier-direct-lookup");
        let suffix = semantic("lexical-frontier-qualified-suffix");
        let targets = [
            (
                semantic("lexical-frontier-target-a"),
                node("lexical-frontier-target-a"),
            ),
            (
                semantic("lexical-frontier-target-b"),
                node("lexical-frontier-target-b"),
            ),
        ];
        let endpoint = |head, symbols: Vec<SemanticId>| {
            EndpointSignature::new(
                head,
                StackPattern::closed(symbols),
                StackPattern::closed(Vec::new()),
            )
        };
        let alias_start = endpoint(alias_head, vec![alias, suffix]);
        let direct_start = endpoint(direct_head, vec![direct, suffix]);
        let make_path = |start, end| {
            PartialPath::new(
                start,
                end,
                Vec::new(),
                Vec::new(),
                ResolutionCompletion::Complete,
            )
        };
        let mut nodes = vec![
            (reference_node, BindingNodeKind::Reference(reference)),
            (alias_head, BindingNodeKind::Scope),
            (direct_head, BindingNodeKind::Scope),
        ];
        nodes.extend(targets.map(|(semantic, node)| (node, BindingNodeKind::Definition(semantic))));
        let mut paths = vec![
            (
                path_id("lexical-frontier-entry"),
                make_path(endpoint(reference_node, Vec::new()), alias_start.clone()),
            ),
            (
                path_id("lexical-frontier-rename"),
                make_path(alias_start.clone(), direct_start.clone()),
            ),
        ];
        for (index, (_, target_node)) in targets.iter().enumerate() {
            for duplicate in 0..2 {
                paths.push((
                    PartialPathId::for_test(format!("lexical-frontier-exit-{index}-{duplicate}")),
                    make_path(direct_start.clone(), endpoint(*target_node, Vec::new())),
                ));
            }
        }
        for reverse_order in [false, true] {
            let mut paths = paths.clone();
            let mut requested = targets;
            if reverse_order {
                paths.reverse();
                requested.reverse();
            }
            let source = PreloadedFragmentSource::from_fragments([PreloadedFragment::new(
                owner,
                nodes.clone(),
                paths,
            )]);
            let raw = BatchResolutionEngine::new(&source)
                .reverse_candidate_references(&requested, &CancellationToken::new())
                .expect("untyped lexical scopes remain observable reverse continuations");
            assert!(
                raw.frontiers.is_empty(),
                "ordinary scopes must not acquire fake typed owners"
            );
            let actual = raw
                .lexical_frontiers
                .iter()
                .map(|frontier| (requested[frontier.target()].0, frontier.start().clone()))
                .collect::<crate::hash::HashSet<_>>();
            let expected = targets
                .into_iter()
                .flat_map(|(target, _)| {
                    [
                        (target, alias_start.clone()),
                        (target, direct_start.clone()),
                    ]
                })
                .collect::<crate::hash::HashSet<_>>();
            assert_eq!(actual, expected);
            assert_eq!(
                raw.lexical_frontiers.len(),
                expected.len(),
                "convergent exits retain one exact target/signature frontier"
            );
            assert_eq!(
                raw.candidates.len(),
                2,
                "retaining lexical frontiers must not stop raw expansion"
            );
            assert_eq!(
                raw.candidates
                    .iter()
                    .map(|candidate| requested[candidate.target()].0)
                    .collect::<BTreeSet<_>>(),
                targets
                    .map(|(target, _)| target)
                    .into_iter()
                    .collect::<BTreeSet<_>>(),
            );
            for candidate in &raw.candidates {
                assert_eq!(candidate.reference(), reference);
                assert_eq!(candidate.node(), reference_node);
            }
            assert_eq!(
                raw.completions.as_ref(),
                &[
                    ResolutionCompletion::Complete,
                    ResolutionCompletion::Complete
                ]
            );
        }
    }

    #[test]
    fn raw_reverse_lexical_open_frontier_is_atomic_with_returned_evidence() {
        let owner = fragment("lexical-frontier-open-owner");
        let target = semantic("lexical-frontier-open-target");
        let target_node = node("lexical-frontier-open-target");
        let head = node("lexical-frontier-open-head");
        let gap = semantic("lexical-frontier-open-gap");
        let start = EndpointSignature::new(
            head,
            StackPattern::open(
                Vec::new(),
                StackVariableId::for_test("lexical-frontier-open-symbols"),
            ),
            StackPattern::closed(Vec::new()),
        );
        let exit = PartialPath::new(
            start.clone(),
            identity_path(target_node).end().clone(),
            Vec::new(),
            Vec::new(),
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                gap,
            )]),
        );
        let source = PreloadedFragmentSource::from_fragments([PreloadedFragment::new(
            owner,
            [
                (head, BindingNodeKind::Scope),
                (target_node, BindingNodeKind::Definition(target)),
            ],
            [(path_id("lexical-frontier-open-exit"), exit)],
        )]);
        let raw = BatchResolutionEngine::new(&source)
            .reverse_candidate_references(&[(target, target_node)], &CancellationToken::new())
            .expect("variable-only lexical continuations are retained");
        assert!(raw.frontiers.is_empty());
        assert_eq!(raw.lexical_frontiers.len(), 1);
        assert_eq!(raw.lexical_frontiers[0].start(), &start);
        assert!(
            raw.completions[0]
                .contains_reason(ResolutionIncompleteReason::UnsupportedSemantic(gap))
        );

        // Cancel after a real lexical frontier and its source evidence have
        // been collected, at the atomic publication boundary.
        let cancellation = CancellationToken::new();
        let mut completion = BatchCompletionLedger::default();
        let mut work = 0;
        assert!(!completion.include(&raw.completions[0], &cancellation, &mut work));
        cancellation.cancel();
        let cancelled =
            BatchResolutionEngine::<PreloadedFragmentSource>::finish_reverse_candidate_batch(
                ReverseCandidateFinalization {
                    candidates: raw.candidates,
                    frontiers: raw.frontiers,
                    lexical_frontiers: raw.lexical_frontiers,
                    targets: vec![ReverseTargetState {
                        completion,
                        certifier: CycleCompletenessCertifier::new(&identity_path(target_node)),
                    }],
                    completion_work: work,
                    composition_attempts: 0,
                    cancelled: false,
                },
                &cancellation,
            )
            .expect(
                "late cancellation preserves source evidence without publishing a frontier prefix",
            );
        assert!(cancelled.candidates.is_empty());
        assert!(cancelled.frontiers.is_empty());
        assert!(cancelled.lexical_frontiers.is_empty());
        assert!(cancelled.completions[0].contains_reason(ResolutionIncompleteReason::Cancelled));
        assert!(
            cancelled.completions[0]
                .contains_reason(ResolutionIncompleteReason::UnsupportedSemantic(gap))
        );
    }

    #[test]
    fn raw_reverse_classified_frontier_preserves_open_stack_unification() {
        let fragment_owner = fragment("reverse-open-observer-fragment");
        let member_owner = semantic("reverse-open-observer-member-owner");
        let target = semantic("reverse-open-observer-target");
        let target_node = node("reverse-open-observer-target-node");
        let seam = node("reverse-open-observer-seam");
        let reference_node = node("reverse-open-observer-reference-node");
        let lookup = semantic("reverse-open-observer-lookup");
        let variable = StackVariableId::for_test("reverse-open-observer-variable");
        let open_exit = PartialPath::new(
            EndpointSignature::new(
                seam,
                StackPattern::open(Vec::new(), variable),
                StackPattern::closed(Vec::new()),
            ),
            EndpointSignature::new(
                target_node,
                StackPattern::closed(Vec::new()),
                StackPattern::closed(Vec::new()),
            ),
            Vec::new(),
            [WitnessStep::Node(target_node)],
            ResolutionCompletion::Complete,
        );
        let mut source = PreloadedFragmentSource::from_fragments([PreloadedFragment::new(
            fragment_owner,
            [
                (seam, BindingNodeKind::Scope),
                (target_node, BindingNodeKind::Definition(target)),
            ],
            [(path_id("reverse-open-observer-exit"), open_exit)],
        )]);
        source.install_member_scope_owners([(seam, member_owner)]);

        let raw = BatchResolutionEngine::new(&source)
            .reverse_candidate_references(&[(target, target_node)], &CancellationToken::new())
            .expect("preloaded reverse source is infallible");
        assert_eq!(raw.frontiers.len(), 1);
        assert_eq!(raw.frontiers[0].owner(), member_owner);
        assert!(raw.frontiers[0].start().symbols().tail().is_some());

        let seeded = PartialPath::new(
            EndpointSignature::new(
                reference_node,
                StackPattern::closed(Vec::new()),
                StackPattern::closed(Vec::new()),
            ),
            EndpointSignature::new(
                seam,
                StackPattern::closed([lookup]),
                StackPattern::closed(Vec::new()),
            ),
            Vec::new(),
            [WitnessStep::Node(seam)],
            ResolutionCompletion::Complete,
        );
        assert!(
            seeded
                .end()
                .can_concatenate_with_poll(raw.frontiers[0].start(), &mut || false,)
                .expect("uncancelled endpoint compatibility completes")
                .is_ok(),
            "typed reverse must use full stack unification, not endpoint equality"
        );
    }

    #[test]
    fn raw_reverse_large_composition_cancels_atomically_and_retains_returned_gap() {
        const STRUCTURAL_CHECKPOINTS: usize = 8;
        const CANCEL_DURING_COMPOSITION_CHECK: usize = 39;

        let owner = fragment("reverse-large-composition-fragment");
        let target = semantic("reverse-large-composition-target");
        let target_node = node("reverse-large-composition-target-node");
        let seam = node("reverse-large-composition-seam");
        let candidate_id = path_id("reverse-large-composition-candidate");
        let path_gap = semantic("reverse-large-composition-path-gap");
        let candidate = PartialPath::new(
            endpoint(seam),
            endpoint(target_node),
            Vec::new(),
            std::iter::repeat_n(
                WitnessStep::Node(seam),
                CANCELLATION_QUANTUM * STRUCTURAL_CHECKPOINTS + 1,
            )
            .collect::<Vec<_>>(),
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                path_gap,
            )]),
        );
        let source = PreloadedFragmentSource::from_fragments([PreloadedFragment::new(
            owner,
            [
                (seam, BindingNodeKind::Scope),
                (target_node, BindingNodeKind::Definition(target)),
            ],
            [(candidate_id, candidate)],
        )]);
        let faulting = FaultingSource::new(&source, TestFault::ReverseMatchWithGap);
        // Twenty-four fixed-shape checks reach hydration. Its eight witness
        // clone checkpoints and the three validation/arena checks complete
        // first; check 39 is then the fourth checkpoint inside the single
        // candidate/path composition, with several structural checkpoints on
        // either side of it rather than a one-check boundary dependency.
        let cancellation =
            CancellationToken::cancel_after_checks_for_test(CANCEL_DURING_COMPOSITION_CHECK);

        let raw = BatchResolutionEngine::new(&faulting)
            .reverse_candidate_references(&[(target, target_node)], &cancellation)
            .expect("preloaded reverse source is infallible");

        assert!(raw.candidates.is_empty());
        assert!(raw.frontiers.is_empty());
        assert_eq!(
            faulting.hydrated_candidates.borrow().as_slice(),
            &[CandidatePathIdentity::new(owner, candidate_id)],
            "cancellation must occur after hydration, inside structural composition"
        );
        assert!(raw.completions[0].contains_reason(
            ResolutionIncompleteReason::UnsupportedSemantic(semantic(
                "reverse-candidate-sibling-gap"
            ))
        ));
        assert!(
            raw.completions[0]
                .contains_reason(ResolutionIncompleteReason::UnsupportedSemantic(path_gap))
        );
        assert!(
            raw.completions[0].contains_reason(ResolutionIncompleteReason::Cancelled),
            "a cancelled structural composition must never publish a partial frontier"
        );
    }

    #[test]
    fn raw_reverse_final_candidate_canonicalization_is_cancellation_atomic() {
        let mut rows = (0..=CANCELLATION_QUANTUM)
            .map(|ordinal| ReverseCandidateReference {
                target: 0,
                reference: semantic(&format!("reverse-final-candidate-{ordinal}")),
                node: node(&format!("reverse-final-candidate-node-{ordinal}")),
            })
            .collect::<Vec<_>>();
        rows.reverse();
        let cancellation = CancellationToken::cancel_after_checks_for_test(1);
        let mut work = 0;

        let canonical = canonicalize_reverse_candidates(rows, &cancellation, &mut work)
            .expect("fixed-size reverse candidate rows are valid");

        assert!(canonical.is_none());
        assert!(cancellation.is_cancelled());
        assert!(
            work >= CANCELLATION_QUANTUM,
            "cancellation must be polled within the one large final canonicalization"
        );
    }

    #[test]
    fn reverse_candidates_are_forward_validated_once_and_shadowed_false_positives_are_removed() {
        let owner = fragment("reverse-shadow-fragment");
        let reference = semantic("reverse-shadow-reference");
        let local = semantic("reverse-shadow-local");
        let imported = semantic("reverse-shadow-imported");
        let choice = semantic("reverse-shadow-choice");
        let reference_node = node("reverse-shadow-reference-node");
        let local_node = node("reverse-shadow-local-node");
        let imported_node = node("reverse-shadow-imported-node");
        let source = PreloadedFragmentSource::from_fragments([PreloadedFragment::new(
            owner,
            [
                (reference_node, BindingNodeKind::Reference(reference)),
                (local_node, BindingNodeKind::Definition(local)),
                (imported_node, BindingNodeKind::Definition(imported)),
            ],
            [
                (
                    path_id("reverse-shadow-local-path"),
                    ranked_path(
                        reference_node,
                        local_node,
                        choice,
                        PrecedenceTier::LexicalBinding,
                    ),
                ),
                (
                    path_id("reverse-shadow-imported-path"),
                    ranked_path(
                        reference_node,
                        imported_node,
                        choice,
                        PrecedenceTier::ExplicitImport,
                    ),
                ),
            ],
        )]);
        let recording = FaultingSource::new(&source, TestFault::None);

        let answer = BatchResolutionEngine::new(&recording)
            .references_to(imported, &CancellationToken::new())
            .expect("preloaded batch source is infallible");

        assert!(answer.references().is_empty());
        assert!(answer.witnesses().is_empty());
        assert_eq!(answer.completion(), &ResolutionCompletion::Complete);
        assert_eq!(recording.reference_seeds.get(), 0);
        assert_eq!(recording.reverse_seed_batches.get(), 1);
        assert_eq!(recording.reverse_seed_requests.borrow().len(), 1);
    }

    #[test]
    fn reverse_zero_match_gap_cannot_prove_a_negative() {
        let fixture = shared_fixture(false);
        let source = FaultingSource::new(&fixture.source, TestFault::EmptyReverseMatchWithGap);

        let answer = BatchResolutionEngine::new(&source)
            .references_to(fixture.target, &CancellationToken::new())
            .expect("semantic reverse gaps are typed incompleteness");

        assert!(answer.references().is_empty());
        assert!(answer.witnesses().is_empty());
        assert!(matches!(
            answer.completion(),
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(
                    semantic("reverse-candidate-coverage-gap")
                ))
        ));
        assert_eq!(source.reference_seeds.get(), 0);
        assert_eq!(source.reverse_seed_batches.get(), 0);
    }

    #[test]
    fn reverse_match_cancellation_preserves_returned_gap_evidence() {
        let fixture = shared_fixture(false);
        let source = FaultingSource::new(&fixture.source, TestFault::CancelOnReverseMatchWithGap);

        let answer = BatchResolutionEngine::new(&source)
            .references_to(fixture.target, &CancellationToken::new())
            .expect("reverse cancellation and gaps are typed incompleteness");

        assert!(answer.references().is_empty());
        assert!(matches!(
            answer.completion(),
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::Cancelled)
                    && reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(
                        semantic("reverse-candidate-coverage-gap")
                    ))
        ));
    }

    #[test]
    fn reverse_seed_cancellation_preserves_returned_gap_evidence() {
        let fixture = shared_fixture(false);
        let source =
            FaultingSource::new(&fixture.source, TestFault::CancelOnReverseSeedIssueWithGap);

        let answer = BatchResolutionEngine::new(&source)
            .references_to(fixture.target, &CancellationToken::new())
            .expect("reverse seed cancellation and gaps are typed incompleteness");

        assert!(answer.references().is_empty());
        assert!(matches!(
            answer.completion(),
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::Cancelled)
                    && reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(
                        semantic("cancelled-reverse-seed-gap")
                    ))
        ));
        assert_eq!(source.reverse_seed_batches.get(), 1);
    }

    #[test]
    fn reverse_cancellation_cannot_publish_a_complete_negative() {
        let fixture = shared_fixture(false);
        let source = FaultingSource::new(&fixture.source, TestFault::CancelOnHydration);
        let cancellation = CancellationToken::new();

        let answer = BatchResolutionEngine::new(&source)
            .references_to(fixture.target, &cancellation)
            .expect("reverse cancellation is typed incompleteness");

        assert!(answer.references().is_empty());
        assert!(answer.witnesses().is_empty());
        assert!(matches!(
            answer.completion(),
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::Cancelled)
        ));
        assert_eq!(source.reference_seeds.get(), 0);
        assert_eq!(source.reverse_seed_batches.get(), 0);
    }

    #[test]
    fn reverse_source_error_returns_no_forward_validated_answer() {
        let fixture = shared_fixture(false);
        let source = FaultingSource::new(&fixture.source, TestFault::FailOnSecondReverseMatch);

        let result = BatchResolutionEngine::new(&source)
            .references_to(fixture.target, &CancellationToken::new());

        assert!(result.is_err());
        assert_eq!(source.reverse_matches.get(), 2);
        assert_eq!(source.reference_seeds.get(), 0);
        assert_eq!(source.reverse_seed_batches.get(), 0);
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

        fn with_reverse_gaps(
            mut self,
            gaps: impl IntoIterator<Item = (ReverseCandidateGapIdentity, ResolutionIncompleteReason)>,
        ) -> Self {
            self.reverse_gaps = gaps.into_iter().collect();
            self
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

        fn with_forward_completion(mut self, completion: ResolutionCompletion) -> Self {
            self.forward_completion = completion;
            self
        }

        fn with_foreign_hydration(
            mut self,
            candidate: CandidatePathIdentity,
            path: PartialPath,
        ) -> Self {
            self.foreign_hydration = Some((candidate, path));
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
        fn selection_authority(&self) -> Option<SeedReadAuthority> {
            None
        }

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
            .resolve_reference_batch(&ReferenceSeedBatch::single(seed), &CancellationToken::new())
            .expect("manual coarse matches resolve");

        assert_eq!(answer.metrics().distinct_candidate_matches(), 2);
        assert_eq!(answer.metrics().distinct_path_hydrations(), 2);
        assert_eq!(answer.metrics().composition_attempts(), 2);
        assert_eq!(answer.metrics().successful_stitches(), 1);
        assert_eq!(answer.answer(reference).unwrap().targets(), &[target]);
    }

    fn ready_java_overlay<'a>(
        base: &'a dyn BatchResolutionFragmentSource,
        mut removed_paths: Vec<CandidatePathIdentity>,
        mut removed_gaps: Vec<ReverseCandidateGapIdentity>,
        mut added_paths: Vec<(CandidatePathIdentity, PartialPath)>,
        mut boundaries: Vec<BindingNodeId>,
        contextual_completion: ResolutionCompletion,
    ) -> SelectedContextOverlayFragmentSource<'a> {
        removed_paths.sort_unstable();
        removed_gaps.sort_unstable();
        added_paths.sort_unstable_by_key(|(candidate, _)| *candidate);
        boundaries.sort_unstable();
        match SelectedContextOverlayFragmentSource::from_parts(
            base,
            removed_paths.into_boxed_slice(),
            removed_gaps.into_boxed_slice(),
            added_paths.into_boxed_slice(),
            boundaries.into_boxed_slice(),
            Box::new([]),
            contextual_completion,
            &CancellationToken::new(),
        )
        .expect("test Java overlay is structurally valid")
        {
            SelectedContextOverlayFragmentSourceConstruction::Ready(source) => *source,
            SelectedContextOverlayFragmentSourceConstruction::Cancelled { .. } => {
                panic!("a live Java overlay construction cannot cancel")
            }
        }
    }

    fn visit_forward_overlay_pages(
        source: &dyn BatchResolutionFragmentSource,
        requests: &[BatchCandidateRequest],
    ) -> StoreResult<(
        Vec<BatchCandidateMatch>,
        BatchCandidateCompletionOutcome,
        Vec<usize>,
    )> {
        let mut matches = Vec::new();
        let mut pages = Vec::new();
        let completion = source.visit_forward_candidate_match_pages(
            requests,
            &CancellationToken::new(),
            &mut |page| {
                pages.push(page.len());
                matches.extend_from_slice(page);
                Ok(true)
            },
        )?;
        Ok((matches, completion, pages))
    }

    fn visit_reverse_overlay_pages(
        source: &dyn BatchResolutionFragmentSource,
        requests: &[BatchCandidateRequest],
    ) -> StoreResult<(Vec<BatchCandidateMatch>, BatchCandidateCompletionOutcome)> {
        let mut matches = Vec::new();
        let completion = source.visit_reverse_candidate_match_pages(
            requests,
            &CancellationToken::new(),
            &mut |page| {
                matches.extend_from_slice(page);
                Ok(true)
            },
        )?;
        Ok((matches, completion))
    }

    fn root_index_path(
        owner: BindingFragmentId,
        label: &str,
        start: EndpointSignature,
        end: EndpointSignature,
    ) -> (CandidatePathIdentity, PartialPath) {
        let id = path_id(label);
        (
            CandidatePathIdentity::new(owner, id),
            PartialPath::new(
                start,
                end,
                Vec::new(),
                Vec::new(),
                ResolutionCompletion::Complete,
            ),
        )
    }

    #[test]
    fn selected_context_root_index_pages_zero_one_and_batch_boundaries() {
        let owner = fragment("selected-context-root-index-owner");
        let key = semantic("selected-context-root-index-key");
        let end = node("selected-context-root-index-end");
        let base = PreloadedFragmentSource::default();

        for (count, expected_pages) in [
            (0_usize, Vec::new()),
            (1, vec![1]),
            (MAX_SOURCE_ROWS_PER_BATCH, vec![MAX_SOURCE_ROWS_PER_BATCH]),
            (
                MAX_SOURCE_ROWS_PER_BATCH + 1,
                vec![MAX_SOURCE_ROWS_PER_BATCH, 1],
            ),
        ] {
            let added = (0..count)
                .map(|ordinal| {
                    root_index_path(
                        owner,
                        &format!("selected-context-root-index-{count}-{ordinal}"),
                        symbol_endpoint(BindingNodeId::universal_root(), [key]),
                        endpoint(end),
                    )
                })
                .collect();
            let overlay = ready_java_overlay(
                &base,
                Vec::new(),
                Vec::new(),
                added,
                Vec::new(),
                ResolutionCompletion::Complete,
            );
            let request = [BatchCandidateRequest::new(
                0,
                symbol_endpoint(BindingNodeId::universal_root(), [key]),
            )];
            let (matches, completion, pages) = visit_forward_overlay_pages(&overlay, &request)
                .expect("selected-context root pages are valid");
            assert_eq!(matches.len(), count);
            assert_eq!(pages, expected_pages);
            assert_eq!(
                completion.unconditional_completion(),
                &ResolutionCompletion::Complete
            );
        }
    }

    #[test]
    fn selected_context_root_index_keeps_keys_and_wildcards_disjoint_in_both_directions() {
        let owner = fragment("selected-context-root-key-owner");
        let key = semantic("selected-context-root-key");
        let other = semantic("selected-context-root-other-key");
        let local = node("selected-context-root-key-local");
        let forward_keyed = root_index_path(
            owner,
            "selected-context-forward-keyed",
            symbol_endpoint(BindingNodeId::universal_root(), [key]),
            endpoint(local),
        );
        let forward_other = root_index_path(
            owner,
            "selected-context-forward-other",
            symbol_endpoint(BindingNodeId::universal_root(), [other]),
            endpoint(local),
        );
        let forward_wildcard = root_index_path(
            owner,
            "selected-context-forward-wildcard",
            open_symbol_endpoint(
                BindingNodeId::universal_root(),
                Vec::new(),
                "selected-context-forward-wildcard-tail",
            ),
            endpoint(local),
        );
        let reverse_keyed = root_index_path(
            owner,
            "selected-context-reverse-keyed",
            endpoint(local),
            symbol_endpoint(BindingNodeId::universal_root(), [key]),
        );
        let reverse_other = root_index_path(
            owner,
            "selected-context-reverse-other",
            endpoint(local),
            symbol_endpoint(BindingNodeId::universal_root(), [other]),
        );
        let reverse_wildcard = root_index_path(
            owner,
            "selected-context-reverse-wildcard",
            endpoint(local),
            open_symbol_endpoint(
                BindingNodeId::universal_root(),
                Vec::new(),
                "selected-context-reverse-wildcard-tail",
            ),
        );
        let expected_forward = BTreeSet::from([forward_keyed.0, forward_wildcard.0]);
        let expected_reverse = BTreeSet::from([reverse_keyed.0, reverse_wildcard.0]);
        let base = PreloadedFragmentSource::default();
        let overlay = ready_java_overlay(
            &base,
            Vec::new(),
            Vec::new(),
            vec![
                forward_keyed,
                forward_other,
                forward_wildcard,
                reverse_keyed,
                reverse_other,
                reverse_wildcard,
            ],
            Vec::new(),
            ResolutionCompletion::Complete,
        );
        let request = [BatchCandidateRequest::new(
            0,
            symbol_endpoint(BindingNodeId::universal_root(), [key]),
        )];

        let (forward, _, _) = visit_forward_overlay_pages(&overlay, &request)
            .expect("forward selected-context root key read");
        assert_eq!(
            forward
                .iter()
                .map(|matched| matched.candidate())
                .collect::<BTreeSet<_>>(),
            expected_forward
        );
        let (reverse, _) = visit_reverse_overlay_pages(&overlay, &request)
            .expect("reverse selected-context root key read");
        assert_eq!(
            reverse
                .iter()
                .map(|matched| matched.candidate())
                .collect::<BTreeSet<_>>(),
            expected_reverse
        );
    }

    #[test]
    fn selected_context_root_index_honors_stop_and_cancellation() {
        let owner = fragment("selected-context-root-stop-owner");
        let key = semantic("selected-context-root-stop-key");
        let end = node("selected-context-root-stop-end");
        let added = (0..=MAX_SOURCE_ROWS_PER_BATCH)
            .map(|ordinal| {
                root_index_path(
                    owner,
                    &format!("selected-context-root-stop-{ordinal}"),
                    symbol_endpoint(BindingNodeId::universal_root(), [key]),
                    endpoint(end),
                )
            })
            .collect();
        let base = PreloadedFragmentSource::default();
        let overlay = ready_java_overlay(
            &base,
            Vec::new(),
            Vec::new(),
            added,
            Vec::new(),
            ResolutionCompletion::Complete,
        );
        let request = [BatchCandidateRequest::new(
            0,
            symbol_endpoint(BindingNodeId::universal_root(), [key]),
        )];
        let mut pages = Vec::new();
        let completion = overlay
            .visit_forward_candidate_match_pages(&request, &CancellationToken::new(), &mut |page| {
                pages.push(page.len());
                Ok(false)
            })
            .expect("selected-context root visitor stop");
        assert_eq!(pages, vec![MAX_SOURCE_ROWS_PER_BATCH]);
        assert_eq!(
            completion.unconditional_completion(),
            &ResolutionCompletion::Complete
        );

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let mut cancelled_rows = Vec::new();
        let completion = overlay
            .visit_forward_candidate_match_pages(&request, &cancellation, &mut |page| {
                cancelled_rows.extend_from_slice(page);
                Ok(true)
            })
            .expect("selected-context root cancellation is semantic");
        assert!(cancelled_rows.is_empty());
        assert!(
            completion
                .unconditional_completion()
                .contains_reason(ResolutionIncompleteReason::Cancelled)
        );
    }

    #[test]
    fn java_overlay_blueprint_reuses_immutable_state_and_opens_fresh_exclusions() {
        let owner = fragment("java-overlay-blueprint-owner");
        let start = node("java-overlay-blueprint-start");
        let end = node("java-overlay-blueprint-end");
        let added = CandidatePathIdentity::new(owner, path_id("java-overlay-blueprint-added-path"));
        let gap =
            ReverseCandidateGapIdentity::new(owner, semantic("java-overlay-blueprint-reverse-gap"));
        let contextual_reason = ResolutionIncompleteReason::UnsupportedSemantic(semantic(
            "java-overlay-blueprint-contextual-gap",
        ));
        let construction = SelectedContextOverlayFragmentSourceBlueprint::from_parts(
            Box::new([]),
            Box::new([gap]),
            Box::new([(added, path(start, end, ResolutionCompletion::Complete))]),
            Box::new([end]),
            Box::new([end]),
            ResolutionCompletion::Incomplete(vec![contextual_reason].into()),
            &CancellationToken::new(),
        )
        .expect("test Java overlay blueprint is structurally valid");
        let SelectedContextOverlayFragmentSourceBlueprintConstruction::Ready(blueprint) =
            construction
        else {
            panic!("a live Java overlay blueprint construction cannot cancel")
        };
        let base = PreloadedFragmentSource::default();
        let mut first = blueprint.open(&base);
        let second = blueprint.open(&base);

        assert_eq!(blueprint.callable_static_import_boundaries(), &[end]);
        assert!(blueprint.is_callable_static_import_boundary(end));
        assert!(!blueprint.is_callable_static_import_boundary(start));

        assert!(std::ptr::eq(
            first
                .added_candidate_path(added)
                .expect("the first source borrows the added path"),
            second
                .added_candidate_path(added)
                .expect("the second source borrows the added path"),
        ));
        assert!(std::ptr::eq(
            first.contextual_reverse_inventory_completion(),
            second.contextual_reverse_inventory_completion(),
        ));

        let mut coverage = ReverseCandidateGapCoverageBuilder::default();
        coverage
            .push(ReverseCandidateGapRow::new(
                gap,
                ReverseCandidateGapLocation::Inventory,
                ResolutionIncompleteReason::UnsupportedSemantic(semantic(
                    "java-overlay-blueprint-raw-gap",
                )),
            ))
            .expect("the exact reverse gap is unique");
        let (coverage, cancellation_observed) = coverage
            .finish(&CancellationToken::new())
            .expect("the exact reverse coverage is valid");
        assert!(!cancellation_observed);
        assert!(
            coverage
                .prepare_exclusions(&mut first.reverse_gap_exclusions, &CancellationToken::new(),)
                .expect("the first operation prepares its exact exclusions")
        );
        assert!(first.reverse_gap_exclusions.prepared.is_some());
        assert!(second.reverse_gap_exclusions.prepared.is_none());
    }

    #[test]
    fn java_overlay_preserves_raw_identity_and_exact_path_gap_and_generated_parity() {
        let first_fragment = fragment("java-overlay-first-fragment");
        let second_fragment = fragment("java-overlay-second-fragment");
        let start = node("java-overlay-start");
        let end = node("java-overlay-end");
        let generated = node("java-overlay-generated-boundary");
        let shared_path_id = path_id("java-overlay-shared-path-id");
        let removed = CandidatePathIdentity::new(first_fragment, shared_path_id);
        let other_fragment_sibling = CandidatePathIdentity::new(
            second_fragment,
            path_id("java-overlay-other-fragment-path"),
        );
        let retained =
            CandidatePathIdentity::new(first_fragment, path_id("java-overlay-retained-path"));
        let added = CandidatePathIdentity::new(first_fragment, path_id("java-overlay-added-path"));
        let inner = PreloadedFragmentSource::from_fragments_with_boundaries(
            [start, end],
            [
                PreloadedFragment::new(
                    first_fragment,
                    [],
                    [
                        (
                            removed.path(),
                            path(start, end, ResolutionCompletion::Complete),
                        ),
                        (
                            retained.path(),
                            path(start, end, ResolutionCompletion::Complete),
                        ),
                    ],
                ),
                PreloadedFragment::new(
                    second_fragment,
                    [],
                    [(
                        other_fragment_sibling.path(),
                        path(start, end, ResolutionCompletion::Complete),
                    )],
                ),
            ],
        );
        let shared_reason = semantic("java-overlay-shared-gap-reason");
        let first_gap =
            ReverseCandidateGapIdentity::new(first_fragment, semantic("java-overlay-first-gap"));
        let second_gap =
            ReverseCandidateGapIdentity::new(first_fragment, semantic("java-overlay-second-gap"));
        let base = JavaOverlayLawSource::new(inner).with_reverse_gaps([
            (
                first_gap,
                ResolutionIncompleteReason::UnsupportedSemantic(shared_reason),
            ),
            (
                second_gap,
                ResolutionIncompleteReason::UnsupportedSemantic(shared_reason),
            ),
        ]);
        let raw_request = [BatchCandidateRequest::new(0, endpoint(end))];
        let raw_before =
            visit_reverse_overlay_pages(&base, &raw_request).expect("raw reverse source is valid");
        let contextual_reason = semantic("java-overlay-contextual-reason");
        let mut overlay = ready_java_overlay(
            &base,
            vec![removed],
            vec![first_gap],
            vec![(
                added,
                path(start, generated, ResolutionCompletion::Complete),
            )],
            vec![generated],
            ResolutionCompletion::Incomplete(
                vec![ResolutionIncompleteReason::UnsupportedSemantic(
                    contextual_reason,
                )]
                .into_boxed_slice()
                .into(),
            ),
        );

        let forward = overlay
            .match_forward_candidates(
                &[BatchCandidateRequest::new(0, endpoint(start))],
                &CancellationToken::new(),
            )
            .expect("overlay forward candidates are valid");
        let forward_candidates: BTreeSet<_> = forward
            .matches()
            .iter()
            .map(|matched| matched.candidate())
            .collect();
        assert_eq!(
            forward_candidates,
            BTreeSet::from([other_fragment_sibling, retained, added])
        );

        let reverse_requests = [
            BatchCandidateRequest::new(0, endpoint(end)),
            BatchCandidateRequest::new(1, endpoint(generated)),
        ];
        let mut reverse_matches = Vec::new();
        let reverse_completion = overlay
            .visit_reverse_candidate_match_pages_with_gap_exclusions(
                &reverse_requests,
                &mut ReverseCandidateGapExclusionPlan::default(),
                &CancellationToken::new(),
                &mut |page| {
                    reverse_matches.extend_from_slice(page);
                    Ok(true)
                },
            )
            .expect("overlay reverse candidates are valid");
        assert_eq!(
            reverse_matches
                .iter()
                .map(|matched| (matched.request_ordinal(), matched.candidate()))
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([(0, other_fragment_sibling), (0, retained), (1, added)])
        );
        assert!(
            reverse_completion
                .unconditional_completion()
                .contains_reason(ResolutionIncompleteReason::UnsupportedSemantic(
                    shared_reason
                )),
            "excluding one exact gap must retain its same-reason sibling"
        );
        assert!(
            !reverse_completion
                .unconditional_completion()
                .contains_reason(ResolutionIncompleteReason::UnsupportedSemantic(
                    contextual_reason
                ))
        );
        assert_eq!(
            overlay.contextual_reverse_inventory_completion(),
            &ResolutionCompletion::Incomplete(
                vec![ResolutionIncompleteReason::UnsupportedSemantic(
                    contextual_reason
                )]
                .into_boxed_slice()
                .into()
            )
        );

        let hydrated = overlay
            .hydrate_candidate_paths(&[other_fragment_sibling, added], &CancellationToken::new())
            .expect("overlay hydrates base and added identities exactly");
        assert_eq!(
            hydrated
                .iter()
                .map(|(candidate, _)| *candidate)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([other_fragment_sibling, added])
        );
        assert_eq!(
            hydrated
                .iter()
                .find(|(candidate, _)| *candidate == added)
                .expect("added path is hydrated locally")
                .1
                .end()
                .node(),
            generated
        );
        assert!(
            overlay
                .hydrate_candidate_paths(&[removed], &CancellationToken::new())
                .expect_err("a removed exact identity cannot be hydrated")
                .to_string()
                .contains("selected-context-removed")
        );
        let classified = overlay
            .classify_endpoint_nodes(&[end, generated], &CancellationToken::new())
            .expect("generated root classification composes with raw classification");
        assert_eq!(classified.len(), 2);
        assert_eq!(
            classified[1],
            BatchEndpointClassification::new(generated, None, None)
        );

        let raw_after = visit_reverse_overlay_pages(&base, &raw_request)
            .expect("overlay calls do not mutate the raw source");
        assert_eq!(raw_after, raw_before);
        assert_eq!(base.filtered_reverse_visits.get(), 1);
        assert_eq!(base.raw_reverse_visits.get(), 2);
    }

    #[test]
    fn java_overlay_delegates_nonplacement_source_contracts_exactly() {
        let fixture = shared_fixture(false);
        let overlay = ready_java_overlay(
            &fixture.source,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            ResolutionCompletion::Complete,
        );
        let query = ResolutionQuery::new(fixture.first_reference);
        assert_eq!(
            overlay
                .reference_seed(query, &CancellationToken::new())
                .expect("overlay seed delegation is valid"),
            fixture
                .source
                .reference_seed(query, &CancellationToken::new())
                .expect("raw seed lookup is valid")
        );
        assert_eq!(
            overlay
                .lookup_definition_node(fixture.target, &CancellationToken::new())
                .expect("overlay definition delegation is valid"),
            fixture
                .source
                .lookup_definition_node(fixture.target, &CancellationToken::new())
                .expect("raw definition lookup is valid")
        );
        assert_eq!(
            overlay
                .lookup_definition_nodes(&[fixture.target], &CancellationToken::new())
                .expect("overlay batched definition delegation is valid"),
            fixture
                .source
                .lookup_definition_nodes(&[fixture.target], &CancellationToken::new())
                .expect("raw batched definition lookup is valid")
        );
        let seed_request = [ReverseReferenceSeedRequest::new(
            fixture.first_reference,
            fixture.first_node,
        )];
        assert_eq!(
            overlay
                .issue_reverse_reference_seeds(&seed_request, &CancellationToken::new())
                .expect("overlay reverse seed delegation is valid"),
            fixture
                .source
                .issue_reverse_reference_seeds(&seed_request, &CancellationToken::new())
                .expect("raw reverse seed issuance is valid")
        );

        let mut raw_seeds = Vec::new();
        let raw_enumeration = fixture
            .source
            .visit_reference_seed_batches(
                MAX_REFERENCE_SEEDS_PER_BATCH,
                &CancellationToken::new(),
                &mut |batch| {
                    raw_seeds.extend_from_slice(batch.seeds());
                    Ok(true)
                },
            )
            .expect("raw seed enumeration is valid");
        let mut overlay_seeds = Vec::new();
        let overlay_enumeration = overlay
            .visit_reference_seed_batches(
                MAX_REFERENCE_SEEDS_PER_BATCH,
                &CancellationToken::new(),
                &mut |batch| {
                    overlay_seeds.extend_from_slice(batch.seeds());
                    Ok(true)
                },
            )
            .expect("overlay seed enumeration delegation is valid");
        assert_eq!(overlay_seeds, raw_seeds);
        assert_eq!(overlay_enumeration, raw_enumeration);
        assert_eq!(
            overlay
                .classify_endpoint_nodes(&[fixture.target_node], &CancellationToken::new())
                .expect("overlay raw-node classification delegation is valid"),
            fixture
                .source
                .classify_endpoint_nodes(&[fixture.target_node], &CancellationToken::new())
                .expect("raw node classification is valid")
        );

        let slot = semantic("java-overlay-delegated-type-slot");
        let mut raw_rules = Vec::new();
        let raw_type_completion = fixture
            .source
            .visit_type_transfer_rules(slot, &CancellationToken::new(), &mut |rule| {
                raw_rules.push(rule.clone());
                Ok(true)
            })
            .expect("raw type transfer visit is valid");
        let mut overlay_rules = Vec::new();
        let overlay_type_completion = overlay
            .visit_type_transfer_rules(slot, &CancellationToken::new(), &mut |rule| {
                overlay_rules.push(rule.clone());
                Ok(true)
            })
            .expect("overlay type transfer delegation is valid");
        assert_eq!(overlay_rules, raw_rules);
        assert_eq!(overlay_type_completion, raw_type_completion);
    }

    #[test]
    fn java_overlay_preserves_bounded_storage_pages_and_canonicalizes_after_exhaustion() {
        let owner = fragment("java-overlay-page-owner");
        let start = node("java-overlay-page-start");
        let end = node("java-overlay-page-end");
        let base_paths: Vec<_> = (0..300)
            .map(|ordinal| {
                (
                    path_id(&format!("java-overlay-base-page-{ordinal}")),
                    path(start, end, ResolutionCompletion::Complete),
                )
            })
            .collect();
        let mut expected = base_paths
            .iter()
            .map(|(path, _)| CandidatePathIdentity::new(owner, *path))
            .collect::<BTreeSet<_>>();
        let inner = PreloadedFragmentSource::from_fragments([PreloadedFragment::new(
            owner,
            [
                (start, BindingNodeKind::Scope),
                (end, BindingNodeKind::Scope),
            ],
            base_paths,
        )]);
        let base = JavaOverlayLawSource::new(inner);
        let added: Vec<_> = (0..300)
            .map(|ordinal| {
                (
                    CandidatePathIdentity::new(
                        owner,
                        path_id(&format!("java-overlay-added-page-{ordinal}")),
                    ),
                    path(start, end, ResolutionCompletion::Complete),
                )
            })
            .collect();
        expected.extend(added.iter().map(|(candidate, _)| *candidate));
        let overlay = ready_java_overlay(
            &base,
            Vec::new(),
            Vec::new(),
            added,
            Vec::new(),
            ResolutionCompletion::Complete,
        );
        let (matches, completion, pages) = visit_forward_overlay_pages(
            &overlay,
            &[BatchCandidateRequest::new(0, endpoint(start))],
        )
        .expect("bounded overlay storage stream is valid");

        assert_eq!(matches.len(), 600);
        assert!(pages.iter().all(|&page| (1..=256).contains(&page)));
        assert_eq!(
            matches
                .iter()
                .map(|matched| matched.candidate())
                .collect::<BTreeSet<_>>(),
            expected
        );
        assert_eq!(
            completion.unconditional_completion(),
            &ResolutionCompletion::Complete
        );

        let materialized = overlay
            .match_forward_candidates(
                &[BatchCandidateRequest::new(0, endpoint(start))],
                &CancellationToken::new(),
            )
            .expect("an exhausted overlay stream materializes canonically");
        assert_eq!(materialized.matches().len(), 600);
        assert!(materialized.matches().windows(2).all(|pair| {
            (pair[0].request_ordinal(), pair[0].candidate())
                < (pair[1].request_ordinal(), pair[1].candidate())
        }));
    }

    #[test]
    fn java_overlay_accepts_reversed_base_storage_order_with_an_interleaved_added_identity() {
        let owner = fragment("java-overlay-interleaved-owner");
        let start = node("java-overlay-interleaved-start");
        let end = node("java-overlay-interleaved-end");
        let mut identities = [
            CandidatePathIdentity::new(owner, path_id("java-overlay-interleaved-a")),
            CandidatePathIdentity::new(owner, path_id("java-overlay-interleaved-b")),
            CandidatePathIdentity::new(owner, path_id("java-overlay-interleaved-c")),
        ];
        identities.sort_unstable();
        let [low, added, high] = identities;
        let base = JavaOverlayLawSource::new(PreloadedFragmentSource::default())
            .with_manual_forward_matches(
                [
                    BatchCandidateMatch::new(high, 0),
                    BatchCandidateMatch::new(low, 0),
                ],
                false,
            );
        let overlay = ready_java_overlay(
            &base,
            Vec::new(),
            Vec::new(),
            vec![(added, path(start, end, ResolutionCompletion::Complete))],
            vec![end],
            ResolutionCompletion::Complete,
        );
        let request = [BatchCandidateRequest::new(0, endpoint(start))];

        let (storage_rows, _, _) = visit_forward_overlay_pages(&overlay, &request)
            .expect("reversed base storage order is a valid overlay input");
        assert_eq!(
            storage_rows
                .iter()
                .map(|matched| matched.candidate())
                .collect::<Vec<_>>(),
            vec![high, low, added]
        );

        let materialized = overlay
            .match_forward_candidates(&request, &CancellationToken::new())
            .expect("the exhausted overlay canonicalizes base and added rows together");
        assert_eq!(
            materialized
                .matches()
                .iter()
                .map(|matched| matched.candidate())
                .collect::<Vec<_>>(),
            vec![low, added, high]
        );
    }

    #[test]
    fn java_overlay_rejects_base_emission_after_downstream_stop() {
        let owner = fragment("java-overlay-stop-owner");
        let start = node("java-overlay-stop-start");
        let end = node("java-overlay-stop-end");
        let matches = (0..512).map(|ordinal| {
            BatchCandidateMatch::new(
                CandidatePathIdentity::new(
                    owner,
                    path_id(&format!("java-overlay-stop-path-{ordinal}")),
                ),
                0,
            )
        });
        let base = JavaOverlayLawSource::new(PreloadedFragmentSource::default())
            .with_manual_forward_matches(matches, true);
        let overlay = ready_java_overlay(
            &base,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            ResolutionCompletion::Complete,
        );
        let mut callback_count = 0_usize;
        let error = overlay
            .visit_forward_candidate_match_pages(
                &[BatchCandidateRequest::new(0, endpoint(start))],
                &CancellationToken::new(),
                &mut |_| {
                    callback_count += 1;
                    Ok(false)
                },
            )
            .expect_err("a base that ignores stop must fail closed");
        assert_eq!(callback_count, 1);
        assert!(
            error
                .to_string()
                .contains("after the overlay visitor stopped")
        );
        let _ = end;
    }

    #[test]
    fn java_overlay_materialized_forward_and_reverse_cancellation_is_atomic() {
        let owner = fragment("java-overlay-materialized-owner");
        let start = node("java-overlay-materialized-start");
        let end = node("java-overlay-materialized-end");
        let added: Vec<_> = (0..64)
            .map(|ordinal| {
                (
                    CandidatePathIdentity::new(
                        owner,
                        path_id(&format!("java-overlay-materialized-{ordinal}")),
                    ),
                    path(start, end, ResolutionCompletion::Complete),
                )
            })
            .collect();
        let forward_reason = ResolutionIncompleteReason::UnsupportedSemantic(semantic(
            "java-overlay-materialized-forward-evidence",
        ));
        let reverse_reason = ResolutionIncompleteReason::UnsupportedSemantic(semantic(
            "java-overlay-materialized-reverse-evidence",
        ));
        let base = JavaOverlayLawSource::new(PreloadedFragmentSource::default())
            .with_forward_completion(ResolutionCompletion::Incomplete(
                vec![forward_reason].into_boxed_slice().into(),
            ))
            .with_reverse_gaps([(
                ReverseCandidateGapIdentity::new(
                    owner,
                    semantic("java-overlay-materialized-reverse-gap"),
                ),
                reverse_reason,
            )]);
        let overlay = ready_java_overlay(
            &base,
            Vec::new(),
            Vec::new(),
            added,
            Vec::new(),
            ResolutionCompletion::Complete,
        );
        let forward_request = [BatchCandidateRequest::new(0, endpoint(start))];
        let reverse_request = [BatchCandidateRequest::new(0, endpoint(end))];

        for (label, reverse) in [("forward", false), ("reverse", true)] {
            let mut saw_complete = false;
            let mut saw_cancelled = false;
            for checks in 1..512 {
                let cancellation = CancellationToken::cancel_after_checks_for_test(checks);
                let outcome = if reverse {
                    overlay.match_reverse_candidates(&reverse_request, &cancellation)
                } else {
                    overlay.match_forward_candidates(&forward_request, &cancellation)
                }
                .expect("materialized overlay cancellation is semantic");
                let cancelled = outcome
                    .unconditional_completion()
                    .contains_reason(ResolutionIncompleteReason::Cancelled);
                if cancelled {
                    saw_cancelled = true;
                    assert!(
                        outcome.matches().is_empty(),
                        "{label} cancellation must not publish a materialized prefix at threshold {checks}"
                    );
                    assert!(
                        outcome
                            .unconditional_completion()
                            .contains_reason(if reverse {
                                reverse_reason
                            } else {
                                forward_reason
                            }),
                        "{label} cancellation must retain source evidence at threshold {checks}"
                    );
                } else {
                    saw_complete = true;
                    assert_eq!(
                        outcome.matches().len(),
                        64,
                        "{label} live materialization must remain exact at threshold {checks}"
                    );
                }
            }
            assert!(saw_complete && saw_cancelled);
        }
    }

    #[test]
    fn java_overlay_polls_large_completion_after_downstream_stop() {
        let owner = fragment("java-overlay-stop-completion-owner");
        let start = node("java-overlay-stop-completion-start");
        let matches = (0..256).map(|ordinal| {
            BatchCandidateMatch::new(
                CandidatePathIdentity::new(
                    owner,
                    path_id(&format!("java-overlay-stop-completion-path-{ordinal}")),
                ),
                0,
            )
        });
        let reasons = (0..1_024)
            .map(|ordinal| {
                ResolutionIncompleteReason::UnsupportedSemantic(semantic(&format!(
                    "java-overlay-stop-completion-reason-{ordinal}"
                )))
            })
            .collect::<BTreeSet<_>>();
        let base = JavaOverlayLawSource::new(PreloadedFragmentSource::default())
            .with_manual_forward_matches(matches, false)
            .with_forward_completion(ResolutionCompletion::Incomplete(
                reasons.into_iter().collect::<Vec<_>>().into(),
            ));
        let overlay = ready_java_overlay(
            &base,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            ResolutionCompletion::Complete,
        );
        let request = [BatchCandidateRequest::new(0, endpoint(start))];
        let mut found_scan_threshold = false;
        for checks in 250..700 {
            let cancellation = CancellationToken::cancel_after_checks_for_test(checks);
            let mut callbacks = 0_usize;
            let completion = overlay
                .visit_forward_candidate_match_pages(&request, &cancellation, &mut |_| {
                    callbacks += 1;
                    Ok(false)
                })
                .expect("stopped overlay completion scan is semantic");
            if callbacks == 1
                && completion
                    .unconditional_completion()
                    .contains_reason(ResolutionIncompleteReason::Cancelled)
            {
                found_scan_threshold = true;
                break;
            }
        }
        assert!(
            found_scan_threshold,
            "a threshold must cancel during the polled large completion scan after stop"
        );
    }

    #[test]
    fn java_overlay_construction_cancellation_retains_separate_context_and_retries() {
        let base = JavaOverlayLawSource::new(PreloadedFragmentSource::default());
        let contextual_reason = ResolutionIncompleteReason::UnsupportedSemantic(semantic(
            "java-overlay-construction-context",
        ));
        let contextual =
            ResolutionCompletion::Incomplete(vec![contextual_reason].into_boxed_slice().into());
        let immediate_cancellation = CancellationToken::new();
        immediate_cancellation.cancel();
        let immediately_cancelled = SelectedContextOverlayFragmentSource::from_parts(
            &base,
            Box::new([]),
            Box::new([]),
            Box::new([]),
            Box::new([]),
            Box::new([]),
            contextual.clone(),
            &immediate_cancellation,
        )
        .expect("immediate construction cancellation is semantic");
        match immediately_cancelled {
            SelectedContextOverlayFragmentSourceConstruction::Cancelled {
                contextual_reverse_inventory_completion,
                cancellation_completion,
            } => {
                assert_eq!(contextual_reverse_inventory_completion, contextual);
                assert_eq!(cancellation_completion, cancelled_completion());
                assert!(!cancellation_completion.contains_reason(contextual_reason));
            }
            SelectedContextOverlayFragmentSourceConstruction::Ready(_) => {
                panic!("an already-cancelled construction cannot publish a source")
            }
        }

        let cancelled = SelectedContextOverlayFragmentSource::from_parts(
            &base,
            Box::new([]),
            Box::new([]),
            Box::new([]),
            Box::new([]),
            Box::new([]),
            contextual.clone(),
            &CancellationToken::cancel_after_checks_for_test(5),
        )
        .expect("construction cancellation is semantic");
        match cancelled {
            SelectedContextOverlayFragmentSourceConstruction::Cancelled {
                contextual_reverse_inventory_completion,
                cancellation_completion,
            } => {
                assert_eq!(contextual_reverse_inventory_completion, contextual);
                assert_eq!(cancellation_completion, cancelled_completion());
                assert!(!cancellation_completion.contains_reason(contextual_reason));
            }
            SelectedContextOverlayFragmentSourceConstruction::Ready(_) => {
                panic!("the final pre-publication token gate must cancel")
            }
        }

        let retry = SelectedContextOverlayFragmentSource::from_parts(
            &base,
            Box::new([]),
            Box::new([]),
            Box::new([]),
            Box::new([]),
            Box::new([]),
            contextual.clone(),
            &CancellationToken::new(),
        )
        .expect("a fresh token retries construction");
        match retry {
            SelectedContextOverlayFragmentSourceConstruction::Ready(source) => {
                assert_eq!(
                    source.contextual_reverse_inventory_completion(),
                    &contextual
                );
            }
            SelectedContextOverlayFragmentSourceConstruction::Cancelled { .. } => {
                panic!("a fresh construction cannot inherit cancellation")
            }
        }

        let after_final_gate = SelectedContextOverlayFragmentSource::from_parts(
            &base,
            Box::new([]),
            Box::new([]),
            Box::new([]),
            Box::new([]),
            Box::new([]),
            contextual,
            &CancellationToken::cancel_after_checks_for_test(6),
        )
        .expect("Ready publication after the final gate is O(1)");
        assert!(matches!(
            after_final_gate,
            SelectedContextOverlayFragmentSourceConstruction::Ready(_)
        ));
    }

    #[test]
    fn java_overlay_conflicts_and_foreign_identities_fail_closed() {
        let owner = fragment("java-overlay-conflict-owner");
        let start = node("java-overlay-conflict-start");
        let end = node("java-overlay-conflict-end");
        let identity = CandidatePathIdentity::new(owner, path_id("java-overlay-conflict-path"));
        let inner = PreloadedFragmentSource::from_fragments([PreloadedFragment::new(
            owner,
            [
                (start, BindingNodeKind::Scope),
                (end, BindingNodeKind::Scope),
            ],
            [(
                identity.path(),
                path(start, end, ResolutionCompletion::Complete),
            )],
        )]);
        let base = JavaOverlayLawSource::new(inner);
        let overlay = ready_java_overlay(
            &base,
            Vec::new(),
            Vec::new(),
            vec![(identity, path(start, end, ResolutionCompletion::Complete))],
            Vec::new(),
            ResolutionCompletion::Complete,
        );
        assert!(
            overlay
                .visit_forward_candidate_match_pages(
                    &[BatchCandidateRequest::new(0, endpoint(start))],
                    &CancellationToken::new(),
                    &mut |_| Ok(true),
                )
                .expect_err("base/add identity conflicts fail closed")
                .to_string()
                .contains("conflicts with selected-context")
        );

        let foreign = CandidatePathIdentity::new(
            fragment("java-overlay-foreign-owner"),
            path_id("java-overlay-foreign-path"),
        );
        let base = JavaOverlayLawSource::new(PreloadedFragmentSource::from_fragments([
            PreloadedFragment::new(
                owner,
                [
                    (start, BindingNodeKind::Scope),
                    (end, BindingNodeKind::Scope),
                ],
                [(
                    identity.path(),
                    path(start, end, ResolutionCompletion::Complete),
                )],
            ),
        ]))
        .with_foreign_hydration(foreign, path(start, end, ResolutionCompletion::Complete));
        let overlay = ready_java_overlay(
            &base,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            ResolutionCompletion::Complete,
        );
        assert!(
            overlay
                .hydrate_candidate_paths(&[identity], &CancellationToken::new())
                .expect_err("foreign base hydration fails closed")
                .to_string()
                .contains("foreign identity")
        );

        let malformed = SelectedContextOverlayFragmentSource::from_parts(
            &base,
            Box::new([identity, identity]),
            Box::new([]),
            Box::new([]),
            Box::new([]),
            Box::new([]),
            ResolutionCompletion::Complete,
            &CancellationToken::new(),
        );
        let Err(malformed) = malformed else {
            panic!("duplicate exact removals must fail closed")
        };
        assert!(
            malformed
                .to_string()
                .contains("duplicate removed candidate path")
        );
    }
}
