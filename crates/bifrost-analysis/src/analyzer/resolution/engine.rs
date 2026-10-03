//! Operation-local stitching over a normalized fragment source.

use std::collections::{BTreeSet, VecDeque};

use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

use super::model::GoDefinitionNamespaces;
use crate::CancellationToken;
use crate::analyzer::store::{Result as StoreResult, StoreError};
use crate::analyzer::structural::{CandidateOutcome, RejectionReason};
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;

use super::batch::{
    BatchCandidateCompletionOutcome, BatchCandidateMatch, BatchCandidateRequest,
    BatchCompletionLedger, BatchReferenceSeed, BatchResolutionFragmentSource,
    CancellationEvidenceLedger, CandidatePathIdentity, FactReferenceSiteMetadata,
    MAX_SOURCE_ROWS_PER_BATCH, ReferenceSeed, ReferenceSeedBatch, ReferenceSeedReadOutcome,
    ReverseCandidateGapCoverage, ReverseCandidateGapCoverageBuilder,
    ReverseCandidateGapExclusionPlan, ReverseCandidateGapIdentity, ReverseCandidateGapLocation,
    ReverseCandidateGapRow, ReverseReferenceSeedRequest,
};
use super::fact_lowering::{
    LoweredCandidateDirection, LoweredCoverageGap, LoweredResolutionFragment,
    LoweringCoverageFrontier,
};
use super::model::{
    BindingCandidateAdmission, BindingFragmentId, BindingNodeId, BindingNodeKind,
    EndpointSignature, LookupAlternative, PartialPath, PartialPathId, PartialScopedSymbol,
    PrecedenceStep, ResolutionAnswer, ResolutionCompletion, ResolutionIncompleteReason,
    ResolutionSlotValue, ResolutionWitness, SemanticId, StackPattern, TypeTransferApplication,
    TypeTransferRule, TypedFrontierState, WitnessStep, clone_completion_with_poll,
};
use super::saturation::{CycleCompletenessCertifier, SaturationBranch, SaturationDecision};

/// Does this candidate endpoint answer this request's endpoint pattern?
///
/// A partial path is a candidate for a request when its endpoint stack can
/// unify with the request's pattern: the two fixed symbol counts agree, or the
/// shorter of the two is open; and when both carry a fixed symbol, the leading
/// symbols are the same identity. The persisted candidate reader applied
/// exactly this predicate in SQL (endpoint key, the three-way fixed-count rule,
/// and the first-symbol identity), so the preloaded source has to apply it too.
/// Matching on the endpoint node alone admits every outgoing path of that node,
/// which makes the two sources disagree about a request's candidate set and
/// lets a route the request can never take carry its gaps into the answer.
///
/// Scope stacks take no part in this: the persisted predicate does not carry
/// them, and a candidate request whose endpoint has one is rejected before it
/// reaches a source.
/// Whether a stored path endpoint can still unify with a requested one.
///
/// This is the index predicate in front of the full unification its callers
/// run after hydration, so it must reject only what cannot unify, and it
/// should reject everything the stored cells already decide.
/// `unify_symbol_stacks_with_poll` compares the two symbol stacks cell by cell
/// across their shared fixed prefix and rejects a cell whose symbol differs or
/// whose scope stack is present on one side only; alpha renaming rewrites
/// stack variables and leaves both of those alone. The whole shared prefix is
/// therefore decidable here, not only its first cell.
///
/// Only the first cell used to be compared. Every root-terminated path of a
/// Rust blob starts its end stack with that blob's own root import anchor
/// symbol, so one universal-root demand admitted all of them: on the tract
/// reverse frontier, 273 root halves of one caller file were hydrated and
/// alpha-renamed on each root-half source-admission probe to find the single
/// one that unified, and that was 87 percent of a reverse confirmation's
/// scope-step budget.
pub(super) fn endpoint_admits_candidate(
    request: &EndpointSignature,
    candidate: &EndpointSignature,
) -> bool {
    let requested = request.symbols();
    let offered = candidate.symbols();
    let counts_unify = match offered.fixed().len().cmp(&requested.fixed().len()) {
        std::cmp::Ordering::Equal => true,
        std::cmp::Ordering::Greater => requested.tail().is_some(),
        std::cmp::Ordering::Less => offered.tail().is_some(),
    };
    counts_unify
        && requested
            .fixed()
            .iter()
            .zip(offered.fixed())
            .all(|(requested, offered)| {
                requested.symbol() == offered.symbol()
                    && requested.scopes().is_some() == offered.scopes().is_some()
            })
}

/// Candidate compositions between cooperative cancellation checks.
///
/// This is a deterministic work quantum, not a duration or deadline. A
/// frontend may cancel the supplied token; this engine does not create or
/// inspect a wall-clock deadline.
pub(super) const CANCELLATION_QUANTUM: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolutionQuery {
    reference: SemanticId,
}

impl ResolutionQuery {
    pub const fn new(reference: SemanticId) -> Self {
        Self { reference }
    }

    pub const fn reference(self) -> SemanticId {
        self.reference
    }
}

/// Exact references after reverse generation and per-reference forward
/// shadow validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceSearchAnswer {
    references: Box<[SemanticId]>,
    witnesses: Box<[ResolutionWitness]>,
    completion: ResolutionCompletion,
}

impl ReferenceSearchAnswer {
    pub(crate) fn new(
        references: impl Into<Box<[SemanticId]>>,
        witnesses: impl Into<Box<[ResolutionWitness]>>,
        completion: ResolutionCompletion,
    ) -> Self {
        Self {
            references: references.into(),
            witnesses: witnesses.into(),
            completion,
        }
    }

    pub fn references(&self) -> &[SemanticId] {
        &self.references
    }

    pub fn witnesses(&self) -> &[ResolutionWitness] {
        &self.witnesses
    }

    pub fn completion(&self) -> &ResolutionCompletion {
        &self.completion
    }
}

/// Read side of immutable resolution facts.
///
/// Candidate visitation returns a sound endpoint-indexed superset. Exact stack
/// unification remains in [`PartialPath::concatenate`], so preload and eventual
/// SQL sources share the same final semantic check. A node ID and a
/// partial-path ID are unique within one selection: each is its mount's
/// ordinal and the position the identity occupies in that blob's catalog.
pub trait ResolutionFragmentSource {
    fn go_spelling_namespace(
        &self,
        reference: SemanticId,
    ) -> StoreResult<Option<ResolutionNamespace>>;

    fn go_package_qualifier(&self, reference: SemanticId) -> StoreResult<bool>;

    fn go_definition_namespaces(
        &self,
        definition: SemanticId,
    ) -> StoreResult<Option<GoDefinitionNamespaces>>;

    fn reference_node(&self, reference: SemanticId) -> StoreResult<Option<BindingNodeId>>;

    fn reference_semantic(&self, node: BindingNodeId) -> StoreResult<Option<SemanticId>>;

    fn definition_node(&self, definition: SemanticId) -> StoreResult<Option<BindingNodeId>>;

    fn definition_semantic(&self, node: BindingNodeId) -> StoreResult<Option<SemanticId>>;

    fn visit_references(
        &self,
        visitor: &mut dyn FnMut(SemanticId, BindingNodeId) -> StoreResult<bool>,
    ) -> StoreResult<()>;

    fn visit_forward_candidates(
        &self,
        endpoint: &EndpointSignature,
        visitor: &mut dyn FnMut(PartialPathId, &PartialPath) -> StoreResult<bool>,
    ) -> StoreResult<()>;

    fn visit_reverse_candidates(
        &self,
        endpoint: &EndpointSignature,
        visitor: &mut dyn FnMut(PartialPathId, &PartialPath) -> StoreResult<bool>,
    ) -> StoreResult<()>;

    /// Visit immutable copy rules originating at `source_slot`.
    /// Binding-only sources may return no rows; unsupported transfer semantics
    /// must instead be represented by incomplete rule or coverage evidence.
    fn visit_type_transfer_rules(
        &self,
        source_slot: SemanticId,
        visitor: &mut dyn FnMut(&TypeTransferRule) -> StoreResult<bool>,
    ) -> StoreResult<ResolutionCompletion>;
}

#[derive(Debug)]
pub(super) struct StoredPartialPath {
    pub(super) identity: CandidatePathIdentity,
    path: PartialPath,
}

/// The first fixed cell of an endpoint stack, as the candidate index keys it.
///
/// `endpoint_admits_candidate` decides a cell of the shared fixed prefix on
/// exactly these two properties, and alpha renaming preserves both, so they
/// are the finest key the index can carry without excluding anything
/// unification would have accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct CandidateLeadCell {
    symbol: SemanticId,
    scoped: bool,
}

impl CandidateLeadCell {
    /// `None` when the endpoint fixes no symbol at all. Its fixed prefix is
    /// empty, so it shares no decidable cell with any request.
    fn of(endpoint: &EndpointSignature) -> Option<Self> {
        endpoint.symbols().fixed().first().map(|cell| Self {
            symbol: cell.symbol(),
            scoped: cell.scopes().is_some(),
        })
    }
}

/// The stored paths whose indexed endpoint is one node, split by lead cell.
///
/// Keying by the node alone made every request walk every path that node
/// offers. Every root-terminated path of a Rust blob leaves the same root
/// import anchor node, so a universal-root request walked two paths per
/// selected mount and `endpoint_admits_candidate` rejected all but a handful
/// on their first cell alone. Keying by what admission checks moves that
/// rejection into the lookup.
#[derive(Debug, Default)]
struct CandidateNodeIndex {
    /// Paths whose indexed endpoint fixes a first cell, by that cell.
    by_lead: HashMap<CandidateLeadCell, Vec<usize>>,
    /// Paths whose indexed endpoint fixes no symbol. Their fixed prefix is
    /// empty, so they can still unify with a request that fixes one, and every
    /// request has to visit them.
    open: Vec<usize>,
}

impl CandidateNodeIndex {
    fn push(&mut self, lead: Option<CandidateLeadCell>, path_index: usize) {
        match lead {
            Some(lead) => self.by_lead.entry(lead).or_default().push(path_index),
            None => self.open.push(path_index),
        }
    }

    /// Put every bucket in strictly increasing candidate-identity order.
    ///
    /// Each path sits in exactly one bucket and identities are unique, so a
    /// merge of any subset of the buckets is strictly increasing too. That is
    /// what keeps a request's emitted candidate order identical to what the
    /// single node-wide vector produced.
    fn sort_by_identity(&mut self, paths: &[StoredPartialPath]) {
        for indices in self.by_lead.values_mut() {
            indices.sort_unstable_by_key(|index| paths[*index].identity);
        }
        self.open
            .sort_unstable_by_key(|index| paths[*index].identity);
    }

    /// The buckets a request with this endpoint has to walk, appended to
    /// `buckets` so one allocation serves a whole page.
    ///
    /// A request that fixes a first cell can be admitted only by a stored
    /// endpoint that fixes the same cell or fixes nothing. A request that
    /// fixes nothing shares an empty prefix with every stored endpoint, so it
    /// walks them all; that is the one case where enumeration is the answer.
    fn extend_buckets_for<'index>(
        &'index self,
        request: &EndpointSignature,
        buckets: &mut Vec<&'index [usize]>,
    ) {
        match CandidateLeadCell::of(request) {
            Some(lead) => {
                if let Some(indices) = self.by_lead.get(&lead) {
                    buckets.push(indices);
                }
                if !self.open.is_empty() {
                    buckets.push(&self.open);
                }
            }
            None => self.extend_all_buckets(buckets),
        }
    }

    /// Every bucket, for the readers that enumerate a node's paths with no
    /// admission predicate to narrow them.
    fn extend_all_buckets<'index>(&'index self, buckets: &mut Vec<&'index [usize]>) {
        buckets.extend(self.by_lead.values().map(Vec::as_slice));
        if !self.open.is_empty() {
            buckets.push(&self.open);
        }
    }

    fn estimated_retained_bytes(&self) -> usize {
        let Self { by_lead, open } = self;
        brokk_bifrost_core::hash::map_of_vec_slot_bytes(by_lead)
            .saturating_add(brokk_bifrost_core::hash::vec_slot_bytes(open))
    }
}

/// What one direction's whole candidate index retains, buckets included.
fn candidate_index_retained_bytes(index: &HashMap<BindingNodeId, CandidateNodeIndex>) -> usize {
    index
        .values()
        .map(CandidateNodeIndex::estimated_retained_bytes)
        .fold(
            brokk_bifrost_core::hash::map_slot_bytes(index),
            usize::saturating_add,
        )
}

/// Take the next path index across sorted buckets in candidate-identity
/// order, consuming what it takes.
///
/// `buckets` holds only non-empty slices; a slice that empties is removed.
/// Bucket order inside the vector is therefore not stable, which does not
/// matter: the choice is by identity and identities are unique across buckets.
fn take_next_candidate_in_identity_order(
    paths: &[StoredPartialPath],
    buckets: &mut Vec<&[usize]>,
) -> Option<usize> {
    if buckets.is_empty() {
        return None;
    }
    let mut best = 0;
    for bucket in 1..buckets.len() {
        if paths[buckets[bucket][0]].identity < paths[buckets[best][0]].identity {
            best = bucket;
        }
    }
    let taken = buckets[best][0];
    buckets[best] = &buckets[best][1..];
    if buckets[best].is_empty() {
        buckets.swap_remove(best);
    }
    Some(taken)
}

/// One immutable, file-local fragment supplied to preload mode.
///
/// The fragment ID is retained in every candidate identity. This makes a
/// candidate globally addressable without relying on an operation-local row
/// number and gives the SQL followup the same key shape.
#[derive(Debug)]
pub struct PreloadedFragment {
    id: BindingFragmentId,
    nodes: Vec<(BindingNodeId, BindingNodeKind)>,
    paths: Vec<(PartialPathId, PartialPath)>,
    reference_metadata: Vec<(SemanticId, FactReferenceSiteMetadata)>,
    go_definition_namespaces: Vec<(SemanticId, GoDefinitionNamespaces)>,
}

impl PreloadedFragment {
    pub fn new(
        id: BindingFragmentId,
        nodes: impl IntoIterator<Item = (BindingNodeId, BindingNodeKind)>,
        paths: impl IntoIterator<Item = (PartialPathId, PartialPath)>,
    ) -> Self {
        Self {
            id,
            nodes: nodes.into_iter().collect(),
            paths: paths.into_iter().collect(),
            reference_metadata: Vec::new(),
            go_definition_namespaces: Vec::new(),
        }
    }

    pub(super) fn with_reference_metadata(
        mut self,
        reference_metadata: impl IntoIterator<Item = (SemanticId, FactReferenceSiteMetadata)>,
    ) -> Self {
        self.reference_metadata = reference_metadata.into_iter().collect();
        self
    }

    pub(super) fn with_go_definition_namespaces(
        mut self,
        definitions: Vec<(SemanticId, GoDefinitionNamespaces)>,
    ) -> Self {
        self.go_definition_namespaces = definitions;
        self
    }

    pub const fn id(&self) -> BindingFragmentId {
        self.id
    }
}

/// In-memory source for closed-world algebra tests and pre-persistence language
/// spikes. It is operation-bounded and is not a workspace cache.
///
/// This source treats its fragment inventory as exhaustive and therefore
/// reports complete seed enumeration and candidate coverage. A partial lowerer
/// must encode every unsupported reachable frontier in path completion
/// evidence; a lowerer that can omit references or fragments must not present
/// those rows as a complete `PreloadedFragmentSource`.
#[derive(Debug, Default)]
pub struct PreloadedFragmentSource {
    fragments: HashSet<BindingFragmentId>,
    reference_inventory_by_fragment: HashMap<BindingFragmentId, ResolutionCompletion>,
    nodes: HashMap<BindingNodeId, BindingNodeKind>,
    node_fragments: HashMap<BindingNodeId, BindingFragmentId>,
    references: HashMap<SemanticId, BindingNodeId>,
    definitions: HashMap<SemanticId, BindingNodeId>,
    reference_metadata: HashMap<SemanticId, FactReferenceSiteMetadata>,
    go_definition_namespaces: HashMap<SemanticId, GoDefinitionNamespaces>,
    reference_order: Vec<(BindingFragmentId, SemanticId, BindingNodeId)>,
    paths: Vec<StoredPartialPath>,
    path_positions: HashMap<CandidatePathIdentity, usize>,
    forward: HashMap<BindingNodeId, CandidateNodeIndex>,
    reverse: HashMap<BindingNodeId, CandidateNodeIndex>,
    member_scope_owners: HashMap<BindingNodeId, SemanticId>,
    type_transfer_rules: HashMap<SemanticId, Vec<TypeTransferRule>>,
    coverage: PreloadedCoverage,
}

#[derive(Debug)]
struct PreloadedCoverage {
    fragment: ResolutionCompletion,
    enumeration: ResolutionCompletion,
    forward_candidate_inventory: ResolutionCompletion,
    reverse_candidate_inventory: ResolutionCompletion,
    references: HashMap<SemanticId, ResolutionCompletion>,
    forward_candidates: HashMap<BindingNodeId, CandidateCoverage>,
    reverse_candidates: HashMap<BindingNodeId, CandidateCoverage>,
    reverse_candidate_gaps: ReverseCandidateGapCoverage,
    type_slots: HashMap<SemanticId, ResolutionCompletion>,
}

#[derive(Debug)]
struct CandidateCoverage {
    all_lookups: ResolutionCompletion,
    by_lookup: HashMap<SemanticId, ResolutionCompletion>,
}

impl Default for CandidateCoverage {
    fn default() -> Self {
        Self {
            all_lookups: ResolutionCompletion::Complete,
            by_lookup: HashMap::default(),
        }
    }
}

impl CandidateCoverage {
    fn apply(&mut self, lookup: Option<SemanticId>, completion: &ResolutionCompletion) {
        if let Some(lookup) = lookup {
            PreloadedCoverage::combine_map(&mut self.by_lookup, lookup, completion);
        } else {
            self.all_lookups = self.all_lookups.combine(completion);
        }
    }

    fn completion_for_with_poll(
        &self,
        endpoint: &EndpointSignature,
        cancellation: &CancellationToken,
        work: &mut usize,
    ) -> ResolutionCompletion {
        let mut completion = BatchCompletionLedger::default();
        let _ = completion.include(&self.all_lookups, cancellation, work);
        if let Some(first) = endpoint.symbols().fixed().first() {
            if let Some(local) = self.by_lookup.get(&first.symbol()) {
                let _ = completion.include(local, cancellation, work);
            }
        } else if endpoint.symbols().tail().is_some() {
            for local in self.by_lookup.values() {
                let _ = completion.include(local, cancellation, work);
            }
        }
        completion.finish_semantic(cancellation, work).0
    }
}

impl CandidateCoverage {
    fn estimated_retained_bytes(&self) -> usize {
        let Self {
            all_lookups: _,
            by_lookup,
        } = self;
        brokk_bifrost_core::hash::map_slot_bytes(by_lookup)
    }
}

impl PreloadedCoverage {
    /// Conservative retained-byte estimate for cache admission. The fields are
    /// destructured exhaustively so a new one cannot silently leave the weight
    /// behind.
    fn estimated_retained_bytes(&self) -> usize {
        let Self {
            fragment: _,
            enumeration: _,
            forward_candidate_inventory: _,
            reverse_candidate_inventory: _,
            references,
            forward_candidates,
            reverse_candidates,
            reverse_candidate_gaps,
            type_slots,
        } = self;
        forward_candidates
            .values()
            .chain(reverse_candidates.values())
            .map(CandidateCoverage::estimated_retained_bytes)
            .fold(
                brokk_bifrost_core::hash::map_slot_bytes(references)
                    .saturating_add(brokk_bifrost_core::hash::map_slot_bytes(forward_candidates))
                    .saturating_add(brokk_bifrost_core::hash::map_slot_bytes(reverse_candidates))
                    .saturating_add(reverse_candidate_gaps.estimated_retained_bytes())
                    .saturating_add(brokk_bifrost_core::hash::map_slot_bytes(type_slots)),
                usize::saturating_add,
            )
    }
}

/// The heap one stored candidate path owns beyond its own inline size.
fn stored_partial_path_owned_bytes(stored: &StoredPartialPath) -> usize {
    let StoredPartialPath { identity: _, path } = stored;
    [path.start(), path.end()]
        .into_iter()
        .map(|endpoint| {
            endpoint
                .symbols()
                .fixed()
                .len()
                .saturating_mul(size_of::<SemanticId>())
                .saturating_add(
                    endpoint
                        .scopes()
                        .fixed()
                        .len()
                        .saturating_mul(size_of::<PartialScopedSymbol>()),
                )
        })
        .fold(
            path.precedence()
                .len()
                .saturating_mul(size_of::<PrecedenceStep>())
                .saturating_add(
                    path.witness()
                        .len()
                        .saturating_mul(size_of::<WitnessStep>()),
                ),
            usize::saturating_add,
        )
}

impl PreloadedFragmentSource {
    /// Conservative retained-byte estimate for cache admission.
    ///
    /// Rust cannot report an allocation's real size, so this charges the slots
    /// every collection allocated plus the heap each entry owns. The fields are
    /// destructured exhaustively so a new one cannot silently leave the weight
    /// behind.
    pub fn estimated_retained_bytes(&self) -> usize {
        let Self {
            fragments,
            reference_inventory_by_fragment,
            nodes,
            node_fragments,
            references,
            definitions,
            reference_metadata,
            go_definition_namespaces,
            reference_order,
            paths,
            path_positions,
            forward,
            reverse,
            member_scope_owners,
            type_transfer_rules,
            coverage,
        } = self;
        paths.iter().map(stored_partial_path_owned_bytes).fold(
            brokk_bifrost_core::hash::set_slot_bytes(fragments)
                .saturating_add(brokk_bifrost_core::hash::map_slot_bytes(
                    reference_inventory_by_fragment,
                ))
                .saturating_add(brokk_bifrost_core::hash::map_slot_bytes(nodes))
                .saturating_add(brokk_bifrost_core::hash::map_slot_bytes(node_fragments))
                .saturating_add(brokk_bifrost_core::hash::map_slot_bytes(references))
                .saturating_add(brokk_bifrost_core::hash::map_slot_bytes(definitions))
                .saturating_add(brokk_bifrost_core::hash::map_slot_bytes(reference_metadata))
                .saturating_add(brokk_bifrost_core::hash::map_slot_bytes(
                    go_definition_namespaces,
                ))
                .saturating_add(brokk_bifrost_core::hash::vec_slot_bytes(reference_order))
                .saturating_add(brokk_bifrost_core::hash::vec_slot_bytes(paths))
                .saturating_add(brokk_bifrost_core::hash::map_slot_bytes(path_positions))
                .saturating_add(candidate_index_retained_bytes(forward))
                .saturating_add(candidate_index_retained_bytes(reverse))
                .saturating_add(brokk_bifrost_core::hash::map_slot_bytes(
                    member_scope_owners,
                ))
                .saturating_add(brokk_bifrost_core::hash::map_of_vec_slot_bytes(
                    type_transfer_rules,
                ))
                .saturating_add(coverage.estimated_retained_bytes()),
            usize::saturating_add,
        )
    }
}

impl Default for PreloadedCoverage {
    fn default() -> Self {
        Self {
            fragment: ResolutionCompletion::Complete,
            enumeration: ResolutionCompletion::Complete,
            forward_candidate_inventory: ResolutionCompletion::Complete,
            reverse_candidate_inventory: ResolutionCompletion::Complete,
            references: HashMap::default(),
            forward_candidates: HashMap::default(),
            reverse_candidates: HashMap::default(),
            reverse_candidate_gaps: ReverseCandidateGapCoverage::empty(),
            type_slots: HashMap::default(),
        }
    }
}

impl PreloadedCoverage {
    fn is_complete(&self) -> bool {
        self.fragment == ResolutionCompletion::Complete
            && self.enumeration == ResolutionCompletion::Complete
            && self.forward_candidate_inventory == ResolutionCompletion::Complete
            && self.reverse_candidate_inventory == ResolutionCompletion::Complete
            && self.references.is_empty()
            && self.forward_candidates.is_empty()
            && self.reverse_candidates.is_empty()
            && self.type_slots.is_empty()
    }

    fn combine_map<K: std::hash::Hash + Eq>(
        values: &mut HashMap<K, ResolutionCompletion>,
        key: K,
        completion: &ResolutionCompletion,
    ) {
        values
            .entry(key)
            .and_modify(|current| *current = current.combine(completion))
            .or_insert_with(|| completion.clone());
    }

    fn apply(&mut self, gap: LoweredCoverageGap) {
        let completion =
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                gap.reason_semantic(),
            )]);
        match gap.frontier() {
            LoweringCoverageFrontier::Fragment => {
                self.fragment = self.fragment.combine(&completion);
            }
            LoweringCoverageFrontier::Enumeration => {
                self.enumeration = self.enumeration.combine(&completion);
            }
            LoweringCoverageFrontier::CandidateInventory {
                direction: LoweredCandidateDirection::Forward,
            } => {
                self.forward_candidate_inventory =
                    self.forward_candidate_inventory.combine(&completion);
            }
            LoweringCoverageFrontier::CandidateInventory {
                direction: LoweredCandidateDirection::Reverse,
            } => {
                self.reverse_candidate_inventory =
                    self.reverse_candidate_inventory.combine(&completion);
            }
            LoweringCoverageFrontier::Reference { semantic, .. } => {
                Self::combine_map(&mut self.references, semantic, &completion);
            }
            LoweringCoverageFrontier::Candidate {
                direction: LoweredCandidateDirection::Forward,
                endpoint,
                lookup,
            } => self
                .forward_candidates
                .entry(endpoint)
                .or_default()
                .apply(lookup, &completion),
            LoweringCoverageFrontier::Candidate {
                direction: LoweredCandidateDirection::Reverse,
                endpoint,
                lookup,
            } => self
                .reverse_candidates
                .entry(endpoint)
                .or_default()
                .apply(lookup, &completion),
            LoweringCoverageFrontier::Type { frontier } => {
                Self::combine_map(&mut self.type_slots, frontier, &completion);
            }
        }
    }

    fn reference_completion_with_poll(
        &self,
        semantic: SemanticId,
        cancellation: &CancellationToken,
        work: &mut usize,
    ) -> ResolutionCompletion {
        let mut completion = BatchCompletionLedger::default();
        let _ = completion.include(&self.fragment, cancellation, work);
        if let Some(local) = self.references.get(&semantic) {
            let _ = completion.include(local, cancellation, work);
        }
        completion.finish_semantic(cancellation, work).0
    }

    fn enumeration_completion_with_poll(
        &self,
        cancellation: &CancellationToken,
        work: &mut usize,
    ) -> ResolutionCompletion {
        let mut completion = BatchCompletionLedger::default();
        let _ = completion.include(&self.fragment, cancellation, work);
        let _ = completion.include(&self.enumeration, cancellation, work);
        completion.finish(cancellation, work).0
    }

    fn candidate_unconditional_completion_with_poll(
        &self,
        direction: LoweredCandidateDirection,
        cancellation: &CancellationToken,
        work: &mut usize,
    ) -> ResolutionCompletion {
        let inventory = match direction {
            LoweredCandidateDirection::Forward => &self.forward_candidate_inventory,
            LoweredCandidateDirection::Reverse => &self.reverse_candidate_inventory,
        };
        let mut completion = BatchCompletionLedger::default();
        let _ = completion.include(&self.fragment, cancellation, work);
        let _ = completion.include(inventory, cancellation, work);
        completion.finish_semantic(cancellation, work).0
    }

    fn candidate_branch_completion_with_poll(
        &self,
        direction: LoweredCandidateDirection,
        endpoint: &EndpointSignature,
        cancellation: &CancellationToken,
        work: &mut usize,
    ) -> ResolutionCompletion {
        let local = match direction {
            LoweredCandidateDirection::Forward => self.forward_candidates.get(&endpoint.node()),
            LoweredCandidateDirection::Reverse => self.reverse_candidates.get(&endpoint.node()),
        };
        local.map_or(ResolutionCompletion::Complete, |local| {
            local.completion_for_with_poll(endpoint, cancellation, work)
        })
    }

    fn reverse_candidate_completion_outcome(
        &self,
        requests: &[BatchCandidateRequest],
        exclusions: Option<&ReverseCandidateGapExclusionPlan>,
        cancellation: &CancellationToken,
        work: &mut usize,
    ) -> StoreResult<(BatchCandidateCompletionOutcome, bool)> {
        let mut cancellation_observed = cancellation.is_cancelled();
        let mut branch_completions = Vec::with_capacity(requests.len());
        for request in requests {
            let (completion, observed) = if let Some(exclusions) = exclusions {
                self.reverse_candidate_gaps
                    .filtered_branch_completion_for_with_poll(
                        request.endpoint(),
                        exclusions,
                        cancellation,
                        work,
                    )?
            } else {
                self.reverse_candidate_gaps.branch_completion_for_with_poll(
                    request.endpoint(),
                    cancellation,
                    work,
                )
            };
            cancellation_observed |= observed;
            branch_completions.push(completion);
        }

        let inventory = if let Some(exclusions) = exclusions {
            self.reverse_candidate_gaps
                .filtered_inventory_completion(exclusions)?
        } else {
            self.reverse_candidate_gaps.inventory_completion()
        };
        let mut unconditional = BatchCompletionLedger::default();
        cancellation_observed |= unconditional.include(&self.fragment, cancellation, work);
        cancellation_observed |= unconditional.include(inventory, cancellation, work);
        let (unconditional, observed) = unconditional.finish_semantic(cancellation, work);
        cancellation_observed |= observed;
        let mut constructor_observed = false;
        let outcome = BatchCandidateCompletionOutcome::new_observing(
            requests.len(),
            unconditional,
            branch_completions,
            || {
                constructor_observed |= poll_reverse_gap_completion(cancellation, work);
            },
        );
        cancellation_observed |= constructor_observed | cancellation.is_cancelled();
        if cancellation_observed {
            return Ok((
                include_preloaded_candidate_cancellation(outcome, cancellation, work),
                true,
            ));
        }
        Ok((outcome, false))
    }

    fn type_completion(&self, slot: SemanticId) -> ResolutionCompletion {
        let mut completion = self.fragment.clone();
        if let Some(local) = self.type_slots.get(&slot) {
            completion = completion.combine(local);
        }
        completion
    }
}

fn poll_reverse_gap_completion(cancellation: &CancellationToken, work: &mut usize) -> bool {
    *work = work
        .checked_add(1)
        .expect("preloaded reverse gap completion work must fit usize");
    work.is_multiple_of(CANCELLATION_QUANTUM) && cancellation.is_cancelled()
}

fn include_preloaded_candidate_cancellation(
    completion: BatchCandidateCompletionOutcome,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> BatchCandidateCompletionOutcome {
    let request_count = completion.branch_completions().len();
    let (unconditional, branches) = completion.into_parts();
    let mut evidence = CancellationEvidenceLedger::default();
    let _ = evidence.include(&unconditional, cancellation, work);
    let (unconditional, _) = evidence.finish(true, cancellation, work);
    BatchCandidateCompletionOutcome::new_observing(request_count, unconditional, branches, || {
        let _ = poll_reverse_gap_completion(cancellation, work);
    })
}

impl PreloadedFragmentSource {
    /// Certify reference inventory for one selected source, including sources
    /// with no reference seeds. Typing gaps are not enumeration gaps.
    pub(crate) fn reference_inventory_completion(
        &self,
        fragment: BindingFragmentId,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> StoreResult<ResolutionCompletion> {
        if !session.scope_step() || cancellation.is_cancelled() {
            return Ok(cancelled_completion());
        }
        if !self.fragments.contains(&fragment) {
            return Err(StoreError::new(format!(
                "reference inventory requested an unselected transient fragment {fragment}"
            )));
        }
        let completion = self
            .reference_inventory_by_fragment
            .get(&fragment)
            .cloned()
            .unwrap_or(ResolutionCompletion::Complete);
        if let ResolutionCompletion::Incomplete(reasons) = &completion {
            for _ in reasons.iter() {
                if !session.scope_step() || cancellation.is_cancelled() {
                    return Ok(completion.combine(&cancelled_completion()));
                }
            }
        }
        if cancellation.is_cancelled() || !session.observe_cancellation() {
            return Ok(completion.combine(&cancelled_completion()));
        }
        Ok(completion)
    }

    fn assert_local_or_boundary_node(
        &self,
        fragment: BindingFragmentId,
        node: BindingNodeId,
        context: &str,
    ) {
        let kind = self
            .nodes
            .get(&node)
            .unwrap_or_else(|| panic!("{context} names unknown binding node {node}"));
        assert!(
            matches!(kind, BindingNodeKind::Root)
                || self.node_fragments.get(&node) == Some(&fragment),
            "{context} names non-local, non-boundary binding node {node} from fragment {fragment}"
        );
    }

    /// Stable owner used by the convenience constructor.
    ///
    /// Tests that model file-major behavior should use [`Self::from_fragments`]
    /// with explicit fragment IDs. Keeping this identity visible avoids an
    /// implicit fragment-less special case in the batch engine.
    /// The fragment a preloaded source mounts its content on.
    ///
    /// A preloaded source is not a selection's mount and never shares an
    /// interior with one, so it takes the unmounted ordinal, which
    /// `MountRebaser::register_mount` refuses to hand to a real mount.
    pub fn synthetic_fragment_id() -> BindingFragmentId {
        BindingFragmentId::unmounted()
    }

    pub fn new(
        nodes: impl IntoIterator<Item = (BindingNodeId, BindingNodeKind)>,
        paths: impl IntoIterator<Item = (PartialPathId, PartialPath)>,
    ) -> Self {
        let mut boundaries = Vec::new();
        let mut local_nodes = Vec::new();
        for (node, kind) in nodes {
            if matches!(kind, BindingNodeKind::Root) {
                boundaries.push(node);
            } else {
                local_nodes.push((node, kind));
            }
        }
        Self::from_fragments_with_boundaries(
            boundaries,
            [PreloadedFragment::new(
                Self::synthetic_fragment_id(),
                local_nodes,
                paths,
            )],
        )
    }

    pub fn from_fragments(fragments: impl IntoIterator<Item = PreloadedFragment>) -> Self {
        Self::from_fragments_with_boundaries([], fragments)
    }

    /// Build an operation-local source from fact-lowered fragments while
    /// retaining every normalized coverage gap.
    ///
    /// Use this constructor for language facts. Calling
    /// [`LoweredResolutionFragment::into_preloaded_parts`] directly is useful
    /// for a publisher, but a query source must install the returned gaps
    /// before it can make closed-world claims.
    pub fn from_lowered_fragments(
        fragments: impl IntoIterator<Item = LoweredResolutionFragment>,
    ) -> Self {
        Self::from_lowered_fragments_with_boundaries([], fragments)
    }

    /// Build a fact-lowered source plus independently owned shared boundaries.
    /// The schema-owned universal root is always present because a content
    /// producer may refer to it without emitting a fragment-local node row.
    pub fn from_lowered_fragments_with_boundaries(
        boundaries: impl IntoIterator<Item = BindingNodeId>,
        fragments: impl IntoIterator<Item = LoweredResolutionFragment>,
    ) -> Self {
        let mut boundaries = boundaries.into_iter().collect::<Vec<_>>();
        let mut unique_boundaries = HashSet::default();
        for &boundary in &boundaries {
            assert!(
                unique_boundaries.insert(boundary),
                "duplicate preloaded boundary node {boundary}"
            );
        }
        if unique_boundaries.insert(BindingNodeId::universal_root()) {
            boundaries.push(BindingNodeId::universal_root());
        }
        let mut preloaded = Vec::new();
        let mut gaps = Vec::new();
        for lowered in fragments {
            let fragment_id = lowered.fragment();
            let (fragment, fragment_gaps) = lowered.into_preloaded_parts();
            preloaded.push(fragment);
            gaps.extend(
                fragment_gaps
                    .into_vec()
                    .into_iter()
                    .map(|(id, gap)| (fragment_id, id, gap)),
            );
        }
        let mut source = Self::from_fragments_with_boundaries(boundaries, preloaded);
        source.install_lowering_coverage(gaps);
        source
    }

    /// Build a preload source with root nodes owned by an independent boundary
    /// artifact rather than by an arbitrary file fragment.
    pub fn from_fragments_with_boundaries(
        boundaries: impl IntoIterator<Item = BindingNodeId>,
        fragments: impl IntoIterator<Item = PreloadedFragment>,
    ) -> Self {
        let mut fragments = fragments.into_iter().collect::<Vec<_>>();
        fragments.sort_unstable_by_key(PreloadedFragment::id);

        let mut source = Self::default();
        for boundary in boundaries {
            assert!(
                source
                    .nodes
                    .insert(boundary, BindingNodeKind::Root)
                    .is_none(),
                "duplicate preloaded boundary node {boundary}"
            );
        }
        let mut fragment_ids = HashSet::default();
        for fragment in &fragments {
            assert!(
                fragment_ids.insert(fragment.id),
                "duplicate preloaded fragment {}",
                fragment.id
            );
            for &(node, kind) in &fragment.nodes {
                assert!(
                    !matches!(kind, BindingNodeKind::Root),
                    "root node {node} must be supplied as an independent boundary"
                );
                assert!(
                    source.nodes.insert(node, kind).is_none(),
                    "duplicate binding node {node}"
                );
                assert!(
                    source.node_fragments.insert(node, fragment.id).is_none(),
                    "duplicate binding node owner {node}"
                );
                match kind {
                    BindingNodeKind::Reference(semantic) => {
                        assert!(
                            source.references.insert(semantic, node).is_none(),
                            "duplicate reference semantic {semantic}"
                        );
                    }
                    BindingNodeKind::Definition(semantic) => {
                        assert!(
                            source.definitions.insert(semantic, node).is_none(),
                            "duplicate definition semantic {semantic}"
                        );
                    }
                    _ => {}
                }
            }
        }
        source.fragments = fragment_ids;
        for fragment in &fragments {
            for &(definition, namespaces) in &fragment.go_definition_namespaces {
                let node = source
                    .definitions
                    .get(&definition)
                    .expect("Go lexical authority needs a definition");
                assert_eq!(source.node_fragments[node], fragment.id);
                assert!(
                    source
                        .go_definition_namespaces
                        .insert(definition, namespaces)
                        .is_none()
                );
            }
            for &(reference, metadata) in &fragment.reference_metadata {
                let reference_node = source.references.get(&reference).unwrap_or_else(|| {
                    panic!("preloaded site metadata names unknown reference semantic {reference}")
                });
                assert_eq!(
                    source.node_fragments.get(reference_node),
                    Some(&fragment.id),
                    "preloaded site metadata {reference} must belong to fragment {}",
                    fragment.id
                );
                if let Some(owner) = metadata.reference_owner().flatten() {
                    let owner_node = source.definitions.get(&owner).unwrap_or_else(|| {
                        panic!(
                            "preloaded reference owner {reference} names unknown definition semantic {owner}"
                        )
                    });
                    assert_eq!(
                        source.node_fragments.get(owner_node),
                        Some(&fragment.id),
                        "preloaded reference owner {owner} must belong to the reference fragment {}",
                        fragment.id
                    );
                }
                assert!(
                    source
                        .reference_metadata
                        .insert(reference, metadata)
                        .is_none(),
                    "duplicate preloaded site metadata for reference semantic {reference}"
                );
            }
        }
        source.reference_order = source
            .references
            .iter()
            .map(|(semantic, node)| {
                let fragment = source
                    .node_fragments
                    .get(node)
                    .copied()
                    .expect("every preloaded reference node has an owning fragment");
                (fragment, *semantic, *node)
            })
            .collect();
        source.reference_order.sort_unstable();

        for fragment in &fragments {
            for &(node, kind) in &fragment.nodes {
                if let BindingNodeKind::JumpToScope(target) = kind {
                    source.assert_local_or_boundary_node(
                        fragment.id,
                        target,
                        &format!("jump node {node} in fragment {}", fragment.id),
                    );
                }
            }
        }

        let mut path_ids = HashSet::default();
        for fragment in fragments {
            for (id, path) in fragment.paths {
                assert!(path_ids.insert(id), "duplicate partial path {id}");
                for (label, endpoint) in [("start", path.start()), ("end", path.end())] {
                    source.assert_local_or_boundary_node(
                        fragment.id,
                        endpoint.node(),
                        &format!(
                            "partial path {id} {label} endpoint in fragment {}",
                            fragment.id
                        ),
                    );
                    for &scope in endpoint.scopes().fixed() {
                        source.assert_local_or_boundary_node(
                            fragment.id,
                            scope,
                            &format!(
                                "partial path {id} {label} scope stack in fragment {}",
                                fragment.id
                            ),
                        );
                    }
                    for symbol in endpoint.symbols().fixed() {
                        let Some(scopes) = symbol.scopes() else {
                            continue;
                        };
                        for &scope in scopes.fixed() {
                            source.assert_local_or_boundary_node(
                                fragment.id,
                                scope,
                                &format!(
                                    "partial path {id} {label} attached scope stack in fragment {}",
                                    fragment.id
                                ),
                            );
                        }
                    }
                }
                for (position, step) in path.witness().iter().enumerate() {
                    if let WitnessStep::Node(node) = *step {
                        source.assert_local_or_boundary_node(
                            fragment.id,
                            node,
                            &format!(
                                "partial path {id} witness position {position} in fragment {}",
                                fragment.id
                            ),
                        );
                    }
                }
                let identity = CandidatePathIdentity::new(fragment.id, id);
                let index = source.paths.len();
                assert!(
                    source.path_positions.insert(identity, index).is_none(),
                    "duplicate candidate path {identity:?}"
                );
                source
                    .forward
                    .entry(path.start().node())
                    .or_default()
                    .push(CandidateLeadCell::of(path.start()), index);
                source
                    .reverse
                    .entry(path.end().node())
                    .or_default()
                    .push(CandidateLeadCell::of(path.end()), index);
                source.paths.push(StoredPartialPath { identity, path });
            }
        }
        let paths = &source.paths;
        for node_index in source.forward.values_mut() {
            node_index.sort_by_identity(paths);
        }
        for node_index in source.reverse.values_mut() {
            node_index.sort_by_identity(paths);
        }
        source
    }

    pub(super) fn install_lowering_coverage(
        &mut self,
        gaps: impl IntoIterator<Item = (BindingFragmentId, SemanticId, LoweredCoverageGap)>,
    ) {
        let mut seen = HashSet::default();
        let mut reverse_candidate_gaps = ReverseCandidateGapCoverageBuilder::default();
        for (fragment, gap_id, gap) in gaps {
            assert!(
                self.fragments.contains(&fragment),
                "preloaded lowering coverage gap {} names non-selected fragment {fragment}",
                gap_id
            );
            let identity = ReverseCandidateGapIdentity::new(fragment, gap_id);
            assert!(
                seen.insert(identity),
                "duplicate preloaded lowering coverage gap ({fragment}, {})",
                gap_id
            );
            if matches!(
                gap.frontier(),
                LoweringCoverageFrontier::Fragment | LoweringCoverageFrontier::Enumeration
            ) {
                PreloadedCoverage::combine_map(
                    &mut self.reference_inventory_by_fragment,
                    fragment,
                    &ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(gap.reason_semantic()),
                    ]),
                );
            }
            match gap.frontier() {
                LoweringCoverageFrontier::Reference { semantic, node } => {
                    assert_eq!(
                        self.references.get(&semantic),
                        Some(&node),
                        "reference coverage gap names a non-selected semantic/node pair"
                    );
                }
                LoweringCoverageFrontier::Candidate { endpoint, .. } => {
                    assert!(
                        self.nodes.contains_key(&endpoint),
                        "candidate coverage gap names unknown endpoint {endpoint}"
                    );
                }
                LoweringCoverageFrontier::Fragment
                | LoweringCoverageFrontier::Enumeration
                | LoweringCoverageFrontier::CandidateInventory { .. }
                | LoweringCoverageFrontier::Type { .. } => {}
            }
            let reverse_location = match gap.frontier() {
                LoweringCoverageFrontier::CandidateInventory {
                    direction: LoweredCandidateDirection::Reverse,
                } => Some(ReverseCandidateGapLocation::Inventory),
                LoweringCoverageFrontier::Candidate {
                    direction: LoweredCandidateDirection::Reverse,
                    endpoint,
                    lookup,
                } => Some(ReverseCandidateGapLocation::Endpoint { endpoint, lookup }),
                _ => None,
            };
            if let Some(location) = reverse_location {
                reverse_candidate_gaps
                    .push(ReverseCandidateGapRow::new(
                        identity,
                        location,
                        ResolutionIncompleteReason::UnsupportedSemantic(gap.reason_semantic()),
                    ))
                    .expect("preloaded reverse candidate gap identities are unique");
            }
            self.coverage.apply(gap);
        }
        let (reverse_candidate_gaps, cancelled) = reverse_candidate_gaps
            .finish(&CancellationToken::new())
            .expect("preloaded reverse candidate gap rows are structurally valid");
        assert!(
            !cancelled,
            "fresh-token preload gap installation returned cancellation"
        );
        debug_assert_eq!(
            reverse_candidate_gaps.inventory_completion(),
            &self.coverage.reverse_candidate_inventory,
            "raw and exact preload reverse-inventory coverage must agree"
        );
        self.coverage.reverse_candidate_gaps = reverse_candidate_gaps;
    }

    pub(super) fn install_member_scope_owners(
        &mut self,
        owners: impl IntoIterator<Item = (BindingNodeId, SemanticId)>,
    ) {
        for (scope_head, owner) in owners {
            assert_eq!(
                self.nodes.get(&scope_head),
                Some(&BindingNodeKind::Scope),
                "member-scope owner {owner} must name a Scope endpoint {scope_head}"
            );
            assert!(
                self.member_scope_owners.insert(scope_head, owner).is_none(),
                "duplicate or conflicting member-scope owner classification for endpoint {scope_head}"
            );
        }
    }

    fn require_legacy_closed_world(&self) -> StoreResult<()> {
        if self.coverage.is_complete() {
            Ok(())
        } else {
            Err(StoreError::new(
                "the visitor-shaped preload engine cannot represent normalized lowering coverage; use BatchResolutionEngine"
                    .to_owned(),
            ))
        }
    }

    fn visit_candidate_match_pages_from_index(
        &self,
        index: &HashMap<BindingNodeId, CandidateNodeIndex>,
        offered_endpoint: fn(&PartialPath) -> &EndpointSignature,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
        work: &mut usize,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<()> {
        self.visit_candidate_match_pages_from_index_limited(
            index,
            offered_endpoint,
            requests,
            MAX_SOURCE_ROWS_PER_BATCH,
            None,
            cancellation,
            work,
            visitor,
        )
    }

    /// Walk the candidate paths a page of requests can be admitted by, one
    /// charged step per path examined.
    ///
    /// The index is keyed by what [`endpoint_admits_candidate`] decides, so a
    /// request visits the bucket of its own first fixed cell plus the bucket
    /// of stored endpoints that fix nothing, and only a request that fixes
    /// nothing itself enumerates a node. The buckets are merged in
    /// candidate-identity order rather than walked one after another: each
    /// bucket is sorted and the buckets are disjoint, so the merge is strictly
    /// increasing, a request's emitted order is what the node-wide vector
    /// produced, and the canonical assertion below still checks every pair.
    /// Concatenating the buckets instead would have changed which candidates a
    /// page holds when a session's budget stops the walk part-way.
    #[allow(clippy::too_many_arguments)]
    fn visit_candidate_match_pages_from_index_limited(
        &self,
        index: &HashMap<BindingNodeId, CandidateNodeIndex>,
        offered_endpoint: fn(&PartialPath) -> &EndpointSignature,
        requests: &[BatchCandidateRequest],
        maximum_page_rows: usize,
        resolution_session: Option<&ResolutionSession>,
        cancellation: &CancellationToken,
        work: &mut usize,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<()> {
        assert!(
            requests.len() <= MAX_SOURCE_ROWS_PER_BATCH,
            "candidate request page has {} entries; maximum is {MAX_SOURCE_ROWS_PER_BATCH}",
            requests.len()
        );
        assert!((1..=MAX_SOURCE_ROWS_PER_BATCH).contains(&maximum_page_rows));
        let mut page = Vec::with_capacity(maximum_page_rows);
        let mut buckets = Vec::new();
        'requests: for (request_ordinal, request) in requests.iter().enumerate() {
            assert_eq!(
                request.request_ordinal(),
                request_ordinal,
                "preloaded candidate requests must use canonical local ordinals"
            );
            if resolution_session.is_some_and(|session| !session.scope_step()) {
                break;
            }
            *work = work
                .checked_add(1)
                .expect("preloaded candidate request work must fit usize");
            if work.is_multiple_of(CANCELLATION_QUANTUM) && cancellation.is_cancelled() {
                break;
            }
            let Some(node_index) = index.get(&request.endpoint().node()) else {
                continue;
            };
            buckets.clear();
            node_index.extend_buckets_for(request.endpoint(), &mut buckets);
            let mut prior = None;
            while let Some(path_index) =
                take_next_candidate_in_identity_order(&self.paths, &mut buckets)
            {
                if resolution_session.is_some_and(|session| !session.scope_step()) {
                    break 'requests;
                }
                *work = work
                    .checked_add(1)
                    .expect("preloaded candidate row work must fit usize");
                if work.is_multiple_of(CANCELLATION_QUANTUM) && cancellation.is_cancelled() {
                    break 'requests;
                }
                let stored = &self.paths[path_index];
                if !endpoint_admits_candidate(request.endpoint(), offered_endpoint(&stored.path)) {
                    continue;
                }
                let candidate = stored.identity;
                if let Some(prior) = prior {
                    assert!(
                        prior < candidate,
                        "preloaded candidate index must be strictly canonical"
                    );
                }
                prior = Some(candidate);
                page.push(BatchCandidateMatch::new(candidate, request_ordinal));
                if page.len() == maximum_page_rows {
                    if !visitor(&page)? {
                        return Ok(());
                    }
                    page.clear();
                }
            }
        }
        if !page.is_empty() && !cancellation.is_cancelled() {
            let _ = visitor(&page)?;
        }
        Ok(())
    }

    pub fn with_type_transfer_rules(
        mut self,
        rules: impl IntoIterator<Item = (SemanticId, TypeTransferRule)>,
    ) -> Self {
        for (source_slot, rule) in rules {
            self.type_transfer_rules
                .entry(source_slot)
                .or_default()
                .push(rule);
        }
        for rules in self.type_transfer_rules.values_mut() {
            rules.sort_unstable();
            rules.dedup();
        }
        self
    }
}

impl ResolutionFragmentSource for PreloadedFragmentSource {
    fn go_spelling_namespace(
        &self,
        reference: SemanticId,
    ) -> StoreResult<Option<ResolutionNamespace>> {
        Ok(self
            .reference_metadata
            .get(&reference)
            .and_then(|metadata| metadata.go_spelling_namespace()))
    }

    fn go_package_qualifier(&self, reference: SemanticId) -> StoreResult<bool> {
        Ok(self
            .reference_metadata
            .get(&reference)
            .is_some_and(|metadata| metadata.go_package_qualifier()))
    }

    fn go_definition_namespaces(
        &self,
        definition: SemanticId,
    ) -> StoreResult<Option<GoDefinitionNamespaces>> {
        Ok(self.go_definition_namespaces.get(&definition).copied())
    }

    fn reference_node(&self, reference: SemanticId) -> StoreResult<Option<BindingNodeId>> {
        self.require_legacy_closed_world()?;
        Ok(self.references.get(&reference).copied())
    }

    fn reference_semantic(&self, node: BindingNodeId) -> StoreResult<Option<SemanticId>> {
        self.require_legacy_closed_world()?;
        Ok(match self.nodes.get(&node) {
            Some(BindingNodeKind::Reference(semantic)) => Some(*semantic),
            _ => None,
        })
    }

    fn definition_node(&self, definition: SemanticId) -> StoreResult<Option<BindingNodeId>> {
        self.require_legacy_closed_world()?;
        Ok(self.definitions.get(&definition).copied())
    }

    fn definition_semantic(&self, node: BindingNodeId) -> StoreResult<Option<SemanticId>> {
        self.require_legacy_closed_world()?;
        Ok(match self.nodes.get(&node) {
            Some(BindingNodeKind::Definition(semantic)) => Some(*semantic),
            _ => None,
        })
    }

    fn visit_references(
        &self,
        visitor: &mut dyn FnMut(SemanticId, BindingNodeId) -> StoreResult<bool>,
    ) -> StoreResult<()> {
        self.require_legacy_closed_world()?;
        let mut references = self
            .references
            .iter()
            .map(|(semantic, node)| (*semantic, *node))
            .collect::<Vec<_>>();
        references.sort_unstable();
        for (semantic, node) in references {
            if !visitor(semantic, node)? {
                break;
            }
        }
        Ok(())
    }

    fn visit_forward_candidates(
        &self,
        endpoint: &EndpointSignature,
        visitor: &mut dyn FnMut(PartialPathId, &PartialPath) -> StoreResult<bool>,
    ) -> StoreResult<()> {
        self.require_legacy_closed_world()?;
        let Some(node_index) = self.forward.get(&endpoint.node()) else {
            return Ok(());
        };
        let mut buckets = Vec::new();
        node_index.extend_all_buckets(&mut buckets);
        while let Some(index) = take_next_candidate_in_identity_order(&self.paths, &mut buckets) {
            let candidate = &self.paths[index];
            if !visitor(candidate.identity.path(), &candidate.path)? {
                break;
            }
        }
        Ok(())
    }

    fn visit_reverse_candidates(
        &self,
        endpoint: &EndpointSignature,
        visitor: &mut dyn FnMut(PartialPathId, &PartialPath) -> StoreResult<bool>,
    ) -> StoreResult<()> {
        self.require_legacy_closed_world()?;
        let Some(node_index) = self.reverse.get(&endpoint.node()) else {
            return Ok(());
        };
        let mut buckets = Vec::new();
        node_index.extend_all_buckets(&mut buckets);
        while let Some(index) = take_next_candidate_in_identity_order(&self.paths, &mut buckets) {
            let candidate = &self.paths[index];
            if !visitor(candidate.identity.path(), &candidate.path)? {
                break;
            }
        }
        Ok(())
    }

    fn visit_type_transfer_rules(
        &self,
        source_slot: SemanticId,
        visitor: &mut dyn FnMut(&TypeTransferRule) -> StoreResult<bool>,
    ) -> StoreResult<ResolutionCompletion> {
        self.require_legacy_closed_world()?;
        let Some(rules) = self.type_transfer_rules.get(&source_slot) else {
            return Ok(ResolutionCompletion::Complete);
        };
        let mut stopped = false;
        for rule in rules {
            if !visitor(rule)? {
                stopped = true;
                break;
            }
        }
        Ok(if stopped {
            rules
                .iter()
                .fold(ResolutionCompletion::Complete, |completion, rule| {
                    completion.combine(rule.completion())
                })
        } else {
            ResolutionCompletion::Complete
        })
    }
}

impl BatchResolutionFragmentSource for PreloadedFragmentSource {
    /// A preload has no selection behind it: it answers from the fragments it
    /// was handed, so it names no authority and is memoized for nothing.
    fn selection_authority(&self) -> Option<super::batch::SeedReadAuthority> {
        None
    }

    fn reference_seed(
        &self,
        query: ResolutionQuery,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<ReferenceSeed>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let Some(&node) = self.references.get(&query.reference()) else {
            return Ok(None);
        };
        let fragment = self
            .node_fragments
            .get(&node)
            .copied()
            .expect("every preloaded reference node has an owning fragment");
        let mut work = 0_usize;
        Ok(Some(ReferenceSeed::new_with_site_metadata(
            fragment,
            query,
            node,
            self.reference_metadata.get(&query.reference()).copied(),
            self.coverage.reference_completion_with_poll(
                query.reference(),
                cancellation,
                &mut work,
            ),
        )))
    }

    fn lookup_reference_seeds(
        &self,
        queries: &[ResolutionQuery],
        cancellation: &CancellationToken,
    ) -> StoreResult<ReferenceSeedReadOutcome> {
        assert!(
            queries.len() <= super::batch::MAX_REFERENCE_SEEDS_PER_BATCH,
            "reference seed batch has {} queries; maximum is {}",
            queries.len(),
            super::batch::MAX_REFERENCE_SEEDS_PER_BATCH
        );
        if cancellation.is_cancelled() {
            return Ok(ReferenceSeedReadOutcome::cancelled(
                ResolutionCompletion::Complete,
            ));
        }

        let mut rows = Vec::with_capacity(queries.len());
        let mut evidence = BatchCompletionLedger::default();
        let mut work = 0_usize;
        for (ordinal, &query) in queries.iter().enumerate() {
            let mut cancellation_observed =
                ordinal.is_multiple_of(CANCELLATION_QUANTUM) && cancellation.is_cancelled();
            let seed = self.references.get(&query.reference()).map(|&node| {
                let fragment = self
                    .node_fragments
                    .get(&node)
                    .copied()
                    .expect("every preloaded reference node has an owning fragment");
                ReferenceSeed::new_with_site_metadata(
                    fragment,
                    query,
                    node,
                    self.reference_metadata.get(&query.reference()).copied(),
                    self.coverage.reference_completion_with_poll(
                        query.reference(),
                        cancellation,
                        &mut work,
                    ),
                )
            });
            if let Some(seed) = &seed {
                cancellation_observed |=
                    evidence.include(seed.completion(), cancellation, &mut work);
            }
            cancellation_observed |= cancellation.is_cancelled();
            if cancellation_observed {
                let (evidence, _) = evidence.finish_semantic(cancellation, &mut work);
                return Ok(ReferenceSeedReadOutcome::cancelled(evidence));
            }
            rows.push(BatchReferenceSeed::new(ordinal, query, seed));
        }
        if cancellation.is_cancelled() {
            let (evidence, _) = evidence.finish_semantic(cancellation, &mut work);
            return Ok(ReferenceSeedReadOutcome::cancelled(evidence));
        }
        Ok(ReferenceSeedReadOutcome::exhausted(rows))
    }

    fn lookup_definition_node(
        &self,
        definition: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<BindingNodeId>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        Ok(self.definitions.get(&definition).copied())
    }

    fn lookup_definition_nodes(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Vec<super::batch::BatchDefinitionNode>> {
        assert!(
            definitions.len() <= super::batch::MAX_REVERSE_TARGETS_PER_BATCH,
            "definition-node batch has {} entries; maximum is {}",
            definitions.len(),
            super::batch::MAX_REVERSE_TARGETS_PER_BATCH
        );
        let mut rows = Vec::with_capacity(definitions.len());
        for (ordinal, definition) in definitions.iter().copied().enumerate() {
            if ordinal.is_multiple_of(CANCELLATION_QUANTUM) && cancellation.is_cancelled() {
                break;
            }
            rows.push(super::batch::BatchDefinitionNode::new(
                definition,
                self.definitions.get(&definition).copied(),
            ));
        }
        Ok(rows)
    }

    fn issue_reverse_reference_seeds(
        &self,
        requests: &[ReverseReferenceSeedRequest],
        cancellation: &CancellationToken,
    ) -> StoreResult<Vec<ReferenceSeed>> {
        assert!(
            requests.len() <= super::batch::MAX_REFERENCE_SEEDS_PER_BATCH,
            "reverse reference seed batch has {} entries; maximum is {}",
            requests.len(),
            super::batch::MAX_REFERENCE_SEEDS_PER_BATCH
        );
        let mut seeds = Vec::with_capacity(requests.len());
        let mut work = 0_usize;
        for (ordinal, request) in requests.iter().copied().enumerate() {
            if ordinal.is_multiple_of(CANCELLATION_QUANTUM) && cancellation.is_cancelled() {
                break;
            }
            let Some(&node) = self.references.get(&request.reference()) else {
                continue;
            };
            if node != request.expected_node() {
                continue;
            }
            let fragment = self
                .node_fragments
                .get(&node)
                .copied()
                .expect("every preloaded reference node has an owning fragment");
            seeds.push(ReferenceSeed::new_with_site_metadata(
                fragment,
                ResolutionQuery::new(request.reference()),
                node,
                self.reference_metadata.get(&request.reference()).copied(),
                self.coverage.reference_completion_with_poll(
                    request.reference(),
                    cancellation,
                    &mut work,
                ),
            ));
        }
        Ok(seeds)
    }

    fn visit_reference_seed_batches(
        &self,
        maximum_batch_size: usize,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&ReferenceSeedBatch) -> StoreResult<bool>,
    ) -> StoreResult<ResolutionCompletion> {
        assert!(
            (1..=super::batch::MAX_REFERENCE_SEEDS_PER_BATCH).contains(&maximum_batch_size),
            "reference batch size must be in 1..={}",
            super::batch::MAX_REFERENCE_SEEDS_PER_BATCH
        );
        let mut work = 0_usize;
        let mut returned_evidence = CancellationEvidenceLedger::default();
        let mut fragment_start = 0;
        while fragment_start < self.reference_order.len() {
            returned_evidence.observe_row(cancellation, &mut work);
            if returned_evidence.cancellation_observed() || cancellation.is_cancelled() {
                let enumeration = self
                    .coverage
                    .enumeration_completion_with_poll(cancellation, &mut work);
                returned_evidence.include(&enumeration, cancellation, &mut work);
                return Ok(returned_evidence.finish(true, cancellation, &mut work).0);
            }
            let fragment = self.reference_order[fragment_start].0;
            let mut fragment_end = fragment_start + 1;
            while fragment_end < self.reference_order.len()
                && self.reference_order[fragment_end].0 == fragment
            {
                returned_evidence.observe_row(cancellation, &mut work);
                if returned_evidence.cancellation_observed() || cancellation.is_cancelled() {
                    let enumeration = self
                        .coverage
                        .enumeration_completion_with_poll(cancellation, &mut work);
                    returned_evidence.include(&enumeration, cancellation, &mut work);
                    return Ok(returned_evidence.finish(true, cancellation, &mut work).0);
                }
                fragment_end += 1;
            }
            for chunk in
                self.reference_order[fragment_start..fragment_end].chunks(maximum_batch_size)
            {
                returned_evidence.observe_row(cancellation, &mut work);
                if returned_evidence.cancellation_observed() || cancellation.is_cancelled() {
                    let enumeration = self
                        .coverage
                        .enumeration_completion_with_poll(cancellation, &mut work);
                    returned_evidence.include(&enumeration, cancellation, &mut work);
                    return Ok(returned_evidence.finish(true, cancellation, &mut work).0);
                }
                let mut seeds = Vec::with_capacity(chunk.len());
                for &(_, reference, node) in chunk {
                    returned_evidence.observe_row(cancellation, &mut work);
                    if returned_evidence.cancellation_observed() || cancellation.is_cancelled() {
                        let enumeration = self
                            .coverage
                            .enumeration_completion_with_poll(cancellation, &mut work);
                        returned_evidence.include(&enumeration, cancellation, &mut work);
                        return Ok(returned_evidence.finish(true, cancellation, &mut work).0);
                    }
                    let completion = self.coverage.reference_completion_with_poll(
                        reference,
                        cancellation,
                        &mut work,
                    );
                    returned_evidence.include(&completion, cancellation, &mut work);
                    seeds.push(ReferenceSeed::new_with_site_metadata(
                        fragment,
                        ResolutionQuery::new(reference),
                        node,
                        self.reference_metadata.get(&reference).copied(),
                        completion,
                    ));
                }
                if returned_evidence.cancellation_observed() || cancellation.is_cancelled() {
                    let enumeration = self
                        .coverage
                        .enumeration_completion_with_poll(cancellation, &mut work);
                    returned_evidence.include(&enumeration, cancellation, &mut work);
                    return Ok(returned_evidence.finish(true, cancellation, &mut work).0);
                }
                let batch = ReferenceSeedBatch::new_observing(seeds, || {
                    returned_evidence.observe_row(cancellation, &mut work);
                });
                if returned_evidence.cancellation_observed() || cancellation.is_cancelled() {
                    let enumeration = self
                        .coverage
                        .enumeration_completion_with_poll(cancellation, &mut work);
                    returned_evidence.include(&enumeration, cancellation, &mut work);
                    return Ok(returned_evidence.finish(true, cancellation, &mut work).0);
                }
                if !visitor(&batch)? {
                    return Ok(self
                        .coverage
                        .enumeration_completion_with_poll(cancellation, &mut work));
                }
                // The visitor now owns this returned batch's cancellation
                // evidence. Keep only the at-most-one batch currently being
                // constructed in the source.
                returned_evidence = CancellationEvidenceLedger::default();
            }
            fragment_start = fragment_end;
        }
        Ok(self
            .coverage
            .enumeration_completion_with_poll(cancellation, &mut work))
    }

    fn visit_reference_seed_batches_in_fragments(
        &self,
        fragments: &HashSet<BindingFragmentId>,
        maximum_batch_size: usize,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&ReferenceSeedBatch) -> StoreResult<bool>,
    ) -> StoreResult<ResolutionCompletion> {
        assert!((1..=super::batch::MAX_REFERENCE_SEEDS_PER_BATCH).contains(&maximum_batch_size));
        let session = ResolutionSession::unbounded();
        let mut fragments = fragments.iter().copied().collect::<Vec<_>>();
        fragments.sort();
        let mut completion = ResolutionCompletion::Complete;
        for &fragment in &fragments {
            completion = completion.combine(&self.reference_inventory_completion(
                fragment,
                cancellation,
                &session,
            )?);
            if cancellation.is_cancelled() {
                return Ok(completion.combine(&cancelled_completion()));
            }
        }
        for fragment in fragments {
            let start = self.reference_order.partition_point(|row| row.0 < fragment);
            let end = self
                .reference_order
                .partition_point(|row| row.0 <= fragment);
            for chunk in self.reference_order[start..end].chunks(maximum_batch_size) {
                let requests = chunk
                    .iter()
                    .map(|&(_, reference, node)| ReverseReferenceSeedRequest::new(reference, node))
                    .collect::<Vec<_>>();
                let seeds = self.issue_reverse_reference_seeds(&requests, cancellation)?;
                if cancellation.is_cancelled() {
                    return Ok(completion.combine(&cancelled_completion()));
                }
                if !visitor(&ReferenceSeedBatch::new(seeds))? {
                    return Ok(if cancellation.is_cancelled() {
                        completion.combine(&cancelled_completion())
                    } else {
                        completion
                    });
                }
            }
        }
        Ok(if cancellation.is_cancelled() {
            completion.combine(&cancelled_completion())
        } else {
            completion
        })
    }

    fn classify_endpoint_nodes(
        &self,
        nodes: &[BindingNodeId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Vec<super::batch::BatchEndpointClassification>> {
        let mut classified = Vec::with_capacity(nodes.len());
        for (ordinal, node) in nodes.iter().copied().enumerate() {
            if ordinal.is_multiple_of(CANCELLATION_QUANTUM) && cancellation.is_cancelled() {
                break;
            }
            let kind = self.nodes.get(&node).ok_or_else(|| {
                crate::analyzer::store::StoreError::new(format!(
                    "cannot classify unknown preloaded endpoint {node}"
                ))
            })?;
            let (reference, definition) = match kind {
                BindingNodeKind::Reference(semantic) => (Some(*semantic), None),
                BindingNodeKind::Definition(semantic) => (None, Some(*semantic)),
                _ => (None, None),
            };
            classified.push(
                super::batch::BatchEndpointClassification::new_with_member_scope_owner(
                    node,
                    reference,
                    definition,
                    self.member_scope_owners.get(&node).copied(),
                )
                .with_go_definition_namespaces(
                    definition.and_then(|definition| {
                        self.go_definition_namespaces.get(&definition).copied()
                    }),
                ),
            );
        }
        Ok(classified)
    }

    fn match_forward_candidates(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
    ) -> StoreResult<super::batch::BatchCandidateOutcome> {
        let mut matches = BTreeSet::new();
        let mut visited = 0_usize;
        let mut buckets = Vec::new();
        'requests: for request in requests {
            visited += 1;
            if visited.is_multiple_of(CANCELLATION_QUANTUM) && cancellation.is_cancelled() {
                break 'requests;
            }
            let Some(node_index) = self.forward.get(&request.endpoint().node()) else {
                continue;
            };
            buckets.clear();
            node_index.extend_buckets_for(request.endpoint(), &mut buckets);
            while let Some(index) = take_next_candidate_in_identity_order(&self.paths, &mut buckets)
            {
                visited += 1;
                if visited.is_multiple_of(CANCELLATION_QUANTUM) && cancellation.is_cancelled() {
                    break 'requests;
                }
                let stored = &self.paths[index];
                if !endpoint_admits_candidate(request.endpoint(), stored.path.start()) {
                    continue;
                }
                matches.insert(BatchCandidateMatch::new(
                    stored.identity,
                    request.request_ordinal(),
                ));
            }
        }
        let mut canonical_matches = Vec::with_capacity(matches.len());
        while let Some(matched) = matches.pop_first() {
            visited += 1;
            if visited.is_multiple_of(CANCELLATION_QUANTUM) {
                let _ = cancellation.is_cancelled();
            }
            canonical_matches.push(matched);
        }
        let unconditional_completion = self.coverage.candidate_unconditional_completion_with_poll(
            LoweredCandidateDirection::Forward,
            cancellation,
            &mut visited,
        );
        let mut branch_completions = Vec::with_capacity(requests.len());
        for request in requests {
            visited += 1;
            if visited.is_multiple_of(CANCELLATION_QUANTUM) {
                let _ = cancellation.is_cancelled();
            }
            branch_completions.push(self.coverage.candidate_branch_completion_with_poll(
                LoweredCandidateDirection::Forward,
                request.endpoint(),
                cancellation,
                &mut visited,
            ));
        }
        Ok(super::batch::BatchCandidateOutcome::new_observing(
            requests.len(),
            canonical_matches,
            unconditional_completion,
            branch_completions,
            || {
                visited += 1;
                if visited.is_multiple_of(CANCELLATION_QUANTUM) {
                    let _ = cancellation.is_cancelled();
                }
            },
        ))
    }

    fn match_reverse_candidates(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
    ) -> StoreResult<super::batch::BatchCandidateOutcome> {
        let mut matches = BTreeSet::new();
        let mut visited = 0_usize;
        let mut buckets = Vec::new();
        'requests: for request in requests {
            visited += 1;
            if visited.is_multiple_of(CANCELLATION_QUANTUM) && cancellation.is_cancelled() {
                break 'requests;
            }
            let Some(node_index) = self.reverse.get(&request.endpoint().node()) else {
                continue;
            };
            buckets.clear();
            node_index.extend_buckets_for(request.endpoint(), &mut buckets);
            while let Some(index) = take_next_candidate_in_identity_order(&self.paths, &mut buckets)
            {
                visited += 1;
                if visited.is_multiple_of(CANCELLATION_QUANTUM) && cancellation.is_cancelled() {
                    break 'requests;
                }
                let stored = &self.paths[index];
                if !endpoint_admits_candidate(request.endpoint(), stored.path.end()) {
                    continue;
                }
                matches.insert(BatchCandidateMatch::new(
                    stored.identity,
                    request.request_ordinal(),
                ));
            }
        }
        let mut canonical_matches = Vec::with_capacity(matches.len());
        while let Some(matched) = matches.pop_first() {
            visited += 1;
            if visited.is_multiple_of(CANCELLATION_QUANTUM) {
                let _ = cancellation.is_cancelled();
            }
            canonical_matches.push(matched);
        }
        let unconditional_completion = self.coverage.candidate_unconditional_completion_with_poll(
            LoweredCandidateDirection::Reverse,
            cancellation,
            &mut visited,
        );
        let mut branch_completions = Vec::with_capacity(requests.len());
        for request in requests {
            visited += 1;
            if visited.is_multiple_of(CANCELLATION_QUANTUM) {
                let _ = cancellation.is_cancelled();
            }
            branch_completions.push(self.coverage.candidate_branch_completion_with_poll(
                LoweredCandidateDirection::Reverse,
                request.endpoint(),
                cancellation,
                &mut visited,
            ));
        }
        Ok(super::batch::BatchCandidateOutcome::new_observing(
            requests.len(),
            canonical_matches,
            unconditional_completion,
            branch_completions,
            || {
                visited += 1;
                if visited.is_multiple_of(CANCELLATION_QUANTUM) {
                    let _ = cancellation.is_cancelled();
                }
            },
        ))
    }

    fn visit_forward_candidate_match_pages(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        self.visit_forward_candidate_match_pages_limited(
            requests,
            MAX_SOURCE_ROWS_PER_BATCH,
            None,
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
        let mut work = 0_usize;
        self.visit_candidate_match_pages_from_index_limited(
            &self.forward,
            PartialPath::start,
            requests,
            maximum_page_rows,
            resolution_session,
            cancellation,
            &mut work,
            visitor,
        )?;
        if cancellation.is_cancelled() {
            return Ok(BatchCandidateCompletionOutcome::new(
                requests.len(),
                cancelled_completion(),
                std::iter::repeat_n(ResolutionCompletion::Complete, requests.len()),
            ));
        }
        let unconditional_completion = self.coverage.candidate_unconditional_completion_with_poll(
            LoweredCandidateDirection::Forward,
            cancellation,
            &mut work,
        );
        let mut branch_completions = Vec::with_capacity(requests.len());
        for request in requests {
            if resolution_session.is_some_and(|session| !session.scope_step()) {
                return Ok(BatchCandidateCompletionOutcome::new(
                    requests.len(),
                    cancelled_completion(),
                    std::iter::repeat_n(ResolutionCompletion::Complete, requests.len()),
                ));
            }
            work = work
                .checked_add(1)
                .expect("forward candidate coverage work must fit usize");
            if work.is_multiple_of(CANCELLATION_QUANTUM) {
                let _ = cancellation.is_cancelled();
            }
            branch_completions.push(self.coverage.candidate_branch_completion_with_poll(
                LoweredCandidateDirection::Forward,
                request.endpoint(),
                cancellation,
                &mut work,
            ));
        }
        Ok(BatchCandidateCompletionOutcome::new_observing(
            requests.len(),
            unconditional_completion,
            branch_completions,
            || {
                work = work
                    .checked_add(1)
                    .expect("forward candidate completion work must fit usize");
                if work.is_multiple_of(CANCELLATION_QUANTUM) {
                    let _ = cancellation.is_cancelled();
                }
            },
        ))
    }

    fn visit_reverse_candidate_match_pages(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        let mut work = 0_usize;
        self.visit_candidate_match_pages_from_index(
            &self.reverse,
            PartialPath::end,
            requests,
            cancellation,
            &mut work,
            visitor,
        )?;
        let unconditional_completion = self.coverage.candidate_unconditional_completion_with_poll(
            LoweredCandidateDirection::Reverse,
            cancellation,
            &mut work,
        );
        let mut branch_completions = Vec::with_capacity(requests.len());
        for request in requests {
            work = work
                .checked_add(1)
                .expect("reverse candidate coverage work must fit usize");
            if work.is_multiple_of(CANCELLATION_QUANTUM) {
                let _ = cancellation.is_cancelled();
            }
            branch_completions.push(self.coverage.candidate_branch_completion_with_poll(
                LoweredCandidateDirection::Reverse,
                request.endpoint(),
                cancellation,
                &mut work,
            ));
        }
        Ok(BatchCandidateCompletionOutcome::new_observing(
            requests.len(),
            unconditional_completion,
            branch_completions,
            || {
                work = work
                    .checked_add(1)
                    .expect("reverse candidate completion work must fit usize");
                if work.is_multiple_of(CANCELLATION_QUANTUM) {
                    let _ = cancellation.is_cancelled();
                }
            },
        ))
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
        assert!(
            requests.len() <= MAX_SOURCE_ROWS_PER_BATCH,
            "candidate request page has {} entries; maximum is {MAX_SOURCE_ROWS_PER_BATCH}",
            requests.len()
        );
        for (request_ordinal, request) in requests.iter().enumerate() {
            assert_eq!(
                request.request_ordinal(),
                request_ordinal,
                "preloaded candidate requests must use canonical local ordinals"
            );
        }

        let prepared = self
            .coverage
            .reverse_candidate_gaps
            .prepare_exclusions(exclusions, cancellation)?;
        let mut work = 0_usize;
        if !prepared {
            return self
                .coverage
                .reverse_candidate_completion_outcome(requests, None, cancellation, &mut work)
                .map(|(outcome, _)| outcome);
        }
        let (mut completion, cancellation_observed) =
            self.coverage.reverse_candidate_completion_outcome(
                requests,
                Some(exclusions),
                cancellation,
                &mut work,
            )?;
        if cancellation_observed {
            return Ok(completion);
        }
        self.visit_candidate_match_pages_from_index(
            &self.reverse,
            PartialPath::end,
            requests,
            cancellation,
            &mut work,
            visitor,
        )?;
        if cancellation.is_cancelled() {
            completion =
                include_preloaded_candidate_cancellation(completion, cancellation, &mut work);
        }
        Ok(completion)
    }

    fn hydrate_candidate_paths(
        &self,
        candidates: &[CandidatePathIdentity],
        cancellation: &CancellationToken,
    ) -> StoreResult<Vec<(CandidatePathIdentity, PartialPath)>> {
        let mut hydrated = Vec::with_capacity(candidates.len());
        let mut work = 0_usize;
        for (ordinal, candidate) in candidates.iter().copied().enumerate() {
            if (ordinal + 1).is_multiple_of(CANCELLATION_QUANTUM) && cancellation.is_cancelled() {
                break;
            }
            if let Some(&index) = self.path_positions.get(&candidate) {
                let mut clone_cancelled = false;
                let Some(path) = self.paths[index].path.clone_with_poll(&mut || {
                    work += 1;
                    if work.is_multiple_of(CANCELLATION_QUANTUM) && cancellation.is_cancelled() {
                        clone_cancelled = true;
                    }
                    false
                }) else {
                    unreachable!("the observational hydration poll always returns false")
                };
                hydrated.push((candidate, path));
                if clone_cancelled {
                    break;
                }
            }
        }
        Ok(hydrated)
    }

    fn visit_type_transfer_rules(
        &self,
        source_slot: SemanticId,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&TypeTransferRule) -> StoreResult<bool>,
    ) -> StoreResult<ResolutionCompletion> {
        let Some(rules) = self.type_transfer_rules.get(&source_slot) else {
            let completion = self.coverage.type_completion(source_slot);
            return Ok(if cancellation.is_cancelled() {
                completion.combine(&cancelled_completion())
            } else {
                completion
            });
        };
        let coverage_completion = self.coverage.type_completion(source_slot);
        let cancellation_completion = || {
            rules
                .iter()
                .fold(coverage_completion.clone(), |completion, rule| {
                    completion.combine(rule.completion())
                })
                .combine(&cancelled_completion())
        };
        for (ordinal, rule) in rules.iter().enumerate() {
            if ordinal.is_multiple_of(CANCELLATION_QUANTUM) && cancellation.is_cancelled() {
                return Ok(cancellation_completion());
            }
            if !visitor(rule)? {
                break;
            }
        }
        Ok(if cancellation.is_cancelled() {
            cancellation_completion()
        } else {
            coverage_completion
        })
    }
}

#[derive(Debug, Clone)]
struct WorkPath {
    path: PartialPath,
    saturation: SaturationBranch,
}

#[derive(Debug, Default)]
struct WorkClock {
    compositions: usize,
}

impl WorkClock {
    fn cancelled_after_composition(&mut self, cancellation: &CancellationToken) -> bool {
        self.compositions += 1;
        self.compositions.is_multiple_of(CANCELLATION_QUANTUM) && cancellation.is_cancelled()
    }
}

/// Single-query compatibility stitcher.
///
/// This readable implementation remains the preload law oracle while consumers
/// migrate to [`super::batch::BatchResolutionEngine`]. Persistent sources do
/// not implement this visitor contract: their point, reverse, broad, and typed
/// operations use the bounded batch seam directly.
pub struct ResolutionEngine<'a, S: ResolutionFragmentSource + ?Sized> {
    source: &'a S,
}

impl<'a, S: ResolutionFragmentSource + ?Sized> ResolutionEngine<'a, S> {
    pub const fn new(source: &'a S) -> Self {
        Self { source }
    }

    pub fn resolve_reference(
        &self,
        query: ResolutionQuery,
        cancellation: &CancellationToken,
    ) -> StoreResult<ResolutionAnswer> {
        let (completed, terminals, completion) = self.resolve_paths(query, cancellation)?;
        Ok(select_paths(
            query.reference,
            completed,
            terminals,
            completion,
            cancellation,
        ))
    }

    /// Advance one typed frontier through immutable file-local copy rules.
    ///
    /// Concrete output values are derived from the incoming operation state;
    /// they are never supplied by the fact source. Rule collection and value
    /// application are atomic with respect to cancellation, so a caller never
    /// observes a prefix as a complete set of alternatives.
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
            self.source
                .visit_type_transfer_rules(state.slot(), &mut |rule| {
                    visited += 1;
                    if visited.is_multiple_of(CANCELLATION_QUANTUM) && cancellation.is_cancelled() {
                        return Ok(false);
                    }
                    rules.push(rule.clone());
                    Ok(true)
                })?;
        apply_type_transfer_rules(state, rules, source_completion, cancellation)
    }

    /// Reverse stitching only generates candidates. Each candidate is then
    /// resolved forward once, including cross-target shadow comparison.
    pub fn references_to(
        &self,
        definition: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<ReferenceSearchAnswer> {
        let (candidate_references, mut completion) =
            self.reverse_candidate_references(definition, cancellation)?;
        let mut references = Vec::new();
        let mut witnesses = Vec::new();

        for reference in candidate_references {
            if cancellation.is_cancelled() {
                completion = completion.combine(&cancelled_completion());
                break;
            }
            let answer = self.resolve_reference(ResolutionQuery::new(reference), cancellation)?;
            completion = completion.combine(answer.completion());
            if answer.targets().contains(&definition) {
                references.push(reference);
                witnesses.extend(
                    answer
                        .witnesses()
                        .iter()
                        .filter(|witness| witness.target() == definition)
                        .cloned(),
                );
            }
        }
        if cancellation.is_cancelled() {
            completion = completion.combine(&cancelled_completion());
        }

        references.sort_unstable();
        references.dedup();
        witnesses.sort_unstable();
        witnesses.dedup();
        if cancellation.is_cancelled() {
            completion = completion.combine(&cancelled_completion());
        }
        Ok(ReferenceSearchAnswer::new(
            references, witnesses, completion,
        ))
    }

    /// Resolve each selected reference once and stream canonical edge groups.
    /// No completed workspace graph is retained by this operation.
    pub fn stream_all_references(
        &self,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(SemanticId, SemanticId, &[ResolutionWitness]),
    ) -> StoreResult<ResolutionCompletion> {
        if cancellation.is_cancelled() {
            return Ok(cancelled_completion());
        }
        let mut completion = ResolutionCompletion::Complete;
        self.source.visit_references(&mut |reference, _| {
            if cancellation.is_cancelled() {
                completion = completion.combine(&cancelled_completion());
                return Ok(false);
            }
            let answer = self.resolve_reference(ResolutionQuery::new(reference), cancellation)?;
            completion = completion.combine(answer.completion());
            for &target in answer.targets() {
                let target_witnesses = answer
                    .witnesses()
                    .iter()
                    .filter(|witness| witness.target() == target)
                    .cloned()
                    .collect::<Vec<_>>();
                visitor(reference, target, &target_witnesses);
            }
            Ok(true)
        })?;
        if cancellation.is_cancelled() {
            completion = completion.combine(&cancelled_completion());
        }
        Ok(completion)
    }

    fn resolve_paths(
        &self,
        query: ResolutionQuery,
        cancellation: &CancellationToken,
    ) -> StoreResult<(
        Vec<CompletedPath>,
        Vec<IncompleteTerminalPath>,
        ResolutionCompletion,
    )> {
        if cancellation.is_cancelled() {
            return Ok((Vec::new(), Vec::new(), cancelled_completion()));
        }
        let Some(reference_node) = self.source.reference_node(query.reference)? else {
            return Ok((
                Vec::new(),
                Vec::new(),
                ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(query.reference),
                ]),
            ));
        };

        let go_spelling_namespace = self.source.go_spelling_namespace(query.reference)?;
        let go_package_qualifier = self.source.go_package_qualifier(query.reference)?;
        let seed = identity_path(reference_node);
        let mut observed_completion = seed.completion().clone();
        let mut certifier = CycleCompletenessCertifier::new(&seed);
        let mut queue = VecDeque::from([WorkPath {
            path: seed,
            saturation: SaturationBranch::default(),
        }]);
        let mut completed = Vec::new();
        let mut terminals = Vec::new();
        let mut completion = ResolutionCompletion::Complete;
        let mut clock = WorkClock::default();
        let mut cancelled = false;

        while let Some(state) = queue.pop_front() {
            if let Some(target) = self.complete_definition(&state.path)? {
                let namespaces = self.source.go_definition_namespaces(target)?;
                match classify_completed_binding(
                    go_spelling_namespace,
                    go_package_qualifier,
                    namespaces,
                    target,
                    state.path,
                ) {
                    CompletedBinding::Complete(candidate) => completed.push(candidate),
                    CompletedBinding::Incomplete(terminal) => terminals.push(terminal),
                }
                continue;
            }

            let mut has_successor = false;
            self.source
                .visit_forward_candidates(state.path.end(), &mut |path_id, candidate| {
                    if clock.cancelled_after_composition(cancellation) {
                        cancelled = true;
                        return Ok(false);
                    }
                    let Ok(path) = state.path.concatenate(candidate) else {
                        return Ok(true);
                    };
                    let path = path.canonicalized_observations();
                    observed_completion = observed_completion.combine(path.completion());
                    match certifier.admit(&state.saturation, path_id, &path) {
                        SaturationDecision::Expand(saturation) => {
                            has_successor = true;
                            queue.push_back(WorkPath { path, saturation });
                        }
                        SaturationDecision::Subsumed => {
                            has_successor = true;
                        }
                        SaturationDecision::Uncertified(gap) => {
                            has_successor = true;
                            terminals.push(IncompleteTerminalPath::new(
                                path.with_additional_completion(&ResolutionCompletion::incomplete(
                                    [ResolutionIncompleteReason::CyclicExpansion(
                                        gap.transition(),
                                    )],
                                )),
                            ));
                        }
                    }
                    Ok(true)
                })?;
            if cancelled {
                completion = completion
                    .combine(&observed_completion)
                    .combine(&cancelled_completion());
                break;
            }
            if !has_successor
                && matches!(state.path.completion(), ResolutionCompletion::Incomplete(_))
            {
                terminals.push(IncompleteTerminalPath::new(state.path));
            }
        }
        if cancellation.is_cancelled() {
            completion = completion
                .combine(&observed_completion)
                .combine(&cancelled_completion());
        }
        Ok((completed, terminals, completion))
    }

    fn reverse_candidate_references(
        &self,
        definition: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<(Vec<SemanticId>, ResolutionCompletion)> {
        if cancellation.is_cancelled() {
            return Ok((Vec::new(), cancelled_completion()));
        }
        let Some(definition_node) = self.source.definition_node(definition)? else {
            return Ok((
                Vec::new(),
                ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(definition),
                ]),
            ));
        };

        let seed = identity_path(definition_node);
        let mut certifier = CycleCompletenessCertifier::new(&seed);
        let mut queue = VecDeque::from([WorkPath {
            path: seed,
            saturation: SaturationBranch::default(),
        }]);
        let mut references = Vec::new();
        let mut completion = ResolutionCompletion::Complete;
        let mut clock = WorkClock::default();
        let mut cancelled = false;

        while let Some(state) = queue.pop_front() {
            completion = completion.combine(state.path.completion());
            if endpoint_is_balanced(state.path.start())
                && let Some(reference) =
                    self.source.reference_semantic(state.path.start().node())?
            {
                references.push(reference);
                continue;
            }

            self.source.visit_reverse_candidates(
                state.path.start(),
                &mut |path_id, candidate| {
                    if clock.cancelled_after_composition(cancellation) {
                        cancelled = true;
                        return Ok(false);
                    }
                    let Ok(path) = candidate.concatenate(&state.path) else {
                        return Ok(true);
                    };
                    let path = path.canonicalized_observations();
                    completion = completion.combine(path.completion());
                    match certifier.admit(&state.saturation, path_id, &path) {
                        SaturationDecision::Expand(saturation) => {
                            queue.push_back(WorkPath { path, saturation });
                        }
                        SaturationDecision::Subsumed => {}
                        SaturationDecision::Uncertified(gap) => {
                            completion = completion.combine(&ResolutionCompletion::incomplete([
                                ResolutionIncompleteReason::CyclicExpansion(gap.transition()),
                            ]));
                        }
                    }
                    Ok(true)
                },
            )?;
            if cancelled {
                completion = completion.combine(&cancelled_completion());
                break;
            }
        }
        if cancellation.is_cancelled() {
            completion = completion.combine(&cancelled_completion());
        }

        references.sort_unstable();
        references.dedup();
        Ok((references, completion))
    }

    fn complete_definition(&self, path: &PartialPath) -> StoreResult<Option<SemanticId>> {
        if endpoint_is_balanced(path.end()) {
            self.source.definition_semantic(path.end().node())
        } else {
            Ok(None)
        }
    }
}

#[derive(Debug)]
pub(super) struct CompletedPath {
    pub(super) target: SemanticId,
    pub(super) admission: BindingCandidateAdmission,
    pub(super) path: PartialPath,
}

/// Binding classification has two domain outcomes, each retaining its path.
#[derive(Debug)]
pub(super) enum CompletedBinding {
    Complete(CompletedPath),
    Incomplete(IncompleteTerminalPath),
}

/// Missing Go namespace authority is uncertainty, never an affirmative blocker.
pub(super) fn classify_completed_binding(
    requested: Option<ResolutionNamespace>,
    package_qualifier: bool,
    namespaces: Option<GoDefinitionNamespaces>,
    target: SemanticId,
    path: PartialPath,
) -> CompletedBinding {
    assert!(!package_qualifier || requested == Some(ResolutionNamespace::TypeOrValue));
    let admission = match requested {
        None => BindingCandidateAdmission::Target,
        Some(requested) => match namespaces {
            Some(namespaces) if namespaces.admits(requested, package_qualifier) => {
                BindingCandidateAdmission::Target
            }
            Some(_) => BindingCandidateAdmission::WrongNamespaceBlocker,
            None => {
                return CompletedBinding::Incomplete(IncompleteTerminalPath::new(
                    path.with_additional_completion(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(target),
                    ])),
                ));
            }
        },
    };
    CompletedBinding::Complete(CompletedPath {
        target,
        admission,
        path,
    })
}

/// One semantically possible branch whose target cannot be enumerated.
///
/// The retained path carries the same normalized choice trace as affirmative
/// paths. Final selection may therefore discharge this evidence only when an
/// affirmative maximum strictly wins the same semantic choice.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct IncompleteTerminalPath {
    path: PartialPath,
}

impl IncompleteTerminalPath {
    pub(super) fn new(path: PartialPath) -> Self {
        assert!(
            matches!(path.completion(), ResolutionCompletion::Incomplete(_)),
            "a terminal path must carry explicit incomplete evidence"
        );
        Self { path }
    }

    pub(super) fn path(&self) -> &PartialPath {
        &self.path
    }
}

pub(super) fn identity_path(node: BindingNodeId) -> PartialPath {
    let endpoint = EndpointSignature::new(
        node,
        StackPattern::closed(Vec::new()),
        StackPattern::closed(Vec::new()),
    );
    PartialPath::new(
        endpoint.clone(),
        endpoint,
        Vec::new(),
        [WitnessStep::Node(node)],
        ResolutionCompletion::Complete,
    )
}

pub(super) fn endpoint_is_balanced(endpoint: &EndpointSignature) -> bool {
    endpoint.symbols().fixed().is_empty()
        && endpoint.symbols().tail().is_none()
        && endpoint.scopes().fixed().is_empty()
        && endpoint.scopes().tail().is_none()
}

pub(super) fn apply_type_transfer_rules(
    state: &TypedFrontierState,
    mut rules: Vec<TypeTransferRule>,
    source_completion: ResolutionCompletion,
    cancellation: &CancellationToken,
) -> StoreResult<(Vec<TypedFrontierState>, ResolutionCompletion)> {
    rules.sort_unstable();
    for duplicate in rules
        .windows(2)
        .filter(|pair| pair[0].semantic() == pair[1].semantic())
    {
        if duplicate[0] != duplicate[1] {
            return Err(StoreError::new(format!(
                "type-transfer semantic {} names conflicting rules: {:?}",
                duplicate[0].semantic(),
                duplicate
            )));
        }
    }
    rules.dedup();

    let base_completion = state.completion().combine(&source_completion);
    let mut completion = rules
        .iter()
        .fold(base_completion.clone(), |completion, rule| {
            completion.combine(rule.completion())
        });
    if cancellation.is_cancelled() {
        return Ok((Vec::new(), completion.combine(&cancelled_completion())));
    }

    let mut alternatives = Vec::with_capacity(rules.len());
    let mut work = 0_usize;
    for rule in rules {
        work += 1;
        if work.is_multiple_of(CANCELLATION_QUANTUM) && cancellation.is_cancelled() {
            return Ok((Vec::new(), completion.combine(&cancelled_completion())));
        }

        let mut values = Vec::with_capacity(state.possible_values().len());
        let mut adjustment_failed = false;
        for value in state.possible_values().iter().copied() {
            work += 1;
            if work.is_multiple_of(CANCELLATION_QUANTUM) && cancellation.is_cancelled() {
                return Ok((Vec::new(), completion.combine(&cancelled_completion())));
            }
            match rule.apply(value) {
                TypeTransferApplication::Value(value) => values.push(value),
                TypeTransferApplication::NoValue => {}
                TypeTransferApplication::IndirectionOutOfRange => adjustment_failed = true,
            }
        }

        let mut rule_completion = base_completion.combine(rule.completion());
        if adjustment_failed {
            rule_completion = rule_completion.combine(&ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(rule.semantic()),
            ]));
        }
        completion = completion.combine(&rule_completion);
        alternatives.push(TypedFrontierState::new(
            rule.target_slot(),
            values,
            rule_completion,
        ));
    }
    if cancellation.is_cancelled() {
        return Ok((Vec::new(), completion.combine(&cancelled_completion())));
    }
    alternatives.sort_unstable_by(|left, right| {
        left.slot()
            .cmp(&right.slot())
            .then_with(|| left.possible_values().cmp(right.possible_values()))
            .then_with(|| left.completion().cmp(right.completion()))
    });
    alternatives.dedup();
    Ok((alternatives, completion))
}

pub(super) fn cancelled_completion() -> ResolutionCompletion {
    ResolutionCompletion::incomplete([ResolutionIncompleteReason::Cancelled])
}

pub(super) fn select_paths(
    reference: SemanticId,
    completed: Vec<CompletedPath>,
    terminals: Vec<IncompleteTerminalPath>,
    unconditional_completion: ResolutionCompletion,
    cancellation: &CancellationToken,
) -> ResolutionAnswer {
    select_paths_with_cancellation_evidence(
        reference,
        completed,
        terminals,
        unconditional_completion,
        ResolutionCompletion::Complete,
        cancellation,
    )
}

struct CompletedPathDominance {
    dominance: Vec<Vec<usize>>,
    indegree: Vec<usize>,
    visited: usize,
}

fn completed_path_dominance_with_poll(
    completed: &[CompletedPath],
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<CompletedPathDominance> {
    let mut dominance = empty_adjacency_with_poll(completed.len(), cancellation, work)?;
    let mut indegree = zero_usize_with_poll(completed.len(), cancellation, work)?;
    for left in 0..completed.len() {
        for right in (left + 1)..completed.len() {
            if selection_cancelled(work, cancellation) {
                return None;
            }
            if path_shadows_with_poll(
                &completed[left].path,
                &completed[right].path,
                cancellation,
                work,
            )? {
                dominance[left].push(right);
                indegree[right] += 1;
            }
            if path_shadows_with_poll(
                &completed[right].path,
                &completed[left].path,
                cancellation,
                work,
            )? {
                dominance[right].push(left);
                indegree[left] += 1;
            }
        }
    }

    let mut visited = 0_usize;
    let mut remaining_indegree = clone_usize_with_poll(&indegree, cancellation, work)?;
    let mut ready = VecDeque::new();
    for (index, &degree) in remaining_indegree.iter().enumerate() {
        if selection_cancelled(work, cancellation) {
            return None;
        }
        if degree == 0 {
            ready.push_back(index);
        }
    }
    while let Some(left) = ready.pop_front() {
        if selection_cancelled(work, cancellation) {
            return None;
        }
        visited += 1;
        for &right in &dominance[left] {
            if selection_cancelled(work, cancellation) {
                return None;
            }
            remaining_indegree[right] -= 1;
            if remaining_indegree[right] == 0 {
                ready.push_back(right);
            }
        }
    }
    if cancellation.is_cancelled() {
        return None;
    }
    Some(CompletedPathDominance {
        dominance,
        indegree,
        visited,
    })
}

/// Select one exact answer while retaining traversal-only evidence solely for
/// the cancellation fallback.
///
/// The conservative snapshot is materialized before dominance analysis. Once
/// that snapshot exists, every cancellation edge returns it with the complete
/// observed reason union plus `Cancelled`; an uncancelled result never sees
/// `cancellation_evidence`.
pub(super) fn select_paths_with_cancellation_evidence(
    reference: SemanticId,
    completed: Vec<CompletedPath>,
    terminals: Vec<IncompleteTerminalPath>,
    unconditional_completion: ResolutionCompletion,
    cancellation_evidence: ResolutionCompletion,
    cancellation: &CancellationToken,
) -> ResolutionAnswer {
    let mut work = 0_usize;
    let mut selection_completion = BatchCompletionLedger::default();
    let mut cancelled =
        selection_completion.include(&unconditional_completion, cancellation, &mut work);
    let (conservative, cancelled_during_publication) = build_conservative_answer(
        reference,
        &completed,
        &terminals,
        &unconditional_completion,
        cancellation,
        &mut work,
    );
    cancelled |= cancelled_during_publication;
    match completion_contains_cancelled_with_poll(&cancellation_evidence, cancellation, &mut work) {
        Some(has_cancelled) => cancelled |= has_cancelled,
        None => cancelled = true,
    }
    cancelled |= cancellation.is_cancelled();
    if cancelled {
        return cancelled_selection_from_ledger(
            conservative,
            selection_completion,
            &cancellation_evidence,
            cancellation,
            &mut work,
        );
    }

    let Some(CompletedPathDominance {
        dominance,
        indegree,
        visited,
    }) = completed_path_dominance_with_poll(&completed, cancellation, &mut work)
    else {
        return cancelled_selection_from_ledger(
            conservative,
            selection_completion,
            &cancellation_evidence,
            cancellation,
            &mut work,
        );
    };

    let mut precedence_consistent = false;
    let mut shadowed = if visited == completed.len() {
        let Some(maxima) = zero_indegree_indices_with_poll(&indegree, cancellation, &mut work)
        else {
            return cancelled_selection_from_ledger(
                conservative,
                selection_completion,
                &cancellation_evidence,
                cancellation,
                &mut work,
            );
        };
        let Some(mut shadowed) = directly_shadowed_with_poll(
            completed.len(),
            &maxima,
            &dominance,
            cancellation,
            &mut work,
        ) else {
            return cancelled_selection_from_ledger(
                conservative,
                selection_completion,
                &cancellation_evidence,
                cancellation,
                &mut work,
            );
        };
        let Some(nontransitive) =
            has_nontransitive_edge_with_poll(&indegree, &shadowed, cancellation, &mut work)
        else {
            return cancelled_selection_from_ledger(
                conservative,
                selection_completion,
                &cancellation_evidence,
                cancellation,
                &mut work,
            );
        };
        if nontransitive {
            let Some(reset) = false_vector_with_poll(completed.len(), cancellation, &mut work)
            else {
                return cancelled_selection_from_ledger(
                    conservative,
                    selection_completion,
                    &cancellation_evidence,
                    cancellation,
                    &mut work,
                );
            };
            shadowed = reset;
            selection_completion.include_reason(
                ResolutionIncompleteReason::InconsistentPrecedence(reference),
            );
        } else {
            precedence_consistent = true;
        }
        shadowed
    } else {
        selection_completion.include_reason(ResolutionIncompleteReason::InconsistentPrecedence(
            reference,
        ));
        let Some(shadowed) = false_vector_with_poll(completed.len(), cancellation, &mut work)
        else {
            return cancelled_selection_from_ledger(
                conservative,
                selection_completion,
                &cancellation_evidence,
                cancellation,
                &mut work,
            );
        };
        shadowed
    };
    if !precedence_consistent && !terminals.is_empty() {
        // Once an uncertain branch joins an already malformed affirmative
        // order, none of that order's direct loser eliminations are proven.
        let Some(reset) = false_vector_with_poll(completed.len(), cancellation, &mut work) else {
            return cancelled_selection_from_ledger(
                conservative,
                selection_completion,
                &cancellation_evidence,
                cancellation,
                &mut work,
            );
        };
        shadowed = reset;
    }

    // Validate the order that would exist if every terminal materialized as a
    // candidate. This catches cross-maximum, losing-affirmative, and
    // terminal-terminal cycles instead of proving a negative from one
    // favorable pair in an otherwise malformed relation. Terminals still
    // never eliminate affirmative targets.
    let Some(mut terminal_discharged) =
        false_vector_with_poll(terminals.len(), cancellation, &mut work)
    else {
        return cancelled_selection_from_ledger(
            conservative,
            selection_completion,
            &cancellation_evidence,
            cancellation,
            &mut work,
        );
    };
    let mut lookup_decision = None;
    if precedence_consistent && !terminals.is_empty() {
        let affirmative_count = completed.len();
        let total = affirmative_count
            .checked_add(terminals.len())
            .expect("selected path count must fit usize");
        let path = |index: usize| {
            if index < affirmative_count {
                &completed[index].path
            } else {
                terminals[index - affirmative_count].path()
            }
        };
        let Some(mut augmented_dominance) =
            empty_adjacency_with_poll(total, cancellation, &mut work)
        else {
            return cancelled_selection_from_ledger(
                conservative,
                selection_completion,
                &cancellation_evidence,
                cancellation,
                &mut work,
            );
        };
        let Some(mut augmented_indegree) = zero_usize_with_poll(total, cancellation, &mut work)
        else {
            return cancelled_selection_from_ledger(
                conservative,
                selection_completion,
                &cancellation_evidence,
                cancellation,
                &mut work,
            );
        };
        'augmented_pairs: for left in 0..total {
            for right in (left + 1)..total {
                if selection_cancelled(&mut work, cancellation) {
                    cancelled = true;
                    break 'augmented_pairs;
                }
                let Some(left_shadows) =
                    path_shadows_with_poll(path(left), path(right), cancellation, &mut work)
                else {
                    cancelled = true;
                    break 'augmented_pairs;
                };
                if left_shadows {
                    augmented_dominance[left].push(right);
                    augmented_indegree[right] += 1;
                }
                let Some(right_shadows) =
                    path_shadows_with_poll(path(right), path(left), cancellation, &mut work)
                else {
                    cancelled = true;
                    break 'augmented_pairs;
                };
                if right_shadows {
                    augmented_dominance[right].push(left);
                    augmented_indegree[left] += 1;
                }
            }
        }

        let mut augmented_visited = 0_usize;
        if !cancelled {
            let Some(mut remaining_indegree) =
                clone_usize_with_poll(&augmented_indegree, cancellation, &mut work)
            else {
                return cancelled_selection_from_ledger(
                    conservative,
                    selection_completion,
                    &cancellation_evidence,
                    cancellation,
                    &mut work,
                );
            };
            let mut ready = VecDeque::new();
            for (index, &degree) in remaining_indegree.iter().enumerate() {
                if selection_cancelled(&mut work, cancellation) {
                    cancelled = true;
                    break;
                }
                if degree == 0 {
                    ready.push_back(index);
                }
            }
            'augmented_topology: while let Some(left) = ready.pop_front() {
                if selection_cancelled(&mut work, cancellation) {
                    cancelled = true;
                    break;
                }
                augmented_visited += 1;
                for &right in &augmented_dominance[left] {
                    if selection_cancelled(&mut work, cancellation) {
                        cancelled = true;
                        break 'augmented_topology;
                    }
                    remaining_indegree[right] -= 1;
                    if remaining_indegree[right] == 0 {
                        ready.push_back(right);
                    }
                }
            }
        }

        if !cancelled && augmented_visited == total {
            let Some(augmented_maxima) =
                zero_indegree_indices_with_poll(&augmented_indegree, cancellation, &mut work)
            else {
                return cancelled_selection_from_ledger(
                    conservative,
                    selection_completion,
                    &cancellation_evidence,
                    cancellation,
                    &mut work,
                );
            };
            let Some(directly_shadowed) = directly_shadowed_with_poll(
                total,
                &augmented_maxima,
                &augmented_dominance,
                cancellation,
                &mut work,
            ) else {
                return cancelled_selection_from_ledger(
                    conservative,
                    selection_completion,
                    &cancellation_evidence,
                    cancellation,
                    &mut work,
                );
            };
            let Some(nontransitive) = has_nontransitive_edge_with_poll(
                &augmented_indegree,
                &directly_shadowed,
                cancellation,
                &mut work,
            ) else {
                return cancelled_selection_from_ledger(
                    conservative,
                    selection_completion,
                    &cancellation_evidence,
                    cancellation,
                    &mut work,
                );
            };
            if nontransitive {
                let Some(reset) = false_vector_with_poll(completed.len(), cancellation, &mut work)
                else {
                    return cancelled_selection_from_ledger(
                        conservative,
                        selection_completion,
                        &cancellation_evidence,
                        cancellation,
                        &mut work,
                    );
                };
                shadowed = reset;
                selection_completion.include_reason(
                    ResolutionIncompleteReason::InconsistentPrecedence(reference),
                );
            } else {
                for (terminal_index, is_discharged) in terminal_discharged.iter_mut().enumerate() {
                    if selection_cancelled(&mut work, cancellation) {
                        cancelled = true;
                        break;
                    }
                    let index = affirmative_count + terminal_index;
                    for &maximum in &augmented_maxima {
                        if selection_cancelled(&mut work, cancellation) {
                            cancelled = true;
                            break;
                        }
                        if maximum < affirmative_count {
                            let Some(contains) = contains_index_with_poll(
                                &augmented_dominance[maximum],
                                index,
                                cancellation,
                                &mut work,
                            ) else {
                                cancelled = true;
                                break;
                            };
                            if contains {
                                *is_discharged = true;
                                break;
                            }
                        }
                    }
                    if cancelled {
                        break;
                    }
                }
                if !cancelled
                    && unconditional_completion == ResolutionCompletion::Complete
                    && completed.iter().all(|candidate| {
                        candidate.admission == BindingCandidateAdmission::Target
                            && candidate.path.completion() == &ResolutionCompletion::Complete
                    })
                    && terminal_discharged.iter().any(|discharged| !discharged)
                {
                    lookup_decision = ordered_lookup_alternatives(
                        &completed,
                        &terminals,
                        &augmented_indegree,
                        cancellation,
                        &mut work,
                    );
                }
            }
        } else if !cancelled {
            let Some(reset) = false_vector_with_poll(completed.len(), cancellation, &mut work)
            else {
                return cancelled_selection_from_ledger(
                    conservative,
                    selection_completion,
                    &cancellation_evidence,
                    cancellation,
                    &mut work,
                );
            };
            shadowed = reset;
            selection_completion.include_reason(
                ResolutionIncompleteReason::InconsistentPrecedence(reference),
            );
        }
    }
    cancelled |= cancellation.is_cancelled();
    if cancelled {
        return cancelled_selection_from_ledger(
            conservative,
            selection_completion,
            &cancellation_evidence,
            cancellation,
            &mut work,
        );
    }

    let (completion, completion_cancelled) =
        selection_completion.finish_semantic(cancellation, &mut work);
    if completion_cancelled || cancellation.is_cancelled() {
        return cancelled_selection_answer(
            conservative,
            &completion,
            &cancellation_evidence,
            cancellation,
            &mut work,
        );
    }
    let Some(answer) = try_build_resolution_answer(
        reference,
        &completed,
        &terminals,
        &shadowed,
        &terminal_discharged,
        &completion,
        cancellation,
        &mut work,
    ) else {
        return cancelled_selection_answer(
            conservative,
            &completion,
            &cancellation_evidence,
            cancellation,
            &mut work,
        );
    };
    if cancellation.is_cancelled() {
        return cancelled_selection_answer(
            conservative,
            &completion,
            &cancellation_evidence,
            cancellation,
            &mut work,
        );
    }
    match lookup_decision {
        Some(decision) => answer.with_lookup_decision(decision),
        None => answer,
    }
}

/// A total order has exactly one vertex of each indegree. Retain its semantic
/// alternatives without reference-specific choice IDs or path witnesses.
/// Partial orders and open stack variables need a richer decision structure;
/// they do not provide this certificate.
fn ordered_lookup_alternatives(
    completed: &[CompletedPath],
    terminals: &[IncompleteTerminalPath],
    indegree: &[usize],
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<Box<[LookupAlternative]>> {
    assert_eq!(indegree.len(), terminals.len() + completed.len());
    let mut ordered = Vec::with_capacity(indegree.len());
    for _ in indegree {
        if selection_cancelled(work, cancellation) {
            return None;
        }
        ordered.push(None);
    }
    for (index, &rank) in indegree.iter().enumerate() {
        if selection_cancelled(work, cancellation)
            || rank >= ordered.len()
            || ordered[rank].is_some()
        {
            return None;
        }
        let alternative = if index < completed.len() {
            LookupAlternative::Target(completed[index].target)
        } else {
            let path = terminals[index - completed.len()].path();
            let endpoint = path.end();
            if endpoint.symbols().tail().is_some() || endpoint.scopes().tail().is_some() {
                return None;
            }
            for symbol in endpoint.symbols().fixed() {
                if selection_cancelled(work, cancellation)
                    || symbol
                        .scopes()
                        .is_some_and(|scopes| scopes.tail().is_some())
                {
                    return None;
                }
            }
            LookupAlternative::Unresolved {
                endpoint: endpoint
                    .clone_with_poll(&mut || selection_cancelled(work, cancellation))?,
                completion: clone_completion_with_poll(path.completion(), &mut || {
                    selection_cancelled(work, cancellation)
                })?,
            }
        };
        ordered[rank] = Some(alternative);
    }
    let mut alternatives = Vec::with_capacity(ordered.len());
    for alternative in ordered {
        if selection_cancelled(work, cancellation) {
            return None;
        }
        alternatives.push(alternative.expect("distinct ranks cover the full order"));
    }
    Some(alternatives.into_boxed_slice())
}

fn cancelled_selection_answer(
    answer: ResolutionAnswer,
    completion: &ResolutionCompletion,
    cancellation_evidence: &ResolutionCompletion,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> ResolutionAnswer {
    let (targets, witnesses, answer_completion) = answer.into_parts();
    let operands = [&answer_completion, completion, cancellation_evidence];
    if operands.iter().any(|completion| {
        matches!(completion, ResolutionCompletion::Incomplete(reasons) if reasons.is_shared())
    }) {
        let mut evidence = CancellationEvidenceLedger::default();
        for operand in operands {
            evidence.include(operand, cancellation, work);
        }
        return ResolutionAnswer::new(targets, witnesses, evidence.finish(true, cancellation, work).0);
    }
    let mut reasons = BTreeSet::new();
    for operand in operands {
        if let ResolutionCompletion::Incomplete(operand_reasons) = operand {
            for &reason in operand_reasons.iter() {
                let _ = selection_cancelled(work, cancellation);
                reasons.insert(reason);
            }
        }
    }
    reasons.insert(ResolutionIncompleteReason::Cancelled);
    let mut completion_reasons = Vec::with_capacity(reasons.len());
    while let Some(reason) = reasons.pop_first() {
        let _ = selection_cancelled(work, cancellation);
        completion_reasons.push(reason);
    }
    ResolutionAnswer::new(
        targets,
        witnesses,
        ResolutionCompletion::Incomplete(completion_reasons.into_boxed_slice().into()),
    )
}

fn cancelled_selection_from_ledger(
    answer: ResolutionAnswer,
    completion: BatchCompletionLedger,
    cancellation_evidence: &ResolutionCompletion,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> ResolutionAnswer {
    let (completion, _) = completion.finish_semantic(cancellation, work);
    cancelled_selection_answer(
        answer,
        &completion,
        cancellation_evidence,
        cancellation,
        work,
    )
}

fn build_conservative_answer(
    reference: SemanticId,
    completed: &[CompletedPath],
    terminals: &[IncompleteTerminalPath],
    base_completion: &ResolutionCompletion,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> (ResolutionAnswer, bool) {
    let mut completion = BatchCompletionLedger::default();
    let mut targets = BTreeSet::new();
    let mut witnesses = Vec::with_capacity(completed.len());
    let mut cancelled = false;
    cancelled |= completion.include(base_completion, cancellation, work);
    for candidate in completed {
        observe_selection_cancellation(work, cancellation, &mut cancelled);
        if candidate.admission == BindingCandidateAdmission::Target {
            targets.insert(candidate.target);
        }
        cancelled |= completion.include(candidate.path.completion(), cancellation, work);
        let mut steps = Vec::with_capacity(candidate.path.witness().len() + 1);
        for &step in candidate.path.witness() {
            observe_selection_cancellation(work, cancellation, &mut cancelled);
            steps.push(step);
        }
        steps.push(WitnessStep::Candidate {
            semantic: candidate.target,
            outcome: match candidate.admission {
                BindingCandidateAdmission::Target => CandidateOutcome::Selected,
                BindingCandidateAdmission::WrongNamespaceBlocker => {
                    CandidateOutcome::Rejected(RejectionReason::WrongNamespace)
                }
            },
        });
        let Some(witness_completion) =
            clone_completion_with_poll(candidate.path.completion(), &mut || {
                observe_selection_cancellation(work, cancellation, &mut cancelled);
                false
            })
        else {
            unreachable!("the observational completion poll always returns false")
        };
        witnesses.push(ResolutionWitness::new(
            reference,
            candidate.target,
            steps,
            witness_completion,
        ));
    }
    for terminal in terminals {
        observe_selection_cancellation(work, cancellation, &mut cancelled);
        cancelled |= completion.include(terminal.path().completion(), cancellation, work);
    }
    let Some(witnesses) = canonicalize_witnesses_with_poll(witnesses, &mut || {
        observe_selection_cancellation(work, cancellation, &mut cancelled);
        false
    }) else {
        unreachable!("the observational witness poll always returns false")
    };
    let mut canonical_targets = Vec::with_capacity(targets.len());
    while let Some(target) = targets.pop_first() {
        observe_selection_cancellation(work, cancellation, &mut cancelled);
        canonical_targets.push(target);
    }
    let (completion, completion_cancelled) = completion.finish_semantic(cancellation, work);
    cancelled |= completion_cancelled | cancellation.is_cancelled();
    (
        ResolutionAnswer::new(canonical_targets, witnesses, completion),
        cancelled,
    )
}

#[allow(clippy::too_many_arguments)]
fn try_build_resolution_answer(
    reference: SemanticId,
    completed: &[CompletedPath],
    terminals: &[IncompleteTerminalPath],
    shadowed: &[bool],
    terminal_discharged: &[bool],
    base_completion: &ResolutionCompletion,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<ResolutionAnswer> {
    assert_eq!(completed.len(), shadowed.len());
    assert_eq!(terminals.len(), terminal_discharged.len());
    let mut completion = BatchCompletionLedger::default();
    if completion.include(base_completion, cancellation, work) {
        return None;
    }
    let mut targets = BTreeSet::new();
    let mut witnesses = Vec::with_capacity(completed.len());
    for (candidate, &is_shadowed) in completed.iter().zip(shadowed) {
        if selection_cancelled(work, cancellation) {
            return None;
        }
        if !is_shadowed {
            if candidate.admission == BindingCandidateAdmission::Target {
                targets.insert(candidate.target);
            }
            if completion.include(candidate.path.completion(), cancellation, work) {
                return None;
            }
        }
        let outcome = if is_shadowed {
            CandidateOutcome::Rejected(RejectionReason::ShadowedByNearer)
        } else if candidate.admission == BindingCandidateAdmission::WrongNamespaceBlocker {
            CandidateOutcome::Rejected(RejectionReason::WrongNamespace)
        } else {
            CandidateOutcome::Selected
        };
        let mut steps = Vec::with_capacity(candidate.path.witness().len() + 1);
        for &step in candidate.path.witness() {
            if selection_cancelled(work, cancellation) {
                return None;
            }
            steps.push(step);
        }
        steps.push(WitnessStep::Candidate {
            semantic: candidate.target,
            outcome,
        });
        let witness_completion =
            clone_completion_with_poll(candidate.path.completion(), &mut || {
                selection_cancelled(work, cancellation)
            })?;
        witnesses.push(ResolutionWitness::new(
            reference,
            candidate.target,
            steps,
            witness_completion,
        ));
    }
    for (terminal, &is_discharged) in terminals.iter().zip(terminal_discharged) {
        if selection_cancelled(work, cancellation) {
            return None;
        }
        if !is_discharged && completion.include(terminal.path().completion(), cancellation, work) {
            return None;
        }
    }
    let witnesses = canonicalize_witnesses_with_poll(witnesses, &mut || {
        selection_cancelled(work, cancellation)
    })?;
    let mut canonical_targets = Vec::with_capacity(targets.len());
    while let Some(target) = targets.pop_first() {
        if selection_cancelled(work, cancellation) {
            return None;
        }
        canonical_targets.push(target);
    }
    let (completion, completion_cancelled) = completion.finish_semantic(cancellation, work);
    if completion_cancelled || cancellation.is_cancelled() {
        return None;
    }
    Some(ResolutionAnswer::new(
        canonical_targets,
        witnesses,
        completion,
    ))
}

fn selection_cancelled(work: &mut usize, cancellation: &CancellationToken) -> bool {
    *work += 1;
    work.is_multiple_of(CANCELLATION_QUANTUM) && cancellation.is_cancelled()
}

fn observe_selection_cancellation(
    work: &mut usize,
    cancellation: &CancellationToken,
    cancelled: &mut bool,
) {
    if selection_cancelled(work, cancellation) {
        *cancelled = true;
    }
}

fn completion_contains_cancelled_with_poll(
    completion: &ResolutionCompletion,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<bool> {
    let ResolutionCompletion::Incomplete(reasons) = completion else {
        return Some(false);
    };
    if reasons.is_shared() {
        return reasons.contains_with_poll(&ResolutionIncompleteReason::Cancelled, &mut || {
            selection_cancelled(work, cancellation)
        });
    }
    for &reason in reasons.iter() {
        if selection_cancelled(work, cancellation) {
            return None;
        }
        if reason == ResolutionIncompleteReason::Cancelled {
            return Some(true);
        }
    }
    Some(false)
}

/// The first shared semantic choice point whose rank differs decides the
/// winner. Unrelated choice points do not order otherwise ambiguous paths.
fn path_shadows_with_poll(
    left: &PartialPath,
    right: &PartialPath,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<bool> {
    for left_step in left.precedence() {
        if selection_cancelled(work, cancellation) {
            return None;
        }
        let mut matched = None;
        for right_step in right.precedence() {
            if selection_cancelled(work, cancellation) {
                return None;
            }
            if right_step.semantic == left_step.semantic {
                matched = Some(right_step);
                break;
            }
        }
        let Some(right_step) = matched else {
            continue;
        };
        match (left_step.tier, left_step.ordinal).cmp(&(right_step.tier, right_step.ordinal)) {
            std::cmp::Ordering::Less => return Some(true),
            std::cmp::Ordering::Greater => return Some(false),
            std::cmp::Ordering::Equal => {}
        }
    }
    Some(false)
}

fn empty_adjacency_with_poll(
    len: usize,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<Vec<Vec<usize>>> {
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        if selection_cancelled(work, cancellation) {
            return None;
        }
        values.push(Vec::new());
    }
    Some(values)
}

fn zero_usize_with_poll(
    len: usize,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<Vec<usize>> {
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        if selection_cancelled(work, cancellation) {
            return None;
        }
        values.push(0);
    }
    Some(values)
}

fn clone_usize_with_poll(
    values: &[usize],
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<Vec<usize>> {
    let mut cloned = Vec::with_capacity(values.len());
    for &value in values {
        if selection_cancelled(work, cancellation) {
            return None;
        }
        cloned.push(value);
    }
    Some(cloned)
}

fn false_vector_with_poll(
    len: usize,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<Vec<bool>> {
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        if selection_cancelled(work, cancellation) {
            return None;
        }
        values.push(false);
    }
    Some(values)
}

fn zero_indegree_indices_with_poll(
    indegree: &[usize],
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<Vec<usize>> {
    let mut indices = Vec::new();
    for (index, &degree) in indegree.iter().enumerate() {
        if selection_cancelled(work, cancellation) {
            return None;
        }
        if degree == 0 {
            indices.push(index);
        }
    }
    Some(indices)
}

fn contains_index_with_poll(
    indices: &[usize],
    sought: usize,
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<bool> {
    for &index in indices {
        if selection_cancelled(work, cancellation) {
            return None;
        }
        if index == sought {
            return Some(true);
        }
    }
    Some(false)
}

fn directly_shadowed_with_poll(
    len: usize,
    maxima: &[usize],
    dominance: &[Vec<usize>],
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<Vec<bool>> {
    let mut shadowed = Vec::with_capacity(len);
    for right in 0..len {
        if selection_cancelled(work, cancellation) {
            return None;
        }
        let mut is_shadowed = false;
        for &left in maxima {
            if selection_cancelled(work, cancellation) {
                return None;
            }
            if contains_index_with_poll(&dominance[left], right, cancellation, work)? {
                is_shadowed = true;
                break;
            }
        }
        shadowed.push(is_shadowed);
    }
    Some(shadowed)
}

fn has_nontransitive_edge_with_poll(
    indegree: &[usize],
    shadowed: &[bool],
    cancellation: &CancellationToken,
    work: &mut usize,
) -> Option<bool> {
    assert_eq!(indegree.len(), shadowed.len());
    for (&degree, &is_shadowed) in indegree.iter().zip(shadowed) {
        if selection_cancelled(work, cancellation) {
            return None;
        }
        if degree != 0 && !is_shadowed {
            return Some(true);
        }
    }
    Some(false)
}

fn canonicalize_witnesses_with_poll<P>(
    witnesses: Vec<ResolutionWitness>,
    cancelled: &mut P,
) -> Option<Vec<ResolutionWitness>>
where
    P: FnMut() -> bool,
{
    let mut order = Vec::with_capacity(witnesses.len());
    let mut scratch = Vec::with_capacity(witnesses.len());
    for index in 0..witnesses.len() {
        if cancelled() {
            return None;
        }
        order.push(index);
        scratch.push(0);
    }

    let mut width = 1_usize;
    while width < order.len() {
        let mut start = 0_usize;
        while start < order.len() {
            if cancelled() {
                return None;
            }
            let middle = start.saturating_add(width).min(order.len());
            let end = middle.saturating_add(width).min(order.len());
            let mut left = start;
            let mut right = middle;
            let mut output = start;
            while left < middle && right < end {
                if cancelled() {
                    return None;
                }
                let ordering = compare_resolution_witnesses_with_poll(
                    &witnesses[order[left]],
                    &witnesses[order[right]],
                    cancelled,
                )?;
                if ordering != std::cmp::Ordering::Greater {
                    scratch[output] = order[left];
                    left += 1;
                } else {
                    scratch[output] = order[right];
                    right += 1;
                }
                output += 1;
            }
            while left < middle {
                if cancelled() {
                    return None;
                }
                scratch[output] = order[left];
                left += 1;
                output += 1;
            }
            while right < end {
                if cancelled() {
                    return None;
                }
                scratch[output] = order[right];
                right += 1;
                output += 1;
            }
            start = end;
        }
        std::mem::swap(&mut order, &mut scratch);
        width = width.saturating_mul(2);
    }

    let mut unique_order = Vec::with_capacity(order.len());
    for index in order {
        if cancelled() {
            return None;
        }
        if let Some(&prior) = unique_order.last()
            && compare_resolution_witnesses_with_poll(
                &witnesses[prior],
                &witnesses[index],
                cancelled,
            )? == std::cmp::Ordering::Equal
        {
            continue;
        }
        unique_order.push(index);
    }

    let mut owned = Vec::with_capacity(witnesses.len());
    for witness in witnesses {
        if cancelled() {
            return None;
        }
        owned.push(Some(witness));
    }
    let mut canonical = Vec::with_capacity(unique_order.len());
    for index in unique_order {
        if cancelled() {
            return None;
        }
        canonical.push(
            owned[index]
                .take()
                .expect("each canonical witness index is consumed once"),
        );
    }
    Some(canonical)
}

fn compare_resolution_witnesses_with_poll<P>(
    left: &ResolutionWitness,
    right: &ResolutionWitness,
    cancelled: &mut P,
) -> Option<std::cmp::Ordering>
where
    P: FnMut() -> bool,
{
    let ordering = left.reference().cmp(&right.reference());
    if ordering != std::cmp::Ordering::Equal {
        return Some(ordering);
    }
    let ordering = left.target().cmp(&right.target());
    if ordering != std::cmp::Ordering::Equal {
        return Some(ordering);
    }
    let shared = left.steps().len().min(right.steps().len());
    for index in 0..shared {
        if cancelled() {
            return None;
        }
        let ordering = left.steps()[index].cmp(&right.steps()[index]);
        if ordering != std::cmp::Ordering::Equal {
            return Some(ordering);
        }
    }
    let ordering = left.steps().len().cmp(&right.steps().len());
    if ordering != std::cmp::Ordering::Equal {
        return Some(ordering);
    }
    compare_completions_with_poll(left.completion(), right.completion(), cancelled)
}

fn compare_completions_with_poll<P>(
    left: &ResolutionCompletion,
    right: &ResolutionCompletion,
    cancelled: &mut P,
) -> Option<std::cmp::Ordering>
where
    P: FnMut() -> bool,
{
    match (left, right) {
        (ResolutionCompletion::Complete, ResolutionCompletion::Complete) => {
            Some(std::cmp::Ordering::Equal)
        }
        (ResolutionCompletion::Complete, ResolutionCompletion::Incomplete(_)) => {
            Some(std::cmp::Ordering::Less)
        }
        (ResolutionCompletion::Incomplete(_), ResolutionCompletion::Complete) => {
            Some(std::cmp::Ordering::Greater)
        }
        (ResolutionCompletion::Incomplete(left), ResolutionCompletion::Incomplete(right)) => {
            if (left.is_shared() || right.is_shared()) && left.equals_with_poll(right, cancelled)? {
                return Some(std::cmp::Ordering::Equal);
            }
            for (left, right) in left.iter().zip(right.iter()) {
                if cancelled() {
                    return None;
                }
                let ordering = left.cmp(right);
                if ordering != std::cmp::Ordering::Equal {
                    return Some(ordering);
                }
            }
            Some(left.len().cmp(&right.len()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::model::{
        PartialScopedSymbol, PrecedenceStep, ResolutionSlotValue, ResolutionTypeRef,
        StackVariableId, TypeTransferValueTransform,
    };
    use super::*;
    use crate::analyzer::resolution::{
        PreloadedFactResolutionService, lower_resolution_facts_with_identity_catalog,
    };
    use crate::analyzer::structural::PrecedenceTier;
    use brokk_bifrost_core::analyzer::Language;
    use brokk_bifrost_core::analyzer::resolution_facts::{
        FileResolutionFacts, ResolutionGapFact, ResolutionGapKind,
        ResolutionReferenceEnumerationGapFact, ResolutionScopeFact, ResolutionScopeId,
        ResolutionScopeInheritance, ResolutionScopeKind, ResolutionSiteFact, ResolutionSiteId,
        ResolutionSiteKind,
    };
    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
    use brokk_bifrost_core::analyzer::usages::resolution_session::{
        BoundedResolution, ResolutionSession,
    };

    fn semantic(value: &str) -> SemanticId {
        SemanticId::for_test(value)
    }

    #[test]
    fn selection_completion_shares_cancelled_evidence_and_equal_comparison_work() {
        let raw = ResolutionCompletion::incomplete((0..4_096_usize).map(|index| {
            ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::for_test(
                index.to_le_bytes(),
            ))
        }));
        let ResolutionCompletion::Incomplete(reasons) = &raw else {
            unreachable!()
        };
        let shared =
            ResolutionCompletion::Incomplete(reasons.to_shared_with_poll(&mut || false).unwrap());
        let mut comparison_work = 0;
        assert_eq!(
            compare_completions_with_poll(&shared, &shared, &mut || {
                comparison_work += 1;
                false
            }),
            Some(std::cmp::Ordering::Equal)
        );
        assert_eq!(comparison_work, 1);

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let mut work = 0;
        let empty = ResolutionCompletion::Incomplete(Vec::new().into());
        let answer = cancelled_selection_answer(
            ResolutionAnswer::new(Vec::new(), Vec::new(), shared),
            &empty,
            &empty,
            &cancellation,
            &mut work,
        );
        assert_eq!(
            answer.completion(),
            &raw.combine(&ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::Cancelled,
            ]))
        );
        assert!(
            matches!(answer.completion(), ResolutionCompletion::Incomplete(reasons) if reasons.is_shared())
        );
        assert!(
            work < 100,
            "selection cancellation must retain the base without scanning it: {work}"
        );
    }

    fn runtime_type(value: &str) -> ResolutionSlotValue {
        ResolutionSlotValue::runtime(ResolutionTypeRef::new(semantic(value), 0), false)
    }

    fn fragment(value: &str) -> BindingFragmentId {
        BindingFragmentId::for_test(value)
    }

    fn type_only_inventory_facts() -> FileResolutionFacts {
        FileResolutionFacts {
            scopes: vec![ResolutionScopeFact {
                id: ResolutionScopeId::new(0),
                parent: None,
                owner: None,
                kind: ResolutionScopeKind::CompilationUnit,
                inheritance: ResolutionScopeInheritance::Lexical,
                start_byte: 0,
                end_byte: 100,
            }],
            sites: vec![ResolutionSiteFact {
                id: ResolutionSiteId::new(0),
                scope: ResolutionScopeId::new(0),
                kind: ResolutionSiteKind::UnsupportedExpression,
                start_byte: 20,
                end_byte: 21,
            }],
            gaps: vec![ResolutionGapFact {
                site: ResolutionSiteId::new(0),
                kind: ResolutionGapKind::UnsupportedExpression,
            }],
            ..FileResolutionFacts::default()
        }
    }

    fn empty_inventory_fragment(fragment: BindingFragmentId) -> LoweredResolutionFragment {
        crate::analyzer::resolution::lower_lexical_for_test(
            fragment,
            Language::Java,
            &FileResolutionFacts::default(),
        )
        .0
    }

    fn enumeration_inventory_fragment(fragment: BindingFragmentId) -> LoweredResolutionFragment {
        let facts = FileResolutionFacts {
            scopes: vec![ResolutionScopeFact {
                id: ResolutionScopeId::new(0),
                parent: None,
                owner: None,
                kind: ResolutionScopeKind::CompilationUnit,
                inheritance: ResolutionScopeInheritance::Lexical,
                start_byte: 0,
                end_byte: 100,
            }],
            sites: vec![ResolutionSiteFact {
                id: ResolutionSiteId::new(0),
                scope: ResolutionScopeId::new(0),
                kind: ResolutionSiteKind::UnsupportedExpression,
                start_byte: 20,
                end_byte: 21,
            }],
            reference_enumeration_gaps: vec![ResolutionReferenceEnumerationGapFact {
                site: ResolutionSiteId::new(0),
                kind: ResolutionGapKind::UnsupportedExpression,
            }],
            ..FileResolutionFacts::default()
        };
        crate::analyzer::resolution::lower_lexical_for_test(fragment, Language::Java, &facts).0
    }

    fn type_only_inventory_fragment(fragment: BindingFragmentId) -> LoweredResolutionFragment {
        crate::analyzer::resolution::lower_lexical_for_test(
            fragment,
            Language::Java,
            &type_only_inventory_facts(),
        )
        .0
    }

    #[test]
    fn scoped_reference_seed_enumeration_certifies_empty_fragment_inventory() {
        let clean = fragment("scoped-seeds-clean");
        let gap = fragment("scoped-seeds-gap");
        let source = PreloadedFragmentSource::from_lowered_fragments([
            empty_inventory_fragment(clean),
            enumeration_inventory_fragment(gap),
        ]);
        let cancellation = CancellationToken::new();
        for (fragments, complete) in [
            (HashSet::default(), true),
            (HashSet::from_iter([clean]), true),
            (HashSet::from_iter([gap]), false),
        ] {
            let completion = source
                .visit_reference_seed_batches_in_fragments(
                    &fragments,
                    1,
                    &cancellation,
                    &mut |_| panic!("empty fragment cannot emit a seed batch"),
                )
                .unwrap();
            assert_eq!(completion == ResolutionCompletion::Complete, complete);
        }
        assert!(
            source
                .visit_reference_seed_batches_in_fragments(
                    &HashSet::from_iter([fragment("unselected-scoped-seeds")]),
                    1,
                    &cancellation,
                    &mut |_| Ok(true)
                )
                .is_err()
        );
        cancellation.cancel();
        let cancelled = source
            .visit_reference_seed_batches_in_fragments(
                &HashSet::default(),
                1,
                &cancellation,
                &mut |_| Ok(true),
            )
            .unwrap();
        assert!(cancelled.contains_reason(ResolutionIncompleteReason::Cancelled));
    }

    #[test]
    fn reference_inventory_completion_is_fragment_scoped_type_only_and_bounded() {
        let zero = fragment("reference-inventory-zero");
        let unrelated = fragment("reference-inventory-unrelated-gap");
        let type_only = fragment("reference-inventory-type-only");
        let source = PreloadedFragmentSource::from_lowered_fragments([
            empty_inventory_fragment(zero),
            enumeration_inventory_fragment(unrelated),
            type_only_inventory_fragment(type_only),
        ]);
        let cancellation = CancellationToken::new();
        let session = ResolutionSession::unbounded();

        assert_eq!(
            source
                .reference_inventory_completion(zero, &cancellation, &session)
                .unwrap(),
            ResolutionCompletion::Complete,
            "a zero-seed source is complete when its own enumeration is complete"
        );
        let requested = source
            .reference_inventory_completion(unrelated, &cancellation, &session)
            .unwrap();
        assert!(
            matches!(requested, ResolutionCompletion::Incomplete(_)),
            "the requested source must retain its own enumeration gap: {requested:?}"
        );
        assert!(!requested.contains_reason(ResolutionIncompleteReason::Cancelled));
        assert_eq!(
            source
                .reference_inventory_completion(type_only, &cancellation, &session)
                .unwrap(),
            ResolutionCompletion::Complete,
            "a type-only gap must not pollute reference inventory"
        );

        let missing = source
            .reference_inventory_completion(
                fragment("reference-inventory-missing"),
                &cancellation,
                &session,
            )
            .expect_err("missing source inventory must fail explicitly");
        assert!(
            missing
                .to_string()
                .contains("unselected transient fragment")
        );

        let already_cancelled = CancellationToken::new();
        already_cancelled.cancel();
        let cancelled = source
            .reference_inventory_completion(zero, &already_cancelled, &session)
            .unwrap();
        assert!(cancelled.contains_reason(ResolutionIncompleteReason::Cancelled));
        assert!(!matches!(cancelled, ResolutionCompletion::Complete));

        let zero_budget = ResolutionSession::bounded(
            ReceiverAnalysisBudget {
                max_scope_nodes: 0,
                ..ReceiverAnalysisBudget::default()
            },
            None,
        );
        let budgeted = source
            .reference_inventory_completion(
                zero,
                zero_budget
                    .cancellation()
                    .expect("bounded inventory session owns cancellation"),
                &zero_budget,
            )
            .unwrap();
        assert!(budgeted.contains_reason(ResolutionIncompleteReason::Cancelled));
        assert!(!matches!(budgeted, ResolutionCompletion::Complete));
        assert!(matches!(
            zero_budget.finish(()),
            BoundedResolution::Exceeded { .. }
        ));

        let service_fragment = fragment("reference-inventory-service-type-only");
        let lowered = crate::analyzer::resolution::lower_resolution_facts_for_selection(
            service_fragment,
            crate::analyzer::resolution::test_shared_names(),
            Language::Java,
            &type_only_inventory_facts(),
        );
        let (lexical, typed, _) = lowered.into_parts();
        let service = PreloadedFactResolutionService::from_lowered_fragments([lexical], [typed]);
        assert_eq!(
            service
                .reference_inventory_completion(service_fragment, &cancellation, &session,)
                .unwrap(),
            ResolutionCompletion::Complete,
            "the fact service must apply the same type-only inventory boundary"
        );
    }

    fn node(value: &str) -> BindingNodeId {
        BindingNodeId::for_test(value)
    }

    fn path_id(value: &str) -> PartialPathId {
        PartialPathId::for_test(value)
    }

    fn endpoint(node: BindingNodeId, symbols: Vec<SemanticId>) -> EndpointSignature {
        EndpointSignature::new(
            node,
            StackPattern::closed(symbols),
            StackPattern::closed(Vec::new()),
        )
    }

    #[test]
    fn preloaded_endpoint_classification_carries_exact_member_scope_owner_and_cancels_atomically() {
        let fragment = fragment("member-scope-classification-fragment");
        let scope_head = node("member-scope-classification-head");
        let owner = semantic("member-scope-classification-owner");
        let mut source = PreloadedFragmentSource::from_fragments([PreloadedFragment::new(
            fragment,
            [(scope_head, BindingNodeKind::Scope)],
            [],
        )]);
        source.install_member_scope_owners([(scope_head, owner)]);

        let classified = source
            .classify_endpoint_nodes(&[scope_head], &CancellationToken::new())
            .expect("preloaded endpoint classification is infallible");

        assert_eq!(classified.len(), 1);
        assert_eq!(classified[0].node(), scope_head);
        assert_eq!(classified[0].member_scope_owner(), Some(owner));
        assert_eq!(classified[0].reference(), None);
        assert_eq!(classified[0].definition(), None);

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert!(
            source
                .classify_endpoint_nodes(&[scope_head], &cancellation)
                .expect("preloaded cancellation is operational")
                .is_empty(),
            "a cancelled endpoint batch must not expose a classified prefix"
        );
    }

    #[test]
    #[should_panic(expected = "must name a Scope endpoint")]
    fn preloaded_member_scope_owner_rejects_a_reference_node() {
        let fragment = fragment("malformed-member-scope-classification-fragment");
        let reference = semantic("malformed-member-scope-reference");
        let reference_node = node("malformed-member-scope-reference-node");
        let mut source = PreloadedFragmentSource::from_fragments([PreloadedFragment::new(
            fragment,
            [(reference_node, BindingNodeKind::Reference(reference))],
            [],
        )]);

        source.install_member_scope_owners([(
            reference_node,
            semantic("malformed-member-scope-owner"),
        )]);
    }

    #[test]
    #[should_panic(expected = "duplicate or conflicting member-scope owner classification")]
    fn preloaded_endpoint_classification_rejects_duplicate_owner_installation() {
        let fragment = fragment("duplicate-member-scope-classification-fragment");
        let scope_head = node("duplicate-member-scope-classification-head");
        let owner = semantic("duplicate-member-scope-classification-owner");
        let mut source = PreloadedFragmentSource::from_fragments([PreloadedFragment::new(
            fragment,
            [(scope_head, BindingNodeKind::Scope)],
            [],
        )]);

        source.install_member_scope_owners([(scope_head, owner), (scope_head, owner)]);
    }

    #[test]
    #[should_panic(expected = "duplicate or conflicting member-scope owner classification")]
    fn preloaded_endpoint_classification_rejects_conflicting_owner_installation() {
        let fragment = fragment("conflicting-member-scope-classification-fragment");
        let scope_head = node("conflicting-member-scope-classification-head");
        let mut source = PreloadedFragmentSource::from_fragments([PreloadedFragment::new(
            fragment,
            [(scope_head, BindingNodeKind::Scope)],
            [],
        )]);

        source.install_member_scope_owners([
            (scope_head, semantic("first-member-scope-owner")),
            (scope_head, semantic("second-member-scope-owner")),
        ]);
    }

    fn path(
        start: BindingNodeId,
        end: BindingNodeId,
        before: Vec<SemanticId>,
        after: Vec<SemanticId>,
        precedence: Vec<PrecedenceStep>,
    ) -> PartialPath {
        path_with_completion(
            start,
            end,
            before,
            after,
            precedence,
            ResolutionCompletion::Complete,
        )
    }

    fn path_with_completion(
        start: BindingNodeId,
        end: BindingNodeId,
        before: Vec<SemanticId>,
        after: Vec<SemanticId>,
        precedence: Vec<PrecedenceStep>,
        completion: ResolutionCompletion,
    ) -> PartialPath {
        PartialPath::new(
            endpoint(start, before),
            endpoint(end, after),
            precedence,
            [WitnessStep::Node(end)],
            completion,
        )
    }

    fn source_with_reverse_inventory_gaps(
        label: &str,
        rows: &[(BindingFragmentId, SemanticId, SemanticId)],
    ) -> (PreloadedFragmentSource, BatchCandidateRequest) {
        let owner = rows
            .first()
            .map(|(fragment, _, _)| *fragment)
            .unwrap_or_else(|| fragment(&format!("{label}-fragment")));
        let start = node(&format!("{label}-start"));
        let end = node(&format!("{label}-end"));
        let mut source = PreloadedFragmentSource::from_fragments([PreloadedFragment::new(
            owner,
            [
                (start, BindingNodeKind::Scope),
                (end, BindingNodeKind::Scope),
            ],
            [(
                path_id(&format!("{label}-path")),
                path(start, end, Vec::new(), Vec::new(), Vec::new()),
            )],
        )]);
        let mut coverage = ReverseCandidateGapCoverageBuilder::default();
        let mut reasons = BTreeSet::new();
        for &(fragment, gap_id, reason) in rows {
            coverage
                .push(ReverseCandidateGapRow::new(
                    ReverseCandidateGapIdentity::new(fragment, gap_id),
                    ReverseCandidateGapLocation::Inventory,
                    ResolutionIncompleteReason::UnsupportedSemantic(reason),
                ))
                .expect("test reverse gaps have unique exact identities");
            reasons.insert(ResolutionIncompleteReason::UnsupportedSemantic(reason));
        }
        let (coverage, cancelled) = coverage
            .finish(&CancellationToken::new())
            .expect("test reverse gap coverage is valid");
        assert!(!cancelled);
        source.coverage.reverse_candidate_gaps = coverage;
        source.coverage.reverse_candidate_inventory = if reasons.is_empty() {
            ResolutionCompletion::Complete
        } else {
            ResolutionCompletion::Incomplete(reasons.into_iter().collect::<Vec<_>>().into())
        };
        (
            source,
            BatchCandidateRequest::new(0, endpoint(end, Vec::new())),
        )
    }

    fn visit_reverse_pages(
        source: &PreloadedFragmentSource,
        request: &BatchCandidateRequest,
        exclusions: Option<&mut ReverseCandidateGapExclusionPlan>,
        cancellation: &CancellationToken,
    ) -> StoreResult<(Vec<BatchCandidateMatch>, BatchCandidateCompletionOutcome)> {
        let mut matches = Vec::new();
        let completion = if let Some(exclusions) = exclusions {
            source.visit_reverse_candidate_match_pages_with_gap_exclusions_shared(
                std::slice::from_ref(request),
                exclusions,
                cancellation,
                &mut |page| {
                    matches.extend_from_slice(page);
                    Ok(true)
                },
            )?
        } else {
            source.visit_reverse_candidate_match_pages(
                std::slice::from_ref(request),
                cancellation,
                &mut |page| {
                    matches.extend_from_slice(page);
                    Ok(true)
                },
            )?
        };
        Ok((matches, completion))
    }

    #[test]
    fn empty_reverse_gap_exclusion_plan_is_exact_raw_parity() {
        let fragment = fragment("empty-reverse-gap-plan-fragment");
        let reason = semantic("empty-reverse-gap-plan-reason");
        let (source, request) = source_with_reverse_inventory_gaps(
            "empty-reverse-gap-plan",
            &[(fragment, semantic("empty-reverse-gap-plan-gap"), reason)],
        );
        let raw = visit_reverse_pages(&source, &request, None, &CancellationToken::new())
            .expect("raw preload reverse visit succeeds");
        let mut exclusions = ReverseCandidateGapExclusionPlan::default();
        let filtered = visit_reverse_pages(
            &source,
            &request,
            Some(&mut exclusions),
            &CancellationToken::new(),
        )
        .expect("empty reverse exclusion delegates to raw preload visit");

        assert_eq!(filtered, raw);
    }

    #[test]
    fn exact_reverse_gap_exclusions_preserve_same_reason_siblings_and_raw_source() {
        let fragment = fragment("same-reason-reverse-gap-fragment");
        let reason = semantic("same-reason-reverse-gap-reason");
        let first =
            ReverseCandidateGapIdentity::new(fragment, semantic("same-reason-reverse-gap-first"));
        let second =
            ReverseCandidateGapIdentity::new(fragment, semantic("same-reason-reverse-gap-second"));
        let (source, request) = source_with_reverse_inventory_gaps(
            "same-reason-reverse-gap",
            &[
                (fragment, first.gap_id(), reason),
                (fragment, second.gap_id(), reason),
            ],
        );
        let raw_before = visit_reverse_pages(&source, &request, None, &CancellationToken::new())
            .expect("raw preload reverse visit succeeds");

        let mut one = ReverseCandidateGapExclusionPlan::new([first]);
        let (_, one_completion) =
            visit_reverse_pages(&source, &request, Some(&mut one), &CancellationToken::new())
                .expect("one exact reverse gap can be excluded");
        assert!(
            one_completion
                .unconditional_completion()
                .contains_reason(ResolutionIncompleteReason::UnsupportedSemantic(reason))
        );

        let mut all = ReverseCandidateGapExclusionPlan::new([first, second]);
        let (_, all_completion) =
            visit_reverse_pages(&source, &request, Some(&mut all), &CancellationToken::new())
                .expect("all exact reverse gaps can be excluded");
        assert_eq!(
            all_completion.unconditional_completion(),
            &ResolutionCompletion::Complete
        );
        let all_reused =
            visit_reverse_pages(&source, &request, Some(&mut all), &CancellationToken::new())
                .expect("one prepared reverse-gap plan is reusable within its exact source");
        assert_eq!(all_reused.1, all_completion);

        let raw_after = visit_reverse_pages(&source, &request, None, &CancellationToken::new())
            .expect("filtered preload calls do not mutate raw coverage");
        assert_eq!(raw_after, raw_before);
    }

    #[test]
    fn prepared_reverse_gap_exclusion_replays_filtered_semantics_before_cancellation() {
        let fragment = fragment("prepared-reverse-gap-cancellation-fragment");
        let removed_gap = semantic("prepared-reverse-gap-cancellation-removed-gap");
        let removed_reason = semantic("prepared-reverse-gap-cancellation-removed-reason");
        let retained_reason = semantic("prepared-reverse-gap-cancellation-retained-reason");
        let (source, request) = source_with_reverse_inventory_gaps(
            "prepared-reverse-gap-cancellation",
            &[
                (fragment, removed_gap, removed_reason),
                (
                    fragment,
                    semantic("prepared-reverse-gap-cancellation-retained-gap"),
                    retained_reason,
                ),
            ],
        );
        let mut plan = ReverseCandidateGapExclusionPlan::new([ReverseCandidateGapIdentity::new(
            fragment,
            removed_gap,
        )]);
        let warm = visit_reverse_pages(
            &source,
            &request,
            Some(&mut plan),
            &CancellationToken::new(),
        )
        .expect("the live preload visit prepares one exact filtered completion");
        assert_eq!(warm.0.len(), 1);
        assert_eq!(
            warm.1.unconditional_completion(),
            &ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                retained_reason
            ),])
        );

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let cancelled = visit_reverse_pages(&source, &request, Some(&mut plan), &cancellation)
            .expect("a prepared preload plan replays immutable semantics under cancellation");
        assert!(cancelled.0.is_empty());
        assert_eq!(
            cancelled.1.unconditional_completion(),
            &warm
                .1
                .unconditional_completion()
                .combine(&cancelled_completion())
        );

        let retried = visit_reverse_pages(
            &source,
            &request,
            Some(&mut plan),
            &CancellationToken::new(),
        )
        .expect("a fresh preload retry remains exact after entry cancellation");
        assert_eq!(retried, warm);
    }

    #[test]
    fn exact_reverse_gap_exclusions_reject_wrong_fragment_unknown_and_stale_fingerprint() {
        let owner_fragment = fragment("exact-reverse-gap-owner");
        let other_fragment = fragment("exact-reverse-gap-other-owner");
        let gap_id = semantic("exact-reverse-gap-id");
        let reason = semantic("exact-reverse-gap-reason");
        let (mut source, request) = source_with_reverse_inventory_gaps(
            "exact-reverse-gap-owner",
            &[(owner_fragment, gap_id, reason)],
        );
        for identity in [
            ReverseCandidateGapIdentity::new(other_fragment, gap_id),
            ReverseCandidateGapIdentity::new(owner_fragment, semantic("unknown-reverse-gap-id")),
        ] {
            let mut plan = ReverseCandidateGapExclusionPlan::new([identity]);
            let mut callback_count = 0_usize;
            let error = source
                .visit_reverse_candidate_match_pages_with_gap_exclusions(
                    std::slice::from_ref(&request),
                    &mut plan,
                    &CancellationToken::new(),
                    &mut |_| {
                        callback_count += 1;
                        Ok(true)
                    },
                )
                .expect_err("an absent exact reverse gap must fail closed");
            assert!(error.to_string().contains("no exact gap"));
            assert_eq!(callback_count, 0);
        }

        let exact = ReverseCandidateGapIdentity::new(owner_fragment, gap_id);
        let mut plan = ReverseCandidateGapExclusionPlan::new([exact]);
        visit_reverse_pages(
            &source,
            &request,
            Some(&mut plan),
            &CancellationToken::new(),
        )
        .expect("the plan prepares against its first exact source");
        let (mut different_source, different_request) = source_with_reverse_inventory_gaps(
            "different-reverse-gap-source",
            &[(
                owner_fragment,
                gap_id,
                semantic("different-reverse-gap-reason"),
            )],
        );
        let mut callback_count = 0_usize;
        let error = different_source
            .visit_reverse_candidate_match_pages_with_gap_exclusions(
                std::slice::from_ref(&different_request),
                &mut plan,
                &CancellationToken::new(),
                &mut |_| {
                    callback_count += 1;
                    Ok(true)
                },
            )
            .expect_err("a prepared plan cannot cross a different raw fingerprint");
        assert!(error.to_string().contains("different raw coverage"));
        assert_eq!(callback_count, 0);
    }

    #[test]
    fn cancellation_during_reverse_gap_preparation_retains_raw_evidence_and_retries_exactly() {
        let fragment = fragment("cancelled-reverse-gap-preparation-fragment");
        let reason = semantic("cancelled-reverse-gap-preparation-reason");
        let identities = (0..64)
            .map(|ordinal| {
                ReverseCandidateGapIdentity::new(
                    fragment,
                    semantic(&format!("cancelled-reverse-gap-{ordinal}")),
                )
            })
            .collect::<Vec<_>>();
        let rows = identities
            .iter()
            .map(|identity| (fragment, identity.gap_id(), reason))
            .collect::<Vec<_>>();
        let (mut source, request) =
            source_with_reverse_inventory_gaps("cancelled-reverse-gap-preparation", &rows);
        let mut plan = ReverseCandidateGapExclusionPlan::new(identities);
        let cancellation = CancellationToken::cancel_after_checks_for_test(5);
        let mut callback_count = 0_usize;
        let cancelled = source
            .visit_reverse_candidate_match_pages_with_gap_exclusions(
                std::slice::from_ref(&request),
                &mut plan,
                &cancellation,
                &mut |_| {
                    callback_count += 1;
                    Ok(true)
                },
            )
            .expect("preload preparation cancellation is semantic");
        assert_eq!(callback_count, 0);
        assert!(
            cancelled
                .unconditional_completion()
                .contains_reason(ResolutionIncompleteReason::UnsupportedSemantic(reason))
        );
        assert!(
            cancelled
                .unconditional_completion()
                .contains_reason(ResolutionIncompleteReason::Cancelled)
        );

        let (matches, retried) = visit_reverse_pages(
            &source,
            &request,
            Some(&mut plan),
            &CancellationToken::new(),
        )
        .expect("a fresh operation token retries an unpublished preparation");
        assert_eq!(matches.len(), 1);
        assert_eq!(
            retried.unconditional_completion(),
            &ResolutionCompletion::Complete
        );
    }

    fn selection_completed(
        label: &str,
        target: SemanticId,
        precedence: Vec<PrecedenceStep>,
        completion: ResolutionCompletion,
    ) -> CompletedPath {
        CompletedPath {
            admission: BindingCandidateAdmission::Target,
            target,
            path: path_with_completion(
                node(&format!("{label}-start")),
                node(&format!("{label}-end")),
                Vec::new(),
                Vec::new(),
                precedence,
                completion,
            ),
        }
    }

    fn selection_terminal(
        label: &str,
        precedence: Vec<PrecedenceStep>,
        reason: SemanticId,
    ) -> IncompleteTerminalPath {
        IncompleteTerminalPath::new(path_with_completion(
            node(&format!("{label}-start")),
            node(&format!("{label}-end")),
            Vec::new(),
            Vec::new(),
            precedence,
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                reason,
            )]),
        ))
    }

    fn precedence(semantic: SemanticId, ordinal: u32) -> PrecedenceStep {
        PrecedenceStep {
            semantic,
            tier: PrecedenceTier::LexicalBinding,
            ordinal,
        }
    }

    fn source_with_paths(
        reference: SemanticId,
        definitions: &[(SemanticId, BindingNodeId)],
        junctions: &[BindingNodeId],
        paths: Vec<(PartialPathId, PartialPath)>,
    ) -> PreloadedFragmentSource {
        let reference_node = node("reference-node");
        let mut nodes = vec![(reference_node, BindingNodeKind::Reference(reference))];
        nodes.extend(
            definitions
                .iter()
                .map(|(semantic, node)| (*node, BindingNodeKind::Definition(*semantic))),
        );
        nodes.extend(junctions.iter().map(|node| (*node, BindingNodeKind::Scope)));
        PreloadedFragmentSource::new(nodes, paths)
    }

    #[test]
    #[should_panic(expected = "names non-local, non-boundary binding node")]
    fn preloaded_fragment_rejects_a_foreign_fixed_endpoint_scope() {
        let foreign_fragment = fragment("foreign-scope-owner");
        let path_fragment = fragment("foreign-scope-user");
        let foreign_scope = node("foreign-fixed-scope");
        let start = node("foreign-fixed-scope-start");
        let end = node("foreign-fixed-scope-end");
        let invalid = PartialPath::new(
            EndpointSignature::new(
                start,
                StackPattern::closed(Vec::new()),
                StackPattern::closed([foreign_scope]),
            ),
            endpoint(end, Vec::new()),
            Vec::new(),
            [WitnessStep::Node(end)],
            ResolutionCompletion::Complete,
        );

        PreloadedFragmentSource::from_fragments([
            PreloadedFragment::new(
                foreign_fragment,
                [(foreign_scope, BindingNodeKind::Scope)],
                [],
            ),
            PreloadedFragment::new(
                path_fragment,
                [
                    (start, BindingNodeKind::Scope),
                    (end, BindingNodeKind::Scope),
                ],
                [(path_id("foreign-fixed-scope-path"), invalid)],
            ),
        ]);
    }

    #[test]
    #[should_panic(expected = "attached scope stack")]
    fn preloaded_fragment_rejects_an_unknown_attached_symbol_scope() {
        let owner = fragment("unknown-attached-scope-owner");
        let start = node("unknown-attached-scope-start");
        let end = node("unknown-attached-scope-end");
        let unknown_scope = node("unknown-attached-scope");
        let invalid = PartialPath::new(
            EndpointSignature::new_scoped(
                start,
                StackPattern::closed([PartialScopedSymbol::scoped(
                    semantic("unknown-attached-name"),
                    StackPattern::closed([unknown_scope]),
                )]),
                StackPattern::closed(Vec::new()),
            ),
            endpoint(end, Vec::new()),
            Vec::new(),
            [WitnessStep::Node(end)],
            ResolutionCompletion::Complete,
        );

        PreloadedFragmentSource::from_fragments([PreloadedFragment::new(
            owner,
            [
                (start, BindingNodeKind::Scope),
                (end, BindingNodeKind::Scope),
            ],
            [(path_id("unknown-attached-scope-path"), invalid)],
        )]);
    }

    #[test]
    #[should_panic(expected = "jump node")]
    fn preloaded_fragment_rejects_a_jump_to_a_foreign_interior() {
        let foreign_fragment = fragment("foreign-jump-owner");
        let jump_fragment = fragment("foreign-jump-user");
        let foreign_scope = node("foreign-jump-scope");
        let jump = node("foreign-jump-node");

        PreloadedFragmentSource::from_fragments([
            PreloadedFragment::new(
                foreign_fragment,
                [(foreign_scope, BindingNodeKind::Scope)],
                [],
            ),
            PreloadedFragment::new(
                jump_fragment,
                [(jump, BindingNodeKind::JumpToScope(foreign_scope))],
                [],
            ),
        ]);
    }

    #[test]
    #[should_panic(expected = "witness position")]
    fn preloaded_fragment_rejects_an_unknown_witness_node() {
        let owner = fragment("unknown-witness-owner");
        let start = node("unknown-witness-start");
        let end = node("unknown-witness-end");
        let unknown = node("unknown-witness-node");
        let invalid = PartialPath::new(
            endpoint(start, Vec::new()),
            endpoint(end, Vec::new()),
            Vec::new(),
            [WitnessStep::Node(unknown)],
            ResolutionCompletion::Complete,
        );

        PreloadedFragmentSource::from_fragments([PreloadedFragment::new(
            owner,
            [
                (start, BindingNodeKind::Scope),
                (end, BindingNodeKind::Scope),
            ],
            [(path_id("unknown-witness-path"), invalid)],
        )]);
    }

    #[test]
    fn preloaded_fragment_accepts_explicit_boundaries_in_all_node_positions() {
        let owner = fragment("explicit-boundary-owner");
        let boundary = node("explicit-shared-boundary");
        let jump = node("explicit-boundary-jump");
        let end = node("explicit-boundary-end");
        let valid = PartialPath::new(
            EndpointSignature::new_scoped(
                jump,
                StackPattern::closed([PartialScopedSymbol::scoped(
                    semantic("explicit-boundary-name"),
                    StackPattern::closed([boundary]),
                )]),
                StackPattern::closed([boundary]),
            ),
            endpoint(end, Vec::new()),
            Vec::new(),
            [WitnessStep::Node(boundary), WitnessStep::Node(end)],
            ResolutionCompletion::Complete,
        );

        let source = PreloadedFragmentSource::from_fragments_with_boundaries(
            [boundary],
            [PreloadedFragment::new(
                owner,
                [
                    (jump, BindingNodeKind::JumpToScope(boundary)),
                    (end, BindingNodeKind::Scope),
                ],
                [(path_id("explicit-boundary-path"), valid)],
            )],
        );

        assert_eq!(source.nodes.get(&boundary), Some(&BindingNodeKind::Root));
    }

    #[test]
    fn fragmented_and_monolithic_paths_resolve_identically() {
        let reference = semantic("reference");
        let target = semantic("target");
        let target_node = node("target-node");
        let seam = node("seam");
        let name = semantic("name");
        let monolithic = source_with_paths(
            reference,
            &[(target, target_node)],
            &[],
            vec![(
                path_id("whole"),
                path(
                    node("reference-node"),
                    target_node,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
            )],
        );
        let fragmented = source_with_paths(
            reference,
            &[(target, target_node)],
            &[seam],
            vec![
                (
                    path_id("push"),
                    path(
                        node("reference-node"),
                        seam,
                        Vec::new(),
                        vec![name],
                        Vec::new(),
                    ),
                ),
                (
                    path_id("pop"),
                    path(seam, target_node, vec![name], Vec::new(), Vec::new()),
                ),
            ],
        );
        let cancellation = CancellationToken::new();

        let whole = ResolutionEngine::new(&monolithic)
            .resolve_reference(ResolutionQuery::new(reference), &cancellation)
            .expect("preloaded source is infallible");
        let pieces = ResolutionEngine::new(&fragmented)
            .resolve_reference(ResolutionQuery::new(reference), &cancellation)
            .expect("preloaded source is infallible");

        assert_eq!(whole.targets(), &[target]);
        assert_eq!(pieces.targets(), whole.targets());
        assert_eq!(pieces.completion(), &ResolutionCompletion::Complete);
    }

    #[test]
    fn imported_package_blocks_plain_names_and_binds_only_structured_qualifiers() {
        let reference = semantic("go-package-reference");
        let package = semantic("go-import-binding");
        let outer = semantic("go-outer-definition");
        let choice = semantic("go-file-spelling-choice");
        for (requested, qualifier) in [
            (ResolutionNamespace::Type, false),
            (ResolutionNamespace::Value, false),
            (ResolutionNamespace::Callable, false),
            (ResolutionNamespace::TypeOrValue, false),
            (ResolutionNamespace::TypeOrValue, true),
        ] {
            let near = selection_completed(
                "package",
                package,
                vec![precedence(choice, 0)],
                ResolutionCompletion::Complete,
            );
            let CompletedBinding::Complete(near) = classify_completed_binding(
                Some(requested),
                qualifier,
                Some(GoDefinitionNamespaces::from_bits(8)),
                package,
                near.path,
            ) else {
                panic!("known package category has complete admission")
            };
            let far = selection_completed(
                "outer",
                outer,
                vec![precedence(choice, 1)],
                ResolutionCompletion::Complete,
            );
            let answer = select_paths(
                reference,
                vec![near, far],
                Vec::new(),
                ResolutionCompletion::Complete,
                &CancellationToken::new(),
            );
            assert_eq!(
                answer.targets(),
                if qualifier {
                    std::slice::from_ref(&package)
                } else {
                    &[]
                }
            );
            assert!(!answer.targets().contains(&outer));
            assert!(
                answer
                    .witnesses()
                    .iter()
                    .any(|witness| witness.target() == package)
            );
        }
    }

    #[test]
    fn missing_go_definition_authority_is_incomplete_and_cannot_block_or_bind() {
        let reference = semantic("go-missing-authority-reference");
        let unknown = semantic("go-unknown-namespace");
        let outer = semantic("go-outer-value");
        let choice = semantic("go-spelling-choice");
        let near = selection_completed(
            "unknown",
            unknown,
            vec![precedence(choice, 0)],
            ResolutionCompletion::Complete,
        );
        let CompletedBinding::Incomplete(terminal) = classify_completed_binding(
            Some(ResolutionNamespace::Value),
            false,
            None,
            unknown,
            near.path,
        ) else {
            panic!("missing namespace authority must remain incomplete");
        };
        let far = selection_completed(
            "far",
            outer,
            vec![precedence(choice, 1)],
            ResolutionCompletion::Complete,
        );
        let answer = select_paths(
            reference,
            vec![far],
            vec![terminal],
            ResolutionCompletion::Complete,
            &CancellationToken::new(),
        );
        assert_eq!(answer.targets(), &[outer]);
        assert!(
            matches!(answer.completion(), ResolutionCompletion::Incomplete(reasons) if reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(unknown)))
        );
        assert!(
            answer
                .witnesses()
                .iter()
                .all(|witness| witness.target() != unknown)
        );
    }

    #[test]
    fn completed_namespace_blocker_dominates_outer_target_without_becoming_a_target() {
        let reference = semantic("go-blocked-reference");
        let blocker = semantic("go-local-type");
        let outer = semantic("go-outer-value");
        let choice = semantic("go-spelling-choice");
        let mut near = selection_completed(
            "near",
            blocker,
            vec![precedence(choice, 0)],
            ResolutionCompletion::Complete,
        );
        near.admission = BindingCandidateAdmission::WrongNamespaceBlocker;
        let far = selection_completed(
            "far",
            outer,
            vec![precedence(choice, 1)],
            ResolutionCompletion::Complete,
        );
        let answer = select_paths(
            reference,
            vec![near, far],
            Vec::new(),
            ResolutionCompletion::Complete,
            &CancellationToken::new(),
        );
        assert!(answer.targets().is_empty());
        assert_eq!(answer.completion(), &ResolutionCompletion::Complete);
        for (target, reason) in [
            (blocker, RejectionReason::WrongNamespace),
            (outer, RejectionReason::ShadowedByNearer),
        ] {
            assert!(answer.witnesses().iter().any(|witness| {
                witness.target() == target
                    && witness.steps().iter().any(|step| {
                        matches!(step,
                    WitnessStep::Candidate { semantic, outcome: CandidateOutcome::Rejected(actual) }
                    if *semantic == target && *actual == reason)
                    })
            }));
        }
    }

    #[test]
    fn nearer_target_dominates_outer_namespace_blocker() {
        let reference = semantic("go-near-reference");
        let local = semantic("go-local-value");
        let blocker = semantic("go-outer-type");
        let choice = semantic("go-spelling-choice");
        let near = selection_completed(
            "near",
            local,
            vec![precedence(choice, 0)],
            ResolutionCompletion::Complete,
        );
        let mut far = selection_completed(
            "far",
            blocker,
            vec![precedence(choice, 1)],
            ResolutionCompletion::Complete,
        );
        far.admission = BindingCandidateAdmission::WrongNamespaceBlocker;
        let answer = select_paths(
            reference,
            vec![near, far],
            Vec::new(),
            ResolutionCompletion::Complete,
            &CancellationToken::new(),
        );
        assert_eq!(answer.targets(), &[local]);
        assert_eq!(answer.completion(), &ResolutionCompletion::Complete);
    }

    #[test]
    fn cancelled_namespace_blocker_keeps_rejected_identity_without_affirmative_target() {
        let reference = semantic("go-cancelled-reference");
        let blocker = semantic("go-local-type");
        let outer = semantic("go-outer-value");
        let choice = semantic("go-spelling-choice");
        let mut near = selection_completed(
            "near",
            blocker,
            vec![precedence(choice, 0)],
            ResolutionCompletion::Complete,
        );
        near.admission = BindingCandidateAdmission::WrongNamespaceBlocker;
        let far = selection_completed(
            "far",
            outer,
            vec![precedence(choice, 1)],
            ResolutionCompletion::Complete,
        );
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let answer = select_paths(
            reference,
            vec![near, far],
            Vec::new(),
            ResolutionCompletion::Complete,
            &cancellation,
        );
        assert_eq!(answer.targets(), &[outer]);
        assert!(
            matches!(answer.completion(), ResolutionCompletion::Incomplete(reasons) if reasons.contains(&ResolutionIncompleteReason::Cancelled))
        );
        assert!(answer.witnesses().iter().any(|witness| {
            witness.target() == blocker && witness.steps().iter().any(|step| matches!(step,
                WitnessStep::Candidate { semantic, outcome: CandidateOutcome::Rejected(RejectionReason::WrongNamespace) }
                if *semantic == blocker))
        }));
    }

    #[test]
    fn precedence_shadows_across_targets_but_equal_rank_is_ambiguous() {
        let reference = semantic("reference");
        let local = semantic("local");
        let imported = semantic("imported");
        let peer = semantic("peer");
        let choice = semantic("choice");
        let local_node = node("local-node");
        let imported_node = node("imported-node");
        let peer_node = node("peer-node");
        let ranked_path = |target_node, tier| {
            path(
                node("reference-node"),
                target_node,
                Vec::new(),
                Vec::new(),
                vec![PrecedenceStep {
                    tier,
                    ordinal: 0,
                    semantic: choice,
                }],
            )
        };
        let source = source_with_paths(
            reference,
            &[
                (local, local_node),
                (imported, imported_node),
                (peer, peer_node),
            ],
            &[],
            vec![
                (
                    path_id("imported"),
                    ranked_path(imported_node, PrecedenceTier::ExplicitImport),
                ),
                (
                    path_id("peer"),
                    ranked_path(peer_node, PrecedenceTier::LexicalBinding),
                ),
                (
                    path_id("local"),
                    ranked_path(local_node, PrecedenceTier::LexicalBinding),
                ),
            ],
        );

        let answer = ResolutionEngine::new(&source)
            .resolve_reference(ResolutionQuery::new(reference), &CancellationToken::new())
            .expect("preloaded source is infallible");

        let mut expected = vec![local, peer];
        expected.sort_unstable();
        assert_eq!(answer.targets(), expected);
        assert!(answer.witnesses().iter().any(|witness| {
            witness.target() == imported
                && witness.steps().iter().any(|step| {
                    matches!(
                        step,
                        WitnessStep::Candidate {
                            outcome: CandidateOutcome::Rejected(RejectionReason::ShadowedByNearer),
                            ..
                        }
                    )
                })
        }));
    }

    #[test]
    fn cyclic_precedence_preserves_candidates_and_is_incomplete() {
        let reference = semantic("cyclic-precedence-reference");
        let first = semantic("first-target");
        let second = semantic("second-target");
        let first_node = node("first-target-node");
        let second_node = node("second-target-node");
        let outer_choice = semantic("outer-choice");
        let inner_choice = semantic("inner-choice");
        let step = |semantic, tier| PrecedenceStep {
            semantic,
            tier,
            ordinal: 0,
        };
        let source = source_with_paths(
            reference,
            &[(first, first_node), (second, second_node)],
            &[],
            vec![
                (
                    path_id("first-cyclic-precedence-path"),
                    path(
                        node("reference-node"),
                        first_node,
                        Vec::new(),
                        Vec::new(),
                        vec![
                            step(outer_choice, PrecedenceTier::LexicalBinding),
                            step(inner_choice, PrecedenceTier::ExplicitImport),
                        ],
                    ),
                ),
                (
                    path_id("second-cyclic-precedence-path"),
                    path(
                        node("reference-node"),
                        second_node,
                        Vec::new(),
                        Vec::new(),
                        vec![
                            step(inner_choice, PrecedenceTier::LexicalBinding),
                            step(outer_choice, PrecedenceTier::ExplicitImport),
                        ],
                    ),
                ),
            ],
        );

        let answer = ResolutionEngine::new(&source)
            .resolve_reference(ResolutionQuery::new(reference), &CancellationToken::new())
            .expect("preloaded source is infallible");

        let mut expected = vec![first, second];
        expected.sort_unstable();
        assert_eq!(answer.targets(), expected);
        assert!(matches!(
            answer.completion(),
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::InconsistentPrecedence(reference))
        ));
        assert!(answer.witnesses().iter().all(|witness| {
            witness.steps().iter().any(|step| {
                matches!(
                    step,
                    WitnessStep::Candidate {
                        outcome: CandidateOutcome::Selected,
                        ..
                    }
                )
            })
        }));
    }

    #[test]
    fn nontransitive_precedence_preserves_every_candidate() {
        let reference = semantic("nontransitive-precedence-reference");
        let maximal = semantic("maximal-target");
        let middle = semantic("middle-target");
        let independent = semantic("independent-target");
        let maximal_node = node("maximal-target-node");
        let middle_node = node("middle-target-node");
        let independent_node = node("independent-target-node");
        let outer_choice = semantic("nontransitive-outer-choice");
        let inner_choice = semantic("nontransitive-inner-choice");
        let step = |semantic, tier| PrecedenceStep {
            semantic,
            tier,
            ordinal: 0,
        };
        let source = source_with_paths(
            reference,
            &[
                (maximal, maximal_node),
                (middle, middle_node),
                (independent, independent_node),
            ],
            &[],
            vec![
                (
                    path_id("maximal-precedence-path"),
                    path(
                        node("reference-node"),
                        maximal_node,
                        Vec::new(),
                        Vec::new(),
                        vec![step(outer_choice, PrecedenceTier::LexicalBinding)],
                    ),
                ),
                (
                    path_id("middle-precedence-path"),
                    path(
                        node("reference-node"),
                        middle_node,
                        Vec::new(),
                        Vec::new(),
                        vec![
                            step(outer_choice, PrecedenceTier::ExplicitImport),
                            step(inner_choice, PrecedenceTier::LexicalBinding),
                        ],
                    ),
                ),
                (
                    path_id("independent-precedence-path"),
                    path(
                        node("reference-node"),
                        independent_node,
                        Vec::new(),
                        Vec::new(),
                        vec![step(inner_choice, PrecedenceTier::ExplicitImport)],
                    ),
                ),
            ],
        );

        let answer = ResolutionEngine::new(&source)
            .resolve_reference(ResolutionQuery::new(reference), &CancellationToken::new())
            .expect("preloaded source is infallible");

        let mut expected = vec![maximal, middle, independent];
        expected.sort_unstable();
        assert_eq!(answer.targets(), expected);
        assert!(matches!(
            answer.completion(),
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::InconsistentPrecedence(reference))
        ));
    }

    #[test]
    fn ordered_lookup_evidence_preserves_endpoints_and_relative_precedence() {
        let reference = semantic("ordered-lookup-reference");
        let target = semantic("ordered-lookup-target");
        let gap = semantic("ordered-lookup-gap");
        let build = |choice, first_rank, second_rank, second_label: &str, reverse_input| {
            let mut terminals = vec![
                selection_terminal("ordered-first", vec![precedence(choice, first_rank)], gap),
                selection_terminal(second_label, vec![precedence(choice, second_rank)], gap),
            ];
            if reverse_input {
                terminals.reverse();
            }
            select_paths(
                reference,
                vec![selection_completed(
                    "ordered-candidate",
                    target,
                    vec![precedence(choice, 1)],
                    ResolutionCompletion::Complete,
                )],
                terminals,
                ResolutionCompletion::Complete,
                &CancellationToken::new(),
            )
        };
        let first = build(semantic("choice-one"), 0, 2, "ordered-second", false);
        let reordered = build(semantic("choice-two"), 0, 2, "ordered-second", true);
        assert!(first.lookup_decision().is_some());
        assert_eq!(first.lookup_decision(), reordered.lookup_decision());
        assert!(
            matches!(first.lookup_decision().unwrap()[1], LookupAlternative::Target(found) if found == target)
        );
        // Identical observed targets and reason sets cannot erase these changes.
        for changed in [
            build(semantic("choice-one"), 2, 0, "ordered-second", false),
            build(semantic("choice-one"), 0, 2, "different-endpoint", false),
        ] {
            assert_eq!(first.targets(), changed.targets());
            assert_eq!(first.completion(), changed.completion());
            assert_ne!(first.lookup_decision(), changed.lookup_decision());
        }
        let tied = build(semantic("choice-one"), 0, 0, "ordered-second", false);
        assert!(tied.lookup_decision().is_none());
        let choice = semantic("duplicate-target-choice");
        let repeated_target = select_paths(
            reference,
            vec![
                selection_completed(
                    "near-target",
                    target,
                    vec![precedence(choice, 1)],
                    ResolutionCompletion::Complete,
                ),
                selection_completed(
                    "far-target",
                    target,
                    vec![precedence(choice, 2)],
                    ResolutionCompletion::Complete,
                ),
            ],
            vec![selection_terminal(
                "ordered-first",
                vec![precedence(choice, 0)],
                gap,
            )],
            ResolutionCompletion::Complete,
            &CancellationToken::new(),
        );
        assert_eq!(repeated_target.targets(), &[target]);
        assert_eq!(
            repeated_target.lookup_decision().unwrap().iter().filter(|alternative| matches!(alternative, LookupAlternative::Target(found) if *found == target)).count(),
            2,
            "distinct ordered paths to one target remain separate alternatives"
        );
        assert_eq!(first.clone_with_poll(&mut || false), Some(first.clone()));
        assert!(first.clone_with_poll(&mut || true).is_none());
    }

    #[test]
    fn affirmative_maximum_discharges_a_strictly_losing_terminal() {
        let reference = semantic("terminal-shadow-reference");
        let target = semantic("terminal-shadow-target");
        let choice = semantic("terminal-shadow-choice");
        let gap = semantic("terminal-shadow-gap");

        let answer = select_paths(
            reference,
            vec![selection_completed(
                "terminal-shadow-winner",
                target,
                vec![precedence(choice, 0)],
                ResolutionCompletion::Complete,
            )],
            vec![selection_terminal(
                "terminal-shadow-loser",
                vec![precedence(choice, 1)],
                gap,
            )],
            ResolutionCompletion::Complete,
            &CancellationToken::new(),
        );

        assert_eq!(answer.targets(), &[target]);
        assert_eq!(answer.completion(), &ResolutionCompletion::Complete);
    }

    #[test]
    fn tied_and_incomparable_terminals_remain_incomplete() {
        let reference = semantic("terminal-ambiguity-reference");
        let target = semantic("terminal-ambiguity-target");
        let choice = semantic("terminal-ambiguity-choice");
        let other_choice = semantic("terminal-ambiguity-other-choice");
        let tied_gap = semantic("terminal-tied-gap");
        let incomparable_gap = semantic("terminal-incomparable-gap");
        let completed = || {
            vec![selection_completed(
                "terminal-ambiguity-winner",
                target,
                vec![precedence(choice, 0)],
                ResolutionCompletion::Complete,
            )]
        };

        let tied = select_paths(
            reference,
            completed(),
            vec![selection_terminal(
                "terminal-tied",
                vec![precedence(choice, 0)],
                tied_gap,
            )],
            ResolutionCompletion::Complete,
            &CancellationToken::new(),
        );
        let incomparable = select_paths(
            reference,
            completed(),
            vec![selection_terminal(
                "terminal-incomparable",
                vec![precedence(other_choice, 0)],
                incomparable_gap,
            )],
            ResolutionCompletion::Complete,
            &CancellationToken::new(),
        );

        for (answer, gap) in [(tied, tied_gap), (incomparable, incomparable_gap)] {
            assert_eq!(answer.targets(), &[target]);
            assert!(matches!(
                answer.completion(),
                ResolutionCompletion::Incomplete(reasons)
                    if reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(gap))
            ));
        }
    }

    #[test]
    fn terminal_crossing_affirmative_maxima_cannot_be_discharged() {
        let reference = semantic("terminal-cross-max-reference");
        let first = semantic("terminal-cross-max-first");
        let second = semantic("terminal-cross-max-second");
        let first_choice = semantic("terminal-cross-max-first-choice");
        let second_choice = semantic("terminal-cross-max-second-choice");
        let gap = semantic("terminal-cross-max-gap");

        let answer = select_paths(
            reference,
            vec![
                selection_completed(
                    "terminal-cross-max-first",
                    first,
                    vec![precedence(first_choice, 1)],
                    ResolutionCompletion::Complete,
                ),
                selection_completed(
                    "terminal-cross-max-second",
                    second,
                    vec![precedence(second_choice, 0)],
                    ResolutionCompletion::Complete,
                ),
            ],
            vec![selection_terminal(
                "terminal-cross-max",
                vec![precedence(second_choice, 1), precedence(first_choice, 0)],
                gap,
            )],
            ResolutionCompletion::Complete,
            &CancellationToken::new(),
        );

        let mut expected = vec![first, second];
        expected.sort_unstable();
        assert_eq!(answer.targets(), expected);
        assert!(matches!(
            answer.completion(),
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(gap))
                    && reasons.contains(&ResolutionIncompleteReason::InconsistentPrecedence(reference))
        ));
    }

    #[test]
    fn augmented_nontransitivity_restores_affirmative_losers() {
        let reference = semantic("terminal-loser-chain-reference");
        let maximum = semantic("terminal-loser-chain-maximum");
        let loser = semantic("terminal-loser-chain-loser");
        let affirmative_choice = semantic("terminal-loser-chain-affirmative-choice");
        let terminal_choice = semantic("terminal-loser-chain-terminal-choice");
        let gap = semantic("terminal-loser-chain-gap");

        let answer = select_paths(
            reference,
            vec![
                selection_completed(
                    "terminal-loser-chain-maximum",
                    maximum,
                    vec![
                        precedence(affirmative_choice, 0),
                        precedence(terminal_choice, 1),
                    ],
                    ResolutionCompletion::Complete,
                ),
                selection_completed(
                    "terminal-loser-chain-loser",
                    loser,
                    vec![precedence(affirmative_choice, 1)],
                    ResolutionCompletion::Complete,
                ),
            ],
            vec![selection_terminal(
                "terminal-loser-chain-terminal",
                vec![precedence(terminal_choice, 0)],
                gap,
            )],
            ResolutionCompletion::Complete,
            &CancellationToken::new(),
        );

        let mut expected = vec![maximum, loser];
        expected.sort_unstable();
        assert_eq!(answer.targets(), expected);
        assert!(matches!(
            answer.completion(),
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(gap))
                    && reasons.contains(&ResolutionIncompleteReason::InconsistentPrecedence(reference))
        ));
    }

    #[test]
    fn terminal_restores_losers_from_an_already_nontransitive_affirmative_order() {
        let reference = semantic("terminal-existing-chain-reference");
        let maximum = semantic("terminal-existing-chain-maximum");
        let loser = semantic("terminal-existing-chain-loser");
        let independent = semantic("terminal-existing-chain-independent");
        let outer_choice = semantic("terminal-existing-chain-outer-choice");
        let inner_choice = semantic("terminal-existing-chain-inner-choice");
        let terminal_choice = semantic("terminal-existing-chain-terminal-choice");
        let gap = semantic("terminal-existing-chain-gap");

        let answer = select_paths(
            reference,
            vec![
                selection_completed(
                    "terminal-existing-chain-maximum",
                    maximum,
                    vec![precedence(outer_choice, 0), precedence(terminal_choice, 1)],
                    ResolutionCompletion::Complete,
                ),
                selection_completed(
                    "terminal-existing-chain-loser",
                    loser,
                    vec![precedence(outer_choice, 1), precedence(inner_choice, 0)],
                    ResolutionCompletion::Complete,
                ),
                selection_completed(
                    "terminal-existing-chain-independent",
                    independent,
                    vec![precedence(inner_choice, 1)],
                    ResolutionCompletion::Complete,
                ),
            ],
            vec![selection_terminal(
                "terminal-existing-chain-terminal",
                vec![precedence(terminal_choice, 0)],
                gap,
            )],
            ResolutionCompletion::Complete,
            &CancellationToken::new(),
        );

        let mut expected = vec![maximum, loser, independent];
        expected.sort_unstable();
        assert_eq!(answer.targets(), expected);
        assert!(matches!(
            answer.completion(),
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(gap))
                    && reasons.contains(&ResolutionIncompleteReason::InconsistentPrecedence(reference))
        ));
    }

    #[test]
    fn bidirectional_affirmative_terminal_cycle_remains_incomplete() {
        let reference = semantic("terminal-bidirectional-reference");
        let target = semantic("terminal-bidirectional-target");
        let first_choice = semantic("terminal-bidirectional-first-choice");
        let second_choice = semantic("terminal-bidirectional-second-choice");
        let gap = semantic("terminal-bidirectional-gap");

        let answer = select_paths(
            reference,
            vec![selection_completed(
                "terminal-bidirectional-affirmative",
                target,
                vec![precedence(first_choice, 0), precedence(second_choice, 1)],
                ResolutionCompletion::Complete,
            )],
            vec![selection_terminal(
                "terminal-bidirectional-terminal",
                vec![precedence(second_choice, 0), precedence(first_choice, 1)],
                gap,
            )],
            ResolutionCompletion::Complete,
            &CancellationToken::new(),
        );

        assert_eq!(answer.targets(), &[target]);
        assert!(matches!(
            answer.completion(),
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(gap))
                    && reasons.contains(&ResolutionIncompleteReason::InconsistentPrecedence(reference))
        ));
    }

    #[test]
    fn terminal_terminal_cycle_below_a_maximum_remains_incomplete() {
        let reference = semantic("terminal-cycle-reference");
        let target = semantic("terminal-cycle-target");
        let maximum_choice = semantic("terminal-cycle-maximum-choice");
        let left_choice = semantic("terminal-cycle-left-choice");
        let right_choice = semantic("terminal-cycle-right-choice");
        let first_gap = semantic("terminal-cycle-first-gap");
        let second_gap = semantic("terminal-cycle-second-gap");

        let answer = select_paths(
            reference,
            vec![selection_completed(
                "terminal-cycle-maximum",
                target,
                vec![precedence(maximum_choice, 0)],
                ResolutionCompletion::Complete,
            )],
            vec![
                selection_terminal(
                    "terminal-cycle-first",
                    vec![
                        precedence(maximum_choice, 1),
                        precedence(left_choice, 0),
                        precedence(right_choice, 1),
                    ],
                    first_gap,
                ),
                selection_terminal(
                    "terminal-cycle-second",
                    vec![
                        precedence(maximum_choice, 1),
                        precedence(right_choice, 0),
                        precedence(left_choice, 1),
                    ],
                    second_gap,
                ),
            ],
            ResolutionCompletion::Complete,
            &CancellationToken::new(),
        );

        assert_eq!(answer.targets(), &[target]);
        assert!(matches!(
            answer.completion(),
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(first_gap))
                    && reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(second_gap))
                    && reasons.contains(&ResolutionIncompleteReason::InconsistentPrecedence(reference))
        ));
    }

    #[test]
    fn losing_affirmative_completion_is_discharged_with_its_path() {
        let reference = semantic("losing-completion-reference");
        let winner = semantic("losing-completion-winner");
        let loser = semantic("losing-completion-loser");
        let choice = semantic("losing-completion-choice");
        let gap = semantic("losing-completion-gap");

        let answer = select_paths(
            reference,
            vec![
                selection_completed(
                    "losing-completion-winner",
                    winner,
                    vec![precedence(choice, 0)],
                    ResolutionCompletion::Complete,
                ),
                selection_completed(
                    "losing-completion-loser",
                    loser,
                    vec![precedence(choice, 1)],
                    ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(gap),
                    ]),
                ),
            ],
            Vec::new(),
            ResolutionCompletion::Complete,
            &CancellationToken::new(),
        );

        assert_eq!(answer.targets(), &[winner]);
        assert_eq!(answer.completion(), &ResolutionCompletion::Complete);
        assert!(answer.witnesses().iter().any(|witness| {
            witness.target() == loser
                && matches!(
                    witness.completion(),
                    ResolutionCompletion::Incomplete(reasons)
                        if reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(gap))
                )
        }));
    }

    #[test]
    fn cancellation_preserves_every_affirmative_and_branch_reason() {
        let reference = semantic("terminal-cancel-reference");
        let first = semantic("terminal-cancel-first");
        let second = semantic("terminal-cancel-second");
        let choice = semantic("terminal-cancel-choice");
        let affirmative_gap = semantic("terminal-cancel-affirmative-gap");
        let terminal_gap = semantic("terminal-cancel-terminal-gap");
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let answer = select_paths(
            reference,
            vec![
                selection_completed(
                    "terminal-cancel-first",
                    first,
                    vec![precedence(choice, 0)],
                    ResolutionCompletion::Complete,
                ),
                selection_completed(
                    "terminal-cancel-second",
                    second,
                    vec![precedence(choice, 1)],
                    ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(affirmative_gap),
                    ]),
                ),
            ],
            vec![selection_terminal(
                "terminal-cancel-terminal",
                vec![precedence(choice, 2)],
                terminal_gap,
            )],
            ResolutionCompletion::Complete,
            &cancellation,
        );

        let mut expected = vec![first, second];
        expected.sort_unstable();
        assert_eq!(answer.targets(), expected);
        assert!(matches!(
            answer.completion(),
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::Cancelled)
                    && reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(affirmative_gap))
                    && reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(terminal_gap))
        ));
    }

    #[test]
    fn reverse_generation_is_forward_validated_for_cross_target_shadowing() {
        let reference = semantic("shadowed-reference");
        let local = semantic("local");
        let imported = semantic("imported");
        let choice = semantic("choice");
        let local_node = node("local-node");
        let imported_node = node("imported-node");
        let source = source_with_paths(
            reference,
            &[(local, local_node), (imported, imported_node)],
            &[],
            vec![
                (
                    path_id("local"),
                    path(
                        node("reference-node"),
                        local_node,
                        Vec::new(),
                        Vec::new(),
                        vec![PrecedenceStep {
                            tier: PrecedenceTier::LexicalBinding,
                            ordinal: 0,
                            semantic: choice,
                        }],
                    ),
                ),
                (
                    path_id("imported"),
                    path(
                        node("reference-node"),
                        imported_node,
                        Vec::new(),
                        Vec::new(),
                        vec![PrecedenceStep {
                            tier: PrecedenceTier::ExplicitImport,
                            ordinal: 0,
                            semantic: choice,
                        }],
                    ),
                ),
            ],
        );

        let references = ResolutionEngine::new(&source)
            .references_to(imported, &CancellationToken::new())
            .expect("preloaded source is infallible");

        assert!(references.references().is_empty());
        assert!(references.witnesses().is_empty());
        assert_eq!(references.completion(), &ResolutionCompletion::Complete);
    }

    #[test]
    fn stack_neutral_cycles_are_certified_complete() {
        let reference = semantic("reference");
        let target = semantic("target");
        let target_node = node("target-node");
        let loop_node = node("loop-node");
        let source = source_with_paths(
            reference,
            &[(target, target_node)],
            &[loop_node],
            vec![
                (
                    path_id("enter"),
                    path(
                        node("reference-node"),
                        loop_node,
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                    ),
                ),
                (
                    path_id("cycle"),
                    path(loop_node, loop_node, Vec::new(), Vec::new(), Vec::new()),
                ),
                (
                    path_id("exit"),
                    path(loop_node, target_node, Vec::new(), Vec::new(), Vec::new()),
                ),
            ],
        );

        let answer = ResolutionEngine::new(&source)
            .resolve_reference(ResolutionQuery::new(reference), &CancellationToken::new())
            .expect("preloaded source is infallible");

        assert_eq!(answer.targets(), &[target]);
        assert_eq!(answer.completion(), &ResolutionCompletion::Complete);
    }

    #[test]
    fn productive_cycles_terminate_without_proving_a_negative() {
        let reference = semantic("productive-reference");
        let target = semantic("productive-target");
        let target_node = node("productive-target-node");
        let loop_node = node("productive-loop-node");
        let tail = StackVariableId::for_test("productive-tail");
        let push = PartialPath::new(
            EndpointSignature::new_scoped(
                loop_node,
                StackPattern::open(Vec::new(), tail),
                StackPattern::closed(Vec::new()),
            ),
            EndpointSignature::new_scoped(
                loop_node,
                StackPattern::open(
                    [PartialScopedSymbol::unscoped(semantic("pushed-name"))],
                    tail,
                ),
                StackPattern::closed(Vec::new()),
            ),
            Vec::new(),
            Vec::new(),
            ResolutionCompletion::Complete,
        );
        let source = source_with_paths(
            reference,
            &[(target, target_node)],
            &[loop_node],
            vec![
                (
                    path_id("productive-enter"),
                    path(
                        node("reference-node"),
                        loop_node,
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                    ),
                ),
                (path_id("productive-cycle"), push),
                (
                    path_id("productive-exit"),
                    path(loop_node, target_node, Vec::new(), Vec::new(), Vec::new()),
                ),
            ],
        );

        let answer = ResolutionEngine::new(&source)
            .resolve_reference(ResolutionQuery::new(reference), &CancellationToken::new())
            .expect("preloaded source is infallible");

        assert_eq!(answer.targets(), &[target]);
        assert!(matches!(
            answer.completion(),
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::CyclicExpansion(
                    path_id("productive-cycle")
                ))
        ));
    }

    #[test]
    fn cancellation_is_polled_by_work_not_time_and_returns_incomplete() {
        let reference = semantic("reference");
        let target = semantic("target");
        let target_node = node("target-node");
        let junctions = (0..40)
            .map(|index| node(&format!("junction-{index}")))
            .collect::<Vec<_>>();
        let mut paths = Vec::new();
        let mut start = node("reference-node");
        for (index, end) in junctions.iter().copied().enumerate() {
            paths.push((
                path_id(&format!("segment-{index}")),
                path(start, end, Vec::new(), Vec::new(), Vec::new()),
            ));
            start = end;
        }
        paths.push((
            path_id("last"),
            path(start, target_node, Vec::new(), Vec::new(), Vec::new()),
        ));
        let source = source_with_paths(reference, &[(target, target_node)], &junctions, paths);
        let cancellation = CancellationToken::cancel_after_checks_for_test(2);

        let answer = ResolutionEngine::new(&source)
            .resolve_reference(ResolutionQuery::new(reference), &cancellation)
            .expect("preloaded source is infallible");

        assert!(answer.targets().is_empty());
        assert!(matches!(
            answer.completion(),
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::Cancelled)
        ));
    }

    #[test]
    fn cancellation_at_an_empty_lookup_boundary_cannot_prove_absence() {
        let reference = semantic("empty-cancelled-reference");
        let reference_node = node("empty-cancelled-reference-node");
        let source = PreloadedFragmentSource::new(
            [(reference_node, BindingNodeKind::Reference(reference))],
            [],
        );
        // The initial check observes a live request. The publication-boundary
        // check observes cancellation after the zero-candidate lookup.
        let cancellation = CancellationToken::cancel_after_checks_for_test(2);

        let answer = ResolutionEngine::new(&source)
            .resolve_reference(ResolutionQuery::new(reference), &cancellation)
            .expect("preloaded source is infallible");

        assert!(answer.targets().is_empty());
        assert!(matches!(
            answer.completion(),
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::Cancelled)
        ));
    }

    #[test]
    fn cancellation_during_selector_work_preserves_candidates() {
        let reference = semantic("selection-cancelled-reference");
        let choice = semantic("selection-cancelled-choice");
        let definitions = (0..40)
            .map(|index| {
                (
                    semantic(&format!("selection-target-{index}")),
                    node(&format!("selection-target-node-{index}")),
                )
            })
            .collect::<Vec<_>>();
        let paths = definitions
            .iter()
            .enumerate()
            .map(|(index, (_, target_node))| {
                (
                    path_id(&format!("selection-path-{index}")),
                    path(
                        node("reference-node"),
                        *target_node,
                        Vec::new(),
                        Vec::new(),
                        vec![PrecedenceStep {
                            semantic: choice,
                            tier: if index == 0 {
                                PrecedenceTier::LexicalBinding
                            } else {
                                PrecedenceTier::ExplicitImport
                            },
                            ordinal: 0,
                        }],
                    ),
                )
            })
            .collect::<Vec<_>>();
        let source = source_with_paths(reference, &definitions, &[], paths);
        // Cancellation may be observed while materializing or comparing the
        // selector inputs; either edge must return the same full snapshot.
        let cancellation = CancellationToken::cancel_after_checks_for_test(8);

        let answer = ResolutionEngine::new(&source)
            .resolve_reference(ResolutionQuery::new(reference), &cancellation)
            .expect("preloaded source is infallible");

        assert_eq!(answer.targets().len(), definitions.len());
        assert!(matches!(
            answer.completion(),
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::Cancelled)
        ));
    }

    #[test]
    fn selector_polls_inside_one_large_witness_and_keeps_the_full_snapshot() {
        let reference = semantic("large-selector-witness-reference");
        let target = semantic("large-selector-witness-target");
        let target_node = node("large-selector-witness-target-node");
        let witness_node = node("large-selector-witness-node");
        let completed = vec![CompletedPath {
            admission: BindingCandidateAdmission::Target,
            target,
            path: PartialPath::new(
                endpoint(node("large-selector-witness-reference-node"), Vec::new()),
                endpoint(target_node, Vec::new()),
                Vec::new(),
                std::iter::repeat_n(WitnessStep::Node(witness_node), CANCELLATION_QUANTUM + 1)
                    .collect::<Vec<_>>(),
                ResolutionCompletion::Complete,
            ),
        }];
        // The seventh token observation occurs inside the witness row loop.
        // Conservative construction must continue observationally and publish
        // the complete in-memory snapshot, never a witness prefix.
        let cancellation = CancellationToken::cancel_after_checks_for_test(7);

        let answer = select_paths(
            reference,
            completed,
            Vec::new(),
            ResolutionCompletion::Complete,
            &cancellation,
        );

        assert_eq!(answer.targets(), &[target]);
        assert_eq!(answer.witnesses().len(), 1);
        assert_eq!(
            answer.witnesses()[0].steps().len(),
            CANCELLATION_QUANTUM + 2,
            "the conservative witness includes every path step and its candidate outcome"
        );
        assert!(matches!(
            answer.completion(),
            ResolutionCompletion::Incomplete(reasons)
                if reasons.get(0) == Some(&ResolutionIncompleteReason::Cancelled)
        ));
    }

    #[test]
    fn dominance_comparison_polls_inside_one_large_precedence_trace() {
        let left_choice = semantic("large-dominance-left-choice");
        let right_choice = semantic("large-dominance-right-choice");
        let left = path(
            node("large-dominance-left-start"),
            node("large-dominance-left-end"),
            Vec::new(),
            Vec::new(),
            (0..=CANCELLATION_QUANTUM)
                .map(|ordinal| PrecedenceStep {
                    semantic: left_choice,
                    tier: PrecedenceTier::LexicalBinding,
                    ordinal: u32::try_from(ordinal)
                        .expect("the cancellation quantum fits a precedence ordinal"),
                })
                .collect(),
        );
        let right = path(
            node("large-dominance-right-start"),
            node("large-dominance-right-end"),
            Vec::new(),
            Vec::new(),
            [PrecedenceStep {
                semantic: right_choice,
                tier: PrecedenceTier::LexicalBinding,
                ordinal: 0,
            }]
            .into(),
        );
        let cancellation = CancellationToken::cancel_after_checks_for_test(1);
        let mut work = 0_usize;

        assert!(
            path_shadows_with_poll(&left, &right, &cancellation, &mut work).is_none(),
            "one deep dominance comparison must yield to cancellation"
        );
        assert!(work >= CANCELLATION_QUANTUM);
    }

    #[test]
    fn traversal_only_completion_evidence_is_invisible_without_cancellation() {
        let reference = semantic("selector-transient-evidence-reference");
        let target = semantic("selector-transient-evidence-target");
        let evidence = ResolutionIncompleteReason::UnsupportedSemantic(semantic(
            "selector-transient-evidence-gap",
        ));

        let answer = select_paths_with_cancellation_evidence(
            reference,
            vec![selection_completed(
                "selector-transient-evidence-path",
                target,
                Vec::new(),
                ResolutionCompletion::Complete,
            )],
            Vec::new(),
            ResolutionCompletion::Complete,
            ResolutionCompletion::incomplete([evidence]),
            &CancellationToken::new(),
        );

        assert_eq!(answer.targets(), &[target]);
        assert_eq!(answer.completion(), &ResolutionCompletion::Complete);
    }

    #[test]
    fn preload_row_order_does_not_change_results() {
        let reference = semantic("reference");
        let first = semantic("first");
        let second = semantic("second");
        let first_node = node("first-node");
        let second_node = node("second-node");
        let rows = vec![
            (
                path_id("first"),
                path(
                    node("reference-node"),
                    first_node,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
            ),
            (
                path_id("second"),
                path(
                    node("reference-node"),
                    second_node,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
            ),
        ];
        let forward = source_with_paths(
            reference,
            &[(first, first_node), (second, second_node)],
            &[],
            rows.clone(),
        );
        let reverse = source_with_paths(
            reference,
            &[(first, first_node), (second, second_node)],
            &[],
            rows.into_iter().rev().collect(),
        );
        let cancellation = CancellationToken::new();

        let forward_answer = ResolutionEngine::new(&forward)
            .resolve_reference(ResolutionQuery::new(reference), &cancellation)
            .expect("preloaded source is infallible");
        let reverse_answer = ResolutionEngine::new(&reverse)
            .resolve_reference(ResolutionQuery::new(reference), &cancellation)
            .expect("preloaded source is infallible");

        assert_eq!(forward_answer, reverse_answer);
    }

    #[test]
    fn equivalent_route_order_does_not_change_the_replay_witness() {
        let reference = semantic("equivalent-route-reference");
        let target = semantic("equivalent-route-target");
        let target_node = node("equivalent-route-target-node");
        let seam = node("equivalent-route-seam");
        let reference_node = node("reference-node");
        let direct = PartialPath::new(
            endpoint(reference_node, Vec::new()),
            endpoint(seam, Vec::new()),
            Vec::new(),
            [WitnessStep::Node(seam)],
            ResolutionCompletion::Complete,
        );
        let repeated = PartialPath::new(
            endpoint(reference_node, Vec::new()),
            endpoint(seam, Vec::new()),
            Vec::new(),
            [WitnessStep::Node(seam), WitnessStep::Node(seam)],
            ResolutionCompletion::Complete,
        );
        let exit = path(seam, target_node, Vec::new(), Vec::new(), Vec::new());
        let make_source = |direct_id, repeated_id| {
            source_with_paths(
                reference,
                &[(target, target_node)],
                &[seam],
                vec![
                    (direct_id, direct.clone()),
                    (repeated_id, repeated.clone()),
                    (path_id("equivalent-route-exit"), exit.clone()),
                ],
            )
        };
        let direct_first = make_source(path_id("a-direct"), path_id("b-repeated"));
        let repeated_first = make_source(path_id("b-direct"), path_id("a-repeated"));

        let first = ResolutionEngine::new(&direct_first)
            .resolve_reference(ResolutionQuery::new(reference), &CancellationToken::new())
            .expect("preloaded source is infallible");
        let second = ResolutionEngine::new(&repeated_first)
            .resolve_reference(ResolutionQuery::new(reference), &CancellationToken::new())
            .expect("preloaded source is infallible");

        assert_eq!(first, second);
        assert_eq!(first.targets(), &[target]);
    }

    #[test]
    fn typed_copy_rule_preserves_value_category_addressability_and_indirection() {
        let source_slot = semantic("source-slot");
        let target_slot = semantic("target-slot");
        let ty = semantic("Receiver");
        let source = PreloadedFragmentSource::new([], []).with_type_transfer_rules([(
            source_slot,
            TypeTransferRule::new(
                semantic("copy-rule"),
                target_slot,
                1,
                TypeTransferValueTransform::Preserve,
                ResolutionCompletion::Complete,
            ),
        )]);
        let input = TypedFrontierState::new(
            source_slot,
            [
                ResolutionSlotValue::type_object(ResolutionTypeRef::new(ty, 0)),
                ResolutionSlotValue::runtime(ResolutionTypeRef::new(ty, 0), false),
                ResolutionSlotValue::runtime(ResolutionTypeRef::new(ty, 0), true),
                ResolutionSlotValue::runtime(ResolutionTypeRef::new(ty, 2), false),
            ],
            ResolutionCompletion::Complete,
        );

        let (alternatives, completion) = ResolutionEngine::new(&source)
            .transfer_types(&input, &CancellationToken::new())
            .expect("preloaded source is infallible");

        assert_eq!(completion, ResolutionCompletion::Complete);
        assert_eq!(alternatives.len(), 1);
        assert_eq!(alternatives[0].slot(), target_slot);
        assert_eq!(
            alternatives[0].possible_values(),
            &[
                ResolutionSlotValue::type_object(ResolutionTypeRef::new(ty, 1)),
                ResolutionSlotValue::runtime(ResolutionTypeRef::new(ty, 1), false),
                ResolutionSlotValue::runtime(ResolutionTypeRef::new(ty, 1), true),
                ResolutionSlotValue::runtime(ResolutionTypeRef::new(ty, 3), false),
            ]
        );
    }

    #[test]
    fn typed_copy_rule_omits_invalid_siblings_and_preserves_all_incompleteness() {
        let source_slot = semantic("incomplete-source-slot");
        let result_slot = semantic("result-slot");
        let incoming_gap = semantic("upstream-gap");
        let rule_gap = semantic("rule-gap");
        let rule_semantic = semantic("decrement-rule");
        let ty = semantic("Receiver");
        let source = PreloadedFragmentSource::new([], []).with_type_transfer_rules([(
            source_slot,
            TypeTransferRule::new(
                rule_semantic,
                result_slot,
                -1,
                TypeTransferValueTransform::Preserve,
                ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(rule_gap),
                ]),
            ),
        )]);
        let input = TypedFrontierState::new(
            source_slot,
            [
                ResolutionSlotValue::runtime(ResolutionTypeRef::new(ty, 0), false),
                ResolutionSlotValue::runtime(ResolutionTypeRef::new(ty, 1), true),
            ],
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                incoming_gap,
            )]),
        );

        let (alternatives, completion) = ResolutionEngine::new(&source)
            .transfer_types(&input, &CancellationToken::new())
            .expect("preloaded source is infallible");

        assert_eq!(alternatives.len(), 1);
        assert_eq!(
            alternatives[0].possible_values(),
            &[ResolutionSlotValue::runtime(
                ResolutionTypeRef::new(ty, 0),
                true,
            )]
        );
        assert!(matches!(
            alternatives[0].completion(),
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(incoming_gap))
                    && reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(rule_gap))
                    && reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(rule_semantic))
        ));
        assert_eq!(alternatives[0].completion(), &completion);
    }

    #[test]
    fn typed_copy_rule_overflow_emits_no_value_and_names_the_rule_gap() {
        let source_slot = semantic("overflow-source-slot");
        let target_slot = semantic("overflow-target-slot");
        let rule_semantic = semantic("increment-overflow-rule");
        let source = PreloadedFragmentSource::new([], []).with_type_transfer_rules([(
            source_slot,
            TypeTransferRule::new(
                rule_semantic,
                target_slot,
                1,
                TypeTransferValueTransform::Preserve,
                ResolutionCompletion::Complete,
            ),
        )]);
        let input = TypedFrontierState::new(
            source_slot,
            [ResolutionSlotValue::runtime(
                ResolutionTypeRef::new(semantic("Receiver"), u32::MAX),
                false,
            )],
            ResolutionCompletion::Complete,
        );

        let (alternatives, completion) = ResolutionEngine::new(&source)
            .transfer_types(&input, &CancellationToken::new())
            .expect("preloaded source is infallible");

        assert_eq!(alternatives.len(), 1);
        assert!(alternatives[0].possible_values().is_empty());
        assert!(matches!(
            completion,
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(rule_semantic))
        ));
    }

    #[test]
    fn typed_copy_rule_empty_input_produces_an_honest_empty_target_state() {
        let source_slot = semantic("empty-source-slot");
        let target_slot = semantic("empty-target-slot");
        let source = PreloadedFragmentSource::new([], []).with_type_transfer_rules([(
            source_slot,
            TypeTransferRule::new(
                semantic("empty-copy-rule"),
                target_slot,
                0,
                TypeTransferValueTransform::Preserve,
                ResolutionCompletion::Complete,
            ),
        )]);
        let input =
            TypedFrontierState::new(source_slot, Vec::new(), ResolutionCompletion::Complete);

        let (alternatives, completion) = ResolutionEngine::new(&source)
            .transfer_types(&input, &CancellationToken::new())
            .expect("preloaded source is infallible");

        assert_eq!(completion, ResolutionCompletion::Complete);
        assert_eq!(alternatives.len(), 1);
        assert_eq!(alternatives[0].slot(), target_slot);
        assert!(alternatives[0].possible_values().is_empty());
        assert_eq!(
            alternatives[0].completion(),
            &ResolutionCompletion::Complete
        );
    }

    #[test]
    fn typed_no_value_rule_discards_inputs_without_claiming_an_adjustment_gap() {
        let source_slot = semantic("void-type-slot");
        let target_slot = semantic("void-call-result-slot");
        let source = PreloadedFragmentSource::new([], []).with_type_transfer_rules([(
            source_slot,
            TypeTransferRule::new(
                semantic("void-copy-rule"),
                target_slot,
                0,
                TypeTransferValueTransform::ToNoValue,
                ResolutionCompletion::Complete,
            ),
        )]);
        let input = TypedFrontierState::new(
            source_slot,
            [
                ResolutionSlotValue::type_object(ResolutionTypeRef::new(semantic("void"), 0)),
                ResolutionSlotValue::runtime(
                    ResolutionTypeRef::new(semantic("adversarial-void-runtime"), u32::MAX),
                    true,
                ),
            ],
            ResolutionCompletion::Complete,
        );

        let (alternatives, completion) = ResolutionEngine::new(&source)
            .transfer_types(&input, &CancellationToken::new())
            .expect("preloaded source is infallible");

        assert_eq!(completion, ResolutionCompletion::Complete);
        assert_eq!(alternatives.len(), 1);
        assert_eq!(alternatives[0].slot(), target_slot);
        assert!(alternatives[0].possible_values().is_empty());
        assert_eq!(
            alternatives[0].completion(),
            &ResolutionCompletion::Complete
        );
    }

    #[test]
    fn cancellation_at_an_empty_transfer_boundary_is_propagated() {
        let input = TypedFrontierState::new(
            semantic("empty-transfer-slot"),
            [runtime_type("Receiver")],
            ResolutionCompletion::Complete,
        );
        let cancellation = CancellationToken::cancel_after_checks_for_test(2);

        let (alternatives, completion) = ResolutionEngine::new(&PreloadedFragmentSource::default())
            .transfer_types(&input, &cancellation)
            .expect("preloaded source is infallible");

        assert!(alternatives.is_empty());
        assert!(matches!(
            completion,
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::Cancelled)
        ));
    }

    #[test]
    fn compatibility_transfer_cancellation_discards_prefix_and_keeps_all_rule_evidence() {
        let source_slot = semantic("compat-cancel-source");
        let incoming_gap = semantic("compat-cancel-incoming-gap");
        let rule_gap = semantic("compat-cancel-rule-gap");
        let source =
            PreloadedFragmentSource::new([], []).with_type_transfer_rules((0..64).map(|ordinal| {
                (
                    source_slot,
                    TypeTransferRule::new(
                        semantic(&format!("compat-cancel-rule-{ordinal}")),
                        semantic(&format!("compat-cancel-target-{ordinal}")),
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
        let input = TypedFrontierState::new(
            source_slot,
            [runtime_type("Receiver")],
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                incoming_gap,
            )]),
        );
        let cancellation = CancellationToken::cancel_after_checks_for_test(3);

        let (alternatives, completion) = ResolutionEngine::new(&source)
            .transfer_types(&input, &cancellation)
            .expect("preloaded source is infallible");

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
    fn broad_stream_resolves_each_reference_once_without_a_graph_allocation() {
        let first_reference = semantic("first-reference");
        let second_reference = semantic("second-reference");
        let target = semantic("target");
        let first_node = node("first-reference-node");
        let second_node = node("second-reference-node");
        let target_node = node("target-node");
        let source = PreloadedFragmentSource::new(
            [
                (first_node, BindingNodeKind::Reference(first_reference)),
                (second_node, BindingNodeKind::Reference(second_reference)),
                (target_node, BindingNodeKind::Definition(target)),
            ],
            [
                (
                    path_id("first-path"),
                    path(first_node, target_node, Vec::new(), Vec::new(), Vec::new()),
                ),
                (
                    path_id("second-path"),
                    path(second_node, target_node, Vec::new(), Vec::new(), Vec::new()),
                ),
            ],
        );
        let mut edges = Vec::new();

        let completion = ResolutionEngine::new(&source)
            .stream_all_references(
                &CancellationToken::new(),
                &mut |reference, definition, witnesses| {
                    assert!(!witnesses.is_empty());
                    edges.push((reference, definition));
                },
            )
            .expect("preloaded source is infallible");

        edges.sort_unstable();
        let mut expected = vec![(first_reference, target), (second_reference, target)];
        expected.sort_unstable();
        assert_eq!(edges, expected);
        assert_eq!(completion, ResolutionCompletion::Complete);
        assert_eq!(
            ResolutionQuery::new(first_reference).reference(),
            first_reference
        );
    }
}
