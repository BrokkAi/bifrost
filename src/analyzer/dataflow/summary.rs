//! Demand-driven in-memory summary tabulation.

use std::cmp::Ordering;
use std::collections::VecDeque;
use std::sync::Arc;

use crate::analyzer::semantic::{
    CallBoundary, CallSiteHandle, CallTransfer, CallTransferSet, ControlContinuation,
    EvidenceCompleteness, IcfgEdgeKind, IcfgExitProfile, IcfgProvider, MatchedReturnProjection,
    ProcedureHandle, ProcedureIcfgBoundary, ProcedureIcfgEdge, ProgramPointHandle, ProgramPointId,
    ProofStatus, SemanticBudget, SemanticOutcome, SemanticProviderError, SemanticRequest,
    SemanticWork, compare_relation_provenance,
};
use crate::hash::{HashMap, HashSet};

use super::transfer::{TransferEvaluation, TransferScratch, evaluate_transfer};
use super::witness::{
    WitnessAdmission, WitnessAlternatives, WitnessArena, WitnessCandidateBudget, WitnessEvidenceId,
    WitnessEvidenceNode, WitnessStaging,
};
use super::{
    DataflowEdge, DataflowRequest, DistributiveDataflowProblem, FactId, PathQuality,
    PathQualityFrontier, SolverTermination, SolverWork, SummaryBoundary, SummaryBoundaryKind,
    SummaryCoverage, SummaryDataflowError, SummaryDataflowResult, SummaryEdge, SummaryEntry,
    SummaryMetrics, SummaryReachedFact, SummarySemanticStatus, TabulationEndSummary,
    WitnessRetentionLimits,
};

const ZERO_FACT_ID: FactId = FactId::new(0);

type CachedCallOutcome = Arc<SemanticOutcome<CallTransferSet>>;
type CachedExitOutcome = Arc<SemanticOutcome<Arc<IcfgExitProfile>>>;
type ExitCacheKey = (ProcedureHandle, ProgramPointId, ProgramPointId);
type ProviderCacheLookup<T> = Result<(T, bool), SolverTermination>;

/// One validated reusable entry-to-exit relation remapped into live facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReusableEndSummary<Fact> {
    pub exit_kind: crate::analyzer::semantic::ReturnTransferKind,
    pub exit_fact: Fact,
    pub qualities: Box<[PathQuality]>,
}

/// One query-visible internal observation retained by a reusable summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReusableReachedFact<Fact> {
    pub point: ProgramPointHandle,
    pub fact: Fact,
    pub qualities: Box<[PathQuality]>,
}

/// Complete reusable relation for one exact callee entry fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReusableProcedureSummary<Fact> {
    pub exits: Box<[ReusableEndSummary<Fact>]>,
    pub reached: Box<[ReusableReachedFact<Fact>]>,
}

/// Optional cross-query summary oracle used by the query-local tabulator.
///
/// A provider must reserve the callback/output work needed to materialize a
/// returned summary through `request` before allocating its returned rows.
/// Cancellation, exhausted work, or invalid cache state must fail closed. The
/// returned relation must be context-independent for the exact procedure and
/// entry fact: query-local tabulation intentionally deduplicates entries by
/// that identity. Context-sensitive clients must decline reuse until their
/// context is represented in a future solver-level entry key.
pub trait ReusableSummaryProvider<Fact> {
    fn summary_for(
        &mut self,
        procedure: &ProcedureHandle,
        entry_fact: Fact,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<ReusableProcedureSummary<Fact>>, SolverTermination>;
}

struct NoReusableSummaries;

impl<Fact> ReusableSummaryProvider<Fact> for NoReusableSummaries {
    fn summary_for(
        &mut self,
        _procedure: &ProcedureHandle,
        _entry_fact: Fact,
        _request: &mut DataflowRequest<'_>,
    ) -> Result<Option<ReusableProcedureSummary<Fact>>, SolverTermination> {
        Ok(None)
    }
}

/// One root procedure and its explicit entry facts for a summary solve.
///
/// The root's declared entry point is implicit. The distinguished zero fact is
/// always added as its own relative entry relation.
#[derive(Debug, Clone, Copy)]
pub struct SummarySolveInput<'input, Fact> {
    root: &'input ProcedureHandle,
    entry_facts: &'input [Fact],
    witness_retention: WitnessRetentionLimits,
}

impl<'input, Fact> SummarySolveInput<'input, Fact> {
    pub const fn new(root: &'input ProcedureHandle, entry_facts: &'input [Fact]) -> Self {
        Self {
            root,
            entry_facts,
            witness_retention: WitnessRetentionLimits::disabled(),
        }
    }

    pub const fn root(self) -> &'input ProcedureHandle {
        self.root
    }

    pub const fn entry_facts(self) -> &'input [Fact] {
        self.entry_facts
    }

    pub const fn with_witness_retention(
        mut self,
        witness_retention: WitnessRetentionLimits,
    ) -> Self {
        self.witness_retention = witness_retention;
        self
    }

    pub const fn witness_retention(self) -> WitnessRetentionLimits {
        self.witness_retention
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct EntryKey {
    procedure: usize,
    entry_point: ProgramPointId,
    entry_fact: FactId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct PathEdgeKey {
    entry: EntryKey,
    point: ProgramPointId,
    fact: FactId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct QueuedPath {
    key: PathEdgeKey,
    quality: PathQuality,
    evidence: Option<WitnessEvidenceId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct EndSummaryKey {
    entry: EntryKey,
    exit_point: ProgramPointId,
    exit_fact: FactId,
}

#[derive(Debug, Clone)]
struct EndSummaryRow {
    key: EndSummaryKey,
    exit: Arc<IcfgExitProfile>,
    qualities: PathQualityFrontier,
    witnesses: WitnessAlternatives,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct IncomingKey {
    callee: EntryKey,
    caller: EntryKey,
    call_point: ProgramPointId,
    call_fact: FactId,
    transfer_index: usize,
}

#[derive(Debug, Clone)]
struct IncomingCall {
    key: IncomingKey,
    origin: CallSiteHandle,
    qualities: PathQualityFrontier,
    witnesses: WitnessAlternatives,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MatchedReturnCacheKey {
    origin: CallSiteHandle,
    transfer_index: usize,
    callee_entry: ProgramPointHandle,
    callee_exit: ProgramPointHandle,
}

#[derive(Debug)]
enum CachedMatchedReturnProjection {
    Edge(Arc<SummaryEdge>),
    Absent,
    Boundary(ProcedureIcfgBoundary),
}

struct StagedFacts<Fact> {
    new_facts: Vec<(Fact, FactId)>,
    ids: Vec<FactId>,
}

enum PathWitnessSource<'edge> {
    Edge {
        predecessor: WitnessEvidenceId,
        predecessor_quality: PathQuality,
        edge: &'edge ProcedureIcfgEdge,
        input_fact: FactId,
    },
    SummaryApplication {
        incoming: WitnessEvidenceId,
        incoming_quality: PathQuality,
        summary: WitnessEvidenceId,
        summary_quality: PathQuality,
        return_edge: &'edge SummaryEdge,
        input_fact: FactId,
    },
    ReusableSummaryApplication {
        incoming: WitnessEvidenceId,
        incoming_quality: PathQuality,
        summary_quality: PathQuality,
        return_edge: &'edge SummaryEdge,
        input_fact: FactId,
    },
}

impl PathWitnessSource<'_> {
    fn quality(&self) -> PathQuality {
        match self {
            Self::Edge {
                predecessor_quality,
                edge,
                ..
            } => predecessor_quality.through_evidence(&edge.proof, &edge.completeness),
            Self::SummaryApplication {
                incoming_quality,
                summary_quality,
                return_edge,
                ..
            }
            | Self::ReusableSummaryApplication {
                incoming_quality,
                summary_quality,
                return_edge,
                ..
            } => incoming_quality
                .conjoin(*summary_quality)
                .through_evidence(return_edge.proof(), return_edge.completeness()),
        }
    }

    fn retained_bytes(&self) -> usize {
        match self {
            Self::Edge { edge, .. } => WitnessEvidenceNode::edge_retained_bytes(edge),
            Self::SummaryApplication { return_edge, .. } => {
                WitnessEvidenceNode::summary_application_retained_bytes(return_edge)
            }
            Self::ReusableSummaryApplication { return_edge, .. } => {
                WitnessEvidenceNode::reusable_summary_application_retained_bytes(return_edge)
            }
        }
    }

    fn evidence_for(&self, output_fact: FactId) -> WitnessEvidenceNode {
        match self {
            Self::Edge {
                predecessor,
                predecessor_quality,
                edge,
                input_fact,
            } => WitnessEvidenceNode::edge(
                *predecessor,
                *predecessor_quality,
                edge,
                *input_fact,
                output_fact,
            ),
            Self::SummaryApplication {
                incoming,
                incoming_quality,
                summary,
                summary_quality,
                return_edge,
                input_fact,
            } => WitnessEvidenceNode::summary_application(
                *incoming,
                *incoming_quality,
                *summary,
                *summary_quality,
                return_edge,
                *input_fact,
                output_fact,
            ),
            Self::ReusableSummaryApplication {
                incoming,
                incoming_quality,
                summary_quality,
                return_edge,
                input_fact,
            } => WitnessEvidenceNode::reusable_summary_application(
                *incoming,
                *incoming_quality,
                *summary_quality,
                return_edge,
                *input_fact,
                output_fact,
            ),
        }
    }

    fn matches_derivation(&self, output_fact: FactId, existing: &WitnessEvidenceNode) -> bool {
        match self {
            Self::Edge {
                predecessor,
                predecessor_quality,
                edge,
                input_fact,
            } => existing.matches_edge_derivation(
                *predecessor,
                *predecessor_quality,
                edge,
                *input_fact,
                output_fact,
            ),
            Self::SummaryApplication {
                incoming,
                incoming_quality,
                summary,
                summary_quality,
                return_edge,
                input_fact,
            } => existing.matches_summary_application_derivation(
                *incoming,
                *incoming_quality,
                *summary,
                *summary_quality,
                return_edge,
                *input_fact,
                output_fact,
            ),
            Self::ReusableSummaryApplication {
                incoming,
                incoming_quality,
                summary_quality,
                return_edge,
                input_fact,
            } => existing.matches_reusable_summary_application_derivation(
                *incoming,
                *incoming_quality,
                *summary_quality,
                return_edge,
                *input_fact,
                output_fact,
            ),
        }
    }
}

struct StagedPathPublication {
    key: PathEdgeKey,
    frontier: PathQualityFrontier,
    frontier_changed: bool,
    witnesses: WitnessAlternatives,
    witnesses_changed: bool,
    queued_evidence: Option<WitnessEvidenceId>,
}

struct StagedIncomingPublication {
    key: IncomingKey,
    existing: Option<usize>,
    frontier: PathQualityFrontier,
    witnesses: WitnessAlternatives,
    frontier_changed: bool,
    witnesses_changed: bool,
    reused_entry: bool,
    activated_evidence: Option<WitnessEvidenceId>,
}

struct SummaryState<Fact> {
    zero_fact: Fact,
    facts: Vec<Fact>,
    fact_ids: HashMap<Fact, FactId>,
    procedures: Vec<ProcedureHandle>,
    procedure_ids: HashMap<ProcedureHandle, usize>,
    reached: HashMap<PathEdgeKey, PathQualityFrontier>,
    path_witnesses: HashMap<PathEdgeKey, WitnessAlternatives>,
    worklist: VecDeque<QueuedPath>,
    summaries: Vec<EndSummaryRow>,
    summary_ids: HashMap<EndSummaryKey, usize>,
    summaries_by_entry: HashMap<EntryKey, Vec<usize>>,
    incoming: Vec<IncomingCall>,
    incoming_ids: HashMap<IncomingKey, usize>,
    incoming_by_entry: HashMap<EntryKey, Vec<usize>>,
    reusable_entries: HashSet<EntryKey>,
    call_cache: HashMap<CallSiteHandle, CachedCallOutcome>,
    exit_cache: HashMap<ExitCacheKey, CachedExitOutcome>,
    call_to_return_cache: HashMap<CallSiteHandle, Arc<[ProcedureIcfgEdge]>>,
    matched_return_cache: HashMap<MatchedReturnCacheKey, Arc<CachedMatchedReturnProjection>>,
    transfer_scratch: TransferScratch<Fact>,
    unproven_edges: HashSet<Arc<SummaryEdge>>,
    partial_edges: HashSet<Arc<SummaryEdge>>,
    boundaries: HashSet<SummaryBoundary>,
    metrics: SummaryMetrics,
    witness_arena: WitnessArena,
    best_effort_witness_retention: bool,
    witness_retention_truncated: bool,
}

impl<Fact> SummaryState<Fact>
where
    Fact: Copy + Eq + std::hash::Hash + Ord,
{
    fn new(zero_fact: Fact, witness_retention: WitnessRetentionLimits) -> Self {
        let best_effort_witness_retention = witness_retention.is_best_effort();
        Self {
            zero_fact,
            facts: Vec::new(),
            fact_ids: HashMap::default(),
            procedures: Vec::new(),
            procedure_ids: HashMap::default(),
            reached: HashMap::default(),
            path_witnesses: HashMap::default(),
            worklist: VecDeque::new(),
            summaries: Vec::new(),
            summary_ids: HashMap::default(),
            summaries_by_entry: HashMap::default(),
            incoming: Vec::new(),
            incoming_ids: HashMap::default(),
            incoming_by_entry: HashMap::default(),
            reusable_entries: HashSet::default(),
            call_cache: HashMap::default(),
            exit_cache: HashMap::default(),
            call_to_return_cache: HashMap::default(),
            matched_return_cache: HashMap::default(),
            transfer_scratch: TransferScratch::new(),
            unproven_edges: HashSet::default(),
            partial_edges: HashSet::default(),
            boundaries: HashSet::default(),
            metrics: SummaryMetrics::default(),
            witness_arena: WitnessArena::new(witness_retention),
            best_effort_witness_retention,
            witness_retention_truncated: false,
        }
    }

    fn abandon_best_effort_witnesses(&mut self) {
        debug_assert!(self.best_effort_witness_retention);
        self.witness_retention_truncated = true;
        self.witness_arena = WitnessArena::new(WitnessRetentionLimits::disabled());
        self.path_witnesses.clear();
        for queued in &mut self.worklist {
            queued.evidence = None;
        }
        for incoming in &mut self.incoming {
            incoming.witnesses = WitnessAlternatives::default();
        }
        for summary in &mut self.summaries {
            summary.witnesses = WitnessAlternatives::default();
        }
    }

    fn mark_reusable_witnesses_omitted(&mut self) {
        debug_assert!(self.best_effort_witness_retention);
        self.witness_retention_truncated = true;
    }

    fn reserve_publication(
        &mut self,
        mut required: SolverWork,
        witness_relations: usize,
        request: &mut DataflowRequest<'_>,
    ) -> Option<SolverTermination> {
        debug_assert_eq!(required.witness_relations, 0);
        if witness_relations == 0 || !self.witness_arena.is_enabled() {
            return request.reserve(required);
        }
        if self.best_effort_witness_retention {
            return match request.reserve_optional_witness_relations(required, witness_relations) {
                Ok(true) => None,
                Ok(false) => {
                    self.abandon_best_effort_witnesses();
                    None
                }
                Err(termination) => Some(termination),
            };
        }
        required.witness_relations = witness_relations;
        request.reserve(required)
    }

    fn request_witness_staging_capacity(&self, request: &DataflowRequest<'_>) -> Option<usize> {
        self.best_effort_witness_retention
            .then(|| request.remaining_witness_relations())
    }

    fn initialize(
        &mut self,
        input: SummarySolveInput<'_, Fact>,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<SolverTermination>, SummaryDataflowError> {
        if request.cancellation.is_cancelled() {
            return Ok(Some(SolverTermination::Cancelled));
        }

        let root = self.intern_procedure(input.root().clone());
        let entry_point = input
            .root()
            .point_handle(input.root().semantics().entry_point())
            .ok_or_else(|| {
                SemanticProviderError::internal("summary root procedure has no entry point")
            })?;

        let mut unique_seeds = HashSet::default();
        unique_seeds.insert(self.zero_fact);
        let mut callback_rows = 0usize;
        if let Err(exceeded) = request.budget.check(SolverWork {
            interned_facts: 1,
            reached_states: 1,
            ..SolverWork::default()
        }) {
            return Ok(Some(SolverTermination::ExceededBudget(exceeded)));
        }
        for &seed in input.entry_facts() {
            if request.cancellation.is_cancelled() {
                return Ok(Some(SolverTermination::Cancelled));
            }
            callback_rows = callback_rows.saturating_add(1);
            let prospective_facts = unique_seeds.len() + usize::from(!unique_seeds.contains(&seed));
            if let Err(exceeded) = request.budget.check(SolverWork {
                interned_facts: prospective_facts,
                reached_states: prospective_facts,
                callback_rows,
                ..SolverWork::default()
            }) {
                return Ok(Some(SolverTermination::ExceededBudget(exceeded)));
            }
            unique_seeds.insert(seed);
        }

        unique_seeds.remove(&self.zero_fact);
        let mut explicit = unique_seeds.into_iter().collect::<Vec<_>>();
        explicit.sort_unstable();

        let mut staged_facts = Vec::with_capacity(explicit.len().saturating_add(1));
        let mut staged_fact_ids = HashMap::default();
        staged_facts.push(self.zero_fact);
        staged_fact_ids.insert(self.zero_fact, ZERO_FACT_ID);
        for seed in explicit {
            let index = staged_facts.len();
            let id = FactId::try_from_index(index)
                .map_err(|_| SummaryDataflowError::FactIdOverflow { index })?;
            staged_facts.push(seed);
            staged_fact_ids.insert(seed, id);
        }

        let staged_states = staged_facts
            .iter()
            .enumerate()
            .map(|(index, _)| {
                let fact = FactId::try_from_index(index)
                    .expect("prevalidated root fact index remains representable");
                PathEdgeKey {
                    entry: EntryKey {
                        procedure: root,
                        entry_point: entry_point.id(),
                        entry_fact: fact,
                    },
                    point: entry_point.id(),
                    fact,
                }
            })
            .collect::<Vec<_>>();
        let mut staged_witness_nodes = Vec::new();
        let mut staged_witness_bytes = 0usize;
        let mut staged_witnesses = Vec::with_capacity(staged_states.len());
        let mut witness_exhausted = false;
        for key in &staged_states {
            if request.cancellation.is_cancelled() {
                return Ok(Some(SolverTermination::Cancelled));
            }
            if self.witness_arena.is_enabled() {
                let mut alternatives = WitnessAlternatives::default();
                let admission = self
                    .witness_arena
                    .stage_candidate(
                        &mut alternatives,
                        PathQuality::PROVEN_COMPLETE,
                        WitnessCandidateBudget::new(
                            WitnessEvidenceNode::seed_retained_bytes(),
                            self.request_witness_staging_capacity(request),
                        ),
                        |existing| existing.matches_seed_derivation(&entry_point, key.fact),
                        || WitnessEvidenceNode::seed(entry_point.clone(), key.fact),
                        WitnessStaging::new(&mut staged_witness_nodes, &mut staged_witness_bytes),
                    )
                    .map_err(|index| SummaryDataflowError::WitnessEvidenceIdOverflow { index })?;
                match admission {
                    WitnessAdmission::Retained(id) => {
                        debug_assert_eq!(
                            alternatives.first(PathQuality::PROVEN_COMPLETE),
                            Some(id)
                        );
                        staged_witnesses.push(Some(alternatives));
                    }
                    WitnessAdmission::Exhausted if self.best_effort_witness_retention => {
                        witness_exhausted = true;
                        break;
                    }
                    WitnessAdmission::Duplicate
                    | WitnessAdmission::Truncated
                    | WitnessAdmission::Exhausted => {
                        return Err(SummaryDataflowError::WitnessInvariant(
                            "new root seed did not retain witness evidence",
                        ));
                    }
                }
            } else {
                staged_witnesses.push(None);
            }
        }
        if witness_exhausted {
            self.abandon_best_effort_witnesses();
            staged_witness_nodes.clear();
            staged_witnesses.clear();
            staged_witnesses.resize_with(staged_states.len(), || None);
        }

        if let Some(termination) = self.reserve_publication(
            SolverWork {
                interned_facts: staged_facts.len(),
                reached_states: staged_states.len(),
                callback_rows,
                ..SolverWork::default()
            },
            staged_witness_nodes.len(),
            request,
        ) {
            return Ok(Some(termination));
        }

        self.facts = staged_facts;
        self.fact_ids = staged_fact_ids;
        if self.witness_arena.is_enabled() {
            for (id, node) in staged_witness_nodes {
                self.witness_arena.commit(id, node);
            }
        }
        for (key, witnesses) in staged_states.into_iter().zip(staged_witnesses) {
            let quality = PathQuality::PROVEN_COMPLETE;
            self.reached
                .insert(key, PathQualityFrontier::singleton(quality));
            let witnesses = self
                .witness_arena
                .is_enabled()
                .then_some(witnesses)
                .flatten();
            let evidence = witnesses
                .as_ref()
                .and_then(|alternatives| alternatives.first(quality));
            if let Some(witnesses) = witnesses {
                self.path_witnesses.insert(key, witnesses);
            }
            self.worklist.push_back(QueuedPath {
                key,
                quality,
                evidence,
            });
        }
        Ok(None)
    }

    fn intern_procedure(&mut self, procedure: ProcedureHandle) -> usize {
        if let Some(index) = self.procedure_ids.get(&procedure).copied() {
            return index;
        }
        let index = self.procedures.len();
        self.procedures.push(procedure.clone());
        self.procedure_ids.insert(procedure, index);
        index
    }

    fn stage_facts(
        &self,
        outputs: &[Fact],
        request: &DataflowRequest<'_>,
    ) -> Result<Option<StagedFacts<Fact>>, SummaryDataflowError> {
        if request.cancellation.is_cancelled() {
            return Ok(None);
        }
        let mut new_facts = Vec::new();
        let mut ids = Vec::with_capacity(outputs.len());
        for &output in outputs {
            if request.cancellation.is_cancelled() {
                return Ok(None);
            }
            if let Some(id) = self.fact_ids.get(&output).copied() {
                ids.push(id);
                continue;
            }
            let index = self.facts.len().saturating_add(new_facts.len());
            let id = FactId::try_from_index(index)
                .map_err(|_| SummaryDataflowError::FactIdOverflow { index })?;
            new_facts.push((output, id));
            ids.push(id);
        }
        Ok(Some(StagedFacts { new_facts, ids }))
    }

    fn commit_facts(&mut self, staged: Vec<(Fact, FactId)>) {
        for (fact, id) in staged {
            let expected = FactId::try_from_index(self.facts.len())
                .expect("prevalidated fact index remains representable");
            debug_assert_eq!(id, expected);
            let replaced = self.fact_ids.insert(fact, id);
            debug_assert!(replaced.is_none(), "staged facts are unique");
            self.facts.push(fact);
        }
    }

    fn publish_path_outputs(
        &mut self,
        entry: EntryKey,
        target: ProgramPointId,
        quality: PathQuality,
        outputs: &[Fact],
        witness_source: Option<PathWitnessSource<'_>>,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<SolverTermination>, SummaryDataflowError> {
        let Some(staged) = self.stage_facts(outputs, request)? else {
            return Ok(Some(SolverTermination::Cancelled));
        };
        let mut staged_states = Vec::new();
        let mut staged_witness_nodes = Vec::new();
        let mut staged_witness_bytes = 0usize;
        let mut new_reached_states = 0;
        let mut witness_exhausted = false;

        for &fact in &staged.ids {
            if request.cancellation.is_cancelled() {
                return Ok(Some(SolverTermination::Cancelled));
            }
            let key = PathEdgeKey {
                entry,
                point: target,
                fact,
            };
            let existing = self.reached.get(&key).copied();
            let mut prospective = existing.unwrap_or_default();
            let frontier_changed = prospective.insert(quality);
            let mut witnesses = self.path_witnesses.get(&key).cloned().unwrap_or_default();
            let before_witnesses = witnesses.clone();
            if frontier_changed {
                witnesses.retain_frontier(prospective);
            }

            let mut queued_evidence = None;
            if self.witness_arena.is_enabled() && prospective.contains(quality) {
                let source =
                    witness_source
                        .as_ref()
                        .ok_or(SummaryDataflowError::WitnessInvariant(
                            "enabled witness publication has no derivation",
                        ))?;
                if source.quality() != quality {
                    return Err(SummaryDataflowError::WitnessInvariant(
                        "candidate witness quality does not match path publication",
                    ));
                }
                let admission = self
                    .witness_arena
                    .stage_candidate(
                        &mut witnesses,
                        quality,
                        WitnessCandidateBudget::new(
                            source.retained_bytes(),
                            self.request_witness_staging_capacity(request),
                        ),
                        |existing| source.matches_derivation(fact, existing),
                        || source.evidence_for(fact),
                        WitnessStaging::new(&mut staged_witness_nodes, &mut staged_witness_bytes),
                    )
                    .map_err(|index| SummaryDataflowError::WitnessEvidenceIdOverflow { index })?;
                match admission {
                    WitnessAdmission::Retained(id) => queued_evidence = Some(id),
                    WitnessAdmission::Exhausted if self.best_effort_witness_retention => {
                        witness_exhausted = true;
                    }
                    WitnessAdmission::Duplicate | WitnessAdmission::Truncated => {}
                    WitnessAdmission::Exhausted => {
                        return Err(SummaryDataflowError::WitnessInvariant(
                            "strict witness retention exhausted without a solver budget",
                        ));
                    }
                }
            }

            if frontier_changed && existing.is_none() {
                new_reached_states += 1;
            }
            if frontier_changed
                && self.witness_arena.is_enabled()
                && queued_evidence.is_none()
                && !witness_exhausted
            {
                return Err(SummaryDataflowError::WitnessInvariant(
                    "new path quality did not retain witness evidence",
                ));
            }
            let witnesses_changed = witnesses != before_witnesses;
            if frontier_changed || witnesses_changed {
                staged_states.push(StagedPathPublication {
                    key,
                    frontier: prospective,
                    frontier_changed,
                    witnesses,
                    witnesses_changed,
                    queued_evidence,
                });
            }
        }

        if witness_exhausted {
            self.abandon_best_effort_witnesses();
            staged_witness_nodes.clear();
        }
        if let Some(termination) = self.reserve_publication(
            SolverWork {
                interned_facts: staged.new_facts.len(),
                reached_states: new_reached_states,
                callback_rows: outputs.len(),
                propagated_outputs: outputs.len(),
                ..SolverWork::default()
            },
            staged_witness_nodes.len(),
            request,
        ) {
            return Ok(Some(termination));
        }

        self.commit_facts(staged.new_facts);
        if self.witness_arena.is_enabled() {
            for (id, node) in staged_witness_nodes {
                self.witness_arena.commit(id, node);
            }
        }
        for publication in staged_states {
            if self.witness_arena.is_enabled() {
                self.witness_arena
                    .mark_alternatives_truncated(&publication.witnesses);
            }
            if publication.frontier_changed {
                self.reached.insert(publication.key, publication.frontier);
            }
            if self.witness_arena.is_enabled() && publication.witnesses_changed {
                self.path_witnesses
                    .insert(publication.key, publication.witnesses);
            }
            let evidence = self
                .witness_arena
                .is_enabled()
                .then_some(publication.queued_evidence)
                .flatten();
            if publication.frontier_changed && !self.witness_arena.is_enabled()
                || evidence.is_some()
            {
                self.worklist.push_back(QueuedPath {
                    key: publication.key,
                    quality,
                    evidence,
                });
            }
        }
        Ok(None)
    }

    fn observe_edge(
        &mut self,
        edge: &ProcedureIcfgEdge,
        request: &mut DataflowRequest<'_>,
    ) -> Option<SolverTermination> {
        if request.cancellation.is_cancelled() {
            return Some(SolverTermination::Cancelled);
        }
        if matches!(edge.proof, ProofStatus::Proven)
            && matches!(edge.completeness, EvidenceCompleteness::Complete)
        {
            return None;
        }
        self.observe_summary_edge(Arc::new(SummaryEdge::from_procedure_edge(edge)), request)
    }

    fn observe_summary_edge(
        &mut self,
        row: Arc<SummaryEdge>,
        request: &mut DataflowRequest<'_>,
    ) -> Option<SolverTermination> {
        if request.cancellation.is_cancelled() {
            return Some(SolverTermination::Cancelled);
        }
        if matches!(row.proof(), ProofStatus::Proven)
            && matches!(row.completeness(), EvidenceCompleteness::Complete)
        {
            return None;
        }
        let retain_unproven = !matches!(row.proof(), ProofStatus::Proven)
            && !self.unproven_edges.contains(row.as_ref());
        let retain_partial = !matches!(row.completeness(), EvidenceCompleteness::Complete)
            && !self.partial_edges.contains(row.as_ref());
        let new_rows = usize::from(retain_unproven) + usize::from(retain_partial);
        if let Some(termination) = reserve_coverage_rows(new_rows, request) {
            return Some(termination);
        }
        if retain_unproven {
            self.unproven_edges.insert(Arc::clone(&row));
        }
        if retain_partial {
            self.partial_edges.insert(row);
        }
        None
    }

    fn observe_boundary(
        &mut self,
        boundary: ProcedureIcfgBoundary,
        request: &mut DataflowRequest<'_>,
    ) -> Option<SolverTermination> {
        self.retain_boundary(SummaryBoundary::from_procedure_boundary(boundary), request)
    }

    fn retain_boundary(
        &mut self,
        boundary: SummaryBoundary,
        request: &mut DataflowRequest<'_>,
    ) -> Option<SolverTermination> {
        if request.cancellation.is_cancelled() {
            return Some(SolverTermination::Cancelled);
        }
        if self.boundaries.contains(&boundary) {
            return None;
        }
        if let Some(termination) = reserve_coverage_rows(1, request) {
            return Some(termination);
        }
        self.boundaries.insert(boundary);
        None
    }

    fn observe_semantic_outcome<T>(
        &mut self,
        at: &ProgramPointHandle,
        origin: Option<CallSiteHandle>,
        outcome: &SemanticOutcome<T>,
        request: &mut DataflowRequest<'_>,
    ) -> Option<SolverTermination> {
        let status = SummarySemanticStatus::from_outcome(outcome);
        if !status.is_complete() {
            return self.retain_boundary(
                SummaryBoundary::new(at.clone(), origin, SummaryBoundaryKind::Semantic(status)),
                request,
            );
        }
        None
    }

    fn reserve_provider_materialization(
        &mut self,
        request: &mut DataflowRequest<'_>,
    ) -> Option<SolverTermination> {
        if let Some(termination) = request.reserve(SolverWork {
            provider_materializations: 1,
            ..SolverWork::default()
        }) {
            return Some(termination);
        }
        self.metrics.provider_materializations =
            self.metrics.provider_materializations.saturating_add(1);
        None
    }

    fn cached_call_transfers<Provider>(
        &mut self,
        provider: &Provider,
        point: &ProgramPointHandle,
        call: crate::analyzer::semantic::CallSiteId,
        semantic_budget: &mut SemanticBudget,
        request: &mut DataflowRequest<'_>,
    ) -> Result<ProviderCacheLookup<CachedCallOutcome>, SummaryDataflowError>
    where
        Provider: IcfgProvider + ?Sized,
    {
        if request.cancellation.is_cancelled() {
            return Ok(Err(SolverTermination::Cancelled));
        }
        let origin = point
            .procedure()
            .call_site_handle(call)
            .ok_or_else(|| SemanticProviderError::internal("failed to scope summary call"))?;
        if let Some(cached) = self.call_cache.get(&origin) {
            self.metrics.provider_cache_hits = self.metrics.provider_cache_hits.saturating_add(1);
            return Ok(Ok((Arc::clone(cached), false)));
        }
        if let Some(termination) = self.reserve_provider_materialization(request) {
            return Ok(Err(termination));
        }
        let mut semantic_request = SemanticRequest::new(semantic_budget, request.cancellation);
        let outcome = provider
            .call_transfers(point.procedure(), call, &mut semantic_request)?
            .map(canonicalize_call_transfer_set);
        if let Some(transfers) = outcome.available_value() {
            let semantic_call = point
                .procedure()
                .semantics()
                .call_site(call)
                .ok_or_else(|| {
                    SemanticProviderError::internal("summary invoke event has no call row")
                })?;
            crate::analyzer::semantic::icfg::validate_call_transfer_set(
                point.procedure(),
                semantic_call,
                transfers,
            )?;
        }
        let outcome = Arc::new(outcome);
        self.call_cache.insert(origin, Arc::clone(&outcome));
        Ok(Ok((outcome, true)))
    }

    fn cached_exit_profile<Provider>(
        &mut self,
        provider: &Provider,
        entry: &ProgramPointHandle,
        point: &ProgramPointHandle,
        semantic_budget: &mut SemanticBudget,
        request: &mut DataflowRequest<'_>,
    ) -> Result<ProviderCacheLookup<CachedExitOutcome>, SummaryDataflowError>
    where
        Provider: IcfgProvider + ?Sized,
    {
        if request.cancellation.is_cancelled() {
            return Ok(Err(SolverTermination::Cancelled));
        }
        let cache_key = (point.procedure().clone(), entry.id(), point.id());
        if let Some(cached) = self.exit_cache.get(&cache_key) {
            self.metrics.provider_cache_hits = self.metrics.provider_cache_hits.saturating_add(1);
            return Ok(Ok((Arc::clone(cached), false)));
        }
        if let Some(termination) = self.reserve_provider_materialization(request) {
            return Ok(Err(termination));
        }
        let mut semantic_request = SemanticRequest::new(semantic_budget, request.cancellation);
        let outcome = provider.exit_profile(entry, point, &mut semantic_request)?;
        if let Some(profile) = outcome.available_value() {
            crate::analyzer::semantic::icfg::validate_exit_profile(entry, point, profile)?;
        }
        let outcome = Arc::new(outcome.map(Arc::new));
        self.exit_cache.insert(cache_key, Arc::clone(&outcome));
        Ok(Ok((outcome, true)))
    }

    fn propagate<P, Provider, Reusable>(
        &mut self,
        provider: &Provider,
        reusable: &mut Reusable,
        problem: &P,
        semantic_budget: &mut SemanticBudget,
        request: &mut DataflowRequest<'_>,
    ) -> Result<SolverTermination, SummaryDataflowError>
    where
        P: DistributiveDataflowProblem<Fact = Fact>,
        Provider: IcfgProvider + ?Sized,
        Reusable: ReusableSummaryProvider<Fact> + ?Sized,
    {
        while let Some(queued) = self.worklist.pop_front() {
            if request.cancellation.is_cancelled() {
                return Ok(SolverTermination::Cancelled);
            }
            if queued.key.point == queued.key.entry.entry_point
                && self.reusable_entries.contains(&queued.key.entry)
            {
                continue;
            }
            let frontier = *self
                .reached
                .get(&queued.key)
                .expect("queued summary paths remain in the reached table");
            if !frontier.contains(queued.quality) {
                continue;
            }
            match (self.witness_arena.is_enabled(), queued.evidence) {
                (true, Some(evidence))
                    if self
                        .path_witnesses
                        .get(&queued.key)
                        .is_some_and(|witnesses| witnesses.contains(queued.quality, evidence)) => {}
                (true, _) => {
                    return Err(SummaryDataflowError::WitnessInvariant(
                        "queued path does not have active witness evidence",
                    ));
                }
                (false, Some(_)) => {
                    return Err(SummaryDataflowError::WitnessInvariant(
                        "disabled witness retention queued an evidence ID",
                    ));
                }
                (false, None) => {}
            }

            let procedure = self.procedures[queued.key.entry.procedure].clone();
            let point = procedure.point_handle(queued.key.point).ok_or_else(|| {
                SemanticProviderError::internal("summary worklist point is stale")
            })?;
            let fact = self.facts[queued.key.fact.index()];

            if is_procedure_exit(&point) {
                if let Some(termination) =
                    self.process_exit(provider, &point, queued, problem, semantic_budget, request)?
                {
                    return Ok(termination);
                }
                continue;
            }

            if let Some(call) = crate::analyzer::semantic::icfg::invoked_call_at(&point)? {
                if let Some(termination) = self.process_call(
                    provider,
                    reusable,
                    problem,
                    &point,
                    call,
                    queued,
                    fact,
                    semantic_budget,
                    request,
                )? {
                    return Ok(termination);
                }
            } else if let Some(termination) =
                self.process_local_edges(problem, &point, queued, None, request)?
            {
                return Ok(termination);
            }
        }
        if request.cancellation.is_cancelled() {
            Ok(SolverTermination::Cancelled)
        } else {
            Ok(SolverTermination::FixedPoint)
        }
    }

    fn process_exit<P, Provider>(
        &mut self,
        provider: &Provider,
        point: &ProgramPointHandle,
        queued: QueuedPath,
        problem: &P,
        semantic_budget: &mut SemanticBudget,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<SolverTermination>, SummaryDataflowError>
    where
        P: DistributiveDataflowProblem<Fact = Fact>,
        Provider: IcfgProvider + ?Sized,
    {
        let entry = point
            .procedure()
            .point_handle(queued.key.entry.entry_point)
            .ok_or_else(|| SemanticProviderError::internal("summary entry point is stale"))?;
        let (outcome, newly_materialized) =
            match self.cached_exit_profile(provider, &entry, point, semantic_budget, request)? {
                Ok(outcome) => outcome,
                Err(termination) => return Ok(Some(termination)),
            };
        if newly_materialized
            && let Some(termination) =
                self.observe_semantic_outcome(point, None, outcome.as_ref(), request)
        {
            return Ok(Some(termination));
        }
        if matches!(outcome.as_ref(), SemanticOutcome::Cancelled { .. })
            || request.cancellation.is_cancelled()
        {
            return Ok(Some(SolverTermination::Cancelled));
        }
        let Some(exit) = outcome.available_value().cloned() else {
            return Ok(None);
        };
        self.publish_end_summary(
            queued.key,
            exit,
            queued.quality,
            queued.evidence,
            problem,
            request,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn process_call<P, Provider, Reusable>(
        &mut self,
        provider: &Provider,
        reusable: &mut Reusable,
        problem: &P,
        point: &ProgramPointHandle,
        call: crate::analyzer::semantic::CallSiteId,
        queued: QueuedPath,
        fact: Fact,
        semantic_budget: &mut SemanticBudget,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<SolverTermination>, SummaryDataflowError>
    where
        P: DistributiveDataflowProblem<Fact = Fact>,
        Provider: IcfgProvider + ?Sized,
        Reusable: ReusableSummaryProvider<Fact> + ?Sized,
    {
        let caller = point.procedure();
        let semantic_call = caller.semantics().call_site(call).ok_or_else(|| {
            SemanticProviderError::internal("summary invoke event has no call row")
        })?;
        let origin = caller
            .call_site_handle(call)
            .ok_or_else(|| SemanticProviderError::internal("failed to scope summary invoke"))?;
        let (outcome, newly_materialized) =
            match self.cached_call_transfers(provider, point, call, semantic_budget, request)? {
                Ok(outcome) => outcome,
                Err(termination) => return Ok(Some(termination)),
            };
        if newly_materialized
            && let Some(termination) = self.observe_semantic_outcome(
                point,
                Some(origin.clone()),
                outcome.as_ref(),
                request,
            )
        {
            return Ok(Some(termination));
        }
        if matches!(outcome.as_ref(), SemanticOutcome::Cancelled { .. })
            || request.cancellation.is_cancelled()
        {
            return Ok(Some(SolverTermination::Cancelled));
        }

        if let Some(transfers) = outcome.available_value() {
            let call_to_return_edges = if newly_materialized {
                let mut projected_edges = Vec::new();
                for boundary in &transfers.boundaries {
                    if request.cancellation.is_cancelled() {
                        return Ok(Some(SolverTermination::Cancelled));
                    }
                    if let Some(termination) = self.retain_boundary(
                        SummaryBoundary::from_dispatch(
                            point.clone(),
                            boundary.origin.clone(),
                            &boundary.dispatch,
                        ),
                        request,
                    ) {
                        return Ok(Some(termination));
                    }
                    let projection = crate::analyzer::semantic::icfg::project_call_boundary(
                        caller,
                        semantic_call,
                        boundary,
                    )?;
                    for boundary in projection.boundaries {
                        if let Some(termination) = self.observe_boundary(boundary, request) {
                            return Ok(Some(termination));
                        }
                    }
                    for edge in projection.edges {
                        projected_edges.push(edge);
                    }
                }
                projected_edges.sort_by(compare_procedure_edges);
                projected_edges.dedup();
                for edge in &projected_edges {
                    if request.cancellation.is_cancelled() {
                        return Ok(Some(SolverTermination::Cancelled));
                    }
                    if let Some(termination) = self.observe_edge(edge, request) {
                        return Ok(Some(termination));
                    }
                }
                let projected_edges = Arc::<[ProcedureIcfgEdge]>::from(projected_edges);
                self.call_to_return_cache
                    .insert(origin.clone(), Arc::clone(&projected_edges));
                projected_edges
            } else {
                self.call_to_return_cache
                    .get(&origin)
                    .cloned()
                    .ok_or_else(|| {
                        SemanticProviderError::internal(
                            "summary call-to-return projection is absent from its cache",
                        )
                    })?
            };
            for edge in call_to_return_edges.iter() {
                if request.cancellation.is_cancelled() {
                    return Ok(Some(SolverTermination::Cancelled));
                }
                if let Some(termination) = self.propagate_owned_edge(
                    problem,
                    queued.key.entry,
                    queued.key.fact,
                    queued.quality,
                    queued.evidence,
                    edge,
                    false,
                    request,
                )? {
                    return Ok(Some(termination));
                }
            }

            for (transfer_index, transfer) in transfers.transfers.iter().enumerate() {
                let edge = ProcedureIcfgEdge {
                    source: point.clone(),
                    target: transfer.callee_entry.clone(),
                    kind: IcfgEdgeKind::Call,
                    origin: Some(origin.clone()),
                    proof: transfer.proof.clone(),
                    completeness: transfer.completeness.clone(),
                    boundary: None,
                };
                if newly_materialized && let Some(termination) = self.observe_edge(&edge, request) {
                    return Ok(Some(termination));
                }
                let incoming_quality = queued
                    .quality
                    .through_evidence(&edge.proof, &edge.completeness);
                let descriptor = descriptor(&edge).with_call_transfer(transfer);
                let outputs = match evaluate_transfer(
                    problem,
                    descriptor,
                    fact,
                    self.zero_fact,
                    queued.key.fact == ZERO_FACT_ID,
                    &mut self.transfer_scratch,
                    request,
                ) {
                    TransferEvaluation::Outputs(outputs) => outputs,
                    TransferEvaluation::Terminated(termination) => {
                        return Ok(Some(termination));
                    }
                };
                if let Some(termination) = self.publish_call_outputs(
                    queued.key,
                    queued.quality,
                    queued.evidence,
                    transfer_index,
                    transfer,
                    &edge,
                    incoming_quality,
                    &outputs,
                    problem,
                    request,
                )? {
                    return Ok(Some(termination));
                }
                if let Some(termination) = self.apply_reusable_callee_summaries(
                    provider,
                    reusable,
                    problem,
                    transfer,
                    &outputs,
                    semantic_budget,
                    request,
                )? {
                    return Ok(Some(termination));
                }
            }
        }

        self.process_local_edges(problem, point, queued, Some(semantic_call), request)
    }

    fn process_local_edges<P>(
        &mut self,
        problem: &P,
        point: &ProgramPointHandle,
        queued: QueuedPath,
        call: Option<&crate::analyzer::semantic::SemanticCallSite>,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<SolverTermination>, SummaryDataflowError>
    where
        P: DistributiveDataflowProblem<Fact = Fact>,
    {
        let procedure = point.procedure();
        let semantics = procedure.semantics();
        let mut previous_projected = None;
        for (_, edge) in semantics.successor_edges(point.id()) {
            if request.cancellation.is_cancelled() {
                return Ok(Some(SolverTermination::Cancelled));
            }
            if call.is_some_and(|call| {
                crate::analyzer::semantic::icfg::is_call_scaffolding(edge, call)
            }) {
                continue;
            }
            let projected = (edge.kind, edge.target_point);
            if previous_projected == Some(projected) {
                continue;
            }
            previous_projected = Some(projected);
            let target = procedure.point_handle(edge.target_point).ok_or_else(|| {
                SemanticProviderError::internal("summary local edge target is stale")
            })?;
            let owned = ProcedureIcfgEdge {
                source: point.clone(),
                target,
                kind: IcfgEdgeKind::Intraprocedural(edge.kind),
                origin: None,
                proof: ProofStatus::Proven,
                completeness: EvidenceCompleteness::Complete,
                boundary: None,
            };
            if let Some(termination) = self.propagate_owned_edge(
                problem,
                queued.key.entry,
                queued.key.fact,
                queued.quality,
                queued.evidence,
                &owned,
                true,
                request,
            )? {
                return Ok(Some(termination));
            }
        }
        Ok(None)
    }

    #[allow(clippy::too_many_arguments)]
    fn propagate_owned_edge<P>(
        &mut self,
        problem: &P,
        entry: EntryKey,
        fact_id: FactId,
        input_quality: PathQuality,
        predecessor_evidence: Option<WitnessEvidenceId>,
        edge: &ProcedureIcfgEdge,
        observe_evidence: bool,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<SolverTermination>, SummaryDataflowError>
    where
        P: DistributiveDataflowProblem<Fact = Fact>,
    {
        if observe_evidence && let Some(termination) = self.observe_edge(edge, request) {
            return Ok(Some(termination));
        }
        let output_quality = input_quality.through_evidence(&edge.proof, &edge.completeness);
        let target = edge.target.id();
        let flow = descriptor(edge);
        let outputs = match evaluate_transfer(
            problem,
            flow,
            self.facts[fact_id.index()],
            self.zero_fact,
            fact_id == ZERO_FACT_ID,
            &mut self.transfer_scratch,
            request,
        ) {
            TransferEvaluation::Outputs(outputs) => outputs,
            TransferEvaluation::Terminated(termination) => {
                return Ok(Some(termination));
            }
        };
        let witness_source = if self.witness_arena.is_enabled() {
            Some(PathWitnessSource::Edge {
                predecessor: predecessor_evidence.ok_or(SummaryDataflowError::WitnessInvariant(
                    "enabled edge propagation has no predecessor evidence",
                ))?,
                predecessor_quality: input_quality,
                edge,
                input_fact: fact_id,
            })
        } else {
            None
        };
        self.publish_path_outputs(
            entry,
            target,
            output_quality,
            &outputs,
            witness_source,
            request,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_reusable_callee_summaries<P, Provider, Reusable>(
        &mut self,
        provider: &Provider,
        reusable: &mut Reusable,
        problem: &P,
        transfer: &CallTransfer,
        entry_facts: &[Fact],
        semantic_budget: &mut SemanticBudget,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<SolverTermination>, SummaryDataflowError>
    where
        P: DistributiveDataflowProblem<Fact = Fact>,
        Provider: IcfgProvider + ?Sized,
        Reusable: ReusableSummaryProvider<Fact> + ?Sized,
    {
        for &entry_fact in entry_facts {
            if request.cancellation.is_cancelled() {
                return Ok(Some(SolverTermination::Cancelled));
            }
            let procedure = self
                .procedure_ids
                .get(&transfer.callee)
                .copied()
                .ok_or_else(|| {
                    SemanticProviderError::internal(
                        "reusable callee was not interned after call publication",
                    )
                })?;
            let entry_fact_id = self.fact_ids.get(&entry_fact).copied().ok_or_else(|| {
                SemanticProviderError::internal(
                    "reusable callee entry fact was not interned after call publication",
                )
            })?;
            let entry = EntryKey {
                procedure,
                entry_point: transfer.callee_entry.id(),
                entry_fact: entry_fact_id,
            };
            if self.reusable_entries.contains(&entry) {
                continue;
            }
            if self.witness_arena.is_enabled() && !self.best_effort_witness_retention {
                self.metrics.reusable_summary_misses =
                    self.metrics.reusable_summary_misses.saturating_add(1);
                continue;
            }
            let summary = match reusable.summary_for(&transfer.callee, entry_fact, request) {
                Ok(Some(summary)) => summary,
                Ok(None) => {
                    self.metrics.reusable_summary_misses =
                        self.metrics.reusable_summary_misses.saturating_add(1);
                    continue;
                }
                Err(termination) => return Ok(Some(termination)),
            };
            if summary.exits.iter().any(|row| row.qualities.is_empty())
                || summary.reached.iter().any(|row| {
                    row.qualities.is_empty() || row.point.procedure() != &transfer.callee
                })
            {
                self.metrics.reusable_summary_misses =
                    self.metrics.reusable_summary_misses.saturating_add(1);
                continue;
            }
            if self.witness_arena.is_enabled() {
                self.mark_reusable_witnesses_omitted();
            }

            let mut facts = summary
                .exits
                .iter()
                .map(|row| row.exit_fact)
                .chain(summary.reached.iter().map(|row| row.fact))
                .collect::<Vec<_>>();
            facts.sort_unstable();
            facts.dedup();
            let Some(staged) = self.stage_facts(&facts, request)? else {
                return Ok(Some(SolverTermination::Cancelled));
            };
            let staged_ids = facts
                .iter()
                .copied()
                .zip(staged.ids.iter().copied())
                .collect::<HashMap<_, _>>();
            let new_reached_states = summary
                .reached
                .iter()
                .filter(|row| {
                    !self.reached.contains_key(&PathEdgeKey {
                        entry,
                        point: row.point.id(),
                        fact: staged_ids[&row.fact],
                    })
                })
                .count();
            if let Some(termination) = self.reserve_publication(
                SolverWork {
                    interned_facts: staged.new_facts.len(),
                    reached_states: new_reached_states,
                    ..SolverWork::default()
                },
                0,
                request,
            ) {
                return Ok(Some(termination));
            }
            self.commit_facts(staged.new_facts);
            self.reusable_entries.insert(entry);
            self.metrics.reusable_summary_hits =
                self.metrics.reusable_summary_hits.saturating_add(1);

            for row in summary.reached {
                let fact = self.fact_ids[&row.fact];
                let path = PathEdgeKey {
                    entry,
                    point: row.point.id(),
                    fact,
                };
                let frontier = self.reached.entry(path).or_default();
                for quality in row.qualities {
                    frontier.insert(quality);
                }
                self.metrics.reusable_observations =
                    self.metrics.reusable_observations.saturating_add(1);
            }

            for row in summary.exits {
                let exit_point = match row.exit_kind {
                    crate::analyzer::semantic::ReturnTransferKind::Normal => {
                        transfer.callee.semantics().normal_exit_point()
                    }
                    crate::analyzer::semantic::ReturnTransferKind::Exceptional => {
                        transfer.callee.semantics().exceptional_exit_point()
                    }
                };
                let exit_point = transfer.callee.point_handle(exit_point).ok_or_else(|| {
                    SemanticProviderError::internal("reusable callee exit point is stale")
                })?;
                let (outcome, newly_materialized) = match self.cached_exit_profile(
                    provider,
                    &transfer.callee_entry,
                    &exit_point,
                    semantic_budget,
                    request,
                )? {
                    Ok(outcome) => outcome,
                    Err(termination) => return Ok(Some(termination)),
                };
                if newly_materialized
                    && let Some(termination) =
                        self.observe_semantic_outcome(&exit_point, None, outcome.as_ref(), request)
                {
                    return Ok(Some(termination));
                }
                let Some(exit) = outcome.available_value().cloned() else {
                    continue;
                };
                let path = PathEdgeKey {
                    entry,
                    point: exit_point.id(),
                    fact: self.fact_ids[&row.exit_fact],
                };
                for quality in row.qualities {
                    if let Some(termination) = self.publish_end_summary(
                        path,
                        Arc::clone(&exit),
                        quality,
                        None,
                        problem,
                        request,
                    )? {
                        return Ok(Some(termination));
                    }
                }
            }
        }
        Ok(None)
    }

    #[allow(clippy::too_many_arguments)]
    fn publish_call_outputs<P>(
        &mut self,
        caller_path: PathEdgeKey,
        caller_quality: PathQuality,
        caller_evidence: Option<WitnessEvidenceId>,
        transfer_index: usize,
        transfer: &CallTransfer,
        call_edge: &ProcedureIcfgEdge,
        quality: PathQuality,
        outputs: &[Fact],
        problem: &P,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<SolverTermination>, SummaryDataflowError>
    where
        P: DistributiveDataflowProblem<Fact = Fact>,
    {
        if request.cancellation.is_cancelled() {
            return Ok(Some(SolverTermination::Cancelled));
        }
        if self.witness_arena.is_enabled() && caller_evidence.is_none() {
            return Err(SummaryDataflowError::WitnessInvariant(
                "enabled call propagation has no caller evidence",
            ));
        }
        let callee_procedure = self
            .procedure_ids
            .get(&transfer.callee)
            .copied()
            .unwrap_or(self.procedures.len());
        let mut new_facts = 0usize;

        // Compute the exact fact charge and validate every prospective ID
        // without retaining output-derived rows. Transfer outputs are already
        // canonical, so each missing fact occupies the next missing position.
        for &output in outputs {
            if request.cancellation.is_cancelled() {
                return Ok(Some(SolverTermination::Cancelled));
            }
            if !self.fact_ids.contains_key(&output) {
                let index = self.facts.len().saturating_add(new_facts);
                FactId::try_from_index(index)
                    .map_err(|_| SummaryDataflowError::FactIdOverflow { index })?;
                new_facts = new_facts.saturating_add(1);
            }
        }

        // Reproduce the established prospective-publication semantics before
        // allocating staging vectors: fact and callback/output work are exact
        // from the first row, while reached and incoming attempts grow one
        // canonical row at a time.
        let mut missing_facts = 0usize;
        let mut new_reached_states = 0usize;
        let mut new_incoming_calls = 0usize;
        for &output in outputs {
            if request.cancellation.is_cancelled() {
                return Ok(Some(SolverTermination::Cancelled));
            }
            let fact = self.fact_ids.get(&output).copied().unwrap_or_else(|| {
                let index = self.facts.len().saturating_add(missing_facts);
                missing_facts = missing_facts.saturating_add(1);
                FactId::try_from_index(index)
                    .expect("prospective fact IDs were validated during exact sizing")
            });
            let callee = EntryKey {
                procedure: callee_procedure,
                entry_point: transfer.callee_entry.id(),
                entry_fact: fact,
            };
            let path = PathEdgeKey {
                entry: callee,
                point: transfer.callee_entry.id(),
                fact,
            };
            if !self.reached.contains_key(&path) {
                new_reached_states = new_reached_states.saturating_add(1);
            }
            let incoming_key = IncomingKey {
                callee,
                caller: caller_path.entry,
                call_point: caller_path.point,
                call_fact: caller_path.fact,
                transfer_index,
            };
            if !self.incoming_ids.contains_key(&incoming_key) {
                new_incoming_calls = new_incoming_calls.saturating_add(1);
            }
            if let Err(exceeded) = request.budget.check(SolverWork {
                interned_facts: new_facts,
                reached_states: new_reached_states,
                callback_rows: outputs.len(),
                propagated_outputs: outputs.len(),
                incoming_calls: new_incoming_calls,
                ..SolverWork::default()
            }) {
                return Ok(Some(SolverTermination::ExceededBudget(exceeded)));
            }
        }
        debug_assert_eq!(missing_facts, new_facts);

        let Some(staged) = self.stage_facts(outputs, request)? else {
            return Ok(Some(SolverTermination::Cancelled));
        };
        debug_assert_eq!(staged.new_facts.len(), new_facts);
        let mut staged_paths = Vec::with_capacity(outputs.len());
        let mut staged_incoming = Vec::with_capacity(outputs.len());
        let mut staged_witness_nodes = Vec::new();
        let mut staged_witness_bytes = 0usize;
        let mut witness_exhausted = false;
        for &fact in &staged.ids {
            if request.cancellation.is_cancelled() {
                return Ok(Some(SolverTermination::Cancelled));
            }
            let callee = EntryKey {
                procedure: callee_procedure,
                entry_point: transfer.callee_entry.id(),
                entry_fact: fact,
            };
            let path = PathEdgeKey {
                entry: callee,
                point: transfer.callee_entry.id(),
                fact,
            };
            let existing_path = self.reached.get(&path).copied();
            let mut path_frontier = existing_path.unwrap_or_default();
            let path_frontier_changed = path_frontier.insert(PathQuality::PROVEN_COMPLETE);
            let mut path_witnesses = self.path_witnesses.get(&path).cloned().unwrap_or_default();
            let before_path_witnesses = path_witnesses.clone();
            if path_frontier_changed {
                path_witnesses.retain_frontier(path_frontier);
            }
            let mut path_evidence = None;
            if self.witness_arena.is_enabled() {
                let admission = self
                    .witness_arena
                    .stage_candidate(
                        &mut path_witnesses,
                        PathQuality::PROVEN_COMPLETE,
                        WitnessCandidateBudget::new(
                            WitnessEvidenceNode::seed_retained_bytes(),
                            self.request_witness_staging_capacity(request),
                        ),
                        |existing| existing.matches_seed_derivation(&transfer.callee_entry, fact),
                        || WitnessEvidenceNode::seed(transfer.callee_entry.clone(), fact),
                        WitnessStaging::new(&mut staged_witness_nodes, &mut staged_witness_bytes),
                    )
                    .map_err(|index| SummaryDataflowError::WitnessEvidenceIdOverflow { index })?;
                match admission {
                    WitnessAdmission::Retained(id) => path_evidence = Some(id),
                    WitnessAdmission::Exhausted if self.best_effort_witness_retention => {
                        witness_exhausted = true;
                    }
                    WitnessAdmission::Duplicate | WitnessAdmission::Truncated => {}
                    WitnessAdmission::Exhausted => {
                        return Err(SummaryDataflowError::WitnessInvariant(
                            "strict witness retention exhausted without a solver budget",
                        ));
                    }
                }
            }
            if path_frontier_changed
                && self.witness_arena.is_enabled()
                && path_evidence.is_none()
                && !witness_exhausted
            {
                return Err(SummaryDataflowError::WitnessInvariant(
                    "new callee entry path did not retain relative seed evidence",
                ));
            }
            let path_witnesses_changed = path_witnesses != before_path_witnesses;
            if path_frontier_changed || path_witnesses_changed {
                staged_paths.push(StagedPathPublication {
                    key: path,
                    frontier: path_frontier,
                    frontier_changed: path_frontier_changed,
                    witnesses: path_witnesses,
                    witnesses_changed: path_witnesses_changed,
                    queued_evidence: path_evidence,
                });
            }

            let incoming_key = IncomingKey {
                callee,
                caller: caller_path.entry,
                call_point: caller_path.point,
                call_fact: caller_path.fact,
                transfer_index,
            };
            let existing_incoming = self.incoming_ids.get(&incoming_key).copied();
            let existing_frontier = existing_incoming.map(|id| self.incoming[id].qualities);
            let mut incoming_frontier = existing_frontier.unwrap_or_default();
            let incoming_frontier_changed = incoming_frontier.insert(quality);
            let mut incoming_witnesses = existing_incoming
                .map(|id| self.incoming[id].witnesses.clone())
                .unwrap_or_default();
            let before_incoming_witnesses = incoming_witnesses.clone();
            if incoming_frontier_changed {
                incoming_witnesses.retain_frontier(incoming_frontier);
            }
            let mut incoming_evidence = None;
            if self.witness_arena.is_enabled() && incoming_frontier.contains(quality) {
                if caller_quality.through_evidence(&call_edge.proof, &call_edge.completeness)
                    != quality
                {
                    return Err(SummaryDataflowError::WitnessInvariant(
                        "incoming call evidence quality does not match publication",
                    ));
                }
                let admission = self
                    .witness_arena
                    .stage_candidate(
                        &mut incoming_witnesses,
                        quality,
                        WitnessCandidateBudget::new(
                            WitnessEvidenceNode::edge_retained_bytes(call_edge),
                            self.request_witness_staging_capacity(request),
                        ),
                        |existing| {
                            existing.matches_edge_derivation(
                                caller_evidence.expect("enabled call evidence was validated"),
                                caller_quality,
                                call_edge,
                                caller_path.fact,
                                fact,
                            )
                        },
                        || {
                            WitnessEvidenceNode::edge(
                                caller_evidence.expect("enabled call evidence was validated"),
                                caller_quality,
                                call_edge,
                                caller_path.fact,
                                fact,
                            )
                        },
                        WitnessStaging::new(&mut staged_witness_nodes, &mut staged_witness_bytes),
                    )
                    .map_err(|index| SummaryDataflowError::WitnessEvidenceIdOverflow { index })?;
                match admission {
                    WitnessAdmission::Retained(id) => incoming_evidence = Some(id),
                    WitnessAdmission::Exhausted if self.best_effort_witness_retention => {
                        witness_exhausted = true;
                    }
                    WitnessAdmission::Duplicate | WitnessAdmission::Truncated => {}
                    WitnessAdmission::Exhausted => {
                        return Err(SummaryDataflowError::WitnessInvariant(
                            "strict witness retention exhausted without a solver budget",
                        ));
                    }
                }
            }
            if incoming_frontier_changed
                && self.witness_arena.is_enabled()
                && incoming_evidence.is_none()
                && !witness_exhausted
            {
                return Err(SummaryDataflowError::WitnessInvariant(
                    "new incoming call quality did not retain witness evidence",
                ));
            }
            let incoming_witnesses_changed = incoming_witnesses != before_incoming_witnesses;
            staged_incoming.push(StagedIncomingPublication {
                key: incoming_key,
                existing: existing_incoming,
                frontier: incoming_frontier,
                witnesses: incoming_witnesses,
                frontier_changed: incoming_frontier_changed,
                witnesses_changed: incoming_witnesses_changed,
                reused_entry: existing_path.is_some(),
                activated_evidence: incoming_evidence,
            });
        }
        if request.cancellation.is_cancelled() {
            return Ok(Some(SolverTermination::Cancelled));
        }

        if witness_exhausted {
            self.abandon_best_effort_witnesses();
            staged_witness_nodes.clear();
        }
        if let Some(termination) = self.reserve_publication(
            SolverWork {
                interned_facts: new_facts,
                reached_states: new_reached_states,
                callback_rows: outputs.len(),
                propagated_outputs: outputs.len(),
                incoming_calls: new_incoming_calls,
                ..SolverWork::default()
            },
            staged_witness_nodes.len(),
            request,
        ) {
            return Ok(Some(termination));
        }

        if !outputs.is_empty() {
            let committed = self.intern_procedure(transfer.callee.clone());
            debug_assert_eq!(committed, callee_procedure);
        }
        self.commit_facts(staged.new_facts);
        if self.witness_arena.is_enabled() {
            for (id, node) in staged_witness_nodes {
                self.witness_arena.commit(id, node);
            }
        }
        for publication in staged_paths {
            if self.witness_arena.is_enabled() {
                self.witness_arena
                    .mark_alternatives_truncated(&publication.witnesses);
            }
            if publication.frontier_changed {
                self.reached.insert(publication.key, publication.frontier);
            }
            if self.witness_arena.is_enabled() && publication.witnesses_changed {
                self.path_witnesses
                    .insert(publication.key, publication.witnesses);
            }
            let evidence = self
                .witness_arena
                .is_enabled()
                .then_some(publication.queued_evidence)
                .flatten();
            if (publication.frontier_changed && !self.witness_arena.is_enabled())
                || evidence.is_some()
            {
                self.worklist.push_back(QueuedPath {
                    key: publication.key,
                    quality: PathQuality::PROVEN_COMPLETE,
                    evidence,
                });
            }
        }

        let mut activated = Vec::new();
        for publication in staged_incoming {
            if self.witness_arena.is_enabled() {
                self.witness_arena
                    .mark_alternatives_truncated(&publication.witnesses);
            }
            let id = if let Some(id) = publication.existing {
                if publication.frontier_changed {
                    self.incoming[id].qualities = publication.frontier;
                }
                if self.witness_arena.is_enabled() && publication.witnesses_changed {
                    self.incoming[id].witnesses = publication.witnesses;
                }
                id
            } else {
                let id = self.incoming.len();
                self.incoming.push(IncomingCall {
                    key: publication.key,
                    origin: transfer.origin.clone(),
                    qualities: publication.frontier,
                    witnesses: if self.witness_arena.is_enabled() {
                        publication.witnesses
                    } else {
                        WitnessAlternatives::default()
                    },
                });
                self.incoming_ids.insert(publication.key, id);
                self.incoming_by_entry
                    .entry(publication.key.callee)
                    .or_default()
                    .push(id);
                if publication.reused_entry {
                    self.metrics.reused_entry_contexts =
                        self.metrics.reused_entry_contexts.saturating_add(1);
                }
                id
            };
            if publication.frontier_changed && !self.witness_arena.is_enabled() {
                activated.push((id, quality, None));
            } else if let Some(evidence) = publication.activated_evidence {
                activated.push((id, quality, Some(evidence)));
            }
        }

        for (incoming, active_quality, active_evidence) in activated {
            if let Some(termination) = self.replay_existing_summaries(
                incoming,
                active_quality,
                active_evidence,
                problem,
                request,
            )? {
                return Ok(Some(termination));
            }
        }
        Ok(None)
    }

    fn publish_end_summary<P>(
        &mut self,
        path: PathEdgeKey,
        exit: Arc<IcfgExitProfile>,
        predecessor_quality: PathQuality,
        predecessor_evidence: Option<WitnessEvidenceId>,
        problem: &P,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<SolverTermination>, SummaryDataflowError>
    where
        P: DistributiveDataflowProblem<Fact = Fact>,
    {
        let quality = if exit.has_return_affecting_gaps() {
            predecessor_quality.conjoin(PathQuality::UNPROVEN_PARTIAL)
        } else {
            predecessor_quality
        };
        let key = EndSummaryKey {
            entry: path.entry,
            exit_point: exit.callee_exit().id(),
            exit_fact: path.fact,
        };
        let existing = self.summary_ids.get(&key).copied();
        let mut qualities = existing
            .map(|id| self.summaries[id].qualities)
            .unwrap_or_default();
        let frontier_changed = qualities.insert(quality);
        let mut witnesses = existing
            .map(|id| self.summaries[id].witnesses.clone())
            .unwrap_or_default();
        let before_witnesses = witnesses.clone();
        if frontier_changed {
            witnesses.retain_frontier(qualities);
        }

        let mut staged_witness_nodes = Vec::new();
        let mut staged_witness_bytes = 0usize;
        let mut activated_evidence = None;
        let mut witness_exhausted = false;
        let reusable_entry = self.reusable_entries.contains(&path.entry);
        if self.witness_arena.is_enabled() && qualities.contains(quality) && !reusable_entry {
            let predecessor =
                predecessor_evidence.ok_or(SummaryDataflowError::WitnessInvariant(
                    "enabled end-summary publication has no predecessor evidence",
                ))?;
            let entry_point = self.procedures[path.entry.procedure]
                .point_handle(path.entry.entry_point)
                .ok_or_else(|| SemanticProviderError::internal("summary entry point is stale"))?;
            let admission = self
                .witness_arena
                .stage_candidate(
                    &mut witnesses,
                    quality,
                    WitnessCandidateBudget::new(
                        WitnessEvidenceNode::end_summary_retained_bytes(),
                        self.request_witness_staging_capacity(request),
                    ),
                    |existing| {
                        existing.matches_end_summary_derivation(
                            predecessor,
                            predecessor_quality,
                            &entry_point,
                            path.entry.entry_fact,
                            &exit,
                            path.fact,
                        )
                    },
                    || {
                        WitnessEvidenceNode::end_summary(
                            predecessor,
                            predecessor_quality,
                            entry_point.clone(),
                            path.entry.entry_fact,
                            Arc::clone(&exit),
                            path.fact,
                        )
                    },
                    WitnessStaging::new(&mut staged_witness_nodes, &mut staged_witness_bytes),
                )
                .map_err(|index| SummaryDataflowError::WitnessEvidenceIdOverflow { index })?;
            match admission {
                WitnessAdmission::Retained(id) => activated_evidence = Some(id),
                WitnessAdmission::Exhausted if self.best_effort_witness_retention => {
                    witness_exhausted = true;
                }
                WitnessAdmission::Duplicate | WitnessAdmission::Truncated => {}
                WitnessAdmission::Exhausted => {
                    return Err(SummaryDataflowError::WitnessInvariant(
                        "strict witness retention exhausted without a solver budget",
                    ));
                }
            }
        }
        if frontier_changed
            && self.witness_arena.is_enabled()
            && !reusable_entry
            && activated_evidence.is_none()
            && !witness_exhausted
        {
            return Err(SummaryDataflowError::WitnessInvariant(
                "new end-summary quality did not retain witness evidence",
            ));
        }
        let witnesses_changed = witnesses != before_witnesses;
        if witness_exhausted {
            self.abandon_best_effort_witnesses();
            staged_witness_nodes.clear();
        }
        if !frontier_changed && !witnesses_changed {
            return Ok(None);
        }

        if let Some(termination) = self.reserve_publication(
            SolverWork {
                end_summaries: usize::from(existing.is_none()),
                ..SolverWork::default()
            },
            staged_witness_nodes.len(),
            request,
        ) {
            return Ok(Some(termination));
        }
        if self.witness_arena.is_enabled() {
            for (id, node) in staged_witness_nodes {
                self.witness_arena.commit(id, node);
            }
            self.witness_arena.mark_alternatives_truncated(&witnesses);
        }
        let summary_id = if let Some(id) = existing {
            if frontier_changed {
                self.summaries[id].qualities = qualities;
            }
            if self.witness_arena.is_enabled() && witnesses_changed {
                self.summaries[id].witnesses = witnesses;
            }
            id
        } else {
            let id = self.summaries.len();
            self.summaries.push(EndSummaryRow {
                key,
                exit,
                qualities,
                witnesses: if self.witness_arena.is_enabled() {
                    witnesses
                } else {
                    WitnessAlternatives::default()
                },
            });
            self.summary_ids.insert(key, id);
            self.summaries_by_entry
                .entry(key.entry)
                .or_default()
                .push(id);
            id
        };

        let incoming_ids = self
            .incoming_by_entry
            .get(&key.entry)
            .cloned()
            .unwrap_or_default();
        for incoming_id in incoming_ids {
            if request.cancellation.is_cancelled() {
                return Ok(Some(SolverTermination::Cancelled));
            }
            let qualities = self.incoming[incoming_id].qualities;
            for incoming_quality in qualities.iter() {
                if self.witness_arena.is_enabled() {
                    if activated_evidence.is_none() && !reusable_entry {
                        continue;
                    }
                    let incoming_evidence = self.incoming[incoming_id]
                        .witnesses
                        .ids(incoming_quality)
                        .to_vec();
                    for incoming_evidence in incoming_evidence {
                        if let Some(termination) = self.apply_summary(
                            incoming_id,
                            summary_id,
                            incoming_quality,
                            Some(incoming_evidence),
                            quality,
                            activated_evidence,
                            problem,
                            request,
                        )? {
                            return Ok(Some(termination));
                        }
                    }
                } else if frontier_changed
                    && let Some(termination) = self.apply_summary(
                        incoming_id,
                        summary_id,
                        incoming_quality,
                        None,
                        quality,
                        None,
                        problem,
                        request,
                    )?
                {
                    return Ok(Some(termination));
                }
            }
        }
        Ok(None)
    }

    fn replay_existing_summaries<P>(
        &mut self,
        incoming: usize,
        incoming_quality: PathQuality,
        incoming_evidence: Option<WitnessEvidenceId>,
        problem: &P,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<SolverTermination>, SummaryDataflowError>
    where
        P: DistributiveDataflowProblem<Fact = Fact>,
    {
        if request.cancellation.is_cancelled() {
            return Ok(Some(SolverTermination::Cancelled));
        }
        if self.witness_arena.is_enabled()
            && incoming_evidence.is_none_or(|evidence| {
                !self.incoming[incoming]
                    .witnesses
                    .contains(incoming_quality, evidence)
            })
        {
            return Err(SummaryDataflowError::WitnessInvariant(
                "summary replay has no active incoming evidence",
            ));
        }
        // No applied-pair table is needed: this path runs only for one newly
        // admitted incoming derivation, while `publish_end_summary` runs only
        // for one newly admitted end-summary derivation. The side admitted
        // second owns the pair exactly once.
        let entry = self.incoming[incoming].key.callee;
        let summary_len = self.summaries_by_entry.get(&entry).map_or(0, Vec::len);
        if summary_len == 0 {
            self.metrics.summary_misses = self.metrics.summary_misses.saturating_add(1);
            return Ok(None);
        }
        self.metrics.summary_hits = self.metrics.summary_hits.saturating_add(1);
        for index in 0..summary_len {
            if request.cancellation.is_cancelled() {
                return Ok(Some(SolverTermination::Cancelled));
            }
            let summary = self
                .summaries_by_entry
                .get(&entry)
                .and_then(|ids| ids.get(index))
                .copied()
                .ok_or_else(|| {
                    SemanticProviderError::internal("summary end-summary index is stale")
                })?;
            let qualities = self.summaries[summary].qualities;
            for summary_quality in qualities.iter() {
                if self.witness_arena.is_enabled() {
                    let summary_evidence = self.summaries[summary]
                        .witnesses
                        .ids(summary_quality)
                        .to_vec();
                    if summary_evidence.is_empty()
                        && self.reusable_entries.contains(&entry)
                        && let Some(termination) = self.apply_summary(
                            incoming,
                            summary,
                            incoming_quality,
                            incoming_evidence,
                            summary_quality,
                            None,
                            problem,
                            request,
                        )?
                    {
                        return Ok(Some(termination));
                    }
                    for summary_evidence in summary_evidence {
                        if let Some(termination) = self.apply_summary(
                            incoming,
                            summary,
                            incoming_quality,
                            incoming_evidence,
                            summary_quality,
                            Some(summary_evidence),
                            problem,
                            request,
                        )? {
                            return Ok(Some(termination));
                        }
                    }
                } else if let Some(termination) = self.apply_summary(
                    incoming,
                    summary,
                    incoming_quality,
                    None,
                    summary_quality,
                    None,
                    problem,
                    request,
                )? {
                    return Ok(Some(termination));
                }
            }
        }
        Ok(None)
    }

    fn cached_incoming_transfer(
        &self,
        incoming: &IncomingCall,
    ) -> Result<&CallTransfer, SummaryDataflowError> {
        self.call_cache
            .get(&incoming.origin)
            .and_then(|outcome| outcome.available_value())
            .and_then(|transfers| transfers.transfers.get(incoming.key.transfer_index))
            .ok_or_else(|| {
                SemanticProviderError::internal(
                    "summary incoming transfer is absent from its cache",
                )
                .into()
            })
    }

    fn matched_return_projection(
        &mut self,
        incoming_id: usize,
        summary_id: usize,
        request: &DataflowRequest<'_>,
    ) -> Result<Option<Arc<CachedMatchedReturnProjection>>, SummaryDataflowError> {
        if request.cancellation.is_cancelled() {
            return Ok(None);
        }
        let key = {
            let incoming = &self.incoming[incoming_id];
            let summary = &self.summaries[summary_id];
            debug_assert_eq!(incoming.key.callee, summary.key.entry);
            MatchedReturnCacheKey {
                origin: incoming.origin.clone(),
                transfer_index: incoming.key.transfer_index,
                callee_entry: summary.exit.callee_entry().clone(),
                callee_exit: summary.exit.callee_exit().clone(),
            }
        };
        if let Some(projection) = self.matched_return_cache.get(&key) {
            return Ok(Some(Arc::clone(projection)));
        }
        if request.cancellation.is_cancelled() {
            return Ok(None);
        }

        let projection = {
            let incoming = &self.incoming[incoming_id];
            let summary = &self.summaries[summary_id];
            let transfer = self.cached_incoming_transfer(incoming)?;
            let projection = match summary.exit.project_matched_return(transfer)? {
                MatchedReturnProjection::Edge(edge) => CachedMatchedReturnProjection::Edge(
                    Arc::new(SummaryEdge::from_owned_procedure_edge(edge)),
                ),
                MatchedReturnProjection::Absent => CachedMatchedReturnProjection::Absent,
                MatchedReturnProjection::Boundary(boundary) => {
                    CachedMatchedReturnProjection::Boundary(boundary)
                }
            };
            Arc::new(projection)
        };
        if request.cancellation.is_cancelled() {
            return Ok(None);
        }

        // This method is reached only after one summary-application charge, so
        // retained fact-independent projections cannot outgrow that budget.
        self.matched_return_cache
            .insert(key, Arc::clone(&projection));
        Ok(Some(projection))
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_summary<P>(
        &mut self,
        incoming_id: usize,
        summary_id: usize,
        incoming_quality: PathQuality,
        incoming_evidence: Option<WitnessEvidenceId>,
        summary_quality: PathQuality,
        summary_evidence: Option<WitnessEvidenceId>,
        problem: &P,
        request: &mut DataflowRequest<'_>,
    ) -> Result<Option<SolverTermination>, SummaryDataflowError>
    where
        P: DistributiveDataflowProblem<Fact = Fact>,
    {
        let reusable_summary = self
            .reusable_entries
            .contains(&self.summaries[summary_id].key.entry);
        if self.witness_arena.is_enabled()
            && (incoming_evidence.is_none_or(|evidence| {
                !self.incoming[incoming_id]
                    .witnesses
                    .contains(incoming_quality, evidence)
            }) || (!reusable_summary
                && summary_evidence.is_none_or(|evidence| {
                    !self.summaries[summary_id]
                        .witnesses
                        .contains(summary_quality, evidence)
                })))
        {
            return Err(SummaryDataflowError::WitnessInvariant(
                "summary application evidence is not active",
            ));
        }
        if let Some(termination) = reserve_summary_application(request) {
            return Ok(Some(termination));
        }
        let (caller, exit_fact) = {
            let incoming = &self.incoming[incoming_id];
            let summary = &self.summaries[summary_id];
            debug_assert_eq!(incoming.key.callee, summary.key.entry);
            (incoming.key.caller, summary.key.exit_fact)
        };
        let Some(projection) = self.matched_return_projection(incoming_id, summary_id, request)?
        else {
            return Ok(Some(SolverTermination::Cancelled));
        };
        match projection.as_ref() {
            CachedMatchedReturnProjection::Absent => {
                self.metrics.summary_applications =
                    self.metrics.summary_applications.saturating_add(1);
                Ok(None)
            }
            CachedMatchedReturnProjection::Boundary(boundary) => {
                if let Some(termination) = self.observe_boundary(boundary.clone(), request) {
                    return Ok(Some(termination));
                }
                self.metrics.summary_applications =
                    self.metrics.summary_applications.saturating_add(1);
                Ok(None)
            }
            CachedMatchedReturnProjection::Edge(edge) => {
                if self.procedures[caller.procedure] != *edge.target().procedure() {
                    return Err(SemanticProviderError::internal(
                        "summary return target belongs to a different caller",
                    )
                    .into());
                }
                if let Some(termination) = self.observe_summary_edge(Arc::clone(edge), request) {
                    return Ok(Some(termination));
                }
                let quality = incoming_quality
                    .conjoin(summary_quality)
                    .through_evidence(edge.proof(), edge.completeness());
                let target = edge.target().id();
                let flow = summary_descriptor(edge);
                let outputs = match evaluate_transfer(
                    problem,
                    flow,
                    self.facts[exit_fact.index()],
                    self.zero_fact,
                    exit_fact == ZERO_FACT_ID,
                    &mut self.transfer_scratch,
                    request,
                ) {
                    TransferEvaluation::Outputs(outputs) => outputs,
                    TransferEvaluation::Terminated(termination) => {
                        return Ok(Some(termination));
                    }
                };
                self.metrics.summary_applications =
                    self.metrics.summary_applications.saturating_add(1);
                let witness_source = if self.witness_arena.is_enabled() {
                    let incoming =
                        incoming_evidence.expect("enabled incoming evidence was validated");
                    Some(if reusable_summary {
                        PathWitnessSource::ReusableSummaryApplication {
                            incoming,
                            incoming_quality,
                            summary_quality,
                            return_edge: edge,
                            input_fact: exit_fact,
                        }
                    } else {
                        PathWitnessSource::SummaryApplication {
                            incoming,
                            incoming_quality,
                            summary: summary_evidence
                                .expect("enabled summary evidence was validated"),
                            summary_quality,
                            return_edge: edge,
                            input_fact: exit_fact,
                        }
                    })
                } else {
                    None
                };
                self.publish_path_outputs(
                    caller,
                    target,
                    quality,
                    &outputs,
                    witness_source,
                    request,
                )
            }
        }
    }

    fn finish(
        mut self,
        termination: SolverTermination,
        work: SolverWork,
        semantic_work: SemanticWork,
    ) -> SummaryDataflowResult<Fact> {
        let witness_owner = (self.witness_arena.is_enabled() || self.best_effort_witness_retention)
            .then(|| Arc::new(()));
        let witness_arena = std::mem::replace(
            &mut self.witness_arena,
            WitnessArena::new(WitnessRetentionLimits::disabled()),
        );
        let witness_store = if termination.is_fixed_point() && !self.best_effort_witness_retention {
            let mut witness_roots = Vec::new();
            for (key, witnesses) in &self.path_witnesses {
                let Some(frontier) = self.reached.get(key) else {
                    continue;
                };
                for quality in frontier.iter() {
                    witness_roots.extend(witnesses.ids(quality));
                }
            }
            for summary in &self.summaries {
                for quality in summary.qualities.iter() {
                    witness_roots.extend(summary.witnesses.ids(quality));
                }
            }
            let (witness_store, witness_remap) = witness_arena.into_compact_store(witness_roots);
            for witnesses in self.path_witnesses.values_mut() {
                witnesses.remap(&witness_remap);
            }
            for summary in &mut self.summaries {
                summary.witnesses.remap(&witness_remap);
            }
            witness_store
        } else {
            // A cancelled, budget-stopped, or locally capped best-effort solve
            // must return promptly. The arena is already relation-budgeted,
            // and preserving dense IDs avoids an uninterruptible full
            // traversal and peak-memory copy.
            witness_arena.into_store()
        };

        let mut reached_rows = self.reached.drain().collect::<Vec<_>>();
        reached_rows.sort_unstable_by_key(|(key, _)| *key);
        let reached = reached_rows
            .into_iter()
            .map(|(key, qualities)| {
                let witnesses = self.path_witnesses.remove(&key).unwrap_or_default();
                let procedure = self.procedures[key.entry.procedure].clone();
                let entry_point = procedure
                    .point_handle(key.entry.entry_point)
                    .expect("published summary entry point remains valid");
                let point = procedure
                    .point_handle(key.point)
                    .expect("published summary path point remains valid");
                SummaryReachedFact::new(
                    SummaryEntry::new(procedure, entry_point, key.entry.entry_fact),
                    point,
                    key.fact,
                    qualities,
                    witnesses,
                    witness_owner.clone(),
                )
            })
            .collect();

        let mut summary_rows = std::mem::take(&mut self.summaries);
        summary_rows.sort_unstable_by_key(|row| row.key);
        let end_summaries = summary_rows
            .into_iter()
            .map(|row| {
                let procedure = self.procedures[row.key.entry.procedure].clone();
                let entry_point = procedure
                    .point_handle(row.key.entry.entry_point)
                    .expect("published summary entry point remains valid");
                TabulationEndSummary::new(
                    SummaryEntry::new(procedure, entry_point, row.key.entry.entry_fact),
                    row.exit,
                    row.key.exit_fact,
                    row.qualities,
                    row.witnesses,
                    witness_owner.clone(),
                )
            })
            .collect();
        self.matched_return_cache.clear();
        let coverage = SummaryCoverage::from_parts(
            self.unproven_edges
                .into_iter()
                .map(Arc::unwrap_or_clone)
                .collect(),
            self.partial_edges
                .into_iter()
                .map(Arc::unwrap_or_clone)
                .collect(),
            self.boundaries.into_iter().collect(),
        );
        SummaryDataflowResult::from_parts(
            self.facts,
            reached,
            end_summaries,
            coverage,
            termination,
            work,
            semantic_work,
            self.metrics,
            witness_store,
            self.witness_retention_truncated,
        )
    }
}

/// Solve one finite distributive problem with query-local procedure summaries.
pub fn solve_with_summaries<P, Provider>(
    input: SummarySolveInput<'_, P::Fact>,
    provider: &Provider,
    problem: &P,
    semantic_budget: &mut SemanticBudget,
    request: &mut DataflowRequest<'_>,
) -> Result<SummaryDataflowResult<P::Fact>, SummaryDataflowError>
where
    P: DistributiveDataflowProblem,
    Provider: IcfgProvider + ?Sized,
{
    let mut reusable = NoReusableSummaries;
    solve_with_reusable_end_summaries(
        input,
        provider,
        problem,
        &mut reusable,
        semantic_budget,
        request,
    )
}

/// Solve with an optional validated cross-query callee-summary oracle.
pub fn solve_with_reusable_end_summaries<P, Provider, Reusable>(
    input: SummarySolveInput<'_, P::Fact>,
    provider: &Provider,
    problem: &P,
    reusable: &mut Reusable,
    semantic_budget: &mut SemanticBudget,
    request: &mut DataflowRequest<'_>,
) -> Result<SummaryDataflowResult<P::Fact>, SummaryDataflowError>
where
    P: DistributiveDataflowProblem,
    Provider: IcfgProvider + ?Sized,
    Reusable: ReusableSummaryProvider<P::Fact> + ?Sized,
{
    let initial_work = request.budget.used();
    let initial_semantic_work = semantic_budget.used();
    let mut state = SummaryState::new(problem.zero_fact(), input.witness_retention());
    let termination = if let Some(termination) = state.initialize(input, request)? {
        termination
    } else {
        state.propagate(provider, reusable, problem, semantic_budget, request)?
    };
    let work = request.budget.used().saturating_sub(initial_work);
    let semantic_work = semantic_budget.used().saturating_sub(initial_semantic_work);
    Ok(state.finish(termination, work, semantic_work))
}

fn reserve_summary_application(request: &mut DataflowRequest<'_>) -> Option<SolverTermination> {
    reserve_solver_work(
        SolverWork {
            summary_applications: 1,
            ..SolverWork::default()
        },
        request,
    )
}

fn reserve_coverage_rows(
    rows: usize,
    request: &mut DataflowRequest<'_>,
) -> Option<SolverTermination> {
    reserve_solver_work(
        SolverWork {
            coverage_rows: rows,
            ..SolverWork::default()
        },
        request,
    )
}

fn reserve_solver_work(
    work: SolverWork,
    request: &mut DataflowRequest<'_>,
) -> Option<SolverTermination> {
    request.reserve(work)
}

fn canonicalize_call_transfer_set(mut set: CallTransferSet) -> CallTransferSet {
    let mut transfers = set.transfers.into_vec();
    transfers.sort_by(compare_call_transfers);
    transfers.dedup();
    let mut boundaries = set.boundaries.into_vec();
    boundaries.sort_by(compare_call_boundaries);
    boundaries.dedup();
    set.transfers = transfers.into_boxed_slice();
    set.boundaries = boundaries.into_boxed_slice();
    set
}

fn descriptor(edge: &ProcedureIcfgEdge) -> DataflowEdge<'_> {
    let descriptor = DataflowEdge::new(
        edge.kind,
        edge.origin.as_ref(),
        &edge.source,
        &edge.target,
        &edge.proof,
        &edge.completeness,
    );
    match edge.boundary.as_ref() {
        Some(boundary) => descriptor.with_boundary(boundary),
        None => descriptor,
    }
}

fn summary_descriptor(edge: &SummaryEdge) -> DataflowEdge<'_> {
    DataflowEdge::new(
        edge.kind(),
        edge.origin(),
        edge.source(),
        edge.target(),
        edge.proof(),
        edge.completeness(),
    )
}

fn compare_procedure_edges(left: &ProcedureIcfgEdge, right: &ProcedureIcfgEdge) -> Ordering {
    compare_program_points(&left.source, &right.source)
        .then_with(|| compare_program_points(&left.target, &right.target))
        .then_with(|| left.kind.label().cmp(right.kind.label()))
        .then_with(|| compare_optional_call_sites(left.origin.as_ref(), right.origin.as_ref()))
        .then_with(|| left.boundary.cmp(&right.boundary))
        .then_with(|| compare_proof(&left.proof, &right.proof))
        .then_with(|| compare_completeness(&left.completeness, &right.completeness))
}

fn compare_program_points(left: &ProgramPointHandle, right: &ProgramPointHandle) -> Ordering {
    compare_procedures(left.procedure(), right.procedure()).then_with(|| left.id().cmp(&right.id()))
}

fn compare_optional_call_sites(
    left: Option<&CallSiteHandle>,
    right: Option<&CallSiteHandle>,
) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(left), Some(right)) => compare_call_sites(left, right),
    }
}

fn is_procedure_exit(point: &ProgramPointHandle) -> bool {
    let semantics = point.procedure().semantics();
    point.id() == semantics.normal_exit_point() || point.id() == semantics.exceptional_exit_point()
}

fn compare_call_transfers(left: &CallTransfer, right: &CallTransfer) -> Ordering {
    compare_call_sites(&left.origin, &right.origin)
        .then_with(|| compare_procedures(&left.callee, &right.callee))
        .then_with(|| left.callee_entry.id().cmp(&right.callee_entry.id()))
        .then_with(|| compare_continuations(left.normal_continuation, right.normal_continuation))
        .then_with(|| {
            compare_continuations(
                left.exceptional_continuation,
                right.exceptional_continuation,
            )
        })
        .then_with(|| compare_proof(&left.proof, &right.proof))
        .then_with(|| compare_completeness(&left.completeness, &right.completeness))
}

fn compare_call_boundaries(left: &CallBoundary, right: &CallBoundary) -> Ordering {
    compare_call_sites(&left.origin, &right.origin)
        .then_with(|| compare_dispatch_boundary_kind(&left.dispatch.kind, &right.dispatch.kind))
        .then_with(|| compare_call_to_return_model(left.model, right.model))
        .then_with(|| compare_proof(&left.dispatch.proof, &right.dispatch.proof))
        .then_with(|| {
            compare_completeness(&left.dispatch.completeness, &right.dispatch.completeness)
        })
        .then_with(|| {
            compare_relation_provenance(&left.dispatch.provenance, &right.dispatch.provenance)
        })
}

fn compare_procedures(left: &ProcedureHandle, right: &ProcedureHandle) -> Ordering {
    left.artifact()
        .key()
        .cmp(right.artifact().key())
        .then_with(|| left.semantics().locator().cmp(right.semantics().locator()))
        .then_with(|| left.id().cmp(&right.id()))
        .then_with(|| {
            Arc::as_ptr(left.artifact())
                .cast::<()>()
                .cmp(&Arc::as_ptr(right.artifact()).cast::<()>())
        })
}

fn compare_call_sites(left: &CallSiteHandle, right: &CallSiteHandle) -> Ordering {
    compare_procedures(left.procedure(), right.procedure()).then_with(|| left.id().cmp(&right.id()))
}

fn compare_continuations(left: ControlContinuation, right: ControlContinuation) -> Ordering {
    let key = |continuation| match continuation {
        ControlContinuation::Target(point) => (0, point.get()),
        ControlContinuation::Absent => (1, 0),
        ControlContinuation::Unknown => (2, 0),
        ControlContinuation::Unsupported => (3, 0),
        ControlContinuation::Unproven => (4, 0),
        ControlContinuation::ExceededBudget => (5, 0),
    };
    key(left).cmp(&key(right))
}

fn compare_proof(left: &ProofStatus, right: &ProofStatus) -> Ordering {
    match (left, right) {
        (ProofStatus::Proven, ProofStatus::Proven) => Ordering::Equal,
        (ProofStatus::Proven, ProofStatus::Unproven(_)) => Ordering::Less,
        (ProofStatus::Unproven(_), ProofStatus::Proven) => Ordering::Greater,
        (ProofStatus::Unproven(left), ProofStatus::Unproven(right)) => left.cmp(right),
    }
}

fn compare_completeness(left: &EvidenceCompleteness, right: &EvidenceCompleteness) -> Ordering {
    match (left, right) {
        (EvidenceCompleteness::Complete, EvidenceCompleteness::Complete) => Ordering::Equal,
        (EvidenceCompleteness::Complete, EvidenceCompleteness::Partial(_)) => Ordering::Less,
        (EvidenceCompleteness::Partial(_), EvidenceCompleteness::Complete) => Ordering::Greater,
        (EvidenceCompleteness::Partial(left), EvidenceCompleteness::Partial(right)) => {
            left.cmp(right)
        }
    }
}

fn compare_call_to_return_model(
    left: Option<crate::analyzer::semantic::CallToReturnModel>,
    right: Option<crate::analyzer::semantic::CallToReturnModel>,
) -> Ordering {
    let rank = |model| match model {
        None => 0,
        Some(crate::analyzer::semantic::CallToReturnModel::Normal) => 1,
        Some(crate::analyzer::semantic::CallToReturnModel::Exceptional) => 2,
        Some(crate::analyzer::semantic::CallToReturnModel::NormalAndExceptional) => 3,
    };
    rank(left).cmp(&rank(right))
}

fn compare_dispatch_boundary_kind(
    left: &crate::analyzer::semantic::DispatchBoundaryKind,
    right: &crate::analyzer::semantic::DispatchBoundaryKind,
) -> Ordering {
    use crate::analyzer::semantic::DispatchBoundaryKind;

    let rank = |kind: &DispatchBoundaryKind| match kind {
        DispatchBoundaryKind::External(_) => 0,
        DispatchBoundaryKind::Unmaterialized(_) => 1,
        DispatchBoundaryKind::Deferred { .. } => 2,
        DispatchBoundaryKind::Unresolved => 3,
        DispatchBoundaryKind::Truncated => 4,
    };
    rank(left)
        .cmp(&rank(right))
        .then_with(|| match (left, right) {
            (DispatchBoundaryKind::External(left), DispatchBoundaryKind::External(right)) => {
                left.cmp(right)
            }
            (
                DispatchBoundaryKind::Unmaterialized(left),
                DispatchBoundaryKind::Unmaterialized(right),
            ) => left.cmp(right),
            (
                DispatchBoundaryKind::Deferred {
                    target: left_target,
                    kind: left_kind,
                },
                DispatchBoundaryKind::Deferred {
                    target: right_target,
                    kind: right_kind,
                },
            ) => left_target
                .cmp(right_target)
                .then_with(|| deferred_kind_rank(*left_kind).cmp(&deferred_kind_rank(*right_kind))),
            _ => Ordering::Equal,
        })
}

fn deferred_kind_rank(kind: crate::analyzer::semantic::DeferredInvocationKind) -> u8 {
    use crate::analyzer::semantic::DeferredInvocationKind;
    match kind {
        DeferredInvocationKind::Async => 0,
        DeferredInvocationKind::Generator => 1,
        DeferredInvocationKind::AsyncGenerator => 2,
        DeferredInvocationKind::LanguageDefined => 3,
    }
}
