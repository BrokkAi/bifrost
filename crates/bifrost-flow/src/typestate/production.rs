//! Production ownership and projection for reusable typestate summaries.
//!
//! The repository is content-keyed and generation-independent, following
//! [`ValueFlowCache`](crate::value_flow::ValueFlowCache).
//!
//! Every entry is addressed by a key that already names each of its semantic
//! inputs. A semantic summary is keyed by `ProcedureSummaryKey`, whose identity
//! carries the procedure's `SemanticArtifactKey` -- a digest over mount, path,
//! language, exact source revision, adapter semantics version, IR version,
//! configuration fingerprint, and dependency fingerprint -- closed over the
//! exact dependency and recursive-group closure. A procedure carries the
//! provider behavior when projection asks for call transfers, because that
//! answer can change without changing the procedure's own source. A call-free
//! procedure uses a provider-independent behavior, so rotating a provider
//! does not discard an exact reusable leaf summary for an unrelated edit. A
//! protocol summary adds the protocol and binding hashes. A whole solved result
//! adds the entry facts, the full provider execution behavior, and both
//! remaining budgets.
//!
//! This remains generation-independent: a stale entry is simply an entry
//! nothing asks for again, and the byte and entry limits retire it. The full
//! workspace behavior conservatively rotates provider-dependent summaries
//! after an analyzed edit, while provider-independent leaves remain reusable. This
//! replaces an earlier generation gate that rotated the whole repository on
//! every workspace update and prevented the policy and search surfaces from
//! sharing exact retained work.
//!
//! Budget-dependent results are still refused rather than retained, on the same
//! grounds `memoizable_outcome` states for value flow: exceeding a budget or
//! being cancelled is a property of the request, not of the artifact, so
//! freezing one into the cache would deny a later, better-funded request the
//! better answer it could reach. See [`publish_exact_result`].

use crate::semantic_summary::{ProcedureDependencyComponentOrder, ProcedureDependencyGraph};
use std::fmt;
use std::sync::{Arc, Condvar, Mutex, OnceLock};

use crate::analyzer::semantic::cfg_algorithms::{
    CfgAlgorithmBudget, CfgAlgorithmError, CfgAlgorithmRequest, strongly_connected_components,
};
use crate::analyzer::semantic::{
    BindingOriginIndex, CallBoundary, CallInvocationMode, CallSiteId, CallableTarget,
    CallableTargetResolution, CandidateCoverage, EvidenceCompleteness, IcfgProvider,
    IcfgProviderBehaviorIdentity, LengthDelimitedDigest, MemoryLocationKind, ProcedureHandle,
    ProofStatus, SemanticBudget, SemanticBudgetExceeded, SemanticCallSite, SemanticEffect,
    SemanticExecutionBudget, SemanticExecutionBudgetCharge, SemanticExecutionBudgetSnapshot,
    SemanticOutcome, SemanticProviderError, SemanticRequest, SemanticValueKind, SemanticWork,
    ValueFlowKind, ValueId,
};
use crate::dataflow::{
    DataflowRequest, ProcedureSummaryIdentity, ProcedureSummaryKey,
    ProductionSemanticSummaryRepository, SemanticInputStatus, SemanticProcedureSummary, SolverWork,
    SummaryBehaviorKey, SummaryBoundaryKind, SummaryCallSourceWitness, SummaryCompleteness,
    SummaryContextKey, SummaryDependencyKey, SummaryEffect, SummaryEffectKey, SummaryEventKey,
    SummaryEvidence, SummaryOrigin, SummaryPort, SummaryPublicationError,
    SummaryPublicationOutcome, SummaryReadObserver, SummaryRecursiveEdge, SummaryRecursiveGroupKey,
    SummaryRepositoryLimits, SummarySchemaVersion, SummarySemanticsVersion, SummaryValidationError,
};
use crate::hash::{HashMap, HashSet};

use super::{
    CompiledProtocol, CompleteProtocolSummaryRepository, ProtocolFactKey,
    ProtocolSemanticSummarySet, ProtocolSummaryCacheStatus, ProtocolSummaryError,
    ProtocolSummaryRepositoryLimits, ProtocolSummarySolveError, TypestateBindingPlan,
    TypestateBindingPlanHash, TypestateFact, TypestateProtocolHash, TypestateSummaryResult,
    solve_typestate_with_reusable_summaries, solve_typestate_with_summaries,
};

const PRODUCTION_SUMMARY_SEMANTICS: &[u8] = b"bifrost-production-semantic-summary-v26";
const EMPTY_CALL_CONTEXT: &[u8] = b"bifrost-production-empty-call-context-v1";
const PRODUCTION_ICFG_BEHAVIOR_DOMAIN: &[u8] = b"bifrost-production-icfg-behavior-v2";
const PRODUCTION_SUMMARY_BEHAVIOR_DOMAIN: &[u8] = b"bifrost-production-summary-behavior-v1";
const PROVIDER_INDEPENDENT_LEAF_BEHAVIOR: &[u8] =
    b"bifrost-production-provider-independent-leaf/v3";
const CALL_EFFECT_DOMAIN: &[u8] = b"bifrost-production-call-effect-v1";
const WORKSPACE_PROVIDER_CONTEXT: &[u8] = b"bifrost-production-workspace-provider-v1";

/// Live provider-execution state whose work must be reproduced on an exact hit.
#[derive(Debug, Clone, Copy)]
pub enum ProductionTypestateExecutionContext<'a> {
    Workspace,
    Policy(&'a SemanticExecutionBudget),
}

impl ProductionTypestateExecutionContext<'_> {
    fn snapshot(self) -> Option<SemanticExecutionBudgetSnapshot> {
        match self {
            Self::Workspace => None,
            Self::Policy(budget) => Some(budget.snapshot()),
        }
    }

    fn provider_context(
        self,
        snapshot: Option<&SemanticExecutionBudgetSnapshot>,
    ) -> ProductionTypestateProviderContext {
        match self {
            Self::Workspace => ProductionTypestateProviderContext::Workspace(
                SummaryBehaviorKey::hash_bytes(WORKSPACE_PROVIDER_CONTEXT),
            ),
            Self::Policy(_) => ProductionTypestateProviderContext::Policy(
                snapshot
                    .expect("policy execution context retains an exact snapshot")
                    .clone(),
            ),
        }
    }

    fn semantic_allowance_key(self, remaining: SemanticWork) -> SemanticWork {
        match self {
            Self::Workspace => remaining,
            // A standalone policy evaluator owns one repository per batch and
            // one configured budget class for all policies. Presentation-only
            // compilation can consume slightly different bookkeeping work;
            // accepted hits replay their exact solve charge and are published
            // only when no budget boundary affected the result.
            Self::Policy(_) => SemanticWork::default(),
        }
    }

    fn charge_since(
        self,
        snapshot: Option<&SemanticExecutionBudgetSnapshot>,
    ) -> Option<Option<SemanticExecutionBudgetCharge>> {
        match self {
            Self::Workspace => Some(None),
            Self::Policy(budget) => budget
                .charge_since(snapshot.expect("policy execution context retains an exact snapshot"))
                .map(Some),
        }
    }

    fn replay_charge(
        self,
        snapshot: Option<&SemanticExecutionBudgetSnapshot>,
        charge: Option<&SemanticExecutionBudgetCharge>,
    ) -> bool {
        match (self, snapshot, charge) {
            (Self::Workspace, None, None) => true,
            (Self::Policy(budget), Some(snapshot), Some(charge)) => {
                budget.replay_charge(snapshot, charge)
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ProductionTypestateProviderContext {
    Workspace(SummaryBehaviorKey),
    Policy(SemanticExecutionBudgetSnapshot),
}

/// Independent limits for semantic identities and protocol-specific rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypestateSummaryRepositoryLimits {
    pub semantic: SummaryRepositoryLimits,
    pub protocol: ProtocolSummaryRepositoryLimits,
    pub max_result_entries: usize,
    pub max_result_bytes: usize,
}

impl Default for TypestateSummaryRepositoryLimits {
    fn default() -> Self {
        Self {
            semantic: SummaryRepositoryLimits::default(),
            protocol: ProtocolSummaryRepositoryLimits::default(),
            max_result_entries: 1_024,
            max_result_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Monotonic cache lifecycle counts. Evictions count retained entries.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ProductionSummaryLifecycleCounters {
    pub hits: usize,
    pub misses: usize,
    pub rejections: usize,
    pub evictions: usize,
    pub recomputations: usize,
}

impl ProductionSummaryLifecycleCounters {
    pub fn saturating_add_assign(&mut self, other: Self) {
        self.hits = self.hits.saturating_add(other.hits);
        self.misses = self.misses.saturating_add(other.misses);
        self.rejections = self.rejections.saturating_add(other.rejections);
        self.evictions = self.evictions.saturating_add(other.evictions);
        self.recomputations = self.recomputations.saturating_add(other.recomputations);
    }
}

/// One bounded, content-keyed in-memory repository owned by one workspace.
///
/// The handle itself is the capability: every entry is addressed by keys that
/// name their own semantic inputs, so there is no separate lease to pair a
/// repository with a generation. Share one `Arc` between every surface that
/// analyzes the same workspace.
#[derive(Debug)]
pub struct ProductionTypestateSummaryRepository {
    state: Mutex<ProductionTypestateSummaryRepositoryState>,
    semantic_summaries: Arc<ProductionSemanticSummaryRepository>,
    /// Counters live behind their own lock rather than inside `state` so a
    /// rejection can be recorded after the state guard is dropped.
    counters: Mutex<ProductionSummaryLifecycleCounters>,
    flights: Mutex<HashMap<ProductionSummaryResultKey, Arc<ProductionSummaryFlight>>>,
}

#[derive(Debug)]
struct ProductionTypestateSummaryRepositoryState {
    protocol: CompleteProtocolSummaryRepository,
    results: HashMap<ProductionSummaryResultKey, CachedTypestateSummaryResult>,
    retained_result_bytes: usize,
    next_result_sequence: u64,
    max_result_entries: usize,
    max_result_bytes: usize,
}

/// Verification's side of the summary read funnel: what this repository would
/// answer for a summary identity a base run recorded.
impl crate::analyzer::SummaryAnswers for ProductionTypestateSummaryRepository {
    fn summary_content(
        &self,
        identity: crate::analyzer::semantic::ids::StableDigest,
    ) -> Option<crate::analyzer::semantic::ids::StableDigest> {
        self.semantic_summaries
            .public_content_for_identity(identity)
    }
}

impl Default for ProductionTypestateSummaryRepository {
    fn default() -> Self {
        Self::with_limits(TypestateSummaryRepositoryLimits::default())
    }
}

impl ProductionTypestateSummaryRepository {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_limits(limits: TypestateSummaryRepositoryLimits) -> Self {
        Self::with_shared_semantic_summaries(
            limits,
            Arc::new(ProductionSemanticSummaryRepository::with_limits(
                limits.semantic,
            )),
        )
    }

    pub fn with_shared_semantic_summaries(
        limits: TypestateSummaryRepositoryLimits,
        semantic_summaries: Arc<ProductionSemanticSummaryRepository>,
    ) -> Self {
        Self {
            state: Mutex::new(ProductionTypestateSummaryRepositoryState {
                protocol: CompleteProtocolSummaryRepository::with_limits(limits.protocol),
                results: HashMap::default(),
                retained_result_bytes: 0,
                next_result_sequence: 0,
                max_result_entries: limits.max_result_entries,
                max_result_bytes: limits.max_result_bytes,
            }),
            semantic_summaries,
            counters: Mutex::new(ProductionSummaryLifecycleCounters::default()),
            flights: Mutex::new(HashMap::default()),
        }
    }

    pub fn counters(&self) -> ProductionSummaryLifecycleCounters {
        *self.lifecycle_counters()
    }

    pub fn retained_result_count(&self) -> usize {
        self.state().results.len()
    }

    pub fn retained_result_bytes(&self) -> usize {
        self.state().retained_result_bytes
    }

    /// Retained semantic procedure summaries, the identities shared by every
    /// surface that analyzes this workspace.
    pub fn retained_semantic_count(&self) -> usize {
        self.semantic_summaries.len()
    }

    /// Retained protocol summaries.
    pub fn retained_protocol_count(&self) -> usize {
        self.state().protocol.len()
    }

    /// Announce to `observer` what this repository holds for every summary in
    /// `summaries` (issue: impact-sliced `--diff-base`, Milestone 5).
    ///
    /// This is the semantic summary funnel one root solve crosses. The solve
    /// projects the summary set its root's call closure needs and then asks
    /// this repository about each one; both halves of that answer -- the
    /// summary it retained, or the absence it did not -- are inputs the solve
    /// acted on, so both are announced. The lookups run under one state guard
    /// because the answers must describe one repository state.
    pub fn observe_semantic_reads(
        &self,
        summaries: &ProductionSemanticSummarySet,
        observer: &dyn SummaryReadObserver,
    ) {
        for summary in &summaries.summaries {
            self.semantic_summaries
                .get_observed(summary.key(), observer);
        }
    }

    /// Whether every summary in `summaries` is already retained verbatim.
    pub fn contains_semantic_set(&self, summaries: &ProductionSemanticSummarySet) -> bool {
        self.semantic_summaries.contains_all(&summaries.summaries)
    }

    pub fn publish_semantic_set(
        &self,
        summaries: &ProductionSemanticSummarySet,
    ) -> Result<SummaryPublicationOutcome, ProductionTypestateSolveError> {
        self.semantic_summaries
            .publish_components(&summaries.summaries, &summaries.components)
            .inspect_err(|_| self.record_rejection())
            .map_err(Into::into)
    }

    pub fn semantic_summaries(&self) -> Arc<ProductionSemanticSummaryRepository> {
        Arc::clone(&self.semantic_summaries)
    }

    pub fn record_rejection(&self) {
        let mut counters = self.lifecycle_counters();
        counters.rejections = counters.rejections.saturating_add(1);
    }

    pub fn record_miss(&self) {
        let mut counters = self.lifecycle_counters();
        counters.misses = counters.misses.saturating_add(1);
    }

    pub fn record_recomputation(&self) {
        let mut counters = self.lifecycle_counters();
        counters.recomputations = counters.recomputations.saturating_add(1);
    }

    fn result(&self, key: &ProductionSummaryResultKey) -> Option<CachedTypestateSummaryResult> {
        self.state().results.get(key).cloned()
    }

    fn record_hit(&self) {
        let mut counters = self.lifecycle_counters();
        counters.hits = counters.hits.saturating_add(1);
    }

    fn publish_result(
        &self,
        key: ProductionSummaryResultKey,
        result: Arc<TypestateSummaryResult>,
        semantic_charge: crate::analyzer::semantic::SemanticBudgetReplay,
        solver_charge: SolverWork,
        execution_charge: Option<SemanticExecutionBudgetCharge>,
    ) -> (bool, usize) {
        let mut state = self.state();
        if state.results.contains_key(&key) {
            return (true, 0);
        }
        let mut retained = CachedTypestateSummaryResult {
            result,
            semantic_charge,
            solver_charge,
            execution_charge,
            published_sequence: 0,
        };
        let retained_bytes = key
            .retained_bytes()
            .saturating_add(retained.retained_bytes());
        if state.max_result_entries == 0 || retained_bytes > state.max_result_bytes {
            drop(state);
            self.record_rejection();
            return (false, 0);
        }
        let mut evictions = 0usize;
        while state.results.len().saturating_add(1) > state.max_result_entries
            || state.retained_result_bytes.saturating_add(retained_bytes) > state.max_result_bytes
        {
            let Some(oldest) = state
                .results
                .iter()
                .min_by_key(|(_, value)| value.published_sequence)
                .map(|(key, _)| key.clone())
            else {
                drop(state);
                self.record_rejection();
                return (false, evictions);
            };
            let removed = state
                .results
                .remove(&oldest)
                .expect("selected result-cache victim remains present");
            state.retained_result_bytes = state.retained_result_bytes.saturating_sub(
                oldest
                    .retained_bytes()
                    .saturating_add(removed.retained_bytes()),
            );
            evictions = evictions.saturating_add(1);
        }
        retained.published_sequence = state.next_result_sequence;
        state.next_result_sequence = state.next_result_sequence.saturating_add(1);
        state.retained_result_bytes = state.retained_result_bytes.saturating_add(retained_bytes);
        state.results.insert(key, retained);
        drop(state);
        self.add_evictions(evictions);
        (true, evictions)
    }

    fn protocol_snapshot(
        &self,
        semantic_summaries: &ProtocolSemanticSummarySet<'_>,
        protocol: &CompiledProtocol,
        bindings: &TypestateBindingPlan,
    ) -> CompleteProtocolSummaryRepository {
        let protocol_repository = self.state().protocol.clone();
        semantic_summaries.compatible_repository(&protocol_repository, protocol, bindings)
    }

    fn protocol_limits(&self) -> ProtocolSummaryRepositoryLimits {
        self.state().protocol.limits()
    }

    fn absorb_protocol(
        &self,
        source: CompleteProtocolSummaryRepository,
        semantic_summaries: &ProtocolSemanticSummarySet<'_>,
    ) -> Result<usize, ProductionTypestateSolveError> {
        let batches = source.into_publication_batches();
        let mut state = self.state();
        state
            .protocol
            .absorb_batches(batches, semantic_summaries)
            .map_err(|error| {
                ProductionTypestateSolveError::Protocol(ProtocolSummarySolveError::Publication(
                    error,
                ))
            })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, ProductionTypestateSummaryRepositoryState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn lifecycle_counters(&self) -> std::sync::MutexGuard<'_, ProductionSummaryLifecycleCounters> {
        self.counters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn add_evictions(&self, evictions: usize) {
        let mut counters = self.lifecycle_counters();
        counters.evictions = counters.evictions.saturating_add(evictions);
    }

    fn begin_flight(
        &self,
        key: &ProductionSummaryResultKey,
    ) -> ProductionSummaryFlightAdmission<'_> {
        let mut flights = self
            .flights
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(flight) = flights.get(key) {
            return ProductionSummaryFlightAdmission::Follower(Arc::clone(flight));
        }
        let flight = Arc::new(ProductionSummaryFlight::default());
        flights.insert(key.clone(), Arc::clone(&flight));
        ProductionSummaryFlightAdmission::Leader(Box::new(ProductionSummaryFlightLeader {
            repository: self,
            key: key.clone(),
            flight,
        }))
    }
}

#[derive(Debug, Default)]
struct ProductionSummaryFlight {
    completed: Mutex<bool>,
    completed_cv: Condvar,
}

impl ProductionSummaryFlight {
    fn wait(&self) {
        let mut completed = self
            .completed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !*completed {
            completed = self
                .completed_cv
                .wait(completed)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

enum ProductionSummaryFlightAdmission<'a> {
    Leader(Box<ProductionSummaryFlightLeader<'a>>),
    Follower(Arc<ProductionSummaryFlight>),
}

struct ProductionSummaryFlightLeader<'a> {
    repository: &'a ProductionTypestateSummaryRepository,
    key: ProductionSummaryResultKey,
    flight: Arc<ProductionSummaryFlight>,
}

impl Drop for ProductionSummaryFlightLeader<'_> {
    fn drop(&mut self) {
        {
            let mut completed = self
                .flight
                .completed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *completed = true;
            self.flight.completed_cv.notify_all();
        }
        let mut flights = self
            .repository
            .flights
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if flights
            .get(&self.key)
            .is_some_and(|retained| Arc::ptr_eq(retained, &self.flight))
        {
            flights.remove(&self.key);
        }
    }
}

#[derive(Debug, Clone)]
struct CachedTypestateSummaryResult {
    result: Arc<TypestateSummaryResult>,
    semantic_charge: crate::analyzer::semantic::SemanticBudgetReplay,
    solver_charge: SolverWork,
    execution_charge: Option<SemanticExecutionBudgetCharge>,
    published_sequence: u64,
}

impl CachedTypestateSummaryResult {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(self.result.retained_bytes())
            .saturating_add(
                self.execution_charge
                    .as_ref()
                    .map_or(0, SemanticExecutionBudgetCharge::retained_bytes),
            )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ProductionSummaryResultKey {
    root: ProcedureSummaryIdentity,
    provider_behavior: SummaryBehaviorKey,
    protocol: TypestateProtocolHash,
    bindings: TypestateBindingPlanHash,
    entry_facts: Box<[ProtocolFactKey]>,
    provider_context: ProductionTypestateProviderContext,
    semantic_allowance: SemanticWork,
    solver_allowance: SolverWork,
}

impl ProductionSummaryResultKey {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(self.root.retained_bytes())
            .saturating_add(std::mem::size_of_val(self.entry_facts.as_ref()))
            .saturating_add(
                self.entry_facts
                    .iter()
                    .map(ProtocolFactKey::retained_bytes)
                    .fold(0_usize, usize::saturating_add),
            )
            .saturating_add(match &self.provider_context {
                ProductionTypestateProviderContext::Workspace(_) => 0,
                ProductionTypestateProviderContext::Policy(snapshot) => snapshot.retained_bytes(),
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypestateProductionCacheStatus {
    Hit,
    MissPublished,
    MissIncomplete,
    MissCapacityRejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionTypestateSolveResult {
    result: Arc<TypestateSummaryResult>,
    cache_status: TypestateProductionCacheStatus,
    protocol_cache_status: Option<ProtocolSummaryCacheStatus>,
    published_protocol_summaries: usize,
    rejected_protocol_reuse: bool,
    lifecycle: ProductionSummaryLifecycleCounters,
}

impl ProductionTypestateSolveResult {
    pub fn result(&self) -> &TypestateSummaryResult {
        self.result.as_ref()
    }

    pub const fn cache_status(&self) -> TypestateProductionCacheStatus {
        self.cache_status
    }

    pub const fn protocol_cache_status(&self) -> Option<ProtocolSummaryCacheStatus> {
        self.protocol_cache_status
    }

    pub const fn published_protocol_summaries(&self) -> usize {
        self.published_protocol_summaries
    }

    pub const fn rejected_protocol_reuse(&self) -> bool {
        self.rejected_protocol_reuse
    }

    pub const fn lifecycle(&self) -> ProductionSummaryLifecycleCounters {
        self.lifecycle
    }

    pub fn into_result(self) -> TypestateSummaryResult {
        Arc::unwrap_or_clone(self.result)
    }
}

#[derive(Debug)]
pub enum ProductionTypestateSolveError {
    Protocol(ProtocolSummarySolveError),
    ProtocolKey(ProtocolSummaryError),
    SemanticPublication(SummaryPublicationError),
}

impl fmt::Display for ProductionTypestateSolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => error.fmt(formatter),
            Self::ProtocolKey(error) => error.fmt(formatter),
            Self::SemanticPublication(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ProductionTypestateSolveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::ProtocolKey(error) => Some(error),
            Self::SemanticPublication(error) => Some(error),
        }
    }
}

impl From<SummaryPublicationError> for ProductionTypestateSolveError {
    fn from(error: SummaryPublicationError) -> Self {
        Self::SemanticPublication(error)
    }
}

/// Solve through the content-keyed production cache without weakening witness evidence.
#[allow(clippy::too_many_arguments)]
pub fn solve_typestate_with_production_summaries<Provider, ProjectionProvider>(
    repository: &ProductionTypestateSummaryRepository,
    observer: &dyn SummaryReadObserver,
    root: &ProcedureHandle,
    entry_facts: &[TypestateFact],
    provider: &Provider,
    projection_provider: &ProjectionProvider,
    execution_context: ProductionTypestateExecutionContext<'_>,
    protocol: &CompiledProtocol,
    bindings: &TypestateBindingPlan,
    semantic_budget: &mut crate::analyzer::semantic::SemanticBudget,
    request: &mut DataflowRequest<'_>,
) -> Result<ProductionTypestateSolveResult, ProductionTypestateSolveError>
where
    Provider: IcfgProvider + ?Sized,
    ProjectionProvider: IcfgProvider + ?Sized,
{
    let mut lifecycle = ProductionSummaryLifecycleCounters::default();
    let semantic_work_before = semantic_budget.replay_snapshot();
    let solver_work_before = request.budget.used();
    let execution_before = execution_context.snapshot();
    let provider_behavior = production_icfg_behavior(provider.behavior_identity());
    let projection_behavior = production_summary_behavior(projection_provider.behavior_identity());
    let result_key = production_result_key(
        summary_identity(root, projection_behavior),
        provider_behavior,
        entry_facts,
        protocol,
        bindings,
        execution_context.provider_context(execution_before.as_ref()),
        execution_context.semantic_allowance_key(semantic_budget.remaining()),
        request.budget.remaining(),
    )?;
    let _flight_leader = if repository.result(&result_key).is_none() {
        match repository.begin_flight(&result_key) {
            ProductionSummaryFlightAdmission::Leader(leader) => Some(leader),
            ProductionSummaryFlightAdmission::Follower(flight) => {
                flight.wait();
                return solve_typestate_with_production_summaries(
                    repository,
                    observer,
                    root,
                    entry_facts,
                    provider,
                    projection_provider,
                    execution_context,
                    protocol,
                    bindings,
                    semantic_budget,
                    request,
                );
            }
        }
    } else {
        None
    };
    if request.cancellation.is_cancelled() {
        repository.record_miss();
        repository.record_rejection();
        lifecycle.misses = lifecycle.misses.saturating_add(1);
        lifecycle.rejections = lifecycle.rejections.saturating_add(1);
    } else if let Some(cached) = repository.result(&result_key) {
        let mut replay_semantic_budget = semantic_budget.clone();
        let mut replay_solver_budget = request.budget.clone();
        let mut replay_charge = cached.semantic_charge;
        let already_held = replay_semantic_budget.has_replay_holder(&cached.result);
        if already_held {
            replay_charge.retained = SemanticWork::default();
        }
        let replayed = replay_semantic_budget
            .replay_continuation(replay_charge)
            .is_ok()
            && replay_solver_budget.charge(cached.solver_charge).is_ok()
            && execution_context
                .replay_charge(execution_before.as_ref(), cached.execution_charge.as_ref());
        if replayed {
            if !already_held {
                replay_semantic_budget.track_replay_holder(&cached.result, replay_charge.retained);
            }
            *semantic_budget = replay_semantic_budget;
            *request.budget = replay_solver_budget;
            repository.record_hit();
            lifecycle.hits = lifecycle.hits.saturating_add(1);
            return Ok(ProductionTypestateSolveResult {
                result: cached.result,
                cache_status: TypestateProductionCacheStatus::Hit,
                protocol_cache_status: None,
                published_protocol_summaries: 0,
                rejected_protocol_reuse: false,
                lifecycle,
            });
        }
        repository.record_miss();
        repository.record_rejection();
        lifecycle.misses = lifecycle.misses.saturating_add(1);
        lifecycle.rejections = lifecycle.rejections.saturating_add(1);
    } else {
        repository.record_miss();
        lifecycle.misses = lifecycle.misses.saturating_add(1);
    }

    repository.record_recomputation();
    lifecycle.recomputations = lifecycle.recomputations.saturating_add(1);
    let semantic_summaries = match project_production_semantic_summaries_with_behavior(
        std::slice::from_ref(root),
        projection_provider,
        projection_behavior,
        &mut SemanticRequest::new(semantic_budget, request.cancellation),
    ) {
        Ok(summaries) => summaries,
        Err(_) => {
            // Incomplete semantic evidence is not publishable. The exact result
            // remains safe to retain because the key includes the concrete
            // workspace provider's immutable artifact, protocol/bindings, entry
            // facts, and both remaining budgets.
            repository.record_rejection();
            lifecycle.rejections = lifecycle.rejections.saturating_add(1);
            let result = Arc::new(
                solve_typestate_with_summaries(
                    root,
                    entry_facts,
                    provider,
                    protocol,
                    bindings,
                    semantic_budget,
                    request,
                )
                .map_err(|error| {
                    ProductionTypestateSolveError::Protocol(ProtocolSummarySolveError::Solve(error))
                })?,
            );
            let cache_status = publish_exact_result(
                repository,
                result_key,
                &result,
                execution_context,
                execution_before.as_ref(),
                semantic_budget,
                &semantic_work_before,
                request.budget.used().saturating_sub(solver_work_before),
                &mut lifecycle,
            );
            return Ok(ProductionTypestateSolveResult {
                result,
                cache_status,
                protocol_cache_status: None,
                published_protocol_summaries: 0,
                rejected_protocol_reuse: false,
                lifecycle,
            });
        }
    };

    let semantic_publication_accepted = match repository.publish_semantic_set(&semantic_summaries) {
        Ok(_) => true,
        Err(ProductionTypestateSolveError::SemanticPublication(_)) => {
            lifecycle.rejections = lifecycle.rejections.saturating_add(1);
            false
        }
        Err(error) => return Err(error),
    };
    // The summary funnel this root solve crossed: for every procedure in the
    // root's call closure, what this repository serves under that procedure's
    // summary identity. Asked after publication, so the answer is the summary
    // the solve actually composed through rather than whatever the cache
    // happened to be warmed with, and so a rejected publication honestly
    // answers absence.
    repository.observe_semantic_reads(&semantic_summaries, observer);
    let semantic_set = semantic_summaries
        .protocol_summaries()
        .map_err(ProductionTypestateSolveError::ProtocolKey)?;
    let mut compatible = if semantic_publication_accepted {
        repository.protocol_snapshot(&semantic_set, protocol, bindings)
    } else {
        CompleteProtocolSummaryRepository::with_limits(repository.protocol_limits())
    };
    let has_compatible_protocol_summaries = !compatible.is_empty();
    let rejected_protocol_reuse = has_compatible_protocol_summaries;
    if rejected_protocol_reuse {
        // Portable protocol rows do not yet carry stable witness fragments.
        // Reject them before execution so policy-provider budgets and latency
        // cannot be consumed by a result that must be discarded anyway.
        repository.record_rejection();
        lifecycle.rejections = lifecycle.rejections.saturating_add(1);
    }
    compatible = CompleteProtocolSummaryRepository::with_limits(repository.protocol_limits());
    let solved = solve_typestate_with_reusable_summaries(
        root,
        entry_facts,
        provider,
        protocol,
        bindings,
        &semantic_set,
        &mut compatible,
        semantic_budget,
        request,
    )
    .map_err(ProductionTypestateSolveError::Protocol)?;
    let protocol_cache_status = solved.cache_status();
    let result = Arc::new(solved.into_computed_result());
    let published_protocol_summaries = if semantic_publication_accepted {
        match repository.absorb_protocol(compatible, &semantic_set) {
            Ok(published) => published,
            Err(_) => {
                repository.record_rejection();
                lifecycle.rejections = lifecycle.rejections.saturating_add(1);
                0
            }
        }
    } else {
        0
    };
    let cache_status = if semantic_publication_accepted {
        publish_exact_result(
            repository,
            result_key,
            &result,
            execution_context,
            execution_before.as_ref(),
            semantic_budget,
            &semantic_work_before,
            request.budget.used().saturating_sub(solver_work_before),
            &mut lifecycle,
        )
    } else {
        TypestateProductionCacheStatus::MissIncomplete
    };
    Ok(ProductionTypestateSolveResult {
        result,
        cache_status,
        protocol_cache_status: Some(protocol_cache_status),
        published_protocol_summaries,
        rejected_protocol_reuse,
        lifecycle,
    })
}

#[allow(clippy::too_many_arguments)]
fn production_result_key(
    root: ProcedureSummaryIdentity,
    provider_behavior: SummaryBehaviorKey,
    entry_facts: &[TypestateFact],
    protocol: &CompiledProtocol,
    bindings: &TypestateBindingPlan,
    provider_context: ProductionTypestateProviderContext,
    semantic_allowance: SemanticWork,
    solver_allowance: SolverWork,
) -> Result<ProductionSummaryResultKey, ProductionTypestateSolveError> {
    let mut stable_entry_facts = entry_facts
        .iter()
        .copied()
        .map(|fact| ProtocolFactKey::from_live(fact, protocol, bindings))
        .collect::<Result<Vec<_>, _>>()
        .map_err(ProductionTypestateSolveError::ProtocolKey)?;
    stable_entry_facts.push(ProtocolFactKey::Zero);
    stable_entry_facts.sort_unstable();
    stable_entry_facts.dedup();
    Ok(ProductionSummaryResultKey {
        root,
        provider_behavior,
        protocol: protocol.hash(),
        bindings: bindings.hash(),
        entry_facts: stable_entry_facts.into_boxed_slice(),
        provider_context,
        semantic_allowance,
        solver_allowance,
    })
}

#[allow(clippy::too_many_arguments)]
fn publish_exact_result(
    repository: &ProductionTypestateSummaryRepository,
    key: ProductionSummaryResultKey,
    result: &Arc<TypestateSummaryResult>,
    execution_context: ProductionTypestateExecutionContext<'_>,
    execution_before: Option<&SemanticExecutionBudgetSnapshot>,
    semantic_budget: &mut SemanticBudget,
    semantic_before: &crate::analyzer::semantic::SemanticBudgetReplaySnapshot,
    solver_charge: SolverWork,
    lifecycle: &mut ProductionSummaryLifecycleCounters,
) -> TypestateProductionCacheStatus {
    // The result can outlive its cache entry, including capacity rejection.
    semantic_budget.bind_replay_holder(result, semantic_before);
    let coverage = result.result().coverage();
    let budget_dependent = matches!(
        coverage.semantic_status(),
        SemanticInputStatus::ExceededBudget { .. } | SemanticInputStatus::Cancelled
    ) || coverage
        .boundaries()
        .iter()
        .any(|boundary| matches!(boundary.kind(), SummaryBoundaryKind::Limit(_)));
    if !result.result().termination().is_fixed_point()
        || result.result().witness_retention_truncated()
        || budget_dependent
    {
        TypestateProductionCacheStatus::MissIncomplete
    } else if let Some(execution_charge) = execution_context.charge_since(execution_before) {
        let semantic_charge = semantic_budget.replay_since(semantic_before);
        let (published, evictions) = repository.publish_result(
            key,
            Arc::clone(result),
            semantic_charge,
            solver_charge,
            execution_charge,
        );
        lifecycle.evictions = lifecycle.evictions.saturating_add(evictions);
        if published {
            TypestateProductionCacheStatus::MissPublished
        } else {
            lifecycle.rejections = lifecycle.rejections.saturating_add(1);
            TypestateProductionCacheStatus::MissCapacityRejected
        }
    } else {
        repository.record_rejection();
        lifecycle.rejections = lifecycle.rejections.saturating_add(1);
        TypestateProductionCacheStatus::MissIncomplete
    }
}

/// Owned semantic identities in bottom-up publication order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionSemanticSummarySet {
    summaries: Vec<SemanticProcedureSummary>,
    components: Vec<std::ops::Range<usize>>,
    complete_call_targets: HashMap<(ProcedureHandle, CallSiteId), Box<[ProcedureHandle]>>,
    behavior: SummaryBehaviorKey,
    procedure_semantics_precharged: bool,
}

impl ProductionSemanticSummarySet {
    pub fn summaries(&self) -> &[SemanticProcedureSummary] {
        &self.summaries
    }

    pub fn components(&self) -> &[std::ops::Range<usize>] {
        &self.components
    }

    pub fn len(&self) -> usize {
        self.summaries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.summaries.is_empty()
    }

    pub fn summary_for(&self, procedure: &ProcedureHandle) -> Option<&SemanticProcedureSummary> {
        let identity = summary_identity(procedure, self.behavior);
        self.summaries
            .iter()
            .find(|summary| summary.key().identity() == &identity)
    }

    /// Exact materialized targets retained from the same projection that
    /// produced this complete summary set.
    ///
    /// The stable summary stores durable dependency identities. This
    /// generation-local companion reconnects one source call occurrence to
    /// its materialized handles without asking the dispatch provider a second
    /// time. Calls with an open boundary are deliberately absent.
    pub fn complete_call_targets(
        &self,
        procedure: &ProcedureHandle,
        call: CallSiteId,
    ) -> Option<&[ProcedureHandle]> {
        self.complete_call_targets
            .get(&(procedure.clone(), call))
            .map(Box::as_ref)
    }

    /// Whether projection already paid to materialize every live procedure
    /// body. A retained closure contains stable rows only, so reconnecting it
    /// to current handles must charge the solver's live semantic scans.
    pub const fn procedure_semantics_precharged(&self) -> bool {
        self.procedure_semantics_precharged
    }

    pub fn protocol_summaries(
        &self,
    ) -> Result<ProtocolSemanticSummarySet<'_>, ProtocolSummaryError> {
        ProtocolSemanticSummarySet::try_new(self.summaries.iter().collect())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductionSummaryProjectionError {
    Provider(SemanticProviderError),
    CallTransferBudgetExceeded {
        procedure: Box<ProcedureSummaryIdentity>,
        exceeded: SemanticBudgetExceeded,
    },
    RetainedClosureBudgetExceeded(SemanticBudgetExceeded),
    Cancelled,
    GraphBudgetExceeded,
    InvalidDependencyGraph,
    Validation(SummaryValidationError),
}

impl fmt::Display for ProductionSummaryProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider(error) => write!(formatter, "semantic provider failed: {error}"),
            Self::CallTransferBudgetExceeded {
                procedure,
                exceeded,
            } => write!(
                formatter,
                "cannot cache call-transfer closure for {:?}: {exceeded}",
                procedure.declaration(),
            ),
            Self::RetainedClosureBudgetExceeded(exceeded) => {
                write!(
                    formatter,
                    "retained semantic summary closure exceeded budget: {exceeded}"
                )
            }
            Self::Cancelled => formatter.write_str("semantic summary projection was cancelled"),
            Self::GraphBudgetExceeded => {
                formatter.write_str("semantic summary graph-analysis budget was exceeded")
            }
            Self::InvalidDependencyGraph => {
                formatter.write_str("semantic summary dependency graph was invalid")
            }
            Self::Validation(error) => write!(formatter, "invalid semantic summary: {error}"),
        }
    }
}

impl std::error::Error for ProductionSummaryProjectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Provider(error) => Some(error),
            Self::Validation(error) => Some(error),
            Self::CallTransferBudgetExceeded { exceeded, .. } => Some(exceeded),
            Self::RetainedClosureBudgetExceeded(exceeded) => Some(exceeded),
            Self::Cancelled | Self::GraphBudgetExceeded | Self::InvalidDependencyGraph => None,
        }
    }
}

impl From<SemanticProviderError> for ProductionSummaryProjectionError {
    fn from(error: SemanticProviderError) -> Self {
        Self::Provider(error)
    }
}

impl From<SummaryValidationError> for ProductionSummaryProjectionError {
    fn from(error: SummaryValidationError) -> Self {
        Self::Validation(error)
    }
}

#[derive(Debug, Clone)]
struct DirectCallEffect {
    call: CallSiteId,
    ordinal: usize,
    callee: ProcedureSummaryIdentity,
    evidence: SummaryEvidence,
}

fn record_direct_call_effect(
    effects: &mut Vec<DirectCallEffect>,
    call: CallSiteId,
    ordinal: usize,
    callee: ProcedureSummaryIdentity,
    evidence: SummaryEvidence,
) -> Result<(), SummaryValidationError> {
    if let Some(current) = effects
        .iter_mut()
        .find(|current| current.call == call && current.callee == callee)
    {
        assert_eq!(
            current.ordinal, ordinal,
            "one semantic call has one stable procedure-local ordinal"
        );
        current.evidence = current.evidence.join(&evidence)?;
    } else {
        effects.push(DirectCallEffect {
            call,
            ordinal,
            callee,
            evidence,
        });
    }
    Ok(())
}

/// Project the exact production ICFG dependency closure into stable reusable
/// summaries.
pub fn project_production_semantic_summaries<Provider>(
    roots: &[ProcedureHandle],
    provider: &Provider,
    request: &mut SemanticRequest<'_>,
) -> Result<ProductionSemanticSummarySet, ProductionSummaryProjectionError>
where
    Provider: IcfgProvider,
{
    let behavior = production_summary_behavior(provider.behavior_identity());
    project_production_semantic_summaries_with_behavior(roots, provider, behavior, request)
}

fn project_production_semantic_summaries_with_behavior<Provider>(
    roots: &[ProcedureHandle],
    provider: &Provider,
    behavior: SummaryBehaviorKey,
    request: &mut SemanticRequest<'_>,
) -> Result<ProductionSemanticSummarySet, ProductionSummaryProjectionError>
where
    Provider: IcfgProvider + ?Sized,
{
    let mut procedures = roots.to_vec();
    canonicalize_procedures(&mut procedures, behavior);
    let mut index_by_handle = procedures
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, procedure)| (procedure, index))
        .collect::<HashMap<_, _>>();
    let mut direct_dependencies = vec![Vec::<ProcedureHandle>::new(); procedures.len()];
    let mut complete_call_targets =
        vec![HashMap::<CallSiteId, Box<[ProcedureHandle]>>::default(); procedures.len()];
    let mut direct_call_effects = vec![Vec::<DirectCallEffect>::new(); procedures.len()];
    let mut direct_effects = vec![Vec::<SummaryEffect>::new(); procedures.len()];
    let mut cursor = 0usize;

    while cursor < procedures.len() {
        let procedure = procedures[cursor].clone();
        let mut dependencies = Vec::new();
        for (call_ordinal, call) in procedure.semantics().call_sites().iter().enumerate() {
            // Detached callees are source dependencies, but never synchronous
            // call transfers: their bodies do not return into this caller.
            if call.invocation_mode == CallInvocationMode::Detached {
                // An IR-owned local target is already exact and needs no
                // second dispatch query.
                if let CallableTargetResolution::Proven(CallableTarget::Local(target)) =
                    call.declared_targets
                {
                    let target = procedure
                        .artifact()
                        .procedure_handle(target)
                        .expect("validated local target belongs to its artifact");
                    let dependency = summary_identity(&target, behavior);
                    let evidence = SummaryEvidence::proven_complete();
                    record_direct_call_effect(
                        &mut direct_call_effects[cursor],
                        call.id,
                        call_ordinal,
                        dependency,
                        evidence,
                    )?;
                    complete_call_targets[cursor].insert(call.id, Box::new([target.clone()]));
                    dependencies.push(target);
                    continue;
                }
                let call_handle = procedure
                    .call_site_handle(call.id)
                    .expect("validated call belongs to its procedure");
                let outcome = provider.resolve_call(&call_handle, request)?;
                let (dispatch, outcome_complete) = match outcome {
                    SemanticOutcome::Complete { value, .. } => (Some(value), true),
                    SemanticOutcome::Ambiguous { candidates, .. } => (Some(candidates), false),
                    SemanticOutcome::Unproven { partial, .. } => (Some(partial), false),
                    SemanticOutcome::Unknown { partial, .. }
                    | SemanticOutcome::Unsupported { partial, .. } => (partial, false),
                    SemanticOutcome::ExceededBudget { exceeded, .. } => {
                        return Err(
                            ProductionSummaryProjectionError::CallTransferBudgetExceeded {
                                procedure: Box::new(summary_identity(&procedure, behavior)),
                                exceeded,
                            },
                        );
                    }
                    SemanticOutcome::Cancelled { .. } => {
                        return Err(ProductionSummaryProjectionError::Cancelled);
                    }
                };
                let dispatch_complete = dispatch.as_ref().is_some_and(|dispatch| {
                    outcome_complete
                        && dispatch.coverage() == CandidateCoverage::Exhaustive
                        && dispatch.boundaries().is_empty()
                        && !dispatch.candidates().is_empty()
                        && dispatch.candidates().iter().all(|candidate| {
                            matches!(candidate.proof(), ProofStatus::Proven)
                                && matches!(
                                    candidate.completeness(),
                                    EvidenceCompleteness::Complete
                                )
                        })
                });
                if !dispatch_complete {
                    direct_effects[cursor].push(project_open_call_effect(
                        &procedure,
                        call,
                        "detached call dispatch was not complete",
                    )?);
                }
                if let Some(dispatch) = dispatch {
                    // Exact candidates are stable may-dependencies. Do not put
                    // them in `complete_call_targets`: raw dispatch does not
                    // establish a complete target set for this invocation.
                    for candidate in dispatch.candidates().iter().filter(|candidate| {
                        matches!(candidate.proof(), ProofStatus::Proven)
                            && matches!(candidate.completeness(), EvidenceCompleteness::Complete)
                    }) {
                        let target = candidate.target().clone();
                        let dependency = summary_identity(&target, behavior);
                        let evidence = SummaryEvidence::from_semantic(
                            candidate.proof(),
                            candidate.completeness(),
                        )?;
                        record_direct_call_effect(
                            &mut direct_call_effects[cursor],
                            call.id,
                            call_ordinal,
                            dependency,
                            evidence,
                        )?;
                        dependencies.push(target);
                    }
                }
                continue;
            }
            let outcome = provider.call_transfers(&procedure, call.id, request)?;
            let (value, outcome_evidence, dispatch_complete) = match outcome {
                SemanticOutcome::Complete { value, .. } => {
                    (value, SummaryEvidence::proven_complete(), true)
                }
                SemanticOutcome::Ambiguous { .. } => {
                    direct_effects[cursor].push(project_open_call_effect(
                        &procedure,
                        call,
                        "call dispatch was ambiguous",
                    )?);
                    continue;
                }
                SemanticOutcome::Unproven { partial, .. } => {
                    direct_effects[cursor].push(project_open_call_effect(
                        &procedure,
                        call,
                        "call dispatch was not proven",
                    )?);
                    // The explicit open boundary accounts for targets omitted
                    // from the partial answer. Each retained transfer is still
                    // a real may-call dependency and must not inherit the
                    // aggregate dispatch incompleteness a second time.
                    (partial, SummaryEvidence::proven_complete(), false)
                }
                SemanticOutcome::Unknown { .. } | SemanticOutcome::Unsupported { .. } => {
                    direct_effects[cursor].push(project_open_call_effect(
                        &procedure,
                        call,
                        "call transfer was unavailable",
                    )?);
                    continue;
                }
                SemanticOutcome::ExceededBudget { exceeded, .. } => {
                    return Err(
                        ProductionSummaryProjectionError::CallTransferBudgetExceeded {
                            procedure: Box::new(summary_identity(&procedure, behavior)),
                            exceeded,
                        },
                    );
                }
                SemanticOutcome::Cancelled { .. } => {
                    return Err(ProductionSummaryProjectionError::Cancelled);
                }
            };
            for (boundary_index, boundary) in value.boundaries.iter().enumerate() {
                direct_effects[cursor].push(project_boundary_effect(
                    &procedure,
                    call,
                    boundary,
                    boundary_index,
                    call_ordinal,
                )?);
            }
            if dispatch_complete && value.boundaries.is_empty() && !value.transfers.is_empty() {
                let mut targets = value
                    .transfers
                    .iter()
                    .map(|transfer| transfer.callee.clone())
                    .collect::<Vec<_>>();
                canonicalize_procedures(&mut targets, behavior);
                complete_call_targets[cursor].insert(call.id, targets.into_boxed_slice());
            }
            for transfer in value.transfers {
                let dependency = summary_identity(&transfer.callee, behavior);
                let evidence =
                    SummaryEvidence::from_semantic(&transfer.proof, &transfer.completeness)?
                        .conjoin(&outcome_evidence)?;
                record_direct_call_effect(
                    &mut direct_call_effects[cursor],
                    call.id,
                    call_ordinal,
                    dependency,
                    evidence,
                )?;
                dependencies.push(transfer.callee);
            }
        }
        canonicalize_procedures(&mut dependencies, behavior);
        for dependency in &dependencies {
            if !index_by_handle.contains_key(dependency) {
                let index = procedures.len();
                procedures.push(dependency.clone());
                direct_dependencies.push(Vec::new());
                complete_call_targets.push(HashMap::default());
                direct_call_effects.push(Vec::new());
                direct_effects.push(Vec::new());
                index_by_handle.insert(dependency.clone(), index);
            }
        }
        direct_dependencies[cursor] = dependencies;
        cursor += 1;
    }

    let mut canonical_order = (0..procedures.len()).collect::<Vec<_>>();
    canonical_order.sort_unstable_by(|&left, &right| {
        summary_identity(&procedures[left], behavior)
            .cmp(&summary_identity(&procedures[right], behavior))
    });
    let mut canonical_by_old = vec![0usize; procedures.len()];
    for (canonical, old) in canonical_order.iter().copied().enumerate() {
        canonical_by_old[old] = canonical;
    }
    let canonical_procedures = canonical_order
        .iter()
        .map(|&old| procedures[old].clone())
        .collect::<Vec<_>>();
    let canonical_edges = canonical_order
        .iter()
        .map(|&old| {
            let mut dependencies = direct_dependencies[old]
                .iter()
                .map(|dependency| canonical_by_old[index_by_handle[dependency]])
                .collect::<Vec<_>>();
            dependencies.sort_unstable();
            dependencies.dedup();
            dependencies
        })
        .collect::<Vec<_>>();
    let canonical_call_effects = canonical_order
        .iter()
        .map(|&old| direct_call_effects[old].clone())
        .collect::<Vec<_>>();
    let canonical_effects = canonical_order
        .iter()
        .map(|&old| direct_effects[old].clone())
        .collect::<Vec<_>>();
    let canonical_call_targets = canonical_order
        .iter()
        .map(|&old| complete_call_targets[old].clone())
        .collect::<Vec<_>>();
    let graph = ProcedureDependencyGraph::new(canonical_edges);
    let mut graph_budget = CfgAlgorithmBudget::default();
    let mut graph_request = CfgAlgorithmRequest::new(&mut graph_budget, request.cancellation);
    let sccs =
        strongly_connected_components(&graph, &mut graph_request).map_err(|error| match error {
            CfgAlgorithmError::Cancelled { .. } => ProductionSummaryProjectionError::Cancelled,
            CfgAlgorithmError::ExceededBudget(_) => {
                ProductionSummaryProjectionError::GraphBudgetExceeded
            }
            CfgAlgorithmError::InvalidNode(_) => {
                ProductionSummaryProjectionError::InvalidDependencyGraph
            }
        })?;

    build_summary_set(
        &canonical_procedures,
        DirectSummaryProjection {
            calls: &canonical_call_effects,
            effects: &canonical_effects,
            call_targets: &canonical_call_targets,
        },
        &graph,
        &sccs.components,
        behavior,
        request.cancellation,
    )
}

fn direct_summary_port(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    value: ValueId,
) -> Option<SummaryPort> {
    match semantics.value(value)?.kind {
        SemanticValueKind::Parameter { ordinal, .. } => Some(SummaryPort::Parameter(ordinal)),
        SemanticValueKind::Receiver { .. } => Some(SummaryPort::Receiver),
        _ => None,
    }
}

fn direct_value_is_reassigned(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    value: ValueId,
    indirect_writes: &HashSet<ValueId>,
) -> bool {
    indirect_writes.contains(&value)
        || semantics
            .points()
            .iter()
            .flat_map(|point| point.events.iter().map(move |event| (point.id, event)))
            .any(|(point, event)| match event.effect {
                SemanticEffect::Assignment { target, .. } => target == value,
                SemanticEffect::MemoryStore { location, .. } => {
                    !semantics.is_formal_cell_initialization(point, &event.effect)
                        && semantics.memory_location(location).is_some_and(
                            |location| match location.kind {
                                MemoryLocationKind::LexicalCell { binding } => binding == value,
                                MemoryLocationKind::Capture {
                                    binding: Some(binding),
                                    ..
                                } => binding == value,
                                _ => false,
                            },
                        )
                }
                _ => false,
            })
}

fn indirect_binding_write_targets(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    origins: &BindingOriginIndex,
) -> HashSet<ValueId> {
    let mut written = HashSet::default();
    let address_taken = origins.address_taken_bindings();
    for point in semantics.points() {
        for event in &point.events {
            let SemanticEffect::MemoryStore { location, .. } = event.effect else {
                continue;
            };
            let Some(MemoryLocationKind::Dereference { address }) = semantics
                .memory_location(location)
                .map(|location| &location.kind)
            else {
                continue;
            };
            let targets = origins.addressed_binding_origins(*address);
            if targets.is_complete() {
                written.extend(targets.bindings().iter().copied());
            } else {
                written.extend(address_taken.iter().copied());
            }
        }
    }
    for binding in address_taken {
        let relevant = crate::hash::HashSet::from_iter([binding]);
        let aliases = crate::flow_state::address_alias_values(semantics, &relevant);
        if !crate::flow_state::address_escape_points(semantics, &aliases, &[]).is_empty() {
            written.insert(binding);
        }
    }
    written
}

/// The exact boundary or literal source of one immutable scalar snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectScalarSource {
    Port(SummaryPort),
    UnsignedInteger(u128),
    Boolean(bool),
    /// An exact structured string constant, spelled as its source text.
    ConstantString(Box<str>),
    IntegerOffset {
        source: ValueId,
        offset: crate::analyzer::semantic::SignedIntegerMagnitude,
    },
}

/// Follow an immutable scalar snapshot to the procedure port or literal that
/// supplied it. Go evaluates an index expression into a temporary before
/// constructing the indexed memory location, so inspecting only the
/// temporary's value kind loses the exact source. A computed expression,
/// assignment, or competing source remains unavailable.
pub fn direct_scalar_source(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    mut value: ValueId,
) -> Option<DirectScalarSource> {
    let mut visited = crate::hash::HashSet::default();
    let binding_origins = BindingOriginIndex::from_semantics(semantics);
    let indirect_writes = indirect_binding_write_targets(semantics, &binding_origins);
    loop {
        if !visited.insert(value) {
            return None;
        }
        let reassigned = direct_value_is_reassigned(semantics, value, &indirect_writes);
        if reassigned {
            return None;
        }
        if let Some(port) = direct_summary_port(semantics, value) {
            return Some(DirectScalarSource::Port(port));
        }
        if let SemanticValueKind::UnsignedInteger(integer) = semantics.value(value)?.kind {
            return Some(DirectScalarSource::UnsignedInteger(integer));
        }
        if let SemanticValueKind::Boolean(boolean) = semantics.value(value)?.kind {
            return Some(DirectScalarSource::Boolean(boolean));
        }
        if let SemanticValueKind::ConstantString(text) = semantics.value(value)?.kind.clone() {
            return Some(DirectScalarSource::ConstantString(text));
        }
        let mut predecessors = semantics
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .filter_map(|event| match &event.effect {
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Local | ValueFlowKind::Parameter | ValueFlowKind::Receiver,
                    source,
                    target,
                } if *target == value => Some((*source, None)),
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::IntegerOffset { offset },
                    source,
                    target,
                } if *target == value => Some((*source, Some(*offset))),
                _ => None,
            });
        let (predecessor, offset) = predecessors.next()?;
        if predecessors.next().is_some() {
            return None;
        }
        if let Some(offset) = offset {
            return Some(DirectScalarSource::IntegerOffset {
                source: predecessor,
                offset,
            });
        }
        value = predecessor;
    }
}

fn project_boundary_effect(
    procedure: &ProcedureHandle,
    call: &SemanticCallSite,
    boundary: &CallBoundary,
    boundary_index: usize,
    call_ordinal: usize,
) -> Result<SummaryEffect, SummaryValidationError> {
    let mapping = procedure
        .semantics()
        .source_mapping(call.source)
        .expect("validated semantic call retains a source mapping");
    let span = mapping.locator.anchor().span();
    let mut bytes = Vec::with_capacity(128);
    bytes.extend_from_slice(CALL_EFFECT_DOMAIN);
    bytes.extend_from_slice(procedure.artifact().key().fingerprint().as_bytes());
    bytes.extend_from_slice(&span.start_byte().to_le_bytes());
    bytes.extend_from_slice(&span.end_byte().to_le_bytes());
    bytes.extend_from_slice(&boundary_index.to_le_bytes());
    bytes.extend_from_slice(match &boundary.dispatch.kind {
        crate::analyzer::semantic::DispatchBoundaryKind::External(_) => b"external",
        crate::analyzer::semantic::DispatchBoundaryKind::Unmaterialized(_) => b"unmaterialized",
        crate::analyzer::semantic::DispatchBoundaryKind::Deferred { .. } => b"deferred",
        crate::analyzer::semantic::DispatchBoundaryKind::Unresolved => b"unresolved",
        crate::analyzer::semantic::DispatchBoundaryKind::Truncated => b"truncated",
    });
    Ok(SummaryEffect::new(
        SummaryEffectKey::UnknownCallBoundary {
            event: SummaryEventKey::hash_bytes(bytes),
            external_call: matches!(
                boundary.dispatch.kind,
                crate::analyzer::semantic::DispatchBoundaryKind::External(_)
            )
            .then(|| {
                (
                    SummaryEventKey::from_call_source(&mapping.locator, call_ordinal),
                    SummaryCallSourceWitness::new(
                        procedure.semantics().locator(),
                        span.start_byte(),
                        span.end_byte(),
                    ),
                )
            }),
        },
        SummaryEvidence::from_semantic(&boundary.dispatch.proof, &boundary.dispatch.completeness)?,
    ))
}

fn project_open_call_effect(
    procedure: &ProcedureHandle,
    call: &SemanticCallSite,
    reason: &str,
) -> Result<SummaryEffect, SummaryValidationError> {
    let mapping = procedure
        .semantics()
        .source_mapping(call.source)
        .expect("validated semantic call retains a source mapping");
    let mut digest = LengthDelimitedDigest::new(CALL_EFFECT_DOMAIN);
    digest.push(procedure.artifact().key().public_fingerprint().as_bytes());
    mapping.locator.push_stable_identity(&mut digest);
    digest.push(reason.as_bytes());
    Ok(SummaryEffect::new(
        SummaryEffectKey::UnknownCallBoundary {
            event: SummaryEventKey::from_digest(digest.finish()),
            external_call: None,
        },
        SummaryEvidence::try_new(vec![reason.to_owned()], vec![reason.to_owned()])?,
    ))
}

struct DirectSummaryProjection<'a> {
    calls: &'a [Vec<DirectCallEffect>],
    effects: &'a [Vec<SummaryEffect>],
    call_targets: &'a [HashMap<CallSiteId, Box<[ProcedureHandle]>>],
}

fn build_summary_set(
    procedures: &[ProcedureHandle],
    direct: DirectSummaryProjection<'_>,
    graph: &ProcedureDependencyGraph,
    components: &[Box<[usize]>],
    behavior: SummaryBehaviorKey,
    cancellation: &crate::cancellation::CancellationToken,
) -> Result<ProductionSemanticSummarySet, ProductionSummaryProjectionError> {
    let DirectSummaryProjection {
        calls: direct_calls,
        effects: direct_effects,
        call_targets: direct_call_targets,
    } = direct;
    let identities = procedures
        .iter()
        .map(|procedure| summary_identity(procedure, behavior))
        .collect::<Vec<_>>();
    let component_order =
        ProcedureDependencyComponentOrder::new(graph, components, procedures.len())
            .ok_or(ProductionSummaryProjectionError::InvalidDependencyGraph)?;
    let component_by_node = &component_order.component_by_node;

    let mut key_by_node = vec![None::<ProcedureSummaryKey>; procedures.len()];
    let mut summaries = Vec::with_capacity(procedures.len());
    let mut summary_components = Vec::with_capacity(components.len());

    for &component in &component_order.components {
        if cancellation.is_cancelled() {
            return Err(ProductionSummaryProjectionError::Cancelled);
        }
        let mut members = components[component].to_vec();
        members.sort_unstable();
        let recursive = members.len() > 1
            || graph.outgoing[members[0]]
                .iter()
                .any(|edge| graph.edges[*edge].1 == members[0]);
        let member_identities = members
            .iter()
            .map(|&member| identities[member].clone())
            .collect::<Vec<_>>();
        let mut recursive_edges = Vec::new();
        for &caller in &members {
            for &edge in &graph.outgoing[caller] {
                let callee = graph.edges[edge].1;
                if component_by_node[callee] == component {
                    recursive_edges.push(SummaryRecursiveEdge::new(
                        identities[caller].clone(),
                        identities[callee].clone(),
                    ));
                }
            }
        }
        let mut external_keys = members
            .iter()
            .flat_map(|&member| {
                graph.outgoing[member].iter().filter_map(|&edge| {
                    let callee = graph.edges[edge].1;
                    (component_by_node[callee] != component).then(|| {
                        key_by_node[callee]
                            .clone()
                            .expect("dependency component emitted")
                    })
                })
            })
            .collect::<Vec<_>>();
        external_keys.sort_unstable();
        external_keys.dedup();
        let recursive_group = recursive
            .then(|| {
                SummaryRecursiveGroupKey::from_closure(
                    &member_identities,
                    &recursive_edges,
                    &external_keys,
                )
            })
            .transpose()?;

        let started = summaries.len();
        for &member in &members {
            let mut dependencies = graph.outgoing[member]
                .iter()
                .map(|&edge| {
                    let callee = graph.edges[edge].1;
                    if component_by_node[callee] == component {
                        SummaryDependencyKey::recursive(identities[callee].clone())
                    } else {
                        SummaryDependencyKey::complete(
                            key_by_node[callee]
                                .clone()
                                .expect("dependency component emitted"),
                        )
                    }
                })
                .collect::<Vec<_>>();
            dependencies.sort_unstable();
            dependencies.dedup();
            let key = ProcedureSummaryKey::try_new(
                identities[member].clone(),
                &dependencies,
                recursive_group,
            )?;
            let mut effects = direct_calls[member]
                .iter()
                .map(|call_effect| {
                    let dependency = dependencies
                        .iter()
                        .find(|dependency| dependency.identity() == &call_effect.callee)
                        .expect("every direct call target is a retained dependency");
                    let call = procedures[member]
                        .semantics()
                        .call_site(call_effect.call)
                        .expect("direct call effect belongs to its procedure");
                    let mapping = procedures[member]
                        .semantics()
                        .source_mapping(call.source)
                        .expect("validated call retains a source mapping");
                    let span = mapping.locator.anchor().span();
                    SummaryEffect::new(
                        SummaryEffectKey::Call {
                            event: SummaryEventKey::from_call_source(
                                &mapping.locator,
                                call_effect.ordinal,
                            ),
                            callee: Box::new(dependency.clone()),
                            witness: Some(SummaryCallSourceWitness::new(
                                procedures[member].semantics().locator(),
                                span.start_byte(),
                                span.end_byte(),
                            )),
                        },
                        call_effect.evidence.clone(),
                    )
                })
                .collect::<Vec<_>>();
            effects.extend_from_slice(&direct_effects[member]);
            let summary = SemanticProcedureSummary::try_new(
                key.clone(),
                Vec::new(),
                effects,
                dependencies,
                SummaryCompleteness::Complete,
            )?;
            key_by_node[member] = Some(key);
            summaries.push(summary);
        }
        summary_components.push(started..summaries.len());
    }

    if summary_components.len() != components.len() {
        return Err(ProductionSummaryProjectionError::InvalidDependencyGraph);
    }

    let complete_call_targets = procedures
        .iter()
        .zip(direct_call_targets)
        .flat_map(|(procedure, calls)| {
            calls
                .iter()
                .map(|(&call, targets)| ((procedure.clone(), call), targets.clone()))
        })
        .collect();

    Ok(ProductionSemanticSummarySet {
        summaries,
        components: summary_components,
        complete_call_targets,
        behavior,
        procedure_semantics_precharged: true,
    })
}

/// The summary behavior one ICFG provider induces, in both halves.
///
/// The cache half folds the provider's full identity; the read half folds the
/// provider's own read half, which is the same engine without the workspace's
/// content identity. Derived from the same domain because they name the same
/// thing at two precisions, and the provider's two digests already live under
/// two domains of their own.
fn production_icfg_behavior(provider: IcfgProviderBehaviorIdentity) -> SummaryBehaviorKey {
    let derive = |identity: &[u8; 32]| {
        let mut bytes = Vec::with_capacity(
            PRODUCTION_ICFG_BEHAVIOR_DOMAIN
                .len()
                .saturating_add(identity.len()),
        );
        bytes.extend_from_slice(PRODUCTION_ICFG_BEHAVIOR_DOMAIN);
        bytes.extend_from_slice(identity);
        crate::analyzer::semantic::ids::StableDigest::sha256(bytes)
    };
    SummaryBehaviorKey::from_parts(derive(provider.as_bytes()), derive(provider.read_bytes()))
}

fn production_summary_behavior(provider: IcfgProviderBehaviorIdentity) -> SummaryBehaviorKey {
    let behavior = production_icfg_behavior(provider);
    let derive = |identity: &[u8; 32]| {
        let mut digest = LengthDelimitedDigest::new(PRODUCTION_SUMMARY_BEHAVIOR_DOMAIN);
        digest.push(identity);
        digest.finish()
    };
    SummaryBehaviorKey::from_parts(derive(behavior.as_bytes()), derive(behavior.read_bytes()))
}

fn provider_independent_leaf_behavior() -> SummaryBehaviorKey {
    static BEHAVIOR: OnceLock<SummaryBehaviorKey> = OnceLock::new();
    *BEHAVIOR.get_or_init(|| {
        let digest = LengthDelimitedDigest::new(PROVIDER_INDEPENDENT_LEAF_BEHAVIOR);
        SummaryBehaviorKey::from_digest(digest.finish())
    })
}

fn summary_identity(
    procedure: &ProcedureHandle,
    provider_behavior: SummaryBehaviorKey,
) -> ProcedureSummaryIdentity {
    let uses_provider = !procedure.semantics().call_sites().is_empty();
    let behavior = if uses_provider {
        provider_behavior
    } else {
        provider_independent_leaf_behavior()
    };
    ProcedureSummaryIdentity::new(
        procedure.artifact().key().clone(),
        procedure.semantics().locator().declaration().clone(),
        SummarySchemaVersion::CURRENT,
        SummarySemanticsVersion::hash_bytes(PRODUCTION_SUMMARY_SEMANTICS),
        SummaryContextKey::hash_bytes(EMPTY_CALL_CONTEXT),
        behavior,
        SummaryOrigin::Inferred,
    )
}

fn canonicalize_procedures(procedures: &mut Vec<ProcedureHandle>, behavior: SummaryBehaviorKey) {
    procedures.sort_unstable_by_key(|procedure| summary_identity(procedure, behavior));
    procedures.dedup_by(|left, right| {
        summary_identity(left, behavior) == summary_identity(right, behavior)
    });
}
