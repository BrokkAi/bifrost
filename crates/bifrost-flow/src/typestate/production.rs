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
//! procedure is keyed by the active semantic model set alone, the digest
//! `ReadKey::Models` records, so an edit to an unrelated file does not discard
//! an exact reusable leaf summary, while a change of model set (which carries
//! any close-match approximation claim) recomputes it. A
//! protocol summary adds the protocol and binding hashes. A whole solved result
//! adds the entry facts, the full provider execution behavior, and both
//! remaining budgets.
//!
//! This remains generation-independent: a stale entry is simply an entry
//! nothing asks for again, and the byte and entry limits retire it. The full
//! workspace behavior conservatively rotates provider-dependent summaries
//! after an analyzed edit, while call-free leaves remain reusable. This
//! replaces an earlier generation gate that rotated the whole repository on
//! every workspace update and prevented the policy and search surfaces from
//! sharing exact retained work.
//!
//! Budget-dependent results are still refused rather than retained, on the same
//! grounds `memoizable_outcome` states for value flow: exceeding a budget or
//! being cancelled is a property of the request, not of the artifact, so
//! freezing one into the cache would deny a later, better-funded request the
//! better answer it could reach. See [`solve_typestate_with_production_summaries`].

use crate::analyzer::ReadKey;
use crate::analyzer::WorkspaceAnalyzer;
use crate::analyzer::workspace_authority::{ReplayingMemo, ReplayingMemoEntry};
use crate::semantic_summary::{ProcedureDependencyComponentOrder, ProcedureDependencyGraph};
use brokk_bifrost_core::analyzer::memo_attribution::ReplayedMemoValue;
use std::fmt;
use std::sync::{Arc, Condvar, Mutex};

use crate::analyzer::semantic::cfg_algorithms::{
    CfgAlgorithmBudget, CfgAlgorithmError, CfgAlgorithmRequest, strongly_connected_components,
};
use crate::analyzer::semantic::{
    BindingOriginIndex, CallBoundary, CallInvocationMode, CallSiteId, CallableTarget,
    CallableTargetResolution, CandidateCoverage, EvidenceCompleteness, FootprintAdmission,
    IcfgProvider, IcfgProviderBehaviorIdentity, LengthDelimitedDigest, MemoryLocationKind,
    ProcedureHandle, ProofStatus, SemanticBudget, SemanticBudgetExceeded, SemanticCallSite,
    SemanticEffect, SemanticExecutionBudget, SemanticExecutionBudgetCharge,
    SemanticExecutionBudgetSnapshot, SemanticOutcome, SemanticProviderError, SemanticRequest,
    SemanticValueKind, SemanticWork, ValueFlowKind, ValueId,
};
use crate::dataflow::{
    DataflowRequest, ProcedureSummaryIdentity, ProcedureSummaryKey,
    ProductionSemanticSummaryRepository, SemanticInputStatus, SemanticProcedureSummary, SolverWork,
    SummaryBehaviorKey, SummaryBoundaryKind, SummaryCallSourceWitness, SummaryCompleteness,
    SummaryContextKey, SummaryDependencyKey, SummaryDimension, SummaryDimensionClaim,
    SummaryDimensionState, SummaryDimensionStatus, SummaryEffect, SummaryEffectKey,
    SummaryEventKey, SummaryEvidence, SummaryIncompleteReason, SummaryOrigin, SummaryPort,
    SummaryPublicationError, SummaryPublicationOutcome, SummaryReadObserver, SummaryRecursiveEdge,
    SummaryRecursiveGroupKey, SummaryRepositoryLimits, SummarySchemaVersion,
    SummarySemanticsVersion, SummaryValidationError,
};
use crate::hash::{HashMap, HashSet};

use super::{
    CompiledProtocol, CompleteProtocolSummaryRepository, ProtocolFactKey, ProtocolReceiptVerdict,
    ProtocolReceiptVerifier, ProtocolSemanticSummarySet, ProtocolSummaryCacheStatus,
    ProtocolSummaryError, ProtocolSummaryRepositoryLimits, ProtocolSummarySolveError,
    TypestateBindingPlan, TypestateBindingPlanHash, TypestateFact, TypestateProtocolHash,
    TypestateSummaryResult, solve_typestate_with_reusable_summaries,
    solve_typestate_with_summaries,
};

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static TYPESTATE_PROTOCOL_SERVING_OVERRIDE: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// Scope protocol serving to one test thread without changing process environment.
#[cfg(any(test, feature = "test-support"))]
pub fn with_typestate_protocol_serving_for_test<T>(serving: bool, run: impl FnOnce() -> T) -> T {
    struct Restore(Option<bool>);
    impl Drop for Restore {
        fn drop(&mut self) {
            TYPESTATE_PROTOCOL_SERVING_OVERRIDE.with(|value| value.set(self.0));
        }
    }
    TYPESTATE_PROTOCOL_SERVING_OVERRIDE.with(|value| {
        let previous = Restore(value.replace(Some(serving)));
        let result = run();
        drop(previous);
        result
    })
}

// Serving stays closed by default. It may open only after #10325 (certified
// definition-probe keys, so protocol receipts hold no raw Index read), the
// served-against-fresh differential, and #10301 (Rust footprints can omit a
// read of a static declared in another file, so rows published today would be
// wrong once served) have landed.
fn protocol_serving_enabled() -> bool {
    let serving = match std::env::var("BIFROST_TYPESTATE_PROTOCOL_SERVING") {
        Ok(value) if value == "1" => true,
        Ok(value) if value == "0" => false,
        Err(std::env::VarError::NotPresent) => false,
        value => panic!("invalid BIFROST_TYPESTATE_PROTOCOL_SERVING: {value:?}"),
    };
    #[cfg(any(test, feature = "test-support"))]
    let serving = TYPESTATE_PROTOCOL_SERVING_OVERRIDE
        .with(|override_value| override_value.get().unwrap_or(serving));
    serving
}

/// Verifies served protocol rows against the request that serves them. One
/// verifier is bound per production solve, so its lookup memo answers each
/// question once against one head, and no answer outlives that workspace.
pub(super) struct ProductionProtocolReceiptVerifier {
    pub(super) workspace: WorkspaceAnalyzer,
    pub(super) memo: std::sync::Mutex<crate::analyzer::LookupMemo>,
}

impl fmt::Debug for ProductionProtocolReceiptVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionProtocolReceiptVerifier")
            .finish()
    }
}

struct ProductionProtocolInventorySource {
    workspace: WorkspaceAnalyzer,
    snapshot: crate::analyzer::read_verification::DefinitionInventorySnapshot,
    cancellation: crate::cancellation::CancellationToken,
}

impl fmt::Debug for ProductionProtocolInventorySource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionProtocolInventorySource")
            .field("snapshot", &self.snapshot)
            .finish()
    }
}

impl super::summary::ProtocolInventorySource for ProductionProtocolInventorySource {
    fn certify(&self, raw: &ReadKey) -> Option<super::summary::DefinitionIndexInventory> {
        if self.cancellation.is_cancelled() {
            return None;
        }
        let ReadKey::Index { family, key } = raw else {
            return None;
        };
        let digest = self
            .snapshot
            .digest(self.workspace.analyzer(), *family, key)?;
        if self.cancellation.is_cancelled() {
            return None;
        }
        Some(super::summary::DefinitionIndexInventory {
            raw: raw.clone(),
            normalization_version: (*family
                == crate::analyzer::read_ledger::IndexFamily::DefinitionNormalizedTail)
                .then_some(
                    crate::analyzer::semantic::read_ledger::DEFINITION_NORMALIZED_TAIL_VERSION,
                ),
            delegates: self.snapshot.languages(),
            digest,
        })
    }
}

impl ProtocolReceiptVerifier for ProductionProtocolReceiptVerifier {
    fn verify(&self, receipt: &super::summary::ProtocolMemberReceipt) -> ProtocolReceiptVerdict {
        use crate::analyzer::{ChangedFacts, HeadInputs, LookupReplayLimits, ReadVerdict};

        // The protocol compilation belongs to this request. Raw index reads and
        // policy, configuration and epoch inputs are unavailable from the
        // workspace, so a receipt that names one cannot be proved here and
        // fails closed. The model set is available from the analyzer, and
        // #9755 records its absence as a read too, so it is verified below
        // rather than refused.
        let _verification = crate::analyzer::ReadAttribution::for_receipt_verification().install();
        let mut keys = Vec::new();
        for key in receipt.protocol_keys() {
            match key.certificate() {
                None => keys.push(key.as_read_key().clone()),
                Some(certificate) => {
                    let Some(snapshot) =
                        crate::analyzer::read_verification::DefinitionInventorySnapshot::capture(
                            self.workspace.analyzer(),
                        )
                    else {
                        return ProtocolReceiptVerdict::Unverifiable;
                    };
                    let ReadKey::Index { family, key } = &certificate.raw else {
                        return ProtocolReceiptVerdict::Unverifiable;
                    };
                    let expected_version = (*family == crate::analyzer::read_ledger::IndexFamily::DefinitionNormalizedTail)
                        .then_some(crate::analyzer::semantic::read_ledger::DEFINITION_NORMALIZED_TAIL_VERSION);
                    if snapshot.languages() != certificate.delegates
                        || certificate.normalization_version != expected_version
                    {
                        return ProtocolReceiptVerdict::Unverifiable;
                    }
                    let Some(digest) = snapshot.digest(self.workspace.analyzer(), *family, key)
                    else {
                        return ProtocolReceiptVerdict::Unverifiable;
                    };
                    if digest != certificate.digest {
                        return ProtocolReceiptVerdict::Stale;
                    }
                }
            }
        }
        if keys.iter().any(|key| {
            matches!(
                key,
                ReadKey::Index { .. }
                    | ReadKey::Policy { .. }
                    | ReadKey::Configuration(_)
                    | ReadKey::Epoch(_)
            )
        }) {
            return ProtocolReceiptVerdict::Unverifiable;
        }
        // The verifier runs inside the serving request's read capture. Its own
        // reads must not reach that ledger: a hit replays the verified receipt
        // into the capture instead, and a lookup replay under an attached
        // ledger would be an unattributed read that refuses unit reuse. Install
        // the guard before observing the model set for the same reason.
        let unused = crate::analyzer::semantic::ids::StableDigest::sha256([]);
        // A receipt recorded through either model accessor verifies only while
        // those accessors still agree. When they disagree, no recorded model
        // read can equal `unused`, so a receipt carrying one is Stale while a
        // receipt that did not read the model set is unaffected.
        let models =
            crate::analyzer::i_analyzer::current_model_set_read_digest(self.workspace.analyzer())
                .unwrap_or(unused);
        let inputs = HeadInputs {
            models,
            policy_semantic_hash: unused,
            policy_source: unused,
            configuration: unused,
            epoch: unused,
        };
        // The keys left after the refusal above (file, path-absence, lookup,
        // artifact and scope keys) are checked directly against the head, so
        // no base difference is needed, and building one would enumerate the
        // whole workspace for every lookup.
        if matches!(
            crate::analyzer::verify_read_set(
                &self.workspace,
                &ChangedFacts::without_base(),
                &inputs,
                &keys,
                LookupReplayLimits::default(),
                &crate::analyzer::NoSummaryAnswers,
                &mut self
                    .memo
                    .lock()
                    .expect("protocol receipt lookup memo poisoned"),
            ),
            ReadVerdict::Unchanged
        ) {
            ProtocolReceiptVerdict::Current
        } else {
            ProtocolReceiptVerdict::Stale
        }
    }
}

const PRODUCTION_SUMMARY_SEMANTICS: &[u8] = b"bifrost-production-semantic-summary-v27";
const EMPTY_CALL_CONTEXT: &[u8] = b"bifrost-production-empty-call-context-v1";
const PRODUCTION_ICFG_BEHAVIOR_DOMAIN: &[u8] = b"bifrost-production-icfg-behavior-v2";
const PRODUCTION_SUMMARY_BEHAVIOR_DOMAIN: &[u8] = b"bifrost-production-summary-behavior-v1";
const PROVIDER_INDEPENDENT_LEAF_BEHAVIOR: &[u8] =
    b"bifrost-production-provider-independent-leaf/v5";
const CALL_EFFECT_DOMAIN: &[u8] = b"bifrost-production-call-effect-v1";
const WORKSPACE_PROVIDER_CONTEXT: &[u8] = b"bifrost-production-workspace-provider-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProtocolAdmissionDecision {
    call_control: bool,
    footprint: bool,
}

impl ProtocolAdmissionDecision {
    fn from_coverage(
        call_control: Option<&FootprintAdmission>,
        footprint: Option<&FootprintAdmission>,
    ) -> Self {
        Self {
            call_control: matches!(call_control, Some(FootprintAdmission::Admitted { .. })),
            footprint: matches!(footprint, Some(FootprintAdmission::Admitted { .. })),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExactResultDecision {
    admissions: Vec<ProtocolAdmissionDecision>,
    reusable_route: bool,
}

fn exact_result_decision(
    summaries: &ProductionSemanticSummarySet,
    bindings: &TypestateBindingPlan,
) -> ExactResultDecision {
    let reusable_route = summaries.summaries().iter().all(|summary| {
        matches!(
            summary.coverage().state(SummaryDimension::Protocol),
            SummaryDimensionState::Complete
        )
    }) && bindings.unproven_relations().iter().all(|relation| {
        summaries
            .root_call_closure()
            .excludes(&relation.observation_procedure)
    });
    ExactResultDecision {
        admissions: summaries.protocol_admissions.clone(),
        reusable_route,
    }
}

fn summary_coverage_decision(
    call_control: Option<&FootprintAdmission>,
    footprint: Option<&FootprintAdmission>,
) -> SummaryCompleteness {
    let admission = ProtocolAdmissionDecision::from_coverage(call_control, footprint);
    let reason = if !admission.call_control {
        "call/control producer admission is unavailable or refused"
    } else if !admission.footprint {
        "full footprint producer admission is unavailable or refused"
    } else {
        return SummaryCompleteness::Complete;
    };
    SummaryCompleteness::partial(vec![SummaryIncompleteReason::SemanticGap(reason.into())])
        .expect("static summary refusal reason is valid")
}

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
/// Storage survives analyzer generations. Each query creates a reader with
/// its current analyzer's owned attribution capability; storage never retains
/// a reader or a query's recording destination.
#[derive(Debug)]
pub(crate) struct ProductionTypestateSummaryStorage {
    state: Mutex<ProductionTypestateSummaryRepositoryState>,
    semantic_summaries: Arc<crate::dataflow::ProductionSemanticSummaryStorage>,
    /// Counters live behind their own lock rather than inside `state` so a
    /// rejection can be recorded after the state guard is dropped.
    counters: Mutex<ProductionSummaryLifecycleCounters>,
    flights: Mutex<HashMap<ProductionSummaryResultKey, Arc<ProductionSummaryFlight>>>,
}

/// A query's capability-bearing reader; the workspace keeps only its storage.
#[derive(Debug)]
pub struct ProductionTypestateSummaryRepository {
    storage: Arc<ProductionTypestateSummaryStorage>,
    semantic_summaries: Arc<ProductionSemanticSummaryRepository>,
    attribution: crate::analyzer::workspace_authority::OwnedMemoCapability,
}

#[derive(Debug)]
struct ProductionTypestateSummaryRepositoryState {
    protocol: super::summary::CompleteProtocolSummaryStorage,
    results: HashMap<ProductionSummaryResultKey, RetainedTypestateSummaryResult>,
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

impl Default for ProductionTypestateSummaryStorage {
    fn default() -> Self {
        Self::with_limits(TypestateSummaryRepositoryLimits::default())
    }
}

impl ProductionTypestateSummaryStorage {
    pub(crate) fn with_limits(limits: TypestateSummaryRepositoryLimits) -> Self {
        Self::with_shared_semantic_summaries(
            limits,
            Arc::new(
                crate::dataflow::ProductionSemanticSummaryStorage::with_limits(limits.semantic),
            ),
        )
    }
    pub(crate) fn with_shared_semantic_summaries(
        limits: TypestateSummaryRepositoryLimits,
        semantic_summaries: Arc<crate::dataflow::ProductionSemanticSummaryStorage>,
    ) -> Self {
        Self {
            state: Mutex::new(ProductionTypestateSummaryRepositoryState {
                protocol: super::summary::CompleteProtocolSummaryStorage::with_limits(
                    limits.protocol,
                ),
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
    pub(crate) fn reader(
        self: &Arc<Self>,
        attribution: crate::analyzer::workspace_authority::OwnedMemoCapability,
    ) -> ProductionTypestateSummaryRepository {
        ProductionTypestateSummaryRepository {
            storage: Arc::clone(self),
            semantic_summaries: Arc::new(self.semantic_summaries.reader(attribution.clone())),
            attribution,
        }
    }
}

impl ProductionTypestateSummaryRepository {
    pub fn new(attribution: crate::analyzer::workspace_authority::OwnedMemoCapability) -> Self {
        Self::with_limits(TypestateSummaryRepositoryLimits::default(), attribution)
    }
    pub fn with_limits(
        limits: TypestateSummaryRepositoryLimits,
        attribution: crate::analyzer::workspace_authority::OwnedMemoCapability,
    ) -> Self {
        Arc::new(ProductionTypestateSummaryStorage::with_limits(limits)).reader(attribution)
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

    #[cfg(test)]
    pub(super) fn retained_result_receipt_bytes(&self) -> usize {
        self.state()
            .results
            .values()
            .map(|cached| cached.entry.retained_read_bytes(read_key_heap_bytes))
            .sum()
    }

    /// Retained semantic procedure summaries, the identities shared by every
    /// surface that analyzes this workspace.
    pub fn retained_semantic_count(&self) -> usize {
        self.semantic_summaries.len()
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

    fn result(
        &self,
        key: &ProductionSummaryResultKey,
    ) -> Option<ReplayedMemoValue<CachedTypestateSummaryResult, ReadKey>> {
        ReplayingMemo::new(())
            .read(&self.attribution.capability(), |_, _| {
                self.state()
                    .results
                    .get(key)
                    .map(|cached| Arc::clone(&cached.entry))
                    .ok_or(())
            })
            .ok()
    }

    fn record_hit(&self) {
        let mut counters = self.lifecycle_counters();
        counters.hits = counters.hits.saturating_add(1);
    }

    fn evict_result(&self, key: &ProductionSummaryResultKey) -> bool {
        let mut state = self.state();
        let Some(removed) = state.results.remove(key) else {
            return false;
        };
        state.retained_result_bytes = state.retained_result_bytes.saturating_sub(
            key.retained_bytes()
                .saturating_add(removed.retained_bytes()),
        );
        drop(state);
        self.add_evictions(1);
        true
    }

    fn publish_result(
        &self,
        key: ProductionSummaryResultKey,
        entry: Arc<ReplayingMemoEntry<CachedTypestateSummaryResult, ReadKey>>,
    ) -> (bool, usize) {
        let mut state = self.state();
        if state.results.contains_key(&key) {
            return (true, 0);
        }
        let mut retained = RetainedTypestateSummaryResult {
            entry,
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

    /// Presence is cache telemetry only; no row or read receipt reaches a solve.
    fn has_compatible_protocol_rows_for_diagnostics(
        &self,
        semantic_summaries: &ProtocolSemanticSummarySet<'_>,
        protocol: &CompiledProtocol,
        bindings: &TypestateBindingPlan,
    ) -> bool {
        let state = self
            .storage
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        semantic_summaries.has_compatible_rows_for_diagnostics(&state.protocol, protocol, bindings)
    }

    fn protocol_limits(&self) -> ProtocolSummaryRepositoryLimits {
        self.state().protocol.limits()
    }

    fn compatible_protocol_repository(
        &self,
        semantic_summaries: &ProtocolSemanticSummarySet<'_>,
        protocol: &CompiledProtocol,
        bindings: &TypestateBindingPlan,
    ) -> CompleteProtocolSummaryRepository {
        let state = self.state();
        semantic_summaries.compatible_repository(
            &state.protocol,
            self.attribution.clone(),
            protocol,
            bindings,
        )
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
        self.storage
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn lifecycle_counters(&self) -> std::sync::MutexGuard<'_, ProductionSummaryLifecycleCounters> {
        self.storage
            .counters
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
            .storage
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
            .storage
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
    projection_refusal: ProjectionRefusal,
    result: Arc<TypestateSummaryResult>,
    root_call_closure: RootCallClosure,
    exact_decision: ExactResultDecision,
    semantic_charge: crate::analyzer::semantic::SemanticBudgetReplay,
    semantic_admission: crate::analyzer::semantic::SemanticMemoAdmission,
    solver_charge: SolverWork,
    execution_charge: Option<SemanticExecutionBudgetCharge>,
}

impl CachedTypestateSummaryResult {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(
                self.exact_decision
                    .admissions
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ProtocolAdmissionDecision>()),
            )
            .saturating_add(self.result.retained_bytes())
            .saturating_add(self.semantic_admission.retained_bytes())
            .saturating_add(
                self.execution_charge
                    .as_ref()
                    .map_or(0, SemanticExecutionBudgetCharge::retained_bytes),
            )
    }
}

#[derive(Debug, Clone)]
struct RetainedTypestateSummaryResult {
    entry: Arc<ReplayingMemoEntry<CachedTypestateSummaryResult, ReadKey>>,
    published_sequence: u64,
}

impl RetainedTypestateSummaryResult {
    fn retained_bytes(&self) -> usize {
        retained_result_entry_bytes(&self.entry)
    }
}

fn read_key_heap_bytes(key: &ReadKey) -> usize {
    use crate::analyzer::store::cache_budget::{RetainedHeap, retained_read_key};
    let mut heap = RetainedHeap::default();
    retained_read_key(&mut heap, key);
    heap.total()
}

fn retained_result_entry_bytes(
    entry: &ReplayingMemoEntry<CachedTypestateSummaryResult, ReadKey>,
) -> usize {
    entry
        .retained_bytes(read_key_heap_bytes)
        .saturating_add(std::mem::size_of::<RetainedTypestateSummaryResult>())
        .saturating_add(
            std::mem::size_of::<ReplayingMemoEntry<CachedTypestateSummaryResult, ReadKey>>()
                .saturating_sub(std::mem::size_of::<CachedTypestateSummaryResult>()),
        )
        // Arc control blocks for the retained entry and its read-key slice.
        .saturating_add(4 * std::mem::size_of::<usize>())
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
    projection_refusal: ProjectionRefusal,
    result: Arc<TypestateSummaryResult>,
    root_call_closure: RootCallClosure,
    cache_status: TypestateProductionCacheStatus,
    protocol_cache_status: Option<ProtocolSummaryCacheStatus>,
    published_protocol_summaries: usize,
    rejected_protocol_reuse: bool,
    lifecycle: ProductionSummaryLifecycleCounters,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectionRefusal {
    None,
    CallControl,
}

impl ProductionTypestateSolveResult {
    pub const fn projection_refused(&self) -> bool {
        matches!(self.projection_refusal, ProjectionRefusal::CallControl)
    }

    pub fn root_call_closure(&self) -> &RootCallClosure {
        &self.root_call_closure
    }
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
    coverage_source: Option<&WorkspaceAnalyzer>,
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
    // A leader may finish without publishing, so followers retry without recursion.
    let (solver_work_before, execution_before, projection_behavior, result_key, _flight_leader) = loop {
        let solver_work_before = request.budget.used();
        let execution_before = execution_context.snapshot();
        let provider_behavior = production_icfg_behavior(provider.behavior_identity());
        let projection_behavior =
            production_summary_behavior(projection_provider.behavior_identity());
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
                    continue;
                }
            }
        } else {
            None
        };
        break (
            solver_work_before,
            execution_before,
            projection_behavior,
            result_key,
            _flight_leader,
        );
    };
    if request.cancellation.is_cancelled() {
        repository.record_miss();
        repository.record_rejection();
        lifecycle.misses = lifecycle.misses.saturating_add(1);
        lifecycle.rejections = lifecycle.rejections.saturating_add(1);
    } else if let Some(cached) = repository.result(&result_key) {
        // The binding hash distinguishes marker sets, but coverage can change
        // while the binding plan stays the same. Recheck the scoped projection
        // before replaying a result or its closure certificate. A policy
        // provider must charge this probe to an isolated execution allowance.
        let mut coverage_budget = semantic_budget.clone();
        let validation_execution = match execution_context {
            ProductionTypestateExecutionContext::Workspace => None,
            ProductionTypestateExecutionContext::Policy(budget) => Some(budget.fork().1),
        };
        let mut coverage_request = match validation_execution.as_ref() {
            Some(execution) => SemanticRequest::with_execution_budget(
                &mut coverage_budget,
                request.cancellation,
                execution,
            ),
            None => SemanticRequest::new(&mut coverage_budget, request.cancellation),
        };
        let current_projection = project_production_semantic_summaries_with_behavior(
            std::slice::from_ref(root),
            projection_provider,
            coverage_source,
            projection_behavior,
            &mut coverage_request,
        );
        let coverage_matches = current_projection.is_ok_and(|current| {
            current.root_call_closure == cached.root_call_closure
                && exact_result_decision(&current, bindings) == cached.exact_decision
                && matches!(cached.projection_refusal, ProjectionRefusal::CallControl)
                    == current.admission_refused
        });
        let mut replay_semantic_budget = semantic_budget.clone();
        let mut replay_solver_budget = request.budget.clone();
        let (replay_charge, already_held) =
            replay_semantic_budget.replay_for_holder(&cached.result, cached.semantic_charge);
        // The execution replay charges the LIVE ledger, so a hit that the
        // coverage check rejects must not reach it; otherwise the fresh solve
        // pays a second time for work it never reused.
        let admission_missed = coverage_matches
            && replay_semantic_budget
                .admit_memo_hit_with(
                    &cached.semantic_admission,
                    projection_provider.memo_dependency_reacquirer(),
                )
                .is_err();
        let replayed = coverage_matches
            && !admission_missed
            && replay_semantic_budget
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
                result: Arc::clone(&cached.result),
                projection_refusal: cached.projection_refusal,
                root_call_closure: cached.root_call_closure.clone(),
                cache_status: TypestateProductionCacheStatus::Hit,
                protocol_cache_status: None,
                published_protocol_summaries: 0,
                rejected_protocol_reuse: false,
                lifecycle,
            });
        }
        if admission_missed && repository.evict_result(&result_key) {
            lifecycle.evictions = lifecycle.evictions.saturating_add(1);
            brokk_bifrost_core::profiling::note(
                "semantic.memo_admission_eviction.typestate_result",
            );
        }
        repository.record_miss();
        repository.record_rejection();
        lifecycle.misses = lifecycle.misses.saturating_add(1);
        lifecycle.rejections = lifecycle.rejections.saturating_add(1);
    } else {
        repository.record_miss();
        lifecycle.misses = lifecycle.misses.saturating_add(1);
    }

    // A rejected cache holder has now dropped. Start the cold receipt after
    // reconciling that eviction, so it is not mistaken for a fill dependency.
    let semantic_work_before = semantic_budget.replay_snapshot();
    repository.record_recomputation();
    lifecycle.recomputations = lifecycle.recomputations.saturating_add(1);
    let mut computed = None;
    let mut cacheable = false;
    let mut cache_status = TypestateProductionCacheStatus::MissIncomplete;
    ReplayingMemo::new(()).read(&repository.attribution.capability(), |_, capture| {
        let mut entry = capture.try_build_weighted(|| {
            let value = compute_typestate_summary(
                repository,
                observer,
                root,
                entry_facts,
                provider,
                projection_provider,
                coverage_source,
                projection_behavior,
                protocol,
                bindings,
                semantic_budget,
                request,
                &mut lifecycle,
            )?;
            let mut execution_charge = None;
            let mut semantic_charge = semantic_budget.replay_since(&semantic_work_before);
            if value.result_cache_eligible {
                // The result may outlive its cache entry, even on rejection.
                semantic_charge.retained =
                    semantic_budget.bind_replay_holder(&value.result, &semantic_work_before);
                let coverage = value.result.result().coverage();
                let budget_dependent = matches!(
                    coverage.semantic_status(),
                    SemanticInputStatus::ExceededBudget { .. } | SemanticInputStatus::Cancelled
                ) || coverage
                    .boundaries()
                    .iter()
                    .any(|boundary| matches!(boundary.kind(), SummaryBoundaryKind::Limit(_)));
                if value.result.result().termination().is_fixed_point()
                    && !value.result.result().witness_retention_truncated()
                    && !budget_dependent
                {
                    if let Some(charge) = execution_context.charge_since(execution_before.as_ref())
                    {
                        execution_charge = charge;
                        cacheable = true;
                    } else {
                        repository.record_rejection();
                        lifecycle.rejections = lifecycle.rejections.saturating_add(1);
                    }
                }
            }
            let retained = CachedTypestateSummaryResult {
                projection_refusal: value.projection_refusal,
                result: Arc::clone(&value.result),
                root_call_closure: value.root_call_closure.clone(),
                exact_decision: value.exact_decision.clone(),
                semantic_charge,
                semantic_admission: semantic_budget
                    .memo_admission_since(&semantic_work_before, &value.result),
                solver_charge: request.budget.used().saturating_sub(solver_work_before),
                execution_charge,
            };
            let bytes = retained.retained_bytes();
            computed = Some(value);
            Ok::<_, ProductionTypestateSolveError>((retained, bytes))
        })?;
        if cacheable {
            let max_bytes = repository.state().max_result_bytes;
            if result_key
                .retained_bytes()
                .saturating_add(retained_result_entry_bytes(&entry))
                > max_bytes
            {
                // Keep a bounded refusal marker if the value itself still fits.
                entry.refuse_replay();
            }
        }
        let entry = Arc::new(entry);
        if cacheable {
            let (published, evictions) = repository.publish_result(result_key, Arc::clone(&entry));
            lifecycle.evictions = lifecycle.evictions.saturating_add(evictions);
            cache_status = if published {
                TypestateProductionCacheStatus::MissPublished
            } else {
                lifecycle.rejections = lifecycle.rejections.saturating_add(1);
                TypestateProductionCacheStatus::MissCapacityRejected
            };
        }
        Ok::<_, ProductionTypestateSolveError>(entry)
    })?;
    let computed = computed.expect("cold result entry was built");
    Ok(ProductionTypestateSolveResult {
        projection_refusal: computed.projection_refusal,
        result: computed.result,
        root_call_closure: computed.root_call_closure,
        cache_status,
        protocol_cache_status: computed.protocol_cache_status,
        published_protocol_summaries: computed.published_protocol_summaries,
        rejected_protocol_reuse: computed.rejected_protocol_reuse,
        lifecycle,
    })
}

struct ComputedTypestateSummaryResult {
    projection_refusal: ProjectionRefusal,
    result: Arc<TypestateSummaryResult>,
    root_call_closure: RootCallClosure,
    exact_decision: ExactResultDecision,
    protocol_cache_status: Option<ProtocolSummaryCacheStatus>,
    published_protocol_summaries: usize,
    rejected_protocol_reuse: bool,
    result_cache_eligible: bool,
}

#[allow(clippy::too_many_arguments)]
fn compute_typestate_summary<Provider, ProjectionProvider>(
    repository: &ProductionTypestateSummaryRepository,
    observer: &dyn SummaryReadObserver,
    root: &ProcedureHandle,
    entry_facts: &[TypestateFact],
    provider: &Provider,
    projection_provider: &ProjectionProvider,
    coverage_source: Option<&WorkspaceAnalyzer>,
    projection_behavior: ProductionSummaryBehavior,
    protocol: &CompiledProtocol,
    bindings: &TypestateBindingPlan,
    semantic_budget: &mut SemanticBudget,
    request: &mut DataflowRequest<'_>,
    lifecycle: &mut ProductionSummaryLifecycleCounters,
) -> Result<ComputedTypestateSummaryResult, ProductionTypestateSolveError>
where
    Provider: IcfgProvider + ?Sized,
    ProjectionProvider: IcfgProvider + ?Sized,
{
    let semantic_summaries = match project_production_semantic_summaries_with_behavior(
        std::slice::from_ref(root),
        projection_provider,
        coverage_source,
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
            let result = solve_typestate_with_summaries(
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
            })?;
            return Ok(ComputedTypestateSummaryResult {
                projection_refusal: ProjectionRefusal::CallControl,
                result: Arc::new(result),
                exact_decision: ExactResultDecision {
                    admissions: Vec::new(),
                    reusable_route: false,
                },
                root_call_closure: RootCallClosure {
                    complete: false,
                    reached: Vec::new(),
                    incomplete_reasons: vec![
                        RootCallClosureIncompleteReason::UnavailableProjection,
                    ],
                },
                protocol_cache_status: None,
                published_protocol_summaries: 0,
                rejected_protocol_reuse: false,
                result_cache_eligible: false,
            });
        }
    };

    let exact_decision = exact_result_decision(&semantic_summaries, bindings);
    if !exact_decision.reusable_route {
        repository.record_rejection();
        lifecycle.rejections = lifecycle.rejections.saturating_add(1);
        let result = solve_typestate_with_summaries(
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
        })?;
        return Ok(ComputedTypestateSummaryResult {
            projection_refusal: if semantic_summaries.admission_refused {
                ProjectionRefusal::CallControl
            } else {
                ProjectionRefusal::None
            },
            result: Arc::new(result),
            root_call_closure: semantic_summaries.root_call_closure().clone(),
            exact_decision,
            protocol_cache_status: None,
            published_protocol_summaries: 0,
            rejected_protocol_reuse: false,
            // Exact result caching retains the projection refusal. It does not
            // publish or consume a reusable semantic/protocol summary.
            result_cache_eligible: true,
        });
    }

    match repository.publish_semantic_set(&semantic_summaries) {
        Ok(_) => {}
        Err(ProductionTypestateSolveError::SemanticPublication(_)) => {
            lifecycle.rejections = lifecycle.rejections.saturating_add(1);
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
    let serving = protocol_serving_enabled();
    let rejections_before_protocol_diagnostic = lifecycle.rejections;
    if !serving
        && repository.has_compatible_protocol_rows_for_diagnostics(
            &semantic_set,
            protocol,
            bindings,
        )
    {
        // Portable protocol rows do not yet carry stable witness fragments.
        // Count their rejection without serving any rows to the solve.
        repository.record_rejection();
        lifecycle.rejections = lifecycle.rejections.saturating_add(1);
    }
    // Preserve the existing diagnostic accessor using the counter delta only.
    let rejected_protocol_reuse = lifecycle.rejections != rejections_before_protocol_diagnostic;
    let mut compatible = if serving {
        repository.compatible_protocol_repository(&semantic_set, protocol, bindings)
    } else {
        CompleteProtocolSummaryRepository::with_limits(
            repository.protocol_limits(),
            repository.attribution.clone(),
        )
    };
    if let Some(workspace) = coverage_source {
        let _suppression = crate::analyzer::ReadAttribution::for_receipt_verification().install();
        if let Some(snapshot) =
            crate::analyzer::read_verification::DefinitionInventorySnapshot::capture(
                workspace.analyzer(),
            )
        {
            compatible.bind_inventory_source(Arc::new(ProductionProtocolInventorySource {
                workspace: workspace.clone(),
                snapshot,
                cancellation: request.cancellation.clone(),
            }));
        }
    }
    if serving && let Some(workspace) = coverage_source {
        compatible.bind_receipt_verifier(Arc::new(ProductionProtocolReceiptVerifier {
            workspace: workspace.clone(),
            memo: Default::default(),
        }));
    }
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
    let published_protocol_summaries = match repository.absorb_protocol(compatible, &semantic_set) {
        Ok(published) => published,
        Err(_) => {
            repository.record_rejection();
            lifecycle.rejections = lifecycle.rejections.saturating_add(1);
            0
        }
    };
    Ok(ComputedTypestateSummaryResult {
        projection_refusal: ProjectionRefusal::None,
        result,
        root_call_closure: semantic_summaries.root_call_closure().clone(),
        exact_decision,
        protocol_cache_status: Some(protocol_cache_status),
        published_protocol_summaries,
        rejected_protocol_reuse,
        // Exact-result retention is independent of semantic row publication.
        result_cache_eligible: true,
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

/// Owned semantic identities in bottom-up publication order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionSemanticSummarySet {
    summaries: Vec<SemanticProcedureSummary>,
    components: Vec<std::ops::Range<usize>>,
    behavior: ProductionSummaryBehavior,
    procedure_semantics_precharged: bool,
    admission_refused: bool,
    protocol_admissions: Vec<ProtocolAdmissionDecision>,
    root_call_closure: RootCallClosure,
}

impl ProductionSemanticSummarySet {
    /// Test-only repository fixture. This deliberately certifies projected
    /// effects that production cannot yet certify; see #9642.
    #[cfg(any(test, feature = "test-support"))]
    pub fn synthetic_complete_for_repository_tests(mut self) -> Self {
        self.summaries = self
            .summaries
            .into_iter()
            .map(|projected| {
                SemanticProcedureSummary::try_new(
                    projected.key().clone(),
                    projected.transfers().to_vec(),
                    projected.effects().to_vec(),
                    projected.dependencies().to_vec(),
                    SummaryCompleteness::Complete,
                )
                .expect("synthetic repository summary is valid")
            })
            .collect();
        self.admission_refused = false;
        self
    }
}

/// Query-lifetime proof of the represented local call graph. A refused
/// admission or an open boundary prevents exclusion of any observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootCallClosure {
    complete: bool,
    reached: Vec<crate::analyzer::semantic::SemanticLocator>,
    incomplete_reasons: Vec<RootCallClosureIncompleteReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RootCallClosureIncompleteReason {
    BudgetStop,
    CoverageRefused,
    OpenCall,
    OpenEffect,
    ExternalCall,
    UnprovenCall,
    OutstandingObligation,
    UnavailableProjection,
}

impl RootCallClosure {
    pub fn excludes(&self, locator: &crate::analyzer::semantic::SemanticLocator) -> bool {
        self.complete && !self.reached.contains(locator)
    }

    pub const fn complete(&self) -> bool {
        self.complete
    }

    pub fn incomplete_reasons(&self) -> &[RootCallClosureIncompleteReason] {
        &self.incomplete_reasons
    }

    /// Scoped call/control coverage justifies the summary dependencies this
    /// root consumes. External boundaries alone do not invalidate that proof.
    pub fn summary_completeness_justified(&self) -> bool {
        !self
            .incomplete_reasons
            .contains(&RootCallClosureIncompleteReason::CoverageRefused)
    }
}

impl ProductionSemanticSummarySet {
    pub fn root_call_closure(&self) -> &RootCallClosure {
        &self.root_call_closure
    }
    pub fn summaries(&self) -> &[SemanticProcedureSummary] {
        &self.summaries
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

#[cfg(test)]
mod root_closure_tests {
    use super::*;
    use crate::analyzer::{
        AnalyzerConfig, Language, LookupKind, LookupQuestion, capture_query_reads,
    };
    use crate::dataflow::MemberReadReceipt;
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    fn unknown_definition_inventory_refuses_conversion() {
        // `DefinitionInventorySnapshot::capture` returns None when any analyzed
        // language lacks a listed snapshot. Standalone analyzers now certify
        // their enumeration (#11076), so pass the unknown inventory directly.
        let member = MemberReadReceipt {
            keys: [ReadKey::index(
                crate::analyzer::IndexFamily::DefinitionExact,
                "calls.helper",
            )]
            .into_iter()
            .collect(),
            channels: Default::default(),
        };
        assert!(super::super::summary::ProtocolMemberReceipt::from_member(&member, None).is_err());
    }

    #[test]
    fn definition_inventory_receipts_verify_edits_and_conversion_is_suppressed() {
        use super::super::summary::ProtocolMemberReceipt;
        use crate::analyzer::IndexFamily;
        use crate::analyzer::read_verification::DefinitionInventorySnapshot;
        let project = InlineTestProject::with_language(Language::Go)
            .file("helper.go", "package calls\nfunc helper() {}\n")
            .file("other.go", "package calls\nfunc other() {}\n")
            .build();
        let build_workspace = || {
            WorkspaceAnalyzer::build_ephemeral_footgun(
                Arc::new(crate::analyzer::FilesystemProject::new(project.root()).unwrap()),
                AnalyzerConfig::default(),
            )
            .unwrap()
        };
        let base = build_workspace();
        let snapshot = DefinitionInventorySnapshot::capture(base.analyzer()).unwrap_or_else(|| {
            panic!(
                "languages={:?} indexes={:?}",
                base.analyzer().languages(),
                base.analyzer()
                    .workspace_fact_indexes()
                    .iter()
                    .map(|index| (
                        index.fact_index_language(),
                        index.definition_inventory_snapshots()
                    ))
                    .collect::<Vec<_>>()
            )
        });
        let source = ProductionProtocolInventorySource {
            workspace: base.clone(),
            snapshot,
            cancellation: Default::default(),
        };
        let missing_member = MemberReadReceipt {
            keys: [ReadKey::index(IndexFamily::DefinitionExact, "calls.future")]
                .into_iter()
                .collect(),
            channels: Default::default(),
        };
        let missing = ProtocolMemberReceipt::from_member(&missing_member, Some(&source)).unwrap();
        let families = [
            IndexFamily::DefinitionExact,
            IndexFamily::DefinitionNormalizedTail,
            IndexFamily::DefinitionIdentifier,
        ];
        let receipts = families.map(|family| {
            let name = if family == IndexFamily::DefinitionIdentifier {
                "helper"
            } else {
                "calls.helper"
            };
            let member = MemberReadReceipt {
                keys: [ReadKey::index(family, name)].into_iter().collect(),
                channels: Default::default(),
            };
            let (receipt, reads) = capture_query_reads(base.analyzer(), || {
                ProtocolMemberReceipt::from_member(&member, Some(&source))
            });
            assert!(reads.keys().is_empty(), "{reads:?}");
            assert_eq!(reads.unattributed_reads(), 0, "{reads:?}");
            receipt.unwrap()
        });
        let verify = |workspace: &WorkspaceAnalyzer, expected| {
            let verifier = ProductionProtocolReceiptVerifier {
                workspace: workspace.clone(),
                memo: Default::default(),
            };
            for receipt in &receipts {
                assert_eq!(verifier.verify(receipt), expected, "{receipt:?}");
            }
        };
        verify(&base, ProtocolReceiptVerdict::Current);
        std::fs::write(
            project.root().join("other.go"),
            "package calls\nfunc other() { var x = 1; _ = x }\n",
        )
        .unwrap();
        let unrelated = build_workspace();
        verify(&unrelated, ProtocolReceiptVerdict::Current);
        std::fs::write(
            project.root().join("helper.go"),
            "package calls\n// shifted\nfunc helper() {}\n",
        )
        .unwrap();
        let shifted = build_workspace();
        verify(&shifted, ProtocolReceiptVerdict::Current);
        std::fs::write(
            project.root().join("other.go"),
            "package calls\nfunc other() {}\nfunc helper() {}\n",
        )
        .unwrap();
        let added = build_workspace();
        verify(&added, ProtocolReceiptVerdict::Stale);
        let raced = ProductionProtocolInventorySource {
            workspace: added.clone(),
            snapshot: source.snapshot.clone(),
            cancellation: Default::default(),
        };
        let member = MemberReadReceipt {
            keys: [ReadKey::index(IndexFamily::DefinitionIdentifier, "helper")]
                .into_iter()
                .collect(),
            channels: Default::default(),
        };
        assert!(ProtocolMemberReceipt::from_member(&member, Some(&raced)).is_err());
        let updated = base.update(&std::collections::BTreeSet::from(
            [project.file("other.go")],
        ));
        let raced_revision = ProductionProtocolInventorySource {
            workspace: updated,
            snapshot: source.snapshot.clone(),
            cancellation: Default::default(),
        };
        assert!(ProtocolMemberReceipt::from_member(&member, Some(&raced_revision)).is_err());
        let cancelled = crate::cancellation::CancellationToken::default();
        cancelled.cancel();
        let cancelled_source = ProductionProtocolInventorySource {
            workspace: base.clone(),
            snapshot: source.snapshot.clone(),
            cancellation: cancelled,
        };
        assert!(ProtocolMemberReceipt::from_member(&member, Some(&cancelled_source)).is_err());
        std::fs::write(
            project.root().join("other.go"),
            "package calls\nfunc other() {}\n",
        )
        .unwrap();
        std::fs::write(
            project.root().join("helper.go"),
            "package calls\nfunc helper(value int) { _ = value }\n",
        )
        .unwrap();
        let changed = build_workspace();
        verify(&changed, ProtocolReceiptVerdict::Stale);
        let verifier = ProductionProtocolReceiptVerifier {
            workspace: changed.clone(),
            memo: Default::default(),
        };
        assert_eq!(verifier.verify(&missing), ProtocolReceiptVerdict::Current);
        std::fs::write(
            project.root().join("other.go"),
            "package calls\nfunc future() {}\n",
        )
        .unwrap();
        let future = build_workspace();
        let verifier = ProductionProtocolReceiptVerifier {
            workspace: future,
            memo: Default::default(),
        };
        assert_eq!(verifier.verify(&missing), ProtocolReceiptVerdict::Stale);
    }

    #[test]
    #[hardwon(
        "#9642: the production receipt verifier recorded its own reads into the serving request's ledger"
    )]
    fn production_receipt_verification_does_not_pollute_serving_read_ledger() {
        use crate::analyzer::semantic::StableDigest;

        let project = InlineTestProject::with_language(Language::Go)
            .file("helper.go", "package calls\nfunc helper() {}\n")
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let member = MemberReadReceipt {
            keys: [ReadKey::Lookup {
                kind: LookupKind::Definitions,
                question: LookupQuestion::Name {
                    language: Some(Language::Go),
                    name: "calls.helper".into(),
                },
                digest: StableDigest::sha256(b"any"),
            }]
            .into_iter()
            .collect(),
            channels: Default::default(),
        };
        let receipt = super::super::summary::ProtocolMemberReceipt::from_member(&member, None)
            .expect("a receipt without Index keys converts");
        let verifier = ProductionProtocolReceiptVerifier {
            workspace: workspace.clone(),
            memo: Default::default(),
        };
        let (_verdict, reads) =
            capture_query_reads(workspace.analyzer(), || verifier.verify(&receipt));
        assert!(reads.keys().is_empty(), "verifier reads leaked: {reads:?}");
        assert_eq!(
            reads.unattributed_reads(),
            0,
            "verification recorded an unattributed read: {reads:?}"
        );
        assert!(reads.is_bounded(), "verification refused reuse: {reads:?}");
    }

    #[test]
    #[hardwon(
        "#10686: #9755's absence read made the production receipt verifier refuse every no-model protocol receipt"
    )]
    fn production_receipt_verification_verifies_the_recorded_model_absence() {
        use crate::analyzer::i_analyzer::current_model_set_digest;
        use crate::analyzer::semantic::ids::StableDigest;

        let project = InlineTestProject::with_language(Language::Go)
            .file("helper.go", "package calls\nfunc helper() {}\n")
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let receipt = |models| {
            let member = MemberReadReceipt {
                keys: [ReadKey::Models(models)].into_iter().collect(),
                channels: Default::default(),
            };
            super::super::summary::ProtocolMemberReceipt::from_member(&member, None)
                .expect("a model read is a protocol receipt key")
        };
        let verifier = ProductionProtocolReceiptVerifier {
            workspace: workspace.clone(),
            memo: Default::default(),
        };
        let (verdict, reads) = capture_query_reads(workspace.analyzer(), || {
            verifier.verify(&receipt(current_model_set_digest(None)))
        });
        assert_eq!(verdict, ProtocolReceiptVerdict::Current);
        assert!(reads.keys().is_empty(), "verifier reads leaked: {reads:?}");
        assert_eq!(
            reads.unattributed_reads(),
            0,
            "verification recorded an unattributed read: {reads:?}"
        );
        assert!(reads.is_bounded(), "verification refused reuse: {reads:?}");
        assert_eq!(
            verifier.verify(&receipt(StableDigest::sha256(b"another model set"))),
            ProtocolReceiptVerdict::Stale
        );
    }

    #[test]
    #[hardwon("#9550: a proven call into another local file was classified as an external call")]
    fn cross_file_local_call_and_unmaterialized_external_call() {
        for (caller, external) in [
            ("package calls\nfunc root() { helper() }\n", false),
            (
                "package calls\nimport \"fmt\"\nfunc root() { helper(); fmt.Println(1) }\n",
                true,
            ),
        ] {
            let project = InlineTestProject::with_language(Language::Go)
                .file("app.go", caller)
                .file("res.go", "package calls\nfunc helper() {}\n")
                .build();
            let workspace = project.workspace_analyzer(AnalyzerConfig::default());
            let file = project.file("app.go");
            let cancellation = crate::analyzer::semantic::CancellationToken::default();
            let mut budget = SemanticBudget::default();
            let outcome = workspace
                .materialize_program_semantics(
                    &file,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("app semantics");
            let artifact = outcome.available_value().expect("app artifact");
            let procedure = artifact
                .procedures()
                .iter()
                .find(|procedure| {
                    procedure
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some("root")
                })
                .expect("root procedure");
            let root = artifact
                .procedure_handle(procedure.id())
                .expect("root handle");
            let closure = project_workspace_root_call_closure(
                &root,
                &workspace.icfg_provider(),
                &workspace,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("root closure");
            assert_eq!(
                closure
                    .incomplete_reasons()
                    .contains(&RootCallClosureIncompleteReason::ExternalCall),
                external,
                "{closure:?}"
            );
            if external {
                assert!(!closure.complete(), "{closure:?}");
            }
        }

        // External-only incompleteness does not imply a refused summary.
        let external_only = RootCallClosure {
            complete: false,
            reached: Vec::new(),
            incomplete_reasons: vec![RootCallClosureIncompleteReason::ExternalCall],
        };
        assert!(external_only.summary_completeness_justified());
    }
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
    project_production_semantic_summaries_with_behavior(roots, provider, None, behavior, request)
}

/// Projects one root with the current workspace's scoped call/control proof.
/// The returned closure is valid only for this query and these artifacts.
pub fn project_workspace_root_call_closure<Provider>(
    root: &ProcedureHandle,
    provider: &Provider,
    workspace: &WorkspaceAnalyzer,
    request: &mut SemanticRequest<'_>,
) -> Result<RootCallClosure, ProductionSummaryProjectionError>
where
    Provider: IcfgProvider,
{
    let behavior = production_summary_behavior(provider.behavior_identity());
    project_production_semantic_summaries_with_behavior(
        std::slice::from_ref(root),
        provider,
        Some(workspace),
        behavior,
        request,
    )
    .map(|summaries| summaries.root_call_closure)
    .or_else(|error| match error {
        ProductionSummaryProjectionError::CallTransferBudgetExceeded { .. }
        | ProductionSummaryProjectionError::RetainedClosureBudgetExceeded(_)
        | ProductionSummaryProjectionError::GraphBudgetExceeded => Ok(RootCallClosure {
            complete: false,
            reached: Vec::new(),
            incomplete_reasons: vec![RootCallClosureIncompleteReason::BudgetStop],
        }),
        error => Err(error),
    })
}

fn project_production_semantic_summaries_with_behavior<Provider>(
    roots: &[ProcedureHandle],
    provider: &Provider,
    coverage_source: Option<&WorkspaceAnalyzer>,
    behavior: ProductionSummaryBehavior,
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
    let mut direct_call_effects = vec![Vec::<DirectCallEffect>::new(); procedures.len()];
    let mut direct_effects = vec![Vec::<SummaryEffect>::new(); procedures.len()];
    let mut closure_complete = coverage_source.is_some();
    let mut closure_reasons = Vec::new();
    if coverage_source.is_none() {
        closure_reasons.push(RootCallClosureIncompleteReason::UnavailableProjection);
    }
    let mut cursor = 0usize;
    let mut coverage = Vec::new();
    let mut admission_refused = false;
    let mut protocol_admissions = Vec::new();

    while cursor < procedures.len() {
        let procedure = procedures[cursor].clone();
        let mut outstanding_obligations = HashSet::default();
        let decision = if let Some(workspace) = coverage_source {
            // Both admissions must describe the exact artifact being projected.
            // Keep their decision in one place while the non-call rule is settled.
            workspace
                .analyzer()
                .record_read(ReadKey::semantic_artifact(procedure.artifact().key()));
            let call_control = workspace.stored_call_control_coverage(&procedure, request)?;
            match &call_control {
                FootprintAdmission::Admitted {
                    call_target_obligations,
                } => {
                    outstanding_obligations.extend(
                        call_target_obligations
                            .iter()
                            .map(|obligation| obligation.call),
                    );
                }
                _ => {
                    closure_complete = false;
                    closure_reasons.push(RootCallClosureIncompleteReason::CoverageRefused);
                }
            }
            let footprint = workspace.stored_footprint_coverage(&procedure, request)?;
            // The direct solver evaluates value and exit effects itself. Only
            // an unproved call closure can hide a callee from that solve.
            admission_refused |= !matches!(call_control, FootprintAdmission::Admitted { .. });
            protocol_admissions.push(ProtocolAdmissionDecision::from_coverage(
                Some(&call_control),
                Some(&footprint),
            ));
            summary_coverage_decision(Some(&call_control), Some(&footprint))
        } else {
            admission_refused = true;
            protocol_admissions.push(ProtocolAdmissionDecision::from_coverage(None, None));
            summary_coverage_decision(None, None)
        };
        coverage.push(decision);
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
                    dependencies.push(target);
                    outstanding_obligations.remove(&call.id);
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
                    closure_complete = false;
                    closure_reasons.push(RootCallClosureIncompleteReason::OpenCall);
                    direct_effects[cursor].push(project_open_call_effect(
                        &procedure,
                        call,
                        "detached call dispatch was not complete",
                    )?);
                }
                let local_dispatch = dispatch_complete
                    && dispatch.as_ref().is_some_and(|dispatch| {
                        dispatch.candidates().iter().all(|candidate| {
                            candidate.target().artifact().key() == procedure.artifact().key()
                        })
                    });
                if local_dispatch {
                    outstanding_obligations.remove(&call.id);
                } else {
                    closure_complete = false;
                    closure_reasons.push(RootCallClosureIncompleteReason::ExternalCall);
                }
                if let Some(dispatch) = dispatch {
                    // Exact candidates are stable may-dependencies.
                    for candidate in dispatch.candidates().iter() {
                        let target = candidate.target().clone();
                        dependencies.push(target.clone());
                        if !matches!(candidate.proof(), ProofStatus::Proven)
                            || !matches!(candidate.completeness(), EvidenceCompleteness::Complete)
                        {
                            continue;
                        }
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
                    }
                }
                continue;
            }
            let outcome = provider.call_transfers(&procedure, call.id, request)?;
            let (value, outcome_evidence) = match outcome {
                SemanticOutcome::Complete { value, .. } => {
                    (value, SummaryEvidence::proven_complete())
                }
                SemanticOutcome::Ambiguous { candidates, .. } => {
                    closure_complete = false;
                    closure_reasons.push(RootCallClosureIncompleteReason::OpenCall);
                    direct_effects[cursor].push(project_open_call_effect(
                        &procedure,
                        call,
                        "call dispatch was ambiguous",
                    )?);
                    (candidates, SummaryEvidence::proven_complete())
                }
                SemanticOutcome::Unproven { partial, .. } => {
                    closure_complete = false;
                    closure_reasons.push(RootCallClosureIncompleteReason::UnprovenCall);
                    direct_effects[cursor].push(project_open_call_effect(
                        &procedure,
                        call,
                        "call dispatch was not proven",
                    )?);
                    // The explicit open boundary accounts for targets omitted
                    // from the partial answer. Each retained transfer is still
                    // a real may-call dependency and must not inherit the
                    // aggregate dispatch incompleteness a second time.
                    (partial, SummaryEvidence::proven_complete())
                }
                SemanticOutcome::Unknown { partial, .. }
                | SemanticOutcome::Unsupported { partial, .. } => {
                    closure_complete = false;
                    closure_reasons.push(RootCallClosureIncompleteReason::OpenCall);
                    direct_effects[cursor].push(project_open_call_effect(
                        &procedure,
                        call,
                        "call transfer was unavailable",
                    )?);
                    let Some(partial) = partial else {
                        continue;
                    };
                    (partial, SummaryEvidence::proven_complete())
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
            let local_transfer = value.boundaries.is_empty()
                && !value.transfers.is_empty()
                && value.transfers.iter().all(|transfer| {
                    matches!(transfer.proof, ProofStatus::Proven)
                        && matches!(transfer.completeness, EvidenceCompleteness::Complete)
                });
            if local_transfer {
                outstanding_obligations.remove(&call.id);
            } else {
                closure_complete = false;
                closure_reasons.push(if value.transfers.is_empty() {
                    RootCallClosureIncompleteReason::ExternalCall
                } else {
                    RootCallClosureIncompleteReason::OpenCall
                });
            }
            for (boundary_index, boundary) in value.boundaries.iter().enumerate() {
                closure_complete = false;
                closure_reasons.push(RootCallClosureIncompleteReason::OpenCall);
                direct_effects[cursor].push(project_boundary_effect(
                    &procedure,
                    call,
                    boundary,
                    boundary_index,
                    call_ordinal,
                )?);
            }
            for transfer in value.transfers {
                if !matches!(transfer.proof, ProofStatus::Proven)
                    || !matches!(transfer.completeness, EvidenceCompleteness::Complete)
                {
                    closure_complete = false;
                    closure_reasons.push(RootCallClosureIncompleteReason::UnprovenCall);
                }
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
        if !outstanding_obligations.is_empty() {
            closure_complete = false;
            closure_reasons.push(RootCallClosureIncompleteReason::OutstandingObligation);
        }
        canonicalize_procedures(&mut dependencies, behavior);
        if !direct_effects[cursor].is_empty() {
            closure_complete = false;
            closure_reasons.push(RootCallClosureIncompleteReason::OpenEffect);
        }
        for dependency in &dependencies {
            if !index_by_handle.contains_key(dependency) {
                let index = procedures.len();
                procedures.push(dependency.clone());
                direct_dependencies.push(Vec::new());
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
    let canonical_coverage = canonical_order
        .iter()
        .map(|&old| coverage[old].clone())
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

    let mut set = build_summary_set(
        &canonical_procedures,
        DirectSummaryProjection {
            calls: &canonical_call_effects,
            effects: &canonical_effects,
        },
        &graph,
        &sccs.components,
        &canonical_coverage,
        admission_refused,
        behavior,
        request.cancellation,
    )?;
    closure_reasons.sort_unstable();
    closure_reasons.dedup();
    set.protocol_admissions = protocol_admissions;
    set.root_call_closure = RootCallClosure {
        complete: closure_complete,
        reached: canonical_procedures
            .iter()
            .map(|procedure| procedure.semantics().locator().clone())
            .collect(),
        incomplete_reasons: closure_reasons,
    };
    Ok(set)
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
        crate::analyzer::semantic::DispatchBoundaryKind::HierarchyUnenumerated => {
            b"hierarchy_unenumerated"
        }
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
}

#[allow(clippy::too_many_arguments)]
fn build_summary_set(
    procedures: &[ProcedureHandle],
    direct: DirectSummaryProjection<'_>,
    graph: &ProcedureDependencyGraph,
    components: &[Box<[usize]>],
    coverage: &[SummaryCompleteness],
    admission_refused: bool,
    behavior: ProductionSummaryBehavior,
    cancellation: &crate::cancellation::CancellationToken,
) -> Result<ProductionSemanticSummarySet, ProductionSummaryProjectionError> {
    let DirectSummaryProjection {
        calls: direct_calls,
        effects: direct_effects,
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
            let protocol_status = match &coverage[member] {
                SummaryCompleteness::Complete => SummaryDimensionStatus::Complete,
                SummaryCompleteness::Partial(reasons) => {
                    SummaryDimensionStatus::Incomplete(reasons.clone())
                }
            };
            let value_transfer_reasons = vec![SummaryIncompleteReason::SemanticGap(
                "value transfers are not projected".into(),
            )];
            let value_transfer = SummaryCompleteness::partial(value_transfer_reasons.clone())?;
            let summary = SemanticProcedureSummary::try_new_with_coverage(
                key.clone(),
                Vec::new(),
                effects,
                dependencies,
                value_transfer,
                vec![
                    SummaryDimensionClaim::new(SummaryDimension::Protocol, protocol_status)?,
                    SummaryDimensionClaim::new(
                        SummaryDimension::ValueTransfer,
                        SummaryDimensionStatus::Incomplete(
                            value_transfer_reasons.into_boxed_slice(),
                        ),
                    )?,
                ],
            )?;
            key_by_node[member] = Some(key);
            summaries.push(summary);
        }
        summary_components.push(started..summaries.len());
    }

    if summary_components.len() != components.len() {
        return Err(ProductionSummaryProjectionError::InvalidDependencyGraph);
    }

    Ok(ProductionSemanticSummarySet {
        summaries,
        components: summary_components,
        behavior,
        procedure_semantics_precharged: true,
        admission_refused,
        protocol_admissions: Vec::new(),
        root_call_closure: RootCallClosure {
            complete: false,
            reached: Vec::new(),
            incomplete_reasons: vec![RootCallClosureIncompleteReason::UnavailableProjection],
        },
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

/// The two behaviors a production summary can be keyed by.
///
/// A procedure with call sites depends on everything the provider dispatches
/// through, so it is keyed by the full workspace provider behavior, which
/// rotates on every analyzed edit. A call-free procedure never asks the
/// provider anything, so its summary is keyed by the active model set alone.
/// That digest is known before the summary is computed and carries the
/// close-match approximation claim, so a leaf that read an approximate model
/// cannot be reused under an exact model set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProductionSummaryBehavior {
    workspace: SummaryBehaviorKey,
    call_free: SummaryBehaviorKey,
}

fn production_summary_behavior(
    provider: IcfgProviderBehaviorIdentity,
) -> ProductionSummaryBehavior {
    let behavior = production_icfg_behavior(provider);
    let derive = |identity: &[u8; 32]| {
        let mut digest = LengthDelimitedDigest::new(PRODUCTION_SUMMARY_BEHAVIOR_DOMAIN);
        digest.push(identity);
        digest.finish()
    };
    let mut call_free = LengthDelimitedDigest::new(PROVIDER_INDEPENDENT_LEAF_BEHAVIOR);
    call_free.push(provider.models_digest().as_bytes());
    ProductionSummaryBehavior {
        workspace: SummaryBehaviorKey::from_parts(
            derive(behavior.as_bytes()),
            derive(behavior.read_bytes()),
        ),
        call_free: SummaryBehaviorKey::from_digest(call_free.finish()),
    }
}

fn summary_identity(
    procedure: &ProcedureHandle,
    behavior: ProductionSummaryBehavior,
) -> ProcedureSummaryIdentity {
    let provider_behavior = if procedure.semantics().call_sites().is_empty() {
        behavior.call_free
    } else {
        behavior.workspace
    };
    ProcedureSummaryIdentity::new(
        procedure.artifact().key().clone(),
        procedure.semantics().locator().declaration().clone(),
        SummarySchemaVersion::CURRENT,
        SummarySemanticsVersion::hash_bytes(PRODUCTION_SUMMARY_SEMANTICS),
        SummaryContextKey::hash_bytes(EMPTY_CALL_CONTEXT),
        provider_behavior,
        SummaryOrigin::Inferred,
    )
}

fn canonicalize_procedures(
    procedures: &mut Vec<ProcedureHandle>,
    behavior: ProductionSummaryBehavior,
) {
    procedures.sort_unstable_by_key(|procedure| summary_identity(procedure, behavior));
    procedures.dedup_by(|left, right| {
        summary_identity(left, behavior) == summary_identity(right, behavior)
    });
}
