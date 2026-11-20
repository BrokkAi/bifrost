//! The execution adapter between the query engine and the flow-sensitive
//! state derivation layer (#1480, Milestone 3).
//!
//! Rows follow the reference-edge precedent ([`super::edges`]): plain pipeline
//! values derived on demand and memoised per request, never carried in the
//! semantic artifact. One requested file or procedure scope is derived once
//! per query, and its per-axis completeness becomes typed diagnostics before
//! any filter runs -- so a `:class read` filter that drops every row still
//! leaves the reason the row set is partial on the response.
//!
//! There is no capability table here on purpose: a static gate cannot describe
//! per-procedure lowering completeness. The per-procedure lowering result is
//! the honest source, and it is what [`FlowStateCompleteness`] reports (#1480).

#[cfg(test)]
use super::super::flow_state::flow_state_for_file_with_snapshot;
use super::super::flow_state::{
    FLOW_STATE_AXES, FileFlowState, FlowRelationRow, FlowStateAxis, FlowStateCompleteness,
    FlowStateDerivation, FlowStateIncompleteReason, FlowStateRequest, NonreturnDiscoveryCache,
    StateEventRow, flow_state_for_materialized_artifact_with_provider,
    flow_state_for_materialized_procedure_with_provider, flow_state_for_selected_property,
};
use super::EXECUTION_DEPENDENT;
use super::Incompleteness;
use super::results::{
    CodeQueryBindingInitializerCall, CodeQueryDiagnostic, CodeQueryDiagnosticCode,
    CodeQueryDiagnosticImpact, CodeQueryFlowRelation, CodeQueryRange, CodeQueryStateEvent,
    CodeQueryStateEventRef,
};
use super::{CarriesReuseVerdict, DerivationExecutionCause, rel_path_string};
#[cfg(test)]
use crate::analyzer::semantic::SemanticGapKind;
use crate::analyzer::semantic::{
    LengthDelimitedDigest, ProcedureHandle, ProcedureId, ProgramPointId, SemanticArtifact,
    SemanticBudget, SemanticBudgetExceeded, SemanticCapability, SemanticOutcome,
    WorkspaceIcfgProvider,
};
use crate::analyzer::semantic_model::ActiveSemanticModelSnapshot;
use crate::analyzer::{IAnalyzer, Language, ProjectFile, WorkspaceAnalyzer};
use crate::cancellation::CancellationToken;
use crate::hash::HashMap;
use brokk_bifrost_analysis::analyzer::workspace_authority::{CaptureScopedMemo, memo_attribution};
use brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict;
use brokk_bifrost_flow::flow_state::{FlowStateOperation, FlowStateRequestMemos};
use brokk_bifrost_rql::{FlowRelationFilter, StateEventFilter};
use std::sync::Arc;

/// Domain separators for the two row families' stable ids.
const STATE_EVENT_ID_DOMAIN: &[u8] = b"bifrost.code_query.state_event.v1";
const FLOW_RELATION_ID_DOMAIN: &[u8] = b"bifrost.code_query.flow_relation.v1";

/// Per-request value memo of derived flow state. Every invocation reports its
/// own completeness evidence; policy normalization deduplicates diagnostics.
pub(super) struct FlowStateTraversalCache<'a> {
    /// One immutable activation snapshot for every file this request derives.
    active_semantic_model_snapshot: CaptureScopedMemo<Option<Arc<ActiveSemanticModelSnapshot>>>,
    /// The same snapshot identity carried into every memo key. `None` remains
    /// distinct from the hash of an activated but empty model set.
    active_model_set_hash: CaptureScopedMemo<Option<Arc<str>>>,
    files: CaptureScopedMemo<FlowStateFiles>,
    nonreturn_provider: Option<WorkspaceIcfgProvider<'a>>,
    nonreturn_discovery_cache: NonreturnDiscoveryCache,
    /// The execution dependences marked while deriving flow state; the query
    /// joins it into its reuse verdict.
    pub(super) reuse: ReuseVerdict,
}

type FlowStateFiles = HashMap<FlowStateFileKey, FlowStateFileEntry>;

/// One file under one model snapshot and one outcome quality. The scope that
/// used to be part of the key now lives in the entry, so one entry can carry
/// the per-file seed operation next to every scope's states.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FlowStateFileKey {
    file: ProjectFile,
    active_model_set_hash: Option<Arc<str>>,
    outcome: FlowStateOutcomeIdentity,
}

#[derive(Default)]
struct FlowStateFileEntry {
    /// The exact native file artifact the seed operation is anchored to. Only
    /// the seed adapter sets it. A different selected view never changes it;
    /// a different native allocation replaces the whole entry.
    native: Option<Arc<SemanticArtifact>>,
    scopes: HashMap<FlowStateCacheScope, ScopeStates>,
    /// The retained per-file grant of the formerly whole-file seeds. `None` for
    /// a query whose consumers all take per-miss grants.
    seed: Option<SeedOperation>,
}

/// The owner KIND of a derivation's resource grant. It is independent of the
/// File/Procedure scope key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlowStateOwner {
    /// The retained per-file seed operation.
    SeedOperation,
    /// A fresh grant per cache miss (every other consumer).
    PerMiss,
}

/// Everything derived for one scope under one exact allocation.
#[derive(Default)]
struct ScopeStates {
    /// The exact allocation these states were derived from (the selected Arc
    /// for a procedure scope), held strongly so address-keyed memos stay valid.
    /// `None` marks the standalone acquisition path, which cannot prove
    /// identity with a separately materialized query artifact.
    artifact: Option<Arc<SemanticArtifact>>,
    /// Shared content: a state with a Content verdict and no operational cause
    /// anywhere in its completeness. Either owner kind may serve it.
    content: Option<Arc<FileFlowState>>,
    /// The paid outcome of the seed owner, served before shared content.
    seed_slot: Option<SeedSlot>,
    /// The paid stopped state of the per-miss owner, served before content.
    per_miss_stop: Option<Arc<FileFlowState>>,
}

#[derive(Clone)]
enum SeedSlot {
    Stopped(Arc<FileFlowState>),
    /// Admitting this scope's distinct selected allocation was refused.
    Refused(SemanticBudgetExceeded),
}

/// The file operation and what its single initial admission decided.
struct SeedOperation {
    /// `None` only while a derivation leases it.
    operation: Option<FlowStateOperation>,
    admission: SeedAdmission,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SeedAdmission {
    /// Not yet decided: decided inside the first lend of the operation.
    Pending,
    /// The native Complete artifact was admitted once.
    Admitted,
    /// A partial native artifact is not prepaid; legacy left resident
    /// admission to the first actual provider access.
    NotApplicable,
    /// The native census was refused; every seed of the file stops with this.
    Refused(SemanticBudgetExceeded),
}

impl ScopeStates {
    fn matches(&self, wanted: &Arc<SemanticArtifact>) -> bool {
        self.artifact
            .as_ref()
            .is_some_and(|retained| Arc::ptr_eq(retained, wanted))
    }

    /// The paid result this owner kind may be served: its own stopped slot
    /// first, then shared content. Another owner's stop is never served.
    fn lookup(&self, owner: FlowStateOwner) -> Option<Arc<FileFlowState>> {
        match owner {
            FlowStateOwner::PerMiss => self.per_miss_stop.clone().or_else(|| self.content.clone()),
            FlowStateOwner::SeedOperation => match &self.seed_slot {
                Some(SeedSlot::Stopped(state)) => Some(Arc::clone(state)),
                _ => self.content.clone(),
            },
        }
    }

    /// File a derived state: admissible content is shared, anything else only
    /// fills its owner's slot, leaving the other owner's paid results intact.
    fn store(&mut self, owner: FlowStateOwner, state: &Arc<FileFlowState>) {
        if state_is_cross_owner_content(state) {
            self.content = Some(Arc::clone(state));
            return;
        }
        match owner {
            FlowStateOwner::PerMiss => self.per_miss_stop = Some(Arc::clone(state)),
            FlowStateOwner::SeedOperation => {
                self.seed_slot = Some(SeedSlot::Stopped(Arc::clone(state)));
            }
        }
    }
}

impl FlowStateFileEntry {
    /// The scope's states for exactly `artifact`; a different allocation (or
    /// the standalone `None`) replaces that scope only, never the operation.
    fn scope_for(
        &mut self,
        scope: FlowStateCacheScope,
        artifact: Option<Arc<SemanticArtifact>>,
    ) -> &mut ScopeStates {
        let states = self.scopes.entry(scope).or_default();
        let same = match (&states.artifact, &artifact) {
            (Some(retained), Some(wanted)) => Arc::ptr_eq(retained, wanted),
            _ => false,
        };
        if !same {
            *states = ScopeStates {
                artifact,
                ..ScopeStates::default()
            };
        }
        states
    }
}

/// A state may cross owners only if it is a function of the inputs it read
/// (Content verdict) and carries no typed operational cause in its global or
/// ANY procedure's completeness, whatever axes the consumer publishes.
fn state_is_cross_owner_content(state: &FileFlowState) -> bool {
    let operational = |completeness: &FlowStateCompleteness| {
        completeness
            .reasons()
            .iter()
            .any(|reason| classify_reason(reason).2.is_some())
    };
    state.reuse_verdict().is_content()
        && !operational(&state.completeness)
        && state
            .procedures
            .iter()
            .all(|derivation| !operational(&derivation.completeness))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum FlowStateCacheScope {
    File,
    Procedure(
        ProcedureId,
        crate::analyzer::semantic::ProcedureInterpretation,
    ),
}

/// The parts of a semantic outcome that shape flow-state completeness.
///
/// Work counters do not change derived rows. Unsupported capability does
/// appear in the typed reason, so it remains part of the identity alongside
/// the outcome discriminant and exact artifact allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum FlowStateOutcomeIdentity {
    #[cfg(test)]
    Standalone,
    Complete,
    Ambiguous,
    Unknown,
    Unsupported(SemanticCapability),
    Unproven,
    ExceededBudget,
    Cancelled,
}

impl FlowStateOutcomeIdentity {
    fn for_outcome<T>(outcome: &SemanticOutcome<T>) -> Self {
        match outcome {
            SemanticOutcome::Complete { .. } => Self::Complete,
            SemanticOutcome::Ambiguous { .. } => Self::Ambiguous,
            SemanticOutcome::Unknown { .. } => Self::Unknown,
            SemanticOutcome::Unsupported { capability, .. } => Self::Unsupported(*capability),
            SemanticOutcome::Unproven { .. } => Self::Unproven,
            SemanticOutcome::ExceededBudget { .. } => Self::ExceededBudget,
            SemanticOutcome::Cancelled { .. } => Self::Cancelled,
        }
    }
}

/// What the scope lookup of a seed derivation found.
enum SeedLookup {
    Hit(Arc<FileFlowState>),
    Refused(SemanticBudgetExceeded),
    Miss,
}

/// What one lend of the seed operation produced.
enum SeedAttempt {
    NativeRefused(SemanticBudgetExceeded),
    ScopeRefused(SemanticBudgetExceeded),
    /// The derived state and whether the ordinary CFG ledger refused.
    Derived(FileFlowState, bool),
}

enum SeedCommit {
    Nothing,
    ScopeRefused(SemanticBudgetExceeded),
    Derived(Arc<FileFlowState>),
}

/// Holds the checked-out seed operation during one derivation and returns the
/// SAME spent operation to its entry on every exit, including unwind. No map
/// access is held while it derives.
struct SeedOperationLease<'g> {
    files: &'g mut CaptureScopedMemo<FlowStateFiles>,
    analyzer: &'g dyn IAnalyzer,
    key: FlowStateFileKey,
    operation: Option<FlowStateOperation>,
    admission: SeedAdmission,
}

impl SeedOperationLease<'_> {
    /// Return the operation and file the scope's paid outcome in one access.
    fn commit(
        mut self,
        scope: FlowStateCacheScope,
        selected: &Arc<SemanticArtifact>,
        commit: SeedCommit,
    ) {
        let operation = self.operation.take();
        let admission = self.admission;
        let key = self.key.clone();
        self.files
            .read_mut(&memo_attribution(self.analyzer), |files| {
                let entry = files.entry(key).or_default();
                entry.seed = Some(SeedOperation {
                    operation,
                    admission,
                });
                match commit {
                    SeedCommit::Nothing => {}
                    SeedCommit::ScopeRefused(exceeded) => {
                        entry.scope_for(scope, Some(Arc::clone(selected))).seed_slot =
                            Some(SeedSlot::Refused(exceeded));
                    }
                    SeedCommit::Derived(state) => entry
                        .scope_for(scope, Some(Arc::clone(selected)))
                        .store(FlowStateOwner::SeedOperation, &state),
                }
            });
    }
}

impl Drop for SeedOperationLease<'_> {
    fn drop(&mut self) {
        // Only reached with the operation still checked out: an unwind. Put
        // back the same spent operation; never construct a replacement grant.
        if let Some(operation) = self.operation.take() {
            let admission = self.admission;
            let key = self.key.clone();
            self.files
                .read_mut(&memo_attribution(self.analyzer), |files| {
                    files.entry(key).or_default().seed = Some(SeedOperation {
                        operation: Some(operation),
                        admission,
                    });
                });
        }
    }
}

impl Default for FlowStateTraversalCache<'_> {
    fn default() -> Self {
        Self::new(None)
    }
}

/// Record the semantic artifact one flow-state derivation was taken from.
///
/// The cache's own key carries a `ProjectFile`, which knows its workspace root,
/// so it can never be the recorded identity. The artifact's public fingerprint
/// can: it names the exact path, content, adapter, IR version, configuration
/// and dependency identity the state was derived under, and nothing about
/// where the checkout lives.
fn record_flow_artifact_read(
    workspace: &WorkspaceAnalyzer,
    artifact: Option<&brokk_bifrost_analysis::analyzer::semantic::SemanticArtifact>,
) {
    let analyzer = workspace.analyzer();
    if !brokk_bifrost_analysis::analyzer::read_attribution_records_reads(|| {
        analyzer.read_ledger_attached()
    }) {
        return;
    }
    let Some(artifact) = artifact else {
        return;
    };
    analyzer.record_read(crate::analyzer::ReadKey::semantic_artifact(artifact.key()));
}

impl<'a> FlowStateTraversalCache<'a> {
    /// Start one request cache from the activation snapshot its other semantic
    /// row families use.
    pub(super) fn new(
        active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    ) -> Self {
        let active_model_set_hash = active_semantic_model_snapshot
            .as_ref()
            .map(|snapshot| Arc::<str>::from(snapshot.active_models().active_model_set_hash()));
        Self {
            active_semantic_model_snapshot: CaptureScopedMemo::new(active_semantic_model_snapshot),
            active_model_set_hash: CaptureScopedMemo::new(active_model_set_hash),
            files: CaptureScopedMemo::default(),
            nonreturn_provider: None,
            nonreturn_discovery_cache: NonreturnDiscoveryCache::default(),
            reuse: ReuseVerdict::Content,
        }
    }

    /// Release derived rows for a completed artifact-independent file window.
    pub(super) fn release_file_window(&mut self) {
        self.files = CaptureScopedMemo::default();
    }

    /// The cache key of one file's entry. The outcome identity is taken from
    /// the outcome as given: mapping a native outcome onto a selected Arc
    /// preserves its variant, so every adapter lands on the same entry.
    fn file_key<T>(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        outcome: &SemanticOutcome<T>,
    ) -> FlowStateFileKey {
        FlowStateFileKey {
            file: file.clone(),
            active_model_set_hash: self
                .active_model_set_hash
                .read(&memo_attribution(analyzer), Clone::clone),
            outcome: FlowStateOutcomeIdentity::for_outcome(outcome),
        }
    }

    /// Derive (or replay) the flow state of one file.
    ///
    /// No read key is formed here: the semantic artifact this state is derived
    /// from records its own `Artifact` key at the materialization funnel, which
    /// runs below this call. The materialized entry points below *do* form
    /// one, because the caller already owns the artifact and this cache can
    /// answer from a retained state without crossing that funnel again.
    ///
    /// Supply an unbound state for the exact-artifact cache regression.
    #[cfg(test)]
    pub(super) fn for_file(
        &mut self,
        workspace: &WorkspaceAnalyzer,
        file: &ProjectFile,
        cancellation: Option<&CancellationToken>,
    ) -> Arc<FileFlowState> {
        let key = FlowStateFileKey {
            file: file.clone(),
            active_model_set_hash: self
                .active_model_set_hash
                .read(&memo_attribution(workspace.analyzer()), Clone::clone),
            outcome: FlowStateOutcomeIdentity::Standalone,
        };
        if let Some(cached) = self
            .files
            .read(&memo_attribution(workspace.analyzer()), |files| {
                files
                    .get(&key)
                    .and_then(|entry| entry.scopes.get(&FlowStateCacheScope::File))
                    .and_then(|states| states.content.clone())
            })
        {
            return cached;
        }
        let derived = Arc::new(flow_state_for_file_with_snapshot(
            workspace,
            file,
            cancellation,
            self.active_semantic_model_snapshot
                .read(&memo_attribution(workspace.analyzer()), Clone::clone),
        ));
        self.files
            .read_mut(&memo_attribution(workspace.analyzer()), |files| {
                // The standalone path has no outcome to pair a state with, so
                // it is filed as content for its one (unbound) scope.
                files
                    .entry(key)
                    .or_default()
                    .scope_for(FlowStateCacheScope::File, None)
                    .content = Some(Arc::clone(&derived));
            });
        derived
    }

    /// Derive (or replay) flow state from the exact semantic artifact outcome
    /// whose handles the caller will join against.
    pub(super) fn for_materialized_file(
        &mut self,
        workspace: &'a WorkspaceAnalyzer,
        file: &ProjectFile,
        outcome: SemanticOutcome<Arc<SemanticArtifact>>,
        cancellation: Option<&CancellationToken>,
    ) -> Arc<FileFlowState> {
        let artifact = outcome.available_value().cloned();
        record_flow_artifact_read(workspace, artifact.as_deref());
        self.cached_materialized_scope(
            workspace,
            workspace.analyzer(),
            file,
            outcome,
            FlowStateCacheScope::File,
            cancellation,
            |outcome, request, provider| {
                let mut budget = crate::analyzer::semantic::SemanticBudget::default();
                flow_state_for_materialized_artifact_with_provider(
                    workspace,
                    file,
                    outcome,
                    request,
                    &mut budget,
                    provider,
                )
            },
        )
    }

    /// Derive (or replay) flow state for one exact procedure from the semantic
    /// artifact allocation that minted its handle. Every miss takes a fresh
    /// grant; the retained seed operation is never touched here.
    pub(super) fn for_materialized_procedure(
        &mut self,
        workspace: &'a WorkspaceAnalyzer,
        file: &ProjectFile,
        outcome: SemanticOutcome<Arc<SemanticArtifact>>,
        procedure: &ProcedureHandle,
        cancellation: Option<&CancellationToken>,
    ) -> Arc<FileFlowState> {
        let artifact = outcome.available_value().cloned();
        record_flow_artifact_read(workspace, artifact.as_deref());
        if let Some(artifact) = artifact.as_ref() {
            assert!(
                Arc::ptr_eq(artifact, procedure.artifact()),
                "procedure-scoped flow cache requires a handle from the supplied artifact allocation"
            );
        }
        self.cached_materialized_scope(
            workspace,
            workspace.analyzer(),
            file,
            outcome,
            FlowStateCacheScope::Procedure(procedure.id(), procedure.interpretation()),
            cancellation,
            |outcome, request, provider| {
                let mut budget = crate::analyzer::semantic::SemanticBudget::default();
                flow_state_for_materialized_procedure_with_provider(
                    workspace,
                    file,
                    outcome,
                    procedure,
                    request,
                    &mut budget,
                    provider,
                )
            },
        )
    }

    /// Derive (or replay) flow state for one seed procedure on the file's
    /// retained operation: the one per-file allowance the formerly whole-file
    /// seeds (state events, flow relations, initializers) share.
    ///
    /// `native` is exactly the file's materialized outcome and `procedure` the
    /// already selected handle (selection authority and receipt were applied by
    /// the caller). The operation is anchored to the native artifact only; the
    /// selected view's allocation lives in the scope's states, so changing the
    /// view never resets paid work. `Err` is only an admission refusal: the
    /// native census (every seed of the file stops) or this scope's distinct
    /// selected allocation (this scope stops). A refusal is retained and
    /// replayed without deriving, re-admitting or refreshing any grant.
    pub(super) fn for_seed_procedure(
        &mut self,
        workspace: &'a WorkspaceAnalyzer,
        file: &ProjectFile,
        native: SemanticOutcome<Arc<SemanticArtifact>>,
        procedure: &ProcedureHandle,
        cancellation: Option<&CancellationToken>,
    ) -> Result<Arc<FileFlowState>, SemanticBudgetExceeded> {
        self.seed_scope(
            workspace,
            file,
            native,
            procedure,
            cancellation,
            |outcome, budget, request, provider| {
                flow_state_for_materialized_procedure_with_provider(
                    workspace, file, outcome, procedure, request, budget, provider,
                )
            },
        )
    }

    fn seed_scope<F>(
        &mut self,
        workspace: &'a WorkspaceAnalyzer,
        file: &ProjectFile,
        native: SemanticOutcome<Arc<SemanticArtifact>>,
        procedure: &ProcedureHandle,
        cancellation: Option<&CancellationToken>,
        derive: F,
    ) -> Result<Arc<FileFlowState>, SemanticBudgetExceeded>
    where
        F: FnOnce(
            SemanticOutcome<Arc<SemanticArtifact>>,
            &mut SemanticBudget,
            &mut FlowStateRequest<'_>,
            &WorkspaceIcfgProvider<'a>,
        ) -> FileFlowState,
    {
        let analyzer = workspace.analyzer();
        let native_artifact = native
            .available_value()
            .cloned()
            .expect("unavailable outcomes are reported before seeding a procedure");
        record_flow_artifact_read(workspace, Some(native_artifact.as_ref()));
        assert_eq!(
            native_artifact.key(),
            procedure.artifact().key(),
            "the selected procedure belongs to the native file artifact's public key"
        );
        let selected = Arc::clone(procedure.artifact());
        // Keep the native variant and work; derive from the exact selected
        // allocation. Never conditioned on pointer equality.
        let derived_outcome = native.clone().map(|_| Arc::clone(&selected));
        let key = self.file_key(analyzer, file, &native);
        let scope = FlowStateCacheScope::Procedure(procedure.id(), procedure.interpretation());

        // Anchor, then look the scope up. Attributed like every other access.
        let lookup = self.files.read_mut(&memo_attribution(analyzer), |files| {
            let entry = files.entry(key.clone()).or_default();
            match &entry.native {
                None => entry.native = Some(Arc::clone(&native_artifact)),
                Some(anchor) if Arc::ptr_eq(anchor, &native_artifact) => {}
                Some(_) => {
                    *entry = FlowStateFileEntry {
                        native: Some(Arc::clone(&native_artifact)),
                        ..FlowStateFileEntry::default()
                    };
                }
            }
            if let Some(SeedOperation {
                admission: SeedAdmission::Refused(exceeded),
                ..
            }) = &entry.seed
            {
                return SeedLookup::Refused(*exceeded);
            }
            match entry.scopes.get(&scope) {
                Some(states) if states.matches(&selected) => match &states.seed_slot {
                    Some(SeedSlot::Refused(exceeded)) => SeedLookup::Refused(*exceeded),
                    _ => states
                        .lookup(FlowStateOwner::SeedOperation)
                        .map_or(SeedLookup::Miss, SeedLookup::Hit),
                },
                _ => SeedLookup::Miss,
            }
        });
        match lookup {
            SeedLookup::Hit(state) => {
                self.reuse.join_in(state.reuse_verdict());
                return Ok(state);
            }
            SeedLookup::Refused(exceeded) => {
                // The refusal is retained and replayed with its legacy marks;
                // nothing is derived, re-admitted or refreshed.
                analyzer.mark_execution_dependent();
                self.reuse.join_in(EXECUTION_DEPENDENT);
                return Err(exceeded);
            }
            SeedLookup::Miss => {}
        }

        let token = cancellation.cloned().unwrap_or_default();
        let snapshot = self
            .active_semantic_model_snapshot
            .read(&memo_attribution(analyzer), Clone::clone);
        let provider = self.nonreturn_provider.get_or_insert_with(|| {
            WorkspaceIcfgProvider::with_active_semantic_model_snapshot(workspace, snapshot.clone())
        });
        let discovery_cache = &self.nonreturn_discovery_cache;

        // Check the operation out. No map access is held during derivation.
        let (operation, admission) = self.files.read_mut(&memo_attribution(analyzer), |files| {
            let entry = files.get_mut(&key).expect("anchored above");
            match entry.seed.as_mut() {
                Some(seed) => (
                    Some(
                        seed.operation
                            .take()
                            .expect("a seed operation is leased by one derivation at a time"),
                    ),
                    seed.admission,
                ),
                None => (None, SeedAdmission::Pending),
            }
        });
        let operation = operation.unwrap_or_else(|| {
            FlowStateOperation::new(FlowStateRequestMemos::new(workspace.retention_budget()))
        });
        let mut lease = SeedOperationLease {
            files: &mut self.files,
            analyzer,
            key,
            operation: Some(operation),
            admission,
        };
        let native_complete = matches!(native, SemanticOutcome::Complete { .. });
        let attempt = {
            let SeedOperationLease {
                operation,
                admission,
                ..
            } = &mut lease;
            operation
                .as_mut()
                .expect("leased operation")
                .with_request(&token, |budget, request| {
                    if *admission == SeedAdmission::Pending {
                        // Decided exactly once per native anchor. A partial
                        // native artifact is not prepaid.
                        *admission = if native_complete {
                            match budget.admit_held_artifact(&native_artifact) {
                                Ok(()) => SeedAdmission::Admitted,
                                Err(exceeded) => SeedAdmission::Refused(exceeded),
                            }
                        } else {
                            SeedAdmission::NotApplicable
                        };
                    }
                    if let SeedAdmission::Refused(exceeded) = *admission {
                        return SeedAttempt::NativeRefused(exceeded);
                    }
                    if *admission == SeedAdmission::Admitted
                        && let Err(exceeded) = budget.admit_held_artifact(&selected)
                    {
                        return SeedAttempt::ScopeRefused(exceeded);
                    }
                    request.install_active_semantic_model_snapshot(snapshot);
                    request.install_nonreturn_discovery_cache(discovery_cache);
                    let refusals_before = request.refusal_count();
                    let state = derive(derived_outcome, budget, request, provider);
                    SeedAttempt::Derived(state, request.refusal_count() > refusals_before)
                })
        };
        match attempt {
            SeedAttempt::NativeRefused(exceeded) => {
                lease.commit(scope, &selected, SeedCommit::Nothing);
                analyzer.mark_execution_dependent();
                self.reuse.join_in(EXECUTION_DEPENDENT);
                Err(exceeded)
            }
            SeedAttempt::ScopeRefused(exceeded) => {
                lease.commit(scope, &selected, SeedCommit::ScopeRefused(exceeded));
                analyzer.mark_execution_dependent();
                self.reuse.join_in(EXECUTION_DEPENDENT);
                Err(exceeded)
            }
            SeedAttempt::Derived(state, refused) => {
                let state = Arc::new(state);
                lease.commit(scope, &selected, SeedCommit::Derived(Arc::clone(&state)));
                self.reuse.join_in(state.reuse_verdict());
                if refused {
                    brokk_bifrost_core::profiling::note_with(|| {
                        format!(
                            "policy.units unbounded origin={}:{} cause=budget:cfg",
                            file!(),
                            line!()
                        )
                    });
                    analyzer.mark_execution_dependent();
                    self.reuse.join_in(EXECUTION_DEPENDENT);
                }
                Ok(state)
            }
        }
    }

    /// Derive property-reaching rows for one exact point from its retained
    /// procedure artifact and this request's frozen semantic-model snapshot.
    pub(super) fn for_selected_property(
        &mut self,
        workspace: &'a WorkspaceAnalyzer,
        file: &ProjectFile,
        outcome: SemanticOutcome<Arc<SemanticArtifact>>,
        procedure: &ProcedureHandle,
        point: ProgramPointId,
        cancellation: Option<&CancellationToken>,
    ) -> Arc<FileFlowState> {
        let state =
            self.for_materialized_procedure(workspace, file, outcome, procedure, cancellation);
        let token = cancellation.cloned().unwrap_or_default();
        let mut request = FlowStateRequest::new(
            &token,
            brokk_bifrost_flow::flow_state::FlowStateRequestMemos::new(
                workspace.retention_budget(),
            ),
        )
        .with_nonreturn_discovery_cache(&self.nonreturn_discovery_cache)
        .with_active_semantic_model_snapshot(
            self.active_semantic_model_snapshot
                .read(&memo_attribution(workspace.analyzer()), Clone::clone),
        );
        let derived = Arc::new(flow_state_for_selected_property(
            workspace,
            file,
            &state,
            procedure,
            point,
            &mut request,
        ));
        if request.refusal_count() > 0 {
            workspace.analyzer().mark_execution_dependent();
            self.reuse.join_in(EXECUTION_DEPENDENT);
        }
        derived
    }

    #[allow(clippy::too_many_arguments)]
    fn cached_materialized_scope<F>(
        &mut self,
        workspace: &'a WorkspaceAnalyzer,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        outcome: SemanticOutcome<Arc<SemanticArtifact>>,
        scope: FlowStateCacheScope,
        cancellation: Option<&CancellationToken>,
        derive: F,
    ) -> Arc<FileFlowState>
    where
        F: FnOnce(
            SemanticOutcome<Arc<SemanticArtifact>>,
            &mut FlowStateRequest<'_>,
            &WorkspaceIcfgProvider<'a>,
        ) -> FileFlowState,
    {
        let artifact = outcome.available_value().cloned();
        let key = self.file_key(analyzer, file, &outcome);
        if let Some(wanted) = artifact.as_ref()
            && let Some(cached) = self.files.read(&memo_attribution(analyzer), |files| {
                files
                    .get(&key)
                    .and_then(|entry| entry.scopes.get(&scope))
                    .filter(|states| states.matches(wanted))
                    .and_then(|states| states.lookup(FlowStateOwner::PerMiss))
            })
        {
            return cached;
        }
        let token = cancellation.cloned().unwrap_or_default();
        let provider = self.nonreturn_provider.get_or_insert_with(|| {
            WorkspaceIcfgProvider::with_active_semantic_model_snapshot(
                workspace,
                self.active_semantic_model_snapshot
                    .read(&memo_attribution(analyzer), Clone::clone),
            )
        });
        let mut request = FlowStateRequest::new(
            &token,
            brokk_bifrost_flow::flow_state::FlowStateRequestMemos::new(
                workspace.retention_budget(),
            ),
        )
        .with_nonreturn_discovery_cache(&self.nonreturn_discovery_cache)
        .with_active_semantic_model_snapshot(
            self.active_semantic_model_snapshot
                .read(&memo_attribution(analyzer), Clone::clone),
        );
        let derived = Arc::new(derive(outcome, &mut request, provider));
        if request.refusal_count() > 0 {
            brokk_bifrost_core::profiling::note_with(|| {
                format!(
                    "policy.units unbounded origin={}:{} cause=budget:cfg",
                    file!(),
                    line!()
                )
            });
            analyzer.mark_execution_dependent();
            self.reuse.join_in(EXECUTION_DEPENDENT);
        }
        self.files.read_mut(&memo_attribution(analyzer), |files| {
            files
                .entry(key)
                .or_default()
                .scope_for(scope, artifact)
                .store(FlowStateOwner::PerMiss, &derived);
        });
        derived
    }

    /// Turn one derivation's completeness into typed diagnostics.
    ///
    /// Every [`FlowStateIncompleteReason`] that blocks an axis of `axes`
    /// surfaces: budget exhaustion and a file that does not lower are
    /// `Incomplete`, never an empty complete answer. `subject` is the thing the
    /// derivation was about (a workspace-relative path, or a procedure's wire
    /// id).
    ///
    /// `axes` is the set of axes the *caller's* row family publishes, and a
    /// reason blocking none of them is not reported. Without it, a
    /// `state-events-of` query over any procedure that contains a call would be
    /// reported incomplete because the lowering cannot model the call's
    /// same-evaluation dependence -- an axis that query does not publish, and
    /// whose hole the event rows already declare covered in their own
    /// `completeness` field. Reporting it made every relational policy over
    /// state events inconclusive on every language with calls (#2443).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn report_completeness(
        &mut self,
        analyzer: &dyn IAnalyzer,
        subject: &str,
        procedure: Option<&super::semantic::SemanticProcedureValue>,
        language: Language,
        completeness: &FlowStateCompleteness,
        axes: &[FlowStateAxis],
        generation: u64,
        diagnostics: &mut Vec<CodeQueryDiagnostic>,
    ) {
        for reason in completeness.reasons() {
            if !axes.iter().any(|axis| reason.blocks(*axis)) {
                continue;
            }
            let (code, detail, cause) = classify_reason(reason);
            let source = procedure.and_then(|procedure| procedure.diagnostic_source());
            let related = procedure
                .map(|procedure| {
                    procedure.related_flow_reasons(
                        &completeness
                            .reasons()
                            .iter()
                            .filter(|other| {
                                axes.iter().any(|axis| other.blocks(*axis))
                                    && classify_reason(other).1 == detail
                            })
                            .cloned()
                            .collect::<Vec<_>>(),
                    )
                })
                .unwrap_or_default();
            let detail = if let FlowStateIncompleteReason::PropertySnapshotBudgetExhausted {
                detail: refusal,
            } = reason
            {
                std::borrow::Cow::Owned(format!("{detail}: {refusal}"))
            } else {
                std::borrow::Cow::Borrowed(detail)
            };
            let uncovered = FLOW_STATE_AXES
                .iter()
                .filter(|axis| !completeness.covers(**axis))
                .map(|axis| axis.label())
                .collect::<Vec<_>>();
            diagnostics.push(super::QueryExecutionState::diagnostic(analyzer, CodeQueryDiagnostic::new(CodeQueryDiagnostic {
                has_non_utf8_refusal: false,
                refusal_sites: Default::default(),
                call_relation_facts: None,
                uses_omissions: Vec::new(),
                incompleteness: match cause { Some(cause) => Incompleteness::Operational(cause), None => Incompleteness::Content },
                related,
                source,
                code,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: language.config_label(),
                message: format!(
                    "{subject} has an incomplete flow-state derivation in generation {generation} ({detail}); uncovered axes: [{}]",
                    uncovered.join(", ")
                ),
            exhausted_roots: Vec::new(),
                withheld_rows_path: None,
 step_index: None, step_op: None, no_rows_reason: None, cause_codes: Vec::new(),
            }), cause));
        }
    }
}

/// The axes a `state_event` row family publishes. A hole in a relation axis
/// leaves the event rows themselves exactly as complete as they were.
pub(super) const STATE_EVENT_AXES: &[FlowStateAxis] =
    &[FlowStateAxis::BindingEvents, FlowStateAxis::PropertyEvents];

/// The axes a `flow_relation` row family publishes.
pub(super) const FLOW_RELATION_AXES: &[FlowStateAxis] = &[
    FlowStateAxis::ReachingRelation,
    FlowStateAxis::DominanceRelation,
    FlowStateAxis::PropertyReachingRelation,
    FlowStateAxis::PropertyDominanceRelation,
    FlowStateAxis::SameEvaluationRelation,
];

/// The diagnostic code and human reason of one incompleteness.
///
/// Total on purpose: a reason added to the derivation layer must be classified
/// here deliberately rather than defaulting into a generic message.
pub(super) fn classify_reason(
    reason: &FlowStateIncompleteReason,
) -> (
    CodeQueryDiagnosticCode,
    &'static str,
    Option<DerivationExecutionCause>,
) {
    use FlowStateIncompleteReason::*;
    match reason {
        AxisUnsupported(_) => (
            CodeQueryDiagnosticCode::FlowStateAxisUnsupported,
            "the lowering declares an axis this derivation stands on unsupported",
            None,
        ),
        NoSemanticProvider => (
            CodeQueryDiagnosticCode::FlowStateAxisUnsupported,
            "no semantic provider is registered for the file's language",
            None,
        ),
        SemanticProviderFailed { .. } => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "the semantic provider returned a typed error",
            Some(DerivationExecutionCause::Provider),
        ),
        SemanticAnalysisPartial { .. } => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "the semantic lowering itself is partial",
            None,
        ),
        Cancelled => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "the derivation was cancelled",
            Some(DerivationExecutionCause::Cancelled),
        ),
        SourceGenerationChanged => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "the analyzed content changed under the derivation",
            Some(DerivationExecutionCause::Snapshot),
        ),
        NoStructuralFacts => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "the language has no structural facts arena to join events onto",
            None,
        ),
        LoweringGap {
            kind: crate::analyzer::semantic::SemanticGapKind::ExceededBudget,
            ..
        } => (
            CodeQueryDiagnosticCode::FlowStateAxisUnsupported,
            "the lowering published an explicit capability gap",
            Some(DerivationExecutionCause::Budget),
        ),
        LoweringGap { .. } => (
            CodeQueryDiagnosticCode::FlowStateAxisUnsupported,
            "the lowering published an explicit capability gap",
            None,
        ),
        BudgetExhausted { .. } => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "a semantic or control-flow algorithm exhausted its budget, so its relation emitted no rows",
            Some(DerivationExecutionCause::Budget),
        ),
        PropertySnapshotBudgetExhausted { .. } => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "the property snapshot exhausted its semantic budget; property events and their relations were withheld",
            Some(DerivationExecutionCause::Budget),
        ),
        SelectedPropertyEndpointUnavailable { .. } => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "a selected semantic property endpoint has no public event projection",
            None,
        ),
        PropertyBaseNotCanonical { .. } => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "a field access has no binding-rooted base, so it contributes no property subject",
            None,
        ),
        BindingWithoutEstablishment { .. } => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "the lowering declares a local binding it never establishes",
            None,
        ),
        BindingScopeLivenessUnavailable { .. } => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "Rust lexical-scope future-frame liveness could not be derived completely",
            None,
        ),
        BindingStateNotClosed { .. } => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "aliasing, capture, or ownership transfer leaves the binding's read/write state open",
            None,
        ),
        PropertyProviderUnavailable => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "the structured property-reaching provider was unavailable",
            Some(DerivationExecutionCause::Provider),
        ),
        PropertyProviderFailed { .. } => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "the structured property-reaching provider returned a typed error",
            Some(DerivationExecutionCause::Provider),
        ),
        PropertyAnalysisPartial { .. } => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "the structured property-reaching snapshot was unavailable from a partial outcome",
            None,
        ),
        PropertyReaching { reason } => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "structured property-reaching evidence was incomplete",
            property_execution_cause(reason),
        ),
        ControlProjectionRejected { .. } => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "the request-local control projection did not match the semantic artifact",
            None,
        ),
        ModeledControlProjectionIncomplete { .. } => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "an applicable modeled control projection could not be proved exactly",
            None,
        ),
    }
}

fn property_execution_cause(
    reason: &crate::analyzer::semantic::PropertyReachingIncompleteReason,
) -> Option<DerivationExecutionCause> {
    use crate::analyzer::semantic::PropertyReachingIncompleteReason::*;
    use crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmError;
    match reason {
        Cancelled => Some(DerivationExecutionCause::Cancelled),
        InputRelationBudgetExceeded { .. } | ReachingPairBudgetExceeded { .. } => {
            Some(DerivationExecutionCause::Budget)
        }
        CandidateCoverage(crate::analyzer::semantic::CandidateCoverage::Truncated) => {
            Some(DerivationExecutionCause::Budget)
        }
        SelectedSemanticGap { gap } | SelectedCleanupMemberGap { gap, .. }
            if gap.kind == crate::analyzer::semantic::SemanticGapKind::ExceededBudget =>
        {
            Some(DerivationExecutionCause::Budget)
        }
        Reachability(error)
        | ReachingDefinitions(error)
        | Dominators(error)
        | ReachingPairs(error) => match error {
            CfgAlgorithmError::Cancelled { .. } => Some(DerivationExecutionCause::Cancelled),
            CfgAlgorithmError::ExceededBudget(_) => Some(DerivationExecutionCause::Budget),
            CfgAlgorithmError::InvalidNode(_) => None,
        },
        SelectedReadMissing { .. }
        | SelectedReadAmbiguous { .. }
        | SelectedRelationEndpointUnavailable { .. }
        | SelectedRuntimeAccess { .. }
        | SelectedAncestorStore { .. }
        | SelectedAliasClosureUnavailable { .. }
        | SelectedSemanticGap { .. }
        | SelectedCleanupMemberGap { .. }
        | CandidateCoverage(_)
        | UnsupportedLocation { .. }
        | DurableIdentityUnavailable { .. }
        | SourceMappingUnavailable { .. }
        | StoreEvidenceIncomplete { .. }
        | ReadEvidenceIncomplete { .. }
        | FieldMemoryEndpointUnavailable { .. }
        | EvaluationEndpointUnavailable { .. }
        | EvaluationEvidenceIncomplete { .. }
        | EvaluationSourceUnknown => None,
    }
}

/// One state-event row travelling through the pipeline.
///
/// The whole file derivation is held by `Arc` rather than the single row,
/// because `flow-relations-of` seeded from an event needs its siblings and its
/// procedure's relations without deriving anything twice.
#[derive(Debug, Clone)]
pub(super) struct StateEventValue {
    pub(super) file_state: Arc<FileFlowState>,
    pub(super) procedure_index: usize,
    pub(super) event: usize,
    pub(super) file: ProjectFile,
    /// The wire identity of the seed procedure, carried from the semantic
    /// handle that produced it so two row families agree on one spelling.
    pub(super) procedure_id: Arc<str>,
    /// Exact request-retained semantic procedure used to relate the event's
    /// establishment value to call results in its initializer.
    pub(super) procedure: ProcedureHandle,
    pub(super) diagnostic_procedure: super::semantic::SemanticProcedureValue,
    /// A scoped relation endpoint still belongs to the original aggregate
    /// derivation. Its origin tells a subsequent aggregate expansion to emit
    /// that scope's coverage before filtering.
    pub(super) selected_property_origin: Option<ProgramPointId>,
}

impl StateEventValue {
    pub(super) fn derivation(&self) -> &FlowStateDerivation {
        &self.file_state.procedures[self.procedure_index]
    }

    pub(super) fn row(&self) -> &StateEventRow {
        self.derivation().event(self.event)
    }

    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }

    pub(super) fn key(&self) -> StateEventKey {
        StateEventKey {
            file: self.file.clone(),
            procedure: self.procedure_id.to_string(),
            event: self.event,
            selected_property_origin: self.selected_property_origin,
        }
    }

    pub(super) fn id(&self) -> String {
        state_event_id(&self.procedure_id, self.row())
    }
}

/// Evidence for one selected read. It retains only its relation rows and
/// coverage; endpoints remain in the shared aggregate derivation.
#[derive(Debug)]
pub(super) struct SelectedPropertyRelations {
    pub(super) point: ProgramPointId,
    pub(super) relations: Box<[FlowRelationRow]>,
    pub(super) completeness: FlowStateCompleteness,
}

/// One flow-relation row travelling through the pipeline.
#[derive(Debug, Clone)]
pub(super) struct FlowRelationValue {
    pub(super) file_state: Arc<FileFlowState>,
    pub(super) procedure_index: usize,
    pub(super) relation: usize,
    pub(super) file: ProjectFile,
    pub(super) procedure_id: Arc<str>,
    pub(super) procedure: ProcedureHandle,
    pub(super) diagnostic_procedure: super::semantic::SemanticProcedureValue,
    pub(super) selected_property: Option<Arc<SelectedPropertyRelations>>,
}

impl FlowRelationValue {
    pub(super) fn derivation(&self) -> &FlowStateDerivation {
        &self.file_state.procedures[self.procedure_index]
    }

    pub(super) fn row(&self) -> &FlowRelationRow {
        match &self.selected_property {
            Some(proof) => &proof.relations[self.relation],
            None => &self.derivation().relations[self.relation],
        }
    }

    fn completeness(&self) -> &FlowStateCompleteness {
        match &self.selected_property {
            Some(proof) => &proof.completeness,
            None => &self.derivation().completeness,
        }
    }

    pub(super) fn source(&self) -> &StateEventRow {
        self.derivation().event(self.row().source_event)
    }

    pub(super) fn target(&self) -> &StateEventRow {
        self.derivation().event(self.row().target_event)
    }

    /// The relation's own source anchor is its target read: that is the
    /// position an author is asking about when they ask what serves a read.
    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }

    pub(super) fn key(&self) -> FlowRelationKey {
        FlowRelationKey {
            file: self.file.clone(),
            procedure: self.procedure_id.to_string(),
            relation: self.relation,
            selected_property_origin: self.selected_property.as_ref().map(|proof| proof.point),
            selected_relation: self.selected_property.as_ref().map(|_| self.id()),
        }
    }

    pub(super) fn id(&self) -> String {
        let mut digest = LengthDelimitedDigest::new(FLOW_RELATION_ID_DOMAIN);
        digest.push(self.procedure_id.as_bytes());
        digest.push(self.row().relation.label().as_bytes());
        digest.push(self.row().certainty.label().as_bytes());
        digest.push(state_event_id(&self.procedure_id, self.source()).as_bytes());
        digest.push(state_event_id(&self.procedure_id, self.target()).as_bytes());
        digest.finish().to_string()
    }

    /// The state event one projection step returns.
    pub(super) fn endpoint(&self, target_end: bool) -> StateEventValue {
        StateEventValue {
            file_state: Arc::clone(&self.file_state),
            procedure_index: self.procedure_index,
            event: if target_end {
                self.row().target_event
            } else {
                self.row().source_event
            },
            file: self.file.clone(),
            procedure_id: Arc::clone(&self.procedure_id),
            procedure: self.procedure.clone(),
            diagnostic_procedure: self.diagnostic_procedure.clone(),
            selected_property_origin: self.selected_property.as_ref().map(|proof| proof.point),
        }
    }
}

/// One request-derived link from a binding establishment to a call result in
/// its initializer receiver chain.
#[derive(Debug, Clone)]
pub(super) struct BindingInitializerCallValue {
    pub(super) row: CodeQueryBindingInitializerCall,
    pub(super) file: ProjectFile,
}

pub(super) fn state_event_id(procedure_id: &str, row: &StateEventRow) -> String {
    let mut digest = LengthDelimitedDigest::new(STATE_EVENT_ID_DOMAIN);
    digest.push(procedure_id.as_bytes());
    digest.push(rel_path_string(&row.site.file).as_bytes());
    digest.push(&row.site.range.start_byte.to_le_bytes());
    digest.push(&row.site.range.end_byte.to_le_bytes());
    digest.push(row.event_class.label().as_bytes());
    digest.push(row.subject.kind().label().as_bytes());
    digest.push(row.subject.member().unwrap_or("").as_bytes());
    digest.push(&(row.subject.value().index() as u64).to_le_bytes());
    digest.finish().to_string()
}

/// Dedup identity of a state-event row: the seed procedure plus the dense
/// event index the derivation minted. Two events at one source position with
/// different classes are two rows, which is the point of the domain.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct StateEventKey {
    pub(super) file: ProjectFile,
    pub(super) procedure: String,
    pub(super) event: usize,
    pub(super) selected_property_origin: Option<ProgramPointId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct FlowRelationKey {
    pub(super) file: ProjectFile,
    pub(super) procedure: String,
    pub(super) relation: usize,
    pub(super) selected_property_origin: Option<ProgramPointId>,
    pub(super) selected_relation: Option<String>,
}

pub(super) fn state_event_filter_matches(filter: &StateEventFilter, row: &StateEventRow) -> bool {
    if !filter.classes.is_empty() && !filter.classes.contains(&row.event_class) {
        return false;
    }
    if !filter.subjects.is_empty() && !filter.subjects.contains(&row.subject.kind()) {
        return false;
    }
    if !filter.read_causes.is_empty()
        && !row
            .read_cause
            .is_some_and(|cause| filter.read_causes.contains(&cause))
    {
        return false;
    }
    true
}

pub(super) fn flow_relation_filter_matches(
    filter: &FlowRelationFilter,
    row: &FlowRelationRow,
) -> bool {
    if !filter.relations.is_empty() && !filter.relations.contains(&row.relation) {
        return false;
    }
    if !filter.certainties.is_empty() && !filter.certainties.contains(&row.certainty) {
        return false;
    }
    true
}

/// The public projection of one state-event row.
pub(super) fn public_state_event(
    value: &StateEventValue,
    range: CodeQueryRange,
) -> CodeQueryStateEvent {
    let row = value.row();
    let common = state_event_projection(value.id(), row, range);
    CodeQueryStateEvent {
        id: common.id,
        ast_id: common.ast_id,
        procedure_id: value.procedure_id.to_string(),
        path: common.path,
        language: crate::analyzer::common::language_for_file(&row.site.file).config_label(),
        range: common.range,
        start_byte: row.site.range.start_byte,
        end_byte: row.site.range.end_byte,
        event_class: common.event_class,
        read_cause: row.read_cause.map(|cause| cause.label()),
        subject: common.subject,
        member: common.member,
        subject_value: row.subject.value().index(),
        program_point: common.program_point,
        program_point_id: common.program_point_id,
        value: row.value.index(),
        completeness: axis_completeness_label(&value.derivation().completeness, row.subject.axis()),
        uncovered_axes: uncovered_axes(&value.derivation().completeness),
        generation: row.generation,
    }
}

/// The public projection of one flow-relation row, with both endpoints
/// rendered inline: a relation is unreadable without knowing which write and
/// which read it names.
pub(super) fn public_flow_relation(
    value: &FlowRelationValue,
    source_range: CodeQueryRange,
    target_range: CodeQueryRange,
) -> CodeQueryFlowRelation {
    let row = value.row();
    CodeQueryFlowRelation {
        id: value.id(),
        procedure_id: value.procedure_id.to_string(),
        path: rel_path_string(value.file()),
        language: crate::analyzer::common::language_for_file(value.file()).config_label(),
        range: target_range,
        relation: row.relation.label(),
        certainty: row.certainty.label(),
        source: state_event_ref(&value.procedure_id, value.source(), source_range),
        target: state_event_ref(&value.procedure_id, value.target(), target_range),
        completeness: axis_completeness_label(
            value.completeness(),
            row.relation.axis_for_subject(value.target().subject.kind()),
        ),
        uncovered_axes: uncovered_axes(value.completeness()),
        generation: row.generation,
    }
}

pub(super) fn state_event_ref(
    procedure_id: &str,
    row: &StateEventRow,
    range: CodeQueryRange,
) -> CodeQueryStateEventRef {
    state_event_projection(state_event_id(procedure_id, row), row, range)
}

fn state_event_projection(
    id: String,
    row: &StateEventRow,
    range: CodeQueryRange,
) -> CodeQueryStateEventRef {
    CodeQueryStateEventRef {
        id,
        ast_id: row.site.ast_id.clone(),
        path: rel_path_string(&row.site.file),
        range,
        event_class: row.event_class.label(),
        subject: row.subject.kind().label(),
        member: row.subject.member().map(str::to_string),
        program_point: row.point.index(),
        program_point_id: row.point_id.to_string(),
    }
}

/// The value domain the `state_event.completeness` and
/// `flow_relation.completeness` row fields publish, minted by
/// [`axis_completeness_label`] (issue #2515).
pub(super) const FLOW_STATE_COMPLETENESS_LABELS: &[&str] = &["complete", "partial"];

/// `complete` exactly when the derivation answers *this row's own axis*;
/// otherwise `partial`. A row whose family was fully enumerated is not made
/// partial by a hole in an unrelated axis, and `uncovered_axes` still names
/// every hole the derivation left.
fn axis_completeness_label(
    completeness: &FlowStateCompleteness,
    axis: FlowStateAxis,
) -> &'static str {
    super::completeness_label_for_coverage(completeness.covers(axis))
}

fn uncovered_axes(completeness: &FlowStateCompleteness) -> Vec<&'static str> {
    FLOW_STATE_AXES
        .iter()
        .filter(|axis| !completeness.covers(**axis))
        .map(|axis| axis.label())
        .collect()
}

/// Assertions that keep this module honest about the vocabulary it renders.
#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon(
        "#14370: RQL dropped snapshot budget details and described retained binding rows as absent"
    )]
    fn property_snapshot_budget_diagnostic_reports_resource_and_withheld_property_rows() {
        let directory = tempfile::tempdir().unwrap();
        let analyzer = crate::analyzer::JavascriptAnalyzer::from_project(
            crate::analyzer::TestProject::new(directory.path().to_path_buf(), Language::JavaScript),
        );
        let refusal = crate::analyzer::semantic::SemanticBudgetExceeded::new(
            crate::analyzer::semantic::SemanticBudgetDimension::Values,
            1,
            2,
        )
        .to_string();
        let completeness = FlowStateCompleteness::Incomplete {
            reasons: vec![FlowStateIncompleteReason::PropertySnapshotBudgetExhausted {
                detail: refusal.clone(),
            }],
        };
        let mut cache = FlowStateTraversalCache::default();
        let mut diagnostics = Vec::new();
        for axes in [STATE_EVENT_AXES, FLOW_RELATION_AXES] {
            cache.report_completeness(
                &analyzer,
                "src/main.js",
                None,
                Language::JavaScript,
                &completeness,
                axes,
                7,
                &mut diagnostics,
            );
        }
        assert_eq!(diagnostics.len(), 2);
        for diagnostic in diagnostics {
            assert_eq!(
                diagnostic.code,
                CodeQueryDiagnosticCode::FlowStateDerivationIncomplete
            );
            assert_eq!(diagnostic.impact, CodeQueryDiagnosticImpact::Incomplete);
            assert_eq!(
                diagnostic.incompleteness,
                Incompleteness::Operational(DerivationExecutionCause::Budget)
            );
            assert!(diagnostic.message.contains(&refusal), "{diagnostic:?}");
            assert!(
                diagnostic
                    .message
                    .contains("property events and their relations were withheld"),
                "{diagnostic:?}"
            );
            assert!(
                !diagnostic.message.contains("relation emitted no rows"),
                "{diagnostic:?}"
            );
        }
    }

    #[test]
    #[hardwon("#7107: flow-state value memo suppressed diagnostics across invocation boundaries")]
    fn an_incomplete_derivation_replays_every_invocation() {
        let directory = tempfile::tempdir().unwrap();
        let analyzer =
            crate::analyzer::JavascriptAnalyzer::from_project(crate::analyzer::TestProject::new(
                directory.path().to_path_buf(),
                crate::analyzer::Language::JavaScript,
            ));

        let mut cache = FlowStateTraversalCache::default();
        let completeness = FlowStateCompleteness::Incomplete {
            reasons: vec![
                FlowStateIncompleteReason::AxisUnsupported(FlowStateAxis::PropertyEvents),
                FlowStateIncompleteReason::BudgetExhausted {
                    axis: FlowStateAxis::ReachingRelation,
                    detail: "NodeVisits limit 1 exceeded at 2".to_string(),
                },
            ],
        };
        let mut diagnostics = Vec::new();
        cache.report_completeness(
            &analyzer,
            "src/main.js",
            None,
            Language::JavaScript,
            &completeness,
            FLOW_STATE_AXES,
            7,
            &mut diagnostics,
        );
        crate::structural::search::test_support::assert_incomplete_diagnostics(&diagnostics, 2);
        // A fresh invocation reports the same evidence independently.
        cache.report_completeness(
            &analyzer,
            "src/main.js",
            None,
            Language::JavaScript,
            &completeness,
            FLOW_STATE_AXES,
            7,
            &mut diagnostics,
        );
        crate::structural::search::test_support::assert_incomplete_diagnostics(&diagnostics, 4);
        assert!(!completeness.covers(FlowStateAxis::PropertyEvents));
        assert!(!completeness.covers(FlowStateAxis::ReachingRelation));
    }

    /// A reason that blocks no axis the caller publishes is not the caller's
    /// incompleteness. This is what keeps a state-event query over a procedure
    /// with a call conclusive: the lowering cannot model the call's
    /// same-evaluation dependence, and a set of binding events is not made
    /// partial by that.
    #[test]
    fn a_reason_outside_the_requested_axes_is_not_reported() {
        let directory = tempfile::tempdir().unwrap();
        let analyzer =
            crate::analyzer::JavascriptAnalyzer::from_project(crate::analyzer::TestProject::new(
                directory.path().to_path_buf(),
                crate::analyzer::Language::JavaScript,
            ));

        let mut cache = FlowStateTraversalCache::default();
        let completeness = FlowStateCompleteness::Incomplete {
            reasons: vec![FlowStateIncompleteReason::LoweringGap {
                gaps: Vec::new(),
                capability: SemanticCapability::Calls,
                kind: SemanticGapKind::Unsupported,
                detail: "the adapter does not model this call".to_string(),
            }],
        };
        let mut diagnostics = Vec::new();
        cache.report_completeness(
            &analyzer,
            "src/main.js",
            None,
            Language::JavaScript,
            &completeness,
            STATE_EVENT_AXES,
            7,
            &mut diagnostics,
        );
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert!(completeness.covers(FlowStateAxis::BindingEvents));

        cache.report_completeness(
            &analyzer,
            "src/main.js",
            None,
            Language::JavaScript,
            &completeness,
            FLOW_RELATION_AXES,
            7,
            &mut diagnostics,
        );
        assert_eq!(
            diagnostics.len(),
            1,
            "the same reason does block the relation family: {diagnostics:?}"
        );
        assert!(!completeness.covers(FlowStateAxis::SameEvaluationRelation));
    }

    // ---- C3 cache controls: owner kinds, the retained seed operation, refusals ----

    use super::super::tests::inline_project::{BuiltInlineTestProject, InlineTestProject};
    use crate::analyzer::AnalyzerConfig;
    use crate::analyzer::semantic::{SemanticRequest, SemanticWork};
    use brokk_bifrost_flow::flow_state::FlowStateOperationConsumption;

    const SEED_SOURCE: &str = r#"package main

func first(input int) int {
    value := input
    return value
}

func second(input int) int {
    value := input
    return value
}
"#;

    /// One project, two analyzer allocations of the same durable file key. The
    /// second one gives distinct same-key artifact allocations: the shape of a
    /// separately admitted selected arena next to the native artifact.
    struct SeedFixture {
        _project: BuiltInlineTestProject,
        workspace: WorkspaceAnalyzer,
        other_workspace: WorkspaceAnalyzer,
        file: ProjectFile,
        native: SemanticOutcome<Arc<SemanticArtifact>>,
        other_native: SemanticOutcome<Arc<SemanticArtifact>>,
    }

    impl SeedFixture {
        fn new() -> Self {
            let project = InlineTestProject::with_language(Language::Go)
                .file("main.go", SEED_SOURCE)
                .build();
            let workspace = project.workspace_analyzer(AnalyzerConfig::default());
            let other_workspace = project.workspace_analyzer(AnalyzerConfig::default());
            let file = project.file("main.go");
            let materialize = |workspace: &WorkspaceAnalyzer| {
                let cancellation = CancellationToken::default();
                workspace
                    .materialize_program_semantics(
                        &file,
                        &mut SemanticRequest::new(&mut SemanticBudget::default(), &cancellation),
                    )
                    .expect("Go artifact materialization")
            };
            let native = materialize(&workspace);
            let other_native = materialize(&other_workspace);
            Self {
                _project: project,
                workspace,
                other_workspace,
                file,
                native,
                other_native,
            }
        }

        fn handles(outcome: &SemanticOutcome<Arc<SemanticArtifact>>) -> Vec<ProcedureHandle> {
            let artifact = outcome.available_value().expect("Go artifact is available");
            let handles = artifact
                .procedures()
                .iter()
                .map(|procedure| {
                    artifact
                        .procedure_handle(procedure.id())
                        .expect("the artifact owns its procedures")
                })
                .collect::<Vec<_>>();
            assert!(handles.len() >= 2, "both functions lower");
            handles
        }
    }

    fn pristine_consumption(fixture: &SeedFixture) -> FlowStateOperationConsumption {
        FlowStateOperation::new(FlowStateRequestMemos::new(
            fixture.workspace.retention_budget(),
        ))
        .consumption()
    }

    fn with_entry<R>(
        cache: &mut FlowStateTraversalCache<'_>,
        fixture: &SeedFixture,
        probe: impl FnOnce(Option<&FlowStateFileEntry>) -> R,
    ) -> R {
        let analyzer = fixture.workspace.analyzer();
        let key = cache.file_key(analyzer, &fixture.file, &fixture.native);
        cache
            .files
            .read(&memo_attribution(analyzer), |files| probe(files.get(&key)))
    }

    fn consumption(
        cache: &mut FlowStateTraversalCache<'_>,
        fixture: &SeedFixture,
    ) -> FlowStateOperationConsumption {
        with_entry(cache, fixture, |entry| {
            entry
                .and_then(|entry| entry.seed.as_ref())
                .and_then(|seed| seed.operation.as_ref())
                .expect("a retained seed operation")
                .consumption()
        })
    }

    fn seed_with<'a>(
        cache: &mut FlowStateTraversalCache<'a>,
        fixture: &'a SeedFixture,
        handle: &ProcedureHandle,
        token: &CancellationToken,
    ) -> Result<Arc<FileFlowState>, SemanticBudgetExceeded> {
        cache.for_seed_procedure(
            &fixture.workspace,
            &fixture.file,
            fixture.native.clone(),
            handle,
            Some(token),
        )
    }

    fn per_miss_with<'a>(
        cache: &mut FlowStateTraversalCache<'a>,
        fixture: &'a SeedFixture,
        handle: &ProcedureHandle,
        token: &CancellationToken,
    ) -> Arc<FileFlowState> {
        cache.for_materialized_procedure(
            &fixture.workspace,
            &fixture.file,
            fixture.native.clone(),
            handle,
            Some(token),
        )
    }

    #[test]
    #[hardwon("#14156: one owner's paid stopped state was lost or served to the other owner kind")]
    fn owner_kinds_keep_their_own_paid_stops_in_both_orders() {
        let fixture = SeedFixture::new();
        let handle = SeedFixture::handles(&fixture.native).remove(0);
        let live = CancellationToken::default();
        let cancelled = CancellationToken::default();
        cancelled.cancel();
        // SeedOperation stop -> PerMiss content -> SeedOperation.
        let mut cache = FlowStateTraversalCache::default();
        let seed_stop = seed_with(&mut cache, &fixture, &handle, &cancelled).expect("admitted");
        assert!(!state_is_cross_owner_content(&seed_stop));
        let after_stop = consumption(&mut cache, &fixture);
        let content = per_miss_with(&mut cache, &fixture, &handle, &live);
        assert!(state_is_cross_owner_content(&content));
        assert!(
            !Arc::ptr_eq(&seed_stop, &content),
            "another owner's stop is never served as content"
        );
        let again = seed_with(&mut cache, &fixture, &handle, &live).expect("admitted");
        assert!(
            Arc::ptr_eq(&again, &seed_stop),
            "the owner's own paid stop wins before shared content"
        );
        assert_eq!(consumption(&mut cache, &fixture), after_stop);

        // PerMiss stop -> SeedOperation content -> PerMiss.
        let mut cache = FlowStateTraversalCache::default();
        let per_miss_stop = per_miss_with(&mut cache, &fixture, &handle, &cancelled);
        assert!(!state_is_cross_owner_content(&per_miss_stop));
        let seed_content = seed_with(&mut cache, &fixture, &handle, &live).expect("admitted");
        assert!(state_is_cross_owner_content(&seed_content));
        assert!(!Arc::ptr_eq(&per_miss_stop, &seed_content));
        let again = per_miss_with(&mut cache, &fixture, &handle, &live);
        assert!(Arc::ptr_eq(&again, &per_miss_stop));
        // The shared content serves the seed owner afterwards, with no spending.
        let before = consumption(&mut cache, &fixture);
        assert!(Arc::ptr_eq(
            &seed_with(&mut cache, &fixture, &handle, &live).expect("admitted"),
            &seed_content
        ));
        assert_eq!(consumption(&mut cache, &fixture), before);
    }

    #[test]
    #[hardwon(
        "#14156: same-file seeds each received a fresh grant, and a cache hit reset or respent it"
    )]
    fn seeds_share_one_cumulative_operation_and_a_hit_spends_nothing() {
        let fixture = SeedFixture::new();
        let handles = SeedFixture::handles(&fixture.native);
        let live = CancellationToken::default();
        let mut cache = FlowStateTraversalCache::default();
        let pristine = pristine_consumption(&fixture);
        let first = seed_with(&mut cache, &fixture, &handles[0], &live).expect("admitted");
        let after_first = consumption(&mut cache, &fixture);
        assert!(after_first.cfg_used != pristine.cfg_used);
        assert!(
            after_first.semantic_used != pristine.semantic_used,
            "the native census was admitted once"
        );
        seed_with(&mut cache, &fixture, &handles[1], &live).expect("admitted");
        let after_second = consumption(&mut cache, &fixture);
        assert!(
            after_second.cfg_used != after_first.cfg_used,
            "the second seed spends on the same ledger"
        );
        let hit = seed_with(&mut cache, &fixture, &handles[0], &live).expect("admitted");
        assert!(Arc::ptr_eq(&first, &hit));
        assert_eq!(
            consumption(&mut cache, &fixture),
            after_second,
            "a cache hit neither resets nor spends"
        );
        with_entry(&mut cache, &fixture, |entry| {
            let entry = entry.expect("entry");
            assert!(Arc::ptr_eq(
                entry.native.as_ref().expect("anchored"),
                fixture.native.available_value().expect("native"),
            ));
            assert_eq!(entry.scopes.len(), 2);
        });
        // Per-miss consumers keep their own grants and never touch the seed op.
        let mut legacy_only = FlowStateTraversalCache::default();
        legacy_only.for_materialized_procedure(
            &fixture.workspace,
            &fixture.file,
            fixture.native.clone(),
            &handles[0],
            Some(&live),
        );
        with_entry(&mut legacy_only, &fixture, |entry| {
            let entry = entry.expect("entry");
            assert!(entry.seed.is_none() && entry.native.is_none());
        });
    }

    /// An operation whose resident semantic allowance is spent, anchored to the
    /// fixture's native artifact before its first (admission) lend.
    fn prime_seed_operation(
        cache: &mut FlowStateTraversalCache<'_>,
        fixture: &SeedFixture,
        remaining: impl FnOnce(&SemanticWork, &SemanticWork) -> SemanticWork,
    ) {
        let analyzer = fixture.workspace.analyzer();
        let native = fixture.native.available_value().expect("native").clone();
        let mut operation = FlowStateOperation::new(FlowStateRequestMemos::new(
            fixture.workspace.retention_budget(),
        ));
        let token = CancellationToken::default();
        operation.with_request(&token, |budget, _| {
            let limits = budget.limits();
            let spend = remaining(&limits, &native.work());
            budget
                .admit(spend)
                .expect("priming spends within the allowance");
        });
        let key = cache.file_key(analyzer, &fixture.file, &fixture.native);
        cache.files.read_mut(&memo_attribution(analyzer), |files| {
            let entry = files.entry(key).or_default();
            entry.native = Some(native);
            entry.seed = Some(SeedOperation {
                operation: Some(operation),
                admission: SeedAdmission::Pending,
            });
        });
    }

    #[test]
    #[hardwon(
        "#14156: a refused native admission was re-derived, re-admitted or refreshed on repeat"
    )]
    fn a_native_admission_refusal_is_retained_and_replayed_without_deriving() {
        let fixture = SeedFixture::new();
        let handles = SeedFixture::handles(&fixture.native);
        let live = CancellationToken::default();
        let mut cache = FlowStateTraversalCache::default();
        // Fill the whole resident allowance: the native census cannot fit.
        prime_seed_operation(&mut cache, &fixture, |limits, _| *limits);
        let first = seed_with(&mut cache, &fixture, &handles[0], &live)
            .expect_err("the native census is refused");
        let spent = consumption(&mut cache, &fixture);
        for handle in &handles {
            assert_eq!(
                seed_with(&mut cache, &fixture, handle, &live)
                    .expect_err("every seed of the file stops"),
                first
            );
        }
        assert_eq!(
            consumption(&mut cache, &fixture),
            spent,
            "no derivation, re-admission or reset on repeat"
        );
        with_entry(&mut cache, &fixture, |entry| {
            let entry = entry.expect("entry");
            assert!(entry.scopes.is_empty(), "nothing was derived");
            assert_eq!(
                entry.seed.as_ref().expect("retained").admission,
                SeedAdmission::Refused(first)
            );
        });
        assert!(!cache.reuse.is_content(), "the stop is sticky");
        // Per-miss consumers are not part of the seed allowance.
        let state = cache.for_materialized_procedure(
            &fixture.workspace,
            &fixture.file,
            fixture.native.clone(),
            &handles[0],
            Some(&live),
        );
        assert!(state_is_cross_owner_content(&state));
    }

    #[test]
    #[hardwon(
        "#14156: a distinct selected allocation was refused for the whole file or admitted for free"
    )]
    fn a_selected_admission_refusal_stops_only_its_scope() {
        let fixture = SeedFixture::new();
        let native_handles = SeedFixture::handles(&fixture.native);
        let selected_handles = SeedFixture::handles(&fixture.other_native);
        assert!(
            !Arc::ptr_eq(selected_handles[0].artifact(), native_handles[0].artifact()),
            "the second analyzer's artifact is a distinct allocation of the same key"
        );
        let live = CancellationToken::default();
        let mut cache = FlowStateTraversalCache::default();
        // Leave room for exactly the native census.
        let prime = |limits: &SemanticWork, census: &SemanticWork| limits.saturating_sub(*census);
        prime_seed_operation(&mut cache, &fixture, prime);
        let refused = cache
            .for_seed_procedure(
                &fixture.workspace,
                &fixture.file,
                fixture.native.clone(),
                &selected_handles[0],
                Some(&live),
            )
            .expect_err("the distinct selected allocation does not fit");
        with_entry(&mut cache, &fixture, |entry| {
            assert_eq!(
                entry.expect("entry").seed.as_ref().expect("op").admission,
                SeedAdmission::Admitted,
                "the native census itself was admitted"
            );
        });
        let spent = consumption(&mut cache, &fixture);
        assert_eq!(
            cache
                .for_seed_procedure(
                    &fixture.workspace,
                    &fixture.file,
                    fixture.native.clone(),
                    &selected_handles[0],
                    Some(&live),
                )
                .expect_err("replayed"),
            refused
        );
        assert_eq!(consumption(&mut cache, &fixture), spent);
        // Another scope selecting the native allocation itself is not touched by
        // the refused alternate. The priming above fills the allowance up to the
        // native census, so a real later derivation may legitimately stop under
        // that artificial pressure. Prove the refused alternate and its
        // retained refusal change nothing by comparing with an independently
        // primed operation that never attempted the alternate: same limits and
        // allowance, same facts, verdict, completeness and ledger deltas.
        let state = cache
            .for_seed_procedure(
                &fixture.workspace,
                &fixture.file,
                fixture.native.clone(),
                &native_handles[1],
                Some(&live),
            )
            .expect("an already admitted allocation costs nothing more");
        let mut control = FlowStateTraversalCache::default();
        prime_seed_operation(&mut control, &fixture, prime);
        let control_before = consumption(&mut control, &fixture);
        let expected = seed_with(&mut control, &fixture, &native_handles[1], &live)
            .expect("the matched native scope is admitted");
        assert_eq!(
            state.reuse_verdict(),
            expected.reuse_verdict(),
            "{state:?} vs {expected:?}"
        );
        assert_eq!(
            state_is_cross_owner_content(&state),
            state_is_cross_owner_content(&expected)
        );
        assert_eq!(state.completeness, expected.completeness);
        let ([actual], [expected]) = (state.procedures.as_slice(), expected.procedures.as_slice())
        else {
            panic!("one derived procedure per native scope");
        };
        assert_eq!(actual.completeness, expected.completeness);
        assert_eq!(actual.events, expected.events);
        assert_eq!(actual.relations, expected.relations);
        let mut actual_work = consumption(&mut cache, &fixture);
        let mut expected_work = consumption(&mut control, &fixture);
        actual_work.semantic_refusals -= spent.semantic_refusals;
        expected_work.semantic_refusals -= control_before.semantic_refusals;
        assert_eq!(
            actual_work, expected_work,
            "the refused alternate changed the later scope's work"
        );
        assert_eq!(
            seed_with(&mut cache, &fixture, &selected_handles[0], &live)
                .expect_err("the alternate refusal remains retained"),
            refused
        );
    }

    fn seed_charging<'a>(
        cache: &mut FlowStateTraversalCache<'a>,
        fixture: &'a SeedFixture,
        handle: &ProcedureHandle,
        token: &CancellationToken,
        panic: bool,
    ) -> std::thread::Result<Result<Arc<FileFlowState>, SemanticBudgetExceeded>> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            cache.seed_scope(
                &fixture.workspace,
                &fixture.file,
                fixture.native.clone(),
                handle,
                Some(token),
                |outcome, budget, request, provider| {
                    let state = flow_state_for_materialized_procedure_with_provider(
                        &fixture.workspace,
                        &fixture.file,
                        outcome,
                        handle,
                        request,
                        budget,
                        provider,
                    );
                    budget
                        .admit(SemanticWork {
                            events: 1,
                            ..SemanticWork::default()
                        })
                        .expect("the injected charge fits");
                    assert!(!panic, "injected panic after charging the ledgers");
                    state
                },
            )
        }))
    }

    #[test]
    #[hardwon("#14156: unwinding out of a seed derivation refunded or dropped the file operation")]
    fn unwinding_seed_derivation_restores_the_same_spent_operation() {
        let fixture = SeedFixture::new();
        let handles = SeedFixture::handles(&fixture.native);
        let live = CancellationToken::default();
        let mut control = FlowStateTraversalCache::default();
        seed_charging(&mut control, &fixture, &handles[0], &live, false)
            .expect("no panic")
            .expect("admitted");
        let expected = consumption(&mut control, &fixture);

        let mut cache = FlowStateTraversalCache::default();
        assert!(seed_charging(&mut cache, &fixture, &handles[0], &live, true).is_err());
        assert_eq!(
            consumption(&mut cache, &fixture),
            expected,
            "the same spent operation came back, not a default grant"
        );
        // The operation is back in its entry and keeps serving seeds.
        cache
            .for_seed_procedure(
                &fixture.workspace,
                &fixture.file,
                fixture.native.clone(),
                &handles[1],
                Some(&live),
            )
            .expect("admitted");
        assert!(consumption(&mut cache, &fixture) != expected);
    }

    #[test]
    #[hardwon(
        "#14156: a legacy File derivation disturbed the seed grant, or a native change did not replace it"
    )]
    fn legacy_file_derivations_keep_the_operation_and_native_changes_replace_it() {
        let fixture = SeedFixture::new();
        let native_handles = SeedFixture::handles(&fixture.native);
        let other_handles = SeedFixture::handles(&fixture.other_native);
        let live = CancellationToken::default();

        // File-before-Procedure initially has no native operation anchor. Adding
        // that anchor must preserve the exact paid File result for a later hit.
        let mut reverse = FlowStateTraversalCache::default();
        let file_state = reverse.for_materialized_file(
            &fixture.workspace,
            &fixture.file,
            fixture.native.clone(),
            Some(&live),
        );
        with_entry(&mut reverse, &fixture, |entry| {
            let entry = entry.expect("the File derivation populated the entry");
            assert!(entry.native.is_none());
            assert!(entry.seed.is_none());
        });
        reverse
            .for_seed_procedure(
                &fixture.workspace,
                &fixture.file,
                fixture.native.clone(),
                &native_handles[0],
                Some(&live),
            )
            .expect("admitted after the File derivation");
        let after_seed = consumption(&mut reverse, &fixture);
        with_entry(&mut reverse, &fixture, |entry| {
            assert!(Arc::ptr_eq(
                entry
                    .expect("the entry survives anchoring")
                    .native
                    .as_ref()
                    .expect("anchored"),
                fixture.native.available_value().expect("native"),
            ));
        });
        let file_hit = reverse.for_materialized_file(
            &fixture.workspace,
            &fixture.file,
            fixture.native.clone(),
            Some(&live),
        );
        assert!(
            Arc::ptr_eq(&file_state, &file_hit),
            "anchoring the seed operation preserves the paid File result"
        );
        assert_eq!(
            consumption(&mut reverse, &fixture),
            after_seed,
            "the File hit leaves every seed ledger unchanged"
        );

        let mut cache = FlowStateTraversalCache::default();
        cache
            .for_seed_procedure(
                &fixture.workspace,
                &fixture.file,
                fixture.native.clone(),
                &native_handles[0],
                Some(&live),
            )
            .expect("admitted");
        let before = consumption(&mut cache, &fixture);

        // File-after-Procedure keeps its own fresh grant and leaves the seed one alone.
        cache.for_materialized_file(
            &fixture.workspace,
            &fixture.file,
            fixture.native.clone(),
            Some(&live),
        );
        assert_eq!(consumption(&mut cache, &fixture), before);

        // A different native allocation replaces the whole entry.
        let other_native_artifact = fixture.other_native.available_value().expect("native");
        cache
            .for_seed_procedure(
                &fixture.other_workspace,
                &fixture.file,
                fixture.other_native.clone(),
                &other_handles[0],
                Some(&live),
            )
            .expect("admitted");
        with_entry(&mut cache, &fixture, |entry| {
            let entry = entry.expect("entry");
            assert!(Arc::ptr_eq(
                entry.native.as_ref().expect("anchored"),
                other_native_artifact,
            ));
            assert_eq!(entry.scopes.len(), 1);
        });
    }

    const SCALING_CARGO: &str =
        "[package]\nname = \"scaling\"\nversion = \"0.1.0\"\nedition = \"2021\"\n";
    const SCALING_SELECTED: &str =
        "pub fn selected(input: i32) -> i32 {\n    let value = input;\n    value\n}\n";

    /// `count` unrelated Drop-bearing procedures under `prefix`.
    fn scaling_siblings(prefix: &str, count: usize) -> String {
        let mut source = format!(
            "pub struct {prefix}Guard(i32);\nimpl Drop for {prefix}Guard {{\n    fn drop(&mut self) {{}}\n}}\n"
        );
        for index in 0..count {
            source.push_str(&format!(
                "pub fn {prefix}sibling_{index}(input: i32) -> i32 {{\n    let guard = {prefix}Guard(input);\n    let value = guard.0;\n    value\n}}\n"
            ));
        }
        source
    }

    /// Everything the control compares, owned so it outlives the project.
    struct ScalingRun {
        derived_procedures: usize,
        event_sites: Vec<(usize, usize)>,
        relation_count: usize,
        completeness: FlowStateCompleteness,
        ordinary_cfg: FlowStateOperationConsumption,
        /// File-wide materialization census of the selected body's file.
        census: SemanticWork,
        /// Procedures a whole-file derivation of the same file produces.
        whole_file_procedures: usize,
    }

    /// The selected body is always the first function of `src/lib.rs`, so its
    /// source offsets are identical in every variant. `other_siblings` lives
    /// in a separate file declared at the end of `lib.rs`.
    fn scaling_run(lib_siblings: usize, other_siblings: usize) -> ScalingRun {
        let lib = format!(
            "{SCALING_SELECTED}{}mod other;\n",
            scaling_siblings("Lib", lib_siblings)
        );
        let other = scaling_siblings("Other", other_siblings);
        let project = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", SCALING_CARGO)
            .file("src/lib.rs", lib)
            .file("src/other.rs", other)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let file = project.file("src/lib.rs");
        let cancellation = CancellationToken::default();
        let native = workspace
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut SemanticBudget::default(), &cancellation),
            )
            .expect("Rust artifact materialization");
        let artifact = native
            .available_value()
            .expect("Rust artifact is available");
        let mut selected = artifact.procedures().iter().filter(|procedure| {
            procedure.locator().declaration().last_segment_name() == Some("selected")
        });
        let id = selected
            .next()
            .expect("the fixed body has a procedure")
            .id();
        assert!(
            selected.next().is_none(),
            "the fixed body has one procedure"
        );
        let handle = artifact
            .procedure_handle(id)
            .expect("the artifact owns its procedures");

        let mut cache = FlowStateTraversalCache::default();
        let state = cache
            .for_seed_procedure(&workspace, &file, native.clone(), &handle, None)
            .expect("the native census is admitted under the default budget");
        let derivation = state.procedures.first().expect("the selected derivation");
        assert_eq!(derivation.procedure, handle.id());
        let analyzer = workspace.analyzer();
        let key = cache.file_key(analyzer, &file, &native);
        let ordinary_cfg = cache.files.read(&memo_attribution(analyzer), |files| {
            files[&key]
                .seed
                .as_ref()
                .expect("a retained seed")
                .operation
                .as_ref()
                .expect("its operation")
                .consumption()
        });
        assert_eq!(
            (
                ordinary_cfg.cfg_refusals,
                ordinary_cfg.nonreturn_cfg_refusals,
                ordinary_cfg.semantic_refusals
            ),
            (0, 0, 0),
        );
        let mut whole_cache = FlowStateTraversalCache::default();
        let whole = whole_cache.for_materialized_file(&workspace, &file, native.clone(), None);
        ScalingRun {
            derived_procedures: state.procedures.len(),
            event_sites: derivation
                .events
                .iter()
                .map(|event| (event.site.range.start_byte, event.site.range.end_byte))
                .collect(),
            relation_count: derivation.relations.len(),
            completeness: derivation.completeness.clone(),
            ordinary_cfg,
            census: artifact.work(),
            whole_file_procedures: whole.procedures.len(),
        }
    }

    fn assert_selected_work_eq(run: &ScalingRun, base: &ScalingRun) {
        assert_eq!(run.derived_procedures, 1);
        assert_eq!(run.event_sites, base.event_sites);
        assert_eq!(run.relation_count, base.relation_count);
        assert_eq!(run.completeness, base.completeness);
        assert_eq!(run.ordinary_cfg.cfg_used, base.ordinary_cfg.cfg_used);
        assert_eq!(
            run.ordinary_cfg.nonreturn_cfg_used,
            base.ordinary_cfg.nonreturn_cfg_used
        );
    }

    #[test]
    #[hardwon("#14156: procedure-seeded flow derived unrelated siblings")]
    fn a_selected_seed_does_not_scale_with_unrelated_siblings() {
        let base = scaling_run(8, 1);
        assert_eq!(base.derived_procedures, 1, "only the selected body derives");
        assert!(
            base.whole_file_procedures > base.derived_procedures,
            "the whole-file derivation covers the siblings the seed does not"
        );

        let mut previous = (base.census.procedures, base.whole_file_procedures);
        for siblings in [16, 32] {
            let run = scaling_run(siblings, 1);
            assert_selected_work_eq(&run, &base);
            // The file-wide census and whole-file derivation DO grow, which is
            // what makes this control distinguish whole-file work.
            assert!(
                run.census.procedures > previous.0,
                "the materialization census covers the whole file: {} vs {}",
                run.census.procedures,
                previous.0
            );
            assert!(run.whole_file_procedures > previous.1);
            previous = (run.census.procedures, run.whole_file_procedures);
        }

        // A sibling in a SEPARATE file changes neither the selected body's file
        // census nor its derivation work.
        let separate = scaling_run(8, 32);
        assert_selected_work_eq(&separate, &base);
        assert_eq!(separate.census, base.census);
        assert_eq!(separate.whole_file_procedures, base.whole_file_procedures);
    }
}
