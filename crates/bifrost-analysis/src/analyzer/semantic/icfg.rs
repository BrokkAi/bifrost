//! Demand-materialized, language-neutral interprocedural control flow.
//!
//! Callable CFGs remain immutable and procedure-local. This module stitches a
//! bounded, generation-local view on demand and never builds an eager
//! whole-workspace graph.

use crate::analyzer::languages::language_support_for_hook;

use crate::analyzer::read_ledger::LookupKind;
use crate::analyzer::read_ledger::ReadKey;

use crate::analyzer::semantic::completeness_reason_bytes;

use crate::analyzer::semantic::workspace_oracle::PreparedWorkspaceDispatchSession;
use crate::analyzer::semantic::workspace_oracle::WorkspaceSemanticOracle;
use crate::analyzer::semantic::workspace_oracle::exact_source_for_procedure;
use crate::analyzer::semantic::workspace_oracle::semantic_locator_work;

use crate::analyzer::semantic::AccessPathAtPoint;
use crate::analyzer::semantic::AliasQuery;
use crate::analyzer::semantic::AliasResult;
use crate::analyzer::semantic::CallContinuationKind;
use crate::analyzer::semantic::CallInvocationMode;
use crate::analyzer::semantic::CallSiteHandle;
use crate::analyzer::semantic::CallSiteId;
use crate::analyzer::semantic::CandidateCoverage;
use crate::analyzer::semantic::ControlContinuation;
use crate::analyzer::semantic::DeferredInvocationKind;
use crate::analyzer::semantic::DispatchBoundary;
use crate::analyzer::semantic::DispatchBoundaryKind;
use crate::analyzer::semantic::DispatchHints;
use crate::analyzer::semantic::DispatchOracle;
use crate::analyzer::semantic::DispatchResult;
use crate::analyzer::semantic::EvidenceCompleteness;
use crate::analyzer::semantic::FreshObjectPublicationQuery;
use crate::analyzer::semantic::FreshObjectPublicationResult;
use crate::analyzer::semantic::HeapOracle;
use crate::analyzer::semantic::LengthDelimitedDigest;
use crate::analyzer::semantic::LocationResult;
use crate::analyzer::semantic::OracleCallContext;
use crate::analyzer::semantic::OracleLimits;
use crate::analyzer::semantic::PointsToResult;
use crate::analyzer::semantic::ProcedureHandle;
use crate::analyzer::semantic::ProcedureInvocationKind;
use crate::analyzer::semantic::ProgramPointHandle;
use crate::analyzer::semantic::ProgramPointId;
use crate::analyzer::semantic::ProofStatus;
use crate::analyzer::semantic::SemanticBudgetExceeded;
use crate::analyzer::semantic::SemanticCallSite;
use crate::analyzer::semantic::SemanticCapability;
use crate::analyzer::semantic::SemanticGap;
use crate::analyzer::semantic::SemanticGapDischarge;
use crate::analyzer::semantic::SemanticOutcome;
use crate::analyzer::semantic::SemanticProviderError;
use crate::analyzer::semantic::SemanticRequest;
use crate::analyzer::semantic::SemanticWork;
use crate::analyzer::semantic::StableDigest;
use crate::analyzer::semantic::StoreAtPoint;
use crate::analyzer::semantic::UpdateEligibility;
use crate::analyzer::semantic::ValueAtPoint;

use crate::analyzer::semantic_model::ActiveSemanticModelSnapshot;
use crate::analyzer::semantic_model::ProcedureSummaryMemberKey;

use crate::analyzer::DispatchHierarchyExpansion;
use crate::analyzer::Language;
use crate::analyzer::WorkspaceAnalyzer;

use crate::hash::HashMap;
use crate::hash::HashSet;

pub use brokk_bifrost_semantic::analyzer::semantic::icfg::*;

use std::collections::VecDeque;

use std::fmt;

use std::sync::Arc;
use std::sync::Mutex;

/// Build the canonical read attribution for one handle-keyed dispatch answer.
///
/// Both the ICFG provider's request ledger and cached value-flow discovery use
/// this function. A cache hit must record the same input as the cold oracle
/// call that populated it, rather than disappearing from a later procedure
/// summary's read set.
pub fn dispatch_read_attribution(
    call: &CallSiteHandle,
    outcome: &SemanticOutcome<DispatchResult>,
) -> DispatchReadAttribution {
    dispatch_read_attribution_with_range(
        call,
        outcome,
        crate::analyzer::semantic::workspace_oracle::exact_call_range(call),
    )
}

pub fn record_dispatch_read(
    workspace: &WorkspaceAnalyzer,
    call: &CallSiteHandle,
    outcome: &SemanticOutcome<DispatchResult>,
) {
    let attribution = dispatch_read_attribution(call, outcome);
    record_dispatch_read_attribution(workspace, &attribution);
}

pub(crate) fn record_dispatch_read_attribution(
    workspace: &WorkspaceAnalyzer,
    attribution: &DispatchReadAttribution,
) {
    let analyzer = workspace.analyzer();
    if !crate::analyzer::read_attribution_records_reads(|| analyzer.read_ledger_attached()) {
        return;
    }
    match attribution {
        DispatchReadAttribution::Attributed(key) => analyzer.record_read(key.clone()),
        DispatchReadAttribution::Unattributed(_) => analyzer.record_unattributed_read(),
    }
}

#[doc(hidden)]
pub fn dispatch_read_attribution_with_range(
    call: &CallSiteHandle,
    outcome: &SemanticOutcome<DispatchResult>,
    range: Result<crate::analyzer::Range, SemanticProviderError>,
) -> DispatchReadAttribution {
    let Some(question) = range.ok().and_then(|range| {
        crate::analyzer::semantic::workspace_oracle::procedure_dispatch_question(call, range)
    }) else {
        return DispatchReadAttribution::Unattributed(
            DispatchReadUnattributedReason::SourceRangeUnavailable,
        );
    };
    DispatchReadAttribution::Attributed(ReadKey::lookup(
        LookupKind::ProcedureDispatch,
        question,
        crate::analyzer::semantic::workspace_oracle::one_call_dispatch_answer_digest(call, outcome),
    ))
}

/// Stable identity of every input that can change one provider's ICFG topology.
///
/// Providers whose behavior varies independently of their semantic artifacts
/// must override [`IcfgProvider::behavior_identity`]. The default preserves one
/// conservative identity for stateless providers and existing test fakes.
/// `read` is the same identity with the workspace's content identity left out,
/// for a record that must compare across two checkouts of the same content.
/// Everything else the digest folds -- the active model set, the semantic-model
/// overlay's presence, the dispatch hierarchy expansion -- is an engine input a
/// reader states independently, while the content identity rotates on every
/// edit anywhere in the workspace. A record keyed by the full digest could
/// therefore never be verified after any edit, however unrelated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IcfgProviderBehaviorIdentity {
    #[doc(hidden)]
    pub digest: StableDigest,
    read: StableDigest,
}

impl IcfgProviderBehaviorIdentity {
    /// One provider identity named by its own bytes.
    ///
    /// Both halves are the same digest: a provider that states its behavior as
    /// a fixed name folds no workspace content, so there is nothing to leave
    /// out.
    pub fn hash_bytes(bytes: impl AsRef<[u8]>) -> Self {
        let digest = StableDigest::sha256(bytes);
        Self {
            digest,
            read: digest,
        }
    }

    pub const fn digest(self) -> StableDigest {
        self.digest
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.digest.as_bytes()
    }

    /// This identity without the workspace's content identity.
    pub const fn read_digest(self) -> StableDigest {
        self.read
    }

    pub const fn read_bytes(&self) -> &[u8; 32] {
        self.read.as_bytes()
    }

    fn workspace(
        workspace: &WorkspaceAnalyzer,
        hierarchy_expansion: DispatchHierarchyExpansion,
        snapshot: Option<&ActiveSemanticModelSnapshot>,
        dispatch_hints: StableDigest,
        python_saved_default_safety: Option<StableDigest>,
        limits: OracleLimits,
    ) -> Self {
        let mut digest = LengthDelimitedDigest::new(WORKSPACE_ICFG_PROVIDER_BEHAVIOR_DOMAIN);
        let mut read = LengthDelimitedDigest::new(WORKSPACE_ICFG_PROVIDER_READ_BEHAVIOR_DOMAIN);
        // Every engine input except the workspace's own content identity, into
        // both halves: each of these is something a reader of a recorded read
        // states for itself, and none of them moves because an unrelated file
        // was edited.
        let push_engine_inputs = |digest: &mut LengthDelimitedDigest| {
            match snapshot {
                Some(snapshot) => {
                    digest.push(b"active-semantic-model-set");
                    digest.push(snapshot.active_models().active_model_set_hash().as_bytes());
                    if snapshot.semantic_model_overlay().is_some() {
                        digest.push(b"semantic-model-overlay-present");
                    } else {
                        digest.push(b"semantic-model-overlay-absent");
                    }
                }
                None => digest.push(b"no-active-semantic-model-set"),
            }
            digest.push(b"dispatch-hierarchy-expansion");
            digest.push(if hierarchy_expansion.concrete_overrides {
                b"concrete-overrides"
            } else {
                b"off"
            });
            match workspace.analyzer().external_dispatch_behavior_identity() {
                Some(identity) => {
                    digest.push(b"external-dispatch-surface");
                    digest.push(identity.as_bytes());
                }
                None => digest.push(b"no-external-dispatch-surface"),
            }
            digest.push(b"oracle-limits");
            let values = limits.values();
            for value in [
                values.dispatch_targets,
                values.objects_per_value,
                values.access_path_length,
                values.alias_breadth,
                values.source_observations,
                values.call_context_depth,
                values.summary_depth,
                values.call_binding_entries,
                values.provenance_records,
                values.evidence_handles,
            ] {
                digest.push(&(value as u64).to_le_bytes());
            }
            digest.push(b"receiver-class-dispatch-hints");
            digest.push(dispatch_hints.as_bytes());
            // Saved defaults depend on callable-scoped metadata mutation
            // evidence, not only on the callee file. Include its complete
            // bounded-scan fingerprint in both replay identity halves.
            if language_support_for_hook(Language::Python, "forward_query_provider")
                .and_then(|support| support.forward_query_provider(workspace.analyzer()))
                .is_some()
            {
                digest.push(b"python-saved-default-safety");
                match python_saved_default_safety {
                    Some(fingerprint) => {
                        digest.push(b"complete");
                        digest.push(fingerprint.as_bytes());
                    }
                    None => digest.push(b"incomplete"),
                }
            }
        };
        push_engine_inputs(&mut digest);
        push_engine_inputs(&mut read);
        // Dispatch can materialize any compatible declaration in the analyzer,
        // not only procedures from the root artifact. Bind the exact analyzed
        // file-set, language composition, epochs, and configuration through
        // their stable content identity. A pointer or generation would prevent
        // valid reuse across equivalent analyzer snapshots without proving the
        // target universes equal.
        //
        // The read half deliberately stops here: it names the same engine,
        // and which files that engine has is what a read set's own `File` and
        // `Artifact` keys state exactly.
        match workspace.analyzer().workspace_content_identity() {
            Some(identity) => {
                digest.push(b"workspace-dispatch-universe");
                digest.push(identity.digest().as_bytes());
            }
            None => {
                // Every production language analyzer publishes a content
                // identity. Only a workspace with no language delegates has a
                // genuinely empty dispatch universe that is safe to name with
                // one shared marker.
                assert!(
                    workspace.analyzer().languages().is_empty(),
                    "a nonempty workspace analyzer must state a content identity for ICFG caching"
                );
                digest.push(b"empty-workspace-dispatch-universe");
            }
        }
        Self {
            digest: digest.finish(),
            read: read.finish(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallBoundary {
    pub origin: CallSiteHandle,
    pub dispatch: DispatchBoundary,
    pub model: CallToReturnModel,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallTransferSet {
    pub transfers: Box<[CallTransfer]>,
    pub boundaries: Box<[CallBoundary]>,
    pub coverage: CandidateCoverage,
}

pub trait IcfgProvider: DispatchOracle {
    /// Stable identity of provider state that can change emitted topology.
    fn behavior_identity(&self) -> IcfgProviderBehaviorIdentity {
        IcfgProviderBehaviorIdentity::hash_bytes(DEFAULT_ICFG_PROVIDER_BEHAVIOR_DOMAIN)
    }

    fn call_transfers(
        &self,
        caller: &ProcedureHandle,
        call: CallSiteId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<CallTransferSet>, SemanticProviderError>;

    /// Resolve one call under the bounded active caller suffix. Providers that
    /// have no contextual implementation retain their ordinary conservative answer.
    fn call_transfers_in_context(
        &self,
        caller: &ProcedureHandle,
        call: CallSiteId,
        _context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<CallTransferSet>, SemanticProviderError> {
        self.call_transfers(caller, call, request)
    }

    fn snapshot(
        &self,
        root: &ProcedureHandle,
        limits: IcfgSnapshotLimits,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<IcfgSnapshot>, SemanticProviderError>;

    /// Materialize callee-local evidence from one procedure entry to one exit.
    ///
    /// Callers should cache the outcome query-locally by procedure, entry, and
    /// exit. A cache miss owns the bounded forward/reverse topology scan;
    /// replaying the returned profile for additional callers or facts owns no
    /// semantic work.
    fn exit_profile(
        &self,
        callee_entry: &ProgramPointHandle,
        callee_exit: &ProgramPointHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<IcfgExitProfile>, SemanticProviderError> {
        materialize_exit_profile(callee_entry, callee_exit, request)
    }
}

/// One provider is tied to one [`WorkspaceAnalyzer`] generation.
#[derive(Clone)]
pub struct WorkspaceIcfgProvider<'a> {
    #[doc(hidden)]
    pub oracle: WorkspaceSemanticOracle<'a>,
    active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    behavior_identity: IcfgProviderBehaviorIdentity,
    #[doc(hidden)]
    pub outcome_cache: Arc<QueryLocalIcfgOutcomeCache<'a>>,
}

#[derive(Clone)]
#[doc(hidden)]
pub struct CachedCallTransferOutcome {
    outcome: SemanticOutcome<CallTransferSet>,
    dispatch_read: DispatchReadAttribution,
}

#[doc(hidden)]
pub struct QueryLocalIcfgOutcomeCache<'a> {
    parent: Option<Arc<QueryLocalIcfgOutcomeCache<'a>>>,
    #[doc(hidden)]
    pub call_transfers: Mutex<HashMap<CallTransferCacheKey, CachedCallTransferOutcome>>,
    #[doc(hidden)]
    pub exit_profiles: Mutex<HashMap<ExitProfileCacheKey, SemanticOutcome<IcfgExitProfile>>>,
    #[doc(hidden)]
    pub dispatch_sessions:
        Mutex<HashMap<ExactArtifactAllocation, Arc<Mutex<PreparedWorkspaceDispatchSession<'a>>>>>,
}

impl Default for QueryLocalIcfgOutcomeCache<'_> {
    fn default() -> Self {
        Self {
            parent: None,
            call_transfers: Mutex::new(HashMap::default()),
            exit_profiles: Mutex::new(HashMap::default()),
            dispatch_sessions: Mutex::new(HashMap::default()),
        }
    }
}

impl<'a> QueryLocalIcfgOutcomeCache<'a> {
    /// Add a snapshot-private write layer over already-published provider work.
    ///
    /// Reads may reuse complete outcomes and paid source sessions from the
    /// parent. New outcomes and source parses remain private to this overlay
    /// until the snapshot's outer semantic-budget charge commits. Keeping only
    /// local writes also makes snapshot creation independent of accumulated
    /// query size.
    fn snapshot_overlay(parent: Arc<Self>) -> Self {
        Self {
            parent: Some(parent),
            call_transfers: Mutex::new(HashMap::default()),
            exit_profiles: Mutex::new(HashMap::default()),
            dispatch_sessions: Mutex::new(HashMap::default()),
        }
    }

    fn call_transfer(&self, key: &CallTransferCacheKey) -> Option<CachedCallTransferOutcome> {
        let local = self
            .call_transfers
            .lock()
            .expect("query-local ICFG call-transfer cache mutex is not poisoned")
            .get(key)
            .cloned();
        local.or_else(|| {
            self.parent
                .as_deref()
                .and_then(|parent| parent.call_transfer(key))
        })
    }

    fn exit_profile(&self, key: &ExitProfileCacheKey) -> Option<SemanticOutcome<IcfgExitProfile>> {
        let local = self
            .exit_profiles
            .lock()
            .expect("query-local ICFG exit-profile cache mutex is not poisoned")
            .get(key)
            .cloned();
        local.or_else(|| {
            self.parent
                .as_deref()
                .and_then(|parent| parent.exit_profile(key))
        })
    }

    fn paid_dispatch_session(
        &self,
        key: &ExactArtifactAllocation,
    ) -> Option<Arc<Mutex<PreparedWorkspaceDispatchSession<'a>>>> {
        let local = self
            .dispatch_sessions
            .lock()
            .expect("query-local ICFG dispatch-session mutex is not poisoned")
            .get(key)
            .cloned();
        if local.as_ref().is_some_and(|session| {
            session
                .lock()
                .expect("query-local exact-artifact dispatch session is not poisoned")
                .retains_exact_source()
        }) {
            return local;
        }
        self.parent
            .as_deref()
            .and_then(|parent| parent.paid_dispatch_session(key))
    }

    /// Publish work from a snapshot whose enclosing budget has committed.
    ///
    /// Concurrent provider users may have won any same-key race while the
    /// snapshot ran. Keep their already-published values and discard the
    /// duplicate, paid snapshot result in that case.
    fn publish_snapshot(self: &Arc<Self>, snapshot: &Self) {
        debug_assert!(
            snapshot
                .parent
                .as_ref()
                .is_some_and(|parent| Arc::ptr_eq(parent, self)),
            "snapshot overlay must publish to its direct parent"
        );
        let snapshot_transfers = std::mem::take(
            &mut *snapshot
                .call_transfers
                .lock()
                .expect("snapshot ICFG call-transfer cache mutex is not poisoned"),
        );
        let mut call_transfers = self
            .call_transfers
            .lock()
            .expect("query-local ICFG call-transfer cache mutex is not poisoned");
        for (key, outcome) in snapshot_transfers {
            call_transfers.entry(key).or_insert(outcome);
        }
        drop(call_transfers);

        let snapshot_profiles = std::mem::take(
            &mut *snapshot
                .exit_profiles
                .lock()
                .expect("snapshot ICFG exit-profile cache mutex is not poisoned"),
        );
        let mut exit_profiles = self
            .exit_profiles
            .lock()
            .expect("query-local ICFG exit-profile cache mutex is not poisoned");
        for (key, outcome) in snapshot_profiles {
            exit_profiles.entry(key).or_insert(outcome);
        }
        drop(exit_profiles);

        let snapshot_sessions = std::mem::take(
            &mut *snapshot
                .dispatch_sessions
                .lock()
                .expect("snapshot ICFG dispatch-session mutex is not poisoned"),
        );
        let mut dispatch_sessions = self
            .dispatch_sessions
            .lock()
            .expect("query-local ICFG dispatch-session mutex is not poisoned");
        for (key, session) in snapshot_sessions {
            if session
                .lock()
                .expect("snapshot exact-artifact dispatch session is not poisoned")
                .retains_exact_source()
            {
                match dispatch_sessions.entry(key) {
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert(session);
                    }
                    std::collections::hash_map::Entry::Occupied(mut entry) => {
                        let already_paid = entry
                            .get()
                            .lock()
                            .expect("published dispatch session is not poisoned")
                            .retains_exact_source();
                        if !already_paid {
                            entry.insert(session);
                        }
                    }
                }
            }
        }
    }
}

impl<'a> WorkspaceIcfgProvider<'a> {
    /// Artifact pin unions per outcome map; overlapping maps must not be added.
    #[doc(hidden)]
    pub fn cached_artifact_bytes(&self) -> (u64, u64, u64) {
        let mut transfers = crate::analyzer::semantic::service::ArtifactRetentionCensus::default();
        let mut profiles = crate::analyzer::semantic::service::ArtifactRetentionCensus::default();
        let mut sessions = crate::analyzer::semantic::service::ArtifactRetentionCensus::default();
        let mut current = Some(self.outcome_cache.as_ref());
        while let Some(cache) = current {
            for (key, cached) in cache
                .call_transfers
                .lock()
                .expect("ICFG transfer cache lock")
                .iter()
            {
                transfers.procedure(&key.0);
                transfers.context(&key.2);
                if let Some(outcome) = cached.outcome.available_value() {
                    for transfer in &outcome.transfers {
                        transfers.procedure(transfer.origin.procedure());
                        transfers.procedure(&transfer.callee);
                        transfers.procedure(transfer.callee_entry.procedure());
                        if let Some(argument) = &transfer.argument_callable {
                            argument.retained_artifacts(&mut transfers);
                        }
                    }
                    for boundary in &outcome.boundaries {
                        transfers.procedure(boundary.origin.procedure());
                        for relation in boundary.dispatch.provenance.iter() {
                            relation.retained_artifacts(&mut transfers);
                        }
                    }
                }
            }
            for key in cache
                .exit_profiles
                .lock()
                .expect("ICFG profile cache lock")
                .keys()
            {
                profiles.procedure(key.0.procedure());
                profiles.procedure(key.1.procedure());
            }
            for key in cache
                .dispatch_sessions
                .lock()
                .expect("ICFG session cache lock")
                .keys()
            {
                sessions.artifact(&key.0);
            }
            current = cache.parent.as_deref();
        }
        (
            transfers.artifact_bytes(),
            profiles.artifact_bytes(),
            sessions.artifact_bytes(),
        )
    }

    /// Bind dispatch and capture proof to explicit limits, also retained in
    /// the provider's behavior and recorded-read identities.
    pub fn with_oracle_limits(workspace: &'a WorkspaceAnalyzer, limits: OracleLimits) -> Self {
        Self::from_oracle(WorkspaceSemanticOracle::with_limits(workspace, limits))
    }

    pub fn new(workspace: &'a WorkspaceAnalyzer) -> Self {
        Self::with_active_semantic_model_snapshot(
            workspace,
            workspace.analyzer().active_semantic_model_snapshot(),
        )
    }

    /// Bind this provider to an active-model snapshot already captured by its
    /// request owner.
    ///
    /// This keeps several semantic consumers in one request on one model
    /// identity even if a later activation publishes a new analyzer overlay.
    pub fn with_active_semantic_model_snapshot(
        workspace: &'a WorkspaceAnalyzer,
        snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    ) -> Self {
        Self::with_active_semantic_model_snapshot_and_hints(
            workspace,
            snapshot,
            DispatchHints::empty(),
        )
    }

    /// Bind this provider to one captured active-model snapshot and one
    /// immutable receiver-class dispatch overlay.
    pub fn with_active_semantic_model_snapshot_and_hints(
        workspace: &'a WorkspaceAnalyzer,
        snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
        dispatch_hints: DispatchHints,
    ) -> Self {
        let oracle = WorkspaceSemanticOracle::with_dispatch_hints(
            workspace,
            snapshot.clone(),
            dispatch_hints,
        );
        Self::from_oracle(oracle)
    }

    fn from_oracle(oracle: WorkspaceSemanticOracle<'a>) -> Self {
        let snapshot = oracle.active_semantic_model_snapshot();
        let behavior_identity = IcfgProviderBehaviorIdentity::workspace(
            oracle.workspace(),
            oracle.hierarchy_expansion(),
            snapshot.as_deref(),
            oracle.dispatch_hints().digest(),
            oracle
                .python_saved_default_safety()
                .map(|safety| safety.fingerprint()),
            *oracle.limits(),
        );
        Self {
            oracle,
            active_semantic_model_snapshot: snapshot,
            behavior_identity,
            outcome_cache: Arc::new(QueryLocalIcfgOutcomeCache::default()),
        }
    }

    pub const fn workspace(&self) -> &'a WorkspaceAnalyzer {
        self.oracle.workspace()
    }

    pub const fn oracle(&self) -> &WorkspaceSemanticOracle<'a> {
        &self.oracle
    }

    fn dispatch_session(
        &self,
        artifact: &Arc<crate::analyzer::semantic::SemanticArtifact>,
    ) -> Arc<Mutex<PreparedWorkspaceDispatchSession<'a>>> {
        let key = ExactArtifactAllocation(Arc::clone(artifact));
        if let Some(session) = self.outcome_cache.paid_dispatch_session(&key) {
            return session;
        }
        // Keep the global lock to one exact lookup. Calls in different
        // artifacts can parse concurrently; calls in this artifact serialize
        // only on their own lazy parser below.
        let mut sessions = self
            .outcome_cache
            .dispatch_sessions
            .lock()
            .expect("query-local ICFG dispatch-session mutex is not poisoned");
        Arc::clone(sessions.entry(key).or_insert_with(|| {
            Arc::new(Mutex::new(
                self.oracle
                    .prepare_call_dispatch_session(Arc::clone(artifact)),
            ))
        }))
    }

    /// Run one snapshot against a private provider-cache fork and publish it
    /// only after the snapshot's outer semantic-budget transaction commits.
    #[doc(hidden)]
    pub fn with_snapshot_transaction<T>(
        &self,
        request: &mut SemanticRequest<'_>,
        operation: impl FnOnce(
            &WorkspaceIcfgProvider<'a>,
            &mut SemanticRequest<'_>,
        ) -> Result<T, SemanticProviderError>,
    ) -> Result<T, SemanticProviderError> {
        let _scope = crate::analyzer::AnalyzerQueryScope::with_active_semantic_model_snapshot(
            self.workspace().analyzer(),
            self.active_semantic_model_snapshot.clone(),
        );
        let snapshot_cache = Arc::new(QueryLocalIcfgOutcomeCache::snapshot_overlay(Arc::clone(
            &self.outcome_cache,
        )));
        let snapshot_provider = Self {
            oracle: self.oracle.clone(),
            active_semantic_model_snapshot: self.active_semantic_model_snapshot.clone(),
            behavior_identity: self.behavior_identity,
            outcome_cache: Arc::clone(&snapshot_cache),
        };
        let mut staged_budget = request.budget.clone();
        let result = match operation(&snapshot_provider, &mut request.staged(&mut staged_budget)) {
            Ok(result) => result,
            Err(error) => {
                request.budget.retain_performed_work(&staged_budget);
                return Err(error);
            }
        };

        // Make the caller's charge durable before any newly retained provider
        // state becomes visible to clones or retries.
        *request.budget = staged_budget;
        self.outcome_cache.publish_snapshot(&snapshot_cache);
        Ok(result)
    }

    /// Record that this provider read `procedure`'s owning semantic artifact
    /// (issue: impact-sliced `--diff-base`, Milestone 5).
    ///
    /// A snapshot, a call-transfer projection and an exit profile all read the
    /// procedure, point, edge and call-site rows of one immutable artifact, and
    /// the artifact is the unit derivation publishes, so the read is named
    /// exactly as `semantic::service::materialize_with_lowerer` names it: by
    /// the artifact's public fingerprint and its workspace-relative path,
    /// never by the mount-bearing `SemanticArtifactKey`. Recording the whole
    /// artifact rather than the rows actually touched is the over-recording
    /// direction the ledger requires.
    ///
    /// A run with no ledger attached pays one relaxed load and allocates
    /// nothing.
    fn record_artifact_read(&self, procedure: &ProcedureHandle) {
        let analyzer = self.workspace().analyzer();
        if !crate::analyzer::read_attribution_records_reads(|| analyzer.read_ledger_attached()) {
            return;
        }
        let key = procedure.artifact().key();
        analyzer.record_read(ReadKey::semantic_artifact(key));
    }

    /// Record one dispatch answer this provider read.
    ///
    /// Dispatch is the channel a typestate or taint solve composes callee
    /// bodies through, so which targets a call site resolved to -- and whether
    /// that set was exhaustive -- is itself an input the solve depended on. The
    /// question names the call by stable procedure lineage and its exact range
    /// relative to that procedure. Replay uniquely resolves that address back
    /// to a handle and calls `DispatchOracle::resolve_call` directly, using the
    /// same procedure-dispatch answer domain as recording.
    ///
    /// A call site with no retained source mapping, or whose span is shared by
    /// another lowered call in the procedure, cannot be named exactly. That is
    /// a funnel crossing this provider cannot attribute, and it says so rather
    /// than staying silent.
    fn record_dispatch_read(
        &self,
        call: &CallSiteHandle,
        outcome: &SemanticOutcome<DispatchResult>,
    ) {
        record_dispatch_read(self.workspace(), call, outcome);
    }
}

impl fmt::Debug for WorkspaceIcfgProvider<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkspaceIcfgProvider")
            .finish_non_exhaustive()
    }
}

#[doc(hidden)]
pub struct SnapshotBuilder {
    limits: IcfgSnapshotLimits,
    interner: HashMap<TraversalKey, IcfgNodeId>,
    traversal: Vec<TraversalKey>,
    nodes: Vec<IcfgNodeKey>,
    edges: Vec<IcfgEdge>,
    edge_set: HashSet<IcfgEdge>,
    /// Every caller-side continuation already published, whichever projection
    /// published it. A dispatch boundary and a matched return can name the
    /// same continuation of the same call, and the two rows differ only in the
    /// boundary they carry, so plain edge deduplication would keep both.
    call_to_return_edges: HashSet<(IcfgNodeId, IcfgNodeId, IcfgEdgeKind)>,
    boundaries: Vec<IcfgBoundary>,
    queue: VecDeque<IcfgNodeId>,
    #[doc(hidden)]
    pub exit_profiles: HashMap<
        (ProcedureHandle, ProgramPointId, ProgramPointId),
        SemanticOutcome<Arc<IcfgExitProfile>>,
    >,
    quality: SnapshotQuality,
    budget_exceeded: Option<SemanticBudgetExceeded>,
    work: SemanticWork,
}

impl SnapshotBuilder {
    #[doc(hidden)]
    pub fn new(limits: IcfgSnapshotLimits) -> Self {
        Self {
            limits,
            interner: HashMap::default(),
            traversal: Vec::new(),
            nodes: Vec::new(),
            edges: Vec::new(),
            edge_set: HashSet::default(),
            call_to_return_edges: HashSet::default(),
            boundaries: Vec::new(),
            queue: VecDeque::new(),
            exit_profiles: HashMap::default(),
            quality: SnapshotQuality::Complete,
            budget_exceeded: None,
            work: SemanticWork::default(),
        }
    }

    fn intern(
        &mut self,
        key: TraversalKey,
        request: &mut SemanticRequest<'_>,
        boundary_at: Option<IcfgNodeId>,
        origin: Option<CallSiteHandle>,
    ) -> Result<Option<(IcfgNodeId, bool)>, SemanticProviderError> {
        if let Some(id) = self.interner.get(&key).copied() {
            return Ok(Some((id, false)));
        }
        if self.nodes.len() >= self.limits.max_nodes {
            self.quality = SnapshotQuality::Truncated;
            if let Some(at) = boundary_at {
                self.boundaries.push(IcfgBoundary {
                    at,
                    origin,
                    kind: IcfgBoundaryKind::Limit(IcfgLimitKind::Nodes),
                });
            }
            return Ok(None);
        }
        let work = node_work(&key);
        if let Err(exceeded) = request.budget.admit(work) {
            self.budget_exceeded = Some(exceeded);
            self.quality = SnapshotQuality::Truncated;
            return Ok(None);
        }
        self.work = self.work.conservative_add(work);
        self.publish_node(key).map(|id| Some((id, true)))
    }

    fn publish_node(&mut self, key: TraversalKey) -> Result<IcfgNodeId, SemanticProviderError> {
        let id = IcfgNodeId::try_from_index(self.nodes.len())?;
        let call_context = key
            .frames
            .iter()
            .map(|frame| frame.transfer.origin.clone())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        self.nodes.push(IcfgNodeKey {
            point: key.point.clone(),
            call_context,
            argument_callable: key
                .frames
                .iter()
                .rev()
                .find_map(|frame| frame.transfer.argument_callable.clone()),
        });
        self.traversal.push(key.clone());
        self.interner.insert(key, id);
        self.queue.push_back(id);
        Ok(id)
    }

    #[allow(clippy::too_many_arguments)]
    fn link(
        &mut self,
        source: IcfgNodeId,
        target_key: TraversalKey,
        kind: IcfgEdgeKind,
        origin: Option<CallSiteHandle>,
        proof: ProofStatus,
        completeness: EvidenceCompleteness,
        boundary: Option<DispatchBoundaryKind>,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Option<IcfgNodeId>, SemanticProviderError> {
        let existing_target = self.interner.get(&target_key).copied();
        if existing_target.is_none() && self.nodes.len() >= self.limits.max_nodes {
            self.quality = SnapshotQuality::Truncated;
            self.boundaries.push(IcfgBoundary {
                at: source,
                origin,
                kind: IcfgBoundaryKind::Limit(IcfgLimitKind::Nodes),
            });
            return Ok(None);
        }
        if self.edges.len() >= self.limits.max_edges {
            self.quality = SnapshotQuality::Truncated;
            self.boundaries.push(IcfgBoundary {
                at: source,
                origin,
                kind: IcfgBoundaryKind::Limit(IcfgLimitKind::Edges),
            });
            return Ok(None);
        }
        let node_work = existing_target.is_none().then(|| node_work(&target_key));
        let edge_work = SemanticWork {
            control_edges: 1,
            nested_entries: 1,
            ..SemanticWork::default()
        };
        let mut staged_budget = request.budget.clone();
        if let Some(work) = node_work
            && let Err(exceeded) = staged_budget.admit(work)
        {
            self.budget_exceeded = Some(exceeded);
            self.quality = SnapshotQuality::Truncated;
            return Ok(None);
        }
        if let Err(exceeded) = staged_budget.admit(edge_work) {
            self.budget_exceeded = Some(exceeded);
            self.quality = SnapshotQuality::Truncated;
            return Ok(None);
        }
        let target = match existing_target {
            Some(target) => target,
            None => self.publish_node(target_key)?,
        };
        let edge = IcfgEdge {
            source,
            target,
            kind,
            origin,
            proof,
            completeness,
            boundary,
        };
        if self.edge_set.contains(&edge) {
            // A duplicate discovered after interning cannot own a new target.
            debug_assert!(existing_target.is_some());
            return Ok(Some(target));
        }
        *request.budget = staged_budget;
        let work = node_work.map_or(edge_work, |node| node.conservative_add(edge_work));
        self.work = self.work.conservative_add(work);
        self.edge_set.insert(edge.clone());
        self.edges.push(edge);
        Ok(Some(target))
    }

    fn record_dispatch_boundaries(&mut self, at: IcfgNodeId, boundaries: &[CallBoundary]) {
        for boundary in boundaries {
            self.boundaries.push(IcfgBoundary {
                at,
                origin: Some(boundary.origin.clone()),
                kind: IcfgBoundaryKind::Dispatch(boundary.dispatch.kind.clone()),
            });
        }
    }

    fn absorb_quality<T>(&mut self, outcome: &SemanticOutcome<T>) {
        let incoming = match outcome {
            SemanticOutcome::Complete { .. } => SnapshotQuality::Complete,
            SemanticOutcome::Ambiguous { .. } => SnapshotQuality::Ambiguous,
            SemanticOutcome::Unknown { .. } => SnapshotQuality::Unknown,
            SemanticOutcome::Unsupported { capability, .. } => {
                SnapshotQuality::Unsupported(*capability)
            }
            SemanticOutcome::Unproven { .. } => SnapshotQuality::Unproven,
            SemanticOutcome::ExceededBudget { exceeded, .. } => {
                self.budget_exceeded = Some(*exceeded);
                SnapshotQuality::Truncated
            }
            SemanticOutcome::Cancelled { .. } => SnapshotQuality::Cancelled,
        };
        self.quality = merge_quality(self.quality, incoming);
    }

    fn freeze(mut self) -> Result<IcfgSnapshot, SemanticProviderError> {
        self.edges.sort_by(|left, right| {
            icfg_edge_sort_key(left)
                .cmp(&icfg_edge_sort_key(right))
                .then_with(|| left.boundary.cmp(&right.boundary))
        });
        IcfgSnapshot::try_from_parts(self.nodes, self.edges, self.boundaries)
    }
}

impl DispatchOracle for WorkspaceIcfgProvider<'_> {
    fn resolve_call(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
        // A direct dispatch request has no enclosing provider transaction in
        // which newly retained syntax can be published. Keep this path
        // one-shot; call-transfer and snapshot materialization own the cache
        // boundaries that make prepared-session reuse safe.
        let outcome = self.oracle.resolve_call(call, request)?;
        self.record_artifact_read(call.procedure());
        self.record_dispatch_read(call, &outcome);
        Ok(outcome)
    }
}

impl HeapOracle for WorkspaceIcfgProvider<'_> {
    fn pointees(
        &self,
        value: &ValueAtPoint,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<PointsToResult>, SemanticProviderError> {
        self.record_artifact_read(value.point().procedure());
        self.oracle.pointees(value, request)
    }

    fn locations(
        &self,
        access: &AccessPathAtPoint,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<LocationResult>, SemanticProviderError> {
        self.record_artifact_read(access.point().procedure());
        self.oracle.locations(access, request)
    }

    fn alias(
        &self,
        query: &AliasQuery,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<AliasResult>, SemanticProviderError> {
        self.record_artifact_read(query.left().point().procedure());
        self.oracle.alias(query, request)
    }

    fn fresh_object_publications(
        &self,
        query: &FreshObjectPublicationQuery,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<FreshObjectPublicationResult>, SemanticProviderError> {
        self.record_artifact_read(query.observation().procedure());
        self.oracle.fresh_object_publications(query, request)
    }

    fn update_eligibility(
        &self,
        store: &StoreAtPoint,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<UpdateEligibility>, SemanticProviderError> {
        self.record_artifact_read(store.store().point().procedure());
        self.oracle.update_eligibility(store, request)
    }
}

impl IcfgProvider for WorkspaceIcfgProvider<'_> {
    fn behavior_identity(&self) -> IcfgProviderBehaviorIdentity {
        self.behavior_identity
    }

    /// The default profile projection, with the callee artifact it reads
    /// named.
    ///
    /// The entry and exit points scope one procedure of one artifact, and the
    /// profile is a bounded scan of that procedure's own topology, so the read
    /// is the artifact. The default implementation is otherwise unchanged.
    fn exit_profile(
        &self,
        callee_entry: &ProgramPointHandle,
        callee_exit: &ProgramPointHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<IcfgExitProfile>, SemanticProviderError> {
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }
        self.record_artifact_read(callee_entry.procedure());
        let cacheable_request =
            request.execution_budget().is_none() && request.artifact_collector().is_none();
        let key = (callee_entry.clone(), callee_exit.clone());
        let cached = cacheable_request.then(|| self.outcome_cache.exit_profile(&key));
        if let Some(outcome) = cached.flatten() {
            return Ok(outcome);
        }
        let refinements = self
            .oracle
            .runtime_refinements_for_procedure(callee_entry.procedure(), request)?;
        match &refinements {
            SemanticOutcome::Cancelled { work, .. } => {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: *work,
                });
            }
            SemanticOutcome::ExceededBudget { exceeded, work, .. } => {
                return Ok(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded: *exceeded,
                    work: *work,
                });
            }
            _ => {}
        }
        let mut discharged = refinements
            .available_value()
            .map(|reads| {
                reads
                    .endpoints
                    .iter()
                    .flat_map(|endpoint| endpoint.discharged_gaps.iter().copied())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        // A proven inert-drop obligation discharges the procedure's omitted
        // drops and turns the aborts whose only active cleanups are those
        // drops into non-rejoining exits (#3757).
        let mut non_rejoining = Vec::new();
        if self
            .oracle
            .procedure_drops_proven_inert(callee_entry.procedure(), request)?
        {
            for gap in callee_entry.procedure().semantics().gaps() {
                match gap.discharge {
                    SemanticGapDischarge::InertDropGlue => discharged.push(gap.id),
                    SemanticGapDischarge::NonRejoiningExceptionalExitAfterInertDrops => {
                        non_rejoining.push(gap.id)
                    }
                    _ => {}
                }
            }
        }
        let mut outcome = materialize_exit_profile_with_runtime_reads(
            callee_entry,
            callee_exit,
            &discharged,
            &non_rejoining,
            request,
        )?;
        let work = match &mut outcome {
            SemanticOutcome::Complete { work, .. }
            | SemanticOutcome::Unproven { work, .. }
            | SemanticOutcome::Unknown { work, .. }
            | SemanticOutcome::Ambiguous { work, .. }
            | SemanticOutcome::Unsupported { work, .. }
            | SemanticOutcome::Cancelled { work, .. }
            | SemanticOutcome::ExceededBudget { work, .. } => work,
        };
        *work = work.conservative_add(refinements.work());
        if cacheable_request && let Some(cached) = outcome.completed_replay() {
            self.outcome_cache
                .exit_profiles
                .lock()
                .expect("query-local ICFG cache mutex is not poisoned")
                .insert(key, cached);
        }
        Ok(outcome)
    }

    fn call_transfers(
        &self,
        caller: &ProcedureHandle,
        call: CallSiteId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<CallTransferSet>, SemanticProviderError> {
        self.call_transfers_in_context(caller, call, &OracleCallContext::empty(), request)
    }

    fn call_transfers_in_context(
        &self,
        caller: &ProcedureHandle,
        call: CallSiteId,
        context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<CallTransferSet>, SemanticProviderError> {
        WorkspaceIcfgProvider::call_transfers_in_context(self, caller, call, context, request)
    }

    fn snapshot(
        &self,
        root: &ProcedureHandle,
        limits: IcfgSnapshotLimits,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<IcfgSnapshot>, SemanticProviderError> {
        self.with_snapshot_transaction(request, |provider, request| {
            provider.materialize_snapshot(root, limits, request)
        })
    }
}

impl WorkspaceIcfgProvider<'_> {
    fn call_transfers_in_context(
        &self,
        caller: &ProcedureHandle,
        call: CallSiteId,
        context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<CallTransferSet>, SemanticProviderError> {
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }
        self.record_artifact_read(caller);
        let cacheable_request =
            request.execution_budget().is_none() && request.artifact_collector().is_none();
        let origin = caller
            .call_site_handle(call)
            .ok_or_else(|| SemanticProviderError::internal("failed to scope semantic call site"))?;
        let cache_key = (caller.clone(), call, context.clone());
        let cached = cacheable_request.then(|| self.outcome_cache.call_transfer(&cache_key));
        if let Some(cached) = cached.flatten() {
            record_dispatch_read_attribution(self.workspace(), &cached.dispatch_read);
            return Ok(cached.outcome);
        }
        let semantic_call = caller
            .semantics()
            .call_site(call)
            .expect("a scoped semantic call remains in its owning procedure")
            .clone();
        let call_evaluation_gaps = scoped_call_evaluation_gaps(caller, &semantic_call);
        let mut staged_budget = request.budget.clone();
        // Context proof can acquire entering-caller source in another artifact.
        // Keep every newly paid session private until transfer projection commits.
        // An empty local session is retryable and retains no source. Keep the
        // ordinary origin entry while contextual acquisitions stay private.
        let _origin_session = self.dispatch_session(caller.artifact());
        let dispatch_cache = Arc::new(QueryLocalIcfgOutcomeCache::snapshot_overlay(Arc::clone(
            &self.outcome_cache,
        )));
        let dispatch_provider = Self {
            oracle: self.oracle.clone(),
            active_semantic_model_snapshot: self.active_semantic_model_snapshot.clone(),
            behavior_identity: self.behavior_identity,
            outcome_cache: Arc::clone(&dispatch_cache),
        };
        let before_probe = staged_budget.used();
        let contextual = self.oracle.resolve_argument_callable(
            &origin,
            context,
            &mut request.staged(&mut staged_budget),
            |entering, request| {
                dispatch_provider.record_artifact_read(entering.procedure());
                let session = dispatch_provider.dispatch_session(entering.procedure().artifact());
                let mut session = session
                    .lock()
                    .expect("entering dispatch session is not poisoned");
                session.resolve_call(entering, request)
            },
        );
        let contextual = match contextual {
            Ok(contextual) => contextual,
            Err(error) => {
                request.budget.retain_performed_work(&staged_budget);
                return Err(error);
            }
        };
        let probe_work = staged_budget.used().saturating_sub(before_probe);
        let dispatch_session = dispatch_provider.dispatch_session(caller.artifact());
        let mut dispatch_session = dispatch_session
            .lock()
            .expect("query-local exact-artifact dispatch session is not poisoned");
        // Waiting for another call from this artifact can outlive the first
        // cancellation check. Do not enter the retained parser after the
        // request has been cancelled.
        if request.cancellation.is_cancelled() {
            request.budget.retain_performed_work(&staged_budget);
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }
        let retained_source_before = dispatch_session.retains_exact_source();
        // The provider is itself query-local. Like its completed-outcome
        // memo, a performed parse is shared by provider clones even when a
        // retry uses a fresh scalar budget. The first successful transfer
        // charged that work; replay owns no new source work.
        let dispatch_outcome = if let Some(outcome) = contextual {
            Ok(outcome)
        } else {
            dispatch_session
                .resolve_call(&origin, &mut request.staged(&mut staged_budget))
                .map(|mut outcome| {
                    match &mut outcome {
                        SemanticOutcome::Complete { work, .. }
                        | SemanticOutcome::Ambiguous { work, .. }
                        | SemanticOutcome::Unknown { work, .. }
                        | SemanticOutcome::Unsupported { work, .. }
                        | SemanticOutcome::Unproven { work, .. }
                        | SemanticOutcome::ExceededBudget { work, .. }
                        | SemanticOutcome::Cancelled { work, .. } => {
                            *work = probe_work.conservative_add(*work);
                        }
                    }
                    outcome
                })
        };
        let dispatch_outcome = match dispatch_outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                if !retained_source_before {
                    dispatch_session.discard_exact_source();
                }
                request.budget.retain_performed_work(&staged_budget);
                return Err(error);
            }
        };
        // Persisted replay currently resolves origin-only questions. Fail closed
        // rather than record a contextual answer under that different question.
        let dispatch_read = if context.calls().is_empty() && !context.was_truncated() {
            dispatch_read_attribution(&origin, &dispatch_outcome)
        } else {
            DispatchReadAttribution::Unattributed(
                DispatchReadUnattributedReason::CallContextUnavailable,
            )
        };
        record_dispatch_read_attribution(self.workspace(), &dispatch_read);
        let mapped = dispatch_outcome.try_map(|dispatch| {
            let mut transfers = Vec::new();
            let mut additional_work = SemanticWork::default();
            let argument_callable = dispatch.argument_callable().cloned().map(Arc::new);
            if let Some(provenance) = &argument_callable {
                additional_work = additional_work.conservative_add(SemanticWork {
                    captures: provenance.capture_bindings().len().saturating_add(
                        provenance
                            .producer()
                            .map_or(0, |producer| producer.captures().len()),
                    ),
                    nested_entries: 8usize
                        .saturating_add(provenance.caller_context().calls().len())
                        .saturating_add(provenance.captures().len())
                        .saturating_add(provenance.capture_bindings().len())
                        .saturating_add(provenance.binding().len())
                        .saturating_add(provenance.producer().map_or(0, |producer| {
                            3usize.saturating_add(producer.captures().len())
                        })),
                    owned_text_bytes: provenance
                        .capture_bindings()
                        .iter()
                        .map(|row| match &row.mode {
                            crate::analyzer::semantic::CaptureMode::LanguageDefined(label) => label.len(),
                            _ => 0,
                        })
                        .fold(0usize, usize::saturating_add),
                    ..SemanticWork::default()
                });
            }
            let (candidates, dispatch_boundaries, coverage) = dispatch.into_parts();
            let mut boundaries = dispatch_boundaries
                .into_vec()
                .into_iter()
                .map(|dispatch| {
                    let normal_continuation_absent = dispatch
                        .unmaterialized_external_target()
                        .is_some_and(|target| {
                            supports_authored_normal_continuation_absence(target.language())
                                && self.active_semantic_model_snapshot.as_deref().is_some_and(
                                    |snapshot| {
                                        snapshot.active_models().proves_normal_continuation_absent(
                                            ProcedureSummaryMemberKey::new(
                                                target.language().semantic_pack_label(),
                                                target.owner_fqn(),
                                                target.member(),
                                                target.has_receiver(),
                                                target.arity(),
                                            ),
                                        )
                                    },
                                )
                        });
                    CallBoundary {
                        origin: origin.clone(),
                        dispatch,
                        model: boundary_call_to_return_model(
                            semantic_call.invocation_mode,
                            normal_continuation_absent,
                        ),
                    }
                })
                .collect::<Vec<_>>();
            for candidate in candidates.into_vec() {
                let properties = candidate.target.semantics().properties();
                if semantic_call.invocation_mode == CallInvocationMode::Detached {
                    let previous_reason_bytes = completeness_reason_bytes(&candidate.completeness);
                    let completeness = EvidenceCompleteness::Partial(
                        "callee body executes in a different task".into(),
                    );
                    let added_reason_bytes = completeness_reason_bytes(&completeness)
                        .saturating_sub(previous_reason_bytes);
                    let target = candidate.target.semantics().locator().clone();
                    let boundary_kind = DispatchBoundaryKind::Deferred {
                        target: target.clone(),
                        kind: DeferredInvocationKind::Async,
                    };
                    let (provenance, provenance_work) = deferred_boundary_provenance(
                        &origin,
                        &boundary_kind,
                        &candidate.provenance,
                        *self.oracle.limits(),
                    )?;
                    boundaries.push(CallBoundary {
                        origin: origin.clone(),
                        dispatch: DispatchBoundary {
                            kind: boundary_kind,
                            external_callee_identity: None,
                            exact_external_target: None,
                            unmaterialized_external_target: None,
                            proof: candidate.proof,
                            completeness,
                            provenance,
                        },
                        // Starting the task returns normally to the registering
                        // procedure. The spawned body's exits never rejoin it.
                        model: CallToReturnModel::Normal,
                    });
                    additional_work = additional_work
                        .conservative_add(semantic_locator_work(&target))
                        .conservative_add(provenance_work)
                        .conservative_add(SemanticWork {
                            owned_text_bytes: added_reason_bytes,
                            ..SemanticWork::default()
                        });
                    continue;
                }
                if properties.invocation == ProcedureInvocationKind::Deferred {
                    let previous_reason_bytes = completeness_reason_bytes(&candidate.completeness);
                    let completeness = EvidenceCompleteness::Partial(
                        "callee body execution requires a later resume transfer".into(),
                    );
                    let added_reason_bytes = completeness_reason_bytes(&completeness)
                        .saturating_sub(previous_reason_bytes);
                    let target = candidate.target.semantics().locator().clone();
                    let boundary_kind = DispatchBoundaryKind::Deferred {
                        target: target.clone(),
                        kind: deferred_invocation_kind(properties),
                    };
                    let (provenance, provenance_work) = deferred_boundary_provenance(
                        &origin,
                        &boundary_kind,
                        &candidate.provenance,
                        *self.oracle.limits(),
                    )?;
                    boundaries.push(CallBoundary {
                        origin: origin.clone(),
                        dispatch: DispatchBoundary {
                            kind: boundary_kind,
                            external_callee_identity: None,
                            exact_external_target: None,
                            unmaterialized_external_target: None,
                            proof: candidate.proof,
                            completeness,
                            provenance,
                        },
                        // Creating the suspended object normally returns to the
                        // caller, while argument binding or language call
                        // mechanics can still fail synchronously.
                        model: CallToReturnModel::NormalAndExceptional,
                    });
                    // The candidate row was already charged by dispatch. The
                    // transfer projection additionally owns its cloned locator,
                    // boundary-kind relation, and newly retained reason text.
                    additional_work = additional_work
                        .conservative_add(semantic_locator_work(&target))
                        .conservative_add(provenance_work)
                        .conservative_add(SemanticWork {
                            owned_text_bytes: added_reason_bytes,
                            ..SemanticWork::default()
                        });
                    continue;
                }
                let Some(entry) = candidate
                    .target
                    .point_handle(candidate.target.semantics().entry_point())
                else {
                    continue;
                };
                let (mut completeness, mut added_reason_bytes) = call_binding_completeness(
                    &semantic_call,
                    candidate.target.semantics().values(),
                    candidate.completeness,
                );
                if argument_callable
                    .as_ref()
                    .is_some_and(|proof| !proof.captures().is_empty())
                {
                    // Exact control-flow dispatch is established, but the value-flow
                    // consumer does not yet project this caller's capture environment.
                    // Preserve the association without claiming complete value transport.
                    let previous = completeness_reason_bytes(&completeness);
                    completeness = EvidenceCompleteness::Partial(match completeness {
                        EvidenceCompleteness::Complete =>
                            "callback argument capture environment transport is incomplete".into(),
                        EvidenceCompleteness::Partial(reason) => format!(
                            "{reason}; callback argument capture environment transport is incomplete"
                        ).into(),
                    });
                    added_reason_bytes = added_reason_bytes.saturating_add(
                        completeness_reason_bytes(&completeness).saturating_sub(previous),
                    );
                }
                additional_work = additional_work.conservative_add(SemanticWork {
                    nested_entries: context.calls().len(),
                    owned_text_bytes: added_reason_bytes,
                    ..SemanticWork::default()
                });
                transfers.push(CallTransfer {
                    origin: origin.clone(),
                    callee: candidate.target,
                    callee_entry: entry,
                    argument_callable: argument_callable.clone(),
                    normal_continuation: semantic_call.normal_continuation,
                    exceptional_continuation: semantic_call.exceptional_continuation,
                    proof: candidate.proof,
                    completeness,
                });
            }
            let mut transfer_set = CallTransferSet {
                transfers: transfers.into_boxed_slice(),
                boundaries: boundaries.into_boxed_slice(),
                coverage,
            };
            additional_work = additional_work.conservative_add(SemanticWork {
                owned_text_bytes: apply_call_evaluation_gaps(
                    &call_evaluation_gaps,
                    &mut transfer_set,
                ),
                ..SemanticWork::default()
            });
            Ok((transfer_set, additional_work))
        });
        let mapped = match mapped {
            Ok(mapped) => mapped,
            Err(error) => {
                // Dispatch charged only the staged ledger. If projection
                // cannot publish a transfer, release its new source holder.
                // Performed work survives the failed projection.
                if !retained_source_before {
                    dispatch_session.discard_exact_source();
                }
                request.budget.retain_performed_work(&staged_budget);
                return Err(error);
            }
        };
        let additional_work = mapped
            .available_value()
            .map_or(SemanticWork::default(), |(_, work)| *work);
        let original_work = mapped.work();
        let total_work = original_work.conservative_add(additional_work);
        if let Some(outcome) = charge_call_transfer_projection(
            &mapped,
            &mut staged_budget,
            additional_work,
            total_work,
            request.cancellation,
        ) {
            if !retained_source_before {
                dispatch_session.discard_exact_source();
            }
            request.budget.retain_performed_work(&staged_budget);
            return Ok(outcome);
        }
        let mut outcome = weaken_call_transfer_outcome(
            mapped.map(|(transfer_set, _)| transfer_set),
            &call_evaluation_gaps,
            total_work,
        );
        if let SemanticOutcome::Complete { value, work } = &outcome
            && value.transfers.iter().any(|transfer| {
                transfer
                    .argument_callable
                    .as_ref()
                    .is_some_and(|proof| !proof.captures().is_empty())
            })
        {
            outcome = SemanticOutcome::Unsupported {
                capability: SemanticCapability::Captures,
                partial: Some(value.clone()),
                work: *work,
            };
        }
        if request.cancellation.is_cancelled()
            && !matches!(outcome, SemanticOutcome::Cancelled { .. })
        {
            outcome = cancelled_call_transfer_outcome(outcome, total_work);
        }
        if outcome.available_value().is_some() {
            *request.budget = staged_budget;
        } else {
            request.budget.retain_performed_work(&staged_budget);
            if !retained_source_before {
                dispatch_session.discard_exact_source();
            }
        }
        drop(dispatch_session);
        if outcome.available_value().is_some() {
            self.outcome_cache.publish_snapshot(&dispatch_cache);
        }
        if cacheable_request && let Some(cached) = outcome.completed_replay() {
            self.outcome_cache
                .call_transfers
                .lock()
                .expect("query-local ICFG cache mutex is not poisoned")
                .insert(
                    cache_key,
                    CachedCallTransferOutcome {
                        outcome: cached,
                        dispatch_read,
                    },
                );
        }
        Ok(outcome)
    }

    fn materialize_snapshot(
        &self,
        root: &ProcedureHandle,
        limits: IcfgSnapshotLimits,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<IcfgSnapshot>, SemanticProviderError> {
        self.record_artifact_read(root);
        limits
            .validate()
            .map_err(|error| SemanticProviderError::internal(error.to_string()))?;
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }
        let max_source_bytes = request.budget.limits().source_bytes;
        let Some((_, root_source)) =
            exact_source_for_procedure(self.workspace(), root, max_source_bytes)?
        else {
            let work = SemanticWork {
                source_bytes: max_source_bytes.saturating_add(1),
                ..SemanticWork::default()
            };
            let exceeded = request.budget.check_admission(work).map_or_else(
                |exceeded| exceeded,
                |_| unreachable!("bounded root-source omission must exceed the remaining budget"),
            );
            return Ok(SemanticOutcome::ExceededBudget {
                partial: Some(IcfgSnapshot::empty()),
                exceeded,
                work,
            });
        };
        let root_entry = root
            .point_handle(root.semantics().entry_point())
            .ok_or_else(|| SemanticProviderError::internal("root procedure has no entry point"))?;
        let root_work = SemanticWork {
            source_bytes: root_source.len(),
            ..SemanticWork::default()
        };
        request.budget.charge_work(root_work);
        let mut builder = SnapshotBuilder::new(limits);
        let mut transfer_cache: HashMap<
            (CallSiteHandle, OracleCallContext),
            SemanticOutcome<CallTransferSet>,
        > = HashMap::default();
        builder.work = root_work;
        builder.intern(
            TraversalKey {
                point: root_entry,
                frames: Box::new([]),
            },
            request,
            None,
            None,
        )?;

        while let Some(node) = builder.queue.pop_front() {
            if request.cancellation.is_cancelled() {
                builder.quality = SnapshotQuality::Cancelled;
                break;
            }
            if !request.charge_execution_traversal(1) {
                builder.quality = merge_quality(builder.quality, SnapshotQuality::Truncated);
                break;
            }
            let key = builder.traversal[node.index()].clone();
            if expand_return(self, &mut builder, node, &key, request)? {
                continue;
            }
            let call = invoked_call_at(&key.point)?;

            if let Some(call) = call {
                let semantic_call = key
                    .point
                    .procedure()
                    .semantics()
                    .call_site(call)
                    .ok_or_else(|| SemanticProviderError::internal("invoke event has no call row"))?
                    .clone();
                let origin = key
                    .point
                    .procedure()
                    .call_site_handle(call)
                    .ok_or_else(|| {
                        SemanticProviderError::internal("failed to scope invoke call")
                    })?;

                if key.frames.len() >= limits.max_call_depth as usize {
                    builder.quality = merge_quality(builder.quality, SnapshotQuality::Truncated);
                    builder.boundaries.push(IcfgBoundary {
                        at: node,
                        origin: Some(origin.clone()),
                        kind: IcfgBoundaryKind::Limit(IcfgLimitKind::CallDepth),
                    });
                } else {
                    let context = OracleCallContext::bounded(
                        key.frames
                            .iter()
                            .map(|frame| frame.transfer.origin.clone())
                            .collect(),
                        *self.oracle.limits(),
                    );
                    let transfer_key = (origin.clone(), context.clone());
                    let (outcome, newly_resolved) =
                        if let Some(cached) = transfer_cache.get(&transfer_key) {
                            (cached.clone(), false)
                        } else {
                            let outcome = self.call_transfers_in_context(
                                key.point.procedure(),
                                call,
                                &context,
                                request,
                            )?;
                            transfer_cache.insert(transfer_key, outcome.clone());
                            (outcome, true)
                        };
                    builder.absorb_quality(&outcome);
                    if newly_resolved {
                        builder.work = builder.work.conservative_add(outcome.work());
                    }
                    if let Some(transfers) = outcome.available_value().cloned() {
                        validate_call_transfer_set(
                            key.point.procedure(),
                            &semantic_call,
                            &transfers,
                        )?;
                        builder.record_dispatch_boundaries(node, &transfers.boundaries);
                        for boundary in &transfers.boundaries {
                            link_boundary_continuations(
                                &mut builder,
                                node,
                                &key,
                                &semantic_call,
                                boundary,
                                request,
                            )?;
                        }
                        for transfer in transfers.transfers.into_vec() {
                            let callee_entry = transfer.callee_entry.clone();
                            let proof = transfer.proof.clone();
                            let completeness = transfer.completeness.clone();
                            let mut frames = key.frames.to_vec();
                            frames.push(CallFrame { transfer });
                            let target_key = TraversalKey {
                                point: callee_entry,
                                frames: frames.into_boxed_slice(),
                            };
                            builder.link(
                                node,
                                target_key,
                                IcfgEdgeKind::Call,
                                Some(origin.clone()),
                                proof,
                                completeness,
                                None,
                                request,
                            )?;
                        }
                    }
                }

                // Preserve any unusual non-scaffolding local edges, while the
                // known normal/exceptional continuation rows are replaced by
                // call and matched-return transfers.
                for (_, edge) in key
                    .point
                    .procedure()
                    .semantics()
                    .successor_edges(key.point.id())
                {
                    if is_call_scaffolding(edge, &semantic_call) {
                        continue;
                    }
                    add_local_edge(&mut builder, node, &key, edge, request)?;
                }
            } else {
                for (_, edge) in key
                    .point
                    .procedure()
                    .semantics()
                    .successor_edges(key.point.id())
                {
                    add_local_edge(&mut builder, node, &key, edge, request)?;
                }
            }
        }

        let quality = builder.quality;
        let exceeded = builder.budget_exceeded;
        let work = builder.work;
        let snapshot = builder.freeze()?;
        Ok(finish_snapshot_outcome(snapshot, quality, exceeded, work))
    }
}

#[doc(hidden)]
pub fn charge_call_transfer_projection(
    mapped: &SemanticOutcome<(CallTransferSet, SemanticWork)>,
    budget: &mut crate::analyzer::semantic::SemanticBudget,
    additional_work: SemanticWork,
    total_work: SemanticWork,
    cancellation: &crate::cancellation::CancellationToken,
) -> Option<SemanticOutcome<CallTransferSet>> {
    budget.admit(additional_work).err().map(|exceeded| {
        if matches!(mapped, SemanticOutcome::Cancelled { .. }) || cancellation.is_cancelled() {
            SemanticOutcome::Cancelled {
                // The projected payload cannot be published when its atomic
                // retained-work charge fails, but the operation-level
                // cancellation still takes precedence over that failure.
                partial: None,
                work: total_work,
            }
        } else {
            SemanticOutcome::ExceededBudget {
                partial: None,
                exceeded,
                work: total_work,
            }
        }
    })
}

pub(crate) fn cancelled_call_transfer_outcome(
    outcome: SemanticOutcome<CallTransferSet>,
    work: SemanticWork,
) -> SemanticOutcome<CallTransferSet> {
    let partial = match outcome {
        SemanticOutcome::Complete { value, .. } => Some(value),
        SemanticOutcome::Ambiguous { candidates, .. } => Some(candidates),
        SemanticOutcome::Unproven { partial, .. } => Some(partial),
        SemanticOutcome::Unknown { partial, .. }
        | SemanticOutcome::Unsupported { partial, .. }
        | SemanticOutcome::ExceededBudget { partial, .. }
        | SemanticOutcome::Cancelled { partial, .. } => partial,
    };
    SemanticOutcome::Cancelled { partial, work }
}

pub(crate) fn apply_call_evaluation_gaps(
    gaps: &[&SemanticGap],
    transfers: &mut CallTransferSet,
) -> usize {
    if gaps.is_empty() {
        return 0;
    }
    let detail = gaps
        .iter()
        .map(|gap| {
            format!(
                "{} {}: {}",
                gap.kind.label(),
                gap.capability.label(),
                gap.detail
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    transfers
        .transfers
        .iter_mut()
        .map(|transfer| {
            let previous_reason_bytes = completeness_reason_bytes(&transfer.completeness);
            transfer.completeness = EvidenceCompleteness::Partial(match &transfer.completeness {
                EvidenceCompleteness::Complete => {
                    format!("caller-side call evaluation is incomplete: {detail}").into()
                }
                EvidenceCompleteness::Partial(existing) => {
                    format!("{existing}; caller-side call evaluation gaps: {detail}").into()
                }
            });
            completeness_reason_bytes(&transfer.completeness).saturating_sub(previous_reason_bytes)
        })
        .fold(0usize, usize::saturating_add)
}

pub(crate) fn weaken_call_transfer_outcome(
    outcome: SemanticOutcome<CallTransferSet>,
    gaps: &[&SemanticGap],
    work: SemanticWork,
) -> SemanticOutcome<CallTransferSet> {
    if gaps.is_empty() {
        return call_transfer_outcome_with_work(outcome, work);
    }
    let gap_quality = gaps.iter().fold(SnapshotQuality::Complete, |quality, gap| {
        merge_quality(quality, semantic_gap_quality(gap))
    });
    match outcome {
        SemanticOutcome::Complete { value, .. } => call_transfer_outcome(value, gap_quality, work),
        SemanticOutcome::Ambiguous { candidates, .. } => call_transfer_outcome(
            candidates,
            merge_quality(SnapshotQuality::Ambiguous, gap_quality),
            work,
        ),
        SemanticOutcome::Unproven { partial, .. } => call_transfer_outcome(
            partial,
            merge_quality(SnapshotQuality::Unproven, gap_quality),
            work,
        ),
        SemanticOutcome::Unknown {
            partial: Some(partial),
            ..
        } => call_transfer_outcome(
            partial,
            merge_quality(SnapshotQuality::Unknown, gap_quality),
            work,
        ),
        SemanticOutcome::Unknown { partial: None, .. } => SemanticOutcome::Unknown {
            partial: None,
            work,
        },
        SemanticOutcome::Unsupported {
            capability,
            partial: Some(partial),
            ..
        } => call_transfer_outcome(
            partial,
            merge_quality(SnapshotQuality::Unsupported(capability), gap_quality),
            work,
        ),
        SemanticOutcome::Unsupported {
            capability,
            partial: None,
            ..
        } => SemanticOutcome::Unsupported {
            capability,
            partial: None,
            work,
        },
        SemanticOutcome::ExceededBudget {
            partial, exceeded, ..
        } => SemanticOutcome::ExceededBudget {
            partial,
            exceeded,
            work,
        },
        SemanticOutcome::Cancelled { partial, .. } => SemanticOutcome::Cancelled { partial, work },
    }
}

pub(crate) fn call_transfer_outcome(
    transfers: CallTransferSet,
    quality: SnapshotQuality,
    work: SemanticWork,
) -> SemanticOutcome<CallTransferSet> {
    match quality {
        SnapshotQuality::Complete => SemanticOutcome::Complete {
            value: transfers,
            work,
        },
        SnapshotQuality::Ambiguous => SemanticOutcome::Ambiguous {
            candidates: transfers,
            work,
        },
        SnapshotQuality::Unproven | SnapshotQuality::Truncated => SemanticOutcome::Unproven {
            partial: transfers,
            work,
        },
        SnapshotQuality::Unknown => SemanticOutcome::Unknown {
            partial: Some(transfers),
            work,
        },
        SnapshotQuality::Unsupported(capability) => SemanticOutcome::Unsupported {
            capability,
            partial: Some(transfers),
            work,
        },
        SnapshotQuality::Cancelled => SemanticOutcome::Cancelled {
            partial: Some(transfers),
            work,
        },
    }
}

pub(crate) fn call_transfer_outcome_with_work(
    outcome: SemanticOutcome<CallTransferSet>,
    work: SemanticWork,
) -> SemanticOutcome<CallTransferSet> {
    match outcome {
        SemanticOutcome::Complete { value, .. } => SemanticOutcome::Complete { value, work },
        SemanticOutcome::Ambiguous { candidates, .. } => {
            SemanticOutcome::Ambiguous { candidates, work }
        }
        SemanticOutcome::Unknown { partial, .. } => SemanticOutcome::Unknown { partial, work },
        SemanticOutcome::Unsupported {
            capability,
            partial,
            ..
        } => SemanticOutcome::Unsupported {
            capability,
            partial,
            work,
        },
        SemanticOutcome::Unproven { partial, .. } => SemanticOutcome::Unproven { partial, work },
        SemanticOutcome::ExceededBudget {
            partial, exceeded, ..
        } => SemanticOutcome::ExceededBudget {
            partial,
            exceeded,
            work,
        },
        SemanticOutcome::Cancelled { partial, .. } => SemanticOutcome::Cancelled { partial, work },
    }
}

pub fn project_call_boundary(
    caller: &ProcedureHandle,
    semantic_call: &SemanticCallSite,
    boundary: &CallBoundary,
) -> Result<CallToReturnProjection, SemanticProviderError> {
    let model = boundary.model;
    if boundary.origin.procedure() != caller {
        return Err(SemanticProviderError::internal(
            "call-to-return boundary belongs to a different caller",
        ));
    }
    if boundary.origin.id() != semantic_call.id {
        return Err(SemanticProviderError::internal(
            "call boundary origin does not match the projected call",
        ));
    }
    let at = caller
        .point_handle(semantic_call.point)
        .ok_or_else(|| SemanticProviderError::internal("call boundary point is stale"))?;

    let mut edges = Vec::new();
    let mut boundaries = Vec::new();
    let mut project = |kind: CallContinuationKind,
                       continuation: ControlContinuation,
                       edge_kind: IcfgEdgeKind|
     -> Result<(), SemanticProviderError> {
        match continuation {
            ControlContinuation::Target(point) => {
                let target = caller.point_handle(point).ok_or_else(|| {
                    SemanticProviderError::internal("call boundary continuation is stale")
                })?;
                edges.push(ProcedureIcfgEdge {
                    source: at.clone(),
                    target,
                    kind: edge_kind,
                    origin: Some(boundary.origin.clone()),
                    proof: boundary.dispatch.proof.clone(),
                    completeness: boundary.dispatch.completeness.clone(),
                    boundary: Some(boundary.dispatch.kind.clone()),
                });
            }
            ControlContinuation::Absent => {}
            state => {
                boundaries.push(ProcedureIcfgBoundary {
                    at: at.clone(),
                    origin: Some(boundary.origin.clone()),
                    kind: IcfgBoundaryKind::Continuation { kind, state },
                });
            }
        }
        Ok(())
    };
    if matches!(
        model,
        CallToReturnModel::Normal | CallToReturnModel::NormalAndExceptional
    ) {
        project(
            CallContinuationKind::Normal,
            semantic_call.normal_continuation,
            IcfgEdgeKind::CallToNormalContinuation,
        )?;
    }
    if matches!(
        model,
        CallToReturnModel::Exceptional | CallToReturnModel::NormalAndExceptional
    ) {
        project(
            CallContinuationKind::Exceptional,
            semantic_call.exceptional_continuation,
            IcfgEdgeKind::CallToExceptionalContinuation,
        )?;
    }
    Ok(CallToReturnProjection {
        edges: edges.into_boxed_slice(),
        boundaries: boundaries.into_boxed_slice(),
    })
}

pub(crate) fn link_boundary_continuations(
    builder: &mut SnapshotBuilder,
    source: IcfgNodeId,
    key: &TraversalKey,
    semantic_call: &SemanticCallSite,
    boundary: &CallBoundary,
    request: &mut SemanticRequest<'_>,
) -> Result<(), SemanticProviderError> {
    let projection = project_call_boundary(key.point.procedure(), semantic_call, boundary)?;
    for edge in projection.edges {
        debug_assert_eq!(edge.source, key.point);
        let kind = edge.kind;
        let linked = builder.link(
            source,
            TraversalKey {
                point: edge.target,
                frames: key.frames.clone(),
            },
            kind,
            edge.origin,
            edge.proof,
            edge.completeness,
            edge.boundary,
            request,
        )?;
        // A matched return through a resolved target of the same call must not
        // publish a second row for a continuation this boundary already owns.
        if let Some(target) = linked
            && matches!(
                kind,
                IcfgEdgeKind::CallToNormalContinuation
                    | IcfgEdgeKind::CallToExceptionalContinuation
            )
        {
            builder.call_to_return_edges.insert((source, target, kind));
        }
    }
    for boundary in projection.boundaries {
        debug_assert_eq!(boundary.at, key.point);
        builder.boundaries.push(IcfgBoundary {
            at: source,
            origin: boundary.origin,
            kind: boundary.kind,
        });
        builder.quality = merge_quality(builder.quality, SnapshotQuality::Unknown);
    }
    Ok(())
}

pub(crate) fn expand_return<P>(
    provider: &P,
    builder: &mut SnapshotBuilder,
    node: IcfgNodeId,
    key: &TraversalKey,
    request: &mut SemanticRequest<'_>,
) -> Result<bool, SemanticProviderError>
where
    P: IcfgProvider + ?Sized,
{
    let semantics = key.point.procedure().semantics();
    if key.point.id() != semantics.normal_exit_point()
        && key.point.id() != semantics.exceptional_exit_point()
    {
        return Ok(false);
    }
    let Some(frame) = key.frames.last() else {
        return Ok(false);
    };
    if frame.transfer.callee != *key.point.procedure() {
        return Err(SemanticProviderError::internal(
            "ICFG return context does not match the exiting callee",
        ));
    }

    let cache_key = (
        key.point.procedure().clone(),
        frame.transfer.callee_entry.id(),
        key.point.id(),
    );
    let (outcome, newly_materialized) = if let Some(cached) = builder.exit_profiles.get(&cache_key)
    {
        (cached.clone(), false)
    } else {
        let outcome = provider.exit_profile(&frame.transfer.callee_entry, &key.point, request)?;
        if let Some(profile) = outcome.available_value() {
            validate_exit_profile(&frame.transfer.callee_entry, &key.point, profile)?;
        }
        let outcome = outcome.map(Arc::new);
        builder.exit_profiles.insert(cache_key, outcome.clone());
        (outcome, true)
    };
    builder.absorb_quality(&outcome);
    if newly_materialized {
        builder.work = builder.work.conservative_add(outcome.work());
    }
    let Some(profile) = outcome.available_value() else {
        return Ok(true);
    };
    builder.quality = merge_quality(builder.quality, profile.quality);

    match profile.project_matched_return(&frame.transfer)? {
        MatchedReturnProjection::Edge { edge, .. } => {
            debug_assert_eq!(edge.source, key.point);
            let caller_frames: Box<[CallFrame]> = key.frames[..key.frames.len() - 1]
                .to_vec()
                .into_boxed_slice();
            let return_kind = edge.kind;
            let continuation_key = TraversalKey {
                point: edge.target,
                frames: caller_frames,
            };
            let continuation = builder.link(
                node,
                continuation_key.clone(),
                edge.kind,
                edge.origin,
                edge.proof,
                edge.completeness,
                edge.boundary,
                request,
            )?;
            if let Some(continuation) = continuation {
                link_caller_side_continuation(
                    builder,
                    &frame.transfer,
                    continuation_key,
                    continuation,
                    return_kind,
                    request,
                )?;
            }
        }
        MatchedReturnProjection::Absent => {}
        MatchedReturnProjection::Boundary(boundary) => {
            debug_assert_eq!(boundary.at, key.point);
            builder.boundaries.push(IcfgBoundary {
                at: node,
                origin: boundary.origin,
                kind: boundary.kind,
            });
            builder.quality = merge_quality(builder.quality, SnapshotQuality::Unknown);
        }
    }
    Ok(true)
}

/// Link the caller's own control continuation across a resolved call whose
/// matched return has just been projected (#1952, #2782).
///
/// A resolved call replaces the caller's scaffolding edge with call and
/// matched-return transfers, so nothing in the bounded graph otherwise lets a
/// caller-side value the callee neither receives nor returns survive the call.
/// Summary tabulation projects this row for itself; a solver reading this
/// snapshot had no way to, and its backward direction therefore lost every
/// value-flow pair that spans a call.
///
/// The row is projected here, beside the matched return, rather than at the
/// call, because the two must agree on when control resumes: a callee that
/// never returns normally reaches no normal exit, so it yields neither a
/// normal return nor a normal continuation.
///
/// The edge is the caller's own scaffolding, so its evidence is proven and
/// complete, and it carries no dispatch boundary. `resolved_call_to_return` is
/// what tells a solver whether to traverse it.
pub(crate) fn link_caller_side_continuation(
    builder: &mut SnapshotBuilder,
    transfer: &CallTransfer,
    continuation_key: TraversalKey,
    continuation: IcfgNodeId,
    return_kind: IcfgEdgeKind,
    request: &mut SemanticRequest<'_>,
) -> Result<(), SemanticProviderError> {
    let kind = match return_kind {
        IcfgEdgeKind::NormalReturn => IcfgEdgeKind::CallToNormalContinuation,
        IcfgEdgeKind::ExceptionalReturn => IcfgEdgeKind::CallToExceptionalContinuation,
        _ => return Ok(()),
    };
    let caller = transfer.origin.procedure();
    let call_site = caller
        .semantics()
        .call_site(transfer.origin.id())
        .ok_or_else(|| SemanticProviderError::internal("ICFG return origin call site is stale"))?;
    let call_point = caller
        .point_handle(call_site.point)
        .ok_or_else(|| SemanticProviderError::internal("ICFG return origin point is stale"))?;
    let call_key = TraversalKey {
        point: call_point,
        frames: continuation_key.frames.clone(),
    };
    // The callee was entered from this node, so it is already interned. An
    // absent caller would mean the return context does not match the call the
    // traversal came through, which `expand_return` has already rejected.
    let source = builder.interner.get(&call_key).copied().ok_or_else(|| {
        SemanticProviderError::internal("ICFG matched return has no calling node")
    })?;
    // A dispatch boundary at the same call already published this
    // continuation, and that row reaches every problem. A second,
    // boundary-free row for it would only duplicate the edge.
    if !builder
        .call_to_return_edges
        .insert((source, continuation, kind))
    {
        return Ok(());
    }
    builder.link(
        source,
        continuation_key,
        kind,
        Some(transfer.origin.clone()),
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
        None,
        request,
    )?;
    Ok(())
}

pub(crate) fn add_local_edge(
    builder: &mut SnapshotBuilder,
    source: IcfgNodeId,
    key: &TraversalKey,
    edge: &crate::analyzer::semantic::ControlEdge,
    request: &mut SemanticRequest<'_>,
) -> Result<(), SemanticProviderError> {
    let point = key
        .point
        .procedure()
        .point_handle(edge.target_point)
        .ok_or_else(|| SemanticProviderError::internal("local CFG edge target is stale"))?;
    let target_key = TraversalKey {
        point,
        frames: key.frames.clone(),
    };
    builder.link(
        source,
        target_key,
        IcfgEdgeKind::Intraprocedural(edge.kind),
        None,
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
        None,
        request,
    )?;
    Ok(())
}

/// Validate provider-owned call projections before either ICFG backend
/// publishes them.
pub fn validate_call_transfer_set(
    caller: &ProcedureHandle,
    semantic_call: &SemanticCallSite,
    transfers: &CallTransferSet,
) -> Result<(), SemanticProviderError> {
    let Some(stored_call) = caller.semantics().call_site(semantic_call.id) else {
        return Err(SemanticProviderError::internal(
            "ICFG call transfer set refers to a call outside its caller",
        ));
    };
    if stored_call != semantic_call {
        return Err(SemanticProviderError::internal(
            "ICFG call transfer set refers to a mismatched semantic call",
        ));
    }
    let origin = caller
        .call_site_handle(semantic_call.id)
        .ok_or_else(|| SemanticProviderError::internal("failed to scope ICFG transfer call"))?;
    if semantic_call.invocation_mode == CallInvocationMode::Detached
        && !transfers.transfers.is_empty()
    {
        return Err(SemanticProviderError::internal(
            "detached call transfer set cannot enter a callee body synchronously",
        ));
    }
    for transfer in &transfers.transfers {
        if transfer.origin != origin {
            return Err(SemanticProviderError::internal(
                "ICFG call transfer origin does not match the requested call",
            ));
        }
        if let Some(proof) = &transfer.argument_callable
            && (proof.closure() != &transfer.callee || proof.callee() != caller)
        {
            return Err(SemanticProviderError::invalid_identity(
                "callback transfer must retain its exact argument invocation proof",
            ));
        }
        if transfer.callee_entry.procedure() != &transfer.callee {
            return Err(SemanticProviderError::internal(
                "ICFG call transfer entry belongs to a different callee",
            ));
        }
        if transfer.normal_continuation != semantic_call.normal_continuation {
            return Err(SemanticProviderError::internal(
                "ICFG call transfer has a mismatched normal continuation",
            ));
        }
        if transfer.exceptional_continuation != semantic_call.exceptional_continuation {
            return Err(SemanticProviderError::internal(
                "ICFG call transfer has a mismatched exceptional continuation",
            ));
        }
    }
    for boundary in &transfers.boundaries {
        if boundary.origin != origin {
            return Err(SemanticProviderError::internal(
                "ICFG call boundary origin does not match the requested call",
            ));
        }
        boundary
            .dispatch
            .validate_for_call(&origin)
            .map_err(|error| {
                SemanticProviderError::internal(format!(
                    "ICFG call boundary has invalid dispatch provenance: {error}"
                ))
            })?;
        if semantic_call.invocation_mode == CallInvocationMode::Detached
            && boundary.model != CallToReturnModel::Normal
        {
            return Err(SemanticProviderError::internal(
                "detached call boundary must retain only the caller's normal continuation",
            ));
        }
    }
    Ok(())
}

impl Drop for WorkspaceIcfgProvider<'_> {
    fn drop(&mut self) {
        if crate::profiling::enabled() && Arc::strong_count(&self.outcome_cache) == 1 {
            let (transfers, profiles, sessions) = self.cached_artifact_bytes();
            crate::profiling::note(format!(
                "semantic.icfg.run_end icfg_transfers_artifact_bytes={transfers} icfg_profiles_artifact_bytes={profiles} icfg_sessions_artifact_bytes={sessions}"
            ));
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod python_test_support;

#[cfg(test)]
mod tests {

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::CallInvocationMode;

    use brokk_bifrost_analysis::analyzer::semantic::icfg::CallToReturnModel;

    use brokk_bifrost_analysis::analyzer::semantic::icfg::CallTransferSet;

    use brokk_bifrost_analysis::analyzer::semantic::icfg::IcfgSnapshot;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::semantic::capabilities::SemanticCapability;

    use brokk_bifrost_core::analyzer::model::LanguageDialect as SemanticLanguage;

    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticOutcome;

    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticWork;

    use brokk_bifrost_analysis::analyzer::semantic::icfg::SnapshotQuality;

    use brokk_bifrost_analysis::analyzer::semantic::icfg::boundary_call_to_return_model;

    use brokk_bifrost_analysis::analyzer::semantic::icfg::charge_call_transfer_projection;

    use brokk_bifrost_analysis::analyzer::semantic::icfg::finish_snapshot_outcome;

    use brokk_bifrost_analysis::analyzer::semantic::icfg::merge_quality;

    use brokk_bifrost_analysis::analyzer::semantic::icfg::supports_authored_normal_continuation_absence;

    use crate::analyzer::semantic::SemanticBudget;

    use crate::cancellation::CancellationToken;

    #[cfg(test)]
    #[test]
    fn detached_external_call_keeps_parent_normal_continuation() {
        assert_eq!(
            boundary_call_to_return_model(CallInvocationMode::Detached, true),
            CallToReturnModel::Normal,
            "a nonreturning target summary describes the detached body, not spawn registration"
        );
        assert_eq!(
            boundary_call_to_return_model(CallInvocationMode::Detached, false),
            CallToReturnModel::Normal
        );
        assert_eq!(
            boundary_call_to_return_model(CallInvocationMode::Ordinary, true),
            CallToReturnModel::Exceptional
        );
        assert_eq!(
            boundary_call_to_return_model(CallInvocationMode::Ordinary, false),
            CallToReturnModel::NormalAndExceptional
        );
    }

    #[cfg(test)]
    #[test]
    fn unsupported_snapshot_quality_uses_stable_capability_order() {
        let deferred = SnapshotQuality::Unsupported(SemanticCapability::DeferredExecution);
        let cleanup = SnapshotQuality::Unsupported(SemanticCapability::CleanupControlFlow);

        let expected = SnapshotQuality::Unsupported(SemanticCapability::CleanupControlFlow);
        assert_eq!(merge_quality(deferred, cleanup), expected);
        assert_eq!(merge_quality(cleanup, deferred), expected);
    }

    #[cfg(test)]
    #[test]
    fn cancelled_dispatch_precedes_a_failed_call_transfer_projection_charge() {
        let cancellation = CancellationToken::default();
        let additional_work = SemanticWork {
            nested_entries: 2,
            ..SemanticWork::default()
        };
        let mapped = SemanticOutcome::Cancelled {
            partial: Some((CallTransferSet::default(), additional_work)),
            work: SemanticWork::default(),
        };
        let mut budget = SemanticBudget::uniform(1).expect("positive semantic budget");

        let outcome = charge_call_transfer_projection(
            &mapped,
            &mut budget,
            additional_work,
            additional_work,
            &cancellation,
        )
        .expect("projection work must exceed the nested-entry budget");

        assert!(matches!(
            outcome,
            SemanticOutcome::Cancelled {
                partial: None,
                work,
            } if work == additional_work
        ));
        assert_eq!(budget.used(), SemanticWork::default());
    }

    #[cfg(test)]
    #[test]
    fn snapshot_cancellation_precedes_an_existing_budget_exhaustion() {
        let attempted_work = SemanticWork {
            nested_entries: 2,
            ..SemanticWork::default()
        };
        let exceeded = SemanticBudget::uniform(1)
            .expect("positive semantic budget")
            .check_admission(attempted_work)
            .expect_err("snapshot work must exceed the nested-entry budget");

        let outcome = finish_snapshot_outcome(
            IcfgSnapshot::empty(),
            SnapshotQuality::Cancelled,
            Some(exceeded),
            attempted_work,
        );

        assert!(matches!(
            outcome,
            SemanticOutcome::Cancelled {
                partial: Some(_),
                work,
            } if work == attempted_work
        ));
    }

    #[cfg(test)]
    #[test]
    fn authored_normal_continuation_absence_starts_with_unambiguous_go_calls() {
        assert!(supports_authored_normal_continuation_absence(
            SemanticLanguage::Standard(Language::Go)
        ));
        assert!(
            !supports_authored_normal_continuation_absence(SemanticLanguage::Standard(
                Language::Java
            )),
            "same-arity overloads need an exact signature and immediate-invocation proof first"
        );
    }
}
