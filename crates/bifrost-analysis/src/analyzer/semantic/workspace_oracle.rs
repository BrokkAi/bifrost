// Preserve explicit engine visibility when an overlay shadows a public glob.
#![allow(hidden_glob_reexports)]

//! Workspace-backed implementations of the language-neutral semantic oracles.

pub use brokk_bifrost_semantic::analyzer::semantic::workspace_oracle::*;
pub(crate) mod conversions;
#[doc(hidden)]
pub mod dispatch;
mod footprint;
pub use footprint::{FootprintUnknown, FootprintVerdict, FormalFootprintCertificate};
#[doc(hidden)]
pub mod heap;
#[doc(hidden)]
pub mod runtime_values;

pub(crate) use runtime_values::{RuntimeSyntaxCache, runtime_syntax_cache};
#[doc(hidden)]
pub mod source;
pub use runtime_values::{
    RuntimeAccessKey, RuntimeKeyedReadEndpoint, RuntimeKeyedReadFilter, RuntimeKeyedReadKeyKind,
    RuntimeKeyedReadResult, RuntimeReadLimitation, RuntimeReadSourceOrigin,
};
#[doc(hidden)]
pub mod value_flow;
use crate::analyzer::languages::{
    SavedDefaultArgumentSafety, SelectedBindingUnavailable, SelectedTupleBinding,
    language_support_for_hook,
};
use crate::analyzer::semantic::{DispatchHints, OracleLimits};
use crate::analyzer::semantic::{FormalParameterPassingMode, ProcedureHandle};
use crate::analyzer::semantic_model::{
    ActiveSemanticModelSnapshot, ResolvedActiveSemanticModels, SemanticModelOverlay,
};
use crate::analyzer::{DispatchHierarchyExpansion, WorkspaceAnalyzer};
#[doc(hidden)]
pub use dispatch::PreparedWorkspaceDispatchPool;
pub use dispatch::procedures_for_definition_with_limits;
pub(super) use dispatch::semantic_locator_work;
pub use dispatch::{
    PreparedWorkspaceDispatchSession, ProcedureRangeLookupStatus, procedures_for_source_ranges,
    procedures_in_artifact,
};
pub(crate) use dispatch::{
    exact_call_range, exact_source_for_procedure, external_constant_field_read_discharges_gap,
    inert_drop_glue_discharges_gap, residual_conversion_discharges_gap,
};
#[doc(hidden)]
pub use source::PreparedSourceDispatchSession;
#[doc(hidden)]
pub use source::one_call_dispatch_answer_digest;
pub(crate) use source::procedure_dispatch_question;
pub use source::{SourceDispatchObservation, SourceDispatchResult, SourcePointsToResult};
use std::fmt;
use std::sync::Arc;
pub use value_flow::{
    GapOpenness, ProcedureOpenness, abort_paths_run_user_code, abort_paths_run_user_code_bounded,
    allocation_call_is_dischargeable, call_target_refinement_call, classify_gap_openness,
    constructor_call_gap_is_discharged, gap_impacts_value_flow, implicit_abort_gap_is_discharged,
    value_flow_capabilities_are_open,
};
/// Workspace semantic oracles bound to one immutable analyzer generation.
/// A Java call's selected declaration and the selected-call lookup's
/// incomplete reason, memoized per call site.
type ConversionJavaTargets = crate::analyzer::usages::common::QueryReadMemo<
    crate::analyzer::semantic::CallSiteHandle,
    Option<(crate::analyzer::CodeUnit, Option<Box<str>>)>,
>;

#[derive(Clone)]
pub struct WorkspaceSemanticOracle<'a> {
    // Tracks cold session lifetime only; real source allocations pay residency.
    source_region: Arc<()>,
    workspace: &'a WorkspaceAnalyzer,
    runtime_reads: runtime_values::RuntimeReadCache,
    runtime_syntax: runtime_values::RuntimeSyntaxCache,
    lexical_indexes: crate::analyzer::lexical_definitions::LexicalIndexCache,
    runtime_write_footprints: runtime_values::AttributedRuntimeWriteFootprintCache,
    // Completed incoming bindings live only as long as this query provider.
    #[doc(hidden)]
    pub incoming_actuals: Arc<IncomingActualCache>,
    pub(super) conversion_sources:
        Arc<crate::analyzer::usages::call_conversion::CallConversionCache>,
    conversion_bindings: Arc<std::sync::Mutex<crate::analyzer::usages::CallBindingCache>>,
    // Provider-owned memos share the immutable captured model snapshot.
    conversion_java_targets: Arc<ConversionJavaTargets>,
    conversion_candidates: Arc<
        crate::analyzer::usages::common::QueryReadMemo<
            crate::analyzer::semantic::ProcedureHandle,
            conversions::ConversionCandidate,
        >,
    >,
    conversion_rows: Arc<
        crate::analyzer::usages::common::QueryReadMemo<
            (
                crate::analyzer::semantic::CallSiteHandle,
                crate::analyzer::semantic::DispatchCandidate,
            ),
            conversions::ConversionRows,
        >,
    >,
    conversion_effects: Arc<
        crate::analyzer::usages::common::QueryReadMemo<
            (
                crate::analyzer::semantic::CallSiteHandle,
                crate::analyzer::semantic::DispatchCandidate,
            ),
            bool,
        >,
    >,
    dispatch_materialization_ns: Arc<std::sync::atomic::AtomicU64>,
    limits: OracleLimits,
    hierarchy_expansion: DispatchHierarchyExpansion,
    active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    dispatch_hints: Arc<DispatchHints>,
    // Share bounded metadata evidence from this analyzer generation (#5112).
    python_saved_default_safety: Option<Arc<SavedDefaultArgumentSafety>>,
}

/// One selected answer and its exact read dependencies. The guarded IR row
/// remains inert; consumers use this selected proof for exact binder sources.
pub struct SelectedPatternProjection {
    pub candidate: crate::analyzer::semantic::GuardedPatternProjection,
    pub binding: SelectedTupleBinding,
    receipt: crate::analyzer::i_analyzer::QueryReadReceipt,
}

impl SelectedPatternProjection {
    /// Stable content identity for the source, declaration, and model reads.
    pub fn receipt_id(&self) -> crate::analyzer::read_ledger::ReadSetDigest {
        self.receipt.digest()
    }

    /// Replay admission inputs when a selected record is reused by a consumer.
    pub fn replay_reads(&self, workspace: &WorkspaceAnalyzer) {
        self.receipt.replay(workspace.analyzer());
    }
}

impl<'a> WorkspaceSemanticOracle<'a> {
    #[cfg(any(test, feature = "test-support"))]
    pub fn conversion_lexical_work(
        &self,
        file: &crate::ProjectFile,
    ) -> crate::analyzer::lexical_definitions::LexicalIndexWork {
        self.conversion_sources
            .lexical_work(self.workspace.analyzer(), file)
    }

    /// Select the guarded pattern projections `wanted` accepts, in one pass
    /// over the procedure's candidates. A consumer asks only for the candidates
    /// it needs, so an unrelated pattern is never admitted and cannot make the
    /// answer unavailable. `None` means execution was cancelled; a candidate
    /// that hit a limit comes back as `Unavailable` with its cause and the
    /// others keep their own decisions.
    pub fn selected_pattern_projections_where(
        &self,
        procedure: &ProcedureHandle,
        request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
        mut wanted: impl FnMut(&crate::analyzer::semantic::GuardedPatternProjection) -> bool,
    ) -> Result<
        Option<Arc<[SelectedPatternProjection]>>,
        crate::analyzer::semantic::SemanticProviderError,
    > {
        let candidates = procedure.semantics().guarded_pattern_projections();
        if candidates.is_empty() {
            return Ok(Some(Arc::from([])));
        }
        let Some(support) = crate::analyzer::languages::language_support(
            procedure.artifact().key().language().language(),
        ) else {
            return Ok(Some(Arc::from([])));
        };
        let mut selected = Vec::new();
        for candidate in candidates {
            if !wanted(candidate) {
                continue;
            }
            let Some(projection) =
                self.admit_pattern_candidate(support, procedure, candidate, request)?
            else {
                return Ok(None);
            };
            selected.push(projection);
        }
        Ok(Some(Arc::from(selected)))
    }

    /// Admit the one candidate with this dense per-procedure ordinal, without
    /// visiting the others. `Ok(None)` is a cancellation, or an ordinal the
    /// procedure does not have.
    pub fn selected_pattern_projection_at(
        &self,
        procedure: &ProcedureHandle,
        ordinal: u32,
        request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<Option<SelectedPatternProjection>, crate::analyzer::semantic::SemanticProviderError>
    {
        let Some(candidate) = procedure
            .semantics()
            .guarded_pattern_projections()
            .get(ordinal as usize)
        else {
            return Ok(None);
        };
        let Some(support) = crate::analyzer::languages::language_support(
            procedure.artifact().key().language().language(),
        ) else {
            return Ok(None);
        };
        self.admit_pattern_candidate(support, procedure, candidate, request)
    }

    fn admit_pattern_candidate(
        &self,
        support: &dyn crate::analyzer::languages::LanguageSupport,
        procedure: &ProcedureHandle,
        candidate: &crate::analyzer::semantic::GuardedPatternProjection,
        request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<Option<SelectedPatternProjection>, crate::analyzer::semantic::SemanticProviderError>
    {
        if request.cancellation.is_cancelled() {
            return Ok(None);
        }
        let (answer, receipt) = crate::analyzer::i_analyzer::QueryReadReceipt::capture(
            self.workspace.analyzer(),
            || {
                self.active_semantic_models();
                support.admit_selected_tuple_binding(
                    self.workspace,
                    procedure,
                    candidate,
                    self.active_semantic_model_snapshot.as_deref(),
                    request,
                )
            },
        );
        let binding = answer?;
        // Only a cancellation interrupts the selection.
        if matches!(
            binding,
            SelectedTupleBinding::Unavailable(SelectedBindingUnavailable::Cancelled)
        ) {
            return Ok(None);
        }
        Ok(Some(SelectedPatternProjection {
            candidate: candidate.clone(),
            binding,
            receipt,
        }))
    }

    /// Prove that one selected callee cannot connect two formal referents.
    #[allow(clippy::too_many_arguments)]
    pub fn formal_footprint_certificate(
        &self,
        call: &crate::analyzer::semantic::CallSiteHandle,
        candidate: &crate::analyzer::semantic::ProcedureHandle,
        context: &crate::analyzer::semantic::OracleCallContext,
        tracked_formal: usize,
        other_formal: usize,
        request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<FormalFootprintCertificate, crate::analyzer::semantic::SemanticProviderError> {
        footprint::formal_footprint_certificate(
            self,
            call,
            candidate,
            context,
            tracked_formal,
            other_formal,
            request,
        )
    }

    fn dispatch_materialization_timer(&self) -> DispatchMaterializationTimer {
        DispatchMaterializationTimer {
            nanos: Arc::clone(&self.dispatch_materialization_ns),
            started: crate::profiling::enabled().then(std::time::Instant::now),
        }
    }

    #[doc(hidden)]
    pub fn dispatch_materialization_seconds(&self) -> f64 {
        self.dispatch_materialization_ns
            .load(std::sync::atomic::Ordering::Relaxed) as f64
            / 1e9
    }

    /// Admit reverse caller sites under their languages' selected build
    /// configurations. Unknown activity retains today's exploration behavior.
    /// The answers and language set live only for this caller query.
    pub fn caller_sites_compiled(
        &self,
        sites: &[crate::analyzer::usages::CallSite],
        cancellation: &crate::CancellationToken,
    ) -> Result<Vec<bool>, crate::analyzer::semantic::SemanticProviderError> {
        let mut compiled = vec![true; sites.len()];
        let languages = sites
            .iter()
            .map(|site| site.file.language())
            .collect::<crate::hash::HashSet<_>>();
        for language in languages {
            let Some(support) = language_support_for_hook(language, "caller_sites_compiled") else {
                continue;
            };
            let answers = support
                .caller_sites_compiled(self.workspace, sites, cancellation)
                .map_err(|error| {
                    crate::analyzer::semantic::SemanticProviderError::internal(error.to_string())
                })?;
            assert_eq!(answers.len(), sites.len());
            for (compiled, answer) in compiled.iter_mut().zip(answers) {
                *compiled &= answer;
            }
        }
        Ok(compiled)
    }

    #[doc(hidden)]
    pub fn new(workspace: &'a WorkspaceAnalyzer) -> Self {
        Self::with_limits(workspace, OracleLimits::default())
    }

    /// Bind an oracle that inherits the workspace's configured class-hierarchy
    /// expansion. Every production path constructs oracles through here or
    /// through [`Self::new`], so the host's choice reaches dispatch without any
    /// intermediate provider having to carry it.
    pub fn with_limits(workspace: &'a WorkspaceAnalyzer, limits: OracleLimits) -> Self {
        Self::with_limits_and_expansion(workspace, limits, workspace.dispatch_hierarchy_expansion())
    }

    /// Bind an oracle to an explicitly stated class-hierarchy expansion,
    /// ignoring what the workspace was configured with.
    ///
    /// This exists so a test can exercise both settings in one process. Setting
    /// the `BIFROST_CHA_CONCRETE_OVERRIDES` variable would not work for that:
    /// test threads share one process environment, and the variable is read
    /// once per process.
    pub fn with_limits_and_expansion(
        workspace: &'a WorkspaceAnalyzer,
        limits: OracleLimits,
        hierarchy_expansion: DispatchHierarchyExpansion,
    ) -> Self {
        let snapshot = workspace.analyzer().active_semantic_model_snapshot();
        Self::with_limits_expansion_and_semantic_model_snapshot(
            workspace,
            limits,
            hierarchy_expansion,
            snapshot,
            DispatchHints::empty(),
        )
    }

    /// Bind dispatch to one immutable receiver-class hint table and one
    /// explicitly captured active-model snapshot.
    pub fn with_dispatch_hints(
        workspace: &'a WorkspaceAnalyzer,
        snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
        dispatch_hints: DispatchHints,
    ) -> Self {
        Self::with_limits_expansion_and_semantic_model_snapshot(
            workspace,
            OracleLimits::default(),
            workspace.dispatch_hierarchy_expansion(),
            snapshot,
            dispatch_hints,
        )
    }

    fn with_limits_expansion_and_semantic_model_snapshot(
        workspace: &'a WorkspaceAnalyzer,
        limits: OracleLimits,
        hierarchy_expansion: DispatchHierarchyExpansion,
        active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
        dispatch_hints: DispatchHints,
    ) -> Self {
        let incoming_actuals = Arc::new(IncomingActualCache::default());
        Self {
            workspace,
            source_region: Arc::new(()),
            lexical_indexes: crate::analyzer::lexical_definitions::lexical_index_cache(
                workspace.retention_budget(),
            ),
            runtime_reads: runtime_values::runtime_read_cache(workspace.retention_budget()),
            dispatch_materialization_ns: Arc::clone(&incoming_actuals.dispatch_materialization_ns),
            incoming_actuals,
            conversion_sources: Arc::new(Default::default()),
            conversion_bindings: Arc::new(Default::default()),
            conversion_java_targets: Arc::new(crate::analyzer::usages::common::query_read_memo()),
            conversion_candidates: Arc::new(crate::analyzer::usages::common::query_read_memo()),
            conversion_rows: Arc::new(crate::analyzer::usages::common::query_read_memo()),
            conversion_effects: Arc::new(crate::analyzer::usages::common::query_read_memo()),
            runtime_syntax: workspace.analyzer().snapshot_caches().map_or_else(
                || runtime_syntax_cache(workspace.retention_budget()),
                |caches| caches.runtime_syntax().clone(),
            ),
            runtime_write_footprints: runtime_values::attributed_runtime_write_footprint_cache(
                workspace.retention_budget(),
            ),
            limits,
            hierarchy_expansion,
            active_semantic_model_snapshot,
            dispatch_hints: Arc::new(dispatch_hints),
            python_saved_default_safety: crate::analyzer::languages::registered_language_supports()
                .find_map(|support| support.saved_default_argument_safety(workspace.analyzer())),
        }
    }

    pub(crate) fn python_saved_default_safety(&self) -> Option<&SavedDefaultArgumentSafety> {
        let safety = self.python_saved_default_safety.as_deref()?;
        crate::analyzer::workspace_authority::record_workspace_authority_read(
            self.workspace.analyzer(),
            crate::analyzer::WorkspaceFactFamily::PythonSavedDefaults,
            crate::analyzer::AuthorityInputs::Fact {
                language: crate::analyzer::Language::Python,
                subject: crate::analyzer::FactSubject::Whole,
                answer: safety.fact_fingerprint(),
            },
        );
        Some(safety)
    }

    pub(crate) fn python_saved_default_is_available(
        &self,
        callee: &ProcedureHandle,
        passing_mode: FormalParameterPassingMode,
    ) -> Option<bool> {
        self.python_saved_default_safety()
            .map(|safety| safety.default_is_available(callee.semantics().locator(), passing_mode))
    }

    pub const fn workspace(&self) -> &'a WorkspaceAnalyzer {
        self.workspace
    }

    pub const fn limits(&self) -> &OracleLimits {
        &self.limits
    }

    /// Which class-hierarchy expansions this oracle's dispatch may add.
    pub const fn hierarchy_expansion(&self) -> DispatchHierarchyExpansion {
        self.hierarchy_expansion
    }

    pub fn active_semantic_models(&self) -> Option<&Arc<ResolvedActiveSemanticModels>> {
        self.workspace
            .analyzer()
            .record_read(crate::analyzer::ReadKey::Models(
                crate::analyzer::i_analyzer::current_model_set_digest(
                    self.active_semantic_model_snapshot
                        .as_ref()
                        .map(|snapshot| snapshot.active_models().active_model_set_hash()),
                ),
            ));

        match self.active_semantic_model_snapshot.as_ref() {
            Some(snapshot) => Some(snapshot.active_models()),
            None => None,
        }
    }

    #[doc(hidden)]
    pub fn active_semantic_model_snapshot(&self) -> Option<Arc<ActiveSemanticModelSnapshot>> {
        self.active_semantic_models();

        self.active_semantic_model_snapshot.as_ref().map(Arc::clone)
    }

    pub(super) fn semantic_model_overlay(&self) -> Option<Arc<SemanticModelOverlay>> {
        self.active_semantic_models();

        self.active_semantic_model_snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.overlay())
    }

    pub const fn dispatch_hints(&self) -> &Arc<DispatchHints> {
        &self.dispatch_hints
    }
}

impl fmt::Debug for WorkspaceSemanticOracle<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkspaceSemanticOracle")
            .field("limits", &self.limits)
            .field("hierarchy_expansion", &self.hierarchy_expansion)
            .field(
                "has_semantic_model_overlay",
                &self
                    .active_semantic_model_snapshot
                    .as_ref()
                    .is_some_and(|snapshot| snapshot.semantic_model_overlay().is_some()),
            )
            .field("dispatch_hints", &self.dispatch_hints.entries().len())
            .finish_non_exhaustive()
    }
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) use value_flow::project_procedure_relations;
