use std::collections::HashMap;
use std::fmt;
use std::ops::Range as ByteRange;
use std::sync::Arc;

use crate::definition::{RowBindingName, RowBindingSource, RowExpansionStep};
use crate::relational::{
    RelationCoverage, RelationalInput, evaluate_row_selector_ir, validate_row_selector_plan,
};
use crate::resolved::LoadedPolicy;
use crate::unit_execution::{UnitAttempt, UnitReuse, recompute_unit};
use crate::units::{
    PolicyIncrementalContext, PolicyUnitKey, PolicyUnitProduct, SelectorProduct,
    SelectorProductSite, UnitPartition, WidenReason,
};
use crate::{PolicyWorkMetric, PolicyWorkReport, PolicyWorkUnit, ResolvedPolicySelector};
use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::common::language_for_file;
use brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest;
use brokk_bifrost_analysis::analyzer::semantic::{
    CallBinding, CallSiteHandle, CallerReceiverBinding, CandidateCoverage, DispatchOracle,
    DurablePortIdentity, EvidenceCompleteness, OracleCallContext, ProcedureHandle, ProofStatus,
    SemanticArtifact, SemanticArtifactLeaseCharge, SemanticArtifactLeaseChild,
    SemanticArtifactLeaseError, SemanticArtifactLeaseSet, SemanticArtifactLeaseWindow,
    SemanticBudget, SemanticBudgetDimension, SemanticBudgetScopeSnapshot, SemanticExecutionBudget,
    SemanticOutcome, SemanticProviderError, SemanticRequest, SemanticWork, ValueFlowOracle,
    ValueId,
};
use brokk_bifrost_analysis::analyzer::usages::effects::EffectCoverage;
use brokk_bifrost_analysis::analyzer::{ProjectFile, Range, ReadKey, WorkspaceAnalyzer};
use brokk_bifrost_analysis::path_utils::rel_path_string;
use brokk_bifrost_rql::structural::search::{
    CodeQueryExecutionScope, CodeQuerySemanticReceipt, DetailedCodeQueryDecoratedParameterEvidence,
    DetailedCodeQueryDomain, DetailedCodeQueryEvidence, UnitExecutionResult, UnitRowItem,
    execute_code_query_detailed_eager_index_workspace_with_semantic_receipt,
    execute_code_query_selector_unit, merge_unit_rows, plan_seed_files,
};
use brokk_bifrost_rql::structural::{
    CodeQueryCompletion, CodeQueryDiagnosticCode, CodeQueryDiagnosticImpact,
    CodeQueryExecutionLimits, CodeQueryExecutionWork, CodeQueryResult, CodeQueryResultDetail,
    CodeQueryResultItem, CodeQueryResultValue, CodeQuerySemanticCompleteness,
    CodeQuerySemanticEvidence, CodeQuerySemanticLimits, CodeQuerySemanticProof,
    CodeQuerySemanticRowLimits, CodeQuerySemanticWork, QueryValueKind,
};
use brokk_bifrost_rql::{
    CallInputSelector, CodeQuery, CodeQueryPlan, CodeQueryPlanSource, PlanPartitioning, QueryStep,
};

#[derive(Debug)]
pub(super) enum PolicySelectorSessionError {
    Incomplete {
        completion: CodeQueryCompletion,
        detail: String,
    },
    Unavailable(String),
    Provider(String),
    /// The sliced compile cannot claim to have produced what a whole compile
    /// would have produced, and the caller must compile the policy again with
    /// no units. Not a failure: the reason says which step refused, and the
    /// answer is the compile this session was avoiding
    /// (`.agents/plans/impact-sliced-diff-base.md`, "The head algorithm").
    Widen(WidenReason),
}

impl fmt::Display for PolicySelectorSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete { detail, .. }
            | Self::Unavailable(detail)
            | Self::Provider(detail) => formatter.write_str(detail),
            Self::Widen(reason) => write!(
                formatter,
                "the sliced selector compile widened: {}",
                reason.stable_label()
            ),
        }
    }
}

#[derive(Clone)]
pub(super) struct PolicySelectedSite {
    pub(super) file: ProjectFile,
    pub(super) span: ByteRange<usize>,
    pub(super) proof: ProofStatus,
    pub(super) completeness: EvidenceCompleteness,
    pub(super) result_contract: Option<PolicyResultContractSelection>,
    pub(super) call_shape: Option<PolicyCallShapeSelection>,
    pub(super) call_binding: Option<PolicySelectedCallBinding>,
    /// Exact semantic value/parameter-port identity retained by a complete
    /// decorated-parameter query row. The corresponding artifact dependency
    /// is admitted into this selector session before the row escapes.
    pub(super) decorated_parameter: Option<PolicyDecoratedParameterSelection>,
    /// This exact row came from the narrowly retained positive subset of an
    /// otherwise incomplete result-contract query.
    pub(super) retained_incomplete_result_contract_query: bool,
}

#[derive(Clone)]
pub(super) struct PolicyDecoratedParameterSelection {
    pub(super) value_locator:
        brokk_bifrost_analysis::analyzer::semantic::ProcedureLocalLocator<ValueId>,
    pub(super) port: brokk_bifrost_analysis::analyzer::semantic::DurablePortIdentity,
}

fn query_plan_contains_decorator_bindings(plan: &CodeQueryPlan) -> bool {
    let mut pending = vec![plan];
    while let Some(plan) = pending.pop() {
        if plan
            .steps
            .iter()
            .any(|step| matches!(step, QueryStep::DecoratorBindings(_)))
        {
            return true;
        }
        if let CodeQueryPlanSource::Set { branches, .. } = &plan.source {
            pending.extend(branches);
        }
    }
    false
}

impl From<DetailedCodeQueryDecoratedParameterEvidence> for PolicyDecoratedParameterSelection {
    fn from(value: DetailedCodeQueryDecoratedParameterEvidence) -> Self {
        Self {
            value_locator: value.value_locator,
            port: value.port,
        }
    }
}

#[derive(Clone)]
pub(super) struct PolicyResultContractSelection {
    pub(super) result_ordinal: u32,
    pub(super) fresh_allocation: bool,
    pub(super) success_guard_coverage: EffectCoverage,
    pub(super) success_guard_edges:
        Vec<brokk_bifrost_analysis::analyzer::semantic::ControlEdgeLocator>,
    pub(super) possible_success_guard_edges:
        Vec<brokk_bifrost_analysis::analyzer::semantic::ControlEdgeLocator>,
    pub(super) member_contracts:
        Vec<brokk_bifrost_analysis::analyzer::semantic_model::CompiledResultMemberContract>,
}

#[derive(Clone)]
pub(super) struct PolicyCallShapeSelection {
    pub(super) callee_name: Option<String>,
    pub(super) argument_count: u32,
}

/// Whether a receiver-bound endpoint applies to one selected source call.
///
/// A structural selector can name syntax such as Go `package.Name(...)` that
/// looks like member access while local callable evidence or exact dispatch
/// proves it is a package function. `ExactNonMatch` is reserved for those
/// proven cases. An absent caller-side receiver without complete evidence
/// stays `Indeterminate`, so the policy compiler preserves its existing
/// fail-closed diagnostic rather than treating missing semantic support as a
/// clean miss.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReceiverBindingApplicability {
    Applicable,
    /// The lowered call has one consistent caller-side receiver, but dispatch
    /// cannot yet prove whether it is a method or a function-valued field.
    /// Consumers may inspect that structured receiver as partial evidence;
    /// they must not turn a possible match into a definite finding.
    CandidateReceiver,
    ExactNonMatch,
    Indeterminate,
    Inconsistent,
}

struct PolicySelectorQueryResult {
    result: CodeQueryResult,
    evidence: Vec<DetailedCodeQueryEvidence>,
    artifact_charge: Option<SemanticArtifactLeaseCharge>,
    retained_incomplete_result_contracts: bool,
}

/// Admit a positive result-contract subset when only its guard/use derivation
/// is incomplete.
///
/// The typed contract row independently proves result identity and reviewed
/// member metadata. A converted condition result can therefore make that row
/// partial without erasing it. This exception remains deliberately narrow:
/// terminal rows, non-exhaustive dispatch, unproven rows, truncation, any other
/// incomplete diagnostic, cancellation, and invalid queries still fail closed.
/// Declared-non-exhaustive diagnostics may coexist with these exact positive
/// rows: they open the run but do not invalidate evidence already proven.
fn retains_independently_proven_result_contracts(
    result: &CodeQueryResult,
    evidence: &[DetailedCodeQueryEvidence],
) -> bool {
    let CodeQueryCompletion::Incomplete { codes } = result.completion() else {
        return false;
    };
    if result.truncated
        || codes.is_empty()
        || codes
            .iter()
            .any(|code| *code != CodeQueryDiagnosticCode::ResultContractDerivationIncomplete)
        || result
            .diagnostics
            .iter()
            .any(|diagnostic| match diagnostic.impact {
                CodeQueryDiagnosticImpact::Advisory
                | CodeQueryDiagnosticImpact::DeclaredNonExhaustive => false,
                CodeQueryDiagnosticImpact::Incomplete => {
                    diagnostic.code != CodeQueryDiagnosticCode::ResultContractDerivationIncomplete
                }
                CodeQueryDiagnosticImpact::Invalid => true,
            })
    {
        return false;
    }

    let mut retained = false;
    for evidence in evidence
        .iter()
        .filter(|evidence| !matches!(evidence.domain, DetailedCodeQueryDomain::File))
    {
        let Some(item) = result.results.get(evidence.result_index) else {
            return false;
        };
        match &item.value {
            CodeQueryResultValue::CallResultContract { value }
                if !value.terminal
                    && value.result_ordinal.is_some()
                    && value.proof == Some("proven")
                    && value.coverage == "exhaustive" =>
            {
                retained = true;
            }
            _ => return false,
        }
    }
    retained
}

pub(super) type PolicyArtifactLeases = SemanticArtifactLeaseSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PolicySemanticPeaks {
    pub(super) row_dimension: usize,
    pub(super) retained_bytes: usize,
    pub(super) traversal_steps: usize,
}

impl PolicySemanticPeaks {
    /// Extend one compile-time semantic region through a child evaluation.
    ///
    /// The child scalar ledger starts at zero with the parent's remaining
    /// allowance, so its row and owned-text work are incremental and must be
    /// added to the compile work exactly once. The lease child already
    /// contains the compile-time base allocations, while the execution budget
    /// is the same shared ledger used during compilation; those two cumulative
    /// quantities must therefore be compared with the compile peak, not added
    /// to it.
    pub(super) fn with_child_evaluation(
        self,
        compile_work: SemanticWork,
        evaluation_work: SemanticWork,
        evaluation_retained_peak: usize,
        cumulative_traversal_steps: usize,
    ) -> Self {
        let total_work = compile_work
            .checked_add(evaluation_work)
            .expect("a bounded semantic child fits its parent's original limits");
        let row_dimension = CodeQuerySemanticRowLimits::ROW_DIMENSIONS
            .into_iter()
            .map(|dimension| total_work.get(dimension))
            .max()
            .unwrap_or(0);
        Self {
            row_dimension: self.row_dimension.max(row_dimension),
            retained_bytes: self
                .retained_bytes
                .max(total_work.owned_text_bytes)
                .max(evaluation_retained_peak),
            traversal_steps: self.traversal_steps.max(cumulative_traversal_steps),
        }
    }
}

pub(super) struct PolicySemanticLeaseWindow {
    child: SemanticArtifactLeaseChild,
    window: SemanticArtifactLeaseWindow,
}

impl PolicySemanticLeaseWindow {
    fn new(leases: &SemanticArtifactLeaseSet) -> Self {
        let mut child = leases.snapshot().into_child();
        let window = child.begin_window(0);
        Self { child, window }
    }

    pub(super) fn collector(
        &self,
    ) -> brokk_bifrost_analysis::analyzer::semantic::SemanticArtifactCollector {
        self.window.collector()
    }

    fn overflow(&self) -> Option<SemanticArtifactLeaseError> {
        self.window.overflow()
    }

    pub(super) fn contains_exact(&self, artifact: &Arc<SemanticArtifact>) -> bool {
        self.window.contains_exact(artifact)
    }

    fn into_charge(self) -> Result<SemanticArtifactLeaseCharge, SemanticArtifactLeaseError> {
        let Self { mut child, window } = self;
        window.commit(&mut child)?;
        Ok(child.into_charge())
    }

    pub(super) fn discard(self) {
        let Self { child, window } = self;
        window.discard();
        drop(child);
    }

    pub(super) fn finish_scalar<R>(
        self,
        value: R,
        operation: &str,
    ) -> Result<R, PolicySelectorSessionError> {
        let error = self.overflow();
        self.discard();
        if let Some(error) = error {
            return Err(semantic_budget_error(format!(
                "{operation} exhausted the shared semantic retained-artifact budget: {error}"
            )));
        }
        Ok(value)
    }
}

pub(super) struct PolicySemanticContinuation<T> {
    // Keep the outcome first so ordinary field drop releases every handle
    // before the bounded lease window is discarded.
    outcome: SemanticOutcome<T>,
    leases: PolicySemanticLeaseWindow,
}

impl<T> PolicySemanticContinuation<T> {
    pub(super) fn outcome(&self) -> &SemanticOutcome<T> {
        &self.outcome
    }

    pub(super) fn contains_exact(&self, artifact: &Arc<SemanticArtifact>) -> bool {
        self.leases.contains_exact(artifact)
    }

    pub(super) fn commit(
        self,
        session: &mut PolicySelectorSession<'_>,
        operation: &str,
    ) -> Result<SemanticOutcome<T>, PolicySelectorSessionError> {
        let Self { outcome, leases } = self;
        session.apply_artifact_charge(leases.into_charge(), operation)?;
        Ok(outcome)
    }

    pub(super) fn finish_scalar<R>(
        self,
        value: R,
        operation: &str,
    ) -> Result<R, PolicySelectorSessionError> {
        let Self { outcome, leases } = self;
        drop(outcome);
        leases.finish_scalar(value, operation)
    }
}

/// Structured relational identity retained from one selected `call_binding` row.
///
/// `actual_index` is the caller-side operand ordinal. `formal_index` is kept
/// only as evidence and must never be passed to a `PolicyPort::ArgumentIndex`.
#[derive(Clone)]
pub(super) struct PolicySelectedCallBinding {
    pub(super) row_id: String,
    pub(super) site_id: String,
    pub(super) site_ast_id: String,
    pub(super) argument_id: String,
    pub(super) call_span: ByteRange<usize>,
    pub(super) actual_index: usize,
    pub(super) formal_index: usize,
    pub(super) formal_name: String,
    pub(super) semantic_target_id: String,
    pub(super) model_callable_id: String,
    pub(super) formal_layout_id: String,
    pub(super) signature_id: Option<String>,
    pub(super) model_id: Option<String>,
    pub(super) pack_id: Option<String>,
    pub(super) selector_proof: &'static str,
    pub(super) selector_summary_id: Option<String>,
    pub(super) selector_summary_model_id: Option<String>,
    pub(super) selector_summary_pack_id: Option<String>,
    pub(super) selector_summary_pack_digest: Option<String>,
}

impl PolicySelectedCallBinding {
    pub(super) fn assert_valid_identity(&self) {
        debug_assert!(!self.row_id.is_empty());
        debug_assert!(!self.site_id.is_empty());
        debug_assert!(!self.site_ast_id.is_empty());
        debug_assert!(!self.argument_id.is_empty());
        debug_assert!(!self.semantic_target_id.is_empty());
        debug_assert!(!self.model_callable_id.is_empty());
        debug_assert!(!self.formal_layout_id.is_empty());
        debug_assert!(self.signature_id.as_ref().is_none_or(|id| !id.is_empty()));
        debug_assert!(self.model_id.as_ref().is_none_or(|id| !id.is_empty()));
        debug_assert!(self.pack_id.as_ref().is_none_or(|pack| !pack.is_empty()));
        debug_assert!(matches!(
            self.selector_proof,
            "declared" | "derived" | "authored_summary"
        ));
        debug_assert!(
            self.selector_proof != "declared"
                || (self.signature_id.is_some() && self.model_id.is_some())
        );
        debug_assert_eq!(
            self.selector_proof == "authored_summary",
            self.selector_summary_id.is_some()
                && self.selector_summary_model_id.is_some()
                && self.selector_summary_pack_id.is_some()
                && self.selector_summary_pack_digest.is_some()
        );
    }
}

pub(super) struct PolicySelectorSession<'a> {
    workspace: &'a WorkspaceAnalyzer,
    analysis: &'static str,
    query_limits: CodeQueryExecutionLimits,
    max_selector_results: usize,
    cancellation: &'a CancellationToken,
    /// Which files every selector this session runs enumerates seeds over.
    ///
    /// The whole analyzed file set by default, which is byte for byte what
    /// every selector did before units existed. A caller compiling one
    /// selector unit per seed file narrows it, and only the seed enumeration
    /// narrows: callers, importers, descendants, dispatch and references still
    /// answer over the whole workspace, because those answers are what make a
    /// finding in an unedited file change.
    execution_scope: CodeQueryExecutionScope<'a>,
    /// The per-seed selector units this compile may reuse, when it holds an
    /// incremental context. Absent for a compile that has nothing to reuse and
    /// for every family that does not unitize its selectors, which then run
    /// byte for byte as they always have.
    units: Option<SelectorUnits<'a>>,
    semantic_budget: SemanticBudget,
    semantic_execution_budget: SemanticExecutionBudget,
    query_work: CodeQueryExecutionWork,
    artifacts: HashMap<ProjectFile, Arc<SemanticArtifact>>,
    artifact_leases: PolicyArtifactLeases,
    materialized_files_limit: usize,
    // Semantic work retired by prior regions. `reset_region_semantic_budget`
    // replaces the live budgets, so their `used`/`work` counters only reflect
    // the current region; without this the reported work would collapse to the
    // last region's consumption. Accumulating the consumed counters here keeps
    // the compile-wide work report accurate. The materialization cache charges
    // each distinct file once, in whichever region first pulls it, so summing
    // per-region charges still totals distinct materializations, not duplicates.
    retired_program_points: usize,
    retired_source_bytes: usize,
    retired_materialized_files: usize,
    retired_traversal_steps: usize,
    // The largest single-region charge each per-region lane saw.  The lane
    // limits are per region -- `reset_region_semantic_budget` restores them --
    // so the quantity a lane must exceed for the compile to finish is the peak
    // one region reaches, not the sum the retired counters above accumulate.
    // These are the calibration inputs the derived-lane model never had (#1936).
    peak_row_dimension: usize,
    peak_retained_bytes: usize,
    peak_traversal_steps: usize,
    live_selector_retained_peak: usize,
    // How many procedure value-flow snapshots this compile actually built
    // through the semantic oracle, as opposed to reusing from the per-compile
    // materialization cache (#2284). The per-region budget resets above hide
    // this in the program-point total, and the program-point total also mixes
    // in dispatch, binding, and solve work, so a repeated materialization is
    // not visible there. This counter is: it must equal the number of distinct
    // procedures the compile reached, whatever their snapshots' completeness.
    semantic_snapshot_materializations: u64,
    // How many procedure visits this compile served on a handle that named a
    // second materialization of an artifact it had already seen (#2289). Keyed
    // on handles, each of those visits missed the discovery cache and re-ran
    // the oracle for the procedure's snapshot, each of its call sites'
    // dispatch, and each candidate's bindings; keyed durably they are hits. A
    // non-zero value here means the byte-bounded artifact cache is evicting
    // files this compile is still walking, which is worth knowing on its own.
    semantic_handle_identity_reuses: u64,
    // How many selector entries this compile scanned.  Each scan is granted the
    // whole-workspace scan allowance (see `remaining_query_limits`), so this is
    // the multiplier on that allowance the compile actually spent.
    selector_scans: u64,
    // Exact allocations first admitted from result-contract query receipts.
    // Later direct materialization can retain the same allocation, so keeping
    // this boundary-specific count makes immediate receipt adoption auditable.
    result_contract_artifact_leases: usize,
    // Result-contract selectors whose exact positive rows were retained while
    // guard/use projection remained incomplete. Typestate carries this query-
    // level fact into its final completion even when no row can seed a subject.
    retained_incomplete_result_contract_selectors: usize,
}

impl<'a> PolicySelectorSession<'a> {
    /// `execution_scope` is which files every selector of this session
    /// enumerates seeds over. A per-seed selector unit passes its one seed
    /// file; everything else passes
    /// [`CodeQueryExecutionScope::whole_workspace`] and executes byte for byte
    /// as it always has.
    pub(super) fn new(
        workspace: &'a WorkspaceAnalyzer,
        analysis: &'static str,
        query_limits: CodeQueryExecutionLimits,
        max_selector_results: usize,
        cancellation: &'a CancellationToken,
        execution_scope: CodeQueryExecutionScope<'a>,
    ) -> Self {
        // Size the materialized-file budget to the workspace, not the fixed
        // per-query IDE cap. That cap bounds how much a single interactive query
        // loads; a policy compile is a whole-workspace analysis that must reach
        // every source and sink, so on a corpus larger than the cap the endpoint
        // enumeration exhausts it before discovery even begins and the whole
        // compile abstains (#1936). The content-keyed materialization cache makes
        // the real cost proportional to distinct files, which cannot exceed the
        // project file count, so this is a principled bound rather than an
        // uncapped one. `max` keeps the per-query default as the floor, so a
        // small workspace is unaffected. The per-region traversal budget, reset
        // in `reset_region_semantic_budget`, still bounds each region's work.
        let materialized_files_limit = query_limits
            .semantic
            .max_materialized_files
            .max(workspace.project_file_count());
        Self {
            workspace,
            analysis,
            query_limits,
            max_selector_results,
            cancellation,
            execution_scope,
            units: None,
            semantic_budget: SemanticBudget::new(semantic_work_limits(query_limits.semantic))
                .expect("validated CodeQuery semantic limits are positive"),
            semantic_execution_budget: SemanticExecutionBudget::new(
                materialized_files_limit,
                query_limits.semantic.max_traversal_steps,
            ),
            query_work: CodeQueryExecutionWork::default(),
            artifacts: HashMap::new(),
            artifact_leases: SemanticArtifactLeaseSet::new(
                query_limits.semantic.max_retained_bytes,
            ),
            materialized_files_limit,
            retired_program_points: 0,
            retired_source_bytes: 0,
            retired_materialized_files: 0,
            retired_traversal_steps: 0,
            peak_row_dimension: 0,
            peak_retained_bytes: 0,
            peak_traversal_steps: 0,
            live_selector_retained_peak: 0,
            semantic_snapshot_materializations: 0,
            semantic_handle_identity_reuses: 0,
            selector_scans: 0,
            result_contract_artifact_leases: 0,
            retained_incomplete_result_contract_selectors: 0,
        }
    }

    /// Record how many procedure value-flow snapshots discovery built through
    /// the oracle rather than reusing cached outcomes (#2284, #2951).
    pub(super) fn record_semantic_snapshot_materializations(&mut self, count: u64) {
        self.semantic_snapshot_materializations = self
            .semantic_snapshot_materializations
            .saturating_add(count);
    }

    /// Record how many procedure visits this compile served on a handle from a
    /// second materialization of one artifact (#2289).
    pub(super) fn record_semantic_handle_identity_reuses(&mut self, reuses: u64) {
        self.semantic_handle_identity_reuses =
            self.semantic_handle_identity_reuses.saturating_add(reuses);
    }

    /// Reset the semantic and execution budgets to their per-region starting
    /// limits.
    ///
    /// Require-model taint discovers and solves each source-to-sink region
    /// independently (#1935). Charging every region against one shared budget
    /// makes an N-file corpus abstain by accumulation, even though each region's
    /// own materialization is small: at corpus scale the shared `nested_entries`
    /// lane crosses its cap after ~76 files and the whole compile aborts.
    /// Resetting per region bounds each region on its own and lets independent
    /// flows all be analyzed. The shared materialization caches (the `#1936`
    /// discovery cache and the semantic artifact cache) are untouched, so
    /// cross-region work stays amortized and each region's budget only accounts
    /// for the material it newly pulls.
    pub(super) fn reset_region_semantic_budget(&mut self) {
        // Retire the finishing region's consumed work before the counters are
        // discarded, so the compile-wide work report stays a running total.
        let used = self.semantic_budget.used();
        self.retired_program_points = self
            .retired_program_points
            .saturating_add(used.program_points);
        self.retired_source_bytes = self.retired_source_bytes.saturating_add(used.source_bytes);
        let execution = self.semantic_execution_budget.work();
        self.retired_materialized_files = self
            .retired_materialized_files
            .saturating_add(execution.materialized_files);
        self.retired_traversal_steps = self
            .retired_traversal_steps
            .saturating_add(execution.traversal_steps);
        let (row_peak, retained_peak, traversal_peak) = self.live_region_peaks();
        self.peak_row_dimension = self.peak_row_dimension.max(row_peak);
        self.peak_retained_bytes = self.peak_retained_bytes.max(retained_peak);
        self.peak_traversal_steps = self.peak_traversal_steps.max(traversal_peak);

        self.semantic_budget =
            SemanticBudget::new(semantic_work_limits(self.query_limits.semantic))
                .expect("validated CodeQuery semantic limits are positive");
        self.semantic_execution_budget = SemanticExecutionBudget::new(
            self.materialized_files_limit,
            self.query_limits.semantic.max_traversal_steps,
        );
        self.live_selector_retained_peak = 0;
    }

    /// The source spans of the actuals one selector's call sites pass to the
    /// formal named `name`, through the analyzer's own actual-to-formal
    /// relation (`call-input :parameter-name`, issue #2438).
    ///
    /// This is the second of the two sources a formal-name port reads. The
    /// dispatch-aware oracle relation is the first and the authoritative one,
    /// but the semantic call row records only that an actual is a keyword
    /// argument, never which keyword, so the oracle retains no mapping for
    /// `put(value=x)`. The structural relation reads the label from the call's
    /// own syntax and is exactly what `(call-input :parameter-name "value")`
    /// publishes, so a port and a query row cannot disagree about which operand
    /// the formal names.
    ///
    /// The result is a flat span list per file, not a per-call map, because a
    /// row's evidence carries only its own byte span. The caller intersects it
    /// with one selected call's own operand spans, which is what distinguishes
    /// a nested call's actual from the enclosing call's.
    pub(super) fn select_named_actuals(
        &mut self,
        selector: &ResolvedPolicySelector,
        name: &str,
    ) -> Result<Vec<(ProjectFile, ByteRange<usize>)>, PolicySelectorSessionError> {
        let Some((_, query)) = selector.as_query() else {
            return Err(PolicySelectorSessionError::Unavailable(format!(
                "selector `{}` is relational; its exact call-binding row must supply the actual directly",
                selector.path
            )));
        };
        let mut query = query.clone();
        query.limit = self.max_selector_results;
        query
            .plan
            .steps
            .push(QueryStep::CallInput(CallInputSelector::ParameterName(
                name.to_owned(),
            )));
        // A selector that does not end at call sites cannot carry a call-input
        // step. That is a typed shortfall of this route, not a failure: the
        // caller falls back to refusing the row with a named reason.
        if query.validate_steps().is_err() {
            return Ok(Vec::new());
        }
        self.selector_scans = self.selector_scans.saturating_add(1);
        let query_limits = self.remaining_query_limits()?;
        let artifact_leases = self.artifact_leases.snapshot();
        let mut detailed = execute_code_query_detailed_eager_index_workspace_with_semantic_receipt(
            self.workspace,
            &query,
            query_limits,
            Some(self.cancellation),
            &self.semantic_budget,
            &self.semantic_execution_budget,
            artifact_leases,
            self.execution_scope,
        );
        let semantic_receipt = detailed.take_semantic_receipt();
        self.query_work = self.query_work.saturating_add(detailed.work);
        self.charge_query_semantic_work(detailed.work.semantic, semantic_receipt)?;
        if !matches!(detailed.result.completion(), CodeQueryCompletion::Complete) {
            return Ok(Vec::new());
        }
        Ok(detailed
            .evidence
            .into_iter()
            .filter(|evidence| matches!(evidence.domain, DetailedCodeQueryDomain::ExpressionSite))
            .filter_map(|evidence| Some((evidence.file, evidence.byte_span?)))
            .collect())
    }

    pub(super) fn select(
        &mut self,
        selector: &ResolvedPolicySelector,
    ) -> Result<Vec<PolicySelectedSite>, PolicySelectorSessionError> {
        if let Some(plan) = selector.as_rows() {
            return self.select_rows(selector, plan);
        }
        let query = self.selector_query(selector)?;
        let retain_decorated_parameter_artifacts =
            query_plan_contains_decorator_bindings(&query.plan);
        let detailed = if retain_decorated_parameter_artifacts {
            self.execute_selector_query_with_artifact_continuation(&query)?
        } else {
            self.execute_selector_query(&query)?
        };
        let (selected, artifact_charge) = Self::selected_sites(selector, detailed)?;
        if let Some(artifact_charge) = artifact_charge {
            self.apply_artifact_charge(
                Ok(artifact_charge),
                "selector decorated-parameter continuation",
            )?;
        }
        Ok(selected)
    }

    /// Compile this session's selectors one seed file at a time, reusing what
    /// a previous run published.
    ///
    /// Called once per compile, before any selector runs. A session that is
    /// never given units executes every selector over the whole workspace,
    /// which is byte for byte what every family did before units existed.
    pub(super) fn with_units(
        &mut self,
        policy: &'a LoadedPolicy,
        incremental: &'a PolicyIncrementalContext<'a>,
        budget: &'a crate::budget::PolicyBudget,
    ) {
        self.units = Some(SelectorUnits::new(
            policy,
            incremental,
            budget,
            self.workspace,
        ));
    }

    /// The keys this compile decided about and what it did with them.
    pub(super) fn take_units(&mut self) -> Option<SelectorUnitOutcome> {
        self.units.take().map(SelectorUnits::into_outcome)
    }

    pub(super) fn select_with_artifact_continuation(
        &mut self,
        selector: &ResolvedPolicySelector,
    ) -> Result<Vec<PolicySelectedSite>, PolicySelectorSessionError> {
        if let Some(plan) = selector.as_rows() {
            return self.select_rows(selector, plan);
        }
        let query = self.selector_query(selector)?;
        if self.units.is_some() {
            return self.select_sliced(selector, &query);
        }
        let detailed = self.execute_selector_query_with_artifact_continuation(&query)?;
        let retained_incomplete_result_contracts = detailed.retained_incomplete_result_contracts;
        let (selected, artifact_charge) = Self::selected_sites(selector, detailed)?;
        if retained_incomplete_result_contracts {
            self.retained_incomplete_result_contract_selectors = self
                .retained_incomplete_result_contract_selectors
                .saturating_add(1);
        }
        #[cfg(any(test, feature = "test-support"))]
        let promoted_artifacts = artifact_charge
            .as_ref()
            .is_some_and(|charge| !charge.is_empty());
        if let Some(artifact_charge) = artifact_charge {
            let retained_before = self.artifact_leases.len();
            self.apply_artifact_charge(
                Ok(artifact_charge),
                "selector result-contract continuation",
            )?;
            self.result_contract_artifact_leases = self
                .result_contract_artifact_leases
                .saturating_add(self.artifact_leases.len().saturating_sub(retained_before));
        }
        #[cfg(any(test, feature = "test-support"))]
        if promoted_artifacts && !selected.is_empty() {
            self.workspace
                .analyzer()
                .test_hooks()
                .invalidate_selector_continuation_semantic_cache_if_armed_for_test();
        }
        Ok(selected)
    }

    /// Compile one selector as the merge of one execution per seed file.
    ///
    /// The units are taken out of the session for the duration, because every
    /// unit's execution charges the session's own ledgers and the two cannot
    /// be borrowed at once. They go back in either way: a widened compile
    /// still reports what its attempt did.
    fn select_sliced(
        &mut self,
        selector: &ResolvedPolicySelector,
        query: &CodeQuery,
    ) -> Result<Vec<PolicySelectedSite>, PolicySelectorSessionError> {
        let mut units = self
            .units
            .take()
            .expect("a sliced selector compile holds its units");
        let selected = self.select_sliced_units(&mut units, selector, query);
        if let Err(PolicySelectorSessionError::Widen(reason)) = &selected {
            units.widened(*reason);
        }
        self.units = Some(units);
        selected
    }

    fn select_sliced_units(
        &mut self,
        units: &mut SelectorUnits<'_>,
        selector: &ResolvedPolicySelector,
        query: &CodeQuery,
    ) -> Result<Vec<PolicySelectedSite>, PolicySelectorSessionError> {
        self.selector_scans = self.selector_scans.saturating_add(1);
        let seed_files = units.enumerate(query, selector.path.as_str())?;
        let mut products = Vec::with_capacity(seed_files.len());
        let mut selected = Vec::new();
        for (index, file) in seed_files.iter().enumerate() {
            let rows = match units.published(index)? {
                Some(product) => {
                    // The unit's own execution moved the compile's shared
                    // semantic ledgers, and reusing it must move them the same
                    // way or the next unit would run under an allowance no
                    // whole compile would have given it.
                    self.charge_stored_selector_work(&product)?;
                    selected.extend(units.sites(&product)?);
                    product.rows
                }
                None => {
                    let executed = self.execute_selector_unit(units, selector, query, file)?;
                    selected.extend(executed.sites.iter().cloned());
                    units.publish(index, &executed);
                    executed.rows
                }
            };
            check_exhaustive_selector_rows(&rows)?;
            products.push(rows);
        }
        let merged = merge_unit_rows(products);
        // Every cumulative cap the whole execution enforces, summed over the
        // units. Reaching one means the whole execution might have truncated
        // somewhere in its own order, so the merged rows are not its rows.
        if merged
            .reached_limit(&self.query_limits, query.limit)
            .is_some()
        {
            return Err(PolicySelectorSessionError::Widen(
                WidenReason::MergedLimitReached,
            ));
        }
        Ok(selected)
    }

    /// Run one seed file's execution of one selector, and read its sites.
    fn execute_selector_unit(
        &mut self,
        units: &SelectorUnits<'_>,
        selector: &ResolvedPolicySelector,
        query: &CodeQuery,
        file: &ProjectFile,
    ) -> Result<ExecutedSelectorUnit, PolicySelectorSessionError> {
        let query_limits = self.remaining_query_limits()?;
        let artifact_leases = self.artifact_leases.snapshot();
        let semantic_before = self.semantic_budget.used();
        let execution_before = self.semantic_execution_budget.work();
        let (executed, reads) = recompute_unit(self.workspace.analyzer(), || {
            execute_code_query_selector_unit(
                self.workspace,
                query,
                query_limits,
                Some(self.cancellation),
                &self.semantic_budget,
                &self.semantic_execution_budget,
                artifact_leases,
                CodeQueryExecutionScope::for_seed_files(
                    std::slice::from_ref(file),
                    &units.workspace_files,
                ),
            )
        });
        let mut detailed = executed.detailed;
        let rows = executed.unit;
        let semantic_receipt = detailed.take_semantic_receipt();
        self.query_work = self.query_work.saturating_add(detailed.work);
        let complete = matches!(detailed.result.completion(), CodeQueryCompletion::Complete);
        let artifact_charge = self.charge_query_semantic_work_with_artifact_continuation(
            detailed.work.semantic,
            semantic_receipt,
            complete,
        )?;
        // A unit that did not complete is not a partition of a complete
        // execution, whatever it selected.
        if !complete {
            return Err(PolicySelectorSessionError::Widen(
                WidenReason::UnitDiagnostics,
            ));
        }
        // The allocations this unit retained cannot be reproduced from a
        // stored product -- they are process-local artifacts -- so a unit that
        // retained any is used here and never published.
        let retained_artifacts = artifact_charge
            .as_ref()
            .is_some_and(|charge| !charge.is_empty());
        let (sites, artifact_charge) = Self::selected_sites(
            selector,
            PolicySelectorQueryResult {
                result: detailed.result,
                evidence: detailed.evidence,
                artifact_charge,
                retained_incomplete_result_contracts: false,
            },
        )?;
        if let Some(artifact_charge) = artifact_charge {
            let retained_before = self.artifact_leases.len();
            self.apply_artifact_charge(
                Ok(artifact_charge),
                "selector result-contract continuation",
            )?;
            self.result_contract_artifact_leases = self
                .result_contract_artifact_leases
                .saturating_add(self.artifact_leases.len().saturating_sub(retained_before));
        }
        let semantic = self.semantic_budget.used().saturating_sub(semantic_before);
        let execution_after = self.semantic_execution_budget.work();
        Ok(ExecutedSelectorUnit {
            reads,
            publishable: !retained_artifacts && sites.iter().all(selector_site_is_projectable),
            product: SelectorProduct {
                rows: rows.clone(),
                sites: sites.iter().map(project_selector_site).collect(),
                semantic,
                materialized_files: lane(
                    execution_after
                        .materialized_files
                        .saturating_sub(execution_before.materialized_files),
                ),
                traversal_steps: lane(
                    execution_after
                        .traversal_steps
                        .saturating_sub(execution_before.traversal_steps),
                ),
            },
            rows,
            sites,
        })
    }

    /// Charge what a reused unit's own execution took out of the shared
    /// semantic ledgers.
    ///
    /// The scalar work rather than the child charge the live path applies: a
    /// stored product carries no process-local artifact identities, so a later
    /// unit may pay a census this one already paid. That over-charges the
    /// semantic lane, which can only widen more often, never less.
    fn charge_stored_selector_work(
        &mut self,
        product: &SelectorProduct,
    ) -> Result<(), PolicySelectorSessionError> {
        if self.semantic_budget.charge(product.semantic).is_err()
            || !self.semantic_execution_budget.charge_external_query_work(
                usize::try_from(product.materialized_files).unwrap_or(usize::MAX),
                usize::try_from(product.traversal_steps).unwrap_or(usize::MAX),
            )
        {
            return Err(semantic_budget_error(format!(
                "{} selectors exhausted the shared semantic materialization budget",
                self.analysis
            )));
        }
        self.query_work = self.query_work.saturating_add(product.rows.work);
        Ok(())
    }

    fn selector_query(
        &self,
        selector: &ResolvedPolicySelector,
    ) -> Result<CodeQuery, PolicySelectorSessionError> {
        // A policy batch runs many selectors against one immutable snapshot,
        // so index reuse is guaranteed: build it on the first selector rather
        // than letting Auto's first-request deferral turn the whole batch
        // into repeated full-workspace scans.
        //
        // Endpoint selection must bind every matching site, not the interactive
        // pagination sample the selector query carries: the catalog validates
        // the authored `limit` to the shared `DEFAULT_LIMIT` of 100, which
        // truncates a corpus-scale source or sink selector before binding and
        // fails the compile closed (#1935). Raise the selection result cap to
        // the host-controlled policy bound; the structural pipeline budget
        // still governs honest truncation above it.
        let (_, query) = selector.as_query().ok_or_else(|| {
            PolicySelectorSessionError::Unavailable(format!(
                "selector `{}` has no executable query kind",
                selector.path
            ))
        })?;
        let mut query = query.clone();
        query.limit = self.max_selector_results;
        Ok(query)
    }

    fn execute_selector_query(
        &mut self,
        query: &brokk_bifrost_rql::CodeQuery,
    ) -> Result<PolicySelectorQueryResult, PolicySelectorSessionError> {
        self.selector_scans = self.selector_scans.saturating_add(1);
        let query_limits = self.remaining_query_limits()?;
        let artifact_leases = self.artifact_leases.snapshot();
        let mut detailed = execute_code_query_detailed_eager_index_workspace_with_semantic_receipt(
            self.workspace,
            query,
            query_limits,
            Some(self.cancellation),
            &self.semantic_budget,
            &self.semantic_execution_budget,
            artifact_leases,
            self.execution_scope,
        );
        let semantic_receipt = detailed.take_semantic_receipt();
        self.query_work = self.query_work.saturating_add(detailed.work);
        self.charge_query_semantic_work(detailed.work.semantic, semantic_receipt)?;
        Ok(PolicySelectorQueryResult {
            result: detailed.result,
            evidence: detailed.evidence,
            artifact_charge: None,
            retained_incomplete_result_contracts: false,
        })
    }

    fn execute_selector_query_with_artifact_continuation(
        &mut self,
        query: &brokk_bifrost_rql::CodeQuery,
    ) -> Result<PolicySelectorQueryResult, PolicySelectorSessionError> {
        self.selector_scans = self.selector_scans.saturating_add(1);
        let query_limits = self.remaining_query_limits()?;
        let artifact_leases = self.artifact_leases.snapshot();
        let mut detailed = execute_code_query_detailed_eager_index_workspace_with_semantic_receipt(
            self.workspace,
            query,
            query_limits,
            Some(self.cancellation),
            &self.semantic_budget,
            &self.semantic_execution_budget,
            artifact_leases,
            self.execution_scope,
        );
        let semantic_receipt = detailed.take_semantic_receipt();
        self.query_work = self.query_work.saturating_add(detailed.work);
        let retain_result_contract_subset =
            retains_independently_proven_result_contracts(&detailed.result, &detailed.evidence);
        let artifact_charge = self.charge_query_semantic_work_with_artifact_continuation(
            detailed.work.semantic,
            semantic_receipt,
            matches!(detailed.result.completion(), CodeQueryCompletion::Complete)
                || retain_result_contract_subset,
        )?;
        Ok(PolicySelectorQueryResult {
            result: detailed.result,
            evidence: detailed.evidence,
            artifact_charge,
            retained_incomplete_result_contracts: retain_result_contract_subset,
        })
    }

    fn selected_sites(
        selector: &ResolvedPolicySelector,
        detailed: PolicySelectorQueryResult,
    ) -> Result<
        (Vec<PolicySelectedSite>, Option<SemanticArtifactLeaseCharge>),
        PolicySelectorSessionError,
    > {
        let result_contract_subset = detailed.retained_incomplete_result_contracts;
        if !matches!(detailed.result.completion(), CodeQueryCompletion::Complete)
            && !result_contract_subset
        {
            let diagnostics = detailed
                .result
                .diagnostics
                .iter()
                .map(|diagnostic| format!("{}: {}", diagnostic.code.as_str(), diagnostic.message))
                .collect::<Vec<_>>()
                .join("; ");
            return Err(PolicySelectorSessionError::Incomplete {
                completion: detailed.result.completion(),
                detail: format!("`{}` ({diagnostics})", selector.path),
            });
        }
        let selected = detailed
            .evidence
            .into_iter()
            .filter(|evidence| !matches!(evidence.domain, DetailedCodeQueryDomain::File))
            .map(|evidence| {
                let item = detailed
                    .result
                    .results
                    .get(evidence.result_index)
                    .ok_or_else(|| {
                        PolicySelectorSessionError::Unavailable(format!(
                            "selector `{}` evidence refers to an absent result row",
                            selector.path
                        ))
                    })?;
                if matches!(
                    &item.value,
                    CodeQueryResultValue::CallResultContract { value } if value.terminal
                ) {
                    // A terminal row proves that this call has no universally
                    // applicable reviewed result contract. It is not an
                    // ordinary call selection and must never fall through to
                    // indexed-result or receiver binding.
                    return Ok(None);
                }
                let decorated_parameter = match (
                    &item.value,
                    evidence.decorated_parameter.as_ref(),
                ) {
                    (
                        CodeQueryResultValue::DecoratedParameter { value },
                        Some(semantic),
                    ) => {
                        let parameter_port_matches = matches!(
                            &semantic.port,
                            DurablePortIdentity::Parameter { ordinal }
                                if value.parameter_ordinal == Some(*ordinal as usize)
                        );
                        let identity_matches = value.procedure_id.as_deref()
                            == Some(semantic.procedure_id.as_str())
                            && value.value_id.as_deref() == Some(semantic.value_id.as_str())
                            && value.port_id.as_deref() == Some(semantic.port_id.as_str());
                        if value.completion != "complete"
                            || value.coverage != "complete"
                            || !identity_matches
                            || !parameter_port_matches
                        {
                            return Err(PolicySelectorSessionError::Unavailable(format!(
                                "selector `{}` produced inconsistent decorated-parameter semantic evidence",
                                selector.path
                            )));
                        }
                        Some(semantic.clone().into())
                    }
                    (CodeQueryResultValue::DecoratedParameter { .. }, None) => {
                        return Err(PolicySelectorSessionError::Unavailable(format!(
                            "selector `{}` produced a decorated parameter without exact semantic evidence",
                            selector.path
                        )));
                    }
                    (_, Some(_)) => {
                        return Err(PolicySelectorSessionError::Unavailable(format!(
                            "selector `{}` attached decorated-parameter evidence to another row kind",
                            selector.path
                        )));
                    }
                    (_, None) => None,
                };
                let span = evidence.byte_span.ok_or_else(|| {
                    PolicySelectorSessionError::Unavailable(format!(
                        "selector `{}` produced a row without a source span",
                        selector.path
                    ))
                })?;
                let (proof, completeness) = selected_site_quality(item);
                let result_contract = match &item.value {
                    CodeQueryResultValue::CallResultContract { value } => {
                        Some(PolicyResultContractSelection {
                            result_ordinal: value.result_ordinal.ok_or_else(|| {
                                PolicySelectorSessionError::Unavailable(format!(
                                    "selector `{}` produced a positive result-contract row without a result ordinal",
                                    selector.path
                                ))
                            })?,
                            fresh_allocation: value.fresh_allocation,
                            success_guard_coverage: value.success_guard_coverage.ok_or_else(|| {
                                PolicySelectorSessionError::Unavailable(format!(
                                    "selector `{}` produced a positive result-contract row without success-guard coverage",
                                    selector.path
                                ))
                            })?,
                            success_guard_edges: value.success_guard_edges.clone(),
                            possible_success_guard_edges: value
                                .possible_success_guard_edges
                                .clone(),
                            member_contracts: value.member_contracts.clone(),
                        })
                    }
                    _ => None,
                };
                let call_shape = match &item.value {
                    CodeQueryResultValue::CallShape { value } => Some(PolicyCallShapeSelection {
                        callee_name: value.callee_name.clone(),
                        argument_count: u32::try_from(value.argument_count).map_err(|_| {
                            PolicySelectorSessionError::Unavailable(format!(
                                "selector `{}` produced a call with too many arguments",
                                selector.path
                            ))
                        })?,
                    }),
                    _ => None,
                };
                let retained_incomplete_result_contract_query =
                    result_contract_subset && result_contract.is_some();
                Ok(Some(PolicySelectedSite {
                    file: evidence.file,
                    span,
                    proof,
                    completeness,
                    result_contract,
                    call_shape,
                    call_binding: None,
                    decorated_parameter,
                    retained_incomplete_result_contract_query,
                }))
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect();
        Ok((selected, detailed.artifact_charge))
    }

    fn select_rows(
        &mut self,
        selector: &ResolvedPolicySelector,
        plan: &crate::definition::RowSelectorPlan,
    ) -> Result<Vec<PolicySelectedSite>, PolicySelectorSessionError> {
        let lowered = validate_row_selector_plan(plan).map_err(|error| {
            PolicySelectorSessionError::Unavailable(format!(
                "selector `{}` has an invalid row plan: {error}",
                selector.path
            ))
        })?;
        let binding_queries = row_binding_queries(plan)?;
        let mut executed = Vec::with_capacity(binding_queries.len());
        let mut coverages = Vec::with_capacity(binding_queries.len());
        let mut incomplete_completion = None;
        let mut diagnostics = Vec::new();

        for (binding, mut query) in binding_queries {
            query.result_detail = CodeQueryResultDetail::Full;
            query.limit = self.max_selector_results;
            self.selector_scans = self.selector_scans.saturating_add(1);
            let query_limits = self.remaining_query_limits()?;
            let artifact_leases = self.artifact_leases.snapshot();
            let mut detailed =
                execute_code_query_detailed_eager_index_workspace_with_semantic_receipt(
                    self.workspace,
                    &query,
                    query_limits,
                    Some(self.cancellation),
                    &self.semantic_budget,
                    &self.semantic_execution_budget,
                    artifact_leases,
                    self.execution_scope,
                );
            let semantic_receipt = detailed.take_semantic_receipt();
            self.query_work = self.query_work.saturating_add(detailed.work);
            self.charge_query_semantic_work(detailed.work.semantic, semantic_receipt)?;
            let completion = detailed.result.completion();
            let declared_binding = lowered.declared_call_binding.as_ref() == Some(&binding);
            let declaration_complete = declared_binding
                && !detailed.result.truncated
                && (matches!(completion, CodeQueryCompletion::Complete)
                    || (!detailed.result.diagnostics.is_empty()
                        && detailed.result.diagnostics.iter().all(|diagnostic| {
                            diagnostic.code == CodeQueryDiagnosticCode::CallBindingDispatchPartial
                        })));
            let coverage = match (&completion, declaration_complete) {
                (_, true) => RelationCoverage::Exhaustive,
                (CodeQueryCompletion::Complete, false) if !detailed.result.truncated => {
                    RelationCoverage::Exhaustive
                }
                (CodeQueryCompletion::ProvenSubset { .. }, false) => RelationCoverage::ProvenSubset,
                _ => RelationCoverage::incomplete(vec![
                    crate::PolicyIncompleteReason::PartialDiscovery,
                ]),
            };
            if (!matches!(completion, CodeQueryCompletion::Complete) || detailed.result.truncated)
                && !declaration_complete
            {
                incomplete_completion.get_or_insert(completion);
            }
            diagnostics.extend(detailed.result.diagnostics.iter().map(|diagnostic| {
                format!(
                    "{}: {}: {}",
                    binding.as_str(),
                    diagnostic.code.as_str(),
                    diagnostic.message
                )
            }));
            coverages.push(coverage);
            executed.push((binding, detailed));
        }

        // One adapter serves every path that evaluates a relational plan: the
        // rendered rows are projected into the same product a unit publishes
        // before the plan reads a field of them.
        let projected = executed
            .iter()
            .map(|(_, detailed)| {
                detailed
                    .result
                    .results
                    .iter()
                    .map(UnitRowItem::project)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let inputs = executed
            .iter()
            .zip(&coverages)
            .zip(&projected)
            .map(|(((binding, _), coverage), rows)| RelationalInput {
                binding,
                rows,
                coverage: coverage.clone(),
            })
            .collect::<Vec<_>>();
        let selection = evaluate_row_selector_ir(
            &lowered.plan,
            lowered.relation,
            lowered.upstream,
            &lowered.upstream_binding,
            &inputs,
        )
        .map_err(|error| {
            PolicySelectorSessionError::Unavailable(format!(
                "selector `{}` row evaluation failed: {error}",
                selector.path
            ))
        })?;

        let upstream = executed
            .iter()
            .find(|(binding, _)| *binding == lowered.upstream_binding)
            .ok_or_else(|| {
                PolicySelectorSessionError::Unavailable(format!(
                    "selector `{}` did not execute output binding `{}`",
                    selector.path, lowered.upstream_binding
                ))
            })?;
        let declared_output =
            lowered.declared_call_binding.as_ref() == Some(&lowered.upstream_binding);
        let uncertain_upstream = !declared_output
            && selection.upstream_rows.iter().any(|row| {
                upstream.1.result.results.get(row.row).is_none_or(|item| {
                    if matches!(
                        &item.value,
                        CodeQueryResultValue::CallBinding { value }
                            if value.binding_kind == Some("receiver")
                    ) {
                        return false;
                    }
                    let (proof, completeness) = selected_site_quality(item);
                    !matches!(proof, ProofStatus::Proven)
                        || !matches!(completeness, EvidenceCompleteness::Complete)
                })
            });
        // The call shape existed, but the exact identity/formal contract
        // rejected every binding row. That is an abstention about a witnessed
        // candidate, not proof that the endpoint is absent. A genuinely absent
        // shape has no upstream rows and remains a conclusive empty selection.
        let rejected_witnessed_candidate = selection.selected_rows.is_empty()
            && !selection.upstream_rows.is_empty()
            && (!declared_output
                || lowered
                    .declared_call_model_id
                    .as_ref()
                    .is_none_or(|expected| {
                        selection.upstream_rows.iter().any(|row| {
                            matches!(
                                upstream.1.result.results.get(row.row).map(|item| &item.value),
                                Some(CodeQueryResultValue::CallBinding { value })
                                    if value.model_callable_id.as_deref() == Some(expected.as_str())
                                        || value.model_id.as_deref() == Some(expected.as_str())
                            )
                        })
                    }));
        let incomplete = incomplete_completion.is_some()
            || !selection.upstream_coverage.is_exhaustive()
            || !selection.selected_coverage.is_exhaustive()
            || selection.limit_exceeded
            || uncertain_upstream
            || rejected_witnessed_candidate;
        if selection.selected_rows.is_empty() && incomplete {
            return Err(PolicySelectorSessionError::Incomplete {
                completion: incomplete_completion
                    .unwrap_or(CodeQueryCompletion::Incomplete { codes: Vec::new() }),
                detail: format!(
                    "selector `{}` could not prove an empty row selection{}",
                    selector.path,
                    if diagnostics.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", diagnostics.join("; "))
                    }
                ),
            });
        }

        selection
            .selected_rows
            .into_iter()
            .map(|selected| {
                let item = upstream.1.result.results.get(selected.row).ok_or_else(|| {
                    PolicySelectorSessionError::Unavailable(format!(
                        "selector `{}` selected an absent row",
                        selector.path
                    ))
                })?;
                let evidence = upstream
                    .1
                    .evidence
                    .iter()
                    .find(|evidence| evidence.result_index == selected.row)
                    .ok_or_else(|| {
                        PolicySelectorSessionError::Unavailable(format!(
                            "selector `{}` selected a row without source evidence",
                            selector.path
                        ))
                    })?;
                let span = evidence.byte_span.clone().ok_or_else(|| {
                    PolicySelectorSessionError::Unavailable(format!(
                        "selector `{}` selected a row without a source span",
                        selector.path
                    ))
                })?;
                let CodeQueryResultValue::CallBinding { value } = &item.value else {
                    return Err(PolicySelectorSessionError::Unavailable(format!(
                        "selector `{}` output is not a call-binding row",
                        selector.path
                    )));
                };
                let call_span = self.call_span_for_ast_id(&evidence.file, &value.site_ast_id)?;
                let (proof, mut completeness) = if declared_output {
                    (ProofStatus::Proven, EvidenceCompleteness::Complete)
                } else {
                    selected_site_quality(item)
                };
                if incomplete {
                    completeness = EvidenceCompleteness::Partial(
                        "row selector input or filtered output was not exhaustive".into(),
                    );
                }
                Ok(PolicySelectedSite {
                    file: evidence.file.clone(),
                    span,
                    proof,
                    completeness,
                    result_contract: None,
                    call_shape: None,
                    decorated_parameter: None,
                    retained_incomplete_result_contract_query: false,
                    call_binding: Some(PolicySelectedCallBinding {
                        row_id: value.id.clone(),
                        site_id: value.site_id.clone(),
                        site_ast_id: value.site_ast_id.clone(),
                        argument_id: value.argument_id.clone().ok_or_else(|| {
                            PolicySelectorSessionError::Unavailable(format!(
                                "selector `{}` selected a binding without an argument identity",
                                selector.path
                            ))
                        })?,
                        call_span,
                        actual_index: value.actual_index.ok_or_else(|| {
                            PolicySelectorSessionError::Unavailable(format!(
                                "selector `{}` selected a binding without an actual index",
                                selector.path
                            ))
                        })?,
                        formal_index: value.formal_index.ok_or_else(|| {
                            PolicySelectorSessionError::Unavailable(format!(
                                "selector `{}` selected a binding without a formal index",
                                selector.path
                            ))
                        })?,
                        formal_name: value.formal_name.clone().ok_or_else(|| {
                            PolicySelectorSessionError::Unavailable(format!(
                                "selector `{}` selected a binding without a formal name",
                                selector.path
                            ))
                        })?,
                        semantic_target_id: value.semantic_target_id.clone().ok_or_else(|| {
                            PolicySelectorSessionError::Unavailable(format!(
                                "selector `{}` selected a binding without semantic target identity",
                                selector.path
                            ))
                        })?,
                        model_callable_id: value.model_callable_id.clone().ok_or_else(|| {
                            PolicySelectorSessionError::Unavailable(format!(
                                "selector `{}` selected a binding without callable-family identity",
                                selector.path
                            ))
                        })?,
                        formal_layout_id: value.formal_layout_id.clone().ok_or_else(|| {
                            PolicySelectorSessionError::Unavailable(format!(
                                "selector `{}` selected a binding without formal-layout identity",
                                selector.path
                            ))
                        })?,
                        signature_id: value.signature_id.clone(),
                        model_id: value.model_id.clone(),
                        pack_id: value.pack_id.clone(),
                        selector_proof: if declared_output {
                            "declared"
                        } else {
                            value.selector_proof.ok_or_else(|| {
                                PolicySelectorSessionError::Unavailable(format!(
                                    "selector `{}` selected a binding without selector proof",
                                    selector.path
                                ))
                            })?
                        },
                        selector_summary_id: if declared_output {
                            None
                        } else {
                            value.selector_summary_id.clone()
                        },
                        selector_summary_model_id: if declared_output {
                            None
                        } else {
                            value.selector_summary_model_id.clone()
                        },
                        selector_summary_pack_id: if declared_output {
                            None
                        } else {
                            value.selector_summary_pack_id.clone()
                        },
                        selector_summary_pack_digest: if declared_output {
                            None
                        } else {
                            value.selector_summary_pack_digest.clone()
                        },
                    }),
                })
            })
            .collect()
    }

    fn call_span_for_ast_id(
        &self,
        file: &ProjectFile,
        expected_ast_id: &str,
    ) -> Result<ByteRange<usize>, PolicySelectorSessionError> {
        let facts = self
            .workspace
            .analyzer()
            .structural_fact_providers()
            .into_iter()
            .find_map(|provider| provider.structural_facts(file))
            .ok_or_else(|| {
                PolicySelectorSessionError::Unavailable(format!(
                    "call-binding site identity cannot be resolved for `{}`",
                    file
                ))
            })?;
        let mut matches = facts.nodes().iter().enumerate().filter(|(index, _)| {
            brokk_bifrost_analysis::analyzer::structural::occurrence_rows::ast_id(
                facts.source_identity(),
                u32::try_from(*index).expect("facts arena node IDs fit u32"),
            ) == expected_ast_id
        });
        let (_, node) = matches.next().ok_or_else(|| {
            PolicySelectorSessionError::Unavailable(
                "selected call-binding AST identity is absent from structural facts".to_owned(),
            )
        })?;
        if matches.next().is_some() {
            return Err(PolicySelectorSessionError::Unavailable(
                "selected call-binding AST identity is ambiguous".to_owned(),
            ));
        }
        Ok(node.range.start_byte..node.range.end_byte)
    }

    pub(super) fn workspace(&self) -> &'a WorkspaceAnalyzer {
        self.workspace
    }

    pub(super) fn cancellation(&self) -> &'a CancellationToken {
        self.cancellation
    }

    pub(super) fn semantic_request(&mut self) -> SemanticRequest<'_> {
        SemanticRequest::with_execution_budget(
            &mut self.semantic_budget,
            self.cancellation,
            &self.semantic_execution_budget,
        )
    }

    pub(super) fn begin_semantic_lease_window(&self) -> PolicySemanticLeaseWindow {
        PolicySemanticLeaseWindow::new(&self.artifact_leases)
    }

    pub(super) fn continue_semantic_in_window<T>(
        &mut self,
        leases: &PolicySemanticLeaseWindow,
        run: impl FnOnce(&mut SemanticRequest<'_>) -> Result<SemanticOutcome<T>, SemanticProviderError>,
    ) -> Result<SemanticOutcome<T>, PolicySelectorSessionError> {
        let collector = leases.collector();
        let outcome = {
            let mut request = SemanticRequest::with_execution_budget(
                &mut self.semantic_budget,
                self.cancellation,
                &self.semantic_execution_budget,
            )
            .with_artifact_collector(&collector);
            run(&mut request)
        };
        match outcome {
            Ok(outcome) => Ok(outcome),
            Err(error) => Err(PolicySelectorSessionError::Provider(error.to_string())),
        }
    }

    /// Run one typestate continuation operation in one bounded lease window.
    /// The caller classifies and fully decodes the primary outcome before it
    /// either commits escaping handles or discards a scalar-only result.
    pub(super) fn continue_semantic<T>(
        &mut self,
        run: impl FnOnce(&mut SemanticRequest<'_>) -> Result<SemanticOutcome<T>, SemanticProviderError>,
    ) -> Result<PolicySemanticContinuation<T>, PolicySelectorSessionError> {
        let leases = self.begin_semantic_lease_window();
        let outcome = self.continue_semantic_in_window(&leases, run)?;
        Ok(PolicySemanticContinuation { outcome, leases })
    }

    /// Classify one source call's tied semantic lowerings for a receiver port.
    ///
    /// Duplicate lowerings of one source site (for example, a `finally` body
    /// specialized per completion route) must agree on whether they publish a
    /// candidate caller-side receiver. Complete callable-reference evidence
    /// can prove a bound receiver or a receiverless function locally. When the
    /// syntax is deliberately ambiguous, only uninterrupted, exhaustive
    /// dispatch may refine it. Exact Go declarations prove their receiver
    /// shape independently of a named formal receiver binding: materialized
    /// methods carry declaration-owned procedure kinds, while external targets
    /// carry resolver-owned call shape. Other materialized targets still need
    /// complete candidate-specific call bindings. Anything less remains
    /// indeterminate and reaches the compiler's fail-closed diagnostic.
    pub(super) fn receiver_binding_applicability(
        &mut self,
        calls: &[(ProcedureHandle, CallSiteHandle)],
    ) -> Result<ReceiverBindingApplicability, PolicySelectorSessionError> {
        assert!(
            !calls.is_empty(),
            "receiver applicability requires at least one semantic call lowering"
        );
        let mut receiver_presence = calls.iter().map(|(procedure, call)| {
            procedure
                .semantics()
                .call_site(call.id())
                .expect("validated call handle resolves")
                .receiver
                .is_some()
        });
        let first = receiver_presence
            .next()
            .expect("non-empty semantic call set has one receiver state");
        if receiver_presence.any(|present| present != first) {
            return Ok(ReceiverBindingApplicability::Inconsistent);
        }
        if first
            && calls.iter().all(|(procedure, call)| {
                let row = procedure
                    .semantics()
                    .call_site(call.id())
                    .expect("validated call handle resolves");
                matches!(
                    procedure
                        .semantics()
                        .proven_caller_receiver_binding(call.id()),
                    Some(CallerReceiverBinding::Bound(receiver))
                        if Some(receiver) == row.receiver
                )
            })
        {
            return Ok(ReceiverBindingApplicability::Applicable);
        }

        if !first
            && calls.iter().all(|(procedure, call)| {
                matches!(
                    procedure
                        .semantics()
                        .proven_caller_receiver_binding(call.id()),
                    Some(CallerReceiverBinding::Absent)
                )
            })
        {
            return Ok(ReceiverBindingApplicability::ExactNonMatch);
        }

        let oracle = self.workspace.semantic_oracle_provider();
        let leases = self.begin_semantic_lease_window();
        let mut exact_receiver = first;
        let mut exact_non_match = true;
        for (procedure, call) in calls {
            let dispatch_outcome = self.continue_semantic_in_window(&leases, |request| {
                oracle.resolve_call(call, request)
            })?;
            self.require_uninterrupted(&dispatch_outcome, "receiver-port dispatch")?;
            self.require_execution_budget("receiver-port dispatch")?;
            let proven_receiver_shape = match &dispatch_outcome {
                // `Unproven` can describe evidence outside receiver shape,
                // such as an unavailable external body. It does not weaken an
                // independently complete declaration or resolver proof.
                // Unknown, unsupported, ambiguous, interrupted, and
                // budget-limited outcomes remain unusable here.
                SemanticOutcome::Complete {
                    value: dispatch, ..
                }
                | SemanticOutcome::Unproven {
                    partial: dispatch, ..
                } => dispatch.proven_receiver_shape(),
                _ => None,
            };
            if let Some(has_receiver) = proven_receiver_shape {
                // An exact receiver-shape proof does not depend on whether the
                // declaration names its receiver. Accept only the exhaustive,
                // unanimous result above: an unproven shape or conflicting
                // target set remains indeterminate.
                exact_receiver &= first && has_receiver;
                exact_non_match &= !has_receiver;
                drop(dispatch_outcome);
                continue;
            }
            let exact_dispatch = dispatch_outcome.is_complete()
                && dispatch_outcome.available_value().is_some_and(|dispatch| {
                    dispatch.coverage() == CandidateCoverage::Exhaustive
                        && !dispatch.candidates().is_empty()
                        && dispatch.boundaries().is_empty()
                        && dispatch.candidates().iter().all(|candidate| {
                            matches!(candidate.proof(), ProofStatus::Proven)
                                && matches!(
                                    candidate.completeness(),
                                    EvidenceCompleteness::Complete
                                )
                        })
                });
            if !exact_dispatch {
                exact_receiver = false;
                exact_non_match = false;
                drop(dispatch_outcome);
                continue;
            }

            let dispatch = dispatch_outcome
                .available_value()
                .expect("an exact dispatch outcome retains its result");
            for candidate in dispatch.candidates() {
                let bindings_outcome = self.continue_semantic_in_window(&leases, |request| {
                    oracle.call_bindings(call, candidate, &OracleCallContext::empty(), request)
                })?;
                self.require_uninterrupted(&bindings_outcome, "receiver-port binding")?;
                self.require_execution_budget("receiver-port binding")?;
                let exact_bindings = bindings_outcome.is_complete()
                    && bindings_outcome.available_value().is_some_and(|bindings| {
                        bindings.coverage() == CandidateCoverage::Exhaustive
                    });
                if !exact_bindings {
                    exact_receiver = false;
                    exact_non_match = false;
                    drop(bindings_outcome);
                    continue;
                }
                let bindings = bindings_outcome
                    .available_value()
                    .expect("exact call bindings retain their result");
                let receiver_bindings = bindings
                    .bindings()
                    .iter()
                    .filter_map(|binding| match binding {
                        CallBinding::Receiver { actual, .. } => Some(actual.id()),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                let expected = procedure
                    .semantics()
                    .call_site(call.id())
                    .expect("validated call handle resolves")
                    .receiver;
                exact_receiver &= receiver_bindings.as_slice() == expected.as_slice();
                exact_non_match &= receiver_bindings.is_empty();
                drop(bindings_outcome);
            }
            drop(dispatch_outcome);
        }
        leases.finish_scalar(
            if exact_receiver {
                ReceiverBindingApplicability::Applicable
            } else if exact_non_match {
                ReceiverBindingApplicability::ExactNonMatch
            } else if first {
                ReceiverBindingApplicability::CandidateReceiver
            } else {
                ReceiverBindingApplicability::Indeterminate
            },
            "receiver-port classification",
        )
    }

    fn apply_artifact_charge(
        &mut self,
        charge: Result<SemanticArtifactLeaseCharge, SemanticArtifactLeaseError>,
        operation: &str,
    ) -> Result<(), PolicySelectorSessionError> {
        let charge = charge.map_err(|error| {
            semantic_budget_error(format!(
                "{operation} exhausted the shared semantic retained-artifact budget: {error}"
            ))
        })?;
        if charge.is_empty() {
            return Ok(());
        }
        self.artifact_leases
            .try_apply_charge(charge, 0)
            .map_err(|error| {
                semantic_budget_error(format!(
                    "{operation} exhausted the shared semantic retained-artifact budget: {error}"
                ))
            })
    }

    pub(super) fn execution_budget(&self) -> &SemanticExecutionBudget {
        &self.semantic_execution_budget
    }

    pub(super) fn semantic_budget_mut(&mut self) -> &mut SemanticBudget {
        &mut self.semantic_budget
    }

    pub(super) fn semantic_used(&self) -> SemanticWork {
        self.semantic_budget.used()
    }

    pub(super) fn semantic_remaining(&self) -> SemanticWork {
        self.semantic_budget.remaining()
    }

    pub(super) fn semantic_scope_snapshot(&self) -> SemanticBudgetScopeSnapshot {
        self.semantic_budget.scope_snapshot()
    }

    pub(super) fn query_work(&self) -> CodeQueryExecutionWork {
        self.query_work
    }

    pub(super) const fn result_contract_artifact_leases(&self) -> usize {
        self.result_contract_artifact_leases
    }

    pub(super) const fn retained_incomplete_result_contract_selectors(&self) -> usize {
        self.retained_incomplete_result_contract_selectors
    }

    pub(super) const fn selector_scans(&self) -> u64 {
        self.selector_scans
    }

    pub(super) fn materialized_artifacts(&self) -> impl Iterator<Item = &Arc<SemanticArtifact>> {
        self.artifacts.values()
    }

    pub(super) fn remember_artifact(&mut self, file: ProjectFile, artifact: Arc<SemanticArtifact>) {
        self.artifacts.entry(file).or_insert(artifact);
    }

    pub(super) fn materialize_with_artifact_continuation(
        &mut self,
        file: &ProjectFile,
    ) -> Result<Arc<SemanticArtifact>, PolicySelectorSessionError> {
        let workspace = self.workspace;
        let continuation = self
            .continue_semantic(|request| workspace.materialize_program_semantics(file, request))?;
        self.require_uninterrupted(continuation.outcome(), "program semantics materialization")?;
        self.require_execution_budget("program semantics materialization")?;
        if !continuation.outcome().is_complete() {
            return Err(PolicySelectorSessionError::Incomplete {
                completion: CodeQueryCompletion::Incomplete {
                    codes: vec![CodeQueryDiagnosticCode::SemanticAnalysisPartial],
                },
                detail: format!(
                    "program semantics are incomplete for {}",
                    file.abs_path().display()
                ),
            });
        }
        let artifact = continuation
            .outcome()
            .available_value()
            .cloned()
            .ok_or_else(|| {
                PolicySelectorSessionError::Unavailable(format!(
                    "program semantics are unavailable for {}",
                    file.abs_path().display()
                ))
            })?;
        let outcome = continuation.commit(self, "program semantics materialization")?;
        drop(outcome);
        assert!(
            self.artifact_leases.snapshot().contains_exact(&artifact),
            "a complete typestate materialization is leased before its handle escapes"
        );
        self.artifacts.insert(file.clone(), Arc::clone(&artifact));
        Ok(artifact)
    }

    pub(super) fn take_artifact_leases(&mut self) -> PolicyArtifactLeases {
        {
            let snapshot = self.artifact_leases.snapshot();
            assert!(
                self.artifacts
                    .values()
                    .all(|artifact| snapshot.contains_exact(artifact)),
                "typestate materialized artifacts must enter the lease ledger before handles escape"
            );
        }
        let max_retained_bytes = self.artifact_leases.max_retained_bytes();
        std::mem::replace(
            &mut self.artifact_leases,
            SemanticArtifactLeaseSet::new(max_retained_bytes),
        )
    }

    pub(super) fn materialize(
        &mut self,
        file: &ProjectFile,
    ) -> Result<Arc<SemanticArtifact>, PolicySelectorSessionError> {
        if let Some(artifact) = self.artifacts.get(file) {
            return Ok(Arc::clone(artifact));
        }
        let workspace = self.workspace;
        let outcome = {
            let mut request = self.semantic_request();
            workspace
                .materialize_program_semantics(file, &mut request)
                .map_err(|error| PolicySelectorSessionError::Provider(error.to_string()))?
        };
        self.require_uninterrupted(&outcome, "program semantics materialization")?;
        self.require_execution_budget("program semantics materialization")?;
        let artifact = outcome.available_value().cloned().ok_or_else(|| {
            PolicySelectorSessionError::Unavailable(format!(
                "program semantics are unavailable for {}",
                file.abs_path().display()
            ))
        })?;
        self.artifacts.insert(file.clone(), Arc::clone(&artifact));
        Ok(artifact)
    }

    pub(super) fn remaining_semantic_traversal_steps(
        &self,
    ) -> Result<usize, PolicySelectorSessionError> {
        let remaining = self.semantic_execution_budget.remaining_traversal_steps();
        if remaining == 0 {
            Err(semantic_budget_error(format!(
                "{} semantic lookup exhausted the shared traversal budget",
                self.analysis
            )))
        } else {
            Ok(remaining)
        }
    }

    pub(super) fn require_execution_budget(
        &self,
        operation: &str,
    ) -> Result<(), PolicySelectorSessionError> {
        if self.semantic_execution_budget.work().exhausted {
            Err(semantic_budget_error(format!(
                "{operation} exhausted the shared semantic file or traversal budget"
            )))
        } else {
            Ok(())
        }
    }

    pub(super) fn require_uninterrupted<T>(
        &self,
        outcome: &brokk_bifrost_analysis::analyzer::semantic::SemanticOutcome<T>,
        operation: &str,
    ) -> Result<(), PolicySelectorSessionError> {
        use brokk_bifrost_analysis::analyzer::semantic::SemanticOutcome;
        match outcome {
            SemanticOutcome::Cancelled { .. } => Err(PolicySelectorSessionError::Incomplete {
                completion: CodeQueryCompletion::Cancelled,
                detail: format!("{operation} was cancelled"),
            }),
            SemanticOutcome::ExceededBudget { exceeded, .. } => Err(semantic_budget_error(
                format!("{operation} exceeded the shared semantic budget: {exceeded}"),
            )),
            _ => Ok(()),
        }
    }

    pub(super) fn work_report(&self, analysis: &str) -> PolicyWorkReport {
        // Report retired regions' work plus the live region's, so per-region
        // budget resets do not hide the compile's cumulative semantic cost.
        let semantic = self.semantic_budget.used();
        let execution = self.semantic_execution_budget.work();
        let semantic_peaks = self.semantic_peaks();
        let metrics = [
            (
                "semantic_materialized_files",
                PolicyWorkUnit::Count,
                self.retired_materialized_files
                    .saturating_add(execution.materialized_files),
            ),
            (
                "semantic_traversal_steps",
                PolicyWorkUnit::Count,
                self.retired_traversal_steps
                    .saturating_add(execution.traversal_steps),
            ),
            (
                "semantic_source_bytes",
                PolicyWorkUnit::Bytes,
                self.retired_source_bytes
                    .saturating_add(semantic.source_bytes),
            ),
            (
                "semantic_program_points",
                PolicyWorkUnit::Rows,
                self.retired_program_points
                    .saturating_add(semantic.program_points),
            ),
            // Each selector entry's subject scan is granted the whole-workspace
            // scan allowance, so this count is the multiplier on that allowance
            // the compile spent.  Reporting it keeps the compile's total scan
            // cost auditable instead of implicit in the entry list.
            (
                "selector_scans",
                PolicyWorkUnit::Count,
                usize::try_from(self.selector_scans).unwrap_or(usize::MAX),
            ),
            // The three per-region lane peaks.  The retired counters above are
            // sums across regions, which is the compile's total cost but not
            // what any lane has to admit: the lanes reset per region, so a lane
            // has to exceed the largest single region's charge.  These are the
            // numbers the derived-lane model must be calibrated against (#1936).
            (
                "semantic_peak_row_dimension",
                PolicyWorkUnit::Rows,
                semantic_peaks.row_dimension,
            ),
            (
                "semantic_peak_retained_bytes",
                PolicyWorkUnit::Bytes,
                semantic_peaks.retained_bytes,
            ),
            (
                "semantic_peak_traversal_steps",
                PolicyWorkUnit::Count,
                semantic_peaks.traversal_steps,
            ),
            // The next three were once reported only when their counters had
            // moved, so a compile that materialized no value-flow snapshot
            // (#2284), saw no artifact-cache handle reuse (#2289), or took no
            // result-contract lease was not given a permanent zero. That
            // reasoning is reversed here, because the name set is not free.
            // Retention accounting sums metric name capacities
            // (`PolicyWorkReport::retained_size` feeds `PolicyRun`'s), and the
            // evaluator's retention search decides how many findings a run
            // keeps from that size. A name set that depends on the run's data
            // therefore makes the *retained finding set* depend on it, which
            // the incremental diff-base work
            // (`.agents/plans/impact-sliced-diff-base.md`) cannot tolerate: it
            // has to prove a reused-result report is byte-identical to a full
            // one. Emitting them always makes the name set a function of the
            // policy family and the `analysis` label alone, and #2659 already
            // settled that a permanent zero is the honest signal -- it says
            // the compile did none of this work, not that nothing was measured.
            (
                "semantic_snapshot_materializations",
                PolicyWorkUnit::Count,
                usize::try_from(self.semantic_snapshot_materializations).unwrap_or(usize::MAX),
            ),
            (
                "semantic_handle_identity_reuses",
                PolicyWorkUnit::Count,
                usize::try_from(self.semantic_handle_identity_reuses).unwrap_or(usize::MAX),
            ),
            (
                "semantic_result_contract_artifact_leases",
                PolicyWorkUnit::Count,
                self.result_contract_artifact_leases,
            ),
        ]
        .into_iter()
        .filter_map(|(name, unit, value)| {
            PolicyWorkMetric::try_new(
                format!("{analysis}.{name}"),
                unit,
                u64::try_from(value).unwrap_or(u64::MAX),
            )
            .ok()
        })
        .collect();
        PolicyWorkReport::try_new(
            self.query_work.scanned_files,
            self.query_work.scanned_source_bytes,
            self.query_work.fact_nodes,
            self.query_work.pipeline_rows,
            self.query_work.examined_references,
            0,
            0,
            0,
            metrics,
        )
        .unwrap_or_default()
    }

    pub(super) fn semantic_peaks(&self) -> PolicySemanticPeaks {
        let (row_dimension, retained_bytes, traversal_steps) = self.live_region_peaks();
        PolicySemanticPeaks {
            row_dimension: self.peak_row_dimension.max(row_dimension),
            retained_bytes: self.peak_retained_bytes.max(retained_bytes),
            traversal_steps: self.peak_traversal_steps.max(traversal_steps),
        }
    }

    /// The current region's charge against each per-region lane, as
    /// `(largest row dimension, retained bytes, traversal steps)`.
    ///
    /// This calibrates `PolicyBudget`'s row lane, and that lane is one
    /// uniform `max_rows_per_dimension` granted to every row dimension, so
    /// the charge it must exceed is the largest single dimension's, not any
    /// one dimension's on its own. Queries inside the region are now capped
    /// per dimension from this budget's own remainders (#2523), but what is
    /// being calibrated here is still the uniform grant those remainders
    /// start from.
    fn live_region_peaks(&self) -> (usize, usize, usize) {
        let used = self.semantic_budget.used();
        let row_peak = CodeQuerySemanticRowLimits::ROW_DIMENSIONS
            .into_iter()
            .map(|dimension| used.get(dimension))
            .max()
            .unwrap_or(0);
        (
            row_peak,
            used.owned_text_bytes
                .max(self.live_selector_retained_peak)
                .max(self.artifact_leases.retained_bytes()),
            self.semantic_execution_budget.work().traversal_steps,
        )
    }

    /// What one more selector query may spend, taken from this session's own
    /// shared ledger.
    ///
    /// The row lanes are published per dimension rather than collapsed. They
    /// deplete at wildly different rates -- `nested_entries` is a census of
    /// every artifact's nested collections and also the dispatch walk's
    /// exploration lane, while `procedures` counts one row per procedure --
    /// so one whole-workspace bind can legitimately spend most of the first
    /// while barely touching the second. Reporting the minimum of the
    /// remainders as a uniform cap made every later query in the session run
    /// against the most depleted lane: on google/gson, reference policy B's
    /// second bind published verdicts for 6 of its 98 marked procedures
    /// before it stopped (#2523). Each dimension now carries its own
    /// remainder, so a drained lane bounds itself and nothing else.
    ///
    /// The uniform scalar stays populated with the minimum. It is not read
    /// while the table is present, and the minimum is the value that cannot
    /// overrun any lane if some later consumer reads it alone.
    fn remaining_query_limits(
        &self,
    ) -> Result<CodeQueryExecutionLimits, PolicySelectorSessionError> {
        let semantic_remaining = self.semantic_budget.remaining();
        let semantic = CodeQuerySemanticLimits {
            max_materialized_files: self
                .semantic_execution_budget
                .remaining_materialized_files(),
            max_source_bytes: semantic_remaining.source_bytes,
            max_rows_per_dimension: CodeQuerySemanticRowLimits::ROW_DIMENSIONS
                .into_iter()
                .map(|dimension| semantic_remaining.get(dimension))
                .min()
                .unwrap_or(0),
            // This is a physical live-window cap, not an additive ledger
            // remainder. Sequential selectors release their windows, so each
            // receives the region's full cap; the forked provider budget is
            // independently bounded by `semantic_remaining.owned_text_bytes`.
            max_retained_bytes: self.query_limits.semantic.max_retained_bytes,
            max_traversal_steps: self.semantic_execution_budget.remaining_traversal_steps(),
            rows_per_dimension: Some(CodeQuerySemanticRowLimits::from_rows(|dimension| {
                semantic_remaining.get(dimension)
            })),
        };
        // The structural scan lanes are granted per selector entry, not shared
        // across the compile.  `PolicyBudget::scaled_for_workspace` sizes them to
        // one whole-workspace subject scan because that is what one selector
        // costs: Theta(workspace facts) (#1771).  Deducting each entry's scan
        // from the next entry's allowance therefore divides one whole-workspace
        // allowance across every source and sink a policy declares, so the
        // first entries consume it and the rest cannot run at all.  On OWASP
        // BenchmarkJava (2766 files, 11.5MB; scaled lane 5532 files, 23.1MB)
        // the third of the taint policy's nine selector entries was left 639
        // files and 2.57MB, exhausted mid-scan, and every category abstained
        // (#1935).  Each entry now gets the whole-workspace allowance; the
        // compile total stays bounded because `select` runs exactly once per
        // declared entry and the policy schema bounds those sets (`:entries`
        // is `SET_256` for sources and for sinks, and the registry bounds
        // match-directory endpoints at `MAX_REGISTERED_ENDPOINTS`).  The
        // `selector_scans` metric reports the multiplier this compile actually
        // used, so the total cost stays auditable rather than implicit.
        //
        // `max_pipeline_rows` bounds one query's materialized rows rather than
        // workspace volume, so it was never a shared quantity either; it is
        // per-query by construction.
        Ok(CodeQueryExecutionLimits {
            max_scanned_files: self.query_limits.max_scanned_files,
            max_scanned_source_bytes: self.query_limits.max_scanned_source_bytes,
            max_fact_nodes: self.query_limits.max_fact_nodes,
            max_pipeline_rows: self.query_limits.max_pipeline_rows,
            semantic,
            typestate: self.query_limits.typestate,
            value_flow: self.query_limits.value_flow,
            taint: self.query_limits.taint,
        })
    }

    fn charge_query_semantic_work(
        &mut self,
        work: CodeQuerySemanticWork,
        receipt: Option<CodeQuerySemanticReceipt>,
    ) -> Result<(), PolicySelectorSessionError> {
        let semantic_work = self.selector_semantic_work(work);
        let Some(receipt) = receipt else {
            assert_eq!(
                work,
                CodeQuerySemanticWork::default(),
                "a selector that performs semantic work must return its one-shot charge",
            );
            return Ok(());
        };
        let (semantic_charge, execution_before, execution_charge, artifact_charge) =
            receipt.into_parts();
        self.apply_query_charge(
            semantic_work,
            semantic_charge,
            execution_before,
            execution_charge,
        )?;
        drop(artifact_charge);
        Ok(())
    }

    fn charge_query_semantic_work_with_artifact_continuation(
        &mut self,
        work: CodeQuerySemanticWork,
        receipt: Option<CodeQuerySemanticReceipt>,
        completed: bool,
    ) -> Result<Option<SemanticArtifactLeaseCharge>, PolicySelectorSessionError> {
        let semantic_work = self.selector_semantic_work(work);
        let Some(receipt) = receipt else {
            assert_eq!(
                work,
                CodeQuerySemanticWork::default(),
                "a selector that performs semantic work must return its one-shot charge",
            );
            return Ok(None);
        };
        let (semantic_charge, execution_before, execution_charge, artifact_charge) =
            receipt.into_parts();
        self.apply_query_charge(
            semantic_work,
            semantic_charge,
            execution_before,
            execution_charge,
        )?;
        if completed {
            Ok(Some(artifact_charge))
        } else {
            drop(artifact_charge);
            Ok(None)
        }
    }

    fn selector_semantic_work(&mut self, work: CodeQuerySemanticWork) -> SemanticWork {
        let usize_work = |value| usize::try_from(value).unwrap_or(usize::MAX);
        self.live_selector_retained_peak = self
            .live_selector_retained_peak
            .max(usize_work(work.retained_bytes));
        SemanticWork {
            source_bytes: usize_work(work.source_bytes),
            procedures: usize_work(work.procedures),
            blocks: usize_work(work.blocks),
            program_points: usize_work(work.program_points),
            values: usize_work(work.values),
            allocations: usize_work(work.allocations),
            call_sites: usize_work(work.call_sites),
            memory_locations: usize_work(work.memory_locations),
            captures: usize_work(work.captures),
            source_mappings: usize_work(work.source_mappings),
            evidence: usize_work(work.evidence),
            gaps: usize_work(work.gaps),
            events: usize_work(work.events),
            control_edges: usize_work(work.control_edges),
            nested_entries: usize_work(work.nested_entries),
            // CodeQuery reports a per-query live high-water mark here, not
            // additive semantic work. The child charge below carries the
            // provider's exact additive owned-text work.
            owned_text_bytes: 0,
        }
    }

    fn apply_query_charge(
        &mut self,
        semantic_work: SemanticWork,
        semantic_charge: brokk_bifrost_analysis::analyzer::semantic::SemanticBudgetCharge,
        execution_before: brokk_bifrost_analysis::analyzer::semantic::SemanticExecutionBudgetSnapshot,
        execution_charge: brokk_bifrost_analysis::analyzer::semantic::SemanticExecutionBudgetCharge,
    ) -> Result<(), PolicySelectorSessionError> {
        if self
            .semantic_budget
            .check_child_charge(semantic_work, &semantic_charge)
            .is_err()
            || !self
                .semantic_execution_budget
                .can_replay_charge(&execution_before, &execution_charge)
        {
            return Err(semantic_budget_error(format!(
                "{} selectors exhausted the shared semantic materialization budget",
                self.analysis
            )));
        }
        assert!(
            self.semantic_execution_budget
                .replay_charge(&execution_before, &execution_charge),
            "the preflighted selector execution child extends the exclusively borrowed parent"
        );
        self.semantic_budget
            .apply_child_charge(semantic_work, semantic_charge)
            .expect("semantic charge was preflighted against an exclusively borrowed ledger");
        Ok(())
    }
}

/// One recomputed selector unit, both as the compile consumes it and as the
/// store would keep it.
struct ExecutedSelectorUnit {
    rows: UnitExecutionResult,
    sites: Vec<PolicySelectedSite>,
    product: SelectorProduct,
    /// The reads that licence publishing this unit, absent when the ledger
    /// could not name every read the execution made.
    reads: Option<Vec<ReadKey>>,
    publishable: bool,
}

/// Whether a selected site is one a stored product can name.
///
/// A site whose selection carries result-contract, call-shape, call-binding or
/// decorated-parameter evidence is derived from semantic identities the
/// product does not project, so the unit that produced it is used by this
/// compile and never published. Publishability is per unit: the units around
/// it are still independent partitions and stay reusable.
fn selector_site_is_projectable(site: &PolicySelectedSite) -> bool {
    site.result_contract.is_none()
        && site.call_shape.is_none()
        && site.call_binding.is_none()
        && site.decorated_parameter.is_none()
        && !site.retained_incomplete_result_contract_query
}

fn project_selector_site(site: &PolicySelectedSite) -> SelectorProductSite {
    SelectorProductSite {
        rel_path: Box::from(rel_path_string(&site.file).as_str()),
        start: site.span.start,
        end: site.span.end,
        unproven: match &site.proof {
            ProofStatus::Proven => None,
            ProofStatus::Unproven(reason) => Some(reason.clone()),
        },
        partial: match &site.completeness {
            EvidenceCompleteness::Complete => None,
            EvidenceCompleteness::Partial(reason) => Some(reason.clone()),
        },
    }
}

/// Exhaustiveness is checked on the product rather than on how it was
/// obtained: a unit that truncated or raised a diagnostic is not a partition
/// of a whole execution, whichever run computed it.
fn check_exhaustive_selector_rows(
    rows: &UnitExecutionResult,
) -> Result<(), PolicySelectorSessionError> {
    if rows.truncated {
        return Err(PolicySelectorSessionError::Widen(
            WidenReason::UnitNotExhaustive,
        ));
    }
    if !rows.diagnostics.is_empty() {
        return Err(PolicySelectorSessionError::Widen(
            WidenReason::UnitDiagnostics,
        ));
    }
    Ok(())
}

fn lane(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// The per-seed selector units of one policy compile.
///
/// One of these is built per compile that holds an incremental context. It
/// owns the shared reuse decision, the key of every unit every selector of the
/// policy asks about, and the count of what the compile did with them.
pub(super) struct SelectorUnits<'a> {
    reuse: UnitReuse<'a>,
    policy: &'a LoadedPolicy,
    incremental: &'a PolicyIncrementalContext<'a>,
    workspace_files: Vec<ProjectFile>,
    files_by_rel: HashMap<String, ProjectFile>,
    /// The keys of the selector this session is executing now, in seed order.
    current: Vec<PolicyUnitKey>,
    keys: Vec<PolicyUnitKey>,
    attempt: UnitAttempt,
    widen: Option<WidenReason>,
    /// Whether every unit this compile decided about is in the store. A run's
    /// unit list is what another run replays instead of evaluating the policy,
    /// so a list naming a unit that was never published would name work no run
    /// did.
    all_published: bool,
}

impl<'a> SelectorUnits<'a> {
    fn new(
        policy: &'a LoadedPolicy,
        incremental: &'a PolicyIncrementalContext<'a>,
        budget: &'a crate::budget::PolicyBudget,
        workspace: &WorkspaceAnalyzer,
    ) -> Self {
        let workspace_files = workspace.analyzer().analyzed_files();
        let files_by_rel = workspace_files
            .iter()
            .map(|file| (rel_path_string(file), file.clone()))
            .collect();
        Self {
            reuse: UnitReuse::new(policy, incremental, budget),
            policy,
            incremental,
            workspace_files,
            files_by_rel,
            current: Vec::new(),
            keys: Vec::new(),
            attempt: UnitAttempt::default(),
            widen: None,
            all_published: true,
        }
    }

    /// Key every seed file of one selector, and load them all in one batch.
    fn enumerate(
        &mut self,
        query: &CodeQuery,
        selector_path: &str,
    ) -> Result<Vec<ProjectFile>, PolicySelectorSessionError> {
        if !PlanPartitioning::classify(&query.plan).is_by_seed() {
            return Err(PolicySelectorSessionError::Widen(
                WidenReason::PlanCrossesSeeds,
            ));
        }
        // A changed-fact set that could not be completed is smaller than the
        // truth, and a smaller set would let a changed input pass verification.
        if !self.incremental.changed().is_complete() {
            return Err(PolicySelectorSessionError::Widen(
                WidenReason::ReverseDependencyEvidenceMissing,
            ));
        }
        let seed_files = plan_seed_files(&query.plan, &self.workspace_files);
        self.attempt.enumerated(seed_files.len());
        let selector = StableDigest::sha256(selector_path);
        self.current = Vec::with_capacity(seed_files.len());
        for file in &seed_files {
            let language = language_for_file(file);
            let rel_path = rel_path_string(file);
            let Some(blob) = self.incremental.changed().head_blob(language, &rel_path) else {
                // Without the blob this path resolves to there is no content
                // identity to key the unit by, which is missing evidence rather
                // than evidence of sameness.
                return Err(PolicySelectorSessionError::Widen(
                    WidenReason::ReverseDependencyEvidenceMissing,
                ));
            };
            self.current.push(self.incremental.inputs().unit_key(
                self.policy,
                UnitPartition::Selector {
                    language,
                    rel_path: rel_path.into_boxed_str(),
                    blob,
                    selector,
                },
            ));
        }
        self.reuse
            .prefetch(&self.current)
            .map_err(PolicySelectorSessionError::Widen)?;
        self.keys.extend(self.current.iter().cloned());
        Ok(seed_files)
    }

    /// The published product for one seed file of the selector being compiled.
    fn published(
        &mut self,
        index: usize,
    ) -> Result<Option<SelectorProduct>, PolicySelectorSessionError> {
        let key = self.current[index].clone();
        match self
            .reuse
            .published(&key)
            .map_err(PolicySelectorSessionError::Widen)?
        {
            Some(product) => {
                self.attempt.reused();
                // One key names one product shape; anything else is a store
                // that answered a different question.
                let product = product
                    .into_selector()
                    .ok_or(PolicySelectorSessionError::Widen(
                        WidenReason::ProductLoadFailed,
                    ))?;
                Ok(Some(product))
            }
            None => {
                self.attempt.recomputed();
                Ok(None)
            }
        }
    }

    /// One stored product's sites, against this workspace's files.
    fn sites(
        &self,
        product: &SelectorProduct,
    ) -> Result<Vec<PolicySelectedSite>, PolicySelectorSessionError> {
        product
            .sites
            .iter()
            .map(|site| {
                let file = self.files_by_rel.get(site.rel_path.as_ref()).ok_or(
                    // The unit verified against this head, so every path it
                    // named is a path this head analyzes.
                    PolicySelectorSessionError::Widen(
                        WidenReason::ReverseDependencyEvidenceMissing,
                    ),
                )?;
                Ok(PolicySelectedSite {
                    file: file.clone(),
                    span: site.start..site.end,
                    proof: match &site.unproven {
                        None => ProofStatus::Proven,
                        Some(reason) => ProofStatus::Unproven(reason.clone()),
                    },
                    completeness: match &site.partial {
                        None => EvidenceCompleteness::Complete,
                        Some(reason) => EvidenceCompleteness::Partial(reason.clone()),
                    },
                    result_contract: None,
                    call_shape: None,
                    call_binding: None,
                    decorated_parameter: None,
                    retained_incomplete_result_contract_query: false,
                })
            })
            .collect()
    }

    /// Publish one recomputed unit under the reads that produced it.
    fn publish(&mut self, index: usize, executed: &ExecutedSelectorUnit) {
        if !executed.publishable {
            self.all_published = false;
            return;
        }
        let Some(reads) = executed.reads.clone() else {
            self.all_published = false;
            self.attempt.unbounded();
            return;
        };
        self.reuse.publish(
            self.current[index].clone(),
            PolicyUnitProduct::Selector(executed.product.clone()),
            reads,
        );
    }

    fn widened(&mut self, reason: WidenReason) {
        self.widen.get_or_insert(reason);
    }

    fn into_outcome(self) -> SelectorUnitOutcome {
        SelectorUnitOutcome {
            all_published: self.all_published,
            keys: if self.all_published {
                self.keys
            } else {
                Vec::new()
            },
            attempt: self.attempt,
            widen: self.widen,
        }
    }
}

/// What one compile's selector units did.
///
/// `keys` is empty when any unit was not published, because a run's unit list
/// is what another run replays instead of evaluating the policy, and a list
/// naming a unit that was never published would name work no run did.
#[derive(Debug, Default)]
pub(super) struct SelectorUnitOutcome {
    pub(super) keys: Vec<PolicyUnitKey>,
    pub(super) attempt: UnitAttempt,
    pub(super) widen: Option<WidenReason>,
    pub(super) all_published: bool,
}

fn semantic_budget_error(detail: impl Into<String>) -> PolicySelectorSessionError {
    PolicySelectorSessionError::Incomplete {
        completion: CodeQueryCompletion::Incomplete {
            codes: vec![CodeQueryDiagnosticCode::SemanticBudgetExhausted],
        },
        detail: detail.into(),
    }
}

pub(super) fn semantic_work_limits(limits: CodeQuerySemanticLimits) -> SemanticWork {
    use SemanticBudgetDimension as Dimension;
    SemanticWork {
        source_bytes: limits.max_source_bytes,
        procedures: limits.rows(Dimension::Procedures),
        blocks: limits.rows(Dimension::Blocks),
        program_points: limits.rows(Dimension::ProgramPoints),
        values: limits.rows(Dimension::Values),
        allocations: limits.rows(Dimension::Allocations),
        call_sites: limits.rows(Dimension::CallSites),
        memory_locations: limits.rows(Dimension::MemoryLocations),
        captures: limits.rows(Dimension::Captures),
        source_mappings: limits.rows(Dimension::SourceMappings),
        evidence: limits.rows(Dimension::Evidence),
        gaps: limits.rows(Dimension::Gaps),
        events: limits.rows(Dimension::Events),
        control_edges: limits.rows(Dimension::ControlEdges),
        nested_entries: limits.rows(Dimension::NestedEntries),
        owned_text_bytes: limits.max_retained_bytes,
    }
}

pub(super) fn source_range(span: &ByteRange<usize>) -> Range {
    Range {
        start_byte: span.start,
        end_byte: span.end,
        start_line: 0,
        end_line: 0,
    }
}

fn row_binding_queries(
    plan: &crate::definition::RowSelectorPlan,
) -> Result<Vec<(RowBindingName, CodeQuery)>, PolicySelectorSessionError> {
    let mut queries: Vec<(RowBindingName, CodeQuery)> = Vec::with_capacity(plan.bindings.len());
    let mut by_name = HashMap::<&str, usize>::new();
    for binding in &plan.bindings {
        let query = match &binding.source {
            RowBindingSource::Query(crate::PolicySelector::Inline { query, .. }) => query.clone(),
            RowBindingSource::Query(crate::PolicySelector::File { .. }) => {
                return Err(PolicySelectorSessionError::Unavailable(format!(
                    "row selector binding `{}` uses a deferred file selector",
                    binding.name
                )));
            }
            RowBindingSource::Query(crate::PolicySelector::Rows { .. }) => {
                return Err(PolicySelectorSessionError::Unavailable(format!(
                    "row selector binding `{}` nests another row selector",
                    binding.name
                )));
            }
            RowBindingSource::Expansion { from, step } => {
                let source = by_name
                    .get(from.as_str())
                    .and_then(|index| queries.get(*index));
                let Some((_, source)) = source else {
                    return Err(PolicySelectorSessionError::Unavailable(format!(
                        "row selector binding `{}` expands unavailable binding `{from}`",
                        binding.name
                    )));
                };
                let mut query = source.clone();
                match step {
                    RowExpansionStep::ReceiverOutcome | RowExpansionStep::ReceiverEvidence => {
                        let source_is_receiver = query
                            .validate_steps()
                            .is_ok_and(|kind| kind == QueryValueKind::ReceiverAnalysis);
                        if !source_is_receiver {
                            query
                                .plan
                                .steps
                                .push(QueryStep::ReceiverTargets(Default::default()));
                        }
                        query.plan.steps.push(match step {
                            RowExpansionStep::ReceiverOutcome => QueryStep::ReceiverOutcome,
                            _ => QueryStep::ReceiverEvidence,
                        });
                    }
                    RowExpansionStep::MemberSelection => {
                        query.plan.steps.push(QueryStep::MemberSelection)
                    }
                    RowExpansionStep::MemberCandidates => query
                        .plan
                        .steps
                        .push(QueryStep::CandidatesOf(Default::default())),
                    RowExpansionStep::CandidateHierarchy => {
                        query.plan.steps.push(QueryStep::CandidateHierarchy)
                    }
                    RowExpansionStep::MemberFamily => {
                        query.plan.steps.push(QueryStep::MemberFamily)
                    }
                    RowExpansionStep::FamilyEdges => query.plan.steps.push(QueryStep::FamilyEdges),
                    RowExpansionStep::DispatchOutcome => {
                        query.plan.steps.push(QueryStep::DispatchOutcome)
                    }
                    RowExpansionStep::DispatchTargets => {
                        query.plan.steps.push(QueryStep::DispatchTargets)
                    }
                }
                query
            }
        };
        by_name.insert(binding.name.as_str(), queries.len());
        queries.push((binding.name.clone(), query));
    }
    Ok(queries)
}

pub(super) fn selected_site_quality(
    item: &CodeQueryResultItem,
) -> (ProofStatus, EvidenceCompleteness) {
    let semantic = match &item.value {
        CodeQueryResultValue::Procedure { value } => Some(&value.evidence),
        CodeQueryResultValue::ProgramPoint { value } => Some(&value.evidence),
        CodeQueryResultValue::ControlEdge { value } => Some(&value.evidence),
        CodeQueryResultValue::TypestateWitness { value } => Some(&value.quality),
        CodeQueryResultValue::TaintFinding { value } => Some(&value.evidence),
        _ => None,
    };
    let (proof, mut completeness) = if let Some(semantic) = semantic {
        semantic_binding_quality(semantic)
    } else {
        match &item.value {
            CodeQueryResultValue::TypestateFinding { value } => (
                if value.path_proven {
                    ProofStatus::Proven
                } else {
                    ProofStatus::Unproven("selector path is unproven".into())
                },
                if value.path_complete && value.analysis_complete {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial("selector analysis is incomplete".into())
                },
            ),
            CodeQueryResultValue::ReferenceSite { value } => (
                proof_from_label(value.proof),
                EvidenceCompleteness::Complete,
            ),
            CodeQueryResultValue::CallSite { value } => (
                proof_from_label(value.proof),
                EvidenceCompleteness::Complete,
            ),
            CodeQueryResultValue::JsxAttributeValue { value } => (
                ProofStatus::Proven,
                if value.coverage == "complete" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        value
                            .reason
                            .unwrap_or("JSX attribute value projection is incomplete")
                            .to_string()
                            .into(),
                    )
                },
            ),
            CodeQueryResultValue::FieldWriteValue { value } => (
                if value.proof == "precise" {
                    ProofStatus::Proven
                } else {
                    ProofStatus::Unproven(
                        format!("field-write proof is {}", value.proof).into(),
                    )
                },
                if value.completeness == "complete" && value.coverage == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!(
                            "field-write evidence is completeness={}, coverage={}",
                            value.completeness, value.coverage
                        )
                        .into(),
                    )
                },
            ),
            // An edge row carries its own proof attribution, exactly as a
            // reference site does; set-level completeness is the query's
            // diagnostics' business (#1479).
            CodeQueryResultValue::ReferenceEdge { value } => (
                proof_from_label(value.proof),
                EvidenceCompleteness::Complete,
            ),
            // A flow-state row is exactly what the derivation computed; its
            // per-axis account is the row's own `completeness` field, so a
            // partial derivation makes the selector's evidence partial rather
            // than silently complete (#1480).
            CodeQueryResultValue::StateEvent { value } => (
                ProofStatus::Proven,
                flow_state_completeness(value.completeness, &value.uncovered_axes),
            ),
            CodeQueryResultValue::FlowRelation { value } => (
                ProofStatus::Proven,
                flow_state_completeness(value.completeness, &value.uncovered_axes),
            ),
            // A control-relation row states its own per-relation completeness
            // the same way, so a derivation whose budget ran out makes the
            // selector's evidence partial rather than silently complete
            // (#2443).
            CodeQueryResultValue::ControlRelation { value } => (
                ProofStatus::Proven,
                control_relation_completeness(value.completeness, &value.uncovered_relations),
            ),
            // A guard row carries the IR evidence of the decision it records,
            // so an unproven or partial lowering makes the selector's evidence
            // unproven or partial rather than silently clean (#2443).
            CodeQueryResultValue::Guard { value } => (
                proof_from_label(value.proof),
                if value.completeness == "complete" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        "guard lowering evidence is partial".into(),
                    )
                },
            ),
            CodeQueryResultValue::CallResult { value } => (
                proof_from_label(value.proof),
                if value.completeness == "complete" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        "call-result lowering evidence is partial".into(),
                    )
                },
            ),
            // A topology row states its own completeness the same way: a build
            // model nobody could read in full makes the selector's evidence
            // partial rather than silently complete (#2448).
            CodeQueryResultValue::SourceSet { value } => (
                ProofStatus::Proven,
                topology_completeness(value.completeness),
            ),
            CodeQueryResultValue::BuildTarget { value } => (
                ProofStatus::Proven,
                topology_completeness(value.completeness),
            ),
            CodeQueryResultValue::TopologyEdge { value } => (
                ProofStatus::Proven,
                topology_completeness(value.completeness),
            ),
            // A rewrite-path row states its own per-domain completeness the
            // same way, so a derivation that could not run makes the
            // selector's evidence partial rather than silently complete
            // (#1480).
            CodeQueryResultValue::RewritePath { value } => (
                ProofStatus::Proven,
                rewrite_path_completeness(value.completeness, &value.uncovered_domains),
            ),
            CodeQueryResultValue::ReceiverAnalysis { .. }
            | CodeQueryResultValue::MemberTargetAnalysis { .. }
            | CodeQueryResultValue::FlowEndpoint { .. }
            | CodeQueryResultValue::FlowWitness { .. } => (
                ProofStatus::Unproven("selector evidence is not exact".into()),
                EvidenceCompleteness::Partial("selector evidence is not exhaustive".into()),
            ),
            CodeQueryResultValue::CallShape { value } => (
                ProofStatus::Proven,
                if value.coverage == "exact" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!("call shape coverage is {}", value.coverage).into(),
                    )
                },
            ),
            // A signature row is proven evidence of what the analyzer
            // persisted, but it is only complete when the language actually
            // recorded an arity. An `arity_unrecorded` or `unrecorded` row
            // must turn an exact-arity assertion unreliable rather than clean.
            CodeQueryResultValue::CallableSignature { value } => (
                ProofStatus::Proven,
                if value.coverage == "exact" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!("callable signature coverage is {}", value.coverage).into(),
                    )
                },
            ),
            // A parameter row whose optionality the language never recorded
            // cannot support a required-versus-optional claim.
            CodeQueryResultValue::SignatureParameter { value } => (
                ProofStatus::Proven,
                if value.optional.is_some() {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        "declared parameter optionality is unrecorded".into(),
                    )
                },
            ),
            // A decorated parameter is an exact source anchor, but a policy
            // endpoint can bind its value only when the row retained a
            // complete parameter port and decorator-binding identity.
            CodeQueryResultValue::DecoratedParameter { value } => {
                let complete = value.terminal
                    && value.completion == "complete"
                    && value.coverage == "complete"
                    && value.procedure_id.is_some()
                    && value.value_id.is_some()
                    && value.parameter_ordinal.is_some()
                    && value.port_id.is_some();
                if complete {
                    (ProofStatus::Proven, EvidenceCompleteness::Complete)
                } else {
                    (
                        ProofStatus::Unproven(
                            "decorated parameter binding or value port is incomplete".into(),
                        ),
                        EvidenceCompleteness::Partial(
                            "decorated parameter binding or value port is incomplete".into(),
                        ),
                    )
                }
            }
            // An overload-selection summary is proven evidence of what the
            // resolver considered, but it is complete only when every verdict
            // was decidable. `unknown_shape` -- an unsupported language, an
            // untraced site, or any undecidable candidate -- must turn an
            // exact-cardinality assertion over the site unreliable rather than
            // clean.
            CodeQueryResultValue::OverloadSelection { value } => (
                ProofStatus::Proven,
                if value.resolution == "unknown_shape" {
                    EvidenceCompleteness::Partial(
                        if value.supported {
                            "overload selection is undecidable at this site"
                        } else {
                            "this language does not report callable applicability"
                        }
                        .into(),
                    )
                } else {
                    EvidenceCompleteness::Complete
                },
            ),
            // A candidate whose applicability nobody could decide cannot
            // support an applicable-or-not claim.
            CodeQueryResultValue::CallableApplicability { value } => (
                ProofStatus::Proven,
                if value.verdict == "unknown" {
                    EvidenceCompleteness::Partial(
                        "candidate applicability is undecided".into(),
                    )
                } else {
                    EvidenceCompleteness::Complete
                },
            ),
            CodeQueryResultValue::CallArgumentGroup { .. }
            | CodeQueryResultValue::CallArgument { .. } => (
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
            ),
            // An effect row's own quality is its derivation and its coverage:
            // a `declared` row with an exhaustive site or procedure is a
            // complete claim, and anything else admits a missing effect.
            CodeQueryResultValue::CallEffect { value } => (
                ProofStatus::Proven,
                if value.coverage == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!("call effect coverage is {}", value.coverage).into(),
                    )
                },
            ),
            CodeQueryResultValue::ResultContractUse { value } => (
                ProofStatus::Proven,
                if value.coverage == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!("result-contract use coverage is {}", value.coverage).into(),
                    )
                },
            ),
            CodeQueryResultValue::ResultContractFailureUse { value } => (
                proof_from_label(value.proof),
                if value.coverage == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!("result-contract failure-use coverage is {}", value.coverage)
                            .into(),
                    )
                },
            ),
            // Result-contract identity is a dispatch-derived claim. A row can
            // have exhaustive candidate coverage while its target proof is
            // still unproven, so neither axis may be inferred from query-level
            // completion alone.
            CodeQueryResultValue::CallResultContract { value } => (
                value.proof.map_or_else(
                    || ProofStatus::Unproven("result-contract dispatch proof is absent".into()),
                    proof_from_label,
                ),
                if value.coverage == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!("result-contract dispatch coverage is {}", value.coverage).into(),
                    )
                },
            ),
            CodeQueryResultValue::ProcedureEffect { value } => (
                ProofStatus::Proven,
                if value.coverage == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!("procedure effect coverage is {}", value.coverage).into(),
                    )
                },
            ),
            CodeQueryResultValue::CallBinding { value } => (
                if value.selector_exact {
                    ProofStatus::Proven
                } else {
                    ProofStatus::Unproven("call-binding selector proof is absent".into())
                },
                if value.mapping == "exact"
                    && value.coverage == "exhaustive"
                    && !value.terminal
                    && value.argument_id.is_some()
                    && value.selector_exact
                    && value.selector_proof.is_some()
                {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!(
                            "call binding is mapping={}, coverage={}, terminal={}, selector={}/{:?}, dispatch={}/{}/{:?}, targets={}, truncated={}",
                            value.mapping,
                            value.coverage,
                            value.terminal,
                            value.selector_exact,
                            value.selector_proof,
                            value.dispatch_outcome,
                            value.dispatch_coverage,
                            value.dispatch_completeness,
                            value.dispatch_target_count,
                            value.dispatch_targets_truncated,
                        )
                        .into(),
                    )
                },
            ),
            CodeQueryResultValue::ReceiverOutcome { value } => (
                ProofStatus::Proven,
                if value.coverage == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!("receiver outcome coverage is {}", value.coverage).into(),
                    )
                },
            ),
            CodeQueryResultValue::ReceiverEvidence { value } => (
                proof_from_label(value.proof),
                if value.completeness == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!("receiver evidence is {}", value.completeness).into(),
                    )
                },
            ),
            CodeQueryResultValue::MemberSelection { value } => (
                ProofStatus::Proven,
                if value.coverage == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!("member selection coverage is {}", value.coverage).into(),
                    )
                },
            ),
            CodeQueryResultValue::NilnessOperation { value } => (
                if value.proof == "exact" {
                    ProofStatus::Proven
                } else {
                    ProofStatus::Unproven(
                        value.reason.unwrap_or("nilness proof is open").into(),
                    )
                },
                if value.coverage == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        value.reason.unwrap_or("nilness coverage is open").into(),
                    )
                },
            ),
            CodeQueryResultValue::SwitchCoverage { value } => (
                if value.proof == "exact" {
                    ProofStatus::Proven
                } else {
                    ProofStatus::Unproven(
                        value.reason.unwrap_or("switch coverage proof is open").into(),
                    )
                },
                if value.verdict == "unknown" {
                    EvidenceCompleteness::Partial(
                        value.reason.unwrap_or("switch coverage is unknown").into(),
                    )
                } else {
                    EvidenceCompleteness::Complete
                },
            ),
            CodeQueryResultValue::ConcurrentAccessConflict { value } => (
                if value.proof == "proven" {
                    ProofStatus::Proven
                } else {
                    ProofStatus::Unproven(
                        value
                            .reasons
                            .first()
                            .map(String::as_str)
                            .unwrap_or("concurrent access proof is open")
                            .into(),
                    )
                },
                if value.coverage == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        value
                            .reasons
                            .first()
                            .map(String::as_str)
                            .unwrap_or("concurrent access coverage is open")
                            .into(),
                    )
                },
            ),
            // A class-set row's own status is its proof story: only a `known`
            // row is a proven claim, every other status carries no proof.
            CodeQueryResultValue::ClassSetRow { value } => (
                if value.status == "known" {
                    ProofStatus::Proven
                } else {
                    ProofStatus::Unproven("class-set row carries no proof".into())
                },
                if value.status == "known" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!("class-set status is {}", value.status).into(),
                    )
                },
            ),
            // An absent-member finding fires only on a fully known class set
            // and a proven-absent member lookup, so the row is its own proof;
            // set-level completeness is the query diagnostics' business, the
            // reference-edge precedent.
            CodeQueryResultValue::AbsentMemberFinding { .. } => {
                (ProofStatus::Proven, EvidenceCompleteness::Complete)
            }
            CodeQueryResultValue::DetachedTaskTransfer { value } => (
                if value.proof == "exact" {
                    ProofStatus::Proven
                } else {
                    ProofStatus::Unproven(
                        value.reason.unwrap_or("detached object identity is open").into(),
                    )
                },
                if value.coverage == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        value.reason.unwrap_or("detached object identity is open").into(),
                    )
                },
            ),
            CodeQueryResultValue::StructuralMatch { .. }
            | CodeQueryResultValue::Declaration { .. }
            | CodeQueryResultValue::File { .. }
            | CodeQueryResultValue::CandidateHop { .. }
            | CodeQueryResultValue::DispatchOutcome { .. }
            | CodeQueryResultValue::DispatchTarget { .. }
            | CodeQueryResultValue::MemberFamily { .. }
            | CodeQueryResultValue::MemberFamilyEdge { .. }
            | CodeQueryResultValue::ExpressionSite { .. }
            // An occurrence row is an exact parser fact about one token. Its
            // completeness question is per role and is answered by the query's
            // diagnostics, not by this per-row evidence judgement.
            | CodeQueryResultValue::Occurrence { .. }
            // A scope, a binding and a candidate row are each an exact record
            // of what one producer derived at one position; whether the *set*
            // is complete is per axis and is answered by the query's
            // diagnostics, exactly as for an occurrence.
            | CodeQueryResultValue::LexicalScope { .. }
            | CodeQueryResultValue::Binding { .. }
            | CodeQueryResultValue::ResolutionCandidate { .. }
            // The materialization rows follow the same reasoning (#1476):
            // each is an exact record of recorded provenance, and per-axis
            // completeness arrives through the query's diagnostics.
            | CodeQueryResultValue::GenerationSite { .. }
            | CodeQueryResultValue::Export { .. }
            | CodeQueryResultValue::DeclarationState { .. }
            // The identity-route rows are parser facts with the same per-axis
            // completeness story (#1475).
            | CodeQueryResultValue::QualifiedPath { .. }
            | CodeQueryResultValue::PathSegment { .. } => {
                (ProofStatus::Proven, EvidenceCompleteness::Complete)
            }
            CodeQueryResultValue::Procedure { .. }
            | CodeQueryResultValue::ProgramPoint { .. }
            | CodeQueryResultValue::ControlEdge { .. }
            | CodeQueryResultValue::TypestateWitness { .. }
            | CodeQueryResultValue::TaintFinding { .. } => {
                unreachable!("semantic result evidence was handled above")
            }
        }
    };
    if item.provenance_truncated {
        completeness = EvidenceCompleteness::Partial("selector provenance was truncated".into());
    }
    (proof, completeness)
}

fn semantic_binding_quality(
    evidence: &CodeQuerySemanticEvidence,
) -> (ProofStatus, EvidenceCompleteness) {
    let proof = match evidence.proof {
        CodeQuerySemanticProof::Proven => ProofStatus::Proven,
        CodeQuerySemanticProof::Unproven => {
            ProofStatus::Unproven("selector semantic evidence is unproven".into())
        }
    };
    let completeness = match evidence.completeness {
        CodeQuerySemanticCompleteness::Complete => EvidenceCompleteness::Complete,
        CodeQuerySemanticCompleteness::Partial => {
            EvidenceCompleteness::Partial("selector semantic evidence is partial".into())
        }
    };
    (proof, completeness)
}

/// The evidence completeness one flow-state row carries (#1480).
///
/// `partial` is never silently upgraded: the uncovered axes travel into the
/// reason string so a policy reader sees which part of the derivation is
/// missing rather than a bare "incomplete".
fn flow_state_completeness(
    completeness: &str,
    uncovered_axes: &[&'static str],
) -> EvidenceCompleteness {
    if completeness == "complete" {
        EvidenceCompleteness::Complete
    } else {
        EvidenceCompleteness::Partial(
            format!(
                "flow-state derivation does not cover [{}]",
                uncovered_axes.join(", ")
            )
            .into(),
        )
    }
}

/// The evidence completeness one rewrite-path row carries (#1480).
fn rewrite_path_completeness(
    completeness: &str,
    uncovered_domains: &[&'static str],
) -> EvidenceCompleteness {
    if completeness == "complete" {
        EvidenceCompleteness::Complete
    } else {
        EvidenceCompleteness::Partial(
            format!(
                "rewrite-path derivation does not cover [{}]",
                uncovered_domains.join(", ")
            )
            .into(),
        )
    }
}

fn topology_completeness(completeness: &str) -> EvidenceCompleteness {
    if completeness == "complete" {
        EvidenceCompleteness::Complete
    } else {
        EvidenceCompleteness::Partial(
            "the workspace's declared build topology was not read in full".into(),
        )
    }
}

fn control_relation_completeness(
    completeness: &str,
    uncovered_relations: &[&'static str],
) -> EvidenceCompleteness {
    if completeness == "complete" {
        EvidenceCompleteness::Complete
    } else {
        EvidenceCompleteness::Partial(
            format!(
                "control-relation derivation does not cover [{}]",
                uncovered_relations.join(", ")
            )
            .into(),
        )
    }
}

fn proof_from_label(label: &str) -> ProofStatus {
    if label == "proven" {
        ProofStatus::Proven
    } else {
        ProofStatus::Unproven(format!("selector evidence is {label}").into())
    }
}

/// Whether one formal parameter slot names `expected`.
///
/// A slot carries every spelling the declaration gives one parameter, because
/// some languages name a formal twice (Swift's external and internal labels)
/// and some prefix it in source but not in a call (PHP's `$value`). Matching
/// any spelling is what lets one authored `(argument :name "value")` bind the
/// same formal in every language that declares it.
pub(super) fn parameter_names_match(names: &[String], expected: &str) -> bool {
    names
        .iter()
        .any(|name| parameter_name_matches(name, expected))
}

/// The single-spelling form of [`parameter_names_match`], for a name taken
/// from a call's keyword actual rather than from a declaration slot.
pub(super) fn parameter_name_matches(name: &str, expected: &str) -> bool {
    name == expected
        || name.strip_prefix('$') == Some(expected)
        || expected.strip_prefix('$') == Some(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
    use crate::{
        PolicyBudget, PolicySelectorPath, PolicySourceIdentity, SchemaVersionOrigin,
        SchemaVersionResolution, SelectorOrigin,
    };
    use brokk_bifrost_analysis::analyzer::semantic_model::{
        CatalogOptions, CompilerOptions, SemanticModelActivationEvidence,
        SemanticModelActivationRequest, SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome,
        SemanticPackCatalog, SessionPackSource, SessionPackSourceKind, SourceFormat,
        acquire_active_semantic_models, compile_source,
    };
    use brokk_bifrost_analysis::analyzer::{AnalyzerConfig, Language, WorkspaceAnalyzer};
    use brokk_bifrost_rql::structural::CodeQuery;

    const EXACT_EXTERNAL_RECEIVER_MODEL: &str = r#"{
  "schema_version": 2,
  "pack_id": "bifrost.test.go.external-receiver",
  "version": "1.0.0",
  "producer": { "name": "bifrost-test", "version": "1.0.0" },
  "language": "go",
  "ecosystem": "go",
  "compatibility": { "bifrost": ">=0.10.6, <1.0.0", "toolchains": [] },
  "provenance": { "source": "test fixture", "revision": "1" },
  "license": "MIT",
  "completeness": "complete",
  "safety": { "generated_code_only": false, "review_required": false },
  "shards": [{
    "id": "go.external.receiver.declarations",
    "activation": [{}],
    "payload": {
      "kind": "declaration_facts",
      "types": [{
        "id": "type.external-module",
        "name": "example.com/external",
        "type_kind": "module",
        "visibility": "package",
        "is_abstract": false,
        "is_sealed": false,
        "has_explicit_type_terms": false,
        "type_parameters": [],
        "type_parameter_constraints": [],
        "embedded_types": [],
        "hierarchy": [],
        "aliases": ["external"],
        "extension_surfaces": [],
        "locator": {
          "kind": "artifact",
          "path": "src/example.com/external/file.go",
          "symbol": "example.com/external"
        }
      }, {
        "id": "type.external-resource",
        "name": "example.com/external.Resource",
        "type_kind": "struct",
        "visibility": "public",
        "is_abstract": false,
        "is_sealed": false,
        "has_explicit_type_terms": false,
        "type_parameters": [],
        "type_parameter_constraints": [],
        "embedded_types": [],
        "hierarchy": [],
        "aliases": [],
        "extension_surfaces": [],
        "locator": {
          "kind": "artifact",
          "path": "src/example.com/external/file.go",
          "symbol": "example.com/external.Resource"
        }
      }],
      "members": [{
        "id": "member.external-open",
        "owner": "type.external-module",
        "name": "Open",
        "member_kind": "function",
        "visibility": "public",
        "is_static": true,
        "is_abstract": false,
        "is_virtual": false,
        "signature": {
          "type_parameters": [],
          "parameters": [],
          "returns": {
            "kind": "tuple",
            "elements": [{
              "kind": "pointer",
              "element": {
                "kind": "declared",
                "id": "type.external-resource",
                "arguments": [],
                "nullable": false
              }
            }, {
              "kind": "named",
              "name": "error",
              "arguments": [],
              "nullable": false
            }]
          }
        },
        "aliases": [],
        "locator": {
          "kind": "artifact",
          "path": "src/example.com/external/file.go",
          "symbol": "example.com/external.Open"
        }
      }, {
        "id": "member.external-resource-read",
        "owner": "type.external-resource",
        "name": "Read",
        "member_kind": "method",
        "visibility": "public",
        "is_static": false,
        "is_abstract": false,
        "is_virtual": false,
        "signature": {
          "type_parameters": [],
          "parameters": [],
          "returns": {
            "kind": "named",
            "name": "error",
            "arguments": [],
            "nullable": false
          }
        },
        "receiver": { "pointer": true },
        "aliases": [],
        "locator": {
          "kind": "artifact",
          "path": "src/example.com/external/file.go",
          "symbol": "example.com/external.Resource.Read"
        }
      }],
      "relations": []
    }
  }, {
    "id": "go.external.receiver.summaries",
    "activation": [{}],
    "payload": {
      "kind": "procedure_summaries",
      "summaries": [{
        "id": "external.open",
        "target": {
          "path": "src/example.com/external/file.go",
          "symbol": "example.com/external.Open()",
          "has_receiver": false,
          "parameter_count": 0
        },
        "completeness": "complete",
        "normal_result_count": 2,
        "transfers": [],
        "effects": [],
        "result_contracts": [{
          "result_ordinal": 0,
          "condition_result_ordinal": 1,
          "predicate": "null",
          "result_success_predicate": "non_null",
          "member_contracts": [{
            "member": "Read",
            "parameter_count": 0,
            "completeness": "complete",
            "preconditions": []
          }]
        }]
      }]
    }
  }]
}"#;

    fn one_file_workspace() -> (BuiltInlineTestProject, WorkspaceAnalyzer) {
        let project = InlineTestProject::with_language(Language::Go)
            .file(
                "subject.go",
                "package subject\n\nfunc subject() {}\nfunc second() {}\nfunc third() {}\n",
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        (project, workspace)
    }

    fn cfg_entry_selector(name: &str, path: &str) -> ResolvedPolicySelector {
        let query = CodeQuery::from_source(&format!(
            r#"(cfg-entry (procedure-of (function :name "{name}")))"#
        ))
        .expect("valid semantic selector");
        ResolvedPolicySelector::try_new(
            PolicySelectorPath::new(path).expect("valid selector path"),
            SchemaVersionResolution {
                version: u32::try_from(query.schema_version).expect("u32 schema version"),
                origin: SchemaVersionOrigin::Explicit,
            },
            query,
            SelectorOrigin::Document {
                source: PolicySourceIdentity::new("test.rqlp"),
            },
        )
        .expect("resolved selector")
    }

    fn resolved_selector(source: &str, path: &str) -> ResolvedPolicySelector {
        let query = CodeQuery::from_source(source).expect("valid test selector");
        ResolvedPolicySelector::try_new(
            PolicySelectorPath::new(path).expect("valid selector path"),
            SchemaVersionResolution {
                version: u32::try_from(query.schema_version).expect("u32 schema version"),
                origin: SchemaVersionOrigin::Explicit,
            },
            query,
            SelectorOrigin::Document {
                source: PolicySourceIdentity::new("test.rqlp"),
            },
        )
        .expect("resolved selector")
    }

    fn limits_for_one_census_and_repeats(
        mut limits: CodeQueryExecutionLimits,
        census: SemanticWork,
        retained_peak: usize,
        traversal_per_selector: usize,
        repeats: usize,
    ) -> CodeQueryExecutionLimits {
        let row_limit = |dimension| {
            census.get(dimension).max(1).saturating_add(
                usize::from(dimension == SemanticBudgetDimension::NestedEntries) * repeats,
            )
        };
        limits.semantic = CodeQuerySemanticLimits {
            max_materialized_files: 1,
            max_source_bytes: census.source_bytes.max(1),
            max_rows_per_dimension: 1,
            max_retained_bytes: retained_peak.max(census.owned_text_bytes).max(1),
            max_traversal_steps: traversal_per_selector
                .max(1)
                .saturating_mul(repeats.saturating_add(1)),
            rows_per_dimension: Some(CodeQuerySemanticRowLimits::from_rows(row_limit)),
        };
        limits
    }

    #[test]
    fn terminal_result_contract_rows_do_not_become_policy_sites() {
        let project = InlineTestProject::with_language(Language::Go)
            .file(
                "subject.go",
                r#"package subject

func target() {}
func caller() { target() }
"#,
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        let cancellation = CancellationToken::default();
        let selector = resolved_selector(
            r#"(call-result-contracts (call-shape (call :callee (name "target"))))"#,
            "/analysis/terminal-result-contract",
        );
        let mut session = PolicySelectorSession::new(
            &workspace,
            "test",
            PolicyBudget::default().query_limits(),
            64,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );

        let selected = session
            .select_with_artifact_continuation(&selector)
            .expect("an exact unmodeled call produces a complete terminal contract row");

        assert!(
            selected.is_empty(),
            "a terminal result-contract row is a proven non-applicability result"
        );
    }

    #[test]
    fn child_evaluation_extends_peaks_without_recounting_cumulative_ledgers() {
        let compile_peaks = PolicySemanticPeaks {
            row_dimension: 12,
            retained_bytes: 150,
            traversal_steps: 17,
        };
        let compile_work = SemanticWork {
            nested_entries: 10,
            owned_text_bytes: 100,
            ..SemanticWork::default()
        };
        let evaluation_work = SemanticWork {
            nested_entries: 7,
            owned_text_bytes: 40,
            ..SemanticWork::default()
        };

        let peaks = compile_peaks.with_child_evaluation(compile_work, evaluation_work, 180, 23);

        assert_eq!(peaks.row_dimension, 17);
        assert_eq!(peaks.retained_bytes, 180);
        assert_eq!(peaks.traversal_steps, 23);
    }

    #[test]
    fn receiver_binding_distinguishes_go_function_method_field_and_unknown() {
        let project = InlineTestProject::new()
            .file("go.mod", "module example.com/receiver-binding\n\ngo 1.22\n")
            .file(
                "app.go",
                r#"package app

import (
    "encoding/binary"
    external "example.com/external"
    unknownpkg "example.com/unknown"
)

type resource struct{}
type callbacks struct { Read func() error }

func Source() resource { return resource{} }
func (resource) Read() error { return nil }

func inspect(item resource, callback callbacks, unknown unknownpkg.Resource) {
    _ = binary.Read(nil, binary.LittleEndian, nil)
    _ = item.Read()
    _ = callback.Read()
    known, err := external.Open()
    if err != nil { return }
    _ = known.Read()
    _ = Source().Read()
    _ = unknown.Read()
}
"#,
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        let pack = compile_source(
            SourceFormat::Json,
            EXACT_EXTERNAL_RECEIVER_MODEL.as_bytes(),
            &CompilerOptions::default(),
        )
        .unwrap_or_else(|diagnostics| {
            panic!("external receiver model must compile: {diagnostics:#?}")
        });
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
            .expect("ephemeral semantic-pack catalog");
        catalog
            .register_session_pack(
                &pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: "test:exact-external-receiver".to_owned(),
                },
            )
            .expect("external receiver model registers");
        let activation = acquire_active_semantic_models(
            workspace.analyzer(),
            &catalog,
            None,
            &SemanticModelActivationRequest {
                bifrost_version: env!("CARGO_PKG_VERSION")
                    .parse()
                    .expect("crate version is semver"),
                evidence: vec![SemanticModelActivationEvidence {
                    language: "go".to_owned(),
                    ecosystem: "go".to_owned(),
                    package: None,
                    module: None,
                    toolchain: None,
                    target: None,
                    configuration: None,
                    artifact_sha256: None,
                }],
                controls: Vec::new(),
                limits: SemanticModelRuntimeLimits::default(),
            },
            &CancellationToken::default(),
        );
        assert!(
            matches!(activation, SemanticModelRuntimeOutcome::Ready { .. }),
            "external receiver model activates: {activation:#?}"
        );
        let selector = resolved_selector(
            r#"(language go (call-shape (call :callee (name "Read"))))"#,
            "/analysis/events/inspect",
        );
        let cancellation = CancellationToken::default();
        let budget = PolicyBudget::default();
        let mut session = PolicySelectorSession::new(
            &workspace,
            "test",
            budget.query_limits(),
            64,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );
        let mut selected = session
            .select(&selector)
            .expect("all Read calls are selected structurally");
        selected.sort_by_key(|site| site.span.start);
        assert_eq!(selected.len(), 6);

        let mut applicability = Vec::new();
        for (site_index, site) in selected.into_iter().enumerate() {
            let artifact = session
                .materialize(&site.file)
                .expect("selected Go file materializes");
            let mut calls = Vec::new();
            for semantics in artifact.procedures() {
                let procedure = artifact
                    .procedure_handle(semantics.id())
                    .expect("artifact procedure has a handle");
                for call in semantics.call_sites() {
                    let span = semantics
                        .source_mapping(call.source)
                        .expect("validated call has a source mapping")
                        .locator
                        .anchor()
                        .span();
                    if span.start_byte() as usize == site.span.start
                        && span.end_byte() as usize == site.span.end
                    {
                        calls.push((
                            procedure.clone(),
                            procedure
                                .call_site_handle(call.id)
                                .expect("validated call has a handle"),
                        ));
                    }
                }
            }
            assert!(!calls.is_empty(), "selected row names a semantic call");
            if site_index == 3 {
                let [(_, call)] = calls.as_slice() else {
                    panic!("the exact external receiver has one semantic lowering: {calls:#?}");
                };
                let oracle = workspace.semantic_oracle_provider();
                let mut semantic_budget = SemanticBudget::default();
                let dispatch_outcome = oracle
                    .resolve_call(
                        call,
                        &mut SemanticRequest::new(&mut semantic_budget, &cancellation),
                    )
                    .expect("exact external receiver dispatch runs");
                let SemanticOutcome::Complete {
                    value: dispatch, ..
                } = dispatch_outcome
                else {
                    panic!(
                        "the declaration and summary packs must close this exact external dispatch: {dispatch_outcome:#?}"
                    );
                };
                assert_eq!(dispatch.coverage(), CandidateCoverage::Exhaustive);
                assert!(dispatch.candidates().is_empty());
                let [boundary] = dispatch.boundaries() else {
                    panic!("exact external receiver keeps one boundary: {dispatch:#?}");
                };
                assert!(matches!(
                    &boundary.completeness,
                    EvidenceCompleteness::Partial(_)
                ));
                assert_eq!(boundary.proven_external_receiver_shape(), Some(true));
            }
            applicability.push(
                session
                    .receiver_binding_applicability(&calls)
                    .expect("receiver applicability is available"),
            );
        }

        assert_eq!(
            applicability,
            [
                ReceiverBindingApplicability::ExactNonMatch,
                ReceiverBindingApplicability::Applicable,
                ReceiverBindingApplicability::ExactNonMatch,
                ReceiverBindingApplicability::Applicable,
                ReceiverBindingApplicability::Applicable,
                ReceiverBindingApplicability::CandidateReceiver,
            ]
        );
    }

    /// Issue #2523. The lanes of the shared semantic ledger deplete at wildly
    /// different rates, so one bind that legitimately spends most of
    /// `nested_entries` must not cap every other dimension of every later
    /// query at what is left of that one lane.
    #[test]
    fn a_drained_lane_caps_itself_and_no_other_dimension() {
        let (_directory, workspace) = one_file_workspace();
        let cancellation = CancellationToken::default();
        let budget = PolicyBudget::default();
        let rows = budget.query_limits().semantic.max_rows_per_dimension;
        let mut session = PolicySelectorSession::new(
            &workspace,
            "test",
            budget.query_limits(),
            64,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );

        session
            .semantic_budget
            .charge(SemanticWork {
                nested_entries: rows - 1,
                procedures: 1,
                ..SemanticWork::default()
            })
            .expect("the charge fits the fresh ledger");

        let semantic = session
            .remaining_query_limits()
            .expect("one drained lane does not exhaust the session")
            .semantic;
        assert_eq!(semantic.rows(SemanticBudgetDimension::NestedEntries), 1);
        assert_eq!(semantic.rows(SemanticBudgetDimension::Procedures), rows - 1);
        for dimension in CodeQuerySemanticRowLimits::ROW_DIMENSIONS {
            if matches!(
                dimension,
                SemanticBudgetDimension::NestedEntries | SemanticBudgetDimension::Procedures
            ) {
                continue;
            }
            assert_eq!(
                semantic.rows(dimension),
                rows,
                "an untouched lane keeps its whole remainder: {dimension:?}"
            );
        }
    }

    /// A zero delta allowance is representable because a continuation may
    /// revisit a paid artifact without spending that row lane. Actual new work
    /// is refused by the child ledger, as the behavior tests below pin.
    #[test]
    fn a_fully_spent_ledger_publishes_zero_delta_row_limits() {
        let (_directory, workspace) = one_file_workspace();
        let cancellation = CancellationToken::default();
        let budget = PolicyBudget::default();
        let rows = budget.query_limits().semantic.max_rows_per_dimension;
        let mut session = PolicySelectorSession::new(
            &workspace,
            "test",
            budget.query_limits(),
            64,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );

        session
            .semantic_budget
            .charge(SemanticWork {
                procedures: rows,
                blocks: rows,
                program_points: rows,
                values: rows,
                allocations: rows,
                call_sites: rows,
                memory_locations: rows,
                captures: rows,
                source_mappings: rows,
                evidence: rows,
                gaps: rows,
                events: rows,
                control_edges: rows,
                nested_entries: rows,
                ..SemanticWork::default()
            })
            .expect("the charge exactly fills every row lane");

        let semantic = session
            .remaining_query_limits()
            .expect("zero delta limits are valid for a paid-artifact revisit")
            .semantic;
        for dimension in CodeQuerySemanticRowLimits::ROW_DIMENSIONS {
            assert_eq!(semantic.rows(dimension), 0, "{dimension:?}");
        }
        assert!(semantic.max_retained_bytes > 0);
    }

    #[test]
    #[should_panic(
        expected = "a selector that performs semantic work must return its one-shot charge"
    )]
    fn semantic_query_work_without_a_charge_fails_closed() {
        let (_directory, workspace) = one_file_workspace();
        let cancellation = CancellationToken::default();
        let budget = PolicyBudget::default();
        let mut session = PolicySelectorSession::new(
            &workspace,
            "test",
            budget.query_limits(),
            64,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );

        let _ = session.charge_query_semantic_work(
            CodeQuerySemanticWork {
                procedures: 1,
                ..CodeQuerySemanticWork::default()
            },
            None,
        );
    }

    /// A session narrowed to one seed file selects only that file's sites;
    /// the same selector over the whole workspace selects every file's.
    ///
    /// This is the seam a per-seed selector unit runs through. Only the seed
    /// enumeration narrows, and the whole-workspace default is what every
    /// caller that does not narrow keeps.
    #[test]
    fn a_narrowed_selector_session_enumerates_only_its_seed_files() {
        let project = InlineTestProject::with_language(Language::Go)
            .file("a.go", "package p\n\nfunc target() {}\n")
            .file("b.go", "package p\n\nfunc target() {}\n")
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let limits = PolicyBudget::default().query_limits();
        let selector = resolved_selector(r#"(function :name "target")"#, "/analysis/subject");

        let mut whole = PolicySelectorSession::new(
            &workspace,
            "test",
            limits,
            64,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );
        let every_site = whole
            .select_with_artifact_continuation(&selector)
            .expect("the whole-workspace selector completes");
        assert_eq!(
            every_site.len(),
            2,
            "the default scope enumerates both files, not {}",
            every_site.len()
        );

        let mut files = workspace.analyzer().analyzed_files();
        files.sort();
        let seed = project.file("a.go");
        let mut narrowed = PolicySelectorSession::new(
            &workspace,
            "test",
            limits,
            64,
            &cancellation,
            CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(&seed), &files),
        );
        let one_site = narrowed
            .select_with_artifact_continuation(&selector)
            .expect("the narrowed selector completes");
        assert_eq!(
            one_site.len(),
            1,
            "the narrowed scope enumerates one file, not {}",
            one_site.len()
        );
        assert_eq!(one_site[0].file, seed);
    }

    /// A selector and the policy compiler continuation are one accounting
    /// scope. The selector pays the artifact census; immediate materialization
    /// may pay only the one repeat lookup, even though RQL released its Arc.
    #[test]
    fn selector_charge_allows_immediate_post_selection_materialization() {
        let (_directory, workspace) = one_file_workspace();
        let cancellation = CancellationToken::default();
        let default_limits = PolicyBudget::default().query_limits();
        let selector = cfg_entry_selector("subject", "/analysis/subject");

        let mut calibration = PolicySelectorSession::new(
            &workspace,
            "test",
            default_limits,
            64,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );
        let calibrated = calibration
            .select(&selector)
            .expect("calibration selector completes");
        assert_eq!(calibrated.len(), 1);
        let census = calibration.semantic_used();
        let retained_peak = calibration.live_selector_retained_peak;
        let traversal = calibration.execution_budget().work().traversal_steps;
        assert!(retained_peak > 0);
        assert!(retained_peak >= census.owned_text_bytes);

        let tight_limits =
            limits_for_one_census_and_repeats(default_limits, census, retained_peak, traversal, 1);
        let mut session = PolicySelectorSession::new(
            &workspace,
            "test",
            tight_limits,
            64,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );
        let selected = session
            .select(&selector)
            .expect("one tightly budgeted selector completes");
        assert_eq!(selected.len(), 1);
        assert_eq!(session.materialized_artifacts().count(), 0);
        let before = session.semantic_used();
        let execution_before = session.execution_budget().work();

        session
            .materialize(&selected[0].file)
            .expect("the continuation pays only repeat work");

        let after = session.semantic_used();
        for dimension in SemanticBudgetDimension::ALL {
            let expected = before.get(dimension).saturating_add(usize::from(
                dimension == SemanticBudgetDimension::NestedEntries,
            ));
            assert_eq!(after.get(dimension), expected, "{dimension:?}");
        }
        assert_eq!(
            session.execution_budget().work().materialized_files,
            execution_before.materialized_files
        );
    }

    /// Sequential RQL windows have a physical high-water limit, while the
    /// provider's exact owned-text and row work remains additive. A paid file
    /// can therefore be revisited with zero new-file and zero owned-text
    /// allowance, but the next real repeat still exhausts its exact row lane.
    #[test]
    fn overlapping_selectors_share_identity_and_retained_high_water() {
        let (_directory, workspace) = one_file_workspace();
        let cancellation = CancellationToken::default();
        let default_limits = PolicyBudget::default().query_limits();
        let first = cfg_entry_selector("subject", "/analysis/first");
        let second = cfg_entry_selector("second", "/analysis/second");
        let third = cfg_entry_selector("third", "/analysis/third");

        let mut calibration = PolicySelectorSession::new(
            &workspace,
            "test",
            default_limits,
            64,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );
        assert_eq!(
            calibration
                .select(&first)
                .expect("calibration selector completes")
                .len(),
            1
        );
        let census = calibration.semantic_used();
        let retained_peak = calibration.live_selector_retained_peak;
        let traversal = calibration.execution_budget().work().traversal_steps;
        assert!(retained_peak >= census.owned_text_bytes);

        let tight_limits =
            limits_for_one_census_and_repeats(default_limits, census, retained_peak, traversal, 1);
        assert_eq!(tight_limits.semantic.max_retained_bytes, retained_peak);
        let mut session = PolicySelectorSession::new(
            &workspace,
            "test",
            tight_limits,
            64,
            &cancellation,
            CodeQueryExecutionScope::whole_workspace(),
        );
        assert_eq!(
            session
                .select(&first)
                .expect("the first selector pays one census")
                .len(),
            1
        );
        assert_eq!(session.execution_budget().work().materialized_files, 1);

        let owned_remaining = session.semantic_remaining().owned_text_bytes;
        session
            .semantic_budget
            .charge(SemanticWork {
                owned_text_bytes: owned_remaining,
                ..SemanticWork::default()
            })
            .expect("the test fills only the additive provider-owned lane");
        assert_eq!(session.semantic_remaining().owned_text_bytes, 0);
        assert_eq!(
            session
                .remaining_query_limits()
                .expect("zero provider-owned delta still permits a paid revisit")
                .semantic
                .max_retained_bytes,
            tight_limits.semantic.max_retained_bytes
        );
        let before_second = session.semantic_used();

        assert_eq!(
            session
                .select(&second)
                .expect("the overlapping selector pays one repeat")
                .len(),
            1
        );
        let after_second = session.semantic_used();
        for dimension in SemanticBudgetDimension::ALL {
            let expected = before_second.get(dimension).saturating_add(usize::from(
                dimension == SemanticBudgetDimension::NestedEntries,
            ));
            assert_eq!(after_second.get(dimension), expected, "{dimension:?}");
        }
        assert_eq!(session.execution_budget().work().materialized_files, 1);
        assert_eq!(session.live_selector_retained_peak, retained_peak);
        let work_report = session.work_report("test");
        let reported_retained_peak = work_report
            .metrics()
            .iter()
            .find(|metric| metric.name() == "test.semantic_peak_retained_bytes")
            .expect("retained peak metric");
        assert_eq!(
            reported_retained_peak.value(),
            u64::try_from(retained_peak).expect("fixture retained peak fits u64")
        );

        let error = match session.select(&third) {
            Ok(_) => panic!("the next actual repeat must exceed the exact additive lane"),
            Err(error) => error,
        };
        assert!(
            matches!(
                error,
                PolicySelectorSessionError::Incomplete {
                    completion: CodeQueryCompletion::Incomplete { ref codes },
                    ..
                } if codes.contains(&CodeQueryDiagnosticCode::SemanticBudgetExhausted)
            ),
            "{error:?}"
        );
    }
}
