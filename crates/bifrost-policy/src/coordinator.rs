//! One-shot, collect-and-continue policy batch coordination.
//!
//! This module owns the boundary between capability-confined policy loading,
//! analyzer-backed evaluation, canonical report assembly, and CLI status
//! selection. Renderers consume only the returned [`PolicyReportDocument`].

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::IAnalyzer;
use brokk_bifrost_analysis::analyzer::packs_document::{
    WORKSPACE_PACKS_DOCUMENT_PATH, WorkspaceActivationError, WorkspaceActivationSources,
    WorkspacePacksActivation, WorkspacePacksConfig, activate_workspace_semantic_sources,
    load_workspace_packs_config, load_workspace_packs_config_at,
};
use brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest;
use brokk_bifrost_analysis::analyzer::semantic::{
    WorkspaceRelativePath, authored_procedure_target_identity,
};
use brokk_bifrost_analysis::analyzer::semantic_model::{
    ActiveSemanticModelShard, ActiveSemanticModelSnapshot, CatalogPackSourceKind,
    ResolvedActiveSemanticModels, SemanticModelActivationExplanation,
    SemanticModelActivationPersistence, SemanticModelActivationRequest,
    SemanticModelActivationStatus, SemanticModelRuntimeOutcome, SemanticPackCatalog,
    WORKSPACE_SEMANTIC_MODEL_DIRECTORY, acquire_active_semantic_models,
    workspace_semantic_models_not_active,
};
use brokk_bifrost_analysis::analyzer::store::policy_units::{
    PolicyEvaluationRow, PolicyEvaluationRowKey,
};
use brokk_bifrost_analysis::analyzer::usages::effects::ModeledProcedureKey;
use brokk_bifrost_analysis::analyzer::usages::effects::modeled_procedure_key_for_unit;
use brokk_bifrost_analysis::analyzer::{
    AnalyzerConfig, AnalyzerQueryScope, ChangedFacts, CodeUnit, DependencyPackEcosystem,
    FilesystemProject, GoDependencyDiscoveryMode, Project, WorkspaceAnalyzer,
};
use brokk_bifrost_analysis::diff_analysis::{
    RevisionExport, RevisionWorkspace, export_revision, resolve_revision_subtree,
};
use brokk_bifrost_analysis::schema_version::SchemaVersionOrigin;
use brokk_bifrost_analysis::workspace_document::WorkspaceRoot;

use super::baseline::{
    PolicyBaselineDocument, PolicyBaselineEntryReview, PolicyBaselineMatchState,
    PolicyBaselineOptions, PolicyBaselineReview, PolicyFindingBaseline,
    load_policy_baseline_from_root,
};
use super::catalog::{CatalogRegistryLimits, TaintCatalogRegistry};
use super::definition::{
    FindingSeverity, PolicyCategoryId, PolicyId, RqlpDocument, UnknownVerdict,
};
use super::evaluator::{DefaultPolicyEvaluator, PolicyEvaluationContext, PolicyEvaluator};
use super::finding::{FindingDiffDisposition, PolicyFindingDiff};
use super::finding::{
    PolicyDiagnostic, PolicyDiagnosticCode, PolicyDiagnosticImpact, PolicyDiagnosticSeverity,
    PolicyFailureReason, PolicyFinding, PolicyIncompleteReason, PolicyRun, PolicyRunCompletion,
    PolicyWorkMetric, PolicyWorkReport, PolicyWorkUnit,
};
use super::finding_identity::{FindingIdentityStability, PolicyFindingId};
use super::loading::{PolicyDocumentLoadError, read_rqlp_document};
use super::registry::{PolicyRegistry, PolicyRegistryError, PolicyRegistryLimits};
use super::report::{
    MAX_DIFF_FIXED_FINDINGS, PolicyDependencyPackActivationMode, PolicyDiffFixedFinding,
    PolicyDiffReview, PolicyExecutionMetadata, PolicyExecutionStage, PolicyExecutionTermination,
    PolicyOptionalReviews, PolicyPackActivationReview, PolicyPackDecision,
    PolicyPackDecisionStatus, PolicyPackProcedureSummaryEvidence, PolicyReportBuilder,
    PolicyReportBuilderError, PolicyReportDiagnostic, PolicyReportDiagnosticCode,
    PolicyReportDocument, PolicyRetentionOutcome, PolicyRuleDescriptor, PolicySourceRange,
    PolicyStageTiming,
};
use super::resolved::{
    EndpointDefinitionSchemaResolution, EndpointOrigin, LoadedPolicy, ResolvedEndpointIdentity,
    SelectorOrigin,
};
use super::retained::{RetainedSize, retained_extra};
use super::scope::{
    PolicyScopeDocument, PolicyScopeDocumentState, PolicyScopeOptions, PolicyScopeReview,
    PolicyScopeSource, load_policy_scope_from_root,
};
use super::source::{
    PolicySourceDiagnostic, PolicySourceIdentity, PolicySourceIdentityError,
    PolicySourceRelatedDiagnostic, parse_rqlp_source, validate_policy_source_identity,
};
use super::suppression::{
    MAX_SUPPRESSION_REKEY_CANDIDATES, PolicyEvaluationDate, PolicyReportEvaluationContext,
    PolicySuppressionDocument, PolicySuppressionDocumentState, PolicySuppressionMatchState,
    PolicySuppressionOptions, PolicySuppressionOrphanState, PolicySuppressionPolicyHashState,
    PolicySuppressionPreflight, PolicySuppressionRecord, PolicySuppressionReview,
    PolicySuppressionSourceState, PolicySuppressionTemporalState,
    load_policy_suppressions_from_root,
};
use super::units::{
    InMemoryPolicyUnitStore, IncrementalBaseState, PersistedPolicyUnitStore,
    PolicyIncrementalContext, PolicyIncrementalReview, PolicyUnitStore, WidenReason,
    WorkspaceUnitInputs, row_key,
};

use super::taint_policy::ProductionTaintPolicyEvaluator;
use super::typestate_policy::ProductionTypestatePolicyEvaluator;
use super::{PolicyBatchBudget, PolicyBudget};

pub const POLICY_EXIT_CLEAN: u8 = 0;
pub const POLICY_EXIT_FINDING: u8 = 1;
pub const POLICY_EXIT_UNRELIABLE: u8 = 2;

/// Finding threshold used only after every requested policy ran completely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyFailOn {
    Never,
    Finding,
    Note,
    Warning,
    Error,
}

impl PolicyFailOn {
    fn matches(self, severity: FindingSeverity) -> bool {
        match self {
            Self::Never => false,
            Self::Finding => true,
            Self::Note => matches!(
                severity,
                FindingSeverity::Note | FindingSeverity::Warning | FindingSeverity::Error
            ),
            Self::Warning => {
                matches!(severity, FindingSeverity::Warning | FindingSeverity::Error)
            }
            Self::Error => severity == FindingSeverity::Error,
        }
    }
}

/// Complete deterministic host contract for one policy-evaluation batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEvaluationOptions {
    evaluation_date: PolicyEvaluationDate,
    suppressions: PolicySuppressionOptions,
    scope: PolicyScopeOptions,
    baseline: PolicyBaselineOptions,
    require_explicit_schema_versions: bool,
    fail_on: PolicyFailOn,
    diff_base: Option<String>,
    /// Whether this batch may reuse persisted per-unit evaluation results.
    ///
    /// The coordinator does not read this yet: Milestone 2 of
    /// `.agents/plans/impact-sliced-diff-base.md` wires it to the sliced
    /// evaluation path. `false` forces the full dual-snapshot evaluation, which
    /// is what every run does today, so the two settings are the same run until
    /// that milestone lands. It exists now so the equivalence harness can pin
    /// the contract the sliced path must meet before the sliced path exists.
    incremental: bool,
    /// Record each policy's evaluation wall time as the
    /// [`EVALUATION_ELAPSED_METRIC`] work metric of its run. Off by default:
    /// a timing changes from run to run, and the canonical report is
    /// byte-identical across successful runs unless the caller asks for
    /// timings (`run_policy` asks with `include_stage_timings`).
    policy_timings: bool,
}

/// Work metric a run carries when [`PolicyEvaluationOptions::policy_timings`]
/// is on: the policy's own evaluation wall time in milliseconds. The batch's
/// `policy_evaluation` stage timing is the sum over policies; this is the
/// per-policy split of it.
pub const EVALUATION_ELAPSED_METRIC: &str = "evaluation.elapsed_ms";

impl PolicyEvaluationOptions {
    pub fn new(evaluation_date: PolicyEvaluationDate) -> Self {
        Self {
            evaluation_date,
            suppressions: PolicySuppressionOptions::default(),
            scope: PolicyScopeOptions::default(),
            baseline: PolicyBaselineOptions::default(),
            require_explicit_schema_versions: false,
            fail_on: PolicyFailOn::Never,
            diff_base: None,
            incremental: true,
            policy_timings: false,
        }
    }

    pub const fn with_suppressions(
        evaluation_date: PolicyEvaluationDate,
        suppressions: PolicySuppressionOptions,
    ) -> Self {
        Self {
            evaluation_date,
            suppressions,
            scope: PolicyScopeOptions::new(PolicyScopeSource::Conventional),
            baseline: PolicyBaselineOptions::new(
                super::baseline::PolicyBaselineSource::Conventional,
            ),
            require_explicit_schema_versions: false,
            fail_on: PolicyFailOn::Never,
            diff_base: None,
            incremental: true,
            policy_timings: false,
        }
    }

    pub fn with_scope(mut self, scope: PolicyScopeOptions) -> Self {
        self.scope = scope;
        self
    }

    pub fn with_baseline(mut self, baseline: PolicyBaselineOptions) -> Self {
        self.baseline = baseline;
        self
    }

    /// Evaluate the same policies against `revision` too, classify every head
    /// finding as new or persisting, and gate only on the new ones.
    ///
    /// `revision` is any spelling `git rev-parse` accepts; it must peel to a
    /// commit in the repository that contains the workspace root.
    pub fn with_diff_base(mut self, revision: String) -> Self {
        self.diff_base = Some(revision);
        self
    }

    pub const fn with_required_schema_versions(mut self, required: bool) -> Self {
        self.require_explicit_schema_versions = required;
        self
    }

    pub const fn with_fail_on(mut self, fail_on: PolicyFailOn) -> Self {
        self.fail_on = fail_on;
        self
    }

    /// Allow or forbid reuse of persisted per-unit evaluation results.
    ///
    /// See the field: nothing reads it before Milestone 2, and `false` is the
    /// forced full dual-snapshot evaluation the equivalence harness compares
    /// against.
    pub const fn with_incremental(mut self, incremental: bool) -> Self {
        self.incremental = incremental;
        self
    }

    /// Record each policy's evaluation wall time in its run; see the field.
    pub const fn with_policy_timings(mut self, policy_timings: bool) -> Self {
        self.policy_timings = policy_timings;
        self
    }

    pub const fn policy_timings(&self) -> bool {
        self.policy_timings
    }

    pub const fn evaluation_date(&self) -> PolicyEvaluationDate {
        self.evaluation_date
    }

    pub const fn suppressions(&self) -> &PolicySuppressionOptions {
        &self.suppressions
    }

    pub const fn scope(&self) -> &PolicyScopeOptions {
        &self.scope
    }

    pub const fn baseline(&self) -> &PolicyBaselineOptions {
        &self.baseline
    }

    pub const fn require_explicit_schema_versions(&self) -> bool {
        self.require_explicit_schema_versions
    }

    pub const fn fail_on(&self) -> PolicyFailOn {
        self.fail_on
    }

    pub fn diff_base(&self) -> Option<&str> {
        self.diff_base.as_deref()
    }

    pub const fn incremental(&self) -> bool {
        self.incremental
    }
}

impl RetainedSize for PolicyEvaluationOptions {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(retained_extra(&self.suppressions))
            .saturating_add(retained_extra(&self.scope))
            .saturating_add(retained_extra(&self.baseline))
            .saturating_add(retained_extra(&self.diff_base))
    }
}

/// Complete canonical report plus the already precedence-resolved CLI status.
pub struct PolicyBatchOutcome {
    report: PolicyReportDocument,
    /// Out-of-band wall-clock stage attribution for this run.
    ///
    /// The canonical report stays byte-identical across successful
    /// invocations, so successful runs never carry timings inside the
    /// document (#2611). This side channel always holds the measured stage
    /// timings; a consumer that wants attribution reads it explicitly and a
    /// consumer that hashes, diffs, or baselines the report never sees it.
    stage_attribution: Vec<PolicyStageTiming>,
    taint_findings: Vec<brokk_bifrost_rql::structural::CodeQueryTaintFinding>,
    taint_analysis_results: Vec<Arc<crate::ProductionTaintAnalysisResult>>,
    exit_status: u8,
    max_retained_report_bytes: usize,
    max_serialized_report_bytes: usize,
    /// What this batch reused instead of recomputing, when it was allowed to
    /// reuse anything.
    ///
    /// Out of band exactly as the stage timings are: the canonical report
    /// stays byte-identical whether or not a run reused a unit, so the reuse
    /// telemetry cannot live inside it. Milestone 3 of
    /// `.agents/plans/impact-sliced-diff-base.md` adds the report section.
    incremental: Option<PolicyIncrementalReview>,
}

impl PolicyBatchOutcome {
    pub const fn report(&self) -> &PolicyReportDocument {
        &self.report
    }

    /// What this batch reused, per policy, or `None` when it could not reuse
    /// anything: no diff base, or `incremental` off.
    pub const fn incremental(&self) -> Option<&PolicyIncrementalReview> {
        self.incremental.as_ref()
    }

    /// How many evaluation units this batch reused instead of recomputing.
    pub fn reused_units(&self) -> u64 {
        self.incremental
            .as_ref()
            .map_or(0, PolicyIncrementalReview::reused_units)
    }

    pub fn into_report(self) -> PolicyReportDocument {
        self.report
    }

    /// Wall-clock stage attribution measured for this run, sorted by stage.
    ///
    /// This is the explicit opt-in channel for timings: it is never part of
    /// the canonical report, which stays byte-identical across successful
    /// invocations. On a deadline outcome the report's `execution` block
    /// carries the same stages, because there elapsed time is the reason the
    /// run stopped.
    pub fn stage_attribution(&self) -> &[PolicyStageTiming] {
        &self.stage_attribution
    }

    pub fn record_preparation_timings(
        &mut self,
        selection_elapsed: Duration,
        suppression_preflight_elapsed: Duration,
        snapshot_elapsed: Duration,
    ) {
        for (stage, elapsed) in [
            (PolicyExecutionStage::PolicySelection, selection_elapsed),
            (
                PolicyExecutionStage::SuppressionPreflight,
                suppression_preflight_elapsed,
            ),
            (PolicyExecutionStage::WorkspaceSnapshot, snapshot_elapsed),
        ] {
            if self
                .stage_attribution
                .iter()
                .any(|timing| timing.stage() == stage)
            {
                continue;
            }
            self.stage_attribution
                .push(PolicyStageTiming::from_duration(stage, elapsed));
        }
        self.stage_attribution.sort_by_key(PolicyStageTiming::stage);
        let current = self.report.execution();
        if current.termination().is_none() {
            return;
        }
        let mut stage_timings = current.stage_timings().to_vec();
        let mut preparation_elapsed_ms = 0_u64;
        for (stage, elapsed) in [
            (PolicyExecutionStage::PolicySelection, selection_elapsed),
            (
                PolicyExecutionStage::SuppressionPreflight,
                suppression_preflight_elapsed,
            ),
            (PolicyExecutionStage::WorkspaceSnapshot, snapshot_elapsed),
        ] {
            if stage_timings.iter().any(|timing| timing.stage() == stage) {
                continue;
            }
            let timing = PolicyStageTiming::from_duration(stage, elapsed);
            preparation_elapsed_ms = preparation_elapsed_ms.saturating_add(timing.elapsed_ms());
            stage_timings.push(timing);
        }
        let execution = PolicyExecutionMetadata::try_new(
            current
                .total_elapsed_ms()
                .saturating_add(preparation_elapsed_ms),
            stage_timings,
            current.termination(),
            current.terminal_stage(),
            current.active_policy_id().cloned(),
            current.completed_policy_ids().to_vec(),
            current.pending_policy_ids().to_vec(),
        )
        .expect("preparation stages are unique and preserve validated policy progress");
        let retained_bytes = self
            .report
            .retained_size()
            .saturating_sub(retained_extra(current))
            .saturating_add(retained_extra(&execution));
        assert!(
            retained_bytes <= self.max_retained_report_bytes,
            "reserved execution metadata must fit the policy report budget"
        );
        self.report.replace_execution(execution);
    }

    /// Diagnostic-neutral taint query rows retained by the same propagation
    /// runs that produced the policy report.
    pub fn taint_findings(&self) -> &[brokk_bifrost_rql::structural::CodeQueryTaintFinding] {
        &self.taint_findings
    }

    /// Immutable production plan/report pairs retained from the propagation
    /// runs that produced this policy outcome.
    pub fn taint_analysis_results(&self) -> &[Arc<crate::ProductionTaintAnalysisResult>] {
        &self.taint_analysis_results
    }

    pub fn taint_query_results(
        &self,
    ) -> impl ExactSizeIterator<Item = brokk_bifrost_rql::structural::CodeQueryResultValue> + '_
    {
        self.taint_findings.iter().cloned().map(|value| {
            brokk_bifrost_rql::structural::CodeQueryResultValue::TaintFinding {
                value: Box::new(value),
            }
        })
    }

    pub const fn exit_status(&self) -> u8 {
        self.exit_status
    }

    pub const fn max_serialized_report_bytes(&self) -> usize {
        self.max_serialized_report_bytes
    }
}

#[derive(Debug)]
pub struct PolicyCoordinatorError {
    message: String,
}

impl PolicyCoordinatorError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for PolicyCoordinatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for PolicyCoordinatorError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyEvaluationInput {
    WorkspaceFile(PathBuf),
    Embedded {
        identity: PolicySourceIdentity,
        source: String,
    },
}

impl PolicyEvaluationInput {
    pub fn workspace_file(path: impl Into<PathBuf>) -> Self {
        Self::WorkspaceFile(path.into())
    }

    pub fn embedded(identity: PolicySourceIdentity, source: impl Into<String>) -> Self {
        Self::Embedded {
            identity,
            source: source.into(),
        }
    }
}

struct PreparedPolicy {
    source: PolicySourceIdentity,
    bytes: String,
    policy_id: PolicyId,
}

enum InputOutcome {
    Pending(PreparedPolicy),
    Diagnostic(PolicyReportDiagnostic),
    Runnable(PolicyId),
}

// Primary diagnostics collectively name every duplicate source. Keep only a
// tiny, deterministic local cross-reference set so even large duplicate groups
// stay within the report builder's mandatory per-input skeleton allowance.
const MAX_DUPLICATE_RELATED_DIAGNOSTICS: usize = 2;

/// Load and evaluate the requested workspace-relative policy roots.
///
/// All roots share one immutable registry and one analyzer snapshot. Invalid
/// inputs become canonical report diagnostics without suppressing valid runs.
/// Only failures that prevent mandatory report skeleton reservation return an
/// error instead of a partial report.
pub fn evaluate_policy_files(
    root: impl AsRef<Path>,
    policy_files: &[PathBuf],
    options: &PolicyEvaluationOptions,
) -> Result<PolicyBatchOutcome, PolicyCoordinatorError> {
    evaluate_policy_files_with_limits(
        root.as_ref(),
        policy_files,
        options,
        PolicyBatchBudget::default(),
        PolicyRegistryLimits::default(),
    )
}

/// Evaluate workspace policy files against a caller-owned immutable analyzer snapshot.
///
/// This is the file-backed counterpart to [`evaluate_policy_source`] for hosts
/// that already own the active workspace snapshot, such as MCP sessions.
pub fn evaluate_policy_files_with_analyzer(
    root: impl AsRef<Path>,
    policy_files: &[PathBuf],
    workspace: &WorkspaceAnalyzer,
    flow_state: &brokk_bifrost_flow::FlowWorkspaceState,
    options: &PolicyEvaluationOptions,
    cancellation: Option<&CancellationToken>,
) -> Result<PolicyBatchOutcome, PolicyCoordinatorError> {
    let batch_budget = PolicyBatchBudget::default();
    if policy_files.is_empty() {
        return Err(PolicyCoordinatorError::new(
            "policy evaluation requires at least one policy file",
        ));
    }
    if policy_files.len() > batch_budget.max_policies() {
        return Err(PolicyCoordinatorError::new(format!(
            "policy evaluation accepts at most {} policy files",
            batch_budget.max_policies()
        )));
    }

    let inputs = policy_files
        .iter()
        .cloned()
        .map(PolicyEvaluationInput::WorkspaceFile)
        .collect::<Vec<_>>();
    evaluate_policy_inputs_with_analyzer(
        root,
        &inputs,
        workspace,
        flow_state,
        options,
        cancellation,
    )
}

/// Evaluate a deterministic mixture of workspace files and caller-owned policy sources.
pub fn evaluate_policy_inputs(
    root: impl AsRef<Path>,
    policy_inputs: &[PolicyEvaluationInput],
    options: &PolicyEvaluationOptions,
) -> Result<PolicyBatchOutcome, PolicyCoordinatorError> {
    evaluate_policy_inputs_with_limits(
        root.as_ref(),
        policy_inputs,
        options,
        PolicyBatchBudget::default(),
        PolicyRegistryLimits::default(),
        None,
        None,
        None,
        None,
        None,
        None,
    )
}

/// Evaluate mixed policy inputs against a caller-owned immutable analyzer snapshot.
pub fn evaluate_policy_inputs_with_analyzer(
    root: impl AsRef<Path>,
    policy_inputs: &[PolicyEvaluationInput],
    workspace: &WorkspaceAnalyzer,
    flow_state: &brokk_bifrost_flow::FlowWorkspaceState,
    options: &PolicyEvaluationOptions,
    cancellation: Option<&CancellationToken>,
) -> Result<PolicyBatchOutcome, PolicyCoordinatorError> {
    evaluate_policy_inputs_with_limits(
        root.as_ref(),
        policy_inputs,
        options,
        PolicyBatchBudget::default(),
        PolicyRegistryLimits::default(),
        Some(workspace),
        Some(flow_state),
        None,
        None,
        None,
        cancellation,
    )
}

/// Evaluate mixed policy inputs against a caller-owned analyzer and its
/// already completed host-owned pack activation.
pub fn evaluate_policy_inputs_with_analyzer_and_host_activation(
    root: impl AsRef<Path>,
    policy_inputs: &[PolicyEvaluationInput],
    workspace: &WorkspaceAnalyzer,
    flow_state: &brokk_bifrost_flow::FlowWorkspaceState,
    options: &PolicyEvaluationOptions,
    host_activation: PolicyHostActivationContext<'_>,
    cancellation: Option<&CancellationToken>,
) -> Result<PolicyBatchOutcome, PolicyCoordinatorError> {
    evaluate_policy_inputs_with_limits(
        root.as_ref(),
        policy_inputs,
        options,
        PolicyBatchBudget::default(),
        PolicyRegistryLimits::default(),
        Some(workspace),
        Some(flow_state),
        None,
        Some(host_activation),
        None,
        cancellation,
    )
}

/// Explicit semantic-pack authority for one analyzer-backed policy batch.
#[derive(Clone, Copy)]
pub struct PolicySemanticModelContext<'a> {
    pub catalog: &'a SemanticPackCatalog,
    pub request: &'a SemanticModelActivationRequest,
    pub persistence: Option<SemanticModelActivationPersistence<'a>>,
}

/// Activation state already owned by a protocol host for one analyzer
/// snapshot. Policy evaluation borrows this context and never activates packs
/// itself when it is supplied.
#[derive(Clone, Copy, Debug)]
pub struct PolicyHostActivationContext<'a> {
    pub config: Option<&'a WorkspacePacksConfig>,
    pub activation: Option<&'a WorkspacePacksActivation>,
    pub attempted_ecosystems: &'a [DependencyPackEcosystem],
    pub failure: Option<&'a str>,
}

impl<'a> PolicyHostActivationContext<'a> {
    pub const fn new(
        config: Option<&'a WorkspacePacksConfig>,
        activation: Option<&'a WorkspacePacksActivation>,
        attempted_ecosystems: &'a [DependencyPackEcosystem],
        failure: Option<&'a str>,
    ) -> Self {
        Self {
            config,
            activation,
            attempted_ecosystems,
            failure,
        }
    }
}

/// Evaluate mixed policy inputs with one generation-cached semantic-model acquisition.
pub fn evaluate_policy_inputs_with_analyzer_and_semantic_models(
    root: impl AsRef<Path>,
    policy_inputs: &[PolicyEvaluationInput],
    workspace: &WorkspaceAnalyzer,
    flow_state: &brokk_bifrost_flow::FlowWorkspaceState,
    options: &PolicyEvaluationOptions,
    semantic_models: PolicySemanticModelContext<'_>,
    cancellation: Option<&CancellationToken>,
) -> Result<PolicyBatchOutcome, PolicyCoordinatorError> {
    evaluate_policy_inputs_with_limits(
        root.as_ref(),
        policy_inputs,
        options,
        PolicyBatchBudget::default(),
        PolicyRegistryLimits::default(),
        Some(workspace),
        Some(flow_state),
        Some(semantic_models),
        None,
        None,
        cancellation,
    )
}

/// Evaluate one live policy source against an analyzer snapshot that the caller owns.
///
/// The root source comes from `source` rather than the filesystem, while referenced
/// selectors, endpoints, endpoint directories, and catalogs remain confined beneath
/// `root` by the normal workspace-backed policy registry.
pub fn evaluate_policy_source(
    root: impl AsRef<Path>,
    source_identity: PolicySourceIdentity,
    source: &str,
    workspace: &WorkspaceAnalyzer,
    flow_state: &brokk_bifrost_flow::FlowWorkspaceState,
    options: &PolicyEvaluationOptions,
    cancellation: Option<&CancellationToken>,
) -> Result<PolicyBatchOutcome, PolicyCoordinatorError> {
    evaluate_policy_inputs_with_analyzer(
        root,
        &[PolicyEvaluationInput::embedded(source_identity, source)],
        workspace,
        flow_state,
        options,
        cancellation,
    )
}

/// Evaluate one live policy source against a caller-owned analyzer and its
/// already completed host-owned pack activation.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_policy_source_with_host_activation(
    root: impl AsRef<Path>,
    source_identity: PolicySourceIdentity,
    source: &str,
    workspace: &WorkspaceAnalyzer,
    flow_state: &brokk_bifrost_flow::FlowWorkspaceState,
    options: &PolicyEvaluationOptions,
    host_activation: PolicyHostActivationContext<'_>,
    cancellation: Option<&CancellationToken>,
) -> Result<PolicyBatchOutcome, PolicyCoordinatorError> {
    evaluate_policy_inputs_with_analyzer_and_host_activation(
        root,
        &[PolicyEvaluationInput::embedded(source_identity, source)],
        workspace,
        flow_state,
        options,
        host_activation,
        cancellation,
    )
}

/// Load configured suppressions without constructing or consulting an analyzer.
///
/// MCP uses this boundary before workspace readiness so a malformed gate input
/// can return a bounded canonical report immediately. Callers that continue to
/// evaluation should move the returned preflight into the analyzer-backed
/// evaluation entry point rather than reading the sources again.
pub fn preflight_policy_suppressions(
    root: impl AsRef<Path>,
    options: &PolicyEvaluationOptions,
) -> Result<PolicySuppressionPreflight, PolicyCoordinatorError> {
    super::suppression::load_policy_suppressions(root.as_ref(), options.suppressions())
        .map(PolicySuppressionPreflight::new)
        .map_err(|error| {
            PolicyCoordinatorError::new(format!(
                "failed to open policy suppression sources: {error}"
            ))
        })
}

/// Construct the compact canonical unreliable result for a failed suppression
/// preflight. No policy has been registered or evaluated, so the report keeps
/// its rule/run/progress collections empty and records only stages that ran.
pub fn suppression_preflight_failure_outcome(
    options: &PolicyEvaluationOptions,
    preflight: PolicySuppressionPreflight,
    selection_elapsed: Duration,
    suppression_preflight_elapsed: Duration,
) -> Result<PolicyBatchOutcome, PolicyCoordinatorError> {
    let outcome = preflight.outcome();
    let failure = outcome.failures.first().ok_or_else(|| {
        PolicyCoordinatorError::new("suppression preflight failure has no diagnostic")
    })?;
    let diagnostic = report_diagnostic(
        PolicyReportDiagnosticCode::SuppressionLoadFailed,
        format!(
            "failed to load policy suppressions from `{}`: {}",
            failure.path, failure.error
        ),
        Some(PolicySourceIdentity::new(&failure.path)),
        None,
        Vec::new(),
    )?;
    let stage_timings = vec![
        PolicyStageTiming::from_duration(PolicyExecutionStage::PolicySelection, selection_elapsed),
        PolicyStageTiming::from_duration(
            PolicyExecutionStage::SuppressionPreflight,
            suppression_preflight_elapsed,
        ),
    ];
    let total_elapsed_ms = stage_timings.iter().fold(0_u64, |total, timing| {
        total.saturating_add(timing.elapsed_ms())
    });
    let execution = PolicyExecutionMetadata::try_new(
        total_elapsed_ms,
        stage_timings,
        None,
        None,
        None,
        Vec::new(),
        Vec::new(),
    )
    .map_err(|error| {
        PolicyCoordinatorError::new(format!(
            "failed to construct suppression preflight metadata: {error}"
        ))
    })?;
    let evaluation = PolicyReportEvaluationContext::new(
        options.evaluation_date(),
        outcome.sources.clone(),
        options.scope(),
        PolicyScopeDocumentState::NotEvaluated,
    );
    let report_started = Instant::now();
    let mut report = PolicyReportDocument::try_new_with_execution(
        evaluation,
        execution,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        PolicyOptionalReviews::default(),
        vec![diagnostic],
        false,
        0,
        None,
    )
    .map_err(|error| {
        PolicyCoordinatorError::new(format!(
            "failed to construct suppression preflight report: {error}"
        ))
    })?;
    let report_timing = PolicyStageTiming::from_duration(
        PolicyExecutionStage::ReportConstruction,
        report_started.elapsed(),
    );
    let complete_stage_timings = vec![
        PolicyStageTiming::from_duration(PolicyExecutionStage::PolicySelection, selection_elapsed),
        PolicyStageTiming::from_duration(
            PolicyExecutionStage::SuppressionPreflight,
            suppression_preflight_elapsed,
        ),
        report_timing,
    ];
    let complete_total_elapsed_ms = complete_stage_timings.iter().fold(0_u64, |total, timing| {
        total.saturating_add(timing.elapsed_ms())
    });
    let complete_execution = PolicyExecutionMetadata::try_new(
        complete_total_elapsed_ms,
        complete_stage_timings.clone(),
        None,
        None,
        None,
        Vec::new(),
        Vec::new(),
    )
    .map_err(|error| {
        PolicyCoordinatorError::new(format!(
            "failed to finalize suppression preflight metadata: {error}"
        ))
    })?;
    report.replace_execution(complete_execution);
    let batch_budget = PolicyBatchBudget::default();
    assert!(
        report.retained_size() <= batch_budget.max_retained_report_bytes(),
        "suppression preflight report must fit the policy report budget"
    );
    Ok(PolicyBatchOutcome {
        report,
        stage_attribution: complete_stage_timings,
        taint_findings: Vec::new(),
        taint_analysis_results: Vec::new(),
        exit_status: POLICY_EXIT_UNRELIABLE,
        max_retained_report_bytes: batch_budget.max_retained_report_bytes(),
        max_serialized_report_bytes: batch_budget.max_serialized_report_bytes(),
        incremental: None,
    })
}

pub fn workspace_snapshot_deadline_outcome(
    options: &PolicyEvaluationOptions,
    selected_policy_ids: Vec<PolicyId>,
    selection_elapsed: Duration,
    snapshot_elapsed: Duration,
) -> Result<PolicyBatchOutcome, PolicyCoordinatorError> {
    let diagnostic = report_diagnostic(
        PolicyReportDiagnosticCode::WorkspaceSnapshotDeadlineExceeded,
        "workspace snapshot was not ready within the request-wide time budget; retry after workspace initialization completes",
        None,
        None,
        Vec::new(),
    )?;
    deadline_before_evaluation_outcome(
        options,
        PolicyBatchBudget::default(),
        options
            .suppressions()
            .source_states(PolicySuppressionDocumentState::NotEvaluated),
        PolicyScopeDocumentState::NotEvaluated,
        vec![
            PolicyStageTiming::from_duration(
                PolicyExecutionStage::PolicySelection,
                selection_elapsed,
            ),
            PolicyStageTiming::from_duration(
                PolicyExecutionStage::WorkspaceSnapshot,
                snapshot_elapsed,
            ),
        ],
        PolicyExecutionStage::WorkspaceSnapshot,
        selected_policy_ids,
        Some(diagnostic),
    )
}

/// Snapshot deadline outcome when suppression configuration completed before
/// the wait. The report preserves that source evidence and timing while still
/// omitting analyzer execution stages.
pub fn workspace_snapshot_deadline_outcome_with_preflight(
    options: &PolicyEvaluationOptions,
    selected_policy_ids: Vec<PolicyId>,
    selection_elapsed: Duration,
    suppression_preflight: &PolicySuppressionPreflight,
    suppression_preflight_elapsed: Duration,
    snapshot_elapsed: Duration,
) -> Result<PolicyBatchOutcome, PolicyCoordinatorError> {
    let diagnostic = report_diagnostic(
        PolicyReportDiagnosticCode::WorkspaceSnapshotDeadlineExceeded,
        "workspace snapshot was not ready within the request-wide time budget; retry after workspace initialization completes",
        None,
        None,
        Vec::new(),
    )?;
    deadline_before_evaluation_outcome(
        options,
        PolicyBatchBudget::default(),
        suppression_preflight.outcome().sources.clone(),
        PolicyScopeDocumentState::NotEvaluated,
        vec![
            PolicyStageTiming::from_duration(
                PolicyExecutionStage::PolicySelection,
                selection_elapsed,
            ),
            PolicyStageTiming::from_duration(
                PolicyExecutionStage::SuppressionPreflight,
                suppression_preflight_elapsed,
            ),
            PolicyStageTiming::from_duration(
                PolicyExecutionStage::WorkspaceSnapshot,
                snapshot_elapsed,
            ),
        ],
        PolicyExecutionStage::WorkspaceSnapshot,
        selected_policy_ids,
        Some(diagnostic),
    )
}

#[allow(clippy::too_many_arguments)]
fn deadline_before_evaluation_outcome(
    options: &PolicyEvaluationOptions,
    batch_budget: PolicyBatchBudget,
    suppression_sources: Vec<PolicySuppressionSourceState>,
    scope_document_state: PolicyScopeDocumentState,
    stage_timings: Vec<PolicyStageTiming>,
    terminal_stage: PolicyExecutionStage,
    pending_policy_ids: Vec<PolicyId>,
    diagnostic: Option<PolicyReportDiagnostic>,
) -> Result<PolicyBatchOutcome, PolicyCoordinatorError> {
    let evaluation = PolicyReportEvaluationContext::new(
        options.evaluation_date(),
        suppression_sources,
        options.scope(),
        scope_document_state,
    );
    let diagnostics = diagnostic.into_iter().collect();
    let total_elapsed_ms = stage_timings.iter().fold(0_u64, |total, timing| {
        total.saturating_add(timing.elapsed_ms())
    });
    let mut stage_attribution = stage_timings.clone();
    stage_attribution.sort_by_key(PolicyStageTiming::stage);
    let execution = PolicyExecutionMetadata::try_new(
        total_elapsed_ms,
        stage_timings,
        Some(PolicyExecutionTermination::DeadlineExceeded),
        Some(terminal_stage),
        None,
        Vec::new(),
        pending_policy_ids,
    )
    .map_err(|error| {
        PolicyCoordinatorError::new(format!(
            "failed to construct deadline policy execution metadata: {error}"
        ))
    })?;
    let report = PolicyReportDocument::try_new_with_execution(
        evaluation,
        execution,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        PolicyOptionalReviews::default(),
        diagnostics,
        false,
        0,
        None,
    )
    .map_err(|error| {
        PolicyCoordinatorError::new(format!("failed to finish deadline policy report: {error}"))
    })?;
    assert!(
        report.retained_size() <= batch_budget.max_retained_report_bytes(),
        "bounded deadline metadata must fit the policy report budget"
    );
    Ok(PolicyBatchOutcome {
        report,
        stage_attribution,
        taint_findings: Vec::new(),
        taint_analysis_results: Vec::new(),
        exit_status: POLICY_EXIT_UNRELIABLE,
        max_retained_report_bytes: batch_budget.max_retained_report_bytes(),
        max_serialized_report_bytes: batch_budget.max_serialized_report_bytes(),
        incremental: None,
    })
}

/// [`evaluate_policy_files`] under a caller-chosen batch budget.
///
/// The budget is what decides which lanes a run reaches, so a caller that
/// needs a run to reach one -- an equivalence harness proving a sliced run
/// truncates where a whole run truncates -- states the allowance rather than
/// growing the workspace until the default allowance runs out.
pub fn evaluate_policy_files_with_limits(
    root: &Path,
    policy_files: &[PathBuf],
    options: &PolicyEvaluationOptions,
    batch_budget: PolicyBatchBudget,
    registry_limits: PolicyRegistryLimits,
) -> Result<PolicyBatchOutcome, PolicyCoordinatorError> {
    if policy_files.is_empty() {
        return Err(PolicyCoordinatorError::new(
            "policy evaluation requires at least one --policy-file",
        ));
    }
    if policy_files.len() > batch_budget.max_policies() {
        return Err(PolicyCoordinatorError::new(format!(
            "policy evaluation accepts at most {} policy files",
            batch_budget.max_policies()
        )));
    }

    let (root, read_root) = open_policy_workspace_root(root)?;

    let mut inputs = Vec::with_capacity(policy_files.len());
    for path in policy_files {
        inputs.push(prepare_input(&read_root, path)?);
    }
    exclude_duplicate_policy_ids(&mut inputs)?;

    evaluate_prepared_policy_inputs(
        &root,
        &read_root,
        inputs,
        options,
        batch_budget,
        registry_limits,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn evaluate_policy_inputs_with_limits(
    root: &Path,
    policy_inputs: &[PolicyEvaluationInput],
    options: &PolicyEvaluationOptions,
    batch_budget: PolicyBatchBudget,
    registry_limits: PolicyRegistryLimits,
    supplied_workspace: Option<&WorkspaceAnalyzer>,
    supplied_flow_state: Option<&brokk_bifrost_flow::FlowWorkspaceState>,
    semantic_models: Option<PolicySemanticModelContext<'_>>,
    host_activation: Option<PolicyHostActivationContext<'_>>,
    supplied_incremental: Option<&PolicyIncrementalContext<'_>>,
    cancellation: Option<&CancellationToken>,
) -> Result<PolicyBatchOutcome, PolicyCoordinatorError> {
    if policy_inputs.is_empty() {
        return Err(PolicyCoordinatorError::new(
            "policy evaluation requires at least one policy input",
        ));
    }
    if policy_inputs.len() > batch_budget.max_policies() {
        return Err(PolicyCoordinatorError::new(format!(
            "policy evaluation accepts at most {} policy inputs",
            batch_budget.max_policies()
        )));
    }

    let (root, read_root) = open_policy_workspace_root(root)?;
    let mut inputs = Vec::with_capacity(policy_inputs.len());
    for input in policy_inputs {
        check_policy_cancellation(cancellation)?;
        inputs.push(match input {
            PolicyEvaluationInput::WorkspaceFile(path) => prepare_input(&read_root, path)?,
            PolicyEvaluationInput::Embedded { identity, source } => {
                prepare_source_input(identity.clone(), source)?
            }
        });
    }
    exclude_duplicate_policy_ids(&mut inputs)?;
    evaluate_prepared_policy_inputs(
        &root,
        &read_root,
        inputs,
        options,
        batch_budget,
        registry_limits,
        supplied_workspace,
        supplied_flow_state,
        semantic_models,
        host_activation,
        None,
        supplied_incremental,
        cancellation,
    )
}

/// Evaluate mixed policy inputs against a caller-owned snapshot and a
/// previously completed analyzer-free suppression preflight.
pub fn evaluate_policy_inputs_with_analyzer_and_suppression_preflight(
    root: impl AsRef<Path>,
    policy_inputs: &[PolicyEvaluationInput],
    workspace: &WorkspaceAnalyzer,
    flow_state: &brokk_bifrost_flow::FlowWorkspaceState,
    options: &PolicyEvaluationOptions,
    suppression_preflight: PolicySuppressionPreflight,
    cancellation: Option<&CancellationToken>,
) -> Result<PolicyBatchOutcome, PolicyCoordinatorError> {
    evaluate_policy_inputs_with_analyzer_and_suppression_preflight_impl(
        root,
        policy_inputs,
        workspace,
        flow_state,
        options,
        suppression_preflight,
        None,
        cancellation,
    )
}

/// Evaluate mixed policy inputs with suppression preflight and a host-owned
/// activation already completed for the supplied analyzer snapshot.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_policy_inputs_with_analyzer_and_suppression_preflight_and_host_activation(
    root: impl AsRef<Path>,
    policy_inputs: &[PolicyEvaluationInput],
    workspace: &WorkspaceAnalyzer,
    flow_state: &brokk_bifrost_flow::FlowWorkspaceState,
    options: &PolicyEvaluationOptions,
    suppression_preflight: PolicySuppressionPreflight,
    host_activation: PolicyHostActivationContext<'_>,
    cancellation: Option<&CancellationToken>,
) -> Result<PolicyBatchOutcome, PolicyCoordinatorError> {
    evaluate_policy_inputs_with_analyzer_and_suppression_preflight_impl(
        root,
        policy_inputs,
        workspace,
        flow_state,
        options,
        suppression_preflight,
        Some(host_activation),
        cancellation,
    )
}

#[allow(clippy::too_many_arguments)]
fn evaluate_policy_inputs_with_analyzer_and_suppression_preflight_impl(
    root: impl AsRef<Path>,
    policy_inputs: &[PolicyEvaluationInput],
    workspace: &WorkspaceAnalyzer,
    flow_state: &brokk_bifrost_flow::FlowWorkspaceState,
    options: &PolicyEvaluationOptions,
    suppression_preflight: PolicySuppressionPreflight,
    host_activation: Option<PolicyHostActivationContext<'_>>,
    cancellation: Option<&CancellationToken>,
) -> Result<PolicyBatchOutcome, PolicyCoordinatorError> {
    if policy_inputs.is_empty() {
        return Err(PolicyCoordinatorError::new(
            "policy evaluation requires at least one policy input",
        ));
    }
    let batch_budget = PolicyBatchBudget::default();
    if policy_inputs.len() > batch_budget.max_policies() {
        return Err(PolicyCoordinatorError::new(format!(
            "policy evaluation accepts at most {} policy inputs",
            batch_budget.max_policies()
        )));
    }
    let (root, read_root) = open_policy_workspace_root(root.as_ref())?;
    let mut inputs = Vec::with_capacity(policy_inputs.len());
    for input in policy_inputs {
        check_policy_cancellation(cancellation)?;
        inputs.push(match input {
            PolicyEvaluationInput::WorkspaceFile(path) => prepare_input(&read_root, path)?,
            PolicyEvaluationInput::Embedded { identity, source } => {
                prepare_source_input(identity.clone(), source)?
            }
        });
    }
    exclude_duplicate_policy_ids(&mut inputs)?;
    evaluate_prepared_policy_inputs(
        &root,
        &read_root,
        inputs,
        options,
        batch_budget,
        PolicyRegistryLimits::default(),
        Some(workspace),
        Some(flow_state),
        None,
        host_activation,
        Some(suppression_preflight),
        None,
        cancellation,
    )
}

/// Total on-disk size and count of the analyzed files in one workspace snapshot.
///
/// A file the analyzer knows about but whose metadata is no longer readable
/// contributes zero bytes; its scan will charge nothing either.
fn analyzed_source_volume(workspace: &WorkspaceAnalyzer) -> (u64, usize) {
    let files = workspace.analyzer().analyzed_files();
    let bytes = files
        .iter()
        .map(|file| {
            std::fs::metadata(file.abs_path())
                .map(|metadata| metadata.len())
                .unwrap_or(0)
        })
        .sum();
    (bytes, files.len())
}

/// Activate every semantic source an owned policy workspace uses.
///
/// Ordinary evaluation and explanation both build short-lived workspace
/// analyzers. Keep their activation authority in one place so shipped models,
/// reviewed workspace models, and dependency packs cannot diverge between the
/// report and the explanation of that report.
pub(crate) fn owned_policy_analyzer_config() -> AnalyzerConfig {
    let mut config = AnalyzerConfig::default();
    config.go.dependency_discovery.mode = GoDependencyDiscoveryMode::CuratedPackEvidence;
    config
}

pub(crate) fn activate_owned_policy_workspace(
    root: &Path,
    workspace: &WorkspaceAnalyzer,
    config: Option<&WorkspacePacksConfig>,
    cancellation: &CancellationToken,
) -> Result<Option<WorkspacePacksActivation>, WorkspaceActivationError> {
    activate_workspace_semantic_sources(
        workspace,
        &owned_policy_analyzer_config(),
        WorkspaceActivationSources {
            catalog_root: root,
            workspace_model_root: Some(root),
            config,
            intrinsic_shipped_models: true,
        },
        cancellation,
    )
}

/// Scale one policy's host budget to the analyzer snapshot it will scan.
pub(crate) fn policy_budget_for_workspace(
    budget: PolicyBudget,
    workspace: Option<&WorkspaceAnalyzer>,
) -> PolicyBudget {
    match workspace {
        Some(workspace) => {
            let (bytes, files) = analyzed_source_volume(workspace);
            budget.scaled_for_workspace(bytes, files)
        }
        None => budget,
    }
}

/// Freeze the exact ready semantic-model publication produced by activation.
pub(crate) fn ready_policy_semantic_model_snapshot(
    activation: Option<&WorkspacePacksActivation>,
) -> Option<Arc<ActiveSemanticModelSnapshot>> {
    activation
        .and_then(|activation| activation.outcome.runtime.as_ref())
        .and_then(|runtime| match runtime {
            SemanticModelRuntimeOutcome::Ready { snapshot, .. } => Some(Arc::clone(snapshot)),
            SemanticModelRuntimeOutcome::Incomplete { .. }
            | SemanticModelRuntimeOutcome::Cancelled(_)
            | SemanticModelRuntimeOutcome::Unavailable(_) => None,
        })
}

/// The workspace location to which a pack-activation review is attributed.
///
/// A dependency activation attempt, including a host-owned absent-document
/// default, belongs to the conventional packs path. Otherwise, reviewed
/// workspace-local models belong to their directory. Intrinsic shipped models
/// are runtime inputs, not evidence that either workspace path exists, so they
/// do not add a top-level review by themselves (#1868, #2493).
fn pack_activation_source_path(
    config: Option<&WorkspacePacksConfig>,
    activation: Option<&WorkspacePacksActivation>,
    attempted_ecosystems: Option<&[DependencyPackEcosystem]>,
    activation_failure: Option<&str>,
) -> Option<&'static str> {
    if config.is_some()
        || attempted_ecosystems.is_some()
        || activation_failure.is_some()
        || activation.is_some_and(|activation| !activation.ecosystems.is_empty())
    {
        Some(WORKSPACE_PACKS_DOCUMENT_PATH)
    } else if activation.is_some_and(|activation| !activation.workspace_models.is_empty()) {
        Some(WORKSPACE_SEMANTIC_MODEL_DIRECTORY)
    } else {
        None
    }
}

/// Find declarations whose terminal names are named by active procedure
/// summaries. Tree-sitter analyzers expose an indexed identifier lookup, but
/// that lookup also includes definition-lookup-only units for resolver use, so
/// filter candidates back to the authoritative per-file declaration set.
/// An analyzer without the complete index keeps the full-declaration fallback.
fn procedure_summary_candidate_declarations(
    analyzer: &dyn IAnalyzer,
    target_member_identifiers: &HashSet<String>,
) -> BTreeSet<CodeUnit> {
    let indexed_lookup = analyzer.has_complete_symbol_lookup_index();
    let candidate_units = if indexed_lookup {
        target_member_identifiers
            .iter()
            .flat_map(|member| analyzer.lookup_candidates_by_identifier(member))
            .collect::<BTreeSet<_>>()
    } else {
        analyzer.all_declarations().collect::<BTreeSet<_>>()
    };
    if !indexed_lookup {
        return candidate_units;
    }

    let mut declarations_by_file = HashMap::<_, BTreeSet<_>>::new();
    candidate_units
        .into_iter()
        .filter(|unit| {
            declarations_by_file
                .entry(unit.source().clone())
                .or_insert_with(|| analyzer.declarations(unit.source()))
                .contains(unit)
        })
        .collect()
}

/// Count the workspace declarations that reach each active procedure summary
/// through the canonical member identity. This answers reachability only: a
/// conflicting posting counts once for every record, while the runtime still
/// refuses to choose between disagreeing claims.
fn procedure_summary_match_evidence(
    analyzer: &dyn IAnalyzer,
    active: &ResolvedActiveSemanticModels,
) -> BTreeMap<String, Vec<PolicyPackProcedureSummaryEvidence>> {
    let mut counts = BTreeMap::<(String, String), u64>::new();
    let mut target_member_identifiers = HashSet::new();
    let mut summaries_by_key = HashMap::<ModeledProcedureKey, Vec<(String, String)>>::new();
    for shard in active.shards() {
        if let Some(summaries) = shard.shard.payload().procedure_summaries() {
            for summary in summaries {
                if let Some((owner, member)) =
                    authored_procedure_target_identity(&summary.target.path, &summary.target.symbol)
                {
                    target_member_identifiers.insert(member.to_owned());
                    summaries_by_key
                        .entry(ModeledProcedureKey {
                            language: shard.manifest.language.clone(),
                            owner: owner.into_owned(),
                            member: member.to_owned(),
                            has_receiver: summary.target.has_receiver,
                            parameter_count: summary.target.parameter_count,
                        })
                        .or_default()
                        .push((shard.manifest.content_sha256.clone(), summary.id.clone()));
                }
                counts.insert(
                    (shard.manifest.content_sha256.clone(), summary.id.clone()),
                    0,
                );
            }
        }
    }
    // The candidate set is already narrowed to declarations whose terminal name
    // one active summary names. The canonical key is what decides the rest, so
    // there is no second owner derivation here to disagree with it -- the
    // duplicate that #2610 found dropped every module-level declaration before
    // the shared key path ever saw it.
    for unit in procedure_summary_candidate_declarations(analyzer, &target_member_identifiers) {
        let Some(key) = modeled_procedure_key_for_unit(analyzer, &unit) else {
            continue;
        };
        let Some(summaries) = summaries_by_key.get(&key) else {
            continue;
        };
        for summary in summaries {
            let count = counts
                .get_mut(summary)
                .expect("every active summary target was initialized");
            *count = count.saturating_add(1);
        }
    }

    let mut evidence = BTreeMap::<String, Vec<PolicyPackProcedureSummaryEvidence>>::new();
    for shard in active.shards() {
        let Some(summaries) = shard.shard.payload().procedure_summaries() else {
            continue;
        };
        let entries = evidence
            .entry(shard.manifest.content_sha256.clone())
            .or_default();
        for summary in summaries {
            let match_count = counts
                .get(&(shard.manifest.content_sha256.clone(), summary.id.clone()))
                .copied()
                .unwrap_or(0);
            entries.push(PolicyPackProcedureSummaryEvidence::new(
                summary.id.clone(),
                summary.target.symbol.clone(),
                match_count,
            ));
        }
    }
    evidence
}

/// Build procedure-summary evidence only when a dependency or reviewed
/// workspace-model route contributed to the activation. Intrinsic models stay
/// active for policy evaluation, but an intrinsic-only activation has no
/// authored pack whose review can consume this whole-workspace scan.
fn procedure_summary_match_evidence_for_review(
    analyzer: &dyn IAnalyzer,
    config: Option<&WorkspacePacksConfig>,
    activation: &WorkspacePacksActivation,
) -> Option<BTreeMap<String, Vec<PolicyPackProcedureSummaryEvidence>>> {
    let dependency_pack_contributed = activation
        .outcome
        .ecosystems
        .iter()
        .filter_map(|ecosystem| ecosystem.preparation.as_ref())
        .any(|preparation| {
            !preparation.packs.is_empty() || !preparation.installed_packs.is_empty()
        });
    if config.is_none() && activation.workspace_models.is_empty() && !dependency_pack_contributed {
        return None;
    }
    let active = match activation.outcome.runtime.as_ref()? {
        SemanticModelRuntimeOutcome::Ready { active, .. } => Some(active),
        SemanticModelRuntimeOutcome::Incomplete { usable, .. } => usable.as_ref(),
        SemanticModelRuntimeOutcome::Cancelled(_) | SemanticModelRuntimeOutcome::Unavailable(_) => {
            None
        }
    }?;
    Some(procedure_summary_match_evidence(analyzer, active))
}

/// Warn when an active, reviewed workspace model publishes a procedure
/// summary that reaches no workspace declaration. Installed or optional
/// dependency packs are intentionally excluded: this diagnostic is for an
/// author who opted a checked-in model into the current workspace.
fn active_workspace_model_zero_match_diagnostics(
    activation: Option<&WorkspacePacksActivation>,
    summary_evidence: Option<&BTreeMap<String, Vec<PolicyPackProcedureSummaryEvidence>>>,
) -> Result<Vec<PolicyReportDiagnostic>, PolicyCoordinatorError> {
    let Some(activation) = activation else {
        return Ok(Vec::new());
    };
    let Some(summary_evidence) = summary_evidence else {
        return Ok(Vec::new());
    };
    let Some(runtime) = activation.outcome.runtime.as_ref() else {
        return Ok(Vec::new());
    };
    let active = match runtime {
        SemanticModelRuntimeOutcome::Ready { active, .. } => active,
        SemanticModelRuntimeOutcome::Incomplete { usable, .. } => {
            let Some(active) = usable else {
                return Ok(Vec::new());
            };
            active
        }
        SemanticModelRuntimeOutcome::Cancelled(_) | SemanticModelRuntimeOutcome::Unavailable(_) => {
            return Ok(Vec::new());
        }
    };
    let mut diagnostics = Vec::new();
    for model in &activation.workspace_models {
        let Some(entries) = summary_evidence.get(&model.manifest_digest) else {
            continue;
        };
        let Some(shard) = active
            .shards()
            .iter()
            .find(|shard| shard.manifest.content_sha256 == model.manifest_digest)
        else {
            continue;
        };
        if shard.source_kind != CatalogPackSourceKind::EphemeralWorkspace {
            continue;
        }
        for entry in entries {
            if entry.match_count() != 0 {
                continue;
            }
            diagnostics.push(workspace_model_warning(
                format!(
                    "the active reviewed workspace semantic model `{}` summary `{}` targeting `{}` matched zero workspace procedures",
                    model.path,
                    entry.summary_id(),
                    entry.symbol(),
                ),
                Some(PolicySourceIdentity::new(&model.path)),
            )?);
        }
    }
    Ok(diagnostics)
}

/// Project one workspace activation transaction into the report's
/// pack-activation review (#1868, #1884, #2493).
///
/// A `None` activation still records an explicit document or host-owned
/// dependency attempt. An activation containing only intrinsic shipped models
/// returns no optional review.
fn pack_activation_review(
    config: Option<&WorkspacePacksConfig>,
    activation: Option<&WorkspacePacksActivation>,
    attempted_ecosystems: Option<&[DependencyPackEcosystem]>,
    activation_failure: Option<&str>,
    summary_evidence: Option<&BTreeMap<String, Vec<PolicyPackProcedureSummaryEvidence>>>,
) -> Option<PolicyPackActivationReview> {
    let source_path =
        pack_activation_source_path(config, activation, attempted_ecosystems, activation_failure)?;
    let dependency_mode = policy_dependency_pack_activation_mode(config);
    let Some(activation) = activation else {
        let decisions = activation_failure
            .map(|failure| {
                vec![PolicyPackDecision::new(
                    "workspace-activation".to_owned(),
                    PolicyPackDecisionStatus::Rejected,
                    Some(failure.to_owned()),
                )]
            })
            .unwrap_or_default();
        return Some(PolicyPackActivationReview::new_with_mode(
            source_path.to_owned(),
            dependency_mode,
            attempted_ecosystems
                .unwrap_or_else(|| config.map_or(&[], WorkspacePacksConfig::ecosystems))
                .iter()
                .map(|ecosystem| ecosystem.label().to_owned())
                .collect(),
            activation_failure.is_none(),
            decisions,
        ));
    };
    let mut decisions = Vec::new();
    for ecosystem in &activation.outcome.ecosystems {
        let Some(preparation) = &ecosystem.preparation else {
            continue;
        };
        for pack in &preparation.packs {
            decisions.push(PolicyPackDecision::new(
                pack.dependency_id.clone(),
                PolicyPackDecisionStatus::Selected,
                None,
            ));
        }
        for pack in &preparation.installed_packs {
            decisions.push(PolicyPackDecision::new(
                pack.dependency_id.clone(),
                PolicyPackDecisionStatus::Selected,
                None,
            ));
        }
        for diagnostic in &preparation.diagnostics {
            let status = match diagnostic.code.as_str() {
                "dependency.pack_version_mismatch" => PolicyPackDecisionStatus::VersionMismatch,
                "dependency.pack_unavailable" => PolicyPackDecisionStatus::Missing,
                _ => continue,
            };
            decisions.push(PolicyPackDecision::new(
                diagnostic
                    .dependency_id
                    .clone()
                    .unwrap_or_else(|| diagnostic.code.clone()),
                status,
                Some(diagnostic.message.clone()),
            ));
        }
    }
    match &activation.outcome.runtime {
        Some(SemanticModelRuntimeOutcome::Ready { active, .. }) => {
            record_active_shards(&mut decisions, active.shards(), summary_evidence);
            record_explanations(&mut decisions, &active.activation_report().explanations);
        }
        Some(SemanticModelRuntimeOutcome::Incomplete { usable, report }) => {
            if let Some(active) = usable {
                record_active_shards(&mut decisions, active.shards(), summary_evidence);
            }
            record_explanations(&mut decisions, &report.explanations);
        }
        Some(
            SemanticModelRuntimeOutcome::Cancelled(report)
            | SemanticModelRuntimeOutcome::Unavailable(report),
        ) => record_explanations(&mut decisions, &report.explanations),
        None => {}
    }
    if let Some(failure) = activation_failure {
        decisions.push(PolicyPackDecision::new(
            "workspace-activation".to_owned(),
            PolicyPackDecisionStatus::Rejected,
            Some(failure.to_owned()),
        ));
    }
    Some(PolicyPackActivationReview::new_with_mode(
        source_path.to_owned(),
        dependency_mode,
        activation
            .ecosystems
            .iter()
            .map(|ecosystem| ecosystem.label().to_owned())
            .collect(),
        activation.outcome.complete() && activation_failure.is_none(),
        decisions,
    ))
}

fn policy_dependency_pack_activation_mode(
    config: Option<&WorkspacePacksConfig>,
) -> PolicyDependencyPackActivationMode {
    match config {
        None => PolicyDependencyPackActivationMode::Default,
        Some(config) if config.ecosystems().is_empty() => {
            PolicyDependencyPackActivationMode::Disabled
        }
        Some(_) => PolicyDependencyPackActivationMode::Configured,
    }
}

/// The report diagnostic for a workspace activation that could not be built.
///
/// A failed catalog open is attributed to the document that named the catalog.
/// A refused workspace-local model is attributed to the file itself when the
/// failure names one, and to the reviewed directory otherwise, so the author
/// is pointed at the thing to fix.
fn workspace_activation_diagnostic(
    error: &WorkspaceActivationError,
) -> Result<PolicyReportDiagnostic, PolicyCoordinatorError> {
    match error {
        WorkspaceActivationError::Catalog(error) => report_diagnostic(
            PolicyReportDiagnosticCode::PackActivationFailed,
            format!("failed to activate workspace packs: {error}"),
            Some(PolicySourceIdentity::new(WORKSPACE_PACKS_DOCUMENT_PATH)),
            None,
            Vec::new(),
        ),
        WorkspaceActivationError::ShippedModels(error) => report_diagnostic(
            PolicyReportDiagnosticCode::PackActivationFailed,
            format!("failed to activate shipped semantic models: {error}"),
            None,
            None,
            Vec::new(),
        ),
        WorkspaceActivationError::WorkspaceModels(models) => {
            // The per-file variants already carry the full workspace-relative
            // path discovery reported; only a whole-directory failure has to
            // fall back to the directory itself.
            let path = models.path().unwrap_or(WORKSPACE_SEMANTIC_MODEL_DIRECTORY);
            report_diagnostic(
                PolicyReportDiagnosticCode::WorkspaceModelLoadFailed,
                format!("failed to activate the reviewed workspace semantic models: {models}"),
                Some(PolicySourceIdentity::new(path)),
                None,
                Vec::new(),
            )
        }
    }
}

/// Condemn a semantic-pack transaction that returned without one publishable
/// active-model snapshot.
///
/// `activate_workspace_semantic_sources` reserves `Err` for setup failures;
/// runtime refusal is carried inside an otherwise successful activation. An
/// owned policy analyzer always requests the intrinsic shipped models, so
/// treating one of these outcomes as ordinary model absence could turn a
/// shipped-model-dependent policy into a false clean result. Incomplete
/// optional dependency discovery is different: when the runtime is ready, its
/// independent intrinsic and workspace models are valid and useful even though
/// the pack review retains that incomplete dependency route.
fn nonready_activation_diagnostic(
    activation: &WorkspacePacksActivation,
) -> Result<Option<PolicyReportDiagnostic>, PolicyCoordinatorError> {
    let message = match activation.outcome.runtime.as_ref() {
        Some(SemanticModelRuntimeOutcome::Ready { .. }) => return Ok(None),
        Some(SemanticModelRuntimeOutcome::Incomplete { report, .. }) => {
            format!("semantic-model runtime was incomplete: {report:?}")
        }
        Some(SemanticModelRuntimeOutcome::Cancelled(report)) => {
            format!("semantic-model runtime was cancelled: {report:?}")
        }
        Some(SemanticModelRuntimeOutcome::Unavailable(report)) => {
            format!("semantic-model runtime was unavailable: {report:?}")
        }
        None => "semantic-model runtime was not attempted".to_owned(),
    };
    let source = (!activation.outcome.ecosystems.is_empty())
        .then(|| PolicySourceIdentity::new(WORKSPACE_PACKS_DOCUMENT_PATH));
    report_diagnostic(
        PolicyReportDiagnosticCode::PackActivationFailed,
        message,
        source,
        None,
        Vec::new(),
    )
    .map(Some)
}

/// Report every reviewed workspace model that did not reach the active set.
///
/// A model held back by the review gate is inert by design: it is reported as
/// a warning that names the missing `enable` entry, and the run stays as
/// reliable as its own evaluation makes it. Any other reason is a defect in
/// the activation and fails the run, because a model that registered and then
/// vanished would decide verdicts by its absence (#2493).
fn inactive_workspace_model_diagnostics(
    activation: Option<&WorkspacePacksActivation>,
) -> Result<Vec<PolicyReportDiagnostic>, PolicyCoordinatorError> {
    let Some(activation) = activation else {
        return Ok(Vec::new());
    };
    if activation.workspace_models.is_empty() {
        return Ok(Vec::new());
    }
    let Some(runtime) = activation.outcome.runtime.as_ref() else {
        return Ok(Vec::new());
    };
    let active = match runtime {
        SemanticModelRuntimeOutcome::Ready { active, .. } => active,
        SemanticModelRuntimeOutcome::Incomplete { usable, .. } => {
            let Some(active) = usable else {
                return Ok(Vec::new());
            };
            active
        }
        SemanticModelRuntimeOutcome::Cancelled(_) | SemanticModelRuntimeOutcome::Unavailable(_) => {
            return Ok(Vec::new());
        }
    };
    let mut diagnostics = Vec::new();
    for inactive in workspace_semantic_models_not_active(&activation.workspace_models, active) {
        let source = Some(PolicySourceIdentity::new(&inactive.model.path));
        let reason = inactive
            .reason
            .unwrap_or("the activation recorded no reason");
        if inactive.awaits_review() {
            diagnostics.push(workspace_model_warning(
                format!(
                    "the reviewed workspace semantic model `{}` is inert: {reason}. Name `{}` in \
                     the `enable` list of {WORKSPACE_PACKS_DOCUMENT_PATH} to activate it.",
                    inactive.model.path, inactive.model.pack_id
                ),
                source,
            )?);
        } else {
            diagnostics.push(report_diagnostic(
                PolicyReportDiagnosticCode::WorkspaceModelLoadFailed,
                format!(
                    "the reviewed workspace semantic model `{}` registered but did not activate: \
                     {reason}",
                    inactive.model.path
                ),
                source,
                None,
                Vec::new(),
            )?);
        }
    }
    Ok(diagnostics)
}

/// One report diagnostic that informs without condemning the run.
///
/// `report_diagnostic` mints errors, and an error makes a run unreliable. An
/// inert review-gated model is not an error: the gate did its job, and the
/// author still needs to see why the model contributed nothing.
fn workspace_model_warning(
    message: String,
    source: Option<PolicySourceIdentity>,
) -> Result<PolicyReportDiagnostic, PolicyCoordinatorError> {
    PolicyReportDiagnostic::try_new(
        PolicyReportDiagnosticCode::WorkspaceModelInert,
        PolicyDiagnosticSeverity::Warning,
        safe_report_text(message),
        source,
        None,
        Vec::new(),
    )
    .map_err(|error| {
        PolicyCoordinatorError::new(format!(
            "failed to construct policy report diagnostic: {error}"
        ))
    })
}

fn record_active_shards(
    decisions: &mut Vec<PolicyPackDecision>,
    shards: &[ActiveSemanticModelShard],
    summary_evidence: Option<&BTreeMap<String, Vec<PolicyPackProcedureSummaryEvidence>>>,
) {
    for shard in shards {
        let mut decision = PolicyPackDecision::new(
            format!("{}@{}", shard.manifest.pack_id, shard.manifest.version),
            PolicyPackDecisionStatus::Selected,
            None,
        );
        if let Some(evidence) =
            summary_evidence.and_then(|evidence| evidence.get(&shard.manifest.content_sha256))
        {
            decision = decision.with_summary_matches(evidence.clone());
        }
        decisions.push(decision);
    }
}

fn record_explanations(
    decisions: &mut Vec<PolicyPackDecision>,
    explanations: &[SemanticModelActivationExplanation],
) {
    for explanation in explanations {
        let status = match explanation.status {
            SemanticModelActivationStatus::Active => PolicyPackDecisionStatus::Selected,
            SemanticModelActivationStatus::Incompatible => PolicyPackDecisionStatus::Incompatible,
            _ => PolicyPackDecisionStatus::Rejected,
        };
        let reason =
            (status != PolicyPackDecisionStatus::Selected).then(|| explanation.reason.clone());
        decisions.push(PolicyPackDecision::new(
            explanation
                .pack_id
                .clone()
                .unwrap_or_else(|| explanation.manifest_digest.clone()),
            status,
            reason,
        ));
    }
}

#[allow(clippy::too_many_arguments)]
fn evaluate_prepared_policy_inputs(
    root: &Path,
    read_root: &WorkspaceRoot,
    mut inputs: Vec<InputOutcome>,
    options: &PolicyEvaluationOptions,
    batch_budget: PolicyBatchBudget,
    registry_limits: PolicyRegistryLimits,
    supplied_workspace: Option<&WorkspaceAnalyzer>,
    supplied_flow_state: Option<&brokk_bifrost_flow::FlowWorkspaceState>,
    semantic_models: Option<PolicySemanticModelContext<'_>>,
    host_activation: Option<PolicyHostActivationContext<'_>>,
    suppression_preflight: Option<PolicySuppressionPreflight>,
    supplied_incremental: Option<&PolicyIncrementalContext<'_>>,
    cancellation: Option<&CancellationToken>,
) -> Result<PolicyBatchOutcome, PolicyCoordinatorError> {
    let registration_started = Instant::now();
    let requested_policy_ids = inputs
        .iter()
        .filter_map(|input| match input {
            InputOutcome::Pending(prepared) => Some(prepared.policy_id.clone()),
            InputOutcome::Runnable(policy_id) => Some(policy_id.clone()),
            InputOutcome::Diagnostic(_) => None,
        })
        .collect::<Vec<_>>();
    // The diff base evaluates exactly the head's policy sources as embedded
    // inputs, so its registry resolves referenced selectors, endpoints, and
    // catalogs beneath the base image rather than the checkout. Registration
    // consumes the pending bytes, so capture them first.
    let diff_base_sources = if options.diff_base().is_some() {
        inputs
            .iter()
            .filter_map(|input| match input {
                InputOutcome::Pending(prepared) => Some((
                    prepared.policy_id.clone(),
                    prepared.source.clone(),
                    prepared.bytes.clone(),
                )),
                InputOutcome::Runnable(_) | InputOutcome::Diagnostic(_) => None,
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    if policy_deadline_reached(cancellation)? {
        return deadline_before_evaluation_outcome(
            options,
            batch_budget,
            options
                .suppressions()
                .source_states(PolicySuppressionDocumentState::NotEvaluated),
            PolicyScopeDocumentState::NotEvaluated,
            vec![PolicyStageTiming::from_duration(
                PolicyExecutionStage::PolicyRegistration,
                registration_started.elapsed(),
            )],
            PolicyExecutionStage::PolicyRegistration,
            requested_policy_ids,
            None,
        );
    }
    let mut secondary_diagnostics = Vec::new();
    let suppression_load = suppression_preflight.map_or_else(
        || load_policy_suppressions_from_root(read_root, options.suppressions()),
        PolicySuppressionPreflight::into_outcome,
    );
    for failure in &suppression_load.failures {
        secondary_diagnostics.push(report_diagnostic(
            PolicyReportDiagnosticCode::SuppressionLoadFailed,
            format!("failed to load policy suppressions: {}", failure.error),
            Some(PolicySourceIdentity::new(&failure.path)),
            None,
            Vec::new(),
        )?);
    }
    let suppression_document = suppression_load.document;
    let suppression_sources = suppression_load.sources;
    let (scope_document, scope_document_state) =
        match load_policy_scope_from_root(read_root, options.scope()) {
            Ok(Some(document)) => (Some(document), PolicyScopeDocumentState::Loaded),
            Ok(None) => (None, PolicyScopeDocumentState::NotFound),
            Err(error) => {
                secondary_diagnostics.push(report_diagnostic(
                    PolicyReportDiagnosticCode::ScopeLoadFailed,
                    format!("failed to load policy scope: {error}"),
                    Some(PolicySourceIdentity::new(
                        options.scope().source().relative_path(),
                    )),
                    None,
                    Vec::new(),
                )?);
                (None, PolicyScopeDocumentState::Invalid)
            }
        };
    // A malformed baseline document is loud: its diagnostic alone makes the
    // run unreliable, so a broken bulk acceptance can never look clean.
    let baseline_document = match load_policy_baseline_from_root(read_root, options.baseline()) {
        Ok(document) => document,
        Err(error) => {
            secondary_diagnostics.push(report_diagnostic(
                PolicyReportDiagnosticCode::BaselineLoadFailed,
                format!("failed to load the policy baseline: {error}"),
                Some(PolicySourceIdentity::new(
                    options.baseline().source().relative_path(),
                )),
                None,
                Vec::new(),
            )?);
            None
        }
    };
    // The workspace packs document opts this evaluation into dependency and
    // stdlib semantic-pack activation (#1868). A malformed document is loud:
    // its diagnostic makes the run unreliable rather than silently evaluating
    // without the configured packs.
    let mut packs_load_failure = None;
    let packs_config = match load_workspace_packs_config(read_root) {
        Ok(config) => config,
        Err(error) => {
            let failure = format!("failed to load the workspace packs document: {error}");
            secondary_diagnostics.push(report_diagnostic(
                PolicyReportDiagnosticCode::PacksLoadFailed,
                failure.clone(),
                Some(PolicySourceIdentity::new(WORKSPACE_PACKS_DOCUMENT_PATH)),
                None,
                Vec::new(),
            )?);
            packs_load_failure = Some(failure);
            None
        }
    };
    if policy_deadline_reached(cancellation)? {
        return deadline_before_evaluation_outcome(
            options,
            batch_budget,
            suppression_sources.clone(),
            scope_document_state,
            vec![PolicyStageTiming::from_duration(
                PolicyExecutionStage::PolicyRegistration,
                registration_started.elapsed(),
            )],
            PolicyExecutionStage::PolicyRegistration,
            requested_policy_ids,
            None,
        );
    }
    let catalogs = Arc::new(
        TaintCatalogRegistry::new_for_workspace(
            root.to_path_buf(),
            CatalogRegistryLimits::default(),
        )
        .map_err(|error| {
            PolicyCoordinatorError::new(format!(
                "failed to initialize policy catalog registry: {error}"
            ))
        })?,
    );
    if policy_deadline_reached(cancellation)? {
        return deadline_before_evaluation_outcome(
            options,
            batch_budget,
            suppression_sources.clone(),
            scope_document_state,
            vec![PolicyStageTiming::from_duration(
                PolicyExecutionStage::PolicyRegistration,
                registration_started.elapsed(),
            )],
            PolicyExecutionStage::PolicyRegistration,
            requested_policy_ids,
            None,
        );
    }
    let mut registry = PolicyRegistry::new_for_workspace(
        root.to_path_buf(),
        catalogs,
        registry_limits,
    )
    .map_err(|error| {
        PolicyCoordinatorError::new(format!("failed to initialize policy registry: {error}"))
    })?;

    // Qualified policy locators need the same analyzer snapshot and active
    // model publication that evaluation will use. Prepare both before closing
    // any policy so the loaded-policy boundary can resolve them exactly once.
    let needs_workspace = inputs
        .iter()
        .any(|input| matches!(input, InputOutcome::Pending(_) | InputOutcome::Runnable(_)));
    let owned_analyzer = if needs_workspace && supplied_workspace.is_none() {
        let project = FilesystemProject::new(root).map_err(|error| {
            PolicyCoordinatorError::new(format!(
                "failed to construct analyzer project {}: {error}",
                root.display()
            ))
        })?;
        let project: Arc<dyn Project> = Arc::new(project);
        // Persisted, so consecutive policy runs over one root reuse the blobs
        // the first run parsed instead of re-parsing the world into a
        // delete-on-drop database. This is the fallback for every host that does
        // not hand us its own analyzer: the `--policy-file` CLI, the MCP
        // workspace-less arm, and any LSP request that arrives before the
        // server's workspace is ready.
        Some(
            WorkspaceAnalyzer::build_persisted(project, owned_policy_analyzer_config()).map_err(
                |error| {
                    PolicyCoordinatorError::new(format!(
                        "failed to build the analyzer workspace at {}: {error}",
                        root.display()
                    ))
                },
            )?,
        )
    } else {
        None
    };
    let workspace = supplied_workspace.or(owned_analyzer.as_ref());
    let workspace_has_analyzable_files =
        workspace.is_some_and(|workspace| !workspace.analyzer().analyzed_files().is_empty());
    let uncancelled = CancellationToken::default();
    let semantic_cancellation = cancellation.unwrap_or(&uncancelled);
    let workspace_activation = match owned_analyzer.as_ref() {
        Some(_) if packs_load_failure.is_some() => Some(None),
        Some(analyzer_workspace) => {
            match activate_owned_policy_workspace(
                root,
                analyzer_workspace,
                packs_config.as_ref(),
                semantic_cancellation,
            ) {
                Ok(activation) => Some(activation),
                Err(error) => {
                    secondary_diagnostics.push(workspace_activation_diagnostic(&error)?);
                    None
                }
            }
        }
        None => None,
    };
    let document_semantic_model_snapshot = ready_policy_semantic_model_snapshot(
        workspace_activation
            .as_ref()
            .and_then(Option::as_ref)
            .or_else(|| host_activation.and_then(|context| context.activation)),
    );
    let host_semantic_model_snapshot = supplied_workspace
        .and_then(|workspace| workspace.analyzer().active_semantic_model_snapshot());
    let active_semantic_model_snapshot = match semantic_models {
        None => Ok(document_semantic_model_snapshot.or(host_semantic_model_snapshot)),
        Some(context) => {
            let workspace = workspace.ok_or_else(|| {
                PolicyCoordinatorError::new(
                    "semantic-model policy evaluation requires an analyzer snapshot",
                )
            })?;
            match acquire_active_semantic_models(
                workspace.analyzer(),
                context.catalog,
                context.persistence,
                context.request,
                semantic_cancellation,
            ) {
                SemanticModelRuntimeOutcome::Ready { snapshot, .. } => Ok(Some(snapshot)),
                SemanticModelRuntimeOutcome::Incomplete { report, .. } => Err(format!(
                    "semantic-model activation was incomplete: {report:?}"
                )),
                SemanticModelRuntimeOutcome::Cancelled(report) => Err(format!(
                    "semantic-model activation was cancelled: {report:?}"
                )),
                SemanticModelRuntimeOutcome::Unavailable(report) => Err(format!(
                    "semantic-model activation was unavailable: {report:?}"
                )),
            }
        }
    };
    let icfg_active_semantic_model_snapshot = active_semantic_model_snapshot
        .as_ref()
        .ok()
        .and_then(|snapshot| snapshot.as_ref().map(Arc::clone));
    // Policy registration resolves qualified locators, so it is part of the
    // same semantic-model transaction as preparation and execution. Pin both a
    // successful publication and a deliberate absence before registration; a
    // supplied workspace may publish a newer model set concurrently.
    let _semantic_model_scope = workspace.map(|workspace| {
        AnalyzerQueryScope::with_active_semantic_model_snapshot(
            workspace.analyzer(),
            icfg_active_semantic_model_snapshot.clone(),
        )
    });

    let mut pending_indexes = inputs
        .iter()
        .enumerate()
        .filter_map(|(index, input)| match input {
            InputOutcome::Pending(prepared) => {
                Some((index, prepared.policy_id.clone(), prepared.source.clone()))
            }
            InputOutcome::Diagnostic(_) | InputOutcome::Runnable(_) => None,
        })
        .collect::<Vec<_>>();
    pending_indexes
        .sort_by(|left, right| (&left.1, left.2.as_str()).cmp(&(&right.1, right.2.as_str())));

    let mut input_by_policy_id = HashMap::new();
    for (input_index, _, source) in pending_indexes {
        if policy_deadline_reached(cancellation)? {
            return deadline_before_evaluation_outcome(
                options,
                batch_budget,
                suppression_sources.clone(),
                scope_document_state,
                vec![PolicyStageTiming::from_duration(
                    PolicyExecutionStage::PolicyRegistration,
                    registration_started.elapsed(),
                )],
                PolicyExecutionStage::PolicyRegistration,
                requested_policy_ids,
                None,
            );
        }
        let InputOutcome::Pending(prepared) = &inputs[input_index] else {
            return Err(PolicyCoordinatorError::new(
                "pending policy input changed during stable registration",
            ));
        };
        let registration = match workspace {
            Some(workspace) => registry
                .register_policy_bytes_with_analyzer(
                    prepared.source.clone(),
                    prepared.bytes.as_bytes(),
                    workspace.analyzer(),
                )
                .map(|policy| policy.definition().metadata.id.clone()),
            None => registry
                .register_policy_bytes(prepared.source.clone(), prepared.bytes.as_bytes())
                .map(|policy| policy.definition().metadata.id.clone()),
        };
        match registration {
            Ok(policy_id) => {
                input_by_policy_id.insert(policy_id.clone(), input_index);
                inputs[input_index] = InputOutcome::Runnable(policy_id);
            }
            Err(error) => {
                inputs[input_index] =
                    InputOutcome::Diagnostic(registry_diagnostic(source, &error)?);
            }
        }
    }

    if options.require_explicit_schema_versions() {
        for policy in registry.policies() {
            let diagnostics = explicit_version_diagnostics(policy)?;
            let Some((primary, secondary)) = diagnostics.split_first() else {
                continue;
            };
            let input_index = *input_by_policy_id
                .get(&policy.definition().metadata.id)
                .ok_or_else(|| {
                    PolicyCoordinatorError::new(format!(
                        "registered policy `{}` has no requested input",
                        policy.definition().metadata.id
                    ))
                })?;
            inputs[input_index] = InputOutcome::Diagnostic(primary.clone());
            secondary_diagnostics.extend_from_slice(secondary);
        }
    }

    let runnable_ids = inputs
        .iter()
        .filter_map(|input| match input {
            InputOutcome::Runnable(policy_id) => Some(policy_id.clone()),
            InputOutcome::Pending(_) | InputOutcome::Diagnostic(_) => None,
        })
        .collect::<HashSet<_>>();
    let evaluation_policy_ids = registry
        .policies()
        .filter(|policy| runnable_ids.contains(&policy.definition().metadata.id))
        .map(|policy| policy.definition().metadata.id.clone())
        .collect::<Vec<_>>();
    let registration_elapsed = registration_started.elapsed();
    if policy_deadline_reached(cancellation)? {
        return deadline_before_evaluation_outcome(
            options,
            batch_budget,
            suppression_sources.clone(),
            scope_document_state,
            vec![PolicyStageTiming::from_duration(
                PolicyExecutionStage::PolicyRegistration,
                registration_elapsed,
            )],
            PolicyExecutionStage::PolicyRegistration,
            requested_policy_ids,
            None,
        );
    }

    let preparation_started = Instant::now();
    // One store per batch, and only where reuse is possible at all: the base
    // publishes into it and the head reads from it. Without a diff base there
    // is nothing published to reuse, and unit-wise execution would only add
    // per-execution overhead until Milestone 3 persists units across runs.
    let unit_store = (options.incremental() && options.diff_base().is_some())
        .then(|| BatchUnitStore::of(workspace));
    let mut runs = HashMap::with_capacity(runnable_ids.len());
    let owned_flow_state = supplied_flow_state
        .is_none()
        .then(brokk_bifrost_flow::FlowWorkspaceState::new);
    let flow_state = supplied_flow_state
        .or(owned_flow_state.as_ref())
        .expect("every policy evaluation owns reusable flow state");
    // A policy subject scan is Theta(workspace facts), so the scan lanes must
    // follow the audited workspace (#1771).  Scaling is a per-lane max, so an
    // explicitly widened caller budget survives and an explicitly narrowed one
    // is raised back to the fixed defaults.
    let per_policy_budget = policy_budget_for_workspace(*batch_budget.per_policy(), workspace);
    let activation_for_report = workspace_activation
        .as_ref()
        .and_then(Option::as_ref)
        .or_else(|| host_activation.and_then(|context| context.activation));
    let activation_config_for_report = match workspace_activation.as_ref() {
        Some(_) => packs_config.as_ref(),
        None => host_activation.and_then(|context| context.config),
    };
    let host_activation_failure = host_activation.and_then(|context| context.failure);
    if host_activation_failure.is_none()
        && let Some(activation) = activation_for_report
        && let Some(diagnostic) = nonready_activation_diagnostic(activation)?
    {
        secondary_diagnostics.push(diagnostic);
    }
    let summary_evidence = workspace.and_then(|workspace| {
        let activation = activation_for_report?;
        procedure_summary_match_evidence_for_review(
            workspace.analyzer(),
            activation_config_for_report,
            activation,
        )
    });
    let packs_review = match workspace_activation.as_ref() {
        // Dependency activation or a reviewed workspace model earns an audit
        // row. Intrinsic shipped models can share the transaction without
        // changing the top-level wire shape by themselves.
        Some(Some(activation)) => pack_activation_review(
            packs_config.as_ref(),
            Some(activation),
            None,
            None,
            summary_evidence.as_ref(),
        ),
        // The transaction ran and neither route contributed. A document still
        // earns a review row so its opt-in stays auditable; a run with no
        // document and no reviewed model keeps its exact schema-version-5
        // shape and attaches nothing.
        Some(None) => pack_activation_review(
            packs_config.as_ref(),
            None,
            None,
            packs_load_failure.as_deref(),
            None,
        ),
        // A supplied analyzer's host owns the transaction. Preserve its exact
        // activation evidence instead of re-running it here.
        None => host_activation.and_then(|context| {
            pack_activation_review(
                context.config,
                context.activation,
                Some(context.attempted_ecosystems),
                context.failure,
                summary_evidence.as_ref(),
            )
        }),
    };
    if let Some(failure) = host_activation_failure {
        secondary_diagnostics.push(report_diagnostic(
            PolicyReportDiagnosticCode::PackActivationFailed,
            format!("host-owned workspace pack activation failed: {failure}"),
            Some(PolicySourceIdentity::new(WORKSPACE_PACKS_DOCUMENT_PATH)),
            None,
            Vec::new(),
        )?);
    }
    // A registered workspace model that never reaches the active set is
    // invisible, and an invisible model decides verdicts by its absence. The
    // review gate is the one honest exception: a `review_required` model with
    // no matching `enable` entry is inert by design, so it is reported as a
    // warning the author can read rather than as a failed run.
    for diagnostic in inactive_workspace_model_diagnostics(activation_for_report)? {
        secondary_diagnostics.push(diagnostic);
    }
    for diagnostic in active_workspace_model_zero_match_diagnostics(
        activation_for_report,
        summary_evidence.as_ref(),
    )? {
        secondary_diagnostics.push(diagnostic);
    }
    // The summaries an activated pack publishes reach taint only through
    // `PolicySemanticModelContext`. An API caller supplies that context; the
    // CLI route supplies none, so without this strand an activated summary pack
    // changed taint results for an API caller alone (#1915).
    // Reuse the resolved runtime the activation already built, exactly as an
    // API caller would, and only when it is `Ready`: an incomplete activation
    // must not silently model calls it never resolved.
    let taint = workspace.map_or_else(ProductionTaintPolicyEvaluator::default, |workspace| {
        ProductionTaintPolicyEvaluator::prepare(
            registry
                .policies()
                .filter(|policy| runnable_ids.contains(&policy.definition().metadata.id)),
            workspace,
            active_semantic_model_snapshot,
            cancellation,
            &per_policy_budget,
        )
    });
    let typestate = ProductionTypestatePolicyEvaluator::with_active_semantic_model_snapshot(
        icfg_active_semantic_model_snapshot.clone(),
    );
    let evaluator = DefaultPolicyEvaluator::new()
        .with_taint(&taint)
        .with_typestate(&typestate)
        .with_active_semantic_model_snapshot(icfg_active_semantic_model_snapshot.clone());
    let preparation_elapsed = preparation_started.elapsed();
    if policy_deadline_reached(cancellation)? {
        return deadline_before_evaluation_outcome(
            options,
            batch_budget,
            suppression_sources.clone(),
            scope_document_state,
            vec![
                PolicyStageTiming::from_duration(
                    PolicyExecutionStage::PolicyRegistration,
                    registration_elapsed,
                ),
                PolicyStageTiming::from_duration(
                    PolicyExecutionStage::PolicyPreparation,
                    preparation_elapsed,
                ),
            ],
            PolicyExecutionStage::PolicyPreparation,
            evaluation_policy_ids,
            None,
        );
    }
    let evaluation_started = Instant::now();
    // The base evaluates before the head loop: its units must exist before the
    // head can verify and reuse them, and the runnable policy set that filters
    // its inputs is known as soon as registration is done.
    let diff_baseline = match options.diff_base() {
        Some(revision) => {
            let base_inputs = diff_base_sources
                .iter()
                .filter(|(policy_id, _, _)| runnable_ids.contains(policy_id))
                .map(|(_, source, bytes)| {
                    PolicyEvaluationInput::embedded(source.clone(), bytes.as_str())
                })
                .collect::<Vec<_>>();
            let runnable_policies = registry
                .policies()
                .filter(|policy| runnable_ids.contains(&policy.definition().metadata.id))
                .collect::<Vec<_>>();
            let evaluation_key = workspace.map(|head| {
                base_evaluation_key(
                    &runnable_policies,
                    options,
                    batch_budget,
                    registry_limits,
                    WorkspaceUnitInputs::of(head, icfg_active_semantic_model_snapshot.as_deref()),
                )
            });
            // An earlier run may have evaluated this exact base already. When
            // it did, its units are the base's own answer and replaying them
            // costs no export, no build and no execution.
            let reused = match (workspace, unit_store.as_ref(), evaluation_key.as_ref()) {
                (Some(head), Some(store), Some(key)) => reuse_persisted_diff_baseline(
                    root,
                    head,
                    revision,
                    &runnable_policies,
                    store,
                    key,
                ),
                _ => None,
            };
            match reused {
                Some(outcome) => Some(outcome),
                None => Some(evaluate_policy_diff_baseline(
                    root,
                    workspace,
                    revision,
                    options,
                    base_inputs,
                    batch_budget,
                    registry_limits,
                    &runnable_policies,
                    evaluation_key,
                    unit_store.as_ref(),
                    cancellation,
                )?),
            }
        }
        None => None,
    };
    // A head unit is reusable only against the base the units were published
    // from, so the head slices exactly when that comparison exists.
    let head_incremental_owned = match (&unit_store, &diff_baseline, workspace) {
        (Some(store), Some(baseline), Some(head)) => baseline.changed.as_ref().map(|changed| {
            PolicyIncrementalContext::new(
                store.units(),
                head,
                changed,
                WorkspaceUnitInputs::of(head, icfg_active_semantic_model_snapshot.as_deref()),
                baseline.state,
            )
        }),
        _ => None,
    };
    // Exactly one of the two exists: the base half of a diff run is handed its
    // caller's context and configures no diff base of its own, and the head
    // half builds one and is handed none.
    assert!(
        supplied_incremental.is_none() || head_incremental_owned.is_none(),
        "a policy batch evaluates either its own head units or a caller's base units, never both"
    );
    let head_incremental = supplied_incremental.or(head_incremental_owned.as_ref());
    let mut fail_closed_gate = false;
    let mut completed_policy_ids = Vec::with_capacity(evaluation_policy_ids.len());
    let mut active_policy_id = None;
    let mut pending_policy_ids = Vec::new();
    let mut deadline_stage = None;
    for (policy_index, policy) in registry
        .policies()
        .filter(|policy| runnable_ids.contains(&policy.definition().metadata.id))
        .enumerate()
    {
        if policy_deadline_reached(cancellation)? {
            deadline_stage.get_or_insert(PolicyExecutionStage::PolicyEvaluation);
        }
        let mut evaluation_budget = per_policy_budget;
        let context = PolicyEvaluationContext {
            analyzer: workspace.map(WorkspaceAnalyzer::analyzer).ok_or_else(|| {
                PolicyCoordinatorError::new(format!(
                    "runnable policy `{}` has no analyzer snapshot",
                    policy.definition().metadata.id
                ))
            })?,
            workspace,
            flow_state,
            cancellation,
            cvss_overlays: &[],
            organizational_risk: &[],
            incremental: head_incremental,
        };
        let policy_started = Instant::now();
        let evaluated = {
            let _scope = brokk_bifrost_analysis::profiling::scope_with(|| {
                format!(
                    "policy_coordinator.evaluate_policy[{}]",
                    policy.definition().metadata.id.as_str()
                )
            });
            evaluator.evaluate(policy, &context, &mut evaluation_budget)
        };
        let policy_elapsed = policy_started.elapsed();
        let mut run = match evaluated {
            Ok(run) => run,
            Err(error) => failed_evaluation_run(policy, error.to_string(), &evaluation_budget)?,
        };
        if options.policy_timings() {
            let elapsed_ms = u64::try_from(policy_elapsed.as_millis()).unwrap_or(u64::MAX);
            let metric = PolicyWorkMetric::try_new(
                EVALUATION_ELAPSED_METRIC,
                PolicyWorkUnit::Milliseconds,
                elapsed_ms,
            )
            .map_err(|error| {
                PolicyCoordinatorError::new(format!(
                    "failed to construct the evaluation timing metric: {error}"
                ))
            })?;
            run.work_mut().try_push_metric(metric).map_err(|error| {
                PolicyCoordinatorError::new(format!(
                    "failed to record the evaluation timing metric: {error}"
                ))
            })?;
        }
        if !workspace_has_analyzable_files {
            run.mark_inconclusive(PolicyIncompleteReason::NoAnalyzableFiles)
                .map_err(|error| {
                    PolicyCoordinatorError::new(format!(
                        "failed to retain empty workspace completion reason: {error}"
                    ))
                })?;
        }
        let deadline_exceeded = policy_deadline_reached(cancellation)?;
        if deadline_exceeded {
            deadline_stage.get_or_insert(PolicyExecutionStage::PolicyEvaluation);
            if matches!(
                run.completion(),
                PolicyRunCompletion::Inconclusive { reasons }
                    if reasons.contains(&PolicyIncompleteReason::Cancelled)
            ) {
                run.replace_incomplete_reason(
                    PolicyIncompleteReason::Cancelled,
                    PolicyIncompleteReason::DeadlineExceeded,
                )
                .map_err(|error| {
                    PolicyCoordinatorError::new(format!(
                        "failed to retain deadline completion reason: {error}"
                    ))
                })?;
            }
            if active_policy_id.is_none() {
                active_policy_id = Some(policy.definition().metadata.id.clone());
                pending_policy_ids.extend_from_slice(&evaluation_policy_ids[policy_index + 1..]);
            }
        } else if active_policy_id.is_none() {
            completed_policy_ids.push(policy.definition().metadata.id.clone());
        }
        // The policy's declared handling of a blocked verdict is applied once
        // the run's completion is final, so an unrelated cause of
        // inconclusiveness -- an empty workspace, a deadline -- is covered by
        // the same declaration (#2506).
        let verdict = policy.definition().on_unknown.verdict;
        run.apply_unknown_verdict(verdict, &evaluation_budget)
            .map_err(|error| {
                PolicyCoordinatorError::new(format!(
                    "failed to apply the declared unknown-result verdict: {error}"
                ))
            })?;
        // A fail-closed run gates exactly as a finding at the policy's own
        // severity would, so the threshold is read from the same option the
        // findings are read with.
        if run.unknown_verdict() == Some(UnknownVerdict::FailClosed)
            && options
                .fail_on()
                .matches(super::evaluator::finding_severity(
                    &policy.definition().metadata.severity,
                    None,
                ))
        {
            fail_closed_gate = true;
        }
        runs.insert(policy.definition().metadata.id.clone(), run);
    }
    let evaluation_elapsed = evaluation_started.elapsed();
    let report_started = Instant::now();
    if policy_deadline_reached(cancellation)? {
        deadline_stage.get_or_insert(PolicyExecutionStage::ReportConstruction);
    }
    // Every policy has run, so the units this batch computed describe work
    // that finished. A run that stopped early publishes nothing: its units
    // would be indistinguishable from complete ones on a later run, and the
    // whole reuse claim rests on being unable to confuse the two.
    if let Some(store) = unit_store.as_ref()
        && deadline_stage.is_none()
    {
        store.flush();
        if let Some(publication) = diff_baseline
            .as_ref()
            .and_then(|outcome| outcome.publication.as_ref())
        {
            store.publish_evaluation(publication);
        }
    }

    let diff_review = match &diff_baseline {
        Some(baseline) => Some(apply_policy_diff(&baseline.baseline, &mut runs)?),
        None => None,
    };
    if let Some(baseline) = diff_baseline.as_ref().map(|outcome| &outcome.baseline)
        && let Some(detail) = &baseline.unreliable_detail
    {
        secondary_diagnostics.push(report_diagnostic(
            PolicyReportDiagnosticCode::DiffBaseUnreliable,
            format!(
                "diff base `{}` ({}) was unreliable, so every head finding gates as if --diff-base had not been given: {detail}",
                baseline.requested_revision, baseline.resolved_commit
            ),
            None,
            None,
            Vec::new(),
        )?);
    }

    let suppression_reviews = match suppression_document.as_ref() {
        Some(document) => apply_policy_suppressions(
            document,
            options.evaluation_date(),
            &registry,
            workspace,
            &mut runs,
        )?,
        None => Vec::new(),
    };
    let scope_reviews = match scope_document.as_ref() {
        Some(document) => apply_policy_scope(document, &mut runs)?,
        None => Vec::new(),
    };
    let evaluation = PolicyReportEvaluationContext::new(
        options.evaluation_date(),
        suppression_sources,
        options.scope(),
        scope_document_state,
    );
    let mut builder = match PolicyReportBuilder::new_with_suppression_audit(
        batch_budget,
        inputs.len(),
        evaluation.clone(),
        suppression_reviews,
        scope_reviews,
    ) {
        Ok(builder) => builder,
        Err(PolicyReportBuilderError::SuppressionAuditPreflightExceeded { .. }) => {
            for finding in runs.values_mut().flat_map(|run| run.findings_mut()) {
                finding.clear_suppression();
                finding.clear_scope();
            }
            secondary_diagnostics.push(report_diagnostic(
                PolicyReportDiagnosticCode::SuppressionAuditRetentionExceeded,
                "suppression and scope audits exceed the report retention budget; no suppressions or scopes were applied",
                Some(PolicySourceIdentity::new(
                    options.suppressions().primary_relative_path(),
                )),
                None,
                Vec::new(),
            )?);
            PolicyReportBuilder::new_with_suppression_audit(
                batch_budget,
                inputs.len(),
                evaluation,
                Vec::new(),
                Vec::new(),
            )
            .map_err(|error| {
                PolicyCoordinatorError::new(format!(
                    "policy report preflight failed after disabling suppressions: {error}"
                ))
            })?
        }
        Err(error) => {
            return Err(PolicyCoordinatorError::new(format!(
                "policy report preflight failed: {error}"
            )));
        }
    };
    // The baseline claims only findings that suppressions and scope left
    // unclaimed, so it joins after the builder preflight settled those
    // attachments (a preflight rollback clears them, and the baseline must
    // see the final claim state).
    let baseline_review = match baseline_document.as_ref() {
        Some(document) => {
            let entries = apply_policy_baseline(document, &registry, &mut runs)?;
            Some(PolicyBaselineReview::new(
                options.baseline().source().relative_path(),
                document,
                entries,
            ))
        }
        None => None,
    };
    // A degraded diff review does not narrow the gate: every finding gates as
    // if no diff base had been given.
    let diff_gating = diff_review
        .as_ref()
        .is_some_and(|review| !review.degraded());
    let threshold_exceeded = fail_closed_gate
        || runs.values().flat_map(PolicyRun::findings).any(|finding| {
            finding.suppression().is_none()
                && finding.scope().is_none()
                && finding.baseline().is_none()
                && options.fail_on().matches(finding.severity())
                && (!diff_gating
                    || finding
                        .diff()
                        .is_some_and(|diff| diff.disposition() == FindingDiffDisposition::New))
        });
    if let Some(review) = diff_review {
        builder.set_diff(review).map_err(|error| {
            PolicyCoordinatorError::new(format!("failed to retain the policy diff review: {error}"))
        })?;
    }
    // Every diff-base run reports what it reused, including the run that
    // reused nothing. The section is charged to the report's retention budget
    // like the diff review, so a section present in one mode and absent in the
    // other would be a retained size that depends on how the run executed, and
    // two runs that must agree byte for byte could retain a different prefix
    // of the same findings at the exact boundary.
    let incremental_review = match head_incremental {
        Some(incremental) => Some(incremental.review()),
        None => options.diff_base().is_some().then(|| {
            let reason = if options.incremental() {
                // Reuse was asked for and there was nothing to reuse against:
                // the base evaluation produced no comparison, which is the
                // same missing evidence a verification reports.
                WidenReason::ReverseDependencyEvidenceMissing
            } else {
                WidenReason::IncrementalDisabled
            };
            PolicyIncrementalReview::evaluated_in_full(
                registry
                    .policies()
                    .filter(|policy| runnable_ids.contains(&policy.definition().metadata.id))
                    .map(|policy| policy.definition().metadata.id.clone()),
                reason,
            )
        }),
    };
    if let Some(review) = incremental_review.clone() {
        builder.set_incremental(review).map_err(|error| {
            PolicyCoordinatorError::new(format!(
                "failed to retain the incremental reuse review: {error}"
            ))
        })?;
    }
    if let Some(review) = packs_review {
        builder.set_packs(review).map_err(|error| {
            PolicyCoordinatorError::new(format!(
                "failed to retain the pack-activation review: {error}"
            ))
        })?;
    }
    if let Some(review) = baseline_review {
        builder.set_baseline(review).map_err(|error| {
            PolicyCoordinatorError::new(format!(
                "failed to retain the policy baseline review: {error}"
            ))
        })?;
    }
    let mut retained_findings = Vec::new();
    for input in inputs {
        if policy_deadline_reached(cancellation)? {
            deadline_stage.get_or_insert(PolicyExecutionStage::ReportConstruction);
        }
        match input {
            InputOutcome::Diagnostic(diagnostic) => builder
                .register_primary_diagnostic(diagnostic)
                .map_err(|error| {
                    PolicyCoordinatorError::new(format!(
                        "failed to reserve a policy diagnostic skeleton: {error}"
                    ))
                })?,
            InputOutcome::Runnable(policy_id) => {
                let policy = registry
                    .policies()
                    .find(|policy| policy.definition().metadata.id == policy_id)
                    .ok_or_else(|| {
                        PolicyCoordinatorError::new(format!(
                            "runnable policy `{policy_id}` is missing from the registry"
                        ))
                    })?;
                let mut run = runs.remove(&policy_id).ok_or_else(|| {
                    PolicyCoordinatorError::new(format!(
                        "runnable policy `{policy_id}` has no evaluation outcome"
                    ))
                })?;
                retained_findings.append(&mut run.take_findings());
                builder
                    .register_policy(PolicyRuleDescriptor::from_loaded(policy), run)
                    .map_err(|error| {
                        PolicyCoordinatorError::new(format!(
                            "failed to reserve a policy run skeleton: {error}"
                        ))
                    })?;
            }
            InputOutcome::Pending(_) => {
                return Err(PolicyCoordinatorError::new(
                    "internal policy coordinator input remained unresolved",
                ));
            }
        }
    }

    // Retention priority: suppressed/scoped findings first (their omission is
    // a loud audit failure), then unclaimed gating findings, then baselined
    // findings last — their identities are already durably recorded in the
    // baseline review counts, so under pressure they are dropped first.
    retained_findings.sort_by_key(|finding| {
        let priority: u8 = if finding.suppression().is_some() || finding.scope().is_some() {
            0
        } else if finding.baseline().is_none() {
            1
        } else {
            2
        };
        (priority, finding.id())
    });
    let mut suppression_result_omitted = false;
    let mut scope_result_omitted = false;
    let mut baseline_result_omitted = false;
    for finding in retained_findings {
        let policy_id = finding.policy_id().clone();
        let finding_id = finding.id();
        let suppressed = finding.suppression().is_some();
        let baselined = finding.baseline().is_some();
        let finding_scope = finding.scope().cloned();
        let outcome = builder.retain_finding(finding).map_err(|error| {
            PolicyCoordinatorError::new(format!("failed to retain a policy finding: {error}"))
        })?;
        if matches!(outcome, PolicyRetentionOutcome::Omitted { .. }) {
            if suppressed {
                builder
                    .mark_suppression_result_omitted(&policy_id, finding_id)
                    .map_err(|error| {
                        PolicyCoordinatorError::new(format!(
                            "failed to record an omitted suppressed finding: {error}"
                        ))
                    })?;
                suppression_result_omitted = true;
            }
            if baselined {
                builder
                    .mark_baseline_result_omitted(&policy_id, finding_id)
                    .map_err(|error| {
                        PolicyCoordinatorError::new(format!(
                            "failed to record an omitted baselined finding: {error}"
                        ))
                    })?;
                baseline_result_omitted = true;
            }
            if let Some(finding_scope) = finding_scope.as_ref() {
                builder
                    .mark_scope_result_omitted(finding_scope)
                    .map_err(|error| {
                        PolicyCoordinatorError::new(format!(
                            "failed to record an omitted scoped finding: {error}"
                        ))
                    })?;
                scope_result_omitted = true;
            }
        }
    }
    if scope_result_omitted {
        secondary_diagnostics.push(report_diagnostic(
            PolicyReportDiagnosticCode::ScopeAuditRetentionExceeded,
            "one or more scoped finding results exceeded the report retention budget",
            Some(PolicySourceIdentity::new(
                options.scope().source().relative_path(),
            )),
            None,
            Vec::new(),
        )?);
    }
    if suppression_result_omitted {
        secondary_diagnostics.push(report_diagnostic(
            PolicyReportDiagnosticCode::SuppressionAuditRetentionExceeded,
            "one or more applied suppression results exceeded the report retention budget",
            Some(PolicySourceIdentity::new(
                options.suppressions().primary_relative_path(),
            )),
            None,
            Vec::new(),
        )?);
    }
    if baseline_result_omitted {
        secondary_diagnostics.push(report_diagnostic(
            PolicyReportDiagnosticCode::BaselineAuditRetentionExceeded,
            "one or more baselined finding results exceeded the report retention budget",
            Some(PolicySourceIdentity::new(
                options.baseline().source().relative_path(),
            )),
            None,
            Vec::new(),
        )?);
    }
    for diagnostic in secondary_diagnostics {
        builder
            .retain_report_diagnostic(diagnostic)
            .map_err(|error| {
                PolicyCoordinatorError::new(format!(
                    "failed to retain a policy report diagnostic: {error}"
                ))
            })?;
    }

    if policy_deadline_reached(cancellation)? {
        deadline_stage.get_or_insert(PolicyExecutionStage::ReportConstruction);
    }
    // The measured stages always leave through the outcome's side channel.
    // They enter the canonical report only on a deadline, where elapsed time
    // is the reason the run stopped; a successful report stays byte-identical
    // across invocations (#2611).
    let stage_attribution = vec![
        PolicyStageTiming::from_duration(
            PolicyExecutionStage::PolicyRegistration,
            registration_elapsed,
        ),
        PolicyStageTiming::from_duration(
            PolicyExecutionStage::PolicyPreparation,
            preparation_elapsed,
        ),
        PolicyStageTiming::from_duration(
            PolicyExecutionStage::PolicyEvaluation,
            evaluation_elapsed,
        ),
        PolicyStageTiming::from_duration(
            PolicyExecutionStage::ReportConstruction,
            report_started.elapsed(),
        ),
    ];
    if let Some(terminal_stage) = deadline_stage {
        let stage_timings = stage_attribution.clone();
        let total_elapsed_ms = stage_timings.iter().fold(0_u64, |total, timing| {
            total.saturating_add(timing.elapsed_ms())
        });
        let execution = PolicyExecutionMetadata::try_new(
            total_elapsed_ms,
            stage_timings,
            Some(PolicyExecutionTermination::DeadlineExceeded),
            Some(terminal_stage),
            active_policy_id,
            completed_policy_ids,
            pending_policy_ids,
        )
        .map_err(|error| {
            PolicyCoordinatorError::new(format!(
                "failed to record policy execution metadata: {error}"
            ))
        })?;
        builder.set_execution(execution).map_err(|error| {
            PolicyCoordinatorError::new(format!(
                "failed to retain policy execution metadata: {error}"
            ))
        })?;
    }
    let report = builder.finish().map_err(|error| {
        PolicyCoordinatorError::new(format!("failed to finish policy report: {error}"))
    })?;
    let taint_findings = taint.take_public_findings();
    let taint_analysis_results = taint.take_retained_analyses();
    let exit_status = report_exit_status(&report, threshold_exceeded);
    Ok(PolicyBatchOutcome {
        report,
        stage_attribution,
        taint_findings,
        taint_analysis_results,
        exit_status,
        max_retained_report_bytes: batch_budget.max_retained_report_bytes(),
        max_serialized_report_bytes: batch_budget.max_serialized_report_bytes(),
        incremental: incremental_review,
    })
}

/// Where one batch's evaluation units live.
///
/// A persisted workspace publishes into the repository's own analyzer cache,
/// so the next run finds them; an ephemeral one keeps them in this process,
/// which is exactly as long as its store would have lasted anyway. Nothing
/// above this distinction knows which one it is holding.
enum BatchUnitStore {
    Memory(RefCell<InMemoryPolicyUnitStore>),
    Persisted(RefCell<PersistedPolicyUnitStore>),
}

impl BatchUnitStore {
    fn of(workspace: Option<&WorkspaceAnalyzer>) -> Self {
        let persisted = workspace
            .filter(|workspace| workspace.persisted_store_path().is_some())
            .and_then(WorkspaceAnalyzer::store);
        match persisted {
            Some(store) => Self::Persisted(RefCell::new(PersistedPolicyUnitStore::new(
                Arc::clone(store),
            ))),
            None => Self::Memory(RefCell::new(InMemoryPolicyUnitStore::new())),
        }
    }

    fn units(&self) -> &RefCell<dyn PolicyUnitStore> {
        match self {
            Self::Memory(store) => store,
            Self::Persisted(store) => store,
        }
    }

    fn persisted(&self) -> Option<&RefCell<PersistedPolicyUnitStore>> {
        match self {
            Self::Memory(_) => None,
            Self::Persisted(store) => Some(store),
        }
    }

    /// Write every unit this batch published.
    ///
    /// A failure here loses reuse and nothing else -- the cache is derived
    /// data, and the next run recomputes exactly what this one computed -- so
    /// it is reported and the run continues rather than failing a correct
    /// evaluation over a cache write.
    fn flush(&self) {
        let Some(store) = self.persisted() else {
            return;
        };
        match store.borrow_mut().flush() {
            Ok(written) => brokk_bifrost_analysis::profiling::note_with(|| {
                format!("policy.units published={written}")
            }),
            Err(error) => brokk_bifrost_analysis::profiling::note_with(|| {
                format!("policy.units publish_failed={error}")
            }),
        }
    }

    /// Record that this run's base evaluation is complete and reusable.
    fn publish_evaluation(&self, evaluation: &PolicyEvaluationRow) {
        let Some(store) = self.persisted() else {
            return;
        };
        let published = store
            .borrow()
            .store()
            .publish_policy_evaluation(evaluation.clone());
        brokk_bifrost_analysis::profiling::note_with(|| match &published {
            Ok(()) => "policy.units base_evaluation=published".to_string(),
            Err(error) => format!("policy.units base_evaluation_failed={error}"),
        });
    }
}

/// Everything a base evaluation was asked, beyond the tree it read.
///
/// The tree id fixes the bytes; these fix the question. Two runs that agree on
/// all of them would produce the same base findings, which is what licenses
/// replaying one run's answer for the other.
fn base_evaluation_key(
    policies: &[&LoadedPolicy],
    options: &PolicyEvaluationOptions,
    batch_budget: PolicyBatchBudget,
    registry_limits: PolicyRegistryLimits,
    inputs: WorkspaceUnitInputs,
) -> PolicyEvaluationRowKey {
    let mut policy_set = policies
        .iter()
        .map(|policy| {
            format!(
                "{}\u{1}{}\u{1}{}",
                policy.definition().metadata.id,
                StableDigest::from_array(*policy.semantic_hash().as_bytes()),
                StableDigest::from_array(*policy.source_hash().as_bytes()),
            )
        })
        .collect::<Vec<_>>();
    policy_set.sort();
    // The base's own options, not the head's: it evaluates with the head's
    // suppression, scope and gate configuration deliberately stripped, and the
    // budgets and registry limits it inherits decide what it retains.
    let base_options = format!(
        "{:?}\u{1}{}\u{1}{batch_budget:?}\u{1}{registry_limits:?}",
        options.evaluation_date(),
        options.require_explicit_schema_versions(),
    );
    PolicyEvaluationRowKey {
        base_tree_oid: String::new(),
        policy_set_digest: StableDigest::sha256(policy_set.join("\u{2}")).to_string(),
        options_digest: StableDigest::sha256(base_options).to_string(),
        configuration_fingerprint: inputs.configuration().to_string(),
        active_model_set_hash: inputs.models().to_string(),
        engine_epoch: inputs.epoch().to_string(),
    }
}

/// Take the findings of a base evaluation an earlier run already completed,
/// without exporting, building or evaluating the base.
///
/// The recorded identities are that evaluation's whole answer, for every
/// policy family: the diff join needs the identities the base concluded, not
/// the units that produced some of them. A taint policy, which publishes no
/// unit at all, is served here exactly as a match policy is.
///
/// `None` means there is nothing recorded and the caller must evaluate the
/// base: no persisted store, no row for this exact question, or a head whose
/// difference from the base cannot be established from the store alone. Every
/// one of those is reported, because "the base was evaluated again" is a fact
/// a reader needs to explain a slow run.
fn reuse_persisted_diff_baseline(
    head_root: &Path,
    head_workspace: &WorkspaceAnalyzer,
    revision: &str,
    policies: &[&LoadedPolicy],
    store: &BatchUnitStore,
    key: &PolicyEvaluationRowKey,
) -> Option<PolicyDiffBaselineOutcome> {
    let persisted = store.persisted()?;
    let subtree = match resolve_revision_subtree(head_root, revision) {
        Ok(subtree) => subtree,
        Err(error) => {
            // The cold path resolves the same revision and reports the failure
            // in its own words, which is the one place this error belongs.
            brokk_bifrost_analysis::profiling::note_with(|| {
                format!("policy.units base_unresolved={error}")
            });
            return None;
        }
    };
    let key = PolicyEvaluationRowKey {
        base_tree_oid: subtree.tree_id().to_string(),
        ..key.clone()
    };
    let evaluation = match persisted.borrow().store().policy_evaluation_for_key(&key) {
        Ok(Some(evaluation)) => evaluation,
        Ok(None) => return None,
        Err(error) => {
            brokk_bifrost_analysis::profiling::note_with(|| {
                format!("policy.units base_lookup_failed={error}")
            });
            return None;
        }
    };
    // The head verifies the units it reuses against what moved since the base.
    // The base's own facts come from the store, because the base workspace
    // this would otherwise need is exactly what is not being built.
    let changed = ChangedFacts::from_committed_tree(head_workspace, subtree.blobs(), &|blob| {
        subtree.source(blob)
    });
    if !changed.is_complete() {
        let (unenumerated, without_index) = changed.incompleteness();
        brokk_bifrost_analysis::profiling::note_with(|| {
            format!(
                "policy.units base_facts_incomplete unenumerated={unenumerated:?} \
                 languages_without_index={without_index:?}"
            )
        });
        return None;
    }
    // The stored identities are keyed by the policy identifier the base ran,
    // and the evaluation key covers the policy set exactly, so every recorded
    // identifier is one of this run's policies. Reading the map through the
    // runnable policies keeps the head's own `PolicyId` values and needs no
    // reparse of a stored string.
    let mut recorded: HashMap<&str, &Vec<[u8; 32]>> = HashMap::new();
    for (policy_id, findings) in &evaluation.identities {
        recorded.insert(policy_id.as_str(), findings);
    }
    let mut identities: HashMap<PolicyId, HashSet<PolicyFindingId>> = HashMap::new();
    for policy in policies {
        let policy_id = &policy.definition().metadata.id;
        // A policy with no recorded identity found nothing at the base, which
        // is a fact rather than a gap: the row is written for the whole policy
        // set at once.
        let Some(findings) = recorded.remove(policy_id.as_str()) else {
            continue;
        };
        identities.insert(
            policy_id.clone(),
            findings
                .iter()
                .map(|finding| PolicyFindingId::from_bytes(*finding))
                .collect(),
        );
    }
    debug_assert!(
        recorded.is_empty(),
        "a base evaluation records identities for the policy set its key names: {recorded:?}"
    );
    Some(PolicyDiffBaselineOutcome {
        baseline: PolicyDiffBaseline {
            requested_revision: revision.to_string(),
            resolved_commit: evaluation.resolved_commit.clone(),
            identities,
            unreliable_detail: None,
        },
        changed: Some(changed),
        publication: None,
        state: IncrementalBaseState::Reused,
    })
}

/// What the base evaluation produced for the head that follows it.
///
/// `changed` is what moved between the base workspace and the head, computed
/// while both analyzers are alive and retained after the base analyzer is
/// dropped. `None` means the base never built a workspace -- an unreliable or
/// empty base -- so the head has nothing published to verify against and
/// evaluates exactly as a run without a diff base does.
struct PolicyDiffBaselineOutcome {
    baseline: PolicyDiffBaseline,
    changed: Option<ChangedFacts>,
    /// What to record about this base evaluation once the run completes, or
    /// `None` when there is nothing a later run could replay: a base that
    /// published no units, a base that was replayed rather than evaluated, or
    /// an ephemeral workspace whose store outlives nothing.
    publication: Option<PolicyEvaluationRow>,
    /// How this run obtained the base, for the review.
    state: IncrementalBaseState,
}

impl PolicyDiffBaselineOutcome {
    /// A base that produced no workspace, and therefore no units.
    const fn without_units(baseline: PolicyDiffBaseline) -> Self {
        Self {
            baseline,
            changed: None,
            publication: None,
            state: IncrementalBaseState::Evaluated,
        }
    }
}

/// Base-revision evaluation summary consumed by the diff join.
///
/// `identities` holds the strong finding identities present at the base
/// revision, keyed by policy so the per-run join is one set lookup. When
/// `unreliable_detail` is present the base evaluation was unreliable, the
/// identity map is empty, and diff gating degrades to full gating.
struct PolicyDiffBaseline {
    requested_revision: String,
    resolved_commit: String,
    identities: HashMap<PolicyId, HashSet<PolicyFindingId>>,
    unreliable_detail: Option<String>,
}

/// Build the analyzer over the exported base revision, with the very
/// configuration the head workspace was built with.
///
/// The analyzer configuration selects dependency discovery, dispatch expansion
/// and per-language behavior, and it is folded into every content identity the
/// build publishes. A base built with a configuration of its own therefore
/// answers a different question than the head whose findings it is joined
/// with, and a finding that persists could be reported as fixed plus new. A
/// head workspace assembled without a build context was never built from a
/// configuration and behaves as the defaults describe, so the base takes the
/// same defaults and parity still holds.
///
/// The base analyzes the whole exported revision through the *head*
/// repository's shared content-addressed cache: the export's own root is a
/// self-deleting temp directory that no cache funnel can resolve, while the
/// revision's blobs are immutable committed content whose parsed facts the
/// worktree build and every later base run reuse (#2769). The caller must keep
/// `export` alive for the whole lifetime of the returned workspace.
///
/// The configuration is returned with the workspace because base semantic-pack
/// activation must use the same one.
fn build_diff_base_workspace(
    export: &RevisionExport,
    head_root: &Path,
    head_workspace: &WorkspaceAnalyzer,
) -> Result<(RevisionWorkspace, AnalyzerConfig), String> {
    let config = head_workspace.config().cloned().unwrap_or_default();
    let base = export.build_workspace(head_root, config.clone())?;
    debug_assert_eq!(
        base.workspace().config(),
        Some(&config),
        "a revision workspace must report the configuration it was built with"
    );
    Ok((base, config))
}

/// Materialize the base revision and evaluate the head's policy sources
/// against it, collecting the strong finding identities and the base run's
/// reliability verdict.
///
/// An unresolvable revision or a workspace outside a git repository is an
/// error: an unresolvable base is an unreliable diff request, never a silent
/// full run. An unreliable base *evaluation* instead degrades, so a broken
/// base cannot mask new findings.
#[allow(clippy::too_many_arguments)]
fn evaluate_policy_diff_baseline(
    head_root: &Path,
    head_workspace: Option<&WorkspaceAnalyzer>,
    revision: &str,
    head_options: &PolicyEvaluationOptions,
    base_inputs: Vec<PolicyEvaluationInput>,
    batch_budget: PolicyBatchBudget,
    registry_limits: PolicyRegistryLimits,
    policies: &[&LoadedPolicy],
    evaluation_key: Option<PolicyEvaluationRowKey>,
    unit_store: Option<&BatchUnitStore>,
    cancellation: Option<&CancellationToken>,
) -> Result<PolicyDiffBaselineOutcome, PolicyCoordinatorError> {
    let export = export_revision(head_root, revision).map_err(|error| {
        PolicyCoordinatorError::new(format!(
            "failed to materialize diff base `{revision}`: {error}"
        ))
    })?;
    if base_inputs.is_empty() {
        return Ok(PolicyDiffBaselineOutcome::without_units(PolicyDiffBaseline {
            requested_revision: revision.to_string(),
            resolved_commit: export.commit_id().to_string(),
            identities: HashMap::new(),
            unreliable_detail: Some(
                "the head evaluation has no runnable policy, so the base revision was not evaluated"
                    .to_string(),
            ),
        }));
    }
    // A runnable policy is what puts an input in `base_inputs`, and a runnable
    // policy needed an analyzer snapshot to close over, so a base with anything
    // to evaluate always has a head workspace whose configuration it copies.
    let head_workspace = head_workspace
        .expect("a runnable policy input implies the head analyzer workspace that closed it");
    let (base, base_analyzer_config) =
        build_diff_base_workspace(&export, head_root, head_workspace).map_err(|error| {
            PolicyCoordinatorError::new(format!(
                "failed to build the diff base analyzer for `{revision}`: {error}"
            ))
        })?;
    // The base activates the packs its own committed document names and the
    // reviewed semantic models its own tree checks in, the same way it loads
    // its own committed suppressions (#1868, #2493). Both sides of the
    // comparison therefore see the same model universe, so a model added or
    // removed in the diff shows up as changed findings instead of as noise.
    // The catalog is machine-local infrastructure, not revision state, so its
    // configured path resolves beneath the head workspace, where installed
    // packs and generated productions already live; the reviewed models come
    // from the exported base tree, because they are revision state. A
    // malformed base document is not handled here: the base evaluation loads
    // the same document, reports `packs-load-failed`, and the baseline
    // degrades through the standard unreliability path.
    {
        let base_packs = load_workspace_packs_config_at(export.root()).ok().flatten();
        let uncancelled = CancellationToken::default();
        if let Err(error) = activate_workspace_semantic_sources(
            base.workspace(),
            &base_analyzer_config,
            WorkspaceActivationSources {
                catalog_root: head_root,
                workspace_model_root: Some(export.root()),
                config: base_packs.as_ref(),
                intrinsic_shipped_models: base_activates_shipped_models(head_workspace),
            },
            cancellation.unwrap_or(&uncancelled),
        ) {
            return Ok(PolicyDiffBaselineOutcome::without_units(
                PolicyDiffBaseline {
                    requested_revision: revision.to_string(),
                    resolved_commit: export.commit_id().to_string(),
                    identities: HashMap::new(),
                    unreliable_detail: Some(format!(
                        "base pack activation failed, so base findings would misstate the configured \
                     external surface: {error}"
                    )),
                },
            ));
        }
    }
    // The base run needs raw identities only: no diff base (which would
    // recurse), no gating threshold, and the head's suppression and scope
    // configuration deliberately not forwarded.
    let base_options = PolicyEvaluationOptions::new(head_options.evaluation_date())
        .with_required_schema_versions(head_options.require_explicit_schema_versions());
    // The base evaluates unit by unit for the same reason the head does: a
    // whole execution cannot attribute its reads to seed files, so unit-wise
    // execution is the only way to publish a per-unit read set at all. Its
    // store starts empty, so every unit is computed here and published; the
    // changed facts it verifies against are the base compared with itself,
    // which states exactly that nothing moved.
    let base_changed =
        unit_store.map(|_| ChangedFacts::between(base.workspace(), base.workspace()));
    let base_incremental = match (unit_store, base_changed.as_ref()) {
        (Some(store), Some(changed)) => Some(PolicyIncrementalContext::new(
            store.units(),
            base.workspace(),
            changed,
            WorkspaceUnitInputs::of(
                base.workspace(),
                base.workspace()
                    .analyzer()
                    .active_semantic_model_snapshot()
                    .as_deref(),
            ),
            IncrementalBaseState::Evaluated,
        )),
        _ => None,
    };
    let outcome = evaluate_policy_inputs_with_limits(
        export.root(),
        &base_inputs,
        &base_options,
        batch_budget,
        registry_limits,
        Some(base.workspace()),
        None,
        None,
        None,
        base_incremental.as_ref(),
        cancellation,
    )?;
    let report = outcome.report();
    if outcome.exit_status() == POLICY_EXIT_UNRELIABLE {
        // An unreliable base classified nothing, so nothing it published may
        // be reused: the head must not verify units against a base whose own
        // evaluation the run refuses to trust.
        return Ok(PolicyDiffBaselineOutcome::without_units(
            PolicyDiffBaseline {
                requested_revision: revision.to_string(),
                resolved_commit: export.commit_id().to_string(),
                identities: HashMap::new(),
                unreliable_detail: Some(diff_base_unreliable_detail(report)),
            },
        ));
    }
    let mut identities: HashMap<PolicyId, HashSet<PolicyFindingId>> = HashMap::new();
    for run in report.runs() {
        for finding in run.findings() {
            // Weak identities are snapshot-local by construction and can never
            // equal a head identity, so only strong ones enter the join set.
            if finding.identity_stability() == FindingIdentityStability::Strong {
                identities
                    .entry(run.policy_id().clone())
                    .or_default()
                    .insert(finding.id());
            }
        }
    }
    // Computed here, while both analyzers are alive: the head verifies its
    // units against it after the base analyzer and its export are gone.
    let changed = head_workspace_changed_facts(unit_store, base.workspace(), head_workspace);
    let publication =
        base_incremental
            .as_ref()
            .zip(evaluation_key)
            .and_then(|(incremental, key)| {
                base_evaluation_publication(
                    incremental,
                    key,
                    export.tree_id(),
                    export.commit_id(),
                    report,
                    &identities,
                    policies,
                )
            });
    Ok(PolicyDiffBaselineOutcome {
        baseline: PolicyDiffBaseline {
            requested_revision: revision.to_string(),
            resolved_commit: export.commit_id().to_string(),
            identities,
            unreliable_detail: None,
        },
        changed,
        publication,
        state: IncrementalBaseState::Evaluated,
    })
}

/// What this base evaluation records for a later run to substitute for
/// evaluating the base again, or `None` when it may not be substituted.
///
/// The record is the identities: the head joins against them and never against
/// the base's units, so a policy family that publishes no unit is recorded
/// exactly as one that publishes forty. The units ride along so the *head* can
/// reuse the per-file work behind them, and so the age sweep knows they belong
/// to a live evaluation.
///
/// Every runnable policy must have run exhaustively. A truncated or
/// inconclusive run found some of the base's findings rather than all of them,
/// and a later run joining against that set would report a persisting finding
/// as new. The batch's own exit status does not answer this: a run that found
/// something exits on the finding gate whatever its completion tier, so the
/// tier is read per policy here.
fn base_evaluation_publication(
    incremental: &PolicyIncrementalContext<'_>,
    key: PolicyEvaluationRowKey,
    tree_id: brokk_bifrost_analysis::analyzer::Oid,
    resolved_commit: &str,
    report: &PolicyReportDocument,
    identities: &HashMap<PolicyId, HashSet<PolicyFindingId>>,
    policies: &[&LoadedPolicy],
) -> Option<PolicyEvaluationRow> {
    let completions = report
        .runs()
        .iter()
        .map(|run| (run.policy_id(), run.completion()))
        .collect::<HashMap<_, _>>();
    for policy in policies {
        let policy_id = &policy.definition().metadata.id;
        let exhaustive = completions
            .get(policy_id)
            .is_some_and(|completion| completion.is_exhaustive());
        if !exhaustive {
            brokk_bifrost_analysis::profiling::note_with(|| {
                format!(
                    "policy.units base_unpublishable policy={policy_id} completion={:?}",
                    completions.get(policy_id)
                )
            });
            return None;
        }
    }
    Some(PolicyEvaluationRow {
        key: PolicyEvaluationRowKey {
            base_tree_oid: tree_id.to_string(),
            ..key
        },
        resolved_commit: resolved_commit.to_string(),
        identities: sorted_evaluation_identities(identities),
        units: incremental
            .published_units()
            .iter()
            .map(|(policy_id, keys)| {
                (
                    policy_id.to_string(),
                    keys.iter().map(row_key).collect::<Vec<_>>(),
                )
            })
            .collect(),
    })
}

/// The identity map as rows, in one order.
///
/// Both levels are sorted because the row is written from a hash map and two
/// runs of the same base must write the same bytes; the store's own key makes
/// the set the identity, but a stable order is what makes the write itself
/// comparable.
fn sorted_evaluation_identities(
    identities: &HashMap<PolicyId, HashSet<PolicyFindingId>>,
) -> Vec<(String, Vec<[u8; 32]>)> {
    let mut rows = identities
        .iter()
        .map(|(policy_id, findings)| {
            let mut findings = findings
                .iter()
                .map(|finding| *finding.as_bytes())
                .collect::<Vec<_>>();
            findings.sort_unstable();
            (policy_id.to_string(), findings)
        })
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| left.0.cmp(&right.0));
    rows
}

/// Whether the base activates the shipped semantic models.
///
/// It mirrors the head, for the reason every other base input mirrors it: the
/// base must see the head's universe or the two sides classify against
/// different worlds. A head the coordinator built activates them and publishes
/// an active snapshot; a head a host supplied activated whatever its host
/// chose, and a host that activated nothing has no snapshot at all -- so a
/// base that activated the shipped models would model calls the head never
/// modelled, and every finding that depends on one would classify as fixed
/// plus new.
fn base_activates_shipped_models(head_workspace: &WorkspaceAnalyzer) -> bool {
    head_workspace
        .analyzer()
        .active_semantic_model_snapshot()
        .is_some()
}

/// What moved between the base the units were published from and the head.
///
/// `None` where no store exists, because nothing was published and the head
/// has nothing to verify.
fn head_workspace_changed_facts(
    unit_store: Option<&BatchUnitStore>,
    base: &WorkspaceAnalyzer,
    head: &WorkspaceAnalyzer,
) -> Option<ChangedFacts> {
    unit_store.map(|_| ChangedFacts::between(base, head))
}

/// Summarize why a base evaluation was unreliable, for the degradation
/// diagnostic. The composed text is bounded later by `safe_report_text`.
fn diff_base_unreliable_detail(report: &PolicyReportDocument) -> String {
    let mut parts = Vec::new();
    if let Some(termination) = report.execution().termination() {
        parts.push(format!("execution terminated ({termination:?})"));
    }
    if !report.diagnostics().is_empty() {
        let codes = report
            .diagnostics()
            .iter()
            .map(PolicyReportDiagnostic::code)
            .collect::<Vec<_>>();
        parts.push(format!("base report diagnostics {codes:?}"));
    }
    if report.diagnostics_truncated() {
        parts.push("base report diagnostics were truncated".to_string());
    }
    for run in report.runs() {
        if !run.completion().is_reliable() || !run.completion().is_exhaustive() {
            parts.push(format!(
                "policy {} completed {:?}",
                run.policy_id(),
                run.completion()
            ));
        }
    }
    assert!(
        !parts.is_empty(),
        "an unreliable base evaluation always has a termination, diagnostic, or non-exhaustive run"
    );
    parts.join("; ")
}

/// Join the head runs against the base identities and attach a diff decision
/// to every retained finding. A degraded baseline attaches nothing.
///
/// This is the diff sibling of [`apply_policy_suppressions`]: same
/// `(policy_id, finding_id)` key, same attachment pattern, one top-level
/// review. Base identities no head finding consumed become the fixed list.
fn apply_policy_diff(
    baseline: &PolicyDiffBaseline,
    runs: &mut HashMap<PolicyId, PolicyRun>,
) -> Result<PolicyDiffReview, PolicyCoordinatorError> {
    if baseline.unreliable_detail.is_some() {
        return Ok(PolicyDiffReview::new(
            baseline.requested_revision.clone(),
            baseline.resolved_commit.clone(),
            true,
            0,
            0,
            Vec::new(),
            0,
        ));
    }
    let mut matched: HashMap<&PolicyId, HashSet<PolicyFindingId>> = HashMap::new();
    let mut new_count = 0_u64;
    let mut persisting_count = 0_u64;
    for (policy_id, run) in runs.iter_mut() {
        let base_ids = baseline.identities.get(policy_id);
        for finding in run.findings_mut() {
            let weak_identity = finding.identity_stability() != FindingIdentityStability::Strong;
            let persisting = !weak_identity
                && base_ids.is_some_and(|identities| identities.contains(&finding.id()));
            let disposition = if persisting {
                matched.entry(policy_id).or_default().insert(finding.id());
                persisting_count = persisting_count.saturating_add(1);
                FindingDiffDisposition::Persisting
            } else {
                new_count = new_count.saturating_add(1);
                FindingDiffDisposition::New
            };
            finding
                .attach_diff(PolicyFindingDiff::new(disposition, weak_identity))
                .map_err(|error| {
                    PolicyCoordinatorError::new(format!(
                        "failed to attach the diff decision for policy {policy_id} finding {}: {error}",
                        finding.id()
                    ))
                })?;
        }
    }
    // Collect every unmatched identity before truncating. The baseline is a
    // hash map, so taking the first `MAX_DIFF_FIXED_FINDINGS` in iteration
    // order would retain a process-dependent subset once more than that many
    // identities are fixed. Sorting first makes the retained subset the 256
    // smallest identities under the report's own ordering, which is the same
    // in every process.
    let mut unmatched: Vec<(&PolicyId, PolicyFindingId)> = Vec::new();
    for (policy_id, identities) in &baseline.identities {
        let consumed = matched.get(policy_id);
        for finding_id in identities {
            if consumed.is_some_and(|ids| ids.contains(finding_id)) {
                continue;
            }
            unmatched.push((policy_id, *finding_id));
        }
    }
    let fixed_count = u64::try_from(unmatched.len()).expect("fixed identity count fits u64");
    unmatched.sort_unstable_by(
        |(left_policy, left_finding), (right_policy, right_finding)| {
            (left_policy.as_str(), left_finding).cmp(&(right_policy.as_str(), right_finding))
        },
    );
    unmatched.truncate(MAX_DIFF_FIXED_FINDINGS);
    let fixed = unmatched
        .into_iter()
        .map(|(policy_id, finding_id)| PolicyDiffFixedFinding::new(policy_id.clone(), finding_id))
        .collect::<Vec<_>>();
    Ok(PolicyDiffReview::new(
        baseline.requested_revision.clone(),
        baseline.resolved_commit.clone(),
        false,
        new_count,
        persisting_count,
        fixed,
        fixed_count,
    ))
}

/// The workspace-relative paths one run actually analyzed.
///
/// This is the oracle that separates a suppression identity that rotated under
/// an edit from one whose file this run never saw (#2418). It is deliberately
/// the analyzed set rather than on-disk existence: a file the analyzer skipped
/// can no more produce a finding than one that is absent, so treating it as
/// present would gate the run on a record it cannot possibly resolve.
///
/// Built at most once per run, and only when some record actually needs it.
struct AnalyzedPaths(HashSet<Box<str>>);

impl AnalyzedPaths {
    fn collect(workspace: Option<&WorkspaceAnalyzer>) -> Self {
        let Some(workspace) = workspace else {
            return Self(HashSet::new());
        };
        Self(
            workspace
                .analyzer()
                .analyzed_files()
                .iter()
                .filter_map(|file| {
                    WorkspaceRelativePath::try_from_path(file.rel_path())
                        .ok()
                        .map(|path| path.as_str().into())
                })
                .collect(),
        )
    }

    fn contains(&self, path: &WorkspaceRelativePath) -> bool {
        self.0.contains(path.as_str())
    }
}

/// Unclaimed identities this run reported for `policy_id` in `path`.
///
/// A record orphaned by rotation still has its finding in the run under a new
/// identity, so these are its re-key targets. Identities another record in the
/// same document already claims are excluded: offering an identity that is
/// already accepted elsewhere would invite a duplicate record.
fn rekey_candidates(
    run: &PolicyRun,
    path: &WorkspaceRelativePath,
    claimed: &HashSet<PolicyFindingId>,
) -> Vec<PolicyFindingId> {
    run.findings()
        .iter()
        .filter(|finding| {
            finding.identity_stability() == FindingIdentityStability::Strong
                && finding.primary().path() == path.as_str()
                && !claimed.contains(&finding.id())
        })
        .map(PolicyFinding::id)
        .take(MAX_SUPPRESSION_REKEY_CANDIDATES)
        .collect()
}

fn apply_policy_suppressions(
    document: &PolicySuppressionDocument,
    evaluation_date: PolicyEvaluationDate,
    registry: &PolicyRegistry,
    workspace: Option<&WorkspaceAnalyzer>,
    runs: &mut HashMap<PolicyId, PolicyRun>,
) -> Result<Vec<PolicySuppressionReview>, PolicyCoordinatorError> {
    let policy_hashes = registry
        .policies()
        .map(|policy| {
            (
                policy.definition().metadata.id.clone(),
                policy.semantic_hash(),
            )
        })
        .collect::<HashMap<_, _>>();
    let claimed_identities = document
        .suppressions()
        .iter()
        .map(PolicySuppressionRecord::finding_id)
        .collect::<HashSet<_>>();
    let mut analyzed_paths = None;
    let mut reviews = Vec::with_capacity(document.suppressions().len());
    for record in document.suppressions() {
        let policy_hash_state = PolicySuppressionPolicyHashState::compare(
            record.policy_hash_at_acceptance(),
            policy_hashes.get(record.policy_id()).copied(),
        );
        let temporal_state = PolicySuppressionTemporalState::for_record(record, evaluation_date);
        let (match_state, finding_index) = match runs.get(record.policy_id()) {
            Some(run) => {
                let finding_index = run
                    .findings()
                    .iter()
                    .position(|finding| finding.id() == record.finding_id());
                let match_state = match finding_index.map(|index| &run.findings()[index]) {
                    Some(finding)
                        if finding.identity_stability() == FindingIdentityStability::Strong =>
                    {
                        PolicySuppressionMatchState::StrongFinding
                    }
                    Some(_) => PolicySuppressionMatchState::CurrentFindingNotStrong,
                    None if run.completion().is_exhaustive() => {
                        PolicySuppressionMatchState::FindingAbsent
                    }
                    None => PolicySuppressionMatchState::PolicyIncomplete,
                };
                (match_state, finding_index)
            }
            None => (PolicySuppressionMatchState::PolicyNotEvaluated, None),
        };
        let (orphan_state, candidates) =
            if match_state == PolicySuppressionMatchState::FindingAbsent {
                match record.path() {
                    None => (PolicySuppressionOrphanState::PathUnrecorded, Vec::new()),
                    Some(path) => {
                        let analyzed =
                            analyzed_paths.get_or_insert_with(|| AnalyzedPaths::collect(workspace));
                        if analyzed.contains(path) {
                            let candidates =
                                runs.get(record.policy_id()).map_or_else(Vec::new, |run| {
                                    rekey_candidates(run, path, &claimed_identities)
                                });
                            (PolicySuppressionOrphanState::Orphaned, candidates)
                        } else {
                            (PolicySuppressionOrphanState::PathNotAnalyzed, Vec::new())
                        }
                    }
                }
            } else {
                (PolicySuppressionOrphanState::Resolved, Vec::new())
            };
        let review = PolicySuppressionReview::new(
            record,
            match_state,
            temporal_state,
            policy_hash_state,
            orphan_state,
            candidates,
        );
        if let (Some(finding_index), Some(suppression)) =
            (finding_index, review.finding_suppression())
        {
            let run = runs.get_mut(record.policy_id()).ok_or_else(|| {
                PolicyCoordinatorError::new(format!(
                    "suppression join lost policy run {}",
                    record.policy_id()
                ))
            })?;
            run.findings_mut()[finding_index]
                .attach_suppression(suppression)
                .map_err(|error| {
                    PolicyCoordinatorError::new(format!(
                        "failed to attach suppression for policy {} finding {}: {error}",
                        record.policy_id(),
                        record.finding_id()
                    ))
                })?;
        }
        reviews.push(review);
    }
    Ok(reviews)
}

fn apply_policy_scope(
    document: &PolicyScopeDocument,
    runs: &mut HashMap<PolicyId, PolicyRun>,
) -> Result<Vec<PolicyScopeReview>, PolicyCoordinatorError> {
    // Category membership is a built-in pack manifest concept; repository
    // policies have no category and match only via policy_ids or an
    // all-policies entry.
    let policy_categories = match super::builtin::built_in_policy_catalog() {
        Ok(catalog) => catalog
            .document()
            .packs
            .iter()
            .flat_map(|pack| pack.policies.iter())
            .filter_map(|entry| {
                let id = PolicyId::new(&entry.id).ok()?;
                let category = PolicyCategoryId::new(&entry.category).ok()?;
                Some((id, category))
            })
            .collect::<HashMap<_, _>>(),
        Err(_) => HashMap::new(),
    };
    let mut reviews = Vec::with_capacity(document.scopes().len());
    for entry in document.scopes() {
        let mut matched_findings = 0_u64;
        for (policy_id, run) in runs.iter_mut() {
            let categories = policy_categories
                .get(policy_id)
                .map(std::slice::from_ref)
                .unwrap_or_default();
            for finding in run.findings_mut() {
                if finding.suppression().is_some() || finding.scope().is_some() {
                    continue;
                }
                if !entry.matches(finding.primary().path(), policy_id, categories) {
                    continue;
                }
                finding
                    .attach_scope(entry.finding_scope())
                    .map_err(|error| {
                        PolicyCoordinatorError::new(format!(
                            "failed to attach scope for policy {policy_id} finding {}: {error}",
                            finding.id()
                        ))
                    })?;
                matched_findings = matched_findings.saturating_add(1);
            }
        }
        reviews.push(PolicyScopeReview::new(entry, matched_findings));
    }
    Ok(reviews)
}

/// Join the baseline document against the head runs and attach an accepted
/// decision to every strong finding not already claimed by a suppression or
/// scope decision.
///
/// This is the bulk sibling of [`apply_policy_suppressions`]: the same
/// `(policy_id, finding_id)` key and attachment pattern, but the join builds
/// one id index per policy so a 100k-entry document stays linear, and the
/// full entry-review vector is folded into bounded counts by the caller.
fn apply_policy_baseline(
    document: &PolicyBaselineDocument,
    registry: &PolicyRegistry,
    runs: &mut HashMap<PolicyId, PolicyRun>,
) -> Result<Vec<PolicyBaselineEntryReview>, PolicyCoordinatorError> {
    let policy_hashes = registry
        .policies()
        .map(|policy| {
            (
                policy.definition().metadata.id.clone(),
                policy.semantic_hash(),
            )
        })
        .collect::<HashMap<_, _>>();
    let mut reviews = Vec::with_capacity(document.entry_count());
    for record in document.policies() {
        let policy_hash_state = PolicySuppressionPolicyHashState::compare(
            record.policy_hash_at_acceptance(),
            policy_hashes.get(record.policy_id()).copied(),
        );
        let Some(run) = runs.get_mut(record.policy_id()) else {
            reviews.extend(record.finding_ids().iter().map(|finding_id| {
                PolicyBaselineEntryReview::new(
                    record.policy_id().clone(),
                    *finding_id,
                    PolicyBaselineMatchState::PolicyNotEvaluated,
                    policy_hash_state,
                )
            }));
            continue;
        };
        let index_by_id = run
            .findings()
            .iter()
            .enumerate()
            .map(|(index, finding)| (finding.id(), index))
            .collect::<HashMap<_, _>>();
        let exhaustive = run.completion().is_exhaustive();
        for finding_id in record.finding_ids() {
            let match_state = match index_by_id.get(finding_id) {
                Some(&index) => {
                    let finding = &run.findings()[index];
                    if finding.identity_stability() != FindingIdentityStability::Strong {
                        PolicyBaselineMatchState::CurrentFindingNotStrong
                    } else if finding.suppression().is_some() || finding.scope().is_some() {
                        PolicyBaselineMatchState::FindingClaimed
                    } else {
                        run.findings_mut()[index]
                            .attach_baseline(PolicyFindingBaseline::new(
                                document,
                                policy_hash_state,
                            ))
                            .map_err(|error| {
                                PolicyCoordinatorError::new(format!(
                                    "failed to attach the baseline decision for policy {} finding {finding_id}: {error}",
                                    record.policy_id()
                                ))
                            })?;
                        PolicyBaselineMatchState::StrongFinding
                    }
                }
                None if exhaustive => PolicyBaselineMatchState::FindingAbsent,
                None => PolicyBaselineMatchState::PolicyIncomplete,
            };
            reviews.push(PolicyBaselineEntryReview::new(
                record.policy_id().clone(),
                *finding_id,
                match_state,
                policy_hash_state,
            ));
        }
    }
    Ok(reviews)
}

fn open_policy_workspace_root(
    root: &Path,
) -> Result<(PathBuf, WorkspaceRoot), PolicyCoordinatorError> {
    let root = root.canonicalize().map_err(|error| {
        PolicyCoordinatorError::new(format!(
            "failed to resolve policy workspace root {}: {error}",
            root.display()
        ))
    })?;
    let workspace = WorkspaceRoot::open(&root).map_err(|error| {
        PolicyCoordinatorError::new(format!(
            "failed to open policy workspace root {}: {error}",
            root.display()
        ))
    })?;
    Ok((root, workspace))
}

fn check_policy_cancellation(
    cancellation: Option<&CancellationToken>,
) -> Result<(), PolicyCoordinatorError> {
    let _ = policy_deadline_reached(cancellation)?;
    Ok(())
}

fn policy_deadline_reached(
    cancellation: Option<&CancellationToken>,
) -> Result<bool, PolicyCoordinatorError> {
    let Some(cancellation) = cancellation else {
        return Ok(false);
    };
    if !cancellation.is_cancelled() {
        return Ok(false);
    }
    if cancellation.is_timed_out() {
        return Ok(true);
    }
    Err(PolicyCoordinatorError::new("policy evaluation cancelled"))
}

fn prepare_input(
    root: &WorkspaceRoot,
    path: &Path,
) -> Result<InputOutcome, PolicyCoordinatorError> {
    let requested_source = requested_source_identity(path);
    if let Err(error) = validate_policy_source_identity(&requested_source) {
        return Ok(InputOutcome::Diagnostic(
            invalid_source_identity_diagnostic(&requested_source, error)?,
        ));
    }
    match read_rqlp_document(root, path) {
        Ok(loaded) => {
            let source = PolicySourceIdentity::new(loaded.workspace_path().as_str());
            if let Err(error) = validate_policy_source_identity(&source) {
                return Ok(InputOutcome::Diagnostic(
                    invalid_source_identity_diagnostic(&source, error)?,
                ));
            }
            let (_, document, parsed) = loaded.into_parts();
            prepare_parsed_input(source, document.source().to_string(), parsed.document())
        }
        Err(error) => Ok(InputOutcome::Diagnostic(document_load_diagnostic(
            path, &error,
        )?)),
    }
}

fn prepare_source_input(
    source_identity: PolicySourceIdentity,
    source: &str,
) -> Result<InputOutcome, PolicyCoordinatorError> {
    if let Err(error) = validate_policy_source_identity(&source_identity) {
        return Ok(InputOutcome::Diagnostic(
            invalid_source_identity_diagnostic(&source_identity, error)?,
        ));
    }

    match parse_rqlp_source(source, source_identity.clone()) {
        Ok(parsed) => prepare_parsed_input(source_identity, source.to_owned(), parsed.document()),
        Err(error) => Ok(InputOutcome::Diagnostic(source_diagnostic(
            source_identity,
            &error.diagnostic,
        )?)),
    }
}

fn prepare_parsed_input(
    source: PolicySourceIdentity,
    bytes: String,
    document: &RqlpDocument,
) -> Result<InputOutcome, PolicyCoordinatorError> {
    match document {
        RqlpDocument::Policy { definition } => Ok(InputOutcome::Pending(PreparedPolicy {
            source,
            bytes,
            policy_id: definition.metadata.id.clone(),
        })),
        RqlpDocument::Endpoint { definition } => Ok(InputOutcome::Diagnostic(report_diagnostic(
            PolicyReportDiagnosticCode::NotExecutableEndpoint,
            format!(
                "endpoint `{}` is a reusable dependency and is not an executable policy root",
                definition.id
            ),
            Some(source),
            None,
            Vec::new(),
        )?)),
    }
}

fn exclude_duplicate_policy_ids(inputs: &mut [InputOutcome]) -> Result<(), PolicyCoordinatorError> {
    let mut groups: HashMap<PolicyId, Vec<usize>> = HashMap::new();
    for (index, input) in inputs.iter().enumerate() {
        if let InputOutcome::Pending(prepared) = input {
            groups
                .entry(prepared.policy_id.clone())
                .or_default()
                .push(index);
        }
    }
    for (policy_id, indexes) in groups {
        if indexes.len() < 2 {
            continue;
        }
        let definition_count = indexes.len();
        let mut sources = Vec::with_capacity(indexes.len());
        for index in &indexes {
            let InputOutcome::Pending(prepared) = &inputs[*index] else {
                return Err(PolicyCoordinatorError::new(
                    "duplicate policy group contains a resolved input",
                ));
            };
            sources.push(prepared.source.clone());
        }
        sources.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        sources.dedup();
        let unique_source_count = sources.len();
        for index in indexes {
            let InputOutcome::Pending(prepared) = &inputs[index] else {
                return Err(PolicyCoordinatorError::new(
                    "duplicate policy input changed during diagnostic construction",
                ));
            };
            let source = prepared.source.clone();
            let related = sources
                .iter()
                .filter(|candidate| **candidate != source)
                .take(MAX_DUPLICATE_RELATED_DIAGNOSTICS)
                .cloned()
                .map(|source| PolicySourceRelatedDiagnostic {
                    source,
                    range: 0..0,
                    message: "duplicate definition of this policy ID".to_string(),
                })
                .collect();
            inputs[index] = InputOutcome::Diagnostic(report_diagnostic(
                PolicyReportDiagnosticCode::DuplicatePolicyId,
                format!(
                    "policy ID `{policy_id}` has {definition_count} requested definitions across {unique_source_count} source identities; every definition was excluded"
                ),
                Some(source),
                None,
                related,
            )?);
        }
    }
    Ok(())
}

fn document_load_diagnostic(
    requested_path: &Path,
    error: &PolicyDocumentLoadError,
) -> Result<PolicyReportDiagnostic, PolicyCoordinatorError> {
    let requested_source = requested_source_identity(requested_path);
    if let Err(identity_error) = validate_policy_source_identity(&requested_source) {
        return invalid_source_identity_diagnostic(&requested_source, identity_error);
    }
    match error {
        PolicyDocumentLoadError::InvalidSourceIdentity { identity, source } => {
            invalid_source_identity_diagnostic(identity, *source)
        }
        PolicyDocumentLoadError::InvalidSource { identity, source } => {
            if let Err(identity_error) = validate_policy_source_identity(identity) {
                return invalid_source_identity_diagnostic(identity, identity_error);
            }
            source_diagnostic(identity.clone(), &source.diagnostic)
        }
        PolicyDocumentLoadError::Workspace(_)
        | PolicyDocumentLoadError::InvalidWorkspacePath { .. } => report_diagnostic(
            PolicyReportDiagnosticCode::PolicyLoadFailed,
            error.to_string(),
            Some(requested_source),
            None,
            Vec::new(),
        ),
    }
}

fn invalid_source_identity_diagnostic(
    identity: &PolicySourceIdentity,
    error: PolicySourceIdentityError,
) -> Result<PolicyReportDiagnostic, PolicyCoordinatorError> {
    let mut digest = Sha256::new();
    digest.update(b"bifrost-policy-invalid-source-identity/v1\0");
    digest.update(identity.as_str().as_bytes());
    let digest = digest.finalize();
    let surrogate = PolicySourceIdentity::new(format!("invalid-source:sha256:{digest:x}"));
    report_diagnostic(
        PolicyReportDiagnosticCode::PolicyValidationFailed,
        format!(
            "requested policy source identity is invalid ({} bytes): {error}; the raw identity was replaced by a stable SHA-256 surrogate",
            identity.as_str().len()
        ),
        Some(surrogate),
        None,
        Vec::new(),
    )
}

fn source_diagnostic(
    identity: PolicySourceIdentity,
    diagnostic: &PolicySourceDiagnostic,
) -> Result<PolicyReportDiagnostic, PolicyCoordinatorError> {
    let code = match diagnostic.code {
        "unsupported-policy-schema-version" => {
            PolicyReportDiagnosticCode::UnsupportedPolicySchemaVersion
        }
        "unsupported-rql-schema-version" => PolicyReportDiagnosticCode::UnsupportedRqlSchemaVersion,
        "conflicting-rql-schema-version" => PolicyReportDiagnosticCode::ConflictingRqlSchemaVersion,
        "source-too-large"
        | "invalid-s-expression"
        | "incomplete-s-expression"
        | "missing-document"
        | "trailing-document" => PolicyReportDiagnosticCode::PolicyParseFailed,
        _ => PolicyReportDiagnosticCode::PolicyValidationFailed,
    };
    report_diagnostic(
        code,
        diagnostic.message.clone(),
        Some(identity),
        Some(
            PolicySourceRange::try_from(diagnostic.range.clone()).map_err(|error| {
                PolicyCoordinatorError::new(format!("invalid policy diagnostic range: {error}"))
            })?,
        ),
        diagnostic.related.clone(),
    )
}

fn registry_diagnostic(
    source: PolicySourceIdentity,
    error: &PolicyRegistryError,
) -> Result<PolicyReportDiagnostic, PolicyCoordinatorError> {
    let code = match error {
        PolicyRegistryError::Source(error) => match error.diagnostic.code {
            "unsupported-policy-schema-version" => {
                PolicyReportDiagnosticCode::UnsupportedPolicySchemaVersion
            }
            "unsupported-rql-schema-version" => {
                PolicyReportDiagnosticCode::UnsupportedRqlSchemaVersion
            }
            "conflicting-rql-schema-version" => {
                PolicyReportDiagnosticCode::ConflictingRqlSchemaVersion
            }
            _ => PolicyReportDiagnosticCode::PolicyValidationFailed,
        },
        PolicyRegistryError::DuplicatePolicyId { .. } => {
            PolicyReportDiagnosticCode::DuplicatePolicyId
        }
        PolicyRegistryError::DuplicateEndpointId { .. } => {
            PolicyReportDiagnosticCode::DuplicateEndpointId
        }
        PolicyRegistryError::PolicyLimitExceeded { .. } => {
            PolicyReportDiagnosticCode::PolicyCountLimit
        }
        PolicyRegistryError::EndpointLimitExceeded { .. } => {
            PolicyReportDiagnosticCode::EndpointCountLimit
        }
        PolicyRegistryError::MatchDirectoryLimitExceeded { .. }
        | PolicyRegistryError::MatchDirectoryCandidateLimitExceeded { .. }
        | PolicyRegistryError::MatchDirectoryLimits { .. } => {
            PolicyReportDiagnosticCode::MatchDirectoryLimit
        }
        PolicyRegistryError::MatchDirectoryManifestMismatch { .. } => {
            PolicyReportDiagnosticCode::MatchDirectoryManifestMismatch
        }
        _ => PolicyReportDiagnosticCode::PolicyValidationFailed,
    };
    report_diagnostic(code, error.to_string(), Some(source), None, Vec::new())
}

fn explicit_version_diagnostics(
    policy: &LoadedPolicy,
) -> Result<Vec<PolicyReportDiagnostic>, PolicyCoordinatorError> {
    let mut diagnostics = Vec::new();
    if policy.schema_resolution().origin == SchemaVersionOrigin::ImplicitCompatible {
        diagnostics.push(report_diagnostic(
            PolicyReportDiagnosticCode::ExplicitPolicySchemaVersionRequired,
            format!(
                "policy `{}` inferred policy schema version {}; add :schema-version {}",
                policy.definition().metadata.id,
                policy.schema_resolution().version,
                policy.schema_resolution().version
            ),
            Some(policy.source().clone()),
            None,
            Vec::new(),
        )?);
    }

    for dependency in policy.endpoint_dependencies() {
        let EndpointDefinitionSchemaResolution::PolicyDocument { resolution } =
            dependency.definition_schema()
        else {
            continue;
        };
        if !matches!(
            dependency.identity(),
            ResolvedEndpointIdentity::MatchEndpoint { .. }
        ) || resolution.origin != SchemaVersionOrigin::ImplicitCompatible
        {
            continue;
        }
        diagnostics.push(report_diagnostic(
            PolicyReportDiagnosticCode::ExplicitPolicySchemaVersionRequired,
            format!(
                "endpoint dependency `{:?}` inferred policy schema version {}; add :schema-version {}",
                dependency.identity(),
                resolution.version,
                resolution.version
            ),
            dependency_source(policy, dependency.origins()),
            None,
            Vec::new(),
        )?);
    }

    for selector in policy.resolved_selectors() {
        let schemas = selector.as_query().map_or_else(
            || {
                selector
                    .query_bindings()
                    .into_iter()
                    .map(|binding| (binding.path, binding.schema_resolution))
                    .collect::<Vec<_>>()
            },
            |(schema, _)| vec![(selector.path.as_str().to_owned(), *schema)],
        );
        for (path, resolution) in schemas {
            if resolution.origin != SchemaVersionOrigin::ImplicitCompatible {
                continue;
            }
            diagnostics.push(report_diagnostic(
                PolicyReportDiagnosticCode::ExplicitRqlSchemaVersionRequired,
                format!(
                    "selector {path} inferred RQL schema version {}; add :schema-version {}",
                    resolution.version, resolution.version
                ),
                Some(selector_source(policy, &selector.origin)),
                None,
                Vec::new(),
            )?);
        }
    }
    diagnostics.sort_by(|left, right| {
        (
            left.source().map(PolicySourceIdentity::as_str),
            left.code(),
            left.message(),
        )
            .cmp(&(
                right.source().map(PolicySourceIdentity::as_str),
                right.code(),
                right.message(),
            ))
    });
    Ok(diagnostics)
}

fn dependency_source(
    policy: &LoadedPolicy,
    origins: &[EndpointOrigin],
) -> Option<PolicySourceIdentity> {
    origins.iter().find_map(|origin| match origin {
        EndpointOrigin::ExactMatch { source, .. }
        | EndpointOrigin::MatchDirectory { source, .. } => Some(source.clone()),
        EndpointOrigin::PolicyLocal { .. } => Some(policy.source().clone()),
        EndpointOrigin::Catalog { .. } => None,
    })
}

fn selector_source(policy: &LoadedPolicy, origin: &SelectorOrigin) -> PolicySourceIdentity {
    match origin {
        SelectorOrigin::Document { source } | SelectorOrigin::ReferencedFile { source, .. } => {
            source.clone()
        }
        SelectorOrigin::Catalog { .. } => policy.source().clone(),
    }
}

fn failed_evaluation_run(
    policy: &LoadedPolicy,
    message: String,
    budget: &PolicyBudget,
) -> Result<PolicyRun, PolicyCoordinatorError> {
    let diagnostic = PolicyDiagnostic::try_new(
        PolicyDiagnosticCode::EvaluationFailure,
        PolicyDiagnosticSeverity::Error,
        PolicyDiagnosticImpact::RunFailed,
        safe_report_text(format!("policy evaluation failed: {message}")),
        None,
        Vec::new(),
    )
    .map_err(|error| {
        PolicyCoordinatorError::new(format!(
            "failed to construct evaluation diagnostic: {error}"
        ))
    })?;
    PolicyRun::try_new(
        policy.definition().metadata.id.clone(),
        policy.semantic_hash(),
        policy.definition().analysis.analysis_type(),
        PolicyRunCompletion::Failed {
            reasons: vec![PolicyFailureReason::InternalInvariant],
        },
        Vec::new(),
        vec![diagnostic],
        false,
        PolicyWorkReport::default(),
        budget,
    )
    .map_err(|error| {
        PolicyCoordinatorError::new(format!("failed to construct failed policy run: {error}"))
    })
}

/// A run's exit status.
///
/// `threshold_exceeded` is the finding gate. The suppression gate is read off
/// the report here rather than passed in, so it survives the audit-retention
/// rollback that drops every review: a rollback leaves no orphan evidence, and
/// a gate must not fire on evidence the report does not carry.
fn report_exit_status(report: &PolicyReportDocument, threshold_exceeded: bool) -> u8 {
    // An accepted decision that no longer resolves to any finding is a defect
    // in the decision record, not in the code (#2418). Without this the
    // rotation is silent: the record stops matching, the finding it covered
    // starts gating as new on exactly one push, and after any merge or
    // projection whose base already contains the rotation it goes quiet again
    // with the dead record still in the document.
    let threshold_exceeded = threshold_exceeded
        || report
            .suppressions()
            .iter()
            .any(PolicySuppressionReview::is_orphaned);
    // A report diagnostic condemns the run when it is an error. Every load,
    // parse, and activation failure is one, so this is the same rule the
    // report has always applied. Advisory report diagnostics -- today only the
    // inert reviewed workspace model (#2493) -- state a fact the author needs
    // without claiming the run could not be trusted: whether an inert model
    // matters is decided by the evaluation that runs without it, which reports
    // its own incompleteness when it has any.
    // A run whose policy declared a non-default handling of unknown results
    // (#2506) has already had that declaration applied: `warn-unreliable` asked
    // for the findings' own status and `fail-closed` already contributed to the
    // finding gate, so neither may also condemn the batch for being incomplete.
    // The marker is set only on an `Inconclusive` run, so a failed or
    // unsupported run still exits unreliable whatever the policy declared.
    let unreliable = report.execution().termination().is_some()
        || report
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.severity() == PolicyDiagnosticSeverity::Error)
        || report.diagnostics_truncated()
        || report
            .runs()
            .iter()
            .any(|run| !run.completion().is_reliable() && run.unknown_verdict().is_none())
        || (!threshold_exceeded
            && report.runs().iter().any(|run| {
                !run.completion().permits_clean_negative() && run.unknown_verdict().is_none()
            }));
    if unreliable {
        return POLICY_EXIT_UNRELIABLE;
    }
    if threshold_exceeded {
        POLICY_EXIT_FINDING
    } else {
        POLICY_EXIT_CLEAN
    }
}

fn report_diagnostic(
    code: PolicyReportDiagnosticCode,
    message: impl Into<String>,
    source: Option<PolicySourceIdentity>,
    byte_range: Option<PolicySourceRange>,
    mut related: Vec<PolicySourceRelatedDiagnostic>,
) -> Result<PolicyReportDiagnostic, PolicyCoordinatorError> {
    for item in &mut related {
        item.message = safe_report_text(std::mem::take(&mut item.message));
    }
    PolicyReportDiagnostic::try_new(
        code,
        PolicyDiagnosticSeverity::Error,
        safe_report_text(message.into()),
        source,
        byte_range,
        related,
    )
    .map_err(|error| {
        PolicyCoordinatorError::new(format!(
            "failed to construct policy report diagnostic: {error}"
        ))
    })
}

fn requested_source_identity(path: &Path) -> PolicySourceIdentity {
    PolicySourceIdentity::new(path.to_string_lossy().replace('\\', "/"))
}

fn safe_report_text(value: String) -> String {
    const MAX_BYTES: usize = 4_096;
    let mut escaped = String::with_capacity(value.len().min(MAX_BYTES));
    for character in value.chars() {
        let unsafe_character = character.is_control()
            || matches!(
                character,
                '\u{061c}'
                    | '\u{200e}'
                    | '\u{200f}'
                    | '\u{0080}'..='\u{009f}'
                    | '\u{202a}'..='\u{202e}'
                    | '\u{2066}'..='\u{2069}'
            );
        let fragment = if unsafe_character {
            format!("\\u{{{:X}}}", u32::from(character))
        } else {
            character.to_string()
        };
        if escaped.len().saturating_add(fragment.len()) > MAX_BYTES {
            break;
        }
        escaped.push_str(&fragment);
    }
    if escaped.is_empty() {
        "policy operation failed".to_string()
    } else {
        escaped
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::fs;

    use brokk_bifrost_analysis::analyzer::DependencyPackActivationOutcome;
    use brokk_bifrost_analysis::analyzer::DispatchHierarchyExpansion;
    use brokk_bifrost_analysis::analyzer::Language;
    use brokk_bifrost_analysis::analyzer::packs_document::parse_workspace_packs_config;
    use brokk_bifrost_analysis::analyzer::semantic_model::{
        CatalogOptions, CompilerOptions, SemanticModelActivationEvidence,
        SemanticModelActivationReport, SemanticModelRuntimeLimits, SessionPackSource,
        SessionPackSourceKind, SourceFormat, compile_source,
    };
    use cap_std::ambient_authority;
    use cap_std::fs::Dir;
    use serde_json::json;

    use super::*;
    use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
    use crate::source::MAX_POLICY_SOURCE_IDENTITY_BYTES;
    use crate::suppression::{
        DEFAULT_POLICY_SUPPRESSION_PATH, LOCAL_POLICY_SUPPRESSION_PATH,
        PRIVATE_POLICY_SUPPRESSION_PATH,
    };
    use crate::write_policy_json;

    fn evaluation_options() -> PolicyEvaluationOptions {
        PolicyEvaluationOptions::new(
            PolicyEvaluationDate::from_ymd(2026, 7, 27).expect("fixed test date"),
        )
    }

    #[test]
    fn owned_policy_workspaces_enable_curated_go_evidence_without_changing_the_global_default() {
        assert_eq!(
            AnalyzerConfig::default().go.dependency_discovery.mode,
            GoDependencyDiscoveryMode::Disabled
        );
        assert_eq!(
            owned_policy_analyzer_config().go.dependency_discovery.mode,
            GoDependencyDiscoveryMode::CuratedPackEvidence
        );
    }

    const REVIEW_SUMMARY_MODEL: &str = r#"{
  "schema_version": 2,
  "pack_id": "test.review-summary",
  "version": "1.0.0",
  "producer": { "name": "bifrost-test", "version": "1.0.0" },
  "language": "go",
  "ecosystem": "go",
  "compatibility": { "bifrost": ">=0.10.5, <1.0.0", "toolchains": [] },
  "provenance": { "source": "test:review-summary", "revision": "reviewed" },
  "license": "Apache-2.0",
  "completeness": "complete",
  "safety": { "generated_code_only": false, "review_required": false },
  "shards": [{
    "id": "test.review-summary.open",
    "activation": [{}],
    "payload": {
      "kind": "procedure_summaries",
      "summaries": [{
        "id": "summary.review-open",
        "target": {
          "path": "review.go",
          "symbol": "example.com/review.Open(name string)",
          "has_receiver": false,
          "parameter_count": 1
        },
        "completeness": "complete",
        "transfers": [{
          "input": { "kind": "parameter", "ordinal": 0 },
          "exit_kind": "normal",
          "output": { "kind": "normal_return" }
        }],
        "effects": []
      }]
    }
  }]
}"#;

    struct SummaryActivationFixture {
        _project: BuiltInlineTestProject,
        _catalog: Option<SemanticPackCatalog>,
        workspace: WorkspaceAnalyzer,
        activation: WorkspacePacksActivation,
    }

    fn summary_project(with_workspace_model: bool) -> BuiltInlineTestProject {
        let project = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.com/review\n")
            .file(
                "review.go",
                "package review\n\nfunc Open(name string) string { return name }\n",
            );
        if with_workspace_model {
            project
                .file(
                    ".bifrost/semantic-models/review-summary.json",
                    REVIEW_SUMMARY_MODEL,
                )
                .build()
        } else {
            project.build()
        }
    }

    fn intrinsic_summary_activation() -> SummaryActivationFixture {
        let project = summary_project(false);
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let pack = compile_source(
            SourceFormat::Json,
            REVIEW_SUMMARY_MODEL.as_bytes(),
            &CompilerOptions::default(),
        )
        .unwrap_or_else(|diagnostics| panic!("summary model must compile: {diagnostics:#?}"));
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
            .expect("ephemeral summary catalog");
        catalog
            .register_session_pack(
                &pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: "test:intrinsic-review-summary".to_owned(),
                },
            )
            .expect("intrinsic summary pack registers");
        let runtime = acquire_active_semantic_models(
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
            matches!(runtime, SemanticModelRuntimeOutcome::Ready { .. }),
            "intrinsic summary model must activate: {runtime:#?}"
        );
        SummaryActivationFixture {
            _project: project,
            _catalog: Some(catalog),
            workspace,
            activation: WorkspacePacksActivation {
                ecosystems: Vec::new(),
                workspace_models: Vec::new(),
                outcome: DependencyPackActivationOutcome {
                    ecosystems: Vec::new(),
                    runtime: Some(runtime),
                    diagnostic_refresh_required: true,
                },
            },
        }
    }

    fn workspace_summary_activation() -> SummaryActivationFixture {
        let project = summary_project(true);
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let activation = activate_workspace_semantic_sources(
            &workspace,
            &AnalyzerConfig::default(),
            WorkspaceActivationSources {
                catalog_root: project.root(),
                workspace_model_root: Some(project.root()),
                config: None,
                intrinsic_shipped_models: false,
            },
            &CancellationToken::default(),
        )
        .expect("workspace summary activation must succeed")
        .expect("reviewed workspace model must contribute an activation");
        assert_eq!(activation.workspace_models.len(), 1);
        SummaryActivationFixture {
            _project: project,
            _catalog: None,
            workspace,
            activation,
        }
    }

    #[test]
    fn configless_intrinsic_activation_skips_review_and_declaration_scan() {
        let fixture = intrinsic_summary_activation();
        let analyzer = fixture.workspace.analyzer();
        analyzer
            .test_hooks()
            .reset_full_declaration_scan_count_for_test();

        let evidence =
            procedure_summary_match_evidence_for_review(analyzer, None, &fixture.activation);

        assert!(evidence.is_none());
        assert_eq!(
            analyzer.test_hooks().full_declaration_scan_count_for_test(),
            0,
            "an intrinsic-only activation has no review that could consume summary evidence"
        );
        assert!(
            pack_activation_review(None, Some(&fixture.activation), None, None, None).is_none()
        );
    }

    /// The base activates the shipped semantic models exactly when the head
    /// has an active model snapshot at all.
    ///
    /// A coordinator-built head activates them and publishes a snapshot, so
    /// its base must too. A host-supplied head that activated nothing has no
    /// snapshot, and a base that activated the shipped models there would
    /// model calls the head never modelled: every finding that depended on one
    /// would classify as fixed plus new, which is the asymmetry Milestone 0
    /// removed for configuration and ignore rules and this removes for models.
    #[test]
    fn the_base_activates_the_shipped_models_exactly_when_the_head_has_them() {
        let bare = summary_project(false);
        let unactivated = bare.workspace_analyzer(AnalyzerConfig::default());
        assert!(
            !base_activates_shipped_models(&unactivated),
            "a head whose host activated nothing gets a base that activates nothing"
        );

        let activated = intrinsic_summary_activation();
        assert!(
            base_activates_shipped_models(&activated.workspace),
            "a head with an active model snapshot gets a base that activates the shipped models"
        );
    }

    #[test]
    fn default_ecosystem_attempt_without_a_dependency_pack_skips_declaration_scan() {
        let mut fixture = intrinsic_summary_activation();
        fixture
            .activation
            .ecosystems
            .push(DependencyPackEcosystem::Go);
        let analyzer = fixture.workspace.analyzer();
        analyzer
            .test_hooks()
            .reset_full_declaration_scan_count_for_test();

        let evidence =
            procedure_summary_match_evidence_for_review(analyzer, None, &fixture.activation);

        assert!(evidence.is_none());
        assert_eq!(
            analyzer.test_hooks().full_declaration_scan_count_for_test(),
            0,
            "attempting an ecosystem without selecting a dependency pack must not scan declarations"
        );
    }

    #[test]
    fn configured_intrinsic_activation_computes_summary_evidence_for_review() {
        let fixture = intrinsic_summary_activation();
        assert!(fixture.activation.workspace_models.is_empty());
        let config =
            parse_workspace_packs_config(r#"{ "schema_version": 1, "ecosystems": ["go"] }"#)
                .expect("Go pack configuration parses");
        let analyzer = fixture.workspace.analyzer();
        analyzer
            .test_hooks()
            .reset_full_declaration_scan_count_for_test();

        let evidence = procedure_summary_match_evidence_for_review(
            analyzer,
            Some(&config),
            &fixture.activation,
        )
        .expect("an explicit pack configuration needs summary evidence");

        assert_eq!(
            analyzer.test_hooks().full_declaration_scan_count_for_test(),
            0,
            "a pack configuration review uses indexed declaration candidates"
        );
        assert!(
            evidence
                .values()
                .flatten()
                .any(|summary| summary.summary_id() == "summary.review-open"),
            "the review evidence must retain the active intrinsic summary"
        );
        let review = pack_activation_review(
            Some(&config),
            Some(&fixture.activation),
            None,
            None,
            Some(&evidence),
        )
        .expect("an explicit pack configuration emits a pack review");
        assert_eq!(review.document_path(), WORKSPACE_PACKS_DOCUMENT_PATH);
        assert!(review.decisions().iter().any(|decision| {
            decision
                .summary_matches()
                .iter()
                .any(|summary| summary.summary_id() == "summary.review-open")
        }));
    }

    #[test]
    fn reviewed_workspace_activation_computes_summary_evidence_for_review() {
        let fixture = workspace_summary_activation();
        let analyzer = fixture.workspace.analyzer();
        analyzer
            .test_hooks()
            .reset_full_declaration_scan_count_for_test();

        let evidence =
            procedure_summary_match_evidence_for_review(analyzer, None, &fixture.activation)
                .expect("reviewed workspace activation needs summary evidence");

        assert_eq!(
            analyzer.test_hooks().full_declaration_scan_count_for_test(),
            0,
            "a real workspace review uses indexed declaration candidates"
        );
        assert!(
            evidence
                .values()
                .flatten()
                .any(|summary| summary.summary_id() == "summary.review-open"),
            "the review evidence must retain the active summary"
        );
        let review =
            pack_activation_review(None, Some(&fixture.activation), None, None, Some(&evidence))
                .expect("reviewed workspace model emits a pack review");
        assert_eq!(review.document_path(), WORKSPACE_PACKS_DOCUMENT_PATH);
        assert!(review.decisions().iter().any(|decision| {
            decision
                .summary_matches()
                .iter()
                .any(|summary| summary.summary_id() == "summary.review-open")
        }));
    }

    fn match_policy(policy_id: &str, name: &str) -> String {
        format!(
            r#"(policy
  :schema-version 1
  :id "{policy_id}"
  :name "{name}"
  :message "Avoid target"
  :severity warning
  :analysis
    (analysis
      :type match
      :selector
        (rql :schema-version 1
          (language typescript (function :name "target")))))"#,
        )
    }

    #[test]
    fn nonready_intrinsic_activation_condemns_an_otherwise_clean_evaluation() {
        let project = InlineTestProject::with_language(Language::TypeScript)
            .file("app.ts", "export function target() {}\n")
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let report = SemanticModelActivationReport::default();
        let cases = [
            ("absent", "not attempted", None),
            (
                "incomplete",
                "incomplete",
                Some(SemanticModelRuntimeOutcome::Incomplete {
                    usable: None,
                    report: report.clone(),
                }),
            ),
            (
                "cancelled",
                "cancelled",
                Some(SemanticModelRuntimeOutcome::Cancelled(report.clone())),
            ),
            (
                "unavailable",
                "unavailable",
                Some(SemanticModelRuntimeOutcome::Unavailable(report)),
            ),
        ];

        for (label, message, runtime) in cases {
            let activation = WorkspacePacksActivation {
                ecosystems: Vec::new(),
                workspace_models: Vec::new(),
                outcome: DependencyPackActivationOutcome {
                    ecosystems: Vec::new(),
                    runtime,
                    diagnostic_refresh_required: true,
                },
            };
            assert!(
                pack_activation_review(None, Some(&activation), None, None, None).is_none(),
                "an owned intrinsic-only activation keeps the optional review absent"
            );
            assert_eq!(
                nonready_activation_diagnostic(&activation)
                    .expect("activation diagnostic")
                    .expect("non-ready activation is diagnosed")
                    .code(),
                PolicyReportDiagnosticCode::PackActivationFailed,
            );
            let outcome = evaluate_policy_source_with_host_activation(
                project.root(),
                PolicySourceIdentity::new(format!("policies/{label}.rqlp")),
                &match_policy(
                    &format!("test.activation-{label}"),
                    "Activation reliability",
                ),
                &workspace,
                &brokk_bifrost_flow::FlowWorkspaceState::new(),
                &evaluation_options(),
                PolicyHostActivationContext::new(None, Some(&activation), &[], None),
                None,
            )
            .expect("non-ready activation produces a canonical report");

            assert_eq!(outcome.exit_status(), POLICY_EXIT_UNRELIABLE, "{label}");
            assert_eq!(outcome.report().runs().len(), 1, "{label}");
            assert!(
                outcome.report().runs()[0].completion().is_complete(),
                "the activation diagnostic, not a coincidental policy failure, condemns {label}"
            );
            assert_eq!(outcome.report().runs()[0].findings().len(), 1, "{label}");
            assert!(
                !outcome
                    .report()
                    .packs()
                    .expect("the host attempt itself is audited")
                    .complete(),
                "a non-ready runtime cannot publish a complete activation review"
            );
            let [diagnostic] = outcome.report().diagnostics() else {
                panic!(
                    "one structured activation diagnostic for {label}: {:#?}",
                    outcome.report()
                )
            };
            assert_eq!(
                diagnostic.code(),
                PolicyReportDiagnosticCode::PackActivationFailed,
                "{label}"
            );
            assert_eq!(diagnostic.severity(), PolicyDiagnosticSeverity::Error);
            assert!(diagnostic.source().is_none());
            assert!(diagnostic.message().contains(message), "{diagnostic:#?}");
        }
    }

    fn write_policy(root: &Path, relative: &str, source: &str) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().expect("policy parent")).expect("create policy parent");
        fs::write(path, source).expect("write policy");
    }

    fn relative_directory_with_len(target_len: usize) -> String {
        assert!(target_len > 0);
        let component_count = target_len.saturating_add(201) / 201;
        let component_bytes = target_len - component_count.saturating_sub(1);
        let base_len = component_bytes / component_count;
        let longer_components = component_bytes % component_count;
        let mut components = Vec::with_capacity(component_count);
        for index in 0..component_count {
            let component_len = base_len + usize::from(index < longer_components);
            assert!((1..=200).contains(&component_len));
            components.push("x".repeat(component_len));
        }
        let relative = components.join("/");
        assert_eq!(relative.len(), target_len);
        relative
    }

    fn create_deep_policy_directory(root: &Path, relative: &str) -> Dir {
        let mut directory =
            Dir::open_ambient_dir(root, ambient_authority()).expect("open workspace directory");
        for component in relative.split('/') {
            directory
                .create_dir(component)
                .expect("create deep policy directory component");
            directory = directory
                .open_dir(component)
                .expect("open deep policy directory component");
        }
        directory
    }

    fn assert_invalid_source_diagnostics(outcome: &PolicyBatchOutcome, expected_lengths: &[usize]) {
        assert_eq!(outcome.exit_status(), POLICY_EXIT_UNRELIABLE);
        assert!(outcome.report().rules().is_empty());
        assert!(outcome.report().runs().is_empty());
        assert_eq!(outcome.report().diagnostics().len(), expected_lengths.len());
        let expected_lengths = expected_lengths.iter().copied().collect::<HashSet<_>>();
        let mut actual_lengths = HashSet::new();
        let mut sources = HashSet::new();
        for diagnostic in outcome.report().diagnostics() {
            assert_eq!(
                diagnostic.code(),
                PolicyReportDiagnosticCode::PolicyValidationFailed
            );
            assert!(diagnostic.related().is_empty());
            assert!(
                diagnostic
                    .message()
                    .contains("the raw identity was replaced by a stable SHA-256 surrogate")
            );
            let byte_count = diagnostic
                .message()
                .strip_prefix("requested policy source identity is invalid (")
                .and_then(|message| message.split_once(" bytes):"))
                .and_then(|(count, _)| count.parse::<usize>().ok())
                .expect("invalid-source diagnostic byte count");
            actual_lengths.insert(byte_count);
            let source = diagnostic.source().expect("surrogate source").as_str();
            assert!(source.starts_with("invalid-source:sha256:"));
            assert_eq!(source.len(), "invalid-source:sha256:".len() + 64);
            sources.insert(source);
        }
        assert_eq!(actual_lengths, expected_lengths);
        assert_eq!(sources.len(), outcome.report().diagnostics().len());
    }

    fn canonical_report_bytes(outcome: &PolicyBatchOutcome) -> Vec<u8> {
        let mut output = Vec::new();
        write_policy_json(
            outcome.report(),
            &mut output,
            outcome.max_serialized_report_bytes(),
        )
        .expect("bounded canonical policy report");
        output
    }

    /// One accepted record. `path` is the optional file the decision was made
    /// against, which is what lets a run tell a rotated identity from a file it
    /// never analyzed.
    fn suppression_record(
        policy_id: &str,
        policy_hash: &str,
        finding_id: &str,
        path: Option<&str>,
    ) -> serde_json::Value {
        let mut record = json!({
            "policy_id": policy_id,
            "finding_id": finding_id,
            "identity_stability": "strong",
            "status": "accepted",
            "reason": "Reviewed exact finding",
            "policy_hash_at_acceptance": policy_hash,
            "accepted_at": "2026-07-01",
            "expires_at": null
        });
        if let Some(path) = path {
            record
                .as_object_mut()
                .expect("record object")
                .insert("path".to_owned(), json!(path));
        }
        record
    }

    fn write_suppressions(root: &Path, records: Vec<serde_json::Value>) {
        let path = root.join(".bifrost/suppressions.json");
        fs::create_dir_all(path.parent().expect("suppression parent"))
            .expect("create suppression directory");
        fs::write(
            path,
            serde_json::to_vec(&json!({
                "schema_version": 1,
                "suppressions": records,
            }))
            .expect("suppression JSON"),
        )
        .expect("write suppression document");
    }

    fn write_test_suppression(root: &Path, policy_id: &str, policy_hash: &str, finding_id: &str) {
        write_suppressions(
            root,
            vec![suppression_record(policy_id, policy_hash, finding_id, None)],
        );
    }

    #[test]
    fn procedure_summary_candidates_use_the_identifier_index() {
        let project = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file(
                "src/lib.rs",
                "pub struct Acme;\nimpl Acme { pub fn run(&self) {} }\n",
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let analyzer = workspace.analyzer();
        analyzer
            .test_hooks()
            .reset_full_declaration_scan_count_for_test();

        let candidates = procedure_summary_candidate_declarations(
            analyzer,
            &HashSet::from([String::from("run")]),
        );

        assert!(
            candidates.iter().any(|unit| unit.terminal_name() == "run"),
            "the indexed lookup must retain the modeled declaration"
        );
        assert_eq!(
            analyzer.test_hooks().full_declaration_scan_count_for_test(),
            0,
            "summary evidence must not enumerate every workspace declaration"
        );
    }

    /// A workspace holding one `target` function per named file, plus a policy
    /// that reports each of them, evaluated with warnings below the failure
    /// threshold so only the suppression gate can change the exit status.
    struct OrphanFixture {
        workspace: tempfile::TempDir,
        policy_paths: [PathBuf; 1],
    }

    impl OrphanFixture {
        fn new(sources: &[&str]) -> Self {
            let workspace = tempfile::tempdir().expect("workspace");
            for source in sources {
                fs::write(
                    workspace.path().join(source),
                    "export function target() {}\n",
                )
                .expect("source fixture");
            }
            write_policy(
                workspace.path(),
                "policies/orphan.rqlp",
                &match_policy("test.orphan", "Orphan"),
            );
            Self {
                workspace,
                policy_paths: [PathBuf::from("policies/orphan.rqlp")],
            }
        }

        fn evaluate(&self) -> PolicyBatchOutcome {
            evaluate_policy_files(
                self.workspace.path(),
                &self.policy_paths,
                &evaluation_options().with_fail_on(PolicyFailOn::Error),
            )
            .expect("policy report")
        }

        fn root(&self) -> &Path {
            self.workspace.path()
        }
    }

    /// The policy hash and the identity of the finding reported in `path`.
    fn identity_in(outcome: &PolicyBatchOutcome, path: &str) -> (String, String) {
        let policy_hash = outcome.report().rules()[0].policy_hash().to_string();
        let finding = outcome.report().runs()[0]
            .findings()
            .iter()
            .find(|finding| finding.primary().path() == path)
            .unwrap_or_else(|| panic!("no finding in {path}"));
        (policy_hash, finding.id().to_string())
    }

    fn write_suppressions_to(root: &Path, relative: &str, records: Vec<serde_json::Value>) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().expect("suppression parent"))
            .expect("create suppression directory");
        fs::write(
            path,
            serde_json::to_vec(&json!({
                "schema_version": 1,
                "suppressions": records,
            }))
            .expect("suppression JSON"),
        )
        .expect("write suppression document");
    }

    #[test]
    fn every_conventional_source_contributes_and_each_is_reported() {
        let fixture = OrphanFixture::new(&["app.ts", "other.ts"]);
        let baseline = fixture.evaluate();
        let (policy_hash, first) = identity_in(&baseline, "app.ts");
        let (_, second) = identity_in(&baseline, "other.ts");

        // The published document accepts one finding; the uncommitted local
        // document accepts the other. The private document is absent, which is
        // the ordinary case and must not be an error.
        write_suppressions_to(
            fixture.root(),
            DEFAULT_POLICY_SUPPRESSION_PATH,
            vec![suppression_record(
                "test.orphan",
                &policy_hash,
                &first,
                Some("app.ts"),
            )],
        );
        write_suppressions_to(
            fixture.root(),
            LOCAL_POLICY_SUPPRESSION_PATH,
            vec![suppression_record(
                "test.orphan",
                &policy_hash,
                &second,
                Some("other.ts"),
            )],
        );

        let outcome = fixture.evaluate();
        assert_eq!(outcome.report().suppressions().len(), 2);
        assert!(
            outcome
                .report()
                .suppressions()
                .iter()
                .all(PolicySuppressionReview::applied),
            "a record from any configured source applies"
        );
        let states = outcome
            .report()
            .evaluation()
            .suppression_sources()
            .iter()
            .map(|source| (source.path(), source.state()))
            .collect::<Vec<_>>();
        assert_eq!(
            states,
            vec![
                (
                    DEFAULT_POLICY_SUPPRESSION_PATH,
                    PolicySuppressionDocumentState::Loaded
                ),
                (
                    PRIVATE_POLICY_SUPPRESSION_PATH,
                    PolicySuppressionDocumentState::NotFound
                ),
                (
                    LOCAL_POLICY_SUPPRESSION_PATH,
                    PolicySuppressionDocumentState::Loaded
                ),
            ],
            "an absent source is reported, not omitted"
        );
        assert_eq!(outcome.exit_status(), POLICY_EXIT_CLEAN);
    }

    #[test]
    fn two_sources_claiming_one_finding_are_rejected_rather_than_resolved() {
        let fixture = OrphanFixture::new(&["app.ts"]);
        let baseline = fixture.evaluate();
        let (policy_hash, claimed) = identity_in(&baseline, "app.ts");

        let mut divergent =
            suppression_record("test.orphan", &policy_hash, &claimed, Some("app.ts"));
        divergent
            .as_object_mut()
            .expect("record object")
            .insert("reason".to_owned(), json!("A different justification"));
        write_suppressions_to(
            fixture.root(),
            DEFAULT_POLICY_SUPPRESSION_PATH,
            vec![suppression_record(
                "test.orphan",
                &policy_hash,
                &claimed,
                Some("app.ts"),
            )],
        );
        write_suppressions_to(
            fixture.root(),
            PRIVATE_POLICY_SUPPRESSION_PATH,
            vec![divergent],
        );

        // Choosing a winner silently is the failure this document exists to
        // prevent, so neither record applies and the run is unreliable.
        let outcome = fixture.evaluate();
        assert_eq!(outcome.exit_status(), POLICY_EXIT_UNRELIABLE);
        assert!(
            outcome.report().suppressions().is_empty(),
            "an ambiguous record set applies nothing"
        );
        let diagnostic = outcome
            .report()
            .diagnostics()
            .iter()
            .find(|diagnostic| {
                diagnostic.code() == PolicyReportDiagnosticCode::SuppressionLoadFailed
            })
            .expect("a load failure naming the collision");
        assert!(
            diagnostic.message().contains("different terms")
                && diagnostic
                    .message()
                    .contains(DEFAULT_POLICY_SUPPRESSION_PATH),
            "the diagnostic must name the other source: {}",
            diagnostic.message()
        );
    }

    /// A well-formed identity that no finding carries, standing in for the one
    /// an edit rotated away from.
    const ROTATED_AWAY_IDENTITY: &str =
        "0000000000000000000000000000000000000000000000000000000000000001";

    #[test]
    fn a_record_whose_analyzed_file_no_longer_carries_it_gates_the_run() {
        let fixture = OrphanFixture::new(&["app.ts"]);
        let baseline = fixture.evaluate();
        assert_eq!(baseline.exit_status(), POLICY_EXIT_CLEAN);
        let (policy_hash, _) = identity_in(&baseline, "app.ts");

        // The record was accepted against a file this run analyzes, and no
        // finding carries its identity: exactly the shape an edit that rotates
        // a canonical identity leaves behind.
        write_suppressions(
            fixture.root(),
            vec![suppression_record(
                "test.orphan",
                &policy_hash,
                ROTATED_AWAY_IDENTITY,
                Some("app.ts"),
            )],
        );

        let outcome = fixture.evaluate();
        let review = &outcome.report().suppressions()[0];
        assert_eq!(
            review.match_state(),
            PolicySuppressionMatchState::FindingAbsent
        );
        assert_eq!(
            review.orphan_state(),
            PolicySuppressionOrphanState::Orphaned
        );
        assert!(review.is_orphaned());
        assert!(!review.applied());
        // Nothing gates on severity here, so the failure is the orphan alone.
        assert_eq!(outcome.exit_status(), POLICY_EXIT_FINDING);
    }

    #[test]
    fn an_orphaned_record_reports_the_unclaimed_identities_in_its_own_file() {
        let fixture = OrphanFixture::new(&["app.ts", "other.ts"]);
        let baseline = fixture.evaluate();
        let (policy_hash, claimed) = identity_in(&baseline, "app.ts");
        let (_, unclaimed) = identity_in(&baseline, "other.ts");

        write_suppressions(
            fixture.root(),
            vec![
                suppression_record("test.orphan", &policy_hash, &claimed, Some("app.ts")),
                suppression_record(
                    "test.orphan",
                    &policy_hash,
                    ROTATED_AWAY_IDENTITY,
                    Some("other.ts"),
                ),
                // A second orphan in the file whose only finding the first
                // record already claims: no candidate is left to offer.
                suppression_record(
                    "test.orphan",
                    &policy_hash,
                    "0000000000000000000000000000000000000000000000000000000000000002",
                    Some("app.ts"),
                ),
            ],
        );

        let outcome = fixture.evaluate();
        let reviews = outcome.report().suppressions();
        let unclaimed = unclaimed
            .parse::<PolicyFindingId>()
            .expect("unclaimed identity");
        assert!(
            reviews
                .iter()
                .any(|review| review.is_orphaned() && review.rekey_candidates() == [unclaimed]),
            "the orphan in other.ts must offer that file's unclaimed identity"
        );
        assert!(
            reviews
                .iter()
                .any(|review| review.is_orphaned() && review.rekey_candidates().is_empty()),
            "an orphan whose file has no unclaimed finding must offer nothing"
        );
        assert_eq!(outcome.exit_status(), POLICY_EXIT_FINDING);
    }

    #[test]
    fn a_record_for_a_file_this_run_did_not_analyze_never_gates() {
        let fixture = OrphanFixture::new(&["app.ts"]);
        let baseline = fixture.evaluate();
        let (policy_hash, claimed) = identity_in(&baseline, "app.ts");

        // This is the projected-document case: `.bifrost/suppressions.json`
        // travels verbatim to a tree that does not contain every file it names,
        // and such a record reports `finding_absent` in every run there.
        write_suppressions(
            fixture.root(),
            vec![
                suppression_record("test.orphan", &policy_hash, &claimed, Some("app.ts")),
                suppression_record(
                    "test.orphan",
                    &policy_hash,
                    ROTATED_AWAY_IDENTITY,
                    Some("private/only.ts"),
                ),
            ],
        );

        let outcome = fixture.evaluate();
        let review = outcome
            .report()
            .suppressions()
            .iter()
            .find(|review| !review.applied())
            .expect("the unresolved record");
        assert_eq!(
            review.match_state(),
            PolicySuppressionMatchState::FindingAbsent
        );
        assert_eq!(
            review.orphan_state(),
            PolicySuppressionOrphanState::PathNotAnalyzed
        );
        assert!(!review.is_orphaned());
        assert!(review.rekey_candidates().is_empty());
        assert_eq!(outcome.exit_status(), POLICY_EXIT_CLEAN);
    }

    #[test]
    fn a_record_with_no_recorded_path_cannot_be_classified_and_never_gates() {
        let fixture = OrphanFixture::new(&["app.ts"]);
        let baseline = fixture.evaluate();
        let (policy_hash, _) = identity_in(&baseline, "app.ts");

        write_test_suppression(
            fixture.root(),
            "test.orphan",
            &policy_hash,
            ROTATED_AWAY_IDENTITY,
        );

        let outcome = fixture.evaluate();
        let review = &outcome.report().suppressions()[0];
        assert_eq!(
            review.match_state(),
            PolicySuppressionMatchState::FindingAbsent
        );
        assert_eq!(
            review.orphan_state(),
            PolicySuppressionOrphanState::PathUnrecorded
        );
        assert_eq!(outcome.exit_status(), POLICY_EXIT_CLEAN);
    }

    #[test]
    fn live_policy_source_uses_supplied_analyzer_and_unsaved_bytes() {
        let workspace = tempfile::tempdir().expect("workspace");
        fs::write(
            workspace.path().join("app.ts"),
            "export function target() {}\n",
        )
        .expect("source fixture");
        write_policy(
            workspace.path(),
            "policies/live.rqlp",
            &match_policy("test.saved", "Saved source"),
        );

        let project = FilesystemProject::new(workspace.path().to_path_buf()).expect("project");
        let project: Arc<dyn Project> = Arc::new(project);
        let analyzer =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("ephemeral workspace should build");
        let live_source = match_policy("test.unsaved", "Unsaved source");

        let outcome = evaluate_policy_source(
            workspace.path(),
            PolicySourceIdentity::new("policies/live.rqlp"),
            &live_source,
            &analyzer,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &evaluation_options(),
            None,
        )
        .expect("live policy report");

        assert_eq!(outcome.exit_status(), POLICY_EXIT_CLEAN);
        assert!(outcome.report().diagnostics().is_empty());
        assert_eq!(outcome.report().rules().len(), 1);
        assert_eq!(
            outcome.report().rules()[0].policy_id().as_str(),
            "test.unsaved"
        );
        assert_eq!(outcome.report().rules()[0].name(), "Unsaved source");
        assert_eq!(outcome.report().runs().len(), 1);
        assert!(outcome.report().runs()[0].completion().is_complete());
        assert_eq!(outcome.report().runs()[0].findings().len(), 1);
        assert_eq!(
            outcome.report().runs()[0].findings()[0].primary().path(),
            "app.ts"
        );
    }

    #[test]
    fn successful_run_keeps_default_execution_and_attributes_stages_out_of_band() {
        let workspace = tempfile::tempdir().expect("workspace");
        fs::write(workspace.path().join("app.ts"), "export const value = 1;\n")
            .expect("source fixture");
        let project = FilesystemProject::new(workspace.path().to_path_buf()).expect("project");
        let project: Arc<dyn Project> = Arc::new(project);
        let analyzer =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("ephemeral workspace should build");

        let mut outcome = evaluate_policy_source(
            workspace.path(),
            PolicySourceIdentity::new("policies/timings.rqlp"),
            &match_policy("test.timings", "Timings"),
            &analyzer,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &evaluation_options(),
            None,
        )
        .expect("successful policy report");

        // The canonical report stays byte-stable: a successful run publishes
        // the default execution block, with no timings and no termination, and
        // no run carries its own evaluation time either.
        assert_eq!(
            outcome.report().execution(),
            &PolicyExecutionMetadata::default()
        );
        assert!(
            outcome.report().runs().iter().all(|run| {
                run.work()
                    .metrics()
                    .iter()
                    .all(|metric| metric.name() != EVALUATION_ELAPSED_METRIC)
            }),
            "{:?}",
            outcome.report().runs()[0].work().metrics()
        );
        assert_eq!(
            outcome
                .stage_attribution()
                .iter()
                .map(PolicyStageTiming::stage)
                .collect::<Vec<_>>(),
            vec![
                PolicyExecutionStage::PolicyRegistration,
                PolicyExecutionStage::PolicyPreparation,
                PolicyExecutionStage::PolicyEvaluation,
                PolicyExecutionStage::ReportConstruction,
            ]
        );

        outcome.record_preparation_timings(
            Duration::from_millis(3),
            Duration::from_millis(5),
            Duration::from_millis(7),
        );
        // Preparation stages augment only the side channel; the report still
        // carries the default execution block.
        assert_eq!(
            outcome.report().execution(),
            &PolicyExecutionMetadata::default()
        );
        assert_eq!(
            outcome
                .stage_attribution()
                .iter()
                .map(|timing| (timing.stage(), timing.elapsed_ms()))
                .take(3)
                .collect::<Vec<_>>(),
            vec![
                (PolicyExecutionStage::PolicySelection, 3),
                (PolicyExecutionStage::SuppressionPreflight, 5),
                (PolicyExecutionStage::WorkspaceSnapshot, 7),
            ]
        );
        assert_eq!(
            outcome
                .stage_attribution()
                .iter()
                .map(PolicyStageTiming::stage)
                .collect::<Vec<_>>(),
            vec![
                PolicyExecutionStage::PolicySelection,
                PolicyExecutionStage::SuppressionPreflight,
                PolicyExecutionStage::WorkspaceSnapshot,
                PolicyExecutionStage::PolicyRegistration,
                PolicyExecutionStage::PolicyPreparation,
                PolicyExecutionStage::PolicyEvaluation,
                PolicyExecutionStage::ReportConstruction,
            ]
        );
    }

    #[test]
    fn policy_timings_option_records_each_runs_evaluation_time_in_its_work() {
        let workspace = tempfile::tempdir().expect("workspace");
        fs::write(workspace.path().join("app.ts"), "export const value = 1;\n")
            .expect("source fixture");
        let project = FilesystemProject::new(workspace.path().to_path_buf()).expect("project");
        let project: Arc<dyn Project> = Arc::new(project);
        let analyzer =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("ephemeral workspace should build");

        let outcome = evaluate_policy_source(
            workspace.path(),
            PolicySourceIdentity::new("policies/timings.rqlp"),
            &match_policy("test.timings", "Timings"),
            &analyzer,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &evaluation_options().with_policy_timings(true),
            None,
        )
        .expect("successful policy report");

        // The per-policy time rides in the run's work, which is the only
        // place a reader can split the batch's `policy_evaluation` stage by
        // policy; the execution block stays at its default either way.
        assert_eq!(outcome.report().runs().len(), 1);
        let timings = outcome.report().runs()[0]
            .work()
            .metrics()
            .iter()
            .filter(|metric| metric.name() == EVALUATION_ELAPSED_METRIC)
            .collect::<Vec<_>>();
        assert_eq!(timings.len(), 1, "{:?}", outcome.report().runs()[0].work());
        assert_eq!(timings[0].unit(), PolicyWorkUnit::Milliseconds);
        assert_eq!(
            outcome.report().execution(),
            &PolicyExecutionMetadata::default()
        );
    }

    #[test]
    fn live_endpoint_root_is_a_canonical_non_executable_diagnostic() {
        let workspace = tempfile::tempdir().expect("workspace");
        fs::write(workspace.path().join("app.ts"), "export const value = 1;\n")
            .expect("source fixture");
        let project = FilesystemProject::new(workspace.path().to_path_buf()).expect("project");
        let project: Arc<dyn Project> = Arc::new(project);
        let analyzer =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("ephemeral workspace should build");
        let endpoint = r#"(endpoint
  :id "endpoint.input"
  :name "Input"
  :display-name "input"
  :role source
  :categories [input.user]
  :selector
    (rql
      (language typescript (function :name "target")))
  :binding return-value
  :supersedes [])"#;

        let outcome = evaluate_policy_source(
            workspace.path(),
            PolicySourceIdentity::new("policies/input.rqlp"),
            endpoint,
            &analyzer,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &evaluation_options(),
            None,
        )
        .expect("endpoint diagnostic report");

        assert_eq!(outcome.exit_status(), POLICY_EXIT_UNRELIABLE);
        assert!(outcome.report().rules().is_empty());
        assert!(outcome.report().runs().is_empty());
        assert_eq!(outcome.report().diagnostics().len(), 1);
        assert_eq!(
            outcome.report().diagnostics()[0].code(),
            PolicyReportDiagnosticCode::NotExecutableEndpoint
        );
        assert_eq!(
            outcome.report().diagnostics()[0]
                .source()
                .map(PolicySourceIdentity::as_str),
            Some("policies/input.rqlp")
        );
    }

    #[test]
    fn live_policy_source_stops_before_registry_loading_when_cancelled() {
        let workspace = tempfile::tempdir().expect("workspace");
        fs::write(workspace.path().join("app.ts"), "export const value = 1;\n")
            .expect("source fixture");
        let project = FilesystemProject::new(workspace.path().to_path_buf()).expect("project");
        let project: Arc<dyn Project> = Arc::new(project);
        let analyzer =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("ephemeral workspace should build");
        let cancellation = CancellationToken::default();
        cancellation.cancel();

        let result = evaluate_policy_source(
            workspace.path(),
            PolicySourceIdentity::new("policies/live.rqlp"),
            &match_policy("test.cancelled", "Cancelled"),
            &analyzer,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &evaluation_options(),
            Some(&cancellation),
        );
        let Err(error) = result else {
            panic!("cancelled evaluation must stop");
        };

        assert_eq!(error.to_string(), "policy evaluation cancelled");
    }

    #[test]
    fn issue_1296_evaluation_deadline_returns_a_canonical_unreliable_report() {
        let workspace = tempfile::tempdir().expect("workspace");
        fs::write(workspace.path().join("app.ts"), "export const value = 1;\n")
            .expect("source fixture");
        let project = FilesystemProject::new(workspace.path().to_path_buf()).expect("project");
        let project: Arc<dyn Project> = Arc::new(project);
        let analyzer =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("ephemeral workspace should build");
        let cancellation = CancellationToken::timeout_after_checks_for_test(9);

        let outcome = evaluate_policy_source(
            workspace.path(),
            PolicySourceIdentity::new("policies/live.rqlp"),
            &match_policy("test.timed-out", "Timed out"),
            &analyzer,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &evaluation_options(),
            Some(&cancellation),
        )
        .expect("request deadline should retain a canonical policy report");

        assert_eq!(outcome.exit_status(), POLICY_EXIT_UNRELIABLE);
        assert!(outcome.report().diagnostics().is_empty());
        assert!(matches!(
            outcome.report().runs()[0].completion(),
            PolicyRunCompletion::Inconclusive { reasons }
                if reasons.contains(&PolicyIncompleteReason::DeadlineExceeded)
        ));
        assert_eq!(
            outcome.report().execution().termination(),
            Some(PolicyExecutionTermination::DeadlineExceeded)
        );
        assert_eq!(
            outcome.report().execution().terminal_stage(),
            Some(PolicyExecutionStage::PolicyEvaluation)
        );
        assert_eq!(
            outcome.report().execution().active_policy_id(),
            Some(&PolicyId::new("test.timed-out").unwrap())
        );
    }

    #[test]
    fn issue_1296_registration_deadline_stops_before_policy_evaluation() {
        let workspace = tempfile::tempdir().expect("workspace");
        fs::write(workspace.path().join("app.ts"), "export const value = 1;\n")
            .expect("source fixture");
        let project = FilesystemProject::new(workspace.path().to_path_buf()).expect("project");
        let project: Arc<dyn Project> = Arc::new(project);
        let analyzer =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("ephemeral workspace should build");
        let cancellation = CancellationToken::default().with_timeout(std::time::Duration::ZERO);

        let outcome = evaluate_policy_source(
            workspace.path(),
            PolicySourceIdentity::new("policies/live.rqlp"),
            &match_policy("test.registration-timeout", "Registration timeout"),
            &analyzer,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &evaluation_options(),
            Some(&cancellation),
        )
        .expect("registration deadline should retain a canonical policy report");

        assert_eq!(outcome.exit_status(), POLICY_EXIT_UNRELIABLE);
        assert!(outcome.report().runs().is_empty());
        assert_eq!(
            outcome.report().execution().terminal_stage(),
            Some(PolicyExecutionStage::PolicyRegistration)
        );
        assert_eq!(
            outcome.report().execution().pending_policy_ids(),
            &[PolicyId::new("test.registration-timeout").unwrap()]
        );
    }

    #[test]
    fn issue_1296_execution_termination_forces_unreliable_exit_status() {
        let outcome = deadline_before_evaluation_outcome(
            &evaluation_options(),
            PolicyBatchBudget::default(),
            evaluation_options()
                .suppressions()
                .source_states(PolicySuppressionDocumentState::NotEvaluated),
            PolicyScopeDocumentState::NotEvaluated,
            vec![PolicyStageTiming::new(
                PolicyExecutionStage::ReportConstruction,
                5_000,
            )],
            PolicyExecutionStage::ReportConstruction,
            Vec::new(),
            None,
        )
        .expect("deadline report");

        assert_eq!(
            report_exit_status(outcome.report(), false),
            POLICY_EXIT_UNRELIABLE
        );
    }

    fn single_run_report(completion: PolicyRunCompletion) -> PolicyReportDocument {
        let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
            CatalogRegistryLimits::default(),
        ));
        let mut registry =
            PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
        registry
            .register_policy_bytes(
                PolicySourceIdentity::new("test:exit-gate"),
                match_policy("test.exit-gate", "Exit gate").as_bytes(),
            )
            .expect("valid policy");
        let policy = registry.policies().next().expect("one policy");
        let descriptor = PolicyRuleDescriptor::from_loaded(policy);
        let run = PolicyRun::try_new(
            policy.definition().metadata.id.clone(),
            policy.semantic_hash(),
            policy.definition().analysis.analysis_type(),
            completion,
            Vec::new(),
            Vec::new(),
            false,
            PolicyWorkReport::default(),
            &PolicyBudget::default(),
        )
        .expect("synthetic run");
        PolicyReportDocument::try_new(vec![descriptor], vec![run], Vec::new(), false, 0, None)
            .expect("canonical report")
    }

    #[test]
    fn issue_1916_proven_by_summary_passes_the_exit_gate_but_inconclusive_does_not() {
        // A summary-backed run with no findings is trustworthy under the
        // require-model contract, so it exits clean rather than unreliable.
        let proven_by_summary = single_run_report(PolicyRunCompletion::ProvenBySummary);
        assert_eq!(
            report_exit_status(&proven_by_summary, false),
            POLICY_EXIT_CLEAN
        );

        // A genuinely inconclusive run with no findings still exits unreliable.
        let inconclusive = single_run_report(
            PolicyRunCompletion::inconclusive(vec![PolicyIncompleteReason::PartialDiscovery])
                .unwrap(),
        );
        assert_eq!(
            report_exit_status(&inconclusive, false),
            POLICY_EXIT_UNRELIABLE
        );
    }

    #[test]
    fn issue_1306_deadline_racing_client_cancellation_keeps_the_canonical_report() {
        let workspace = tempfile::tempdir().expect("workspace");
        fs::write(workspace.path().join("app.ts"), "export const value = 1;\n")
            .expect("source fixture");
        let project = FilesystemProject::new(workspace.path().to_path_buf()).expect("project");
        let project: Arc<dyn Project> = Arc::new(project);
        let analyzer =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("ephemeral workspace should build");
        let cancellation = CancellationToken::default().with_timeout(std::time::Duration::ZERO);
        cancellation.cancel();

        let outcome = evaluate_policy_source(
            workspace.path(),
            PolicySourceIdentity::new("policies/live.rqlp"),
            &match_policy("test.deadline-race", "Deadline race"),
            &analyzer,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &evaluation_options(),
            Some(&cancellation),
        )
        .expect("an expired deadline must not become a cancellation error");

        assert_eq!(outcome.exit_status(), POLICY_EXIT_UNRELIABLE);
        assert_eq!(
            outcome.report().execution().termination(),
            Some(PolicyExecutionTermination::DeadlineExceeded)
        );
    }

    #[test]
    fn maximum_duplicate_group_is_bounded_complete_and_argument_order_independent() {
        let workspace = tempfile::tempdir().expect("workspace");
        let source = match_policy("test.duplicate", "Duplicate");
        let mut paths = Vec::new();
        let filename_len = "duplicate-000.rqlp".len();
        let relative_directory =
            relative_directory_with_len(MAX_POLICY_SOURCE_IDENTITY_BYTES - filename_len - 1);
        let directory = create_deep_policy_directory(workspace.path(), &relative_directory);
        for index in 0..PolicyBatchBudget::default().max_policies() {
            let filename = format!("duplicate-{index:03}.rqlp");
            directory
                .write(&filename, &source)
                .expect("write duplicate policy");
            let relative = format!("{relative_directory}/{filename}");
            assert_eq!(relative.len(), MAX_POLICY_SOURCE_IDENTITY_BYTES);
            paths.push(PathBuf::from(relative));
        }

        let forward = evaluate_policy_files(workspace.path(), &paths, &evaluation_options())
            .expect("forward duplicate report");
        paths.reverse();
        let reversed = evaluate_policy_files(workspace.path(), &paths, &evaluation_options())
            .expect("reversed duplicate report");

        assert_eq!(forward.exit_status(), POLICY_EXIT_UNRELIABLE);
        assert_eq!(reversed.exit_status(), POLICY_EXIT_UNRELIABLE);
        assert_eq!(
            canonical_report_bytes(&forward),
            canonical_report_bytes(&reversed)
        );
        assert!(forward.report().rules().is_empty());
        assert!(forward.report().runs().is_empty());
        assert_eq!(forward.report().diagnostics().len(), 256);
        assert!(
            forward.report().diagnostics().iter().all(|diagnostic| {
                diagnostic.related().len() == MAX_DUPLICATE_RELATED_DIAGNOSTICS
            })
        );
        let named_sources = forward
            .report()
            .diagnostics()
            .iter()
            .filter_map(PolicyReportDiagnostic::source)
            .map(PolicySourceIdentity::as_str)
            .collect::<HashSet<_>>();
        assert_eq!(named_sources.len(), 256);
        let first = format!("{relative_directory}/duplicate-000.rqlp");
        let last = format!("{relative_directory}/duplicate-255.rqlp");
        assert!(named_sources.contains(first.as_str()));
        assert!(named_sources.contains(last.as_str()));
        assert!(named_sources.iter().all(|source| {
            validate_policy_source_identity(&PolicySourceIdentity::new(source)).is_ok()
                && source.len() == MAX_POLICY_SOURCE_IDENTITY_BYTES
        }));
        assert!(forward.report().diagnostics().iter().all(|diagnostic| {
            diagnostic.message()
                == "policy ID `test.duplicate` has 256 requested definitions across 256 source identities; every definition was excluded"
        }));
    }

    #[test]
    fn oversized_duplicate_sources_are_rejected_before_duplicate_grouping() {
        let workspace = tempfile::tempdir().expect("workspace");
        let source = match_policy("test.duplicate", "Duplicate");
        let source_len = MAX_POLICY_SOURCE_IDENTITY_BYTES + 128;
        let filename_len = "duplicate-000.rqlp".len();
        let relative_directory = relative_directory_with_len(source_len - filename_len - 1);
        let directory = create_deep_policy_directory(workspace.path(), &relative_directory);
        let mut paths = Vec::new();
        for index in 0..2 {
            let filename = format!("duplicate-{index:03}.rqlp");
            directory
                .write(&filename, &source)
                .expect("write oversized duplicate policy");
            let relative = format!("{relative_directory}/{filename}");
            assert_eq!(relative.len(), source_len);
            paths.push(PathBuf::from(relative));
        }

        let forward = evaluate_policy_files(workspace.path(), &paths, &evaluation_options())
            .expect("oversized duplicate report");
        paths.reverse();
        let reversed = evaluate_policy_files(workspace.path(), &paths, &evaluation_options())
            .expect("reversed oversized duplicate report");

        assert_invalid_source_diagnostics(&forward, &[source_len, source_len]);
        assert!(forward.report().diagnostics().iter().all(|diagnostic| {
            diagnostic
                .message()
                .contains("policy source identity must be at most 1024 bytes")
        }));
        assert_eq!(
            canonical_report_bytes(&forward),
            canonical_report_bytes(&reversed)
        );
    }

    #[test]
    fn missing_oversized_and_control_sources_have_bounded_canonical_diagnostics() {
        let workspace = tempfile::tempdir().expect("workspace");
        let missing_len = 8 * 1024 + 257;
        let filename = "missing-policy.rqlp";
        let relative_directory = relative_directory_with_len(missing_len - filename.len() - 1);
        let missing = PathBuf::from(format!("{relative_directory}/{filename}"));
        assert_eq!(missing.to_string_lossy().len(), missing_len);
        let control = PathBuf::from("policies/control-source\n.rqlp");
        let control_len = control.to_string_lossy().len();
        let mut paths = vec![missing.clone(), control.clone()];

        let forward = evaluate_policy_files(workspace.path(), &paths, &evaluation_options())
            .expect("invalid requested-source report");
        paths.reverse();
        let reversed = evaluate_policy_files(workspace.path(), &paths, &evaluation_options())
            .expect("reversed invalid requested-source report");

        assert_invalid_source_diagnostics(&forward, &[missing_len, control_len]);
        assert!(forward.report().diagnostics().iter().any(|diagnostic| {
            diagnostic
                .message()
                .contains("policy source identity must be at most 1024 bytes")
        }));
        assert!(forward.report().diagnostics().iter().any(|diagnostic| {
            diagnostic
                .message()
                .contains("policy source identity must not contain control characters")
        }));
        for diagnostic in forward.report().diagnostics() {
            assert!(!diagnostic.message().contains("control-source"));
            assert!(!diagnostic.message().contains('\n'));
            assert_ne!(
                diagnostic.source().unwrap().as_str(),
                missing.to_string_lossy()
            );
            assert_ne!(
                diagnostic.source().unwrap().as_str(),
                control.to_string_lossy()
            );
        }
        assert_eq!(
            canonical_report_bytes(&forward),
            canonical_report_bytes(&reversed)
        );
    }

    #[test]
    fn cumulative_registry_limit_uses_policy_id_order_not_argument_order() {
        let workspace = tempfile::tempdir().expect("workspace");
        fs::write(
            workspace.path().join("app.ts"),
            "export function other() {}\n",
        )
        .expect("source fixture");
        let first_source = match_policy("test.a", "A");
        let second_source = match_policy("test.z", "Z");
        write_policy(workspace.path(), "policies/a.rqlp", &first_source);
        write_policy(workspace.path(), "policies/z.rqlp", &second_source);
        let limits = PolicyRegistryLimits::default()
            .with_max_retained_source_and_selector_bytes(
                first_source.len().max(second_source.len()),
            )
            .unwrap();

        let evaluate = |paths: &[PathBuf]| {
            evaluate_policy_files_with_limits(
                workspace.path(),
                paths,
                &evaluation_options(),
                PolicyBatchBudget::default(),
                limits,
            )
            .expect("bounded registry report")
        };
        let reversed = evaluate(&[
            PathBuf::from("policies/z.rqlp"),
            PathBuf::from("policies/a.rqlp"),
        ]);
        let forward = evaluate(&[
            PathBuf::from("policies/a.rqlp"),
            PathBuf::from("policies/z.rqlp"),
        ]);

        assert_eq!(reversed.exit_status(), POLICY_EXIT_UNRELIABLE);
        assert_eq!(
            canonical_report_bytes(&reversed),
            canonical_report_bytes(&forward)
        );
        assert_eq!(reversed.report().rules().len(), 1);
        assert_eq!(reversed.report().rules()[0].policy_id().as_str(), "test.a");
        assert_eq!(reversed.report().diagnostics().len(), 1);
        assert_eq!(
            reversed.report().diagnostics()[0]
                .source()
                .map(PolicySourceIdentity::as_str),
            Some("policies/z.rqlp")
        );
    }

    #[test]
    fn match_directory_entry_limit_retains_its_report_diagnostic_code() {
        let workspace = tempfile::tempdir().expect("workspace");
        fs::create_dir(workspace.path().join("endpoints")).expect("endpoint directory");
        for name in ["ignored-a.txt", "ignored-b.txt", "ignored-c.txt"] {
            fs::write(workspace.path().join("endpoints").join(name), "ignored")
                .expect("irrelevant directory entry");
        }
        write_policy(
            workspace.path(),
            "policies/limit.rqlp",
            r#"(policy
  :schema-version 1
  :id "test.directory-limit"
  :name "Directory limit"
  :message (generated-message :relation can-reach)
  :severity warning
  :analysis
    (analysis
      :type taint
      :mode may
      :sources
        (endpoint-set :include-matches [
          (match-directory :path "endpoints" :scope recursive
            :categories (all [input.user]))])
      :sinks
        (endpoint-set :include-matches [
          (match-directory :path "endpoints" :scope recursive
            :categories (all [output.sensitive]))])))"#,
        );
        let limits = PolicyRegistryLimits::default()
            .with_max_match_directory_entries(2)
            .expect("lower directory-entry limit");

        let outcome = evaluate_policy_files_with_limits(
            workspace.path(),
            &[PathBuf::from("policies/limit.rqlp")],
            &evaluation_options(),
            PolicyBatchBudget::default(),
            limits,
        )
        .expect("bounded directory report");

        assert_eq!(outcome.exit_status(), POLICY_EXIT_UNRELIABLE);
        assert!(outcome.report().rules().is_empty());
        assert!(outcome.report().runs().is_empty());
        assert_eq!(outcome.report().diagnostics().len(), 1);
        assert_eq!(
            outcome.report().diagnostics()[0].code(),
            PolicyReportDiagnosticCode::MatchDirectoryLimit
        );
        assert!(
            outcome.report().diagnostics()[0]
                .message()
                .contains("more than 2 total entries")
        );
    }

    #[test]
    fn applied_suppressions_are_retained_first_and_omission_is_explicitly_unreliable() {
        let workspace = tempfile::tempdir().expect("workspace");
        fs::write(
            workspace.path().join("app.ts"),
            "export function target() {}\n",
        )
        .expect("source fixture");
        write_policy(
            workspace.path(),
            "policies/a.rqlp",
            &match_policy("test.a", "A"),
        );
        write_policy(
            workspace.path(),
            "policies/z.rqlp",
            &match_policy("test.z", "Z"),
        );
        let paths = [
            PathBuf::from("policies/a.rqlp"),
            PathBuf::from("policies/z.rqlp"),
        ];
        let baseline = evaluate_policy_files(workspace.path(), &paths, &evaluation_options())
            .expect("baseline report");
        let rule = baseline
            .report()
            .rules()
            .iter()
            .find(|rule| rule.policy_id().as_str() == "test.z")
            .expect("test.z rule");
        let finding = baseline
            .report()
            .runs()
            .iter()
            .find(|run| run.policy_id().as_str() == "test.z")
            .expect("test.z run")
            .findings()[0]
            .id();
        write_test_suppression(
            workspace.path(),
            "test.z",
            &rule.policy_hash().to_string(),
            &finding.to_string(),
        );

        let one_result_budget = PolicyBatchBudget::builder()
            .with_max_total_findings(1)
            .unwrap()
            .build()
            .unwrap();
        let retained = evaluate_policy_files_with_limits(
            workspace.path(),
            &paths,
            &evaluation_options(),
            one_result_budget,
            PolicyRegistryLimits::default(),
        )
        .expect("one-result report");
        let retained_findings = retained
            .report()
            .runs()
            .iter()
            .flat_map(PolicyRun::findings)
            .collect::<Vec<_>>();
        assert_eq!(retained_findings.len(), 1);
        assert_eq!(retained_findings[0].policy_id().as_str(), "test.z");
        assert!(retained_findings[0].suppression().is_some());
        assert!(retained.report().suppressions()[0].applied());
        assert!(!retained.report().suppressions()[0].result_omitted());

        let zero_result_budget = PolicyBatchBudget::builder()
            .with_max_total_findings(0)
            .unwrap()
            .build()
            .unwrap();
        let omitted = evaluate_policy_files_with_limits(
            workspace.path(),
            &paths,
            &evaluation_options(),
            zero_result_budget,
            PolicyRegistryLimits::default(),
        )
        .expect("zero-result report");
        assert_eq!(omitted.exit_status(), POLICY_EXIT_UNRELIABLE);
        assert!(
            omitted
                .report()
                .runs()
                .iter()
                .all(|run| run.findings().is_empty())
        );
        assert!(omitted.report().suppressions()[0].applied());
        assert!(omitted.report().suppressions()[0].result_omitted());
        assert!(omitted.report().diagnostics().iter().any(|diagnostic| {
            diagnostic.code() == PolicyReportDiagnosticCode::SuppressionAuditRetentionExceeded
        }));
    }

    fn run_git(dir: &Path, args: &[&str]) {
        let output = std::process::Command::new("git")
            .current_dir(dir)
            .args(["-c", "commit.gpgSign=false"])
            .args(args)
            .output()
            .expect("run git");
        assert!(
            output.status.success(),
            "git {args:?} failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    fn init_git_workspace(root: &Path) {
        run_git(root, &["init"]);
        run_git(root, &["config", "user.email", "test@example.com"]);
        run_git(root, &["config", "user.name", "Test User"]);
    }

    fn commit_everything(root: &Path, message: &str) {
        run_git(root, &["add", "."]);
        run_git(root, &["commit", "-m", message]);
    }

    fn identity_map(report: &PolicyReportDocument) -> HashMap<PolicyId, HashSet<PolicyFindingId>> {
        let mut identities: HashMap<PolicyId, HashSet<PolicyFindingId>> = HashMap::new();
        for run in report.runs() {
            for finding in run.findings() {
                identities
                    .entry(run.policy_id().clone())
                    .or_default()
                    .insert(finding.id());
            }
        }
        identities
    }

    #[test]
    fn diff_join_classifies_new_persisting_and_fixed_findings() {
        let policy = match_policy("test.diff", "Diff test");
        let base = tempfile::tempdir().expect("base workspace");
        fs::write(base.path().join("app.ts"), "export function target() {}\n")
            .expect("base source");
        write_policy(base.path(), "policies/diff.rqlp", &policy);
        let base_outcome = evaluate_policy_files(
            base.path(),
            &[PathBuf::from("policies/diff.rqlp")],
            &evaluation_options(),
        )
        .expect("base evaluation");
        assert_eq!(base_outcome.report().runs()[0].findings().len(), 1);

        let head = tempfile::tempdir().expect("head workspace");
        fs::write(head.path().join("app.ts"), "export function target() {}\n")
            .expect("head source");
        fs::write(
            head.path().join("extra.ts"),
            "export function target() { return 2; }\n",
        )
        .expect("head extra source");
        write_policy(head.path(), "policies/diff.rqlp", &policy);
        let head_outcome = evaluate_policy_files(
            head.path(),
            &[PathBuf::from("policies/diff.rqlp")],
            &evaluation_options(),
        )
        .expect("head evaluation");

        let baseline = PolicyDiffBaseline {
            requested_revision: "HEAD".to_string(),
            resolved_commit: "0".repeat(40),
            identities: identity_map(base_outcome.report()),
            unreliable_detail: None,
        };
        let mut runs = head_outcome
            .report()
            .runs()
            .iter()
            .map(|run| (run.policy_id().clone(), run.clone()))
            .collect::<HashMap<_, _>>();
        let review = apply_policy_diff(&baseline, &mut runs).expect("diff join");

        assert!(!review.degraded());
        assert_eq!(review.new_count(), 1);
        assert_eq!(review.persisting_count(), 1);
        assert_eq!(review.fixed_count(), 0);
        assert!(review.fixed().is_empty());
        let policy_id = PolicyId::new("test.diff").expect("policy id");
        for finding in runs[&policy_id].findings() {
            let diff = finding.diff().expect("attached diff decision");
            assert!(!diff.weak_identity());
            match finding.primary().path() {
                "app.ts" => assert_eq!(diff.disposition(), FindingDiffDisposition::Persisting),
                "extra.ts" => assert_eq!(diff.disposition(), FindingDiffDisposition::New),
                other => panic!("unexpected finding path {other}"),
            }
        }
        let mut cleared = runs[&policy_id].findings()[0].clone();
        cleared.clear_diff();
        assert!(cleared.diff().is_none());

        // Reverse the direction: the extra.ts identity becomes fixed.
        let reversed_baseline = PolicyDiffBaseline {
            requested_revision: "HEAD".to_string(),
            resolved_commit: "0".repeat(40),
            identities: identity_map(head_outcome.report()),
            unreliable_detail: None,
        };
        let mut reversed_runs = base_outcome
            .report()
            .runs()
            .iter()
            .map(|run| (run.policy_id().clone(), run.clone()))
            .collect::<HashMap<_, _>>();
        let reversed = apply_policy_diff(&reversed_baseline, &mut reversed_runs).expect("join");
        assert_eq!(reversed.new_count(), 0);
        assert_eq!(reversed.persisting_count(), 1);
        assert_eq!(reversed.fixed_count(), 1);
        assert_eq!(reversed.fixed().len(), 1);
        assert_eq!(reversed.fixed()[0].policy_id().as_str(), "test.diff");
        assert!(!reversed.fixed_truncated());
    }

    /// A truncated fixed list must retain the same 256 identities in every
    /// process. The baseline is a hash map, so before the join sorted its
    /// candidates the retained subset was whatever iteration order handed it
    /// first, which made two runs of the same build over the same inputs
    /// disagree on the reported list while agreeing on the count.
    #[test]
    fn truncated_fixed_list_retains_the_smallest_identities_deterministically() {
        const IDENTITIES_PER_POLICY: usize = 150;

        // Two policies so the ordering exercises both comparator components.
        // The identity hex is the index, so identity order is index order and
        // the expected retained subset is computable by hand.
        let policy_ids =
            ["test.diff-a", "test.diff-b"].map(|id| PolicyId::new(id).expect("fixture policy id"));
        let finding_ids = (0..IDENTITIES_PER_POLICY)
            .map(|index| {
                format!("{index:064x}")
                    .parse::<PolicyFindingId>()
                    .expect("fixture finding id")
            })
            .collect::<Vec<_>>();
        let expected = policy_ids
            .iter()
            .flat_map(|policy_id| {
                finding_ids
                    .iter()
                    .map(move |finding_id| (policy_id.clone(), *finding_id))
            })
            .take(MAX_DIFF_FIXED_FINDINGS)
            .collect::<Vec<_>>();

        // Two baselines built in opposite insertion orders. `HashMap` gives
        // them different iteration orders, so an implementation that truncated
        // before sorting would retain different identities in the two joins.
        let baseline_of = |reversed: bool| {
            let mut identities: HashMap<PolicyId, HashSet<PolicyFindingId>> = HashMap::new();
            for policy_id in &policy_ids {
                let entry = identities.entry(policy_id.clone()).or_default();
                if reversed {
                    entry.extend(finding_ids.iter().rev().copied());
                } else {
                    entry.extend(finding_ids.iter().copied());
                }
            }
            PolicyDiffBaseline {
                requested_revision: "HEAD".to_string(),
                resolved_commit: "0".repeat(40),
                identities,
                unreliable_detail: None,
            }
        };

        let mut reviews = Vec::new();
        for reversed in [false, true] {
            let baseline = baseline_of(reversed);
            let mut runs = HashMap::new();
            reviews.push(apply_policy_diff(&baseline, &mut runs).expect("diff join"));
        }
        let [first, second] = &reviews[..] else {
            panic!("two joins produce two reviews");
        };

        assert_eq!(first.new_count(), 0);
        assert_eq!(first.persisting_count(), 0);
        assert_eq!(
            first.fixed_count(),
            u64::try_from(2 * IDENTITIES_PER_POLICY).expect("fixture count fits u64"),
        );
        assert_eq!(first.fixed().len(), MAX_DIFF_FIXED_FINDINGS);
        assert!(first.fixed_truncated());
        assert_eq!(
            first
                .fixed()
                .iter()
                .map(|entry| (entry.policy_id().clone(), entry.finding_id()))
                .collect::<Vec<_>>(),
            expected,
        );
        assert_eq!(first.fixed(), second.fixed());
    }

    #[test]
    fn diff_base_gates_only_new_findings_and_reports_fixed() {
        let workspace = tempfile::tempdir().expect("workspace");
        init_git_workspace(workspace.path());
        fs::write(
            workspace.path().join("app.ts"),
            "export function target() {}\n",
        )
        .expect("source fixture");
        write_policy(
            workspace.path(),
            "policies/diff.rqlp",
            &match_policy("test.diff", "Diff test"),
        );
        commit_everything(workspace.path(), "base");

        let gating_date = PolicyEvaluationDate::from_ymd(2026, 7, 27).expect("fixed test date");
        let diff_options = PolicyEvaluationOptions::new(gating_date)
            .with_fail_on(PolicyFailOn::Warning)
            .with_diff_base("HEAD".to_string());
        let full_options =
            PolicyEvaluationOptions::new(gating_date).with_fail_on(PolicyFailOn::Warning);
        let paths = [PathBuf::from("policies/diff.rqlp")];

        // The committed finding persists and does not gate in diff mode.
        let clean = evaluate_policy_files(workspace.path(), &paths, &diff_options)
            .expect("diff evaluation");
        assert_eq!(clean.exit_status(), POLICY_EXIT_CLEAN);
        let review = clean.report().diff().expect("diff review");
        assert!(!review.degraded());
        assert_eq!(
            (
                review.new_count(),
                review.persisting_count(),
                review.fixed_count()
            ),
            (0, 1, 0)
        );
        assert_eq!(review.base_revision(), "HEAD");
        assert_eq!(review.base_commit().len(), 40);
        let encoded = serde_json::to_value(clean.report()).expect("encode diff report");
        assert_eq!(encoded["diff"]["persisting_count"], 1);
        assert_eq!(
            encoded["runs"][0]["findings"][0]["diff"]["disposition"],
            "persisting"
        );

        // The identical finding gates without the diff base, and its report
        // has no diff field at all.
        let full = evaluate_policy_files(workspace.path(), &paths, &full_options)
            .expect("full evaluation");
        assert_eq!(full.exit_status(), POLICY_EXIT_FINDING);
        assert!(full.report().diff().is_none());
        let encoded = serde_json::to_value(full.report()).expect("encode full report");
        assert!(encoded.get("diff").is_none());
        assert!(
            encoded["runs"][0]["findings"][0].get("diff").is_none(),
            "{encoded:#}"
        );

        // One new uncommitted finding gates with exactly itself as new.
        fs::write(
            workspace.path().join("extra.ts"),
            "export function target() { return 2; }\n",
        )
        .expect("new offending source");
        let gated = evaluate_policy_files(workspace.path(), &paths, &diff_options)
            .expect("diff evaluation with a new finding");
        assert_eq!(gated.exit_status(), POLICY_EXIT_FINDING);
        let review = gated.report().diff().expect("diff review");
        assert_eq!(
            (
                review.new_count(),
                review.persisting_count(),
                review.fixed_count()
            ),
            (1, 1, 0)
        );

        // Repairing every finding reports the committed one as fixed.
        fs::remove_file(workspace.path().join("extra.ts")).expect("remove new source");
        fs::write(workspace.path().join("app.ts"), "export const value = 1;\n")
            .expect("repaired source");
        let repaired = evaluate_policy_files(workspace.path(), &paths, &diff_options)
            .expect("diff evaluation after repair");
        assert_eq!(repaired.exit_status(), POLICY_EXIT_CLEAN);
        let review = repaired.report().diff().expect("diff review");
        assert_eq!(
            (
                review.new_count(),
                review.persisting_count(),
                review.fixed_count()
            ),
            (0, 0, 1)
        );
        assert_eq!(review.fixed().len(), 1);
        assert_eq!(review.fixed()[0].policy_id().as_str(), "test.diff");
    }

    /// The base of a `--diff-base` run must be analyzed the way the head was.
    /// The analyzer configuration selects dependency discovery, dispatch
    /// expansion and per-language behavior, and it is folded into every content
    /// identity a build publishes, so a base that built with a configuration of
    /// its own would answer a different question than the head it is joined
    /// with. The head here is host-supplied and carries a configuration neither
    /// the defaults nor the coordinator's owned configuration would produce.
    #[test]
    fn the_diff_base_analyzer_is_built_with_the_head_configuration() {
        let workspace = tempfile::tempdir().expect("workspace");
        init_git_workspace(workspace.path());
        fs::write(
            workspace.path().join("app.ts"),
            "export function target() {}\n",
        )
        .expect("source fixture");
        write_policy(
            workspace.path(),
            "policies/diff.rqlp",
            &match_policy("test.diff", "Diff test"),
        );
        commit_everything(workspace.path(), "base");

        let mut head_config = owned_policy_analyzer_config();
        head_config.dispatch_hierarchy_expansion = DispatchHierarchyExpansion::CONCRETE_OVERRIDES;
        assert_ne!(
            head_config,
            AnalyzerConfig::default(),
            "the fixture only means something if the head configuration is not the default"
        );
        let project: Arc<dyn Project> =
            Arc::new(FilesystemProject::new(workspace.path()).expect("head project"));
        let head = WorkspaceAnalyzer::build_persisted(project, head_config.clone())
            .expect("head analyzer");
        assert_eq!(head.config(), Some(&head_config));

        // The whole host-supplied diff path still runs and joins.
        let gating_date = PolicyEvaluationDate::from_ymd(2026, 7, 27).expect("fixed test date");
        let diff_options = PolicyEvaluationOptions::new(gating_date)
            .with_fail_on(PolicyFailOn::Warning)
            .with_diff_base("HEAD".to_string());
        let outcome = evaluate_policy_inputs_with_analyzer(
            workspace.path(),
            &[PolicyEvaluationInput::workspace_file(PathBuf::from(
                "policies/diff.rqlp",
            ))],
            &head,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &diff_options,
            None,
        )
        .expect("diff evaluation over a host-supplied head workspace");
        assert_eq!(outcome.exit_status(), POLICY_EXIT_CLEAN);
        let review = outcome.report().diff().expect("diff review");
        assert!(!review.degraded());
        assert_eq!(
            (
                review.new_count(),
                review.persisting_count(),
                review.fixed_count()
            ),
            (0, 1, 0)
        );

        // That run's base came from this function, which takes its
        // configuration from the head workspace rather than choosing one.
        let export = export_revision(workspace.path(), "HEAD").expect("export the base revision");
        let (base, base_config) = build_diff_base_workspace(&export, workspace.path(), &head)
            .expect("base analyzer workspace");
        assert_eq!(base_config, head_config);
        assert_eq!(base.workspace().config(), head.config());
    }

    #[test]
    fn unreliable_diff_base_degrades_to_full_gating_with_a_loud_diagnostic() {
        let workspace = tempfile::tempdir().expect("workspace");
        init_git_workspace(workspace.path());
        fs::write(
            workspace.path().join("app.ts"),
            "export function target() {}\n",
        )
        .expect("source fixture");
        write_policy(
            workspace.path(),
            "policies/diff.rqlp",
            &match_policy("test.diff", "Diff test"),
        );
        // The committed suppressions document is invalid, so the base
        // evaluation is unreliable by the ordinary reliability rules. The
        // working tree removes it, so the head evaluation stays reliable.
        let suppressions = workspace.path().join(".bifrost/suppressions.json");
        fs::create_dir_all(suppressions.parent().expect("suppressions parent"))
            .expect("suppressions directory");
        fs::write(&suppressions, "{ not json").expect("invalid suppressions");
        commit_everything(workspace.path(), "base with broken suppressions");
        fs::remove_file(&suppressions).expect("repair working tree");

        let gating_date = PolicyEvaluationDate::from_ymd(2026, 7, 27).expect("fixed test date");
        let diff_options = PolicyEvaluationOptions::new(gating_date)
            .with_fail_on(PolicyFailOn::Warning)
            .with_diff_base("HEAD".to_string());
        let outcome = evaluate_policy_files(
            workspace.path(),
            &[PathBuf::from("policies/diff.rqlp")],
            &diff_options,
        )
        .expect("degraded diff evaluation");

        // The degradation diagnostic makes the run itself unreliable, so the
        // broken base can never be mistaken for a clean diff run.
        assert_eq!(outcome.exit_status(), POLICY_EXIT_UNRELIABLE);
        let review = outcome.report().diff().expect("diff review");
        assert!(review.degraded());
        assert_eq!(review.new_count(), 0);
        assert_eq!(review.persisting_count(), 0);
        assert_eq!(review.fixed_count(), 0);
        let diagnostic = outcome
            .report()
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code() == PolicyReportDiagnosticCode::DiffBaseUnreliable)
            .expect("degradation diagnostic");
        assert!(
            diagnostic.message().contains("SuppressionLoadFailed"),
            "{}",
            diagnostic.message()
        );
        // No finding carries a diff decision under degraded gating.
        assert!(
            outcome
                .report()
                .runs()
                .iter()
                .flat_map(PolicyRun::findings)
                .all(|finding| finding.diff().is_none())
        );
    }

    #[test]
    fn unresolvable_diff_base_and_non_git_root_fail_the_run() {
        let workspace = tempfile::tempdir().expect("workspace");
        init_git_workspace(workspace.path());
        fs::write(
            workspace.path().join("app.ts"),
            "export function target() {}\n",
        )
        .expect("source fixture");
        write_policy(
            workspace.path(),
            "policies/diff.rqlp",
            &match_policy("test.diff", "Diff test"),
        );
        commit_everything(workspace.path(), "base");

        let gating_date = PolicyEvaluationDate::from_ymd(2026, 7, 27).expect("fixed test date");
        let unresolvable =
            PolicyEvaluationOptions::new(gating_date).with_diff_base("does-not-exist".to_string());
        let Err(error) = evaluate_policy_files(
            workspace.path(),
            &[PathBuf::from("policies/diff.rqlp")],
            &unresolvable,
        ) else {
            panic!("unresolvable diff base must fail the run");
        };
        assert!(error.to_string().contains("does-not-exist"), "{error}");

        let plain = tempfile::tempdir().expect("non-git workspace");
        fs::write(plain.path().join("app.ts"), "export function target() {}\n")
            .expect("source fixture");
        write_policy(
            plain.path(),
            "policies/diff.rqlp",
            &match_policy("test.diff", "Diff test"),
        );
        let head_options =
            PolicyEvaluationOptions::new(gating_date).with_diff_base("HEAD".to_string());
        let Err(error) = evaluate_policy_files(
            plain.path(),
            &[PathBuf::from("policies/diff.rqlp")],
            &head_options,
        ) else {
            panic!("a non-git root must fail the diff run");
        };
        assert!(
            error.to_string().contains("not inside a git repository"),
            "{error}"
        );
    }
}
