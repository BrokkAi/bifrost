//! One-shot, collect-and-continue policy batch coordination.
//!
//! This module owns the boundary between capability-confined policy loading,
//! analyzer-backed evaluation, canonical report assembly, and CLI status
//! selection. Renderers consume only the returned [`PolicyReportDocument`].

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::IAnalyzer;
use brokk_bifrost_analysis::analyzer::common::language_for_file;
use brokk_bifrost_analysis::analyzer::packs_document::{
    WORKSPACE_PACKS_DOCUMENT_PATH, WorkspaceActivationError, WorkspaceActivationSources,
    WorkspacePacksActivation, WorkspacePacksConfig, activate_workspace_semantic_sources,
    imported_node_builtin_modules, load_workspace_packs_config, load_workspace_packs_config_at,
};
use brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest;
use brokk_bifrost_analysis::analyzer::semantic::{
    ConfigurationFingerprint, WorkspaceRelativePath, authored_procedure_target_identity,
};
use brokk_bifrost_analysis::analyzer::semantic_model::{
    ActiveSemanticModelShard, ActiveSemanticModelSnapshot, CatalogPackSourceKind, Completeness,
    DependencyPackDiagnosticSeverity, DependencyPackPreparationOutcome, Locator,
    ResolvedActiveSemanticModels, SemanticModelActivationExplanation,
    SemanticModelActivationPersistence, SemanticModelActivationRequest,
    SemanticModelActivationStatus, SemanticModelRuntimeOutcome, SemanticPackCatalog,
    StandardLibraryPackExpectation, StandardLibraryPackSelection, TypeKind,
    WORKSPACE_SEMANTIC_MODEL_DIRECTORY, acquire_active_semantic_models,
    workspace_semantic_models_not_active,
};
use brokk_bifrost_analysis::analyzer::store::policy_units::{
    PolicyEvaluationPolicyRow, PolicyEvaluationRow, PolicyEvaluationRowKey,
};
use brokk_bifrost_analysis::analyzer::usages::effects::ModeledProcedureKey;
use brokk_bifrost_analysis::analyzer::usages::effects::modeled_procedure_key_for_unit;
use brokk_bifrost_analysis::analyzer::{
    AnalyzerConfig, AnalyzerQueryScope, ChangedFacts, CodeUnit, DependencyPackActivationOutcome,
    DependencyPackEcosystem, FilesystemProject, Language, Project, ProjectFile, WorkspaceAnalyzer,
    WorkspaceFileListingCache,
};
use brokk_bifrost_analysis::path_normalization::NormalizePath;
use brokk_bifrost_analysis::path_utils::rel_path_string;
use brokk_bifrost_analysis::schema_version::SchemaVersionOrigin;
use brokk_bifrost_analysis::workspace_document::WorkspaceRoot;
use brokk_bifrost_rql::structural::CodeQueryExecutionLimits;
use brokk_bifrost_rql::structural::search::CodeQueryExecutionScope;
use brokk_bifrost_tools::diff_analysis::{
    RevisionExport, RevisionWorkspace, changed_buffer_ranges, export_revision,
    resolve_revision_subtree, worktree_paths_match_head,
};

use super::baseline::{
    DEFAULT_POLICY_BASELINE_PATH, PolicyBaselineDocument, PolicyBaselineEntryReview,
    PolicyBaselineMatchState, PolicyBaselineOptions, PolicyBaselineReview, PolicyFindingBaseline,
    load_policy_baseline_from_root,
};
use super::builtin::BuiltInPolicySelectionRecord;
use super::catalog::{CatalogRegistryLimits, TaintCatalogRegistry};
use super::definition::{
    FindingSeverity, PolicyCategoryId, PolicyId, RqlpDocument, UnknownVerdict,
};
use super::evaluator::{
    DefaultPolicyEvaluator, PolicyEvaluationContext, PolicyEvaluator,
    policy_supports_execution_scope, policy_uses_only_file_facts,
};
use super::finding::{FindingDiffDisposition, PolicyFindingDiff};
use super::finding::{
    PolicyDiagnostic, PolicyDiagnosticCode, PolicyDiagnosticImpact, PolicyDiagnosticSeverity,
    PolicyFailureReason, PolicyFinding, PolicyIncompleteReason, PolicyRun, PolicyRunCompletion,
    PolicyRunScope, PolicySelectionProvenance, PolicyWorkMetric, PolicyWorkReport, PolicyWorkUnit,
    UnavailablePolicyCapability,
};
use super::finding_identity::{FindingIdentityStability, PolicyFindingId};
use super::loading::{PolicyDocumentLoadError, read_rqlp_document};
use super::locator::is_qualified_locator_code;
use super::registry::{PolicyRegistry, PolicyRegistryError, PolicyRegistryLimits};
use super::report::{
    MAX_DIFF_FIXED_FINDINGS, PolicyDependencyPackActivationMode, PolicyDiffCounts,
    PolicyDiffFixedFinding, PolicyDiffReview, PolicyDiffUnqualifiedPolicy, PolicyExecutionMetadata,
    PolicyExecutionStage, PolicyExecutionTermination, PolicyOptionalReviews,
    PolicyPackActivationReview, PolicyPackDecision, PolicyPackDecisionStatus,
    PolicyPackProcedureSummaryEvidence, PolicyReportBuilder, PolicyReportBuilderError,
    PolicyReportDiagnostic, PolicyReportDiagnosticCode, PolicyReportDocument,
    PolicyRetentionOutcome, PolicyRuleDescriptor, PolicySourceRange, PolicyStageTiming,
};
use super::resolved::{
    EndpointDefinitionSchemaResolution, EndpointOrigin, LoadedPolicy, ResolvedEndpointIdentity,
    SelectorOrigin,
};
use super::retained::{RetainedSize, retained_extra};
use super::scope::{
    DEFAULT_POLICY_SCOPE_PATH, PolicyScopeDocument, PolicyScopeDocumentState, PolicyScopeOptions,
    PolicyScopeReview, PolicyScopeSource, load_policy_scope_from_root,
};
use super::source::{
    PolicySourceDiagnostic, PolicySourceIdentity, PolicySourceIdentityError,
    PolicySourceRelatedDiagnostic, parse_rqlp_source, validate_policy_source_identity,
};
use super::suppression::{
    CONVENTIONAL_POLICY_SUPPRESSION_PATHS, MAX_SUPPRESSION_REKEY_CANDIDATES, PolicyEvaluationDate,
    PolicyReportEvaluationContext, PolicySuppressionDocument, PolicySuppressionDocumentState,
    PolicySuppressionMatchState, PolicySuppressionOptions, PolicySuppressionOrphanState,
    PolicySuppressionPolicyHashState, PolicySuppressionPreflight, PolicySuppressionRecord,
    PolicySuppressionReview, PolicySuppressionSourceState, PolicySuppressionTemporalState,
    load_policy_suppressions_from_root,
};
use super::units::{
    InMemoryPolicyUnitStore, IncrementalBaseState, PersistedPolicyUnitStore,
    PolicyIncrementalContext, PolicyIncrementalReview, PolicyIncrementalRun, PolicyUnitStore,
    UnitSnapshots, WidenReason, WorkspaceUnitInputs, row_key, workspace_snapshot,
};

use super::taint_policy::{PolicyChangedFile, ProductionTaintPolicyEvaluator};
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

/// What the batch exit status makes of a run whose completion is Bifrost's own
/// `inconclusive` verdict: it ran, and could not prove there is nothing more
/// to find (#8111).
///
/// A policy's own `(on-unknown :verdict ...)` declaration (#2506) outranks
/// this caller choice where it says something: `warn-unreliable` keeps the run
/// advisory and `fail-closed` gates it as a finding, under either value.
/// `abstain`, the default, and `treat-may-as-finding`, which changes only what
/// is published, leave the run to this choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolicyOnInconclusive {
    /// Advisory: the run is reported, never gates, and the batch exits clean
    /// when no finding crosses the threshold. This is how SlopCop reads the
    /// same verdict, so the two never disagree on one report.
    #[default]
    Pass,
    /// The run is unreliable and the batch exits 2, whatever else it found.
    Unreliable,
}

impl PolicyOnInconclusive {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Unreliable => "unreliable",
        }
    }
}

/// How one run bears on the batch exit status. Every consumer of that
/// decision -- the exit status, the diff base's aggregate verdict, SARIF's
/// `executionSuccessful` -- classifies runs here, so they cannot drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyRunGate {
    /// The run proves a clean negative: complete, proven by authored-complete
    /// summaries, or a default selection that could not run.
    Clean,
    /// A verdict that never searched the whole program (a proven subset). It
    /// condemns the batch only when no finding gates it.
    Subset,
    /// Bifrost's own inconclusive verdict, advisory: reported, never gating.
    Inconclusive,
    /// No verdict the batch may rely on: the run failed, was unsupported, was
    /// explicitly requested and could not run, or was inconclusive under
    /// [`PolicyOnInconclusive::Unreliable`] with no policy declaration.
    Unreliable,
}

impl PolicyRunGate {
    pub fn of(run: &PolicyRun, on_inconclusive: PolicyOnInconclusive) -> Self {
        let completion = run.completion();
        if completion.permits_clean_negative() {
            Self::Clean
        } else if completion.is_reliable() {
            Self::Subset
        } else if completion.inconclusive_scope().is_some()
            && (on_inconclusive == PolicyOnInconclusive::Pass
                || matches!(
                    run.unknown_verdict(),
                    Some(UnknownVerdict::WarnUnreliable | UnknownVerdict::FailClosed)
                ))
        {
            Self::Inconclusive
        } else {
            Self::Unreliable
        }
    }
}

/// Which changed range a run asks about.
///
/// The range narrows only the taint composition's sinks. Every
/// other run, and every run of the ICFG engine, names the range it did not
/// narrow instead.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum PolicyRangeRequest {
    /// Every endpoint of the workspace.
    #[default]
    Workspace,
    /// The changed hunks of the diff base comparison. Sink procedures must
    /// overlap a hunk. Needs a diff base and incremental reuse.
    DiffBase,
    /// Exactly these workspace-relative files.
    Files(Vec<String>),
}

/// Advisory expected policy evaluation times, in milliseconds.
///
/// An ordered map permits empty hints in the const options constructor.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(try_from = "BTreeMap<String, u64>")]
pub struct PolicyCostHints(BTreeMap<String, u64>);

impl TryFrom<BTreeMap<String, u64>> for PolicyCostHints {
    type Error = String;

    fn try_from(hints: BTreeMap<String, u64>) -> Result<Self, Self::Error> {
        let max_policies = PolicyBatchBudget::default().max_policies();
        if hints.len() > max_policies {
            return Err(format!(
                "policy_cost_hints accepts at most {max_policies} entries"
            ));
        }
        if hints.contains_key("") {
            return Err("policy_cost_hints policy ids must be non-empty".to_string());
        }
        Ok(Self(hints))
    }
}

/// Complete deterministic host contract for one policy-evaluation batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEvaluationOptions {
    evaluation_date: PolicyEvaluationDate,
    suppressions: PolicySuppressionOptions,
    scope: PolicyScopeOptions,
    // The diff base uses the head's normalized execution domain, including no scope.
    scope_override: Option<Option<PolicyScopeDocument>>,
    baseline: PolicyBaselineOptions,
    require_explicit_schema_versions: bool,
    fail_on: PolicyFailOn,
    on_inconclusive: PolicyOnInconclusive,
    diff_base: Option<String>,
    /// Whether this batch may publish or reuse complete policy units in the
    /// repository's analyzer cache. Either kind of scan verifies a unit's
    /// inputs before reuse and publishes the units it recomputes. `false`
    /// evaluates in full and skips policy-unit cache access on either path.
    incremental: bool,
    /// Record each policy's evaluation wall time as the
    /// [`EVALUATION_ELAPSED_METRIC`] work metric of its run. Off by default:
    /// a timing changes from run to run, and the canonical report is
    /// byte-identical across successful runs unless the caller asks for
    /// timings (`run_policy` asks with `include_stage_timings`).
    policy_timings: bool,
    /// Request-owned scheduling advice, excluded from the report and its context.
    policy_cost_hints: PolicyCostHints,
    /// The built-in selection this batch was resolved from, recorded in the
    /// report's evaluation context. Absent when no built-in policy was selected.
    builtin_selection: Option<BuiltInPolicySelectionRecord>,
    /// The changed range the runs are scoped to.
    range: PolicyRangeRequest,
}

/// Work metric a run carries when [`PolicyEvaluationOptions::policy_timings`]
/// is on: the policy's own evaluation wall time in milliseconds. The batch's
/// `policy_evaluation` stage timing is the sum over policies; this is the
/// per-policy split of it.
pub const EVALUATION_ELAPSED_METRIC: &str = "evaluation.elapsed_ms";
const UNIT_PREFETCH_METRIC: &str = "units.prefetch_ms";
const UNIT_VERIFY_METRIC: &str = "units.verify_ms";
const UNIT_LOOKUP_REPLAY_METRIC: &str = "units.lookup_replay_ms";
const UNIT_RECOMPUTE_METRIC: &str = "units.recompute_ms";

impl PolicyEvaluationOptions {
    pub fn new(evaluation_date: PolicyEvaluationDate) -> Self {
        Self::with_suppressions(evaluation_date, PolicySuppressionOptions::default())
    }

    pub const fn with_suppressions(
        evaluation_date: PolicyEvaluationDate,
        suppressions: PolicySuppressionOptions,
    ) -> Self {
        Self {
            evaluation_date,
            suppressions,
            scope: PolicyScopeOptions::new(PolicyScopeSource::Conventional),
            scope_override: None,
            baseline: PolicyBaselineOptions::new(
                super::baseline::PolicyBaselineSource::Conventional,
            ),
            require_explicit_schema_versions: false,
            fail_on: PolicyFailOn::Never,
            on_inconclusive: PolicyOnInconclusive::Pass,
            diff_base: None,
            incremental: true,
            policy_timings: false,
            policy_cost_hints: PolicyCostHints(BTreeMap::new()),
            builtin_selection: None,
            range: PolicyRangeRequest::Workspace,
        }
    }

    /// Record the built-in selection this batch was resolved from.
    pub fn with_builtin_selection(mut self, selection: BuiltInPolicySelectionRecord) -> Self {
        self.builtin_selection = Some(selection);
        self
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

    pub const fn with_on_inconclusive(mut self, on_inconclusive: PolicyOnInconclusive) -> Self {
        self.on_inconclusive = on_inconclusive;
        self
    }

    /// Allow policy-unit publication and verified reuse, or force full
    /// evaluation without policy-unit cache access.
    pub const fn with_incremental(mut self, incremental: bool) -> Self {
        self.incremental = incremental;
        self
    }

    /// Record each policy's evaluation wall time in its run; see the field.
    pub const fn with_policy_timings(mut self, policy_timings: bool) -> Self {
        self.policy_timings = policy_timings;
        self
    }

    /// Start unknown policies first, then policies with the largest expected cost.
    pub fn with_policy_cost_hints(mut self, hints: PolicyCostHints) -> Self {
        self.policy_cost_hints = hints;
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

    pub const fn on_inconclusive(&self) -> PolicyOnInconclusive {
        self.on_inconclusive
    }

    pub fn diff_base(&self) -> Option<&str> {
        self.diff_base.as_deref()
    }

    pub const fn incremental(&self) -> bool {
        self.incremental
    }

    /// Scope the taint runs to a changed range.
    pub fn with_range(mut self, range: PolicyRangeRequest) -> Self {
        self.range = range;
        self
    }

    pub const fn range(&self) -> &PolicyRangeRequest {
        &self.range
    }
}

impl RetainedSize for PolicyEvaluationOptions {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(retained_extra(&self.suppressions))
            .saturating_add(retained_extra(&self.scope))
            .saturating_add(retained_extra(&self.baseline))
            .saturating_add(retained_extra(&self.diff_base))
            .saturating_add(self.policy_cost_hints.0.keys().fold(0usize, |bytes, id| {
                bytes
                    .saturating_add(std::mem::size_of::<(String, u64)>())
                    .saturating_add(id.capacity())
            }))
            .saturating_add(match &self.range {
                PolicyRangeRequest::Files(files) => retained_extra(files),
                PolicyRangeRequest::Workspace | PolicyRangeRequest::DiffBase => 0,
            })
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
    /// telemetry cannot live inside it. The incremental review carries that
    /// telemetry separately.
    incremental: Option<PolicyIncrementalReview>,
}

impl PolicyBatchOutcome {
    pub const fn report(&self) -> &PolicyReportDocument {
        &self.report
    }

    /// What this batch reused, per policy, or `None` when it could not reuse
    /// anything: `incremental` off, or a workspace that states no snapshot
    /// identity. A full scan reports its base as `evaluated`, because it has
    /// none to replay.
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
        required_capabilities: Vec<String>,
        selection_provenance: Option<PolicySelectionProvenance>,
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
            required_capabilities: Vec::new(),
            selection_provenance: None,
        }
    }

    /// A policy source the caller named by ID outside the catalog, such as a
    /// verified policy-bundle entry. Like a policy file, it declares no
    /// catalog capabilities.
    pub fn explicitly_selected(identity: PolicySourceIdentity, source: String) -> Self {
        Self::Embedded {
            identity,
            source,
            required_capabilities: Vec::new(),
            selection_provenance: Some(PolicySelectionProvenance::ExplicitPolicyId),
        }
    }

    pub fn selected_builtin(policy: super::builtin::SelectedBuiltInPolicy<'_>) -> Self {
        let manifest = policy.manifest();
        Self::Embedded {
            identity: policy.source_identity(),
            source: policy.source().to_owned(),
            required_capabilities: manifest.required_capabilities.clone(),
            selection_provenance: Some(policy.selection_provenance()),
        }
    }

    fn embedded_with_selection(
        identity: PolicySourceIdentity,
        source: impl Into<String>,
        required_capabilities: Vec<String>,
        selection_provenance: Option<PolicySelectionProvenance>,
    ) -> Self {
        Self::Embedded {
            identity,
            source: source.into(),
            required_capabilities,
            selection_provenance,
        }
    }
}

struct PreparedPolicy {
    needs_catalog_registry: bool,
    source: PolicySourceIdentity,
    bytes: String,
    policy_id: PolicyId,
    required_capabilities: Vec<String>,
    selection_provenance: Option<PolicySelectionProvenance>,
}

#[derive(Clone)]
struct SelectedPolicyMetadata {
    required_capabilities: Vec<String>,
    selection_provenance: PolicySelectionProvenance,
}

#[derive(Clone)]
struct DiffBasePolicyInput {
    policy_id: PolicyId,
    source: PolicySourceIdentity,
    bytes: String,
    required_capabilities: Vec<String>,
    selection_provenance: Option<PolicySelectionProvenance>,
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
        PolicyWorkspaceSource::Root,
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
        PolicyWorkspaceSource::Supplied(workspace),
        Some(flow_state),
        None,
        None,
        None,
        cancellation,
    )
}

/// Evaluate mixed policy inputs for a protocol host's session: an MCP server,
/// or a scoped CLI session.
///
/// Policy evaluation answers one question whatever asks it. The CLI, the
/// GitHub action, an MCP session and a full scan all evaluate on a workspace
/// analyzed under the default analyzer configuration and activated with the
/// policy's own semantic sources -- the shipped models, the repository's
/// reviewed models and its packs document -- so their findings, their content
/// identities and the keys of the evidence they publish agree, and one entry
/// point's published units serve another's later run. A session's own
/// analyzer and activation serve its other tools under the configuration
/// those tools need. When that configuration matches, the coordinator borrows
/// the session's analyzer and projection. Otherwise it builds the policy workspace
/// over the session's project, languages and store -- the files and overlays
/// the session sees, the facts it already parsed. It activates policy sources itself.
/// The session's activation is not borrowed.
pub fn evaluate_policy_inputs_for_host_session(
    root: impl AsRef<Path>,
    policy_inputs: &[PolicyEvaluationInput],
    session: &WorkspaceAnalyzer,
    options: &PolicyEvaluationOptions,
    cancellation: Option<&CancellationToken>,
) -> Result<PolicyBatchOutcome, PolicyCoordinatorError> {
    evaluate_policy_inputs_with_limits(
        root.as_ref(),
        policy_inputs,
        options,
        PolicyBatchBudget::default(),
        PolicyRegistryLimits::default(),
        PolicyWorkspaceSource::HostSession(session),
        None,
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
        PolicyWorkspaceSource::Supplied(workspace),
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
        PolicyWorkspaceSource::Supplied(workspace),
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
    )
    .with_builtin_selection(options.builtin_selection.clone());
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
    Ok(unreliable_empty_policy_outcome(
        report,
        complete_stage_timings,
        batch_budget,
    ))
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

/// Deadline outcome for a run whose budget expired while its diff base was
/// being materialized, built, or evaluated.
///
/// The phase is named in the report so a caller can tell a base it never
/// reached from one that was evaluated and found unreliable: the latter
/// degrades gating with `DiffBaseUnreliable` and still evaluates the head,
/// while this outcome says the budget ended the run and every policy is
/// pending. Nothing of the head ran, so `runs` is empty and the report carries
/// no diff review at all.
#[allow(clippy::too_many_arguments)]
fn diff_base_deadline_outcome(
    options: &PolicyEvaluationOptions,
    batch_budget: PolicyBatchBudget,
    suppression_sources: Vec<PolicySuppressionSourceState>,
    scope_document_state: PolicyScopeDocumentState,
    registration_elapsed: Duration,
    preparation_elapsed: Duration,
    diff_base_elapsed: Duration,
    pending_policy_ids: Vec<PolicyId>,
    revision: &str,
) -> Result<PolicyBatchOutcome, PolicyCoordinatorError> {
    let diagnostic = report_diagnostic(
        PolicyReportDiagnosticCode::DiffBaseDeadlineExceeded,
        format!(
            "the request-wide time budget expired while the diff base `{revision}` was being \
             evaluated; no policy was evaluated against the head"
        ),
        None,
        None,
        Vec::new(),
    )?;
    deadline_before_evaluation_outcome(
        options,
        batch_budget,
        suppression_sources,
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
            PolicyStageTiming::from_duration(PolicyExecutionStage::DiffBase, diff_base_elapsed),
        ],
        PolicyExecutionStage::DiffBase,
        pending_policy_ids,
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
    )
    .with_builtin_selection(options.builtin_selection.clone());
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
    Ok(unreliable_empty_policy_outcome(
        report,
        stage_attribution,
        batch_budget,
    ))
}

fn unreliable_empty_policy_outcome(
    report: PolicyReportDocument,
    stage_attribution: Vec<PolicyStageTiming>,
    batch_budget: PolicyBatchBudget,
) -> PolicyBatchOutcome {
    PolicyBatchOutcome {
        report,
        stage_attribution,
        taint_findings: Vec::new(),
        taint_analysis_results: Vec::new(),
        exit_status: POLICY_EXIT_UNRELIABLE,
        max_retained_report_bytes: batch_budget.max_retained_report_bytes(),
        max_serialized_report_bytes: batch_budget.max_serialized_report_bytes(),
        incremental: None,
    }
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

    let policy_inputs = policy_files
        .iter()
        .cloned()
        .map(PolicyEvaluationInput::WorkspaceFile)
        .collect::<Vec<_>>();
    let (root, read_root, inputs) = prepare_policy_inputs(root, &policy_inputs, None)?;

    evaluate_prepared_policy_inputs(
        &root,
        &read_root,
        inputs,
        options,
        batch_budget,
        registry_limits,
        PolicyWorkspaceSource::Root,
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
    workspace_source: PolicyWorkspaceSource<'_>,
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

    let (root, read_root, inputs) = prepare_policy_inputs(root, policy_inputs, cancellation)?;
    evaluate_prepared_policy_inputs(
        &root,
        &read_root,
        inputs,
        options,
        batch_budget,
        registry_limits,
        workspace_source,
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
        PolicyWorkspaceSource::Supplied(workspace),
        Some(flow_state),
        options,
        suppression_preflight,
        None,
        cancellation,
    )
}

/// [`evaluate_policy_inputs_for_host_session`] with suppression configuration
/// the host already validated before it waited for its session.
pub fn evaluate_policy_inputs_for_host_session_with_suppression_preflight(
    root: impl AsRef<Path>,
    policy_inputs: &[PolicyEvaluationInput],
    session: &WorkspaceAnalyzer,
    options: &PolicyEvaluationOptions,
    suppression_preflight: PolicySuppressionPreflight,
    cancellation: Option<&CancellationToken>,
) -> Result<PolicyBatchOutcome, PolicyCoordinatorError> {
    evaluate_policy_inputs_with_analyzer_and_suppression_preflight_impl(
        root,
        policy_inputs,
        PolicyWorkspaceSource::HostSession(session),
        None,
        options,
        suppression_preflight,
        None,
        cancellation,
    )
}

#[allow(clippy::too_many_arguments)]
fn evaluate_policy_inputs_with_analyzer_and_suppression_preflight_impl(
    root: impl AsRef<Path>,
    policy_inputs: &[PolicyEvaluationInput],
    workspace_source: PolicyWorkspaceSource<'_>,
    flow_state: Option<&brokk_bifrost_flow::FlowWorkspaceState>,
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
    let (root, read_root, inputs) =
        prepare_policy_inputs(root.as_ref(), policy_inputs, cancellation)?;
    evaluate_prepared_policy_inputs(
        &root,
        &read_root,
        inputs,
        options,
        batch_budget,
        PolicyRegistryLimits::default(),
        workspace_source,
        flow_state,
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
/// Evaluation may borrow a matching host workspace; explanation may build a
/// short-lived one. Keep their activation authority in one place so shipped models,
/// reviewed workspace models, and dependency packs cannot diverge between the
/// report and the explanation of that report.
pub(crate) fn activate_owned_policy_workspace(
    root: &Path,
    workspace: &WorkspaceAnalyzer,
    config: Option<&WorkspacePacksConfig>,
    cancellation: &CancellationToken,
) -> Result<Option<WorkspacePacksActivation>, WorkspaceActivationError> {
    activate_workspace_semantic_sources(
        workspace,
        &AnalyzerConfig::default(),
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

/// Query limits for one trusted whole-workspace code query.
///
/// A host that already trusts the query document -- a CLI invocation, or the
/// private correctness corpus -- can ask for the same source-volume scaling
/// that policy evaluation gets. The interactive `CodeQueryExecutionLimits`
/// defaults size one bounded request over an unknown workspace, so on a real
/// checkout they stop a whole-repository question well before it finishes: the
/// pinned bbolt endpoint query attempted 33,289 source mappings against the
/// fixed default of 33,288 and returned nothing.
///
/// This is deliberately the identical computation policy evaluation performs,
/// not a second scaling rule, so the two entry points cannot drift. The
/// allowance comes from the analyzed source volume and the host's decision to
/// call this, never from the query document, which must not be able to raise
/// its own limits.
pub fn workspace_scaled_query_limits(workspace: &WorkspaceAnalyzer) -> CodeQueryExecutionLimits {
    policy_budget_for_workspace(PolicyBudget::default(), Some(workspace)).query_limits()
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

/// The policy capabilities this engine provides, sorted. A policy that
/// requires any other capability is reported as not run, with the missing
/// names, instead of running without the analysis it depends on. Open-pack
/// acquisition does not reject a release for these names; it admits the
/// release and leaves the decision to each policy.
///
/// Advertise a name only when an in-tree policy that requires it is exercised
/// by the test suite through its catalog requirements. Retained policy packs,
/// the `capability-admission` golden cases and focused catalog-selection
/// regressions supply that evidence. One test checks every retained pack
/// requirement against this list; another checks that every name here is
/// required by one of those exercised policies.
pub const ENGINE_POLICY_CAPABILITIES: &[&str] = &[
    "absent-member",
    "actual-to-formal-binding",
    "assignment-relations",
    "bounded-caller-reachability",
    "branch-relations",
    "call-argument-conversion",
    "callable-metrics",
    "callable-signature",
    "canonical-external-dispatch",
    "class-set-type-flow",
    "conditional-result-contracts",
    "configuration-facts",
    "declaration-attributes",
    "declaration-bounded-containment",
    "declaration-selection-imports",
    "declared-store-boundary",
    "descendant-match",
    "endpoint-categories",
    "endpoint-set-imports",
    "exact-call-target",
    "exact-result-use",
    "exhaustive-effect-coverage",
    "external-api-identity",
    "failure-edge-control",
    "failure-handler-state",
    "flow",
    "guard-dominance",
    "interprocedural-transfer",
    "javadoc-facts",
    "language-rule-facts",
    "lexical-environment",
    "literal-occurrences",
    "loop-relations",
    "module-identity-declaration-selection",
    "native-result-obligation",
    "nilness-operations",
    "normal-and-exceptional-exit",
    "normalized-call",
    "normalized-call-roles",
    "operation-precondition-contracts",
    "origin-shape-assertion",
    "pending-cleanup-flow",
    "prepared-c-syntax",
    "prepared-syntax",
    "procedure-local-scalar-refinement",
    "python-call-relations",
    "python-cfg",
    "python-class-hierarchy",
    "python-declaration-models",
    "python-import-cycles",
    "python-import-site",
    "reaching-binding-assertion",
    "reaching-definitions",
    "resolved-call-target",
    "result-contract-failure-uses",
    "result-contract-operation-uses",
    "reviewed-csharp-bcl-result-obligation",
    "reviewed-javascript-string-result-obligation",
    "reviewed-jdk-result-obligation",
    "reviewed-libc-result-obligation",
    "reviewed-php-result-obligation",
    "reviewed-python-builtin-result-obligation",
    "reviewed-python-result-obligation",
    "reviewed-ruby-core-result-obligation",
    "reviewed-typescript-string-result-obligation",
    "runtime-keyed-read",
    "same-evaluation",
    "scalar-state",
    "scoped-callable-completeness",
    "semantic-control-flow",
    "semantic-guard-facts",
    "semantic-model-declared-effects",
    "semantic-model-provenance",
    "statement-facts",
    "statement-reachability",
    "structural-match",
    "taint",
    "terminal-obligation",
    "transitive-procedure-effects",
    "typestate",
    "value-origin-assertion",
];

enum PolicyCapabilityAvailability {
    Available,
    Unavailable { reason: String },
}

fn policy_capability_availability(
    label: &str,
    snapshot: Option<&ActiveSemanticModelSnapshot>,
    workspace_has_python_source: bool,
) -> PolicyCapabilityAvailability {
    match label {
        "python-declaration-models"
            if workspace_has_python_source
                && !snapshot.is_some_and(|snapshot| {
                    snapshot.publishes_complete_declaration_surface_for("python")
                }) =>
        {
            PolicyCapabilityAvailability::Unavailable {
                reason: "the active semantic snapshot does not publish a complete Python declaration surface".to_owned(),
            }
        }
        _ if ENGINE_POLICY_CAPABILITIES.binary_search(&label).is_err() => {
            PolicyCapabilityAvailability::Unavailable {
                reason: format!("this engine does not provide the `{label}` capability"),
            }
        }
        _ => PolicyCapabilityAvailability::Available,
    }
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
    active.visit_procedure_summary_targets(|manifest_digest, language, targets| {
        for (id, target) in targets {
            if let Some((owner, member)) =
                authored_procedure_target_identity(&target.path, &target.symbol)
            {
                target_member_identifiers.insert(member.to_owned());
                summaries_by_key
                    .entry(ModeledProcedureKey {
                        language: language.to_owned(),
                        owner: owner.into_owned(),
                        member: member.to_owned(),
                        has_receiver: target.has_receiver,
                        parameter_count: target.parameter_count,
                    })
                    .or_default()
                    .push((manifest_digest.to_owned(), id.to_owned()));
            }
            counts.insert((manifest_digest.to_owned(), id.to_owned()), 0);
        }
    });
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
    active.visit_procedure_summary_targets(|manifest_digest, _language, targets| {
        let entries = evidence.entry(manifest_digest.to_owned()).or_default();
        for (id, target) in targets {
            let match_count = counts
                .get(&(manifest_digest.to_owned(), id.to_owned()))
                .copied()
                .unwrap_or(0);
            entries.push(PolicyPackProcedureSummaryEvidence::new(
                id.to_owned(),
                target.symbol.clone(),
                match_count,
            ));
        }
    });
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

fn usable_active_semantic_models(
    activation: &WorkspacePacksActivation,
) -> Option<&ResolvedActiveSemanticModels> {
    match activation.outcome.runtime.as_ref()? {
        SemanticModelRuntimeOutcome::Ready { active, .. } => Some(active),
        SemanticModelRuntimeOutcome::Incomplete { usable, .. } => usable.as_deref(),
        SemanticModelRuntimeOutcome::Cancelled(_) | SemanticModelRuntimeOutcome::Unavailable(_) => {
            None
        }
    }
}

/// Warn when an active, reviewed workspace model publishes a procedure
/// summary whose workspace source identity reaches no workspace declaration.
/// External targets cannot match workspace procedures by design; their
/// identities are checked by model loading and endpoint identity validation.
fn active_workspace_model_zero_match_diagnostics(
    analyzer: Option<&dyn IAnalyzer>,
    activation: Option<&WorkspacePacksActivation>,
    summary_evidence: Option<&BTreeMap<String, Vec<PolicyPackProcedureSummaryEvidence>>>,
) -> Result<Vec<PolicyReportDiagnostic>, PolicyCoordinatorError> {
    let Some(activation) = activation else {
        return Ok(Vec::new());
    };
    let Some(summary_evidence) = summary_evidence else {
        return Ok(Vec::new());
    };
    let Some(active) = usable_active_semantic_models(activation) else {
        return Ok(Vec::new());
    };
    let Some(analyzer) = analyzer else {
        return Ok(Vec::new());
    };
    let shards = active.shards();
    let workspace_files = analyzer.analyzed_files();
    let mut diagnostics = Vec::new();
    for model in &activation.workspace_models {
        let Some(entries) = summary_evidence.get(&model.manifest_digest) else {
            continue;
        };
        let Some(shard) = shards
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
            let summary = shards
                .iter()
                .filter(|shard| {
                    shard.manifest.content_sha256 == model.manifest_digest
                        && shard.descriptor.payload_kind
                            == brokk_bifrost_analysis::analyzer::semantic_model::PayloadKind::ProcedureSummaries
                })
                .find_map(|shard| {
                    active
                        .procedure_summary_family(shard, [entry.summary_id()])
                        .iter()
                        .find(|summary| summary.id == entry.summary_id())
                        .cloned()
                })
                .expect("every summary review entry has an active summary");
            // A qualified target's path is provenance, not its identity.
            // An artifact owner remains external even when that display path
            // happens to name a workspace file.
            let external_owner =
                authored_procedure_target_identity(&summary.target.path, &summary.target.symbol)
                    .is_some_and(|(owner, _)| {
                        active.all_type_records_named(&owner).any(|candidate| {
                            candidate.shard.manifest.language == shard.manifest.language
                                && matches!(
                                    &candidate.record.locator,
                                    Locator::Artifact { .. } | Locator::Interchange { .. }
                                )
                        })
                    });
            if external_owner {
                continue;
            }
            let path = Path::new(&summary.target.path);
            let file = if path.is_absolute() {
                analyzer.project().file_by_abs_path(path)
            } else {
                analyzer.project().file_by_rel_path(path)
            };
            if !file.is_some_and(|file| workspace_files.contains(&file)) {
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
    node_builtin_imports: &BTreeSet<(Language, &'static str)>,
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
    // A declared standard-library dependency is reported once, under the pack
    // it expects, by `record_standard_library_packs`; its generic
    // per-dependency rows would only repeat that decision without the pack.
    let standard_library_dependencies = activation
        .outcome
        .ecosystems
        .iter()
        .flat_map(|ecosystem| ecosystem.discovery.standard_library_pack_expectations())
        .flat_map(|expectation| match &expectation.selection {
            StandardLibraryPackSelection::Declared { dependency_ids } => dependency_ids.as_slice(),
            StandardLibraryPackSelection::NotSelected { .. }
            | StandardLibraryPackSelection::Unpinned => &[],
        })
        .map(String::as_str)
        .collect::<HashSet<_>>();
    for ecosystem in &activation.outcome.ecosystems {
        for diagnostic in &ecosystem.discovery.diagnostics {
            if diagnostic
                .dependency_id
                .as_deref()
                .is_some_and(|id| standard_library_dependencies.contains(id))
            {
                continue;
            }
            decisions.push(PolicyPackDecision::new(
                diagnostic
                    .dependency_id
                    .clone()
                    .unwrap_or_else(|| diagnostic.code.clone()),
                PolicyPackDecisionStatus::Missing,
                Some(format!("{}: {}", diagnostic.code, diagnostic.message)),
            ));
        }
        let Some(preparation) = &ecosystem.preparation else {
            continue;
        };
        // Preparation already bounds diagnostics and their messages. Keep the
        // retained warnings on the selected dependency rather than losing them
        // when its partial pack remains usable.
        let warning_reason = |dependency_id: &str| {
            let warnings = preparation
                .diagnostics
                .iter()
                .filter(|diagnostic| {
                    diagnostic.severity == DependencyPackDiagnosticSeverity::Warning
                        && diagnostic.dependency_id.as_deref() == Some(dependency_id)
                })
                .map(|diagnostic| format!("{}: {}", diagnostic.code, diagnostic.message))
                .collect::<Vec<_>>();
            (!warnings.is_empty()).then(|| warnings.join("; "))
        };
        for pack in &preparation.packs {
            decisions.push(PolicyPackDecision::new(
                pack.dependency_id.clone(),
                PolicyPackDecisionStatus::Selected,
                warning_reason(&pack.dependency_id),
            ));
        }
        for pack in &preparation.installed_packs {
            if standard_library_dependencies.contains(pack.dependency_id.as_str()) {
                continue;
            }
            decisions.push(PolicyPackDecision::new(
                pack.dependency_id.clone(),
                PolicyPackDecisionStatus::Selected,
                warning_reason(&pack.dependency_id),
            ));
        }
        for diagnostic in &preparation.diagnostics {
            if diagnostic
                .dependency_id
                .as_deref()
                .is_some_and(|id| standard_library_dependencies.contains(id))
            {
                continue;
            }
            let status = match diagnostic.code.as_str() {
                "dependency.pack_version_mismatch" => PolicyPackDecisionStatus::VersionMismatch,
                "dependency.pack_unavailable" | "preparation.unaccounted-dependency" => {
                    PolicyPackDecisionStatus::Missing
                }
                _ if diagnostic.severity == DependencyPackDiagnosticSeverity::Error
                    && diagnostic.dependency_id.as_ref().is_none_or(|id| {
                        !preparation
                            .packs
                            .iter()
                            .any(|pack| &pack.dependency_id == id)
                            && !preparation
                                .installed_packs
                                .iter()
                                .any(|pack| &pack.dependency_id == id)
                    }) =>
                {
                    PolicyPackDecisionStatus::Rejected
                }
                _ => continue,
            };
            decisions.push(PolicyPackDecision::new(
                diagnostic
                    .dependency_id
                    .clone()
                    .unwrap_or_else(|| diagnostic.code.clone()),
                status,
                Some(format!("{}: {}", diagnostic.code, diagnostic.message)),
            ));
        }
    }
    match &activation.outcome.runtime {
        Some(SemanticModelRuntimeOutcome::Ready { active, .. }) => {
            record_active_shards(&mut decisions, &active.shards(), summary_evidence);
            record_explanations(&mut decisions, &active.activation_report().explanations);
        }
        Some(SemanticModelRuntimeOutcome::Incomplete { usable, report }) => {
            if let Some(active) = usable {
                record_active_shards(&mut decisions, &active.shards(), summary_evidence);
            }
            record_explanations(&mut decisions, &report.explanations);
        }
        Some(
            SemanticModelRuntimeOutcome::Cancelled(report)
            | SemanticModelRuntimeOutcome::Unavailable(report),
        ) => record_explanations(&mut decisions, &report.explanations),
        None => {}
    }
    record_standard_library_packs(&mut decisions, &activation.outcome);
    record_unmodeled_node_builtins(
        &mut decisions,
        node_builtin_imports,
        activation.outcome.runtime.as_ref(),
    );
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
    let Some(active) = usable_active_semantic_models(activation) else {
        return Ok(Vec::new());
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
    shards: &[Arc<ActiveSemanticModelShard>],
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
        // A selection reason is not boilerplate now that a pack can declare a
        // compatible range instead of an exact build: it names the requirement
        // that admitted this workspace, which is what makes an
        // `external_indexed` answer attributable to a stated version contract
        // (#3465).
        decisions.push(PolicyPackDecision::new(
            explanation
                .pack_id
                .clone()
                .unwrap_or_else(|| explanation.manifest_digest.clone()),
            status,
            Some(explanation.reason.clone()),
        ));
    }
}

/// Record one decision naming each standard-library pack discovery expected
/// for a language present in the workspace (#3464).
///
/// A pack the runtime considered already has its decision, recorded under the
/// pack identity by `record_active_shards` and `record_explanations`, which
/// keep the runtime's own reason. Everything else used to be silent: a
/// workspace that declared no toolchain resolved no dependency, and a declared
/// toolchain with nothing installed reported only its dependency identity.
/// Both now name the pack, with the exact reason it did not activate.
fn record_standard_library_packs(
    decisions: &mut Vec<PolicyPackDecision>,
    outcome: &DependencyPackActivationOutcome,
) {
    let runtime_decided = runtime_decided_packs(outcome.runtime.as_ref());
    for ecosystem in &outcome.ecosystems {
        for expectation in ecosystem.discovery.standard_library_pack_expectations() {
            let language = expectation.language.config_label();
            let (status, reason) = match &expectation.selection {
                StandardLibraryPackSelection::NotSelected { reason } => {
                    (PolicyPackDecisionStatus::Rejected, reason.clone())
                }
                StandardLibraryPackSelection::Declared { .. } | StandardLibraryPackSelection::Unpinned
                    if runtime_decided.contains(expectation.pack_id) =>
                {
                    continue;
                }
                StandardLibraryPackSelection::Unpinned => (
                    PolicyPackDecisionStatus::Missing,
                    "the project's toolchain is unpinned; no installed standard-library pack is available for approximate activation. Install a Bifrost-packs release with `bifrost install-semantic-packs`".to_owned(),
                ),
                StandardLibraryPackSelection::Declared { dependency_ids } => {
                    declared_standard_library_pack_decision(
                        expectation,
                        dependency_ids,
                        ecosystem.preparation.as_ref(),
                        outcome.runtime.as_ref(),
                    )
                }
            };
            decisions.push(PolicyPackDecision::new(
                expectation.pack_id.to_owned(),
                status,
                Some(format!("{language}: {reason}")),
            ));
        }
    }
}

/// Record each Node built-in module the workspace imports that no active pack
/// declares (#3464).
///
/// Node's built-in modules are the JavaScript runtime's standard library, but
/// no npm dependency declares them, so neither discovery nor preparation ever
/// names one. A call such as `fs.readFileSync` then resolves to no declaration
/// and the report must still say why: the decision names the module and the
/// language that imports it.
fn record_unmodeled_node_builtins(
    decisions: &mut Vec<PolicyPackDecision>,
    node_builtin_imports: &BTreeSet<(Language, &'static str)>,
    runtime: Option<&SemanticModelRuntimeOutcome>,
) {
    let active = match runtime {
        Some(SemanticModelRuntimeOutcome::Ready { active, .. }) => Some(active),
        Some(SemanticModelRuntimeOutcome::Incomplete { usable, .. }) => usable.as_ref(),
        Some(
            SemanticModelRuntimeOutcome::Cancelled(_) | SemanticModelRuntimeOutcome::Unavailable(_),
        )
        | None => None,
    };
    for (language, module) in node_builtin_imports {
        let language = language.config_label();
        let declared = active.is_some_and(|active| {
            active.types_named(module).records.iter().any(|record| {
                record.record.type_kind == TypeKind::Module
                    && record.shard.manifest.language == language
            })
        });
        if declared {
            continue;
        }
        decisions.push(PolicyPackDecision::new(
            format!("node:{module}"),
            PolicyPackDecisionStatus::Missing,
            Some(format!(
                "{language}: the workspace imports the Node built-in module `{module}`, and no \
                 active semantic pack declares it"
            )),
        ));
    }
}

/// The packs the semantic-model runtime itself recorded a decision for.
fn runtime_decided_packs(runtime: Option<&SemanticModelRuntimeOutcome>) -> HashSet<String> {
    let (shards, explanations) = match runtime {
        Some(SemanticModelRuntimeOutcome::Ready { active, .. }) => (
            active.shards(),
            active.activation_report().explanations.as_slice(),
        ),
        Some(SemanticModelRuntimeOutcome::Incomplete { usable, report }) => (
            usable
                .as_ref()
                .map(|active| active.shards())
                .unwrap_or_default(),
            report.explanations.as_slice(),
        ),
        Some(
            SemanticModelRuntimeOutcome::Cancelled(report)
            | SemanticModelRuntimeOutcome::Unavailable(report),
        ) => (Vec::new(), report.explanations.as_slice()),
        None => (Vec::new(), &[][..]),
    };
    shards
        .iter()
        .map(|shard| shard.manifest.pack_id.clone())
        .chain(
            explanations
                .iter()
                .filter_map(|explanation| explanation.pack_id.clone()),
        )
        .collect()
}

/// Why a declared standard-library pack the runtime never considered did not
/// activate, read from preparation's verdict on the declaring dependencies.
fn declared_standard_library_pack_decision(
    expectation: &StandardLibraryPackExpectation,
    dependency_ids: &[String],
    preparation: Option<&DependencyPackPreparationOutcome>,
    runtime: Option<&SemanticModelRuntimeOutcome>,
) -> (PolicyPackDecisionStatus, String) {
    let Some(preparation) = preparation else {
        return (
            PolicyPackDecisionStatus::Rejected,
            format!(
                "dependency preparation did not run for {}",
                dependency_ids.join(", ")
            ),
        );
    };

    if let Some(diagnostic) = preparation.diagnostics.iter().find(|diagnostic| {
        diagnostic.code == "dependency.pack_version_mismatch"
            && diagnostic
                .dependency_id
                .as_ref()
                .is_some_and(|id| dependency_ids.contains(id))
    }) {
        return (
            PolicyPackDecisionStatus::VersionMismatch,
            diagnostic.message.clone(),
        );
    }

    if let Some(decision) = declared_standard_library_runtime_decision(
        expectation,
        dependency_ids,
        preparation,
        runtime,
    ) {
        return decision;
    }

    let refusal = preparation.diagnostics.iter().find(|diagnostic| {
        diagnostic.severity == DependencyPackDiagnosticSeverity::Error
            && diagnostic
                .dependency_id
                .as_ref()
                .is_some_and(|id| dependency_ids.contains(id))
    });
    match refusal {
        Some(diagnostic)
            if matches!(
                diagnostic.code.as_str(),
                "dependency.pack_unavailable" | "preparation.unaccounted-dependency"
            ) =>
        {
            (
                PolicyPackDecisionStatus::Missing,
                expectation.not_installed_reason(),
            )
        }
        Some(diagnostic) => (
            PolicyPackDecisionStatus::Rejected,
            format!("{}: {}", diagnostic.code, diagnostic.message),
        ),
        None => (
            PolicyPackDecisionStatus::Rejected,
            format!(
                "neither dependency preparation nor the semantic-model runtime recorded a verdict \
                 for {}",
                dependency_ids.join(", ")
            ),
        ),
    }
}

/// Carry an active, complete pack's runtime verdict to the expected standard-
/// library identity. Partial packs can contribute useful facts but cannot
/// satisfy the whole-library expectation.
fn declared_standard_library_runtime_decision(
    expectation: &StandardLibraryPackExpectation,
    dependency_ids: &[String],
    preparation: &DependencyPackPreparationOutcome,
    runtime: Option<&SemanticModelRuntimeOutcome>,
) -> Option<(PolicyPackDecisionStatus, String)> {
    let runtime = runtime?;
    let prepared_manifest_digests = preparation
        .packs
        .iter()
        .filter(|pack| dependency_ids.contains(&pack.dependency_id))
        .map(|pack| pack.production.manifest_digest.as_str())
        .chain(
            preparation
                .installed_packs
                .iter()
                .filter(|pack| dependency_ids.contains(&pack.dependency_id))
                .flat_map(|pack| pack.manifest_digests.iter().map(String::as_str)),
        )
        .collect::<HashSet<_>>();
    if prepared_manifest_digests.is_empty() {
        return None;
    }

    let (shards, explanations) = match runtime {
        SemanticModelRuntimeOutcome::Ready { active, .. } => (
            active.shards(),
            active.activation_report().explanations.as_slice(),
        ),
        SemanticModelRuntimeOutcome::Incomplete { usable, report } => (
            usable
                .as_ref()
                .map(|active| active.shards())
                .unwrap_or_default(),
            report.explanations.as_slice(),
        ),
        SemanticModelRuntimeOutcome::Cancelled(report)
        | SemanticModelRuntimeOutcome::Unavailable(report) => {
            (Vec::new(), report.explanations.as_slice())
        }
    };

    let complete_active_manifest_digests = shards
        .iter()
        .filter(|shard| shard.manifest.completeness == Completeness::Complete)
        .map(|shard| shard.manifest.content_sha256.as_str())
        .collect::<HashSet<_>>();
    if complete_active_manifest_digests.is_empty() {
        return None;
    }

    if let Some(explanation) = explanations.iter().find(|explanation| {
        explanation.status == SemanticModelActivationStatus::Active
            && prepared_manifest_digests.contains(explanation.manifest_digest.as_str())
            && complete_active_manifest_digests.contains(explanation.manifest_digest.as_str())
    }) {
        return Some((
            PolicyPackDecisionStatus::Selected,
            explanation.reason.clone(),
        ));
    }

    if shards.iter().any(|shard| {
        shard.manifest.language == expectation.language.config_label()
            && prepared_manifest_digests.contains(shard.manifest.content_sha256.as_str())
            && shard.manifest.completeness == Completeness::Complete
    }) {
        return Some((
            PolicyPackDecisionStatus::Selected,
            format!(
                "the declared dependency {} has an active semantic pack",
                dependency_ids.join(", ")
            ),
        ));
    }

    None
}

/// Where one batch's analyzer snapshot comes from.
#[derive(Clone, Copy)]
enum PolicyWorkspaceSource<'a> {
    /// The coordinator builds the policy workspace over the root and activates
    /// it: the CLI and the GitHub action.
    Root,
    /// The coordinator reuses a matching host analyzer or builds the policy
    /// workspace over its project, languages and store: an MCP session, or a
    /// scoped CLI session. Policy semantic sources are activated independently
    /// of the session's other tools.
    HostSession(&'a WorkspaceAnalyzer),
    /// The caller analyzed and activated this snapshot itself and owns that
    /// choice: an API caller, or the base half of a diff run, which is built
    /// with the head's configuration and mirrors its activation.
    Supplied(&'a WorkspaceAnalyzer),
}

/// One policy's evaluation, before the batch-level bookkeeping that reads
/// policy order.
struct EvaluatedPolicy {
    policy_id: PolicyId,
    run: PolicyRun,
    elapsed: std::time::Duration,
    /// Whether the shared cancellation deadline had already expired when this
    /// policy's evaluation returned. The batch's completed, active, and pending
    /// classification takes the earliest policy that observed it, so the result
    /// is the same whichever worker reached it first.
    deadline_exceeded: bool,
    /// Whether this policy's final verdict gates at the requested threshold.
    fail_closed: bool,
}

/// Evaluate exactly one runnable policy.
///
/// The call touches shared immutable state and the thread-safe reuse context
/// only, so a caller may run it concurrently with another policy's evaluation.
/// Every order-dependent decision -- the completed, active, and pending policy
/// classification and the fail-closed gate -- is deferred to the caller's
/// ordered merge.
#[allow(clippy::too_many_arguments)]
fn evaluate_policy_once(
    policy: &LoadedPolicy,
    evaluator: &DefaultPolicyEvaluator<'_>,
    workspace: Option<&WorkspaceAnalyzer>,
    flow_state: &brokk_bifrost_flow::FlowWorkspaceState,
    root_memo: &brokk_bifrost_rql::TypeFlowRootMemo,
    cancellation: Option<&CancellationToken>,
    head_incremental: Option<&PolicyIncrementalContext<'_>>,
    scoped_files: &HashMap<PolicyId, Vec<ProjectFile>>,
    workspace_files: &[ProjectFile],
    per_policy_budget: PolicyBudget,
    options: &PolicyEvaluationOptions,
    workspace_has_analyzable_files: bool,
) -> Result<EvaluatedPolicy, PolicyCoordinatorError> {
    let _attribution = brokk_bifrost_analysis::analyzer::ReadAttribution::for_request().install();
    let policy_id = policy.definition().metadata.id.clone();
    let mut evaluation_budget = per_policy_budget;
    if scoped_files.contains_key(&policy_id)
        && let Some(incremental) = head_incremental
    {
        incremental.record_run(PolicyIncrementalRun::whole_family(policy_id.clone()));
    }
    let context = PolicyEvaluationContext {
        analyzer: workspace.map(WorkspaceAnalyzer::analyzer).ok_or_else(|| {
            PolicyCoordinatorError::new(format!(
                "runnable policy `{}` has no analyzer snapshot",
                policy.definition().metadata.id
            ))
        })?,
        workspace,
        flow_state,
        root_memo: Some(root_memo),
        cancellation,
        cvss_overlays: &[],
        organizational_risk: &[],
        // Scoped evaluations do not publish or replay whole-domain units.
        incremental: if scoped_files.contains_key(&policy_id) {
            None
        } else {
            head_incremental
        },
    };
    let policy_started = Instant::now();
    let evaluated = {
        let _scope = brokk_bifrost_analysis::profiling::scope_with(|| {
            format!(
                "policy_coordinator.evaluate_policy[{}]",
                policy.definition().metadata.id.as_str()
            )
        });
        match scoped_files.get(&policy_id) {
            Some(selected) => evaluator.evaluate_in_scope(
                policy,
                &context,
                &mut evaluation_budget,
                CodeQueryExecutionScope::for_seed_files(selected, workspace_files),
            ),
            None => evaluator.evaluate(policy, &context, &mut evaluation_budget),
        }
    };
    let elapsed = policy_started.elapsed();
    let mut run = match evaluated {
        Ok(run) => run,
        Err(error) => failed_evaluation_run(policy, error.to_string(), &evaluation_budget)?,
    };
    if options.policy_timings() {
        let elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
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
        // Read only after the evaluator returned: every unit-reuse state of
        // this policy (typestate keeps its own inside the session) has dropped
        // by then and flushed its metrics. Reading earlier would miss them.
        if let Some(metrics) =
            head_incremental.and_then(|context| context.unit_phase_metrics(&policy_id))
        {
            for (name, elapsed) in [
                (UNIT_PREFETCH_METRIC, metrics.prefetch),
                (UNIT_VERIFY_METRIC, metrics.verify),
                (UNIT_LOOKUP_REPLAY_METRIC, metrics.lookup_replay),
                (UNIT_RECOMPUTE_METRIC, metrics.recompute),
            ] {
                let metric = PolicyWorkMetric::try_new(
                    name,
                    PolicyWorkUnit::Milliseconds,
                    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
                )
                .map_err(|error| {
                    PolicyCoordinatorError::new(format!(
                        "failed to construct the unit timing metric: {error}"
                    ))
                })?;
                run.work_mut().try_push_metric(metric).map_err(|error| {
                    PolicyCoordinatorError::new(format!(
                        "failed to record the unit timing metric: {error}"
                    ))
                })?;
            }
        }
    }
    if !workspace_has_analyzable_files && !policy_uses_only_file_facts(policy) {
        run.mark_inconclusive(PolicyIncompleteReason::NoAnalyzableFiles);
    }
    let deadline_exceeded = policy_deadline_reached(cancellation)?;
    if deadline_exceeded
        && matches!(
            run.completion(),
            PolicyRunCompletion::Inconclusive { reasons, .. }
                if reasons.contains(&PolicyIncompleteReason::Cancelled)
        )
    {
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
    // The policy's declared handling of a blocked verdict is applied once the
    // run's completion is final, so an unrelated cause of inconclusiveness --
    // an empty workspace, a deadline -- is covered by the same declaration
    // (#2506).
    let verdict = policy.definition().on_unknown.verdict;
    run.apply_unknown_verdict(verdict, &evaluation_budget)
        .map_err(|error| {
            PolicyCoordinatorError::new(format!(
                "failed to apply the declared unknown-result verdict: {error}"
            ))
        })?;
    // A fail-closed run gates exactly as a finding at the policy's own severity
    // would, so the threshold is read from the same option the findings are.
    let fail_closed = run.unknown_verdict() == Some(UnknownVerdict::FailClosed)
        && options
            .fail_on()
            .matches(super::evaluator::finding_severity(
                &policy.definition().metadata.severity,
                None,
            ));
    Ok(EvaluatedPolicy {
        policy_id,
        run,
        elapsed,
        deadline_exceeded,
        fail_closed,
    })
}

#[allow(clippy::too_many_arguments)]
fn evaluate_prepared_policy_inputs(
    root: &Path,
    read_root: &WorkspaceRoot,
    mut inputs: Vec<InputOutcome>,
    options: &PolicyEvaluationOptions,
    batch_budget: PolicyBatchBudget,
    registry_limits: PolicyRegistryLimits,
    workspace_source: PolicyWorkspaceSource<'_>,
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
                InputOutcome::Pending(prepared) => Some(DiffBasePolicyInput {
                    policy_id: prepared.policy_id.clone(),
                    source: prepared.source.clone(),
                    bytes: prepared.bytes.clone(),
                    required_capabilities: prepared.required_capabilities.clone(),
                    selection_provenance: prepared.selection_provenance,
                }),
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
    let mut diff_base_policy_unqualified = Vec::new();
    let suppression_load = {
        let _scope =
            brokk_bifrost_analysis::profiling::scope("policy.registration.suppression_preflight");
        suppression_preflight.map_or_else(
            || load_policy_suppressions_from_root(read_root, options.suppressions()),
            PolicySuppressionPreflight::into_outcome,
        )
    };
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
    let (scope_document, scope_document_state) = {
        let _scope = brokk_bifrost_analysis::profiling::scope("policy.registration.scope_document");
        match options.scope_override.as_ref().map_or_else(
            || load_policy_scope_from_root(read_root, options.scope()),
            |scope| Ok(scope.clone()),
        ) {
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
        }
    };
    // A malformed baseline document is loud: its diagnostic alone makes the
    // run unreliable, so a broken bulk acceptance can never look clean.
    let baseline_document = {
        let _scope =
            brokk_bifrost_analysis::profiling::scope("policy.registration.baseline_document");
        match load_policy_baseline_from_root(read_root, options.baseline()) {
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
        }
    };
    // The workspace packs document opts this evaluation into dependency and
    // stdlib semantic-pack activation (#1868). A malformed document is loud:
    // its diagnostic makes the run unreliable rather than silently evaluating
    // without the configured packs.
    let mut packs_load_failure = None;
    let packs_config = {
        let _scope = brokk_bifrost_analysis::profiling::scope("policy.registration.packs_document");
        match load_workspace_packs_config(read_root) {
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
    let catalogs = {
        let _scope =
            brokk_bifrost_analysis::profiling::scope("policy.registration.catalog_registry");
        let mut catalogs = TaintCatalogRegistry::new_for_workspace(
            root.to_path_buf(),
            CatalogRegistryLimits::default(),
        )
        .map_err(|error| {
            PolicyCoordinatorError::new(format!(
                "failed to initialize policy catalog registry: {error}"
            ))
        })?;
        // Installed roots become run inputs only for catalog-dependent policies.
        if inputs.iter().any(|input| matches!(input, InputOutcome::Pending(prepared) if prepared.needs_catalog_registry)) {
            super::builtin::register_run_catalogs(&mut catalogs).map_err(|error| {
                PolicyCoordinatorError::new(format!("failed to register pack catalogs: {error}"))
            })?;
        }
        Arc::new(catalogs)
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
    let mut registry = {
        let _scope =
            brokk_bifrost_analysis::profiling::scope("policy.registration.policy_registry");
        PolicyRegistry::new_for_workspace(root.to_path_buf(), catalogs, registry_limits).map_err(
            |error| {
                PolicyCoordinatorError::new(format!(
                    "failed to initialize policy registry: {error}"
                ))
            },
        )?
    };

    // Qualified policy locators need the same analyzer snapshot and active
    // model publication that evaluation will use. Prepare both before closing
    // any policy so the loaded-policy boundary can resolve them exactly once.
    registry.set_cancellation(cancellation.cloned());
    let needs_workspace = inputs
        .iter()
        .any(|input| matches!(input, InputOutcome::Pending(_) | InputOutcome::Runnable(_)));
    let supplied_workspace = match workspace_source {
        PolicyWorkspaceSource::Supplied(workspace) => Some(workspace),
        PolicyWorkspaceSource::Root | PolicyWorkspaceSource::HostSession(_) => None,
    };
    let policy_config = AnalyzerConfig::default();
    let mut reused_host_workspace = None;
    let owned_analyzer = match workspace_source {
        _ if !needs_workspace => None,
        PolicyWorkspaceSource::Supplied(_) => None,
        PolicyWorkspaceSource::HostSession(session) => {
            let _scope =
                brokk_bifrost_analysis::profiling::scope("policy.registration.host_session");
            // Workspace content identities hash the complete configuration's
            // Debug representation. SemanticArtifactKey's configuration is
            // narrower (intrafile lowering defaults), so it cannot establish
            // that the host's workspace projection answers this policy request.
            let defaults_fingerprint =
                ConfigurationFingerprint::hash_bytes(format!("{policy_config:?}").as_bytes());
            let host = session
                .config()
                .map(|config| {
                    ConfigurationFingerprint::hash_bytes(format!("{config:?}").as_bytes())
                })
                .unwrap_or(defaults_fingerprint);
            let reuse = host == defaults_fingerprint;
            brokk_bifrost_analysis::profiling::note_with(|| {
                format!(
                    "policy.host_configuration reused={reuse} host={host:?} defaults={defaults_fingerprint:?}"
                )
            });
            if reuse {
                reused_host_workspace = Some(session);
                None
            } else {
                Some(
                    session
                        .rebuild_with_config(policy_config)
                        .map_err(|error| {
                            PolicyCoordinatorError::new(format!(
                                "failed to build the policy workspace over the host session at {}: \
                                 {error}",
                                root.display()
                            ))
                        })?,
                )
            }
        }
        PolicyWorkspaceSource::Root => {
            let project = owned_policy_project(root).map_err(|error| {
                PolicyCoordinatorError::new(format!(
                    "failed to construct analyzer project {}: {error}",
                    root.display()
                ))
            })?;
            let project: Arc<dyn Project> = Arc::new(project);
            // Persisted, so consecutive policy runs over one root reuse the
            // blobs the first run parsed instead of re-parsing the world into a
            // delete-on-drop database.
            Some({
                let _scope =
                    brokk_bifrost_analysis::profiling::scope("policy.registration.owned_analyzer");
                WorkspaceAnalyzer::build_persisted(project, policy_config).map_err(|error| {
                    PolicyCoordinatorError::new(format!(
                        "failed to build the analyzer workspace at {}: {error}",
                        root.display()
                    ))
                })?
            })
        }
    };
    let workspace = supplied_workspace
        .or(reused_host_workspace)
        .or(owned_analyzer.as_ref());
    let workspace_has_analyzable_files =
        workspace.is_some_and(|workspace| !workspace.analyzer().analyzed_files().is_empty());
    let uncancelled = CancellationToken::default();
    let semantic_cancellation = cancellation.unwrap_or(&uncancelled);
    let mut workspace_activation_failure = None;
    let workspace_activation = {
        let _scope =
            brokk_bifrost_analysis::profiling::scope("policy.registration.workspace_activation");
        match reused_host_workspace.or(owned_analyzer.as_ref()) {
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
                        let failed_configured_catalog =
                            matches!(&error, WorkspaceActivationError::Catalog(_));
                        if failed_configured_catalog {
                            workspace_activation_failure = Some(error.to_string());
                        }
                        secondary_diagnostics.push(workspace_activation_diagnostic(&error)?);
                        failed_configured_catalog.then_some(None)
                    }
                }
            }
            None => None,
        }
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
    let mut selected_policy_metadata = HashMap::new();
    let mut unavailable_locators = HashMap::new();
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
        let registration = {
            let _scope = brokk_bifrost_analysis::profiling::scope_with(|| {
                format!("policy.registration.policy[{}]", prepared.policy_id)
            });
            match workspace {
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
            }
        };
        let registration = match registration {
            Err(PolicyRegistryError::Source(diagnostic))
                if workspace.is_some() && is_qualified_locator_code(diagnostic.diagnostic.code) =>
            {
                if policy_deadline_reached(cancellation)? {
                    Err(PolicyRegistryError::Source(diagnostic))
                } else {
                    // An unavailable workspace identity is not an authoring
                    // error. Revalidate the entire authored policy, including
                    // imports and registry budgets, with deferred locators.
                    // Its authored hash identifies only the not-run record;
                    // this plan cannot execute or publish policy-unit evidence.
                    let unavailable = UnavailablePolicyCapability {
                        label: diagnostic.diagnostic.code.to_owned(),
                        reason: diagnostic.diagnostic.message.clone(),
                    };
                    registry
                        .register_policy_bytes_deferred(
                            prepared.source.clone(),
                            prepared.bytes.as_bytes(),
                        )
                        .map(|policy| {
                            let policy_id = policy.definition().metadata.id.clone();
                            unavailable_locators.insert(policy_id.clone(), unavailable);
                            policy_id
                        })
                }
            }
            registration => registration,
        };
        match registration {
            Ok(policy_id) => {
                input_by_policy_id.insert(policy_id.clone(), input_index);
                if let Some(selection_provenance) = prepared.selection_provenance {
                    selected_policy_metadata.insert(
                        policy_id.clone(),
                        SelectedPolicyMetadata {
                            required_capabilities: prepared.required_capabilities.clone(),
                            selection_provenance,
                        },
                    );
                }
                inputs[input_index] = InputOutcome::Runnable(policy_id);
            }
            Err(error) => {
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

    let mut runnable_ids = inputs
        .iter()
        .filter_map(|input| match input {
            InputOutcome::Runnable(policy_id) => Some(policy_id.clone()),
            InputOutcome::Pending(_) | InputOutcome::Diagnostic(_) => None,
        })
        .collect::<HashSet<_>>();

    let mut not_run_runs = HashMap::new();
    let semantic_snapshot = active_semantic_model_snapshot
        .as_ref()
        .ok()
        .and_then(Option::as_deref);
    let workspace_has_python_source = workspace.is_some_and(|workspace| {
        workspace
            .analyzer()
            .analyzed_files()
            .iter()
            .any(|file| language_for_file(file) == Language::Python)
    });
    for policy in registry.policies() {
        let policy_id = &policy.definition().metadata.id;
        if !runnable_ids.contains(policy_id) {
            continue;
        }
        let metadata = selected_policy_metadata.get(policy_id);
        let mut unavailable_capabilities = unavailable_locators
            .remove(policy_id)
            .into_iter()
            .collect::<Vec<_>>();
        unavailable_capabilities.extend(
            metadata
                .into_iter()
                .flat_map(|metadata| &metadata.required_capabilities)
                .filter_map(|label| {
                    match policy_capability_availability(
                        label,
                        semantic_snapshot,
                        workspace_has_python_source,
                    ) {
                        PolicyCapabilityAvailability::Available => None,
                        PolicyCapabilityAvailability::Unavailable { reason } => {
                            Some(UnavailablePolicyCapability {
                                label: label.clone(),
                                reason,
                            })
                        }
                    }
                }),
        );
        if unavailable_capabilities.is_empty() {
            continue;
        }
        unavailable_capabilities.sort();
        unavailable_capabilities.dedup();
        let completion = PolicyRunCompletion::NotRun {
            unavailable_capabilities,
            selected_by: metadata.map_or(PolicySelectionProvenance::ExplicitPolicyId, |metadata| {
                metadata.selection_provenance
            }),
        };
        let run = PolicyRun::try_new(
            policy.definition().metadata.id.clone(),
            policy.semantic_hash(),
            policy.definition().analysis.analysis_type(),
            completion,
            Vec::new(),
            Vec::new(),
            false,
            PolicyWorkReport::default(),
            batch_budget.per_policy(),
        )
        .map_err(|error| {
            PolicyCoordinatorError::new(format!(
                "failed to construct not-run policy result for `{policy_id}`: {error}"
            ))
        })?;
        not_run_runs.insert(policy_id.clone(), run);
        runnable_ids.remove(policy_id);
    }
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
    // Nested base evaluation receives its caller's context. Other scans use
    // the same persisted store, so a full scan can publish units for a later
    // diff scan without creating a separate cache identity. Every unit carries
    // the identity of the snapshot that computed it, so a workspace that
    // states none can neither publish nor reuse one.
    let head_snapshot = (options.incremental() && supplied_incremental.is_none())
        .then(|| workspace.and_then(workspace_snapshot))
        .flatten();
    let unit_store = head_snapshot.map(|_| BatchUnitStore::of(workspace));
    let mut runs = not_run_runs;
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
    let root_memo = brokk_bifrost_rql::TypeFlowRootMemo::default();
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
    let node_builtin_imports = workspace
        .filter(|_| activation_for_report.is_some())
        .map(imported_node_builtin_modules)
        .unwrap_or_default();
    let mut packs_review = match workspace_activation.as_ref() {
        // Dependency activation or a reviewed workspace model earns an audit
        // row. Intrinsic shipped models can share the transaction without
        // changing the top-level wire shape by themselves.
        Some(Some(activation)) => pack_activation_review(
            packs_config.as_ref(),
            Some(activation),
            None,
            None,
            summary_evidence.as_ref(),
            &node_builtin_imports,
        ),
        // The transaction ran and neither route contributed. A document still
        // earns a review row so its opt-in stays auditable; a run with no
        // document and no reviewed model attaches nothing.
        Some(None) => pack_activation_review(
            packs_config.as_ref(),
            None,
            None,
            packs_load_failure
                .as_deref()
                .or(workspace_activation_failure.as_deref()),
            None,
            &node_builtin_imports,
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
                &node_builtin_imports,
            )
        }),
    };
    let mut catalog_identities = registry
        .policies()
        .flat_map(|policy| policy.catalogs().iter().cloned())
        .collect::<Vec<_>>();
    catalog_identities.sort();
    catalog_identities.dedup();
    if !catalog_identities.is_empty() {
        let review = packs_review.get_or_insert_with(|| {
            PolicyPackActivationReview::new_with_mode(
                String::new(),
                super::report::PolicyDependencyPackActivationMode::Disabled,
                Vec::new(),
                true,
                Vec::new(),
            )
        });
        review.set_catalogs(catalog_identities);
    }
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
    if let Some(active) = activation_for_report.and_then(usable_active_semantic_models) {
        let shards = active.shards();
        let packs = shards
            .iter()
            .filter(|shard| shard.approximate)
            .map(|shard| (&shard.manifest.pack_id, &shard.manifest.version))
            .collect::<BTreeSet<_>>();
        for (pack_id, version) in packs {
            secondary_diagnostics.push(PolicyReportDiagnostic::try_new(
                PolicyReportDiagnosticCode::ApproximateStandardLibrary,
                PolicyDiagnosticSeverity::Note,
                format!("ADVISORY: selected {pack_id}@{version}; the project's toolchain is unpinned, so std facts are approximate; pin a toolchain channel in rust-toolchain.toml for exact std facts"),
                None, None, Vec::new(),
            ).map_err(|error| PolicyCoordinatorError::new(format!("failed to construct approximate stdlib advisory: {error}")))?);
        }
    }
    for diagnostic in inactive_workspace_model_diagnostics(activation_for_report)? {
        secondary_diagnostics.push(diagnostic);
    }
    for diagnostic in active_workspace_model_zero_match_diagnostics(
        workspace.map(|workspace| workspace.analyzer()),
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
    // Category metadata cannot affect a scope that selects only policy ids or
    // all policies. Avoid loading unrelated rule packs for those runs.
    let policy_categories = if scope_document.as_ref().is_some_and(|document| {
        document
            .scopes()
            .iter()
            .any(|entry| !entry.policy_categories().is_empty())
    }) {
        built_in_scope_categories()
    } else {
        HashMap::new()
    };
    let workspace_files = workspace
        .map(|workspace| workspace.analyzer().analyzed_files())
        .unwrap_or_default();
    let scoped_files = registry
        .policies()
        .filter_map(|policy| {
            let id = &policy.definition().metadata.id;
            let document = scope_document.as_ref()?;
            let categories = policy_categories
                .get(id)
                .map(std::slice::from_ref)
                .unwrap_or_default();
            let selected = workspace_files
                .iter()
                .filter(|file| !document.excludes_root(&rel_path_string(file), id, categories))
                .cloned()
                .collect::<Vec<_>>();
            let unsupported_scope = !policy_supports_execution_scope(policy)
                && document
                    .scopes()
                    .iter()
                    .any(|entry| entry.excludes_roots() && entry.matches_policy(id, categories));
            (selected.len() != workspace_files.len() || unsupported_scope)
                .then(|| (id.clone(), selected))
        })
        .collect::<HashMap<PolicyId, Vec<ProjectFile>>>();
    let evaluation_started = Instant::now();
    let mut diff_base_elapsed = std::time::Duration::ZERO;
    let preparation_before_diff = preparation_started.elapsed();
    // The base evaluates before the head loop: its units must exist before the
    // head can verify and reuse them, and the runnable policy set that filters
    // its inputs is known as soon as registration is done.
    let diff_baseline = match options.diff_base() {
        Some(revision) => {
            let base_inputs = diff_base_sources
                .iter()
                .filter(|input| runnable_ids.contains(&input.policy_id))
                .map(|input| {
                    PolicyEvaluationInput::embedded_with_selection(
                        input.source.clone(),
                        input.bytes.as_str(),
                        input.required_capabilities.clone(),
                        input.selection_provenance,
                    )
                })
                .collect::<Vec<_>>();
            let runnable_policies = registry
                .policies()
                .filter(|policy| runnable_ids.contains(&policy.definition().metadata.id))
                .collect::<Vec<_>>();
            let evaluation_key = workspace.map(|head| {
                base_evaluation_key(
                    options,
                    scope_document.as_ref(),
                    batch_budget,
                    registry_limits,
                    WorkspaceUnitInputs::of(head, icfg_active_semantic_model_snapshot.as_deref()),
                )
            });
            let diff_base_started = Instant::now();
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
            let phase = match reused {
                Some(outcome) => DiffBaselinePhase::Evaluated(Box::new(outcome)),
                None => evaluate_policy_diff_baseline(
                    root,
                    workspace,
                    revision,
                    options,
                    scope_document.as_ref(),
                    base_inputs,
                    batch_budget,
                    registry_limits,
                    &runnable_policies,
                    evaluation_key,
                    unit_store.as_ref(),
                    cancellation,
                )?,
            };
            diff_base_elapsed = diff_base_started.elapsed();
            let outcome = match phase {
                DiffBaselinePhase::Evaluated(outcome) => Some(*outcome),
                DiffBaselinePhase::DeadlineReached => None,
            };
            // A budget that expired anywhere in the phase -- inside the base
            // work or while replaying a persisted base -- ends the run here
            // rather than buying a head loop under a spent budget. Nothing of
            // the head ran, so the run is honestly incomplete instead of a
            // full-gating run whose base merely looked unreliable.
            if outcome.is_none() || policy_deadline_reached(cancellation)? {
                return diff_base_deadline_outcome(
                    options,
                    batch_budget,
                    suppression_sources.clone(),
                    scope_document_state,
                    registration_elapsed,
                    preparation_before_diff,
                    diff_base_elapsed,
                    evaluation_policy_ids,
                    revision,
                );
            }
            outcome
        }
        None => None,
    };
    // The changed range the taint runs bind sinks in. It is
    // resolved after the base phase, because a diff range reads the base
    // comparison that only that phase produces.
    let range = resolve_changed_range(
        options.range(),
        root,
        diff_baseline
            .as_ref()
            .map(|outcome| outcome.baseline.resolved_commit.as_str()),
        workspace,
        diff_baseline
            .as_ref()
            .and_then(|outcome| outcome.comparison.as_ref())
            .map(|comparison| &comparison.changed),
    );
    let changed_files = match &range {
        ChangedRangeResolution::Files(files) => Some(files.as_slice()),
        ChangedRangeResolution::Unrequested | ChangedRangeResolution::Unresolved(_) => None,
    };
    // Taint preparation follows the base phase, so its time is measured apart
    // from the base phase and charged to preparation, not to evaluation.
    let late_preparation_started = Instant::now();
    let taint = workspace.map_or_else(ProductionTaintPolicyEvaluator::default, |workspace| {
        ProductionTaintPolicyEvaluator::prepare_in_range(
            brokk_bifrost_rql::SemanticFlowResources::from_workspace_state(flow_state)
                .with_root_memo(Some(root_memo.clone())),
            registry
                .policies()
                .filter(|policy| runnable_ids.contains(&policy.definition().metadata.id))
                .filter(|policy| !scoped_files.contains_key(&policy.definition().metadata.id)),
            workspace,
            active_semantic_model_snapshot,
            cancellation,
            &per_policy_budget,
            changed_files,
        )
    });
    let typestate = ProductionTypestatePolicyEvaluator::with_active_semantic_model_snapshot(
        icfg_active_semantic_model_snapshot.clone(),
    );
    let evaluator = DefaultPolicyEvaluator::new()
        .with_taint(&taint)
        .with_typestate(&typestate)
        .with_active_semantic_model_snapshot(icfg_active_semantic_model_snapshot.clone());
    let preparation_elapsed = preparation_before_diff + late_preparation_started.elapsed();
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

    // A diff head verifies against the exact base. A full scan compares its
    // workspace with itself: that proves the name-index reads of a unit an
    // earlier scan computed on this same snapshot, every other read is checked
    // against the workspace, and a unit with index reads from any other
    // snapshot is recomputed. What a full scan publishes carries the scanned
    // snapshot's identity, so a later diff run whose base is this tree
    // verifies it too.
    let publication_changed = (unit_store.is_some() && diff_baseline.is_none()).then(|| {
        ChangedFacts::between(
            workspace.expect("a policy store requires a workspace"),
            workspace.expect("a policy store requires a workspace"),
        )
    });
    let head_incremental_owned = match (&unit_store, &diff_baseline, workspace, head_snapshot) {
        (Some(store), Some(baseline), Some(head), Some(head_snapshot)) => {
            baseline.comparison.as_ref().map(|comparison| {
                PolicyIncrementalContext::new(
                    store.units(),
                    head,
                    &comparison.changed,
                    WorkspaceUnitInputs::of(head, icfg_active_semantic_model_snapshot.as_deref()),
                    baseline.state,
                    UnitSnapshots {
                        base: comparison.snapshot,
                        head: head_snapshot,
                    },
                )
                .with_base_review(baseline.base_review.as_ref())
            })
        }
        (Some(store), None, Some(head), Some(head_snapshot)) => {
            Some(PolicyIncrementalContext::new(
                store.units(),
                head,
                publication_changed
                    .as_ref()
                    .expect("a full policy scan has its own facts"),
                WorkspaceUnitInputs::of(head, icfg_active_semantic_model_snapshot.as_deref()),
                IncrementalBaseState::Evaluated,
                UnitSnapshots::of(head_snapshot),
            ))
        }
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
    // The batch is nested inside the pinned analyzer/model scope and never
    // crosses a base/head boundary. Evaluation is independent per policy and
    // may run on a bounded pool; unit publication and every order-dependent
    // decision stay serial in the merge below.
    let subject_batch = workspace.map(|workspace| {
        super::evaluator::SubjectQueryBatch::new(
            workspace.analyzer(),
            registry
                .policies()
                .filter(|policy| runnable_ids.contains(&policy.definition().metadata.id))
                .filter(|policy| !scoped_files.contains_key(&policy.definition().metadata.id)),
            &per_policy_budget,
        )
    });
    let evaluator = evaluator.with_subject_batch(subject_batch.as_ref());
    let mut deadline_stage = None;
    let mut policy_evaluation_elapsed = std::time::Duration::ZERO;
    // The batch evaluates its runnable policies into independent results -- on
    // a bounded pool when policy parallelism is greater than one -- and merges
    // them here in policy order. A serial batch
    // (`BIFROST_POLICY_PARALLELISM=1`) runs exactly as it always has.
    let runnable_policies = registry
        .policies()
        .filter(|policy| runnable_ids.contains(&policy.definition().metadata.id))
        .collect::<Vec<_>>();
    let parallelism = super::policy_evaluation_parallelism();
    let evaluations = if parallelism <= 1 {
        // With one worker the total time is independent of dispatch order.
        let mut evaluations = Vec::with_capacity(runnable_policies.len());
        for policy in runnable_policies.iter().copied() {
            if policy_deadline_reached(cancellation)? {
                deadline_stage.get_or_insert(PolicyExecutionStage::PolicyEvaluation);
            }
            evaluations.push(evaluate_policy_once(
                policy,
                &evaluator,
                workspace,
                flow_state,
                &root_memo,
                cancellation,
                head_incremental,
                &scoped_files,
                &workspace_files,
                per_policy_budget,
                options,
                workspace_has_analyzable_files,
            )?);
        }
        evaluations
    } else {
        let mut dispatch = runnable_policies
            .iter()
            .copied()
            .enumerate()
            .collect::<Vec<_>>();
        dispatch.sort_by_key(|(index, policy)| {
            let hint = options
                .policy_cost_hints
                .0
                .get(policy.definition().metadata.id.as_str());
            (
                hint.is_some(),
                std::cmp::Reverse(hint.copied().unwrap_or(0)),
                *index,
            )
        });
        let mut results =
            super::parallel::map_bounded(parallelism, &dispatch, |(index, policy)| {
                (
                    index,
                    evaluate_policy_once(
                        policy,
                        &evaluator,
                        workspace,
                        flow_state,
                        &root_memo,
                        cancellation,
                        head_incremental,
                        &scoped_files,
                        &workspace_files,
                        per_policy_budget,
                        options,
                        workspace_has_analyzable_files,
                    ),
                )
            });
        results.sort_unstable_by_key(|(index, _)| *index);
        // The first failure in policy order is the one the batch reports, so a
        // failure is deterministic whichever worker produced it.
        let mut evaluations = Vec::with_capacity(results.len());
        for (_, result) in results {
            evaluations.push(result?);
        }
        evaluations
    };
    let mut fail_closed_gate = false;
    let mut completed_policy_ids = Vec::with_capacity(evaluation_policy_ids.len());
    let mut active_policy_id = None;
    let mut pending_policy_ids = Vec::new();
    for (policy_index, evaluated) in evaluations.into_iter().enumerate() {
        policy_evaluation_elapsed += evaluated.elapsed;
        if evaluated.deadline_exceeded {
            deadline_stage.get_or_insert(PolicyExecutionStage::PolicyEvaluation);
            if active_policy_id.is_none() {
                active_policy_id = Some(evaluated.policy_id.clone());
                pending_policy_ids.extend_from_slice(&evaluation_policy_ids[policy_index + 1..]);
            }
        } else if active_policy_id.is_none() {
            completed_policy_ids.push(evaluated.policy_id.clone());
        }
        if evaluated.fail_closed {
            fail_closed_gate = true;
        }
        runs.insert(
            evaluated.policy_id,
            record_unscoped_range(evaluated.run, &range),
        );
    }
    let evaluation_elapsed = evaluation_started.elapsed();
    brokk_bifrost_analysis::profiling::duration(
        "policy.coordination_including_diff_base",
        evaluation_elapsed.saturating_sub(policy_evaluation_elapsed),
    );
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
                "diff base `{}` ({}) was unreliable; qualified policies use verified diff evidence and unqualified policies use full gating: {detail}",
                baseline.requested_revision, baseline.resolved_commit
            ),
            None,
            None,
            Vec::new(),
        )?);
    }
    if let Some(baseline) = diff_baseline.as_ref().map(|outcome| &outcome.baseline) {
        for policy in &baseline.unqualified_policies {
            diff_base_policy_unqualified.push(policy.policy_id().clone());
            // An unqualified policy gates every head finding in full, so no
            // new finding hides behind it. When its base run was Bifrost's own
            // inconclusive verdict the comparison it could not make is
            // advisory, as SlopCop reads it (#8111); a base that an unreliable
            // reading condemns already carries `diff-base-unreliable`. Any
            // other unqualified base run reached no verdict and stays an error.
            let severity = if policy.completion() == "inconclusive" {
                PolicyDiagnosticSeverity::Warning
            } else {
                PolicyDiagnosticSeverity::Error
            };
            secondary_diagnostics.push(report_diagnostic_with_severity(
                PolicyReportDiagnosticCode::DiffBasePolicyUnqualified,
                severity,
                format!(
                    "diff base policy `{}` is unqualified ({}, {}); diagnostics: {:?}",
                    policy.policy_id(),
                    policy.completion(),
                    policy.completion_detail(),
                    policy.diagnostics()
                ),
                None,
                None,
                Vec::new(),
            )?);
        }
    }

    let suppression_reviews = match suppression_document.as_ref() {
        Some(document) => apply_policy_suppressions(
            document,
            options.evaluation_date(),
            &registry,
            workspace,
            &scoped_files,
            &mut runs,
        )?,
        None => Vec::new(),
    };
    let scope_reviews = match scope_document.as_ref() {
        Some(document) => {
            let mut reviews = apply_policy_scope(document, &policy_categories, &mut runs)?;
            for review in &mut reviews {
                if !review.entry().excludes_roots() {
                    continue;
                }
                let count = registry
                    .policies()
                    .filter(|policy| {
                        runs.contains_key(&policy.definition().metadata.id)
                            && policy_supports_execution_scope(policy)
                    })
                    .map(|policy| {
                        let id = &policy.definition().metadata.id;
                        let categories = policy_categories
                            .get(id)
                            .map(std::slice::from_ref)
                            .unwrap_or_default();
                        workspace_files
                            .iter()
                            .filter(|file| {
                                review
                                    .entry()
                                    .matches(&rel_path_string(file), id, categories)
                            })
                            .count() as u64
                    })
                    .sum();
                review.set_excluded_root_files(count);
            }
            reviews
        }
        None => Vec::new(),
    };
    let evaluation = PolicyReportEvaluationContext::new(
        options.evaluation_date(),
        suppression_sources,
        options.scope(),
        scope_document_state,
    )
    .with_builtin_selection(options.builtin_selection.clone());
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
                format!(
                    "suppression and scope audits exceed the report retention budget; finding acceptance was rolled back, but execution root exclusions remain in effect under {} for policies {:?}",
                    options.scope().source().relative_path(),
                    {
                        let mut ids = registry.policies()
                            .filter(|policy| policy_supports_execution_scope(policy))
                            .map(|policy| &policy.definition().metadata.id)
                            .filter(|id| scoped_files.contains_key(*id))
                            .collect::<Vec<_>>();
                        ids.sort();
                        ids
                    },
                ),
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
    let threshold_exceeded = fail_closed_gate
        || runs.values().flat_map(PolicyRun::findings).any(|finding| {
            finding.suppression().is_none()
                && finding.scope().is_none()
                && finding.baseline().is_none()
                && options.fail_on().matches(finding.severity())
                // Keep exact diff decisions for qualified policies when a
                // different policy lacks complete base evidence. Findings
                // without a decision retain the ordinary full gate.
                && finding.diff().is_none_or(|diff| {
                    diff.disposition() == FindingDiffDisposition::New
                })
        });
    if let Some(review) = diff_review {
        builder.set_diff(review).map_err(|error| {
            PolicyCoordinatorError::new(format!("failed to retain the policy diff review: {error}"))
        })?;
    }
    for policy_id in diff_base_policy_unqualified {
        if let Some(run) = runs.get(&policy_id) {
            for finding in run.findings() {
                if finding.diff().is_none() {
                    continue;
                }
                return Err(PolicyCoordinatorError::new(format!(
                    "unqualified diff-base policy {policy_id} unexpectedly has a finding diff decision for {}",
                    finding.id()
                )));
            }
        }
    }
    // Every diff-base run reports what it reused, including the run that
    // reused nothing. The section is charged to the report's retention budget
    // like the diff review, so a section present in one mode and absent in the
    // other would be a retained size that depends on how the run executed, and
    // two runs that must agree byte for byte could retain a different prefix
    // of the same findings at the exact boundary.
    let incremental_review = options.diff_base().map(|_| match head_incremental {
        Some(incremental) => match diff_baseline
            .as_ref()
            .and_then(|outcome| outcome.base_review.as_ref())
        {
            Some(base_review) => incremental.review().with_base_runs(base_review),
            None => incremental.review(),
        },
        None => {
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
        }
    });
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
    //
    // The diff-base phase is its own stage rather than part of
    // policy evaluation. A diff-scoped run spends its export, base build and
    // base evaluation there before a single head policy runs, and billing that
    // to `policy_evaluation` is what left #3351 unable to say which phase
    // consumed the request budget. The stage is present only when a diff base
    // was requested, and the evaluation stage keeps the head loop's own time so
    // the stages still sum to the run's elapsed time.
    let mut stage_attribution = Vec::with_capacity(5);
    stage_attribution.push(PolicyStageTiming::from_duration(
        PolicyExecutionStage::PolicyRegistration,
        registration_elapsed,
    ));
    stage_attribution.push(PolicyStageTiming::from_duration(
        PolicyExecutionStage::PolicyPreparation,
        preparation_elapsed,
    ));
    if options.diff_base().is_some() {
        stage_attribution.push(PolicyStageTiming::from_duration(
            PolicyExecutionStage::DiffBase,
            diff_base_elapsed,
        ));
    }
    stage_attribution.push(PolicyStageTiming::from_duration(
        PolicyExecutionStage::PolicyEvaluation,
        evaluation_elapsed
            .saturating_sub(diff_base_elapsed)
            .saturating_sub(preparation_elapsed.saturating_sub(preparation_before_diff)),
    ));
    stage_attribution.push(PolicyStageTiming::from_duration(
        PolicyExecutionStage::ReportConstruction,
        report_started.elapsed(),
    ));
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
    // A complete head over a workspace that holds exactly what `HEAD` commits
    // is the answer a later diff base at that commit needs, so it is recorded
    // as one. Only a head this run owns: the base half of a diff run is
    // handed its caller's context and evaluates an exported tree.
    if deadline_stage.is_none()
        && let Some(store) = unit_store.as_ref()
        && store.persisted().is_some()
        && let Some(incremental) = head_incremental_owned.as_ref()
        && let Some(head) = workspace
        && let Some(publication) = head_evaluation_publication(
            root,
            head,
            options,
            base_evaluation_key(
                options,
                scope_document.as_ref(),
                batch_budget,
                registry_limits,
                WorkspaceUnitInputs::of(head, icfg_active_semantic_model_snapshot.as_deref()),
            ),
            incremental,
            &report,
            &runnable_policies,
        )
    {
        store.publish_evaluation(&publication);
    }
    let taint_findings = taint.take_public_findings();
    let taint_analysis_results = taint.take_retained_analyses();
    let exit_status = report_exit_status(&report, threshold_exceeded, options.on_inconclusive());
    Ok(PolicyBatchOutcome {
        report,
        stage_attribution,
        taint_findings,
        taint_analysis_results,
        exit_status,
        max_retained_report_bytes: batch_budget.max_retained_report_bytes(),
        max_serialized_report_bytes: batch_budget.max_serialized_report_bytes(),
        // A full scan's review stays out of the report, which carries the
        // section only for diff runs, but a caller can still read what the
        // scan reused.
        incremental: incremental_review.or_else(|| {
            head_incremental_owned
                .as_ref()
                .map(PolicyIncrementalContext::review)
        }),
    })
}

/// Where one batch's evaluation units live.
///
/// A persisted workspace publishes into the repository's own analyzer cache,
/// so the next run finds them; an ephemeral one keeps them in this process,
/// which is exactly as long as its store would have lasted anyway. Nothing
/// above this distinction knows which one it is holding.
enum BatchUnitStore {
    Memory(Mutex<InMemoryPolicyUnitStore>),
    Persisted(Mutex<PersistedPolicyUnitStore>),
}

impl BatchUnitStore {
    fn of(workspace: Option<&WorkspaceAnalyzer>) -> Self {
        let persisted = workspace
            .filter(|workspace| workspace.persisted_store_path().is_some())
            .and_then(WorkspaceAnalyzer::store);
        match persisted {
            Some(store) => {
                Self::Persisted(Mutex::new(PersistedPolicyUnitStore::new(Arc::clone(store))))
            }
            None => Self::Memory(Mutex::new(InMemoryPolicyUnitStore::new())),
        }
    }

    fn units(&self) -> &Mutex<dyn PolicyUnitStore> {
        match self {
            Self::Memory(store) => store,
            Self::Persisted(store) => store,
        }
    }

    fn persisted(&self) -> Option<&Mutex<PersistedPolicyUnitStore>> {
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
        match store
            .lock()
            .expect("persisted policy-unit store mutex poisoned")
            .flush()
        {
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
            .lock()
            .expect("persisted policy-unit store mutex poisoned")
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
    options: &PolicyEvaluationOptions,
    scope: Option<&PolicyScopeDocument>,
    batch_budget: PolicyBatchBudget,
    registry_limits: PolicyRegistryLimits,
    inputs: WorkspaceUnitInputs,
) -> PolicyEvaluationRowKey {
    // The base's own options, not the head's: it evaluates with the head's
    // suppression and gate configuration deliberately stripped, and the
    // budgets and registry limits it inherits decide what it retains. The
    // head's handling of inconclusive runs is kept: it decides the base's
    // recorded aggregate verdict.
    let base_options = format!(
        "{:?}\u{1}{}\u{1}{}\u{1}{batch_budget:?}\u{1}{registry_limits:?}\u{1}{scope:?}",
        options.evaluation_date(),
        options.require_explicit_schema_versions(),
        options.on_inconclusive().label(),
    );
    PolicyEvaluationRowKey {
        base_tree_oid: String::new(),
        options_digest: StableDigest::sha256(base_options).to_string(),
        configuration_fingerprint: inputs.configuration().to_string(),
        active_model_set_hash: inputs.models().to_string(),
        engine_epoch: inputs.epoch().to_string(),
    }
}

fn policy_set_digest(policies: &[&LoadedPolicy]) -> String {
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
    StableDigest::sha256(policy_set.join("\u{2}")).to_string()
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
    let evaluation = match persisted
        .lock()
        .expect("persisted policy-unit store mutex poisoned")
        .store()
        .policy_evaluation_for_key(&key)
    {
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
    // A shared evaluation row can contain policies from other runs. Admit a
    // child only when its authored and resolved dependency identities match
    // and its own completion is exhaustive. A missing or stale child requires
    // one full base evaluation: the batch retention budget is global, so
    // evaluating only that child could produce a different answer than the
    // original ordered batch.
    let mut recorded: HashMap<&str, _> = HashMap::new();
    for policy in &evaluation.policies {
        recorded.insert(policy.policy_id.as_str(), policy);
    }
    let mut identities: HashMap<PolicyId, HashSet<PolicyFindingId>> = HashMap::new();
    let mut unqualified = Vec::new();
    for policy in policies {
        let policy_id = &policy.definition().metadata.id;
        let Some(evidence) = recorded.remove(policy_id.as_str()) else {
            brokk_bifrost_analysis::profiling::note_with(|| {
                format!("policy.units base_policy_missing={policy_id}")
            });
            return None;
        };
        if evidence.source_hash != policy.source_hash().to_string()
            || evidence.semantic_hash != policy.semantic_hash().to_string()
        {
            brokk_bifrost_analysis::profiling::note_with(|| {
                format!("policy.units base_policy_stale={policy_id}")
            });
            return None;
        }
        if evidence.completion != "complete" || !evidence.qualified {
            unqualified.push(PolicyDiffUnqualifiedPolicy::new(
                policy_id.clone(),
                evidence.completion.clone(),
                if evidence.qualified {
                    evidence.completion_detail.clone()
                } else {
                    evidence.qualification_detail.clone()
                },
                evidence.diagnostics.clone(),
            ));
            continue;
        }
        identities.insert(
            policy_id.clone(),
            evidence
                .identities
                .iter()
                .map(|finding| PolicyFindingId::from_bytes(*finding))
                .collect(),
        );
    }
    let requested_policy_set_digest = policy_set_digest(policies);
    let policy_set_matches = evaluation.policy_set_digest == requested_policy_set_digest;
    let aggregate_unreliable = if policy_set_matches {
        evaluation.aggregate_unreliable
    } else {
        !unqualified.is_empty()
    };
    let unreliable_detail = policy_set_matches
        .then(|| evaluation.unreliable_detail.clone())
        .flatten();
    Some(PolicyDiffBaselineOutcome {
        baseline: PolicyDiffBaseline {
            requested_revision: revision.to_string(),
            // The row is keyed by tree, and another commit with the same tree
            // may have recorded it; the review names the commit asked about.
            resolved_commit: subtree.commit_id().to_string(),
            identities,
            unqualified_policies: unqualified,
            aggregate_unreliable,
            unreliable_detail,
        },
        comparison: Some(BaseComparison {
            changed,
            snapshot: StableDigest::from_array(evaluation.base_content_identity),
        }),
        publication: None,
        state: IncrementalBaseState::Reused,
        base_review: None,
    })
}

/// What the head verifies its units against.
///
/// `changed` is what moved between the base workspace and the head, and
/// `snapshot` is the base workspace's content identity: a unit computed on
/// that snapshot is verified against `changed`, which is a statement about
/// exactly that pair.
struct BaseComparison {
    changed: ChangedFacts,
    snapshot: StableDigest,
}

/// What a run's changed-range request resolved to.
enum ChangedRangeResolution {
    /// The request named no range.
    Unrequested,
    /// The analyzed workspace files the range names.
    Files(Vec<PolicyChangedFile>),
    /// The request could not be resolved, so its runs are whole-workspace.
    Unresolved(String),
}

/// Resolve `request` against the head workspace.
///
/// A diff range reads the exact base blobs and the analyzer's indexed head
/// buffers. Zero-context hunks narrow the changed files from `comparison`.
/// The range is unresolved when that comparison is missing or incomplete: a smaller set
/// could hide a changed sink, so the run must say it is whole-workspace rather
/// than guess.
fn resolve_changed_range(
    request: &PolicyRangeRequest,
    root: &Path,
    revision: Option<&str>,
    workspace: Option<&WorkspaceAnalyzer>,
    comparison: Option<&ChangedFacts>,
) -> ChangedRangeResolution {
    match request {
        PolicyRangeRequest::Workspace => ChangedRangeResolution::Unrequested,
        PolicyRangeRequest::Files(paths) => {
            let Some(workspace) = workspace else {
                return ChangedRangeResolution::Files(Vec::new());
            };
            let wanted = paths.iter().map(String::as_str).collect::<HashSet<_>>();
            ChangedRangeResolution::Files(
                workspace
                    .analyzer()
                    .analyzed_files()
                    .into_iter()
                    .filter(|file| wanted.contains(rel_path_string(file).as_str()))
                    .map(|file| PolicyChangedFile { file, hunks: None })
                    .collect(),
            )
        }
        PolicyRangeRequest::DiffBase => {
            let Some(changed) = comparison else {
                return ChangedRangeResolution::Unresolved(
                    "the diff base has no incremental comparison (the run is not incremental, or the base produced no workspace)"
                        .to_owned(),
                );
            };
            if !changed.is_complete() {
                return ChangedRangeResolution::Unresolved(
                    "the changed facts between the base and the head are incomplete".to_owned(),
                );
            }
            let changed_paths = changed.changed_paths().collect::<HashSet<_>>();
            let Some(workspace) = workspace else {
                return ChangedRangeResolution::Files(Vec::new());
            };
            let hunks = (|| -> Result<Vec<PolicyChangedFile>, String> {
                let subtree =
                    resolve_revision_subtree(root, revision.expect("diff comparison has a base"))?;
                let base_blobs = subtree
                    .blobs()
                    .iter()
                    .map(|(path, oid)| (path.as_ref(), *oid))
                    .collect::<HashMap<_, _>>();
                workspace
                    .analyzer()
                    .analyzed_files()
                    .into_iter()
                    .filter(|file| {
                        let path = rel_path_string(file);
                        changed_paths.contains(&(language_for_file(file), path.as_str()))
                    })
                    .map(|file| {
                        let path = rel_path_string(&file);
                        let base = match base_blobs.get(path.as_str()) {
                            Some(oid) => subtree
                                .source(*oid)
                                .ok_or_else(|| format!("base source unavailable for {path}"))?,
                            None => String::new(),
                        };
                        let head = workspace
                            .analyzer()
                            .indexed_source(&file)
                            .ok_or_else(|| format!("indexed head source unavailable for {path}"))?;
                        Ok(PolicyChangedFile {
                            hunks: Some(changed_buffer_ranges(&base, &head)?),
                            file,
                        })
                    })
                    .collect()
            })();
            match hunks {
                Ok(files) => ChangedRangeResolution::Files(files),
                Err(reason) => ChangedRangeResolution::Unresolved(reason),
            }
        }
    }
}

/// Record on a run that the request did not narrow it, unless the run already
/// says how its endpoints were scoped. Only composed taint sinks narrow.
fn record_unscoped_range(run: PolicyRun, range: &ChangedRangeResolution) -> PolicyRun {
    let reason = match range {
        ChangedRangeResolution::Unrequested => return run,
        ChangedRangeResolution::Unresolved(reason) => {
            format!("changed range unavailable: {reason}")
        }
        ChangedRangeResolution::Files(_) => {
            "the run did not narrow to the changed range; only composed taint sinks do".to_owned()
        }
    };
    if run.scope().is_some() {
        return run;
    }
    run.with_scope(Some(PolicyRunScope::workspace(vec![reason])))
}

/// What the base evaluation produced for the head that follows it.
///
/// `comparison` is computed while both analyzers are alive and retained after
/// the base analyzer is dropped. `None` means the base never built a workspace
/// -- an unreliable or empty base -- so the head has nothing published to
/// verify against and evaluates exactly as a run without a diff base does.
struct PolicyDiffBaselineOutcome {
    baseline: PolicyDiffBaseline,
    comparison: Option<BaseComparison>,
    /// What to record about this base evaluation once the run completes, or
    /// `None` when there is nothing a later run could replay: a base that
    /// published no units, a base that was replayed rather than evaluated, or
    /// an ephemeral workspace whose store outlives nothing.
    publication: Option<PolicyEvaluationRow>,
    /// How this run obtained the base, for the review.
    state: IncrementalBaseState,
    /// What the base evaluation did with each policy's units, when this run
    /// evaluated the base with a unit store.
    base_review: Option<PolicyIncrementalReview>,
}

impl PolicyDiffBaselineOutcome {
    /// A base that produced no workspace, and therefore no units.
    const fn without_units(baseline: PolicyDiffBaseline) -> Self {
        Self {
            baseline,
            comparison: None,
            publication: None,
            state: IncrementalBaseState::Evaluated,
            base_review: None,
        }
    }
}

const MISSING_BASE_POLICY_DETAIL: &str = "the base report has no run for this loaded policy";

/// Base-revision evaluation summary consumed by the diff join.
///
/// `identities` holds strong finding identities only for qualified policies.
/// `unqualified_policies` retains completion and diagnostic context for each
/// policy whose evidence cannot support a diff decision.
struct PolicyDiffBaseline {
    requested_revision: String,
    resolved_commit: String,
    identities: HashMap<PolicyId, HashSet<PolicyFindingId>>,
    unqualified_policies: Vec<PolicyDiffUnqualifiedPolicy>,
    unreliable_detail: Option<String>,
    aggregate_unreliable: bool,
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
    cancellation: &CancellationToken,
) -> Result<(RevisionWorkspace, AnalyzerConfig), String> {
    let config = head_workspace.config().cloned().unwrap_or_default();
    let base = export.build_workspace(head_root, config.clone(), cancellation)?;
    debug_assert_eq!(
        base.workspace().config(),
        Some(&config),
        "a revision workspace must report the configuration it was built with"
    );
    Ok((base, config))
}

/// How one diff-base phase ended.
///
/// A phase that ran out of budget is not the same answer as a base whose
/// evaluation was unreliable: the former ends the run with every policy
/// pending, while the latter degrades the join to full gating and still
/// evaluates the head against it. The evaluated outcome is boxed because it
/// carries the base's identity map and the changed-fact set while the deadline
/// arm carries nothing.
enum DiffBaselinePhase {
    Evaluated(Box<PolicyDiffBaselineOutcome>),
    DeadlineReached,
}

/// Materialize the base revision and evaluate the head's policy sources
/// against it, collecting the strong finding identities and the base run's
/// reliability verdict.
///
/// An unresolvable revision or a workspace outside a git repository is an
/// error: an unresolvable base is an unreliable diff request, never a silent
/// full run. An unreliable base *evaluation* instead degrades, so a broken
/// base cannot mask new findings. A request whose budget expires mid-phase
/// stops the phase: the export, the base build and the base evaluation are
/// each checked, so a spent budget never buys another whole-revision build or
/// a head evaluation the caller cannot wait for.
#[allow(clippy::too_many_arguments)]
fn evaluate_policy_diff_baseline(
    head_root: &Path,
    head_workspace: Option<&WorkspaceAnalyzer>,
    revision: &str,
    head_options: &PolicyEvaluationOptions,
    head_scope: Option<&PolicyScopeDocument>,
    base_inputs: Vec<PolicyEvaluationInput>,
    batch_budget: PolicyBatchBudget,
    registry_limits: PolicyRegistryLimits,
    policies: &[&LoadedPolicy],
    evaluation_key: Option<PolicyEvaluationRowKey>,
    unit_store: Option<&BatchUnitStore>,
    cancellation: Option<&CancellationToken>,
) -> Result<DiffBaselinePhase, PolicyCoordinatorError> {
    if policy_deadline_reached(cancellation)? {
        return Ok(DiffBaselinePhase::DeadlineReached);
    }
    // The diff-base phase can spend minutes on a large repository before a
    // single head policy runs, so its work publishes the request phase a
    // budgeted host reports: a request cut short here says which phase it was
    // in instead of naming the tool (issue #3170), and a progress-capable
    // client watches the phase move (issue #3351).
    let phase_token = cancellation.cloned().unwrap_or_default();
    let export = {
        let _phase = phase_token.enter_phase(format!("materializing the diff base `{revision}`"));
        export_revision(head_root, revision).map_err(|error| {
            PolicyCoordinatorError::new(format!(
                "failed to materialize diff base `{revision}`: {error}"
            ))
        })?
    };
    if base_inputs.is_empty() {
        let detail =
            "the head evaluation has no runnable policy, so the base revision was not evaluated";
        return Ok(DiffBaselinePhase::Evaluated(Box::new(
            PolicyDiffBaselineOutcome::without_units(PolicyDiffBaseline {
                requested_revision: revision.to_string(),
                resolved_commit: export.commit_id().to_string(),
                identities: HashMap::new(),
                unqualified_policies: unqualified_without_run(policies, detail),
                aggregate_unreliable: true,
                unreliable_detail: Some(detail.to_string()),
            }),
        )));
    }
    // A runnable policy is what puts an input in `base_inputs`, and a runnable
    // policy needed an analyzer snapshot to close over, so a base with anything
    // to evaluate always has a head workspace whose configuration it copies.
    let head_workspace = head_workspace
        .expect("a runnable policy input implies the head analyzer workspace that closed it");
    let uncancelled = CancellationToken::default();
    let (base, base_analyzer_config) = {
        let _phase =
            phase_token.enter_phase(format!("building the diff base analyzer for `{revision}`"));
        build_diff_base_workspace(
            &export,
            head_root,
            head_workspace,
            cancellation.unwrap_or(&uncancelled),
        )
        .map_err(|error| {
            PolicyCoordinatorError::new(format!(
                "failed to build the diff base analyzer for `{revision}`: {error}"
            ))
        })?
    };
    if policy_deadline_reached(cancellation)? {
        return Ok(DiffBaselinePhase::DeadlineReached);
    }
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
            let detail = format!(
                "base pack activation failed, so base findings would misstate the configured \
                 external surface: {error}"
            );
            return Ok(DiffBaselinePhase::Evaluated(Box::new(
                PolicyDiffBaselineOutcome::without_units(PolicyDiffBaseline {
                    requested_revision: revision.to_string(),
                    resolved_commit: export.commit_id().to_string(),
                    identities: HashMap::new(),
                    unqualified_policies: unqualified_without_run(policies, &detail),
                    aggregate_unreliable: true,
                    unreliable_detail: Some(detail),
                }),
            )));
        }
    }
    // The base run needs raw identities only: no diff base (which would
    // recurse), no gating threshold, and no head suppression configuration.
    // Its execution domain must match the head, even when the committed base
    // scope differs or the head intentionally has no scope document.
    let mut base_options = PolicyEvaluationOptions::new(head_options.evaluation_date())
        .with_required_schema_versions(head_options.require_explicit_schema_versions())
        .with_on_inconclusive(head_options.on_inconclusive())
        .with_policy_cost_hints(head_options.policy_cost_hints.clone());
    base_options.scope_override = Some(head_scope.cloned());
    // The base evaluates unit by unit for the same reason the head does: a
    // whole execution cannot attribute its reads to seed files, so unit-wise
    // execution is the only way to publish a per-unit read set at all. Its
    // store may hold units from any earlier run. It compares the base with
    // itself, which proves a unit's name-index reads only for a unit computed
    // on this same base snapshot -- a full scan of this revision, or an
    // earlier evaluation of it -- so it reuses exactly those, after checking
    // their other reads against the base, and recomputes every other unit.
    let base_snapshot = unit_store.and_then(|_| workspace_snapshot(base.workspace()));
    let base_changed =
        base_snapshot.map(|_| ChangedFacts::between(base.workspace(), base.workspace()));
    let base_incremental = match (unit_store, base_changed.as_ref(), base_snapshot) {
        (Some(store), Some(changed), Some(snapshot)) => Some(PolicyIncrementalContext::new(
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
            UnitSnapshots::of(snapshot),
        )),
        _ => None,
    };
    let outcome = {
        let _phase = phase_token.enter_phase(format!("evaluating the diff base `{revision}`"));
        evaluate_policy_inputs_with_limits(
            export.root(),
            &base_inputs,
            &base_options,
            batch_budget,
            registry_limits,
            PolicyWorkspaceSource::Supplied(base.workspace()),
            None,
            None,
            None,
            base_incremental.as_ref(),
            cancellation,
        )?
    };
    // A base evaluation that stopped on the budget answers nothing about the
    // base: the head must not run, and its empty identity map must never be
    // mistaken for a base that was evaluated and found unreliable.
    if policy_deadline_reached(cancellation)? {
        return Ok(DiffBaselinePhase::DeadlineReached);
    }
    let report = outcome.report();
    let report_evidence_incomplete =
        report.execution().termination().is_some() || report.diagnostics_truncated();
    let identities = if report_evidence_incomplete {
        HashMap::new()
    } else {
        exhaustive_run_identities(report.runs())
    };
    // Computed here, while both analyzers are alive: the head verifies its
    // units against it after the base analyzer and its export are gone.
    let comparison = base_snapshot.map(|snapshot| BaseComparison {
        changed: ChangedFacts::between(base.workspace(), head_workspace),
        snapshot,
    });
    let unqualified_policies = unqualified_base_policies(policies, report, &identities);
    let aggregate_unreliable = outcome.exit_status() == POLICY_EXIT_UNRELIABLE;
    let unreliable_detail = aggregate_unreliable.then(|| diff_base_unreliable_detail(report));
    let baseline = PolicyDiffBaseline {
        requested_revision: revision.to_string(),
        resolved_commit: export.commit_id().to_string(),
        identities,
        unqualified_policies,
        aggregate_unreliable,
        unreliable_detail,
    };
    if policy_deadline_reached(cancellation)? {
        return Ok(DiffBaselinePhase::DeadlineReached);
    }
    let publication =
        base_incremental
            .as_ref()
            .zip(evaluation_key)
            .and_then(|(incremental, key)| {
                base_evaluation_publication(
                    incremental,
                    key,
                    export.tree_id(),
                    report,
                    policies,
                    &baseline,
                )
            });
    let base_review = base_incremental
        .as_ref()
        .map(PolicyIncrementalContext::review);
    Ok(DiffBaselinePhase::Evaluated(Box::new(
        PolicyDiffBaselineOutcome {
            baseline,
            comparison,
            publication,
            state: IncrementalBaseState::Evaluated,
            base_review,
        },
    )))
}

/// What a run records about its own head for a later run whose diff base is
/// the commit this head holds, or `None` when the head is not that commit's
/// answer (#6638).
///
/// A base evaluation answers one question about one tree: what the policies
/// conclude over its committed bytes, in the head's execution domain, with the
/// conventional suppression and baseline documents and no gate. A head answers
/// the same question when nothing it read differs from `HEAD`: every analyzed
/// file holds the committed blob, the documents and reviewed models under
/// `.bifrost/` are committed and unmodified, the run used the conventional
/// documents, and it evaluated every endpoint rather than a changed range.
/// Without this, only a diff run that evaluated a base recorded one, so a full
/// scan never seeded the next check's base and a check's head never seeded
/// the check after it: each check evaluated its base again.
///
/// The head's report is read exactly as a base evaluation's report is, except
/// for what it says about its own diff base, which describes another tree. A
/// head whose semantic sources failed to activate records nothing, because a
/// base evaluation that met the same failure concludes no identity at all.
fn head_evaluation_publication(
    root: &Path,
    head: &WorkspaceAnalyzer,
    options: &PolicyEvaluationOptions,
    key: PolicyEvaluationRowKey,
    incremental: &PolicyIncrementalContext<'_>,
    report: &PolicyReportDocument,
    policies: &[&LoadedPolicy],
) -> Option<PolicyEvaluationRow> {
    let base_options = PolicyEvaluationOptions::new(options.evaluation_date());
    if *options.range() != PolicyRangeRequest::Workspace
        || options.suppressions() != base_options.suppressions()
        || options.baseline() != base_options.baseline()
        || report.execution().termination().is_some()
        || report.diagnostics_truncated()
        || tree_diagnostics(report).any(|diagnostic| {
            matches!(
                diagnostic.code(),
                PolicyReportDiagnosticCode::PacksLoadFailed
                    | PolicyReportDiagnosticCode::PackActivationFailed
                    | PolicyReportDiagnosticCode::WorkspaceModelLoadFailed
            )
        })
    {
        return None;
    }
    let subtree = match resolve_revision_subtree(root, "HEAD") {
        Ok(subtree) => subtree,
        Err(error) => {
            brokk_bifrost_analysis::profiling::note_with(|| {
                format!("policy.units head_unrecorded head_unresolved={error}")
            });
            return None;
        }
    };
    let changed =
        ChangedFacts::from_committed_tree(head, subtree.blobs(), &|blob| subtree.source(blob));
    if !changed.is_complete() || changed.changed_path_count() != 0 {
        let changed_paths = changed.changed_paths().collect::<Vec<_>>();
        brokk_bifrost_analysis::profiling::note_with(|| {
            format!(
                "policy.units head_unrecorded changed_paths={} paths={changed_paths:?} complete={}",
                changed.changed_path_count(),
                changed.is_complete()
            )
        });
        return None;
    }
    let committed_documents = [
        WORKSPACE_PACKS_DOCUMENT_PATH,
        WORKSPACE_SEMANTIC_MODEL_DIRECTORY,
        DEFAULT_POLICY_BASELINE_PATH,
        DEFAULT_POLICY_SCOPE_PATH,
    ]
    .into_iter()
    .chain(CONVENTIONAL_POLICY_SUPPRESSION_PATHS)
    .collect::<Vec<_>>();
    match worktree_paths_match_head(root, &committed_documents) {
        Ok(true) => {}
        Ok(false) => {
            brokk_bifrost_analysis::profiling::note(
                "policy.units head_unrecorded documents_differ",
            );
            return None;
        }
        Err(error) => {
            brokk_bifrost_analysis::profiling::note_with(|| {
                format!("policy.units head_unrecorded status_failed={error}")
            });
            return None;
        }
    }
    let identities = exhaustive_run_identities(report.runs());
    // The base run gates nothing, so only an orphaned suppression exceeds its
    // threshold.
    let aggregate_unreliable = report_unreliable(
        report,
        tree_diagnostics(report),
        report_has_orphaned_suppression(report),
        options.on_inconclusive(),
    );
    let baseline = PolicyDiffBaseline {
        requested_revision: "HEAD".to_string(),
        resolved_commit: subtree.commit_id().to_string(),
        unqualified_policies: unqualified_base_policies(policies, report, &identities),
        identities,
        aggregate_unreliable,
        unreliable_detail: aggregate_unreliable.then(|| diff_base_unreliable_detail(report)),
    };
    base_evaluation_publication(
        incremental,
        key,
        subtree.tree_id(),
        report,
        policies,
        &baseline,
    )
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
/// Every policy run is recorded with its completion and diagnostics. Only an
/// exhaustive run carries identities and units that may qualify a diff join.
fn base_evaluation_publication(
    incremental: &PolicyIncrementalContext<'_>,
    key: PolicyEvaluationRowKey,
    tree_id: brokk_bifrost_analysis::analyzer::Oid,
    report: &PolicyReportDocument,
    policies: &[&LoadedPolicy],
    baseline: &PolicyDiffBaseline,
) -> Option<PolicyEvaluationRow> {
    // Execution termination depends on time or host conditions absent from
    // the key. Retention truncation is deterministic under its keyed budget.
    if report.execution().termination().is_some() {
        return None;
    }
    let runs = report
        .runs()
        .iter()
        .map(|run| (run.policy_id(), run))
        .collect::<HashMap<_, _>>();
    let mut policy_rows = policies
        .iter()
        .map(|policy| {
            let policy_id = &policy.definition().metadata.id;
            let Some(run) = runs.get(policy_id) else {
                return PolicyEvaluationPolicyRow {
                    policy_id: policy_id.to_string(),
                    source_hash: policy.source_hash().to_string(),
                    semantic_hash: policy.semantic_hash().to_string(),
                    completion: "missing".to_string(),
                    completion_detail: "{\"type\":\"missing\"}".to_string(),
                    qualified: false,
                    qualification_detail: MISSING_BASE_POLICY_DETAIL.to_string(),
                    diagnostics: Vec::new(),
                    identities: Vec::new(),
                    units: Vec::new(),
                };
            };
            let findings = baseline.identities.get(policy_id);
            let units = if findings.is_some() {
                incremental
                    .published_units()
                    .iter()
                    .find(|(published_policy, _)| *published_policy == *policy_id)
                    .map(|(_, keys)| keys.iter().map(row_key).collect())
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            let qualified = findings.is_some();
            let qualification_detail = if qualified {
                String::new()
            } else {
                base_run_unqualified_detail(report, run)
            };
            PolicyEvaluationPolicyRow {
                policy_id: policy_id.to_string(),
                source_hash: policy.source_hash().to_string(),
                semantic_hash: policy.semantic_hash().to_string(),
                completion: run.completion().label().to_string(),
                completion_detail: serde_json::to_string(run.completion())
                    .expect("policy completion serializes"),
                qualified,
                qualification_detail,
                diagnostics: base_run_diagnostics(report, run),
                identities: findings
                    .into_iter()
                    .flat_map(|findings| findings.iter())
                    .map(|finding| *finding.as_bytes())
                    .collect(),
                units,
            }
        })
        .collect::<Vec<_>>();
    policy_rows.sort_by(|left, right| left.policy_id.cmp(&right.policy_id));
    Some(PolicyEvaluationRow {
        key: PolicyEvaluationRowKey {
            base_tree_oid: tree_id.to_string(),
            ..key
        },
        resolved_commit: baseline.resolved_commit.clone(),
        policy_set_digest: policy_set_digest(policies),
        unreliable_detail: baseline.unreliable_detail.clone(),
        aggregate_unreliable: baseline.aggregate_unreliable,
        base_content_identity: *incremental.snapshot().as_bytes(),
        policies: policy_rows,
        unqualified_policy_ids: baseline
            .unqualified_policies
            .iter()
            .map(|policy| policy.policy_id().as_str().to_string())
            .collect(),
    })
}

/// The strong finding identities of every run whose evidence is exhaustive,
/// keyed by policy. A policy is present with an empty set when it concluded no
/// strong identity, which is a complete answer; a run that is not exhaustive is
/// absent, because its findings cannot support a diff decision.
fn exhaustive_run_identities<'a>(
    runs: impl IntoIterator<Item = &'a PolicyRun>,
) -> HashMap<PolicyId, HashSet<PolicyFindingId>> {
    let mut identities: HashMap<PolicyId, HashSet<PolicyFindingId>> = HashMap::new();
    for run in runs {
        if !run.completion().is_exhaustive()
            || run.diagnostics_truncated()
            || run.obligations_truncated()
        {
            continue;
        }
        let policy_identities = identities.entry(run.policy_id().clone()).or_default();
        for finding in run.findings() {
            // Weak identities are snapshot-local by construction and can never
            // equal a head identity, so only strong ones enter the join set.
            if finding.identity_stability() == FindingIdentityStability::Strong {
                policy_identities.insert(finding.id());
            }
        }
    }
    identities
}

/// Every loaded policy whose base evaluation concluded no identities, with
/// the reason it cannot classify head findings.
fn unqualified_base_policies(
    policies: &[&LoadedPolicy],
    report: &PolicyReportDocument,
    identities: &HashMap<PolicyId, HashSet<PolicyFindingId>>,
) -> Vec<PolicyDiffUnqualifiedPolicy> {
    let runs = report
        .runs()
        .iter()
        .map(|run| (run.policy_id(), run))
        .collect::<HashMap<_, _>>();
    policies
        .iter()
        .filter(|policy| !identities.contains_key(&policy.definition().metadata.id))
        .map(|policy| {
            let policy_id = policy.definition().metadata.id.clone();
            let Some(run) = runs.get(&policy_id) else {
                return PolicyDiffUnqualifiedPolicy::new(
                    policy_id,
                    "missing",
                    MISSING_BASE_POLICY_DETAIL,
                    Vec::new(),
                );
            };
            PolicyDiffUnqualifiedPolicy::new(
                policy_id,
                run.completion().label(),
                base_run_unqualified_detail(report, run),
                base_run_diagnostics(report, run),
            )
        })
        .collect()
}

/// Why one base policy run cannot classify head findings, naming the first
/// reason in the order a reader would act on it.
fn base_run_unqualified_detail(report: &PolicyReportDocument, run: &PolicyRun) -> String {
    if report.execution().termination().is_some() {
        format!(
            "base execution terminated: {:?}",
            report.execution().termination()
        )
    } else if report.diagnostics_truncated() {
        "base report diagnostics were truncated".to_string()
    } else if run.diagnostics_truncated() {
        "policy diagnostics were truncated".to_string()
    } else if run.obligations_truncated() {
        "policy obligations were truncated".to_string()
    } else {
        format!(
            "policy completion is not exhaustive: {}",
            serde_json::to_string(run.completion()).expect("policy completion serializes")
        )
    }
}

/// Every diagnostic one base policy run carries into the diff review, with any
/// truncation of the run's or the report's collections stated.
///
/// One list serves both the run that evaluated the base, which reports it
/// directly, and the stored evaluation a later run replays it from, so a run
/// that reuses the base reports exactly what the run that evaluated it did.
fn base_run_diagnostics(report: &PolicyReportDocument, run: &PolicyRun) -> Vec<String> {
    run.diagnostics()
        .iter()
        .map(|diagnostic| serde_json::to_string(diagnostic).expect("policy diagnostic serializes"))
        .chain(tree_diagnostics(report).map(|diagnostic| {
            serde_json::to_string(diagnostic).expect("report diagnostic serializes")
        }))
        .chain(
            report
                .diagnostics_truncated()
                .then(|| "base report diagnostic collection was truncated".to_string()),
        )
        .chain(
            run.diagnostics_truncated()
                .then(|| "policy diagnostic collection was truncated".to_string()),
        )
        .chain(
            run.obligations_truncated()
                .then(|| "policy obligation collection was truncated".to_string()),
        )
        .collect()
}

/// The report diagnostics that describe the tree `report` evaluated.
///
/// A diff head's report also states what happened to its base, which is
/// another tree; a base evaluation's report never does. Recording a head as a
/// later run's base therefore reads exactly what a base evaluation of the same
/// tree would have reported.
fn tree_diagnostics(
    report: &PolicyReportDocument,
) -> impl Iterator<Item = &PolicyReportDiagnostic> + '_ {
    report.diagnostics().iter().filter(|diagnostic| {
        !matches!(
            diagnostic.code(),
            PolicyReportDiagnosticCode::DiffBaseDeadlineExceeded
                | PolicyReportDiagnosticCode::DiffBaseUnreliable
                | PolicyReportDiagnosticCode::DiffBasePolicyUnqualified
        )
    })
}

fn unqualified_without_run(
    policies: &[&LoadedPolicy],
    detail: &str,
) -> Vec<PolicyDiffUnqualifiedPolicy> {
    policies
        .iter()
        .map(|policy| {
            PolicyDiffUnqualifiedPolicy::new(
                policy.definition().metadata.id.clone(),
                "not_evaluated",
                detail,
                Vec::new(),
            )
        })
        .collect()
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

/// Summarize why a base evaluation was unreliable, for the degradation
/// diagnostic. The composed text is bounded later by `safe_report_text`.
fn diff_base_unreliable_detail(report: &PolicyReportDocument) -> String {
    let mut parts = Vec::new();
    if let Some(termination) = report.execution().termination() {
        parts.push(format!("execution terminated ({termination:?})"));
    }
    let codes = tree_diagnostics(report)
        .map(PolicyReportDiagnostic::code)
        .collect::<Vec<_>>();
    if !codes.is_empty() {
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
    let mut matched: HashMap<&PolicyId, HashSet<PolicyFindingId>> = HashMap::new();
    let mut new_count = 0_u64;
    let mut persisting_count = 0_u64;
    for (policy_id, run) in runs.iter_mut() {
        if baseline
            .unqualified_policies
            .iter()
            .any(|unqualified| unqualified.policy_id() == policy_id)
        {
            continue;
        }
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
        baseline.aggregate_unreliable,
        baseline.unqualified_policies.clone(),
        PolicyDiffCounts {
            new: new_count,
            persisting: persisting_count,
            fixed: fixed_count,
        },
        fixed,
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
    scoped_files: &HashMap<PolicyId, Vec<ProjectFile>>,
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
        let (orphan_state, candidates) = if match_state
            == PolicySuppressionMatchState::FindingAbsent
        {
            match record.path() {
                None => (PolicySuppressionOrphanState::PathUnrecorded, Vec::new()),
                Some(path) => {
                    let analyzed =
                        analyzed_paths.get_or_insert_with(|| AnalyzedPaths::collect(workspace));
                    // Findings can anchor outside their analysis root. If any
                    // roots were excluded for this policy, absence at a retained
                    // path does not prove that an old finding was resolved.
                    if analyzed.contains(path) && !scoped_files.contains_key(record.policy_id()) {
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

fn built_in_scope_categories() -> HashMap<PolicyId, PolicyCategoryId> {
    // Category membership is a built-in pack manifest concept; repository
    // policies have no category and match only via policy_ids or an
    // all-policies entry.
    match super::builtin::built_in_policy_catalog() {
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
    }
}

fn apply_policy_scope(
    document: &PolicyScopeDocument,
    policy_categories: &HashMap<PolicyId, PolicyCategoryId>,
    runs: &mut HashMap<PolicyId, PolicyRun>,
) -> Result<Vec<PolicyScopeReview>, PolicyCoordinatorError> {
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

fn prepare_policy_inputs(
    root: &Path,
    policy_inputs: &[PolicyEvaluationInput],
    cancellation: Option<&CancellationToken>,
) -> Result<(PathBuf, WorkspaceRoot, Vec<InputOutcome>), PolicyCoordinatorError> {
    let (root, read_root) = open_policy_workspace_root(root)?;
    let mut inputs = Vec::with_capacity(policy_inputs.len());
    for input in policy_inputs {
        check_policy_cancellation(cancellation)?;
        inputs.push(match input {
            PolicyEvaluationInput::WorkspaceFile(path) => prepare_input(&read_root, path)?,
            PolicyEvaluationInput::Embedded {
                identity,
                source,
                required_capabilities,
                selection_provenance,
            } => prepare_source_input(
                identity.clone(),
                source,
                required_capabilities.clone(),
                *selection_provenance,
            )?,
        });
    }
    exclude_duplicate_policy_ids(&mut inputs)?;
    Ok((root, read_root, inputs))
}

fn owned_policy_project(root: &Path) -> std::io::Result<FilesystemProject> {
    // The project and its listing live for one owned policy-evaluation snapshot.
    // A later evaluation constructs a fresh cache, while repeated analyzer
    // queries in this evaluation reuse the same tracked-plus-ignore-aware set.
    //
    // `with_cached_listing` canonicalizes the project root and asserts the
    // listing was built from that same spelling, so the cache must be built
    // from the canonical root. A lexical `.normalize()` alone keeps platform
    // spellings that differ from `canonicalize` -- `/var` versus `/private/var`
    // on macOS, an 8.3 short name on Windows -- and trips the assertion.
    let root = root.canonicalize()?.normalize();
    let listing = Arc::new(WorkspaceFileListingCache::new(root.clone()));
    FilesystemProject::with_cached_listing(root, listing)
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
    if let Some(outcome) = invalid_input_source_identity(&requested_source)? {
        return Ok(outcome);
    }
    match read_rqlp_document(root, path) {
        Ok(loaded) => {
            let source = PolicySourceIdentity::new(loaded.workspace_path().as_str());
            if let Some(outcome) = invalid_input_source_identity(&source)? {
                return Ok(outcome);
            }
            let (_, document, parsed) = loaded.into_parts();
            prepare_parsed_input(
                source,
                document.source().to_string(),
                parsed.document(),
                Vec::new(),
                None,
            )
        }
        Err(error) => Ok(InputOutcome::Diagnostic(document_load_diagnostic(
            path, &error,
        )?)),
    }
}

fn prepare_source_input(
    source_identity: PolicySourceIdentity,
    source: &str,
    required_capabilities: Vec<String>,
    selection_provenance: Option<PolicySelectionProvenance>,
) -> Result<InputOutcome, PolicyCoordinatorError> {
    if let Some(outcome) = invalid_input_source_identity(&source_identity)? {
        return Ok(outcome);
    }

    match parse_rqlp_source(source, source_identity.clone()) {
        Ok(parsed) => prepare_parsed_input(
            source_identity,
            source.to_owned(),
            parsed.document(),
            required_capabilities,
            selection_provenance,
        ),
        Err(error) => Ok(InputOutcome::Diagnostic(source_diagnostic(
            source_identity,
            &error.diagnostic,
        )?)),
    }
}

fn invalid_input_source_identity(
    identity: &PolicySourceIdentity,
) -> Result<Option<InputOutcome>, PolicyCoordinatorError> {
    match validate_policy_source_identity(identity) {
        Ok(()) => Ok(None),
        Err(error) => Ok(Some(InputOutcome::Diagnostic(
            invalid_source_identity_diagnostic(identity, error)?,
        ))),
    }
}

fn prepare_parsed_input(
    source: PolicySourceIdentity,
    bytes: String,
    document: &RqlpDocument,
    required_capabilities: Vec<String>,
    selection_provenance: Option<PolicySelectionProvenance>,
) -> Result<InputOutcome, PolicyCoordinatorError> {
    match document {
        RqlpDocument::Policy { definition } => Ok(InputOutcome::Pending(PreparedPolicy {
            needs_catalog_registry: super::builtin::policy_needs_catalog_registry(document),
            source,
            bytes,
            policy_id: definition.metadata.id.clone(),
            required_capabilities,
            selection_provenance,
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
        RqlpDocument::EndpointSet { .. } => Ok(InputOutcome::Diagnostic(report_diagnostic(
            PolicyReportDiagnosticCode::NotExecutableEndpoint,
            "an endpoint-set document is a reusable dependency, not an executable policy root"
                .to_string(),
            Some(source),
            None,
            Vec::new(),
        )?)),
        RqlpDocument::DeclarationSelection { .. } => {
            Ok(InputOutcome::Diagnostic(report_diagnostic(
                PolicyReportDiagnosticCode::NotExecutableEndpoint,
                "a declaration-selection document is policy configuration, not an executable policy root"
                    .to_string(),
                Some(source),
                None,
                Vec::new(),
            )?))
        }
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
    let code = schema_version_diagnostic_code(diagnostic.code).unwrap_or(match diagnostic.code {
        "source-too-large"
        | "invalid-s-expression"
        | "incomplete-s-expression"
        | "missing-document"
        | "trailing-document" => PolicyReportDiagnosticCode::PolicyParseFailed,
        _ => PolicyReportDiagnosticCode::PolicyValidationFailed,
    });
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

fn schema_version_diagnostic_code(code: &str) -> Option<PolicyReportDiagnosticCode> {
    match code {
        "unsupported-policy-schema-version" => {
            Some(PolicyReportDiagnosticCode::UnsupportedPolicySchemaVersion)
        }
        "unsupported-rql-schema-version" => {
            Some(PolicyReportDiagnosticCode::UnsupportedRqlSchemaVersion)
        }
        "conflicting-rql-schema-version" => {
            Some(PolicyReportDiagnosticCode::ConflictingRqlSchemaVersion)
        }
        _ => None,
    }
}

fn registry_diagnostic(
    source: PolicySourceIdentity,
    error: &PolicyRegistryError,
) -> Result<PolicyReportDiagnostic, PolicyCoordinatorError> {
    let registry_error = error;
    if let PolicyRegistryError::EndpointSetImport { source, error }
    | PolicyRegistryError::DeclarationSelectionImport { source, error } = error
    {
        let message = match registry_error {
            PolicyRegistryError::DeclarationSelectionImport { .. } => registry_error.to_string(),
            _ => error.to_string(),
        };
        return report_diagnostic(
            PolicyReportDiagnosticCode::PolicyValidationFailed,
            message,
            Some(source.clone()),
            Some(
                PolicySourceRange::try_from(error.diagnostic.range.clone()).map_err(|error| {
                    PolicyCoordinatorError::new(format!(
                        "invalid endpoint-set diagnostic range: {error}"
                    ))
                })?,
            ),
            error.diagnostic.related.clone(),
        );
    }
    let code = match error {
        PolicyRegistryError::Source(error) => schema_version_diagnostic_code(error.diagnostic.code)
            .unwrap_or(PolicyReportDiagnosticCode::PolicyValidationFailed),
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
        let (schema, _) = selector.as_query().expect("selectors are RQL queries");
        let schemas = [(selector.path.as_str().to_owned(), *schema)];
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
        | EndpointOrigin::EndpointSetFile { source, .. }
        | EndpointOrigin::MatchDirectory { source, .. } => Some(source.clone()),
        EndpointOrigin::PolicyLocal { .. } => Some(policy.source().clone()),
        EndpointOrigin::Catalog { .. } => None,
    })
}

fn selector_source(policy: &LoadedPolicy, origin: &SelectorOrigin) -> PolicySourceIdentity {
    match origin {
        SelectorOrigin::Document { source }
        | SelectorOrigin::ReferencedFile { source, .. }
        | SelectorOrigin::DeclarationSelection { source, .. } => source.clone(),
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
fn report_exit_status(
    report: &PolicyReportDocument,
    threshold_exceeded: bool,
    on_inconclusive: PolicyOnInconclusive,
) -> u8 {
    // An accepted decision that no longer resolves to any finding is a defect
    // in the decision record, not in the code (#2418). Without this the
    // rotation is silent: the record stops matching, the finding it covered
    // starts gating as new on exactly one push, and after any merge or
    // projection whose base already contains the rotation it goes quiet again
    // with the dead record still in the document.
    let threshold_exceeded = threshold_exceeded || report_has_orphaned_suppression(report);
    if report_unreliable(
        report,
        report.diagnostics(),
        threshold_exceeded,
        on_inconclusive,
    ) {
        return POLICY_EXIT_UNRELIABLE;
    }
    if threshold_exceeded {
        POLICY_EXIT_FINDING
    } else {
        POLICY_EXIT_CLEAN
    }
}

fn report_has_orphaned_suppression(report: &PolicyReportDocument) -> bool {
    report
        .suppressions()
        .iter()
        .any(PolicySuppressionReview::is_orphaned)
}

/// Whether `report` cannot be trusted, judged by `diagnostics` as its report
/// diagnostics. `threshold_exceeded` is whether the run gates on a finding,
/// orphaned suppressions included.
fn report_unreliable<'a>(
    report: &PolicyReportDocument,
    diagnostics: impl IntoIterator<Item = &'a PolicyReportDiagnostic>,
    threshold_exceeded: bool,
    on_inconclusive: PolicyOnInconclusive,
) -> bool {
    report_lacks_verdict(report, diagnostics, on_inconclusive)
        || (!threshold_exceeded
            && report
                .runs()
                .iter()
                .any(|run| PolicyRunGate::of(run, on_inconclusive) == PolicyRunGate::Subset))
}

/// Whether some part of `report` reached no verdict at all, so no exit status
/// but unreliable may describe it, whatever it found. This is SlopCop's sense
/// of unreliable (#8111): the evaluation terminated, an error report
/// diagnostic, truncated report diagnostics, or a run [`PolicyRunGate`]
/// classifies as unreliable.
pub(crate) fn report_lacks_verdict<'a>(
    report: &PolicyReportDocument,
    diagnostics: impl IntoIterator<Item = &'a PolicyReportDiagnostic>,
    on_inconclusive: PolicyOnInconclusive,
) -> bool {
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
    // TreatMayAsFinding changes publication only; its marker never waives
    // coverage obligations, so the caller's `on_inconclusive` decides it.
    // The marker is set only on an `Inconclusive` run, so a failed or
    // unsupported run still exits unreliable whatever the policy declared.
    report.execution().termination().is_some()
        || diagnostics
            .into_iter()
            .any(|diagnostic| diagnostic.severity() == PolicyDiagnosticSeverity::Error)
        || report.diagnostics_truncated()
        || report
            .runs()
            .iter()
            .any(|run| PolicyRunGate::of(run, on_inconclusive) == PolicyRunGate::Unreliable)
}

fn report_diagnostic(
    code: PolicyReportDiagnosticCode,
    message: impl Into<String>,
    source: Option<PolicySourceIdentity>,
    byte_range: Option<PolicySourceRange>,
    related: Vec<PolicySourceRelatedDiagnostic>,
) -> Result<PolicyReportDiagnostic, PolicyCoordinatorError> {
    report_diagnostic_with_severity(
        code,
        PolicyDiagnosticSeverity::Error,
        message,
        source,
        byte_range,
        related,
    )
}

fn report_diagnostic_with_severity(
    code: PolicyReportDiagnosticCode,
    severity: PolicyDiagnosticSeverity,
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
        severity,
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
    use crate::PolicyRunScopeKind;
    use brokk_bifrost_test_macros::hardwon;
    use std::collections::HashSet;
    use std::fs;

    use brokk_bifrost_analysis::analyzer::DependencyPackActivationOutcome;
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
    use crate::inline_project::{BuiltInlineTestProject, InlineTestProject, run_git};
    use crate::source::MAX_POLICY_SOURCE_IDENTITY_BYTES;
    use crate::suppression::{
        DEFAULT_POLICY_SUPPRESSION_PATH, LOCAL_POLICY_SUPPRESSION_PATH,
        PRIVATE_POLICY_SUPPRESSION_PATH,
    };
    use crate::write_policy_json;

    fn evaluation_options() -> PolicyEvaluationOptions {
        crate::test_support::evaluation_options("2026-07-27")
    }

    #[test]
    #[hardwon(
        "#4994: base evaluation rows failed the completion CHECK for newer completion labels"
    )]
    fn every_policy_completion_round_trips_through_the_store_writer() {
        use crate::finding::PolicyCapability;
        use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("policy-cache.db");
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        let digest = "a".repeat(64);
        let key = PolicyEvaluationRowKey {
            base_tree_oid: "b".repeat(40),
            options_digest: digest.clone(),
            configuration_fingerprint: digest.clone(),
            active_model_set_hash: digest.clone(),
            engine_epoch: digest.clone(),
        };
        let completions = [
            PolicyRunCompletion::Complete,
            PolicyRunCompletion::ProvenSubset { codes: Vec::new() },
            PolicyRunCompletion::ProvenBySummary,
            PolicyRunCompletion::inconclusive(vec![PolicyIncompleteReason::ReportRetentionBudget])
                .expect("canonical reasons"),
            PolicyRunCompletion::NotRun {
                unavailable_capabilities: vec![UnavailablePolicyCapability {
                    label: "qualified-call-locator-zero".to_string(),
                    reason: "no exact identity".to_string(),
                }],
                selected_by: PolicySelectionProvenance::ExplicitPolicyId,
            },
            PolicyRunCompletion::Unsupported {
                capability: PolicyCapability::TaintEvaluation,
            },
            PolicyRunCompletion::Failed {
                reasons: vec![PolicyFailureReason::InvalidExecutionPlan],
            },
        ];
        let policies = completions
            .iter()
            .map(|completion| {
                let qualified = completion.is_exhaustive();
                PolicyEvaluationPolicyRow {
                    policy_id: format!("test.{}", completion.label()),
                    source_hash: digest.clone(),
                    semantic_hash: digest.clone(),
                    completion: completion.label().to_string(),
                    completion_detail: serde_json::to_string(completion).unwrap(),
                    qualified,
                    qualification_detail: if qualified {
                        String::new()
                    } else {
                        "unqualified".to_string()
                    },
                    diagnostics: Vec::new(),
                    identities: Vec::new(),
                    units: Vec::new(),
                }
            })
            .collect::<Vec<_>>();
        store
            .publish_policy_evaluation(PolicyEvaluationRow {
                key: key.clone(),
                resolved_commit: "c".repeat(40),
                policy_set_digest: digest,
                unreliable_detail: None,
                aggregate_unreliable: true,
                base_content_identity: [1; 32],
                unqualified_policy_ids: policies
                    .iter()
                    .filter(|p| !p.qualified)
                    .map(|p| p.policy_id.clone())
                    .collect(),
                policies: policies.clone(),
            })
            .unwrap();
        drop(store);
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        let loaded = store.policy_evaluation_for_key(&key).unwrap().unwrap();
        for expected in policies {
            let actual = loaded
                .policies
                .iter()
                .find(|p| p.policy_id == expected.policy_id)
                .unwrap();
            assert_eq!(actual.completion, expected.completion);
            assert_eq!(actual.completion_detail, expected.completion_detail);
            assert_eq!(actual.qualified, expected.qualified);
        }
    }

    #[test]
    #[hardwon(
        "#4994: absent base runs were omitted from publication and could not replay their verdict"
    )]
    fn missing_base_run_replays_and_terminated_base_is_not_published() {
        let root = tempfile::tempdir().unwrap();
        init_git_workspace(root.path());
        fs::write(root.path().join("app.ts"), "export function target() {}\n").unwrap();
        commit_everything(root.path(), "base");
        let workspace = WorkspaceAnalyzer::build_persisted(
            Arc::new(owned_policy_project(root.path()).unwrap()),
            AnalyzerConfig::default(),
        )
        .unwrap();
        let store = BatchUnitStore::of(Some(&workspace));
        let catalogs = Arc::new(
            TaintCatalogRegistry::new_for_workspace(
                root.path().to_path_buf(),
                CatalogRegistryLimits::default(),
            )
            .unwrap(),
        );
        let mut registry = PolicyRegistry::new_for_workspace(
            root.path().to_path_buf(),
            catalogs,
            PolicyRegistryLimits::default(),
        )
        .unwrap();
        let source = match_policy("test.missing", "Missing");
        let policy = registry
            .register_policy_bytes_with_analyzer(
                PolicySourceIdentity::new("policies/missing.rqlp"),
                source.as_bytes(),
                workspace.analyzer(),
            )
            .unwrap();
        let policies = [policy];
        let changed = ChangedFacts::between(&workspace, &workspace);
        let inputs = WorkspaceUnitInputs::of(&workspace, None);
        let incremental = PolicyIncrementalContext::new(
            store.units(),
            &workspace,
            &changed,
            inputs,
            IncrementalBaseState::Evaluated,
            UnitSnapshots::of(workspace_snapshot(&workspace).unwrap()),
        );
        let subtree = resolve_revision_subtree(root.path(), "HEAD").unwrap();
        let key = base_evaluation_key(
            &evaluation_options(),
            None,
            PolicyBatchBudget::default(),
            PolicyRegistryLimits::default(),
            inputs,
        );
        let report = PolicyReportBuilder::new(PolicyBatchBudget::default(), 0)
            .unwrap()
            .finish()
            .unwrap();
        // Missing evidence can accompany an unreliable batch or a batch whose
        // selection deliberately does not make an absent capability fatal.
        for aggregate_unreliable in [false, true] {
            let baseline = PolicyDiffBaseline {
                requested_revision: "HEAD".to_string(),
                resolved_commit: subtree.commit_id().to_string(),
                identities: HashMap::new(),
                unqualified_policies: vec![PolicyDiffUnqualifiedPolicy::new(
                    policy.definition().metadata.id.clone(),
                    "missing",
                    MISSING_BASE_POLICY_DETAIL,
                    Vec::new(),
                )],
                unreliable_detail: aggregate_unreliable
                    .then(|| "base registration failed".to_string()),
                aggregate_unreliable,
            };
            let row = base_evaluation_publication(
                &incremental,
                key.clone(),
                subtree.tree_id(),
                &report,
                &policies,
                &baseline,
            )
            .unwrap();
            assert_eq!(row.policies.len(), 1);
            assert!(!row.policies[0].qualified);
            assert!(row.policies[0].identities.is_empty());
            store.publish_evaluation(&row);
            let replay = reuse_persisted_diff_baseline(
                root.path(),
                &workspace,
                "HEAD",
                &policies,
                &store,
                &key,
            )
            .unwrap();
            assert_eq!(replay.state, IncrementalBaseState::Reused);
            assert_eq!(
                replay.baseline.unqualified_policies,
                baseline.unqualified_policies
            );
            assert_eq!(
                replay.baseline.aggregate_unreliable,
                baseline.aggregate_unreliable
            );
            assert_eq!(
                replay.baseline.unreliable_detail,
                baseline.unreliable_detail
            );
            assert!(replay.baseline.identities.is_empty());

            let mut builder = PolicyReportBuilder::new(PolicyBatchBudget::default(), 0).unwrap();
            builder
                .set_execution(
                    PolicyExecutionMetadata::try_new(
                        0,
                        Vec::new(),
                        Some(PolicyExecutionTermination::DeadlineExceeded),
                        Some(PolicyExecutionStage::PolicyEvaluation),
                        None,
                        Vec::new(),
                        Vec::new(),
                    )
                    .unwrap(),
                )
                .unwrap();
            let terminated = builder.finish().unwrap();
            assert!(
                base_evaluation_publication(
                    &incremental,
                    key.clone(),
                    subtree.tree_id(),
                    &terminated,
                    &policies,
                    &baseline
                )
                .is_none()
            );
        }
    }

    #[test]
    #[hardwon(
        "#4682: a parallel policy batch must produce the same canonical report bytes as a serial one"
    )]
    fn parallel_policy_evaluation_matches_the_serial_report() {
        let workspace = tempfile::tempdir().expect("workspace directory");
        fs::write(
            workspace.path().join("target.py"),
            "def target():\n    return 1\n\ndef other():\n    return 2\n",
        )
        .expect("Python file");
        // Three independent policies, so a batch at a width above one has more
        // than a single runnable policy to schedule concurrently.
        let sources = ["alpha", "beta", "gamma"].map(|suffix| {
            let source = format!(
                r#"(policy
  :schema-version 1
  :id "test.parallel-{suffix}"
  :name "Python target {suffix}"
  :message "Avoid target"
  :severity warning
  :analysis
    (analysis
      :type match
      :selector
        (rql :schema-version 1
          (language python (function :name "target")))))"#
            );
            PolicyEvaluationInput::embedded(
                PolicySourceIdentity::new(format!("policies/{suffix}.rqlp")),
                source,
            )
        });
        let options = evaluation_options();
        let env_key = crate::parallel::POLICY_PARALLELISM_ENV;

        let prior = std::env::var(env_key).ok();
        // SAFETY: nextest runs each test in its own process, and this test is
        // the only reader or writer of this variable.
        unsafe { std::env::set_var(env_key, "1") };
        let serial = evaluate_policy_inputs(workspace.path(), &sources, &options)
            .expect("serial policy evaluation");
        let serial_bytes = canonical_report_bytes(&serial);

        // SAFETY: see above. A wider pool evaluates the same three policies
        // concurrently; the merged report must be byte-identical.
        unsafe { std::env::set_var(env_key, "4") };
        assert_eq!(
            crate::policy_evaluation_parallelism(),
            4,
            "the test must actually exercise the parallel path"
        );
        let parallel = evaluate_policy_inputs(workspace.path(), &sources, &options)
            .expect("parallel policy evaluation");
        let parallel_bytes = canonical_report_bytes(&parallel);
        let hints = serde_json::from_value(serde_json::json!({
            "test.parallel-alpha": 1,
            "test.parallel-beta": 2,
            "test.parallel-gamma": 3
        }))
        .expect("policy cost hints");
        let hinted = evaluate_policy_inputs(
            workspace.path(),
            &sources,
            &options.with_policy_cost_hints(hints),
        )
        .expect("hinted parallel policy evaluation");
        assert_eq!(serial_bytes, canonical_report_bytes(&hinted));
        assert_eq!(serial.exit_status(), hinted.exit_status());

        match prior {
            Some(value) => unsafe { std::env::set_var(env_key, value) },
            None => unsafe { std::env::remove_var(env_key) },
        }

        assert_eq!(
            parallel.report().runs().len(),
            3,
            "the wide batch ran every policy"
        );
        assert_eq!(
            serial.exit_status(),
            parallel.exit_status(),
            "the wide batch gates exactly as the serial one does"
        );
        assert_eq!(
            serial_bytes, parallel_bytes,
            "the parallel report must match the serial report byte for byte"
        );
    }

    #[test]
    #[hardwon(
        "#7336: a missing restored assembly made discovery incomplete but its diagnostic never reached the report"
    )]
    fn missing_restored_csharp_assembly_reaches_the_policy_report() {
        let project = InlineTestProject::with_language(Language::CSharp)
            .file("App.cs", "class App { static void Target() {} }\n")
            .file("App.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>")
            .file("obj/project.assets.json", r#"{
                "version": 3,
                "targets": { "net8.0": { "Missing.Package/1.0.0": {
                    "type": "package",
                    "compile": { "lib/net8.0/Missing.Package.dll": {} }
                }}},
                "libraries": { "Missing.Package/1.0.0": {
                    "type": "package", "path": "missing.package/1.0.0"
                }},
                "packageFolders": {}
            }"#)
            .build();
        let policy = PolicyEvaluationInput::embedded(
            PolicySourceIdentity::new("policies/target.rqlp"),
            r#"(policy :schema-version 1 :id "test.csharp-discovery"
                :name "C# discovery" :message "Target" :severity warning
                :analysis (analysis :type match :selector
                    (rql :schema-version 1
                        (language csharp (function :name "Target")))) )"#,
        );
        let outcome = evaluate_policy_inputs(project.root(), &[policy], &evaluation_options())
            .expect("C# policy evaluation");
        assert_eq!(outcome.report().runs().len(), 1, "the policy ran");
        let report = serde_json::to_value(outcome.report()).expect("policy report JSON");
        assert_eq!(report["packs"]["complete"], false, "{report:#}");
        assert!(
            report["packs"]["decisions"]
                .as_array()
                .expect("pack decisions")
                .iter()
                .any(|decision| {
                    decision["pack"] == "csharp.dependency_unresolved"
                        && decision["status"] == "missing"
                        && decision["reason"].as_str().is_some_and(|reason| {
                            reason.starts_with("csharp.dependency_unresolved: ")
                                && reason.contains("Missing.Package")
                                && reason.contains("net8.0")
                        })
                }),
            "{report:#}"
        );
    }

    #[test]
    #[hardwon(
        "#3464: a failed standard-library pack preparation must remain visible in the run review instead of disappearing behind the no-pack result."
    )]
    fn failed_dependency_preparation_retains_its_reason_in_the_pack_review() {
        use brokk_bifrost_analysis::analyzer::DependencyPackEcosystemOutcome;
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            DependencyDiscoveryOutcome, DependencyPackDiagnostic, DependencyPackPreparationOutcome,
        };

        let activation = WorkspacePacksActivation {
            ecosystems: vec![DependencyPackEcosystem::Jvm],
            workspace_models: Vec::new(),
            outcome: DependencyPackActivationOutcome {
                ecosystems: vec![DependencyPackEcosystemOutcome {
                    ecosystem: DependencyPackEcosystem::Jvm,
                    discovery: DependencyDiscoveryOutcome::complete(Vec::new()),
                    preparation: Some(DependencyPackPreparationOutcome {
                        packs: Vec::new(),
                        installed_packs: Vec::new(),
                        evidence: Vec::new(),
                        diagnostics: vec![DependencyPackDiagnostic {
                            severity: DependencyPackDiagnosticSeverity::Error,
                            code: "catalog.install".to_owned(),
                            dependency_id: Some("jdk:21.0.8".to_owned()),
                            location: None,
                            message: "generated artifact failed validation".to_owned(),
                        }],
                        suppressed_diagnostics: Default::default(),
                        complete: false,
                        cancelled: false,
                        profile: Default::default(),
                    }),
                }],
                runtime: None,
                diagnostic_refresh_required: true,
            },
        };
        let review =
            pack_activation_review(None, Some(&activation), None, None, None, &BTreeSet::new())
                .expect("an attempted dependency activation has a review");
        assert!(!review.complete());
        let json = serde_json::to_value(review).unwrap();
        assert_eq!(
            json["decisions"],
            json!([{
                "pack": "jdk:21.0.8",
                "status": "rejected",
                "reason": "catalog.install: generated artifact failed validation"
            }])
        );
    }

    /// Every standard-library expectation becomes one decision under its
    /// pack (#3464): an undeclared toolchain is rejected with discovery's
    /// reason, a version near miss keeps preparation's description, and a
    /// declared toolchain with nothing installed is missing with the install
    /// route, replacing the anonymous rows for its dependency. An imported
    /// Node built-in that no active pack declares is missing under its module.
    #[test]
    #[hardwon(
        "#3464: identify which expected standard-library pack failed so zero-configuration activation cannot report an unexplained empty result."
    )]
    fn standard_library_expectations_name_their_pack_with_the_preparation_verdict() {
        use brokk_bifrost_analysis::analyzer::DependencyPackEcosystemOutcome;
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            DependencyDiscoveryOutcome, DependencyPackDiagnostic, DependencyPackPreparationOutcome,
        };

        fn ecosystem(
            ecosystem: DependencyPackEcosystem,
            expectation: StandardLibraryPackExpectation,
            diagnostics: Vec<DependencyPackDiagnostic>,
        ) -> DependencyPackEcosystemOutcome {
            let mut discovery = DependencyDiscoveryOutcome::complete(Vec::new());
            discovery.expect_standard_library_pack(expectation);
            DependencyPackEcosystemOutcome {
                ecosystem,
                discovery,
                preparation: Some(DependencyPackPreparationOutcome {
                    packs: Vec::new(),
                    installed_packs: Vec::new(),
                    evidence: Vec::new(),
                    diagnostics,
                    suppressed_diagnostics: Default::default(),
                    complete: false,
                    cancelled: false,
                    profile: Default::default(),
                }),
            }
        }
        fn error(code: &str, dependency_id: &str, message: &str) -> DependencyPackDiagnostic {
            DependencyPackDiagnostic {
                severity: DependencyPackDiagnosticSeverity::Error,
                code: code.to_owned(),
                dependency_id: Some(dependency_id.to_owned()),
                location: None,
                message: message.to_owned(),
            }
        }

        let rust = StandardLibraryPackExpectation::declared(
            Language::Rust,
            "bifrost.rust-stdlib",
            vec!["rust:stdlib:nightly-2026-08-24".to_owned()],
        );
        let missing_reason = rust.not_installed_reason();
        let activation = WorkspacePacksActivation {
            ecosystems: vec![
                DependencyPackEcosystem::Python,
                DependencyPackEcosystem::Composer,
                DependencyPackEcosystem::Cargo,
            ],
            workspace_models: Vec::new(),
            outcome: DependencyPackActivationOutcome {
                ecosystems: vec![
                    ecosystem(
                        DependencyPackEcosystem::Python,
                        StandardLibraryPackExpectation::declared(
                            Language::Python,
                            "bifrost.python-stdlib",
                            vec!["python:stdlib:declared:cpython:3.9.0".to_owned()],
                        ),
                        vec![error(
                            "dependency.pack_version_mismatch",
                            "python:stdlib:declared:cpython:3.9.0",
                            "pack bifrost.python-stdlib requires cpython >=3.10.0, <3.15.0",
                        )],
                    ),
                    ecosystem(
                        DependencyPackEcosystem::Composer,
                        StandardLibraryPackExpectation::not_selected(
                            Language::Php,
                            "bifrost.php-builtin",
                            "the workspace declares no PHP version".to_owned(),
                        ),
                        Vec::new(),
                    ),
                    ecosystem(
                        DependencyPackEcosystem::Cargo,
                        rust,
                        vec![
                            error(
                                "dependency.pack_unavailable",
                                "rust:stdlib:nightly-2026-08-24",
                                "no pack",
                            ),
                            error(
                                "preparation.unaccounted-dependency",
                                "rust:stdlib:nightly-2026-08-24",
                                "no pack",
                            ),
                        ],
                    ),
                ],
                runtime: None,
                diagnostic_refresh_required: true,
            },
        };
        let node_imports = BTreeSet::from([(Language::JavaScript, "fs")]);
        let review =
            pack_activation_review(None, Some(&activation), None, None, None, &node_imports)
                .expect("an attempted dependency activation has a review");
        let json = serde_json::to_value(review).unwrap();
        assert_eq!(
            json["decisions"],
            json!([
                {
                    "pack": "bifrost.php-builtin",
                    "status": "rejected",
                    "reason": "php: the workspace declares no PHP version"
                },
                {
                    "pack": "bifrost.python-stdlib",
                    "status": "version_mismatch",
                    "reason": "python: pack bifrost.python-stdlib requires cpython >=3.10.0, <3.15.0"
                },
                {
                    "pack": "bifrost.rust-stdlib",
                    "status": "missing",
                    "reason": format!("rust: {missing_reason}")
                },
                {
                    "pack": "node:fs",
                    "status": "missing",
                    "reason": "javascript: the workspace imports the Node built-in module `fs`, \
                               and no active semantic pack declares it"
                }
            ])
        );
    }

    #[test]
    #[hardwon(
        "#3698: reuse the file listing within one workspace epoch, then invalidate it when files are added."
    )]
    fn owned_policy_project_reuses_and_invalidates_workspace_listing() {
        let workspace = tempfile::tempdir().expect("workspace directory");
        let root = workspace
            .path()
            .canonicalize()
            .expect("canonical workspace");
        fs::write(root.join("before.py"), "value = 1\n").expect("initial Python file");

        let project = owned_policy_project(&root).expect("cached policy project");
        let first = project
            .all_files_shared()
            .expect("initial workspace listing");
        let repeated = project
            .all_files_shared()
            .expect("repeated workspace listing");
        assert!(
            Arc::ptr_eq(&first, &repeated),
            "readers share the cached Arc"
        );

        fs::write(root.join("after.py"), "value = 2\n").expect("later Python file");
        fs::remove_file(root.join("before.py")).expect("remove old Python file");
        project.invalidate_cached_file_listing();
        let refreshed = project
            .all_files_shared()
            .expect("listing after invalidation");
        assert!(
            !Arc::ptr_eq(&first, &refreshed),
            "invalidation replaces the Arc"
        );
        assert!(
            refreshed
                .iter()
                .any(|file| file.rel_path() == Path::new("after.py")),
            "invalidation makes newly added workspace files visible"
        );
        assert!(
            !refreshed
                .iter()
                .any(|file| file.rel_path() == Path::new("before.py")),
            "invalidation removes deleted workspace files"
        );
    }

    #[test]
    #[hardwon(
        "#3698: policy evaluation must discover both newly added and deleted workspace files after a cached listing."
    )]
    fn owned_policy_evaluation_observes_added_and_deleted_python_files() {
        let workspace = tempfile::tempdir().expect("workspace directory");
        fs::write(
            workspace.path().join("before.py"),
            "def target():\n    return 1\n",
        )
        .expect("initial Python file");
        let policy = r#"(policy
  :schema-version 1
  :id "test.policy-inventory"
  :name "Python target"
  :message "Avoid target"
  :severity warning
  :analysis
    (analysis
      :type match
      :selector
        (rql :schema-version 1
          (language python (function :name "target")))))"#;
        let input = PolicyEvaluationInput::embedded(
            PolicySourceIdentity::new("policies/target.rqlp"),
            policy,
        );

        let initial = evaluate_policy_inputs(
            workspace.path(),
            std::slice::from_ref(&input),
            &evaluation_options(),
        )
        .expect("initial owned policy evaluation");
        let initial_run = &initial.report().runs()[0];
        assert_eq!(initial.exit_status(), POLICY_EXIT_CLEAN);
        assert!(initial_run.completion().is_complete());
        let initial_findings = initial_run.findings();
        assert_eq!(initial_findings.len(), 1, "the initial file matches");
        assert_eq!(initial_findings[0].primary().path(), "before.py");

        fs::remove_file(workspace.path().join("before.py")).expect("remove initial file");
        fs::write(
            workspace.path().join("after.py"),
            "def target():\n    return 2\n",
        )
        .expect("replacement Python file");
        let refreshed = evaluate_policy_inputs(
            workspace.path(),
            std::slice::from_ref(&input),
            &evaluation_options(),
        )
        .expect("fresh owned policy evaluation");
        let refreshed_run = &refreshed.report().runs()[0];
        assert_eq!(refreshed.exit_status(), POLICY_EXIT_CLEAN);
        assert!(refreshed_run.completion().is_complete());
        let refreshed_findings = refreshed_run.findings();
        assert_eq!(refreshed_findings.len(), 1, "the replacement file matches");
        assert_eq!(refreshed_findings[0].primary().path(), "after.py");
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
                approximate_standard_libraries: Vec::new(),
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

    /// A changed range binds the taint composition's sinks only in its files,
    /// and the run names those files. Each module holds a sink that
    /// a source in the same module reaches, so the whole-workspace run finds
    /// both and the ranged run finds only the sink in its file.
    #[test]
    fn a_changed_range_binds_sinks_only_in_its_files() {
        const MODULE: &str = r#"fn source() -> String {
    String::new()
}

fn sink(text: String) -> usize {
    text.len()
}

pub fn run() {
    let raw = source();
    sink(raw);
}
"#;
        const POLICY: &str = r#"(policy
  :schema-version 1
  :id "test.range"
  :name "Range"
  :message "tainted data reached sink"
  :severity warning
  :analysis (analysis
    :type taint
    :mode may
    :call-modeling (call-modeling :unmodeled optimistic)
    :sources (endpoint-set :entries [
      (source :id raw-input :display-name "raw input" :categories [input.user]
        :selector (rql :schema-version 1
          (language rust (call :callee (name "source"))))
        :bind return-value :labels [attacker-controlled])])
    :sinks (endpoint-set :entries [
      (sink :id sink :display-name "sink" :categories [data.sensitive]
        :selector (rql :schema-version 1
          (language rust (call :callee (name "sink"))))
        :dangerous-operand (argument :index 0)
        :accepts [attacker-controlled])])))
"#;
        let workspace = tempfile::tempdir().expect("workspace directory");
        fs::create_dir_all(workspace.path().join("src")).expect("source directory");
        fs::write(workspace.path().join("src/lib.rs"), "mod a;\nmod b;\n").expect("crate root");
        for module in ["a", "b"] {
            fs::write(workspace.path().join(format!("src/{module}.rs")), MODULE)
                .expect("module source");
        }
        write_policy(workspace.path(), "policies/range.rqlp", POLICY);
        let paths = [PathBuf::from("policies/range.rqlp")];
        let evaluate = |options: &PolicyEvaluationOptions| -> PolicyRun {
            evaluate_policy_files_with_limits(
                workspace.path(),
                &paths,
                options,
                PolicyBatchBudget::default(),
                PolicyRegistryLimits::default(),
            )
            .expect("the policy evaluates")
            .report()
            .runs()[0]
                .clone()
        };
        let sink_files = |run: &PolicyRun| {
            let mut files = run
                .findings()
                .iter()
                .map(|finding| finding.primary().path().to_owned())
                .collect::<Vec<_>>();
            files.sort();
            files
        };

        let whole = evaluate(&evaluation_options());
        assert_eq!(sink_files(&whole), ["src/a.rs", "src/b.rs"]);
        assert!(
            whole.scope().is_none(),
            "a run with no range states no scope"
        );

        let ranged = evaluate(
            &evaluation_options()
                .with_range(PolicyRangeRequest::Files(vec!["src/a.rs".to_owned()])),
        );
        assert_eq!(sink_files(&ranged), ["src/a.rs"]);
        let scope = ranged.scope().expect("a range-scoped run states its scope");
        assert_eq!(scope.kind(), PolicyRunScopeKind::ChangedRange);
        assert!(
            scope
                .examined_procedures()
                .iter()
                .all(|procedure| procedure.path() == "src/a.rs")
        );
        assert!(scope.widened().is_empty());
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

    // Synthetic engine fixture, not a product rule or a framework model.
    const QUALIFIED_CALL_OUTCOME_POLICY: &str = r#"(policy
      :schema-version 1
      :id "test.qualified-call-outcome"
      :name "Qualified call outcome"
      :message "Target call"
      :severity warning
      :analysis (analysis :type assertion
        (bind :name calls :query (rql :schema-version 1
          (resolved-call :resolves-to "Widget.create" :proof exact
            (call-bindings (call-shape (call :callee "create"))))))
        (group :name by-call :by (calls.id)
          (aggregate :name violations :op count))
        (assert :group by-call :value violations :cardinality (exactly 0))))"#;

    #[test]
    #[hardwon(
        "#4803: an unavailable qualified locator must retain a requested policy run without claiming absence"
    )]
    fn unavailable_qualified_locator_retains_a_not_run_policy() {
        let project = InlineTestProject::with_language(Language::Python)
            .file("app.py", "def create(): return 1\nvalue = create()\n")
            .file("policies/qualified.rqlp", QUALIFIED_CALL_OUTCOME_POLICY)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let flow = brokk_bifrost_flow::FlowWorkspaceState::new();
        let catalogs = Arc::new(
            TaintCatalogRegistry::new_for_workspace(
                project.root().to_path_buf(),
                CatalogRegistryLimits::default(),
            )
            .expect("catalog registry"),
        );
        let mut strict = PolicyRegistry::new_for_workspace(
            project.root().to_path_buf(),
            catalogs,
            PolicyRegistryLimits::default(),
        )
        .expect("policy registry");
        let error = strict
            .register_policy_bytes_with_analyzer(
                PolicySourceIdentity::new("policies/qualified.rqlp"),
                QUALIFIED_CALL_OUTCOME_POLICY.as_bytes(),
                workspace.analyzer(),
            )
            .expect_err("direct registration must still reject an unavailable exact identity");
        let PolicyRegistryError::Source(source) = error else {
            panic!("expected a typed qualified locator error: {error}");
        };
        assert!(
            source
                .diagnostic
                .code
                .starts_with("qualified-call-locator-")
        );
        let unavailable = UnavailablePolicyCapability {
            label: source.diagnostic.code.to_owned(),
            reason: source.diagnostic.message,
        };
        let authored_hash = strict
            .register_policy_bytes_deferred(
                PolicySourceIdentity::new("policies/qualified.rqlp"),
                QUALIFIED_CALL_OUTCOME_POLICY.as_bytes(),
            )
            .expect("the complete authored policy is valid")
            .semantic_hash();
        for (selection, expected_exit) in [
            (
                Some(PolicySelectionProvenance::ExplicitPolicyId),
                POLICY_EXIT_UNRELIABLE,
            ),
            (
                Some(PolicySelectionProvenance::PackCategoryOrDefault),
                POLICY_EXIT_CLEAN,
            ),
            (None, POLICY_EXIT_UNRELIABLE),
        ] {
            let input = match selection {
                Some(selection) => PolicyEvaluationInput::embedded_with_selection(
                    PolicySourceIdentity::new("policies/qualified.rqlp"),
                    QUALIFIED_CALL_OUTCOME_POLICY,
                    Vec::new(),
                    Some(selection),
                ),
                None => PolicyEvaluationInput::workspace_file("policies/qualified.rqlp"),
            };
            let selection = selection.unwrap_or(PolicySelectionProvenance::ExplicitPolicyId);
            let outcome = evaluate_policy_inputs_with_analyzer(
                project.root(),
                &[input],
                &workspace,
                &flow,
                &evaluation_options(),
                None,
            )
            .expect("canonical policy report");
            assert_eq!(
                outcome.report().runs().len(),
                1,
                "the policy must remain in the report"
            );
            assert_eq!(outcome.report().rules().len(), 1);
            assert!(outcome.report().diagnostics().is_empty());
            let run = &outcome.report().runs()[0];
            assert_eq!(run.policy_id().as_str(), "test.qualified-call-outcome");
            assert!(run.findings().is_empty());
            assert_eq!(run.policy_hash(), authored_hash);
            assert_eq!(
                run.completion(),
                &PolicyRunCompletion::NotRun {
                    unavailable_capabilities: vec![unavailable.clone()],
                    selected_by: selection,
                }
            );
            assert_eq!(outcome.exit_status(), expected_exit);
        }
    }

    #[test]
    #[hardwon(
        "#4803: a qualified locator must still select its exact declaration, excluding same-named calls"
    )]
    fn available_qualified_locator_evaluates_exact_calls() {
        // Workspace-exact rows prove positive selections. An empty exact
        // selection cannot close a partially discovered Java dispatch family
        // (selector_compiler::admits_existing_incomplete_call_bindings). Keep
        // the standalone near miss inconclusive rather than claiming absence;
        // the mixed case independently checks that its call adds no finding.
        for (body, expected_findings, expected_completion) in [
            ("return Widget.create(1);", 1, PolicyRunCompletion::Complete),
            (
                "int value = Widget.create(1); return Other.create(value);",
                1,
                PolicyRunCompletion::Complete,
            ),
            (
                "return Other.create(1);",
                0,
                PolicyRunCompletion::inconclusive(vec![PolicyIncompleteReason::PartialDiscovery])
                    .expect("partial discovery is an incomplete reason"),
            ),
        ] {
            let source = format!(
                "final class Widget {{ static int create(int value) {{ return value; }} }}\nfinal class Other {{ static int create(int value) {{ return value; }} }}\nclass Caller {{ int run() {{ {body} }} }}\n"
            );
            let project = InlineTestProject::with_language(Language::Java)
                .file("Example.java", &source)
                .build();
            let workspace = project.workspace_analyzer(AnalyzerConfig::default());
            let outcome = evaluate_policy_source(
                project.root(),
                PolicySourceIdentity::new("policies/qualified.rqlp"),
                QUALIFIED_CALL_OUTCOME_POLICY,
                &workspace,
                &brokk_bifrost_flow::FlowWorkspaceState::new(),
                &evaluation_options(),
                None,
            )
            .expect("canonical policy report");
            assert_eq!(outcome.report().runs().len(), 1);
            assert!(outcome.report().diagnostics().is_empty());
            let run = &outcome.report().runs()[0];
            assert_eq!(run.completion(), &expected_completion, "{body}");
            assert_eq!(run.findings().len(), expected_findings, "{body}");
            for finding in run.findings() {
                let primary = finding.primary();
                assert_eq!(primary.path(), "Example.java");
                let span = primary.byte_span().expect("located exact call finding");
                let start = source.find("Widget.create(1)").expect("positive call");
                let end = start + "Widget.create(1)".len();
                assert!(
                    span.start() >= u64::try_from(start).expect("fixture start fits u64")
                        && span.end() <= u64::try_from(end).expect("fixture end fits u64"),
                    "finding must stay within Widget.create, excluding Other.create: {span:?}"
                );
            }
        }
    }

    #[test]
    #[hardwon(
        "#4803: a missing qualified declaration cannot turn invalid policy source into a not-run policy"
    )]
    fn invalid_qualified_policy_source_remains_a_validation_error() {
        let project = InlineTestProject::with_language(Language::Python)
            .file("app.py", "value = 1\n")
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let source = QUALIFIED_CALL_OUTCOME_POLICY
            .replace(":cardinality (exactly 0)", ":cardinality (exactly -1)");
        let outcome = evaluate_policy_source(
            project.root(),
            PolicySourceIdentity::new("policies/invalid.rqlp"),
            &source,
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &evaluation_options(),
            None,
        )
        .expect("canonical invalid-source report");
        assert!(outcome.report().runs().is_empty());
        assert!(outcome.report().rules().is_empty());
        assert!(
            outcome
                .report()
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.severity() == PolicyDiagnosticSeverity::Error)
        );
        assert_eq!(outcome.exit_status(), POLICY_EXIT_UNRELIABLE);
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
                pack_activation_review(None, Some(&activation), None, None, None, &BTreeSet::new())
                    .is_none(),
                "an owned intrinsic-only activation keeps the optional review absent"
            );
            assert_eq!(
                nonready_activation_diagnostic(&activation)
                    .expect("activation diagnostic")
                    .expect("non-ready activation is diagnosed")
                    .code(),
                PolicyReportDiagnosticCode::PackActivationFailed,
            );
            let source = match_policy(
                &format!("test.activation-{label}"),
                "Activation reliability",
            );
            let outcome = evaluate_policy_inputs_with_analyzer_and_host_activation(
                project.root(),
                &[PolicyEvaluationInput::embedded(
                    PolicySourceIdentity::new(format!("policies/{label}.rqlp")),
                    &source,
                )],
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
        crate::policy_suppressions::accepted_suppression_record(
            policy_id,
            finding_id,
            Some(policy_hash),
            "Reviewed exact finding",
            None,
            None,
            path,
        )
    }

    fn write_suppressions(root: &Path, records: Vec<serde_json::Value>) {
        crate::policy_suppressions::write_policy_suppressions(
            root,
            DEFAULT_POLICY_SUPPRESSION_PATH,
            records,
        );
    }

    fn write_test_suppression(root: &Path, policy_id: &str, policy_hash: &str, finding_id: &str) {
        write_suppressions(
            root,
            vec![suppression_record(policy_id, policy_hash, finding_id, None)],
        );
    }

    #[test]
    #[hardwon(
        "#2586: use the analyzer identifier index for procedure-summary candidates instead of scanning every declaration."
    )]
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
        crate::policy_suppressions::write_policy_suppressions(root, relative, records);
    }

    #[test]
    #[hardwon(
        "#2418: combine published and local suppression sources while preserving which source claimed each finding."
    )]
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
    #[hardwon(
        "#2418: conflicting suppression authorities for one finding must be rejected rather than silently choosing one."
    )]
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
    #[hardwon(
        "#2418: a stale suppression whose finding identity rotated must gate the run instead of silently hiding the orphan."
    )]
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
    #[hardwon(
        "#2418: report each files unclaimed finding identities against that same file, including multiple orphans."
    )]
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
    #[hardwon(
        "#2418: a suppression for a file outside this runs analyzed scope must not be misclassified as a stale finding."
    )]
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
    #[hardwon(
        "#2418: pathless suppression records cannot be assigned to an analyzed file and must not produce a false orphan gate."
    )]
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
    #[hardwon(
        "#2605: opt-in stage timings must stay outside canonical report bytes so successful policy runs remain deterministic."
    )]
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
    #[hardwon(
        "#1296: deadline exhaustion must produce the canonical unreliable report instead of a generic cancellation error."
    )]
    fn issue_1296_evaluation_deadline_returns_a_canonical_unreliable_report() {
        let workspace = tempfile::tempdir().expect("workspace");
        fs::write(workspace.path().join("app.ts"), "export const value = 1;\n")
            .expect("source fixture");
        let project = FilesystemProject::new(workspace.path().to_path_buf()).expect("project");
        let project: Arc<dyn Project> = Arc::new(project);
        let analyzer =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("ephemeral workspace should build");
        // Include the registry's entry and pre-commit cancellation checks so
        // this injection still reaches evaluation rather than registration.
        let cancellation = CancellationToken::timeout_after_checks_for_test(11);

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
            PolicyRunCompletion::Inconclusive { reasons, .. }
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
    #[hardwon(
        "#1296: a spent registration deadline must stop before policy evaluation and report that phase accurately."
    )]
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
    #[hardwon(
        "#1296: execution termination must force an unreliable exit even when a partial report contains no finding."
    )]
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
            report_exit_status(outcome.report(), false, PolicyOnInconclusive::Pass),
            POLICY_EXIT_UNRELIABLE
        );
    }

    fn single_run_report(completion: PolicyRunCompletion) -> PolicyReportDocument {
        crate::test_support::report_with_run_completion(
            "test:exit-gate",
            &match_policy("test.exit-gate", "Exit gate"),
            completion,
        )
    }

    #[test]
    #[hardwon(
        "#1916: authored-complete summary evidence may satisfy require-model completion while genuinely inconclusive evidence may not."
    )]
    fn issue_1916_proven_by_summary_passes_the_exit_gate_but_inconclusive_does_not() {
        // A summary-backed run with no findings is trustworthy under the
        // require-model contract, so it exits clean rather than unreliable.
        let proven_by_summary = single_run_report(PolicyRunCompletion::ProvenBySummary);
        assert_eq!(
            report_exit_status(&proven_by_summary, false, PolicyOnInconclusive::Unreliable),
            POLICY_EXIT_CLEAN
        );

        // A genuinely inconclusive run with no findings exits unreliable when
        // the caller asks for the strict reading.
        let inconclusive = single_run_report(
            PolicyRunCompletion::inconclusive(vec![PolicyIncompleteReason::PartialDiscovery])
                .unwrap(),
        );
        assert_eq!(
            report_exit_status(&inconclusive, false, PolicyOnInconclusive::Unreliable),
            POLICY_EXIT_UNRELIABLE
        );
    }

    /// SlopCop's reading of one stored `completion`, transcribed from
    /// `bifrost-service` `server/src/check.rs` (`IncompleteReason::of` and
    /// `IncompletePolicy::is_unproven`): whether the run keeps a clean check
    /// from being clean. A timed-out run blocks; Bifrost's own `inconclusive`
    /// verdict never does, whatever its reasons; every other completion that
    /// is not complete blocks. `SLOPCOP_CLEAN_TYPES` are the completions the
    /// runner does not record as incomplete at all.
    fn slopcop_blocks_clean(completion: &serde_json::Value) -> bool {
        const SLOPCOP_CLEAN_TYPES: [&str; 2] = ["complete", "proven_by_summary"];
        let deadline = completion["reasons"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|reason| reason == "rule_deadline_exceeded");
        if SLOPCOP_CLEAN_TYPES.contains(&completion["type"].as_str().unwrap_or_default()) {
            return false;
        }
        deadline || completion["type"] != "inconclusive"
    }

    #[test]
    #[hardwon(
        "#8111: an inconclusive verdict SlopCop reads as clean failed the published policy-scan action as unreliable"
    )]
    fn issue_8111_exit_status_agrees_with_slopcop_on_one_report() {
        let inconclusive = || {
            PolicyRunCompletion::inconclusive(vec![PolicyIncompleteReason::CapabilityIncomplete])
                .unwrap()
        };
        let failed =
            || PolicyRunCompletion::failed(vec![PolicyFailureReason::InternalInvariant]).unwrap();
        // Done when 1: a report whose only non-complete runs are inconclusive
        // passes by default, as SlopCop calls it clean; done when 2: a run
        // with no verdict still exits unreliable, as SlopCop blocks it.
        for (label, completion, default_status) in [
            ("complete", PolicyRunCompletion::Complete, POLICY_EXIT_CLEAN),
            (
                "proven_by_summary",
                PolicyRunCompletion::ProvenBySummary,
                POLICY_EXIT_CLEAN,
            ),
            ("inconclusive", inconclusive(), POLICY_EXIT_CLEAN),
            (
                "inconclusive deadline",
                PolicyRunCompletion::inconclusive(vec![PolicyIncompleteReason::DeadlineExceeded])
                    .unwrap(),
                POLICY_EXIT_CLEAN,
            ),
            ("failed", failed(), POLICY_EXIT_UNRELIABLE),
        ] {
            let report = single_run_report(completion);
            let stored = serde_json::to_value(report.runs()[0].completion()).unwrap();
            let status = report_exit_status(&report, false, PolicyOnInconclusive::default());
            assert_eq!(status, default_status, "{label}");
            // A deadline Bifrost records as an inconclusive reason is not
            // SlopCop's `rule_deadline_exceeded`, which its runner writes for a
            // rule it stopped itself; every other row reads identically.
            if label != "inconclusive deadline" {
                assert_eq!(
                    status == POLICY_EXIT_UNRELIABLE,
                    slopcop_blocks_clean(&stored),
                    "{label}: {stored}"
                );
            }
        }

        // Findings win over an inconclusive run: the gate names the finding
        // rather than the tooling.
        let report = single_run_report(inconclusive());
        assert_eq!(
            report_exit_status(&report, true, PolicyOnInconclusive::Pass),
            POLICY_EXIT_FINDING
        );
        // The strict reading keeps the behavior before #8111.
        assert_eq!(
            report_exit_status(&report, false, PolicyOnInconclusive::Unreliable),
            POLICY_EXIT_UNRELIABLE
        );
        assert_eq!(
            report_exit_status(&report, true, PolicyOnInconclusive::Unreliable),
            POLICY_EXIT_UNRELIABLE
        );

        // Report-level causes keep a batch of inconclusive runs unreliable
        // under the default: an error report diagnostic and truncated report
        // diagnostics. Termination is pinned by #1296 above.
        let error = report_diagnostic(
            PolicyReportDiagnosticCode::PacksLoadFailed,
            "pack failed to load",
            None,
            None,
            Vec::new(),
        )
        .unwrap();
        let with_report_diagnostics = |diagnostics, truncated, omitted| {
            let run = report.runs()[0].clone();
            PolicyReportDocument::try_new(
                report.rules().to_vec(),
                vec![run],
                diagnostics,
                truncated,
                omitted,
                truncated.then_some(PolicyDiagnosticSeverity::Warning),
            )
            .expect("canonical report")
        };
        assert_eq!(
            report_exit_status(
                &with_report_diagnostics(vec![error], false, 0),
                false,
                PolicyOnInconclusive::Pass
            ),
            POLICY_EXIT_UNRELIABLE
        );
        assert_eq!(
            report_exit_status(
                &with_report_diagnostics(Vec::new(), true, 1),
                false,
                PolicyOnInconclusive::Pass
            ),
            POLICY_EXIT_UNRELIABLE
        );
    }

    #[test]
    #[hardwon(
        "#1331: a deadline racing client cancellation must preserve the canonical deadline report."
    )]
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
                unqualified_policies: Vec::new(),
                unreliable_detail: None,
                aggregate_unreliable: false,
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

    #[test]
    #[hardwon("#2586: mixed diff batches reuse only complete per-policy evidence")]
    fn mixed_diff_base_reuses_only_complete_policy_evidence() {
        let workspace = tempfile::tempdir().expect("workspace");
        init_git_workspace(workspace.path());
        fs::write(
            workspace.path().join("app.ts"),
            "export function target() {}\nexport function over() {}\nexport function over() {}\n",
        )
        .expect("source fixture");
        write_policy(
            workspace.path(),
            "policies/complete.rqlp",
            &match_policy("test.complete", "Complete"),
        );
        write_policy(
            workspace.path(),
            "policies/incomplete.rqlp",
            &match_policy("test.incomplete", "Incomplete")
                .replace(":name \"target\"", ":name \"over\""),
        );
        commit_everything(workspace.path(), "base");

        let per_policy = PolicyBudget::builder()
            .with_max_findings(1)
            .unwrap()
            .build()
            .unwrap();
        let budget = PolicyBatchBudget::builder()
            .with_per_policy(per_policy)
            .unwrap()
            .build()
            .unwrap();
        let options = PolicyEvaluationOptions::new(
            PolicyEvaluationDate::from_ymd(2026, 7, 27).expect("fixed test date"),
        )
        .with_fail_on(PolicyFailOn::Warning)
        .with_diff_base("HEAD".to_string());
        let paths = [
            PathBuf::from("policies/complete.rqlp"),
            PathBuf::from("policies/incomplete.rqlp"),
        ];

        let cold = evaluate_policy_files_with_limits(
            workspace.path(),
            &paths,
            &options,
            budget,
            PolicyRegistryLimits::default(),
        )
        .expect("cold mixed evaluation");
        let warm = evaluate_policy_files_with_limits(
            workspace.path(),
            &paths,
            &options,
            budget,
            PolicyRegistryLimits::default(),
        )
        .expect("warm mixed evaluation");
        for outcome in [&cold, &warm] {
            // The inconclusive base run is advisory (#8111), so the base's
            // aggregate verdict holds and the policy it leaves unqualified
            // gates its head finding in full: the finding, not the tooling,
            // decides the exit status.
            assert_eq!(outcome.exit_status(), POLICY_EXIT_FINDING);
            let review = outcome.report().diff().expect("diff review");
            assert!(!review.degraded());
            assert_eq!(review.persisting_count(), 1);
            assert_eq!(review.unqualified_policies().len(), 1);
            assert_eq!(
                review.unqualified_policies()[0].policy_id().as_str(),
                "test.incomplete"
            );
            let complete = outcome
                .report()
                .runs()
                .iter()
                .find(|run| run.policy_id().as_str() == "test.complete")
                .expect("complete run");
            assert!(complete.completion().is_exhaustive());
            assert_eq!(complete.findings().len(), 1);
            assert_eq!(
                complete.findings()[0]
                    .diff()
                    .map(PolicyFindingDiff::disposition),
                Some(FindingDiffDisposition::Persisting),
            );
            let incomplete = outcome
                .report()
                .runs()
                .iter()
                .find(|run| run.policy_id().as_str() == "test.incomplete")
                .expect("incomplete run");
            assert!(!incomplete.completion().is_exhaustive());
            assert!(
                incomplete
                    .findings()
                    .iter()
                    .all(|finding| finding.diff().is_none())
            );
        }
        assert_eq!(
            cold.report().diff().expect("cold review"),
            warm.report().diff().expect("warm review"),
        );
        assert_eq!(
            warm.report()
                .incremental()
                .expect("warm reuse review")
                .base(),
            IncrementalBaseState::Reused,
        );

        // Changing authored policy bytes invalidates its own cached child.
        // The global report budget requires a full ordered base rerun rather
        // than evaluating only the changed child with a fresh batch quota.
        write_policy(
            workspace.path(),
            "policies/complete.rqlp",
            &match_policy("test.complete", "Renamed complete"),
        );
        let changed = evaluate_policy_files_with_limits(
            workspace.path(),
            &paths,
            &options,
            budget,
            PolicyRegistryLimits::default(),
        )
        .expect("changed policy evaluates its base again");
        assert_eq!(
            changed
                .report()
                .incremental()
                .expect("changed review")
                .base(),
            IncrementalBaseState::Evaluated,
        );
        assert_eq!(
            changed
                .report()
                .diff()
                .expect("changed diff")
                .persisting_count(),
            1
        );
        let changed_warm = evaluate_policy_files_with_limits(
            workspace.path(),
            &paths,
            &options,
            budget,
            PolicyRegistryLimits::default(),
        )
        .expect("unchanged policy reuses its new base answer");
        assert_eq!(
            changed_warm
                .report()
                .incremental()
                .expect("new warm review")
                .base(),
            IncrementalBaseState::Reused,
        );
        assert_eq!(changed.report().diff(), changed_warm.report().diff());

        // A newly requested policy is a missing child under the same shared
        // key. It also forces a complete base evaluation, then becomes warm.
        write_policy(
            workspace.path(),
            "policies/added.rqlp",
            &match_policy("test.added", "Complete empty")
                .replace(":name \"target\"", ":name \"never\""),
        );
        let paths_with_added = [
            PathBuf::from("policies/complete.rqlp"),
            PathBuf::from("policies/incomplete.rqlp"),
            PathBuf::from("policies/added.rqlp"),
        ];
        let added = evaluate_policy_files_with_limits(
            workspace.path(),
            &paths_with_added,
            &options,
            budget,
            PolicyRegistryLimits::default(),
        )
        .expect("new policy evaluates its base");
        assert_eq!(
            added.report().incremental().expect("added review").base(),
            IncrementalBaseState::Evaluated,
        );
        assert_eq!(
            added
                .report()
                .diff()
                .expect("added diff")
                .persisting_count(),
            1
        );
        let added_run = added
            .report()
            .runs()
            .iter()
            .find(|run| run.policy_id().as_str() == "test.added")
            .expect("added complete-empty policy ran");
        assert!(added_run.completion().is_exhaustive());
        assert!(added_run.findings().is_empty());
        assert!(
            added
                .report()
                .diff()
                .expect("added diff")
                .unqualified_policies()
                .iter()
                .all(|policy| policy.policy_id().as_str() != "test.added")
        );
        let added_warm = evaluate_policy_files_with_limits(
            workspace.path(),
            &paths_with_added,
            &options,
            budget,
            PolicyRegistryLimits::default(),
        )
        .expect("new policy is reusable on the next run");
        assert_eq!(
            added_warm
                .report()
                .incremental()
                .expect("added warm review")
                .base(),
            IncrementalBaseState::Reused,
        );
        assert_eq!(added.report().diff(), added_warm.report().diff());
        assert!(
            added_warm
                .report()
                .runs()
                .iter()
                .find(|run| run.policy_id().as_str() == "test.added")
                .expect("reused complete-empty policy ran")
                .findings()
                .is_empty()
        );
    }

    #[test]
    #[hardwon("#2586: stale diff child preserves finding-limit parity across batches")]
    fn stale_diff_child_keeps_batch_finding_limit_parity() {
        let workspace = tempfile::tempdir().expect("workspace");
        init_git_workspace(workspace.path());
        fs::write(
            workspace.path().join("app.ts"),
            "export function target() {}\n",
        )
        .expect("source fixture");
        write_policy(
            workspace.path(),
            "policies/first.rqlp",
            &match_policy("test.first", "First"),
        );
        write_policy(
            workspace.path(),
            "policies/second.rqlp",
            &match_policy("test.second", "Second"),
        );
        commit_everything(workspace.path(), "base");
        let paths = [
            PathBuf::from("policies/first.rqlp"),
            PathBuf::from("policies/second.rqlp"),
        ];
        let options = PolicyEvaluationOptions::new(
            PolicyEvaluationDate::from_ymd(2026, 7, 27).expect("fixed test date"),
        )
        .with_diff_base("HEAD".to_string());
        let budget = PolicyBatchBudget::builder()
            .with_max_total_findings(1)
            .unwrap()
            .build()
            .unwrap();
        let evaluate = || {
            evaluate_policy_files_with_limits(
                workspace.path(),
                &paths,
                &options,
                budget,
                PolicyRegistryLimits::default(),
            )
            .expect("bounded diff evaluation")
        };
        let cold = evaluate();
        let warm = evaluate();
        // The truncated run is inconclusive and advisory (#8111), and no
        // threshold gates, so the batch is clean.
        assert_eq!(cold.exit_status(), POLICY_EXIT_CLEAN);
        assert_eq!(cold.report().diff(), warm.report().diff());
        assert_eq!(
            warm.report().incremental().expect("warm review").base(),
            IncrementalBaseState::Reused,
        );
        assert_eq!(
            warm.report()
                .diff()
                .expect("diff review")
                .unqualified_policies()
                .len(),
            1
        );

        // A source change makes one child stale. Recomputing just that child
        // with a fresh batch quota would manufacture a second complete
        // finding; the full base rerun preserves the original truncation.
        write_policy(
            workspace.path(),
            "policies/second.rqlp",
            &match_policy("test.second", "Renamed second"),
        );
        let changed = evaluate();
        assert_eq!(
            changed
                .report()
                .incremental()
                .expect("changed review")
                .base(),
            IncrementalBaseState::Evaluated,
        );
        assert_eq!(
            changed
                .report()
                .diff()
                .expect("changed diff")
                .persisting_count(),
            1
        );
        assert_eq!(
            changed
                .report()
                .diff()
                .expect("changed diff")
                .unqualified_policies()
                .len(),
            1
        );
        let changed_warm = evaluate();
        assert_eq!(
            changed_warm
                .report()
                .incremental()
                .expect("changed warm review")
                .base(),
            IncrementalBaseState::Reused,
        );
        assert_eq!(changed.report().diff(), changed_warm.report().diff());
    }

    /// The base of a `--diff-base` run must be analyzed the way the head was.
    /// The analyzer configuration selects dependency discovery, dispatch
    /// expansion and per-language behavior, and it is folded into every content
    /// identity a build publishes, so the base must use the same configuration
    /// as the host-supplied head.
    #[test]
    #[hardwon(
        "d0ce89824e27: a warm policy request rebuilt and reprojected the host analyzer although its configuration was unchanged"
    )]
    fn host_policy_requests_reuse_the_default_analyzer_and_diff_base_configuration() {
        // Capture the existing production profiling scopes in an isolated
        // process: timing is read once, and other tests must not share its flag.
        const CHILD: &str = "BIFROST_HOST_CONFIG_PROFILE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(
                std::env::current_exe().expect("current test executable"),
            )
            .args([
                "--exact",
                "coordinator::tests::host_policy_requests_reuse_the_default_analyzer_and_diff_base_configuration",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("BIFROST_TIMING", "1")
            .output()
            .expect("profile host policy requests");
            let stderr = String::from_utf8(output.stderr).expect("UTF-8 profile");
            assert!(output.status.success(), "{stderr}");
            for request in ["cold", "warm"] {
                let trace = stderr
                    .split_once(&format!("HOST_CONFIG_BEGIN {request}\n"))
                    .expect("request begins")
                    .1
                    .split_once(&format!("HOST_CONFIG_END {request}\n"))
                    .expect("request ends")
                    .0;
                assert_eq!(
                    trace
                        .lines()
                        .filter(|line| line.trim_end().ends_with("BEGIN WorkspaceAnalyzer::build"))
                        .count(),
                    0,
                    "{request}: {trace}"
                );
                assert!(
                    trace.contains("policy.host_configuration reused=true"),
                    "{request}: {trace}"
                );
                assert!(
                    !trace.contains("WorkspaceBuildSnapshot::resolve_identities"),
                    "{trace}"
                );
                assert!(!trace.contains("gitblob::dirty_worktree_paths"), "{trace}");
            }
            return;
        }
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

        let project: Arc<dyn Project> =
            Arc::new(FilesystemProject::new(workspace.path()).expect("host project"));
        let host = WorkspaceAnalyzer::build_persisted(project, AnalyzerConfig::default())
            .expect("default host analyzer");
        let inputs = [PolicyEvaluationInput::workspace_file(PathBuf::from(
            "policies/diff.rqlp",
        ))];
        let options = PolicyEvaluationOptions::new(
            PolicyEvaluationDate::from_ymd(2026, 7, 27).expect("fixed test date"),
        );
        let evaluate_host = |request: &str, host: &WorkspaceAnalyzer| {
            eprintln!("HOST_CONFIG_BEGIN {request}");
            let outcome = evaluate_policy_inputs_for_host_session(
                workspace.path(),
                &inputs,
                host,
                &options,
                None,
            )
            .expect("host policy evaluation");
            eprintln!("HOST_CONFIG_END {request}");
            assert_eq!(outcome.report().runs().len(), 1, "{:?}", outcome.report());
            assert_eq!(
                outcome.report().runs()[0].completion(),
                &PolicyRunCompletion::Complete
            );
            assert_eq!(outcome.report().runs()[0].findings().len(), 1);
            outcome
        };
        let cold = evaluate_host("cold", &host);
        let warm = evaluate_host("warm", &host);
        assert_eq!(canonical_report_bytes(&cold), canonical_report_bytes(&warm));

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
            &host,
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
        let (base, base_config) = build_diff_base_workspace(
            &export,
            workspace.path(),
            &host,
            &CancellationToken::default(),
        )
        .expect("base analyzer workspace");
        assert_eq!(base_config, AnalyzerConfig::default());
        assert_eq!(base.workspace().config(), host.config());
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
        assert_eq!(review.persisting_count(), 1);
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
        // The unrelated aggregate diagnostic does not discard this policy's
        // exact base evidence. The scan still exits unreliable.
        assert!(
            outcome
                .report()
                .runs()
                .iter()
                .flat_map(PolicyRun::findings)
                .all(|finding| finding.diff().is_some_and(|diff| {
                    diff.disposition() == FindingDiffDisposition::Persisting
                }))
        );
    }

    /// Issue #3351: a diff-scoped request whose budget expires while the base
    /// revision is being materialized, built, or evaluated must return the
    /// canonical deadline report, never a base-unreliable degradation.
    ///
    /// The coordinator's cancellation checks are counted rather than timed, so
    /// this sweeps every check index the fixture can reach. Before the fix a
    /// spent budget inside the diff-base phase bought the rest of the phase and
    /// a head evaluation: the base's empty identity set joined as `unreliable`,
    /// gating degraded to a full run, and the report carried a head run whose
    /// findings were computed under a cancelled token. That is exactly the
    /// shape the second assertion rejects; the first pins the honest answer for
    /// the checks that land in the phase itself.
    #[test]
    #[hardwon(
        "#3351: exhausting the diff-base budget must leave every policy pending instead of treating the base as a clean result."
    )]
    fn issue_3351_a_spent_budget_in_the_diff_base_leaves_every_policy_pending() {
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
        let project: Arc<dyn Project> =
            Arc::new(FilesystemProject::new(workspace.path()).expect("head project"));
        let head = WorkspaceAnalyzer::build_persisted(project, AnalyzerConfig::default())
            .expect("head analyzer");
        let gating_date = PolicyEvaluationDate::from_ymd(2026, 7, 27).expect("fixed test date");
        let diff_options = PolicyEvaluationOptions::new(gating_date)
            .with_fail_on(PolicyFailOn::Warning)
            .with_diff_base("HEAD".to_string());
        let paths = [PathBuf::from("policies/diff.rqlp")];
        let policy_id = PolicyId::new("test.diff").expect("fixture policy id");
        let mut diff_base_deadlines = 0;

        for checks in 1..=48 {
            let cancellation = CancellationToken::timeout_after_checks_for_test(checks);
            let outcome = evaluate_policy_files_with_analyzer(
                workspace.path(),
                &paths,
                &head,
                &brokk_bifrost_flow::FlowWorkspaceState::new(),
                &diff_options,
                Some(&cancellation),
            )
            .unwrap_or_else(|error| panic!("checks={checks}: {error}"));
            let execution = outcome.report().execution();
            if execution.terminal_stage() == Some(PolicyExecutionStage::DiffBase) {
                diff_base_deadlines += 1;
                assert_eq!(
                    execution.termination(),
                    Some(PolicyExecutionTermination::DeadlineExceeded),
                    "checks={checks}"
                );
                assert!(
                    outcome.report().runs().is_empty(),
                    "checks={checks}: no head policy ran, so no run may be reported"
                );
                assert!(
                    outcome.report().diff().is_none(),
                    "checks={checks}: a base that never finished evaluating has no join to report"
                );
                assert!(
                    outcome
                        .report()
                        .diagnostics()
                        .iter()
                        .any(|diagnostic| diagnostic.code()
                            == PolicyReportDiagnosticCode::DiffBaseDeadlineExceeded),
                    "checks={checks}: the deadline names the phase it stopped"
                );
                assert_eq!(
                    execution.pending_policy_ids(),
                    std::slice::from_ref(&policy_id),
                    "checks={checks}"
                );
                assert!(
                    execution.completed_policy_ids().is_empty()
                        && execution.active_policy_id().is_none(),
                    "checks={checks}"
                );
                assert!(
                    execution
                        .stage_timings()
                        .iter()
                        .any(|timing| timing.stage() == PolicyExecutionStage::DiffBase),
                    "checks={checks}: the phase that spent the budget is attributed"
                );
            }
            assert!(
                !(execution.termination().is_some()
                    && outcome.report().diff().is_some_and(|diff| diff.degraded())
                    && !outcome.report().runs().is_empty()),
                "checks={checks}: a spent budget must not be reported as a degraded base with head runs"
            );
        }
        assert!(
            diff_base_deadlines > 0,
            "the sweep never reached the diff-base phase"
        );
    }

    #[test]
    #[hardwon(
        "#3351: charge and report diff-base work in its own phase so the bounded MCP request accounts for the cost that caused its timeout."
    )]
    fn a_diff_scoped_run_attributes_its_base_phase_separately() {
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
        let paths = [PathBuf::from("policies/diff.rqlp")];

        let diff_options = evaluation_options().with_diff_base("HEAD".to_string());
        let scoped =
            evaluate_policy_files(workspace.path(), &paths, &diff_options).expect("diff run");
        let stages = scoped
            .stage_attribution()
            .iter()
            .map(PolicyStageTiming::stage)
            .collect::<Vec<_>>();
        assert!(
            stages.contains(&PolicyExecutionStage::DiffBase),
            "a diff-scoped run attributes its base phase: {stages:?}"
        );
        assert_eq!(
            stages
                .iter()
                .filter(|stage| **stage == PolicyExecutionStage::DiffBase)
                .count(),
            1,
            "{stages:?}"
        );

        let full = evaluate_policy_files(workspace.path(), &paths, &evaluation_options())
            .expect("full run");
        assert!(
            !full
                .stage_attribution()
                .iter()
                .any(|timing| timing.stage() == PolicyExecutionStage::DiffBase),
            "a run without a diff base has no base phase to attribute"
        );
    }

    #[test]
    #[hardwon("#5236: a modeled &str result kept an InertDropGlue gap")]
    fn modeled_rust_reference_results_close_drop_gaps_and_warn_only_for_workspace_targets() {
        let project = tempfile::tempdir().expect("workspace");
        for (path, source) in [
            (
                "src/lib.rs",
                include_str!("../testdata/modeled-rust-drop/lib.rs"),
            ),
            (
                "policy.rqlp",
                include_str!("../testdata/modeled-rust-drop/policy.rqlp"),
            ),
            (
                ".bifrost/semantic-models/model.json",
                include_str!("../testdata/modeled-rust-drop/model.json"),
            ),
            (
                "Cargo.toml",
                "[package]\nname = \"modeled-drop\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            ),
        ] {
            write_policy(project.path(), path, source);
        }
        // External targets are excluded even in a clean zero-finding run.
        // A stale workspace target still warns independently of findings.
        for (receiver, expected_findings) in [("password", 3), ("absent", 0)] {
            write_policy(
                project.path(),
                "policy.rqlp",
                &include_str!("../testdata/modeled-rust-drop/policy.rqlp")
                    .replace(":name \"password\"", &format!(":name \"{receiver}\"")),
            );
            let outcome = evaluate_policy_files(
                project.path(),
                &[PathBuf::from("policy.rqlp")],
                &evaluation_options(),
            )
            .expect("policy evaluation");
            let report = serde_json::to_value(outcome.report()).expect("render report");
            assert!(
                matches!(
                    report["runs"][0]["completion"]["type"].as_str(),
                    Some("complete" | "proven_by_summary")
                ),
                "{report:#}"
            );
            assert_eq!(
                report["runs"][0]["findings"]
                    .as_array()
                    .expect("findings")
                    .len(),
                expected_findings,
                "{report:#}"
            );
            // Rust call-site refinement can retain finding-level warnings.
            // This regression pins complete discovery: no procedure/drop
            // gap may leave the run incomplete.
            assert!(
                report["runs"][0]["diagnostics"]
                    .as_array()
                    .expect("run diagnostics")
                    .iter()
                    .all(|diagnostic| diagnostic["impact"] != "run_incomplete"),
                "{report:#}"
            );
            let inert = report["diagnostics"]
                .as_array()
                .expect("diagnostics")
                .iter()
                .filter(|diagnostic| diagnostic["code"] == "workspace-model-inert")
                .collect::<Vec<_>>();
            assert_eq!(inert.len(), 1, "{report:#}");
            assert!(
                inert[0]["message"]
                    .as_str()
                    .expect("message")
                    .contains("summary.fixture.missing-workspace-target"),
                "{report:#}"
            );
            let summaries = report["packs"]["decisions"]
                .as_array()
                .expect("pack decisions")
                .iter()
                .find_map(|decision| decision["summary_matches"].as_array())
                .expect("summary matches");
            for summary in summaries {
                assert_eq!(summary["match_count"], 0, "{summary:#}");
            }
        }
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
            &BTreeSet::new(),
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
    #[hardwon("#2893: policy evaluation duration is reported as a work metric when requested")]
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
            unqualified_policies: Vec::new(),
            unreliable_detail: None,
            aggregate_unreliable: false,
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
            unqualified_policies: Vec::new(),
            unreliable_detail: None,
            aggregate_unreliable: false,
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
}

#[cfg(test)]
mod pack_catalog_tests {
    use super::*;
    use crate::catalog::{CatalogRegistryLimits, TaintCatalogDefinition, TaintCatalogRegistry};
    use crate::definition::*;
    use crate::inline_project::InlineTestProject;
    use serde_json::json;
    use std::fs;

    const POLICY: &str = r#"(policy :schema-version 1 :id "test.catalog-flow"
      :name "Catalog flow" :message "tainted data reached sink" :severity warning
      :analysis (analysis :type taint :mode may
        :call-modeling (call-modeling :unmodeled optimistic)
        :sources (endpoint-set :entries [
          (source :id raw :display-name "raw" :categories [input.user]
            :selector (rql :schema-version 1 (language rust (call :callee (name "source"))))
            :bind return-value :labels [untrusted])])
        :sinks (endpoint-set :include-sets [
          (catalog :any-registered true :categories (any [sql-injection]))])))"#;

    #[test]
    fn installed_pack_catalogs_select_categories_and_record_provenance_per_run() {
        let project = InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", "fn source() -> String { String::new() }\nfn sink(s: String) {}\npub fn run() { sink(source()); }\n")
            .build();
        let packs = tempfile::tempdir().unwrap();
        let pack = packs.path().join("test.catalogs");
        fs::create_dir_all(pack.join("catalogs")).unwrap();
        let mut fixture =
            TaintCatalogRegistry::new_without_workspace(CatalogRegistryLimits::default());
        let hash = fixture
            .register(TaintCatalogDefinition {
                schema_version: 1,
                name: PolicyId::new("test.sinks").unwrap(),
                version: 1,
                categories: vec![
                    PolicyCategoryId::new("sql-injection").unwrap(),
                    PolicyCategoryId::new("path-injection").unwrap(),
                ],
                sources: Vec::new(),
                sinks: vec![
                    TaintSinkSpec {
                        id: TaintEntryId::new("sql-execute").unwrap(),
                        display_name: "SQL execute".into(),
                        categories: vec![PolicyCategoryId::new("sql-injection").unwrap()],
                        selector: crate::test_support::inline_match_selector("sink"),
                        dangerous_operand: PolicyPort::ArgumentIndex { index: 0 },
                        accepts: vec![TaintLabel::new("untrusted").unwrap()],
                        tags: Vec::new(),
                        impacts: Vec::new(),
                    },
                    TaintSinkSpec {
                        id: TaintEntryId::new("path-use").unwrap(),
                        display_name: "Path use".into(),
                        categories: vec![PolicyCategoryId::new("path-injection").unwrap()],
                        selector: crate::test_support::inline_match_selector("sink"),
                        dangerous_operand: PolicyPort::ArgumentIndex { index: 0 },
                        accepts: vec![TaintLabel::new("untrusted").unwrap()],
                        tags: Vec::new(),
                        impacts: Vec::new(),
                    },
                ],
                sanitizers: Vec::new(),
                transforms: Vec::new(),
                external_models: Vec::new(),
            })
            .unwrap();
        let document = fixture.iter().next().unwrap().canonical_json().to_vec();
        let fixture = Arc::new(fixture);
        let mut bounded_registry = PolicyRegistry::new_without_workspace(
            fixture.clone(),
            PolicyRegistryLimits::default()
                .with_max_endpoints(2)
                .unwrap(),
        );
        let loaded = bounded_registry
            .register_policy_bytes(PolicySourceIdentity::new("bounded.rqlp"), POLICY.as_bytes())
            .unwrap();
        assert_eq!(
            loaded.resolved_taint().unwrap().sinks.len(),
            1,
            "filter before endpoint budget"
        );
        let overlap_policy = POLICY.replace("(catalog :any-registered true :categories (any [sql-injection]))", "(catalog :name \"test.sinks\" :version 1) (catalog :any-registered true :categories (any [sql-injection]))");
        let mut overlap_registry = PolicyRegistry::new_without_workspace(
            fixture.clone(),
            PolicyRegistryLimits::default()
                .with_max_endpoints(3)
                .unwrap(),
        );
        let overlap = overlap_registry
            .register_policy_bytes(
                PolicySourceIdentity::new("overlap.rqlp"),
                overlap_policy.as_bytes(),
            )
            .unwrap();
        assert_eq!(overlap.resolved_taint().unwrap().sinks.len(), 2);
        let auxiliary_policy = POLICY.replace(":sinks (endpoint-set", ":sanitizers (endpoint-set :include-sets [(catalog :any-registered true :categories (any [sql-injection]))]) :sinks (endpoint-set");
        let mut auxiliary_registry =
            PolicyRegistry::new_without_workspace(fixture, PolicyRegistryLimits::default());
        let error = auxiliary_registry
            .register_policy_bytes(
                PolicySourceIdentity::new("empty-auxiliary.rqlp"),
                auxiliary_policy.as_bytes(),
            )
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("resolved sanitizer endpoint set must not be empty"),
            "{error}"
        );

        fs::write(pack.join("catalogs/sinks.json"), &document).unwrap();
        fs::create_dir_all(pack.join("policies")).unwrap();
        fs::write(pack.join("policies/flow.rqlp"), POLICY).unwrap();
        let identity = crate::builtin::policy_source_identity(
            PolicySourceIdentity::new("fixture.rqlp"),
            POLICY.as_bytes(),
        )
        .unwrap();
        assert!(matches!(
            identity.analyzer_free,
            crate::builtin::PolicySourceIdentityResolution::WorkspaceRequired {
                diagnostic_code: "catalogs-require-policy-run",
                ..
            }
        ));
        let manifest = json!({"schema_version": 2, "id": "test.catalogs", "version": "1.0.0",
            "name": "Test-only catalogs", "description": "Synthetic engine test, no product content",
            "policies": [{"path": "policies/flow.rqlp", "id": "test.catalog-flow", "authored_hash": identity.authored_hash.to_string(),
              "resolved_semantic_hash": null, "category": "security", "supported_languages": ["rust"],
              "required_capabilities": ["taint"], "severity_rationale": "Synthetic flow", "remediation": "Synthetic fixture"}],
            "catalogs": [{"path": "catalogs/sinks.json", "semantic_hash": hash.to_string()}]});
        fs::write(pack.join("manifest.json"), manifest.to_string()).unwrap();
        // nextest isolates every test process, including environment and OnceLocks.
        unsafe {
            std::env::set_var(crate::builtin::POLICY_PACK_ROOT_ENV, packs.path());
        }
        let options = crate::test_support::evaluation_options("2026-10-26");
        let evaluate = |policy: &str| {
            evaluate_policy_inputs(
                project.root(),
                &[PolicyEvaluationInput::embedded(
                    PolicySourceIdentity::new("catalog-test.rqlp"),
                    policy,
                )],
                &options,
            )
            .unwrap()
        };
        let inventory = crate::builtin::built_in_policy_catalog().unwrap();
        let selected = inventory
            .select(&crate::builtin::BuiltInPolicySelection {
                policy_ids: vec!["test.catalog-flow".into()],
                ..Default::default()
            })
            .unwrap();
        assert_eq!(selected.len(), 1);
        let outcome = evaluate_policy_inputs(
            project.root(),
            &[PolicyEvaluationInput::selected_builtin(selected[0])],
            &options,
        )
        .unwrap();
        let report = serde_json::to_value(outcome.report()).unwrap();
        assert_eq!(
            report["runs"][0]["findings"].as_array().unwrap().len(),
            1,
            "{report:#}"
        );
        assert_eq!(
            report["packs"]["catalogs"],
            json!([{"name": "test.sinks", "version": 1, "sha256": hash.to_string()}])
        );
        let provenance = report["runs"][0]["findings"][0].to_string();
        assert!(
            provenance.contains("test.sinks") && provenance.contains("sql-execute"),
            "{provenance}"
        );
        let typo = serde_json::to_value(
            evaluate(&POLICY.replace("sql-injection", "sql-injectoin")).report(),
        )
        .unwrap();
        assert!(
            typo.to_string()
                .contains("unknown catalog category `sql-injectoin`"),
            "{typo:#}"
        );
        let bundle = tempfile::tempdir().unwrap();
        fs::create_dir_all(bundle.path().join("catalogs")).unwrap();
        fs::write(bundle.path().join("catalogs/sinks.json"), &document).unwrap();
        use sha2::Digest;
        let bundle_index = json!({"schema_version": 1, "repository": "test-only/catalogs",
            "source_commit": "synthetic", "bifrost_pin": {}, "policies": [],
            "files": [{"path": "catalogs/sinks.json", "sha256": format!("{:x}", sha2::Sha256::digest(&document)), "size": document.len()}],
            "catalogs": [{"path": "catalogs/sinks.json", "semantic_hash": hash.to_string()}]});
        fs::write(
            bundle.path().join("policy-bundle.json"),
            bundle_index.to_string(),
        )
        .unwrap();
        unsafe {
            std::env::remove_var(crate::builtin::POLICY_PACK_ROOT_ENV);
            std::env::set_var(crate::builtin::POLICY_BUNDLE_ROOT_ENV, bundle.path());
        }
        let bundled = serde_json::to_value(evaluate(POLICY).report()).unwrap();
        assert_eq!(bundled["packs"]["catalogs"], report["packs"]["catalogs"]);
        assert_eq!(
            bundled["runs"][0]["findings"].as_array().unwrap().len(),
            1,
            "{bundled:#}"
        );
        // A manifest pin is checked independently of the archive byte digest.
        let mut bad_pin = bundle_index.clone();
        bad_pin["catalogs"][0]["semantic_hash"] = json!("0".repeat(64));
        fs::write(
            bundle.path().join("policy-bundle.json"),
            bad_pin.to_string(),
        )
        .unwrap();
        let failure = evaluate_policy_inputs(
            project.root(),
            &[PolicyEvaluationInput::embedded(
                PolicySourceIdentity::new("pin.rqlp"),
                POLICY,
            )],
            &options,
        )
        .err()
        .expect("catalog loading must fail");
        assert!(
            failure.to_string().contains("semantic hash mismatch"),
            "{failure}"
        );
        let mut unindexed = bundle_index;
        unindexed["catalogs"][0]["path"] = json!("unindexed.json");
        fs::write(
            bundle.path().join("policy-bundle.json"),
            unindexed.to_string(),
        )
        .unwrap();
        let failure = evaluate_policy_inputs(
            project.root(),
            &[PolicyEvaluationInput::embedded(
                PolicySourceIdentity::new("unindexed.rqlp"),
                POLICY,
            )],
            &options,
        )
        .err()
        .expect("catalog loading must fail");
        assert!(failure.to_string().contains("unindexed file"), "{failure}");
        unsafe {
            std::env::remove_var(crate::builtin::POLICY_BUNDLE_ROOT_ENV);
        }
        // A new run rereads the installation rather than retaining catalog content.
        fs::remove_dir_all(&pack).unwrap();
        unsafe {
            std::env::remove_var(crate::builtin::POLICY_PACK_ROOT_ENV);
        }
        let empty = serde_json::to_value(evaluate(POLICY).report()).unwrap();
        assert!(
            empty
                .to_string()
                .contains("resolved Sink endpoint set must not be empty"),
            "{empty:#}"
        );
    }
    #[test]
    fn generated_jdk_sink_catalog_reports_exec_array_with_entry_provenance() {
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            CatalogOptions, CompilerOptions, SemanticModelActivationEvidence, SessionPackSource,
            SessionPackSourceKind, SourceFormat, compile_source,
        };
        // This golden is generated and schema-validated by the sibling M7
        // foundry test. It is a synthetic engine fixture, never product content.
        let golden: serde_json::Value = serde_json::from_str(include_str!(
            "../../bifrost-semantic-packs/testdata/summary-corpora/codeql-jdk-catalogs/expected.txt"
        ))
        .unwrap();
        let name = "codeql-jdk-sinks-command-injection";
        let document = &golden["catalogs"][name];
        let mut registry = TaintCatalogRegistry::new_without_workspace(Default::default());
        let hash = registry
            .register_json_bytes(
                crate::catalog::CatalogSourceIdentity::new("generated-jdk-fixture").unwrap(),
                &serde_json::to_vec(document).unwrap(),
            )
            .unwrap();
        let packs = tempfile::tempdir().unwrap();
        let pack = packs.path().join("test.generated-jdk");
        fs::create_dir_all(pack.join("catalogs")).unwrap();
        fs::write(
            pack.join("catalogs/sinks.json"),
            serde_json::to_vec(document).unwrap(),
        )
        .unwrap();
        fs::write(pack.join("manifest.json"), json!({
            "schema_version": 2, "id": "test.generated-jdk", "version": "1.0.0",
            "name": "Synthetic generated catalog", "description": "M7 engine fixture only",
            "policies": [], "catalogs": [{"path": "catalogs/sinks.json", "semantic_hash": hash.to_string()}]
        }).to_string()).unwrap();
        let project = InlineTestProject::with_language(Language::Java)
            .file(
                "Probe.java",
                r#"class Probe {
    static String[] source() { return new String[]{"x"}; }
    void run(Runtime runtime, Other other) throws Exception {
        runtime.exec(source());
        other.exec(source());
    }
}
class Other { void exec(String[] value) {} }
"#,
            )
            .build();
        let declarations = json!({
            "schema_version": 19, "pack_id": "test.generated-jdk.declarations", "version": "1.0.0",
            "producer": {"name": "bifrost-test-fixture", "version": "1.0.0"},
            "language": "java", "ecosystem": "jdk", "compatibility": {"toolchains": []},
            "provenance": {"source": "Synthetic test-only unnamed JMOD-style formal", "revision": "#4365"},
            "license": "Apache-2.0", "completeness": "complete",
            "safety": {"generated_code_only": false, "review_required": false},
            "shards": [{"id": "test.runtime.declarations", "activation": [{}], "payload": {
                "kind": "declaration_facts",
                "types": [{"id": "test.runtime", "name": "java.lang.Runtime", "type_kind": "class", "visibility": "public",
                    "locator": {"kind": "artifact", "path": "java.base/java/lang/Runtime.java", "symbol": "java.lang.Runtime"}}],
                "members": [{"id": "test.runtime.exec", "owner": "test.runtime", "name": "exec", "member_kind": "method",
                    "visibility": "public", "is_static": false, "callable_family_complete": true,
                    "signature": {"parameters": [{"type": {"kind": "array", "element": {"kind": "named", "name": "java.lang.String"}}, "passing_mode": "positional_only"}]},
                    "locator": {"kind": "artifact", "path": "java.base/java/lang/Runtime.java", "symbol": "exec(java.lang.String[])"}}]
            }}]
        });
        let compiled = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&declarations).unwrap(),
            &CompilerOptions::default(),
        )
        .unwrap();
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        catalog
            .register_session_pack(
                &compiled,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: "test:generated-jdk-declarations".into(),
                },
            )
            .unwrap();
        let request = SemanticModelActivationRequest {
            approximate_standard_libraries: Vec::new(),
            bifrost_version: env!("CARGO_PKG_VERSION").parse().unwrap(),
            evidence: vec![SemanticModelActivationEvidence {
                language: "java".into(),
                ecosystem: "jdk".into(),
                package: None,
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            }],
            controls: Vec::new(),
            limits: Default::default(),
        };
        let policy = POLICY
            .replace("language rust", "language java")
            .replace("sql-injection", "command-injection")
            .replace("[untrusted]", "[attacker-controlled]");
        unsafe {
            std::env::set_var(crate::builtin::POLICY_PACK_ROOT_ENV, packs.path());
        }
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let outcome = evaluate_policy_inputs_with_analyzer_and_semantic_models(
            project.root(),
            &[PolicyEvaluationInput::embedded(
                PolicySourceIdentity::new("generated.rqlp"),
                &policy,
            )],
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            &crate::test_support::evaluation_options("2026-10-26"),
            PolicySemanticModelContext {
                catalog: &catalog,
                request: &request,
                persistence: None,
            },
            None,
        )
        .unwrap();
        unsafe {
            std::env::remove_var(crate::builtin::POLICY_PACK_ROOT_ENV);
        }
        let report = serde_json::to_value(outcome.report()).unwrap();
        assert_eq!(
            report["runs"][0]["findings"].as_array().unwrap().len(),
            1,
            "{report:#}"
        );
        let primary = outcome.report().runs()[0].findings()[0].primary();
        assert_eq!(primary.path(), "Probe.java");
        let region = primary
            .region()
            .expect("Runtime.exec finding has a source region");
        assert_eq!(region.start_line(), 4);
        assert_eq!(region.end_line(), 4);
        assert_eq!(report["packs"]["catalogs"][0]["name"], name, "{report:#}");
        let finding = report["runs"][0]["findings"][0].to_string();
        let entry = document["sinks"][0]["id"].as_str().unwrap();
        assert!(
            finding.contains(name) && finding.contains(entry),
            "{finding}"
        );
    }

    #[test]
    fn catalog_wildcard_vocabulary_decodes_validates_ranges_and_hovers() {
        let parse = |source: &str| {
            crate::parse_rqlp_source(source, PolicySourceIdentity::new("wildcard.rqlp"))
        };
        let parsed = parse(POLICY).unwrap();
        let RqlpDocument::Policy { definition } = parsed.document() else {
            panic!("policy");
        };
        let PolicyAnalysis::Taint { spec } = &definition.analysis else {
            panic!("taint");
        };
        assert!(matches!(
            spec.sinks.include_sets[0],
            CatalogRef::AnyRegistered { .. }
        ));
        for (keyword, signature) in [
            (":any-registered", ":any-registered true"),
            (":categories (any", ":categories (any|all [CATEGORY...])"),
        ] {
            let offset = POLICY.find(keyword).unwrap() + 2;
            let help = crate::source::rqlp_source_help_at(POLICY, offset).unwrap();
            assert_eq!(help.signature, signature);
        }
        let invalid = POLICY.replace(":any-registered true", ":any-registered maybe");
        let error = parse(&invalid).unwrap_err().diagnostic;
        assert_eq!(&invalid[error.range], "maybe");
        for reference in [
            "(catalog :any-registered false :categories (any [sql-injection]))",
            "(catalog :any-registered true)",
            "(catalog :name test.sinks :version 1 :categories (any [sql-injection]))",
            "(catalog :any-registered true :name test.sinks :categories (any [sql-injection]))",
        ] {
            let source = POLICY.replace(
                "(catalog :any-registered true :categories (any [sql-injection]))",
                reference,
            );
            assert_eq!(
                parse(&source).unwrap_err().diagnostic.code,
                "invalid-catalog-reference"
            );
        }
        let exact = POLICY.replace(":sinks (endpoint-set", ":finding-combinations [(finding-combination :id exact :source (categories :any [input.user]) :sink (endpoints [(endpoint-ref :catalog (catalog :any-registered true :categories (any [sql-injection])) :entry sql-execute)]) :message \"M\")] :sinks (endpoint-set");
        let error = parse(&exact).unwrap_err().diagnostic;
        assert_eq!(error.code, "invalid-endpoint-reference", "{error:?}");
        assert!(exact[error.range].starts_with("(catalog :any-registered"));
        for (kind, entry) in [
            (
                "sanitizers",
                "(sanitizer :id clean :categories [sql-injection] :selector (rql :schema-version 1 (name \"clean\")) :input (argument :index 0) :output return-value :removes [untrusted])",
            ),
            (
                "transforms",
                "(transform :id clean :categories [sql-injection] :selector (rql :schema-version 1 (name \"clean\")) :input (argument :index 0) :output return-value :adds [untrusted])",
            ),
            (
                "external-models",
                "(external-model :id clean :categories [sql-injection] :selector (rql :schema-version 1 (name \"clean\")) :transfers [(transfer :from (argument :index 0) :to return-value :labels [untrusted] :effect propagate)])",
            ),
        ] {
            let source = format!(
                "(endpoint-set-document :schema-version 1 :kind {kind} :set (endpoint-set :entries [{entry}]))"
            );
            let parsed = parse(&source).unwrap();
            assert_eq!(
                parsed.document().to_normalized_authored_json()["set"]["entries"][0]["categories"],
                json!(["sql-injection"])
            );
            let offset = source.find(":categories").unwrap() + 2;
            assert_eq!(
                crate::source::rqlp_source_help_at(&source, offset)
                    .unwrap()
                    .signature,
                ":categories [CATEGORY...]"
            );
        }
    }
}
