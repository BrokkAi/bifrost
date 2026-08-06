//! One-shot, collect-and-continue policy batch coordination.
//!
//! This module owns the boundary between capability-confined policy loading,
//! analyzer-backed evaluation, canonical report assembly, and CLI status
//! selection. Renderers consume only the returned [`PolicyReportDocument`].

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::semantic_model::{
    SemanticModelActivationPersistence, SemanticModelActivationRequest,
    SemanticModelRuntimeOutcome, SemanticPackCatalog, acquire_active_semantic_models,
};
use brokk_bifrost_analysis::analyzer::{
    AnalyzerConfig, FilesystemProject, Project, WorkspaceAnalyzer,
};
use brokk_bifrost_analysis::schema_version::SchemaVersionOrigin;
use brokk_bifrost_analysis::workspace_document::WorkspaceRoot;

use super::catalog::{CatalogRegistryLimits, TaintCatalogRegistry};
use super::definition::{FindingSeverity, PolicyCategoryId, PolicyId, RqlpDocument};
use super::evaluator::{DefaultPolicyEvaluator, PolicyEvaluationContext, PolicyEvaluator};
use super::finding::{
    PolicyDiagnostic, PolicyDiagnosticCode, PolicyDiagnosticImpact, PolicyDiagnosticSeverity,
    PolicyFailureReason, PolicyIncompleteReason, PolicyRun, PolicyRunCompletion, PolicyWorkReport,
};
use super::finding_identity::FindingIdentityStability;
use super::loading::{PolicyDocumentLoadError, read_rqlp_document};
use super::registry::{PolicyRegistry, PolicyRegistryError, PolicyRegistryLimits};
use super::report::{
    PolicyExecutionMetadata, PolicyExecutionStage, PolicyExecutionTermination, PolicyReportBuilder,
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
    PolicyEvaluationDate, PolicyReportEvaluationContext, PolicySuppressionDocument,
    PolicySuppressionDocumentState, PolicySuppressionMatchState, PolicySuppressionOptions,
    PolicySuppressionPolicyHashState, PolicySuppressionReview, PolicySuppressionTemporalState,
    load_policy_suppressions_from_root,
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
    require_explicit_schema_versions: bool,
    fail_on: PolicyFailOn,
}

impl PolicyEvaluationOptions {
    pub fn new(evaluation_date: PolicyEvaluationDate) -> Self {
        Self {
            evaluation_date,
            suppressions: PolicySuppressionOptions::default(),
            scope: PolicyScopeOptions::default(),
            require_explicit_schema_versions: false,
            fail_on: PolicyFailOn::Never,
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
            require_explicit_schema_versions: false,
            fail_on: PolicyFailOn::Never,
        }
    }

    pub fn with_scope(mut self, scope: PolicyScopeOptions) -> Self {
        self.scope = scope;
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

    pub const fn evaluation_date(&self) -> PolicyEvaluationDate {
        self.evaluation_date
    }

    pub const fn suppressions(&self) -> &PolicySuppressionOptions {
        &self.suppressions
    }

    pub const fn scope(&self) -> &PolicyScopeOptions {
        &self.scope
    }

    pub const fn require_explicit_schema_versions(&self) -> bool {
        self.require_explicit_schema_versions
    }

    pub const fn fail_on(&self) -> PolicyFailOn {
        self.fail_on
    }
}

impl RetainedSize for PolicyEvaluationOptions {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(retained_extra(&self.suppressions))
            .saturating_add(retained_extra(&self.scope))
    }
}

/// Complete canonical report plus the already precedence-resolved CLI status.
pub struct PolicyBatchOutcome {
    report: PolicyReportDocument,
    taint_findings: Vec<brokk_bifrost_analysis::analyzer::structural::CodeQueryTaintFinding>,
    taint_analysis_results: Vec<Arc<crate::ProductionTaintAnalysisResult>>,
    exit_status: u8,
    max_retained_report_bytes: usize,
    max_serialized_report_bytes: usize,
}

impl PolicyBatchOutcome {
    pub const fn report(&self) -> &PolicyReportDocument {
        &self.report
    }

    pub fn into_report(self) -> PolicyReportDocument {
        self.report
    }

    pub fn record_preparation_timings(
        &mut self,
        selection_elapsed: Duration,
        snapshot_elapsed: Duration,
    ) {
        let current = self.report.execution();
        if current.termination().is_none() {
            return;
        }
        let mut stage_timings = current.stage_timings().to_vec();
        stage_timings.push(PolicyStageTiming::from_duration(
            PolicyExecutionStage::PolicySelection,
            selection_elapsed,
        ));
        stage_timings.push(PolicyStageTiming::from_duration(
            PolicyExecutionStage::WorkspaceSnapshot,
            snapshot_elapsed,
        ));
        let preparation_elapsed_ms = stage_timings
            .iter()
            .filter(|timing| {
                matches!(
                    timing.stage(),
                    PolicyExecutionStage::PolicySelection | PolicyExecutionStage::WorkspaceSnapshot
                )
            })
            .fold(0_u64, |total, timing| {
                total.saturating_add(timing.elapsed_ms())
            });
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
    pub fn taint_findings(
        &self,
    ) -> &[brokk_bifrost_analysis::analyzer::structural::CodeQueryTaintFinding] {
        &self.taint_findings
    }

    /// Immutable production plan/report pairs retained from the propagation
    /// runs that produced this policy outcome.
    pub fn taint_analysis_results(&self) -> &[Arc<crate::ProductionTaintAnalysisResult>] {
        &self.taint_analysis_results
    }

    pub fn taint_query_results(
        &self,
    ) -> impl ExactSizeIterator<
        Item = brokk_bifrost_analysis::analyzer::structural::CodeQueryResultValue,
    > + '_ {
        self.taint_findings.iter().cloned().map(|value| {
            brokk_bifrost_analysis::analyzer::structural::CodeQueryResultValue::TaintFinding {
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
    evaluate_policy_inputs_with_analyzer(root, &inputs, workspace, options, cancellation)
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
    )
}

/// Evaluate mixed policy inputs against a caller-owned immutable analyzer snapshot.
pub fn evaluate_policy_inputs_with_analyzer(
    root: impl AsRef<Path>,
    policy_inputs: &[PolicyEvaluationInput],
    workspace: &WorkspaceAnalyzer,
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

/// Evaluate mixed policy inputs with one generation-cached semantic-model acquisition.
pub fn evaluate_policy_inputs_with_analyzer_and_semantic_models(
    root: impl AsRef<Path>,
    policy_inputs: &[PolicyEvaluationInput],
    workspace: &WorkspaceAnalyzer,
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
        Some(semantic_models),
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
    options: &PolicyEvaluationOptions,
    cancellation: Option<&CancellationToken>,
) -> Result<PolicyBatchOutcome, PolicyCoordinatorError> {
    evaluate_policy_inputs_with_analyzer(
        root,
        &[PolicyEvaluationInput::embedded(source_identity, source)],
        workspace,
        options,
        cancellation,
    )
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
        PolicySuppressionDocumentState::NotEvaluated,
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

#[allow(clippy::too_many_arguments)]
fn deadline_before_evaluation_outcome(
    options: &PolicyEvaluationOptions,
    batch_budget: PolicyBatchBudget,
    suppression_document_state: PolicySuppressionDocumentState,
    scope_document_state: PolicyScopeDocumentState,
    stage_timings: Vec<PolicyStageTiming>,
    terminal_stage: PolicyExecutionStage,
    pending_policy_ids: Vec<PolicyId>,
    diagnostic: Option<PolicyReportDiagnostic>,
) -> Result<PolicyBatchOutcome, PolicyCoordinatorError> {
    let evaluation = PolicyReportEvaluationContext::new(
        options.evaluation_date(),
        options.suppressions(),
        suppression_document_state,
        options.scope(),
        scope_document_state,
    );
    let diagnostics = diagnostic.into_iter().collect();
    let total_elapsed_ms = stage_timings.iter().fold(0_u64, |total, timing| {
        total.saturating_add(timing.elapsed_ms())
    });
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
        taint_findings: Vec::new(),
        taint_analysis_results: Vec::new(),
        exit_status: POLICY_EXIT_UNRELIABLE,
        max_retained_report_bytes: batch_budget.max_retained_report_bytes(),
        max_serialized_report_bytes: batch_budget.max_serialized_report_bytes(),
    })
}

fn evaluate_policy_files_with_limits(
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
    semantic_models: Option<PolicySemanticModelContext<'_>>,
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
        semantic_models,
        cancellation,
    )
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
    semantic_models: Option<PolicySemanticModelContext<'_>>,
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
    if policy_deadline_reached(cancellation)? {
        return deadline_before_evaluation_outcome(
            options,
            batch_budget,
            PolicySuppressionDocumentState::NotEvaluated,
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
    let (suppression_document, suppression_document_state) =
        match load_policy_suppressions_from_root(read_root, options.suppressions()) {
            Ok(Some(document)) => (Some(document), PolicySuppressionDocumentState::Loaded),
            Ok(None) => (None, PolicySuppressionDocumentState::NotFound),
            Err(error) => {
                secondary_diagnostics.push(report_diagnostic(
                    PolicyReportDiagnosticCode::SuppressionLoadFailed,
                    format!("failed to load policy suppressions: {error}"),
                    Some(PolicySourceIdentity::new(
                        options.suppressions().source().relative_path(),
                    )),
                    None,
                    Vec::new(),
                )?);
                (None, PolicySuppressionDocumentState::Invalid)
            }
        };
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
    if policy_deadline_reached(cancellation)? {
        return deadline_before_evaluation_outcome(
            options,
            batch_budget,
            suppression_document_state,
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
            suppression_document_state,
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
                suppression_document_state,
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
        let registration = registry
            .register_policy_bytes(prepared.source.clone(), prepared.bytes.as_bytes())
            .map(|policy| policy.definition().metadata.id.clone());
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
            suppression_document_state,
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
    let owned_analyzer = if runnable_ids.is_empty() || supplied_workspace.is_some() {
        None
    } else {
        let project = FilesystemProject::new(root).map_err(|error| {
            PolicyCoordinatorError::new(format!(
                "failed to construct analyzer project {}: {error}",
                root.display()
            ))
        })?;
        let project: Arc<dyn Project> = Arc::new(project);
        Some(WorkspaceAnalyzer::build(project, AnalyzerConfig::default()))
    };
    if policy_deadline_reached(cancellation)? {
        return deadline_before_evaluation_outcome(
            options,
            batch_budget,
            suppression_document_state,
            scope_document_state,
            vec![
                PolicyStageTiming::from_duration(
                    PolicyExecutionStage::PolicyRegistration,
                    registration_elapsed,
                ),
                PolicyStageTiming::from_duration(
                    PolicyExecutionStage::PolicyPreparation,
                    preparation_started.elapsed(),
                ),
            ],
            PolicyExecutionStage::PolicyPreparation,
            evaluation_policy_ids,
            None,
        );
    }

    let mut runs = HashMap::with_capacity(runnable_ids.len());
    let workspace = supplied_workspace.or(owned_analyzer.as_ref());
    let uncancelled = CancellationToken::default();
    let semantic_cancellation = cancellation.unwrap_or(&uncancelled);
    let active_semantic_models = match semantic_models {
        None => Ok(None),
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
                SemanticModelRuntimeOutcome::Ready { active, .. } => Ok(Some(active)),
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
    let taint = workspace.map_or_else(ProductionTaintPolicyEvaluator::default, |workspace| {
        ProductionTaintPolicyEvaluator::prepare(
            registry
                .policies()
                .filter(|policy| runnable_ids.contains(&policy.definition().metadata.id)),
            workspace,
            active_semantic_models,
            cancellation,
            batch_budget.per_policy(),
        )
    });
    let typestate = ProductionTypestatePolicyEvaluator::default();
    let evaluator = DefaultPolicyEvaluator::new()
        .with_taint(&taint)
        .with_typestate(&typestate);
    let preparation_elapsed = preparation_started.elapsed();
    if policy_deadline_reached(cancellation)? {
        return deadline_before_evaluation_outcome(
            options,
            batch_budget,
            suppression_document_state,
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
        let mut evaluation_budget = *batch_budget.per_policy();
        let context = PolicyEvaluationContext {
            analyzer: workspace.map(WorkspaceAnalyzer::analyzer).ok_or_else(|| {
                PolicyCoordinatorError::new(format!(
                    "runnable policy `{}` has no analyzer snapshot",
                    policy.definition().metadata.id
                ))
            })?,
            workspace,
            cancellation,
            cvss_overlays: &[],
            organizational_risk: &[],
        };
        let mut run = match evaluator.evaluate(policy, &context, &mut evaluation_budget) {
            Ok(run) => run,
            Err(error) => failed_evaluation_run(policy, error.to_string(), &evaluation_budget)?,
        };
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
        runs.insert(policy.definition().metadata.id.clone(), run);
    }
    let evaluation_elapsed = evaluation_started.elapsed();
    let report_started = Instant::now();
    if policy_deadline_reached(cancellation)? {
        deadline_stage.get_or_insert(PolicyExecutionStage::ReportConstruction);
    }

    let suppression_reviews = match suppression_document.as_ref() {
        Some(document) => {
            apply_policy_suppressions(document, options.evaluation_date(), &registry, &mut runs)?
        }
        None => Vec::new(),
    };
    let scope_reviews = match scope_document.as_ref() {
        Some(document) => apply_policy_scope(document, &mut runs)?,
        None => Vec::new(),
    };
    let evaluation = PolicyReportEvaluationContext::new(
        options.evaluation_date(),
        options.suppressions(),
        suppression_document_state,
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
                    options.suppressions().source().relative_path(),
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
    let threshold_exceeded = runs.values().flat_map(PolicyRun::findings).any(|finding| {
        finding.suppression().is_none()
            && finding.scope().is_none()
            && options.fail_on().matches(finding.severity())
    });
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

    retained_findings.sort_by_key(|finding| {
        (
            finding.suppression().is_none() && finding.scope().is_none(),
            finding.id(),
        )
    });
    let mut suppression_result_omitted = false;
    let mut scope_result_omitted = false;
    for finding in retained_findings {
        let policy_id = finding.policy_id().clone();
        let finding_id = finding.id();
        let suppressed = finding.suppression().is_some();
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
                options.suppressions().source().relative_path(),
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
    if let Some(terminal_stage) = deadline_stage {
        let stage_timings = vec![
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
        taint_findings,
        taint_analysis_results,
        exit_status,
        max_retained_report_bytes: batch_budget.max_retained_report_bytes(),
        max_serialized_report_bytes: batch_budget.max_serialized_report_bytes(),
    })
}

fn apply_policy_suppressions(
    document: &PolicySuppressionDocument,
    evaluation_date: PolicyEvaluationDate,
    registry: &PolicyRegistry,
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
        let review =
            PolicySuppressionReview::new(record, match_state, temporal_state, policy_hash_state);
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
            .manifest()
            .policies
            .iter()
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
        if selector.schema_resolution.origin != SchemaVersionOrigin::ImplicitCompatible {
            continue;
        }
        diagnostics.push(report_diagnostic(
            PolicyReportDiagnosticCode::ExplicitRqlSchemaVersionRequired,
            format!(
                "selector {} inferred RQL schema version {}; add :schema-version {}",
                selector.path,
                selector.schema_resolution.version,
                selector.schema_resolution.version
            ),
            Some(selector_source(policy, &selector.origin)),
            None,
            Vec::new(),
        )?);
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

fn report_exit_status(report: &PolicyReportDocument, threshold_exceeded: bool) -> u8 {
    let unreliable = report.execution().termination().is_some()
        || !report.diagnostics().is_empty()
        || report.diagnostics_truncated()
        || report
            .runs()
            .iter()
            .any(|run| !run.completion().is_reliable())
        || (!threshold_exceeded
            && report
                .runs()
                .iter()
                .any(|run| !run.completion().is_exhaustive()));
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

    use cap_std::ambient_authority;
    use cap_std::fs::Dir;
    use serde_json::json;

    use super::*;
    use crate::source::MAX_POLICY_SOURCE_IDENTITY_BYTES;
    use crate::write_policy_json;

    fn evaluation_options() -> PolicyEvaluationOptions {
        PolicyEvaluationOptions::new(
            PolicyEvaluationDate::from_ymd(2026, 7, 27).expect("fixed test date"),
        )
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

    fn write_test_suppression(root: &Path, policy_id: &str, policy_hash: &str, finding_id: &str) {
        let path = root.join(".bifrost/suppressions.json");
        fs::create_dir_all(path.parent().expect("suppression parent"))
            .expect("create suppression directory");
        fs::write(
            path,
            serde_json::to_vec(&json!({
                "schema_version": 1,
                "suppressions": [{
                    "policy_id": policy_id,
                    "finding_id": finding_id,
                    "identity_stability": "strong",
                    "status": "accepted",
                    "reason": "Reviewed exact finding",
                    "policy_hash_at_acceptance": policy_hash,
                    "accepted_at": "2026-07-01",
                    "expires_at": null
                }]
            }))
            .expect("suppression JSON"),
        )
        .expect("write suppression document");
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
        let analyzer = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
        let live_source = match_policy("test.unsaved", "Unsaved source");

        let outcome = evaluate_policy_source(
            workspace.path(),
            PolicySourceIdentity::new("policies/live.rqlp"),
            &live_source,
            &analyzer,
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
    fn live_endpoint_root_is_a_canonical_non_executable_diagnostic() {
        let workspace = tempfile::tempdir().expect("workspace");
        fs::write(workspace.path().join("app.ts"), "export const value = 1;\n")
            .expect("source fixture");
        let project = FilesystemProject::new(workspace.path().to_path_buf()).expect("project");
        let project: Arc<dyn Project> = Arc::new(project);
        let analyzer = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
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
        let analyzer = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        cancellation.cancel();

        let result = evaluate_policy_source(
            workspace.path(),
            PolicySourceIdentity::new("policies/live.rqlp"),
            &match_policy("test.cancelled", "Cancelled"),
            &analyzer,
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
        let analyzer = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
        let cancellation = CancellationToken::timeout_after_checks_for_test(9);

        let outcome = evaluate_policy_source(
            workspace.path(),
            PolicySourceIdentity::new("policies/live.rqlp"),
            &match_policy("test.timed-out", "Timed out"),
            &analyzer,
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
        let analyzer = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
        let cancellation = CancellationToken::default().with_timeout(std::time::Duration::ZERO);

        let outcome = evaluate_policy_source(
            workspace.path(),
            PolicySourceIdentity::new("policies/live.rqlp"),
            &match_policy("test.registration-timeout", "Registration timeout"),
            &analyzer,
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
            PolicySuppressionDocumentState::NotEvaluated,
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

    #[test]
    fn issue_1306_deadline_racing_client_cancellation_keeps_the_canonical_report() {
        let workspace = tempfile::tempdir().expect("workspace");
        fs::write(workspace.path().join("app.ts"), "export const value = 1;\n")
            .expect("source fixture");
        let project = FilesystemProject::new(workspace.path().to_path_buf()).expect("project");
        let project: Arc<dyn Project> = Arc::new(project);
        let analyzer = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
        let cancellation = CancellationToken::default().with_timeout(std::time::Duration::ZERO);
        cancellation.cancel();

        let outcome = evaluate_policy_source(
            workspace.path(),
            PolicySourceIdentity::new("policies/live.rqlp"),
            &match_policy("test.deadline-race", "Deadline race"),
            &analyzer,
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
}
