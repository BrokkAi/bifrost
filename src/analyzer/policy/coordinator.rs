//! One-shot, collect-and-continue policy batch coordination.
//!
//! This module owns the boundary between capability-confined policy loading,
//! analyzer-backed evaluation, canonical report assembly, and CLI status
//! selection. Renderers consume only the returned [`PolicyReportDocument`].

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::CancellationToken;
use crate::analyzer::{AnalyzerConfig, FilesystemProject, IAnalyzer, Project, WorkspaceAnalyzer};
use crate::schema_version::SchemaVersionOrigin;
use crate::workspace_document::WorkspaceRoot;

use super::catalog::{CatalogRegistryLimits, TaintCatalogRegistry};
use super::definition::{FindingSeverity, PolicyId, RqlpDocument};
use super::evaluator::{DefaultPolicyEvaluator, PolicyEvaluationContext, PolicyEvaluator};
use super::finding::{
    PolicyDiagnostic, PolicyDiagnosticCode, PolicyDiagnosticImpact, PolicyDiagnosticSeverity,
    PolicyFailureReason, PolicyRun, PolicyRunCompletion, PolicyWorkReport,
};
use super::loading::{PolicyDocumentLoadError, read_rqlp_document};
use super::registry::{PolicyRegistry, PolicyRegistryError, PolicyRegistryLimits};
use super::report::{
    PolicyReportBuilder, PolicyReportDiagnostic, PolicyReportDiagnosticCode, PolicyReportDocument,
    PolicyRuleDescriptor, PolicySourceRange,
};
use super::resolved::{
    EndpointDefinitionSchemaResolution, EndpointOrigin, LoadedPolicy, ResolvedEndpointIdentity,
    SelectorOrigin,
};
use super::source::{
    PolicySourceDiagnostic, PolicySourceIdentity, PolicySourceIdentityError,
    PolicySourceRelatedDiagnostic, parse_rqlp_source, validate_policy_source_identity,
};
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

/// Complete canonical report plus the already precedence-resolved CLI status.
pub struct PolicyBatchOutcome {
    report: PolicyReportDocument,
    exit_status: u8,
    max_serialized_report_bytes: usize,
}

impl PolicyBatchOutcome {
    pub const fn report(&self) -> &PolicyReportDocument {
        &self.report
    }

    pub fn into_report(self) -> PolicyReportDocument {
        self.report
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
    require_explicit_schema_versions: bool,
    fail_on: PolicyFailOn,
) -> Result<PolicyBatchOutcome, PolicyCoordinatorError> {
    evaluate_policy_files_with_limits(
        root.as_ref(),
        policy_files,
        require_explicit_schema_versions,
        fail_on,
        PolicyBatchBudget::default(),
        PolicyRegistryLimits::default(),
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
    analyzer: &dyn IAnalyzer,
    cancellation: Option<&CancellationToken>,
) -> Result<PolicyBatchOutcome, PolicyCoordinatorError> {
    let (root, _) = open_policy_workspace_root(root.as_ref())?;

    let input = prepare_source_input(source_identity, source)?;
    evaluate_policy_inputs(
        &root,
        vec![input],
        false,
        PolicyFailOn::Never,
        PolicyBatchBudget::default(),
        PolicyRegistryLimits::default(),
        Some(analyzer),
        cancellation,
    )
}

fn evaluate_policy_files_with_limits(
    root: &Path,
    policy_files: &[PathBuf],
    require_explicit_schema_versions: bool,
    fail_on: PolicyFailOn,
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

    evaluate_policy_inputs(
        &root,
        inputs,
        require_explicit_schema_versions,
        fail_on,
        batch_budget,
        registry_limits,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn evaluate_policy_inputs(
    root: &Path,
    mut inputs: Vec<InputOutcome>,
    require_explicit_schema_versions: bool,
    fail_on: PolicyFailOn,
    batch_budget: PolicyBatchBudget,
    registry_limits: PolicyRegistryLimits,
    supplied_analyzer: Option<&dyn IAnalyzer>,
    cancellation: Option<&CancellationToken>,
) -> Result<PolicyBatchOutcome, PolicyCoordinatorError> {
    check_policy_cancellation(cancellation)?;
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
    check_policy_cancellation(cancellation)?;
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
        check_policy_cancellation(cancellation)?;
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

    let mut secondary_diagnostics = Vec::new();
    if require_explicit_schema_versions {
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

    let owned_analyzer = if runnable_ids.is_empty() || supplied_analyzer.is_some() {
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
    check_policy_cancellation(cancellation)?;

    let evaluator = DefaultPolicyEvaluator::new();
    let mut runs = HashMap::with_capacity(runnable_ids.len());
    let analyzer =
        supplied_analyzer.or_else(|| owned_analyzer.as_ref().map(WorkspaceAnalyzer::analyzer));
    for policy in registry
        .policies()
        .filter(|policy| runnable_ids.contains(&policy.definition().metadata.id))
    {
        check_policy_cancellation(cancellation)?;
        let mut evaluation_budget = *batch_budget.per_policy();
        let context = PolicyEvaluationContext {
            analyzer: analyzer.ok_or_else(|| {
                PolicyCoordinatorError::new(format!(
                    "runnable policy `{}` has no analyzer snapshot",
                    policy.definition().metadata.id
                ))
            })?,
            cancellation,
            cvss_overlays: &[],
            organizational_risk: &[],
        };
        let run = match evaluator.evaluate(policy, &context, &mut evaluation_budget) {
            Ok(run) => run,
            Err(error) => failed_evaluation_run(policy, error.to_string(), &evaluation_budget)?,
        };
        runs.insert(policy.definition().metadata.id.clone(), run);
    }

    let mut builder = PolicyReportBuilder::new(batch_budget, inputs.len()).map_err(|error| {
        PolicyCoordinatorError::new(format!("policy report preflight failed: {error}"))
    })?;
    let mut retained_findings = Vec::new();
    for input in inputs {
        check_policy_cancellation(cancellation)?;
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

    retained_findings.sort_by_key(|finding| finding.id());
    for finding in retained_findings {
        builder.retain_finding(finding).map_err(|error| {
            PolicyCoordinatorError::new(format!("failed to retain a policy finding: {error}"))
        })?;
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

    let report = builder.finish().map_err(|error| {
        PolicyCoordinatorError::new(format!("failed to finish policy report: {error}"))
    })?;
    let exit_status = report_exit_status(&report, fail_on);
    Ok(PolicyBatchOutcome {
        report,
        exit_status,
        max_serialized_report_bytes: batch_budget.max_serialized_report_bytes(),
    })
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
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return Err(PolicyCoordinatorError::new("policy evaluation cancelled"));
    }
    Ok(())
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

fn report_exit_status(report: &PolicyReportDocument, fail_on: PolicyFailOn) -> u8 {
    let unreliable = !report.diagnostics().is_empty()
        || report.diagnostics_truncated()
        || report
            .runs()
            .iter()
            .any(|run| !run.completion().is_complete());
    if unreliable {
        return POLICY_EXIT_UNRELIABLE;
    }
    if report
        .runs()
        .iter()
        .flat_map(PolicyRun::findings)
        .any(|finding| fail_on.matches(finding.severity()))
    {
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

    use super::*;
    use crate::analyzer::policy::source::MAX_POLICY_SOURCE_IDENTITY_BYTES;
    use crate::policy::write_policy_json;

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
        (rql :schema-version 2
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
            analyzer.analyzer(),
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
            analyzer.analyzer(),
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
            analyzer.analyzer(),
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

        let forward = evaluate_policy_files(workspace.path(), &paths, false, PolicyFailOn::Never)
            .expect("forward duplicate report");
        paths.reverse();
        let reversed = evaluate_policy_files(workspace.path(), &paths, false, PolicyFailOn::Never)
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

        let forward = evaluate_policy_files(workspace.path(), &paths, false, PolicyFailOn::Never)
            .expect("oversized duplicate report");
        paths.reverse();
        let reversed = evaluate_policy_files(workspace.path(), &paths, false, PolicyFailOn::Never)
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

        let forward = evaluate_policy_files(workspace.path(), &paths, false, PolicyFailOn::Never)
            .expect("invalid requested-source report");
        paths.reverse();
        let reversed = evaluate_policy_files(workspace.path(), &paths, false, PolicyFailOn::Never)
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
                false,
                PolicyFailOn::Never,
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
            false,
            PolicyFailOn::Never,
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
}
