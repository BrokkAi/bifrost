use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};

use crate::DependencyPackActivationOutcome;
use crate::analyzer::semantic_model::{
    SemanticModelActivationReport, SemanticModelRuntimeLifecycle, SemanticModelRuntimeOutcome,
};
use crate::analyzer::{
    SemanticDiagnosticIncompleteReason, SemanticDiagnosticOutcome, SemanticDiagnosticReport,
    SemanticDiagnosticReportStatus,
};
use crate::semantic_packs::release_bundle::ReleaseBundleMeasurements;

pub const SEMANTIC_DIAGNOSTIC_ROLLOUT_SCHEMA_VERSION: u32 = 1;

const PROOF_CLASSES: [&str; 4] = ["resolved", "ambiguous", "absent", "incomplete"];
const SUPPRESSION_CLASSES: [&str; 9] = [
    "missing_dependency_discovery",
    "stale_generation",
    "cancelled",
    "truncated",
    "unsupported_semantics",
    "dynamic_behavior",
    "runtime_unavailable",
    "corrupt_semantic_pack",
    "unsupported_generated_surface",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticDiagnosticRolloutArtifact {
    pub schema_version: u32,
    pub generated_at: String,
    pub identity: SemanticDiagnosticRolloutIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_bundle: Option<ReleaseBundleMeasurements>,
    pub activation_samples: Vec<SemanticDiagnosticActivationSample>,
    pub diagnostic_samples: Vec<SemanticDiagnosticSample>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticDiagnosticRolloutIdentity {
    pub bifrost_revision: String,
    pub bifrost_dirty: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bifrost_tree_sha256: Option<String>,
    pub fixture: PinnedRolloutInput,
    pub configuration: HashedRolloutConfiguration,
    pub active_packs: Vec<ActivePackIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedRolloutInput {
    pub id: String,
    pub revision: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HashedRolloutConfiguration {
    pub id: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivePackIdentity {
    pub pack_id: String,
    pub pack_version: String,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticDiagnosticCacheState {
    Cold,
    Warm,
}

impl SemanticDiagnosticCacheState {
    const fn label(self) -> &'static str {
        match self {
            Self::Cold => "cold",
            Self::Warm => "warm",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticDiagnosticActivationResult {
    NotStarted,
    Ready,
    Incomplete,
    Cancelled,
    Unavailable,
}

impl SemanticDiagnosticActivationResult {
    const fn label(self) -> &'static str {
        match self {
            Self::NotStarted => "not_started",
            Self::Ready => "ready",
            Self::Incomplete => "incomplete",
            Self::Cancelled => "cancelled",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticDiagnosticActivationSample {
    pub id: String,
    pub cache_state: SemanticDiagnosticCacheState,
    pub host_elapsed_nanos: u64,
    pub complete: bool,
    pub result: SemanticDiagnosticActivationResult,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<SemanticModelRuntimeLifecycle>,
    pub diagnostic_refresh_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_model_set_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<SemanticModelActivationReport>,
}

impl SemanticDiagnosticActivationSample {
    pub fn from_dependency_pack_outcome(
        id: impl Into<String>,
        cache_state: SemanticDiagnosticCacheState,
        host_elapsed_nanos: u64,
        outcome: &DependencyPackActivationOutcome,
    ) -> Self {
        let (result, lifecycle, active_model_set_sha256, report) = match outcome.runtime.as_ref() {
            Some(SemanticModelRuntimeOutcome::Ready { active, lifecycle }) => (
                SemanticDiagnosticActivationResult::Ready,
                Some(*lifecycle),
                Some(active.active_model_set_hash().to_owned()),
                Some(active.activation_report().clone()),
            ),
            Some(SemanticModelRuntimeOutcome::Incomplete { usable, report }) => (
                SemanticDiagnosticActivationResult::Incomplete,
                None,
                usable
                    .as_ref()
                    .map(|active| active.active_model_set_hash().to_owned()),
                Some(report.clone()),
            ),
            Some(SemanticModelRuntimeOutcome::Cancelled(report)) => (
                SemanticDiagnosticActivationResult::Cancelled,
                None,
                None,
                Some(report.clone()),
            ),
            Some(SemanticModelRuntimeOutcome::Unavailable(report)) => (
                SemanticDiagnosticActivationResult::Unavailable,
                None,
                None,
                Some(report.clone()),
            ),
            None => (
                SemanticDiagnosticActivationResult::NotStarted,
                None,
                None,
                None,
            ),
        };

        Self {
            id: id.into(),
            cache_state,
            host_elapsed_nanos,
            complete: outcome.complete(),
            result,
            lifecycle,
            diagnostic_refresh_required: outcome.diagnostic_refresh_required,
            active_model_set_sha256,
            report,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticDiagnosticPhase {
    ColdDiagnostic,
    WarmDiagnostic,
    RefreshDiagnostic,
}

impl SemanticDiagnosticPhase {
    const fn label(self) -> &'static str {
        match self {
            Self::ColdDiagnostic => "cold_diagnostic",
            Self::WarmDiagnostic => "warm_diagnostic",
            Self::RefreshDiagnostic => "refresh_diagnostic",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticDiagnosticSample {
    pub activation_sample_id: String,
    pub phase: SemanticDiagnosticPhase,
    pub cache_state: SemanticDiagnosticCacheState,
    pub file_id: String,
    pub elapsed_nanos: u64,
    /// Delta from `SemanticPackCatalog::sql_statement_count` around the request.
    pub catalog_sql_statements: u64,
    pub report: SemanticDiagnosticReportCounts,
}

impl SemanticDiagnosticSample {
    pub fn from_report(
        activation_sample_id: impl Into<String>,
        phase: SemanticDiagnosticPhase,
        cache_state: SemanticDiagnosticCacheState,
        file_id: impl Into<String>,
        elapsed_nanos: u64,
        catalog_sql_statements: u64,
        report: &SemanticDiagnosticReport,
    ) -> Self {
        Self {
            activation_sample_id: activation_sample_id.into(),
            phase,
            cache_state,
            file_id: file_id.into(),
            elapsed_nanos,
            catalog_sql_statements,
            report: SemanticDiagnosticReportCounts::from_report(report),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticDiagnosticReportCounts {
    pub status: SemanticDiagnosticReportStatus,
    pub emitted_errors: u64,
    pub proof_classes: BTreeMap<String, u64>,
    pub suppression_classes: BTreeMap<String, u64>,
}

impl SemanticDiagnosticReportCounts {
    pub fn from_report(report: &SemanticDiagnosticReport) -> Self {
        let mut proof_classes = BTreeMap::new();
        let mut suppression_classes = BTreeMap::new();
        for outcome in report.outcomes() {
            let proof_class = match outcome {
                SemanticDiagnosticOutcome::Resolved { .. } => "resolved",
                SemanticDiagnosticOutcome::Ambiguous { .. } => "ambiguous",
                SemanticDiagnosticOutcome::Absent(_) => "absent",
                SemanticDiagnosticOutcome::Incomplete { reasons, .. } => {
                    for reason in reasons {
                        increment(&mut suppression_classes, suppression_class(reason));
                    }
                    "incomplete"
                }
            };
            increment(&mut proof_classes, proof_class);
        }
        Self {
            status: report.status(),
            emitted_errors: report.diagnostics().len().try_into().unwrap_or(u64::MAX),
            proof_classes,
            suppression_classes,
        }
    }
}

fn suppression_class(reason: &SemanticDiagnosticIncompleteReason) -> &'static str {
    match reason {
        SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery { .. } => {
            "missing_dependency_discovery"
        }
        SemanticDiagnosticIncompleteReason::StaleGeneration { .. } => "stale_generation",
        SemanticDiagnosticIncompleteReason::Cancelled => "cancelled",
        SemanticDiagnosticIncompleteReason::Truncated => "truncated",
        SemanticDiagnosticIncompleteReason::UnsupportedSemantics { .. } => "unsupported_semantics",
        SemanticDiagnosticIncompleteReason::DynamicBehavior { .. } => "dynamic_behavior",
        SemanticDiagnosticIncompleteReason::RuntimeUnavailable { .. } => "runtime_unavailable",
        SemanticDiagnosticIncompleteReason::CorruptSemanticPack { .. } => "corrupt_semantic_pack",
        SemanticDiagnosticIncompleteReason::UnsupportedGeneratedSurface { .. } => {
            "unsupported_generated_surface"
        }
    }
}

fn increment(counts: &mut BTreeMap<String, u64>, key: &str) {
    let count = counts.entry(key.to_owned()).or_default();
    *count = count.saturating_add(1);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticDiagnosticRolloutStatus {
    Complete,
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticDiagnosticRolloutAggregate {
    pub schema_version: u32,
    pub identity: SemanticDiagnosticRolloutIdentity,
    pub status: SemanticDiagnosticRolloutStatus,
    pub activation: Vec<SemanticDiagnosticActivationAggregate>,
    pub diagnostics: Vec<SemanticDiagnosticPhaseAggregate>,
    pub proof_classes: BTreeMap<String, u64>,
    pub suppression_classes: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticDiagnosticActivationAggregate {
    pub cache_state: SemanticDiagnosticCacheState,
    pub samples: u64,
    pub result_classes: BTreeMap<String, u64>,
    pub lifecycle_classes: BTreeMap<String, u64>,
    pub host_elapsed: NanosecondPercentiles,
    pub selection: NanosecondPercentiles,
    pub decode_hydration: NanosecondPercentiles,
    pub matcher_construction: NanosecondPercentiles,
    pub maximum_catalog_sql_statements: u64,
    pub maximum_catalog_candidates: u64,
    pub maximum_retained_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticDiagnosticPhaseAggregate {
    pub phase: SemanticDiagnosticPhase,
    pub cache_state: SemanticDiagnosticCacheState,
    pub samples: u64,
    pub latency: NanosecondPercentiles,
    pub complete_reports: u64,
    pub incomplete_reports: u64,
    pub emitted_errors: u64,
    pub catalog_sql_statements: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NanosecondPercentiles {
    pub p50: Option<u64>,
    pub p95: Option<u64>,
}

impl NanosecondPercentiles {
    fn from_values(values: &[u64]) -> Self {
        Self {
            p50: nearest_rank(values, 50),
            p95: nearest_rank(values, 95),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticDiagnosticRolloutError {
    messages: Vec<String>,
}

impl SemanticDiagnosticRolloutError {
    pub fn messages(&self) -> &[String] {
        &self.messages
    }
}

impl Display for SemanticDiagnosticRolloutError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.messages.join("; "))
    }
}

impl std::error::Error for SemanticDiagnosticRolloutError {}

pub fn aggregate_semantic_diagnostic_rollout(
    artifacts: &[SemanticDiagnosticRolloutArtifact],
) -> Result<SemanticDiagnosticRolloutAggregate, SemanticDiagnosticRolloutError> {
    if artifacts.is_empty() {
        return Err(validation_error(
            "at least one rollout artifact is required",
        ));
    }
    for artifact in artifacts {
        validate_artifact(artifact)?;
    }
    let identity = artifacts[0].identity.clone();
    if artifacts
        .iter()
        .skip(1)
        .any(|artifact| artifact.identity != identity)
    {
        return Err(validation_error(
            "all rollout artifacts must have the same pinned identity",
        ));
    }

    let activation_samples = artifacts
        .iter()
        .flat_map(|artifact| artifact.activation_samples.iter())
        .collect::<Vec<_>>();
    let diagnostic_samples = artifacts
        .iter()
        .flat_map(|artifact| artifact.diagnostic_samples.iter())
        .collect::<Vec<_>>();

    let activation = [
        SemanticDiagnosticCacheState::Cold,
        SemanticDiagnosticCacheState::Warm,
    ]
    .into_iter()
    .filter_map(|cache_state| {
        let samples = activation_samples
            .iter()
            .copied()
            .filter(|sample| sample.cache_state == cache_state)
            .collect::<Vec<_>>();
        (!samples.is_empty()).then(|| aggregate_activation(cache_state, &samples))
    })
    .collect();

    let mut diagnostic_groups = BTreeMap::<
        (SemanticDiagnosticPhase, SemanticDiagnosticCacheState),
        Vec<&SemanticDiagnosticSample>,
    >::new();
    let mut proof_classes = BTreeMap::new();
    let mut suppression_classes = BTreeMap::new();
    for sample in &diagnostic_samples {
        diagnostic_groups
            .entry((sample.phase, sample.cache_state))
            .or_default()
            .push(sample);
        merge_counts(&mut proof_classes, &sample.report.proof_classes);
        merge_counts(&mut suppression_classes, &sample.report.suppression_classes);
    }
    let diagnostics = diagnostic_groups
        .into_iter()
        .map(|((phase, cache_state), samples)| aggregate_diagnostics(phase, cache_state, &samples))
        .collect::<Vec<_>>();

    let activation_complete = activation_samples.iter().all(|sample| {
        sample.complete && sample.result == SemanticDiagnosticActivationResult::Ready
    });
    let diagnostics_complete = diagnostic_samples.iter().all(|sample| {
        sample.report.status == SemanticDiagnosticReportStatus::Complete
            && sample.catalog_sql_statements == 0
    });
    let status = if activation_complete && diagnostics_complete {
        SemanticDiagnosticRolloutStatus::Complete
    } else {
        SemanticDiagnosticRolloutStatus::Incomplete
    };

    Ok(SemanticDiagnosticRolloutAggregate {
        schema_version: SEMANTIC_DIAGNOSTIC_ROLLOUT_SCHEMA_VERSION,
        identity,
        status,
        activation,
        diagnostics,
        proof_classes,
        suppression_classes,
    })
}

fn aggregate_activation(
    cache_state: SemanticDiagnosticCacheState,
    samples: &[&SemanticDiagnosticActivationSample],
) -> SemanticDiagnosticActivationAggregate {
    let mut result_classes = BTreeMap::new();
    let mut lifecycle_classes = BTreeMap::new();
    let host_elapsed = samples
        .iter()
        .map(|sample| sample.host_elapsed_nanos)
        .collect::<Vec<_>>();
    let reports = samples
        .iter()
        .filter_map(|sample| sample.report.as_ref())
        .collect::<Vec<_>>();
    for sample in samples {
        increment(&mut result_classes, sample.result.label());
        if let Some(lifecycle) = sample.lifecycle {
            increment(&mut lifecycle_classes, lifecycle_label(lifecycle));
        }
    }
    SemanticDiagnosticActivationAggregate {
        cache_state,
        samples: samples.len().try_into().unwrap_or(u64::MAX),
        result_classes,
        lifecycle_classes,
        host_elapsed: NanosecondPercentiles::from_values(&host_elapsed),
        selection: NanosecondPercentiles::from_values(
            &reports
                .iter()
                .map(|report| report.phase_measurements.selection_nanos)
                .collect::<Vec<_>>(),
        ),
        decode_hydration: NanosecondPercentiles::from_values(
            &reports
                .iter()
                .map(|report| report.phase_measurements.decode_hydration_nanos)
                .collect::<Vec<_>>(),
        ),
        matcher_construction: NanosecondPercentiles::from_values(
            &reports
                .iter()
                .map(|report| report.phase_measurements.matcher_construction_nanos)
                .collect::<Vec<_>>(),
        ),
        maximum_catalog_sql_statements: reports
            .iter()
            .map(|report| report.phase_measurements.catalog_sql_statements)
            .max()
            .unwrap_or_default(),
        maximum_catalog_candidates: reports
            .iter()
            .map(|report| report.catalog_candidates.try_into().unwrap_or(u64::MAX))
            .max()
            .unwrap_or_default(),
        maximum_retained_bytes: reports
            .iter()
            .map(|report| report.retained_bytes)
            .max()
            .unwrap_or_default(),
    }
}

fn aggregate_diagnostics(
    phase: SemanticDiagnosticPhase,
    cache_state: SemanticDiagnosticCacheState,
    samples: &[&SemanticDiagnosticSample],
) -> SemanticDiagnosticPhaseAggregate {
    SemanticDiagnosticPhaseAggregate {
        phase,
        cache_state,
        samples: samples.len().try_into().unwrap_or(u64::MAX),
        latency: NanosecondPercentiles::from_values(
            &samples
                .iter()
                .map(|sample| sample.elapsed_nanos)
                .collect::<Vec<_>>(),
        ),
        complete_reports: samples
            .iter()
            .filter(|sample| sample.report.status == SemanticDiagnosticReportStatus::Complete)
            .count()
            .try_into()
            .unwrap_or(u64::MAX),
        incomplete_reports: samples
            .iter()
            .filter(|sample| sample.report.status == SemanticDiagnosticReportStatus::Incomplete)
            .count()
            .try_into()
            .unwrap_or(u64::MAX),
        emitted_errors: samples
            .iter()
            .map(|sample| sample.report.emitted_errors)
            .fold(0_u64, u64::saturating_add),
        catalog_sql_statements: samples
            .iter()
            .map(|sample| sample.catalog_sql_statements)
            .fold(0_u64, u64::saturating_add),
    }
}

fn merge_counts(target: &mut BTreeMap<String, u64>, source: &BTreeMap<String, u64>) {
    for (key, value) in source {
        let count = target.entry(key.clone()).or_default();
        *count = count.saturating_add(*value);
    }
}

fn lifecycle_label(lifecycle: SemanticModelRuntimeLifecycle) -> &'static str {
    match lifecycle {
        SemanticModelRuntimeLifecycle::Cached => "cached",
        SemanticModelRuntimeLifecycle::Built => "built",
        SemanticModelRuntimeLifecycle::Uncached => "uncached",
    }
}

fn validate_artifact(
    artifact: &SemanticDiagnosticRolloutArtifact,
) -> Result<(), SemanticDiagnosticRolloutError> {
    let mut messages = Vec::new();
    if artifact.schema_version != SEMANTIC_DIAGNOSTIC_ROLLOUT_SCHEMA_VERSION {
        messages.push(format!(
            "unsupported rollout schema version {}",
            artifact.schema_version
        ));
    }
    require_text(
        &mut messages,
        "generated_at",
        artifact.generated_at.as_str(),
    );
    require_text(
        &mut messages,
        "bifrost_revision",
        artifact.identity.bifrost_revision.as_str(),
    );
    require_text(
        &mut messages,
        "fixture.id",
        artifact.identity.fixture.id.as_str(),
    );
    require_text(
        &mut messages,
        "fixture.revision",
        artifact.identity.fixture.revision.as_str(),
    );
    require_text(
        &mut messages,
        "configuration.id",
        artifact.identity.configuration.id.as_str(),
    );
    validate_sha256(
        &mut messages,
        "configuration.sha256",
        artifact.identity.configuration.sha256.as_str(),
    );
    if let Some(tree_sha256) = artifact.identity.bifrost_tree_sha256.as_deref() {
        validate_sha256(&mut messages, "bifrost_tree_sha256", tree_sha256);
    }

    let mut active_packs = BTreeSet::new();
    for pack in &artifact.identity.active_packs {
        require_text(&mut messages, "active_packs.pack_id", pack.pack_id.as_str());
        require_text(
            &mut messages,
            "active_packs.pack_version",
            pack.pack_version.as_str(),
        );
        validate_sha256(
            &mut messages,
            "active_packs.manifest_sha256",
            pack.manifest_sha256.as_str(),
        );
        if !active_packs.insert((pack.pack_id.as_str(), pack.pack_version.as_str())) {
            messages.push(format!(
                "duplicate active pack {}@{}",
                pack.pack_id, pack.pack_version
            ));
        }
    }

    if artifact.activation_samples.is_empty() {
        messages.push("at least one activation sample is required".to_owned());
    }
    if artifact.diagnostic_samples.is_empty() {
        messages.push("at least one diagnostic sample is required".to_owned());
    }
    let mut activations = BTreeMap::new();
    for sample in &artifact.activation_samples {
        require_text(&mut messages, "activation_samples.id", sample.id.as_str());
        if activations.insert(sample.id.as_str(), sample).is_some() {
            messages.push(format!("duplicate activation sample id `{}`", sample.id));
        }
        if sample.complete != (sample.result == SemanticDiagnosticActivationResult::Ready) {
            messages.push(format!(
                "activation sample `{}` has inconsistent complete and result values",
                sample.id
            ));
        }
        if sample.lifecycle.is_some()
            != (sample.result == SemanticDiagnosticActivationResult::Ready)
        {
            messages.push(format!(
                "activation sample `{}` has an invalid runtime lifecycle",
                sample.id
            ));
        }
        if let Some(hash) = sample.active_model_set_sha256.as_deref() {
            validate_sha256(&mut messages, "active_model_set_sha256", hash);
        }
    }

    for sample in &artifact.diagnostic_samples {
        require_text(
            &mut messages,
            "diagnostic_samples.file_id",
            sample.file_id.as_str(),
        );
        match sample.phase {
            SemanticDiagnosticPhase::ColdDiagnostic
                if sample.cache_state != SemanticDiagnosticCacheState::Cold =>
            {
                messages.push("cold diagnostic sample must use cold cache state".to_owned());
            }
            SemanticDiagnosticPhase::WarmDiagnostic
                if sample.cache_state != SemanticDiagnosticCacheState::Warm =>
            {
                messages.push("warm diagnostic sample must use warm cache state".to_owned());
            }
            _ => {}
        }
        match activations.get(sample.activation_sample_id.as_str()) {
            Some(activation) => {
                if sample.phase == SemanticDiagnosticPhase::RefreshDiagnostic
                    && !activation.diagnostic_refresh_required
                {
                    messages.push(format!(
                        "refresh diagnostic sample refers to activation `{}` without a refresh request",
                        sample.activation_sample_id
                    ));
                }
            }
            None => messages.push(format!(
                "diagnostic sample refers to unknown activation `{}`",
                sample.activation_sample_id
            )),
        }
        validate_report_counts(&mut messages, &sample.report);
    }

    if messages.is_empty() {
        Ok(())
    } else {
        Err(SemanticDiagnosticRolloutError { messages })
    }
}

fn validate_report_counts(messages: &mut Vec<String>, report: &SemanticDiagnosticReportCounts) {
    let known_proofs = PROOF_CLASSES.into_iter().collect::<BTreeSet<_>>();
    for key in report.proof_classes.keys() {
        if !known_proofs.contains(key.as_str()) {
            messages.push(format!("unknown diagnostic proof class `{key}`"));
        }
    }
    let known_suppressions = SUPPRESSION_CLASSES.into_iter().collect::<BTreeSet<_>>();
    for key in report.suppression_classes.keys() {
        if !known_suppressions.contains(key.as_str()) {
            messages.push(format!("unknown diagnostic suppression class `{key}`"));
        }
    }
    let absent = report
        .proof_classes
        .get("absent")
        .copied()
        .unwrap_or_default();
    let incomplete = report
        .proof_classes
        .get("incomplete")
        .copied()
        .unwrap_or_default();
    let suppressions = report
        .suppression_classes
        .values()
        .copied()
        .fold(0_u64, u64::saturating_add);
    if report.emitted_errors != absent {
        messages.push("emitted error count must equal complete absence count".to_owned());
    }
    match report.status {
        SemanticDiagnosticReportStatus::Complete if incomplete != 0 || suppressions != 0 => {
            messages.push(
                "a complete diagnostic report cannot contain incomplete outcomes or suppressions"
                    .to_owned(),
            );
        }
        SemanticDiagnosticReportStatus::Incomplete
            if incomplete == 0 || suppressions < incomplete =>
        {
            messages.push(
                "an incomplete diagnostic report must retain each suppression reason".to_owned(),
            );
        }
        _ => {}
    }
}

fn require_text(messages: &mut Vec<String>, field: &str, value: &str) {
    if value.trim().is_empty() {
        messages.push(format!("{field} must not be empty"));
    }
}

fn validate_sha256(messages: &mut Vec<String>, field: &str, value: &str) {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        messages.push(format!("{field} must be a lowercase SHA-256 value"));
    }
}

fn validation_error(message: impl Into<String>) -> SemanticDiagnosticRolloutError {
    SemanticDiagnosticRolloutError {
        messages: vec![message.into()],
    }
}

fn nearest_rank(values: &[u64], percentile: usize) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    assert!((1..=100).contains(&percentile));
    let mut values = values.to_vec();
    values.sort_unstable();
    let rank = values
        .len()
        .saturating_mul(percentile)
        .div_ceil(100)
        .saturating_sub(1);
    values.get(rank).copied()
}

pub fn render_semantic_diagnostic_rollout_markdown(
    aggregate: &SemanticDiagnosticRolloutAggregate,
) -> String {
    let mut output = String::new();
    output.push_str("# Semantic diagnostic rollout\n\n");
    output.push_str(&format!(
        "Status: `{}`\n\n",
        match aggregate.status {
            SemanticDiagnosticRolloutStatus::Complete => "complete",
            SemanticDiagnosticRolloutStatus::Incomplete => "incomplete",
        }
    ));
    output.push_str(&format!(
        "Bifrost revision: `{}`  \nFixture: `{}` at `{}`  \nConfiguration: `{}` with `{}`\n\n",
        aggregate.identity.bifrost_revision,
        aggregate.identity.fixture.id,
        aggregate.identity.fixture.revision,
        aggregate.identity.configuration.id,
        aggregate.identity.configuration.sha256,
    ));
    output.push_str("## Active packs\n\n");
    if aggregate.identity.active_packs.is_empty() {
        output.push_str("No semantic pack was active.\n\n");
    } else {
        output.push_str("| Pack | Version | Manifest SHA-256 |\n|---|---:|---|\n");
        for pack in &aggregate.identity.active_packs {
            output.push_str(&format!(
                "| `{}` | `{}` | `{}` |\n",
                pack.pack_id, pack.pack_version, pack.manifest_sha256
            ));
        }
        output.push('\n');
    }

    output.push_str("## Activation\n\n");
    output.push_str(
        "| Cache | Samples | Results | Lifecycle | Host p50 ms | Host p95 ms | Selection p95 ms | Decode p95 ms | Matcher p95 ms | Max SQL | Max candidates | Max retained bytes |\n|---|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|\n",
    );
    for activation in &aggregate.activation {
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            activation.cache_state.label(),
            activation.samples,
            format_counts_inline(&activation.result_classes),
            format_counts_inline(&activation.lifecycle_classes),
            format_millis(activation.host_elapsed.p50),
            format_millis(activation.host_elapsed.p95),
            format_millis(activation.selection.p95),
            format_millis(activation.decode_hydration.p95),
            format_millis(activation.matcher_construction.p95),
            activation.maximum_catalog_sql_statements,
            activation.maximum_catalog_candidates,
            activation.maximum_retained_bytes,
        ));
    }
    output.push('\n');

    output.push_str("## Diagnostics\n\n");
    output.push_str(
        "| Phase | Cache | Samples | p50 ms | p95 ms | Complete | Incomplete | Errors | SQL |\n|---|---|---:|---:|---:|---:|---:|---:|---:|\n",
    );
    for diagnostic in &aggregate.diagnostics {
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            diagnostic.phase.label(),
            diagnostic.cache_state.label(),
            diagnostic.samples,
            format_millis(diagnostic.latency.p50),
            format_millis(diagnostic.latency.p95),
            diagnostic.complete_reports,
            diagnostic.incomplete_reports,
            diagnostic.emitted_errors,
            diagnostic.catalog_sql_statements,
        ));
    }
    output.push('\n');
    render_counts(&mut output, "Proof classes", &aggregate.proof_classes);
    render_counts(
        &mut output,
        "Suppression classes",
        &aggregate.suppression_classes,
    );
    output
}

fn format_counts_inline(counts: &BTreeMap<String, u64>) -> String {
    if counts.is_empty() {
        return "-".to_owned();
    }
    counts
        .iter()
        .map(|(class, count)| format!("{class}={count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_counts(output: &mut String, title: &str, counts: &BTreeMap<String, u64>) {
    output.push_str(&format!("## {title}\n\n"));
    if counts.is_empty() {
        output.push_str("None.\n\n");
        return;
    }
    output.push_str("| Class | Count |\n|---|---:|\n");
    for (class, count) in counts {
        output.push_str(&format!("| `{class}` | {count} |\n"));
    }
    output.push('\n');
}

fn format_millis(nanos: Option<u64>) -> String {
    nanos.map_or_else(
        || "-".to_owned(),
        |nanos| format!("{:.3}", nanos as f64 / 1_000_000.0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Range;
    use crate::analyzer::semantic_model::{
        CatalogPackSourceKind, Completeness, SemanticModelActivationExplanation,
        SemanticModelActivationPhaseMeasurements, SemanticModelActivationStatus,
    };
    use crate::analyzer::structural::resolution::BoundaryStatus;
    use crate::analyzer::{SemanticAbsenceProof, SemanticDiagnostic, SemanticDiagnosticDomain};
    use crate::semantic_packs::release_bundle::{
        PinnedLookupQuery, ReleaseGenerator, ReleaseLookupMeasurement, ReleasePackMeasurement,
    };

    const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const SHA_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    #[test]
    fn artifact_round_trip_preserves_lifecycle_release_and_identity_metadata() {
        let artifact = complete_artifact();
        let encoded = serde_json::to_vec_pretty(&artifact).expect("artifact serializes");
        let decoded: SemanticDiagnosticRolloutArtifact =
            serde_json::from_slice(&encoded).expect("artifact deserializes");
        assert_eq!(decoded, artifact);

        let activation = &decoded.activation_samples[0];
        let report = activation.report.as_ref().expect("activation report");
        assert_eq!(report.catalog_candidates, 17);
        assert_eq!(report.retained_bytes, 29);
        assert_eq!(report.phase_measurements.catalog_sql_statements, 5);
        assert_eq!(
            activation.lifecycle,
            Some(SemanticModelRuntimeLifecycle::Built)
        );
        assert_eq!(decoded.identity.bifrost_revision, "0123456789abcdef");
        assert_eq!(decoded.identity.fixture.revision, "fixture-revision-1");
        assert_eq!(decoded.identity.configuration.sha256, SHA_A);
        assert_eq!(decoded.identity.active_packs[0].manifest_sha256, SHA_B);

        let release = decoded.release_bundle.expect("release measurements");
        assert_eq!(release.packs[0].activation_candidate_count, 17);
        assert_eq!(release.packs[0].retained_model_bytes, 29);
        assert_eq!(release.packs[0].activation_catalog_sql_statements, 5);
    }

    #[test]
    fn aggregate_keeps_cold_and_warm_phases_separate() {
        let mut first = complete_artifact();
        first.diagnostic_samples.push(SemanticDiagnosticSample {
            activation_sample_id: "activation-1".to_owned(),
            phase: SemanticDiagnosticPhase::WarmDiagnostic,
            cache_state: SemanticDiagnosticCacheState::Warm,
            file_id: "src/Main.java".to_owned(),
            elapsed_nanos: 2_000_000,
            catalog_sql_statements: 0,
            report: complete_report_counts(),
        });
        let mut second = first.clone();
        second.generated_at = "2026-08-06T07:31:00Z".to_owned();
        second.activation_samples[0].host_elapsed_nanos = 8_000_000;
        second.diagnostic_samples[0].elapsed_nanos = 6_000_000;
        second.diagnostic_samples[1].elapsed_nanos = 4_000_000;

        let aggregate = aggregate_semantic_diagnostic_rollout(&[first, second]).expect("aggregate");
        assert_eq!(aggregate.status, SemanticDiagnosticRolloutStatus::Complete);
        assert_eq!(aggregate.activation[0].host_elapsed.p50, Some(7_000_000));
        let cold = aggregate
            .diagnostics
            .iter()
            .find(|phase| phase.phase == SemanticDiagnosticPhase::ColdDiagnostic)
            .expect("cold diagnostics");
        let warm = aggregate
            .diagnostics
            .iter()
            .find(|phase| phase.phase == SemanticDiagnosticPhase::WarmDiagnostic)
            .expect("warm diagnostics");
        assert_eq!(cold.latency.p95, Some(6_000_000));
        assert_eq!(warm.latency.p95, Some(4_000_000));
    }

    #[test]
    fn incomplete_production_report_cannot_render_as_complete() {
        let mut report = SemanticDiagnosticReport::new();
        report.push_incomplete(None, vec![SemanticDiagnosticIncompleteReason::Cancelled]);
        let mut artifact = complete_artifact();
        artifact.diagnostic_samples[0] = SemanticDiagnosticSample::from_report(
            "activation-1",
            SemanticDiagnosticPhase::ColdDiagnostic,
            SemanticDiagnosticCacheState::Cold,
            "src/Main.java",
            1_000_000,
            0,
            &report,
        );

        let aggregate = aggregate_semantic_diagnostic_rollout(&[artifact]).expect("aggregate");
        assert_eq!(
            aggregate.status,
            SemanticDiagnosticRolloutStatus::Incomplete
        );
        assert_eq!(aggregate.proof_classes.get("incomplete"), Some(&1));
        assert_eq!(aggregate.suppression_classes.get("cancelled"), Some(&1));
        assert!(
            render_semantic_diagnostic_rollout_markdown(&aggregate)
                .contains("Status: `incomplete`")
        );
    }

    #[test]
    fn activation_adapter_keeps_a_cancelled_production_outcome_incomplete() {
        let report = activation_report();
        let outcome = DependencyPackActivationOutcome {
            ecosystems: Vec::new(),
            runtime: Some(SemanticModelRuntimeOutcome::Cancelled(report.clone())),
            diagnostic_refresh_required: false,
        };
        let sample = SemanticDiagnosticActivationSample::from_dependency_pack_outcome(
            "cancelled",
            SemanticDiagnosticCacheState::Cold,
            11,
            &outcome,
        );
        assert!(!sample.complete);
        assert_eq!(sample.result, SemanticDiagnosticActivationResult::Cancelled);
        assert_eq!(sample.lifecycle, None);
        assert_eq!(sample.report, Some(report));
        assert!(!sample.diagnostic_refresh_required);
    }

    #[test]
    fn report_adapter_counts_each_production_proof_class_and_suppression_class() {
        let range = Range {
            start_byte: 2,
            end_byte: 6,
            start_line: 1,
            end_line: 1,
        };
        let mut report = SemanticDiagnosticReport::new();
        report.push_resolved(range, BoundaryStatus::WorkspaceLocal);
        report.push_ambiguous(
            range,
            vec![
                BoundaryStatus::WorkspaceLocal,
                BoundaryStatus::ExternalIndexed,
            ],
        );
        report.push_absent(
            SemanticAbsenceProof {
                range,
                domain: SemanticDiagnosticDomain::Type {
                    name: "Missing".to_owned(),
                },
                boundary: BoundaryStatus::WorkspaceLocal,
            },
            SemanticDiagnostic {
                range,
                source: "test",
                kind: "unrecognized_symbol",
                message: "not stored in the rollout artifact".to_owned(),
            },
        );
        report.push_incomplete(
            None,
            vec![
                SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                    boundary: BoundaryStatus::ExternalUnknown,
                },
                SemanticDiagnosticIncompleteReason::StaleGeneration {
                    expected: 3,
                    actual: 2,
                },
                SemanticDiagnosticIncompleteReason::Cancelled,
                SemanticDiagnosticIncompleteReason::Truncated,
                SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                    detail: "generated".to_owned(),
                },
                SemanticDiagnosticIncompleteReason::DynamicBehavior {
                    detail: "dynamic".to_owned(),
                },
                SemanticDiagnosticIncompleteReason::RuntimeUnavailable {
                    detail: "offline".to_owned(),
                },
                SemanticDiagnosticIncompleteReason::CorruptSemanticPack {
                    detail: "digest".to_owned(),
                },
                SemanticDiagnosticIncompleteReason::UnsupportedGeneratedSurface {
                    detail: "owner".to_owned(),
                },
            ],
        );

        let counts = SemanticDiagnosticReportCounts::from_report(&report);
        assert_eq!(counts.emitted_errors, 1);
        for class in PROOF_CLASSES {
            assert_eq!(counts.proof_classes.get(class), Some(&1), "{class}");
        }
        for class in SUPPRESSION_CLASSES {
            assert_eq!(counts.suppression_classes.get(class), Some(&1), "{class}");
        }
        let encoded = serde_json::to_string(&counts).expect("counts serialize");
        assert!(!encoded.contains("not stored in the rollout artifact"));
        assert!(!encoded.contains("Missing"));
    }

    #[test]
    fn validation_rejects_revision_configuration_pack_cache_refresh_and_sql_drift() {
        let mut artifact = complete_artifact();
        artifact.identity.bifrost_revision.clear();
        artifact.identity.configuration.sha256 = "bad".to_owned();
        artifact.identity.active_packs[0].manifest_sha256 = "BAD".to_owned();
        artifact.diagnostic_samples[0].cache_state = SemanticDiagnosticCacheState::Warm;
        artifact.diagnostic_samples.push(SemanticDiagnosticSample {
            activation_sample_id: "activation-1".to_owned(),
            phase: SemanticDiagnosticPhase::RefreshDiagnostic,
            cache_state: SemanticDiagnosticCacheState::Warm,
            file_id: "src/Main.java".to_owned(),
            elapsed_nanos: 1,
            catalog_sql_statements: 1,
            report: complete_report_counts(),
        });

        let error = aggregate_semantic_diagnostic_rollout(&[artifact]).expect_err("invalid");
        let message = error.to_string();
        assert!(message.contains("bifrost_revision"));
        assert!(message.contains("configuration.sha256"));
        assert!(message.contains("active_packs.manifest_sha256"));
        assert!(message.contains("cold diagnostic sample"));
        assert!(message.contains("without a refresh request"));
    }

    #[test]
    fn diagnostic_sql_metadata_prevents_a_complete_rollout_result() {
        let mut artifact = complete_artifact();
        artifact.diagnostic_samples[0].catalog_sql_statements = 1;
        let aggregate = aggregate_semantic_diagnostic_rollout(&[artifact]).expect("aggregate");
        assert_eq!(
            aggregate.status,
            SemanticDiagnosticRolloutStatus::Incomplete
        );
        assert_eq!(aggregate.diagnostics[0].catalog_sql_statements, 1);
    }

    fn complete_artifact() -> SemanticDiagnosticRolloutArtifact {
        SemanticDiagnosticRolloutArtifact {
            schema_version: SEMANTIC_DIAGNOSTIC_ROLLOUT_SCHEMA_VERSION,
            generated_at: "2026-08-06T07:30:00Z".to_owned(),
            identity: SemanticDiagnosticRolloutIdentity {
                bifrost_revision: "0123456789abcdef".to_owned(),
                bifrost_dirty: false,
                bifrost_tree_sha256: Some(SHA_C.to_owned()),
                fixture: PinnedRolloutInput {
                    id: "fixture-java".to_owned(),
                    revision: "fixture-revision-1".to_owned(),
                },
                configuration: HashedRolloutConfiguration {
                    id: "java-opt-in".to_owned(),
                    sha256: SHA_A.to_owned(),
                },
                active_packs: vec![ActivePackIdentity {
                    pack_id: "jdk".to_owned(),
                    pack_version: "21".to_owned(),
                    manifest_sha256: SHA_B.to_owned(),
                }],
            },
            release_bundle: Some(release_measurements()),
            activation_samples: vec![SemanticDiagnosticActivationSample {
                id: "activation-1".to_owned(),
                cache_state: SemanticDiagnosticCacheState::Cold,
                host_elapsed_nanos: 7_000_000,
                complete: true,
                result: SemanticDiagnosticActivationResult::Ready,
                lifecycle: Some(SemanticModelRuntimeLifecycle::Built),
                diagnostic_refresh_required: false,
                active_model_set_sha256: Some(SHA_C.to_owned()),
                report: Some(activation_report()),
            }],
            diagnostic_samples: vec![SemanticDiagnosticSample {
                activation_sample_id: "activation-1".to_owned(),
                phase: SemanticDiagnosticPhase::ColdDiagnostic,
                cache_state: SemanticDiagnosticCacheState::Cold,
                file_id: "src/Main.java".to_owned(),
                elapsed_nanos: 5_000_000,
                catalog_sql_statements: 0,
                report: complete_report_counts(),
            }],
        }
    }

    fn activation_report() -> SemanticModelActivationReport {
        SemanticModelActivationReport {
            explanations: vec![SemanticModelActivationExplanation {
                manifest_digest: SHA_B.to_owned(),
                pack_id: Some("jdk".to_owned()),
                shard_id: "jdk-types".to_owned(),
                source_kind: CatalogPackSourceKind::PreShipped,
                source_id: "release:jdk@21".to_owned(),
                status: SemanticModelActivationStatus::Active,
                reason: "exact artifact match".to_owned(),
            }],
            catalog_candidates: 17,
            loaded_shards: 2,
            loaded_records: 19,
            index_entries: 23,
            working_bytes: 27,
            retained_bytes: 29,
            phase_measurements: SemanticModelActivationPhaseMeasurements {
                selection_nanos: 1_000_000,
                decode_hydration_nanos: 2_000_000,
                matcher_construction_nanos: 3_000_000,
                catalog_sql_statements: 5,
            },
            ..Default::default()
        }
    }

    fn complete_report_counts() -> SemanticDiagnosticReportCounts {
        SemanticDiagnosticReportCounts {
            status: SemanticDiagnosticReportStatus::Complete,
            emitted_errors: 0,
            proof_classes: BTreeMap::from([("resolved".to_owned(), 1)]),
            suppression_classes: BTreeMap::new(),
        }
    }

    fn release_measurements() -> ReleaseBundleMeasurements {
        ReleaseBundleMeasurements {
            schema_version: 1,
            generator: ReleaseGenerator {
                name: "test".to_owned(),
                version: "1".to_owned(),
            },
            packs: vec![ReleasePackMeasurement {
                pack_id: "jdk".to_owned(),
                pack_version: "21".to_owned(),
                generation_millis: 31,
                artifact_bytes: 37,
                manifest_bytes: 41,
                stored_shard_bytes: 43,
                raw_shard_bytes: 47,
                shard_count: 2,
                record_count: 19,
                completeness: Completeness::Complete,
                activation_micros: 7_000,
                activation_selection_nanos: 1_000_000,
                cold_decode_hydration_nanos: 2_000_000,
                matcher_construction_nanos: 3_000_000,
                activation_catalog_sql_statements: 5,
                activation_candidate_count: 17,
                matcher_index_entries: 23,
                retained_model_bytes: 29,
                lookups: vec![ReleaseLookupMeasurement {
                    query: PinnedLookupQuery::Type {
                        name: "java.lang.String".to_owned(),
                    },
                    cold_nanos: 53,
                    warm_nanos: 59,
                    records: 1,
                }],
                diagnostics: Vec::new(),
                suppressed_diagnostics: 0,
            }],
        }
    }
}
