//! Retained production taint results.
//!
//! A solved taint batch produces an immutable plan/report pair. Both the policy
//! authoring layer (brokk-bifrost-policy) and standalone CodeQuery projection
//! consume that pair, so it lives here with the taint engine that produces it
//! rather than in either consumer.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;

use crate::analyzer::WorkspaceAnalyzer;
use crate::analyzer::semantic::{
    LengthDelimitedDigest, ProcedureHandle, SemanticArtifact, SemanticArtifactKey,
};
use crate::analyzer::taint::{
    TaintAnalysisPlan, TaintBatchCompatibilityKey, TaintFindingReport, TaintModelError,
};

/// Observed production phase costs for one retained compatible taint batch.
///
/// These measurements describe the work that produced the immutable retained
/// plan/report pair. They are diagnostic observations only: no policy decision,
/// completeness result, or cache behavior depends on them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ProductionTaintPhaseMetrics {
    plan_discovery_and_summary_binding_ns: u64,
    batch_planning_ns: u64,
    propagation_ns: u64,
    finding_and_witness_reconstruction_ns: u64,
    standalone_projection_ns: u64,
    policy_projection_ns: u64,
    compatible_policy_count: usize,
    propagation_solves: usize,
}

impl ProductionTaintPhaseMetrics {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        plan_discovery_and_summary_binding: Duration,
        batch_planning: Duration,
        propagation: Duration,
        finding_and_witness_reconstruction: Duration,
        standalone_projection: Duration,
        policy_projection: Duration,
        compatible_policy_count: usize,
        propagation_solves: usize,
    ) -> Self {
        Self {
            plan_discovery_and_summary_binding_ns: duration_ns(plan_discovery_and_summary_binding),
            batch_planning_ns: duration_ns(batch_planning),
            propagation_ns: duration_ns(propagation),
            finding_and_witness_reconstruction_ns: duration_ns(finding_and_witness_reconstruction),
            standalone_projection_ns: duration_ns(standalone_projection),
            policy_projection_ns: duration_ns(policy_projection),
            compatible_policy_count,
            propagation_solves,
        }
    }

    pub const fn plan_discovery_and_summary_binding_ns(&self) -> u64 {
        self.plan_discovery_and_summary_binding_ns
    }

    pub const fn batch_planning_ns(&self) -> u64 {
        self.batch_planning_ns
    }

    pub const fn propagation_ns(&self) -> u64 {
        self.propagation_ns
    }

    pub const fn finding_and_witness_reconstruction_ns(&self) -> u64 {
        self.finding_and_witness_reconstruction_ns
    }

    pub const fn standalone_projection_ns(&self) -> u64 {
        self.standalone_projection_ns
    }

    pub const fn policy_projection_ns(&self) -> u64 {
        self.policy_projection_ns
    }

    pub const fn compatible_policy_count(&self) -> usize {
        self.compatible_policy_count
    }

    pub const fn propagation_solves(&self) -> usize {
        self.propagation_solves
    }
}

fn duration_ns(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

/// One immutable production-compiled taint plan and the retained report from
/// its single compatible-batch solve.
///
/// Policy projection and standalone CodeQuery projection both consume this
/// exact plan/report pair. Constructing another plan or invoking propagation is
/// deliberately outside this type's API.
#[derive(Debug)]
pub struct ProductionTaintAnalysisResult {
    plan: Arc<TaintAnalysisPlan>,
    report: Arc<TaintFindingReport>,
    compatibility: TaintBatchCompatibilityKey,
    projection_scope: Box<str>,
    projection_limits: crate::analyzer::structural::CodeQueryTaintProjectionLimits,
    artifact_keys: Box<[SemanticArtifactKey]>,
    retained_artifact_bytes: usize,
    registration_digest: Box<str>,
    phase_metrics: ProductionTaintPhaseMetrics,
}

impl ProductionTaintAnalysisResult {
    pub fn new(
        plan: Arc<TaintAnalysisPlan>,
        report: Arc<TaintFindingReport>,
        compatibility: TaintBatchCompatibilityKey,
        projection_limits: crate::analyzer::structural::CodeQueryTaintProjectionLimits,
    ) -> Self {
        assert!(
            report.belongs_to(&plan),
            "retained taint plan/report mismatch"
        );
        let mut artifact_keys = HashSet::new();
        let mut artifact_allocations =
            HashSet::<*const SemanticArtifact>::new();
        let mut retained_artifact_bytes = 0u64;
        plan.for_each_retained_artifact(|artifact| {
            artifact_keys.insert(artifact.key().clone());
            if artifact_allocations.insert(Arc::as_ptr(artifact)) {
                retained_artifact_bytes = retained_artifact_bytes.saturating_add(
                    crate::analyzer::semantic::service::semantic_artifact_retained_bytes(artifact),
                );
            }
        });
        plan.for_each_retained_artifact_key(|key| {
            artifact_keys.insert(key.clone());
        });
        let mut artifact_keys = artifact_keys.into_iter().collect::<Vec<_>>();
        artifact_keys.sort_unstable();
        let projection_scope = compatibility
            .propagation_semantics()
            .to_owned()
            .into_boxed_str();
        Self {
            plan,
            report,
            compatibility,
            projection_scope,
            projection_limits,
            artifact_keys: artifact_keys.into_boxed_slice(),
            retained_artifact_bytes: usize::try_from(retained_artifact_bytes).unwrap_or(usize::MAX),
            registration_digest: "".into(),
            phase_metrics: ProductionTaintPhaseMetrics::default(),
        }
    }

    pub fn plan(&self) -> &Arc<TaintAnalysisPlan> {
        &self.plan
    }

    pub fn report(&self) -> &Arc<TaintFindingReport> {
        &self.report
    }

    pub const fn compatibility(&self) -> &TaintBatchCompatibilityKey {
        &self.compatibility
    }

    pub const fn projection_scope(&self) -> &str {
        &self.projection_scope
    }

    pub const fn projection_limits(
        &self,
    ) -> crate::analyzer::structural::CodeQueryTaintProjectionLimits {
        self.projection_limits
    }

    pub fn expected_root(&self) -> &ProcedureHandle {
        self.plan.value_flow().root()
    }

    pub fn plan_report_match(&self) -> bool {
        self.report.belongs_to(&self.plan)
    }

    pub fn retained_plan_bytes(&self) -> usize {
        self.plan.retained_bytes()
    }

    pub fn retained_report_bytes(&self) -> usize {
        self.report.retained_bytes()
    }

    pub fn finding_count(&self) -> usize {
        self.report.findings().len()
    }

    pub fn retained_witnesses(&self) -> usize {
        self.report.retained_witnesses()
    }

    pub fn retained_witness_steps(&self) -> usize {
        self.report.retained_witness_steps()
    }

    pub fn retained_witness_bytes(&self) -> usize {
        self.report.retained_witness_bytes()
    }

    pub fn bound_summary_count(&self) -> usize {
        self.plan.value_flow().external_summaries().entries().len()
    }

    pub fn artifact_keys(&self) -> &[SemanticArtifactKey] {
        &self.artifact_keys
    }

    pub const fn retained_artifact_bytes(&self) -> usize {
        self.retained_artifact_bytes
    }

    pub fn registration_digest(&self) -> &str {
        assert!(
            !self.registration_digest.is_empty(),
            "production taint result must receive its registration digest"
        );
        &self.registration_digest
    }

    pub const fn phase_metrics(&self) -> &ProductionTaintPhaseMetrics {
        &self.phase_metrics
    }

    pub fn set_phase_metrics(&mut self, phase_metrics: ProductionTaintPhaseMetrics) {
        self.phase_metrics = phase_metrics;
    }

    pub fn set_registration_digest(
        &mut self,
        findings: &[crate::analyzer::structural::CodeQueryTaintFinding],
    ) -> Result<(), serde_json::Error> {
        assert!(self.registration_digest.is_empty());
        let mut digest = LengthDelimitedDigest::new(b"bifrost.production_taint_result.v1");
        digest.push(self.compatibility.workspace_snapshot().as_bytes());
        digest.push(self.compatibility.propagation_semantics().as_bytes());
        digest.push(format!("{:?}", self.compatibility.unmodeled_call_behavior()).as_bytes());
        digest.push(format!("{:?}", self.compatibility.universe()).as_bytes());
        digest.push(format!("{:?}", self.expected_root().artifact().key()).as_bytes());
        digest.push(format!("{:?}", self.expected_root().semantics().locator()).as_bytes());
        digest.push(format!("{:?}", self.projection_limits).as_bytes());
        digest.push(format!("{:?}", self.artifact_keys).as_bytes());
        digest.push(&serde_json::to_vec(findings)?);
        self.registration_digest = digest.finish().to_string().into_boxed_str();
        Ok(())
    }

    pub fn project_findings(
        &self,
        workspace: &WorkspaceAnalyzer,
        limits: crate::analyzer::structural::CodeQueryTaintProjectionLimits,
    ) -> Result<
        Vec<crate::analyzer::structural::CodeQueryTaintFinding>,
        TaintModelError,
    > {
        crate::analyzer::structural::project_taint_finding_report(
            workspace,
            &self.plan,
            &self.report,
            &self.projection_scope,
            crate::analyzer::structural::CodeQueryTaintProjectionLimits::new(
                limits
                    .max_origins_per_finding
                    .min(self.projection_limits.max_origins_per_finding),
                limits
                    .max_witnesses_per_finding
                    .min(self.projection_limits.max_witnesses_per_finding),
                limits
                    .max_steps_per_witness
                    .min(self.projection_limits.max_steps_per_witness),
                limits
                    .max_witness_bytes
                    .min(self.projection_limits.max_witness_bytes),
            ),
        )
    }

    pub(crate) fn project_findings_bounded(
        &self,
        workspace: &WorkspaceAnalyzer,
        limits: crate::analyzer::structural::CodeQueryTaintLimits,
        max_findings: usize,
        cancellation: &crate::cancellation::CancellationToken,
    ) -> Result<
        crate::analyzer::structural::BoundedTaintProjection,
        TaintModelError,
    > {
        crate::analyzer::structural::project_taint_finding_report_bounded(
            workspace,
            &self.plan,
            &self.report,
            &self.projection_scope,
            crate::analyzer::structural::CodeQueryTaintProjectionLimits::new(
                limits
                    .max_origins_per_finding
                    .min(self.projection_limits.max_origins_per_finding),
                limits
                    .max_witnesses_per_finding
                    .min(self.projection_limits.max_witnesses_per_finding),
                limits
                    .max_steps_per_witness
                    .min(self.projection_limits.max_steps_per_witness),
                limits
                    .max_witness_bytes
                    .min(self.projection_limits.max_witness_bytes),
            ),
            limits.max_findings.min(max_findings),
            limits.max_projected_bytes,
            Some(cancellation),
        )
    }
}
