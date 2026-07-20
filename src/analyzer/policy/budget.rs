//! Host-controlled, schema-version-1 policy evaluation and report budgets.
//!
//! Policy source can only lower author-facing report options.  These limits are
//! supplied by the embedding and are deliberately private so neither policy
//! decoding nor an evaluator can raise a hard cap by mutating a field directly.

use std::fmt;

use crate::analyzer::structural::CodeQueryExecutionLimits;

const MAX_SCANNED_FILES: usize = 20_000;
const MAX_SCANNED_SOURCE_BYTES: usize = 128 * 1024 * 1024;
const MAX_FACT_NODES: usize = 2_000_000;
const MAX_PIPELINE_ROWS: usize = 50_000;

const MAX_FINDINGS: usize = 1_000;
const MAX_DIAGNOSTICS: usize = 256;
const MAX_RELATED_LOCATIONS_PER_FINDING: usize = 64;
const MAX_EVIDENCE_REFS_PER_FINDING: usize = 256;
const MAX_EVIDENCE_BYTES_PER_FINDING: usize = 64 * 1024;
const MAX_ORIGINS_PER_FINDING: usize = 256;
const MAX_WITNESSES_PER_FINDING: usize = 64;
const MAX_WITNESS_STEPS: usize = 1_024;
const MAX_WITNESS_BYTES: usize = 1024 * 1024;
const MAX_CVSS_OVERLAYS: usize = 256;
const MAX_CVSS_EVIDENCE_RECORDS_PER_FINDING: usize = 256;
const MAX_CVSS_VARIANTS_PER_FINDING: usize = 32;
const MAX_CVSS_REDUCTION_STEPS: usize = 32_768;
const MAX_PROJECTION_SCENARIO_MEMBERSHIPS: usize = 16_384;
const MAX_ORGANIZATIONAL_RISK_OVERLAYS: usize = 64;
const MAX_RETAINED_REPORT_BYTES_PER_POLICY: usize = 16 * 1024 * 1024;

const MAX_POLICIES_PER_BATCH: usize = 256;
const MAX_TOTAL_FINDINGS_PER_BATCH: usize = 10_000;
const MAX_RETAINED_REPORT_BYTES_PER_BATCH: usize = 64 * 1024 * 1024;
const MAX_SERIALIZED_REPORT_BYTES_PER_BATCH: usize = 64 * 1024 * 1024;

/// Immutable limits for one policy evaluation and its retained report data.
#[derive(Debug, Clone, Copy)]
pub struct PolicyBudget {
    query: CodeQueryExecutionLimits,
    max_findings: usize,
    max_diagnostics: usize,
    max_related_locations_per_finding: usize,
    max_evidence_refs_per_finding: usize,
    max_evidence_bytes_per_finding: usize,
    max_origins_per_finding: usize,
    max_witnesses_per_finding: usize,
    max_witness_steps: usize,
    max_witness_bytes: usize,
    max_cvss_overlays: usize,
    max_cvss_evidence_records_per_finding: usize,
    max_cvss_variants_per_finding: usize,
    max_cvss_reduction_steps: usize,
    max_projection_scenario_memberships: usize,
    max_organizational_risk_overlays: usize,
    max_retained_report_bytes: usize,
}

impl Default for PolicyBudget {
    fn default() -> Self {
        Self {
            query: CodeQueryExecutionLimits {
                max_scanned_files: MAX_SCANNED_FILES,
                max_scanned_source_bytes: MAX_SCANNED_SOURCE_BYTES,
                max_fact_nodes: MAX_FACT_NODES,
                max_pipeline_rows: MAX_PIPELINE_ROWS,
            },
            max_findings: MAX_FINDINGS,
            max_diagnostics: MAX_DIAGNOSTICS,
            max_related_locations_per_finding: MAX_RELATED_LOCATIONS_PER_FINDING,
            max_evidence_refs_per_finding: MAX_EVIDENCE_REFS_PER_FINDING,
            max_evidence_bytes_per_finding: MAX_EVIDENCE_BYTES_PER_FINDING,
            max_origins_per_finding: MAX_ORIGINS_PER_FINDING,
            // These are host hard caps.  The effective witness limits are the
            // minimum of these values and the authored PolicyReportOptions.
            max_witnesses_per_finding: MAX_WITNESSES_PER_FINDING,
            max_witness_steps: MAX_WITNESS_STEPS,
            max_witness_bytes: MAX_WITNESS_BYTES,
            max_cvss_overlays: MAX_CVSS_OVERLAYS,
            max_cvss_evidence_records_per_finding: MAX_CVSS_EVIDENCE_RECORDS_PER_FINDING,
            max_cvss_variants_per_finding: MAX_CVSS_VARIANTS_PER_FINDING,
            max_cvss_reduction_steps: MAX_CVSS_REDUCTION_STEPS,
            max_projection_scenario_memberships: MAX_PROJECTION_SCENARIO_MEMBERSHIPS,
            max_organizational_risk_overlays: MAX_ORGANIZATIONAL_RISK_OVERLAYS,
            max_retained_report_bytes: MAX_RETAINED_REPORT_BYTES_PER_POLICY,
        }
    }
}

impl PolicyBudget {
    pub fn builder() -> PolicyBudgetBuilder {
        PolicyBudgetBuilder::default()
    }

    pub const fn query_limits(&self) -> CodeQueryExecutionLimits {
        self.query
    }

    pub const fn max_findings(&self) -> usize {
        self.max_findings
    }

    pub const fn max_diagnostics(&self) -> usize {
        self.max_diagnostics
    }

    pub const fn max_related_locations_per_finding(&self) -> usize {
        self.max_related_locations_per_finding
    }

    pub const fn max_evidence_refs_per_finding(&self) -> usize {
        self.max_evidence_refs_per_finding
    }

    pub const fn max_evidence_bytes_per_finding(&self) -> usize {
        self.max_evidence_bytes_per_finding
    }

    pub const fn max_origins_per_finding(&self) -> usize {
        self.max_origins_per_finding
    }

    pub const fn max_witnesses_per_finding(&self) -> usize {
        self.max_witnesses_per_finding
    }

    pub const fn max_witness_steps(&self) -> usize {
        self.max_witness_steps
    }

    pub const fn max_witness_bytes(&self) -> usize {
        self.max_witness_bytes
    }

    pub const fn max_cvss_overlays(&self) -> usize {
        self.max_cvss_overlays
    }

    pub const fn max_cvss_evidence_records_per_finding(&self) -> usize {
        self.max_cvss_evidence_records_per_finding
    }

    pub const fn max_cvss_variants_per_finding(&self) -> usize {
        self.max_cvss_variants_per_finding
    }

    pub const fn max_cvss_reduction_steps(&self) -> usize {
        self.max_cvss_reduction_steps
    }

    pub const fn max_projection_scenario_memberships(&self) -> usize {
        self.max_projection_scenario_memberships
    }

    pub const fn max_organizational_risk_overlays(&self) -> usize {
        self.max_organizational_risk_overlays
    }

    pub const fn max_retained_report_bytes(&self) -> usize {
        self.max_retained_report_bytes
    }
}

/// Immutable limits for one multi-policy report invocation.
#[derive(Debug, Clone, Copy)]
pub struct PolicyBatchBudget {
    max_policies: usize,
    max_total_findings: usize,
    max_retained_report_bytes: usize,
    max_serialized_report_bytes: usize,
    per_policy: PolicyBudget,
}

impl Default for PolicyBatchBudget {
    fn default() -> Self {
        Self {
            max_policies: MAX_POLICIES_PER_BATCH,
            max_total_findings: MAX_TOTAL_FINDINGS_PER_BATCH,
            max_retained_report_bytes: MAX_RETAINED_REPORT_BYTES_PER_BATCH,
            max_serialized_report_bytes: MAX_SERIALIZED_REPORT_BYTES_PER_BATCH,
            per_policy: PolicyBudget::default(),
        }
    }
}

impl PolicyBatchBudget {
    pub fn builder() -> PolicyBatchBudgetBuilder {
        PolicyBatchBudgetBuilder::default()
    }

    pub const fn max_policies(&self) -> usize {
        self.max_policies
    }

    pub const fn max_total_findings(&self) -> usize {
        self.max_total_findings
    }

    pub const fn max_retained_report_bytes(&self) -> usize {
        self.max_retained_report_bytes
    }

    pub const fn max_serialized_report_bytes(&self) -> usize {
        self.max_serialized_report_bytes
    }

    pub const fn per_policy(&self) -> &PolicyBudget {
        &self.per_policy
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyBudgetField {
    ScannedFiles,
    ScannedSourceBytes,
    FactNodes,
    PipelineRows,
    Findings,
    Diagnostics,
    RelatedLocationsPerFinding,
    EvidenceRefsPerFinding,
    EvidenceBytesPerFinding,
    OriginsPerFinding,
    WitnessesPerFinding,
    WitnessSteps,
    WitnessBytes,
    CvssOverlays,
    CvssEvidenceRecordsPerFinding,
    CvssVariantsPerFinding,
    CvssReductionSteps,
    ProjectionScenarioMemberships,
    OrganizationalRiskOverlays,
    RetainedReportBytesPerPolicy,
    PoliciesPerBatch,
    TotalFindingsPerBatch,
    RetainedReportBytesPerBatch,
    SerializedReportBytesPerBatch,
}

impl PolicyBudgetField {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ScannedFiles => "scanned_files",
            Self::ScannedSourceBytes => "scanned_source_bytes",
            Self::FactNodes => "fact_nodes",
            Self::PipelineRows => "pipeline_rows",
            Self::Findings => "findings",
            Self::Diagnostics => "diagnostics",
            Self::RelatedLocationsPerFinding => "related_locations_per_finding",
            Self::EvidenceRefsPerFinding => "evidence_refs_per_finding",
            Self::EvidenceBytesPerFinding => "evidence_bytes_per_finding",
            Self::OriginsPerFinding => "origins_per_finding",
            Self::WitnessesPerFinding => "witnesses_per_finding",
            Self::WitnessSteps => "witness_steps",
            Self::WitnessBytes => "witness_bytes",
            Self::CvssOverlays => "cvss_overlays",
            Self::CvssEvidenceRecordsPerFinding => "cvss_evidence_records_per_finding",
            Self::CvssVariantsPerFinding => "cvss_variants_per_finding",
            Self::CvssReductionSteps => "cvss_reduction_steps",
            Self::ProjectionScenarioMemberships => "projection_scenario_memberships",
            Self::OrganizationalRiskOverlays => "organizational_risk_overlays",
            Self::RetainedReportBytesPerPolicy => "retained_report_bytes_per_policy",
            Self::PoliciesPerBatch => "policies_per_batch",
            Self::TotalFindingsPerBatch => "total_findings_per_batch",
            Self::RetainedReportBytesPerBatch => "retained_report_bytes_per_batch",
            Self::SerializedReportBytesPerBatch => "serialized_report_bytes_per_batch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyBudgetError {
    ExceedsHardCap {
        field: PolicyBudgetField,
        value: usize,
        hard_cap: usize,
    },
    PerPolicyRetainedBytesExceedBatch {
        per_policy: usize,
        batch: usize,
    },
}

impl fmt::Display for PolicyBudgetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExceedsHardCap {
                field,
                value,
                hard_cap,
            } => write!(
                formatter,
                "policy budget {} value {value} exceeds schema-version-1 hard cap {hard_cap}",
                field.as_str()
            ),
            Self::PerPolicyRetainedBytesExceedBatch { per_policy, batch } => write!(
                formatter,
                "per-policy retained report budget {per_policy} exceeds batch retained report budget {batch}"
            ),
        }
    }
}

impl std::error::Error for PolicyBudgetError {}

fn ensure_at_most(
    field: PolicyBudgetField,
    value: usize,
    hard_cap: usize,
) -> Result<(), PolicyBudgetError> {
    if value > hard_cap {
        return Err(PolicyBudgetError::ExceedsHardCap {
            field,
            value,
            hard_cap,
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Default)]
pub struct PolicyBudgetBuilder {
    budget: PolicyBudget,
}

macro_rules! policy_budget_setter {
    ($method:ident, $member:ident, $field:ident, $hard_cap:ident) => {
        pub fn $method(mut self, value: usize) -> Result<Self, PolicyBudgetError> {
            ensure_at_most(PolicyBudgetField::$field, value, $hard_cap)?;
            self.budget.$member = value;
            Ok(self)
        }
    };
}

impl PolicyBudgetBuilder {
    pub fn with_query_limits(
        mut self,
        limits: CodeQueryExecutionLimits,
    ) -> Result<Self, PolicyBudgetError> {
        ensure_at_most(
            PolicyBudgetField::ScannedFiles,
            limits.max_scanned_files,
            MAX_SCANNED_FILES,
        )?;
        ensure_at_most(
            PolicyBudgetField::ScannedSourceBytes,
            limits.max_scanned_source_bytes,
            MAX_SCANNED_SOURCE_BYTES,
        )?;
        ensure_at_most(
            PolicyBudgetField::FactNodes,
            limits.max_fact_nodes,
            MAX_FACT_NODES,
        )?;
        ensure_at_most(
            PolicyBudgetField::PipelineRows,
            limits.max_pipeline_rows,
            MAX_PIPELINE_ROWS,
        )?;
        self.budget.query = limits;
        Ok(self)
    }

    policy_budget_setter!(with_max_findings, max_findings, Findings, MAX_FINDINGS);
    policy_budget_setter!(
        with_max_diagnostics,
        max_diagnostics,
        Diagnostics,
        MAX_DIAGNOSTICS
    );
    policy_budget_setter!(
        with_max_related_locations_per_finding,
        max_related_locations_per_finding,
        RelatedLocationsPerFinding,
        MAX_RELATED_LOCATIONS_PER_FINDING
    );
    policy_budget_setter!(
        with_max_evidence_refs_per_finding,
        max_evidence_refs_per_finding,
        EvidenceRefsPerFinding,
        MAX_EVIDENCE_REFS_PER_FINDING
    );
    policy_budget_setter!(
        with_max_evidence_bytes_per_finding,
        max_evidence_bytes_per_finding,
        EvidenceBytesPerFinding,
        MAX_EVIDENCE_BYTES_PER_FINDING
    );
    policy_budget_setter!(
        with_max_origins_per_finding,
        max_origins_per_finding,
        OriginsPerFinding,
        MAX_ORIGINS_PER_FINDING
    );
    policy_budget_setter!(
        with_max_witnesses_per_finding,
        max_witnesses_per_finding,
        WitnessesPerFinding,
        MAX_WITNESSES_PER_FINDING
    );
    policy_budget_setter!(
        with_max_witness_steps,
        max_witness_steps,
        WitnessSteps,
        MAX_WITNESS_STEPS
    );
    policy_budget_setter!(
        with_max_witness_bytes,
        max_witness_bytes,
        WitnessBytes,
        MAX_WITNESS_BYTES
    );
    policy_budget_setter!(
        with_max_cvss_overlays,
        max_cvss_overlays,
        CvssOverlays,
        MAX_CVSS_OVERLAYS
    );
    policy_budget_setter!(
        with_max_cvss_evidence_records_per_finding,
        max_cvss_evidence_records_per_finding,
        CvssEvidenceRecordsPerFinding,
        MAX_CVSS_EVIDENCE_RECORDS_PER_FINDING
    );
    policy_budget_setter!(
        with_max_cvss_variants_per_finding,
        max_cvss_variants_per_finding,
        CvssVariantsPerFinding,
        MAX_CVSS_VARIANTS_PER_FINDING
    );
    policy_budget_setter!(
        with_max_cvss_reduction_steps,
        max_cvss_reduction_steps,
        CvssReductionSteps,
        MAX_CVSS_REDUCTION_STEPS
    );
    policy_budget_setter!(
        with_max_projection_scenario_memberships,
        max_projection_scenario_memberships,
        ProjectionScenarioMemberships,
        MAX_PROJECTION_SCENARIO_MEMBERSHIPS
    );
    policy_budget_setter!(
        with_max_organizational_risk_overlays,
        max_organizational_risk_overlays,
        OrganizationalRiskOverlays,
        MAX_ORGANIZATIONAL_RISK_OVERLAYS
    );
    policy_budget_setter!(
        with_max_retained_report_bytes,
        max_retained_report_bytes,
        RetainedReportBytesPerPolicy,
        MAX_RETAINED_REPORT_BYTES_PER_POLICY
    );

    pub fn build(self) -> Result<PolicyBudget, PolicyBudgetError> {
        Ok(self.budget)
    }
}

#[derive(Debug, Clone, Default)]
pub struct PolicyBatchBudgetBuilder {
    budget: PolicyBatchBudget,
}

macro_rules! batch_budget_setter {
    ($method:ident, $member:ident, $field:ident, $hard_cap:ident) => {
        pub fn $method(mut self, value: usize) -> Result<Self, PolicyBudgetError> {
            ensure_at_most(PolicyBudgetField::$field, value, $hard_cap)?;
            self.budget.$member = value;
            Ok(self)
        }
    };
}

impl PolicyBatchBudgetBuilder {
    batch_budget_setter!(
        with_max_policies,
        max_policies,
        PoliciesPerBatch,
        MAX_POLICIES_PER_BATCH
    );
    batch_budget_setter!(
        with_max_total_findings,
        max_total_findings,
        TotalFindingsPerBatch,
        MAX_TOTAL_FINDINGS_PER_BATCH
    );
    batch_budget_setter!(
        with_max_retained_report_bytes,
        max_retained_report_bytes,
        RetainedReportBytesPerBatch,
        MAX_RETAINED_REPORT_BYTES_PER_BATCH
    );
    batch_budget_setter!(
        with_max_serialized_report_bytes,
        max_serialized_report_bytes,
        SerializedReportBytesPerBatch,
        MAX_SERIALIZED_REPORT_BYTES_PER_BATCH
    );

    pub fn with_per_policy(mut self, budget: PolicyBudget) -> Result<Self, PolicyBudgetError> {
        self.budget.per_policy = budget;
        Ok(self)
    }

    pub fn build(self) -> Result<PolicyBatchBudget, PolicyBudgetError> {
        if self.budget.per_policy.max_retained_report_bytes > self.budget.max_retained_report_bytes
        {
            return Err(PolicyBudgetError::PerPolicyRetainedBytesExceedBatch {
                per_policy: self.budget.per_policy.max_retained_report_bytes,
                batch: self.budget.max_retained_report_bytes,
            });
        }
        Ok(self.budget)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_the_schema_version_one_cli_caps() {
        let budget = PolicyBudget::default();
        let query = budget.query_limits();
        assert_eq!(query.max_scanned_files, 20_000);
        assert_eq!(query.max_scanned_source_bytes, 128 * 1024 * 1024);
        assert_eq!(query.max_fact_nodes, 2_000_000);
        assert_eq!(query.max_pipeline_rows, 50_000);
        assert_eq!(budget.max_findings(), 1_000);
        assert_eq!(budget.max_diagnostics(), 256);
        assert_eq!(budget.max_related_locations_per_finding(), 64);
        assert_eq!(budget.max_evidence_refs_per_finding(), 256);
        assert_eq!(budget.max_evidence_bytes_per_finding(), 64 * 1024);
        assert_eq!(budget.max_origins_per_finding(), 256);
        assert_eq!(budget.max_witnesses_per_finding(), 64);
        assert_eq!(budget.max_witness_steps(), 1_024);
        assert_eq!(budget.max_witness_bytes(), 1024 * 1024);
        assert_eq!(budget.max_cvss_overlays(), 256);
        assert_eq!(budget.max_cvss_evidence_records_per_finding(), 256);
        assert_eq!(budget.max_cvss_variants_per_finding(), 32);
        assert_eq!(budget.max_cvss_reduction_steps(), 32_768);
        assert_eq!(budget.max_projection_scenario_memberships(), 16_384);
        assert_eq!(budget.max_organizational_risk_overlays(), 64);
        assert_eq!(budget.max_retained_report_bytes(), 16 * 1024 * 1024);

        let batch = PolicyBatchBudget::default();
        assert_eq!(batch.max_policies(), 256);
        assert_eq!(batch.max_total_findings(), 10_000);
        assert_eq!(batch.max_retained_report_bytes(), 64 * 1024 * 1024);
        assert_eq!(batch.max_serialized_report_bytes(), 64 * 1024 * 1024);
    }

    #[test]
    fn every_limit_can_be_lowered_to_zero() {
        let budget = PolicyBudget::builder()
            .with_query_limits(CodeQueryExecutionLimits {
                max_scanned_files: 0,
                max_scanned_source_bytes: 0,
                max_fact_nodes: 0,
                max_pipeline_rows: 0,
            })
            .unwrap()
            .with_max_findings(0)
            .unwrap()
            .with_max_diagnostics(0)
            .unwrap()
            .with_max_related_locations_per_finding(0)
            .unwrap()
            .with_max_evidence_refs_per_finding(0)
            .unwrap()
            .with_max_evidence_bytes_per_finding(0)
            .unwrap()
            .with_max_origins_per_finding(0)
            .unwrap()
            .with_max_witnesses_per_finding(0)
            .unwrap()
            .with_max_witness_steps(0)
            .unwrap()
            .with_max_witness_bytes(0)
            .unwrap()
            .with_max_cvss_overlays(0)
            .unwrap()
            .with_max_cvss_evidence_records_per_finding(0)
            .unwrap()
            .with_max_cvss_variants_per_finding(0)
            .unwrap()
            .with_max_cvss_reduction_steps(0)
            .unwrap()
            .with_max_projection_scenario_memberships(0)
            .unwrap()
            .with_max_organizational_risk_overlays(0)
            .unwrap()
            .with_max_retained_report_bytes(0)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(budget.max_findings(), 0);
        assert_eq!(budget.max_retained_report_bytes(), 0);
    }

    #[test]
    fn builders_reject_values_above_their_hard_caps() {
        let query_error = PolicyBudget::builder()
            .with_query_limits(CodeQueryExecutionLimits {
                max_scanned_files: MAX_SCANNED_FILES + 1,
                ..CodeQueryExecutionLimits::default()
            })
            .unwrap_err();
        assert_eq!(
            query_error,
            PolicyBudgetError::ExceedsHardCap {
                field: PolicyBudgetField::ScannedFiles,
                value: MAX_SCANNED_FILES + 1,
                hard_cap: MAX_SCANNED_FILES,
            }
        );

        assert!(
            PolicyBudget::builder()
                .with_max_findings(MAX_FINDINGS + 1)
                .is_err()
        );
        assert!(
            PolicyBudget::builder()
                .with_max_diagnostics(MAX_DIAGNOSTICS + 1)
                .is_err()
        );
        assert!(
            PolicyBudget::builder()
                .with_max_related_locations_per_finding(MAX_RELATED_LOCATIONS_PER_FINDING + 1,)
                .is_err()
        );
        assert!(
            PolicyBudget::builder()
                .with_max_evidence_refs_per_finding(MAX_EVIDENCE_REFS_PER_FINDING + 1)
                .is_err()
        );
        assert!(
            PolicyBudget::builder()
                .with_max_evidence_bytes_per_finding(MAX_EVIDENCE_BYTES_PER_FINDING + 1)
                .is_err()
        );
        assert!(
            PolicyBudget::builder()
                .with_max_origins_per_finding(MAX_ORIGINS_PER_FINDING + 1)
                .is_err()
        );
        assert!(
            PolicyBudget::builder()
                .with_max_witnesses_per_finding(MAX_WITNESSES_PER_FINDING + 1)
                .is_err()
        );
        assert!(
            PolicyBudget::builder()
                .with_max_witness_steps(MAX_WITNESS_STEPS + 1)
                .is_err()
        );
        assert!(
            PolicyBudget::builder()
                .with_max_witness_bytes(MAX_WITNESS_BYTES + 1)
                .is_err()
        );
        assert!(
            PolicyBudget::builder()
                .with_max_cvss_overlays(MAX_CVSS_OVERLAYS + 1)
                .is_err()
        );
        assert!(
            PolicyBudget::builder()
                .with_max_cvss_evidence_records_per_finding(
                    MAX_CVSS_EVIDENCE_RECORDS_PER_FINDING + 1,
                )
                .is_err()
        );
        assert!(
            PolicyBudget::builder()
                .with_max_cvss_variants_per_finding(MAX_CVSS_VARIANTS_PER_FINDING + 1)
                .is_err()
        );
        assert!(
            PolicyBudget::builder()
                .with_max_cvss_reduction_steps(MAX_CVSS_REDUCTION_STEPS + 1)
                .is_err()
        );
        assert!(
            PolicyBudget::builder()
                .with_max_projection_scenario_memberships(MAX_PROJECTION_SCENARIO_MEMBERSHIPS + 1,)
                .is_err()
        );
        assert!(
            PolicyBudget::builder()
                .with_max_organizational_risk_overlays(MAX_ORGANIZATIONAL_RISK_OVERLAYS + 1)
                .is_err()
        );
        assert!(
            PolicyBudget::builder()
                .with_max_retained_report_bytes(MAX_RETAINED_REPORT_BYTES_PER_POLICY + 1)
                .is_err()
        );

        assert!(
            PolicyBatchBudget::builder()
                .with_max_policies(MAX_POLICIES_PER_BATCH + 1)
                .is_err()
        );
        assert!(
            PolicyBatchBudget::builder()
                .with_max_total_findings(MAX_TOTAL_FINDINGS_PER_BATCH + 1)
                .is_err()
        );
        assert!(
            PolicyBatchBudget::builder()
                .with_max_retained_report_bytes(MAX_RETAINED_REPORT_BYTES_PER_BATCH + 1)
                .is_err()
        );
        assert!(
            PolicyBatchBudget::builder()
                .with_max_serialized_report_bytes(MAX_SERIALIZED_REPORT_BYTES_PER_BATCH + 1)
                .is_err()
        );
    }

    #[test]
    fn batch_requires_per_policy_retention_to_fit_but_not_serialized_output() {
        let batch = PolicyBatchBudget::builder()
            .with_max_serialized_report_bytes(1)
            .unwrap()
            .build()
            .expect("serialized output is an independent coordinator cap");
        assert_eq!(batch.max_serialized_report_bytes(), 1);

        let error = PolicyBatchBudget::builder()
            .with_max_retained_report_bytes(1024)
            .unwrap()
            .build()
            .unwrap_err();
        assert_eq!(
            error,
            PolicyBudgetError::PerPolicyRetainedBytesExceedBatch {
                per_policy: MAX_RETAINED_REPORT_BYTES_PER_POLICY,
                batch: 1024,
            }
        );

        let lowered_per_policy = PolicyBudget::builder()
            .with_max_retained_report_bytes(1024)
            .unwrap()
            .build()
            .unwrap();
        PolicyBatchBudget::builder()
            .with_max_retained_report_bytes(1024)
            .unwrap()
            .with_per_policy(lowered_per_policy)
            .unwrap()
            .build()
            .expect("equal per-policy and batch retained limits are valid");
    }
}
