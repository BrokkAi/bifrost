//! Host-controlled, schema-version-1 policy evaluation and report budgets.
//!
//! Policy source can only lower author-facing report options.  These limits are
//! supplied by the embedding and are deliberately private so neither policy
//! decoding nor an evaluator can raise a hard cap by mutating a field directly.

use std::fmt;

use brokk_bifrost_analysis::analyzer::structural::{
    CodeQueryExecutionLimits, CodeQuerySemanticLimits, CodeQueryTypestateLimits,
};

const MAX_SCANNED_FILES: usize = 20_000;
const MAX_SCANNED_SOURCE_BYTES: usize = 128 * 1024 * 1024;
const MAX_FACT_NODES: usize = 2_000_000;
const MAX_PIPELINE_ROWS: usize = 50_000;

// The three scan lanes are the only lanes whose default is a floor rather than
// a cap.  A whole-workspace policy subject scan costs Theta(workspace facts),
// so `PolicyBudget::scaled_for_workspace` raises them with the audited
// workspace's measured volume (#1771).  These hard caps, 16x the defaults,
// bound the raised values and remain the builder's rejection threshold.
const MAX_SCANNED_FILES_HARD_CAP: usize = 16 * MAX_SCANNED_FILES;
const MAX_SCANNED_SOURCE_BYTES_HARD_CAP: usize = 16 * MAX_SCANNED_SOURCE_BYTES;
const MAX_FACT_NODES_HARD_CAP: usize = 16 * MAX_FACT_NODES;

/// Measured density on a large Rust workspace is ~1 fact node per 10.6 source
/// bytes; 1 per 6 gives ~1.8x headroom for denser languages (#1771).
const SOURCE_BYTES_PER_SCALED_FACT_NODE: u64 = 6;
const SCALED_SCAN_HEADROOM: u64 = 2;
const MAX_SEMANTIC_MATERIALIZED_FILES: usize = 256;
const MAX_SEMANTIC_SOURCE_BYTES: usize = 16 * 1024 * 1024;
const MAX_SEMANTIC_ROWS_PER_DIMENSION: usize = 1_000_000;
const MAX_SEMANTIC_RETAINED_BYTES: usize = 64 * 1024 * 1024;
const MAX_SEMANTIC_TRAVERSAL_STEPS: usize = 1_000_000;

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

fn saturating_usize(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

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
                semantic: CodeQuerySemanticLimits::default(),
                typestate: CodeQueryTypestateLimits::default(),
                value_flow: Default::default(),
                taint: Default::default(),
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

    /// Raise the three scan lanes to fit one whole-workspace subject scan.
    ///
    /// The fixed defaults act as floors and the hard caps as ceilings, so a
    /// workspace smaller than the defaults is returned unchanged and an
    /// explicitly widened budget is never narrowed.  `max_pipeline_rows` bounds
    /// per-query memory rather than workspace volume and stays fixed.
    pub fn scaled_for_workspace(mut self, total_source_bytes: u64, total_files: usize) -> Self {
        let scaled_fact_nodes =
            saturating_usize(total_source_bytes / SOURCE_BYTES_PER_SCALED_FACT_NODE);
        let scaled_source_bytes =
            saturating_usize(total_source_bytes.saturating_mul(SCALED_SCAN_HEADROOM));
        let scaled_files = total_files.saturating_mul(SCALED_SCAN_HEADROOM as usize);

        self.query.max_fact_nodes = self
            .query
            .max_fact_nodes
            .max(scaled_fact_nodes)
            .min(MAX_FACT_NODES_HARD_CAP);
        self.query.max_scanned_source_bytes = self
            .query
            .max_scanned_source_bytes
            .max(scaled_source_bytes)
            .min(MAX_SCANNED_SOURCE_BYTES_HARD_CAP);
        self.query.max_scanned_files = self
            .query
            .max_scanned_files
            .max(scaled_files)
            .min(MAX_SCANNED_FILES_HARD_CAP);
        self
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
    SemanticMaterializedFiles,
    SemanticSourceBytes,
    SemanticRowsPerDimension,
    SemanticRetainedBytes,
    SemanticTraversalSteps,
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
            Self::SemanticMaterializedFiles => "semantic_materialized_files",
            Self::SemanticSourceBytes => "semantic_source_bytes",
            Self::SemanticRowsPerDimension => "semantic_rows_per_dimension",
            Self::SemanticRetainedBytes => "semantic_retained_bytes",
            Self::SemanticTraversalSteps => "semantic_traversal_steps",
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
    InvalidQueryLimits {
        detail: &'static str,
    },
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
            Self::InvalidQueryLimits { detail } => {
                write!(formatter, "invalid policy query limits: {detail}")
            }
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
        if !limits.semantic.all_positive() {
            return Err(PolicyBudgetError::InvalidQueryLimits {
                detail: "semantic limits must all be positive",
            });
        }
        if !limits.typestate.is_valid() {
            return Err(PolicyBudgetError::InvalidQueryLimits {
                detail: "typestate limits must be positive and within their hard caps",
            });
        }
        ensure_at_most(
            PolicyBudgetField::ScannedFiles,
            limits.max_scanned_files,
            MAX_SCANNED_FILES_HARD_CAP,
        )?;
        ensure_at_most(
            PolicyBudgetField::ScannedSourceBytes,
            limits.max_scanned_source_bytes,
            MAX_SCANNED_SOURCE_BYTES_HARD_CAP,
        )?;
        ensure_at_most(
            PolicyBudgetField::FactNodes,
            limits.max_fact_nodes,
            MAX_FACT_NODES_HARD_CAP,
        )?;
        ensure_at_most(
            PolicyBudgetField::PipelineRows,
            limits.max_pipeline_rows,
            MAX_PIPELINE_ROWS,
        )?;
        ensure_at_most(
            PolicyBudgetField::SemanticMaterializedFiles,
            limits.semantic.max_materialized_files,
            MAX_SEMANTIC_MATERIALIZED_FILES,
        )?;
        ensure_at_most(
            PolicyBudgetField::SemanticSourceBytes,
            limits.semantic.max_source_bytes,
            MAX_SEMANTIC_SOURCE_BYTES,
        )?;
        ensure_at_most(
            PolicyBudgetField::SemanticRowsPerDimension,
            limits.semantic.max_rows_per_dimension,
            MAX_SEMANTIC_ROWS_PER_DIMENSION,
        )?;
        ensure_at_most(
            PolicyBudgetField::SemanticRetainedBytes,
            limits.semantic.max_retained_bytes,
            MAX_SEMANTIC_RETAINED_BYTES,
        )?;
        ensure_at_most(
            PolicyBudgetField::SemanticTraversalSteps,
            limits.semantic.max_traversal_steps,
            MAX_SEMANTIC_TRAVERSAL_STEPS,
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
        assert_eq!(
            query.semantic.max_materialized_files,
            MAX_SEMANTIC_MATERIALIZED_FILES
        );
        assert_eq!(
            query.semantic.max_retained_bytes,
            MAX_SEMANTIC_RETAINED_BYTES
        );
        assert_eq!(
            query.semantic.max_traversal_steps,
            MAX_SEMANTIC_TRAVERSAL_STEPS
        );
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
                semantic: CodeQuerySemanticLimits::default(),
                typestate: CodeQueryTypestateLimits::default(),
                value_flow: Default::default(),
                taint: Default::default(),
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
    fn query_limits_reject_zero_semantic_and_typestate_dimensions() {
        let semantic_error = PolicyBudget::builder()
            .with_query_limits(CodeQueryExecutionLimits {
                semantic: CodeQuerySemanticLimits {
                    max_source_bytes: 0,
                    ..CodeQuerySemanticLimits::default()
                },
                ..CodeQueryExecutionLimits::default()
            })
            .unwrap_err();
        assert_eq!(
            semantic_error,
            PolicyBudgetError::InvalidQueryLimits {
                detail: "semantic limits must all be positive",
            }
        );

        let typestate_error = PolicyBudget::builder()
            .with_query_limits(CodeQueryExecutionLimits {
                typestate: CodeQueryTypestateLimits {
                    max_candidates: 0,
                    ..CodeQueryTypestateLimits::default()
                },
                ..CodeQueryExecutionLimits::default()
            })
            .unwrap_err();
        assert_eq!(
            typestate_error,
            PolicyBudgetError::InvalidQueryLimits {
                detail: "typestate limits must be positive and within their hard caps",
            }
        );
    }

    #[test]
    fn builders_reject_values_above_their_hard_caps() {
        // The scan lanes' hard cap is the workspace-scaling ceiling, not the
        // fixed default floor (#1771).
        let query_error = PolicyBudget::builder()
            .with_query_limits(CodeQueryExecutionLimits {
                max_scanned_files: MAX_SCANNED_FILES_HARD_CAP + 1,
                ..CodeQueryExecutionLimits::default()
            })
            .unwrap_err();
        assert_eq!(
            query_error,
            PolicyBudgetError::ExceedsHardCap {
                field: PolicyBudgetField::ScannedFiles,
                value: MAX_SCANNED_FILES_HARD_CAP + 1,
                hard_cap: MAX_SCANNED_FILES_HARD_CAP,
            }
        );
        assert!(
            PolicyBudget::builder()
                .with_query_limits(CodeQueryExecutionLimits {
                    max_scanned_files: MAX_SCANNED_FILES_HARD_CAP,
                    max_scanned_source_bytes: MAX_SCANNED_SOURCE_BYTES_HARD_CAP,
                    max_fact_nodes: MAX_FACT_NODES_HARD_CAP,
                    ..CodeQueryExecutionLimits::default()
                })
                .is_ok()
        );

        for (limits, field, value, hard_cap) in [
            (
                CodeQueryExecutionLimits {
                    semantic: CodeQuerySemanticLimits {
                        max_materialized_files: MAX_SEMANTIC_MATERIALIZED_FILES + 1,
                        ..CodeQuerySemanticLimits::default()
                    },
                    ..CodeQueryExecutionLimits::default()
                },
                PolicyBudgetField::SemanticMaterializedFiles,
                MAX_SEMANTIC_MATERIALIZED_FILES + 1,
                MAX_SEMANTIC_MATERIALIZED_FILES,
            ),
            (
                CodeQueryExecutionLimits {
                    semantic: CodeQuerySemanticLimits {
                        max_source_bytes: MAX_SEMANTIC_SOURCE_BYTES + 1,
                        ..CodeQuerySemanticLimits::default()
                    },
                    ..CodeQueryExecutionLimits::default()
                },
                PolicyBudgetField::SemanticSourceBytes,
                MAX_SEMANTIC_SOURCE_BYTES + 1,
                MAX_SEMANTIC_SOURCE_BYTES,
            ),
            (
                CodeQueryExecutionLimits {
                    semantic: CodeQuerySemanticLimits {
                        max_rows_per_dimension: MAX_SEMANTIC_ROWS_PER_DIMENSION + 1,
                        ..CodeQuerySemanticLimits::default()
                    },
                    ..CodeQueryExecutionLimits::default()
                },
                PolicyBudgetField::SemanticRowsPerDimension,
                MAX_SEMANTIC_ROWS_PER_DIMENSION + 1,
                MAX_SEMANTIC_ROWS_PER_DIMENSION,
            ),
            (
                CodeQueryExecutionLimits {
                    semantic: CodeQuerySemanticLimits {
                        max_retained_bytes: MAX_SEMANTIC_RETAINED_BYTES + 1,
                        ..CodeQuerySemanticLimits::default()
                    },
                    ..CodeQueryExecutionLimits::default()
                },
                PolicyBudgetField::SemanticRetainedBytes,
                MAX_SEMANTIC_RETAINED_BYTES + 1,
                MAX_SEMANTIC_RETAINED_BYTES,
            ),
            (
                CodeQueryExecutionLimits {
                    semantic: CodeQuerySemanticLimits {
                        max_traversal_steps: MAX_SEMANTIC_TRAVERSAL_STEPS + 1,
                        ..CodeQuerySemanticLimits::default()
                    },
                    ..CodeQueryExecutionLimits::default()
                },
                PolicyBudgetField::SemanticTraversalSteps,
                MAX_SEMANTIC_TRAVERSAL_STEPS + 1,
                MAX_SEMANTIC_TRAVERSAL_STEPS,
            ),
        ] {
            assert_eq!(
                PolicyBudget::builder()
                    .with_query_limits(limits)
                    .unwrap_err(),
                PolicyBudgetError::ExceedsHardCap {
                    field,
                    value,
                    hard_cap,
                }
            );
        }

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
    fn scan_lanes_scale_with_the_audited_workspace_volume() {
        // This repository at the time of #1771: 1309 Rust files, 37.6MB.
        let scaled = PolicyBudget::default().scaled_for_workspace(37_600_000, 1_309);
        let query = scaled.query_limits();
        assert!(
            query.max_fact_nodes >= 6_200_000,
            "fact nodes did not scale: {}",
            query.max_fact_nodes
        );
        assert_eq!(query.max_fact_nodes, 37_600_000 / 6);
        // Both lanes stay at their default floors: 2x37.6MB and 2x1309 are
        // below the fixed defaults.
        assert_eq!(query.max_scanned_source_bytes, MAX_SCANNED_SOURCE_BYTES);
        assert_eq!(query.max_scanned_files, MAX_SCANNED_FILES);
        assert_eq!(query.max_pipeline_rows, MAX_PIPELINE_ROWS);

        let wide = PolicyBudget::default().scaled_for_workspace(1_024 * 1024 * 1024, 100_000);
        let wide_query = wide.query_limits();
        assert_eq!(wide_query.max_scanned_source_bytes, 2 * 1024 * 1024 * 1024);
        assert_eq!(wide_query.max_scanned_files, 200_000);
    }

    #[test]
    fn scaled_scan_lanes_clamp_to_their_hard_caps() {
        let scaled = PolicyBudget::default().scaled_for_workspace(u64::MAX, usize::MAX);
        let query = scaled.query_limits();
        assert_eq!(query.max_fact_nodes, MAX_FACT_NODES_HARD_CAP);
        assert_eq!(
            query.max_scanned_source_bytes,
            MAX_SCANNED_SOURCE_BYTES_HARD_CAP
        );
        assert_eq!(query.max_scanned_files, MAX_SCANNED_FILES_HARD_CAP);
        assert_eq!(query.max_pipeline_rows, MAX_PIPELINE_ROWS);
        PolicyBudget::builder()
            .with_query_limits(query)
            .expect("clamped scan lanes stay within the builder hard caps");
    }

    #[test]
    fn a_small_workspace_leaves_every_lane_at_its_default() {
        let scaled = PolicyBudget::default().scaled_for_workspace(1024 * 1024, 50);
        let query = scaled.query_limits();
        assert_eq!(query.max_fact_nodes, MAX_FACT_NODES);
        assert_eq!(query.max_scanned_source_bytes, MAX_SCANNED_SOURCE_BYTES);
        assert_eq!(query.max_scanned_files, MAX_SCANNED_FILES);
        assert_eq!(query.max_pipeline_rows, MAX_PIPELINE_ROWS);
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
