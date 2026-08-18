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

// Policy endpoint SELECTION must bind every matching source or sink site, not
// an interactive pagination sample.  The RQL result limit governing one
// selector query is the query's own `limit` field, which the catalog validates
// to the shared `DEFAULT_LIMIT` of 100 -- an interactive default.  At corpus
// scale a workspace-wide source or sink selector matches far more than 100
// sites, so the query truncates and reports `ResultLimitReached` before binding
// completes, which fails the require-model taint compile closed (#1935).  The
// selection result cap is therefore the pipeline-row ceiling rather than 100: a
// selection pipeline cannot emit more rows than `MAX_PIPELINE_ROWS` permits, so
// this bound never truncates before the pipeline budget -- the real
// corpus-scale limit -- does.  A selector that genuinely exceeds the pipeline
// budget still degrades honestly through the query's own incompleteness signal.
const MAX_SELECTOR_RESULTS: usize = MAX_PIPELINE_ROWS;

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

// The five semantic lanes are floors as well, for the same reason as the scan
// lanes.  They were sized for one interactive query, but a require-model taint
// compile is a whole-workspace analysis: it must materialize program semantics
// for every source and sink site in the audited corpus.  On OWASP
// BenchmarkJava, 1572 files, the fixed `MAX_SEMANTIC_MATERIALIZED_FILES` of 256
// is exhausted before endpoint enumeration finishes, and the 16MiB
// `MAX_SEMANTIC_SOURCE_BYTES` lane together with the row lane is exhausted at
// roughly 156 files, so the whole compile abstains.  Because the caps were also
// the builder's rejection threshold, no host or driver configuration could
// raise them (#1936).  These hard caps, 16x the defaults, are the new rejection
// threshold and the ceiling that `PolicyBudget::scaled_for_workspace` clamps to,
// exactly as #1771 did for the scan lanes.
const MAX_SEMANTIC_MATERIALIZED_FILES_HARD_CAP: usize = 16 * MAX_SEMANTIC_MATERIALIZED_FILES;
const MAX_SEMANTIC_SOURCE_BYTES_HARD_CAP: usize = 16 * MAX_SEMANTIC_SOURCE_BYTES;
const MAX_SEMANTIC_ROWS_PER_DIMENSION_HARD_CAP: usize = 16 * MAX_SEMANTIC_ROWS_PER_DIMENSION;
const MAX_SEMANTIC_RETAINED_BYTES_HARD_CAP: usize = 16 * MAX_SEMANTIC_RETAINED_BYTES;
const MAX_SEMANTIC_TRAVERSAL_STEPS_HARD_CAP: usize = 16 * MAX_SEMANTIC_TRAVERSAL_STEPS;

// Measured semantic density of a require-model taint compile, per source byte,
// on OWASP BenchmarkJava at 007786f86: 2770 analyzed files, 11,633,213 source
// bytes.  The measurement is the largest single-region charge each lane saw
// across all six category compiles, which is what a lane has to admit because
// `reset_region_semantic_budget` restores the lanes per region.  It is reported
// by `taint.semantic_peak_row_dimension` and `taint.semantic_peak_retained_bytes`.
//
// #1936 derived these two lanes from the semantic byte lane's scaling ratio
// because no corpus-scale run existed to measure.  That model was 6.6x short on
// the row lane and 1.7x short on the retention lane, so every category abstained
// (`nested_entries` attempted 1386788 against limit 1386787).
//
// The row lane binds on `nested_entries`, not on any per-entity dimension: it is
// a census of every artifact's nested collections -- CFG adjacency arrays,
// locator declaration segments, call arguments, evidence sources, block points,
// dispatch candidates -- so it counts several rows per program point.  One
// `max_rows_per_dimension` bounds every row dimension, so it must admit that
// largest one.  The semantic provider's own defaults agree about the shape:
// `NestedEntries` is 8,000,000 against `ProgramPoints` at 1,000,000.
//
// The peak measured 9,187,328 rows, 0.79 rows per source byte.  Three rows per
// two source bytes is 1.9x that, matching the ~1.8x headroom of the
// `SOURCE_BYTES_PER_SCALED_FACT_NODE` precedent.  That precedent's divisor form
// cannot express this density: Java runs to more than one row per source byte,
// and the smallest whole divisor, 1, would leave only 1.27x.
//
// On this corpus the requested 17,449,819 rows clamps to the 16,000,000 hard
// cap, so the realized headroom over the measurement is 1.74x rather than 1.9x.
// Anything denser than 1.38 rows per source byte clamps here, so the constant's
// value only distinguishes other workspace sizes.
const SCALED_SEMANTIC_ROWS_PER_SOURCE_BYTES: u64 = 3;
const SCALED_SEMANTIC_ROW_SOURCE_BYTES: u64 = 2;

// The retention lane peaked at 159,599,751 owned text bytes, 13.7 per source
// byte.  Owned text is dominated by locator paths and declaration segment names,
// which repeat per procedure, memory location, call target, and source mapping.
// 25 per source byte is 1.82x the measurement, and 290,830,325 bytes on this
// corpus, well inside the 1GiB hard cap.
const SCALED_SEMANTIC_RETAINED_BYTES_PER_SOURCE_BYTE: u64 = 25;

// The traversal lane is deliberately not recalibrated.  It peaked at 386,156
// steps, which its own fixed default of 1,000,000 already admits with 2.6x
// headroom and its #1936 scaled value of 1,386,787 with 3.6x.  A measured
// density for it (1 step per 30.1 source bytes, 1 per 15 with headroom) would
// compute 775,547 here and therefore LOWER the lane to its floor.  Every budget
// change in this area must only raise, because lowering a lane can turn a
// decision into an abstention on a workspace that is not the one measured.

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
    max_selector_results: usize,
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
            max_selector_results: MAX_SELECTOR_RESULTS,
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

    /// Maximum matching sites one policy source or sink selector may bind.
    ///
    /// This overrides the selector query's interactive `DEFAULT_LIMIT` so a
    /// corpus-scale endpoint selection binds every site instead of truncating
    /// at the pagination default (#1935).
    pub const fn max_selector_results(&self) -> usize {
        self.max_selector_results
    }

    /// Raise the scan and semantic lanes to fit one whole-workspace analysis.
    ///
    /// The fixed defaults act as floors and the hard caps as ceilings, so a
    /// workspace smaller than the defaults is returned unchanged and an
    /// explicitly widened budget is never narrowed.  `max_pipeline_rows` bounds
    /// per-query memory rather than workspace volume and stays fixed.
    ///
    /// The semantic file and byte lanes follow the same measured volume as the
    /// scan lanes because a policy compile materializes program semantics for
    /// the whole audited corpus, not for one interactive query (#1936).  The row
    /// and retention lanes take their own measured densities per source byte,
    /// from a corpus-scale run on OWASP BenchmarkJava; see the constants above
    /// for the measurement and the headroom.  The traversal lane keeps the
    /// byte-lane ratio it has had since #1936: its measured peak sits below even
    /// its fixed default, so a measured density would only lower it.
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

        self.query.semantic.max_materialized_files = self
            .query
            .semantic
            .max_materialized_files
            .max(scaled_files)
            .min(MAX_SEMANTIC_MATERIALIZED_FILES_HARD_CAP);
        self.query.semantic.max_source_bytes = self
            .query
            .semantic
            .max_source_bytes
            .max(scaled_source_bytes)
            .min(MAX_SEMANTIC_SOURCE_BYTES_HARD_CAP);
        // The row and retention lanes take their measured per-source-byte
        // densities.  Both are at least their fixed defaults, because the
        // defaults are floors, and both clamp to their hard caps.
        let scaled_semantic_rows = saturating_usize(
            total_source_bytes.saturating_mul(SCALED_SEMANTIC_ROWS_PER_SOURCE_BYTES)
                / SCALED_SEMANTIC_ROW_SOURCE_BYTES,
        );
        let scaled_semantic_retained_bytes = saturating_usize(
            total_source_bytes.saturating_mul(SCALED_SEMANTIC_RETAINED_BYTES_PER_SOURCE_BYTE),
        );
        self.query.semantic.max_rows_per_dimension = self
            .query
            .semantic
            .max_rows_per_dimension
            .max(scaled_semantic_rows)
            .min(MAX_SEMANTIC_ROWS_PER_DIMENSION_HARD_CAP);
        self.query.semantic.max_retained_bytes = self
            .query
            .semantic
            .max_retained_bytes
            .max(scaled_semantic_retained_bytes)
            .min(MAX_SEMANTIC_RETAINED_BYTES_HARD_CAP);
        // The traversal lane keeps the byte-lane ratio: how many default
        // semantic byte budgets the scaled byte lane spans, multiplied before
        // dividing so a corpus between one and two budgets does not floor to 1
        // (#1936).  The ratio is at least 1 because the byte lane's default is a
        // floor, and at most 16 because it was clamped to 16x just above, so the
        // u128 product cannot overflow and the result respects the hard cap.
        let scaled_semantic_bytes = self.query.semantic.max_source_bytes;
        let scaled_traversal_steps = {
            let scaled = (MAX_SEMANTIC_TRAVERSAL_STEPS as u128)
                .saturating_mul(scaled_semantic_bytes as u128)
                / (MAX_SEMANTIC_SOURCE_BYTES as u128);
            usize::try_from(scaled)
                .unwrap_or(usize::MAX)
                .max(MAX_SEMANTIC_TRAVERSAL_STEPS)
        };
        self.query.semantic.max_traversal_steps = self
            .query
            .semantic
            .max_traversal_steps
            .max(scaled_traversal_steps)
            .min(MAX_SEMANTIC_TRAVERSAL_STEPS_HARD_CAP);
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
    SelectorResults,
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
            Self::SelectorResults => "selector_results",
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
            MAX_SEMANTIC_MATERIALIZED_FILES_HARD_CAP,
        )?;
        ensure_at_most(
            PolicyBudgetField::SemanticSourceBytes,
            limits.semantic.max_source_bytes,
            MAX_SEMANTIC_SOURCE_BYTES_HARD_CAP,
        )?;
        ensure_at_most(
            PolicyBudgetField::SemanticRowsPerDimension,
            limits.semantic.max_rows_per_dimension,
            MAX_SEMANTIC_ROWS_PER_DIMENSION_HARD_CAP,
        )?;
        ensure_at_most(
            PolicyBudgetField::SemanticRetainedBytes,
            limits.semantic.max_retained_bytes,
            MAX_SEMANTIC_RETAINED_BYTES_HARD_CAP,
        )?;
        ensure_at_most(
            PolicyBudgetField::SemanticTraversalSteps,
            limits.semantic.max_traversal_steps,
            MAX_SEMANTIC_TRAVERSAL_STEPS_HARD_CAP,
        )?;
        self.budget.query = limits;
        Ok(self)
    }

    policy_budget_setter!(
        with_max_selector_results,
        max_selector_results,
        SelectorResults,
        MAX_SELECTOR_RESULTS
    );
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
        assert_eq!(budget.max_selector_results(), 50_000);
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
            .with_max_selector_results(0)
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
        assert_eq!(budget.max_selector_results(), 0);
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

        // The semantic lanes' hard cap is likewise the workspace-scaling
        // ceiling, not the fixed default floor (#1936).
        for (limits, field, value, hard_cap) in [
            (
                CodeQueryExecutionLimits {
                    semantic: CodeQuerySemanticLimits {
                        max_materialized_files: MAX_SEMANTIC_MATERIALIZED_FILES_HARD_CAP + 1,
                        ..CodeQuerySemanticLimits::default()
                    },
                    ..CodeQueryExecutionLimits::default()
                },
                PolicyBudgetField::SemanticMaterializedFiles,
                MAX_SEMANTIC_MATERIALIZED_FILES_HARD_CAP + 1,
                MAX_SEMANTIC_MATERIALIZED_FILES_HARD_CAP,
            ),
            (
                CodeQueryExecutionLimits {
                    semantic: CodeQuerySemanticLimits {
                        max_source_bytes: MAX_SEMANTIC_SOURCE_BYTES_HARD_CAP + 1,
                        ..CodeQuerySemanticLimits::default()
                    },
                    ..CodeQueryExecutionLimits::default()
                },
                PolicyBudgetField::SemanticSourceBytes,
                MAX_SEMANTIC_SOURCE_BYTES_HARD_CAP + 1,
                MAX_SEMANTIC_SOURCE_BYTES_HARD_CAP,
            ),
            (
                CodeQueryExecutionLimits {
                    semantic: CodeQuerySemanticLimits {
                        max_rows_per_dimension: MAX_SEMANTIC_ROWS_PER_DIMENSION_HARD_CAP + 1,
                        ..CodeQuerySemanticLimits::default()
                    },
                    ..CodeQueryExecutionLimits::default()
                },
                PolicyBudgetField::SemanticRowsPerDimension,
                MAX_SEMANTIC_ROWS_PER_DIMENSION_HARD_CAP + 1,
                MAX_SEMANTIC_ROWS_PER_DIMENSION_HARD_CAP,
            ),
            (
                CodeQueryExecutionLimits {
                    semantic: CodeQuerySemanticLimits {
                        max_retained_bytes: MAX_SEMANTIC_RETAINED_BYTES_HARD_CAP + 1,
                        ..CodeQuerySemanticLimits::default()
                    },
                    ..CodeQueryExecutionLimits::default()
                },
                PolicyBudgetField::SemanticRetainedBytes,
                MAX_SEMANTIC_RETAINED_BYTES_HARD_CAP + 1,
                MAX_SEMANTIC_RETAINED_BYTES_HARD_CAP,
            ),
            (
                CodeQueryExecutionLimits {
                    semantic: CodeQuerySemanticLimits {
                        max_traversal_steps: MAX_SEMANTIC_TRAVERSAL_STEPS_HARD_CAP + 1,
                        ..CodeQuerySemanticLimits::default()
                    },
                    ..CodeQueryExecutionLimits::default()
                },
                PolicyBudgetField::SemanticTraversalSteps,
                MAX_SEMANTIC_TRAVERSAL_STEPS_HARD_CAP + 1,
                MAX_SEMANTIC_TRAVERSAL_STEPS_HARD_CAP,
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

        // A host may now configure any semantic value between the default floor
        // and the hard cap; before #1936 the default was also the rejection
        // threshold, so no configuration could raise a semantic lane at all.
        let widened = PolicyBudget::builder()
            .with_query_limits(CodeQueryExecutionLimits {
                semantic: CodeQuerySemanticLimits {
                    max_materialized_files: MAX_SEMANTIC_MATERIALIZED_FILES_HARD_CAP,
                    max_source_bytes: MAX_SEMANTIC_SOURCE_BYTES_HARD_CAP,
                    max_rows_per_dimension: MAX_SEMANTIC_ROWS_PER_DIMENSION_HARD_CAP,
                    max_retained_bytes: MAX_SEMANTIC_RETAINED_BYTES_HARD_CAP,
                    max_traversal_steps: MAX_SEMANTIC_TRAVERSAL_STEPS_HARD_CAP,
                },
                ..CodeQueryExecutionLimits::default()
            })
            .expect("semantic values at the hard cap are accepted")
            .build()
            .unwrap();
        assert_eq!(
            widened.query_limits().semantic.max_materialized_files,
            MAX_SEMANTIC_MATERIALIZED_FILES_HARD_CAP
        );
        assert!(
            PolicyBudget::builder()
                .with_query_limits(CodeQueryExecutionLimits {
                    semantic: CodeQuerySemanticLimits {
                        max_materialized_files: MAX_SEMANTIC_MATERIALIZED_FILES + 1,
                        max_source_bytes: MAX_SEMANTIC_SOURCE_BYTES + 1,
                        max_rows_per_dimension: MAX_SEMANTIC_ROWS_PER_DIMENSION + 1,
                        max_retained_bytes: MAX_SEMANTIC_RETAINED_BYTES + 1,
                        max_traversal_steps: MAX_SEMANTIC_TRAVERSAL_STEPS + 1,
                    },
                    ..CodeQueryExecutionLimits::default()
                })
                .is_ok()
        );

        assert!(
            PolicyBudget::builder()
                .with_max_selector_results(MAX_SELECTOR_RESULTS + 1)
                .is_err()
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
    fn a_small_workspace_leaves_every_scan_lane_at_its_default() {
        let scaled = PolicyBudget::default().scaled_for_workspace(1024 * 1024, 50);
        let query = scaled.query_limits();
        assert_eq!(query.max_fact_nodes, MAX_FACT_NODES);
        assert_eq!(query.max_scanned_source_bytes, MAX_SCANNED_SOURCE_BYTES);
        assert_eq!(query.max_scanned_files, MAX_SCANNED_FILES);
        assert_eq!(query.max_pipeline_rows, MAX_PIPELINE_ROWS);
        // Four of the five semantic lanes stay at their defaults: 1MiB of source
        // is below every one of those floors.
        let semantic = query.semantic;
        let default = CodeQuerySemanticLimits::default();
        assert_eq!(
            semantic.max_materialized_files,
            default.max_materialized_files
        );
        assert_eq!(semantic.max_source_bytes, default.max_source_bytes);
        assert_eq!(semantic.max_retained_bytes, default.max_retained_bytes);
        assert_eq!(semantic.max_traversal_steps, default.max_traversal_steps);
        // The row lane does rise, and this is the measurement changing the
        // answer rather than the scaling overreaching.  The fixed 1,000,000
        // default was set for one interactive query; the measured density of a
        // Java taint compile is 0.79 rows per source byte, so 1MiB of source
        // already charges ~828,000 rows and the default leaves only 1.2x.  At
        // 1.5 rows per source byte the lane is 1,572,864 here.
        assert_eq!(semantic.max_rows_per_dimension, 1024 * 1024 * 3 / 2);
        assert!(semantic.max_rows_per_dimension > default.max_rows_per_dimension);
    }

    #[test]
    fn semantic_lanes_scale_with_the_audited_workspace_volume() {
        // OWASP BenchmarkJava at the time of #1936: 1572 files, ~40MB.  Before
        // this change the compile abstained here: the 256-file materialization
        // lane was exhausted during endpoint enumeration and the 16MiB source
        // lane was exhausted at roughly 156 files.
        let scaled = PolicyBudget::default().scaled_for_workspace(40_000_000, 1_572);
        let semantic = scaled.query_limits().semantic;
        assert_eq!(semantic.max_materialized_files, 3_144);
        assert!(semantic.max_materialized_files > MAX_SEMANTIC_MATERIALIZED_FILES);
        assert_eq!(semantic.max_source_bytes, 80_000_000);
        assert!(semantic.max_source_bytes > MAX_SEMANTIC_SOURCE_BYTES);
        // The row and retention lanes take their measured densities: 1.5 rows
        // and 25 owned text bytes per source byte.  Both clamp here, because
        // 40MB of source at those densities exceeds both hard caps.
        assert_eq!(
            semantic.max_rows_per_dimension,
            MAX_SEMANTIC_ROWS_PER_DIMENSION_HARD_CAP
        );
        assert_eq!(semantic.max_retained_bytes, 40_000_000 * 25);
        assert!(semantic.max_retained_bytes < MAX_SEMANTIC_RETAINED_BYTES_HARD_CAP);
        // The traversal lane keeps the byte-lane ratio, 80_000_000 / 16MiB,
        // multiplied before dividing.  Flooring the ratio to whole default byte
        // budgets left the first real corpus run (ratio 1.38) at its floor, and
        // every category abstained (#1936).
        assert_eq!(
            semantic.max_traversal_steps,
            (1_000_000_u128 * 80_000_000 / (16 * 1024 * 1024)) as usize
        );

        // The measured corpus itself: OWASP BenchmarkJava at 007786f86, 2770
        // analyzed files and 11,633,213 source bytes.  Its measured peaks were
        // 9,187,328 rows, 159,599,751 owned text bytes, and 386,156 traversal
        // steps, so every lane must admit at least those.
        let corpus = PolicyBudget::default().scaled_for_workspace(11_633_213, 2_770);
        let corpus_semantic = corpus.query_limits().semantic;
        assert_eq!(
            corpus_semantic.max_rows_per_dimension, MAX_SEMANTIC_ROWS_PER_DIMENSION_HARD_CAP,
            "1.5 rows per source byte requests 17_449_819 and clamps"
        );
        assert!(
            corpus_semantic.max_rows_per_dimension >= 9_187_328,
            "the row lane must admit the measured peak: {}",
            corpus_semantic.max_rows_per_dimension
        );
        assert_eq!(corpus_semantic.max_retained_bytes, 11_633_213 * 25);
        assert!(
            corpus_semantic.max_retained_bytes >= 159_599_751,
            "the retention lane must admit the measured peak: {}",
            corpus_semantic.max_retained_bytes
        );
        assert!(
            corpus_semantic.max_traversal_steps >= 386_156,
            "the traversal lane must admit the measured peak: {}",
            corpus_semantic.max_traversal_steps
        );
        assert!(corpus_semantic.max_traversal_steps > MAX_SEMANTIC_TRAVERSAL_STEPS);
        PolicyBudget::builder()
            .with_query_limits(scaled.query_limits())
            .expect("scaled semantic lanes stay within the builder hard caps");
    }

    /// The measured densities may only raise a lane.  Lowering one can turn a
    /// decision into an abstention on a workspace that is not the one measured,
    /// so the calibrated model must dominate the #1936 ratio model everywhere.
    #[test]
    fn the_measured_densities_never_lower_a_lane_below_the_ratio_model() {
        for total_source_bytes in [
            0_u64,
            1_024,
            1024 * 1024,
            11_633_213,
            40_000_000,
            256 * 1024 * 1024,
            u64::MAX / 32,
        ] {
            let semantic = PolicyBudget::default()
                .scaled_for_workspace(total_source_bytes, 1_000)
                .query_limits()
                .semantic;
            let byte_lane = (total_source_bytes.saturating_mul(SCALED_SCAN_HEADROOM) as u128)
                .max(MAX_SEMANTIC_SOURCE_BYTES as u128)
                .min(MAX_SEMANTIC_SOURCE_BYTES_HARD_CAP as u128);
            let ratio_model = |base: usize, hard_cap: usize| -> usize {
                let scaled =
                    (base as u128).saturating_mul(byte_lane) / (MAX_SEMANTIC_SOURCE_BYTES as u128);
                usize::try_from(scaled)
                    .unwrap_or(usize::MAX)
                    .max(base)
                    .min(hard_cap)
            };
            assert!(
                semantic.max_rows_per_dimension
                    >= ratio_model(
                        MAX_SEMANTIC_ROWS_PER_DIMENSION,
                        MAX_SEMANTIC_ROWS_PER_DIMENSION_HARD_CAP
                    ),
                "row lane regressed at {total_source_bytes} bytes"
            );
            assert!(
                semantic.max_retained_bytes
                    >= ratio_model(
                        MAX_SEMANTIC_RETAINED_BYTES,
                        MAX_SEMANTIC_RETAINED_BYTES_HARD_CAP
                    ),
                "retention lane regressed at {total_source_bytes} bytes"
            );
            assert!(
                semantic.max_traversal_steps
                    >= ratio_model(
                        MAX_SEMANTIC_TRAVERSAL_STEPS,
                        MAX_SEMANTIC_TRAVERSAL_STEPS_HARD_CAP
                    ),
                "traversal lane regressed at {total_source_bytes} bytes"
            );
        }
    }

    #[test]
    fn scaled_semantic_lanes_clamp_to_their_hard_caps() {
        let scaled = PolicyBudget::default().scaled_for_workspace(u64::MAX, usize::MAX);
        let semantic = scaled.query_limits().semantic;
        assert_eq!(
            semantic.max_materialized_files,
            MAX_SEMANTIC_MATERIALIZED_FILES_HARD_CAP
        );
        assert_eq!(
            semantic.max_source_bytes,
            MAX_SEMANTIC_SOURCE_BYTES_HARD_CAP
        );
        assert_eq!(
            semantic.max_rows_per_dimension,
            MAX_SEMANTIC_ROWS_PER_DIMENSION_HARD_CAP
        );
        assert_eq!(
            semantic.max_retained_bytes,
            MAX_SEMANTIC_RETAINED_BYTES_HARD_CAP
        );
        assert_eq!(
            semantic.max_traversal_steps,
            MAX_SEMANTIC_TRAVERSAL_STEPS_HARD_CAP
        );
        PolicyBudget::builder()
            .with_query_limits(scaled.query_limits())
            .expect("clamped semantic lanes stay within the builder hard caps");
    }

    #[test]
    fn scaling_never_lowers_a_host_widened_semantic_budget() {
        let host_widened = PolicyBudget::builder()
            .with_query_limits(CodeQueryExecutionLimits {
                semantic: CodeQuerySemanticLimits {
                    max_materialized_files: 8 * MAX_SEMANTIC_MATERIALIZED_FILES,
                    max_source_bytes: 8 * MAX_SEMANTIC_SOURCE_BYTES,
                    max_rows_per_dimension: 8 * MAX_SEMANTIC_ROWS_PER_DIMENSION,
                    max_retained_bytes: 8 * MAX_SEMANTIC_RETAINED_BYTES,
                    max_traversal_steps: 8 * MAX_SEMANTIC_TRAVERSAL_STEPS,
                },
                ..CodeQueryExecutionLimits::default()
            })
            .expect("values between the default and the hard cap are accepted")
            .build()
            .unwrap();
        // A workspace far smaller than the configured budget: every lane keeps
        // the host's value rather than falling back to the default floor.
        let semantic = host_widened
            .scaled_for_workspace(1024 * 1024, 50)
            .query_limits()
            .semantic;
        assert_eq!(
            semantic.max_materialized_files,
            8 * MAX_SEMANTIC_MATERIALIZED_FILES
        );
        assert_eq!(semantic.max_source_bytes, 8 * MAX_SEMANTIC_SOURCE_BYTES);
        assert_eq!(
            semantic.max_rows_per_dimension,
            8 * MAX_SEMANTIC_ROWS_PER_DIMENSION
        );
        assert_eq!(semantic.max_retained_bytes, 8 * MAX_SEMANTIC_RETAINED_BYTES);
        assert_eq!(
            semantic.max_traversal_steps,
            8 * MAX_SEMANTIC_TRAVERSAL_STEPS
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
