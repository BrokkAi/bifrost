//! Host-controlled, schema-version-1 policy evaluation and report budgets.
//!
//! Policy source can only lower author-facing report options.  These limits are
//! supplied by the embedding and are deliberately private so neither policy
//! decoding nor an evaluator can raise a hard cap by mutating a field directly.

use std::fmt;

use brokk_bifrost_rql::structural::{
    CodeQueryExecutionLimits, CodeQuerySemanticLimits, CodeQuerySemanticRowLimits,
    CodeQueryTypestateLimits,
};

use super::relational::MAX_RETAINED_RELATIONAL_OBLIGATIONS;

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
// Semantic lanes cap resident admissions only. Source scans and traversal of
// existing rows are non-refusing work telemetry, including on cache replay.
// Cumulative = admitted plus worked per lane: held-and-scanned bytes can count
// twice. It is telemetry, not a bound; root-work peaks are also telemetry.
// The numerical resident grants retain their historical mixed-work calibration;
// removing work refusal does not widen any resident grant.
const SCALED_SEMANTIC_SOURCE_BYTES_PER_SOURCE_BYTE: u64 = 64;
const MAX_SEMANTIC_MATERIALIZED_FILES: usize = 256;
const MAX_SEMANTIC_SOURCE_BYTES: usize = 16 * 1024 * 1024;
const MAX_SEMANTIC_ROWS_PER_DIMENSION: usize = 1_000_000;
// 256 MiB, raised from 64 MiB with owner approval on issue #2523
// (2026-08-23): after the per-dimension row caps landed, this floor was
// the last binder on the gson relational effect walk, which retains just
// over 64 MiB at full 98/98 subject coverage (206 MiB process peak RSS;
// a 1 GiB probe retained no more than the 256 MiB run). The floor only
// governs workspaces whose 25-bytes-per-source-byte scaled value falls
// below it, roughly under 10 MiB of source. The 16x hard cap moves with
// it (1 GiB -> 4 GiB) per the uniform audited ratio from #1936; the cap
// is a host-configured rejection threshold and the clamp for workspaces
// past ~160 MiB of source, never a silent default.
const MAX_SEMANTIC_RETAINED_BYTES: usize = 256 * 1024 * 1024;

// The four semantic limits are floors as well, for the same reason as the scan
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

// Retained nested collections often outnumber program points: CFG adjacency,
// locator segments, call arguments, evidence sources and dispatch candidates
// each contribute rows. max_rows_per_dimension bounds each retained row lane;
// NestedEntries includes retained nested entries, never traversal visits.
// These ratios and hard caps preserve the prior numerical grants. Their older
// corpus measurements mixed retained rows and traversal, so those measurements
// are not a census of today's resident allocations. Work does not spend them.
const SCALED_SEMANTIC_ROWS_PER_SOURCE_BYTES: u64 = 3;
const SCALED_SEMANTIC_ROW_SOURCE_BYTES: u64 = 1;

// The Java retention lane peaked at 159,599,751 owned text bytes, 13.7 per
// source byte. Owned text is dominated by locator paths and declaration segment
// names, which repeat per procedure, memory location, call target, and source
// mapping. Restic Go nilness runs over 2,368,675 source bytes first exhausted
// the 256 MiB floor and then a 540,057,900-byte scaled grant before producing
// query rows. The latter establishes a stricter lower bound of 228 retained
// bytes per source byte. Granting 456 bytes per source byte gives that measured
// lower bound 2x headroom. The lane remains capped at 16 times its fixed floor
// and this is an only-raises change for every workspace.
const SCALED_SEMANTIC_RETAINED_BYTES_PER_SOURCE_BYTE: u64 = 456;

const MAX_FINDINGS: usize = 1_000;

// The findings lane is a floor as well, for the same reason as the scan lanes
// (#1771) and the semantic lanes (#1936), and it is the one output lane that is
// deliberately request-wide rather than per-batch (#2208): it caps how much one
// whole request may report, so on a corpus the early batches spend it and every
// later batch degrades to `BatchFindingLimit` and retains no analysis at all.
// Measured on OWASP BenchmarkJava at 007786f86 (#2471): the `xss` category
// spends the fixed 1000-finding lane, 55 analyzed cases fell to `NotAnalyzed`
// purely because of where they sat in the batch order, and the category's
// TP/FP moved (26 -> 22 TP, 7 -> 10 FP) under changes that touched no `xss`
// code at all.  A fixed lane therefore makes every measurement on a corpus a
// queue-position lottery.
//
// Raising it is abstention-direction-only.  A larger output cap can only let a
// batch retain findings it already produced; it can never remove a finding, so
// it can only turn `NotAnalyzed` into a decided or inconclusive case, and it can
// never turn a flagged case into an affirmative clear.
//
// This hard cap, 16x the default, is the new rejection threshold and the ceiling
// `PolicyBudget::scaled_for_workspace` clamps to, exactly as #1771 did for the
// scan lanes and #1936 for the semantic lanes.
const MAX_FINDINGS_HARD_CAP: usize = 16 * MAX_FINDINGS;

// A finding is reported at a location, so the audited workspace's file count is
// the volume the output lane has to follow.  This is the scan-file lane's own
// model -- `total_files * SCALED_SCAN_HEADROOM` (#1771) -- reused rather than a
// second one invented: one request may report up to two findings per audited
// file.  On OWASP BenchmarkJava's 2770 analyzed files that is 5540, which the
// 16000 hard cap admits; a workspace above 8000 files clamps.
const SCALED_FINDINGS_PER_FILE: usize = SCALED_SCAN_HEADROOM as usize;

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
// One retained obligation per blocked verdict.  This is the evaluator's own
// retention bound, so the report cap and the evaluation cap are one number and
// a run can never be asked to retain an obligation the evaluator dropped.
const MAX_OBLIGATIONS_PER_RUN: usize = MAX_RETAINED_RELATIONAL_OBLIGATIONS;
/// Per-policy caps on the taint composition engine. Defaults are the
/// values the composition runs under; hard caps are sixteen times the defaults,
/// like the other workspace-scaling lanes.
const MAX_COMPOSITION_PROCEDURES: usize = 50_000;
const MAX_COMPOSITION_HOPS: usize = 2_000_000;
const MAX_COMPOSITION_CALLERS_PER_PROCEDURE: usize = 10_000;
const MAX_COMPOSITION_PROCEDURES_HARD_CAP: usize = 16 * MAX_COMPOSITION_PROCEDURES;
const MAX_COMPOSITION_HOPS_HARD_CAP: usize = 16 * MAX_COMPOSITION_HOPS;
const MAX_COMPOSITION_CALLERS_PER_PROCEDURE_HARD_CAP: usize =
    16 * MAX_COMPOSITION_CALLERS_PER_PROCEDURE;
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
    max_obligations_per_run: usize,
    max_retained_report_bytes: usize,
    max_composition_procedures: usize,
    max_composition_hops: usize,
    max_composition_callers_per_procedure: usize,
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
            max_obligations_per_run: MAX_OBLIGATIONS_PER_RUN,
            max_composition_procedures: MAX_COMPOSITION_PROCEDURES,
            max_composition_hops: MAX_COMPOSITION_HOPS,
            max_composition_callers_per_procedure: MAX_COMPOSITION_CALLERS_PER_PROCEDURE,
            max_retained_report_bytes: MAX_RETAINED_REPORT_BYTES_PER_POLICY,
        }
    }
}

impl PolicyBudget {
    pub fn builder() -> PolicyBudgetBuilder {
        PolicyBudgetBuilder::default()
    }

    /// The query limits one policy query runs under, with this budget's row
    /// lane published per semantic dimension.
    ///
    /// The lane itself is one uniform quantity: `scaled_for_workspace`
    /// derives a single row density for the audited workspace, and
    /// `selector_compiler::semantic_resident_limits` has always granted it to
    /// every row dimension. Publishing it per dimension says which layer owns
    /// these lanes and prevents memory-shaped estimates from narrowing the
    /// homogeneous retained-row dimensions. It also preserves each shared
    /// ledger remainder when a live selector session replaces this initial
    /// uniform table.
    ///
    /// #2523 exposed that, without a table, the executor priced every
    /// `nested_entries` unit as one 96-byte `SemanticLocator`, even though a
    /// unit can instead be a CFG adjacency offset, call argument, evidence
    /// source. Traversal steps no longer consume this resident grant. On google/gson that estimate capped
    /// the lane at 11,650 rows against an audited 2,944,018, and reference
    /// policy B's second bind stopped after 6 of its 98 marked procedures. The
    /// executor now keeps the authored uniform limit for that heterogeneous
    /// lane even without a table; the table remains authoritative for every
    /// policy-owned lane.
    ///
    /// Nested entries and retained bytes bound resident materialization, not
    /// the cumulative work reported by receipts. File/root window release
    /// refunds these lanes without changing their scaling or hard caps.
    /// Cumulative telemetry is admitted plus worked per lane: the same bytes
    /// can count twice when held and scanned. It is telemetry, not a bound.
    ///
    /// The memory bound is unchanged, because it was never the estimate:
    /// query-side materialization charges each artifact's measured retained
    /// bytes against `max_retained_bytes`.
    ///
    /// A live per-lane table comes from `PolicySelectorSession`, which prices
    /// each dimension from its own shared ledger's remainder; nothing authors
    /// one into a budget.
    pub fn query_limits(&self) -> CodeQueryExecutionLimits {
        let rows = self.query.semantic.max_rows_per_dimension;
        let mut limits = self.query;
        limits.semantic.rows_per_dimension = Some(CodeQuerySemanticRowLimits::from_rows(|_| rows));
        limits
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
    /// The semantic file lane follows the scan-file volume because a policy
    /// compile materializes program semantics for the whole audited corpus, not
    /// for one interactive query (#1936).  Semantic source work has a separate
    /// multiplier because one source file can be read by multiple exact
    /// semantic requests.  The row and retention lanes take their own measured
    /// densities per source byte, from corpus-scale Java and Go runs; see the
    /// constants above for the measurements and headroom.
    ///
    /// The findings lane follows the audited file count for the same reason
    /// (#2471): it is one request's total output cap, so a fixed value makes a
    /// corpus-scale run's late batches lose their findings to the batch order.
    pub fn scaled_for_workspace(mut self, total_source_bytes: u64, total_files: usize) -> Self {
        let scaled_fact_nodes =
            saturating_usize(total_source_bytes / SOURCE_BYTES_PER_SCALED_FACT_NODE);
        let scaled_scan_source_bytes =
            saturating_usize(total_source_bytes.saturating_mul(SCALED_SCAN_HEADROOM));
        let scaled_semantic_source_bytes = saturating_usize(
            total_source_bytes.saturating_mul(SCALED_SEMANTIC_SOURCE_BYTES_PER_SOURCE_BYTE),
        );
        let scaled_files = total_files.saturating_mul(SCALED_SCAN_HEADROOM as usize);

        self.query.max_fact_nodes = self
            .query
            .max_fact_nodes
            .max(scaled_fact_nodes)
            .min(MAX_FACT_NODES_HARD_CAP);
        self.query.max_scanned_source_bytes = self
            .query
            .max_scanned_source_bytes
            .max(scaled_scan_source_bytes)
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
            .max(scaled_semantic_source_bytes)
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
        self.max_findings = self
            .max_findings
            .max(total_files.saturating_mul(SCALED_FINDINGS_PER_FILE))
            .min(MAX_FINDINGS_HARD_CAP);
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

    /// Unmet negative-proof obligations one run may retain.  Obligations are
    /// report retention like findings and diagnostics, so they take their own
    /// lane rather than competing for the diagnostic cap.
    pub const fn max_obligations_per_run(&self) -> usize {
        self.max_obligations_per_run
    }

    pub const fn max_composition_procedures(&self) -> usize {
        self.max_composition_procedures
    }

    pub const fn max_composition_hops(&self) -> usize {
        self.max_composition_hops
    }

    pub const fn max_composition_callers_per_procedure(&self) -> usize {
        self.max_composition_callers_per_procedure
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
    ObligationsPerRun,
    CompositionProcedures,
    CompositionHops,
    CompositionCallersPerProcedure,
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
            Self::ObligationsPerRun => "obligations_per_run",
            Self::CompositionProcedures => "composition_procedures",
            Self::CompositionHops => "composition_hops",
            Self::CompositionCallersPerProcedure => "composition_callers_per_procedure",
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

        self.budget.query = limits;
        Ok(self)
    }

    policy_budget_setter!(
        with_max_selector_results,
        max_selector_results,
        SelectorResults,
        MAX_SELECTOR_RESULTS
    );
    // The findings lane's hard cap is the workspace-scaling ceiling, not the
    // fixed default floor (#2471), exactly as the scan and semantic lanes are.
    policy_budget_setter!(
        with_max_findings,
        max_findings,
        Findings,
        MAX_FINDINGS_HARD_CAP
    );
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
        with_max_composition_procedures,
        max_composition_procedures,
        CompositionProcedures,
        MAX_COMPOSITION_PROCEDURES_HARD_CAP
    );
    policy_budget_setter!(
        with_max_composition_hops,
        max_composition_hops,
        CompositionHops,
        MAX_COMPOSITION_HOPS_HARD_CAP
    );
    policy_budget_setter!(
        with_max_composition_callers_per_procedure,
        max_composition_callers_per_procedure,
        CompositionCallersPerProcedure,
        MAX_COMPOSITION_CALLERS_PER_PROCEDURE_HARD_CAP
    );
    policy_budget_setter!(
        with_max_obligations_per_run,
        max_obligations_per_run,
        ObligationsPerRun,
        MAX_OBLIGATIONS_PER_RUN
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
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#1936: measured semantic budgets were rejected at the default floor")]
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

                    ..CodeQuerySemanticLimits::default()
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

                        ..CodeQuerySemanticLimits::default()
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
        // The findings lane's rejection threshold moved from the default floor
        // to the 16x hard cap (#2471).  A value between the two is now a legal
        // host configuration -- before this change no configuration could raise
        // the request-wide output cap at all, which is the defect the ticket
        // records.
        assert!(
            PolicyBudget::builder()
                .with_max_findings(MAX_FINDINGS_HARD_CAP + 1)
                .is_err()
        );
        assert!(
            PolicyBudget::builder()
                .with_max_findings(MAX_FINDINGS + 1)
                .is_ok()
        );
        assert_eq!(
            PolicyBudget::builder()
                .with_max_findings(MAX_FINDINGS_HARD_CAP)
                .expect("a findings value at the hard cap is accepted")
                .build()
                .unwrap()
                .max_findings(),
            MAX_FINDINGS_HARD_CAP
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
    #[hardwon("#1771: fixed scan budgets left large workspaces inconclusive")]
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
    #[hardwon(
        "#1771: the fix prevented scaled scan grants from exceeding the hard cap after workspace-volume growth."
    )]
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
        assert_eq!(scaled.max_findings(), MAX_FINDINGS_HARD_CAP);
        PolicyBudget::builder()
            .with_query_limits(query)
            .expect("clamped scan lanes stay within the builder hard caps");
    }

    #[test]
    #[hardwon("#1936: measured Go workspace work exhausted the semantic row grant")]
    fn go_whole_workspace_semantics_has_headroom_over_the_measured_lower_bound() {
        let semantic = PolicyBudget::default()
            .scaled_for_workspace(735_750, 94)
            .query_limits()
            .semantic;
        assert_eq!(semantic.max_rows_per_dimension, 2_207_250);
        assert!(
            semantic.max_rows_per_dimension > 1_103_625,
            "the Ghostferry run exhausted this lower bound before completion"
        );
    }

    #[test]
    #[hardwon("#1936: measured workspace work exhausted retained and source grants")]
    fn restic_whole_workspace_retention_has_headroom_over_the_measured_lower_bound() {
        let semantic = PolicyBudget::default()
            .scaled_for_workspace(2_368_675, 538)
            .query_limits()
            .semantic;
        assert_eq!(semantic.max_retained_bytes, 1_080_115_800);
        assert!(
            semantic.max_retained_bytes >= 2 * 540_057_900,
            "the Restic run exhausted the prior scaled retained-artifact grant before producing rows"
        );

        assert_eq!(semantic.max_source_bytes, 151_595_200);
        assert!(
            semantic.max_source_bytes >= 2 * 75_797_600,
            "the Restic run exhausted the prior semantic source-work grant after reaching its accepted result row"
        );
    }

    #[test]
    #[hardwon("#1936: semantic lane caps made measured policy evaluation abstain")]
    fn semantic_lanes_scale_with_the_audited_workspace_volume() {
        // OWASP BenchmarkJava at the time of #1936: 1572 files, ~40MB.  Before
        // this change the compile abstained here: the 256-file materialization
        // lane was exhausted during endpoint enumeration and the 16MiB source
        // lane was exhausted at roughly 156 files.
        let scaled = PolicyBudget::default().scaled_for_workspace(40_000_000, 1_572);
        let semantic = scaled.query_limits().semantic;
        assert_eq!(semantic.max_materialized_files, 3_144);
        assert!(semantic.max_materialized_files > MAX_SEMANTIC_MATERIALIZED_FILES);
        assert_eq!(
            semantic.max_source_bytes,
            MAX_SEMANTIC_SOURCE_BYTES_HARD_CAP
        );
        assert!(semantic.max_source_bytes > MAX_SEMANTIC_SOURCE_BYTES);
        // The row and retention lanes take their calibrated densities (the
        // row and retention lanes clamp because their calibrated densities
        // exceed the respective hard caps at this workspace size.
        assert_eq!(
            semantic.max_rows_per_dimension,
            MAX_SEMANTIC_ROWS_PER_DIMENSION_HARD_CAP
        );
        assert_eq!(
            semantic.max_retained_bytes,
            MAX_SEMANTIC_RETAINED_BYTES_HARD_CAP
        );

        // The measured corpus itself: OWASP BenchmarkJava at 007786f86, 2770
        // analyzed files and 11,633,213 source bytes.  Its measured peaks were
        // 9,187,328 rows, 159,599,751 owned text bytes, and 386,156 traversal
        // steps, so every lane must admit at least those.
        let corpus = PolicyBudget::default().scaled_for_workspace(11_633_213, 2_770);
        let corpus_semantic = corpus.query_limits().semantic;
        assert_eq!(
            corpus_semantic.max_rows_per_dimension, MAX_SEMANTIC_ROWS_PER_DIMENSION_HARD_CAP,
            "3 rows per source byte requests 34_899_639 and clamps"
        );
        assert!(
            corpus_semantic.max_rows_per_dimension >= 9_187_328,
            "the row lane must admit the measured peak: {}",
            corpus_semantic.max_rows_per_dimension
        );
        assert_eq!(
            corpus_semantic.max_retained_bytes, MAX_SEMANTIC_RETAINED_BYTES_HARD_CAP,
            "456 retained bytes per source byte requests 5_304_745_128 and clamps"
        );
        assert!(
            corpus_semantic.max_retained_bytes >= 159_599_751,
            "the retention lane must admit the measured peak: {}",
            corpus_semantic.max_retained_bytes
        );

        PolicyBudget::builder()
            .with_query_limits(scaled.query_limits())
            .expect("scaled semantic lanes stay within the builder hard caps");
    }

    #[test]
    fn semantic_resident_source_has_an_independent_scale_floor_and_cap() {
        let workspace_source_bytes = 40_000_000_u64;
        let query = PolicyBudget::default()
            .scaled_for_workspace(workspace_source_bytes, 1_000)
            .query_limits();
        let expected_semantic_source = saturating_usize(
            workspace_source_bytes.saturating_mul(SCALED_SEMANTIC_SOURCE_BYTES_PER_SOURCE_BYTE),
        )
        .clamp(
            MAX_SEMANTIC_SOURCE_BYTES,
            MAX_SEMANTIC_SOURCE_BYTES_HARD_CAP,
        );
        assert_eq!(query.semantic.max_source_bytes, expected_semantic_source);
        assert_eq!(
            query.max_scanned_source_bytes, MAX_SCANNED_SOURCE_BYTES,
            "the structural lane keeps its own larger floor"
        );
        assert_ne!(
            query.semantic.max_source_bytes, query.max_scanned_source_bytes,
            "resident semantic source and structural scanning are separate lanes"
        );

        let small = PolicyBudget::default().scaled_for_workspace(1, 1);
        assert_eq!(
            small.query_limits().semantic.max_source_bytes,
            MAX_SEMANTIC_SOURCE_BYTES,
            "the default remains the resident semantic source floor"
        );
        let enormous = PolicyBudget::default().scaled_for_workspace(u64::MAX, usize::MAX);
        assert_eq!(
            enormous.query_limits().semantic.max_source_bytes,
            MAX_SEMANTIC_SOURCE_BYTES_HARD_CAP,
            "saturating resident source still clamps to the builder hard cap"
        );
    }

    /// The request-wide output lane must follow the audited workspace, or a
    /// corpus-scale run loses its late batches to the batch order (#2471).
    #[test]
    #[hardwon("#2471: request-wide finding cap starved the analyzed corpus")]
    fn the_findings_lane_scales_with_the_audited_workspace_volume() {
        // OWASP BenchmarkJava at 007786f86: 2770 analyzed files, 11,633,213
        // source bytes.  The fixed 1000-finding lane is spent by the `xss`
        // category before its later batches solve, so 55 analyzed cases read as
        // `NotAnalyzed`.  Two findings per audited file admits 5540 here.
        let corpus = PolicyBudget::default().scaled_for_workspace(11_633_213, 2_770);
        assert_eq!(corpus.max_findings(), 5_540);
        assert!(corpus.max_findings() > MAX_FINDINGS);

        // The default is a floor: a workspace smaller than it is unchanged.
        let small = PolicyBudget::default().scaled_for_workspace(1024 * 1024, 50);
        assert_eq!(small.max_findings(), MAX_FINDINGS);

        // An explicitly widened host budget is never narrowed by scaling.
        let host_widened = PolicyBudget::builder()
            .with_max_findings(8 * MAX_FINDINGS)
            .expect("a value between the default and the hard cap is accepted")
            .build()
            .unwrap();
        assert_eq!(
            host_widened
                .scaled_for_workspace(1024 * 1024, 50)
                .max_findings(),
            8 * MAX_FINDINGS
        );

        // And the scaled value stays a legal builder input, so a host can round
        // trip the budget the coordinator computed.
        PolicyBudget::builder()
            .with_max_findings(corpus.max_findings())
            .expect("the scaled findings lane stays within the builder hard cap");
    }

    /// The measured densities may only raise a lane.  Lowering one can turn a
    /// decision into an abstention on a workspace that is not the one measured,
    /// so the calibrated model must dominate the #1936 ratio model everywhere.
    #[test]
    #[hardwon(
        "#1936: measured workspace semantic work must remain above the calibrated ratio floor"
    )]
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
        }
    }

    #[test]
    #[hardwon(
        "#1771: the workspace-scaling fix must cap every semantic lane so larger repositories cannot admit unbounded work."
    )]
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

        PolicyBudget::builder()
            .with_query_limits(scaled.query_limits())
            .expect("clamped semantic lanes stay within the builder hard caps");
    }

    #[test]
    #[hardwon(
        "#1771: the scaling fix must preserve caller-widened semantic grants instead of shrinking them back to defaults."
    )]
    fn scaling_never_lowers_a_host_widened_semantic_budget() {
        let host_widened = PolicyBudget::builder()
            .with_query_limits(CodeQueryExecutionLimits {
                semantic: CodeQuerySemanticLimits {
                    max_materialized_files: 8 * MAX_SEMANTIC_MATERIALIZED_FILES,
                    max_source_bytes: 8 * MAX_SEMANTIC_SOURCE_BYTES,
                    max_rows_per_dimension: 8 * MAX_SEMANTIC_ROWS_PER_DIMENSION,
                    max_retained_bytes: 8 * MAX_SEMANTIC_RETAINED_BYTES,

                    ..CodeQuerySemanticLimits::default()
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
    }

    #[hardwon("#1771: zero semantic and typestate budgets must be rejected")]
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

    #[hardwon("368d5f661b9e: workspace scaling preserves independently widened semantic limits")]
    #[test]
    fn scaling_preserves_independently_widened_semantic_limits() {
        let custom_source_bytes = 8 * MAX_SEMANTIC_SOURCE_BYTES;

        let host_widened = PolicyBudget::builder()
            .with_query_limits(CodeQueryExecutionLimits {
                semantic: CodeQuerySemanticLimits {
                    max_source_bytes: custom_source_bytes,

                    ..CodeQuerySemanticLimits::default()
                },
                ..CodeQueryExecutionLimits::default()
            })
            .expect("independently widened semantic lanes are valid")
            .build()
            .unwrap();

        let semantic = host_widened
            .scaled_for_workspace(1024 * 1024, 50)
            .query_limits()
            .semantic;
        assert_eq!(semantic.max_source_bytes, custom_source_bytes);
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
