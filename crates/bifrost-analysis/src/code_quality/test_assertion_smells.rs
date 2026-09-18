//! MCP `report_test_assertion_smells` handler. Runs the analyzer's
//! per-language test-assertion smell heuristic across the given files,
//! applies `min_score` and `max_findings` caps, and renders a markdown
//! report whose layout matches brokk-core `CodeQualityToolsMcp
//! .reportTestAssertionSmells`.

use super::{
    pick_weight, resolve_project_files,
    structured_quality::{
        MAX_QUALITY_FINDINGS, QualityEvidenceCache, QualityFinding, QualityFindingKind,
        StructuredQualityFindings, TestAssertionQualityFinding, TestAssertionQualityMetrics,
        parameters, reasons, render_quality_findings,
    },
};
use crate::analyzer::{IAnalyzer, TestAssertionSmell, TestAssertionWeights};
use crate::path_utils::AmbiguousPathInput;
use serde::{Deserialize, Serialize};

const DEFAULT_TEST_ASSERTION_MIN_SCORE: i32 = 4;
const DEFAULT_TEST_ASSERTION_MAX_FINDINGS: i32 = 80;
const MAX_TEST_ASSERTION_CANDIDATES: usize = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportTestAssertionSmellsParams {
    pub file_paths: Vec<String>,
    #[serde(default)]
    pub min_score: i32,
    #[serde(default)]
    pub max_findings: i32,
    #[serde(default = "default_neg")]
    pub no_assertion_weight: i32,
    #[serde(default = "default_neg")]
    pub tautological_assertion_weight: i32,
    #[serde(default = "default_neg")]
    pub constant_truth_weight: i32,
    #[serde(default = "default_neg")]
    pub constant_equality_weight: i32,
    #[serde(default = "default_neg")]
    pub nullness_only_weight: i32,
    #[serde(default = "default_neg")]
    pub shallow_assertion_only_weight: i32,
    #[serde(default = "default_neg")]
    pub overspecified_literal_weight: i32,
    #[serde(default = "default_neg")]
    pub anonymous_test_double_weight: i32,
    #[serde(default = "default_neg")]
    pub repeated_anonymous_test_double_weight: i32,
    #[serde(default = "default_neg")]
    pub meaningful_assertion_credit: i32,
    #[serde(default = "default_neg")]
    pub meaningful_assertion_credit_cap: i32,
    #[serde(default = "default_neg")]
    pub large_literal_length_threshold: i32,
}

fn default_neg() -> i32 {
    -1
}

impl Default for ReportTestAssertionSmellsParams {
    fn default() -> Self {
        Self {
            file_paths: Vec::new(),
            min_score: 0,
            max_findings: 0,
            no_assertion_weight: -1,
            tautological_assertion_weight: -1,
            constant_truth_weight: -1,
            constant_equality_weight: -1,
            nullness_only_weight: -1,
            shallow_assertion_only_weight: -1,
            overspecified_literal_weight: -1,
            anonymous_test_double_weight: -1,
            repeated_anonymous_test_double_weight: -1,
            meaningful_assertion_credit: -1,
            meaningful_assertion_credit_cap: -1,
            large_literal_length_threshold: -1,
        }
    }
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct ReportTestAssertionSmellsResult {
    pub report: String,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ambiguous_paths: Vec<AmbiguousPathInput>,
    pub structured: StructuredQualityFindings,
}

pub fn report_test_assertion_smells(
    analyzer: &dyn IAnalyzer,
    params: ReportTestAssertionSmellsParams,
) -> ReportTestAssertionSmellsResult {
    let threshold = if params.min_score > 0 {
        params.min_score
    } else {
        DEFAULT_TEST_ASSERTION_MIN_SCORE
    };
    let requested_findings_cap = if params.max_findings > 0 {
        params.max_findings as usize
    } else {
        DEFAULT_TEST_ASSERTION_MAX_FINDINGS as usize
    };
    let findings_cap = requested_findings_cap.min(MAX_QUALITY_FINDINGS);
    let defaults = TestAssertionWeights::defaults();
    let weights = TestAssertionWeights {
        no_assertion_weight: pick_weight(params.no_assertion_weight, defaults.no_assertion_weight),
        tautological_assertion_weight: pick_weight(
            params.tautological_assertion_weight,
            defaults.tautological_assertion_weight,
        ),
        constant_truth_weight: pick_weight(
            params.constant_truth_weight,
            defaults.constant_truth_weight,
        ),
        constant_equality_weight: pick_weight(
            params.constant_equality_weight,
            defaults.constant_equality_weight,
        ),
        nullness_only_weight: pick_weight(
            params.nullness_only_weight,
            defaults.nullness_only_weight,
        ),
        shallow_assertion_only_weight: pick_weight(
            params.shallow_assertion_only_weight,
            defaults.shallow_assertion_only_weight,
        ),
        overspecified_literal_weight: pick_weight(
            params.overspecified_literal_weight,
            defaults.overspecified_literal_weight,
        ),
        anonymous_test_double_weight: pick_weight(
            params.anonymous_test_double_weight,
            defaults.anonymous_test_double_weight,
        ),
        repeated_anonymous_test_double_weight: pick_weight(
            params.repeated_anonymous_test_double_weight,
            defaults.repeated_anonymous_test_double_weight,
        ),
        meaningful_assertion_credit: pick_weight(
            params.meaningful_assertion_credit,
            defaults.meaningful_assertion_credit,
        ),
        meaningful_assertion_credit_cap: pick_weight(
            params.meaningful_assertion_credit_cap,
            defaults.meaningful_assertion_credit_cap,
        ),
        large_literal_length_threshold: pick_weight(
            params.large_literal_length_threshold,
            defaults.large_literal_length_threshold,
        ),
    };

    let resolved = resolve_project_files(analyzer, params.file_paths);
    let mut analysis_truncated = false;
    let ambiguous_paths = resolved.ambiguous_paths.clone();
    let mut findings: Vec<TestAssertionSmell> = Vec::new();
    let mut remaining_candidates = MAX_TEST_ASSERTION_CANDIDATES;
    for file in &resolved.files {
        if !analyzer.contains_tests(file) {
            continue;
        }
        if remaining_candidates == 0 {
            analysis_truncated = true;
            break;
        }
        let analysis =
            analyzer.find_test_assertion_smells_limited(file, weights, remaining_candidates);
        if let Some(inspected_candidates) = analysis.inspected_candidates {
            remaining_candidates = remaining_candidates.saturating_sub(inspected_candidates);
        }
        analysis_truncated |= analysis.truncated;
        findings.extend(analysis.findings);
        if analysis.truncated {
            break;
        }
    }

    let mut filtered: Vec<TestAssertionSmell> = findings
        .into_iter()
        .filter(|finding| finding.score >= threshold)
        .collect();
    filtered.sort_by(test_assertion_smell_cmp);

    let shown = findings_cap.min(filtered.len());
    let retained = filtered.iter().take(shown);
    let mut evidence_cache = QualityEvidenceCache::new();
    let structured_findings = retained
        .map(|finding| structured_test_assertion_finding(analyzer, &mut evidence_cache, finding))
        .collect();
    let parameters = parameters(
        threshold,
        &[
            ("noAssertion", weights.no_assertion_weight),
            ("tautology", weights.tautological_assertion_weight),
            ("constantTruth", weights.constant_truth_weight),
            ("constantEquality", weights.constant_equality_weight),
            ("nullnessOnly", weights.nullness_only_weight),
            ("shallowOnly", weights.shallow_assertion_only_weight),
            ("overspecifiedLiteral", weights.overspecified_literal_weight),
            ("anonymousDouble", weights.anonymous_test_double_weight),
            (
                "repeatedAnonymousDouble",
                weights.repeated_anonymous_test_double_weight,
            ),
            ("assertionCredit", weights.meaningful_assertion_credit),
            (
                "assertionCreditCap",
                weights.meaningful_assertion_credit_cap,
            ),
            (
                "largeLiteralThreshold",
                weights.large_literal_length_threshold,
            ),
        ],
    );
    let structured = StructuredQualityFindings::new(
        QualityFindingKind::TestAssertion,
        parameters,
        structured_findings,
        !resolved.input_truncated
            && resolved.skipped_inputs == 0
            && resolved.ambiguous_paths.is_empty(),
        !analysis_truncated,
        requested_findings_cap,
        filtered.len(),
    );
    let truncated = !structured.completion.complete();

    let report = render_quality_findings(
        &structured,
        &ambiguous_paths,
        format!("No test assertion smells met minScore {threshold}"),
    );

    ReportTestAssertionSmellsResult {
        report,
        truncated,
        ambiguous_paths,
        structured,
    }
}

fn structured_test_assertion_finding(
    analyzer: &dyn IAnalyzer,
    evidence_cache: &mut QualityEvidenceCache,
    finding: &TestAssertionSmell,
) -> QualityFinding {
    QualityFinding::TestAssertion(TestAssertionQualityFinding {
        assertion_kind: finding.assertion_kind.clone(),
        reasons: reasons(&finding.reasons),
        metrics: TestAssertionQualityMetrics {
            score: finding.score,
            assertion_count: finding.assertion_count,
        },
        evidence: evidence_cache.evidence(
            analyzer,
            &finding.file,
            &finding.enclosing_fq_name,
            Some(finding.start_byte),
            finding.excerpt.clone(),
        ),
    })
}

fn test_assertion_smell_cmp(a: &TestAssertionSmell, b: &TestAssertionSmell) -> std::cmp::Ordering {
    b.score
        .cmp(&a.score)
        .then_with(|| a.file.to_string().cmp(&b.file.to_string()))
        .then_with(|| a.enclosing_fq_name.cmp(&b.enclosing_fq_name))
        .then_with(|| a.assertion_kind.cmp(&b.assertion_kind))
        .then_with(|| a.start_byte.cmp(&b.start_byte))
}
