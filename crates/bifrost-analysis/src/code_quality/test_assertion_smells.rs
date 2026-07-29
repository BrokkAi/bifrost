//! MCP `report_test_assertion_smells` handler. Runs the analyzer's
//! per-language test-assertion smell heuristic across the given files,
//! applies `min_score` and `max_findings` caps, and renders a markdown
//! report whose layout matches brokk-core `CodeQualityToolsMcp
//! .reportTestAssertionSmells`.

use super::{
    ReportLines, append_ambiguous_path_notes, pick_weight, resolve_project_files,
    sanitize_table_cell,
};
use crate::analyzer::{IAnalyzer, TestAssertionSmell, TestAssertionWeights};
use crate::path_utils::{AmbiguousPathInput, rel_path_string};
use serde::{Deserialize, Serialize};

const DEFAULT_TEST_ASSERTION_MIN_SCORE: i32 = 4;
const DEFAULT_TEST_ASSERTION_MAX_FINDINGS: i32 = 80;

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

#[derive(Debug, Clone, Serialize)]
pub struct ReportTestAssertionSmellsResult {
    pub report: String,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ambiguous_paths: Vec<AmbiguousPathInput>,
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
    let findings_cap = if params.max_findings > 0 {
        params.max_findings as usize
    } else {
        DEFAULT_TEST_ASSERTION_MAX_FINDINGS as usize
    };
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

    let resolved = resolve_project_files(analyzer.project(), params.file_paths);
    let mut truncated = resolved.input_truncated;
    let ambiguous_paths = resolved.ambiguous_paths.clone();
    let mut findings: Vec<TestAssertionSmell> = Vec::new();
    for file in &resolved.files {
        if !analyzer.contains_tests(file) {
            continue;
        }
        findings.extend(analyzer.find_test_assertion_smells(file, weights));
    }

    let mut filtered: Vec<TestAssertionSmell> = findings
        .into_iter()
        .filter(|finding| finding.score >= threshold)
        .collect();
    filtered.sort_by(test_assertion_smell_cmp);

    if filtered.is_empty() {
        return ReportTestAssertionSmellsResult {
            report: format!("No test assertion smells met minScore {threshold}."),
            truncated,
            ambiguous_paths,
        };
    }

    let total = filtered.len();
    let shown = findings_cap.min(total);
    let rows_truncated = total > shown;
    truncated |= rows_truncated;

    let mut lines = ReportLines::with_capacity(shown + 8);
    lines.line("## Test assertion smells");
    lines.blank();
    lines.line(format!("- Min score: {threshold}"));
    lines.line(format!("- Findings shown: {shown} of {total}"));
    lines.line(format!(
        "- Weights: {}",
        format_weights!(
            "noAssertion" => weights.no_assertion_weight,
            "tautology" => weights.tautological_assertion_weight,
            "constantTruth" => weights.constant_truth_weight,
            "constantEquality" => weights.constant_equality_weight,
            "nullnessOnly" => weights.nullness_only_weight,
            "shallowOnly" => weights.shallow_assertion_only_weight,
            "overspecifiedLiteral" => weights.overspecified_literal_weight,
            "anonymousDouble" => weights.anonymous_test_double_weight,
            "repeatedAnonymousDouble" => weights.repeated_anonymous_test_double_weight,
            "assertionCredit" => weights.meaningful_assertion_credit,
            "assertionCreditCap" => weights.meaningful_assertion_credit_cap,
            "largeLiteralThreshold" => weights.large_literal_length_threshold,
        )
    ));
    append_ambiguous_path_notes(&mut lines, &ambiguous_paths);
    lines.blank();
    lines.line("| Score | Kind | Assertions | Symbol | File | Reasons | Excerpt |");
    lines.line("|------:|------|-----------:|--------|------|---------|---------|");
    for finding in filtered.iter().take(shown) {
        let reasons = sanitize_table_cell(&finding.reasons.join(", "));
        let kind = sanitize_table_cell(&finding.assertion_kind);
        let symbol = sanitize_table_cell(&finding.enclosing_fq_name);
        let file = sanitize_table_cell(&rel_path_string(&finding.file));
        let excerpt = sanitize_table_cell(&finding.excerpt);
        lines.line(format!(
            "| {score} | `{kind}` | {assertions} | `{symbol}` | `{file}` | `{reasons}` | `{excerpt}` |",
            score = finding.score,
            assertions = finding.assertion_count,
        ));
    }
    if rows_truncated {
        lines.blank();
        lines.line("- Note: output truncated; increase maxFindings to see more.");
    }

    ReportTestAssertionSmellsResult {
        report: lines.build(),
        truncated,
        ambiguous_paths,
    }
}

fn test_assertion_smell_cmp(a: &TestAssertionSmell, b: &TestAssertionSmell) -> std::cmp::Ordering {
    b.score
        .cmp(&a.score)
        .then_with(|| a.file.to_string().cmp(&b.file.to_string()))
        .then_with(|| a.enclosing_fq_name.cmp(&b.enclosing_fq_name))
        .then_with(|| a.assertion_kind.cmp(&b.assertion_kind))
        .then_with(|| a.start_byte.cmp(&b.start_byte))
}
