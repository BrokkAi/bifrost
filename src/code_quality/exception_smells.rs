//! MCP `report_exception_handling_smells` handler. Runs the analyzer's
//! per-language exception-handling smell heuristic across the given files,
//! applies `min_score` and `max_findings` caps, and renders a markdown
//! report whose layout (header, weights line, table columns, sanitization,
//! truncation note) matches brokk-core `CodeQualityToolsMcp
//! .reportExceptionHandlingSmells` byte-for-byte.

use super::{ReportLines, pick_weight, resolve_project_files, sanitize_table_cell};
use crate::analyzer::{ExceptionHandlingSmell, ExceptionSmellWeights, IAnalyzer};
use crate::path_utils::rel_path_string;
use serde::{Deserialize, Serialize};

const DEFAULT_EXCEPTION_MIN_SCORE: i32 = 4;
const DEFAULT_EXCEPTION_MAX_FINDINGS: i32 = 80;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportExceptionHandlingSmellsParams {
    pub file_paths: Vec<String>,
    /// `<= 0` → default of `4` (brokk-shared default).
    #[serde(default)]
    pub min_score: i32,
    /// `<= 0` → default of `80`.
    #[serde(default)]
    pub max_findings: i32,
    /// All `*_weight` and `*_credit*` knobs accept `< 0` to keep the brokk
    /// default (zero is honored as an explicit override). Mirrors brokk-core
    /// MCP semantics so the same JSON arguments produce identical reports.
    #[serde(default = "default_neg")]
    pub generic_throwable_weight: i32,
    #[serde(default = "default_neg")]
    pub generic_exception_weight: i32,
    #[serde(default = "default_neg")]
    pub generic_runtime_exception_weight: i32,
    #[serde(default = "default_neg")]
    pub empty_body_weight: i32,
    #[serde(default = "default_neg")]
    pub comment_only_body_weight: i32,
    #[serde(default = "default_neg")]
    pub small_body_weight: i32,
    #[serde(default = "default_neg")]
    pub log_only_body_weight: i32,
    #[serde(default = "default_neg")]
    pub meaningful_body_credit_per_statement: i32,
    #[serde(default = "default_neg")]
    pub meaningful_body_statement_threshold: i32,
    #[serde(default = "default_neg")]
    pub small_body_max_statements: i32,
}

fn default_neg() -> i32 {
    -1
}

impl Default for ReportExceptionHandlingSmellsParams {
    /// Use `-1` for every weight knob so `..Default::default()` in tests and
    /// callers picks up brokk's defaults via [`pick_weight`]. A plain
    /// `#[derive(Default)]` would zero them out — and `pick_weight` treats
    /// `0` as an explicit override, which would silence every rule.
    fn default() -> Self {
        Self {
            file_paths: Vec::new(),
            min_score: 0,
            max_findings: 0,
            generic_throwable_weight: -1,
            generic_exception_weight: -1,
            generic_runtime_exception_weight: -1,
            empty_body_weight: -1,
            comment_only_body_weight: -1,
            small_body_weight: -1,
            log_only_body_weight: -1,
            meaningful_body_credit_per_statement: -1,
            meaningful_body_statement_threshold: -1,
            small_body_max_statements: -1,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportExceptionHandlingSmellsResult {
    pub report: String,
    /// `true` when the findings list was clipped to `max_findings` rows or
    /// when more file paths were supplied than [`super::MAX_FILE_PATHS`].
    pub truncated: bool,
}

pub fn report_exception_handling_smells(
    analyzer: &dyn IAnalyzer,
    params: ReportExceptionHandlingSmellsParams,
) -> ReportExceptionHandlingSmellsResult {
    let threshold = if params.min_score > 0 {
        params.min_score
    } else {
        DEFAULT_EXCEPTION_MIN_SCORE
    };
    let findings_cap = if params.max_findings > 0 {
        params.max_findings as usize
    } else {
        DEFAULT_EXCEPTION_MAX_FINDINGS as usize
    };
    let defaults = ExceptionSmellWeights::defaults();
    let weights = ExceptionSmellWeights {
        generic_throwable_weight: pick_weight(
            params.generic_throwable_weight,
            defaults.generic_throwable_weight,
        ),
        generic_exception_weight: pick_weight(
            params.generic_exception_weight,
            defaults.generic_exception_weight,
        ),
        generic_runtime_exception_weight: pick_weight(
            params.generic_runtime_exception_weight,
            defaults.generic_runtime_exception_weight,
        ),
        empty_body_weight: pick_weight(params.empty_body_weight, defaults.empty_body_weight),
        comment_only_body_weight: pick_weight(
            params.comment_only_body_weight,
            defaults.comment_only_body_weight,
        ),
        small_body_weight: pick_weight(params.small_body_weight, defaults.small_body_weight),
        log_only_weight: pick_weight(params.log_only_body_weight, defaults.log_only_weight),
        meaningful_body_credit_per_statement: pick_weight(
            params.meaningful_body_credit_per_statement,
            defaults.meaningful_body_credit_per_statement,
        ),
        meaningful_body_statement_threshold: pick_weight(
            params.meaningful_body_statement_threshold,
            defaults.meaningful_body_statement_threshold,
        ),
        small_body_max_statements: pick_weight(
            params.small_body_max_statements,
            defaults.small_body_max_statements,
        ),
    };

    let resolved = resolve_project_files(analyzer.project(), params.file_paths);
    let mut input_truncated = resolved.input_truncated;
    let mut findings: Vec<ExceptionHandlingSmell> = Vec::new();
    for file in &resolved.files {
        findings.extend(analyzer.find_exception_handling_smells(file, weights));
    }

    let filtered: Vec<ExceptionHandlingSmell> = {
        let mut v: Vec<ExceptionHandlingSmell> = findings
            .into_iter()
            .filter(|f| f.score >= threshold)
            .collect();
        v.sort_by(|a, b| {
            b.score
                .cmp(&a.score)
                .then_with(|| a.file.to_string().cmp(&b.file.to_string()))
                .then_with(|| a.enclosing_fq_name.cmp(&b.enclosing_fq_name))
                .then_with(|| a.start_byte.cmp(&b.start_byte))
        });
        v
    };

    if filtered.is_empty() {
        return ReportExceptionHandlingSmellsResult {
            report: format!("No exception-handling smells met minScore {threshold}."),
            truncated: input_truncated,
        };
    }
    let total = filtered.len();
    let shown = findings_cap.min(total);
    let rows_truncated = total > shown;
    input_truncated |= rows_truncated;

    let mut lines = ReportLines::with_capacity(shown + 8);
    lines.line("## Exception handling smells");
    lines.blank();
    lines.line(format!("- Min score: {threshold}"));
    lines.line(format!("- Findings shown: {shown} of {total}"));
    lines.line(format!(
        "- Weights: {}",
        format_weights!(
            "Throwable" => weights.generic_throwable_weight,
            "Exception" => weights.generic_exception_weight,
            "RuntimeException" => weights.generic_runtime_exception_weight,
            "empty" => weights.empty_body_weight,
            "commentOnly" => weights.comment_only_body_weight,
            "small" => weights.small_body_weight,
            "logOnly" => weights.log_only_weight,
            "creditPerStmt" => weights.meaningful_body_credit_per_statement,
            "creditCap" => weights.meaningful_body_statement_threshold,
            "smallBodyMax" => weights.small_body_max_statements,
        )
    ));
    lines.blank();
    lines.line("| Score | Catch Type | Statements | Symbol | File | Reasons | Excerpt |");
    lines.line("|------:|------------|-----------:|--------|------|---------|---------|");
    for finding in filtered.iter().take(shown) {
        let reasons = sanitize_table_cell(&finding.reasons.join(", "));
        let catch_type = sanitize_table_cell(&finding.catch_type);
        let symbol = sanitize_table_cell(&finding.enclosing_fq_name);
        let file = sanitize_table_cell(&rel_path_string(&finding.file));
        let excerpt = sanitize_table_cell(&finding.excerpt);
        lines.line(format!(
            "| {score} | `{catch_type}` | {stmts} | `{symbol}` | `{file}` | `{reasons}` | `{excerpt}` |",
            score = finding.score,
            stmts = finding.body_statement_count,
        ));
    }
    if rows_truncated {
        lines.blank();
        lines.line("- Note: output truncated; increase maxFindings to see more.");
    }

    ReportExceptionHandlingSmellsResult {
        report: lines.build(),
        truncated: input_truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::AnalyzerFixture;

    fn java_with_catch(body: &str) -> String {
        format!(
            "package com.example;\n\npublic class Foo {{\n  public void bar() {{\n    try {{ int x = 1; }} catch (Exception e) {{\n{body}    }}\n  }}\n}}\n"
        )
    }

    #[test]
    fn exception_smells_empty_body_above_threshold_is_reported() {
        let java = java_with_catch("");
        let fix = AnalyzerFixture::new(&[("Foo.java", java.as_str())]);
        let result = report_exception_handling_smells(
            fix.analyzer.analyzer(),
            ReportExceptionHandlingSmellsParams {
                file_paths: vec!["Foo.java".to_string()],
                ..Default::default()
            },
        );
        assert!(
            result.report.starts_with("## Exception handling smells"),
            "report: {}",
            result.report
        );
        assert!(result.report.contains("- Min score: 4"));
        assert!(result.report.contains("- Findings shown: 1 of 1"));
        // Empty body + catching Exception → score = 5 (empty) + 3 (Exception) +
        // 2 (small body, 0 stmts) = 10. Reasons listed comma-joined inside backticks.
        assert!(
            result
                .report
                .contains("| 10 | `Exception` | 0 | `com.example.Foo.bar`")
        );
        assert!(
            result
                .report
                .contains("generic-catch:Exception, empty-body, small-body:0")
        );
        assert!(!result.truncated);
    }

    #[test]
    fn exception_smells_meaningful_body_below_threshold_is_filtered() {
        let body = "      System.out.println(1);\n      System.out.println(2);\n      System.out.println(3);\n";
        let java = java_with_catch(body);
        let fix = AnalyzerFixture::new(&[("Foo.java", java.as_str())]);
        let result = report_exception_handling_smells(
            fix.analyzer.analyzer(),
            ReportExceptionHandlingSmellsParams {
                file_paths: vec!["Foo.java".to_string()],
                ..Default::default()
            },
        );
        // catch Exception (3) + 3 stmts * creditPerStmt(1) = 0 after credit → filtered.
        assert_eq!(
            result.report,
            "No exception-handling smells met minScore 4."
        );
    }

    #[test]
    fn exception_smells_non_java_files_are_silently_skipped() {
        let fix = AnalyzerFixture::new(&[("src/lib.rs", "fn trivial() -> i32 { 0 }\n")]);
        let result = report_exception_handling_smells(
            fix.analyzer.analyzer(),
            ReportExceptionHandlingSmellsParams {
                file_paths: vec!["src/lib.rs".to_string()],
                ..Default::default()
            },
        );
        assert_eq!(
            result.report,
            "No exception-handling smells met minScore 4."
        );
    }

    #[test]
    fn exception_smells_log_only_body_gets_log_reason() {
        let body = "      log.error(\"boom\", e);\n";
        let java = java_with_catch(body);
        let fix = AnalyzerFixture::new(&[("Foo.java", java.as_str())]);
        let result = report_exception_handling_smells(
            fix.analyzer.analyzer(),
            ReportExceptionHandlingSmellsParams {
                file_paths: vec!["Foo.java".to_string()],
                ..Default::default()
            },
        );
        assert!(
            result.report.contains("log-only-body"),
            "report: {}",
            result.report
        );
        // 1-stmt body still counts as small (<= small_body_max=2).
        assert!(result.report.contains("small-body:1"));
    }

    #[test]
    fn exception_smells_throwable_outranks_exception() {
        let java = "package com.example;\n\npublic class Foo {\n  public void bar() {\n    try { int x = 1; } catch (Throwable t) {\n    }\n    try { int y = 2; } catch (Exception e) {\n    }\n  }\n}\n";
        let fix = AnalyzerFixture::new(&[("Foo.java", java)]);
        let result = report_exception_handling_smells(
            fix.analyzer.analyzer(),
            ReportExceptionHandlingSmellsParams {
                file_paths: vec!["Foo.java".to_string()],
                ..Default::default()
            },
        );
        // Throwable empty: 5 + 5 + 2 = 12. Exception empty: 3 + 5 + 2 = 10.
        // Throwable must appear first.
        let throwable_pos = result.report.find("`Throwable`").unwrap();
        let exception_pos = result.report.find("`Exception`").unwrap();
        assert!(throwable_pos < exception_pos);
    }

    #[test]
    fn exception_smells_max_findings_truncates_output() {
        let java = "package com.example;\n\npublic class Foo {\n  public void bar() {\n    try { int x = 1; } catch (Exception e) {}\n    try { int y = 2; } catch (Exception e) {}\n  }\n}\n";
        let fix = AnalyzerFixture::new(&[("Foo.java", java)]);
        let result = report_exception_handling_smells(
            fix.analyzer.analyzer(),
            ReportExceptionHandlingSmellsParams {
                file_paths: vec!["Foo.java".to_string()],
                max_findings: 1,
                ..Default::default()
            },
        );
        assert!(result.truncated);
        assert!(result.report.contains("- Findings shown: 1 of 2"));
        assert!(
            result
                .report
                .contains("- Note: output truncated; increase maxFindings to see more.")
        );
    }

    #[test]
    fn exception_smells_explicit_min_score_filters_low_scores() {
        // Catch Exception with one logging statement: 3 (Exception) + 2 (small) + 2 (log-only)
        // − 1 (credit) = 6. Use min_score 7 to filter it out.
        let body = "      log.warn(\"oops\");\n";
        let java = java_with_catch(body);
        let fix = AnalyzerFixture::new(&[("Foo.java", java.as_str())]);
        let result = report_exception_handling_smells(
            fix.analyzer.analyzer(),
            ReportExceptionHandlingSmellsParams {
                file_paths: vec!["Foo.java".to_string()],
                min_score: 7,
                ..Default::default()
            },
        );
        assert_eq!(
            result.report,
            "No exception-handling smells met minScore 7."
        );
    }
}
