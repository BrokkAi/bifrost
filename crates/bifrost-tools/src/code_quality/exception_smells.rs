//! MCP `report_exception_handling_smells` handler. Runs the analyzer's
//! per-language exception-handling smell heuristic across the given files,
//! applies `min_score` and `max_findings` caps, and renders a markdown
//! report whose finding table and scoring controls remain compatible with
//! brokk-core `CodeQualityToolsMcp.reportExceptionHandlingSmells`. Bifrost
//! additionally reports unsupported inputs and analysis failures explicitly.

use crate::code_quality::ReportLines;

use crate::code_quality::append_ambiguous_path_notes;

use crate::code_quality::pick_weight;

use crate::code_quality::resolve_project_files;

use crate::code_quality::sanitize_table_cell;

use brokk_bifrost_core::analyzer::model::ExceptionHandlingAnalysis;

use brokk_bifrost_core::analyzer::model::ExceptionHandlingSmell;

use brokk_bifrost_core::analyzer::model::ExceptionSmellWeights;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_analysis::path_utils::AmbiguousPathInput;

use brokk_bifrost_core::path_utils::rel_path_string;
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
    #[serde(default = "crate::code_quality::default_weight_sentinel")]
    pub generic_throwable_weight: i32,
    #[serde(default = "crate::code_quality::default_weight_sentinel")]
    pub generic_exception_weight: i32,
    #[serde(default = "crate::code_quality::default_weight_sentinel")]
    pub generic_runtime_exception_weight: i32,
    #[serde(default = "crate::code_quality::default_weight_sentinel")]
    pub empty_body_weight: i32,
    #[serde(default = "crate::code_quality::default_weight_sentinel")]
    pub comment_only_body_weight: i32,
    #[serde(default = "crate::code_quality::default_weight_sentinel")]
    pub small_body_weight: i32,
    #[serde(default = "crate::code_quality::default_weight_sentinel")]
    pub log_only_body_weight: i32,
    #[serde(default = "crate::code_quality::default_weight_sentinel")]
    pub meaningful_body_credit_per_statement: i32,
    #[serde(default = "crate::code_quality::default_weight_sentinel")]
    pub meaningful_body_statement_threshold: i32,
    #[serde(default = "crate::code_quality::default_weight_sentinel")]
    pub small_body_max_statements: i32,
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
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ambiguous_paths: Vec<AmbiguousPathInput>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub unsupported_files: Vec<ExceptionAnalysisNote>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub failed_files: Vec<ExceptionAnalysisNote>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExceptionAnalysisNote {
    pub file: String,
    pub reason: String,
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

    let resolved = resolve_project_files(analyzer, params.file_paths);
    let mut input_truncated = resolved.input_truncated;
    let ambiguous_paths = resolved.ambiguous_paths.clone();
    let mut findings: Vec<ExceptionHandlingSmell> = Vec::new();
    let mut analyzed_files = 0_usize;
    let mut unsupported_files = Vec::new();
    let mut failed_files = Vec::new();
    for file in &resolved.files {
        match analyzer.find_exception_handling_smells(file, weights) {
            ExceptionHandlingAnalysis::Analyzed(file_findings) => {
                analyzed_files += 1;
                findings.extend(file_findings);
            }
            ExceptionHandlingAnalysis::Unsupported { reason } => {
                unsupported_files.push(ExceptionAnalysisNote {
                    file: rel_path_string(file),
                    reason,
                });
            }
            ExceptionHandlingAnalysis::Failed { message } => {
                failed_files.push(ExceptionAnalysisNote {
                    file: rel_path_string(file),
                    reason: message,
                });
            }
        }
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
        let report = if unsupported_files.is_empty() && failed_files.is_empty() {
            format!("No exception-handling smells met minScore {threshold}.")
        } else {
            render_empty_analysis_report(
                threshold,
                analyzed_files,
                &unsupported_files,
                &failed_files,
            )
        };
        return ReportExceptionHandlingSmellsResult {
            report,
            truncated: input_truncated,
            ambiguous_paths,
            unsupported_files,
            failed_files,
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
    append_ambiguous_path_notes(&mut lines, &ambiguous_paths);
    append_analysis_notes(&mut lines, &unsupported_files, &failed_files);
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
        ambiguous_paths,
        unsupported_files,
        failed_files,
    }
}

fn render_empty_analysis_report(
    threshold: i32,
    analyzed_files: usize,
    unsupported_files: &[ExceptionAnalysisNote],
    failed_files: &[ExceptionAnalysisNote],
) -> String {
    let mut lines = ReportLines::with_capacity(4 + unsupported_files.len() + failed_files.len());
    if analyzed_files == 0 {
        lines.line("Exception-handling smell analysis produced no supported results.");
    } else {
        lines.line(format!(
            "No exception-handling smells met minScore {threshold} in {analyzed_files} analyzed file(s)."
        ));
    }
    append_analysis_notes(&mut lines, unsupported_files, failed_files);
    lines.build()
}

fn append_analysis_notes(
    lines: &mut ReportLines,
    unsupported_files: &[ExceptionAnalysisNote],
    failed_files: &[ExceptionAnalysisNote],
) {
    if !unsupported_files.is_empty() {
        lines.blank();
        lines.line("Unsupported files:");
        for note in unsupported_files {
            lines.line(format!(
                "- `{}`: {}",
                sanitize_table_cell(&note.file),
                sanitize_table_cell(&note.reason)
            ));
        }
    }
    if !failed_files.is_empty() {
        lines.blank();
        lines.line("Analysis failures:");
        for note in failed_files {
            lines.line(format!(
                "- `{}`: {}",
                sanitize_table_cell(&note.file),
                sanitize_table_cell(&note.reason)
            ));
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::code_quality::exception_smells::*;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;

    #[test]
    fn exception_smells_unsupported_files_are_not_reported_as_clean() {
        let fix = AnalyzerFixture::new(&[("notes.txt", "not parsed source\n")]);
        let result = report_exception_handling_smells(
            fix.analyzer.analyzer(),
            ReportExceptionHandlingSmellsParams {
                file_paths: vec!["notes.txt".to_string()],
                ..Default::default()
            },
        );
        assert!(
            result
                .report
                .starts_with("Exception-handling smell analysis produced no supported results.")
        );
        assert!(result.report.contains("Unsupported files:"));
        assert!(result.report.contains("`notes.txt`"));
        assert_eq!(result.unsupported_files.len(), 1);
        assert!(result.failed_files.is_empty());
    }
}
