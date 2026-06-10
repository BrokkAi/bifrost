//! MCP `compute_cognitive_complexity` handler. Walks the language's
//! tree-sitter AST via [`IAnalyzer::compute_cognitive_complexities`] and
//! flags functions whose score exceeds the threshold. Output format
//! mirrors brokk-core's `CodeQualityToolsMcp.computeCognitiveComplexity`
//! byte-for-byte (`- <fqName>: <complexity>`, no source-path suffix).

use super::{MAX_REPORT_LINES, ReportLines, append_ambiguous_path_notes, resolve_project_files};
use crate::analyzer::IAnalyzer;
use crate::path_utils::AmbiguousPathInput;
use serde::{Deserialize, Serialize};

const DEFAULT_COGNITIVE_THRESHOLD: i32 = 15;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeCognitiveComplexityParams {
    pub file_paths: Vec<String>,
    #[serde(default)]
    pub threshold: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComputeCognitiveComplexityResult {
    pub report: String,
    /// `true` when input or output was clipped: either more than
    /// `MAX_FILE_PATHS` paths were supplied, or the report hit
    /// `MAX_REPORT_LINES` flagged functions.
    pub truncated: bool,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ambiguous_paths: Vec<AmbiguousPathInput>,
}

pub fn compute_cognitive_complexity(
    analyzer: &dyn IAnalyzer,
    params: ComputeCognitiveComplexityParams,
) -> ComputeCognitiveComplexityResult {
    let limit = if params.threshold > 0 {
        params.threshold
    } else {
        DEFAULT_COGNITIVE_THRESHOLD
    };
    let resolved = resolve_project_files(analyzer.project(), params.file_paths);
    let mut truncated = resolved.input_truncated;
    let ambiguous_paths = resolved.ambiguous_paths.clone();

    let mut lines = ReportLines::new();
    lines.line(format!("Cognitive complexity (threshold: {limit}):"));
    append_ambiguous_path_notes(&mut lines, &ambiguous_paths);
    let mut found_any = false;
    let mut report_full = false;

    'outer: for file in &resolved.files {
        for (cu, complexity) in analyzer.compute_cognitive_complexities(file) {
            if cu.is_synthetic() {
                continue;
            }
            if (complexity as i32) <= limit {
                continue;
            }
            if lines.len() > MAX_REPORT_LINES {
                truncated = true;
                report_full = true;
                break 'outer;
            }
            lines.line(format!("- {fq}: {complexity}", fq = cu.fq_name()));
            found_any = true;
        }
    }

    let report = if found_any {
        if report_full {
            lines.line(format!(
                "(report truncated at {MAX_REPORT_LINES} flagged functions)"
            ));
        }
        lines.build()
    } else {
        format!("No methods exceeded the cognitive complexity threshold of {limit}.")
    };
    ComputeCognitiveComplexityResult {
        report,
        truncated,
        ambiguous_paths,
    }
}

#[cfg(test)]
mod tests {
    use super::super::MAX_FILE_PATHS;
    use super::*;
    use crate::test_support::AnalyzerFixture;

    #[test]
    fn cognitive_simple_function_returns_empty_report() {
        let fix = AnalyzerFixture::new(&[("src/lib.rs", "fn trivial() -> i32 { 0 }\n")]);
        let result = compute_cognitive_complexity(
            fix.analyzer.analyzer(),
            ComputeCognitiveComplexityParams {
                file_paths: vec!["src/lib.rs".to_string()],
                threshold: 0,
            },
        );
        assert_eq!(
            result.report,
            "No methods exceeded the cognitive complexity threshold of 15."
        );
        assert!(!result.truncated);
    }

    #[test]
    fn cognitive_complex_function_is_flagged_without_source_suffix() {
        // Score above the explicit threshold of 1 — verifies the report
        // line uses `- fq: N` (no `(in src)` tail), matching brokk-core MCP.
        let src = "fn busy(x: i32) -> i32 {\n    \
            if x > 0 {\n        \
                if x > 1 { return 1; }\n    \
            }\n    \
            0\n}\n";
        let fix = AnalyzerFixture::new(&[("src/lib.rs", src)]);
        let result = compute_cognitive_complexity(
            fix.analyzer.analyzer(),
            ComputeCognitiveComplexityParams {
                file_paths: vec!["src/lib.rs".to_string()],
                threshold: 1,
            },
        );
        assert_eq!(
            result.report,
            "Cognitive complexity (threshold: 1):\n- busy: 3"
        );
        assert!(!result.truncated);
    }

    #[test]
    fn cognitive_threshold_zero_uses_default_of_fifteen() {
        let src = "fn small() {}\n";
        let fix = AnalyzerFixture::new(&[("src/lib.rs", src)]);
        let result = compute_cognitive_complexity(
            fix.analyzer.analyzer(),
            ComputeCognitiveComplexityParams {
                file_paths: vec!["src/lib.rs".to_string()],
                threshold: 0,
            },
        );
        assert!(
            result.report.contains("threshold of 15"),
            "expected default 15: {}",
            result.report
        );
    }

    #[test]
    fn cognitive_missing_files_silently_skipped() {
        let fix = AnalyzerFixture::new(&[("src/lib.rs", "fn x() {}\n")]);
        let result = compute_cognitive_complexity(
            fix.analyzer.analyzer(),
            ComputeCognitiveComplexityParams {
                file_paths: vec!["does/not/exist.rs".to_string()],
                threshold: 0,
            },
        );
        assert_eq!(
            result.report,
            "No methods exceeded the cognitive complexity threshold of 15."
        );
    }

    #[test]
    fn cognitive_absolute_paths_are_rejected_without_panic() {
        let fix = AnalyzerFixture::new(&[("src/lib.rs", "fn x() {}\n")]);
        let result = compute_cognitive_complexity(
            fix.analyzer.analyzer(),
            ComputeCognitiveComplexityParams {
                file_paths: vec!["/etc/passwd".to_string()],
                threshold: 0,
            },
        );
        assert_eq!(
            result.report,
            "No methods exceeded the cognitive complexity threshold of 15."
        );
    }

    #[test]
    fn cognitive_file_paths_above_cap_marks_truncated() {
        let fix = AnalyzerFixture::new(&[("src/lib.rs", "fn x() {}\n")]);
        let mut paths = vec!["src/lib.rs".to_string(); MAX_FILE_PATHS];
        paths.push("src/extra.rs".to_string());
        let result = compute_cognitive_complexity(
            fix.analyzer.analyzer(),
            ComputeCognitiveComplexityParams {
                file_paths: paths,
                threshold: 0,
            },
        );
        assert!(result.truncated);
    }

    #[test]
    fn cognitive_complexity_equal_to_threshold_is_not_flagged() {
        // 1 base `if` = 1; threshold 1 must NOT flag (uses `>`, not `>=`).
        let src = "fn small(x: i32) { if x > 0 {} }\n";
        let fix = AnalyzerFixture::new(&[("src/lib.rs", src)]);
        let result = compute_cognitive_complexity(
            fix.analyzer.analyzer(),
            ComputeCognitiveComplexityParams {
                file_paths: vec!["src/lib.rs".to_string()],
                threshold: 1,
            },
        );
        assert_eq!(
            result.report,
            "No methods exceeded the cognitive complexity threshold of 1."
        );
    }
}
