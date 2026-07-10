//! MCP `compute_cyclomatic_complexity` handler. Flags any function whose
//! heuristic cyclomatic complexity (counts of `if`/`while`/`for`/`switch`/
//! `case`/`catch` keywords plus `&&`/`||`/`?` operators, plus a base of 1)
//! exceeds the supplied threshold. Output format mirrors brokk-core's
//! `CodeQualityToolsMcp.computeCyclomaticComplexity` byte-for-byte.

use super::{
    MAX_REPORT_LINES, ReportLines, append_ambiguous_path_notes, cyclomatic_complexity_for,
    resolve_project_files,
};
use crate::analyzer::{CodeUnit, IAnalyzer};
use crate::path_utils::{AmbiguousPathInput, rel_path_string};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

const DEFAULT_CYCLOMATIC_THRESHOLD: i32 = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeCyclomaticComplexityParams {
    pub file_paths: Vec<String>,
    #[serde(default)]
    pub threshold: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComputeCyclomaticComplexityResult {
    pub report: String,
    /// `true` when input or output was clipped: either more than
    /// `MAX_FILE_PATHS` paths were supplied, or the report hit
    /// `MAX_REPORT_LINES` flagged functions.
    pub truncated: bool,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ambiguous_paths: Vec<AmbiguousPathInput>,
}

pub fn compute_cyclomatic_complexity(
    analyzer: &dyn IAnalyzer,
    params: ComputeCyclomaticComplexityParams,
) -> ComputeCyclomaticComplexityResult {
    let limit = if params.threshold > 0 {
        params.threshold
    } else {
        DEFAULT_CYCLOMATIC_THRESHOLD
    };
    let resolved = resolve_project_files(analyzer.project(), params.file_paths);
    let mut truncated = resolved.input_truncated;
    let ambiguous_paths = resolved.ambiguous_paths.clone();

    let mut lines = ReportLines::new();
    lines.line(format!("Cyclomatic complexity (threshold: {limit}):"));
    append_ambiguous_path_notes(&mut lines, &ambiguous_paths);
    let mut found_any = false;
    let mut report_full = false;

    'outer: for file in &resolved.files {
        // Iterative DFS over the code-unit tree to avoid unbounded
        // recursion on pathological inputs (deeply nested generated code,
        // for example).
        let mut work: VecDeque<CodeUnit> = analyzer.top_level_declarations(file).into();
        while let Some(cu) = work.pop_front() {
            if cu.is_function() {
                let complexity = cyclomatic_complexity_for(analyzer, &cu) as i32;
                if complexity > limit {
                    // `lines` always carries the leading header, so the
                    // count of flagged functions equals `lines.len() - 1`.
                    if lines.len() > MAX_REPORT_LINES {
                        truncated = true;
                        report_full = true;
                        break 'outer;
                    }
                    lines.line(format!(
                        "- {fq}: {complexity} (in {src})",
                        fq = cu.fq_name(),
                        src = rel_path_string(cu.source()),
                    ));
                    found_any = true;
                }
            }
            for child in analyzer.direct_children(&cu) {
                work.push_back(child);
            }
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
        format!("No methods exceeded the complexity threshold of {limit}.")
    };
    ComputeCyclomaticComplexityResult {
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
    fn simple_function_under_threshold_returns_empty_report() {
        let fix = AnalyzerFixture::new(&[("src/lib.rs", "fn trivial() -> i32 { 0 }\n")]);
        let result = compute_cyclomatic_complexity(
            fix.analyzer.analyzer(),
            ComputeCyclomaticComplexityParams {
                file_paths: vec!["src/lib.rs".to_string()],
                threshold: 0,
            },
        );
        assert_eq!(
            result.report,
            "No methods exceeded the complexity threshold of 10."
        );
        assert!(!result.truncated);
    }

    #[test]
    fn function_above_threshold_is_flagged() {
        let body = format!(
            "fn busy(x: i32) -> i32 {{\n{}    0\n}}\n",
            "    if x > 0 {}\n".repeat(11)
        );
        let fix = AnalyzerFixture::new(&[("src/lib.rs", body.as_str())]);
        let result = compute_cyclomatic_complexity(
            fix.analyzer.analyzer(),
            ComputeCyclomaticComplexityParams {
                file_paths: vec!["src/lib.rs".to_string()],
                threshold: 0,
            },
        );
        assert_eq!(
            result.report,
            "Cyclomatic complexity (threshold: 10):\n- busy: 12 (in src/lib.rs)"
        );
        assert!(!result.truncated);
    }

    #[test]
    fn explicit_threshold_overrides_default() {
        // 1 base + 1 `if` = 2; threshold 1 should flag.
        let fix = AnalyzerFixture::new(&[("src/lib.rs", "fn small(x: i32) { if x > 0 {} }\n")]);
        let result = compute_cyclomatic_complexity(
            fix.analyzer.analyzer(),
            ComputeCyclomaticComplexityParams {
                file_paths: vec!["src/lib.rs".to_string()],
                threshold: 1,
            },
        );
        assert_eq!(
            result.report,
            "Cyclomatic complexity (threshold: 1):\n- small: 2 (in src/lib.rs)"
        );
    }

    #[test]
    fn complexity_equal_to_threshold_is_not_flagged() {
        // 1 base + 1 `if` = 2; threshold 2 must NOT flag (uses `>` not `>=`).
        let fix = AnalyzerFixture::new(&[("src/lib.rs", "fn small(x: i32) { if x > 0 {} }\n")]);
        let result = compute_cyclomatic_complexity(
            fix.analyzer.analyzer(),
            ComputeCyclomaticComplexityParams {
                file_paths: vec!["src/lib.rs".to_string()],
                threshold: 2,
            },
        );
        assert_eq!(
            result.report,
            "No methods exceeded the complexity threshold of 2."
        );
    }

    #[test]
    fn logical_operators_count_toward_complexity() {
        // 1 base + 1 `if` + 2 `&&` + 1 `||` + 1 `?` = 6; threshold 5 flags.
        let fix = AnalyzerFixture::new(&[(
            "src/lib.rs",
            "fn ops(a: bool, b: bool, c: bool) -> Option<bool> {\n    \
             let _q = Some(a)?;\n    \
             if a && b && c || a { Some(true) } else { Some(false) }\n}\n",
        )]);
        let result = compute_cyclomatic_complexity(
            fix.analyzer.analyzer(),
            ComputeCyclomaticComplexityParams {
                file_paths: vec!["src/lib.rs".to_string()],
                threshold: 5,
            },
        );
        assert_eq!(
            result.report,
            "Cyclomatic complexity (threshold: 5):\n- ops: 6 (in src/lib.rs)"
        );
    }

    #[test]
    fn iterates_into_nested_methods() {
        let fix = AnalyzerFixture::new(&[(
            "src/lib.rs",
            "struct S;\nimpl S {\n    fn m(&self, x: i32) {\n        if x > 0 { if x > 1 {} }\n    }\n}\n",
        )]);
        let result = compute_cyclomatic_complexity(
            fix.analyzer.analyzer(),
            ComputeCyclomaticComplexityParams {
                file_paths: vec!["src/lib.rs".to_string()],
                threshold: 2,
            },
        );
        assert!(result.report.contains("S.m: 3"));
    }

    #[test]
    fn missing_files_are_silently_skipped() {
        let fix = AnalyzerFixture::new(&[("src/lib.rs", "fn x() {}\n")]);
        let result = compute_cyclomatic_complexity(
            fix.analyzer.analyzer(),
            ComputeCyclomaticComplexityParams {
                file_paths: vec!["does/not/exist.rs".to_string()],
                threshold: 0,
            },
        );
        assert_eq!(
            result.report,
            "No methods exceeded the complexity threshold of 10."
        );
    }

    #[test]
    fn absolute_paths_are_rejected_without_panic() {
        let fix = AnalyzerFixture::new(&[("src/lib.rs", "fn x() {}\n")]);
        let result = compute_cyclomatic_complexity(
            fix.analyzer.analyzer(),
            ComputeCyclomaticComplexityParams {
                file_paths: vec!["/etc/passwd".to_string()],
                threshold: 0,
            },
        );
        assert_eq!(
            result.report,
            "No methods exceeded the complexity threshold of 10."
        );
    }

    #[test]
    fn non_function_code_units_are_ignored() {
        let fix = AnalyzerFixture::new(&[("src/lib.rs", "struct S;\n")]);
        let result = compute_cyclomatic_complexity(
            fix.analyzer.analyzer(),
            ComputeCyclomaticComplexityParams {
                file_paths: vec!["src/lib.rs".to_string()],
                threshold: 0,
            },
        );
        assert_eq!(
            result.report,
            "No methods exceeded the complexity threshold of 10."
        );
    }

    #[test]
    fn empty_file_paths_returns_empty_report() {
        let fix = AnalyzerFixture::new(&[("src/lib.rs", "fn x() {}\n")]);
        let result = compute_cyclomatic_complexity(
            fix.analyzer.analyzer(),
            ComputeCyclomaticComplexityParams {
                file_paths: vec![],
                threshold: 0,
            },
        );
        assert_eq!(
            result.report,
            "No methods exceeded the complexity threshold of 10."
        );
        assert!(!result.truncated);
    }

    #[test]
    fn multiple_files_share_one_header() {
        let fix = AnalyzerFixture::new(&[
            ("src/a.rs", "fn alpha(x: i32) { if x > 0 {} }\n"),
            ("src/b.rs", "fn beta() {}\n"),
        ]);
        let result = compute_cyclomatic_complexity(
            fix.analyzer.analyzer(),
            ComputeCyclomaticComplexityParams {
                file_paths: vec!["src/a.rs".to_string(), "src/b.rs".to_string()],
                threshold: 1,
            },
        );
        assert_eq!(
            result.report,
            "Cyclomatic complexity (threshold: 1):\n- a.alpha: 2 (in src/a.rs)"
        );
    }

    #[test]
    fn file_paths_above_cap_marks_truncated() {
        let fix = AnalyzerFixture::new(&[("src/lib.rs", "fn x() {}\n")]);
        let mut paths = vec!["src/lib.rs".to_string(); MAX_FILE_PATHS];
        paths.push("src/extra.rs".to_string());
        let result = compute_cyclomatic_complexity(
            fix.analyzer.analyzer(),
            ComputeCyclomaticComplexityParams {
                file_paths: paths,
                threshold: 0,
            },
        );
        assert!(result.truncated);
    }

    #[test]
    fn oversize_source_falls_back_to_base_complexity() {
        // Build a function whose body is well over MAX_SOURCE_BYTES; the
        // heuristic should bail and report base complexity 1.
        let body = format!(
            "fn huge() -> i32 {{\n{}    0\n}}\n",
            "    if true {}\n".repeat(200_000)
        );
        let fix = AnalyzerFixture::new(&[("src/lib.rs", body.as_str())]);
        let analyzer = fix.analyzer.analyzer();
        let huge = analyzer
            .get_all_declarations()
            .into_iter()
            .find(|cu| cu.is_function() && cu.identifier() == "huge")
            .expect("huge fn declared");
        assert_eq!(cyclomatic_complexity_for(analyzer, &huge), 1);
    }
}
