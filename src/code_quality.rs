use crate::analyzer::{CodeUnit, CommentDensityStats, IAnalyzer, Language};
use crate::path_utils::{rel_path_string, workspace_rel_path};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::LazyLock;

const DEFAULT_CYCLOMATIC_THRESHOLD: i32 = 10;
const DEFAULT_COGNITIVE_THRESHOLD: i32 = 15;
const DEFAULT_COMMENT_DENSITY_MAX_LINES: i32 = 120;
const DEFAULT_COMMENT_DENSITY_MAX_TOP_LEVEL_ROWS: i32 = 60;
const DEFAULT_COMMENT_DENSITY_MAX_FILES: i32 = 25;

/// Sentinel returned by brokk-core MCP when comment density isn't available
/// for the requested symbol or file. Bifrost mirrors the wording exactly so
/// callers comparing reports across servers see identical bytes.
const COMMENT_DENSITY_JAVA_ONLY: &str =
    "Comment density is only available for Java symbols in this analyzer snapshot.";

// Bound MCP-supplied path lists so a single call cannot allocate an
// unbounded `Vec<String>` of report lines or pin the analyzer scanning
// thousands of files. Mirrors the per-tool caps already used in
// `file_tools.rs` / `git_tools.rs`.
const MAX_FILE_PATHS: usize = 200;

// Hard cap on report lines (one line per flagged function). Protects the
// JSON-RPC transport from megabyte-scale responses on pathological input.
const MAX_REPORT_LINES: usize = 500;

// Per-function source-text size cap before the regex scan. Beyond this,
// the function's complexity defaults to the base of 1 — treating an
// unanalyzably large body as opaque rather than spinning the regex engine
// over multiple megabytes per code unit.
const MAX_SOURCE_BYTES: usize = 1_000_000;

// Heuristic cyclomatic-complexity decision points. Mirrors brokk-shared
// `IAnalyzer.COMPLEXITY_KEYWORDS` / `COMPLEXITY_OPERATORS` exactly so the
// scores produced here match the brokk-core MCP byte-for-byte.
static COMPLEXITY_KEYWORDS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(if|while|for|switch|case|catch)\b").expect("valid regex"));
static COMPLEXITY_OPERATORS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"&&|\|\||\?").expect("valid regex"));

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
}

/// Heuristic cyclomatic complexity for a single function-like code unit.
/// Returns 0 for non-function units. Counts a base of 1 plus each
/// occurrence of `if/while/for/switch/case/catch` keywords and each
/// `&&`/`||`/`?` operator in the unit's source. Source bodies above
/// `MAX_SOURCE_BYTES` are treated as opaque (returns the base of 1).
pub fn cyclomatic_complexity_for(analyzer: &dyn IAnalyzer, code_unit: &CodeUnit) -> u32 {
    if !code_unit.is_function() {
        return 0;
    }
    let source = analyzer.get_source(code_unit, false).unwrap_or_default();
    if source.len() > MAX_SOURCE_BYTES {
        return 1;
    }
    let mut complexity: u32 = 1;
    complexity += COMPLEXITY_KEYWORDS.find_iter(&source).count() as u32;
    complexity += COMPLEXITY_OPERATORS.find_iter(&source).count() as u32;
    complexity
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
    let project = analyzer.project();
    let mut lines: Vec<String> = vec![format!("Cyclomatic complexity (threshold: {limit}):")];
    let mut found_any = false;
    let mut truncated = params.file_paths.len() > MAX_FILE_PATHS;
    let mut report_full = false;

    'outer: for input in params.file_paths.into_iter().take(MAX_FILE_PATHS) {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some(rel) = workspace_rel_path(trimmed) else {
            continue;
        };
        let Some(file) = project.file_by_rel_path(&rel) else {
            continue;
        };

        // Iterative DFS over the code-unit tree to avoid unbounded
        // recursion on pathological inputs (deeply nested generated code,
        // for example).
        let mut work: VecDeque<CodeUnit> = analyzer.get_top_level_declarations(&file).into();
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
                    lines.push(format!(
                        "- {fq}: {complexity} (in {src})",
                        fq = cu.fq_name(),
                        src = rel_path_string(cu.source()),
                    ));
                    found_any = true;
                }
            }
            for child in analyzer.get_direct_children(&cu) {
                work.push_back(child);
            }
        }
    }

    let report = if found_any {
        if report_full {
            lines.push(format!(
                "(report truncated at {MAX_REPORT_LINES} flagged functions)"
            ));
        }
        lines.join("\n")
    } else {
        format!("No methods exceeded the complexity threshold of {limit}.")
    };
    ComputeCyclomaticComplexityResult { report, truncated }
}

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
}

/// MCP `compute_cognitive_complexity` handler. Computes a heuristic cognitive
/// complexity per function in each requested file using the analyzer's
/// per-language tree-sitter scorer and flags functions whose score exceeds
/// `threshold`.
///
/// The output format mirrors brokk-core's `CodeQualityToolsMcp
/// .computeCognitiveComplexity` byte-for-byte (`- <fqName>: <complexity>`,
/// no source-path suffix) so the bifrost MCP can be substituted for the
/// brokk-core MCP without callers noticing.
pub fn compute_cognitive_complexity(
    analyzer: &dyn IAnalyzer,
    params: ComputeCognitiveComplexityParams,
) -> ComputeCognitiveComplexityResult {
    let limit = if params.threshold > 0 {
        params.threshold
    } else {
        DEFAULT_COGNITIVE_THRESHOLD
    };
    let project = analyzer.project();
    let mut lines: Vec<String> = vec![format!("Cognitive complexity (threshold: {limit}):")];
    let mut found_any = false;
    let mut truncated = params.file_paths.len() > MAX_FILE_PATHS;
    let mut report_full = false;

    'outer: for input in params.file_paths.into_iter().take(MAX_FILE_PATHS) {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some(rel) = workspace_rel_path(trimmed) else {
            continue;
        };
        let Some(file) = project.file_by_rel_path(&rel) else {
            continue;
        };

        for (cu, complexity) in analyzer.compute_cognitive_complexities(&file) {
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
            lines.push(format!("- {fq}: {complexity}", fq = cu.fq_name()));
            found_any = true;
        }
    }

    let report = if found_any {
        if report_full {
            lines.push(format!(
                "(report truncated at {MAX_REPORT_LINES} flagged functions)"
            ));
        }
        lines.join("\n")
    } else {
        format!("No methods exceeded the cognitive complexity threshold of {limit}.")
    };
    ComputeCognitiveComplexityResult { report, truncated }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportCommentDensityForCodeUnitParams {
    pub fq_name: String,
    #[serde(default)]
    pub max_lines: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportCommentDensityForCodeUnitResult {
    pub report: String,
    /// `true` when the markdown report was clipped to `max_lines` rendered lines.
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportCommentDensityForFilesParams {
    pub file_paths: Vec<String>,
    #[serde(default)]
    pub max_top_level_rows: i32,
    #[serde(default)]
    pub max_files: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportCommentDensityForFilesResult {
    pub report: String,
    /// `true` when either the declaration-rows table or the file list was
    /// clipped against its respective cap. The trailing markdown footer
    /// already reports the exact counts, so this flag is for callers that
    /// short-circuit on any truncation.
    pub truncated: bool,
}

/// MCP `report_comment_density_for_code_unit` handler. Looks up the requested
/// symbol, prefers a Java-extension definition, then renders the per-symbol
/// comment-density block (own + rolled-up header/inline/span). Behaviour and
/// output format mirror brokk-core `CodeQualityToolsMcp
/// .reportCommentDensityForCodeUnit` so the two MCP servers are
/// interchangeable for callers.
pub fn report_comment_density_for_code_unit(
    analyzer: &dyn IAnalyzer,
    params: ReportCommentDensityForCodeUnitParams,
) -> ReportCommentDensityForCodeUnitResult {
    let key = params.fq_name.trim();
    if key.is_empty() {
        return ReportCommentDensityForCodeUnitResult {
            report: "Missing fqName.".to_string(),
            truncated: false,
        };
    }
    let cap = if params.max_lines > 0 {
        params.max_lines
    } else {
        DEFAULT_COMMENT_DENSITY_MAX_LINES
    };
    let defs = analyzer.get_definitions(key);
    if defs.is_empty() {
        return ReportCommentDensityForCodeUnitResult {
            report: format!("No definition found for: {key}"),
            truncated: false,
        };
    }
    let cu = defs
        .iter()
        .find(|d| code_unit_extension(d) == Some("java".to_string()))
        .cloned()
        .unwrap_or_else(|| defs[0].clone());
    let Some(stats) = analyzer.comment_density(&cu) else {
        return ReportCommentDensityForCodeUnitResult {
            report: COMMENT_DENSITY_JAVA_ONLY.to_string(),
            truncated: false,
        };
    };
    let (report, truncated) = truncate_to_line_cap(format_comment_density_for_unit(&stats), cap);
    ReportCommentDensityForCodeUnitResult { report, truncated }
}

/// MCP `report_comment_density_for_files` handler. For each requested file
/// the report emits a section with a markdown table whose rows are top-level
/// declarations and their own / rolled-up header / inline / span line counts.
/// Non-Java files and missing files produce single-line placeholders so the
/// output stays useful when callers pass mixed lists. Mirrors
/// brokk-core `CodeQualityToolsMcp.reportCommentDensityForFiles`
/// byte-for-byte.
pub fn report_comment_density_for_files(
    analyzer: &dyn IAnalyzer,
    params: ReportCommentDensityForFilesParams,
) -> ReportCommentDensityForFilesResult {
    let row_cap = if params.max_top_level_rows > 0 {
        params.max_top_level_rows
    } else {
        DEFAULT_COMMENT_DENSITY_MAX_TOP_LEVEL_ROWS
    };
    let file_cap = if params.max_files > 0 {
        params.max_files
    } else {
        DEFAULT_COMMENT_DENSITY_MAX_FILES
    };
    let project = analyzer.project();
    let mut lines: Vec<String> = vec!["## Comment density by file".to_string(), String::new()];
    let mut files_shown: i32 = 0;
    let mut rows_emitted: i32 = 0;
    let mut rows_truncated = false;
    let mut files_truncated = false;

    'outer: for input in params.file_paths.iter() {
        if files_shown >= file_cap {
            files_truncated = true;
            break;
        }
        let trimmed = input.trim();
        let display = if trimmed.is_empty() { input } else { trimmed };
        let Some(rel) = workspace_rel_path(trimmed) else {
            lines.push(format!("- Missing file (skipped): `{display}`"));
            files_shown += 1;
            continue;
        };
        let Some(file) = project.file_by_rel_path(&rel) else {
            lines.push(format!("- Missing file (skipped): `{display}`"));
            files_shown += 1;
            continue;
        };
        if !file.exists() {
            lines.push(format!("- Missing file (skipped): `{display}`"));
            files_shown += 1;
            continue;
        }
        let rel_display = rel_path_string(&file);
        let is_java = file
            .rel_path()
            .extension()
            .and_then(|ext| ext.to_str())
            .map(Language::from_extension)
            == Some(Language::Java);
        if !is_java {
            lines.push(format!("### `{rel_display}`"));
            lines.push("(not a Java file; skipped)".to_string());
            lines.push(String::new());
            files_shown += 1;
            continue;
        }
        let stats = analyzer.comment_density_by_top_level(&file);
        if stats.is_empty() {
            lines.push(format!("### `{rel_display}`"));
            lines.push(COMMENT_DENSITY_JAVA_ONLY.to_string());
            lines.push(String::new());
            files_shown += 1;
            continue;
        }
        files_shown += 1;
        lines.push(format!("### `{rel_display}`"));
        lines.push("| Declaration | Hdr | Inl | Span | Roll H | Roll I | Roll S |".to_string());
        lines.push("|-------------|-----|-----|------|--------|--------|--------|".to_string());
        for s in &stats {
            if rows_emitted >= row_cap {
                rows_truncated = true;
                break 'outer;
            }
            lines.push(format!(
                "| `{name}` | {h} | {i} | {sp} | {rh} | {ri} | {rs} |",
                name = sanitize_table_cell(&s.fq_name),
                h = s.header_comment_lines,
                i = s.inline_comment_lines,
                sp = s.span_lines,
                rh = s.rolled_up_header_comment_lines,
                ri = s.rolled_up_inline_comment_lines,
                rs = s.rolled_up_span_lines,
            ));
            rows_emitted += 1;
        }
        lines.push(String::new());
    }

    lines.push(String::new());
    lines.push(format!(
        "- Files shown: {files_shown} (cap {file_cap}{suffix})",
        suffix = if files_truncated {
            ", list truncated"
        } else {
            ""
        }
    ));
    lines.push(format!(
        "- Declaration rows: {rows_emitted} (cap {row_cap}{suffix})",
        suffix = if rows_truncated {
            ", table truncated"
        } else {
            ""
        }
    ));
    if rows_truncated || files_truncated {
        lines.push("- Note: narrow the path list or increase caps to see more.".to_string());
    }

    ReportCommentDensityForFilesResult {
        report: lines.join("\n"),
        truncated: rows_truncated || files_truncated,
    }
}

fn code_unit_extension(cu: &CodeUnit) -> Option<String> {
    cu.source()
        .rel_path()
        .extension()
        .and_then(|ext| ext.to_str())
        .map(str::to_string)
}

fn format_comment_density_for_unit(s: &CommentDensityStats) -> String {
    let mut lines: Vec<String> = Vec::with_capacity(6);
    lines.push("## Comment density".to_string());
    lines.push(String::new());
    lines.push(format!("- Symbol: `{}`", s.fq_name));
    lines.push(format!("- File: `{}`", s.relative_path));
    lines.push(format!(
        "- Own: header {}, inline {}, span {}",
        s.header_comment_lines, s.inline_comment_lines, s.span_lines
    ));
    lines.push(format!(
        "- Rolled-up: header {}, inline {}, span {}",
        s.rolled_up_header_comment_lines, s.rolled_up_inline_comment_lines, s.rolled_up_span_lines
    ));
    lines.join("\n")
}

fn truncate_to_line_cap(text: String, max_lines: i32) -> (String, bool) {
    if max_lines <= 0 {
        return (text, false);
    }
    let cap = max_lines as usize;
    let line_count = text.lines().count();
    if line_count <= cap {
        return (text, false);
    }
    let kept: Vec<&str> = text.lines().take(cap).collect();
    let omitted = line_count - cap;
    let truncated_text = format!("{}\n\n... ({omitted} more lines omitted)", kept.join("\n"));
    (truncated_text, true)
}

/// Defensive replacement of markdown-breaking characters in table cells.
/// Mirrors brokk's [`CodeQualityToolsMcp.sanitizeTableCell`]: pipe characters
/// are escaped, backticks become apostrophes (so attacker-controlled paths
/// cannot break out of the inline code span and inject markdown into
/// downstream LLM consumers), and control characters collapse to a single
/// space so each row remains valid GFM.
fn sanitize_table_cell(value: &str) -> String {
    let escaped = value.replace('|', "\\|").replace('`', "'");
    escaped
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
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

    // -- compute_cognitive_complexity --

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

    // -------- report_comment_density_for_code_unit / forFiles --------

    const SAMPLE_JAVA: &str = "package com.example;\n\
                              \n\
                              /** Header doc for Foo. */\n\
                              public class Foo {\n\
                              \n\
                              \x20   // header for bar\n\
                              \x20   public void bar() {\n\
                              \x20       // inline comment\n\
                              \x20       int x = 1;\n\
                              \x20   }\n\
                              \n\
                              \x20   public void baz() {\n\
                              \x20       int y = 2;\n\
                              \x20   }\n\
                              }\n";

    #[test]
    fn comment_density_for_code_unit_blank_fq_name_returns_missing() {
        let fix = AnalyzerFixture::new(&[("Foo.java", SAMPLE_JAVA)]);
        let result = report_comment_density_for_code_unit(
            fix.analyzer.analyzer(),
            ReportCommentDensityForCodeUnitParams {
                fq_name: "   ".to_string(),
                max_lines: 0,
            },
        );
        assert_eq!(result.report, "Missing fqName.");
        assert!(!result.truncated);
    }

    #[test]
    fn comment_density_for_code_unit_unknown_symbol_returns_message() {
        let fix = AnalyzerFixture::new(&[("Foo.java", SAMPLE_JAVA)]);
        let result = report_comment_density_for_code_unit(
            fix.analyzer.analyzer(),
            ReportCommentDensityForCodeUnitParams {
                fq_name: "com.example.Nope".to_string(),
                max_lines: 0,
            },
        );
        assert_eq!(result.report, "No definition found for: com.example.Nope");
    }

    #[test]
    fn comment_density_for_code_unit_non_java_returns_java_only_sentinel() {
        let fix = AnalyzerFixture::new(&[("src/lib.rs", "fn trivial() -> i32 { 0 }\n")]);
        let result = report_comment_density_for_code_unit(
            fix.analyzer.analyzer(),
            ReportCommentDensityForCodeUnitParams {
                fq_name: "trivial".to_string(),
                max_lines: 0,
            },
        );
        assert_eq!(result.report, COMMENT_DENSITY_JAVA_ONLY);
    }

    #[test]
    fn comment_density_for_code_unit_reports_class_with_rollup() {
        let fix = AnalyzerFixture::new(&[("Foo.java", SAMPLE_JAVA)]);
        let result = report_comment_density_for_code_unit(
            fix.analyzer.analyzer(),
            ReportCommentDensityForCodeUnitParams {
                fq_name: "com.example.Foo".to_string(),
                max_lines: 0,
            },
        );
        assert!(
            result.report.starts_with("## Comment density"),
            "report: {}",
            result.report
        );
        assert!(result.report.contains("- Symbol: `com.example.Foo`"));
        assert!(result.report.contains("- File: `Foo.java`"));
        // Class own header is 1 (the JavaDoc above `class Foo`), inline 0.
        assert!(result.report.contains("- Own: header 1, inline 0,"));
        // Rolled-up adds bar()'s own header (1) and inline (1).
        assert!(
            result.report.contains("- Rolled-up: header 2, inline 1,"),
            "report: {}",
            result.report
        );
        assert!(!result.truncated);
    }

    #[test]
    fn comment_density_for_code_unit_truncates_to_max_lines() {
        let fix = AnalyzerFixture::new(&[("Foo.java", SAMPLE_JAVA)]);
        let result = report_comment_density_for_code_unit(
            fix.analyzer.analyzer(),
            ReportCommentDensityForCodeUnitParams {
                fq_name: "com.example.Foo".to_string(),
                max_lines: 2,
            },
        );
        assert!(result.truncated);
        assert!(result.report.contains("more lines omitted"));
    }

    #[test]
    fn comment_density_for_files_renders_table_and_footer() {
        let fix = AnalyzerFixture::new(&[("Foo.java", SAMPLE_JAVA)]);
        let result = report_comment_density_for_files(
            fix.analyzer.analyzer(),
            ReportCommentDensityForFilesParams {
                file_paths: vec!["Foo.java".to_string()],
                max_top_level_rows: 0,
                max_files: 0,
            },
        );
        assert!(result.report.starts_with("## Comment density by file"));
        assert!(result.report.contains("### `Foo.java`"));
        assert!(
            result
                .report
                .contains("| Declaration | Hdr | Inl | Span | Roll H | Roll I | Roll S |"),
        );
        assert!(result.report.contains("| `com.example.Foo` |"));
        assert!(result.report.contains("- Files shown: 1 (cap 25)"));
        assert!(result.report.contains("- Declaration rows: 1 (cap 60)"));
        assert!(!result.truncated);
    }

    #[test]
    fn comment_density_for_files_missing_file_emits_skipped_line() {
        let fix = AnalyzerFixture::new(&[("Foo.java", SAMPLE_JAVA)]);
        let result = report_comment_density_for_files(
            fix.analyzer.analyzer(),
            ReportCommentDensityForFilesParams {
                file_paths: vec!["does/not/exist.java".to_string()],
                max_top_level_rows: 0,
                max_files: 0,
            },
        );
        assert!(
            result
                .report
                .contains("- Missing file (skipped): `does/not/exist.java`"),
            "report: {}",
            result.report
        );
        assert!(result.report.contains("- Files shown: 1 (cap 25)"));
    }

    #[test]
    fn comment_density_for_files_non_java_file_emits_skip_block() {
        let fix = AnalyzerFixture::new(&[("Foo.java", SAMPLE_JAVA), ("notes.txt", "hello\n")]);
        let result = report_comment_density_for_files(
            fix.analyzer.analyzer(),
            ReportCommentDensityForFilesParams {
                file_paths: vec!["notes.txt".to_string()],
                max_top_level_rows: 0,
                max_files: 0,
            },
        );
        assert!(result.report.contains("### `notes.txt`"));
        assert!(result.report.contains("(not a Java file; skipped)"));
    }

    #[test]
    fn comment_density_for_files_file_cap_truncates_list() {
        let fix = AnalyzerFixture::new(&[
            ("A.java", SAMPLE_JAVA.replace("Foo", "A").as_str()),
            ("B.java", SAMPLE_JAVA.replace("Foo", "B").as_str()),
        ]);
        let result = report_comment_density_for_files(
            fix.analyzer.analyzer(),
            ReportCommentDensityForFilesParams {
                file_paths: vec!["A.java".to_string(), "B.java".to_string()],
                max_top_level_rows: 0,
                max_files: 1,
            },
        );
        assert!(result.truncated);
        assert!(
            result
                .report
                .contains("- Files shown: 1 (cap 1, list truncated)")
        );
        assert!(
            result
                .report
                .contains("- Note: narrow the path list or increase caps to see more.")
        );
    }

    #[test]
    fn comment_density_for_files_row_cap_truncates_table() {
        let fix = AnalyzerFixture::new(&[("Foo.java", SAMPLE_JAVA)]);
        let result = report_comment_density_for_files(
            fix.analyzer.analyzer(),
            ReportCommentDensityForFilesParams {
                file_paths: vec!["Foo.java".to_string()],
                max_top_level_rows: 0,
                max_files: 0,
            },
        );
        // Sanity: one top-level declaration emits exactly one row.
        let row_count = result
            .report
            .lines()
            .filter(|l| l.starts_with("| `com.example.Foo`"))
            .count();
        assert_eq!(row_count, 1);
    }
}
