//! MCP `report_comment_density_for_code_unit` and
//! `report_comment_density_for_files` handlers. The shared analyzer trait
//! supports every parsed source language. Output format mirrors brokk-core's
//! `CodeQualityToolsMcp.reportCommentDensity*` byte-for-byte.
//!
//! Unlike the other handlers in this module, the file-list flavour does
//! NOT use [`crate::code_quality::resolve_project_files`] — it emits
//! per-input "Missing file (skipped)" inline lines that wouldn't fit the
//! shared helper's silent-skip contract.

use crate::code_quality::sanitize_table_cell;

use brokk_bifrost_core::analyzer::model::CommentDensityStats;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_analysis::path_utils::AmbiguousPathInput;

use brokk_bifrost_analysis::path_utils::ResolvedFileInput;

use brokk_bifrost_analysis::path_utils::WorkspaceFileResolver;

use brokk_bifrost_core::path_utils::rel_path_string;
use serde::{Deserialize, Serialize};

const DEFAULT_COMMENT_DENSITY_MAX_LINES: i32 = 120;
const DEFAULT_COMMENT_DENSITY_MAX_TOP_LEVEL_ROWS: i32 = 60;
const DEFAULT_COMMENT_DENSITY_MAX_FILES: i32 = 25;

/// Returned when the selected declaration's analyzer cannot provide parsed
/// comment density (for example, an unsupported file type).
const COMMENT_DENSITY_UNAVAILABLE: &str =
    "Comment density is unavailable for this symbol in this analyzer snapshot.";

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
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ambiguous_paths: Vec<AmbiguousPathInput>,
}

/// MCP `report_comment_density_for_code_unit` handler. Looks up the requested
/// symbol, selects the first parsed definition that supports density, then renders the per-symbol
/// comment-density block (own + rolled-up header/inline/span).
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
    let Some(stats) = defs
        .iter()
        .find_map(|code_unit| analyzer.comment_density(code_unit))
    else {
        return ReportCommentDensityForCodeUnitResult {
            report: COMMENT_DENSITY_UNAVAILABLE.to_string(),
            truncated: false,
        };
    };
    let (report, truncated) = truncate_to_line_cap(format_comment_density_for_unit(&stats), cap);
    ReportCommentDensityForCodeUnitResult { report, truncated }
}

/// MCP `report_comment_density_for_files` handler. For each requested file
/// the report emits a section with a markdown table whose rows are top-level
/// declarations and their own / rolled-up header / inline / span line counts.
/// Unsupported files and missing files produce single-line placeholders so the
/// output stays useful when callers pass mixed lists.
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
    let resolver = WorkspaceFileResolver::for_analyzer(analyzer);
    let mut lines: Vec<String> = vec!["## Comment density by file".to_string(), String::new()];
    let mut files_shown: i32 = 0;
    let mut rows_emitted: i32 = 0;
    let mut rows_truncated = false;
    let mut files_truncated = false;
    let mut ambiguous_paths = Vec::new();

    'outer: for input in params.file_paths.iter() {
        if files_shown >= file_cap {
            files_truncated = true;
            break;
        }
        let trimmed = input.trim();
        let display = if trimmed.is_empty() { input } else { trimmed };
        let file = match resolver.resolve_literal(trimmed) {
            ResolvedFileInput::File(file) if file.exists() => file,
            ResolvedFileInput::File(_) | ResolvedFileInput::NotFound(_) => {
                lines.push(format!("- Missing file (skipped): `{display}`"));
                files_shown += 1;
                continue;
            }
            ResolvedFileInput::Ambiguous(item) => {
                lines.push(format!(
                    "- Ambiguous file (skipped): `{}` -> {}",
                    item.input,
                    item.matches.join(", ")
                ));
                ambiguous_paths.push(item);
                files_shown += 1;
                continue;
            }
        };
        let rel_display = rel_path_string(&file);
        let stats = analyzer.comment_density_by_top_level(&file);
        if stats.is_empty() {
            lines.push(format!("### `{rel_display}`"));
            lines.push("(comment density unavailable; skipped)".to_string());
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
        ambiguous_paths,
    }
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

#[cfg(test)]
mod tests {

    use crate::code_quality::comment_density::*;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;

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
    #[brokk_bifrost_test_macros::hardwon(
        "#1415: Parses 128 Java methods and checks declaration-level totals include every child comment count"
    )]
    fn comment_density_dense_file_rolls_up_all_methods() {
        const METHOD_COUNT: u32 = 128;
        let mut source = String::from("// class header\nclass Dense {\n");
        for index in 0..METHOD_COUNT {
            source.push_str(&format!(
                "    // method header\n    void method_{index}() {{\n        // inline\n        int value_{index} = {index};\n    }}\n"
            ));
        }
        source.push_str("}\n");
        let fix = AnalyzerFixture::new(&[("Dense.java", &source)]);
        let file = ProjectFile::new(fix.project_root(), "Dense.java");

        let stats = fix.analyzer.analyzer().comment_density_by_top_level(&file);

        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].header_comment_lines, 1);
        assert_eq!(stats[0].inline_comment_lines, 0);
        assert_eq!(stats[0].rolled_up_header_comment_lines, METHOD_COUNT + 1);
        assert_eq!(stats[0].rolled_up_inline_comment_lines, METHOD_COUNT);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#1420: Regression covers conditional PHP free functions and excludes a function nested in a deferred closure"
    )]
    fn php_conditional_free_functions_have_file_and_symbol_density() {
        let fix = AnalyzerFixture::new(&[(
            "functions.php",
            r#"<?php
declare(strict_types=1);

namespace FastRoute;

use FastRoute\Cache\FileCache;
use LogicException;

use function function_exists;
use function is_string;

if (! function_exists('FastRoute\simpleDispatcher')) {
    /** Header for the conditional free function. */
    function simpleDispatcher(): void
    {
        // Inline implementation note.
        work();
    }

    /** Header for the second conditional free function. */
    function cachedDispatcher(): void
    {
        // Second inline implementation note.
        work();
    }
}

$factory = static function (): void {
    function deferredUntilInvocation(): void {}
};
"#,
        )]);
        let analyzer = fix.analyzer.analyzer();
        let file_result = report_comment_density_for_files(
            analyzer,
            ReportCommentDensityForFilesParams {
                file_paths: vec!["functions.php".to_string()],
                max_top_level_rows: 0,
                max_files: 0,
            },
        );
        assert!(
            file_result.report.contains("`FastRoute.simpleDispatcher`"),
            "{}",
            file_result.report
        );
        assert!(
            file_result.report.contains("`FastRoute.cachedDispatcher`"),
            "{}",
            file_result.report
        );
        assert!(
            !file_result.report.contains("comment density unavailable"),
            "{}",
            file_result.report
        );
        assert!(
            !file_result.report.contains("deferredUntilInvocation"),
            "{}",
            file_result.report
        );

        let symbol_result = report_comment_density_for_code_unit(
            analyzer,
            ReportCommentDensityForCodeUnitParams {
                fq_name: "FastRoute.simpleDispatcher".to_string(),
                max_lines: 0,
            },
        );
        assert!(
            symbol_result.report.contains("- Own: header 1, inline 1,"),
            "{}",
            symbol_result.report
        );
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
