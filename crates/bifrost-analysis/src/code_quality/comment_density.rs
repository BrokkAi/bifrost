//! MCP `report_comment_density_for_code_unit` and
//! `report_comment_density_for_files` handlers. The shared analyzer trait
//! supports every parsed source language. Output format mirrors brokk-core's
//! `CodeQualityToolsMcp.reportCommentDensity*` byte-for-byte.
//!
//! Unlike the other handlers in this module, the file-list flavour does
//! NOT use [`crate::code_quality::resolve_project_files`] — it emits
//! per-input "Missing file (skipped)" inline lines that wouldn't fit the
//! shared helper's silent-skip contract.

use super::sanitize_table_cell;
use crate::analyzer::{CommentDensityStats, IAnalyzer};
use crate::path_utils::{
    AmbiguousPathInput, ResolvedFileInput, WorkspaceFileResolver, rel_path_string,
};
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
    use super::*;
    use crate::analyzer::{Language, ProjectFile};
    use crate::test_support::AnalyzerFixture;

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
    fn comment_density_for_files_unsupported_file_emits_skip_block() {
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
        assert!(
            result
                .report
                .contains("(comment density unavailable; skipped)")
        );
    }

    #[test]
    fn comment_density_supports_every_parsed_language_for_files_and_symbols() {
        let files = [
            (
                "JavaTop.java",
                "// header\nclass JavaTop {\n    void method() {\n        // inline\n        int value = 1;\n    }\n}\n",
            ),
            (
                "go_top.go",
                "// header\ntype GoTop struct {\n    Value int // inline\n}\n",
            ),
            (
                "cpp_top.cpp",
                "// header\nclass CppTop {\n    int method() {\n        // inline\n        return 1;\n    }\n};\n",
            ),
            (
                "javascript_top.js",
                "// header\nclass JavaScriptTop {\n    method() {\n        // inline\n        return 1;\n    }\n}\n",
            ),
            (
                "typescript_top.ts",
                "// header\nclass TypeScriptTop {\n    method(): number {\n        // inline\n        return 1;\n    }\n}\n",
            ),
            (
                "tsx_top.tsx",
                "// header\nclass TsxTop {\n    render() {\n        return <div>{/* inline */}</div>;\n    }\n}\n",
            ),
            (
                "python_top.py",
                "# header\nclass PythonTop:\n    def method(self):\n        # inline\n        return 1\n",
            ),
            (
                "rust_top.rs",
                "// header\nstruct RustTop {\n    value: i32, // inline\n}\n",
            ),
            (
                "php_top.php",
                "<?php\n// header\nclass PhpTop {\n    public int $value; // inline\n}\n",
            ),
            (
                "scala_top.scala",
                "// header\nclass ScalaTop {\n    def method: Int = {\n        // inline\n        1\n    }\n}\n",
            ),
            (
                "csharp_top.cs",
                "// header\nclass CSharpTop {\n    int Method() {\n        // inline\n        return 1;\n    }\n}\n",
            ),
            (
                "ruby_top.rb",
                "# header\nclass RubyTop\n  def method\n    # inline\n    1\n  end\nend\n",
            ),
            (
                "kotlin_top.kt",
                "// header\nclass KotlinTop {\n    fun method(): Int {\n        // inline\n        return 1\n    }\n}\n",
            ),
        ];
        let fixture_files: Vec<(&str, &str)> = files
            .iter()
            .map(|(path, source)| (*path, *source))
            .collect();
        let fix = AnalyzerFixture::new(&fixture_files);
        let analyzer = fix.analyzer.analyzer();
        assert_eq!(
            analyzer.languages(),
            Language::ANALYZABLE.into_iter().collect(),
            "fixture must cover every parsed language"
        );
        let result = report_comment_density_for_files(
            analyzer,
            ReportCommentDensityForFilesParams {
                file_paths: files.iter().map(|(path, _)| (*path).to_string()).collect(),
                max_top_level_rows: 0,
                max_files: 0,
            },
        );

        for (path, _) in files {
            assert!(
                result.report.contains(&format!("### `{path}`")),
                "{path}: {}",
                result.report
            );
            let file = ProjectFile::new(fix.project_root(), path);
            let declaration = analyzer
                .top_level_declarations(&file)
                .into_iter()
                .find(|unit| !unit.is_module() && !unit.is_synthetic())
                .unwrap_or_else(|| panic!("expected a top-level declaration in {path}"));
            let symbol_result = report_comment_density_for_code_unit(
                analyzer,
                ReportCommentDensityForCodeUnitParams {
                    fq_name: declaration.fq_name(),
                    max_lines: 0,
                },
            );
            assert!(
                symbol_result.report.starts_with("## Comment density"),
                "{path}: {}",
                symbol_result.report
            );
            assert!(
                symbol_result
                    .report
                    .contains(&format!("- Symbol: `{}`", declaration.fq_name())),
                "{path}: {}",
                symbol_result.report
            );
            assert!(
                symbol_result.report.contains("- Own: header 1,"),
                "{path}: {}",
                symbol_result.report
            );
            if matches!(
                path,
                "javascript_top.js" | "typescript_top.ts" | "tsx_top.tsx"
            ) {
                assert!(
                    symbol_result.report.contains("inline 1"),
                    "{path}: {}",
                    symbol_result.report
                );
            }
        }
        assert!(
            !result.report.contains("comment density unavailable"),
            "{}",
            result.report
        );
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
