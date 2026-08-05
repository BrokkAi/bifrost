//! Function extraction and canonical embedding-document rendering.
//!
//! Each function is embedded once with a SweRank-shaped path header. Methods
//! include their nearest structurally enclosing class; free functions do not.
//! The literal `class` marker is part of the measured document contract even
//! when the source language calls the enclosing type a struct, trait, or enum.

use brokk_bifrost_analysis::analyzer::{
    AnalyzerStreamingFileScope, CodeUnit, IAnalyzer, ProjectFile,
};
use brokk_bifrost_analysis::path_utils::rel_path_string;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionChunk {
    pub ord: i64,
    pub symbol: String,
    pub function_name: String,
    pub enclosing_class: Option<String>,
    pub start_line: Option<i64>,
    pub end_line: Option<i64>,
    pub source_text: String,
}

impl FunctionChunk {
    /// Build the exact document sent to the passage embedder. This text is
    /// deliberately ephemeral: callers hash/embed it but never persist it.
    pub fn embedding_document(&self, file_path: &str) -> String {
        embedding_document(
            file_path,
            &self.function_name,
            self.enclosing_class.as_deref(),
            &self.source_text,
        )
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileChunks {
    pub file_path: String,
    pub chunks: Vec<FunctionChunk>,
}

/// Canonical SweRank document representation used by every embedding profile.
pub fn embedding_document(
    file_path: &str,
    function_name: &str,
    enclosing_class: Option<&str>,
    source_text: &str,
) -> String {
    match enclosing_class {
        Some(class_name) => {
            format!("{file_path}/{class_name}/{function_name}\nclass {class_name}:{source_text}")
        }
        None => format!("{file_path}/{function_name}\n{source_text}"),
    }
}

/// Extract every named function from `file` in source order.
pub fn extract_file_chunks(analyzer: &dyn IAnalyzer, file: &ProjectFile) -> FileChunks {
    let _streaming_scope = AnalyzerStreamingFileScope::new(analyzer, file);
    let file_path = rel_path_string(file);
    let _scope =
        brokk_bifrost_analysis::profiling::scope(format!("nlp::extract_file_chunks[{file_path}]"));

    // (unit, nearest enclosing class) work stack. Function source already
    // contains local declarations, so functions do not extend the traversal.
    let mut stack: Vec<(CodeUnit, Option<CodeUnit>)> = {
        let _scope =
            brokk_bifrost_analysis::profiling::scope("nlp::extract_file_chunks::top_level");
        analyzer
            .top_level_declarations(file)
            .into_iter()
            .map(|unit| (unit, None))
            .collect()
    };
    let mut functions: Vec<(CodeUnit, Option<CodeUnit>)> = Vec::new();
    {
        let _scope = brokk_bifrost_analysis::profiling::scope("nlp::extract_file_chunks::walk");
        while let Some((unit, enclosing_class)) = stack.pop() {
            if unit.is_anonymous() {
                continue;
            }
            if unit.is_function() {
                functions.push((unit, enclosing_class));
                continue;
            }
            if unit.is_class() || unit.is_module() {
                let next_enclosing = if unit.is_class() {
                    Some(unit.clone())
                } else {
                    enclosing_class.clone()
                };
                for child in analyzer.direct_children_in_file(&unit) {
                    debug_assert_eq!(child.source(), file);
                    stack.push((child, next_enclosing.clone()));
                }
            }
        }
    }
    functions.sort_by_key(|(unit, _)| {
        analyzer
            .ranges(unit)
            .first()
            .map(|range| range.start_line)
            .unwrap_or(usize::MAX)
    });

    let _scope = brokk_bifrost_analysis::profiling::scope("nlp::extract_file_chunks::emit");
    let chunks = functions
        .into_iter()
        .filter_map(|(unit, enclosing_class)| {
            let source_text = normalize_line_endings(analyzer.get_source(&unit, true)?);
            if source_text.trim().is_empty() {
                return None;
            }
            let range = analyzer.ranges(&unit).first().cloned();
            Some((
                unit,
                enclosing_class.map(|class| class.identifier().to_string()),
                source_text,
                range,
            ))
        })
        .enumerate()
        .map(
            |(ord, (unit, enclosing_class, source_text, range))| FunctionChunk {
                ord: ord as i64,
                symbol: unit.fq_name(),
                function_name: unit.identifier().to_string(),
                enclosing_class,
                start_line: range.as_ref().map(|range| range.start_line as i64),
                end_line: range.as_ref().map(|range| range.end_line as i64),
                source_text,
            },
        )
        .collect();

    FileChunks { file_path, chunks }
}

fn normalize_line_endings(source: String) -> String {
    if !source.as_bytes().contains(&b'\r') {
        return source;
    }
    source.replace("\r\n", "\n").replace('\r', "\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_analysis::analyzer::{CppAnalyzer, JavaAnalyzer, Language, TestProject};

    fn fixture_analyzer() -> (tempfile::TempDir, JavaAnalyzer) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = ProjectFile::new(root.clone(), std::path::PathBuf::from("A.java"));
        file.write(
            r#"public class A {
    void method1() {}

    public String method2(String input) {
        return input;
    }

    public String method2(String input, int otherInput) {
        return input + otherInput;
    }
}
"#,
        )
        .unwrap();
        let analyzer = JavaAnalyzer::from_project(TestProject::new(root, Language::Java));
        (temp, analyzer)
    }

    fn chunks_for(analyzer: &dyn IAnalyzer, name: &str) -> FileChunks {
        let file = analyzer
            .analyzed_files()
            .into_iter()
            .find(|file| rel_path_string(file) == name)
            .unwrap_or_else(|| panic!("fixture file {name} not analyzed"));
        extract_file_chunks(analyzer, &file)
    }

    #[test]
    fn canonical_documents_match_swerank_exactly() {
        assert_eq!(
            embedding_document("pkg/mod.py", "do_work", None, "def do_work():\n    pass"),
            "pkg/mod.py/do_work\ndef do_work():\n    pass"
        );
        assert_eq!(
            embedding_document(
                "pkg/mod.py",
                "do_work",
                Some("Worker"),
                "    def do_work(self):\n        pass",
            ),
            "pkg/mod.py/Worker/do_work\nclass Worker:    def do_work(self):\n        pass"
        );
    }

    #[test]
    fn semantic_source_uses_one_line_ending_form() {
        let lf = "fn run() {\n    work();\n}\n".to_string();
        assert_eq!(normalize_line_endings(lf.clone()), lf);
        assert_eq!(
            normalize_line_endings("fn run() {\r\n    work();\r}\r\n".to_string()),
            "fn run() {\n    work();\n}\n"
        );
    }

    #[test]
    fn extracts_only_ordered_functions_with_structured_class_names() {
        let (_temp, analyzer) = fixture_analyzer();
        analyzer.reset_package_declaration_scan_count_for_test();
        let result = chunks_for(&analyzer, "A.java");
        assert_eq!(analyzer.package_declaration_scan_count_for_test(), 0);
        assert_eq!(result.chunks.len(), 3);
        assert!(
            result
                .chunks
                .iter()
                .all(|chunk| chunk.enclosing_class.as_deref() == Some("A"))
        );
        assert!(
            result
                .chunks
                .iter()
                .all(|chunk| chunk.symbol.starts_with("A.method"))
        );

        let lines: Vec<i64> = result
            .chunks
            .iter()
            .filter_map(|chunk| chunk.start_line)
            .collect();
        let mut sorted = lines.clone();
        sorted.sort_unstable();
        assert_eq!(lines, sorted);
    }

    #[test]
    fn streaming_extraction_does_not_fill_the_interactive_file_state_cache() {
        let (_temp, analyzer) = fixture_analyzer();
        let file = analyzer
            .analyzed_files()
            .into_iter()
            .find(|file| rel_path_string(file) == "A.java")
            .expect("A.java analyzed");
        analyzer.reset_candidate_hydration_count_for_test();

        let extracted = extract_file_chunks(&analyzer, &file);
        assert!(!extracted.chunks.is_empty());
        assert_eq!(analyzer.candidate_hydration_count_for_test(), 1);

        assert!(!analyzer.top_level_declarations(&file).is_empty());
        assert_eq!(analyzer.candidate_hydration_count_for_test(), 2);
    }

    #[test]
    fn streaming_cpp_extraction_reuses_file_state_for_definition_ranges() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = ProjectFile::new(root.clone(), "worker.h");
        file.write(
            "void run(int value) {\n    value += 1;\n}\n\nvoid run(double value) {\n    value += 2.0;\n}\n",
        )
        .unwrap();
        let analyzer = CppAnalyzer::from_project(TestProject::new(root, Language::Cpp));
        let top_level = analyzer.top_level_declarations(&file);
        assert!(!top_level.is_empty());
        assert!(top_level.iter().any(CodeUnit::is_function));
        analyzer.reset_enclosing_parent_query_counts_for_test();

        let extracted = extract_file_chunks(&analyzer, &file);

        assert_eq!(extracted.chunks.len(), 2);
        assert!(extracted.chunks.iter().all(|chunk| {
            chunk.source_text.contains("value += 1") && chunk.source_text.contains("value += 2.0")
        }));
        assert_eq!(analyzer.sql_definitions_query_count_for_test(), 0);
    }

    #[test]
    fn function_chunk_excludes_file_license_header() {
        use brokk_bifrost_analysis::analyzer::TypescriptAnalyzer;

        let source = "\
/**
 * Copyright (c) 2017-present, Facebook, Inc.
 */

export function loadRoutes(routes: number): number {
  return routes + 1;
}
";
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = ProjectFile::new(root.clone(), std::path::PathBuf::from("routes.ts"));
        file.write(source).unwrap();
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));

        let result = extract_file_chunks(&analyzer, &file);
        let function = result.chunks.first().expect("loadRoutes chunk");
        assert!(!function.source_text.contains("Copyright"));
        assert!(
            function
                .source_text
                .trim_start()
                .starts_with("export function loadRoutes")
        );
        assert_eq!(function.start_line, Some(5));
    }
}
