//! Read-only inventory of callable declaration sites from an analyzer generation.

use brokk_bifrost_analysis::analyzer::i_analyzer::{AnalyzerQueryScope, IAnalyzer};
use brokk_bifrost_core::analyzer::model::{CodeUnit, Language, ProjectFile};
use brokk_bifrost_core::analyzer::test_paths;
use brokk_bifrost_core::analyzer::tree_walk::expanded_comment_start;
use brokk_bifrost_core::path_utils;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListFunctionSourcesParams {
    pub paths: Option<Vec<String>>,
    #[serde(default = "include_tests_default")]
    pub include_tests: bool,
}

impl Default for ListFunctionSourcesParams {
    fn default() -> Self {
        Self {
            paths: None,
            include_tests: true,
        }
    }
}

const fn include_tests_default() -> bool {
    true
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct FunctionSource {
    pub declaration_id: String,
    pub site_id: String,
    pub fq_name: String,
    pub name: String,
    pub kind: String,
    pub signature: String,
    pub language: String,
    pub rel_path: String,
    pub blob_oid: String,
    /// Declaration coordinates, before attached-comment expansion (one-based lines).
    pub start_line: usize,
    pub end_line: usize,
    pub start_byte: usize,
    pub end_byte: usize,
    pub is_test: bool,
    /// Exact indexed text, extended backwards to attached comments.
    pub source: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SkippedFunctionSourceFile {
    pub rel_path: String,
    pub reason: String,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct FunctionSourcesSummary {
    /// Files contributing at least one record.
    pub file_count: usize,
    pub record_count: usize,
    pub skipped_files: Vec<SkippedFunctionSourceFile>,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct ListFunctionSourcesResult {
    pub summary: FunctionSourcesSummary,
    pub records: Vec<FunctionSource>,
}

/// Inventory one analyzer generation. All grouping and output live only for this query;
/// each file's indexed source is fetched once and dropped after its records are built.
pub fn list_function_sources(
    analyzer: &dyn IAnalyzer,
    params: ListFunctionSourcesParams,
) -> ListFunctionSourcesResult {
    let _scope = AnalyzerQueryScope::new(analyzer);
    let paths = params
        .paths
        .map(|paths| paths.into_iter().collect::<HashSet<_>>());
    let mut by_file: HashMap<ProjectFile, Vec<(CodeUnit, bool)>> = HashMap::new();
    for unit in analyzer.all_declarations() {
        if unit.is_synthetic() || !unit.is_function() {
            continue;
        }
        let file = unit.source();
        let rel_path = path_utils::rel_path_string(file);
        if paths
            .as_ref()
            .is_some_and(|paths| !paths.contains(&rel_path))
        {
            continue;
        }
        let language = Language::from_path(file.rel_path());
        let is_test =
            analyzer.in_test_region(&unit) || test_paths::is_test_like_path(&rel_path, language);
        if is_test && !params.include_tests {
            continue;
        }
        by_file
            .entry(file.clone())
            .or_default()
            .push((unit, is_test));
    }
    let mut files: Vec<_> = by_file.into_iter().collect();
    files.sort_by(|(left, _), (right, _)| left.rel_path().cmp(right.rel_path()));
    let mut result = ListFunctionSourcesResult::default();
    for (file, units) in files {
        let rel_path = path_utils::rel_path_string(&file);
        let Some(text) = analyzer.indexed_source(&file) else {
            result
                .summary
                .skipped_files
                .push(SkippedFunctionSourceFile {
                    rel_path,
                    reason: "no indexed source".into(),
                });
            continue;
        };
        let Some(oid) = analyzer.indexed_blob_oid(&file) else {
            result
                .summary
                .skipped_files
                .push(SkippedFunctionSourceFile {
                    rel_path,
                    reason: "no blob OID".into(),
                });
            continue;
        };
        let before = result.records.len();
        let language = Language::from_path(file.rel_path());
        for (unit, is_test) in units {
            let signature = analyzer
                .signatures(&unit)
                .first()
                .map(ToString::to_string)
                .or_else(|| unit.signature().map(str::to_owned))
                .unwrap_or_default();
            for range in analyzer.ranges(&unit) {
                let comment_start = expanded_comment_start(language, &text, range.start_byte);
                let source = text
                    .get(comment_start..range.end_byte)
                    .expect("declaration range must address indexed source")
                    .to_owned();
                result.records.push(FunctionSource {
                    declaration_id: unit.declaration_id().as_str().to_owned(),
                    site_id: unit
                        .declaration_site_id(range.start_byte, range.end_byte)
                        .as_str()
                        .to_owned(),
                    fq_name: unit.fq_name(),
                    name: unit.identifier().to_owned(),
                    kind: unit.kind().display_lowercase().to_owned(),
                    signature: signature.clone(),
                    language: format!("{language:?}").to_lowercase(),
                    rel_path: rel_path.clone(),
                    blob_oid: oid.to_string(),
                    start_line: range.start_line,
                    end_line: range.end_line,
                    start_byte: range.start_byte,
                    end_byte: range.end_byte,
                    is_test,
                    source,
                });
            }
        }
        if result.records.len() > before {
            result.summary.file_count += 1;
        }
    }
    result.records.sort_by(|left, right| {
        (
            &left.rel_path,
            left.start_byte,
            left.end_byte,
            &left.site_id,
        )
            .cmp(&(
                &right.rel_path,
                right.start_byte,
                right.end_byte,
                &right.site_id,
            ))
    });
    result.summary.record_count = result.records.len();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_analysis::{AnalyzerConfig, inline_project::InlineTestProject};
    use git2::{ObjectType, Oid};

    #[test]
    fn inventory_uses_every_indexed_range_and_raw_blob_identity() {
        let java = "class Methods {\n    /// Integer overload.\n    int run(int x) { return x; }\n    int run(String x) { return x.length(); }\n}\n";
        let rust = "struct Worker;\nimpl Worker { fn first() {} fn second() {} }\n/// Outer docs.\npub fn outer() { fn inner() {} inner(); }\n#[cfg(test)]\nmod tests { #[test] fn inline_test() {} }\n";
        let project = InlineTestProject::new()
            .file("Methods.java", java)
            .file("src/lib.rs", rust)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let analyzer = workspace.analyzer();
        // Mutating disk after indexing must change neither the text nor its identity.
        project
            .file("Methods.java")
            .write("class Changed {}\n")
            .unwrap();
        let result = list_function_sources(analyzer, ListFunctionSourcesParams::default());
        let expected_ranges: usize = analyzer
            .all_declarations()
            .filter(|unit| !unit.is_synthetic() && unit.is_function())
            .map(|unit| analyzer.ranges(&unit).len())
            .sum();
        assert_eq!(result.records.len(), expected_ranges);
        assert_eq!(result.summary.file_count, 2);
        // Rust block-local functions have native facts but no CodeUnit projection.
        // The public declaration inventory contains the outer function, the
        // inline test, two methods and the two Java overloads.
        assert_eq!(result.summary.record_count, 6, "{result:?}");
        assert!(result.summary.skipped_files.is_empty());
        let overloads: Vec<_> = result
            .records
            .iter()
            .filter(|record| record.name == "run")
            .collect();
        assert_eq!(overloads.len(), 2);
        assert_ne!(overloads[0].site_id, overloads[1].site_id);
        assert!(
            result
                .records
                .iter()
                .any(|record| record.name == "inline_test" && record.is_test)
        );
        for record in &result.records {
            let original = if record.rel_path == "Methods.java" {
                java
            } else {
                rust
            };
            assert_eq!(
                record.blob_oid,
                Oid::hash_object(ObjectType::Blob, original.as_bytes())
                    .unwrap()
                    .to_string()
            );
            let expanded = expanded_comment_start(
                Language::from_path(std::path::Path::new(&record.rel_path)),
                original,
                record.start_byte,
            );
            assert_eq!(record.source, original[expanded..record.end_byte]);
        }
        assert_eq!(
            overloads[0].source,
            "    /// Integer overload.\n    int run(int x) { return x; }"
        );
        assert_eq!(
            result
                .records
                .iter()
                .find(|record| record.name == "outer")
                .unwrap()
                .source,
            "/// Outer docs.\npub fn outer() { fn inner() {} inner(); }"
        );
        let filtered = list_function_sources(
            analyzer,
            ListFunctionSourcesParams {
                paths: Some(vec!["src/lib.rs".into()]),
                include_tests: false,
            },
        );
        assert_eq!(filtered.summary.record_count, 3);
        assert!(
            filtered
                .records
                .iter()
                .all(|record| !record.is_test && record.rel_path == "src/lib.rs")
        );
        assert!(
            list_function_sources(
                analyzer,
                ListFunctionSourcesParams {
                    paths: Some(Vec::new()),
                    include_tests: true,
                }
            )
            .records
            .is_empty()
        );
        assert!(
            serde_json::from_str::<ListFunctionSourcesParams>("{}")
                .unwrap()
                .include_tests
        );
    }
    #[test]
    fn inventory_preserves_multiple_ranges_of_one_callable() {
        let source = "void run();\nvoid run() {}\n";
        let project = InlineTestProject::new().file("methods.cpp", source).build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let result =
            list_function_sources(workspace.analyzer(), ListFunctionSourcesParams::default());
        assert_eq!(result.records.len(), 2, "{result:?}");
        assert_eq!(
            result.records[0].declaration_id,
            result.records[1].declaration_id
        );
        assert_ne!(result.records[0].site_id, result.records[1].site_id);
        assert_eq!(result.records[0].source, "void run();");
        assert_eq!(result.records[1].source, "void run() {}");
    }
}
