//! Read-only inventory of callable declaration sites from an analyzer generation.

use brokk_bifrost_analysis::analyzer::i_analyzer::{
    AnalyzerQueryScope, IAnalyzer, QueryReadIncomplete,
};
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
    /// Null when the test classification was unavailable; a request that
    /// excludes tests then reports the reason as incompleteness (#11385).
    pub is_test: Option<bool>,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub incomplete: Vec<crate::result_incomplete::ToolResultIncomplete>,

    pub summary: FunctionSourcesSummary,
    pub records: Vec<FunctionSource>,
}

/// Inventory one analyzer generation. All grouping and output live only for this query;
/// each file's indexed source is fetched once and dropped after its records are built.
pub fn list_function_sources(
    analyzer: &dyn IAnalyzer,
    params: ListFunctionSourcesParams,
) -> ListFunctionSourcesResult {
    list_function_sources_with_selection(analyzer, params, |paths| match paths {
        // The workspace inventory has no typed answer on master yet; #12226
        // slice 3 replaces this arm with `all_declarations_answer()`.
        None => brokk_bifrost_core::analyzer::query_read_incomplete::LookupOutcome::Found(
            analyzer.all_declarations().collect(),
        ),
        Some(paths) => {
            let mut files = paths
                .iter()
                .filter_map(|path| {
                    if std::path::Path::new(path).is_absolute() {
                        return None;
                    }
                    let file = ProjectFile::new(analyzer.project().root(), path);
                    (path_utils::rel_path_string(&file) == *path).then_some(file)
                })
                .collect::<Vec<_>>();
            // `paths` is a hash set; a fixed order names the same failing file every run.
            files.sort();
            let languages = analyzer.languages();
            files.retain(|file| {
                if languages.contains(&Language::from_path(file.rel_path()))
                    || (!languages.is_empty() && analyzer.owns_source_file(file))
                {
                    return true;
                }
                // An added file can introduce a language for which the selected
                // generation has no delegate yet. Preserve adopted include-file
                // ownership without starting another analyzer or scanning disk.
                analyzer.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceGap(
                    format!(
                        "requested path `{}` has no selected source analyzer; it is not indexed in this generation",
                        path_utils::rel_path_string(file),
                    )
                    .into(),
                ));
                false
            });
            analyzer.declarations_for_files_answer(&files)
        }
    })
}

fn list_function_sources_with_selection(
    analyzer: &dyn IAnalyzer,
    params: ListFunctionSourcesParams,
    select: impl FnOnce(
        &Option<HashSet<String>>,
    ) -> brokk_bifrost_core::analyzer::query_read_incomplete::LookupOutcome<
        Vec<CodeUnit>,
    >,
) -> ListFunctionSourcesResult {
    let scope = if params.paths.is_some() {
        AnalyzerQueryScope::capturing_read_incompleteness(analyzer)
    } else {
        AnalyzerQueryScope::new(analyzer)
    };
    let paths = params
        .paths
        .map(|paths| paths.into_iter().collect::<HashSet<_>>());
    // A mixed path batch must name every unindexed path even when a different
    // source gap was observed first. Whole-workspace requests retain their
    // existing first-reason result and do not capture every workspace gap.
    let incomplete = || {
        if paths.is_some() {
            scope
                .captured_read_incompleteness()
                .into_iter()
                .map(crate::result_incomplete::ToolResultIncomplete::from)
                .collect()
        } else {
            crate::result_incomplete::query_read_incomplete(&scope)
        }
    };
    let mut by_file: HashMap<ProjectFile, Vec<(CodeUnit, Option<bool>)>> = HashMap::new();
    let answer = select(&paths);
    let units = match answer.into_inventory_result() {
        Ok(units) => units,
        Err(reason) => {
            analyzer.record_query_incomplete(reason);
            return ListFunctionSourcesResult {
                incomplete: incomplete(),
                ..ListFunctionSourcesResult::default()
            };
        }
    };
    for unit in units {
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
        // An unclassified function is kept with an unknown status: it belongs
        // to the inventory either way. Only a request that excludes tests
        // depends on the verdict, so only that one is incomplete.
        let is_test = if test_paths::is_test_like_path(&rel_path, language) {
            Some(true)
        } else {
            match analyzer.in_test_region(&unit) {
                Ok(value) => Some(value),
                Err(reason) => {
                    if !params.include_tests {
                        analyzer.record_query_incomplete(reason);
                    }
                    None
                }
            }
        };
        if is_test == Some(true) && !params.include_tests {
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
    result.incomplete = incomplete();
    result.summary.record_count = result.records.len();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_analysis::{AnalyzerConfig, inline_project::InlineTestProject};
    use git2::{ObjectType, Oid};

    /// Master's workspace inventory, captured as a typed answer.
    fn full_inventory(
        analyzer: &dyn IAnalyzer,
    ) -> brokk_bifrost_core::analyzer::query_read_incomplete::LookupOutcome<Vec<CodeUnit>> {
        brokk_bifrost_analysis::analyzer::i_analyzer::capture_lookup_answer(analyzer, || {
            brokk_bifrost_core::analyzer::query_read_incomplete::LookupOutcome::Found(
                analyzer.all_declarations().collect(),
            )
        })
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13007: listing one file's function sources enumerated every workspace declaration"
    )]
    fn one_file_listing_through_multi_analyzer_reads_only_that_file() {
        use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
        use brokk_bifrost_rust_analysis::analyzer::rust::RustAnalyzer;
        let mut hydrated = Vec::new();
        for unrelated in [1, 32] {
            let mut builder = InlineTestProject::new()
                .file(
                    "Cargo.toml",
                    "[package]\nname = \"probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
                )
                .file(
                    "src/lib.rs",
                    "pub fn target() {}\npub fn helper() -> u32 { 1 }\n",
                )
                .file("tool.py", "def tool():\n    pass\n")
                .file("Model.java", "class Model { void work() {} }\n");
            for n in 0..unrelated {
                builder = builder.file(
                    format!("src/bin/other{n}.rs"),
                    format!("pub fn unrelated{n}() {{}}\nfn main() {{ unrelated{n}(); }}\n"),
                );
            }
            let project = builder.build();
            let workspace = project.workspace_analyzer(AnalyzerConfig::default());
            // The MCP tool calls list_function_sources on this same analyzer.
            let analyzer = workspace.analyzer();
            let WorkspaceAnalyzer::Multi(multi) = &workspace else {
                panic!("multi-language workspace expected");
            };
            assert!(
                [Language::Rust, Language::Python, Language::Java]
                    .iter()
                    .all(|language| multi.delegates().contains_key(language)),
                "{:?}",
                multi.delegates().keys().collect::<Vec<_>>()
            );
            let rust = multi.delegates()[&Language::Rust].analyzer();
            let rust = (rust as &dyn std::any::Any)
                .downcast_ref::<RustAnalyzer>()
                .expect("Rust delegate");
            let store = &rust.inner.store_context.store;
            analyzer
                .test_hooks()
                .reset_full_declaration_scan_count_for_test();
            store.take_mounted_declarations_hydrated_for_test();
            let result = list_function_sources(
                analyzer,
                ListFunctionSourcesParams {
                    paths: Some(vec!["src/lib.rs".into()]),
                    include_tests: true,
                },
            );
            assert!(result.incomplete.is_empty(), "{result:?}");
            let mut names = result
                .records
                .iter()
                .map(|record| record.name.as_str())
                .collect::<Vec<_>>();
            names.sort();
            assert_eq!(names, ["helper", "target"]);
            // The CodeUnitIndex default filters all_declarations(), which runs the
            // full mounted-declaration scan of every delegate it reaches.
            assert_eq!(
                analyzer.test_hooks().full_declaration_scan_count_for_test(),
                0,
                "a delegate fell back to the all_declarations filter"
            );
            hydrated.push(store.take_mounted_declarations_hydrated_for_test());
        }
        // Per-file SQL ran, and it hydrated only the requested file's rows.
        assert!(hydrated[0] > 0, "{hydrated:?}");
        assert!(hydrated[0] <= 2, "{hydrated:?}");
        assert_eq!(hydrated[0], hydrated[1], "{hydrated:?}");
    }

    #[cfg(unix)]
    #[test]
    fn direct_declarations_reject_absolute_rendered_identity() {
        use brokk_bifrost_analysis::{CodeUnitIndex, TreeSitterAnalyzer};
        use brokk_bifrost_python_analysis::analyzer::python::adapter::PythonAdapter;

        let project = InlineTestProject::new()
            .file(r"\evil.py", "def broken():\n    pass\n")
            .file("healthy.py", "def healthy():\n    pass\n")
            .build();
        let analyzer = TreeSitterAnalyzer::new(project.project_dyn(), PythonAdapter::default());
        let broken = analyzer
            .declarations_for_files_answer(&[project.file(r"\evil.py")])
            .into_inventory_result();
        assert!(broken.is_err(), "{broken:?}");
        let healthy = analyzer
            .declarations_for_files_answer(&[project.file("healthy.py")])
            .into_inventory_result()
            .unwrap();
        let functions = healthy
            .iter()
            .filter(|unit| unit.is_function())
            .collect::<Vec<_>>();
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].identifier(), "healthy");
    }

    #[cfg(unix)]
    #[test]
    fn colliding_indexed_identities_are_incomplete() {
        use brokk_bifrost_analysis::analyzer::store::liveness::{LivePathEntry, LivePathMap};
        use brokk_bifrost_analysis::{CodeUnitIndex, TreeSitterAnalyzer};
        use brokk_bifrost_js_ts_analysis::analyzer::javascript::JavascriptAdapter;
        let project = InlineTestProject::new()
            .file("src/api.js", "function work() {}\n")
            .file("healthy.js", "function healthy() {}\n")
            .build();
        let mut analyzer = TreeSitterAnalyzer::new(project.project_dyn(), JavascriptAdapter);
        // Real coexisting spellings panic during publication (workspace paths
        // are unique). Reproduce the collapsed store key with both captured
        // indexed identities, without repairing that preexisting producer bug.
        let map = LivePathMap::trust_filesystem_generation();
        map.replace_all(analyzer.indexed_live_snapshot.all_paths().map(|file| {
            LivePathEntry::filesystem(
                file.clone(),
                analyzer.indexed_live_snapshot.oid_for_path(file).unwrap(),
            )
        }));
        let alias = project.file("src\\api.js");
        alias.write("function work() {}\n").unwrap();
        map.refresh([LivePathEntry::filesystem(
            alias,
            analyzer
                .indexed_blob_oid(&project.file("src/api.js"))
                .unwrap(),
        )]);
        analyzer.indexed_live_snapshot = map.snapshot();
        for (path, complete) in [("src/api.js", false), ("healthy.js", true)] {
            let result = list_function_sources(
                &analyzer,
                ListFunctionSourcesParams {
                    paths: Some(vec![path.into()]),
                    include_tests: true,
                },
            );
            assert_eq!(result.incomplete.is_empty(), complete, "{result:?}");
            if complete {
                assert_eq!(result.records.len(), 1);
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn rendered_path_corruption_is_scoped_to_requested_key() {
        use std::os::unix::ffi::OsStringExt;
        for (name, requested, coexist) in [
            (std::ffi::OsString::from("src\\api.py"), "src/api.py", false),
            (std::ffi::OsString::from("src\\api.js"), "src/api.js", false),
            (
                std::ffi::OsString::from_vec(b"api\xff.js".to_vec()),
                "api\u{fffd}.js",
                false,
            ),
        ] {
            if name.to_str().is_none() {
                let probe = tempfile::tempdir().unwrap();
                match std::fs::write(probe.path().join(&name), "") {
                    Ok(()) => {}
                    // APFS refuses non-UTF-8 names with EILSEQ (#14088); the
                    // literal-backslash cases still run on such filesystems.
                    Err(error) if error.raw_os_error() == Some(libc::EILSEQ) => continue,
                    Err(error) => panic!("{name:?}: {error:?}"),
                }
            }
            let healthy_path = if requested.ends_with(".py") {
                "healthy.py"
            } else {
                "healthy.js"
            };
            let healthy_source = if requested.ends_with(".py") {
                "def healthy():\n    pass\n"
            } else {
                "function healthy() {}\n"
            };
            let mut fixture = InlineTestProject::new()
                .file(
                    std::path::PathBuf::from(name),
                    if requested.ends_with(".py") {
                        "def broken():\n    pass\n"
                    } else {
                        "function broken() {}\n"
                    },
                )
                .file(healthy_path, healthy_source);
            if coexist {
                fixture = fixture.file(
                    requested,
                    if requested.ends_with(".py") {
                        "def slash():\n    pass\n"
                    } else {
                        "function slash() {}\n"
                    },
                );
            }
            let project = fixture.build();
            let workspace = project.workspace_analyzer(AnalyzerConfig::default());
            let analyzer = workspace.analyzer();
            let result = list_function_sources(
                analyzer,
                ListFunctionSourcesParams {
                    paths: Some(vec![requested.into()]),
                    include_tests: true,
                },
            );
            assert!(!result.incomplete.is_empty(), "{requested}: {result:?}");
            let healthy = list_function_sources(
                analyzer,
                ListFunctionSourcesParams {
                    paths: Some(vec![healthy_path.into()]),
                    include_tests: true,
                },
            );
            assert!(healthy.incomplete.is_empty(), "{healthy:?}");
            assert_eq!(healthy.records.len(), 1);
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13007: a path-filtered function-source request scanned every declaration"
    )]
    fn filtered_inventory_is_byte_identical_to_full_scan_filter() {
        let project = InlineTestProject::new()
            .file("src/lib.rs", "/// API docs.\npub fn run() { fn nested() {} nested(); }\n#[cfg(test)] mod tests { #[test] fn check() {} }\n")
            .file("Model.java", "class Model { int run(int x) { return x; } int run(String x) { return 0; } }\n")
            .file("pkg/__init__.py", "")
            .file("pkg/api.py", "def run():\n    def nested():\n        pass\n    nested()\n")
            .file("src/module.ts", "import { value } from './provider'; export function run(): number { return value; }\n")
            .file("src/provider.ts", "export const value = 1;\n")
            .file("common.h", "struct Outer { struct Inner { int value; } member; };\nvoid run();\n")
            .file("one.c", "#include \"common.h\"\nvoid run() {}\n")
            .file("two.cpp", "#include \"common.h\"\nvoid other() {}\n")
            .file("methods.cpp", "void work();\nvoid work() {}\n")
            .file("tests/helper.py", "def test_helper():\n    pass\n")
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let analyzer = workspace.analyzer();
        project
            .file("Model.java")
            .write("class Changed {}\n")
            .unwrap();
        let absolute = project
            .file("pkg/api.py")
            .abs_path()
            .to_string_lossy()
            .into_owned();
        for include_tests in [true, false] {
            for paths in [
                None,
                Some(vec![]),
                Some(vec!["pkg/api.py"]),
                Some(vec!["common.h", "one.c", "two.cpp"]),
                Some(vec![
                    "src/lib.rs",
                    "src/lib.rs",
                    "Model.java",
                    "methods.cpp",
                    "src/module.ts",
                    "tests/helper.py",
                ]),
                Some(vec![
                    "./pkg/api.py",
                    "pkg/../pkg/api.py",
                    "src\\lib.rs",
                    absolute.as_str(),
                ]),
                Some(vec!["methods.cpp", "src/lib.rs", "pkg/api.py"]),
                Some(vec!["pkg/api.py", "src/lib.rs", "methods.cpp"]),
            ] {
                let params = || ListFunctionSourcesParams {
                    paths: paths
                        .as_ref()
                        .map(|paths| paths.iter().map(|path| (*path).to_owned()).collect()),
                    include_tests,
                };
                let reference = list_function_sources_with_selection(analyzer, params(), |_| {
                    full_inventory(analyzer)
                });
                let actual = list_function_sources(analyzer, params());
                assert_eq!(
                    serde_json::to_vec(&reference).unwrap(),
                    serde_json::to_vec(&actual).unwrap(),
                    "paths={paths:?}, include_tests={include_tests}: {actual:?}"
                );
            }
            // #13977: an unindexed selector has a typed gap instead of the
            // full-scan filter's clean empty answer. Keep the healthy file.
            let healthy = list_function_sources(
                analyzer,
                ListFunctionSourcesParams {
                    paths: Some(vec!["pkg/api.py".into()]),
                    include_tests,
                },
            );
            assert!(!healthy.records.is_empty(), "{healthy:?}");
            let partial = list_function_sources(
                analyzer,
                ListFunctionSourcesParams {
                    paths: Some(vec![
                        "pkg/api.py".into(),
                        "missing.py".into(),
                        "missing.cpp".into(),
                    ]),
                    include_tests,
                },
            );
            assert_eq!(
                serde_json::to_value(&partial.records).unwrap(),
                serde_json::to_value(&healthy.records).unwrap(),
                "{partial:?}"
            );
            assert_eq!(partial.incomplete.len(), 2, "{partial:?}");
            for path in ["missing.py", "missing.cpp"] {
                assert!(partial.incomplete.iter().any(|reason| {
                    reason.reason
                        == crate::result_incomplete::ToolResultIncompleteReason::SemanticEvidenceIncomplete
                        && reason.detail.as_deref().is_some_and(|detail| detail.contains(path))
                }), "{partial:?}");
            }
        }
        // Include the synthetic module units and both header readings in the
        // differential, even though function_sources only emits callables.
        let _scope = AnalyzerQueryScope::new(analyzer);
        let files = [
            project.file("pkg/api.py"),
            project.file("src/module.ts"),
            project.file("common.h"),
        ];
        let mut expected = full_inventory(analyzer)
            .into_inventory_result()
            .unwrap()
            .into_iter()
            .filter(|unit| files.contains(unit.source()))
            .collect::<Vec<_>>();
        let mut actual = analyzer
            .declarations_for_files_answer(&files)
            .into_inventory_result()
            .unwrap();
        assert!(
            expected
                .iter()
                .any(|unit| unit.is_module() && unit.source() == &project.file("pkg/api.py")),
            "fixture must include a synthetic module"
        );
        expected.sort();
        actual.sort();
        assert_eq!(expected, actual);
    }

    #[test]
    fn macro_include_dependency_failure_is_incomplete() {
        use brokk_bifrost_analysis::CodeUnitIndex;
        use brokk_bifrost_cpp_analysis::analyzer::cpp::CppAnalyzer;
        let project = InlineTestProject::new()
            .file("donor.h", "#define FIELDS int member;\n")
            .file(
                "owner.cpp",
                "#include \"donor.h\"\nstruct Owner { FIELDS };\nvoid work() {}\n",
            )
            .file("healthy.cpp", "void healthy() {}\n")
            .build();
        let analyzer = CppAnalyzer::new(project.project_dyn());
        let params = || ListFunctionSourcesParams {
            paths: Some(vec!["owner.cpp".into()]),
            include_tests: true,
        };
        let files = [project.file("owner.cpp")];
        let expected = full_inventory(&analyzer)
            .into_inventory_result()
            .unwrap()
            .into_iter()
            .filter(|unit| files.contains(unit.source()))
            .collect::<Vec<_>>();
        let actual = analyzer
            .declarations_for_files_answer(&files)
            .into_inventory_result()
            .unwrap();
        assert_eq!(
            expected, actual,
            "macro-composed field inventories must be identical"
        );
        let healthy = serde_json::to_vec(&list_function_sources(&analyzer, params())).unwrap();
        for failed in ["owner.cpp", "donor.h", "healthy.cpp"] {
            analyzer
                .inner()
                .store_context
                .store
                .inject_declaration_read_failure_for_test(failed);
            let reference = list_function_sources_with_selection(&analyzer, params(), |_| {
                full_inventory(&analyzer)
            });
            assert!(
                !reference.incomplete.is_empty(),
                "full inventory must observe {failed}"
            );
            let actual = list_function_sources(&analyzer, params());
            if failed == "healthy.cpp" {
                assert_eq!(healthy, serde_json::to_vec(&actual).unwrap());
            } else {
                assert_eq!(
                    serde_json::to_vec(&reference).unwrap(),
                    serde_json::to_vec(&actual).unwrap(),
                    "failed={failed}: {actual:?}"
                );
            }
        }
    }

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
                .any(|record| record.name == "inline_test" && record.is_test == Some(true))
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
                .all(|record| record.is_test == Some(false) && record.rel_path == "src/lib.rs")
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
