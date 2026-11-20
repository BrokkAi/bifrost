//! The tree-sitter analyzer's request caches record the reads their fills
//! recorded when they hit (#7262). The engine and the criterion are in
//! `brokk_bifrost_analysis::test_support::hit_parity`.
//!
//! Each row opens its own request scope, so the row's cache starts empty; the
//! first run fills it and the second run hits it.
//!
//! | row | class | fixture | evidence |
//! | --- | --- | --- | --- |
//! | definition parent cache `parent_units` | R | Java member `p.Other.use` | definition candidate queries |
//! | `identifier_candidate_units` | R | Java identifier `run` | identifier candidate executions |
//! | `definition_units` | C | Java `p.Outer` | definition candidate queries |
//! | package bucket `top_level_class_units_by_package` | C | Java package `p` | package declaration scans |
//! | class range index `class_ranges` | C | Java `p/Outer.java` | the same shared index returned |
//! | `analyzed_live_files` | R | Java workspace | `analyzed_live_file_hits` |
//! | `path_synthetic_modules` | C | Python package `pkg` | workspace path scans |

use super::declaration_candidates::{java_analyzer, python_analyzer};
use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;
use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;
use brokk_bifrost_analysis::analyzer::{
    AnalyzerConfig, FactSubject, IndexFamily, LanguageAdapter, LookupQuestion, ReadKey,
    WorkspaceAnalyzer, WorkspaceFactFamily,
};
use brokk_bifrost_analysis::test_support::hit_parity::{Class, Coverage, Evidence, Head, Rows};
use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
use brokk_bifrost_core::analyzer::model::CodeUnitType;
use brokk_bifrost_test_macros::hardwon;
use std::cell::Cell;
use std::sync::Arc;
use std::sync::atomic::Ordering;

const JAVA_FILES: [(&str, &str); 2] = [
    (
        "p/Outer.java",
        "package p;\npublic class Outer {\n  public static class Inner {\n    public void m() {}\n  }\n  public void run() {}\n}\n",
    ),
    (
        "p/Other.java",
        "package p;\npublic class Other {\n  public void use(Outer o) { o.run(); }\n}\n",
    ),
];

const PYTHON_FILES: [(&str, &str); 3] = [
    ("pkg/__init__.py", ""),
    ("pkg/mod.py", "def f():\n    return 1\n"),
    ("top.py", "import pkg.mod\n"),
];

fn overlay_membership_of_a_file(key: &ReadKey) -> bool {
    matches!(
        key,
        ReadKey::Lookup {
            question: LookupQuestion::WorkspaceFact {
                family: WorkspaceFactFamily::WorkspaceOverlayMembership,
                subject: FactSubject::File { .. },
                ..
            },
            ..
        }
    )
}

/// The head the analyzer's own workspace is verified against.
fn head_of<A: LanguageAdapter>(analyzer: &TreeSitterAnalyzer<A>) -> Head {
    let base = WorkspaceAnalyzer::build_ephemeral_footgun(
        Arc::clone(&analyzer.project),
        AnalyzerConfig::default(),
    )
    .expect("the base workspace builds");
    Head::of(Arc::clone(&analyzer.project), &base)
}

#[test]
#[hardwon("#7262: a cache hit recorded fewer reads than the fill that built its entry")]
fn java_request_caches_record_the_reads_their_fills_recorded() {
    let (_temp, analyzer) = java_analyzer(&JAVA_FILES);
    let _ = analyzer.get_all_declarations();
    let head = head_of(&analyzer);
    let mut rows = Rows::new(&analyzer, &head);
    let queries = || analyzer.definition_candidates_query_count_for_test() as u64;

    let member = analyzer
        .get_all_declarations()
        .into_iter()
        .find(|unit| unit.identifier() == "use")
        .expect("the member `use` is declared");
    {
        let _scope = AnalyzerQueryScope::new(&analyzer);
        rows.row(
            "definition parent cache",
            Class::Replay,
            Evidence::Fills(&queries),
            || analyzer.definition_parent_unit(&member),
        );
    }
    {
        let _scope = AnalyzerQueryScope::new(&analyzer);
        let executions = || {
            analyzer
                .query_read_cache_lock()
                .identifier_candidate_query_executions
                .load(Ordering::Relaxed) as u64
        };
        rows.row(
            "identifier_candidate_units",
            Class::Replay,
            Evidence::Fills(&executions),
            || analyzer.lookup_declarations_by_identifier_limited("run", 16, || true),
        );
    }
    {
        let _scope = AnalyzerQueryScope::new(&analyzer);
        rows.row(
            "definition_units",
            Class::ConsumerKeys,
            Evidence::Fills(&queries),
            || CodeUnitIndex::definitions(&analyzer, "p.Outer").count(),
        );
    }
    {
        let _scope = AnalyzerQueryScope::new(&analyzer);
        // The bucket holds every package of one whole-workspace scan, so a
        // change in any package can change a later lookup. The hit records the
        // language's whole scope instead of the fill's per-package probe
        // (`persisted_top_level_classes_in_package`).
        rows.row_covering(
            "package bucket",
            Class::ConsumerKeys,
            Evidence::Fills(&|| analyzer.package_declaration_scan_count_for_test() as u64),
            &[Coverage {
                claim: "the package probe is covered by the language scope",
                covered: &|key| {
                    matches!(
                        key,
                        ReadKey::Index {
                            family: IndexFamily::PackageMembership,
                            ..
                        }
                    )
                },
                by: &|key| matches!(key, ReadKey::Scope { .. }),
            }],
            || analyzer.class_declarations_in_package("p"),
        );
    }
    {
        let _scope = AnalyzerQueryScope::new(&analyzer);
        let file = analyzer
            .get_all_declarations()
            .into_iter()
            .find(|unit| unit.kind() == CodeUnitType::Class && unit.identifier() == "Outer")
            .expect("class Outer is declared")
            .source()
            .clone();
        let shared = Cell::new(0_u64);
        let previous = Cell::new(None);
        // The hit records the file's blob before the memo (`class_range_index`),
        // and the blob names the overlay's content, so the fill's overlay
        // membership read is covered by the file key.
        rows.row_covering(
            "class range index",
            Class::ConsumerKeys,
            Evidence::Hits(&|| shared.get()),
            &[Coverage {
                claim: "the file's overlay membership is covered by the file's blob",
                covered: &overlay_membership_of_a_file,
                by: &|key| matches!(key, ReadKey::File { .. }),
            }],
            || {
                let index = CodeUnitIndex::class_range_index(&analyzer, &file);
                if previous
                    .replace(Some(index.clone()))
                    .is_some_and(|earlier| Arc::ptr_eq(&earlier, &index))
                {
                    shared.set(shared.get() + 1);
                }
            },
        );
    }
    {
        let _scope = AnalyzerQueryScope::new(&analyzer);
        // The answer is the analyzed file set, which nothing narrower than the
        // language scope bounds (`analyzed_live_files` records it before the
        // memo answers).
        rows.row(
            "analyzed_live_files",
            Class::Replay,
            Evidence::Hits(&|| {
                analyzer
                    .query_read_cache_lock()
                    .analyzed_live_file_hits
                    .load(Ordering::Relaxed) as u64
            }),
            || analyzer.analyzed_live_files(),
        );
    }
    rows.finish();
}

#[test]
#[hardwon("#7262: a cache hit recorded fewer reads than the fill that built its entry")]
fn python_path_module_cache_records_the_reads_its_fill_recorded() {
    let (_temp, analyzer) = python_analyzer(&PYTHON_FILES);
    let _ = analyzer.get_all_declarations();
    let head = head_of(&analyzer);
    let mut rows = Rows::new(&analyzer, &head);
    let _scope = AnalyzerQueryScope::new(&analyzer);
    rows.row(
        "path_synthetic_modules",
        Class::ConsumerKeys,
        Evidence::Fills(&|| analyzer.workspace_path_scan_count_for_test() as u64),
        || analyzer.path_synthetic_modules_for_test(),
    );
    rows.finish();
}

#[test]
#[hardwon("#12681: a later capture in one request omitted WorkspaceOverlayMembers")]
fn analyzed_live_files_hit_records_every_seed_read_before_and_after_an_edit() {
    use brokk_bifrost_analysis::analyzer::{IAnalyzer, ProjectFile, capture_query_reads};
    use std::collections::BTreeSet;

    let files = [
        PYTHON_FILES.as_slice(),
        &[("tools/Gen.java", "class Gen {}\n")],
    ]
    .concat();
    let (_temp, mut analyzer) = python_analyzer(&files);
    let _ = analyzer.get_all_declarations();
    for run in 0..2 {
        let (cold_files, cold_reads) = {
            // A then B share a request but have independent capture ledgers.
            let _scope = AnalyzerQueryScope::new(&analyzer);
            let (cold_files, cold_reads) =
                capture_query_reads(&analyzer, || analyzer.analyzed_live_files());
            let hits = analyzer
                .query_read_cache_lock()
                .analyzed_live_file_hits
                .load(Ordering::Relaxed);
            let (warm_files, warm_reads) =
                capture_query_reads(&analyzer, || analyzer.analyzed_live_files());
            assert_eq!(warm_files, cold_files, "run {run}: warm and cold answers");
            assert_eq!(warm_reads.keys(), cold_reads.keys(), "run {run}: receipts");
            assert!(
                analyzer
                    .query_read_cache_lock()
                    .analyzed_live_file_hits
                    .load(Ordering::Relaxed)
                    > hits,
                "capture B must use the request memo"
            );
            (cold_files, cold_reads)
        };
        // A fresh single capture must carry the same keys as the shared hit.
        let _scope = AnalyzerQueryScope::new(&analyzer);
        let (fresh_files, fresh_reads) =
            capture_query_reads(&analyzer, || analyzer.analyzed_live_files());
        assert_eq!(fresh_files, cold_files, "run {run}: fresh answer");
        assert_eq!(
            fresh_reads.keys(),
            cold_reads.keys(),
            "run {run}: fresh receipt"
        );
        let membership = fresh_reads
            .keys()
            .into_iter()
            .filter(overlay_membership_of_a_file)
            .collect::<Vec<_>>();
        assert_eq!(membership.len(), PYTHON_FILES.len(), "{membership:?}");
        drop(_scope);
        if run == 0 {
            // An unrelated-language source is present in the project seed and
            // edited between requests; it is neither a package nor config file.
            let edited = ProjectFile::new(analyzer.project.root().to_path_buf(), "tools/Gen.java");
            edited.write("class Gen { int x; }\n").expect("edit");
            analyzer = analyzer.update(&BTreeSet::from([edited]));
        }
    }
}
