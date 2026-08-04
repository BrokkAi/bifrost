//! `scan_usages_by_reference` must not re-scan every workspace declaration once
//! per `using` directive of every candidate file — issue #1194.
//!
//! The MCP property fuzzer found that all five StockSharp shards burned 26+ CPU
//! hours each in the scan-probe phase without completing, at flat IO. Stack
//! sampling put 6/6 samples in the same frame:
//!
//! ```text
//! candidates::find_import_graph_candidates
//!   -> CSharpAnalyzer::imported_code_units_of
//!     -> TreeSitterAnalyzer::class_declarations_in_package
//!       -> AnalyzerStore::declaration_candidate_rows_for_langs   (whole workspace)
//! ```
//!
//! C# import-graph candidate discovery asks "what does this file import?" for
//! every analyzed file, and the C# answer is "every top-level class in each of
//! its `using` namespaces". `class_declarations_in_package` answered that
//! package-scoped question with a *whole-workspace* declaration scan plus a
//! hydrated package filter, so one scan probe issued (files x usings) whole
//! workspace scans — tens of thousands on StockSharp, each materializing and
//! hydrating every persisted declaration row in the repository.
//!
//! The fix hoists that scan: one pass buckets every top-level class by its
//! hydrated package and the bucket map is retained for the active request. Rows,
//! hydration, and the package equality test are unchanged, so results are
//! identical; only the number of scans differs.
//!
//! These are perf pins in the shape of `issue_1175_scan_usages_reparse.rs`: they
//! assert a *count* of work, which is deterministic, rather than wall time,
//! which is not.

mod common;

use brokk_bifrost::searchtools::{
    ScanUsagesByReferenceParams, ScanUsagesEntry, ScanUsagesStatus, scan_usages_by_reference,
};
use brokk_bifrost::{CSharpAnalyzer, IAnalyzer, Language};
use common::InlineTestProject;

/// A library namespace holding the scan target, three consumers that reference
/// it, and `bystanders` files that name neither the target nor its namespace.
///
/// The bystanders are the load-bearing part. Import-graph candidate discovery
/// sweeps *every* analyzed file; a file that plainly could import the target
/// (same namespace, or it spells the target's name) is admitted on the cheap
/// syntactic test. Only files that fail that test fall through to "resolve what
/// this file actually imports", which is where C# materializes every top-level
/// class in each of the file's `using` namespaces. A workspace whose files are
/// mostly unrelated to the scan target — the normal case, and StockSharp's —
/// therefore drives that path once per (file, using) pair.
fn bystander_heavy_project(bystanders: usize) -> (common::BuiltInlineTestProject, CSharpAnalyzer) {
    let mut builder = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Lib/Widget.cs",
            "namespace Lib;\n\npublic class Widget\n{\n    public int Size() => 1;\n}\n\npublic class Gadget\n{\n}\n",
        )
        .file(
            "Support/Registry.cs",
            "namespace Support;\n\npublic class Registry\n{\n}\n",
        )
        .file(
            "Support/Extra/Helper.cs",
            "namespace Support.Extra;\n\npublic class Helper\n{\n}\n",
        );
    for index in 0..3 {
        builder = builder.file(
            format!("App/Consumer{index}.cs"),
            format!(
                "using Lib;\n\nnamespace App;\n\npublic class Consumer{index}\n{{\n    public Widget Make() => new Widget();\n}}\n"
            ),
        );
    }
    for index in 0..bystanders {
        builder = builder.file(
            format!("Noise/Bystander{index}.cs"),
            format!(
                "using Support;\nusing Support.Extra;\n\nnamespace Noise;\n\npublic class Bystander{index}\n{{\n    public Registry Keep() => new Registry();\n\n    public Helper Assist() => new Helper();\n}}\n"
            ),
        );
    }
    let project = builder.build();
    let analyzer = CSharpAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn scan_widget(analyzer: &CSharpAnalyzer) -> ScanUsagesEntry {
    let mut result = scan_usages_by_reference(
        analyzer,
        ScanUsagesByReferenceParams {
            symbols: vec!["Lib.Widget".to_string()],
            include_tests: true,
            paths: None,
            include_same_owner: false,
            max_duration_secs: None,
        },
    );
    assert_eq!(result.results.len(), 1, "one requested symbol");
    result.results.remove(0)
}

/// The pin, stated as a complexity bound: growing the workspace tenfold must
/// not grow the number of whole-workspace declaration scans the package-scoped
/// class lookup performs.
///
/// Before the fix this scaled with (files x `using` directives) — two usings in
/// each of forty bystanders cost eighty whole-workspace scans,
/// which is exactly the shape that turned one StockSharp scan probe into hours
/// of pure compute.
#[test]
fn package_declaration_scans_do_not_grow_with_workspace_size() {
    let mut counts = Vec::new();
    for bystanders in [4_usize, 40] {
        let (_project, analyzer) = bystander_heavy_project(bystanders);
        analyzer
            .test_hooks()
            .reset_package_declaration_scan_count_for_test();

        let entry = scan_widget(&analyzer);
        assert_eq!(
            entry.status,
            ScanUsagesStatus::Found,
            "the scan must still find the library type's usages: {entry:#?}"
        );

        counts.push(
            analyzer
                .test_hooks()
                .package_declaration_scan_count_for_test(),
        );
    }

    let [small, large] = counts[..] else {
        unreachable!("two measurements");
    };
    assert!(
        large <= small,
        "package-scoped class lookups must not re-scan every workspace declaration \
         per file per using directive: 4 bystanders cost {small} whole-workspace scans, \
         40 bystanders cost {large}"
    );
}

/// The absolute bound behind the growth pin: one request scans the workspace's
/// declarations at most once to answer package-scoped class lookups, however
/// many distinct packages it has to resolve.
#[test]
fn one_scan_answers_every_package_lookup_in_a_request() {
    let (_project, analyzer) = bystander_heavy_project(40);
    analyzer
        .test_hooks()
        .reset_package_declaration_scan_count_for_test();

    let entry = scan_widget(&analyzer);
    assert_eq!(entry.status, ScanUsagesStatus::Found, "{entry:#?}");

    assert!(
        analyzer
            .test_hooks()
            .package_declaration_scan_count_for_test()
            <= 1,
        "a single scan_usages_by_reference call must issue at most one whole-workspace \
         declaration scan for package-scoped class lookups, got {}",
        analyzer
            .test_hooks()
            .package_declaration_scan_count_for_test()
    );
}

/// The fix is a hoist, not a behavior change: the usages themselves — status,
/// count, and files — must be exactly what they were.
#[test]
fn every_reference_to_the_library_type_is_still_reported() {
    let (_project, analyzer) = bystander_heavy_project(4);
    let entry = scan_widget(&analyzer);

    assert_eq!(entry.status, ScanUsagesStatus::Found, "{entry:#?}");
    let mut files: Vec<&str> = entry.files.iter().map(|file| file.path.as_str()).collect();
    files.sort_unstable();
    assert_eq!(
        files,
        vec!["App/Consumer0.cs", "App/Consumer1.cs", "App/Consumer2.cs"],
        "{entry:#?}"
    );
    assert_eq!(
        entry.total_hits,
        Some(6),
        "each consumer names Widget as a return type and in a construction: {entry:#?}"
    );
}
