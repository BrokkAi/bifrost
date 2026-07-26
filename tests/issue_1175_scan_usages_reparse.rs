//! `scan_usages_by_reference` must not re-parse a candidate file once per
//! declaration it inspects — issue #1175.
//!
//! The MCP property fuzzer found a C corpus (gojue/ecapture, whose `kern/bpf`
//! tree vendors two multi-megabyte generated `vmlinux` headers) where scanning
//! usages of a single header-declared enum ran for 13 hours at 100% CPU and
//! read 148 GB out of the analyzer store. The store is a fraction of that size:
//! the reads were the *same* 4.8 MB header source, fetched and re-parsed tens
//! of thousands of times inside one scan.
//!
//! The cause was structural, not a missing cap. The C++ `VisibilityIndex` owned
//! a *clone* of the analyzer, and `TreeSitterAnalyzer::clone` deliberately
//! hands the clone a fresh, empty `QueryReadCache` (clones cross analyzer
//! generations and overlays, where another generation's hydrated state would be
//! wrong). Every `prepared_syntax` call the index made therefore ran against a
//! read cache with no active query scope, missed unconditionally, and re-read
//! plus re-parsed the file from scratch. The index now borrows the analyzer, so
//! its parses land in the live request's cache like everybody else's.
//!
//! These are perf pins in the shape of the existing enclosing-owner query-count
//! pins in `usages_cpp_graph_test.rs`: they assert a *count* of work, which is
//! deterministic, rather than a wall-clock time, which is not.

mod common;

use brokk_bifrost::{
    CppAnalyzer, Language, ProjectFile,
    searchtools::{
        ScanUsagesByReferenceParams, ScanUsagesEntry, ScanUsagesStatus, scan_usages_by_reference,
    },
};
use common::InlineTestProject;

/// A header declaring the scan target, plus a consumer that includes it and
/// references the target `references` times. The extra `Widget` peers give the
/// visibility index a real candidate list to walk, which is the path that
/// re-parsed the header per reference.
fn shared_header_project(references: usize) -> (common::BuiltInlineTestProject, CppAnalyzer) {
    let uses = (0..references)
        .map(|index| format!("    Widget widget_{index};\n"))
        .collect::<String>();
    let built = InlineTestProject::with_language(Language::Cpp)
        .file(
            "shared.h",
            "#pragma once\nstruct Widget {};\nstruct Gadget {};\nstruct Doohickey {};\n",
        )
        .file(
            "consumer.cpp",
            format!("#include \"shared.h\"\n\nvoid consume() {{\n{uses}}}\n"),
        )
        .file(
            "other_consumer.cpp",
            "#include \"shared.h\"\n\nvoid consume_other() {\n    Widget widget;\n    Gadget gadget;\n}\n",
        )
        .build();
    let analyzer = CppAnalyzer::from_project(built.project().clone());
    (built, analyzer)
}

fn scan_widget(analyzer: &CppAnalyzer) -> ScanUsagesEntry {
    let mut result = scan_usages_by_reference(
        analyzer,
        ScanUsagesByReferenceParams {
            symbols: vec!["Widget".to_string()],
            include_tests: true,
            paths: None,
            include_same_owner: false,
        },
    );
    assert_eq!(result.results.len(), 1, "one requested symbol");
    result.results.remove(0)
}

fn parse_counts(analyzer: &CppAnalyzer, files: &[ProjectFile]) -> Vec<usize> {
    files
        .iter()
        .map(|file| analyzer.prepared_syntax_parse_count_for_test(file))
        .collect()
}

/// The pin: one scan parses each participating file exactly once, however many
/// times the target is referenced.
///
/// Before the fix this scaled with the reference count — the header was parsed
/// once per candidate inspection, so twenty references cost twenty-odd parses
/// of the header (and of the referencing file), which is exactly the shape that
/// turned one generated header into 148 GB of store reads.
#[test]
fn scan_usages_parses_each_candidate_file_once_per_call() {
    let (built, analyzer) = shared_header_project(20);
    let header = built.file("shared.h");
    let consumer = built.file("consumer.cpp");
    let other = built.file("other_consumer.cpp");

    analyzer.reset_prepared_syntax_parse_counts_for_test();
    let entry = scan_widget(&analyzer);

    assert_eq!(
        entry.status,
        ScanUsagesStatus::Found,
        "the scan must still find the header-declared type's usages: {entry:#?}"
    );
    assert_eq!(
        parse_counts(&analyzer, &[header, consumer, other]),
        vec![1, 1, 1],
        "one scan must parse each file once; a per-candidate re-parse is the #1175 blow-up"
    );
}

/// The same pin stated as a complexity bound: growing the number of references
/// tenfold must not grow the number of parses at all. A count that tracks the
/// reference count is the quadratic behavior returning, whatever its constant.
#[test]
fn parse_count_does_not_grow_with_the_number_of_references() {
    let mut counts = Vec::new();
    for references in [2_usize, 20] {
        let (built, analyzer) = shared_header_project(references);
        let header = built.file("shared.h");

        analyzer.reset_prepared_syntax_parse_counts_for_test();
        let entry = scan_widget(&analyzer);
        assert_eq!(entry.status, ScanUsagesStatus::Found, "{entry:#?}");

        counts.push(analyzer.prepared_syntax_parse_count_for_test(&header));
    }

    assert_eq!(
        counts,
        vec![1, 1],
        "header parses must be independent of how often the target is referenced"
    );
}

/// The fix is a borrow, not a behavior change: the usages themselves — count,
/// files, and status — must be exactly what they were.
#[test]
fn every_reference_to_the_header_declared_type_is_still_reported() {
    let (built, analyzer) = shared_header_project(3);
    let entry = scan_widget(&analyzer);

    assert_eq!(entry.status, ScanUsagesStatus::Found, "{entry:#?}");
    assert_eq!(
        entry.total_hits,
        Some(4),
        "three references in consumer.cpp plus one in other_consumer.cpp: {entry:#?}"
    );
    let mut files: Vec<&str> = entry.files.iter().map(|file| file.path.as_str()).collect();
    files.sort_unstable();
    assert_eq!(files, vec!["consumer.cpp", "other_consumer.cpp"]);
    let _ = built;
}
