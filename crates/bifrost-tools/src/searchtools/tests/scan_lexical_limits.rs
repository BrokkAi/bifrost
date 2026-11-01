use super::*;
use brokk_bifrost_analysis::test_support::AnalyzerFixture;

#[test]
fn c_label_source_at_byte_limit_is_scanned() {
    let source = "void f(void) { goto end; end: return; }\n";
    let fixture = AnalyzerFixture::new_for_language(Language::Cpp, &[("labels.c", source)]);
    let params = || ScanUsagesByLocationParams {
        targets: vec![ScanUsagesTarget {
            path: "labels.c".to_string(),
            line: 1,
            column: Some(source.find("end:").expect("label") + 1),
            symbol: None,
        }],
        include_tests: true,
        paths: None,
        include_same_owner: true,
    };
    for (budget, expected_reason) in [
        (source.len(), None),
        (
            source.len() - 1,
            Some(ScanUsagesIncompleteReason::SourceBytes),
        ),
    ] {
        let context = ScanUsagesExecutionContext::with_limits(
            brokk_bifrost_core::CancellationToken::default(),
            1_000,
            10_000,
            budget,
            1_000,
        );
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let result = crate::searchtools::scan_usages::scan_usages_by_location_with_context(
            fixture.analyzer.analyzer(),
            scope.token(),
            params(),
            &context,
        );
        let entry = &result.results[0];
        assert_eq!(entry.incomplete_reason, expected_reason, "{result:#?}");
        if expected_reason.is_none() {
            assert!(entry.complete, "{result:#?}");
            assert_eq!(entry.total_hits, Some(1), "{result:#?}");
        }
    }
}

#[test]
fn header_macro_lexical_respects_path_and_callsite_cap() {
    let header = "typedef struct event_s { int x; int y; } event_t;\n#define PROCESS(block) \\\ndo { event_t* event; block } while (0)\n";
    let usage = "#include \"../include/flag.h\"\nvoid f(void) { PROCESS({ (void)event->x; (void)event->y; }); }\n";
    let fixture = AnalyzerFixture::new_for_language(
        Language::Cpp,
        &[
            ("include/flag.h", header),
            ("src/use.c", usage),
            ("src/other.c", "int y = 0;\n"),
        ],
    );
    let params = || ScanUsagesByLocationParams {
        targets: vec![ScanUsagesTarget {
            path: "include/flag.h".to_string(),
            line: 3,
            column: Some(15),
            symbol: None,
        }],
        include_tests: true,
        paths: Some(vec!["src/use.c".to_string()]),
        include_same_owner: true,
    };
    let result = crate::searchtools::scan_usages::scan_usages_by_location(
        fixture.analyzer.analyzer(),
        params(),
    );
    let entry = &result.results[0];
    assert_eq!(entry.total_hits, Some(2), "{result:#?}");
    assert_eq!(entry.files.len(), 1, "{result:#?}");
    assert_eq!(entry.files[0].path, "src/use.c", "{result:#?}");

    let context = ScanUsagesExecutionContext::with_limits(
        brokk_bifrost_core::CancellationToken::default(),
        1_000,
        10_000,
        usize::MAX,
        1,
    );
    let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
    let bounded = crate::searchtools::scan_usages::scan_usages_by_location_with_context(
        fixture.analyzer.analyzer(),
        scope.token(),
        params(),
        &context,
    );
    assert_eq!(
        bounded.results[0].status,
        ScanUsagesStatus::TooManyCallsites,
        "{bounded:#?}"
    );
    assert_eq!(bounded.results[0].limit, Some(1), "{bounded:#?}");
}

#[test]
fn candidate_file_limit_reports_candidate_files() {
    let fixture = AnalyzerFixture::new_for_language(
        Language::Rust,
        &[(
            "lib.rs",
            "pub fn target() {}\npub fn caller() { target(); }\n",
        )],
    );
    let context = ScanUsagesExecutionContext::with_limits(
        brokk_bifrost_core::CancellationToken::default(),
        0,
        0,
        usize::MAX,
        usize::MAX,
    );
    let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
    let result = crate::searchtools::scan_usages::scan_usages_by_reference_with_context(
        fixture.analyzer.analyzer(),
        scope.token(),
        crate::searchtools::scan_usages::ScanUsagesByReferenceParams {
            symbols: vec!["target".to_string()],
            include_tests: true,
            paths: None,
            include_same_owner: true,
        },
        &context,
    );
    assert_eq!(result.results.len(), 1, "{result:#?}");
    assert_eq!(
        result.results[0].incomplete_reason,
        Some(ScanUsagesIncompleteReason::CandidateFiles),
        "{result:#?}"
    );
}

#[test]
fn capped_callable_precedes_later_lexical_label() {
    let source = "void target(void) {}\nvoid caller(void) {\n  target();\n  target();\n}\nvoid marked(void) {\nhere: return;\n}\n";
    let fixture = AnalyzerFixture::new_for_language(Language::Cpp, &[("mix.c", source)]);
    let context = ScanUsagesExecutionContext::with_limits(
        brokk_bifrost_core::CancellationToken::default(),
        1_000,
        10_000,
        usize::MAX,
        1,
    );
    let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
    let result = crate::searchtools::scan_usages::scan_usages_by_location_with_context(
        fixture.analyzer.analyzer(),
        scope.token(),
        ScanUsagesByLocationParams {
            targets: vec![
                ScanUsagesTarget {
                    path: "mix.c".to_string(),
                    line: 1,
                    column: Some(6),
                    symbol: None,
                },
                ScanUsagesTarget {
                    path: "mix.c".to_string(),
                    line: 7,
                    column: Some(1),
                    symbol: None,
                },
            ],
            include_tests: true,
            paths: None,
            include_same_owner: true,
        },
        &context,
    );
    assert_eq!(result.results.len(), 2, "{result:#?}");
    assert_eq!(
        result.results[0].status,
        ScanUsagesStatus::TooManyCallsites,
        "{result:#?}"
    );
    assert_eq!(
        result.results[1].symbol.as_deref(),
        Some("here"),
        "{result:#?}"
    );
}
