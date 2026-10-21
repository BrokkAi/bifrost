#[cfg(test)]
mod rust_departing_read_ledger_scope_tests_tests {

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

    use brokk_bifrost_analysis::analyzer::i_analyzer::capture_nested_reads;

    use crate::analyzer::read_ledger::ReadKey;
    use brokk_bifrost_analysis::analyzer::i_analyzer::capture_query_reads;

    use brokk_bifrost_analysis::analyzer::read_ledger::ReadLedger;

    use brokk_bifrost_semantic::analyzer::semantic::ids::StableDigest;
    use brokk_bifrost_test_macros::hardwon;
    use std::sync::Arc;
    #[test]
    #[hardwon("#2586: shared policy subject scans double-charged nested read ledgers")]
    fn query_capture_preserves_nested_funnel_attribution_without_double_charging() {
        let project = crate::inline_project::InlineTestProject::with_language(
            brokk_bifrost_core::analyzer::model::Language::Rust,
        )
        .file("lib.rs", "fn work() {}")
        .build();
        let workspace = project
            .workspace_analyzer(brokk_bifrost_core::analyzer::config::AnalyzerConfig::default());
        let analyzer = workspace.analyzer();
        let other = Arc::new(ReadLedger::new());
        let enclosing = Arc::new(ReadLedger::new());
        let _other_scope = AnalyzerQueryScope::with_read_ledger(analyzer, Arc::clone(&other));
        let _enclosing_scope =
            AnalyzerQueryScope::with_read_ledger(analyzer, Arc::clone(&enclosing));
        let internal = ReadKey::Configuration(StableDigest::sha256(b"implementation"));
        let published = ReadKey::Configuration(StableDigest::sha256(b"replayable answer"));
        let (answer, captured) = capture_query_reads(analyzer, || {
            capture_nested_reads(analyzer, || {
                analyzer.record_read(internal.clone());
                analyzer.record_unattributed_read();
            });
            analyzer.record_read(published.clone());
            analyzer.record_unattributed_read();
            42
        });
        assert_eq!(answer, 42);
        assert_eq!(captured.keys(), vec![published.clone()]);
        assert_eq!(enclosing.keys(), vec![published.clone()]);
        assert_eq!(captured.unattributed_reads(), 1);
        assert_eq!(enclosing.unattributed_reads(), 1);
        let mut expected = vec![internal, published];
        expected.sort();
        assert_eq!(other.keys(), expected);
        assert_eq!(other.unattributed_reads(), 2);
    }
}
