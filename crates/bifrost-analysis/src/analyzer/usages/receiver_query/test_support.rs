use super::*;
#[doc(hidden)]
pub fn marker_range(source: &str, marker: &str) -> Range {
    let start_byte = source.find(marker).expect("marker");
    range_at(source, marker, start_byte)
}
#[doc(hidden)]
pub fn last_marker_range(source: &str, marker: &str) -> Range {
    let start_byte = source.rfind(marker).expect("marker");
    range_at(source, marker, start_byte)
}
#[doc(hidden)]
pub fn range_at(source: &str, marker: &str, start_byte: usize) -> Range {
    Range {
        start_byte,
        end_byte: start_byte + marker.len(),
        start_line: source[..start_byte]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count(),
        end_line: source[..start_byte + marker.len()]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count(),
    }
}
#[doc(hidden)]
pub fn assert_factory_ranges_limited_and_cancellable(analyzer: &dyn IAnalyzer, factory: &CodeUnit) {
    let tiny_budget = ReceiverAnalysisBudget {
        max_scope_nodes: 1,
        ..ReceiverAnalysisBudget::default()
    };
    let mut tiny_ledger = ReceiverWorkLedger::new(tiny_budget);
    assert!(matches!(
        code_unit_ranges_bounded(analyzer, factory, None, &mut tiny_ledger)
            .expect("tiny factory range budget"),
        CompatibilityOutcome::Exceeded(ReceiverBudgetLimit::ScopeNodes)
    ));
    assert_eq!(tiny_ledger.work().scope_nodes, 1);

    let cancellation = CancellationToken::default();
    cancellation.cancel();
    let mut cancelled_ledger = ReceiverWorkLedger::new(ReceiverAnalysisBudget::default());
    assert!(matches!(
        code_unit_ranges_bounded(
            analyzer,
            factory,
            Some(&cancellation),
            &mut cancelled_ledger,
        ),
        Err(ReceiverQueryError::Cancelled)
    ));
    assert_eq!(cancelled_ledger.work(), ReceiverAnalysisWork::default());
}
