#[cfg(test)]
use super::*;

#[cfg(test)]
#[test]
fn semantic_receiver_evidence_requires_complete_exhaustive_input_for_precision() {
    let outcomes = [
        SemanticOutcome::Complete {
            value: (),
            work: SemanticWork::default(),
        },
        SemanticOutcome::Ambiguous {
            candidates: (),
            work: SemanticWork::default(),
        },
        SemanticOutcome::Unknown {
            partial: Some(()),
            work: SemanticWork::default(),
        },
        SemanticOutcome::Unsupported {
            capability: crate::analyzer::semantic::SemanticCapability::Values,
            partial: Some(()),
            work: SemanticWork::default(),
        },
        SemanticOutcome::Unproven {
            partial: (),
            work: SemanticWork::default(),
        },
    ];
    let coverages = [
        CandidateCoverage::Exhaustive,
        CandidateCoverage::Open,
        CandidateCoverage::Truncated,
    ];

    for (outcome_index, outcome) in outcomes.iter().enumerate() {
        for coverage in coverages {
            let evidence = SemanticReceiverEvidence::from_outcome(outcome, coverage);
            assert_eq!(
                evidence.supports_precise(),
                outcome_index == 0 && coverage == CandidateCoverage::Exhaustive
            );
            assert_eq!(
                evidence.is_truncated(),
                coverage == CandidateCoverage::Truncated
            );
            assert!(
                !evidence.legacy_provider_can_close(),
                "raw incomplete evidence must not be reclassified as global capability openness"
            );
        }
    }
}

#[cfg(test)]
#[test]
fn receiver_semantic_bridge_uses_every_receiver_limit() {
    let bridge = ReceiverSemanticBridge::new(ReceiverAnalysisBudget {
        context_depth: 2,
        max_targets: 3,
        max_summary_expansions: 9,
        max_hierarchy_order_work: 17,
        max_resolution_rounds: ReceiverAnalysisBudget::default().max_resolution_rounds,
        max_hierarchy_order_steps: ReceiverAnalysisBudget::default().max_hierarchy_order_steps,
    })
    .expect("aggregate semantic budget");
    let semantic = bridge.budget.limits();
    assert_eq!(semantic.call_sites, 9);
    assert_eq!(semantic.memory_locations, 9);
    assert_eq!(semantic.captures, 9);
    // Resident rows and text keep the semantic budget's own limits: visiting
    // syntax is work and has no allowance (#13216).
    let defaults = SemanticBudget::default().limits();
    assert_eq!(semantic.procedures, defaults.procedures);
    assert_eq!(semantic.nested_entries, defaults.nested_entries);
    assert_eq!(semantic.owned_text_bytes, defaults.owned_text_bytes);
    let aggregate_work = ReceiverSemanticBridge::receiver_work(SemanticWork {
        call_sites: 4,
        memory_locations: 3,
        captures: 2,
        ..SemanticWork::default()
    });
    assert_eq!(aggregate_work.summary_expansions, 9);

    let oracle = bridge.oracle_limits.values();
    assert_eq!(oracle.dispatch_targets, 3);
    assert_eq!(oracle.objects_per_value, 3);
    assert_eq!(oracle.alias_breadth, 3);
    assert_eq!(oracle.source_observations, 3);
    assert_eq!(oracle.call_context_depth, 2);
    assert_eq!(oracle.summary_depth, 9);
    assert_eq!(oracle.call_binding_entries, 9);

    let zero_context = ReceiverSemanticBridge::new(ReceiverAnalysisBudget {
        context_depth: 0,
        ..ReceiverAnalysisBudget::default()
    })
    .expect("zero-context receiver budget");
    assert_eq!(zero_context.oracle_limits.call_context_depth(), 1);

    assert_eq!(
        ReceiverSemanticBridge::new(ReceiverAnalysisBudget {
            max_summary_expansions: ReceiverSemanticBridge::SUMMARY_DIMENSIONS - 1,
            ..ReceiverAnalysisBudget::default()
        })
        .unwrap_err(),
        ReceiverBudgetLimit::SummaryExpansions
    );
}

#[cfg(test)]
#[test]
fn incomplete_provider_rows_make_the_query_execution_dependent() {
    use brokk_bifrost_core::analyzer::query_batch::QueryBatch;
    let mut ledger = ReceiverWorkLedger::new(ReceiverAnalysisBudget::default());
    assert_eq!(ledger.reuse_verdict(), ReuseVerdict::Content);
    let outcome = charge_limited_projection(QueryBatch::incomplete(vec![1], 1), None, &mut ledger)
        .expect("uncancelled projection");
    assert!(matches!(
        outcome,
        CompatibilityOutcome::Unavailable("provider_rows_incomplete")
    ));
    assert_eq!(
        ledger.reuse_verdict(),
        ReuseVerdict::ExecutionDependent(ExecutionCause::Other)
    );
}
