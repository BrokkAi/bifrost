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
        max_scope_nodes: 17,
        max_resolution_rounds: ReceiverAnalysisBudget::default().max_resolution_rounds,
        max_hierarchy_order_steps: ReceiverAnalysisBudget::default().max_hierarchy_order_steps,
    })
    .expect("aggregate semantic budget");
    let semantic = bridge.budget.limits();
    assert_eq!(semantic.procedures, 2);
    assert_eq!(semantic.control_edges, 1);
    assert_eq!(semantic.nested_entries, 5);
    assert_eq!(semantic.call_sites, 9);
    assert_eq!(semantic.memory_locations, 9);
    assert_eq!(semantic.captures, 9);
    assert_eq!(semantic.source_bytes, 17 * 1_024);
    let scope_limits = ReceiverSemanticBridge::receiver_work(semantic);
    assert_eq!(scope_limits.scope_nodes, 17);
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
            max_scope_nodes: ReceiverSemanticBridge::SCOPE_DIMENSIONS - 1,
            ..ReceiverAnalysisBudget::default()
        })
        .unwrap_err(),
        ReceiverBudgetLimit::ScopeNodes
    );
    assert_eq!(
        ReceiverSemanticBridge::new(ReceiverAnalysisBudget {
            max_summary_expansions: ReceiverSemanticBridge::SUMMARY_DIMENSIONS - 1,
            ..ReceiverAnalysisBudget::default()
        })
        .unwrap_err(),
        ReceiverBudgetLimit::SummaryExpansions
    );
}
