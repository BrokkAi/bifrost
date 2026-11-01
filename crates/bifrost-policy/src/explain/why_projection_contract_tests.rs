use super::*;
use crate::finding::{PolicyCoveragePartition, ProofMetadata, ProofReason, ProofState};

#[test]
fn flow_and_taint_roots_name_directional_endpoints() {
    let fixture = Fixture::new();
    for (policy, source, destination, vocabulary) in [
        (
            FLOW_POLICY,
            "Reader.read",
            "Store.put",
            ("origin", "observation"),
        ),
        (
            TAINT_POLICY,
            "user input",
            "sensitive store",
            ("source", "sink"),
        ),
    ] {
        let run = path_run(&fixture, policy, FakePath::proved());
        let explanation =
            explain_finding(&run, &only_finding(&run), &ExplanationLimits::default()).unwrap();
        assert_eq!(
            explanation.root().expected(),
            Some(
                format!(
                    "a value from {} `{}` reaches {} `{}` at event `{}`",
                    vocabulary.0, source, vocabulary.1, destination, "test:observation-0"
                )
                .as_str()
            )
        );
    }
}

#[test]
fn a_truncated_retained_path_leaves_witness_coverage_unknown() {
    let fixture = Fixture::new();
    let run = path_run(
        &fixture,
        FLOW_POLICY,
        FakePath {
            witness_steps_truncated: true,
            ..FakePath::proved()
        },
    );
    assert!(!run.findings()[0].witnesses_truncated());
    let explanation =
        explain_finding(&run, &only_finding(&run), &ExplanationLimits::default()).unwrap();
    assert_eq!(
        root_child(&explanation, "retained_witnesses").outcome(),
        ExplanationOutcome::Unknown
    );
}

#[test]
fn proof_preserves_multiple_reason_labels_with_separators() {
    let fixture = Fixture::new();
    struct TwoReasonAdapter;
    impl crate::projection::sealed::TaintAdapter for TwoReasonAdapter {}
    impl crate::evaluator::TaintPolicyEvaluator for TwoReasonAdapter {
        fn evaluate_taint(
            &self,
            _authority: &crate::projection::TaintProjectionAuthority,
            _policy: &LoadedPolicy,
            spec: &crate::resolved::ResolvedTaintPolicySpec,
            _context: &PolicyEvaluationContext<'_>,
            _budget: &PolicyBudget,
        ) -> crate::projection::TaintProjectionPayload {
            let mut projected = fake_projection(spec, FakePath::proved());
            projected.pairs[0].report.proof = ProofMetadata::try_new(
                ProofState::Proven,
                vec![ProofReason::DataflowWitness, ProofReason::ExactCallTarget],
                Vec::new(),
            )
            .unwrap();
            crate::projection::TaintProjectionPayload {
                engine: None,
                scope: None,
                projections: vec![projected],
                completion: PolicyRunCompletion::Complete,
                diagnostics: Vec::new(),
                diagnostics_truncated: false,
                work: crate::finding::PolicyWorkReport::default(),
                authored_arm_closures: Vec::new(),
            }
        }
    }
    let run = with_policy(FLOW_POLICY, |policy| {
        DefaultPolicyEvaluator::new()
            .with_taint(&TwoReasonAdapter)
            .evaluate(policy, &fixture.context(), &mut PolicyBudget::default())
            .unwrap()
    });
    let explanation =
        explain_finding(&run, &only_finding(&run), &ExplanationLimits::default()).unwrap();
    assert_eq!(
        root_child(&explanation, "path_proof").actual(),
        Some("proven: exact_call_target, dataflow_witness")
    );
}

#[test]
fn obligation_names_assertion_group_and_partition_coverage() {
    let budget = PolicyBudget::builder()
        .with_query_limits(CodeQueryExecutionLimits {
            max_pipeline_rows: 1,
            ..CodeQueryExecutionLimits::default()
        })
        .unwrap()
        .build()
        .unwrap();
    let fixture = Fixture::with_source(RELATIONAL_TWO_READS);
    let mut run = fixture.run_with_budget(FORBID_READS_RELATIONAL, budget);
    let finding = run.findings()[0].clone();
    let PolicyFindingEvidence::Assertion { evidence } = finding.evidence() else {
        panic!("assertion evidence")
    };
    let assertion = evidence.anchor().assert_id().to_string();
    for truncated in [false, true] {
        let obligation = PolicyObligation::try_new(
            &assertion,
            PolicyObligationKind::AbsenceRequiresExhaustiveCoverage,
            "by-read",
            Some("app.ts#alias"),
            vec![PolicyCoveragePartition::new("function", "app.ts")],
            truncated,
            vec![PolicyIncompleteReason::PipelineRowBudget],
        )
        .unwrap();
        run.set_obligations(&[obligation], false, 0, &PolicyBudget::default())
            .unwrap();
        let explanation =
            explain_finding(&run, &finding.id(), &ExplanationLimits::default()).unwrap();
        let node = root_child(&explanation, "absence_requires_exhaustive_coverage");
        assert_eq!(
            node.expected(),
            Some(
                format!("assertion `{assertion}` can publish a verdict for group `by-read`")
                    .as_str()
            )
        );
        assert_eq!(node.actual(), Some(format!("no verdict was published at group key `app.ts#alias` in analysis partition function `app.ts`{}", if truncated { ", ..." } else { "" }).as_str()));
    }
}
