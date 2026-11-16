use super::*;

fn diagnostic() -> PolicyReportDiagnostic {
    PolicyReportDiagnostic::try_new(
        PolicyReportDiagnosticCode::PolicyLoadFailed,
        PolicyDiagnosticSeverity::Error,
        "failed",
        Some(PolicySourceIdentity::new("input.rqlp")),
        None,
        Vec::new(),
        crate::RelatedLocationOmissions::Known(0),
    )
    .unwrap()
}

#[test]
fn pack_decision_limit_reports_only_actual_omissions() {
    for count in [
        MAX_PACK_ACTIVATION_DECISIONS,
        MAX_PACK_ACTIVATION_DECISIONS + 1,
    ] {
        let decisions = (0..count)
            .map(|i| {
                PolicyPackDecision::new(
                    format!("pack-{i}"),
                    PolicyPackDecisionStatus::Selected,
                    None,
                )
            })
            .collect();
        let review = PolicyPackActivationReview::new_with_mode(
            "packs.json".into(),
            PolicyDependencyPackActivationMode::Default,
            Vec::new(),
            true,
            decisions,
        );
        assert_eq!(review.decisions().len(), MAX_PACK_ACTIVATION_DECISIONS);
        assert_eq!(
            review.decisions_truncated(),
            count > MAX_PACK_ACTIVATION_DECISIONS
        );
    }
}

#[test]
fn registration_stops_at_the_declared_input_count() {
    let mut builder = PolicyReportBuilder::new(PolicyBatchBudget::default(), 1).unwrap();
    builder.register_primary_diagnostic(diagnostic()).unwrap();
    assert!(matches!(
        builder.register_primary_diagnostic(diagnostic()),
        Err(PolicyReportBuilderError::UnexpectedInputOutcome)
    ));
    assert_eq!(builder.finish().unwrap().diagnostics().len(), 1);
}

#[test]
fn evaluation_waits_for_all_input_outcomes() {
    let loaded = loaded_match_policy();
    let (descriptor, run) = report_skeleton();
    let mut builder = PolicyReportBuilder::new(PolicyBatchBudget::default(), 2).unwrap();
    builder.register_policy(descriptor, run).unwrap();
    assert!(matches!(
        builder.retain_policy_findings(vec![vec![report_finding(&loaded)]]),
        Err(PolicyReportBuilderError::EvaluationBeforeSkeletonsComplete)
    ));
    builder.register_primary_diagnostic(diagnostic()).unwrap();
    assert!(
        builder
            .retain_policy_findings(vec![vec![report_finding(&loaded)]])
            .unwrap()
            .is_empty()
    );
}

#[test]
fn retained_review_bytes_include_baseline_allocation() {
    use crate::baseline::parse_policy_baseline_document;
    let baseline = parse_policy_baseline_document(&serde_json::json!({
        "schema_version": 1, "reason": "Onboarding acceptance", "accepted_at": "2026-08-08", "policies": []
    }).to_string()).unwrap();
    let review = PolicyBaselineReview::new(&"x".repeat(10_000), &baseline, Vec::new());
    let packs = PolicyPackActivationReview::new_with_mode(
        "y".repeat(10_000),
        PolicyDependencyPackActivationMode::Default,
        Vec::new(),
        true,
        Vec::new(),
    );
    let exact = empty_document_retained_bytes() + retained_extra(&review) + retained_extra(&packs);
    let mut at_bound = PolicyReportBuilder::new(batch_budget_capped_at(exact), 0).unwrap();
    at_bound.set_baseline(review.clone()).unwrap();
    at_bound.set_packs(packs.clone()).unwrap();
    assert!(at_bound.finish().is_ok());
    let mut below = PolicyReportBuilder::new(batch_budget_capped_at(exact - 1), 0).unwrap();
    below.set_baseline(review).unwrap();
    assert!(
        matches!(below.set_packs(packs), Err(PolicyReportBuilderError::BatchRetentionExceeded { max_bytes, .. }) if max_bytes == exact - 1)
    );
}

#[test]
fn review_admission_accepts_exact_bound_and_rejects_one_byte_short() {
    let review = PolicyPackActivationReview::new_with_mode(
        "x".repeat(10_000),
        PolicyDependencyPackActivationMode::Default,
        Vec::new(),
        true,
        Vec::new(),
    );
    let empty = empty_document_retained_bytes();
    let exact = empty + retained_extra(&review);
    assert!(exact > minimum_construction_budget());
    let mut at_bound = PolicyReportBuilder::new(batch_budget_capped_at(exact), 0).unwrap();
    at_bound.set_packs(review.clone()).unwrap();
    assert!(at_bound.finish().is_ok());
    let mut below = PolicyReportBuilder::new(batch_budget_capped_at(exact - 1), 0).unwrap();
    assert!(
        matches!(below.set_packs(review), Err(PolicyReportBuilderError::BatchRetentionExceeded { max_bytes, .. }) if max_bytes == exact - 1)
    );
}

#[test]
fn registration_preserves_emergency_bytes_at_exact_bound() {
    let prefix = "bifrost.security.";
    let long_id = format!("{prefix}{}", "x".repeat(200 - prefix.len()));
    let source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/policies/dynamic-eval.rqlp"
    ))
    .replace("bifrost.security.dynamic-eval", &long_id);
    let loaded = load_match_policy(&source);
    let descriptor = PolicyRuleDescriptor::from_loaded(&loaded);
    let run = report_run(
        &loaded,
        PolicyAnalysisType::Match,
        PolicyRunCompletion::Complete,
    );
    let review = PolicyPackActivationReview::new_with_mode(
        "x".repeat(10_000),
        PolicyDependencyPackActivationMode::Default,
        Vec::new(),
        true,
        Vec::new(),
    );
    let budget_at = |cap| {
        let per_policy = crate::budget::PolicyBudget::builder()
            .with_max_retained_report_bytes(cap)
            .unwrap()
            .build()
            .unwrap();
        PolicyBatchBudget::builder()
            .with_max_retained_report_bytes(cap)
            .unwrap()
            .with_per_policy(per_policy)
            .unwrap()
            .build()
            .unwrap()
    };
    let can_register = |cap| {
        let Ok(mut builder) = PolicyReportBuilder::new(budget_at(cap), 1) else {
            return false;
        };
        builder.set_packs(review.clone()).is_ok()
            && builder
                .register_policy(descriptor.clone(), run.clone())
                .is_ok()
    };
    assert!(!can_register(0));
    let mut refused = 0;
    let mut admitted = 50_000;
    assert!(can_register(admitted));
    while admitted - refused > 1 {
        let mid = refused + (admitted - refused) / 2;
        if can_register(mid) {
            admitted = mid;
        } else {
            refused = mid;
        }
    }
    // Consume the ordinary execution allowance before the first omission.
    let stages = [
        PolicyExecutionStage::PolicySelection,
        PolicyExecutionStage::SuppressionPreflight,
        PolicyExecutionStage::WorkspaceSnapshot,
        PolicyExecutionStage::PolicyRegistration,
        PolicyExecutionStage::PolicyPreparation,
        PolicyExecutionStage::DiffBase,
        PolicyExecutionStage::PolicyEvaluation,
        PolicyExecutionStage::ReportConstruction,
    ]
    .into_iter()
    .map(|stage| PolicyStageTiming::new(stage, 1))
    .collect();
    let policy_id = loaded.definition().metadata.id.clone();
    let execution = PolicyExecutionMetadata::try_new(
        8,
        stages,
        Some(PolicyExecutionTermination::DeadlineExceeded),
        Some(PolicyExecutionStage::PolicyEvaluation),
        Some(policy_id.clone()),
        PolicyExecutionProgress {
            interrupted: vec![policy_id],
            ..PolicyExecutionProgress::default()
        },
    )
    .unwrap();
    // Empty policies need no hypothetical omission metadata reservation, even
    // when execution metadata has consumed the ordinary shell allowance.
    let mut empty = PolicyReportBuilder::new(budget_at(admitted), 1).unwrap();
    empty.set_packs(review.clone()).unwrap();
    empty
        .register_policy(descriptor.clone(), run.clone())
        .unwrap();
    empty.set_execution(execution.clone()).unwrap();
    assert!(
        empty
            .retain_policy_findings(vec![Vec::new()])
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        empty.finish().unwrap().runs()[0]
            .work()
            .omitted_findings_lower_bound(),
        0
    );

    // A nonempty candidate set reserves its exact admission metadata before
    // it spends any finding bytes. This reservation cannot spend emergency.
    let mut envelope = run.clone();
    envelope.reserve_admission_metadata(
        &[&report_finding(&loaded)],
        &[
            "policy/evaluator_retention",
            "policy/findings",
            "policy/retained_report_bytes",
            "batch/retained_report_bytes",
        ],
    );
    let mut refused_run = run.clone();
    refused_run
        .work_mut()
        .add_retention_omitted_findings_for_dimension("batch/retained_report_bytes", 1);
    refused_run.record_budget_refusal("batch/retained_report_bytes");
    refused_run.mark_inconclusive(PolicyIncompleteReason::ReportRetentionBudget);
    let actual_metadata = refused_run.retained_size() - run.retained_size();
    assert!(actual_metadata < envelope.retained_size() - run.retained_size());
    let admission_cap = admitted + actual_metadata;
    let mut builder = PolicyReportBuilder::new(budget_at(admission_cap), 1).unwrap();
    builder.set_packs(review.clone()).unwrap();
    builder
        .register_policy(descriptor.clone(), run.clone())
        .unwrap();
    builder.set_execution(execution.clone()).unwrap();
    let emergency = builder.emergency_allowance;
    assert_eq!(
        builder
            .retain_policy_findings(vec![vec![report_finding(&loaded)]])
            .unwrap()
            .len(),
        1
    );
    assert_eq!(builder.emergency_allowance, emergency);
    let report = builder.finish().unwrap();
    assert!(admission_cap - report.retained_size() >= EMERGENCY_DIAGNOSTIC_ALLOWANCE);
    let omitted_run = &report.runs()[0];
    assert_eq!(omitted_run.work().omitted_findings_lower_bound(), 1);
    assert_eq!(
        omitted_run.work().retention_omitted_findings_by_dimension(),
        &std::collections::BTreeMap::from([("batch/retained_report_bytes".to_owned(), 1)])
    );
    assert!(
        matches!(omitted_run.completion(), PolicyRunCompletion::Inconclusive { reasons, .. } if reasons.contains(&PolicyIncompleteReason::ReportRetentionBudget))
    );

    // The same shell has no allowance for even the actual omission metadata.
    let mut too_tight = PolicyReportBuilder::new(budget_at(admitted), 1).unwrap();
    too_tight.set_packs(review.clone()).unwrap();
    too_tight
        .register_policy(descriptor.clone(), run.clone())
        .unwrap();
    too_tight.set_execution(execution).unwrap();
    assert!(
        matches!(too_tight.retain_policy_findings(vec![vec![report_finding(&loaded)]]),
        Err(PolicyReportBuilderError::BatchRetentionExceeded { retained_bytes, max_bytes }) if max_bytes == admitted && retained_bytes > max_bytes)
    );

    let mut below = PolicyReportBuilder::new(budget_at(admitted - 1), 1).unwrap();
    below.set_packs(review).unwrap();
    assert!(matches!(below.register_policy(descriptor, run),
        Err(PolicyReportBuilderError::BatchRetentionExceeded { max_bytes, .. })
            if max_bytes == admitted - 1));
}

#[test]
fn candidate_finding_reserves_incomplete_reason_bytes() {
    let loaded = loaded_match_policy();
    let (descriptor, run) = report_skeleton();
    let finding = report_finding(&loaded);
    let mut candidate = run.clone();
    candidate.replace_findings(vec![finding.clone()]);
    let candidate_bytes = descriptor.retained_size() + candidate.retained_size();
    let cap = candidate_bytes + PER_POLICY_INCOMPLETE_REASON_ALLOWANCE - 1;
    let per_policy = crate::budget::PolicyBudget::builder()
        .with_max_retained_report_bytes(cap)
        .unwrap()
        .build()
        .unwrap();
    let budget = PolicyBatchBudget::builder()
        .with_per_policy(per_policy)
        .unwrap()
        .build()
        .unwrap();
    let mut builder = PolicyReportBuilder::new(budget, 1).unwrap();
    builder.register_policy(descriptor, run).unwrap();
    assert_eq!(
        builder
            .retain_policy_findings(vec![vec![finding]])
            .unwrap()
            .len(),
        1
    );
    let document = builder.finish().unwrap();
    assert!(
        matches!(document.runs()[0].completion(), PolicyRunCompletion::Inconclusive { reasons, .. } if reasons.contains(&PolicyIncompleteReason::ReportRetentionBudget))
    );
}

fn another_match_policy() -> LoadedPolicy {
    let source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/policies/dynamic-eval.rqlp"
    ))
    .replace(
        "bifrost.security.dynamic-eval",
        "bifrost.security.other-eval",
    );
    load_match_policy(&source)
}

#[test]
fn a_run_lookup_requires_both_policy_id_and_hash() {
    let first = loaded_match_policy();
    let second = another_match_policy();
    let mut builder = PolicyReportBuilder::new(PolicyBatchBudget::default(), 2).unwrap();
    builder
        .register_policy(
            report_skeleton().0,
            report_run(
                &first,
                PolicyAnalysisType::Match,
                PolicyRunCompletion::Complete,
            ),
        )
        .unwrap();
    builder
        .register_policy(
            PolicyRuleDescriptor::from_loaded(&second),
            report_run(
                &second,
                PolicyAnalysisType::Match,
                PolicyRunCompletion::Complete,
            ),
        )
        .unwrap();
    assert!(matches!(
        builder.retain_run_diagnostic(
            &first.definition().metadata.id,
            second.semantic_hash(),
            run_diagnostic("wrong hash")
        ),
        Err(PolicyReportBuilderError::UnknownPolicyRun)
    ));
    builder
        .retain_policy_findings(vec![vec![report_finding(&second)]])
        .unwrap();
    let report = builder.finish().unwrap();
    assert_eq!(
        report
            .runs()
            .iter()
            .find(|run| run.policy_id() == &second.definition().metadata.id)
            .unwrap()
            .findings()
            .len(),
        1
    );
    assert!(
        report
            .runs()
            .iter()
            .find(|run| run.policy_id() == &first.definition().metadata.id)
            .unwrap()
            .findings()
            .is_empty()
    );
}

#[test]
fn finish_requires_every_declared_input_outcome() {
    let mut builder = PolicyReportBuilder::new(PolicyBatchBudget::default(), 2).unwrap();
    builder.register_primary_diagnostic(diagnostic()).unwrap();
    assert!(matches!(
        builder.finish(),
        Err(PolicyReportBuilderError::InputsNotFullyRegistered {
            expected: 2,
            registered: 1
        })
    ));
}

#[test]
fn final_document_uses_the_full_retained_byte_budget() {
    let review = PolicyPackActivationReview::new_with_mode(
        "x".repeat(10_000),
        PolicyDependencyPackActivationMode::Default,
        Vec::new(),
        true,
        Vec::new(),
    );
    let exact = empty_document_retained_bytes() + retained_extra(&review);
    let mut builder = PolicyReportBuilder::new(batch_budget_capped_at(exact), 0).unwrap();
    builder.set_packs(review).unwrap();
    assert_eq!(builder.finish().unwrap().retained_size(), exact);
}

#[test]
fn primary_diagnostic_uses_the_full_input_allowance() {
    let large = PolicyReportDiagnostic::try_new(
        PolicyReportDiagnosticCode::PolicyLoadFailed,
        PolicyDiagnosticSeverity::Error,
        "x".repeat(MAX_REPORT_TEXT_BYTES),
        Some(PolicySourceIdentity::new("input.rqlp")),
        None,
        Vec::new(),
        crate::RelatedLocationOmissions::Known(0),
    )
    .unwrap();
    assert!(large.retained_size() > SKELETON_ALLOWANCE_PER_INPUT / 2);
    assert!(large.retained_size() <= SKELETON_ALLOWANCE_PER_INPUT);
    let mut builder = PolicyReportBuilder::new(PolicyBatchBudget::default(), 1).unwrap();
    builder.register_primary_diagnostic(large).unwrap();
    assert_eq!(builder.finish().unwrap().diagnostics().len(), 1);
}

fn run_diagnostic(message: &str) -> PolicyDiagnostic {
    PolicyDiagnostic::try_new(
        PolicyDiagnosticCode::StableAnchorUnavailable,
        PolicyDiagnosticSeverity::Note,
        PolicyDiagnosticImpact::Advisory,
        message,
        None,
        Vec::new(),
        crate::RelatedLocationOmissions::Known(0),
    )
    .unwrap()
}

#[test]
fn run_diagnostic_cap_keeps_two_distinct_reasons() {
    let loaded = loaded_match_policy();
    let (descriptor, run) = report_skeleton();
    let mut builder = PolicyReportBuilder::new(PolicyBatchBudget::default(), 1).unwrap();
    builder.register_policy(descriptor, run).unwrap();
    for message in ["first reason", "second reason"] {
        assert_eq!(
            builder
                .retain_run_diagnostic(
                    &loaded.definition().metadata.id,
                    loaded.semantic_hash(),
                    run_diagnostic(message)
                )
                .unwrap(),
            PolicyRetentionOutcome::Retained
        );
    }
    let report = builder.finish().unwrap();
    let run = &report.runs()[0];
    assert_eq!(run.diagnostics().len(), 2);
    assert!(!run.diagnostics_truncated());
}

#[test]
fn candidate_reports_the_full_retained_policy_bytes() {
    let loaded = loaded_match_policy();
    let (descriptor, run) = report_skeleton();
    let mut builder = PolicyReportBuilder::new(PolicyBatchBudget::default(), 1).unwrap();
    builder.register_policy(descriptor, run).unwrap();
    builder
        .retain_policy_findings(vec![vec![report_finding(&loaded)]])
        .unwrap();
    let report = builder.finish().unwrap();
    let expected = report.rules()[0].retained_size() + report.runs()[0].retained_size();
    assert_eq!(
        report.runs()[0].work().retained_report_bytes() as usize,
        expected
    );
}

#[test]
fn batch_finding_count_does_not_refuse_later_policies() {
    let policies = (0..11).map(retention_policy).collect::<Vec<_>>();
    let candidates = policies
        .iter()
        .map(|policy| {
            (0..1000)
                .map(|i| retention_candidate(policy, i, 16, "detail"))
                .collect()
        })
        .collect();
    let mut builder = retention_builder(&policies, 64 * 1024 * 1024);
    assert!(
        builder
            .retain_policy_findings(candidates)
            .unwrap()
            .is_empty()
    );
    let report = builder.finish().unwrap();
    assert_eq!(
        report
            .runs()
            .iter()
            .map(|run| run.findings().len())
            .sum::<usize>(),
        11_000
    );
    assert!(
        report
            .runs()
            .iter()
            .all(|run| run.work().omitted_findings_lower_bound() == 0)
    );
}

#[test]
fn execution_metadata_is_charged_before_it_is_attached() {
    let review = PolicyPackActivationReview::new_with_mode(
        "x".repeat(10_000),
        PolicyDependencyPackActivationMode::Default,
        Vec::new(),
        true,
        Vec::new(),
    );
    let execution = PolicyExecutionMetadata::try_new(
        1,
        vec![PolicyStageTiming::new(
            PolicyExecutionStage::PolicySelection,
            1,
        )],
        None,
        None,
        None,
        PolicyExecutionProgress::default(),
    )
    .unwrap();
    let exact =
        empty_document_retained_bytes() + retained_extra(&review) + retained_extra(&execution);
    for (cap, accepted) in [(exact, true), (exact - 1, false)] {
        let mut builder = PolicyReportBuilder::new(batch_budget_capped_at(cap), 0).unwrap();
        builder.set_packs(review.clone()).unwrap();
        let result = builder.set_execution(execution.clone());
        if accepted {
            result.unwrap();
            assert_eq!(
                builder.finish().unwrap().execution().stage_timings().len(),
                1
            );
        } else {
            assert!(
                matches!(result, Err(PolicyReportBuilderError::BatchRetentionExceeded { max_bytes, .. }) if max_bytes == cap)
            );
        }
    }
}

#[test]
fn suppression_omission_joins_policy_and_finding() {
    let source = format!(
        r#"{{"schema_version":1,"suppressions":[
            {{"policy_id":"bifrost.security.dynamic-eval","finding_id":"{}","identity_stability":"strong","status":"accepted","reason":"Reviewed","accepted_at":"2026-07-01"}},
            {{"policy_id":"bifrost.security.dynamic-eval","finding_id":"{}","identity_stability":"strong","status":"accepted","reason":"Reviewed","accepted_at":"2026-07-01"}}
        ]}}"#,
        "1".repeat(64),
        "2".repeat(64),
    );
    let document = parse_policy_suppression_document(&source).unwrap();
    let reviews = document
        .suppressions()
        .iter()
        .map(|record| {
            PolicySuppressionReview::new(
                record,
                PolicySuppressionMatchState::StrongFinding,
                PolicySuppressionTemporalState::Current,
                PolicySuppressionPolicyHashState::Unknown,
                PolicySuppressionOrphanState::Resolved,
                Vec::new(),
            )
        })
        .collect();
    let mut builder = PolicyReportBuilder::new_with_suppression_audit(
        PolicyBatchBudget::default(),
        0,
        default_test_evaluation_context(),
        reviews,
        Vec::new(),
    )
    .unwrap();
    let policy = PolicyId::new("bifrost.security.dynamic-eval").unwrap();
    for digit in ["1", "2"] {
        let finding = digit.repeat(64).parse::<PolicyFindingId>().unwrap();
        builder
            .mark_suppression_result_omitted(&policy, finding)
            .unwrap();
    }
    assert!(
        builder
            .finish()
            .unwrap()
            .suppressions()
            .iter()
            .all(PolicySuppressionReview::result_omitted)
    );
}

#[test]
fn diagnostic_truncation_metadata_must_agree() {
    for (truncated, omitted, severity) in [
        (true, 1, None),
        (true, 0, Some(PolicyDiagnosticSeverity::Error)),
        (false, 1, None),
    ] {
        let result = PolicyReportDocument::try_new_with_execution(
            default_test_evaluation_context(),
            PolicyExecutionMetadata::default(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            PolicyOptionalReviews::default(),
            Vec::new(),
            truncated,
            omitted,
            severity,
        );
        assert!(matches!(
            result,
            Err(PolicyReportDocumentError::InconsistentDiagnosticTruncation)
        ));
    }
    assert!(
        PolicyReportDocument::try_new_with_execution(
            default_test_evaluation_context(),
            PolicyExecutionMetadata::default(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            PolicyOptionalReviews::default(),
            Vec::new(),
            true,
            1,
            Some(PolicyDiagnosticSeverity::Error),
        )
        .is_ok()
    );
}

#[test]
fn diagnostic_messages_make_report_order_independent_of_input_order() {
    let first = PolicyReportDiagnostic::try_new(
        PolicyReportDiagnosticCode::PolicyLoadFailed,
        PolicyDiagnosticSeverity::Error,
        "alpha",
        Some(PolicySourceIdentity::new("input.rqlp")),
        None,
        Vec::new(),
        crate::RelatedLocationOmissions::Known(0),
    )
    .unwrap();
    let second = PolicyReportDiagnostic::try_new(
        PolicyReportDiagnosticCode::PolicyLoadFailed,
        PolicyDiagnosticSeverity::Error,
        "beta",
        Some(PolicySourceIdentity::new("input.rqlp")),
        None,
        Vec::new(),
        crate::RelatedLocationOmissions::Known(0),
    )
    .unwrap();
    let mut outputs = Vec::new();
    for diagnostics in [
        [first.clone(), second.clone()],
        [second.clone(), first.clone()],
    ] {
        let mut builder = PolicyReportBuilder::new(PolicyBatchBudget::default(), 2).unwrap();
        for diagnostic in diagnostics {
            builder.register_primary_diagnostic(diagnostic).unwrap();
        }
        outputs.push(serde_json::to_value(builder.finish().unwrap()).unwrap());
    }
    assert_eq!(outputs[0], outputs[1]);
}

#[test]
fn related_diagnostic_ranges_make_report_order_independent_of_input_order() {
    let diagnostic_with_end = |end| {
        PolicyReportDiagnostic::try_new(
            PolicyReportDiagnosticCode::PolicyLoadFailed,
            PolicyDiagnosticSeverity::Error,
            "same",
            Some(PolicySourceIdentity::new("input.rqlp")),
            None,
            vec![PolicySourceRelatedDiagnostic {
                source: PolicySourceIdentity::new("related.rqlp"),
                range: 1..end,
                message: "related".into(),
            }],
            crate::RelatedLocationOmissions::Known(0),
        )
        .unwrap()
    };
    let first = diagnostic_with_end(2);
    let second = diagnostic_with_end(3);
    let mut outputs = Vec::new();
    for diagnostics in [
        [first.clone(), second.clone()],
        [second.clone(), first.clone()],
    ] {
        let mut builder = PolicyReportBuilder::new(PolicyBatchBudget::default(), 2).unwrap();
        for diagnostic in diagnostics {
            builder.register_primary_diagnostic(diagnostic).unwrap();
        }
        outputs.push(serde_json::to_value(builder.finish().unwrap()).unwrap());
    }
    assert_eq!(outputs[0], outputs[1]);
}

#[test]
fn preflight_counts_allocated_rule_slots_at_exact_bound() {
    let evaluation = default_test_evaluation_context();
    let base = report_storage_size(
        &evaluation,
        &Vec::<PolicyRuleDescriptor>::new(),
        &Vec::<PolicyRun>::with_capacity(1),
        &Vec::new(),
        &Vec::new(),
        &Vec::<PolicyReportDiagnostic>::with_capacity(1),
    );
    // Construction allocates one rule slot even before any rule is registered.
    let required = base
        + size_of::<PolicyRuleDescriptor>()
        + SKELETON_ALLOWANCE_PER_INPUT
        + PolicyExecutionMetadata::maximum_retained_size(1)
        + EMERGENCY_DIAGNOSTIC_ALLOWANCE;
    assert!(PolicyReportBuilder::new(batch_budget_capped_at(required), 1).is_ok());
    assert!(matches!(
        PolicyReportBuilder::new(batch_budget_capped_at(required - 1), 1),
        Err(PolicyReportBuilderError::SkeletonPreflightExceeded { required_bytes, max_bytes })
            if required_bytes == required && max_bytes == required - 1
    ));
}

#[test]
fn finished_report_retained_size_includes_run_storage() {
    let (descriptor, run) = report_skeleton();
    let mut builder = PolicyReportBuilder::new(PolicyBatchBudget::default(), 1).unwrap();
    builder.register_policy(descriptor, run).unwrap();
    let report = builder.finish().unwrap();
    let expected = report_storage_size(
        &report.evaluation,
        &report.rules,
        &report.runs,
        &report.suppressions,
        &report.scope,
        &report.diagnostics,
    ) + retained_extra(&report.execution)
        + retained_extra(&report.reviews);
    assert_eq!(report.retained_size(), expected);
    assert!(retained_extra(&report.runs) > 0);
}

#[test]
fn applied_suppression_requires_a_suppressed_finding() {
    let loaded = loaded_match_policy();
    let finding = report_finding(&loaded);
    let source = format!(
        r#"{{"schema_version":1,"suppressions":[{{"policy_id":"{}","finding_id":"{}","identity_stability":"strong","status":"accepted","reason":"Reviewed","accepted_at":"2026-07-01"}}]}}"#,
        finding.policy_id(),
        finding.id(),
    );
    let document = parse_policy_suppression_document(&source).unwrap();
    let review = PolicySuppressionReview::new(
        &document.suppressions()[0],
        PolicySuppressionMatchState::StrongFinding,
        PolicySuppressionTemporalState::Current,
        PolicySuppressionPolicyHashState::Matching,
        PolicySuppressionOrphanState::Resolved,
        Vec::new(),
    );
    for attached in [false, true] {
        let mut finding = finding.clone();
        if attached {
            finding
                .attach_suppression(review.finding_suppression().unwrap())
                .unwrap();
        }
        let mut builder = PolicyReportBuilder::new_with_suppression_audit(
            PolicyBatchBudget::default(),
            1,
            default_test_evaluation_context(),
            vec![review.clone()],
            Vec::new(),
        )
        .unwrap();
        builder
            .register_policy(
                report_skeleton().0,
                report_run(
                    &loaded,
                    PolicyAnalysisType::Match,
                    PolicyRunCompletion::Complete,
                ),
            )
            .unwrap();
        builder.retain_policy_findings(vec![vec![finding]]).unwrap();
        let result = builder.finish();
        if attached {
            assert!(result.is_ok());
        } else {
            assert!(matches!(
                result,
                Err(PolicyReportBuilderError::Document(
                    PolicyReportDocumentError::MissingSuppressedFinding { .. }
                ))
            ));
        }
    }
}

#[test]
fn scope_join_requires_an_applied_review() {
    let scope_document = crate::scope::parse_policy_scope_document(
        r#"{"schema_version":1,"scopes":[{"path":"src","reason":"Reviewed"}]}"#,
    )
    .unwrap();
    let entry = &scope_document.scopes()[0];
    let loaded = loaded_match_policy();
    for applied in [false, true] {
        let mut finding = report_finding(&loaded);
        finding.attach_scope(entry.finding_scope()).unwrap();
        let review = PolicyScopeReview::new(entry, u64::from(applied));
        let mut builder = PolicyReportBuilder::new_with_suppression_audit(
            PolicyBatchBudget::default(),
            1,
            default_test_evaluation_context(),
            Vec::new(),
            vec![review],
        )
        .unwrap();
        builder
            .register_policy(
                report_skeleton().0,
                report_run(
                    &loaded,
                    PolicyAnalysisType::Match,
                    PolicyRunCompletion::Complete,
                ),
            )
            .unwrap();
        builder.retain_policy_findings(vec![vec![finding]]).unwrap();
        let result = builder.finish();
        if applied {
            assert!(result.is_ok());
        } else {
            assert!(matches!(
                result,
                Err(PolicyReportBuilderError::Document(
                    PolicyReportDocumentError::ScopedFindingWithoutReview { .. }
                ))
            ));
        }
    }
}

#[test]
fn baseline_join_subtracts_omitted_results() {
    use crate::baseline::{
        PolicyBaselineEntryReview, PolicyBaselineMatchState, PolicyFindingBaseline,
        parse_policy_baseline_document,
    };
    let loaded = loaded_match_policy();
    let finding = report_finding(&loaded);
    let absent_id = "a".repeat(64).parse::<PolicyFindingId>().unwrap();
    let source = serde_json::json!({
        "schema_version": 1, "reason": "Reviewed", "accepted_at": "2026-08-08",
        "policies": [{"policy_id": finding.policy_id().as_str(), "finding_ids": [finding.id().to_string(), absent_id.to_string()]}],
    }).to_string();
    let document = parse_policy_baseline_document(&source).unwrap();
    let entries = [finding.id(), absent_id]
        .into_iter()
        .map(|id| {
            PolicyBaselineEntryReview::new(
                finding.policy_id().clone(),
                id,
                PolicyBaselineMatchState::StrongFinding,
                PolicySuppressionPolicyHashState::Matching,
            )
        })
        .collect();
    let review = PolicyBaselineReview::new("baseline.json", &document, entries);
    let make_builder = || {
        let mut finding = finding.clone();
        finding
            .attach_baseline(PolicyFindingBaseline::new(
                &document,
                PolicySuppressionPolicyHashState::Matching,
            ))
            .unwrap();
        let mut builder = PolicyReportBuilder::new(PolicyBatchBudget::default(), 1).unwrap();
        builder
            .register_policy(
                report_skeleton().0,
                report_run(
                    &loaded,
                    PolicyAnalysisType::Match,
                    PolicyRunCompletion::Complete,
                ),
            )
            .unwrap();
        builder.retain_policy_findings(vec![vec![finding]]).unwrap();
        builder.set_baseline(review.clone()).unwrap();
        builder
    };
    let rejected = make_builder().finish();
    assert!(matches!(
        rejected,
        Err(PolicyReportBuilderError::Document(
            PolicyReportDocumentError::BaselineAppliedJoinMismatch {
                attached: 1,
                applied_count: 2,
                result_omitted_count: 0
            }
        ))
    ));
    let mut accepted = make_builder();
    accepted
        .mark_baseline_result_omitted(finding.policy_id(), absent_id)
        .unwrap();
    let report = accepted.finish().unwrap();
    assert_eq!(report.baseline().unwrap().applied_count(), 2);
    assert_eq!(report.baseline().unwrap().result_omitted_count(), 1);
    assert_eq!(report.runs()[0].findings().len(), 1);
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#11321: omitted diagnostics lost original lanes and simultaneous policy/batch byte cuts"
)]
fn budget_telemetry_survives_omitted_run_diagnostic() {
    let loaded = loaded_match_policy();
    for (batch_limit, expected) in [
        (
            16 * 1024,
            vec![
                "batch/retained_report_bytes",
                "policy/retained_report_bytes",
                "query/fact_nodes",
            ],
        ),
        (
            64 * 1024 * 1024,
            vec!["policy/retained_report_bytes", "query/fact_nodes"],
        ),
    ] {
        let per_policy = crate::budget::PolicyBudget::builder()
            .with_max_retained_report_bytes(4096)
            .unwrap()
            .build()
            .unwrap();
        let budget = PolicyBatchBudget::builder()
            .with_max_retained_report_bytes(batch_limit)
            .unwrap()
            .with_per_policy(per_policy)
            .unwrap()
            .build()
            .unwrap();
        let mut builder = PolicyReportBuilder::new(budget, 1).unwrap();
        builder
            .register_policy(
                PolicyRuleDescriptor::from_loaded(&loaded),
                report_run(
                    &loaded,
                    PolicyAnalysisType::Match,
                    PolicyRunCompletion::inconclusive(vec![
                        PolicyIncompleteReason::PartialDiscovery,
                    ])
                    .unwrap(),
                ),
            )
            .unwrap();
        let diagnostic = PolicyDiagnostic::try_new(
            PolicyDiagnosticCode::CodeQuery {
                code:
                    brokk_bifrost_rql::structural::CodeQueryDiagnosticCode::ExecutionBudgetExhausted
                        .try_into()
                        .unwrap(),
            },
            PolicyDiagnosticSeverity::Error,
            PolicyDiagnosticImpact::RunIncomplete,
            "x".repeat(4096),
            None,
            (0..64)
                .map(|index| {
                    crate::finding::RelatedPolicyLocation::try_new(
                        crate::finding::PolicyLocationRelationship::Evidence,
                        crate::test_support::policy_test_location(
                            &format!("src/{}/site{index}.rs", "x".repeat(200)),
                            0,
                            1,
                            1,
                        ),
                        Vec::new(),
                    )
                    .unwrap()
                })
                .collect(),
            crate::RelatedLocationOmissions::Known(0),
        )
        .unwrap()
        .with_exhausted_roots(vec![
            brokk_bifrost_rql::structural::CodeQueryExhaustedRoot {
                path: ".".to_string(),
                procedure: None,
                lane: "query/fact_nodes".to_string(),
                stage: None,
                budget: None,
                charge: None,
                feedback_iteration: None,
            },
        ]);
        assert_eq!(
            builder
                .retain_run_diagnostic(
                    &loaded.definition().metadata.id,
                    loaded.semantic_hash(),
                    diagnostic
                )
                .unwrap(),
            PolicyRetentionOutcome::DiagnosticOmitted
        );
        let report = builder.finish().unwrap();
        assert_eq!(report.runs()[0].budget_refusals(), expected);
        assert_eq!(
            report.runs()[0].worst_omitted_diagnostic_severity(),
            Some(PolicyDiagnosticSeverity::Error)
        );
        assert_eq!(
            serde_json::to_value(report.runs()[0].diagnostic_causes()).unwrap(),
            serde_json::json!([{ "code": "execution_budget_exhausted", "impact": "run_incomplete", "execution_cause": "unknown" }])
        );
    }
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#11321: simultaneous policy and batch finding cuts reported only the batch lane"
)]
fn budget_telemetry_reports_each_reached_finding_limit() {
    let loaded = loaded_match_policy();
    let per_policy = crate::budget::PolicyBudget::builder()
        .with_max_findings(0)
        .unwrap()
        .build()
        .unwrap();
    let budget = PolicyBatchBudget::builder()
        .with_per_policy(per_policy)
        .unwrap()
        .build()
        .unwrap();
    let mut builder = PolicyReportBuilder::new(budget, 1).unwrap();
    let (descriptor, run) = report_skeleton();
    builder.register_policy(descriptor, run).unwrap();
    assert_eq!(
        builder
            .retain_policy_findings(vec![vec![report_finding(&loaded)]])
            .unwrap()
            .len(),
        1
    );
    let report = builder.finish().unwrap();
    assert_eq!(report.runs()[0].budget_refusals(), ["policy/findings"]);
    assert!(report.runs()[0].findings().is_empty());
}

#[test]
// Hard-won: #12089 interaction: a finding-ID collision crossed retention accounting.
#[brokk_bifrost_test_macros::hardwon(
    "#12089: interaction: partial suppression-group retention rejected a surviving sibling"
)]
fn partially_retained_suppressed_collision_group_keeps_valid_audit() {
    let loaded = loaded_match_policy();
    let mut finding = report_finding(&loaded);
    let document = parse_policy_suppression_document(
        &serde_json::json!({
            "schema_version": 1, "suppressions": [{
                "policy_id": finding.policy_id(), "finding_id": finding.id(),
                "identity_stability": "strong", "status": "accepted", "reason": "Reviewed",
                "accepted_at": "2026-07-01"
            }]
        })
        .to_string(),
    )
    .unwrap();
    let review = PolicySuppressionReview::new(
        &document.suppressions()[0],
        PolicySuppressionMatchState::StrongFinding,
        PolicySuppressionTemporalState::Current,
        PolicySuppressionPolicyHashState::Unknown,
        PolicySuppressionOrphanState::Resolved,
        Vec::new(),
    );
    finding
        .attach_suppression(review.finding_suppression().unwrap())
        .unwrap();
    for record_omission in [false, true] {
        let (descriptor, mut run) = report_skeleton();
        run.replace_findings(vec![finding.clone()]);
        if record_omission {
            run.add_retention_omitted_findings(1);
            run.mark_inconclusive(PolicyIncompleteReason::ReportRetentionBudget);
        }
        let mut review = review.clone();
        review.mark_result_omitted();
        let result = PolicyReportDocument::try_new_with_suppression_audit(
            default_test_evaluation_context(),
            vec![descriptor],
            vec![run],
            vec![review],
            Vec::new(),
            false,
            0,
            None,
        );
        assert_eq!(
            result.is_ok(),
            record_omission,
            "recorded omission: {record_omission}: {result:?}"
        );
    }
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#12105: per-policy byte admission shed unrelated policies' optional detail"
)]
fn per_policy_byte_refusal_preserves_other_runs_detail() {
    use serde::de::DeserializeSeed;
    let loaded = loaded_match_policy();
    let other = another_match_policy();
    let make = |policy: &LoadedPolicy, label: &str| {
        let finding = report_finding(policy);
        let related = crate::finding::RelatedPolicyLocation::try_new(
            crate::finding::PolicyLocationRelationship::Evidence,
            finding.primary().clone(),
            Vec::new(),
        )
        .unwrap()
        .with_label(label.to_owned())
        .unwrap();
        let mut wire = serde_json::to_value(&finding).unwrap();
        wire["related"] = serde_json::json!([related]);
        crate::finding::PolicyFindingSeed::new(&crate::budget::PolicyBudget::default())
            .deserialize(wire)
            .unwrap()
    };
    let descriptor = PolicyRuleDescriptor::from_loaded(&loaded);
    let mut minimal = report_run(
        &loaded,
        PolicyAnalysisType::Match,
        PolicyRunCompletion::Complete,
    );
    minimal.replace_findings(vec![report_finding(&loaded)]);
    let cap = descriptor.retained_size()
        + minimal.retained_size()
        + PER_POLICY_INCOMPLETE_REASON_ALLOWANCE
        + 2048;
    let budget = PolicyBatchBudget::builder()
        .with_per_policy(
            crate::budget::PolicyBudget::builder()
                .with_max_retained_report_bytes(cap)
                .unwrap()
                .build()
                .unwrap(),
        )
        .unwrap()
        .build()
        .unwrap();
    let mut builder = PolicyReportBuilder::new(budget, 2).unwrap();
    for policy in [&loaded, &other] {
        builder
            .register_policy(
                PolicyRuleDescriptor::from_loaded(policy),
                report_run(
                    policy,
                    PolicyAnalysisType::Match,
                    PolicyRunCompletion::Complete,
                ),
            )
            .unwrap();
    }
    let unaffected = make(&other, "retained source context");
    assert!(
        builder
            .retain_policy_findings(vec![
                vec![unaffected.clone()],
                vec![make(&loaded, &"x".repeat(2048))]
            ])
            .unwrap()
            .is_empty()
    );
    let document = builder.finish().unwrap();
    let run = document
        .runs()
        .iter()
        .find(|run| run.policy_id() == &other.definition().metadata.id)
        .unwrap();
    assert_eq!(
        serde_json::to_value(run.findings()).unwrap(),
        serde_json::json!([unaffected])
    );
    assert!(matches!(run.completion(), PolicyRunCompletion::Complete));
    assert!(run.diagnostic_causes().iter().next().is_none());
}

fn retention_policy(index: usize) -> LoadedPolicy {
    load_match_policy(
        &include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/policies/dynamic-eval.rqlp"
        ))
        .replace(
            "bifrost.security.dynamic-eval",
            &format!("test.retention.p{index:03}"),
        ),
    )
}

fn retention_candidate(
    policy: &LoadedPolicy,
    index: usize,
    message_bytes: usize,
    detail: &str,
) -> PolicyFinding {
    use serde::de::DeserializeSeed;
    let anchor = MatchFindingAnchor::strong(
        MatchResultDomain::CallSite,
        WorkspaceRelativePath::new("src/app.rs").unwrap(),
        None,
        Some(SourceSliceHash::from_bytes([5; 32])),
        index as u32,
    )
    .unwrap();
    let finding = report_finding_with_anchor(policy, anchor, FindingCompleteness::Complete);
    let related = crate::finding::RelatedPolicyLocation::try_new(
        crate::finding::PolicyLocationRelationship::Evidence,
        finding.primary().clone(),
        Vec::new(),
    )
    .unwrap()
    .with_label(detail.to_owned())
    .unwrap();
    let mut wire = serde_json::to_value(&finding).unwrap();
    wire["message"] = serde_json::json!("x".repeat(message_bytes));
    wire["related"] = serde_json::json!([related]);
    crate::finding::PolicyFindingSeed::new(&crate::budget::PolicyBudget::default())
        .deserialize(wire)
        .unwrap()
}

fn retention_builder(policies: &[LoadedPolicy], cap: usize) -> PolicyReportBuilder {
    let budget = PolicyBatchBudget::builder()
        .with_max_retained_report_bytes(cap)
        .unwrap()
        .with_per_policy(
            crate::budget::PolicyBudget::builder()
                .with_max_retained_report_bytes(cap.min(16 * 1024 * 1024))
                .unwrap()
                .build()
                .unwrap(),
        )
        .unwrap()
        .build()
        .unwrap();
    let mut builder = PolicyReportBuilder::new(budget, policies.len()).unwrap();
    for policy in policies {
        builder
            .register_policy(
                PolicyRuleDescriptor::from_loaded(policy),
                report_run(
                    policy,
                    PolicyAnalysisType::Match,
                    PolicyRunCompletion::Complete,
                ),
            )
            .unwrap();
    }
    builder
}

fn retention_base_and_metadata(
    builder: &PolicyReportBuilder,
    findings: &[Vec<PolicyFinding>],
) -> usize {
    let base = report_storage_size(
        &builder.evaluation,
        &builder.rules,
        &builder.runs,
        &builder.suppressions,
        &builder.scope,
        &builder.diagnostics,
    ) + builder.reviews_extra()
        + builder.outstanding_skeleton_allowance
        + builder.emergency_allowance;
    base + builder
        .runs
        .iter()
        .zip(findings)
        .map(|(run, findings)| {
            let mut envelope = run.clone();
            envelope.reserve_admission_metadata(
                &findings.iter().collect::<Vec<_>>(),
                &[
                    "policy/evaluator_retention",
                    "policy/findings",
                    "policy/retained_report_bytes",
                    "batch/retained_report_bytes",
                ],
            );
            envelope.retained_size() - run.retained_size()
        })
        .sum::<usize>()
}

#[test]
fn fair_prefix_keeps_small_policies_complete_with_detail_independent_of_arrival() {
    let policies = (0..4).map(retention_policy).collect::<Vec<_>>();
    let candidates = policies
        .iter()
        .enumerate()
        .map(|(i, policy)| {
            (0..if i == 0 { 100 } else { 1 })
                .map(|j| {
                    retention_candidate(
                        policy,
                        j,
                        if i == 0 { 4096 } else { 32 },
                        if i == 0 {
                            "dominant detail"
                        } else {
                            "small detail"
                        },
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let probe = retention_builder(&policies, 64 * 1024 * 1024);
    let mut stripped = candidates[0][0].clone();
    stripped.omit_optional_detail();
    let cap = retention_base_and_metadata(&probe, &candidates)
        + candidates[1..]
            .iter()
            .map(|p| {
                let mut f = p[0].clone();
                f.omit_optional_detail();
                f.retained_size()
            })
            .sum::<usize>()
        + 5 * stripped.retained_size()
        + stripped.retained_size() / 2;
    let mut builder = retention_builder(&policies, cap);
    let omitted = builder.retain_policy_findings(candidates.clone()).unwrap();
    let report = builder.finish().unwrap();
    assert_eq!(report.runs()[0].findings().len(), 5);
    assert_eq!(omitted.len(), 95);
    assert_eq!(
        report.runs()[0]
            .work()
            .retention_omitted_findings_by_dimension(),
        &std::collections::BTreeMap::from([("batch/retained_report_bytes".to_string(), 95)])
    );
    for (run, expected) in report.runs()[1..].iter().zip(&candidates[1..]) {
        assert!(matches!(run.completion(), PolicyRunCompletion::Complete));
        assert_eq!(
            serde_json::to_value(run.findings()).unwrap(),
            serde_json::to_value(expected).unwrap()
        );
    }
    let mut reversed_policies = policies;
    reversed_policies.reverse();
    let mut reversed = candidates;
    reversed.reverse();
    for policy in &mut reversed {
        policy.reverse();
    }
    let mut builder = retention_builder(&reversed_policies, cap);
    builder.retain_policy_findings(reversed).unwrap();
    assert_eq!(
        serde_json::to_value(&report).unwrap(),
        serde_json::to_value(builder.finish().unwrap()).unwrap()
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#12089: interaction: ID-keyed rollback deleted prior colliding records"
)]
fn rejected_duplicate_preserves_all_prior_records_and_detail() {
    use serde::de::DeserializeSeed;
    let policies = vec![retention_policy(0)];
    let admitted = retention_candidate(&policies[0], 0, 32, "retained source context");
    let mut wire = serde_json::to_value(&admitted).unwrap();
    wire["message"] = serde_json::json!("z".repeat(4000));
    let refused = crate::finding::PolicyFindingSeed::new(&crate::budget::PolicyBudget::default())
        .deserialize(wire)
        .unwrap();
    assert_eq!(admitted.id(), refused.id());
    let candidates = vec![vec![refused.clone(), admitted.clone(), admitted.clone()]];
    let mut builder = retention_builder(&policies, 100_000);
    let base = retention_base_and_metadata(&builder, &candidates);
    let review_at = |length| {
        PolicyPackActivationReview::new_with_mode(
            "x".repeat(length),
            PolicyDependencyPackActivationMode::Default,
            Vec::new(),
            true,
            Vec::new(),
        )
    };
    let review_fixed = retained_extra(&review_at(1)) - 1;
    let path_bytes = builder.budget.max_retained_report_bytes()
        - base
        - review_fixed
        - 2 * admitted.retained_size();
    builder.set_packs(review_at(path_bytes)).unwrap();
    let omitted = builder.retain_policy_findings(candidates).unwrap();
    assert_eq!(omitted, vec![refused]);
    let report = builder.finish().unwrap();
    let run = &report.runs()[0];
    // Exact equality includes every optional-detail field of both siblings.
    assert_eq!(run.findings(), &[admitted.clone(), admitted]);
    assert_eq!(
        run.work().retention_omitted_findings_by_dimension(),
        &std::collections::BTreeMap::from([("batch/retained_report_bytes".to_owned(), 1)])
    );
    assert_eq!(run.budget_refusals(), ["batch/retained_report_bytes"]);
    assert!(
        run.diagnostics()
            .iter()
            .any(|diagnostic| { diagnostic.code() == &PolicyDiagnosticCode::DuplicateFindingId })
    );
}

#[test]
fn batch_detail_refusal_does_not_claim_policy_byte_exhaustion() {
    let policies = vec![retention_policy(0)];
    let full = retention_candidate(&policies[0], 0, 32, &"x".repeat(2048));
    let mut stripped = full.clone();
    assert!(stripped.omit_optional_detail());
    let candidates = vec![vec![full.clone()]];
    let mut builder = retention_builder(&policies, 100_000);
    let base = retention_base_and_metadata(&builder, &candidates);
    let review_at = |length| {
        PolicyPackActivationReview::new_with_mode(
            "x".repeat(length),
            PolicyDependencyPackActivationMode::Default,
            Vec::new(),
            true,
            Vec::new(),
        )
    };
    let review_fixed = retained_extra(&review_at(1)) - 1;
    let path_bytes =
        builder.budget.max_retained_report_bytes() - base - review_fixed - stripped.retained_size();
    builder.set_packs(review_at(path_bytes)).unwrap();
    assert!(
        builder.policy_retained_bytes(&builder.runs, 0)
            + full.retained_size()
            + PER_POLICY_INCOMPLETE_REASON_ALLOWANCE
            < builder.budget.per_policy().max_retained_report_bytes()
    );
    assert!(
        builder
            .retain_policy_findings(candidates)
            .unwrap()
            .is_empty()
    );
    let report = builder.finish().unwrap();
    let run = &report.runs()[0];
    assert_eq!(run.budget_refusals(), ["batch/retained_report_bytes"]);
    assert_eq!(run.work().retention_omitted_findings_lower_bound(), 0);
    assert!(
        run.work()
            .retention_omitted_findings_by_dimension()
            .is_empty()
    );
    assert_eq!(run.findings(), &[stripped]);
    assert!(run.diagnostic_causes().iter().any(|cause| {
        cause.execution_cause() == crate::finding::PolicyDiagnosticExecutionCause::DetailRetention
    }));
}

#[test]
fn presence_tiers_precede_other_policies_lower_priority_findings() {
    let policies = (0..2).map(retention_policy).collect::<Vec<_>>();
    let scope = crate::scope::parse_policy_scope_document(
        r#"{"schema_version":1,"scopes":[{"path":"src","reason":"Reviewed"}]}"#,
    )
    .unwrap();
    let accepted = (0..3)
        .map(|i| {
            let mut finding = retention_candidate(&policies[1], i, 4096, "accepted");
            finding
                .attach_scope(scope.scopes()[0].finding_scope())
                .unwrap();
            finding
        })
        .collect::<Vec<_>>();
    let accepted_ids = accepted
        .iter()
        .map(|finding| finding.id())
        .collect::<std::collections::BTreeSet<_>>();
    let candidates = vec![
        (0..100)
            .map(|i| retention_candidate(&policies[0], i, 4096, "active"))
            .collect::<Vec<_>>(),
        accepted,
    ];
    let probe = retention_builder(&policies, 64 * 1024 * 1024);
    let presence = candidates[1]
        .iter()
        .map(|finding| {
            let mut stripped = finding.clone();
            stripped.omit_optional_detail();
            stripped.retained_size()
        })
        .sum::<usize>();
    let cap = retention_base_and_metadata(&probe, &candidates) + presence + 1024;
    let mut builder = retention_builder(&policies, cap);
    let omitted = builder.retain_policy_findings(candidates).unwrap();
    assert!(builder.runs[0].findings().is_empty());
    assert_eq!(
        builder.runs[1]
            .findings()
            .iter()
            .map(|finding| finding.id())
            .collect::<std::collections::BTreeSet<_>>(),
        accepted_ids
    );
    assert_eq!(omitted.len(), 100);
}

#[test]
fn all_policy_metadata_reservations_preserve_the_emergency_allowance() {
    let policies = (0..256).map(retention_policy).collect::<Vec<_>>();
    let per_policy = crate::budget::PolicyBudget::builder()
        .with_max_findings(0)
        .unwrap()
        .with_max_retained_report_bytes(3 * 1024 * 1024)
        .unwrap()
        .build()
        .unwrap();
    let budget = PolicyBatchBudget::builder()
        .with_max_retained_report_bytes(3 * 1024 * 1024)
        .unwrap()
        .with_per_policy(per_policy)
        .unwrap()
        .build()
        .unwrap();
    let mut builder = PolicyReportBuilder::new(budget, 256).unwrap();
    let dimensions = [
        "policy/evaluator_retention",
        "policy/findings",
        "policy/retained_report_bytes",
        "batch/retained_report_bytes",
    ];
    for policy in &policies {
        let mut run = report_run(
            policy,
            PolicyAnalysisType::Match,
            PolicyRunCompletion::Complete,
        );
        for dimension in dimensions {
            run.work_mut()
                .add_retention_omitted_findings_for_dimension(dimension, 1);
        }
        builder
            .register_policy(PolicyRuleDescriptor::from_loaded(policy), run)
            .unwrap();
    }
    let before = builder.emergency_allowance;
    let candidates = policies.iter().map(|p| vec![report_finding(p)]).collect();
    assert_eq!(
        builder.retain_policy_findings(candidates).unwrap().len(),
        256
    );
    assert_eq!(builder.emergency_allowance, before);
    for run in &builder.runs {
        assert_eq!(run.work().retention_omitted_findings_lower_bound(), 5);
        assert_eq!(
            run.work().retention_omitted_findings_by_dimension()["policy/findings"],
            2
        );
        assert_eq!(
            run.work()
                .retention_omitted_findings_by_dimension()
                .values()
                .sum::<u64>(),
            5
        );
    }
    builder.finish().unwrap();
}

#[test]
fn simultaneous_byte_refusals_count_a_dropped_finding_once() {
    let policy = loaded_match_policy();
    let finding = report_finding(&policy);
    let (descriptor, run) = report_skeleton();
    let mut stripped = finding.clone();
    stripped.omit_optional_detail();
    let mut envelope = run.clone();
    envelope.reserve_admission_metadata(
        &[&finding],
        &[
            "policy/evaluator_retention",
            "policy/findings",
            "policy/retained_report_bytes",
            "batch/retained_report_bytes",
        ],
    );
    let metadata = envelope.retained_size() - run.retained_size();
    let policy_cap = descriptor.retained_size()
        + run.retained_size()
        + metadata
        + PER_POLICY_INCOMPLETE_REASON_ALLOWANCE
        + stripped.retained_size() / 2;
    let budget = PolicyBatchBudget::builder()
        .with_max_retained_report_bytes(100_000)
        .unwrap()
        .with_per_policy(
            crate::budget::PolicyBudget::builder()
                .with_max_retained_report_bytes(policy_cap)
                .unwrap()
                .build()
                .unwrap(),
        )
        .unwrap()
        .build()
        .unwrap();
    let mut builder = PolicyReportBuilder::new(budget, 1).unwrap();
    builder.register_policy(descriptor, run).unwrap();
    let base = retention_base_and_metadata(&builder, &[vec![finding.clone()]]);
    let review_at = |length| {
        PolicyPackActivationReview::new_with_mode(
            "x".repeat(length),
            PolicyDependencyPackActivationMode::Default,
            Vec::new(),
            true,
            Vec::new(),
        )
    };
    let review_fixed = retained_extra(&review_at(1)) - 1;
    let path_bytes =
        budget.max_retained_report_bytes() - base - review_fixed - stripped.retained_size() / 2;
    builder.set_packs(review_at(path_bytes)).unwrap();
    assert_eq!(
        builder
            .retain_policy_findings(vec![vec![finding]])
            .unwrap()
            .len(),
        1
    );
    let report = builder.finish().unwrap();
    let run = &report.runs()[0];
    assert_eq!(
        run.budget_refusals(),
        [
            "batch/retained_report_bytes",
            "policy/retained_report_bytes"
        ]
    );
    assert_eq!(
        run.work().retention_omitted_findings_by_dimension(),
        &std::collections::BTreeMap::from([("policy/retained_report_bytes".to_owned(), 1)])
    );
    assert_eq!(
        run.work()
            .retention_omitted_findings_by_dimension()
            .values()
            .sum::<u64>(),
        run.work().retention_omitted_findings_lower_bound()
    );
}
