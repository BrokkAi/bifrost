use super::*;

fn diagnostic() -> PolicyReportDiagnostic {
    PolicyReportDiagnostic::try_new(
        PolicyReportDiagnosticCode::PolicyLoadFailed,
        PolicyDiagnosticSeverity::Error,
        "failed",
        Some(PolicySourceIdentity::new("input.rqlp")),
        None,
        Vec::new(),
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
        builder.retain_finding(report_finding(&loaded)),
        Err(PolicyReportBuilderError::EvaluationBeforeSkeletonsComplete)
    ));
    builder.register_primary_diagnostic(diagnostic()).unwrap();
    assert_eq!(
        builder.retain_finding(report_finding(&loaded)).unwrap(),
        PolicyRetentionOutcome::Retained
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
            .with_max_total_findings(0)
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
    let mut builder = PolicyReportBuilder::new(budget_at(admitted), 1).unwrap();
    builder.set_packs(review.clone()).unwrap();
    builder
        .register_policy(descriptor.clone(), run.clone())
        .unwrap();

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
    builder.set_execution(execution).unwrap();
    assert_eq!(
        builder.retain_finding(report_finding(&loaded)).unwrap(),
        PolicyRetentionOutcome::Omitted {
            reason: PolicyIncompleteReason::BatchFindingLimit
        }
    );
    let report = builder.finish().unwrap();
    // The first omission must leave room for the remaining emergency metadata.
    assert!(
        admitted - report.retained_size()
            >= EMERGENCY_DIAGNOSTIC_ALLOWANCE - PER_POLICY_INCOMPLETE_REASON_ALLOWANCE
    );
    assert_eq!(report.runs()[0].work().omitted_findings_lower_bound(), 1);
    assert!(
        matches!(report.runs()[0].completion(), PolicyRunCompletion::Inconclusive { reasons, .. }
        if reasons.contains(&PolicyIncompleteReason::BatchFindingLimit))
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
        builder.retain_finding(finding).unwrap(),
        PolicyRetentionOutcome::Omitted {
            reason: PolicyIncompleteReason::ReportRetentionBudget
        }
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
    builder.retain_finding(report_finding(&second)).unwrap();
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
    builder.retain_finding(report_finding(&loaded)).unwrap();
    let report = builder.finish().unwrap();
    let expected = report.rules()[0].retained_size() + report.runs()[0].retained_size();
    assert_eq!(
        report.runs()[0].work().retained_report_bytes() as usize,
        expected
    );
}

#[test]
fn batch_finding_limit_counts_all_runs() {
    let first = loaded_match_policy();
    let second = another_match_policy();
    let budget = PolicyBatchBudget::builder()
        .with_max_total_findings(2)
        .unwrap()
        .build()
        .unwrap();
    let mut builder = PolicyReportBuilder::new(budget, 2).unwrap();
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
    builder.retain_finding(report_finding(&first)).unwrap();
    builder.retain_finding(report_finding(&second)).unwrap();
    let alternate_anchor = MatchFindingAnchor::strong(
        MatchResultDomain::CallSite,
        WorkspaceRelativePath::new("src/app.rs").unwrap(),
        None,
        Some(SourceSliceHash::from_bytes([5; 32])),
        0,
    )
    .unwrap();
    assert_eq!(
        builder
            .retain_finding(report_finding_with_anchor(
                &second,
                alternate_anchor,
                FindingCompleteness::Complete
            ))
            .unwrap(),
        PolicyRetentionOutcome::Omitted {
            reason: PolicyIncompleteReason::BatchFindingLimit
        }
    );
    let report = builder.finish().unwrap();
    assert_eq!(
        report
            .runs()
            .iter()
            .map(|run| run.findings().len())
            .sum::<usize>(),
        2
    );
    assert!(
        report
            .runs()
            .iter()
            .any(|run| run.work().omitted_findings_lower_bound() == 1)
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
    )
    .unwrap();
    let second = PolicyReportDiagnostic::try_new(
        PolicyReportDiagnosticCode::PolicyLoadFailed,
        PolicyDiagnosticSeverity::Error,
        "beta",
        Some(PolicySourceIdentity::new("input.rqlp")),
        None,
        Vec::new(),
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
        builder.retain_finding(finding).unwrap();
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
        builder.retain_finding(finding).unwrap();
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
        builder.retain_finding(finding).unwrap();
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
