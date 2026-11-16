use super::*;

fn comparator_contract() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/diagnostic-cause-contract-schema19.json"
    ))
    .unwrap()
}

#[test]
fn diagnostic_causes_match_the_comparator_code_and_impact_inventory() {
    let mut codes = vec![
        PolicyDiagnosticCode::UnsupportedAnalysis,
        PolicyDiagnosticCode::StableAnchorUnavailable,
        PolicyDiagnosticCode::EndpointDominanceUndecidable,
        PolicyDiagnosticCode::EvaluationFailure,
        PolicyDiagnosticCode::EmptySelection,
        PolicyDiagnosticCode::UnknownVerdictFailClosed,
        PolicyDiagnosticCode::BatchFindingLimit,
        PolicyDiagnosticCode::ReportRetentionBudget,
        PolicyDiagnosticCode::CvssVariantBudget,
        PolicyDiagnosticCode::ProjectionScenarioMembershipBudget,
        PolicyDiagnosticCode::OrganizationalRiskOverlayBudget,
        PolicyDiagnosticCode::DuplicateFindingId,
        PolicyDiagnosticCode::InternalError {
            cause: PolicyInternalErrorCause::StoreRead,
            policy_id: loaded_match_policy().definition().metadata.id.clone(),
            error: "store unavailable".to_string(),
        },
    ];
    for label in CodeQueryDiagnosticCode::LABELS {
        let raw: CodeQueryDiagnosticCode =
            serde_json::from_value(serde_json::json!(label)).unwrap();
        let code = if raw == CodeQueryDiagnosticCode::TypestateAnalysisPartial {
            PolicyCodeQueryDiagnostic::TypestatePartial {
                scope: TypestatePartialScope::Evaluation,
            }
        } else {
            raw.try_into().unwrap()
        };
        codes.push(PolicyDiagnosticCode::CodeQuery { code });
    }
    let contract = comparator_contract();
    let mut emitted = std::collections::BTreeSet::new();
    for code in &codes {
        let mut set = PolicyDiagnosticCauses::default();
        set.insert(
            code,
            if matches!(code, PolicyDiagnosticCode::InternalError { .. }) {
                PolicyDiagnosticImpact::RunFailed
            } else {
                PolicyDiagnosticImpact::RunIncomplete
            },
        );
        let cause = set.iter().next().unwrap();
        assert_eq!(set.iter().count(), 1);
        let value = serde_json::to_value(cause).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 3);
        assert!(
            contract["class_by_code"].get(cause.code).is_some(),
            "unclassified emitted code: {value}"
        );
        emitted.insert(cause.code.to_owned());
    }
    assert_eq!(
        emitted,
        contract["class_by_code"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect()
    );
    assert_eq!(emitted.len(), 139);
    let impacts = [
        PolicyDiagnosticImpact::Advisory,
        PolicyDiagnosticImpact::DeclaredNonExhaustive,
        PolicyDiagnosticImpact::FindingPartial,
        PolicyDiagnosticImpact::RunIncomplete,
        PolicyDiagnosticImpact::RunUnsupported,
        PolicyDiagnosticImpact::RunFailed,
    ];
    assert_eq!(serde_json::to_value(impacts).unwrap(), contract["impacts"]);
    let mut all = PolicyDiagnosticCauses::default();
    for code in &codes {
        for cause in DIAGNOSTIC_EXECUTION_CAUSES {
            if matches!(code, PolicyDiagnosticCode::InternalError { .. }) {
                if *cause != PolicyDiagnosticExecutionCause::Known(None) {
                    all.insert_with_execution_cause(
                        code,
                        PolicyDiagnosticImpact::RunFailed,
                        *cause,
                    );
                }
            } else {
                for impact in impacts {
                    all.insert_with_execution_cause(code, impact, *cause);
                }
            }
        }
    }
    assert_eq!(all.iter().count(), 138 * 9 + 8);
    assert!(
        all.iter()
            .all(|cause| cause.impact() == PolicyDiagnosticImpact::RunFailed)
    );
    let mut merged = PolicyDiagnosticCauses::default();
    merged.union(&all);
    merged.union(&all);
    assert_eq!(merged, all);
    let loaded = loaded_match_policy();
    let budget = PolicyBudget::builder()
        .with_max_retained_report_bytes(4096)
        .unwrap()
        .build()
        .unwrap();
    let run = PolicyRun::try_new(
        loaded.definition().metadata.id.clone(),
        loaded.semantic_hash(),
        PolicyAnalysisType::Match,
        PolicyRunCompletion::inconclusive(vec![PolicyIncompleteReason::ReportRetentionBudget])
            .unwrap(),
        Vec::new(),
        PolicyDiagnostics {
            entries: Vec::new(),
            causes: all,
            worst_omitted_diagnostic_severity: None,
        },
        true,
        PolicyWorkReport::default(),
        &budget,
    )
    .expect("all cause pairs fit a small report allowance independently of detail storage");
    assert_eq!(
        serde_json::to_value(run).unwrap()["diagnostic_causes"]
            .as_array()
            .unwrap()
            .len(),
        137 * 9 + 8 + 1 // retention code is centrally certified to one origin
    );
}

#[test]
fn diagnostic_causes_survive_zero_detail_retention_without_inventing_context() {
    for (code, legacy_class) in [
        (PolicyDiagnosticCode::ReportRetentionBudget, "detail_only"),
        (
            PolicyDiagnosticCode::CodeQuery {
                code: CodeQueryDiagnosticCode::ExecutionBudgetExhausted
                    .try_into()
                    .unwrap(),
            },
            "execution",
        ),
        (
            PolicyDiagnosticCode::CodeQuery {
                code: CodeQueryDiagnosticCode::QualifyingTypeUnresolved
                    .try_into()
                    .unwrap(),
            },
            "semantic",
        ),
    ] {
        let diagnostic = PolicyDiagnostic::try_new(
            code.clone(),
            PolicyDiagnosticSeverity::Warning,
            PolicyDiagnosticImpact::RunIncomplete,
            "retained cause, omitted detail",
            None,
            Vec::new(),
            crate::RelatedLocationOmissions::Known(0),
        )
        .unwrap();
        let mut diagnostics: PolicyDiagnostics = vec![diagnostic.clone(), diagnostic].into();
        assert!(normalize_policy_diagnostics_bounded(&mut diagnostics, 0));
        let mut run = run_at(
            PolicyRunCompletion::inconclusive(vec![
                PolicyIncompleteReason::PartialDiscovery,
                PolicyIncompleteReason::ReportRetentionBudget,
            ])
            .unwrap(),
        );
        run.replace_diagnostics(diagnostics, true);
        let value = serde_json::to_value(&run).unwrap();
        assert_eq!(value["diagnostics"], serde_json::json!([]));
        let causes = value["diagnostic_causes"].as_array().unwrap();
        assert_eq!(causes.len(), 1);
        assert_eq!(causes[0]["impact"], "run_incomplete");
        assert_eq!(
            causes[0]["execution_cause"],
            if matches!(code, PolicyDiagnosticCode::ReportRetentionBudget) {
                "detail_retention"
            } else {
                "unknown"
            }
        );
        let contract = comparator_contract();
        assert_eq!(
            contract["class_by_code"][causes[0]["code"].as_str().unwrap()],
            legacy_class
        );
    }
    let clean = serde_json::to_value(run_at(PolicyRunCompletion::Complete)).unwrap();
    assert_eq!(clean["diagnostic_causes"], serde_json::json!([]));
}

#[test]
fn diagnostic_causes_include_late_unknown_verdict_diagnostics() {
    let mut run = run_at(
        PolicyRunCompletion::inconclusive(vec![PolicyIncompleteReason::PartialDiscovery]).unwrap(),
    );
    run.apply_unknown_verdict(UnknownVerdict::FailClosed, &PolicyBudget::default())
        .unwrap();
    let value = serde_json::to_value(run).unwrap();
    assert_eq!(
        value["diagnostic_causes"],
        serde_json::json!([
            {"code": "unknown_verdict_fail_closed", "impact": "run_incomplete", "execution_cause": "unknown"}
        ])
    );
}

#[test]
fn omitted_diagnostic_severity_survives_count_folding_and_replacement() {
    for severity in [
        PolicyDiagnosticSeverity::Note,
        PolicyDiagnosticSeverity::Warning,
        PolicyDiagnosticSeverity::Error,
    ] {
        let diagnostic = PolicyDiagnostic::new_bounded(
            PolicyDiagnosticCode::EvaluationFailure,
            severity,
            PolicyDiagnosticImpact::RunIncomplete,
            "omitted diagnostic",
        );
        let mut diagnostics: PolicyDiagnostics = vec![diagnostic].into();
        assert!(normalize_policy_diagnostics_bounded(&mut diagnostics, 0));
        let mut run = run_at(
            PolicyRunCompletion::inconclusive(vec![PolicyIncompleteReason::ReportRetentionBudget])
                .unwrap(),
        );
        run.replace_diagnostics(diagnostics, true);
        assert_eq!(run.worst_omitted_diagnostic_severity(), Some(severity));
        assert_eq!(
            serde_json::to_value(&run).unwrap()["worst_omitted_diagnostic_severity"],
            serde_json::to_value(severity).unwrap()
        );
        run.replace_diagnostics(Vec::new(), true);
        assert_eq!(run.worst_omitted_diagnostic_severity(), Some(severity));
    }
    let mut diagnostics: PolicyDiagnostics = ["first", "second"]
        .into_iter()
        .map(|message| {
            PolicyDiagnostic::new_bounded(
                PolicyDiagnosticCode::EvaluationFailure,
                PolicyDiagnosticSeverity::Error,
                PolicyDiagnosticImpact::RunIncomplete,
                message,
            )
        })
        .collect();
    assert!(normalize_policy_diagnostics_bounded(&mut diagnostics, 1));
    assert_eq!(
        diagnostics.worst_omitted_diagnostic_severity(),
        Some(PolicyDiagnosticSeverity::Error)
    );
    let clean = serde_json::to_value(run_at(PolicyRunCompletion::Complete)).unwrap();
    assert_eq!(
        clean["worst_omitted_diagnostic_severity"],
        serde_json::Value::Null
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#11391: private execution causes consumed duplicate presentation slots"
)]
fn private_causes_deduplicate_details_without_losing_the_pair_inventory() {
    let code = PolicyDiagnosticCode::CodeQuery {
        code: CodeQueryDiagnosticCode::SemanticAnalysisPartial
            .try_into()
            .unwrap(),
    };
    let first = PolicyDiagnostic::try_new(
        code,
        PolicyDiagnosticSeverity::Warning,
        PolicyDiagnosticImpact::RunIncomplete,
        "same public detail",
        None,
        Vec::new(),
        RelatedLocationOmissions::Known(0),
    )
    .unwrap()
    .with_execution_cause(None);
    let second = first
        .clone()
        .with_execution_cause(Some(brokk_bifrost_rql::DiagnosticExecutionCause::Provider));
    assert_eq!(first, second);
    let mut diagnostics = PolicyDiagnostics::default();
    diagnostics.push(first);
    diagnostics.push(second);
    let truncated = normalize_policy_diagnostics_bounded(&mut diagnostics, 1);
    assert_eq!(diagnostics.len(), 1);
    assert!(!truncated);
    assert_eq!(diagnostics.causes().iter().count(), 2);
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#11391: internal errors must carry known execution dependence"
)]
fn internal_error_uses_existing_other_and_preserves_a_canonical_producer_cause() {
    let code = PolicyDiagnosticCode::InternalError {
        cause: PolicyInternalErrorCause::StoreRead,
        policy_id: loaded_match_policy().definition().metadata.id.clone(),
        error: "store failure".to_string(),
    };
    let diagnostic = PolicyDiagnostic::try_new(
        code,
        PolicyDiagnosticSeverity::Error,
        PolicyDiagnosticImpact::RunFailed,
        "store read failed",
        None,
        Vec::new(),
        RelatedLocationOmissions::Known(0),
    )
    .unwrap();
    let mut diagnostics = PolicyDiagnostics::default();
    diagnostics.push(diagnostic.clone());
    assert_eq!(
        serde_json::to_value(diagnostics.causes()).unwrap()[0]["execution_cause"],
        "other"
    );
    let mut canonical = PolicyDiagnostics::default();
    canonical.push(
        diagnostic
            .with_execution_cause(Some(brokk_bifrost_rql::DiagnosticExecutionCause::Provider)),
    );
    assert_eq!(
        serde_json::to_value(canonical.causes()).unwrap()[0]["execution_cause"],
        "provider"
    );
}
