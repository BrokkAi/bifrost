use super::*;
use serde_json::json;

#[test]
fn overlay_scope_wire_names_identify_both_domains() {
    let scope = PolicyOverlayScope::FindingScenario {
        finding: PolicyFindingId::from_bytes([3; 32]),
        scenario: SourceScenarioId::try_new("test", "source").unwrap(),
    };
    let wire = serde_json::to_value(&scope).unwrap();
    assert_eq!(wire["type"], "finding_scenario");
    assert_eq!(
        wire["finding"],
        serde_json::to_value(PolicyFindingId::from_bytes([3; 32])).unwrap()
    );
    assert_eq!(
        wire["scenario"],
        serde_json::to_value(SourceScenarioId::try_new("test", "source").unwrap()).unwrap()
    );
    assert_eq!(wire.as_object().unwrap().len(), 3);
    assert_eq!(
        serde_json::to_value(CvssEvidenceScope::System {
            system: CvssSystemScope::SubsequentSystem,
        })
        .unwrap(),
        json!({"type": "system", "system": "subsequent_system"})
    );
}

#[test]
fn policy_overlay_refines_global_overlay() {
    let policy = PolicyOverlayScope::Policy {
        policy_id: PolicyId::new("test.policy").unwrap(),
    };
    assert!(policy.strictly_refines(&PolicyOverlayScope::AllFindings));
}

#[test]
fn finding_scenario_retains_allocated_scenario_name() {
    let short = PolicyOverlayScope::FindingScenario {
        finding: PolicyFindingId::from_bytes([1; 32]),
        scenario: SourceScenarioId::try_new("test", "s").unwrap(),
    };
    let long = PolicyOverlayScope::FindingScenario {
        finding: PolicyFindingId::from_bytes([1; 32]),
        scenario: SourceScenarioId::try_new("test", "scenario-with-a-long-name").unwrap(),
    };
    assert!(long.retained_size() > short.retained_size());
}

#[test]
fn assumptions_keep_all_distinct_values_in_canonical_order() {
    let original = crate::test_support::cvss_test_metric_evidence(CvssBaseMetric::Av, 1, "cvss");
    let make = |assumptions: Vec<String>| {
        CvssMetricEvidence::try_new(
            original.metric(),
            original.value(),
            original.basis(),
            original.evidence_refs().to_vec(),
            original.rationale().to_string(),
            assumptions,
            original.assessor_or_tool().to_string(),
            original.assessed_at().map(str::to_string),
            original.system_scope(),
            original.content_hash(),
        )
        .unwrap()
    };
    let first = make(vec!["zulu".into(), "alpha".into()]);
    let second = make(vec!["alpha".into(), "zulu".into()]);
    assert_eq!(first.assumptions(), &["alpha", "zulu"]);
    assert_eq!(
        serde_json::to_value(first).unwrap(),
        serde_json::to_value(second).unwrap()
    );
}

#[test]
fn scoring_requires_every_base_metric_and_no_optional_metric() {
    let base_metrics = [
        CvssBaseMetric::Av,
        CvssBaseMetric::Ac,
        CvssBaseMetric::At,
        CvssBaseMetric::Pr,
        CvssBaseMetric::Ui,
        CvssBaseMetric::Vc,
        CvssBaseMetric::Vi,
        CvssBaseMetric::Va,
        CvssBaseMetric::Sc,
        CvssBaseMetric::Si,
        CvssBaseMetric::Sa,
    ];
    let metrics: Vec<_> = base_metrics
        .into_iter()
        .enumerate()
        .map(|(index, metric)| {
            crate::test_support::cvss_test_metric_evidence(
                metric,
                u8::try_from(index + 1).unwrap(),
                "cvss",
            )
        })
        .collect();
    let component = CvssComponentResult::try_new(
        CvssNomenclature::B,
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H".into(),
        10.0,
        CvssSeverity::Critical,
    )
    .unwrap();
    let score = |values| {
        CvssAssessment::scored(
            CvssVersion::V4_0,
            CvssNomenclature::B,
            component.vector().to_string(),
            vec![component.clone()],
            values,
            crate::test_support::cvss_assessment_provenance(),
        )
    };
    assert!(score(metrics.clone()).is_ok());
    assert!(matches!(
        score(metrics[..10].to_vec()),
        Err(CvssValidationError::IncompleteScoredBaseMetrics)
    ));
}

#[test]
fn assessment_set_accepts_only_highest_scored_selection() {
    let metrics = [
        CvssBaseMetric::Av,
        CvssBaseMetric::Ac,
        CvssBaseMetric::At,
        CvssBaseMetric::Pr,
        CvssBaseMetric::Ui,
        CvssBaseMetric::Vc,
        CvssBaseMetric::Vi,
        CvssBaseMetric::Va,
        CvssBaseMetric::Sc,
        CvssBaseMetric::Si,
        CvssBaseMetric::Sa,
    ]
    .into_iter()
    .enumerate()
    .map(|(index, metric)| {
        crate::test_support::cvss_test_metric_evidence(
            metric,
            u8::try_from(index + 1).unwrap(),
            "cvss",
        )
    })
    .collect::<Vec<_>>();
    let make = |metrics: Vec<CvssMetricEvidence>, byte| {
        let scored = vector::score_metrics(&metrics).unwrap();
        let assessment = CvssAssessment::scored(
            CvssVersion::V4_0,
            scored.nomenclature,
            scored.full_vector,
            scored.components,
            metrics,
            crate::test_support::cvss_assessment_provenance(),
        )
        .unwrap();
        CvssAssessmentVariant::try_new(
            VulnerabilityIdentity::from_bytes([byte; 32]),
            Vec::new(),
            false,
            0,
            SourceScenarioSetHash::from_bytes([byte; 32]),
            Vec::new(),
            false,
            assessment,
        )
        .unwrap()
    };
    let high = make(metrics.clone(), 1);
    let low_metrics = metrics
        .into_iter()
        .map(|item| {
            if item.metric()
                != (CvssMetric::Base {
                    metric: CvssBaseMetric::Vc,
                })
            {
                return item;
            }
            CvssMetricEvidence::try_new(
                item.metric(),
                CvssMetricValue::try_new(item.metric(), CvssMetricValueToken::N).unwrap(),
                item.basis(),
                item.evidence_refs().to_vec(),
                item.rationale().to_string(),
                item.assumptions().to_vec(),
                item.assessor_or_tool().to_string(),
                item.assessed_at().map(str::to_string),
                item.system_scope(),
                item.content_hash(),
            )
            .unwrap()
        })
        .collect();
    let low = make(low_metrics, 2);
    let selected = high.id();
    assert!(matches!(
        CvssAssessmentSet::try_new(vec![low.clone(), high.clone()], Some(low.id())),
        Err(CvssValidationError::IncorrectSelection)
    ));
    let set = CvssAssessmentSet::try_new(vec![low, high], Some(selected)).unwrap();
    assert_eq!(set.selected_for_display(), Some(selected));
    assert_eq!(set.selected_severity(), Some(CvssSeverity::Critical));
}

fn unscored_with(
    established: Vec<CvssMetricEvidence>,
    reasons: Vec<CvssUnscoredReason>,
) -> CvssAssessment {
    CvssAssessment::unscored(
        CvssVersion::V4_0,
        established,
        Vec::new(),
        reasons,
        crate::test_support::cvss_assessment_provenance(),
    )
    .unwrap()
}

#[test]
fn metric_evidence_normalizes_order_and_identical_duplicates() {
    let av = crate::test_support::cvss_test_metric_evidence(CvssBaseMetric::Av, 1, "cvss");
    let ac = crate::test_support::cvss_test_metric_evidence(CvssBaseMetric::Ac, 2, "cvss");
    let reason = CvssUnscoredReason::RunIncomplete {
        reason: PolicyIncompleteReason::Cancelled,
    };
    let canonical = unscored_with(vec![av.clone(), ac.clone()], vec![reason.clone()]);
    let reordered = unscored_with(vec![ac, av.clone(), av], vec![reason]);
    assert_eq!(
        serde_json::to_value(&canonical).unwrap(),
        serde_json::to_value(&reordered).unwrap()
    );
    let CvssAssessment::Unscored { established, .. } = canonical else {
        unreachable!()
    };
    assert_eq!(
        established
            .iter()
            .map(|item| item.metric().first_label())
            .collect::<Vec<_>>(),
        ["AV", "AC"]
    );
}

#[test]
fn one_scenario_is_valid_in_an_incoherent_reason() {
    let scenario = SourceScenarioId::try_new("test", "only-source").unwrap();
    let reason = CvssUnscoredReason::incoherent_scenario(
        SourceScenarioSetHash::from_bytes([7; 32]),
        vec![scenario.clone()],
        false,
        0,
        "One source is enough".into(),
    )
    .unwrap();
    let wire = serde_json::to_value(reason).unwrap();
    assert_eq!(wire["scenario_ids"], json!([scenario]));
}

#[test]
fn distinct_incoherent_reasons_have_canonical_report_order() {
    let scenario = SourceScenarioId::try_new("test", "source").unwrap();
    let make = |rationale: &str| {
        CvssUnscoredReason::incoherent_scenario(
            SourceScenarioSetHash::from_bytes([8; 32]),
            vec![scenario.clone()],
            false,
            0,
            rationale.into(),
        )
        .unwrap()
    };
    let alpha = make("Alpha cause");
    let zulu = make("Zulu cause");
    let first = unscored_with(Vec::new(), vec![zulu.clone(), alpha.clone()]);
    let second = unscored_with(Vec::new(), vec![alpha, zulu]);
    assert_eq!(
        serde_json::to_value(&first).unwrap(),
        serde_json::to_value(&second).unwrap()
    );
    let CvssAssessment::Unscored { reasons, .. } = first else {
        unreachable!()
    };
    assert_eq!(reasons.len(), 2);
}

#[test]
fn vector_and_severity_reject_invalid_boundary_values() {
    let component = CvssComponentResult::try_new(
        CvssNomenclature::B,
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H".into(),
        10.0,
        CvssSeverity::Critical,
    )
    .unwrap();
    assert!(matches!(
        CvssAssessment::scored(
            CvssVersion::V4_0,
            CvssNomenclature::B,
            "CVSS:3.1/AV:N/AC:L".into(),
            vec![component],
            Vec::new(),
            crate::test_support::cvss_assessment_provenance(),
        ),
        Err(CvssValidationError::InvalidVector)
    ));
    for (score, severity) in [(9.0, CvssSeverity::High), (3.5, CvssSeverity::Medium)] {
        assert!(matches!(
            CvssComponentResult::try_new(
                CvssNomenclature::B,
                "CVSS:4.0/AV:N".into(),
                score,
                severity
            ),
            Err(CvssValidationError::ScoreSeverityMismatch { .. })
        ));
    }
}

fn unscored_variant_id(reason: CvssUnscoredReason) -> CvssAssessmentVariantId {
    identity::variant_id(
        VulnerabilityIdentity::from_bytes([1; 32]),
        SourceScenarioSetHash::from_bytes([2; 32]),
        &unscored_with(Vec::new(), vec![reason]),
    )
}

#[test]
fn unscored_identity_binds_conflict_metric_and_incomplete_cause() {
    let conflict = |metric| {
        CvssUnscoredReason::conflicting_metric_evidence(
            CvssMetric::Base { metric },
            CvssEvidenceSetHash::from_bytes([3; 32]),
            vec![EvidenceRef::try_new("cvss", "proof").unwrap()],
            false,
            0,
        )
        .unwrap()
    };
    let av = unscored_variant_id(conflict(CvssBaseMetric::Av));
    assert_eq!(av, unscored_variant_id(conflict(CvssBaseMetric::Av)));
    assert_ne!(av, unscored_variant_id(conflict(CvssBaseMetric::Ac)));
    let incomplete = |reason| CvssUnscoredReason::RunIncomplete { reason };
    let cancelled = unscored_variant_id(incomplete(PolicyIncompleteReason::Cancelled));
    assert_eq!(
        cancelled,
        unscored_variant_id(incomplete(PolicyIncompleteReason::Cancelled))
    );
    assert_ne!(
        cancelled,
        unscored_variant_id(incomplete(PolicyIncompleteReason::DeadlineExceeded))
    );
}

#[test]
fn evidence_set_identity_uses_stable_big_endian_count() {
    let one = CvssEvidenceContentHash::from_bytes([1; 32]);
    let two = CvssEvidenceContentHash::from_bytes([2; 32]);
    let digest = identity::evidence_set_hash([two, one, one]);
    assert_eq!(
        digest.to_string(),
        "1237759effcee817374fc66a42d61dc186b220f71199749573c0e3cc48370dcb"
    );
    assert_eq!(digest, identity::evidence_set_hash([one, two]));
}

#[test]
fn variant_identity_binds_scenarios_and_every_metric_hash() {
    let vulnerability = VulnerabilityIdentity::from_bytes([1; 32]);
    let first = crate::test_support::cvss_test_metric_evidence(CvssBaseMetric::Av, 1, "cvss");
    let second = crate::test_support::cvss_test_metric_evidence(CvssBaseMetric::Ac, 2, "cvss");
    let alternate = crate::test_support::cvss_test_metric_evidence(CvssBaseMetric::Ac, 3, "cvss");
    let assess = |evidence| {
        unscored_with(
            evidence,
            vec![CvssUnscoredReason::RunIncomplete {
                reason: PolicyIncompleteReason::Cancelled,
            }],
        )
    };
    let original = assess(vec![first.clone(), second]);
    let changed = assess(vec![first, alternate]);
    let scenario = SourceScenarioSetHash::from_bytes([4; 32]);
    let id = identity::variant_id(vulnerability, scenario, &original);
    assert_eq!(id, identity::variant_id(vulnerability, scenario, &original));
    assert_ne!(
        id,
        identity::variant_id(
            vulnerability,
            SourceScenarioSetHash::from_bytes([5; 32]),
            &original
        )
    );
    assert_ne!(id, identity::variant_id(vulnerability, scenario, &changed));
}

#[test]
fn collected_environment_and_threat_overlays_keep_their_basis() {
    use crate::definition::{CvssEnvironmentalOrSupplementalMetric, CvssThreatMetric};
    use crate::evaluator::{
        CvssEnvironmentOverlayEvidence, CvssEvaluationOverlay, CvssOverlayEvidenceMetadata,
        CvssThreatOverlayEvidence,
    };
    let metadata = |scope| {
        CvssOverlayEvidenceMetadata::try_new(
            vec![EvidenceRef::try_new("cvss", "external").unwrap()],
            "External assessment".into(),
            Vec::new(),
            "assessor".into(),
            "2026-01-01T00:00:00Z".into(),
            scope,
            None,
        )
        .unwrap()
    };
    let environment_metric = CvssMetric::EnvironmentalOrSupplemental {
        metric: CvssEnvironmentalOrSupplementalMetric::Cr,
    };
    let threat_metric = CvssMetric::Threat {
        metric: CvssThreatMetric::E,
    };
    let environment = CvssEnvironmentOverlayEvidence::try_new(
        CvssEnvironmentalOrSupplementalMetric::Cr,
        CvssMetricValue::try_new(environment_metric, CvssMetricValueToken::H).unwrap(),
        metadata(CvssEvidenceScope::Global),
    )
    .unwrap();
    let threat = CvssThreatOverlayEvidence::try_new(
        CvssThreatMetric::E,
        CvssMetricValue::try_new(threat_metric, CvssMetricValueToken::A).unwrap(),
        metadata(CvssEvidenceScope::Global),
    )
    .unwrap();
    let records = policy_evidence::collect_overlays(&[
        CvssEvaluationOverlay::EnvironmentProfile {
            scope: PolicyOverlayScope::AllFindings,
            evidence: environment,
        },
        CvssEvaluationOverlay::ThreatFeed {
            scope: PolicyOverlayScope::AllFindings,
            evidence: threat,
        },
    ])
    .unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(
        records
            .iter()
            .find(|record| record.evidence.metric() == environment_metric)
            .unwrap()
            .evidence
            .basis(),
        CvssEvidenceBasis::EnvironmentProfile
    );
    assert_eq!(
        records
            .iter()
            .find(|record| record.evidence.metric() == threat_metric)
            .unwrap()
            .evidence
            .basis(),
        CvssEvidenceBasis::ThreatFeed
    );
}

#[test]
fn authored_assertion_reaches_each_matching_scenario_with_assumptions() {
    use crate::catalog::{CatalogRegistryLimits, TaintCatalogRegistry};
    use crate::definition::TaintLabel;
    use crate::finding_identity::OpaqueFindingKey;
    use crate::future_evidence::{TaintFindingAnchor, TaintPolicyProjectionFacts};
    use crate::registry::{PolicyRegistry, PolicyRegistryLimits};
    use crate::source::PolicySourceIdentity;
    use std::sync::Arc;

    let policy_source = r#"(policy
      :id "test.cvss-scenarios"
      :name "CVSS scenarios"
      :message (generated-message :relation can-reach)
      :severity (cvss-severity :when-unscored warning)
      :analysis (analysis
        :type taint :mode may
        :sources (endpoint-set :entries [
          (source :id request :display-name "request input"
            :categories [input.user] :selector (rql (name "request"))
            :bind return-value :labels [alpha])])
        :sinks (endpoint-set :entries [
          (sink :id store :display-name "store"
            :categories [data.sensitive] :selector (rql (name "store"))
            :dangerous-operand matched-value :accepts [alpha])]))
      :classification (classification
        :fallback (classification-id :taxonomy "Bifrost" :id "SCENARIOS")
        :cvss (cvss :version "4.0" :emit when-base-complete
          :metric-rules [
            (metric :name AV :value N
              :when (any [
                (source-labels :all [alpha])
                (source-labels :all [beta])])
              :basis policy-assertion :scope vulnerable-system
              :evidence-refs [policy:self]
              :rationale "alpha source"
              :assumptions ["first condition" "second condition"])])))"#;
    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry =
        PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
    registry
        .register_policy_bytes(
            PolicySourceIdentity::new("test:cvss-scenarios"),
            policy_source.as_bytes(),
        )
        .unwrap();
    let policy = registry.policies().next().unwrap();
    let spec = policy.resolved_taint().unwrap();
    let source = &spec.sources[0];
    let scenarios = [
        SourceScenarioId::try_new("test", "first").unwrap(),
        SourceScenarioId::try_new("test", "second").unwrap(),
    ];
    let fact = crate::test_support::taint_source_projection_fact(
        source.identity.clone(),
        source.semantic_hash,
        source.analysis_projection_hash,
        source.definition.display_name.clone(),
        source.definition.categories.clone(),
        TaintLabel::new("alpha").unwrap(),
        None,
        scenarios.to_vec(),
        EvidenceRef::try_new("test-source", "request").unwrap(),
    );
    let sink = &spec.sinks[0];
    let projection = TaintPolicyProjectionFacts::try_new(
        sink.identity.clone(),
        sink.semantic_hash,
        sink.analysis_projection_hash,
        sink.definition.display_name.clone(),
        sink.definition.categories.clone(),
        sink.definition.tags.clone(),
        sink.definition.impacts.clone(),
        vec![TaintLabel::new("alpha").unwrap()],
        vec![fact],
        &crate::budget::PolicyBudget::default(),
    )
    .unwrap();
    let anchor = TaintFindingAnchor::weak(OpaqueFindingKey::try_new("test", "finding").unwrap());
    let finding = CvssFindingProjection::Taint {
        anchor: &anchor,
        projection: &projection,
        sources: &projection.source_facts,
    };
    let records =
        match policy_evidence::collect_policy_assertions(policy, finding, &mut || true).unwrap() {
            policy_evidence::EvidenceCollection::Complete(records) => records,
            policy_evidence::EvidenceCollection::BudgetExceeded => panic!("unbounded charge"),
        };
    assert_eq!(records.len(), 2);
    for scenario in &scenarios {
        assert!(records.iter().any(|record| record.target_scope
            == PolicyOverlayScope::SourceScenario {
                scenario_id: scenario.clone()
            }));
    }
    for record in &records {
        assert_eq!(
            record.evidence.assumptions(),
            &["first condition", "second condition"]
        );
        assert_eq!(record.evidence.basis(), CvssEvidenceBasis::PolicyAssertion);
    }
}
