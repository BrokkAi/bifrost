use super::*;
use std::mem::size_of;

fn evidence_ref(label: &str) -> EvidenceRef {
    EvidenceRef::try_new("cvss", label).unwrap()
}

fn make_provenance(
    refs: &[&str],
    hashes: Vec<CvssEvidenceContentHash>,
) -> CvssAssessmentProvenance {
    CvssAssessmentProvenance::try_new(
        "bifrost.test".to_string(),
        refs.iter().map(|name| evidence_ref(name)).collect(),
        Vec::new(),
        hashes,
    )
    .unwrap()
}

fn metric(metric: CvssBaseMetric, byte: u8) -> CvssMetricEvidence {
    crate::test_support::cvss_test_metric_evidence(metric, byte, "cvss")
}

fn unscored(metrics: Vec<CvssMetricEvidence>, refs: &[&str]) -> CvssAssessment {
    CvssAssessment::unscored(
        CvssVersion::V4_0,
        metrics,
        vec![CvssBaseMetric::Sa],
        vec![CvssUnscoredReason::MissingBaseEvidence],
        make_provenance(refs, Vec::new()),
    )
    .unwrap()
}

fn scored(refs: &[&str]) -> CvssAssessment {
    let vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H";
    let component = CvssComponentResult::try_new(
        CvssNomenclature::B,
        vector.to_string(),
        10.0,
        CvssSeverity::Critical,
    )
    .unwrap();
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
    .map(|(i, base_metric)| metric(base_metric, (i + 1) as u8))
    .collect();
    CvssAssessment::scored(
        CvssVersion::V4_0,
        CvssNomenclature::B,
        vector.to_string(),
        vec![component],
        metrics,
        make_provenance(refs, Vec::new()),
    )
    .unwrap()
}

fn variant(assessment: CvssAssessment, byte: u8) -> CvssAssessmentVariant {
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
}

#[test]
fn assessment_set_preserves_references_from_every_variant_and_evidence_source() {
    let first_metric = metric(CvssBaseMetric::Av, 1);
    let first_metric = CvssMetricEvidence::try_new(
        first_metric.metric(),
        first_metric.value(),
        first_metric.basis(),
        vec![evidence_ref("unscored-first")],
        first_metric.rationale().to_string(),
        first_metric.assumptions().to_vec(),
        first_metric.assessor_or_tool().to_string(),
        None,
        first_metric.system_scope(),
        first_metric.content_hash(),
    )
    .unwrap();
    let first = unscored(
        vec![first_metric, metric(CvssBaseMetric::Ac, 2)],
        &["unscored-provenance"],
    );
    let second = scored(&["scored-provenance-a", "scored-provenance-b"]);
    let second_id = variant(second.clone(), 2).id();
    let set =
        CvssAssessmentSet::try_new(vec![variant(first, 1), variant(second, 2)], Some(second_id))
            .unwrap();
    let mut refs = Vec::new();
    set.append_evidence_refs(&mut refs);
    for label in [
        "AV",
        "AC",
        "unscored-first",
        "unscored-provenance",
        "scored-provenance-a",
        "scored-provenance-b",
    ] {
        assert!(refs.contains(&&evidence_ref(label)), "missing {label}");
    }
}

#[test]
fn first_metric_changes_variant_identity() {
    let first = unscored(vec![metric(CvssBaseMetric::Av, 1)], &[]);
    let second = unscored(vec![metric(CvssBaseMetric::Av, 2)], &[]);
    assert_ne!(variant(first, 1).id(), variant(second, 1).id());
}

#[test]
fn scored_record_count_matches_evidence_at_the_boundary() {
    let assessment = scored(&[]);
    let count = match &assessment {
        CvssAssessment::Scored { metrics, .. } => metrics.len(),
        _ => unreachable!(),
    };
    let id = variant(assessment, 1).id();
    let set = CvssAssessmentSet::try_new(vec![variant(scored(&[]), 1)], Some(id)).unwrap();
    assert_eq!(set.evidence_record_count(), count);
    assert!(set.evidence_record_count() <= count);
    assert!(set.evidence_record_count() > count - 1);
}

#[test]
fn provenance_keeps_distinct_overlay_scopes() {
    let scopes = vec![
        PolicyOverlayScope::AllFindings,
        PolicyOverlayScope::SourceScenario {
            scenario_id: SourceScenarioId::try_new("cvss", "scenario-one").unwrap(),
        },
    ];
    let provenance = CvssAssessmentProvenance::try_new(
        "bifrost.test".to_string(),
        Vec::new(),
        scopes.clone(),
        Vec::new(),
    )
    .unwrap();
    assert_eq!(provenance.overlay_scopes().len(), 2);
    assert!(
        scopes
            .iter()
            .all(|scope| provenance.overlay_scopes().contains(scope))
    );
}

#[test]
fn retained_bytes_include_all_owned_cvss_payloads() {
    let scored = scored(&[]);
    let CvssAssessment::Scored {
        vector,
        components,
        metrics,
        provenance,
        ..
    } = &scored
    else {
        unreachable!()
    };
    let expected = size_of::<CvssAssessment>()
        + retained_extra(vector)
        + retained_extra(components)
        + retained_extra(metrics)
        + retained_extra(provenance);
    assert_eq!(scored.retained_size(), expected);

    let unscored = unscored(Vec::new(), &[]);
    let CvssAssessment::Unscored {
        established,
        missing_base_metrics,
        reasons,
        provenance,
        ..
    } = &unscored
    else {
        unreachable!()
    };
    let expected = size_of::<CvssAssessment>()
        + retained_extra(established)
        + retained_extra(missing_base_metrics)
        + retained_extra(reasons)
        + retained_extra(provenance);
    assert_eq!(unscored.retained_size(), expected);

    let hash_provenance = make_provenance(
        &[],
        vec![
            CvssEvidenceContentHash::from_bytes([1; 32]),
            CvssEvidenceContentHash::from_bytes([2; 32]),
        ],
    );
    let expected = size_of::<CvssAssessmentProvenance>()
        + retained_extra(&hash_provenance.reducer)
        + retained_extra(&hash_provenance.evidence_refs)
        + retained_extra(&hash_provenance.overlay_scopes)
        + retained_extra(&hash_provenance.content_hashes);
    assert_eq!(hash_provenance.retained_size(), expected);
}

fn witness(index: usize) -> WitnessId {
    WitnessId::try_new("cvss", format!("witness-{index:04}")).unwrap()
}

fn detailed_variant(
    byte: u8,
    witnesses: Vec<WitnessId>,
    witnesses_truncated: bool,
    scenarios_truncated: bool,
) -> CvssAssessmentVariant {
    CvssAssessmentVariant::try_new(
        VulnerabilityIdentity::from_bytes([byte; 32]),
        vec![SourceScenarioId::try_new("cvss", format!("scenario-{byte}")).unwrap()],
        scenarios_truncated,
        u64::from(scenarios_truncated),
        SourceScenarioSetHash::from_bytes([byte; 32]),
        witnesses,
        witnesses_truncated,
        unscored(vec![metric(CvssBaseMetric::Av, byte)], &[]),
    )
    .unwrap()
}

#[test]
fn witness_limit_preserves_every_reference_and_refuses_one_past() {
    let refs = (0..MAX_WITNESS_REFS).map(witness).collect::<Vec<_>>();
    let variant = detailed_variant(1, refs.clone(), false, false);
    assert_eq!(variant.witness_refs(), refs);
    let mut over = refs;
    over.push(witness(MAX_WITNESS_REFS));
    assert!(matches!(
        CvssAssessmentVariant::try_new(
            VulnerabilityIdentity::from_bytes([1; 32]),
            Vec::new(),
            false,
            0,
            SourceScenarioSetHash::from_bytes([1; 32]),
            over,
            false,
            unscored(Vec::new(), &[]),
        ),
        Err(CvssValidationError::TooManyItems {
            field: "cvss_variant.witness_refs",
            max: MAX_WITNESS_REFS
        })
    ));

    let set = CvssAssessmentSet::try_new(vec![variant], None).unwrap();
    let mut collected = Vec::new();
    set.append_witness_refs(&mut collected);
    assert_eq!(collected.len(), MAX_WITNESS_REFS);
    assert!(
        collected
            .iter()
            .all(|id| set.variants()[0].witness_refs().contains(id))
    );

    let retained_after_omission =
        detailed_variant(2, (0..MAX_WITNESS_REFS).map(witness).collect(), true, false);
    let report = serde_json::to_value(&retained_after_omission).unwrap();
    assert_eq!(report["witness_refs_truncated"], true);
    assert!(retained_after_omission.validate().is_ok());
}

#[test]
fn source_scenario_limit_and_truncation_consistency_are_reported() {
    let scenarios = (0..MAX_SOURCE_SCENARIOS)
        .map(|index| SourceScenarioId::try_new("cvss", format!("scenario-{index:05}")).unwrap())
        .collect::<Vec<_>>();
    let construct = |values: Vec<SourceScenarioId>, truncated, omitted| {
        CvssAssessmentVariant::try_new(
            VulnerabilityIdentity::from_bytes([3; 32]),
            values,
            truncated,
            omitted,
            SourceScenarioSetHash::from_bytes([3; 32]),
            Vec::new(),
            false,
            unscored(Vec::new(), &[]),
        )
    };
    let exact = construct(scenarios.clone(), false, 0).unwrap();
    assert_eq!(exact.source_scenarios().len(), MAX_SOURCE_SCENARIOS);
    assert!(!exact.source_scenarios_truncated());
    let after_omission = construct(scenarios.clone(), true, 1).unwrap();
    assert!(after_omission.source_scenarios_truncated());
    assert_eq!(
        serde_json::to_value(&after_omission).unwrap()["source_scenarios_truncated"],
        true
    );
    let mut over = scenarios.clone();
    over.push(SourceScenarioId::try_new("cvss", "scenario-over").unwrap());
    assert!(matches!(
        construct(over, true, 1),
        Err(CvssValidationError::TooManyItems {
            field: "source_scenarios",
            max: MAX_SOURCE_SCENARIOS
        })
    ));
    assert!(matches!(
        construct(scenarios.clone(), false, 1),
        Err(CvssValidationError::InvalidTruncation {
            field: "cvss_variant.source_scenarios"
        })
    ));
    assert!(matches!(
        construct(scenarios, true, 0),
        Err(CvssValidationError::InvalidTruncation {
            field: "cvss_variant.source_scenarios"
        })
    ));
}

#[test]
fn one_truncated_variant_marks_the_whole_report_incomplete() {
    // A source with one more item than a display cap retains its boundary
    // subset and carries the omission; a second variant can still be complete.
    let truncated = detailed_variant(1, vec![witness(0), witness(1)], true, true);
    assert!(truncated.validate().is_ok());
    let complete = detailed_variant(2, vec![witness(2)], false, false);
    let set = CvssAssessmentSet::try_new(vec![truncated, complete], None).unwrap();
    assert!(set.has_truncated_witness_refs());
    assert!(set.has_truncated_source_scenarios());
    assert_eq!(set.evidence_record_count(), 2);
    assert!(set.evidence_record_count() <= 2);
    assert!(set.evidence_record_count() > 1);

    let report = serde_json::to_value(&set).unwrap();
    let variants = report["variants"].as_array().unwrap();
    assert!(variants.iter().any(|v| v["witness_refs_truncated"] == true));
    assert!(
        variants
            .iter()
            .any(|v| v["source_scenarios_truncated"] == true)
    );
    assert!(
        variants
            .iter()
            .any(|v| v["witness_refs_truncated"] == false)
    );
}

#[test]
fn repeated_reference_retention_keeps_earlier_truncation() {
    let mut evidence = metric(CvssBaseMetric::Av, 1);
    let retained = Vec::new();
    evidence.retain_evidence_refs(&retained);
    assert!(evidence.evidence_refs_truncated);
    assert!(evidence.evidence_refs().is_empty());
    evidence.retain_evidence_refs(&retained);
    assert!(evidence.evidence_refs_truncated);
    assert!(evidence.validate().is_ok());
}

#[test]
fn retained_bytes_include_assumptions_witnesses_and_selection_reason() {
    let evidence = metric(CvssBaseMetric::Av, 1);
    assert!(!evidence.assumptions().is_empty());
    let expected = size_of::<CvssMetricEvidence>()
        + retained_extra(&evidence.evidence_refs)
        + retained_extra(&evidence.rationale)
        + retained_extra(&evidence.assumptions)
        + retained_extra(&evidence.assessor_or_tool)
        + retained_extra(&evidence.assessed_at);
    assert_eq!(evidence.retained_size(), expected);

    let variant = detailed_variant(1, vec![witness(0), witness(1)], false, false);
    let expected = size_of::<CvssAssessmentVariant>()
        + retained_extra(&variant.source_scenarios)
        + retained_extra(&variant.witness_refs)
        + retained_extra(&variant.assessment);
    assert_eq!(variant.retained_size(), expected);

    let set = CvssAssessmentSet::try_new(vec![variant], None).unwrap();
    assert!(set.selection_rationale().is_some());
    let expected = size_of::<CvssAssessmentSet>()
        + retained_extra(&set.variants)
        + retained_extra(&set.selection_rationale);
    assert_eq!(set.retained_size(), expected);
}

#[test]
fn fresh_metric_evidence_is_complete_until_references_are_removed() {
    let base = metric(CvssBaseMetric::Av, 1);
    let refs = vec![evidence_ref("first"), evidence_ref("second")];
    let mut evidence = CvssMetricEvidence::try_new(
        base.metric(),
        base.value(),
        base.basis(),
        refs.clone(),
        base.rationale().to_string(),
        base.assumptions().to_vec(),
        base.assessor_or_tool().to_string(),
        None,
        base.system_scope(),
        base.content_hash(),
    )
    .unwrap();
    assert!(!evidence.evidence_refs_truncated);
    evidence.retain_evidence_refs(&refs);
    assert!(!evidence.evidence_refs_truncated);
    assert_eq!(evidence.evidence_refs(), refs);
    evidence.retain_evidence_refs(&[evidence_ref("first")]);
    assert!(evidence.evidence_refs_truncated);
}

#[test]
fn assessed_at_preserves_fractional_seconds_in_utc_report() {
    let base = metric(CvssBaseMetric::Av, 2);
    let evidence = CvssMetricEvidence::try_new(
        base.metric(),
        base.value(),
        base.basis(),
        base.evidence_refs().to_vec(),
        base.rationale().to_string(),
        base.assumptions().to_vec(),
        base.assessor_or_tool().to_string(),
        Some("2024-01-02T04:04:05.120+01:00".to_string()),
        base.system_scope(),
        base.content_hash(),
    )
    .unwrap();
    assert_eq!(evidence.assessed_at(), Some("2024-01-02T03:04:05.120Z"));
    assert_eq!(
        serde_json::to_value(&evidence).unwrap()["assessed_at"],
        "2024-01-02T03:04:05.120Z"
    );
}

#[test]
fn threat_nomenclature_has_its_distinct_report_tag() {
    assert_eq!(serde_json::to_value(CvssNomenclature::BT).unwrap(), "bt");
    assert_ne!(
        serde_json::to_value(CvssNomenclature::BT).unwrap(),
        serde_json::to_value(CvssNomenclature::BE).unwrap()
    );
}

#[test]
fn incomplete_run_reason_is_canonical_without_losing_its_cause() {
    use crate::finding::PolicyIncompleteReason;
    let cancelled = CvssUnscoredReason::RunIncomplete {
        reason: PolicyIncompleteReason::Cancelled,
    };
    let deadline = CvssUnscoredReason::RunIncomplete {
        reason: PolicyIncompleteReason::DeadlineExceeded,
    };
    let left = CvssAssessment::unscored(
        CvssVersion::V4_0,
        Vec::new(),
        Vec::new(),
        vec![deadline.clone(), cancelled.clone(), cancelled.clone()],
        make_provenance(&[], Vec::new()),
    )
    .unwrap();
    let right = CvssAssessment::unscored(
        CvssVersion::V4_0,
        Vec::new(),
        Vec::new(),
        vec![cancelled, deadline],
        make_provenance(&[], Vec::new()),
    )
    .unwrap();
    assert_eq!(left, right);
    let distinct = CvssAssessment::unscored(
        CvssVersion::V4_0,
        Vec::new(),
        Vec::new(),
        vec![CvssUnscoredReason::RunIncomplete {
            reason: PolicyIncompleteReason::QueryResultLimit,
        }],
        make_provenance(&[], Vec::new()),
    )
    .unwrap();
    assert_ne!(left, distinct);
    let report = serde_json::to_value(&left).unwrap();
    assert_eq!(report["reasons"].as_array().unwrap().len(), 2);
    assert!(
        report["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .all(|reason| reason["type"] == "run_incomplete")
    );
}

#[test]
fn incoherent_scenario_rationale_counts_owned_capacity() {
    let mut rationale = String::with_capacity(512);
    rationale.push_str("Evidence cannot be correlated");
    assert!(rationale.capacity() > rationale.len());
    let reason = CvssUnscoredReason::incoherent_scenario(
        SourceScenarioSetHash::from_bytes([3; 32]),
        vec![SourceScenarioId::try_new("cvss", "scenario-a").unwrap()],
        false,
        0,
        rationale,
    )
    .unwrap();
    let CvssUnscoredReason::IncoherentScenario {
        scenario_ids,
        rationale,
        ..
    } = &reason
    else {
        unreachable!()
    };
    let exact_bytes =
        size_of::<CvssUnscoredReason>() + retained_extra(scenario_ids) + retained_extra(rationale);
    assert_eq!(reason.retained_size(), exact_bytes);
    assert!(reason.retained_size() <= exact_bytes);
    assert!(reason.retained_size() > exact_bytes - 1);
}

#[test]
fn finding_scenario_overlay_requires_both_parts_to_match() {
    let policy = PolicyId::new("test.cvss-overlay").unwrap();
    let finding_a = PolicyFindingId::from_bytes([1; 32]);
    let finding_b = PolicyFindingId::from_bytes([2; 32]);
    let scenario_x = SourceScenarioId::try_new("cvss", "scenario-x").unwrap();
    let scenario_y = SourceScenarioId::try_new("cvss", "scenario-y").unwrap();
    let scope = PolicyOverlayScope::FindingScenario {
        finding: finding_a,
        scenario: scenario_x.clone(),
    };
    assert!(scope.applies_to(&policy, &finding_a, std::slice::from_ref(&scenario_x)));
    assert!(!scope.applies_to(&policy, &finding_a, &[scenario_y]));
    assert!(!scope.applies_to(&policy, &finding_b, &[scenario_x]));
}
