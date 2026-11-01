use super::*;

fn read_finding(value: &serde_json::Value) -> Result<PolicyFinding, serde_json::Error> {
    let json = serde_json::to_string(value).unwrap();
    let mut decoder = serde_json::Deserializer::from_str(&json);
    serde::de::DeserializeSeed::deserialize(
        PolicyFindingSeed::new(&PolicyBudget::default()),
        &mut decoder,
    )
}

fn plain_finding() -> serde_json::Value {
    let budget = PolicyBudget::default();
    let finding = finding_with(
        &loaded_match_policy(),
        match_evidence(),
        Vec::new(),
        None,
        &budget,
    )
    .unwrap();
    serde_json::to_value(finding).unwrap()
}

#[test]
fn certainty_reasons_must_all_be_valid_and_canonical() {
    let malformed = CertaintyReason::AnalyzerAmbiguity {
        code: "bad reason".into(),
    };
    assert!(
        FindingCertainty::possible(vec![CertaintyReason::AmbiguousReceiver, malformed.clone()])
            .is_err()
    );

    let mut value = plain_finding();
    value["certainty"] = serde_json::json!({
        "type": "possible",
        "reasons": [CertaintyReason::AmbiguousReceiver, malformed],
    });
    let error = read_finding(&value).unwrap_err().to_string();
    assert!(
        error.contains("bad reason") || error.contains("identifier"),
        "{error}"
    );

    value["certainty"] = serde_json::json!({
        "type": "possible",
        "reasons": [CertaintyReason::AmbiguousReceiver, CertaintyReason::AmbiguousReceiver],
    });
    let error = read_finding(&value).unwrap_err().to_string();
    assert!(error.contains("certainty_reasons"), "{error}");
}

#[test]
fn incomplete_reason_set_requires_canonical_order_and_distinct_values() {
    let mut value = plain_finding();
    value["completeness"] = serde_json::json!({
        "type": "partial",
        "reasons": [FindingIncompleteReason::WitnessTruncated, FindingIncompleteReason::WitnessTruncated],
    });
    let error = read_finding(&value).unwrap_err().to_string();
    assert!(error.contains("finding_incomplete_reasons"), "{error}");
    value["completeness"] = serde_json::json!({
        "type": "partial",
        "reasons": [FindingIncompleteReason::EvidenceTruncated, FindingIncompleteReason::WitnessTruncated],
    });
    let error = read_finding(&value).unwrap_err().to_string();
    assert!(error.contains("finding_incomplete_reasons"), "{error}");
}

#[test]
fn a_full_typed_reason_input_is_allowed() {
    let reasons = vec![PolicyIncompleteReason::PartialDiscovery; MAX_TYPED_REASONS];
    let completion = PolicyRunCompletion::inconclusive(reasons).unwrap();
    assert_eq!(
        completion.inconclusive_scope(),
        Some(&InconclusiveScope::Run)
    );
    assert!(matches!(
        PolicyRunCompletion::inconclusive(vec![
            PolicyIncompleteReason::PartialDiscovery;
            MAX_TYPED_REASONS + 1
        ]),
        Err(CompletionReasonError::TooMany {
            max_items: MAX_TYPED_REASONS
        })
    ));
}

#[test]
fn certainty_reason_labels_name_the_distinct_causes() {
    assert_eq!(
        CertaintyReason::AmbiguousReceiver.label(),
        "ambiguous_receiver"
    );
    assert_eq!(
        CertaintyReason::MultipleCandidateDeclarations.label(),
        "multiple_candidate_declarations"
    );
    let reason = CertaintyReason::analyzer_ambiguity("mixed_case_code").unwrap();
    assert_eq!(reason.label(), "mixed_case_code");
    assert!(CertaintyReason::analyzer_ambiguity("MixedCaseCode").is_err());
    assert!(
        FindingCertainty::possible(vec![CertaintyReason::AnalyzerAmbiguity {
            code: "not a code".into()
        }])
        .is_err()
    );
}

#[test]
fn a_display_region_requires_a_byte_span() {
    assert_eq!(
        PolicySourceLocation::try_new(
            path(),
            None,
            Some(PolicyDisplayRegion::new(1, 1, 1, 2).unwrap()),
        ),
        Err(PolicyLocationError::SpanRegionMismatch),
    );
}

#[test]
fn provenance_steps_keep_their_via_witness_and_validate_operations() {
    let via = PolicyQueryResultRef::file(path());
    let step =
        PolicyQueryProvenanceStep::try_new("call_target", call_terminal(), Some(via.clone()))
            .unwrap();
    assert_eq!(step.via(), Some(&via));
    assert_eq!(step.operation(), "call_target");
    assert!(PolicyQueryProvenanceStep::try_new("call target", call_terminal(), Some(via)).is_err());
    let invalid_via = PolicyQueryResultRef::ConfigurationFact {
        location: location(),
        id: "bad id".into(),
        fact_id: "good_id".into(),
    };
    assert!(
        PolicyQueryProvenanceStep::try_new("call_target", call_terminal(), Some(invalid_via))
            .is_err()
    );
}

#[test]
fn provenance_step_count_and_retained_bytes_have_distinct_limits() {
    let step =
        PolicyQueryProvenanceStep::try_new("call_target", PolicyQueryResultRef::file(path()), None)
            .unwrap();
    let at_count_cap = vec![step; MAX_QUERY_PROVENANCE_STEPS];
    assert!(matches!(
        PolicyQueryProvenance::try_new(
            Vec::new(),
            PolicyQueryResultRef::file(path()),
            at_count_cap.clone()
        ),
        Err(ReportValueError::TooManyBytes {
            field: "query_provenance",
            max_bytes: MAX_EVIDENCE_BYTES
        })
    ));
    let mut over_count_cap = at_count_cap;
    over_count_cap.push(over_count_cap[0].clone());
    assert!(matches!(
        PolicyQueryProvenance::try_new(
            Vec::new(),
            PolicyQueryResultRef::file(path()),
            over_count_cap
        ),
        Err(ReportValueError::TooManyItems {
            field: "query_provenance_steps",
            max_items: MAX_QUERY_PROVENANCE_STEPS
        })
    ));
}

fn assertion_with_derivations(
    derivations: Vec<EffectDerivationEvidence>,
    omitted: u64,
) -> Result<AssertionFindingEvidence, ReportValueError> {
    AssertionFindingEvidence::try_new(
        super::super::super::finding_identity::AssertionFindingAnchor::new(
            path(),
            "ast:7",
            "no_reads",
        ),
        "occurrence",
        "value_reference",
        "cardinality",
        "none",
        None,
        1,
        vec![PolicyCapability::TaintEvaluation],
        derivations,
        omitted,
    )
}

#[test]
fn omitted_effect_derivation_is_reported_even_when_only_one_is_missing() {
    let evidence = assertion_with_derivations(Vec::new(), 1).unwrap();
    assert!(evidence.effect_derivations_truncated());
    assert_eq!(evidence.omitted_effect_derivations_lower_bound(), 1);
    let rendered = serde_json::to_value(&evidence).unwrap();
    assert_eq!(rendered["effect_derivations_truncated"], true);
    assert_eq!(rendered["omitted_effect_derivations_lower_bound"], 1);
}

#[test]
fn assertion_effect_chains_count_toward_the_evidence_budget() {
    let derivation = EffectDerivationEvidence::try_new(
        "effect",
        "known",
        "direct",
        None,
        None,
        None,
        None,
        "complete",
        Some("x".repeat(MAX_REPORT_PROSE_BYTES)),
        1,
        false,
    )
    .unwrap();
    assert!(assertion_with_derivations(vec![derivation.clone(); 8], 0).is_ok());
    assert!(matches!(
        assertion_with_derivations(vec![derivation; MAX_EFFECT_DERIVATIONS], 0),
        Err(ReportValueError::TooManyBytes {
            field: "assertion_evidence",
            max_bytes: MAX_EVIDENCE_BYTES
        })
    ));
}

#[test]
fn flow_payload_counts_toward_the_run_byte_budget() {
    use crate::definition::{TaintEntryId, TaintLabel};
    use crate::finding_identity::{
        AnalysisEventRef, AnalysisFindingId, OpaqueFindingKey, SourceScenarioId,
    };
    use crate::future_evidence::{TaintFindingAnchor, TaintProjectionFactsHash};
    use crate::resolved::ResolvedEndpointIdentity;

    let policy_id = PolicyId::new("security.flow").unwrap();
    let endpoint = |name| ResolvedEndpointIdentity::Local {
        policy_id: policy_id.clone(),
        entry_id: TaintEntryId::new(name).unwrap(),
    };
    let scenarios = vec![SourceScenarioId::try_new("taint", "scenario").unwrap()];
    let scenario_hash = SourceScenarioSetHash::try_from_scenarios(scenarios.clone()).unwrap();
    let taint = TaintFindingEvidence::try_new_with_threat_model(
        AnalysisFindingId::try_new("taint", "finding").unwrap(),
        TaintFindingAnchor::weak(OpaqueFindingKey::try_new("taint", "flow").unwrap()),
        AnalysisEventRef::try_new("taint", "sink-event").unwrap(),
        endpoint("source"),
        endpoint("sink"),
        "source".into(),
        None,
        "sink".into(),
        Vec::new(),
        Vec::new(),
        None,
        Vec::new(),
        Vec::new(),
        vec![TaintLabel::new("public").unwrap()],
        Vec::new(),
        false,
        scenarios,
        false,
        0,
        scenario_hash,
        Vec::new(),
        false,
        TaintProjectionFactsHash::from_bytes([1; 32]),
        &PolicyBudget::default(),
    )
    .unwrap();
    let payload_bytes = taint.retained_size();
    let evidence = PolicyFindingEvidence::Flow {
        evidence: FlowFindingEvidence::new(taint),
    };
    let loaded = loaded_match_policy();
    let proof = ProofMetadata::try_new(
        ProofState::Proven,
        vec![ProofReason::DirectStructuralMatch],
        Vec::new(),
    )
    .unwrap();
    let finding = PolicyFinding::try_new(
        loaded.definition().metadata.id.clone(),
        loaded.semantic_hash(),
        FindingSeverity::Warning,
        "flow".into(),
        FindingClassification::Unclassified,
        FindingCertainty::Definite,
        FindingCompleteness::partial(vec![FindingIncompleteReason::StableAnchorWeak]).unwrap(),
        location(),
        Vec::new(),
        false,
        0,
        evidence,
        false,
        0,
        None,
        None,
        proof,
        Vec::new(),
        false,
        0,
        &PolicyBudget::default(),
    )
    .unwrap();
    let completion =
        PolicyRunCompletion::inconclusive(vec![PolicyIncompleteReason::StableAnchorUnavailable])
            .unwrap();
    let run_at = |budget: &PolicyBudget| {
        PolicyRun::try_new(
            loaded.definition().metadata.id.clone(),
            loaded.semantic_hash(),
            PolicyAnalysisType::Flow,
            completion.clone(),
            vec![finding.clone()],
            Vec::new(),
            false,
            PolicyWorkReport::default(),
            budget,
        )
    };
    let full = run_at(&PolicyBudget::default()).unwrap();
    let reported_payload = finding.evidence().retained_size();
    let expected_evidence_bytes = std::mem::size_of::<PolicyFindingEvidence>() + payload_bytes
        - std::mem::size_of::<FlowFindingEvidence>();
    let exact = full.retained_size() - reported_payload + expected_evidence_bytes;
    let budget = |max| {
        PolicyBudget::builder()
            .with_max_retained_report_bytes(max)
            .unwrap()
            .build()
            .unwrap()
    };
    assert!(run_at(&budget(exact)).is_ok());
    assert!(
        matches!(run_at(&budget(exact - 1)), Err(PolicyRunError::RetainedReportBytesExceeded { max }) if max == exact - 1)
    );
}
