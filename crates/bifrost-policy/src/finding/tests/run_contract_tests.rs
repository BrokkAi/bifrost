use super::*;
use crate::classification::{ClassificationProvenance, TaxonomyClassification};
use crate::definition::TaintEntryId;
use crate::finding_identity::{AnalysisEventRef, AnalysisFindingId, OpaqueFindingKey};
use crate::future_evidence::{
    FlowFindingEvidence, TaintFindingAnchor, TaintFindingEvidence, TaintProjectionFactsHash,
};

#[test]
fn empty_run_admits_exact_finding_limit() {
    let run = run_at(PolicyRunCompletion::Complete);
    let budget = PolicyBudget::builder()
        .with_max_findings(0)
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(run.validate_against_budget(&budget), Ok(()));
}

#[test]
fn detached_findings_are_no_longer_retained_by_run() {
    let mut run = run_at(PolicyRunCompletion::Complete);
    let loaded = loaded_match_policy();
    let finding = finding_with(
        &loaded,
        match_evidence(),
        Vec::new(),
        None,
        &PolicyBudget::default(),
    )
    .unwrap();
    run.replace_findings(vec![finding]);
    let detached = run.take_findings();
    assert_eq!(detached.len(), 1);
    assert_eq!(run.work().retained_findings(), 0);
}

#[test]
fn obligation_overflow_restores_prior_obligations() {
    let mut run = run_at(
        PolicyRunCompletion::inconclusive(vec![PolicyIncompleteReason::PipelineRowBudget]).unwrap(),
    );
    run.set_obligations(&[obligation()], false, 0, &PolicyBudget::default())
        .unwrap();
    let before = run.obligations().to_vec();
    let limit = run.retained_size();
    let budget = PolicyBudget::builder()
        .with_max_retained_report_bytes(limit)
        .unwrap()
        .build()
        .unwrap();
    let mut larger = obligation();
    larger.assertion = "a much larger obligation assertion that exceeds the old size".to_string();
    assert!(matches!(
        run.set_obligations(&[larger], false, 0, &budget),
        Err(PolicyRunError::RetainedReportBytesExceeded { .. })
    ));
    assert_eq!(run.obligations(), before);
}

#[test]
fn diagnostic_loss_invalidates_reliable_completion() {
    let mut run = run_at(PolicyRunCompletion::Complete);
    run.replace_diagnostics(Vec::new(), true);
    assert_eq!(
        run.validate_against_budget(&PolicyBudget::default()),
        Err(PolicyRunError::CompletionDoesNotReflectDiagnostics)
    );
}

#[test]
fn fail_closed_unknown_verdict_is_an_error() {
    let mut run = run_at(
        PolicyRunCompletion::inconclusive(vec![PolicyIncompleteReason::PipelineRowBudget]).unwrap(),
    );
    run.apply_unknown_verdict(UnknownVerdict::FailClosed, &PolicyBudget::default())
        .unwrap();
    let diagnostic = run
        .diagnostics()
        .iter()
        .find(|diagnostic| *diagnostic.code() == PolicyDiagnosticCode::UnknownVerdictFailClosed)
        .unwrap();
    assert_eq!(diagnostic.severity(), PolicyDiagnosticSeverity::Error);
    assert_eq!(diagnostic.impact(), PolicyDiagnosticImpact::RunIncomplete);
}

#[test]
fn diagnostic_cap_retains_exactly_two_distinct_families() {
    let mut diagnostics = ["alpha", "beta", "gamma"]
        .into_iter()
        .map(|family| {
            PolicyDiagnostic::try_new_in_family(
                PolicyDiagnosticCode::EvaluationFailure,
                PolicyDiagnosticSeverity::Warning,
                PolicyDiagnosticImpact::RunIncomplete,
                family,
                family,
                None,
                Vec::new(),
            )
            .unwrap()
        })
        .collect();
    assert!(normalize_policy_diagnostics_bounded(&mut diagnostics, 2));
    assert_eq!(diagnostics.len(), 2);
}

#[test]
fn changed_range_procedures_count_at_the_report_byte_edge() {
    let base = run_at(PolicyRunCompletion::Complete);
    let scope = PolicyRunScope::changed_range(vec![location()], Vec::new());
    let expected = base.retained_size()
        + scope.examined_procedures.as_ref().unwrap().capacity()
            * size_of::<PolicySourceLocation>()
        + scope
            .examined_procedures
            .as_ref()
            .unwrap()
            .iter()
            .map(retained_extra)
            .sum::<usize>();
    let run = base.with_scope(Some(scope));
    let exact = PolicyBudget::builder()
        .with_max_retained_report_bytes(expected)
        .unwrap()
        .build()
        .unwrap();
    let below = PolicyBudget::builder()
        .with_max_retained_report_bytes(expected - 1)
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(run.validate_against_budget(&exact), Ok(()));
    assert!(matches!(
        run.validate_against_budget(&below),
        Err(PolicyRunError::RetainedReportBytesExceeded { .. })
    ));
}

#[test]
fn one_character_identifier_is_accepted_in_a_finding_value() {
    let value = CertaintyReason::analyzer_ambiguity("x").unwrap();
    assert_eq!(value.label(), "x");
}

#[test]
fn folded_multisite_diagnostic_has_no_single_site_location() {
    let diagnostic = |line| {
        PolicyDiagnostic::try_new_in_family(
            PolicyDiagnosticCode::EvaluationFailure,
            PolicyDiagnosticSeverity::Warning,
            PolicyDiagnosticImpact::RunIncomplete,
            "site_family",
            "one site failed",
            Some(PolicySourceLocation::span(
                path(),
                PolicyByteSpan::new(line, line + 1).unwrap(),
                PolicyDisplayRegion::new(line, 1, line, 2).unwrap(),
            )),
            Vec::new(),
        )
        .unwrap()
    };
    let mut diagnostics = vec![diagnostic(1), diagnostic(2)];
    assert!(normalize_policy_diagnostics_bounded(&mut diagnostics, 1));
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0].family_count(), 2);
    assert!(diagnostics[0].primary().is_none());
}

fn taint_evidence_with_witness() -> PolicyFindingEvidence {
    let scenario = crate::finding_identity::SourceScenarioId::try_new("taint", "a").unwrap();
    let scenario_hash = SourceScenarioSetHash::try_from_scenarios(vec![scenario.clone()]).unwrap();
    let endpoint = crate::resolved::ResolvedEndpointIdentity::Local {
        policy_id: PolicyId::new("security.flow").unwrap(),
        entry_id: TaintEntryId::new("endpoint").unwrap(),
    };
    let taint = TaintFindingEvidence::try_new(
        AnalysisFindingId::try_new("taint", "one").unwrap(),
        TaintFindingAnchor::weak(OpaqueFindingKey::try_new("taint", "one").unwrap()),
        AnalysisEventRef::try_new("taint", "sink").unwrap(),
        endpoint.clone(),
        endpoint,
        "source".to_string(),
        "sink".to_string(),
        Vec::new(),
        Vec::new(),
        None,
        Vec::new(),
        Vec::new(),
        vec![crate::definition::TaintLabel::new("untrusted").unwrap()],
        Vec::new(),
        false,
        vec![scenario],
        false,
        0,
        scenario_hash,
        vec![WitnessId::try_new("taint", "missing").unwrap()],
        false,
        TaintProjectionFactsHash::from_bytes([1; 32]),
        &PolicyBudget::default(),
    )
    .unwrap();
    PolicyFindingEvidence::Taint { evidence: taint }
}

fn weak_finding_with(
    evidence: PolicyFindingEvidence,
    cvss: Option<CvssAssessmentSet>,
) -> Result<PolicyFinding, PolicyFindingError> {
    let loaded = loaded_match_policy();
    PolicyFinding::try_new(
        loaded.definition().metadata.id.clone(),
        loaded.semantic_hash(),
        FindingSeverity::Warning,
        "finding".to_string(),
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
        cvss,
        None,
        ProofMetadata::try_new(
            ProofState::Proven,
            vec![ProofReason::DirectStructuralMatch],
            Vec::new(),
        )
        .unwrap(),
        Vec::new(),
        false,
        0,
        &PolicyBudget::default(),
    )
}

#[test]
fn taint_first_witness_reference_must_be_retained() {
    assert!(matches!(
        weak_finding_with(taint_evidence_with_witness(), None),
        Err(PolicyFindingError::DanglingWitnessReference { .. })
    ));
}

#[test]
fn flow_first_witness_reference_must_be_retained() {
    let PolicyFindingEvidence::Taint { evidence } = taint_evidence_with_witness() else {
        unreachable!()
    };
    let flow = PolicyFindingEvidence::Flow {
        evidence: FlowFindingEvidence::new(evidence),
    };
    assert!(matches!(
        weak_finding_with(flow, None),
        Err(PolicyFindingError::DanglingWitnessReference { .. })
    ));
}

#[test]
fn cvss_scenario_display_must_join_every_taint_scenario() {
    let endpoint = crate::resolved::ResolvedEndpointIdentity::Local {
        policy_id: PolicyId::new("security.flow").unwrap(),
        entry_id: TaintEntryId::new("endpoint").unwrap(),
    };
    let scenario =
        |name| crate::finding_identity::SourceScenarioId::try_new("taint", name).unwrap();
    let a = scenario("a");
    let b = scenario("b");
    let c = scenario("c");
    let set_hash = SourceScenarioSetHash::try_from_scenarios(vec![a.clone(), b.clone()]).unwrap();
    let taint = TaintFindingEvidence::try_new(
        AnalysisFindingId::try_new("taint", "two_scenarios").unwrap(),
        TaintFindingAnchor::weak(OpaqueFindingKey::try_new("taint", "two_scenarios").unwrap()),
        AnalysisEventRef::try_new("taint", "sink").unwrap(),
        endpoint.clone(),
        endpoint,
        "source".to_string(),
        "sink".to_string(),
        Vec::new(),
        Vec::new(),
        None,
        Vec::new(),
        Vec::new(),
        vec![crate::definition::TaintLabel::new("untrusted").unwrap()],
        Vec::new(),
        false,
        vec![a.clone(), b],
        false,
        0,
        set_hash,
        Vec::new(),
        false,
        TaintProjectionFactsHash::from_bytes([1; 32]),
        &PolicyBudget::default(),
    )
    .unwrap();
    let vulnerability = VulnerabilityIdentity::from_bytes(
        crate::future_evidence::taint_vulnerability_digest(taint.anchor()),
    );
    let cvss = unscored_cvss(vulnerability, vec![a, c], set_hash, false);
    assert!(matches!(
        weak_finding_with(PolicyFindingEvidence::Taint { evidence: taint }, Some(cvss)),
        Err(PolicyFindingError::CvssSourceScenarioJoinMismatch)
    ));
}

fn assert_run_byte_edge(run: &PolicyRun, expected: usize) {
    let exact = PolicyBudget::builder()
        .with_max_retained_report_bytes(expected)
        .unwrap()
        .build()
        .unwrap();
    let below = PolicyBudget::builder()
        .with_max_retained_report_bytes(expected - 1)
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(run.validate_against_budget(&exact), Ok(()));
    assert!(matches!(
        run.validate_against_budget(&below),
        Err(PolicyRunError::RetainedReportBytesExceeded { .. })
    ));
}

#[test]
fn unsupported_capability_heap_counts_at_byte_edge() {
    let base = run_at(PolicyRunCompletion::Complete).retained_size();
    let capability = PolicyCapability::query_feature("rust", "occurrences").unwrap();
    let PolicyCapability::QueryFeature { language, feature } = &capability else {
        unreachable!()
    };
    let expected = base + language.capacity() + feature.capacity();
    let run = run_at(PolicyRunCompletion::Unsupported { capability });
    assert_run_byte_edge(&run, expected);
}

#[test]
fn unsupported_domain_reason_counts_at_byte_edge() {
    let base = run_at(PolicyRunCompletion::Complete).retained_size();
    let capability = PolicyCapability::QueryDomain {
        domain: "rust".to_string(),
        capability: Some("resolution".to_string()),
        reason: "missing_provider".to_string(),
    };
    let PolicyCapability::QueryDomain {
        domain,
        capability: label,
        reason,
    } = &capability
    else {
        unreachable!()
    };
    let expected =
        base + domain.capacity() + label.as_ref().unwrap().capacity() + reason.capacity();
    let run = run_at(PolicyRunCompletion::Unsupported { capability });
    assert_run_byte_edge(&run, expected);
}

#[test]
fn unavailable_capability_reason_counts_at_byte_edge() {
    let base = run_at(PolicyRunCompletion::Complete).retained_size();
    let unavailable = UnavailablePolicyCapability {
        label: "rust".to_string(),
        reason: "model_not_installed".to_string(),
    };
    let expected = base
        + size_of::<UnavailablePolicyCapability>()
        + unavailable.label.capacity()
        + unavailable.reason.capacity();
    let run = run_at(PolicyRunCompletion::NotRun {
        unavailable_capabilities: vec![unavailable],
        selected_by: PolicySelectionProvenance::ExplicitPolicyId,
    });
    assert_run_byte_edge(&run, expected);
}

#[test]
fn proof_only_evidence_reference_obeys_finding_cap() {
    let loaded = loaded_match_policy();
    let mut finding = finding_with(
        &loaded,
        match_evidence(),
        Vec::new(),
        None,
        &PolicyBudget::default(),
    )
    .unwrap();
    finding.proof = ProofMetadata::try_new(
        ProofState::Proven,
        vec![ProofReason::DirectStructuralMatch],
        vec![EvidenceRef::try_new("query", "proof").unwrap()],
    )
    .unwrap();
    let zero = PolicyBudget::builder()
        .with_max_evidence_refs_per_finding(0)
        .unwrap()
        .build()
        .unwrap();
    assert!(matches!(
        finding.validate_against_budget(&zero),
        Err(PolicyFindingError::Value(ReportValueError::TooManyItems {
            field: "finding_evidence_refs",
            ..
        }))
    ));
}

#[test]
fn shared_proof_and_witness_reference_counts_once() {
    let loaded = loaded_match_policy();
    let reference = EvidenceRef::try_new("query", "shared").unwrap();
    let step = WitnessStep::try_new(
        WitnessStepKind::Call,
        Some(location()),
        "call",
        vec![reference.clone()],
    )
    .unwrap();
    let witness = BoundedWitness::try_new(
        WitnessId::try_new("query", "witness").unwrap(),
        vec![step],
        false,
        0,
    )
    .unwrap();
    let mut finding = finding_with(
        &loaded,
        match_evidence(),
        vec![witness],
        None,
        &PolicyBudget::default(),
    )
    .unwrap();
    finding.proof = ProofMetadata::try_new(
        ProofState::Proven,
        vec![ProofReason::DirectStructuralMatch],
        vec![reference],
    )
    .unwrap();
    let one = PolicyBudget::builder()
        .with_max_evidence_refs_per_finding(1)
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(finding.validate_against_budget(&one), Ok(()));
}

#[test]
fn classification_only_evidence_reference_obeys_finding_cap() {
    let loaded = loaded_match_policy();
    let mut finding = finding_with(
        &loaded,
        match_evidence(),
        Vec::new(),
        None,
        &PolicyBudget::default(),
    )
    .unwrap();
    finding.classification = FindingClassification::classified(
        TaxonomyClassification::try_new("cwe", "0", None, ClassificationProvenance::PolicyFallback)
            .unwrap(),
        vec![
            TaxonomyClassification::try_new(
                "cwe",
                "1",
                None,
                ClassificationProvenance::analysis_evidence(
                    "bifrost.test",
                    vec![EvidenceRef::try_new("query", "classification").unwrap()],
                )
                .unwrap(),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let zero = PolicyBudget::builder()
        .with_max_evidence_refs_per_finding(0)
        .unwrap()
        .build()
        .unwrap();
    assert!(matches!(
        finding.validate_against_budget(&zero),
        Err(PolicyFindingError::Value(ReportValueError::TooManyItems {
            field: "finding_evidence_refs",
            ..
        }))
    ));
}

fn run_with_finding(finding: PolicyFinding) -> PolicyRun {
    let mut run = run_at(PolicyRunCompletion::Complete);
    run.replace_findings(vec![finding]);
    run
}

#[test]
fn may_evidence_reason_reservation_counts_at_byte_edge() {
    let loaded = loaded_match_policy();
    let original = finding_with(
        &loaded,
        match_evidence(),
        Vec::new(),
        None,
        &PolicyBudget::default(),
    )
    .unwrap();
    let base = run_with_finding(original.clone()).retained_size();
    let mut reason = String::with_capacity(64);
    reason.push_str("may");
    let mut finding = original;
    finding.certainty =
        FindingCertainty::possible(vec![CertaintyReason::MayEvidence { reason }]).unwrap();
    let FindingCertainty::Possible { reasons } = &finding.certainty else {
        unreachable!()
    };
    let CertaintyReason::MayEvidence { reason } = &reasons[0] else {
        unreachable!()
    };
    let expected = base + reasons.capacity() * size_of::<CertaintyReason>() + reason.capacity();
    assert_run_byte_edge(&run_with_finding(finding), expected);
}

#[test]
fn ambiguity_code_reservation_counts_at_byte_edge() {
    let loaded = loaded_match_policy();
    let original = finding_with(
        &loaded,
        match_evidence(),
        Vec::new(),
        None,
        &PolicyBudget::default(),
    )
    .unwrap();
    let base = run_with_finding(original.clone()).retained_size();
    let mut code = String::with_capacity(72);
    code.push_str("bifrost.ambiguous");
    let mut finding = original;
    finding.certainty =
        FindingCertainty::possible(vec![CertaintyReason::AnalyzerAmbiguity { code }]).unwrap();
    let FindingCertainty::Possible { reasons } = &finding.certainty else {
        unreachable!()
    };
    let CertaintyReason::AnalyzerAmbiguity { code } = &reasons[0] else {
        unreachable!()
    };
    let expected = base + reasons.capacity() * size_of::<CertaintyReason>() + code.capacity();
    assert_run_byte_edge(&run_with_finding(finding), expected);
}

#[test]
fn partial_finding_reasons_count_at_byte_edge() {
    let loaded = loaded_match_policy();
    let original = finding_with(
        &loaded,
        match_evidence(),
        Vec::new(),
        None,
        &PolicyBudget::default(),
    )
    .unwrap();
    let base = run_with_finding(original.clone()).retained_size();
    let mut finding = original;
    let mut reasons = Vec::with_capacity(4);
    reasons.push(FindingIncompleteReason::DeclaredNonExhaustive);
    finding.completeness = FindingCompleteness::Partial { reasons };
    let FindingCompleteness::Partial { reasons } = &finding.completeness else {
        unreachable!()
    };
    let expected = base + reasons.capacity() * size_of::<FindingIncompleteReason>();
    assert!(reasons.capacity() > reasons.len());
    assert_eq!(
        finding.completeness.retained_size(),
        size_of::<FindingCompleteness>()
            + reasons.capacity() * size_of::<FindingIncompleteReason>()
    );
    assert_run_byte_edge(&run_with_finding(finding), expected);
}
