use super::*;

#[test]
fn stored_completion_preserves_summary_and_proven_subset() {
    for completion in [
        PolicyRunCompletion::ProvenBySummary,
        PolicyRunCompletion::proven_subset(vec![CodeQueryDiagnosticCode::ResultLimitReached])
            .unwrap(),
    ] {
        let wire = serde_json::to_string(&completion).unwrap();
        let decoded: PolicyRunCompletion = serde_json::from_str(&wire).unwrap();
        assert_eq!(decoded, completion);
        assert!(!decoded.is_complete());
    }
}

#[test]
fn stored_related_label_and_witness_provenance_survive_decoding() {
    let related = RelatedPolicyLocation::try_new(
        PolicyLocationRelationship::CallTarget,
        location(),
        Vec::new(),
    )
    .unwrap()
    .with_label("source".to_string())
    .unwrap();
    let decoded: RelatedPolicyLocation =
        serde_json::from_value(serde_json::to_value(&related).unwrap()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap()["label"], "source");

    let endpoint = crate::resolved::ResolvedEndpointIdentity::MatchEndpoint {
        endpoint_id: "example-source".parse().unwrap(),
    };
    let step = WitnessStep::try_new_with_provenance(
        WitnessStepKind::DeclaredStore,
        None,
        "store",
        Vec::new(),
        Some(WitnessStepProvenance::DeclaredStore {
            write_model: endpoint.clone(),
            read_model: endpoint,
            store: "records".to_string(),
            write_instance: StoreDimensionEvidence::Undeclared,
            write_key: StoreDimensionEvidence::Undeclared,
            read_instance: StoreDimensionEvidence::Undeclared,
            read_key: StoreDimensionEvidence::Undeclared,
        }),
    )
    .unwrap();
    let wire = serde_json::to_value(&step).unwrap();
    let decoded: WitnessStep = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(
        serde_json::to_value(decoded).unwrap()["provenance"],
        wire["provenance"]
    );
}

#[test]
fn stored_witness_rejects_an_incorrect_retained_byte_claim() {
    let witness = BoundedWitness::try_new(
        crate::finding_identity::WitnessId::try_new("bifrost.test", "w").unwrap(),
        vec![
            WitnessStep::try_new(WitnessStepKind::Call, Some(location()), "call", Vec::new())
                .unwrap(),
        ],
        false,
        0,
    )
    .unwrap();
    let mut wire = serde_json::to_value(witness).unwrap();
    wire["retained_bytes"] = json!(wire["retained_bytes"].as_u64().unwrap() - 1);
    assert!(serde_json::from_value::<BoundedWitness>(wire).is_err());
}

#[test]
fn stored_assertion_accepts_one_omitted_derivation() {
    let PolicyFindingEvidence::Assertion { evidence } = assertion_evidence() else {
        unreachable!()
    };
    let mut wire = serde_json::to_value(evidence).unwrap();
    wire["effect_derivations_truncated"] = json!(true);
    wire["omitted_effect_derivations_lower_bound"] = json!(1);
    let decoded: AssertionFindingEvidence = serde_json::from_value(wire).unwrap();
    assert!(decoded.effect_derivations_truncated);
    assert_eq!(decoded.omitted_effect_derivations_lower_bound, 1);
}

#[test]
fn stored_finding_rejects_analysis_type_disagreeing_with_evidence() {
    let budget = PolicyBudget::default();
    let loaded = loaded_match_policy();
    let finding = finding_with(&loaded, match_evidence(), Vec::new(), None, &budget).unwrap();
    let mut wire = serde_json::to_value(finding).unwrap();
    wire["analysis_type"] = json!("assertion");
    let bytes = serde_json::to_string(&wire).unwrap();
    let mut deserializer = serde_json::Deserializer::from_str(&bytes);
    assert!(
        serde::de::DeserializeSeed::deserialize(
            PolicyFindingSeed::new(&budget),
            &mut deserializer,
        )
        .is_err()
    );
}

#[test]
fn retained_report_cap_counts_anchor_owned_bytes() {
    use crate::finding_identity::{AssertionFindingAnchor, StableIdentityDerivation};

    let loaded = loaded_match_policy();
    let default_budget = PolicyBudget::default();
    let make_finding = |kind: &str, suffix: &str| {
        let evidence = match kind {
            "assertion" => PolicyFindingEvidence::Assertion {
                evidence: AssertionFindingEvidence::try_new(
                    AssertionFindingAnchor::new(path(), "ast:7", format!("assert{suffix}")),
                    "occurrence",
                    "value_reference",
                    "cardinality",
                    "none",
                    None,
                    0,
                    Vec::new(),
                    Vec::new(),
                    0,
                )
                .unwrap(),
            },
            "weak" | "strong" => {
                let anchor = if kind == "weak" {
                    MatchFindingAnchor::weak(
                        MatchResultDomain::CallSite,
                        path(),
                        OpaqueFindingKey::try_new("bifrost.test", format!("key{suffix}")).unwrap(),
                    )
                } else {
                    MatchFindingAnchor::strong(
                        MatchResultDomain::CallSite,
                        path(),
                        Some(
                            StableSemanticIdentity::try_new(
                                "bifrost.test",
                                path(),
                                StableIdentityDerivation::CatalogEntry,
                                format!("owner{suffix}"),
                            )
                            .unwrap(),
                        ),
                        Some(SourceSliceHash::from_bytes([4; 32])),
                        0,
                    )
                    .unwrap()
                };
                PolicyFindingEvidence::Match {
                    evidence: MatchFindingEvidence::try_new(
                        MatchResultDomain::CallSite,
                        anchor,
                        call_terminal(),
                        Vec::new(),
                        false,
                    )
                    .unwrap(),
                }
            }
            _ => unreachable!(),
        };
        let completeness = if kind == "weak" {
            FindingCompleteness::partial(vec![FindingIncompleteReason::StableAnchorWeak]).unwrap()
        } else {
            FindingCompleteness::Complete
        };
        PolicyFinding::try_new(
            loaded.definition().metadata.id.clone(),
            loaded.semantic_hash(),
            FindingSeverity::Warning,
            "finding".to_string(),
            FindingClassification::Unclassified,
            FindingCertainty::Definite,
            completeness,
            location(),
            Vec::new(),
            false,
            0,
            evidence,
            false,
            0,
            None,
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
            &default_budget,
        )
        .unwrap()
    };
    let make_run = |finding: PolicyFinding, budget: &PolicyBudget| {
        let completion = if finding.identity_stability()
            == crate::finding_identity::FindingIdentityStability::Weak
        {
            PolicyRunCompletion::inconclusive(vec![PolicyIncompleteReason::StableAnchorUnavailable])
                .unwrap()
        } else {
            PolicyRunCompletion::Complete
        };
        PolicyRun::try_new(
            loaded.definition().metadata.id.clone(),
            loaded.semantic_hash(),
            finding.analysis_type(),
            completion,
            vec![finding],
            Vec::new(),
            false,
            PolicyWorkReport::default(),
            budget,
        )
    };
    for kind in ["assertion", "weak", "strong"] {
        let short = make_run(make_finding(kind, "a"), &default_budget).unwrap();
        let suffix = "b".repeat(100);
        let long = make_finding(kind, &suffix);
        // Only the owned anchor text changes. This delta is independent of
        // the retained-size implementation being checked.
        let exact_bytes = short.retained_size() + suffix.len() - 1;
        let exact = PolicyBudget::builder()
            .with_max_retained_report_bytes(exact_bytes)
            .unwrap()
            .build()
            .unwrap();
        assert!(make_run(long.clone(), &exact).is_ok(), "{kind}: exact cap");
        let below = PolicyBudget::builder()
            .with_max_retained_report_bytes(exact_bytes - 1)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            make_run(long, &below).unwrap_err(),
            PolicyRunError::RetainedReportBytesExceeded {
                max: exact_bytes - 1
            },
            "{kind}: one byte below the retained cap",
        );
    }
}
