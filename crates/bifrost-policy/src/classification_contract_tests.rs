use crate::classification::{
    ClassificationError, ClassificationProvenance as P, FindingClassification,
    OrganizationalRiskAssessment, OrganizationalRiskError, TaxonomyClassification as T,
    TextValidationError,
};
use crate::definition::FindingCombinationId;
use crate::finding_identity::EvidenceRef;
use serde_json::json;

fn evidence(value: &str) -> EvidenceRef {
    EvidenceRef::try_new("policy", value).unwrap()
}
fn classification(taxonomy: &str, id: &str, provenance: P) -> T {
    T::try_new(taxonomy, id, Some("Display".into()), provenance).unwrap()
}

#[test]
fn taxonomy_identity_and_exact_combination_provenance_survive_normalization() {
    let combination = P::FindingCombination {
        combination_id: FindingCombinationId::new("exact").unwrap(),
    };
    let generic = classification("Y", "20", P::policy_refinement(0).unwrap());
    let exact = classification("Y", "20", combination.clone());
    for refinements in [
        vec![generic.clone(), exact.clone()],
        vec![exact.clone(), generic.clone()],
    ] {
        let value = FindingClassification::classified(
            classification("X", "20", P::PolicyFallback),
            refinements,
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(value.refinements()).unwrap(),
            json!([{"taxonomy":"Y","identifier":"20","name":"Display","provenance":{"type":"finding_combination","combination_id":"exact"}}])
        );
    }
}

#[test]
fn report_text_limits_are_bytes_and_preserve_field_diagnostics() {
    // Report names allow 256 bytes; organizational prose allows 4096.
    for n in [128, 129, 256] {
        let value = T::try_new("T", "i".repeat(n), Some("n".repeat(n)), P::PolicyFallback).unwrap();
        assert_eq!(
            serde_json::to_value(value).unwrap()["identifier"],
            "i".repeat(n)
        );
    }
    for (id, reason) in [
        (String::new(), TextValidationError::Empty),
        ("\n".into(), TextValidationError::UnsafeCharacter),
        (
            "i".repeat(257),
            TextValidationError::TooLong { max_bytes: 256 },
        ),
    ] {
        assert_eq!(
            T::try_new("T", id, None, P::PolicyFallback).unwrap_err(),
            ClassificationError::InvalidIdentifier { reason }
        );
    }
    assert!(T::try_new("\u{e9}".repeat(128), "id", None, P::PolicyFallback).is_ok());
    assert_eq!(
        T::try_new("\u{e9}".repeat(129), "id", None, P::PolicyFallback).unwrap_err(),
        ClassificationError::InvalidTaxonomy {
            reason: TextValidationError::TooLong { max_bytes: 256 }
        }
    );
    for n in [256, 257, 4096] {
        let value = OrganizationalRiskAssessment::try_new(
            "s".into(),
            "high".into(),
            "r".repeat(n),
            vec![],
            Some("a".repeat(n)),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(value).unwrap()["assessor"],
            "a".repeat(n)
        );
    }
    assert!(matches!(
        OrganizationalRiskAssessment::try_new(
            "s".into(),
            "high".into(),
            "r".into(),
            vec![],
            Some("a".repeat(4097))
        ),
        Err(OrganizationalRiskError::InvalidAssessor {
            reason: TextValidationError::TooLong { max_bytes: 4096 }
        })
    ));
}

#[test]
fn provenance_requires_bounded_indices_valid_adapters_and_canonical_evidence() {
    assert_eq!(
        serde_json::to_value(P::policy_refinement(127).unwrap()).unwrap(),
        json!({"type":"policy_refinement","refinement_index":127})
    );
    assert_eq!(
        P::policy_refinement(128).unwrap_err(),
        ClassificationError::RefinementIndexOutOfRange {
            index: 128,
            max_exclusive: 128
        }
    );
    assert!(
        serde_json::from_value::<P>(json!({"type":"policy_refinement","refinement_index":128}))
            .is_err()
    );
    for adapter in [
        " test.adapter",
        "test.adapter ",
        "test/adapter",
        ":adapter",
        "t\u{e9}.adapter",
    ] {
        assert!(
            matches!(
                P::analysis_evidence(adapter, vec![evidence("a")]),
                Err(ClassificationError::InvalidAnalysisAdapter { .. })
            ),
            "{adapter}"
        );
    }
    assert_eq!(
        P::analysis_evidence("test.adapter", vec![])
            .unwrap_err()
            .to_string(),
        "at least one evidence reference is required"
    );
    for refs in [
        vec![],
        vec![evidence("b"), evidence("a")],
        vec![evidence("a"), evidence("a")],
    ] {
        assert!(
            T::try_new(
                "T",
                "id",
                None,
                P::AnalysisEvidence {
                    adapter: "test.adapter".into(),
                    evidence_refs: refs
                }
            )
            .is_err()
        );
    }
    let value = classification(
        "T",
        "id",
        P::analysis_evidence("test.adapter", vec![evidence("a"), evidence("b")]).unwrap(),
    );
    let wire = json!({"taxonomy":"T","identifier":"id","name":"Display","provenance":{"type":"analysis_evidence","adapter":"test.adapter","evidence_refs":["policy:a","policy:b"]}});
    assert_eq!(serde_json::to_value(&value).unwrap(), wire);
    assert_eq!(serde_json::from_value::<T>(wire).unwrap(), value);
}

#[test]
fn risk_identity_distinguishes_rating_and_each_evidence_reference() {
    let make = |rating: &str, refs| {
        OrganizationalRiskAssessment::try_new(
            "risk".into(),
            rating.into(),
            "rationale".into(),
            refs,
            Some("team".into()),
        )
        .unwrap()
    };
    let high_a = make("high", vec![evidence("a")]);
    for other in [
        make("low", vec![evidence("a")]),
        make("high", vec![evidence("b")]),
    ] {
        assert_ne!(
            serde_json::to_value(&high_a).unwrap()["content_hash"],
            serde_json::to_value(other).unwrap()["content_hash"]
        );
    }
    assert_eq!(
        make("high", vec![evidence("b"), evidence("a"), evidence("a")]),
        make("high", vec![evidence("a"), evidence("b")])
    );
}

#[test]
fn applicable_refinements_keep_distinct_classifications_and_display_names() {
    use crate::classification::{ClassificationProjection, reduce_finding_classification};
    use crate::definition::{
        AnyOrAll, ClassificationPredicate as Q, ClassificationRefinementSpec, PolicyAnalysisType,
        PolicyCategoryId, PolicyClassificationSpec, TaxonomyClassificationSpec,
    };
    let category = |name| PolicyCategoryId::new(name).unwrap();
    let analysis = |kind| Q::AnalysisType {
        analysis_type: kind,
    };
    let partial = |quantifier| Q::SourceCategories {
        quantifier,
        values: vec![category("input.a"), category("input.b")],
    };
    let spec_value = |id: &str| TaxonomyClassificationSpec {
        taxonomy: "Test".into(),
        identifier: id.into(),
        name: Some(format!("Display {id}")),
    };
    let predicates = [
        analysis(PolicyAnalysisType::Taint),
        analysis(PolicyAnalysisType::Match),
        Q::All {
            predicates: vec![
                analysis(PolicyAnalysisType::Taint),
                analysis(PolicyAnalysisType::Match),
            ],
        },
        partial(AnyOrAll::Any),
        partial(AnyOrAll::All),
    ];
    let spec = PolicyClassificationSpec {
        fallback: spec_value("fallback"),
        refinements: predicates
            .into_iter()
            .enumerate()
            .map(|(i, when)| ClassificationRefinementSpec {
                when,
                add: vec![spec_value(&format!("r{i}"))],
            })
            .collect(),
        cvss: None,
    };
    let categories = [category("input.a")];
    let result = reduce_finding_classification(
        Some(&spec),
        ClassificationProjection::taint_pair(&categories, &[], &[], &[], &[], None),
        None,
    )
    .unwrap();
    assert_eq!(
        result
            .refinements()
            .iter()
            .map(T::identifier)
            .collect::<Vec<_>>(),
        ["r0", "r3"]
    );
    assert_eq!(result.broad().unwrap().name(), Some("Display fallback"));
    assert_eq!(result.refinements()[0].name(), Some("Display r0"));
}

#[test]
fn stored_classifications_require_identity_order_not_just_the_same_count() {
    let wire = json!({"type":"classified", "broad":{"taxonomy":"T","identifier":"broad","name":null,"provenance":{"type":"policy_fallback"}}, "refinements":[{"taxonomy":"T","identifier":"z","name":null,"provenance":{"type":"policy_refinement","refinement_index":0}},{"taxonomy":"T","identifier":"a","name":null,"provenance":{"type":"policy_refinement","refinement_index":1}}]});
    assert!(
        serde_json::from_value::<FindingClassification>(wire)
            .unwrap_err()
            .to_string()
            .contains("normal form")
    );
}

#[test]
fn combinations_require_both_endpoints_and_follow_authored_supersedes() {
    use crate::classification::TaintPresentationReducer;
    use crate::definition::EndpointId;
    use crate::resolved::{ResolvedEndpointIdentity, ResolvedFindingCombination};
    let endpoint = |name| ResolvedEndpointIdentity::MatchEndpoint {
        endpoint_id: EndpointId::new(name).unwrap(),
    };
    let combination = |id, source, sink, supersedes| {
        ResolvedFindingCombination::new(
            FindingCombinationId::new(id).unwrap(),
            vec![endpoint(source)],
            vec![endpoint(sink)],
            "message".into(),
            None,
            vec![],
            supersedes,
        )
    };
    let combinations = [
        combination("a", "s1", "t1", vec![]),
        combination("b", "s2", "t2", vec![]),
    ];
    let reducer = TaintPresentationReducer::try_new(&combinations).unwrap();
    for (source, sink, winner) in [
        ("s1", "t1", Some("a")),
        ("s2", "t2", Some("b")),
        ("s1", "t2", None),
        ("s2", "t1", None),
    ] {
        assert_eq!(
            reducer
                .select(&endpoint(source), &endpoint(sink))
                .unwrap()
                .map(|c| c.id.as_str()),
            winner
        );
    }
    let combinations = [
        combination("general", "s1", "t1", vec![]),
        combination(
            "specific",
            "s1",
            "t1",
            vec![FindingCombinationId::new("general").unwrap()],
        ),
    ];
    assert_eq!(
        TaintPresentationReducer::try_new(&combinations)
            .unwrap()
            .select(&endpoint("s1"), &endpoint("t1"))
            .unwrap()
            .unwrap()
            .id
            .as_str(),
        "specific"
    );
}
