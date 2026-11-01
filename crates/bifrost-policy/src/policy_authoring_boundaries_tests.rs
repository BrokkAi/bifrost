use crate::*;

fn metric(
    when: CvssEvidencePredicate,
    refs: Vec<PolicyEvidenceRef>,
    rationale: &str,
    assumptions: Vec<String>,
) -> Result<CvssMetricRule, InvalidCvssMetricRule> {
    CvssMetricRule::try_new(
        CvssBaseMetric::Av,
        CvssMetricValue::try_new(
            CvssMetric::Base {
                metric: CvssBaseMetric::Av,
            },
            CvssMetricValueToken::N,
        )
        .unwrap(),
        when,
        PolicyCvssBasis::PolicyAssertion,
        CvssEvidenceScope::System {
            system: CvssSystemScope::VulnerableSystem,
        },
        refs,
        rationale.to_owned(),
        assumptions,
    )
}

fn leaf() -> CvssEvidencePredicate {
    CvssEvidencePredicate::AnalysisType {
        analysis_type: PolicyAnalysisType::Match,
    }
}

#[test]
fn cvss_evidence_reference_limit_admits_exactly_sixty_four() {
    // MAX_POLICY_SET_ITEMS documents an inclusive maximum of 64.
    for count in [64, 65] {
        let refs = (0..count)
            .map(|index| PolicyEvidenceRef::Selector {
                path: PolicySelectorPath::new(format!("/analysis/selector/{index}")).unwrap(),
            })
            .collect();
        let result = metric(leaf(), refs, "reason", vec![]);
        if count == 64 {
            assert!(result.is_ok(), "{result:?}");
        } else {
            assert!(matches!(
                result,
                Err(InvalidCvssMetricRule::TooManyEvidenceReferences { max: 64 })
            ));
        }
    }
}

#[test]
fn cvss_predicate_depth_counts_each_edge_once() {
    // MAX_POLICY_PREDICATE_DEPTH is 16, with the root at zero.
    for depth in [8, 9, 16, 17] {
        let mut predicate = leaf();
        for level in 0..depth {
            predicate = if level % 2 == 0 {
                CvssEvidencePredicate::All {
                    predicates: vec![predicate],
                }
            } else {
                CvssEvidencePredicate::Any {
                    predicates: vec![predicate],
                }
            };
        }
        let result = metric(
            predicate,
            vec![PolicyEvidenceRef::PolicySelf],
            "reason",
            vec![],
        );
        if depth <= 16 {
            assert!(result.is_ok(), "depth {depth}: {result:?}");
        } else {
            assert!(matches!(
                result,
                Err(InvalidCvssMetricRule::PredicateDepthLimit { max: 16 })
            ));
        }
    }
}

#[test]
fn cvss_category_limit_admits_exactly_sixty_four() {
    // MAX_POLICY_SET_ITEMS is an inclusive maximum for quantified values.
    for count in [64, 65] {
        let predicate = CvssEvidencePredicate::SourceCategories {
            quantifier: AnyOrAll::Any,
            values: (0..count)
                .map(|index| PolicyCategoryId::new(format!("category-{index}")).unwrap())
                .collect(),
        };
        let result = metric(
            predicate,
            vec![PolicyEvidenceRef::PolicySelf],
            "reason",
            vec![],
        );
        if count == 64 {
            assert!(result.is_ok(), "{result:?}");
        } else {
            assert!(matches!(
                result,
                Err(InvalidCvssMetricRule::TooManyPredicateValues { max: 64 })
            ));
        }
    }
}

const POLICY: &str = r#"(policy :id "example.input" :name "Input" :message "Input" :severity warning
 :analysis (analysis :type match :selector (rql (language python (call :callee (name "input")))))
 :classification (classification :fallback (classification-id :taxonomy "CWE" :id "CWE-20")
 :cvss (cvss :version "4.0" :emit when-base-complete :metric-rules [
 (metric :name AV :value N :when PREDICATE :basis policy-assertion :scope vulnerable-system
 :evidence-refs [policy:self] :rationale RATIONALE :assumptions [ASSUMPTION]) ])))"#;

fn source(
    predicate: &str,
    rationale: &str,
    assumption: &str,
) -> Result<ParsedRqlpDocument, PolicySourceError> {
    let text = POLICY
        .replace("PREDICATE", predicate)
        .replace("RATIONALE", rationale)
        .replace("ASSUMPTION", assumption);
    parse_rqlp_source(&text, PolicySourceIdentity::new("boundaries.rqlp"))
}

#[test]
fn cvss_source_requires_nonempty_single_line_display_text() {
    let predicate = "(analysis-type :is match)";
    assert!(source(predicate, "\" \"", "\" \"").is_ok());
    for (rationale, assumption) in [("\"\"", "\"ok\""), ("\"ok\"", "\"\"")] {
        let error = source(predicate, rationale, assumption).unwrap_err();
        assert!(error.diagnostic.message.contains("empty"), "{error:?}");
    }
    for (rationale, assumption) in [
        (r#""line\nbreak""#, "\"ok\""),
        ("\"ok\"", r#""line\nbreak""#),
    ] {
        let error = source(predicate, rationale, assumption).unwrap_err();
        assert!(error.diagnostic.message.contains("character"), "{error:?}");
    }
}

#[test]
fn classification_adapter_identifier_obeys_boundary_alphabet() {
    for adapter in [
        "good.adapter",
        "good-adapter",
        "good_adapter",
        "good:adapter",
        "good.",
        "good-",
        "good_",
    ] {
        let evidence = serde_json::from_str("\"policy:input\"").unwrap();
        let result = ClassificationProvenance::analysis_evidence(adapter, vec![evidence]);
        if matches!(adapter, "good.adapter" | "good-adapter" | "good_adapter") {
            assert!(result.is_ok(), "{adapter}: {result:?}");
        } else {
            assert!(
                matches!(
                    result,
                    Err(ClassificationError::InvalidAnalysisAdapter { .. })
                ),
                "{adapter}: {result:?}"
            );
        }
    }
}

#[test]
fn cvss_quantified_categories_require_unique_values() {
    let predicate = CvssEvidencePredicate::SourceCategories {
        quantifier: AnyOrAll::Any,
        values: vec![PolicyCategoryId::new("input.user").unwrap(); 2],
    };
    assert!(matches!(
        metric(
            predicate,
            vec![PolicyEvidenceRef::PolicySelf],
            "reason",
            vec![]
        ),
        Err(InvalidCvssMetricRule::DuplicatePredicateValue)
    ));
}

#[test]
fn cvss_display_text_rejects_newlines_at_the_typed_boundary() {
    for (rationale, assumptions) in [
        ("line\nbreak", vec!["ok".to_owned()]),
        ("ok", vec!["line\nbreak".to_owned()]),
    ] {
        let result = metric(
            leaf(),
            vec![PolicyEvidenceRef::PolicySelf],
            rationale,
            assumptions,
        );
        assert!(
            matches!(
                result,
                Err(InvalidCvssMetricRule::InvalidRationaleCharacter)
                    | Err(InvalidCvssMetricRule::InvalidAssumptionCharacter { index: 0 })
            ),
            "{result:?}"
        );
    }
}
