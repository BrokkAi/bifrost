use crate::query::*;
use serde_json::json;

fn relation() -> serde_json::Value {
    json!({"correlate": {
        "relation": {"dependency_configuration": {"owner": "npm:workspace:a", "ecosystem": "npm", "version_ranges": [">=1.0.0"], "documents": ["a.properties"], "values": ["true"]}},
        "code": {"dependency_evidence": {}},
        "configuration": {"configuration_facts": {}}
    }})
}

#[test]
fn projected_names_preserve_byte_boundaries() {
    // MAX_ROW_FIELD_NAME_LENGTH and MAX_ROW_PROJECTION_COLUMNS are inclusive.
    for (name, valid) in [
        ("".to_owned(), false),
        (" ".to_owned(), true),
        ("x".repeat(256), true),
        ("x".repeat(255) + "  ", false),
        ("\u{e9}".repeat(128), true),
        ("\u{e9}".repeat(129), false),
    ] {
        let mut query = CodeQuery::from_json(&json!({"occurrences": {}})).unwrap();
        query
            .plan
            .steps
            .push(QueryStep::Project(vec![QueryRowProjectionColumn {
                source: "id".into(),
                name: name.clone(),
            }]));
        assert_eq!(query.validate_steps().is_ok(), valid, "{name:?}");
        let decoded = CodeQuery::from_json(&query.to_canonical_json());
        assert_eq!(decoded.is_ok(), valid, "{name:?}");
        if let Ok(decoded) = decoded {
            assert_eq!(decoded.to_canonical_json(), query.to_canonical_json());
        }
    }
    let mut query = CodeQuery::from_json(&json!({"occurrences": {}})).unwrap();
    query.plan.steps.push(QueryStep::Project(vec![]));
    assert_eq!(
        query.validate_steps().unwrap_err().message,
        "row projection columns must contain from 1 through 32 entries"
    );
}

#[test]
fn dependency_relation_inclusive_limits_round_trip() {
    // MAX_CORRELATION_DOCUMENTS, MAX_GLOB_LENGTH and the version-range
    // diagnostic document inclusive limits of 32, 1024 and 32 respectively.
    for (field, value, valid) in [
        (
            "documents",
            json!(
                (0..32)
                    .map(|i| format!("d{i}.properties"))
                    .collect::<Vec<_>>()
            ),
            true,
        ),
        (
            "documents",
            json!(
                (0..33)
                    .map(|i| format!("d{i}.properties"))
                    .collect::<Vec<_>>()
            ),
            false,
        ),
        (
            "documents",
            json!(["a/".repeat(506) + "a.properties"]),
            true,
        ),
        (
            "documents",
            json!(["a/".repeat(506) + "aa.properties"]),
            false,
        ),
        ("version_ranges", json!(vec![">=1.0.0"; 32]), true),
        ("version_ranges", json!(vec![">=1.0.0"; 33]), false),
        ("ecosystem", json!("cargo"), true),
    ] {
        let mut input = relation();
        input["correlate"]["relation"]["dependency_configuration"][field] = value;
        let result = CodeQuery::from_json(&input);
        assert_eq!(result.is_ok(), valid, "{input}: {result:?}");
        if let Ok(query) = result {
            let canonical = query.to_canonical_json();
            assert_eq!(
                CodeQuery::from_json(&canonical)
                    .unwrap()
                    .to_canonical_json(),
                canonical
            );
        }
    }
}

#[test]
fn unrestricted_configuration_branch_is_order_independent() {
    for branches in [
        json!([{"configuration_facts": {}}, {"configuration_facts": {"formats": ["json"]}}]),
        json!([{"configuration_facts": {"formats": ["json"]}}, {"configuration_facts": {}}]),
    ] {
        let mut input = relation();
        input["correlate"]["configuration"] = json!({"union": branches});
        let query = CodeQuery::from_json(&input).unwrap();
        assert!(query.validate_steps().is_ok());
    }
}

#[test]
fn nested_exclusion_and_empty_role_patterns_round_trip() {
    for input in [
        json!({"match": {"kind": "call"}, "inside": {"not_kind": "function"}}),
        json!({"match": {"kind": "call", "args": [{}]}}),
    ] {
        let query = CodeQuery::from_json(&input).unwrap();
        let canonical = query.to_canonical_json();
        assert_eq!(
            CodeQuery::from_json(&canonical)
                .unwrap()
                .to_canonical_json(),
            canonical
        );
    }
    assert!(CodeQuery::from_json(&json!({"match": {"kind": "call", "all": [{}]}})).is_err());
}

#[test]
fn single_module_role_requires_semantic_admission() {
    let query = CodeQuery::from_json(
        &json!({"match": {"kind": "import", "module": {"name": "package"}}, "where": ["a.py"]}),
    )
    .unwrap();
    assert!(query.may_use_semantic_packs());
}

#[test]
fn captured_regex_literals_keep_all_components_and_anchors() {
    let exact = StringPredicate::Regex(regex::Regex::new("^(foo)(bar)$").unwrap());
    assert_eq!(exact.exact_alternatives(), Some(vec!["foobar".into()]));
}

#[test]
fn one_sided_regex_does_not_offer_exact_postings() {
    let predicate = StringPredicate::Regex(regex::Regex::new("^(foo)(bar)").unwrap());
    assert!(predicate.matches("foobarbaz"));
    assert_eq!(predicate.exact_alternatives(), None);
}

#[test]
fn cross_domain_depth_charges_each_plan_once() {
    let leaf = CodeQuery::from_json(&json!({"occurrences": {}}))
        .unwrap()
        .plan;
    let mut code = leaf.clone();
    for _ in 0..15 {
        code = CodeQueryPlan {
            source: CodeQueryPlanSource::Set {
                op: SetOperator::Union,
                branches: vec![code, leaf.clone()],
            },
            steps: vec![],
        };
    }
    let mut query =
        CodeQuery::from_sexp("(require-both :code (call) :configuration (configuration-facts))")
            .unwrap();
    let CodeQueryPlanSource::RequireBoth(requirement) = &mut query.plan.source else {
        panic!("require-both");
    };
    requirement.code = code.clone();
    assert!(query.validate_steps().is_ok());
    let CodeQueryPlanSource::RequireBoth(requirement) = &mut query.plan.source else {
        panic!("require-both");
    };
    requirement.code = CodeQueryPlan {
        source: CodeQueryPlanSource::Set {
            op: SetOperator::Union,
            branches: vec![code, leaf],
        },
        steps: vec![],
    };
    assert!(query.validate_steps().is_err());
}
