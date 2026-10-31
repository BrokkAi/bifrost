use super::*;
use serde_json::json;

#[test]
fn feature_demands_include_false_and_nested_constraints() {
    let cases = [
        ("async", json!(false), "async"),
        ("unsafe_context", json!(false), "unsafe"),
        ("string_value", json!("x"), "string"),
        ("assignment_value_kind", json!("tuple"), "assignment"),
        ("assignment_target_unstarred_count", json!(2), "assignment"),
        ("integer_has_all_bits", json!(2), "integer"),
        ("integer_has_no_bits", json!(2), "integer"),
        ("duplicate_key", json!(false), "duplicate"),
        ("duplicate_key", json!(true), "duplicate"),
    ];
    for (field, value, demand) in cases {
        for nested in [false, true] {
            let kind = match demand {
                "async" => "function",
                "string" => "string_literal",
                "assignment" => "assignment",
                "integer" => "numeric_literal",
                "duplicate" => "object_property",
                _ => "call",
            };
            let mut pattern = json!({"kind":kind, (field): value});
            if nested {
                pattern = json!({"kind":"call", "all": [pattern, {"kind":"call"}]});
            }
            let query = CodeQuery::from_json(&json!({"match":pattern})).unwrap();
            let seed = query.seed().unwrap();
            let required = match demand {
                "async" => seed.constrains_async_callable(),
                "unsafe" => seed.constrains_unsafe_context(),
                "string" => seed.constrains_string_value(),
                "assignment" => seed.constrains_assignment_shape(),
                "integer" => seed.constrains_integer_literal_value(),
                "duplicate" => seed.constrains_duplicate_dictionary_key(),
                _ => unreachable!(),
            };
            assert!(required, "{field} nested={nested}");
        }
    }
}

#[test]
fn mixed_conjunction_demands_callable_signature() {
    let plain = CodeQuery::from_json(&json!({"match":{"kind":"call"}})).unwrap();
    assert!(!plain.seed().unwrap().constrains_callable_signature());
    let query = CodeQuery::from_json(
        &json!({"match":{"kind":"call","all":[{"visibility":["public"]},{"kind":"call"}]}}),
    )
    .unwrap();
    assert!(query.seed().unwrap().constrains_callable_signature());
}

#[test]
fn negative_descendants_retain_kind_and_role_requirements() {
    let positive = CodeQuery::from_json(
        &json!({"match":{"kind":"call","has":{"kind":"call","kwargs":{"shell":{"kind":"boolean_literal"}}}}}),
    )
    .unwrap();
    let negative = CodeQuery::from_json(
        &json!({"match":{"kind":"call","not_has":{"kind":"call","kwargs":{"shell":{"kind":"boolean_literal"}}}}}),
    )
    .unwrap();
    assert_eq!(
        positive.seed().unwrap().referenced_kinds(),
        negative.seed().unwrap().referenced_kinds()
    );
    assert_eq!(
        positive.seed().unwrap().used_roles(),
        negative.seed().unwrap().used_roles()
    );
}

#[test]
fn language_expansion_deduplicates_across_authored_labels() {
    use schema::expand_language_labels;
    assert_eq!(
        expand_language_labels(&["java", "kotlin", "java"]).unwrap(),
        expand_language_labels(&["java", "kotlin"]).unwrap()
    );
    assert_eq!(
        expand_language_labels(&["jvm", "java"]).unwrap(),
        expand_language_labels(&["jvm"]).unwrap()
    );
}

#[test]
fn embedded_selector_checks_first_vector_entry() {
    for source in ["[(limit 1 (call))]", "[(call) (limit 1 (call))]"] {
        let parsed = crate::sexp::parse_sexp(source).unwrap();
        let error = sexp::validate_policy_selector_expr(&parsed.expr.unwrap()).unwrap_err();
        assert!(error.message.contains("limit"), "{error:?}");
        assert_eq!(&source[error.range], "limit");
    }
}

#[test]
fn unknown_embedded_query_reports_match_path() {
    let parsed = crate::sexp::parse_sexp("(bogus)").unwrap();
    let error = sexp::code_query_from_expr(
        &parsed.expr.unwrap(),
        schema::resolve_rql_schema_version(None).unwrap(),
    )
    .unwrap_err();
    assert_eq!(error.path, "match");
    assert_eq!(error.range, 1..6);
}

#[test]
fn cross_domain_children_preserve_authored_order() {
    for op in ["correlate", "require_both"] {
        let mut input = json!({(op):{
            "relation":{"configuration_key":{"documents":["app.properties"]}},
            "code":{"match":{"kind":"method"},"steps":[{"op":"enclosing_decl"},{"op":"call_sites_to","proof":"proven"},{"op":"call_input","parameter_index":0}]},
            "configuration":{"configuration_facts":{}}
        }});
        if op == "require_both" {
            input[op].as_object_mut().unwrap().remove("relation");
        }
        let mut query = CodeQuery::from_json(&input).unwrap();
        let children = query.plan.source.child_plans();
        assert!(matches!(children[0].source, CodeQueryPlanSource::Seed(_)));
        assert!(matches!(
            children[1].source,
            CodeQueryPlanSource::ConfigurationFacts(_)
        ));
        let children = query.plan.source.child_plans_mut();
        assert!(matches!(children[0].source, CodeQueryPlanSource::Seed(_)));
        assert!(matches!(
            children[1].source,
            CodeQueryPlanSource::ConfigurationFacts(_)
        ));
    }
}
