use super::{CodeQuery, sexp_to_json};

#[test]
fn input_byte_limit_is_inclusive() {
    // MAX_SEXP_INPUT_BYTES is 64 * 1024 in the public query decoder.
    let source = format!("(call){}", " ".repeat(65536 - 6));
    assert_eq!(
        CodeQuery::from_sexp(&source).unwrap().to_canonical_json(),
        CodeQuery::from_sexp("(call)").unwrap().to_canonical_json()
    );
    assert!(CodeQuery::from_sexp(&(source + " ")).is_err());
}

#[test]
fn visibility_spelling_is_canonical() {
    assert_eq!(
        sexp_to_json("(function :visibility package-private)").unwrap(),
        serde_json::json!({"match":{"kind":"function", "visibility":"package_private"}})
    );
}

#[test]
fn lowering_errors_keep_the_public_message() {
    assert_eq!(
        sexp_to_json("(call :bogus true)").unwrap_err(),
        "unknown pattern field `:bogus`"
    );
}

#[test]
fn duplicate_keyword_error_points_to_second_occurrence() {
    let source = "(call :kwargs ((shell (boolean_literal)) (shell (string_literal))))";
    let parsed = crate::sexp::parse_sexp(source).unwrap();
    let schema = super::resolve_rql_schema_version(None).unwrap();
    let error = super::code_query_from_expr(&parsed.expr.unwrap(), schema).unwrap_err();
    assert_eq!(error.range, 42..47);
    assert_eq!(error.message, "duplicate S-expression field `shell`");
}

#[test]
fn qualifying_type_registry_roundtrip_and_nested_identity_ranges() {
    use crate::query::{CallIdentity, CodeQueryPlanSource};
    let source = r#"(language rust (call :qualifying-type (instantiated-type :identity (qualified "cbc.Encryptor") :arguments [(instantiated-type :identity (qualified "des.Des"))])))"#;
    let query = CodeQuery::from_sexp(source).expect("new call constraint parses");
    let json = query.to_canonical_json();
    let decoded = CodeQuery::from_json(&json).unwrap();
    assert_eq!(decoded.to_canonical_json(), json);
    let CodeQueryPlanSource::Seed(seed) = &query.plan.source else {
        panic!("seed");
    };
    let outer = seed.root.qualifying_type.as_ref().expect("constraint");
    for (identity, expected) in [
        (&outer.identity, "\"cbc.Encryptor\""),
        (&outer.arguments[0].identity, "\"des.Des\""),
    ] {
        let CallIdentity::Qualified {
            source_range: Some(range),
            ..
        } = identity
        else {
            panic!("located qualified identity");
        };
        assert_eq!(&source[range.clone()], expected);
    }
    let mut canonical = json;
    canonical["match"]["qualifying_type"]["resolved_identities"] =
        serde_json::json!([{"active_semantic_model":"cbc-v1"},{"active_semantic_model":"cbc-v2"}]);
    assert_eq!(
        CodeQuery::from_json(&canonical)
            .unwrap()
            .to_canonical_json(),
        canonical
    );
    for invalid in [
        "(identifier :qualifying-type (instantiated-type :identity (qualified \"cbc.Encryptor\")))",
        "(call :identity (qualified \"cbc.Encryptor\"))",
        "(call :qualifying-type (instantiated-type :arguments []))",
        "(call :qualifying-type (instantiated-type :identity (qualified \"\")))",
        "(call :qualifying-type (instantiated-type :identity (qualified \"cbc.Encryptor\") :identity (qualified \"cbc.Encryptor\")))",
    ] {
        assert!(CodeQuery::from_sexp(invalid).is_err(), "{invalid}");
    }
}
