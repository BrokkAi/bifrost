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
