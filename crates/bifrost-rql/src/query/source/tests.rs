use super::*;

#[test]
fn source_and_diagnostic_budgets_are_bounded() {
    let oversized = " ".repeat(MAX_QUERY_SOURCE_BYTES + 1);
    let diagnostics = validate_query_source(&oversized);
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0].code, "query-too-large");
    assert!(query_source_help_at(&oversized, 0).is_none());

    let mut many_errors = String::from("(call");
    for index in 0..=MAX_SOURCE_DIAGNOSTICS {
        many_errors.push_str(&format!(" :unknown-{index} 1"));
    }
    many_errors.push(')');
    assert_eq!(
        validate_query_source(&many_errors).len(),
        MAX_SOURCE_DIAGNOSTICS
    );
}

#[test]
fn plan_budgets_stop_rql_source_validation_early() {
    let mut deep_rql = "(banana)".to_string();
    for _ in 0..=MAX_QUERY_PLAN_DEPTH {
        deep_rql = format!("(union {deep_rql} (call))");
    }
    let source = deep_rql;
    let diagnostics = validate_query_source(&source);
    assert_eq!(diagnostics.len(), 1, "{source}: {diagnostics:#?}");
    assert!(diagnostics[0].message.contains("plan depth"));

    let rql_group = format!("(union {})", vec!["(call)"; 16].join(" "));
    let wide_rql = format!("(union {})", vec![rql_group; 4].join(" "));
    let source = wide_rql;
    let diagnostics = validate_query_source(&source);
    assert_eq!(diagnostics.len(), 1, "{source}: {diagnostics:#?}");
    assert!(diagnostics[0].message.contains("at most 64 nodes"));
}

#[test]
fn accepted_rql_shorthands_have_no_live_diagnostics() {
    for source in [
        r#"(call :callee "run")"#,
        r#"(import :module "os")"#,
        r#"(result-detail "full" (call))"#,
        r#"(explain (call))"#,
        r#"(profile (call))"#,
        r#"(imports-of (file-of (class)))"#,
    ] {
        CodeQuery::from_source(source)
            .unwrap_or_else(|error| panic!("{source:?} should execute: {error}"));
        assert!(
            validate_query_source(source).is_empty(),
            "{source:?} should lint cleanly"
        );
    }
}

#[test]
fn cpp_fact_help_and_validation_are_schema_driven() {
    let source = "(cpp-facts :kind assignment-does-not-return-this (method :name \"operator=\"))";
    assert!(validate_query_source(source).is_empty(), "{source}");
    let help =
        query_source_help_at(source, source.find(":kind").unwrap()).expect("cpp fact kind help");
    assert_eq!(&source[help.range], ":kind");
    assert!(help.description.contains("C++"));

    let invalid = "(cpp-facts :kind no-such-cpp-fact (method))";
    let diagnostic = validate_query_source(invalid)
        .into_iter()
        .find(|diagnostic| diagnostic.code == "invalid-query-step-option")
        .expect("invalid C++ fact kind diagnostic");
    assert_eq!(&invalid[diagnostic.range], "no-such-cpp-fact");
}

#[test]
fn shared_statement_fact_and_language_rule_vocabulary_is_schema_driven() {
    let source = r#"(language csharp
        (statement-facts :kind nested-loops-with-same-variable
          (assignment :language-rule "cs/static-array")))"#;
    assert!(validate_query_source(source).is_empty(), "{source}");

    let statement_help = query_source_help_at(source, source.find("statement-facts").unwrap())
        .expect("statement fact help");
    assert!(statement_help.description.contains("Java"));
    let rule_help = query_source_help_at(source, source.find(":language-rule").unwrap())
        .expect("language rule help");
    assert_eq!(&source[rule_help.range], ":language-rule");
    assert!(rule_help.description.contains("language-rule"));

    let invalid_fact = "(statement-facts :kind no-such-statement-fact (assignment))";
    let fact_diagnostic = validate_query_source(invalid_fact)
        .into_iter()
        .find(|diagnostic| diagnostic.code == "invalid-query-step-option")
        .expect("invalid statement fact diagnostic");
    assert_eq!(
        &invalid_fact[fact_diagnostic.range],
        "no-such-statement-fact"
    );

    let invalid_rule = r#"(assignment :language-rule "cs/no-such-rule")"#;
    let rule_diagnostic = validate_query_source(invalid_rule)
        .into_iter()
        .find(|diagnostic| diagnostic.code == "invalid-query")
        .expect("invalid language rule diagnostic");
    assert_eq!(&invalid_rule[rule_diagnostic.range], "\"cs/no-such-rule\"");
}

#[test]
fn async_callable_property_and_await_kind_help_are_schema_driven() {
    let async_source = "(function :async true)";
    assert!(
        validate_query_source(async_source).is_empty(),
        "{:#?}",
        validate_query_source(async_source)
    );
    let offset = async_source.find(":async").expect("async property");
    let help = query_source_help_at(async_source, offset).expect("async property help");
    assert_eq!(&async_source[help.range], ":async");
    assert!(help.description.contains("AST-backed async"));

    let await_source = "(program-point-of (await))";
    assert!(
        validate_query_source(await_source).is_empty(),
        "{:#?}",
        validate_query_source(await_source)
    );
    let offset = await_source.find("await").expect("await form");
    let help = query_source_help_at(await_source, offset).expect("await kind help");
    assert_eq!(&await_source[help.range], "await");

    let source = "(function :async 1)";
    let diagnostic = validate_query_source(source)
        .into_iter()
        .find(|diagnostic| diagnostic.code == "wrong-value-shape")
        .expect("async requires a boolean");
    assert_eq!(&source[diagnostic.range], "1");

    let source = "(function :asyn true)";
    let diagnostic = validate_query_source(source)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("Did you mean"))
        .expect("async property suggestion");
    assert!(diagnostic.message.contains("async"), "{diagnostic:#?}");
}

/// `module` is spelled by both a normalized kind and a role (issue #2518),
/// so the source surface has to keep them apart by position: a head symbol
/// (or a `kind` value) is the declaration kind, a `:module` keyword is the
/// import role.
#[test]
fn module_kind_and_module_role_keep_separate_help_and_validation() {
    let kind_source = r#"(module :name "tests")"#;
    assert!(
        validate_query_source(kind_source).is_empty(),
        "{:#?}",
        validate_query_source(kind_source)
    );
    let kind_help = query_source_help_at(kind_source, kind_source.find("module").unwrap())
        .expect("module kind help");
    assert_eq!(&kind_source[kind_help.range], "module");
    assert!(
        kind_help.description.contains("module or namespace"),
        "{}",
        kind_help.description
    );

    let role_source = r#"(import :module (name "fmt"))"#;
    assert!(
        validate_query_source(role_source).is_empty(),
        "{:#?}",
        validate_query_source(role_source)
    );
    let role_help = query_source_help_at(role_source, role_source.find(":module").unwrap())
        .expect("module role help");
    assert_eq!(&role_source[role_help.range], ":module");
    assert!(
        role_help
            .description
            .contains("module referenced by an import"),
        "{}",
        role_help.description
    );

    // The role is not valid on a module pattern, so constraining it is a
    // query error rather than a silent narrowing.
    let invalid = r#"(module :module (name "fmt"))"#;
    let diagnostic = validate_query_source(invalid)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("not valid for kind"))
        .unwrap_or_else(|| panic!("missing role-compatibility diagnostic for {invalid}"));
    assert_eq!(&invalid[diagnostic.range], ":module");
}

#[test]
fn comparison_and_assertion_vocabulary_has_validation_and_hover_help() {
    let comparison =
        r#"(comparison :left (identifier) :right (null_literal) :operator (text/regex "^==$"))"#;
    assert!(
        validate_query_source(comparison).is_empty(),
        "{:#?}",
        validate_query_source(comparison)
    );
    for (token, expected) in [
        ("comparison", "comparison expression"),
        (":left", "left-hand side"),
        (":right", "right-hand side"),
        (":operator", "operator token"),
    ] {
        let help = query_source_help_at(comparison, comparison.find(token).unwrap())
            .unwrap_or_else(|| panic!("missing hover help for {token}"));
        assert!(
            help.description.contains(expected),
            "{token}: {}",
            help.description
        );
    }

    let assertion = "(assertion :test (comparison))";
    assert!(validate_query_source(assertion).is_empty());
    let test_help = query_source_help_at(assertion, assertion.find(":test").unwrap())
        .expect("assertion test role help");
    assert!(
        test_help
            .description
            .contains("expression tested by an assertion")
    );

    for (kind, expected_help) in [
        ("binary_expression", "binary expression"),
        ("comparison_chain", "chained comparison"),
    ] {
        let source = format!("({kind})");
        assert!(validate_query_source(&source).is_empty(), "{kind}");
        let help = query_source_help_at(&source, source.find(kind).unwrap())
            .unwrap_or_else(|| panic!("missing hover help for {kind}"));
        assert!(
            help.description.contains(expected_help),
            "{kind}: {}",
            help.description
        );
    }

    for (label, expected_help) in [
        (
            "python-comparison-constants",
            "AST operands are supported constants",
        ),
        ("python-comparison-using-is", "effective custom __eq__"),
        ("python-comparison-using-is-non-portable", "CPython interns"),
    ] {
        let source = format!("({label} (language python (comparison)))");
        assert!(validate_query_source(&source).is_empty(), "{label}");
        let help = query_source_help_at(&source, source.find(label).unwrap())
            .unwrap_or_else(|| panic!("missing hover help for {label}"));
        assert!(
            help.description.contains(expected_help),
            "{label}: {}",
            help.description
        );
    }

    let invalid = "(assertion :left (comparison))";
    let diagnostic = validate_query_source(invalid)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("not valid for kind"))
        .expect("left is invalid on assertion");
    assert_eq!(&invalid[diagnostic.range], ":left");
}

#[test]
fn capture_anchor_step_has_validation_and_hover_help() {
    let source = r#"(anchor :capture "condition"
        (language python
          (if :test (literal :capture "condition"))))"#;
    assert!(
        validate_query_source(source).is_empty(),
        "{:#?}",
        validate_query_source(source)
    );
    let anchor = query_source_help_at(source, source.find("anchor").unwrap())
        .expect("anchor step hover help");
    assert!(anchor.description.contains("source range"));
    let capture = query_source_help_at(source, source.find(":capture").unwrap())
        .expect("anchor capture option hover help");
    assert!(capture.description.contains("structural capture"));

    let invalid = r#"(anchor :capture "missing" (language python (if)))"#;
    let diagnostic = validate_query_source(invalid)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("not declared"))
        .expect("unknown capture should be rejected");
    assert_eq!(&invalid[diagnostic.range], "\"missing\"");
}

/// The iteration vocabulary added for issue #2647: the `collection_literal`
/// kind, the single-valued `iterable` role, and the ordered `elements` role.
/// Every surface is registry-driven, so both spellings lint, hover, and
/// misspell identically, and each role is constrained to the one kind it is
/// declared valid for.
#[test]
fn iteration_vocabulary_help_suggestions_and_validation_ranges_are_schema_driven() {
    for (source, token, needle) in [
        (
            "(for_loop :iterable (identifier))",
            ":iterable",
            "for-each loop iterates",
        ),
        (
            "(collection_literal :elements [(string_literal)])",
            ":elements",
            "elements of a collection literal",
        ),
    ] {
        assert!(
            validate_query_source(source).is_empty(),
            "{source}: {:#?}",
            validate_query_source(source)
        );
        let offset = source.find(token).expect("help token");
        let help = query_source_help_at(source, offset).expect("iteration role help");
        assert_eq!(&source[help.range], token);
        assert!(help.description.contains(needle), "{}", help.description);
    }

    let literal = "(collection_literal :elements [(string_literal)])";
    let kind_help = query_source_help_at(literal, literal.find("collection_literal").unwrap())
        .expect("collection_literal kind help");
    assert_eq!(&literal[kind_help.range], "collection_literal");
    assert!(
        kind_help.description.contains("collection display literal"),
        "{}",
        kind_help.description
    );

    // `iterable` takes one pattern and `elements` an ordered list, so the
    // opposite shape is a value-shape error at the offending value.
    for (source, invalid) in [
        ("(for_loop :iterable [(identifier)])", "[(identifier)]"),
        (
            "(collection_literal :elements (string_literal))",
            "(string_literal)",
        ),
    ] {
        let diagnostic = validate_query_source(source)
            .into_iter()
            .find(|diagnostic| diagnostic.code == "wrong-value-shape")
            .unwrap_or_else(|| panic!("missing shape diagnostic for {source}"));
        assert_eq!(&source[diagnostic.range], invalid);
    }

    // Each role is declared valid for exactly one kind, so naming it on any
    // other pattern is an error rather than a silent narrowing.
    for (source, token) in [
        ("(while_loop :iterable (identifier))", ":iterable"),
        ("(call :elements [(string_literal)])", ":elements"),
    ] {
        let diagnostic = validate_query_source(source)
            .into_iter()
            .find(|diagnostic| diagnostic.message.contains("not valid for kind"))
            .unwrap_or_else(|| panic!("missing role-compatibility diagnostic for {source}"));
        assert_eq!(&source[diagnostic.range], token);
    }

    for (source, needle) in [
        ("(for_loop :iterble (identifier))", "iterable"),
        (
            "(collection_literal :element [(string_literal)])",
            "elements",
        ),
    ] {
        let diagnostic = validate_query_source(source)
            .into_iter()
            .find(|diagnostic| diagnostic.message.contains("Did you mean"))
            .unwrap_or_else(|| panic!("missing suggestion for {source}"));
        assert!(
            diagnostic.message.contains(needle),
            "{}",
            diagnostic.message
        );
    }
}

#[test]
fn exact_index_help_and_validation_are_schema_driven() {
    for source in [
        r#"(collection_literal :elements [(string_literal :index 1)])"#,
        r#"(collection_literal :elements [(string_literal (index 1))])"#,
    ] {
        assert!(
            validate_query_source(source).is_empty(),
            "{source}: {:#?}",
            validate_query_source(source)
        );
    }

    let property = r#"(collection_literal :elements [(string_literal :index 1)])"#;
    let help = query_source_help_at(property, property.find(":index").unwrap())
        .expect("index property help");
    assert_eq!(&property[help.range], ":index");
    assert!(help.description.contains("exact zero-based position"));

    let form = r#"(collection_literal :elements [(string_literal (index 1))])"#;
    let help = query_source_help_at(form, form.find("index").unwrap()).expect("index form help");
    assert_eq!(&form[help.range], "index");

    let root_index = "(collection_literal :index 1)";
    let diagnostic = validate_query_source(root_index)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("ordered list role"))
        .expect("index rejected outside list role");
    assert_eq!(&root_index[diagnostic.range], "1");

    let invalid = "(collection_literal :elements [(string_literal :index -1)])";
    let diagnostic = validate_query_source(invalid)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("non-negative"))
        .expect("negative index rejected");
    assert_eq!(&invalid[diagnostic.range], "-1");
}

#[test]
fn string_parts_role_help_and_validation_are_schema_driven() {
    let source = "(string_literal :parts [(string_literal)])";
    assert!(
        validate_query_source(source).is_empty(),
        "{:#?}",
        validate_query_source(source)
    );
    let help =
        query_source_help_at(source, source.find(":parts").unwrap()).expect("parts role help");
    assert_eq!(&source[help.range], ":parts");
    assert!(
        help.description
            .contains("implicitly concatenated literals")
    );
    assert!(help.description.contains("interpolated expressions"));

    let invalid = "(collection_literal :parts [(string_literal)])";
    let diagnostic = validate_query_source(invalid)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("not valid for kind"))
        .expect("parts role restricted to strings");
    assert_eq!(&invalid[diagnostic.range], ":parts");
}

#[test]
fn parenthesized_literal_property_has_schema_help() {
    let source = "(string_literal :parenthesized true)";
    assert!(
        validate_query_source(source).is_empty(),
        "{:#?}",
        validate_query_source(source)
    );
    let help = query_source_help_at(source, source.find(":parenthesized").unwrap())
        .expect("parenthesized help");
    assert_eq!(&source[help.range], ":parenthesized");
    assert!(help.description.contains("string-literal"));
}

#[test]
fn duplicate_key_property_has_schema_help_and_validation_ranges() {
    let source = "(object_property :duplicate-key true)";
    assert!(validate_query_source(source).is_empty());
    let help = query_source_help_at(source, source.find(":duplicate-key").unwrap())
        .expect("duplicate key help");
    assert_eq!(&source[help.range], ":duplicate-key");
    assert!(help.description.contains("Python dictionary"));

    let source = "(object_property :duplicate-key \"true\")";
    let diagnostic = validate_query_source(source)
        .into_iter()
        .find(|diagnostic| diagnostic.code == "wrong-value-shape")
        .expect("boolean property rejects a string value");
    assert_eq!(&source[diagnostic.range], "\"true\"");

    let source = "(object_property :duplicate-ky true)";
    let diagnostic = validate_query_source(source)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("Did you mean"))
        .expect("duplicate-key typo suggestion");
    assert!(diagnostic.message.contains("duplicate-key"));
}

#[test]
fn integer_literal_value_and_mask_fields_have_schema_help_and_validation() {
    let source = r#"(numeric_literal :integer-value "511" :integer-has-any-bits 2 :integer-has-all-bits 3 :integer-has-no-bits 4)"#;
    assert!(
        validate_query_source(source).is_empty(),
        "{:#?}",
        validate_query_source(source)
    );
    for token in [
        "integer-value",
        "integer-has-any-bits",
        "integer-has-all-bits",
        "integer-has-no-bits",
    ] {
        let help = query_source_help_at(source, source.find(token).unwrap())
            .unwrap_or_else(|| panic!("missing integer-literal help for {token}"));
        assert_eq!(&source[help.range], format!(":{token}"));
        assert!(help.description.contains("integer literal"));
    }

    for (invalid, expected_value) in [
        (r#"(numeric_literal :integer-value "0511")"#, "\"0511\""),
        ("(numeric_literal :integer-has-any-bits 0)", "0"),
        (
            "(numeric_literal :integer-has-no-bits 4294967296)",
            "4294967296",
        ),
    ] {
        let diagnostic = validate_query_source(invalid)
            .into_iter()
            .find(|diagnostic| &invalid[diagnostic.range.clone()] == expected_value)
            .unwrap_or_else(|| panic!("expected integer-value rejection for {invalid}"));
        assert_eq!(&invalid[diagnostic.range], expected_value);
    }
}

#[test]
fn assignment_shape_properties_have_schema_help_and_validate_enum_values() {
    let source =
        "(assignment :assignment-target-kind tuple :assignment-unstarred-count-mismatch true)";
    assert!(
        validate_query_source(source).is_empty(),
        "{:#?}",
        validate_query_source(source)
    );
    for token in [
        "assignment-target-kind",
        "assignment-unstarred-count-mismatch",
    ] {
        let help = query_source_help_at(source, source.find(token).unwrap())
            .unwrap_or_else(|| panic!("missing assignment-shape help for {token}"));
        assert_eq!(&source[help.range], format!(":{token}"));
        assert!(!help.description.is_empty());
    }

    let invalid = "(assignment :assignment-target-kind array)";
    let diagnostic = validate_query_source(invalid)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("list or tuple"))
        .expect("unsupported assignment sequence kind is rejected");
    assert_eq!(&invalid[diagnostic.range], "array");
}

#[test]
fn hierarchy_step_help_and_option_diagnostics_are_range_precise() {
    let rql = "(subtypes :depth 2 (enclosing-decl (class)))";
    for token in ["subtypes", ":depth"] {
        let offset = rql.find(token).unwrap();
        let help = query_source_help_at(rql, offset)
            .unwrap_or_else(|| panic!("no hierarchy help for {token}"));
        assert!(!help.description.is_empty());
    }
    assert!(validate_query_source(rql).is_empty());

    let invalid = "(supertypes :depth 0 (enclosing-decl (class)))";
    let diagnostics = validate_query_source(invalid);
    assert!(diagnostics.iter().any(|diagnostic| {
        &invalid[diagnostic.range.clone()] == "0" && diagnostic.message.contains("positive integer")
    }));

    let conflicting = "(supertypes :depth 2 :transitive true (enclosing-decl (class)))";
    let diagnostics = validate_query_source(conflicting);
    assert!(
        diagnostics.iter().any(|diagnostic| {
            &conflicting[diagnostic.range.clone()] == "(enclosing-decl (class))"
                && diagnostic.code == "wrong-value-shape"
                && diagnostic
                    .message
                    .contains(":depth count or :transitive true")
        }),
        "{diagnostics:?}"
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#3745: absent-member proof values were not constrained to the conditional row domain"
)]
fn absent_member_proof_option_help_validation_and_row_domain_are_typed() {
    let rql = "(absent-member :proof conditional (procedure-of (function)))";
    for token in ["absent-member", ":proof"] {
        let offset = rql.find(token).expect("absent-member proof token");
        let help = query_source_help_at(rql, offset)
            .unwrap_or_else(|| panic!("no absent-member help for {token}"));
        assert_eq!(&rql[help.range], token);
        assert!(!help.description.is_empty());
    }
    let offset = rql.find(":proof").expect("proof option");
    let help = query_source_help_at(rql, offset).expect("proof help");
    assert!(help.description.contains("conditional"), "{help:?}");
    for proof in ["proven", "conditional", "any"] {
        let rql = format!("(absent-member :proof {proof} (procedure-of (function)))");
        assert!(validate_query_source(&rql).is_empty(), "{rql}");
    }

    let invalid = "(absent-member :proof unproven (procedure-of (function)))";
    let diagnostic = validate_query_source(invalid)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("unproven"))
        .expect("invalid proof tier diagnostic");
    assert_eq!(&invalid[diagnostic.range.clone()], "unproven");
    for allowed in ["proven", "conditional", "any"] {
        assert!(diagnostic.message.contains(allowed), "{diagnostic:?}");
    }

    let duplicate = "(absent-member :proof any :proof proven (procedure-of (function)))";
    let diagnostic = validate_query_source(duplicate)
        .into_iter()
        .find(|diagnostic| diagnostic.code == "duplicate-property")
        .expect("duplicate proof option diagnostic");
    assert_eq!(&duplicate[diagnostic.range.clone()], ":proof");

    let fields =
        crate::structural::search::DetailedCodeQueryDomain::AbsentMemberFinding.row_fields();
    let proof = fields
        .iter()
        .find(|field| field.name == "proof")
        .expect("absent-member proof field");
    assert_eq!(
        proof.scalar_type,
        crate::structural::search::CodeQueryRowScalarType::ConstrainedEnum
    );
    assert_eq!(
        proof.value_domain.and_then(|domain| domain.labels()),
        Some(["proven", "conditional"].as_slice())
    );
}

#[test]
fn set_composition_help_and_domain_diagnostics_are_range_precise() {
    let rql = "(file-of (union (enclosing-decl (class :name \"A\")) (enclosing-decl (class :name \"B\"))))";
    for token in ["union", "file-of"] {
        let offset = rql.find(token).unwrap();
        let help = query_source_help_at(rql, offset)
            .unwrap_or_else(|| panic!("no set-composition help for {token}"));
        assert_eq!(&rql[help.range], token);
        assert!(!help.description.is_empty());
    }
    assert!(validate_query_source(rql).is_empty());

    let rql_source = "(intersect (enclosing-decl (class)) (file-of (class)))";
    let diagnostic = validate_query_source(rql_source)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("first branch produces"))
        .expect("typed branch diagnostic");
    assert_eq!(&rql_source[diagnostic.range], "(class)");

    // A union of different row kinds is valid on its own (#5352); a typed
    // step over it is what the diagnostic refuses.
    let mixed_union = "(union (enclosing-decl (class)) (file-of (class)))";
    assert!(validate_query_source(mixed_union).is_empty());
    let stepped = "(imports-of (union (enclosing-decl (class)) (file-of (class))))";
    let diagnostic = validate_query_source(stepped)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("requires rows of one kind"))
        .expect("mixed union step diagnostic");
    assert_eq!(&stepped[diagnostic.range], "imports-of");

    let too_short = "(except (class))";
    let diagnostic = validate_query_source(too_short)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("at least two"))
        .expect("branch-count diagnostic");
    assert_eq!(&too_short[diagnostic.range], "(class)");
}

#[test]
fn points_to_candidate_help_and_shape_diagnostics_are_range_precise() {
    let rql = r#"(points-to-candidates (points-to :capture service (call :receiver (capture "service"))))"#;
    let offset = rql.find("points-to-candidates").unwrap();
    let help = query_source_help_at(rql, offset).expect("candidate expansion help");
    assert_eq!(&rql[help.range], "points-to-candidates");
    assert!(!help.description.is_empty());
    assert!(validate_query_source(rql).is_empty());

    let wrong_shape = "(points-to-candidates (function))";
    let diagnostic = validate_query_source(wrong_shape)
        .into_iter()
        .next()
        .expect("wrong candidate input diagnostic");
    assert_eq!(diagnostic.code, "invalid-query");
    assert!(!diagnostic.message.is_empty());
    assert_eq!(&wrong_shape[diagnostic.range], "points-to-candidates");
}

#[test]
fn byte_ranges_preserve_utf8_boundaries() {
    let source = "(call :unknown-λ 1)";
    let diagnostic = validate_query_source(source).pop().expect("diagnostic");
    assert_eq!(&source[diagnostic.range], ":unknown-λ");
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#744: RQL quick-fix suggestions duplicated aliases and emitted ambiguous/distant candidates"
)]
fn suggestion_selector_deduplicates_aliases_and_suppresses_ties_and_distant_values() {
    assert_eq!(
        best_suggestion(
            "not_haz",
            [
                ("not-has".to_string(), "not-has".to_string()),
                ("not-has".to_string(), "not_has".to_string()),
            ],
        ),
        Some("not-has".to_string())
    );
    assert_eq!(
        best_suggestion(
            "cot",
            [
                ("cat".to_string(), "cat".to_string()),
                ("cut".to_string(), "cut".to_string()),
            ],
        ),
        None
    );
    assert_eq!(
        best_suggestion("unrelated", [("call".to_string(), "call".to_string())]),
        None
    );
    assert_eq!(
        best_suggestion(
            "result_detail",
            [("result-detail".to_string(), "result_detail".to_string())],
        ),
        None
    );
}

#[test]
fn python_format_issues_form_help_and_diagnostics_are_range_precise() {
    for label in ["python-format-issues", "python_format_issues"] {
        let source = format!("({label} (language python (call)))");
        let offset = source.find(label).unwrap();
        let help = query_source_help_at(&source, offset)
            .unwrap_or_else(|| panic!("no format-issues help for {label}"));
        assert_eq!(&source[help.range], label);
        assert!(help.description.contains("brace-format and percent-format"));
        assert!(validate_query_source(&source).is_empty(), "{source}");

        let wrong_upstream = format!("({label} (call-shape (call)))");
        let diagnostic = validate_query_source(&wrong_upstream)
            .into_iter()
            .find(|diagnostic| diagnostic.code == "invalid-query")
            .expect("typed structural-match upstream diagnostic");
        assert_eq!(
            &wrong_upstream[diagnostic.range.clone()],
            label,
            "{diagnostic:?}"
        );
    }
}

#[test]
fn python_rule_fact_forms_validate_and_hover_from_schema() {
    let forms = [
        "procedure-return-profile",
        "python-iterator-return-protocol",
        "python-builtin-identity",
        "python-raise-not-implemented",
        "python-attribute-shadows-method",
        "python-modification-of-default-value",
        "call-result-use",
        "tuple-return-groups",
        "lambda-forwarding",
        "python-url-construction",
        "python-raise-legality",
        "python-special-method-raise",
    ];
    for (form, query) in forms.into_iter().zip([
        "(procedure-return-profile (procedure-of (language python (callable))))",
        "(python-iterator-return-protocol (procedure-of (language python (method :name \"__iter__\"))))",
        "(python-builtin-identity (language python (occurrences :class reference)))",
        "(python-raise-not-implemented (language python (throw)))",
        "(python-attribute-shadows-method (enclosing-decl (language python (class))))",
        "(python-modification-of-default-value (enclosing-decl (language python (function))))",
        "(call-result-use (call-shape (language python (call))))",
        "(tuple-return-groups (procedure-of (language python (callable))))",
        "(lambda-forwarding (language python (lambda)))",
        "(python-url-construction (language python (binary_expression)))",
        "(python-raise-legality (language python (throw)))",
        "(python-special-method-raise (language python (throw)))",
    ]) {
        let help = query_source_help_at(query, query.find(form).unwrap())
            .unwrap_or_else(|| panic!("no help for {form}"));
        assert_eq!(&query[help.range], form);
        assert!(!help.description.is_empty());
        assert!(
            validate_query_source(query).is_empty(),
            "{query}: {:#?}",
            validate_query_source(query)
        );
    }
    let underscored = "(procedure_return_profile (procedure-of (language python (callable))))";
    assert!(
        validate_query_source(underscored).is_empty(),
        "{underscored}"
    );
    let underscored = "(python_iterator_return_protocol (procedure-of (language python (method :name \"__iter__\"))))";
    assert!(
        validate_query_source(underscored).is_empty(),
        "{underscored}"
    );
    let underscored =
        "(python_attribute_shadows_method (enclosing-decl (language python (class))))";
    assert!(
        validate_query_source(underscored).is_empty(),
        "{underscored}"
    );
    let underscored =
        "(python_modification_of_default_value (enclosing-decl (language python (function))))";
    assert!(
        validate_query_source(underscored).is_empty(),
        "{underscored}"
    );

    let invalid = "(procedure-return-profiles (procedure-of (callable)))";
    let diagnostic = validate_query_source(invalid)
        .into_iter()
        .find(|diagnostic| diagnostic.code == "unknown-form")
        .expect("unknown-form diagnostic");
    assert_eq!(
        &invalid[diagnostic.range.clone()],
        "procedure-return-profiles"
    );
}

#[test]
fn rust_pointer_findings_form_validates_and_has_hover_help() {
    for form in ["rust-pointer-findings", "rust_pointer_findings"] {
        let source = format!("({form} (procedure-of (language rust (function :name \"run\"))))");
        assert!(
            validate_query_source(&source).is_empty(),
            "{source}: {:#?}",
            validate_query_source(&source)
        );
        let help = query_source_help_at(&source, source.find(form).unwrap())
            .unwrap_or_else(|| panic!("missing RQL help for {form}"));
        assert_eq!(&source[help.range], form);
        assert!(help.description.contains("pointer provenance"));
        assert!(help.description.contains("completeness"));
    }

    let invalid = "(rust-pointer-findings (call))";
    let diagnostic = validate_query_source(invalid)
        .into_iter()
        .find(|diagnostic| diagnostic.code == "invalid-query")
        .expect("pointer findings require procedure input");
    assert_eq!(&invalid[diagnostic.range], "rust-pointer-findings");
}

#[test]
fn procedure_effects_accept_procedure_rows_with_registered_help_and_ranges() {
    let rql = "(procedure-effects (procedure-of (function (name \"run\"))))";
    for token in ["procedure-effects", "procedure-of"] {
        let offset = rql.find(token).unwrap();
        let help =
            query_source_help_at(rql, offset).unwrap_or_else(|| panic!("no help for {token}"));
        assert_eq!(&rql[help.range], token);
        assert!(!help.description.is_empty());
    }
    assert!(
        validate_query_source(rql).is_empty(),
        "{rql}: {:#?}",
        validate_query_source(rql)
    );

    let wrong_upstream = "(procedure-effects (call-shape (call :callee (name \"run\"))))";
    let diagnostic = validate_query_source(wrong_upstream)
        .into_iter()
        .find(|diagnostic| {
            diagnostic.code == "invalid-query"
                && diagnostic
                    .message
                    .contains("requires declaration or procedure")
        })
        .expect("procedure-effects rejects a call-shape upstream");
    assert_eq!(
        &wrong_upstream[diagnostic.range.clone()],
        "procedure-effects"
    );
}

#[test]
fn accepted_language_aliases_do_not_produce_diagnostics() {
    for source in ["(language c++ (call))", "(language c# (call))"] {
        assert!(
            validate_query_source(source).is_empty(),
            "accepted language alias should validate: {source}"
        );
    }
}

#[test]
fn arity_forms_validate_ranges_at_exact_positions() {
    // Well-formed exact and range forms validate clean in RQL source.
    for source in [
        r#"(call :callee (name "execute") :arity 1)"#,
        r#"(call (arity :min 1 :max 3))"#,
        r#"(call (arity :min 1))"#,
    ] {
        assert!(
            validate_query_source(source).is_empty(),
            "well-formed arity should validate: {source}: {:#?}",
            validate_query_source(source)
        );
    }

    // A min above max is rejected at the offending predicate/object.
    let rql = r#"(call (arity :min 3 :max 1))"#;
    let diagnostic = validate_query_source(rql).pop().expect("range diagnostic");
    assert_eq!(diagnostic.code, "invalid-query");
    assert!(
        diagnostic.message.contains("must not exceed"),
        "{diagnostic:?}"
    );

    // An empty range constrains nothing.
    let rql_source = "(call (arity))";
    let diagnostic = validate_query_source(rql_source)
        .pop()
        .expect("empty range diagnostic");
    assert!(
        diagnostic.message.contains("expects a count"),
        "{diagnostic:?}"
    );

    // A bound above MAX_ARITY.
    let rql = "(call (arity 100000))";
    let diagnostic = validate_query_source(rql).pop().expect("bound diagnostic");
    assert!(diagnostic.message.contains("at most"), "{diagnostic:?}");

    // An unknown range key is flagged at that key.
    let rql_source = "(call (arity :exactly 1))";
    let diagnostics = validate_query_source(rql_source);
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| &rql_source[diagnostic.range.clone()] == ":exactly"),
        "{diagnostics:#?}"
    );

    // The `:arity` property does not take a range list.
    let rql = r#"(call :arity [1 3])"#;
    assert!(!validate_query_source(rql).is_empty());

    // Arity alone cannot anchor the root pattern.
    let rql = "(arity 1)";
    let diagnostic = validate_query_source(rql)
        .pop()
        .expect("root anchor diagnostic");
    assert!(diagnostic.message.contains("kind"), "{diagnostic:?}");
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#3351: keyed-read value-family options were not validated against the portable runtime contract"
)]
fn keyed_read_value_family_options_validate_have_range_help() {
    let source = "(keyed-read-value :runtime node :global process :container argv :key-kind static-index :index-min 1 :index-max 3 (call))";
    assert!(
        validate_query_source(source).is_empty(),
        "{source}: {:#?}",
        validate_query_source(source)
    );
    for token in [":key-kind", ":index-min", ":index-max"] {
        let help = query_source_help_at(source, source.find(token).unwrap())
            .unwrap_or_else(|| panic!("no keyed-read help for {token}"));
        assert_eq!(&source[help.range], token);
        assert!(!help.description.is_empty());
    }

    for (source, token) in [
        (
            "(keyed-read-value :runtime node :global process :container env :key-kind static-index (call))",
            "env",
        ),
        (
            "(keyed-read-value :runtime node :global process :container argv :key-kind static-property (call))",
            "argv",
        ),
        (
            "(keyed-read-value :runtime node :global process :container argv :key-kind static-property :index-min 1 (call))",
            "static-property",
        ),
        (
            "(keyed-read-value :runtime node :global process :container argv :key-kind static-index :index-min 4 :index-max 2 (call))",
            "4",
        ),
        (
            "(keyed-read-value :runtime node :global process :container argv :index 4294967295 (call))",
            "4294967295",
        ),
    ] {
        let diagnostics = validate_query_source(source);
        assert!(!diagnostics.is_empty(), "{source}");
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| &source[diagnostic.range.clone()] == token),
            "{source}: {diagnostics:#?}"
        );
    }
}

#[test]
fn generated_json_is_machine_serialization_only() {
    let query = CodeQuery::from_source("(language rust (call :callee (name \"run\")))")
        .expect("authored RQL");
    let canonical = query.to_canonical_json();
    let decoded = CodeQuery::from_json(&canonical).expect("machine JSON");
    assert_eq!(decoded.to_canonical_json(), canonical);
    let source = canonical.to_string();
    assert!(CodeQuery::from_source(&source).is_err());
    assert!(!validate_query_source(&source).is_empty());
    assert!(query_source_help_at(&source, source.find("match").unwrap()).is_none());
}

#[test]
fn configuration_key_validation_matches_the_decoder() {
    // The editor validator and the canonical decoder must agree on which
    // authored keys are selectable, including the empty key that JSON admits.
    let empty_key = r#"(configuration-facts :format json :key "")"#;
    assert!(
        validate_query_source(empty_key).is_empty(),
        "{:#?}",
        validate_query_source(empty_key)
    );
    assert!(crate::structural::CodeQuery::from_sexp(empty_key).is_ok());

    let oversized = format!(
        r#"(configuration-facts :format json :key "{}")"#,
        "k".repeat(MAX_CONFIGURATION_KEY_LENGTH + 1)
    );
    let diagnostics = validate_query_source(&oversized);
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "wrong-value-shape"),
        "{diagnostics:#?}"
    );
    assert!(crate::structural::CodeQuery::from_sexp(&oversized).is_err());
}

#[test]
fn explicit_enum_row_literal_help_and_error_ranges_are_precise() {
    let source = "(filter :where ((failure_predicate eq (enum false))) (call-result-obligations (call-shape (call))))";
    assert!(validate_query_source(source).is_empty());
    let offset = source.find("enum").unwrap();
    let help = query_source_help_at(source, offset).expect("explicit enum help");
    assert_eq!(&source[help.range], "enum");
    assert!(help.description.contains("Boolean"));
    let invalid = source.replace("(enum false)", "(enum false true)");
    let diagnostics = validate_query_source(&invalid);
    let diagnostic = diagnostics
        .iter()
        .find(|d| d.message.contains("exactly one label"))
        .unwrap_or_else(|| panic!("expected invalid enum: {diagnostics:?}"));
    assert_eq!(&invalid[diagnostic.range.clone()], "(enum false true)");
}

#[test]
fn cross_domain_operators_have_shared_help_and_range_precise_validation() {
    let rql = r#"(correlate
  :relation (configuration-key :documents ["src/main/resources/app.properties"])
  :code (call-input :parameter-index 0 (call-sites-to (enclosing-decl (method (name "get")))))
  :configuration (configuration-facts :format properties))"#;
    assert!(
        validate_query_source(rql).is_empty(),
        "{:#?}",
        validate_query_source(rql)
    );
    for token in [
        "correlate",
        ":relation",
        "configuration-key",
        ":documents",
        ":code",
        ":configuration",
    ] {
        let help = query_source_help_at(rql, rql.find(token).unwrap()).expect(token);
        assert_eq!(&rql[help.range], token);
        assert!(!help.description.is_empty(), "{token}");
    }
    let require = "(require-both :code (call) :configuration (configuration-facts))";
    let help = query_source_help_at(require, 1).expect("require-both help");
    assert_eq!(&require[help.range], "require-both");
    assert!(
        help.description.contains("never pairs"),
        "{}",
        help.description
    );

    // A glob is not a declared document: the typed error lands on the entry.
    let glob = rql.replace("src/main/resources/app.properties", "**/*.properties");
    let diagnostic = validate_query_source(&glob)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("without globs"))
        .expect("declared-document diagnostic");
    assert_eq!(&glob[diagnostic.range], r#""**/*.properties""#);

    // An unknown relation is suggested from the relation registry only.
    let misspelled = rql.replace("configuration-key", "configuration-keys");
    let diagnostic = validate_query_source(&misspelled)
        .into_iter()
        .find(|diagnostic| diagnostic.code == "unknown-form")
        .expect("unknown relation diagnostic");
    assert_eq!(&misspelled[diagnostic.range.clone()], "configuration-keys");
    assert!(
        format!("{:?}", diagnostic.fix).contains("configuration-key"),
        "{diagnostic:?}"
    );

    // A relation is not a query, and require-both takes no relation.
    let relation = r#"(configuration-key :documents ["a.properties"])"#;
    let diagnostic = validate_query_source(relation)
        .into_iter()
        .next()
        .expect("relation-as-query diagnostic");
    assert_eq!(&relation[diagnostic.range], "configuration-key");
    let related = format!(
        "(require-both :relation {relation} :code (call) :configuration (configuration-facts))"
    );
    let diagnostic = validate_query_source(&related)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("never relates rows"))
        .expect("require-both relation diagnostic");
    assert_eq!(&related[diagnostic.range], relation);
}

#[test]
fn dependency_configuration_relation_help_and_validation_range() {
    let rql = r#"(correlate
        :relation (dependency-configuration :owner "npm:workspace:packages/a"
            :ecosystem npm :version-range "<2.0.0" :documents ["a.properties"] :values ["true"])
        :code (dependency-evidence :ecosystem npm :kind locked)
        :configuration (configuration-facts :format properties :key "feature.enabled"))"#;
    assert!(
        validate_query_source(rql).is_empty(),
        "{:#?}",
        validate_query_source(rql)
    );
    for token in [
        "dependency-configuration",
        ":owner",
        ":ecosystem",
        ":version-range",
        ":documents",
        ":values",
    ] {
        let help = query_source_help_at(rql, rql.find(token).unwrap()).expect(token);
        assert_eq!(&rql[help.range], token);
        assert!(!help.description.is_empty());
    }
    let invalid = rql.replace("<2.0.0", "workspace:*");
    let diagnostic = validate_query_source(&invalid)
        .into_iter()
        .find(|diagnostic| {
            diagnostic.range
                == (invalid.find("\"workspace:*\"").unwrap()
                    ..invalid.find("\"workspace:*\"").unwrap() + "\"workspace:*\"".len())
        })
        .expect("version range diagnostic on exact value");
    assert_eq!(&invalid[diagnostic.range], "\"workspace:*\"");
}

#[test]
fn resolved_value_source_validation_and_help_are_registered() {
    let source = r#"(resolved-value :resolves-to "django.views.decorators.csrf.csrf_exempt" :proof exact
        (language python (decorator)))"#;
    assert!(
        validate_query_source(source).is_empty(),
        "{source}: {:#?}",
        validate_query_source(source)
    );
    for token in [":resolves-to", ":proof"] {
        let help = query_source_help_at(source, source.find(token).unwrap())
            .unwrap_or_else(|| panic!("no resolved-value help for {token}"));
        assert_eq!(&source[help.range], token);
        assert!(!help.description.is_empty());
    }

    let invalid = source.replace(":proof exact", ":proof declared");
    let diagnostic = validate_query_source(&invalid)
        .into_iter()
        .find(|diagnostic| diagnostic.code == "unknown-value")
        .expect("resolved-value rejects a non-exact proof");
    assert_eq!(&invalid[diagnostic.range], "declared");
    assert!(diagnostic.message.contains("must be exact"));
}

#[test]
fn rust_marker_impls_form_validation_ranges_and_hover() {
    for form in ["rust-marker-impls-of", "rust_marker_impls_of"] {
        let source = format!("({form} (language rust (class)))");
        assert!(
            validate_query_source(&source).is_empty(),
            "{source}: {:?}",
            validate_query_source(&source)
        );
        let help = query_source_help_at(&source, source.find(form).unwrap()).unwrap();
        assert_eq!(&source[help.range], form);
        assert!(help.description.contains("marker bounds"));
        assert!(help.description.contains("completeness"));
    }
    let invalid = "(rust-marker-impls-of (file-of (class)))";
    let diagnostic = validate_query_source(invalid)
        .into_iter()
        .find(|d| d.code == "invalid-query")
        .unwrap();
    assert_eq!(&invalid[diagnostic.range], "rust-marker-impls-of");
}

#[test]
fn callee_provenance_columns_validate_with_hover_and_ranges() {
    let source = "(project :columns (callee_provenance callee_supplier callee_type_shape callee_bounds) (call-shape (language rust (call))))";
    assert!(
        validate_query_source(source).is_empty(),
        "{:#?}",
        validate_query_source(source)
    );
    let help =
        query_source_help_at(source, source.find("call-shape").unwrap()).expect("call shape hover");
    assert_eq!(&source[help.range], "call-shape");
    for column in [
        "callee_provenance",
        "callee_supplier",
        "callee_type_shape",
        "callee_bounds",
        "unsupported",
    ] {
        assert!(
            help.description.contains(column),
            "missing {column}: {}",
            help.description
        );
    }
    let invalid = "(project :columns (callee_suppllier) (call-shape (call)))";
    let diagnostics = validate_query_source(invalid);
    assert!(!diagnostics.is_empty());
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| invalid[diagnostic.range.clone()].contains("callee_suppllier")),
        "{diagnostics:#?}"
    );
}

#[test]
fn unsafe_context_call_property_has_help_and_diagnostic_ranges() {
    let source = "(language rust (call :unsafe-context true))";
    assert!(
        validate_query_source(source).is_empty(),
        "{:#?}",
        validate_query_source(source)
    );
    let help = query_source_help_at(source, source.find("unsafe-context").unwrap())
        .expect("unsafe-context hover");
    assert!(help.description.contains("Rust"));
    assert!(help.description.contains("call"));
    for source in [
        "(expression :unsafe-context true)",
        "(call :unsafe-context 7)",
    ] {
        let diagnostics = validate_query_source(source);
        assert!(!diagnostics.is_empty());
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| !source[diagnostic.range.clone()].is_empty()),
            "{diagnostics:#?}"
        );
    }
}

#[test]
fn declaration_attributes_and_expression_roles_have_editor_support() {
    for source in [
        r#"(class :type-kind "interface" :modifier "sealed")"#,
        r#"(class :and [(type-kind "record") (modifier "public")])"#,
        r#"(cast :type (identifier) :value (identifier))"#,
        r#"(instance_of :operand (identifier) :type (identifier) :binding (identifier))"#,
        r#"(subscript :object (identifier) :indices ((numeric_literal)))"#,
        r#"(array_creation :type (identifier) :dimensions ((capture "dimension")) :value (collection_literal))"#,
        r#"(unary_expression :operator (capture "op") :operand (identifier))"#,
        r#"(lock :value (identifier) :body (block))"#,
        r#"(if :test (identifier) :consequence (identifier) :alternative (identifier))"#,
        r#"(continue :label (name "outer"))"#,
    ] {
        assert!(
            validate_query_source(source).is_empty(),
            "{source}: {:#?}",
            validate_query_source(source)
        );
        super::super::CodeQuery::from_source(source).expect("parse registered syntax");
        let help = query_source_help_at(source, 1).expect("kind/form hover");
        assert!(!help.description.is_empty());
    }
    let source = r#"(class :type-kind "interface" :modifier "volatile")"#;
    for token in [":type-kind", ":modifier"] {
        assert!(query_source_help_at(source, source.find(token).unwrap()).is_some());
    }
    for (source, token) in [
        (r#"(class :type-kind "misspelled")"#, "misspelled"),
        (r#"(class :modifier "misspelled")"#, "misspelled"),
        (r#"(call :indices ((identifier)))"#, ":indices"),
    ] {
        let diagnostics = validate_query_source(source);
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| source[diagnostic.range.clone()].contains(token)),
            "{source}: {diagnostics:#?}"
        );
    }
}
