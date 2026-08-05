use super::*;

#[test]
fn quiet_for_empty_and_incomplete_sources() {
    for source in [
        "",
        "  ; comment",
        "(call",
        "(call :callee",
        "\"unfinished",
        "{\"match\":",
    ] {
        assert!(validate_query_source(source).is_empty(), "{source:?}");
    }
}

#[test]
fn reports_multiple_rql_errors_at_exact_ranges() {
    let source = "(call :wat 1 :name 2 :also-nope 3)";
    let diagnostics = validate_query_source(source);
    assert_eq!(diagnostics.len(), 3);
    assert_eq!(&source[diagnostics[0].range.clone()], ":wat");
    assert_eq!(&source[diagnostics[1].range.clone()], "2");
    assert_eq!(&source[diagnostics[2].range.clone()], ":also-nope");
}

#[test]
fn reports_multiple_json_errors_at_key_and_value_ranges() {
    let source = r#"{"oops": 1, "match": {"kind": "banana", "capture": 4}}"#;
    let mut diagnostics = validate_query_source(source);
    diagnostics.sort_by_key(|diagnostic| diagnostic.range.start);
    assert_eq!(diagnostics.len(), 3);
    assert_eq!(&source[diagnostics[0].range.clone()], "\"oops\"");
    assert_eq!(&source[diagnostics[1].range.clone()], "\"banana\"");
    assert_eq!(&source[diagnostics[2].range.clone()], "4");
}

#[test]
fn reports_independent_semantic_errors_with_unknown_properties() {
    for source in [
        r#"(call :unknown 1 :name/regex "[")"#,
        r#"{"unknown":1,"match":{"kind":"call","name":{"regex":"["}}}"#,
    ] {
        let diagnostics = validate_query_source(source);
        assert_eq!(diagnostics.len(), 2, "{source}: {diagnostics:#?}");
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "unknown-property")
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("invalid regex"))
        );
    }
}

#[test]
fn reports_role_compatibility_without_waiting_for_typed_lowering() {
    for source in [
        r#"(assignment :unknown 1 :callee (name "run"))"#,
        r#"{"unknown":1,"match":{"kind":"assignment","callee":{"name":"run"}}}"#,
    ] {
        let diagnostics = validate_query_source(source);
        assert_eq!(diagnostics.len(), 2, "{source}: {diagnostics:#?}");
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("not valid for kind"))
        );
    }
}

#[test]
fn text_predicate_requires_regex_object_in_json() {
    let source = r#"{"match":{"text":"exact"}}"#;
    let diagnostic = validate_query_source(source).pop().expect("diagnostic");
    assert_eq!(diagnostic.code, "wrong-value-shape");
    assert_eq!(&source[diagnostic.range], "\"exact\"");
}

#[test]
fn malformed_json_range_is_byte_correct_after_utf8() {
    let source = r#"{"λ": 1, ]"#;
    let diagnostic = validate_query_source(source).pop().expect("diagnostic");
    assert_eq!(diagnostic.code, "invalid-json");
    assert_eq!(&source[diagnostic.range], "]");
}

#[test]
fn json_schema_validation_uses_the_compatibility_registry() {
    use crate::schema_version::{SchemaVersionDescriptor, SchemaVersionRegistry};

    let registry = SchemaVersionRegistry::new(&[
        SchemaVersionDescriptor::new(2, None, true),
        SchemaVersionDescriptor::new(3, Some(2), true),
    ])
    .unwrap();
    for source in [
        r#"{"schema_version":2,"match":{"kind":"call"}}"#,
        r#"{"match":{"kind":"call"}}"#,
    ] {
        let analysis = analyze_json_with_schema_registry(source, &registry);
        assert!(
            analysis.diagnostics.is_empty(),
            "{:?}",
            analysis.diagnostics
        );
    }

    let source = r#"{"schema_version":1,"match":{"kind":"call"}}"#;
    let analysis = analyze_json_with_schema_registry(source, &registry);
    assert_eq!(analysis.diagnostics.len(), 1);
    assert_eq!(analysis.diagnostics[0].code, "unsupported-schema-version");
    assert_eq!(&source[analysis.diagnostics[0].range.clone()], "1");
}

#[test]
fn incomplete_rql_keeps_help_for_completed_tokens() {
    let source = "(call :callee";
    let offset = source.find(":callee").unwrap() + 1;
    let help = query_source_help_at(source, offset).expect("role help");
    assert_eq!(&source[help.range], ":callee");
    assert!(validate_query_source(source).is_empty());
}

#[test]
fn incomplete_json_keeps_help_for_completed_keys() {
    for (source, token) in [
        (r#"{"match":"#, "match"),
        (r#"{"match":{"kind":"#, "kind"),
        (r#"{"match":{"kind":"call","callee":"#, "callee"),
    ] {
        let offset = source.find(token).unwrap();
        let help = query_source_help_at(source, offset)
            .unwrap_or_else(|| panic!("no help for {token} in {source}"));
        assert_eq!(&source[help.range], format!("\"{token}\""));
        assert!(validate_query_source(source).is_empty());
    }
}

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
fn plan_budgets_stop_json_and_rql_source_validation_early() {
    let mut deep_json = serde_json::json!({ "match": 3 });
    let mut deep_rql = "(banana)".to_string();
    for _ in 0..=MAX_QUERY_PLAN_DEPTH {
        deep_json = serde_json::json!({
            "union": [deep_json, { "match": { "kind": "call" } }]
        });
        deep_rql = format!("(union {deep_rql} (call))");
    }
    for source in [deep_json.to_string(), deep_rql] {
        let diagnostics = validate_query_source(&source);
        assert_eq!(diagnostics.len(), 1, "{source}: {diagnostics:#?}");
        assert!(diagnostics[0].message.contains("plan depth"));
    }

    let json_groups = (0..4)
        .map(|_| {
            serde_json::json!({
                "union": (0..16)
                    .map(|_| serde_json::json!({ "match": { "kind": "call" } }))
                    .collect::<Vec<_>>()
            })
        })
        .collect::<Vec<_>>();
    let wide_json = serde_json::json!({ "union": json_groups }).to_string();
    let rql_group = format!("(union {})", vec!["(call)"; 16].join(" "));
    let wide_rql = format!("(union {})", vec![rql_group; 4].join(" "));
    for source in [wide_json, wide_rql] {
        let diagnostics = validate_query_source(&source);
        assert_eq!(diagnostics.len(), 1, "{source}: {diagnostics:#?}");
        assert!(diagnostics[0].message.contains("at most 64 nodes"));
    }
}

#[test]
fn canonical_json_and_rql_execute_equivalently() {
    let rql =
        CodeQuery::from_source("(language rust (call :callee (name \"run\")))").expect("RQL query");
    let json = CodeQuery::from_source(
        r#"{"languages":["rust"],"match":{"kind":"call","callee":{"name":"run"}}}"#,
    )
    .expect("JSON query");
    assert_eq!(rql.to_canonical_json(), json.to_canonical_json());
}

#[test]
fn execution_mode_frontends_validate_with_exact_ranges_and_shared_help() {
    let rql = "(profile (call))";
    let json = r#"{"execution_mode":"profile","match":{"kind":"call"}}"#;
    assert_eq!(
        CodeQuery::from_source(rql).unwrap().to_canonical_json(),
        CodeQuery::from_source(json).unwrap().to_canonical_json()
    );
    assert!(validate_query_source(rql).is_empty());
    assert!(validate_query_source(json).is_empty());

    let nested_rql = "(union (profile (call)) (call))";
    let diagnostic = validate_query_source(nested_rql)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("root query"))
        .expect("nested RQL execution-mode diagnostic");
    assert_eq!(&nested_rql[diagnostic.range], "profile");

    let nested_json = r#"{"union":[{"execution_mode":"profile","match":{"kind":"call"}},{"match":{"kind":"call"}}]}"#;
    let diagnostic = validate_query_source(nested_json)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("root query"))
        .expect("nested JSON execution-mode diagnostic");
    assert_eq!(&nested_json[diagnostic.range], r#""execution_mode""#);

    let duplicated = "(profile (explain (call)))";
    let diagnostic = validate_query_source(duplicated)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("duplicate S-expression field"))
        .expect("mutually exclusive execution-mode diagnostic");
    assert_eq!(&duplicated[diagnostic.range], "profile");

    let invalid_json = r#"{"execution_mode":"profil","match":{"kind":"call"}}"#;
    let diagnostic = validate_query_source(invalid_json)
        .into_iter()
        .find(|diagnostic| diagnostic.code == "invalid-execution-mode")
        .expect("invalid execution mode diagnostic");
    assert_eq!(&invalid_json[diagnostic.range.clone()], r#""profil""#);
    assert_eq!(
        diagnostic.fix,
        Some(QuerySourceFix {
            title: "Replace with `profile`".to_string(),
            edit: QuerySourceEdit::Replace {
                new_text: r#""profile""#.to_string(),
            },
        })
    );

    let rql_help = query_source_help_at(rql, rql.find("profile").unwrap()).unwrap();
    assert_eq!(&rql[rql_help.range], "profile");
    assert!(rql_help.description.contains("operator timing"));
    let value_offset = json.find("profile").unwrap();
    let json_help = query_source_help_at(json, value_offset).unwrap();
    assert_eq!(&json[json_help.range], r#""profile""#);
    assert!(json_help.description.contains("operator-level"));
}

#[test]
fn declaration_bounded_containment_has_shared_help_and_version_ranges() {
    let rql = "(inside-decl (loop) (call :callee (name \"open\")))";
    assert!(validate_query_source(rql).is_empty());
    let help =
        query_source_help_at(rql, rql.find("inside-decl").unwrap()).expect("inside-decl help");
    assert_eq!(&rql[help.range], "inside-decl");
    assert!(help.description.contains("callable declaration"));

    let json = r#"{"schema_version":4,"match":{"kind":"call"},"inside_decl":{"kind":"loop"}}"#;
    let diagnostic = validate_query_source(json)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("requires schema version 5"))
        .expect("version diagnostic");
    assert_eq!(&json[diagnostic.range], r#""inside_decl""#);
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
fn help_covers_forms_properties_roles_kinds_and_values() {
    let source = "(result-detail full (call :callee (name \"run\")))";
    for (token, expected_range) in [
        ("result-detail", "result-detail"),
        ("full", "full"),
        ("call", "call"),
        ("callee", ":callee"),
        ("name", "name"),
    ] {
        let offset = source.find(token).unwrap();
        let help =
            query_source_help_at(source, offset).unwrap_or_else(|| panic!("no help for {token}"));
        assert!(!help.description.is_empty());
        assert_eq!(&source[help.range], expected_range);
    }
    assert!(query_source_help_at(source, source.find("run").unwrap()).is_none());
}

#[test]
fn typed_pipeline_help_and_json_diagnostics_use_shared_schema() {
    let rql = "(file-of (enclosing-decl (call)))";
    for token in ["file-of", "enclosing-decl"] {
        let offset = rql.find(token).unwrap();
        let help =
            query_source_help_at(rql, offset).unwrap_or_else(|| panic!("no help for {token}"));
        assert_eq!(&rql[help.range], token);
        assert!(!help.description.is_empty());
    }
    let file_of_help = query_source_help_at(rql, rql.find("file-of").unwrap()).unwrap();
    assert!(file_of_help.description.contains("reference site"));
    assert!(file_of_help.description.contains("receiver analyses"));
    assert!(validate_query_source(rql).is_empty());

    let json = r#"{"schema_version":2,"match":{"kind":"call"},"steps":[{"op":"file_of"}]}"#;
    for token in ["steps", "op", "file_of"] {
        let offset = json.find(token).unwrap();
        let help =
            query_source_help_at(json, offset).unwrap_or_else(|| panic!("no help for {token}"));
        assert!(!help.description.is_empty());
    }
    let file_of_help = query_source_help_at(json, json.find("file_of").unwrap()).unwrap();
    assert!(file_of_help.description.contains("reference sites"));
    assert!(file_of_help.description.contains("receiver analyses"));
    assert!(
        crate::analyzer::structural::query::schema::QueryStepOp::FileOf
            .signature()
            .contains("reference_site")
    );
    assert!(validate_query_source(json).is_empty());

    let invalid = r#"{"schema_version":2,"match":{"kind":"call"},"steps":[{"op":"imports_of"}]}"#;
    let diagnostic = validate_query_source(invalid).pop().expect("diagnostic");
    assert_eq!(diagnostic.code, "invalid-query");
    assert_eq!(&invalid[diagnostic.range], r#"{"op":"imports_of"}"#);
    assert!(diagnostic.message.contains("requires file"));

    let version_two =
        r#"{"schema_version":2,"match":{"kind":"function"},"steps":[{"op":"procedure_of"}]}"#;
    let diagnostic = validate_query_source(version_two)
        .pop()
        .expect("diagnostic");
    assert_eq!(diagnostic.code, "invalid-query");
    assert_eq!(&version_two[diagnostic.range], r#""procedure_of""#);
    assert!(diagnostic.message.contains("requires schema version 3"));
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

    let invalid = r#"{"match":{"kind":"class"},"steps":[{"op":"enclosing_decl"},{"op":"supertypes","depth":0}]}"#;
    let diagnostics = validate_query_source(invalid);
    assert!(diagnostics.iter().any(|diagnostic| {
        &invalid[diagnostic.range.clone()] == "0" && diagnostic.message.contains("positive integer")
    }));

    let conflicting = r#"{"match":{"kind":"class"},"steps":[{"op":"enclosing_decl"},{"op":"supertypes","depth":2,"transitive":true}]}"#;
    let diagnostics = validate_query_source(conflicting);
    assert!(diagnostics.iter().any(|diagnostic| {
        &conflicting[diagnostic.range.clone()] == "true"
            && diagnostic.message.contains("mutually exclusive")
    }));
}

#[test]
fn typestate_step_help_and_diagnostics_are_range_precise() {
    let rql = "(witness :max-steps 8 :max-bytes 2048 (typestate :protocol-ref test:lifecycle (procedure-of (function))))";
    for token in [
        "witness",
        ":max-steps",
        ":max-bytes",
        "typestate",
        ":protocol-ref",
    ] {
        let offset = rql.find(token).unwrap();
        let help = query_source_help_at(rql, offset)
            .unwrap_or_else(|| panic!("no typestate help for {token}"));
        assert_eq!(&rql[help.range], token);
        assert!(!help.description.is_empty());
    }
    assert!(validate_query_source(rql).is_empty());

    let json = r#"{"match":{"kind":"function"},"steps":[{"op":"procedure_of"},{"op":"typestate","protocol_ref":"test:lifecycle"},{"op":"witness","max_steps":8,"max_bytes":2048}]}"#;
    for token in [
        "typestate",
        "protocol_ref",
        "witness",
        "max_steps",
        "max_bytes",
    ] {
        let offset = json.find(token).unwrap();
        let help = query_source_help_at(json, offset)
            .unwrap_or_else(|| panic!("no JSON typestate help for {token}"));
        assert!(!help.description.is_empty());
    }
    assert!(validate_query_source(json).is_empty());

    let version_three = r#"{"schema_version":3,"match":{"kind":"function"},"steps":[{"op":"procedure_of"},{"op":"typestate","protocol_ref":"test:lifecycle"}]}"#;
    let diagnostic = validate_query_source(version_three)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("requires schema version 4"))
        .expect("schema-version diagnostic");
    assert_eq!(&version_three[diagnostic.range], r#""typestate""#);

    let invalid_ref = r#"{"match":{"kind":"function"},"steps":[{"op":"procedure_of"},{"op":"typestate","protocol_ref":"missing-separator"}]}"#;
    let diagnostic = validate_query_source(invalid_ref)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("namespace:name"))
        .expect("protocol-ref diagnostic");
    assert_eq!(&invalid_ref[diagnostic.range], r#""missing-separator""#);
}

#[test]
fn value_flow_help_and_diagnostics_are_range_precise() {
    let rql = "(witness :max-steps 8 (value-flow :plan-ref test:flow (procedure-of (function))))";
    for token in ["witness", "value-flow", ":plan-ref"] {
        let offset = rql.find(token).unwrap();
        let help = query_source_help_at(rql, offset)
            .unwrap_or_else(|| panic!("no value-flow help for {token}"));
        assert_eq!(&rql[help.range], token);
        assert!(!help.description.is_empty());
    }
    assert!(validate_query_source(rql).is_empty());

    let json = r#"{"match":{"kind":"function"},"steps":[{"op":"procedure_of"},{"op":"value_flow","plan_ref":"test:flow"},{"op":"witness","max_steps":8}]}"#;
    for token in ["value_flow", "plan_ref", "witness", "max_steps"] {
        let offset = json.find(token).unwrap();
        let help = query_source_help_at(json, offset)
            .unwrap_or_else(|| panic!("no JSON value-flow help for {token}"));
        assert!(!help.description.is_empty());
    }
    assert!(validate_query_source(json).is_empty());

    let version_five = r#"{"schema_version":5,"match":{"kind":"function"},"steps":[{"op":"procedure_of"},{"op":"value_flow","plan_ref":"test:flow"}]}"#;
    let diagnostic = validate_query_source(version_five)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("requires schema version 6"))
        .expect("schema-version diagnostic");
    assert_eq!(&version_five[diagnostic.range], r#""value_flow""#);

    let invalid_ref = r#"{"match":{"kind":"function"},"steps":[{"op":"procedure_of"},{"op":"value_flow","plan_ref":"missing-separator"}]}"#;
    let diagnostic = validate_query_source(invalid_ref)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("namespace:name"))
        .expect("plan-ref diagnostic");
    assert_eq!(&invalid_ref[diagnostic.range], r#""missing-separator""#);
}

#[test]
fn taint_help_and_diagnostics_are_range_precise() {
    let rql = "(taint :taint-ref test:flow (procedure-of (function)))";
    for token in ["taint", ":taint-ref"] {
        let offset = rql.find(token).unwrap();
        let help = query_source_help_at(rql, offset)
            .unwrap_or_else(|| panic!("no taint help for {token}"));
        assert_eq!(&rql[help.range], token);
        assert!(!help.description.is_empty());
    }
    assert!(validate_query_source(rql).is_empty());

    let json = r#"{"schema_version":7,"match":{"kind":"function"},"steps":[{"op":"procedure_of"},{"op":"taint","taint_ref":"test:flow"}]}"#;
    for token in ["taint", "taint_ref"] {
        let offset = json.find(token).unwrap();
        let help = query_source_help_at(json, offset)
            .unwrap_or_else(|| panic!("no JSON taint help for {token}"));
        assert!(!help.description.is_empty());
    }
    assert!(validate_query_source(json).is_empty());

    let version_six = r#"{"schema_version":6,"match":{"kind":"function"},"steps":[{"op":"procedure_of"},{"op":"taint","taint_ref":"test:flow"}]}"#;
    let diagnostic = validate_query_source(version_six)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("requires schema version 7"))
        .expect("schema-version diagnostic");
    assert_eq!(&version_six[diagnostic.range], r#""taint""#);

    let invalid_ref = r#"{"match":{"kind":"function"},"steps":[{"op":"procedure_of"},{"op":"taint","taint_ref":"missing-separator"}]}"#;
    let diagnostic = validate_query_source(invalid_ref)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("namespace:name"))
        .expect("taint-ref diagnostic");
    assert_eq!(&invalid_ref[diagnostic.range], r#""missing-separator""#);
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

    let json = r#"{"union":[{"match":{"kind":"class"},"steps":[{"op":"enclosing_decl"}]},{"match":{"kind":"class"},"steps":[{"op":"file_of"}]}]}"#;
    let diagnostic = validate_query_source(json)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("first branch produces"))
        .expect("typed branch diagnostic");
    assert_eq!(
        &json[diagnostic.range],
        r#"{"match":{"kind":"class"},"steps":[{"op":"file_of"}]}"#
    );

    let too_short = "(except (class))";
    let diagnostic = validate_query_source(too_short)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("at least two"))
        .expect("branch-count diagnostic");
    assert_eq!(&too_short[diagnostic.range], "(class)");
}

#[test]
fn parameter_name_constraints_are_shared_by_json_and_rql_validation() {
    let oversized = "x".repeat(MAX_KWARG_NAME_LENGTH + 1);
    let rql = format!(
        "(call-input :parameter-name \"{oversized}\" (call-sites-to (enclosing-decl (method))))"
    );
    let json = format!(
        r#"{{"match":{{"kind":"method"}},"steps":[{{"op":"enclosing_decl"}},{{"op":"call_sites_to"}},{{"op":"call_input","parameter_name":"{oversized}"}}]}}"#
    );

    for (source, expected) in [
        (rql.as_str(), format!("\"{oversized}\"")),
        (json.as_str(), format!("\"{oversized}\"")),
    ] {
        let diagnostics = validate_query_source(source);
        assert!(diagnostics.iter().any(|diagnostic| {
            source[diagnostic.range.clone()] == expected
                && diagnostic.message.contains("parameter name")
        }));
    }

    for source in [
        r#"(call-input :parameter-name "" (call-sites-to (enclosing-decl (method))))"#,
        r#"{"match":{"kind":"method"},"steps":[{"op":"enclosing_decl"},{"op":"call_sites_to"},{"op":"call_input","parameter_name":""}]}"#,
    ] {
        assert!(validate_query_source(source).iter().any(|diagnostic| {
            &source[diagnostic.range.clone()] == "\"\""
                && diagnostic.message.contains("parameter name")
        }));
    }
}

#[test]
fn receiver_step_help_and_capture_diagnostics_are_range_precise() {
    let rql = "(points-to :capture service (call :receiver (capture \"service\")))";
    for token in ["points-to", ":capture"] {
        let offset = rql.find(token).unwrap();
        let help = query_source_help_at(rql, offset)
            .unwrap_or_else(|| panic!("no receiver traversal help for {token}"));
        assert_eq!(&rql[help.range], token);
        assert!(!help.description.is_empty());
    }
    assert!(validate_query_source(rql).is_empty());

    let json = r#"{"match":{"kind":"call","receiver":{"capture":"service"}},"steps":[{"op":"points_to","capture":"service"}]}"#;
    for token in ["points_to", "capture"] {
        let offset = json.rfind(token).unwrap();
        let help = query_source_help_at(json, offset)
            .unwrap_or_else(|| panic!("no JSON receiver traversal help for {token}"));
        assert!(!help.description.is_empty());
    }
    assert!(validate_query_source(json).is_empty());

    let missing = r#"{"match":{"kind":"call"},"steps":[{"op":"points_to","capture":"service"}]}"#;
    let diagnostic = validate_query_source(missing).pop().expect("diagnostic");
    assert_eq!(diagnostic.code, "invalid-query");
    assert_eq!(&missing[diagnostic.range], r#""service""#);
    assert!(
        diagnostic
            .message
            .contains("not declared by a positive pattern")
    );

    let wrong_domain = r#"{"match":{"kind":"class","capture":"service"},"steps":[{"op":"enclosing_decl"},{"op":"references_of"},{"op":"points_to","capture":"service"}]}"#;
    let diagnostic = validate_query_source(wrong_domain)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("capture is allowed only"))
        .expect("domain diagnostic");
    assert_eq!(&wrong_domain[diagnostic.range], r#""service""#);
}

#[test]
fn reference_step_help_and_option_diagnostics_are_range_precise() {
    let rql = "(references-of :surface external-usages :reference-kinds [field-write] :proof proven (enclosing-decl (class)))";
    for token in ["references-of", ":surface", ":reference-kinds", ":proof"] {
        let offset = rql.find(token).unwrap();
        let help = query_source_help_at(rql, offset)
            .unwrap_or_else(|| panic!("no reference traversal help for {token}"));
        assert_eq!(&rql[help.range], token);
        assert!(!help.description.is_empty());
    }
    assert!(validate_query_source(rql).is_empty());

    for (source, token) in [
        (
            r#"{"match":{"kind":"class"},"steps":[{"op":"enclosing_decl"},{"op":"references_of","reference_kinds":["field_guess"]}]}"#,
            "\"field_guess\"",
        ),
        (
            r#"{"match":{"kind":"class"},"steps":[{"op":"enclosing_decl"},{"op":"used_by","proof":"maybe"}]}"#,
            "\"maybe\"",
        ),
        (
            r#"{"match":{"kind":"class"},"steps":[{"op":"enclosing_decl"},{"op":"uses","surface":"all"}]}"#,
            "\"all\"",
        ),
    ] {
        let diagnostics = validate_query_source(source);
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| &source[diagnostic.range.clone()] == token),
            "{source}: {diagnostics:#?}"
        );
    }
}

#[test]
fn byte_ranges_preserve_utf8_boundaries() {
    let source = "(call :unknown-λ 1)";
    let diagnostic = validate_query_source(source).pop().expect("diagnostic");
    assert_eq!(&source[diagnostic.range], ":unknown-λ");
}

#[test]
fn spelling_fixes_use_unique_canonical_schema_candidates() {
    let cases = [
        (
            "(resut-detail full (call))",
            "resut-detail",
            "result-detail",
        ),
        ("(call :captur \"item\")", ":captur", ":capture"),
        ("(call :calle (call))", ":calle", ":callee"),
        ("(cal)", "cal", "call"),
        ("(language ruts (call))", "ruts", "rust"),
        ("(language .rss (call))", ".rss", "rust"),
        ("(result-detail ful (call))", "ful", "full"),
        ("(profle (call))", "profle", "profile"),
        (r#"{"matc":{"kind":"call"}}"#, "\"matc\"", "\"match\""),
        (r#"{"match":{"kind":"cal"}}"#, "\"cal\"", "\"call\""),
        (
            r#"{"match":{"kind":"call","calle":{"kind":"call"}}}"#,
            "\"calle\"",
            "\"callee\"",
        ),
        (
            r#"{"match":{"name":{"regx":"item"}}}"#,
            "\"regx\"",
            "\"regex\"",
        ),
        (
            r#"{"languages":["ruts"],"match":{"kind":"call"}}"#,
            "\"ruts\"",
            "\"rust\"",
        ),
        (
            r#"{"result_detail":"ful","match":{"kind":"call"}}"#,
            "\"ful\"",
            "\"full\"",
        ),
        (
            r#"{"execution_mode":"profil","match":{"kind":"call"}}"#,
            "\"profil\"",
            "\"profile\"",
        ),
        (
            r#"{"steps":[{"op":"fileof"}],"match":{"kind":"call"}}"#,
            "\"fileof\"",
            "\"file_of\"",
        ),
    ];

    for (source, token, replacement) in cases {
        let diagnostic = validate_query_source(source)
            .into_iter()
            .find(|diagnostic| &source[diagnostic.range.clone()] == token)
            .unwrap_or_else(|| panic!("missing diagnostic for {token} in {source}"));
        assert!(diagnostic.message.contains("Did you mean"));
        assert_eq!(&source[diagnostic.range], token);
        assert_eq!(
            diagnostic.fix,
            Some(QuerySourceFix {
                title: format!(
                    "Replace with `{}`",
                    replacement.trim_matches('"').trim_start_matches(':')
                ),
                edit: QuerySourceEdit::Replace {
                    new_text: replacement.to_string(),
                },
            })
        );
    }

    let ambiguous = "(language .rts (call))";
    let diagnostic = validate_query_source(ambiguous)
        .into_iter()
        .find(|diagnostic| &ambiguous[diagnostic.range.clone()] == ".rts")
        .expect("language diagnostic");
    assert!(!diagnostic.message.contains("Did you mean"));
    assert_eq!(diagnostic.fix, None);
}

#[test]
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
fn safe_shape_fixes_wrap_only_recognizable_single_values() {
    let supported = [
        (
            r#"{"where":"src/**/*.rs","match":{"kind":"call"}}"#,
            "\"src/**/*.rs\"",
        ),
        (
            r#"{"languages":"rust","match":{"kind":"call"}}"#,
            "\"rust\"",
        ),
        (
            r#"{"steps":{"op":"file_of"},"match":{"kind":"call"}}"#,
            r#"{"op":"file_of"}"#,
        ),
        (
            r#"{"match":{"kind":"call","args":{"kind":"call"}}}"#,
            r#"{"kind":"call"}"#,
        ),
        ("(call :args (call))", "(call)"),
    ];
    for (source, token) in supported {
        let diagnostic = validate_query_source(source)
            .into_iter()
            .find(|diagnostic| &source[diagnostic.range.clone()] == token)
            .unwrap_or_else(|| panic!("missing wrapping diagnostic for {source}"));
        assert_eq!(
            diagnostic.fix,
            Some(QuerySourceFix {
                title: if source.starts_with('(') {
                    "Wrap in a pattern list".to_string()
                } else {
                    "Wrap in an array".to_string()
                },
                edit: QuerySourceEdit::Surround {
                    prefix: "[".to_string(),
                    suffix: "]".to_string(),
                },
            })
        );
    }

    for source in [
        r#"{"where":1,"match":{"kind":"call"}}"#,
        r#"{"match":{"kind":"call","args":"item"}}"#,
        r#"{"match":{"kind":"call","kwargs":[]}}"#,
        r#"{"match":{"kind":"call","args":{"wat":{"kind":"call"}}}}"#,
        r#"{"steps":{"wat":"file_of"},"match":{"kind":"call"}}"#,
        r#"{"steps":{"op":"wat"},"match":{"kind":"call"}}"#,
        "(call :args \"item\")",
        "(call :args (call :wat 1))",
    ] {
        assert!(
            validate_query_source(source)
                .into_iter()
                .all(|diagnostic| diagnostic.fix.is_none())
        );
    }
}

/// Occurrence filters are validated against the registries in both
/// frontends, and hover reaches every option keyword.
#[test]
fn occurrence_filter_help_and_value_diagnostics_are_range_precise() {
    let rql =
        "(occurrences-in :class reference :role [member_position] :namespace value (function))";
    for token in ["occurrences-in", ":class", ":role", ":namespace"] {
        let offset = rql.find(token).unwrap();
        let help = query_source_help_at(rql, offset)
            .unwrap_or_else(|| panic!("no occurrence help for {token}"));
        assert_eq!(&rql[help.range], token);
        assert!(!help.description.is_empty());
    }
    assert!(validate_query_source(rql).is_empty(), "{rql}");

    let seed = "(language \"rust\" (occurrences :role binder))";
    assert!(
        validate_query_source(seed).is_empty(),
        "{seed}: {:#?}",
        validate_query_source(seed)
    );

    for (source, token, code) in [
        ("(occurrences :role binderr)", "binderr", "unknown-value"),
        ("(occurrences :kind function)", ":kind", "unknown-property"),
        (
            "(occurrences :role binder :role declaration_name)",
            ":role",
            "duplicate-property",
        ),
        (
            r#"{"occurrences":{"role":["binderr"]}}"#,
            "\"binderr\"",
            "unknown-value",
        ),
        (
            r#"{"occurrences":{"kind":["function"]}}"#,
            "\"kind\"",
            "unknown-property",
        ),
    ] {
        let diagnostic = validate_query_source(source)
            .into_iter()
            .find(|diagnostic| diagnostic.code == code)
            .unwrap_or_else(|| panic!("no {code} diagnostic for {source}"));
        assert_eq!(&source[diagnostic.range.clone()], token, "{source}");
    }
}

/// Materialization filters are validated against the registries in both
/// frontends, and hover reaches every option keyword (#1476).
#[test]
fn materialization_filter_help_and_value_diagnostics_are_range_precise() {
    let rql = "(declaration-state-of :origin generated :declaration-only true \
               :config-gated false (enclosing-decl (function)))";
    for token in [
        "declaration-state-of",
        ":origin",
        ":declaration-only",
        ":config-gated",
    ] {
        let offset = rql.find(token).unwrap();
        let help = query_source_help_at(rql, offset)
            .unwrap_or_else(|| panic!("no materialization help for {token}"));
        assert_eq!(&rql[help.range], token);
        assert!(!help.description.is_empty());
    }
    assert!(
        validate_query_source(rql).is_empty(),
        "{rql}: {:#?}",
        validate_query_source(rql)
    );

    let sites = "(generated-by (generates (generation-sites :kind accessor_macro \
                 :input literal)))";
    for token in [
        "generation-sites",
        ":kind",
        ":input",
        "generates",
        "generated-by",
    ] {
        let offset = sites.find(token).unwrap();
        let help = query_source_help_at(sites, offset)
            .unwrap_or_else(|| panic!("no materialization help for {token}"));
        assert_eq!(&sites[help.range], token);
        assert!(!help.description.is_empty());
    }
    assert!(
        validate_query_source(sites).is_empty(),
        "{sites}: {:#?}",
        validate_query_source(sites)
    );

    let exports = "(export-target (exports :form default_anonymous :name \"default\"))";
    assert!(
        validate_query_source(exports).is_empty(),
        "{exports}: {:#?}",
        validate_query_source(exports)
    );

    for (source, token, code) in [
        (
            "(generation-sites :kind accessor_macroo)",
            "accessor_macroo",
            "unknown-value",
        ),
        (
            "(generation-sites :form named)",
            ":form",
            "unknown-property",
        ),
        (
            "(exports :form default_anonymous :form named)",
            ":form",
            "duplicate-property",
        ),
        (
            "(declaration-state-of :declaration-only maybe (class))",
            "maybe",
            "unknown-value",
        ),
        (
            r#"{"generation_sites":{"kind":["accessor_macroo"]}}"#,
            "\"accessor_macroo\"",
            "unknown-value",
        ),
        (
            r#"{"exports":{"input":["literal"]}}"#,
            "\"input\"",
            "unknown-property",
        ),
    ] {
        let diagnostic = validate_query_source(source)
            .into_iter()
            .find(|diagnostic| diagnostic.code == code)
            .unwrap_or_else(|| panic!("no {code} diagnostic for {source}"));
        assert_eq!(&source[diagnostic.range.clone()], token, "{source}");
    }
}

#[test]
fn accepted_language_aliases_do_not_produce_diagnostics() {
    for source in [
        "(language c++ (call))",
        "(language c# (call))",
        r#"{"languages":["c++","c#"],"match":{"kind":"call"}}"#,
    ] {
        assert!(
            validate_query_source(source).is_empty(),
            "accepted language alias should validate: {source}"
        );
    }
}
