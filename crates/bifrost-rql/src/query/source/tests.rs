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
    use brokk_bifrost_core::schema_version::{SchemaVersionDescriptor, SchemaVersionRegistry};

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
        .find(|diagnostic| diagnostic.code == "unsupported-schema-version")
        .expect("version diagnostic");
    assert_eq!(&json[diagnostic.range], "4");
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
fn boolean_value_help_suggestions_and_validation_ranges_are_schema_driven() {
    for (source, token) in [
        ("(boolean_literal :boolean-value true)", ":boolean-value"),
        ("(boolean_literal (boolean-value false))", "boolean-value"),
        (
            r#"{"match":{"kind":"boolean_literal","boolean_value":true}}"#,
            r#""boolean_value""#,
        ),
    ] {
        assert!(
            validate_query_source(source).is_empty(),
            "{source}: {:#?}",
            validate_query_source(source)
        );
        let offset = source.find(token).expect("help token");
        let help = query_source_help_at(source, offset).expect("boolean value help");
        assert_eq!(&source[help.range], token);
        assert!(help.description.contains("language-neutral"));
    }

    for (source, invalid) in [
        ("(boolean_literal :boolean-value 1)", "1"),
        ("(boolean_literal (boolean-value \"true\"))", r#""true""#),
        (
            r#"{"match":{"kind":"boolean_literal","boolean_value":"true"}}"#,
            r#""true""#,
        ),
    ] {
        let diagnostic = validate_query_source(source)
            .into_iter()
            .find(|diagnostic| diagnostic.code == "wrong-value-shape")
            .unwrap_or_else(|| panic!("missing boolean shape diagnostic for {source}"));
        assert_eq!(&source[diagnostic.range], invalid);
    }

    for source in [
        "(boolean_literal :boolean-vlue true)",
        r#"{"match":{"kind":"boolean_literal","boolean_vlue":true}}"#,
    ] {
        let diagnostic = validate_query_source(source)
            .into_iter()
            .find(|diagnostic| diagnostic.message.contains("Did you mean"))
            .unwrap_or_else(|| panic!("missing boolean_value suggestion for {source}"));
        assert!(diagnostic.message.contains("boolean"));
    }
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

    let json = r#"{"schema_version":1,"match":{"kind":"call"},"steps":[{"op":"file_of"}]}"#;
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
        crate::schema::QueryStepOp::FileOf
            .signature()
            .contains("reference_site")
    );
    assert!(validate_query_source(json).is_empty());

    let invalid = r#"{"schema_version":1,"match":{"kind":"call"},"steps":[{"op":"imports_of"}]}"#;
    let diagnostic = validate_query_source(invalid).pop().expect("diagnostic");
    assert_eq!(diagnostic.code, "invalid-query");
    assert_eq!(&invalid[diagnostic.range], r#"{"op":"imports_of"}"#);
    assert!(diagnostic.message.contains("requires file"));
}

#[test]
fn decorator_binding_identity_options_have_shared_help_and_validation() {
    let rql = r#"(decorator-bindings :module "@nestjs/common" :imported-name Query (parameter))"#;
    assert!(validate_query_source(rql).is_empty(), "{rql:?}");
    for token in [":module", ":imported-name"] {
        let help = query_source_help_at(rql, rql.find(token).unwrap())
            .unwrap_or_else(|| panic!("no help for {token}"));
        assert_eq!(&rql[help.range], token);
        assert!(!help.description.is_empty());
    }

    let json = r#"{"match":{"kind":"parameter"},"steps":[{"op":"decorator_bindings","module":"@nestjs/common","imported_name":"Query"}]}"#;
    assert!(validate_query_source(json).is_empty(), "{json:?}");
    for token in ["module", "imported_name"] {
        let help = query_source_help_at(json, json.find(token).unwrap())
            .unwrap_or_else(|| panic!("no help for {token}"));
        assert!(!help.description.is_empty());
    }

    let invalid_rql = r#"(decorator-bindings :module (wrong) (parameter))"#;
    let diagnostic = validate_query_source(invalid_rql)
        .into_iter()
        .find(|diagnostic| diagnostic.code == "wrong-value-shape")
        .expect("invalid module value should be diagnosed");
    assert_eq!(&invalid_rql[diagnostic.range], "(wrong)");

    let invalid_json =
        r#"{"match":{"kind":"parameter"},"steps":[{"op":"decorator_bindings","module":7}]}"#;
    let diagnostic = validate_query_source(invalid_json)
        .into_iter()
        .find(|diagnostic| diagnostic.code == "wrong-value-shape")
        .expect("invalid module value should be diagnosed");
    assert_eq!(&invalid_json[diagnostic.range], "7");
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

    let invalid_ref = r#"{"match":{"kind":"function"},"steps":[{"op":"procedure_of"},{"op":"typestate","protocol_ref":"missing-separator"}]}"#;
    let diagnostic = validate_query_source(invalid_ref)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("namespace:name"))
        .expect("protocol-ref diagnostic");
    assert_eq!(&invalid_ref[diagnostic.range], r#""missing-separator""#);
}

/// Hover help and validation ranges for the flow-state vocabulary (#1480), in
/// both frontends. Every option name and every constrained value is checked at
/// its own range, so an editor cannot underline the wrong token.
#[test]
fn flow_state_help_and_diagnostics_are_range_precise() {
    let rql = "(flow-relations-of :relation [reaching] :certainty [exact] (state-events-of :class [establish] :subject [binding] (procedure-of (function))))";
    for token in [
        "flow-relations-of",
        ":relation",
        ":certainty",
        "state-events-of",
        ":class",
        ":subject",
    ] {
        let offset = rql.find(token).unwrap();
        let help = query_source_help_at(rql, offset)
            .unwrap_or_else(|| panic!("no flow-state help for {token}"));
        assert_eq!(&rql[help.range], token);
        assert!(!help.description.is_empty());
    }
    assert!(validate_query_source(rql).is_empty(), "{rql}");

    for projection in ["(flow-source ", "(flow-target "] {
        let source = format!("{projection}(flow-relations-of (procedure-of (function))))");
        let offset = source
            .find(projection.trim_start_matches('(').trim())
            .unwrap();
        let help = query_source_help_at(&source, offset).expect("flow projection help");
        assert!(!help.description.is_empty());
        assert!(validate_query_source(&source).is_empty(), "{source}");
    }

    let json = r#"{"match":{"kind":"function"},"steps":[{"op":"procedure_of"},{"op":"state_events_of","event_class":["read"],"subject":["property"]},{"op":"flow_relations_of","flow_relation":["dominates"],"certainty":["may"]}]}"#;
    for token in [
        "state_events_of",
        "event_class",
        "subject",
        "flow_relations_of",
        "flow_relation",
        "certainty",
    ] {
        let offset = json.find(token).unwrap();
        let help = query_source_help_at(json, offset)
            .unwrap_or_else(|| panic!("no JSON flow-state help for {token}"));
        assert!(!help.description.is_empty());
    }
    assert!(validate_query_source(json).is_empty(), "{json}");
}

/// A constrained value outside the registry is reported on the value's own
/// range, and the message names the allowed set.
#[test]
fn flow_state_constrained_values_report_their_allowed_set() {
    let rql = "(state-events-of :class [obliterate] (procedure-of (function)))";
    let diagnostic = validate_query_source(rql)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("obliterate"))
        .expect("state-event class diagnostic");
    assert_eq!(&rql[diagnostic.range.clone()], "obliterate");
    for allowed in ["establish", "kill", "read"] {
        assert!(diagnostic.message.contains(allowed), "{diagnostic:?}");
    }

    let rql = "(flow-relations-of :certainty [probably] (procedure-of (function)))";
    let diagnostic = validate_query_source(rql)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("probably"))
        .expect("certainty diagnostic");
    assert_eq!(&rql[diagnostic.range.clone()], "probably");
    assert!(diagnostic.message.contains("exact"), "{diagnostic:?}");
    assert!(diagnostic.message.contains("may"), "{diagnostic:?}");

    let rql = "(state-events-of :relation [reaching] (procedure-of (function)))";
    let diagnostic = validate_query_source(rql)
        .into_iter()
        .find(|diagnostic| diagnostic.code == "unknown-property")
        .expect("unknown option diagnostic");
    assert_eq!(&rql[diagnostic.range.clone()], ":relation");

    let json = r#"{"match":{"kind":"function"},"steps":[{"op":"procedure_of"},{"op":"flow_relations_of","flow_relation":["adjacent"]}]}"#;
    let diagnostic = validate_query_source(json)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("adjacent"))
        .expect("JSON flow-relation diagnostic");
    assert_eq!(&json[diagnostic.range.clone()], "\"adjacent\"");
}

/// Hover help and validation ranges for the control-relation vocabulary
/// (#2443), in both frontends. Every option name and every constrained value is
/// checked at its own range, so an editor cannot underline the wrong token.
#[test]
fn control_relation_help_and_diagnostics_are_range_precise() {
    let rql = "(control-relations :relation [dominates] \
                :exit-partition [normal-and-exceptional] (procedure-of (function)))";
    for token in ["control-relations", ":relation", ":exit-partition"] {
        let offset = rql.find(token).unwrap();
        let help = query_source_help_at(rql, offset)
            .unwrap_or_else(|| panic!("no control-relation help for {token}"));
        assert_eq!(&rql[help.range], token);
        assert!(!help.description.is_empty());
    }
    assert!(validate_query_source(rql).is_empty(), "{rql}");

    let json = r#"{"match":{"kind":"function"},"steps":[{"op":"procedure_of"},{"op":"control_relations","control_relation":["in_loop"],"exit_partition":["normal_and_exceptional"]}]}"#;
    for token in ["control_relations", "control_relation", "exit_partition"] {
        let offset = json.find(token).unwrap();
        let help = query_source_help_at(json, offset)
            .unwrap_or_else(|| panic!("no JSON control-relation help for {token}"));
        assert!(!help.description.is_empty());
    }
    assert!(validate_query_source(json).is_empty(), "{json}");
}

/// Hover help and validation ranges for the guard step (#2443 slice 2), in
/// both frontends. The step has no option axis, so one borrowed from a sibling
/// step is reported on its own token rather than ignored.
#[test]
fn guard_help_and_diagnostics_are_range_precise() {
    let rql = "(guards-of (procedure-of (function)))";
    let offset = rql.find("guards-of").unwrap();
    let help = query_source_help_at(rql, offset).expect("guard help");
    assert_eq!(&rql[help.range], "guards-of");
    assert!(
        help.description.contains("guard_facts"),
        "{:?}",
        help.description
    );
    assert!(validate_query_source(rql).is_empty(), "{rql}");

    let json =
        r#"{"match":{"kind":"function"},"steps":[{"op":"procedure_of"},{"op":"guards_of"}]}"#;
    let offset = json.find("guards_of").unwrap();
    let help = query_source_help_at(json, offset).expect("JSON guard help");
    assert!(!help.description.is_empty());
    assert!(validate_query_source(json).is_empty(), "{json}");

    let borrowed = "(guards-of :relation [dominates] (procedure-of (function)))";
    let diagnostic = validate_query_source(borrowed)
        .into_iter()
        .find(|diagnostic| diagnostic.code == "wrong-value-shape")
        .expect("a guard step takes no option axis");
    assert!(diagnostic.message.contains("guards-of"), "{diagnostic:?}");
}

/// A constrained value outside the registry is reported on the value's own
/// range, and the message names the allowed set -- including the reserved exit
/// partitions, which are declared values even though no row carries them yet.
#[test]
fn control_relation_constrained_values_report_their_allowed_set() {
    let rql = "(control-relations :relation [precedes] (procedure-of (function)))";
    let diagnostic = validate_query_source(rql)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("precedes"))
        .expect("control-relation diagnostic");
    assert_eq!(&rql[diagnostic.range.clone()], "precedes");
    for allowed in [
        "dominates",
        "postdominates",
        "control_depends_on",
        "reachable",
        "in_loop",
    ] {
        assert!(diagnostic.message.contains(allowed), "{diagnostic:?}");
    }

    let rql = "(control-relations :exit-partition [normal_and_cancellation] \
                (procedure-of (function)))";
    let diagnostic = validate_query_source(rql)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("normal_and_cancellation"))
        .expect("exit-partition diagnostic");
    for allowed in ["normal_and_exceptional", "normal_only", "with_suspension"] {
        assert!(diagnostic.message.contains(allowed), "{diagnostic:?}");
    }

    let rql = "(control-relations :certainty [exact] (procedure-of (function)))";
    let diagnostic = validate_query_source(rql)
        .into_iter()
        .find(|diagnostic| diagnostic.code == "unknown-property")
        .expect("unknown option diagnostic");
    assert_eq!(&rql[diagnostic.range.clone()], ":certainty");
}

/// Hover help and validation ranges for the three project-topology steps
/// (#2448), in both frontends.
///
/// Each step name hovers at its own range with the description the step
/// registry declares, and a well-formed chain reports nothing. The steps carry
/// no option axis at all, so a borrowed one is a shape error naming the step
/// rather than a silently ignored key.
#[test]
fn topology_step_help_and_diagnostics_are_range_precise() {
    let rql = "(topology-edges-of (target-of (file-of (class :name \"Order\"))))";
    for token in ["topology-edges-of", "target-of", "file-of"] {
        let offset = rql.find(token).unwrap();
        let help = query_source_help_at(rql, offset)
            .unwrap_or_else(|| panic!("no topology help for {token}"));
        assert_eq!(&rql[help.range], token);
        assert!(!help.description.is_empty());
    }
    assert!(validate_query_source(rql).is_empty(), "{rql}");

    let source_set = "(source-set-of (file-of (class :name \"Order\")))";
    let offset = source_set.find("source-set-of").unwrap();
    let help = query_source_help_at(source_set, offset).expect("no help for source-set-of");
    assert_eq!(&source_set[help.range], "source-set-of");
    assert!(
        help.description.contains("source set"),
        "{:?}",
        help.description
    );
    assert!(validate_query_source(source_set).is_empty(), "{source_set}");

    let json = r#"{"match":{"kind":"class"},"steps":[{"op":"file_of"},{"op":"target_of"},{"op":"topology_edges_of"}]}"#;
    for token in ["target_of", "topology_edges_of"] {
        let offset = json.find(token).unwrap();
        let help = query_source_help_at(json, offset)
            .unwrap_or_else(|| panic!("no JSON topology help for {token}"));
        assert!(!help.description.is_empty());
    }
    assert!(validate_query_source(json).is_empty(), "{json}");

    let borrowed = "(target-of :scope [compile] (file-of (class)))";
    let diagnostic = validate_query_source(borrowed)
        .into_iter()
        .find(|diagnostic| diagnostic.code == "wrong-value-shape")
        .expect("a topology step takes no option axis");
    assert!(diagnostic.message.contains("target-of"), "{diagnostic:?}");
}

/// Hover help and validation ranges for the bounded rewrite vocabulary
/// (#1480), in both frontends.
#[test]
fn rewrite_path_help_and_diagnostics_are_range_precise() {
    let rql =
        "(rewrite-paths-of :domain [rust-import-alias] :outcome [cycle] (file-of (function)))";
    for token in ["rewrite-paths-of", ":domain", ":outcome"] {
        let offset = rql.find(token).unwrap();
        let help = query_source_help_at(rql, offset)
            .unwrap_or_else(|| panic!("no rewrite-path help for {token}"));
        assert_eq!(&rql[help.range], token);
        assert!(!help.description.is_empty());
    }
    assert!(validate_query_source(rql).is_empty(), "{rql}");

    let json = r#"{"match":{"kind":"function"},"steps":[{"op":"file_of"},{"op":"rewrite_paths_of","domain":["rust_import_alias"],"rewrite_outcome":["converged"]}]}"#;
    for token in ["rewrite_paths_of", "domain", "rewrite_outcome"] {
        let offset = json.find(token).unwrap();
        let help = query_source_help_at(json, offset)
            .unwrap_or_else(|| panic!("no JSON rewrite-path help for {token}"));
        assert!(!help.description.is_empty());
    }
    assert!(validate_query_source(json).is_empty(), "{json}");
}

/// A constrained value outside the registry is reported on the value's own
/// range, and the message names the allowed set.
#[test]
fn rewrite_path_constrained_values_report_their_allowed_set() {
    let rql = "(rewrite-paths-of :outcome [diverged] (file-of (function)))";
    let diagnostic = validate_query_source(rql)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("diverged"))
        .expect("rewrite outcome diagnostic");
    assert_eq!(&rql[diagnostic.range.clone()], "diverged");
    for allowed in ["converged", "cycle", "exceeded_budget"] {
        assert!(diagnostic.message.contains(allowed), "{diagnostic:?}");
    }

    let rql = "(rewrite-paths-of :certainty [exact] (file-of (function)))";
    let diagnostic = validate_query_source(rql)
        .into_iter()
        .find(|diagnostic| diagnostic.code == "unknown-property")
        .expect("unknown option diagnostic");
    assert_eq!(&rql[diagnostic.range.clone()], ":certainty");

    let json = r#"{"match":{"kind":"function"},"steps":[{"op":"file_of"},{"op":"rewrite_paths_of","domain":["ruby_require"]}]}"#;
    let diagnostic = validate_query_source(json)
        .into_iter()
        .find(|diagnostic| diagnostic.message.contains("ruby_require"))
        .expect("JSON rewrite-domain diagnostic");
    assert_eq!(&json[diagnostic.range.clone()], "\"ruby_require\"");
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

    let json = r#"{"schema_version":1,"match":{"kind":"function"},"steps":[{"op":"procedure_of"},{"op":"taint","taint_ref":"test:flow"}]}"#;
    for token in ["taint", "taint_ref"] {
        let offset = json.find(token).unwrap();
        let help = query_source_help_at(json, offset)
            .unwrap_or_else(|| panic!("no JSON taint help for {token}"));
        assert!(!help.description.is_empty());
    }
    assert!(validate_query_source(json).is_empty());

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

/// Result-contract projection, aggregate validation, and typed operation uses
/// hover from the same registry that parses and validates both RQL spellings
/// and JSON operations.
#[test]
fn result_contract_use_form_help_and_diagnostics_are_range_precise() {
    for rql in [
        "(result-contract-uses (call-result-contracts (call-shape (call :callee \"Open\"))))",
        "(result-contract-operation-uses (call-result-contracts (call-shape (call :callee \"Open\"))))",
    ] {
        for token in [
            if rql.starts_with("(result-contract-operation-uses") {
                "result-contract-operation-uses"
            } else {
                "result-contract-uses"
            },
            "call-result-contracts",
        ] {
            let offset = rql.find(token).unwrap();
            let help = query_source_help_at(rql, offset)
                .unwrap_or_else(|| panic!("no result-contract help for {token}"));
            assert_eq!(&rql[help.range], token);
            assert!(!help.description.is_empty());
            if token == "result-contract-operation-uses" {
                assert!(help.description.contains("positional call arguments"));
                assert!(help.description.contains("parameter_ordinal"));
            }
        }
        assert!(
            validate_query_source(rql).is_empty(),
            "{rql}: {:#?}",
            validate_query_source(rql)
        );
    }

    let underscored = "(result_contract_operation_uses (call_result_contracts (call_shape (call :callee \"Open\"))))";
    assert!(
        validate_query_source(underscored).is_empty(),
        "{underscored}: {:#?}",
        validate_query_source(underscored)
    );

    for operation in ["result_contract_uses", "result_contract_operation_uses"] {
        let json = format!(
            r#"{{"match":{{"kind":"call"}},"steps":[{{"op":"call_shape"}},{{"op":"call_result_contracts"}},{{"op":"{operation}"}}]}}"#
        );
        let offset = json.find(operation).unwrap();
        let help = query_source_help_at(&json, offset).expect("no JSON result-contract-use help");
        let expected = format!("\"{operation}\"");
        assert_eq!(&json[help.range], expected.as_str());
        assert!(
            validate_query_source(&json).is_empty(),
            "{json}: {:#?}",
            validate_query_source(&json)
        );
    }

    let wrong_upstream = "(result-contract-operation-uses (call-shape (call)))";
    let diagnostic = validate_query_source(wrong_upstream)
        .into_iter()
        .find(|diagnostic| {
            diagnostic.code == "invalid-query"
                && diagnostic.message.contains("requires call_result_contract")
        })
        .expect("typed upstream diagnostic");
    assert_eq!(
        &wrong_upstream[diagnostic.range.clone()],
        "result-contract-operation-uses",
        "{diagnostic:?}"
    );

    let removed_summary =
        "(result-contract-use-summary (call-result-contracts (call-shape (call))))";
    let diagnostic = validate_query_source(removed_summary)
        .into_iter()
        .find(|diagnostic| diagnostic.code == "unknown-form")
        .expect("unknown-form diagnostic");
    assert_eq!(
        &removed_summary[diagnostic.range.clone()],
        "result-contract-use-summary",
        "{diagnostic:?}"
    );
}

#[test]
fn result_contract_failure_use_help_and_diagnostics_are_range_precise() {
    let rql = "(result-contract-failure-uses :provenance [distinct-zero-binding unknown] :consumer [returned-call-argument] (call-result-contracts (call-shape (call :callee \"Open\"))))";
    for token in ["result-contract-failure-uses", ":provenance", ":consumer"] {
        let offset = rql.find(token).unwrap();
        let help = query_source_help_at(rql, offset)
            .unwrap_or_else(|| panic!("no failure-use help for {token}"));
        assert_eq!(&rql[help.range], token);
        assert!(!help.description.is_empty());
    }
    assert!(
        validate_query_source(rql).is_empty(),
        "{rql}: {:#?}",
        validate_query_source(rql)
    );

    let json = r#"{"match":{"kind":"call"},"steps":[{"op":"call_shape"},{"op":"call_result_contracts"},{"op":"result_contract_failure_uses","provenance":["distinct_zero_binding"],"consumer":["returned_call_argument"]}]}"#;
    for token in ["result_contract_failure_uses", "provenance", "consumer"] {
        let offset = json.find(token).unwrap();
        let help = query_source_help_at(json, offset)
            .unwrap_or_else(|| panic!("no JSON failure-use help for {token}"));
        assert!(!help.description.is_empty());
    }
    assert!(
        validate_query_source(json).is_empty(),
        "{json}: {:#?}",
        validate_query_source(json)
    );

    for (source, token, allowed) in [
        (
            "(result-contract-failure-uses :provenance [same-name] (call-result-contracts (call-shape (call))))",
            "same-name",
            &["condition_result", "distinct_zero_binding", "unknown"][..],
        ),
        (
            "(result-contract-failure-uses :consumer [log] (call-result-contracts (call-shape (call))))",
            "log",
            &["return", "returned_call_argument", "call_argument"][..],
        ),
    ] {
        let diagnostic = validate_query_source(source)
            .into_iter()
            .find(|diagnostic| diagnostic.code == "invalid-query-step-option")
            .unwrap_or_else(|| panic!("no constrained-value diagnostic for {source}"));
        assert_eq!(&source[diagnostic.range.clone()], token);
        for label in allowed {
            assert!(diagnostic.message.contains(label), "{diagnostic:?}");
        }
    }

    for (source, token, allowed) in [
        (
            r#"{"match":{"kind":"call"},"steps":[{"op":"call_shape"},{"op":"call_result_contracts"},{"op":"result_contract_failure_uses","provenance":["same_name"]}]}"#,
            r#""same_name""#,
            &["condition_result", "distinct_zero_binding", "unknown"][..],
        ),
        (
            r#"{"match":{"kind":"call"},"steps":[{"op":"call_shape"},{"op":"call_result_contracts"},{"op":"result_contract_failure_uses","consumer":["log"]}]}"#,
            r#""log""#,
            &["return", "returned_call_argument", "call_argument"][..],
        ),
    ] {
        let diagnostic = validate_query_source(source)
            .into_iter()
            .find(|diagnostic| diagnostic.code == "unknown-value")
            .unwrap_or_else(|| panic!("no JSON constrained-value diagnostic for {source}"));
        assert_eq!(&source[diagnostic.range.clone()], token, "{diagnostic:?}");
        for label in allowed {
            assert!(diagnostic.message.contains(label), "{diagnostic:?}");
        }
    }

    let wrong_upstream = "(result-contract-failure-uses (call-shape (call)))";
    let diagnostic = validate_query_source(wrong_upstream)
        .into_iter()
        .find(|diagnostic| {
            diagnostic.code == "invalid-query"
                && diagnostic.message.contains("requires call_result_contract")
        })
        .expect("typed failure-use upstream diagnostic");
    assert_eq!(
        &wrong_upstream[diagnostic.range.clone()],
        "result-contract-failure-uses"
    );
}

/// The callable-signature row wrappers hover from the same registry that
/// parses them, and live validation accepts the wrapper chain and rejects a
/// misspelling with a range-precise diagnostic (#1478 M2).
#[test]
fn callable_signature_form_help_and_diagnostics_are_range_precise() {
    let rql = "(signature-parameters (callable-signature (enclosing-decl (method))))";
    for token in ["signature-parameters", "callable-signature"] {
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

    // The underscore spelling is the same form.
    let underscored = "(signature_parameters (callable_signature (enclosing-decl (method))))";
    assert!(
        validate_query_source(underscored).is_empty(),
        "{underscored}: {:#?}",
        validate_query_source(underscored)
    );

    let misspelled = "(callable-signatures (enclosing-decl (method)))";
    let diagnostic = validate_query_source(misspelled)
        .into_iter()
        .find(|diagnostic| diagnostic.code == "unknown-form")
        .expect("unknown-form diagnostic");
    assert_eq!(&misspelled[diagnostic.range.clone()], "callable-signatures");
}

/// The decorator-binding wrapper is declared once and therefore gets parser,
/// alias, validation, and hover behavior in both spellings from the same
/// registry (#2644).
#[test]
fn decorator_binding_form_help_and_diagnostics_are_range_precise() {
    let rql = "(decorator-bindings (parameter))";
    for token in ["decorator-bindings", "parameter"] {
        let offset = rql.find(token).unwrap();
        let help =
            query_source_help_at(rql, offset).unwrap_or_else(|| panic!("no help for {token}"));
        assert_eq!(&rql[help.range], token);
        assert!(!help.description.is_empty());
    }
    assert!(validate_query_source(rql).is_empty(), "{rql}");

    let underscored = "(decorator_bindings (parameter))";
    assert!(
        validate_query_source(underscored).is_empty(),
        "{underscored}: {:#?}",
        validate_query_source(underscored)
    );

    let misspelled = "(decorator-binding (parameter))";
    let diagnostic = validate_query_source(misspelled)
        .into_iter()
        .find(|diagnostic| diagnostic.code == "unknown-form")
        .expect("unknown-form diagnostic");
    assert_eq!(&misspelled[diagnostic.range.clone()], "decorator-binding");

    let json = r#"{"match":{"kind":"parameter"},"steps":[{"op":"decorator_bindings"}]}"#;
    assert!(validate_query_source(json).is_empty(), "{json}");
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

    // The inverse linkage step (#1660) validates and hovers in both
    // spellings, exactly like its forward sibling.
    let stubs = "(stubs-of (enclosing-decl (function)))";
    for token in ["stubs-of", "enclosing-decl"] {
        let offset = stubs.find(token).unwrap();
        let help = query_source_help_at(stubs, offset)
            .unwrap_or_else(|| panic!("no materialization help for {token}"));
        assert_eq!(&stubs[help.range], token);
        assert!(!help.description.is_empty());
    }
    assert!(
        validate_query_source(stubs).is_empty(),
        "{stubs}: {:#?}",
        validate_query_source(stubs)
    );
    let underscored = "(stubs_of (enclosing-decl (function)))";
    assert!(
        validate_query_source(underscored).is_empty(),
        "{underscored}: {:#?}",
        validate_query_source(underscored)
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

#[test]
fn arity_help_covers_the_predicate_form_property_and_json_field() {
    // Predicate form and inline property both hover on the `arity` token.
    let form = "(call (arity :min 1 :max 3))";
    let form_help =
        query_source_help_at(form, form.find("arity").unwrap()).expect("arity form help");
    assert_eq!(&form[form_help.range.clone()], "arity");
    assert!(
        form_help.description.contains("argument count"),
        "{form_help:?}"
    );

    let property = r#"(call :callee (name "execute") :arity 1)"#;
    let property_help =
        query_source_help_at(property, property.find(":arity").unwrap()).expect("arity property");
    assert_eq!(&property[property_help.range], ":arity");
    assert!(!property_help.description.is_empty());

    // The JSON `arity` field carries the same vocabulary help.
    let json = r#"{"match":{"kind":"call","arity":1}}"#;
    let json_help =
        query_source_help_at(json, json.find("\"arity\"").unwrap()).expect("arity json help");
    assert_eq!(&json[json_help.range], "\"arity\"");
    assert!(json_help.description.contains("argument count"));
}

#[test]
fn arity_frontends_validate_ranges_at_exact_positions() {
    // Well-formed exact and range forms validate clean in both frontends.
    for source in [
        r#"(call :callee (name "execute") :arity 1)"#,
        r#"(call (arity :min 1 :max 3))"#,
        r#"(call (arity :min 1))"#,
        r#"{"match":{"kind":"call","arity":1}}"#,
        r#"{"match":{"kind":"call","arity":{"min":1,"max":3}}}"#,
        r#"{"match":{"kind":"call","arity":{"max":2}}}"#,
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

    let json = r#"{"match":{"kind":"call","arity":{"min":3,"max":1}}}"#;
    let diagnostic = validate_query_source(json)
        .pop()
        .expect("json range diagnostic");
    assert!(
        diagnostic.message.contains("must not exceed"),
        "{diagnostic:?}"
    );

    // An empty range constrains nothing.
    let json = r#"{"match":{"kind":"call","arity":{}}}"#;
    let diagnostic = validate_query_source(json)
        .pop()
        .expect("empty range diagnostic");
    assert!(
        diagnostic.message.contains("at least one"),
        "{diagnostic:?}"
    );

    // A bound above MAX_ARITY.
    let rql = "(call (arity 100000))";
    let diagnostic = validate_query_source(rql).pop().expect("bound diagnostic");
    assert!(diagnostic.message.contains("at most"), "{diagnostic:?}");

    // An unknown range key is flagged at that key.
    let json = r#"{"match":{"kind":"call","arity":{"exactly":1}}}"#;
    let diagnostics = validate_query_source(json);
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| &json[diagnostic.range.clone()] == "\"exactly\""),
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
fn visibility_help_covers_the_predicate_form_property_and_json_field() {
    let form = "(method (visibility public))";
    let form_help =
        query_source_help_at(form, form.find("visibility").unwrap()).expect("visibility form help");
    assert_eq!(&form[form_help.range.clone()], "visibility");
    assert!(
        form_help.description.contains("visibility"),
        "{form_help:?}"
    );

    let property = "(method :visibility public)";
    let property_help = query_source_help_at(property, property.find(":visibility").unwrap())
        .expect("visibility property");
    assert_eq!(&property[property_help.range], ":visibility");

    let json = r#"{"match":{"kind":"method","visibility":"public"}}"#;
    let json_help = query_source_help_at(json, json.find("\"visibility\"").unwrap())
        .expect("visibility json help");
    assert_eq!(&json[json_help.range], "\"visibility\"");
}

#[test]
fn visibility_and_parameter_type_frontends_validate_at_exact_positions() {
    for source in [
        "(method :visibility public)",
        "(method :visibility [public protected])",
        "(method :visibility (public protected))",
        "(method (visibility package-private))",
        r#"(method :parameter-type "String")"#,
        r#"(method :parameter-type/regex "String")"#,
        r#"{"match":{"kind":"method","visibility":"public"}}"#,
        r#"{"match":{"kind":"method","visibility":["public","protected"]}}"#,
        r#"{"match":{"kind":"method","parameter_type":"String"}}"#,
        r#"{"match":{"kind":"method","parameter_type":{"regex":"String"}}}"#,
    ] {
        assert!(
            validate_query_source(source).is_empty(),
            "well-formed callable signature predicate should validate: {source}: {:#?}",
            validate_query_source(source)
        );
    }

    let rql = "(call :visibility public)";
    let diagnostic = validate_query_source(rql)
        .pop()
        .expect("visibility on call");
    assert!(diagnostic.message.contains("callable"), "{diagnostic:?}");

    let json = r#"{"match":{"kind":"call","parameter_type":"String"}}"#;
    let diagnostic = validate_query_source(json)
        .pop()
        .expect("parameter_type on call");
    assert!(diagnostic.message.contains("callable"), "{diagnostic:?}");

    let rql = "(method :visibility banana)";
    let diagnostic = validate_query_source(rql)
        .pop()
        .expect("unknown visibility");
    assert!(
        diagnostic.message.contains("unknown visibility"),
        "{diagnostic:?}"
    );
}

#[test]
fn jsx_attribute_value_source_frontends_validate_and_hover_from_schema() {
    let rql = r#"(jsx-attribute-value :identity intrinsic :element-name div :property-name __html
        (jsx_attribute (name "dangerouslySetInnerHTML")))"#;
    assert!(
        validate_query_source(rql).is_empty(),
        "{:#?}",
        validate_query_source(rql)
    );
    let help =
        query_source_help_at(rql, rql.find(":identity").unwrap()).expect("identity option help");
    assert!(help.description.contains("semantic element identity"));

    let json = r#"{"match":{"kind":"jsx_attribute"},"steps":[{"op":"jsx_attribute_value","identity":"intrinsic","element_name":"div","property_name":"__html"}]}"#;
    assert!(
        validate_query_source(json).is_empty(),
        "{:#?}",
        validate_query_source(json)
    );
    let help =
        query_source_help_at(json, json.find("\"identity\"").unwrap()).expect("JSON identity help");
    assert!(help.description.contains("semantic element identity"));

    let invalid = r#"(jsx-attribute-value :identity unresolved (jsx_attribute))"#;
    let diagnostic = validate_query_source(invalid)
        .into_iter()
        .find(|diagnostic| diagnostic.code == "unknown-value")
        .expect("invalid identity diagnostic");
    assert!(diagnostic.message.contains("intrinsic"));
}
