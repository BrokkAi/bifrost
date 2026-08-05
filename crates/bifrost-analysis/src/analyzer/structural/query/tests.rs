use super::*;
use crate::analyzer::Language;
use crate::analyzer::structural::kinds::ALL_ROLES;
use crate::analyzer::structural::occurrences::{Namespace, OccurrenceClass, OccurrenceRole};
use crate::analyzer::structural::{NormalizedKind, Role};
use crate::analyzer::usages::{ReferenceKind, UsageHitSurface, UsageProof};
use serde_json::{Value, json};

fn parse(json: Value) -> Result<CodeQuery, QueryError> {
    CodeQuery::from_json(&json)
}

fn parse_ok(json: Value) -> CodeQuery {
    parse(json).expect("query should parse")
}

fn error_of(json: Value) -> QueryError {
    parse(json).expect_err("query should be rejected")
}

#[test]
fn parses_the_issue_example_query() {
    let query = parse_ok(json!({
        "where": ["src/**/*.py", "src/**/*.ts"],
        "match": {
            "kind": "call",
            "callee": { "name": "eval" },
            "args": [{ "capture": "code" }]
        },
        "inside": {
            "kind": "function",
            "capture": "enclosing_function"
        },
        "limit": 100
    }));

    let seed = query.seed().expect("structural seed");
    assert_eq!(seed.where_globs.len(), 2);
    assert_eq!(query.limit, 100);
    assert_eq!(seed.root.kinds, vec![NormalizedKind::Call]);
    let callee = seed.root.callee.as_ref().expect("callee pattern");
    assert!(matches!(&callee.name, Some(StringPredicate::Exact(name)) if name == "eval"));
    assert_eq!(seed.root.args.len(), 1);
    assert_eq!(seed.root.args[0].capture.as_deref(), Some("code"));
    let inside = seed.inside.as_ref().expect("inside pattern");
    assert_eq!(inside.kinds, vec![NormalizedKind::Function]);
    assert_eq!(inside.capture.as_deref(), Some("enclosing_function"));
}

#[test]
fn declaration_bounded_containment_round_trips_and_requires_schema_version_five() {
    let json = json!({
        "schema_version": 5,
        "match": { "kind": "call", "callee": { "name": "open" } },
        "inside_decl": { "kind": "loop", "capture": "loop" }
    });
    let query = parse_ok(json.clone());
    let seed = query.seed().expect("structural seed");
    assert_eq!(
        seed.inside_decl
            .as_ref()
            .expect("inside_decl pattern")
            .kinds,
        vec![NormalizedKind::Loop]
    );
    assert_eq!(query.to_canonical_json()["schema_version"], json!(5));
    assert_eq!(query.to_canonical_json()["match"], json["match"]);
    assert_eq!(
        query.to_canonical_json()["inside_decl"],
        json["inside_decl"]
    );

    parse_ok(json!({
        "schema_version": 5,
        "match": { "kind": "call" },
        "inside_decl": { "kind": "loop", "capture": "loop" },
        "steps": [{ "op": "points_to", "capture": "loop" }]
    }));

    let rql = CodeQuery::from_sexp(
        "(inside-decl (loop :capture \"loop\") (call :callee (name \"open\")))",
    )
    .expect("declaration-bounded RQL should lower");
    assert_eq!(rql.schema_version, SCHEMA_VERSION);
    assert_eq!(rql.to_canonical_json()["match"], json["match"]);
    assert_eq!(rql.to_canonical_json()["inside_decl"], json["inside_decl"]);

    let error = error_of(json!({
        "schema_version": 4,
        "match": { "kind": "call" },
        "inside_decl": { "kind": "loop" }
    }));
    assert_eq!(error.path, "inside_decl");
    assert!(error.message.contains("requires schema version 5"));
}

#[test]
fn parses_and_canonicalizes_reference_traversal_filters() {
    let query = parse_ok(json!({
        "match": { "kind": "class", "name": "Target" },
        "steps": [
            { "op": "enclosing_decl" },
            {
                "op": "references_of",
                "reference_kinds": ["field_write", "method_call"],
                "proof": "proven",
                "surface": "lsp_references"
            }
        ]
    }));
    assert_eq!(
        query.plan.steps[1],
        QueryStep::ReferencesOf(ReferenceTraversalFilter {
            reference_kinds: vec![ReferenceKind::FieldWrite, ReferenceKind::MethodCall],
            proof: Some(UsageProof::Proven),
            surface: UsageHitSurface::LspReferences,
        })
    );
    assert_eq!(
        query.to_canonical_json()["steps"][1],
        json!({
            "op": "references_of",
            "reference_kinds": ["field_write", "method_call"],
            "proof": "proven",
            "surface": "lsp_references"
        })
    );
}

#[test]
fn parses_call_traversal_sites_and_formal_input_selectors() {
    let query = parse_ok(json!({
        "match": { "kind": "callable", "name": "sink" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "callers", "depth": 3, "proof": "proven" },
            { "op": "call_sites_from", "proof": "unproven" },
            { "op": "call_input", "parameter_index": 0 },
            { "op": "file_of" }
        ]
    }));
    assert_eq!(
        query.plan.steps[1],
        QueryStep::Callers(CallTraversalFilter {
            depth: std::num::NonZeroUsize::new(3).unwrap(),
            proof: Some(UsageProof::Proven),
            completeness: CallTraversalCompleteness::Exhaustive,
        })
    );
    assert_eq!(
        query.plan.steps[2],
        QueryStep::CallSitesFrom(CallSiteTraversalFilter {
            proof: Some(UsageProof::Unproven),
        })
    );
    assert_eq!(
        query.plan.steps[3],
        QueryStep::CallInput(CallInputSelector::ParameterIndex(0))
    );
    assert_eq!(query.to_canonical_json()["steps"][1]["depth"], 3);

    let proven_subset = parse_ok(json!({
        "match": { "kind": "callable", "name": "sink" },
        "steps": [
            { "op": "enclosing_decl" },
            {
                "op": "callers",
                "depth": 2,
                "proof": "proven",
                "completeness": "proven_subset"
            }
        ]
    }));
    assert_eq!(
        proven_subset.plan.steps[1],
        QueryStep::Callers(CallTraversalFilter {
            depth: std::num::NonZeroUsize::new(2).unwrap(),
            proof: Some(UsageProof::Proven),
            completeness: CallTraversalCompleteness::ProvenSubset,
        })
    );
    assert_eq!(
        proven_subset.to_canonical_json()["steps"][1]["completeness"],
        "proven_subset"
    );

    let rql = CodeQuery::from_sexp(
        r#"(call-input :parameter-name "payload" (call-sites-to :proof proven (enclosing-decl (method (name "sink")))))"#,
    )
    .expect("RQL call pipeline should parse");
    assert_eq!(
        rql.plan.steps,
        vec![
            QueryStep::EnclosingDecl,
            QueryStep::CallSitesTo(CallSiteTraversalFilter {
                proof: Some(UsageProof::Proven),
            }),
            QueryStep::CallInput(CallInputSelector::ParameterName("payload".to_string())),
        ]
    );

    for step in [
        json!({ "op": "call_input" }),
        json!({ "op": "call_input", "receiver": true, "parameter_index": 0 }),
        json!({ "op": "callers", "transitive": true }),
        json!({ "op": "callers", "completeness": "proven_subset" }),
        json!({ "op": "callers", "proof": "unproven", "completeness": "proven_subset" }),
        json!({ "op": "callees", "proof": "proven", "completeness": "proven_subset" }),
        json!({ "op": "uses", "completeness": "proven_subset" }),
    ] {
        assert!(
            parse(json!({
                "match": { "kind": "callable", "name": "sink" },
                "steps": [{ "op": "enclosing_decl" }, step]
            }))
            .is_err()
        );
    }

    for (step, expected) in [
        (
            QueryStep::Callers(CallTraversalFilter {
                depth: std::num::NonZeroUsize::MIN,
                proof: None,
                completeness: CallTraversalCompleteness::ProvenSubset,
            }),
            "requires proof to be proven",
        ),
        (
            QueryStep::Callees(CallTraversalFilter {
                depth: std::num::NonZeroUsize::MIN,
                proof: Some(UsageProof::Proven),
                completeness: CallTraversalCompleteness::ProvenSubset,
            }),
            "supported only for callers",
        ),
    ] {
        let mut direct = proven_subset.clone();
        direct.plan.steps[1] = step;
        assert!(
            direct
                .validate_steps()
                .expect_err("invalid direct IR must be rejected")
                .to_string()
                .contains(expected)
        );
    }
}

#[test]
fn receiver_steps_parse_canonically_and_validate_capture_domains() {
    let json = json!({
        "match": {
            "kind": "call",
            "receiver": { "capture": "service" }
        },
        "steps": [
            { "op": "receiver_targets", "capture": "service" },
            { "op": "file_of" }
        ]
    });
    let query = parse_ok(json.clone());
    assert_eq!(
        query.plan.steps[0],
        QueryStep::ReceiverTargets(ReceiverTraversalFilter {
            capture: Some("service".to_string()),
        })
    );
    assert_eq!(query.to_canonical_json()["schema_version"], SCHEMA_VERSION);

    let rql = CodeQuery::from_sexp(
        r#"(file-of (receiver-targets :capture service (call :receiver (capture "service"))))"#,
    )
    .expect("receiver RQL");
    assert_eq!(rql.to_canonical_json(), query.to_canonical_json());

    for (steps, path) in [
        (
            json!([{ "op": "points_to", "capture": "missing" }]),
            "steps[0].capture",
        ),
        (
            json!([
                { "op": "enclosing_decl" },
                { "op": "references_of" },
                { "op": "points_to", "capture": "service" }
            ]),
            "steps[2].capture",
        ),
    ] {
        let error = error_of(json!({
            "match": {
                "kind": "call",
                "receiver": { "capture": "service" }
            },
            "steps": steps
        }));
        assert_eq!(error.path, path);
    }
}

#[test]
fn receiver_steps_enforce_their_typed_input_domains() {
    for (steps, path) in [
        (
            json!([{ "op": "member_targets" }, { "op": "file_of" }]),
            None,
        ),
        (
            json!([{ "op": "enclosing_decl" }, { "op": "points_to" }]),
            Some("steps[1]"),
        ),
        (
            json!([
                { "op": "enclosing_decl" },
                { "op": "call_sites_to" },
                { "op": "member_targets" }
            ]),
            Some("steps[2]"),
        ),
    ] {
        let result = parse(json!({
            "match": { "kind": "call" },
            "steps": steps
        }));
        match path {
            None => assert!(result.is_ok()),
            Some(path) => assert_eq!(result.expect_err("invalid domain").path, path),
        }
    }
}

#[test]
fn reference_options_are_operation_specific_and_constrained() {
    for (step, path) in [
        (
            json!({ "op": "file_of", "proof": "proven" }),
            "steps[1].proof",
        ),
        (
            json!({ "op": "uses", "reference_kinds": [] }),
            "steps[1].reference_kinds",
        ),
        (
            json!({ "op": "used_by", "proof": "maybe" }),
            "steps[1].proof",
        ),
        (
            json!({ "op": "references_of", "surface": "all" }),
            "steps[1].surface",
        ),
    ] {
        let error = error_of(json!({
            "match": { "kind": "class", "name": "Target" },
            "steps": [{ "op": "enclosing_decl" }, step]
        }));
        assert_eq!(error.path, path);
    }
}

#[test]
fn parses_kind_unions_and_exclusions() {
    // "All named functions, but not constructors or lambdas" — both
    // spellings from the design discussion.
    let union = parse_ok(json!({
        "match": { "kind": ["function", "method"] }
    }));
    assert_eq!(
        union.seed().unwrap().root.kinds,
        vec![NormalizedKind::Function, NormalizedKind::Method]
    );

    let subtractive = parse_ok(json!({
        "match": { "kind": "callable", "not_kind": ["constructor", "lambda"] }
    }));
    assert_eq!(
        subtractive.seed().unwrap().root.kinds,
        vec![NormalizedKind::Callable]
    );
    assert_eq!(
        subtractive.seed().unwrap().root.not_kinds,
        vec![NormalizedKind::Constructor, NormalizedKind::Lambda]
    );

    // Roles are valid when at least one union member supports them.
    let mixed = parse_ok(json!({
        "match": { "kind": ["call", "assignment"], "callee": { "name": "eval" } }
    }));
    assert!(mixed.seed().unwrap().root.callee.is_some());
}

#[test]
fn parses_receiver_kwargs_and_regex_predicates() {
    let query = parse_ok(json!({
        "languages": ["python"],
        "match": {
            "kind": "call",
            "receiver": { "name": "subprocess" },
            "callee": { "name": "run" },
            "kwargs": { "shell": { "kind": "boolean_literal" } }
        },
        "not_inside": {
            "kind": "class",
            "name": { "regex": ".*Test$" }
        }
    }));

    let seed = query.seed().unwrap();
    assert_eq!(seed.languages, vec![Language::Python]);
    assert_eq!(query.limit, DEFAULT_LIMIT);
    assert_eq!(seed.root.kwargs.len(), 1);
    assert_eq!(seed.root.kwargs[0].0, "shell");
    let not_inside = seed.not_inside.as_ref().expect("not_inside pattern");
    assert!(matches!(
        &not_inside.name,
        Some(StringPredicate::Regex(regex)) if regex.is_match("LoginTest")
    ));
}

#[test]
fn parses_result_detail_mode() {
    let query = parse_ok(json!({
        "match": { "kind": "call" },
        "result_detail": "full"
    }));
    assert_eq!(query.result_detail, CodeQueryResultDetail::Full);

    let defaulted = parse_ok(json!({ "match": { "kind": "call" } }));
    assert_eq!(defaulted.result_detail, CodeQueryResultDetail::Compact);

    let error = error_of(json!({
        "match": { "kind": "call" },
        "result_detail": "verbose"
    }));
    assert_eq!(error.path, "result_detail");
}

#[test]
fn parses_defaults_and_rejects_nested_execution_modes() {
    for (label, expected) in [
        ("results", CodeQueryExecutionMode::Results),
        ("explain", CodeQueryExecutionMode::Explain),
        ("profile", CodeQueryExecutionMode::Profile),
    ] {
        let query = parse_ok(json!({
            "match": { "kind": "call" },
            "execution_mode": label
        }));
        assert_eq!(query.execution_mode, expected);
        assert_eq!(query.to_canonical_json()["execution_mode"], label);
    }

    let defaulted = parse_ok(json!({ "match": { "kind": "call" } }));
    assert_eq!(defaulted.execution_mode, CodeQueryExecutionMode::Results);

    let error = error_of(json!({
        "match": { "kind": "call" },
        "execution_mode": "trace"
    }));
    assert_eq!(error.path, "execution_mode");

    let nested = error_of(json!({
        "union": [
            {
                "match": { "kind": "call" },
                "execution_mode": "profile"
            },
            { "match": { "kind": "class" } }
        ]
    }));
    assert_eq!(nested.path, "union[0].execution_mode");
    assert!(nested.message.contains("root query"));
}

#[test]
fn parses_and_rejects_schema_version() {
    let query = parse_ok(json!({
        "schema_version": 2,
        "match": { "kind": "call" }
    }));
    assert_eq!(query.schema_version, 2);
    assert_eq!(query.to_canonical_json()["schema_version"], 2);

    let defaulted = parse_ok(json!({ "match": { "kind": "call" } }));
    assert_eq!(defaulted.schema_version, SCHEMA_VERSION);

    let error = error_of(json!({
        "schema_version": 1,
        "match": { "kind": "call" }
    }));
    assert_eq!(error.path, "schema_version");
}

#[test]
fn schema_version_three_adds_the_typed_cfg_algebra() {
    let query = parse_ok(json!({
        "schema_version": 3,
        "match": { "kind": "function" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "cfg_entry" },
            { "op": "cfg_successor_edges" },
            { "op": "cfg_edge_target" }
        ]
    }));
    assert_eq!(
        query.plan.steps,
        vec![
            QueryStep::ProcedureOf,
            QueryStep::CfgEntry,
            QueryStep::CfgSuccessorEdges,
            QueryStep::CfgEdgeTarget,
        ]
    );
    assert_eq!(
        query.validate_steps().unwrap(),
        QueryValueKind::ProgramPoint
    );

    let rql = CodeQuery::from_sexp(
        "(cfg-edge-target (cfg-successor-edges (cfg-entry (procedure-of (function)))))",
    )
    .expect("version-three CFG RQL should lower");
    assert_eq!(rql.schema_version, SCHEMA_VERSION);
    assert_eq!(rql.plan.steps, query.plan.steps);

    let error = error_of(json!({
        "schema_version": 2,
        "match": { "kind": "function" },
        "steps": [{ "op": "procedure_of" }]
    }));
    assert_eq!(error.path, "steps[0].op");
    assert!(error.message.contains("requires schema version 3"));
}

#[test]
fn schema_version_four_adds_registered_typestate_findings_and_witnesses() {
    let query = parse_ok(json!({
        "schema_version": 4,
        "match": { "kind": "function", "name": "lifecycle" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "typestate", "protocol_ref": "embedding:bifrost.test.resource-lifecycle" },
            { "op": "witness", "max_steps": 12, "max_bytes": 4096 },
            { "op": "file_of" }
        ]
    }));
    assert!(matches!(
        &query.plan.steps[1],
        QueryStep::Typestate(TypestateTraversal { protocol_ref })
            if protocol_ref.to_string() == "embedding:bifrost.test.resource-lifecycle"
    ));
    assert_eq!(
        query.plan.steps[2],
        QueryStep::Witness(WitnessTraversal {
            max_steps: Some(12),
            max_bytes: Some(4096),
        })
    );
    assert_eq!(query.validate_steps().unwrap(), QueryValueKind::File);

    let rql = CodeQuery::from_sexp(
        "(file-of (witness :max-steps 12 :max-bytes 4096 (typestate :protocol-ref embedding:bifrost.test.resource-lifecycle (procedure-of (function :name \"lifecycle\")))))",
    )
    .expect("schema-four typestate RQL should lower");
    assert_eq!(rql.schema_version, SCHEMA_VERSION);
    assert_eq!(rql.plan.steps, query.plan.steps);

    let error = error_of(json!({
        "schema_version": 3,
        "match": { "kind": "function" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "typestate", "protocol_ref": "test:lifecycle" }
        ]
    }));
    assert_eq!(error.path, "steps[1].op");
    assert!(error.message.contains("requires schema version 4"));
}

#[test]
fn typestate_step_options_are_required_bounded_and_operation_specific() {
    let missing = error_of(json!({
        "match": { "kind": "function" },
        "steps": [{ "op": "procedure_of" }, { "op": "typestate" }]
    }));
    assert_eq!(missing.path, "steps[1].protocol_ref");

    let invalid_ref = error_of(json!({
        "match": { "kind": "function" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "typestate", "protocol_ref": "missing-separator" }
        ]
    }));
    assert_eq!(invalid_ref.path, "steps[1].protocol_ref");

    let negative = error_of(json!({
        "match": { "kind": "function" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "typestate", "protocol_ref": "test:lifecycle" },
            { "op": "witness", "max_steps": -1 }
        ]
    }));
    assert_eq!(negative.path, "steps[2].max_steps");

    let wrong_operation = error_of(json!({
        "match": { "kind": "function" },
        "steps": [{ "op": "procedure_of", "protocol_ref": "test:lifecycle" }]
    }));
    assert_eq!(wrong_operation.path, "steps[0].protocol_ref");
}

#[test]
fn schema_version_six_adds_registered_value_flow_endpoints_and_witnesses() {
    let query = parse_ok(json!({
        "schema_version": 6,
        "match": { "kind": "function", "name": "run" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "value_flow", "plan_ref": "test:request-to-sink" },
            { "op": "witness", "max_steps": 24, "max_bytes": 8192 },
            { "op": "file_of" }
        ]
    }));
    assert!(matches!(
        &query.plan.steps[1],
        QueryStep::ValueFlow(ValueFlowTraversal { plan_ref })
            if plan_ref.to_string() == "test:request-to-sink"
    ));
    assert_eq!(query.validate_steps().unwrap(), QueryValueKind::File);

    let rql = CodeQuery::from_sexp(
        "(file-of (witness :max-steps 24 :max-bytes 8192 (value-flow :plan-ref test:request-to-sink (procedure-of (function :name \"run\")))))",
    )
    .expect("schema-six value-flow RQL should lower");
    assert_eq!(rql.schema_version, SCHEMA_VERSION);
    assert_eq!(rql.plan.steps, query.plan.steps);

    let error = error_of(json!({
        "schema_version": 5,
        "match": { "kind": "function" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "value_flow", "plan_ref": "test:request-to-sink" }
        ]
    }));
    assert_eq!(error.path, "steps[1].op");
    assert!(error.message.contains("requires schema version 6"));
}

#[test]
fn value_flow_plan_ref_is_required_and_operation_specific() {
    let missing = error_of(json!({
        "match": { "kind": "function" },
        "steps": [{ "op": "procedure_of" }, { "op": "value_flow" }]
    }));
    assert_eq!(missing.path, "steps[1].plan_ref");

    let invalid = error_of(json!({
        "match": { "kind": "function" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "value_flow", "plan_ref": "missing-separator" }
        ]
    }));
    assert_eq!(invalid.path, "steps[1].plan_ref");

    let wrong_operation = error_of(json!({
        "match": { "kind": "function" },
        "steps": [{ "op": "procedure_of", "plan_ref": "test:flow" }]
    }));
    assert_eq!(wrong_operation.path, "steps[0].plan_ref");
}

#[test]
fn schema_version_seven_adds_retained_taint_findings() {
    let query = parse_ok(json!({
        "schema_version": 7,
        "match": { "kind": "function", "name": "run" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "taint", "taint_ref": "test:request-to-sink" },
            { "op": "file_of" }
        ]
    }));
    assert!(matches!(
        &query.plan.steps[1],
        QueryStep::Taint(TaintTraversal { taint_ref })
            if taint_ref.to_string() == "test:request-to-sink"
    ));
    assert_eq!(query.validate_steps().unwrap(), QueryValueKind::File);

    let rql = CodeQuery::from_sexp(
        "(file-of (taint :taint-ref test:request-to-sink (procedure-of (function :name \"run\"))))",
    )
    .expect("schema-seven taint RQL should lower");
    assert_eq!(rql.schema_version, SCHEMA_VERSION);
    assert_eq!(rql.plan.steps, query.plan.steps);

    let error = error_of(json!({
        "schema_version": 6,
        "match": { "kind": "function" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "taint", "taint_ref": "test:request-to-sink" }
        ]
    }));
    assert_eq!(error.path, "steps[1].op");
    assert!(error.message.contains("requires schema version 7"));
}

#[test]
fn taint_ref_is_required_and_operation_specific() {
    let missing = error_of(json!({
        "match": { "kind": "function" },
        "steps": [{ "op": "procedure_of" }, { "op": "taint" }]
    }));
    assert_eq!(missing.path, "steps[1].taint_ref");

    let invalid = error_of(json!({
        "match": { "kind": "function" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "taint", "taint_ref": "missing-separator" }
        ]
    }));
    assert_eq!(invalid.path, "steps[1].taint_ref");

    let wrong_operation = error_of(json!({
        "match": { "kind": "function" },
        "steps": [{ "op": "procedure_of", "taint_ref": "test:taint" }]
    }));
    assert_eq!(wrong_operation.path, "steps[0].taint_ref");
}

#[test]
fn typed_cfg_algebra_validates_each_domain_transition() {
    for (steps, expected) in [
        (
            vec![json!({ "op": "procedure_of" })],
            QueryValueKind::Procedure,
        ),
        (
            vec![
                json!({ "op": "procedure_of" }),
                json!({ "op": "cfg_exits" }),
            ],
            QueryValueKind::ProgramPoint,
        ),
        (
            vec![
                json!({ "op": "procedure_of" }),
                json!({ "op": "cfg_entry" }),
                json!({ "op": "cfg_predecessor_edges" }),
            ],
            QueryValueKind::ControlEdge,
        ),
        (
            vec![
                json!({ "op": "procedure_of" }),
                json!({ "op": "cfg_entry" }),
                json!({ "op": "cfg_successor_edges" }),
                json!({ "op": "cfg_edge_source" }),
                json!({ "op": "file_of" }),
            ],
            QueryValueKind::File,
        ),
    ] {
        let query = parse_ok(json!({
            "schema_version": 3,
            "match": { "kind": "function" },
            "steps": steps
        }));
        assert_eq!(query.validate_steps().unwrap(), expected);
    }

    let error = error_of(json!({
        "schema_version": 3,
        "match": { "kind": "function" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "cfg_successor_edges" }
        ]
    }));
    assert_eq!(error.path, "steps[1]");
    assert!(error.message.contains("program_point"));
    assert!(error.message.contains("procedure"));

    let error = error_of(json!({
        "schema_version": 3,
        "match": { "kind": "function" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "cfg_entry" }
        ]
    }));
    assert_eq!(error.path, "steps[1]");
    assert!(error.message.contains("requires procedure"));
    assert!(error.message.contains("declaration"));
}

#[test]
fn typed_cfg_set_branches_must_have_compatible_domains() {
    let query = parse_ok(json!({
        "schema_version": 3,
        "union": [
            {
                "match": { "kind": "function", "name": "left" },
                "steps": [{ "op": "procedure_of" }]
            },
            {
                "match": { "kind": "function", "name": "right" },
                "steps": [{ "op": "procedure_of" }]
            }
        ],
        "steps": [{ "op": "cfg_entry" }]
    }));
    assert_eq!(
        query.validate_steps().unwrap(),
        QueryValueKind::ProgramPoint
    );

    let error = error_of(json!({
        "schema_version": 3,
        "union": [
            {
                "match": { "kind": "function" },
                "steps": [{ "op": "procedure_of" }]
            },
            { "match": { "kind": "function" } }
        ]
    }));
    assert_eq!(error.path, "union[1]");
    assert!(error.message.contains("structural_match"));
    assert!(error.message.contains("procedure"));
}

#[test]
fn compatible_schema_successor_changes_only_the_emitted_version() {
    use crate::schema_version::{SchemaVersionDescriptor, SchemaVersionRegistry};

    let registry = SchemaVersionRegistry::new(&[
        SchemaVersionDescriptor::new(2, None, true),
        SchemaVersionDescriptor::new(3, Some(2), true),
    ])
    .unwrap();
    let source = json!({ "match": { "kind": "call" } });
    let inferred = CodeQuery::from_json_with_schema_registry(&source, &registry).unwrap();
    let explicit = CodeQuery::from_json_with_schema_registry(
        &json!({ "schema_version": 2, "match": { "kind": "call" } }),
        &registry,
    )
    .unwrap();

    assert_eq!(inferred.schema_version, 3);
    assert_eq!(explicit.schema_version, 2);
    let mut inferred_json = inferred.to_canonical_json();
    let mut explicit_json = explicit.to_canonical_json();
    inferred_json
        .as_object_mut()
        .unwrap()
        .remove("schema_version");
    explicit_json
        .as_object_mut()
        .unwrap()
        .remove("schema_version");
    assert_eq!(inferred_json, explicit_json);
}

#[test]
fn canonical_query_plan_projection_excludes_execution_controls() {
    let query = parse_ok(json!({
        "schema_version": 2,
        "match": { "kind": "call" },
        "limit": 7,
        "result_detail": "full",
        "execution_mode": "profile"
    }));
    let projected = query.to_canonical_query_plan_json();

    assert_eq!(projected["schema_version"], 2);
    assert!(projected.get("match").is_some());
    assert!(projected.get("limit").is_none());
    assert!(projected.get("result_detail").is_none());
    assert!(projected.get("execution_mode").is_none());
}

#[test]
fn parses_and_validates_typed_steps() {
    let query = parse_ok(json!({
        "match": { "kind": "call" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "file_of" },
            { "op": "imports_of" },
            { "op": "importers_of" }
        ]
    }));
    assert_eq!(
        query.plan.steps,
        vec![
            QueryStep::EnclosingDecl,
            QueryStep::FileOf,
            QueryStep::ImportsOf,
            QueryStep::ImportersOf,
        ]
    );
    assert_eq!(
        query.to_canonical_json()["steps"],
        json!([
            { "op": "enclosing_decl" },
            { "op": "file_of" },
            { "op": "imports_of" },
            { "op": "importers_of" }
        ])
    );

    let error = error_of(json!({
        "match": { "kind": "call" },
        "steps": [{ "op": "imports_of" }]
    }));
    assert_eq!(error.path, "steps[0]");
    assert!(error.message.contains("structural_match"));

    let error = error_of(json!({
        "match": { "kind": "call" },
        "steps": [{ "op": "file_of", "depth": 2 }]
    }));
    assert_eq!(error.path, "steps[0].depth");

    let error = error_of(json!({
        "match": { "kind": "call" },
        "steps": [{ "op": "calls_of" }]
    }));
    assert_eq!(error.path, "steps[0].op");
}

#[test]
fn parses_typed_set_composition_and_common_suffix_steps() {
    let json = json!({
        "union": [
            {
                "match": { "kind": "class", "name": "Legacy" },
                "steps": [{ "op": "enclosing_decl" }]
            },
            {
                "match": { "kind": "class", "name": "Replacement" },
                "steps": [{ "op": "enclosing_decl" }]
            }
        ],
        "steps": [{ "op": "file_of" }],
        "limit": 20
    });
    let query = parse_ok(json);
    assert_eq!(query.validate_steps().unwrap(), QueryValueKind::File);
    assert!(matches!(
        query.plan.source,
        CodeQueryPlanSource::Set {
            op: SetOperator::Union,
            ref branches,
        } if branches.len() == 2
    ));

    let rql = CodeQuery::from_sexp(
        r#"(limit 20
          (file-of
            (union
              (enclosing-decl (class :name "Legacy"))
              (enclosing-decl (class :name "Replacement")))))"#,
    )
    .expect("set RQL should parse");
    assert_eq!(rql.to_canonical_json(), query.to_canonical_json());
    assert_eq!(
        query.to_canonical_json()["union"][0]["steps"][0]["op"],
        "enclosing_decl"
    );
}

#[test]
fn set_composition_rejects_invalid_shapes_and_incompatible_domains() {
    let error = error_of(json!({
        "union": [{ "match": { "kind": "class" } }]
    }));
    assert_eq!(error.path, "union");
    assert!(error.message.contains("at least two"));

    let error = error_of(json!({
        "match": { "kind": "class" },
        "intersect": [
            { "match": { "kind": "class" } },
            { "match": { "kind": "class" } }
        ]
    }));
    assert_eq!(error.path, "intersect");
    assert!(error.message.contains("mutually exclusive"));

    let error = error_of(json!({
        "except": [
            {
                "match": { "kind": "class" },
                "steps": [{ "op": "enclosing_decl" }]
            },
            {
                "match": { "kind": "class" },
                "steps": [{ "op": "file_of" }]
            }
        ]
    }));
    assert_eq!(error.path, "except[1]");
    assert!(error.message.contains("file"));
    assert!(error.message.contains("declaration"));

    let error = error_of(json!({
        "union": [
            { "match": { "kind": "class" }, "limit": 1 },
            { "match": { "kind": "class" } }
        ]
    }));
    assert_eq!(error.path, "union[0].limit");
}

#[test]
fn composed_structural_capture_must_exist_in_every_branch() {
    let valid = parse_ok(json!({
        "intersect": [
            {
                "match": { "kind": "call", "receiver": { "capture": "service" } }
            },
            {
                "match": { "kind": "call", "receiver": { "capture": "service" } }
            }
        ],
        "steps": [{ "op": "points_to", "capture": "service" }]
    }));
    assert_eq!(
        valid.validate_steps().unwrap(),
        QueryValueKind::ReceiverAnalysis
    );

    let error = error_of(json!({
        "union": [
            {
                "match": { "kind": "call", "receiver": { "capture": "service" } }
            },
            { "match": { "kind": "call" } }
        ],
        "steps": [{ "op": "points_to", "capture": "service" }]
    }));
    assert_eq!(error.path, "steps[0].capture");
    assert!(error.message.contains("every contributing"));

    let difference = parse_ok(json!({
        "except": [
            {
                "match": { "kind": "call", "receiver": { "capture": "service" } }
            },
            { "match": { "kind": "call", "callee": { "name": "ignored" } } }
        ],
        "steps": [{ "op": "points_to", "capture": "service" }]
    }));
    assert_eq!(
        difference.validate_steps().unwrap(),
        QueryValueKind::ReceiverAnalysis
    );

    let rql = CodeQuery::from_sexp(
        r#"(points-to :capture service
          (except
            (call :receiver (capture "service"))
            (call :callee "ignored")))"#,
    )
    .expect("except RQL should preserve first-branch captures");
    assert_eq!(
        rql.validate_steps().unwrap(),
        QueryValueKind::ReceiverAnalysis
    );
}

#[test]
fn receiver_analysis_projects_typed_outcome_and_evidence_rows() {
    let outcome =
        CodeQuery::from_sexp(r#"(receiver-outcome (receiver-targets (call :callee "run")))"#)
            .expect("receiver outcome RQL");
    assert_eq!(
        outcome.validate_steps().unwrap(),
        QueryValueKind::ReceiverOutcome
    );
    assert_eq!(outcome.schema_version, RECEIVER_EVIDENCE_SCHEMA_VERSION);

    let evidence = parse_ok(json!({
        "schema_version": RECEIVER_EVIDENCE_SCHEMA_VERSION,
        "match": { "kind": "call", "callee": { "name": "run" } },
        "steps": [
            { "op": "receiver_targets" },
            { "op": "receiver_evidence" }
        ]
    }));
    assert_eq!(
        evidence.validate_steps().unwrap(),
        QueryValueKind::ReceiverEvidence
    );
    assert_eq!(
        evidence.to_canonical_json()["steps"][1]["op"],
        "receiver_evidence"
    );

    let error = error_of(json!({
        "schema_version": RECEIVER_EVIDENCE_SCHEMA_VERSION - 1,
        "match": { "kind": "call", "callee": { "name": "run" } },
        "steps": [
            { "op": "receiver_targets" },
            { "op": "receiver_outcome" }
        ]
    }));
    assert_eq!(error.path, "steps[1].op");
}

#[test]
fn parses_configured_hierarchy_and_member_steps() {
    let query = parse_ok(json!({
        "match": { "kind": "class" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "supertypes" },
            { "op": "subtypes", "depth": 3 },
            { "op": "subtypes", "transitive": true },
            { "op": "members" },
            { "op": "owner" }
        ]
    }));
    assert_eq!(
        query.plan.steps,
        vec![
            QueryStep::EnclosingDecl,
            QueryStep::Supertypes(HierarchyTraversal::Direct),
            QueryStep::Subtypes(HierarchyTraversal::Depth(
                std::num::NonZeroUsize::new(3).unwrap()
            )),
            QueryStep::Subtypes(HierarchyTraversal::Transitive),
            QueryStep::Members,
            QueryStep::Owner,
        ]
    );
    assert_eq!(
        query.to_canonical_json()["steps"],
        json!([
            { "op": "enclosing_decl" },
            { "op": "supertypes" },
            { "op": "subtypes", "depth": 3 },
            { "op": "subtypes", "transitive": true },
            { "op": "members" },
            { "op": "owner" }
        ])
    );

    for (step, path) in [
        (json!({ "op": "supertypes", "depth": 0 }), "steps[1].depth"),
        (
            json!({ "op": "supertypes", "transitive": false }),
            "steps[1].transitive",
        ),
        (
            json!({ "op": "subtypes", "depth": 2, "transitive": true }),
            "steps[1].transitive",
        ),
        (json!({ "op": "members", "depth": 2 }), "steps[1].depth"),
    ] {
        let error = error_of(json!({
            "match": { "kind": "class" },
            "steps": [{ "op": "enclosing_decl" }, step]
        }));
        assert_eq!(error.path, path);
    }
}

#[test]
fn rejects_more_than_the_step_budget() {
    let steps = (0..=MAX_QUERY_STEPS)
        .map(|_| json!({ "op": "file_of" }))
        .collect::<Vec<_>>();
    let error = error_of(json!({
        "match": { "kind": "call" },
        "steps": steps
    }));
    assert_eq!(error.path, "steps");
}

#[test]
fn canonical_json_round_trips() {
    let original = json!({
        "where": ["src/**/*.py"],
        "languages": ["python"],
        "match": {
            "kind": "call",
            "callee": { "name": "eval" },
            "args": [{ "capture": "code" }]
        },
        "inside": { "kind": ["function", "method"], "capture": "fn" },
        "not_inside": { "kind": "class", "not_kind": "declaration" },
        "limit": 50
    });
    let canonical = parse_ok(original).to_canonical_json();
    let reparsed = parse_ok(canonical.clone());
    assert_eq!(reparsed.to_canonical_json(), canonical);
}

#[test]
fn rejects_unknown_top_level_and_pattern_fields() {
    let error = error_of(json!({
        "match": { "kind": "call" },
        "insde": { "kind": "function" }
    }));
    assert_eq!(error.path, "insde");

    let error = error_of(json!({
        "match": { "kind": "call", "calee": { "name": "eval" } }
    }));
    assert_eq!(error.path, "match.calee");
}

#[test]
fn rejects_unknown_kind_with_suggestions() {
    let error = error_of(json!({ "match": { "kind": "method_invocation" } }));
    assert_eq!(error.path, "match.kind");
    assert!(
        error.message.contains("call"),
        "message should list valid kinds: {}",
        error.message
    );
}

#[test]
fn rejects_removed_kind_exact_as_unknown_field() {
    // `kind_exact` existed briefly and was dropped in favor of kind
    // unions + not_kind; a caller using it gets the unknown-field error
    // listing the current vocabulary.
    let error = error_of(json!({
        "match": { "kind_exact": "string_literal" }
    }));
    assert_eq!(error.path, "match.kind_exact");
    assert!(error.message.contains("unknown field"));
}

#[test]
fn rejects_empty_and_malformed_kind_arrays() {
    let error = error_of(json!({ "match": { "kind": [] } }));
    assert_eq!(error.path, "match.kind");

    let error = error_of(json!({ "match": { "kind": ["call", 3] } }));
    assert_eq!(error.path, "match.kind[1]");

    let error = error_of(json!({
        "match": { "kind": "call", "not_kind": ["lambada"] }
    }));
    assert_eq!(error.path, "match.not_kind[0]");
}

#[test]
fn rejects_role_invalid_for_kind() {
    let error = error_of(json!({
        "match": { "kind": "assignment", "callee": { "name": "eval" } }
    }));
    assert_eq!(error.path, "match.callee");
    assert!(error.message.contains("not valid for kind"));

    // A union where no member supports the role is provably empty.
    let error = error_of(json!({
        "match": { "kind": ["assignment", "import"], "callee": { "name": "eval" } }
    }));
    assert_eq!(error.path, "match.callee");
}

#[test]
fn rejects_role_without_declared_kind() {
    let error = error_of(json!({
        "match": { "name": "run", "callee": { "name": "eval" } }
    }));
    assert_eq!(error.path, "match.callee");
    assert!(error.message.contains("requires the pattern to declare"));
}

#[test]
fn rejects_unconstrained_root_pattern() {
    let error = error_of(json!({ "match": { "capture": "everything" } }));
    assert_eq!(error.path, "match");
    assert!(error.message.contains("root pattern"));
}

#[test]
fn allows_capture_only_and_empty_nested_patterns() {
    let query = parse_ok(json!({
        "match": { "kind": "call", "args": [{}, { "capture": "second" }] }
    }));
    assert!(query.seed().unwrap().root.args[0].is_empty());
    assert_eq!(
        query.seed().unwrap().root.args[1].capture.as_deref(),
        Some("second")
    );
}

#[test]
fn rejects_bad_regex_bad_glob_and_unknown_language() {
    let error = error_of(json!({
        "match": { "kind": "call", "callee": { "name": { "regex": "[" } } }
    }));
    assert_eq!(error.path, "match.callee.name.regex");

    let error = error_of(json!({
        "where": ["src/[oops"],
        "match": { "kind": "call" }
    }));
    assert_eq!(error.path, "where[0]");

    let error = error_of(json!({
        "languages": ["cobol"],
        "match": { "kind": "call" }
    }));
    assert_eq!(error.path, "languages[0]");
}

#[test]
fn rejects_out_of_range_limits() {
    assert_eq!(
        error_of(json!({ "match": { "kind": "call" }, "limit": 0 })).path,
        "limit"
    );
    assert_eq!(
        error_of(json!({ "match": { "kind": "call" }, "limit": 100000 })).path,
        "limit"
    );
}

#[test]
fn rejects_query_budget_overruns() {
    let too_many_globs = (0..=MAX_WHERE_GLOBS)
        .map(|index| json!(format!("src/{index}.py")))
        .collect::<Vec<_>>();
    let error = error_of(json!({
        "where": too_many_globs,
        "match": { "kind": "call" }
    }));
    assert_eq!(error.path, "where");

    let mut deeply_nested = json!({ "kind": "call" });
    for _ in 0..=MAX_PATTERN_DEPTH {
        deeply_nested = json!({ "kind": "call", "has": deeply_nested });
    }
    let error = error_of(json!({ "match": deeply_nested }));
    assert!(error.message.contains("pattern nesting"), "{error}");

    let too_many_args = (0..=MAX_ROLE_LIST_ENTRIES)
        .map(|_| json!({ "capture": "arg" }))
        .collect::<Vec<_>>();
    let error = error_of(json!({
        "match": { "kind": "call", "args": too_many_args }
    }));
    assert_eq!(error.path, "match.args");

    let error = error_of(json!({
        "match": {
            "kind": "call",
            "text": { "regex": "x".repeat(MAX_STRING_PREDICATE_LENGTH + 1) }
        }
    }));
    assert_eq!(error.path, "match.text.regex");

    let mut too_deep = json!({ "match": 3 });
    for _ in 0..=MAX_QUERY_PLAN_DEPTH {
        too_deep = json!({
            "union": [too_deep, { "match": { "kind": "call" } }]
        });
    }
    let error = error_of(too_deep);
    assert!(error.message.contains("plan depth"), "{error}");

    let mut groups = Vec::new();
    for group in 0..4 {
        let leaves = (0..16)
            .map(|index| {
                if group == 3 && index == 11 {
                    json!({ "match": 3 })
                } else {
                    json!({ "match": { "kind": "call" } })
                }
            })
            .collect::<Vec<_>>();
        groups.push(json!({ "union": leaves }));
    }
    let error = error_of(json!({ "union": groups }));
    assert!(error.message.contains("at most 64 nodes"), "{error}");
}

#[test]
fn role_accessors_cover_every_role_category() {
    let sub = Pattern {
        capture: Some("target".to_string()),
        ..Pattern::default()
    };
    let mut pattern = Pattern {
        callee: Some(Box::new(sub.clone())),
        receiver: Some(Box::new(sub.clone())),
        args: vec![sub.clone()],
        kwargs: vec![("named".to_string(), sub.clone())],
        left: Some(Box::new(sub.clone())),
        right: Some(Box::new(sub.clone())),
        module: Some(Box::new(sub.clone())),
        decorators: vec![sub.clone()],
        object: Some(Box::new(sub.clone())),
        field: Some(Box::new(sub.clone())),
        ..Pattern::default()
    };

    for &role in ALL_ROLES {
        match role {
            Role::Callee
            | Role::Receiver
            | Role::Left
            | Role::Right
            | Role::Module
            | Role::Object
            | Role::Field => {
                assert!(pattern.single_role_pattern(role).is_some(), "{role:?}");
                assert!(pattern.list_role_patterns(role).is_empty(), "{role:?}");
            }
            Role::Arg | Role::Decorator => {
                assert!(pattern.single_role_pattern(role).is_none(), "{role:?}");
                assert_eq!(pattern.list_role_patterns(role).len(), 1, "{role:?}");
            }
            Role::Kwarg => {
                assert!(pattern.single_role_pattern(role).is_none(), "{role:?}");
                assert!(pattern.list_role_patterns(role).is_empty(), "{role:?}");
                assert_eq!(pattern.kwargs.len(), 1);
            }
        }
    }

    pattern.args.clear();
    pattern.decorators.clear();
    pattern.kwargs.clear();
    assert!(pattern.has_role_constraints());
}

#[test]
fn not_kind_alone_does_not_anchor_a_root() {
    let error = error_of(json!({ "match": { "not_kind": "lambda" } }));
    assert_eq!(error.path, "match");
    assert!(error.message.contains("root pattern"));
}

#[test]
fn exact_alternatives_expand_anchored_literal_alternations() {
    let alternatives = |pattern: &str| {
        StringPredicate::Regex(regex::Regex::new(pattern).expect("regex compiles"))
            .exact_alternatives()
    };

    assert_eq!(
        StringPredicate::Exact("read".to_string()).exact_alternatives(),
        Some(vec!["read".to_string()])
    );
    assert_eq!(alternatives("^read$"), Some(vec!["read".to_string()]));
    assert_eq!(
        alternatives("^(read|read_to_string)$"),
        Some(vec!["read".to_string(), "read_to_string".to_string()])
    );
    assert_eq!(
        alternatives("^(?:to_vec|to_string|to_vec)$"),
        Some(vec!["to_string".to_string(), "to_vec".to_string()]),
        "non-capturing groups expand and duplicates collapse"
    );
    assert_eq!(
        alternatives(
            "^(sort|sort_by|sort_by_key|sort_by_cached_key|sort_unstable|sort_unstable_by|sort_unstable_by_key)$"
        )
        .map(|alternatives| alternatives.len()),
        Some(7)
    );

    // Everything the extractor cannot prove finite and literal stays opaque.
    assert_eq!(alternatives("read"), None, "unanchored");
    assert_eq!(alternatives("^read"), None, "half anchored");
    assert_eq!(alternatives("^read_[a-z]+$"), None, "class");
    assert_eq!(alternatives("^(read|write.*)$"), None, "non-literal branch");
    assert_eq!(alternatives("^(read|)$"), None, "empty branch");
    assert_eq!(alternatives("(?i)^read$"), None, "case folding");
    assert_eq!(alternatives("^(a|b)(c|d)$"), None, "product of groups");
}

/// The occurrence filter is one type shared by the seed and both producing
/// steps, so every frontend must spell it the same way.
#[test]
fn occurrence_filters_decode_identically_from_the_seed_and_from_a_step() {
    let seed = parse_ok(json!({
        "occurrences": { "class": ["binding"], "role": ["binder"], "namespace": ["value"] }
    }));
    let CodeQueryPlanSource::Occurrences(seed) = &seed.plan.source else {
        panic!("occurrences is its own plan source");
    };
    assert_eq!(seed.filter.classes, vec![OccurrenceClass::Binding]);
    assert_eq!(seed.filter.roles, vec![OccurrenceRole::Binder]);
    assert_eq!(seed.filter.namespaces, vec![Namespace::Value]);

    let stepped = parse_ok(json!({
        "match": { "kind": "function" },
        "steps": [{ "op": "occurrences_in", "class": ["binding"], "role": ["binder"], "namespace": ["value"] }]
    }));
    let QueryStep::OccurrencesIn(step_filter) = &stepped.plan.steps[0] else {
        panic!("occurrences_in decodes to its own step");
    };
    assert_eq!(step_filter, &seed.filter);
}

/// A single label is accepted wherever a list is, so the JSON frontend mirrors
/// RQL's `:role binder`.
#[test]
fn occurrence_filter_axes_accept_one_label_or_a_list() {
    let single = parse_ok(json!({ "occurrences": { "role": "binder" } }));
    let list = parse_ok(json!({ "occurrences": { "role": ["binder"] } }));
    assert_eq!(single.to_canonical_json(), list.to_canonical_json());
}

#[test]
fn occurrence_steps_reject_invalid_domains_and_unknown_options() {
    let wrong_input = error_of(json!({
        "match": { "kind": "function" },
        "steps": [{ "op": "occurrence_target" }]
    }));
    assert!(
        wrong_input.message.contains("requires occurrence"),
        "{wrong_input:?}"
    );

    let wrong_source = error_of(json!({
        "occurrences": {},
        "steps": [{ "op": "enclosing_decl" }]
    }));
    assert!(
        wrong_source.message.contains("requires structural_match"),
        "{wrong_source:?}"
    );

    let unknown_option = error_of(json!({
        "match": { "kind": "function" },
        "steps": [{ "op": "occurrences_in", "depth": 2 }]
    }));
    assert_eq!(unknown_option.path, "steps[0].depth");

    let misplaced_filter = error_of(json!({
        "match": { "kind": "function" },
        "steps": [{ "op": "enclosing_decl", "role": ["binder"] }]
    }));
    assert_eq!(misplaced_filter.path, "steps[0].role");
}

/// Duplicate values within one axis collapse; the axes stay independent.
#[test]
fn occurrence_filter_values_deduplicate_within_an_axis() {
    let query = parse_ok(json!({
        "occurrences": { "role": ["binder", "binder", "declaration_name"] }
    }));
    let CodeQueryPlanSource::Occurrences(seed) = &query.plan.source else {
        panic!("occurrences is its own plan source");
    };
    assert_eq!(
        seed.filter.roles,
        vec![OccurrenceRole::Binder, OccurrenceRole::DeclarationName]
    );
    assert!(seed.filter.classes.is_empty());
}

/// An unconstrained filter depends on every role, a class filter on that
/// class's roles, and a role filter on exactly the named roles. This is what
/// scopes capability reporting to what a query actually asked about.
#[test]
fn required_roles_narrow_with_the_filter() {
    let unconstrained = OccurrenceFilter::default();
    assert_eq!(
        unconstrained.required_roles().len(),
        crate::analyzer::structural::occurrences::ALL_OCCURRENCE_ROLES.len()
    );

    let by_class = OccurrenceFilter {
        classes: vec![OccurrenceClass::Binding],
        ..OccurrenceFilter::default()
    };
    assert_eq!(by_class.required_roles(), vec![OccurrenceRole::Binder]);

    let by_role = OccurrenceFilter {
        classes: vec![OccurrenceClass::Reference],
        roles: vec![OccurrenceRole::PathSegment],
        ..OccurrenceFilter::default()
    };
    assert_eq!(
        by_role.required_roles(),
        vec![OccurrenceRole::PathSegment],
        "an explicit role list is the narrowest claim and wins"
    );
}
