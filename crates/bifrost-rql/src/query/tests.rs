use super::*;
use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::structural::control_relation::{
    ControlExitPartition, ControlRelationKind,
};
use brokk_bifrost_core::analyzer::structural::flow_state::{
    FlowCertainty, FlowRelation as FlowRelationLabel, FlowSubjectKind, StateEventClass,
};
use brokk_bifrost_core::analyzer::structural::kinds::{ALL_ROLES, NormalizedKind, Role};
use brokk_bifrost_core::analyzer::structural::occurrences::{
    Namespace, OccurrenceClass, OccurrenceRole,
};
use brokk_bifrost_core::analyzer::structural::rewrite_path::{
    RewriteDomainKind, RewriteOutcomeKind,
};
use brokk_bifrost_core::analyzer::usages::model::{ReferenceKind, UsageHitSurface, UsageProof};
use serde_json::{Value, json};

fn parse(json: Value) -> Result<CodeQuery, QueryError> {
    CodeQuery::from_json(&json)
}

fn parse_ok(json: Value) -> CodeQuery {
    parse(json).expect("query should parse")
}

#[test]
fn decorator_bindings_accepts_exact_import_identity_filters() {
    let json_query = parse_ok(json!({
        "match": { "kind": "parameter" },
        "steps": [{
            "op": "decorator_bindings",
            "module": "@nestjs/common",
            "imported_name": "Query"
        }]
    }));
    assert_eq!(
        json_query.plan.steps[0],
        QueryStep::DecoratorBindings(DecoratorBindingFilter {
            module: Some("@nestjs/common".to_string()),
            imported_name: Some("Query".to_string()),
        })
    );
    assert_eq!(
        json_query.to_canonical_json()["steps"][0],
        json!({
            "op": "decorator_bindings",
            "module": "@nestjs/common",
            "imported_name": "Query"
        })
    );

    let rql_query = CodeQuery::from_sexp(
        r#"(decorator-bindings :module "@nestjs/common" :imported-name Query (parameter))"#,
    )
    .expect("decorator binding identity filters should lower");
    assert_eq!(
        rql_query.to_canonical_json(),
        json_query.to_canonical_json()
    );

    assert!(
        parse(json!({
            "match": { "kind": "parameter" },
            "steps": [{ "op": "decorator_bindings", "module": 7 }]
        }))
        .is_err()
    );
    assert!(
        CodeQuery::from_sexp(
            r#"(decorator-bindings :imported-name Query :imported_name Other (parameter))"#,
        )
        .is_err()
    );
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
fn declaration_bounded_containment_round_trips() {
    let json = json!({
        "schema_version": 1,
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
    assert_eq!(query.to_canonical_json()["schema_version"], json!(1));
    assert_eq!(query.to_canonical_json()["match"], json["match"]);
    assert_eq!(
        query.to_canonical_json()["inside_decl"],
        json["inside_decl"]
    );

    parse_ok(json!({
        "schema_version": 1,
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
fn boolean_literal_values_parse_and_canonicalize_across_json_and_rql() {
    let json_query = parse_ok(json!({
        "match": { "kind": "boolean_literal", "boolean_value": true }
    }));
    assert_eq!(json_query.seed().unwrap().root.boolean_value, Some(true));
    assert_eq!(
        json_query.to_canonical_json()["match"]["boolean_value"],
        json!(true)
    );

    for source in [
        "(boolean_literal :boolean-value true)",
        "(boolean_literal :boolean_value true)",
        "(boolean_literal (boolean-value true))",
        "(boolean_literal (boolean_value true))",
    ] {
        let rql = CodeQuery::from_sexp(source).expect("boolean-value RQL should lower");
        assert_eq!(rql.to_canonical_json(), json_query.to_canonical_json());
    }

    let false_query = CodeQuery::from_sexp("(boolean_literal (boolean-value false))")
        .expect("false boolean-value RQL should lower");
    assert_eq!(
        false_query.to_canonical_json()["match"]["boolean_value"],
        json!(false)
    );

    for invalid in [
        json!({ "match": { "kind": "boolean_literal", "boolean_value": 1 } }),
        json!({ "match": { "kind": "boolean_literal", "boolean_value": "true" } }),
    ] {
        let error = error_of(invalid);
        assert_eq!(error.path, "match.boolean_value");
        assert_eq!(error.message, "expected a boolean literal");
    }
    assert!(CodeQuery::from_sexp("(boolean_literal :boolean-value 1)").is_err());
    assert!(CodeQuery::from_sexp("(boolean_literal (boolean-value \"true\"))").is_err());
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
        "schema_version": 1,
        "match": { "kind": "call" }
    }));
    assert_eq!(query.schema_version, 1);
    assert_eq!(query.to_canonical_json()["schema_version"], 1);

    let defaulted = parse_ok(json!({ "match": { "kind": "call" } }));
    assert_eq!(defaulted.schema_version, SCHEMA_VERSION);

    let error = error_of(json!({
        "schema_version": 2,
        "match": { "kind": "call" }
    }));
    assert_eq!(error.path, "schema_version");
}

#[test]
fn typed_cfg_algebra_parses_and_lowers() {
    let query = parse_ok(json!({
        "schema_version": 1,
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
    .expect("CFG RQL should lower");
    assert_eq!(rql.schema_version, SCHEMA_VERSION);
    assert_eq!(rql.plan.steps, query.plan.steps);
}

/// The flow-state vocabulary (#1480) parses from both frontends, lowers to the
/// same typed steps, and types its pipeline end to end.
#[test]
fn flow_state_steps_parse_and_lower_from_both_frontends() {
    let query = parse_ok(json!({
        "schema_version": 1,
        "match": { "kind": "function", "name": "handler" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "state_events_of", "event_class": ["establish", "read"], "subject": ["binding"] },
            { "op": "flow_relations_of", "flow_relation": ["reaching"], "certainty": ["exact"] },
            { "op": "flow_target" }
        ]
    }));
    assert_eq!(
        query.plan.steps,
        vec![
            QueryStep::ProcedureOf,
            QueryStep::StateEventsOf(StateEventFilter {
                classes: vec![StateEventClass::Establish, StateEventClass::Read],
                subjects: vec![FlowSubjectKind::Binding],
            }),
            QueryStep::FlowRelationsOf(FlowRelationFilter {
                relations: vec![FlowRelationLabel::Reaching],
                certainties: vec![FlowCertainty::Exact],
            }),
            QueryStep::FlowTarget,
        ]
    );
    assert_eq!(query.validate_steps().unwrap(), QueryValueKind::StateEvent);

    let rql = CodeQuery::from_sexp(
        "(flow-target (flow-relations-of :relation [reaching] :certainty [exact] \
           (state-events-of :class [establish read] :subject [binding] \
             (procedure-of (function :name \"handler\")))))",
    )
    .expect("flow-state RQL should lower");
    assert_eq!(rql.schema_version, SCHEMA_VERSION);
    assert_eq!(rql.plan.steps, query.plan.steps);
    assert_eq!(rql.to_canonical_json(), query.to_canonical_json());
}

/// The hyphenated RQL spellings canonicalize to the wire labels, and the
/// `flow-source` projection types back to a state event.
#[test]
fn flow_state_hyphenated_values_canonicalize_to_wire_labels() {
    let rql = CodeQuery::from_sexp(
        "(flow-source (flow-relations-of :relation [same-evaluation] \
           (state-events-of (procedure-of (function)))))",
    )
    .expect("same-evaluation should lower");
    assert_eq!(
        rql.plan.steps,
        vec![
            QueryStep::ProcedureOf,
            QueryStep::StateEventsOf(StateEventFilter::default()),
            QueryStep::FlowRelationsOf(FlowRelationFilter {
                relations: vec![FlowRelationLabel::SameEvaluation],
                certainties: Vec::new(),
            }),
            QueryStep::FlowSource,
        ]
    );
    assert_eq!(rql.validate_steps().unwrap(), QueryValueKind::StateEvent);
}

/// Flow relations can be seeded from a procedure directly, and a state event
/// row is addressable by `file-of` like every other source-backed row.
#[test]
fn flow_relations_seed_from_a_procedure_and_state_events_reach_files() {
    let relations =
        CodeQuery::from_sexp("(flow-relations-of (procedure-of (function)))").expect("lowers");
    assert_eq!(
        relations.validate_steps().unwrap(),
        QueryValueKind::FlowRelation
    );
    let files = CodeQuery::from_sexp("(file-of (state-events-of (procedure-of (function))))")
        .expect("lowers");
    assert_eq!(files.validate_steps().unwrap(), QueryValueKind::File);
}

/// The typed algebra rejects a projection applied to the wrong row family, and
/// says which family it wanted.
#[test]
fn flow_state_projections_reject_incompatible_inputs() {
    let error = error_of(json!({
        "schema_version": 1,
        "match": { "kind": "function" },
        "steps": [{ "op": "procedure_of" }, { "op": "flow_source" }]
    }));
    assert!(error.message.contains("flow_relation"), "{error:?}");

    let error = error_of(json!({
        "schema_version": 1,
        "match": { "kind": "function" },
        "steps": [{ "op": "state_events_of" }]
    }));
    assert!(
        error.message.contains("procedure or declaration"),
        "{error:?}"
    );
}

/// A bad constrained value is rejected by the decoder, on the offending field's
/// own path, and the allowed set is what the registry says.
#[test]
fn flow_state_filters_reject_values_outside_their_vocabulary() {
    let error = error_of(json!({
        "schema_version": 1,
        "match": { "kind": "function" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "state_events_of", "event_class": ["establish", "obliterate"] }
        ]
    }));
    assert_eq!(error.path, "steps[1].event_class[1]");

    let error = error_of(json!({
        "schema_version": 1,
        "match": { "kind": "function" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "flow_relations_of", "certainty": ["probably"] }
        ]
    }));
    assert_eq!(error.path, "steps[1].certainty[0]");

    let error = error_of(json!({
        "schema_version": 1,
        "match": { "kind": "function" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "state_events_of", "relation": ["reaching"] }
        ]
    }));
    assert_eq!(error.path, "steps[1].relation");
}

/// The control-relation vocabulary (#2443) parses from both frontends, lowers
/// to the same typed step, and types its pipeline end to end.
#[test]
fn control_relation_steps_parse_and_lower_from_both_frontends() {
    let query = parse_ok(json!({
        "schema_version": 1,
        "match": { "kind": "function", "name": "handler" },
        "steps": [
            { "op": "procedure_of" },
            {
                "op": "control_relations",
                "control_relation": ["dominates", "control_depends_on"],
                "exit_partition": ["normal_and_exceptional"]
            }
        ]
    }));
    assert_eq!(
        query.plan.steps,
        vec![
            QueryStep::ProcedureOf,
            QueryStep::ControlRelations(ControlRelationFilter {
                relations: vec![
                    ControlRelationKind::Dominates,
                    ControlRelationKind::ControlDependsOn
                ],
                exit_partitions: vec![ControlExitPartition::NormalAndExceptional],
            }),
        ]
    );
    assert_eq!(
        query.validate_steps().unwrap(),
        QueryValueKind::ControlRelation
    );

    // The hyphenated RQL spellings canonicalize to the same wire labels.
    let rql = CodeQuery::from_sexp(
        "(control-relations :relation [dominates control-depends-on] \
           :exit-partition [normal-and-exceptional] \
           (procedure-of (function :name \"handler\")))",
    )
    .expect("control-relation RQL should lower");
    assert_eq!(rql.schema_version, SCHEMA_VERSION);
    assert_eq!(rql.plan.steps, query.plan.steps);
    assert_eq!(rql.to_canonical_json(), query.to_canonical_json());
}

/// A reserved exit partition is authorable: it is a value no row carries today,
/// not a value the parser refuses. Rejecting it would make a partitioned
/// derivation a breaking change instead of an added value (#2443).
#[test]
fn a_reserved_exit_partition_parses_and_a_misspelled_one_does_not() {
    let reserved = CodeQuery::from_sexp(
        "(control-relations :exit-partition [normal-only] (procedure-of (function)))",
    )
    .expect("a reserved partition is a declared value");
    assert_eq!(
        reserved.plan.steps,
        vec![
            QueryStep::ProcedureOf,
            QueryStep::ControlRelations(ControlRelationFilter {
                relations: Vec::new(),
                exit_partitions: vec![ControlExitPartition::NormalOnly],
            }),
        ]
    );

    let error = error_of(json!({
        "schema_version": 1,
        "match": { "kind": "function" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "control_relations", "exit_partition": ["normal_and_cancellation"] }
        ]
    }));
    assert_eq!(error.path, "steps[1].exit_partition[0]");
}

/// The typed algebra refuses the step over anything but a procedure, and a
/// value outside the relation vocabulary is rejected on its own path.
#[test]
fn control_relations_reject_wrong_inputs_and_unknown_values() {
    let error = error_of(json!({
        "schema_version": 1,
        "match": { "kind": "function" },
        "steps": [{ "op": "control_relations" }]
    }));
    assert!(error.message.contains("procedure"), "{error:?}");

    let error = error_of(json!({
        "schema_version": 1,
        "match": { "kind": "function" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "control_relations", "control_relation": ["dominates", "precedes"] }
        ]
    }));
    assert_eq!(error.path, "steps[1].control_relation[1]");

    let error = error_of(json!({
        "schema_version": 1,
        "match": { "kind": "function" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "control_relations", "certainty": ["exact"] }
        ]
    }));
    assert_eq!(error.path, "steps[1].certainty");
}

/// The `guards_of` step (#2443 slice 2) parses from both frontends, lowers to
/// the same typed step, and types its pipeline end to end.
///
/// The step takes no option axis: a guard row carries its predicate as a
/// column, so an author narrows with `:where` rather than with a filter the
/// registry would have to keep in step with the IR enum.
#[test]
fn guard_steps_parse_and_lower_from_both_frontends() {
    let query = parse_ok(json!({
        "schema_version": 1,
        "match": { "kind": "function", "name": "handler" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "guards_of" }
        ]
    }));
    assert_eq!(
        query.plan.steps,
        vec![QueryStep::ProcedureOf, QueryStep::GuardsOf]
    );
    assert_eq!(query.validate_steps().unwrap(), QueryValueKind::Guard);

    let rql = CodeQuery::from_sexp("(guards-of (procedure-of (function :name \"handler\")))")
        .expect("guard RQL should lower");
    assert_eq!(rql.schema_version, SCHEMA_VERSION);
    assert_eq!(rql.plan.steps, query.plan.steps);
    assert_eq!(rql.to_canonical_json(), query.to_canonical_json());
}

/// The typed algebra refuses `guards_of` over anything but a procedure, and the
/// step carries no option axis, so one borrowed from a sibling step is rejected
/// on its own path rather than silently ignored.
#[test]
fn guard_steps_reject_wrong_inputs_and_borrowed_options() {
    let error = error_of(json!({
        "schema_version": 1,
        "match": { "kind": "function" },
        "steps": [{ "op": "guards_of" }]
    }));
    assert!(error.message.contains("procedure"), "{error:?}");

    let error = error_of(json!({
        "schema_version": 1,
        "match": { "kind": "function" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "guards_of", "control_relation": ["dominates"] }
        ]
    }));
    assert_eq!(error.path, "steps[1].control_relation");
}

/// The three project-topology steps (#2448) parse from both frontends, lower
/// to the same typed steps, and type their pipeline end to end.
///
/// The chain is the one an architecture rule writes: a file's declared target,
/// and that target's declared dependencies.
#[test]
fn topology_steps_parse_and_lower_from_both_frontends() {
    let query = parse_ok(json!({
        "schema_version": 1,
        "match": { "kind": "class", "name": "Order" },
        "steps": [
            { "op": "file_of" },
            { "op": "target_of" },
            { "op": "topology_edges_of" }
        ]
    }));
    assert_eq!(
        query.plan.steps,
        vec![
            QueryStep::FileOf,
            QueryStep::TargetOf,
            QueryStep::TopologyEdgesOf,
        ]
    );
    assert_eq!(
        query.validate_steps().unwrap(),
        QueryValueKind::TopologyEdge
    );

    let rql =
        CodeQuery::from_sexp("(topology-edges-of (target-of (file-of (class :name \"Order\"))))")
            .expect("topology RQL should lower");
    assert_eq!(rql.schema_version, SCHEMA_VERSION);
    assert_eq!(rql.plan.steps, query.plan.steps);
    assert_eq!(rql.to_canonical_json(), query.to_canonical_json());

    let source_set = CodeQuery::from_sexp("(source-set-of (file-of (class :name \"Order\")))")
        .expect("source-set-of RQL should lower");
    assert_eq!(
        source_set.plan.steps,
        vec![QueryStep::FileOf, QueryStep::SourceSetOf]
    );
    assert_eq!(
        source_set.validate_steps().unwrap(),
        QueryValueKind::SourceSet
    );
}

/// The typed algebra refuses each topology step over anything but its declared
/// input, so a rule cannot ask a source file for its dependencies or a source
/// set for its edges.
#[test]
fn topology_steps_reject_wrong_inputs() {
    let error = error_of(json!({
        "schema_version": 1,
        "match": { "kind": "class" },
        "steps": [{ "op": "target_of" }]
    }));
    assert!(error.message.contains("file"), "{error:?}");

    let error = error_of(json!({
        "schema_version": 1,
        "match": { "kind": "class" },
        "steps": [{ "op": "file_of" }, { "op": "topology_edges_of" }]
    }));
    assert!(error.message.contains("build_target"), "{error:?}");

    let error = error_of(json!({
        "schema_version": 1,
        "match": { "kind": "class" },
        "steps": [
            { "op": "file_of" },
            { "op": "source_set_of" },
            { "op": "topology_edges_of" }
        ]
    }));
    assert!(error.message.contains("build_target"), "{error:?}");

    // The steps carry no option axis at all, so one borrowed from a sibling
    // step is rejected on its own path rather than silently ignored.
    let error = error_of(json!({
        "schema_version": 1,
        "match": { "kind": "class" },
        "steps": [
            { "op": "file_of" },
            { "op": "target_of", "certainty": ["exact"] }
        ]
    }));
    assert_eq!(error.path, "steps[1].certainty");
}

/// The bounded rewrite-path vocabulary (#1480) parses from both frontends,
/// lowers to the same typed step, and types its pipeline end to end.
#[test]
fn rewrite_path_steps_parse_and_lower_from_both_frontends() {
    let query = parse_ok(json!({
        "schema_version": 1,
        "match": { "kind": "function", "name": "use_alias" },
        "steps": [
            { "op": "file_of" },
            {
                "op": "rewrite_paths_of",
                "domain": ["rust_import_alias"],
                "rewrite_outcome": ["cycle", "exceeded_budget"]
            }
        ]
    }));
    assert_eq!(
        query.plan.steps,
        vec![
            QueryStep::FileOf,
            QueryStep::RewritePathsOf(RewritePathFilter {
                domains: vec![RewriteDomainKind::RustImportAlias],
                outcomes: vec![
                    RewriteOutcomeKind::Cycle,
                    RewriteOutcomeKind::ExceededBudget
                ],
            }),
        ]
    );
    assert_eq!(query.validate_steps().unwrap(), QueryValueKind::RewritePath);

    // The author writes the hyphenated spellings; they canonicalize to the
    // wire labels the registry owns.
    let rql = CodeQuery::from_sexp(
        "(rewrite-paths-of :domain [rust-import-alias] :outcome [cycle exceeded-budget] \
           (file-of (function :name \"use_alias\")))",
    )
    .expect("rewrite-path RQL should lower");
    assert_eq!(rql.schema_version, SCHEMA_VERSION);
    assert_eq!(rql.plan.steps, query.plan.steps);
    assert_eq!(rql.to_canonical_json(), query.to_canonical_json());
}

/// The typed algebra rejects a rewrite-path step applied to anything but a
/// file, and says what it wanted.
#[test]
fn rewrite_paths_reject_incompatible_inputs() {
    let error = error_of(json!({
        "schema_version": 1,
        "match": { "kind": "function" },
        "steps": [{ "op": "procedure_of" }, { "op": "rewrite_paths_of" }]
    }));
    assert!(error.message.contains("file"), "{error:?}");
}

/// A bad constrained value is rejected by the decoder on the offending field's
/// own path, and an option that belongs to another family is rejected too.
#[test]
fn rewrite_path_filters_reject_values_outside_their_vocabulary() {
    let error = error_of(json!({
        "schema_version": 1,
        "match": { "kind": "function" },
        "steps": [
            { "op": "file_of" },
            { "op": "rewrite_paths_of", "rewrite_outcome": ["diverged"] }
        ]
    }));
    assert_eq!(error.path, "steps[1].rewrite_outcome[0]");

    let error = error_of(json!({
        "schema_version": 1,
        "match": { "kind": "function" },
        "steps": [
            { "op": "file_of" },
            { "op": "rewrite_paths_of", "domain": ["python_import_alias"] }
        ]
    }));
    assert_eq!(error.path, "steps[1].domain[0]");

    let error = error_of(json!({
        "schema_version": 1,
        "match": { "kind": "function" },
        "steps": [
            { "op": "file_of" },
            { "op": "rewrite_paths_of", "certainty": ["exact"] }
        ]
    }));
    assert_eq!(error.path, "steps[1].certainty");
}

#[test]
fn registered_typestate_findings_and_witnesses_parse() {
    let query = parse_ok(json!({
        "schema_version": 1,
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
    .expect("typestate RQL should lower");
    assert_eq!(rql.schema_version, SCHEMA_VERSION);
    assert_eq!(rql.plan.steps, query.plan.steps);
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
fn registered_value_flow_endpoints_and_witnesses_parse() {
    let query = parse_ok(json!({
        "schema_version": 1,
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
    .expect("value-flow RQL should lower");
    assert_eq!(rql.schema_version, SCHEMA_VERSION);
    assert_eq!(rql.plan.steps, query.plan.steps);
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
fn retained_taint_findings_parse() {
    let query = parse_ok(json!({
        "schema_version": 1,
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
    .expect("taint RQL should lower");
    assert_eq!(rql.schema_version, SCHEMA_VERSION);
    assert_eq!(rql.plan.steps, query.plan.steps);
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
            "schema_version": 1,
            "match": { "kind": "function" },
            "steps": steps
        }));
        assert_eq!(query.validate_steps().unwrap(), expected);
    }

    let error = error_of(json!({
        "schema_version": 1,
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
        "schema_version": 1,
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
        "schema_version": 1,
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
        "schema_version": 1,
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
    use brokk_bifrost_core::schema_version::{SchemaVersionDescriptor, SchemaVersionRegistry};

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
        "schema_version": 1,
        "match": { "kind": "call" },
        "limit": 7,
        "result_detail": "full",
        "execution_mode": "profile"
    }));
    let projected = query.to_canonical_query_plan_json();

    assert_eq!(projected["schema_version"], 1);
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
    assert_eq!(outcome.schema_version, SCHEMA_VERSION);

    let evidence = parse_ok(json!({
        "schema_version": SCHEMA_VERSION,
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
}

#[test]
fn jsx_attribute_value_is_a_distinct_operand_ranged_terminal() {
    let query = parse_ok(json!({
        "match": { "kind": "jsx_attribute", "name": "dangerouslySetInnerHTML" },
        "steps": [{
            "op": "jsx_attribute_value",
            "identity": "intrinsic",
            "element_name": "div",
            "property_name": "__html"
        }]
    }));
    assert_eq!(
        query.validate_steps().unwrap(),
        QueryValueKind::JsxAttributeValue
    );
    assert_eq!(
        query.plan.steps[0],
        QueryStep::JsxAttributeValue(JsxAttributeValueTraversal {
            identity: Some(JsxElementIdentity::Intrinsic),
            element_name: Some("div".to_string()),
            property_name: Some("__html".to_string()),
        })
    );
    assert_eq!(
        query.to_canonical_json()["steps"][0],
        json!({
            "op": "jsx_attribute_value",
            "identity": "intrinsic",
            "element_name": "div",
            "property_name": "__html"
        })
    );

    let rql = CodeQuery::from_sexp(
        r#"(jsx-attribute-value :identity intrinsic :element-name div :property-name __html
             (jsx_attribute (name "dangerouslySetInnerHTML")))"#,
    )
    .expect("JSX value projection RQL");
    assert_eq!(
        rql.validate_steps().unwrap(),
        QueryValueKind::JsxAttributeValue
    );
    assert_eq!(rql.to_canonical_json(), query.to_canonical_json());
}

#[test]
fn jsx_attribute_value_rejects_unknown_identity() {
    let error = error_of(json!({
        "match": { "kind": "jsx_attribute" },
        "steps": [{ "op": "jsx_attribute_value", "identity": "maybe" }]
    }));
    assert!(error.path.ends_with("identity"));
    assert!(error.message.contains("intrinsic"));
}

#[test]
fn call_shape_projects_typed_group_and_argument_rows() {
    let shape =
        CodeQuery::from_sexp(r#"(call-shape (call :callee "run"))"#).expect("call shape RQL");
    assert_eq!(shape.validate_steps().unwrap(), QueryValueKind::CallShape);
    assert_eq!(shape.schema_version, SCHEMA_VERSION);

    let arguments = parse_ok(json!({
        "schema_version": SCHEMA_VERSION,
        "match": { "kind": "call", "callee": { "name": "run" } },
        "steps": [
            { "op": "call_shape" },
            { "op": "call_argument_groups" },
            { "op": "call_arguments" }
        ]
    }));
    assert_eq!(
        arguments.validate_steps().unwrap(),
        QueryValueKind::CallArgument
    );
    assert_eq!(
        arguments.to_canonical_json()["steps"][2]["op"],
        "call_arguments"
    );

    let rql = CodeQuery::from_sexp(
        r#"(call-arguments (call-argument-groups (call-shape (call :callee "run"))))"#,
    )
    .expect("chained call shape RQL");
    assert_eq!(rql.validate_steps().unwrap(), QueryValueKind::CallArgument);

    // Group and argument projections only accept their own upstream domain.
    let wrong = CodeQuery::from_json(&json!({
        "match": { "kind": "call" },
        "steps": [{ "op": "call_arguments" }]
    }))
    .expect_err("call_arguments must reject a structural upstream");
    assert!(wrong.message.contains("requires call_argument_group"));
}

#[test]
fn call_bindings_project_typed_actual_to_formal_rows() {
    let rql = CodeQuery::from_sexp(r#"(call-bindings (call-shape (call :callee "run")))"#)
        .expect("call binding RQL");
    assert_eq!(rql.validate_steps().unwrap(), QueryValueKind::CallBinding);
    assert_eq!(rql.schema_version, SCHEMA_VERSION);

    let json = parse_ok(json!({
        "schema_version": SCHEMA_VERSION,
        "match": { "kind": "call", "callee": { "name": "run" } },
        "steps": [
            { "op": "call_shape" },
            { "op": "call_bindings" }
        ]
    }));
    assert_eq!(json.validate_steps().unwrap(), QueryValueKind::CallBinding);
    assert_eq!(json.to_canonical_json()["steps"][1]["op"], "call_bindings");
    // Both frontends lower to the same plan, so the S-expression spelling is a
    // surface and never a second semantics.
    assert_eq!(rql.to_canonical_json(), json.to_canonical_json());

    // The binding relation is derived where the call-shape identities exist,
    // so nothing else is a legal upstream.
    let wrong = CodeQuery::from_json(&json!({
        "match": { "kind": "call" },
        "steps": [{ "op": "call_bindings" }]
    }))
    .expect_err("call_bindings must reject a structural upstream");
    assert!(
        wrong.message.contains("requires call_shape"),
        "{}",
        wrong.message
    );

    // A binding row reaches its file like every other row domain.
    let files = parse_ok(json!({
        "match": { "kind": "call", "callee": { "name": "run" } },
        "steps": [
            { "op": "call_shape" },
            { "op": "call_bindings" },
            { "op": "file_of" }
        ]
    }));
    assert_eq!(files.validate_steps().unwrap(), QueryValueKind::File);
}

#[test]
fn effect_steps_project_typed_call_and_procedure_effect_rows() {
    let call_rql = CodeQuery::from_sexp(r#"(call-effects (call-shape (call :callee "send")))"#)
        .expect("call effect RQL");
    assert_eq!(
        call_rql.validate_steps().unwrap(),
        QueryValueKind::CallEffect
    );
    assert_eq!(call_rql.schema_version, SCHEMA_VERSION);

    let call_json = parse_ok(json!({
        "schema_version": SCHEMA_VERSION,
        "match": { "kind": "call", "callee": { "name": "send" } },
        "steps": [
            { "op": "call_shape" },
            { "op": "call_effects" }
        ]
    }));
    assert_eq!(
        call_json.validate_steps().unwrap(),
        QueryValueKind::CallEffect
    );
    assert_eq!(
        call_json.to_canonical_json()["steps"][1]["op"],
        "call_effects"
    );
    // Both frontends lower to the same plan, so the S-expression spelling is a
    // surface and never a second semantics.
    assert_eq!(call_rql.to_canonical_json(), call_json.to_canonical_json());

    // A direct effect is a fact about a call site, so the call-shape row -- the
    // only upstream that owns a stable site identity -- is the sole legal input.
    let wrong_call = CodeQuery::from_json(&json!({
        "match": { "kind": "call" },
        "steps": [{ "op": "call_effects" }]
    }))
    .expect_err("call_effects must reject a structural upstream");
    assert!(
        wrong_call.message.contains("requires call_shape"),
        "{}",
        wrong_call.message
    );

    let procedure_rql =
        CodeQuery::from_sexp(r#"(procedure-effects (enclosing-decl (method (name "handle"))))"#)
            .expect("procedure effect RQL");
    assert_eq!(
        procedure_rql.validate_steps().unwrap(),
        QueryValueKind::ProcedureEffect
    );
    let procedure_json = parse_ok(json!({
        "schema_version": SCHEMA_VERSION,
        "match": { "kind": "method", "name": "handle" },
        "steps": [{ "op": "enclosing_decl" }, { "op": "procedure_effects" }]
    }));
    assert_eq!(
        procedure_json.validate_steps().unwrap(),
        QueryValueKind::ProcedureEffect
    );
    assert_eq!(
        procedure_rql.to_canonical_json(),
        procedure_json.to_canonical_json()
    );

    // A summary is keyed on a declaration, so a call-shape upstream is refused.
    let wrong_procedure = CodeQuery::from_json(&json!({
        "match": { "kind": "call", "callee": { "name": "send" } },
        "steps": [{ "op": "call_shape" }, { "op": "procedure_effects" }]
    }))
    .expect_err("procedure_effects must reject a call-shape upstream");
    assert!(
        wrong_procedure.message.contains("requires declaration"),
        "{}",
        wrong_procedure.message
    );

    // Both effect rows reach their file like every other row domain.
    for steps in [
        vec![
            json!({ "op": "call_shape" }),
            json!({ "op": "call_effects" }),
        ],
        vec![
            json!({ "op": "enclosing_decl" }),
            json!({ "op": "procedure_effects" }),
        ],
    ] {
        let mut steps = steps;
        steps.push(json!({ "op": "file_of" }));
        let files = parse_ok(json!({
            "match": { "kind": "method", "name": "handle" },
            "steps": steps
        }));
        assert_eq!(files.validate_steps().unwrap(), QueryValueKind::File);
    }
}

#[test]
fn callable_signature_projects_typed_signature_and_parameter_rows() {
    let signature =
        CodeQuery::from_sexp(r#"(callable-signature (enclosing-decl (method (name "run"))))"#)
            .expect("callable signature RQL");
    assert_eq!(
        signature.validate_steps().unwrap(),
        QueryValueKind::CallableSignature
    );
    assert_eq!(signature.schema_version, SCHEMA_VERSION);

    let parameters = parse_ok(json!({
        "schema_version": SCHEMA_VERSION,
        "match": { "kind": "function", "name": "run" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "callable_signature" },
            { "op": "signature_parameters" }
        ]
    }));
    assert_eq!(
        parameters.validate_steps().unwrap(),
        QueryValueKind::SignatureParameter
    );
    assert_eq!(
        parameters.to_canonical_json()["steps"][2]["op"],
        "signature_parameters"
    );

    let rql = CodeQuery::from_sexp(
        r#"(signature-parameters (callable-signature (enclosing-decl (method (name "run")))))"#,
    )
    .expect("chained callable signature RQL");
    assert_eq!(
        rql.validate_steps().unwrap(),
        QueryValueKind::SignatureParameter
    );

    // The signature step is declaration-shaped, and the parameter projection
    // accepts only its own upstream domain.
    let wrong_upstream = CodeQuery::from_json(&json!({
        "match": { "kind": "function" },
        "steps": [{ "op": "signature_parameters" }]
    }))
    .expect_err("signature_parameters must reject a structural upstream");
    assert!(
        wrong_upstream
            .message
            .contains("requires callable_signature")
    );

    let wrong_signature_upstream = CodeQuery::from_json(&json!({
        "match": { "kind": "call" },
        "steps": [{ "op": "call_shape" }, { "op": "callable_signature" }]
    }))
    .expect_err("callable_signature must reject a call-shape upstream");
    assert!(
        wrong_signature_upstream
            .message
            .contains("requires declaration")
    );

    // A signature row reaches its file like every other row domain.
    let files = parse_ok(json!({
        "match": { "kind": "function", "name": "run" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "callable_signature" },
            { "op": "file_of" }
        ]
    }));
    assert_eq!(files.validate_steps().unwrap(), QueryValueKind::File);
}

#[test]
fn decorator_bindings_projects_parameter_rows_and_accepts_both_frontends() {
    let json = parse_ok(json!({
        "schema_version": SCHEMA_VERSION,
        "match": { "kind": "parameter" },
        "steps": [{ "op": "decorator_bindings" }]
    }));
    assert_eq!(
        json.validate_steps().unwrap(),
        QueryValueKind::DecoratedParameter
    );
    assert_eq!(
        json.to_canonical_json()["steps"][0]["op"],
        "decorator_bindings"
    );

    let sexp =
        CodeQuery::from_sexp("(decorator-bindings (parameter))").expect("decorator-binding RQL");
    assert_eq!(
        sexp.validate_steps().unwrap(),
        QueryValueKind::DecoratedParameter
    );
    assert_eq!(
        sexp.to_canonical_json()["steps"][0]["op"],
        "decorator_bindings"
    );

    let files = parse_ok(json!({
        "match": { "kind": "parameter" },
        "steps": [{ "op": "decorator_bindings" }, { "op": "file_of" }]
    }));
    assert_eq!(files.validate_steps().unwrap(), QueryValueKind::File);

    let wrong_upstream = CodeQuery::from_json(&json!({
        "match": { "kind": "parameter" },
        "steps": [
            { "op": "decorator_bindings" },
            { "op": "decorator_bindings" }
        ]
    }))
    .expect_err("decorator_bindings must consume structural matches");
    assert!(wrong_upstream.message.contains("requires structural_match"));
}

/// The two callable-applicability steps are occurrence-shaped and register the
/// same way every other row domain does: both spellings parse, the value kinds
/// are their own, an upstream that is not an occurrence is refused at the
/// exact step, and both rows reach their file.
#[test]
fn callable_applicability_and_overload_selection_project_occurrence_rows() {
    let applicability =
        CodeQuery::from_sexp(r#"(callable-applicability (occurrences :class reference))"#)
            .expect("callable applicability RQL");
    assert_eq!(
        applicability.validate_steps().unwrap(),
        QueryValueKind::CallableApplicability
    );
    assert_eq!(applicability.schema_version, SCHEMA_VERSION);

    let selection = CodeQuery::from_sexp(r#"(overload-selection (occurrences :class reference))"#)
        .expect("overload selection RQL");
    assert_eq!(
        selection.validate_steps().unwrap(),
        QueryValueKind::OverloadSelection
    );

    let underscored = parse_ok(json!({
        "schema_version": SCHEMA_VERSION,
        "occurrences": { "class": "reference" },
        "steps": [{ "op": "overload_selection" }]
    }));
    assert_eq!(
        underscored.validate_steps().unwrap(),
        QueryValueKind::OverloadSelection
    );
    assert_eq!(
        underscored.to_canonical_json()["steps"][0]["op"],
        "overload_selection"
    );

    // Neither step accepts anything but an occurrence: a call-shape row
    // describes the site's arguments, not the candidates considered for it.
    for op in ["callable_applicability", "overload_selection"] {
        let wrong = CodeQuery::from_json(&json!({
            "match": { "kind": "call" },
            "steps": [{ "op": "call_shape" }, { "op": op }]
        }))
        .unwrap_err();
        assert!(
            wrong.message.contains("requires occurrence"),
            "{op}: {}",
            wrong.message
        );
    }

    for op in ["callable_applicability", "overload_selection"] {
        let files = parse_ok(json!({
            "occurrences": { "class": "reference" },
            "steps": [{ "op": op }, { "op": "file_of" }]
        }));
        assert_eq!(files.validate_steps().unwrap(), QueryValueKind::File);
    }
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
        iterable: Some(Box::new(sub.clone())),
        elements: vec![sub.clone()],
        tag: Some(Box::new(sub.clone())),
        attributes: vec![sub.clone()],
        children: vec![sub.clone()],
        value: Some(Box::new(sub.clone())),
        key: Some(Box::new(sub.clone())),
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
            | Role::Field
            | Role::Iterable
            | Role::Tag
            | Role::Value
            | Role::Key => {
                assert!(pattern.single_role_pattern(role).is_some(), "{role:?}");
                assert!(pattern.list_role_patterns(role).is_empty(), "{role:?}");
            }
            Role::Arg | Role::Decorator | Role::Element | Role::Attributes | Role::Children => {
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
    pattern.elements.clear();
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
        brokk_bifrost_core::analyzer::structural::occurrences::ALL_OCCURRENCE_ROLES.len()
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

#[test]
fn arity_constraint_matches_bounds_inclusively() {
    assert!(ArityConstraint::exact(1).matches(1));
    assert!(!ArityConstraint::exact(1).matches(0));
    assert!(!ArityConstraint::exact(1).matches(2));

    let at_least_one = ArityConstraint {
        min: Some(1),
        max: None,
    };
    assert!(!at_least_one.matches(0));
    assert!(at_least_one.matches(1));
    assert!(at_least_one.matches(9));

    let range = ArityConstraint {
        min: Some(1),
        max: Some(3),
    };
    assert!(!range.matches(0));
    assert!(range.matches(1));
    assert!(range.matches(3));
    assert!(!range.matches(4));

    let at_most_two = ArityConstraint {
        min: None,
        max: Some(2),
    };
    assert!(at_most_two.matches(0));
    assert!(at_most_two.matches(2));
    assert!(!at_most_two.matches(3));
}

#[test]
fn parses_exact_arity_from_json_and_rql() {
    let query = parse_ok(json!({
        "match": { "kind": "call", "callee": { "name": "execute" }, "arity": 1 }
    }));
    let root = &query.seed().expect("structural seed").root;
    assert_eq!(root.arity, Some(ArityConstraint::exact(1)));

    // The inline `:arity` property and the `(arity N)` predicate form both
    // lower to the same exact constraint.
    for source in [
        r#"(call :callee (name "execute") :arity 1)"#,
        r#"(call :callee (name "execute") (arity 1))"#,
    ] {
        let rql = CodeQuery::from_sexp(source).expect("arity RQL should lower");
        assert_eq!(
            rql.seed().expect("structural seed").root.arity,
            Some(ArityConstraint::exact(1)),
            "{source}"
        );
        assert_eq!(
            rql.to_canonical_json()["match"]["arity"],
            json!(1),
            "{source}"
        );
    }
}

#[test]
fn parses_arity_ranges_from_json_and_rql() {
    let cases = [
        (json!({ "min": 1, "max": 3 }), Some(1u32), Some(3u32)),
        (json!({ "min": 2 }), Some(2), None),
        (json!({ "max": 4 }), None, Some(4)),
    ];
    for (spec, min, max) in cases {
        let query = parse_ok(json!({
            "match": { "kind": "call", "arity": spec }
        }));
        assert_eq!(
            query.seed().expect("seed").root.arity,
            Some(ArityConstraint { min, max }),
            "{spec}"
        );
    }

    let range =
        CodeQuery::from_sexp(r#"(call (arity :min 1 :max 3))"#).expect("range RQL should lower");
    assert_eq!(
        range.seed().expect("seed").root.arity,
        Some(ArityConstraint {
            min: Some(1),
            max: Some(3),
        })
    );

    let open_top = CodeQuery::from_sexp(r#"(call (arity :min 1))"#).expect("open-top RQL");
    assert_eq!(
        open_top.seed().expect("seed").root.arity,
        Some(ArityConstraint {
            min: Some(1),
            max: None,
        })
    );
}

#[test]
fn arity_round_trips_through_canonical_json() {
    // Exact stays a bare number; an open-ended or asymmetric range stays an
    // object; a symmetric range collapses to the exact number.
    let range = json!({
        "schema_version": 1,
        "match": { "kind": "call", "arity": { "min": 1, "max": 3 } }
    });
    assert_eq!(
        parse_ok(range.clone()).to_canonical_json()["match"]["arity"],
        range["match"]["arity"]
    );

    let open = json!({ "match": { "kind": "call", "arity": { "min": 2 } } });
    assert_eq!(
        parse_ok(open.clone()).to_canonical_json()["match"]["arity"],
        open["match"]["arity"]
    );

    let symmetric = parse_ok(json!({
        "match": { "kind": "call", "arity": { "min": 2, "max": 2 } }
    }));
    assert_eq!(symmetric.to_canonical_json()["match"]["arity"], json!(2));

    // RQL and JSON exact forms lower to the same IR.
    let rql = CodeQuery::from_sexp(r#"(call :arity 2)"#).expect("rql exact arity");
    let json_query = parse_ok(json!({ "match": { "kind": "call", "arity": 2 } }));
    assert_eq!(rql.to_canonical_json(), json_query.to_canonical_json());
}

#[test]
fn rejects_invalid_arity_specifications() {
    // min greater than max.
    let error = error_of(json!({
        "match": { "kind": "call", "arity": { "min": 3, "max": 1 } }
    }));
    assert_eq!(error.path, "match.arity");
    assert!(error.message.contains("must not exceed"), "{error}");

    // An empty range object constrains nothing.
    let error = error_of(json!({
        "match": { "kind": "call", "arity": {} }
    }));
    assert_eq!(error.path, "match.arity");
    assert!(error.message.contains("at least one"), "{error}");

    // A bound above MAX_ARITY.
    let error = error_of(json!({
        "match": { "kind": "call", "arity": (MAX_ARITY as u64) + 1 }
    }));
    assert_eq!(error.path, "match.arity");
    assert!(error.message.contains("at most"), "{error}");

    // A negative or fractional exact count is not a non-negative integer.
    for bad in [json!(-1), json!(1.5), json!("two")] {
        let error = error_of(json!({
            "match": { "kind": "call", "arity": bad }
        }));
        assert_eq!(error.path, "match.arity", "{bad}");
    }

    // An unknown range key.
    let error = error_of(json!({
        "match": { "kind": "call", "arity": { "exactly": 1 } }
    }));
    assert!(error.path.starts_with("match.arity"), "{error}");

    // The `:arity` property does not take a range; a non-integer is rejected.
    assert!(CodeQuery::from_sexp(r#"(call :arity [1 3])"#).is_err());
    assert!(
        CodeQuery::from_sexp(r#"(arity 1)"#).is_err(),
        "arity alone is not a root anchor"
    );
}
