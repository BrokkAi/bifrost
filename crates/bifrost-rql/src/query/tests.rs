use super::*;
use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::cpp_class_facts::CppClassFactKind;
use brokk_bifrost_core::analyzer::statement_facts::StatementFactKind;
use brokk_bifrost_core::analyzer::structural::control_relation::{
    ControlExitPartition, ControlRelationKind,
};
use brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind;
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
fn cpp_fact_steps_round_trip_across_json_and_rql() {
    let json_query = parse_ok(json!({
        "languages": ["cpp"],
        "match": { "kind": "method", "name": "operator=" },
        "steps": [{
            "op": "cpp_facts",
            "kind": "assignment-does-not-return-this"
        }]
    }));
    assert_eq!(
        json_query.plan.steps,
        vec![QueryStep::CppFacts(
            CppClassFactKind::AssignmentDoesNotReturnThis
        )]
    );

    let rql_query = CodeQuery::from_sexp(
        r#"(language cpp
             (cpp-facts :kind assignment-does-not-return-this
               (method :name "operator=")))"#,
    )
    .expect("C++ fact RQL should lower");
    assert_eq!(
        rql_query.to_canonical_json(),
        json_query.to_canonical_json()
    );
    assert_eq!(
        json_query.to_canonical_json()["steps"][0],
        json!({
            "op": "cpp_facts",
            "kind": "assignment-does-not-return-this"
        })
    );

    let invalid = error_of(json!({
        "match": { "kind": "method" },
        "steps": [{ "op": "cpp_facts", "kind": "not-a-cpp-fact" }]
    }));
    assert_eq!(invalid.path, "steps[0].kind");
    assert!(invalid.message.contains("assignment-does-not-return-this"));

    let internal_label = error_of(json!({
        "match": { "kind": "method" },
        "steps": [{
            "op": "cpp_facts",
            "cpp_fact_kind": "assignment-does-not-return-this"
        }]
    }));
    assert_eq!(internal_label.path, "steps[0].cpp_fact_kind");
}

#[test]
fn capture_anchor_step_round_trips_and_requires_a_declared_capture() {
    let json_query = parse_ok(json!({
        "languages": ["python"],
        "match": {
            "kind": "if",
            "test": { "kind": "literal", "capture": "condition" }
        },
        "steps": [{ "op": "anchor", "capture": "condition" }]
    }));
    assert_eq!(
        json_query.plan.steps,
        vec![QueryStep::CaptureAnchor("condition".to_owned())]
    );

    let rql_query = CodeQuery::from_sexp(
        r#"(anchor :capture "condition"
             (language python
               (if :test (literal :capture "condition"))))"#,
    )
    .expect("capture anchor RQL should lower");
    assert_eq!(
        rql_query.to_canonical_json(),
        json_query.to_canonical_json()
    );

    let missing_capture = error_of(json!({
        "languages": ["python"],
        "match": { "kind": "if" },
        "steps": [{ "op": "anchor", "capture": "condition" }]
    }));
    assert_eq!(missing_capture.path, "steps[0].capture");
    assert!(missing_capture.message.contains("not declared"));
}

#[test]
fn statement_fact_steps_and_language_rules_round_trip_across_json_and_rql() {
    let json_query = parse_ok(json!({
        "languages": ["csharp"],
        "match": {
            "kind": "assignment",
            "language_rule": "cs/static-array"
        },
        "steps": [{
            "op": "statement_facts",
            "statement_fact_kind": "nested-loops-with-same-variable"
        }]
    }));
    assert_eq!(
        json_query.plan.steps,
        vec![QueryStep::StatementFacts(
            StatementFactKind::NestedLoopsWithSameVariable
        )]
    );

    let rql_query = CodeQuery::from_sexp(
        r#"(language csharp
             (statement-facts :kind nested-loops-with-same-variable
               (assignment :language-rule "cs/static-array")))"#,
    )
    .expect("statement fact and language rule RQL should lower");
    assert_eq!(
        rql_query.to_canonical_json(),
        json_query.to_canonical_json()
    );
    assert_eq!(
        json_query.to_canonical_json()["steps"][0],
        json!({
            "op": "statement_facts",
            "statement_fact_kind": "nested-loops-with-same-variable"
        })
    );
    assert_eq!(
        json_query.to_canonical_json()["match"]["language_rule"],
        "cs/static-array"
    );
}

#[test]
fn keyed_read_value_accepts_exact_and_static_key_family_selectors() {
    let exact = parse_ok(json!({
        "match": { "kind": "call" },
        "steps": [{
            "op": "keyed_read_value",
            "runtime": "node",
            "global": "process",
            "container": "env",
            "property": "TOKEN"
        }]
    }));
    assert_eq!(
        exact.plan.steps,
        vec![QueryStep::KeyedReadValue(KeyedReadValueTraversal::new(
            "node".to_owned(),
            "process".to_owned(),
            "env".to_owned(),
            KeyedReadKeySelector::ExactProperty("TOKEN".to_owned()),
            false,
        ))]
    );

    let family = parse_ok(json!({
        "match": { "kind": "call" },
        "steps": [{
            "op": "keyed_read_value",
            "runtime": "node",
            "global": "process",
            "container": "argv",
            "key_kind": "static-index",
            "index_min": 1,
            "index_max": 3
        }]
    }));
    assert_eq!(
        family.plan.steps,
        vec![QueryStep::KeyedReadValue(KeyedReadValueTraversal::new(
            "node".to_owned(),
            "process".to_owned(),
            "argv".to_owned(),
            KeyedReadKeySelector::StaticIndexRange {
                min: Some(1),
                max: Some(3),
            },
            false,
        ))]
    );
    assert_eq!(
        family.to_canonical_json()["steps"][0],
        json!({
            "op": "keyed_read_value",
            "runtime": "node",
            "global": "process",
            "container": "argv",
            "key_kind": "static-index",
            "index_min": 1,
            "index_max": 3
        })
    );

    for spelling in ["keyed-read-value", "keyed_read_value"] {
        let source = format!(
            "({spelling} :runtime node :global process :container argv :key-kind static-index :index-min 1 :index-max 3 (call))"
        );
        let rql = CodeQuery::from_sexp(&source).expect("key family RQL should lower");
        assert_eq!(rql.to_canonical_json(), family.to_canonical_json());
    }
}

#[test]
fn keyed_read_value_rejects_mixed_selector_modes_and_invalid_bounds() {
    let mixed = error_of(json!({
        "match": { "kind": "call" },
        "steps": [{
            "op": "keyed_read_value",
            "runtime": "node",
            "global": "process",
            "container": "env",
            "property": "TOKEN",
            "key_kind": "static-property"
        }]
    }));
    assert!(
        mixed
            .message
            .contains("either one exact property/index or key_kind")
    );

    let wrong_bounds = error_of(json!({
        "match": { "kind": "call" },
        "steps": [{
            "op": "keyed_read_value",
            "runtime": "node",
            "global": "process",
            "container": "env",
            "key_kind": "static-property",
            "index_min": 1
        }]
    }));
    assert!(
        wrong_bounds
            .message
            .contains("index bounds require key_kind static-index")
    );

    let reversed = error_of(json!({
        "match": { "kind": "call" },
        "steps": [{
            "op": "keyed_read_value",
            "runtime": "node",
            "global": "process",
            "container": "argv",
            "key_kind": "static-index",
            "index_min": 4,
            "index_max": 2
        }]
    }));
    assert_eq!(reversed.path, "steps[0].index_min");

    let out_of_range_min = error_of(json!({
        "match": { "kind": "call" },
        "steps": [{
            "op": "keyed_read_value",
            "runtime": "node",
            "global": "process",
            "container": "argv",
            "key_kind": "static-index",
            "index_min": 4294967295u64
        }]
    }));
    assert_eq!(out_of_range_min.path, "steps[0].index_min");
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
            annotation_type: None,
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

    let annotation_query = parse_ok(json!({
        "match": { "kind": "parameter" },
        "steps": [{
            "op": "decorator_bindings",
            "annotation_type": "org.springframework.web.bind.annotation.RequestParam"
        }]
    }));
    assert_eq!(
        annotation_query.plan.steps[0],
        QueryStep::DecoratorBindings(DecoratorBindingFilter {
            module: None,
            imported_name: None,
            annotation_type: Some(
                "org.springframework.web.bind.annotation.RequestParam".to_string()
            ),
        })
    );
    assert_eq!(
        CodeQuery::from_sexp(
            r#"(decorator-bindings :annotation-type "org.springframework.web.bind.annotation.RequestParam" (parameter))"#,
        )
        .expect("annotation type filter should lower")
        .to_canonical_json(),
        annotation_query.to_canonical_json()
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
fn row_filter_and_projection_round_trip_across_rql_and_json() {
    let rql = CodeQuery::from_sexp(
        r#"(project :columns (id (target_count candidates) role)
              (filter :where (
                (class in [reference declaration])
                (target_count ge 0)
                (target_count le (field target_count))
                (target_id is-not-null)
                (id ne "missing"))
                (occurrences)))"#,
    )
    .expect("typed row steps should parse");
    let canonical = json!({
        "schema_version": "1",
        "occurrences": {},
        "steps": [
            {
                "op": "filter",
                "where": [
                    {
                        "field": "class",
                        "op": "in",
                        "values": [{ "enum": "reference" }, { "enum": "declaration" }]
                    },
                    {
                        "field": "target_count",
                        "op": "ge",
                        "value": { "integer": 0 }
                    },
                    {
                        "field": "target_count",
                        "op": "le",
                        "value": { "field": "target_count" }
                    },
                    { "field": "target_id", "op": "is_not_null" },
                    {
                        "field": "id",
                        "op": "ne",
                        "value": { "string": "missing" }
                    }
                ]
            },
            {
                "op": "project",
                "columns": [
                    { "source": "id", "name": "id" },
                    { "source": "target_count", "name": "candidates" },
                    { "source": "role", "name": "role" }
                ]
            }
        ],
        "limit": 100,
        "result_detail": "compact",
        "execution_mode": "results"
    });

    assert_eq!(rql.to_canonical_json(), canonical);
    assert_eq!(parse_ok(canonical.clone()).to_canonical_json(), canonical);
}

#[test]
fn python_import_site_fields_are_typed_and_filterable() {
    let query = parse_ok(json!({
        "match": { "kind": "import" },
        "steps": [
            { "op": "python_import_site" },
            {
                "op": "filter",
                "where": [
                    {
                        "field": "python_import_module",
                        "op": "eq",
                        "value": { "string": "helper" }
                    },
                    {
                        "field": "python_import_form",
                        "op": "eq",
                        "value": { "enum": "from" }
                    },
                    {
                        "field": "python_import_polluting",
                        "op": "eq",
                        "value": { "boolean": true }
                    }
                ]
            }
        ]
    }));
    assert_eq!(
        query.plan.steps,
        vec![
            QueryStep::PythonImportSite,
            QueryStep::Filter(vec![
                QueryRowPredicate {
                    field: "python_import_module".to_string(),
                    op: QueryRowPredicateOp::Eq,
                    operand: QueryRowPredicateOperand::Literal(QueryRowLiteral::String(
                        "helper".to_string()
                    )),
                },
                QueryRowPredicate {
                    field: "python_import_form".to_string(),
                    op: QueryRowPredicateOp::Eq,
                    operand: QueryRowPredicateOperand::Literal(QueryRowLiteral::ConstrainedEnum(
                        "from".to_string()
                    ),),
                },
                QueryRowPredicate {
                    field: "python_import_polluting".to_string(),
                    op: QueryRowPredicateOp::Eq,
                    operand: QueryRowPredicateOperand::Literal(QueryRowLiteral::Boolean(true)),
                },
            ]),
        ]
    );
    assert_eq!(
        query.to_canonical_json()["steps"][0],
        json!({ "op": "python_import_site" })
    );
    let rql = CodeQuery::from_sexp("(python-import-site (import :module \"helper\"))")
        .expect("hyphenated Python import-site RQL wrapper");
    assert_eq!(rql.plan.steps, vec![QueryStep::PythonImportSite]);
    assert_eq!(
        rql.to_canonical_json()["steps"][0],
        json!({ "op": "python_import_site" })
    );

    let error = error_of(json!({
        "match": { "kind": "import" },
        "steps": [
            { "op": "python_import_site" },
            {
                "op": "filter",
                "where": [{
                    "field": "python_import_form",
                    "op": "eq",
                    "value": { "enum": "import_from" }
                }]
            }
        ]
    }));
    assert!(
        error
            .message
            .contains("not a value of `python_import_form`")
    );
}

#[test]
fn python_import_cycles_register_both_query_spellings_and_typed_cycle_state() {
    let json_query = parse_ok(json!({
        "match": { "kind": "import" },
        "steps": [
            { "op": "python_import_cycles" },
            {
                "op": "filter",
                "where": [{
                    "field": "python_import_cycle_state",
                    "op": "eq",
                    "value": { "enum": "incomplete" }
                }]
            }
        ]
    }));
    assert_eq!(json_query.plan.steps[0], QueryStep::PythonImportCycles);
    assert_eq!(
        json_query.to_canonical_json()["steps"][0],
        json!({ "op": "python_import_cycles" })
    );

    let sexp_query = CodeQuery::from_sexp(
        "(python-import-cycles (language python (import :module \"helper\")))",
    )
    .expect("hyphenated cycle relation wrapper");
    assert_eq!(sexp_query.plan.steps, vec![QueryStep::PythonImportCycles]);
    assert_eq!(
        sexp_query.to_canonical_json()["steps"][0],
        json!({ "op": "python_import_cycles" })
    );
}

#[test]
fn python_unsafe_cyclic_import_registers_json_and_sexp_wrappers() {
    let json_query = parse_ok(json!({
        "match": { "kind": "field_access" },
        "steps": [{ "op": "python_unsafe_cyclic_import" }]
    }));
    assert_eq!(
        json_query.plan.steps,
        vec![QueryStep::PythonUnsafeCyclicImport]
    );
    assert_eq!(
        json_query.to_canonical_json()["steps"][0],
        json!({ "op": "python_unsafe_cyclic_import" })
    );

    let sexp_query =
        CodeQuery::from_sexp("(python-unsafe-cyclic-import (language python (field_access)))")
            .expect("hyphenated unsafe-cycle wrapper");
    assert_eq!(
        sexp_query.plan.steps,
        vec![QueryStep::PythonUnsafeCyclicImport]
    );
    assert_eq!(
        sexp_query.to_canonical_json()["steps"][0],
        json!({ "op": "python_unsafe_cyclic_import" })
    );
}

#[test]
fn row_steps_validate_public_types_domains_and_projected_schema() {
    for (step, path, message) in [
        (
            json!({
                "op": "filter",
                "where": [{
                    "field": "target_count",
                    "op": "eq",
                    "value": { "string": "one" }
                }]
            }),
            "steps[0].where[0].value",
            "does not match",
        ),
        (
            json!({
                "op": "filter",
                "where": [{
                    "field": "role",
                    "op": "eq",
                    "value": { "enum": "Reference" }
                }]
            }),
            "steps[0].where[0].value",
            "is not a value of `role`; the accepted values are",
        ),
        (
            json!({
                "op": "filter",
                "where": [{ "field": "id", "op": "is_null" }]
            }),
            "steps[0].where[0]",
            "not nullable",
        ),
        (
            json!({
                "op": "project",
                "columns": [
                    { "source": "id", "name": "key" },
                    { "source": "ast_id", "name": "key" }
                ]
            }),
            "steps[0].columns[1].name",
            "duplicate projected row field",
        ),
    ] {
        let error = error_of(json!({
            "occurrences": {},
            "steps": [step]
        }));
        assert_eq!(error.path, path);
        assert!(error.message.contains(message), "{error:?}");
    }

    let error = error_of(json!({
        "occurrences": {},
        "steps": [
            {
                "op": "project",
                "columns": [{ "source": "target_count", "name": "count" }]
            },
            {
                "op": "filter",
                "where": [{
                    "field": "target_count",
                    "op": "ge",
                    "value": { "integer": 1 }
                }]
            }
        ]
    }));
    assert_eq!(error.path, "steps[1].where[0].field");
    assert!(error.message.contains("count"), "{error:?}");
}

#[test]
fn set_branches_require_the_same_visible_projected_row_schema() {
    let branch = |name: &str| {
        json!({
            "occurrences": { "class": "reference" },
            "steps": [{
                "op": "project",
                "columns": [{ "source": "target_count", "name": name }]
            }]
        })
    };
    let compatible = parse_ok(json!({
        "union": [branch("count"), branch("count")],
        "steps": [{
            "op": "filter",
            "where": [{
                "field": "count",
                "op": "ge",
                "value": { "integer": 1 }
            }]
        }]
    }));
    assert_eq!(compatible.validate_row_fields().unwrap().1[0].0, "count");

    let incompatible = error_of(json!({
        "union": [branch("count"), branch("total")]
    }));
    assert_eq!(incompatible.path, "union[1]");
    assert!(
        incompatible.message.contains("row schema"),
        "{incompatible:?}"
    );
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
    assert_eq!(query.to_canonical_json()["schema_version"], json!("1"));
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
    assert_eq!(
        query.to_canonical_json()["schema_version"],
        SCHEMA_VERSION.to_string()
    );

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
fn points_to_candidate_rows_parse_from_json_and_both_rql_spellings() {
    let json_query = parse_ok(json!({
        "match": {
            "kind": "call",
            "receiver": { "capture": "service" }
        },
        "steps": [
            { "op": "points_to", "capture": "service" },
            { "op": "points_to_candidates" }
        ]
    }));
    assert_eq!(
        json_query.validate_steps().unwrap(),
        QueryValueKind::PointsToCandidate
    );
    assert_eq!(
        json_query.to_canonical_json()["steps"],
        json!([
            { "op": "points_to", "capture": "service" },
            { "op": "points_to_candidates" }
        ])
    );

    for spelling in ["points-to-candidates", "points_to_candidates"] {
        let source = format!(
            r#"({spelling} (points-to :capture service (call :receiver (capture "service"))))"#
        );
        let rql = CodeQuery::from_sexp(&source).expect("candidate row RQL should lower");
        assert_eq!(rql.to_canonical_json(), json_query.to_canonical_json());
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
fn duplicate_dictionary_key_predicate_parses_and_canonicalizes() {
    let json_query = parse_ok(json!({
        "match": {
            "kind": "object_property",
            "duplicate_key": true
        }
    }));
    assert_eq!(json_query.seed().unwrap().root.duplicate_key, Some(true));
    assert_eq!(
        json_query.to_canonical_json()["match"]["duplicate_key"],
        json!(true)
    );

    for source in [
        "(object_property :duplicate-key true)",
        "(object_property :duplicate_key true)",
        "(object_property (duplicate-key true))",
        "(object_property (duplicate_key true))",
    ] {
        let rql = CodeQuery::from_sexp(source).expect("duplicate-key RQL should lower");
        assert_eq!(rql.to_canonical_json(), json_query.to_canonical_json());
    }

    let error = error_of(json!({
        "match": { "kind": "object_property", "duplicate_key": "yes" }
    }));
    assert_eq!(error.path, "match.duplicate_key");
    assert_eq!(error.message, "expected a boolean literal");
    assert!(CodeQuery::from_sexp("(object_property :duplicate-key 1)").is_err());
}

#[test]
fn exact_ordered_role_index_parses_and_canonicalizes() {
    let json_query = parse_ok(json!({
        "match": {
            "kind": "collection_literal",
            "elements": [{ "kind": "string_literal", "index": 1 }]
        }
    }));
    let root = &json_query.seed().expect("seed").root;
    assert_eq!(root.elements[0].index, Some(1));
    assert_eq!(
        json_query.to_canonical_json()["match"]["elements"][0]["index"],
        json!(1)
    );

    for source in [
        r#"(collection_literal :elements [(string_literal :index 1)])"#,
        r#"(collection_literal :elements [(string_literal (index 1))])"#,
    ] {
        let rql = CodeQuery::from_sexp(source).expect("indexed RQL should lower");
        assert_eq!(rql.to_canonical_json(), json_query.to_canonical_json());
    }

    for invalid in [
        json!({ "match": { "kind": "collection_literal", "index": 1 } }),
        json!({
            "match": {
                "kind": "collection_literal",
                "elements": [{ "kind": "string_literal", "index": -1 }]
            }
        }),
        json!({
            "match": {
                "kind": "collection_literal",
                "elements": [{ "kind": "string_literal", "index": (MAX_ARITY as u64) + 1 }]
            }
        }),
    ] {
        let error = error_of(invalid);
        assert!(error.path.ends_with("index"), "{error:?}");
    }
    assert!(CodeQuery::from_sexp("(collection_literal :index 1)").is_err());
}

#[test]
fn string_literal_parenthesization_parses_and_canonicalizes() {
    let json_query = parse_ok(json!({
        "match": { "kind": "string_literal", "parenthesized": true }
    }));
    assert_eq!(json_query.seed().unwrap().root.parenthesized, Some(true));
    for source in [
        "(string_literal :parenthesized true)",
        "(string_literal (parenthesized true))",
    ] {
        let rql = CodeQuery::from_sexp(source).expect("parenthesized RQL should lower");
        assert_eq!(rql.to_canonical_json(), json_query.to_canonical_json());
    }
    let error = error_of(json!({
        "match": { "kind": "string_literal", "parenthesized": "yes" }
    }));
    assert_eq!(error.path, "match.parenthesized");
}

#[test]
fn integer_literal_values_and_bit_masks_parse_and_canonicalize() {
    let json_query = parse_ok(json!({
        "match": {
            "kind": "numeric_literal",
            "integer_value": "340282366920938463463374607431768211455",
            "integer_has_any_bits": 2,
            "integer_has_all_bits": 3,
            "integer_has_no_bits": 4
        }
    }));
    let pattern = &json_query.seed().unwrap().root;
    assert_eq!(
        pattern.integer_value.as_deref(),
        Some("340282366920938463463374607431768211455")
    );
    assert_eq!(pattern.integer_has_any_bits, Some(2));
    assert_eq!(pattern.integer_has_all_bits, Some(3));
    assert_eq!(pattern.integer_has_no_bits, Some(4));

    for source in [
        r#"(numeric_literal :integer-value "340282366920938463463374607431768211455" :integer-has-any-bits 2 :integer-has-all-bits 3 :integer-has-no-bits 4)"#,
        r#"(numeric_literal (integer-value "340282366920938463463374607431768211455") (integer-has-any-bits 2) (integer-has-all-bits 3) (integer-has-no-bits 4))"#,
    ] {
        let rql = CodeQuery::from_sexp(source).expect("integer-value RQL should lower");
        assert_eq!(rql.to_canonical_json(), json_query.to_canonical_json());
    }

    for (invalid, path) in [
        (
            json!({ "match": { "kind": "numeric_literal", "integer_value": "0511" } }),
            "match.integer_value",
        ),
        (
            json!({ "match": { "kind": "numeric_literal", "integer_has_any_bits": 0 } }),
            "match.integer_has_any_bits",
        ),
        (
            json!({ "match": { "kind": "numeric_literal", "integer_has_no_bits": (u32::MAX as u64) + 1 } }),
            "match.integer_has_no_bits",
        ),
    ] {
        let error = error_of(invalid);
        assert_eq!(error.path, path);
    }
    assert!(CodeQuery::from_sexp("(numeric_literal :integer-value 511)").is_err());
    assert!(CodeQuery::from_sexp("(numeric_literal :integer-has-all-bits 0)").is_err());
}

#[test]
fn assignment_shape_fields_parse_and_canonicalize() {
    let json_query = parse_ok(json!({
        "match": {
            "kind": "assignment",
            "assignment_target_kind": "tuple",
            "assignment_value_kind": "list",
            "assignment_target_unstarred_count": 2,
            "assignment_value_unstarred_count": 3,
            "assignment_target_starred": false,
            "assignment_value_starred": false,
            "assignment_unstarred_count_mismatch": true
        }
    }));
    let pattern = &json_query.seed().unwrap().root;
    assert_eq!(pattern.assignment_target_kind.unwrap().label(), "tuple");
    assert_eq!(pattern.assignment_value_kind.unwrap().label(), "list");
    assert_eq!(pattern.assignment_target_unstarred_count, Some(2));
    assert_eq!(pattern.assignment_value_unstarred_count, Some(3));
    assert_eq!(pattern.assignment_target_starred, Some(false));
    assert_eq!(pattern.assignment_value_starred, Some(false));
    assert_eq!(pattern.assignment_unstarred_count_mismatch, Some(true));

    for source in [
        "(assignment :assignment-target-kind tuple :assignment-value-kind list :assignment-target-unstarred-count 2 :assignment-value-unstarred-count 3 :assignment-target-starred false :assignment-value-starred false :assignment-unstarred-count-mismatch true)",
        "(assignment (assignment-target-kind tuple) (assignment-value-kind list) (assignment-target-unstarred-count 2) (assignment-value-unstarred-count 3) (assignment-target-starred false) (assignment-value-starred false) (assignment-unstarred-count-mismatch true))",
    ] {
        let rql = CodeQuery::from_sexp(source).expect("assignment shape RQL should lower");
        assert_eq!(rql.to_canonical_json(), json_query.to_canonical_json());
    }

    for (invalid, path) in [
        (
            json!({ "match": { "kind": "assignment", "assignment_target_kind": "array" } }),
            "match.assignment_target_kind",
        ),
        (
            json!({ "match": { "kind": "assignment", "assignment_target_unstarred_count": -1 } }),
            "match.assignment_target_unstarred_count",
        ),
        (
            json!({ "match": { "kind": "assignment", "assignment_value_unstarred_count": (MAX_ARITY as u64) + 1 } }),
            "match.assignment_value_unstarred_count",
        ),
    ] {
        assert_eq!(error_of(invalid).path, path);
    }
}

#[test]
fn async_callable_and_await_patterns_canonicalize_with_point_projection() {
    let async_query = CodeQuery::from_json(&json!({
        "match": { "kind": "function", "async": true }
    }))
    .expect("async callable query");
    assert_eq!(async_query.seed().unwrap().root.is_async, Some(true));
    assert_eq!(
        async_query.to_canonical_json()["match"]["async"],
        json!(true)
    );
    for source in ["(function :async true)", "(function (async true))"] {
        let parsed = CodeQuery::from_sexp(source).expect("async predicate should lower");
        assert_eq!(parsed.to_canonical_json(), async_query.to_canonical_json());
    }
    let false_query = CodeQuery::from_sexp("(function :async false)")
        .expect("sync callable predicate should lower");
    assert_eq!(
        false_query.to_canonical_json()["match"]["async"],
        json!(false)
    );

    let await_query =
        CodeQuery::from_sexp("(program-point-of (await))").expect("await point query should lower");
    assert_eq!(
        await_query.seed().unwrap().root.kinds,
        vec![NormalizedKind::Await]
    );
    assert_eq!(
        await_query.plan.steps[0].output_kind(QueryValueKind::StructuralMatch),
        Some(QueryValueKind::ProgramPoint)
    );
    assert_eq!(
        await_query.to_canonical_json()["steps"][0]["op"],
        json!("program_point_of")
    );

    for invalid in [
        json!({ "match": { "kind": "await", "async": true } }),
        json!({ "match": { "kind": "function", "async": "true" } }),
    ] {
        assert!(CodeQuery::from_json(&invalid).is_err());
    }
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
fn parses_and_rejects_schema_version() {
    let query = parse_ok(json!({
        "schema_version": 1,
        "match": { "kind": "call" }
    }));
    assert_eq!(query.schema_version, 1);
    assert_eq!(query.to_canonical_json()["schema_version"], "1");

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

    let error = error_of(json!({
        "schema_version": 1,
        "match": { "kind": "function" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "class_set" },
            { "op": "witness" }
        ]
    }));
    assert!(error.message.contains("absent_member_finding"), "{error:?}");
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

#[test]
fn switch_coverage_steps_parse_and_lower_from_both_frontends() {
    let query = parse_ok(json!({
        "schema_version": 1,
        "match": { "kind": "function", "name": "coverage" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "switch_coverage" }
        ]
    }));
    assert_eq!(
        query.plan.steps,
        vec![QueryStep::ProcedureOf, QueryStep::SwitchCoverage]
    );
    assert_eq!(
        query.validate_steps().unwrap(),
        QueryValueKind::SwitchCoverage
    );

    let rql =
        CodeQuery::from_sexp("(switch-coverage (procedure-of (function :name \"coverage\")))")
            .expect("switch coverage RQL should lower");
    assert_eq!(rql.schema_version, SCHEMA_VERSION);
    assert_eq!(rql.plan.steps, query.plan.steps);
    assert_eq!(rql.to_canonical_json(), query.to_canonical_json());
}

#[test]
fn assignment_relation_steps_parse_and_lower_from_both_frontends() {
    let query = parse_ok(json!({
        "schema_version": 1,
        "match": { "kind": "function", "name": "assign" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "assignment_relations" }
        ]
    }));
    assert_eq!(
        query.plan.steps,
        vec![
            QueryStep::ProcedureOf,
            QueryStep::AssignmentRelations(AssignmentRelationFilter::default())
        ]
    );
    assert_eq!(
        query.validate_steps().unwrap(),
        QueryValueKind::AssignmentRelation
    );

    let rql =
        CodeQuery::from_sexp("(assignment-relations (procedure-of (function :name \"assign\")))")
            .expect("assignment relation RQL should lower");
    assert_eq!(rql.schema_version, SCHEMA_VERSION);
    assert_eq!(rql.plan.steps, query.plan.steps);
    assert_eq!(rql.to_canonical_json(), query.to_canonical_json());

    let swap = parse_ok(json!({
        "schema_version": 1,
        "match": { "kind": "function", "name": "assign" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "assignment_relations", "assignment_relation": ["failed_swap"] }
        ]
    }));
    let swap_rql = CodeQuery::from_sexp(
        "(assignment-relations :relation [failed-swap] (procedure-of (function :name \"assign\")))",
    )
    .expect("selected assignment relation RQL should lower");
    assert_eq!(swap_rql.plan.steps, swap.plan.steps);
    assert_eq!(swap_rql.to_canonical_json(), swap.to_canonical_json());
}

#[test]
fn loop_relation_step_parses_from_json_and_rql() {
    let json = parse_ok(json!({
        "schema_version": 1,
        "match": { "kind": "function", "name": "check" },
        "steps": [{ "op": "procedure_of" }, { "op": "loop_relations" }]
    }));
    assert_eq!(
        json.plan.steps,
        vec![QueryStep::ProcedureOf, QueryStep::LoopRelations]
    );
    assert_eq!(json.validate_steps().unwrap(), QueryValueKind::LoopRelation);
    let rql = CodeQuery::from_sexp("(loop-relations (procedure-of (function :name \"check\")))")
        .expect("Java loop relation RQL should lower");
    assert_eq!(rql.to_canonical_json(), json.to_canonical_json());
}

#[test]
fn statement_reachability_step_parses_from_json_and_rql() {
    let json = parse_ok(json!({
        "schema_version": 1,
        "match": { "kind": "function", "name": "check" },
        "steps": [{ "op": "procedure_of" }, { "op": "statement_reachability" }]
    }));
    assert_eq!(
        json.plan.steps,
        vec![QueryStep::ProcedureOf, QueryStep::StatementReachability]
    );
    assert_eq!(
        json.validate_steps().unwrap(),
        QueryValueKind::StatementReachability
    );
    let rql =
        CodeQuery::from_sexp("(statement-reachability (procedure-of (function :name \"check\")))")
            .expect("statement reachability RQL should lower");
    assert_eq!(rql.to_canonical_json(), json.to_canonical_json());
}

#[test]
fn pending_cleanup_flow_step_parses_from_json_and_rql() {
    let json = parse_ok(json!({
        "schema_version": 1,
        "match": { "kind": "function", "name": "check" },
        "steps": [{ "op": "procedure_of" }, { "op": "pending_cleanup_flows" }]
    }));
    assert_eq!(
        json.plan.steps,
        vec![QueryStep::ProcedureOf, QueryStep::PendingCleanupFlows]
    );
    assert_eq!(
        json.validate_steps().unwrap(),
        QueryValueKind::PendingCleanupFlow
    );
    let rql =
        CodeQuery::from_sexp("(pending-cleanup-flows (procedure-of (function :name \"check\")))")
            .expect("pending cleanup flow RQL should lower");
    assert_eq!(rql.to_canonical_json(), json.to_canonical_json());
}

#[test]
fn class_set_and_absent_member_steps_parse_and_lower_from_both_frontends() {
    let query = parse_ok(json!({
        "schema_version": 1,
        "match": { "kind": "function", "name": "read_config" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "class_set" }
        ]
    }));
    assert_eq!(
        query.plan.steps,
        vec![QueryStep::ProcedureOf, QueryStep::ClassSet]
    );
    assert_eq!(query.validate_steps().unwrap(), QueryValueKind::ClassSetRow);

    for spelling in ["class-set", "class_set"] {
        let rql = CodeQuery::from_sexp(&format!(
            "({spelling} (procedure-of (function :name \"read_config\")))"
        ))
        .expect("class-set RQL should lower");
        assert_eq!(rql.schema_version, SCHEMA_VERSION);
        assert_eq!(rql.to_canonical_json(), query.to_canonical_json());
    }

    let finding = parse_ok(json!({
        "schema_version": 1,
        "match": { "kind": "function", "name": "read_config" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "absent_member" }
        ]
    }));
    assert_eq!(
        finding.plan.steps,
        vec![
            QueryStep::ProcedureOf,
            QueryStep::AbsentMember(AbsentMemberProofFilter::Proven)
        ]
    );
    assert_eq!(
        finding.validate_steps().unwrap(),
        QueryValueKind::AbsentMemberFinding
    );

    let witness = parse_ok(json!({
        "schema_version": 1,
        "match": { "kind": "function", "name": "read_config" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "absent_member" },
            { "op": "witness", "max_steps": 12, "max_bytes": 4096 }
        ]
    }));
    assert_eq!(
        witness.plan.steps,
        vec![
            QueryStep::ProcedureOf,
            QueryStep::AbsentMember(AbsentMemberProofFilter::Proven),
            QueryStep::Witness(WitnessTraversal {
                max_steps: Some(12),
                max_bytes: Some(4096),
            })
        ]
    );
    assert_eq!(
        witness.validate_steps().unwrap(),
        QueryValueKind::AbsentMemberWitness
    );
    assert_eq!(
        CodeQuery::from_sexp(
            "(witness :max-steps 12 :max-bytes 4096 (absent-member (procedure-of (function :name \"read_config\"))))"
        )
        .expect("absent-member witness RQL should lower")
        .to_canonical_json(),
        witness.to_canonical_json()
    );

    for spelling in ["absent-member", "absent_member"] {
        let rql = CodeQuery::from_sexp(&format!(
            "({spelling} (procedure-of (function :name \"read_config\")))"
        ))
        .expect("absent-member RQL should lower");
        assert_eq!(rql.to_canonical_json(), finding.to_canonical_json());
    }

    // Both steps type only over procedures: a structural-match input is
    // refused with the expected-input description.
    let error = error_of(json!({
        "match": { "kind": "class" },
        "steps": [{ "op": "class_set" }]
    }));
    assert!(error.message.contains("procedure"), "{error:?}");
}

#[test]
fn absent_member_proof_filter_parses_from_both_frontends_and_omits_the_default() {
    for proof in AbsentMemberProofFilter::ALL {
        let query = parse_ok(json!({
            "schema_version": 1,
            "match": { "kind": "function", "name": "check" },
            "steps": [
                { "op": "procedure_of" },
                { "op": "absent_member", "finding_proof": proof.label() }
            ]
        }));
        assert_eq!(
            query.plan.steps,
            vec![QueryStep::ProcedureOf, QueryStep::AbsentMember(proof)]
        );
        let rql = CodeQuery::from_sexp(&format!(
            "(absent-member :proof {} (procedure-of (function :name \"check\")))",
            proof.label()
        ))
        .expect("absent-member proof RQL should lower");
        assert_eq!(rql.to_canonical_json(), query.to_canonical_json());
        // The default tier is not spelled in canonical JSON, so a query
        // written before the filter existed keeps its canonical form.
        let canonical = query.to_canonical_json();
        let step = &canonical["steps"][1];
        assert_eq!(
            step.get("finding_proof").is_some(),
            proof != AbsentMemberProofFilter::Proven,
            "{canonical}"
        );
        assert_eq!(parse_ok(canonical.clone()).plan.steps, query.plan.steps);
    }
    let unknown = error_of(json!({
        "match": { "kind": "function" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "absent_member", "finding_proof": "unproven" }
        ]
    }));
    assert_eq!(unknown.path, "steps[1].finding_proof");
    assert!(unknown.message.contains("conditional"), "{unknown:?}");
    // The option belongs to absent_member alone.
    let borrowed = error_of(json!({
        "match": { "kind": "function" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "class_set", "finding_proof": "any" }
        ]
    }));
    assert_eq!(borrowed.path, "steps[1].finding_proof");
    for source in [
        "(absent-member :proof unproven (procedure-of (function)))",
        "(absent-member :tier any (procedure-of (function)))",
        "(absent-member :proof any :proof proven (procedure-of (function)))",
    ] {
        assert!(CodeQuery::from_sexp(source).is_err(), "{source}");
    }
}

#[test]
fn detached_task_transfer_steps_parse_and_lower_from_both_frontends() {
    let query = parse_ok(json!({
        "schema_version": 1,
        "match": { "kind": "function", "name": "spawn" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "detached_task_transfers" }
        ]
    }));
    assert_eq!(
        query.plan.steps,
        vec![QueryStep::ProcedureOf, QueryStep::DetachedTaskTransfers]
    );
    assert_eq!(
        query.validate_steps().unwrap(),
        QueryValueKind::DetachedTaskTransfer
    );

    let rql =
        CodeQuery::from_sexp("(detached-task-transfers (procedure-of (function :name \"spawn\")))")
            .expect("detached task transfer RQL should lower");
    assert_eq!(rql.to_canonical_json(), query.to_canonical_json());
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
fn rust_pointer_findings_parse_and_round_trip() {
    let json_query = parse_ok(json!({
        "schema_version": 1,
        "languages": ["rust"],
        "match": { "kind": "function", "name": "run" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "rust_pointer_findings" }
        ]
    }));
    assert_eq!(
        json_query.plan.steps,
        vec![QueryStep::ProcedureOf, QueryStep::RustPointerFindings]
    );
    assert_eq!(
        json_query.validate_steps().unwrap(),
        QueryValueKind::RustPointerFinding
    );

    let rql_query = CodeQuery::from_sexp(
        "(rust-pointer-findings (procedure-of (language rust (function :name \"run\"))))",
    )
    .expect("Rust pointer findings RQL should lower");
    assert_eq!(
        rql_query.to_canonical_json(),
        json_query.to_canonical_json()
    );

    let invalid = error_of(json!({
        "match": { "kind": "function" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "rust_pointer_findings", "kind": "raw" }
        ]
    }));
    assert_eq!(invalid.path, "steps[1].kind");
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

    // A union may combine procedure and structural rows (#5352), but a CFG
    // step needs procedure rows alone, so the refusal lands on the step.
    let mixed = parse_ok(json!({
        "schema_version": 1,
        "union": [
            {
                "match": { "kind": "function" },
                "steps": [{ "op": "procedure_of" }]
            },
            { "match": { "kind": "function" } }
        ]
    }));
    assert_eq!(
        mixed.validate_row_kinds().unwrap(),
        [QueryValueKind::Procedure, QueryValueKind::StructuralMatch]
    );
    let error = error_of(json!({
        "schema_version": 1,
        "union": [
            {
                "match": { "kind": "function" },
                "steps": [{ "op": "procedure_of" }]
            },
            { "match": { "kind": "function" } }
        ],
        "steps": [{ "op": "cfg_entry" }]
    }));
    assert_eq!(error.path, "steps[0]");
    assert!(error.message.contains("requires rows of one kind"));
    assert!(error.message.contains("structural_match"));
    assert!(error.message.contains("procedure"));
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
    let outcome = CodeQuery::from_sexp(r#"(receiver-outcome (call :callee "run"))"#)
        .expect("receiver outcome RQL");
    assert_eq!(
        outcome.validate_steps().unwrap(),
        QueryValueKind::ReceiverOutcome
    );
    assert_eq!(outcome.schema_version, SCHEMA_VERSION);

    let evidence = parse_ok(json!({
        "schema_version": SCHEMA_VERSION,
        "match": { "kind": "call", "callee": { "name": "run" } },
        "steps": [{ "op": "receiver_evidence" }]
    }));
    assert_eq!(
        evidence.validate_steps().unwrap(),
        QueryValueKind::ReceiverEvidence
    );
    assert_eq!(
        evidence.to_canonical_json()["steps"][0]["op"],
        "receiver_evidence"
    );
}

#[test]
fn field_write_value_parses_canonically_and_lowers_from_both_frontends() {
    let json_query = parse_ok(json!({
        "schema_version": SCHEMA_VERSION,
        "match": {
            "kind": "assignment",
            "operator": { "text": { "regex": "^=$" } }
        },
        "steps": [
            { "op": "member_targets" },
            {
                "op": "field_write_value",
                "receiver_identity_id": "receiver-id-123",
                "member_target_id": "member-id-456"
            }
        ]
    }));
    assert_eq!(
        json_query.plan.steps,
        vec![
            QueryStep::MemberTargets(ReceiverTraversalFilter::default()),
            QueryStep::FieldWriteValue(FieldWriteValueTraversal {
                receiver_identity_id: Some("receiver-id-123".to_string()),
                member_target_id: Some("member-id-456".to_string()),
            }),
        ]
    );
    assert_eq!(
        json_query.validate_steps().unwrap(),
        QueryValueKind::FieldWriteValue
    );
    assert_eq!(
        json_query.to_canonical_json(),
        json!({
            "schema_version": SCHEMA_VERSION.to_string(),
            "match": {
                "kind": "assignment",
                "operator": { "text": { "regex": "^=$" } }
            },
            "limit": DEFAULT_LIMIT,
            "result_detail": "compact",
            "execution_mode": "results",
            "steps": [
                { "op": "member_targets" },
                {
                    "op": "field_write_value",
                    "receiver_identity_id": "receiver-id-123",
                    "member_target_id": "member-id-456"
                }
            ]
        })
    );
    let canonical = json_query.to_canonical_json();
    assert_eq!(parse_ok(canonical.clone()).to_canonical_json(), canonical);

    let rql = CodeQuery::from_sexp(
        r#"(field-write-value :receiver-identity-id "receiver-id-123"
             :member-target-id "member-id-456"
             (member-targets (assignment :operator (text/regex "^=$"))))"#,
    )
    .expect("field-write-value RQL should lower");
    assert_eq!(
        rql.validate_steps().unwrap(),
        QueryValueKind::FieldWriteValue
    );
    assert_eq!(rql.plan.steps, json_query.plan.steps);
    assert_eq!(rql.to_canonical_json(), json_query.to_canonical_json());
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
fn python_rule_fact_relations_validate_in_both_query_frontends() {
    let sexp_queries = [
        (
            r#"(procedure-return-profile (procedure-of (language python (callable))))"#,
            json!({
                "languages": ["python"],
                "match": { "kind": "callable" },
                "steps": [
                    { "op": "procedure_of" },
                    { "op": "procedure_return_profile" }
                ]
            }),
        ),
        (
            r#"(call-result-use (call-shape (language python (call))))"#,
            json!({
                "languages": ["python"],
                "match": { "kind": "call" },
                "steps": [
                    { "op": "call_shape" },
                    { "op": "call_result_use" }
                ]
            }),
        ),
        (
            r#"(tuple-return-groups (procedure-of (language python (callable))))"#,
            json!({
                "languages": ["python"],
                "match": { "kind": "callable" },
                "steps": [
                    { "op": "procedure_of" },
                    { "op": "tuple_return_groups" }
                ]
            }),
        ),
        (
            r#"(lambda-forwarding (language python (lambda)))"#,
            json!({
                "languages": ["python"],
                "match": { "kind": "lambda" },
                "steps": [{ "op": "lambda_forwarding" }]
            }),
        ),
        (
            r#"(python-format-issues (language python (call)))"#,
            json!({
                "languages": ["python"],
                "match": { "kind": "call" },
                "steps": [{ "op": "python_format_issues" }]
            }),
        ),
        (
            r#"(python-format-issues (language python (binary_expression)))"#,
            json!({
                "languages": ["python"],
                "match": { "kind": "binary_expression" },
                "steps": [{ "op": "python_format_issues" }]
            }),
        ),
        (
            r#"(python-url-construction (language python (binary_expression)))"#,
            json!({
                "languages": ["python"],
                "match": { "kind": "binary_expression" },
                "steps": [{ "op": "python_url_construction" }]
            }),
        ),
        (
            r#"(python-url-construction (language python (call)))"#,
            json!({
                "languages": ["python"],
                "match": { "kind": "call" },
                "steps": [{ "op": "python_url_construction" }]
            }),
        ),
        (
            r#"(python-url-construction (language python (string_literal)))"#,
            json!({
                "languages": ["python"],
                "match": { "kind": "string_literal" },
                "steps": [{ "op": "python_url_construction" }]
            }),
        ),
        (
            r#"(python-raise-legality (language python (throw)))"#,
            json!({
                "languages": ["python"],
                "match": { "kind": "throw" },
                "steps": [{ "op": "python_raise_legality" }]
            }),
        ),
        (
            r#"(python-special-method-raise (language python (throw)))"#,
            json!({
                "languages": ["python"],
                "match": { "kind": "throw" },
                "steps": [{ "op": "python_special_method_raise" }]
            }),
        ),
    ];
    for (rql, json_value) in sexp_queries {
        let sexp = CodeQuery::from_sexp(rql).unwrap_or_else(|error| panic!("{rql}: {error}"));
        let json = parse_ok(json_value);
        assert_eq!(
            sexp.validate_steps().unwrap(),
            QueryValueKind::PythonRuleFact
        );
        assert_eq!(
            json.validate_steps().unwrap(),
            QueryValueKind::PythonRuleFact
        );
        assert_eq!(sexp.to_canonical_json(), json.to_canonical_json());
    }

    let wrong = CodeQuery::from_json(&json!({
        "languages": ["python"],
        "match": { "kind": "call" },
        "steps": [{ "op": "call_result_use" }]
    }))
    .expect_err("call-result-use requires a typed call-shape input");
    assert!(wrong.message.contains("requires call_shape"), "{wrong}");
}

#[test]
fn call_results_project_typed_indexed_normal_ports() {
    let rql = CodeQuery::from_sexp(r#"(call-results (call-shape (call :callee "open")))"#)
        .expect("call result RQL");
    assert_eq!(rql.validate_steps().unwrap(), QueryValueKind::CallResult);
    assert_eq!(rql.schema_version, SCHEMA_VERSION);

    let json = parse_ok(json!({
        "schema_version": SCHEMA_VERSION,
        "match": { "kind": "call", "callee": { "name": "open" } },
        "steps": [
            { "op": "call_shape" },
            { "op": "call_results" }
        ]
    }));
    assert_eq!(json.validate_steps().unwrap(), QueryValueKind::CallResult);
    assert_eq!(rql.to_canonical_json(), json.to_canonical_json());

    let wrong = CodeQuery::from_json(&json!({
        "match": { "kind": "call" },
        "steps": [{ "op": "call_results" }]
    }))
    .expect_err("call_results must reject a structural upstream");
    assert!(wrong.message.contains("requires call_shape"), "{wrong:?}");
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
    let procedure_row_input = CodeQuery::from_json(&json!({
        "match": { "kind": "function", "name": "handle" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "procedure_effects" }
        ]
    }))
    .expect("procedure_effects accepts an exact procedure row");
    assert_eq!(
        procedure_row_input.validate_steps().unwrap(),
        QueryValueKind::ProcedureEffect
    );

    // Procedure effects accept only a declaration or an exact procedure row.
    let wrong_procedure = CodeQuery::from_json(&json!({
        "match": { "kind": "call", "callee": { "name": "send" } },
        "steps": [{ "op": "call_shape" }, { "op": "procedure_effects" }]
    }))
    .expect_err("procedure_effects must reject a call-shape upstream");
    assert!(
        wrong_procedure
            .message
            .contains("requires declaration or procedure"),
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
fn call_result_contracts_project_a_typed_row_from_call_shape() {
    let rql = CodeQuery::from_sexp(r#"(call-result-contracts (call-shape (call :callee "Open")))"#)
        .expect("call result contract RQL");
    assert_eq!(
        rql.validate_steps().unwrap(),
        QueryValueKind::CallResultContract
    );

    let json = parse_ok(json!({
        "schema_version": SCHEMA_VERSION,
        "match": { "kind": "call", "callee": { "name": "Open" } },
        "steps": [
            { "op": "call_shape" },
            { "op": "call_result_contracts" }
        ]
    }));
    assert_eq!(
        json.validate_steps().unwrap(),
        QueryValueKind::CallResultContract
    );
    assert_eq!(rql.to_canonical_json(), json.to_canonical_json());

    let wrong = CodeQuery::from_json(&json!({
        "match": { "kind": "call" },
        "steps": [{ "op": "call_result_contracts" }]
    }))
    .expect_err("call_result_contracts must reject a structural upstream");
    assert!(
        wrong.message.contains("requires call_shape"),
        "{}",
        wrong.message
    );

    let files = parse_ok(json!({
        "match": { "kind": "call", "callee": { "name": "Open" } },
        "steps": [
            { "op": "call_shape" },
            { "op": "call_result_contracts" },
            { "op": "file_of" }
        ]
    }));
    assert_eq!(files.validate_steps().unwrap(), QueryValueKind::File);
}

#[test]
fn call_result_obligations_project_a_separate_typed_row() {
    let rql =
        CodeQuery::from_sexp(r#"(call-result-obligations (call-shape (call :callee "trim")))"#)
            .expect("result obligation RQL");
    assert_eq!(
        rql.validate_steps().unwrap(),
        QueryValueKind::CallResultObligation
    );
    let json = parse_ok(json!({
        "schema_version": SCHEMA_VERSION,
        "match": { "kind": "call", "callee": { "name": "trim" } },
        "steps": [
            { "op": "call_shape" },
            { "op": "call_result_obligations" }
        ]
    }));
    assert_eq!(rql.to_canonical_json(), json.to_canonical_json());
    let wrong = CodeQuery::from_json(&json!({
        "match": { "kind": "call" },
        "steps": [{ "op": "call_result_obligations" }]
    }))
    .expect_err("obligation projection requires a call shape");
    assert!(wrong.message.contains("requires call_shape"));
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "3b9a2f8d89a7: keep the established schema-v1 result_contract_uses row and its call-result-contract input"
)]
fn result_contract_uses_enriches_a_contract_row_without_changing_its_type() {
    let rql = CodeQuery::from_sexp(
        r#"(result-contract-uses (call-result-contracts (call-shape (call :callee "Open"))))"#,
    )
    .expect("result contract use validation RQL");
    assert_eq!(
        rql.validate_steps().unwrap(),
        QueryValueKind::CallResultContract
    );

    let json = parse_ok(json!({
        "schema_version": SCHEMA_VERSION,
        "match": { "kind": "call", "callee": { "name": "Open" } },
        "steps": [
            { "op": "call_shape" },
            { "op": "call_result_contracts" },
            { "op": "result_contract_uses" }
        ]
    }));
    assert_eq!(
        json.validate_steps().unwrap(),
        QueryValueKind::CallResultContract
    );
    assert_eq!(rql.to_canonical_json(), json.to_canonical_json());

    let wrong = CodeQuery::from_json(&json!({
        "match": { "kind": "call" },
        "steps": [
            { "op": "call_shape" },
            { "op": "result_contract_uses" }
        ]
    }))
    .expect_err("result_contract_uses must reject a call-shape upstream");
    assert!(
        wrong.message.contains("requires call_result_contract"),
        "{}",
        wrong.message
    );
}

#[test]
fn result_subject_uses_project_typed_rows_from_call_results() {
    let rql = CodeQuery::from_sexp(
        r#"(result-subject-uses (call-results (call-shape (call :callee "build"))))"#,
    )
    .expect("result subject use RQL");
    assert_eq!(
        rql.validate_steps().unwrap(),
        QueryValueKind::ResultSubjectUse
    );

    let underscored = CodeQuery::from_sexp(
        r#"(result_subject_uses (call_results (call_shape (call :callee "build"))))"#,
    )
    .expect("underscored result subject use RQL");
    assert_eq!(underscored.to_canonical_json(), rql.to_canonical_json());

    let json = parse_ok(json!({
        "schema_version": SCHEMA_VERSION,
        "match": { "kind": "call", "callee": { "name": "build" } },
        "steps": [
            { "op": "call_shape" },
            { "op": "call_results" },
            { "op": "result_subject_uses" }
        ]
    }));
    assert_eq!(
        json.validate_steps().unwrap(),
        QueryValueKind::ResultSubjectUse
    );
    assert_eq!(rql.to_canonical_json(), json.to_canonical_json());

    let wrong = CodeQuery::from_json(&json!({
        "match": { "kind": "call" },
        "steps": [
            { "op": "call_shape" },
            { "op": "result_subject_uses" }
        ]
    }))
    .expect_err("result_subject_uses must reject a call-shape upstream");
    assert!(
        wrong.message.contains("requires call_result"),
        "{}",
        wrong.message
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "3b9a2f8d89a7: keep per-operation rows under the distinct result_contract_operation_uses name"
)]
fn result_contract_operation_uses_project_typed_operation_rows() {
    let rql = CodeQuery::from_sexp(
        r#"(result-contract-operation-uses (call-result-contracts (call-shape (call :callee "Open"))))"#,
    )
    .expect("result contract operation-use RQL");
    assert_eq!(
        rql.validate_steps().unwrap(),
        QueryValueKind::ResultContractUse
    );

    let json = parse_ok(json!({
        "schema_version": SCHEMA_VERSION,
        "match": { "kind": "call", "callee": { "name": "Open" } },
        "steps": [
            { "op": "call_shape" },
            { "op": "call_result_contracts" },
            { "op": "result_contract_operation_uses" }
        ]
    }));
    assert_eq!(
        json.validate_steps().unwrap(),
        QueryValueKind::ResultContractUse
    );
    assert_eq!(rql.to_canonical_json(), json.to_canonical_json());

    let files = parse_ok(json!({
        "match": { "kind": "call", "callee": { "name": "Open" } },
        "steps": [
            { "op": "call_shape" },
            { "op": "call_result_contracts" },
            { "op": "result_contract_operation_uses" },
            { "op": "file_of" }
        ]
    }));
    assert_eq!(files.validate_steps().unwrap(), QueryValueKind::File);

    let wrong = CodeQuery::from_json(&json!({
        "match": { "kind": "call" },
        "steps": [
            { "op": "call_shape" },
            { "op": "result_contract_operation_uses" }
        ]
    }))
    .expect_err("result_contract_operation_uses must reject a call-shape upstream");
    assert!(
        wrong.message.contains("requires call_result_contract"),
        "{}",
        wrong.message
    );
}

#[test]
fn result_contract_failure_uses_project_typed_filtered_rows() {
    let rql = CodeQuery::from_sexp(
        r#"(result-contract-failure-uses
              :provenance [condition-result distinct-zero-binding unknown]
              :consumer [return returned-call-argument]
              (call-result-contracts (call-shape (call :callee "Open"))))"#,
    )
    .expect("result contract failure-use RQL");
    assert_eq!(
        rql.validate_steps().unwrap(),
        QueryValueKind::ResultContractFailureUse
    );
    assert_eq!(
        rql.plan.steps.last(),
        Some(&QueryStep::ResultContractFailureUses(
            ResultContractFailureUseFilter {
                provenances: vec![
                    FailureUseProvenance::ConditionResult,
                    FailureUseProvenance::DistinctZeroBinding,
                    FailureUseProvenance::Unknown,
                ],
                consumers: vec![
                    FailureUseConsumer::Return,
                    FailureUseConsumer::ReturnedCallArgument,
                ],
            }
        ))
    );

    let json = parse_ok(json!({
        "schema_version": SCHEMA_VERSION,
        "match": { "kind": "call", "callee": { "name": "Open" } },
        "steps": [
            { "op": "call_shape" },
            { "op": "call_result_contracts" },
            {
                "op": "result_contract_failure_uses",
                "provenance": ["condition_result", "distinct_zero_binding", "unknown"],
                "consumer": ["return", "returned_call_argument"]
            }
        ]
    }));
    assert_eq!(rql.to_canonical_json(), json.to_canonical_json());

    let files = parse_ok(json!({
        "match": { "kind": "call", "callee": { "name": "Open" } },
        "steps": [
            { "op": "call_shape" },
            { "op": "call_result_contracts" },
            { "op": "result_contract_failure_uses" },
            { "op": "file_of" }
        ]
    }));
    assert_eq!(files.validate_steps().unwrap(), QueryValueKind::File);

    let wrong = CodeQuery::from_json(&json!({
        "match": { "kind": "call" },
        "steps": [
            { "op": "call_shape" },
            { "op": "result_contract_failure_uses" }
        ]
    }))
    .expect_err("failure-use projection must reject a call-shape upstream");
    assert!(
        wrong.message.contains("requires call_result_contract"),
        "{}",
        wrong.message
    );

    let invalid = CodeQuery::from_json(&json!({
        "match": { "kind": "call" },
        "steps": [
            { "op": "call_shape" },
            { "op": "call_result_contracts" },
            { "op": "result_contract_failure_uses", "provenance": ["same_name"] }
        ]
    }))
    .expect_err("free-form failure provenance must not enter the typed plan");
    assert!(invalid.message.contains("failure-use provenance"));
    assert!(invalid.path.ends_with(".provenance[0]"), "{}", invalid.path);
}

#[test]
fn result_contract_calls_preserve_call_shape_type_for_positive_discovery() {
    let rql = CodeQuery::from_sexp(
        r#"(result-contract-calls (call-shape (call :callee (name "Open"))))"#,
    )
    .expect("result contract call discovery RQL");
    assert_eq!(rql.validate_steps().unwrap(), QueryValueKind::CallShape);

    let json = parse_ok(json!({
        "schema_version": SCHEMA_VERSION,
        "match": { "kind": "call", "callee": { "name": "Open" } },
        "steps": [
            { "op": "call_shape" },
            { "op": "result_contract_calls" }
        ]
    }));
    assert_eq!(json.validate_steps().unwrap(), QueryValueKind::CallShape);
    assert_eq!(rql.to_canonical_json(), json.to_canonical_json());

    let wrong = CodeQuery::from_json(&json!({
        "match": { "kind": "call" },
        "steps": [{ "op": "result_contract_calls" }]
    }))
    .expect_err("result_contract_calls must reject a structural upstream");
    assert!(
        wrong.message.contains("requires call_shape"),
        "{}",
        wrong.message
    );
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
fn callable_metrics_projects_from_declarations() {
    let json = parse_ok(json!({
        "schema_version": SCHEMA_VERSION,
        "match": { "kind": "method", "name": "run" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "callable_metrics" }
        ]
    }));
    assert_eq!(
        json.validate_steps().unwrap(),
        QueryValueKind::CallableMetrics
    );

    let sexp = CodeQuery::from_sexp(r#"(callable-metrics (enclosing-decl (method (name "run"))))"#)
        .expect("callable metrics RQL");
    assert_eq!(sexp.to_canonical_json(), json.to_canonical_json());

    let files = parse_ok(json!({
        "match": { "kind": "method", "name": "run" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "callable_metrics" },
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
    assert_eq!(
        canonical["inside"],
        json!({"kind": ["function", "method"], "capture": "fn"})
    );
    assert_eq!(
        canonical["not_inside"],
        json!({"kind": "class", "not_kind": "declaration"})
    );
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
fn comparison_and_assertion_roles_round_trip_through_json() {
    let query = parse_ok(json!({
        "match": {
            "kind": "comparison",
            "left": { "kind": "identifier" },
            "right": { "kind": "null_literal" },
            "operator": { "text": { "regex": "^==$" } }
        },
        "inside": {
            "kind": "assertion",
            "test": { "kind": "comparison" }
        }
    }));
    assert_eq!(
        query.to_canonical_json()["match"],
        json!({
            "kind": "comparison",
            "left": { "kind": "identifier" },
            "right": { "kind": "null_literal" },
            "operator": { "text": { "regex": "^==$" } }
        })
    );
    assert_eq!(
        query.to_canonical_json()["inside"],
        json!({
            "kind": "assertion",
            "test": { "kind": "comparison" }
        })
    );

    let binary = parse_ok(json!({
        "match": {
            "kind": "binary_expression",
            "left": { "kind": "identifier" },
            "right": { "kind": "numeric_literal" },
            "operator": { "text": { "regex": "^%$" } }
        }
    }));
    assert_eq!(
        binary.to_canonical_json()["match"]["operator"],
        json!({ "text": { "regex": "^%$" } })
    );
}

#[test]
fn not_kind_alone_does_not_anchor_a_root() {
    let error = error_of(json!({ "match": { "not_kind": "lambda" } }));
    assert_eq!(error.path, "match");
    assert!(error.message.contains("root pattern"));
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#1398+#1458+#1459+#1461+002968fd9bf2: bounded literal regex alternatives must not widen indexed query search"
)]
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

#[test]
fn occurrences_in_accepts_a_lexical_scope_and_returns_occurrences() {
    let query = CodeQuery::from_sexp(
        "(occurrences-in :role global_directive (filter :where ((kind is-null)) (language python (scopes))))",
    )
    .expect("occurrences-in should accept a lexical-scope seed");
    assert_eq!(
        query.validate_steps().expect("valid scope relation"),
        QueryValueKind::Occurrence
    );
    assert!(
        query
            .plan
            .steps
            .iter()
            .any(|step| matches!(step, QueryStep::OccurrencesIn(_)))
    );
}

/// A single label is accepted wherever a list is, so the JSON frontend mirrors
/// RQL's `:role binder`.
#[test]
fn occurrence_filter_axes_accept_one_label_or_a_list() {
    let single = parse_ok(json!({ "occurrences": { "role": "binder" } }));
    let list = parse_ok(json!({ "occurrences": { "role": ["binder"] } }));
    assert_eq!(single.to_canonical_json(), list.to_canonical_json());
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
fn binding_uses_accepts_binding_rows_in_rql_and_json() {
    let json = parse_ok(json!({
        "bindings": { "kind": ["parameter"], "name": ["value"] },
        "steps": [{ "op": "binding_uses" }]
    }));
    assert_eq!(json.validate_steps().unwrap(), QueryValueKind::Occurrence);
    assert_eq!(json.plan.steps, vec![QueryStep::BindingUses]);

    let rql = CodeQuery::from_sexp(r#"(binding-uses (bindings :kind [parameter] :name [value]))"#)
        .expect("binding uses RQL");
    assert_eq!(rql.validate_steps().unwrap(), QueryValueKind::Occurrence);
    assert_eq!(rql.to_canonical_json(), json.to_canonical_json());

    let wrong_upstream = error_of(json!({
        "match": { "kind": "function" },
        "steps": [{ "op": "binding_uses" }]
    }));
    assert!(wrong_upstream.message.contains("requires binding"));
}

#[test]
fn python_comparison_wrappers_parse_from_rql_and_json() {
    for (step_op, step, rql_name) in [
        (
            "python_comparison_constants",
            QueryStep::PythonComparisonConstants,
            "python-comparison-constants",
        ),
        (
            "python_comparison_using_is",
            QueryStep::PythonComparisonUsingIs,
            "python-comparison-using-is",
        ),
        (
            "python_comparison_using_is_non_portable",
            QueryStep::PythonComparisonUsingIsNonPortable,
            "python-comparison-using-is-non-portable",
        ),
        (
            "identical_operands",
            QueryStep::IdenticalOperands,
            "identical-operands",
        ),
        (
            "python_missing_self",
            QueryStep::PythonMissingSelf,
            "python-missing-self",
        ),
    ] {
        let json = parse_ok(json!({
            "languages": ["python"],
            "match": { "kind": "comparison" },
            "steps": [{ "op": step_op }]
        }));
        assert_eq!(
            json.validate_steps().unwrap(),
            QueryValueKind::StructuralMatch
        );
        assert_eq!(json.plan.steps, vec![step]);

        let rql = CodeQuery::from_sexp(&format!("({rql_name} (language python (comparison)))"))
            .expect("comparison identity wrapper RQL");
        assert_eq!(
            rql.validate_steps().unwrap(),
            QueryValueKind::StructuralMatch
        );
        assert_eq!(rql.to_canonical_json(), json.to_canonical_json());
    }

    for step in [
        "python_comparison_constants",
        "python_comparison_using_is",
        "python_comparison_using_is_non_portable",
        "identical_operands",
        "python_missing_self",
    ] {
        let error = error_of(json!({
            "bindings": {},
            "steps": [{ "op": step }]
        }));
        assert!(
            error.message.contains("requires structural_match"),
            "{step}: {error:?}"
        );
    }

    let reference = schema::query_step_reference();
    assert!(reference.contains("identical_operands (comparison -> comparison)"));
    assert!(reference.contains("python_missing_self (comparison -> comparison)"));
    assert!(reference.contains("python_comparison_constants (comparison -> comparison)"));
    assert!(reference.contains("python_comparison_using_is (comparison -> comparison)"));
    assert!(
        reference.contains("python_comparison_using_is_non_portable (comparison -> comparison)")
    );
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

#[test]
fn conjunctive_where_preserves_flat_identity_and_matches_all_groups() {
    let flat = parse_ok(json!({"match": {"kind": "call"}, "where": ["src/**", "lib/**"]}));
    let nested = parse_ok(json!({"match": {"kind": "call"}, "where": [["src/**", "lib/**"]]}));
    assert_eq!(flat.to_canonical_json(), nested.to_canonical_json());
    assert_eq!(
        flat.to_canonical_json()["where"],
        json!(["src/**", "lib/**"])
    );
    let conjoined =
        CodeQuery::from_sexp(r#"(where "**/*.py" (where "src/**" "lib/**" (call)))"#).unwrap();
    let seed = conjoined.seed().unwrap();
    assert!(seed.where_globs.matches("src/main.py"));
    assert!(seed.where_globs.matches("lib/main.py"));
    assert!(!seed.where_globs.matches("src/main.rs"));
    assert!(!seed.where_globs.matches("test/main.py"));
    assert_eq!(
        CodeQuery::from_json(&conjoined.to_canonical_json())
            .unwrap()
            .to_canonical_json(),
        conjoined.to_canonical_json()
    );
    let redundant = CodeQuery::from_sexp(r#"(where "src/**" (where "src/**" (call)))"#).unwrap();
    assert_eq!(redundant.to_canonical_json()["where"], json!(["src/**"]));
}

#[test]
fn nested_where_rejects_empty_mixed_and_over_budget_groups() {
    for scope in [json!([[]]), json!(["src/**", ["lib/**"]]), json!([[7]])] {
        assert!(parse(json!({"match": {"kind": "call"}, "where": scope})).is_err());
    }
    let total = vec![
        vec!["src/**"; MAX_WHERE_GLOBS / 2 + 1],
        vec!["lib/**"; MAX_WHERE_GLOBS / 2 + 1],
    ];
    let error = parse(json!({"match": {"kind": "call"}, "where": total})).unwrap_err();
    assert_eq!(error.path, "where");
    let empty = parse_ok(json!({"match": {"kind": "call"}, "where": []}));
    assert!(empty.seed().unwrap().where_globs.matches("any/file.rs"));
}

#[test]
fn shared_scope_and_nested_wrappers_distribute_identically_over_sets() {
    use crate::sexp::parse_sexp;
    let local = parse_sexp(r#"(union (language java (call)) (union (language kotlin (call)) (language scala (call))))"#).unwrap().expr.unwrap();
    let language = parse_sexp("jvm").unwrap().expr.unwrap();
    let glob = parse_sexp(r#""src/**""#).unwrap().expr.unwrap();
    let shared = sexp::code_query_from_expr_with_scope(
        &local,
        schema::resolve_rql_schema_version(None).unwrap(),
        &[language],
        &[glob],
    )
    .unwrap();
    let explicit = CodeQuery::from_sexp(
        r#"(language jvm (where "src/**" (union (language java (call)) (union (language kotlin (call)) (language scala (call))))))"#,
    ).unwrap();
    assert_eq!(shared.to_canonical_json(), explicit.to_canonical_json());
    let conflict = CodeQuery::from_sexp(
        "(language jvm (union (call) (union (call) (language python (call)))))",
    )
    .unwrap_err();
    assert!(
        conflict.contains("union[1].union[1].languages"),
        "{conflict}"
    );
    assert!(conflict.contains("disjoint"), "{conflict}");
}

#[test]
fn empty_shared_scope_does_not_add_an_axis_to_configuration_facts() {
    use crate::sexp::parse_sexp;
    let local = parse_sexp("(configuration-facts :format json)")
        .unwrap()
        .expr
        .unwrap();
    let query = sexp::code_query_from_expr_with_scope(
        &local,
        schema::resolve_rql_schema_version(None).unwrap(),
        &[],
        &[],
    )
    .unwrap();
    assert!(matches!(
        query.plan.source,
        CodeQueryPlanSource::ConfigurationFacts(_)
    ));
}

#[test]
fn shared_scope_errors_retain_local_or_embedding_provenance() {
    use crate::sexp::parse_sexp;
    let schema = schema::resolve_rql_schema_version(None).unwrap();
    let local = parse_sexp("(union (call) (language python (call)))")
        .unwrap()
        .expr
        .unwrap();
    let language = parse_sexp("jvm").unwrap().expr.unwrap();
    let error =
        sexp::code_query_from_expr_with_scope(&local, schema, &[language], &[]).unwrap_err();
    assert_eq!(error.origin, sexp::QueryExprErrorOrigin::SharedScope);
    assert_eq!(error.path, "union[1].languages");
    let bad_glob = parse_sexp(r#""[""#).unwrap().expr.unwrap();
    let error =
        sexp::code_query_from_expr_with_scope(&local, schema, &[], &[bad_glob]).unwrap_err();
    assert_eq!(error.origin, sexp::QueryExprErrorOrigin::SharedScope);
    assert_eq!(error.path, "where[0]");
    let invalid = parse_sexp(r#"(call :name (regex "["))"#)
        .unwrap()
        .expr
        .unwrap();
    let error = sexp::code_query_from_expr_with_scope(&invalid, schema, &[], &[]).unwrap_err();
    assert_eq!(error.origin, sexp::QueryExprErrorOrigin::Local);
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "63f9a52c1f86: canonical schema versions must be strings while legacy numeric inputs remain accepted"
)]
fn schema_version_strings_round_trip_and_normalize_legacy_numbers() {
    for version in [json!("1"), json!(1)] {
        let query = parse_ok(json!({"schema_version": version, "match": {"kind": "call"}}));
        let canonical = query.to_canonical_json();
        assert_eq!(canonical["schema_version"], "1");
        assert_eq!(parse_ok(canonical.clone()).to_canonical_json(), canonical);
    }
    for version in [
        json!("2"),
        json!("1.0.0"),
        json!("01"),
        json!("+1"),
        json!(""),
        json!(true),
        json!(null),
    ] {
        let error = error_of(json!({"schema_version": version, "match": {"kind": "call"}}));
        assert_eq!(error.path, "schema_version");
    }
}

#[test]
fn branch_relations_parse_and_filter_by_relation() {
    let json = parse_ok(json!({
        "schema_version": 1,
        "match": { "kind": "if" },
        "steps": [{ "op": "branch_relations", "branch_relation": ["identical_bodies"] }]
    }));
    assert_eq!(
        json.validate_steps().unwrap(),
        QueryValueKind::BranchRelation
    );
    assert_eq!(
        json.plan.steps,
        vec![QueryStep::BranchRelations(BranchRelationFilter {
            relations: vec![BranchRelationKind::IdenticalBodies],
        })]
    );
    let rql = CodeQuery::from_sexp("(branch-relations :relation [identical-bodies] (if))")
        .expect("branch relation RQL");
    assert_eq!(rql.to_canonical_json(), json.to_canonical_json());

    let reserved = CodeQuery::from_sexp(
        "(branch-relations :relation [contradictory-condition redundant-boolean-return] (if))",
    )
    .expect("reserved relations are declared values");
    assert_eq!(
        reserved.validate_steps().unwrap(),
        QueryValueKind::BranchRelation
    );

    let wrong = error_of(json!({
        "schema_version": 1,
        "match": { "kind": "function" },
        "steps": [{ "op": "file_of" }, { "op": "branch_relations" }]
    }));
    assert!(wrong.message.contains("structural_match"), "{wrong:?}");
    let unknown = error_of(json!({
        "schema_version": 1,
        "match": { "kind": "if" },
        "steps": [{ "op": "branch_relations", "branch_relation": ["clone"] }]
    }));
    assert_eq!(unknown.path, "steps[0].branch_relation[0]");
}

#[test]
fn failure_handler_state_parses_in_rql_and_json_with_structural_input() {
    let rql = CodeQuery::from_sexp("(failure-handler-state (language java (catch)))")
        .expect("Java catch state RQL");
    let json = parse_ok(json!({
        "schema_version": 1,
        "languages": ["java"],
        "match": { "kind": "catch" },
        "steps": [{ "op": "failure_handler_state" }]
    }));
    assert_eq!(rql.to_canonical_json(), json.to_canonical_json());
    assert_eq!(
        rql.validate_steps().unwrap(),
        QueryValueKind::FailureHandlerState
    );
    let wrong = error_of(json!({
        "schema_version": 1,
        "match": { "kind": "function" },
        "steps": [{ "op": "file_of" }, { "op": "failure_handler_state" }]
    }));
    assert!(wrong.message.contains("structural_match"), "{wrong:?}");
}

#[test]
fn explicit_enum_row_literals_preserve_boolean_named_labels() {
    let query = CodeQuery::from_sexp(
        "(filter :where ((failure_predicate eq (enum false)) (terminal eq false)) (call-result-obligations (call-shape (call))))",
    ).expect("enum and Boolean literals remain distinct");
    let json = query.to_canonical_json();
    let predicates = &json["steps"][2]["where"];
    assert_eq!(predicates[0]["value"], json!({"enum": "false"}));
    assert_eq!(predicates[1]["value"], json!({"boolean": false}));
    assert_eq!(
        CodeQuery::from_json(&json).unwrap().to_canonical_json(),
        json
    );
    assert!(CodeQuery::from_sexp(
        "(filter :where ((failure_predicate in [(enum true) (enum false)])) (call-result-obligations (call-shape (call))))"
    ).is_ok());
}

#[test]
fn resolved_value_parses_for_call_bindings_and_decorator_matches() {
    let call_source = r#"(resolved-value :resolves-to "paramiko.AutoAddPolicy" :proof exact
        (call-bindings (call-shape (call :callee (name "set_missing_host_key_policy")))))"#;
    let call_query = CodeQuery::from_sexp(call_source).expect("resolved-value call query");
    let filter = call_query
        .plan
        .steps
        .iter()
        .find_map(|step| match step {
            QueryStep::ResolvedValue(filter) => Some(filter),
            _ => None,
        })
        .expect("resolved-value is in the call-binding plan");
    assert_eq!(filter.proof, ResolvedCallProof::Exact);
    assert!(matches!(
        &filter.resolves_to,
        CallIdentity::Qualified { value, .. } if value == "paramiko.AutoAddPolicy"
    ));
    let canonical = call_query.to_canonical_json();
    assert_eq!(canonical["steps"][2]["op"], "resolved_value");
    assert_eq!(canonical["steps"][2]["call_proof"], "exact");
    assert_eq!(
        CodeQuery::from_json(&canonical)
            .expect("resolved-value canonical JSON")
            .to_canonical_json(),
        canonical
    );

    let decorator_source = "(resolved_value :resolves_to django.csrf_exempt :proof exact (language python (decorator)))";
    let decorator_query =
        CodeQuery::from_sexp(decorator_source).expect("resolved-value decorator query");
    assert!(decorator_query.plan.steps.iter().any(|step| matches!(
        step,
        QueryStep::ResolvedValue(ResolvedValueFilter {
            resolves_to: CallIdentity::Stable(identity),
            proof: ResolvedCallProof::Exact,
        }) if identity == "django.csrf_exempt"
    )));

    let invalid = call_source.replace(":proof exact", ":proof declared");
    assert!(
        CodeQuery::from_sexp(&invalid)
            .expect_err("resolved-value accepts exact proof only")
            .contains("proof must be exact"),
        "{invalid}"
    );
}

#[test]
fn union_combines_different_row_kinds_when_only_shared_fields_are_read() {
    // The #3543 performance policies pair an exact Python call-effects
    // branch with name-matched branches for the other languages (#5352).
    let python = r#"(language python
          (filter :where ((effect_id eq "bifrost.performance.database_call") (terminal eq false))
            (call-effects
              (call-shape
                (inside-decl (loop :capture "region")
                  (call :callee (name "execute") :capture "smell"))))))"#;
    let java = r#"(language java
          (inside-decl (loop :capture "region")
            (call :receiver (name "statement") :callee (name "executeQuery") :capture "smell")))"#;

    let union = CodeQuery::from_sexp(&format!("(union {python} {java})"))
        .expect("a union of call_effect and structural_match rows validates");
    assert_eq!(union.validate_steps().unwrap(), QueryValueKind::CallEffect);
    assert_eq!(
        union.validate_row_kinds().unwrap(),
        [QueryValueKind::CallEffect, QueryValueKind::StructuralMatch]
    );
    // Only `id` is published by both kinds under one name and type; the
    // structural row may leave it null, so the union may too.
    let (_, fields) = union.validate_row_fields().unwrap();
    assert_eq!(
        fields
            .iter()
            .map(|(name, field)| (name.as_str(), field.nullable))
            .collect::<Vec<_>>(),
        [("id", true)]
    );
    let decoded = CodeQuery::from_json(&union.to_canonical_json()).expect("canonical JSON parses");
    assert_eq!(decoded.to_canonical_json(), union.to_canonical_json());

    let reversed = CodeQuery::from_sexp(&format!("(union {java} {python})"))
        .expect("branch order does not decide admission");
    assert_eq!(
        reversed.validate_steps().unwrap(),
        QueryValueKind::StructuralMatch
    );
    assert_eq!(
        reversed.validate_row_kinds().unwrap(),
        [QueryValueKind::StructuralMatch, QueryValueKind::CallEffect]
    );

    let projected =
        CodeQuery::from_sexp(&format!("(project :columns (id) (union {python} {java}))"))
            .expect("a projection of a shared field follows a mixed union");
    assert_eq!(
        projected.validate_row_kinds().unwrap(),
        [QueryValueKind::CallEffect, QueryValueKind::StructuralMatch]
    );

    // A nested mixed union stays mixed for its parent.
    let nested = CodeQuery::from_sexp(&format!("(union (union {python} {java}) {java})"))
        .expect("a mixed union composes with a further union");
    assert_eq!(
        nested.validate_row_kinds().unwrap(),
        [QueryValueKind::CallEffect, QueryValueKind::StructuralMatch]
    );

    for op in ["intersect", "except"] {
        let error = CodeQuery::from_sexp(&format!("({op} {python} {java})"))
            .expect_err("identity comparison needs one row kind");
        assert!(
            error.contains(&format!("invalid query at {op}[1]:"))
                && error.contains("only union combines different row kinds"),
            "{error}"
        );
        let error = CodeQuery::from_sexp(&format!("({op} (union {python} {java}) {java})"))
            .expect_err("a nested mixed union is still mixed");
        assert!(
            error.contains(&format!("invalid query at {op}[1]:")),
            "{error}"
        );
    }

    let error = CodeQuery::from_sexp(&format!("(enclosing-decl (union {python} {java}))"))
        .expect_err("a typed step needs one row kind");
    assert!(
        error.contains("invalid query at steps[0]:") && error.contains("requires rows of one kind"),
        "{error}"
    );

    let error = CodeQuery::from_sexp(&format!(
        r#"(filter :where ((effect_id eq "x")) (union {python} {java}))"#
    ))
    .expect_err("a field only one branch publishes is not readable");
    assert!(
        error.contains("invalid query at steps[0].where[0].field:")
            && error.contains("unknown row field"),
        "{error}"
    );
}

#[test]
fn rust_marker_impls_parse_and_round_trip() {
    let json_query = parse_ok(json!({
        "schema_version": 1,
        "languages": ["rust"],
        "match": { "kind": "class" },
        "steps": [{ "op": "rust_marker_impls_of" }]
    }));
    assert_eq!(json_query.plan.steps, vec![QueryStep::RustMarkerImplsOf]);
    assert_eq!(
        json_query.validate_steps().unwrap(),
        QueryValueKind::RustMarkerImpl
    );
    for name in ["rust-marker-impls-of", "rust_marker_impls_of"] {
        let rql = CodeQuery::from_sexp(&format!("({name} (language rust (class)))")).unwrap();
        assert_eq!(rql.to_canonical_json(), json_query.to_canonical_json());
    }
    let invalid = error_of(json!({
        "match": { "kind": "class" },
        "steps": [{ "op": "rust_marker_impls_of", "kind": "raw" }]
    }));
    assert_eq!(invalid.path, "steps[0].kind");
}

#[test]
fn callee_provenance_columns_parse_and_round_trip() {
    let query = CodeQuery::from_sexp(
        r#"(project :columns (callee_provenance callee_supplier callee_type_shape callee_bounds)
            (filter :where ((callee_provenance eq caller_supplied)
                            (callee_supplier eq "parameter 1")
                            (callee_type_shape eq fn_bound_generic)
                            (callee_bounds eq ["FnMut"]))
                (call-shape (language rust (call)))))"#,
    )
    .expect("callee provenance columns parse");
    query.validate_steps().expect("callee columns validate");
    let decoded =
        CodeQuery::from_json(&query.to_canonical_json()).expect("JSON decoder accepts columns");
    assert_eq!(decoded.to_canonical_json(), query.to_canonical_json());
    assert!(
        CodeQuery::from_sexp(
            "(filter :where ((callee_provenance eq invented)) (call-shape (call)))"
        )
        .is_err()
    );
}

#[test]
fn unsafe_context_call_property_round_trips_and_rejects_non_calls() {
    for spelling in ["unsafe-context", "unsafe_context"] {
        for expected in [true, false] {
            let query =
                CodeQuery::from_sexp(&format!("(language rust (call :{spelling} {expected}))"))
                    .expect("unsafe call property");
            let decoded = CodeQuery::from_json(&query.to_canonical_json())
                .expect("JSON unsafe call property");
            assert_eq!(decoded.to_canonical_json(), query.to_canonical_json());
        }
    }
    for kind in ["expression", "function", "identifier"] {
        assert!(CodeQuery::from_sexp(&format!("({kind} :unsafe-context true)")).is_err());
    }
    assert!(CodeQuery::from_sexp("(call :unsafe-context 1)").is_err());
}
