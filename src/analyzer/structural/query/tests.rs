use super::*;
use crate::analyzer::Language;
use crate::analyzer::structural::kinds::ALL_ROLES;
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

    assert_eq!(query.where_globs.len(), 2);
    assert_eq!(query.limit, 100);
    assert_eq!(query.root.kinds, vec![NormalizedKind::Call]);
    let callee = query.root.callee.as_ref().expect("callee pattern");
    assert!(matches!(&callee.name, Some(StringPredicate::Exact(name)) if name == "eval"));
    assert_eq!(query.root.args.len(), 1);
    assert_eq!(query.root.args[0].capture.as_deref(), Some("code"));
    let inside = query.inside.as_ref().expect("inside pattern");
    assert_eq!(inside.kinds, vec![NormalizedKind::Function]);
    assert_eq!(inside.capture.as_deref(), Some("enclosing_function"));
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
        query.steps[1],
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
        union.root.kinds,
        vec![NormalizedKind::Function, NormalizedKind::Method]
    );

    let subtractive = parse_ok(json!({
        "match": { "kind": "callable", "not_kind": ["constructor", "lambda"] }
    }));
    assert_eq!(subtractive.root.kinds, vec![NormalizedKind::Callable]);
    assert_eq!(
        subtractive.root.not_kinds,
        vec![NormalizedKind::Constructor, NormalizedKind::Lambda]
    );

    // Roles are valid when at least one union member supports them.
    let mixed = parse_ok(json!({
        "match": { "kind": ["call", "assignment"], "callee": { "name": "eval" } }
    }));
    assert!(mixed.root.callee.is_some());
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

    assert_eq!(query.languages, vec![Language::Python]);
    assert_eq!(query.limit, DEFAULT_LIMIT);
    assert_eq!(query.root.kwargs.len(), 1);
    assert_eq!(query.root.kwargs[0].0, "shell");
    let not_inside = query.not_inside.as_ref().expect("not_inside pattern");
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
fn parses_and_rejects_schema_version() {
    let query = parse_ok(json!({
        "schema_version": 2,
        "match": { "kind": "call" }
    }));
    assert_eq!(query.schema_version, SCHEMA_VERSION);
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
        query.steps,
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
        query.steps,
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
    assert!(query.root.args[0].is_empty());
    assert_eq!(query.root.args[1].capture.as_deref(), Some("second"));
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
