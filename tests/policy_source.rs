use std::path::{Path, PathBuf};

use brokk_bifrost::policy::{
    EndpointRole, InlineLocalSemanticProjectionError, ParsedRqlpDocument, PolicyAnalysis,
    PolicyFormatOptions, PolicyMessageSpec, PolicySelector, PolicySemanticEvent,
    PolicySourceIdentity, RqlpDocument, SchemaVersionOrigin, TypestateEventTrigger,
    TypestateTerminalTrigger, format_rqlp_source, format_rqlp_source_with_options,
    parse_rqlp_source, validate_rqlp_source,
};
use serde_json::Value;

const POLICY_FIXTURES: &[&str] = &[
    "dynamic-eval.rqlp",
    "attacker-controlled-to-sensitive-sinks.rqlp",
    "resource-lifecycle.rqlp",
    "classification-cvss.rqlp",
];

const ENDPOINT_FIXTURES: &[&str] = &[
    "endpoints/http-request-parameter.rqlp",
    "endpoints/resource-acquire.rqlp",
    "endpoints/resource-close.rqlp",
    "endpoints/sensitive-user-pii.rqlp",
];

fn fixture_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/policies")
        .join(relative)
}

fn fixture_source(relative: &str) -> String {
    let path = fixture_path(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn parse(source: &str, identity: &str) -> Result<ParsedRqlpDocument, String> {
    parse_rqlp_source(source, PolicySourceIdentity::new(identity)).map_err(|error| {
        format!(
            "{} at {:?}: {}",
            error.diagnostic.code, error.diagnostic.range, error.diagnostic.message,
        )
    })
}

fn parse_fixture(relative: &str) -> ParsedRqlpDocument {
    let path = fixture_path(relative);
    let source = fixture_source(relative);
    parse_rqlp_source(&source, PolicySourceIdentity::new(path.to_string_lossy())).unwrap_or_else(
        |error| {
            panic!(
                "failed to parse {} at {:?}: {} ({})",
                path.display(),
                error.diagnostic.range,
                error.diagnostic.message,
                error.diagnostic.code,
            )
        },
    )
}

fn normalized_gold_path(relative: &str) -> PathBuf {
    let relative = relative
        .strip_suffix(".rqlp")
        .expect("policy fixtures use the .rqlp suffix");
    fixture_path(&format!("{relative}.normalized.json"))
}

fn inline_semantic_gold_path(relative: &str) -> PathBuf {
    let relative = relative
        .strip_suffix(".rqlp")
        .expect("policy fixtures use the .rqlp suffix");
    fixture_path(&format!("{relative}.inline-semantic.json"))
}

#[test]
fn shipped_examples_cover_every_document_and_analysis_variant() {
    for relative in POLICY_FIXTURES {
        assert!(
            matches!(
                parse_fixture(relative).document(),
                RqlpDocument::Policy { .. }
            ),
            "{relative} should be a policy document",
        );
    }
    for relative in ENDPOINT_FIXTURES {
        assert!(
            matches!(
                parse_fixture(relative).document(),
                RqlpDocument::Endpoint { .. }
            ),
            "{relative} should be an endpoint document",
        );
    }

    let RqlpDocument::Policy { definition } = parse_fixture("dynamic-eval.rqlp").into_document()
    else {
        panic!("dynamic-eval should be a policy")
    };
    assert!(matches!(definition.analysis, PolicyAnalysis::Match { .. }));

    let RqlpDocument::Policy { definition } =
        parse_fixture("attacker-controlled-to-sensitive-sinks.rqlp").into_document()
    else {
        panic!("attacker-controlled-to-sensitive-sinks should be a policy")
    };
    let PolicyAnalysis::Taint { spec } = definition.analysis else {
        panic!("expected taint analysis")
    };
    assert!(matches!(
        definition.metadata.message,
        PolicyMessageSpec::Generated { .. }
    ));
    assert_eq!(spec.sources.include_matches.len(), 1);
    assert_eq!(spec.sinks.include_matches.len(), 1);
    assert_eq!(spec.finding_combinations.len(), 1);
    assert_eq!(
        spec.finding_combinations[0].message,
        "User-controlled I/O can reach sensitive user PII"
    );

    let RqlpDocument::Policy { definition } =
        parse_fixture("resource-lifecycle.rqlp").into_document()
    else {
        panic!("resource-lifecycle should be a policy")
    };
    let PolicyAnalysis::Typestate { spec } = definition.analysis else {
        panic!("expected typestate analysis")
    };
    assert!(matches!(
        spec.automaton.events[0].trigger,
        TypestateEventTrigger::MatchEndpoints { .. }
    ));
    assert!(
        spec.automaton
            .terminal_expectations
            .iter()
            .any(|expectation| {
                matches!(
                    expectation.trigger,
                    TypestateTerminalTrigger::SemanticEvent {
                        event: PolicySemanticEvent::NormalProcedureExit { .. }
                    }
                )
            })
    );
    assert!(
        spec.automaton
            .terminal_expectations
            .iter()
            .any(|expectation| {
                matches!(
                    expectation.trigger,
                    TypestateTerminalTrigger::SemanticEvent {
                        event: PolicySemanticEvent::ExceptionalProcedureExit { .. }
                    }
                )
            })
    );

    let RqlpDocument::Policy { definition } =
        parse_fixture("classification-cvss.rqlp").into_document()
    else {
        panic!("classification-cvss should be a policy")
    };
    let classification = definition
        .classification
        .expect("classification fixture should decode classification metadata");
    assert_eq!(classification.refinements.len(), 1);
    assert_eq!(
        classification
            .cvss
            .expect("classification fixture should decode CVSS policy")
            .metric_rules
            .len(),
        1
    );

    let RqlpDocument::Endpoint { definition } =
        parse_fixture("endpoints/http-request-parameter.rqlp").into_document()
    else {
        panic!("HTTP request parameter should be an endpoint")
    };
    assert_eq!(definition.role, EndpointRole::Source);
    let RqlpDocument::Endpoint { definition } =
        parse_fixture("endpoints/sensitive-user-pii.rqlp").into_document()
    else {
        panic!("sensitive PII should be an endpoint")
    };
    assert_eq!(definition.role, EndpointRole::Sink);
}

#[test]
fn normalized_authored_json_matches_checked_in_golds() {
    for relative in POLICY_FIXTURES.iter().chain(ENDPOINT_FIXTURES) {
        let actual = parse_fixture(relative)
            .document()
            .to_normalized_authored_json();
        let path = normalized_gold_path(relative);
        let expected: Value = serde_json::from_str(
            &std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display())),
        )
        .unwrap_or_else(|error| panic!("invalid JSON gold {}: {error}", path.display()));
        assert_eq!(actual, expected, "normalized JSON drifted for {relative}");
    }
}

#[test]
fn inline_local_semantic_json_matches_golds_and_drops_authoring_only_tags() {
    for relative in ["dynamic-eval.rqlp", "endpoints/http-request-parameter.rqlp"] {
        let document = parse_fixture(relative);
        let actual = document
            .to_inline_local_canonical_semantic_json()
            .expect("closed inline fixture should have a local semantic projection");
        let path = inline_semantic_gold_path(relative);
        let expected: Value = serde_json::from_str(
            &std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display())),
        )
        .unwrap_or_else(|error| panic!("invalid JSON gold {}: {error}", path.display()));
        assert_eq!(actual, expected, "semantic JSON drifted for {relative}");

        let selector_path = if relative.starts_with("endpoints/") {
            "/selector"
        } else {
            "/analysis/selector"
        };
        assert!(
            actual.pointer(&format!("{selector_path}/type")).is_none(),
            "the authored inline-selector tag must not enter semantic meaning",
        );
        assert_eq!(
            actual.pointer(&format!("{selector_path}/schema_version")),
            Some(&Value::from(2)),
        );
    }

    let directory_composed = parse_fixture("attacker-controlled-to-sensitive-sinks.rqlp");
    assert!(matches!(
        directory_composed
            .to_inline_local_canonical_semantic_json(),
        Err(InlineLocalSemanticProjectionError::MatchDirectory { path })
            if path == "tests/fixtures/policies/endpoints"
    ));
}

#[test]
fn omitted_versions_select_latest_compatible_but_explicit_versions_are_exact() {
    let implicit = parse_fixture("dynamic-eval.rqlp");
    assert_eq!(implicit.schema_resolution().version, 1);
    assert_eq!(
        implicit.schema_resolution().origin,
        SchemaVersionOrigin::ImplicitCompatible
    );
    let implicit_semantic = implicit.to_inline_local_canonical_semantic_json().unwrap();
    let RqlpDocument::Policy {
        definition: implicit_definition,
    } = implicit.into_document()
    else {
        panic!("expected policy")
    };
    let PolicyAnalysis::Match { spec } = &implicit_definition.analysis else {
        panic!("expected match policy")
    };
    let PolicySelector::Inline { schema, .. } = &spec.selector else {
        panic!("expected inline selector")
    };
    assert_eq!(schema.version, 2);
    assert_eq!(schema.origin, SchemaVersionOrigin::ImplicitCompatible);

    let explicit_source = fixture_source("dynamic-eval.rqlp")
        .replacen("(policy", "(policy\n  :schema-version 1", 1)
        .replacen("(rql", "(rql :schema-version 2", 1);
    let explicit = parse(&explicit_source, "explicit.rqlp").expect("explicit policy should parse");
    assert_eq!(explicit.schema_resolution().version, 1);
    assert_eq!(
        explicit.schema_resolution().origin,
        SchemaVersionOrigin::Explicit
    );
    let RqlpDocument::Policy { definition } = explicit.document() else {
        panic!("expected explicit policy")
    };
    let PolicyAnalysis::Match { spec } = &definition.analysis else {
        panic!("expected explicit match policy")
    };
    let PolicySelector::Inline { schema, .. } = &spec.selector else {
        panic!("expected explicit inline selector")
    };
    assert_eq!(schema.version, 2);
    assert_eq!(schema.origin, SchemaVersionOrigin::Explicit);
    let implicit_document = RqlpDocument::Policy {
        definition: implicit_definition,
    };
    assert_eq!(
        explicit.document().to_normalized_authored_json(),
        implicit_document.to_normalized_authored_json(),
        "version provenance is not part of normalized authored JSON",
    );
    assert_eq!(
        explicit.to_inline_local_canonical_semantic_json().unwrap(),
        implicit_semantic,
        "explicit and inferred version origins do not change semantic meaning",
    );

    let unsupported_policy = "(policy :schema-version 999 :id \"p\" :unknown-field true)";
    let error = parse_rqlp_source(
        unsupported_policy,
        PolicySourceIdentity::new("unsupported-policy.rqlp"),
    )
    .unwrap_err();
    assert_eq!(error.diagnostic.code, "unsupported-policy-schema-version");
    assert_eq!(&unsupported_policy[error.diagnostic.range], "999");
    assert!(
        error
            .diagnostic
            .message
            .contains("supported exact versions: 1")
    );

    let unsupported_rql = r#"(policy
      :id "p"
      :name "P"
      :message "M"
      :severity warning
      :analysis
        (analysis
          :type match
          :selector (rql :schema-version 999 (call))))"#;
    let error = parse_rqlp_source(
        unsupported_rql,
        PolicySourceIdentity::new("unsupported-rql.rqlp"),
    )
    .unwrap_err();
    assert_eq!(error.diagnostic.code, "unsupported-rql-schema-version");
    assert_eq!(&unsupported_rql[error.diagnostic.range], "999");
    assert!(
        error
            .diagnostic
            .message
            .contains("supported exact versions: 2")
    );
}

#[test]
fn inline_selector_projection_and_source_map_are_semantic_and_range_exact() {
    let source = fixture_source("dynamic-eval.rqlp");
    let parsed = parse_rqlp_source(&source, PolicySourceIdentity::new("dynamic-eval.rqlp"))
        .expect("fixture should parse");
    let normalized = parsed.document().to_normalized_authored_json();
    assert_eq!(
        normalized.pointer("/analysis/selector/schema_version"),
        Some(&Value::from(2))
    );
    assert_eq!(
        normalized.pointer("/analysis/selector/query/schema_version"),
        Some(&Value::from(2))
    );
    assert!(
        normalized
            .pointer("/analysis/selector/query/limit")
            .is_none()
    );
    assert!(
        normalized
            .pointer("/analysis/selector/query/result_detail")
            .is_none()
    );

    let query = parsed
        .source_map()
        .iter()
        .find(|entry| entry.path == "/analysis/selector/query")
        .expect("inline selector should map its nested RQL query");
    assert_eq!(
        &source[query.range.clone()],
        "(language python\n            (call :callee (name \"eval\")))"
    );
}

#[test]
fn file_selector_remains_typed_and_unresolved_until_workspace_loading() {
    let source = r#"(policy
      :id "bifrost.security.file-selector"
      :name "File selector"
      :message "File selector matched"
      :severity note
      :analysis
        (analysis
          :type match
          :selector
            (rql-file :schema-version 2 :path "queries/eval.rql")))"#;
    let parsed = parse_rqlp_source(source, PolicySourceIdentity::new("file-selector.rqlp"))
        .expect("file selector should decode without performing I/O");
    assert_eq!(parsed.unresolved_file_selectors().len(), 1);
    let unresolved = &parsed.unresolved_file_selectors()[0];
    assert_eq!(unresolved.path, "/analysis/selector");
    assert_eq!(unresolved.authored_schema_version, Some(2));
    assert_eq!(unresolved.workspace_path.as_str(), "queries/eval.rql");
    assert_eq!(
        &source[unresolved.range.clone()],
        "(rql-file :schema-version 2 :path \"queries/eval.rql\")"
    );
    assert_eq!(
        parsed
            .document()
            .to_normalized_authored_json()
            .pointer("/analysis/selector"),
        Some(&serde_json::json!({
            "type": "file",
            "authored_schema_version": 2,
            "path": "queries/eval.rql",
        }))
    );
    assert!(matches!(
        parsed.to_inline_local_canonical_semantic_json(),
        Err(InlineLocalSemanticProjectionError::FileSelector { path })
            if path == "queries/eval.rql"
    ));
}

#[test]
fn diagnostics_point_into_nested_rql_and_validation_is_deterministic() {
    let output_control = r#"(policy
      :id "p"
      :name "P"
      :message "M"
      :severity warning
      :analysis
        (analysis
          :type match
          :selector
            (rql (union (call) (result-detail full (call))))))"#;
    let error = parse_rqlp_source(
        output_control,
        PolicySourceIdentity::new("output-control.rqlp"),
    )
    .unwrap_err();
    assert_eq!(error.diagnostic.code, "query-output-control-not-allowed");
    assert_eq!(
        &output_control[error.diagnostic.range.clone()],
        "result-detail"
    );
    assert!(error.diagnostic.fix.is_none());
    assert!(error.diagnostic.related.is_empty());

    let diagnostics = validate_rqlp_source(output_control);
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0], error.diagnostic);

    let invalid_inline = r#"(policy
      :id "p"
      :name "P"
      :message "M"
      :severity warning
      :analysis
        (analysis
          :type match
          :selector (rql (call :callee (name 42)))))"#;
    let error = parse_rqlp_source(
        invalid_inline,
        PolicySourceIdentity::new("invalid-inline.rqlp"),
    )
    .unwrap_err();
    assert_eq!(error.diagnostic.code, "invalid-inline-rql");
    assert_eq!(&invalid_inline[error.diagnostic.range], "42");
}

#[test]
fn selector_evidence_references_must_name_an_exact_registered_selector_path() {
    let source = fixture_source("classification-cvss.rqlp");
    let valid = source.replace(
        ":evidence-refs [policy:self]",
        ":evidence-refs [selector:/analysis/selector]",
    );
    let parsed = parse_rqlp_source(&valid, PolicySourceIdentity::new("valid-selector-ref.rqlp"))
        .expect("the exact match selector path should resolve");
    parsed
        .to_inline_local_canonical_semantic_json()
        .expect("the resolved selector evidence should remain closed");

    let invalid = source.replace(
        ":evidence-refs [policy:self]",
        ":evidence-refs [selector:/analysis/missing]",
    );
    let error = parse_rqlp_source(
        &invalid,
        PolicySourceIdentity::new("invalid-selector-ref.rqlp"),
    )
    .unwrap_err();
    assert_eq!(error.diagnostic.code, "unknown-selector-evidence-reference");
    assert_eq!(
        &invalid[error.diagnostic.range],
        "selector:/analysis/missing"
    );
}

#[test]
fn source_validation_recovers_independent_bounded_schema_errors() {
    let source = r#"(policy
      :id "first"
      :id "second"
      :name "Example"
      :unknown-one 1
      :unknown-two 2
      :tags [alpha alpha beta beta]
      :message "Message"
      :severity warning
      :analysis (analysis :type match :selector (rql (call))))"#;
    let diagnostics = validate_rqlp_source(source);
    let actual = diagnostics
        .iter()
        .map(|diagnostic| (diagnostic.code, &source[diagnostic.range.clone()]))
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        vec![
            ("duplicate-field", ":id"),
            ("unknown-field", ":unknown-one"),
            ("unknown-field", ":unknown-two"),
            ("duplicate-set-value", "alpha"),
            ("duplicate-set-value", "beta"),
        ]
    );
    assert_eq!(validate_rqlp_source(source), diagnostics);
}

#[test]
fn local_category_combinations_require_loaded_endpoint_composition() {
    let source = r#"(policy
      :id "test.local-category-combination"
      :name "Local category combination"
      :message (generated-message :relation can-reach)
      :severity warning
      :analysis (analysis
        :type taint
        :mode may
        :sources (endpoint-set)
        :sinks (endpoint-set)
        :finding-combinations [(finding-combination
          :id specific
          :source (categories :all [input.user-controlled])
          :sink (categories :all [data.pii])
          :message "User-controlled I/O can reach sensitive user PII")]))"#;
    let parsed = parse_rqlp_source(
        source,
        PolicySourceIdentity::new("local-category-combination.rqlp"),
    )
    .expect("the authoring document is valid without external dependencies");

    assert!(matches!(
        parsed.to_inline_local_canonical_semantic_json(),
        Err(InlineLocalSemanticProjectionError::EndpointPredicateRequiresComposition)
    ));
}

#[test]
fn formatter_is_lossless_for_comments_unicode_and_in_progress_schema_errors() {
    let source = "; π before\n(policy :id \"bifrost.example.λ\" :future (unknown-record :text \"escaped\\n🐉\") ; inline comment\n :schema-version 999)\n; after\n";
    for width in [80, 100, 120] {
        let options = PolicyFormatOptions::new(width).unwrap();
        let once = format_rqlp_source_with_options(source, &options)
            .expect("syntactically valid but schema-invalid buffers remain formattable");
        let twice = format_rqlp_source_with_options(&once, &options).unwrap();
        assert_eq!(once, twice, "formatter must be idempotent at width {width}");
        assert!(once.starts_with("; π before\n"));
        assert!(once.contains("; inline comment"));
        assert!(once.contains("\"escaped\\n🐉\""));
        assert!(once.ends_with("\n; after\n"));
        assert!(once.contains(":schema-version 999"));
    }

    let incomplete = format_rqlp_source("(policy :id \"unfinished\"").unwrap_err();
    assert_eq!(incomplete.diagnostic.code, "incomplete-s-expression");
    assert_eq!(incomplete.diagnostic.range.end, 24);
}

#[test]
fn formatter_preserves_crlf_without_creating_mixed_line_endings() {
    let source = "; before\r\n(policy :id \"p\" :name \"P\" :message \"M\" :severity warning :analysis (analysis :type match :selector (rql (call :callee (name \"eval\")))))\r\n; after\r\n";
    let options = PolicyFormatOptions::new(80).unwrap();
    let once = format_rqlp_source_with_options(source, &options).unwrap();
    let without_crlf = once.replace("\r\n", "");

    assert!(once.contains("\r\n  :analysis"), "{once:?}");
    assert!(once.ends_with("\r\n; after\r\n"), "{once:?}");
    assert!(!without_crlf.contains(['\r', '\n']), "{once:?}");
    assert_eq!(
        format_rqlp_source_with_options(&once, &options).unwrap(),
        once,
        "CRLF formatting must be idempotent",
    );
}

#[test]
fn complete_document_formatting_matches_width_golds_and_is_idempotent() {
    let source = fixture_source("endpoints/http-request-parameter.rqlp");
    for width in [80, 100, 120] {
        let options = PolicyFormatOptions::new(width).unwrap();
        let actual = format_rqlp_source_with_options(&source, &options).unwrap();
        let gold_path = fixture_path(&format!(
            "endpoints/http-request-parameter.format-{width}.rqlp"
        ));
        let expected = std::fs::read_to_string(&gold_path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", gold_path.display()));
        assert_eq!(actual, expected, "formatter gold drifted at width {width}");
        assert_eq!(
            format_rqlp_source_with_options(&actual, &options).unwrap(),
            actual,
            "formatter was not idempotent at width {width}",
        );
    }
}
