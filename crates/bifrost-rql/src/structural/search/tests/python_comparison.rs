use super::*;
use brokk_bifrost_test_macros::hardwon;

const IDENTICAL_EXPRESSIONS_FIXTURE: &str = include_str!(
    "../../../../testdata/structural-search/codeql-python-rules/py-comparison-of-identical-expressions/lib.py"
);
const MISSING_SELF_FIXTURE: &str = include_str!(
    "../../../../testdata/structural-search/codeql-python-rules/py-comparison-missing-self/lib.py"
);

fn python_analyzer(source: &str) -> (tempfile::TempDir, Box<dyn IAnalyzer>) {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), "src/main.py")
        .write(source)
        .expect("write Python source");
    let analyzer = language_analyzer(Language::Python, TestProject::new(root, Language::Python));
    (temp, analyzer)
}

fn run_query(
    analyzer: &dyn IAnalyzer,
    source: &str,
    mode: StructuralAccessMode,
) -> DetailedCodeQueryResult {
    let query = CodeQuery::from_source(source).expect("query should parse");
    execute_code_query_with_access_mode(
        analyzer,
        &query,
        CodeQueryExecutionLimits::default(),
        mode,
        true,
    )
    .expect("query should execute")
}

fn structural_texts(result: &CodeQueryResult) -> Vec<String> {
    result
        .results
        .iter()
        .map(|item| match &item.value {
            CodeQueryResultValue::StructuralMatch { value } => value.text.clone(),
            other => panic!("expected a structural match, got {other:?}"),
        })
        .collect()
}

fn structural_lines(result: &CodeQueryResult) -> Vec<(usize, String)> {
    result
        .results
        .iter()
        .map(|item| match &item.value {
            CodeQueryResultValue::StructuralMatch { value } => {
                (value.start_line, value.text.clone())
            }
            other => panic!("expected a structural match, got {other:?}"),
        })
        .collect()
}

#[test]
fn equality_to_none_and_scalar_comparisons_use_ast_roles() {
    let (_temp, analyzer) = python_analyzer(
        r#"def check(equal_value, identity_value, value):
    equal = equal_value == None
    identity = identity_value is None
    constant = 1 == 1
    signed = -1 == +2
    parenthesized = ((3)) == (+((4)))
    signed_parenthesized = -(5) == +((6))
    variable = value == 1
    arithmetic = (1 + 2) == 3
    inverted = ~1 == 1
    display = (1, 2) == (1, 2)
    dynamic_string = (f"value={value}") == "value"
    assert 7 == 7
    remainder = value % 2
"#,
    );

    let equal_none =
        r#"(language python (comparison :right (null_literal) :operator (text/regex "^==$")))"#;
    let scalar_constants = r#"(not-inside (assertion :test (comparison))
        (language python
          (comparison
            :left (literal :not-kind collection_literal)
            :right (literal :not-kind collection_literal))))"#;
    let remainder = r#"(language python
        (binary_expression :left (identifier) :right (numeric_literal)
          :operator (text/regex "^%$")))"#;

    for mode in [
        StructuralAccessMode::ScanOnly,
        StructuralAccessMode::IndexedRequired,
    ] {
        let equal = run_query(analyzer.as_ref(), equal_none, mode);
        assert_eq!(equal.result.completion(), CodeQueryCompletion::Complete);
        assert_eq!(
            structural_texts(&equal.result),
            vec!["equal_value == None"],
            "`is None` must not satisfy `== None` under {mode:?}"
        );

        let constants = run_query(analyzer.as_ref(), scalar_constants, mode);
        assert_eq!(constants.result.completion(), CodeQueryCompletion::Complete);
        assert_eq!(
            structural_texts(&constants.result),
            vec!["1 == 1", "-1 == +2", "((3)) == (+((4)))", "-(5) == +((6))"],
            "signed and parenthesized constants match, while computed values, collections, variables, and direct assert tests do not under {mode:?}"
        );

        let modulo = run_query(analyzer.as_ref(), remainder, mode);
        assert_eq!(modulo.result.completion(), CodeQueryCompletion::Complete);
        assert_eq!(structural_texts(&modulo.result), vec!["value % 2"]);
    }
}

#[test]
fn constant_comparison_filter_covers_constant_tuples_strings_and_unary_operators() {
    let (_temp, analyzer) = python_analyzer(
        r#"def check(value):
    scalar = 1 == 2
    unary_not = (not True) == False
    bitwise_not = (~1) == -2
    signed = -1 == +2
    joined_string = ("a" + ("b" + "c")) == "abc"
    adjacent_string = ("a" "b") == "ab"
    tuple_constants = ((1, "x"), (False, None)) == ((1, "x"), (False, None))
    tuple_variable = (value, 1) == (value, 1)
    arithmetic = (1 + 2) == 3
    interpolated = f"value={1}" == "value=1"
    assert (8 == 8)
    assert (9 == 9) and (10 == 10)
"#,
    );
    let result = run_query(
        analyzer.as_ref(),
        "(python-comparison-constants (language python (comparison)))",
        StructuralAccessMode::IndexedRequired,
    );
    assert_eq!(result.result.completion(), CodeQueryCompletion::Complete);
    let mut found = structural_texts(&result.result);
    found.sort();
    let expected = [
        "(not True) == False",
        "(~1) == -2",
        "-1 == +2",
        "1 == 2",
        "(\"a\" + (\"b\" + \"c\")) == \"abc\"",
        "(\"a\" \"b\") == \"ab\"",
        "((1, \"x\"), (False, None)) == ((1, \"x\"), (False, None))",
        "9 == 9",
        "10 == 10",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<std::collections::BTreeSet<_>>()
    .into_iter()
    .collect::<Vec<_>>();
    assert_eq!(
        found, expected,
        "constant expressions must be selected from AST operands only"
    );
}

#[test]
fn comparison_using_is_uses_custom_mro_equality_and_builtin_value_types() {
    let (_temp, analyzer) = python_analyzer(
        r#"class HasValueEquality:
    def __eq__(self, other):
        return True

class InheritedEquality(HasValueEquality):
    pass

class IdentityOnly:
    pass

def check(value, left, right):
    direct = HasValueEquality() is HasValueEquality()
    inherited = InheritedEquality() is InheritedEquality()
    inherited_negated = InheritedEquality() is not InheritedEquality()
    no_equality = IdentityOnly() is IdentityOnly()
    string_value = "a value that is not interned" is value
    integer_value = 1 is value
    float_value = 1.5 is value
    tuple_value = (1, "two") is value
    mixed_custom_and_identity = HasValueEquality() is IdentityOnly()
    mixed_literal_and_identity = 1 is IdentityOnly()
    none_singleton = value is None
    true_singleton = value is True
    false_singleton = value is False
    not_implemented_singleton = value is NotImplemented
    ellipsis_singleton = value is Ellipsis
    unresolved = left is right
"#,
    );
    let result = run_query(
        analyzer.as_ref(),
        "(python-comparison-using-is (language python (comparison)))",
        StructuralAccessMode::IndexedRequired,
    );
    assert_eq!(
        result.result.completion(),
        CodeQueryCompletion::Incomplete {
            codes: vec![CodeQueryDiagnosticCode::OccurrenceResolutionIncomplete],
        },
        "literal parameters and unresolved operands retain typed-incomplete class evidence"
    );
    let mut found = structural_texts(&result.result);
    found.sort();
    assert_eq!(
        found,
        vec![
            "\"a value that is not interned\" is value",
            "(1, \"two\") is value",
            "1.5 is value",
            "1 is value",
            "HasValueEquality() is HasValueEquality()",
            "InheritedEquality() is InheritedEquality()",
            "InheritedEquality() is not InheritedEquality()",
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>(),
        "custom and builtin value equality match; identity-only and singleton cases do not"
    );
    assert!(
        result
            .result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("runtime class")),
        "unresolved operand classes are visible as an incomplete diagnostic"
    );
}

#[test]
fn comparison_using_is_keeps_singletons_and_identity_only_classes_as_complete_near_misses() {
    let (_temp, analyzer) = python_analyzer(
        r#"class HasValueEquality:
    def __eq__(self, other):
        return True

class IdentityOnly:
    pass

def check(value):
    none = value is None
    true = value is True
    false = value is False
    not_implemented = value is NotImplemented
    ellipsis = value is Ellipsis
    identity_only = IdentityOnly() is IdentityOnly()
    mixed_custom_and_identity = HasValueEquality() is IdentityOnly()
"#,
    );
    let result = run_query(
        analyzer.as_ref(),
        "(python-comparison-using-is (language python (comparison)))",
        StructuralAccessMode::IndexedRequired,
    );
    assert_eq!(result.result.completion(), CodeQueryCompletion::Complete);
    assert!(
        result.result.results.is_empty(),
        "singleton and identity-only classes use identity semantics"
    );
}

#[test]
fn comparison_using_is_nonportable_distinguishes_cpython_and_universal_interning() {
    let (_temp, analyzer) = python_analyzer(
        r#"class IdentityOnly:
    pass

def check(value):
    short_string = "7" is value
    small_integer = 1 is value
    negative_small_integer = -5 is value
    latin_one_string = "é" is value
    inverse = value is not "8"
    zero = 0 is value
    empty_string = "" is value
    long_string = "long" is value
    large_integer = 257 is value
    below_negative_range = -6 is value
    non_latin_one = "λ" is value
    singleton = None is "7"
    identity_only = 1 is IdentityOnly()
"#,
    );
    let result = run_query(
        analyzer.as_ref(),
        "(python-comparison-using-is-non-portable (language python (comparison)))",
        StructuralAccessMode::IndexedRequired,
    );
    assert_eq!(
        result.result.completion(),
        CodeQueryCompletion::Incomplete {
            codes: vec![CodeQueryDiagnosticCode::OccurrenceResolutionIncomplete],
        },
        "the target literal is known while the other operand class remains open"
    );
    let mut found = structural_texts(&result.result);
    found.sort();
    let expected = [
        "\"7\" is value",
        "1 is value",
        "-5 is value",
        "\"é\" is value",
        "value is not \"8\"",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<std::collections::BTreeSet<_>>()
    .into_iter()
    .collect::<Vec<_>>();
    assert_eq!(found, expected);
}

#[test]
#[hardwon("#5964: ordering-only chains cannot satisfy equality operator demands")]
fn comparison_chains_are_selectable_and_role_queries_are_incomplete() {
    let (temp, analyzer) = python_analyzer(
        "def check(left, middle, right):\n    # == in a comment is not a comparison operator.\n    return left < middle < right\n",
    );
    let broad = run_query(
        analyzer.as_ref(),
        "(language python (comparison))",
        StructuralAccessMode::IndexedRequired,
    );
    assert_eq!(broad.result.completion(), CodeQueryCompletion::Complete);
    assert_eq!(
        structural_texts(&broad.result),
        vec!["left < middle < right"]
    );

    // The indexed kind posting includes the chain subtype, so a role query
    // reaches the chain fact and reports its missing pairwise roles.
    for query in [
        r#"(language python (comparison :left (identifier)))"#,
        r#"(language python (comparison :right (identifier)))"#,
        r#"(language python (comparison :operator (name "<")))"#,
        r#"(python-comparison-constants (language python (comparison)))"#,
        r#"(python-comparison-using-is (language python (comparison)))"#,
        r#"(python-comparison-using-is-non-portable (language python (comparison)))"#,
        r#"(identical-operands (language python (comparison)))"#,
        r#"(python-missing-self (language python (comparison)))"#,
    ] {
        let constrained = run_query(
            analyzer.as_ref(),
            query,
            StructuralAccessMode::IndexedRequired,
        );
        assert_eq!(
            constrained.result.completion(),
            CodeQueryCompletion::Incomplete {
                codes: vec![CodeQueryDiagnosticCode::UnsupportedStructuralFeature],
            },
            "{query}"
        );
        assert!(
            constrained
                .result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("comparison chains")),
            "the missing pairwise roles must be reported for {query}: {:#?}",
            constrained.result.diagnostics
        );
    }

    // The equality spelling in the comment satisfies the name-source anchor,
    // so the grammar proof must inspect operators in indexed and scan access.
    for mode in [
        StructuralAccessMode::IndexedRequired,
        StructuralAccessMode::ScanOnly,
    ] {
        for operator in [
            serde_json::json!({ "name": "==" }),
            serde_json::json!({ "text": { "regex": "^==$" } }),
        ] {
            let query = CodeQuery::from_json(&serde_json::json!({
                "languages": ["python"],
                "match": { "kind": "comparison", "operator": operator, "right": { "kind": "null_literal" } }
            })).expect("equality role query");
            let result = execute_code_query_with_access_mode(
                analyzer.as_ref(),
                &query,
                CodeQueryExecutionLimits::default(),
                mode,
                true,
            )
            .expect("operator proof query");
            assert_eq!(result.result.completion(), CodeQueryCompletion::Complete);
            assert!(result.result.results.is_empty());
        }
    }

    // Boolean and wildcard demands were previously omitted by the coarse
    // admission walk. No predicate from one branch may discharge another.
    for pattern in [
        serde_json::json!({ "kind": "comparison", "operator": { "text": { "regex": "^(==|<)$" } } }),
        serde_json::json!({ "kind": "comparison", "any": [ { "kind": "comparison", "operator": { "name": "==" } }, { "kind": "comparison", "operator": { "name": "<" } } ] }),
        serde_json::json!({ "kind": "comparison", "all": [ { "kind": "comparison", "operator": { "name": "==" } } ] }),
        serde_json::json!({ "kind": "comparison", "not": { "kind": "comparison", "operator": { "name": "==" } } }),
        serde_json::json!({ "kind": "comparison", "not_has": { "kind": "comparison", "operator": { "name": "==" } } }),
    ] {
        let query =
            CodeQuery::from_json(&serde_json::json!({ "languages": ["python"], "match": pattern }))
                .expect("opaque/wildcard role query");
        let result = execute_code_query_with_access_mode(
            analyzer.as_ref(),
            &query,
            CodeQueryExecutionLimits::default(),
            StructuralAccessMode::IndexedRequired,
            true,
        )
        .expect("opaque/wildcard role query execution");
        assert!(
            matches!(
                result.result.completion(),
                CodeQueryCompletion::Incomplete { .. }
            ),
            "{query:?}: {:#?}",
            result.result
        );
        assert!(
            result
                .result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("comparison chains"))
        );
    }

    // Public JSON requires a kind on every role-bearing pattern. Internal
    // rewrites may still carry wildcard IR: exercise that executor boundary
    // only after a valid decode, without weakening the public decoder.
    let mut wildcard =
        CodeQuery::from_source(r#"(language python (comparison :operator (name "<")))"#)
            .expect("valid role query before typed adjustment");
    let crate::query::CodeQueryPlanSource::Seed(seed) = &mut wildcard.plan.source else {
        panic!("structural seed")
    };
    seed.root.kinds.clear();
    // This wildcard has no sound indexed anchor; scan access exercises its
    // unsupported role demand without requiring a structural posting.
    let wildcard_result = execute_code_query_with_access_mode(
        analyzer.as_ref(),
        &wildcard,
        CodeQueryExecutionLimits::default(),
        StructuralAccessMode::ScanOnly,
        true,
    )
    .expect("typed wildcard executor query");
    assert!(
        wildcard_result
            .result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code
                == CodeQueryDiagnosticCode::UnsupportedStructuralFeature
                && diagnostic.message.contains("comparison chains"))
    );
    assert!(matches!(
        wildcard_result.result.completion(),
        CodeQueryCompletion::Incomplete { .. }
    ));

    let negative_context = CodeQuery::from_json(&serde_json::json!({
        "languages": ["python"],
        "match": { "kind": "comparison" },
        "not_inside": { "kind": "comparison", "operator": { "name": "==" } }
    }))
    .expect("negative seed role demand");
    let negative = execute_code_query_with_access_mode(
        analyzer.as_ref(),
        &negative_context,
        CodeQueryExecutionLimits::default(),
        StructuralAccessMode::IndexedRequired,
        true,
    )
    .expect("negative seed role query");
    assert!(matches!(
        negative.result.completion(),
        CodeQueryCompletion::Incomplete { .. }
    ));

    // Construct exact source anchors independently of the diagnostic producer.
    // One aggregate Incomplete would not prove that BOTH chains stayed open.
    let prefix = "def check(a, b):\n    first = ";
    let first_chain = "a < b == None";
    let between = "\n    return ";
    let second_chain = "a == b is None";
    let first_start = prefix.len();
    let second_start = first_start + first_chain.len() + between.len();
    let expected_ranges = [
        (first_start, first_start + first_chain.len()),
        (second_start, second_start + second_chain.len()),
    ];
    let mixed_source = format!("{prefix}{first_chain}{between}{second_chain}\n");
    let (_mixed_temp, mixed) = python_analyzer(&mixed_source);
    let equality = CodeQuery::from_source(
        r#"(language python (comparison :operator (text/regex "^==$") :right (null_literal)))"#,
    )
    .expect("equality query");
    let result = execute_code_query_with_access_mode(
        mixed.as_ref(),
        &equality,
        CodeQueryExecutionLimits::default(),
        StructuralAccessMode::IndexedRequired,
        true,
    )
    .expect("mixed chain query");
    assert!(matches!(
        result.result.completion(),
        CodeQueryCompletion::Incomplete { .. }
    ));
    assert!(
        result.result.results.is_empty(),
        "no correlated pair roles are invented"
    );
    assert!(
        result
            .result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code
                == CodeQueryDiagnosticCode::UnsupportedStructuralFeature
                && diagnostic
                    .message
                    .ends_with(&format!("at byte ranges {expected_ranges:?}"))),
        "both exact chain ranges must remain diagnosed: {:#?}",
        result.result.diagnostics
    );

    // Exercise the actual bounded syntax bridge without a second parser or a
    // fabricated facts/provider implementation. Wrong bytes, a stopped walk,
    // and an adapter with no grammar hook must never yield an empty domain.
    let providers = analyzer.structural_fact_providers();
    let provider = providers
        .iter()
        .find(|provider| provider.structural_language() == Language::Python)
        .expect("Python provider");
    let file = provider
        .structural_files()
        .into_iter()
        .next()
        .expect("source file");
    let facts = provider.structural_facts(&file).expect("source facts");
    let super::super::super::provider::StructuralSyntaxLimitedOutcome::Available(syntax) =
        provider.structural_syntax_limited(&file, facts.source().len(), None)
    else {
        panic!("exact prepared source")
    };
    let spec = brokk_bifrost_analysis::analyzer::structural_spec_for(Language::Python)
        .expect("Python structural spec");
    let mut complete_checks = 0;
    let domains = super::super::seeds::collect_comparison_chain_operators(
        &facts,
        syntax.prepared(),
        spec,
        &mut || {
            complete_checks += 1;
            true
        },
    )
    .expect("complete operator domain");
    let texts = domains
        .values()
        .flat_map(|operators| {
            operators
                .iter()
                .map(|operator| operator.text(facts.source()))
        })
        .collect::<Vec<_>>();
    assert_eq!(texts, ["<", "<"]);
    for stop_at in [5, complete_checks] {
        let mut checks = 0;
        assert!(
            super::super::seeds::collect_comparison_chain_operators(
                &facts,
                syntax.prepared(),
                spec,
                &mut || {
                    checks += 1;
                    checks < stop_at
                }
            )
            .is_none(),
            "early or final stop cannot publish a domain"
        );
    }
    let unsupported = brokk_bifrost_analysis::analyzer::structural_spec_for(Language::Rust)
        .expect("Rust structural spec");
    assert!(
        super::super::seeds::collect_comparison_chain_operators(
            &facts,
            syntax.prepared(),
            unsupported,
            &mut || true
        )
        .is_none()
    );
    let mixed_providers = mixed.structural_fact_providers();
    let mixed_provider = mixed_providers
        .iter()
        .find(|provider| provider.structural_language() == Language::Python)
        .expect("mixed Python provider");
    let mixed_file = mixed_provider
        .structural_files()
        .into_iter()
        .next()
        .expect("mixed source file");
    let super::super::super::provider::StructuralSyntaxLimitedOutcome::Available(mixed_syntax) =
        mixed_provider.structural_syntax_limited(
            &mixed_file,
            CodeQueryExecutionLimits::default().max_scanned_source_bytes,
            None,
        )
    else {
        panic!("mixed prepared source")
    };
    // Provider ownership follows the language registry, not the workspace root.
    // A real Rust file is outside this Python provider's grammar ownership.
    let unowned_file = ProjectFile::new(
        temp.path().canonicalize().expect("canonical root"),
        "src/unowned.rs",
    );
    unowned_file
        .write("fn unowned() {}\n")
        .expect("write unowned language control");
    let unavailable = provider.structural_syntax_limited(
        &unowned_file,
        CodeQueryExecutionLimits::default().max_scanned_source_bytes,
        None,
    );
    assert!(
        matches!(
            &unavailable,
            super::super::super::provider::StructuralSyntaxLimitedOutcome::Unavailable
        ),
        "unowned language must be unavailable: {unavailable:?}"
    );
    assert!(
        super::super::seeds::collect_comparison_chain_operators(
            &facts,
            mixed_syntax.prepared(),
            spec,
            &mut || true
        )
        .is_none()
    );
    let exceeded = provider.structural_syntax_limited(&file, 0, None);
    assert!(
        matches!(
            &exceeded,
            super::super::super::provider::StructuralSyntaxLimitedOutcome::Exceeded { .. }
        ),
        "zero source admission must be exceeded: {exceeded:?}"
    );
    let cancellation = CancellationToken::default();
    cancellation.cancel();
    let cancelled_syntax =
        provider.structural_syntax_limited(&file, facts.source().len(), Some(&cancellation));
    assert!(
        matches!(
            &cancelled_syntax,
            super::super::super::provider::StructuralSyntaxLimitedOutcome::Cancelled
        ),
        "pre-cancelled syntax request must stay cancelled: {cancelled_syntax:?}"
    );
    let cancelled = execute_with_cancellation(
        analyzer.as_ref(),
        &equality,
        CodeQueryExecutionLimits::default(),
        &cancellation,
    );
    assert_eq!(cancelled.completion(), CodeQueryCompletion::Cancelled);
}

#[test]
fn identical_expression_filter_uses_campaign_binding_and_attribute_fixtures() {
    let (_temp, analyzer) = python_analyzer(IDENTICAL_EXPRESSIONS_FIXTURE);
    let result = run_query(
        analyzer.as_ref(),
        "(identical-operands (language python (comparison)))",
        StructuralAccessMode::IndexedRequired,
    );

    assert_eq!(result.result.completion(), CodeQueryCompletion::Complete);
    assert_eq!(
        structural_texts(&result.result),
        vec!["value == value", "self.value == self.value"],
        "the campaign's distinct roots, distinct members, and NaN-sensitive calls are near misses"
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#4649: CodeQL routes repeated method parameters and locals through missing-self"
)]
fn missing_self_filter_matches_upstream_member_name_heuristic() {
    let (_temp, analyzer) = python_analyzer(MISSING_SELF_FIXTURE);
    let result = run_query(
        analyzer.as_ref(),
        "(python-missing-self (language python (comparison)))",
        StructuralAccessMode::IndexedRequired,
    );

    assert_eq!(result.result.completion(), CodeQueryCompletion::Complete);
    assert_eq!(
        structural_lines(&result.result),
        vec![
            (9, "item == item".to_owned()),
            (15, "item == item".to_owned()),
            (20, "item == item".to_owned()),
        ],
        "CodeQL considers a same-named local or parameter when the class declares that attribute"
    );
}

#[test]
fn identical_expression_filter_reports_unresolved_binding_identity() {
    let (_temp, analyzer) = python_analyzer("def check():\n    return unknown == unknown\n");
    let result = run_query(
        analyzer.as_ref(),
        "(identical-operands (language python (comparison)))",
        StructuralAccessMode::IndexedRequired,
    );
    assert_eq!(
        result.result.completion(),
        CodeQueryCompletion::Incomplete {
            codes: vec![CodeQueryDiagnosticCode::OccurrenceResolutionIncomplete],
        }
    );
    assert!(result.result.results.is_empty());
}
