use super::*;

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
fn comparison_chains_are_selectable_and_role_queries_are_incomplete() {
    let (_temp, analyzer) =
        python_analyzer("def check(left, middle, right):\n    return left < middle < right\n");
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
