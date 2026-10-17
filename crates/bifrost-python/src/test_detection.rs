use crate::declarations::py_node_text;
use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::model::{TestAssertionSmell, TestAssertionWeights};
use brokk_bifrost_core::analyzer::test_assertions::{
    CommonTestAssertionKind, TestAssertionSignal, append_test_assertion_findings,
    classify_common_test_assertion, compact_assertion_excerpt, is_common_assertion_literal,
    normalize_assertion_expression, oversized_quoted_literal,
};
use regex::Regex;
use std::sync::LazyLock;
use tree_sitter::{Node, Parser};

const TEST_ASSERTION_EXCERPT_MAX_LEN: usize = 180;

static PY_ASSERT_EQUALITY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"self\.assert(?:Equal|Is)\s*\((?P<left>[^,\n]+?)\s*,\s*(?P<right>[^,\n\)]+)"#)
        .expect("valid regex")
});
static PY_ASSERT_TRUTH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"self\.assert(?P<matcher>True|False|IsNone|IsNotNone)\s*\((?P<arg>[^,\n\)]+)"#)
        .expect("valid regex")
});
static PY_BARE_ASSERT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?m)^\s*assert\s+(?P<expr>[^\n]+)"#).expect("valid regex"));
static PY_RAISES_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"pytest\.raises\s*\(|self\.assertRaises\s*\("#).expect("valid regex")
});
static PY_VERIFY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\.\s*assert_(?:called|called_once|called_once_with|called_with|not_called)\s*\("#)
        .expect("valid regex")
});

#[derive(Clone)]
struct PythonTestCase {
    name: String,
    body: String,
    start_byte: usize,
}

pub fn detect_python_test_assertion_smells(
    file: &ProjectFile,
    source: &str,
    weights: &TestAssertionWeights,
) -> Vec<TestAssertionSmell> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .expect("failed to load python parser");
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let mut test_cases = Vec::new();
    collect_python_test_cases(tree.root_node(), source, &mut test_cases);

    let mut findings = Vec::new();
    for test_case in test_cases {
        analyze_python_test_case(file, &test_case, weights, &mut findings);
    }
    findings
}

fn collect_python_test_cases(node: Node<'_>, source: &str, out: &mut Vec<PythonTestCase>) {
    match node.kind() {
        "function_definition" => {
            if python_function_has_fixture_decorator(node, source) {
                return;
            }
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = py_node_text(name_node, source).trim().to_string();
                if name.starts_with("test_") {
                    let body = node
                        .child_by_field_name("body")
                        .map(|body| py_node_text(body, source).to_string())
                        .unwrap_or_else(|| py_node_text(node, source).to_string());
                    out.push(PythonTestCase {
                        name,
                        body,
                        start_byte: node.start_byte(),
                    });
                }
            }
        }
        "decorated_definition" => {
            if python_decorated_definition_has_fixture(node, source) {
                return;
            }
            let has_pytest_mark = py_node_text(node, source).contains("pytest.mark");
            if has_pytest_mark
                && let Some(definition) = node.child_by_field_name("definition")
                && definition.kind() == "function_definition"
            {
                let name = definition
                    .child_by_field_name("name")
                    .map(|name_node| py_node_text(name_node, source).trim().to_string())
                    .unwrap_or_else(|| "anonymous".to_string());
                let body = definition
                    .child_by_field_name("body")
                    .map(|body| py_node_text(body, source).to_string())
                    .unwrap_or_else(|| py_node_text(definition, source).to_string());
                out.push(PythonTestCase {
                    name,
                    body,
                    start_byte: node.start_byte(),
                });
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_python_test_cases(child, source, out);
    }
}

fn python_function_has_fixture_decorator(function: Node<'_>, source: &str) -> bool {
    let Some(parent) = function.parent() else {
        return false;
    };
    parent.kind() == "decorated_definition"
        && python_decorated_definition_has_fixture(parent, source)
}

fn python_decorated_definition_has_fixture(node: Node<'_>, source: &str) -> bool {
    py_node_text(node, source).contains("@pytest.fixture")
}

fn analyze_python_test_case(
    file: &ProjectFile,
    test_case: &PythonTestCase,
    weights: &TestAssertionWeights,
    out: &mut Vec<TestAssertionSmell>,
) {
    let mut assertions = collect_python_assertions(&test_case.body, weights);
    for assertion in &mut assertions {
        assertion.start_byte = test_case.start_byte.saturating_add(assertion.start_byte);
    }
    let symbol = format!("{}::{}", file, test_case.name);
    append_test_assertion_findings(
        file,
        symbol,
        compact_assertion_excerpt(&test_case.body, TEST_ASSERTION_EXCERPT_MAX_LEN),
        test_case.start_byte,
        &assertions,
        weights,
        out,
    );
}

fn collect_python_assertions(
    body: &str,
    weights: &TestAssertionWeights,
) -> Vec<TestAssertionSignal> {
    let mut assertions = Vec::new();

    for captures in PY_ASSERT_EQUALITY_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let left = normalize_python_expr(captures.name("left").map(|m| m.as_str()).unwrap_or(""));
        let right = normalize_python_expr(captures.name("right").map(|m| m.as_str()).unwrap_or(""));
        if left.is_empty() || right.is_empty() {
            continue;
        }
        if left == right {
            let classification = classify_common_test_assertion(
                if is_python_literal(&left) {
                    CommonTestAssertionKind::ConstantEquality
                } else {
                    CommonTestAssertionKind::SelfComparison
                },
                weights,
            );
            assertions.push(TestAssertionSignal {
                kind: classification.kind.to_string(),
                score: classification.score,
                shallow: classification.shallow,
                meaningful: false,
                reasons: vec![classification.kind.to_string()],
                excerpt: compact_assertion_excerpt(whole.as_str(), TEST_ASSERTION_EXCERPT_MAX_LEN),
                start_byte: whole.start(),
            });
        } else if let Some(literal) = oversized_python_literal(&left, &right, weights) {
            assertions.push(TestAssertionSignal {
                kind: "overspecified-literal".to_string(),
                score: weights.overspecified_literal_weight,
                shallow: false,
                meaningful: false,
                reasons: vec![format!("overspecified-literal:{literal}")],
                excerpt: compact_assertion_excerpt(whole.as_str(), TEST_ASSERTION_EXCERPT_MAX_LEN),
                start_byte: whole.start(),
            });
        } else {
            let classification =
                classify_common_test_assertion(CommonTestAssertionKind::Meaningful, weights);
            assertions.push(TestAssertionSignal {
                kind: classification.kind.to_string(),
                score: classification.score,
                shallow: classification.shallow,
                meaningful: classification.score == 0,
                reasons: vec![classification.kind.to_string()],
                excerpt: compact_assertion_excerpt(whole.as_str(), TEST_ASSERTION_EXCERPT_MAX_LEN),
                start_byte: whole.start(),
            });
        }
    }

    for captures in PY_ASSERT_TRUTH_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let matcher = captures.name("matcher").map(|m| m.as_str()).unwrap_or("");
        let arg = normalize_python_expr(captures.name("arg").map(|m| m.as_str()).unwrap_or(""));
        let kind = match matcher {
            "True" if arg == "True" => CommonTestAssertionKind::ConstantTruth,
            "False" if arg == "False" => CommonTestAssertionKind::ConstantTruth,
            "IsNone" | "IsNotNone" => CommonTestAssertionKind::NullnessOnly,
            _ => CommonTestAssertionKind::Meaningful,
        };
        let classification = classify_common_test_assertion(kind, weights);
        assertions.push(TestAssertionSignal {
            kind: classification.kind.to_string(),
            score: classification.score,
            shallow: classification.shallow,
            meaningful: classification.score == 0,
            reasons: vec![classification.kind.to_string()],
            excerpt: compact_assertion_excerpt(whole.as_str(), TEST_ASSERTION_EXCERPT_MAX_LEN),
            start_byte: whole.start(),
        });
    }

    for captures in PY_BARE_ASSERT_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let expr = normalize_python_expr(captures.name("expr").map(|m| m.as_str()).unwrap_or(""));
        let trimmed = expr.trim();
        let maybe_signal = if trimmed == "True" || trimmed == "False" {
            Some(("constant-truth", weights.constant_truth_weight, true))
        } else if trimmed.contains(" is not None") || trimmed.contains(" is None") {
            Some(("nullness-only", weights.nullness_only_weight, true))
        } else if let Some((left, right)) = trimmed.split_once("==") {
            let left = normalize_python_expr(left);
            let right = normalize_python_expr(right);
            if left == right {
                if is_python_literal(&left) {
                    Some(("constant-equality", weights.constant_equality_weight, false))
                } else {
                    Some((
                        "self-comparison",
                        weights.tautological_assertion_weight,
                        false,
                    ))
                }
            } else if oversized_python_literal(&left, &right, weights).is_some() {
                Some((
                    "overspecified-literal",
                    weights.overspecified_literal_weight,
                    false,
                ))
            } else {
                None
            }
        } else {
            None
        };

        if let Some((kind, score, shallow)) = maybe_signal {
            assertions.push(TestAssertionSignal {
                kind: kind.to_string(),
                score,
                shallow,
                meaningful: false,
                reasons: vec![kind.to_string()],
                excerpt: compact_assertion_excerpt(whole.as_str(), TEST_ASSERTION_EXCERPT_MAX_LEN),
                start_byte: whole.start(),
            });
        } else {
            assertions.push(TestAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                meaningful: true,
                reasons: vec!["meaningful-assertion".to_string()],
                excerpt: compact_assertion_excerpt(whole.as_str(), TEST_ASSERTION_EXCERPT_MAX_LEN),
                start_byte: whole.start(),
            });
        }
    }

    for regex in [&*PY_RAISES_RE, &*PY_VERIFY_RE] {
        for captures in regex.captures_iter(body) {
            let whole = captures.get(0).expect("whole match");
            assertions.push(TestAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                meaningful: true,
                reasons: vec!["meaningful-assertion".to_string()],
                excerpt: compact_assertion_excerpt(whole.as_str(), TEST_ASSERTION_EXCERPT_MAX_LEN),
                start_byte: whole.start(),
            });
        }
    }

    assertions
}

fn normalize_python_expr(expr: &str) -> String {
    normalize_assertion_expression(expr.trim().trim_end_matches(',').trim_end_matches(':'))
}

fn is_python_literal(expr: &str) -> bool {
    let trimmed = expr.trim();
    is_common_assertion_literal(trimmed)
        || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
        || matches!(trimmed, "True" | "False" | "None")
}

fn oversized_python_literal(
    left: &str,
    right: &str,
    weights: &TestAssertionWeights,
) -> Option<String> {
    oversized_quoted_literal(left, right, weights, &['"', '\''])
}

pub fn python_source_contains_tests(source: &str) -> bool {
    static TEST_DEF_RE: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"(?m)^\s*def\s+test_[A-Za-z0-9_]*\s*\(").unwrap());
    source.contains("@pytest.mark.") || TEST_DEF_RE.is_match(source)
}
