use super::declarations::py_node_text;
use super::*;
use regex::Regex;
use std::sync::LazyLock;
use tree_sitter::{Node, Parser};

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

#[derive(Clone)]
struct PythonAssertionSignal {
    kind: String,
    score: i32,
    shallow: bool,
    meaningful: bool,
    reason: String,
    excerpt: String,
    start_byte: usize,
}

pub(super) fn detect_python_test_assertion_smells(
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
    let assertions = collect_python_assertions(&test_case.body, weights);
    let assertion_count = assertions.len() as i32;
    let symbol = format!("{}::{}", file, test_case.name);

    if assertion_count == 0 {
        out.push(TestAssertionSmell {
            file: file.clone(),
            enclosing_fq_name: symbol,
            assertion_kind: "no-assertions".to_string(),
            score: weights.no_assertion_weight,
            assertion_count: 0,
            reasons: vec!["no-assertions".to_string()],
            excerpt: compact_python_excerpt(&test_case.body),
            start_byte: test_case.start_byte,
        });
        return;
    }

    for assertion in &assertions {
        if assertion.score <= 0 {
            continue;
        }
        out.push(TestAssertionSmell {
            file: file.clone(),
            enclosing_fq_name: symbol.clone(),
            assertion_kind: assertion.kind.clone(),
            score: assertion.score,
            assertion_count,
            reasons: vec![assertion.reason.clone()],
            excerpt: assertion.excerpt.clone(),
            start_byte: test_case.start_byte + assertion.start_byte,
        });
    }

    if assertions.iter().all(|assertion| assertion.shallow) {
        let score = (weights.shallow_assertion_only_weight
            - python_meaningful_assertion_credit(assertions.iter(), weights))
        .max(0);
        if score > 0 {
            out.push(TestAssertionSmell {
                file: file.clone(),
                enclosing_fq_name: symbol,
                assertion_kind: "shallow-assertions-only".to_string(),
                score,
                assertion_count,
                reasons: vec!["shallow-assertions-only".to_string()],
                excerpt: compact_python_excerpt(&test_case.body),
                start_byte: test_case.start_byte,
            });
        }
    }
}

fn collect_python_assertions(
    body: &str,
    weights: &TestAssertionWeights,
) -> Vec<PythonAssertionSignal> {
    let mut assertions = Vec::new();

    for captures in PY_ASSERT_EQUALITY_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let left = normalize_python_expr(captures.name("left").map(|m| m.as_str()).unwrap_or(""));
        let right = normalize_python_expr(captures.name("right").map(|m| m.as_str()).unwrap_or(""));
        if left.is_empty() || right.is_empty() {
            continue;
        }
        if left == right {
            let (kind, reason, score) = if is_python_literal(&left) {
                (
                    "constant-equality".to_string(),
                    "constant-equality".to_string(),
                    weights.constant_equality_weight,
                )
            } else {
                (
                    "self-comparison".to_string(),
                    "self-comparison".to_string(),
                    weights.tautological_assertion_weight,
                )
            };
            assertions.push(PythonAssertionSignal {
                kind,
                score,
                shallow: false,
                meaningful: false,
                reason,
                excerpt: compact_python_excerpt(whole.as_str()),
                start_byte: whole.start(),
            });
        } else if let Some(literal) = oversized_python_literal(&left, &right, weights) {
            assertions.push(PythonAssertionSignal {
                kind: "overspecified-literal".to_string(),
                score: weights.overspecified_literal_weight,
                shallow: false,
                meaningful: false,
                reason: format!("overspecified-literal:{literal}"),
                excerpt: compact_python_excerpt(whole.as_str()),
                start_byte: whole.start(),
            });
        } else {
            assertions.push(PythonAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                meaningful: true,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_python_excerpt(whole.as_str()),
                start_byte: whole.start(),
            });
        }
    }

    for captures in PY_ASSERT_TRUTH_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let matcher = captures.name("matcher").map(|m| m.as_str()).unwrap_or("");
        let arg = normalize_python_expr(captures.name("arg").map(|m| m.as_str()).unwrap_or(""));
        let (kind, reason, score, shallow) = match matcher {
            "True" if arg == "True" => (
                "constant-truth".to_string(),
                "constant-truth".to_string(),
                weights.constant_truth_weight,
                true,
            ),
            "False" if arg == "False" => (
                "constant-truth".to_string(),
                "constant-truth".to_string(),
                weights.constant_truth_weight,
                true,
            ),
            "IsNone" | "IsNotNone" => (
                "nullness-only".to_string(),
                "nullness-only".to_string(),
                weights.nullness_only_weight,
                true,
            ),
            _ => (
                "meaningful-assertion".to_string(),
                "meaningful-assertion".to_string(),
                0,
                false,
            ),
        };
        assertions.push(PythonAssertionSignal {
            kind,
            score,
            shallow,
            meaningful: score == 0,
            reason,
            excerpt: compact_python_excerpt(whole.as_str()),
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
            assertions.push(PythonAssertionSignal {
                kind: kind.to_string(),
                score,
                shallow,
                meaningful: false,
                reason: kind.to_string(),
                excerpt: compact_python_excerpt(whole.as_str()),
                start_byte: whole.start(),
            });
        } else {
            assertions.push(PythonAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                meaningful: true,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_python_excerpt(whole.as_str()),
                start_byte: whole.start(),
            });
        }
    }

    for regex in [&*PY_RAISES_RE, &*PY_VERIFY_RE] {
        for captures in regex.captures_iter(body) {
            let whole = captures.get(0).expect("whole match");
            assertions.push(PythonAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                meaningful: true,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_python_excerpt(whole.as_str()),
                start_byte: whole.start(),
            });
        }
    }

    assertions
}

fn python_meaningful_assertion_credit<'a>(
    assertions: impl Iterator<Item = &'a PythonAssertionSignal>,
    weights: &TestAssertionWeights,
) -> i32 {
    let count = assertions.filter(|assertion| assertion.meaningful).count() as i32;
    let creditable = count.min(weights.meaningful_assertion_credit_cap.max(0));
    weights.meaningful_assertion_credit.max(0) * creditable
}

fn normalize_python_expr(expr: &str) -> String {
    expr.trim()
        .trim_end_matches(',')
        .trim_end_matches(':')
        .trim_matches(|ch| matches!(ch, '(' | ')' | ' '))
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_python_literal(expr: &str) -> bool {
    let trimmed = expr.trim();
    (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
        || matches!(trimmed, "True" | "False" | "None")
        || trimmed.parse::<i64>().is_ok()
        || trimmed.parse::<f64>().is_ok()
}

fn oversized_python_literal(
    left: &str,
    right: &str,
    weights: &TestAssertionWeights,
) -> Option<String> {
    [left, right].into_iter().find_map(|expr| {
        let trimmed = expr.trim();
        let unquoted = trimmed
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .or_else(|| {
                trimmed
                    .strip_prefix('\'')
                    .and_then(|s| s.strip_suffix('\''))
            })?;
        (unquoted.len() >= weights.large_literal_length_threshold.max(0) as usize)
            .then(|| trimmed.to_string())
    })
}

fn compact_python_excerpt(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(super) fn python_source_contains_tests(source: &str) -> bool {
    static TEST_DEF_RE: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"(?m)^\s*def\s+test_[A-Za-z0-9_]*\s*\(").unwrap());
    source.contains("@pytest.mark.") || TEST_DEF_RE.is_match(source)
}

impl TestDetectionProvider for PythonAnalyzer {}
