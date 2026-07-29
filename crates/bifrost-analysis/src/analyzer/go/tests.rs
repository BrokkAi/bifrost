use crate::analyzer::{ProjectFile, TestAssertionSmell, TestAssertionWeights};
use regex::Regex;
use std::sync::LazyLock;
use tree_sitter::Node;

use super::declarations::go_node_text;

static GO_TEST_FUNC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)func\s+(?P<name>Test[A-Za-z0-9_]+)\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s+\*testing\.T\s*\)\s*\{(?P<body>.*?)\n\}"#,
    )
    .expect("valid regex")
});
static GO_ASSERT_EQUALITY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?:assert|require)\.(?:Equal|Same)\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*,\s*(?P<left>[^,\n]+?)\s*,\s*(?P<right>[^,\n\)]+)"#,
    )
    .expect("valid regex")
});
static GO_ASSERT_TRUTH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?:assert|require)\.(?P<matcher>True|False|Nil|NotNil|NoError)\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*,\s*(?P<arg>[^,\n\)]+)"#,
    )
    .expect("valid regex")
});
static GO_PANICS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?:assert|require)\.Panics\s*\("#).expect("valid regex"));
static GO_VERIFY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\.\s*AssertExpectations\s*\("#).expect("valid regex"));
static GO_TESTING_ERRORF_BRANCH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)if\s+(?P<cond>.*?)\s*\{\s*[A-Za-z_][A-Za-z0-9_]*\.(?:Errorf|Fatalf|Error|Fatal)\s*\("#,
    )
    .expect("valid regex")
});

#[derive(Clone)]
struct GoAssertionSignal {
    kind: String,
    score: i32,
    shallow: bool,
    meaningful: bool,
    reason: String,
    excerpt: String,
    start_byte: usize,
}

pub(super) fn detect_go_test_assertion_smells(
    file: &ProjectFile,
    source: &str,
    weights: &TestAssertionWeights,
) -> Vec<TestAssertionSmell> {
    let mut findings = Vec::new();
    for captures in GO_TEST_FUNC_RE.captures_iter(source) {
        let Some(name_match) = captures.name("name") else {
            continue;
        };
        let Some(body_match) = captures.name("body") else {
            continue;
        };
        analyze_go_test_case(
            file,
            name_match.as_str(),
            body_match.as_str(),
            body_match.start(),
            weights,
            &mut findings,
        );
    }
    findings
}

fn analyze_go_test_case(
    file: &ProjectFile,
    name: &str,
    body: &str,
    start_byte: usize,
    weights: &TestAssertionWeights,
    out: &mut Vec<TestAssertionSmell>,
) {
    let assertions = collect_go_assertions(body, weights);
    let assertion_count = assertions.len() as i32;
    let symbol = format!("{}::{}", file, name);

    if assertion_count == 0 {
        out.push(TestAssertionSmell {
            file: file.clone(),
            enclosing_fq_name: symbol,
            assertion_kind: "no-assertions".to_string(),
            score: weights.no_assertion_weight,
            assertion_count: 0,
            reasons: vec!["no-assertions".to_string()],
            excerpt: compact_go_excerpt(body),
            start_byte,
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
            start_byte: start_byte + assertion.start_byte,
        });
    }

    if assertions.iter().all(|assertion| assertion.shallow) {
        let score = (weights.shallow_assertion_only_weight
            - go_meaningful_assertion_credit(assertions.iter(), weights))
        .max(0);
        if score > 0 {
            out.push(TestAssertionSmell {
                file: file.clone(),
                enclosing_fq_name: symbol,
                assertion_kind: "shallow-assertions-only".to_string(),
                score,
                assertion_count,
                reasons: vec!["shallow-assertions-only".to_string()],
                excerpt: compact_go_excerpt(body),
                start_byte,
            });
        }
    }
}

fn collect_go_assertions(body: &str, weights: &TestAssertionWeights) -> Vec<GoAssertionSignal> {
    let mut assertions = Vec::new();

    for captures in GO_ASSERT_EQUALITY_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let left = normalize_go_expr(captures.name("left").map(|m| m.as_str()).unwrap_or(""));
        let right = normalize_go_expr(captures.name("right").map(|m| m.as_str()).unwrap_or(""));
        let signal = if left == right {
            let (kind, reason, score) = if is_go_literal(&left) {
                (
                    "constant-equality",
                    "constant-equality",
                    weights.constant_equality_weight,
                )
            } else {
                (
                    "self-comparison",
                    "self-comparison",
                    weights.tautological_assertion_weight,
                )
            };
            GoAssertionSignal {
                kind: kind.to_string(),
                score,
                shallow: false,
                meaningful: false,
                reason: reason.to_string(),
                excerpt: compact_go_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        } else {
            GoAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                meaningful: true,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_go_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        };
        assertions.push(signal);
    }

    for captures in GO_ASSERT_TRUTH_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let matcher = captures.name("matcher").map(|m| m.as_str()).unwrap_or("");
        let arg = normalize_go_expr(captures.name("arg").map(|m| m.as_str()).unwrap_or(""));
        let (kind, score, shallow) = match matcher {
            "True" if arg == "true" => ("constant-truth", weights.constant_truth_weight, true),
            "False" if arg == "false" => ("constant-truth", weights.constant_truth_weight, true),
            "Nil" | "NotNil" => ("nullness-only", weights.nullness_only_weight, true),
            _ => ("meaningful-assertion", 0, false),
        };
        assertions.push(GoAssertionSignal {
            kind: kind.to_string(),
            score,
            shallow,
            meaningful: score == 0,
            reason: kind.to_string(),
            excerpt: compact_go_excerpt(whole.as_str()),
            start_byte: whole.start(),
        });
    }

    for regex in [&*GO_PANICS_RE, &*GO_VERIFY_RE] {
        for captures in regex.captures_iter(body) {
            let whole = captures.get(0).expect("whole match");
            assertions.push(GoAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                meaningful: true,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_go_excerpt(whole.as_str()),
                start_byte: whole.start(),
            });
        }
    }

    for captures in GO_TESTING_ERRORF_BRANCH_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let cond = normalize_go_expr(captures.name("cond").map(|m| m.as_str()).unwrap_or(""));
        let signal = if let Some((left, right)) = split_go_comparison(&cond, "==") {
            if left == right {
                let (kind, reason, score, shallow) = if is_go_literal(&left) {
                    (
                        "constant-equality",
                        "constant-equality",
                        weights.constant_equality_weight,
                        false,
                    )
                } else {
                    (
                        "self-comparison",
                        "self-comparison",
                        weights.tautological_assertion_weight,
                        false,
                    )
                };
                GoAssertionSignal {
                    kind: kind.to_string(),
                    score,
                    shallow,
                    meaningful: false,
                    reason: reason.to_string(),
                    excerpt: compact_go_excerpt(whole.as_str()),
                    start_byte: whole.start(),
                }
            } else if matches!(right.as_str(), "nil") || matches!(left.as_str(), "nil") {
                GoAssertionSignal {
                    kind: "nullness-only".to_string(),
                    score: weights.nullness_only_weight,
                    shallow: true,
                    meaningful: false,
                    reason: "nullness-only".to_string(),
                    excerpt: compact_go_excerpt(whole.as_str()),
                    start_byte: whole.start(),
                }
            } else {
                GoAssertionSignal {
                    kind: "meaningful-assertion".to_string(),
                    score: 0,
                    shallow: false,
                    meaningful: true,
                    reason: "meaningful-assertion".to_string(),
                    excerpt: compact_go_excerpt(whole.as_str()),
                    start_byte: whole.start(),
                }
            }
        } else if let Some((_left, _right)) = split_go_comparison(&cond, "!=") {
            GoAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                meaningful: true,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_go_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        } else {
            GoAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                meaningful: true,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_go_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        };
        assertions.push(signal);
    }

    assertions
}

fn go_meaningful_assertion_credit<'a>(
    assertions: impl Iterator<Item = &'a GoAssertionSignal>,
    weights: &TestAssertionWeights,
) -> i32 {
    let count = assertions.filter(|assertion| assertion.meaningful).count() as i32;
    let creditable = count.min(weights.meaningful_assertion_credit_cap.max(0));
    weights.meaningful_assertion_credit.max(0) * creditable
}

fn normalize_go_expr(expr: &str) -> String {
    expr.trim()
        .trim_end_matches(',')
        .trim_matches(|ch| matches!(ch, '(' | ')' | ' '))
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_go_literal(expr: &str) -> bool {
    let trimmed = expr.trim();
    (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || matches!(trimmed, "true" | "false" | "nil")
        || trimmed.parse::<i64>().is_ok()
        || trimmed.parse::<f64>().is_ok()
}

fn compact_go_excerpt(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn split_go_comparison(expr: &str, op: &str) -> Option<(String, String)> {
    let (left, right) = expr.split_once(op)?;
    Some((normalize_go_expr(left), normalize_go_expr(right)))
}

pub(super) fn go_contains_tests(root: Node<'_>, source: &str) -> bool {
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        if child.kind() != "function_declaration" {
            continue;
        }
        if is_go_test_function(child, source) {
            return true;
        }
    }
    false
}

fn is_go_test_function(node: Node<'_>, source: &str) -> bool {
    let Some(name_node) = node.child_by_field_name("name") else {
        return false;
    };
    let name = go_node_text(name_node, source).trim();
    if !name.starts_with("Test") || node.child_by_field_name("type_parameters").is_some() {
        return false;
    }
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return false;
    };
    let raw = go_node_text(parameters, source).replace(char::is_whitespace, "");
    static GO_TEST_PARAM_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"^\([A-Za-z_][A-Za-z0-9_]*(\*?)testing\.T\)$").unwrap()
    });
    GO_TEST_PARAM_RE.is_match(&raw)
}
