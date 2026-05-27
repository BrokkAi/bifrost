use super::model::node_text;
use crate::analyzer::{ProjectFile, TestAssertionSmell, TestAssertionWeights};
use regex::Regex;
use std::sync::LazyLock;
use tree_sitter::{Language as TsLanguage, Node, Parser};

static JS_TS_EXPECT_EQUALITY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"expect\s*\((?P<actual>[^()\n]+?)\)\s*(?:\.\s*(?:resolves|rejects|not))*\s*\.\s*(?P<matcher>toBe|toEqual|toStrictEqual)\s*\((?P<expected>[^)\n]+?)\)"#,
    )
    .expect("valid regex")
});
static JS_TS_EXPECT_SHALLOW_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"expect\s*\((?P<actual>[^()\n]+?)\)\s*(?:\.\s*not)?\s*\.\s*(?P<matcher>toBeTruthy|toBeFalsy|toBeDefined|toBeNull|toBeUndefined)\s*\(\s*\)"#,
    )
    .expect("valid regex")
});
static JS_TS_EXPECT_THROW_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"expect\s*\((?P<actual>[^)\n]+?)\)\s*(?:\.\s*(?:rejects|resolves))?\s*\.\s*toThrow(?:Error)?\s*\("#)
        .expect("valid regex")
});
static JS_TS_EXPECT_SNAPSHOT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"expect\s*\((?P<actual>[^)\n]+?)\)\s*\.\s*toMatch(?:Inline)?Snapshot\s*\("#)
        .expect("valid regex")
});
static JS_TS_EXPECT_VERIFY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"expect\s*\((?P<actual>[^)\n]+?)\)\s*\.\s*toHaveBeenCalled(?:Times|With)?\s*\("#)
        .expect("valid regex")
});
static JS_TS_ASSERT_EQUALITY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"assert\.(?P<matcher>strictEqual|equal|deepEqual)\s*\((?P<left>[^,\n]+?)\s*,\s*(?P<right>[^,\n\)]+)"#,
    )
    .expect("valid regex")
});
static JS_TS_ASSERT_TRUTH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"assert\.(?P<matcher>ok|isTrue|isFalse|isNotNull|isNull)\s*\((?P<arg>[^,\n\)]+)"#)
        .expect("valid regex")
});

#[derive(Clone)]
struct JsTsTestCase {
    name: String,
    body: String,
    start_byte: usize,
}

#[derive(Clone)]
struct JsTsAssertionSignal {
    kind: String,
    score: i32,
    shallow: bool,
    meaningful: bool,
    reason: String,
    excerpt: String,
    start_byte: usize,
}

pub(crate) fn detect_js_ts_test_assertion_smells(
    file: &ProjectFile,
    source: &str,
    parser_language: TsLanguage,
    weights: &TestAssertionWeights,
) -> Vec<TestAssertionSmell> {
    let mut parser = Parser::new();
    parser
        .set_language(&parser_language)
        .expect("failed to set js/ts parser language");
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let mut test_cases = Vec::new();
    collect_js_ts_test_cases(tree.root_node(), source, &mut test_cases);

    let mut findings = Vec::new();
    for test_case in test_cases {
        analyze_js_ts_test_case(file, &test_case, weights, &mut findings);
    }
    findings
}

fn collect_js_ts_test_cases(node: Node<'_>, source: &str, out: &mut Vec<JsTsTestCase>) {
    if node.kind() == "call_expression"
        && is_js_ts_test_invocation(node, source)
        && let Some(arguments) = node.child_by_field_name("arguments")
    {
        let mut name: Option<String> = None;
        let mut callback: Option<Node<'_>> = None;
        let mut cursor = arguments.walk();
        for child in arguments.named_children(&mut cursor) {
            match child.kind() {
                "string" | "template_string" if name.is_none() => {
                    name = Some(trim_js_ts_string_literal(node_text(child, source)));
                }
                "arrow_function" | "function" | "generator_function" => {
                    callback = Some(child);
                }
                _ => {}
            }
        }
        if let Some(callback) = callback {
            let body = callback.child_by_field_name("body").unwrap_or(callback);
            out.push(JsTsTestCase {
                name: name.unwrap_or_else(|| "anonymous".to_string()),
                body: node_text(body, source).to_string(),
                start_byte: node.start_byte(),
            });
        }
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_js_ts_test_cases(child, source, out);
    }
}

fn is_js_ts_test_invocation(node: Node<'_>, source: &str) -> bool {
    let Some(function) = node.child_by_field_name("function") else {
        return false;
    };
    let raw = node_text(function, source).trim();
    let terminal = raw
        .split('.')
        .next_back()
        .unwrap_or(raw)
        .trim_matches(|ch: char| ch == '?' || ch == '!');
    terminal == "it" || terminal == "test"
}

fn analyze_js_ts_test_case(
    file: &ProjectFile,
    test_case: &JsTsTestCase,
    weights: &TestAssertionWeights,
    out: &mut Vec<TestAssertionSmell>,
) {
    let assertions = collect_js_ts_assertions(&test_case.body, weights);
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
            excerpt: compact_test_assertion_excerpt(&test_case.body),
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
            - js_ts_meaningful_assertion_credit(assertions.iter(), weights))
        .max(0);
        if score > 0 {
            out.push(TestAssertionSmell {
                file: file.clone(),
                enclosing_fq_name: symbol,
                assertion_kind: "shallow-assertions-only".to_string(),
                score,
                assertion_count,
                reasons: vec!["shallow-assertions-only".to_string()],
                excerpt: compact_test_assertion_excerpt(&test_case.body),
                start_byte: test_case.start_byte,
            });
        }
    }
}

fn collect_js_ts_assertions(
    body: &str,
    weights: &TestAssertionWeights,
) -> Vec<JsTsAssertionSignal> {
    let mut assertions = Vec::new();

    for captures in JS_TS_EXPECT_EQUALITY_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let actual =
            normalize_js_ts_expr(captures.name("actual").map(|m| m.as_str()).unwrap_or(""));
        let expected =
            normalize_js_ts_expr(captures.name("expected").map(|m| m.as_str()).unwrap_or(""));
        if actual.is_empty() || expected.is_empty() {
            continue;
        }
        if actual == expected {
            let (kind, reason, score) = if is_js_ts_literal(&actual) {
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
            assertions.push(JsTsAssertionSignal {
                kind,
                score,
                shallow: false,
                meaningful: false,
                reason,
                excerpt: compact_test_assertion_excerpt(whole.as_str()),
                start_byte: whole.start(),
            });
        } else if let Some(literal) = oversized_js_ts_literal(&actual, &expected, weights) {
            assertions.push(JsTsAssertionSignal {
                kind: "overspecified-literal".to_string(),
                score: weights.overspecified_literal_weight,
                shallow: false,
                meaningful: false,
                reason: format!("overspecified-literal:{literal}"),
                excerpt: compact_test_assertion_excerpt(whole.as_str()),
                start_byte: whole.start(),
            });
        } else {
            assertions.push(JsTsAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                meaningful: true,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_test_assertion_excerpt(whole.as_str()),
                start_byte: whole.start(),
            });
        }
    }

    for captures in JS_TS_EXPECT_SHALLOW_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let actual =
            normalize_js_ts_expr(captures.name("actual").map(|m| m.as_str()).unwrap_or(""));
        let matcher = captures.name("matcher").map(|m| m.as_str()).unwrap_or("");
        let (kind, reason, score) = if actual == "true" && matcher == "toBeTruthy"
            || actual == "false" && matcher == "toBeFalsy"
        {
            (
                "constant-truth".to_string(),
                "constant-truth".to_string(),
                weights.constant_truth_weight,
            )
        } else if matches!(matcher, "toBeNull" | "toBeUndefined" | "toBeDefined") {
            (
                "nullness-only".to_string(),
                "nullness-only".to_string(),
                weights.nullness_only_weight,
            )
        } else {
            (
                "shallow-assertion".to_string(),
                "shallow-assertion".to_string(),
                0,
            )
        };
        assertions.push(JsTsAssertionSignal {
            kind,
            score,
            shallow: true,
            meaningful: false,
            reason,
            excerpt: compact_test_assertion_excerpt(whole.as_str()),
            start_byte: whole.start(),
        });
    }

    for captures in JS_TS_EXPECT_SNAPSHOT_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        assertions.push(JsTsAssertionSignal {
            kind: "snapshot-assertion".to_string(),
            score: weights.overspecified_literal_weight,
            shallow: false,
            meaningful: false,
            reason: "snapshot-assertion".to_string(),
            excerpt: compact_test_assertion_excerpt(whole.as_str()),
            start_byte: whole.start(),
        });
    }

    for regex in [&*JS_TS_EXPECT_THROW_RE, &*JS_TS_EXPECT_VERIFY_RE] {
        for captures in regex.captures_iter(body) {
            let whole = captures.get(0).expect("whole match");
            assertions.push(JsTsAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                meaningful: true,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_test_assertion_excerpt(whole.as_str()),
                start_byte: whole.start(),
            });
        }
    }

    for captures in JS_TS_ASSERT_EQUALITY_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let left = normalize_js_ts_expr(captures.name("left").map(|m| m.as_str()).unwrap_or(""));
        let right = normalize_js_ts_expr(captures.name("right").map(|m| m.as_str()).unwrap_or(""));
        if left.is_empty() || right.is_empty() {
            continue;
        }
        if left == right {
            let (kind, reason, score) = if is_js_ts_literal(&left) {
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
            assertions.push(JsTsAssertionSignal {
                kind,
                score,
                shallow: false,
                meaningful: false,
                reason,
                excerpt: compact_test_assertion_excerpt(whole.as_str()),
                start_byte: whole.start(),
            });
        } else if let Some(literal) = oversized_js_ts_literal(&left, &right, weights) {
            assertions.push(JsTsAssertionSignal {
                kind: "overspecified-literal".to_string(),
                score: weights.overspecified_literal_weight,
                shallow: false,
                meaningful: false,
                reason: format!("overspecified-literal:{literal}"),
                excerpt: compact_test_assertion_excerpt(whole.as_str()),
                start_byte: whole.start(),
            });
        } else {
            assertions.push(JsTsAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                meaningful: true,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_test_assertion_excerpt(whole.as_str()),
                start_byte: whole.start(),
            });
        }
    }

    for captures in JS_TS_ASSERT_TRUTH_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let matcher = captures.name("matcher").map(|m| m.as_str()).unwrap_or("");
        let arg = normalize_js_ts_expr(captures.name("arg").map(|m| m.as_str()).unwrap_or(""));
        let (kind, reason, score, shallow) = match matcher {
            "ok" | "isTrue" if arg == "true" => (
                "constant-truth".to_string(),
                "constant-truth".to_string(),
                weights.constant_truth_weight,
                true,
            ),
            "isFalse" if arg == "false" => (
                "constant-truth".to_string(),
                "constant-truth".to_string(),
                weights.constant_truth_weight,
                true,
            ),
            "isNotNull" | "isNull" => (
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
        assertions.push(JsTsAssertionSignal {
            kind,
            score,
            shallow,
            meaningful: score == 0,
            reason,
            excerpt: compact_test_assertion_excerpt(whole.as_str()),
            start_byte: whole.start(),
        });
    }

    assertions
}

fn js_ts_meaningful_assertion_credit<'a>(
    assertions: impl Iterator<Item = &'a JsTsAssertionSignal>,
    weights: &TestAssertionWeights,
) -> i32 {
    let count = assertions.filter(|assertion| assertion.meaningful).count() as i32;
    let creditable = count.min(weights.meaningful_assertion_credit_cap.max(0));
    weights.meaningful_assertion_credit.max(0) * creditable
}

fn normalize_js_ts_expr(expr: &str) -> String {
    expr.trim()
        .trim_end_matches(';')
        .trim_matches(|ch| matches!(ch, '(' | ')' | ' '))
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_js_ts_literal(expr: &str) -> bool {
    let trimmed = expr.trim();
    (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
        || matches!(trimmed, "true" | "false" | "null" | "undefined")
        || trimmed.parse::<i64>().is_ok()
        || trimmed.parse::<f64>().is_ok()
}

fn oversized_js_ts_literal(
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

fn trim_js_ts_string_literal(raw: &str) -> String {
    raw.trim()
        .trim_matches('`')
        .trim_matches('"')
        .trim_matches('\'')
        .to_string()
}

fn compact_test_assertion_excerpt(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}
