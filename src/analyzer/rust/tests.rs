use crate::analyzer::{ProjectFile, TestAssertionSmell, TestAssertionWeights};
use regex::Regex;
use std::sync::LazyLock;

pub(super) fn rust_source_contains_tests(source: &str) -> bool {
    source.contains("#[cfg(test)]") || source.contains("#[test]")
}

static RUST_TEST_FN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)#\s*\[\s*test\s*\]\s*fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)[^{]*\{(?P<body>.*?)\n\}"#,
    )
    .expect("valid regex")
});
static RUST_ASSERT_EQ_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"assert_eq!\s*\((?P<left>[^,\n]+?)\s*,\s*(?P<right>[^,\n\)]+)"#)
        .expect("valid regex")
});
static RUST_ASSERT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"assert!\s*\((?P<expr>[^\n\)]+)"#).expect("valid regex"));
static RUST_MATCHES_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"matches!\s*\("#).expect("valid regex"));

#[derive(Clone)]
struct RustAssertionSignal {
    kind: String,
    score: i32,
    shallow: bool,
    meaningful: bool,
    reason: String,
    excerpt: String,
    start_byte: usize,
}

pub(super) fn detect_rust_test_assertion_smells(
    file: &ProjectFile,
    source: &str,
    weights: &TestAssertionWeights,
) -> Vec<TestAssertionSmell> {
    let mut findings = Vec::new();
    for captures in RUST_TEST_FN_RE.captures_iter(source) {
        let Some(name_match) = captures.name("name") else {
            continue;
        };
        let Some(body_match) = captures.name("body") else {
            continue;
        };
        analyze_rust_test_case(
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

fn analyze_rust_test_case(
    file: &ProjectFile,
    name: &str,
    body: &str,
    start_byte: usize,
    weights: &TestAssertionWeights,
    out: &mut Vec<TestAssertionSmell>,
) {
    let assertions = collect_rust_assertions(body, weights);
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
            excerpt: compact_rust_excerpt(body),
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
            - rust_meaningful_assertion_credit(assertions.iter(), weights))
        .max(0);
        if score > 0 {
            out.push(TestAssertionSmell {
                file: file.clone(),
                enclosing_fq_name: symbol,
                assertion_kind: "shallow-assertions-only".to_string(),
                score,
                assertion_count,
                reasons: vec!["shallow-assertions-only".to_string()],
                excerpt: compact_rust_excerpt(body),
                start_byte,
            });
        }
    }
}

fn collect_rust_assertions(body: &str, weights: &TestAssertionWeights) -> Vec<RustAssertionSignal> {
    let mut assertions = Vec::new();

    for captures in RUST_ASSERT_EQ_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let left = normalize_rust_expr(captures.name("left").map(|m| m.as_str()).unwrap_or(""));
        let right = normalize_rust_expr(captures.name("right").map(|m| m.as_str()).unwrap_or(""));
        let signal = if left == right {
            let (kind, reason, score) = if is_rust_literal(&left) {
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
            RustAssertionSignal {
                kind: kind.to_string(),
                score,
                shallow: false,
                meaningful: false,
                reason: reason.to_string(),
                excerpt: compact_rust_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        } else if let Some(literal) = oversized_rust_literal(&left, &right, weights) {
            RustAssertionSignal {
                kind: "overspecified-literal".to_string(),
                score: weights.overspecified_literal_weight,
                shallow: true,
                meaningful: false,
                reason: format!("overspecified-literal:{literal}"),
                excerpt: compact_rust_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        } else {
            RustAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                meaningful: true,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_rust_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        };
        assertions.push(signal);
    }

    for captures in RUST_ASSERT_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let expr = normalize_rust_expr(captures.name("expr").map(|m| m.as_str()).unwrap_or(""));
        let trimmed = expr.trim();
        let signal = if trimmed == "true" || trimmed == "false" {
            RustAssertionSignal {
                kind: "constant-truth".to_string(),
                score: weights.constant_truth_weight,
                shallow: true,
                meaningful: false,
                reason: "constant-truth".to_string(),
                excerpt: compact_rust_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        } else if trimmed.contains(".is_some()") || trimmed.contains(".is_none()") {
            RustAssertionSignal {
                kind: "nullness-only".to_string(),
                score: weights.nullness_only_weight,
                shallow: true,
                meaningful: false,
                reason: "nullness-only".to_string(),
                excerpt: compact_rust_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        } else {
            RustAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                meaningful: true,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_rust_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        };
        assertions.push(signal);
    }

    for captures in RUST_MATCHES_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        assertions.push(RustAssertionSignal {
            kind: "meaningful-assertion".to_string(),
            score: 0,
            shallow: false,
            meaningful: true,
            reason: "meaningful-assertion".to_string(),
            excerpt: compact_rust_excerpt(whole.as_str()),
            start_byte: whole.start(),
        });
    }

    assertions
}

fn rust_meaningful_assertion_credit<'a>(
    assertions: impl Iterator<Item = &'a RustAssertionSignal>,
    weights: &TestAssertionWeights,
) -> i32 {
    let count = assertions.filter(|assertion| assertion.meaningful).count() as i32;
    let creditable = count.min(weights.meaningful_assertion_credit_cap.max(0));
    weights.meaningful_assertion_credit.max(0) * creditable
}

fn normalize_rust_expr(expr: &str) -> String {
    expr.trim()
        .trim_end_matches(',')
        .trim_matches(|ch| matches!(ch, '(' | ')' | ' '))
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_rust_literal(expr: &str) -> bool {
    let trimmed = expr.trim();
    (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || matches!(trimmed, "true" | "false" | "None")
        || trimmed.parse::<i64>().is_ok()
        || trimmed.parse::<f64>().is_ok()
}

fn compact_rust_excerpt(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn oversized_rust_literal(
    left: &str,
    right: &str,
    weights: &TestAssertionWeights,
) -> Option<String> {
    [left, right].into_iter().find_map(|expr| {
        let trimmed = expr.trim();
        let unquoted = trimmed
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))?;
        (unquoted.len() >= weights.large_literal_length_threshold.max(0) as usize)
            .then(|| trimmed.to_string())
    })
}
