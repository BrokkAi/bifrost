use crate::analyzer::{ProjectFile, TestAssertionSmell, TestAssertionWeights};
use regex::Regex;
use std::sync::LazyLock;

static SCALA_TEST_BLOCK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?s)"(?P<name>[^"]+)"\s+should\s+"[^"]+"\s+in\s*\{(?P<body>.*?)\n\}"#)
        .expect("valid regex")
});
static SCALA_FUNSUITE_TEST_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?s)test\s*\("(?P<name>[^"]+)"\)\s*\{(?P<body>.*?)\n\s*\}"#).expect("valid regex")
});
static SCALA_ASSERT_COMPARISON_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"assert(?:Result)?\s*\((?P<left>[^=\n\)]+?)\s*(?P<op>==|!=)\s*(?P<right>[^,\n\)]+)\)"#,
    )
    .expect("valid regex")
});
static SCALA_ASSERT_SIMPLE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"assert(?:Result)?\s*\((?P<expr>[^,\n\)]+)\)"#).expect("valid regex")
});
static SCALA_JUNIT_EQUALITY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"assert(?:Equals|Same)\s*\((?P<left>[^,\n]+?)\s*,\s*(?P<right>[^,\n\)]+)"#)
        .expect("valid regex")
});
static SCALA_JUNIT_NULLNESS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"assert(?:NotNull|Null)\s*\((?P<arg>[^,\n\)]+)"#).expect("valid regex")
});
static SCALA_SHOULDBE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?P<left>[A-Za-z0-9_\."]+)\s+should(?:Be|Equal)\s+(?P<right>[A-Za-z0-9_\."]+)"#)
        .expect("valid regex")
});
static SCALA_THROWS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"assertThrows\[|thrownBy\s*\{|intercept\["#).expect("valid regex")
});
static SCALA_VERIFY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"verify\s*\("#).expect("valid regex"));

#[derive(Clone)]
struct ScalaAssertionSignal {
    kind: String,
    score: i32,
    shallow: bool,
    reason: String,
    excerpt: String,
    start_byte: usize,
}

pub(super) fn detect_scala_test_assertion_smells(
    file: &ProjectFile,
    source: &str,
    weights: &TestAssertionWeights,
) -> Vec<TestAssertionSmell> {
    let mut findings = Vec::new();
    for captures in SCALA_TEST_BLOCK_RE.captures_iter(source) {
        let Some(name_match) = captures.name("name") else {
            continue;
        };
        let Some(body_match) = captures.name("body") else {
            continue;
        };
        analyze_scala_test_case(
            file,
            name_match.as_str(),
            body_match.as_str(),
            body_match.start(),
            weights,
            &mut findings,
        );
    }
    for captures in SCALA_FUNSUITE_TEST_RE.captures_iter(source) {
        let Some(name_match) = captures.name("name") else {
            continue;
        };
        let Some(body_match) = captures.name("body") else {
            continue;
        };
        analyze_scala_test_case(
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

fn analyze_scala_test_case(
    file: &ProjectFile,
    name: &str,
    body: &str,
    start_byte: usize,
    weights: &TestAssertionWeights,
    out: &mut Vec<TestAssertionSmell>,
) {
    let assertions = collect_scala_assertions(body, weights);
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
            excerpt: compact_scala_excerpt(body),
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
        out.push(TestAssertionSmell {
            file: file.clone(),
            enclosing_fq_name: symbol,
            assertion_kind: "shallow-assertions-only".to_string(),
            score: weights.shallow_assertion_only_weight,
            assertion_count,
            reasons: vec!["shallow-assertions-only".to_string()],
            excerpt: compact_scala_excerpt(body),
            start_byte,
        });
    }
}

fn collect_scala_assertions(
    body: &str,
    weights: &TestAssertionWeights,
) -> Vec<ScalaAssertionSignal> {
    let mut assertions = Vec::new();

    for captures in SCALA_SHOULDBE_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let left = normalize_scala_expr(captures.name("left").map(|m| m.as_str()).unwrap_or(""));
        let right = normalize_scala_expr(captures.name("right").map(|m| m.as_str()).unwrap_or(""));
        let signal = if left == right {
            let (kind, reason, score) = if is_scala_literal(&left) {
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
            ScalaAssertionSignal {
                kind: kind.to_string(),
                score,
                shallow: false,
                reason: reason.to_string(),
                excerpt: compact_scala_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        } else {
            ScalaAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_scala_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        };
        assertions.push(signal);
    }

    for captures in SCALA_JUNIT_EQUALITY_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let left = normalize_scala_expr(captures.name("left").map(|m| m.as_str()).unwrap_or(""));
        let right = normalize_scala_expr(captures.name("right").map(|m| m.as_str()).unwrap_or(""));
        let signal = if left == right {
            let (kind, reason, score) = if is_scala_literal(&left) {
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
            ScalaAssertionSignal {
                kind: kind.to_string(),
                score,
                shallow: false,
                reason: reason.to_string(),
                excerpt: compact_scala_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        } else if let Some(literal) = oversized_scala_literal(&left, &right, weights) {
            ScalaAssertionSignal {
                kind: "overspecified-literal".to_string(),
                score: weights.overspecified_literal_weight,
                shallow: false,
                reason: format!("overspecified-literal:{literal}"),
                excerpt: compact_scala_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        } else {
            ScalaAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_scala_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        };
        assertions.push(signal);
    }

    for captures in SCALA_JUNIT_NULLNESS_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        assertions.push(ScalaAssertionSignal {
            kind: "nullness-only".to_string(),
            score: weights.nullness_only_weight,
            shallow: true,
            reason: "nullness-only".to_string(),
            excerpt: compact_scala_excerpt(whole.as_str()),
            start_byte: whole.start(),
        });
    }

    for captures in SCALA_ASSERT_COMPARISON_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let left = normalize_scala_expr(captures.name("left").map(|m| m.as_str()).unwrap_or(""));
        let right = normalize_scala_expr(captures.name("right").map(|m| m.as_str()).unwrap_or(""));
        let operator = captures.name("op").map(|m| m.as_str()).unwrap_or("==");
        let signal = if operator == "==" && left == right {
            let (kind, reason, score) = if is_scala_literal(&left) {
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
            ScalaAssertionSignal {
                kind: kind.to_string(),
                score,
                shallow: false,
                reason: reason.to_string(),
                excerpt: compact_scala_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        } else if operator == "==" {
            if let Some(literal) = oversized_scala_literal(&left, &right, weights) {
                ScalaAssertionSignal {
                    kind: "overspecified-literal".to_string(),
                    score: weights.overspecified_literal_weight,
                    shallow: false,
                    reason: format!("overspecified-literal:{literal}"),
                    excerpt: compact_scala_excerpt(whole.as_str()),
                    start_byte: whole.start(),
                }
            } else if is_scala_null_literal(&left) || is_scala_null_literal(&right) {
                ScalaAssertionSignal {
                    kind: "nullness-only".to_string(),
                    score: weights.nullness_only_weight,
                    shallow: true,
                    reason: "nullness-only".to_string(),
                    excerpt: compact_scala_excerpt(whole.as_str()),
                    start_byte: whole.start(),
                }
            } else {
                ScalaAssertionSignal {
                    kind: "meaningful-assertion".to_string(),
                    score: 0,
                    shallow: false,
                    reason: "meaningful-assertion".to_string(),
                    excerpt: compact_scala_excerpt(whole.as_str()),
                    start_byte: whole.start(),
                }
            }
        } else {
            ScalaAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_scala_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        };
        assertions.push(signal);
    }

    for captures in SCALA_ASSERT_SIMPLE_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let expr = normalize_scala_expr(captures.name("expr").map(|m| m.as_str()).unwrap_or(""));
        if expr.contains("==") || expr.contains("!=") {
            continue;
        }
        let signal = if expr == "true" {
            ScalaAssertionSignal {
                kind: "constant-truth".to_string(),
                score: weights.constant_truth_weight,
                shallow: true,
                reason: "constant-truth".to_string(),
                excerpt: compact_scala_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        } else {
            ScalaAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_scala_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        };
        assertions.push(signal);
    }

    for regex in [&*SCALA_THROWS_RE, &*SCALA_VERIFY_RE] {
        for captures in regex.captures_iter(body) {
            let whole = captures.get(0).expect("whole match");
            assertions.push(ScalaAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_scala_excerpt(whole.as_str()),
                start_byte: whole.start(),
            });
        }
    }

    assertions
}

fn normalize_scala_expr(expr: &str) -> String {
    expr.trim()
        .trim_matches(|ch| matches!(ch, '(' | ')' | ' '))
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_scala_literal(expr: &str) -> bool {
    let trimmed = expr.trim();
    (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || matches!(trimmed, "true" | "false" | "null")
        || trimmed.parse::<i64>().is_ok()
        || trimmed.parse::<f64>().is_ok()
}

fn is_scala_null_literal(expr: &str) -> bool {
    expr.trim() == "null"
}

fn compact_scala_excerpt(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn oversized_scala_literal(
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

pub(super) fn scala_contains_tests(source: &str) -> bool {
    source.contains("@Test")
        || source.contains("@org.junit.Test")
        || source.contains("test(\"")
        || source.contains("test (\"")
        || (source.contains(" should ") && source.contains(" in {"))
}
