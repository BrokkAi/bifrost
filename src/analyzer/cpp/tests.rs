use super::*;
use regex::Regex;
use std::sync::LazyLock;

static CPP_GTEST_TEST_START_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?s)\b(?:TEST|TEST_F|TEST_P|TYPED_TEST)\b\s*(?:/\*.*?\*/\s*)?\([^)]*\)\s*\{"#)
        .expect("valid regex")
});
static CPP_CATCH2_TEST_START_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?s)\b(?:TEST_CASE|SCENARIO)\b\s*\([^)]*\)\s*\{"#).expect("valid regex")
});
static CPP_BOOST_TEST_START_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?s)\bBOOST_AUTO_TEST_CASE\b\s*\([^)]*\)\s*\{"#).expect("valid regex")
});
static CPP_MSTEST_METHOD_START_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?s)\bTEST_METHOD\b\s*\([^)]*\)\s*\{"#).expect("valid regex"));
static CPP_ASSERT_TRUTH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:EXPECT|ASSERT)_(?P<matcher>TRUE|FALSE)\s*\((?P<arg>[^)\n]+)\)"#)
        .expect("valid regex")
});
static CPP_ASSERT_EQUALITY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?:EXPECT|ASSERT)_(?P<matcher>EQ|NE)\s*\((?P<left>[^,\n]+?)\s*,\s*(?P<right>[^)\n]+)\)"#,
    )
    .expect("valid regex")
});

#[derive(Clone)]
struct CppAssertionSignal {
    kind: String,
    score: i32,
    shallow: bool,
    reason: String,
    excerpt: String,
    start_byte: usize,
}

pub(super) fn detect_cpp_test_assertion_smells(
    file: &ProjectFile,
    source: &str,
    weights: &TestAssertionWeights,
) -> Vec<TestAssertionSmell> {
    let mut findings = Vec::new();
    for regex in [
        &*CPP_GTEST_TEST_START_RE,
        &*CPP_CATCH2_TEST_START_RE,
        &*CPP_BOOST_TEST_START_RE,
        &*CPP_MSTEST_METHOD_START_RE,
    ] {
        for whole in regex.find_iter(source) {
            let Some((body, body_start)) = extract_braced_body(source, whole.end() - 1) else {
                continue;
            };
            analyze_cpp_test_case(file, body, body_start, weights, &mut findings);
        }
    }
    findings
}

fn analyze_cpp_test_case(
    file: &ProjectFile,
    body: &str,
    start_byte: usize,
    weights: &TestAssertionWeights,
    out: &mut Vec<TestAssertionSmell>,
) {
    let assertions = collect_cpp_assertions(body, weights);
    let assertion_count = assertions.len() as i32;
    let symbol = file.to_string();

    if assertion_count == 0 {
        out.push(TestAssertionSmell {
            file: file.clone(),
            enclosing_fq_name: symbol,
            assertion_kind: "no-assertions".to_string(),
            score: weights.no_assertion_weight,
            assertion_count: 0,
            reasons: vec!["no-assertions".to_string()],
            excerpt: compact_cpp_excerpt(body),
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
            excerpt: compact_cpp_excerpt(body),
            start_byte,
        });
    }
}

fn collect_cpp_assertions(body: &str, weights: &TestAssertionWeights) -> Vec<CppAssertionSignal> {
    let mut assertions = Vec::new();

    for captures in CPP_ASSERT_TRUTH_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let matcher = captures.name("matcher").map(|m| m.as_str()).unwrap_or("");
        let arg = normalize_cpp_expr(captures.name("arg").map(|m| m.as_str()).unwrap_or(""));
        let (kind, score, shallow) = match matcher {
            "TRUE" if arg == "true" => ("constant-truth", weights.constant_truth_weight, true),
            "FALSE" if arg == "false" => ("constant-truth", weights.constant_truth_weight, true),
            _ => ("meaningful-assertion", 0, false),
        };
        assertions.push(CppAssertionSignal {
            kind: kind.to_string(),
            score,
            shallow,
            reason: kind.to_string(),
            excerpt: compact_cpp_excerpt(whole.as_str()),
            start_byte: whole.start(),
        });
    }

    for captures in CPP_ASSERT_EQUALITY_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let matcher = captures.name("matcher").map(|m| m.as_str()).unwrap_or("");
        let left = normalize_cpp_expr(captures.name("left").map(|m| m.as_str()).unwrap_or(""));
        let right = normalize_cpp_expr(captures.name("right").map(|m| m.as_str()).unwrap_or(""));
        let signal = if matcher == "EQ" && left == right {
            let (kind, reason, score) = if is_cpp_literal(&left) {
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
            CppAssertionSignal {
                kind: kind.to_string(),
                score,
                shallow: false,
                reason: reason.to_string(),
                excerpt: compact_cpp_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        } else if matcher == "NE" && (is_cpp_null_literal(&left) || is_cpp_null_literal(&right)) {
            CppAssertionSignal {
                kind: "nullness-only".to_string(),
                score: weights.nullness_only_weight,
                shallow: true,
                reason: "nullness-only".to_string(),
                excerpt: compact_cpp_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        } else {
            CppAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_cpp_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        };
        assertions.push(signal);
    }

    assertions
}

pub(super) fn cpp_contains_tests(source: &str) -> bool {
    [
        &*CPP_GTEST_TEST_START_RE,
        &*CPP_CATCH2_TEST_START_RE,
        &*CPP_BOOST_TEST_START_RE,
        &*CPP_MSTEST_METHOD_START_RE,
    ]
    .iter()
    .any(|regex| regex.is_match(source))
}

fn normalize_cpp_expr(expr: &str) -> String {
    expr.trim()
        .trim_end_matches(';')
        .trim_matches(|ch| matches!(ch, '(' | ')' | ' '))
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_cpp_literal(expr: &str) -> bool {
    let trimmed = expr.trim();
    (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || matches!(trimmed, "true" | "false" | "nullptr" | "NULL")
        || trimmed.parse::<i64>().is_ok()
        || trimmed.parse::<f64>().is_ok()
}

fn is_cpp_null_literal(expr: &str) -> bool {
    matches!(expr.trim(), "nullptr" | "NULL")
}

fn compact_cpp_excerpt(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn extract_braced_body(source: &str, open_brace_index: usize) -> Option<(&str, usize)> {
    let mut depth = 0usize;
    let mut body_start = None;
    for (offset, ch) in source[open_brace_index..].char_indices() {
        let absolute = open_brace_index + offset;
        match ch {
            '{' => {
                depth += 1;
                if depth == 1 {
                    body_start = Some(absolute + ch.len_utf8());
                }
            }
            '}' => {
                if depth == 1 {
                    let start = body_start?;
                    return Some((&source[start..absolute], start));
                }
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    None
}
