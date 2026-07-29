use crate::analyzer::{ProjectFile, TestAssertionSmell, TestAssertionWeights};
use crate::hash::HashSet;
use regex::Regex;
use std::sync::LazyLock;

static PHP_TEST_METHOD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)function\s+(?P<name>test[A-Za-z0-9_]+)\s*\([^)]*\)\s*:\s*void\s*\{(?P<body>.*?)\n\s*\}"#,
    )
    .expect("valid regex")
});
static PHP_ASSERT_EQUALITY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\$this->assert(?:Same|Equals)\s*\((?P<left>[^,\n]+?)\s*,\s*(?P<right>[^,\n\)]+)"#)
        .expect("valid regex")
});
static PHP_ASSERT_TRUTH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\$this->assert(?P<matcher>True|False|Null|NotNull)\s*\((?P<arg>[^,\n\)]+)"#)
        .expect("valid regex")
});
static PHP_THROWS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\$this->expectException\s*\("#).expect("valid regex"));
static PHP_VERIFY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\$[A-Za-z_][A-Za-z0-9_]*->expects\s*\("#).expect("valid regex"));

#[derive(Clone)]
struct PhpAssertionSignal {
    kind: String,
    score: i32,
    shallow: bool,
    reason: String,
    excerpt: String,
    start_byte: usize,
}

pub(super) fn detect_php_test_assertion_smells(
    file: &ProjectFile,
    source: &str,
    weights: &TestAssertionWeights,
) -> Vec<TestAssertionSmell> {
    let mut findings = Vec::new();
    for captures in PHP_TEST_METHOD_RE.captures_iter(source) {
        let Some(name_match) = captures.name("name") else {
            continue;
        };
        let Some(body_match) = captures.name("body") else {
            continue;
        };
        analyze_php_test_case(
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

fn analyze_php_test_case(
    file: &ProjectFile,
    name: &str,
    body: &str,
    start_byte: usize,
    weights: &TestAssertionWeights,
    out: &mut Vec<TestAssertionSmell>,
) {
    let assertions = collect_php_assertions(body, weights);
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
            excerpt: compact_php_excerpt(body),
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
            excerpt: compact_php_excerpt(body),
            start_byte,
        });
    }
}

fn collect_php_assertions(body: &str, weights: &TestAssertionWeights) -> Vec<PhpAssertionSignal> {
    let mut assertions = Vec::new();

    for captures in PHP_ASSERT_EQUALITY_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let left = normalize_php_expr(captures.name("left").map(|m| m.as_str()).unwrap_or(""));
        let right = normalize_php_expr(captures.name("right").map(|m| m.as_str()).unwrap_or(""));
        let signal = if left == right {
            let (kind, reason, score) = if is_php_literal(&left) {
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
            PhpAssertionSignal {
                kind: kind.to_string(),
                score,
                shallow: false,
                reason: reason.to_string(),
                excerpt: compact_php_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        } else {
            PhpAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_php_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        };
        assertions.push(signal);
    }

    for captures in PHP_ASSERT_TRUTH_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let matcher = captures.name("matcher").map(|m| m.as_str()).unwrap_or("");
        let arg = normalize_php_expr(captures.name("arg").map(|m| m.as_str()).unwrap_or(""));
        let (kind, score, shallow) = match matcher {
            "True" if arg == "true" => ("constant-truth", weights.constant_truth_weight, true),
            "False" if arg == "false" => ("constant-truth", weights.constant_truth_weight, true),
            "Null" | "NotNull" => ("nullness-only", weights.nullness_only_weight, true),
            _ => ("meaningful-assertion", 0, false),
        };
        assertions.push(PhpAssertionSignal {
            kind: kind.to_string(),
            score,
            shallow,
            reason: kind.to_string(),
            excerpt: compact_php_excerpt(whole.as_str()),
            start_byte: whole.start(),
        });
    }

    for regex in [&*PHP_THROWS_RE, &*PHP_VERIFY_RE] {
        for captures in regex.captures_iter(body) {
            let whole = captures.get(0).expect("whole match");
            assertions.push(PhpAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_php_excerpt(whole.as_str()),
                start_byte: whole.start(),
            });
        }
    }

    assertions
}

fn normalize_php_expr(expr: &str) -> String {
    expr.trim()
        .trim_end_matches(';')
        .trim_matches(|ch| matches!(ch, '(' | ')' | ' '))
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_php_literal(expr: &str) -> bool {
    let trimmed = expr.trim();
    (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
        || matches!(trimmed, "true" | "false" | "null")
        || trimmed.parse::<i64>().is_ok()
        || trimmed.parse::<f64>().is_ok()
}

fn compact_php_excerpt(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(super) fn php_contains_tests(
    source: &str,
    parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> bool {
    let test_classes = php_test_classes(parsed);
    if !test_classes.is_empty() {
        return true;
    }

    if parsed.declarations().iter().any(|code_unit| {
        code_unit.is_function()
            && code_unit
                .identifier()
                .to_ascii_lowercase()
                .starts_with("test")
            && php_function_parent_class(code_unit.short_name())
                .is_some_and(|class_name| test_classes.contains(class_name))
    }) {
        return true;
    }

    static DOCBLOCK_TEST_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(
            r"(?is)/\*\*.*?@test.*?\*/\s*(?:(?:public|protected|private|static|final|abstract|readonly)\s+)*function\b",
        )
        .unwrap()
    });
    DOCBLOCK_TEST_RE.is_match(source)
}

fn php_test_classes(parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile) -> HashSet<String> {
    let mut classes = HashSet::default();
    for code_unit in parsed
        .declarations()
        .iter()
        .filter(|code_unit| code_unit.is_class())
    {
        let name = code_unit.identifier();
        if php_test_class_name(name)
            || parsed
                .raw_supertypes
                .get(code_unit)
                .is_some_and(|parents| parents.iter().any(|parent| php_extends_testcase(parent)))
        {
            classes.insert(code_unit.short_name().to_string());
        }
    }
    classes
}

fn php_test_class_name(name: &str) -> bool {
    name.ends_with("Test") || name.ends_with("TestCase")
}

fn php_extends_testcase(parent: &str) -> bool {
    parent
        .rsplit(['\\', '.'])
        .next()
        .is_some_and(|name| name == "TestCase")
}

fn php_function_parent_class(short_name: &str) -> Option<&str> {
    short_name.rsplit_once('.').map(|(parent, _)| parent)
}
