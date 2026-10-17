use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::common::collapse_whitespace;
use brokk_bifrost_core::analyzer::model::{TestAssertionSmell, TestAssertionWeights};
use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;
use brokk_bifrost_core::analyzer::test_assertions::{
    CommonTestAssertionKind, TestAssertionSignal, append_test_assertion_findings,
    classify_common_test_assertion, is_common_assertion_literal, normalize_assertion_expression,
};
use brokk_bifrost_core::hash::HashSet;
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

pub fn detect_php_test_assertion_smells(
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
    let symbol = format!("{}::{}", file, name);
    let assertions: Vec<_> = collect_php_assertions(body, weights)
        .into_iter()
        .map(|assertion| TestAssertionSignal {
            kind: assertion.kind,
            score: assertion.score,
            shallow: assertion.shallow,
            meaningful: false,
            reasons: vec![assertion.reason],
            excerpt: assertion.excerpt,
            start_byte: start_byte + assertion.start_byte,
        })
        .collect();
    append_test_assertion_findings(
        file,
        symbol,
        collapse_whitespace(body),
        start_byte,
        &assertions,
        weights,
        out,
    );
}

fn collect_php_assertions(body: &str, weights: &TestAssertionWeights) -> Vec<PhpAssertionSignal> {
    let mut assertions = Vec::new();

    for captures in PHP_ASSERT_EQUALITY_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let left = normalize_php_expr(captures.name("left").map(|m| m.as_str()).unwrap_or(""));
        let right = normalize_php_expr(captures.name("right").map(|m| m.as_str()).unwrap_or(""));
        let classification = if left == right {
            classify_common_test_assertion(
                if is_php_literal(&left) {
                    CommonTestAssertionKind::ConstantEquality
                } else {
                    CommonTestAssertionKind::SelfComparison
                },
                weights,
            )
        } else {
            classify_common_test_assertion(CommonTestAssertionKind::Meaningful, weights)
        };
        assertions.push(PhpAssertionSignal {
            kind: classification.kind.to_string(),
            score: classification.score,
            shallow: classification.shallow,
            reason: classification.kind.to_string(),
            excerpt: collapse_whitespace(whole.as_str()),
            start_byte: whole.start(),
        });
    }

    for captures in PHP_ASSERT_TRUTH_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let matcher = captures.name("matcher").map(|m| m.as_str()).unwrap_or("");
        let arg = normalize_php_expr(captures.name("arg").map(|m| m.as_str()).unwrap_or(""));
        let kind = match matcher {
            "True" if arg == "true" => CommonTestAssertionKind::ConstantTruth,
            "False" if arg == "false" => CommonTestAssertionKind::ConstantTruth,
            "Null" | "NotNull" => CommonTestAssertionKind::NullnessOnly,
            _ => CommonTestAssertionKind::Meaningful,
        };
        let classification = classify_common_test_assertion(kind, weights);
        assertions.push(PhpAssertionSignal {
            kind: classification.kind.to_string(),
            score: classification.score,
            shallow: classification.shallow,
            reason: classification.kind.to_string(),
            excerpt: collapse_whitespace(whole.as_str()),
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
                excerpt: collapse_whitespace(whole.as_str()),
                start_byte: whole.start(),
            });
        }
    }

    assertions
}

fn normalize_php_expr(expr: &str) -> String {
    normalize_assertion_expression(expr.trim().trim_end_matches(';'))
}

fn is_php_literal(expr: &str) -> bool {
    let trimmed = expr.trim();
    is_common_assertion_literal(trimmed)
        || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
        || matches!(trimmed, "true" | "false" | "null")
}

pub fn php_contains_tests(source: &str, parsed: &ParsedFile) -> bool {
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

fn php_test_classes(parsed: &ParsedFile) -> HashSet<String> {
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
