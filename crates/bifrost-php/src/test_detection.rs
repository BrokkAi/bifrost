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

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
        .expect("PHP grammar is valid");
    let tree = parser.parse(source, None).expect("PHP source parses");
    let mut pending = vec![tree.root_node()];
    while let Some(node) = pending.pop() {
        if matches!(node.kind(), "function_definition" | "method_declaration")
            && crate::graph::syntax::declaration_doc_comment(node, source).is_some_and(|comment| {
                let arena = mago_allocator::LocalArena::new();
                let document = mago_phpdoc_syntax::PHPDocParser::parse(
                    &arena,
                    mago_database::file::FileId::zero(),
                    comment.as_bytes(),
                );
                !document.has_errors()
                    && document
                        .tags()
                        .any(|tag| tag.name.value.eq_ignore_ascii_case(b"test"))
            })
        {
            return true;
        }
        brokk_bifrost_core::analyzer::tree_walk::push_named_children_reversed(node, &mut pending);
    }
    false
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
        .is_some_and(|name| name.eq_ignore_ascii_case("TestCase"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon(
        "847cee536608: quicksilver round 9 on brokk-bifrost-php: testcase case and docblock lookalikes"
    )]
    fn test_detection_uses_declarations_and_attached_comments() {
        for (body, expected) in [
            (r"class Checks extends \PHPUnit\Framework\TestCase {}", true),
            (r"class Checks extends \PHPUnit\Framework\testcase {}", true),
            (r"class Checks extends \PHPUnit\Framework\TESTCASE {}", true),
            ("class CheckoutTest {}", true),
            ("class CheckoutTestCase {}", true),
            ("class Contest {}", false),
            (
                "class Checks { /** @test*/ public function works() {} }",
                true,
            ),
            (
                "class Checks { /** prose about @test */ public function works() {} }",
                false,
            ),
            (
                "class Checks { /** @test */ public function works() {} }",
                true,
            ),
            (
                "$x = <<<'RAW'\n/** @test */ public function fake() {}\nRAW;",
                false,
            ),
            ("$x = '/** @test */ public function fake() {}';", false),
            ("/** @test */ $x = 1; function fake() {}", false),
        ] {
            let source = format!("<?php {body}");
            let mut parser = tree_sitter::Parser::new();
            parser
                .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
                .unwrap();
            let tree = parser.parse(&source, None).unwrap();
            assert!(!tree.root_node().has_error());
            let file = ProjectFile::new(std::env::temp_dir(), "detection.php");
            let parsed = crate::declarations::parse_php_file(&file, &source, &tree);
            assert_eq!(php_contains_tests(&source, &parsed), expected, "{body}");
        }
    }
}
