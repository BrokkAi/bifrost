//! C++ test-file recognition and test-assertion smell detection.
//!
//! `analyzer/cpp/tests.rs` in `brokk-bifrost-analysis` keeps the empty
//! `impl TestDetectionProvider for CppAnalyzer` and the analyzer-bound fixture
//! suites; everything here is a pure function of the file's source text and
//! its syntax tree. The analyzer passes its prepared tree, so a report does not
//! reparse a file that another request already parsed.
//!
//! C++ recognizes the four framework macro families: `TEST`/`TEST_F`/`TEST_P`/`TYPED_TEST` (gtest),
//! `TEST_CASE`/`SCENARIO` (Catch2), `BOOST_AUTO_TEST_CASE` and `TEST_METHOD`
//! (MSTest). Assertion smells use their parsed function bodies.

use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::common::collapse_whitespace;
use brokk_bifrost_core::analyzer::model::{TestAssertionSmell, TestAssertionWeights};
use brokk_bifrost_core::analyzer::test_assertions::{
    TestAssertionSignal, append_test_assertion_findings, is_common_assertion_literal,
    normalize_assertion_expression,
};
use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, walk_tree_preorder};
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

/// `tree` must be the C++ syntax tree of exactly `source`.
pub fn detect_cpp_test_assertion_smells(
    file: &ProjectFile,
    source: &str,
    tree: &tree_sitter::Tree,
    weights: &TestAssertionWeights,
) -> Vec<TestAssertionSmell> {
    let mut findings = Vec::new();
    walk_tree_preorder(tree.root_node(), true, |node| {
        if let Some(body) = cpp_test_body(node, source)
            && body.kind() == "compound_statement"
            && let Some(open) = body.child(0)
            && let Some(close) = body.child(body.child_count() - 1)
            && open.kind() == "{"
            && close.kind() == "}"
            && !close.is_missing()
        {
            let start = open.end_byte();
            let end = close.start_byte();
            analyze_cpp_test_case(file, &source[start..end], start, weights, &mut findings);
        }
        WalkControl::Continue
    });
    findings
}

/// Identifier arguments parse as function declarators. String arguments (as
/// used by Catch2) parse as a call without a semicolon followed by a block.
/// Both routes select the complete compound statement from the syntax tree.
fn cpp_test_body<'tree>(
    node: tree_sitter::Node<'tree>,
    source: &str,
) -> Option<tree_sitter::Node<'tree>> {
    let (declarator, body) = match node.kind() {
        "function_definition" => (
            node.child_by_field_name("declarator")?,
            node.child_by_field_name("body")?,
        ),
        "compound_statement" => {
            let mut previous = node.prev_named_sibling()?;
            while previous.is_extra() {
                previous = previous.prev_named_sibling()?;
            }
            if previous.kind() != "expression_statement" {
                return None;
            }
            let terminator = previous.child(previous.child_count() - 1)?;
            if terminator.kind() != ";" || !terminator.is_missing() {
                return None;
            }
            let call = previous.named_child(0)?;
            if call.kind() != "call_expression" {
                return None;
            }
            (call.child_by_field_name("function")?, node)
        }
        _ => return None,
    };
    let name = crate::structural::declarator_name_node(declarator)?;
    matches!(
        name.utf8_text(source.as_bytes()).expect("source node"),
        "TEST"
            | "TEST_F"
            | "TEST_P"
            | "TYPED_TEST"
            | "TEST_CASE"
            | "SCENARIO"
            | "BOOST_AUTO_TEST_CASE"
            | "TEST_METHOD"
    )
    .then_some(body)
}

fn analyze_cpp_test_case(
    file: &ProjectFile,
    body: &str,
    start_byte: usize,
    weights: &TestAssertionWeights,
    out: &mut Vec<TestAssertionSmell>,
) {
    let symbol = file.to_string();
    let assertions: Vec<_> = collect_cpp_assertions(body, weights)
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
            excerpt: collapse_whitespace(whole.as_str()),
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
                excerpt: collapse_whitespace(whole.as_str()),
                start_byte: whole.start(),
            }
        } else if matcher == "NE" && (is_cpp_null_literal(&left) || is_cpp_null_literal(&right)) {
            CppAssertionSignal {
                kind: "nullness-only".to_string(),
                score: weights.nullness_only_weight,
                shallow: true,
                reason: "nullness-only".to_string(),
                excerpt: collapse_whitespace(whole.as_str()),
                start_byte: whole.start(),
            }
        } else {
            CppAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                reason: "meaningful-assertion".to_string(),
                excerpt: collapse_whitespace(whole.as_str()),
                start_byte: whole.start(),
            }
        };
        assertions.push(signal);
    }

    assertions
}

pub fn cpp_contains_tests(source: &str) -> bool {
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
    normalize_assertion_expression(expr.trim().trim_end_matches(';'))
}

fn is_cpp_literal(expr: &str) -> bool {
    let trimmed = expr.trim();
    is_common_assertion_literal(trimmed) || matches!(trimmed, "true" | "false" | "nullptr" | "NULL")
}

fn is_cpp_null_literal(expr: &str) -> bool {
    matches!(expr.trim(), "nullptr" | "NULL")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(
        file: &ProjectFile,
        source: &str,
        weights: &TestAssertionWeights,
    ) -> Vec<TestAssertionSmell> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("C++ grammar");
        let tree = parser.parse(source, None).expect("C++ parse");
        detect_cpp_test_assertion_smells(file, source, &tree, weights)
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "e3c20990a105: quicksilver round 4 on brokk-bifrost-cpp: string and comment braces truncated test bodies"
    )]
    fn braces_in_literals_and_comments_do_not_hide_assertions() {
        let file = ProjectFile::new(std::env::current_dir().unwrap(), "braces.cpp");
        for framework in [
            "TEST(Suite, Case)",
            "TEST_F(Suite, Case)",
            "TEST_P(Suite, Case)",
            "TYPED_TEST(Suite, Case)",
            r#"TEST_CASE("case")"#,
            r#"SCENARIO("case")"#,
            "BOOST_AUTO_TEST_CASE(case)",
            "TEST_METHOD(case)",
        ] {
            for prefix in [r#"const char *s = "}";"#, "// }\n", "/* } */"] {
                let source = format!("{framework} {{ {prefix} EXPECT_EQ(actual, expected); }}");
                assert!(
                    detect(&file, &source, &TestAssertionWeights::defaults()).is_empty(),
                    "{source}"
                );
                // Prove recognition ran, rather than accepting an empty result
                // from an unsupported macro shape.
                let missing = format!("{framework} {{ {prefix} do_work(); }}");
                assert!(
                    !detect(&file, &missing, &TestAssertionWeights::defaults()).is_empty(),
                    "{missing}"
                );
            }
        }
    }

    #[test]
    fn nonpositive_shallow_only_score_emits_no_finding() {
        let file = ProjectFile::new(
            std::env::current_dir().expect("test working directory"),
            "shallow-only.cpp",
        );
        let mut weights = TestAssertionWeights::defaults();
        weights.constant_truth_weight = 0;
        weights.shallow_assertion_only_weight = 0;

        let findings = detect(&file, "TEST(Suite, case) { EXPECT_TRUE(true); }", &weights);

        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }
}
