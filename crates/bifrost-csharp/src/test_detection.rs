use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::common::{collapse_whitespace, node_source_text as node_text};
use brokk_bifrost_core::analyzer::model::{TestAssertionSmell, TestAssertionWeights};
use brokk_bifrost_core::analyzer::test_assertions::{
    CommonTestAssertionKind, TestAssertionSignal, append_test_assertion_findings,
    classify_common_test_assertion, is_common_assertion_literal, normalize_assertion_expression,
};
use regex::Regex;
use std::sync::LazyLock;
use tree_sitter::Node;

static CSHARP_TEST_METHOD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)(?:\[[^\]]*(?:Fact|Theory|Test|TestMethod)[^\]]*\]\s*)+[\w<>\[\],\s]+\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*\{(?P<body>.*?)\n\}"#,
    )
    .expect("valid regex")
});
static CSHARP_ASSERT_EQUALITY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"Assert\.(?:Equal|Same)\s*\((?P<left>[^,\n]+?)\s*,\s*(?P<right>[^,\n\)]+)"#)
        .expect("valid regex")
});
static CSHARP_ASSERT_TRUTH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"Assert\.(?P<matcher>True|False|Null|NotNull)\s*\((?P<arg>[^,\n\)]+)"#)
        .expect("valid regex")
});
static CSHARP_THROWS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"Assert\.Throws(?:Async)?<|Assert\.Throws(?:Async)?\s*\("#).expect("valid regex")
});
static CSHARP_VERIFY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\.\s*Verify\s*\("#).expect("valid regex"));

#[derive(Clone)]
struct CSharpAssertionSignal {
    kind: String,
    score: i32,
    shallow: bool,
    meaningful: bool,
    reason: String,
    excerpt: String,
    start_byte: usize,
}

pub fn detect_csharp_test_assertion_smells(
    file: &ProjectFile,
    source: &str,
    weights: &TestAssertionWeights,
) -> Vec<TestAssertionSmell> {
    let mut findings = Vec::new();
    for captures in CSHARP_TEST_METHOD_RE.captures_iter(source) {
        let Some(name_match) = captures.name("name") else {
            continue;
        };
        let Some(body_match) = captures.name("body") else {
            continue;
        };
        analyze_csharp_test_case(
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

fn analyze_csharp_test_case(
    file: &ProjectFile,
    name: &str,
    body: &str,
    start_byte: usize,
    weights: &TestAssertionWeights,
    out: &mut Vec<TestAssertionSmell>,
) {
    let symbol = format!("{}::{}", file, name);
    let assertions: Vec<_> = collect_csharp_assertions(body, weights)
        .into_iter()
        .map(|assertion| TestAssertionSignal {
            kind: assertion.kind,
            score: assertion.score,
            shallow: assertion.shallow,
            meaningful: assertion.meaningful,
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

fn collect_csharp_assertions(
    body: &str,
    weights: &TestAssertionWeights,
) -> Vec<CSharpAssertionSignal> {
    let mut assertions = Vec::new();

    for captures in CSHARP_ASSERT_EQUALITY_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let left = normalize_csharp_expr(captures.name("left").map(|m| m.as_str()).unwrap_or(""));
        let right = normalize_csharp_expr(captures.name("right").map(|m| m.as_str()).unwrap_or(""));
        let classification = if left == right {
            classify_common_test_assertion(
                if is_csharp_literal(&left) {
                    CommonTestAssertionKind::ConstantEquality
                } else {
                    CommonTestAssertionKind::SelfComparison
                },
                weights,
            )
        } else {
            classify_common_test_assertion(CommonTestAssertionKind::Meaningful, weights)
        };
        assertions.push(CSharpAssertionSignal {
            kind: classification.kind.to_string(),
            score: classification.score,
            shallow: classification.shallow,
            meaningful: classification.kind == "meaningful-assertion",
            reason: classification.kind.to_string(),
            excerpt: collapse_whitespace(whole.as_str()),
            start_byte: whole.start(),
        });
    }

    for captures in CSHARP_ASSERT_TRUTH_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let matcher = captures.name("matcher").map(|m| m.as_str()).unwrap_or("");
        let arg = normalize_csharp_expr(captures.name("arg").map(|m| m.as_str()).unwrap_or(""));
        let kind = match matcher {
            "True" if arg == "true" => CommonTestAssertionKind::ConstantTruth,
            "False" if arg == "false" => CommonTestAssertionKind::ConstantTruth,
            "Null" | "NotNull" => CommonTestAssertionKind::NullnessOnly,
            _ => CommonTestAssertionKind::Meaningful,
        };
        let classification = classify_common_test_assertion(kind, weights);
        assertions.push(CSharpAssertionSignal {
            kind: classification.kind.to_string(),
            score: classification.score,
            shallow: classification.shallow,
            meaningful: classification.score == 0,
            reason: classification.kind.to_string(),
            excerpt: collapse_whitespace(whole.as_str()),
            start_byte: whole.start(),
        });
    }

    for regex in [&*CSHARP_THROWS_RE, &*CSHARP_VERIFY_RE] {
        for captures in regex.captures_iter(body) {
            let whole = captures.get(0).expect("whole match");
            assertions.push(CSharpAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                meaningful: true,
                reason: "meaningful-assertion".to_string(),
                excerpt: collapse_whitespace(whole.as_str()),
                start_byte: whole.start(),
            });
        }
    }

    assertions
}

fn normalize_csharp_expr(expr: &str) -> String {
    normalize_assertion_expression(expr.trim().trim_end_matches(';'))
}

fn is_csharp_literal(expr: &str) -> bool {
    let trimmed = expr.trim();
    is_common_assertion_literal(trimmed) || matches!(trimmed, "true" | "false" | "null")
}

/// Whether this method declaration carries a runner-recognized test attribute.
///
/// The owner check stays structural: attributes on a class, parameter,
/// property, or nested local declaration do not make this method runnable.
pub fn csharp_method_has_runnable_test_attribute(node: Node<'_>, source: &str) -> bool {
    if node.kind() != "method_declaration" {
        return false;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| child.kind() == "attribute_list")
        .any(|attribute_list| {
            let mut cursor = attribute_list.walk();
            attribute_list
                .named_children(&mut cursor)
                .any(|attribute| csharp_runnable_test_attribute(attribute, source))
        })
}

fn csharp_runnable_test_attribute(node: Node<'_>, source: &str) -> bool {
    let Some(attribute_list) = node
        .parent()
        .filter(|parent| parent.kind() == "attribute_list")
    else {
        return false;
    };
    if !attribute_list
        .parent()
        .is_some_and(|owner| owner.kind() == "method_declaration")
    {
        return false;
    }
    let Some(name) = node
        .child_by_field_name("name")
        .or_else(|| node.named_child(0))
    else {
        return false;
    };
    let Some(final_name) = final_identifier_text(name, source) else {
        return false;
    };
    csharp_test_attribute_name(final_name)
}

fn csharp_test_attribute_name(name: &str) -> bool {
    let final_name = name.strip_suffix("Attribute").unwrap_or(name);
    matches!(
        final_name,
        "Fact"
            | "Theory"
            | "Test"
            | "TestCase"
            | "TestCaseSource"
            | "TestMethod"
            | "DataTestMethod"
    ) || ["Fact", "Theory"].iter().any(|suffix| {
        final_name
            .strip_suffix(suffix)
            .is_some_and(|prefix| !prefix.is_empty())
    })
}

fn final_identifier_text<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    let mut last = None;
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "identifier" {
            let text = node_text(current, source).trim();
            if !text.is_empty() {
                last = Some(text);
            }
        }
        for index in (0..current.named_child_count()).rev() {
            if let Some(child) = current.named_child(index) {
                stack.push(child);
            }
        }
    }
    last
}

#[cfg(test)]
mod test_classification_tests {
    use crate::declarations::parse_csharp_file;
    use brokk_bifrost_core::analyzer::ProjectFile;
    use tree_sitter::Parser;

    fn contains_tests(source: &str) -> bool {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
            .expect("C# grammar");
        let tree = parser.parse(source, None).expect("C# tree");
        let file = ProjectFile::new(std::env::temp_dir(), "Tests.cs");
        parse_csharp_file(&file, source, &tree)
            .contains_tests
            .expect("primary classification")
    }

    #[test]
    fn mixed_runnable_and_metadata_attributes_remain_tests() {
        for attributes in [
            "[Fact, Obsolete]",
            "[Test, Category(\"slow\")]",
            "[Fact][Obsolete]",
            "[Test][Category(\"slow\")]",
        ] {
            let source = format!("class Suite {{ {attributes} void Runs() {{ }} }}");
            assert!(contains_tests(&source), "{attributes}");
        }
        assert!(!contains_tests(
            "class Suite { [Category(\"slow\"), Obsolete] void Helper() {} }"
        ));
    }

    #[test]
    fn recognizes_custom_xunit_fact_and_theory_names() {
        for attribute in [
            "ConditionalTheory",
            "ConditionalTheoryAttribute",
            "Microsoft.AspNetCore.InternalTesting.ConditionalTheoryAttribute",
            "RetryFact",
            "SkippableFactAttribute",
        ] {
            let source = format!("public class Suite {{ [{attribute}] public void Runs() {{ }} }}");
            assert!(contains_tests(&source), "{attribute}");
        }
    }

    #[test]
    fn rejects_non_runnable_attributes_and_non_method_placements() {
        for source in [
            "[TestFixture] public class Suite { public void Helper() { } }",
            "[Fact] public class Suite { public void Helper() { } }",
            "public class Suite { [TestCategory(\"slow\")] public void Helper() { } }",
            "public class Suite { [TestInitialize] public void Setup() { } }",
            "public class Suite { [TheoryData] public void Helper() { } }",
            "public class Suite { [FactData] public void Helper() { } }",
            "public class Suite { public void Helper([Fact] int value) { } }",
            "public class Suite { [Fact] public int Value { get; set; } }",
        ] {
            assert!(!contains_tests(source), "{source}");
        }
    }
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#701: C# resolution omitted interface owners and mishandled generic arity in explicit member declarations"
)]
fn csharp_issue701_arity_key_keeps_generic_owner_and_normalizes_constructor_member() {
    assert_eq!(
        crate::syntax::csharp_arity_preserving_full_name("Ns.List`1.#ctor"),
        "Ns.List`1.List"
    );
    assert_eq!(
        crate::syntax::csharp_arity_preserving_full_name("global::Ns.Outer+Inner`1.#ctor"),
        "Ns.Outer.Inner`1.Inner"
    );
}
