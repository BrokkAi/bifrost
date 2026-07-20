use crate::analyzer::tree_sitter_analyzer::{WalkControl, walk_named_tree_preorder};
use crate::analyzer::{ProjectFile, TestAssertionSmell, TestAssertionWeights};
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

pub(super) fn detect_csharp_test_assertion_smells(
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
    let assertions = collect_csharp_assertions(body, weights);
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
            excerpt: compact_csharp_excerpt(body),
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
            - csharp_meaningful_assertion_credit(assertions.iter(), weights))
        .max(0);
        if score > 0 {
            out.push(TestAssertionSmell {
                file: file.clone(),
                enclosing_fq_name: symbol,
                assertion_kind: "shallow-assertions-only".to_string(),
                score,
                assertion_count,
                reasons: vec!["shallow-assertions-only".to_string()],
                excerpt: compact_csharp_excerpt(body),
                start_byte,
            });
        }
    }
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
        let signal = if left == right {
            let (kind, reason, score) = if is_csharp_literal(&left) {
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
            CSharpAssertionSignal {
                kind: kind.to_string(),
                score,
                shallow: false,
                meaningful: false,
                reason: reason.to_string(),
                excerpt: compact_csharp_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        } else {
            CSharpAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                meaningful: true,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_csharp_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        };
        assertions.push(signal);
    }

    for captures in CSHARP_ASSERT_TRUTH_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let matcher = captures.name("matcher").map(|m| m.as_str()).unwrap_or("");
        let arg = normalize_csharp_expr(captures.name("arg").map(|m| m.as_str()).unwrap_or(""));
        let (kind, score, shallow) = match matcher {
            "True" if arg == "true" => ("constant-truth", weights.constant_truth_weight, true),
            "False" if arg == "false" => ("constant-truth", weights.constant_truth_weight, true),
            "Null" | "NotNull" => ("nullness-only", weights.nullness_only_weight, true),
            _ => ("meaningful-assertion", 0, false),
        };
        assertions.push(CSharpAssertionSignal {
            kind: kind.to_string(),
            score,
            shallow,
            meaningful: score == 0,
            reason: kind.to_string(),
            excerpt: compact_csharp_excerpt(whole.as_str()),
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
                excerpt: compact_csharp_excerpt(whole.as_str()),
                start_byte: whole.start(),
            });
        }
    }

    assertions
}

fn csharp_meaningful_assertion_credit<'a>(
    assertions: impl Iterator<Item = &'a CSharpAssertionSignal>,
    weights: &TestAssertionWeights,
) -> i32 {
    let count = assertions.filter(|assertion| assertion.meaningful).count() as i32;
    let creditable = count.min(weights.meaningful_assertion_credit_cap.max(0));
    weights.meaningful_assertion_credit.max(0) * creditable
}

fn normalize_csharp_expr(expr: &str) -> String {
    expr.trim()
        .trim_end_matches(';')
        .trim_matches(|ch| matches!(ch, '(' | ')' | ' '))
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_csharp_literal(expr: &str) -> bool {
    let trimmed = expr.trim();
    (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || matches!(trimmed, "true" | "false" | "null")
        || trimmed.parse::<i64>().is_ok()
        || trimmed.parse::<f64>().is_ok()
}

fn compact_csharp_excerpt(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(super) fn csharp_contains_tests(root: Node<'_>, source: &str) -> bool {
    let mut found = false;
    walk_named_tree_preorder(root, true, |node| {
        found |= node.kind() == "attribute" && csharp_test_attribute(node, source);
        if found {
            WalkControl::SkipChildren
        } else {
            WalkControl::Continue
        }
    });
    found
}

fn csharp_test_attribute(node: Node<'_>, source: &str) -> bool {
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
        "Test" | "Fact" | "Theory" | "TestMethod" | "TestCase"
    )
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

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or_default()
}

#[test]
fn csharp_issue701_arity_key_keeps_generic_owner_and_normalizes_constructor_member() {
    assert_eq!(
        super::csharp_arity_preserving_full_name("Ns.List`1.#ctor"),
        "Ns.List`1.List"
    );
    assert_eq!(
        super::csharp_arity_preserving_full_name("global::Ns.Outer+Inner`1.#ctor"),
        "Ns.Outer.Inner`1.Inner"
    );
}
