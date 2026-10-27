use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::common::{collapse_whitespace, node_source_text as node_text};
use brokk_bifrost_core::analyzer::model::{TestAssertionSmell, TestAssertionWeights};
use brokk_bifrost_core::analyzer::test_assertions::{
    TestAssertionSignal, append_test_assertion_findings, is_common_assertion_literal,
    normalize_assertion_expression, oversized_quoted_literal,
};
use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, walk_named_tree_preorder};
use brokk_bifrost_core::path_utils::workspace_relative_slash_path;
use regex::Regex;
use std::sync::LazyLock;
use tree_sitter::Node;

pub fn rust_source_contains_tests(root: Node<'_>, source: &str) -> bool {
    let mut found = false;
    walk_named_tree_preorder(root, true, |node| {
        found |= node.kind() == "attribute_item" && rust_attribute_is_test_evidence(node, source);
        if found {
            WalkControl::SkipChildren
        } else {
            WalkControl::Continue
        }
    });
    found
}

/// Shared attribute test-evidence predicate used by both file-level test
/// classification (`rust_source_contains_tests`) and the per-declaration
/// test-region taint recorded during the declaration walk (see
/// `declarations::rust_item_carries_test_attribute`).
///
/// Positive evidence is any of:
///  - an attribute whose path's **last segment is `test`**
///    (`#[test]`, `#[tokio::test]`, `#[sqlx::test]`, `#[actix_rt::test]`,
///    custom `#[my::test]`), which subsumes the historical literal allowlist;
///  - `#[rstest]`, whose spelling has no `test` segment but is a well-known
///    test-case attribute;
///  - `#[cfg(...)]` whose predicate carries a positive `test` atom
///    (`cfg(test)`, `cfg(all(test, feature = "x"))`), while `cfg(not(test))`
///    is not evidence.
///
/// `cfg_attr` is intentionally out of scope: it re-gates *other* attributes and
/// does not by itself establish a test region.
pub fn rust_attribute_is_test_evidence(attribute_item: Node<'_>, source: &str) -> bool {
    let Some(attribute) = rust_attribute_node(attribute_item) else {
        return false;
    };
    let Some(path) = attribute.named_child(0) else {
        return false;
    };
    let last_segment = rust_attribute_path_last_segment(path, source);
    if last_segment == Some("cfg") {
        return attribute
            .child_by_field_name("arguments")
            .and_then(|arguments| {
                crate::lexical_scope::rust_cfg_argument_condition(arguments, source)
            })
            .is_some_and(|condition| cfg_has_positive_test_atom(&condition));
    }
    matches!(last_segment, Some("test") | Some("rstest"))
}

/// The `attribute` node nested inside an `attribute_item` (`# [ attribute ]`).
fn rust_attribute_node(attribute_item: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = attribute_item.walk();
    attribute_item
        .named_children(&mut cursor)
        .find(|child| child.kind() == "attribute")
}

/// Last path segment of an attribute path node. For a `scoped_identifier`
/// (`tokio::test`) this is the `name` field (`test`); for a bare `identifier`
/// (`test`, `cfg`) it is the identifier text itself. Other path shapes (e.g.
/// `crate`, `self`, generics) have no meaningful trailing test segment.
fn rust_attribute_path_last_segment<'a>(path: Node<'_>, source: &'a str) -> Option<&'a str> {
    match path.kind() {
        "scoped_identifier" => {
            let name = path.child_by_field_name("name")?;
            Some(node_text(name, source).trim())
        }
        "identifier" => Some(node_text(path, source).trim()),
        _ => None,
    }
}

/// Track test occurrences in both polarities through the structured postfix
/// predicate. Negation swaps polarity; all/any retain their children's evidence.
fn cfg_has_positive_test_atom(
    condition: &brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition,
) -> bool {
    use brokk_bifrost_core::analyzer::rust_facts::RustCfgInstruction;
    let mut stack: Vec<(bool, bool)> = Vec::new();
    for instruction in condition.instructions() {
        match instruction {
            RustCfgInstruction::Atom(name) => stack.push((name == "test", false)),
            RustCfgInstruction::KeyValue { .. } | RustCfgInstruction::Unknown => {
                stack.push((false, false))
            }
            RustCfgInstruction::Not => {
                let (positive, negative) = stack.pop().expect("cfg negation operand");
                stack.push((negative, positive));
            }
            RustCfgInstruction::All(count) | RustCfgInstruction::Any(count) => {
                assert!(stack.len() >= count, "cfg predicate operands");
                let start = stack.len() - count;
                let evidence = stack
                    .drain(start..)
                    .fold((false, false), |(positive, negative), child| {
                        (positive || child.0, negative || child.1)
                    });
                stack.push(evidence);
            }
        }
    }
    assert_eq!(stack.len(), 1, "cfg predicate result");
    stack[0].0
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

pub fn detect_rust_test_assertion_smells(
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
    let symbol = format!(
        "{}::{}",
        workspace_relative_slash_path(file.rel_path()),
        name
    );
    let assertions: Vec<_> = collect_rust_assertions(body, weights)
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
                excerpt: collapse_whitespace(whole.as_str()),
                start_byte: whole.start(),
            }
        } else if let Some(literal) = oversized_rust_literal(&left, &right, weights) {
            RustAssertionSignal {
                kind: "overspecified-literal".to_string(),
                score: weights.overspecified_literal_weight,
                shallow: true,
                meaningful: false,
                reason: format!("overspecified-literal:{literal}"),
                excerpt: collapse_whitespace(whole.as_str()),
                start_byte: whole.start(),
            }
        } else {
            RustAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                meaningful: true,
                reason: "meaningful-assertion".to_string(),
                excerpt: collapse_whitespace(whole.as_str()),
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
                excerpt: collapse_whitespace(whole.as_str()),
                start_byte: whole.start(),
            }
        } else if trimmed.contains(".is_some()") || trimmed.contains(".is_none()") {
            RustAssertionSignal {
                kind: "nullness-only".to_string(),
                score: weights.nullness_only_weight,
                shallow: true,
                meaningful: false,
                reason: "nullness-only".to_string(),
                excerpt: collapse_whitespace(whole.as_str()),
                start_byte: whole.start(),
            }
        } else {
            RustAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                meaningful: true,
                reason: "meaningful-assertion".to_string(),
                excerpt: collapse_whitespace(whole.as_str()),
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
            excerpt: collapse_whitespace(whole.as_str()),
            start_byte: whole.start(),
        });
    }

    assertions
}

fn normalize_rust_expr(expr: &str) -> String {
    normalize_assertion_expression(expr.trim().trim_end_matches(','))
}

fn is_rust_literal(expr: &str) -> bool {
    let trimmed = expr.trim();
    is_common_assertion_literal(trimmed) || matches!(trimmed, "true" | "false" | "None")
}

fn oversized_rust_literal(
    left: &str,
    right: &str,
    weights: &TestAssertionWeights,
) -> Option<String> {
    oversized_quoted_literal(left, right, weights, &['"'])
}
