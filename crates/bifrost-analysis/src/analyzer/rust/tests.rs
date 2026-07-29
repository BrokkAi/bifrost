use crate::analyzer::tree_sitter_analyzer::{WalkControl, walk_named_tree_preorder};
use crate::analyzer::{ProjectFile, TestAssertionSmell, TestAssertionWeights};
use regex::Regex;
use std::sync::LazyLock;
use tree_sitter::Node;

pub(super) fn rust_source_contains_tests(root: Node<'_>, source: &str) -> bool {
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
///  - `#[cfg(...)]` whose predicate carries a positive `test` token
///    (`cfg(test)`, `cfg(all(test, feature = "x"))`), while `cfg(not(test))`
///    is not evidence.
///
/// `cfg_attr` is intentionally out of scope: it re-gates *other* attributes and
/// does not by itself establish a test region.
pub(super) fn rust_attribute_is_test_evidence(attribute_item: Node<'_>, source: &str) -> bool {
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
            .and_then(|arguments| rust_token_tree_interior_text(arguments, source))
            .is_some_and(cfg_body_has_positive_test_token);
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

/// Interior text of a delimited `token_tree` (`( ... )`), excluding the
/// outermost delimiters, so `#[cfg(all(test))]`'s arguments yield `all(test)`.
fn rust_token_tree_interior_text<'a>(token_tree: Node<'_>, source: &'a str) -> Option<&'a str> {
    if token_tree.kind() != "token_tree" {
        return None;
    }
    let open = token_tree.child(0)?;
    let close = token_tree.child(token_tree.child_count().checked_sub(1)?)?;
    source.get(open.end_byte()..close.start_byte())
}

fn cfg_body_has_positive_test_token(body: &str) -> bool {
    if body.contains("not(test)") {
        return false;
    }

    let mut token = String::new();
    let mut in_string = false;
    for ch in body.chars() {
        if ch == '"' {
            in_string = !in_string;
            token.clear();
            continue;
        }
        if in_string {
            continue;
        }
        if ch.is_ascii_alphanumeric() || ch == '_' {
            token.push(ch);
            continue;
        }
        if token == "test" {
            return true;
        }
        token.clear();
    }
    token == "test"
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or_default()
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
