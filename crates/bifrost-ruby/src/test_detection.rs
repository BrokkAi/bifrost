//! Ruby test-file recognition and test-assertion smell detection.
//!
//! `analyzer/ruby/tests.rs` in `brokk-bifrost-analysis` keeps the empty
//! `impl TestDetectionProvider for RubyAnalyzer` and the analyzer-bound
//! fixture suites; everything here is a pure function of a parsed file.

use crate::declarations::{extract_name_segments, parse_ruby_tree, ruby_node_text};
use crate::syntax::{
    ruby_call_arguments, ruby_first_call_argument, single_static_string_content_node,
};
use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::model::{
    TestAssertionAnalysis, TestAssertionSmell, TestAssertionWeights,
};
use brokk_bifrost_core::analyzer::test_assertions::{
    TestAssertionSignal, append_test_assertion_findings, compact_assertion_excerpt,
};
use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, walk_named_tree_preorder};
use tree_sitter::Node;

const TEST_ASSERTION_EXCERPT_MAX_LEN: usize = 180;
const RSPEC_DESCRIPTION_MAX_LEN: usize = 180;
const MIN_RUBY_ASSERTION_NODE_BUDGET: usize = 10_000;
const MAX_RUBY_ASSERTION_NODE_BUDGET: usize = 1_000_000;
const RUBY_ASSERTION_NODES_PER_CANDIDATE: usize = 100;

const MINITEST_ASSERTION_METHODS: &[&str] = &[
    "assert",
    "refute",
    "assert_empty",
    "refute_empty",
    "assert_equal",
    "refute_equal",
    "assert_in_delta",
    "refute_in_delta",
    "assert_in_epsilon",
    "refute_in_epsilon",
    "assert_includes",
    "refute_includes",
    "assert_instance_of",
    "refute_instance_of",
    "assert_kind_of",
    "refute_kind_of",
    "assert_match",
    "refute_match",
    "assert_nil",
    "refute_nil",
    "assert_operator",
    "refute_operator",
    "assert_output",
    "assert_path_exists",
    "refute_path_exists",
    "assert_pattern",
    "refute_pattern",
    "assert_predicate",
    "refute_predicate",
    "assert_raises",
    "assert_respond_to",
    "refute_respond_to",
    "assert_same",
    "refute_same",
    "assert_send",
    "assert_silent",
    "assert_throws",
    "flunk",
    "pass",
];

/// Heuristic detection of Ruby test files across the common frameworks:
/// RSpec, Minitest, and Test::Unit. Recognition is entirely parser-backed so
/// assertion-like text in comments and strings cannot classify a file as a
/// test.
pub fn ruby_contains_tests(root: Node<'_>, source: &str) -> bool {
    let mut found = false;
    walk_named_tree_preorder(root, true, |node| {
        found = match node.kind() {
            "method" => {
                ruby_method_name(node, source).is_some_and(|name| name.starts_with("test_"))
            }
            "class" => ruby_test_superclass(node, source),
            "call" => ruby_test_marker_call(node, source),
            _ => false,
        };
        if found {
            WalkControl::Break
        } else {
            WalkControl::Continue
        }
    });
    found
}

#[derive(Clone)]
struct RubyTestCase<'tree> {
    name: String,
    body: Node<'tree>,
    start_byte: usize,
}

pub fn detect_ruby_test_assertion_smells(
    file: &ProjectFile,
    source: &str,
    weights: &TestAssertionWeights,
) -> Vec<TestAssertionSmell> {
    detect_ruby_test_assertion_smells_limited(file, source, weights, usize::MAX).findings
}

pub fn detect_ruby_test_assertion_smells_limited(
    file: &ProjectFile,
    source: &str,
    weights: &TestAssertionWeights,
    max_candidates: usize,
) -> TestAssertionAnalysis {
    let Some(tree) = parse_ruby_tree(source) else {
        return TestAssertionAnalysis {
            findings: Vec::new(),
            inspected_candidates: Some(0),
            truncated: false,
        };
    };
    let mut findings = Vec::new();
    let mut inspected_candidates = 0usize;
    let mut remaining_nodes = ruby_assertion_node_budget(max_candidates);
    let mut truncated = false;
    walk_named_tree_preorder(tree.root_node(), true, |node| {
        if remaining_nodes == 0 {
            truncated = true;
            return WalkControl::Break;
        }
        remaining_nodes -= 1;
        if let Some(test_case) = ruby_test_case(node, source) {
            if inspected_candidates >= max_candidates {
                truncated = true;
                return WalkControl::Break;
            }
            let remaining = max_candidates - inspected_candidates;
            let assertions = collect_ruby_assertions_limited(
                test_case.body,
                source,
                weights,
                remaining,
                &mut remaining_nodes,
            );
            if assertions.truncated {
                truncated = true;
                return WalkControl::Break;
            }
            inspected_candidates += assertions.signals.len().max(1);
            analyze_ruby_test_case(
                file,
                source,
                test_case,
                weights,
                assertions.signals,
                &mut findings,
            );
            if findings.len() > max_candidates {
                findings.truncate(max_candidates);
                truncated = true;
            }
            if truncated {
                WalkControl::Break
            } else {
                WalkControl::SkipChildren
            }
        } else {
            WalkControl::Continue
        }
    });
    TestAssertionAnalysis {
        findings,
        inspected_candidates: Some(inspected_candidates),
        truncated,
    }
}

fn ruby_test_case<'tree>(node: Node<'tree>, source: &'tree str) -> Option<RubyTestCase<'tree>> {
    if node.kind() == "method" {
        let name = ruby_method_name(node, source)?;
        if !name.starts_with("test_") {
            return None;
        }
        return Some(RubyTestCase {
            name: bounded_test_case_name(name),
            body: node.child_by_field_name("body").unwrap_or(node),
            start_byte: node.start_byte(),
        });
    }
    if node.kind() != "call" || call_receiver(node).is_some() {
        return None;
    }
    let method = call_method_name(node, source)?;
    if !matches!(method, "it" | "specify") {
        return None;
    }
    let block = node.child_by_field_name("block")?;
    let description = ruby_first_call_argument(node)
        .and_then(static_string_content)
        .map(|content| ruby_node_text(content, source))
        .filter(|description| !description.is_empty())
        .unwrap_or(method);
    Some(RubyTestCase {
        name: bounded_test_case_name(description),
        body: block.child_by_field_name("body").unwrap_or(block),
        start_byte: node.start_byte(),
    })
}

fn analyze_ruby_test_case(
    file: &ProjectFile,
    source: &str,
    test_case: RubyTestCase<'_>,
    weights: &TestAssertionWeights,
    assertions: Vec<TestAssertionSignal>,
    out: &mut Vec<TestAssertionSmell>,
) {
    let symbol = format!("{}::{}", file, test_case.name);
    append_test_assertion_findings(
        file,
        symbol,
        compact_ruby_excerpt(ruby_node_text(test_case.body, source)),
        test_case.start_byte,
        &assertions,
        weights,
        out,
    );
}

struct RubyAssertionCollection {
    signals: Vec<TestAssertionSignal>,
    truncated: bool,
}

fn collect_ruby_assertions_limited(
    body: Node<'_>,
    source: &str,
    weights: &TestAssertionWeights,
    max_assertions: usize,
    remaining_nodes: &mut usize,
) -> RubyAssertionCollection {
    let mut assertions = Vec::new();
    let mut truncated = false;
    walk_named_tree_preorder(body, true, |node| {
        if *remaining_nodes == 0 {
            truncated = true;
            return WalkControl::Break;
        }
        *remaining_nodes -= 1;
        if node != body && ruby_test_case(node, source).is_some() {
            return WalkControl::SkipChildren;
        }
        if matches!(node.kind(), "method" | "singleton_method")
            || ruby_deferred_callable(node, source)
        {
            return WalkControl::SkipChildren;
        }
        if node.kind() != "call" {
            return WalkControl::Continue;
        }
        if let Some(signal) = ruby_assertion_signal(node, source, weights) {
            if assertions.len() >= max_assertions {
                truncated = true;
                return WalkControl::Break;
            }
            assertions.push(signal);
            WalkControl::SkipChildren
        } else {
            WalkControl::Continue
        }
    });
    RubyAssertionCollection {
        signals: assertions,
        truncated,
    }
}

fn ruby_assertion_node_budget(max_candidates: usize) -> usize {
    if max_candidates == usize::MAX {
        return usize::MAX;
    }
    max_candidates
        .saturating_mul(RUBY_ASSERTION_NODES_PER_CANDIDATE)
        .clamp(
            MIN_RUBY_ASSERTION_NODE_BUDGET,
            MAX_RUBY_ASSERTION_NODE_BUDGET,
        )
}

fn ruby_assertion_signal(
    call: Node<'_>,
    source: &str,
    weights: &TestAssertionWeights,
) -> Option<TestAssertionSignal> {
    if let Some(signal) = rspec_assertion_signal(call, source, weights) {
        return Some(signal);
    }
    let method = call_method_name(call, source)?;
    let receiver = call_receiver(call);
    if receiver.is_none_or(|receiver| receiver.kind() == "self")
        && MINITEST_ASSERTION_METHODS.contains(&method)
    {
        return Some(minitest_assertion_signal(call, method, source, weights));
    }
    if matches!(
        method,
        "must_equal"
            | "wont_equal"
            | "must_same"
            | "wont_same"
            | "must_be_nil"
            | "wont_be_nil"
            | "must_raise"
            | "must_throw"
    ) && receiver.is_some()
    {
        return Some(minitest_expectation_signal(call, method, source, weights));
    }
    None
}

fn minitest_assertion_signal(
    call: Node<'_>,
    method: &str,
    source: &str,
    weights: &TestAssertionWeights,
) -> TestAssertionSignal {
    let arguments = ruby_call_arguments(call);
    let classification = match method {
        "assert_equal" | "refute_equal" | "assert_same" | "refute_same" => arguments
            .first()
            .zip(arguments.get(1))
            .map(|(&left, &right)| classify_ruby_equality(left, right, source, weights)),
        "assert_nil" | "refute_nil" => {
            Some(("nullness-only", weights.nullness_only_weight, true, false))
        }
        "assert" if arguments.first().is_some_and(|node| node.kind() == "true") => {
            Some(("constant-truth", weights.constant_truth_weight, true, false))
        }
        "refute" if arguments.first().is_some_and(|node| node.kind() == "false") => {
            Some(("constant-truth", weights.constant_truth_weight, true, false))
        }
        _ => None,
    };
    assertion_signal(call, source, classification, weights, arguments.into_iter())
}

fn minitest_expectation_signal(
    call: Node<'_>,
    method: &str,
    source: &str,
    weights: &TestAssertionWeights,
) -> TestAssertionSignal {
    let receiver = call_receiver(call).expect("expectation method has receiver");
    let arguments = ruby_call_arguments(call);
    let classification = match method {
        "must_equal" | "wont_equal" | "must_same" | "wont_same" => arguments
            .first()
            .map(|&argument| classify_ruby_equality(receiver, argument, source, weights)),
        "must_be_nil" | "wont_be_nil" => {
            Some(("nullness-only", weights.nullness_only_weight, true, false))
        }
        _ => None,
    };
    assertion_signal(
        call,
        source,
        classification,
        weights,
        std::iter::once(receiver).chain(arguments),
    )
}

fn rspec_assertion_signal(
    call: Node<'_>,
    source: &str,
    weights: &TestAssertionWeights,
) -> Option<TestAssertionSignal> {
    if !matches!(call_method_name(call, source)?, "to" | "not_to" | "to_not") {
        return None;
    }
    let expectation = call_receiver(call)?;
    let actual = if expectation.kind() == "call"
        && call_method_name(expectation, source) == Some("expect")
        && call_receiver(expectation).is_none()
    {
        ruby_first_call_argument(expectation)
    } else if ruby_is_bare_call_named(expectation, "is_expected", source) {
        None
    } else {
        return None;
    };
    let matcher = ruby_first_call_argument(call)?;
    let matcher_method = if matcher.kind() == "call" {
        call_method_name(matcher, source)
    } else if matcher.kind() == "identifier" {
        Some(ruby_node_text(matcher, source))
    } else {
        None
    };
    let matcher_arguments = if matcher.kind() == "call" {
        ruby_call_arguments(matcher)
    } else {
        Vec::new()
    };
    let built_in_matcher = matcher.kind() != "call" || call_receiver(matcher).is_none();
    let classification = match matcher_method.filter(|_| built_in_matcher) {
        Some("eq" | "eql" | "equal" | "be") => actual
            .zip(matcher_arguments.first().copied())
            .map(|(left, right)| classify_ruby_equality(left, right, source, weights)),
        Some("be_nil") => Some(("nullness-only", weights.nullness_only_weight, true, false)),
        Some("be_truthy" | "be_falsey") => actual.and_then(|node| {
            matches!(node.kind(), "true" | "false").then_some((
                "constant-truth",
                weights.constant_truth_weight,
                true,
                false,
            ))
        }),
        _ => None,
    };
    assertion_signal(
        call,
        source,
        classification,
        weights,
        actual.into_iter().chain(matcher_arguments),
    )
    .into()
}

fn classify_ruby_equality(
    left: Node<'_>,
    right: Node<'_>,
    source: &str,
    weights: &TestAssertionWeights,
) -> (&'static str, i32, bool, bool) {
    if ruby_node_text(left, source).trim() == ruby_node_text(right, source).trim() {
        if ruby_scalar_literal(left) {
            (
                "constant-equality",
                weights.constant_equality_weight,
                false,
                false,
            )
        } else {
            (
                "self-comparison",
                weights.tautological_assertion_weight,
                false,
                false,
            )
        }
    } else if ruby_scalar_literal(left) && ruby_scalar_literal(right) {
        (
            "constant-equality",
            weights.constant_equality_weight,
            false,
            false,
        )
    } else {
        ("meaningful-assertion", 0, false, true)
    }
}

fn assertion_signal<'tree>(
    call: Node<'tree>,
    source: &str,
    classification: Option<(&'static str, i32, bool, bool)>,
    weights: &TestAssertionWeights,
    mut literal_candidates: impl Iterator<Item = Node<'tree>>,
) -> TestAssertionSignal {
    let oversized_literal = literal_candidates.any(|node| oversized_ruby_string(node, weights));
    let (mut kind, mut score, shallow, mut meaningful) =
        classification.unwrap_or(("meaningful-assertion", 0, false, true));
    let mut reasons: Vec<String> = (score > 0).then(|| kind.to_string()).into_iter().collect();
    if oversized_literal {
        score += weights.overspecified_literal_weight;
        reasons.push("overspecified-literal".to_string());
        kind = "overspecified-literal";
        meaningful = false;
    }
    TestAssertionSignal {
        kind: kind.to_string(),
        score,
        shallow,
        meaningful,
        reasons,
        excerpt: compact_ruby_excerpt(ruby_node_text(call, source)),
        start_byte: call.start_byte(),
    }
}

fn ruby_test_marker_call(node: Node<'_>, source: &str) -> bool {
    let Some(method) = call_method_name(node, source) else {
        return false;
    };
    let receiver = call_receiver(node);
    if receiver.is_none() && matches!(method, "describe" | "context" | "it" | "specify") {
        return true;
    }
    if method == "describe"
        && receiver.is_some_and(|receiver| ruby_node_text(receiver, source) == "RSpec")
    {
        return true;
    }
    if !matches!(method, "require" | "require_relative") || receiver.is_some() {
        return false;
    }
    ruby_first_call_argument(node)
        .and_then(static_string_content)
        .map(|content| ruby_node_text(content, source))
        .is_some_and(|required| {
            matches!(required, "spec_helper" | "test_helper" | "test/unit")
                || required == "rspec"
                || required.starts_with("rspec/")
                || required == "minitest"
                || required.starts_with("minitest/")
        })
}

fn ruby_test_superclass(node: Node<'_>, source: &str) -> bool {
    let Some(superclass) = node.child_by_field_name("superclass") else {
        return false;
    };
    let Some(name) = superclass.named_child(0) else {
        return false;
    };
    matches!(
        extract_name_segments(name, source).as_slice(),
        [first, second] if (first == "Minitest" || first == "MiniTest") && second == "Test"
    ) || matches!(
        extract_name_segments(name, source).as_slice(),
        [first, second, third] if first == "Test" && second == "Unit" && third == "TestCase"
    )
}

fn ruby_method_name<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    node.child_by_field_name("name")
        .map(|name| ruby_node_text(name, source))
}

fn call_method_name<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    node.child_by_field_name("method")
        .map(|method| ruby_node_text(method, source))
}

fn call_receiver(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("receiver")
}

fn static_string_content(node: Node<'_>) -> Option<Node<'_>> {
    (node.kind() == "string")
        .then(|| single_static_string_content_node(node))
        .flatten()
}

fn ruby_scalar_literal(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "integer" | "float" | "complex" | "rational" | "true" | "false" | "nil" | "simple_symbol"
    ) || static_string_content(node).is_some()
}

fn oversized_ruby_string(node: Node<'_>, weights: &TestAssertionWeights) -> bool {
    static_string_content(node).is_some_and(|content| {
        content.end_byte().saturating_sub(content.start_byte())
            > weights.large_literal_length_threshold.max(0) as usize
    })
}

fn compact_ruby_excerpt(text: &str) -> String {
    compact_assertion_excerpt(text, TEST_ASSERTION_EXCERPT_MAX_LEN)
}

fn bounded_test_case_name(description: &str) -> String {
    if description.chars().count() <= RSPEC_DESCRIPTION_MAX_LEN {
        return description.to_string();
    }
    let end = description
        .char_indices()
        .nth(RSPEC_DESCRIPTION_MAX_LEN)
        .map(|(index, _)| index)
        .unwrap_or(description.len());
    format!("{}...", &description[..end])
}

fn ruby_deferred_callable(node: Node<'_>, source: &str) -> bool {
    if node.kind() == "lambda" {
        return true;
    }
    if node.kind() != "call" || node.child_by_field_name("block").is_none() {
        return false;
    }
    let receiver = call_receiver(node);
    let Some(method) = call_method_name(node, source) else {
        return false;
    };
    (receiver.is_none_or(|receiver| receiver.kind() == "self")
        && matches!(
            method,
            "proc" | "lambda" | "define_method" | "define_singleton_method"
        ))
        || (method == "new"
            && receiver.is_some_and(|receiver| {
                matches!(extract_name_segments(receiver, source).as_slice(), [name] if name == "Proc")
            }))
}

fn ruby_is_bare_call_named(node: Node<'_>, expected: &str, source: &str) -> bool {
    (node.kind() == "identifier" && ruby_node_text(node, source) == expected)
        || (node.kind() == "call"
            && call_receiver(node).is_none()
            && call_method_name(node, source) == Some(expected))
}
