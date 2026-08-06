//! Kotlin test detection and test-assertion-smell analysis (#1243).
//!
//! [`kotlin_contains_tests`] recognizes the test frameworks and DSL shapes
//! that commonly appear in Kotlin source: JUnit4/5 annotations (also used
//! unmodified by kotlin.test's own `@Test`), Kotest spec base classes named
//! by a class-like declaration's supertype list, Kotest's
//! `test("name") { … }` / `"name" should { … }` block forms, and Spek's
//! `describe`/`it` blocks. Detection is deliberately name-based rather than
//! import-resolved, matching every other language's `contains_tests`: it
//! answers "does this file plausibly declare tests", not "which framework,
//! precisely" (the `java_extends_testcase` analogue is `java/tests.rs:169`;
//! the Kotest-supertype check here is its Kotlin counterpart).
//!
//! [`detect_kotlin_test_assertion_smells`] scores the same shapes' bodies for
//! weak assertions. It mirrors Java's tree-walk shape (`java/tests.rs`)
//! rather than Scala's regex table: Kotlin's assertion vocabulary spans two
//! distinct AST shapes — ordinary calls (kotlin.test, JUnit `Assertions.*`,
//! MockK `verify`) and infix expressions (Kotest's `shouldBe` family) — which
//! a structural walk distinguishes far more reliably than a regex would, and
//! the vendored grammar exposes both shapes as ordinary named nodes.
//!
//! Deliberately out of scope: Kotest's `"name" should { … }` test-declaration
//! form is recognized for [`kotlin_contains_tests`] but is not treated as its
//! own scoreable assertion-smell unit — there is no clean way to
//! structurally distinguish it from an ordinary `should` assertion used
//! *inside* a `test`/`it` body without risking double-scoring the same
//! block twice.

use crate::kotlin::supertypes::extract_kotlin_supertypes;
use crate::kotlin::syntax::{kotlin_callee, kotlin_named_argument_label};
use brokk_bifrost_core::analyzer::common::node_source_text as node_text;
use brokk_bifrost_core::analyzer::model::{TestAssertionSmell, TestAssertionWeights};
use brokk_bifrost_core::analyzer::tree_walk::{
    WalkControl, named_children, walk_named_tree_preorder,
};
use brokk_bifrost_core::analyzer::{CodeUnitIndex, ProjectFile};
use brokk_bifrost_core::path_utils::rel_path_string;
use tree_sitter::{Node, Parser};

use crate::kotlin::declarations::{KOTLIN_CLASS_LIKE_KINDS, kotlin_identifier_text};

const KOTLIN_TEST_ANNOTATIONS: &[&str] = &["Test", "ParameterizedTest", "RepeatedTest"];

/// Kotest spec base classes recognized as "this class-like declaration is
/// itself a test spec". Issue #1243 names the first four explicitly; the
/// rest are Kotest's other built-in spec styles, which share the identical
/// "extend a spec base class" shape and cost nothing extra to recognize.
const KOTEST_SPEC_BASE_CLASSES: &[&str] = &[
    "StringSpec",
    "FunSpec",
    "DescribeSpec",
    "BehaviorSpec",
    "WordSpec",
    "ShouldSpec",
    "FreeSpec",
    "FeatureSpec",
    "ExpectSpec",
    "AnnotationSpec",
];

/// Callee names recognized as a DSL test-case declaration: Kotest's
/// `test("name") { … }` and Spek/Kotest's `it("name") { … }`. `describe` is
/// deliberately excluded — it is a grouping construct, not a test case, and
/// is already reachable through the file's generic tree walk so nested
/// `it(...)` blocks inside it are still found.
const KOTLIN_TEST_DSL_CALLS: &[&str] = &["test", "it"];

const KOTLIN_TEST_ASSERTION_CALLS: &[&str] = &[
    "assertEquals",
    "assertNotEquals",
    "assertTrue",
    "assertFalse",
    "assertNull",
    "assertNotNull",
    "assertSame",
    "assertNotSame",
    "fail",
];
const KOTLIN_SHALLOW_ASSERTION_CALLS: &[&str] = &["assertNull", "assertNotNull"];
const KOTLIN_THROW_ASSERTION_CALLS: &[&str] = &["assertThrows", "assertFailsWith", "shouldThrow"];
const KOTLIN_MOCK_VERIFY_CALLS: &[&str] = &["verify", "coVerify", "verifyAll", "verifySequence"];
const KOTEST_SHOULD_INFIX: &[&str] = &["shouldBe", "shouldNotBe", "shouldEqual", "shouldNotEqual"];

const KOTLIN_CONSTANT_LITERAL_KINDS: &[&str] = &[
    "boolean_literal",
    "null_literal",
    "character_literal",
    "integer_literal",
    "hex_literal",
    "bin_literal",
    "long_literal",
    "real_literal",
    "unsigned_literal",
];

const KIND_JUNIT: &str = "junit-assertion";
const KIND_MOCK_VERIFICATION: &str = "mock-verification";
const KIND_MEANINGFUL: &str = "meaningful-assertion";
const KIND_NO_ASSERTIONS: &str = "no-assertions";
const KIND_CONSTANT_TRUTH: &str = "constant-truth";
const KIND_CONSTANT_EQUALITY: &str = "constant-equality";
const KIND_SELF_COMPARISON: &str = "self-comparison";
const KIND_NULLNESS_ONLY: &str = "nullness-only";
const KIND_SHALLOW_ONLY: &str = "shallow-assertions-only";
const KIND_OVERSPECIFIED_LITERAL: &str = "overspecified-literal";

const TEST_ASSERTION_EXCERPT_MAX_LEN: usize = 180;

/// Whether a Kotlin file contains any recognized test-framework evidence.
pub fn kotlin_contains_tests(root: Node<'_>, source: &str) -> bool {
    let mut found = false;
    walk_named_tree_preorder(root, true, |node| {
        found |= match node.kind() {
            "annotation" => kotlin_test_annotation(node, source),
            kind if KOTLIN_CLASS_LIKE_KINDS.contains(&kind) => {
                kotlin_test_spec_supertype(node, source)
            }
            "call_expression" => kotlin_test_dsl_call(node, source),
            "infix_expression" => kotlin_test_should_block(node, source),
            _ => false,
        };
        if found {
            WalkControl::SkipChildren
        } else {
            WalkControl::Continue
        }
    });
    found
}

fn kotlin_test_annotation(node: Node<'_>, source: &str) -> bool {
    kotlin_annotation_simple_name(node, source)
        .is_some_and(|name| KOTLIN_TEST_ANNOTATIONS.contains(&name))
}

/// The simple (rightmost) name an `annotation` node spells, whether it holds
/// a bare `user_type` (`@Test`) or a `constructor_invocation` wrapping one
/// (`@ParameterizedTest(...)`).
fn kotlin_annotation_simple_name<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    let user_type = named_children(node)
        .into_iter()
        .find_map(|child| match child.kind() {
            "user_type" => Some(child),
            "constructor_invocation" => named_children(child)
                .into_iter()
                .find(|inner| inner.kind() == "user_type"),
            _ => None,
        })?;
    named_children(user_type)
        .into_iter()
        .rfind(|child| child.kind() == "type_identifier")
        .map(|segment| kotlin_identifier_text(segment, source))
}

fn kotlin_test_spec_supertype(node: Node<'_>, source: &str) -> bool {
    extract_kotlin_supertypes(node, source)
        .iter()
        .any(|supertype| {
            let simple = supertype.rsplit('.').next().unwrap_or(supertype.as_str());
            KOTEST_SPEC_BASE_CLASSES.contains(&simple)
        })
}

fn kotlin_test_dsl_call(node: Node<'_>, source: &str) -> bool {
    kotlin_callee(node)
        .filter(|callee| callee.kind() == "simple_identifier")
        .is_some_and(|callee| {
            KOTLIN_TEST_DSL_CALLS.contains(&kotlin_identifier_text(callee, source))
        })
}

/// Kotest's `"name" should { … }` block form: an infix `should` whose right
/// operand is a bare lambda. An assertion use of `should`
/// (`actual should beGreaterThan(1)`) never has a lambda on the right, so
/// this shape is specific to the test-declaration form.
fn kotlin_test_should_block(node: Node<'_>, source: &str) -> bool {
    let children = named_children(node);
    let [_, operator, right] = children.as_slice() else {
        return false;
    };
    operator.kind() == "simple_identifier"
        && kotlin_identifier_text(*operator, source) == "should"
        && right.kind() == "lambda_literal"
}

/// One test-case body discovered by [`collect_kotlin_test_cases`], together
/// with the line span used to look up its enclosing declaration.
struct KotlinTestCase<'tree> {
    body: Node<'tree>,
    start_row: usize,
    end_row: usize,
}

pub fn detect_kotlin_test_assertion_smells(
    analyzer: &dyn CodeUnitIndex,
    file: &ProjectFile,
    source: &str,
    weights: &TestAssertionWeights,
) -> Vec<TestAssertionSmell> {
    let Some(tree) = parse_kotlin_tree_for_tests(source) else {
        return Vec::new();
    };
    let mut cases = Vec::new();
    collect_kotlin_test_cases(tree.root_node(), source, &mut cases);

    let mut findings = Vec::new();
    for case in cases {
        analyze_kotlin_test_case(analyzer, file, source, case, weights, &mut findings);
    }
    findings.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.enclosing_fq_name.cmp(&b.enclosing_fq_name))
            .then_with(|| a.start_byte.cmp(&b.start_byte))
    });
    findings
}

fn parse_kotlin_tree_for_tests(source: &str) -> Option<tree_sitter::Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&crate::kotlin::language::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

fn collect_kotlin_test_cases<'tree>(
    root: Node<'tree>,
    source: &str,
    out: &mut Vec<KotlinTestCase<'tree>>,
) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "function_declaration" if kotlin_function_is_junit_test(node, source) => {
                if let Some(body) = kotlin_function_body_node(node) {
                    out.push(KotlinTestCase {
                        body,
                        start_row: node.start_position().row,
                        end_row: node.end_position().row,
                    });
                }
            }
            "call_expression" if kotlin_test_dsl_call(node, source) => {
                if let Some(body) = kotlin_call_trailing_lambda_body(node) {
                    out.push(KotlinTestCase {
                        body,
                        start_row: node.start_position().row,
                        end_row: node.end_position().row,
                    });
                }
            }
            _ => {}
        }
        stack.extend(named_children(node));
    }
}

fn kotlin_function_is_junit_test(function: Node<'_>, source: &str) -> bool {
    let Some(modifiers) = named_children(function)
        .into_iter()
        .find(|child| child.kind() == "modifiers")
    else {
        return false;
    };
    named_children(modifiers)
        .into_iter()
        .filter(|child| child.kind() == "annotation")
        .any(|annotation| {
            kotlin_annotation_simple_name(annotation, source)
                .is_some_and(|name| KOTLIN_TEST_ANNOTATIONS.contains(&name))
        })
}

fn kotlin_function_body_node(function: Node<'_>) -> Option<Node<'_>> {
    named_children(function)
        .into_iter()
        .find(|child| child.kind() == "function_body")
}

/// The `lambda_literal` a DSL test call's trailing lambda holds
/// (`test("name") { … }`), or `None` for a call with no trailing lambda —
/// which names no scoreable body.
fn kotlin_call_trailing_lambda_body(call: Node<'_>) -> Option<Node<'_>> {
    let call_suffix = named_children(call)
        .into_iter()
        .find(|child| child.kind() == "call_suffix")?;
    let annotated_lambda = named_children(call_suffix)
        .into_iter()
        .find(|child| child.kind() == "annotated_lambda")?;
    named_children(annotated_lambda)
        .into_iter()
        .find(|child| child.kind() == "lambda_literal")
}

fn analyze_kotlin_test_case(
    analyzer: &dyn CodeUnitIndex,
    file: &ProjectFile,
    source: &str,
    case: KotlinTestCase<'_>,
    weights: &TestAssertionWeights,
    out: &mut Vec<TestAssertionSmell>,
) {
    let mut calls = Vec::new();
    collect_nodes_by_kind(case.body, "call_expression", &mut calls);
    let mut infixes = Vec::new();
    collect_nodes_by_kind(case.body, "infix_expression", &mut infixes);

    let enclosing = analyzer
        .enclosing_code_unit_for_lines(file, case.start_row, case.end_row)
        .map(|cu| cu.fq_name())
        .unwrap_or_else(|| rel_path_string(file));

    let mut assertions: Vec<KotlinAssertionSignal> = calls
        .into_iter()
        .filter_map(|call| kotlin_call_assertion_signal(call, source, weights))
        .collect();
    assertions.extend(
        infixes
            .into_iter()
            .filter_map(|infix| kotlin_infix_assertion_signal(infix, source, weights)),
    );

    let assertion_count = assertions.len() as i32;
    if assertion_count == 0 {
        out.push(TestAssertionSmell {
            file: file.clone(),
            enclosing_fq_name: enclosing,
            assertion_kind: KIND_NO_ASSERTIONS.to_string(),
            score: weights.no_assertion_weight,
            assertion_count: 0,
            reasons: vec![KIND_NO_ASSERTIONS.to_string()],
            excerpt: compact_kotlin_excerpt(node_text(case.body, source)),
            start_byte: case.body.start_byte(),
        });
        return;
    }

    for assertion in &assertions {
        if assertion.score <= 0 {
            continue;
        }
        out.push(TestAssertionSmell {
            file: file.clone(),
            enclosing_fq_name: enclosing.clone(),
            assertion_kind: assertion.kind.clone(),
            score: assertion.score,
            assertion_count,
            reasons: vec![assertion.reason.clone()],
            excerpt: assertion.excerpt.clone(),
            start_byte: assertion.start_byte,
        });
    }

    if assertions.iter().all(|assertion| assertion.shallow) {
        out.push(TestAssertionSmell {
            file: file.clone(),
            enclosing_fq_name: enclosing,
            assertion_kind: KIND_SHALLOW_ONLY.to_string(),
            score: weights.shallow_assertion_only_weight,
            assertion_count,
            reasons: vec![KIND_SHALLOW_ONLY.to_string()],
            excerpt: compact_kotlin_excerpt(node_text(case.body, source)),
            start_byte: case.body.start_byte(),
        });
    }
}

#[derive(Clone)]
struct KotlinAssertionSignal {
    kind: String,
    score: i32,
    shallow: bool,
    reason: String,
    excerpt: String,
    start_byte: usize,
}

fn kotlin_call_assertion_signal(
    call: Node<'_>,
    source: &str,
    weights: &TestAssertionWeights,
) -> Option<KotlinAssertionSignal> {
    let callee = kotlin_callee(call)?;
    if callee.kind() != "simple_identifier" {
        return None;
    }
    let name = kotlin_identifier_text(callee, source);
    let text = compact_kotlin_excerpt(node_text(call, source));

    if KOTLIN_TEST_ASSERTION_CALLS.contains(&name) {
        return Some(classify_kotlin_junit_assertion(
            call, name, source, &text, weights,
        ));
    }
    if KOTLIN_MOCK_VERIFY_CALLS.contains(&name) {
        return Some(KotlinAssertionSignal {
            kind: KIND_MOCK_VERIFICATION.to_string(),
            score: 0,
            shallow: false,
            reason: KIND_MEANINGFUL.to_string(),
            excerpt: text,
            start_byte: call.start_byte(),
        });
    }
    if KOTLIN_THROW_ASSERTION_CALLS.contains(&name) {
        return Some(KotlinAssertionSignal {
            kind: KIND_JUNIT.to_string(),
            score: 0,
            shallow: false,
            reason: KIND_MEANINGFUL.to_string(),
            excerpt: text,
            start_byte: call.start_byte(),
        });
    }
    None
}

fn classify_kotlin_junit_assertion(
    call: Node<'_>,
    name: &str,
    source: &str,
    text: &str,
    weights: &TestAssertionWeights,
) -> KotlinAssertionSignal {
    let args = kotlin_call_argument_exprs(call);
    let mut score = 0;
    let mut reason = KIND_MEANINGFUL.to_string();
    let mut kind = KIND_JUNIT.to_string();
    let shallow = KOTLIN_SHALLOW_ASSERTION_CALLS.contains(&name);

    // kotlin.test/JUnit5 put the condition first and an optional message
    // last; JUnit4 puts the message first. Taking the *last* argument
    // handles JUnit4's `assertTrue(message, condition)` correctly and, for
    // the far more common single-argument `assertTrue(condition)` call,
    // is the condition either way.
    if (name == "assertTrue" || name == "assertFalse")
        && let Some(arg) = args.last()
    {
        let text_of_arg = node_text(*arg, source).trim();
        let constant_truth = (name == "assertTrue" && text_of_arg == "true")
            || (name == "assertFalse" && text_of_arg == "false");
        if constant_truth {
            score += weights.constant_truth_weight;
            reason = KIND_CONSTANT_TRUTH.to_string();
            kind = KIND_CONSTANT_TRUTH.to_string();
        }
    }

    if (name == "assertEquals" || name == "assertSame") && args.len() >= 2 {
        let expected = args[0];
        let actual = args[1];
        if is_constant_kotlin_expression(expected) && is_constant_kotlin_expression(actual) {
            score += weights.constant_equality_weight;
            reason = KIND_CONSTANT_EQUALITY.to_string();
            kind = KIND_CONSTANT_EQUALITY.to_string();
        } else if same_kotlin_expression(expected, actual, source) {
            score += weights.tautological_assertion_weight;
            reason = KIND_SELF_COMPARISON.to_string();
            kind = KIND_SELF_COMPARISON.to_string();
        }
    }

    if (name == "assertNull" || name == "assertNotNull") && args.len() <= 2 {
        score += weights.nullness_only_weight;
        reason = KIND_NULLNESS_ONLY.to_string();
        kind = KIND_NULLNESS_ONLY.to_string();
    }

    if contains_overspecified_kotlin_literal(&args, source, weights) {
        score += weights.overspecified_literal_weight;
        reason = KIND_OVERSPECIFIED_LITERAL.to_string();
        kind = KIND_OVERSPECIFIED_LITERAL.to_string();
    }

    KotlinAssertionSignal {
        kind,
        score,
        shallow,
        reason,
        excerpt: text.to_string(),
        start_byte: call.start_byte(),
    }
}

fn kotlin_infix_assertion_signal(
    infix: Node<'_>,
    source: &str,
    weights: &TestAssertionWeights,
) -> Option<KotlinAssertionSignal> {
    let children = named_children(infix);
    let [left, operator, right] = children.as_slice() else {
        return None;
    };
    if operator.kind() != "simple_identifier" {
        return None;
    }
    let name = kotlin_identifier_text(*operator, source);
    if !KOTEST_SHOULD_INFIX.contains(&name) {
        return None;
    }
    let text = compact_kotlin_excerpt(node_text(infix, source));

    let (mut kind, mut score) = if same_kotlin_expression(*left, *right, source) {
        if is_constant_kotlin_expression(*right) {
            (KIND_CONSTANT_EQUALITY, weights.constant_equality_weight)
        } else {
            (KIND_SELF_COMPARISON, weights.tautological_assertion_weight)
        }
    } else if is_constant_kotlin_expression(*left) && is_constant_kotlin_expression(*right) {
        (KIND_CONSTANT_EQUALITY, weights.constant_equality_weight)
    } else {
        (KIND_MEANINGFUL, 0)
    };

    if is_overspecified_kotlin_literal(*left, source, weights)
        || is_overspecified_kotlin_literal(*right, source, weights)
    {
        score += weights.overspecified_literal_weight;
        kind = KIND_OVERSPECIFIED_LITERAL;
    }

    Some(KotlinAssertionSignal {
        kind: kind.to_string(),
        score,
        shallow: false,
        reason: kind.to_string(),
        excerpt: text,
        start_byte: infix.start_byte(),
    })
}

/// Nodes of `kind` anywhere in `root`'s subtree (root included), walked
/// iteratively rather than recursively so a deeply nested test body cannot
/// blow the stack.
fn collect_nodes_by_kind<'tree>(root: Node<'tree>, kind: &str, out: &mut Vec<Node<'tree>>) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == kind {
            out.push(node);
        }
        stack.extend(named_children(node));
    }
}

fn kotlin_call_argument_exprs(call: Node<'_>) -> Vec<Node<'_>> {
    let Some(call_suffix) = named_children(call)
        .into_iter()
        .find(|child| child.kind() == "call_suffix")
    else {
        return Vec::new();
    };
    let Some(value_arguments) = named_children(call_suffix)
        .into_iter()
        .find(|child| child.kind() == "value_arguments")
    else {
        return Vec::new();
    };
    named_children(value_arguments)
        .into_iter()
        .filter(|child| child.kind() == "value_argument")
        .filter_map(kotlin_value_argument_expr)
        .collect()
}

/// The value expression a `value_argument` carries, skipping the label of a
/// named argument (`foo(name = 1)`).
fn kotlin_value_argument_expr(argument: Node<'_>) -> Option<Node<'_>> {
    named_children(argument)
        .into_iter()
        .find(|child| !kotlin_named_argument_label(argument, *child))
}

fn is_constant_kotlin_expression(node: Node<'_>) -> bool {
    match node.kind() {
        "string_literal" => !named_children(node).into_iter().any(|child| {
            matches!(
                child.kind(),
                "interpolated_expression" | "interpolated_identifier"
            )
        }),
        kind => KOTLIN_CONSTANT_LITERAL_KINDS.contains(&kind),
    }
}

fn same_kotlin_expression(left: Node<'_>, right: Node<'_>, source: &str) -> bool {
    node_text(left, source).trim() == node_text(right, source).trim()
}

fn contains_overspecified_kotlin_literal(
    args: &[Node<'_>],
    source: &str,
    weights: &TestAssertionWeights,
) -> bool {
    args.iter()
        .any(|arg| is_overspecified_kotlin_literal(*arg, source, weights))
}

fn is_overspecified_kotlin_literal(
    node: Node<'_>,
    source: &str,
    weights: &TestAssertionWeights,
) -> bool {
    let threshold = weights.large_literal_length_threshold.max(0) as usize;
    node.kind() == "string_literal" && node_text(node, source).len() >= threshold
}

fn compact_kotlin_excerpt(text: &str) -> String {
    let compact = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.chars().count() <= TEST_ASSERTION_EXCERPT_MAX_LEN {
        return compact;
    }
    let mut truncated: String = compact
        .chars()
        .take(TEST_ASSERTION_EXCERPT_MAX_LEN)
        .collect();
    truncated.push_str("...");
    truncated
}
