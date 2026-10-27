use super::model::node_text;
use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::common::collapse_whitespace;
use brokk_bifrost_core::analyzer::model::{TestAssertionSmell, TestAssertionWeights};
use brokk_bifrost_core::analyzer::test_assertions::{
    CommonTestAssertionKind, TestAssertionSignal, append_test_assertion_findings,
    classify_common_test_assertion, oversized_quoted_literal,
};
use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, walk_named_tree_preorder};
use tree_sitter::{Language as TsLanguage, Node, Parser};

struct JsTsTestCase<'tree> {
    name: String,
    callback: Node<'tree>,
    start_byte: usize,
}

pub fn detect_js_ts_test_assertion_smells(
    file: &ProjectFile,
    source: &str,
    parser_language: TsLanguage,
    weights: &TestAssertionWeights,
) -> Vec<TestAssertionSmell> {
    let mut parser = Parser::new();
    parser
        .set_language(&parser_language)
        .expect("failed to set js/ts parser language");
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let mut test_cases = Vec::new();
    collect_js_ts_test_cases(tree.root_node(), source, &mut test_cases);

    let mut findings = Vec::new();
    for test_case in test_cases {
        analyze_js_ts_test_case(file, &test_case, source, weights, &mut findings);
    }
    findings
}

fn collect_js_ts_test_cases<'tree>(
    root: Node<'tree>,
    source: &str,
    out: &mut Vec<JsTsTestCase<'tree>>,
) {
    walk_named_tree_preorder(root, true, |node| {
        if node.kind() == "call_expression"
            && is_js_ts_test_invocation(node, source)
            && let Some(arguments) = node.child_by_field_name("arguments")
        {
            let mut name: Option<String> = None;
            let mut callback: Option<Node<'_>> = None;
            let mut cursor = arguments.walk();
            for child in arguments.named_children(&mut cursor) {
                match child.kind() {
                    "string" | "template_string" if name.is_none() => {
                        name = Some(trim_js_ts_string_literal(node_text(child, source)));
                    }
                    "arrow_function" | "function" | "generator_function" => {
                        callback = Some(child);
                    }
                    _ => {}
                }
            }
            if let Some(callback) = callback {
                out.push(JsTsTestCase {
                    name: name.unwrap_or_else(|| "anonymous".to_string()),
                    callback,
                    start_byte: node.start_byte(),
                });
            }
        }

        WalkControl::Continue
    });
}

fn is_js_ts_test_invocation(node: Node<'_>, source: &str) -> bool {
    let Some(function) = node.child_by_field_name("function") else {
        return false;
    };
    match function.kind() {
        "identifier" => is_js_ts_test_root(function, source),
        "member_expression" => {
            let Some(object) = function.child_by_field_name("object") else {
                return false;
            };
            let Some(property) = function.child_by_field_name("property") else {
                return false;
            };
            match node_text(property, source).trim() {
                "only" | "skip" | "each" => is_js_ts_test_root(object, source),
                // A subtest (`t.test(name, fn)` in node:test and tap) passes a
                // callback; a RegExp `pattern.test(text)` never does.
                "test" | "it" => call_passes_callback(node),
                _ => false,
            }
        }
        "call_expression" => {
            let Some(factory) = function.child_by_field_name("function") else {
                return false;
            };
            if factory.kind() != "member_expression" {
                return false;
            }
            let Some(object) = factory.child_by_field_name("object") else {
                return false;
            };
            let Some(property) = factory.child_by_field_name("property") else {
                return false;
            };
            is_js_ts_test_root(object, source) && node_text(property, source).trim() == "each"
        }
        _ => false,
    }
}

fn call_passes_callback(call: Node<'_>) -> bool {
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = arguments.walk();
    arguments.named_children(&mut cursor).any(|child| {
        matches!(
            child.kind(),
            "arrow_function" | "function" | "generator_function"
        )
    })
}

fn is_js_ts_test_root(node: Node<'_>, source: &str) -> bool {
    let mut current = node;
    loop {
        match current.kind() {
            "identifier" => {
                return matches!(node_text(current, source).trim(), "it" | "test");
            }
            "member_expression" => {
                let Some(object) = current.child_by_field_name("object") else {
                    return false;
                };
                current = object;
            }
            _ => return false,
        }
    }
}

fn analyze_js_ts_test_case(
    file: &ProjectFile,
    test_case: &JsTsTestCase<'_>,
    source: &str,
    weights: &TestAssertionWeights,
    out: &mut Vec<TestAssertionSmell>,
) {
    let body = test_case
        .callback
        .child_by_field_name("body")
        .unwrap_or(test_case.callback);
    let assertions = collect_js_ts_assertions(body, source, weights);
    append_test_assertion_findings(
        file,
        format!("{}::{}", file, test_case.name),
        collapse_whitespace(node_text(body, source)),
        test_case.start_byte,
        &assertions,
        weights,
        out,
    );
}

fn collect_js_ts_assertions(
    body: Node<'_>,
    source: &str,
    weights: &TestAssertionWeights,
) -> Vec<TestAssertionSignal> {
    let mut assertions = Vec::new();
    walk_named_tree_preorder(body, true, |node| {
        if node.kind() == "call_expression"
            && let Some(assertion) = js_ts_assertion_signal(node, source, weights)
        {
            assertions.push(assertion);
        }
        // Helper arrows inside a test retain their assertions. String and
        // comment contents are never interpreted as calls.
        WalkControl::Continue
    });
    assertions
}

fn js_ts_assertion_signal(
    call: Node<'_>,
    source: &str,
    weights: &TestAssertionWeights,
) -> Option<TestAssertionSignal> {
    let function = call.child_by_field_name("function")?;
    if function.kind() != "member_expression" {
        return None;
    }
    let matcher = node_text(function.child_by_field_name("property")?, source);
    let mut object = function.child_by_field_name("object")?;
    while object.kind() == "member_expression" {
        let modifier = object.child_by_field_name("property")?;
        if !matches!(node_text(modifier, source), "not" | "resolves" | "rejects") {
            return None;
        }
        object = object.child_by_field_name("object")?;
    }
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    let mut args = arguments
        .named_children(&mut cursor)
        .filter(|n| !n.is_extra());
    let (root, actual, expected) = match object.kind() {
        "call_expression" => {
            let callee = object.child_by_field_name("function")?;
            if callee.kind() != "identifier" || node_text(callee, source) != "expect" {
                return None;
            }
            let actual_args = object.child_by_field_name("arguments")?;
            let mut actual_cursor = actual_args.walk();
            let actual = actual_args
                .named_children(&mut actual_cursor)
                .find(|n| !n.is_extra())?;
            ("expect", actual, args.next())
        }
        "identifier" if node_text(object, source) == "assert" => {
            ("assert", args.next()?, args.next())
        }
        _ => return None,
    };

    let mut operands = None;
    let mut kind = match (root, matcher) {
        ("expect", "toBe" | "toEqual" | "toStrictEqual")
        | ("assert", "strictEqual" | "equal" | "deepEqual") => {
            operands = Some((actual, expected?));
            CommonTestAssertionKind::Meaningful
        }
        ("expect", "toBeTruthy") | ("assert", "ok" | "isTrue") if actual.kind() == "true" => {
            CommonTestAssertionKind::ConstantTruth
        }
        ("expect", "toBeFalsy") | ("assert", "isFalse") if actual.kind() == "false" => {
            CommonTestAssertionKind::ConstantTruth
        }
        ("expect", "toBeNull" | "toBeUndefined" | "toBeDefined")
        | ("assert", "isNotNull" | "isNull") => CommonTestAssertionKind::NullnessOnly,
        ("expect", "toBeTruthy" | "toBeFalsy") => CommonTestAssertionKind::Meaningful,
        (
            "expect",
            "toThrow"
            | "toThrowError"
            | "toHaveBeenCalled"
            | "toHaveBeenCalledTimes"
            | "toHaveBeenCalledWith"
            | "toMatchSnapshot"
            | "toMatchInlineSnapshot",
        )
        | ("assert", "ok" | "isTrue" | "isFalse") => CommonTestAssertionKind::Meaningful,
        _ => return None,
    };
    let mut oversized = None;
    if let Some((left, right)) = operands {
        if js_ts_operands_equal(left, right, source) {
            kind = if is_js_ts_literal(left, source) {
                CommonTestAssertionKind::ConstantEquality
            } else {
                CommonTestAssertionKind::SelfComparison
            };
        } else {
            // Only selected string literal nodes can supply a large literal.
            let literal_text = |node: Node<'_>| {
                if node.kind() == "string" {
                    node_text(node, source)
                } else {
                    ""
                }
            };
            oversized = oversized_quoted_literal(
                literal_text(left),
                literal_text(right),
                weights,
                &['"', '\''],
            );
        }
    }
    let classification = classify_common_test_assertion(kind, weights);
    let (kind, score, shallow, meaningful, reason) = if let Some(literal) = oversized {
        (
            "overspecified-literal",
            weights.overspecified_literal_weight,
            false,
            false,
            format!("overspecified-literal:{literal}"),
        )
    } else if root == "expect" && matches!(matcher, "toMatchSnapshot" | "toMatchInlineSnapshot") {
        (
            "snapshot-assertion",
            weights.overspecified_literal_weight,
            false,
            false,
            "snapshot-assertion".to_string(),
        )
    } else if root == "expect"
        && matches!(matcher, "toBeTruthy" | "toBeFalsy")
        && matches!(kind, CommonTestAssertionKind::Meaningful)
    {
        (
            "shallow-assertion",
            0,
            true,
            false,
            "shallow-assertion".to_string(),
        )
    } else {
        (
            classification.kind,
            classification.score,
            classification.shallow,
            matches!(kind, CommonTestAssertionKind::Meaningful)
                || (root == "assert" && operands.is_none() && classification.score == 0),
            classification.kind.to_string(),
        )
    };
    Some(TestAssertionSignal {
        kind: kind.to_string(),
        score,
        shallow,
        meaningful,
        reasons: vec![reason],
        excerpt: collapse_whitespace(node_text(call, source)),
        start_byte: call.start_byte(),
    })
}

// Compare tree shape and leaf tokens, including punctuation and string data.
// Formatting and comments between tokens do not change expression identity.
fn js_ts_operands_equal(left: Node<'_>, right: Node<'_>, source: &str) -> bool {
    let mut pending = vec![(left, right)];
    while let Some((left, right)) = pending.pop() {
        if left.kind() != right.kind() {
            return false;
        }
        if left.child_count() == 0 && right.child_count() == 0 {
            if node_text(left, source) != node_text(right, source) {
                return false;
            }
            continue;
        }
        let mut left_cursor = left.walk();
        let mut right_cursor = right.walk();
        let mut left_children = left.children(&mut left_cursor).filter(|n| !n.is_extra());
        let mut right_children = right.children(&mut right_cursor).filter(|n| !n.is_extra());
        loop {
            match (left_children.next(), right_children.next()) {
                (Some(left), Some(right)) => pending.push((left, right)),
                (None, None) => break,
                _ => return false,
            }
        }
    }
    true
}

fn is_js_ts_literal(node: Node<'_>, source: &str) -> bool {
    match node.kind() {
        "string" | "number" | "true" | "false" | "null" | "undefined" => true,
        "identifier" => node_text(node, source) == "undefined",
        "unary_expression" => {
            node.child_by_field_name("operator")
                .is_some_and(|operator| matches!(node_text(operator, source), "+" | "-"))
                && node
                    .child_by_field_name("argument")
                    .is_some_and(|argument| argument.kind() == "number")
        }
        _ => false,
    }
}

fn trim_js_ts_string_literal(raw: &str) -> String {
    raw.trim()
        .trim_matches('`')
        .trim_matches('"')
        .trim_matches('\'')
        .to_string()
}
