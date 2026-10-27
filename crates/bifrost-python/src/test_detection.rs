use crate::declarations::py_node_text;
use crate::syntax::{decorator_callee, python_static_attribute_path};
use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::model::{TestAssertionSmell, TestAssertionWeights};
use brokk_bifrost_core::analyzer::test_assertions::{
    CommonTestAssertionKind, TestAssertionSignal, append_test_assertion_findings,
    classify_common_test_assertion, compact_assertion_excerpt,
};
use brokk_bifrost_core::analyzer::tree_walk::{
    WalkControl, walk_named_tree_preorder, walk_tree_preorder,
};
use tree_sitter::Node;

const TEST_ASSERTION_EXCERPT_MAX_LEN: usize = 180;

struct PythonTestCase<'tree> {
    name: String,
    definition: Node<'tree>,
    body: Node<'tree>,
}

pub fn detect_python_test_assertion_smells(
    file: &ProjectFile,
    source: &str,
    weights: &TestAssertionWeights,
) -> Vec<TestAssertionSmell> {
    let Some(tree) = crate::declarations::parse_python_tree(source) else {
        return Vec::new();
    };
    let mut test_cases = Vec::new();
    collect_python_test_cases(tree.root_node(), source, &mut test_cases);
    let mut findings = Vec::new();
    for test_case in test_cases {
        analyze_python_test_case(file, &test_case, source, weights, &mut findings);
    }
    findings
}

fn collect_python_test_cases<'tree>(
    node: Node<'tree>,
    source: &str,
    out: &mut Vec<PythonTestCase<'tree>>,
) {
    walk_named_tree_preorder(node, true, |current| {
        if current.kind() != "function_definition" {
            return WalkControl::Continue;
        }
        let mut marked = false;
        if let Some(parent) = current
            .parent()
            .filter(|p| p.kind() == "decorated_definition")
        {
            let mut cursor = parent.walk();
            for decorator in parent
                .named_children(&mut cursor)
                .filter(|n| n.kind() == "decorator")
            {
                let Some(path) = decorator_callee(decorator).and_then(python_static_attribute_path)
                else {
                    continue;
                };
                let names: Vec<_> = path.iter().map(|n| py_node_text(*n, source)).collect();
                if names == ["pytest", "fixture"] {
                    return WalkControl::SkipChildren;
                }
                marked |= names.len() >= 3 && names[..2] == ["pytest", "mark"];
            }
        }
        if let (Some(name), Some(body)) = (
            current.child_by_field_name("name"),
            current.child_by_field_name("body"),
        ) {
            let name = py_node_text(name, source);
            if name.starts_with("test_") || marked {
                out.push(PythonTestCase {
                    name: name.to_string(),
                    definition: current,
                    body,
                });
            }
        }
        WalkControl::Continue
    });
}

pub fn python_tree_contains_tests(root: Node<'_>, source: &str) -> bool {
    let mut test_cases = Vec::new();
    collect_python_test_cases(root, source, &mut test_cases);
    !test_cases.is_empty()
}

fn analyze_python_test_case(
    file: &ProjectFile,
    test_case: &PythonTestCase<'_>,
    source: &str,
    weights: &TestAssertionWeights,
    out: &mut Vec<TestAssertionSmell>,
) {
    let assertions = collect_python_assertions(test_case.body, source, weights);
    append_test_assertion_findings(
        file,
        format!("{}::{}", file, test_case.name),
        compact_assertion_excerpt(
            py_node_text(test_case.body, source),
            TEST_ASSERTION_EXCERPT_MAX_LEN,
        ),
        test_case.definition.start_byte(),
        &assertions,
        weights,
        out,
    );
}

fn collect_python_assertions(
    body: Node<'_>,
    source: &str,
    weights: &TestAssertionWeights,
) -> Vec<TestAssertionSignal> {
    let mut assertions = Vec::new();
    walk_named_tree_preorder(body, true, |node| {
        if matches!(
            node.kind(),
            "function_definition" | "class_definition" | "lambda" | "string" | "comment"
        ) {
            return WalkControl::SkipChildren;
        }
        let mut operands = None;
        let kind = if node.kind() == "assert_statement" {
            let Some(expr) = node.named_child(0).map(unparenthesized) else {
                return WalkControl::Continue;
            };
            match expr.kind() {
                "true" | "false" => Some(CommonTestAssertionKind::ConstantTruth),
                "comparison_operator" if expr.named_child_count() == 2 => {
                    let left = expr.named_child(0).unwrap();
                    let right = expr.named_child(1).unwrap();
                    let operator = expr
                        .child_by_field_name("operators")
                        .expect("comparison has an operator");
                    match operator.kind() {
                        "==" => {
                            operands = Some((left, right));
                            Some(CommonTestAssertionKind::Meaningful)
                        }
                        "is" | "is not" if unparenthesized(right).kind() == "none" => {
                            Some(CommonTestAssertionKind::NullnessOnly)
                        }
                        _ => Some(CommonTestAssertionKind::Meaningful),
                    }
                }
                _ => Some(CommonTestAssertionKind::Meaningful),
            }
        } else if node.kind() == "call" {
            let function = node
                .child_by_field_name("function")
                .expect("call has a function");
            if function.kind() == "attribute"
                && function
                    .child_by_field_name("attribute")
                    .is_some_and(|name| {
                        matches!(
                            py_node_text(name, source),
                            "assert_called"
                                | "assert_called_once"
                                | "assert_called_once_with"
                                | "assert_called_with"
                                | "assert_not_called"
                        )
                    })
            {
                Some(CommonTestAssertionKind::Meaningful)
            } else {
                let Some(path) = python_static_attribute_path(function) else {
                    return WalkControl::Continue;
                };
                let names: Vec<_> = path.iter().map(|n| py_node_text(*n, source)).collect();
                let arguments = node
                    .child_by_field_name("arguments")
                    .expect("call has arguments");
                let mut cursor = arguments.walk();
                let args: Vec<_> = arguments
                    .named_children(&mut cursor)
                    .filter(|n| !n.is_extra())
                    .collect();
                match names.as_slice() {
                    ["self", "assertEqual" | "assertIs"] if args.len() >= 2 => {
                        operands = Some((args[0], args[1]));
                        Some(CommonTestAssertionKind::Meaningful)
                    }
                    ["self", "assertTrue"]
                        if args
                            .first()
                            .is_some_and(|n| unparenthesized(*n).kind() == "true") =>
                    {
                        Some(CommonTestAssertionKind::ConstantTruth)
                    }
                    ["self", "assertFalse"]
                        if args
                            .first()
                            .is_some_and(|n| unparenthesized(*n).kind() == "false") =>
                    {
                        Some(CommonTestAssertionKind::ConstantTruth)
                    }
                    ["self", "assertIsNone" | "assertIsNotNone"] => {
                        Some(CommonTestAssertionKind::NullnessOnly)
                    }
                    ["self", "assertTrue" | "assertFalse" | "assertRaises"]
                    | ["pytest", "raises"] => Some(CommonTestAssertionKind::Meaningful),
                    _ => None,
                }
            }
        } else {
            None
        };
        let Some(mut kind) = kind else {
            return WalkControl::Continue;
        };
        let mut oversized = None;
        if let Some((left, right)) = operands {
            if normalize_python_expr(left, source) == normalize_python_expr(right, source) {
                kind = if is_python_literal(unparenthesized(left)) {
                    CommonTestAssertionKind::ConstantEquality
                } else {
                    CommonTestAssertionKind::SelfComparison
                };
            } else {
                oversized = oversized_python_literal(left, right, source, weights);
            }
        }
        let classification = classify_common_test_assertion(kind, weights);
        let (kind, score, shallow, meaningful, reasons) = if let Some(literal) = oversized {
            (
                "overspecified-literal",
                weights.overspecified_literal_weight,
                false,
                false,
                vec![format!("overspecified-literal:{literal}")],
            )
        } else {
            (
                classification.kind,
                classification.score,
                classification.shallow,
                classification.score == 0,
                vec![classification.kind.to_string()],
            )
        };
        assertions.push(TestAssertionSignal {
            kind: kind.to_string(),
            score,
            shallow,
            meaningful,
            reasons,
            excerpt: compact_assertion_excerpt(
                py_node_text(node, source),
                TEST_ASSERTION_EXCERPT_MAX_LEN,
            ),
            start_byte: node.start_byte(),
        });
        WalkControl::SkipChildren
    });
    assertions
}

fn unparenthesized(mut node: Node<'_>) -> Node<'_> {
    while node.kind() == "parenthesized_expression" {
        let mut cursor = node.walk();
        node = node
            .named_children(&mut cursor)
            .find(|child| !child.is_extra())
            .expect("parenthesized expression has an operand");
    }
    node
}

// Compare grammar-selected tokens. Whitespace in string contents remains data;
// comments and grouping parentheses do not change expression identity.
fn normalize_python_expr<'source>(
    node: Node<'_>,
    source: &'source str,
) -> Vec<(u16, &'source str)> {
    let mut tokens = Vec::new();
    walk_tree_preorder(node, true, |current| {
        if current.is_extra() {
            return WalkControl::SkipChildren;
        }
        if current.child_count() == 0
            && !current
                .parent()
                .is_some_and(|p| p.kind() == "parenthesized_expression" && !current.is_named())
        {
            tokens.push((current.kind_id(), py_node_text(current, source)));
        }
        WalkControl::Continue
    });
    tokens
}

fn is_python_literal(node: Node<'_>) -> bool {
    match node.kind() {
        "integer" | "float" | "true" | "false" | "none" => true,
        "unary_operator" => {
            node.child_by_field_name("operator")
                .is_some_and(|operator| matches!(operator.kind(), "+" | "-"))
                && node
                    .child_by_field_name("argument")
                    .is_some_and(|argument| {
                        matches!(unparenthesized(argument).kind(), "integer" | "float")
                    })
        }
        "string" => {
            let mut cursor = node.walk();
            !node
                .named_children(&mut cursor)
                .any(|child| child.kind() == "interpolation")
        }
        _ => false,
    }
}

fn oversized_python_literal<'source>(
    left: Node<'_>,
    right: Node<'_>,
    source: &'source str,
    weights: &TestAssertionWeights,
) -> Option<&'source str> {
    [left, right]
        .into_iter()
        .map(unparenthesized)
        .find_map(|node| {
            if node.kind() != "string" {
                return None;
            }
            let mut length = 0;
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                match child.kind() {
                    "interpolation" => return None,
                    "string_content" => length += child.end_byte() - child.start_byte(),
                    _ => {}
                }
            }
            (length >= weights.large_literal_length_threshold.max(0) as usize)
                .then(|| py_node_text(node, source))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon(
        "6e62e856da86: source scans counted assertion lookalikes and lost operand boundaries"
    )]
    fn qs6_assertion_syntax_ignores_strings_and_nested_definitions() {
        let source = "# \u{e9}\n@pytest.mark.slow\ndef test_marked():\n    self.assertEqual((one, two), (one, two))\ndef test_strings():\n    text = '''\n    assert True\n    self.assertEqual(1, 1)\n    '''\n    # self.assertTrue(True)\n    def helper():\n        assert False\ndef test_fixture_text():\n    text = '@pytest.fixture'\n    assert True\n@pytest.fixture\ndef test_fixture():\n    assert True\n";
        let file = ProjectFile::new(std::env::temp_dir(), "test_sample.py");
        let findings =
            detect_python_test_assertion_smells(&file, source, &TestAssertionWeights::defaults());
        let actual: Vec<_> = findings
            .iter()
            .map(|f| {
                (
                    f.enclosing_fq_name.rsplit("::").next().unwrap(),
                    f.assertion_kind.as_str(),
                    f.start_byte,
                )
            })
            .collect();
        assert_eq!(
            actual,
            vec![
                (
                    "test_marked",
                    "self-comparison",
                    source.find("self.assertEqual").unwrap()
                ),
                (
                    "test_strings",
                    "no-assertions",
                    source.find("def test_strings").unwrap()
                ),
                (
                    "test_fixture_text",
                    "constant-truth",
                    source.rfind("    assert True\n@pytest.fixture").unwrap() + 4
                ),
                (
                    "test_fixture_text",
                    "shallow-assertions-only",
                    source.find("def test_fixture_text").unwrap()
                ),
            ]
        );
    }
}
