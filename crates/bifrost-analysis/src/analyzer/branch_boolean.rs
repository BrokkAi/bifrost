//! Exact Boolean return outcomes for two immediate conditional arms.
//!
//! This is a syntax fact, not an autofix decision. Replacing the condition with
//! a returned expression would additionally need Boolean type, conversion,
//! operator and evaluation evidence that this classifier does not claim.

use brokk_bifrost_core::analyzer::Language;
use tree_sitter::Node;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BooleanBranchOutcome {
    /// The first arm returns true and the second returns false.
    Condition,
    /// The first arm returns false and the second returns true.
    NegatedCondition,
}

/// Classify the immediate true and false statement bodies of one conditional.
///
/// The caller owns branch pairing, including a same-block fall-through return,
/// and must pass the body of the true arm first.
/// This function refuses nested conditionals, additional statements, computed
/// values, parse errors, and languages whose grammar has not been reviewed.
pub fn classify_boolean_branches(
    language: Language,
    true_body: Node<'_>,
    false_body: Node<'_>,
) -> Option<BooleanBranchOutcome> {
    let first = returned_boolean(language, true_body)?;
    let second = returned_boolean(language, false_body)?;
    match (first, second) {
        (true, false) => Some(BooleanBranchOutcome::Condition),
        (false, true) => Some(BooleanBranchOutcome::NegatedCondition),
        _ => None,
    }
}

fn returned_boolean(language: Language, mut body: Node<'_>) -> Option<bool> {
    let block_kind = match language {
        Language::Java => "block",
        Language::JavaScript | Language::TypeScript => "statement_block",
        Language::Python => "block",
        _ => return None,
    };
    if body.has_error() || body.is_missing() {
        return None;
    }
    while body.kind() == block_kind {
        body = single_runtime_named_child(body)?;
    }
    if body.kind() != "return_statement" || body.has_error() {
        return None;
    }
    let mut expression = single_runtime_named_child(body)?;
    while expression.kind() == "parenthesized_expression" {
        expression = single_runtime_named_child(expression)?;
    }
    if expression.has_error() || expression.is_missing() {
        return None;
    }
    match expression.kind() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn single_runtime_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    let mut children = node
        .named_children(&mut cursor)
        .filter(|child| !child.is_extra());
    let only = children.next()?;
    children.next().is_none().then_some(only)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn classify(language: Language, source: &str) -> Option<BooleanBranchOutcome> {
        let grammar = match language {
            Language::Java => tree_sitter_java::LANGUAGE.into(),
            Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
            Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Language::Python => tree_sitter_python::LANGUAGE.into(),
            _ => unreachable!(),
        };
        let mut parser = Parser::new();
        parser.set_language(&grammar).expect("supported grammar");
        let tree = parser.parse(source, None).expect("parsed source");
        assert!(!tree.root_node().has_error(), "{source}");
        let mut pending = vec![tree.root_node()];
        while let Some(node) = pending.pop() {
            if node.kind() == "if_statement" {
                let first = node.child_by_field_name("consequence").expect("true arm");
                let alternative = node.child_by_field_name("alternative").expect("false arm");
                let second = if alternative.kind() == "else_clause" {
                    alternative.named_child(0).expect("else body")
                } else {
                    alternative
                };
                return classify_boolean_branches(language, first, second);
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
        panic!("no if statement in {source}");
    }

    #[test]
    fn exact_boolean_return_arms_across_pilot_languages() {
        for (language, source, expected) in [
            (
                Language::Java,
                "class C { boolean f(boolean x) { if (x) { return true; } else { return false; } } }",
                BooleanBranchOutcome::Condition,
            ),
            (
                Language::Java,
                "class C { boolean f(boolean x) { if (x) { /* why */ { return (((true))); } } else return false; } }",
                BooleanBranchOutcome::Condition,
            ),
            (
                Language::JavaScript,
                "function f(x) { if (x) return false; else return true; }",
                BooleanBranchOutcome::NegatedCondition,
            ),
            (
                Language::TypeScript,
                "function f(x: unknown) { if (x) { return (true); } else { return (false); } }",
                BooleanBranchOutcome::Condition,
            ),
            (
                Language::Python,
                "def f(x):\n    if x:\n        return True\n    else:\n        return False\n",
                BooleanBranchOutcome::Condition,
            ),
        ] {
            assert_eq!(classify(language, source), Some(expected), "{source}");
        }
    }

    #[test]
    fn other_branch_work_is_not_a_boolean_return_pair() {
        for (language, source) in [
            (
                Language::Java,
                "class C { boolean f(boolean x) { if (x) { log(); return true; } else { return false; } } void log() {} }",
            ),
            (
                Language::JavaScript,
                "function f(x) { if (x) { return true; } else { return true; } }",
            ),
            (
                Language::TypeScript,
                "function f(x: unknown) { if (x) { return Boolean(x); } else { return false; } }",
            ),
            (
                Language::Python,
                "def f(x):\n    if x:\n        return True\n    else:\n        return bool(x)\n",
            ),
        ] {
            assert_eq!(classify(language, source), None, "{source}");
        }
    }
}
