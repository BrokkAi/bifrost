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
///
/// Go's `true` and `false` are predeclared names that a program could
/// shadow; they are read as the literals, which every real program means.
pub fn classify_boolean_branches(
    language: Language,
    source: &str,
    true_body: Node<'_>,
    false_body: Node<'_>,
) -> Option<BooleanBranchOutcome> {
    let first = returned_boolean(language, source, true_body)?;
    let second = returned_boolean(language, source, false_body)?;
    match (first, second) {
        (true, false) => Some(BooleanBranchOutcome::Condition),
        (false, true) => Some(BooleanBranchOutcome::NegatedCondition),
        _ => None,
    }
}

fn returned_boolean(language: Language, source: &str, mut body: Node<'_>) -> Option<bool> {
    // Wrappers that hold exactly one statement without changing it.
    let wrappers: &[&str] = match language {
        Language::Java | Language::Python | Language::CSharp => &["block"],
        Language::JavaScript | Language::TypeScript => &["statement_block"],
        Language::Go => &["block", "statement_list"],
        Language::Kotlin => &["control_structure_body", "block", "statements"],
        Language::Rust => &["block", "expression_statement"],
        Language::Scala => &["block", "indented_block"],
        Language::Php => &["compound_statement", "colon_block"],
        Language::Cpp => &["compound_statement"],
        Language::Ruby => &["then", "else"],
        _ => return None,
    };
    if body.has_error() || body.is_missing() {
        return None;
    }
    while wrappers.contains(&body.kind()) {
        body = single_runtime_named_child(body)?;
    }
    if body.has_error() {
        return None;
    }
    let mut expression = match language {
        // A labeled `return@label` can leave a different function than a
        // plain `return`, so only the unlabeled form pairs.
        Language::Kotlin => {
            if body.kind() != "jump_expression" || body.child(0)?.kind() != "return" {
                return None;
            }
            single_runtime_named_child(body)?
        }
        Language::Ruby => {
            if body.kind() != "return" {
                return None;
            }
            let arguments = single_runtime_named_child(body)?;
            if arguments.kind() != "argument_list" {
                return None;
            }
            single_runtime_named_child(arguments)?
        }
        Language::Rust | Language::Scala => {
            if body.kind() != "return_expression" {
                return None;
            }
            single_runtime_named_child(body)?
        }
        Language::Go => {
            if body.kind() != "return_statement" {
                return None;
            }
            let values = single_runtime_named_child(body)?;
            if values.kind() != "expression_list" {
                return None;
            }
            single_runtime_named_child(values)?
        }
        _ => {
            if body.kind() != "return_statement" {
                return None;
            }
            single_runtime_named_child(body)?
        }
    };
    while expression.kind() == "parenthesized_expression" {
        expression = single_runtime_named_child(expression)?;
    }
    if expression.has_error() || expression.is_missing() {
        return None;
    }
    let literal = match expression.kind() {
        "boolean_literal" => source.get(expression.byte_range())?,
        // PHP spells `true` and `false` case-insensitively.
        "boolean" => &source.get(expression.byte_range())?.to_ascii_lowercase(),
        kind => kind,
    };
    match literal {
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
            Language::CSharp => tree_sitter_c_sharp::LANGUAGE.into(),
            Language::Go => tree_sitter_go::LANGUAGE.into(),
            Language::Kotlin => crate::analyzer::kotlin::language::LANGUAGE.into(),
            Language::Php => tree_sitter_php::LANGUAGE_PHP.into(),
            _ => unreachable!(),
        };
        let mut parser = Parser::new();
        parser.set_language(&grammar).expect("supported grammar");
        let tree = parser.parse(source, None).expect("parsed source");
        assert!(!tree.root_node().has_error(), "{source}");
        let mut pending = vec![tree.root_node()];
        while let Some(node) = pending.pop() {
            if matches!(node.kind(), "if_statement" | "if_expression") {
                let first = node
                    .child_by_field_name(
                        crate::analyzer::structural::branch_relations::consequence_field(language),
                    )
                    .expect("true arm");
                let alternative = node.child_by_field_name("alternative").expect("false arm");
                let second = if alternative.kind() == "else_clause" {
                    alternative.named_child(0).expect("else body")
                } else {
                    alternative
                };
                return classify_boolean_branches(language, source, first, second);
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
            (
                Language::CSharp,
                "class C { bool F(bool x) { if (x) { return true; } else return (false); } }",
                BooleanBranchOutcome::Condition,
            ),
            (
                Language::Go,
                "package p\n\nfunc f(x bool) bool {\n\tif x {\n\t\treturn false\n\t} else {\n\t\treturn true\n\t}\n}\n",
                BooleanBranchOutcome::NegatedCondition,
            ),
            (
                Language::Kotlin,
                "fun f(x: Boolean): Boolean {\n    if (x) { return true } else return false\n}\n",
                BooleanBranchOutcome::Condition,
            ),
            (
                Language::Php,
                "<?php\nfunction f($x) {\n    if ($x) {\n        return TRUE;\n    } else {\n        return false;\n    }\n}\n",
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
            (
                Language::CSharp,
                "class C { bool F(bool x) { if (x) { G(); return true; } else { return false; } } void G() {} }",
            ),
            (
                Language::Go,
                "package p\n\nfunc f(x bool) (bool, error) {\n\tif x {\n\t\treturn true, nil\n\t} else {\n\t\treturn false, nil\n\t}\n}\n",
            ),
            // `return@run` leaves the lambda, not `f`.
            (
                Language::Kotlin,
                "fun f(x: Boolean): Boolean {\n    run { if (x) return@run true else return false }\n    return true\n}\n",
            ),
        ] {
            assert_eq!(classify(language, source), None, "{source}");
        }
    }
}
