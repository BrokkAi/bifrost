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

/// The Kotlin grammar uses expressions for both statements and values. This
/// result keeps the Kotlin-only value-context decision beside the syntax
/// classifier instead of making the shared return-arm classifier permissive for
/// every language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KotlinBooleanBranchClassification {
    NotApplicable,
    Open,
    Proven(BooleanBranchOutcome),
}

/// Classify Kotlin's expression-valued Boolean branches.
///
/// A direct `true`/`false` pair is useful to A6 only when the `if` expression
/// supplies the enclosing function or lambda result. A non-Boolean direct pair
/// in that same position remains open: the result context is known, but this
/// syntax hook does not claim a type conversion or a replacement proof.
pub fn classify_kotlin_boolean_branches(
    source: &str,
    if_node: Node<'_>,
    true_body: Node<'_>,
    false_body: Node<'_>,
) -> KotlinBooleanBranchClassification {
    let Some(context) = kotlin_result_context(if_node, source) else {
        return KotlinBooleanBranchClassification::NotApplicable;
    };
    let Some(first) = kotlin_direct_result(true_body) else {
        return KotlinBooleanBranchClassification::NotApplicable;
    };
    let Some(second) = kotlin_direct_result(false_body) else {
        return KotlinBooleanBranchClassification::NotApplicable;
    };
    // Preserve the established return-arm classifier for explicit returns,
    // including a labeled return from a nested lambda. This hook owns only
    // expression-valued Boolean pairs; return arms still need the shared
    // language-specific handling below.
    if kotlin_is_return_arm(first) || kotlin_is_return_arm(second) {
        return KotlinBooleanBranchClassification::NotApplicable;
    }
    let first_value = kotlin_boolean_literal(source, first);
    let second_value = kotlin_boolean_literal(source, second);
    match (context, first_value, second_value) {
        (KotlinResultContext::Boolean, Some(true), Some(false)) => {
            KotlinBooleanBranchClassification::Proven(BooleanBranchOutcome::Condition)
        }
        (KotlinResultContext::Boolean, Some(false), Some(true)) => {
            KotlinBooleanBranchClassification::Proven(BooleanBranchOutcome::NegatedCondition)
        }
        (KotlinResultContext::Boolean, Some(_), Some(_)) => {
            KotlinBooleanBranchClassification::NotApplicable
        }
        (KotlinResultContext::Other, Some(_), Some(_)) => KotlinBooleanBranchClassification::Open,
        _ => KotlinBooleanBranchClassification::Open,
    }
}

/// Whether a Kotlin `when` has the narrow shape that could otherwise be an A6
/// Boolean branch relation. The shared relation code uses this as a coverage
/// hook only; it does not claim that a `when` is an `if`.
pub fn kotlin_when_is_a6_shape(source: &str, when_node: Node<'_>) -> bool {
    if when_node.kind() != "when_expression" {
        return false;
    }
    let mut cursor = when_node.walk();
    let entries = when_node
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "when_entry")
        .collect::<Vec<_>>();
    if entries.len() != 2 {
        return false;
    }
    let Some(first) = kotlin_when_boolean_result(source, entries[0]) else {
        return false;
    };
    let Some(second) = kotlin_when_boolean_result(source, entries[1]) else {
        return false;
    };
    if first.0 == second.0 || first.1 != second.1 {
        return false;
    }
    if first.1 {
        true
    } else {
        matches!(
            kotlin_result_context(when_node, source),
            Some(KotlinResultContext::Boolean)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KotlinResultContext {
    Boolean,
    Other,
}

fn kotlin_result_context(node: Node<'_>, source: &str) -> Option<KotlinResultContext> {
    let mut current = node;
    loop {
        let parent = current.parent()?;
        match parent.kind() {
            // `return if (...) ...` returns from the enclosing function. A
            // named return has an extra label child and stays outside this
            // hook, just as the existing Kotlin return-arm classifier does.
            "jump_expression"
                if parent
                    .child(0)
                    .is_some_and(|child| child.kind() == "return")
                    && single_named_child(parent)
                        .is_some_and(|child| child.id() == current.id()) =>
            {
                return Some(kotlin_enclosing_function_context(parent, source));
            }
            // An expression body has one result expression. A block-bodied
            // function's statements are evaluated for effect in Kotlin.
            "function_body"
                if single_named_child(parent).is_some_and(|child| child.id() == current.id()) =>
            {
                let function = parent
                    .parent()
                    .filter(|owner| owner.kind() == "function_declaration")?;
                return Some(kotlin_declared_function_context(function, source));
            }
            // A lambda or anonymous function's final statement is its result,
            // including a braced `if` whose two arms each contain one Boolean
            // literal. A named function's block body is intentionally absent:
            // Kotlin requires an explicit return there.
            "statements"
                if kotlin_result_owner(parent).is_some_and(|owner| {
                    matches!(owner.kind(), "lambda_literal" | "anonymous_function")
                }) && last_named_child(parent)
                    .is_some_and(|child| child.id() == current.id()) =>
            {
                let owner = kotlin_result_owner(parent)?;
                return Some(if owner.kind() == "anonymous_function" {
                    kotlin_declared_function_context(owner, source)
                } else {
                    KotlinResultContext::Boolean
                });
            }
            "parenthesized_expression" => current = parent,
            _ => return None,
        }
    }
}

fn kotlin_result_owner(statements: Node<'_>) -> Option<Node<'_>> {
    let parent = statements.parent()?;
    if parent.kind() == "function_body" {
        parent.parent()
    } else {
        Some(parent)
    }
}

fn kotlin_enclosing_function_context(node: Node<'_>, source: &str) -> KotlinResultContext {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "function_declaration" {
            return kotlin_declared_function_context(parent, source);
        }
        current = parent.parent();
    }
    KotlinResultContext::Other
}

fn kotlin_declared_function_context(function: Node<'_>, source: &str) -> KotlinResultContext {
    let receiver = function
        .child_by_field_name("receiver")
        .map(|node| node.id());
    let mut cursor = function.walk();
    let Some(return_type) = function
        .named_children(&mut cursor)
        .filter(|child| Some(child.id()) != receiver)
        .find(|child| {
            matches!(
                child.kind(),
                "user_type"
                    | "nullable_type"
                    | "not_nullable_type"
                    | "function_type"
                    | "parenthesized_type"
            )
        })
    else {
        return KotlinResultContext::Other;
    };
    if return_type.kind() != "user_type" {
        return KotlinResultContext::Other;
    }
    let mut type_cursor = return_type.walk();
    let identifiers = return_type
        .named_children(&mut type_cursor)
        .filter(|child| child.kind() == "type_identifier")
        .collect::<Vec<_>>();
    if identifiers.len() == 1
        && identifiers[0]
            .utf8_text(source.as_bytes())
            .is_ok_and(|text| text == "Boolean")
        && return_type.named_child_count() == 1
    {
        KotlinResultContext::Boolean
    } else {
        KotlinResultContext::Other
    }
}

fn kotlin_direct_result(mut body: Node<'_>) -> Option<Node<'_>> {
    if body.kind() == "control_structure_body" {
        body = single_named_child(body)?;
    }
    if body.kind() == "statements" {
        body = single_named_child(body)?;
    }
    while body.kind() == "parenthesized_expression" {
        body = single_named_child(body)?;
    }
    (!body.has_error() && !body.is_missing()).then_some(body)
}

fn kotlin_when_boolean_result(source: &str, entry: Node<'_>) -> Option<(bool, bool)> {
    let mut cursor = entry.walk();
    let body = entry
        .named_children(&mut cursor)
        .find(|child| child.kind() == "control_structure_body")?;
    let result = kotlin_direct_result(body)?;
    if let Some(value) = kotlin_boolean_literal(source, result) {
        return Some((value, false));
    }
    if !kotlin_is_return_arm(result) {
        return None;
    }
    let value = single_named_child(result)
        .and_then(kotlin_direct_result)
        .and_then(|node| kotlin_boolean_literal(source, node))?;
    Some((value, true))
}

fn kotlin_is_return_arm(node: Node<'_>) -> bool {
    node.kind() == "jump_expression" && node.child(0).is_some_and(|child| child.kind() == "return")
}

fn kotlin_boolean_literal(source: &str, node: Node<'_>) -> Option<bool> {
    if node.kind() != "boolean_literal" {
        return None;
    }
    match node.utf8_text(source.as_bytes()).ok()? {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn single_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    let mut children = node
        .named_children(&mut cursor)
        .filter(|child| !child.is_extra());
    let child = children.next()?;
    children.next().is_none().then_some(child)
}

fn last_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| !child.is_extra())
        .last()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalaBooleanBranchClassification {
    Proven(BooleanBranchOutcome),
    NotCandidate,
    Open,
}

/// Classify Scala's expression-valued `if` in addition to its explicit-return
/// form. The caller supplies the `if` node when it has one; a missing node is
/// useful for the existing arm-only unit-test surface and admits only returns.
///
/// A pair of complementary literals is an open result unless the enclosing
/// callable and its result type prove that this value is the method result.
/// This keeps nested values, `Any`, and user-defined types named `Boolean`
/// visible as incomplete rather than treating syntax alone as a finding.
pub fn classify_scala_boolean_branches(
    source: &str,
    true_body: Node<'_>,
    false_body: Node<'_>,
    if_node: Option<Node<'_>>,
) -> ScalaBooleanBranchClassification {
    let Some(first) = scala_branch_value(source, true_body) else {
        return ScalaBooleanBranchClassification::NotCandidate;
    };
    let Some(second) = scala_branch_value(source, false_body) else {
        return ScalaBooleanBranchClassification::NotCandidate;
    };
    let outcome = match (first.value, second.value) {
        (true, false) => BooleanBranchOutcome::Condition,
        (false, true) => BooleanBranchOutcome::NegatedCondition,
        _ => return ScalaBooleanBranchClassification::NotCandidate,
    };

    let both_return = first.explicit_return && second.explicit_return;
    let expression_value = !first.explicit_return && !second.explicit_return;
    if !both_return && !expression_value {
        return ScalaBooleanBranchClassification::Open;
    }
    let Some(if_node) = if_node else {
        return if both_return {
            ScalaBooleanBranchClassification::Proven(outcome)
        } else {
            ScalaBooleanBranchClassification::Open
        };
    };
    if both_return {
        if scala_enclosing_method(if_node)
            .is_some_and(|method| scala_result_is_boolean(source, method, true))
        {
            ScalaBooleanBranchClassification::Proven(outcome)
        } else {
            ScalaBooleanBranchClassification::Open
        }
    } else if expression_value
        && if_node.child_by_field_name("alternative").is_some()
        && scala_if_is_method_result(if_node)
        && scala_enclosing_method(if_node)
            .is_some_and(|method| scala_result_is_boolean(source, method, false))
    {
        ScalaBooleanBranchClassification::Proven(outcome)
    } else {
        ScalaBooleanBranchClassification::Open
    }
}

#[derive(Debug, Clone, Copy)]
struct ScalaBranchValue {
    value: bool,
    explicit_return: bool,
}

fn scala_branch_value(source: &str, mut body: Node<'_>) -> Option<ScalaBranchValue> {
    if body.has_error() || body.is_missing() {
        return None;
    }
    while matches!(body.kind(), "block" | "indented_block") {
        body = single_runtime_named_child(body)?;
    }
    let explicit_return = body.kind() == "return_expression";
    if explicit_return {
        body = single_runtime_named_child(body)?;
    }
    while body.kind() == "parenthesized_expression" {
        body = single_runtime_named_child(body)?;
    }
    if body.has_error() || body.is_missing() || body.kind() != "boolean_literal" {
        return None;
    }
    let value = match source.get(body.byte_range())? {
        "true" => true,
        "false" => false,
        _ => return None,
    };
    Some(ScalaBranchValue {
        value,
        explicit_return,
    })
}

fn scala_enclosing_method(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if matches!(parent.kind(), "lambda_expression" | "case_block") {
            return None;
        }
        if parent.kind() == "function_definition" {
            return Some(parent);
        }
        node = parent;
    }
    None
}

fn scala_if_is_method_result(mut node: Node<'_>) -> bool {
    loop {
        let Some(parent) = node.parent() else {
            return false;
        };
        match parent.kind() {
            "parenthesized_expression" => node = parent,
            "return_expression" => return true,
            "block" | "indented_block" => {
                let Some(last) = last_runtime_named_child(parent) else {
                    return false;
                };
                if last.id() != node.id() {
                    return false;
                }
                node = parent;
            }
            "function_definition" => {
                return parent
                    .child_by_field_name("body")
                    .is_some_and(|body| body.id() == node.id());
            }
            _ => return false,
        }
    }
}

fn last_runtime_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    let mut last = None;
    for child in node
        .named_children(&mut cursor)
        .filter(|child| !child.is_extra())
    {
        last = Some(child);
    }
    last
}

fn scala_result_is_boolean(source: &str, method: Node<'_>, explicit_return: bool) -> bool {
    let Some(return_type) = method.child_by_field_name("return_type") else {
        return !explicit_return;
    };
    if return_type.has_error() || return_type.is_missing() {
        return false;
    }
    if scala_defines_named_type(method, source, "Boolean") {
        return false;
    }
    return_type.kind() == "type_identifier"
        && source
            .get(return_type.byte_range())
            .is_some_and(|text| text.trim() == "Boolean")
}

/// Whether the source file declares a Scala type with the supplied unqualified
/// name. A local type can shadow a prelude scalar name, so syntax-only scalar
/// classification must leave that type open.
pub(crate) fn scala_defines_named_type(mut node: Node<'_>, source: &str, expected: &str) -> bool {
    while let Some(parent) = node.parent() {
        node = parent;
    }
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        if matches!(
            current.kind(),
            "class_definition"
                | "trait_definition"
                | "object_definition"
                | "enum_definition"
                | "type_definition"
        ) && current
            .child_by_field_name("name")
            .and_then(|name| source.get(name.byte_range()))
            == Some(expected)
        {
            return true;
        }
        let mut cursor = current.walk();
        pending.extend(current.named_children(&mut cursor));
    }
    false
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
        Language::Rust => {
            // Rust `if` is an expression, so a tail Boolean literal is the
            // branch result without a `return` expression wrapper.
            if body.kind() == "boolean_literal" {
                body
            } else {
                if body.kind() != "return_expression" {
                    return None;
                }
                single_runtime_named_child(body)?
            }
        }
        Language::Scala => {
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
    crate::analyzer::tree_walk::single_named_child_matching(node, |child| !child.is_extra())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn classify_kotlin_value(source: &str) -> KotlinBooleanBranchClassification {
        let mut parser = Parser::new();
        parser
            .set_language(&crate::analyzer::kotlin::language::LANGUAGE.into())
            .expect("Kotlin grammar");
        let tree = parser.parse(source, None).expect("parsed source");
        assert!(!tree.root_node().has_error(), "{source}");
        let mut pending = vec![tree.root_node()];
        while let Some(node) = pending.pop() {
            if node.kind() == "if_expression" {
                let first = node.child_by_field_name("consequence").expect("true arm");
                let alternative = node.child_by_field_name("alternative").expect("false arm");
                let second = if alternative.kind() == "else_clause" {
                    alternative.named_child(0).expect("else body")
                } else {
                    alternative
                };
                return classify_kotlin_boolean_branches(source, node, first, second);
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
        panic!("no Kotlin if expression in {source}");
    }

    #[test]
    fn kotlin_expression_result_boolean_pairs_are_context_scoped() {
        for source in [
            "fun f(c: Boolean): Boolean { return if (c) true else false }\n",
            "fun f(c: Boolean): Boolean = if (c) true else false\n",
            "fun f(c: Boolean): Boolean { val g = { if (c) { true } else { false } }; return g() }\n",
            "fun f(c: Boolean): Boolean { val g = fun(x: Boolean): Boolean { if (x) { true } else { false } }; return g(c) }\n",
        ] {
            assert!(
                matches!(
                    classify_kotlin_value(source),
                    KotlinBooleanBranchClassification::Proven(BooleanBranchOutcome::Condition)
                ),
                "{source}"
            );
        }
        assert_eq!(
            classify_kotlin_value("fun f(c: Boolean): Int = if (c) 1 else 0\n"),
            KotlinBooleanBranchClassification::Open
        );
        assert_eq!(
            classify_kotlin_value("fun f(c: Boolean): Boolean = if (c) true else true\n"),
            KotlinBooleanBranchClassification::NotApplicable
        );
    }
}
