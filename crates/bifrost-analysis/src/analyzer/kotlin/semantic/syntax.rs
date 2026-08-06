//! Structured reads of the Kotlin syntax tree needed by semantic lowering.
//!
//! The vendored grammar is field-poor: only `if_expression` names its
//! condition/consequence/alternative, and only `function_declaration`,
//! `property_declaration`, and `function_type` name a `receiver`. Everything
//! else — the callee of a call, the operand of a postfix operator, the binding
//! of a `for`, the arms of a `when` — is recovered positionally from named
//! children, or from the anonymous operator tokens the grammar keeps as
//! ordinary children.
//!
//! Reads that are already shared with definition navigation and the usage
//! graphs live in [`brokk_bifrost_jvm::kotlin::syntax`] and are reused from here
//! rather than duplicated.

use super::*;

pub(super) use brokk_bifrost_jvm::kotlin::syntax::{
    kotlin_call_arity, kotlin_callee, kotlin_named_argument_label, kotlin_navigation_receiver,
    kotlin_value_arguments,
};

/// Named children with comments removed.
pub(super) fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| !is_comment_kind(child.kind()))
        .collect()
}

pub(super) fn first_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| !is_comment_kind(child.kind()))
}

pub(super) fn child_of_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    named_children(node)
        .into_iter()
        .find(|child| child.kind() == kind)
}

fn is_comment_kind(kind: &str) -> bool {
    matches!(kind, "line_comment" | "multiline_comment" | "comment")
}

/// Whether `node` carries the anonymous operator token `token` as a direct
/// child. The Kotlin grammar spells `?.`, `!!`, `?:`, `!`, `else`, and the
/// `jump_expression` keywords as anonymous tokens rather than fields.
pub(super) fn has_token(node: Node<'_>, token: &str) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|child| !child.is_named() && child.kind() == token)
}

/// The first anonymous token of `node`, used to classify `jump_expression`
/// (`return`, `return@`, `break`, `break@`, `continue`, `continue@`, `throw`).
pub(super) fn first_token(node: Node<'_>) -> Option<&'static str> {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .find(|child| !child.is_named())
        .map(|child| child.kind())
}

/// Syntax that owns its own executable boundary, and therefore terminates a
/// body-local scan such as the free-`this` or local-binding walks.
pub(super) fn is_kotlin_nested_execution_boundary(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "function_declaration"
            | "secondary_constructor"
            | "anonymous_function"
            | "lambda_literal"
            | "class_declaration"
            | "object_declaration"
            | "companion_object"
            | "class_body"
            | "enum_class_body"
            | "getter"
            | "setter"
            | "anonymous_initializer"
    )
}

/// Whether a nested callable body reads the lexical receiver directly.
pub(super) fn body_contains_free_this(
    body: Node<'_>,
    cancellation: &CancellationToken,
) -> Result<bool, LoweringCancelled> {
    let mut found = false;
    try_walk_named_tree_preorder(body, true, |node| {
        if cancellation.is_cancelled() {
            return Err(LoweringCancelled);
        }
        if node.id() != body.id() && is_kotlin_nested_execution_boundary(node) {
            return Ok(WalkControl::SkipChildren);
        }
        if node.kind() == "this_expression" {
            found = true;
            return Ok(WalkControl::Break);
        }
        Ok(WalkControl::Continue)
    })?;
    Ok(found)
}

/// The declaration container a node opens, if any.
pub(super) fn declaration_container_kind(node: Node<'_>) -> Option<DeclarationSegmentKind> {
    match node.kind() {
        "class_declaration" | "object_declaration" | "companion_object" => {
            Some(DeclarationSegmentKind::Type)
        }
        "class_body"
            if node
                .parent()
                .is_some_and(|parent| matches!(parent.kind(), "object_literal" | "enum_entry")) =>
        {
            Some(DeclarationSegmentKind::Type)
        }
        _ => None,
    }
}

/// A container's name: the first `type_identifier` child. Kotlin names no
/// declaration with a field, and an anonymous `object : Base()` has no name at
/// all.
pub(super) fn declaration_container_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    child_of_kind(node, "type_identifier")
        .and_then(|name| nonempty_node_text(source, name))
        .map(Box::<str>::from)
}

/// Whether a declaration sits at a declaration site (a type body or the file)
/// rather than inside an executable body.
///
/// Kotlin reuses `property_declaration`, `getter`, and `setter` for both, so
/// the enclosing syntax is what separates a member from an ordinary statement.
pub(super) fn is_declaration_site(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        matches!(
            parent.kind(),
            "class_body" | "enum_class_body" | "source_file"
        )
    })
}

/// The value-producing expression a `property_declaration` initializes with,
/// skipping the binding, its type, and any accessors.
pub(super) fn property_initializer(node: Node<'_>) -> Option<Node<'_>> {
    let mut seen_binding = false;
    for child in named_children(node) {
        match child.kind() {
            "modifiers" | "binding_pattern_kind" | "type_constraints" => continue,
            "variable_declaration" | "multi_variable_declaration" => {
                seen_binding = true;
                continue;
            }
            "getter" | "setter" | "property_delegate" | "receiver_type" => continue,
            _ if seen_binding => return Some(child),
            _ => continue,
        }
    }
    None
}

/// The default expression of a primary-constructor `class_parameter`.
///
/// The grammar spells `class C(val x: Int = compute())` as
/// `class_parameter(binding_pattern_kind, simple_identifier, user_type, expr)`
/// with no field naming the default, so the expression is the first named child
/// after the parameter's own name and declared type.
pub(super) fn class_parameter_default(node: Node<'_>) -> Option<Node<'_>> {
    let mut seen_name = false;
    for child in named_children(node) {
        match child.kind() {
            "modifiers" | "binding_pattern_kind" => continue,
            _ if is_type_syntax(child.kind()) => continue,
            "simple_identifier" if !seen_name => {
                seen_name = true;
            }
            _ if seen_name => return Some(child),
            _ => continue,
        }
    }
    None
}

/// The delegate expression of a `val x by expr` property.
pub(super) fn property_delegate_expression(node: Node<'_>) -> Option<Node<'_>> {
    child_of_kind(node, "property_delegate").and_then(first_named_child)
}

/// The binding a property or `for` introduces: one `variable_declaration`, or
/// the `multi_variable_declaration` of a destructuring form.
pub(super) fn binding_node(node: Node<'_>) -> Option<Node<'_>> {
    named_children(node).into_iter().find(|child| {
        matches!(
            child.kind(),
            "variable_declaration" | "multi_variable_declaration"
        )
    })
}

/// Every `simple_identifier` a binding introduces, in source order.
pub(super) fn binding_names(node: Node<'_>) -> Vec<Node<'_>> {
    match node.kind() {
        "variable_declaration" => child_of_kind(node, "simple_identifier")
            .into_iter()
            .collect(),
        "multi_variable_declaration" => named_children(node)
            .into_iter()
            .filter(|child| child.kind() == "variable_declaration")
            .filter_map(|child| child_of_kind(child, "simple_identifier"))
            .collect(),
        _ => Vec::new(),
    }
}

/// How a `function_body` (or accessor body) carries its statements.
#[derive(Debug, Clone, Copy)]
pub(super) enum BodyShape<'tree> {
    /// `{ … }` — a `statements` list.
    Block(Node<'tree>),
    /// `= expr` — one expression whose value is the result.
    Expression(Node<'tree>),
    /// `{}` — no executable syntax.
    Empty,
}

pub(super) fn function_body_shape(body: Node<'_>) -> BodyShape<'_> {
    match first_named_child(body) {
        Some(child) if child.kind() == "statements" => BodyShape::Block(child),
        Some(child) => BodyShape::Expression(child),
        None => BodyShape::Empty,
    }
}

/// Unwrap a `control_structure_body` to the syntax that actually executes: the
/// `statements` list of a block, or the single statement of a bodyless arm.
pub(super) fn control_structure_body_content(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "control_structure_body" {
        return Some(node);
    }
    child_of_kind(node, "statements").or_else(|| first_named_child(node))
}

/// Whether a modifier keyword is present on a declaration.
///
/// The grammar groups modifiers by category (`inheritance_modifier`,
/// `member_modifier`, …) rather than naming each keyword, so the keyword is
/// read from the modifier leaf's own text.
pub(super) fn has_modifier(source: &str, node: Node<'_>, modifier: &str) -> bool {
    let Some(modifiers) = child_of_kind(node, "modifiers") else {
        return false;
    };
    named_children(modifiers)
        .into_iter()
        .any(|child| node_text(source, child) == Some(modifier))
}

/// The type declaration a member belongs to, stopping at the first enclosing
/// body so a nested class does not answer for its outer class.
pub(super) fn enclosing_type_declaration(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "class_declaration" | "object_declaration" | "companion_object" | "object_literal"
        ) {
            return Some(parent);
        }
        if parent.kind() == "source_file" {
            return None;
        }
        current = parent.parent();
    }
    None
}

/// Whether a member of `declaration` can be overridden.
///
/// Kotlin classes and members are final unless opened, which inverts Java's
/// default: only `open`/`abstract`/`sealed` declarations, and interfaces,
/// admit an override.
pub(super) fn type_admits_overrides(source: &str, declaration: Node<'_>) -> bool {
    if declaration.kind() != "class_declaration" {
        // `object`, `companion object`, and anonymous object literals cannot be
        // subclassed, so their members are never overridden.
        return false;
    }
    has_token(declaration, "interface")
        || has_modifier(source, declaration, "open")
        || has_modifier(source, declaration, "abstract")
        || has_modifier(source, declaration, "sealed")
}

/// Whether a `navigation_expression` selects through the null-safe `?.`
/// operator rather than the ordinary `.`.
pub(super) fn is_safe_navigation(node: Node<'_>) -> bool {
    node.kind() == "navigation_expression"
        && child_of_kind(node, "navigation_suffix").is_some_and(|suffix| has_token(suffix, "?."))
}

/// The member selected by a `navigation_expression`.
pub(super) fn navigation_member(node: Node<'_>) -> Option<Node<'_>> {
    child_of_kind(node, "navigation_suffix").and_then(|suffix| {
        named_children(suffix)
            .into_iter()
            .find(|child| child.kind() != "type_arguments")
    })
}

/// The operand of a `postfix_expression` or `prefix_expression`.
pub(super) fn unary_operand(node: Node<'_>) -> Option<Node<'_>> {
    named_children(node)
        .into_iter()
        .find(|child| !matches!(child.kind(), "annotation" | "label"))
}

/// The two operands of a binary-shaped node, in source order.
pub(super) fn binary_operands(node: Node<'_>) -> Vec<Node<'_>> {
    named_children(node)
        .into_iter()
        .filter(|child| !is_type_syntax(child.kind()) && child.kind() != "annotation")
        .collect()
}

pub(super) fn is_type_syntax(kind: &str) -> bool {
    matches!(
        kind,
        "user_type"
            | "nullable_type"
            | "not_nullable_type"
            | "parenthesized_type"
            | "function_type"
            | "type_arguments"
            | "type_parameters"
            | "type_constraints"
            | "type_modifiers"
            | "receiver_type"
            | "type_identifier"
            | "type_test"
    )
}

/// The runtime sub-expressions of an opaque operation.
pub(super) fn runtime_expression_children(node: Node<'_>) -> Vec<Node<'_>> {
    named_children(node)
        .into_iter()
        .filter(|child| {
            !is_type_syntax(child.kind())
                && !matches!(
                    child.kind(),
                    "annotation" | "modifiers" | "label" | "class_body" | "binding_pattern_kind"
                )
        })
        .collect()
}

/// The `label` a statement, loop, or lambda carries.
///
/// A declaring label spells its trailing `@` inside the token (`outer@`); a
/// `jump_expression`'s label does not, because the `@` belongs to the
/// `break@`/`continue@`/`return@` keyword.
pub(super) fn label_text<'source>(source: &'source str, label: Node<'_>) -> Option<&'source str> {
    let text = nonempty_node_text(source, label)?;
    Some(text.strip_suffix('@').unwrap_or(text))
}

/// The label a `jump_expression` names, if it names one.
pub(super) fn jump_label<'tree>(node: Node<'tree>) -> Option<Node<'tree>> {
    child_of_kind(node, "label")
}

/// The value a `jump_expression` carries, if it carries one.
pub(super) fn jump_operand<'tree>(node: Node<'tree>) -> Option<Node<'tree>> {
    named_children(node)
        .into_iter()
        .find(|child| child.kind() != "label")
}

/// The subject a `when` switches on.
pub(super) fn when_subject_expression(node: Node<'_>) -> Option<Node<'_>> {
    child_of_kind(node, "when_subject").and_then(|subject| {
        named_children(subject)
            .into_iter()
            .find(|child| child.kind() != "annotation")
    })
}

pub(super) fn when_entries(node: Node<'_>) -> Vec<Node<'_>> {
    named_children(node)
        .into_iter()
        .filter(|child| child.kind() == "when_entry")
        .collect()
}

pub(super) fn when_entry_conditions(entry: Node<'_>) -> Vec<Node<'_>> {
    named_children(entry)
        .into_iter()
        .filter(|child| child.kind() == "when_condition")
        .collect()
}

pub(super) fn when_entry_guard(entry: Node<'_>) -> Option<Node<'_>> {
    child_of_kind(entry, "guard_condition").and_then(first_named_child)
}

pub(super) fn when_entry_body(entry: Node<'_>) -> Option<Node<'_>> {
    child_of_kind(entry, "control_structure_body")
}

/// The runtime expression a `when` condition evaluates, if it has one.
///
/// `is T` carries only type syntax, so it has no operand; `in a..b` evaluates
/// the range it tests against.
pub(super) fn when_condition_operand(condition: Node<'_>) -> Option<Node<'_>> {
    let inner = first_named_child(condition)?;
    match inner.kind() {
        "type_test" => None,
        "range_test" => first_named_child(inner),
        _ => Some(inner),
    }
}

/// The three positional slots of a `for (binding in iterable) body`.
pub(super) fn for_statement_parts<'tree>(
    node: Node<'tree>,
) -> Option<(Node<'tree>, Node<'tree>, Option<Node<'tree>>)> {
    let children = named_children(node)
        .into_iter()
        .filter(|child| child.kind() != "annotation")
        .collect::<Vec<_>>();
    let binding = *children.first()?;
    let iterable = *children.get(1)?;
    let body = children
        .get(2)
        .copied()
        .filter(|child| child.kind() == "control_structure_body");
    Some((binding, iterable, body))
}

/// The condition and optional body of a `while`.
pub(super) fn while_statement_parts<'tree>(
    node: Node<'tree>,
) -> Option<(Node<'tree>, Option<Node<'tree>>)> {
    let children = named_children(node);
    let condition = children
        .iter()
        .copied()
        .find(|child| child.kind() != "control_structure_body")?;
    let body = children
        .into_iter()
        .find(|child| child.kind() == "control_structure_body");
    Some((condition, body))
}

/// The optional body and condition of a `do … while`.
pub(super) fn do_while_statement_parts<'tree>(
    node: Node<'tree>,
) -> Option<(Option<Node<'tree>>, Node<'tree>)> {
    let children = named_children(node);
    let body = children
        .iter()
        .copied()
        .find(|child| child.kind() == "control_structure_body");
    let condition = children
        .into_iter()
        .find(|child| child.kind() != "control_structure_body")?;
    Some((body, condition))
}

/// The target and value of an `assignment`.
pub(super) fn assignment_parts<'tree>(
    node: Node<'tree>,
) -> Option<(Node<'tree>, Option<Node<'tree>>)> {
    let children = named_children(node);
    let target = *children.first()?;
    let value = children.get(1).copied();
    Some((target, value))
}

/// How a `directly_assignable_expression` names its destination.
#[derive(Debug, Clone, Copy)]
pub(super) enum AssignmentTarget<'tree> {
    /// A bare name: a local, a parameter, or an implicit-receiver member.
    Name(Node<'tree>),
    /// `base.member = …`
    Field {
        base: Node<'tree>,
        member: Node<'tree>,
    },
    /// `base[index] = …`
    Index {
        base: Node<'tree>,
        index: Option<Node<'tree>>,
    },
    /// Anything else the grammar admits; evaluated opaquely.
    Opaque(Node<'tree>),
}

pub(super) fn assignment_target(node: Node<'_>) -> AssignmentTarget<'_> {
    if node.kind() != "directly_assignable_expression" {
        return AssignmentTarget::Opaque(node);
    }
    let children = named_children(node);
    let Some(base) = children.first().copied() else {
        return AssignmentTarget::Opaque(node);
    };
    match children.get(1).copied() {
        None if base.kind() == "simple_identifier" => AssignmentTarget::Name(base),
        None => AssignmentTarget::Opaque(base),
        Some(suffix) if suffix.kind() == "navigation_suffix" => navigation_member(node)
            .or_else(|| first_named_child(suffix))
            .map_or(AssignmentTarget::Opaque(node), |member| {
                AssignmentTarget::Field { base, member }
            }),
        Some(suffix) if suffix.kind() == "indexing_suffix" => AssignmentTarget::Index {
            base,
            index: first_named_child(suffix),
        },
        Some(_) => AssignmentTarget::Opaque(node),
    }
}

/// The base and index of an `indexing_expression`.
pub(super) fn indexing_parts<'tree>(
    node: Node<'tree>,
) -> Option<(Node<'tree>, Option<Node<'tree>>)> {
    let children = named_children(node);
    let base = *children.first()?;
    let index = children
        .into_iter()
        .find(|child| child.kind() == "indexing_suffix")
        .and_then(first_named_child);
    Some((base, index))
}

/// The trailing lambda a call passes outside its parentheses.
pub(super) fn trailing_lambda(call: Node<'_>) -> Option<Node<'_>> {
    child_of_kind(call, "call_suffix")
        .and_then(|suffix| child_of_kind(suffix, "annotated_lambda"))
        .and_then(|annotated| child_of_kind(annotated, "lambda_literal"))
}

/// One argument of a call, with the expansion and domain its syntax proves.
#[derive(Debug, Clone, Copy)]
pub(super) struct CallArgumentNode<'tree> {
    /// The expression evaluated for the argument. For a spread this is the
    /// spread operand, because `*` itself produces no value of its own.
    pub(super) value: Node<'tree>,
    /// Whether the source spelled a label, which Kotlin binds by keyword.
    pub(super) keyword: bool,
    /// Whether the source spread an array into the positional tail.
    pub(super) spread: bool,
}

impl CallArgumentNode<'_> {
    pub(super) fn expansion(self) -> CallArgumentExpansion {
        let domain = if self.keyword {
            ArgumentDomain::Keyword
        } else {
            ArgumentDomain::Positional
        };
        if self.spread {
            CallArgumentExpansion::Spread(domain)
        } else {
            CallArgumentExpansion::Direct(domain)
        }
    }
}

/// One `value_argument`, classified by the two things its syntax settles: the
/// label that makes it a keyword argument, and the `*` that makes it a spread.
///
/// A named argument spells its label as the first of two named children, so the
/// value is the last one either way; the label reader is consulted so this and
/// the shared usage readers cannot drift about which child is the label.
pub(super) fn value_argument_parts(argument: Node<'_>) -> Option<CallArgumentNode<'_>> {
    let children = named_children(argument)
        .into_iter()
        .filter(|child| child.kind() != "annotation")
        .collect::<Vec<_>>();
    let value = children.last().copied()?;
    let keyword = children.len() >= 2 && kotlin_named_argument_label(argument, children[0]);
    debug_assert!(
        children.len() < 2 || keyword,
        "a two-child value_argument is a named argument"
    );
    if value.kind() == "spread_expression" {
        return Some(CallArgumentNode {
            value: first_named_child(value).unwrap_or(value),
            keyword,
            spread: true,
        });
    }
    Some(CallArgumentNode {
        value,
        keyword,
        spread: false,
    })
}

/// The value half of one `value_argument`.
pub(super) fn value_argument_value(argument: Node<'_>) -> Option<Node<'_>> {
    value_argument_parts(argument).map(|argument| argument.value)
}

/// Argument expressions of a call, trailing lambda included.
///
/// A trailing lambda is bound positionally to the callee's last parameter, so
/// it joins the list as an ordinary direct positional argument.
pub(super) fn call_arguments(call: Node<'_>) -> Vec<CallArgumentNode<'_>> {
    let mut arguments = kotlin_value_arguments(call)
        .map(|list| {
            named_children(list)
                .into_iter()
                .filter(|child| child.kind() == "value_argument")
                .filter_map(value_argument_parts)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    arguments.extend(trailing_lambda(call).map(|lambda| CallArgumentNode {
        value: lambda,
        keyword: false,
        spread: false,
    }));
    arguments
}

/// The `annotated_lambda` label a `return@label` inside a trailing lambda can
/// name: an explicit `forEach lbl@{ … }`, or the implicit label formed from the
/// callee's simple name.
pub(super) fn lambda_boundary_label<'source>(
    source: &'source str,
    lambda: Node<'_>,
) -> Option<&'source str> {
    let annotated = lambda
        .parent()
        .filter(|parent| parent.kind() == "annotated_lambda")?;
    if let Some(label) = child_of_kind(annotated, "label") {
        return label_text(source, label);
    }
    let call = annotated
        .parent()
        .filter(|parent| parent.kind() == "call_suffix")
        .and_then(|suffix| suffix.parent())
        .filter(|parent| parent.kind() == "call_expression")?;
    let callee = kotlin_callee(call)?;
    let name = match callee.kind() {
        "navigation_expression" => navigation_member(callee)?,
        _ => callee,
    };
    nonempty_node_text(source, name)
}

/// Whether the value an expression produces is consumed.
///
/// Kotlin has no statement/expression split in its grammar, so this walks the
/// enclosing syntax: a child of `statements` is evaluated for effect unless it
/// is the tail expression of a lambda, and an arm inherits the position of the
/// `if`/`when` it belongs to.
pub(super) fn value_is_used(node: Node<'_>) -> bool {
    let mut current = node;
    loop {
        let Some(parent) = current.parent() else {
            return false;
        };
        match parent.kind() {
            "statements" => {
                return parent
                    .parent()
                    .is_some_and(|owner| owner.kind() == "lambda_literal")
                    && named_children(parent)
                        .last()
                        .is_some_and(|last| last.id() == current.id());
            }
            "control_structure_body"
            | "parenthesized_expression"
            | "when_entry"
            | "if_expression"
            | "when_expression"
            | "try_expression" => current = parent,
            "while_statement" | "do_while_statement" | "for_statement" | "source_file" => {
                return false;
            }
            _ => return true,
        }
    }
}

/// The expression whose value a block or arm produces, if the shape makes one
/// syntactically identifiable.
pub(super) fn result_expression(node: Node<'_>) -> Option<Node<'_>> {
    let content = control_structure_body_content(node)?;
    if content.kind() == "statements" {
        return named_children(content).last().copied();
    }
    Some(content)
}

/// The scope a local binding is visible in.
pub(super) fn kotlin_local_scope(node: Node<'_>) -> Option<(usize, usize)> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "statements"
                | "control_structure_body"
                | "when_entry"
                | "catch_block"
                | "for_statement"
        ) {
            return Some((parent.start_byte(), parent.end_byte()));
        }
        if is_kotlin_nested_execution_boundary(parent) {
            return Some((parent.start_byte(), parent.end_byte()));
        }
        current = parent.parent();
    }
    None
}

pub(super) fn expression_value_kind(node: Node<'_>) -> SemanticValueKind {
    match node.kind() {
        "lambda_literal" | "anonymous_function" | "callable_reference" => {
            SemanticValueKind::Callable
        }
        "integer_literal" | "long_literal" | "hex_literal" | "bin_literal" | "unsigned_literal"
        | "real_literal" | "boolean_literal" | "character_literal" | "null_literal"
        | "string_literal" => SemanticValueKind::Constant,
        _ => SemanticValueKind::Temporary,
    }
}

/// Leaves with no further runtime structure to schedule.
pub(super) fn is_runtime_leaf(kind: &str) -> bool {
    matches!(
        kind,
        "simple_identifier"
            | "this_expression"
            | "super_expression"
            | "integer_literal"
            | "long_literal"
            | "hex_literal"
            | "bin_literal"
            | "unsigned_literal"
            | "real_literal"
            | "boolean_literal"
            | "character_literal"
            | "null_literal"
            | "string_content"
            | "interpolated_identifier"
            | "interpolation_identifier_start"
            | "interpolation_expression_start"
            | "interpolation_expression_end"
            | "character_escape_seq"
            | "line_comment"
            | "multiline_comment"
            | "label"
            | "type_identifier"
            | "binding_pattern_kind"
    )
}

/// Declarations that occupy a statement slot but execute nothing there.
pub(super) fn is_inert_statement(kind: &str) -> bool {
    matches!(
        kind,
        "class_declaration"
            | "object_declaration"
            | "companion_object"
            | "function_declaration"
            | "secondary_constructor"
            | "anonymous_initializer"
            | "type_alias"
            | "getter"
            | "setter"
            | "import_list"
            | "import_header"
            | "package_header"
            | "file_annotation"
            | "shebang_line"
            | "annotation"
    )
}

pub(super) fn required_child<'tree>(
    node: Node<'tree>,
    slot: &str,
) -> Result<Node<'tree>, KotlinLoweringError> {
    node.child_by_field_name(slot)
        .ok_or_else(|| missing_slot(node, slot))
}

pub(super) fn missing_slot(node: Node<'_>, slot: &str) -> KotlinLoweringError {
    KotlinLoweringError::Invalid(format!(
        "{} node at bytes {}..{} is missing structured {slot}",
        node.kind(),
        node.start_byte(),
        node.end_byte()
    ))
}

pub(super) fn node_range(node: Node<'_>) -> Range {
    Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row + 1,
        end_line: node.end_position().row + 1,
    }
}

pub(super) const fn completion_label(kind: CompletionKind) -> &'static str {
    match kind {
        CompletionKind::Normal => "normal",
        CompletionKind::Return => "return",
        CompletionKind::Throw => "throw",
        CompletionKind::Break => "break",
        CompletionKind::Continue => "continue",
        CompletionKind::Yield => "yield",
    }
}
