//! Structured reads of the Kotlin syntax tree needed by semantic lowering.
//!
//! The Kotlin grammar is field-poor: only `if_expression` names its
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

use crate::analyzer::kotlin::semantic::*;

use brokk_bifrost_analysis::analyzer::common::is_comment_kind;
/// Whether a Kotlin node carries an anonymous operator token as a direct child.
pub(super) use brokk_bifrost_core::analyzer::tree_walk::has_token_child as has_token;

pub(super) use brokk_bifrost_jvm::kotlin::declarations::kotlin_has_modifier as has_modifier;
pub(super) use brokk_bifrost_jvm::kotlin::syntax::{
    KotlinIntegerSuffix, kotlin_binding_name_nodes as binding_names,
    kotlin_binding_node as binding_node, kotlin_binding_type_node, kotlin_call_arity,
    kotlin_call_trailing_lambda_body as trailing_lambda, kotlin_callee,
    kotlin_declared_return_type_node, kotlin_declared_scalar_type,
    kotlin_first_token as first_token, kotlin_integer_literal_value, kotlin_literal_scalar_type,
    kotlin_named_argument_label, kotlin_navigation_member as navigation_member,
    kotlin_navigation_receiver,
    kotlin_property_delegate_expression as property_delegate_expression, kotlin_unwrap_receiver,
    kotlin_value_arguments,
};

/// Named children with comments removed.
pub(in crate::analyzer::kotlin::semantic) fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    brokk_bifrost_core::analyzer::tree_walk::named_children_iter(node)
        .filter(|child| !is_comment_kind(child.kind()))
        .collect()
}

pub(in crate::analyzer::kotlin::semantic) fn first_named_child(node: Node<'_>) -> Option<Node<'_>> {
    brokk_bifrost_core::analyzer::tree_walk::first_named_child_matching(node, |child| {
        !is_comment_kind(child.kind())
    })
}

pub(in crate::analyzer::kotlin::semantic) fn child_of_kind<'tree>(
    node: Node<'tree>,
    kind: &str,
) -> Option<Node<'tree>> {
    brokk_bifrost_core::analyzer::tree_walk::first_named_child_matching(node, |child| {
        !is_comment_kind(child.kind()) && child.kind() == kind
    })
}

/// Syntax that owns its own executable boundary, and therefore terminates a
/// body-local scan such as the free-`this` or local-binding walks.
pub(in crate::analyzer::kotlin::semantic) fn is_kotlin_nested_execution_boundary(
    node: Node<'_>,
) -> bool {
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
pub(in crate::analyzer::kotlin::semantic) fn body_contains_free_this(
    body: Node<'_>,
    cancellation: &CancellationToken,
) -> Result<bool, LoweringCancelled> {
    brokk_bifrost_semantic::analyzer::semantic::lowering::body_contains_matching_node(
        body,
        cancellation,
        |node| node.id() != body.id() && is_kotlin_nested_execution_boundary(node),
        |node| node.kind() == "this_expression",
    )
}

/// The declaration container a node opens, if any.
pub(in crate::analyzer::kotlin::semantic) fn declaration_container_kind(
    node: Node<'_>,
) -> Option<DeclarationSegmentKind> {
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
pub(in crate::analyzer::kotlin::semantic) fn declaration_container_name(
    source: &str,
    node: Node<'_>,
) -> Option<Box<str>> {
    child_of_kind(node, "type_identifier")
        .and_then(|name| nonempty_node_text(source, name))
        .map(Box::<str>::from)
}

/// Whether a declaration sits at a declaration site (a type body or the file)
/// rather than inside an executable body.
///
/// Kotlin reuses `property_declaration`, `getter`, and `setter` for both, so
/// the enclosing syntax is what separates a member from an ordinary statement.
pub(in crate::analyzer::kotlin::semantic) fn is_declaration_site(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        matches!(
            parent.kind(),
            "class_body" | "enum_class_body" | "source_file"
        )
    })
}

/// The value-producing expression a `property_declaration` initializes with,
/// skipping the binding, its type, and any accessors.
pub(in crate::analyzer::kotlin::semantic) fn property_initializer(
    node: Node<'_>,
) -> Option<Node<'_>> {
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

pub(super) use brokk_bifrost_jvm::kotlin::syntax::kotlin_parameter_default as class_parameter_default;

/// How a `function_body` (or accessor body) carries its statements.
#[derive(Debug, Clone, Copy)]
pub(in crate::analyzer::kotlin::semantic) enum BodyShape<'tree> {
    /// `{ … }` — a `statements` list.
    Block(Node<'tree>),
    /// `= expr` — one expression whose value is the result.
    Expression(Node<'tree>),
    /// `{}` — no executable syntax.
    Empty,
}

pub(in crate::analyzer::kotlin::semantic) fn function_body_shape(body: Node<'_>) -> BodyShape<'_> {
    match first_named_child(body) {
        Some(child) if child.kind() == "statements" => BodyShape::Block(child),
        Some(child) => BodyShape::Expression(child),
        None => BodyShape::Empty,
    }
}

/// Unwrap a `control_structure_body` to the syntax that actually executes: the
/// `statements` list of a block, or the single statement of a bodyless arm.
pub(in crate::analyzer::kotlin::semantic) fn control_structure_body_content(
    node: Node<'_>,
) -> Option<Node<'_>> {
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
/// The type declaration a member belongs to, stopping at the first enclosing
/// body so a nested class does not answer for its outer class.
pub(in crate::analyzer::kotlin::semantic) fn enclosing_type_declaration(
    node: Node<'_>,
) -> Option<Node<'_>> {
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
pub(in crate::analyzer::kotlin::semantic) fn type_admits_overrides(declaration: Node<'_>) -> bool {
    if declaration.kind() != "class_declaration" {
        // `object`, `companion object`, and anonymous object literals cannot be
        // subclassed, so their members are never overridden.
        return false;
    }
    has_token(declaration, "interface")
        || has_modifier(declaration, "open")
        || has_modifier(declaration, "abstract")
        || has_modifier(declaration, "sealed")
}

/// Whether a `navigation_expression` selects through the null-safe `?.`
/// operator rather than the ordinary `.`.
pub(in crate::analyzer::kotlin::semantic) fn is_safe_navigation(node: Node<'_>) -> bool {
    node.kind() == "navigation_expression"
        && child_of_kind(node, "navigation_suffix").is_some_and(|suffix| has_token(suffix, "?."))
}

/// The member selected by a `navigation_expression`.
/// The operand of a `postfix_expression` or `prefix_expression`.
pub(in crate::analyzer::kotlin::semantic) fn unary_operand(node: Node<'_>) -> Option<Node<'_>> {
    named_children(node)
        .into_iter()
        .find(|child| !matches!(child.kind(), "annotation" | "label"))
}

/// The two operands of a binary-shaped node, in source order.
pub(in crate::analyzer::kotlin::semantic) fn binary_operands(node: Node<'_>) -> Vec<Node<'_>> {
    named_children(node)
        .into_iter()
        .filter(|child| !is_type_syntax(child.kind()) && child.kind() != "annotation")
        .collect()
}

pub(in crate::analyzer::kotlin::semantic) fn is_type_syntax(kind: &str) -> bool {
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
pub(in crate::analyzer::kotlin::semantic) fn runtime_expression_children(
    node: Node<'_>,
) -> Vec<Node<'_>> {
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
pub(in crate::analyzer::kotlin::semantic) fn label_text<'source>(
    source: &'source str,
    label: Node<'_>,
) -> Option<&'source str> {
    let text = nonempty_node_text(source, label)?;
    Some(text.strip_suffix('@').unwrap_or(text))
}

/// The label a `jump_expression` names, if it names one.
pub(in crate::analyzer::kotlin::semantic) fn jump_label<'tree>(
    node: Node<'tree>,
) -> Option<Node<'tree>> {
    child_of_kind(node, "label")
}

/// The value a `jump_expression` carries, if it carries one.
pub(in crate::analyzer::kotlin::semantic) fn jump_operand<'tree>(
    node: Node<'tree>,
) -> Option<Node<'tree>> {
    named_children(node)
        .into_iter()
        .find(|child| child.kind() != "label")
}

/// The subject a `when` switches on.
pub(in crate::analyzer::kotlin::semantic) fn when_subject_expression(
    node: Node<'_>,
) -> Option<Node<'_>> {
    child_of_kind(node, "when_subject").and_then(|subject| {
        named_children(subject)
            .into_iter()
            .find(|child| child.kind() != "annotation")
    })
}

pub(in crate::analyzer::kotlin::semantic) fn when_entries(node: Node<'_>) -> Vec<Node<'_>> {
    named_children(node)
        .into_iter()
        .filter(|child| child.kind() == "when_entry")
        .collect()
}

pub(in crate::analyzer::kotlin::semantic) fn when_entry_conditions(
    entry: Node<'_>,
) -> Vec<Node<'_>> {
    named_children(entry)
        .into_iter()
        .filter(|child| child.kind() == "when_condition")
        .collect()
}

pub(in crate::analyzer::kotlin::semantic) fn when_entry_guard(entry: Node<'_>) -> Option<Node<'_>> {
    child_of_kind(entry, "guard_condition").and_then(first_named_child)
}

pub(in crate::analyzer::kotlin::semantic) fn when_entry_body(entry: Node<'_>) -> Option<Node<'_>> {
    child_of_kind(entry, "control_structure_body")
}

/// The runtime expression a `when` condition evaluates, if it has one.
///
/// `is T` carries only type syntax, so it has no operand; `in a..b` evaluates
/// the range it tests against.
pub(in crate::analyzer::kotlin::semantic) fn when_condition_operand(
    condition: Node<'_>,
) -> Option<Node<'_>> {
    let inner = first_named_child(condition)?;
    match inner.kind() {
        "type_test" => None,
        "range_test" => first_named_child(inner),
        _ => Some(inner),
    }
}

/// The three positional slots of a `for (binding in iterable) body`.
pub(in crate::analyzer::kotlin::semantic) fn for_statement_parts<'tree>(
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
pub(in crate::analyzer::kotlin::semantic) fn while_statement_parts<'tree>(
    node: Node<'tree>,
) -> Option<(Node<'tree>, Option<Node<'tree>>)> {
    loop_statement_condition_and_body(node)
}

/// The optional body and condition of a `do … while`.
pub(in crate::analyzer::kotlin::semantic) fn do_while_statement_parts<'tree>(
    node: Node<'tree>,
) -> Option<(Option<Node<'tree>>, Node<'tree>)> {
    let (condition, body) = loop_statement_condition_and_body(node)?;
    Some((body, condition))
}

fn loop_statement_condition_and_body<'tree>(
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

/// The target and value of an `assignment`.
pub(in crate::analyzer::kotlin::semantic) fn assignment_parts<'tree>(
    node: Node<'tree>,
) -> Option<(Node<'tree>, Option<Node<'tree>>)> {
    let children = named_children(node);
    let target = *children.first()?;
    let value = children.get(1).copied();
    Some((target, value))
}

/// Whether an `assignment` uses a compound operator (`+=`, `-=`, `*=`, `/=`,
/// `%=`). The grammar spells the operator as an anonymous token.
pub(in crate::analyzer::kotlin::semantic) fn is_compound_assignment(node: Node<'_>) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|child| !child.is_named() && matches!(child.kind(), "+=" | "-=" | "*=" | "/=" | "%="))
}

/// How a `directly_assignable_expression` names its destination.
#[derive(Debug, Clone, Copy)]
pub(in crate::analyzer::kotlin::semantic) enum AssignmentTarget<'tree> {
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

pub(in crate::analyzer::kotlin::semantic) fn assignment_target(
    node: Node<'_>,
) -> AssignmentTarget<'_> {
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
pub(in crate::analyzer::kotlin::semantic) fn indexing_parts<'tree>(
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
/// One argument of a call, with the expansion and domain its syntax proves.
#[derive(Debug, Clone, Copy)]
pub(in crate::analyzer::kotlin::semantic) struct CallArgumentNode<'tree> {
    /// The expression evaluated for the argument. For a spread this is the
    /// spread operand, because `*` itself produces no value of its own.
    pub(in crate::analyzer::kotlin::semantic) value: Node<'tree>,
    /// The structured label node, when Kotlin binds this argument by keyword.
    pub(in crate::analyzer::kotlin::semantic) keyword: Option<Node<'tree>>,
    /// Whether the source spread an array into the positional tail.
    pub(in crate::analyzer::kotlin::semantic) spread: bool,
}

impl CallArgumentNode<'_> {
    pub(in crate::analyzer::kotlin::semantic) fn expansion(self) -> CallArgumentExpansion {
        let domain = if self.keyword.is_some() {
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
pub(in crate::analyzer::kotlin::semantic) fn value_argument_parts(
    argument: Node<'_>,
) -> Option<CallArgumentNode<'_>> {
    let children = named_children(argument)
        .into_iter()
        .filter(|child| child.kind() != "annotation")
        .collect::<Vec<_>>();
    let value = children.last().copied()?;
    let keyword = (children.len() >= 2 && kotlin_named_argument_label(argument, children[0]))
        .then_some(children[0]);
    debug_assert!(
        children.len() < 2 || keyword.is_some(),
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
pub(in crate::analyzer::kotlin::semantic) fn value_argument_value(
    argument: Node<'_>,
) -> Option<Node<'_>> {
    value_argument_parts(argument).map(|argument| argument.value)
}

/// Argument expressions of a call, trailing lambda included.
///
/// A trailing lambda is bound positionally to the callee's last parameter, so
/// it joins the list as an ordinary direct positional argument.
pub(in crate::analyzer::kotlin::semantic) fn call_arguments(
    call: Node<'_>,
) -> Vec<CallArgumentNode<'_>> {
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
        keyword: None,
        spread: false,
    }));
    arguments
}

/// The `annotated_lambda` label a `return@label` inside a trailing lambda can
/// name: an explicit `forEach lbl@{ … }`, or the implicit label formed from the
/// callee's simple name.
pub(in crate::analyzer::kotlin::semantic) fn lambda_boundary_label<'source>(
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
pub(in crate::analyzer::kotlin::semantic) fn value_is_used(node: Node<'_>) -> bool {
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
pub(in crate::analyzer::kotlin::semantic) fn result_expression(node: Node<'_>) -> Option<Node<'_>> {
    let content = control_structure_body_content(node)?;
    if content.kind() == "statements" {
        return named_children(content).last().copied();
    }
    Some(content)
}

/// The scope a local binding is visible in.
pub(in crate::analyzer::kotlin::semantic) fn kotlin_local_scope(
    node: Node<'_>,
) -> Option<(usize, usize)> {
    brokk_bifrost_core::analyzer::tree_walk::find_ancestor(node, |parent| {
        matches!(
            parent.kind(),
            "statements"
                | "control_structure_body"
                | "when_entry"
                | "catch_block"
                | "for_statement"
        ) || is_kotlin_nested_execution_boundary(parent)
    })
    .map(|scope| (scope.start_byte(), scope.end_byte()))
}

pub(in crate::analyzer::kotlin::semantic) fn expression_value_kind(
    node: Node<'_>,
) -> SemanticValueKind {
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

/// Refine a generic expression value with the exact constants Kotlin's
/// grammar represents structurally. A literal inferred through a non-literal
/// expression is deliberately left generic; callers must have a declaration
/// type or one of these literal nodes before publishing scalar facts.
pub(in crate::analyzer::kotlin::semantic) fn typed_expression_value_kind(
    source: &str,
    node: Node<'_>,
) -> SemanticValueKind {
    if let Some((value, suffix)) = kotlin_integer_literal_value(node, source)
        && (!suffix.is_unsigned() || (0..=u64::MAX as i128).contains(&value))
    {
        return if value < 0 {
            SemanticValueKind::SignedInteger(value)
        } else {
            SemanticValueKind::UnsignedInteger(value as u128)
        };
    }
    if node.kind() == "boolean_literal"
        && let Some(value) = node_text(source, node).and_then(|text| match text {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        })
    {
        return SemanticValueKind::Boolean(value);
    }
    expression_value_kind(node)
}

/// Leaves with no further runtime structure to schedule.
pub(in crate::analyzer::kotlin::semantic) fn is_runtime_leaf(kind: &str) -> bool {
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
pub(in crate::analyzer::kotlin::semantic) fn is_inert_statement(kind: &str) -> bool {
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

pub(in crate::analyzer::kotlin::semantic) fn required_child<'tree>(
    node: Node<'tree>,
    slot: &str,
) -> Result<Node<'tree>, KotlinLoweringError> {
    brokk_bifrost_semantic::analyzer::semantic::lowering::required_field_or_else(
        node,
        slot,
        missing_slot,
    )
}

pub(in crate::analyzer::kotlin::semantic) fn missing_slot(
    node: Node<'_>,
    slot: &str,
) -> KotlinLoweringError {
    KotlinLoweringError::Invalid(format!(
        "{} node at bytes {}..{} is missing structured {slot}",
        node.kind(),
        node.start_byte(),
        node.end_byte()
    ))
}

pub(super) use brokk_bifrost_core::analyzer::tree_walk::node_range;

/// Procedure syntax roles for the Kotlin lowering. Every child of a
/// `statements` block, and a non-block loop or branch body, is a statement;
/// statement labels are siblings peeled off before lowering. `for` iterates
/// and is not a conditional loop.
pub(crate) const PROCEDURE_SYNTAX_ROLES:
    brokk_bifrost_analysis::analyzer::languages::ProcedureSyntaxRoles =
    brokk_bifrost_analysis::analyzer::languages::ProcedureSyntaxRoles {
        statement_kind: kotlin_statement_kind,
        loop_site: |node| {
            use brokk_bifrost_analysis::analyzer::loop_facts::LoopKind;

            use brokk_bifrost_analysis::analyzer::loop_facts::LoopSyntax;
            match node.kind() {
                "while_statement" => {
                    let (condition, body) = while_statement_parts(node)?;
                    Some(LoopSyntax {
                        kind: LoopKind::While,
                        body,
                        condition: Some(condition),
                    })
                }
                "do_while_statement" => {
                    let (body, condition) = do_while_statement_parts(node)?;
                    Some(LoopSyntax {
                        kind: LoopKind::Do,
                        body,
                        condition: Some(condition),
                    })
                }
                _ => None,
            }
        },
        loop_site_with_source: None,
        // Initializer procedures (class properties, primary-constructor
        // defaults, enum entries) have expression bodies and no statements.
        procedure_matches: |_, node| {
            matches!(
                node.kind(),
                "function_declaration"
                    | "secondary_constructor"
                    | "anonymous_initializer"
                    | "getter"
                    | "setter"
                    | "lambda_literal"
                    | "anonymous_function"
                    | "property_declaration"
                    | "class_parameter"
                    | "enum_entry"
            )
        },
        nested_procedure: |node| {
            matches!(
                node.kind(),
                "function_declaration"
                    | "secondary_constructor"
                    | "anonymous_initializer"
                    | "getter"
                    | "setter"
                    | "lambda_literal"
                    | "anonymous_function"
                    | "class_declaration"
                    | "object_declaration"
                    | "object_literal"
                    | "class_body"
            )
        },
    };

fn kotlin_statement_kind(node: Node<'_>) -> Option<&'static str> {
    let parent = node.parent()?;
    let in_block = parent.kind() == "statements";
    let single_body = parent.kind() == "control_structure_body" && node.kind() != "statements";
    if !(in_block || single_body)
        || is_inert_statement(node.kind())
        || matches!(node.kind(), "label" | "line_comment" | "multiline_comment")
    {
        return None;
    }
    Some(match node.kind() {
        "jump_expression" => {
            let keyword = node.child(0)?.kind();
            if keyword.starts_with("return") {
                "return"
            } else if keyword.starts_with("throw") {
                "throw"
            } else if keyword.starts_with("break") {
                "break"
            } else if keyword.starts_with("continue") {
                "continue"
            } else {
                "expression"
            }
        }
        "property_declaration" | "destructuring_declaration" => "local_declaration",
        "while_statement" => "while",
        "do_while_statement" => "do",
        "for_statement" => "enhanced_for",
        "if_expression" => "if",
        "when_expression" => "switch",
        "try_expression" => "try",
        _ => "expression",
    })
}
