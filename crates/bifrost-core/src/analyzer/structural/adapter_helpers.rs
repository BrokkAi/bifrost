//! Small utilities for structural-search language adapters.
//!
//! These helpers are intentionally limited to mechanics that are identical
//! across adapters. Grammar-specific decisions, such as how an expression's
//! terminal name is found, stay in the language adapter.

use super::facts::{IntegerLiteralValue, Span, decode_integer_literal_digits};
use super::kinds::Role;
use super::spec::RoleSink;
use crate::analyzer::common::node_source_text;
pub use crate::analyzer::tree_walk::node_range;
use crate::analyzer::tree_walk::{expression_target_node, last_named_child, named_children_iter};
use tree_sitter::Node;

/// Assert that every grammar node name in a language adapter's kind table
/// exists in the grammar used by that adapter.
#[cfg(feature = "test-support")]
pub fn assert_kind_table_matches_grammar(
    grammar: tree_sitter::Language,
    grammar_name: &str,
    table: &[(&str, super::kinds::NormalizedKind)],
) {
    for (name, kind) in table {
        assert_ne!(
            grammar.id_for_node_kind(name, true),
            0,
            "node type {name:?} (mapped to {kind:?}) does not exist in {grammar_name}"
        );
    }
}

/// The boolean value of an AST-selected `true` or `false` literal spelling.
pub fn boolean_literal_value(spelling: &str) -> Option<bool> {
    match spelling {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// The byte span inside a string node's opening and closing delimiters.
/// Callers check the language-specific node kind before using this arithmetic.
pub fn unquoted_string_content_span(node: Node<'_>) -> Option<Span> {
    let start = node.start_byte().checked_add(1)?;
    let end = node.end_byte().checked_sub(1)?;
    (start <= end).then_some(Span {
        start_byte: start,
        end_byte: end,
    })
}

/// The nearest ancestor of `node` (inclusive of its parent chain, exclusive of
/// `node` itself) whose grammar kind `accept` admits.
///
/// Every adapter's binding-activation hook asks the same question -- "which
/// binding form does this token belong to?" -- and answers it by climbing the
/// parent chain, so the climb itself is shared and only the predicate is
/// grammar knowledge.
pub fn nearest_ancestor<'tree>(
    node: Node<'tree>,
    accept: impl FnMut(&str) -> bool,
) -> Option<Node<'tree>> {
    nearest_ancestor_with(node, |node| node.parent(), accept)
}

/// The nearest ancestor selected with a caller-provided parent lookup.
///
/// This keeps the traversal shared for callers that already maintain a parent
/// index, while `nearest_ancestor` uses tree-sitter's parent links directly.
pub fn nearest_ancestor_with<'tree>(
    node: Node<'tree>,
    mut parent_of: impl FnMut(Node<'tree>) -> Option<Node<'tree>>,
    mut accept: impl FnMut(&str) -> bool,
) -> Option<Node<'tree>> {
    let mut current = node;
    while let Some(parent) = parent_of(current) {
        if accept(parent.kind()) {
            return Some(parent);
        }
        current = parent;
    }
    None
}

/// The grammar field name `child` occupies in `parent`, or `None` when the
/// child is unnamed-positional. Occurrence-role classification is written
/// against AST fields, so every adapter needs this exact question answered.
///
/// Walked with a cursor, not indexed. `Node::child(i)` re-descends the child
/// list from the start on every call -- and must step through invisible nodes
/// to reach the i-th visible one -- so indexing `0..child_count` is quadratic
/// in the child count and superlinear in the subtree those children span. A
/// cursor advances to the next sibling in constant time, which makes the scan
/// linear. This runs for every occurrence-role classification in every
/// language adapter, so the difference is not academic: it was 98% of the
/// fuzzer's CPU on a wide-node file.
pub fn field_name_in_parent(parent: Node<'_>, child: Node<'_>) -> Option<&'static str> {
    let mut cursor = parent.walk();
    if !cursor.goto_first_child() {
        return None;
    }
    loop {
        if cursor.node() == child {
            return cursor.field_name();
        }
        if !cursor.goto_next_sibling() {
            return None;
        }
    }
}

/// Whether `child` occupies `parent`'s `field`.
pub fn is_field_of(parent: Node<'_>, child: Node<'_>, field: &str) -> bool {
    field_name_in_parent(parent, child) == Some(field)
}

pub fn first_named_child<'tree>(node: Node<'tree>) -> Option<Node<'tree>> {
    node.named_child(0)
}

/// The short-circuit boolean operator selected by a binary expression's
/// `operator` field.
pub fn short_circuit_operator(node: Node<'_>) -> Option<&'static str> {
    match node.child_by_field_name("operator")?.kind() {
        "&&" => Some("&&"),
        "||" => Some("||"),
        _ => None,
    }
}

/// Return an if-expression's alternative body, unwrapping an `else_clause`.
/// Else-if nodes are returned unchanged.
pub fn if_alternative_body<'tree>(if_node: Node<'tree>) -> Option<Node<'tree>> {
    let alternative = if_node.child_by_field_name("alternative")?;
    if alternative.kind() == "else_clause" {
        alternative
            .child_by_field_name("body")
            .or_else(|| alternative.named_child(0))
    } else {
        Some(alternative)
    }
}

/// Return the expression assigned by a declarator's initializer clause.
///
/// C#'s grammar has used both named `value`/`initializer` fields and an
/// `equals_value_clause` wrapper across the supported grammar releases. The
/// tree-shape fallback is shared so declaration extraction and source-backed
/// structural relations answer the same question.
pub fn declarator_initializer(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("value")
        .or_else(|| node.child_by_field_name("initializer"))
        .or_else(|| {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find(|child| child.kind() == "equals_value_clause")
                .and_then(|clause| {
                    clause
                        .child_by_field_name("value")
                        .or_else(|| clause.named_child(0))
                })
        })
        .or_else(|| {
            let name = node.child_by_field_name("name")?;
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find(|child| child.start_byte() > name.end_byte())
        })
}

/// Decode the C# integer-literal token forms shared by the structural adapter
/// and source-backed C# relations. Syntax selection remains the caller's AST
/// work; this helper only classifies an already-selected literal value.
pub fn csharp_integer_literal_value(node: Node<'_>, source: &str) -> Option<IntegerLiteralValue> {
    let literal = if node.kind() == "prefix_unary_expression" {
        let operator = node.child(0)?;
        if !matches!(operator.kind(), "+" | "-") {
            return None;
        }
        let literal = last_named_child(node).map(expression_target_node)?;
        let value = decode_csharp_integer_literal_value(literal, source)?;
        return if operator.kind() == "-" {
            Some(value.negated())
        } else {
            Some(value)
        };
    } else {
        node
    };
    decode_csharp_integer_literal_value(literal, source)
}

fn decode_csharp_integer_literal_value(
    literal: Node<'_>,
    source: &str,
) -> Option<IntegerLiteralValue> {
    if literal.kind() != "integer_literal" {
        return None;
    }
    let text = node_source_text(literal, source);
    let suffix_len = text
        .bytes()
        .rev()
        .take_while(|byte| matches!(byte, b'u' | b'U' | b'l' | b'L'))
        .count();
    if suffix_len > 2 {
        return None;
    }
    let text = text.get(..text.len().checked_sub(suffix_len)?)?;
    let (radix, digits) = match text.as_bytes() {
        [b'0', b'x' | b'X', rest @ ..] => (16, rest),
        [b'0', b'b' | b'B', rest @ ..] => (2, rest),
        _ => (10, text.as_bytes()),
    };
    decode_integer_literal_digits(radix, digits)
}
/// Prefer a grammar field, then the first direct named child.
pub fn child_by_field_or_first_named_child<'tree>(
    node: Node<'tree>,
    field: &str,
) -> Option<Node<'tree>> {
    node.child_by_field_name(field)
        .or_else(|| first_named_child(node))
}

pub fn attach_role_with_derived_name<'tree>(
    sink: &mut RoleSink<'_>,
    role: Role,
    target: Node<'tree>,
    name_of: impl FnOnce(Node<'tree>) -> Option<Node<'tree>>,
) {
    sink.role_maybe_named(role, target, name_of(target));
}

pub fn attach_argument_role_with_derived_name<'tree>(
    sink: &mut RoleSink<'_>,
    argument: Node<'tree>,
    name_of: impl FnOnce(Node<'tree>) -> Option<Node<'tree>>,
) {
    sink.argument_maybe_named(
        argument,
        name_of(argument),
        is_spread_argument_node(argument),
    );
}

/// Attach decorator roles found under a grammar-specific declaration child.
/// Adapters supply the grammar's container and decorator kinds; the traversal
/// and role attachment are shared.
pub fn attach_decorators_under<'tree>(
    sink: &mut RoleSink<'_>,
    declaration: Node<'tree>,
    container_kind: &str,
    decorator_kinds: &[&str],
    name_of: impl Fn(Node<'tree>) -> Option<Node<'tree>> + Copy,
) {
    for container in named_children_iter(declaration) {
        if container.kind() != container_kind {
            continue;
        }
        for decorator in named_children_iter(container) {
            if decorator_kinds.contains(&decorator.kind()) {
                attach_role_with_derived_name(sink, Role::Decorator, decorator, name_of);
            }
        }
    }
}

pub fn is_spread_argument_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "spread_element"
            | "splat_argument"
            | "hash_splat_argument"
            | "list_splat"
            | "dictionary_splat"
            | "spread_expression"
            | "spread_argument"
            | "variadic_argument"
            | "variadic_unpacking"
    ) || (node.kind() == "argument"
        && (0..node.named_child_count())
            .filter_map(|index| node.named_child(index))
            .any(|child| child.kind() == "variadic_unpacking"))
}

pub fn attach_positional_argument_roles<'tree, F>(
    sink: &mut RoleSink<'_>,
    arguments: Node<'tree>,
    name_of: F,
) where
    F: Fn(Node<'tree>) -> Option<Node<'tree>> + Copy,
{
    for argument in named_children_iter(arguments) {
        if !sink.should_continue() {
            break;
        }
        attach_argument_role_with_derived_name(sink, argument, name_of);
    }
}

/// Visit each named child in an argument list until the visitor says to stop.
/// Language adapters supply argument classification; the AST walk and cutoff
/// remain shared.
pub fn for_each_argument<'tree>(
    arguments: Node<'tree>,
    mut visit: impl FnMut(Node<'tree>) -> bool,
) {
    for argument in named_children_iter(arguments) {
        if !visit(argument) {
            break;
        }
    }
}

pub fn attach_terminal_callee<'tree>(
    sink: &mut RoleSink<'_>,
    expression: Node<'tree>,
    terminal_name: Option<Node<'tree>>,
) {
    if let Some(name) = terminal_name {
        if sink.should_continue() {
            sink.role_named(Role::Callee, name, name);
            sink.set_name(name);
        }
    } else {
        sink.role(Role::Callee, expression);
    }
}

/// Climb from a segment token to the outermost node of the left-nested
/// qualified chain it participates in (`scoped_identifier`,
/// `nested_identifier`, and language equivalents). `None` when the token sits
/// in no chain node at all — a bare identifier is not a path.
pub fn qualified_chain_root<'tree>(
    token: Node<'tree>,
    chain: &[(&str, Option<&str>)],
) -> Option<Node<'tree>> {
    let mut root = token;
    while let Some(parent) = root.parent() {
        if chain.iter().any(|(kind, _)| *kind == parent.kind()) {
            root = parent;
        } else {
            break;
        }
    }
    (root.id() != token.id()).then_some(root)
}

/// Climb from a named type or value token to the qualified chain it belongs
/// to. Every adapter accepts the same terminal token kinds; only its chain
/// table is grammar-specific.
pub fn qualified_path_chain_root<'tree>(
    token: Node<'tree>,
    chain: &[(&str, Option<&str>)],
) -> Option<Node<'tree>> {
    if !matches!(token.kind(), "identifier" | "type_identifier") {
        return None;
    }
    qualified_chain_root(token, chain)
}

/// The ordered segment tokens of the left-nested chain rooted at `root`.
///
/// `chain` pairs each chain node kind with the field that names its own
/// segment (`scoped_identifier`/`name`, `nested_identifier`/`property`), or
/// `None` for a chain node without fields whose segment is positionally its
/// last named child (Java's `scoped_type_identifier`); the remaining named
/// child is the next outer-to-inner link, ending at the head token. A
/// link wrapped in one of `unwrap_kinds` (Rust's turbofish
/// `generic_type` inside a path) is unwrapped to the type or function it
/// wraps. Reads AST fields only; an unexpected shape yields an empty vector,
/// which the derivation layer reports as an unenumerable chain rather than a
/// partial ordering.
pub fn linear_chain_tokens<'tree>(
    root: Node<'tree>,
    chain: &[(&str, Option<&str>)],
    unwrap_kinds: &[&str],
) -> Vec<Node<'tree>> {
    let mut tokens = Vec::new();
    let mut current = root;
    loop {
        let Some(&(_, name_field)) = chain.iter().find(|(kind, _)| *kind == current.kind()) else {
            tokens.push(current);
            break;
        };
        let Some(name) = chain_name_child(current, name_field) else {
            return Vec::new();
        };
        tokens.push(name);
        let mut scope = None;
        let mut cursor = current.walk();
        for child in current.named_children(&mut cursor) {
            if child.id() != name.id() {
                scope = Some(child);
                break;
            }
        }
        drop(cursor);
        let Some(mut scope) = scope else {
            return Vec::new();
        };
        while unwrap_kinds.contains(&scope.kind()) {
            let mut cursor = scope.walk();
            let inner = scope
                .named_children(&mut cursor)
                .find(|child| child.kind() != "type_arguments");
            match inner {
                Some(inner) => scope = inner,
                None => return Vec::new(),
            }
        }
        current = scope;
    }
    tokens.reverse();
    tokens
}

/// The number of generic (type) arguments the source spells at `token`'s
/// segment position: climb the chain while the token remains the chain's own
/// name field, and when the enclosing node is one of `wrapper_kinds`
/// (`generic_type`, `generic_function`), count the named children of its
/// `type_arguments` child. `None` when the source spells no arguments there.
pub fn spelled_generic_arity(
    token: Node<'_>,
    chain: &[(&str, Option<&str>)],
    wrapper_kinds: &[&str],
) -> Option<u32> {
    let mut anchor = token;
    loop {
        let parent = anchor.parent()?;
        if let Some(&(_, name_field)) = chain.iter().find(|(kind, _)| *kind == parent.kind()) {
            if chain_name_child(parent, name_field).map(|name| name.id()) != Some(anchor.id()) {
                return None;
            }
            anchor = parent;
            continue;
        }
        if !wrapper_kinds.contains(&parent.kind()) {
            return None;
        }
        let mut cursor = parent.walk();
        let arguments = parent
            .named_children(&mut cursor)
            .find(|child| child.kind() == "type_arguments")?;
        let count = arguments.named_child_count();
        return Some(u32::try_from(count).expect("type argument count fits in u32"));
    }
}

/// The child that spells a chain node's own segment: the named field where the
/// grammar has one, otherwise the last named child (the positional convention
/// of field-less chain nodes such as Java's `scoped_type_identifier`).
///
/// Public because occurrence-role classification asks the same question the
/// chain walkers above do -- "is this token the chain node's own segment, or
/// one of its scope segments?" -- and a chain node without fields must not be
/// answered with a field lookup that is false for every child.
pub fn chain_name_child<'tree>(node: Node<'tree>, name_field: Option<&str>) -> Option<Node<'tree>> {
    match name_field {
        Some(field) => node.child_by_field_name(field),
        None => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor).last()
        }
    }
}

/// Grammar hooks describe one step; the shared loop owns callee traversal.
/// Immediate-child selection is needed where a grammar has no name field.
pub enum CalleeSpineStep {
    Name,
    Field(&'static str),
    ChildKind(&'static str),
    OnlyChild,
    FieldOrOnlyChild(&'static str),
}

/// Follow only the callee's member/name/wrapper spine. Calls, subscripts,
/// lambdas and other value expressions stop; their descendants cannot name
/// the declaration invoked by the enclosing call.
pub fn terminal_callee_leaf(
    mut node: Node<'_>,
    step: impl Fn(&str) -> Option<CalleeSpineStep>,
) -> Option<Node<'_>> {
    loop {
        node = match if node.kind() == "parenthesized_expression" {
            Some(CalleeSpineStep::OnlyChild)
        } else {
            step(node.kind())
        }? {
            CalleeSpineStep::Name => return Some(node),
            CalleeSpineStep::Field(field) => {
                crate::analyzer::tree_walk::last_named_field_child(node, field)?
            }
            CalleeSpineStep::ChildKind(kind) => {
                crate::analyzer::tree_walk::single_named_child_matching(node, |child| {
                    child.kind() == kind
                })?
            }
            CalleeSpineStep::OnlyChild => {
                crate::analyzer::tree_walk::single_named_child_matching(node, |_| true)?
            }
            CalleeSpineStep::FieldOrOnlyChild(field) => {
                node.child_by_field_name(field).or_else(|| {
                    crate::analyzer::tree_walk::single_named_child_matching(node, |_| true)
                })?
            }
        };
    }
}

/// Read direct grammar modifier tokens and modifier wrappers, excluding names,
/// annotations and declaration bodies. Adapters select the declaration owner.
pub fn declaration_modifier_words(node: Node<'_>, source: &str) -> Vec<String> {
    use crate::analyzer::tree_walk::children_iter;
    let container = children_iter(node).find(|child| child.kind() == "modifiers");
    let mut words = Vec::new();
    for child in children_iter(container.unwrap_or(node)) {
        let word = match child.kind() {
            "modifier" | "accessibility_modifier" => source.get(child.byte_range()),
            "static get" => Some("static"),
            "static" | "abstract" | "final" | "volatile" | "synchronized" | "transient"
            | "native" | "strictfp" | "default" | "sealed" | "non-sealed" | "public"
            | "protected" | "private" | "readonly" | "override" | "virtual" | "async"
            | "partial" | "unsafe" | "extern" | "new" | "required" => Some(child.kind()),
            _ => None,
        };
        if let Some(word) = word {
            words.push(word.to_owned());
        }
    }
    if node.kind() == "abstract_method_signature" && !words.iter().any(|word| word == "abstract") {
        words.push("abstract".to_owned());
    }
    words
}

/// Attach all children of each selected grammar field in source order.
pub fn attach_field_roles<'tree>(
    sink: &mut RoleSink<'_>,
    node: Node<'tree>,
    fields: &[(Role, &str)],
    derive_name: impl Fn(Node<'tree>) -> Option<Node<'tree>>,
) {
    for &(role, field) in fields {
        let mut cursor = node.walk();
        for child in node.children_by_field_name(field, &mut cursor) {
            attach_role_with_derived_name(sink, role, expression_target_node(child), &derive_name);
        }
    }
}
