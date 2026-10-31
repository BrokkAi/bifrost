//! Structured reads of the Kotlin syntax tree, shared by every Kotlin consumer.
//!
//! The `brokk-tree-sitter-kotlin` grammar
//! is field-poor: of everything this module reads, only `function_declaration`
//! and `property_declaration` carry a tree-sitter field (`receiver`). The callee
//! of a call, the member of a navigation, the label of a named argument, and the
//! segments of a dotted type are all recovered *positionally* from named
//! children.
//!
//! Positional reads are easy to get subtly wrong, and wrong in a way that fails
//! silently — a mis-read callee does not error, it just resolves nothing. So they
//! live here once rather than once per consumer. Definition navigation
//! (`crate::analyzer::usages::get_definition::kotlin`, issue #1238) and the usage
//! graphs (`crate::analyzer::usages::kotlin_graph`, issue #1239) both read the
//! grammar through this module, which is also what keeps them from disagreeing
//! about what a given syntax shape means.
//!
//! The shapes, as dumped from the pinned grammar:
//!
//! ```text
//! Base()              (call_expression (simple_identifier)
//!                        (call_suffix (value_arguments)))
//! base.greet("x")     (call_expression
//!                        (navigation_expression (simple_identifier)
//!                          (navigation_suffix (simple_identifier)))
//!                        (call_suffix (value_arguments
//!                          (value_argument (string_literal)))))
//! lib.Base            (user_type (type_identifier) (type_identifier))
//! lib.Base?           (nullable_type (user_type (type_identifier)
//!                        (type_identifier)) (quest))
//! foo(name = 1)       (value_argument (simple_identifier) (integer_literal))
//! import a.b.C as D   (import_header (identifier (simple_identifier)
//!                        (simple_identifier) (simple_identifier))
//!                        (import_alias (type_identifier)))
//! ```
//!
//! Note in particular that a dotted type name is *one* `user_type` node with one
//! `type_identifier` child per segment, not a nested or scoped node. Nothing here
//! splits source text on `.` or `::` to recover that structure.

use brokk_bifrost_core::analyzer::tree_walk::{
    first_named_child_of_kind, is_comment_kind, named_children,
};
use brokk_bifrost_core::analyzer::usages::common::node_text;
use tree_sitter::Node;

/// Whether a `this@Label` label names an owner's simple name.
pub fn kotlin_owner_label_matches(owner_simple_name: &str, label: &str) -> bool {
    owner_simple_name == label
}

/// The callee expression of a Kotlin call.
///
/// A `call_expression`'s children are the callee followed by `call_suffix`, and a
/// `constructor_invocation` (a supertype list entry such as `: Base(1)`) spells
/// its callee as the `user_type` it constructs followed by `value_arguments`.
/// Neither names the callee with a field, so the callee is "the first named child
/// that is not the argument suffix".
pub fn kotlin_callee(call: Node<'_>) -> Option<Node<'_>> {
    named_children(call)
        .into_iter()
        .find(|child| !matches!(child.kind(), "call_suffix" | "value_arguments"))
}

/// The `call_expression` whose callee is `node`, if `node` is a callee at all.
pub fn kotlin_call_with_callee(node: Node<'_>) -> Option<Node<'_>> {
    let call = node
        .parent()
        .filter(|parent| parent.kind() == "call_expression")?;
    (kotlin_callee(call)?.id() == node.id()).then_some(call)
}

/// The `value_arguments` node a Kotlin call passes its arguments in.
///
/// An ordinary call nests it inside `call_suffix`; a `constructor_invocation`
/// holds it directly.
pub fn kotlin_value_arguments(call: Node<'_>) -> Option<Node<'_>> {
    if let Some(arguments) = first_named_child_of_kind(call, "value_arguments") {
        return Some(arguments);
    }
    first_named_child_of_kind(call, "call_suffix")
        .and_then(|suffix| first_named_child_of_kind(suffix, "value_arguments"))
}

/// The first variable binding a Kotlin property or loop introduces.
pub fn kotlin_binding_node(node: Node<'_>) -> Option<Node<'_>> {
    named_children(node).into_iter().find(|child| {
        matches!(
            child.kind(),
            "variable_declaration" | "multi_variable_declaration"
        )
    })
}

/// The value-producing expression a Kotlin property initializes with.
///
/// The caller selects the child stream, including its comment policy. This
/// helper owns only the positional binding/initializer rules: declaration
/// metadata and non-initializer property children are skipped, and an
/// initializer is considered only after a binding has appeared.
pub fn kotlin_property_initializer<'tree>(
    children: impl IntoIterator<Item = Node<'tree>>,
) -> Option<Node<'tree>> {
    let mut seen_binding = false;
    for child in children {
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

/// The expression a delegated Kotlin property supplies after `by`.
pub fn kotlin_property_delegate_expression(property: Node<'_>) -> Option<Node<'_>> {
    let delegate = named_children(property)
        .into_iter()
        .find(|child| child.kind() == "property_delegate")?;
    named_children(delegate)
        .into_iter()
        .find(|child| !is_comment_kind(child.kind()))
}

/// How many arguments a call passes.
///
/// A trailing lambda (`items.forEach { … }`) is an argument even though it sits
/// outside the parentheses, so it counts: without it, every trailing-lambda call
/// would look like it passed one argument too few and would fail to match its own
/// overload.
pub fn kotlin_call_arity(call: Node<'_>) -> usize {
    let positional = kotlin_value_arguments(call)
        .map(|arguments| {
            named_children(arguments)
                .into_iter()
                .filter(|child| child.kind() == "value_argument")
                .count()
        })
        .unwrap_or(0);
    let trailing = first_named_child_of_kind(call, "call_suffix")
        .is_some_and(|suffix| first_named_child_of_kind(suffix, "annotated_lambda").is_some());
    positional + usize::from(trailing)
}

/// Whether `node` is the *label* of a named argument rather than its value.
///
/// `foo(name = 1)` is `(value_argument (simple_identifier) (integer_literal))`; a
/// positional `foo(name)` is `(value_argument (simple_identifier))`. The label is
/// therefore the first of two or more named children.
pub fn kotlin_named_argument_label(argument: Node<'_>, node: Node<'_>) -> bool {
    let children = named_children(argument);
    children.len() > 1 && children[0].id() == node.id()
}

/// The receiver expression a `navigation_expression` selects from.
pub fn kotlin_navigation_receiver(navigation: Node<'_>) -> Option<Node<'_>> {
    named_children(navigation)
        .into_iter()
        .find(|child| child.kind() != "navigation_suffix")
}

/// Whether a node kind spells `receiver.member`.
///
/// Two node kinds do. An ordinary member access is `navigation_expression`; the
/// *left-hand side of an assignment* is `directly_assignable_expression`, which
/// the grammar gives a distinct kind but the identical shape — a receiver
/// followed by `navigation_suffix`. Missing the second one would report a
/// property's reads and not its writes, even though Kotlin indexes one
/// declaration for both.
pub fn kotlin_is_navigation_kind(kind: &str) -> bool {
    matches!(
        kind,
        "navigation_expression" | "directly_assignable_expression"
    )
}

/// The member a navigation selects: the `simple_identifier` inside its
/// `navigation_suffix`.
///
/// `.` and `?.` produce the same shape, so a safe call reads exactly like a
/// plain one — which is correct, because a safe call names the same member.
pub fn kotlin_navigation_member(navigation: Node<'_>) -> Option<Node<'_>> {
    first_named_child_of_kind(navigation, "navigation_suffix")
        .and_then(|suffix| first_named_child_of_kind(suffix, "simple_identifier"))
}

/// The first anonymous token kind among a node's direct children.
pub fn kotlin_first_token(node: Node<'_>) -> Option<&'static str> {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .find(|child| !child.is_named())
        .map(|child| child.kind())
}

/// The `lambda_literal` a call passes outside its parentheses, if any.
pub fn kotlin_call_trailing_lambda_body(call: Node<'_>) -> Option<Node<'_>> {
    first_named_child_of_kind(call, "call_suffix")
        .and_then(|suffix| first_named_child_of_kind(suffix, "annotated_lambda"))
        .and_then(|annotated| first_named_child_of_kind(annotated, "lambda_literal"))
}

/// Every simple identifier introduced by a Kotlin binding, in source order.
pub fn kotlin_binding_name_nodes<'tree>(binding: Node<'tree>) -> Vec<Node<'tree>> {
    match binding.kind() {
        "variable_declaration" => first_named_child_of_kind(binding, "simple_identifier")
            .into_iter()
            .collect(),
        "multi_variable_declaration" => named_children(binding)
            .into_iter()
            .filter(|child| child.kind() == "variable_declaration")
            .filter_map(|declaration| first_named_child_of_kind(declaration, "simple_identifier"))
            .collect(),
        _ => Vec::new(),
    }
}

/// The identifier nodes of a dotted navigation, outermost qualifier first, when
/// every link of it is a plain name.
///
/// `lib.Base` yields the `lib` token then the `Base` token. `None` when any link
/// is something other than a name — `f().Base` spells no dotted name at all.
pub fn kotlin_dotted_navigation_segments(navigation: Node<'_>) -> Option<Vec<Node<'_>>> {
    kotlin_dotted_navigation_segments_with_max_depth(navigation, usize::MAX)
}

/// The dotted components of a navigation when every segment has a spelling.
pub fn kotlin_dotted_navigation_components(
    navigation: Node<'_>,
    source: &str,
) -> Option<Vec<String>> {
    let segments = kotlin_dotted_navigation_segments(navigation)?;
    let names: Vec<&str> = segments
        .iter()
        .map(|segment| node_text(*segment, source))
        .collect();
    (!names.iter().any(|name| name.is_empty()))
        .then(|| names.into_iter().map(str::to_string).collect())
}

/// The named type segments selected by a Kotlin class literal.
pub fn kotlin_class_literal_type_segments(literal: Node<'_>) -> Option<Vec<Node<'_>>> {
    match literal.kind() {
        "type_identifier" | "simple_identifier" => Some(vec![literal]),
        kind if kotlin_is_navigation_kind(kind) => kotlin_dotted_navigation_segments(literal),
        _ => None,
    }
}

/// The terminal token and ordered name tokens of a Kotlin constructor callee.
pub fn kotlin_constructed_type_name_nodes(callee: Node<'_>) -> Option<(Node<'_>, Vec<Node<'_>>)> {
    match callee.kind() {
        "simple_identifier" => Some((callee, vec![callee])),
        "user_type" => {
            let segments = kotlin_user_type_segments(callee);
            Some((*segments.last()?, segments))
        }
        kind if kotlin_is_navigation_kind(kind) => Some((
            kotlin_navigation_member(callee)?,
            kotlin_dotted_navigation_segments(callee)?,
        )),
        _ => None,
    }
}

/// The bounded form of [`kotlin_dotted_navigation_segments`].
pub fn kotlin_dotted_navigation_segments_with_max_depth(
    navigation: Node<'_>,
    max_navigation_depth: usize,
) -> Option<Vec<Node<'_>>> {
    let mut segments = Vec::new();
    let mut current = navigation;
    let mut depth = 0;
    loop {
        if depth >= max_navigation_depth {
            return None;
        }
        segments.push(kotlin_navigation_member(current)?);
        depth += 1;
        let receiver = kotlin_navigation_receiver(current)?;
        match receiver.kind() {
            kind if kotlin_is_navigation_kind(kind) => current = receiver,
            "simple_identifier" => {
                segments.push(receiver);
                break;
            }
            _ => return None,
        }
    }
    segments.reverse();
    Some(segments)
}

/// The node naming the type a *class literal* selects: the `C` of `C::class`, or
/// the `lib.D` of `lib.D::class`.
///
/// The grammar spells the two forms differently. A bare `C::class` is a
/// `callable_reference` whose left side is aliased to `type_identifier`, and a
/// qualified `lib.D::class` is a `navigation_expression` whose receiver carries
/// the dotted name. What both share, and what tells them from `C::member` and
/// `lib.D.member`, is the `class` keyword on the right: the grammar admits it in
/// place of the `simple_identifier` a member reference spells, and being a
/// keyword it is an anonymous node that no named-child lookup can see.
///
/// A *bound* literal (`x::class`, on a value) is spelled identically to `C::class`
/// and is not distinguishable here; the caller separates the two by asking whether
/// the leading name is a value binding in scope.
pub fn kotlin_class_literal_type(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "callable_reference" if selects_class_keyword(node) => {
            first_named_child_of_kind(node, "type_identifier")
        }
        kind if kotlin_is_navigation_kind(kind) => {
            let suffix = first_named_child_of_kind(node, "navigation_suffix")?;
            selects_class_keyword(suffix).then(|| kotlin_navigation_receiver(node))?
        }
        _ => None,
    }
}

/// Whether `node`'s last child is the `class` keyword.
fn selects_class_keyword(node: Node<'_>) -> bool {
    node.child_count()
        .checked_sub(1)
        .and_then(|last| node.child(last))
        .is_some_and(|last| last.kind() == "class")
}

/// How many wrapper layers `kotlin_unwrap_receiver` peels before giving up.
const MAX_RECEIVER_WRAPPER_DEPTH: usize = 32;

/// Strip the wrappers that do not change *what* a receiver denotes: `!!`
/// (`postfix_expression`) and redundant parentheses.
///
/// Iterative and depth-capped rather than recursive, per the repository's
/// stack-safety rule: `(((x)))!!` is legal Kotlin and a malformed tree can nest
/// further still.
pub fn kotlin_unwrap_receiver(node: Node<'_>) -> Node<'_> {
    let mut current = node;
    for _ in 0..MAX_RECEIVER_WRAPPER_DEPTH {
        let inner = match current.kind() {
            "postfix_expression" | "parenthesized_expression" => named_children(current)
                .into_iter()
                .find(|child| child.is_named() && child.kind() != "postfix_unary_operator"),
            _ => None,
        };
        match inner {
            Some(inner) => current = inner,
            None => break,
        }
    }
    current
}

/// The `type_identifier` children of a `user_type`, in source order.
///
/// One per dotted segment: `lib.Base` yields the `lib` token then the `Base`
/// token. `type_arguments` are deliberately excluded — a generic argument is a
/// type reference in its own right, reached by walking into it, not a segment of
/// the outer name.
pub fn kotlin_user_type_segments(user_type: Node<'_>) -> Vec<Node<'_>> {
    named_children(user_type)
        .into_iter()
        .filter(|child| child.kind() == "type_identifier")
        .collect()
}

/// Whether `node` is the name a declaration introduces rather than a reference to
/// something declared elsewhere.
pub fn kotlin_is_declaration_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    let expected_kind = match parent.kind() {
        "class_declaration" | "object_declaration" | "companion_object" | "type_alias"
        | "type_parameter" => "type_identifier",
        "function_declaration"
        | "variable_declaration"
        | "parameter"
        | "class_parameter"
        | "enum_entry"
        | "parameter_with_optional_type" => "simple_identifier",
        _ => return false,
    };
    node.kind() == expected_kind
        && first_named_child_of_kind(parent, expected_kind)
            .is_some_and(|name| name.id() == node.id())
}

/// The identifier a Kotlin declaration names.
///
/// No declaration carries a `name` field, so the name is "the first named child
/// of the declaration's name kind" -- the same positional rule
/// [`kotlin_is_declaration_name`] checks from the other direction. A
/// `property_declaration` holds its name one level down, inside its
/// `variable_declaration`.
///
/// Without this a caller that only has fields to go on falls back to searching
/// the declaration's text for the name, and a body that mentions the same name
/// -- `fun offset(n: Int) { this.offset = n }` -- answers first (#2712).
pub fn kotlin_declaration_name(declaration: Node<'_>) -> Option<Node<'_>> {
    match declaration.kind() {
        "class_declaration" | "object_declaration" => {
            first_named_child_of_kind(declaration, "type_identifier")
        }
        "function_declaration" => first_named_child_of_kind(declaration, "simple_identifier"),
        "property_declaration" => {
            let variables: Vec<Node<'_>> = named_children(declaration)
                .into_iter()
                .filter(|child| child.kind() == "variable_declaration")
                .collect();
            match variables.as_slice() {
                [variable] => first_named_child_of_kind(*variable, "simple_identifier"),
                // A destructuring property spells its names in a
                // `multi_variable_declaration`, and no single token is the
                // name of the declaration as a whole.
                _ => None,
            }
        }
        _ => None,
    }
}

/// The `import_header` enclosing `node`, if `node` sits inside an import.
///
/// A focus inside an import can land on the `identifier`'s `simple_identifier`,
/// on the `import_alias`'s `type_identifier`, or on the header itself.
pub fn kotlin_enclosing_import_header(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if candidate.kind() == "import_header" {
            return Some(candidate);
        }
        current = candidate.parent();
    }
    None
}

/// The dotted path segments of an `import_header`, in source order.
pub fn kotlin_import_header_segments(header: Node<'_>) -> Vec<Node<'_>> {
    let Some(path) = first_named_child_of_kind(header, "identifier") else {
        return Vec::new();
    };
    named_children(path)
        .into_iter()
        .filter(|child| child.kind() == "simple_identifier")
        .collect()
}

/// Whether a node kind can appear as the value half of a property declaration.
pub fn kotlin_is_expression_kind(kind: &str) -> bool {
    matches!(
        kind,
        "call_expression"
            | "navigation_expression"
            | "as_expression"
            | "simple_identifier"
            | "parenthesized_expression"
            | "postfix_expression"
            | "object_literal"
    )
}

/// How many type wrappers (`T?`, `(T)`, `T & Any`) one spelling walk unwraps
/// before giving up.
///
/// A written type nests wrappers only a handful deep in real source; the cap
/// exists so a pathological or recovery-mangled tree cannot make one lookup
/// unbounded.
const MAX_TYPE_WRAPPER_DEPTH: usize = 32;

/// The dotted nominal name a Kotlin type node spells, exactly as written.
///
/// `lib.Base` yields `"lib.Base"`, `Base?` yields `"Base"`, `List<String>`
/// yields `"List"`, and a shape that names no nominal type at all — a function
/// type, a star projection — yields `None`.
///
/// Nullability and generic arguments are dropped because what a consumer does
/// with this is *resolve* it: it is a name to look up in the writing file's
/// scope, not rendered source. The full written form is already carried by the
/// declaration's rendered signature label, so nothing is lost from the index.
/// Resolution deliberately stays with the consumer — a spelled type means
/// whatever the file that wrote it says it means, and resolving at index time
/// would bake in one file's imports.
///
/// The walk is iterative and depth-capped rather than recursive, per the
/// repository's stack-safety rule for analyzer tree walks.
pub fn kotlin_type_name_components(node: Node<'_>, source: &str) -> Option<Vec<String>> {
    let mut frontier = vec![node];
    for _ in 0..MAX_TYPE_WRAPPER_DEPTH {
        let mut next = Vec::new();
        for current in frontier {
            match current.kind() {
                "user_type" => {
                    let segments = kotlin_user_type_segments(current)
                        .into_iter()
                        .map(|segment| segment.utf8_text(source.as_bytes()).unwrap_or_default())
                        .filter(|segment| !segment.is_empty())
                        .map(str::to_string)
                        .collect::<Vec<_>>();
                    if !segments.is_empty() {
                        return Some(segments);
                    }
                }
                // Wrappers that hold the nominal type one level down. A
                // `type_projection` is how a generic argument is spelled, and
                // `receiver_type` is what the `receiver` field holds.
                "nullable_type" | "not_nullable_type" | "parenthesized_type" | "receiver_type"
                | "type_projection" => next.extend(named_children(current)),
                _ => {}
            }
        }
        if next.is_empty() {
            return None;
        }
        frontier = next;
    }
    None
}

/// The type parameters `node` declares, in declaration order.
///
/// Read from the `type_parameters` child rather than from a field, because the
/// grammar names no field for it. Both `class Box<T>` and `fun <T> f()` carry
/// it, and a declaration without the child writes no parameters at all.
pub fn kotlin_declared_type_parameter_names(node: Node<'_>, source: &str) -> Vec<String> {
    let Some(parameters) = first_named_child_of_kind(node, "type_parameters") else {
        return Vec::new();
    };
    named_children(parameters)
        .into_iter()
        .filter(|child| child.kind() == "type_parameter")
        .filter_map(|parameter| first_named_child_of_kind(parameter, "type_identifier"))
        .map(|name| name.utf8_text(source.as_bytes()).unwrap_or_default())
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect()
}

pub fn kotlin_type_spelling(node: Node<'_>, source: &str) -> Option<String> {
    kotlin_type_name_components(node, source).map(|components| components.join("."))
}

pub fn kotlin_declared_return_type_components(
    function: Node<'_>,
    source: &str,
) -> Option<Vec<String>> {
    kotlin_type_name_components(kotlin_declared_return_type_node(function)?, source)
}

/// The return-type node a `function_declaration` writes, or `None` when it
/// writes none.
///
/// The return type is the only bare type node among a function's children:
/// parameters live inside `function_value_parameters`, and an extension's
/// receiver sits behind the `receiver` field, which is why the receiver is
/// excluded by node identity rather than by position.
pub fn kotlin_declared_return_type_node(function: Node<'_>) -> Option<Node<'_>> {
    let receiver = function
        .child_by_field_name("receiver")
        .map(|node| node.id());
    named_children(function)
        .into_iter()
        .filter(|child| Some(child.id()) != receiver)
        .find(|child| KOTLIN_TYPE_NODE_KINDS.contains(&child.kind()))
}

pub fn kotlin_binding_type_components(binding: Node<'_>, source: &str) -> Option<Vec<String>> {
    kotlin_type_name_components(kotlin_binding_type_node(binding)?, source)
}

/// The name introduced by a Kotlin value declaration supported by usage scans.
pub fn kotlin_value_declaration_name(binding: Node<'_>, source: &str) -> Option<String> {
    if !matches!(
        binding.kind(),
        "variable_declaration" | "parameter" | "class_parameter" | "parameter_with_optional_type"
    ) {
        return None;
    }
    let name = first_named_child_of_kind(binding, "simple_identifier")?;
    let name = node_text(name, source);
    (!name.is_empty()).then(|| name.to_string())
}

/// The node kinds that spell a written Kotlin type.
pub const KOTLIN_TYPE_NODE_KINDS: &[&str] = &[
    "user_type",
    "nullable_type",
    "not_nullable_type",
    "function_type",
    "parenthesized_type",
];

/// The type node a binding writes, or `None` when it writes none.
///
/// A `variable_declaration` (`val base: Base`), a `class_parameter`
/// (`class D(val base: Base)`) and a `parameter` (`fun f(base: Base)`) all
/// spell the bound name first and the type after the `:`, so the written type
/// is the first named child of a type kind. A consumer that needs the type
/// *node* -- to classify it, rather than to render its name -- takes it from
/// here instead of re-deriving the position.
pub fn kotlin_binding_type_node(binding: Node<'_>) -> Option<Node<'_>> {
    named_children(binding)
        .into_iter()
        .find(|child| KOTLIN_TYPE_NODE_KINDS.contains(&child.kind()))
}

/// The Kotlin scalar types whose primitive operators have JVM scalar semantics.
///
/// This intentionally excludes nullable, unsigned, floating-point, character,
/// and user-defined types. Kotlin routes operators for those through calls or
/// representation-specific rules that the scalar solver cannot prove here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KotlinScalarType {
    Int,
    Long,
    Short,
    Byte,
    Boolean,
}

/// Classify a written Kotlin type when it is exactly one supported, non-nullable
/// scalar type. Qualified `kotlin.Int` spellings are accepted; aliases and
/// arbitrary qualified names remain unresolved and therefore open.
pub fn kotlin_declared_scalar_type(type_node: Node<'_>, source: &str) -> Option<KotlinScalarType> {
    let mut current = type_node;
    for _ in 0..MAX_TYPE_WRAPPER_DEPTH {
        match current.kind() {
            "user_type" => {
                let segments = kotlin_user_type_segments(current);
                let names = segments
                    .iter()
                    .filter_map(|segment| segment.utf8_text(source.as_bytes()).ok())
                    .collect::<Vec<_>>();
                return match names.as_slice() {
                    [name] => kotlin_scalar_type_name(name),
                    [prefix, name] if *prefix == "kotlin" => kotlin_scalar_type_name(name),
                    _ => None,
                };
            }
            // A nullable wrapper must stay open even when its inner type is a
            // supported scalar: nullability changes equality and comparison.
            "nullable_type" => return None,
            "parenthesized_type" | "not_nullable_type" => {
                current = named_children(current).into_iter().next()?;
            }
            _ => return None,
        }
    }
    None
}

fn kotlin_scalar_type_name(name: &str) -> Option<KotlinScalarType> {
    match name {
        "Int" => Some(KotlinScalarType::Int),
        "Long" => Some(KotlinScalarType::Long),
        "Short" => Some(KotlinScalarType::Short),
        "Byte" => Some(KotlinScalarType::Byte),
        "Boolean" => Some(KotlinScalarType::Boolean),
        _ => None,
    }
}

/// The suffix written on a Kotlin integer literal, independent of its value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KotlinIntegerSuffix {
    None,
    Long,
    Unsigned,
    UnsignedLong,
}

impl KotlinIntegerSuffix {
    pub fn is_unsigned(self) -> bool {
        matches!(self, Self::Unsigned | Self::UnsignedLong)
    }
}

/// Decode an AST-selected decimal, hexadecimal or binary integer literal.
/// Unary signs are folded iteratively; range and suffix applicability belong
/// to the caller, since a numeric value alone does not establish a Kotlin type.
pub fn kotlin_integer_literal_value(
    node: Node<'_>,
    source: &str,
) -> Option<(i128, KotlinIntegerSuffix)> {
    let prefixed = node.kind() == "prefix_expression";
    let mut node = node;
    let mut negative = false;
    while node.kind() == "prefix_expression" && node.named_child_count() == 1 {
        let operator = node
            .children(&mut node.walk())
            .find(|child| !child.is_named())
            .map(|child| child.kind())?;
        match operator {
            "+" => {}
            "-" => negative = !negative,
            _ => return None,
        }
        node = node.named_child(0).expect("one prefix operand");
    }
    let (literal, suffix) = match node.kind() {
        "integer_literal" | "hex_literal" | "bin_literal" => (node, KotlinIntegerSuffix::None),
        "long_literal" => (node.named_child(0)?, KotlinIntegerSuffix::Long),
        "unsigned_literal" => {
            let suffix = if node.utf8_text(source.as_bytes()).ok()?.ends_with('L') {
                KotlinIntegerSuffix::UnsignedLong
            } else {
                KotlinIntegerSuffix::Unsigned
            };
            (node.named_child(0)?, suffix)
        }
        _ => return None,
    };
    // UInt/ULong do not define unaryPlus or unaryMinus. An extension could,
    // but its result is not a literal constant this syntax reader can prove.
    if prefixed && suffix.is_unsigned() {
        return None;
    }
    let digits = literal.utf8_text(source.as_bytes()).ok()?.replace('_', "");
    let (radix, digits) = if let Some(digits) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        (16, digits)
    } else if let Some(digits) = digits
        .strip_prefix("0b")
        .or_else(|| digits.strip_prefix("0B"))
    {
        (2, digits)
    } else {
        (10, digits.as_str())
    };
    let value = i128::from_str_radix(digits, radix).ok()?;
    let value = if negative {
        value.checked_neg()?
    } else {
        value
    };
    Some((value, suffix))
}

/// Classify a literal whose default Kotlin type is one of the supported scalar
/// types. The value itself is read separately so the semantic producer can
/// publish an exact constant.
pub fn kotlin_literal_scalar_type(node: Node<'_>, source: &str) -> Option<KotlinScalarType> {
    if node.kind() == "boolean_literal"
        && matches!(node.utf8_text(source.as_bytes()).ok()?, "true" | "false")
    {
        return Some(KotlinScalarType::Boolean);
    }
    let (value, suffix) = kotlin_integer_literal_value(node, source)?;
    // Unsigned inline classes are distinct from the supported signed scalars.
    if suffix.is_unsigned() {
        return None;
    }
    if suffix == KotlinIntegerSuffix::Long {
        return i64::try_from(value).ok().map(|_| KotlinScalarType::Long);
    }
    if i32::try_from(value).is_ok() {
        Some(KotlinScalarType::Int)
    } else if i64::try_from(value).is_ok() {
        Some(KotlinScalarType::Long)
    } else {
        None
    }
}

pub fn kotlin_extension_receiver_components(
    declaration: Node<'_>,
    source: &str,
) -> Option<Vec<String>> {
    kotlin_type_name_components(declaration.child_by_field_name("receiver")?, source)
}

/// The return type a `function_declaration` writes, or `None` when it writes
/// none.
///
/// The return type is the only bare type node among a function's children:
/// parameters live inside `function_value_parameters`, and an extension's
/// receiver sits behind the `receiver` field, which is why the receiver is
/// excluded by node identity rather than by position. A function with an
/// expression body and no written type (`fun f() = compute()`) writes no return
/// type and is reported absent — inferring what the source did not write is
/// semantic work this does not do.
pub fn kotlin_declared_return_type_text(function: Node<'_>, source: &str) -> Option<String> {
    kotlin_declared_return_type_components(function, source).map(|components| components.join("."))
}

/// The type a binding writes, or `None` when it writes none.
///
/// A `variable_declaration` (`val base: Base`) or a `class_parameter`
/// (`class D(val base: Base)`) holds its name and then its type node, so the
/// type is the first child that spells one.
pub fn kotlin_binding_type_text(binding: Node<'_>, source: &str) -> Option<String> {
    kotlin_binding_type_components(binding, source).map(|components| components.join("."))
}

/// The type an extension declaration extends, or `None` when the declaration is
/// not an extension.
///
/// `receiver` is one of the very few genuine tree-sitter fields in the vendored
/// grammar, carried by both `function_declaration` and `property_declaration`,
/// so extension-ness is a structured check and never a name heuristic.
pub fn kotlin_extension_receiver_text(declaration: Node<'_>, source: &str) -> Option<String> {
    kotlin_extension_receiver_components(declaration, source).map(|components| components.join("."))
}

/// The default expression attached to a Kotlin function or constructor parameter.
/// Function defaults are siblings of the hidden parameter rule; constructor
/// defaults are children of the visible class_parameter rule.
pub fn kotlin_parameter_default(parameter: Node<'_>) -> Option<Node<'_>> {
    let equals = if parameter.kind() == "parameter" {
        parameter.next_sibling().filter(|node| node.kind() == "=")
    } else {
        let mut cursor = parameter.walk();
        parameter
            .children(&mut cursor)
            .find(|node| node.kind() == "=")
    }?;
    equals.next_named_sibling()
}

#[cfg(test)]
mod quicksilver_tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon(
        "d5886539d3ef: quicksilver round 5 on brokk-bifrost-jvm: nested Kotlin unary prefixes exhausted the stack"
    )]
    fn decimal_integer_deep_prefixes_are_stack_safe() {
        let source = format!("val value = {}1\n", "+ ".repeat(30_000));
        let tree = crate::kotlin::language::parse_tree(&source).unwrap();
        assert!(!tree.root_node().has_error());
        let mut expression = None;
        brokk_bifrost_core::analyzer::tree_walk::walk_named_tree_preorder(
            tree.root_node(),
            true,
            |node| {
                if node.kind() == "prefix_expression" {
                    expression = Some(node);
                    brokk_bifrost_core::analyzer::tree_walk::WalkControl::Break
                } else {
                    brokk_bifrost_core::analyzer::tree_walk::WalkControl::Continue
                }
            },
        );
        let expression = expression.expect("prefix expression");
        let mut current = expression;
        let mut depth = 0;
        while current.kind() == "prefix_expression" {
            depth += 1;
            current = current.named_child(0).unwrap();
        }
        assert_eq!(depth, 30_000, "pinned grammar nests each prefix");
        std::thread::scope(|scope| {
            std::thread::Builder::new()
                .stack_size(128 * 1024)
                .spawn_scoped(scope, || {
                    assert_eq!(
                        kotlin_integer_literal_value(expression, &source),
                        Some((1, KotlinIntegerSuffix::None))
                    );
                })
                .unwrap()
                .join()
                .unwrap()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, walk_named_tree_preorder};

    #[test]
    fn grammar_selected_argument_delegate_name_and_signature_nodes() {
        // The pinned grammar has two argument-list parents and no single name
        // for a destructuring property. Spans below are authored source tokens.
        let source = "@Anno(1) class Child : Base(2)\nval count: Int = 3\nval delegated by /*comment*/ lazy { 4 }\nval (a, b) = pair\nfun library.Receiver.result(): library.Result = f(5)\n";
        let tree = crate::kotlin::language::parse_tree(source).unwrap();
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );
        let mut arguments = Vec::new();
        let mut properties = Vec::new();
        let mut signatures = Vec::new();
        walk_named_tree_preorder(tree.root_node(), true, |node| {
            match node.kind() {
                "constructor_invocation" | "call_expression" => {
                    if let Some(args) = kotlin_value_arguments(node) {
                        arguments.push((
                            args.utf8_text(source.as_bytes()).unwrap(),
                            args.parent().unwrap().kind(),
                        ));
                        assert_eq!(args.kind(), "value_arguments");
                        let start = source
                            .find(args.utf8_text(source.as_bytes()).unwrap())
                            .unwrap();
                        assert_eq!(args.byte_range(), start..start + args.byte_range().len());
                    }
                }
                "property_declaration" => {
                    properties.push(kotlin_declaration_name(node).map(|name| {
                        assert_eq!(name.kind(), "simple_identifier");
                        assert_eq!(name.parent().unwrap().kind(), "variable_declaration");
                        (
                            name.utf8_text(source.as_bytes()).unwrap(),
                            name.byte_range(),
                        )
                    }));
                    if let Some(delegate) = kotlin_property_delegate_expression(node) {
                        assert_eq!(delegate.kind(), "call_expression");
                        assert_eq!(delegate.utf8_text(source.as_bytes()).unwrap(), "lazy { 4 }");
                        assert_eq!(delegate.parent().unwrap().kind(), "property_delegate");
                    } else {
                        assert!(
                            !node
                                .utf8_text(source.as_bytes())
                                .unwrap()
                                .contains("delegated")
                        );
                    }
                }
                "function_declaration" => signatures.push((
                    kotlin_extension_receiver_text(node, source),
                    kotlin_declared_return_type_text(node, source),
                )),
                _ => {}
            }
            WalkControl::Continue
        });
        assert_eq!(
            arguments,
            [
                // In an annotation, the pinned grammar consumes the opening
                // parenthesis outside the value_arguments node.
                ("1)", "constructor_invocation"),
                ("(2)", "constructor_invocation"),
                ("(5)", "call_suffix")
            ]
        );
        assert_eq!(
            properties,
            [
                Some((
                    "count",
                    source.find("count").unwrap()..source.find("count").unwrap() + 5
                )),
                Some((
                    "delegated",
                    source.find("delegated").unwrap()..source.find("delegated").unwrap() + 9
                )),
                None
            ]
        );
        assert_eq!(
            signatures,
            [(
                Some("library.Receiver".into()),
                Some("library.Result".into())
            )]
        );
    }

    #[test]
    fn decimal_literal_boundaries_follow_kotlin_integer_ranges() {
        // Kotlin signed decimal constants: the L suffix fixes Long; an
        // unsuffixed value fitting 32 signed bits defaults to Int.
        for (spelling, value, scalar) in [
            ("-1", -1_i128, KotlinScalarType::Int),
            ("+1", 1, KotlinScalarType::Int),
            ("2147483646", 2147483646, KotlinScalarType::Int),
            ("2147483647", 2147483647, KotlinScalarType::Int),
            ("2147483648", 2147483648, KotlinScalarType::Long),
            ("-2147483648", -2147483648, KotlinScalarType::Int),
            ("-2147483649", -2147483649, KotlinScalarType::Long),
            ("1L", 1, KotlinScalarType::Long),
        ] {
            let source = format!("val n = {spelling}\n");
            let tree = crate::kotlin::language::parse_tree(&source).unwrap();
            assert!(!tree.root_node().has_error());
            let property = tree.root_node().named_child(0).unwrap();
            let expression = property
                .named_child(property.named_child_count() - 1)
                .unwrap();
            assert_eq!(expression.utf8_text(source.as_bytes()).unwrap(), spelling);
            assert_eq!(
                kotlin_integer_literal_value(expression, &source).map(|(value, _)| value),
                Some(value),
                "{spelling}"
            );
            assert_eq!(
                kotlin_literal_scalar_type(expression, &source),
                Some(scalar),
                "{spelling}"
            );
        }
        let source = "fun widths(i: Int, l: Long) {}";
        let tree = crate::kotlin::language::parse_tree(source).unwrap();
        let mut widths = Vec::new();
        walk_named_tree_preorder(tree.root_node(), true, |node| {
            if node.kind() == "parameter" {
                widths.push(kotlin_declared_scalar_type(
                    kotlin_binding_type_node(node).unwrap(),
                    source,
                ));
            }
            WalkControl::Continue
        });
        assert_eq!(
            widths,
            [Some(KotlinScalarType::Int), Some(KotlinScalarType::Long)]
        );
    }
}
