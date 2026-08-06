//! Structured reads of the Kotlin syntax tree, shared by every Kotlin consumer.
//!
//! The vendored Kotlin grammar (`crates/bifrost-analysis/vendor/tree-sitter-kotlin`)
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

use brokk_bifrost_core::analyzer::Range;
use brokk_bifrost_core::analyzer::tree_walk::{first_named_child_of_kind, named_children};
use brokk_bifrost_core::analyzer::usages::reference_site::smallest_named_node_covering;
use tree_sitter::Node;

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

/// The identifier nodes of a dotted navigation, outermost qualifier first, when
/// every link of it is a plain name.
///
/// `lib.Base` yields the `lib` token then the `Base` token. `None` when any link
/// is something other than a name — `f().Base` spells no dotted name at all.
pub fn kotlin_dotted_navigation_segments(navigation: Node<'_>) -> Option<Vec<Node<'_>>> {
    let mut segments = Vec::new();
    let mut current = navigation;
    loop {
        segments.push(kotlin_navigation_member(current)?);
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
pub fn kotlin_type_spelling(node: Node<'_>, source: &str) -> Option<String> {
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
                        .collect::<Vec<_>>();
                    if !segments.is_empty() {
                        return Some(segments.join("."));
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
    let receiver = function
        .child_by_field_name("receiver")
        .map(|node| node.id());
    named_children(function)
        .into_iter()
        .filter(|child| Some(child.id()) != receiver)
        .find_map(|child| kotlin_type_spelling(child, source))
}

/// The type a binding writes, or `None` when it writes none.
///
/// A `variable_declaration` (`val base: Base`) or a `class_parameter`
/// (`class D(val base: Base)`) holds its name and then its type node, so the
/// type is the first child that spells one.
pub fn kotlin_binding_type_text(binding: Node<'_>, source: &str) -> Option<String> {
    named_children(binding)
        .into_iter()
        .find_map(|child| kotlin_type_spelling(child, source))
}

/// The type an extension declaration extends, or `None` when the declaration is
/// not an extension.
///
/// `receiver` is one of the very few genuine tree-sitter fields in the vendored
/// grammar, carried by both `function_declaration` and `property_declaration`,
/// so extension-ness is a structured check and never a name heuristic.
pub fn kotlin_extension_receiver_text(declaration: Node<'_>, source: &str) -> Option<String> {
    kotlin_type_spelling(declaration.child_by_field_name("receiver")?, source)
}

/// The declaration node covering `range`.
///
/// The smallest covering node is not always the declaration: an `enum_entry`
/// spans exactly its own name, so its `simple_identifier` child covers the same
/// bytes and would win the smallest-covering walk. Climbing back out to the
/// outermost node with the same span picks the declaration rather than the name
/// inside it.
pub fn kotlin_declaration_node<'tree>(root: Node<'tree>, range: &Range) -> Option<Node<'tree>> {
    let mut node = smallest_named_node_covering(root, range.start_byte, range.end_byte)?;
    while let Some(parent) = node.parent() {
        if parent.start_byte() != node.start_byte() || parent.end_byte() != node.end_byte() {
            break;
        }
        node = parent;
    }
    Some(node)
}
