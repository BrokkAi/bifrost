//! Kotlin structural spec for `query_code` (issue #1240).
//!
//! This maps the vendored fwcd tree-sitter-kotlin node types onto Bifrost's
//! normalized structural vocabulary and extracts role edges from the tree.
//!
//! The grammar is field-poor — of everything this adapter reads, only
//! `function_declaration` and `property_declaration` carry a tree-sitter field,
//! and neither field is one this adapter needs. Callees, navigation members,
//! named-argument labels, dotted type segments, and import paths are therefore
//! recovered *positionally*, and every positional read routes through
//! [`crate::analyzer::kotlin::syntax`] so that structural search, definition
//! navigation (#1238), and the usage graphs (#1239) cannot drift apart about
//! what a given syntax shape means.
//!
//! Kotlin specifics worth recording, because they differ from the closest JVM
//! precedent (Scala):
//!
//! * Kotlin has real constructors. `primary_constructor` and
//!   `secondary_constructor` both normalize to [`NormalizedKind::Constructor`],
//!   and because neither spells a name of its own they borrow the enclosing
//!   class-like declaration's name, so `{kind: constructor, name: "Service"}`
//!   works the way it does for Java and C#.
//! * Kotlin supports keyword arguments, so [`Role::Kwarg`] is real here.
//!   A named argument is *not* an assignment in this grammar: `f(code = "x")`
//!   parses as `(value_argument (simple_identifier) (string_literal))`, not as
//!   an `assignment` node, so unlike Scala no `should_extract` suppression is
//!   needed to keep it out of `{kind: assignment}` results. The cross-language
//!   suite pins that behavior.
//! * A trailing lambda sits outside the parentheses (`items.forEach { … }`) but
//!   is an argument, so it is attached after the parenthesized arguments and
//!   participates in positional `args` matching.
//! * `jump_expression` is one node type for `return`/`throw`/`break`/`continue`.
//!   The table maps it to [`NormalizedKind::Return`] and `refine_kind` promotes
//!   the `throw` spelling to [`NormalizedKind::Throw`]; `break`/`continue` are
//!   dropped by `should_extract` rather than being mislabeled as returns.
//! * Numeric literals nest: `10L` is `(long_literal (integer_literal))` and
//!   `-3` is `(prefix_expression (integer_literal))`. Only the outermost node
//!   becomes a fact, so `{kind: numeric_literal}` yields one match per literal.

use crate::analyzer::Language;
use crate::analyzer::kotlin::syntax::{
    kotlin_callee, kotlin_import_header_segments, kotlin_named_argument_label,
    kotlin_navigation_receiver, kotlin_user_type_segments, kotlin_value_arguments,
};
use crate::analyzer::structural::adapter_helpers::{
    attach_role_with_derived_name, attach_terminal_callee, first_named_child,
};
use crate::analyzer::structural::{DeclarationMaterializationSupport, NO_MATERIALIZATION_SUPPORT};
use crate::analyzer::structural::{LexicalEnvironmentSupport, NO_LEXICAL_ENVIRONMENT_SUPPORT};
use crate::analyzer::structural::{NO_OCCURRENCE_ROLE_SUPPORT, OccurrenceRoleSupport};
use crate::analyzer::structural::{NormalizedKind, Role, RoleSink, Span, StructuralSpec};
use crate::analyzer::tree_walk::{first_named_child_of_kind, has_token_child, named_children};
use tree_sitter::Node;

#[derive(Debug, Default)]
pub(crate) struct KotlinStructuralSpec;

pub(crate) static KOTLIN_STRUCTURAL_SPEC: KotlinStructuralSpec = KotlinStructuralSpec;

const KOTLIN_KIND_TABLE: &[(&str, NormalizedKind)] = &[
    // calls
    ("call_expression", NormalizedKind::Call),
    ("constructor_invocation", NormalizedKind::Call),
    ("infix_expression", NormalizedKind::Call),
    // member access
    ("navigation_expression", NormalizedKind::FieldAccess),
    // callables
    ("function_declaration", NormalizedKind::Function),
    ("primary_constructor", NormalizedKind::Constructor),
    ("secondary_constructor", NormalizedKind::Constructor),
    ("lambda_literal", NormalizedKind::Lambda),
    ("anonymous_function", NormalizedKind::Lambda),
    // class-like declarations (`interface`, `enum class` and `annotation
    // class` are all `class_declaration` in this grammar)
    ("class_declaration", NormalizedKind::Class),
    ("object_declaration", NormalizedKind::Class),
    ("companion_object", NormalizedKind::Class),
    ("object_literal", NormalizedKind::Class),
    // bindings
    ("property_declaration", NormalizedKind::Assignment),
    ("assignment", NormalizedKind::Assignment),
    ("import_header", NormalizedKind::Import),
    // annotations
    ("annotation", NormalizedKind::Decorator),
    ("file_annotation", NormalizedKind::Decorator),
    // references
    ("simple_identifier", NormalizedKind::Identifier),
    ("type_identifier", NormalizedKind::Identifier),
    // literals
    ("string_literal", NormalizedKind::StringLiteral),
    ("character_literal", NormalizedKind::StringLiteral),
    ("integer_literal", NormalizedKind::NumericLiteral),
    ("real_literal", NormalizedKind::NumericLiteral),
    ("hex_literal", NormalizedKind::NumericLiteral),
    ("bin_literal", NormalizedKind::NumericLiteral),
    ("long_literal", NormalizedKind::NumericLiteral),
    ("unsigned_literal", NormalizedKind::NumericLiteral),
    ("prefix_expression", NormalizedKind::NumericLiteral),
    ("boolean_literal", NormalizedKind::BooleanLiteral),
    ("null_literal", NormalizedKind::NullLiteral),
    // control flow (`jump_expression` is refined to `throw` where it spells one)
    ("jump_expression", NormalizedKind::Return),
    ("catch_block", NormalizedKind::Catch),
    ("if_expression", NormalizedKind::If),
    ("when_expression", NormalizedKind::If),
    ("for_statement", NormalizedKind::ForLoop),
    ("while_statement", NormalizedKind::WhileLoop),
    ("do_while_statement", NormalizedKind::WhileLoop),
];

fn span_from(first: Node<'_>, last: Node<'_>) -> Span {
    Span {
        start_byte: first.start_byte(),
        end_byte: last.end_byte(),
    }
}

/// The member a `navigation_suffix` selects.
///
/// Shared by `navigation_expression` (`a.b`, `a?.b`) and
/// `directly_assignable_expression` (`this.field = 3`), which spell the suffix
/// the same way but are otherwise unrelated nodes.
fn navigation_member<'tree>(node: Node<'tree>) -> Option<Node<'tree>> {
    first_named_child_of_kind(node, "navigation_suffix").and_then(first_named_child)
}

/// The named node an annotation applies, skipping a `@file:`-style use-site
/// target.
fn annotation_subject<'tree>(annotation: Node<'tree>) -> Option<Node<'tree>> {
    named_children(annotation)
        .into_iter()
        .find(|child| child.kind() != "use_site_target")
}

/// The terminal identifier that names an expression, or `None` when the shape
/// has no single name (a `when`, an arithmetic expression, an object literal).
fn expression_name_node<'tree>(expression: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = expression;
    loop {
        match current.kind() {
            "simple_identifier" | "type_identifier" | "this_expression" | "super_expression" => {
                return Some(current);
            }
            "navigation_expression" => current = navigation_member(current)?,
            "directly_assignable_expression" => {
                current = navigation_member(current).or_else(|| first_named_child(current))?;
            }
            "call_expression" => current = kotlin_callee(current)?,
            "constructor_invocation" => current = first_named_child_of_kind(current, "user_type")?,
            "user_type" => current = kotlin_user_type_segments(current).last().copied()?,
            "annotation" | "file_annotation" => current = annotation_subject(current)?,
            "infix_expression" => current = current.named_child(1)?,
            "parenthesized_expression"
            | "spread_expression"
            | "as_expression"
            | "postfix_expression"
            | "check_expression"
            | "indexing_expression"
            | "nullable_type"
            | "not_nullable_type"
            | "parenthesized_type" => current = first_named_child(current)?,
            _ => return None,
        }
    }
}

/// The name introduced by a `variable_declaration` or the first name of a
/// destructuring `multi_variable_declaration`.
fn binding_name_node<'tree>(binding: Node<'tree>) -> Option<Node<'tree>> {
    match binding.kind() {
        "multi_variable_declaration" => first_named_child_of_kind(binding, "variable_declaration")
            .and_then(|declaration| first_named_child_of_kind(declaration, "simple_identifier")),
        _ => first_named_child_of_kind(binding, "simple_identifier"),
    }
}

fn property_binding_node<'tree>(property: Node<'tree>) -> Option<Node<'tree>> {
    first_named_child_of_kind(property, "variable_declaration")
        .or_else(|| first_named_child_of_kind(property, "multi_variable_declaration"))
}

/// The first named child that follows the anonymous `token` child.
fn named_child_after_token<'tree>(node: Node<'tree>, token: &str) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    let mut past_token = false;
    for child in node.children(&mut cursor) {
        if past_token && child.is_named() {
            return Some(child);
        }
        if !child.is_named() && child.kind() == token {
            past_token = true;
        }
    }
    None
}

/// The value a property declaration binds: an `= …` initializer, or the
/// expression of a `by …` delegate. A property with neither (`val x: String`
/// in an interface, or one defined solely by a getter) binds nothing and is
/// not an assignment.
fn property_value_node<'tree>(property: Node<'tree>) -> Option<Node<'tree>> {
    if let Some(delegate) = first_named_child_of_kind(property, "property_delegate") {
        return first_named_child(delegate);
    }
    named_child_after_token(property, "=")
}

/// The right-hand side of an `assignment` node. Simple and augmented
/// assignments alike spell their operator as an anonymous token, so the value
/// is simply the second named child.
fn assignment_value_node<'tree>(assignment: Node<'tree>) -> Option<Node<'tree>> {
    assignment.named_child(1)
}

fn is_numeric_literal_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "integer_literal"
            | "real_literal"
            | "hex_literal"
            | "bin_literal"
            | "long_literal"
            | "unsigned_literal"
    )
}

/// Whether a `prefix_expression` is the sign of a numeric literal (`-3`,
/// `+2.5`) rather than some other unary form (`!flag`, `++index`).
fn is_signed_numeric_prefix(node: Node<'_>) -> bool {
    node.kind() == "prefix_expression"
        && node.named_child_count() == 1
        && node.named_child(0).is_some_and(is_numeric_literal_node)
        && (has_token_child(node, "-") || has_token_child(node, "+"))
}

/// Whether a numeric literal is nested inside a wider numeric literal and so
/// already accounted for: `10L` is `(long_literal (integer_literal))`, `1u` is
/// `(unsigned_literal (integer_literal))`, and `-3` wraps its magnitude in a
/// signed `prefix_expression`.
fn is_nested_numeric_literal(node: Node<'_>) -> bool {
    node.parent()
        .is_some_and(|parent| is_numeric_literal_node(parent) || is_signed_numeric_prefix(parent))
}

/// The keyword a `jump_expression` is spelled with (`return`, `return@`,
/// `throw`, `break`, `break@`, `continue`, `continue@`).
fn jump_keyword(node: Node<'_>) -> Option<&'static str> {
    node.child(0)
        .filter(|child| !child.is_named())
        .map(|child| child.kind())
}

fn is_throw_jump(node: Node<'_>) -> bool {
    node.kind() == "jump_expression" && jump_keyword(node) == Some("throw")
}

fn is_return_or_throw_jump(node: Node<'_>) -> bool {
    matches!(jump_keyword(node), Some("return" | "return@" | "throw"))
}

/// The class-like declaration a constructor belongs to, which is also where a
/// Kotlin constructor gets its name: neither `primary_constructor` nor
/// `secondary_constructor` spells one.
fn enclosing_class_name_node<'tree>(constructor: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = constructor.parent();
    while let Some(node) = current {
        if matches!(
            node.kind(),
            "class_declaration" | "object_declaration" | "companion_object"
        ) {
            return first_named_child_of_kind(node, "type_identifier");
        }
        current = node.parent();
    }
    None
}

fn declaration_name_node<'tree>(declaration: Node<'tree>) -> Option<Node<'tree>> {
    match declaration.kind() {
        "function_declaration" => first_named_child_of_kind(declaration, "simple_identifier"),
        "class_declaration" | "object_declaration" | "companion_object" => {
            first_named_child_of_kind(declaration, "type_identifier")
        }
        "primary_constructor" | "secondary_constructor" => enclosing_class_name_node(declaration),
        _ => None,
    }
}

/// Annotations hang off a declaration's `modifiers` node rather than off the
/// declaration directly, exactly as they do in Java.
fn attach_decorators(sink: &mut RoleSink<'_>, declaration: Node<'_>) {
    for modifiers in named_children(declaration) {
        if modifiers.kind() != "modifiers" {
            continue;
        }
        for modifier in named_children(modifiers) {
            if modifier.kind() != "annotation" {
                continue;
            }
            attach_role_with_derived_name(sink, Role::Decorator, modifier, expression_name_node);
        }
    }
}

fn attach_argument(sink: &mut RoleSink<'_>, argument: Node<'_>) {
    sink.argument_maybe_named(
        argument,
        expression_name_node(argument),
        argument.kind() == "spread_expression",
    );
}

/// The label/value split of a `value_argument`, routed through the shared
/// positional read so this adapter and the usage graphs agree about which
/// arguments are named.
fn named_argument_parts<'tree>(argument: Node<'tree>) -> Option<(Node<'tree>, Node<'tree>)> {
    let children = named_children(argument);
    let keyword = children.first().copied()?;
    if !kotlin_named_argument_label(argument, keyword) {
        return None;
    }
    Some((keyword, children.get(1).copied()?))
}

/// The `lambda_literal` a call passes outside its parentheses, if any.
///
/// The `annotated_lambda` wrapper is stepped through deliberately: the
/// `lambda_literal` inside it is the node that becomes a `lambda` fact, so
/// targeting it lets `args: [{kind: lambda, …}]` and `has:` constraints reach
/// the lambda body.
fn trailing_lambda<'tree>(call: Node<'tree>) -> Option<Node<'tree>> {
    first_named_child_of_kind(call, "call_suffix")
        .and_then(|suffix| first_named_child_of_kind(suffix, "annotated_lambda"))
        .and_then(|annotated| first_named_child_of_kind(annotated, "lambda_literal"))
}

fn attach_call_arguments(sink: &mut RoleSink<'_>, call: Node<'_>) {
    if let Some(arguments) = kotlin_value_arguments(call) {
        for argument in named_children(arguments) {
            if !sink.should_continue() {
                return;
            }
            if argument.kind() != "value_argument" {
                continue;
            }
            match named_argument_parts(argument) {
                Some((keyword, value)) => sink.kwarg(keyword, value),
                None => {
                    if let Some(value) = first_named_child(argument) {
                        attach_argument(sink, value);
                    }
                }
            }
        }
    }
    if let Some(lambda) = trailing_lambda(call)
        && sink.should_continue()
    {
        attach_argument(sink, lambda);
    }
}

/// `a to b` and other user-defined infix calls: `(infix_expression left
/// operator right)`, with the operator spelled as a `simple_identifier`.
fn attach_infix_call(sink: &mut RoleSink<'_>, node: Node<'_>) {
    let children = named_children(node);
    if let Some(operator) = children.get(1).copied() {
        attach_terminal_callee(sink, operator, expression_name_node(operator));
    }
    if let Some(receiver) = children.first().copied() {
        attach_role_with_derived_name(sink, Role::Receiver, receiver, expression_name_node);
    }
    if let Some(argument) = children.get(2).copied() {
        attach_argument(sink, argument);
    }
}

fn attach_import_modules(sink: &mut RoleSink<'_>, header: Node<'_>) {
    let segments = kotlin_import_header_segments(header);
    if let Some(&last) = segments.last() {
        // Both the leaf name and the whole dotted path are accepted spellings
        // of the module, so `Try` and `scala.util.Try`-style queries both hit
        // while a shared *prefix* (`util`) does not.
        sink.role_named(Role::Module, header, last);
        if segments.len() > 1
            && let Some(&first) = segments.first()
        {
            sink.role_named_span(Role::Module, header, span_from(first, last));
        }
    }
    // `import a.b.C as D` also introduces `D`; unlike Scala's renaming
    // selectors the original path stays a legitimate spelling of what was
    // imported, so the alias is attached in addition to it rather than
    // instead of it.
    if let Some(alias) = first_named_child_of_kind(header, "import_alias")
        && let Some(name) = first_named_child(alias)
    {
        sink.role_named(Role::Module, alias, name);
    }
}

impl StructuralSpec for KotlinStructuralSpec {
    fn language(&self) -> Language {
        Language::Kotlin
    }

    fn kind_table(&self) -> &'static [(&'static str, NormalizedKind)] {
        KOTLIN_KIND_TABLE
    }

    fn refine_kind(
        &self,
        node: Node<'_>,
        kind: NormalizedKind,
        enclosing: Option<NormalizedKind>,
        _source: &str,
    ) -> NormalizedKind {
        match kind {
            NormalizedKind::Function if enclosing == Some(NormalizedKind::Class) => {
                NormalizedKind::Method
            }
            NormalizedKind::Return if is_throw_jump(node) => NormalizedKind::Throw,
            _ => kind,
        }
    }

    fn should_extract(&self, node: Node<'_>, kind: NormalizedKind) -> bool {
        match kind {
            NormalizedKind::NumericLiteral => {
                if node.kind() == "prefix_expression" {
                    is_signed_numeric_prefix(node)
                } else {
                    !is_nested_numeric_literal(node)
                }
            }
            // `break`/`continue` share `jump_expression` with `return`/`throw`
            // but are neither.
            NormalizedKind::Return => is_return_or_throw_jump(node),
            // A property that binds nothing is a declaration, not an assignment.
            NormalizedKind::Assignment => {
                node.kind() != "property_declaration" || property_value_node(node).is_some()
            }
            _ => true,
        }
    }

    fn supports_kind(&self, kind: NormalizedKind) -> bool {
        // `method` and `throw` are produced by `refine_kind` rather than by a
        // table entry, so the derived-from-table default would under-report.
        matches!(kind, NormalizedKind::Method | NormalizedKind::Throw)
            || self
                .kind_table()
                .iter()
                .any(|(_, fact_kind)| fact_kind.satisfies(kind))
    }

    /// Kotlin has not learned occurrence-role classification yet (#1473).
    /// The empty table is the honest answer: queries and assertions that ask
    /// for an occurrence role here report incomplete rather than clean-empty.
    fn occurrence_role_support(&self) -> &OccurrenceRoleSupport {
        &NO_OCCURRENCE_ROLE_SUPPORT
    }

    fn lexical_environment_support(&self) -> &LexicalEnvironmentSupport {
        &NO_LEXICAL_ENVIRONMENT_SUPPORT
    }

    fn materialization_support(&self) -> &DeclarationMaterializationSupport {
        &NO_MATERIALIZATION_SUPPORT
    }

    fn extract(&self, node: Node<'_>, kind: NormalizedKind, sink: &mut RoleSink<'_>) {
        match kind {
            NormalizedKind::Call => {
                if node.kind() == "infix_expression" {
                    attach_infix_call(sink, node);
                    return;
                }
                if let Some(callee) = kotlin_callee(node) {
                    attach_terminal_callee(sink, callee, expression_name_node(callee));
                    if callee.kind() == "navigation_expression"
                        && let Some(receiver) = kotlin_navigation_receiver(callee)
                    {
                        attach_role_with_derived_name(
                            sink,
                            Role::Receiver,
                            receiver,
                            expression_name_node,
                        );
                    }
                }
                attach_call_arguments(sink, node);
            }
            NormalizedKind::FieldAccess => {
                if let Some(field) = navigation_member(node) {
                    sink.set_name(field);
                    sink.role_named(Role::Field, field, field);
                }
                if let Some(object) = kotlin_navigation_receiver(node) {
                    attach_role_with_derived_name(sink, Role::Object, object, expression_name_node);
                }
            }
            NormalizedKind::Function
            | NormalizedKind::Method
            | NormalizedKind::Constructor
            | NormalizedKind::Class
            | NormalizedKind::Lambda => {
                if let Some(name) = declaration_name_node(node) {
                    sink.set_name(name);
                }
                attach_decorators(sink, node);
            }
            NormalizedKind::Assignment => match node.kind() {
                "property_declaration" => {
                    if let Some(binding) = property_binding_node(node) {
                        attach_role_with_derived_name(sink, Role::Left, binding, binding_name_node);
                        if let Some(name) = binding_name_node(binding) {
                            sink.set_name(name);
                        }
                    }
                    if let Some(value) = property_value_node(node) {
                        attach_role_with_derived_name(
                            sink,
                            Role::Right,
                            value,
                            expression_name_node,
                        );
                    }
                }
                _ => {
                    if let Some(left) = first_named_child(node) {
                        attach_role_with_derived_name(sink, Role::Left, left, expression_name_node);
                        if let Some(name) = expression_name_node(left) {
                            sink.set_name(name);
                        }
                    }
                    if let Some(right) = assignment_value_node(node) {
                        attach_role_with_derived_name(
                            sink,
                            Role::Right,
                            right,
                            expression_name_node,
                        );
                    }
                }
            },
            NormalizedKind::Import => attach_import_modules(sink, node),
            NormalizedKind::Decorator => {
                if let Some(name) = expression_name_node(node) {
                    sink.set_name(name);
                }
            }
            NormalizedKind::Identifier => sink.set_name(node),
            _ => {}
        }
    }
}

#[cfg(test)]
mod structural_spec_tests {
    use super::*;

    #[test]
    fn kotlin_kind_table_matches_grammar() {
        crate::analyzer::structural::adapter_helpers::assert_kind_table_matches_grammar(
            crate::analyzer::kotlin::language::LANGUAGE.into(),
            "tree-sitter-kotlin",
            KOTLIN_KIND_TABLE,
        );
    }

    #[test]
    fn kotlin_advertises_the_kinds_it_refines_into() {
        assert!(KOTLIN_STRUCTURAL_SPEC.supports_kind(NormalizedKind::Method));
        assert!(KOTLIN_STRUCTURAL_SPEC.supports_kind(NormalizedKind::Throw));
        assert!(KOTLIN_STRUCTURAL_SPEC.supports_kind(NormalizedKind::Constructor));
        assert!(KOTLIN_STRUCTURAL_SPEC.supports_kind(NormalizedKind::Callable));
        assert!(KOTLIN_STRUCTURAL_SPEC.supports_kind(NormalizedKind::Declaration));
        assert!(KOTLIN_STRUCTURAL_SPEC.supports_kind(NormalizedKind::Literal));
    }

    #[test]
    fn kotlin_supports_every_role_including_keyword_arguments() {
        for &role in crate::analyzer::structural::kinds::ALL_ROLES {
            assert!(
                KOTLIN_STRUCTURAL_SPEC.supports_role(role),
                "Kotlin should model {role:?}"
            );
        }
    }
}
