//! Kotlin structural spec for `query_code` (issue #1240).
//!
//! This maps the `brokk-tree-sitter-kotlin` node types onto Bifrost's
//! normalized structural vocabulary and extracts role edges from the tree.
//!
//! The grammar is field-poor — of everything this adapter reads, only
//! `function_declaration` and `property_declaration` carry a tree-sitter field,
//! and neither field is one this adapter needs. Callees, navigation members,
//! named-argument labels, dotted type segments, and import paths are therefore
//! recovered *positionally*, and every positional read routes through
//! [`crate::kotlin::syntax`] so that structural search, definition
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

use brokk_bifrost_core::analyzer::semantic_diagnostics::contains_node as contains;
use brokk_bifrost_core::analyzer::structural::adapter_helpers::{
    attach_argument_role_with_derived_name, attach_decorators_under, attach_role_with_derived_name,
    attach_terminal_callee, first_named_child,
};
use brokk_bifrost_core::analyzer::structural::callable::CallSiteContext;
use brokk_bifrost_core::analyzer::structural::edges::{
    DEEP_REFERENCE_EDGE_SUPPORT, ReferenceEdgeSupport,
};
use brokk_bifrost_core::analyzer::structural::facts::Span;
use brokk_bifrost_core::analyzer::structural::kinds::{NormalizedKind, Role};
use brokk_bifrost_core::analyzer::structural::materialization::{
    DeclarationMaterializationSupport, NO_MATERIALIZATION_SUPPORT,
};
use brokk_bifrost_core::analyzer::structural::occurrences::{
    OccurrenceRole, OccurrenceRoleSupport,
};
use brokk_bifrost_core::analyzer::structural::resolution::{
    BindingActivation, BindingKind, EnvironmentAxis, HoistingClass, LexicalEnvironmentSupport,
};
use brokk_bifrost_core::analyzer::structural::routes::{
    IdentityRouteSupport, NO_IDENTITY_ROUTE_SUPPORT,
};
use brokk_bifrost_core::analyzer::structural::spec::{RoleSink, StructuralSpec};
use brokk_bifrost_core::analyzer::tree_walk::{
    first_named_child_of_kind, named_children, node_range,
};
use brokk_bifrost_core::analyzer::{Language, Range};
use tree_sitter::Node;

use crate::kotlin::syntax::{
    kotlin_binding_name_nodes, kotlin_binding_node,
    kotlin_call_trailing_lambda_body as trailing_lambda, kotlin_callee,
    kotlin_first_token as jump_keyword, kotlin_import_header_segments, kotlin_named_argument_label,
    kotlin_navigation_member as navigation_member, kotlin_navigation_receiver,
    kotlin_property_delegate_expression, kotlin_user_type_segments, kotlin_value_arguments,
};

#[derive(Debug, Default)]
pub struct KotlinStructuralSpec;

pub static KOTLIN_STRUCTURAL_SPEC: KotlinStructuralSpec = KotlinStructuralSpec;

static KOTLIN_OCCURRENCE_ROLE_SUPPORT: OccurrenceRoleSupport = OccurrenceRoleSupport::NONE
    .supported(OccurrenceRole::DeclarationName)
    .supported(OccurrenceRole::Binder)
    .supported(OccurrenceRole::LabelOrKey)
    .supported(OccurrenceRole::TypeOperand)
    .supported(OccurrenceRole::PathSegment)
    .supported(OccurrenceRole::ImportAlias)
    .supported(OccurrenceRole::ImportTarget)
    .supported(OccurrenceRole::ReceiverPosition)
    .supported(OccurrenceRole::MemberPosition)
    .supported(OccurrenceRole::ValueReference);

pub const KOTLIN_KIND_TABLE: &[(&str, NormalizedKind)] = &[
    ("line_comment", NormalizedKind::Comment),
    ("multiline_comment", NormalizedKind::Comment),
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
    // A `typealias` declares a type, so its fact is a type-namespace
    // declaration and its name inherits `Namespace::Type` through
    // `declared_fact_kind`. Absent from the table, the alias name had no
    // declaring fact at all and landed in the value namespace beside a
    // same-named `val` (#2892).
    ("type_alias", NormalizedKind::Class),
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
    // A braced body is a `statements` node (the grammar has no `block`), and
    // it is a scope: a `val` declared in it ends with it.
    ("statements", NormalizedKind::Block),
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
    brokk_bifrost_core::analyzer::common::span_from_nodes(first, last)
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
pub(crate) fn property_value_node<'tree>(property: Node<'tree>) -> Option<Node<'tree>> {
    if let Some(value) = kotlin_property_delegate_expression(property) {
        return Some(value);
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

/// Classify one Kotlin identifier from its structured AST position.
///
/// Kotlin's grammar exposes few named fields, so this deliberately shares the
/// same positional helpers as definition navigation and the graph resolver.
/// Qualified import and type paths classify each segment exactly once; member
/// and receiver positions are derived from the navigation expression shape.
fn kotlin_occurrence_role(node: Node<'_>) -> Option<OccurrenceRole> {
    if !matches!(node.kind(), "simple_identifier" | "type_identifier") {
        return None;
    }

    if crate::type_parameters::is_name(node, brokk_bifrost_core::analyzer::Language::Kotlin) {
        return Some(OccurrenceRole::DeclarationName);
    }

    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "import_header" => {
                let segments = kotlin_import_header_segments(parent);
                let position = segments.iter().position(|segment| *segment == node)?;
                return Some(if position + 1 == segments.len() {
                    OccurrenceRole::ImportTarget
                } else {
                    OccurrenceRole::PathSegment
                });
            }
            "import_alias" => return Some(OccurrenceRole::ImportAlias),
            "user_type" => {
                let segments = kotlin_user_type_segments(parent);
                let position = segments.iter().position(|segment| *segment == node)?;
                return Some(if position + 1 == segments.len() {
                    OccurrenceRole::TypeOperand
                } else {
                    OccurrenceRole::PathSegment
                });
            }
            "navigation_suffix" => return Some(OccurrenceRole::MemberPosition),
            "navigation_expression" => {
                if kotlin_navigation_receiver(parent)
                    .is_some_and(|receiver| contains(receiver, node))
                {
                    return Some(OccurrenceRole::ReceiverPosition);
                }
            }
            "value_argument" if kotlin_named_argument_label(parent, node) => {
                return Some(OccurrenceRole::LabelOrKey);
            }
            // The token a declaration names itself with, read through the
            // shared `declaration_name_node` -- which is also what sets the
            // fact's name pointer, so the role and the namespace it inherits
            // are decided by one rule. Asking for a `name` *field* instead
            // never matched: this grammar spells no field on any declaration,
            // so every Kotlin declaration name fell through to
            // `ValueReference` (#2892).
            "class_declaration"
            | "object_declaration"
            | "companion_object"
            | "type_alias"
            | "function_declaration"
                if declaration_name_node(parent) == Some(current) =>
            {
                return Some(OccurrenceRole::DeclarationName);
            }
            // Only the declaring token itself: a name deeper inside a loop
            // or catch body, or in a parameter's default value, is a read.
            // A `for` variable and a lambda parameter are `variable_declaration`
            // names, and a function parameter's name is inside its `parameter`;
            // the other direct children of `for_statement` and
            // `function_value_parameter` are reads.
            "variable_declaration" | "parameter" | "catch_block" if current.id() == node.id() => {
                return Some(OccurrenceRole::Binder);
            }
            "call_expression" | "constructor_invocation" | "infix_expression" => break,
            _ => {}
        }
        current = parent;
    }
    Some(OccurrenceRole::ValueReference)
}

/// Whether a `prefix_expression` is the sign of a numeric literal (`-3`,
/// `+2.5`) rather than some other unary form (`!flag`, `++index`).
fn is_signed_numeric_prefix(node: Node<'_>) -> bool {
    if node.kind() != "prefix_expression" || node.named_child_count() != 1 {
        return false;
    }
    let operator = (0..node.child_count())
        .filter_map(|index| node.child(index))
        .find(|child| !child.is_named() && matches!(child.kind(), "+" | "-"))
        .map(|child| child.kind());
    brokk_bifrost_core::analyzer::tree_walk::is_signed_numeric_operand(
        node.named_child(0),
        operator,
        is_numeric_literal_node,
    )
}

/// Whether a numeric literal is nested inside a wider numeric literal and so
/// already accounted for: `10L` is `(long_literal (integer_literal))`, `1u` is
/// `(unsigned_literal (integer_literal))`, and `-3` wraps its magnitude in a
/// signed `prefix_expression`.
fn is_nested_numeric_literal(node: Node<'_>) -> bool {
    node.parent()
        .is_some_and(|parent| is_numeric_literal_node(parent) || is_signed_numeric_prefix(parent))
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

/// The identifier token a declaration names itself with.
///
/// This grammar spells no `name` field on any declaration -- a class writes
/// `alias($.simple_identifier, $.type_identifier)` positionally -- so the name
/// is the declaration's first identifier child of the kind that form uses. A
/// `type_alias` names itself the way a class does, with the aliased type
/// following as a `user_type`, `nullable_type` or `function_type` rather than
/// as a second bare `type_identifier`.
fn declaration_name_node<'tree>(declaration: Node<'tree>) -> Option<Node<'tree>> {
    match declaration.kind() {
        "function_declaration" => first_named_child_of_kind(declaration, "simple_identifier"),
        "class_declaration" | "object_declaration" | "companion_object" | "type_alias" => {
            first_named_child_of_kind(declaration, "type_identifier")
        }
        "primary_constructor" | "secondary_constructor" => enclosing_class_name_node(declaration),
        _ => None,
    }
}

/// Annotations hang off a declaration's `modifiers` node rather than off the
/// declaration directly, exactly as they do in Java.
fn attach_decorators(sink: &mut RoleSink<'_>, declaration: Node<'_>) {
    attach_decorators_under(
        sink,
        declaration,
        "modifiers",
        &["annotation"],
        expression_name_node,
    );
}

fn attach_argument(sink: &mut RoleSink<'_>, argument: Node<'_>) {
    attach_argument_role_with_derived_name(sink, argument, expression_name_node);
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

/// Kotlin derives its scope tree from the callable, class-like, loop, catch
/// and block facts in [`KOTLIN_KIND_TABLE`], and every binder it classifies
/// states an interval through [`kotlin_binding_activation`]. Import binders and
/// the package clause are not derived; the member walk reports per-candidate
/// callable applicability (#1478 M3).
static KOTLIN_LEXICAL_ENVIRONMENT_SUPPORT: LexicalEnvironmentSupport =
    LexicalEnvironmentSupport::NONE
        .supported(EnvironmentAxis::Scopes)
        .supported(EnvironmentAxis::BindingIntervals)
        .supported(EnvironmentAxis::CallableApplicability);

/// The binding one Kotlin binder token introduces, and the interval it is in
/// effect over.
///
/// - A function, constructor or lambda parameter is in effect over its whole
///   callable (`ScopeWide`).
/// - A `catch` parameter is in effect over the catch body, a `for` variable
///   over the loop body, and a `when (val x = ..)` subject over the `when`.
/// - A local `val`/`var` is in effect from the end of its declaration to the
///   end of its block, so `val x = x` reads an outer `x`.
/// - A property of a class body or of the file is in effect over that whole
///   scope.
/// - A property declared `by` a delegate states no interval: reading it calls
///   the delegate's `getValue`, so it is not a binding whose value the
///   environment can stand for.
fn kotlin_binding_activation(binder: Node<'_>, scope: Range) -> Option<BindingActivation> {
    let binding = |kind, hoisting, activation| {
        Some(BindingActivation {
            kind,
            hoisting,
            activation,
        })
    };
    let parent = binder.parent()?;
    match parent.kind() {
        "parameter" => binding(BindingKind::Parameter, HoistingClass::ScopeWide, scope),
        // The catch body is the block's own `statements`, absent when empty.
        "catch_block" => binding(
            BindingKind::CatchOrResource,
            HoistingClass::DeclaredHead,
            Range {
                start_byte: binder.end_byte(),
                end_byte: parent.end_byte(),
                start_line: binder.end_position().row + 1,
                end_line: parent.end_position().row + 1,
            },
        ),
        "variable_declaration" => {
            let mut owner = parent.parent()?;
            if owner.kind() == "multi_variable_declaration" {
                owner = owner.parent()?;
            }
            match owner.kind() {
                "lambda_parameters" => {
                    binding(BindingKind::Parameter, HoistingClass::ScopeWide, scope)
                }
                "for_statement" => binding(
                    BindingKind::LoopVariable,
                    HoistingClass::DeclaredHead,
                    node_range(first_named_child_of_kind(owner, "control_structure_body")?),
                ),
                "when_subject" => binding(
                    BindingKind::Local,
                    HoistingClass::DeclaredHead,
                    node_range(owner.parent()?),
                ),
                "property_declaration" => {
                    if first_named_child_of_kind(owner, "property_delegate").is_some() {
                        return None;
                    }
                    if owner.parent()?.kind() != "statements" {
                        return binding(BindingKind::Local, HoistingClass::ScopeWide, scope);
                    }
                    binding(
                        BindingKind::Local,
                        HoistingClass::SourceOrder,
                        Range {
                            start_byte: owner.end_byte(),
                            end_byte: scope.end_byte,
                            start_line: owner.end_position().row + 1,
                            end_line: scope.end_line,
                        },
                    )
                }
                _ => None,
            }
        }
        _ => None,
    }
}

impl StructuralSpec for KotlinStructuralSpec {
    fn language(&self) -> Language {
        Language::Kotlin
    }

    fn supports_boolean_literal_value(&self) -> bool {
        true
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
        _context: &CallSiteContext,
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
        brokk_bifrost_core::analyzer::structural::spec::supports_kind_from_table(
            kind,
            &[
                NormalizedKind::Method,
                NormalizedKind::Throw,
                NormalizedKind::SyntaxError,
            ],
            self.kind_table(),
        )
    }

    fn supports_role(&self, role: Role) -> bool {
        // #2647: not yet extracted by this adapter.
        brokk_bifrost_core::analyzer::structural::spec::supports_role_without_iterable_or_element(
            role,
        )
    }

    fn occurrence_role_support(&self) -> &OccurrenceRoleSupport {
        &KOTLIN_OCCURRENCE_ROLE_SUPPORT
    }

    fn lexical_environment_support(&self) -> &LexicalEnvironmentSupport {
        &KOTLIN_LEXICAL_ENVIRONMENT_SUPPORT
    }

    fn type_parameter_owner<'tree>(&self, name: Node<'tree>) -> Option<Node<'tree>> {
        crate::type_parameters::owner(name, brokk_bifrost_core::analyzer::Language::Kotlin)
    }

    fn type_parameter_scope_barrier(&self, owner: Node<'_>) -> bool {
        crate::type_parameters::barrier(owner, brokk_bifrost_core::analyzer::Language::Kotlin)
    }

    fn binding_activation(&self, binder: Node<'_>, scope: Range) -> Option<BindingActivation> {
        kotlin_binding_activation(binder, scope)
    }

    fn materialization_support(&self) -> &DeclarationMaterializationSupport {
        &NO_MATERIALIZATION_SUPPORT
    }

    fn reference_edge_support(&self) -> &ReferenceEdgeSupport {
        &DEEP_REFERENCE_EDGE_SUPPORT
    }

    fn identity_route_support(&self) -> &IdentityRouteSupport {
        &NO_IDENTITY_ROUTE_SUPPORT
    }

    fn extract(&self, node: Node<'_>, kind: NormalizedKind, sink: &mut RoleSink<'_>) {
        if let Some(role) = kotlin_occurrence_role(node) {
            sink.occurrence_role(node, role);
        }
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
                    if let Some(binding) = kotlin_binding_node(node) {
                        attach_role_with_derived_name(sink, Role::Left, binding, |binding| {
                            kotlin_binding_name_nodes(binding).into_iter().next()
                        });
                        if let Some(name) = kotlin_binding_name_nodes(binding).into_iter().next() {
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
mod grammar_boundary_tests {
    use super::*;
    use brokk_bifrost_core::analyzer::ProjectFile;
    use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;
    use brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceId;

    fn parse(source: &str) -> ParsedFile {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&crate::kotlin::language::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let file = ProjectFile::new(
            std::env::temp_dir().join("kotlin-grammar-boundary"),
            "Sample.kt",
        );
        crate::kotlin::declarations::parse_kotlin_file(&file, source, &tree)
    }

    fn grammar_nodes<'a>(source: &'a str, kinds: &[&str]) -> Vec<(String, &'a str)> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&crate::kotlin::language::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let mut stack = vec![tree.root_node()];
        let mut selected = Vec::new();
        while let Some(node) = stack.pop() {
            if kinds.contains(&node.kind()) {
                selected.push((node.kind().to_owned(), &source[node.byte_range()]));
            }
            let mut cursor = node.walk();
            stack.extend(
                node.named_children(&mut cursor)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev(),
            );
        }
        selected
    }

    fn text<'a>(parsed: &ParsedFile, source: &'a str, id: SourceOccurrenceId) -> &'a str {
        let range = parsed
            .source_facts
            .as_ref()
            .unwrap()
            .occurrences
            .occurrence(id)
            .range;
        &source[range.start_byte..range.end_byte]
    }

    // Ordered grammar operands and import identifiers must survive as exact
    // role ranges, including delegated values and nested infix calls.
    #[test]
    fn structural_role_grammar_boundary() {
        let source = "import a.C\nimport a.b.D\nimport a.E as Alias\nimport a.*\ninterface Empty { val absent: Int }\nval delegated by factory()\nval initialized = factory()\nval result = left combine right\nfun use() { consume(left combine right); target = source; target += delta }";
        assert_eq!(
            grammar_nodes(source, &["infix_expression", "assignment"]),
            [
                ("infix_expression".into(), "left combine right"),
                ("infix_expression".into(), "left combine right"),
                ("assignment".into(), "target = source"),
                ("assignment".into(), "target += delta"),
            ]
        );
        let parsed = parse(source);
        let facts = &parsed.source_facts.as_ref().unwrap().structural;
        let mut actual = Vec::new();
        for (index, node) in facts.nodes().iter().enumerate() {
            if !matches!(
                node.kind,
                NormalizedKind::Assignment | NormalizedKind::Call | NormalizedKind::Import
            ) {
                continue;
            }
            for role in facts.roles(index as u32) {
                if matches!(
                    role.role,
                    Role::Left | Role::Right | Role::Arg | Role::Module
                ) {
                    actual.push((
                        text(&parsed, source, node.occurrence),
                        role.role,
                        text(&parsed, source, role.occurrence),
                        role.name.map(|id| text(&parsed, source, id)),
                    ));
                }
            }
        }
        assert_eq!(
            actual,
            vec![
                ("import a.C", Role::Module, "import a.C", Some("C")),
                ("import a.C", Role::Module, "import a.C", Some("a.C")),
                ("import a.b.D", Role::Module, "import a.b.D", Some("D")),
                ("import a.b.D", Role::Module, "import a.b.D", Some("a.b.D")),
                (
                    "import a.E as Alias",
                    Role::Module,
                    "import a.E as Alias",
                    Some("E")
                ),
                (
                    "import a.E as Alias",
                    Role::Module,
                    "import a.E as Alias",
                    Some("a.E")
                ),
                (
                    "import a.E as Alias",
                    Role::Module,
                    "as Alias",
                    Some("Alias")
                ),
                ("import a.*", Role::Module, "import a.*", Some("a")),
                (
                    "val delegated by factory()",
                    Role::Left,
                    "delegated",
                    Some("delegated")
                ),
                (
                    "val delegated by factory()",
                    Role::Right,
                    "factory()",
                    Some("factory")
                ),
                (
                    "val initialized = factory()",
                    Role::Left,
                    "initialized",
                    Some("initialized")
                ),
                (
                    "val initialized = factory()",
                    Role::Right,
                    "factory()",
                    Some("factory")
                ),
                (
                    "val result = left combine right",
                    Role::Left,
                    "result",
                    Some("result")
                ),
                (
                    "val result = left combine right",
                    Role::Right,
                    "left combine right",
                    Some("combine")
                ),
                ("left combine right", Role::Arg, "right", Some("right")),
                (
                    "consume(left combine right)",
                    Role::Arg,
                    "left combine right",
                    Some("combine")
                ),
                ("left combine right", Role::Arg, "right", Some("right")),
                ("target = source", Role::Left, "target", Some("target")),
                ("target = source", Role::Right, "source", Some("source")),
                ("target += delta", Role::Left, "target", Some("target")),
                ("target += delta", Role::Right, "delta", Some("delta")),
            ]
        );
    }

    // The numeric token owns its suffix and sign. Nested magnitude nodes
    // must not introduce extra literal occurrences; unary identifiers are not literals.
    #[test]
    fn numeric_token_grammar_boundary() {
        let source = "val a = 1u; val b = 1uL; val c = 2L; val d = -3; val e = +4.5; val f = 0xffu; val g = -value; val h = !flag";
        assert_eq!(
            grammar_nodes(
                source,
                &["unsigned_literal", "long_literal", "prefix_expression"]
            ),
            [
                ("unsigned_literal".into(), "1u"),
                ("unsigned_literal".into(), "1uL"),
                ("long_literal".into(), "2L"),
                ("prefix_expression".into(), "-3"),
                ("prefix_expression".into(), "+4.5"),
                ("unsigned_literal".into(), "0xffu"),
                ("prefix_expression".into(), "-value"),
                ("prefix_expression".into(), "!flag"),
            ]
        );
        let parsed = parse(source);
        let actual: Vec<_> = parsed
            .source_facts
            .as_ref()
            .unwrap()
            .structural
            .nodes()
            .iter()
            .filter(|node| node.kind == NormalizedKind::NumericLiteral)
            .map(|node| text(&parsed, source, node.occurrence))
            .collect();
        assert_eq!(actual, ["1u", "1uL", "2L", "-3", "+4.5", "0xffu"]);
    }

    #[test]
    fn recovery_grammar_boundary() {
        let source = "fun valid() { call() }\nfun broken( {";
        assert_eq!(
            grammar_nodes(source, &["ERROR"]),
            [("ERROR".into(), "fun broken( {")]
        );
        let parsed = parse(source);
        let facts = &parsed.source_facts.as_ref().unwrap().structural;
        let errors: Vec<_> = facts
            .recovered_regions()
            .iter()
            .map(|span| span.text(source))
            .collect();
        assert_eq!(errors, ["fun broken( {"]);
        // The query layer materializes SyntaxError from recovered regions.
        // Capability discovery must admit those rows, alongside ordinary calls.
        assert!(
            facts
                .nodes()
                .iter()
                .any(|node| node.kind == NormalizedKind::Call)
        );
        for kind in [NormalizedKind::SyntaxError, NormalizedKind::Call] {
            assert!(KOTLIN_STRUCTURAL_SPEC.supports_kind(kind), "{kind:?}");
        }
    }
}
