//! Scala structural spec for `query_code`.

use brokk_bifrost_core::analyzer::structural::adapter_helpers::{
    attach_argument_role_with_derived_name, attach_role_with_derived_name, attach_terminal_callee,
    chain_name_child, field_name_in_parent, first_named_child, nearest_ancestor,
};
use brokk_bifrost_core::analyzer::structural::callable::{
    CallKind, CallSiteContext, CallSiteFacts,
};
use brokk_bifrost_core::analyzer::structural::edges::{
    INVERSE_REFERENCE_EDGE_SUPPORT, ReferenceEdgeSupport,
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
    BindingActivation, BindingKind, CALLABLE_APPLICABILITY_ONLY_SUPPORT, HoistingClass,
    LexicalEnvironmentSupport,
};
use brokk_bifrost_core::analyzer::structural::routes::{
    IdentityRouteSupport, NO_IDENTITY_ROUTE_SUPPORT,
};
use brokk_bifrost_core::analyzer::structural::spec::{RoleSink, StructuralSpec};
use brokk_bifrost_core::analyzer::{Language, Range};
use tree_sitter::Node;

/// The left-nested qualified-name chains of the Scala grammar, paired with the
/// field that names each link's own segment.
///
/// Neither chain node carries grammar fields at all: `stable_identifier` is
/// `seq(choice(_identifier, stable_identifier), ".", _identifier)` and
/// `stable_type_identifier` ends in a `type_identifier`, so both spell their
/// own segment positionally as the last named child. `None` is what selects
/// that reading in `chain_name_child`; a field lookup would be false for every
/// child and would classify a whole qualified type as path segments (#1644).
const SCALA_PATH_CHAIN: &[(&str, Option<&str>)] = &[
    ("stable_identifier", None),
    ("stable_type_identifier", None),
];

/// The declaration heads whose `name` field is the declared symbol itself.
const SCALA_DECLARATION_HEADS: &[&str] = &[
    "class_definition",
    "object_definition",
    "trait_definition",
    "enum_definition",
    "package_object",
    "given_definition",
    "function_definition",
    "function_declaration",
    "type_definition",
    "val_declaration",
    "var_declaration",
    "simple_enum_case",
    "full_enum_case",
    "type_parameters",
    "covariant_type_parameter",
    "contravariant_type_parameter",
    "type_lambda",
];

/// The binding forms whose `name` field introduces a fresh local binding.
///
/// `binding` is a parenthesized lambda parameter (`(a: Int, b: Int) => ...`),
/// `context_bound` is the Scala 3 named context bound (`[T: Ord as ord]`).
const SCALA_BINDER_HEADS: &[&str] = &["parameter", "class_parameter", "binding", "context_bound"];

#[derive(Debug, Default)]
pub struct ScalaStructuralSpec;

pub static SCALA_STRUCTURAL_SPEC: ScalaStructuralSpec = ScalaStructuralSpec;

pub const SCALA_KIND_TABLE: &[(&str, NormalizedKind)] = &[
    ("call_expression", NormalizedKind::Call),
    ("infix_expression", NormalizedKind::Call),
    ("postfix_expression", NormalizedKind::Call),
    ("field_expression", NormalizedKind::FieldAccess),
    ("function_definition", NormalizedKind::Function),
    ("function_declaration", NormalizedKind::Function),
    ("lambda_expression", NormalizedKind::Lambda),
    ("class_definition", NormalizedKind::Class),
    ("object_definition", NormalizedKind::Class),
    ("trait_definition", NormalizedKind::Class),
    ("enum_definition", NormalizedKind::Class),
    // A `type` alias declares a type, so its fact is a type-namespace
    // declaration and its name inherits `Namespace::Type` through
    // `declared_fact_kind`. Absent from the table, the alias name had no
    // declaring fact at all and landed in the value namespace (#2878).
    ("type_definition", NormalizedKind::Class),
    ("val_definition", NormalizedKind::Assignment),
    ("var_definition", NormalizedKind::Assignment),
    ("assignment_expression", NormalizedKind::Assignment),
    ("import_declaration", NormalizedKind::Import),
    ("annotation", NormalizedKind::Decorator),
    ("identifier", NormalizedKind::Identifier),
    ("operator_identifier", NormalizedKind::Identifier),
    ("type_identifier", NormalizedKind::Identifier),
    ("stable_type_identifier", NormalizedKind::Identifier),
    ("string", NormalizedKind::StringLiteral),
    (
        "interpolated_string_expression",
        NormalizedKind::StringLiteral,
    ),
    ("character_literal", NormalizedKind::StringLiteral),
    ("prefix_expression", NormalizedKind::NumericLiteral),
    ("integer_literal", NormalizedKind::NumericLiteral),
    ("floating_point_literal", NormalizedKind::NumericLiteral),
    ("boolean_literal", NormalizedKind::BooleanLiteral),
    ("null_literal", NormalizedKind::NullLiteral),
    ("return_expression", NormalizedKind::Return),
    ("throw_expression", NormalizedKind::Throw),
    ("catch_clause", NormalizedKind::Catch),
    ("if_expression", NormalizedKind::If),
    ("for_expression", NormalizedKind::ForLoop),
    ("while_expression", NormalizedKind::WhileLoop),
    ("do_while_expression", NormalizedKind::WhileLoop),
];

fn last_named_child<'tree>(node: Node<'tree>) -> Option<Node<'tree>> {
    (0..node.named_child_count())
        .rev()
        .find_map(|index| node.named_child(index))
}

fn single_named_child(node: Node<'_>) -> Option<Node<'_>> {
    if node.named_child_count() == 1 {
        node.named_child(0)
    } else {
        None
    }
}

fn expression_target_node(mut node: Node<'_>) -> Node<'_> {
    while matches!(node.kind(), "expression" | "parenthesized_expression") {
        let Some(child) = first_named_child(node) else {
            break;
        };
        node = child;
    }
    node
}

fn expression_name_node<'tree>(expression: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = expression_target_node(expression);
    loop {
        match current.kind() {
            "identifier" | "operator_identifier" | "type_identifier" => return Some(current),
            "stable_type_identifier" => current = last_named_child(current)?,
            "call_expression" => current = current.child_by_field_name("function")?,
            "generic_function" => current = current.child_by_field_name("function")?,
            "field_expression" => current = current.child_by_field_name("field")?,
            "assignment_expression" => current = current.child_by_field_name("left")?,
            "binding" => current = current.child_by_field_name("name")?,
            _ => return None,
        }
    }
}

/// The applied method of a postfix application (`rows toList`).
///
/// The grammar spells neither operand of a `postfix_expression` in a field, so
/// the method is read positionally: it is the last identifier of the
/// expression, and everything before it is the receiver.
fn postfix_operator_node(node: Node<'_>) -> Option<Node<'_>> {
    (0..node.named_child_count())
        .filter_map(|index| node.named_child(index))
        .rfind(|child| matches!(child.kind(), "identifier" | "operator_identifier"))
}

fn call_function_node(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "infix_expression" => node.child_by_field_name("operator"),
        "postfix_expression" => postfix_operator_node(node),
        _ => node
            .child_by_field_name("function")
            .map(expression_target_node),
    }
}

fn callable_target_node(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = expression_target_node(node);
    while current.kind() == "generic_function" {
        current = current
            .child_by_field_name("function")
            .map(expression_target_node)?;
    }
    Some(current)
}

fn is_numeric_literal_node(node: Node<'_>) -> bool {
    matches!(node.kind(), "integer_literal" | "floating_point_literal")
}

fn prefix_argument(node: Node<'_>) -> Option<Node<'_>> {
    last_named_child(node).map(expression_target_node)
}

fn is_signed_numeric_prefix(node: Node<'_>) -> bool {
    node.kind() == "prefix_expression"
        && prefix_argument(node).is_some_and(is_numeric_literal_node)
        && (0..node.child_count())
            .filter_map(|index| node.child(index))
            .any(|child| !child.is_named() && matches!(child.kind(), "+" | "-"))
}

fn is_inside_signed_numeric_wrapper(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    is_signed_numeric_prefix(parent)
}

fn is_named_argument_assignment(node: Node<'_>) -> bool {
    node.kind() == "assignment_expression"
        && node
            .parent()
            .is_some_and(|parent| parent.kind() == "arguments")
}

fn attach_argument_roles(sink: &mut RoleSink<'_>, arguments: Node<'_>) {
    match arguments.kind() {
        "arguments" => {
            for index in 0..arguments.named_child_count() {
                if !sink.should_continue() {
                    break;
                }
                let Some(argument) = arguments.named_child(index) else {
                    continue;
                };
                let argument = expression_target_node(argument);
                if let Some((keyword, value)) = named_argument_parts(argument) {
                    sink.kwarg(keyword, value);
                } else {
                    attach_argument_role_with_derived_name(sink, argument, expression_name_node);
                }
            }
        }
        "block" | "case_block" => {
            let argument = single_named_child(arguments)
                .map(expression_target_node)
                .unwrap_or(arguments);
            attach_role_with_derived_name(sink, Role::Arg, argument, expression_name_node);
        }
        "colon_argument" => {
            if let Some(argument) = last_named_child(arguments).map(expression_target_node) {
                let argument = single_named_child(argument)
                    .map(expression_target_node)
                    .unwrap_or(argument);
                attach_role_with_derived_name(sink, Role::Arg, argument, expression_name_node);
            }
        }
        _ => {}
    }
}

fn named_argument_parts(argument: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    if argument.kind() != "assignment_expression" {
        return None;
    }
    let keyword = argument
        .child_by_field_name("left")
        .map(expression_target_node)?;
    if !matches!(keyword.kind(), "identifier" | "operator_identifier") {
        return None;
    }
    let value = argument
        .child_by_field_name("right")
        .map(expression_target_node)?;
    Some((keyword, value))
}

fn pattern_name_node<'tree>(pattern: Node<'tree>) -> Option<Node<'tree>> {
    let current = expression_target_node(pattern);
    match current.kind() {
        "identifier" | "operator_identifier" => Some(current),
        "identifiers" => first_named_child(current),
        "binding" => current.child_by_field_name("name"),
        _ => expression_name_node(current).or_else(|| first_named_child(current)),
    }
}

fn attach_decorators(sink: &mut RoleSink<'_>, declaration: Node<'_>) {
    for index in 0..declaration.named_child_count() {
        let Some(child) = declaration.named_child(index) else {
            continue;
        };
        if child.kind() == "annotation" {
            attach_role_with_derived_name(sink, Role::Decorator, child, expression_name_node);
        }
    }
}

fn is_case_class(node: Node<'_>) -> bool {
    node.kind() == "class_definition"
        && (0..node.child_count())
            .filter_map(|index| node.child(index))
            .any(|child| !child.is_named() && child.kind() == "case")
}

fn attach_class_parameters(sink: &mut RoleSink<'_>, declaration: Node<'_>) {
    let mut cursor = declaration.walk();
    for parameters in declaration.children_by_field_name("class_parameters", &mut cursor) {
        for index in 0..parameters.named_child_count() {
            let Some(parameter) = parameters.named_child(index) else {
                continue;
            };
            if parameter.kind() != "class_parameter" {
                continue;
            }
            if let Some(name) = parameter.child_by_field_name("name") {
                sink.role_named(Role::Arg, parameter, name);
            }
        }
    }
}

fn annotation_name(node: Node<'_>) -> Option<Node<'_>> {
    for index in 0..node.named_child_count() {
        let child = node.named_child(index)?;
        if child.kind() == "arguments" {
            continue;
        }
        return expression_name_node(child).or(Some(child));
    }
    None
}

fn path_field_nodes(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.children_by_field_name("path", &mut cursor)
        .filter(|child| matches!(child.kind(), "identifier" | "operator_identifier"))
        .collect()
}

fn span_from(first: Node<'_>, last: Node<'_>) -> Span {
    Span {
        start_byte: first.start_byte(),
        end_byte: last.end_byte(),
    }
}

fn attach_path_module(sink: &mut RoleSink<'_>, target: Node<'_>, path: &[Node<'_>]) {
    let Some(last) = path.last().copied() else {
        return;
    };
    sink.role_named(Role::Module, target, last);
    if path.len() > 1 {
        sink.role_named_span(Role::Module, target, span_from(path[0], last));
    }
}

fn attach_selector_module(sink: &mut RoleSink<'_>, selector: Node<'_>) {
    match selector.kind() {
        "identifier" | "operator_identifier" => {
            sink.role_named(Role::Module, selector, selector);
        }
        "as_renamed_identifier" | "arrow_renamed_identifier" => {
            let Some(alias) = selector.child_by_field_name("alias") else {
                return;
            };
            if alias.kind() != "wildcard" {
                sink.role_named(Role::Module, selector, alias);
            }
        }
        _ => {}
    }
}

/// Whether an import or export names what it brings in with a selector list, a
/// rename, or a wildcard rather than with the tail of its `path`.
///
/// Both the module-role edges and occurrence classification need the same
/// answer: with a selector present every `path` child is a scope segment, and
/// without one the last `path` child is the imported name itself.
fn has_namespace_selectors(node: Node<'_>) -> bool {
    (0..node.named_child_count())
        .filter_map(|index| node.named_child(index))
        .any(|child| {
            matches!(
                child.kind(),
                "namespace_selectors"
                    | "namespace_wildcard"
                    | "as_renamed_identifier"
                    | "arrow_renamed_identifier"
            )
        })
}

fn attach_import_modules(sink: &mut RoleSink<'_>, node: Node<'_>) {
    for index in 0..node.named_child_count() {
        let Some(child) = node.named_child(index) else {
            continue;
        };
        match child.kind() {
            "namespace_selectors" => {
                for selector_index in 0..child.named_child_count() {
                    if let Some(selector) = child.named_child(selector_index) {
                        attach_selector_module(sink, selector);
                    }
                }
            }
            "as_renamed_identifier" | "arrow_renamed_identifier" => {
                attach_selector_module(sink, child)
            }
            _ => {}
        }
    }
    if !has_namespace_selectors(node) {
        attach_path_module(sink, node, &path_field_nodes(node));
    }
}

static SCALA_OCCURRENCE_ROLE_SUPPORT: OccurrenceRoleSupport = OccurrenceRoleSupport::NONE
    .supported(OccurrenceRole::DeclarationName)
    .supported(OccurrenceRole::Binder)
    .supported(OccurrenceRole::LabelOrKey)
    .supported(OccurrenceRole::TypeOperand)
    .supported(OccurrenceRole::PathSegment)
    .supported(OccurrenceRole::ImportAlias)
    .supported(OccurrenceRole::ImportTarget)
    .supported(OccurrenceRole::ReceiverPosition)
    .supported(OccurrenceRole::MemberPosition)
    .supported(OccurrenceRole::PatternPosition)
    .supported(OccurrenceRole::ValueReference);

/// What a pattern slot does with the token that fills it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PatternSlot {
    /// A bare identifier here introduces a fresh binding.
    Binds,
    /// The slot names something declared elsewhere: an extractor, an infix
    /// extractor's operator, or a matched constant.
    Matches,
}

/// The pattern slot `anchor` occupies in `parent`, or `None` when `parent` is
/// not a pattern position at all.
///
/// Scala spells a pattern with the same node kinds as an expression, so the
/// slot -- not the token -- is what says a name is being bound. `case other`
/// and `case Other` are spelled identically apart from the capital letter, and
/// this classifier never reads a spelling to tell them apart: a bare
/// identifier in a binding slot is a binder, and a qualified chain in the same
/// slot is a match, which the caller decides from the chain it climbed.
fn scala_pattern_slot(parent: Node<'_>, anchor: Node<'_>) -> Option<PatternSlot> {
    let field = field_name_in_parent(parent, anchor);
    match parent.kind() {
        "case_clause" | "catch_clause" | "val_definition" | "var_definition" | "typed_pattern"
        | "repeat_pattern"
            if field == Some("pattern") =>
        {
            Some(PatternSlot::Binds)
        }
        // `case whole @ Some(inner)` binds through both of its fields.
        "capture_pattern" => Some(PatternSlot::Binds),
        // `val a, b = 1` and the tuple, alternative and named pattern forms
        // hold their sub-patterns positionally.
        "identifiers"
        | "tuple_pattern"
        | "alternative_pattern"
        | "named_pattern"
        | "named_tuple_pattern" => Some(PatternSlot::Binds),
        // `case Widget(a, b)`: the `type` field names the extractor.
        "case_class_pattern" => Some(match field {
            Some("type") => PatternSlot::Matches,
            _ => PatternSlot::Binds,
        }),
        // `case a :: rest`: the operator names the infix extractor.
        "infix_pattern" => Some(match field {
            Some("operator") => PatternSlot::Matches,
            _ => PatternSlot::Binds,
        }),
        // A `for` enumerator has no fields at all; its grammar rule is
        // `_pattern ("<-" | "=") expression guard?`, so the pattern is
        // positionally the first named child.
        "enumerator" if first_named_child(parent).map(|first| first.id()) == Some(anchor.id()) => {
            Some(PatternSlot::Binds)
        }
        _ => None,
    }
}

/// Classify one Scala identifier token by its AST position.
///
/// `operator_identifier` is classified alongside `identifier` and
/// `type_identifier` because it is a name token of the same standing in this
/// grammar: `def +(other: Int)` declares a method with it and `case a :: rest`
/// matches an extractor with it, and leaving it out would silently drop those
/// occurrences.
///
/// Compound `stable_identifier`/`stable_type_identifier` nodes are *not*
/// classified: an occurrence is a token, so the chain contributes its segments
/// (`PathSegment`) and its tail (the role the whole chain plays in context),
/// never a third row spanning both.
fn scala_occurrence_role(node: Node<'_>) -> Option<OccurrenceRole> {
    if !matches!(
        node.kind(),
        "identifier" | "operator_identifier" | "type_identifier"
    ) {
        return None;
    }

    // Climb out of any qualified-name chain this token terminates. A token in
    // a scope position is a path segment however deep the chain runs; which
    // child spells the chain node's own segment comes from `SCALA_PATH_CHAIN`.
    let mut anchor = node;
    let mut parent = anchor.parent()?;
    while let Some(&(_, name_field)) = SCALA_PATH_CHAIN
        .iter()
        .find(|(kind, _)| *kind == parent.kind())
    {
        if chain_name_child(parent, name_field).map(|name| name.id()) != Some(anchor.id()) {
            return Some(OccurrenceRole::PathSegment);
        }
        anchor = parent;
        parent = anchor.parent()?;
    }
    let chain_tail = anchor.id() != node.id();

    if let Some(slot) = scala_pattern_slot(parent, anchor) {
        // A chain in a binding slot still matches something declared
        // elsewhere: `case Colors.Red =>` names a constant where
        // `case other =>` introduces a binding.
        return Some(if slot == PatternSlot::Binds && !chain_tail {
            OccurrenceRole::Binder
        } else {
            OccurrenceRole::PatternPosition
        });
    }

    let field = field_name_in_parent(parent, anchor);
    let parent_kind = parent.kind();
    let role = match parent_kind {
        // `package app.model` declares `model` inside `app`; the leading
        // segments are its scope, exactly as a Java package clause's are.
        "package_identifier" => {
            if last_named_child(parent).map(|last| last.id()) == Some(anchor.id()) {
                OccurrenceRole::DeclarationName
            } else {
                OccurrenceRole::PathSegment
            }
        }
        // `import a.b.C` names its target with the last `path` child. With a
        // selector list, a rename or a wildcard the target is spelled in the
        // selector instead and every path child is a scope segment. `export`
        // has the identical shape.
        "import_declaration" | "export_declaration" => {
            if !has_namespace_selectors(parent)
                && path_field_nodes(parent).last().map(|last| last.id()) == Some(anchor.id())
            {
                OccurrenceRole::ImportTarget
            } else {
                OccurrenceRole::PathSegment
            }
        }
        "namespace_selectors" => OccurrenceRole::ImportTarget,
        "as_renamed_identifier" | "arrow_renamed_identifier" => match field {
            Some("alias") => OccurrenceRole::ImportAlias,
            _ => OccurrenceRole::ImportTarget,
        },
        "field_expression" => match field {
            Some("field") => OccurrenceRole::MemberPosition,
            Some("value") => OccurrenceRole::ReceiverPosition,
            _ => OccurrenceRole::ValueReference,
        },
        // `a + b` applies `+` to `a`, so the operator is the member and the
        // left operand the receiver; the right operand is an argument.
        "infix_expression" => match field {
            Some("operator") => OccurrenceRole::MemberPosition,
            Some("left") => OccurrenceRole::ReceiverPosition,
            _ => OccurrenceRole::ValueReference,
        },
        "postfix_expression" => {
            if postfix_operator_node(parent).map(|operator| operator.id()) == Some(anchor.id()) {
                OccurrenceRole::MemberPosition
            } else {
                OccurrenceRole::ReceiverPosition
            }
        }
        // A named argument is an `assignment_expression` inside `arguments`,
        // which is also why `should_extract` keeps it from becoming an
        // assignment fact.
        "assignment_expression"
            if field == Some("left") && is_named_argument_assignment(parent) =>
        {
            OccurrenceRole::LabelOrKey
        }
        "named_type_argument" if field == Some("name") => OccurrenceRole::LabelOrKey,
        // `xs.map(item => item.trim)` binds its single parameter directly in
        // the lambda's `parameters` field; a parenthesized list binds through
        // `bindings`, whose `binding` children are in SCALA_BINDER_HEADS.
        "lambda_expression" if field == Some("parameters") => OccurrenceRole::Binder,
        _ if field == Some("name") && SCALA_DECLARATION_HEADS.contains(&parent_kind) => {
            OccurrenceRole::DeclarationName
        }
        _ if field == Some("name") && SCALA_BINDER_HEADS.contains(&parent_kind) => {
            OccurrenceRole::Binder
        }
        // Every remaining `type_identifier` position is a type operand
        // (extends and with clauses, type arguments, bounds, ascriptions,
        // annotations, `new` targets); every remaining identifier is a read.
        _ if node.kind() == "type_identifier" => OccurrenceRole::TypeOperand,
        _ => OccurrenceRole::ValueReference,
    };
    Some(role)
}

/// The binding one Scala binder token introduces, and the interval it is in
/// effect over.
///
/// Scala has four shapes and they differ only in that interval:
///
/// - A parameter -- method, class, or lambda -- is in effect over its whole
///   callable, which is exactly the declaring scope, so it is `ScopeWide`.
///   That is what makes a parameter reachable from inside a body whose byte
///   range does not contain the parameter list.
/// - A `val`/`var` local is in effect from the end of its definition to the
///   end of its scope (`SourceOrder`), which is why a read above it reaches
///   nothing.
/// - A pattern binder is in effect from the end of the pattern to the end of
///   its `case` clause (`DeclaredHead`), which is a named sub-range of the
///   declaring scope rather than a suffix of it. The guard is inside that
///   range because `case x if x > 0 =>` reads the binder in it. A `catch`
///   binder is the same shape and gets the same answer: Scala's catch is a
///   pattern match, and its braced form nests the case clause in a
///   `case_block` while Scala 3's braceless `try x catch case e: E => e`
///   inlines the same case pattern into the `catch_clause` itself.
/// - A `for` binder -- a generator or a `=` definition -- is in effect from
///   the end of the enumerator's own right-hand side to the end of the whole
///   `for` expression, so it covers its own guard, the remaining enumerators
///   and the yield or body, and not the expression it is generated from.
fn scala_binding_activation(binder: Node<'_>, scope: Range) -> Option<BindingActivation> {
    let form = nearest_ancestor(binder, |kind| {
        matches!(
            kind,
            "parameter"
                | "class_parameter"
                | "binding"
                | "lambda_expression"
                | "val_definition"
                | "var_definition"
                | "case_clause"
                | "catch_clause"
                | "enumerator"
        )
    })?;
    match form.kind() {
        "parameter" | "class_parameter" | "binding" | "lambda_expression" => {
            Some(BindingActivation {
                kind: BindingKind::Parameter,
                hoisting: HoistingClass::ScopeWide,
                activation: scope,
            })
        }
        "case_clause" | "catch_clause" => {
            let pattern = form.child_by_field_name("pattern")?;
            Some(BindingActivation {
                kind: BindingKind::PatternBinder,
                hoisting: HoistingClass::DeclaredHead,
                activation: Range {
                    start_byte: pattern.end_byte(),
                    end_byte: form.end_byte(),
                    start_line: pattern.end_position().row + 1,
                    end_line: form.end_position().row + 1,
                },
            })
        }
        "enumerator" => {
            let generated_from = form.named_child(1)?;
            let for_expression = nearest_ancestor(form, |kind| kind == "for_expression")?;
            Some(BindingActivation {
                kind: BindingKind::LoopVariable,
                hoisting: HoistingClass::DeclaredHead,
                activation: Range {
                    start_byte: generated_from.end_byte(),
                    end_byte: for_expression.end_byte(),
                    start_line: generated_from.end_position().row + 1,
                    end_line: for_expression.end_position().row + 1,
                },
            })
        }
        _ => Some(BindingActivation {
            kind: BindingKind::Local,
            hoisting: HoistingClass::SourceOrder,
            activation: Range {
                start_byte: form.end_byte(),
                end_byte: scope.end_byte,
                start_line: form.end_position().row + 1,
                end_line: scope.end_line,
            },
        }),
    }
}

impl StructuralSpec for ScalaStructuralSpec {
    fn language(&self) -> Language {
        Language::Scala
    }

    fn supports_boolean_literal_value(&self) -> bool {
        true
    }

    fn kind_table(&self) -> &'static [(&'static str, NormalizedKind)] {
        SCALA_KIND_TABLE
    }

    fn generator_construct(&self, node: Node<'_>, _kind: NormalizedKind) -> Option<&'static str> {
        is_case_class(node).then_some("scala_case_class")
    }

    fn refine_kind(
        &self,
        _node: Node<'_>,
        kind: NormalizedKind,
        enclosing: Option<NormalizedKind>,
        _source: &str,
        _context: &CallSiteContext,
    ) -> NormalizedKind {
        if kind == NormalizedKind::Function && enclosing == Some(NormalizedKind::Class) {
            NormalizedKind::Method
        } else {
            kind
        }
    }

    fn should_extract(&self, node: Node<'_>, kind: NormalizedKind) -> bool {
        if kind == NormalizedKind::NumericLiteral {
            if node.kind() == "prefix_expression" {
                return is_signed_numeric_prefix(node);
            }
            if is_numeric_literal_node(node) && is_inside_signed_numeric_wrapper(node) {
                return false;
            }
        }

        kind != NormalizedKind::Assignment || !is_named_argument_assignment(node)
    }

    /// Scala's grammar names two call shapes the shared arena cannot: an
    /// `infix_expression` is an infix application (an `operator_identifier`
    /// operator makes it a symbolic operator application), and a
    /// `call_expression` whose own function is another `call_expression` is
    /// one more argument list of a curried application, not a call of the
    /// inner call's result. `new Foo(1)` is deliberately absent: the grammar
    /// spells it `instance_expression`, which this adapter's kind table does
    /// not admit as a call at all, so there is no Scala constructor call site
    /// to classify yet (#1478).
    fn call_site_facts(
        &self,
        node: Node<'_>,
        _source: &str,
        _context: &CallSiteContext,
    ) -> Option<CallSiteFacts> {
        match node.kind() {
            "infix_expression" => {
                let operator = node.child_by_field_name("operator")?;
                Some(CallSiteFacts::of_kind(
                    if operator.kind() == "operator_identifier" {
                        CallKind::Operator
                    } else {
                        CallKind::Infix
                    },
                ))
            }
            "call_expression" => {
                let function = callable_target_node(
                    node.child_by_field_name("function")
                        .map(expression_target_node)?,
                )?;
                (function.kind() == "call_expression")
                    .then(|| CallSiteFacts::unrefined().continuing())
            }
            _ => None,
        }
    }

    fn supports_kind(&self, kind: NormalizedKind) -> bool {
        kind == NormalizedKind::Method
            || self
                .kind_table()
                .iter()
                .any(|(_, fact_kind)| fact_kind.satisfies(kind))
    }

    fn supports_role(&self, role: Role) -> bool {
        // #2647: not yet extracted by this adapter.
        !matches!(role, Role::Iterable | Role::Element)
    }

    fn occurrence_role_support(&self) -> &OccurrenceRoleSupport {
        &SCALA_OCCURRENCE_ROLE_SUPPORT
    }

    fn lexical_environment_support(&self) -> &LexicalEnvironmentSupport {
        // Scala classifies occurrence roles and states a binding interval for
        // every binder it emits (#1597 slice 1), but it derives no scope tree,
        // no import binders and no package clause yet, so the axes those feed
        // stay unsupported until slice 2 builds the environment on top of this
        // classification. `scala_filter_callable_units` does report
        // per-candidate callable applicability (#1478 M3). The per-axis table
        // states exactly that rather than rounding it either way.
        &CALLABLE_APPLICABILITY_ONLY_SUPPORT
    }

    fn materialization_support(&self) -> &DeclarationMaterializationSupport {
        &NO_MATERIALIZATION_SUPPORT
    }

    fn reference_edge_support(&self) -> &ReferenceEdgeSupport {
        &INVERSE_REFERENCE_EDGE_SUPPORT
    }

    fn identity_route_support(&self) -> &IdentityRouteSupport {
        &NO_IDENTITY_ROUTE_SUPPORT
    }

    fn binding_activation(&self, binder: Node<'_>, scope: Range) -> Option<BindingActivation> {
        scala_binding_activation(binder, scope)
    }

    fn extract(&self, node: Node<'_>, kind: NormalizedKind, sink: &mut RoleSink<'_>) {
        if let Some(role) = scala_occurrence_role(node) {
            sink.occurrence_role(node, role);
        }
        match kind {
            NormalizedKind::Call => {
                if let Some(function) = call_function_node(node) {
                    attach_terminal_callee(sink, function, expression_name_node(function));
                    if node.kind() == "infix_expression"
                        && let Some(receiver) = node.child_by_field_name("left")
                    {
                        attach_role_with_derived_name(
                            sink,
                            Role::Receiver,
                            receiver,
                            expression_name_node,
                        );
                    }
                    if node.kind() == "postfix_expression"
                        && let Some(receiver) = node.named_child(0)
                        && receiver.end_byte() <= function.start_byte()
                    {
                        attach_role_with_derived_name(
                            sink,
                            Role::Receiver,
                            receiver,
                            expression_name_node,
                        );
                    }
                    if let Some(target) = callable_target_node(function)
                        && target.kind() == "field_expression"
                        && let Some(receiver) = target.child_by_field_name("value")
                    {
                        attach_role_with_derived_name(
                            sink,
                            Role::Receiver,
                            receiver,
                            expression_name_node,
                        );
                    }
                }
                if node.kind() == "infix_expression"
                    && let Some(argument) = node.child_by_field_name("right")
                {
                    attach_argument_role_with_derived_name(sink, argument, expression_name_node);
                }
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    attach_argument_roles(sink, arguments);
                }
            }
            NormalizedKind::FieldAccess => {
                if let Some(field) = node.child_by_field_name("field") {
                    sink.role_named(Role::Field, field, field);
                    sink.set_name(field);
                }
                if let Some(object) = node.child_by_field_name("value") {
                    attach_role_with_derived_name(sink, Role::Object, object, expression_name_node);
                }
            }
            NormalizedKind::Function
            | NormalizedKind::Method
            | NormalizedKind::Constructor
            | NormalizedKind::Class => {
                if let Some(name) = node.child_by_field_name("name") {
                    sink.set_name(name);
                }
                attach_decorators(sink, node);
                if is_case_class(node) {
                    attach_class_parameters(sink, node);
                }
            }
            NormalizedKind::Assignment => match node.kind() {
                "val_definition" | "var_definition" => {
                    if let Some(pattern) = node.child_by_field_name("pattern") {
                        attach_role_with_derived_name(sink, Role::Left, pattern, pattern_name_node);
                        if let Some(name) = pattern_name_node(pattern) {
                            sink.set_name(name);
                        }
                    }
                    if let Some(value) = node.child_by_field_name("value") {
                        let value = expression_target_node(value);
                        attach_role_with_derived_name(
                            sink,
                            Role::Right,
                            value,
                            expression_name_node,
                        );
                    }
                }
                _ => {
                    if let Some(left) = node.child_by_field_name("left") {
                        let left = expression_target_node(left);
                        attach_role_with_derived_name(sink, Role::Left, left, expression_name_node);
                        if let Some(name) = expression_name_node(left) {
                            sink.set_name(name);
                        }
                    }
                    if let Some(right) = node.child_by_field_name("right") {
                        let right = expression_target_node(right);
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
                if let Some(name) = annotation_name(node) {
                    attach_terminal_callee(sink, name, expression_name_node(name).or(Some(name)));
                }
            }
            NormalizedKind::Identifier => match expression_name_node(node) {
                Some(name) => sink.set_name(name),
                None => sink.set_name(node),
            },
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SCALA_STRUCTURAL_SPEC, scala_occurrence_role};
    use brokk_bifrost_core::analyzer::structural::adapter_helpers::{nearest_ancestor, node_range};
    use brokk_bifrost_core::analyzer::structural::occurrences::OccurrenceRole;
    use brokk_bifrost_core::analyzer::structural::resolution::{BindingKind, HoistingClass};
    use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;
    use tree_sitter::Node;

    /// Every binder token of `source` with the binding the spec states for it,
    /// as `(token, kind, hoisting class, activation text)` in source order.
    ///
    /// The declaring scope passed in is the nearest enclosing callable, lambda
    /// or template, which is the range the environment layer will hand the
    /// adapter once Scala derives a scope tree. Until that lands the
    /// `BindingIntervals` axis stays unsupported and this is the only caller,
    /// so the intervals are asserted here rather than through a query.
    fn binding_activations(source: &str) -> Vec<(&str, BindingKind, HoistingClass, &str)> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&crate::scala::language::LANGUAGE.into())
            .expect("load Bifrost Scala grammar");
        let tree = parser.parse(source, None).expect("parse Scala");
        assert!(
            !tree.root_node().has_error(),
            "fixture must parse without recovery:\n{}",
            tree.root_node().to_sexp()
        );

        let mut found = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    stack.push(child);
                }
            }
            if scala_occurrence_role(node) != Some(OccurrenceRole::Binder) {
                continue;
            }
            let scope = nearest_ancestor(node, |kind| {
                matches!(
                    kind,
                    "function_definition"
                        | "lambda_expression"
                        | "class_definition"
                        | "object_definition"
                        | "trait_definition"
                )
            })
            .expect("every fixture binder sits in a callable, lambda or template");
            let binding = SCALA_STRUCTURAL_SPEC
                .binding_activation(node, node_range(scope))
                .expect("every classified binder states an interval");
            found.push((
                text_of(node, source),
                binding.kind,
                binding.hoisting,
                &source[binding.activation.start_byte..binding.activation.end_byte],
            ));
        }
        found
    }

    fn text_of<'source>(node: Node<'_>, source: &'source str) -> &'source str {
        &source[node.start_byte()..node.end_byte()]
    }

    /// The four binder shapes Scala has, and the interval each is in effect
    /// over. The shapes differ only in that interval, so the interval is what
    /// the assertions are about.
    #[test]
    fn scala_states_a_binding_interval_for_every_binder_shape() {
        let source = concat!(
            "object Host {\n",
            "  def run(rows: List[String], seed: Int): Int = {\n",
            "    val total = seed\n",
            "    val sizes = for (row <- rows if row.nonEmpty) yield row.length\n",
            "    rows.foreach { case entry => entry }\n",
            "    rows.map(item => item.length)\n",
            "    total\n",
            "  }\n",
            "}\n",
        );
        let found = binding_activations(source);
        assert_eq!(
            found
                .iter()
                .map(|(token, kind, hoisting, _)| (*token, *kind, *hoisting))
                .collect::<Vec<_>>(),
            vec![
                ("rows", BindingKind::Parameter, HoistingClass::ScopeWide),
                ("seed", BindingKind::Parameter, HoistingClass::ScopeWide),
                ("total", BindingKind::Local, HoistingClass::SourceOrder),
                ("sizes", BindingKind::Local, HoistingClass::SourceOrder),
                (
                    "row",
                    BindingKind::LoopVariable,
                    HoistingClass::DeclaredHead
                ),
                (
                    "entry",
                    BindingKind::PatternBinder,
                    HoistingClass::DeclaredHead
                ),
                ("item", BindingKind::Parameter, HoistingClass::ScopeWide),
            ],
            "{found:#?}"
        );

        let activation = |name: &str| {
            found
                .iter()
                .find(|(token, _, _, _)| *token == name)
                .unwrap_or_else(|| panic!("no binder named {name} in {found:#?}"))
                .3
        };

        // A parameter is in effect over its whole callable, which is what
        // makes it reachable from a body whose byte range excludes the
        // parameter list.
        assert!(
            activation("rows").starts_with("def run("),
            "{:?}",
            activation("rows")
        );
        // A local is in effect only below its own definition, which is why a
        // read above it reaches nothing.
        assert!(
            activation("total").starts_with("\n    val sizes"),
            "{:?}",
            activation("total")
        );
        // A generator covers its own guard, the remaining enumerators and the
        // yield -- and not the expression it is generated from.
        assert_eq!(activation("row"), " if row.nonEmpty) yield row.length");
        // A pattern binder covers the guard and the body of its own case.
        assert_eq!(activation("entry"), " => entry");
        // A lambda parameter is scope-wide over the lambda itself.
        assert_eq!(activation("item"), "item => item.length");
    }

    /// Scala 3's braceless `catch` inlines its case pattern into the
    /// `catch_clause` itself, where the braced form nests a `case_clause` in a
    /// `case_block`. Both spellings are the same construct, so both must state
    /// the same interval rather than let the binder climb to an outer form.
    #[test]
    fn a_braceless_catch_binder_is_scoped_to_its_own_clause() {
        let source = concat!(
            "object Host {\n",
            "  val outcome = try compute() catch case failure: RuntimeException => failure\n",
            "}\n",
        );
        let found = binding_activations(source);
        let failure = found
            .iter()
            .find(|(token, _, _, _)| *token == "failure")
            .unwrap_or_else(|| panic!("the catch pattern binds: {found:#?}"));
        assert_eq!(
            (failure.1, failure.2),
            (BindingKind::PatternBinder, HoistingClass::DeclaredHead)
        );
        assert_eq!(failure.3, " => failure");
    }
}
