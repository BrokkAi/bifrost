//! PHP structural spec for `query_code`.

use brokk_bifrost_core::analyzer::structural::adapter_helpers::{
    attach_role_with_derived_name, attach_terminal_callee, field_name_in_parent, first_named_child,
    is_spread_argument_node, nearest_ancestor,
};
use brokk_bifrost_core::analyzer::structural::callable::CallSiteContext;
use brokk_bifrost_core::analyzer::structural::edges::{
    INVERSE_REFERENCE_EDGE_SUPPORT, ReferenceEdgeSupport,
};
use brokk_bifrost_core::analyzer::structural::kinds::{NormalizedKind, Role};
use brokk_bifrost_core::analyzer::structural::materialization::{
    DeclarationMaterializationSupport, NO_MATERIALIZATION_SUPPORT,
};
use brokk_bifrost_core::analyzer::structural::occurrences::{
    Namespace, OccurrenceRole, OccurrenceRoleSupport, default_occurrence_namespace,
};
use brokk_bifrost_core::analyzer::structural::resolution::{
    BindingActivation, BindingKind, EnvironmentAxis, HoistingClass, ImportActivation,
    LexicalEnvironmentSupport, ScopeFormation,
};
use brokk_bifrost_core::analyzer::structural::routes::{
    CuratedExportSurface, IdentityRouteSupport, NO_IDENTITY_ROUTE_SUPPORT, RouteHopKind,
};
use brokk_bifrost_core::analyzer::structural::spec::{RoleSink, StructuralSpec};
use brokk_bifrost_core::analyzer::{Language, Range};
use tree_sitter::Node;

#[derive(Debug, Default)]
pub struct PhpStructuralSpec;

pub static PHP_STRUCTURAL_SPEC: PhpStructuralSpec = PhpStructuralSpec;

pub const PHP_KIND_TABLE: &[(&str, NormalizedKind)] = &[
    ("function_call_expression", NormalizedKind::Call),
    ("member_call_expression", NormalizedKind::Call),
    ("nullsafe_member_call_expression", NormalizedKind::Call),
    ("scoped_call_expression", NormalizedKind::Call),
    ("object_creation_expression", NormalizedKind::Call),
    ("member_access_expression", NormalizedKind::FieldAccess),
    (
        "nullsafe_member_access_expression",
        NormalizedKind::FieldAccess,
    ),
    (
        "scoped_property_access_expression",
        NormalizedKind::FieldAccess,
    ),
    (
        "class_constant_access_expression",
        NormalizedKind::FieldAccess,
    ),
    ("function_definition", NormalizedKind::Function),
    ("method_declaration", NormalizedKind::Method),
    ("anonymous_function", NormalizedKind::Lambda),
    ("arrow_function", NormalizedKind::Lambda),
    ("class_declaration", NormalizedKind::Class),
    ("interface_declaration", NormalizedKind::Class),
    ("trait_declaration", NormalizedKind::Class),
    ("enum_declaration", NormalizedKind::Class),
    ("namespace_definition", NormalizedKind::Module),
    ("property_element", NormalizedKind::Assignment),
    ("const_element", NormalizedKind::Assignment),
    ("assignment_expression", NormalizedKind::Assignment),
    (
        "augmented_assignment_expression",
        NormalizedKind::Assignment,
    ),
    (
        "reference_assignment_expression",
        NormalizedKind::Assignment,
    ),
    ("namespace_use_declaration", NormalizedKind::Import),
    ("attribute", NormalizedKind::Decorator),
    ("name", NormalizedKind::Identifier),
    ("namespace_name", NormalizedKind::Identifier),
    ("qualified_name", NormalizedKind::Identifier),
    ("relative_scope", NormalizedKind::Identifier),
    ("variable_name", NormalizedKind::Identifier),
    ("string", NormalizedKind::StringLiteral),
    ("encapsed_string", NormalizedKind::StringLiteral),
    ("unary_op_expression", NormalizedKind::NumericLiteral),
    ("integer", NormalizedKind::NumericLiteral),
    ("float", NormalizedKind::NumericLiteral),
    ("boolean", NormalizedKind::BooleanLiteral),
    ("null", NormalizedKind::NullLiteral),
    ("return_statement", NormalizedKind::Return),
    ("throw_expression", NormalizedKind::Throw),
    ("catch_clause", NormalizedKind::Catch),
    ("if_statement", NormalizedKind::If),
    ("for_statement", NormalizedKind::Loop),
    ("foreach_statement", NormalizedKind::ForLoop),
    ("while_statement", NormalizedKind::WhileLoop),
    ("do_statement", NormalizedKind::WhileLoop),
];

fn last_named_child<'tree>(node: Node<'tree>) -> Option<Node<'tree>> {
    (0..node.named_child_count())
        .rev()
        .find_map(|index| node.named_child(index))
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
            "name" | "relative_scope" => return Some(current),
            "namespace_name" | "qualified_name" => current = last_named_child(current)?,
            "variable_name" | "named_type" => current = first_named_child(current)?,
            "function_call_expression" => current = current.child_by_field_name("function")?,
            "member_call_expression" | "nullsafe_member_call_expression" => {
                current = current.child_by_field_name("name")?;
            }
            "scoped_call_expression"
            | "member_access_expression"
            | "nullsafe_member_access_expression"
            | "scoped_property_access_expression" => {
                current = current.child_by_field_name("name")?
            }
            "class_constant_access_expression" => current = last_named_child(current)?,
            "object_creation_expression" => current = object_creation_callee(current)?,
            _ => return None,
        }
    }
}

fn is_numeric_literal_node(node: Node<'_>) -> bool {
    matches!(node.kind(), "integer" | "float")
}

fn unary_argument(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("argument")
        .map(expression_target_node)
        .or_else(|| first_named_child(node).map(expression_target_node))
}

fn is_signed_numeric_unary(node: Node<'_>) -> bool {
    node.kind() == "unary_op_expression"
        && node
            .child_by_field_name("operator")
            .is_some_and(|operator| matches!(operator.kind(), "+" | "-"))
        && unary_argument(node).is_some_and(is_numeric_literal_node)
}

fn is_inside_signed_numeric_wrapper(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    is_signed_numeric_unary(parent)
}

fn object_creation_callee(node: Node<'_>) -> Option<Node<'_>> {
    for index in 0..node.named_child_count() {
        let child = node.named_child(index)?;
        if child.kind() == "arguments" {
            continue;
        }
        return Some(child);
    }
    None
}

fn object_creation_arguments(node: Node<'_>) -> Option<Node<'_>> {
    (0..node.named_child_count())
        .filter_map(|index| node.named_child(index))
        .find(|child| child.kind() == "arguments")
}

fn argument_value_node<'tree>(
    argument: Node<'tree>,
    keyword: Option<Node<'tree>>,
) -> Option<Node<'tree>> {
    (0..argument.named_child_count())
        .filter_map(|index| argument.named_child(index))
        .find(|child| {
            keyword.is_none_or(|keyword| child.id() != keyword.id())
                && !matches!(child.kind(), "reference_modifier" | "variadic_unpacking")
        })
        .map(expression_target_node)
}

fn attach_argument_roles(sink: &mut RoleSink<'_>, arguments: Node<'_>) {
    for index in 0..arguments.named_child_count() {
        if !sink.should_continue() {
            break;
        }
        let Some(argument) = arguments.named_child(index) else {
            continue;
        };
        if argument.kind() != "argument" {
            continue;
        }
        let keyword = argument.child_by_field_name("name");
        if let Some(value) = argument_value_node(argument, keyword) {
            if let Some(keyword) = keyword {
                sink.kwarg(keyword, value);
            } else {
                sink.argument_maybe_named(
                    value,
                    expression_name_node(value),
                    is_spread_argument_node(argument),
                );
            }
        }
    }
}

fn attach_decorators(sink: &mut RoleSink<'_>, declaration: Node<'_>) {
    let Some(attributes) = declaration.child_by_field_name("attributes") else {
        return;
    };
    let mut stack = vec![attributes];
    while let Some(node) = stack.pop() {
        if node.kind() == "attribute" {
            attach_role_with_derived_name(sink, Role::Decorator, node, expression_name_node);
            continue;
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
}

fn first_child_named_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    (0..node.named_child_count())
        .filter_map(|index| node.named_child(index))
        .find(|child| child.kind() == kind)
}

fn first_child_not_named_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    (0..node.named_child_count())
        .filter_map(|index| node.named_child(index))
        .find(|child| child.kind() != kind)
}

fn last_import_clause_name(node: Node<'_>) -> Option<Node<'_>> {
    (0..node.named_child_count())
        .rev()
        .filter_map(|index| node.named_child(index))
        .find(|child| matches!(child.kind(), "name" | "qualified_name"))
}

fn attach_module_binding(sink: &mut RoleSink<'_>, module: Node<'_>) {
    sink.role_named(Role::Module, module, module);
    if let Some(name) = expression_name_node(module)
        && name.id() != module.id()
    {
        sink.role_named(Role::Module, module, name);
    }
}

fn attach_import_modules(sink: &mut RoleSink<'_>, node: Node<'_>) {
    match node.kind() {
        "namespace_use_clause" => {
            if let Some(module) = node
                .child_by_field_name("alias")
                .or_else(|| last_import_clause_name(node))
            {
                attach_module_binding(sink, module);
            }
        }
        "namespace_use_group" => {
            for index in 0..node.named_child_count() {
                let Some(child) = node.named_child(index) else {
                    continue;
                };
                if child.kind() == "namespace_use_clause" {
                    attach_import_modules(sink, child);
                }
            }
        }
        "namespace_use_declaration" => {
            if let Some(group) = node.child_by_field_name("body") {
                attach_import_modules(sink, group);
                return;
            }
            for index in 0..node.named_child_count() {
                let Some(child) = node.named_child(index) else {
                    continue;
                };
                if child.kind() == "namespace_use_clause" {
                    attach_import_modules(sink, child);
                }
            }
        }
        _ => {}
    }
}

fn const_element_value(node: Node<'_>) -> Option<Node<'_>> {
    first_child_not_named_kind(node, "name").map(expression_target_node)
}

static PHP_OCCURRENCE_ROLE_SUPPORT: OccurrenceRoleSupport = OccurrenceRoleSupport::NONE
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

/// The node whose AST position decides a `name` token's occurrence role.
///
/// PHP spells a variable as `$` plus a `name` (`variable_name`), a qualified
/// class name as a `namespace_name` prefix plus a tail `name`
/// (`qualified_name`), and a by-reference binder as a `by_ref` around either.
/// The `name` is always the token the row is attached to, but the position
/// that gives it a meaning is the wrapper's, so the wrappers pass through
/// here and every classification below reads one grammar field of one host.
fn php_role_subject<'tree>(name: Node<'tree>) -> Option<(Node<'tree>, Node<'tree>)> {
    let mut subject = name;
    let mut host = name.parent()?;
    while matches!(host.kind(), "qualified_name" | "variable_name" | "by_ref") {
        subject = host;
        host = host.parent()?;
    }
    Some((subject, host))
}

/// Whether `subject` is a binder of the `foreach` header it sits in rather
/// than the collection the header iterates.
///
/// `foreach_statement` names no field for its header parts: its named children
/// are the collection expression first, then the value binder, or a `pair` of
/// key and value binders. Position among the children is therefore what the
/// grammar states, and the `body` field is the only part that is named.
fn php_is_foreach_binder(foreach: Node<'_>, subject: Node<'_>) -> bool {
    let body = foreach.child_by_field_name("body");
    let mut header = (0..foreach.named_child_count())
        .filter_map(|index| foreach.named_child(index))
        .filter(|child| body.is_none_or(|body| child.id() != body.id()));
    // The first header child is the iterated collection; every later one is a
    // binder the loop introduces.
    header.next().is_some_and(|collection| {
        collection.id() != subject.id() && header.any(|child| child.id() == subject.id())
    })
}

/// Whether `subject` occupies a destructuring or `foreach` binder position,
/// following the `list_literal`/`pair` nesting up to the construct that binds.
///
/// `[$a, $b] = $pair` and `list($k => $v) = $row` reach an assignment's `left`
/// field; `foreach ($rows as [$a, $b])` reaches the loop header.
fn php_is_binding_target(subject: Node<'_>, host: Node<'_>) -> bool {
    let mut subject = subject;
    let mut host = host;
    loop {
        match host.kind() {
            "assignment_expression" | "reference_assignment_expression" => {
                return field_name_in_parent(host, subject) == Some("left");
            }
            "foreach_statement" => return php_is_foreach_binder(host, subject),
            "list_literal" | "pair" => {
                subject = host;
                let Some(parent) = host.parent() else {
                    return false;
                };
                host = parent;
            }
            _ => return false,
        }
    }
}

/// Whether a `namespace_name` is a path written for its own sake -- the
/// `name` field of a `namespace` declaration -- rather than the prefix of a
/// qualified name or of a group `use`.
fn php_namespace_name_declares(namespace_name: Node<'_>) -> bool {
    namespace_name.parent().is_some_and(|parent| {
        parent.kind() == "namespace_definition"
            && field_name_in_parent(parent, namespace_name) == Some("name")
    })
}

/// Classify one PHP `name` token by its AST position.
///
/// Every arm reads a grammar field or a child position of the token's host, so
/// a role is only ever claimed where the parse tree states it. A token whose
/// host states nothing more specific is a plain read, which is what
/// [`OccurrenceRole::ValueReference`] means.
fn php_occurrence_role(node: Node<'_>) -> Option<OccurrenceRole> {
    if node.kind() != "name" {
        return None;
    }
    let parent = node.parent()?;
    if parent.kind() == "namespace_name" {
        // A namespace path's segments are path segments; only the tail of the
        // path a `namespace` statement declares names the module itself.
        let is_tail = last_named_child(parent).is_some_and(|tail| tail.id() == node.id());
        return Some(if is_tail && php_namespace_name_declares(parent) {
            OccurrenceRole::DeclarationName
        } else {
            OccurrenceRole::PathSegment
        });
    }

    let (subject, host) = php_role_subject(node)?;
    let field = field_name_in_parent(host, subject);
    let role = match host.kind() {
        "function_definition"
        | "method_declaration"
        | "class_declaration"
        | "interface_declaration"
        | "trait_declaration"
        | "enum_declaration"
        | "enum_case"
        | "property_element"
            if field == Some("name") =>
        {
            OccurrenceRole::DeclarationName
        }
        // `const A = 1, B = A;` puts the declared name first and the value
        // expression after it, with no field on either.
        "const_element" => {
            if first_child_named_kind(host, "name").is_some_and(|first| first.id() == subject.id())
            {
                OccurrenceRole::DeclarationName
            } else {
                OccurrenceRole::ValueReference
            }
        }
        "simple_parameter" | "variadic_parameter" | "property_promotion_parameter"
            if field == Some("name") =>
        {
            OccurrenceRole::Binder
        }
        // Every child of a closure's `use (...)` clause is a captured name.
        "anonymous_function_use_clause" => OccurrenceRole::Binder,
        "catch_clause" if field == Some("name") => OccurrenceRole::Binder,
        "static_variable_declaration" if field == Some("name") => OccurrenceRole::Binder,
        "global_declaration" => OccurrenceRole::Binder,
        "namespace_use_clause" => {
            if field == Some("alias") {
                OccurrenceRole::ImportAlias
            } else {
                OccurrenceRole::ImportTarget
            }
        }
        // The written class names of a signature, a hierarchy clause, a trait
        // `use` inside a class body, an attribute, and `new C`.
        "named_type"
        | "base_clause"
        | "class_interface_clause"
        | "use_declaration"
        | "attribute" => OccurrenceRole::TypeOperand,
        "object_creation_expression" if subject.kind() == "name" => OccurrenceRole::TypeOperand,
        "member_call_expression"
        | "nullsafe_member_call_expression"
        | "member_access_expression"
        | "nullsafe_member_access_expression"
        | "scoped_call_expression"
        | "scoped_property_access_expression" => match field {
            Some("name") => OccurrenceRole::MemberPosition,
            Some("object") | Some("scope") => OccurrenceRole::ReceiverPosition,
            _ => OccurrenceRole::ValueReference,
        },
        // `C::CONST` and `C::class` name no fields; the owner comes first and
        // the constant last, which is the only thing the grammar states.
        "class_constant_access_expression" => {
            if last_named_child(host).is_some_and(|tail| tail.id() == subject.id()) {
                OccurrenceRole::MemberPosition
            } else {
                OccurrenceRole::ReceiverPosition
            }
        }
        "argument" if field == Some("name") => OccurrenceRole::LabelOrKey,
        _ if php_is_binding_target(subject, host) => OccurrenceRole::Binder,
        _ => OccurrenceRole::ValueReference,
    };
    Some(role)
}

/// How a PHP fact of `kind` participates in the file's lexical scope tree.
///
/// PHP scopes variables by *function*, not by block: a name first assigned
/// inside a `foreach`, `while` or `catch` is still in effect after that
/// statement ends, so none of those open a scope here even though the C-family
/// default opens one for each. What does open a scope is a callable (its
/// parameters and locals), a class-like body (its members), and a
/// `namespace` (the `use` names it imports). The file scope the derivation
/// layer synthesizes is the unbraced `namespace N;` scope as well: that form
/// replaces the file's namespace from its own statement to the end of the
/// file rather than opening a body.
fn php_scope_formation(kind: NormalizedKind) -> ScopeFormation {
    if kind.satisfies(NormalizedKind::Class) {
        ScopeFormation::MemberScope
    } else if kind.satisfies(NormalizedKind::Callable) || kind == NormalizedKind::Module {
        ScopeFormation::BindingScope
    } else {
        ScopeFormation::NotAScope
    }
}

/// The interval that runs from the end of `after` to the end of `scope`.
fn php_after(after: Node<'_>, scope: Range) -> Range {
    Range {
        start_byte: after.end_byte(),
        end_byte: scope.end_byte,
        start_line: after.end_position().row + 1,
        end_line: scope.end_line,
    }
}

/// The binding one PHP binder token introduces, and the interval it is in
/// effect over.
///
/// PHP has two activation shapes and no third. A parameter -- of a function, a
/// method, a closure, or an arrow function, including a promoted constructor
/// parameter, a variadic one, a by-reference one and one with a default -- is
/// bound before the body runs, so it is `ScopeWide` over the callable. A
/// closure's `use (...)` capture is bound the same way, at the moment the
/// closure is created, so it is also `ScopeWide` and never in effect outside
/// the closure.
///
/// Everything else is a local, and a PHP local comes into existence where it
/// is first written and lasts to the end of its function: `SourceOrder`. That
/// covers an assignment target, a `foreach` key or value, a `catch` variable,
/// a `list()`/`[...]` destructuring element, a `static` variable and a
/// `global` declaration. Each states its own end byte rather than a shared
/// one, because the constructs differ in where the binding completes: an
/// assignment binds after its right-hand side, while a `foreach` or `catch`
/// binder must already be in effect inside the body that follows it.
fn php_binding_activation(binder: Node<'_>, scope: Range) -> Option<BindingActivation> {
    let form = nearest_ancestor(binder, |kind| {
        matches!(
            kind,
            "simple_parameter"
                | "variadic_parameter"
                | "property_promotion_parameter"
                | "anonymous_function_use_clause"
                | "catch_clause"
                | "static_variable_declaration"
                | "global_declaration"
                | "foreach_statement"
                | "assignment_expression"
                | "reference_assignment_expression"
        )
    })?;
    match form.kind() {
        "simple_parameter"
        | "variadic_parameter"
        | "property_promotion_parameter"
        | "anonymous_function_use_clause" => Some(BindingActivation {
            kind: BindingKind::Parameter,
            hoisting: HoistingClass::ScopeWide,
            activation: scope,
        }),
        "catch_clause" => Some(BindingActivation {
            kind: BindingKind::CatchOrResource,
            hoisting: HoistingClass::SourceOrder,
            activation: php_after(binder, scope),
        }),
        "foreach_statement" => Some(BindingActivation {
            kind: BindingKind::LoopVariable,
            hoisting: HoistingClass::SourceOrder,
            activation: php_after(binder, scope),
        }),
        _ => Some(BindingActivation {
            kind: BindingKind::Local,
            hoisting: HoistingClass::SourceOrder,
            activation: php_after(form, scope),
        }),
    }
}

/// PHP resolves an imported name at compile time, but sequentially: the manual
/// states that `use` must sit in the outermost scope of a file or inside a
/// `namespace` declaration "because the importing is done at compile time and
/// not runtime, so it cannot be block scoped", and the position of the `use`
/// decides which code can see the name -- a reference written above it does
/// not resolve through it. The interval is therefore the end of the
/// declaration to the end of the namespace scope it is written in, the same
/// shape Scala's block-local import states (#2925).
fn php_import_binder_activation(declaration: Range, scope: Range) -> ImportActivation {
    ImportActivation::from_declaration(declaration, scope)
}

/// PHP derives every axis this producer owns: its scope tree comes from the
/// callable, class-like and namespace facts in [`PHP_KIND_TABLE`], every
/// binder it classifies states an interval through [`php_binding_activation`],
/// every `use` clause carries a parser-derived structured path, and a file's
/// namespace is written in the source. The two candidate axes stay
/// unsupported: the PHP resolver records selected member candidates but no
/// per-tier rejected set.
static PHP_LEXICAL_ENVIRONMENT_SUPPORT: LexicalEnvironmentSupport = LexicalEnvironmentSupport::NONE
    .supported(EnvironmentAxis::Scopes)
    .supported(EnvironmentAxis::BindingIntervals)
    .supported(EnvironmentAxis::ImportBinders)
    .supported(EnvironmentAxis::PackageClause)
    .supported(EnvironmentAxis::CandidateSelection);

impl StructuralSpec for PhpStructuralSpec {
    fn language(&self) -> Language {
        Language::Php
    }

    fn kind_table(&self) -> &'static [(&'static str, NormalizedKind)] {
        PHP_KIND_TABLE
    }

    fn refine_kind(
        &self,
        node: Node<'_>,
        kind: NormalizedKind,
        _enclosing: Option<NormalizedKind>,
        source: &str,
        _context: &CallSiteContext,
    ) -> NormalizedKind {
        if kind == NormalizedKind::Method
            && node
                .child_by_field_name("name")
                .and_then(|name| name.utf8_text(source.as_bytes()).ok())
                .is_some_and(|name| name == "__construct")
        {
            NormalizedKind::Constructor
        } else {
            kind
        }
    }

    fn should_extract(&self, node: Node<'_>, kind: NormalizedKind) -> bool {
        if kind == NormalizedKind::NumericLiteral {
            if node.kind() == "unary_op_expression" {
                return is_signed_numeric_unary(node);
            }
            if is_numeric_literal_node(node) && is_inside_signed_numeric_wrapper(node) {
                return false;
            }
        }

        kind != NormalizedKind::Assignment
            || match node.kind() {
                "property_element" => node.child_by_field_name("default_value").is_some(),
                "const_element" => const_element_value(node).is_some(),
                _ => true,
            }
    }

    fn supports_kind(&self, kind: NormalizedKind) -> bool {
        kind == NormalizedKind::Constructor
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
        &PHP_OCCURRENCE_ROLE_SUPPORT
    }

    fn lexical_environment_support(&self) -> &LexicalEnvironmentSupport {
        &PHP_LEXICAL_ENVIRONMENT_SUPPORT
    }

    fn scope_formation(&self, kind: NormalizedKind) -> ScopeFormation {
        php_scope_formation(kind)
    }

    fn binding_activation(&self, binder: Node<'_>, scope: Range) -> Option<BindingActivation> {
        php_binding_activation(binder, scope)
    }

    fn import_binder_activation(
        &self,
        declaration: Range,
        scope: Range,
        _scope_kind: Option<NormalizedKind>,
    ) -> ImportActivation {
        php_import_binder_activation(declaration, scope)
    }

    fn materialization_support(&self) -> &DeclarationMaterializationSupport {
        &NO_MATERIALIZATION_SUPPORT
    }

    /// A PHP `use` at file scope imports a name into this file and nothing
    /// more: the language has no form that re-exports an imported name to
    /// another file, so every token of a `namespace_use_declaration` is a
    /// plain import hop. A `use` inside a class body is trait composition,
    /// which is a different node and introduces no import binder.
    fn indirection_relation(
        &self,
        token: Node<'_>,
        _source: &str,
        _surface: &CuratedExportSurface,
    ) -> Option<RouteHopKind> {
        nearest_ancestor(token, |kind| kind == "namespace_use_declaration")
            .map(|_| RouteHopKind::Import)
    }

    /// PHP classifies a path segment only inside a `namespace_name`, and PHP
    /// has no nested classes, so a backslash-separated qualifier is always a
    /// namespace. The general `PathPrefix` answer would be true but weaker
    /// than what this grammar states (#3064).
    fn occurrence_namespace(
        &self,
        role: OccurrenceRole,
        declares: Option<NormalizedKind>,
    ) -> Option<Namespace> {
        match role {
            OccurrenceRole::PathSegment => Some(Namespace::Module),
            _ => default_occurrence_namespace(role, declares),
        }
    }

    fn reference_edge_support(&self) -> &ReferenceEdgeSupport {
        &INVERSE_REFERENCE_EDGE_SUPPORT
    }

    fn identity_route_support(&self) -> &IdentityRouteSupport {
        &NO_IDENTITY_ROUTE_SUPPORT
    }

    fn extract(&self, node: Node<'_>, kind: NormalizedKind, sink: &mut RoleSink<'_>) {
        if let Some(role) = php_occurrence_role(node) {
            sink.occurrence_role(node, role);
        }

        match kind {
            NormalizedKind::Call => {
                let function = if node.kind() == "object_creation_expression" {
                    object_creation_callee(node)
                } else {
                    node.child_by_field_name("function")
                        .or_else(|| node.child_by_field_name("name"))
                };
                if let Some(function) = function {
                    attach_terminal_callee(sink, function, expression_name_node(function));
                }
                let receiver = match node.kind() {
                    "member_call_expression" | "nullsafe_member_call_expression" => {
                        node.child_by_field_name("object")
                    }
                    "scoped_call_expression" => node.child_by_field_name("scope"),
                    _ => None,
                };
                if let Some(receiver) = receiver {
                    attach_role_with_derived_name(
                        sink,
                        Role::Receiver,
                        receiver,
                        expression_name_node,
                    );
                }
                let arguments = if node.kind() == "object_creation_expression" {
                    object_creation_arguments(node)
                } else {
                    node.child_by_field_name("arguments")
                };
                if let Some(arguments) = arguments {
                    attach_argument_roles(sink, arguments);
                }
            }
            NormalizedKind::FieldAccess => {
                let field = if node.kind() == "class_constant_access_expression" {
                    last_named_child(node)
                } else {
                    node.child_by_field_name("name")
                };
                if let Some(field) = field {
                    attach_role_with_derived_name(sink, Role::Field, field, expression_name_node);
                    if let Some(name) = expression_name_node(field) {
                        sink.set_name(name);
                    }
                }
                let object = if node.kind() == "class_constant_access_expression" {
                    first_named_child(node)
                } else {
                    node.child_by_field_name("object")
                        .or_else(|| node.child_by_field_name("scope"))
                };
                if let Some(object) = object {
                    attach_role_with_derived_name(sink, Role::Object, object, expression_name_node);
                }
            }
            NormalizedKind::Function
            | NormalizedKind::Method
            | NormalizedKind::Constructor
            | NormalizedKind::Class
            | NormalizedKind::Module => {
                // A namespace's `name` is a `namespace_name`, so the fact
                // takes its terminal segment the same way a qualified call or
                // import does. Every other declaration head names a bare
                // `name`, which `expression_name_node` returns unchanged.
                if let Some(name) = node.child_by_field_name("name") {
                    sink.set_name(expression_name_node(name).unwrap_or(name));
                }
                attach_decorators(sink, node);
            }
            NormalizedKind::Lambda => attach_decorators(sink, node),
            NormalizedKind::Assignment => match node.kind() {
                "property_element" => {
                    if let Some(name) = node.child_by_field_name("name") {
                        attach_role_with_derived_name(sink, Role::Left, name, expression_name_node);
                        if let Some(name) = expression_name_node(name) {
                            sink.set_name(name);
                        }
                    }
                    if let Some(value) = node.child_by_field_name("default_value") {
                        let value = expression_target_node(value);
                        attach_role_with_derived_name(
                            sink,
                            Role::Right,
                            value,
                            expression_name_node,
                        );
                    }
                }
                "const_element" => {
                    if let Some(name) = first_child_named_kind(node, "name") {
                        sink.role_named(Role::Left, name, name);
                        sink.set_name(name);
                    }
                    if let Some(value) = const_element_value(node) {
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
                if let Some(name) = first_named_child(node) {
                    attach_terminal_callee(sink, name, expression_name_node(name));
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
    use super::php_occurrence_role;
    use brokk_bifrost_core::analyzer::structural::occurrences::OccurrenceRole;
    use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;
    use tree_sitter::Parser;

    fn parse(source: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
            .expect("PHP grammar is valid");
        let tree = parser.parse(source, None).expect("PHP source parses");
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );
        tree
    }

    fn identifier_roles(source: &str) -> Vec<(String, Option<OccurrenceRole>)> {
        let tree = parse(source);
        let mut pending = vec![tree.root_node()];
        let mut identifiers = Vec::new();
        while let Some(node) = pending.pop() {
            if node.kind() == "name" {
                identifiers.push((
                    node.utf8_text(source.as_bytes())
                        .expect("name has valid source span")
                        .to_owned(),
                    php_occurrence_role(node),
                ));
            }
            pending.extend(
                (0..node.named_child_count())
                    .rev()
                    .filter_map(|index| node.named_child(index)),
            );
        }
        identifiers
    }

    #[test]
    fn member_positions_follow_php_member_fields_only() {
        let source = r#"<?php
            class Service {
                public string $field;
                public function run(string $label): void {}
                public static function build(): self { }
            }

            function caller(Service $service, string $label, array $items): void {
                $service->run(label: $label);
                $service?->field;
                Service::build();
                Service::$field;
                Service::class;
                $items['run'];
                $service->field;
            }
        "#;

        let identifiers = identifier_roles(source);
        let members = identifiers
            .iter()
            .filter_map(|(spelling, role)| {
                (*role == Some(OccurrenceRole::MemberPosition)).then_some(spelling.as_str())
            })
            .collect::<Vec<_>>();
        assert_eq!(
            members,
            ["run", "field", "build", "field", "class", "field"]
        );

        for spelling in ["Service", "service", "label", "items", "caller", "run"] {
            let matching = identifiers
                .iter()
                .filter(|(name, _)| name == spelling)
                .collect::<Vec<_>>();
            assert!(
                matching
                    .iter()
                    .any(|(_, role)| { *role != Some(OccurrenceRole::MemberPosition) }),
                "{spelling} has a non-member occurrence in the fixture"
            );
        }
    }

    /// Every role the classifier can answer must be declared supported, and
    /// every role it never answers must not be: an undeclared role read as
    /// "no such occurrence" would be a silent empty answer (#2962).
    #[test]
    fn php_support_declares_exactly_the_roles_the_classifier_answers() {
        let support = super::PHP_STRUCTURAL_SPEC.occurrence_role_support();
        for role in [
            OccurrenceRole::DeclarationName,
            OccurrenceRole::Binder,
            OccurrenceRole::LabelOrKey,
            OccurrenceRole::TypeOperand,
            OccurrenceRole::PathSegment,
            OccurrenceRole::ImportAlias,
            OccurrenceRole::ImportTarget,
            OccurrenceRole::ReceiverPosition,
            OccurrenceRole::MemberPosition,
            OccurrenceRole::ValueReference,
        ] {
            assert!(support.is_supported(role), "{role} must be declared");
        }
        // PHP's grammar establishes neither of these: it has no pattern
        // syntax, and nothing in it generates declarations elsewhere.
        assert!(!support.is_supported(OccurrenceRole::PatternPosition));
        assert!(!support.is_supported(OccurrenceRole::GeneratedSource));
    }

    /// Every binder, import and declaration shape the environment layer reads,
    /// classified from the grammar fields alone.
    #[test]
    fn php_classifies_binders_imports_and_declaration_names() {
        let source = r#"<?php
            namespace App\Util;

            use App\Model\Widget as Gadget;
            use function App\Support\helper;

            const LIMIT = 10;

            class Service {
                public string $field;

                public function __construct(private Gadget $gadget) {}

                public function run(string $label, int ...$rest): void {
                    $total = 0;
                    static $seen = 0;
                    global $registry;
                    foreach ([1] as $key => $value) {
                        $total = $total + $value + $key;
                    }
                    [$first, $second] = [1, 2];
                    try {
                        helper($label);
                    } catch (\RuntimeException $error) {
                        $total = $first + $second + $error->getCode() + $seen;
                    }
                    $adder = function (int $addend) use ($total, &$registry) {
                        return $addend + $total;
                    };
                    $twice = fn(int $once) => $once * 2;
                    $this->field = $adder(1) + $twice(2);
                }
            }
        "#;

        let identifiers = identifier_roles(source);
        let spelled = |role: OccurrenceRole| {
            let mut found = identifiers
                .iter()
                .filter_map(|(spelling, actual)| {
                    (*actual == Some(role)).then_some(spelling.as_str())
                })
                .collect::<Vec<_>>();
            found.sort_unstable();
            found.dedup();
            found
        };

        assert_eq!(
            spelled(OccurrenceRole::Binder),
            [
                "addend", "adder", "error", "first", "gadget", "key", "label", "once", "registry",
                "rest", "second", "seen", "total", "twice", "value"
            ],
            "every parameter, capture, local, loop, catch and destructuring binder"
        );
        assert_eq!(spelled(OccurrenceRole::ImportAlias), ["Gadget"]);
        assert_eq!(spelled(OccurrenceRole::ImportTarget), ["Widget", "helper"]);
        assert_eq!(
            spelled(OccurrenceRole::DeclarationName),
            ["LIMIT", "Service", "Util", "__construct", "field", "run"],
            "the namespace tail, the class, its members and the constant"
        );
        assert!(
            spelled(OccurrenceRole::PathSegment).contains(&"App"),
            "a namespace path's leading segments are path segments"
        );
        assert!(
            !spelled(OccurrenceRole::Binder).contains(&"this"),
            "`$this` is a receiver, never a binder"
        );
        assert!(
            spelled(OccurrenceRole::MemberPosition).contains(&"field"),
            "`$this->field` is a member position"
        );
    }
}
