//! PHP structural spec for `query_code`.

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::structural::adapter_helpers::{
    attach_role_with_derived_name, attach_terminal_callee, first_named_child,
    is_spread_argument_node,
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
    OccurrenceRole, OccurrenceRoleSupport,
};
use brokk_bifrost_core::analyzer::structural::resolution::{
    LexicalEnvironmentSupport, NO_LEXICAL_ENVIRONMENT_SUPPORT,
};
use brokk_bifrost_core::analyzer::structural::routes::{
    IdentityRouteSupport, NO_IDENTITY_ROUTE_SUPPORT,
};
use brokk_bifrost_core::analyzer::structural::spec::{RoleSink, StructuralSpec};
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

static PHP_OCCURRENCE_ROLE_SUPPORT: OccurrenceRoleSupport =
    OccurrenceRoleSupport::NONE.supported(OccurrenceRole::MemberPosition);

fn php_member_name_node(node: Node<'_>) -> Option<Node<'_>> {
    let node = expression_target_node(node);
    match node.kind() {
        "name" => Some(node),
        "variable_name" => first_named_child(node),
        _ => None,
    }
}

fn php_member_position(node: Node<'_>) -> Option<OccurrenceRole> {
    if node.kind() != "name" {
        return None;
    }

    let mut current = node;
    while let Some(parent) = current.parent() {
        let member = match parent.kind() {
            "member_call_expression"
            | "nullsafe_member_call_expression"
            | "member_access_expression"
            | "nullsafe_member_access_expression"
            | "scoped_call_expression"
            | "scoped_property_access_expression" => parent.child_by_field_name("name")?,
            "class_constant_access_expression" => last_named_child(parent)?,
            _ => {
                if matches!(
                    parent.kind(),
                    "expression" | "parenthesized_expression" | "variable_name"
                ) {
                    current = parent;
                    continue;
                }
                return None;
            }
        };

        return php_member_name_node(member)
            .is_some_and(|name| name.id() == node.id())
            .then_some(OccurrenceRole::MemberPosition);
    }
    None
}

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

    fn occurrence_role_support(&self) -> &OccurrenceRoleSupport {
        &PHP_OCCURRENCE_ROLE_SUPPORT
    }

    fn lexical_environment_support(&self) -> &LexicalEnvironmentSupport {
        &NO_LEXICAL_ENVIRONMENT_SUPPORT
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

    fn extract(&self, node: Node<'_>, kind: NormalizedKind, sink: &mut RoleSink<'_>) {
        if let Some(role) = php_member_position(node) {
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
            | NormalizedKind::Class => {
                if let Some(name) = node.child_by_field_name("name") {
                    sink.set_name(name);
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
    use super::php_member_position;
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
                    php_member_position(node),
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

    #[test]
    fn php_support_advertises_only_member_position() {
        let support = super::PHP_STRUCTURAL_SPEC.occurrence_role_support();
        assert!(support.is_supported(OccurrenceRole::MemberPosition));
        assert!(!support.is_supported(OccurrenceRole::ReceiverPosition));
        assert!(!support.is_supported(OccurrenceRole::LabelOrKey));
        assert!(!support.is_supported(OccurrenceRole::DeclarationName));
        assert!(!support.is_supported(OccurrenceRole::ValueReference));
    }
}
