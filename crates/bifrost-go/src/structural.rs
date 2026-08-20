//! Go structural spec for `query_code`.

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::structural::adapter_helpers::{
    attach_positional_argument_roles, attach_role_with_derived_name, attach_terminal_callee,
    field_name_in_parent, first_named_child,
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
    LexicalEnvironmentSupport, NO_LEXICAL_ENVIRONMENT_SUPPORT,
};
use brokk_bifrost_core::analyzer::structural::routes::{
    IdentityRouteSupport, NO_IDENTITY_ROUTE_SUPPORT,
};
use brokk_bifrost_core::analyzer::structural::spec::{RoleSink, StructuralSpec};
use tree_sitter::Node;

#[derive(Debug, Default)]
pub struct GoStructuralSpec;

pub static GO_STRUCTURAL_SPEC: GoStructuralSpec = GoStructuralSpec;

const GO_KIND_TABLE: &[(&str, NormalizedKind)] = &[
    ("call_expression", NormalizedKind::Call),
    ("selector_expression", NormalizedKind::FieldAccess),
    ("function_declaration", NormalizedKind::Function),
    ("method_declaration", NormalizedKind::Method),
    ("func_literal", NormalizedKind::Lambda),
    ("type_spec", NormalizedKind::Class),
    ("type_alias", NormalizedKind::Declaration),
    ("assignment_statement", NormalizedKind::Assignment),
    ("short_var_declaration", NormalizedKind::Assignment),
    ("var_spec", NormalizedKind::Assignment),
    ("const_spec", NormalizedKind::Assignment),
    ("import_declaration", NormalizedKind::Import),
    ("identifier", NormalizedKind::Identifier),
    ("field_identifier", NormalizedKind::Identifier),
    ("package_identifier", NormalizedKind::Identifier),
    ("type_identifier", NormalizedKind::Identifier),
    ("interpreted_string_literal", NormalizedKind::StringLiteral),
    ("raw_string_literal", NormalizedKind::StringLiteral),
    ("int_literal", NormalizedKind::NumericLiteral),
    ("float_literal", NormalizedKind::NumericLiteral),
    ("true", NormalizedKind::BooleanLiteral),
    ("false", NormalizedKind::BooleanLiteral),
    ("nil", NormalizedKind::NullLiteral),
    ("return_statement", NormalizedKind::Return),
    ("if_statement", NormalizedKind::If),
    ("for_statement", NormalizedKind::Loop),
];

fn expression_name_node<'tree>(expression: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = expression;
    loop {
        match current.kind() {
            "identifier" | "field_identifier" | "package_identifier" | "type_identifier" => {
                return Some(current);
            }
            "selector_expression" => current = current.child_by_field_name("field")?,
            "call_expression" => current = current.child_by_field_name("function")?,
            "qualified_type" => current = current.child_by_field_name("name")?,
            "parenthesized_expression" | "expression_list" => current = first_named_child(current)?,
            _ => return None,
        }
    }
}

fn unquoted_go_string_span(node: Node<'_>) -> Option<Span> {
    if !matches!(
        node.kind(),
        "interpreted_string_literal" | "raw_string_literal"
    ) {
        return None;
    }
    let start = node.start_byte().checked_add(1)?;
    let end = node.end_byte().checked_sub(1)?;
    (start <= end).then_some(Span {
        start_byte: start,
        end_byte: end,
    })
}

fn attach_import_spec_module(sink: &mut RoleSink<'_>, import_spec: Node<'_>) {
    if let Some(path) = import_spec.child_by_field_name("path") {
        if let Some(name) = unquoted_go_string_span(path) {
            sink.role_named_span(Role::Module, path, name);
        } else {
            sink.role(Role::Module, path);
        }
    }
}

fn attach_import_modules(sink: &mut RoleSink<'_>, import: Node<'_>) {
    if import.kind() == "import_spec" {
        attach_import_spec_module(sink, import);
        return;
    }

    for index in 0..import.named_child_count() {
        let Some(child) = import.named_child(index) else {
            continue;
        };
        match child.kind() {
            "import_spec" => attach_import_spec_module(sink, child),
            "import_spec_list" => {
                for spec_index in 0..child.named_child_count() {
                    let Some(spec) = child.named_child(spec_index) else {
                        continue;
                    };
                    if spec.kind() == "import_spec" {
                        attach_import_spec_module(sink, spec);
                    }
                }
            }
            _ => {}
        }
    }
}

fn attach_role_target<'tree>(
    sink: &mut RoleSink<'_>,
    role: Role,
    target: Node<'tree>,
    first_name: &mut Option<Node<'tree>>,
) {
    attach_role_with_derived_name(sink, role, target, expression_name_node);
    if first_name.is_none() {
        *first_name = expression_name_node(target);
    }
}

fn attach_role_targets<'tree>(
    sink: &mut RoleSink<'_>,
    role: Role,
    target: Node<'tree>,
) -> Option<Node<'tree>> {
    let mut first_name = None;
    if target.kind() == "expression_list" {
        for index in 0..target.named_child_count() {
            let Some(child) = target.named_child(index) else {
                continue;
            };
            attach_role_target(sink, role, child, &mut first_name);
        }
    } else {
        attach_role_target(sink, role, target, &mut first_name);
    }
    first_name
}

fn attach_name_field_targets<'tree>(
    sink: &mut RoleSink<'_>,
    role: Role,
    node: Node<'tree>,
) -> Option<Node<'tree>> {
    let mut first_name = None;
    let mut cursor = node.walk();
    for name in node.children_by_field_name("name", &mut cursor) {
        if !name.is_named() {
            continue;
        }
        attach_role_target(sink, role, name, &mut first_name);
    }
    first_name
}

fn attach_value_field_targets<'tree>(
    sink: &mut RoleSink<'_>,
    role: Role,
    node: Node<'tree>,
    field: &str,
) -> Option<Node<'tree>> {
    node.child_by_field_name(field)
        .and_then(|target| attach_role_targets(sink, role, target))
}

static GO_OCCURRENCE_ROLE_SUPPORT: OccurrenceRoleSupport =
    OccurrenceRoleSupport::NONE.supported(OccurrenceRole::MemberPosition);

/// Classify the selector member token in a Go `selector_expression`.
///
/// The Go grammar gives a selector its two semantic positions as named
/// fields: `operand` is the receiver and `field` is the member. Keeping this
/// check on the field relationship means a declaration, keyed literal, label,
/// or ordinary identifier with the same spelling cannot be mistaken for a
/// member occurrence.
fn go_occurrence_role(node: Node<'_>) -> Option<OccurrenceRole> {
    if !matches!(
        node.kind(),
        "identifier" | "field_identifier" | "package_identifier" | "type_identifier"
    ) {
        return None;
    }

    let parent = node.parent()?;
    (parent.kind() == "selector_expression" && field_name_in_parent(parent, node) == Some("field"))
        .then_some(OccurrenceRole::MemberPosition)
}

impl StructuralSpec for GoStructuralSpec {
    fn language(&self) -> Language {
        Language::Go
    }

    fn kind_table(&self) -> &'static [(&'static str, NormalizedKind)] {
        GO_KIND_TABLE
    }

    fn should_extract(&self, node: Node<'_>, kind: NormalizedKind) -> bool {
        kind != NormalizedKind::Assignment
            || !matches!(node.kind(), "var_spec" | "const_spec")
            || node.child_by_field_name("value").is_some()
    }

    fn supports_role(&self, role: Role) -> bool {
        !matches!(role, Role::Kwarg | Role::Decorator)
    }

    fn occurrence_role_support(&self) -> &OccurrenceRoleSupport {
        &GO_OCCURRENCE_ROLE_SUPPORT
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
        if let Some(role) = go_occurrence_role(node) {
            sink.occurrence_role(node, role);
        }
        match kind {
            NormalizedKind::Call => {
                if let Some(function) = node.child_by_field_name("function") {
                    attach_terminal_callee(sink, function, expression_name_node(function));
                    if function.kind() == "selector_expression"
                        && let Some(operand) = function.child_by_field_name("operand")
                    {
                        attach_role_with_derived_name(
                            sink,
                            Role::Receiver,
                            operand,
                            expression_name_node,
                        );
                    }
                }
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    attach_positional_argument_roles(sink, arguments, expression_name_node);
                }
            }
            NormalizedKind::FieldAccess => {
                if let Some(field) = node.child_by_field_name("field") {
                    sink.set_name(field);
                    sink.role_named(Role::Field, field, field);
                }
                if let Some(operand) = node.child_by_field_name("operand") {
                    attach_role_with_derived_name(
                        sink,
                        Role::Object,
                        operand,
                        expression_name_node,
                    );
                }
            }
            NormalizedKind::Function
            | NormalizedKind::Method
            | NormalizedKind::Class
            | NormalizedKind::Declaration => {
                if let Some(name) = node.child_by_field_name("name") {
                    sink.set_name(name);
                }
            }
            NormalizedKind::Assignment => {
                let first_left_name = match node.kind() {
                    "var_spec" | "const_spec" => attach_name_field_targets(sink, Role::Left, node),
                    _ => attach_value_field_targets(sink, Role::Left, node, "left"),
                };
                if let Some(name) = first_left_name {
                    sink.set_name(name);
                }
                match node.kind() {
                    "var_spec" | "const_spec" => {
                        attach_value_field_targets(sink, Role::Right, node, "value");
                    }
                    _ => {
                        attach_value_field_targets(sink, Role::Right, node, "right");
                    }
                }
            }
            NormalizedKind::Import => attach_import_modules(sink, node),
            NormalizedKind::Identifier => sink.set_name(node),
            _ => {}
        }
    }
}

#[cfg(test)]
mod structural_spec_tests {
    use super::*;

    fn parse(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .expect("Go grammar is valid");
        parser.parse(source, None).expect("source parses")
    }

    #[test]
    fn go_kind_table_matches_grammar() {
        let grammar: tree_sitter::Language = tree_sitter_go::LANGUAGE.into();
        for (name, kind) in GO_KIND_TABLE {
            assert_ne!(
                grammar.id_for_node_kind(name, true),
                0,
                "node type {name:?} (mapped to {kind:?}) does not exist in tree-sitter-go"
            );
        }
    }

    #[test]
    fn selector_members_are_member_positions_and_near_misses_are_not() {
        let source = concat!(
            "package example\n\n",
            "type Widget struct {\n",
            "\tMember int\n",
            "}\n\n",
            "func render(receiver Widget, label string) int {\n",
            "\tvalue := receiver.Member\n",
            "\tkeyed := Widget{Member: value}\n",
            "label: for value < 2 {\n",
            "\t\tbreak label\n",
            "\t}\n",
            "\treturn value + unrelated\n",
            "}\n",
        );
        let tree = parse(source);
        let mut selectors = Vec::new();
        let mut identifiers = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "selector_expression" {
                selectors.push(node);
            }
            if matches!(
                node.kind(),
                "identifier" | "field_identifier" | "package_identifier" | "type_identifier"
            ) {
                identifiers.push(node);
            }
            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    stack.push(child);
                }
            }
        }

        assert_eq!(selectors.len(), 1, "fixture should contain one selector");
        let selector = selectors[0];
        let member = selector
            .child_by_field_name("field")
            .expect("selector member");
        let receiver = selector
            .child_by_field_name("operand")
            .expect("selector receiver");
        assert_eq!(
            go_occurrence_role(member),
            Some(OccurrenceRole::MemberPosition)
        );
        assert_eq!(go_occurrence_role(receiver), None);

        let keyed_member = identifiers
            .iter()
            .copied()
            .find(|node| {
                node.parent().is_some_and(|literal| {
                    literal.parent().is_some_and(|keyed| {
                        keyed.kind() == "keyed_element"
                            && keyed.child_by_field_name("key") == Some(literal)
                    })
                })
            })
            .expect("keyed literal member name");
        assert_eq!(go_occurrence_role(keyed_member), None);

        for identifier in identifiers {
            let parent = identifier.parent();
            let is_selector_member = parent.is_some_and(|parent| {
                parent.kind() == "selector_expression"
                    && field_name_in_parent(parent, identifier) == Some("field")
            });
            if !is_selector_member {
                assert_eq!(
                    go_occurrence_role(identifier),
                    None,
                    "non-selector identifier at {} must not be classified",
                    identifier.start_byte()
                );
            }
        }

        assert!(
            GO_STRUCTURAL_SPEC
                .occurrence_role_support()
                .is_supported(OccurrenceRole::MemberPosition)
        );
        assert!(
            GO_STRUCTURAL_SPEC
                .occurrence_role_support()
                .iter()
                .filter(|(_, support)| support.is_supported())
                .all(|(role, _)| role == OccurrenceRole::MemberPosition)
        );
    }
}
