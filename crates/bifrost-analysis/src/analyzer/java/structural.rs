//! Java structural spec for `query_code`.
//!
//! This maps tree-sitter-java node types to Bifrost's normalized structural
//! vocabulary and extracts role edges from AST fields.

use crate::analyzer::Language;
use crate::analyzer::structural::adapter_helpers::{
    attach_positional_argument_roles, attach_role_with_derived_name, attach_terminal_callee,
    field_name_in_parent, first_named_child, is_field_of,
};
use crate::analyzer::structural::{
    NormalizedKind, OccurrenceRole, OccurrenceRoleSupport, Role, RoleSink, StructuralSpec,
};
use tree_sitter::Node;

#[derive(Debug, Default)]
pub(crate) struct JavaStructuralSpec;

pub(crate) static JAVA_STRUCTURAL_SPEC: JavaStructuralSpec = JavaStructuralSpec;

const JAVA_KIND_TABLE: &[(&str, NormalizedKind)] = &[
    ("method_invocation", NormalizedKind::Call),
    ("object_creation_expression", NormalizedKind::Call),
    ("field_access", NormalizedKind::FieldAccess),
    ("method_declaration", NormalizedKind::Method),
    ("constructor_declaration", NormalizedKind::Constructor),
    (
        "compact_constructor_declaration",
        NormalizedKind::Constructor,
    ),
    ("lambda_expression", NormalizedKind::Lambda),
    ("class_declaration", NormalizedKind::Class),
    ("interface_declaration", NormalizedKind::Class),
    ("enum_declaration", NormalizedKind::Class),
    ("record_declaration", NormalizedKind::Class),
    ("annotation_type_declaration", NormalizedKind::Class),
    ("variable_declarator", NormalizedKind::Assignment),
    ("assignment_expression", NormalizedKind::Assignment),
    ("import_declaration", NormalizedKind::Import),
    ("identifier", NormalizedKind::Identifier),
    ("type_identifier", NormalizedKind::Identifier),
    ("scoped_identifier", NormalizedKind::Identifier),
    ("scoped_type_identifier", NormalizedKind::Identifier),
    ("string_literal", NormalizedKind::StringLiteral),
    ("decimal_integer_literal", NormalizedKind::NumericLiteral),
    ("hex_integer_literal", NormalizedKind::NumericLiteral),
    ("octal_integer_literal", NormalizedKind::NumericLiteral),
    ("binary_integer_literal", NormalizedKind::NumericLiteral),
    (
        "decimal_floating_point_literal",
        NormalizedKind::NumericLiteral,
    ),
    ("true", NormalizedKind::BooleanLiteral),
    ("false", NormalizedKind::BooleanLiteral),
    ("null_literal", NormalizedKind::NullLiteral),
    ("return_statement", NormalizedKind::Return),
    ("throw_statement", NormalizedKind::Throw),
    ("catch_clause", NormalizedKind::Catch),
    ("if_statement", NormalizedKind::If),
    ("for_statement", NormalizedKind::Loop),
    ("enhanced_for_statement", NormalizedKind::ForLoop),
    ("while_statement", NormalizedKind::WhileLoop),
    ("do_statement", NormalizedKind::WhileLoop),
    ("annotation", NormalizedKind::Decorator),
    ("marker_annotation", NormalizedKind::Decorator),
];

fn last_named_child(node: Node<'_>) -> Option<Node<'_>> {
    node.named_child_count()
        .checked_sub(1)
        .and_then(|index| node.named_child(index))
}

pub(crate) fn expression_name_node<'tree>(expression: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = expression;
    loop {
        match current.kind() {
            "identifier" | "type_identifier" | "this" | "super" => return Some(current),
            "scoped_identifier" | "scoped_type_identifier" => {
                current = current
                    .child_by_field_name("name")
                    .or_else(|| last_named_child(current))?;
            }
            "generic_type" => {
                current = current
                    .child_by_field_name("type")
                    .or_else(|| first_named_child(current))?;
            }
            "field_access" => current = current.child_by_field_name("field")?,
            "method_invocation" => current = current.child_by_field_name("name")?,
            "object_creation_expression" => current = current.child_by_field_name("type")?,
            "annotation" | "marker_annotation" => current = current.child_by_field_name("name")?,
            _ => return None,
        }
    }
}

fn attach_decorators(sink: &mut RoleSink<'_>, declaration: Node<'_>) {
    for index in 0..declaration.named_child_count() {
        let Some(child) = declaration.named_child(index) else {
            continue;
        };
        if child.kind() != "modifiers" {
            continue;
        }
        for modifier_index in 0..child.named_child_count() {
            let Some(modifier_child) = child.named_child(modifier_index) else {
                continue;
            };
            if matches!(modifier_child.kind(), "annotation" | "marker_annotation") {
                attach_role_with_derived_name(
                    sink,
                    Role::Decorator,
                    modifier_child,
                    expression_name_node,
                );
            }
        }
    }
}

static JAVA_OCCURRENCE_ROLE_SUPPORT: OccurrenceRoleSupport = OccurrenceRoleSupport::NONE
    .supported(OccurrenceRole::DeclarationName)
    .supported(OccurrenceRole::Binder)
    .supported(OccurrenceRole::LabelOrKey)
    .supported(OccurrenceRole::TypeOperand)
    .supported(OccurrenceRole::PathSegment)
    .supported(OccurrenceRole::ImportTarget)
    .supported(OccurrenceRole::ReceiverPosition)
    .supported(OccurrenceRole::MemberPosition)
    .supported(OccurrenceRole::ValueReference);

/// The declaration heads whose `name` field is the declared symbol itself.
const JAVA_DECLARATION_HEADS: &[&str] = &[
    "class_declaration",
    "interface_declaration",
    "enum_declaration",
    "record_declaration",
    "annotation_type_declaration",
    "method_declaration",
    "constructor_declaration",
    "compact_constructor_declaration",
    "annotation_type_element_declaration",
    "enum_constant",
    "type_parameter",
];

/// The binding forms whose `name` field introduces a fresh local binding.
const JAVA_BINDER_HEADS: &[&str] = &[
    "formal_parameter",
    "spread_parameter",
    "catch_formal_parameter",
    "resource",
    "variable_declarator",
];

/// Classify one Java identifier token by its AST position.
///
/// Compound `scoped_identifier`/`scoped_type_identifier` nodes are *not*
/// classified: an occurrence is a token, so the chain contributes its segments
/// (`PathSegment`) and its tail (the role the whole chain plays in context),
/// never a third row spanning both.
fn java_occurrence_role(node: Node<'_>) -> Option<OccurrenceRole> {
    if !matches!(node.kind(), "identifier" | "type_identifier") {
        return None;
    }

    // Climb out of any qualified-name chain this token terminates. A token in
    // a `scope` position is a path segment however deep the chain runs.
    let mut anchor = node;
    let mut parent = anchor.parent()?;
    while matches!(
        parent.kind(),
        "scoped_identifier" | "scoped_type_identifier"
    ) {
        if !is_field_of(parent, anchor, "name") {
            return Some(OccurrenceRole::PathSegment);
        }
        anchor = parent;
        parent = anchor.parent()?;
    }

    let field = field_name_in_parent(parent, anchor);
    let parent_kind = parent.kind();
    let role = match parent_kind {
        "import_declaration" => OccurrenceRole::ImportTarget,
        "package_declaration" => OccurrenceRole::DeclarationName,
        "annotation" | "marker_annotation" if field == Some("name") => OccurrenceRole::TypeOperand,
        "element_value_pair" if field == Some("key") => OccurrenceRole::LabelOrKey,
        "labeled_statement" | "break_statement" | "continue_statement" => {
            OccurrenceRole::LabelOrKey
        }
        "method_invocation" => match field {
            Some("name") => OccurrenceRole::MemberPosition,
            Some("object") => OccurrenceRole::ReceiverPosition,
            _ => OccurrenceRole::ValueReference,
        },
        "field_access" => match field {
            Some("field") => OccurrenceRole::MemberPosition,
            Some("object") => OccurrenceRole::ReceiverPosition,
            _ => OccurrenceRole::ValueReference,
        },
        "object_creation_expression" if field == Some("type") => OccurrenceRole::TypeOperand,
        _ if field == Some("name") && JAVA_DECLARATION_HEADS.contains(&parent_kind) => {
            OccurrenceRole::DeclarationName
        }
        _ if field == Some("name") && JAVA_BINDER_HEADS.contains(&parent_kind) => {
            OccurrenceRole::Binder
        }
        // `(a, b) -> ...` binds through `inferred_parameters`, and `a -> ...`
        // binds through the lambda's own `parameters` field.
        "inferred_parameters" => OccurrenceRole::Binder,
        "lambda_expression" if field == Some("parameters") => OccurrenceRole::Binder,
        // Every remaining `type_identifier` position in Java is a type operand
        // (extends/implements clauses, generic arguments, casts, throws,
        // annotated types); every remaining `identifier` is a value read.
        _ if node.kind() == "type_identifier"
            || matches!(anchor.kind(), "type_identifier" | "scoped_type_identifier") =>
        {
            OccurrenceRole::TypeOperand
        }
        _ => OccurrenceRole::ValueReference,
    };
    Some(role)
}

impl StructuralSpec for JavaStructuralSpec {
    fn language(&self) -> Language {
        Language::Java
    }

    fn kind_table(&self) -> &'static [(&'static str, NormalizedKind)] {
        JAVA_KIND_TABLE
    }

    fn should_extract(&self, node: Node<'_>, kind: NormalizedKind) -> bool {
        kind != NormalizedKind::Assignment
            || node.kind() != "variable_declarator"
            || node.child_by_field_name("value").is_some()
    }

    fn supports_role(&self, role: Role) -> bool {
        role != Role::Kwarg
    }

    fn occurrence_role_support(&self) -> &OccurrenceRoleSupport {
        &JAVA_OCCURRENCE_ROLE_SUPPORT
    }

    fn extract(&self, node: Node<'_>, kind: NormalizedKind, sink: &mut RoleSink<'_>) {
        if let Some(role) = java_occurrence_role(node) {
            sink.occurrence_role(node, role);
        }
        match kind {
            NormalizedKind::Call => {
                match node.kind() {
                    "method_invocation" => {
                        if let Some(name) = node.child_by_field_name("name") {
                            attach_terminal_callee(sink, name, Some(name));
                        }
                        if let Some(object) = node.child_by_field_name("object") {
                            attach_role_with_derived_name(
                                sink,
                                Role::Receiver,
                                object,
                                expression_name_node,
                            );
                        }
                    }
                    "object_creation_expression" => {
                        if let Some(type_node) = node.child_by_field_name("type") {
                            attach_role_with_derived_name(
                                sink,
                                Role::Callee,
                                type_node,
                                expression_name_node,
                            );
                            if let Some(name) = expression_name_node(type_node) {
                                sink.set_name(name);
                            }
                        }
                    }
                    _ => {}
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
                if let Some(object) = node.child_by_field_name("object") {
                    attach_role_with_derived_name(sink, Role::Object, object, expression_name_node);
                }
            }
            NormalizedKind::Method | NormalizedKind::Constructor | NormalizedKind::Class => {
                if let Some(name) = node.child_by_field_name("name") {
                    sink.set_name(name);
                }
                attach_decorators(sink, node);
            }
            NormalizedKind::Assignment => match node.kind() {
                "variable_declarator" => {
                    if let Some(name) = node.child_by_field_name("name") {
                        sink.set_name(name);
                        sink.role_named(Role::Left, name, name);
                    }
                    if let Some(value) = node.child_by_field_name("value") {
                        attach_role_with_derived_name(
                            sink,
                            Role::Right,
                            value,
                            expression_name_node,
                        );
                    }
                }
                "assignment_expression" => {
                    if let Some(left) = node.child_by_field_name("left") {
                        attach_role_with_derived_name(sink, Role::Left, left, expression_name_node);
                    }
                    if let Some(right) = node.child_by_field_name("right") {
                        attach_role_with_derived_name(
                            sink,
                            Role::Right,
                            right,
                            expression_name_node,
                        );
                    }
                }
                _ => {}
            },
            NormalizedKind::Import => {
                for index in 0..node.named_child_count() {
                    let Some(child) = node.named_child(index) else {
                        continue;
                    };
                    if matches!(
                        child.kind(),
                        "identifier" | "scoped_identifier" | "field_access"
                    ) {
                        sink.role_named(Role::Module, child, child);
                        break;
                    }
                }
            }
            NormalizedKind::Identifier => match node.kind() {
                "scoped_identifier" | "scoped_type_identifier" => {
                    if let Some(name) = node
                        .child_by_field_name("name")
                        .or_else(|| last_named_child(node))
                    {
                        sink.set_name(name);
                    }
                }
                _ => sink.set_name(node),
            },
            NormalizedKind::Decorator => {
                if let Some(name) = expression_name_node(node) {
                    sink.set_name(name);
                }
            }
            NormalizedKind::Lambda => {
                attach_decorators(sink, node);
            }
            _ => {
                if let Some(name) = first_named_child(node).and_then(expression_name_node) {
                    sink.set_name(name);
                }
            }
        }
    }
}

#[cfg(test)]
mod structural_spec_tests {
    use super::*;

    use crate::analyzer::structural::adapter_helpers::{
        assert_occurrence_role, occurrence_roles_of,
    };

    /// The four positions #1473 names for Java: a declaration head, a bound
    /// parameter, an annotation operand consumed as a type, and the tail of an
    /// import — each of which a semantic layer has historically mislabelled.
    #[test]
    fn java_classifies_declaration_binder_annotation_and_import_positions() {
        let source = concat!(
            "package com.example.app;\n",
            "import java.util.List;\n",
            "@Deprecated\n",
            "class Widget {\n",
            "    List<String> render(String label) {\n",
            "        return helper.build(label);\n",
            "    }\n",
            "}\n",
        );
        let found = occurrence_roles_of(
            &JAVA_STRUCTURAL_SPEC,
            &tree_sitter_java::LANGUAGE.into(),
            source,
        );

        let at = |needle: &str| source.find(needle).expect("fixture token");
        assert_occurrence_role(&found, at("Widget"), OccurrenceRole::DeclarationName);
        assert_occurrence_role(&found, at("render"), OccurrenceRole::DeclarationName);
        assert_occurrence_role(&found, at("label)"), OccurrenceRole::Binder);
        assert_occurrence_role(&found, at("Deprecated"), OccurrenceRole::TypeOperand);
        assert_occurrence_role(&found, at("List;"), OccurrenceRole::ImportTarget);
        assert_occurrence_role(&found, at("java.util"), OccurrenceRole::PathSegment);
        assert_occurrence_role(&found, at("List<String>"), OccurrenceRole::TypeOperand);
        assert_occurrence_role(&found, at("String label"), OccurrenceRole::TypeOperand);
        assert_occurrence_role(&found, at("helper"), OccurrenceRole::ReceiverPosition);
        assert_occurrence_role(&found, at("build"), OccurrenceRole::MemberPosition);
        assert_occurrence_role(&found, at("label);"), OccurrenceRole::ValueReference);
    }

    /// Support is a declaration, not a description of what happened to be
    /// emitted: every role Java emits must be one it declares.
    #[test]
    fn java_emits_only_roles_it_declares_as_supported() {
        let source = "class A { void f(int b) { c.d(b); } }\n";
        let found = occurrence_roles_of(
            &JAVA_STRUCTURAL_SPEC,
            &tree_sitter_java::LANGUAGE.into(),
            source,
        );
        assert!(!found.is_empty());
        for (_, text, role) in &found {
            assert!(
                JAVA_STRUCTURAL_SPEC
                    .occurrence_role_support()
                    .is_supported(*role),
                "java emitted undeclared role {role:?} for {text:?}"
            );
        }
    }

    #[test]
    fn java_kind_table_matches_grammar() {
        crate::analyzer::structural::adapter_helpers::assert_kind_table_matches_grammar(
            tree_sitter_java::LANGUAGE.into(),
            "tree-sitter-java",
            JAVA_KIND_TABLE,
        );
    }
}
