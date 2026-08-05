//! Java structural spec for `query_code`.
//!
//! This maps tree-sitter-java node types to Bifrost's normalized structural
//! vocabulary and extracts role edges from AST fields.

use crate::analyzer::structural::adapter_helpers::{
    attach_positional_argument_roles, attach_role_with_derived_name, attach_terminal_callee,
    field_name_in_parent, first_named_child, is_field_of, nearest_ancestor, node_range,
};
use crate::analyzer::structural::adapter_helpers::{
    linear_chain_tokens, qualified_chain_root, spelled_generic_arity,
};
use crate::analyzer::structural::{
    BindingActivation, BindingKind, DEEP_LEXICAL_ENVIRONMENT_SUPPORT_WITH_REJECTIONS,
    HoistingClass, LexicalEnvironmentSupport, NormalizedKind, OccurrenceRole,
    OccurrenceRoleSupport, Role, RoleSink, StructuralSpec,
};
use crate::analyzer::structural::{DEEP_IDENTITY_AXES, IdentityRouteSupport, RouteHopKind};
use crate::analyzer::{Language, Range};
use tree_sitter::Node;

/// The left-nested qualified-name chains of the Java grammar, paired with the
/// field that names each link's own segment.
const JAVA_PATH_CHAIN: &[(&str, Option<&str>)] = &[
    ("scoped_identifier", Some("name")),
    ("scoped_type_identifier", None),
];

#[derive(Debug, Default)]
pub(crate) struct JavaStructuralSpec;

pub(crate) static JAVA_STRUCTURAL_SPEC: JavaStructuralSpec = JavaStructuralSpec;

const JAVA_KIND_TABLE: &[(&str, NormalizedKind)] = &[
    ("method_invocation", NormalizedKind::Call),
    ("method_reference", NormalizedKind::Call),
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
    // Java scopes statements with `block`; `switch_block` is the statement
    // list of a switch, and both are separate nodes from the callable, class,
    // and loop declarations that already become facts.
    ("block", NormalizedKind::Block),
    ("switch_block", NormalizedKind::Block),
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

/// The binding one Java binder token introduces, and the interval it is in
/// effect over.
///
/// Java has four shapes and they differ only in that interval:
///
/// - A formal or lambda parameter is in effect over its whole callable, which
///   is exactly the declaring scope, so it is `ScopeWide`. This is what makes a
///   parameter reachable from inside the body block even though the parameter
///   list sits outside that block's byte range.
/// - A local is in effect from the end of its declaration statement to the end
///   of its block (`SourceOrder`), which is why a read above the declaration
///   reaches nothing.
/// - A `catch` parameter is in effect over the catch clause's body, and a
///   try-with-resources resource over the try block — both `DeclaredHead`,
///   because the interval is a named sub-range of the declaring scope rather
///   than a suffix of it.
fn java_binding_activation(binder: Node<'_>, scope: Range) -> Option<BindingActivation> {
    let form = nearest_ancestor(binder, |kind| {
        matches!(
            kind,
            "formal_parameter"
                | "spread_parameter"
                | "receiver_parameter"
                | "inferred_parameters"
                | "lambda_expression"
                | "catch_formal_parameter"
                | "resource"
                | "variable_declarator"
                | "type_pattern"
        )
    })?;
    match form.kind() {
        "formal_parameter"
        | "spread_parameter"
        | "receiver_parameter"
        | "inferred_parameters"
        | "lambda_expression" => Some(BindingActivation {
            kind: BindingKind::Parameter,
            hoisting: HoistingClass::ScopeWide,
            activation: scope,
        }),
        "catch_formal_parameter" => {
            let clause = nearest_ancestor(form, |kind| kind == "catch_clause")?;
            let body = clause.child_by_field_name("body")?;
            Some(BindingActivation {
                kind: BindingKind::CatchOrResource,
                hoisting: HoistingClass::DeclaredHead,
                activation: node_range(body),
            })
        }
        "resource" => {
            let statement = nearest_ancestor(form, |kind| kind == "try_with_resources_statement")?;
            let body = statement.child_by_field_name("body")?;
            Some(BindingActivation {
                kind: BindingKind::CatchOrResource,
                hoisting: HoistingClass::DeclaredHead,
                activation: node_range(body),
            })
        }
        "type_pattern" => {
            // `if (o instanceof String s)` binds `s` for the guarded branch.
            // The grammar does not mark that branch, so the honest interval is
            // the enclosing condition's statement, which the pattern's nearest
            // statement ancestor states exactly.
            let statement = nearest_ancestor(form, |kind| {
                matches!(kind, "if_statement" | "while_statement" | "do_statement")
            })?;
            Some(BindingActivation {
                kind: BindingKind::PatternBinder,
                hoisting: HoistingClass::DeclaredHead,
                activation: node_range(statement),
            })
        }
        _ => {
            // A local declarator: in effect from the end of the statement that
            // declares it. A `for` init declaration ends before the condition,
            // so the loop's own header sees the variable.
            let declaration =
                nearest_ancestor(form, |kind| kind == "local_variable_declaration").unwrap_or(form);
            Some(BindingActivation {
                kind: BindingKind::Local,
                hoisting: HoistingClass::SourceOrder,
                activation: Range {
                    start_byte: declaration.end_byte(),
                    end_byte: scope.end_byte,
                    start_line: declaration.end_position().row + 1,
                    end_line: scope.end_line,
                },
            })
        }
    }
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

    fn generator_construct(&self, node: Node<'_>, _kind: NormalizedKind) -> Option<&'static str> {
        (node.kind() == "method_reference").then_some("java_method_reference")
    }

    fn supports_role(&self, role: Role) -> bool {
        role != Role::Kwarg
    }

    fn occurrence_role_support(&self) -> &OccurrenceRoleSupport {
        &JAVA_OCCURRENCE_ROLE_SUPPORT
    }

    fn lexical_environment_support(&self) -> &LexicalEnvironmentSupport {
        &DEEP_LEXICAL_ENVIRONMENT_SUPPORT_WITH_REJECTIONS
    }

    fn identity_route_support(&self) -> &IdentityRouteSupport {
        // Java has no export, re-export, partial, or header/body construct;
        // its indirections are imports and nested owners.
        static SUPPORT: IdentityRouteSupport = DEEP_IDENTITY_AXES
            .supported_relation(RouteHopKind::Import)
            .supported_relation(RouteHopKind::NestedOwner);
        &SUPPORT
    }

    fn binding_activation(&self, binder: Node<'_>, scope: Range) -> Option<BindingActivation> {
        java_binding_activation(binder, scope)
    }

    fn qualified_path_root<'tree>(&self, token: Node<'tree>) -> Option<Node<'tree>> {
        if !matches!(token.kind(), "identifier" | "type_identifier") {
            return None;
        }
        qualified_chain_root(token, JAVA_PATH_CHAIN)
    }

    fn path_segment_tokens<'tree>(&self, root: Node<'tree>) -> Vec<Node<'tree>> {
        linear_chain_tokens(root, JAVA_PATH_CHAIN, &[])
    }

    fn segment_generic_arity(&self, token: Node<'_>) -> Option<u32> {
        spelled_generic_arity(token, JAVA_PATH_CHAIN, &["generic_type"])
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
                    "method_reference" => {
                        let mut cursor = node.walk();
                        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
                        if let Some((member, receivers)) = children.split_last()
                            && let Some(receiver) = receivers.last()
                        {
                            attach_terminal_callee(sink, *member, Some(*member));
                            attach_role_with_derived_name(
                                sink,
                                Role::Receiver,
                                *receiver,
                                expression_name_node,
                            );
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
        assert_occurrence_role, block_facts_of, occurrence_roles_of,
    };

    /// Java's scope-forming statement lists are `block` and `switch_block`.
    /// The class body is neither: it is a member list, and the declarations in
    /// it are already facts of their own.
    #[test]
    fn java_blocks_and_switch_blocks_become_scope_facts() {
        let source = concat!(
            "class Widget {\n",
            "    void render(int size) {\n",
            "        if (size > 0) {\n",
            "            log(size);\n",
            "        }\n",
            "        switch (size) {\n",
            "            default:\n",
            "                break;\n",
            "        }\n",
            "    }\n",
            "}\n",
        );

        assert_eq!(
            block_facts_of(
                &JAVA_STRUCTURAL_SPEC,
                &tree_sitter_java::LANGUAGE.into(),
                source,
            ),
            vec![
                concat!(
                    "{\n",
                    "        if (size > 0) {\n",
                    "            log(size);\n",
                    "        }\n",
                    "        switch (size) {\n",
                    "            default:\n",
                    "                break;\n",
                    "        }\n",
                    "    }",
                ),
                concat!("{\n", "            log(size);\n", "        }"),
                concat!(
                    "{\n",
                    "            default:\n",
                    "                break;\n",
                    "        }",
                ),
            ]
        );
    }

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
