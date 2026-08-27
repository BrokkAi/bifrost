//! C# structural spec for `query_code`.

use crate::syntax::{csharp_conditional_member_access, csharp_member_name};
use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::structural::adapter_helpers::{
    attach_role_with_derived_name, attach_terminal_callee, first_named_child,
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
    CALLABLE_APPLICABILITY_ONLY_SUPPORT, LexicalEnvironmentSupport,
};
use brokk_bifrost_core::analyzer::structural::routes::{
    IdentityAxis, IdentityRouteSupport, RouteHopKind,
};
use brokk_bifrost_core::analyzer::structural::spec::{RoleSink, StructuralSpec};
use tree_sitter::Node;

#[derive(Debug, Default)]
pub struct CSharpStructuralSpec;

pub static CSHARP_STRUCTURAL_SPEC: CSharpStructuralSpec = CSharpStructuralSpec;

static CSHARP_OCCURRENCE_ROLE_SUPPORT: OccurrenceRoleSupport =
    OccurrenceRoleSupport::NONE.supported(OccurrenceRole::MemberPosition);

pub const CSHARP_KIND_TABLE: &[(&str, NormalizedKind)] = &[
    ("invocation_expression", NormalizedKind::Call),
    ("object_creation_expression", NormalizedKind::Call),
    ("member_access_expression", NormalizedKind::FieldAccess),
    ("conditional_access_expression", NormalizedKind::FieldAccess),
    ("method_declaration", NormalizedKind::Method),
    ("constructor_declaration", NormalizedKind::Constructor),
    ("local_function_statement", NormalizedKind::Function),
    ("lambda_expression", NormalizedKind::Lambda),
    ("anonymous_method_expression", NormalizedKind::Lambda),
    ("class_declaration", NormalizedKind::Class),
    ("interface_declaration", NormalizedKind::Class),
    ("struct_declaration", NormalizedKind::Class),
    ("enum_declaration", NormalizedKind::Class),
    ("record_declaration", NormalizedKind::Class),
    ("property_declaration", NormalizedKind::Declaration),
    ("variable_declarator", NormalizedKind::Assignment),
    ("assignment_expression", NormalizedKind::Assignment),
    ("using_directive", NormalizedKind::Import),
    ("attribute", NormalizedKind::Decorator),
    ("identifier", NormalizedKind::Identifier),
    ("generic_name", NormalizedKind::Identifier),
    ("qualified_name", NormalizedKind::Identifier),
    ("alias_qualified_name", NormalizedKind::Identifier),
    ("predefined_type", NormalizedKind::Identifier),
    ("string_literal", NormalizedKind::StringLiteral),
    ("verbatim_string_literal", NormalizedKind::StringLiteral),
    ("raw_string_literal", NormalizedKind::StringLiteral),
    ("character_literal", NormalizedKind::StringLiteral),
    ("prefix_unary_expression", NormalizedKind::NumericLiteral),
    ("integer_literal", NormalizedKind::NumericLiteral),
    ("real_literal", NormalizedKind::NumericLiteral),
    ("boolean_literal", NormalizedKind::BooleanLiteral),
    ("null_literal", NormalizedKind::NullLiteral),
    ("return_statement", NormalizedKind::Return),
    ("throw_statement", NormalizedKind::Throw),
    ("throw_expression", NormalizedKind::Throw),
    ("catch_clause", NormalizedKind::Catch),
    ("if_statement", NormalizedKind::If),
    ("switch_statement", NormalizedKind::If),
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
            "identifier" | "predefined_type" => return Some(current),
            "generic_name" => current = first_named_child(current)?,
            "qualified_name" | "alias_qualified_name" => {
                current = current.child_by_field_name("name")?;
            }
            "invocation_expression" => current = current.child_by_field_name("function")?,
            "object_creation_expression" => current = current.child_by_field_name("type")?,
            "member_access_expression" => current = current.child_by_field_name("name")?,
            "conditional_access_expression" => current = conditional_member_binding(current)?,
            "member_binding_expression" => current = current.child_by_field_name("name")?,
            "argument" | "attribute_argument" => {
                current = first_argument_value(current).map(expression_target_node)?;
            }
            _ => return None,
        }
    }
}

fn is_numeric_literal_node(node: Node<'_>) -> bool {
    matches!(node.kind(), "integer_literal" | "real_literal")
}

fn is_signed_numeric_prefix(node: Node<'_>) -> bool {
    node.kind() == "prefix_unary_expression"
        && last_named_child(node)
            .map(expression_target_node)
            .is_some_and(is_numeric_literal_node)
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

fn callable_target_node(node: Node<'_>) -> Option<Node<'_>> {
    Some(expression_target_node(node))
}

fn conditional_member_binding(node: Node<'_>) -> Option<Node<'_>> {
    csharp_conditional_member_access(node).map(|access| access.binding)
}

/// Classify the terminal identifier of an ordinary or conditional member name.
///
/// A generic member name inserts one `generic_name` wrapper between the
/// identifier and its owning access node. Checking the owning node's `name`
/// field keeps receivers, declaration names and named-argument labels out of
/// the member-position role without inspecting source text.
fn csharp_member_position(node: Node<'_>) -> Option<OccurrenceRole> {
    if node.kind() != "identifier" {
        return None;
    }

    let parent = node.parent()?;
    let member_name = match parent.kind() {
        "member_access_expression" | "member_binding_expression" => {
            parent.child_by_field_name("name")?
        }
        "generic_name" => {
            if parent.child_by_field_name("name") != Some(node) {
                return None;
            }
            let access = parent.parent()?;
            if !matches!(
                access.kind(),
                "member_access_expression" | "member_binding_expression"
            ) || access.child_by_field_name("name") != Some(parent)
            {
                return None;
            }
            parent
        }
        _ => return None,
    };

    csharp_member_name(member_name)
        .is_some_and(|member| member.identifier.id() == node.id())
        .then_some(OccurrenceRole::MemberPosition)
}

fn first_argument_value(argument: Node<'_>) -> Option<Node<'_>> {
    let keyword = argument.child_by_field_name("name");
    (0..argument.named_child_count())
        .filter_map(|index| argument.named_child(index))
        .find(|child| keyword.is_none_or(|keyword| child.id() != keyword.id()))
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
        if let Some(value) = first_argument_value(argument).map(expression_target_node) {
            if let Some(keyword) = keyword {
                sink.kwarg(keyword, value);
            } else {
                attach_role_with_derived_name(sink, Role::Arg, value, expression_name_node);
            }
        }
    }
}

fn attach_decorators(sink: &mut RoleSink<'_>, declaration: Node<'_>) {
    for index in 0..declaration.named_child_count() {
        let Some(child) = declaration.named_child(index) else {
            continue;
        };
        if child.kind() != "attribute_list" {
            continue;
        }
        for attr_index in 0..child.named_child_count() {
            if let Some(attribute) = child.named_child(attr_index)
                && attribute.kind() == "attribute"
            {
                attach_role_with_derived_name(
                    sink,
                    Role::Decorator,
                    attribute,
                    expression_name_node,
                );
            }
        }
    }
}

fn variable_declarator_value(node: Node<'_>) -> Option<Node<'_>> {
    let name = node.child_by_field_name("name");
    (0..node.named_child_count())
        .filter_map(|index| node.named_child(index))
        .find(|child| {
            name.is_none_or(|name| child.id() != name.id())
                && child.kind() != "bracketed_argument_list"
        })
        .map(expression_target_node)
}

fn using_type_node(node: Node<'_>) -> Option<Node<'_>> {
    let alias = node.child_by_field_name("name");
    (0..node.named_child_count())
        .filter_map(|index| node.named_child(index))
        .find(|child| alias.is_none_or(|alias| child.id() != alias.id()))
}

fn span_from(first: Node<'_>, last: Node<'_>) -> Span {
    Span {
        start_byte: first.start_byte(),
        end_byte: last.end_byte(),
    }
}

fn leftmost_name_node(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        match node.kind() {
            "identifier" | "predefined_type" => return Some(node),
            "generic_name" | "qualified_name" | "alias_qualified_name" => {
                node = node
                    .child_by_field_name("qualifier")
                    .or_else(|| node.child_by_field_name("alias"))
                    .or_else(|| first_named_child(node))?;
            }
            _ => return first_named_child(node),
        }
    }
}

fn attach_module_binding(sink: &mut RoleSink<'_>, target: Node<'_>, name: Node<'_>) {
    sink.role_named(Role::Module, target, name);
    if let Some(first) = leftmost_name_node(target)
        && first.id() != name.id()
    {
        sink.role_named_span(Role::Module, target, span_from(first, name));
    }
}

fn attach_import_modules(sink: &mut RoleSink<'_>, node: Node<'_>) {
    if let Some(alias) = node.child_by_field_name("name") {
        sink.role_named(Role::Module, node, alias);
        return;
    }
    if let Some(target) = using_type_node(node)
        && let Some(name) = expression_name_node(target)
    {
        attach_module_binding(sink, target, name);
    }
}

impl StructuralSpec for CSharpStructuralSpec {
    fn language(&self) -> Language {
        Language::CSharp
    }

    fn supports_boolean_literal_value(&self) -> bool {
        true
    }

    fn parser_included_ranges(&self, source: &str) -> Option<Vec<tree_sitter::Range>> {
        crate::preprocessor::csharp_included_ranges(source)
    }

    fn kind_table(&self) -> &'static [(&'static str, NormalizedKind)] {
        CSHARP_KIND_TABLE
    }

    fn should_extract(&self, node: Node<'_>, kind: NormalizedKind) -> bool {
        if kind == NormalizedKind::FieldAccess && node.kind() == "conditional_access_expression" {
            return conditional_member_binding(node).is_some();
        }

        if kind == NormalizedKind::NumericLiteral {
            if node.kind() == "prefix_unary_expression" {
                return is_signed_numeric_prefix(node);
            }
            if is_numeric_literal_node(node) && is_inside_signed_numeric_wrapper(node) {
                return false;
            }
        }

        kind != NormalizedKind::Assignment
            || node.kind() != "variable_declarator"
            || variable_declarator_value(node).is_some()
    }

    /// C# spells object creation as its own grammar node, so a constructor
    /// call is a node-type reading (#1478). Named arguments already reach the
    /// shared arena as keyword roles and need no classification here.
    fn call_site_facts(
        &self,
        node: Node<'_>,
        _source: &str,
        _context: &CallSiteContext,
    ) -> Option<CallSiteFacts> {
        (node.kind() == "object_creation_expression")
            .then(|| CallSiteFacts::of_kind(CallKind::Constructor))
    }

    fn supports_role(&self, role: Role) -> bool {
        // #2647: not yet extracted by this adapter.
        !matches!(role, Role::Iterable | Role::Element)
    }

    fn occurrence_role_support(&self) -> &OccurrenceRoleSupport {
        &CSHARP_OCCURRENCE_ROLE_SUPPORT
    }

    fn lexical_environment_support(&self) -> &LexicalEnvironmentSupport {
        // C# classifies no scopes, binding intervals, import binders or
        // package clause, but its member walk reports per-candidate callable
        // applicability (#1478 M3). The per-axis table states exactly that.
        &CALLABLE_APPLICABILITY_ONLY_SUPPORT
    }

    fn materialization_support(&self) -> &DeclarationMaterializationSupport {
        &NO_MATERIALIZATION_SUPPORT
    }

    fn reference_edge_support(&self) -> &ReferenceEdgeSupport {
        &INVERSE_REFERENCE_EDGE_SUPPORT
    }

    fn identity_route_support(&self) -> &IdentityRouteSupport {
        // C#'s occurrence adapter is shallow, so it claims no path axes; its
        // declaration layer does enumerate the parts of a partial type, which
        // is exactly the partial-part relation.
        static SUPPORT: IdentityRouteSupport = IdentityRouteSupport::NONE
            .supported_axis(IdentityAxis::CanonicalIdentity)
            .supported_axis(IdentityAxis::PhysicalGrouping)
            .supported_relation(RouteHopKind::PartialPart)
            .supported_relation(RouteHopKind::NestedOwner);
        &SUPPORT
    }

    fn extract(&self, node: Node<'_>, kind: NormalizedKind, sink: &mut RoleSink<'_>) {
        if let Some(role) = csharp_member_position(node) {
            sink.occurrence_role(node, role);
        }

        match kind {
            NormalizedKind::Call => {
                let function = if node.kind() == "object_creation_expression" {
                    node.child_by_field_name("type")
                } else {
                    node.child_by_field_name("function")
                };
                if let Some(function) = function {
                    attach_terminal_callee(sink, function, expression_name_node(function));
                    if let Some(target) = callable_target_node(function)
                        && target.kind() == "member_access_expression"
                        && let Some(receiver) = target.child_by_field_name("expression")
                    {
                        attach_role_with_derived_name(
                            sink,
                            Role::Receiver,
                            receiver,
                            expression_name_node,
                        );
                    }
                    if let Some(target) = callable_target_node(function)
                        && target.kind() == "conditional_access_expression"
                        && let Some(receiver) = target.child_by_field_name("condition")
                    {
                        attach_role_with_derived_name(
                            sink,
                            Role::Receiver,
                            receiver,
                            expression_name_node,
                        );
                    }
                }
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    attach_argument_roles(sink, arguments);
                }
            }
            NormalizedKind::FieldAccess => {
                let field = if node.kind() == "conditional_access_expression" {
                    conditional_member_binding(node)
                        .and_then(|binding| binding.child_by_field_name("name"))
                } else {
                    node.child_by_field_name("name")
                };
                if let Some(field) = field {
                    attach_role_with_derived_name(sink, Role::Field, field, expression_name_node);
                    if let Some(name) = expression_name_node(field) {
                        sink.set_name(name);
                    }
                }
                let object = if node.kind() == "conditional_access_expression" {
                    node.child_by_field_name("condition")
                } else {
                    node.child_by_field_name("expression")
                };
                if let Some(object) = object {
                    attach_role_with_derived_name(sink, Role::Object, object, expression_name_node);
                }
            }
            NormalizedKind::Function
            | NormalizedKind::Method
            | NormalizedKind::Constructor
            | NormalizedKind::Class
            | NormalizedKind::Declaration => {
                if let Some(name) = node.child_by_field_name("name") {
                    sink.set_name(name);
                }
                attach_decorators(sink, node);
            }
            NormalizedKind::Assignment => match node.kind() {
                "variable_declarator" => {
                    if let Some(name) = node.child_by_field_name("name") {
                        sink.role_named(Role::Left, name, name);
                        sink.set_name(name);
                    }
                    if let Some(value) = variable_declarator_value(node) {
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
                if let Some(name) = node.child_by_field_name("name") {
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
    use super::*;
    use brokk_bifrost_core::analyzer::structural::occurrences::OccurrenceRole;
    use tree_sitter::{Parser, Tree};

    fn parse(source: &str) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
            .expect("C# grammar loads");
        let tree = parser.parse(source, None).expect("C# source parses");
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
            if node.kind() == "identifier" {
                let spelling = node
                    .utf8_text(source.as_bytes())
                    .expect("identifier has valid source span")
                    .to_owned();
                identifiers.push((spelling, csharp_member_position(node)));
            }
            pending
                .extend((0..node.named_child_count()).filter_map(|index| node.named_child(index)));
        }
        identifiers
    }

    #[test]
    fn member_positions_are_limited_to_member_access_names() {
        let source = r#"
            class Runner {
                int Field;
                void Build(int count) { }

                void Run(Runner service, int count) {
                    var result = service.Build(count: count);
                    var optional = service?.Build(count: count);
                    var unrelated = count;
                }
            }
        "#;

        let identifiers = identifier_roles(source);
        let member_names: Vec<_> = identifiers
            .iter()
            .filter_map(|(spelling, role)| {
                (*role == Some(OccurrenceRole::MemberPosition)).then_some(spelling.as_str())
            })
            .collect();
        assert_eq!(member_names, ["Build", "Build"]);

        for spelling in ["service", "count", "Field", "unrelated", "result"] {
            assert!(
                identifiers
                    .iter()
                    .filter(|(name, _)| name == spelling)
                    .all(|(_, role)| *role != Some(OccurrenceRole::MemberPosition)),
                "{spelling} must not be a member-position occurrence"
            );
        }

        assert!(
            identifiers
                .iter()
                .filter(|(name, _)| name == "Build")
                .any(|(_, role)| role.is_none()),
            "the Build declaration must not be a member-position occurrence"
        );
    }

    #[test]
    fn csharp_support_advertises_only_member_position() {
        let support = CSHARP_STRUCTURAL_SPEC.occurrence_role_support();
        assert!(support.is_supported(OccurrenceRole::MemberPosition));
        assert!(!support.is_supported(OccurrenceRole::ReceiverPosition));
        assert!(!support.is_supported(OccurrenceRole::ValueReference));
    }
}
