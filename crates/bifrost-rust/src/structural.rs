//! Rust structural spec for `query_code`.

use brokk_bifrost_core::analyzer::structural::adapter_helpers::{
    attach_positional_argument_roles, attach_role_with_derived_name, attach_terminal_callee,
    field_name_in_parent, first_named_child, is_field_of, nearest_ancestor, node_range,
};
use brokk_bifrost_core::analyzer::structural::adapter_helpers::{
    linear_chain_tokens, qualified_chain_root, spelled_generic_arity,
};
use brokk_bifrost_core::analyzer::structural::edges::{
    DEEP_REFERENCE_EDGE_SUPPORT, ReferenceEdgeSupport,
};
use brokk_bifrost_core::analyzer::structural::kinds::{NormalizedKind, Role};
use brokk_bifrost_core::analyzer::structural::materialization::{
    DeclarationMaterializationSupport, NO_MATERIALIZATION_SUPPORT,
};
use brokk_bifrost_core::analyzer::structural::occurrences::{
    OccurrenceRole, OccurrenceRoleSupport,
};
use brokk_bifrost_core::analyzer::structural::resolution::{
    BindingActivation, BindingKind, DEEP_LEXICAL_ENVIRONMENT_SUPPORT_WITH_REJECTIONS,
    HoistingClass, LexicalEnvironmentSupport,
};
use brokk_bifrost_core::analyzer::structural::routes::{
    DEEP_IDENTITY_AXES, IdentityRouteSupport, RouteHopKind,
};
use brokk_bifrost_core::analyzer::structural::spec::{RoleSink, StructuralSpec};
use brokk_bifrost_core::analyzer::{Language, Range};
use tree_sitter::Node;

/// The left-nested qualified-path chains of the Rust grammar, paired with the
/// field that names each link's own segment. A turbofish link
/// (`Vec::<u8>::new`) wraps its inner path in `generic_type`, which the chain
/// walk unwraps.
const RUST_PATH_CHAIN: &[(&str, Option<&str>)] = &[
    ("scoped_identifier", Some("name")),
    ("scoped_type_identifier", Some("name")),
];

#[derive(Debug, Default)]
pub struct RustStructuralSpec;

pub static RUST_STRUCTURAL_SPEC: RustStructuralSpec = RustStructuralSpec;

fn macro_arguments(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("arguments").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .find(|child| child.kind() == "token_tree")
    })
}

pub const RUST_KIND_TABLE: &[(&str, NormalizedKind)] = &[
    ("call_expression", NormalizedKind::Call),
    ("macro_invocation", NormalizedKind::Call),
    ("attribute", NormalizedKind::Decorator),
    ("field_declaration", NormalizedKind::Declaration),
    ("field_expression", NormalizedKind::FieldAccess),
    ("function_item", NormalizedKind::Function),
    ("function_signature_item", NormalizedKind::Function),
    ("closure_expression", NormalizedKind::Lambda),
    ("struct_item", NormalizedKind::Class),
    ("enum_item", NormalizedKind::Class),
    ("trait_item", NormalizedKind::Class),
    ("type_item", NormalizedKind::Declaration),
    ("const_item", NormalizedKind::Assignment),
    ("static_item", NormalizedKind::Assignment),
    ("let_declaration", NormalizedKind::Assignment),
    ("assignment_expression", NormalizedKind::Assignment),
    ("compound_assignment_expr", NormalizedKind::Assignment),
    ("use_declaration", NormalizedKind::Import),
    ("identifier", NormalizedKind::Identifier),
    ("field_identifier", NormalizedKind::Identifier),
    ("scoped_identifier", NormalizedKind::Identifier),
    ("type_identifier", NormalizedKind::Identifier),
    ("char_literal", NormalizedKind::StringLiteral),
    ("string_literal", NormalizedKind::StringLiteral),
    ("raw_string_literal", NormalizedKind::StringLiteral),
    ("unary_expression", NormalizedKind::NumericLiteral),
    ("integer_literal", NormalizedKind::NumericLiteral),
    ("float_literal", NormalizedKind::NumericLiteral),
    ("negative_literal", NormalizedKind::NumericLiteral),
    ("boolean_literal", NormalizedKind::BooleanLiteral),
    ("return_expression", NormalizedKind::Return),
    ("if_expression", NormalizedKind::If),
    ("for_expression", NormalizedKind::ForLoop),
    ("while_expression", NormalizedKind::WhileLoop),
    ("loop_expression", NormalizedKind::Loop),
    // Every Rust scope-forming statement list is a `block`: function bodies,
    // loop and conditional bodies, and bare blocks in expression position.
    ("block", NormalizedKind::Block),
];

fn expression_name_node<'tree>(expression: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = expression;
    loop {
        match current.kind() {
            "identifier" | "field_identifier" | "type_identifier" | "self" | "super" | "crate" => {
                return Some(current);
            }
            "scoped_identifier" => current = current.child_by_field_name("name")?,
            "generic_function" => current = current.child_by_field_name("function")?,
            "field_expression" => current = current.child_by_field_name("field")?,
            "call_expression" => current = current.child_by_field_name("function")?,
            "mut_pattern" | "ref_pattern" => current = first_named_child(current)?,
            "parenthesized_expression" => current = first_named_child(current)?,
            _ => return None,
        }
    }
}

fn attach_scoped_receiver(sink: &mut RoleSink<'_>, function: Node<'_>) {
    if function.kind() != "scoped_identifier" {
        return;
    }
    if let Some(path) = function.child_by_field_name("path") {
        attach_role_with_derived_name(sink, Role::Receiver, path, expression_name_node);
    }
}

fn call_function_target(mut function: Node<'_>) -> Node<'_> {
    while function.kind() == "generic_function" {
        let Some(inner) = function.child_by_field_name("function") else {
            break;
        };
        function = inner;
    }
    function
}

fn is_numeric_literal_node(node: Node<'_>) -> bool {
    matches!(node.kind(), "integer_literal" | "float_literal")
}

fn is_negative_numeric_unary(node: Node<'_>) -> bool {
    node.kind() == "unary_expression"
        && node.child(0).is_some_and(|operator| operator.kind() == "-")
        && first_named_child(node).is_some_and(is_numeric_literal_node)
}

fn is_inside_negative_numeric_wrapper(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    parent.kind() == "negative_literal" || is_negative_numeric_unary(parent)
}

fn attach_use_module(sink: &mut RoleSink<'_>, node: Node<'_>) {
    match node.kind() {
        "identifier" | "scoped_identifier" | "self" | "super" | "crate" => {
            attach_role_with_derived_name(sink, Role::Module, node, expression_name_node);
        }
        "use_as_clause" => {
            if let Some(alias) = node.child_by_field_name("alias") {
                attach_role_with_derived_name(sink, Role::Module, alias, expression_name_node);
            } else if let Some(first) = first_named_child(node) {
                attach_use_module(sink, first);
            }
        }
        "scoped_use_list" => {
            if let Some(list) = node.child_by_field_name("list") {
                attach_use_module(sink, list);
            }
        }
        _ => {
            for index in 0..node.named_child_count() {
                let Some(child) = node.named_child(index) else {
                    continue;
                };
                attach_use_module(sink, child);
            }
        }
    }
}

fn function_item_is_method(node: Node<'_>) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        match parent.kind() {
            "impl_item" | "trait_item" => return true,
            "function_item" => return false,
            _ => current = parent.parent(),
        }
    }
    false
}

fn is_inside_derive_attribute(node: Node<'_>, source: &str) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        match parent.kind() {
            "token_tree" => current = parent.parent(),
            "attribute" => {
                return first_named_child(parent).is_some_and(|name| {
                    name.kind() == "identifier" && name.utf8_text(source.as_bytes()) == Ok("derive")
                });
            }
            _ => return false,
        }
    }
    false
}

fn derive_path_module(node: Node<'_>) -> Option<Node<'_>> {
    let separator = node.prev_sibling()?;
    (separator.kind() == "::")
        .then(|| separator.prev_named_sibling())
        .flatten()
        .filter(|module| module.kind() == "identifier")
}

static RUST_OCCURRENCE_ROLE_SUPPORT: OccurrenceRoleSupport = OccurrenceRoleSupport::NONE
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

const RUST_DECLARATION_HEADS: &[&str] = &[
    "function_item",
    "function_signature_item",
    "struct_item",
    "enum_item",
    "union_item",
    "trait_item",
    "type_item",
    "const_item",
    "static_item",
    "mod_item",
    "macro_definition",
    "field_declaration",
    "enum_variant",
    "associated_type",
    "extern_crate_declaration",
    "type_parameter",
    "const_parameter",
];

/// Whether this node sits inside a `use` tree, which is what separates an
/// import target from an ordinary path reference spelled the same way.
fn rust_is_in_use_tree(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "use_declaration" => return true,
            "scoped_identifier" | "scoped_use_list" | "use_list" | "use_as_clause"
            | "use_wildcard" => current = parent,
            _ => return false,
        }
    }
    false
}

/// Classify one Rust identifier token by its AST position.
///
/// Raw identifiers need no special handling here: `r#type` lexes as a single
/// `identifier` token, so `let r#type = ...` reaches the same binder arm as any
/// other let pattern. Stripping the `r#` prefix is a spelling concern, not a
/// role concern.
fn rust_occurrence_role(node: Node<'_>) -> Option<OccurrenceRole> {
    if !matches!(
        node.kind(),
        "identifier" | "field_identifier" | "type_identifier"
    ) {
        return None;
    }

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
        "use_as_clause" if field == Some("alias") => OccurrenceRole::ImportAlias,
        "scoped_use_list" if field == Some("path") => OccurrenceRole::PathSegment,
        _ if rust_is_in_use_tree(anchor) => OccurrenceRole::ImportTarget,
        _ if field == Some("name") && RUST_DECLARATION_HEADS.contains(&parent_kind) => {
            OccurrenceRole::DeclarationName
        }
        "parameter" | "let_declaration" | "for_expression" if field == Some("pattern") => {
            OccurrenceRole::Binder
        }
        "closure_parameters" | "ref_pattern" | "mut_pattern" | "tuple_pattern"
        | "slice_pattern" | "captured_pattern" => OccurrenceRole::Binder,
        "field_pattern" if field == Some("pattern") => OccurrenceRole::Binder,
        "field_pattern" if field == Some("name") => OccurrenceRole::LabelOrKey,
        "tuple_struct_pattern" => match field {
            Some("type") => OccurrenceRole::PatternPosition,
            _ => OccurrenceRole::Binder,
        },
        "struct_pattern" if field == Some("type") => OccurrenceRole::PatternPosition,
        "field_expression" => match field {
            Some("field") => OccurrenceRole::MemberPosition,
            Some("value") => OccurrenceRole::ReceiverPosition,
            _ => OccurrenceRole::ValueReference,
        },
        "field_initializer" if field == Some("field") => OccurrenceRole::LabelOrKey,
        _ if node.kind() == "type_identifier" => OccurrenceRole::TypeOperand,
        _ if node.kind() == "field_identifier" => OccurrenceRole::MemberPosition,
        _ => OccurrenceRole::ValueReference,
    };
    Some(role)
}

/// The binding one Rust binder token introduces, and the interval it is in
/// effect over.
///
/// This generalizes the intervals `analyzer::rust::lexical_scope` already
/// computes for its private shadowing queries: a `let` is in effect from the
/// end of its declaration to the end of its block, so re-binding the same name
/// is two bindings with adjacent intervals; a `match` arm's pattern is in
/// effect over that arm only; a `for` pattern over the loop body; and
/// parameters over their whole callable.
fn rust_binding_activation(binder: Node<'_>, scope: Range) -> Option<BindingActivation> {
    let form = nearest_ancestor(binder, |kind| {
        matches!(
            kind,
            "let_declaration"
                | "let_condition"
                | "for_expression"
                | "match_arm"
                | "parameter"
                | "closure_parameters"
                | "self_parameter"
        )
    })?;
    match form.kind() {
        "parameter" | "closure_parameters" | "self_parameter" => Some(BindingActivation {
            kind: BindingKind::Parameter,
            hoisting: HoistingClass::ScopeWide,
            activation: scope,
        }),
        "for_expression" => {
            let body = form.child_by_field_name("body")?;
            Some(BindingActivation {
                kind: BindingKind::LoopVariable,
                hoisting: HoistingClass::DeclaredHead,
                activation: node_range(body),
            })
        }
        "match_arm" => Some(BindingActivation {
            kind: BindingKind::PatternBinder,
            hoisting: HoistingClass::DeclaredHead,
            activation: node_range(form),
        }),
        "let_condition" => {
            // `if let Some(x) = value { .. }` binds for the whole conditional
            // expression, which is the smallest range the grammar states.
            let owner = nearest_ancestor(form, |kind| {
                matches!(kind, "if_expression" | "while_expression")
            })?;
            Some(BindingActivation {
                kind: BindingKind::PatternBinder,
                hoisting: HoistingClass::DeclaredHead,
                activation: node_range(owner),
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

impl StructuralSpec for RustStructuralSpec {
    fn language(&self) -> Language {
        Language::Rust
    }

    fn kind_table(&self) -> &'static [(&'static str, NormalizedKind)] {
        RUST_KIND_TABLE
    }

    fn refine_kind(
        &self,
        node: Node<'_>,
        kind: NormalizedKind,
        _enclosing: Option<NormalizedKind>,
        source: &str,
    ) -> NormalizedKind {
        if kind == NormalizedKind::Identifier
            && node.kind() == "identifier"
            && is_inside_derive_attribute(node, source)
        {
            NormalizedKind::Decorator
        } else if kind == NormalizedKind::Function && function_item_is_method(node) {
            NormalizedKind::Method
        } else {
            kind
        }
    }

    fn should_extract(&self, node: Node<'_>, kind: NormalizedKind) -> bool {
        if kind == NormalizedKind::NumericLiteral {
            if node.kind() == "unary_expression" {
                return is_negative_numeric_unary(node);
            }
            if is_numeric_literal_node(node) && is_inside_negative_numeric_wrapper(node) {
                return false;
            }
        }

        kind != NormalizedKind::Assignment
            || !matches!(
                node.kind(),
                "const_item" | "let_declaration" | "static_item"
            )
            || node.child_by_field_name("value").is_some()
    }

    fn supports_kind(&self, kind: NormalizedKind) -> bool {
        kind == NormalizedKind::Method
            || self
                .kind_table()
                .iter()
                .any(|(_, fact_kind)| fact_kind.satisfies(kind))
    }

    fn supports_role(&self, role: Role) -> bool {
        !matches!(role, Role::Kwarg | Role::Decorator)
    }

    fn occurrence_role_support(&self) -> &OccurrenceRoleSupport {
        &RUST_OCCURRENCE_ROLE_SUPPORT
    }

    fn lexical_environment_support(&self) -> &LexicalEnvironmentSupport {
        &DEEP_LEXICAL_ENVIRONMENT_SUPPORT_WITH_REJECTIONS
    }

    fn materialization_support(&self) -> &DeclarationMaterializationSupport {
        &NO_MATERIALIZATION_SUPPORT
    }

    fn reference_edge_support(&self) -> &ReferenceEdgeSupport {
        &DEEP_REFERENCE_EDGE_SUPPORT
    }

    fn identity_route_support(&self) -> &IdentityRouteSupport {
        // `use x as y` is an alias, `pub use` is a re-export, and a trait
        // member's impl item is an implementation peer.
        static SUPPORT: IdentityRouteSupport = DEEP_IDENTITY_AXES
            .supported_relation(RouteHopKind::Alias)
            .supported_relation(RouteHopKind::Import)
            .supported_relation(RouteHopKind::ReExport)
            .supported_relation(RouteHopKind::NestedOwner)
            .supported_relation(RouteHopKind::Implementation);
        &SUPPORT
    }

    fn binding_activation(&self, binder: Node<'_>, scope: Range) -> Option<BindingActivation> {
        rust_binding_activation(binder, scope)
    }

    fn qualified_path_root<'tree>(&self, token: Node<'tree>) -> Option<Node<'tree>> {
        if !matches!(token.kind(), "identifier" | "type_identifier") {
            return None;
        }
        qualified_chain_root(token, RUST_PATH_CHAIN)
    }

    fn path_segment_tokens<'tree>(&self, root: Node<'tree>) -> Vec<Node<'tree>> {
        linear_chain_tokens(root, RUST_PATH_CHAIN, &["generic_type", "generic_function"])
    }

    fn segment_generic_arity(&self, token: Node<'_>) -> Option<u32> {
        spelled_generic_arity(
            token,
            RUST_PATH_CHAIN,
            &["generic_type", "generic_function"],
        )
    }

    fn indirection_relation(&self, token: Node<'_>) -> Option<RouteHopKind> {
        let declaration = nearest_ancestor(token, |kind| kind == "use_declaration")?;
        let mut cursor = declaration.walk();
        let reexports = declaration
            .children(&mut cursor)
            .any(|child| child.kind() == "visibility_modifier");
        Some(if reexports {
            RouteHopKind::ReExport
        } else {
            RouteHopKind::Import
        })
    }

    /// `r#type` is the identifier `type` wearing the raw-identifier escape the
    /// lexer already accepted as one token.
    fn decode_spelling(&self, raw: &str) -> Option<String> {
        raw.strip_prefix("r#").map(str::to_owned)
    }

    fn extract(&self, node: Node<'_>, kind: NormalizedKind, sink: &mut RoleSink<'_>) {
        if let Some(role) = rust_occurrence_role(node) {
            sink.occurrence_role(node, role);
        }
        match kind {
            NormalizedKind::Decorator => {
                let name = if node.kind() == "attribute" {
                    first_named_child(node)
                } else {
                    expression_name_node(node)
                };
                if let Some(name) = name {
                    sink.set_name(name);
                }
                if node.kind() == "attribute"
                    && let Some(value) = node.child_by_field_name("value")
                {
                    sink.role(Role::Arg, value);
                }
                if node.kind() == "identifier"
                    && let Some(module) = derive_path_module(node)
                {
                    sink.role_named(Role::Module, module, module);
                }
            }
            NormalizedKind::Declaration if node.kind() == "field_declaration" => {
                if let Some(name) = node.child_by_field_name("name") {
                    sink.set_name(name);
                }
            }
            NormalizedKind::Call => {
                if node.kind() == "macro_invocation" {
                    if let Some(macro_name) = node.child_by_field_name("macro") {
                        attach_terminal_callee(sink, macro_name, expression_name_node(macro_name));
                    }
                    if let Some(arguments) = macro_arguments(node) {
                        attach_positional_argument_roles(sink, arguments, expression_name_node);
                    }
                } else if let Some(function) = node.child_by_field_name("function") {
                    attach_terminal_callee(sink, function, expression_name_node(function));
                    let target = call_function_target(function);
                    if target.kind() == "field_expression"
                        && let Some(value) = target.child_by_field_name("value")
                    {
                        attach_role_with_derived_name(
                            sink,
                            Role::Receiver,
                            value,
                            expression_name_node,
                        );
                    }
                    attach_scoped_receiver(sink, target);
                }
                if node.kind() != "macro_invocation"
                    && let Some(arguments) = node.child_by_field_name("arguments")
                {
                    attach_positional_argument_roles(sink, arguments, expression_name_node);
                }
            }
            NormalizedKind::FieldAccess => {
                if let Some(field) = node.child_by_field_name("field") {
                    sink.set_name(field);
                    sink.role_named(Role::Field, field, field);
                }
                if let Some(value) = node.child_by_field_name("value") {
                    attach_role_with_derived_name(sink, Role::Object, value, expression_name_node);
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
            NormalizedKind::Assignment => match node.kind() {
                "const_item" | "static_item" => {
                    if let Some(name) = node.child_by_field_name("name") {
                        sink.role_named(Role::Left, name, name);
                        sink.set_name(name);
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
                "let_declaration" => {
                    if let Some(pattern) = node.child_by_field_name("pattern") {
                        attach_role_with_derived_name(
                            sink,
                            Role::Left,
                            pattern,
                            expression_name_node,
                        );
                        if let Some(name) = expression_name_node(pattern) {
                            sink.set_name(name);
                        }
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
                "assignment_expression" | "compound_assignment_expr" => {
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
                if let Some(argument) = node.child_by_field_name("argument") {
                    attach_use_module(sink, argument);
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
