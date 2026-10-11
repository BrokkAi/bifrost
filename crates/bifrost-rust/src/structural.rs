//! Rust structural spec for `query_code`.

use brokk_bifrost_core::analyzer::model::AmbientUseRole;
use brokk_bifrost_core::analyzer::structural::adapter_helpers::{
    attach_role_with_derived_name, attach_terminal_callee, field_name_in_parent, first_named_child,
    is_field_of, nearest_ancestor, node_range,
};
use brokk_bifrost_core::analyzer::structural::adapter_helpers::{
    linear_chain_tokens, qualified_path_chain_root, spelled_generic_arity,
};
use brokk_bifrost_core::analyzer::structural::callable::{
    CallShapeCoverage, CallSiteContext, CallSiteFacts,
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
use brokk_bifrost_core::analyzer::structural::result_use::{
    CallResultUse, CallResultUseIndex, CallResultUseOpenReason, CallResultUseSite,
    IntentionalDiscardKind,
};
use brokk_bifrost_core::analyzer::structural::routes::{
    CuratedExportSurface, DEEP_IDENTITY_AXES, IdentityRouteSupport, RouteHopKind,
};
use brokk_bifrost_core::analyzer::structural::spec::{RoleSink, StructuralSpec};
use brokk_bifrost_core::analyzer::{Language, Range};
use tree_sitter::Node;

use crate::declarations::rust_parameter_label_node;
use crate::syntax::{outer_attributes, unwrap_attributes};

/// The left-nested qualified-path chains of the Rust grammar, paired with the
/// field that names each link's own segment. A turbofish link
/// (`Vec::<u8>::new`) wraps its inner path in `generic_type`, which the chain
/// walk unwraps.
const RUST_PATH_CHAIN: &[(&str, Option<&str>)] = &[
    ("scoped_identifier", Some("name")),
    ("scoped_type_identifier", Some("name")),
];

const RUST_TASK_SPAWN_PATHS: &[&[&str]] = &[
    &["std", "thread", "spawn"],
    &["tokio", "spawn"],
    &["tokio", "task", "spawn_blocking"],
    &["rayon", "spawn"],
];

#[derive(Debug, Default)]
pub struct RustStructuralSpec;

pub static RUST_STRUCTURAL_SPEC: RustStructuralSpec = RustStructuralSpec;

/// Classify one exact Rust call expression without resolving its callee.  The
/// `drop` spelling is read only from the parser-selected function identifier;
/// no source-wide search is used.
pub fn rust_call_result_use(call: Node<'_>, source: &str) -> CallResultUseSite {
    let default = if call.kind() != "call_expression"
        || call.has_error()
        || has_recovery_ancestor(call)
    {
        CallResultUse::Open(CallResultUseOpenReason::RecoveredSyntax)
    } else if has_deferred_ancestor(call) {
        CallResultUse::Open(CallResultUseOpenReason::DeferredContext)
    } else {
        let mut expression = call;
        loop {
            let Some(parent) = expression.parent() else {
                break CallResultUse::Open(CallResultUseOpenReason::UnclassifiedSyntax);
            };
            if parent.is_error() || parent.is_missing() {
                break CallResultUse::Open(CallResultUseOpenReason::RecoveredSyntax);
            }
            match parent.kind() {
                "parenthesized_expression"
                    if parent.named_child_count() == 1
                        && parent
                            .named_child(0)
                            .is_some_and(|child| child.id() == expression.id()) =>
                {
                    expression = parent;
                }
                "expression_statement"
                    if parent.named_child_count() == 1
                        && parent
                            .named_child(0)
                            .is_some_and(|child| child.id() == expression.id()) =>
                {
                    break CallResultUse::Discarded;
                }
                "let_declaration" if field_name_in_parent(parent, expression) == Some("value") => {
                    let pattern = parent
                        .child_by_field_name("pattern")
                        .expect("Rust let declarations have a pattern");
                    break if pattern.kind() == "_" {
                        CallResultUse::IntentionalDiscard(IntentionalDiscardKind::RustLetUnderscore)
                    } else {
                        CallResultUse::Consumed
                    };
                }
                "arguments" => {
                    let Some(outer_call) = parent.parent() else {
                        break CallResultUse::Consumed;
                    };
                    if outer_call.kind() == "call_expression"
                        && outer_call
                            .child_by_field_name("function")
                            .is_some_and(|function| {
                                function.kind() == "identifier"
                                    && function
                                        .utf8_text(source.as_bytes())
                                        .is_ok_and(|text| text == "drop")
                            })
                    {
                        break CallResultUse::IntentionalDiscard(IntentionalDiscardKind::RustDrop);
                    }
                    break CallResultUse::Consumed;
                }
                "closure_expression" | "async_block" | "gen_block" => {
                    break CallResultUse::Open(CallResultUseOpenReason::DeferredContext);
                }
                "macro_invocation" => {
                    break CallResultUse::Open(CallResultUseOpenReason::UnsupportedSyntax);
                }
                _ => break CallResultUse::Consumed,
            }
        }
    };
    CallResultUseSite::new(call.start_byte(), call.end_byte(), default)
}

fn has_recovery_ancestor(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if parent.is_error() || parent.is_missing() {
            return true;
        }
        node = parent;
    }
    false
}

fn has_deferred_ancestor(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "closure_expression" | "async_block" | "gen_block"
        ) {
            return true;
        }
        node = parent;
    }
    false
}

/// One source-snapshot index of exact Rust call spans.
#[derive(Debug, Clone)]
pub struct RustCallResultUseIndex {
    inner: CallResultUseIndex,
}

impl RustCallResultUseIndex {
    pub fn new(root: Node<'_>, source: &str) -> Self {
        let mut sites = Vec::new();
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if node.kind() == "call_expression" {
                sites.push(rust_call_result_use(node, source));
            }
            for index in (0..node.named_child_count()).rev() {
                stack.push(node.named_child(index).expect("named child exists"));
            }
        }
        Self {
            inner: CallResultUseIndex::new(sites),
        }
    }

    pub fn at_span(
        &self,
        start_byte: usize,
        end_byte: usize,
    ) -> Result<&CallResultUseSite, CallResultUseOpenReason> {
        self.inner.at_span(start_byte, end_byte)
    }

    pub fn sites(&self) -> &[CallResultUseSite] {
        self.inner.sites()
    }
}

fn macro_arguments(node: Node<'_>) -> Option<Node<'_>> {
    crate::declarations::rust_macro_invocation_arguments(node)
}

fn rust_modeled_sink_macro_argument_count(node: Node<'_>, source: &str) -> Option<usize> {
    let path = node.child_by_field_name("macro")?;
    let segments = crate::graph_support::rust_path_segments(path)?;
    let member = brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix(
        crate::declarations::rust_node_text(*segments.last()?, source),
    );
    match segments.as_slice() {
        [member_node] if member_node.kind() == "identifier" => {
            matches!(member, "print" | "println" | "eprint" | "eprintln").then_some(1)
        }
        [owner_node, _]
            if owner_node.kind() == "identifier"
                && brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix(
                    crate::declarations::rust_node_text(*owner_node, source),
                ) == "std"
                && matches!(member, "print" | "println" | "eprint" | "eprintln") =>
        {
            Some(1)
        }
        [owner_node, _]
            if owner_node.kind() == "identifier"
                && brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix(
                    crate::declarations::rust_node_text(*owner_node, source),
                ) == "log"
                && crate::format_args::rust_logging_macro("log", member).is_some() =>
        {
            Some(5)
        }
        _ => None,
    }
}

pub const RUST_KIND_TABLE: &[(&str, NormalizedKind)] = &[
    ("line_comment", NormalizedKind::Comment),
    ("block_comment", NormalizedKind::Comment),
    ("call_expression", NormalizedKind::Call),
    ("macro_invocation", NormalizedKind::Call),
    ("attribute", NormalizedKind::Decorator),
    ("field_declaration", NormalizedKind::Declaration),
    ("field_expression", NormalizedKind::FieldAccess),
    ("function_item", NormalizedKind::Function),
    ("function_signature_item", NormalizedKind::Function),
    ("parameter", NormalizedKind::Parameter),
    ("closure_expression", NormalizedKind::Lambda),
    ("async_block", NormalizedKind::Lambda),
    ("await_expression", NormalizedKind::Await),
    ("struct_item", NormalizedKind::Class),
    ("enum_item", NormalizedKind::Class),
    ("trait_item", NormalizedKind::Class),
    // A `type` alias declares a type, so its fact is a type-namespace
    // declaration and its name inherits `Namespace::Type` through
    // `default_occurrence_namespace`. Recorded as a bare `Declaration`, the
    // alias name landed in the value namespace beside a same-named `const`
    // (#2911).
    ("type_item", NormalizedKind::Class),
    ("mod_item", NormalizedKind::Module),
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
    ("array_expression", NormalizedKind::CollectionLiteral),
    ("tuple_expression", NormalizedKind::CollectionLiteral),
    ("for_expression", NormalizedKind::ForLoop),
    ("while_expression", NormalizedKind::WhileLoop),
    ("loop_expression", NormalizedKind::Loop),
    // Every Rust scope-forming statement list is a `block`: function bodies,
    // loop and conditional bodies, and bare blocks in expression position.
    ("block", NormalizedKind::Block),
];

/// Remove transparent receiver parentheses without descending recursively.
pub fn rust_receiver_operand(mut node: Node<'_>) -> Node<'_> {
    while node.kind() == "parenthesized_expression" {
        let Some(operand) = node.named_child(0) else {
            return node;
        };
        node = operand;
    }
    node
}

// Attribute wrappers carry syntax ownership but are not separate semantic
// values. Role targets must name the payload that becomes a structural fact.
fn attach_rust_role<'tree>(
    sink: &mut RoleSink<'_>,
    role: Role,
    target: Node<'tree>,
    name_of: impl FnOnce(Node<'tree>) -> Option<Node<'tree>>,
) {
    attach_role_with_derived_name(sink, role, unwrap_attributes(target), name_of);
}

pub fn expression_name_node<'tree>(expression: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = unwrap_attributes(expression);
    loop {
        current = unwrap_attributes(current);
        match current.kind() {
            "identifier" | "field_identifier" | "type_identifier" | "self" | "super" | "crate" => {
                return Some(current);
            }
            "scoped_identifier" | "scoped_type_identifier" | "struct_expression" => {
                current = current.child_by_field_name("name")?
            }
            "generic_type" => current = current.child_by_field_name("type")?,
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
        attach_rust_role(sink, Role::Receiver, path, expression_name_node);
    }
}

/// Publish the written generic arguments attached to a call's callee path.
/// Rust uses `generic_function` for `make::<T>()` and `generic_type` for the
/// turbofish in a scoped path such as `Wrapper::<T>::new()`. The path fields
/// are followed iteratively so nested qualified names do not require a
/// source-text parser or recursive Rust calls.
fn attach_call_type_arguments(sink: &mut RoleSink<'_>, function: Node<'_>) {
    let mut pending = vec![function];
    while let Some(node) = pending.pop() {
        match node.kind() {
            "generic_function" | "generic_type" => {
                if let Some(arguments) = node.child_by_field_name("type_arguments") {
                    for index in 0..arguments.named_child_count() {
                        if !sink.should_continue() {
                            return;
                        }
                        let Some(argument) = arguments.named_child(index) else {
                            continue;
                        };
                        let argument = unwrap_attributes(argument);
                        sink.role_maybe_named(
                            Role::TypeArguments,
                            argument,
                            expression_name_node(argument),
                        );
                    }
                }
                let field = if node.kind() == "generic_function" {
                    "function"
                } else {
                    "type"
                };
                if let Some(inner) = node.child_by_field_name(field) {
                    pending.push(inner);
                }
            }
            "scoped_identifier" | "scoped_type_identifier" => {
                if let Some(path) = node.child_by_field_name("path") {
                    pending.push(path);
                }
            }
            _ => {}
        }
    }
}

pub fn call_function_target(mut function: Node<'_>) -> Node<'_> {
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

fn is_qualified_task_spawn(node: Node<'_>, source: &str) -> bool {
    if node.kind() != "call_expression" {
        return false;
    }
    let Some(function) = node.child_by_field_name("function") else {
        return false;
    };
    let function = call_function_target(function);
    if !matches!(
        function.kind(),
        "scoped_identifier" | "scoped_type_identifier"
    ) {
        return false;
    }
    let segments = if crate::graph_support::rust_path_is_leading_absolute(function) {
        let Some(segments) = crate::graph_support::rust_path_segments(function) else {
            return false;
        };
        segments
    } else {
        linear_chain_tokens(
            function,
            RUST_PATH_CHAIN,
            &["generic_type", "generic_function"],
        )
    };
    RUST_TASK_SPAWN_PATHS.iter().any(|expected| {
        segments.len() == expected.len()
            && segments
                .iter()
                .zip(expected.iter())
                .all(|(segment, expected)| {
                    segment
                        .utf8_text(source.as_bytes())
                        .is_ok_and(|actual| actual == *expected)
                })
    })
}

fn attach_use_module(sink: &mut RoleSink<'_>, node: Node<'_>) {
    match node.kind() {
        "identifier" | "scoped_identifier" | "self" | "super" | "crate" => {
            attach_rust_role(sink, Role::Module, node, expression_name_node);
        }
        "use_as_clause" => {
            if let Some(alias) = node.child_by_field_name("alias") {
                attach_rust_role(sink, Role::Module, alias, expression_name_node);
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

/// Attach `decorators` edges for the outer attributes written above `item`.
///
/// Tree-sitter-rust 0.24 stores an item's outer attributes in a grammar-owned
/// `attributes` group. Inner `#![...]` attributes remain separate nodes that
/// configure the enclosing module rather than the item.
fn attach_outer_attribute_decorators(sink: &mut RoleSink<'_>, item: Node<'_>) {
    for attribute_item in outer_attributes(item) {
        if let Some(attribute) = first_named_child(attribute_item) {
            attach_rust_role(sink, Role::Decorator, attribute, first_named_child);
        }
    }
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
pub(crate) fn rust_occurrence_role(node: Node<'_>) -> Option<OccurrenceRole> {
    if !matches!(
        node.kind(),
        "identifier" | "field_identifier" | "type_identifier"
    ) {
        return None;
    }

    let mut anchor = node;
    let mut parent = anchor.parent()?;
    // Lifetimes and loop labels have their own Rust namespaces. They are
    // neither value nor type references in the source occurrence inventory.
    if parent.kind() == "lifetime" {
        return None;
    }
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
        "field_pattern" if field == Some("name") => OccurrenceRole::MemberPosition,
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
        "field_initializer" if field == Some("field") => OccurrenceRole::MemberPosition,
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
            // `if let Some(x) = value { .. }` binds in the consequence only;
            // the else arm can resolve the same spelling to an outer local.
            let owner = nearest_ancestor(form, |kind| {
                matches!(kind, "if_expression" | "while_expression")
            })?;
            let body = match owner.kind() {
                "if_expression" => owner.child_by_field_name("consequence"),
                "while_expression" => owner.child_by_field_name("body"),
                _ => None,
            }?;
            Some(BindingActivation {
                kind: BindingKind::PatternBinder,
                hoisting: HoistingClass::DeclaredHead,
                activation: node_range(body),
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

    fn generator_construct(
        &self,
        node: Node<'_>,
        _kind: NormalizedKind,
        _source: &str,
    ) -> Option<&'static str> {
        (node.kind() == "macro_invocation").then_some("rust_macro_invocation")
    }

    fn supports_boolean_literal_value(&self) -> bool {
        true
    }

    fn supports_async_callable_value(&self) -> bool {
        true
    }

    fn supports_string_literal_value(&self) -> bool {
        true
    }

    fn string_literal_value_may_be_absent(&self, node: Node<'_>, source: &str) -> bool {
        match node.kind() {
            // The released Rust grammar represents cooked byte and C strings
            // (`b"..."`, `c"..."`) with the ordinary string-literal node and
            // raw byte and C strings (`br"..."`, `cr"..."`) with the raw-string
            // node. Their prefix is a value classification after the grammar
            // has selected the literal node; none of them has a decoded UTF-8
            // string value. Only an unprefixed spelling is a `str`.
            "string_literal" => {
                let Some(spelling) = source.get(node.start_byte()..node.end_byte()) else {
                    return false;
                };
                !spelling.starts_with('"')
                    || node.has_error()
                    || crate::cargo_routes::rust_cooked_string_literal_has_invalid_escape(
                        node, source,
                    )
            }
            "raw_string_literal" => {
                let Some(spelling) = source.get(node.start_byte()..node.end_byte()) else {
                    return false;
                };
                !spelling.starts_with('r') || node.has_error()
            }
            _ => false,
        }
    }

    fn string_literal_value(&self, node: Node<'_>, source: &str) -> Option<String> {
        match node.kind() {
            "string_literal" | "raw_string_literal" => {
                crate::cargo_routes::rust_static_string_literal(node, source)
            }
            // Rust normalizes character literals under the existing
            // string_literal kind for cross-language query compatibility, but
            // their token has no child structure from which this string-value
            // axis can be established. They remain selectable by kind/text.
            "char_literal" => None,
            _ => None,
        }
    }
    fn kind_table(&self) -> &'static [(&'static str, NormalizedKind)] {
        RUST_KIND_TABLE
    }

    fn call_site_facts(
        &self,
        node: Node<'_>,
        source: &str,
        _context: &CallSiteContext,
    ) -> Option<CallSiteFacts> {
        if node.kind() != "macro_invocation" {
            return None;
        }
        let coverage = if rust_modeled_sink_macro_argument_count(node, source).is_some()
            && crate::format_args::rust_format_macro_arguments(node, source).is_ok()
        {
            CallShapeCoverage::ExactMacroDerived
        } else {
            CallShapeCoverage::UnknownMacroDerived
        };
        Some(CallSiteFacts::of_coverage(coverage))
    }

    fn refine_kind(
        &self,
        node: Node<'_>,
        kind: NormalizedKind,
        _enclosing: Option<NormalizedKind>,
        source: &str,
        _context: &CallSiteContext,
    ) -> NormalizedKind {
        if kind == NormalizedKind::Call && is_qualified_task_spawn(node, source) {
            NormalizedKind::ConcurrentSpawn
        } else if kind == NormalizedKind::Identifier
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

    fn async_callable_value(&self, node: Node<'_>) -> Option<bool> {
        match node.kind() {
            "function_item" | "function_signature_item" => {
                let mut cursor = node.walk();
                let modifiers = node
                    .children(&mut cursor)
                    .find(|child| child.kind() == "function_modifiers");
                Some(modifiers.is_some_and(|modifiers| {
                    let mut cursor = modifiers.walk();
                    modifiers
                        .children(&mut cursor)
                        .any(|modifier| modifier.kind() == "async")
                }))
            }
            "closure_expression" => {
                let mut cursor = node.walk();
                Some(
                    node.children(&mut cursor)
                        .any(|child| child.kind() == "async"),
                )
            }
            "async_block" => Some(true),
            _ => None,
        }
    }

    fn supports_kind(&self, kind: NormalizedKind) -> bool {
        brokk_bifrost_core::analyzer::structural::spec::supports_kind_from_table(
            kind,
            &[
                NormalizedKind::Method,
                NormalizedKind::SyntaxError,
                NormalizedKind::ConcurrentSpawn,
            ],
            self.kind_table(),
        )
    }

    fn supports_role(&self, role: Role) -> bool {
        brokk_bifrost_core::analyzer::structural::spec::supports_role_without_kwarg(role)
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
        qualified_path_chain_root(token, RUST_PATH_CHAIN)
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

    /// Rust consumes an import without spelling its name in one way: a `use`
    /// can name a trait, and a trait is brought into scope for its *methods*,
    /// so `use std::io::Write;` followed by `file.write_all(..)` spells the
    /// method and never the trait. Every kind listed here is one whose uses
    /// spell the imported name.
    ///
    /// An attributed declaration is unknown rather than ordinary:
    /// [`outer_attributes`] reads the grammar's grouped layout only, a
    /// procedural macro declaration looks like a function, and an attribute
    /// macro can transform the declaration that follows it. Neither is a
    /// source-backed proof without expansion. A trait, a module, a `use` alias
    /// and every other form are unknown here for the same reason: absence of a
    /// positive fact, not a negative one.
    fn declaration_ambient_use(&self, node: Node<'_>) -> Option<AmbientUseRole> {
        if outer_attributes(node).next().is_some() {
            return None;
        }
        matches!(
            node.kind(),
            "struct_item"
                | "enum_item"
                | "union_item"
                | "function_item"
                | "const_item"
                | "static_item"
        )
        .then_some(AmbientUseRole::NotAmbient)
    }

    fn indirection_relation(
        &self,
        token: Node<'_>,
        _source: &str,
        _surface: &CuratedExportSurface,
    ) -> Option<RouteHopKind> {
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
                attach_outer_attribute_decorators(sink, node);
            }
            NormalizedKind::Call | NormalizedKind::ConcurrentSpawn => {
                if node.kind() == "macro_invocation" {
                    let source = sink.source();
                    if let Some(macro_name) = node.child_by_field_name("macro") {
                        attach_terminal_callee(sink, macro_name, expression_name_node(macro_name));
                        attach_scoped_receiver(sink, macro_name);
                    }
                    let modeled_sink = rust_modeled_sink_macro_argument_count(node, source)
                        .and_then(|argument_count| {
                            let arguments =
                                crate::format_args::rust_format_macro_arguments(node, source)
                                    .ok()?;
                            Some((argument_count, arguments))
                        });
                    if let Some((argument_count, arguments)) = modeled_sink {
                        for index in 0..argument_count {
                            if !sink.should_continue() {
                                break;
                            }
                            // Formal arguments past the written ones have no source node of
                            // their own, so they stay on the invocation.
                            let target = arguments.get(index).map_or(node, |argument| {
                                node.descendant_for_byte_range(
                                    argument.range.start_byte,
                                    argument.range.end_byte,
                                )
                                .expect("a format argument range lies inside its macro invocation")
                            });
                            sink.argument_maybe_named(target, None, false);
                        }
                    } else if let Some(arguments) = macro_arguments(node) {
                        for index in 0..arguments.named_child_count() {
                            if !sink.should_continue() {
                                break;
                            }
                            let Some(argument) = arguments.named_child(index) else {
                                continue;
                            };
                            if matches!(argument.kind(), "line_comment" | "block_comment") {
                                continue;
                            }
                            let argument = unwrap_attributes(argument);
                            sink.argument_maybe_named(
                                argument,
                                expression_name_node(argument),
                                false,
                            );
                        }
                    }
                } else if let Some(function) = node.child_by_field_name("function") {
                    attach_terminal_callee(sink, function, expression_name_node(function));
                    attach_call_type_arguments(sink, function);
                    let target = call_function_target(function);
                    if target.kind() == "field_expression"
                        && let Some(value) = target.child_by_field_name("value")
                    {
                        attach_rust_role(sink, Role::Receiver, value, expression_name_node);
                    }
                    attach_scoped_receiver(sink, target);
                }
                if node.kind() != "macro_invocation"
                    && let Some(arguments) = node.child_by_field_name("arguments")
                {
                    for index in 0..arguments.named_child_count() {
                        if !sink.should_continue() {
                            break;
                        }
                        let Some(argument) = arguments.named_child(index) else {
                            continue;
                        };
                        if matches!(argument.kind(), "line_comment" | "block_comment") {
                            continue;
                        }
                        let argument = unwrap_attributes(argument);
                        sink.argument_maybe_named(argument, expression_name_node(argument), false);
                    }
                }
            }
            NormalizedKind::FieldAccess => {
                if let Some(field) = node.child_by_field_name("field") {
                    sink.set_name(field);
                    sink.role_named(Role::Field, field, field);
                }
                if let Some(value) = node.child_by_field_name("value") {
                    attach_rust_role(sink, Role::Object, value, expression_name_node);
                }
            }
            NormalizedKind::Function
            | NormalizedKind::Method
            | NormalizedKind::Class
            | NormalizedKind::Module
            | NormalizedKind::Declaration => {
                if let Some(name) = node.child_by_field_name("name") {
                    sink.set_name(name);
                }
                attach_outer_attribute_decorators(sink, node);
            }
            NormalizedKind::Parameter => {
                if let Some(name) = rust_parameter_label_node(node) {
                    sink.set_name(name);
                }
            }
            NormalizedKind::Assignment => match node.kind() {
                "const_item" | "static_item" => {
                    attach_outer_attribute_decorators(sink, node);
                    if let Some(name) = node.child_by_field_name("name") {
                        sink.role_named(Role::Left, name, name);
                        sink.set_name(name);
                    }
                    if let Some(value) = node.child_by_field_name("value") {
                        attach_rust_role(sink, Role::Right, value, expression_name_node);
                    }
                }
                "let_declaration" => {
                    if let Some(pattern) = node.child_by_field_name("pattern") {
                        attach_rust_role(sink, Role::Left, pattern, expression_name_node);
                        if let Some(name) = expression_name_node(pattern) {
                            sink.set_name(name);
                        }
                    }
                    if let Some(value) = node.child_by_field_name("value") {
                        attach_rust_role(sink, Role::Right, value, expression_name_node);
                    }
                }
                "assignment_expression" | "compound_assignment_expr" => {
                    if let Some(left) = node.child_by_field_name("left") {
                        attach_rust_role(sink, Role::Left, left, expression_name_node);
                    }
                    if let Some(right) = node.child_by_field_name("right") {
                        attach_rust_role(sink, Role::Right, right, expression_name_node);
                    }
                }
                _ => {}
            },
            NormalizedKind::Import => {
                attach_outer_attribute_decorators(sink, node);
                if let Some(argument) = node.child_by_field_name("argument") {
                    attach_use_module(sink, argument);
                }
            }
            NormalizedKind::Identifier => match expression_name_node(node) {
                Some(name) => sink.set_name(name),
                None => sink.set_name(node),
            },
            NormalizedKind::ForLoop => {
                if let Some(value) = node.child_by_field_name("value") {
                    attach_rust_role(sink, Role::Iterable, value, expression_name_node);
                }
            }
            NormalizedKind::CollectionLiteral => {
                // `[x; n]` repeat syntax spells a length operand, not an
                // element list, and its run-time size can be anything, so it
                // deliberately gets no element edges: with zero `elements`
                // edges it can never satisfy an at-least-one-element arity
                // bound, which is how the origin-shape assert asks.
                if node.child_by_field_name("length").is_some() {
                    return;
                }
                for index in 0..node.named_child_count() {
                    let Some(child) = node.named_child(index) else {
                        continue;
                    };
                    if matches!(
                        child.kind(),
                        "attributes" | "line_comment" | "block_comment"
                    ) {
                        continue;
                    }
                    attach_rust_role(sink, Role::Element, child, expression_name_node);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
use brokk_bifrost_core::analyzer::source_facts::PrimarySourceFactCollector;
#[cfg(test)]
use brokk_bifrost_core::analyzer::tree_walk::ParentIndex;

#[test]
fn collection_elements_exclude_attributes_and_target_expression_payloads() {
    for source in [
        "fn f() { let values = [#[Marker] first(), second()]; }",
        "fn f() { let values = (#[Marker] first(), second()); }",
    ] {
        let tree = crate::lexical_scope::parse_rust_tree(source).expect("Rust tree");
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );
        let mut facts = PrimarySourceFactCollector::new(source);
        let mut collection = None;
        let mut calls = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if matches!(node.kind(), "array_expression" | "tuple_expression") {
                collection = Some(node);
            }
            if node.kind() == "call_expression" {
                calls.push((node.start_byte(), node.id()));
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        calls.sort_unstable();
        let parents = ParentIndex::new(tree.root_node());
        let mut sink = RoleSink::new(source, &mut facts, 32, None, &parents);
        RUST_STRUCTURAL_SPEC.extract(
            collection.unwrap(),
            NormalizedKind::CollectionLiteral,
            &mut sink,
        );
        let (_, roles, _, stop) = sink.into_parts();
        assert_eq!(stop, None);
        assert_eq!(
            roles.iter().map(|role| role.role).collect::<Vec<_>>(),
            [Role::Element, Role::Element]
        );
        assert_eq!(
            roles
                .iter()
                .map(
                    |role| &source[facts.occurrence(role.occurrence).range.start_byte
                        ..facts.occurrence(role.occurrence).range.end_byte]
                )
                .collect::<Vec<_>>(),
            ["first()", "second()"]
        );
        assert_eq!(
            roles
                .iter()
                .map(|role| role.target_node)
                .collect::<Vec<_>>(),
            calls.into_iter().map(|(_, id)| id).collect::<Vec<_>>()
        );
    }
}

#[cfg(test)]
mod binding_activation_tests {
    use super::{nearest_ancestor, node_range, rust_binding_activation};
    use brokk_bifrost_core::analyzer::Range;
    use brokk_bifrost_test_macros::hardwon;
    use tree_sitter::Node;

    fn nodes_of_kind<'tree>(root: Node<'tree>, kind: &str) -> Vec<Node<'tree>> {
        let mut found = Vec::new();
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if node.kind() == kind {
                found.push(node);
            }
            for index in (0..node.named_child_count()).rev() {
                stack.push(node.named_child(index).expect("named child"));
            }
        }
        found.sort_unstable_by_key(|node| node.start_byte());
        found
    }

    #[test]
    #[hardwon("eea67f995994: while-let pattern binders use the grammar body field")]
    fn let_condition_activation_uses_owner_specific_body_field() {
        let source = concat!(
            "fn run(first: Option<i32>, second: Option<i32>) {\n",
            "    if let Some(value) = first {\n",
            "        let _ = value;\n",
            "    } else {\n",
            "        let _ = first;\n",
            "    }\n",
            "    while let Some(value) = second {\n",
            "        let _ = value;\n",
            "        break;\n",
            "    }\n",
            "}\n",
        );
        let tree = crate::lexical_scope::parse_rust_tree(source).expect("Rust tree");
        let root = tree.root_node();
        assert!(!root.has_error(), "{}", root.to_sexp());
        let scope = Range {
            start_byte: root.start_byte(),
            end_byte: root.end_byte(),
            start_line: root.start_position().row + 1,
            end_line: root.end_position().row + 1,
        };
        let conditions = nodes_of_kind(root, "let_condition");
        assert_eq!(conditions.len(), 2);

        for condition in conditions {
            let owner = nearest_ancestor(condition, |kind| {
                matches!(kind, "if_expression" | "while_expression")
            })
            .expect("let condition owner");
            let body = match owner.kind() {
                "if_expression" => owner
                    .child_by_field_name("consequence")
                    .expect("if consequence field"),
                "while_expression" => owner.child_by_field_name("body").expect("while body field"),
                _ => unreachable!("unexpected let condition owner: {}", owner.kind()),
            };
            let pattern = condition
                .child_by_field_name("pattern")
                .expect("let condition pattern");
            let binder = nodes_of_kind(pattern, "identifier")
                .into_iter()
                .next()
                .expect("pattern binder");

            let activation = rust_binding_activation(binder, scope).expect("binding activation");
            assert_eq!(activation.activation, node_range(body));
        }
    }
}

#[cfg(test)]
mod parameter_tests {
    use super::*;
    use crate::test_helpers::{occurrence_text, parse_rust_fixture};

    #[test]
    fn parameters_are_named_structural_facts() {
        let source = "fn receive(password: &str) {}\n";
        let parsed = parse_rust_fixture(source);
        let source_facts = parsed.source_facts.as_ref().expect("Rust source facts");
        let parameter = source_facts
            .structural
            .nodes()
            .iter()
            .find(|node| node.kind == NormalizedKind::Parameter)
            .expect("parameter structural fact");

        assert_eq!(
            occurrence_text(source, &source_facts.occurrences, parameter.occurrence),
            "password: &str"
        );
        let name = parameter.name.expect("parameter name");
        assert_eq!(
            occurrence_text(source, &source_facts.occurrences, name),
            "password"
        );
    }
}

#[cfg(test)]
mod literal_tests {
    use super::*;
    use crate::test_helpers::{occurrence_text, parse_rust_fixture};

    #[test]
    fn byte_strings_are_string_literal_facts() {
        let source = "fn key() { let value = b\"0123456789abcdef\"; }\n";
        let parsed = parse_rust_fixture(source);
        let source_facts = parsed.source_facts.as_ref().expect("Rust source facts");
        let literal = source_facts
            .structural
            .nodes()
            .iter()
            .find(|node| node.kind == NormalizedKind::StringLiteral)
            .expect("byte-string structural fact");

        assert_eq!(
            occurrence_text(source, &source_facts.occurrences, literal.occurrence),
            "b\"0123456789abcdef\""
        );
    }

    #[test]
    fn byte_and_c_string_values_are_absent_from_string_facts() {
        let source = concat!(
            "fn key() {\n",
            "    let cooked = b\"ok\";\n",
            "    let raw = br\"x\";\n",
            "    let c_cooked = c\"main\";\n",
            "    let c_raw = cr\"y\";\n",
            "    let text = \"ok\";\n",
            "}\n",
        );
        let parsed = parse_rust_fixture(source);
        let source_facts = parsed.source_facts.as_ref().expect("Rust source facts");
        let value_for = |spelling: &str| {
            source_facts
                .structural
                .nodes()
                .iter()
                .find(|node| {
                    node.kind == NormalizedKind::StringLiteral
                        && occurrence_text(source, &source_facts.occurrences, node.occurrence)
                            == spelling
                })
                .map(|node| node.string_value.clone())
                .unwrap_or_else(|| panic!("missing string-literal fact for {spelling}"))
        };

        assert_eq!(value_for("b\"ok\""), None);
        assert_eq!(value_for("br\"x\""), None);
        assert_eq!(value_for("c\"main\""), None);
        assert_eq!(value_for("cr\"y\""), None);
        assert_eq!(value_for("\"ok\""), Some("ok".to_owned()));
    }

    #[test]
    fn invalid_string_literals_keep_structural_facts_without_values() {
        let source = r#"
fn literals() {
    let emoji = "\💩";
    let symbol = "\●";
    let character = 'a';
    let raw = r"\💩";
    let valid = "\u{1F4A9}";
    let invalid_char = '\💩';
    let unicode = "\u{_0000}";
}
"#;
        let parsed = parse_rust_fixture(source);
        let source_facts = parsed.source_facts.as_ref().expect("Rust source facts");
        let value_for = |spelling: &str| {
            source_facts
                .structural
                .nodes()
                .iter()
                .find(|node| {
                    node.kind == NormalizedKind::StringLiteral
                        && occurrence_text(source, &source_facts.occurrences, node.occurrence)
                            == spelling
                })
                .map(|node| node.string_value.clone())
                .unwrap_or_else(|| panic!("missing string-literal fact for {spelling}"))
        };

        assert_eq!(value_for(r#""\💩""#), None);
        assert_eq!(value_for(r#""\●""#), None);
        assert_eq!(value_for("'a'"), None);
        assert_eq!(value_for(r#"r"\💩""#), Some("\\💩".to_owned()));
        assert_eq!(value_for(r#""\u{1F4A9}""#), Some("💩".to_owned()));
    }
}

#[cfg(test)]
mod type_argument_role_tests {
    use super::*;
    use brokk_bifrost_core::analyzer::source_facts::PrimarySourceFactCollector;
    use brokk_bifrost_core::analyzer::tree_walk::ParentIndex;

    #[test]
    fn calls_publish_generic_function_and_scoped_path_type_arguments() {
        let source = concat!(
            "struct Wrapper<T>(core::marker::PhantomData<T>);\n",
            "impl<T> Wrapper<T> { fn new() -> Self { loop {} } }\n",
            "fn make<T>() {}\n",
            "fn use_values() {\n",
            "    make::<u8>();\n",
            "    Wrapper::<des::Des>::new();\n",
            "}\n",
        );
        let tree = crate::lexical_scope::parse_rust_tree(source).expect("Rust tree");
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );
        let mut calls = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "call_expression" {
                calls.push(node);
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        calls.sort_unstable_by_key(|node| node.start_byte());
        assert_eq!(calls.len(), 2);

        let mut argument_texts = Vec::new();
        for call in calls {
            let mut facts = PrimarySourceFactCollector::new(source);
            let parents = ParentIndex::new(tree.root_node());
            let mut sink = RoleSink::new(source, &mut facts, 32, None, &parents);
            RUST_STRUCTURAL_SPEC.extract(call, NormalizedKind::Call, &mut sink);
            let (_, roles, _, stop) = sink.into_parts();
            assert_eq!(stop, None);
            let texts = roles
                .iter()
                .filter(|role| role.role == Role::TypeArguments)
                .map(|role| {
                    let range = facts.occurrence(role.occurrence).range;
                    source[range.start_byte..range.end_byte].to_owned()
                })
                .collect::<Vec<_>>();
            argument_texts.push(texts);
        }

        assert_eq!(argument_texts, vec![vec!["u8"], vec!["des::Des"]]);
    }
}

#[cfg(test)]
mod result_use_tests {
    use super::{RustCallResultUseIndex, rust_call_result_use};
    use brokk_bifrost_core::analyzer::structural::result_use::{
        CallResultUse, IntentionalDiscardKind,
    };
    use tree_sitter::Parser;

    fn tree(source: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust grammar");
        parser.parse(source, None).expect("Rust tree")
    }

    fn call_nodes(tree: &tree_sitter::Tree) -> Vec<tree_sitter::Node<'_>> {
        let mut calls = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "call_expression" {
                calls.push(node);
            }
            for index in (0..node.named_child_count()).rev() {
                stack.push(node.named_child(index).expect("named child"));
            }
        }
        calls.sort_by_key(|node| node.start_byte());
        calls
    }

    #[test]
    fn statement_and_explicit_drop_forms_are_distinct_from_consumed_contexts() {
        let source = concat!(
            "fn sink(_: i32) {}\n",
            "fn f() -> i32 { 1 }\n",
            "fn run() -> i32 {\n",
            "    f();\n",
            "    let _ = f();\n",
            "    drop(f());\n",
            "    sink(f());\n",
            "    return f();\n",
            "}\n",
        );
        let tree = tree(source);
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );
        let calls = call_nodes(&tree);
        assert_eq!(calls.len(), 7, "{}", tree.root_node().to_sexp());
        assert_eq!(
            rust_call_result_use(calls[0], source).for_port(0),
            CallResultUse::Discarded
        );
        assert!(matches!(
            rust_call_result_use(calls[1], source).for_port(0),
            CallResultUse::IntentionalDiscard(IntentionalDiscardKind::RustLetUnderscore)
        ));
        assert!(matches!(
            rust_call_result_use(calls[2], source).for_port(0),
            CallResultUse::Discarded
        ));
        assert_eq!(
            rust_call_result_use(calls[3], source).for_port(0),
            CallResultUse::IntentionalDiscard(IntentionalDiscardKind::RustDrop)
        );
        assert_eq!(
            rust_call_result_use(calls[4], source).for_port(0),
            CallResultUse::Discarded
        );
        assert_eq!(
            rust_call_result_use(calls[5], source).for_port(0),
            CallResultUse::Consumed
        );
        assert_eq!(
            rust_call_result_use(calls[6], source).for_port(0),
            CallResultUse::Consumed
        );
    }

    #[test]
    fn closure_tail_and_recovered_syntax_stay_open() {
        let closure_source = "fn f() -> i32 { 1 }\nfn run() { let _closure = || f(); }\n";
        let closure_tree = tree(closure_source);
        assert!(!closure_tree.root_node().has_error());
        let calls = call_nodes(&closure_tree);
        assert_eq!(
            rust_call_result_use(calls[0], closure_source).for_port(0),
            CallResultUse::Open(
                brokk_bifrost_core::analyzer::structural::result_use::CallResultUseOpenReason::DeferredContext
            )
        );
        let recovered_source = "fn f() -> i32 { 1 }\nfn run() { let _ = f(, 1); }\n";
        let recovered_tree = tree(recovered_source);
        assert!(recovered_tree.root_node().has_error());
        let recovered_calls = call_nodes(&recovered_tree);
        assert!(matches!(
            rust_call_result_use(recovered_calls[0], recovered_source).for_port(0),
            CallResultUse::Open(_)
        ));
    }

    #[test]
    fn exact_index_uses_the_call_span() {
        let source = "fn f() -> i32 { 1 }\nfn run() { f(); }\n";
        let tree = tree(source);
        let calls = call_nodes(&tree);
        let index = RustCallResultUseIndex::new(tree.root_node(), source);
        assert_eq!(
            index
                .at_span(calls[0].start_byte(), calls[0].end_byte())
                .expect("indexed call")
                .for_port(0),
            CallResultUse::Discarded
        );
        assert!(index.at_span(source.len(), source.len()).is_err());
    }
}
