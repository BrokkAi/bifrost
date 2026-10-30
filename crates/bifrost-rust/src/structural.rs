//! Rust structural spec for `query_code`.

use brokk_bifrost_core::analyzer::model::AmbientUseRole;
use brokk_bifrost_core::analyzer::structural::adapter_helpers::{
    CalleeSpineStep, attach_role_with_derived_name, attach_terminal_callee, field_name_in_parent,
    first_named_child, is_field_of, nearest_ancestor, node_range, terminal_callee_leaf,
};
use brokk_bifrost_core::analyzer::structural::adapter_helpers::{
    linear_chain_tokens, qualified_path_chain_root, spelled_generic_arity,
};
use brokk_bifrost_core::analyzer::structural::callable::{
    CallShapeCoverage, CallSiteContext, CallSiteFacts, CalleeProvenance, CalleeProvenanceFact,
    CalleeSupplier, CalleeTypeShape,
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

fn rust_modeled_sink_macro_layout(
    node: Node<'_>,
    source: &str,
) -> Option<crate::format_args::RustMacroRuntimeLayout> {
    crate::format_args::rust_macro_runtime_layout_for_path(
        node.child_by_field_name("macro")?,
        source,
    )
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
    ("trait_alias", NormalizedKind::Class),
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

/// Grammar steps for the shared call-callee spine. A value expression has no step.
pub fn callee_spine_step(kind: &str) -> Option<CalleeSpineStep> {
    use CalleeSpineStep::{Field, Name};
    match kind {
        "identifier" | "field_identifier" | "type_identifier" => Some(Name),
        "field_expression" => Some(Field("field")),
        "scoped_identifier" | "scoped_type_identifier" => Some(Field("name")),
        "generic_function" => Some(Field("function")),
        _ => None,
    }
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

/// Return the receiver and named member when a Rust call uses method syntax.
/// Generic call wrappers are transparent, but parentheses are not: `(value.field)()`
/// calls a computed field value rather than spelling a method call.
pub fn rust_method_call_parts(function: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    let function = call_function_target(function);
    if function.kind() != "field_expression" {
        return None;
    }
    let member = function.child_by_field_name("field")?;
    (member.kind() == "field_identifier")
        .then(|| function.child_by_field_name("value"))
        .flatten()
        .map(|receiver| (receiver, member))
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
    let mut pending = vec![node];
    while let Some(node) = pending.pop() {
        match node.kind() {
            "identifier" | "scoped_identifier" | "self" | "super" | "crate" => {
                attach_rust_role(sink, Role::Module, node, expression_name_node);
            }
            "use_as_clause" => {
                if let Some(alias) = node.child_by_field_name("alias") {
                    attach_rust_role(sink, Role::Module, alias, expression_name_node);
                } else if let Some(first) = first_named_child(node) {
                    pending.push(first);
                }
            }
            "scoped_use_list" => {
                if let Some(list) = node.child_by_field_name("list") {
                    pending.push(list);
                }
            }
            _ => {
                // Reverse the push order to preserve the recursive walk's output.
                for index in (0..node.named_child_count()).rev() {
                    if let Some(child) = node.named_child(index) {
                        pending.push(child);
                    }
                }
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
    "trait_alias",
    "type_item",
    "const_item",
    "static_item",
    "mod_item",
    "macro_definition",
    "decl_macro",
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

// Provenance depends only on this blob's syntax, unlike dispatch or models.
// Keep it on the persisted structural node array alongside other call facts:
// every call-shape read already loads that node, avoiding another join or a
// query-time reparse. STRUCTURAL_FACTS_VERSION invalidates old array layouts.
fn rust_callee_provenance<E>(
    call: Node<'_>,
    source: &str,
    charge: &mut dyn FnMut(usize) -> Result<(), E>,
) -> Result<CalleeProvenanceFact, E> {
    let Some(function) = call.child_by_field_name("function") else {
        return Ok(rust_unknown_callee_provenance());
    };
    let method_receiver = rust_method_call_parts(function);
    let mut callee = rust_callee_value(
        method_receiver.map_or(function, |(receiver, _)| receiver),
        charge,
    )?;
    // A local alias (`let f = init;`) carries the provenance of the binding
    // its initializer selects. Each hop resolves the initializer at its own
    // position, so shadowing on either side keeps the nearest binding, and
    // `let f = f;` reads the binding before it.
    let mut aliases: Vec<(Node<'_>, Node<'_>)> = Vec::new();
    let binding = loop {
        charge(1)?;
        if matches!(callee.kind(), "scoped_identifier" | "generic_function")
            || (callee.kind() == "field_expression" && method_receiver.is_some())
        {
            break None;
        }
        // A callable stored in a field needs value-flow provenance. In a method
        // call the receiver was selected above, so nominal receivers still carry
        // their own parameter type evidence.
        if !matches!(callee.kind(), "identifier" | "self") {
            return Ok(rust_unknown_callee_provenance());
        }
        let Some(binding) =
            crate::lexical_scope::rust_value_binding_at_bounded(callee, source, charge)?
        else {
            break None;
        };
        if let Some((alias, _)) = aliases.last() {
            // A binding is visible only after its own initializer, so every
            // hop moves to an earlier binding and the chain terminates.
            debug_assert!(binding.start_byte() < alias.start_byte());
        }
        if binding.kind() == "let_declaration"
            && binding
                .child_by_field_name("pattern")
                .is_some_and(|pattern| pattern.kind() == "identifier")
            && let Some(value) = binding.child_by_field_name("value")
            && value.kind() != "closure_expression"
        {
            aliases.push((binding, callee));
            callee = rust_callee_value(value, charge)?;
            continue;
        }
        break Some(binding);
    };
    let fact = rust_binding_callee_provenance(callee, binding, source, charge)?;
    if fact.provenance == CalleeProvenance::Unknown || aliases.is_empty() {
        return Ok(fact);
    }
    // A write to an alias or to its source can replace the value between the
    // initializer and the call, including from a later loop iteration.
    aliases.extend(binding.map(|binding| (binding, callee)));
    for (binding, occurrence) in aliases {
        if rust_binding_may_be_written(binding, occurrence, source, charge)? {
            return Ok(rust_unknown_callee_provenance());
        }
    }
    Ok(fact)
}

fn rust_unknown_callee_provenance() -> CalleeProvenanceFact {
    CalleeProvenanceFact {
        provenance: CalleeProvenance::Unknown,
        supplier: None,
        shape: CalleeTypeShape::Unknown,
        bounds: Vec::new(),
    }
}

/// The value a callee or alias initializer reads, through parentheses,
/// borrows and dereferences.
fn rust_callee_value<'tree, E>(
    mut value: Node<'tree>,
    charge: &mut dyn FnMut(usize) -> Result<(), E>,
) -> Result<Node<'tree>, E> {
    loop {
        charge(1)?;
        let inner = match value.kind() {
            "parenthesized_expression" => value.named_child(0),
            "reference_expression" => value.child_by_field_name("value"),
            "unary_expression"
                if value
                    .child(0)
                    .is_some_and(|operator| operator.kind() == "*") =>
            {
                value.named_child(0)
            }
            _ => None,
        };
        let Some(inner) = inner else {
            return Ok(value);
        };
        value = inner;
    }
}

/// Whether any use of a value binding may replace the value it holds.
/// `occurrence` is a use that selected the binding and supplies its spelling.
///
/// Rust writes an initialized binding only when it is declared `mut`, so an
/// immutable binding needs no scan. A use of a mutable one in its scope is
/// a write when it may assign, mutably borrow or autoref it, and the scan
/// re-resolves each such use so a shadowing binding's writes do not count.
fn rust_binding_may_be_written<E>(
    binding: Node<'_>,
    occurrence: Node<'_>,
    source: &str,
    charge: &mut dyn FnMut(usize) -> Result<(), E>,
) -> Result<bool, E> {
    let mutable = match binding.kind() {
        // `&mut self` borrows mutably; only `mut self` is a mutable binding.
        "self_parameter" => binding
            .child(0)
            .is_some_and(|first| first.kind() == "mutable_specifier"),
        "mut_pattern" => true,
        _ => {
            let mut cursor = binding.walk();
            binding
                .child_by_field_name("pattern")
                .is_some_and(|pattern| pattern.kind() == "mut_pattern")
                || binding
                    .named_children(&mut cursor)
                    .any(|child| child.kind() == "mutable_specifier")
        }
    };
    if !mutable {
        return Ok(false);
    }
    let mut stack = Vec::new();
    if binding.kind() == "let_declaration" {
        // A let is in effect from its end to the end of its block.
        let block = crate::syntax::parent_outside_attributes(binding)
            .expect("a let declaration has an enclosing block");
        let mut cursor = block.walk();
        stack.extend(
            block
                .named_children(&mut cursor)
                .filter(|statement| statement.start_byte() >= binding.end_byte()),
        );
    } else if let Some(body) = nearest_ancestor(binding, |kind| {
        matches!(
            kind,
            "function_item" | "function_signature_item" | "closure_expression"
        )
    })
    .and_then(|callable| callable.child_by_field_name("body"))
    {
        stack.push(body);
    }
    let name = crate::declarations::rust_node_text(occurrence, source);
    while let Some(node) = stack.pop() {
        charge(1)?;
        let named_use = match node.kind() {
            "self" => true,
            "identifier" => matches!(
                rust_occurrence_role(node),
                Some(OccurrenceRole::ValueReference | OccurrenceRole::ReceiverPosition)
            ),
            _ => false,
        };
        if named_use
            && crate::declarations::rust_node_text(node, source) == name
            && rust_occurrence_may_write(node, charge)?
            && crate::lexical_scope::rust_value_binding_at_bounded(node, source, charge)?
                .is_some_and(|selected| selected.id() == binding.id())
        {
            return Ok(true);
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    Ok(false)
}

/// Whether a value use may write the binding it names: an assignment target,
/// including a destructuring one, a `&mut` borrow or `ref mut` pattern
/// scrutinee of a place it roots, a method receiver (autoref can borrow
/// mutably), or a macro input, which can expand to any of these.
fn rust_occurrence_may_write<E>(
    occurrence: Node<'_>,
    charge: &mut dyn FnMut(usize) -> Result<(), E>,
) -> Result<bool, E> {
    let mut node = occurrence;
    // Composite expressions are transparent only to an assignment target;
    // anywhere else they hold a moved or copied value, not the place.
    let mut place = true;
    while let Some(parent) = node.parent() {
        charge(1)?;
        match parent.kind() {
            "token_tree" => return Ok(true),
            "assignment_expression" | "compound_assignment_expr" => {
                return Ok(is_field_of(parent, node, "left"));
            }
            "reference_expression" => {
                let mut cursor = parent.walk();
                return Ok(place
                    && parent
                        .named_children(&mut cursor)
                        .any(|child| child.kind() == "mutable_specifier"));
            }
            "let_declaration" | "let_condition" if place && is_field_of(parent, node, "value") => {
                return match parent.child_by_field_name("pattern") {
                    Some(pattern) => rust_pattern_borrows_mutably(pattern, charge),
                    None => Ok(false),
                };
            }
            "match_expression" if place && is_field_of(parent, node, "value") => {
                let Some(arms) = parent.child_by_field_name("body") else {
                    return Ok(false);
                };
                let mut cursor = arms.walk();
                for arm in arms.named_children(&mut cursor) {
                    if let Some(pattern) = arm.child_by_field_name("pattern")
                        && rust_pattern_borrows_mutably(pattern, charge)?
                    {
                        return Ok(true);
                    }
                }
                return Ok(false);
            }
            "field_expression" if place && is_field_of(parent, node, "value") => {
                // A method call, with or without a turbofish.
                let call = nearest_ancestor(parent, |kind| kind != "generic_function");
                if call.is_some_and(|call| {
                    call.kind() == "call_expression"
                        && call
                            .child_by_field_name("function")
                            .is_some_and(|function| call_function_target(function) == parent)
                }) {
                    return Ok(true);
                }
            }
            "index_expression" if place && parent.named_child(0) == Some(node) => {}
            "unary_expression"
                if place
                    && parent
                        .child(0)
                        .is_some_and(|operator| operator.kind() == "*") => {}
            "parenthesized_expression" => {}
            "call_expression" if is_field_of(parent, node, "arguments") => place = false,
            "tuple_expression"
            | "array_expression"
            | "arguments"
            | "field_initializer"
            | "shorthand_field_initializer"
            | "field_initializer_list"
            | "struct_expression" => place = false,
            _ => return Ok(false),
        }
        node = parent;
    }
    Ok(false)
}

/// Whether a pattern binds part of its scrutinee by `ref mut`.
fn rust_pattern_borrows_mutably<E>(
    pattern: Node<'_>,
    charge: &mut dyn FnMut(usize) -> Result<(), E>,
) -> Result<bool, E> {
    let mut stack = vec![pattern];
    while let Some(node) = stack.pop() {
        charge(1)?;
        if node.kind() == "ref_pattern"
            && node
                .named_child(0)
                .is_some_and(|inner| inner.kind() == "mut_pattern")
        {
            return Ok(true);
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    Ok(false)
}

/// Classify the value binding `callee` selected; `None` is a named item.
fn rust_binding_callee_provenance<E>(
    callee: Node<'_>,
    binding: Option<Node<'_>>,
    source: &str,
    charge: &mut dyn FnMut(usize) -> Result<(), E>,
) -> Result<CalleeProvenanceFact, E> {
    let mut fact = rust_unknown_callee_provenance();
    let Some(binding) = binding else {
        fact.provenance = CalleeProvenance::Declared;
        return Ok(fact);
    };
    if binding.kind() == "let_declaration" {
        if binding
            .child_by_field_name("value")
            .is_some_and(|value| value.kind() == "closure_expression")
        {
            fact.provenance = CalleeProvenance::LocalClosure;
        }
        return Ok(fact);
    }
    let mut ancestor = binding.parent();
    let mut parameters = None;
    let mut callable = None;
    while let Some(node) = ancestor {
        charge(1)?;
        if matches!(node.kind(), "parameters" | "closure_parameters") {
            parameters = Some(node);
        }
        if matches!(node.kind(), "function_item" | "closure_expression") {
            callable = Some(node);
            break;
        }
        ancestor = node.parent();
    }
    let Some(parameters) = parameters else {
        return Ok(fact);
    };
    let Some(callable) = callable else {
        return Ok(fact);
    };
    let is_closure = callable.kind() == "closure_expression";
    let mut ordinal = 0;
    for index in 0..parameters.named_child_count() {
        charge(1)?;
        let parameter =
            unwrap_attributes(parameters.named_child(index).expect("indexed parameter"));
        if matches!(
            parameter.kind(),
            "line_comment" | "block_comment" | "attribute_item"
        ) {
            continue;
        }
        if parameter.id() == binding.id() {
            break;
        }
        if parameter.kind() != "self_parameter" {
            ordinal += 1;
        }
    }
    let supplier = if binding.kind() == "self_parameter" || callee.kind() == "self" {
        CalleeSupplier::Receiver
    } else if is_closure {
        CalleeSupplier::ClosureParameter(ordinal)
    } else {
        CalleeSupplier::Parameter(ordinal)
    };
    if binding.kind() == "self_parameter" {
        let mut owner = callable.parent();
        while let Some(node) = owner {
            charge(1)?;
            match node.kind() {
                "trait_item" => {
                    fact.provenance = CalleeProvenance::CallerSupplied;
                    fact.supplier = Some(supplier);
                    break;
                }
                "impl_item" | "source_file" => break,
                _ => owner = node.parent(),
            }
        }
        return Ok(fact);
    }
    let Some(mut ty) = binding.child_by_field_name("type") else {
        if is_closure {
            fact.provenance = CalleeProvenance::CallerSupplied;
            fact.supplier = Some(supplier);
        }
        return Ok(fact);
    };
    while ty.kind() == "reference_type" {
        charge(1)?;
        let Some(inner) = ty.child_by_field_name("type") else {
            return Ok(fact);
        };
        ty = inner;
    }
    fact.shape = match ty.kind() {
        "dynamic_type" => CalleeTypeShape::DynTrait,
        "abstract_type" => CalleeTypeShape::ImplTrait,
        "function_type" => CalleeTypeShape::FnPointer,
        _ => CalleeTypeShape::Nominal,
    };
    if matches!(ty.kind(), "dynamic_type" | "abstract_type") {
        if let Some(bounds) = ty.child_by_field_name("trait") {
            fact.bounds = rust_callee_bound_paths(bounds, source, charge)?;
        }
    } else if ty.kind() == "type_identifier" {
        let type_name = crate::declarations::rust_node_text(ty, source);
        let mut bound_nodes = Vec::new();
        let mut generic = false;
        if let Some(formals) = callable.child_by_field_name("type_parameters") {
            let mut cursor = formals.walk();
            for parameter in formals.named_children(&mut cursor) {
                charge(1)?;
                if parameter.kind() == "type_parameter"
                    && parameter.child_by_field_name("name").is_some_and(|name| {
                        crate::declarations::rust_node_text(name, source) == type_name
                    })
                {
                    generic = true;
                    if let Some(bounds) = parameter.child_by_field_name("bounds") {
                        bound_nodes.push(bounds);
                    }
                }
            }
        }
        if generic {
            let mut cursor = callable.walk();
            for clause in callable.named_children(&mut cursor) {
                charge(1)?;
                if clause.kind() != "where_clause" {
                    continue;
                }
                let mut cursor = clause.walk();
                for predicate in clause.named_children(&mut cursor) {
                    charge(1)?;
                    if predicate.child_by_field_name("left").is_some_and(|left| {
                        left.kind() == "type_identifier"
                            && crate::declarations::rust_node_text(left, source) == type_name
                    }) && let Some(bounds) = predicate.child_by_field_name("bounds")
                    {
                        bound_nodes.push(bounds);
                    }
                }
            }
            for bounds in bound_nodes {
                fact.bounds
                    .extend(rust_callee_bound_paths(bounds, source, charge)?);
            }
            if !fact.bounds.is_empty() {
                fact.shape = if fact.bounds.iter().any(|path| {
                    // Paths are already selected and assembled from AST nodes;
                    // matching their value is not parsing source syntax.
                    matches!(path.as_str(), "Fn" | "FnMut" | "FnOnce")
                        || ["::Fn", "::FnMut", "::FnOnce"]
                            .iter()
                            .any(|suffix| path.ends_with(suffix))
                }) {
                    CalleeTypeShape::FnBoundGeneric
                } else {
                    CalleeTypeShape::TraitBoundGeneric
                };
            }
        }
    }
    if is_closure
        || !matches!(
            fact.shape,
            CalleeTypeShape::Nominal | CalleeTypeShape::Unknown
        )
    {
        fact.provenance = CalleeProvenance::CallerSupplied;
        fact.supplier = Some(supplier);
    } else {
        fact.provenance = CalleeProvenance::Declared;
    }
    Ok(fact)
}

/// Inline and where-clause bounds on one structurally selected type. Callers
/// select the lexical binder first; matching identifier values here does not
/// infer a binding from spelling.
pub fn rust_declared_type_bounds<'tree>(
    owner: Node<'tree>,
    ty: Node<'tree>,
    source: &str,
) -> Vec<Node<'tree>> {
    let path = |node: Node<'tree>| {
        // The native parameter rows select bare names. For a projection,
        // compare plain path structure only; generic projections need their
        // substitutions and must not inherit a differently applied bound.
        let mut qualifier = node;
        loop {
            if qualifier.kind() == "generic_type" {
                return None;
            }
            let Some(parent_path) = qualifier.child_by_field_name("path") else {
                break;
            };
            qualifier = parent_path;
        }
        crate::graph_support::rust_path_segments(node).map(|nodes| {
            nodes
                .into_iter()
                .map(|part| {
                    brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix(
                        crate::declarations::rust_node_text(part, source),
                    )
                })
                .collect::<Vec<_>>()
        })
    };
    let expected = path(ty);
    let same = |node: Node<'tree>| {
        node.kind() == ty.kind()
            && crate::graph_support::rust_path_is_leading_absolute(node)
                == crate::graph_support::rust_path_is_leading_absolute(ty)
            && expected
                .as_ref()
                .is_some_and(|expected| path(node).as_ref() == Some(expected))
    };
    let mut result = Vec::new();
    if let Some(parameters) = owner.child_by_field_name("type_parameters") {
        let mut cursor = parameters.walk();
        for parameter in parameters.named_children(&mut cursor) {
            if parameter.child_by_field_name("name").is_some_and(same)
                && let Some(bounds) = parameter.child_by_field_name("bounds")
            {
                result.push(bounds);
            }
        }
    }
    let mut cursor = owner.walk();
    for clause in owner.named_children(&mut cursor) {
        if clause.kind() != "where_clause" {
            continue;
        }
        let mut cursor = clause.walk();
        for predicate in clause.named_children(&mut cursor) {
            if predicate.child_by_field_name("left").is_some_and(same)
                && let Some(bounds) = predicate.child_by_field_name("bounds")
            {
                result.push(bounds);
            }
        }
    }
    result
}

fn rust_callee_bound_paths<E>(
    bounds: Node<'_>,
    source: &str,
    charge: &mut dyn FnMut(usize) -> Result<(), E>,
) -> Result<Vec<String>, E> {
    let mut result = Vec::new();
    let mut stack = vec![bounds];
    while let Some(node) = stack.pop() {
        charge(1)?;
        match node.kind() {
            "function_type" => {
                if let Some(head) = node.child_by_field_name("trait") {
                    stack.push(head);
                }
            }
            "type_identifier" | "scoped_type_identifier" | "generic_type" => {
                if let Some(path) = crate::declarations::rust_nominal_type_path(node, source) {
                    charge(path.len())?;
                    result.push(path.join("::"));
                }
            }
            "trait_bounds"
            | "bounded_type"
            | "higher_ranked_trait_bound"
            | "removed_trait_bound" => {
                for index in (0..node.named_child_count()).rev() {
                    charge(1)?;
                    stack.push(node.named_child(index).expect("indexed bound"));
                }
            }
            _ => {}
        }
    }
    Ok(result)
}

impl StructuralSpec for RustStructuralSpec {
    fn supports_unsafe_context(&self) -> bool {
        true
    }

    fn unsafe_context_value(
        &self,
        node: Node<'_>,
        charge: &mut dyn FnMut(
            usize,
        ) -> Result<
            (),
            brokk_bifrost_core::analyzer::structural::collector::StructuralFactCollectorStop,
        >,
    ) -> Result<
        Option<bool>,
        brokk_bifrost_core::analyzer::structural::collector::StructuralFactCollectorStop,
    > {
        crate::ownership::rust_node_is_in_unsafe_context_bounded(node, charge).map(Some)
    }

    fn callee_provenance(
        &self,
        node: Node<'_>,
        source: &str,
        charge: &mut dyn FnMut(
            usize,
        ) -> Result<
            (),
            brokk_bifrost_core::analyzer::structural::collector::StructuralFactCollectorStop,
        >,
    ) -> Result<
        Option<CalleeProvenanceFact>,
        brokk_bifrost_core::analyzer::structural::collector::StructuralFactCollectorStop,
    > {
        rust_callee_provenance(node, source, charge).map(Some)
    }

    fn embedded_syntax_kinds(&self) -> &'static [&'static str] {
        &["token_tree"]
    }
    fn embedded_syntax(
        &self,
        node: Node<'_>,
        source: &str,
    ) -> Vec<brokk_bifrost_core::analyzer::structural::spec::EmbeddedSyntaxTree> {
        if node.kind() != "token_tree" {
            return Vec::new();
        }
        let Some(invocation) = node
            .parent()
            .filter(|parent| parent.kind() == "macro_invocation")
        else {
            return Vec::new();
        };
        let Some(operands) = crate::macro_matcher::parse_macro_operands(invocation, source) else {
            return Vec::new();
        };
        let arguments =
            crate::format_args::macro_arguments_from_operands(invocation, source, &operands);
        let named = arguments
            .iter()
            .filter_map(|argument| argument.name.as_deref())
            .collect::<Vec<_>>();
        let format_index =
            crate::format_args::rust_macro_format_operand(invocation, source, &arguments);
        let mut captures = format_index
            .and_then(|index| operands.get(index))
            .map(|operand| {
                crate::format_args::rust_format_capture_trees(operand.node(), source, &named)
            })
            .unwrap_or_default();
        let mut trees = operands
            .into_iter()
            .zip(arguments)
            .map(|(operand, argument)| {
                brokk_bifrost_core::analyzer::structural::spec::EmbeddedSyntaxTree {
                    anchor: node.id(),
                    range: argument.value_range,
                    tree: operand.tree,
                }
            })
            .collect::<Vec<_>>();
        trees.append(&mut captures);
        trees
    }

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
        let coverage = if rust_modeled_sink_macro_layout(node, source).is_some()
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
                        attach_terminal_callee(
                            sink,
                            macro_name,
                            terminal_callee_leaf(macro_name, callee_spine_step),
                        );
                        attach_scoped_receiver(sink, macro_name);
                    }
                    let modeled_sink =
                        rust_modeled_sink_macro_layout(node, source).and_then(|layout| {
                            let arguments =
                                crate::format_args::rust_format_macro_arguments(node, source)
                                    .ok()?;
                            Some((layout, arguments))
                        });
                    if let Some((layout, arguments)) = modeled_sink {
                        for role in layout.arguments {
                            if !sink.should_continue() {
                                break;
                            }
                            use crate::format_args::RustMacroRuntimeArgument;
                            let written_index = match *role {
                                RustMacroRuntimeArgument::Message { first_operand }
                                | RustMacroRuntimeArgument::OptionalMessage { first_operand } => {
                                    Some(first_operand)
                                }
                                RustMacroRuntimeArgument::BorrowedOperand(index) => Some(index),
                                RustMacroRuntimeArgument::DebugOperand => Some(0),
                                RustMacroRuntimeArgument::AssertionKind => None,
                            };
                            // Synthetic arguments without written operands stay
                            // anchored to their invocation.
                            let target = written_index
                                .and_then(|index| arguments.get(index))
                                .map_or(node, |argument| {
                                    node.descendant_for_byte_range(
                                        argument.range.start_byte,
                                        argument.range.end_byte,
                                    )
                                    .expect(
                                        "a format argument range lies inside its macro invocation",
                                    )
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
                    attach_terminal_callee(
                        sink,
                        function,
                        terminal_callee_leaf(function, callee_spine_step),
                    );
                    attach_call_type_arguments(sink, function);
                    if let Some((receiver, _member)) = rust_method_call_parts(function) {
                        attach_rust_role(sink, Role::Receiver, receiver, expression_name_node);
                    }
                    attach_scoped_receiver(sink, call_function_target(function));
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
    use super::{RustCallResultUseIndex, rust_call_result_use, rust_method_call_parts};
    use crate::structural::RUST_STRUCTURAL_SPEC;
    use brokk_bifrost_core::analyzer::source_facts::PrimarySourceFactCollector;
    use brokk_bifrost_core::analyzer::structural::kinds::{NormalizedKind, Role};
    use brokk_bifrost_core::analyzer::structural::result_use::{
        CallResultUse, IntentionalDiscardKind,
    };
    use brokk_bifrost_core::analyzer::structural::spec::{RoleSink, StructuralSpec};
    use brokk_bifrost_core::analyzer::tree_walk::ParentIndex;
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
    fn recovery_boundary_keeps_calls_open_and_hides_declarations() {
        use brokk_bifrost_core::analyzer::structural::result_use::CallResultUseOpenReason;
        let source = "match { fn nested() {} f(); }; fn sibling() {}";
        let tree = tree(source);
        let calls = call_nodes(&tree);
        assert_eq!(calls.len(), 1);
        assert!(!calls[0].has_error(), "call itself must be clean");
        let mut parent = calls[0].parent();
        let mut recovered = false;
        while let Some(node) = parent {
            recovered |= node.is_error() || node.is_missing();
            parent = node.parent();
        }
        assert!(recovered, "{}", tree.root_node().to_sexp());
        assert_eq!(
            rust_call_result_use(calls[0], source).for_port(0),
            CallResultUse::Open(CallResultUseOpenReason::RecoveredSyntax)
        );
        let recovered_block = calls[0].parent().unwrap().parent().unwrap();
        assert_eq!(recovered_block.kind(), "block");
        let nested = recovered_block.named_child(0).unwrap();
        assert_eq!(nested.kind(), "function_item");
        assert_eq!(
            nested
                .child_by_field_name("name")
                .unwrap()
                .utf8_text(source.as_bytes())
                .unwrap(),
            "nested"
        );
        let parsed = crate::test_helpers::parse_rust_fixture(source);
        let mut declarations = parsed
            .declarations()
            .iter()
            .map(|unit| unit.identifier())
            .collect::<Vec<_>>();
        declarations.sort_unstable();
        assert_eq!(
            declarations,
            ["sibling"],
            "ERROR interior must not publish declarations: {}",
            tree.root_node().to_sexp()
        );
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

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5522: numeric tuple fields and parenthesized callable fields are not Rust method calls"
    )]
    fn rust_method_call_shape_requires_an_unparenthesized_named_field() {
        let source = concat!(
            "type Callable = fn(i32);\n",
            "struct TupleHolder(Callable, (Callable, Callable));\n",
            "struct Holder { callback: Callable, method: Callable }\n",
            "impl Holder {\n",
            "    fn callback(&self, _: i32) {}\n",
            "    fn method<T>(&self, _: T) {}\n",
            "}\n",
            "impl TupleHolder {\n",
            "    fn run(&self, holder: &Holder) {\n",
            "    self.0(1);\n",
            "    self.1.0(2);\n",
            "    (self.0)(3);\n",
            "    holder.callback(4);\n",
            "    (holder.callback)(5);\n",
            "    holder.method::<i32>(6);\n",
            "    }\n",
            "}\n",
        );
        let tree = tree(source);
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );
        let calls = call_nodes(&tree);
        let shapes = calls
            .iter()
            .copied()
            .map(|call| {
                let function = call.child_by_field_name("function").expect("call function");
                let call_text = &source[call.start_byte()..call.end_byte()];
                let shape = rust_method_call_parts(function).map(|(receiver, member)| {
                    (
                        source[receiver.start_byte()..receiver.end_byte()].to_owned(),
                        source[member.start_byte()..member.end_byte()].to_owned(),
                    )
                });
                (call_text, shape)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            shapes,
            vec![
                ("self.0(1)", None),
                ("self.1.0(2)", None),
                ("(self.0)(3)", None),
                (
                    "holder.callback(4)",
                    Some(("holder".to_owned(), "callback".to_owned()))
                ),
                ("(holder.callback)(5)", None),
                (
                    "holder.method::<i32>(6)",
                    Some(("holder".to_owned(), "method".to_owned()))
                ),
            ]
        );
        for (call, expected_receiver) in
            calls
                .iter()
                .copied()
                .zip([None, None, None, Some("holder"), None, Some("holder")])
        {
            let parents = ParentIndex::new(tree.root_node());
            let mut facts = PrimarySourceFactCollector::new(source);
            let mut sink = RoleSink::new(source, &mut facts, 16, None, &parents);
            RUST_STRUCTURAL_SPEC.extract(call, NormalizedKind::Call, &mut sink);
            let (_, roles, _, stop) = sink.into_parts();
            assert_eq!(stop, None);
            let receivers = roles
                .iter()
                .filter(|role| role.role == Role::Receiver)
                .map(|role| {
                    let range = facts.occurrence(role.occurrence).range;
                    &source[range.start_byte..range.end_byte]
                })
                .collect::<Vec<_>>();
            assert_eq!(receivers, expected_receiver.into_iter().collect::<Vec<_>>());
        }
    }
}

#[test]
fn callee_provenance_walk_obeys_the_extraction_work_allowance() {
    // The alias form also charges the write scans of both mutable bindings.
    for source in [
        "fn run<F: Fn()>(f: F) { f(); }",
        "fn run<F: FnMut()>(mut f: F) { let mut g = f; g(); }",
    ] {
        let tree = crate::lexical_scope::parse_rust_tree(source).expect("Rust grammar");
        let mut stack = vec![tree.root_node()];
        let call = loop {
            let node = stack.pop().expect("fixture call");
            if node.kind() == "call_expression" {
                break node;
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        };
        let mut work = 0;
        let fact = rust_callee_provenance(call, source, &mut |amount| {
            work += amount;
            Ok::<_, ()>(())
        })
        .expect("unlimited classification");
        assert_eq!(
            fact.provenance,
            CalleeProvenance::CallerSupplied,
            "{source}"
        );
        assert!(work > 1);
        let mut remaining = work - 1;
        assert!(
            rust_callee_provenance(call, source, &mut |amount| {
                remaining = remaining.checked_sub(amount).ok_or(())?;
                Ok::<_, ()>(())
            })
            .is_err(),
            "{source}"
        );
    }
}

#[cfg(test)]
mod attribute_role_grammar_tests {
    #[test]
    fn grammar_derive_and_ordinary_attribute_arguments() {
        for (attribute, expected) in [("derive", true), ("allow", false), ("custom", false)] {
            let source = format!("#[{attribute}(Marker)] struct Item;");
            let tree = crate::lexical_scope::parse_rust_tree(&source).unwrap();
            assert!(!tree.root_node().has_error());
            let mut pending = vec![tree.root_node()];
            let marker = loop {
                let node = pending.pop().expect("Marker token");
                if node.kind() == "identifier" && node.utf8_text(source.as_bytes()) == Ok("Marker")
                {
                    break node;
                }
                pending.extend(node.named_children(&mut node.walk()));
            };
            assert_eq!(marker.parent().unwrap().kind(), "token_tree");
            assert_eq!(
                super::is_inside_derive_attribute(marker, &source),
                expected,
                "{attribute}"
            );
        }
    }
}

#[cfg(test)]
mod ownership_role_grammar_boundary {
    use super::*;

    #[test]
    fn ownership_structural_roles_follow_grammar_fields() {
        let source = "use dep::*; use root::{a, nest::{b as c, *}}; fn f() { module::helper(); Wrapper::<Outer>::make::<Inner>(); let S { member: bound } = value; }";
        let tree = crate::test_helpers::parse_rust(source);
        assert!(!tree.root_node().has_error());
        let parents = ParentIndex::new(tree.root_node());
        let mut nodes = Vec::new();
        let mut pending = vec![tree.root_node()];
        while let Some(node) = pending.pop() {
            nodes.push(node);
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
        nodes.sort_by_key(Node::start_byte);
        // Grammar-selected import targets and struct-pattern fields carry
        // different namespaces despite sharing identifier-like spellings.
        for (text, kind, parent_kind, field, role) in [
            (
                "dep",
                "identifier",
                "use_wildcard",
                None,
                OccurrenceRole::ImportTarget,
            ),
            (
                "member",
                "field_identifier",
                "field_pattern",
                Some("name"),
                OccurrenceRole::MemberPosition,
            ),
            (
                "bound",
                "identifier",
                "field_pattern",
                Some("pattern"),
                OccurrenceRole::Binder,
            ),
        ] {
            let node = nodes
                .iter()
                .copied()
                .find(|node| node.kind() == kind && &source[node.byte_range()] == text)
                .unwrap();
            let parent = node.parent().unwrap();
            assert_eq!(parent.kind(), parent_kind);
            assert_eq!(field_name_in_parent(parent, node), field);
            assert_eq!(rust_occurrence_role(node), Some(role));
        }
        let mut output = Vec::new();
        for node in nodes
            .iter()
            .copied()
            .filter(|node| matches!(node.kind(), "call_expression" | "use_declaration"))
        {
            let mut facts = PrimarySourceFactCollector::new(source);
            let mut sink = RoleSink::new(source, &mut facts, 32, None, &parents);
            let kind = if node.kind() == "call_expression" {
                NormalizedKind::Call
            } else {
                NormalizedKind::Import
            };
            RUST_STRUCTURAL_SPEC.extract(node, kind, &mut sink);
            let (_, roles, _, stop) = sink.into_parts();
            assert_eq!(stop, None);
            let mut selected = roles
                .into_iter()
                .filter(|role| {
                    matches!(
                        role.role,
                        Role::Module | Role::Receiver | Role::TypeArguments
                    )
                })
                .map(|role| {
                    let range = facts.occurrence(role.occurrence).range;
                    (
                        role.role,
                        source[range.start_byte..range.end_byte].to_owned(),
                    )
                })
                .collect::<Vec<_>>();
            selected.sort_unstable();
            output.push(selected);
        }
        assert_eq!(
            output,
            [
                vec![(Role::Module, "dep".into())],
                vec![(Role::Module, "a".into()), (Role::Module, "c".into())],
                vec![(Role::Receiver, "module".into())],
                vec![
                    (Role::Receiver, "Wrapper::<Outer>".into()),
                    (Role::TypeArguments, "Inner".into()),
                    (Role::TypeArguments, "Outer".into())
                ],
            ]
        );
    }
}
