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
use brokk_bifrost_core::analyzer::structural::facts::Span;
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

fn rust_binding_needs_strict_selection(binder: Node<'_>) -> bool {
    let whole_arm = binder
        .parent()
        .is_some_and(|parent| parent.kind() == "match_pattern");
    let whole_let_condition = binder.parent().is_some_and(|parent| {
        parent.kind() == "let_condition"
            && parent
                .child_by_field_name("pattern")
                .is_some_and(|pattern| pattern.id() == binder.id())
    });
    let shorthand_field = binder.kind() == "shorthand_field_identifier"
        && binder
            .parent()
            .is_some_and(|parent| parent.kind() == "field_pattern");
    let mut ancestor = binder.parent();
    while let Some(parent) = ancestor {
        if parent.kind() == "let_declaration" && parent.child_by_field_name("alternative").is_some()
        {
            return true;
        }
        if matches!(parent.kind(), "or_pattern" | "reference_pattern") {
            return true;
        }
        if matches!(
            parent.kind(),
            "match_pattern" | "match_arm" | "let_condition"
        ) {
            return true;
        }
        if matches!(
            parent.kind(),
            "match_arm"
                | "let_declaration"
                | "let_condition"
                | "parameter"
                | "closure_parameters"
                | "for_expression"
        ) {
            break;
        }
        ancestor = parent.parent();
    }
    whole_arm || whole_let_condition || shorthand_field
}

fn rust_occurrence_needs_binding_verdict(node: Node<'_>, role: OccurrenceRole) -> bool {
    role == OccurrenceRole::Binder && rust_binding_needs_strict_selection(node)
}

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
    ("shorthand_field_identifier", NormalizedKind::Identifier),
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

/// The last statement of a block. Comments are named extras in
/// tree-sitter-rust and a labeled block's `label` is a named child; neither is
/// a statement.
pub fn rust_block_last_statement(block: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = block.walk();
    block
        .named_children(&mut cursor)
        .filter(|child| !child.is_extra() && child.kind() != "label")
        .last()
}

/// The expression a block evaluates to. A trailing `if`, `match`, `loop` or
/// block without `;` sits inside an `expression_statement`; the statement's
/// expression is the tail. A last statement ending in `;`, a `let` or an item
/// leaves the block without a tail value.
pub fn rust_block_tail_expression(block: Node<'_>) -> Option<Node<'_>> {
    let last = rust_block_last_statement(block)?;
    if last.kind() == "expression_statement" {
        let mut cursor = last.walk();
        if last.children(&mut cursor).any(|child| child.kind() == ";") {
            return None;
        }
        let mut cursor = last.walk();
        return last
            .named_children(&mut cursor)
            .find(|child| !child.is_extra());
    }
    let kind = last.kind();
    let declaration = kind.ends_with("_declaration")
        || kind.ends_with("_item")
        || matches!(kind, "macro_definition" | "empty_statement");
    (!declaration).then_some(last)
}

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

/// An outer attribute is source preserving only when every effective meta
/// item selected by its parsed `cfg_attr` tree has a known inert path.
fn rust_attribute_preserves_body(
    attribute: Node<'_>,
    source: &str,
    context: Option<&CallSiteContext>,
) -> bool {
    let Some(item) = attribute.parent() else {
        return false;
    };
    if item.kind() != "attribute_item" {
        return false;
    }
    let owner_scope = item
        .parent()
        .and_then(|attributes| attributes.parent())
        .and_then(|owner| owner.parent());
    crate::resolution::rust_effective_attributes(std::iter::once(item), source).is_some_and(
        |attributes| {
            !attributes.is_empty()
                && attributes.into_iter().all(|attribute| {
                    if attribute.path.len() != 1 {
                        return false;
                    }
                    let name = crate::declarations::rust_node_text(attribute.path[0], source);
                    if name == "test" {
                        let mut work = 0usize;
                        let mut charge = |amount: usize| -> Result<(), ()> {
                            work = work.saturating_add(amount);
                            (work <= 100_000).then_some(()).ok_or(())
                        };
                        let unshadowed = owner_scope.is_some_and(|scope| {
                            if let Some(context) = context {
                                let mut current = Some(scope);
                                while let Some(node) = current {
                                    if !context.test_attribute_scope_unshadowed(node.id()) {
                                        return false;
                                    }
                                    current = node.parent();
                                }
                                true
                            } else {
                                crate::lexical_scope::rust_test_attribute_unshadowed_bounded(
                                    scope,
                                    source,
                                    &mut charge,
                                ) == Ok(true)
                            }
                        });
                        if !unshadowed {
                            return false;
                        }
                    }
                    matches!(
                        name,
                        "test"
                            | "cfg"
                            | "allow"
                            | "warn"
                            | "deny"
                            | "forbid"
                            | "expect"
                            | "inline"
                            | "cold"
                            | "must_use"
                            | "doc"
                            | "deprecated"
                            | "track_caller"
                            | "derive"
                            | "automatically_derived"
                            | "non_exhaustive"
                            | "repr"
                    )
                })
        },
    )
}

fn attach_attribute_arguments(sink: &mut RoleSink<'_>, arguments: Node<'_>) {
    fn emit(sink: &mut RoleSink<'_>, segment: &[Node<'_>]) {
        let Some(first) = segment.first().copied() else {
            return;
        };
        let last = *segment.last().unwrap();
        let span = Span {
            start_byte: first.start_byte(),
            end_byte: last.end_byte(),
        };
        if segment.len() == 1 && first.kind() == "identifier" {
            sink.argument_maybe_named(first, Some(first), false);
        } else if segment.len() >= 3 && first.kind() == "identifier" && segment[1].kind() == "=" {
            if segment.len() == 3
                && matches!(
                    segment[2].kind(),
                    "string_literal"
                        | "char_literal"
                        | "integer_literal"
                        | "float_literal"
                        | "boolean_literal"
                )
            {
                sink.kwarg(first, segment[2]);
            } else {
                sink.kwarg_value_span(
                    first,
                    Span {
                        start_byte: segment[2].start_byte(),
                        end_byte: last.end_byte(),
                    },
                );
            }
        } else {
            sink.argument_span(span);
        }
    }
    let mut segment = Vec::new();
    for index in 1..arguments.child_count().saturating_sub(1) {
        if !sink.should_continue() {
            break;
        }
        let child = arguments.child(index).unwrap();
        if child.is_extra() {
            continue;
        }
        if child.kind() == "," {
            emit(sink, &segment);
            segment.clear();
        } else {
            segment.push(child);
        }
    }
    emit(sink, &segment);
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
        "identifier" | "field_identifier" | "type_identifier" | "shorthand_field_identifier"
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
        "parameter" | "let_declaration" | "let_condition" | "for_expression"
            if field == Some("pattern") =>
        {
            OccurrenceRole::Binder
        }
        "closure_parameters" | "ref_pattern" | "reference_pattern" | "mut_pattern"
        | "or_pattern" | "tuple_pattern" | "slice_pattern" | "captured_pattern" => {
            if anchor.id() == node.id() {
                OccurrenceRole::Binder
            } else {
                OccurrenceRole::PatternPosition
            }
        }
        "match_pattern" if field == Some("condition") => OccurrenceRole::ValueReference,
        "match_pattern" if anchor.id() == node.id() => OccurrenceRole::Binder,
        "match_pattern" => OccurrenceRole::PatternPosition,
        "field_pattern" if field == Some("pattern") => OccurrenceRole::Binder,
        "field_pattern" if node.kind() == "shorthand_field_identifier" => OccurrenceRole::Binder,
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
        "parameter"
            if form.parent().is_some_and(|parameters| {
                parameters.kind() == "parameters"
                    && parameters
                        .parent()
                        .is_some_and(|owner| owner.kind() == "function_signature_item")
            }) =>
        {
            None
        }
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
            // A let-chain binder is visible in later `&&` conditions as well
            // as the body, but never in its own initializer or the else arm.
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
                activation: Range {
                    start_byte: form.end_byte(),
                    end_byte: body.end_byte(),
                    start_line: form.end_position().row + 1,
                    end_line: body.end_position().row + 1,
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
    fn call_site_context(&self, root: Node<'_>, source: &str) -> CallSiteContext {
        self.call_site_context_limited(root, source, usize::MAX, None)
            .expect("unbounded Rust syntax preparation")
    }

    fn call_site_context_limited(
        &self,
        root: Node<'_>,
        source: &str,
        _max_work_items: usize,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    ) -> Result<
        CallSiteContext,
        brokk_bifrost_core::analyzer::structural::collector::StructuralFactCollectorStop,
    > {
        use brokk_bifrost_core::analyzer::structural::collector::StructuralFactCollectorStop;
        let mut binders = Vec::new();
        let mut test_scopes_to_prepare = Vec::new();
        let mut stack = vec![root];
        let mut work = 0usize;
        // This is a preparation budget, not the collector's fact-node budget:
        // raw Rust syntax can contain many nodes that never become facts.
        // Fixed per-file work allowance: identical bytes always persist the
        // same verdicts regardless of request budget or cache history.
        const PREPARATION_LIMIT: usize = 100_000;
        while let Some(node) = stack.pop() {
            if cancellation.is_some_and(|token| token.is_cancelled()) {
                return Err(StructuralFactCollectorStop::Cancelled);
            }
            work = work.saturating_add(1);
            if work > PREPARATION_LIMIT {
                return Ok(CallSiteContext::with_open_binding_candidates());
            }
            if let Some(role) = rust_occurrence_role(node)
                && rust_occurrence_needs_binding_verdict(node, role)
            {
                binders.push(node);
            }
            if node.kind() == "attribute_item"
                && crate::resolution::rust_effective_attributes(std::iter::once(node), source)
                    .is_some_and(|attributes| {
                        attributes.into_iter().any(|attribute| {
                            attribute.path.len() == 1
                                && crate::declarations::rust_node_text(attribute.path[0], source)
                                    == "test"
                        })
                    })
                && let Some(scope) = node
                    .parent()
                    .and_then(|attributes| attributes.parent())
                    .and_then(|owner| owner.parent())
            {
                test_scopes_to_prepare.push(scope);
            }
            for index in (0..node.named_child_count()).rev() {
                stack.push(node.named_child(index).expect("named child"));
            }
        }
        // Classification is a second bounded phase. The index scans each
        // lexical scope once; charge each candidate before entering it.
        if work.saturating_add(binders.len()) > PREPARATION_LIMIT {
            return Ok(CallSiteContext::with_open_binding_candidates());
        }
        if cancellation.is_some_and(|token| token.is_cancelled()) {
            return Err(StructuralFactCollectorStop::Cancelled);
        }
        let mut index = crate::lexical_scope::RustStrictPatternIndex::default();
        let mut answers = Vec::with_capacity(binders.len());
        for &binder in &binders {
            if cancellation.is_some_and(|token| token.is_cancelled()) {
                return Err(StructuralFactCollectorStop::Cancelled);
            }
            work += 1;
            if work > PREPARATION_LIMIT {
                return Ok(CallSiteContext::with_open_binding_candidates());
            }
            let verdict = if rust_binding_needs_strict_selection(binder) {
                let mut charge = |amount: usize| {
                    if cancellation.is_some_and(|token| token.is_cancelled()) {
                        return Err(StructuralFactCollectorStop::Cancelled);
                    }
                    work = work.saturating_add(amount);
                    if work > PREPARATION_LIMIT {
                        return Err(StructuralFactCollectorStop::Exceeded);
                    }
                    Ok(())
                };
                let classification =
                    match index.classify_with_budget(root, source, binder, &mut charge) {
                        Ok(classification) => classification,
                        Err(StructuralFactCollectorStop::Cancelled) => {
                            return Err(StructuralFactCollectorStop::Cancelled);
                        }
                        Err(StructuralFactCollectorStop::Exceeded) => {
                            return Ok(CallSiteContext::with_open_binding_candidates());
                        }
                    };
                match classification {
                    crate::lexical_scope::RustPatternName::Binding => {
                        brokk_bifrost_core::analyzer::structural::spec::BindingCandidateVerdict::Binding
                    }
                    crate::lexical_scope::RustPatternName::ValueItem => {
                        brokk_bifrost_core::analyzer::structural::spec::BindingCandidateVerdict::ValueItem
                    }
                    crate::lexical_scope::RustPatternName::Unknown => {
                        brokk_bifrost_core::analyzer::structural::spec::BindingCandidateVerdict::Open
                    }
                }
            } else {
                brokk_bifrost_core::analyzer::structural::spec::BindingCandidateVerdict::Binding
            };
            answers.push(verdict);
        }
        let verdicts = binders
            .into_iter()
            .zip(answers)
            .map(|(binder, verdict)| (binder.id(), verdict))
            .collect();
        let mut test_scopes = brokk_bifrost_core::hash::HashMap::default();
        for owner_scope in test_scopes_to_prepare {
            let mut current = Some(owner_scope);
            while let Some(scope) = current {
                if cancellation.is_some_and(|token| token.is_cancelled()) {
                    return Err(StructuralFactCollectorStop::Cancelled);
                }
                if let std::collections::hash_map::Entry::Vacant(entry) =
                    test_scopes.entry(scope.id())
                {
                    let mut charge = |amount: usize| {
                        if cancellation.is_some_and(|token| token.is_cancelled()) {
                            return Err(StructuralFactCollectorStop::Cancelled);
                        }
                        work = work.saturating_add(amount);
                        if work > PREPARATION_LIMIT {
                            return Err(StructuralFactCollectorStop::Exceeded);
                        }
                        Ok(())
                    };
                    let unshadowed = match crate::lexical_scope::rust_test_scope_unshadowed_bounded(
                        scope,
                        source,
                        &mut charge,
                    ) {
                        Ok(value) => value,
                        Err(StructuralFactCollectorStop::Cancelled) => {
                            return Err(StructuralFactCollectorStop::Cancelled);
                        }
                        Err(StructuralFactCollectorStop::Exceeded) => {
                            return Ok(CallSiteContext::with_open_binding_candidates());
                        }
                    };
                    entry.insert(unshadowed);
                }
                current = scope.parent();
            }
        }
        Ok(CallSiteContext::with_binding_candidate_verdicts(verdicts)
            .with_test_attribute_scopes(test_scopes))
    }

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
        source: &str,
    ) -> Option<&'static str> {
        if node.kind() == "macro_invocation" {
            return Some("rust_macro_invocation");
        }
        if node.kind() == "attribute" {
            return Some(if rust_attribute_preserves_body(node, source, None) {
                "rust_body_preserving_attribute"
            } else {
                "rust_opaque_attribute"
            });
        }
        None
    }

    fn generator_construct_with_context(
        &self,
        node: Node<'_>,
        kind: NormalizedKind,
        source: &str,
        context: &CallSiteContext,
    ) -> Option<&'static str> {
        if node.kind() == "attribute" {
            return Some(
                if rust_attribute_preserves_body(node, source, Some(context)) {
                    "rust_body_preserving_attribute"
                } else {
                    "rust_opaque_attribute"
                },
            );
        }
        self.generator_construct(node, kind, source)
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
    fn extra_emitted_kinds(&self) -> &'static [NormalizedKind] {
        // Refinement and embedded-leaf outputs beyond the grammar kind table.
        &[NormalizedKind::ConcurrentSpawn, NormalizedKind::Method]
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

    fn binding_candidate_excluded(&self, binder: Node<'_>) -> bool {
        let Some(signature) = nearest_ancestor(binder, |kind| kind == "function_signature_item")
        else {
            return false;
        };
        let Some(parameters) = signature.child_by_field_name("parameters") else {
            return false;
        };
        // Only the signature's own formals are absent from CodeQL's local
        // Variable rows. A const-expression `let` inside a written type is a
        // real local and must retain its binder fact.
        let Some(parameter) = nearest_ancestor(binder, |kind| {
            matches!(kind, "parameter" | "self_parameter")
        }) else {
            return false;
        };
        let in_formal_list = parameter
            .parent()
            .is_some_and(|parent| parent.id() == parameters.id());
        let in_formal_pattern = if parameter.kind() == "self_parameter" {
            binder
                .parent()
                .is_some_and(|parent| parent.id() == parameter.id())
        } else {
            parameter
                .child_by_field_name("pattern")
                .is_some_and(|pattern| {
                    pattern.start_byte() <= binder.start_byte()
                        && binder.end_byte() <= pattern.end_byte()
                })
        };
        in_formal_list && in_formal_pattern
    }

    fn binding_candidate_verdict(
        &self,
        root: Node<'_>,
        source: &str,
        binder: Node<'_>,
    ) -> brokk_bifrost_core::analyzer::structural::spec::BindingCandidateVerdict {
        use crate::lexical_scope::RustPatternName;
        use brokk_bifrost_core::analyzer::structural::spec::BindingCandidateVerdict;
        // Parameter patterns are irrefutable. A binder beneath `&` remains
        // a binding unless this lexical check proves a competing value item.
        if !rust_binding_needs_strict_selection(binder) {
            return BindingCandidateVerdict::Binding;
        }
        let mut work = 0usize;
        let mut charge = |amount: usize| -> Result<(), ()> {
            work = work.saturating_add(amount);
            (work <= 100_000).then_some(()).ok_or(())
        };
        match crate::lexical_scope::rust_pattern_name_strict_bounded(
            root,
            source,
            binder,
            &mut charge,
        ) {
            Ok(RustPatternName::Binding) => BindingCandidateVerdict::Binding,
            Ok(RustPatternName::ValueItem) => BindingCandidateVerdict::ValueItem,
            Ok(RustPatternName::Unknown) | Err(()) => BindingCandidateVerdict::Open,
        }
    }

    fn binding_candidate_verdicts(
        &self,
        root: Node<'_>,
        source: &str,
        binders: &[Node<'_>],
    ) -> Vec<brokk_bifrost_core::analyzer::structural::spec::BindingCandidateVerdict> {
        use brokk_bifrost_core::analyzer::structural::spec::BindingCandidateVerdict;
        let mut index = crate::lexical_scope::RustStrictPatternIndex::default();
        binders
            .iter()
            .map(|&binder| {
                if !rust_binding_needs_strict_selection(binder) {
                    return BindingCandidateVerdict::Binding;
                }
                match index.classify(root, source, binder) {
                    crate::lexical_scope::RustPatternName::Binding => {
                        BindingCandidateVerdict::Binding
                    }
                    crate::lexical_scope::RustPatternName::ValueItem => {
                        BindingCandidateVerdict::ValueItem
                    }
                    crate::lexical_scope::RustPatternName::Unknown => BindingCandidateVerdict::Open,
                }
            })
            .collect()
    }

    fn logical_binding_anchor(&self, binder: Node<'_>, source: &str) -> Option<(usize, usize)> {
        let anchor = crate::binding_identity::rust_binding_anchor(binder, source)?;
        Some((anchor.start_byte, anchor.end_byte))
    }

    fn logical_binding_anchors(
        &self,
        binders: &[Node<'_>],
        source: &str,
    ) -> Vec<Option<(usize, usize)>> {
        let Some(first) = binders.first() else {
            return Vec::new();
        };
        let mut root = *first;
        while let Some(parent) = root.parent() {
            root = parent;
        }
        crate::binding_identity::rust_binding_anchors(root, source, binders)
            .0
            .into_iter()
            .map(|anchor| anchor.map(|anchor| (anchor.start_byte, anchor.end_byte)))
            .collect()
    }

    fn binding_syntax(
        &self,
        binder: Node<'_>,
    ) -> Option<brokk_bifrost_core::analyzer::structural::spec::BindingSyntax> {
        crate::binding_identity::rust_binding_syntax(binder)
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
            // Bare match/let-condition patterns and `&C` need lexical
            // selection before their occurrence class can be published.
            let ambiguous_pattern = rust_occurrence_needs_binding_verdict(node, role);
            if ambiguous_pattern {
                match sink
                    .binding_candidate_verdict_at(node.id())
                    .unwrap_or(brokk_bifrost_core::analyzer::structural::spec::BindingCandidateVerdict::Open)
                {
                    brokk_bifrost_core::analyzer::structural::spec::BindingCandidateVerdict::Binding => {
                        sink.occurrence_role(node, OccurrenceRole::Binder);
                    }
                    brokk_bifrost_core::analyzer::structural::spec::BindingCandidateVerdict::ValueItem => {
                        sink.occurrence_role(node, OccurrenceRole::PatternPosition);
                    }
                    brokk_bifrost_core::analyzer::structural::spec::BindingCandidateVerdict::Open => {
                        // The paired roles are a query-time completeness gap:
                        // either a binding or a matched value item may exist.
                        sink.occurrence_role(node, OccurrenceRole::Binder);
                        sink.occurrence_role(node, OccurrenceRole::PatternPosition);
                    }
                }
            } else {
                sink.occurrence_role(node, role);
            }
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
                if node.kind() == "attribute"
                    && let Some(arguments) = node.child_by_field_name("arguments")
                {
                    attach_attribute_arguments(sink, arguments);
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
                    // A compound assignment names its operator; a plain one
                    // spells `=` as an anonymous token.
                    let operator = node.child_by_field_name("operator").or_else(|| {
                        let mut cursor = node.walk();
                        node.children(&mut cursor).find(|child| child.kind() == "=")
                    });
                    if let Some(operator) = operator {
                        sink.role_named(Role::Operator, operator, operator);
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
        let tree = parse_rust_tree_for_test(source).expect("Rust tree");
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
        let (_, roles, _, _, stop) = sink.into_parts();
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
                .map(|role| match role.target {
                    brokk_bifrost_core::analyzer::structural::spec::PendingRoleTargetKind::Node(
                        id,
                    ) => id,
                    brokk_bifrost_core::analyzer::structural::spec::PendingRoleTargetKind::Span =>
                        panic!("call argument has a node target"),
                })
                .collect::<Vec<_>>(),
            calls.into_iter().map(|(_, id)| id).collect::<Vec<_>>()
        );
    }
}

#[cfg(test)]
mod binding_activation_tests {
    use super::{
        RUST_STRUCTURAL_SPEC, nearest_ancestor, node_range, parse_rust_tree_for_test,
        rust_binding_activation, rust_occurrence_needs_binding_verdict, rust_occurrence_role,
    };
    use brokk_bifrost_core::analyzer::Range;
    use brokk_bifrost_core::analyzer::structural::occurrences::OccurrenceRole;
    use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;
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
            "    if let Some(guarded) = first && guarded > 0 {\n",
            "        let _ = guarded;\n",
            "    }\n",
            "}\n",
        );
        let tree = parse_rust_tree_for_test(source).expect("Rust tree");
        let root = tree.root_node();
        assert!(!root.has_error(), "{}", root.to_sexp());
        let scope = Range {
            start_byte: root.start_byte(),
            end_byte: root.end_byte(),
            start_line: root.start_position().row + 1,
            end_line: root.end_position().row + 1,
        };
        let conditions = nodes_of_kind(root, "let_condition");
        assert_eq!(conditions.len(), 3);

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
            assert_eq!(activation.activation.start_byte, condition.end_byte());
            assert_eq!(activation.activation.end_byte, body.end_byte());
            if &source[binder.byte_range()] == "guarded" {
                let guard_use = source.find("guarded > 0").unwrap();
                assert!(activation.activation.start_byte <= guard_use);
                assert!(guard_use < activation.activation.end_byte);
            }
        }
    }

    #[test]
    fn trait_signature_parameters_are_not_value_bindings() {
        let source = "trait T { fn declared(&self, unused: i32); fn defined(&self, live: i32) { let _ = live; } }";
        let tree = parse_rust_tree_for_test(source).expect("Rust tree");
        let root = tree.root_node();
        assert!(!root.has_error(), "{}", root.to_sexp());
        let scope = node_range(root);
        let parameters = nodes_of_kind(root, "parameter");
        assert_eq!(parameters.len(), 2);
        let names: Vec<_> = parameters
            .iter()
            .map(|parameter| {
                let pattern = parameter.child_by_field_name("pattern").unwrap();
                let name = &source[pattern.byte_range()];
                (name, rust_binding_activation(pattern, scope).is_some())
            })
            .collect();
        assert_eq!(names, [("unused", false), ("live", true)]);
    }

    #[test]
    #[hardwon("#10389: bodyless trait signatures exclude only their own formals")]
    fn trait_signature_const_expression_local_is_not_excluded() {
        let source =
            "trait T { fn f(x: [u8; { let n = 1; let _c = |nested: usize| nested; n }]); }";
        let tree = parse_rust_tree_for_test(source).unwrap();
        let root = tree.root_node();
        assert!(!root.has_error(), "{}", root.to_sexp());
        let identifiers = nodes_of_kind(root, "identifier");
        let binder = |name: &str| {
            identifiers
                .iter()
                .copied()
                .find(|node| &source[node.byte_range()] == name)
                .unwrap()
        };
        assert!(RUST_STRUCTURAL_SPEC.binding_candidate_excluded(binder("x")));
        assert!(!RUST_STRUCTURAL_SPEC.binding_candidate_excluded(binder("n")));
        assert!(!RUST_STRUCTURAL_SPEC.binding_candidate_excluded(binder("nested")));
    }

    #[test]
    #[hardwon("#10389: reference parameter patterns retain irrefutable binders")]
    fn reference_parameter_patterns_are_bindings_unless_a_value_item_wins() {
        use brokk_bifrost_core::analyzer::structural::spec::BindingCandidateVerdict;
        let source = "const X: i32 = 0; fn f(&x: &i32, &(a, b): &(i32, i32), &X: &i32) {} fn g() { let _closure = |&y: &i32| y; }";
        let tree = parse_rust_tree_for_test(source).unwrap();
        let root = tree.root_node();
        assert!(!root.has_error(), "{}", root.to_sexp());
        for (name, expected) in [
            ("x", BindingCandidateVerdict::Binding),
            ("a", BindingCandidateVerdict::Binding),
            ("b", BindingCandidateVerdict::Binding),
            ("y", BindingCandidateVerdict::Binding),
            ("X", BindingCandidateVerdict::ValueItem),
        ] {
            let binder = nodes_of_kind(root, "identifier")
                .into_iter()
                .find(|node| {
                    &source[node.byte_range()] == name
                        && nearest_ancestor(*node, |kind| kind == "reference_pattern").is_some()
                })
                .expect(name);
            assert_eq!(
                RUST_STRUCTURAL_SPEC.binding_candidate_verdict(root, source, binder),
                expected,
                "{name}"
            );
        }
    }

    #[test]
    #[hardwon("#10389: shorthand field pattern selects a visible constant")]
    fn shorthand_field_pattern_checks_lexical_value_items() {
        use brokk_bifrost_core::analyzer::structural::spec::BindingCandidateVerdict;
        let source =
            "const X: i32 = 0; struct P { X: i32 } fn f(p: P) { match p { P { X } => {} } }";
        let tree = parse_rust_tree_for_test(source).unwrap();
        let root = tree.root_node();
        assert!(!root.has_error(), "{}", root.to_sexp());
        let binder = nodes_of_kind(root, "shorthand_field_identifier")
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(
            RUST_STRUCTURAL_SPEC.binding_candidate_verdict(root, source, binder),
            BindingCandidateVerdict::ValueItem
        );
    }

    #[test]
    #[hardwon("#10389: bare or alternatives are binder candidates with one anchor")]
    fn bare_or_alternatives_have_binding_roles_and_one_anchor() {
        let source = "fn f(v: i32) { match v { x | x => { let _ = x; } } }";
        let tree = parse_rust_tree_for_test(source).unwrap();
        let root = tree.root_node();
        assert!(!root.has_error(), "{}", root.to_sexp());
        let alternatives: Vec<_> = nodes_of_kind(root, "identifier")
            .into_iter()
            .filter(|node| node.parent().is_some_and(|p| p.kind() == "or_pattern"))
            .collect();
        assert_eq!(alternatives.len(), 2);
        let context = RUST_STRUCTURAL_SPEC.call_site_context(root, source);
        for alternative in &alternatives {
            assert_eq!(
                rust_occurrence_role(*alternative),
                Some(OccurrenceRole::Binder)
            );
            assert_eq!(
                context.binding_candidate_verdict_at(alternative.id()),
                Some(brokk_bifrost_core::analyzer::structural::spec::BindingCandidateVerdict::Binding)
            );
        }
        let anchors = RUST_STRUCTURAL_SPEC.logical_binding_anchors(&alternatives, source);
        assert_eq!(anchors[0], anchors[1]);
        assert!(anchors[0].is_some());
    }

    #[test]
    #[hardwon("#10389: bare or-pattern constants and globs keep honest verdicts")]
    fn bare_or_alternatives_respect_value_items_and_open_imports() {
        use brokk_bifrost_core::analyzer::structural::spec::BindingCandidateVerdict;
        for (prefix, expected) in [
            ("const MAX: i32 = 1;", BindingCandidateVerdict::ValueItem),
            ("use dep::*;", BindingCandidateVerdict::Open),
        ] {
            let source = format!("{prefix} fn f(v: i32) {{ match v {{ MAX | MAX => () }} }}");
            let tree = parse_rust_tree_for_test(&source).unwrap();
            let root = tree.root_node();
            let alternatives: Vec<_> = nodes_of_kind(root, "identifier")
                .into_iter()
                .filter(|node| node.parent().is_some_and(|p| p.kind() == "or_pattern"))
                .collect();
            assert_eq!(alternatives.len(), 2);
            for alternative in alternatives {
                assert_eq!(
                    RUST_STRUCTURAL_SPEC.binding_candidate_verdict(root, &source, alternative),
                    expected
                );
            }
        }
    }

    #[test]
    #[hardwon("#10389: nested refutable identifiers select value items or stay Open")]
    fn nested_refutable_identifiers_check_lexical_items() {
        use brokk_bifrost_core::analyzer::structural::spec::BindingCandidateVerdict;
        let source = "const MAX: i32 = 1; fn f(v: Option<i32>, pair: (i32, i32)) { match v { Some(MAX) => (), Some(x) => () } match pair { (MAX, x) => () } }";
        let tree = parse_rust_tree_for_test(source).unwrap();
        let root = tree.root_node();
        assert!(!root.has_error(), "{}", root.to_sexp());
        let context = RUST_STRUCTURAL_SPEC.call_site_context(root, source);
        let patterns: Vec<_> = nodes_of_kind(root, "identifier")
            .into_iter()
            .filter(|node| nearest_ancestor(*node, |kind| kind == "match_pattern").is_some())
            .collect();
        let max: Vec<_> = patterns
            .iter()
            .copied()
            .filter(|node| &source[node.byte_range()] == "MAX")
            .collect();
        assert_eq!(max.len(), 2);
        for node in max {
            assert_eq!(
                RUST_STRUCTURAL_SPEC.binding_candidate_verdict(root, source, node),
                BindingCandidateVerdict::ValueItem
            );
            assert_eq!(
                context.binding_candidate_verdict_at(node.id()),
                Some(BindingCandidateVerdict::ValueItem)
            );
        }
        let x: Vec<_> = patterns
            .iter()
            .copied()
            .filter(|node| &source[node.byte_range()] == "x")
            .collect();
        assert_eq!(x.len(), 2);
        for node in x {
            assert_eq!(
                RUST_STRUCTURAL_SPEC.binding_candidate_verdict(root, source, node),
                BindingCandidateVerdict::Binding
            );
            assert_eq!(
                context.binding_candidate_verdict_at(node.id()),
                Some(BindingCandidateVerdict::Binding)
            );
        }
    }

    // The Rust unused-variable binding-facts fixture, copied here because this
    // crate is public and the shared fixture tree is not.
    const UNUSED_VARIABLE_BINDERS: &str = r#"#![allow(dead_code, unused_variables, unused_assignments)]

fn plain(used_parameter: i32, unused_parameter: i32) {
    let unused_uninitialized: i32;
    let initialized = 1;
    let _ignored: i32;
    let used = used_parameter;
    let used = used + 1;
    let assigned: i32;
    assigned = 2;
    let _ = (used, assigned);
}

fn closure_parameters() {
    let closure = |used_closure: i32, unused_closure: i32| {
        let _ = used_closure;
    };
    let _ = closure;
}

fn patterns(input: Option<(i32, i32)>, values: Vec<i32>) {
    if let Some((if_used, if_unused)) = input {
        let _ = if_used;
    }
    for loop_unused in values {
        let nested = 1;
        let _ = nested;
    }
    match input {
        Some((match_used, match_unused)) => {
            let _ = match_used;
        }
        None => {}
    }
}

enum Either {
    A(i32),
    B(i32),
}

fn or_pattern(value: Either) {
    match value {
        Either::A(or_unused) | Either::B(or_unused) => {}
    }
}

fn initializer_shapes(value: Option<(i32, i32)>) {
    let (destructured_left, destructured_right) = (1, 2);
    let Some(let_else_name) = value else { return };
    if let Some((if_left, if_right)) = value {}
    if let if_whole = 1 {}
    while let Some(while_name) = value {
        break;
    }
    while let while_whole = 1 {
        break;
    }
}

fn shadowing() {
    let shadowed: i32;
    {
        let shadowed = 1;
        let _ = shadowed;
    }
}

fn captures() {
    let captured = 1;
    let closure = || captured;
    let _ = closure;
}

fn binding_modes() {
    let source = 1;
    let ref by_ref = source;
    let ref mut by_ref_mut = source;
    let _x: i32;
}

struct Receiver;

impl Receiver {
    fn method(&self, method_unused: i32) {}
}

fn exclusion_shapes(value: Option<i32>) {
    match value {
        Some(UPPERCASE_ARM) => {}
        None => {}
    }
    match value {
        NESTED_UPPERCASE | NESTED_UPPERCASE => {}
    }
    let before_todo: i32;
    todo!();
}

macro_rules! use_value {
    ($name:ident) => {
        let _ = $name;
    };
}

macro_rules! make_binding {
    () => {
        let macro_binder: i32;
    };
}

fn macro_access() {
    let macro_value = 1;
    use_value!(macro_value);
    make_binding!();
}
"#;

    #[test]
    #[hardwon("#10389: batched Rust binder selection preserves per-node verdicts")]
    fn batch_binding_verdicts_match_per_node_fixture_answers() {
        for source in [
            UNUSED_VARIABLE_BINDERS,
            "const C: i32 = 1; struct P { C: i32 } fn f(v: P) { match v { P { C } => {} } }",
            "const C: i32 = 1; fn f(v: i32) { use dep::*; match v { C => {}, x => {} } }",
            "fn f(&x: &i32, &(a, b): &(i32, i32)) { let _ = (x, a, b); }",
        ] {
            let tree = parse_rust_tree_for_test(source).unwrap();
            let root = tree.root_node();
            let binders: Vec<_> = nodes_of_kind(root, "identifier")
                .into_iter()
                .chain(nodes_of_kind(root, "shorthand_field_identifier"))
                .filter(|node| rust_occurrence_role(*node) == Some(OccurrenceRole::Binder))
                .collect();
            let batch = RUST_STRUCTURAL_SPEC.binding_candidate_verdicts(root, source, &binders);
            let per_node: Vec<_> = binders
                .iter()
                .map(|binder| RUST_STRUCTURAL_SPEC.binding_candidate_verdict(root, source, *binder))
                .collect();
            assert_eq!(batch, per_node, "{source}");
            let extraction_context = RUST_STRUCTURAL_SPEC.call_site_context(root, source);
            for (&binder, &verdict) in binders.iter().zip(&per_node) {
                if rust_occurrence_needs_binding_verdict(binder, OccurrenceRole::Binder) {
                    assert_eq!(
                        extraction_context.binding_candidate_verdict_at(binder.id()),
                        Some(verdict),
                        "{source}"
                    );
                }
            }
        }
    }

    #[test]
    #[hardwon("#10389: strict Rust pattern scope scans grow linearly with functions")]
    fn strict_pattern_scope_index_scans_file_once_for_many_functions() {
        let mut source = String::new();
        for index in 0..128 {
            use std::fmt::Write as _;
            writeln!(
                source,
                "fn f{index}(v: i32) {{ match v {{ x{index} => () }} }}"
            )
            .unwrap();
        }
        let tree = parse_rust_tree_for_test(&source).unwrap();
        let root = tree.root_node();
        let binders: Vec<_> = nodes_of_kind(root, "identifier")
            .into_iter()
            .filter(|node| {
                node.parent()
                    .is_some_and(|parent| parent.kind() == "match_pattern")
            })
            .collect();
        assert_eq!(binders.len(), 128);
        let mut index = crate::lexical_scope::RustStrictPatternIndex::default();
        for binder in binders {
            assert_eq!(
                index.classify(root, &source, binder),
                crate::lexical_scope::RustPatternName::Binding
            );
        }
        assert_eq!(index.source_file_scans, 1);
        assert!(index.scope_scans <= 128 * 16, "{}", index.scope_scans);
    }

    #[test]
    #[hardwon("#10389: Rust binding prewalk honors cancellation and fact budget")]
    fn binding_context_preparation_stops_before_unbounded_scan() {
        use brokk_bifrost_core::analyzer::structural::collector::StructuralFactCollectorStop;
        let source = (0..128)
            .map(|i| format!("fn f{i}(v: i32) {{ match v {{ x{i} => () }} }}"))
            .collect::<Vec<_>>()
            .join("\n");
        let tree = parse_rust_tree_for_test(&source).unwrap();
        let token = brokk_bifrost_core::CancellationToken::new();
        token.cancel();
        assert!(matches!(
            RUST_STRUCTURAL_SPEC.call_site_context_limited(
                tree.root_node(),
                &source,
                usize::MAX,
                Some(&token)
            ),
            Err(StructuralFactCollectorStop::Cancelled)
        ));
        assert!(
            RUST_STRUCTURAL_SPEC
                .call_site_context_limited(tree.root_node(), &source, 10, None)
                .is_ok()
        );
        let huge = (0..16_000)
            .map(|i| format!("fn f{i}(v: i32) {{ match v {{ x{i} => () }} }}"))
            .collect::<Vec<_>>()
            .join("\n");
        let huge_tree = parse_rust_tree_for_test(&huge).unwrap();
        let context = RUST_STRUCTURAL_SPEC
            .call_site_context_limited(huge_tree.root_node(), &huge, 10, None)
            .unwrap();
        let unbounded_context = RUST_STRUCTURAL_SPEC
            .call_site_context_limited(huge_tree.root_node(), &huge, usize::MAX, None)
            .unwrap();
        let first = nodes_of_kind(huge_tree.root_node(), "identifier")
            .into_iter()
            .find(|node| &huge[node.byte_range()] == "x0")
            .unwrap();
        assert_eq!(
            context.binding_candidate_verdict_at(first.id()),
            Some(brokk_bifrost_core::analyzer::structural::spec::BindingCandidateVerdict::Open)
        );
        assert_eq!(
            context.binding_candidate_verdict_at(first.id()),
            unbounded_context.binding_candidate_verdict_at(first.id())
        );
    }

    #[test]
    fn shorthand_field_and_bare_arm_are_binder_candidates() {
        let source = "struct Point { y: i32 } fn f(point: Point) { match point { Point { y } => (), E::Variant => (), p => () } }";
        let tree = parse_rust_tree_for_test(source).unwrap();
        let root = tree.root_node();
        assert!(!root.has_error(), "{}", root.to_sexp());
        let shorthand = nodes_of_kind(root, "shorthand_field_identifier");
        assert_eq!(shorthand.len(), 1);
        assert_eq!(
            rust_occurrence_role(shorthand[0]),
            Some(OccurrenceRole::Binder)
        );
        let bare = nodes_of_kind(root, "identifier")
            .into_iter()
            .find(|node| {
                &source[node.byte_range()] == "p"
                    && node
                        .parent()
                        .is_some_and(|parent| parent.kind() == "match_pattern")
            })
            .unwrap();
        assert_eq!(rust_occurrence_role(bare), Some(OccurrenceRole::Binder));
        let variant = nodes_of_kind(root, "identifier")
            .into_iter()
            .find(|node| &source[node.byte_range()] == "Variant")
            .unwrap();
        assert_eq!(
            rust_occurrence_role(variant),
            Some(OccurrenceRole::PatternPosition)
        );
    }

    #[test]
    #[hardwon("#10389: qualified Rust variant patterns retain references inside wrappers")]
    fn qualified_variant_patterns_are_references_and_bare_names_are_binders() {
        let source = "enum E { A, B } fn f(v: E, r: &E) { match r { &E::A => {}, &E::B => {}, &x => {} } match v { E::A | E::B => {}, a | b => {} } }";
        let tree = parse_rust_tree_for_test(source).unwrap();
        let root = tree.root_node();
        assert!(!root.has_error(), "{}", root.to_sexp());
        for node in nodes_of_kind(root, "identifier") {
            let text = &source[node.byte_range()];
            if matches!(text, "A" | "B") && node.start_byte() > source.find("match r").unwrap() {
                assert_eq!(
                    rust_occurrence_role(node),
                    Some(OccurrenceRole::PatternPosition),
                    "{text}"
                );
            }
            if matches!(text, "x" | "a" | "b") {
                assert_eq!(
                    rust_occurrence_role(node),
                    Some(OccurrenceRole::Binder),
                    "{text}"
                );
            }
        }
    }

    #[test]
    #[hardwon("#10389: local test-module glob preserves built-in test only when proven")]
    fn local_test_glob_checks_parent_exports() {
        for (parent, expected) in [
            ("", "rust_body_preserving_attribute"),
            ("use tokio::*;", "rust_opaque_attribute"),
            ("macro_rules! test { () => {} }", "rust_opaque_attribute"),
        ] {
            let source = format!(
                "{parent} mod tests {{ use super::*; #[test] fn t() {{ let unused = 1; }} }}"
            );
            let tree = parse_rust_tree_for_test(&source).unwrap();
            let context = RUST_STRUCTURAL_SPEC.call_site_context(tree.root_node(), &source);
            let attribute = nodes_of_kind(tree.root_node(), "attribute")
                .into_iter()
                .next()
                .unwrap();
            assert!(
                RUST_STRUCTURAL_SPEC.generator_construct_with_context(
                    attribute,
                    brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind::Decorator,
                    &source,
                    &context,
                ) == Some(expected),
                "{source}"
            );
        }
        for (source, expected) in [
            (
                "mod tests { use tokio::test; #[test] fn t() { let x = 1; } }",
                "rust_opaque_attribute",
            ),
            (
                "#[test] fn t() { let x = 1; }",
                "rust_body_preserving_attribute",
            ),
            (
                "#[cfg_attr(test, test)] fn t() { let x = 1; }",
                "rust_body_preserving_attribute",
            ),
        ] {
            let tree = parse_rust_tree_for_test(source).unwrap();
            let context = RUST_STRUCTURAL_SPEC.call_site_context(tree.root_node(), source);
            let attribute = nodes_of_kind(tree.root_node(), "attribute")
                .into_iter()
                .next()
                .unwrap();
            assert_eq!(
                RUST_STRUCTURAL_SPEC.generator_construct_with_context(
                    attribute,
                    brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind::Decorator,
                    source,
                    &context,
                ),
                Some(expected),
                "{source}"
            );
        }
    }

    #[test]
    #[hardwon("#10389: nested test attribute cannot reuse a source-file verdict by byte offset")]
    fn nested_test_attribute_checks_source_file_scope() {
        let source = "fn outer() { #[test] fn t() { let x = 1; } } use some_proc_macro::test;";
        let tree = parse_rust_tree_for_test(source).unwrap();
        let context = RUST_STRUCTURAL_SPEC.call_site_context(tree.root_node(), source);
        let attribute = nodes_of_kind(tree.root_node(), "attribute")
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(
            RUST_STRUCTURAL_SPEC.generator_construct_with_context(
                attribute,
                brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind::Decorator,
                source,
                &context,
            ),
            Some("rust_opaque_attribute")
        );
    }

    #[test]
    #[hardwon("#10389: let-else constant patterns are values while bare names bind")]
    fn refutable_let_else_uses_strict_pattern_selection() {
        use brokk_bifrost_core::analyzer::structural::spec::BindingCandidateVerdict;
        let source = "const MAX: i32 = 1; fn f(v: Option<i32>) { let Some(MAX) = v else { return }; let _ = MAX; let Some(x) = v else { return }; let _ = x; }";
        let tree = parse_rust_tree_for_test(source).unwrap();
        let root = tree.root_node();
        let context = RUST_STRUCTURAL_SPEC.call_site_context(root, source);
        for node in nodes_of_kind(root, "identifier") {
            if node.start_byte() < source.find("let Some(MAX)").unwrap() {
                continue;
            }
            match &source[node.byte_range()] {
                "MAX" if node.start_byte() == source.find("let Some(MAX)").unwrap() + 9 => {
                    assert_eq!(
                        context.binding_candidate_verdict_at(node.id()),
                        Some(BindingCandidateVerdict::ValueItem)
                    );
                }
                "x" if node.start_byte() == source.find("let Some(x)").unwrap() + 9 => {
                    assert_eq!(
                        context.binding_candidate_verdict_at(node.id()),
                        Some(BindingCandidateVerdict::Binding)
                    );
                }
                _ => {}
            }
        }
    }

    #[test]
    #[hardwon("#10389: test attribute scope prewalk scans a module once")]
    fn test_attribute_scope_preparation_is_linear_and_bounded() {
        let source = format!(
            "mod tests {{ use super::*; {} }}",
            (0..128)
                .map(|i| format!("#[test] fn t{i}() {{ let unused = {i}; }}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
        let tree = parse_rust_tree_for_test(&source).unwrap();
        let context = RUST_STRUCTURAL_SPEC.call_site_context(tree.root_node(), &source);
        assert!(
            context.test_attribute_scope_scans() <= 4,
            "{}",
            context.test_attribute_scope_scans()
        );

        let huge = format!(
            "{}#[test] fn t() {{ let unused = 1; }}",
            (0..40_000)
                .map(|i| format!("const C{i}: i32 = {i};"))
                .collect::<Vec<_>>()
                .join("\n")
        );
        let tree = parse_rust_tree_for_test(&huge).unwrap();
        let context = RUST_STRUCTURAL_SPEC
            .call_site_context_limited(tree.root_node(), &huge, 100_000, None)
            .unwrap();
        let attribute = nodes_of_kind(tree.root_node(), "attribute")
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(
            RUST_STRUCTURAL_SPEC.generator_construct_with_context(
                attribute,
                brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind::Decorator,
                &huge,
                &context
            ),
            Some("rust_opaque_attribute")
        );
    }

    #[test]
    fn strict_bare_patterns_keep_value_items_and_named_struct_bindings_distinct() {
        use brokk_bifrost_core::analyzer::structural::spec::BindingCandidateVerdict;
        let source = "const C: i32 = 1; struct S { field: i32 } fn f(v: i32) { match v { C => {}, S => {}, &C => {}, _ => {} } }";
        let tree = parse_rust_tree_for_test(source).unwrap();
        let root = tree.root_node();
        assert!(!root.has_error(), "{}", root.to_sexp());
        for (name, expected) in [
            ("C", BindingCandidateVerdict::ValueItem),
            ("S", BindingCandidateVerdict::Binding),
        ] {
            let pattern = nodes_of_kind(root, "identifier")
                .into_iter()
                .find(|node| {
                    &source[node.byte_range()] == name
                        && node
                            .parent()
                            .is_some_and(|parent| parent.kind() == "match_pattern")
                })
                .unwrap();
            assert_eq!(
                RUST_STRUCTURAL_SPEC.binding_candidate_verdict(root, source, pattern),
                expected,
                "{name}"
            );
            if name == "S" {
                let mut charge = |_: usize| Ok::<(), ()>(());
                assert_eq!(
                    crate::lexical_scope::rust_pattern_name_bounded(
                        root,
                        source,
                        pattern,
                        &mut charge,
                    ),
                    Ok(crate::lexical_scope::RustPatternName::Binding)
                );
            }
        }
        let reference_constant = nodes_of_kind(root, "identifier")
            .into_iter()
            .find(|node| {
                &source[node.byte_range()] == "C"
                    && node
                        .parent()
                        .is_some_and(|parent| parent.kind() == "reference_pattern")
            })
            .unwrap();
        assert_eq!(
            RUST_STRUCTURAL_SPEC.binding_candidate_verdict(root, source, reference_constant),
            BindingCandidateVerdict::ValueItem
        );
        let mut charge = |_: usize| Ok::<(), ()>(());
        assert_eq!(
            crate::lexical_scope::rust_pattern_name_bounded(
                root,
                source,
                reference_constant,
                &mut charge,
            ),
            Ok(crate::lexical_scope::RustPatternName::ValueItem)
        );
    }

    #[test]
    fn inner_glob_keeps_outer_constant_pattern_open() {
        use brokk_bifrost_core::analyzer::structural::spec::BindingCandidateVerdict;
        let source = "const C: i32 = 1; fn f(v: i32) { use dep::*; match v { C => {}, _ => {} } }";
        let tree = parse_rust_tree_for_test(source).unwrap();
        let root = tree.root_node();
        assert!(!root.has_error(), "{}", root.to_sexp());
        let pattern = nodes_of_kind(root, "identifier")
            .into_iter()
            .find(|node| {
                &source[node.byte_range()] == "C"
                    && node
                        .parent()
                        .is_some_and(|parent| parent.kind() == "match_pattern")
            })
            .unwrap();
        assert_eq!(
            RUST_STRUCTURAL_SPEC.binding_candidate_verdict(root, source, pattern),
            BindingCandidateVerdict::Open
        );
    }

    #[test]
    fn named_field_struct_does_not_hide_outer_value_item() {
        use brokk_bifrost_core::analyzer::structural::spec::BindingCandidateVerdict;
        let source = "const S: i32 = 1; fn f(v: i32) { struct S { field: i32 } match v { S => {}, _ => {} } }";
        let tree = parse_rust_tree_for_test(source).unwrap();
        let root = tree.root_node();
        assert!(!root.has_error(), "{}", root.to_sexp());
        let pattern = nodes_of_kind(root, "identifier")
            .into_iter()
            .find(|node| {
                &source[node.byte_range()] == "S"
                    && node
                        .parent()
                        .is_some_and(|parent| parent.kind() == "match_pattern")
            })
            .unwrap();
        assert_eq!(
            RUST_STRUCTURAL_SPEC.binding_candidate_verdict(root, source, pattern),
            BindingCandidateVerdict::ValueItem
        );
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

    #[test]
    fn constant_pattern_keeps_reference_occurrence_when_binding_is_excluded() {
        let source = "const C: i32 = 1; fn f(v: i32) { match v { C => {}, &C => {}, x if x > 0 => {}, _ => {} } }";
        let parsed = parse_rust_fixture(source);
        let source_facts = parsed.source_facts.as_ref().unwrap();
        let facts = &source_facts.structural;
        for marker in ["C =>", "&C =>"] {
            let start = source.find(marker).unwrap() + usize::from(marker.starts_with('&'));
            let node = facts
                .nodes()
                .iter()
                .position(|node| {
                    let range = source_facts.occurrences.occurrence(node.occurrence).range;
                    range.start_byte == start && range.end_byte == start + 1
                })
                .unwrap() as u32;
            let roles = facts.occurrence_roles(node);
            assert!(
                !roles.contains(&OccurrenceRole::Binder),
                "{marker}: {roles:?}"
            );
            assert!(
                roles.contains(&OccurrenceRole::PatternPosition),
                "{marker}: {roles:?}"
            );
        }
        let guard = source.find("if x >").unwrap() + 3;
        let node = facts
            .nodes()
            .iter()
            .position(|node| {
                let range = source_facts.occurrences.occurrence(node.occurrence).range;
                range.start_byte == guard && range.end_byte == guard + 1
            })
            .unwrap() as u32;
        assert!(
            facts
                .occurrence_roles(node)
                .contains(&OccurrenceRole::ValueReference)
        );
    }

    #[test]
    fn let_condition_constant_and_imported_match_pattern_keep_reference_possibility() {
        let source = "const C: i32 = 1; use dep::D; fn f(v: i32) { if let C = v {} match v { D => {}, _ => {} } }";
        let parsed = parse_rust_fixture(source);
        let source_facts = parsed.source_facts.as_ref().unwrap();
        let facts = &source_facts.structural;
        for (marker, expect_binder) in [("C = v", false), ("D =>", true)] {
            let start = source.find(marker).unwrap();
            let node = facts
                .nodes()
                .iter()
                .position(|node| {
                    let range = source_facts.occurrences.occurrence(node.occurrence).range;
                    range.start_byte == start && range.end_byte == start + 1
                })
                .unwrap() as u32;
            let roles = facts.occurrence_roles(node);
            assert_eq!(
                roles.contains(&OccurrenceRole::Binder),
                expect_binder,
                "{marker}: {roles:?}"
            );
            assert!(
                roles.contains(&OccurrenceRole::PatternPosition),
                "{marker}: {roles:?}"
            );
        }
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
        let tree = parse_rust_tree_for_test(source).expect("Rust tree");
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
            let (_, roles, _, _, stop) = sink.into_parts();
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
            let (_, roles, _, _, stop) = sink.into_parts();
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
        let tree = parse_rust_tree_for_test(source).expect("Rust grammar");
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
    use super::parse_rust_tree_for_test;
    #[test]
    fn grammar_derive_and_ordinary_attribute_arguments() {
        for (attribute, expected) in [("derive", true), ("allow", false), ("custom", false)] {
            let source = format!("#[{attribute}(Marker)] struct Item;");
            let tree = parse_rust_tree_for_test(&source).unwrap();
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
            let (_, roles, _, _, stop) = sink.into_parts();
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

#[cfg(test)]
fn parse_rust_tree_for_test(source: &str) -> Option<tree_sitter::Tree> {
    // Standalone fixtures have no analyzer owner; retain nothing across calls.
    let caches = crate::lexical_scope::RustLexicalCaches::new(
        &brokk_bifrost_core::retention_budget::RetentionBudget::retain_nothing(),
    );
    crate::lexical_scope::parse_rust_tree_with(&caches, source)
}
