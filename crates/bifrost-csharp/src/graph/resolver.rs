use crate::declarations::CSHARP_IDENTIFIER_SIGIL;
use crate::graph::CSharpGraphSource;
use crate::graph_support::{self, CSharpSource};
use crate::hierarchy;
use crate::syntax::{
    CSharpMemberName, CSharpRelationalGenericCall, csharp_callable_arity,
    csharp_conditional_member_access, csharp_member_name, csharp_method_generic_arity,
    csharp_normalize_full_name, csharp_signature_return_type, csharp_source_identifier,
    csharp_type_leftmost_identifier, csharp_type_node_identity, csharp_type_reference_root,
    csharp_using_directive_is_global, csharp_using_directive_is_static,
    csharp_using_directive_namespace, csharp_using_directive_target,
};
use brokk_bifrost_core::analyzer::model::{
    CallableArity, SignatureMetadata, StructuredTypeIdentity, StructuredTypeName,
};
use brokk_bifrost_core::analyzer::query_batch::LimitedQueryRows;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
pub(super) use brokk_bifrost_core::analyzer::usages::common::same_node;

/// Trimmed C# node text with the verbatim-identifier `@` sigil normalized off
/// identifier tokens (`@class` -> `class`). Declaration short/fq names already
/// strip `@` when built, so the reference/get-definition side must strip it too
/// for a verbatim-identifier usage to resolve to its declaration (previously it
/// did not — the same normalization-agreement class as Rust's `r#`). Gated to
/// the `identifier` kind so `@"..."` verbatim strings and attribute markers are
/// untouched.
pub fn node_text<'a>(node: tree_sitter::Node<'_>, source: &'a str) -> &'a str {
    brokk_bifrost_core::analyzer::common::node_ident_text(
        node,
        source,
        true,
        &CSHARP_IDENTIFIER_SIGIL,
    )
}
use brokk_bifrost_core::analyzer::usages::inverted_edges::ClassRangeIndex;
use brokk_bifrost_core::analyzer::usages::local_inference::{
    LocalInferenceEngine, SymbolResolution,
};
use brokk_bifrost_core::analyzer::usages::parsed_tree::parse_tree_sitter_file;
use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
use brokk_bifrost_core::analyzer::{CodeUnit, Language, ProjectFile};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use std::sync::Arc;
use tree_sitter::Node;

fn resolution_scope_step(session: Option<&ResolutionSession>) -> bool {
    session.is_none_or(ResolutionSession::scope_step)
}

fn resolution_query<T>(
    session: Option<&ResolutionSession>,
    query: impl FnOnce() -> T,
) -> Option<T> {
    match session {
        Some(session) => session.query(query),
        None => Some(query()),
    }
}

fn resolution_query_rows<T>(
    session: Option<&ResolutionSession>,
    query: impl FnOnce() -> Vec<T>,
) -> Vec<T> {
    match session {
        Some(session) => session.query_rows(query),
        None => query(),
    }
}

fn resolution_query_limited_rows<T>(
    session: Option<&ResolutionSession>,
    limited_query: impl FnOnce(usize) -> LimitedQueryRows<T>,
    unbounded_query: impl FnOnce() -> Vec<T>,
) -> Vec<T> {
    match session {
        Some(session) => session.query_limited_rows(limited_query),
        None => unbounded_query(),
    }
}

fn resolution_summary_rows<T>(
    session: Option<&ResolutionSession>,
    query: impl FnOnce() -> Vec<T>,
) -> Vec<T> {
    match session {
        Some(session) => session.summary_rows(query),
        None => query(),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    Type,
    Constructor,
    Method,
    Field,
}

pub struct TargetSpec {
    pub target: CodeUnit,
    pub(super) kind: TargetKind,
    pub(super) owner: CodeUnit,
    pub(super) member_name: String,
    pub(super) callable_arity: Option<CallableArity>,
    pub(super) generic_arity: Option<usize>,
    pub(super) is_extension_method: bool,
}

impl TargetSpec {
    pub fn from_target(graph: &CSharpGraphSource<'_>, target: &CodeUnit) -> Option<Self> {
        if target.is_class() {
            return Some(Self {
                target: target.clone(),
                kind: TargetKind::Type,
                owner: target.clone(),
                member_name: csharp_source_identifier(target).to_string(),
                callable_arity: None,
                generic_arity: None,
                is_extension_method: false,
            });
        }

        let owner = graph.index.parent_of(target)?;
        let kind = if target.is_field() {
            TargetKind::Field
        } else if target.identifier() == csharp_source_identifier(&owner) {
            TargetKind::Constructor
        } else {
            TargetKind::Method
        };

        Some(Self {
            target: target.clone(),
            kind,
            owner,
            member_name: target.identifier().to_string(),
            callable_arity: (kind == TargetKind::Method || kind == TargetKind::Constructor)
                .then(|| csharp_callable_arity(graph.index, target)),
            generic_arity: (kind == TargetKind::Method)
                .then(|| csharp_method_generic_arity(target.signature())),
            is_extension_method: kind == TargetKind::Method && is_extension_method(graph, target),
        })
    }

    pub(super) fn is_extension_method(&self) -> bool {
        self.is_extension_method
    }

    pub(super) fn accepts_explicit_generic_arity(&self, arity: Option<usize>) -> bool {
        arity.is_none_or(|arity| self.generic_arity == Some(arity))
    }
}

pub fn seed_visible_bindings_at(
    scope: Node<'_>,
    target: Node<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
) {
    seed_visible_bindings_inner(scope, target, csharp, token, file, source, bindings);
}

pub fn seed_bindings_before(
    node: Node<'_>,
    cutoff_start: usize,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<CSharpDeclaredType>,
) {
    seed_bindings_before_inner(node, cutoff_start, csharp, token, file, source, bindings);
}

#[allow(clippy::too_many_arguments)]
pub fn seed_bindings_before_in_session(
    node: Node<'_>,
    cutoff_start: usize,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<CSharpDeclaredType>,
    session: &ResolutionSession,
) {
    // Mirror `seed_bindings_before_inner` iteratively so deep local syntax is
    // stack-safe and each visited node is charged exactly once.
    let mut stack = vec![(node, 0usize)];
    while let Some((current, next_child)) = stack.pop() {
        if next_child == 0 {
            if current.start_byte() >= cutoff_start || !session.scope_step() {
                continue;
            }
            match current.kind() {
                "parameter" => {
                    seed_parameter_in_session(
                        current, csharp, token, file, source, bindings, session,
                    );
                    if !session.observe_cancellation() {
                        return;
                    }
                }
                "variable_declaration" => {
                    seed_variable_declaration_in_session(
                        current, csharp, token, file, source, bindings, session,
                    );
                    if !session.observe_cancellation() {
                        return;
                    }
                }
                _ => {}
            }
        }
        let Some(child) = current.named_child(next_child) else {
            continue;
        };
        if child.start_byte() >= cutoff_start {
            continue;
        }
        stack.push((current, next_child + 1));
        stack.push((child, 0));
    }
}

fn seed_bindings_before_inner(
    node: Node<'_>,
    cutoff_start: usize,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<CSharpDeclaredType>,
) {
    if node.start_byte() >= cutoff_start {
        return;
    }

    match node.kind() {
        "parameter" => seed_parameter(node, csharp, token, file, source, bindings),
        "variable_declaration" => {
            seed_variable_declaration(node, csharp, token, file, source, bindings)
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.start_byte() >= cutoff_start {
            break;
        }
        seed_bindings_before_inner(child, cutoff_start, csharp, token, file, source, bindings);
    }
}

const SCOPE_NODES: &[&str] = &[
    "method_declaration",
    "constructor_declaration",
    "destructor_declaration",
    "operator_declaration",
    "property_declaration",
    "accessor_declaration",
    "local_function_statement",
    "lambda_expression",
    "block",
    "for_statement",
    "for_each_statement",
    "using_statement",
    "catch_clause",
];

fn seed_visible_bindings_inner(
    node: Node<'_>,
    target: Node<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
) {
    if node.start_byte() >= target.start_byte() {
        return;
    }

    let enters_scope = SCOPE_NODES.contains(&node.kind());
    if enters_scope && !node_covers(node, target) {
        return;
    }
    if enters_scope {
        bindings.enter_scope();
    }

    match node.kind() {
        "parameter" => seed_usage_parameter(node, csharp, token, file, source, bindings),
        "variable_declaration" => {
            seed_usage_variable_declaration(node, csharp, token, file, source, bindings)
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.start_byte() >= target.start_byte() {
            break;
        }
        if SCOPE_NODES.contains(&child.kind()) && !node_covers(child, target) {
            continue;
        }
        seed_visible_bindings_inner(child, target, csharp, token, file, source, bindings);
    }
}

fn node_covers(container: Node<'_>, target: Node<'_>) -> bool {
    container.start_byte() <= target.start_byte() && target.end_byte() <= container.end_byte()
}

fn seed_usage_parameter(
    node: Node<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    seed_usage_symbol_for_type(name_node, type_node, csharp, token, file, source, bindings);
}

fn seed_parameter(
    node: Node<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<CSharpDeclaredType>,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    seed_symbol_for_type(name_node, type_node, csharp, token, file, source, bindings);
}

fn seed_parameter_in_session(
    node: Node<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<CSharpDeclaredType>,
    session: &ResolutionSession,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    seed_symbol_for_type_in_session(
        name_node, type_node, csharp, token, file, source, bindings, session,
    );
}

fn seed_usage_variable_declaration(
    node: Node<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
) {
    if is_member_variable_declaration(node) {
        return;
    }
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    let type_text = reference_type_text(type_node, source);

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "variable_declarator" {
            continue;
        }
        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };
        if type_text == "var" {
            if let Some(initializer_type) = object_created_type(child)
                && let Some(target) = resolve_usage_type_fq_name(
                    csharp,
                    token,
                    file,
                    &reference_type_text(initializer_type, source),
                )
            {
                bindings.seed_symbol(node_text(name_node, source), target);
            } else if let Some(target) =
                var_initializer_member_type(child, csharp, token, file, source, bindings, true)
            {
                bindings.seed_symbol(node_text(name_node, source), target);
            } else {
                bindings.declare_shadow(node_text(name_node, source));
            }
        } else {
            seed_usage_symbol_for_type(name_node, type_node, csharp, token, file, source, bindings);
        }
    }
}

fn seed_variable_declaration(
    node: Node<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<CSharpDeclaredType>,
) {
    if is_member_variable_declaration(node) {
        return;
    }
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    let type_text = reference_type_text(type_node, source);

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "variable_declarator" {
            continue;
        }
        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };
        if type_text == "var" {
            if let Some(initializer_type) = object_created_type(child)
                && let Some(target) = resolve_type_fq_name(
                    csharp,
                    token,
                    file,
                    &reference_type_text(initializer_type, source),
                )
            {
                bindings.seed_symbol(
                    node_text(name_node, source),
                    CSharpDeclaredType::resolved(target),
                );
            } else if let Some(target) =
                var_initializer_member_type(child, csharp, token, file, source, bindings, false)
            {
                bindings.seed_symbol(
                    node_text(name_node, source),
                    CSharpDeclaredType::resolved(target),
                );
            } else {
                bindings.declare_shadow(node_text(name_node, source));
            }
        } else {
            seed_symbol_for_type(name_node, type_node, csharp, token, file, source, bindings);
        }
    }
}

fn seed_variable_declaration_in_session(
    node: Node<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<CSharpDeclaredType>,
    session: &ResolutionSession,
) {
    if is_member_variable_declaration(node) {
        return;
    }
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    let type_text = reference_type_text(type_node, source);

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "variable_declarator" || !session.scope_step() {
            continue;
        }
        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };
        if type_text == "var" {
            if let Some(initializer_type) = object_created_type(child) {
                if let Some(target) = resolve_type_fq_name_in_session(
                    csharp,
                    token,
                    file,
                    &reference_type_text(initializer_type, source),
                    session,
                ) {
                    bindings.seed_symbol(
                        node_text(name_node, source),
                        CSharpDeclaredType::resolved(target),
                    );
                } else {
                    bindings.declare_shadow(node_text(name_node, source));
                }
            } else if variable_declarator_initializer(child).is_some() {
                session.mark_scope_incomplete();
                return;
            } else {
                bindings.declare_shadow(node_text(name_node, source));
            }
        } else {
            seed_symbol_for_type_in_session(
                name_node, type_node, csharp, token, file, source, bindings, session,
            );
        }
    }
}

pub(super) fn is_member_variable_declaration(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        matches!(
            parent.kind(),
            "field_declaration" | "event_field_declaration"
        )
    })
}

fn var_initializer_member_type<T: DeclaredTypeName>(
    declarator: Node<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    bindings: &LocalInferenceEngine<T>,
    usage: bool,
) -> Option<String> {
    let initializer = variable_declarator_initializer(declarator)?;
    expression_type_fq_name_inner(initializer, csharp, token, file, source, bindings, usage)
}

fn variable_declarator_initializer(declarator: Node<'_>) -> Option<Node<'_>> {
    declarator
        .child_by_field_name("value")
        .or_else(|| declarator.child_by_field_name("initializer"))
        .or_else(|| {
            let mut cursor = declarator.walk();
            declarator
                .named_children(&mut cursor)
                .find(|child| child.kind() == "equals_value_clause")
                .and_then(|clause| {
                    clause
                        .child_by_field_name("value")
                        .or_else(|| clause.named_child(0))
                })
        })
        .or_else(|| {
            let name = declarator.child_by_field_name("name")?;
            let mut cursor = declarator.walk();
            declarator
                .named_children(&mut cursor)
                .find(|child| child.start_byte() > name.end_byte())
        })
}

fn expression_type_fq_name<T: DeclaredTypeName>(
    expression: Node<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    bindings: &LocalInferenceEngine<T>,
) -> Option<String> {
    expression_type_fq_name_inner(expression, csharp, token, file, source, bindings, true)
}

fn expression_type_fq_name_inner<T: DeclaredTypeName>(
    expression: Node<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    bindings: &LocalInferenceEngine<T>,
    usage: bool,
) -> Option<String> {
    match expression.kind() {
        "identifier" => {
            let name = node_text(expression, source);
            first_precise_binding(bindings, name).or_else(|| {
                let owner = enclosing_declared_type(expression, csharp, token, file, source)?;
                member_declared_type_fq_name_for_scope(csharp, token, &owner, name, usage)
            })
        }
        "member_access_expression" | "conditional_access_expression" => {
            let (receiver, name_node) = match expression.kind() {
                "member_access_expression" => (
                    member_access_receiver(expression)?,
                    member_access_name(expression)?,
                ),
                _ => {
                    let access = csharp_conditional_member_access(expression)?;
                    (access.receiver, access.name)
                }
            };
            let name = csharp_member_name(name_node)?;
            let owners = receiver_type_units(receiver, csharp, token, file, source, bindings);
            owners.into_iter().find_map(|owner| {
                member_declared_type_fq_name_for_scope(
                    csharp,
                    token,
                    &owner,
                    node_text(name.identifier, source),
                    usage,
                )
            })
        }
        "invocation_expression" => invocation_expression_return_type_fq_name(
            expression, csharp, token, file, source, bindings, usage,
        ),
        "parenthesized_expression" | "checked_expression" => {
            expression.named_child(0).and_then(|inner| {
                expression_type_fq_name_inner(inner, csharp, token, file, source, bindings, usage)
            })
        }
        "cast_expression" | "as_expression" => expression
            .child_by_field_name(if expression.kind() == "cast_expression" {
                "type"
            } else {
                "right"
            })
            .and_then(|type_node| {
                resolve_type_fq_name_for_scope(
                    csharp,
                    token,
                    file,
                    &reference_type_text(type_node, source),
                    usage,
                )
            }),
        _ => None,
    }
}

fn invocation_expression_return_type_fq_name<T: DeclaredTypeName>(
    invocation: Node<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    bindings: &LocalInferenceEngine<T>,
    usage: bool,
) -> Option<String> {
    let function = invocation.child_by_field_name("function")?;
    let arity = argument_count(invocation, source);
    match function.kind() {
        "identifier" => {
            let owner = enclosing_declared_type(function, csharp, token, file, source)?;
            method_return_type_fq_name_for_arity_inner(
                csharp,
                token,
                &owner,
                node_text(function, source),
                Some(arity),
                None,
                None,
                usage,
                None,
            )
        }
        "generic_name" => {
            let name = csharp_member_name(function)?;
            let type_arguments = resolved_type_arguments(name, csharp, token, file, source, usage);
            let owner = enclosing_declared_type(function, csharp, token, file, source)?;
            method_return_type_fq_name_for_arity_inner(
                csharp,
                token,
                &owner,
                node_text(name.identifier, source),
                Some(arity),
                name.explicit_generic_arity,
                type_arguments.as_deref(),
                usage,
                None,
            )
        }
        "member_access_expression" | "conditional_access_expression" => {
            let (receiver, name_node) = match function.kind() {
                "member_access_expression" => (
                    member_access_receiver(function)?,
                    member_access_name(function)?,
                ),
                _ => {
                    let access = csharp_conditional_member_access(function)?;
                    (access.receiver, access.name)
                }
            };
            let name = csharp_member_name(name_node)?;
            let type_arguments = resolved_type_arguments(name, csharp, token, file, source, usage);
            let owners = receiver_type_units(receiver, csharp, token, file, source, bindings);
            owners.into_iter().find_map(|owner| {
                method_return_type_fq_name_for_arity_inner(
                    csharp,
                    token,
                    &owner,
                    node_text(name.identifier, source),
                    Some(arity),
                    name.explicit_generic_arity,
                    type_arguments.as_deref(),
                    usage,
                    None,
                )
            })
        }
        _ => None,
    }
}

fn receiver_type_units<T: DeclaredTypeName>(
    receiver: Node<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    bindings: &LocalInferenceEngine<T>,
) -> Vec<CodeUnit> {
    match receiver.kind() {
        "identifier" => {
            let name = node_text(receiver, source);
            if let Some(target) = first_precise_binding(bindings, name) {
                return usage_type_declarations_for_fq_name(csharp, token, &target);
            }
            if bindings.is_shadowed(name) {
                Vec::new()
            } else {
                enclosing_declared_type(receiver, csharp, token, file, source)
                    .and_then(|owner| {
                        usage_member_declared_type_fq_name(csharp, token, &owner, name)
                    })
                    .or_else(|| resolve_usage_type_fq_name(csharp, token, file, name))
                    .into_iter()
                    .flat_map(|fq_name| {
                        usage_type_declarations_for_fq_name(csharp, token, &fq_name)
                    })
                    .collect()
            }
        }
        "this" => enclosing_declared_type(receiver, csharp, token, file, source)
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

/// The one type name a symbol binds, as text.
///
/// Both engine flavours answer the same way here: this walk consumes the name
/// as a lookup key, which is what a written spelling still needs and what a
/// proved identity already is.
fn first_precise_binding<T: DeclaredTypeName>(
    bindings: &LocalInferenceEngine<T>,
    name: &str,
) -> Option<String> {
    let SymbolResolution::Precise(targets) = bindings.resolve_symbol(name) else {
        return None;
    };
    (targets.len() == 1)
        .then(|| targets.iter().next())
        .flatten()
        .map(|target| target.type_name().to_string())
}

fn member_access_receiver(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("expression")
        .or_else(|| node.child_by_field_name("object"))
        .or_else(|| node.child_by_field_name("receiver"))
        .or_else(|| {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find(|child| child.kind() != "identifier")
        })
}

fn member_access_name(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("name").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .filter(|child| child.kind() == "identifier")
            .last()
    })
}

pub(super) fn enclosing_declared_type(
    node: Node<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    _source: &str,
) -> Option<CodeUnit> {
    let byte = node.start_byte();
    let class_ranges = ClassRangeIndex::build(csharp, file);
    let fqn = class_ranges.enclosing(byte)?;
    class_unit_for_fq_name(csharp, token, fqn)
}

pub(super) fn class_unit_for_fq_name(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    fqn: &str,
) -> Option<CodeUnit> {
    let mut candidates = usage_type_declarations_for_fq_name(csharp, token, fqn);
    graph_support::sort_dedup_type_candidates(&mut candidates);
    (candidates.len() == 1).then(|| candidates.remove(0))
}

pub fn usage_direct_base(
    graph: &CSharpGraphSource<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    owner: &CodeUnit,
) -> Option<CodeUnit> {
    let mut candidates = hierarchy::usage_direct_ancestors(csharp, token, owner)
        .into_iter()
        .filter(|candidate| csharp_is_class_base_declaration(graph, candidate))
        .collect::<Vec<_>>();
    graph_support::sort_dedup_type_candidates(&mut candidates);
    (graph_support::logical_type_count(&candidates) == 1)
        .then(|| candidates.into_iter().next())
        .flatten()
}

fn csharp_is_class_base_declaration(graph: &CSharpGraphSource<'_>, candidate: &CodeUnit) -> bool {
    let language = tree_sitter_c_sharp::LANGUAGE.into();
    let Some(parsed) = parse_tree_sitter_file(
        candidate.source(),
        crate::preprocessor::csharp_parse_spec(&language),
    ) else {
        return false;
    };
    graph.index.ranges(candidate).into_iter().any(|range| {
        parsed
            .tree
            .root_node()
            .named_descendant_for_byte_range(range.start_byte, range.end_byte)
            .is_some_and(|node| matches!(node.kind(), "class_declaration" | "record_declaration"))
    })
}

fn forward_class_unit_for_fq_name(csharp: &dyn CSharpSource, fqn: &str) -> Option<CodeUnit> {
    let mut candidates = forward_type_declarations_for_fq_name(csharp, fqn);
    graph_support::sort_dedup_type_candidates(&mut candidates);
    (candidates.len() == 1).then(|| candidates.remove(0))
}

fn usage_type_declarations_for_fq_name(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    fqn: &str,
) -> Vec<CodeUnit> {
    let mut candidates = graph_support::usage_type_candidates_by_fqn(csharp, token, fqn);
    graph_support::sort_dedup_type_candidates(&mut candidates);
    candidates
}

fn forward_type_declarations_for_fq_name(csharp: &dyn CSharpSource, fqn: &str) -> Vec<CodeUnit> {
    let mut candidates = graph_support::declaration_candidates_by_fqn(csharp, fqn, false)
        .into_iter()
        .filter(|unit| unit.is_class())
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        candidates = graph_support::declaration_candidates_by_fqn(csharp, fqn, true)
            .into_iter()
            .filter(|unit| unit.is_class())
            .collect();
    }
    graph_support::sort_dedup_type_candidates(&mut candidates);
    candidates
}

fn forward_type_declarations_for_fq_name_in_session(
    csharp: &dyn CSharpSource,
    fqn: &str,
    session: &ResolutionSession,
) -> Vec<CodeUnit> {
    let mut candidates = session
        .query_limited_rows(|limit| {
            graph_support::declaration_candidates_by_fqn_limited(csharp, fqn, false, limit, || {
                session.observe_cancellation()
            })
        })
        .into_iter()
        .filter(|unit| unit.is_class())
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        candidates = session
            .query_limited_rows(|limit| {
                graph_support::declaration_candidates_by_fqn_limited(
                    csharp,
                    fqn,
                    true,
                    limit,
                    || session.observe_cancellation(),
                )
            })
            .into_iter()
            .filter(|unit| unit.is_class())
            .collect();
    }
    graph_support::sort_dedup_type_candidates(&mut candidates);
    candidates
}

fn forward_class_unit_for_fq_name_in_session(
    csharp: &dyn CSharpSource,
    fqn: &str,
    session: &ResolutionSession,
) -> Option<CodeUnit> {
    let mut candidates = forward_type_declarations_for_fq_name_in_session(csharp, fqn, session);
    (candidates.len() == 1).then(|| candidates.remove(0))
}

fn using_aliases_for_file_in_session(
    csharp: &dyn CSharpSource,
    file: &ProjectFile,
    session: &ResolutionSession,
) -> HashMap<String, String> {
    session
        .query_limited_rows(|limit| {
            csharp.using_aliases_of_limited(file, limit, &mut || session.observe_cancellation())
        })
        .into_iter()
        .collect()
}

fn file_using_namespaces_for_file_in_session(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    session: &ResolutionSession,
) -> Vec<String> {
    session.query_limited_rows(|limit| {
        graph_support::file_using_namespaces_limited(csharp, token, file, limit)
    })
}

fn visible_type_candidates_in_session(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    name: &str,
    resolve_aliases: bool,
    session: &ResolutionSession,
) -> Vec<CodeUnit> {
    let mut using_aliases = || {
        let aliases = Arc::new(using_aliases_for_file_in_session(csharp, file, session));
        session.observe_cancellation().then_some(aliases)
    };
    let mut namespace_of_file = || {
        session
            .query_limited_rows(|limit| csharp.namespace_of_file_limited(file, limit))
            .into_iter()
            .next()
    };
    let mut file_using_namespaces = || {
        let namespaces = file_using_namespaces_for_file_in_session(csharp, token, file, session);
        session.observe_cancellation().then_some(namespaces)
    };
    let mut global_using_namespaces = || {
        let mut namespaces: Vec<_> = session.query_limited_rows(|limit| {
            csharp.global_using_namespaces_limited(limit, &mut || session.observe_cancellation())
        });
        namespaces.sort();
        session.observe_cancellation().then_some(namespaces)
    };
    // No budget of its own: a namespace this cannot decide answers `true`, which
    // leaves the probe in place and the search exactly as wide as before.
    let mut namespace_exists = |namespace: &str| {
        session
            .query(|| csharp.workspace_namespace_exists(namespace))
            .unwrap_or(true)
    };
    let mut type_candidates_by_fqn = |fqn: &str| {
        let candidates = forward_type_declarations_for_fq_name_in_session(csharp, fqn, session);
        session.observe_cancellation().then_some(candidates)
    };
    graph_support::visible_type_candidates_with_lookups(
        name,
        resolve_aliases,
        &mut using_aliases,
        &mut namespace_of_file,
        &mut file_using_namespaces,
        &mut global_using_namespaces,
        &mut namespace_exists,
        &mut type_candidates_by_fqn,
    )
}

/// The bounded fork of [`graph_support::supertype_candidates`]: the enclosing
/// type chain of `part` first, then the file-keyed search (#1801).
fn supertype_candidates_in_session(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    part: &CodeUnit,
    raw: &str,
    session: &ResolutionSession,
) -> Vec<CodeUnit> {
    graph_support::supertype_candidates_with_lookups(
        &part.fq_name(),
        raw,
        &mut |fqn| {
            let candidates = forward_type_declarations_for_fq_name_in_session(csharp, fqn, session);
            session.observe_cancellation().then_some(candidates)
        },
        &mut |name| {
            visible_type_candidates_in_session(csharp, token, part.source(), name, true, session)
        },
    )
}

fn forward_direct_ancestors_in_session(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    owner: &CodeUnit,
    session: &ResolutionSession,
) -> Vec<CodeUnit> {
    if !session.summary_step() {
        return Vec::new();
    }
    let mut parts = session.query_limited_rows(|limit| {
        graph_support::partial_type_parts_limited(csharp, owner, limit, || {
            session.observe_cancellation()
        })
    });
    if !session.observe_cancellation() {
        return Vec::new();
    }
    if parts.is_empty() {
        if !session.scope_step() {
            return Vec::new();
        }
        parts.push(owner.clone());
    }

    let mut ancestors = Vec::new();
    for part in parts {
        if !session.scope_step() {
            return Vec::new();
        }
        let raw_supertypes =
            session.query_limited_rows(|limit| csharp.raw_supertypes_limited(&part, limit));
        if !session.observe_cancellation() {
            return Vec::new();
        }
        for raw in raw_supertypes {
            if !session.scope_step() {
                return Vec::new();
            }
            let candidates = supertype_candidates_in_session(csharp, token, &part, &raw, session);
            if !session.observe_cancellation() {
                return Vec::new();
            }
            let Some(ancestor) = graph_support::unique_logical_type(candidates) else {
                continue;
            };
            if !session.scope_step() {
                return Vec::new();
            }
            ancestors.push(ancestor);
        }
    }
    graph_support::sort_dedup_type_candidates(&mut ancestors);
    ancestors
}

pub fn member_declared_type_fq_name(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    _file: &ProjectFile,
    owner: &CodeUnit,
    member_name: &str,
) -> Option<String> {
    member_declared_type_fq_name_inner(csharp, token, owner, member_name, false, None)
}

pub fn member_declared_type_fq_name_in_session(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    _file: &ProjectFile,
    owner: &CodeUnit,
    member_name: &str,
    session: &ResolutionSession,
) -> Option<String> {
    member_declared_type_fq_name_inner(csharp, token, owner, member_name, false, Some(session))
}

/// Resolve the unique element type of a field or property declaration.
///
/// Arrays project their element node. A generic declaration projects its sole
/// structured type argument; declarations with zero or several arguments fail
/// closed. Keeping this on `StructuredTypeIdentity` avoids reconstructing type
/// arguments from normalized signature text (#2231).
pub fn member_declared_collection_element_type_fq_name_in_session(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    owner: &CodeUnit,
    member_name: &str,
    session: &ResolutionSession,
) -> Option<String> {
    let member_fqn = format!("{}.{}", owner.fq_name(), member_name);
    let candidates = session.query_limited_rows(|limit| {
        csharp.member_candidates_for_owner_limited(
            owner.fq_name().as_str(),
            member_name,
            limit,
            &mut || session.observe_cancellation(),
        )
    });
    if !session.observe_cancellation() {
        return None;
    }

    let mut resolved_types = Vec::new();
    for unit in candidates {
        if !session.scope_step() {
            return None;
        }
        if !unit.is_field() || unit.fq_name() != member_fqn {
            continue;
        }
        let metadata =
            session.query_limited_rows(|limit| csharp.signature_metadata_limited(&unit, limit));
        if !session.observe_cancellation() {
            return None;
        }
        for metadata in metadata {
            if !session.scope_step() {
                return None;
            }
            let Some(identity) = metadata.return_type_identity().cloned() else {
                continue;
            };
            let element = if identity.is_array() {
                identity.into_container_element_with(|| session.scope_step())
            } else {
                identity.into_single_generic_argument_with(|| session.scope_step())
            };
            let Some(element) = element else {
                continue;
            };
            if let Some(resolved) = resolve_structured_member_type_fq_name_in_session(
                csharp,
                token,
                unit.source(),
                owner,
                &element,
                session,
            ) {
                resolved_types.push(resolved);
            }
        }
    }
    resolved_types.sort();
    resolved_types.dedup();
    (resolved_types.len() == 1).then(|| resolved_types.remove(0))
}

pub fn member_declared_collection_element_type_fq_name(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    owner: &CodeUnit,
    member_name: &str,
) -> Option<String> {
    let member_fqn = format!("{}.{}", owner.fq_name(), member_name);
    let mut resolved_types = csharp
        .member_candidates_for_owner(owner.fq_name().as_str(), member_name)
        .into_iter()
        .filter(|unit| unit.is_field() && unit.fq_name() == member_fqn)
        .flat_map(|unit| {
            csharp
                .signature_metadata(&unit)
                .into_iter()
                .filter_map(move |metadata| {
                    let identity = metadata.return_type_identity()?.clone();
                    let element = if identity.is_array() {
                        identity.into_container_element_with(|| true)
                    } else {
                        identity.into_single_generic_argument_with(|| true)
                    }?;
                    resolve_structured_member_type_fq_name(
                        csharp,
                        token,
                        unit.source(),
                        owner,
                        &element,
                    )
                })
        })
        .collect::<Vec<_>>();
    resolved_types.sort();
    resolved_types.dedup();
    (resolved_types.len() == 1).then(|| resolved_types.remove(0))
}

pub(super) fn usage_member_declared_type_fq_name(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    owner: &CodeUnit,
    member_name: &str,
) -> Option<String> {
    member_declared_type_fq_name_inner(csharp, token, owner, member_name, true, None)
}

fn member_declared_type_fq_name_for_scope(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    owner: &CodeUnit,
    member_name: &str,
    usage: bool,
) -> Option<String> {
    member_declared_type_fq_name_inner(csharp, token, owner, member_name, usage, None)
}

fn member_declared_type_fq_name_inner(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    owner: &CodeUnit,
    member_name: &str,
    usage: bool,
    session: Option<&ResolutionSession>,
) -> Option<String> {
    // A member named by an unqualified identifier can be declared by the owner
    // itself or inherited from an ancestor, so take the same nearest-member walk
    // the call and shadowing paths use. Asking only the owner's own members left
    // an inherited field's declared type unknown, and the caller then mistook the
    // field name for a visible type of the same name.
    let graph = CSharpGraphSource::from_source(csharp);
    let candidates = nearest_member_candidates_for_owner_inner(
        &graph,
        csharp,
        token,
        owner,
        member_name,
        None,
        None,
        usage,
        session,
    );
    let mut resolved_types = Vec::new();
    for unit in candidates {
        if !resolution_scope_step(session) {
            return None;
        }
        if !unit.is_field() {
            continue;
        }
        // The declared type text is written in the declaring type's scope, so a
        // type nested in that ancestor must be resolved against it, not against
        // the type the member was reached through.
        let declaring = resolution_query(session, || graph.index.parent_of(&unit))
            .flatten()
            .unwrap_or_else(|| owner.clone());
        let metadata = resolution_query_limited_rows(
            session,
            |limit| csharp.signature_metadata_limited(&unit, limit),
            || csharp.signature_metadata(&unit),
        );
        let resolved = if let Some(session) = session {
            let resolved = metadata.iter().find_map(|metadata| {
                let identity = metadata.return_type_identity()?;
                resolve_structured_member_type_fq_name_in_session(
                    csharp,
                    token,
                    unit.source(),
                    &declaring,
                    identity,
                    session,
                )
            })?;
            Some(resolved)
        } else {
            let declared_type = metadata
                .iter()
                .find_map(|metadata| metadata.return_type_text().map(str::to_string))
                .or_else(|| member_declared_type(csharp, &unit));
            declared_type.and_then(|declared_type| {
                resolve_member_type_fq_name(
                    csharp,
                    token,
                    unit.source(),
                    &declaring,
                    &declared_type,
                    usage,
                )
            })
        };
        if let Some(resolved) = resolved {
            resolved_types.push(resolved);
        }
    }
    resolved_types.sort();
    resolved_types.dedup();
    (resolved_types.len() == 1).then(|| resolved_types.remove(0))
}

/// Resolve the type named by a method's declared return type, so a call
/// receiver (`GetFoo().Member`) can be typed by the callee. The stored member
/// `signature()` keeps only the parameter list, so read the return type from the
/// full signature text (`signatures`), which is `Return Name(params) { … }`.
#[allow(clippy::too_many_arguments)]
pub fn method_return_type_fq_name_for_arity(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    _file: &ProjectFile,
    owner: &CodeUnit,
    method_name: &str,
    arity: Option<usize>,
    explicit_generic_arity: Option<usize>,
    explicit_type_arguments: Option<&[String]>,
) -> Option<String> {
    method_return_type_fq_name_for_arity_inner(
        csharp,
        token,
        owner,
        method_name,
        arity,
        explicit_generic_arity,
        explicit_type_arguments,
        false,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn method_return_type_fq_name_for_arity_in_session(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    _file: &ProjectFile,
    owner: &CodeUnit,
    method_name: &str,
    arity: Option<usize>,
    explicit_generic_arity: Option<usize>,
    explicit_type_arguments: Option<&[String]>,
    session: &ResolutionSession,
) -> Option<String> {
    method_return_type_fq_name_for_arity_inner(
        csharp,
        token,
        owner,
        method_name,
        arity,
        explicit_generic_arity,
        explicit_type_arguments,
        false,
        Some(session),
    )
}

pub(super) fn usage_method_return_type_fq_name_for_arity(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    owner: &CodeUnit,
    method_name: &str,
    arity: Option<usize>,
    explicit_generic_arity: Option<usize>,
    explicit_type_arguments: Option<&[String]>,
) -> Option<String> {
    method_return_type_fq_name_for_arity_inner(
        csharp,
        token,
        owner,
        method_name,
        arity,
        explicit_generic_arity,
        explicit_type_arguments,
        true,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn method_return_type_fq_name_for_arity_inner(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    owner: &CodeUnit,
    method_name: &str,
    arity: Option<usize>,
    explicit_generic_arity: Option<usize>,
    explicit_type_arguments: Option<&[String]>,
    usage: bool,
    session: Option<&ResolutionSession>,
) -> Option<String> {
    let candidates = nearest_member_candidates_for_owner_inner(
        &CSharpGraphSource::from_source(csharp),
        csharp,
        token,
        owner,
        method_name,
        explicit_generic_arity,
        arity,
        usage,
        session,
    );
    let mut resolved = Vec::new();
    for unit in candidates {
        if !resolution_scope_step(session) {
            return None;
        }
        if !unit.is_function() {
            continue;
        }
        let callable_arity = resolution_query(session, || csharp_callable_arity(csharp, &unit))?;
        if arity.is_some_and(|call_arity| !callable_arity.accepts(call_arity)) {
            continue;
        }
        if let Some(resolved_type) = callable_return_type_fq_name(
            csharp,
            token,
            &unit,
            owner,
            explicit_type_arguments,
            usage,
            session,
        ) {
            resolved.push(resolved_type);
        } else if session.is_some() {
            return None;
        }
    }
    resolved.sort();
    resolved.dedup();
    (resolved.len() == 1).then(|| resolved.remove(0))
}

/// Resolve a callable's declared return type to a fully-qualified type name,
/// applying explicit type-argument substitution when the return is a bare method
/// type parameter. `owner_fallback` supplies the declaring owner only when the
/// unit's own parent is unavailable. Shared between ordinary member return typing
/// and extension-method return typing so both derive the return FQN identically.
fn callable_return_type_fq_name(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    unit: &CodeUnit,
    owner_fallback: &CodeUnit,
    explicit_type_arguments: Option<&[String]>,
    usage: bool,
    session: Option<&ResolutionSession>,
) -> Option<String> {
    if !unit.is_function() {
        return None;
    }
    let metadata = resolution_query_limited_rows(
        session,
        |limit| csharp.signature_metadata_limited(unit, limit),
        || csharp.signature_metadata(unit),
    );
    let declaring_owner = resolution_query(session, || csharp.parent_of(unit))
        .flatten()
        .unwrap_or_else(|| owner_fallback.clone());
    if let Some(session) = session {
        return metadata.iter().find_map(|metadata| {
            resolve_structured_method_return_type_fq_name_in_session(
                csharp,
                token,
                unit.source(),
                &declaring_owner,
                metadata,
                explicit_type_arguments,
                session,
            )
        });
    }
    if let Some(substituted) = substituted_method_type_parameter(&metadata, explicit_type_arguments)
    {
        return Some(substituted);
    }
    let declared_type = metadata
        .iter()
        .find_map(|metadata| metadata.return_type_text().map(str::to_string))
        .or_else(|| method_return_type(csharp, unit))?;
    resolve_member_type_fq_name(
        csharp,
        token,
        unit.source(),
        &declaring_owner,
        &declared_type,
        usage,
    )
}

/// Type an invocation whose callee is an extension method by that extension's
/// declared return type. Mirrors `method_return_type_fq_name_for_arity` for the
/// case the invoked name is not an ordinary member of the receiver type but a
/// visible extension method — the piece that lets chained receivers such as
/// `handler.Handle("Ada").Tag()` be typed when `Handle` is itself an extension.
/// Reuses the shared extension-candidate matcher (so the same visibility scoping
/// and `this`-parameter compatibility gate apply) and the shared return-type
/// derivation. Returns a type FQN only when the matching extensions agree on one.
#[allow(clippy::too_many_arguments)]
pub fn extension_invocation_return_type_fq_name(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    graph: &CSharpGraphSource<'_>,
    source: &str,
    site: Node<'_>,
    receiver_type_names: &[String],
    method: &str,
    call_arity: Option<usize>,
    explicit_generic_arity: Option<usize>,
    explicit_type_arguments: Option<&[String]>,
    usage: bool,
) -> Option<String> {
    extension_invocation_return_type_fq_name_inner(
        csharp,
        token,
        graph,
        source,
        site,
        receiver_type_names,
        method,
        call_arity,
        explicit_generic_arity,
        explicit_type_arguments,
        usage,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn extension_invocation_return_type_fq_name_in_session(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    graph: &CSharpGraphSource<'_>,
    source: &str,
    site: Node<'_>,
    receiver_type_names: &[String],
    method: &str,
    call_arity: Option<usize>,
    explicit_generic_arity: Option<usize>,
    explicit_type_arguments: Option<&[String]>,
    usage: bool,
    session: &ResolutionSession,
) -> Option<String> {
    extension_invocation_return_type_fq_name_inner(
        csharp,
        token,
        graph,
        source,
        site,
        receiver_type_names,
        method,
        call_arity,
        explicit_generic_arity,
        explicit_type_arguments,
        usage,
        Some(session),
    )
}

#[allow(clippy::too_many_arguments)]
fn extension_invocation_return_type_fq_name_inner(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    graph: &CSharpGraphSource<'_>,
    source: &str,
    site: Node<'_>,
    receiver_type_names: &[String],
    method: &str,
    call_arity: Option<usize>,
    explicit_generic_arity: Option<usize>,
    explicit_type_arguments: Option<&[String]>,
    usage: bool,
    session: Option<&ResolutionSession>,
) -> Option<String> {
    if receiver_type_names.is_empty() {
        return None;
    }
    let candidates = visible_extension_method_candidates_inner(
        csharp,
        token,
        graph,
        source,
        site,
        receiver_type_names,
        method,
        call_arity,
        explicit_generic_arity,
        usage,
        session,
    );
    let mut resolved = Vec::new();
    for unit in candidates {
        if !resolution_scope_step(session) {
            return None;
        }
        if let Some(resolved_type) = callable_return_type_fq_name(
            csharp,
            token,
            &unit,
            &unit,
            explicit_type_arguments,
            usage,
            session,
        ) {
            resolved.push(resolved_type);
        } else if session.is_some() {
            return None;
        }
    }
    resolved.sort();
    resolved.dedup();
    (resolved.len() == 1).then(|| resolved.remove(0))
}

fn resolved_type_arguments(
    name: CSharpMemberName<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    usage: bool,
) -> Option<Vec<String>> {
    let arguments = name.type_arguments?;
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .map(|argument| {
            resolve_type_fq_name_for_scope(
                csharp,
                token,
                file,
                &reference_type_text(argument, source),
                usage,
            )
        })
        .collect()
}

fn substituted_method_type_parameter(
    metadata: &[SignatureMetadata],
    explicit_type_arguments: Option<&[String]>,
) -> Option<String> {
    let arguments = explicit_type_arguments?;
    metadata.iter().find_map(|metadata| {
        let return_type = metadata.bare_return_type_parameter()?;
        metadata
            .type_parameters()
            .iter()
            .position(|parameter| parameter == return_type)
            .and_then(|index| arguments.get(index).cloned())
    })
}

fn resolve_member_type_fq_name(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    owner: &CodeUnit,
    type_text: &str,
    usage: bool,
) -> Option<String> {
    let nested_fq_name = if owner.package_name().is_empty() {
        format!("{}${type_text}", owner.short_name())
    } else {
        format!(
            "{}.{}${type_text}",
            owner.package_name(),
            owner.short_name()
        )
    };
    let nested = if usage {
        class_unit_for_fq_name(csharp, token, &nested_fq_name)
    } else {
        forward_class_unit_for_fq_name(csharp, &nested_fq_name)
    };
    nested.map(|unit| unit.fq_name()).or_else(|| {
        if usage {
            resolve_usage_type_fq_name(csharp, token, file, type_text)
        } else {
            resolve_type_fq_name(csharp, token, file, type_text)
        }
    })
}

fn resolve_structured_method_return_type_fq_name_in_session(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    owner: &CodeUnit,
    metadata: &SignatureMetadata,
    explicit_type_arguments: Option<&[String]>,
    session: &ResolutionSession,
) -> Option<String> {
    let identity = metadata.return_type_identity()?;
    let name = identity.nominal_name_with(|| session.scope_step())?;
    if csharp_structured_name_is_method_type_parameter(name, metadata) {
        if identity.is_pointer()
            || identity.is_reference()
            || identity.generic_argument_count().is_some()
        {
            return None;
        }
        let arguments = explicit_type_arguments?;
        let parameter = name.path().first()?;
        return metadata
            .type_parameters()
            .iter()
            .position(|candidate| candidate == parameter)
            .and_then(|index| arguments.get(index).cloned());
    }
    resolve_structured_member_type_fq_name_in_session(csharp, token, file, owner, identity, session)
}

fn resolve_structured_member_type_fq_name_in_session(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    owner: &CodeUnit,
    identity: &StructuredTypeIdentity,
    session: &ResolutionSession,
) -> Option<String> {
    let name = identity.nominal_name_with(|| session.scope_step())?;
    if csharp_owner_chain_declares_type_parameter_in_session(csharp, owner, name, session) {
        return None;
    }
    resolve_structured_type_fq_name_in_session(csharp, token, file, name, session)
}

fn resolve_structured_member_type_fq_name(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    owner: &CodeUnit,
    identity: &StructuredTypeIdentity,
) -> Option<String> {
    let name = identity.nominal_name()?;
    if csharp_owner_chain_declares_type_parameter(csharp, owner, name) {
        return None;
    }
    resolve_structured_type_fq_name(csharp, token, file, name)
}

fn csharp_owner_chain_declares_type_parameter(
    csharp: &dyn CSharpSource,
    owner: &CodeUnit,
    name: &StructuredTypeName,
) -> bool {
    let [candidate] = name.path() else {
        return false;
    };
    if name.is_absolute() {
        return false;
    }
    let mut current = Some(owner.clone());
    while let Some(unit) = current {
        if !unit.is_class() {
            return false;
        }
        if csharp
            .signature_metadata(&unit)
            .iter()
            .any(|metadata| metadata.type_parameters().contains(candidate))
        {
            return true;
        }
        current = csharp.parent_of(&unit);
    }
    false
}

fn csharp_structured_name_is_method_type_parameter(
    name: &StructuredTypeName,
    metadata: &SignatureMetadata,
) -> bool {
    !name.is_absolute()
        && matches!(name.path(), [parameter] if metadata.type_parameters().contains(parameter))
}

fn csharp_owner_chain_declares_type_parameter_in_session(
    csharp: &dyn CSharpSource,
    owner: &CodeUnit,
    name: &StructuredTypeName,
    session: &ResolutionSession,
) -> bool {
    let [candidate] = name.path() else {
        return false;
    };
    if name.is_absolute() {
        return false;
    }
    let mut current = Some(owner.clone());
    while let Some(unit) = current {
        if !unit.is_class() || !session.scope_step() {
            return false;
        }
        let metadata =
            session.query_limited_rows(|limit| csharp.signature_metadata_limited(&unit, limit));
        if !session.observe_cancellation() {
            return false;
        }
        if metadata
            .iter()
            .any(|metadata| metadata.type_parameters().contains(candidate))
        {
            return true;
        }
        current = session.query(|| csharp.parent_of(&unit)).flatten();
        if !session.observe_cancellation() {
            return false;
        }
    }
    false
}

fn resolve_structured_type_fq_name_in_session(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    name: &StructuredTypeName,
    session: &ResolutionSession,
) -> Option<String> {
    let path = name.path();
    let [builtin] = path else {
        return resolve_non_builtin_structured_type_fq_name_in_session(
            csharp, token, file, name, session,
        );
    };
    if let Some(canonical) = canonical_builtin_type_identity(builtin) {
        return Some(canonical.to_string());
    }
    resolve_non_builtin_structured_type_fq_name_in_session(csharp, token, file, name, session)
}

fn resolve_structured_type_fq_name(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    name: &StructuredTypeName,
) -> Option<String> {
    if let [builtin] = name.path()
        && let Some(canonical) = canonical_builtin_type_identity(builtin)
    {
        return Some(canonical.to_string());
    }
    let path = name.path();
    if path.is_empty() {
        return None;
    }
    let alias_qualified = path
        .first()
        .and_then(|component| component.strip_suffix("::"));
    if !name.is_absolute() && alias_qualified.is_none() {
        for prefix_len in (0..=name.lexical_scope().len()).rev() {
            let candidate =
                render_csharp_structured_path(&name.lexical_scope()[..prefix_len], path, false);
            let candidates = forward_type_declarations_for_fq_name(csharp, &candidate);
            if !candidates.is_empty() {
                return graph_support::unique_logical_type(candidates).map(|unit| unit.fq_name());
            }
        }
    }
    let rendered = if let Some(alias) = alias_qualified {
        let suffix = render_csharp_structured_path(&[], &path[1..], false);
        if suffix.is_empty() {
            alias.to_string()
        } else {
            format!("{alias}::{suffix}")
        }
    } else {
        render_csharp_structured_path(&[], path, name.is_absolute())
    };
    let candidates = if name.is_absolute() {
        forward_type_declarations_for_fq_name(csharp, &rendered)
    } else {
        graph_support::visible_type_candidates(csharp, token, file, &rendered)
    };
    graph_support::unique_logical_type(candidates).map(|unit| unit.fq_name())
}

fn resolve_non_builtin_structured_type_fq_name_in_session(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    name: &StructuredTypeName,
    session: &ResolutionSession,
) -> Option<String> {
    let path = name.path();
    if path.is_empty() {
        return None;
    }

    let alias_qualified = path
        .first()
        .and_then(|component| component.strip_suffix("::"));
    if !name.is_absolute() && alias_qualified.is_none() {
        for prefix_len in (0..=name.lexical_scope().len()).rev() {
            if !session.scope_step() {
                return None;
            }
            let candidate =
                render_csharp_structured_path(&name.lexical_scope()[..prefix_len], path, false);
            let candidates =
                forward_type_declarations_for_fq_name_in_session(csharp, &candidate, session);
            if !session.observe_cancellation() {
                return None;
            }
            if !candidates.is_empty() {
                return unique_logical_type_fq_name(&candidates, session);
            }
        }
    }

    let rendered = if let Some(alias) = alias_qualified {
        let suffix = render_csharp_structured_path(&[], &path[1..], false);
        if suffix.is_empty() {
            alias.to_string()
        } else {
            format!("{alias}::{suffix}")
        }
    } else {
        render_csharp_structured_path(&[], path, name.is_absolute())
    };
    let candidates = if name.is_absolute() {
        forward_type_declarations_for_fq_name_in_session(csharp, &rendered, session)
    } else {
        visible_type_candidates_in_session(csharp, token, file, &rendered, true, session)
    };
    if !session.observe_cancellation() || candidates.is_empty() {
        return None;
    }
    unique_logical_type_fq_name(&candidates, session)
}

fn render_csharp_structured_path(prefix: &[String], path: &[String], absolute: bool) -> String {
    let mut rendered = String::new();
    if absolute {
        rendered.push_str("global::");
    }
    for component in prefix.iter().chain(path) {
        if !rendered.is_empty() && !rendered.ends_with("::") {
            rendered.push('.');
        }
        rendered.push_str(component);
    }
    rendered
}

fn unique_logical_type_fq_name(
    candidates: &[CodeUnit],
    session: &ResolutionSession,
) -> Option<String> {
    if !session.scope_step() || graph_support::logical_type_count(candidates) != 1 {
        return None;
    }
    graph_support::first_logical_type_fqn(candidates)
}

fn member_declared_type(csharp: &dyn CSharpSource, member: &CodeUnit) -> Option<String> {
    let signatures = csharp.signatures(member);
    let signature = member
        .signature()
        .or_else(|| signatures.first().map(String::as_str))?;
    type_text_before_name(signature, member.identifier())
}

/// A method's declared return type, read from the full signature
/// (`Return Name(params) { … }`); constructors, whose signature starts at the
/// name, yield `None`.
fn method_return_type(csharp: &dyn CSharpSource, method: &CodeUnit) -> Option<String> {
    let signatures = csharp.signatures(method);
    let signature = signatures.first().map(String::as_str)?;
    type_text_before_name(signature, method.identifier())
}

/// Extract the (normalized) type token that precedes `name` in a declaration
/// signature — the field/parameter type or a method's return type.
fn type_text_before_name(signature: &str, name: &str) -> Option<String> {
    csharp_signature_return_type(signature, name)
}

/// What the binding seeder settled about a local's or parameter's declared
/// type.
///
/// The two variants are not interchangeable spellings of one string. A
/// `Resolved` identity is one this seeder already proved against the workspace
/// in the caller's own request and analyzer generation, so a consumer looks it
/// up absolutely and never re-reads it as written source text. A `Spelling` is
/// written type text the seeder could not settle, which still has to go through
/// the visible-name ladder -- and through external-type resolution behind it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CSharpDeclaredType {
    Resolved { fqn: String },
    Spelling(String),
}

impl CSharpDeclaredType {
    /// The seeded form of a type reference the resolver answered with `fqn`.
    ///
    /// `resolve_type_fq_name` answers a canonical builtin identity such as
    /// `System.Int32` for a keyword type. That names a declaration the
    /// workspace does not hold, so it stays a spelling for the consumer's own
    /// lookup -- workspace first, then the external index -- to settle. Every
    /// other success is a workspace fq name the seeder proved.
    fn resolved(fqn: String) -> Self {
        if canonical_builtin_type_identity(&fqn).is_some() {
            Self::Spelling(fqn)
        } else {
            Self::Resolved { fqn }
        }
    }

    /// The type text this binding carries, for a consumer that treats a proved
    /// identity and a written spelling the same way.
    pub fn as_type_name(&self) -> &str {
        match self {
            Self::Resolved { fqn } => fqn,
            Self::Spelling(spelling) => spelling,
        }
    }
}

/// The type text a seeded binding carries, so the expression-typing walk below
/// reads a raw-fq-name engine and a [`CSharpDeclaredType`] engine alike.
trait DeclaredTypeName: Clone + Eq + std::hash::Hash {
    fn type_name(&self) -> &str;
}

impl DeclaredTypeName for String {
    fn type_name(&self) -> &str {
        self
    }
}

impl DeclaredTypeName for CSharpDeclaredType {
    fn type_name(&self) -> &str {
        self.as_type_name()
    }
}

fn seed_usage_symbol_for_type(
    name_node: Node<'_>,
    type_node: Node<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let reference = reference_type_text(type_node, source);
    match resolve_usage_type_fq_name(csharp, token, file, &reference) {
        Some(target) => bindings.seed_symbol(node_text(name_node, source), target),
        None => bindings.declare_shadow(node_text(name_node, source)),
    }
}

fn seed_symbol_for_type(
    name_node: Node<'_>,
    type_node: Node<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<CSharpDeclaredType>,
) {
    let reference = reference_type_text(type_node, source);
    if let Some(target) = resolve_type_fq_name(csharp, token, file, &reference) {
        bindings.seed_symbol(
            node_text(name_node, source),
            CSharpDeclaredType::resolved(target),
        );
        return;
    }
    let normalized = normalize_type_text(&reference);
    let raw_type = csharp
        .using_aliases_of(file)
        .get(&normalized)
        .cloned()
        .unwrap_or(normalized);
    if raw_type.is_empty() || raw_type == "var" {
        bindings.declare_shadow(node_text(name_node, source));
    } else {
        bindings.seed_symbol(
            node_text(name_node, source),
            CSharpDeclaredType::Spelling(raw_type),
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn seed_symbol_for_type_in_session(
    name_node: Node<'_>,
    type_node: Node<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<CSharpDeclaredType>,
    session: &ResolutionSession,
) {
    let reference = reference_type_text(type_node, source);
    if let Some(target) = resolve_type_fq_name_in_session(csharp, token, file, &reference, session)
    {
        bindings.seed_symbol(
            node_text(name_node, source),
            CSharpDeclaredType::resolved(target),
        );
        return;
    }
    if !session.observe_cancellation() {
        return;
    }
    let normalized = normalize_type_text(&reference);
    let raw_type = using_aliases_for_file_in_session(csharp, file, session)
        .get(&normalized)
        .cloned()
        .unwrap_or(normalized);
    if raw_type.is_empty() || raw_type == "var" {
        bindings.declare_shadow(node_text(name_node, source));
    } else {
        bindings.seed_symbol(
            node_text(name_node, source),
            CSharpDeclaredType::Spelling(raw_type),
        );
    }
}

pub fn object_created_type(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() == "object_creation_expression" {
        return node
            .child_by_field_name("type")
            .or_else(|| first_type_child(node));
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(found) = object_created_type(child) {
            return Some(found);
        }
    }
    None
}

pub(super) fn resolves_to_target(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    reference: &str,
    target: &CodeUnit,
) -> bool {
    let normalized = normalize_type_text(reference);
    graph_support::resolve_usage_visible_type(csharp, token, file, &normalized)
        .is_some_and(|resolved| resolved == *target)
        || reference_matches_target_fq_name(&normalized, target)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn resolves_to_target_at(
    file: &ProjectFile,
    class_ranges: &ClassRangeIndex,
    reference: &str,
    node: Node<'_>,
    source: &str,
    target: &CodeUnit,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
) -> bool {
    resolve_type_fq_name_at(csharp, token, file, class_ranges, reference, node, source)
        .is_some_and(|resolved| type_identity_matches(&resolved, &target.fq_name()))
}

pub(super) fn resolve_type_fq_name_at(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    class_ranges: &ClassRangeIndex,
    reference: &str,
    node: Node<'_>,
    source: &str,
) -> Option<String> {
    let normalized = expand_alias_qualified_type(csharp, file, &normalize_type_text(reference));
    if normalized.is_empty() || type_parameter_shadows_reference(node, source, &normalized) {
        return None;
    }
    if let Some(canonical) = canonical_builtin_type_identity(&normalized) {
        return Some(canonical.to_string());
    }
    resolve_in_enclosing_type_scopes(csharp, token, class_ranges, &normalized, node.start_byte())
        .map(|unit| unit.fq_name())
        .or_else(|| resolve_usage_visible_type_fq_name(csharp, token, file, &normalized))
        .or_else(|| class_unit_for_fq_name(csharp, token, &normalized).map(|unit| unit.fq_name()))
}

/// Resolve a type name in a grammar-proven context that permits omitted
/// generic arity, such as `nameof(Box)` (#2209). Each lexical scope still
/// probes the exact arity-zero identity first; only an exact miss in that same
/// scope widens to generic declarations with the normalized name.
pub(super) fn resolve_arity_free_type_fq_name_at(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    class_ranges: &ClassRangeIndex,
    reference: &str,
    node: Node<'_>,
    source: &str,
) -> Option<String> {
    let normalized = expand_alias_qualified_type(csharp, file, &normalize_type_text(reference));
    if normalized.is_empty() || type_parameter_shadows_reference(node, source, &normalized) {
        return None;
    }
    if let Some(canonical) = canonical_builtin_type_identity(&normalized) {
        return Some(canonical.to_string());
    }

    let nested = class_ranges
        .enclosing(node.start_byte())
        .and_then(|declaring_type_fqn| {
            let candidates = graph_support::enclosing_type_candidates_with_lookups(
                declaring_type_fqn,
                &normalized,
                &mut |fqn| {
                    Some(graph_support::usage_arity_free_type_candidates_by_fqn(
                        csharp, token, fqn,
                    ))
                },
            )?;
            graph_support::unique_logical_type(candidates)
        });
    nested
        .map(|unit| unit.fq_name())
        .or_else(|| {
            graph_support::unique_logical_type(
                graph_support::usage_arity_free_visible_type_candidates(
                    csharp,
                    token,
                    file,
                    &normalized,
                ),
            )
            .map(|unit| unit.fq_name())
        })
        .or_else(|| {
            graph_support::unique_logical_type(
                graph_support::usage_arity_free_type_candidates_by_fqn(csharp, token, &normalized),
            )
            .map(|unit| unit.fq_name())
        })
}

pub fn resolve_type_fq_name(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    reference: &str,
) -> Option<String> {
    let normalized = expand_alias_qualified_type(csharp, file, &normalize_type_text(reference));
    if let Some(canonical) = canonical_builtin_type_identity(&normalized) {
        return Some(canonical.to_string());
    }
    if let Some(target) = resolve_visible_type_fq_name(csharp, token, file, &normalized) {
        return Some(target);
    }
    forward_class_unit_for_fq_name(csharp, &normalized).map(|unit| unit.fq_name())
}

fn resolve_type_fq_name_in_session(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    reference: &str,
    session: &ResolutionSession,
) -> Option<String> {
    let normalized = normalize_type_text(reference);
    if let Some(canonical) = canonical_builtin_type_identity(&normalized) {
        return Some(canonical.to_string());
    }
    let candidates =
        visible_type_candidates_in_session(csharp, token, file, &normalized, true, session);
    if graph_support::logical_type_count(&candidates) == 1 {
        return graph_support::first_logical_type_fqn(&candidates);
    }
    forward_class_unit_for_fq_name_in_session(csharp, &normalized, session)
        .map(|unit| unit.fq_name())
}

fn resolve_usage_type_fq_name(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    reference: &str,
) -> Option<String> {
    let normalized = expand_alias_qualified_type(csharp, file, &normalize_type_text(reference));
    if let Some(canonical) = canonical_builtin_type_identity(&normalized) {
        return Some(canonical.to_string());
    }
    if let Some(target) = resolve_usage_visible_type_fq_name(csharp, token, file, &normalized) {
        return Some(target);
    }
    class_unit_for_fq_name(csharp, token, &normalized).map(|unit| unit.fq_name())
}

fn resolve_type_fq_name_for_scope(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    reference: &str,
    usage: bool,
) -> Option<String> {
    if usage {
        resolve_usage_type_fq_name(csharp, token, file, reference)
    } else {
        resolve_type_fq_name(csharp, token, file, reference)
    }
}

fn expand_alias_qualified_type(
    csharp: &dyn CSharpSource,
    file: &ProjectFile,
    reference: &str,
) -> String {
    let Some((alias, suffix)) = reference.split_once("::") else {
        return reference.to_string();
    };
    if alias == "global" {
        return reference.to_string();
    }
    csharp
        .using_aliases_of(file)
        .get(alias)
        .map(|target| {
            if suffix.is_empty() {
                target.clone()
            } else {
                format!("{target}.{suffix}")
            }
        })
        .unwrap_or_else(|| reference.to_string())
}

fn resolve_visible_type_fq_name(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    reference: &str,
) -> Option<String> {
    let candidates = graph_support::visible_type_candidates(csharp, token, file, reference);
    (graph_support::logical_type_count(&candidates) == 1)
        .then(|| graph_support::first_logical_type_fqn(&candidates))
        .flatten()
}

fn resolve_usage_visible_type_fq_name(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    reference: &str,
) -> Option<String> {
    let candidates = graph_support::usage_visible_type_candidates(csharp, token, file, reference);
    (graph_support::logical_type_count(&candidates) == 1)
        .then(|| graph_support::first_logical_type_fqn(&candidates))
        .flatten()
}

fn resolve_in_enclosing_type_scopes(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    class_ranges: &ClassRangeIndex,
    name: &str,
    byte: usize,
) -> Option<CodeUnit> {
    if name.is_empty() {
        return None;
    }
    // A qualified spelling (`Outer.Inner`, #972) resolves the way C# reads it:
    // the first segment is a simple name found on this same enclosing-class
    // walk, and every later segment is a nested type of the type the previous
    // segment named. Without this, the inverse scan omits a nested-class
    // construction (`new Outer.Inner(...)`) written where the outer is visible
    // only through the site's enclosing classes -- a reference the forward side
    // resolves (#2232).
    let (prefix, suffix) = match name.split_once('.') {
        Some((prefix, suffix)) if !prefix.is_empty() && !suffix.is_empty() => {
            (prefix, Some(suffix))
        }
        Some(_) => return None,
        None => (name, None),
    };

    let mut scope = class_ranges.enclosing_unit(byte)?.clone();
    loop {
        let mut candidates = nested_class_children_named(csharp, token, &scope, prefix);
        if !candidates.is_empty() {
            graph_support::sort_dedup_type_candidates(&mut candidates);
            let resolved = (graph_support::logical_type_count(&candidates) == 1)
                .then(|| candidates.into_iter().next())
                .flatten();
            // The first scope that binds the prefix decides: C# simple-name
            // lookup stops there, so a missing nested suffix is unresolved
            // rather than an invitation to bind a further-out type of the same
            // spelling.
            return resolved.and_then(|unit| match suffix {
                None => Some(unit),
                Some(suffix) => resolve_nested_type_suffix(csharp, token, &unit, suffix),
            });
        }

        let Some(parent) = csharp.parent_of(&scope) else {
            return resolve_in_enclosing_namespace(csharp, token, scope.package_name(), name);
        };
        scope = parent;
    }
}

/// Every nested class spelled `name` that `scope`'s partial parts declare.
fn nested_class_children_named(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    scope: &CodeUnit,
    name: &str,
) -> Vec<CodeUnit> {
    let mut parts = graph_support::usage_partial_type_parts(csharp, token, scope);
    if parts.is_empty() {
        parts.push(scope.clone());
    }
    parts
        .into_iter()
        .flat_map(|part| csharp.direct_children(&part))
        .filter(|child| child.is_class() && child.identifier() == name)
        .collect()
}

/// The nested type `suffix` names below `owner`, one segment at a time, or
/// `None` when any segment is missing or ambiguous (#972).
fn resolve_nested_type_suffix(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    owner: &CodeUnit,
    suffix: &str,
) -> Option<CodeUnit> {
    let mut owner = owner.clone();
    for segment in suffix.split('.') {
        let mut candidates = nested_class_children_named(csharp, token, &owner, segment);
        graph_support::sort_dedup_type_candidates(&mut candidates);
        owner = (graph_support::logical_type_count(&candidates) == 1)
            .then(|| candidates.into_iter().next())
            .flatten()?;
    }
    Some(owner)
}

fn resolve_in_enclosing_namespace(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    namespace: &str,
    name: &str,
) -> Option<CodeUnit> {
    brokk_bifrost_core::analyzer::usages::common::namespace_prefixes(namespace).find_map(|scope| {
        let candidate_fqn = if scope.is_empty() {
            name.to_string()
        } else {
            format!("{scope}.{name}")
        };
        class_unit_for_fq_name(csharp, token, &candidate_fqn)
    })
}

pub fn type_parameter_shadows_reference(node: Node<'_>, source: &str, reference: &str) -> bool {
    if reference.contains('.') {
        return false;
    }
    let mut current = node;
    while let Some(parent) = current.parent() {
        if declaration_type_parameters_shadow(parent, source, reference) {
            return true;
        }
        current = parent;
    }
    false
}

fn declaration_type_parameters_shadow(
    declaration: Node<'_>,
    source: &str,
    reference: &str,
) -> bool {
    if !matches!(
        declaration.kind(),
        "class_declaration"
            | "interface_declaration"
            | "struct_declaration"
            | "record_declaration"
            | "record_struct_declaration"
            | "method_declaration"
            | "constructor_declaration"
            | "operator_declaration"
            | "delegate_declaration"
            | "local_function_statement"
    ) {
        return false;
    }
    declaration
        .child_by_field_name("type_parameters")
        .or_else(|| first_named_child_of_kind(declaration, "type_parameter_list"))
        .is_some_and(|parameters| type_parameter_list_contains(parameters, source, reference))
}

fn type_parameter_list_contains(parameters: Node<'_>, source: &str, reference: &str) -> bool {
    let mut cursor = parameters.walk();
    parameters.named_children(&mut cursor).any(|parameter| {
        parameter.kind() == "type_parameter" && type_parameter_name(parameter, source) == reference
    })
}

fn type_parameter_name<'a>(parameter: Node<'_>, source: &'a str) -> &'a str {
    parameter
        .child_by_field_name("name")
        .map(|name| node_text(name, source))
        .unwrap_or_else(|| node_text(parameter, source))
        .trim()
}

pub(super) fn type_identity_matches(left: &str, right: &str) -> bool {
    left == right
        || canonical_builtin_type_identity(left).is_some_and(|left| {
            canonical_builtin_type_identity(right).is_some_and(|right| left == right)
        })
}

pub fn canonical_builtin_type_identity(reference: &str) -> Option<&'static str> {
    match reference.strip_prefix("global::").unwrap_or(reference) {
        "bool" | "System.Boolean" => Some("System.Boolean"),
        "byte" | "System.Byte" => Some("System.Byte"),
        "sbyte" | "System.SByte" => Some("System.SByte"),
        "char" | "System.Char" => Some("System.Char"),
        "decimal" | "System.Decimal" => Some("System.Decimal"),
        "double" | "System.Double" => Some("System.Double"),
        "float" | "System.Single" => Some("System.Single"),
        "int" | "System.Int32" => Some("System.Int32"),
        "uint" | "System.UInt32" => Some("System.UInt32"),
        "nint" | "System.IntPtr" => Some("System.IntPtr"),
        "nuint" | "System.UIntPtr" => Some("System.UIntPtr"),
        "long" | "System.Int64" => Some("System.Int64"),
        "ulong" | "System.UInt64" => Some("System.UInt64"),
        "short" | "System.Int16" => Some("System.Int16"),
        "ushort" | "System.UInt16" => Some("System.UInt16"),
        "string" | "System.String" => Some("System.String"),
        "object" | "System.Object" => Some("System.Object"),
        _ => None,
    }
}

pub fn is_extension_method(graph: &CSharpGraphSource<'_>, unit: &CodeUnit) -> bool {
    unit.is_function()
        && graph.index.signature_metadata(unit).iter().any(|metadata| {
            metadata.extension_receiver_type_identity().is_some()
                || metadata.extension_receiver_type().is_some()
        })
}

pub fn extension_method_receiver_type(
    graph: &CSharpGraphSource<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    unit: &CodeUnit,
) -> Option<CSharpExtensionReceiver> {
    extension_method_receiver_type_inner(graph, csharp, token, unit, false, None)
}

fn usage_extension_method_receiver_type(
    graph: &CSharpGraphSource<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    unit: &CodeUnit,
) -> Option<CSharpExtensionReceiver> {
    extension_method_receiver_type_inner(graph, csharp, token, unit, true, None)
}

fn extension_method_receiver_type_in_session(
    graph: &CSharpGraphSource<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    unit: &CodeUnit,
    session: &ResolutionSession,
) -> Option<CSharpExtensionReceiver> {
    extension_method_receiver_type_inner(graph, csharp, token, unit, false, Some(session))
}

pub enum CSharpExtensionReceiver {
    Any,
    Exact(String),
}

/// The C# source arrives as a parameter rather than from a downcast of the
/// dispatching analyzer, which is what this body did before the move. Every
/// caller already holds the same source -- the graph entry points are reached
/// only after `resolve_analyzer::<CSharpAnalyzer>` succeeded in the shim -- so
/// the resolved value is identical and the `?` this replaces could not fail on
/// any of them.
fn extension_method_receiver_type_inner(
    graph: &CSharpGraphSource<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    unit: &CodeUnit,
    usage: bool,
    session: Option<&ResolutionSession>,
) -> Option<CSharpExtensionReceiver> {
    if !unit.is_function() {
        return None;
    }
    let owner = resolution_query(session, || graph.index.parent_of(unit)).flatten()?;
    let metadata = resolution_query_limited_rows(
        session,
        |limit| csharp.signature_metadata_limited(unit, limit),
        || csharp.signature_metadata(unit),
    );
    match session {
        Some(session) => metadata.iter().find_map(|metadata| {
            if metadata.extension_receiver_is_unconstrained_type_parameter() {
                return Some(CSharpExtensionReceiver::Any);
            }
            let identity = metadata.extension_receiver_type_identity()?;
            let name = identity.nominal_name_with(|| session.scope_step())?;
            if csharp_structured_name_is_method_type_parameter(name, metadata) {
                return None;
            }
            resolve_structured_member_type_fq_name_in_session(
                csharp,
                token,
                unit.source(),
                &owner,
                identity,
                session,
            )
            .map(CSharpExtensionReceiver::Exact)
        }),
        None => {
            if metadata
                .iter()
                .any(SignatureMetadata::extension_receiver_is_unconstrained_type_parameter)
            {
                return Some(CSharpExtensionReceiver::Any);
            }
            let receiver_type = metadata
                .iter()
                .find_map(|metadata| metadata.extension_receiver_type())?;
            let resolved = resolve_member_type_fq_name(
                csharp,
                token,
                unit.source(),
                &owner,
                receiver_type,
                usage,
            );
            resolved
                .or_else(|| Some(normalize_type_text(receiver_type)))
                .map(CSharpExtensionReceiver::Exact)
        }
    }
}

#[derive(Default)]
struct CSharpExtensionScope {
    namespaces: HashSet<String>,
    static_owner_fqns: HashSet<String>,
}

pub(super) fn extension_visibility_site_key(site: Node<'_>) -> (usize, usize) {
    let mut root = site;
    while let Some(parent) = root.parent() {
        if parent.kind() == "namespace_declaration" {
            return (parent.start_byte(), parent.end_byte());
        }
        root = parent;
    }
    let mut cursor = root.walk();
    root.named_children(&mut cursor)
        .find(|child| child.kind() == "file_scoped_namespace_declaration")
        .map_or((root.start_byte(), root.end_byte()), |namespace| {
            (namespace.start_byte(), namespace.end_byte())
        })
}

#[allow(clippy::too_many_arguments)]
pub fn visible_extension_method_candidates(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    graph: &CSharpGraphSource<'_>,
    _file: &ProjectFile,
    source: &str,
    site: Node<'_>,
    receiver_type_names: &[String],
    member: &str,
    call_arity: Option<usize>,
    explicit_generic_arity: Option<usize>,
) -> Vec<CodeUnit> {
    visible_extension_method_candidates_inner(
        csharp,
        token,
        graph,
        source,
        site,
        receiver_type_names,
        member,
        call_arity,
        explicit_generic_arity,
        false,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn visible_extension_method_candidates_in_session(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    graph: &CSharpGraphSource<'_>,
    _file: &ProjectFile,
    source: &str,
    site: Node<'_>,
    receiver_type_names: &[String],
    member: &str,
    call_arity: Option<usize>,
    explicit_generic_arity: Option<usize>,
    session: &ResolutionSession,
) -> Vec<CodeUnit> {
    visible_extension_method_candidates_inner(
        csharp,
        token,
        graph,
        source,
        site,
        receiver_type_names,
        member,
        call_arity,
        explicit_generic_arity,
        false,
        Some(session),
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn usage_visible_extension_method_candidates(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    graph: &CSharpGraphSource<'_>,
    source: &str,
    site: Node<'_>,
    receiver_type_names: &[String],
    member: &str,
    call_arity: Option<usize>,
    explicit_generic_arity: Option<usize>,
) -> Vec<CodeUnit> {
    visible_extension_method_candidates_inner(
        csharp,
        token,
        graph,
        source,
        site,
        receiver_type_names,
        member,
        call_arity,
        explicit_generic_arity,
        true,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn visible_extension_method_candidates_inner(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    graph: &CSharpGraphSource<'_>,
    source: &str,
    site: Node<'_>,
    receiver_type_names: &[String],
    member: &str,
    call_arity: Option<usize>,
    explicit_generic_arity: Option<usize>,
    usage: bool,
    session: Option<&ResolutionSession>,
) -> Vec<CodeUnit> {
    let compatible_receiver_types =
        compatible_receiver_type_names(csharp, token, graph, receiver_type_names, usage, session);
    if !usage && compatible_receiver_types.is_empty() {
        return Vec::new();
    }
    let scopes = extension_visibility_scopes(csharp, token, source, site, usage, session);
    let mut named_candidates = Vec::new();
    let named = if usage {
        resolution_query_rows(session, || {
            graph_support::usage_declaration_candidates_by_identifier(csharp, token, member)
                .to_vec()
        })
    } else {
        resolution_query_limited_rows(
            session,
            |limit| {
                csharp.declaration_candidates_by_identifier_limited(member, limit, &mut || {
                    session.is_none_or(ResolutionSession::observe_cancellation)
                })
            },
            || {
                csharp
                    .declaration_candidates_by_identifier(member)
                    .into_iter()
                    .collect()
            },
        )
    };
    for unit in named {
        if !resolution_scope_step(session) {
            return Vec::new();
        }
        if unit.is_function() && unit.identifier() == member {
            named_candidates.push(unit);
        }
    }
    // Extension lookup normally stops at the nearest enclosing scope that offers
    // an applicable declaration, which is what C# does: a `using`-imported
    // extension loses to one declared in an enclosing namespace. Applicability
    // is decided by the receiver type, so that ordering is only meaningful when
    // the scan knows it. A usage-mode site whose receiver never typed --
    // an external or open-generic receiver, or a capture the local binder cannot
    // see -- has no receiver to decide with, and stopping at the nearest scope
    // there names one same-spelled declaration and silently disclaims every
    // other one. In ILSpy that made `typeHint.GetStackType()` answer
    // `IL.ILTypeExtensions.GetStackType(this PrimitiveType)` from the enclosing
    // namespace and report the actual `TypeSystem.TypeUtils.GetStackType(this
    // IType)` target as verified-absent (#1261). Untyped, every visible scope's
    // candidates are equally possible, so they are all returned and the caller
    // records the site as unproven rather than proving or disclaiming one.
    let receiver_is_untyped = usage && compatible_receiver_types.is_empty();
    let mut untyped_receiver_candidates = Vec::new();
    for scope in scopes {
        if !resolution_scope_step(session) {
            return Vec::new();
        }
        let mut candidates = Vec::new();
        for unit in &named_candidates {
            if !resolution_scope_step(session) {
                return Vec::new();
            }
            if scope.namespaces.contains(unit.package_name()) {
                candidates.push(unit.clone());
            }
        }
        for owner_fqn in &scope.static_owner_fqns {
            if !resolution_scope_step(session) {
                return Vec::new();
            }
            let static_candidates = if usage {
                resolution_query_rows(session, || {
                    graph_support::usage_member_candidates_for_owner(
                        csharp, token, owner_fqn, member,
                    )
                })
            } else {
                resolution_query_limited_rows(
                    session,
                    |limit| {
                        csharp.member_candidates_for_owner_limited(
                            owner_fqn,
                            member,
                            limit,
                            &mut || session.is_none_or(ResolutionSession::observe_cancellation),
                        )
                    },
                    || {
                        csharp
                            .member_candidates_for_owner(owner_fqn, member)
                            .into_iter()
                            .collect()
                    },
                )
            };
            for unit in static_candidates {
                if !resolution_scope_step(session) {
                    return Vec::new();
                }
                if unit.is_function() && unit.identifier() == member {
                    candidates.push(unit);
                }
            }
        }
        candidates.sort();
        candidates.dedup();
        let mut filtered = Vec::new();
        for unit in candidates {
            if !resolution_scope_step(session) {
                return Vec::new();
            }
            if explicit_generic_arity
                .is_some_and(|arity| csharp_method_generic_arity(unit.signature()) != arity)
            {
                continue;
            }
            let receiver = if usage {
                usage_extension_method_receiver_type(graph, csharp, token, &unit)
            } else if let Some(session) = session {
                extension_method_receiver_type_in_session(graph, csharp, token, &unit, session)
            } else {
                extension_method_receiver_type(graph, csharp, token, &unit)
            };
            if session.is_some_and(|session| !session.observe_cancellation()) {
                return Vec::new();
            }
            let Some(receiver) = receiver else {
                continue;
            };
            let matches_receiver = |receiver: &str| {
                let receiver = csharp_normalize_full_name(receiver);
                compatible_receiver_types
                    .iter()
                    .any(|candidate| type_identity_matches(candidate, &receiver))
            };
            let compatible = match receiver {
                CSharpExtensionReceiver::Any => true,
                CSharpExtensionReceiver::Exact(receiver) => {
                    (usage && compatible_receiver_types.is_empty()) || matches_receiver(&receiver)
                }
            };
            if compatible {
                filtered.push(unit);
            }
        }
        let candidates = filtered;
        let Some(call_arity) = call_arity else {
            if !candidates.is_empty() {
                if receiver_is_untyped {
                    untyped_receiver_candidates.extend(candidates);
                    continue;
                }
                return candidates;
            }
            continue;
        };
        let Some(declared_arity) = call_arity.checked_add(1) else {
            return Vec::new();
        };
        let applicable = candidates
            .iter()
            .filter(|candidate| {
                resolution_scope_step(session)
                    && resolution_query(session, || {
                        csharp_callable_arity(graph.index, candidate).accepts(declared_arity)
                    })
                    .unwrap_or(false)
            })
            .cloned()
            .collect::<Vec<_>>();
        if !applicable.is_empty() {
            if receiver_is_untyped {
                untyped_receiver_candidates.extend(applicable);
                continue;
            }
            return applicable;
        }
        // A declaration whose parameter list cannot accept this argument list is
        // not the target -- the same verdict #1797 made the ordinary member walk
        // give, and the one every other caller of this scan has always taken.
        // Only the forward member branch asked for the rejected set back, which
        // is how jellyfin's one-argument `typeFilter.Contains(e.Type)` answered
        // the three-parameter `EnumerableExtensions.Contains` and the MCP SDK's
        // `options.GetTypeInfo(typeof(T))` answered a receiver-only extension
        // (#1266). Neither the inverse scan nor extension return typing ever
        // saw those bindings, which is exactly why they surfaced as
        // forward/inverse disagreements.
    }
    untyped_receiver_candidates.sort();
    untyped_receiver_candidates.dedup();
    untyped_receiver_candidates
}

fn extension_visibility_scopes(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    source: &str,
    site: Node<'_>,
    usage: bool,
    session: Option<&ResolutionSession>,
) -> Vec<CSharpExtensionScope> {
    let mut root = site;
    let mut namespace_nodes = Vec::new();
    while let Some(parent) = root.parent() {
        if !resolution_scope_step(session) {
            return Vec::new();
        }
        if parent.kind() == "namespace_declaration" {
            namespace_nodes.push(parent);
        }
        root = parent;
    }

    let mut namespace_declarations = Vec::with_capacity(namespace_nodes.len());
    let mut namespace = String::new();
    for declaration in namespace_nodes.iter().rev() {
        if !resolution_scope_step(session) {
            return Vec::new();
        }
        let Some(name) = declaration.child_by_field_name("name") else {
            continue;
        };
        let segment = csharp_type_node_identity(name, source);
        if segment.is_empty() {
            continue;
        }
        let parent_namespace = namespace.clone();
        namespace = if parent_namespace.is_empty() {
            segment
        } else {
            format!("{parent_namespace}.{segment}")
        };
        namespace_declarations.push((*declaration, parent_namespace, namespace.clone()));
    }

    let mut scopes = Vec::new();
    for (declaration, parent_namespace, namespace) in namespace_declarations.iter().rev() {
        if !resolution_scope_step(session) {
            return Vec::new();
        }
        push_namespace_scopes(
            csharp,
            token,
            source,
            &mut scopes,
            namespace,
            parent_namespace,
            declaration.child_by_field_name("body"),
            0,
            usize::MAX,
            usage,
            session,
        );
    }

    let file_scoped_declaration = if namespace_nodes.is_empty() {
        let mut cursor = root.walk();
        root.named_children(&mut cursor)
            .find(|child| child.kind() == "file_scoped_namespace_declaration")
    } else {
        None
    };
    if let Some(declaration) = file_scoped_declaration
        && let Some(namespace) = declaration
            .child_by_field_name("name")
            .map(|name| csharp_type_node_identity(name, source))
            .filter(|namespace| !namespace.is_empty())
    {
        push_namespace_scopes(
            csharp,
            token,
            source,
            &mut scopes,
            &namespace,
            "",
            Some(root),
            declaration.end_byte(),
            usize::MAX,
            usage,
            session,
        );
    }

    let mut compilation_scope = CSharpExtensionScope::default();
    compilation_scope.namespaces.insert(String::new());
    collect_scope_using_directives(
        csharp,
        token,
        source,
        root,
        "",
        0,
        file_scoped_declaration.map_or(usize::MAX, |declaration| declaration.start_byte()),
        &mut compilation_scope,
        usage,
        session,
    );
    compilation_scope
        .namespaces
        .extend(resolution_query_limited_rows(
            session,
            |limit| {
                csharp.global_using_namespaces_limited(limit, &mut || {
                    session.is_none_or(ResolutionSession::observe_cancellation)
                })
            },
            || csharp.global_using_namespaces().iter().cloned().collect(),
        ));
    let global_static_owner_fqns = resolution_query_limited_rows(
        session,
        |limit| {
            csharp.global_static_using_type_names_limited(limit, &mut || {
                session.is_none_or(ResolutionSession::observe_cancellation)
            })
        },
        || {
            if usage {
                csharp
                    .usage_global_static_using_types()
                    .iter()
                    .map(CodeUnit::fq_name)
                    .collect()
            } else {
                csharp
                    .global_static_using_types()
                    .iter()
                    .map(CodeUnit::fq_name)
                    .collect()
            }
        },
    );
    compilation_scope
        .static_owner_fqns
        .extend(global_static_owner_fqns);
    scopes.push(compilation_scope);
    scopes
}

#[allow(clippy::too_many_arguments)]
fn push_namespace_scopes(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    source: &str,
    scopes: &mut Vec<CSharpExtensionScope>,
    namespace: &str,
    parent_namespace: &str,
    using_scope_node: Option<Node<'_>>,
    using_start: usize,
    using_end: usize,
    usage: bool,
    session: Option<&ResolutionSession>,
) {
    let mut current = namespace.to_string();
    let mut include_usings = true;
    while !current.is_empty() && current != parent_namespace {
        if !resolution_scope_step(session) {
            return;
        }
        let mut scope = CSharpExtensionScope::default();
        scope.namespaces.insert(current.clone());
        if include_usings && let Some(scope_node) = using_scope_node {
            collect_scope_using_directives(
                csharp,
                token,
                source,
                scope_node,
                &current,
                using_start,
                using_end,
                &mut scope,
                usage,
                session,
            );
        }
        scopes.push(scope);
        include_usings = false;
        let Some(parent) = csharp_namespace_parent(&current) else {
            break;
        };
        current = parent;
    }
}

/// The namespace one level outward from `current` (its dotted prefix with the
/// innermost component dropped), or `None` if `current` is already a single
/// component. A C# namespace path is `.`-joined with no embedded delimiters in
/// any single identifier segment, so re-tokenizing it with the shared
/// structured splitter and dropping the innermost component reproduces
/// `rsplit_once('.')`'s outward walk exactly (mirrors the cpp namespace-chain
/// walk in `cpp_qualifier_lookup_tiers`).
fn csharp_namespace_parent(current: &str) -> Option<String> {
    let mut parts =
        brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path(Language::CSharp, current);
    if parts.len() <= 1 {
        return None;
    }
    parts.pop();
    Some(parts.join("."))
}

#[allow(clippy::too_many_arguments)]
fn collect_scope_using_directives(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    source: &str,
    scope_node: Node<'_>,
    resolution_namespace: &str,
    using_start: usize,
    using_end: usize,
    scope: &mut CSharpExtensionScope,
    usage: bool,
    session: Option<&ResolutionSession>,
) {
    let mut cursor = scope_node.walk();
    for directive in scope_node.named_children(&mut cursor).filter(|child| {
        child.kind() == "using_directive"
            && !csharp_using_directive_is_global(*child)
            && using_start <= child.start_byte()
            && child.end_byte() <= using_end
    }) {
        if !resolution_scope_step(session) {
            return;
        }
        if csharp_using_directive_is_static(directive) {
            if let Some(target) = csharp_using_directive_target(directive, source)
                && let Some(owner) = namespace_relative_names(resolution_namespace, &target)
                    .into_iter()
                    .find_map(|candidate| {
                        if !resolution_scope_step(session) {
                            return None;
                        }
                        if usage {
                            resolution_query(session, || {
                                class_unit_for_fq_name(csharp, token, &candidate)
                            })
                            .flatten()
                        } else {
                            resolution_query(session, || {
                                forward_class_unit_for_fq_name(csharp, &candidate)
                            })
                            .flatten()
                        }
                    })
            {
                scope.static_owner_fqns.insert(owner.fq_name());
            }
        } else if let Some(target) = csharp_using_directive_namespace(directive, source) {
            let namespace = namespace_relative_names(resolution_namespace, &target)
                .into_iter()
                .find(|candidate| {
                    if !resolution_scope_step(session) {
                        return false;
                    }
                    if usage {
                        resolution_query(session, || {
                            graph_support::usage_workspace_namespace_exists(
                                csharp, token, candidate,
                            )
                        })
                        .unwrap_or(false)
                    } else {
                        resolution_query(session, || csharp.workspace_namespace_exists(candidate))
                            .unwrap_or(false)
                    }
                })
                .unwrap_or_else(|| normalize_type_text(&target));
            if !namespace.is_empty() {
                scope.namespaces.insert(namespace);
            }
        }
    }
}

fn namespace_relative_names(namespace: &str, target: &str) -> Vec<String> {
    let target = normalize_type_text(target);
    if target.is_empty() {
        return Vec::new();
    }
    if target.starts_with("global::") {
        return vec![target.trim_start_matches("global::").to_string()];
    }
    let mut names = Vec::new();
    let mut prefix = namespace.to_string();
    while !prefix.is_empty() {
        names.push(format!("{prefix}.{target}"));
        prefix = csharp_namespace_parent(&prefix).unwrap_or_default();
    }
    names.push(target);
    names
}

pub fn compatible_receiver_type_names(
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    graph: &CSharpGraphSource<'_>,
    receiver_type_names: &[String],
    usage: bool,
    session: Option<&ResolutionSession>,
) -> HashSet<String> {
    let mut compatible = HashSet::default();
    for receiver_type in receiver_type_names {
        if !resolution_scope_step(session) {
            return HashSet::default();
        }
        compatible.insert(csharp_normalize_full_name(receiver_type));
        let owners = if usage {
            resolution_query_rows(session, || {
                graph_support::usage_type_candidates_by_fqn(csharp, token, receiver_type)
            })
        } else if let Some(session) = session {
            forward_type_declarations_for_fq_name_in_session(csharp, receiver_type, session)
        } else {
            forward_type_declarations_for_fq_name(csharp, receiver_type)
        };
        for owner in owners {
            if !resolution_scope_step(session) {
                return HashSet::default();
            }
            if usage {
                let mut stack = resolution_summary_rows(session, || {
                    hierarchy::usage_direct_ancestors(csharp, token, &owner)
                });
                let mut seen = HashSet::default();
                while let Some(ancestor) = stack.pop() {
                    if !resolution_scope_step(session) {
                        return HashSet::default();
                    }
                    if !seen.insert(ancestor.clone()) {
                        continue;
                    }
                    compatible.insert(csharp_normalize_full_name(&ancestor.fq_name()));
                    stack.extend(resolution_summary_rows(session, || {
                        hierarchy::usage_direct_ancestors(csharp, token, &ancestor)
                    }));
                }
            } else if let Some(session) = session {
                let mut stack = forward_direct_ancestors_in_session(csharp, token, &owner, session);
                if !session.observe_cancellation() {
                    return HashSet::default();
                }
                let mut seen = HashSet::default();
                while let Some(ancestor) = stack.pop() {
                    if !resolution_scope_step(Some(session)) {
                        return HashSet::default();
                    }
                    if !seen.insert(ancestor.clone()) {
                        continue;
                    }
                    compatible.insert(csharp_normalize_full_name(&ancestor.fq_name()));
                    let direct =
                        forward_direct_ancestors_in_session(csharp, token, &ancestor, session);
                    if !session.observe_cancellation() {
                        return HashSet::default();
                    }
                    stack.extend(direct);
                }
            } else if let Some(provider) = graph.hierarchy {
                let mut stack = provider.get_direct_ancestors(&owner);
                let mut seen = HashSet::default();
                while let Some(ancestor) = stack.pop() {
                    if !seen.insert(ancestor.clone()) {
                        continue;
                    }
                    compatible.insert(csharp_normalize_full_name(&ancestor.fq_name()));
                    stack.extend(provider.get_direct_ancestors(&ancestor));
                }
            }
        }
    }
    compatible
}

fn reference_matches_target_fq_name(reference: &str, target: &CodeUnit) -> bool {
    reference == target.fq_name() || reference == target.fq_name().replace('$', ".")
}

pub(super) fn normalize_type_text(reference: &str) -> String {
    let mut normalized = reference.trim();
    loop {
        let without_nullable = normalized.trim_end_matches('?').trim();
        let without_arrays = without_nullable.trim_end_matches("[]").trim();
        if without_arrays == normalized {
            break;
        }
        normalized = without_arrays;
    }
    normalized
        .split('<')
        .next()
        .unwrap_or(normalized)
        .trim()
        .to_string()
}

pub fn reference_type_node(mut node: Node<'_>) -> Node<'_> {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "qualified_name" | "generic_name" | "nullable_type" | "array_type"
        ) {
            node = parent;
            continue;
        }
        break;
    }
    node
}

pub fn reference_type_text(node: Node<'_>, source: &str) -> String {
    csharp_type_node_identity(reference_type_node(node), source)
}

/// The outermost node whose locals and parameters are lexically visible at
/// `node`: the enclosing member declaration.
///
/// The walk deliberately passes *through* `local_function_statement` and
/// `lambda_expression`. C# name lookup inside a local function continues into
/// the enclosing method, so a local function body sees that method's parameters
/// and its locals declared before the local function (#2172). Capturing does
/// not change visibility: a `static` local function that names an enclosing
/// local is rejected as CS8421, "a static local function cannot contain a
/// reference to 'x'", which is a capture error naming the binding lookup found,
/// not a lookup failure. Stopping at the local function instead made every
/// receiver inside one untyped.
///
/// `seed_visible_bindings_at` walks down from here and opens one binding scope
/// per nested scope it enters, so a local function's own parameters and locals
/// still shadow the enclosing ones by nearest-scope-wins, and its textual
/// position rule already matches C#'s CS0841, "cannot use local variable before
/// it is declared".
pub fn binding_scope_node(mut node: Node<'_>) -> Node<'_> {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "method_declaration"
                | "constructor_declaration"
                | "property_declaration"
                | "accessor_declaration"
        ) {
            return parent;
        }
        node = parent;
    }
    node
}

pub(super) fn receiver_targets_owner(
    receiver_node: Node<'_>,
    graph: &CSharpGraphSource<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    bindings: &LocalInferenceEngine<String>,
) -> SymbolResolution<String> {
    receiver_type_fq_names(receiver_node, graph, csharp, token, file, source, bindings)
}

fn receiver_type_fq_names(
    receiver_node: Node<'_>,
    graph: &CSharpGraphSource<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    bindings: &LocalInferenceEngine<String>,
) -> SymbolResolution<String> {
    match receiver_node.kind() {
        "identifier" => {
            let receiver = node_text(receiver_node, source);
            match bindings.resolve_symbol(receiver) {
                SymbolResolution::Precise(targets) => SymbolResolution::Precise(targets),
                SymbolResolution::Unknown if !bindings.is_shadowed(receiver) => {
                    usage_class_field_receiver_type(
                        receiver_node,
                        receiver,
                        graph,
                        csharp,
                        token,
                        file,
                        source,
                    )
                }
                resolution => resolution,
            }
        }
        "member_access_expression" | "conditional_access_expression" => {
            expression_type_fq_name(receiver_node, csharp, token, file, source, bindings)
                .map(|fq_name| SymbolResolution::Precise(std::iter::once(fq_name).collect()))
                .unwrap_or(SymbolResolution::Unknown)
        }
        "invocation_expression" => {
            expression_type_fq_name(receiver_node, csharp, token, file, source, bindings)
                .map(|fq_name| SymbolResolution::Precise(std::iter::once(fq_name).collect()))
                .unwrap_or(SymbolResolution::Unknown)
        }
        "object_creation_expression" => object_created_type(receiver_node)
            .and_then(|type_node| {
                resolve_usage_type_fq_name(
                    csharp,
                    token,
                    file,
                    &reference_type_text(type_node, source),
                )
            })
            .map(|fq_name| SymbolResolution::Precise(std::iter::once(fq_name).collect()))
            .unwrap_or(SymbolResolution::Unknown),
        "parenthesized_expression" | "checked_expression" => receiver_node
            .named_child(0)
            .map(|inner| {
                receiver_type_fq_names(inner, graph, csharp, token, file, source, bindings)
            })
            .unwrap_or(SymbolResolution::Unknown),
        "cast_expression" | "as_expression" => receiver_node
            .child_by_field_name(if receiver_node.kind() == "cast_expression" {
                "type"
            } else {
                "right"
            })
            .and_then(|type_node| {
                resolve_usage_type_fq_name(
                    csharp,
                    token,
                    file,
                    &reference_type_text(type_node, source),
                )
            })
            .map(|fq_name| SymbolResolution::Precise(std::iter::once(fq_name).collect()))
            .unwrap_or(SymbolResolution::Unknown),
        "this" => enclosing_declared_type(receiver_node, csharp, token, file, source)
            .map(|owner| SymbolResolution::Precise(std::iter::once(owner.fq_name()).collect()))
            .unwrap_or(SymbolResolution::Unknown),
        "base" => enclosing_declared_type(receiver_node, csharp, token, file, source)
            .and_then(|owner| usage_direct_base(graph, csharp, token, &owner))
            .map(|owner| SymbolResolution::Precise(std::iter::once(owner.fq_name()).collect()))
            .unwrap_or(SymbolResolution::Unknown),
        _ => SymbolResolution::Unknown,
    }
}

pub(super) fn usage_class_field_receiver_type(
    receiver_node: Node<'_>,
    receiver: &str,
    graph: &CSharpGraphSource<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
) -> SymbolResolution<String> {
    let Some(enclosing) = enclosing_declared_type(receiver_node, csharp, token, file, source)
    else {
        return SymbolResolution::Unknown;
    };
    let candidates =
        nearest_member_candidates_for_owner(graph, csharp, token, &enclosing, receiver, None)
            .into_iter()
            .filter(|candidate| {
                !(candidate.is_function()
                    && graph.index.parent_of(candidate).is_some_and(|owner| {
                        candidate.identifier() == csharp_source_identifier(&owner)
                    }))
            })
            .collect::<Vec<_>>();
    if candidates.is_empty() {
        return SymbolResolution::Unknown;
    }
    let mut resolved_types = candidates
        .iter()
        .filter(|candidate| candidate.is_field())
        .filter_map(|candidate| graph.index.parent_of(candidate))
        .filter_map(|owner| usage_member_declared_type_fq_name(csharp, token, &owner, receiver))
        .collect::<Vec<_>>();
    resolved_types.sort();
    resolved_types.dedup();
    if resolved_types.len() == 1 {
        SymbolResolution::Precise(resolved_types.into_iter().collect())
    } else {
        SymbolResolution::Ambiguous
    }
}

/// Whether an unqualified identifier binds to a value member on the enclosing
/// type or its nearest declaring ancestor. This is deliberately independent of
/// declared-type inference: constants and other value members still shadow a
/// visible type with the same name even when their type cannot be resolved.
pub(super) fn usage_unqualified_value_member_shadows_type(
    node: Node<'_>,
    name: &str,
    graph: &CSharpGraphSource<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
) -> bool {
    let Some(enclosing) = enclosing_declared_type(node, csharp, token, file, source) else {
        return false;
    };
    nearest_member_candidates_for_owner(graph, csharp, token, &enclosing, name, None)
        .iter()
        .any(CodeUnit::is_field)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn usage_relational_generic_call_has_type_argument(
    call: CSharpRelationalGenericCall<'_>,
    graph: &CSharpGraphSource<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    class_ranges: &ClassRangeIndex,
    source: &str,
    bindings: &LocalInferenceEngine<String>,
) -> bool {
    let Some(leftmost) = csharp_type_leftmost_identifier(call.type_argument) else {
        return false;
    };
    let name = node_text(leftmost, source);
    if member_name_is_locally_bound(name, bindings)
        || unqualified_member_has_structured_shadow(leftmost, source)
        || usage_unqualified_value_member_shadows_type(
            leftmost, name, graph, csharp, token, file, source,
        )
    {
        return false;
    }
    let reference = reference_type_text(call.type_argument, source);
    resolve_type_fq_name_at(
        csharp,
        token,
        file,
        class_ranges,
        &reference,
        call.type_argument,
        source,
    )
    .is_some()
}

/// Whether an unqualified `member_name` is bound by a local (parameter or local
/// variable) of the same name in scope — in which case it is provably *not* the
/// field, so the occurrence should be skipped rather than treated as an ambiguous
/// (fallback-forcing) match.
pub(super) fn member_name_is_locally_bound(
    member_name: &str,
    bindings: &LocalInferenceEngine<String>,
) -> bool {
    !matches!(
        bindings.resolve_symbol(member_name),
        SymbolResolution::Unknown
    ) || bindings.is_shadowed(member_name)
}

#[derive(Clone)]
pub(super) enum UnqualifiedMethodGroupResolution {
    Unique(CodeUnit),
    Ambiguous(Vec<CodeUnit>),
    NoMember,
}

pub(super) fn nearest_member_candidates_for_owner(
    graph: &CSharpGraphSource<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    owner: &CodeUnit,
    name: &str,
    explicit_generic_arity: Option<usize>,
) -> Vec<CodeUnit> {
    nearest_member_candidates_for_owner_inner(
        graph,
        csharp,
        token,
        owner,
        name,
        explicit_generic_arity,
        None,
        true,
        None,
    )
}

pub(super) fn applicable_member_candidates_for_owner(
    graph: &CSharpGraphSource<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    owner: &CodeUnit,
    name: &str,
    explicit_generic_arity: Option<usize>,
    call_arity: usize,
) -> Vec<CodeUnit> {
    nearest_member_candidates_for_owner_inner(
        graph,
        csharp,
        token,
        owner,
        name,
        explicit_generic_arity,
        Some(call_arity),
        true,
        None,
    )
}

/// Resolve the callable selected by invocation syntax. The invocation may call
/// either a method or the delegate value read from a field/property, so only
/// method candidates are constrained by the outer argument list.
pub(super) fn invocation_member_candidates_for_owner(
    graph: &CSharpGraphSource<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    owner: &CodeUnit,
    name: &str,
    explicit_generic_arity: Option<usize>,
    call_arity: usize,
) -> Vec<CodeUnit> {
    let mut candidates = applicable_member_candidates_for_owner(
        graph,
        csharp,
        token,
        owner,
        name,
        explicit_generic_arity,
        call_arity,
    );
    if explicit_generic_arity.is_none() {
        candidates.extend(
            nearest_member_candidates_for_owner(graph, csharp, token, owner, name, None)
                .into_iter()
                .filter(|candidate| !candidate.is_function()),
        );
    }
    candidates.sort();
    candidates.dedup();
    candidates
}

#[allow(clippy::too_many_arguments)]
pub fn nearest_member_candidates_for_owner_inner(
    graph: &CSharpGraphSource<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    owner: &CodeUnit,
    name: &str,
    explicit_generic_arity: Option<usize>,
    call_arity: Option<usize>,
    usage: bool,
    session: Option<&ResolutionSession>,
) -> Vec<CodeUnit> {
    let mut hierarchy = None;
    let mut seen = HashSet::default();
    let mut level = if usage {
        resolution_query_rows(session, || {
            graph_support::usage_partial_type_parts(csharp, token, owner)
        })
    } else {
        resolution_query_limited_rows(
            session,
            |limit| {
                graph_support::partial_type_parts_limited(csharp, owner, limit, || {
                    session.is_none_or(ResolutionSession::observe_cancellation)
                })
            },
            || graph_support::partial_type_parts(csharp, owner),
        )
    };
    if level.is_empty() {
        if !resolution_scope_step(session) {
            return Vec::new();
        }
        level.push(owner.clone());
    }
    while !level.is_empty() {
        if !resolution_scope_step(session) {
            return Vec::new();
        }
        let mut members = Vec::new();
        let mut current_level = Vec::new();
        for current in level {
            if !resolution_scope_step(session) {
                return Vec::new();
            }
            if !seen.insert(current.clone()) {
                continue;
            }
            let candidates = if usage {
                resolution_query_rows(session, || {
                    graph_support::usage_member_candidates_for_owner(
                        csharp,
                        token,
                        &current.fq_name(),
                        name,
                    )
                })
            } else {
                resolution_query_limited_rows(
                    session,
                    |limit| {
                        csharp.member_candidates_for_owner_limited(
                            &current.fq_name(),
                            name,
                            limit,
                            &mut || session.is_none_or(ResolutionSession::observe_cancellation),
                        )
                    },
                    || {
                        csharp
                            .member_candidates_for_owner(&current.fq_name(), name)
                            .into_iter()
                            .collect()
                    },
                )
            };
            for candidate in candidates {
                if !resolution_scope_step(session) {
                    return Vec::new();
                }
                if candidate.identifier() != name {
                    continue;
                }
                let parent_matches =
                    resolution_query(session, || graph.index.parent_of(&candidate))
                        .flatten()
                        .is_some_and(|parent| parent.fq_name() == current.fq_name());
                if !parent_matches {
                    continue;
                }
                if !explicit_generic_arity.is_none_or(|arity| {
                    candidate.is_function()
                        && csharp_method_generic_arity(candidate.signature()) == arity
                }) {
                    continue;
                }
                let accepts_arity = call_arity.is_none_or(|arity| {
                    candidate.is_function()
                        && resolution_query(session, || {
                            csharp_callable_arity(graph.index, &candidate).accepts(arity)
                        })
                        .unwrap_or(false)
                });
                if accepts_arity {
                    members.push(candidate);
                }
            }
            current_level.push(current);
        }
        members.sort();
        members.dedup();
        if !members.is_empty() {
            return members;
        }
        if !usage && session.is_none() && hierarchy.is_none() {
            hierarchy = graph.hierarchy;
        }
        let mut next_level = Vec::new();
        if usage {
            for current in current_level {
                if !resolution_scope_step(session) {
                    return Vec::new();
                }
                for ancestor in resolution_summary_rows(session, || {
                    hierarchy::usage_direct_ancestors(csharp, token, &current)
                }) {
                    if !resolution_scope_step(session) {
                        return Vec::new();
                    }
                    let mut parts = resolution_query_rows(session, || {
                        graph_support::usage_partial_type_parts(csharp, token, &ancestor)
                    });
                    if parts.is_empty() {
                        if !resolution_scope_step(session) {
                            return Vec::new();
                        }
                        parts.push(ancestor);
                    }
                    next_level.extend(parts);
                }
            }
        } else if let Some(session) = session {
            for current in current_level {
                if !session.scope_step() {
                    return Vec::new();
                }
                for ancestor in
                    forward_direct_ancestors_in_session(csharp, token, &current, session)
                {
                    if !session.scope_step() {
                        return Vec::new();
                    }
                    let mut parts = session.query_limited_rows(|limit| {
                        graph_support::partial_type_parts_limited(csharp, &ancestor, limit, || {
                            session.observe_cancellation()
                        })
                    });
                    if !session.observe_cancellation() {
                        return Vec::new();
                    }
                    if parts.is_empty() {
                        if !session.scope_step() {
                            return Vec::new();
                        }
                        parts.push(ancestor);
                    }
                    next_level.extend(parts);
                }
            }
        } else if let Some(hierarchy) = hierarchy {
            for current in current_level {
                for ancestor in hierarchy.get_direct_ancestors(&current) {
                    let mut parts = graph_support::partial_type_parts(csharp, &ancestor);
                    if parts.is_empty() {
                        parts.push(ancestor);
                    }
                    next_level.extend(parts);
                }
            }
        }
        level = next_level;
    }
    Vec::new()
}

pub(super) fn unqualified_member_has_local_binding(
    node: Node<'_>,
    source: &str,
    bindings: &LocalInferenceEngine<String>,
) -> bool {
    member_name_is_locally_bound(node_text(node, source), bindings)
}

pub(super) fn unqualified_member_has_structured_shadow(node: Node<'_>, source: &str) -> bool {
    let name = node_text(node, source);
    local_function_name_is_in_scope(node, source, name)
        || structured_local_name_is_in_scope(node, source, name)
}

pub(super) fn resolve_unqualified_method_group_for_owner(
    graph: &CSharpGraphSource<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    owner: &CodeUnit,
    name: &str,
) -> UnqualifiedMethodGroupResolution {
    let members = nearest_member_candidates_for_owner(graph, csharp, token, owner, name, None);
    if members.is_empty() {
        return UnqualifiedMethodGroupResolution::NoMember;
    }
    let mut candidates = members
        .iter()
        .filter(|candidate| {
            candidate.is_function()
                && graph
                    .index
                    .parent_of(candidate)
                    .is_some_and(|declaring_owner| {
                        candidate.identifier() != csharp_source_identifier(&declaring_owner)
                    })
        })
        .cloned()
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.dedup();
    if candidates.len() != members.len() {
        return UnqualifiedMethodGroupResolution::NoMember;
    }
    if candidates.len() == 1 {
        return UnqualifiedMethodGroupResolution::Unique(candidates.remove(0));
    }
    UnqualifiedMethodGroupResolution::Ambiguous(candidates)
}

fn local_function_name_is_in_scope(node: Node<'_>, source: &str, name: &str) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if matches!(parent.kind(), "block" | "switch_section") {
            let mut cursor = parent.walk();
            if parent.named_children(&mut cursor).any(|child| {
                child.kind() == "local_function_statement"
                    && child
                        .child_by_field_name("name")
                        .is_some_and(|candidate| node_text(candidate, source) == name)
            }) {
                return true;
            }
        }
        current = parent;
    }
    false
}

fn structured_local_name_is_in_scope(node: Node<'_>, source: &str, name: &str) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "foreach_statement"
            && parent
                .child_by_field_name("body")
                .is_some_and(|body| node_covers(body, node))
            && parent
                .child_by_field_name("left")
                .is_some_and(|left| binding_container_has_name(left, source, name))
        {
            return true;
        }

        let mut cursor = parent.walk();
        for sibling in parent.named_children(&mut cursor) {
            if same_node(sibling, current) || sibling.start_byte() >= current.start_byte() {
                break;
            }
            if prior_node_declares_local_name(sibling, source, name) {
                return true;
            }
        }
        current = parent;
    }
    false
}

fn prior_node_declares_local_name(root: Node<'_>, source: &str, name: &str) -> bool {
    if LOCAL_BINDING_SCOPE_BARRIERS.contains(&root.kind()) {
        return false;
    }
    let mut stack = vec![root];
    while let Some(current) = stack.pop() {
        if !same_node(current, root) && LOCAL_BINDING_SCOPE_BARRIERS.contains(&current.kind()) {
            continue;
        }
        if matches!(
            current.kind(),
            "variable_declarator"
                | "declaration_expression"
                | "declaration_pattern"
                | "catch_declaration"
                | "tuple_pattern"
                | "parenthesized_variable_designation"
        ) && binding_container_has_name(current, source, name)
        {
            return true;
        }
        let mut cursor = current.walk();
        let mut children = current.named_children(&mut cursor).collect::<Vec<_>>();
        children.reverse();
        stack.extend(children);
    }
    false
}

const LOCAL_BINDING_SCOPE_BARRIERS: &[&str] = &[
    "block",
    "method_declaration",
    "constructor_declaration",
    "destructor_declaration",
    "operator_declaration",
    "property_declaration",
    "accessor_declaration",
    "local_function_statement",
    "lambda_expression",
    "anonymous_method_expression",
    "field_declaration",
    "event_field_declaration",
    "class_declaration",
    "interface_declaration",
    "struct_declaration",
    "record_declaration",
    "record_struct_declaration",
    "for_statement",
    "foreach_statement",
    "using_statement",
    "catch_clause",
];

fn binding_container_has_name(node: Node<'_>, source: &str, name: &str) -> bool {
    if node.kind() == "identifier" {
        return node_text(node, source) == name;
    }
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        for index in 0..current.child_count() {
            let Some(child) = current.child(index) else {
                continue;
            };
            if !child.is_named() {
                continue;
            }
            if current.field_name_for_child(index as u32) == Some("name")
                && child.kind() == "identifier"
                && node_text(child, source) == name
            {
                return true;
            }
            if matches!(
                child.kind(),
                "tuple_pattern" | "parenthesized_variable_designation"
            ) {
                stack.push(child);
            }
        }
    }
    false
}

/// An unqualified identifier (no receiver) that matches a field/property name resolves to
/// that field only when it appears inside the owning type and is not shadowed by a local
/// binding (parameter or local variable) of the same name. This proves self-references such
/// as `Last = value` inside a method of the field's own class.
#[allow(clippy::too_many_arguments)]
pub(super) fn unqualified_member_resolves_to_owner(
    node: Node<'_>,
    member_name: &str,
    owner: &CodeUnit,
    graph: &CSharpGraphSource<'_>,
    csharp: &dyn CSharpSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    bindings: &LocalInferenceEngine<String>,
) -> bool {
    if member_name_is_locally_bound(member_name, bindings) {
        return false;
    }
    enclosing_declared_type(node, csharp, token, file, source).is_some_and(|enclosing| {
        let candidates = nearest_member_candidates_for_owner(
            graph,
            csharp,
            token,
            &enclosing,
            member_name,
            None,
        );
        candidates.iter().any(|candidate| {
            graph
                .index
                .parent_of(candidate)
                .is_some_and(|declaring_owner| declaring_owner.fq_name() == owner.fq_name())
        })
    })
}

pub fn is_type_reference_node(node: Node<'_>) -> bool {
    csharp_type_reference_root(node).is_some()
}

pub fn argument_count(node: Node<'_>, _source: &str) -> usize {
    let Some(arguments) = node
        .child_by_field_name("arguments")
        .or_else(|| first_named_child_of_kind(node, "argument_list"))
    else {
        return 0;
    };
    count_named_children_of_kind(arguments, "argument")
}

pub fn object_initializer_for_label(node: Node<'_>) -> Option<Node<'_>> {
    let parent = node.parent()?;
    if parent.kind() != "assignment_expression" {
        return None;
    }
    if parent.child_by_field_name("left") != Some(node) && parent.named_child(0) != Some(node) {
        return None;
    }
    let initializer = parent.parent()?;
    matches!(
        initializer.kind(),
        "initializer_expression" | "object_initializer_expression"
    )
    .then_some(initializer)
}

pub fn object_initializer_owner_type_node(initializer: Node<'_>) -> Option<Node<'_>> {
    let object_creation = initializer.parent()?;
    match object_creation.kind() {
        "object_creation_expression" => object_creation
            .child_by_field_name("type")
            .or_else(|| first_type_child(object_creation))
            .or_else(|| implicit_object_creation_target_type(object_creation)),
        "implicit_object_creation_expression" => {
            implicit_object_creation_target_type(object_creation)
        }
        _ => None,
    }
}

/// The expression a target-typed `new()` must take its type from when the tree
/// does not write that type: the left side of the assignment it initializes.
pub fn object_creation_assignment_target(initializer: Node<'_>) -> Option<Node<'_>> {
    let object_creation = initializer.parent()?;
    if object_creation.kind() != "implicit_object_creation_expression" {
        return None;
    }
    let assignment = object_creation.parent()?;
    if assignment.kind() != "assignment_expression" {
        return None;
    }
    if assignment.child_by_field_name("right") != Some(object_creation) {
        return None;
    }
    assignment.child_by_field_name("left")
}

/// The collection expression whose element target-types this initializer's
/// implicit `new()`.
///
/// This covers both forms from #2231: an implicit creation nested beneath a
/// collection expression assigned to a collection value, and an implicit
/// creation assigned directly through an element access. The returned node is
/// the collection value (`items` in both `items = [new()]` and
/// `items[index] = new()`), not the element access itself.
pub fn object_creation_collection_target(initializer: Node<'_>) -> Option<Node<'_>> {
    let object_creation = initializer.parent()?;
    if object_creation.kind() != "implicit_object_creation_expression" {
        return None;
    }

    if let Some(assignment) = object_creation.parent()
        && assignment.kind() == "assignment_expression"
        && assignment.child_by_field_name("right") == Some(object_creation)
    {
        let left = assignment.child_by_field_name("left")?;
        if left.kind() == "element_access_expression" {
            return left
                .child_by_field_name("expression")
                .or_else(|| left.named_child(0));
        }
    }

    let mut current = object_creation.parent()?;
    while matches!(current.kind(), "expression_element" | "collection_element") {
        current = current.parent()?;
    }
    if current.kind() != "collection_expression" {
        return None;
    }
    let assignment = current.parent()?;
    if assignment.kind() != "assignment_expression"
        || assignment.child_by_field_name("right") != Some(current)
    {
        return None;
    }
    assignment.child_by_field_name("left")
}

/// The written type a target-typed `new()` takes its type from.
///
/// C# gives `new()` the type of the expression's *target*, so this is a walk to
/// that target rather than a lookup on the creation itself. Every position
/// answered here is one where the target's type is written in the tree and can
/// be read off it: an initialized declarator, property or parameter, and a
/// `return` statement or expression body, whose target is the enclosing
/// function's declared return type.
///
/// Collection elements are the one nested target handled here. An array type
/// or a collection type with exactly one structured generic argument states a
/// unique element type in the tree. Multi-argument collections remain refused:
/// choosing a key or value argument would be a guess. Other targets whose type
/// the tree does not write are deliberately not answered: the left side of an
/// assignment, a call argument, or a switch arm. Each of those needs the
/// target's own declaration resolved through the index, which is the resolver's
/// work, not this syntax walk's.
///
/// The `= <value>` clause is transparent because the grammar does not always
/// build one: a `variable_declarator` can carry the value in its own `value`
/// field, which is why the declarator is matched here rather than through the
/// clause.
fn implicit_object_creation_target_type(object_creation: Node<'_>) -> Option<Node<'_>> {
    if let Some(mut parent) = object_creation.parent() {
        while matches!(parent.kind(), "expression_element" | "collection_element") {
            parent = parent.parent()?;
        }
        match parent.kind() {
            // `T[] values = [new() { ... }]`: the collection expression takes
            // its target from the outer declaration, while the implicit object
            // creation takes the element of that target.
            "collection_expression" => {
                let collection_type = expression_target_type(parent)?;
                return collection_element_type_node(collection_type);
            }
            // `new List<T> { new() { ... } }`: the containing object creation
            // writes the collection type directly. The initializer expression
            // is the structured bridge between both creations.
            "initializer_expression" => {
                let collection_creation = parent.parent()?;
                if !matches!(
                    collection_creation.kind(),
                    "object_creation_expression" | "implicit_object_creation_expression"
                ) {
                    return None;
                }
                let collection_type = match collection_creation.kind() {
                    "object_creation_expression" => collection_creation
                        .child_by_field_name("type")
                        .or_else(|| first_type_child(collection_creation)),
                    "implicit_object_creation_expression" => {
                        expression_target_type(collection_creation)
                    }
                    _ => None,
                }?;
                return collection_element_type_node(collection_type);
            }
            _ => {}
        }
    }

    expression_target_type(object_creation)
}

/// The target type written by the syntax surrounding `expression`.
fn expression_target_type(expression: Node<'_>) -> Option<Node<'_>> {
    let mut current = expression;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "equals_value_clause" | "parenthesized_expression" | "checked_expression" => {
                current = parent;
            }
            "variable_declarator" => {
                let initializer = variable_declarator_initializer(parent)?;
                if initializer.start_byte() > expression.start_byte()
                    || expression.end_byte() > initializer.end_byte()
                {
                    return None;
                }
                let declaration = parent.parent()?;
                return declaration
                    .child_by_field_name("type")
                    .or_else(|| first_type_child(declaration));
            }
            // A property initializer and a parameter default both state the
            // target type on the declaration itself.
            "property_declaration" | "indexer_declaration" | "parameter" => {
                return crate::declarations::csharp_declared_type_node(parent);
            }
            "arrow_expression_clause" | "return_statement" => {
                return enclosing_function_return_type(parent);
            }
            "ERROR" => {
                if let Some(type_node) = error_recovered_implicit_declarator_type(parent, current) {
                    return Some(type_node);
                }
                current = parent;
            }
            _ => return None,
        }
    }
    None
}

/// Project the unique element type written by a collection type syntax node.
///
/// This is deliberately AST-only. An array owns one element type, and a generic
/// name with exactly one type argument has one possible element projection. A
/// qualified type delegates to its terminal name. Multi-argument generic names
/// and non-generic collection spellings do not prove an element type.
pub fn collection_element_type_node(mut collection_type: Node<'_>) -> Option<Node<'_>> {
    loop {
        match collection_type.kind() {
            "type" | "nullable_type" => {
                collection_type = collection_type
                    .child_by_field_name("type")
                    .or_else(|| collection_type.named_child(0))?;
            }
            "array_type" => {
                return collection_type
                    .child_by_field_name("type")
                    .or_else(|| collection_type.named_child(0));
            }
            "qualified_name" | "alias_qualified_name" => {
                collection_type = collection_type.child_by_field_name("name").or_else(|| {
                    collection_type.named_child(collection_type.named_child_count().checked_sub(1)?)
                })?;
            }
            "generic_name" => {
                let arguments = collection_type
                    .child_by_field_name("type_arguments")
                    .or_else(|| first_named_child_of_kind(collection_type, "type_argument_list"))?;
                return (arguments.named_child_count() == 1)
                    .then(|| arguments.named_child(0))
                    .flatten();
            }
            _ => return None,
        }
    }
}

/// The element type written for a local, parameter, same-file field, or
/// same-file property used as `collection_target`.
///
/// The local walk follows only the lexical scope path containing the target and
/// uses the same nearest-scope binding engine as ordinary receiver inference.
/// A non-collection local shadows a same-named field and therefore returns no
/// type instead of falling through. Cross-file and inherited members require
/// index metadata and remain the caller's fallback.
pub fn collection_target_element_type_node<'tree>(
    collection_target: Node<'tree>,
    source: &str,
) -> Option<Node<'tree>> {
    if collection_target.kind() != "identifier" {
        return None;
    }
    let target_name = node_text(collection_target, source);
    let mut root = collection_target;
    while let Some(parent) = root.parent() {
        root = parent;
    }

    if let Some(local_elements) = local_collection_element_type_nodes(
        root,
        collection_target.start_byte(),
        target_name,
        source,
    ) {
        return (local_elements.len() == 1).then(|| local_elements[0]);
    }
    same_file_member_collection_element_type_node(collection_target, target_name, source)
}

/// `None` means no local declaration shadows `target_name`; `Some([])` means a
/// local exists but does not prove exactly one element type.
fn local_collection_element_type_nodes<'tree>(
    root: Node<'tree>,
    cutoff_start: usize,
    target_name: &str,
    source: &str,
) -> Option<Vec<Node<'tree>>> {
    let mut bindings = LocalInferenceEngine::new(Default::default());
    let mut stack = vec![(root, 0usize)];
    while let Some((node, next_child)) = stack.pop() {
        if next_child == 0 {
            if node.start_byte() >= cutoff_start {
                continue;
            }
            let enters_scope = SCOPE_NODES.contains(&node.kind());
            if enters_scope
                && !(node.start_byte() <= cutoff_start && cutoff_start < node.end_byte())
            {
                continue;
            }
            if enters_scope {
                bindings.enter_scope();
            }
            if node.kind() == "parameter" && node.end_byte() <= cutoff_start {
                seed_collection_element_binding(node, source, &mut bindings);
            } else if node.kind() == "variable_declaration"
                && !is_member_variable_declaration(node)
                && node.end_byte() <= cutoff_start
            {
                let Some(type_node) = node.child_by_field_name("type") else {
                    continue;
                };
                let mut cursor = node.walk();
                for declarator in node
                    .named_children(&mut cursor)
                    .filter(|child| child.kind() == "variable_declarator")
                {
                    let Some(name_node) = declarator.child_by_field_name("name") else {
                        continue;
                    };
                    seed_collection_element_name(name_node, type_node, source, &mut bindings);
                }
            }
        }
        let Some(child) = node.named_child(next_child) else {
            continue;
        };
        if child.start_byte() >= cutoff_start {
            continue;
        }
        stack.push((node, next_child + 1));
        stack.push((child, 0));
    }

    match bindings.resolve_symbol(target_name) {
        SymbolResolution::Precise(nodes) => Some(nodes.into_iter().collect()),
        SymbolResolution::Ambiguous => Some(Vec::new()),
        SymbolResolution::Unknown if bindings.is_shadowed(target_name) => Some(Vec::new()),
        SymbolResolution::Unknown => None,
    }
}

fn seed_collection_element_binding<'tree>(
    declaration: Node<'tree>,
    source: &str,
    bindings: &mut LocalInferenceEngine<Node<'tree>>,
) {
    let Some(name_node) = declaration.child_by_field_name("name") else {
        return;
    };
    let Some(type_node) = declaration.child_by_field_name("type") else {
        return;
    };
    seed_collection_element_name(name_node, type_node, source, bindings);
}

fn seed_collection_element_name<'tree>(
    name_node: Node<'tree>,
    type_node: Node<'tree>,
    source: &str,
    bindings: &mut LocalInferenceEngine<Node<'tree>>,
) {
    let name = node_text(name_node, source);
    if let Some(element) = collection_element_type_node(type_node) {
        bindings.seed_symbol(name, element);
    } else {
        bindings.declare_shadow(name);
    }
}

fn same_file_member_collection_element_type_node<'tree>(
    target: Node<'tree>,
    target_name: &str,
    source: &str,
) -> Option<Node<'tree>> {
    let mut owner = target;
    loop {
        owner = owner.parent()?;
        if matches!(
            owner.kind(),
            "class_declaration" | "struct_declaration" | "record_declaration"
        ) {
            break;
        }
    }
    let body = owner
        .child_by_field_name("body")
        .or_else(|| owner.named_child(owner.named_child_count().checked_sub(1)?))?;
    let mut cursor = body.walk();
    for declaration in body.named_children(&mut cursor) {
        match declaration.kind() {
            "field_declaration" | "event_field_declaration" => {
                let variable = declaration.child_by_field_name("declaration").or_else(|| {
                    let mut declaration_cursor = declaration.walk();
                    declaration
                        .named_children(&mut declaration_cursor)
                        .find(|child| child.kind() == "variable_declaration")
                })?;
                let type_node = variable.child_by_field_name("type")?;
                let mut variable_cursor = variable.walk();
                if variable
                    .named_children(&mut variable_cursor)
                    .filter(|child| child.kind() == "variable_declarator")
                    .filter_map(|declarator| declarator.child_by_field_name("name"))
                    .any(|name| node_text(name, source) == target_name)
                {
                    return collection_element_type_node(type_node);
                }
            }
            "property_declaration" => {
                let name_node = declaration.child_by_field_name("name")?;
                if node_text(name_node, source) == target_name {
                    return declaration
                        .child_by_field_name("type")
                        .and_then(collection_element_type_node);
                }
            }
            _ => {}
        }
    }
    None
}

/// The declared return type of the function whose body produces `node`.
///
/// The walk refuses rather than guesses wherever the enclosing declaration does
/// not state the type of this value: a lambda or anonymous method has its own
/// return type, a constructor and a destructor declare none, and a `set`,
/// `init`, `add` or `remove` accessor produces no value at all.
fn enclosing_function_return_type(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "lambda_expression"
            | "anonymous_method_expression"
            | "constructor_declaration"
            | "destructor_declaration" => return None,
            "accessor_declaration" => {
                let name = parent.child_by_field_name("name")?;
                if name.kind() != "get" {
                    return None;
                }
                current = parent;
            }
            "method_declaration"
            | "local_function_statement"
            | "operator_declaration"
            | "conversion_operator_declaration"
            | "property_declaration"
            | "indexer_declaration" => {
                return crate::declarations::csharp_declared_type_node(parent);
            }
            _ => current = parent,
        }
    }
    None
}

fn error_recovered_implicit_declarator_type<'tree>(
    error: Node<'tree>,
    value: Node<'tree>,
) -> Option<Node<'tree>> {
    let mut cursor = error.walk();
    let children = error.named_children(&mut cursor).collect::<Vec<_>>();
    let value_index = children.iter().position(|child| same_node(*child, value))?;
    let name = value_index
        .checked_sub(1)
        .and_then(|index| children.get(index))?;
    if !matches!(name.kind(), "identifier" | "implicit_parameter") {
        return None;
    }
    let type_node = value_index
        .checked_sub(2)
        .and_then(|index| children.get(index))?;
    is_type_syntax_kind(type_node.kind()).then_some(*type_node)
}

fn count_named_children_of_kind(node: Node<'_>, kind: &str) -> usize {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| child.kind() == kind)
        .count()
}

pub fn first_type_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| is_type_syntax_kind(child.kind()))
}

fn is_type_syntax_kind(kind: &str) -> bool {
    matches!(
        kind,
        "identifier" | "qualified_name" | "generic_name" | "nullable_type" | "array_type" | "type"
    )
}

fn first_named_child_of_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == kind)
}
