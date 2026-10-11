//! Go-native failure branches for the empty failure-handler policy.
//!
//! Go does not have catch clauses.  The failure representation covered here
//! is the explicit `error`/`nil` guard, plus the two source-level forms that
//! deliberately discard a predeclared `recover` result.  The walk is
//! iterative and stops at function literals because each literal is a
//! separate callable seed.

use super::GoAnalyzer;
use crate::analyzer::go::type_identity_proof::go_predeclared_type_name_is_exact;
use crate::analyzer::structural::failure_handlers::{
    HandlerBodyGap, HandlerBodyShape, HandlerBodyState, NativeFailureBranch,
};
use crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree;
use crate::analyzer::usages::get_definition::{
    DefinitionLookupStatus, parse_go_tree, resolve_go_bounded,
};
use crate::analyzer::usages::reference_site::ResolvedReferenceSite;
use crate::analyzer::{IAnalyzer, ProjectFile, Range, WorkspaceAnalyzer, resolve_analyzer};
use brokk_bifrost_core::analyzer::model::StructuredTypeNodeView;
use brokk_bifrost_core::analyzer::query_token::QueryScope;
use brokk_bifrost_core::analyzer::tree_walk::node_range;
use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;
use brokk_bifrost_core::path_utils::rel_path_string;
use brokk_bifrost_go::declarations::go_structured_type_identity;
use brokk_bifrost_go::graph::reference::go_name_shadowed_at_with_scope;
use tree_sitter::Node;

const LOOKUP_LIMIT: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindingProof {
    Error,
    Other,
    Shadowed,
    Open,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BuiltinProof {
    Exact,
    Shadowed,
    Open,
    NotCandidate,
}

#[derive(Clone, Copy)]
struct BindingCandidate {
    proof: BindingProof,
    scope_depth: usize,
    start_byte: usize,
}

/// Find Go's native failure branches inside one callable.
pub fn go_failure_handler_body_shapes(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    syntax: &PreparedSyntaxTree,
    callable: Range,
) -> Vec<NativeFailureBranch> {
    let Some(go) = resolve_analyzer::<GoAnalyzer>(workspace.analyzer()) else {
        return Vec::new();
    };
    let Some(callable_node) = syntax
        .tree()
        .root_node()
        .named_descendant_for_byte_range(callable.start_byte, callable.end_byte)
        .filter(|node| {
            node.start_byte() == callable.start_byte && node.end_byte() == callable.end_byte
        })
    else {
        return Vec::new();
    };
    let Some(body) = callable_node.child_by_field_name("body") else {
        return Vec::new();
    };

    let analyzer = workspace.analyzer();
    let mut stack = vec![body];
    let mut branches = Vec::new();
    while let Some(node) = stack.pop() {
        if node.id() != body.id() && node.kind() == "func_literal" {
            continue;
        }
        let branch = match node.kind() {
            "if_statement" => classify_if(analyzer, go, file, syntax, node, callable_node),
            "defer_statement" => classify_defer(analyzer, go, file, syntax, node),
            _ => None,
        };
        if let Some(branch) = branch {
            branches.push(branch);
        }

        let mut cursor = node.walk();
        let mut children = node.named_children(&mut cursor).collect::<Vec<_>>();
        children.reverse();
        stack.extend(children);
    }
    branches.sort_by_key(|branch: &NativeFailureBranch| branch.handler.start_byte);
    branches
}

fn classify_if(
    analyzer: &dyn IAnalyzer,
    go: &GoAnalyzer,
    file: &ProjectFile,
    syntax: &PreparedSyntaxTree,
    if_node: Node<'_>,
    callable: Node<'_>,
) -> Option<NativeFailureBranch> {
    let condition = if_node.child_by_field_name("condition")?;
    let comparison = condition
        .child_by_field_name("operator")
        .filter(|operator| matches!(operator.kind(), "==" | "!="))
        .and_then(|_| (condition.kind() == "binary_expression").then_some(condition))?;
    let left = bare_expression(comparison.child_by_field_name("left")?);
    let right = bare_expression(comparison.child_by_field_name("right")?);
    let (name_node, operator, body) = if is_nil_node(right) && is_identifier(left) {
        let body = match comparison.child_by_field_name("operator")?.kind() {
            "!=" => if_node.child_by_field_name("consequence"),
            "==" => alternative_body(if_node),
            _ => None,
        };
        (
            left,
            comparison.child_by_field_name("operator")?.kind(),
            body,
        )
    } else if is_nil_node(left) && is_identifier(right) {
        let body = match comparison.child_by_field_name("operator")?.kind() {
            "!=" => if_node.child_by_field_name("consequence"),
            "==" => alternative_body(if_node),
            _ => None,
        };
        (
            right,
            comparison.child_by_field_name("operator")?.kind(),
            body,
        )
    } else {
        return None;
    };
    let name = syntax.source().get(name_node.byte_range())?;

    // `if r := recover(); r != nil` is the second supported panic-swallowing
    // shape. It is checked before ordinary error binding so that recover is
    // proved as a builtin rather than treated as an unresolved variable.
    if operator == "!="
        && let Some(initializer) = if_node.child_by_field_name("initializer")
        && let Some((call, _ordinal)) = call_binding_for_name(initializer, name, syntax.source())
        && call_is_recover(call, syntax.source())
    {
        return match predeclared_builtin_status(
            analyzer,
            go,
            file,
            syntax,
            call.child_by_field_name("function")?,
            "recover",
        ) {
            BuiltinProof::Exact => Some(NativeFailureBranch {
                handler: node_range(if_node),
                shape: branch_shape(if_node, body),
            }),
            BuiltinProof::Open => Some(NativeFailureBranch {
                handler: node_range(if_node),
                shape: open_shape(body, HandlerBodyGap::SyntaxRecovery),
            }),
            BuiltinProof::Shadowed | BuiltinProof::NotCandidate => None,
        };
    }

    if operator == "==" && if_node.child_by_field_name("alternative").is_none() {
        return None;
    }
    let proof = binding_proof(analyzer, go, file, syntax, name_node, name, callable);
    let shape = match proof {
        BindingProof::Error => branch_shape(if_node, body),
        BindingProof::Open => open_shape(body, HandlerBodyGap::SyntaxRecovery),
        BindingProof::Other | BindingProof::Shadowed => return None,
    };
    Some(NativeFailureBranch {
        handler: node_range(if_node),
        shape,
    })
}

fn classify_defer(
    analyzer: &dyn IAnalyzer,
    go: &GoAnalyzer,
    file: &ProjectFile,
    syntax: &PreparedSyntaxTree,
    defer_node: Node<'_>,
) -> Option<NativeFailureBranch> {
    let call = defer_node
        .named_child(0)
        .filter(|child| child.kind() == "call_expression")?;
    let function = bare_expression(call.child_by_field_name("function")?);
    if function.kind() != "func_literal" {
        return None;
    }
    let body = function.child_by_field_name("body")?;
    if has_syntax_recovery(defer_node) || has_syntax_recovery(body) {
        return Some(NativeFailureBranch {
            handler: node_range(defer_node),
            shape: open_shape(Some(body), HandlerBodyGap::SyntaxRecovery),
        });
    }

    let mut saw_recover = false;
    let mut unknown_recover = false;
    let mut non_recover_statement = false;
    for statement in body_statements(body) {
        if is_noop_body_child(statement) {
            continue;
        }
        match direct_recover_discard(statement, syntax.source()) {
            Some(call) => match predeclared_builtin_status(
                analyzer,
                go,
                file,
                syntax,
                call.child_by_field_name("function")?,
                "recover",
            ) {
                BuiltinProof::Exact => saw_recover = true,
                BuiltinProof::Open => unknown_recover = true,
                BuiltinProof::Shadowed | BuiltinProof::NotCandidate => non_recover_statement = true,
            },
            None => non_recover_statement = true,
        }
    }
    if !saw_recover {
        if !unknown_recover {
            return None;
        }
        return Some(NativeFailureBranch {
            handler: node_range(defer_node),
            shape: open_shape(Some(body), HandlerBodyGap::SyntaxRecovery),
        });
    }
    if unknown_recover {
        return Some(NativeFailureBranch {
            handler: node_range(defer_node),
            shape: open_shape(Some(body), HandlerBodyGap::SyntaxRecovery),
        });
    }
    Some(NativeFailureBranch {
        handler: node_range(defer_node),
        shape: HandlerBodyShape {
            // A direct recover discard is the handled failure operation, not
            // additional work in the deferred handler. Any other statement
            // keeps the handler nonempty.
            state: if non_recover_statement {
                HandlerBodyState::Nonempty
            } else {
                HandlerBodyState::Empty
            },
            body: Some(node_range(body)),
            try_body: None,
        },
    })
}

fn branch_shape(if_node: Node<'_>, body: Option<Node<'_>>) -> HandlerBodyShape {
    if has_syntax_recovery(if_node) {
        open_shape(body, HandlerBodyGap::SyntaxRecovery)
    } else {
        classify_body(body)
    }
}

fn classify_body(body: Option<Node<'_>>) -> HandlerBodyShape {
    let Some(body) = body else {
        return open_shape(None, HandlerBodyGap::MissingBody);
    };
    let range = node_range(body);
    if has_syntax_recovery(body) || body.kind() != "block" {
        return open_shape(Some(body), HandlerBodyGap::SyntaxRecovery);
    }
    let empty = body_statements(body).into_iter().all(is_noop_body_child);
    HandlerBodyShape {
        state: if empty {
            HandlerBodyState::Empty
        } else {
            HandlerBodyState::Nonempty
        },
        body: Some(range),
        try_body: None,
    }
}

fn open_shape(body: Option<Node<'_>>, gap: HandlerBodyGap) -> HandlerBodyShape {
    HandlerBodyShape {
        state: HandlerBodyState::Open(gap),
        body: body.map(node_range),
        try_body: None,
    }
}

fn body_statements(body: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = body.walk();
    let children = body.named_children(&mut cursor).collect::<Vec<_>>();
    let mut statements = Vec::new();
    for child in children {
        if child.kind() == "statement_list" {
            let mut cursor = child.walk();
            statements.extend(child.named_children(&mut cursor));
        } else {
            statements.push(child);
        }
    }
    statements
}

fn binding_proof(
    analyzer: &dyn IAnalyzer,
    go: &GoAnalyzer,
    file: &ProjectFile,
    syntax: &PreparedSyntaxTree,
    use_node: Node<'_>,
    name: &str,
    callable: Node<'_>,
) -> BindingProof {
    let root = syntax.tree().root_node();
    let source = syntax.source();
    let mut explicit = None;
    let mut short_call = None;
    let mut assignment_call = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "parameter_declaration" | "var_spec")
            && let Some(type_node) = node.child_by_field_name("type")
            && node_has_name(node, name, source)
            && let Some((scope, depth)) = binding_scope(node)
            && scope_contains(scope, use_node)
            && declaration_visible(node, scope, use_node)
        {
            let candidate = BindingCandidate {
                proof: explicit_type_proof(analyzer, go, file, syntax, type_node),
                scope_depth: depth,
                start_byte: node.start_byte(),
            };
            if is_better(candidate, explicit) {
                explicit = Some(candidate);
            }
        }
        if matches!(
            node.kind(),
            "short_var_declaration" | "assignment_statement" | "var_spec"
        ) && let Some((call, ordinal)) = call_binding_for_name(node, name, source)
            && node.end_byte() <= use_node.start_byte()
            && let Some((scope, depth)) = binding_scope(node)
            && scope_contains(scope, use_node)
            && let proof = call_result_proof(analyzer, go, file, syntax, call, ordinal)
        {
            let candidate = BindingCandidate {
                proof,
                scope_depth: depth,
                start_byte: node.start_byte(),
            };
            if node.kind() == "assignment_statement" {
                if is_better(candidate, assignment_call) {
                    assignment_call = Some(candidate);
                }
            } else if is_better(candidate, short_call) {
                short_call = Some(candidate);
            }
        } else if node.kind() == "short_var_declaration"
            && node.end_byte() <= use_node.start_byte()
            && let Some((scope, depth)) = binding_scope(node)
            && scope_contains(scope, use_node)
            && inferred_non_error_binding(node, name, source)
        {
            let candidate = BindingCandidate {
                proof: BindingProof::Other,
                scope_depth: depth,
                start_byte: node.start_byte(),
            };
            if is_better(candidate, short_call) {
                short_call = Some(candidate);
            }
        }

        if node.kind() != "func_literal" || node.id() == callable.id() {
            let mut cursor = node.walk();
            let mut children = node.named_children(&mut cursor).collect::<Vec<_>>();
            children.reverse();
            stack.extend(children);
        }
    }

    if let Some(short) = short_call
        && explicit.is_none_or(|typed| {
            short.scope_depth > typed.scope_depth
                || (short.scope_depth == typed.scope_depth && short.start_byte >= typed.start_byte)
        })
    {
        return short.proof;
    }
    if let Some(typed) = explicit
        && (!matches!(typed.proof, BindingProof::Open)
            || assignment_call.is_none_or(|assignment| assignment.start_byte <= typed.start_byte))
    {
        return typed.proof;
    }
    assignment_call
        .map(|candidate| candidate.proof)
        .unwrap_or(BindingProof::Open)
}

fn explicit_type_proof(
    analyzer: &dyn IAnalyzer,
    _go: &GoAnalyzer,
    file: &ProjectFile,
    syntax: &PreparedSyntaxTree,
    type_node: Node<'_>,
) -> BindingProof {
    let Some(identity) = go_structured_type_identity(type_node, syntax.source()) else {
        return BindingProof::Open;
    };
    let simple_named = matches!(
        identity.view(identity.root_id()),
        Some(StructuredTypeNodeView::Named(_))
    );
    let Some(name) = identity.nominal_name() else {
        return BindingProof::Other;
    };
    if !simple_named
        || name.is_absolute()
        || !name.lexical_scope().is_empty()
        || name.path() != ["error"]
    {
        return BindingProof::Other;
    }
    match go_predeclared_type_name_is_exact(
        analyzer,
        file,
        syntax.source(),
        syntax.tree().root_node(),
        type_node,
        "error",
    ) {
        Some(true) => BindingProof::Error,
        Some(false) => BindingProof::Shadowed,
        None => BindingProof::Open,
    }
}

fn call_result_proof(
    analyzer: &dyn IAnalyzer,
    go: &GoAnalyzer,
    file: &ProjectFile,
    syntax: &PreparedSyntaxTree,
    call: Node<'_>,
    ordinal: usize,
) -> BindingProof {
    let Some(function) = call.child_by_field_name("function") else {
        return BindingProof::Open;
    };
    let Some(site) = call_site(file, syntax.source(), function) else {
        return BindingProof::Open;
    };
    let result = resolve_go_bounded(
        analyzer,
        file,
        syntax.source(),
        Some(syntax.tree()),
        &site,
        ReceiverAnalysisBudget::default(),
        None,
    );
    let BoundedResolution::Complete { value, .. } = result else {
        return BindingProof::Open;
    };
    if value.status != DefinitionLookupStatus::Resolved
        || !value.modeled_definitions.is_empty()
        || value.definitions.len() != 1
    {
        return BindingProof::Open;
    }
    let declaration = &value.definitions[0];
    let metadata = go.signature_metadata_limited(declaration, 64);
    if !metadata.complete || metadata.rows.len() != 1 {
        return BindingProof::Open;
    }
    let Some(identity) = metadata.rows[0].result_type_identity(ordinal) else {
        return BindingProof::Other;
    };
    let Some(name) = identity.nominal_name() else {
        return BindingProof::Other;
    };
    if !matches!(
        identity.view(identity.root_id()),
        Some(StructuredTypeNodeView::Named(_))
    ) || name.is_absolute()
        || !name.lexical_scope().is_empty()
        || name.path() != ["error"]
    {
        return BindingProof::Other;
    }

    let Some(source) = analyzer.indexed_source(declaration.source()) else {
        return BindingProof::Open;
    };
    let Some(tree) = parse_go_tree(&source) else {
        return BindingProof::Open;
    };
    let ranges = go.ranges_limited(declaration, 8);
    if !ranges.complete {
        return BindingProof::Open;
    }
    let Some(callable) = ranges.rows.into_iter().find_map(|range| {
        tree.root_node()
            .named_descendant_for_byte_range(range.start_byte, range.end_byte)
            .filter(|node| {
                node.start_byte() == range.start_byte
                    && node.end_byte() == range.end_byte
                    && matches!(node.kind(), "function_declaration" | "method_declaration")
            })
    }) else {
        return BindingProof::Open;
    };
    let Some(type_node) = result_type_node(callable, ordinal) else {
        return BindingProof::Open;
    };
    match go_predeclared_type_name_is_exact(
        analyzer,
        declaration.source(),
        &source,
        tree.root_node(),
        type_node,
        "error",
    ) {
        Some(true) => BindingProof::Error,
        Some(false) => BindingProof::Shadowed,
        None => BindingProof::Open,
    }
}

fn result_type_node(callable: Node<'_>, ordinal: usize) -> Option<Node<'_>> {
    let result = callable.child_by_field_name("result")?;
    if result.kind() != "parameter_list" {
        return (ordinal == 0).then_some(result);
    }
    let mut cursor = result.walk();
    let mut remaining = ordinal;
    for declaration in result.named_children(&mut cursor) {
        if !matches!(
            declaration.kind(),
            "parameter_declaration" | "variadic_parameter_declaration"
        ) {
            continue;
        }
        let mut names = declaration.walk();
        let count = declaration
            .children_by_field_name("name", &mut names)
            .count()
            .max(1);
        if remaining < count {
            return declaration.child_by_field_name("type");
        }
        remaining -= count;
    }
    None
}

fn call_site(
    file: &ProjectFile,
    source: &str,
    function: Node<'_>,
) -> Option<ResolvedReferenceSite> {
    let function = bare_expression(function);
    let focus = if function.kind() == "selector_expression" {
        function.child_by_field_name("field")?
    } else {
        function
    };
    let text = source.get(focus.byte_range())?.to_owned();
    let range = node_range(function);
    Some(ResolvedReferenceSite {
        path: rel_path_string(file),
        text,
        range,
        focus_start_byte: focus.start_byte(),
        focus_end_byte: focus.end_byte(),
    })
}

fn call_binding_for_name<'tree>(
    statement: Node<'tree>,
    name: &str,
    source: &str,
) -> Option<(Node<'tree>, usize)> {
    let left = statement.child_by_field_name("left")?;
    let right = statement.child_by_field_name("right")?;
    let mut left_cursor = left.walk();
    let lefts = if left.kind() == "expression_list" {
        left.named_children(&mut left_cursor).collect::<Vec<_>>()
    } else {
        vec![left]
    };
    let ordinal = lefts
        .into_iter()
        .enumerate()
        .find_map(|(ordinal, target)| {
            let target = bare_expression(target);
            (is_identifier(target) && source.get(target.byte_range()) == Some(name))
                .then_some(ordinal)
        })?;
    let mut right_cursor = right.walk();
    let rights = if right.kind() == "expression_list" {
        right.named_children(&mut right_cursor).collect::<Vec<_>>()
    } else {
        vec![right]
    };
    let call = if rights.len() == 1 && rights[0].kind() == "call_expression" {
        bare_expression(rights[0])
    } else {
        bare_expression(*rights.get(ordinal)?)
    };
    (call.kind() == "call_expression").then_some((call, ordinal))
}

fn inferred_non_error_binding(statement: Node<'_>, name: &str, source: &str) -> bool {
    let Some(left) = statement.child_by_field_name("left") else {
        return false;
    };
    let Some(right) = statement.child_by_field_name("right") else {
        return false;
    };
    let mut left_cursor = left.walk();
    let lefts = if left.kind() == "expression_list" {
        left.named_children(&mut left_cursor).collect::<Vec<_>>()
    } else {
        vec![left]
    };
    let Some(ordinal) = lefts.into_iter().position(|target| {
        let target = bare_expression(target);
        is_identifier(target) && source.get(target.byte_range()) == Some(name)
    }) else {
        return false;
    };
    let mut right_cursor = right.walk();
    let rights = if right.kind() == "expression_list" {
        right.named_children(&mut right_cursor).collect::<Vec<_>>()
    } else {
        vec![right]
    };
    let Some(value) = rights.get(ordinal).copied().map(bare_expression) else {
        return false;
    };
    matches!(
        value.kind(),
        "int_literal"
            | "float_literal"
            | "imaginary_literal"
            | "rune_literal"
            | "interpreted_string_literal"
            | "raw_string_literal"
            | "true"
            | "false"
            | "composite_literal"
            | "func_literal"
    )
}

fn binding_scope(node: Node<'_>) -> Option<(Node<'_>, usize)> {
    if matches!(
        node.kind(),
        "parameter_declaration" | "variadic_parameter_declaration"
    ) {
        let mut ancestor = node.parent();
        while let Some(current) = ancestor {
            if matches!(
                current.kind(),
                "func_literal" | "function_declaration" | "method_declaration"
            ) {
                return Some((current, syntax_depth(current)));
            }
            ancestor = current.parent();
        }
        return None;
    }
    let mut child = node;
    let mut ancestor = node.parent();
    while let Some(current) = ancestor {
        let header_binding = match current.kind() {
            "for_statement" => current.child_by_field_name("body").is_none_or(|body| {
                !(body.start_byte() <= child.start_byte() && child.end_byte() <= body.end_byte())
            }),
            "if_statement" | "expression_switch_statement" | "type_switch_statement" => current
                .child_by_field_name("initializer")
                .is_some_and(|initializer| {
                    initializer.start_byte() <= node.start_byte()
                        && node.end_byte() <= initializer.end_byte()
                }),
            _ => false,
        };
        if header_binding || current.kind() == "block" {
            return Some((current, syntax_depth(current)));
        }
        if current.kind() == "source_file" {
            return Some((current, syntax_depth(current)));
        }
        if current.kind() == "statement_list"
            && current.parent().is_some_and(|parent| {
                matches!(
                    parent.kind(),
                    "expression_case" | "type_case" | "communication_case" | "default_case"
                )
            })
        {
            return Some((current, syntax_depth(current)));
        }
        child = current;
        ancestor = current.parent();
    }
    None
}

fn declaration_visible(node: Node<'_>, scope: Node<'_>, use_node: Node<'_>) -> bool {
    if scope.kind() == "source_file" {
        true
    } else {
        node.end_byte() <= use_node.start_byte()
    }
}

fn scope_contains(scope: Node<'_>, node: Node<'_>) -> bool {
    scope.start_byte() <= node.start_byte() && node.end_byte() <= scope.end_byte()
}

fn syntax_depth(node: Node<'_>) -> usize {
    let mut depth = 0;
    let mut current = node.parent();
    while let Some(parent) = current {
        depth += 1;
        current = parent.parent();
    }
    depth
}

fn is_better(candidate: BindingCandidate, current: Option<BindingCandidate>) -> bool {
    current.is_none_or(|current| {
        (candidate.scope_depth, candidate.start_byte) > (current.scope_depth, current.start_byte)
    })
}

fn node_has_name(node: Node<'_>, name: &str, source: &str) -> bool {
    let mut cursor = node.walk();
    node.children_by_field_name("name", &mut cursor)
        .any(|candidate| source.get(candidate.byte_range()) == Some(name))
}

fn predeclared_builtin_status(
    analyzer: &dyn IAnalyzer,
    go: &GoAnalyzer,
    file: &ProjectFile,
    syntax: &PreparedSyntaxTree,
    identifier: Node<'_>,
    expected: &str,
) -> BuiltinProof {
    if !is_identifier(identifier) || syntax.source().get(identifier.byte_range()) != Some(expected)
    {
        return BuiltinProof::NotCandidate;
    }
    match go_name_shadowed_at_with_scope(
        syntax.tree().root_node(),
        syntax.source(),
        identifier.start_byte(),
        expected,
        || true,
    ) {
        Some(true) => return BuiltinProof::Shadowed,
        Some(false) => {}
        None => return BuiltinProof::Open,
    }
    let scope = crate::analyzer::AnalyzerQueryScope::new(analyzer);
    let (imports, dot_imports) = go.definition_import_namespaces(scope.token(), file);
    if !dot_imports.is_empty() || imports.contains_key(expected) {
        return BuiltinProof::Shadowed;
    }
    match go.predeclared_builtin_shadow_status_limited(
        &rel_path_string(file),
        expected,
        LOOKUP_LIMIT,
        || true,
    ) {
        Some(true) => BuiltinProof::Shadowed,
        Some(false) => BuiltinProof::Exact,
        None => BuiltinProof::Open,
    }
}

fn call_is_recover(call: Node<'_>, source: &str) -> bool {
    call.child_by_field_name("function")
        .map(bare_expression)
        .is_some_and(|function| {
            is_identifier(function) && source.get(function.byte_range()) == Some("recover")
        })
        && call
            .child_by_field_name("arguments")
            .is_none_or(|arguments| {
                let mut cursor = arguments.walk();
                arguments.named_children(&mut cursor).next().is_none()
            })
}

fn direct_recover_discard<'tree>(statement: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    if statement.kind() == "expression_statement" {
        let call = statement.named_child(0)?;
        return (call.kind() == "call_expression" && call_is_recover(call, source)).then_some(call);
    }
    if matches!(
        statement.kind(),
        "assignment_statement" | "short_var_declaration"
    ) {
        let left = statement.child_by_field_name("left")?;
        let right = statement.child_by_field_name("right")?;
        let left = expression_at_ordinal(left, 0)?;
        let right = expression_at_ordinal(right, 0)?;
        if left.kind() == "identifier"
            && right.kind() == "call_expression"
            && left.utf8_text(source.as_bytes()).ok() == Some("_")
            && call_is_recover(right, source)
        {
            return Some(right);
        }
    }
    None
}

fn expression_at_ordinal(node: Node<'_>, ordinal: usize) -> Option<Node<'_>> {
    if node.kind() != "expression_list" {
        return (ordinal == 0).then_some(node);
    }
    node.named_child(ordinal)
}

fn alternative_body(if_node: Node<'_>) -> Option<Node<'_>> {
    let alternative = if_node.child_by_field_name("alternative")?;
    if alternative.kind() == "else_clause" {
        alternative
            .child_by_field_name("body")
            .or_else(|| alternative.named_child(0))
    } else {
        Some(alternative)
    }
}

fn bare_expression(mut node: Node<'_>) -> Node<'_> {
    while node.kind() == "parenthesized_expression" {
        let Some(inner) = node.named_child(0) else {
            break;
        };
        node = inner;
    }
    node
}

fn is_identifier(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "identifier" | "field_identifier" | "type_identifier" | "package_identifier"
    )
}

fn is_nil_node(node: Node<'_>) -> bool {
    node.kind() == "nil"
}

fn is_noop_body_child(node: Node<'_>) -> bool {
    matches!(node.kind(), "comment" | "empty_statement") || node.is_extra()
}

fn has_syntax_recovery(node: Node<'_>) -> bool {
    if node.has_error() || node.is_missing() {
        return true;
    }
    let mut ancestor = node.parent();
    while let Some(parent) = ancestor {
        if parent.is_error() {
            return true;
        }
        ancestor = parent.parent();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::Language;
    use crate::analyzer::LanguageDialect;
    use crate::test_support::AnalyzerFixture;
    use brokk_bifrost_core::analyzer::prepared_syntax::{
        PreparedSourceOrigin, PreparedSyntaxSource,
    };
    use std::sync::Arc;

    fn prepared(source: &str) -> PreparedSyntaxTree {
        PreparedSyntaxTree::new(
            PreparedSyntaxSource::Exact(Arc::from(source)),
            brokk_bifrost_go::parse::parse_go(source).expect("Go source parses"),
            crate::text_utils::compute_line_starts(source),
            LanguageDialect::Standard(Language::Go),
            PreparedSourceOrigin::Disk,
            None,
        )
    }

    fn branches(source: &str) -> Vec<NativeFailureBranch> {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Go,
            &[("go.mod", "module example.com/app\n"), ("main.go", source)],
        );
        let file = ProjectFile::new(fixture.project_root(), "main.go");
        let syntax = prepared(source);
        let mut stack = vec![syntax.tree().root_node()];
        let callable = loop {
            let node = stack.pop().expect("callable fixture");
            if node.kind() == "function_declaration"
                && node
                    .child_by_field_name("name")
                    .and_then(|name| name.utf8_text(source.as_bytes()).ok())
                    == Some("work")
            {
                break node_range(node);
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        };
        go_failure_handler_body_shapes(fixture.analyzer(), &file, &syntax, callable)
    }

    fn states(source: &str) -> Vec<HandlerBodyState> {
        branches(source)
            .into_iter()
            .map(|branch| branch.shape.state)
            .collect()
    }

    #[test]
    fn recognizes_error_guards_and_empty_else() {
        let source = r#"package p
func work(err error) {
	var declared error
	if declared != nil {}
	if err != nil {}
	if nil != err {}
	if err == nil { work(err) } else {}
}
"#;
        assert_eq!(
            states(source),
            vec![
                HandlerBodyState::Empty,
                HandlerBodyState::Empty,
                HandlerBodyState::Empty,
                HandlerBodyState::Empty,
            ]
        );
    }

    #[test]
    fn recognizes_call_inferred_error_and_recover_forms() {
        let source = r#"package p
func fail() error { return nil }
func pair() (int, error) { return 0, nil }
func work(assigned error) {
	assigned = fail()
	if assigned != nil {}
	if err := fail(); err != nil {}
	if _, err := pair(); err != nil {}
	if r := recover(); r != nil {}
	defer func() { recover() }()
	defer func() { _ = recover() }()
}
"#;
        assert_eq!(
            states(source),
            vec![
                HandlerBodyState::Empty,
                HandlerBodyState::Empty,
                HandlerBodyState::Empty,
                HandlerBodyState::Empty,
                HandlerBodyState::Empty,
                HandlerBodyState::Empty,
            ]
        );
    }

    #[test]
    fn keeps_working_bodies_nonempty_and_rejects_near_misses() {
        let source = r#"package p
func fail() error { return nil }
func work(err error) {
	if err != nil { _ = err }
	if err := 0; err != nil {}
	if err := fail(); err != nil { return }
	defer func() { recover(); println("work") }()
}
"#;
        assert_eq!(
            states(source),
            vec![
                HandlerBodyState::Nonempty,
                HandlerBodyState::Nonempty,
                HandlerBodyState::Nonempty,
            ]
        );

        let shadowed = r#"package p
type error struct{}
func work(err error) { if err != nil {} }
"#;
        assert!(states(shadowed).is_empty());

        let concrete = r#"package p
type ConcreteError struct{}
func work(err ConcreteError) { if err != nil {} }
"#;
        assert!(states(concrete).is_empty());

        let unresolved = r#"package p
func work() { if err := missing(); err != nil {} }
"#;
        assert_eq!(
            states(unresolved),
            vec![HandlerBodyState::Open(HandlerBodyGap::SyntaxRecovery)]
        );

        let shadowed_recover = r#"package p
func recover() any { return nil }
func work() {
	if r := recover(); r != nil {}
	defer func() { recover() }()
}
"#;
        assert!(states(shadowed_recover).is_empty());

        let selector_guards = r#"package p
import "errors"
func work(err error, target any) {
	if errors.Is(err, target) {}
	if errors.As(err, &target) {}
}
"#;
        assert!(states(selector_guards).is_empty());

        let recovered = "package p\nfunc work(err error) { if err != nil { + } }\n";
        assert!(matches!(
            states(recovered).as_slice(),
            [HandlerBodyState::Open(_)]
        ));
    }

    #[test]
    fn nested_function_literals_are_separate_callable_seeds() {
        let source = r#"package p
func work(err error) {
	if err != nil {}
	_ = func(inner error) { if inner != nil {} }
}
"#;
        assert_eq!(states(source), vec![HandlerBodyState::Empty]);

        let fixture = AnalyzerFixture::new_for_language(
            Language::Go,
            &[("go.mod", "module example.com/app\n"), ("main.go", source)],
        );
        let file = ProjectFile::new(fixture.project_root(), "main.go");
        let syntax = prepared(source);
        let mut stack = vec![syntax.tree().root_node()];
        let literal = loop {
            let node = stack.pop().expect("function literal fixture");
            if node.kind() == "func_literal" {
                break node;
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        };
        assert_eq!(
            go_failure_handler_body_shapes(
                fixture.analyzer(),
                &file,
                &syntax,
                node_range(literal),
            )
            .into_iter()
            .map(|branch| branch.shape.state)
            .collect::<Vec<_>>(),
            vec![HandlerBodyState::Empty]
        );
    }
}
