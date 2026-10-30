//! Go-native failure branches for the empty failure-handler policy.
//!
//! Go does not have catch clauses.  The failure representation covered here
//! is the explicit `error`/`nil` guard, plus the two source-level forms that
//! deliberately discard a predeclared `recover` result.  The walk is
//! iterative and stops at function literals because each literal is a
//! separate callable seed.

use crate::analyzer::go::GoAnalyzer;

use crate::analyzer::go::type_identity_proof::go_predeclared_type_name_is_exact;

use brokk_bifrost_analysis::analyzer::structural::failure_handlers::HandlerBodyGap;

use brokk_bifrost_analysis::analyzer::structural::failure_handlers::HandlerBodyShape;

use brokk_bifrost_analysis::analyzer::structural::failure_handlers::HandlerBodyState;

use brokk_bifrost_analysis::analyzer::structural::failure_handlers::{
    HandlerIdentityProof, NativeFailureBranch,
};

use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

use crate::analyzer::usages::get_definition::go::parse_go_tree;

use crate::analyzer::go::native_points::{GoNativePointRequest, GoNativePointRequestOpen};
use brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery;
use brokk_bifrost_analysis::analyzer::languages::ReceiverRequest;
use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::model::Range;

use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;

use crate::analyzer::usages::get_definition::go::go_unwrap_parenthesized_type;
use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
use brokk_bifrost_core::analyzer::model::{StructuredTypeIdentity, StructuredTypeNodeView};
use brokk_bifrost_core::analyzer::query_token::QueryScope;
use brokk_bifrost_core::analyzer::tree_walk::node_range;
use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;
use brokk_bifrost_core::path_utils::rel_path_string;
use brokk_bifrost_go::declarations::{
    go_embedded_type_nodes, go_structured_type_identity, is_predeclared_go_basic_type,
};
use brokk_bifrost_go::references::go_name_shadowed_at_with_scope;
use tree_sitter::Node;

use brokk_bifrost_analysis::analyzer::native_points::open_native_point_operation;
use brokk_bifrost_analysis::analyzer::resolution::SemanticId;
use brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedSemanticLocator;
use brokk_bifrost_analysis::analyzer::store::resolution_operation::{
    SelectedResolutionOperationOpenOutcome, SelectedResolutionOperationOutcome,
};
use brokk_bifrost_core::hash::HashMap;

const LOOKUP_LIMIT: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindingProof {
    Error,
    Other,
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

struct HandlerEvidence<'a> {
    request: Option<GoNativePointRequestOpen<'a>>,
    cancellation: &'a CancellationToken,
    lexical: Option<SelectedResolutionOperationOpenOutcome<'a, 'a>>,
    types: HashMap<SemanticId, BindingProof>,
}

/// Find Go's native failure branches inside one callable.
pub fn go_failure_handler_body_shapes(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    syntax: &PreparedSyntaxTree,
    callable: Range,
    cancellation: &CancellationToken,
) -> Vec<NativeFailureBranch> {
    let mut evidence = HandlerEvidence {
        request: None,
        cancellation,
        lexical: None,
        types: HashMap::default(),
    };
    callable_body_shapes(workspace, file, syntax, callable, &mut evidence)
}

/// Classify a file in one pass, sharing lazy native type work across callables.
/// The caller retains only these completed rows for its query lifetime.
pub fn go_failure_handler_file_body_shapes(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    syntax: &PreparedSyntaxTree,
    cancellation: &CancellationToken,
) -> HashMap<Range, Vec<NativeFailureBranch>> {
    use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, walk_tree_preorder};
    let mut evidence = HandlerEvidence {
        request: None,
        cancellation,
        lexical: None,
        types: HashMap::default(),
    };
    let mut result = HashMap::default();
    walk_tree_preorder(syntax.tree().root_node(), true, |node| {
        if cancellation.is_cancelled() {
            return WalkControl::Break;
        }
        if matches!(
            node.kind(),
            "function_declaration" | "method_declaration" | "func_literal"
        ) {
            let range = node_range(node);
            result.insert(
                range,
                callable_body_shapes(workspace, file, syntax, range, &mut evidence),
            );
        }
        WalkControl::Continue
    });
    if cancellation.is_cancelled() {
        workspace.analyzer().mark_execution_dependent();
        result.clear();
    }
    result
}

fn callable_body_shapes<'go>(
    workspace: &'go WorkspaceAnalyzer,
    file: &ProjectFile,
    syntax: &PreparedSyntaxTree,
    callable: Range,
    evidence: &mut HandlerEvidence<'go>,
) -> Vec<NativeFailureBranch> {
    let cancellation = evidence.cancellation;
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
    let _scope = brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::with_cancellation(
        analyzer,
        cancellation,
    );
    let mut stack = vec![body];
    let mut branches = Vec::new();
    while let Some(node) = stack.pop() {
        if cancellation.is_cancelled() {
            analyzer.mark_execution_dependent();
            return Vec::new();
        }
        if node.id() != body.id() && node.kind() == "func_literal" {
            continue;
        }
        let branch = match node.kind() {
            "if_statement" => {
                classify_if(analyzer, go, file, syntax, node, callable_node, evidence)
            }
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

fn classify_if<'go>(
    analyzer: &dyn IAnalyzer,
    go: &'go GoAnalyzer,
    file: &ProjectFile,
    syntax: &PreparedSyntaxTree,
    if_node: Node<'_>,
    callable: Node<'_>,
    evidence: &mut HandlerEvidence<'go>,
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
                identity: HandlerIdentityProof::Exact,
                shape: branch_shape(if_node, body),
            }),
            BuiltinProof::Open => Some(NativeFailureBranch {
                handler: node_range(if_node),
                identity: HandlerIdentityProof::Open,
                shape: branch_shape(if_node, body),
            }),
            BuiltinProof::Shadowed | BuiltinProof::NotCandidate => None,
        };
    }

    if operator == "==" && if_node.child_by_field_name("alternative").is_none() {
        return None;
    }
    let proof = binding_proof(analyzer, go, file, syntax, name_node, callable, evidence);
    let identity = match proof {
        BindingProof::Error => HandlerIdentityProof::Exact,
        BindingProof::Open => HandlerIdentityProof::Open,
        BindingProof::Other => return None,
    };
    Some(NativeFailureBranch {
        handler: node_range(if_node),
        identity,
        shape: branch_shape(if_node, body),
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
            identity: HandlerIdentityProof::Open,
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
    if !saw_recover && !unknown_recover {
        return None;
    }
    Some(NativeFailureBranch {
        handler: node_range(defer_node),
        identity: if unknown_recover {
            HandlerIdentityProof::Open
        } else {
            HandlerIdentityProof::Exact
        },
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

enum SelectedBindingEvidence<'tree> {
    Syntax(Node<'tree>),
    Native(BindingProof),
}

fn native_binding_static_type<'tree, 'go>(
    analyzer: &dyn IAnalyzer,
    go: &'go GoAnalyzer,
    file: &ProjectFile,
    syntax: &'tree PreparedSyntaxTree,
    use_node: Node<'tree>,
    evidence: &mut HandlerEvidence<'go>,
) -> BoundedResolution<Option<SelectedBindingEvidence<'tree>>> {
    let cancellation = evidence.cancellation;
    let request = &mut evidence.request;
    use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupStatus;
    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisWork;
    let unknown = || BoundedResolution::Complete {
        value: Some(SelectedBindingEvidence::Native(BindingProof::Open)),
        work: ReceiverAnalysisWork::default(),
    };
    let site =
        call_site(file, syntax.source(), use_node).expect("selected identifier has a source range");
    let query = BoundedReceiverQuery {
        analyzer,
        file,
        source: syntax.source(),
        tree: Some(syntax.tree()),
        site: &site,
        budget: ReceiverAnalysisBudget::default(),
        cancellation: Some(cancellation),
    };
    let locator = SelectedSemanticLocator::for_reference_range(
        "go",
        rel_path_string(file),
        site.focus_start_byte,
        site.focus_end_byte,
    );
    let lookup = if let Some(GoNativePointRequestOpen::Ready(request)) = request.as_mut() {
        request.resolve_local_declaration(&locator, query.budget, cancellation)
    } else {
        if evidence.lexical.is_none() {
            match open_native_point_operation(&go.inner, cancellation) {
                Ok(opened) => evidence.lexical = Some(opened),
                Err(error) => {
                    analyzer.record_query_failure(error);
                    return unknown();
                }
            }
        }
        match evidence
            .lexical
            .as_mut()
            .expect("lexical operation was opened")
        {
            SelectedResolutionOperationOpenOutcome::Ready(operation) => {
                operation.resolve_local_declaration_bounded(&locator, query.budget, cancellation)
            }
            SelectedResolutionOperationOpenOutcome::Cancelled => {
                return BoundedResolution::Cancelled {
                    work: Default::default(),
                };
            }
            _ => {
                analyzer.mark_execution_dependent();
                return unknown();
            }
        }
    };
    let lookup = match lookup {
        Ok(value) => value,
        Err(error) => {
            analyzer.record_query_failure(error);
            return unknown();
        }
    };
    let (identity, lexical, work) = match lookup {
        BoundedResolution::Complete {
            value: SelectedResolutionOperationOutcome::Native(Some((identity, lexical))),
            work,
        } => (identity, lexical, work),
        BoundedResolution::Exceeded { limit, work } => {
            return BoundedResolution::Exceeded { limit, work };
        }
        BoundedResolution::Cancelled { work } => return BoundedResolution::Cancelled { work },
        BoundedResolution::Complete {
            value: SelectedResolutionOperationOutcome::Cancelled(_),
            work,
        } => return BoundedResolution::Cancelled { work },
        BoundedResolution::Complete {
            value: SelectedResolutionOperationOutcome::Native(None),
            ..
        } => return unknown(),
        _ => {
            analyzer.mark_execution_dependent();
            return unknown();
        }
    };
    if lexical.source_file.as_ref() != Some(file) {
        return unknown();
    }
    let range = lexical.name_range;
    let root = syntax.tree().root_node();
    let Some(name) = root
        .named_descendant_for_byte_range(range.start_byte, range.end_byte)
        .filter(|name| {
            name.kind() == "identifier"
                && name.start_byte() == range.start_byte
                && name.end_byte() == range.end_byte
        })
    else {
        return unknown();
    };
    let Some(parent) = name.parent() else {
        return unknown();
    };
    let declaration = parent
        .parent()
        .filter(|switch| {
            switch.kind() == "type_switch_statement"
                && switch.child_by_field_name("alias") == Some(parent)
        })
        .unwrap_or(parent);
    let explicit = match declaration.kind() {
        "variadic_parameter_declaration" => Some(declaration),
        "parameter_declaration" | "var_spec" => declaration.child_by_field_name("type"),
        "type_switch_statement" => {
            let mut ancestor = use_node.parent();
            let mut clause = None;
            while let Some(node) = ancestor {
                if matches!(node.kind(), "type_case" | "default_case")
                    && node.parent() == Some(declaration)
                {
                    clause = Some(node);
                    break;
                }
                ancestor = node.parent();
            }
            clause.and_then(|clause| {
                brokk_bifrost_go::declarations::go_single_type_switch_case_type(
                    clause,
                    syntax.source(),
                )
            })
        }
        _ => None,
    };
    if let Some(type_node) = explicit
        && explicit_type_proof(analyzer, file, syntax.source(), root, type_node)
            != BindingProof::Open
    {
        return BoundedResolution::Complete {
            value: Some(SelectedBindingEvidence::Syntax(type_node)),
            work,
        };
    }
    if let Some(proof) = evidence.types.get(&identity) {
        return BoundedResolution::Complete {
            value: Some(SelectedBindingEvidence::Native(*proof)),
            work,
        };
    }
    // Retain an open proof for bounded/unfinished attempts as well: a binder
    // is queried at most once during this file pass.
    evidence.types.insert(identity, BindingProof::Open);
    // The lexical reader is no longer needed once the type request owns one.
    evidence.lexical = None;
    if request.is_none() {
        *request = Some(
            match GoNativePointRequest::open_for_file(
                go,
                file,
                analyzer.semantic_model_overlay(),
                cancellation,
            ) {
                Ok(opened) => opened,
                Err(error) => {
                    analyzer.record_query_failure(error);
                    return unknown();
                }
            },
        );
    }
    let request = match request.as_mut().expect("type request was opened") {
        GoNativePointRequestOpen::Ready(request) => request,
        GoNativePointRequestOpen::Cancelled => {
            return BoundedResolution::Cancelled {
                work: Default::default(),
            };
        }
        _ => {
            analyzer.mark_execution_dependent();
            return unknown();
        }
    };
    let mut selected = BindingProof::Open;
    let remaining = BoundedReceiverQuery {
        budget: ReceiverAnalysisBudget {
            max_scope_nodes: query
                .budget
                .max_scope_nodes
                .saturating_sub(work.scope_nodes),
            max_summary_expansions: query
                .budget
                .max_summary_expansions
                .saturating_sub(work.summary_expansions),
            ..query.budget
        },
        ..query
    };
    let mut receiver = None;
    let types = request.resolve_declared_type_with_evidence(remaining, identity, |answer| {
        selected = native_declared_type_proof(answer);
        if selected == BindingProof::Open {
            use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedNativeTypes;
            if let Ok(Some(ty)) =
                brokk_bifrost_analysis::analyzer::native_points::selected_value_type_for_barrier(
                    &answer.answer,
                    answer.query_result_slot,
                )
                && let SelectedNativeTypes::Ready {
                    external_owners, ..
                } = &answer.value_types
                && !external_owners
                    .iter()
                    .any(|(identity, _)| *identity == ty.identity())
            {
                receiver = Some(ty);
            }
        }
    });
    match types {
        BoundedResolution::Complete {
            value,
            work: type_work,
        } => {
            let mut proof = if value.status == TypeLookupStatus::Resolved {
                selected
            } else {
                BindingProof::Open
            };
            let mut total_work = super::native_points::go_add_resolution_work(work, type_work);
            if proof == BindingProof::Open
                && let Some(receiver) = receiver
            {
                let member_query = BoundedReceiverQuery {
                    budget: ReceiverAnalysisBudget {
                        max_scope_nodes: query
                            .budget
                            .max_scope_nodes
                            .saturating_sub(total_work.scope_nodes),
                        max_summary_expansions: query
                            .budget
                            .max_summary_expansions
                            .saturating_sub(total_work.summary_expansions),
                        max_resolution_rounds: query
                            .budget
                            .max_resolution_rounds
                            .saturating_sub(total_work.resolution_rounds),
                        ..query.budget
                    },
                    ..query
                };
                match super::model_receiver::go_selected_static_type_member(
                    request,
                    member_query,
                    receiver,
                    "Error",
                    false,
                ) {
                    Ok(BoundedResolution::Complete {
                        value: Some(member),
                        work: member_work,
                    }) => {
                        proof = native_error_member_proof(&member);
                        total_work =
                            super::native_points::go_add_resolution_work(total_work, member_work);
                    }
                    Ok(BoundedResolution::Complete {
                        work: member_work, ..
                    }) => {
                        total_work =
                            super::native_points::go_add_resolution_work(total_work, member_work)
                    }
                    Ok(BoundedResolution::Exceeded {
                        limit,
                        work: member_work,
                    }) => {
                        return BoundedResolution::Exceeded {
                            limit,
                            work: super::native_points::go_add_resolution_work(
                                total_work,
                                member_work,
                            ),
                        };
                    }
                    Ok(BoundedResolution::Cancelled { work: member_work }) => {
                        return BoundedResolution::Cancelled {
                            work: super::native_points::go_add_resolution_work(
                                total_work,
                                member_work,
                            ),
                        };
                    }
                    Err(error) => {
                        analyzer.record_query_failure(error);
                    }
                }
            }
            evidence.types.insert(identity, proof);
            BoundedResolution::Complete {
                value: Some(SelectedBindingEvidence::Native(proof)),
                work: total_work,
            }
        }
        BoundedResolution::Exceeded {
            limit,
            work: type_work,
        } => BoundedResolution::Exceeded {
            limit,
            work: super::native_points::go_add_resolution_work(work, type_work),
        },
        BoundedResolution::Cancelled { work: type_work } => BoundedResolution::Cancelled {
            work: super::native_points::go_add_resolution_work(work, type_work),
        },
    }
}

fn binding_proof<'go>(
    analyzer: &dyn IAnalyzer,
    go: &'go GoAnalyzer,
    file: &ProjectFile,
    syntax: &PreparedSyntaxTree,
    use_node: Node<'_>,
    callable: Node<'_>,
    evidence: &mut HandlerEvidence<'go>,
) -> BindingProof {
    let root = syntax.tree().root_node();
    let source = syntax.source();
    let name = source
        .get(use_node.byte_range())
        .expect("selected identifier belongs to prepared source");
    // Use the declared binding's static type, including across a multi-name :=
    // assignment. A later assignment's value cannot provide a negative proof.
    // Native evidence selects the binder first. Exact annotation syntax still
    // supplies unnamed channel/function shapes and struct embedding: native
    // identities omit whether an anonymous struct embeds error. Inferred types
    // always use the selected declaration slot, never an assignment's value.
    // Named types and interfaces use native static member selection. A bounded
    // type or promotion frontier cannot exclude an error value.
    match native_binding_static_type(analyzer, go, file, syntax, use_node, evidence) {
        BoundedResolution::Complete {
            value: Some(SelectedBindingEvidence::Native(proof)),
            ..
        } => return proof,
        BoundedResolution::Complete {
            value: Some(SelectedBindingEvidence::Syntax(type_node)),
            ..
        } => return explicit_type_proof(analyzer, file, source, root, type_node),
        BoundedResolution::Exceeded { .. } | BoundedResolution::Cancelled { .. } => {
            analyzer.mark_execution_dependent();
        }
        _ => {}
    }
    // No unique certified local binder (for example a package-level variable
    // or an uncertified local): the pre-existing syntactic positive rule still
    // runs, walking parameters, var specs and := bindings by name, with
    // call_result_proof for call-bound values. Milestone 3c retires it once
    // native binder selection covers package-level and uncertified binders.
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
                proof: explicit_type_proof(analyzer, file, source, root, type_node),
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
            && let proof = call_result_proof(analyzer, go, file, syntax, call, ordinal, evidence)
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
        }

        if node.kind() != "func_literal" || node.id() == callable.id() {
            let mut cursor = node.walk();
            let mut children = node.named_children(&mut cursor).collect::<Vec<_>>();
            children.reverse();
            stack.extend(children);
        }
    }

    let proof = if let Some(short) = short_call
        && explicit.is_none_or(|typed| {
            short.scope_depth > typed.scope_depth
                || (short.scope_depth == typed.scope_depth && short.start_byte >= typed.start_byte)
        }) {
        short.proof
    } else if let Some(typed) = explicit {
        typed.proof
    } else {
        assignment_call
            .map(|candidate| candidate.proof)
            .unwrap_or(BindingProof::Open)
    };
    // Keep the positive rule, but an unknown declaration type cannot acquire
    // a negative proof from a call or literal assigned later in its scope.
    match proof {
        BindingProof::Other => BindingProof::Open,
        _ => proof,
    }
}

// The policy's existing positive set is the plain predeclared error identity.
// Shadowing is checked separately at the type declaration's source location.
fn is_error_type(identity: &StructuredTypeIdentity) -> bool {
    matches!(
        identity.view(identity.root_id()),
        Some(StructuredTypeNodeView::Named(_))
    ) && identity.nominal_name().is_some_and(|name| {
        !name.is_absolute() && name.lexical_scope().is_empty() && name.path() == ["error"]
    })
}

// Only unnamed containers have a structural identity that rules out methods.
// A nominal name (including pointers to one) needs a separate method-set proof.
fn is_definitely_non_error_type(identity: &StructuredTypeIdentity) -> bool {
    matches!(
        identity.view(identity.root_id()),
        Some(
            StructuredTypeNodeView::Array(_)
                | StructuredTypeNodeView::Slice(_)
                | StructuredTypeNodeView::Map { .. }
        )
    )
}

fn predeclared_basic_type_name(identity: &StructuredTypeIdentity) -> Option<&str> {
    let Some(StructuredTypeNodeView::Named(name)) = identity.view(identity.root_id()) else {
        return None;
    };
    let [basic] = name.path() else { return None };
    (!name.is_absolute() && name.lexical_scope().is_empty() && is_predeclared_basic_name(basic))
        .then_some(basic)
}

fn is_predeclared_basic_name(name: &str) -> bool {
    is_predeclared_go_basic_type(name)
}

fn native_declared_type_proof(
    answer: &brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedNativeReferenceTypes,
) -> BindingProof {
    use super::type_identity_proof::{ObservedCarrierType, go_observed_value_type};
    use brokk_bifrost_analysis::analyzer::semantic::{ObservedValueType, ValueShape};
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedNativeTypes;
    use brokk_bifrost_core::analyzer::resolution_facts::IntrinsicTypeKind;
    let Ok(Some(selected)) =
        brokk_bifrost_analysis::analyzer::native_points::selected_value_type_for_barrier(
            &answer.answer,
            answer.query_result_slot,
        )
    else {
        return BindingProof::Open;
    };
    if selected.indirection() == 0
        && let SelectedNativeTypes::Ready { intrinsic, .. } = &answer.value_types
        && intrinsic.iter().any(|descriptor| {
            descriptor.identity() == selected.identity()
                && descriptor.kind() == IntrinsicTypeKind::LanguageBuiltin
                && descriptor.spelling() == "error"
        })
    {
        // A complete native answer is the declaration's static type, so error
        // and basic/unnamed shapes prove their verdict without the fallback.
        return BindingProof::Error;
    }
    // Carrier shape follows underlying types for value predicates. A named
    // slice, function or scalar can still own Error, so its source nominal
    // identity must reach static membership before any non-handler decision.
    if let SelectedNativeTypes::Ready { nominal, .. } = &answer.value_types
        && nominal
            .iter()
            .any(|(identity, _)| *identity == selected.identity())
    {
        return BindingProof::Open;
    }
    match go_observed_value_type(answer) {
        ObservedCarrierType::Type(ObservedValueType::NonNamed(
            ValueShape::Array | ValueShape::Slice | ValueShape::Map | ValueShape::Function,
        )) => BindingProof::Other,
        ObservedCarrierType::Type(ObservedValueType::Named { canonical })
            if is_predeclared_basic_name(&canonical) =>
        {
            BindingProof::Other
        }
        _ => BindingProof::Open,
    }
}

fn native_error_member_proof(
    answer: &brokk_bifrost_analysis::analyzer::store::resolution_operation::go_receiver_anchor::GoStaticTypeMember,
) -> BindingProof {
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::go_receiver_anchor::GoStaticMembership;
    use brokk_bifrost_core::analyzer::resolution_facts::IntrinsicTypeKind;
    match answer.membership() {
        GoStaticMembership::Open => BindingProof::Open,
        // Native literal-alias and builtin-interface inventories remain open
        // until #7990; absence in an interface cannot prove a non-handler.
        GoStaticMembership::Excluded if answer.receiver_is_interface => BindingProof::Open,
        GoStaticMembership::Excluded => BindingProof::Other,
        GoStaticMembership::Present => {
            let member = &answer.candidates[0];
            let Some(signature) = &member.signature else {
                return BindingProof::Open;
            };
            if !member.signature_types_complete {
                return BindingProof::Open;
            }
            let matches = signature.parameters().is_empty()
                && signature.result_types().len() == 1
                && member
                    .signature_types
                    .iter()
                    .find(|state| state.slot() == signature.result_types()[0].slot())
                    .is_some_and(|state| match state.possible_values() {
                        [value] if value.ty().indirection() == 0 => {
                            answer.intrinsic_types.iter().any(|descriptor| {
                                descriptor.identity() == value.ty().identity()
                                    && descriptor.kind() == IntrinsicTypeKind::Primitive
                                    && descriptor.spelling() == "string"
                            })
                        }
                        _ => false,
                    });
            if matches {
                BindingProof::Error
            } else if answer.receiver_is_interface {
                BindingProof::Open
            } else {
                BindingProof::Other
            }
        }
    }
}

fn explicit_type_proof(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    type_node: Node<'_>,
) -> BindingProof {
    if type_node.has_error() || type_node.is_missing() {
        return BindingProof::Open;
    }
    // Parentheses do not change any type shape, including channels/functions
    // that the indexed type identity does not currently represent.
    let Some(type_node) = go_unwrap_parenthesized_type(type_node) else {
        return BindingProof::Open;
    };
    // Unnamed structs may promote Error() from any embedded field. Their
    // pointer types have the same uncertainty; only a struct without embedding
    // proves that no such method exists. Navigation has no identity for structs.
    let mut underlying = type_node;
    while matches!(underlying.kind(), "pointer_type" | "parenthesized_type") {
        let Some(inner) = underlying
            .child_by_field_name("type")
            .or_else(|| underlying.named_child(0))
        else {
            return BindingProof::Open;
        };
        underlying = inner;
    }
    if underlying.kind() == "struct_type" {
        return if go_embedded_type_nodes(underlying).is_empty() {
            BindingProof::Other
        } else {
            BindingProof::Open
        };
    }
    // The AST also proves these unnamed shapes even though navigation does not
    // represent function or channel identities, or an unsupported element type.
    if matches!(
        type_node.kind(),
        "channel_type"
            | "function_type"
            | "map_type"
            | "slice_type"
            | "variadic_parameter_declaration"
            | "array_type"
            | "implicit_length_array_type"
    ) {
        return BindingProof::Other;
    }
    let Some(identity) = go_structured_type_identity(type_node, source) else {
        return BindingProof::Open;
    };
    if is_definitely_non_error_type(&identity) {
        return BindingProof::Other;
    }
    // A source-backed identity gap is reusable, but these limited provider
    // proofs can also stop without an answer. Preserve that distinction.
    let predeclared = |name| {
        let proof =
            go_predeclared_type_name_is_exact(analyzer, file, source, root, type_node, name);
        if proof.is_none() {
            analyzer.mark_execution_dependent();
        }
        proof
    };
    if is_error_type(&identity) {
        return match predeclared("error") {
            Some(true) => BindingProof::Error,
            Some(false) | None => BindingProof::Open,
        };
    }
    if let Some(name) = predeclared_basic_type_name(&identity)
        && predeclared(name) == Some(true)
    {
        return BindingProof::Other;
    }
    BindingProof::Open
}

fn call_result_proof(
    analyzer: &dyn IAnalyzer,
    go: &GoAnalyzer,
    file: &ProjectFile,
    syntax: &PreparedSyntaxTree,
    call: Node<'_>,
    ordinal: usize,
    evidence: &mut HandlerEvidence<'_>,
) -> BindingProof {
    let Some(function) = call.child_by_field_name("function") else {
        return BindingProof::Open;
    };
    let Some(site) = call_site(file, syntax.source(), function) else {
        return BindingProof::Open;
    };
    let Some(GoNativePointRequestOpen::Ready(request)) = evidence.request.as_mut() else {
        return BindingProof::Open;
    };
    let result = request.resolve_definition(BoundedReceiverQuery {
        analyzer,
        file,
        source: syntax.source(),
        tree: Some(syntax.tree()),
        site: &site,
        budget: ReceiverAnalysisBudget::default(),
        cancellation: Some(evidence.cancellation),
    });
    let BoundedResolution::Complete { value, .. } = result else {
        analyzer.mark_execution_dependent();
        return BindingProof::Open;
    };
    if !matches!(
        value.status,
        DefinitionLookupStatus::Resolved
            | DefinitionLookupStatus::NoDefinition
            | DefinitionLookupStatus::UnresolvableImportBoundary
            | DefinitionLookupStatus::Ambiguous
    ) {
        analyzer.mark_execution_dependent();
    }
    if value.status != DefinitionLookupStatus::Resolved
        || !value.modeled_definitions.is_empty()
        || value.definitions.len() != 1
    {
        return BindingProof::Open;
    }
    let declaration = &value.definitions[0];
    let metadata = go.signature_metadata_limited(declaration, 64);
    if !metadata.complete {
        analyzer.mark_execution_dependent();
        return BindingProof::Open;
    }
    if metadata.rows.len() != 1 {
        return BindingProof::Open;
    }
    let Some(source) = analyzer.indexed_source(declaration.source()) else {
        analyzer.mark_execution_dependent();
        return BindingProof::Open;
    };
    let Some(tree) = parse_go_tree(&source) else {
        analyzer.mark_execution_dependent();
        return BindingProof::Open;
    };
    let ranges = go.ranges_limited(declaration, 8);
    if !ranges.complete {
        analyzer.mark_execution_dependent();
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
    explicit_type_proof(
        analyzer,
        declaration.source(),
        &source,
        tree.root_node(),
        type_node,
    )
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
    let scope = brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(analyzer);
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
        None => {
            analyzer.mark_execution_dependent();
            BuiltinProof::Open
        }
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
    brokk_bifrost_core::analyzer::structural::adapter_helpers::if_alternative_body(if_node)
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

    use crate::analyzer::go::failure_handlers::*;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;

    fn prepared(source: &str) -> PreparedSyntaxTree {
        crate::analyzer::prepared_go_test_syntax(
            source,
            brokk_bifrost_go::parse::parse_go(source).expect("Go source parses"),
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
        go_failure_handler_body_shapes(
            fixture.analyzer(),
            &file,
            &syntax,
            callable,
            &CancellationToken::default(),
        )
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
        // The complete local method inventory proves this named type is not
        // an error value; there is no handler candidate to leave open.
        assert!(branches(shadowed).is_empty());

        let concrete = r#"package p
type ConcreteError struct{}
func work(err ConcreteError) { if err != nil {} }
"#;
        // The complete local method inventory proves this named type is not
        // an error value; there is no handler candidate to leave open.
        assert!(branches(concrete).is_empty());

        let unresolved = r#"package p
func work() { if err := missing(); err != nil {} }
"#;
        assert_eq!(states(unresolved), vec![HandlerBodyState::Empty]);
        assert!(
            branches(unresolved)
                .iter()
                .all(|branch| branch.identity == HandlerIdentityProof::Open)
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
                &CancellationToken::default(),
            )
            .into_iter()
            .map(|branch| branch.shape.state)
            .collect::<Vec<_>>(),
            vec![HandlerBodyState::Empty]
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#7509: Go failure-handler classification ignored caller cancellation"
    )]
    fn cancelled_handler_pass_issues_no_native_reads() {
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::selected_sql_trace::{
            begin_production_selected_sql_trace, finish_production_selected_sql_trace,
        };
        let source = "package p\nfunc work(err error) { if err != nil {} }\n";
        let fixture = AnalyzerFixture::new_for_language(
            Language::Go,
            &[("go.mod", "module example.com/app\n"), ("main.go", source)],
        );
        let syntax = prepared(source);
        let file = ProjectFile::new(fixture.project_root(), "main.go");
        let mut cursor = syntax.tree().root_node().walk();
        let callable = syntax
            .tree()
            .root_node()
            .named_children(&mut cursor)
            .find(|node| node.kind() == "function_declaration")
            .expect("fixture callable");
        let cancellation = CancellationToken::default();
        assert_eq!(
            go_failure_handler_body_shapes(
                fixture.analyzer(),
                &file,
                &syntax,
                node_range(callable),
                &cancellation
            )
            .len(),
            1,
            "uncancelled pass actually finds a handler"
        );
        cancellation.cancel();
        let store = fixture.analyzer().store().expect("native fixture store");
        begin_production_selected_sql_trace(store);
        let branches = go_failure_handler_body_shapes(
            fixture.analyzer(),
            &file,
            &syntax,
            node_range(callable),
            &cancellation,
        );
        let cost = finish_production_selected_sql_trace(store);
        assert!(
            branches.is_empty(),
            "cancelled pass must not publish partial evidence"
        );
        assert!(
            cost.statements.is_empty(),
            "caller cancellation stops before native SQL: {cost:?}"
        );
    }
}
