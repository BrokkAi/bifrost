//! Exact source statement entries from one immutable procedure artifact.
//!
//! A query must enumerate executable syntax from a prepared tree before asking
//! for an entry. A missing producer site for such syntax is open coverage, not
//! evidence that the statement is unreachable.

use crate::analyzer::languages::ProcedureSyntaxRoles;
use crate::analyzer::languages::language_support_for_hook;
use crate::analyzer::read_ledger::reason as derivation_reason;
use crate::analyzer::semantic::cfg_algorithms::{
    CfgAlgorithmBudget, CfgAlgorithmRequest, DenseBidirectionalGraph, FeasibleSuccessors,
    forward_reachability_with_filtered_successors, forward_reachability_with_successors,
};

use crate::analyzer::semantic::type_flow::{
    source_span_for_node, validate_prepared_syntax_source_for_procedure,
};

use crate::analyzer::semantic::{
    ControlEdgeId, ControlEdgeKind, EvidenceCompleteness, GuardPredicate, ProcedureHandle,
    ProcedureSemantics, ProgramPointId, ProofStatus, SemanticCapability, SemanticGapDischarge,
    SemanticGapSubject, SemanticRole, SourceMappingKind, SourceSpan,
};

use crate::analyzer::structural::provider::StructuralSyntaxLimitedOutcome;
use crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree;
use crate::analyzer::{ProjectFile, WorkspaceAnalyzer};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use crate::text_utils::{compute_line_starts, line_column_for_offset};
use brokk_bifrost_core::analyzer::tree_walk::node_range;
pub use brokk_bifrost_semantic::analyzer::semantic::statement_entries::*;
use tree_sitter::Node;

/// Rust's literal guard and bare wildcard pattern edges proven infeasible by
/// exact prepared syntax. Other languages and unavailable syntax exclude none.
pub fn rust_infeasible_control_edges(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    cancellation: Option<&CancellationToken>,
) -> Vec<ControlEdgeId> {
    if procedure.artifact().key().language().language() != crate::analyzer::Language::Rust {
        return Vec::new();
    }
    let Ok(prepared) = ProcedureSyntax::prepare(workspace, procedure, cancellation) else {
        return Vec::new();
    };
    rust_infeasible_edges(procedure.semantics(), &prepared.syntax)
}

fn rust_infeasible_edges(
    semantics: &ProcedureSemantics,
    syntax: &PreparedSyntaxTree,
) -> Vec<ControlEdgeId> {
    let root = syntax.tree().root_node();
    let exact_node = |source| {
        let mapping = semantics.source_mapping(source)?;
        if mapping.kind != SourceMappingKind::Exact {
            return None;
        }
        let span = mapping.locator.anchor().span();
        let node = root.named_descendant_for_byte_range(
            span.start_byte() as usize,
            span.end_byte() as usize,
        )?;
        (source_span_for_node(node) == span).then_some(node)
    };
    let mut excluded = HashSet::default();
    for guard in semantics.guard_facts() {
        let Some(node) = exact_node(guard.source) else {
            continue;
        };
        if let GuardPredicate::ConstantBoolean { value } = guard.predicate {
            let mut literal = node;
            while matches!(
                literal.kind(),
                "parenthesized_expression" | "boolean_literal"
            ) {
                let Some(child) = literal.named_child(0).or_else(|| literal.child(0)) else {
                    break;
                };
                literal = child;
            }
            if matches!((literal.kind(), value), ("true", true) | ("false", false))
                && let Some(edge) = guard.infeasible_edge()
                && semantics.control_edge(edge).is_some_and(|row| {
                    row.kind
                        == if value {
                            ControlEdgeKind::ConditionalFalse
                        } else {
                            ControlEdgeKind::ConditionalTrue
                        }
                })
            {
                excluded.insert(edge);
            }
        } else if node.kind() == "let_condition"
            && node
                .child_by_field_name("pattern")
                .is_some_and(|pattern| pattern.kind() == "_")
            && let Some(edge) = guard.false_edge
            && semantics
                .control_edge(edge)
                .is_some_and(|row| row.kind == ControlEdgeKind::ConditionalFalse)
        {
            excluded.insert(edge);
        }
    }
    for point in semantics.points() {
        let Some(node) = exact_node(point.source) else {
            continue;
        };
        if node.kind() != "let_declaration"
            || !node
                .child_by_field_name("pattern")
                .is_some_and(|pattern| pattern.kind() == "_")
            || node.child_by_field_name("alternative").is_none()
        {
            continue;
        }
        for (id, edge) in semantics.successor_edges(point.id) {
            if edge.kind == ControlEdgeKind::ConditionalFalse {
                excluded.insert(id);
            }
        }
    }
    let mut excluded = excluded.into_iter().collect::<Vec<_>>();
    excluded.sort_unstable();
    excluded
}
/// Prepared syntax validated against one procedure's artifact snapshot, with
/// the syntax roles of the procedure's language.
pub(crate) struct ProcedureSyntax {
    pub(crate) file: ProjectFile,
    pub(crate) syntax: std::sync::Arc<PreparedSyntaxTree>,
    pub(crate) roles: ProcedureSyntaxRoles,
}

impl ProcedureSyntax {
    /// Load and validate the prepared tree for `procedure`. The error is a
    /// stable open reason for the caller's row or diagnostic.
    pub(crate) fn prepare(
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        cancellation: Option<&CancellationToken>,
    ) -> Result<Self, &'static str> {
        let language = procedure.artifact().key().language().language();
        let roles = language_support_for_hook(language, "procedure_syntax_roles")
            .and_then(|support| support.procedure_syntax_roles())
            .ok_or(derivation_reason::UNSUPPORTED_LANGUAGE)?;
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err(derivation_reason::CANCELLED);
        }
        let file = ProjectFile::new(
            workspace.analyzer().project().root().to_path_buf(),
            procedure.artifact().key().path().as_path(),
        );
        let syntax = workspace
            .analyzer()
            .structural_fact_providers()
            .into_iter()
            .find(|provider| provider.structural_language() == language)
            .map(|provider| {
                provider.structural_syntax_limited(&file, MAX_STATEMENT_SOURCE_BYTES, cancellation)
            });
        let syntax = match syntax {
            Some(StructuralSyntaxLimitedOutcome::Available(syntax)) => syntax,
            Some(StructuralSyntaxLimitedOutcome::Exceeded { .. }) => {
                brokk_bifrost_core::profiling::note_with(|| {
                    format!(
                        "policy.units unbounded origin={}:{} cause=budget:source",
                        file!(),
                        line!()
                    )
                });
                workspace.analyzer().mark_execution_dependent();
                return Err(derivation_reason::SOURCE_BUDGET_EXHAUSTED);
            }
            Some(StructuralSyntaxLimitedOutcome::Cancelled) => {
                return Err(derivation_reason::CANCELLED);
            }
            Some(StructuralSyntaxLimitedOutcome::Unavailable) | None => {
                brokk_bifrost_core::profiling::note_with(|| {
                    format!(
                        "policy.units unbounded origin={}:{} cause=provider:prepared_syntax",
                        file!(),
                        line!()
                    )
                });
                workspace.analyzer().mark_execution_dependent();
                return Err(derivation_reason::PREPARED_SYNTAX_UNAVAILABLE);
            }
        };
        let syntax = validate_prepared_syntax_source_for_procedure(
            workspace,
            procedure,
            &file,
            syntax.into_inner(),
        )
        .map_err(|_| derivation_reason::SOURCE_IDENTITY_MISMATCH)?;
        Ok(Self {
            file,
            syntax,
            roles,
        })
    }

    /// The unique syntax node that owns `procedure`: its exact source span
    /// and a node role that matches the procedure kind. Wrappers can share a
    /// callable's span, so the role match must select exactly one node.
    pub(crate) fn procedure_node(
        &self,
        procedure: &ProcedureHandle,
    ) -> Result<Node<'_>, &'static str> {
        let semantics = procedure.semantics();
        let mut callable_mapping = None;
        for candidate in semantics.source_mappings().iter().filter(|mapping| {
            mapping.kind == SourceMappingKind::Exact
                && mapping.locator.role() == SemanticRole::SourceMapping
        }) {
            assert!(
                callable_mapping.replace(candidate).is_none(),
                "a procedure publishes at most one exact callable source mapping"
            );
        }
        let mapping = callable_mapping.unwrap_or_else(|| {
            semantics
                .source_mapping(semantics.source())
                .expect("validated procedure source exists")
        });
        if mapping.kind != SourceMappingKind::Exact {
            return Err(derivation_reason::PROCEDURE_MAPPING_INEXACT);
        }
        let span = mapping.locator.anchor().span();
        let mut node = self
            .syntax
            .tree()
            .root_node()
            .named_descendant_for_byte_range(span.start_byte() as usize, span.end_byte() as usize)
            .ok_or(derivation_reason::PROCEDURE_SYNTAX_MISSING)?;
        let mut matching_roles = 0;
        let mut selected = None;
        loop {
            if source_span_for_node(node) != span {
                break;
            }
            if (self.roles.procedure_matches)(semantics.kind(), node) {
                matching_roles += 1;
                selected = Some(node);
            }
            let Some(parent) = node.parent() else {
                break;
            };
            node = parent;
        }
        let node = selected
            .filter(|_| matching_roles == 1)
            .ok_or(derivation_reason::PROCEDURE_SYNTAX_AMBIGUOUS)?;
        if node.has_error() {
            return Err(derivation_reason::PROCEDURE_SYNTAX_RECOVERY);
        }
        Ok(node)
    }
}

/// Assess every executable statement owned by one exact semantic procedure.
/// A missing site or incomplete control proof is an open row.
pub fn statement_assessments(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    cancellation: Option<&CancellationToken>,
) -> StatementAssessments {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return build_statement_assessments(workspace, procedure, cancellation);
    }
    (*workspace
        .analyzer()
        .statement_assessments_for(workspace, procedure, cancellation))
    .clone()
}

pub(crate) fn build_statement_assessments(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    cancellation: Option<&CancellationToken>,
) -> StatementAssessments {
    let prepared = match ProcedureSyntax::prepare(workspace, procedure, cancellation) {
        Ok(prepared) => prepared,
        Err(reason) => return unavailable(reason),
    };
    let ProcedureSyntax {
        file,
        syntax,
        roles: grammar,
    } = &prepared;
    let Ok(index) = StatementEntryIndex::new(procedure, file, syntax) else {
        brokk_bifrost_core::profiling::note_with(|| {
            format!(
                "policy.units unbounded origin={}:{} cause=snapshot",
                file!(),
                line!()
            )
        });
        workspace.analyzer().mark_execution_dependent();
        return unavailable(derivation_reason::SOURCE_IDENTITY_MISMATCH);
    };
    let semantics = procedure.semantics();
    let procedure_node = match prepared.procedure_node(procedure) {
        Ok(node) => node,
        Err(reason) => return unavailable(reason),
    };
    // The procedure's own body block is its entry, not a statement of it.
    let procedure_body = procedure_node
        .child_by_field_name("body")
        .unwrap_or(procedure_node);

    let line_starts = compute_line_starts(syntax.source());
    let mut stack = vec![procedure_node];
    let mut candidates = Vec::new();
    let mut span_counts = HashMap::<SourceSpan, usize>::default();
    while let Some(node) = stack.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return unavailable(derivation_reason::CANCELLED);
        }
        if node.id() != procedure_node.id() && (grammar.nested_procedure)(node) {
            continue;
        }
        if node.id() != procedure_body.id()
            && let Some(kind) = (grammar.statement_kind)(node)
        {
            let span = source_span_for_node(node);
            *span_counts.entry(span).or_default() += 1;
            let (start_line, start_column) =
                line_column_for_offset(syntax.source(), &line_starts, node.start_byte());
            let (end_line, end_column) =
                line_column_for_offset(syntax.source(), &line_starts, node.end_byte());
            candidates.push((
                span,
                node.has_error(),
                StatementAssessment {
                    range: node_range(node),
                    coordinates: StatementCoordinates {
                        start_line,
                        start_column,
                        end_line,
                        end_column,
                    },
                    kind,
                    verdict: StatementVerdict::Open(derivation_reason::SYNTAX_RECOVERY),
                    region_first: None,
                },
            ));
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    let uncancelled = CancellationToken::new();
    let mut budget = CfgAlgorithmBudget::default();
    let mut request = CfgAlgorithmRequest::new(&mut budget, cancellation.unwrap_or(&uncancelled));
    let rust = procedure.artifact().key().language().language() == crate::analyzer::Language::Rust;
    let feasible = FeasibleSuccessors::new(
        semantics,
        if rust {
            rust_infeasible_edges(semantics, syntax)
        } else {
            Vec::new()
        },
    );
    let (potential, suffix, uncertain, source_order) = match control_projection(
        workspace,
        procedure,
        (syntax, &index),
        procedure_node,
        &feasible,
        cancellation.unwrap_or(&uncancelled),
        &mut request,
    ) {
        Ok(projection) => projection,
        Err(reason) => return unavailable(reason),
    };
    let certain = match forward_reachability_with_filtered_successors(
        &feasible,
        semantics.entry_point(),
        |point| !uncertain[point.index()],
        |edge| {
            control_edge_proves_route(semantics, semantics.control_edges()[edge.index()].evidence)
        },
        |_| (&[], &[]),
        &mut request,
    ) {
        Ok(reachable) => reachable,
        Err(error) => return unavailable(execution_open_reason(workspace.analyzer(), error)),
    };
    let may_reach = match forward_reachability_with_successors(
        &feasible,
        semantics.entry_point(),
        |_| true,
        |point| {
            (
                &potential[point.index()],
                &source_order[suffix[point.index()]..],
            )
        },
        &mut request,
    ) {
        Ok(reachable) => reachable,
        Err(error) => return unavailable(execution_open_reason(workspace.analyzer(), error)),
    };
    // Rust's prepared source has no expansion nodes. Every mapped statement is
    // visible, including a macro invocation; an isolated statement has no
    // producer entry and remains Open. Non-statement IR points are bridged.
    let mut entry_owners = HashMap::<ProgramPointId, Vec<usize>>::default();
    if rust {
        for (ordinal, (span, malformed, _)) in candidates.iter().enumerate() {
            if !malformed
                && span_counts[span] == 1
                && let Ok(entries) = index.at_span(*span)
            {
                for entry in entries {
                    entry_owners.entry(*entry).or_default().push(ordinal);
                }
            }
        }
    }
    let mut rows = Vec::with_capacity(candidates.len());
    for (span, malformed, mut row) in candidates.iter().cloned() {
        if let Err(error) = request.visit_node::<ProgramPointId>() {
            return unavailable(execution_open_reason(workspace.analyzer(), error));
        }
        if !malformed {
            row.verdict = if span_counts[&span] != 1 {
                StatementVerdict::Open(derivation_reason::AMBIGUOUS_STATEMENT_SPAN)
            } else {
                match index.at_span(span) {
                    Err(StatementEntryOpen::MissingProducerSite) => {
                        StatementVerdict::Open(derivation_reason::MISSING_STATEMENT_ENTRY)
                    }
                    Err(StatementEntryOpen::SourceSnapshotMismatch) => {
                        StatementVerdict::Open(derivation_reason::SOURCE_IDENTITY_MISMATCH)
                    }
                    Ok(entries) => {
                        // The walk includes a point before checking whether its
                        // continuation is certain; a statement at that point
                        // must not inherit a Reachable proof from membership.
                        if entries.iter().any(|point| {
                            certain.contains(semantics, *point) && !uncertain[point.index()]
                        }) {
                            StatementVerdict::Reachable
                        } else if entries
                            .iter()
                            .any(|point| may_reach.contains(semantics, *point))
                        {
                            StatementVerdict::Open(reason::CONTROL_EVIDENCE_INCOMPLETE)
                        } else {
                            StatementVerdict::Unreachable
                        }
                    }
                }
            };
        }
        rows.push(row);
    }
    if rust {
        // Region first is a projection of the existing reachability verdicts.
        // The CFG supplies only predecessor identity, bridged over points with
        // no visible statement owner; it never supplies a second control proof.
        let mut first = Vec::with_capacity(candidates.len());
        for (ordinal, (span, _, _)) in candidates.iter().enumerate() {
            match region_first_for_statement(
                &feasible,
                &index,
                *span,
                &entry_owners,
                ordinal,
                &rows,
                &mut request,
            ) {
                Ok(verdict) => first.push(verdict),
                Err(error) => {
                    return unavailable(execution_open_reason(workspace.analyzer(), error));
                }
            }
        }
        for (row, verdict) in rows.iter_mut().zip(first) {
            row.region_first = verdict;
        }
    }
    rows.sort_unstable_by_key(|row| (row.range.start_byte, row.range.end_byte));
    StatementAssessments {
        rows,
        complete: true,
        reason: None,
    }
}

/// Classify an unreachable statement from its existing verdict and those of
/// its visible CFG predecessors. An unreachable predecessor wins (not first),
/// otherwise any Open predecessor makes this Open; otherwise this is first.
/// A candidate whose own reachability is Open cannot claim to be first.
fn region_first_for_statement<
    G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
>(
    graph: &G,
    index: &StatementEntryIndex,
    span: SourceSpan,
    owners: &HashMap<ProgramPointId, Vec<usize>>,
    ordinal: usize,
    rows: &[StatementAssessment],
    request: &mut CfgAlgorithmRequest<'_>,
) -> Result<
    Option<RegionFirstVerdict>,
    crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmError<ProgramPointId>,
> {
    match rows[ordinal].verdict {
        StatementVerdict::Reachable => return Ok(None),
        StatementVerdict::Open(_) => return Ok(Some(RegionFirstVerdict::Open)),
        StatementVerdict::Unreachable => {}
    }
    let Ok(entries) = index.at_span(span) else {
        return Ok(Some(RegionFirstVerdict::Open));
    };
    let mut pending = entries.to_vec();
    let mut seen = HashSet::default();
    let mut unreachable_predecessor = false;
    let mut open_predecessor = false;
    while let Some(point) = pending.pop() {
        if !seen.insert(point) {
            continue;
        }
        request.visit_node::<ProgramPointId>()?;
        for (_, source) in graph.predecessors(point) {
            request.visit_node::<ProgramPointId>()?;
            if let Some(predecessors) = owners.get(&source) {
                let mut found_other = false;
                for predecessor in predecessors
                    .iter()
                    .copied()
                    .filter(|owner| *owner != ordinal)
                {
                    found_other = true;
                    match rows[predecessor].verdict {
                        StatementVerdict::Unreachable => unreachable_predecessor = true,
                        StatementVerdict::Open(_) => open_predecessor = true,
                        StatementVerdict::Reachable => {}
                    }
                }
                if found_other {
                    continue;
                }
            }
            pending.push(source);
        }
    }
    Ok(Some(if unreachable_predecessor {
        RegionFirstVerdict::NotFirst
    } else if open_predecessor {
        RegionFirstVerdict::Open
    } else {
        RegionFirstVerdict::First
    }))
}

/// Potential control destinations and points whose normal continuation is
/// uncertain. The language default is the whole procedure: it cannot create
/// a new Unreachable answer for a language without a structured hook.
type ControlProjection = (
    Vec<Vec<ProgramPointId>>,
    Vec<usize>,
    Vec<bool>,
    Vec<ProgramPointId>,
);

fn control_projection(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    source: (&PreparedSyntaxTree, &StatementEntryIndex),
    procedure_node: Node<'_>,
    feasible: &FeasibleSuccessors<'_, ProcedureSemantics>,
    cancellation: &CancellationToken,
    request: &mut CfgAlgorithmRequest<'_>,
) -> Result<ControlProjection, &'static str> {
    let (syntax, index) = source;
    let semantics = procedure.semantics();
    let rust = procedure.artifact().key().language().language() == crate::analyzer::Language::Rust;
    let mut source_order = semantics
        .points()
        .iter()
        .map(|point| {
            // Points without an exact source position may follow any gap.
            // Keep them in every source-order suffix to over-approximate
            // normal continuation rather than silently dropping a route.
            let start = semantics
                .source_mapping(point.source)
                .filter(|source| source.kind == SourceMappingKind::Exact)
                .map(|source| source.locator.anchor().span().start_byte() as usize)
                .unwrap_or(usize::MAX);
            (start, point.id)
        })
        .collect::<Vec<_>>();
    source_order.sort_unstable_by_key(|(start, point)| (*start, *point));
    let ordered_points = source_order
        .iter()
        .map(|(_, point)| *point)
        .collect::<Vec<_>>();
    let mut potential = vec![Vec::new(); ordered_points.len()];
    let mut suffix = vec![ordered_points.len(); ordered_points.len()];
    let mut uncertain = vec![false; ordered_points.len()];
    // This proof is already provided by LanguageSupport and used by the
    // workspace oracle. It consumes the same exact prepared source and span;
    // the answer is memoized only for this procedure assessment.
    let inert_drops = if rust
        && semantics.gaps().iter().any(|gap| {
            gap.capability == SemanticCapability::CleanupControlFlow
                && gap.discharge == SemanticGapDischarge::InertDropGlue
        }) {
        language_support_for_hook(
            crate::analyzer::Language::Rust,
            "procedure_drops_run_no_user_code",
        )
        .is_some_and(|support| {
            support.procedure_drops_run_no_user_code(
                workspace.analyzer(),
                &ProjectFile::new(
                    workspace.analyzer().project().root().to_path_buf(),
                    procedure.artifact().key().path().as_path(),
                ),
                &std::sync::Arc::<str>::from(syntax.source()),
                procedure_node.start_byte()..procedure_node.end_byte(),
            )
        })
    } else {
        false
    };
    let macro_points = semantics
        .gaps()
        .iter()
        .filter(|gap| gap.capability == SemanticCapability::NonLocalControl)
        .map(|gap| gap.point)
        .collect::<HashSet<_>>();
    let exits = [
        semantics.normal_exit_point(),
        semantics.exceptional_exit_point(),
    ];
    for gap in semantics.gaps() {
        request
            .visit_node::<ProgramPointId>()
            .map_err(|error| execution_open_reason(workspace.analyzer(), error))?;
        if gap.discharge == SemanticGapDischarge::RetainedControlTopology
            || (!rust && gap.discharge == SemanticGapDischarge::NonRejoiningExceptionalExit)
            || !matches!(
                gap.capability,
                SemanticCapability::NormalControlFlow
                    | SemanticCapability::ExceptionalControlFlow
                    | SemanticCapability::CleanupControlFlow
                    | SemanticCapability::NonLocalControl
                    | SemanticCapability::GuardFacts
                    | SemanticCapability::SwitchFacts
            )
        {
            continue;
        }
        let origin = if gap.subject == SemanticGapSubject::Procedure {
            semantics.entry_point()
        } else {
            gap.point
        };
        let (targets, from, certain_continuation) = if !rust {
            (Vec::new(), 0, false)
        } else if macro_points.contains(&gap.point) {
            let (targets, from) = rust_structured_successors(
                semantics,
                feasible,
                syntax,
                index,
                procedure_node,
                gap.point,
                &source_order,
            )
            .unwrap_or_default();
            (targets, from, false)
        } else if gap.capability == SemanticCapability::CleanupControlFlow {
            let mut targets = feasible
                .successors(gap.point)
                .map(|(_, target)| target)
                .collect::<Vec<_>>();
            targets.extend(exits);
            (
                targets,
                ordered_points.len(),
                gap.discharge == SemanticGapDischarge::InertDropGlue && inert_drops,
            )
        } else if gap.capability == SemanticCapability::ExceptionalControlFlow
            && matches!(
                gap.subject,
                SemanticGapSubject::Point | SemanticGapSubject::Value(_)
            )
            && matches!(
                gap.discharge,
                SemanticGapDischarge::NonRejoiningExceptionalExit
                    | SemanticGapDischarge::NonRejoiningExceptionalExitAfterInertDrops
                    | SemanticGapDischarge::ExitOnlyProcedureCompletion
            )
        {
            // These typed obligations cannot rejoin Rust's ordinary body.
            // The IR has no primitive-operation event that could establish
            // certain normal completion, so the retained continuation stays
            // uncertain while MayReach adds only exit routes.
            (exits.to_vec(), ordered_points.len(), false)
        } else if matches!(
            gap.discharge,
            SemanticGapDischarge::InertDropGlue
                | SemanticGapDischarge::NonRejoiningExceptionalExitAfterInertDrops
        ) {
            // A drop obligation outside CleanupControlFlow has no reviewed
            // structured route. Keep the language default until family B
            // assigns it a typed cleanup capability.
            (Vec::new(), 0, false)
        } else if gap.capability == SemanticCapability::NormalControlFlow
            && matches!(gap.subject, SemanticGapSubject::CallSite(_))
        {
            (exits.to_vec(), ordered_points.len(), false)
        } else {
            let (targets, from) = rust_structured_successors(
                semantics,
                feasible,
                syntax,
                index,
                procedure_node,
                gap.point,
                &source_order,
            )
            .unwrap_or_default();
            (targets, from, false)
        };
        potential[origin.index()].extend(targets);
        suffix[origin.index()] = suffix[origin.index()].min(from);
        uncertain[origin.index()] |= !certain_continuation;
    }
    let complete_evidence = |id| {
        let evidence = semantics
            .evidence_row(id)
            .expect("validated control evidence");
        evidence.proof == ProofStatus::Proven
            && evidence.completeness == EvidenceCompleteness::Complete
    };
    for point in semantics.points() {
        request
            .visit_node::<ProgramPointId>()
            .map_err(|error| execution_open_reason(workspace.analyzer(), error))?;
        if !complete_evidence(point.evidence)
            || (point.id != exits[0]
                && point.id != exits[1]
                && semantics.successor_edges(point.id).len() == 0)
        {
            uncertain[point.id.index()] = true;
            if rust {
                if let Some((targets, from)) = rust_structured_successors(
                    semantics,
                    feasible,
                    syntax,
                    index,
                    procedure_node,
                    point.id,
                    &source_order,
                ) {
                    potential[point.id.index()].extend(targets);
                    suffix[point.id.index()] = suffix[point.id.index()].min(from);
                } else {
                    suffix[point.id.index()] = 0;
                }
            } else {
                suffix[point.id.index()] = 0;
            }
        }
    }
    for edge in semantics.control_edges() {
        request
            .visit_edge::<ProgramPointId>()
            .map_err(|error| execution_open_reason(workspace.analyzer(), error))?;
        if !complete_evidence(edge.evidence) {
            uncertain[edge.source_point.index()] = true;
            if rust {
                if let Some((targets, from)) = rust_structured_successors(
                    semantics,
                    feasible,
                    syntax,
                    index,
                    procedure_node,
                    edge.source_point,
                    &source_order,
                ) {
                    potential[edge.source_point.index()].extend(targets);
                    suffix[edge.source_point.index()] = suffix[edge.source_point.index()].min(from);
                } else {
                    suffix[edge.source_point.index()] = 0;
                }
            } else {
                suffix[edge.source_point.index()] = 0;
            }
        }
    }
    if cancellation.is_cancelled() {
        return Err(reason::CANCELLED);
    }
    for targets in &mut potential {
        targets.sort_unstable();
        targets.dedup();
    }
    Ok((potential, suffix, uncertain, ordered_points))
}

/// Rust has no goto. An unknown expansion can continue normally, return or
/// unwind, or break/continue any enclosing loop (including labeled loops).
/// The exit over-approximation includes every later point after each enclosing
/// loop or labeled block; this is intentionally wider than its exact next site.
fn rust_structured_successors(
    semantics: &ProcedureSemantics,
    feasible: &FeasibleSuccessors<'_, ProcedureSemantics>,
    syntax: &PreparedSyntaxTree,
    index: &StatementEntryIndex,
    procedure_node: Node<'_>,
    origin: ProgramPointId,
    source_order: &[(usize, ProgramPointId)],
) -> Option<(Vec<ProgramPointId>, usize)> {
    let point = semantics.points().get(origin.index())?;
    let mapping = semantics.source_mapping(point.source)?;
    let span = mapping.locator.anchor().span();
    if mapping.kind != SourceMappingKind::Exact {
        return None;
    }
    let mut node = syntax
        .tree()
        .root_node()
        .named_descendant_for_byte_range(span.start_byte() as usize, span.end_byte() as usize)?;
    // A potential continuation may use retained feasible edges, but must not
    // reintroduce a literal or wildcard failure edge pruned for both walks.
    let mut targets = feasible
        .successors(origin)
        .map(|(_, target)| target)
        .collect::<Vec<_>>();
    targets.extend([
        semantics.normal_exit_point(),
        semantics.exceptional_exit_point(),
    ]);
    // A retained boundary can omit its ordinary edge entirely (for example
    // an unsupported `try {}` expression). Find the next statement in the
    // enclosing block, rather than jumping over intervening return/break.
    let mut normal_successor_found = false;
    let mut normal_successor_blocked = false;
    let mut suffix = source_order.len();
    loop {
        if node.has_error() {
            return None;
        }
        if matches!(
            node.kind(),
            "function_item" | "closure_expression" | "async_block" | "gen_block"
        ) {
            // A nested body has its own control domain. Its return must not
            // suppress a continuation in the enclosing procedure.
            if node.id() != procedure_node.id() {
                return None;
            }
            break;
        }
        let loop_node = matches!(
            node.kind(),
            "loop_expression" | "while_expression" | "for_expression"
        );
        // tree-sitter-rust puts a block label directly among the block's
        // named children; there is no `labeled_expression` wrapper.
        let labeled_block = node.kind() == "block" && {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .any(|child| child.kind() == "label")
        };
        if loop_node || labeled_block {
            let loop_span = source_span_for_node(node);
            if loop_node {
                let mut found_header = false;
                for site in semantics.loop_sites() {
                    let Some(site_mapping) = semantics.source_mapping(site.source) else {
                        continue;
                    };
                    if site_mapping.locator.anchor().span() == loop_span {
                        targets.push(site.header);
                        found_header = true;
                    }
                }
                if !found_header {
                    return None;
                }
            }
            // A macro can break out of this loop or labeled block. Include
            // points after it even if the next statement lacks an entry.
            suffix = suffix.min(
                source_order.partition_point(|(start, _)| *start < loop_span.end_byte() as usize),
            );
        }
        let Some(parent) = node.parent() else {
            break;
        };
        let transfers_control = |kind| {
            matches!(
                kind,
                "return_expression" | "break_expression" | "continue_expression"
            )
        };
        if transfers_control(node.kind())
            || (node.kind() == "expression_statement"
                && node
                    .named_child(0)
                    .is_some_and(|child| transfers_control(child.kind())))
        {
            normal_successor_blocked = true;
        }
        if parent.kind() == "block" && !normal_successor_found && !normal_successor_blocked {
            // Tree-sitter extras and Rust attributes have no control entry.
            // A trailing comment on an unreachable statement must not turn
            // its bounded continuation into a procedure-wide fallback.
            let mut next = node.next_named_sibling();
            while next
                .is_some_and(|sibling| sibling.is_extra() || sibling.kind() == "attribute_item")
            {
                next = next.and_then(|sibling| sibling.next_named_sibling());
            }
            if let Some(next) = next {
                let Ok(entries) = index.at_span(source_span_for_node(next)) else {
                    return None;
                };
                targets.extend_from_slice(entries);
                normal_successor_found = true;
            }
        }
        node = parent;
    }
    Some((targets, suffix))
}

/// Classify the typed refusal before its public row erases it to a label.
fn execution_open_reason(
    analyzer: &dyn crate::analyzer::IAnalyzer,
    error: crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmError<ProgramPointId>,
) -> &'static str {
    let cause = crate::analyzer::read_ledger::DerivationExecutionCause::from_cfg_error(&error);
    brokk_bifrost_core::profiling::note_with(|| {
        format!(
            "policy.units unbounded origin={}:{} cause=cfg:{cause:?} detail={error:?}",
            file!(),
            line!()
        )
    });
    analyzer.mark_execution_dependent();
    algorithm_open_reason(error)
}

#[derive(Debug)]
pub struct AccountedStatementAssessments(pub StatementAssessments);
impl std::ops::Deref for AccountedStatementAssessments {
    type Target = StatementAssessments;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl brokk_bifrost_core::retention_budget::RetainedBytes for AccountedStatementAssessments {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<StatementAssessments>()
            + self.0.rows.capacity() * std::mem::size_of::<StatementAssessment>()
    }
}

#[cfg(test)]
pub(crate) mod tests {}
