//! Query-local pending-transfer flow through lowered cleanup regions.
//!
//! A cleanup edge is the semantic producer's structured hand-off into a
//! finally/ensure/defer/using/with body. This module never searches source
//! text. It uses the edge and point selected by the semantic artifact, then
//! asks tree-sitter for the AST node at that already-selected source span so
//! the row can name the cleanup and the explicit abrupt statement inside it.

use super::results::{
    CodeQueryPendingCleanupFlow, CodeQueryProgramPointRef, CodeQueryRange, CodeQueryResultRef,
    DetailedCodeQueryKey,
};
use super::semantic::SemanticProcedureValue;
use super::*;
use crate::analyzer::common::language_for_file;
use crate::analyzer::semantic::LengthDelimitedDigest;
use crate::analyzer::usages::get_definition::parse_tree_for_language;
use crate::analyzer::{ProjectFile, Range};
use crate::cancellation::CancellationToken;
use crate::hash::HashSet;
use brokk_bifrost_analysis::analyzer::semantic::{ControlEdgeKind, ProgramPointId, SemanticEffect};
use tree_sitter::Node;

const PENDING_CLEANUP_FLOW_ID_DOMAIN: &[u8] = b"bifrost.code_query.pending_cleanup_flow.v1";
const MAX_CLEANUP_WALK_POINTS: usize = 50_000;

#[derive(Debug, Clone)]
pub(super) struct PendingCleanupFlowValue {
    pub(super) file: ProjectFile,
    pub(super) anchor: Range,
    pub(super) row: CodeQueryPendingCleanupFlow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CleanupKind {
    Finally,
    Ensure,
    Defer,
    Using,
    With,
    RaiiDrop,
}

impl CleanupKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Finally => "finally",
            Self::Ensure => "ensure",
            Self::Defer => "defer",
            Self::Using => "using",
            Self::With => "with",
            Self::RaiiDrop => "raii_drop",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum PendingKind {
    Return,
    Throw,
    Break,
    Continue,
}

impl PendingKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Return => "return",
            Self::Throw => "throw",
            Self::Break => "break",
            Self::Continue => "continue",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CleanupOutcome {
    Preserves(ProgramPointId),
    Overrides(ProgramPointId, PendingKind),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CleanupPathOutcome {
    Preserve(ProgramPointId),
    Override(ProgramPointId, PendingKind),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PendingCleanupEdge {
    source: ProgramPointId,
    target: ProgramPointId,
    origin: ProgramPointId,
    pending_kind: PendingKind,
}

#[derive(Debug)]
struct CleanupAnalysis {
    outcome: CleanupOutcome,
    transitions: Vec<PendingCleanupEdge>,
}

fn source_range(
    procedure: &brokk_bifrost_analysis::analyzer::semantic::ProcedureSemantics,
    point: ProgramPointId,
) -> Option<(usize, usize)> {
    let point = procedure.point(point)?;
    let mapping = procedure.source_mapping(point.source)?;
    let span = mapping.locator.anchor().span();
    Some((span.start_byte() as usize, span.end_byte() as usize))
}

fn source_node<'tree>(root: Node<'tree>, start: usize, end: usize) -> Option<Node<'tree>> {
    let end = end.max(start.saturating_add(1));
    root.descendant_for_byte_range(start, end)
}

fn cleanup_kind_direct(node: Node<'_>) -> Option<CleanupKind> {
    match node.kind() {
        "finally_clause" | "finally_block" | "finally" => Some(CleanupKind::Finally),
        "ensure" | "ensure_clause" => Some(CleanupKind::Ensure),
        "defer_statement" => Some(CleanupKind::Defer),
        "using_statement"
        | "using_declaration"
        | "try_with_resources_statement"
        | "resource_specification"
        | "use_statement" => Some(CleanupKind::Using),
        "with_statement" | "with_clause" | "with_block" => Some(CleanupKind::With),
        "drop_expression" | "destructor" | "destructor_declaration" | "scope_exit" => {
            Some(CleanupKind::RaiiDrop)
        }
        _ => None,
    }
}

fn cleanup_kind(node: Node<'_>) -> Option<CleanupKind> {
    let mut current = Some(node);
    while let Some(node) = current {
        let result = cleanup_kind_direct(node);
        if result.is_some() {
            return result;
        }
        current = node.parent();
    }
    None
}

fn pending_kind_from_node(node: Node<'_>) -> Option<PendingKind> {
    let mut current = Some(node);
    while let Some(node) = current {
        let kind = node.kind();
        let result = match kind {
            "return_statement" | "return" | "return_expression" => Some(PendingKind::Return),
            "throw_statement" | "throw_expression" | "throw" | "raise_statement" | "raise" => {
                Some(PendingKind::Throw)
            }
            "break_statement" | "break_expression" | "break" => Some(PendingKind::Break),
            "continue_statement"
            | "continue_expression"
            | "continue"
            | "next"
            | "redo"
            | "retry" => Some(PendingKind::Continue),
            _ => None,
        };
        if result.is_some() {
            return result;
        }
        current = node.parent();
    }
    None
}

fn pending_kind(
    procedure: &brokk_bifrost_analysis::analyzer::semantic::ProcedureSemantics,
    point: ProgramPointId,
    root: Option<Node<'_>>,
    source: Option<(usize, usize)>,
) -> Option<PendingKind> {
    let point_row = procedure.point(point)?;
    for event in &point_row.events {
        match event.effect {
            SemanticEffect::ProcedureReturn { .. } => return Some(PendingKind::Return),
            SemanticEffect::Throw { .. } => return Some(PendingKind::Throw),
            _ => {}
        }
    }
    let (root, (start, end)) = (root?, source?);
    pending_kind_from_node(source_node(root, start, end)?)
}

fn has_gap(
    procedure: &brokk_bifrost_analysis::analyzer::semantic::ProcedureSemantics,
    point: ProgramPointId,
) -> bool {
    procedure.point(point).is_some_and(|point| {
        point
            .events
            .iter()
            .any(|event| matches!(event.effect, SemanticEffect::Gap { .. }))
    })
}

fn cleanup_outcome(
    procedure: &brokk_bifrost_analysis::analyzer::semantic::ProcedureSemantics,
    entry: ProgramPointId,
    cleanup_span: (usize, usize),
    origin: ProgramPointId,
    incoming_kind: PendingKind,
    root: Option<Node<'_>>,
    cancellation: Option<&CancellationToken>,
) -> CleanupAnalysis {
    let mut pending = vec![entry];
    let mut seen = HashSet::default();
    let mut outcomes = Vec::new();
    let mut transitions = Vec::new();
    let mut steps = 0_usize;
    while let Some(point) = pending.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return CleanupAnalysis {
                outcome: CleanupOutcome::Unknown,
                transitions,
            };
        }
        steps = steps.saturating_add(1);
        if steps > MAX_CLEANUP_WALK_POINTS || !seen.insert(point) {
            if steps > MAX_CLEANUP_WALK_POINTS {
                return CleanupAnalysis {
                    outcome: CleanupOutcome::Unknown,
                    transitions,
                };
            }
            continue;
        }
        if has_gap(procedure, point) {
            outcomes.push(CleanupPathOutcome::Unknown);
            continue;
        }
        let point_source = source_range(procedure, point);
        if let Some(kind) = pending_kind(procedure, point, root, point_source) {
            outcomes.push(CleanupPathOutcome::Override(point, kind));
            for (_, edge) in procedure.successor_edges(point) {
                if edge.kind == ControlEdgeKind::Cleanup {
                    transitions.push(PendingCleanupEdge {
                        source: point,
                        target: edge.target_point,
                        origin: point,
                        pending_kind: kind,
                    });
                }
            }
            continue;
        }
        let mut successors = procedure.successor_edges(point).peekable();
        if successors.peek().is_none() {
            outcomes.push(CleanupPathOutcome::Unknown);
            continue;
        }
        for (_, edge) in successors {
            if edge.kind == ControlEdgeKind::Cleanup {
                let target_inside_cleanup = source_range(procedure, edge.target_point)
                    .is_some_and(|(start, end)| start >= cleanup_span.0 && end <= cleanup_span.1);
                transitions.push(PendingCleanupEdge {
                    source: point,
                    target: edge.target_point,
                    origin,
                    pending_kind: incoming_kind,
                });
                if target_inside_cleanup {
                    // A cleanup edge whose selected body is nested inside
                    // this cleanup is still part of this cleanup's execution
                    // path. Walk it locally so an inner override affects the
                    // outer verdict; the transition also publishes the inner
                    // cleanup as its own row.
                    pending.push(edge.target_point);
                } else {
                    outcomes.push(CleanupPathOutcome::Preserve(edge.target_point));
                }
                continue;
            }
            if edge.target_point == procedure.normal_exit_point()
                || edge.target_point == procedure.exceptional_exit_point()
            {
                outcomes.push(CleanupPathOutcome::Preserve(edge.target_point));
                continue;
            }
            let Some(target_source) = source_range(procedure, edge.target_point) else {
                outcomes.push(CleanupPathOutcome::Unknown);
                continue;
            };
            if target_source.0 >= cleanup_span.0 && target_source.1 <= cleanup_span.1 {
                pending.push(edge.target_point);
            } else {
                // The shared lowering uses a relay or an outer destination
                // after normal cleanup completion. A point outside the
                // selected body is therefore preservation, unless the path
                // itself carried an explicit abrupt effect (handled above).
                outcomes.push(CleanupPathOutcome::Preserve(edge.target_point));
            }
        }
    }

    if outcomes.is_empty() {
        return CleanupAnalysis {
            outcome: CleanupOutcome::Unknown,
            transitions,
        };
    }
    let mut preserve_target = None;
    let mut override_target = None;
    let mut override_kind = None;
    let mut unknown = false;
    for outcome in outcomes {
        match outcome {
            CleanupPathOutcome::Preserve(target) => {
                preserve_target.get_or_insert(target);
            }
            CleanupPathOutcome::Override(target, kind) => {
                override_target.get_or_insert(target);
                override_kind.get_or_insert(kind);
            }
            CleanupPathOutcome::Unknown => unknown = true,
        };
    }
    if unknown || (preserve_target.is_some() && override_target.is_some()) {
        return CleanupAnalysis {
            outcome: CleanupOutcome::Unknown,
            transitions,
        };
    }
    if let (Some(target), Some(kind)) = (override_target, override_kind) {
        return CleanupAnalysis {
            outcome: CleanupOutcome::Overrides(target, kind),
            transitions,
        };
    }
    CleanupAnalysis {
        outcome: preserve_target.map_or(CleanupOutcome::Unknown, CleanupOutcome::Preserves),
        transitions,
    }
}

fn public_range(
    procedure: &SemanticProcedureValue,
    point: ProgramPointId,
) -> Option<CodeQueryRange> {
    procedure
        .point_value(point)
        .map(|point| point.public().range)
}

fn public_ref(
    procedure: &SemanticProcedureValue,
    point: ProgramPointId,
) -> Option<CodeQueryProgramPointRef> {
    procedure.point_value(point).map(|point| point.point_ref())
}

fn diagnostic(
    procedure: &SemanticProcedureValue,
    reason: &str,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) {
    diagnostics.push(CodeQueryDiagnostic {
        related: Vec::new(),
        source: None,
        code: CodeQueryDiagnosticCode::PendingCleanupFlowDerivationIncomplete,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: language_for_file(procedure.file()).config_label(),
        message: format!(
            "{} pending cleanup flow is incomplete: {reason}",
            procedure.wire_id()
        ),
        exhausted_roots: Vec::new(),
        withheld_rows_path: None,
    });
}

fn row(
    procedure: &SemanticProcedureValue,
    pending_origin: ProgramPointId,
    cleanup_entry: ProgramPointId,
    cleanup_kind: CleanupKind,
    pending_kind: PendingKind,
    outcome: CleanupOutcome,
    reason: Option<String>,
) -> Option<PipelineExpansion> {
    let source = public_ref(procedure, pending_origin)?;
    let target = public_ref(procedure, cleanup_entry)?;
    let range = public_range(procedure, cleanup_entry)?;
    let (start_byte, end_byte) = source_range(procedure.handle.semantics(), cleanup_entry)?;
    let procedure_id = procedure.wire_id();
    let cleanup_id = target.id.clone();
    let mut digest = LengthDelimitedDigest::new(PENDING_CLEANUP_FLOW_ID_DOMAIN);
    digest.push(procedure_id.as_bytes());
    digest.push(cleanup_id.as_bytes());
    digest.push(source.id.as_bytes());
    digest.push(pending_kind.label().as_bytes());
    let (verdict, proof, coverage) = match outcome {
        CleanupOutcome::Preserves(_) | CleanupOutcome::Overrides(_, _) if reason.is_none() => {
            let verdict = if matches!(outcome, CleanupOutcome::Overrides(_, _)) {
                "overrides"
            } else {
                "preserves"
            };
            (verdict, "exact", "exhaustive")
        }
        _ => ("unknown", "unknown", "incomplete"),
    };
    Some(pipeline_expansion(PipelineValue::PendingCleanupFlow(
        Box::new(PendingCleanupFlowValue {
            file: procedure.file().clone(),
            anchor: Range {
                start_byte,
                end_byte,
                start_line: range.start_line,
                end_line: range.end_line,
            },
            row: CodeQueryPendingCleanupFlow {
                id: digest.finish().to_string(),
                procedure_id,
                path: source.path.clone(),
                language: language_for_file(procedure.file()).config_label(),
                range,
                cleanup_id,
                cleanup_kind: cleanup_kind.label(),
                pending_kind: pending_kind.label(),
                source,
                target,
                verdict,
                proof,
                coverage,
                reason,
            },
        }),
    )))
}

pub(super) fn detailed_key(value: &PendingCleanupFlowValue) -> DetailedCodeQueryKey {
    DetailedCodeQueryKey::PendingCleanupFlow {
        id: value.row.id.clone(),
        procedure_id: value.row.procedure_id.clone(),
    }
}

pub(super) fn result_ref(value: &PendingCleanupFlowValue) -> CodeQueryResultRef {
    CodeQueryResultRef::PendingCleanupFlow {
        id: value.row.id.clone(),
        path: value.row.path.clone(),
        range: value.row.range,
        procedure_id: value.row.procedure_id.clone(),
        cleanup_kind: value.row.cleanup_kind,
        pending_kind: value.row.pending_kind,
        verdict: value.row.verdict,
    }
}

pub(super) fn pending_cleanup_flow_expansions(
    procedure: &SemanticProcedureValue,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    let language = language_for_file(procedure.file());
    let tree = parse_tree_for_language(procedure.file(), language, procedure.source_text());
    let root = tree.as_ref().map(|tree| tree.root_node());
    let semantics = procedure.handle.semantics();
    let mut rows = Vec::new();
    let mut semantic_cleanup_spans = Vec::new();
    let procedure_span = procedure.byte_span();
    let syntax_cleanup_spans = root.map(|root| {
        let mut spans = Vec::new();
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if node.start_byte() >= procedure_span.start
                && node.end_byte() <= procedure_span.end
                && let Some(kind) = cleanup_kind_direct(node)
            {
                spans.push((kind, node.start_byte(), node.end_byte()));
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        spans
    });
    let mut pending_edges = Vec::new();
    let mut seen_pending_edges = HashSet::default();
    let mut direct_cleanup_edges = 0_usize;
    for edge in semantics
        .control_edges()
        .iter()
        .filter(|edge| edge.kind == ControlEdgeKind::Cleanup)
    {
        direct_cleanup_edges = direct_cleanup_edges.saturating_add(1);
        let Some((cleanup_start, cleanup_end)) = source_range(semantics, edge.target_point) else {
            diagnostic(procedure, "cleanup_source_mapping_missing", diagnostics);
            continue;
        };
        let Some(root) = root else {
            diagnostic(procedure, "syntax_unavailable", diagnostics);
            continue;
        };
        let Some(cleanup_kind) =
            cleanup_kind(source_node(root, cleanup_start, cleanup_end).unwrap_or(root))
        else {
            diagnostic(procedure, "cleanup_kind_unrecognized", diagnostics);
            continue;
        };
        semantic_cleanup_spans.push((cleanup_kind, cleanup_start, cleanup_end));
        let Some(pending_source) = source_range(semantics, edge.source_point) else {
            continue;
        };
        let Some(pending_kind) = pending_kind(
            semantics,
            edge.source_point,
            Some(root),
            Some(pending_source),
        ) else {
            continue;
        };
        let pending_edge = PendingCleanupEdge {
            source: edge.source_point,
            target: edge.target_point,
            origin: edge.source_point,
            pending_kind,
        };
        if seen_pending_edges.insert(pending_edge) {
            pending_edges.push(pending_edge);
        }
    }

    if direct_cleanup_edges == 0 {
        if let Some(syntax_cleanup_spans) = syntax_cleanup_spans
            && !syntax_cleanup_spans.is_empty()
        {
            diagnostic(procedure, "cleanup_semantics_unpublished", diagnostics);
        }
        return rows;
    }

    let mut processed_edges = 0_usize;
    while let Some(pending_edge) = pending_edges.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            diagnostic(procedure, "cancelled", diagnostics);
            break;
        }
        processed_edges = processed_edges.saturating_add(1);
        if processed_edges > MAX_CLEANUP_WALK_POINTS {
            diagnostic(
                procedure,
                "pending_cleanup_state_budget_exhausted",
                diagnostics,
            );
            break;
        }
        let Some(root) = root else {
            diagnostic(procedure, "syntax_unavailable", diagnostics);
            break;
        };
        let Some((cleanup_start, cleanup_end)) = source_range(semantics, pending_edge.target)
        else {
            diagnostic(procedure, "cleanup_source_mapping_missing", diagnostics);
            continue;
        };
        let Some(cleanup_kind) =
            cleanup_kind(source_node(root, cleanup_start, cleanup_end).unwrap_or(root))
        else {
            diagnostic(procedure, "cleanup_kind_unrecognized", diagnostics);
            continue;
        };
        let analysis = cleanup_outcome(
            semantics,
            pending_edge.target,
            (cleanup_start, cleanup_end),
            pending_edge.origin,
            pending_edge.pending_kind,
            Some(root),
            cancellation,
        );
        let mut reason = None;
        let exact_selection_incomplete = procedure.exact_selection_incomplete_reason().is_some();
        let mut outcome = analysis.outcome;
        if exact_selection_incomplete {
            reason = Some("procedure_semantic_quality_incomplete".to_owned());
            outcome = CleanupOutcome::Unknown;
        }
        if matches!(outcome, CleanupOutcome::Unknown) {
            reason = reason.or_else(|| Some("cleanup_outcome_unproven".to_owned()));
        }
        if let Some(expansion) = row(
            procedure,
            pending_edge.origin,
            pending_edge.target,
            cleanup_kind,
            pending_edge.pending_kind,
            outcome,
            reason,
        ) {
            rows.push(expansion);
        }
        if exact_selection_incomplete || matches!(outcome, CleanupOutcome::Unknown) {
            continue;
        }
        for transition in analysis.transitions {
            if seen_pending_edges.insert(transition) {
                pending_edges.push(transition);
            }
        }
    }
    if let Some(syntax_cleanup_spans) = syntax_cleanup_spans {
        for (kind, start, end) in syntax_cleanup_spans {
            let has_semantic_edge = semantic_cleanup_spans.iter().any(
                |(semantic_kind, semantic_start, semantic_end)| {
                    *semantic_kind == kind && start < *semantic_end && *semantic_start < end
                },
            );
            if !has_semantic_edge {
                diagnostic(procedure, "cleanup_semantics_unpublished", diagnostics);
            }
        }
    }
    rows
}
