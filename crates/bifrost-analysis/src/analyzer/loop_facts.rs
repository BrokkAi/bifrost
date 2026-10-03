//! Exact prepared-source loop sites for procedure-local control proofs.

use crate::CancellationToken;
use crate::analyzer::Range;
use crate::analyzer::WorkspaceAnalyzer;
use crate::analyzer::semantic::statement_entries::ProcedureSyntax;
use crate::analyzer::semantic::{ProcedureHandle, SourcePosition, SourceSpan};
use crate::text_utils::{compute_line_starts, line_column_for_offset};
use tree_sitter::Node;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopKind {
    While,
    For,
    Do,
}

/// One conditional loop's syntax as its language classifies it. A missing
/// field is recovery, reported by the enumerator; a `for` may have no
/// condition.
#[derive(Debug, Clone, Copy)]
pub struct LoopSyntax<'tree> {
    pub kind: LoopKind,
    pub body: Option<Node<'tree>>,
    pub condition: Option<Node<'tree>>,
}

#[derive(Debug, Clone, Copy)]
pub struct LoopSite {
    pub kind: LoopKind,
    pub loop_span: SourceSpan,
    pub body_span: SourceSpan,
    pub condition_span: Option<SourceSpan>,
}

#[derive(Debug, Clone)]
pub struct LoopCandidate {
    pub range: Range,
    pub coordinates: LoopCoordinates,
    pub body_coordinates: Option<LoopCoordinates>,
    pub kind: LoopKind,
    pub site: Option<LoopSite>,
    pub reason: Option<&'static str>,
}

#[derive(Debug, Clone, Copy)]
pub struct LoopCoordinates {
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

#[derive(Debug, Clone)]
pub struct LoopCandidates {
    pub rows: Vec<LoopCandidate>,
    pub complete: bool,
    pub reason: Option<&'static str>,
}

fn unavailable(reason: &'static str) -> LoopCandidates {
    LoopCandidates {
        rows: Vec::new(),
        complete: false,
        reason: Some(reason),
    }
}

/// Collect only loops owned by this exact semantic procedure. Nested callable
/// bodies have separate semantic owners and are never attributed to the outer
/// procedure. The prepared tree is validated against the artifact snapshot.
pub fn loop_candidates(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    cancellation: Option<&CancellationToken>,
) -> LoopCandidates {
    let prepared = match ProcedureSyntax::prepare(workspace, procedure, cancellation) {
        Ok(prepared) => prepared,
        Err(reason) => return unavailable(reason),
    };
    let procedure_node = match prepared.procedure_node(procedure) {
        Ok(node) => node,
        Err(reason) => return unavailable(reason),
    };
    let source = prepared.syntax.source();
    let roles = prepared.roles;
    let mut rows = Vec::new();
    let line_starts = compute_line_starts(source);
    let mut stack = vec![procedure_node];
    while let Some(node) = stack.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return unavailable("cancelled");
        }
        if node.id() != procedure_node.id() && (roles.nested_procedure)(node) {
            continue;
        }
        if let Some(LoopSyntax {
            kind,
            body,
            condition,
        }) = (roles.loop_site)(node)
        {
            let reason = if node.has_error() {
                Some("syntax_recovery")
            } else if body.is_none() {
                Some("body_field_missing")
            } else if kind != LoopKind::For && condition.is_none() {
                Some("condition_field_missing")
            } else {
                None
            };
            rows.push(LoopCandidate {
                range: node_range(node),
                coordinates: node_coordinates(node, source, &line_starts),
                body_coordinates: body.map(|body| node_coordinates(body, source, &line_starts)),
                kind,
                site: if reason.is_none() {
                    Some(LoopSite {
                        kind,
                        loop_span: node_span(node),
                        body_span: node_span(body.expect("checked body field")),
                        condition_span: condition.map(node_span),
                    })
                } else {
                    None
                },
                reason,
            });
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    rows.sort_unstable_by_key(|row| row.range.start_byte);
    LoopCandidates {
        rows,
        complete: true,
        reason: None,
    }
}

fn node_span(node: Node<'_>) -> SourceSpan {
    let position = |byte: usize, point: tree_sitter::Point| {
        SourcePosition::new(byte as u32, point.row as u32, point.column as u32)
    };
    SourceSpan::new(
        position(node.start_byte(), node.start_position()),
        position(node.end_byte(), node.end_position()),
    )
    .expect("tree-sitter node has ordered source positions")
}

fn node_range(node: Node<'_>) -> Range {
    Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row + 1,
        end_line: node.end_position().row + 1,
    }
}

fn node_coordinates(node: Node<'_>, source: &str, line_starts: &[usize]) -> LoopCoordinates {
    let (start_line, start_column) = line_column_for_offset(source, line_starts, node.start_byte());
    let (end_line, end_column) = line_column_for_offset(source, line_starts, node.end_byte());
    LoopCoordinates {
        start_line,
        start_column,
        end_line,
        end_column,
    }
}
