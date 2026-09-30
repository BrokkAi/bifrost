//! Exact prepared-Java loop sites for procedure-local control proofs.

use crate::CancellationToken;
use crate::analyzer::semantic::type_flow::validate_prepared_syntax_source_for_procedure;
use crate::analyzer::semantic::{ProcedureHandle, SourceMappingKind, SourcePosition, SourceSpan};
use crate::analyzer::structural::provider::StructuralSyntaxLimitedOutcome;
use crate::analyzer::{Language, ProjectFile, Range, WorkspaceAnalyzer};
use crate::text_utils::{compute_line_starts, line_column_for_offset};
use tree_sitter::Node;

const MAX_SOURCE_BYTES: usize = 1_048_576;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JavaLoopKind {
    While,
    For,
    Do,
}

#[derive(Debug, Clone, Copy)]
pub struct JavaLoopSite {
    pub kind: JavaLoopKind,
    pub loop_span: SourceSpan,
    pub body_span: SourceSpan,
    pub condition_span: Option<SourceSpan>,
}

#[derive(Debug, Clone)]
pub struct JavaLoopCandidate {
    pub range: Range,
    pub coordinates: JavaLoopCoordinates,
    pub body_coordinates: Option<JavaLoopCoordinates>,
    pub kind: JavaLoopKind,
    pub site: Option<JavaLoopSite>,
    pub reason: Option<&'static str>,
}

#[derive(Debug, Clone, Copy)]
pub struct JavaLoopCoordinates {
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

#[derive(Debug, Clone)]
pub struct JavaLoopCandidates {
    pub rows: Vec<JavaLoopCandidate>,
    pub complete: bool,
    pub reason: Option<&'static str>,
}

fn unavailable(reason: &'static str) -> JavaLoopCandidates {
    JavaLoopCandidates {
        rows: Vec::new(),
        complete: false,
        reason: Some(reason),
    }
}

/// Collect only loops owned by this exact semantic procedure. Nested callable
/// bodies have separate semantic owners and are never attributed to the outer
/// procedure. The prepared tree is validated against the artifact snapshot.
pub fn java_loop_candidates(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    cancellation: Option<&CancellationToken>,
) -> JavaLoopCandidates {
    if procedure.artifact().key().language().language() != Language::Java {
        return unavailable("unsupported_language");
    }
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return unavailable("cancelled");
    }
    let file = ProjectFile::new(
        workspace.analyzer().project().root().to_path_buf(),
        procedure.artifact().key().path().as_path(),
    );
    let syntax = workspace
        .analyzer()
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == Language::Java)
        .map(|provider| provider.structural_syntax_limited(&file, MAX_SOURCE_BYTES, cancellation));
    let syntax = match syntax {
        Some(StructuralSyntaxLimitedOutcome::Available(syntax)) => syntax,
        Some(StructuralSyntaxLimitedOutcome::Exceeded { .. }) => {
            return unavailable("source_budget_exhausted");
        }
        Some(StructuralSyntaxLimitedOutcome::Cancelled) => return unavailable("cancelled"),
        Some(StructuralSyntaxLimitedOutcome::Unavailable) | None => {
            return unavailable("prepared_syntax_unavailable");
        }
    };
    let Ok(syntax) = validate_prepared_syntax_source_for_procedure(
        workspace,
        procedure,
        &file,
        syntax.into_inner(),
    ) else {
        return unavailable("source_identity_mismatch");
    };
    let semantics = procedure.semantics();
    let Some(mapping) = semantics.source_mapping(semantics.source()) else {
        return unavailable("procedure_mapping_missing");
    };
    if mapping.kind != SourceMappingKind::Exact {
        return unavailable("procedure_mapping_inexact");
    }
    let span = mapping.locator.anchor().span();
    let Some(procedure_node) = syntax
        .tree()
        .root_node()
        .named_descendant_for_byte_range(span.start_byte() as usize, span.end_byte() as usize)
    else {
        return unavailable("procedure_syntax_missing");
    };
    if procedure_node.start_byte() != span.start_byte() as usize
        || procedure_node.end_byte() != span.end_byte() as usize
        || procedure_node.has_error()
    {
        return unavailable("procedure_syntax_inexact");
    }
    let mut rows = Vec::new();
    let line_starts = compute_line_starts(syntax.source());
    let mut stack = vec![procedure_node];
    while let Some(node) = stack.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return unavailable("cancelled");
        }
        if node.id() != procedure_node.id()
            && matches!(
                node.kind(),
                "method_declaration"
                    | "constructor_declaration"
                    | "lambda_expression"
                    | "class_declaration"
                    | "class_body"
            )
        {
            continue;
        }
        let kind = match node.kind() {
            "while_statement" => Some(JavaLoopKind::While),
            "for_statement" => Some(JavaLoopKind::For),
            "do_statement" => Some(JavaLoopKind::Do),
            _ => None,
        };
        if let Some(kind) = kind {
            let body = node.child_by_field_name("body");
            let condition = node.child_by_field_name("condition");
            let reason = if node.has_error() {
                Some("syntax_recovery")
            } else if body.is_none() {
                Some("body_field_missing")
            } else if kind != JavaLoopKind::For && condition.is_none() {
                Some("condition_field_missing")
            } else {
                None
            };
            rows.push(JavaLoopCandidate {
                range: node_range(node),
                coordinates: node_coordinates(node, syntax.source(), &line_starts),
                body_coordinates: body
                    .map(|body| node_coordinates(body, syntax.source(), &line_starts)),
                kind,
                site: if reason.is_none() {
                    Some(JavaLoopSite {
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
    JavaLoopCandidates {
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

fn node_coordinates(node: Node<'_>, source: &str, line_starts: &[usize]) -> JavaLoopCoordinates {
    let (start_line, start_column) = line_column_for_offset(source, line_starts, node.start_byte());
    let (end_line, end_column) = line_column_for_offset(source, line_starts, node.end_byte());
    JavaLoopCoordinates {
        start_line,
        start_column,
        end_line,
        end_column,
    }
}
