//! Exact source statement entries from one immutable procedure artifact.
//!
//! A query must enumerate executable syntax from a prepared tree before asking
//! for an entry. A missing producer site for such syntax is open coverage, not
//! evidence that the statement is unreachable.

use crate::analyzer::languages::ProcedureSyntaxRoles;
use crate::analyzer::languages::language_support_for_hook;
use crate::analyzer::read_ledger::reason as derivation_reason;
use crate::analyzer::semantic::cfg_algorithms::{
    CfgAlgorithmBudget, CfgAlgorithmRequest, forward_reachability,
};

use crate::analyzer::semantic::type_flow::{
    source_span_for_node, validate_prepared_syntax_source_for_procedure,
};

use crate::analyzer::semantic::{
    ProcedureHandle, ProgramPointId, SemanticRole, SourceMappingKind, SourceSpan,
};

use crate::analyzer::structural::provider::StructuralSyntaxLimitedOutcome;
use crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree;
use crate::analyzer::{ProjectFile, WorkspaceAnalyzer};
use crate::cancellation::CancellationToken;
use crate::hash::HashMap;
use crate::text_utils::{compute_line_starts, line_column_for_offset};
use brokk_bifrost_core::analyzer::tree_walk::node_range;
pub use brokk_bifrost_semantic::analyzer::semantic::statement_entries::*;
use tree_sitter::Node;
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
                },
            ));
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    let uncancelled = CancellationToken::new();
    let mut budget = CfgAlgorithmBudget::default();
    let mut request = CfgAlgorithmRequest::new(&mut budget, cancellation.unwrap_or(&uncancelled));
    let reachable = forward_reachability(semantics, semantics.entry_point(), &mut request);
    let control_open = match &reachable {
        Err(error) => Some(execution_open_reason(workspace.analyzer(), *error)),
        Ok(reachable) => match scan_control_evidence(semantics, reachable, &mut request) {
            Ok(reason) => reason,
            Err(error) => Some(execution_open_reason(workspace.analyzer(), error)),
        },
    };
    let mut rows = Vec::with_capacity(candidates.len());
    for (span, malformed, mut row) in candidates {
        if let Err(error) = request.visit_node::<ProgramPointId>() {
            return unavailable(execution_open_reason(workspace.analyzer(), error));
        }
        if !malformed {
            row.verdict = if span_counts[&span] != 1 {
                StatementVerdict::Open(derivation_reason::AMBIGUOUS_STATEMENT_SPAN)
            } else if let Some(reason) = control_open {
                StatementVerdict::Open(reason)
            } else {
                match index.at_span(span) {
                    Err(StatementEntryOpen::MissingProducerSite) => {
                        StatementVerdict::Open(derivation_reason::MISSING_STATEMENT_ENTRY)
                    }
                    Err(StatementEntryOpen::SourceSnapshotMismatch) => {
                        StatementVerdict::Open(derivation_reason::SOURCE_IDENTITY_MISMATCH)
                    }
                    Ok(entries) => {
                        let reachable = reachable.as_ref().expect("complete control proof");
                        if entries
                            .iter()
                            .any(|point| reachable.contains(semantics, *point))
                        {
                            StatementVerdict::Reachable
                        } else {
                            StatementVerdict::Unreachable
                        }
                    }
                }
            };
        }
        rows.push(row);
    }
    rows.sort_unstable_by_key(|row| (row.range.start_byte, row.range.end_byte));
    StatementAssessments {
        rows,
        complete: true,
        reason: None,
    }
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

#[cfg(test)]
pub(crate) mod tests {}
