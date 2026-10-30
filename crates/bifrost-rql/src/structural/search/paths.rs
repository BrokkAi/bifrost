//! The execution adapter between the query engine and the qualified-path
//! producer (#1475, Milestone 4).
//!
//! Two row families arrive here: qualified paths and their segments, from the
//! per-file derivation in `structural::qualified_paths`. They follow the
//! occurrence and environment precedents — plain pipeline values derived on
//! demand and memoised per request, never semantic-artifact backed. The
//! resolved variant (segment prefix resolution) is a second, separately
//! memoised derivation because it runs one resolver batch per file: a query
//! that never says `:resolved true` or `segment-target` never pays for it.
//!
//! The honesty rule lives here too: a file whose adapter does not answer the
//! `path_segments` axis becomes an `Incomplete` diagnostic, and asking for
//! resolution from an adapter without the `segment_resolution` axis is
//! reported rather than silently returning rows without statuses.

use super::super::qualified_paths::{
    PathSegmentRow, QualifiedPathCompleteness, QualifiedPathDerivationOptions,
    QualifiedPathIncompleteReason, QualifiedPathRow, QualifiedPathsFileResult,
    qualified_paths_for_file,
};
use super::super::routes::IdentityAxis;
use super::DerivationExecutionCause;
use super::results::{
    CodeQueryDiagnostic, CodeQueryDiagnosticCode, CodeQueryDiagnosticImpact, CodeQueryPathSegment,
    CodeQueryQualifiedPath, CodeQueryRange,
};
use crate::analyzer::semantic::LengthDelimitedDigest;
use crate::analyzer::{IAnalyzer, ProjectFile};
use crate::cancellation::CancellationToken;
use crate::hash::HashMap;
use brokk_bifrost_analysis::analyzer::workspace_authority::{CaptureScopedMemo, memo_attribution};
use std::sync::Arc;

/// Domain separator for a qualified-path row's stable id.
const PATH_ID_DOMAIN: &[u8] = b"bifrost.code_query.qualified_path.v1";
/// Domain separator for a path-segment row's stable id.
const SEGMENT_ID_DOMAIN: &[u8] = b"bifrost.code_query.path_segment.v1";

/// Pure per-request value memo. Each invocation emits its own diagnostics;
/// policy normalization deduplicates repeated observations.
#[derive(Default)]
pub(super) struct PathTraversalCache {
    rows_only: CaptureScopedMemo<HashMap<ProjectFile, Arc<QualifiedPathsFileResult>>>,
    resolved: CaptureScopedMemo<HashMap<ProjectFile, Arc<QualifiedPathsFileResult>>>,
}

impl PathTraversalCache {
    /// Derive (or replay) one file's qualified paths. The resolved variant is
    /// cached separately from the plain one for the cost reason in the module
    /// docs. `None` only on cancellation.
    pub(super) fn paths_for(
        &mut self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        resolved: bool,
        cancellation: Option<&CancellationToken>,
    ) -> Option<Arc<QualifiedPathsFileResult>> {
        let cache = if resolved {
            &mut self.resolved
        } else {
            &mut self.rows_only
        };
        if let Some(cached) = cache.read(&memo_attribution(analyzer), |cache| {
            cache.get(file).cloned()
        }) {
            return Some(cached);
        }
        let token = cancellation.cloned().unwrap_or_default();
        let options = if resolved {
            QualifiedPathDerivationOptions::WITH_SEGMENT_RESOLUTION
        } else {
            QualifiedPathDerivationOptions::ROWS_ONLY
        };
        let derived = Arc::new(
            qualified_paths_for_file(analyzer, file, options, &token)
                .inspect_err(|error| { brokk_bifrost_core::profiling::note_with(|| format!("policy.units unbounded origin={}:{} cause=qualified_paths_error detail={error:?}", file!(), line!())); analyzer.mark_execution_dependent(); })
                .ok()?,
        );
        if let QualifiedPathCompleteness::Incomplete { reasons, .. } = &derived.completeness
            && reasons.iter().any(|reason| {
                matches!(
                    reason,
                    QualifiedPathIncompleteReason::FactsUnavailable
                        | QualifiedPathIncompleteReason::ResolutionCancelled
                )
            })
        {
            brokk_bifrost_core::profiling::note_with(|| {
                format!(
                    "policy.units unbounded origin={}:{} cause=qualified_paths_incomplete detail={reasons:?}",
                    file!(),
                    line!()
                )
            });
            analyzer.mark_execution_dependent();
        }
        let cache = if resolved {
            &mut self.resolved
        } else {
            &mut self.rows_only
        };
        cache.read_mut(&memo_attribution(analyzer), |cache| {
            cache.insert(file.clone(), Arc::clone(&derived))
        });
        Some(derived)
    }

    /// Turn one file's path completeness into typed diagnostics, scoped to the
    /// axes the query actually depends on.
    pub(super) fn report_completeness(
        &mut self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        result: &QualifiedPathsFileResult,
        required: &[IdentityAxis],
        diagnostics: &mut Vec<CodeQueryDiagnostic>,
    ) {
        let QualifiedPathCompleteness::Incomplete { reasons, .. } = &result.completeness else {
            return;
        };
        let language = crate::analyzer::common::language_for_file(file);
        for axis in required {
            if result.completeness.covers(*axis) {
                continue;
            }
            let unsupported = reasons.iter().any(|reason| {
                matches!(reason, QualifiedPathIncompleteReason::AxisUnsupported(other) if other == axis)
            });
            if unsupported {
                // An unsupported axis is a property of the adapter, so it is
                // repeated identically for every item and normalized later.
                diagnostics.push(CodeQueryDiagnostic {
                    related: Vec::new(),
                    source: None,
                    code: CodeQueryDiagnosticCode::IdentityAxisUnsupported,
                    impact: CodeQueryDiagnosticImpact::Incomplete,
                    branch: Vec::new(),
                    language: language.config_label(),
                    message: format!(
                        "structural adapter for {} does not support identity axis(es): {}",
                        language.config_label(),
                        axis.label()
                    ),
                    exhausted_roots: Vec::new(),
                    withheld_rows_path: None,
                });
                continue;
            }
            let cause = if reasons
                .iter()
                .any(|reason| matches!(reason, QualifiedPathIncompleteReason::ResolutionCancelled))
            {
                Some(DerivationExecutionCause::Cancelled)
            } else if reasons
                .iter()
                .any(|reason| matches!(reason, QualifiedPathIncompleteReason::FactsUnavailable))
            {
                Some(DerivationExecutionCause::Provider)
            } else {
                None
            };
            diagnostics.push(super::QueryExecutionState::diagnostic(analyzer, CodeQueryDiagnostic {
                related: Vec::new(),
                source: None,
                code: CodeQueryDiagnosticCode::PathDerivationIncomplete,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: language.config_label(),
                message: format!(
                    "{} has incomplete qualified-path rows ({}); its {} rows are not the whole set",
                    super::rel_path_string(file),
                    reasons
                        .iter()
                        .map(incomplete_reason_label)
                        .collect::<Vec<_>>()
                        .join(", "),
                    axis.label()
                ),
                exhausted_roots: Vec::new(),
                withheld_rows_path: None,
            }, cause));
        }
    }
}

fn incomplete_reason_label(reason: &QualifiedPathIncompleteReason) -> &'static str {
    match reason {
        QualifiedPathIncompleteReason::AxisUnsupported(_) => "axis unsupported",
        QualifiedPathIncompleteReason::NoStructuralAdapter => "no structural adapter",
        QualifiedPathIncompleteReason::FactsUnavailable => "no structural facts",
        QualifiedPathIncompleteReason::SyntaxUnavailable => "source did not parse",
        QualifiedPathIncompleteReason::ChainUnenumerable => "a chain could not be enumerated",
        QualifiedPathIncompleteReason::PathAnchorUnclassified => {
            "a path's terminal segment is not a fact"
        }
        QualifiedPathIncompleteReason::ResolutionCancelled => "segment resolution was cancelled",
    }
}

/// One qualified-path row travelling through the pipeline. The whole file
/// result travels with the row because `segments-of` is answered from it, and
/// a derived result is shared rather than cloned per row.
#[derive(Debug, Clone)]
pub(super) struct PathValue {
    pub(super) file: ProjectFile,
    pub(super) result: Arc<QualifiedPathsFileResult>,
    /// Index into [`QualifiedPathsFileResult::paths`].
    pub(super) index: usize,
}

impl PathValue {
    pub(super) fn row(&self) -> &QualifiedPathRow {
        &self.result.paths[self.index]
    }

    pub(super) fn key(&self) -> PathKey {
        PathKey {
            file: self.file.clone(),
            terminal_node: self.row().terminal_node,
        }
    }

    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }

    pub(super) fn id(&self) -> String {
        let row = self.row();
        let mut digest = LengthDelimitedDigest::new(PATH_ID_DOMAIN);
        digest.push(row.content_identity.as_bytes());
        digest.push(&row.terminal_node.to_le_bytes());
        digest.finish().to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct PathKey {
    pub(super) file: ProjectFile,
    pub(super) terminal_node: u32,
}

/// One path-segment row travelling through the pipeline.
#[derive(Debug, Clone)]
pub(super) struct SegmentValue {
    pub(super) file: ProjectFile,
    pub(super) result: Arc<QualifiedPathsFileResult>,
    /// Index into [`QualifiedPathsFileResult::segments`].
    pub(super) index: usize,
}

impl SegmentValue {
    pub(super) fn row(&self) -> &PathSegmentRow {
        &self.result.segments[self.index]
    }

    pub(super) fn key(&self) -> SegmentKey {
        let row = self.row();
        SegmentKey {
            file: self.file.clone(),
            path_terminal_node: row.path_terminal_node,
            ordinal: row.ordinal,
        }
    }

    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }

    pub(super) fn id(&self) -> String {
        let row = self.row();
        let mut digest = LengthDelimitedDigest::new(SEGMENT_ID_DOMAIN);
        digest.push(row.content_identity.as_bytes());
        digest.push(&row.path_terminal_node.to_le_bytes());
        digest.push(&row.ordinal.to_le_bytes());
        digest.finish().to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct SegmentKey {
    pub(super) file: ProjectFile,
    pub(super) path_terminal_node: u32,
    pub(super) ordinal: u32,
}

/// The axes a path query depends on, with and without segment resolution.
pub(super) const PATH_QUERY_AXES: &[IdentityAxis] = &[IdentityAxis::PathSegments];
pub(super) const RESOLVED_PATH_QUERY_AXES: &[IdentityAxis] =
    &[IdentityAxis::PathSegments, IdentityAxis::SegmentResolution];

/// The public projection of one qualified-path row.
pub(super) fn public_path(value: &PathValue, range: CodeQueryRange) -> CodeQueryQualifiedPath {
    let row = value.row();
    let metadata = super::public_source_metadata(&row.file, row.range, range);
    CodeQueryQualifiedPath {
        id: value.id(),
        ast_id: row.ast_id(),
        path: metadata.path,
        language: metadata.language,
        range: metadata.range,
        start_byte: metadata.start_byte,
        end_byte: metadata.end_byte,
        segment_count: row.segment_count,
    }
}

/// The public projection of one path-segment row.
pub(super) fn public_segment(value: &SegmentValue, range: CodeQueryRange) -> CodeQueryPathSegment {
    let row = value.row();
    let metadata = super::public_source_metadata(&row.file, row.range, range);
    CodeQueryPathSegment {
        id: value.id(),
        ast_id: row.ast_id(),
        path: metadata.path,
        language: metadata.language,
        range: metadata.range,
        start_byte: metadata.start_byte,
        end_byte: metadata.end_byte,
        path_ast_id: super::super::occurrence_rows::ast_id(
            row.content_identity,
            row.path_terminal_node,
        ),
        ordinal: row.ordinal,
        text: row.text.clone(),
        namespace: row.namespace.map(|namespace| namespace.label()),
        generic_arity: row.generic_arity,
        resolution_status: row
            .resolution
            .as_ref()
            .map(|resolution| resolution.status.label()),
        target_count: row
            .resolution
            .as_ref()
            .map(|resolution| resolution.targets.len()),
    }
}
