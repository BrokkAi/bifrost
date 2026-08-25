//! Pipeline execution for the `callable_applicability` and
//! `overload_selection` steps (issue #1478, Milestone 3).
//!
//! Both steps read one thing: the production resolver's own candidate trace for
//! a reference occurrence, projected by
//! [`crate::analyzer::usages::overload_selection`]. Nothing here decides
//! applicability, and nothing here re-runs a resolver -- the verdicts were
//! produced by the same function that produced the resolver's winners.
//!
//! `overload_selection` is mandatory per occurrence: a language that does not
//! report the callable axis, or an occurrence whose file recorded no trace,
//! still yields exactly one row saying so. Only a file whose traced derivation
//! cannot be produced at all (budget) yields none, and that is reported through
//! `row_exhausted`. `callable_applicability` is the per-candidate projection and
//! is legitimately empty when the resolver considered nothing.

use super::*;

use crate::analyzer::usages::get_definition::trace::TraceCandidate;
use crate::analyzer::usages::overload_selection::{
    ApplicabilityRow, OverloadSelectionReport, OverloadSelectionRow, overload_selection_report,
    supports_callable_applicability,
};

/// The mandatory overload-selection summary for one reference occurrence.
#[derive(Debug, Clone)]
pub(super) struct OverloadSelectionValue {
    pub(super) occurrence: Arc<OccurrenceRow>,
    pub(super) report: Arc<OverloadSelectionReport>,
}

impl OverloadSelectionValue {
    pub(super) fn row(&self) -> &OverloadSelectionRow {
        &self.report.selection
    }
}

/// One considered candidate's applicability row, beside the trace candidate it
/// was projected from so the rendered row can name the candidate declaration.
#[derive(Debug, Clone)]
pub(super) struct CallableApplicabilityValue {
    pub(super) occurrence: Arc<OccurrenceRow>,
    pub(super) candidate: Arc<TraceCandidate>,
    pub(super) selection: Arc<OverloadSelectionReport>,
    pub(super) ordinal: usize,
}

impl CallableApplicabilityValue {
    pub(super) fn row(&self) -> &ApplicabilityRow {
        &self.selection.applicability[self.ordinal]
    }
}

/// Derive one occurrence's applicability evidence from the traced file.
///
/// The trace is a second, opt-in derivation of the occurrence's file, so the
/// reference row is re-located inside the traced result by AST identity -- node
/// plus role -- rather than by position, exactly as the candidate and
/// member-selection steps do.
fn report_for_occurrence(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    row: &OccurrenceRow,
    cancellation: Option<&CancellationToken>,
    row_exhausted: &mut bool,
) -> Option<(Arc<OccurrenceRow>, Arc<OverloadSelectionReport>)> {
    let traced = environment_cache.traced_occurrences_for(analyzer, &row.file, cancellation);
    let Some(traced) = traced else {
        *row_exhausted = true;
        return None;
    };
    let traced_row = traced
        .rows
        .iter()
        .find(|other| other.node == row.node && other.role == row.role);
    let occurrence = Arc::new(traced_row.cloned().unwrap_or_else(|| row.clone()));
    let supported =
        supports_callable_applicability(crate::analyzer::common::language_for_file(&row.file));
    let report = overload_selection_report(
        &occurrence.ast_id(),
        supported,
        traced_row.and_then(|row| row.candidates.as_ref()),
    );
    Some((occurrence, Arc::new(report)))
}

/// Exactly one summary row per occurrence the traced file can be produced for.
pub(super) fn overload_selection_expansions(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    row: &OccurrenceRow,
    cancellation: Option<&CancellationToken>,
    row_exhausted: &mut bool,
) -> Vec<PipelineExpansion> {
    let Some((occurrence, report)) = report_for_occurrence(
        analyzer,
        environment_cache,
        row,
        cancellation,
        row_exhausted,
    ) else {
        return Vec::new();
    };
    vec![pipeline_expansion(PipelineValue::OverloadSelection(
        Box::new(OverloadSelectionValue { occurrence, report }),
    ))]
}

/// One row per candidate the resolver considered at this occurrence.
pub(super) fn callable_applicability_expansions(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    row: &OccurrenceRow,
    cancellation: Option<&CancellationToken>,
    row_exhausted: &mut bool,
) -> Vec<PipelineExpansion> {
    let Some((occurrence, report)) = report_for_occurrence(
        analyzer,
        environment_cache,
        row,
        cancellation,
        row_exhausted,
    ) else {
        return Vec::new();
    };
    let Some(traced) = environment_cache.traced_occurrences_for(analyzer, &row.file, cancellation)
    else {
        *row_exhausted = true;
        return Vec::new();
    };
    let candidates = traced
        .rows
        .iter()
        .find(|other| other.node == row.node && other.role == row.role)
        .and_then(|row| row.candidates.as_ref())
        .map(|trace| trace.candidates.as_slice())
        .unwrap_or_default();
    debug_assert_eq!(
        candidates.len(),
        report.applicability.len(),
        "one applicability row per considered candidate"
    );
    candidates
        .iter()
        .enumerate()
        .map(|(ordinal, candidate)| {
            pipeline_expansion(PipelineValue::CallableApplicability(Box::new(
                CallableApplicabilityValue {
                    occurrence: Arc::clone(&occurrence),
                    candidate: Arc::new(candidate.clone()),
                    selection: Arc::clone(&report),
                    ordinal,
                },
            )))
        })
        .collect()
}
