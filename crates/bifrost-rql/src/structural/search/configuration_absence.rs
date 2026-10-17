//! Document-scoped configuration anti-joins.
//!
//! A negative configuration claim is only emitted for a complete document
//! arena. The input row is the document root and the filter is evaluated over
//! every fact in that same arena; this prevents a filtered seed from turning
//! an unreadable or unrouted document into a vacuous absence.

use super::configuration::fact_matches_filter;
use super::*;
use crate::query::ConfigurationFactsFilter;
use brokk_bifrost_core::analyzer::configuration::ConfigurationNodeKind;

pub(super) fn expansions(
    value: &ConfigurationFactValue,
    filter: &ConfigurationFactsFilter,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    if value.index != 0 || !matches!(value.fact().kind(), ConfigurationNodeKind::Document { .. }) {
        diagnostics.push(incomplete_diagnostic(
            CodeQueryDiagnosticCode::InvalidPlan,
            "workspace",
            format!(
                "configuration_absence requires a document-root configuration_fact input; {} is not a document root",
                rel_path_string(value.file())
            ),
            Vec::new(),
        ));
        return Vec::new();
    }
    if !value.document.completeness().is_complete() {
        // The ingestion cache reports the recovery reason when the document is
        // read. Keep this guard here as well because callers may construct a
        // document row through a shared plan whose diagnostic was emitted in
        // another branch.
        diagnostics.push(incomplete_diagnostic(
            CodeQueryDiagnosticCode::SemanticAnalysisPartial,
            "workspace",
            format!(
                "configuration_absence cannot prove absence in partly recovered document {}",
                rel_path_string(value.file())
            ),
            Vec::new(),
        ));
        return Vec::new();
    }

    let match_found = value
        .document
        .facts()
        .iter()
        .enumerate()
        .map(|(index, _)| ConfigurationFactValue {
            file: value.file.clone(),
            document: Arc::clone(&value.document),
            source: Arc::clone(&value.source),
            index,
        })
        .any(|candidate| fact_matches_filter(&candidate, filter));
    if match_found {
        Vec::new()
    } else {
        vec![pipeline_expansion(PipelineValue::ConfigurationFact(
            value.clone(),
        ))]
    }
}
