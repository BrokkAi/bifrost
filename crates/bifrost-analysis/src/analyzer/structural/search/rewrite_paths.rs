//! The execution adapter between the query engine and the bounded
//! rewrite-path derivation layer (#1480, milestone 4).
//!
//! Rows follow the flow-state precedent ([`super::flow_state`]): plain
//! pipeline values derived on demand and memoised per request, never carried in
//! an artifact. One file is derived once per query, and the derivation's own
//! completeness becomes typed diagnostics before any filter runs -- so an
//! `:outcome cycle` filter that drops every row still leaves the reason the row
//! set is partial on the response.
//!
//! There is no capability table here. A rewrite domain is declared by the
//! production chase that implements it, not by a per-language capability row;
//! the honest source is whether the chase could be run over this file, which is
//! exactly what [`RewritePathCompleteness`] reports.

use super::super::rewrite_paths::{
    FileRewritePaths, RewritePathCompleteness, RewritePathIncompleteReason, RewritePathRequest,
    rewrite_paths_for_file,
};
use super::rel_path_string;
use super::results::{
    CodeQueryDiagnostic, CodeQueryDiagnosticCode, CodeQueryDiagnosticImpact, CodeQueryRange,
    CodeQueryRewritePath, CodeQueryRewriteStep,
};
use crate::analyzer::semantic::LengthDelimitedDigest;
use crate::analyzer::{IAnalyzer, Language, ProjectFile};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_core::analyzer::structural::rewrite_path::{
    ALL_REWRITE_DOMAIN_KINDS, RewritePath,
};
use brokk_bifrost_rql::RewritePathFilter;
use std::sync::Arc;

/// Domain separator for the row family's stable ids.
const REWRITE_PATH_ID_DOMAIN: &[u8] = b"bifrost.code_query.rewrite_path.v1";

/// Per-request memo of derived rewrite paths plus the diagnostics already
/// reported, so one file is derived once and one reason is reported once.
#[derive(Default)]
pub(super) struct RewritePathTraversalCache {
    files: HashMap<ProjectFile, Arc<FileRewritePaths>>,
    reported: HashSet<(String, &'static str)>,
}

impl RewritePathTraversalCache {
    /// Derive (or replay) the rewrite paths of one file.
    pub(super) fn for_file(
        &mut self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        cancellation: Option<&CancellationToken>,
    ) -> Arc<FileRewritePaths> {
        if let Some(cached) = self.files.get(file) {
            return Arc::clone(cached);
        }
        let token = cancellation.cloned().unwrap_or_default();
        let derived = Arc::new(rewrite_paths_for_file(
            analyzer,
            file,
            &mut RewritePathRequest::new(&token),
        ));
        self.files.insert(file.clone(), Arc::clone(&derived));
        derived
    }

    /// Turn one derivation's completeness into typed diagnostics.
    pub(super) fn report_completeness(
        &mut self,
        subject: &str,
        language: Language,
        completeness: &RewritePathCompleteness,
        generation: u64,
        diagnostics: &mut Vec<CodeQueryDiagnostic>,
    ) {
        for reason in completeness.reasons() {
            let (code, detail) = classify_reason(reason);
            if !self.reported.insert((subject.to_string(), detail)) {
                continue;
            }
            let uncovered = uncovered_domains(completeness);
            diagnostics.push(CodeQueryDiagnostic {
                code,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: language.config_label(),
                message: format!(
                    "{subject} has an incomplete rewrite-path derivation in generation \
                     {generation} ({detail}); uncovered domains: [{}]",
                    uncovered.join(", ")
                ),
            });
        }
    }
}

/// The diagnostic code and human reason of one incompleteness.
///
/// Total on purpose: a reason added to the derivation layer must be classified
/// here deliberately rather than defaulting into a generic message.
fn classify_reason(
    reason: &RewritePathIncompleteReason,
) -> (CodeQueryDiagnosticCode, &'static str) {
    match reason {
        RewritePathIncompleteReason::NoDomainAnalyzer(_) => (
            CodeQueryDiagnosticCode::RewriteDomainUnsupported,
            "the workspace has no analyzer for the domain's language",
        ),
        RewritePathIncompleteReason::Cancelled => (
            CodeQueryDiagnosticCode::RewritePathDerivationIncomplete,
            "the derivation was cancelled",
        ),
        RewritePathIncompleteReason::NoIndexedSource => (
            CodeQueryDiagnosticCode::RewritePathDerivationIncomplete,
            "the analyzer no longer holds the analyzed source the origins anchor in",
        ),
    }
}

/// One rewrite-path row travelling through the pipeline.
///
/// The whole file derivation is held by `Arc` rather than the single row: one
/// query commonly asks for every path of a file, and the rows share it.
#[derive(Debug, Clone)]
pub(super) struct RewritePathValue {
    pub(super) file_paths: Arc<FileRewritePaths>,
    pub(super) index: usize,
    pub(super) file: ProjectFile,
}

impl RewritePathValue {
    pub(super) fn row(&self) -> &RewritePath {
        &self.file_paths.paths[self.index]
    }

    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }

    pub(super) fn key(&self) -> RewritePathKey {
        RewritePathKey {
            file: self.file.clone(),
            index: self.index,
        }
    }

    /// The row's content-scoped identity: the domain, the origin site, and the
    /// terminal outcome. Two chases of one file from two different origins are
    /// two rows, which is the point of the domain.
    pub(super) fn id(&self) -> String {
        let row = self.row();
        let mut digest = LengthDelimitedDigest::new(REWRITE_PATH_ID_DOMAIN);
        digest.push(row.domain.label().as_bytes());
        digest.push(rel_path_string(&row.origin.file).as_bytes());
        digest.push(&row.origin.range.start_byte.to_le_bytes());
        digest.push(&row.origin.range.end_byte.to_le_bytes());
        digest.push(row.origin.specifier.as_bytes());
        digest.push(row.outcome.kind().label().as_bytes());
        for step in &row.steps {
            digest.push(step.state_key.as_bytes());
            digest.push(step.output.as_bytes());
        }
        digest.finish().to_string()
    }
}

/// Dedup identity of a rewrite-path row: the file plus the dense index the
/// derivation minted.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct RewritePathKey {
    pub(super) file: ProjectFile,
    pub(super) index: usize,
}

pub(super) fn rewrite_path_filter_matches(filter: &RewritePathFilter, row: &RewritePath) -> bool {
    if !filter.domains.is_empty() && !filter.domains.contains(&row.domain) {
        return false;
    }
    if !filter.outcomes.is_empty() && !filter.outcomes.contains(&row.outcome.kind()) {
        return false;
    }
    true
}

/// The public projection of one rewrite-path row.
///
/// Every part of the claim travels: the declared bound, the ordered steps with
/// their semantic state keys and the rule that fired, and the outcome's own
/// payload. A reader must be able to replay the chase from the row alone.
pub(super) fn public_rewrite_path(
    value: &RewritePathValue,
    range: CodeQueryRange,
) -> CodeQueryRewritePath {
    let row = value.row();
    CodeQueryRewritePath {
        id: value.id(),
        path: rel_path_string(&row.origin.file),
        language: crate::analyzer::common::language_for_file(&row.origin.file).config_label(),
        range,
        start_byte: row.origin.range.start_byte,
        end_byte: row.origin.range.end_byte,
        domain: row.domain.label(),
        origin_specifier: row.origin.specifier.clone(),
        declared_bound: row.declared_bound,
        step_count: row.steps.len(),
        steps: row
            .steps
            .iter()
            .map(|step| CodeQueryRewriteStep {
                state_key: step.state_key.clone(),
                input: step.input.clone(),
                output: step.output.clone(),
                rule: step.rule,
            })
            .collect(),
        outcome: row.outcome.kind().label(),
        fixed_point: row.outcome.fixed_point().map(str::to_string),
        witness: row.outcome.witness().to_vec(),
        explored: row.outcome.explored(),
        completeness: domain_completeness_label(value),
        uncovered_domains: uncovered_domains(&value.file_paths.completeness),
        generation: row.generation,
    }
}

/// The value domain the `rewrite_path.completeness` row field publishes,
/// minted by [`domain_completeness_label`] (issue #2515).
pub(super) const REWRITE_PATH_COMPLETENESS_LABELS: &[&str] = &["complete", "partial"];

/// `complete` exactly when the derivation answers *this row's own domain*;
/// otherwise `partial`.
fn domain_completeness_label(value: &RewritePathValue) -> &'static str {
    if value.file_paths.completeness.covers(value.row().domain) {
        "complete"
    } else {
        "partial"
    }
}

fn uncovered_domains(completeness: &RewritePathCompleteness) -> Vec<&'static str> {
    ALL_REWRITE_DOMAIN_KINDS
        .iter()
        .filter(|domain| !completeness.covers(**domain))
        .map(|domain| domain.label())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::analyzer::structural::rewrite_path::{
        ALL_REWRITE_OUTCOME_KINDS, RewriteDomainKind, RewriteOrigin, RewriteOutcome,
        RewriteOutcomeKind,
    };

    fn row(outcome: RewriteOutcome) -> RewritePath {
        RewritePath {
            domain: RewriteDomainKind::RustImportAlias,
            origin: RewriteOrigin {
                file: ProjectFile::new(std::path::Path::new("/tmp"), "src/lib.rs"),
                specifier: "a".to_string(),
                range: crate::analyzer::Range {
                    start_byte: 0,
                    end_byte: 1,
                    start_line: 1,
                    end_line: 1,
                },
            },
            declared_bound: 2,
            steps: Vec::new(),
            outcome,
            generation: 3,
        }
    }

    #[test]
    fn every_rewrite_vocabulary_value_has_a_wire_label() {
        for domain in ALL_REWRITE_DOMAIN_KINDS {
            assert!(!domain.label().is_empty());
        }
        for outcome in ALL_REWRITE_OUTCOME_KINDS {
            assert!(!outcome.label().is_empty());
        }
    }

    #[test]
    fn an_outcome_filter_keeps_only_the_named_outcome() {
        let cycle = row(RewriteOutcome::Cycle {
            witness: vec!["c".to_string(), "a".to_string(), "c".to_string()],
        });
        let converged = row(RewriteOutcome::Converged {
            fixed_point: "c::d".to_string(),
        });
        let filter = RewritePathFilter {
            domains: Vec::new(),
            outcomes: vec![RewriteOutcomeKind::Cycle],
        };
        assert!(rewrite_path_filter_matches(&filter, &cycle));
        assert!(!rewrite_path_filter_matches(&filter, &converged));
        assert!(rewrite_path_filter_matches(
            &RewritePathFilter::default(),
            &converged
        ));
        assert!(RewritePathFilter::default().is_empty());
    }

    #[test]
    fn an_incomplete_derivation_reports_every_reason_once_per_subject() {
        let mut cache = RewritePathTraversalCache::default();
        let completeness = RewritePathCompleteness::Incomplete {
            reasons: vec![
                RewritePathIncompleteReason::NoDomainAnalyzer(RewriteDomainKind::RustImportAlias),
                RewritePathIncompleteReason::Cancelled,
            ],
        };
        let mut diagnostics = Vec::new();
        cache.report_completeness(
            "src/lib.rs",
            Language::Rust,
            &completeness,
            7,
            &mut diagnostics,
        );
        assert_eq!(diagnostics.len(), 2, "{diagnostics:?}");
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.impact == CodeQueryDiagnosticImpact::Incomplete),
            "{diagnostics:?}"
        );
        cache.report_completeness(
            "src/lib.rs",
            Language::Rust,
            &completeness,
            7,
            &mut diagnostics,
        );
        assert_eq!(diagnostics.len(), 2, "{diagnostics:?}");
        assert!(!completeness.covers(RewriteDomainKind::RustImportAlias));
    }
}
