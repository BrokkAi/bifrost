//! The execution adapter between the query engine and Milestone 2's
//! per-file occurrence derivation (#1473).
//!
//! Occurrences are not semantic-artifact backed, so they follow the
//! `ReferenceSite`/`CallSite` pipeline-value pattern: a plain value carried
//! through the pipeline, derived on demand and cached per request.
//!
//! The honesty rule the whole domain exists for lives here: whenever a query
//! names roles the file's adapter cannot classify, this module turns that into
//! an `Incomplete` diagnostic, so an empty answer is never mistaken for "there
//! are none".

use super::super::capabilities::{QueryFeature, QueryFeatures};
use super::super::occurrence_rows::{
    OccurrenceCompleteness, OccurrenceFileResult, OccurrenceIncompleteReason, OccurrenceRow,
    OccurrenceTarget, occurrences_for_file,
};
use super::super::occurrences::OccurrenceRole;
use super::super::query::OccurrenceFilter;
use super::results::{
    CodeQueryDiagnostic, CodeQueryDiagnosticCode, CodeQueryDiagnosticImpact, CodeQueryRange,
};
use crate::analyzer::{IAnalyzer, Language, ProjectFile};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use std::sync::Arc;

/// Per-request memo of derived occurrence rows plus the diagnostics already
/// reported, so one file is derived once and one capability gap is reported
/// once no matter how many pipeline rows touch it.
#[derive(Default)]
pub(super) struct OccurrenceTraversalCache {
    files: HashMap<ProjectFile, Arc<OccurrenceFileResult>>,
    reported: HashSet<(Language, OccurrenceRole, CodeQueryDiagnosticCode)>,
    reported_files: HashSet<(ProjectFile, CodeQueryDiagnosticCode)>,
}

impl OccurrenceTraversalCache {
    /// Derive (or replay) one file's occurrence rows.
    ///
    /// `None` means the request was cancelled; an adapter that classifies
    /// nothing still returns a result, whose completeness says so.
    pub(super) fn rows_for_file(
        &mut self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        cancellation: Option<&CancellationToken>,
    ) -> Option<Arc<OccurrenceFileResult>> {
        if let Some(cached) = self.files.get(file) {
            return Some(Arc::clone(cached));
        }
        let token = cancellation.cloned().unwrap_or_default();
        let derived = occurrences_for_file(analyzer, file, &token).ok()?;
        let derived = Arc::new(derived);
        self.files.insert(file.clone(), Arc::clone(&derived));
        Some(derived)
    }

    /// Turn a file result's completeness into typed diagnostics, scoped to the
    /// roles the query actually depends on.
    ///
    /// A file whose adapter cannot name path-segment namespaces is still
    /// authoritative about its binders, so a `(role binder)` query over it must
    /// not be reported incomplete.
    pub(super) fn report_completeness(
        &mut self,
        file: &ProjectFile,
        result: &OccurrenceFileResult,
        filter: &OccurrenceFilter,
        diagnostics: &mut Vec<CodeQueryDiagnostic>,
    ) {
        let OccurrenceCompleteness::Incomplete { reasons, .. } = &result.completeness else {
            return;
        };
        let language = crate::analyzer::common::language_for_file(file);
        let required = filter.required_roles();
        for reason in reasons {
            match reason {
                OccurrenceIncompleteReason::RoleUnsupported(role)
                | OccurrenceIncompleteReason::NamespaceUnknown(role) => {
                    if !required.contains(role) {
                        continue;
                    }
                    let code = CodeQueryDiagnosticCode::OccurrenceRoleUnsupported;
                    if !self.reported.insert((language, *role, code)) {
                        continue;
                    }
                    let message = match reason {
                        // An adapter that classifies the role but cannot name
                        // its namespace is a distinct, narrower gap than one
                        // that does not classify it at all, and the two must
                        // not be reported with the same prose.
                        OccurrenceIncompleteReason::NamespaceUnknown(_) => format!(
                            "structural adapter for {} cannot assign a namespace to occurrence role(s): {}",
                            language.config_label(),
                            role.label()
                        ),
                        _ => QueryFeatures::for_occurrence_filter(filter)
                            .unsupported_by(|feature| {
                                !matches!(
                                    feature,
                                    QueryFeature::OccurrenceRole(candidate) if candidate == *role
                                )
                            })
                            .into_diagnostics(language)
                            .first()
                            .expect("one unsupported occurrence role yields one diagnostic")
                            .message(),
                    };
                    diagnostics.push(CodeQueryDiagnostic {
                        code,
                        impact: CodeQueryDiagnosticImpact::Incomplete,
                        branch: Vec::new(),
                        language: language.config_label(),
                        message,
                    });
                }
                OccurrenceIncompleteReason::NoStructuralAdapter
                | OccurrenceIncompleteReason::FactsUnavailable => {
                    let code = CodeQueryDiagnosticCode::OccurrenceResolutionIncomplete;
                    if !self.reported_files.insert((file.clone(), code)) {
                        continue;
                    }
                    let detail = match reason {
                        OccurrenceIncompleteReason::NoStructuralAdapter => {
                            "has no structural adapter"
                        }
                        _ => "has no structural facts in this workspace",
                    };
                    diagnostics.push(CodeQueryDiagnostic {
                        code,
                        impact: CodeQueryDiagnosticImpact::Incomplete,
                        branch: Vec::new(),
                        language: language.config_label(),
                        message: format!(
                            "{} {detail}; its occurrences were omitted",
                            super::rel_path_string(file)
                        ),
                    });
                }
            }
        }
    }
}

/// One occurrence row travelling through the pipeline.
///
/// The row is shared rather than cloned: a single file's derivation feeds every
/// pipeline row that touches it, and the row owns a `CodeUnit` and two strings.
#[derive(Debug, Clone)]
pub(super) struct OccurrenceValue {
    pub(super) row: Arc<OccurrenceRow>,
}

/// Dedup identity: the AST node plus its role, which is exactly what the
/// occurrence id digests.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct OccurrenceKey {
    pub(super) file: ProjectFile,
    pub(super) node: u32,
    pub(super) role: OccurrenceRole,
}

impl OccurrenceValue {
    pub(super) fn key(&self) -> OccurrenceKey {
        OccurrenceKey {
            file: self.row.file.clone(),
            node: self.row.node,
            role: self.row.role,
        }
    }

    pub(super) fn file(&self) -> &ProjectFile {
        &self.row.file
    }
}

/// Select the rows of one file result that satisfy a filter, newest-first in
/// arena order so results are deterministic.
pub(super) fn select_rows<'rows>(
    result: &'rows OccurrenceFileResult,
    filter: &OccurrenceFilter,
) -> impl Iterator<Item = &'rows OccurrenceRow> {
    result
        .rows
        .iter()
        .filter(|row| filter.matches(row.class, row.role, row.namespace))
}

/// The public projection of one occurrence row.
pub(super) fn public_occurrence(
    row: &OccurrenceRow,
    range: CodeQueryRange,
    target: super::results::CodeQueryOccurrenceTarget,
) -> super::results::CodeQueryOccurrence {
    super::results::CodeQueryOccurrence {
        id: row.id(),
        ast_id: row.ast_id(),
        path: super::rel_path_string(&row.file),
        language: crate::analyzer::common::language_for_file(&row.file).config_label(),
        class: row.class.label(),
        role: row.role.label(),
        namespace: row.namespace.label(),
        range,
        start_byte: row.range.start_byte,
        end_byte: row.range.end_byte,
        enclosing_symbol: row
            .enclosing
            .as_ref()
            .map(crate::analyzer::CodeUnit::fq_name),
        raw_spelling: row.raw_spelling.clone(),
        decoded_spelling: row.decoded_spelling.clone(),
        target,
    }
}

/// The stable label of a resolution outcome, so `unresolved` never degenerates
/// into an unexplained empty target.
pub(super) fn target_status_label(target: &OccurrenceTarget) -> &'static str {
    match target {
        OccurrenceTarget::None => "none",
        OccurrenceTarget::Resolved(_) => "resolved",
        OccurrenceTarget::Lexical(_) => "lexical",
        OccurrenceTarget::Unresolved(status) => status.as_str(),
    }
}
