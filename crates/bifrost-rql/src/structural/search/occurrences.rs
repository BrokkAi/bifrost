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
    OccurrenceCompleteness, OccurrenceDerivationOptions, OccurrenceFileResult,
    OccurrenceIncompleteReason, OccurrenceRow, OccurrenceTarget,
    occurrences_for_file_with_options_and_roles,
    occurrences_for_file_with_options_roles_and_ast_ids,
    resolve_occurrence_targets_for_rows as derive_targets_for_rows,
};
use super::super::occurrences::{OccurrenceClass, OccurrenceRole};
use super::results::{
    CodeQueryDiagnostic, CodeQueryDiagnosticCode, CodeQueryDiagnosticImpact, CodeQueryRange,
};
use crate::analyzer::{IAnalyzer, Language, ProjectFile};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_rql::OccurrenceFilter;
use std::sync::{Arc, Mutex};

/// Complete occurrence products retained by an explicitly scoped row-family
/// session. Diagnostic suppression stays query-local in
/// [`OccurrenceTraversalCache`]; only immutable producer output crosses query
/// boundaries.
#[derive(Default)]
pub(super) struct OccurrenceTraversalStore {
    files: HashMap<(ProjectFile, Vec<OccurrenceRole>), Arc<OccurrenceFileResult>>,
    /// Demand-resolved target outcomes reused only inside the surrounding
    /// row-family session. The session pins the workspace and model snapshot;
    /// keys retain the exact occurrence role.
    targets: HashMap<OccurrenceKey, OccurrenceTarget>,
    target_roles: HashMap<ProjectFile, HashSet<OccurrenceRole>>,
    derivations: usize,
    reuses: usize,
}

impl OccurrenceTraversalStore {
    pub(super) fn stats(&self) -> (usize, usize) {
        (self.derivations, self.reuses)
    }
}

/// Per-request memo of derived occurrence rows plus the diagnostics already
/// reported, so one file is derived once and one capability gap is reported
/// once no matter how many pipeline rows touch it.
#[derive(Default)]
pub(super) struct OccurrenceTraversalCache {
    files: HashMap<(ProjectFile, Vec<OccurrenceRole>), Arc<OccurrenceFileResult>>,
    targets: HashMap<OccurrenceKey, OccurrenceTarget>,
    complete_families: HashMap<ProjectFile, HashSet<OccurrenceRole>>,
    shared: Option<Arc<Mutex<OccurrenceTraversalStore>>>,
    selected_ast_ids: Option<Arc<std::collections::HashSet<String>>>,
    reported: HashSet<(Language, OccurrenceRole, CodeQueryDiagnosticCode)>,
    reported_files: HashSet<(ProjectFile, CodeQueryDiagnosticCode)>,
    /// What this execution asked occurrence derivation for. One choice per
    /// execution, so a memoized file is never replayed to a consumer that
    /// needed more of it than the first consumer asked for.
    options: OccurrenceDerivationOptions,
}

impl OccurrenceTraversalCache {
    pub(super) fn with_options(options: OccurrenceDerivationOptions) -> Self {
        Self {
            options,
            ..Self::default()
        }
    }

    pub(super) fn with_shared_store(
        options: OccurrenceDerivationOptions,
        shared: Arc<Mutex<OccurrenceTraversalStore>>,
        selected_ast_ids: Option<Arc<std::collections::HashSet<String>>>,
    ) -> Self {
        Self {
            options,
            shared: Some(shared),
            selected_ast_ids,
            ..Self::default()
        }
    }

    pub(super) fn with_selected_ast_ids(
        options: OccurrenceDerivationOptions,
        selected_ast_ids: Arc<std::collections::HashSet<String>>,
    ) -> Self {
        Self {
            options,
            selected_ast_ids: Some(selected_ast_ids),
            ..Self::default()
        }
    }

    /// A parallel seed branch gets fresh diagnostic suppression and local
    /// lookups while retaining the parent query's immutable shared products.
    pub(super) fn fork_empty(&self) -> Self {
        Self {
            options: self.options,
            shared: self.shared.clone(),
            selected_ast_ids: self.selected_ast_ids.clone(),
            ..Self::default()
        }
    }

    /// Derive (or replay) one file's occurrence rows.
    ///
    /// `None` means the request was cancelled; an adapter that classifies
    /// nothing still returns a result, whose completeness says so.
    pub(super) fn rows_for_file(
        &mut self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        filter: &OccurrenceFilter,
        cancellation: Option<&CancellationToken>,
    ) -> Option<Arc<OccurrenceFileResult>> {
        let mut roles = filter.required_roles();
        roles.sort_unstable();
        roles.dedup();
        let key = (file.clone(), roles);
        if let Some(cached) = self.files.get(&key).cloned() {
            self.record_complete_family(file, &key.1, &cached);
            return Some(cached);
        }
        if let Some(shared_store) = self.shared.clone() {
            let cached = {
                let mut shared = shared_store
                    .lock()
                    .expect("a row-family occurrence cache lock is not poisoned");
                let cached = shared.files.get(&key).cloned();
                if cached.is_some() {
                    shared.reuses = shared.reuses.saturating_add(1);
                }
                cached
            };
            if let Some(cached) = cached {
                self.record_complete_family(file, &key.1, &cached);
                self.files.insert(key, Arc::clone(&cached));
                return Some(cached);
            }
        }
        let token = cancellation.cloned().unwrap_or_default();
        let derived = match &self.selected_ast_ids {
            Some(ast_ids) => occurrences_for_file_with_options_roles_and_ast_ids(
                analyzer,
                file,
                self.options,
                &key.1,
                ast_ids,
                &token,
            ),
            None => occurrences_for_file_with_options_and_roles(
                analyzer,
                file,
                self.options,
                Some(&key.1),
                &token,
            ),
        }
        .ok()?;
        let mut derived = Arc::new(derived);
        self.record_complete_family(file, &key.1, &derived);
        if let Some(shared) = &self.shared {
            let mut shared = shared
                .lock()
                .expect("a row-family occurrence cache lock is not poisoned");
            shared.derivations = shared.derivations.saturating_add(1);
            if key.1.iter().all(|role| derived.completeness.covers(*role)) {
                if let Some(cached) = shared.files.get(&key).cloned() {
                    derived = cached;
                } else {
                    shared.files.insert(key.clone(), Arc::clone(&derived));
                }
            }
        }
        self.files.insert(key, Arc::clone(&derived));
        Some(derived)
    }

    /// Resolve only the reference rows a downstream query step still needs.
    ///
    /// Callers group rows by file before calling this method, so one
    /// definition batch handles all surviving locators in that file. Exact
    /// outcomes are query-local by default and may cross selector scans only
    /// when this query's complete occurrence family is retained in the
    /// explicitly scoped row-family session.
    pub(super) fn resolve_targets_for_rows(
        &mut self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        rows: &mut [OccurrenceRow],
        cancellation: Option<&CancellationToken>,
    ) -> bool {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return false;
        }
        if rows.is_empty() {
            return true;
        }
        for row in rows.iter() {
            assert_eq!(row.file, *file, "one target batch contains one file");
        }

        let shared_store = self.shared.clone();
        let shared = shared_store.as_ref().map(|shared_store| {
            shared_store
                .lock()
                .expect("a row-family occurrence cache lock is not poisoned")
        });
        let shared_target_roles = shared
            .as_ref()
            .and_then(|shared| shared.target_roles.get(file));
        let mut pending_keys = Vec::new();
        let mut pending_rows = Vec::new();
        let mut pending_indices = HashMap::default();
        let mut pending_shareable = Vec::new();
        for row in rows.iter_mut() {
            if row.class != OccurrenceClass::Reference
                || !matches!(&row.target, OccurrenceTarget::NotDerived)
            {
                continue;
            }
            let key = OccurrenceKey::from_row(row);
            let shareable = self.has_complete_occurrence_family(file, row.role);
            if let Some(target) = self.targets.get(&key) {
                row.target = target.clone();
            } else if shareable
                && shared_target_roles.is_some_and(|roles| roles.contains(&row.role))
                && let Some(target) = shared.as_ref().and_then(|shared| shared.targets.get(&key))
            {
                row.target = target.clone();
                self.targets.insert(key, target.clone());
            } else if let Some(index) = pending_indices.get(&key).copied() {
                pending_shareable[index] |= shareable;
            } else {
                pending_indices.insert(key.clone(), pending_keys.len());
                pending_keys.push(key);
                pending_rows.push(row.clone());
                pending_shareable.push(shareable);
            }
        }
        drop(shared);

        if !pending_rows.is_empty() {
            let token = cancellation.cloned().unwrap_or_default();
            if derive_targets_for_rows(analyzer, file, &mut pending_rows, &token).is_err() {
                return false;
            }
            let mut shared = shared_store.as_ref().map(|shared_store| {
                shared_store
                    .lock()
                    .expect("a row-family occurrence cache lock is not poisoned")
            });
            let mut shared_roles = HashSet::default();
            for ((key, row), shareable) in pending_keys
                .into_iter()
                .zip(pending_rows)
                .zip(pending_shareable)
            {
                assert!(
                    !matches!(&row.target, OccurrenceTarget::NotDerived),
                    "the target batch derives every selected reference row"
                );
                self.targets.insert(key.clone(), row.target.clone());
                if shareable && let Some(shared) = shared.as_deref_mut() {
                    shared_roles.insert(key.role);
                    shared.targets.entry(key).or_insert(row.target);
                }
            }
            if !shared_roles.is_empty()
                && let Some(shared) = shared.as_deref_mut()
            {
                shared
                    .target_roles
                    .entry(file.clone())
                    .or_default()
                    .extend(shared_roles);
            }
        }

        for row in rows.iter_mut() {
            if row.class == OccurrenceClass::Reference
                && matches!(&row.target, OccurrenceTarget::NotDerived)
            {
                row.target = self
                    .targets
                    .get(&OccurrenceKey::from_row(row))
                    .expect("a requested occurrence target was derived in this query")
                    .clone();
            }
        }
        true
    }

    fn has_complete_occurrence_family(&self, file: &ProjectFile, role: OccurrenceRole) -> bool {
        self.complete_families
            .get(file)
            .is_some_and(|roles| roles.contains(&role))
    }

    fn record_complete_family(
        &mut self,
        file: &ProjectFile,
        roles: &[OccurrenceRole],
        result: &OccurrenceFileResult,
    ) {
        if roles.iter().all(|role| result.completeness.covers(*role)) {
            self.complete_families
                .entry(file.clone())
                .or_default()
                .extend(roles.iter().copied());
        }
    }

    /// Turn a file result's completeness into typed diagnostics, scoped to the
    /// roles the query actually depends on.
    ///
    /// A file whose adapter classifies no generated-source token is still
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
                        exhausted_roots: Vec::new(),
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
                        exhausted_roots: Vec::new(),
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
        OccurrenceKey::from_row(&self.row)
    }

    pub(super) fn file(&self) -> &ProjectFile {
        &self.row.file
    }
}

impl OccurrenceKey {
    fn from_row(row: &OccurrenceRow) -> Self {
        Self {
            file: row.file.clone(),
            node: row.node,
            role: row.role,
        }
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
        OccurrenceTarget::NotDerived => "not_derived",
    }
}
