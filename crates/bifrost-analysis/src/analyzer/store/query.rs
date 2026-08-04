use std::path::Path;
use std::sync::Arc;

use git2::Oid;

use crate::CancellationToken;
use crate::analyzer::store::liveness::{LiveSnapshot, Liveness};
use crate::analyzer::store::{
    CandidateRow, LimitedQueryRows, Result, SearchCandidateKey, SearchCandidateNameRow, StoreError,
};
use crate::analyzer::tree_sitter_analyzer::LanguageAdapter;
use crate::analyzer::{CodeUnit, ProjectFile};
use crate::hash::{HashMap, HashSet};

pub struct QueryResolver<'a, A: LanguageAdapter> {
    adapter: &'a A,
    project_root: &'a Path,
    snapshot: Arc<LiveSnapshot>,
}

impl<'a, A: LanguageAdapter> QueryResolver<'a, A> {
    pub fn from_snapshot(
        adapter: &'a A,
        project_root: &'a Path,
        snapshot: Arc<LiveSnapshot>,
    ) -> Self {
        Self {
            adapter,
            project_root,
            snapshot,
        }
    }

    pub fn from_liveness(
        adapter: &'a A,
        project_root: &'a Path,
        liveness: &'a Liveness,
    ) -> Result<Self> {
        let snapshot = liveness.snapshot().map_err(StoreError::new)?;
        Ok(Self::from_snapshot(adapter, project_root, snapshot))
    }

    pub fn resolve_rows(&self, rows: impl IntoIterator<Item = CandidateRow>) -> Vec<CodeUnit> {
        self.resolve_rows_with_payload(rows.into_iter().map(|row| (row, ())))
            .into_iter()
            .map(|(unit, ())| unit)
            .collect()
    }

    pub fn resolve_rows_with_payload<T>(
        &self,
        rows: impl IntoIterator<Item = (CandidateRow, T)>,
    ) -> Vec<(CodeUnit, T)>
    where
        T: Clone,
    {
        self.resolve_rows_with_payload_while(rows, || true).rows
    }

    pub(crate) fn resolve_rows_with_payload_cancellable<T>(
        &self,
        rows: impl IntoIterator<Item = (CandidateRow, T)>,
        cancellation: Option<&CancellationToken>,
    ) -> LimitedQueryRows<(CodeUnit, T)>
    where
        T: Clone,
    {
        match cancellation {
            Some(cancellation) => {
                self.resolve_rows_with_payload_while(rows, || !cancellation.is_cancelled())
            }
            None => self.resolve_rows_with_payload_while(rows, || true),
        }
    }

    fn resolve_rows_with_payload_while<T>(
        &self,
        rows: impl IntoIterator<Item = (CandidateRow, T)>,
        mut continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<(CodeUnit, T)>
    where
        T: Clone,
    {
        let rows: Vec<_> = rows.into_iter().collect();
        let mut inspected = 0usize;
        let mut files = HashSet::default();
        for (row, _) in &rows {
            if !continue_query() {
                return LimitedQueryRows::incomplete(Vec::new(), inspected);
            }
            inspected = inspected.saturating_add(1);
            if self.snapshot.contains_oid(row.blob_oid) {
                files.extend(self.paths_for_row(row));
            }
        }

        if !continue_query() {
            return LimitedQueryRows::incomplete(Vec::new(), inspected);
        }
        let stale: HashSet<_> = self.snapshot.validate(files.iter()).into_iter().collect();
        if !continue_query() {
            return LimitedQueryRows::incomplete(Vec::new(), inspected);
        }

        let mut out = Vec::new();
        for (row, payload) in rows {
            if !continue_query() {
                return LimitedQueryRows::incomplete(out, inspected);
            }
            inspected = inspected.saturating_add(1);
            for file in self.paths_for_row(&row) {
                if !continue_query() {
                    return LimitedQueryRows::incomplete(out, inspected);
                }
                if !stale.contains(&file) {
                    out.push((self.code_unit_for_row(&row, &file), payload.clone()));
                }
            }
        }

        LimitedQueryRows::complete(out, inspected)
    }

    /// Decide which persisted declarations a `search_symbols` pattern batch can
    /// match, using only the cheap name projection.
    ///
    /// A unit's fully-qualified name is `package_name` plus its short name, and
    /// `package_name` is hydrated from the persisted content qualifier together
    /// with the live path the blob is mounted at. Both inputs are constant per
    /// `(blob, language)` and per `(blob, language, qualifier)` respectively, so
    /// they are memoized: a workspace with tens of thousands of declarations
    /// spread over a few hundred files hydrates a few hundred package prefixes
    /// instead of one per declaration (issue #1199).
    ///
    /// Liveness is intentionally *not* applied here. This pass only narrows the
    /// key set; the full hydration pass re-applies stat validation and the
    /// authoritative match predicate, so this must stay a superset and must not
    /// become the place where a candidate is finally accepted.
    pub(crate) fn match_candidate_names_cancellable(
        &self,
        langs: &[String],
        rows: &[SearchCandidateNameRow],
        mut keep: impl FnMut(&str, &str) -> bool,
        cancellation: Option<&CancellationToken>,
    ) -> LimitedQueryRows<SearchCandidateKey> {
        let mut paths: HashMap<(Oid, usize), Vec<ProjectFile>> = HashMap::default();
        let mut packages: HashMap<(Oid, usize, &str), Vec<String>> = HashMap::default();
        let mut out = Vec::new();
        let mut inspected = 0usize;
        for row in rows {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return LimitedQueryRows::incomplete(out, inspected);
            }
            inspected = inspected.saturating_add(1);
            let Some(lang) = langs.get(row.lang_index) else {
                continue;
            };
            let files = paths
                .entry((row.blob_oid, row.lang_index))
                .or_insert_with(|| {
                    self.paths_for_oid(row.blob_oid)
                        .into_iter()
                        .filter(|file| self.adapter.storage_language_key_for_file(file) == *lang)
                        .collect()
                });
            if files.is_empty() {
                continue;
            }
            let package_names = packages
                .entry((row.blob_oid, row.lang_index, row.content_qualifier.as_str()))
                .or_insert_with(|| {
                    files
                        .iter()
                        .map(|file| {
                            self.adapter
                                .hydrate_content_qualifier(&row.content_qualifier, file)
                        })
                        .collect()
                });
            if package_names
                .iter()
                .any(|package_name| keep(package_name, &row.short_name))
            {
                out.push(SearchCandidateKey {
                    lang_index: row.lang_index,
                    blob_oid: row.blob_oid,
                    unit_key: row.unit_key,
                });
            }
        }
        LimitedQueryRows::complete(out, inspected)
    }

    fn paths_for_oid(&self, oid: Oid) -> Vec<ProjectFile> {
        self.snapshot
            .paths_for_oid(oid)
            .iter()
            .cloned()
            .filter_map(|file| self.rebase_to_project_root(&file))
            .collect()
    }

    fn paths_for_row(&self, row: &CandidateRow) -> Vec<ProjectFile> {
        self.paths_for_oid(row.blob_oid)
            .into_iter()
            .filter(|file| self.adapter.storage_language_key_for_file(file) == row.lang)
            .collect()
    }

    fn rebase_to_project_root(&self, file: &ProjectFile) -> Option<ProjectFile> {
        crate::analyzer::common::rebase_project_file_to_root(file, self.project_root)
    }

    fn code_unit_for_row(&self, row: &CandidateRow, file: &ProjectFile) -> CodeUnit {
        let (fq, package_segment_count) = crate::analyzer::store::hydrate_unit_fq(
            self.adapter,
            row.fq_segments.as_deref(),
            &row.content_qualifier,
            file,
        )
        .expect("candidate row must contain a valid structured FqName");
        CodeUnit::from_fq(
            file.clone(),
            row.kind,
            fq,
            package_segment_count,
            row.signature.clone(),
            row.flags.synthetic,
        )
    }
}
