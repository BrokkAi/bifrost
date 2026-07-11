use std::path::Path;
use std::sync::Arc;

use git2::Oid;

use crate::analyzer::store::liveness::{LiveSnapshot, Liveness};
use crate::analyzer::store::{CandidateRow, Result, StoreError};
use crate::analyzer::tree_sitter_analyzer::LanguageAdapter;
use crate::analyzer::{CodeUnit, ProjectFile};
use crate::hash::HashSet;

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
        let rows: Vec<_> = rows.into_iter().collect();
        let mut stale = HashSet::default();
        let mut files = HashSet::default();
        for (row, _) in &rows {
            if !self.snapshot.contains_oid(row.blob_oid) {
                continue;
            }
            files.extend(self.paths_for_row(row));
        }
        stale.extend(self.snapshot.validate(files.iter()));

        let mut out = Vec::new();
        for (row, payload) in rows {
            for file in self.paths_for_row(&row) {
                if stale.contains(&file) {
                    continue;
                }
                out.push((self.code_unit_for_row(&row, &file), payload.clone()));
            }
        }
        out
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
        let package_name = self
            .adapter
            .hydrate_content_qualifier(&row.content_qualifier, file);
        CodeUnit::with_signature(
            file.clone(),
            row.kind,
            package_name,
            row.short_name.clone(),
            row.signature.clone(),
            row.flags.synthetic,
        )
    }
}
