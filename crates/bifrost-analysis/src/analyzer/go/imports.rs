//! `ImportAnalysisProvider` for Go: the memoization shell around
//! [`brokk_bifrost_go::imports`].
//!
//! Only the caching stays here. `GoMemoCaches` is moka-backed and moka is
//! deliberately kept out of `brokk-bifrost-go` and out of core, so each method
//! below fetches or fills a cache slot and hands the actual resolution to the
//! Go crate along with the file list and workspace path index it needs.

use crate::analyzer::CodeUnitIndex;
use crate::analyzer::{CodeUnit, ImportAnalysisProvider, ImportInfo, ProjectFile};
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_go::imports::{
    GoImportTables, build_go_dir_parent_files, build_go_dir_parent_suffix_files,
    build_go_package_files, dir_suffix_matches, extract_go_import_path,
    go_directory_sibling_import_files, go_imported_code_units_of, go_matching_import_files,
    go_package_of, go_relevant_imports_for,
};
use std::sync::Arc;

use super::GoAnalyzer;

impl ImportAnalysisProvider for GoAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> Arc<HashSet<CodeUnit>> {
        if let Some(cached) = self.memo_caches.imported_code_units.get(file) {
            return cached;
        }

        let resolved = Arc::new(go_imported_code_units_of(
            &self.inner,
            &self.import_tables(),
            file,
            &self.inner.import_info_of(file),
        ));

        self.memo_caches
            .imported_code_units
            .insert(file.clone(), Arc::clone(&resolved));
        resolved
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        if let Some(cached) = self.memo_caches.referencing_files.get(file) {
            return (*cached).clone();
        }

        let reverse_index = crate::analyzer::memoized_reverse_import_index(
            &self.memo_caches.reverse_import_index,
            || self.inner.all_files(),
            |candidate| self.imported_code_units_of(candidate),
        );
        let referencing = reverse_index
            .get(file)
            .map(|files| (**files).clone())
            .unwrap_or_default();
        self.memo_caches
            .referencing_files
            .insert(file.clone(), Arc::new(referencing.clone()));
        referencing
    }

    fn import_info_of(&self, file: &ProjectFile) -> Vec<ImportInfo> {
        self.inner.import_info_of(file)
    }

    fn imported_files_from_infos(
        &self,
        file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<HashSet<ProjectFile>> {
        let tables = self.import_tables();
        Some(
            imports
                .iter()
                .filter_map(|import| extract_go_import_path(&import.raw_snippet))
                .flat_map(|path| {
                    let resolved = go_matching_import_files(&tables, file, &path);
                    if !resolved.is_empty() {
                        return resolved;
                    }
                    // Only the fallback needs the whole analyzed file list.
                    go_directory_sibling_import_files(
                        self.workspace_path_index(),
                        &self.inner.all_files(),
                        file,
                        &path,
                    )
                })
                .collect(),
        )
    }

    fn relevant_imports_for(&self, code_unit: &CodeUnit) -> HashSet<String> {
        let source = self.inner.get_source(code_unit, false).unwrap_or_default();
        go_relevant_imports_for(&source, &self.inner.import_info_of(code_unit.source()))
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        let target_pkg = self.go_package_of(target);
        imports.iter().any(|import| {
            let Some(path) = extract_go_import_path(&import.raw_snippet) else {
                return false;
            };
            target_pkg.as_deref() == Some(path.as_str()) || dir_suffix_matches(target, &path)
        }) || self
            .imported_code_units_of(source_file)
            .iter()
            .any(|code_unit| code_unit.source() == target)
    }
}

impl GoAnalyzer {
    /// Resolve only `file`'s namespace from persisted import and package facts.
    /// This deliberately avoids the whole-workspace package graph used by bulk
    /// usage analysis.
    pub(crate) fn definition_import_namespaces(
        &self,
        file: &ProjectFile,
    ) -> (HashMap<String, Vec<String>>, Vec<String>) {
        brokk_bifrost_go::imports::go_definition_import_namespaces(
            &self.inner,
            self.workspace_path_index(),
            |candidate| self.package_clause_of(candidate),
            file,
            &self.inner.import_info_of(file),
        )
    }

    /// Canonical package identity (import path) of a file, taken from any of
    /// its declarations. `None` for files with no top-level declarations.
    pub(super) fn go_package_of(&self, file: &ProjectFile) -> Option<String> {
        go_package_of(&self.inner, file)
    }

    fn import_tables(&self) -> GoImportTables<'_> {
        GoImportTables {
            package_files: self.package_files(),
            dir_parent_files: self.dir_parent_files(),
            dir_parent_suffix_files: self.dir_parent_suffix_files(),
        }
    }

    fn package_files(&self) -> &HashMap<String, Arc<Vec<ProjectFile>>> {
        self.memo_caches
            .package_files
            .get_or_init(|| build_go_package_files(&self.inner, &self.inner.all_files()))
    }

    fn dir_parent_files(&self) -> &HashMap<String, Arc<Vec<ProjectFile>>> {
        self.memo_caches
            .dir_parent_files
            .get_or_init(|| build_go_dir_parent_files(&self.inner, &self.inner.all_files()))
    }

    fn dir_parent_suffix_files(&self) -> &HashMap<String, Arc<Vec<ProjectFile>>> {
        self.memo_caches
            .dir_parent_suffix_files
            .get_or_init(|| build_go_dir_parent_suffix_files(&self.inner, &self.inner.all_files()))
    }
}
