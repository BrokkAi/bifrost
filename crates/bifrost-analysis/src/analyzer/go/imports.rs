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
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_go::imports::{
    GoImportTables, dir_suffix_matches, go_directory_sibling_import_files, go_import_path,
    go_imported_code_units_of, go_matching_import_files, go_relevant_imports_for, parent_path_key,
    path_suffixes,
};
use std::sync::Arc;

use super::GoAnalyzer;
use crate::analyzer::{AnalyzerQueryScope, QueryScope};

impl ImportAnalysisProvider for GoAnalyzer {
    fn file_dependency_facts_for_files(
        &self,
        files: &[ProjectFile],
    ) -> Option<crate::hash::HashMap<ProjectFile, crate::analyzer::FileDependencyFacts>> {
        Some(self.inner.bulk_file_dependency_facts(files.iter().cloned()))
    }

    fn imported_code_units_of(&self, file: &ProjectFile) -> Arc<HashSet<CodeUnit>> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        if let Some(cached) = self.memo_caches.imported_code_units.get(file) {
            return cached;
        }

        let resolved = Arc::new(go_imported_code_units_of(
            &self.inner,
            &self.import_tables(),
            file,
            &self.inner.import_info_of(token, file),
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

    fn import_info_of(&self, token: QueryToken<'_>, file: &ProjectFile) -> Vec<ImportInfo> {
        self.inner.import_info_of(token, file)
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
                .filter_map(go_import_path)
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
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        let source = self.inner.get_source(code_unit, false).unwrap_or_default();
        go_relevant_imports_for(
            &source,
            &self.inner.import_info_of(token, code_unit.source()),
        )
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        let target_pkg = self.go_package_of(target);
        imports.iter().any(|import| {
            let Some(path) = go_import_path(import) else {
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
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> (HashMap<String, Vec<String>>, Vec<String>) {
        brokk_bifrost_go::imports::go_definition_import_namespaces(
            &self.inner,
            self.workspace_path_index(),
            |candidate| self.package_clause_of(candidate),
            file,
            &self.inner.import_info_of(token, file),
        )
    }

    /// Canonical package identity (import path) of a file, taken from any of
    /// its persisted package-clause fact. This remains available in the
    /// file-dependency build, which intentionally omits declarations.
    pub(super) fn go_package_of(&self, file: &ProjectFile) -> Option<String> {
        let declared = self.inner.content_qualifier_of(file)?;
        (!declared.is_empty()).then(|| {
            self.workspace_path_index()
                .canonical_package_name(file, &declared)
        })
    }

    fn import_tables(&self) -> GoImportTables<'_> {
        GoImportTables {
            package_files: self.package_files(),
            dir_parent_files: self.dir_parent_files(),
            dir_parent_suffix_files: self.dir_parent_suffix_files(),
        }
    }

    fn package_files(&self) -> &HashMap<String, Arc<Vec<ProjectFile>>> {
        self.memo_caches.package_files.get_or_init(|| {
            let mut grouped: HashMap<String, Vec<ProjectFile>> = HashMap::default();
            for file in self.inner.all_files() {
                if let Some(package) = self.go_package_of(&file) {
                    grouped.entry(package).or_default().push(file);
                }
            }
            grouped
                .into_iter()
                .map(|(package, files)| (package, Arc::new(files)))
                .collect()
        })
    }

    fn dir_parent_files(&self) -> &HashMap<String, Arc<Vec<ProjectFile>>> {
        self.memo_caches.dir_parent_files.get_or_init(|| {
            let mut grouped: HashMap<String, Vec<ProjectFile>> = HashMap::default();
            for file in self.inner.all_files() {
                if self.go_package_of(&file).is_some() {
                    grouped
                        .entry(parent_path_key(&file))
                        .or_default()
                        .push(file);
                }
            }
            grouped
                .into_iter()
                .map(|(parent, files)| (parent, Arc::new(files)))
                .collect()
        })
    }

    fn dir_parent_suffix_files(&self) -> &HashMap<String, Arc<Vec<ProjectFile>>> {
        self.memo_caches.dir_parent_suffix_files.get_or_init(|| {
            let mut grouped: HashMap<String, Vec<ProjectFile>> = HashMap::default();
            for file in self.inner.all_files() {
                if self.go_package_of(&file).is_none() {
                    continue;
                }
                let parent = parent_path_key(&file);
                for suffix in path_suffixes(&parent) {
                    grouped
                        .entry(suffix.to_string())
                        .or_default()
                        .push(file.clone());
                }
            }
            grouped
                .into_iter()
                .map(|(suffix, files)| (suffix, Arc::new(files)))
                .collect()
        })
    }
}
