//! `ImportAnalysisProvider` for Rust: the memoization shell around
//! [`brokk_bifrost_rust::imports`].
//!
//! Only the caching stays here. The two moka caches are analyzer state, so each
//! method below fetches or fills a cache slot and hands the actual resolution to
//! the Rust crate through the [`RustSource`] the analyzer implements.

use crate::analyzer::{CodeUnit, ImportAnalysisProvider, ImportInfo, ProjectFile};
use crate::hash::HashSet;
use brokk_bifrost_rust::imports::{rust_could_import_file, rust_imported_code_units};
use std::sync::Arc;

use super::RustAnalyzer;

impl ImportAnalysisProvider for RustAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> HashSet<CodeUnit> {
        if let Some(cached) = self.imported_code_units.get(file) {
            return (*cached).clone();
        }

        let resolved = rust_imported_code_units(self, file, &self.inner.import_info_of(file));

        self.imported_code_units
            .insert(file.clone(), Arc::new(resolved.clone()));
        resolved
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        if let Some(cached) = self.referencing_files.get(file) {
            return (*cached).clone();
        }

        let reverse_index = crate::analyzer::memoized_reverse_import_index(
            &self.reverse_import_index,
            || self.inner.all_files(),
            |candidate| self.imported_code_units_of(candidate),
        );
        let referencing = reverse_index
            .get(file)
            .map(|files| (**files).clone())
            .unwrap_or_default();
        self.referencing_files
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
        Some(
            imports
                .iter()
                .filter_map(|import| import.path.as_ref())
                .flat_map(|path| {
                    brokk_bifrost_rust::graph_support::resolve_direct_import_files(
                        self,
                        file,
                        &path.segments,
                    )
                })
                .collect(),
        )
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        rust_could_import_file(self, source_file, imports, target)
    }
}
