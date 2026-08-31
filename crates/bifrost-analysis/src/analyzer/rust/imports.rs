//! `ImportAnalysisProvider` for Rust: the memoization shell around
//! [`brokk_bifrost_rust::imports`].
//!
//! Only the caching stays here. The two moka caches are analyzer state, so each
//! method below fetches or fills a cache slot and hands the actual resolution to
//! the Rust crate through the [`RustSource`] the analyzer implements.

use crate::analyzer::{CodeUnit, ImportAnalysisProvider, ImportInfo, ProjectFile};
use crate::hash::HashSet;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_rust::declarations::rust_package_name;
use brokk_bifrost_rust::imports::{
    resolve_rust_import_fq_name, rust_could_import_file, rust_imported_code_units,
};
use std::sync::Arc;

use super::RustAnalyzer;
use crate::analyzer::{AnalyzerQueryScope, QueryScope};

impl ImportAnalysisProvider for RustAnalyzer {
    fn file_dependency_facts_for_files(
        &self,
        files: &[ProjectFile],
    ) -> Option<crate::hash::HashMap<ProjectFile, crate::analyzer::FileDependencyFacts>> {
        Some(self.inner.bulk_file_dependency_facts(files.iter().cloned()))
    }

    fn imported_code_units_of(&self, file: &ProjectFile) -> Arc<HashSet<CodeUnit>> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        if let Some(cached) = self.imported_code_units.get(file) {
            return cached;
        }

        let resolved = Arc::new(rust_imported_code_units(
            self,
            file,
            &self.inner.import_info_of(token, file),
        ));

        self.imported_code_units
            .insert(file.clone(), Arc::clone(&resolved));
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

    fn import_info_of(&self, token: QueryToken<'_>, file: &ProjectFile) -> Vec<ImportInfo> {
        self.inner.import_info_of(token, file)
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

    fn additional_direct_file_dependencies(
        &self,
        files: &[ProjectFile],
        cancellation: &crate::cancellation::CancellationToken,
    ) -> Option<crate::analyzer::AdditionalFileDependencies> {
        let routes = self.cargo_routes_while(&|| !cancellation.is_cancelled())?;
        let selected: HashSet<_> = files.iter().cloned().collect();
        let mut dependencies: crate::hash::HashMap<ProjectFile, HashSet<ProjectFile>> =
            crate::hash::HashMap::default();
        for declaration in routes.external_module_declarations() {
            if cancellation.is_cancelled() {
                return None;
            }
            if selected.contains(&declaration.declaring_file)
                && selected.contains(&declaration.target_file)
            {
                dependencies
                    .entry(declaration.declaring_file.clone())
                    .or_default()
                    .insert(declaration.target_file.clone());
            }
        }
        Some(crate::analyzer::AdditionalFileDependencies::complete(
            dependencies,
        ))
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        rust_could_import_file(self, source_file, imports, target)
    }

    /// Rust answers "could this file import the target" by resolving each
    /// `use` path to an fq name and asking the store which files define it,
    /// so the shared candidate walk charged one `definition_candidates` query
    /// per `use` statement in the workspace (#1748). Every path the walk will
    /// ask about is derivable from the import facts it already has, so resolve
    /// them all here and hand the whole set to one batched store read.
    fn prefetch_import_targets(
        &self,
        files: &[ProjectFile],
        import_infos: Option<&crate::hash::HashMap<ProjectFile, Vec<ImportInfo>>>,
        cancellation: &crate::cancellation::CancellationToken,
    ) {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        use rayon::prelude::*;

        let mut fq_names: Vec<String> = files
            .par_iter()
            .flat_map_iter(|file| {
                if cancellation.is_cancelled() {
                    return Vec::new().into_iter();
                }
                let package = rust_package_name(file);
                let imports = import_infos
                    .and_then(|infos| infos.get(file).cloned())
                    .unwrap_or_else(|| self.inner.import_info_of(token, file));
                imports
                    .iter()
                    .filter_map(|import| {
                        resolve_rust_import_fq_name(file, &package, &import.raw_snippet)
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
            })
            .collect();
        if cancellation.is_cancelled() {
            return;
        }
        fq_names.sort_unstable();
        fq_names.dedup();
        self.inner.prefetch_definitions(&fq_names);
    }
}
