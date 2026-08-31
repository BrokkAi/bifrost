//! C#'s `ImportAnalysisProvider` impl and the memo cells behind it.
//!
//! What a `using` directive *says* -- namespace, static-member target, or alias
//! -- moved to [`brokk_bifrost_csharp::imports`]; the caching, the reverse
//! import index and the implicit same-namespace reference index stay here
//! because they read the analyzer's own cells.

use crate::analyzer::CodeUnitIndex;
use crate::analyzer::{
    CodeUnit, CodeUnitType, ImportAnalysisProvider, ImportInfo, ImportReachability, ProjectFile,
};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use std::sync::Arc;

use super::CSharpAnalyzer;
use super::graph_support::{
    compute_implicit_reference_index, csharp_import_reachability, visible_type_candidates,
};
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
use brokk_bifrost_csharp::imports::{csharp_using_alias_from_import, csharp_using_namespace};
impl ImportAnalysisProvider for CSharpAnalyzer {
    fn file_dependency_facts_for_files(
        &self,
        files: &[ProjectFile],
    ) -> Option<crate::hash::HashMap<ProjectFile, crate::analyzer::FileDependencyFacts>> {
        let mut facts = self.inner.bulk_file_dependency_facts(files.iter().cloned());
        let test_files = self.hierarchy_test_files();
        for (file, facts) in &mut facts {
            if test_files.contains(file) {
                facts.contains_tests = Some(true);
            }
        }
        Some(facts)
    }

    fn imported_code_units_of(&self, file: &ProjectFile) -> Arc<HashSet<CodeUnit>> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        if let Some(cached) = self.memo_caches.imported_code_units.get(file) {
            return cached;
        }
        let namespaces = self.using_namespaces_of(token, file);
        let aliases = self.using_aliases_of(token, file);
        if namespaces.is_empty() && aliases.is_empty() {
            return Arc::new(HashSet::default());
        }
        let mut imported: HashSet<CodeUnit> = HashSet::default();
        for namespace in &namespaces {
            imported.extend(
                self.inner
                    .class_declarations_in_package(namespace)
                    .iter()
                    .cloned(),
            );
        }
        for target in aliases.values() {
            imported.extend(visible_type_candidates(self, token, file, target));
        }
        let imported = Arc::new(imported);
        self.memo_caches
            .imported_code_units
            .insert(file.clone(), Arc::clone(&imported));
        imported
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        if let Some(cached) = self.memo_caches.referencing_files.get(file) {
            return (*cached).clone();
        }
        let target_classes = self
            .declarations(file)
            .into_iter()
            .filter(|unit| unit.kind() == CodeUnitType::Class)
            .collect::<Vec<_>>();
        let target_namespaces: HashSet<String> = target_classes
            .iter()
            .map(|unit| unit.package_name().to_string())
            .collect();
        if target_namespaces.is_empty() {
            return HashSet::default();
        }
        let reverse_index = crate::analyzer::memoized_reverse_import_index(
            &self.memo_caches.reverse_import_index,
            || self.inner.all_files(),
            |candidate| self.imported_code_units_of(candidate),
        );
        let mut result = reverse_index
            .get(file)
            .map(|files| (**files).clone())
            .unwrap_or_default();

        if let Some(files) = self.implicit_reference_index(token).get(file) {
            result.extend(files.iter().cloned());
        }

        self.memo_caches
            .referencing_files
            .insert(file.clone(), Arc::new(result.clone()));
        result
    }

    fn import_info_of(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Vec<crate::analyzer::ImportInfo> {
        self.inner.import_info_of(token, file)
    }

    fn import_infos_for_files(
        &self,
        files: &[ProjectFile],
    ) -> Option<HashMap<ProjectFile, Vec<ImportInfo>>> {
        Some(self.inner.bulk_import_infos(files.iter().cloned()))
    }

    fn imported_files_from_infos(
        &self,
        file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<HashSet<ProjectFile>> {
        let files_by_namespace = self.file_dependencies_by_namespace();
        let mut imported = HashSet::default();
        let namespaces = imports
            .iter()
            .filter_map(csharp_using_namespace)
            .collect::<HashSet<_>>();
        for namespace in namespaces {
            if let Some(files) = files_by_namespace.get(&namespace) {
                imported.extend(files.iter().cloned());
            }
        }

        let aliases = imports
            .iter()
            .filter_map(csharp_using_alias_from_import)
            .collect::<HashMap<_, _>>();
        if !aliases.is_empty() {
            let scope = AnalyzerQueryScope::new(self);
            let token = scope.token();
            for target in aliases.values() {
                imported.extend(
                    visible_type_candidates(self, token, file, target)
                        .into_iter()
                        .map(|unit| unit.source().clone()),
                );
            }
        }
        Some(imported)
    }

    fn prefetch_file_dependency_targets(
        &self,
        _files: &[ProjectFile],
        imports: Option<&HashMap<ProjectFile, Vec<ImportInfo>>>,
        cancellation: &CancellationToken,
    ) {
        if !cancellation.is_cancelled() {
            let _ = self.file_dependencies_by_namespace();
            let _ = self.compilation_index();
            if let Some(imports) = imports {
                let mut global_using_files = imports
                    .iter()
                    .filter(|(_, imports)| imports.iter().any(|import| import.is_global))
                    .map(|(file, _)| file.clone())
                    .collect::<Vec<_>>();
                global_using_files.sort();
                global_using_files.dedup();
                let _ = self.memo_caches.global_using_files.set(global_using_files);
            }
        }
    }

    fn additional_direct_file_dependencies(
        &self,
        files: &[ProjectFile],
        cancellation: &CancellationToken,
    ) -> Option<crate::analyzer::AdditionalFileDependencies> {
        let global_using_files = self.memo_caches.global_using_files.get_or_init(|| {
            let imports = self.inner.bulk_import_infos(files.iter().cloned());
            let mut global_using_files = imports
                .into_iter()
                .filter(|(_, imports)| imports.iter().any(|import| import.is_global))
                .map(|(file, _)| file)
                .collect::<Vec<_>>();
            global_using_files.sort();
            global_using_files.dedup();
            global_using_files
        });
        if cancellation.is_cancelled() {
            return None;
        }
        let compilation_index = self.compilation_index();
        if !compilation_index.is_complete() && crate::profiling::enabled() {
            crate::profiling::note(format!(
                "csharp compilation scopes unresolved: {:?}",
                compilation_index.unresolved_scopes()
            ));
        }
        let dependencies = if global_using_files.is_empty() {
            HashMap::default()
        } else {
            compilation_index.global_using_dependencies(files, global_using_files.as_slice())
        };
        if cancellation.is_cancelled() {
            return None;
        }
        Some(if compilation_index.is_complete() {
            crate::analyzer::AdditionalFileDependencies::complete(dependencies)
        } else {
            crate::analyzer::AdditionalFileDependencies::incomplete(dependencies)
        })
    }

    /// Derived from [`Self::import_reachability`] rather than written
    /// separately: the two spellings answer one question, and only the
    /// three-valued one distinguishes a proven "no" from an undecided one.
    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[crate::analyzer::ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        matches!(
            self.import_reachability(source_file, imports, target),
            ImportReachability::Reaches
        )
    }

    fn import_reachability(
        &self,
        source_file: &ProjectFile,
        imports: &[crate::analyzer::ImportInfo],
        target: &ProjectFile,
    ) -> ImportReachability {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        csharp_import_reachability(self, token, source_file, imports, target)
    }
}

impl CSharpAnalyzer {
    fn file_dependencies_by_namespace(&self) -> Arc<HashMap<String, Arc<Vec<ProjectFile>>>> {
        self.memo_caches
            .file_dependencies_by_namespace
            .get_or_build_on_dedicated_pool(|| {
                let mut grouped: HashMap<String, HashSet<ProjectFile>> = HashMap::default();
                for unit in self
                    .inner
                    .all_declarations()
                    .filter(|unit| unit.kind() == CodeUnitType::Class)
                {
                    grouped
                        .entry(unit.package_name().to_string())
                        .or_default()
                        .insert(unit.source().clone());
                }
                grouped
                    .into_iter()
                    .map(|(namespace, files)| {
                        let mut files = files.into_iter().collect::<Vec<_>>();
                        files.sort();
                        (namespace, Arc::new(files))
                    })
                    .collect()
            })
    }

    fn implicit_reference_index(
        &self,
        token: QueryToken<'_>,
    ) -> Arc<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>> {
        self.memo_caches.implicit_reference_index.get_or_build(
            || compute_implicit_reference_index(self, token, true),
            || compute_implicit_reference_index(self, token, false),
        )
    }
}
