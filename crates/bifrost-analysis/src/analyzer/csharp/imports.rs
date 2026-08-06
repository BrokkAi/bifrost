//! C#'s `ImportAnalysisProvider` impl and the memo cells behind it.
//!
//! What a `using` directive *says* -- namespace, static-member target, or alias
//! -- moved to [`brokk_bifrost_csharp::imports`]; the caching, the reverse
//! import index and the implicit same-namespace reference index stay here
//! because they read the analyzer's own cells.

use crate::analyzer::CodeUnitIndex;
use crate::analyzer::{
    CodeUnit, CodeUnitType, ImportAnalysisProvider, ImportReachability, ProjectFile,
};
use crate::hash::{HashMap, HashSet};
use std::sync::Arc;

use super::CSharpAnalyzer;
use super::graph_support::{
    compute_implicit_reference_index, csharp_import_reachability, visible_type_candidates,
};
impl ImportAnalysisProvider for CSharpAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> HashSet<CodeUnit> {
        if let Some(cached) = self.memo_caches.imported_code_units.get(file) {
            return (*cached).clone();
        }
        let namespaces = self.using_namespaces_of(file);
        let aliases = self.using_aliases_of(file);
        if namespaces.is_empty() && aliases.is_empty() {
            return HashSet::default();
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
            imported.extend(visible_type_candidates(self, file, target));
        }
        self.memo_caches
            .imported_code_units
            .insert(file.clone(), Arc::new(imported.clone()));
        imported
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
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

        if let Some(files) = self.implicit_reference_index().get(file) {
            result.extend(files.iter().cloned());
        }

        self.memo_caches
            .referencing_files
            .insert(file.clone(), Arc::new(result.clone()));
        result
    }

    fn import_info_of(&self, file: &ProjectFile) -> Vec<crate::analyzer::ImportInfo> {
        self.inner.import_info_of(file)
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
        csharp_import_reachability(self, source_file, imports, target)
    }
}

impl CSharpAnalyzer {
    fn implicit_reference_index(&self) -> Arc<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>> {
        self.memo_caches.implicit_reference_index.get_or_build(
            || compute_implicit_reference_index(self, true),
            || compute_implicit_reference_index(self, false),
        )
    }
}
