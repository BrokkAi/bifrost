//! C#'s `ImportAnalysisProvider` impl and the memo cells behind it.
//!
//! What a `using` directive *says* -- namespace, static-member target, or alias
//! -- moved to [`brokk_bifrost_csharp::imports`]; the caching, the reverse
//! import index and the implicit same-namespace reference index stay here
//! because they read the analyzer's own cells.

use crate::analyzer::CodeUnitIndex;
use crate::analyzer::{CodeUnit, CodeUnitType, ImportAnalysisProvider, ProjectFile};
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_csharp::imports::csharp_using_namespace;
use std::sync::Arc;

use super::CSharpAnalyzer;
use super::graph_support::{compute_implicit_reference_index, visible_type_candidates};
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

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[crate::analyzer::ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        let target_classes = self
            .declarations(target)
            .into_iter()
            .filter(|unit| unit.kind() == CodeUnitType::Class)
            .collect::<Vec<_>>();
        let arity_sensitive = target_classes
            .iter()
            .any(|unit| unit.identifier().contains('`'));
        if self.namespace_of_file(source_file) == self.namespace_of_file(target) && !arity_sensitive
        {
            return true;
        }
        let target_namespaces: HashSet<String> = target_classes
            .iter()
            .map(|unit| unit.package_name().to_string())
            .collect();
        let target_names: HashSet<String> = target_classes
            .iter()
            .flat_map(|unit| {
                let fq_name = unit.fq_name();
                [
                    unit.identifier().to_string(),
                    fq_name.clone(),
                    fq_name.replace('$', "."),
                ]
            })
            .collect();
        let source_aliases = self.using_aliases_of(source_file);
        if let Some(identifiers) = self.inner.type_identifiers_of(source_file) {
            for identifier in identifiers {
                if target_names.contains(&identifier) {
                    return true;
                }
                if identifier
                    .strip_prefix("global::")
                    .is_some_and(|global_name| target_names.contains(global_name))
                {
                    return true;
                }
                let uses_namespace_alias = source_aliases.keys().any(|alias| {
                    identifier
                        .strip_prefix(alias)
                        .is_some_and(|suffix| suffix.starts_with("::"))
                });
                if uses_namespace_alias {
                    let candidates = visible_type_candidates(self, source_file, &identifier);
                    if target_classes
                        .iter()
                        .any(|target| candidates.contains(target))
                    {
                        return true;
                    }
                }
            }
        }
        let source_imports = self.using_namespaces_of(source_file);
        imports
            .iter()
            .filter_map(|import| csharp_using_namespace(&import.raw_snippet))
            .chain(source_imports)
            .any(|namespace| target_namespaces.contains(&namespace))
            || source_aliases.values().any(|alias_target| {
                let candidates = visible_type_candidates(self, source_file, alias_target);
                self.declarations(target)
                    .into_iter()
                    .filter(|unit| unit.kind() == CodeUnitType::Class)
                    .any(|unit| candidates.contains(&unit))
            })
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
