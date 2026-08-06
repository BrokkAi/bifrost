//! `KotlinAnalyzer`'s own import resolution (#1237).
//!
//! The node-reading half -- the structured [`ImportInfo`] a Kotlin
//! `import_header` decodes to, the dotted path it names, and the default
//! import packages -- moved to [`brokk_bifrost_jvm::kotlin::imports`]. What is
//! left needs the analyzer: two realm-keyed moka caches, the
//! once-per-generation package export table, the same-package reference index,
//! and the `ImportAnalysisProvider` impl those three answer.

use crate::analyzer::CodeUnitIndex;
use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::{
    CodeUnit, IAnalyzer, ImportAnalysisProvider, ImportInfo, Language, ProjectFile,
    build_reverse_file_index,
};
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_jvm::kotlin::imports::is_kotlin_importable_top_level;
pub(crate) use brokk_bifrost_jvm::kotlin::imports::{
    KOTLIN_DEFAULT_IMPORT_PACKAGES, kotlin_import_path,
};
use brokk_bifrost_jvm::realm::JvmSourceRealm;
use std::sync::Arc;

use super::KotlinAnalyzer;

impl KotlinAnalyzer {
    /// Every declaration an import path can name directly.
    ///
    /// Kotlin fully-qualified names are dotted all the way down — package
    /// segments, nested types, and members alike — so `import a.b.Outer.Inner`
    /// and `import a.b.Registry.register` are the same single lookup as
    /// `import a.b.C`, with no need to split the path and walk owners.
    fn declarations_named(&self, fqn: &str, realm: Option<&JvmSourceRealm<'_>>) -> Vec<CodeUnit> {
        let mut units: Vec<CodeUnit> = IAnalyzer::global_usage_definition_index(&self.inner)
            .fqn(fqn)
            .iter()
            .filter(|unit| unit.fq_name() == fqn && !unit.is_synthetic())
            .cloned()
            .collect();
        // A Kotlin file can import a Java or Scala declaration from the same
        // workspace, so the realm's other members answer for the names Kotlin's
        // own index does not hold.
        if let Some(realm) = realm {
            units.extend(realm.peer_declarations_by_fqn(fqn, Language::Kotlin));
        }
        units
    }

    /// The top-level declarations a Kotlin package exports, keyed by package.
    ///
    /// Built once per analyzer generation because a star import has to widen
    /// to a whole package and repeating that scan per file would be quadratic
    /// in workspace size.
    pub(crate) fn top_level_declarations_by_package(&self) -> &HashMap<String, Arc<Vec<CodeUnit>>> {
        self.top_level_declarations_by_package.get_or_init(|| {
            let mut by_package: HashMap<String, Vec<CodeUnit>> = HashMap::default();
            for unit in self.inner.all_declarations() {
                if is_kotlin_importable_top_level(&unit) {
                    by_package
                        .entry(unit.package_name().to_string())
                        .or_default()
                        .push(unit);
                }
            }
            by_package
                .into_iter()
                .map(|(package, units)| (package, Arc::new(units)))
                .collect()
        })
    }

    /// The declarations a star import over `path` makes visible.
    ///
    /// `path` is a package (`import a.b.*`) or a single object-like owner
    /// (`import a.b.Mode.*`, which imports an enum's entries or an object's
    /// members). Both forms are legal Kotlin and are distinguished by what the
    /// workspace actually declares, not by guessing from the spelling.
    fn star_imported_declarations(
        &self,
        path: &str,
        realm: Option<&JvmSourceRealm<'_>>,
    ) -> Vec<CodeUnit> {
        if let Some(units) = self.top_level_declarations_by_package().get(path) {
            return units.as_ref().clone();
        }
        self.declarations_named(path, realm)
            .iter()
            .filter(|owner| owner.is_class())
            .flat_map(|owner| self.inner.direct_children(owner))
            .filter(|unit| !unit.is_synthetic())
            .collect()
    }

    fn resolve_import_infos(
        &self,
        imports: &[ImportInfo],
        realm: Option<&JvmSourceRealm<'_>>,
    ) -> HashSet<CodeUnit> {
        let mut resolved = HashSet::default();
        for import in imports {
            let Some(path) = kotlin_import_path(import) else {
                continue;
            };
            if import.is_wildcard {
                resolved.extend(self.star_imported_declarations(&path, realm));
            } else {
                resolved.extend(self.declarations_named(&path, realm));
            }
        }
        resolved
    }

    /// The declarations a Kotlin file imports, widened to the whole JVM source
    /// realm when a realm view is supplied.
    ///
    /// The realm-aware and realm-less answers are cached separately: a
    /// Kotlin-only result must never be served to a caller that can also see
    /// Java and Scala declarations.
    pub(crate) fn imported_code_units_in_realm(
        &self,
        file: &ProjectFile,
        realm: Option<&JvmSourceRealm<'_>>,
    ) -> HashSet<CodeUnit> {
        let cache = match realm {
            Some(_) => &self.realm_imported_code_units,
            None => &self.imported_code_units,
        };
        if let Some(cached) = cache.get(file) {
            return (*cached).clone();
        }
        if file_language(file) != Language::Kotlin {
            return HashSet::default();
        }
        let imports = self.inner.import_info_of(file);
        let resolved = self.resolve_import_infos(&imports, realm);
        cache.insert(file.clone(), Arc::new(resolved.clone()));
        resolved
    }

    /// Files that can see one another without an import because they declare
    /// the same package and spell one another's names.
    fn same_package_reference_index(&self) -> Arc<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>> {
        self.same_package_reference_index.get_or_build(
            || self.compute_same_package_reference_index(true),
            || self.compute_same_package_reference_index(false),
        )
    }

    fn compute_same_package_reference_index(
        &self,
        parallel: bool,
    ) -> HashMap<ProjectFile, Arc<HashSet<ProjectFile>>> {
        let mut targets_by_package_and_name: HashMap<(String, String), Vec<ProjectFile>> =
            HashMap::default();
        for file in self.inner.all_files() {
            if file_language(&file) != Language::Kotlin {
                continue;
            }
            let package = self.inner.package_name_of(&file).unwrap_or_default();
            for declaration in self.inner.top_level_declarations(&file) {
                targets_by_package_and_name
                    .entry((package.clone(), declaration.identifier().to_string()))
                    .or_default()
                    .push(file.clone());
            }
        }

        let files: Vec<_> = self.inner.all_files();
        build_reverse_file_index(
            &files,
            |candidate| {
                if file_language(candidate) != Language::Kotlin {
                    return Vec::new();
                }
                let package = self.inner.package_name_of(candidate).unwrap_or_default();
                let Some(identifiers) = self.inner.type_identifiers_of(candidate) else {
                    return Vec::new();
                };
                identifiers
                    .iter()
                    .filter_map(|identifier| {
                        targets_by_package_and_name.get(&(package.clone(), identifier.clone()))
                    })
                    .flat_map(|targets| targets.iter().cloned())
                    .collect()
            },
            parallel,
        )
    }
}

impl ImportAnalysisProvider for KotlinAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> HashSet<CodeUnit> {
        self.imported_code_units_in_realm(file, None)
    }

    fn import_info_of(&self, file: &ProjectFile) -> Vec<ImportInfo> {
        self.inner.import_info_of(file)
    }

    fn imported_code_units_from_infos(
        &self,
        _file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<HashSet<CodeUnit>> {
        Some(self.resolve_import_infos(imports, None))
    }

    /// Kotlin files that reference `file`.
    ///
    /// Deliberately Kotlin-to-Kotlin, even under a multi-language analyzer.
    /// Answering "which Kotlin files reference this *Java* file" needs both
    /// halves of this index to cross the realm, and only one of them can:
    /// the import half could consult the realm view, but the same-package half
    /// needs each JVM member's files and top-level declarations, which the
    /// realm's forward-query surface does not expose. A half-crossing answer —
    /// imports counted, same-package references silently dropped — would be
    /// worse than a clearly bounded one, so this index stays within one
    /// language.
    ///
    /// The usage graphs do not depend on it crossing: a cross-language JVM type
    /// query widens its own candidate set over every JVM language directly
    /// (`usages/candidates.rs::add_cross_language_jvm_candidates`), so a Kotlin
    /// reference to a Java type is found without this relation having an opinion
    /// about it (#1239 milestone 4).
    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        if let Some(cached) = self.referencing_files.get(file) {
            return (*cached).clone();
        }
        if file_language(file) != Language::Kotlin {
            return HashSet::default();
        }
        let reverse_index = crate::analyzer::memoized_reverse_import_index(
            &self.reverse_import_index,
            || self.inner.all_files(),
            |candidate| self.imported_code_units_of(candidate),
        );
        let mut result = reverse_index
            .get(file)
            .map(|files| (**files).clone())
            .unwrap_or_default();
        if let Some(files) = self.same_package_reference_index().get(file) {
            result.extend(files.iter().cloned());
        }

        self.referencing_files
            .insert(file.clone(), Arc::new(result.clone()));
        result
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        if source_file == target {
            return false;
        }
        if file_language(source_file) != Language::Kotlin
            || file_language(target) != Language::Kotlin
        {
            return false;
        }

        let source_package = self.inner.package_name_of(source_file).unwrap_or_default();
        let target_package = self.inner.package_name_of(target).unwrap_or_default();
        if source_package == target_package {
            return true;
        }

        imports.iter().any(|import| {
            let Some(path) = kotlin_import_path(import) else {
                return false;
            };
            if import.is_wildcard {
                return path == target_package
                    || self
                        .star_imported_declarations(&path, None)
                        .iter()
                        .any(|unit| unit.source() == target);
            }
            self.declarations_named(&path, None)
                .iter()
                .any(|unit| unit.source() == target)
        })
    }
}
