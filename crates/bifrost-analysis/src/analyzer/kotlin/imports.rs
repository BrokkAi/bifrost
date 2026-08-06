//! `KotlinAnalyzer`'s `ImportAnalysisProvider` impl and the memo cells behind
//! it.
//!
//! What an `import` header *says*, and how Kotlin's explicit, same-package,
//! star and default tiers turn one into declarations, moved to
//! [`brokk_bifrost_jvm::kotlin::imports`]. The caching stays here: two
//! realm-keyed moka caches, the once-per-generation package export table, the
//! reverse import index and the same-package reference index all read the
//! analyzer's own cells, which `IAnalyzer::update`/`update_all` rebuild
//! wholesale.

use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::{CodeUnit, ImportAnalysisProvider, ImportInfo, Language, ProjectFile};
use crate::hash::{HashMap, HashSet};
/// Re-exported under its historical path for the parked Kotlin source-jar pack
/// producer, which reads the same default-import table.
pub(crate) use brokk_bifrost_jvm::kotlin::imports::KOTLIN_DEFAULT_IMPORT_PACKAGES;
use brokk_bifrost_jvm::kotlin::imports::{
    compute_kotlin_same_package_reference_index, kotlin_could_import_file,
    resolve_kotlin_import_infos,
};
use brokk_bifrost_jvm::realm::JvmSourceRealm;
use std::sync::Arc;

use super::KotlinAnalyzer;

impl KotlinAnalyzer {
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
        let resolved = resolve_kotlin_import_infos(self, &imports, realm);
        cache.insert(file.clone(), Arc::new(resolved.clone()));
        resolved
    }

    /// Files that can see one another without an import because they declare
    /// the same package and spell one another's names.
    fn same_package_reference_index(&self) -> Arc<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>> {
        self.same_package_reference_index.get_or_build(
            || compute_kotlin_same_package_reference_index(self, true),
            || compute_kotlin_same_package_reference_index(self, false),
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
        Some(resolve_kotlin_import_infos(self, imports, None))
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
        kotlin_could_import_file(self, source_file, imports, target)
    }
}
