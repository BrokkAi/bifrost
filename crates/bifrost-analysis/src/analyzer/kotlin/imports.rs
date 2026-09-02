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
use crate::analyzer::tree_sitter_analyzer::BulkFileStateSource;
use crate::analyzer::{
    CodeUnit, IAnalyzer, ImportAnalysisProvider, ImportInfo, Language, ProjectFile,
};
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_jvm::kotlin::graph_support::KotlinSource;
use brokk_bifrost_jvm::kotlin::imports::{
    compute_kotlin_same_package_reference_index, is_kotlin_importable_top_level,
    kotlin_could_import_file, kotlin_import_path, resolve_kotlin_import_infos,
};
use brokk_bifrost_jvm::realm::JvmSourceRealm;
use std::sync::Arc;

use super::KotlinAnalyzer;
use crate::analyzer::{AnalyzerQueryScope, QueryScope};

#[derive(Default)]
pub(super) struct KotlinFileDependencyIndex {
    declaration_files: HashMap<String, HashSet<ProjectFile>>,
    importable_files_by_package: HashMap<String, HashSet<ProjectFile>>,
    direct_member_files: HashMap<String, HashSet<ProjectFile>>,
}

impl KotlinFileDependencyIndex {
    fn build(
        analyzer: &KotlinAnalyzer,
        files: &[ProjectFile],
        cancellation: &crate::cancellation::CancellationToken,
    ) -> Option<Self> {
        let states = analyzer.bulk_file_states(files.iter().cloned(), BulkFileStateSource::Omit);
        if cancellation.is_cancelled() {
            return None;
        }
        let kotlin_file_count = files
            .iter()
            .filter(|file| file_language(file) == Language::Kotlin)
            .count();
        if states.len() != kotlin_file_count {
            return None;
        }

        let mut index = Self::default();
        for (file, state) in states {
            if cancellation.is_cancelled() {
                return None;
            }
            for declaration in &state.declarations {
                if declaration.is_synthetic() {
                    continue;
                }
                index
                    .declaration_files
                    .entry(declaration.fq_name())
                    .or_default()
                    .insert(file.clone());
                if is_kotlin_importable_top_level(declaration) {
                    index
                        .importable_files_by_package
                        .entry(declaration.package_name().to_string())
                        .or_default()
                        .insert(file.clone());
                }
            }
            for (owner, children) in &state.children {
                if !owner.is_class() {
                    continue;
                }
                let targets = index
                    .direct_member_files
                    .entry(owner.fq_name())
                    .or_default();
                targets.extend(
                    children
                        .iter()
                        .filter(|child| !child.is_synthetic())
                        .map(|child| child.source().clone()),
                );
            }
        }
        Some(index)
    }

    fn resolve_imports(&self, file: &ProjectFile, imports: &[ImportInfo]) -> HashSet<ProjectFile> {
        let mut imported = HashSet::default();
        for import in imports {
            let Some(path) = kotlin_import_path(import) else {
                continue;
            };
            if import.is_wildcard {
                if let Some(files) = self.importable_files_by_package.get(&path) {
                    imported.extend(files.iter().cloned());
                } else if let Some(files) = self.direct_member_files.get(&path) {
                    imported.extend(files.iter().cloned());
                }
            } else if let Some(files) = self.declaration_files.get(&path) {
                imported.extend(files.iter().cloned());
            }
        }
        imported.remove(file);
        imported
    }
}

impl KotlinAnalyzer {
    /// The declarations a Kotlin file imports, widened to the whole JVM source
    /// realm when a realm view is supplied.
    ///
    /// The realm-aware and realm-less answers are cached separately: a
    /// Kotlin-only result must never be served to a caller that can also see
    /// Java and Scala declarations.
    pub(crate) fn imported_code_units_in_realm(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
        realm: Option<&JvmSourceRealm<'_>>,
    ) -> Arc<HashSet<CodeUnit>> {
        let cache = match realm {
            Some(_) => &self.realm_imported_code_units,
            None => &self.imported_code_units,
        };
        if let Some(cached) = cache.get(file) {
            return cached;
        }
        if file_language(file) != Language::Kotlin {
            return Arc::new(HashSet::default());
        }
        let imports = self.inner.import_info_of(token, file);
        let resolved = Arc::new(resolve_kotlin_import_infos(self, token, &imports, realm));
        cache.insert(file.clone(), Arc::clone(&resolved));
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
    fn file_dependency_facts_for_files(
        &self,
        files: &[ProjectFile],
    ) -> Option<crate::hash::HashMap<ProjectFile, crate::analyzer::FileDependencyFacts>> {
        Some(self.inner.bulk_file_dependency_facts(files.iter().cloned()))
    }

    fn imported_code_units_of(&self, file: &ProjectFile) -> Arc<HashSet<CodeUnit>> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        self.imported_code_units_in_realm(token, file, None)
    }

    fn import_info_of(&self, token: QueryToken<'_>, file: &ProjectFile) -> Vec<ImportInfo> {
        self.inner.import_info_of(token, file)
    }

    fn imported_code_units_from_infos(
        &self,
        _file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<Arc<HashSet<CodeUnit>>> {
        let scope = AnalyzerQueryScope::new(self);
        Some(Arc::new(resolve_kotlin_import_infos(
            self,
            scope.token(),
            imports,
            None,
        )))
    }

    fn imported_files_from_infos(
        &self,
        file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<HashSet<ProjectFile>> {
        self.file_dependency_index
            .get()
            .map(|index| index.resolve_imports(file, imports))
    }

    fn prefetch_file_dependency_targets(
        &self,
        files: &[ProjectFile],
        _import_infos: Option<&HashMap<ProjectFile, Vec<ImportInfo>>>,
        cancellation: &crate::cancellation::CancellationToken,
    ) {
        if self.file_dependency_index.get().is_none()
            && let Some(index) = KotlinFileDependencyIndex::build(self, files, cancellation)
        {
            let _ = self.file_dependency_index.set(index);
        }
    }

    /// Kotlin answers "could this file import the target" by resolving each
    /// import path against the workspace's declarations, so the shared
    /// candidate walk charged one relational point batch per distinct import
    /// path per request (#1748's shape, Rust's batch precedent). Every path
    /// the walk will ask about is derivable from the import facts it already
    /// has, so resolve them all here through the same two batched reads the
    /// point path would issue one name at a time.
    fn prefetch_import_targets(
        &self,
        files: &[ProjectFile],
        import_infos: Option<&HashMap<ProjectFile, Vec<ImportInfo>>>,
        cancellation: &crate::cancellation::CancellationToken,
    ) {
        // Without an open request scope there is no shared memo to fill, so a
        // prefetch would resolve into a lookup nobody else can see.
        if self.inner.definition_lookup_memo().is_none() {
            return;
        }
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        let packages = self.top_level_declarations_by_package();
        let mut paths: Vec<String> = Vec::new();
        for file in files {
            if cancellation.is_cancelled() {
                return;
            }
            if file_language(file) != Language::Kotlin {
                continue;
            }
            let owned_imports;
            let imports = match import_infos.and_then(|all| all.get(file)) {
                Some(imports) => imports.as_slice(),
                None => {
                    owned_imports = self.inner.import_info_of(token, file);
                    &owned_imports
                }
            };
            for import in imports {
                let Some(path) = kotlin_import_path(import) else {
                    continue;
                };
                // A star import over a workspace package answers from the
                // per-generation package export table, not the fqn memo; only
                // the object-star and single-name forms reach the lookup.
                if import.is_wildcard && packages.contains_key(&path) {
                    continue;
                }
                paths.push(path);
            }
        }
        if cancellation.is_cancelled() {
            return;
        }
        paths.sort_unstable();
        paths.dedup();
        let lookup = crate::analyzer::AnalyzerDefinitionLookup::new(self, Language::Kotlin);
        lookup.prefetch_fqns(&paths);
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
        let scope = AnalyzerQueryScope::new(self);
        kotlin_could_import_file(self, scope.token(), source_file, imports, target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{AnalyzerDefinitionLookup, KotlinAnalyzer};
    use crate::inline_project::InlineTestProject;

    /// Cost pin for the scan-path milestone: after `prefetch_import_targets`,
    /// resolving the import paths the candidate walk will ask about costs no
    /// further store reads, and the memoized answers are the point path's.
    #[test]
    fn import_target_prefetch_fills_the_shared_definition_memo() {
        let fixture = InlineTestProject::with_language(Language::Kotlin)
            .file(
                "Service.kt",
                "package api\n\nclass Service { fun run() {} }\n",
            )
            .file(
                "Registry.kt",
                "package api\n\nobject Registry { fun register() {} }\n",
            )
            .file(
                "Consumer.kt",
                "package app\n\nimport api.Service\nimport api.Registry.*\n\
                 import api.missing.Thing\n\n\
                 class Consumer { fun call(service: Service) { service.run() } }\n",
            )
            .build();
        let files = [
            ProjectFile::new(fixture.root(), "Service.kt"),
            ProjectFile::new(fixture.root(), "Registry.kt"),
            ProjectFile::new(fixture.root(), "Consumer.kt"),
        ];
        let analyzer = KotlinAnalyzer::new(fixture.project_arc());
        let names = ["api.Service", "api.Registry", "api.missing.Thing"];
        let unprefetched: Vec<_> = {
            let _scope = AnalyzerQueryScope::new(&analyzer);
            let lookup = AnalyzerDefinitionLookup::new(&analyzer, Language::Kotlin);
            names.iter().map(|name| lookup.fqn(name)).collect()
        };
        assert_eq!(
            unprefetched[0]
                .iter()
                .map(|unit| unit.fq_name())
                .collect::<Vec<_>>(),
            vec!["api.Service".to_string()],
            "the fixture's class must resolve, or this test pins nothing"
        );
        assert_eq!(
            unprefetched[1]
                .iter()
                .map(|unit| unit.fq_name())
                .collect::<Vec<_>>(),
            vec!["api.Registry".to_string()],
            "the single-line object must resolve: its misparse is recovered \
             by the declaration walk"
        );

        let _scope = AnalyzerQueryScope::new(&analyzer);
        analyzer.prefetch_import_targets(&files, None, &crate::CancellationToken::new());

        let before = analyzer.relational_batch_reader_checkouts_for_test();
        let lookup = AnalyzerDefinitionLookup::new(&analyzer, Language::Kotlin);
        let prefetched: Vec<_> = names.iter().map(|name| lookup.fqn(name)).collect();
        assert_eq!(
            analyzer.relational_batch_reader_checkouts_for_test() - before,
            0,
            "every import path the walk will ask about must answer from the shared memo"
        );
        assert_eq!(
            prefetched, unprefetched,
            "a memoized answer must equal the point path's"
        );
    }
}
