//! `ImportAnalysisProvider` for Go: the memoization shell around
//! [`brokk_bifrost_go::imports`].
//!
//! Only the caching stays here. `GoMemoCaches` is moka-backed and moka is
//! deliberately kept out of `brokk-bifrost-go` and out of core, so each method
//! below fetches or fills a cache slot and hands the actual resolution to the
//! Go crate along with the file list and workspace path index it needs.

use crate::analyzer::CodeUnitIndex;
use crate::analyzer::{
    CodeUnit, ImportAnalysisProvider, ImportInfo, ImportReachability, ProjectFile,
};
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
    fn import_infos_for_files(
        &self,
        files: &[ProjectFile],
    ) -> Option<crate::hash::HashMap<ProjectFile, Vec<crate::analyzer::ImportInfo>>> {
        Some(self.inner.bulk_import_infos(files.iter().cloned()))
    }

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
        let mut resolved: HashSet<ProjectFile> = HashSet::default();
        let mut unresolved: Vec<String> = Vec::new();
        for path in imports.iter().filter_map(go_import_path) {
            let files = go_matching_import_files(&tables, file, &path);
            if files.is_empty() {
                unresolved.push(path);
            } else {
                resolved.extend(files);
            }
        }
        if !unresolved.is_empty() {
            // Only the fallback needs the whole analyzed file list, and it
            // needs it once for the call -- not once per unresolved import.
            // `all_files` is the store-validated listing, so repeating it per
            // import made an unresolved stdlib import cost a workspace walk.
            let all_files = self.inner.all_files();
            for path in unresolved {
                resolved.extend(go_directory_sibling_import_files(
                    self.workspace_path_index(),
                    &all_files,
                    file,
                    &path,
                ));
            }
        }
        Some(resolved)
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
        matches!(
            self.import_reachability(source_file, imports, target),
            ImportReachability::Reaches
        )
    }

    /// Go's reachability rule, answered from file and package facts alone.
    ///
    /// A Go file can name a declaration in another file in exactly two ways:
    /// the two files declare the same package (a Go package is the files of
    /// one directory, and nothing else is in scope unqualified), or the file
    /// imports the target's package. Both are decided from persisted package
    /// clauses and the file's own import list, so the whole rule is complete
    /// and `DoesNotReach` is a proof rather than an absence of evidence --
    /// which retires the caller's expansion backstop for Go.
    ///
    /// That backstop was the cost this replaces (#1748): it answered a file
    /// question by materializing the declarations of every file every import
    /// brought in, once per candidate, and on a 20k-file workspace the bounded
    /// file-state cache then read the same states from SQLite over and over.
    /// The declaration-level answer is still available through
    /// [`ImportAnalysisProvider::imported_code_units_of`] for the callers that
    /// genuinely need units.
    ///
    /// The one undecidable case is a target whose package clause was never
    /// persisted. Nothing here can prove either answer for it, so it reports
    /// `Unknown` and the caller expands exactly as before. The count of such
    /// files is reported once per workspace by [`GoAnalyzer::import_facts`].
    fn import_reachability(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> ImportReachability {
        let facts = self.import_facts();
        let target_package = facts.package_of(target);
        let target_parent = parent_path_key(target);
        let reaches = (target_package.is_some() && target_package == facts.package_of(source_file))
            || imports.iter().any(|import| {
                go_import_path(import).is_some_and(|path| {
                    target_package == Some(path.as_str())
                        || dir_suffix_matches(&target_parent, &path)
                })
            });
        if reaches {
            ImportReachability::Reaches
        } else if target_package.is_some() {
            ImportReachability::DoesNotReach
        } else {
            ImportReachability::Unknown
        }
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
        let facts = self.import_facts();
        GoImportTables {
            package_files: &facts.package_files,
            dir_parent_files: &facts.dir_parent_files,
            dir_parent_suffix_files: &facts.dir_parent_suffix_files,
        }
    }

    /// The workspace import facts, built once. Every table below answers the
    /// same question -- which package does this file declare -- so they are
    /// built in one pass; separately, each read every file's persisted package
    /// clause again.
    pub(super) fn import_facts(&self) -> &GoImportFacts {
        self.memo_caches.import_facts.get_or_init(|| {
            let files = self.inner.all_files();
            let mut package_of_file: HashMap<ProjectFile, String> = HashMap::default();
            for file in &files {
                if let Some(package) = self.go_package_of(file) {
                    package_of_file.insert(file.clone(), package);
                }
            }
            // A file with no persisted package clause is the one shape
            // `import_reachability` cannot decide, so name the size of that
            // tail once per workspace rather than per undecided pair.
            brokk_bifrost_core::profiling::note_with(|| {
                format!(
                    "go::import_facts[files={}, without_package_clause={}]",
                    files.len(),
                    files.len() - package_of_file.len()
                )
            });

            let mut package_files: HashMap<String, Vec<ProjectFile>> = HashMap::default();
            let mut dir_parent_files: HashMap<String, Vec<ProjectFile>> = HashMap::default();
            let mut dir_parent_suffix_files: HashMap<String, Vec<ProjectFile>> = HashMap::default();
            for file in &files {
                let Some(package) = package_of_file.get(file) else {
                    continue;
                };
                package_files
                    .entry(package.clone())
                    .or_default()
                    .push(file.clone());
                let parent = parent_path_key(file);
                for suffix in path_suffixes(&parent) {
                    dir_parent_suffix_files
                        .entry(suffix.to_string())
                        .or_default()
                        .push(file.clone());
                }
                dir_parent_files
                    .entry(parent)
                    .or_default()
                    .push(file.clone());
            }

            GoImportFacts {
                package_of_file,
                package_files: share(package_files),
                dir_parent_files: share(dir_parent_files),
                dir_parent_suffix_files: share(dir_parent_suffix_files),
            }
        })
    }
}

/// Every workspace-scale Go import fact, built in one pass over the analyzed
/// file list.
pub(super) struct GoImportFacts {
    /// Canonical package identity of each file that persisted a package
    /// clause. Absence means the clause was never persisted, which is what
    /// `import_reachability` reports as `Unknown`.
    package_of_file: HashMap<ProjectFile, String>,
    package_files: HashMap<String, Arc<Vec<ProjectFile>>>,
    dir_parent_files: HashMap<String, Arc<Vec<ProjectFile>>>,
    dir_parent_suffix_files: HashMap<String, Arc<Vec<ProjectFile>>>,
}

impl GoImportFacts {
    pub(super) fn package_of(&self, file: &ProjectFile) -> Option<&str> {
        self.package_of_file.get(file).map(String::as_str)
    }
}

fn share(grouped: HashMap<String, Vec<ProjectFile>>) -> HashMap<String, Arc<Vec<ProjectFile>>> {
    grouped
        .into_iter()
        .map(|(key, files)| (key, Arc::new(files)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::super::test_analyzer;
    use crate::analyzer::{
        AnalyzerQueryScope, CodeUnitIndex, ImportAnalysisProvider, ImportInfo, ImportReachability,
        ProjectFile, QueryScope,
    };

    /// Three packages under one module: `app` imports `store`, `unrelated`
    /// imports neither, and `app` has a second file in the same package.
    fn workspace() -> super::GoAnalyzer {
        test_analyzer(&[
            (
                "store/store.go",
                "package store\n\ntype Item struct{}\n\nfunc Get() Item { return Item{} }\n",
            ),
            (
                "app/app.go",
                "package app\n\nimport \"example.com/app/store\"\n\nfunc Run() { store.Get() }\n",
            ),
            ("app/helper.go", "package app\n\nfunc Helper() {}\n"),
            (
                "unrelated/other.go",
                "package unrelated\n\nfunc Other() {}\n",
            ),
        ])
    }

    fn file(analyzer: &super::GoAnalyzer, rel_path: &str) -> ProjectFile {
        analyzer
            .get_analyzed_files()
            .into_iter()
            .find(|file| file.rel_path().to_string_lossy().replace('\\', "/") == rel_path)
            .unwrap_or_else(|| panic!("fixture has no {rel_path}"))
    }

    fn imports_of(analyzer: &super::GoAnalyzer, file: &ProjectFile) -> Vec<ImportInfo> {
        let scope = AnalyzerQueryScope::new(analyzer);
        analyzer.import_info_of(scope.token(), file)
    }

    #[test]
    fn reachability_is_decided_from_package_facts() {
        let analyzer = workspace();
        let store = file(&analyzer, "store/store.go");
        let app = file(&analyzer, "app/app.go");
        let helper = file(&analyzer, "app/helper.go");
        let unrelated = file(&analyzer, "unrelated/other.go");

        assert_eq!(
            analyzer.import_reachability(&app, &imports_of(&analyzer, &app), &store),
            ImportReachability::Reaches,
            "app imports store"
        );
        assert_eq!(
            analyzer.import_reachability(&helper, &imports_of(&analyzer, &helper), &app),
            ImportReachability::Reaches,
            "a Go file names its own package's declarations without importing them"
        );
        // A proven negative, not merely an absence of evidence: this is what
        // lets the candidate walk skip its declaration-expansion backstop.
        assert_eq!(
            analyzer.import_reachability(&unrelated, &imports_of(&analyzer, &unrelated), &store),
            ImportReachability::DoesNotReach,
            "unrelated imports nothing"
        );
        assert!(!analyzer.could_import_file(
            &unrelated,
            &imports_of(&analyzer, &unrelated),
            &store
        ));
    }

    /// Cost pin for #1748: reachability reads file and package facts only, so
    /// once the workspace facts are warm no pair costs a file-state hydration.
    /// Before this change every undecided pair materialized the declarations
    /// of every file the candidate's imports brought in.
    #[test]
    fn reachability_hydrates_no_file_state_once_warm() {
        let analyzer = workspace();
        let files: Vec<ProjectFile> = [
            "store/store.go",
            "app/app.go",
            "app/helper.go",
            "unrelated/other.go",
        ]
        .into_iter()
        .map(|rel_path| file(&analyzer, rel_path))
        .collect();
        let imports: Vec<Vec<ImportInfo>> = files
            .iter()
            .map(|file| imports_of(&analyzer, file))
            .collect();
        // Warm the workspace package facts, which read each file's persisted
        // package clause once.
        analyzer.import_reachability(&files[1], &imports[1], &files[0]);

        let before = analyzer.full_hydration_count_for_test();
        for (source, source_imports) in files.iter().zip(&imports) {
            for target in &files {
                analyzer.import_reachability(source, source_imports, target);
            }
        }
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            before,
            "reachability must answer from file and package facts alone"
        );
    }
}
