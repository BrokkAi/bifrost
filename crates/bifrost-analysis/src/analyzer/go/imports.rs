use crate::analyzer::{CodeUnit, IAnalyzer, ImportAnalysisProvider, ImportInfo, ProjectFile};
use crate::hash::{HashMap, HashSet};
use std::sync::Arc;

use super::GoAnalyzer;

impl ImportAnalysisProvider for GoAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> HashSet<CodeUnit> {
        if let Some(cached) = self.memo_caches.imported_code_units.get(file) {
            return (*cached).clone();
        }

        let mut resolved = HashSet::default();
        for import in self.inner.import_info_of(file) {
            if import.alias.as_deref() == Some("_") {
                continue;
            }
            let Some(path) = extract_go_import_path(&import.raw_snippet) else {
                continue;
            };
            for target_file in self.matching_import_files(file, &path) {
                resolved.extend(
                    self.inner
                        .top_level_declarations(&target_file)
                        .into_iter()
                        .filter(|code_unit| !code_unit.is_module()),
                );
            }
        }

        self.memo_caches
            .imported_code_units
            .insert(file.clone(), Arc::new(resolved.clone()));
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
                .filter_map(|import| extract_go_import_path(&import.raw_snippet))
                .flat_map(|path| self.direct_import_files(file, &path))
                .collect(),
        )
    }

    fn relevant_imports_for(&self, code_unit: &CodeUnit) -> HashSet<String> {
        let source = self.inner.get_source(code_unit, false).unwrap_or_default();
        let mut relevant = HashSet::default();
        for import in self.inner.import_info_of(code_unit.source()) {
            if import.alias.as_deref() == Some("_") {
                continue;
            }

            let token = import
                .alias
                .as_ref()
                .filter(|alias| alias.as_str() != ".")
                .cloned()
                .or_else(|| import.identifier.clone())
                .unwrap_or_default();
            if token.is_empty() || source.contains(&token) || import.alias.as_deref() == Some(".") {
                relevant.insert(import.raw_snippet.clone());
            }
        }
        relevant
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        let target_pkg = self.go_package_of(target);
        imports.iter().any(|import| {
            let Some(path) = extract_go_import_path(&import.raw_snippet) else {
                return false;
            };
            target_pkg.as_deref() == Some(path.as_str()) || dir_suffix_matches(target, &path)
        }) || self
            .imported_code_units_of(source_file)
            .into_iter()
            .any(|code_unit| code_unit.source() == target)
    }
}

impl GoAnalyzer {
    /// Resolve only `file`'s namespace from persisted import and package facts.
    /// This deliberately avoids the whole-workspace package graph used by bulk
    /// usage analysis.
    pub(crate) fn definition_import_namespaces(
        &self,
        file: &ProjectFile,
    ) -> (HashMap<String, Vec<String>>, Vec<String>) {
        let mut by_alias: HashMap<String, Vec<String>> = HashMap::default();
        let mut dot_imports = Vec::new();
        for import in self.inner.import_info_of(file) {
            let alias = import.alias.as_deref();
            if alias == Some("_") {
                continue;
            }
            let Some(path) = extract_go_import_path(&import.raw_snippet) else {
                continue;
            };
            let vendor_suffix = format!("/vendor/{path}");
            let mut packages: Vec<String> = self
                .workspace_path_index()
                .import_files(file, &path)
                .into_iter()
                .filter(|target| self.is_analyzed(target))
                .filter_map(|target| {
                    let declared = self.package_clause_of(&target)?;
                    Some(super::packages::canonical_go_package_name(
                        &target, &declared,
                    ))
                })
                .filter(|package| package == &path || package.ends_with(&vendor_suffix))
                .collect();
            packages.sort();
            packages.dedup();
            if packages.is_empty() {
                // Preserve the source import path for packages outside the
                // indexed workspace so callers can report an import boundary.
                packages.push(path.clone());
            }
            match alias {
                Some(".") => dot_imports.extend(packages),
                Some(explicit) => by_alias
                    .entry(explicit.to_string())
                    .or_default()
                    .extend(packages),
                None => {
                    let local = self
                        .workspace_package_clause(file, &path)
                        .or(import.identifier)
                        .unwrap_or_else(|| default_import_local_name(&path));
                    by_alias.entry(local).or_default().extend(packages);
                }
            }
        }
        for packages in by_alias.values_mut() {
            packages.sort();
            packages.dedup();
        }
        dot_imports.sort();
        dot_imports.dedup();
        (by_alias, dot_imports)
    }

    fn workspace_package_clause(
        &self,
        source_file: &ProjectFile,
        import_path: &str,
    ) -> Option<String> {
        self.workspace_path_index()
            .import_files(source_file, import_path)
            .into_iter()
            .filter(|file| self.is_analyzed(file))
            .find_map(|file| self.package_clause_of(&file))
            .filter(|package| !package.is_empty())
    }

    /// Canonical package identity (import path) of a file, taken from any of
    /// its declarations. `None` for files with no top-level declarations.
    pub(super) fn go_package_of(&self, file: &ProjectFile) -> Option<String> {
        self.inner
            .top_level_declarations(file)
            .into_iter()
            .next()
            .map(|unit| unit.package_name().to_string())
    }

    fn matching_import_files(
        &self,
        source_file: &ProjectFile,
        import_path: &str,
    ) -> Vec<ProjectFile> {
        // Prefer exact canonical-package identity: with a go.mod present a
        // package's `package_name` is its import path, so this is unambiguous.
        if let Some(files) = self.package_files().get(import_path) {
            let exact: Vec<_> = files
                .iter()
                .filter(|candidate| *candidate != source_file)
                .cloned()
                .collect();
            if !exact.is_empty() {
                return exact;
            }
        }

        // Fall back to the legacy directory-suffix heuristic only when no
        // canonical package matches (module-less or vendored layouts).
        let mut seen = HashSet::default();
        let mut matching = Vec::new();
        for suffix in path_suffixes(import_path) {
            if let Some(files) = self.dir_parent_files().get(suffix) {
                for candidate in files.iter() {
                    if candidate != source_file && seen.insert(candidate.clone()) {
                        matching.push(candidate.clone());
                    }
                }
            }
        }
        if let Some(files) = self.dir_parent_suffix_files().get(import_path) {
            for candidate in files.iter() {
                if candidate != source_file && seen.insert(candidate.clone()) {
                    matching.push(candidate.clone());
                }
            }
        }
        matching
    }

    fn direct_import_files(
        &self,
        source_file: &ProjectFile,
        import_path: &str,
    ) -> Vec<ProjectFile> {
        let resolved = self.matching_import_files(source_file, import_path);
        if !resolved.is_empty() {
            return resolved;
        }

        let directories: HashSet<_> = self
            .workspace_path_index()
            .import_files(source_file, import_path)
            .into_iter()
            .map(|file| file.parent())
            .collect();
        self.inner
            .all_files()
            .into_iter()
            .filter(|file| file != source_file && directories.contains(&file.parent()))
            .collect()
    }

    fn package_files(&self) -> &HashMap<String, Arc<Vec<ProjectFile>>> {
        self.memo_caches.package_files.get_or_init(|| {
            let mut files_by_package: HashMap<String, Vec<ProjectFile>> = HashMap::default();
            for file in self.inner.all_files() {
                if let Some(package) = self.go_package_of(&file) {
                    files_by_package
                        .entry(package)
                        .or_default()
                        .push(file.clone());
                }
            }
            files_by_package
                .into_iter()
                .map(|(package, files)| (package, Arc::new(files)))
                .collect()
        })
    }

    fn dir_parent_files(&self) -> &HashMap<String, Arc<Vec<ProjectFile>>> {
        self.memo_caches.dir_parent_files.get_or_init(|| {
            let mut files_by_parent: HashMap<String, Vec<ProjectFile>> = HashMap::default();
            for file in self.inner.all_files() {
                if self.go_package_of(&file).is_none() {
                    continue;
                }
                files_by_parent
                    .entry(parent_path_key(&file))
                    .or_default()
                    .push(file.clone());
            }
            files_by_parent
                .into_iter()
                .map(|(parent, files)| (parent, Arc::new(files)))
                .collect()
        })
    }

    fn dir_parent_suffix_files(&self) -> &HashMap<String, Arc<Vec<ProjectFile>>> {
        self.memo_caches.dir_parent_suffix_files.get_or_init(|| {
            let mut files_by_suffix: HashMap<String, Vec<ProjectFile>> = HashMap::default();
            for file in self.inner.all_files() {
                if self.go_package_of(&file).is_none() {
                    continue;
                }
                for suffix in path_suffixes(&parent_path_key(&file)) {
                    files_by_suffix
                        .entry(suffix.to_string())
                        .or_default()
                        .push(file.clone());
                }
            }
            files_by_suffix
                .into_iter()
                .map(|(suffix, files)| (suffix, Arc::new(files)))
                .collect()
        })
    }
}

fn default_import_local_name(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_string()
}

/// Legacy directory-suffix import match, used only as a fallback when no
/// declaration's canonical package equals the import path (module-less or
/// vendored layouts).
fn dir_suffix_matches(candidate: &ProjectFile, path: &str) -> bool {
    let parent = parent_path_key(candidate);
    parent == path || path.ends_with(&format!("/{parent}")) || parent.ends_with(&format!("/{path}"))
}

fn parent_path_key(file: &ProjectFile) -> String {
    file.parent().to_string_lossy().replace('\\', "/")
}

fn path_suffixes(path: &str) -> impl Iterator<Item = &str> {
    let mut suffixes = Vec::new();
    suffixes.push(path);
    suffixes.extend(
        path.match_indices('/')
            .map(|(index, _)| &path[index + 1..])
            .filter(|suffix| !suffix.is_empty()),
    );
    suffixes.into_iter()
}

pub(super) fn extract_go_import_path(raw_import: &str) -> Option<String> {
    let trimmed = raw_import.trim();
    trimmed
        .split_whitespace()
        .next_back()
        .map(|path| {
            path.trim_matches('"')
                .trim_matches('`')
                .trim_matches('\'')
                .to_string()
        })
        .filter(|path| !path.is_empty())
}
