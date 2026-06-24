use crate::analyzer::{
    CodeUnit, IAnalyzer, ImportAnalysisProvider, ImportInfo, ProjectFile,
    build_reverse_import_index,
};
use crate::hash::HashSet;
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
            // Prefer exact canonical-package identity: with a go.mod present a
            // package's `package_name` is its import path, so this is
            // unambiguous. Fall back to the directory-suffix heuristic only
            // when nothing matches exactly (module-less or vendored layouts
            // where the import path is a suffix of the directory).
            let mut matching_files: Vec<_> = self
                .inner
                .all_files()
                .filter(|candidate| *candidate != file)
                .filter(|candidate| self.go_package_of(candidate).as_deref() == Some(path.as_str()))
                .cloned()
                .collect();
            if matching_files.is_empty() {
                matching_files = self
                    .inner
                    .all_files()
                    .filter(|candidate| *candidate != file)
                    .filter(|candidate| dir_suffix_matches(candidate, &path))
                    .cloned()
                    .collect();
            }
            for target_file in matching_files {
                resolved.extend(
                    self.inner
                        .top_level_declarations(&target_file)
                        .filter(|code_unit| !code_unit.is_module())
                        .cloned(),
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

        let reverse_index = self.memo_caches.reverse_import_index.get_or_init(|| {
            let files: Vec<_> = self.inner.all_files().cloned().collect();
            build_reverse_import_index(&files, |candidate| self.imported_code_units_of(candidate))
        });
        let referencing = reverse_index
            .get(file)
            .map(|files| (**files).clone())
            .unwrap_or_default();
        self.memo_caches
            .referencing_files
            .insert(file.clone(), Arc::new(referencing.clone()));
        referencing
    }

    fn import_info_of<'a>(&'a self, file: &ProjectFile) -> &'a [ImportInfo] {
        self.inner.import_info_of(file)
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
    /// Canonical package identity (import path) of a file, taken from any of
    /// its declarations. `None` for files with no top-level declarations.
    pub(super) fn go_package_of(&self, file: &ProjectFile) -> Option<String> {
        self.inner
            .top_level_declarations(file)
            .next()
            .map(|unit| unit.package_name().to_string())
    }
}

/// Legacy directory-suffix import match, used only as a fallback when no
/// declaration's canonical package equals the import path (module-less or
/// vendored layouts).
fn dir_suffix_matches(candidate: &ProjectFile, path: &str) -> bool {
    let parent = candidate.parent().to_string_lossy().replace('\\', "/");
    parent == path || path.ends_with(&format!("/{parent}")) || parent.ends_with(&format!("/{path}"))
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
