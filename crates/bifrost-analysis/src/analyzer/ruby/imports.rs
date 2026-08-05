//! Ruby's import surface: the analyzer-bound half.
//!
//! `require`/`autoload` parsing and resolution, the Gemfile-driven Zeitwerk
//! conventions and the reference-identifier collector are
//! [`brokk_bifrost_ruby::imports`]. What stays here is the memoized state --
//! the autoload constant index, the five Zeitwerk `OnceLock` cells, the reverse
//! import `PoolSafeMemo`, the two moka caches -- and the accessors that fill it.

use super::*;
use crate::analyzer::{ImportInfo, Language};
use brokk_bifrost_ruby::imports::{
    collect_ruby_autoload_edges, collect_ruby_reference_identifiers,
    gemfile_declares_zeitwerk_autoloading, gemfile_lock_declares_zeitwerk_autoloading,
    is_zeitwerk_autoload_file, resolve_required_file,
};
use std::sync::Arc;

impl RubyAnalyzer {
    /// Project files this file pulls in via supported Ruby require forms.
    pub(crate) fn required_files(&self, file: &ProjectFile) -> Vec<ProjectFile> {
        self.inner
            .import_info_of(file)
            .iter()
            .filter_map(|import| resolve_required_file(file, import))
            .collect()
    }

    /// Whether a supported load directive cannot be closed over project files.
    ///
    /// A bare `require` can load a gem or a caller-provided load-path entry at
    /// runtime. Navigation can still offer best-effort indexed results, but a
    /// diagnostic must not claim that a constant is absent while that boundary
    /// remains open.
    pub(crate) fn has_unresolved_load_directive(&self, file: &ProjectFile) -> bool {
        self.inner
            .import_info_of(file)
            .iter()
            .any(|import| resolve_required_file(file, import).is_none())
    }

    pub(crate) fn autoload_visible_files_for_constant(
        &self,
        constant: &str,
    ) -> HashSet<ProjectFile> {
        self.autoload_constant_files()
            .get(constant)
            .cloned()
            .unwrap_or_default()
    }

    fn autoload_constant_files(&self) -> &HashMap<String, HashSet<ProjectFile>> {
        self.autoload_constant_files.get_or_init(|| {
            let mut index: HashMap<String, HashSet<ProjectFile>> = HashMap::default();
            for file in self.inner.all_files() {
                let Ok(source) = self.inner.project().read_source(&file) else {
                    continue;
                };
                let Some(tree) = parse_ruby_tree(&source) else {
                    continue;
                };
                collect_ruby_autoload_edges(&file, &source, tree.root_node(), &mut index);
            }
            index
        })
    }

    fn has_zeitwerk_autoload_conventions(&self) -> bool {
        *self.zeitwerk_project.get_or_init(|| {
            self.project_file_contents("Gemfile")
                .as_deref()
                .is_some_and(gemfile_declares_zeitwerk_autoloading)
                || self
                    .project_file_contents("Gemfile.lock")
                    .as_deref()
                    .is_some_and(gemfile_lock_declares_zeitwerk_autoloading)
        })
    }

    fn project_file_contents(&self, rel_path: &str) -> Option<String> {
        let file = ProjectFile::new(self.inner.project().root().to_path_buf(), rel_path);
        self.inner.project().read_source(&file).ok()
    }

    pub(crate) fn zeitwerk_autoload_files(&self) -> &HashSet<ProjectFile> {
        self.zeitwerk_autoload_files.get_or_init(|| {
            if !self.has_zeitwerk_autoload_conventions() {
                return HashSet::default();
            }
            self.inner
                .project()
                .analyzable_files(Language::Ruby)
                .map(|files| {
                    files
                        .into_iter()
                        .filter(is_zeitwerk_autoload_file)
                        .collect()
                })
                .unwrap_or_default()
        })
    }

    fn zeitwerk_consumer_files(&self) -> &HashSet<ProjectFile> {
        self.zeitwerk_consumer_files.get_or_init(|| {
            if !self.has_zeitwerk_autoload_conventions() {
                return HashSet::default();
            }
            self.inner
                .project()
                .analyzable_files(Language::Ruby)
                .map(|files| files.into_iter().collect())
                .unwrap_or_default()
        })
    }

    fn zeitwerk_autoload_code_units(&self) -> &HashSet<CodeUnit> {
        self.zeitwerk_autoload_code_units.get_or_init(|| {
            let mut units = HashSet::default();
            for file in self.zeitwerk_autoload_files() {
                for code_unit in self.inner.top_level_declarations(file) {
                    units.insert(code_unit.clone());
                }
            }
            units
        })
    }

    pub(crate) fn zeitwerk_reference_files_for_identifier(
        &self,
        identifier: &str,
    ) -> HashSet<ProjectFile> {
        if identifier.is_empty() {
            return HashSet::default();
        }
        self.zeitwerk_reference_files()
            .get(identifier)
            .into_iter()
            .flat_map(|files| files.iter().cloned())
            .collect()
    }

    pub(crate) fn zeitwerk_visible_files_for(
        &self,
        file: &ProjectFile,
    ) -> Option<&HashSet<ProjectFile>> {
        self.zeitwerk_consumer_files()
            .contains(file)
            .then(|| self.zeitwerk_autoload_files())
    }

    fn zeitwerk_reference_files(&self) -> &HashMap<String, HashSet<ProjectFile>> {
        self.zeitwerk_reference_files.get_or_init(|| {
            let mut references: HashMap<String, HashSet<ProjectFile>> = HashMap::default();
            for file in self.zeitwerk_consumer_files() {
                let Ok(source) = self.inner.project().read_source(file) else {
                    continue;
                };
                let Some(tree) = parse_ruby_tree(&source) else {
                    continue;
                };
                collect_ruby_reference_identifiers(&source, tree.root_node(), |identifier| {
                    references
                        .entry(identifier.to_string())
                        .or_default()
                        .insert(file.clone());
                });
            }
            references
        })
    }

    fn effective_imported_code_units(&self, file: &ProjectFile) -> HashSet<CodeUnit> {
        let mut units = HashSet::default();
        for required in self.required_files(file) {
            for code_unit in self.inner.top_level_declarations(&required) {
                units.insert(code_unit.clone());
            }
        }
        if self.zeitwerk_consumer_files().contains(file) {
            units.extend(
                self.zeitwerk_autoload_code_units()
                    .iter()
                    .filter(|code_unit| code_unit.source() != file)
                    .cloned(),
            );
        }
        units
    }

    pub(super) fn build_reverse_import_index(
        &self,
    ) -> Arc<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>> {
        crate::analyzer::memoized_reverse_file_index(
            &self.reverse_import_index,
            || self.inner.all_files(),
            |file| self.required_files(file),
        )
    }

    fn transitive_referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        let reverse_index = self.build_reverse_import_index();
        let mut referencing = HashSet::default();
        let mut visited = HashSet::default();
        visited.insert(file.clone());
        let mut stack: Vec<ProjectFile> = reverse_index
            .get(file)
            .map(|files| files.iter().cloned().collect())
            .unwrap_or_default();
        while let Some(next) = stack.pop() {
            if !visited.insert(next.clone()) {
                continue;
            }
            referencing.insert(next.clone());
            if let Some(parents) = reverse_index.get(&next) {
                stack.extend(parents.iter().cloned());
            }
        }
        referencing
    }
}

impl ImportAnalysisProvider for RubyAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> HashSet<CodeUnit> {
        if let Some(cached) = self.imported_code_units.get(file) {
            return (*cached).clone();
        }
        let units = self.effective_imported_code_units(file);
        self.imported_code_units
            .insert(file.clone(), Arc::new(units.clone()));
        units
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        if let Some(cached) = self.referencing_files.get(file) {
            return (*cached).clone();
        }
        let referencing = self.transitive_referencing_files_of(file);
        self.referencing_files
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
                .filter_map(|import| resolve_required_file(file, import))
                .collect(),
        )
    }
}
