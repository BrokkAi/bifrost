//! Ruby's import surface: the analyzer-bound half.
//!
//! Every decision here is [`brokk_bifrost_ruby::imports`]. What stays is the
//! memoized state -- the autoload constant index, the five Zeitwerk `OnceLock`
//! cells, the reverse-import `PoolSafeMemo`, the two moka caches -- and the
//! `get_or_init` call sites that fill it.
//!
//! `zeitwerk_reference_files_for_identifier` in particular keeps its lazy
//! trigger here on purpose: `RubyQueryResolver`'s post-budget scan-set
//! augmentation is what first forces the whole-workspace reference scan, and
//! that timing is part of the augmentation contract even though no assertion
//! pins it.

use super::*;
use crate::analyzer::ImportInfo;
use brokk_bifrost_ruby::imports::{
    build_autoload_constant_files, build_zeitwerk_autoload_code_units,
    build_zeitwerk_autoload_files, build_zeitwerk_consumer_files, build_zeitwerk_reference_files,
    detect_zeitwerk_autoload_conventions, ruby_effective_imported_code_units,
    ruby_imported_files_from_infos, ruby_required_files, ruby_transitive_referencing_files_of,
};
use brokk_bifrost_ruby::mixins::RubyOwnerRelationFact;
use std::sync::Arc;

impl RubyAnalyzer {
    /// Project files this file pulls in via supported Ruby require forms.
    pub(crate) fn required_files(&self, file: &ProjectFile) -> Vec<ProjectFile> {
        ruby_required_files(self, file)
    }

    pub(crate) fn zeitwerk_autoload_files(&self) -> &HashSet<ProjectFile> {
        self.zeitwerk_autoload_files
            .get_or_init(|| build_zeitwerk_autoload_files(self))
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

    fn zeitwerk_reference_files(&self) -> &HashMap<String, HashSet<ProjectFile>> {
        self.zeitwerk_reference_files
            .get_or_init(|| build_zeitwerk_reference_files(self))
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
}

impl ImportAnalysisProvider for RubyAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> HashSet<CodeUnit> {
        if let Some(cached) = self.imported_code_units.get(file) {
            return (*cached).clone();
        }
        let units = ruby_effective_imported_code_units(self, file);
        self.imported_code_units
            .insert(file.clone(), Arc::new(units.clone()));
        units
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        if let Some(cached) = self.referencing_files.get(file) {
            return (*cached).clone();
        }
        let referencing = ruby_transitive_referencing_files_of(self, file);
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
        Some(ruby_imported_files_from_infos(file, imports))
    }
}

/// The memoized products Ruby's language logic resolves through.
///
/// Every cell stays on the analyzer because `IAnalyzer::update`/`update_all`
/// rebuild it wholesale through `Self::from_inner`; this impl is the only place
/// the crate can reach them.
impl brokk_bifrost_ruby::graph_support::RubySource for RubyAnalyzer {
    fn all_files(&self) -> Vec<ProjectFile> {
        self.inner.all_files()
    }

    fn autoload_constant_files(&self) -> &HashMap<String, HashSet<ProjectFile>> {
        self.autoload_constant_files
            .get_or_init(|| build_autoload_constant_files(self))
    }

    fn has_zeitwerk_autoload_conventions(&self) -> bool {
        *self
            .zeitwerk_project
            .get_or_init(|| detect_zeitwerk_autoload_conventions(self))
    }

    fn zeitwerk_autoload_files(&self) -> &HashSet<ProjectFile> {
        RubyAnalyzer::zeitwerk_autoload_files(self)
    }

    fn zeitwerk_consumer_files(&self) -> &HashSet<ProjectFile> {
        self.zeitwerk_consumer_files
            .get_or_init(|| build_zeitwerk_consumer_files(self))
    }

    fn zeitwerk_autoload_code_units(&self) -> &HashSet<CodeUnit> {
        self.zeitwerk_autoload_code_units
            .get_or_init(|| build_zeitwerk_autoload_code_units(self))
    }

    fn reverse_import_index(&self) -> Arc<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>> {
        self.build_reverse_import_index()
    }

    fn mixin_relations(&self) -> &[TypeRelation] {
        RubyAnalyzer::mixin_relations(self)
    }

    fn semantic_facts(&self) -> &RubySemanticFacts {
        RubyAnalyzer::semantic_facts(self)
    }

    fn types_by_identifier(&self) -> &HashMap<String, Vec<CodeUnit>> {
        RubyAnalyzer::types_by_identifier(self)
    }

    fn method_dispatch_mode(&self, unit: &CodeUnit) -> RubyMethodDispatchMode {
        RubyAnalyzer::method_dispatch_mode(self, unit)
    }

    /// The one accessor with no landed precedent: it reads
    /// `TreeSitterAnalyzer::fetch_file_state`, whose `Arc<FileState>` is
    /// crate-private here, and hands the decoded facts across.
    fn forward_owner_relation_facts(&self, owner: &CodeUnit) -> Vec<RubyOwnerRelationFact> {
        RubyAnalyzer::forward_owner_relation_facts(self, owner)
    }
}
