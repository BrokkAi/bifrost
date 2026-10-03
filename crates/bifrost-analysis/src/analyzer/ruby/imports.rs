//! Ruby's import surface: the analyzer-bound half.
//!
//! Every decision here is [`brokk_bifrost_ruby::imports`]. What stays is the
//! memoized state -- the autoload constant index, the five Zeitwerk `OnceLock`
//! cells, the reverse-import `PoolSafeMemo`, the two moka caches -- and the
//! `get_or_init` call sites that fill it.
//!
use super::*;
use crate::analyzer::ImportInfo;
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_ruby::imports::{
    build_autoload_constant_files, build_zeitwerk_autoload_code_units,
    build_zeitwerk_autoload_files, build_zeitwerk_consumer_files,
    detect_zeitwerk_autoload_conventions, ruby_effective_imported_code_units,
    ruby_imported_files_from_infos, ruby_required_files, ruby_transitive_referencing_files_of,
};
use brokk_bifrost_ruby::mixins::RubyOwnerRelationFact;
use std::sync::Arc;

impl RubyAnalyzer {
    fn canonical_source_files(&self) -> Option<Vec<ProjectFile>> {
        let files = self
            .inner
            .project()
            .all_files_shared()
            .map_err(|error| {
                self.record_query_failure(crate::analyzer::store::StoreError::new(format!(
                    "reading Ruby source inventory: {error}"
                )));
            })
            .ok()?;
        Some(
            files
                .iter()
                .filter(|file| file_language(file) == Language::Ruby)
                .cloned()
                .collect(),
        )
    }

    pub(crate) fn canonical_sources_ready(&self) -> bool {
        if self.source_readiness.get().is_some() {
            return true;
        }
        let Some(files) = self.canonical_source_files() else {
            return false;
        };
        if !files
            .iter()
            .all(|file| self.inner.canonical_ruby_source_facts(file).is_some())
        {
            return false;
        }
        self.source_readiness.get_or_init(|| ());
        true
    }

    /// Project files this file pulls in via supported Ruby require forms.
    pub(crate) fn required_files(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Vec<ProjectFile> {
        ruby_required_files(self, token, file)
    }

    pub(crate) fn zeitwerk_autoload_files(&self) -> &HashSet<ProjectFile> {
        self.zeitwerk_autoload_files
            .get_or_init(|| build_zeitwerk_autoload_files(self))
    }

    pub(super) fn build_reverse_import_index(
        &self,
        token: QueryToken<'_>,
    ) -> Arc<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>> {
        if !self.canonical_sources_ready() {
            return Arc::new(HashMap::default());
        }
        crate::analyzer::memoized_reverse_file_index(
            &self.reverse_import_index,
            || self.inner.all_files(),
            |file| self.required_files(token, file),
        )
    }
}

impl ImportAnalysisProvider for RubyAnalyzer {
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
        if let Some(cached) = self.imported_code_units.get(file) {
            return cached;
        }
        if !self.canonical_sources_ready() {
            return Arc::new(HashSet::default());
        }
        let units = Arc::new(ruby_effective_imported_code_units(self, token, file));
        self.imported_code_units
            .insert(file.clone(), Arc::clone(&units));
        units
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        if let Some(cached) = self.referencing_files.get(file) {
            return (*cached).clone();
        }
        if !self.canonical_sources_ready() {
            return HashSet::default();
        }
        let referencing = ruby_transitive_referencing_files_of(self, file);
        self.referencing_files
            .insert(file.clone(), Arc::new(referencing.clone()));
        referencing
    }

    fn import_info_of(&self, token: QueryToken<'_>, file: &ProjectFile) -> Vec<ImportInfo> {
        self.import_info_of_checked(token, file).unwrap_or_default()
    }

    fn import_info_of_checked(
        &self,
        _token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Option<Vec<ImportInfo>> {
        self.inner.canonical_ruby_source_facts(file).map(|facts| {
            facts
                .loads
                .into_iter()
                .filter(|load| load.generic)
                .map(|load| load.import)
                .collect()
        })
    }

    fn imported_files_from_infos(
        &self,
        file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<HashSet<ProjectFile>> {
        ruby_imported_files_from_infos(self, file, imports)
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

    fn source_files(&self) -> Option<Vec<ProjectFile>> {
        self.canonical_source_files()
    }

    fn source_facts(
        &self,
        file: &ProjectFile,
    ) -> Option<brokk_bifrost_core::analyzer::ruby_facts::RubyFileSourceInfo> {
        self.inner.canonical_ruby_source_facts(file)
    }

    fn autoload_constant_files(&self) -> Option<&HashMap<String, HashSet<ProjectFile>>> {
        if let Some(index) = self.autoload_constant_files.get() {
            return Some(index);
        }
        let index = build_autoload_constant_files(self)?;
        Some(self.autoload_constant_files.get_or_init(|| index))
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
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        self.build_reverse_import_index(token)
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
