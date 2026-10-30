//! Ruby's import surface: the analyzer-bound half.
//!
//! Every decision here is [`brokk_bifrost_ruby::imports`]. What stays is the
//! memoized state -- the autoload constant index, the five Zeitwerk `OnceLock`
//! cells, the reverse-import `PoolSafeMemo`, the two moka caches -- and the
//! `get_or_init` call sites that fill it.
//!

use crate::analyzer::ruby::source_facts::RubySourceFacts;

use crate::analyzer::ruby::*;

use brokk_bifrost_core::analyzer::model::ImportInfo;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::query_token::QueryScope;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_ruby::imports::{
    build_autoload_constant_files, build_zeitwerk_autoload_code_units,
    gemfile_declares_zeitwerk_autoloading, gemfile_lock_declares_zeitwerk_autoloading,
    is_zeitwerk_autoload_file, ruby_effective_imported_code_units, ruby_imported_files_from_infos,
    ruby_required_files, ruby_transitive_referencing_files_of,
};
use brokk_bifrost_ruby::mixins::RubyOwnerRelationFact;
use std::sync::Arc;

impl RubyAnalyzer {
    fn load_authority_files(
        &self,
        reads: &brokk_bifrost_analysis::analyzer::ReadLedger,
    ) -> Arc<[ReadKey]> {
        reads
            .keys()
            .into_iter()
            .filter(|key| match key {
                ReadKey::PathAbsent { .. } => true,
                ReadKey::File { rel_path, .. } => {
                    let file = ProjectFile::new(
                        self.inner.project().root().to_path_buf(),
                        rel_path.as_ref(),
                    );
                    file_language(&file) != Language::Ruby
                }
                _ => false,
            })
            .collect()
    }

    fn canonical_source_files(&self) -> Option<Vec<ProjectFile>> {
        let files = self
            .inner
            .project()
            .all_files_shared()
            .map_err(|error| {
                self.record_query_failure(
                    brokk_bifrost_analysis::analyzer::store::StoreError::new(format!(
                        "reading Ruby source inventory: {error}"
                    )),
                );
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

    fn zeitwerk_files(&self) -> HashSet<ProjectFile> {
        if !brokk_bifrost_ruby::graph_support::RubySource::has_zeitwerk_autoload_conventions(self) {
            return HashSet::default();
        }
        match self.project().analyzable_files(Language::Ruby) {
            Ok(files) => files.into_iter().collect(),
            Err(error) => {
                self.record_query_failure(
                    brokk_bifrost_analysis::analyzer::store::StoreError::new(format!(
                        "Ruby Zeitwerk inventory IO: {error}"
                    )),
                );
                HashSet::default()
            }
        }
    }

    pub(crate) fn canonical_sources_ready(&self) -> bool {
        self.source_readiness.read(
            &memo_attribution(self),
            |memo| {
                if memo.get().is_some() {
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
                memo.get_or_init(|| ());
                true
            },
            |_| self.authority_inputs(),
        )
    }

    /// Project files this file pulls in via supported Ruby require forms.
    pub(crate) fn required_files(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Vec<ProjectFile> {
        ruby_required_files(self, token, file)
    }

    pub(crate) fn zeitwerk_autoload_files(&self) -> std::sync::Arc<HashSet<ProjectFile>> {
        self.zeitwerk_autoload_files.read(
            &memo_attribution(self),
            |memo| {
                brokk_bifrost_analysis::analyzer::common::complete_query_cache_arc_cell(
                    self,
                    memo,
                    || {
                        self.zeitwerk_files()
                            .into_iter()
                            .filter(is_zeitwerk_autoload_file)
                            .collect()
                    },
                )
            },
            |_| self.authority_inputs(),
        )
    }

    pub(crate) fn build_reverse_import_index(
        &self,
        token: QueryToken<'_>,
    ) -> Arc<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>> {
        if !self.canonical_sources_ready() {
            return Arc::new(HashMap::default());
        }
        let entry = self.reverse_import_index.read(
            &memo_attribution(self),
            |(memo, inputs)| {
                if let Some(files) = inputs.get(&()) {
                    let missing =
                        || unreachable!("a load certificate is published after its index");
                    return (memo.get_or_build(missing, missing), files);
                }
                // If the bounded certificate was evicted, repeat the existing build
                // for its inputs; the generation's original index stays shared.
                let (attempt, reads) =
                    brokk_bifrost_analysis::analyzer::capture_query_reads(self, || {
                        brokk_bifrost_analysis::analyzer::common::complete_query_cache_fill(self, || {
                            brokk_bifrost_core::analyzer::capabilities::memoized_reverse_file_index(
                                &PoolSafeMemo::new(),
                                || self.inner.all_files(),
                                |file| self.required_files(token, file),
                            )
                        })
                    });
                let files = self.load_authority_files(&reads);
                let index = match attempt {
                    Ok(index) => index,
                    Err(index) => return (Arc::new(index), files),
                };
                let index = memo.get_or_build(|| Arc::clone(&index), || Arc::clone(&index));
                inputs.insert((), Arc::clone(&files));
                (index, files)
            },
            |entry| self.authority_inputs_with(&entry.1),
        );
        Arc::clone(entry.0.as_ref())
    }
}

impl ImportAnalysisProvider for RubyAnalyzer {
    fn import_infos_for_files(
        &self,
        files: &[ProjectFile],
    ) -> Option<
        brokk_bifrost_core::hash::HashMap<
            ProjectFile,
            Vec<brokk_bifrost_core::analyzer::model::ImportInfo>,
        >,
    > {
        Some(self.inner.bulk_import_infos(files.iter().cloned()))
    }

    fn file_dependency_facts_for_files(
        &self,
        files: &[ProjectFile],
    ) -> Option<
        brokk_bifrost_core::hash::HashMap<
            ProjectFile,
            brokk_bifrost_core::analyzer::capabilities::FileDependencyFacts,
        >,
    > {
        Some(self.inner.bulk_file_dependency_facts(files.iter().cloned()))
    }

    fn imported_code_units_of(&self, file: &ProjectFile) -> Arc<HashSet<CodeUnit>> {
        if !self.canonical_sources_ready() {
            return Arc::new(HashSet::default());
        }
        let value = self
            .imported_code_units
            .read(&memo_attribution(self), |cache, capture| {
                Ok::<_, std::convert::Infallible>(cache.get(file).unwrap_or_else(|| {
                    let cache_fill =
                        brokk_bifrost_analysis::analyzer::common::QueryCacheFill::new(self);
                    let entry = Arc::new(capture.build_weighted(|| {
                        let value = {
                            let scope = AnalyzerQueryScope::new(self);
                            let token = scope.token();

                            Arc::new(ruby_effective_imported_code_units(self, token, file))
                        };
                        let bytes = weight_code_unit_set(file, &value) as usize;
                        (value, bytes)
                    }));
                    if cache_fill.is_complete() {
                        cache.insert(file.clone(), Arc::clone(&entry));
                    }
                    entry
                }))
            })
            .expect("import memo build is infallible");
        Arc::clone(&value)
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        if !self.canonical_sources_ready() {
            return HashSet::default();
        }
        let value = self
            .referencing_files
            .read(&memo_attribution(self), |cache, capture| {
                Ok::<_, std::convert::Infallible>(cache.get(file).unwrap_or_else(|| {
                    let cache_fill =
                        brokk_bifrost_analysis::analyzer::common::QueryCacheFill::new(self);
                    let entry = Arc::new(capture.build_weighted(|| {
                        let value = {
                            let referencing = ruby_transitive_referencing_files_of(self, file);

                            Arc::new(referencing)
                        };
                        let bytes = weight_project_file_set(file, &value) as usize;
                        (value, bytes)
                    }));
                    if cache_fill.is_complete() {
                        cache.insert(file.clone(), Arc::clone(&entry));
                    }
                    entry
                }))
            })
            .expect("import memo build is infallible");
        (**value).clone()
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
    fn required_file_exists(&self, file: &ProjectFile) -> bool {
        let exists = file.exists();
        if !brokk_bifrost_analysis::analyzer::read_attribution_records_reads(|| {
            self.read_ledger_attached()
        }) {
            return exists;
        }
        if exists {
            match self.inner.project().read_source_snapshot(file) {
                Ok(snapshot) => self.record_read(ReadKey::file(
                    Language::Ruby,
                    brokk_bifrost_core::path_utils::rel_path_string(file),
                    snapshot.oid(),
                )),
                Err(error) => {
                    self.record_query_failure(
                        brokk_bifrost_analysis::analyzer::store::StoreError::new(format!(
                            "reading Ruby load candidate {file:?}: {error}"
                        )),
                    );
                    self.record_unattributed_read();
                }
            }
        } else {
            self.record_read(ReadKey::path_absent(
                Language::Ruby,
                brokk_bifrost_core::path_utils::rel_path_string(file),
            ));
        }
        exists
    }

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

    fn autoload_constant_files(&self) -> Option<Arc<AutoloadConstantFiles>> {
        self.autoload_constant_files
            .read(
                &memo_attribution(self),
                |(memo, inputs)| {
                    if let (Some(index), Some(files)) = (memo.get(), inputs.get(&())) {
                        return Some((Arc::clone(index), files));
                    }
                    let (attempt, reads) =
                        brokk_bifrost_analysis::analyzer::capture_query_reads(self, || {
                            brokk_bifrost_analysis::analyzer::common::complete_query_cache_fill(
                                self,
                                || build_autoload_constant_files(self),
                            )
                        });
                    let files = self.load_authority_files(&reads);
                    match attempt {
                        Ok(Some(index)) => {
                            let index = Arc::clone(memo.get_or_init(|| Arc::new(index)));
                            inputs.insert((), Arc::clone(&files));
                            Some((index, files))
                        }
                        Err(Some(index)) => Some((Arc::new(index), files)),
                        Ok(None) | Err(None) => None,
                    }
                },
                |answer| {
                    self.authority_inputs_with(
                        answer.as_ref().map_or(&[], |entry| entry.1.as_ref()),
                    )
                },
            )
            .map(|entry| entry.0)
    }

    fn has_zeitwerk_autoload_conventions(&self) -> bool {
        self.zeitwerk_project.read(
            &memo_attribution(self),
            |memo| {
                brokk_bifrost_analysis::analyzer::common::complete_query_cache_cell(
                    self,
                    memo,
                    || {
                        for (path, matches) in [
                            (
                                "Gemfile",
                                gemfile_declares_zeitwerk_autoloading as fn(&str) -> bool,
                            ),
                            (
                                "Gemfile.lock",
                                gemfile_lock_declares_zeitwerk_autoloading as fn(&str) -> bool,
                            ),
                        ] {
                            let file = ProjectFile::new(self.project().root().to_path_buf(), path);
                            match self.project().read_source(&file) {
                                Ok(source) if matches(&source) => return true,
                                Ok(_) => {}
                                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                                Err(error) => self.record_query_failure(
                                    brokk_bifrost_analysis::analyzer::store::StoreError::new(
                                        format!("Ruby Zeitwerk {path} IO: {error}"),
                                    ),
                                ),
                            }
                        }
                        false
                    },
                )
            },
            |_| self.authority_inputs(),
        )
    }

    fn zeitwerk_autoload_files(&self) -> std::sync::Arc<HashSet<ProjectFile>> {
        RubyAnalyzer::zeitwerk_autoload_files(self)
    }

    fn zeitwerk_consumer_files(&self) -> std::sync::Arc<HashSet<ProjectFile>> {
        self.zeitwerk_consumer_files.read(
            &memo_attribution(self),
            |memo| {
                brokk_bifrost_analysis::analyzer::common::complete_query_cache_arc_cell(
                    self,
                    memo,
                    || self.zeitwerk_files(),
                )
            },
            |_| self.authority_inputs(),
        )
    }

    fn zeitwerk_autoload_code_units(&self) -> std::sync::Arc<HashSet<CodeUnit>> {
        self.zeitwerk_autoload_code_units.read(
            &memo_attribution(self),
            |memo| {
                brokk_bifrost_analysis::analyzer::common::complete_query_cache_arc_cell(
                    self,
                    memo,
                    || build_zeitwerk_autoload_code_units(self),
                )
            },
            |_| self.authority_inputs(),
        )
    }

    fn reverse_import_index(&self) -> Arc<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        self.build_reverse_import_index(token)
    }

    fn mixin_relations(&self) -> std::sync::Arc<Vec<TypeRelation>> {
        RubyAnalyzer::mixin_relations(self)
    }

    fn semantic_facts(&self) -> std::sync::Arc<RubySemanticFacts> {
        RubyAnalyzer::semantic_facts(self)
    }

    fn types_by_identifier(&self) -> std::sync::Arc<HashMap<String, Vec<CodeUnit>>> {
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
