use crate::analyzer::store::StoreError;
use crate::analyzer::{
    AnalyzerConfig, AnalyzerDelegate, BuildProgress, CSharpAnalyzer, CppAnalyzer, GoAnalyzer,
    IAnalyzer, JavaAnalyzer, JavascriptAnalyzer, Language, MultiAnalyzer, PhpAnalyzer, Project,
    PythonAnalyzer, RubyAnalyzer, RustAnalyzer, ScalaAnalyzer, TypescriptAnalyzer,
};
use crate::profiling;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

#[derive(Clone)]
pub struct EmptyAnalyzer {
    project: Arc<dyn Project>,
}

impl EmptyAnalyzer {
    pub fn new(project: Arc<dyn Project>) -> Self {
        Self { project }
    }
}

impl IAnalyzer for EmptyAnalyzer {
    fn all_declarations(&self) -> Box<dyn Iterator<Item = crate::analyzer::CodeUnit> + '_> {
        Box::new(std::iter::empty())
    }

    fn languages(&self) -> std::collections::BTreeSet<Language> {
        std::collections::BTreeSet::new()
    }

    fn update(
        &self,
        _changed_files: &std::collections::BTreeSet<crate::analyzer::ProjectFile>,
    ) -> Self
    where
        Self: Sized,
    {
        self.clone()
    }

    fn update_all(&self) -> Self
    where
        Self: Sized,
    {
        self.clone()
    }

    fn project(&self) -> &dyn Project {
        self.project.as_ref()
    }

    fn get_all_declarations(&self) -> Vec<crate::analyzer::CodeUnit> {
        Vec::new()
    }

    fn declarations(
        &self,
        _file: &crate::analyzer::ProjectFile,
    ) -> std::collections::BTreeSet<crate::analyzer::CodeUnit> {
        std::collections::BTreeSet::new()
    }

    fn get_definitions(&self, _fq_name: &str) -> Vec<crate::analyzer::CodeUnit> {
        Vec::new()
    }

    fn direct_children(
        &self,
        _code_unit: &crate::analyzer::CodeUnit,
    ) -> Vec<crate::analyzer::CodeUnit> {
        Vec::new()
    }

    fn extract_call_receiver(&self, _reference: &str) -> Option<String> {
        None
    }

    fn import_statements(&self, _file: &crate::analyzer::ProjectFile) -> Vec<String> {
        Vec::new()
    }

    fn enclosing_code_unit(
        &self,
        _file: &crate::analyzer::ProjectFile,
        _range: &crate::analyzer::Range,
    ) -> Option<crate::analyzer::CodeUnit> {
        None
    }

    fn enclosing_code_unit_for_lines(
        &self,
        _file: &crate::analyzer::ProjectFile,
        _start_line: usize,
        _end_line: usize,
    ) -> Option<crate::analyzer::CodeUnit> {
        None
    }

    fn is_access_expression(
        &self,
        _file: &crate::analyzer::ProjectFile,
        _start_byte: usize,
        _end_byte: usize,
    ) -> bool {
        false
    }

    fn find_nearest_declaration(
        &self,
        _file: &crate::analyzer::ProjectFile,
        _start_byte: usize,
        _end_byte: usize,
        _ident: &str,
    ) -> Option<crate::analyzer::DeclarationInfo> {
        None
    }

    fn ranges(&self, _code_unit: &crate::analyzer::CodeUnit) -> Vec<crate::analyzer::Range> {
        Vec::new()
    }

    fn get_skeleton(&self, _code_unit: &crate::analyzer::CodeUnit) -> Option<String> {
        None
    }

    fn get_skeleton_header(&self, _code_unit: &crate::analyzer::CodeUnit) -> Option<String> {
        None
    }

    fn get_source(
        &self,
        _code_unit: &crate::analyzer::CodeUnit,
        _include_comments: bool,
    ) -> Option<String> {
        None
    }

    fn get_sources(
        &self,
        _code_unit: &crate::analyzer::CodeUnit,
        _include_comments: bool,
    ) -> std::collections::BTreeSet<String> {
        std::collections::BTreeSet::new()
    }

    fn search_definitions(
        &self,
        _pattern: &str,
        _auto_quote: bool,
    ) -> std::collections::BTreeSet<crate::analyzer::CodeUnit> {
        std::collections::BTreeSet::new()
    }
}

#[derive(Clone)]
pub enum WorkspaceAnalyzer {
    Empty(EmptyAnalyzer),
    Single(Box<AnalyzerDelegate>),
    Multi(Box<MultiAnalyzer>),
}

impl WorkspaceAnalyzer {
    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        match self {
            Self::Empty(_) => Self::Empty(EmptyAnalyzer::new(project)),
            Self::Single(delegate) => Self::Single(Box::new(delegate.clone_with_project(project))),
            Self::Multi(analyzer) => Self::Multi(Box::new(analyzer.clone_with_project(project))),
        }
    }

    pub fn build(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let store_context = crate::analyzer::default_store_context(project.as_ref());
        Self::build_filtered(project, config, None, store_context, None, true)
            .expect("failed to initialize in-memory workspace analyzer")
    }

    pub(crate) fn build_for_service(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let store_context = crate::analyzer::default_store_context(project.as_ref());
        Self::build_filtered(project, config, None, store_context, None, false)
            .expect("failed to initialize in-memory workspace analyzer")
    }

    pub fn build_for_languages(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        languages: &BTreeSet<Language>,
    ) -> Self {
        let store_context = crate::analyzer::default_store_context(project.as_ref());
        Self::build_filtered(project, config, Some(languages), store_context, None, true)
            .expect("failed to initialize in-memory workspace analyzer")
    }

    pub fn build_persisted(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
    ) -> Result<Self, StoreError> {
        let store_context = crate::analyzer::persistent_store_context(project.as_ref())?;
        Self::build_filtered(project, config, None, store_context, None, true)
    }

    pub(crate) fn build_persisted_for_service(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
    ) -> Result<Self, StoreError> {
        let store_context = crate::analyzer::persistent_store_context(project.as_ref())?;
        Self::build_filtered(project, config, None, store_context, None, false)
    }

    pub(crate) fn build_persisted_at_for_service(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        db_path: &Path,
    ) -> Result<Self, StoreError> {
        let store_context =
            crate::analyzer::persistent_store_context_at(project.as_ref(), db_path)?;
        Self::build_filtered(project, config, None, store_context, None, false)
    }

    /// Progress-reporting variant of `build_persisted`.
    pub fn build_persisted_with_progress<F>(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        progress: F,
    ) -> Result<Self, StoreError>
    where
        F: Fn(crate::analyzer::BuildProgressEvent) + Send + Sync + 'static,
    {
        let store_context = crate::analyzer::persistent_store_context(project.as_ref())?;
        Self::build_filtered(
            project,
            config,
            None,
            store_context,
            Some(Arc::new(progress)),
            true,
        )
    }

    fn build_filtered(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        requested_languages: Option<&BTreeSet<Language>>,
        store_context: crate::analyzer::AnalyzerStoreContext,
        progress: Option<BuildProgress>,
        revalidate_filesystem_paths: bool,
    ) -> Result<Self, StoreError> {
        let _scope = profiling::scope("WorkspaceAnalyzer::build");
        let mut delegates = BTreeMap::new();
        let project_languages = project.analyzer_languages();
        let selected_languages: Vec<_> = match requested_languages {
            Some(requested) if !requested.is_empty() => project_languages
                .into_iter()
                .filter(|language| requested.contains(language))
                .collect(),
            _ => project_languages.into_iter().collect(),
        };
        for language in selected_languages {
            let delegate = {
                let _scope = profiling::scope(format!("WorkspaceAnalyzer::build[{language:?}]"));
                let project = Arc::clone(&project);
                let cfg = config.clone();
                let mut store_context = store_context.clone();
                store_context.live_paths = Arc::new(if revalidate_filesystem_paths {
                    crate::analyzer::store::liveness::LivePathMap::default()
                } else {
                    crate::analyzer::store::liveness::LivePathMap::trust_filesystem_generation()
                });
                macro_rules! build_delegate {
                    ($variant:ident, $analyzer:ty) => {
                        AnalyzerDelegate::$variant(<$analyzer>::new_with_config_store_context(
                            project,
                            cfg,
                            store_context,
                            progress.as_ref().map(Arc::clone),
                        )?)
                    };
                }
                match language {
                    Language::Java => build_delegate!(Java, JavaAnalyzer),
                    Language::Go => build_delegate!(Go, GoAnalyzer),
                    Language::Cpp => build_delegate!(Cpp, CppAnalyzer),
                    Language::JavaScript => build_delegate!(JavaScript, JavascriptAnalyzer),
                    Language::TypeScript => build_delegate!(TypeScript, TypescriptAnalyzer),
                    Language::Python => build_delegate!(Python, PythonAnalyzer),
                    Language::Rust => build_delegate!(Rust, RustAnalyzer),
                    Language::Php => build_delegate!(Php, PhpAnalyzer),
                    Language::Scala => build_delegate!(Scala, ScalaAnalyzer),
                    Language::CSharp => build_delegate!(CSharp, CSharpAnalyzer),
                    Language::Ruby => build_delegate!(Ruby, RubyAnalyzer),
                    Language::None => continue,
                }
            };
            delegates.insert(language, delegate);
        }

        Ok(match delegates.len() {
            0 => Self::Empty(EmptyAnalyzer::new(project)),
            1 => Self::Single(Box::new(
                delegates.into_values().next().expect("checked len"),
            )),
            _ => Self::Multi(Box::new(MultiAnalyzer::new(delegates))),
        })
    }

    pub fn analyzer(&self) -> &dyn IAnalyzer {
        match self {
            Self::Empty(analyzer) => analyzer,
            Self::Single(delegate) => match delegate.as_ref() {
                AnalyzerDelegate::Java(analyzer) => analyzer,
                AnalyzerDelegate::CSharp(analyzer) => analyzer,
                AnalyzerDelegate::Cpp(analyzer) => analyzer,
                AnalyzerDelegate::Go(analyzer) => analyzer,
                AnalyzerDelegate::JavaScript(analyzer) => analyzer,
                AnalyzerDelegate::Php(analyzer) => analyzer,
                AnalyzerDelegate::Python(analyzer) => analyzer,
                AnalyzerDelegate::TypeScript(analyzer) => analyzer,
                AnalyzerDelegate::Rust(analyzer) => analyzer,
                AnalyzerDelegate::Scala(analyzer) => analyzer,
                AnalyzerDelegate::Ruby(analyzer) => analyzer,
            },
            Self::Multi(analyzer) => analyzer.as_ref(),
        }
    }

    /// Select the execution-semantics provider for the requested file without
    /// widening the monolithic [`IAnalyzer`] surface.
    pub fn program_semantics_provider_for_file(
        &self,
        file: &crate::analyzer::ProjectFile,
    ) -> Option<&dyn crate::analyzer::semantic::ProgramSemanticsProvider> {
        match self {
            Self::Empty(_) => None,
            Self::Single(delegate) => {
                let language = crate::analyzer::common::language_for_file(file);
                (delegate.language() == language).then(|| delegate.program_semantics_provider())
            }
            Self::Multi(analyzer) => analyzer.program_semantics_provider_for_file(file),
        }
    }

    /// Check a retained semantic handle against the complete identity of the
    /// file's current analyzer generation without rematerializing its IR.
    #[cfg(test)]
    pub(crate) fn semantic_artifact_key_is_current(
        &self,
        key: &crate::analyzer::semantic::SemanticArtifactKey,
        max_source_bytes: usize,
    ) -> Result<Option<bool>, crate::analyzer::semantic::SemanticProviderError> {
        let root = self.analyzer().project().root();
        if key.mount() != crate::analyzer::semantic::WorkspaceMountId::from_root(root) {
            return Ok(Some(false));
        }
        let file = crate::analyzer::ProjectFile::new(root.to_path_buf(), key.path().as_path());
        let Some(provider) = self.program_semantics_provider_for_file(&file) else {
            return Ok(Some(false));
        };
        Ok(provider
            .current_artifact_key(&file, max_source_bytes)?
            .map(|current| current == *key))
    }

    /// File-aware semantic materialization routed through the concrete
    /// language analyzer. Unknown extensions remain explicitly unsupported.
    pub fn materialize_program_semantics(
        &self,
        file: &crate::analyzer::ProjectFile,
        request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<
        crate::analyzer::semantic::SemanticOutcome<
            Arc<crate::analyzer::semantic::SemanticArtifact>,
        >,
        crate::analyzer::semantic::SemanticProviderError,
    > {
        let Some(provider) = self.program_semantics_provider_for_file(file) else {
            return Ok(crate::analyzer::semantic::SemanticOutcome::Unsupported {
                capability: crate::analyzer::semantic::SemanticCapability::Procedures,
                partial: None,
                work: crate::analyzer::semantic::SemanticWork::default(),
            });
        };
        provider.materialize(file, request)
    }

    /// Bind the demand-materialized ICFG facade to this exact analyzer
    /// generation without widening the language analyzers or `IAnalyzer`.
    pub fn icfg_provider(&self) -> crate::analyzer::semantic::WorkspaceIcfgProvider<'_> {
        crate::analyzer::semantic::WorkspaceIcfgProvider::new(self)
    }

    /// Bind the language-neutral semantic-oracle facade to this exact analyzer
    /// generation without widening the language analyzers or `IAnalyzer`.
    pub fn semantic_oracle_provider(
        &self,
    ) -> crate::analyzer::semantic::WorkspaceSemanticOracle<'_> {
        crate::analyzer::semantic::WorkspaceSemanticOracle::new(self)
    }

    /// Starts a request-scoped query cache across the active language analyzers.
    pub(crate) fn begin_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        self.analyzer().begin_query(context);
    }

    pub(crate) fn end_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        self.analyzer().end_query(context);
    }

    pub fn update(&self, changed_files: &BTreeSet<crate::analyzer::ProjectFile>) -> Self {
        let _scope = profiling::scope("WorkspaceAnalyzer::update");
        if profiling::enabled() {
            profiling::note(format!("changed_files={}", changed_files.len()));
        }
        match self {
            Self::Empty(analyzer) => Self::Empty(analyzer.clone()),
            Self::Single(delegate) => Self::Single(Box::new(delegate.update(changed_files))),
            Self::Multi(analyzer) => Self::Multi(Box::new(analyzer.update(changed_files))),
        }
    }

    pub fn update_all(&self) -> Self {
        let _scope = profiling::scope("WorkspaceAnalyzer::update_all");
        match self {
            Self::Empty(analyzer) => Self::Empty(analyzer.clone()),
            Self::Single(delegate) => Self::Single(Box::new(delegate.update_all())),
            Self::Multi(analyzer) => Self::Multi(Box::new(analyzer.update_all())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{OverlayProject, ProjectFile, TestProject};
    use crate::gitblob::tests::{commit_all, init_repo};
    use rusqlite::Connection;

    #[test]
    fn semantic_generation_check_rejects_a_stale_configuration_identity() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = ProjectFile::new(root.clone(), "src/generation.ts");
        file.write("export const generation = 1;\n").unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::TypeScript));
        let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
        let cancellation = crate::analyzer::semantic::CancellationToken::default();
        let mut budget = crate::analyzer::semantic::SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &file,
                &mut crate::analyzer::semantic::SemanticRequest::new(&mut budget, &cancellation),
            )
            .unwrap()
            .available_value()
            .cloned()
            .expect("semantic artifact");
        assert!(
            workspace
                .semantic_artifact_key_is_current(artifact.key(), usize::MAX)
                .unwrap()
                .expect("source within limit")
        );

        let current = artifact.key();
        let stale = crate::analyzer::semantic::SemanticArtifactKey::new(
            current.mount(),
            current.path().clone(),
            current.language(),
            current.revision(),
            current.adapter().clone(),
            current.ir_version(),
            crate::analyzer::semantic::ConfigurationFingerprint::hash_bytes(b"stale-configuration"),
            current.dependencies(),
        );
        assert_eq!(
            workspace
                .semantic_artifact_key_is_current(&stale, usize::MAX)
                .unwrap(),
            Some(false)
        );
    }

    #[test]
    fn unsupported_analyzer_query_remains_a_healthy_empty_result() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Python));
        let analyzer = EmptyAnalyzer::new(project);
        let context = Arc::new(crate::analyzer::AnalyzerQueryContext::default());

        analyzer.begin_query(&context);
        assert!(analyzer.definitions("Missing").next().is_none());
        assert!(context.store_error().is_none());
        analyzer.end_query(&context);
    }

    #[test]
    fn request_overlay_snapshot_cannot_replace_committed_structural_facts() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let disk_source = "export const disk = call(1);\n";
        let overlay_source = "export const overlay = call(1, 2);\nexport const extra = call(3);\n";
        std::fs::write(root.join(".gitignore"), ".brokk/\n").unwrap();
        std::fs::write(root.join("app.ts"), disk_source).unwrap();
        let repository = init_repo(&root);
        commit_all(&repository, "disk source");
        let project: Arc<dyn Project> =
            Arc::new(TestProject::new(root.clone(), Language::TypeScript));
        let file = ProjectFile::new(root.clone(), "app.ts");

        let disk_workspace =
            WorkspaceAnalyzer::build_persisted(Arc::clone(&project), AnalyzerConfig::default())
                .expect("persisted analyzer should build");
        let disk_provider = disk_workspace.analyzer().structural_search_providers()[0];
        let disk_facts = disk_provider.structural_facts(&file).unwrap();
        let disk_fact_count = disk_facts.nodes().len();
        assert_eq!(disk_facts.source(), disk_source);

        let overlay = Arc::new(OverlayProject::new(Arc::clone(&project)));
        assert!(overlay.set(file.abs_path(), overlay_source.to_owned()));
        let overlay_workspace =
            disk_workspace.clone_with_project(Arc::clone(&overlay) as Arc<dyn Project>);
        let overlay_provider = overlay_workspace.analyzer().structural_search_providers()[0];
        let extractions_before = overlay_provider.structural_extraction_count();
        let overlay_facts = overlay_provider.structural_facts(&file).unwrap();
        assert_eq!(overlay_facts.source(), overlay_source);
        assert_ne!(overlay_facts.nodes().len(), disk_fact_count);
        assert_eq!(
            overlay_provider.structural_extraction_count(),
            extractions_before + 1,
            "the unseen overlay blob must extract its own facts"
        );
        drop(overlay_workspace);
        drop(disk_workspace);

        let disk_reopened = WorkspaceAnalyzer::build_persisted(project, AnalyzerConfig::default())
            .expect("persisted analyzer should reopen");
        let disk_provider = disk_reopened.analyzer().structural_search_providers()[0];
        let hydrated_before = disk_provider.structural_hydration_count();
        let disk_facts = disk_provider.structural_facts(&file).unwrap();
        assert_eq!(disk_facts.source(), disk_source);
        assert_eq!(disk_facts.nodes().len(), disk_fact_count);
        assert_eq!(disk_provider.structural_extraction_count(), 0);
        assert_eq!(
            disk_provider.structural_hydration_count(),
            hydrated_before + 1
        );
        drop(disk_reopened);

        let disk_oid = git2::Oid::hash_object(git2::ObjectType::Blob, disk_source.as_bytes())
            .expect("hash committed source");
        let committed_snapshot_rows = Connection::open(root.join(".brokk/bifrost_cache.db"))
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM structural_facts_snapshots
                 WHERE blob_oid = ?1 AND lang = 'typescript:ts'",
                [disk_oid.to_string()],
                |row| row.get::<_, usize>(0),
            )
            .unwrap();
        assert_eq!(
            committed_snapshot_rows, 1,
            "overlay analysis must not replace the committed source snapshot"
        );
    }
}
