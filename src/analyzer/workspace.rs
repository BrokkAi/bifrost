use crate::analyzer::persistence::AnalyzerStorage;
use crate::analyzer::{
    AnalyzerConfig, AnalyzerDelegate, BuildProgress, CSharpAnalyzer, CppAnalyzer, GoAnalyzer,
    IAnalyzer, JavaAnalyzer, JavascriptAnalyzer, Language, MultiAnalyzer, PhpAnalyzer, Project,
    ProjectFile, PythonAnalyzer, RubyAnalyzer, RustAnalyzer, ScalaAnalyzer, TypescriptAnalyzer,
};
use crate::profiling;
use std::collections::{BTreeMap, BTreeSet};
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
    fn indexed_source<'a>(&'a self, _file: &ProjectFile) -> Option<&'a str> {
        None
    }

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

    fn declarations(
        &self,
        _file: &crate::analyzer::ProjectFile,
    ) -> std::collections::BTreeSet<crate::analyzer::CodeUnit> {
        std::collections::BTreeSet::new()
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
    pub fn build(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        Self::build_filtered(project, config, None, None, None)
    }

    pub fn build_for_languages(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        languages: &BTreeSet<Language>,
    ) -> Self {
        Self::build_filtered(project, config, Some(languages), None, None)
    }

    /// Build the workspace analyzer with persistence enabled. Each
    /// language analyzer reads/writes its baseline through `storage` —
    /// see `crate::analyzer::persistence` for the schema + reconcile
    /// algorithm.
    pub fn build_with_storage(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        storage: Arc<AnalyzerStorage>,
    ) -> Self {
        Self::build_filtered(project, config, None, Some(storage), None)
    }

    pub fn build_with_storage_and_progress<F>(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        storage: Arc<AnalyzerStorage>,
        progress: F,
    ) -> Self
    where
        F: Fn(crate::analyzer::BuildProgressEvent) + Send + Sync + 'static,
    {
        Self::build_filtered(
            project,
            config,
            None,
            Some(storage),
            Some(Arc::new(progress)),
        )
    }

    /// Storage-aware variant of `build_for_languages`.
    pub fn build_for_languages_with_storage(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        languages: &BTreeSet<Language>,
        storage: Arc<AnalyzerStorage>,
    ) -> Self {
        Self::build_filtered(project, config, Some(languages), Some(storage), None)
    }

    /// Build with on-disk persistence at the project's default cache location
    /// (`<persistence_root>/.bifrost/analyzer.db`) when one is available,
    /// reusing the persisted baseline so only changed files are re-analyzed.
    ///
    /// Persistence is best-effort: when the project has no persistence root,
    /// the cache path is unsafe (symlinked), or the DB cannot be opened, this
    /// transparently falls back to a full in-memory `build`. The returned
    /// analyzer retains the storage handle, so later incremental `update`s
    /// write their changes back.
    pub fn build_persisted(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        match Self::open_default_storage(project.as_ref()) {
            Some(storage) => Self::build_with_storage(project, config, storage),
            None => Self::build(project, config),
        }
    }

    /// Progress-reporting variant of `build_persisted`.
    pub fn build_persisted_with_progress<F>(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        progress: F,
    ) -> Self
    where
        F: Fn(crate::analyzer::BuildProgressEvent) + Send + Sync + 'static,
    {
        match Self::open_default_storage(project.as_ref()) {
            Some(storage) => {
                Self::build_with_storage_and_progress(project, config, storage, progress)
            }
            None => Self::build(project, config),
        }
    }

    /// Open the analyzer DB at the project's default, symlink-safe cache path.
    /// Returns `None` (disabling persistence) when there is no persistence
    /// root, the path is unsafe, or the DB cannot be opened/migrated.
    fn open_default_storage(project: &dyn Project) -> Option<Arc<AnalyzerStorage>> {
        project
            .persistence_root()
            .and_then(crate::analyzer::persistence::safe_default_db_path)
            .and_then(|path| AnalyzerStorage::open(path).ok())
            .map(Arc::new)
    }

    fn build_filtered(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        requested_languages: Option<&BTreeSet<Language>>,
        storage: Option<Arc<AnalyzerStorage>>,
        progress: Option<BuildProgress>,
    ) -> Self {
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
                macro_rules! build_delegate {
                    ($variant:ident, $analyzer:ty) => {
                        match (storage.as_ref(), progress.as_ref()) {
                            (Some(storage), Some(progress)) => AnalyzerDelegate::$variant(
                                <$analyzer>::new_with_config_storage_and_progress(
                                    project,
                                    cfg,
                                    Arc::clone(storage),
                                    Arc::clone(progress),
                                ),
                            ),
                            (Some(storage), None) => AnalyzerDelegate::$variant(
                                <$analyzer>::new_with_config_and_storage(
                                    project,
                                    cfg,
                                    Arc::clone(storage),
                                ),
                            ),
                            (None, _) => AnalyzerDelegate::$variant(<$analyzer>::new_with_config(
                                project, cfg,
                            )),
                        }
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

        match delegates.len() {
            0 => Self::Empty(EmptyAnalyzer::new(project)),
            1 => Self::Single(Box::new(
                delegates.into_values().next().expect("checked len"),
            )),
            _ => Self::Multi(Box::new(MultiAnalyzer::new(delegates))),
        }
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

    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        match self {
            Self::Empty(_) => Self::Empty(EmptyAnalyzer::new(project)),
            Self::Single(delegate) => Self::Single(Box::new(delegate.clone_with_project(project))),
            Self::Multi(analyzer) => Self::Multi(Box::new(analyzer.clone_with_project(project))),
        }
    }

    pub fn update(&self, changed_files: &BTreeSet<crate::analyzer::ProjectFile>) -> Self {
        match self {
            Self::Empty(analyzer) => Self::Empty(analyzer.clone()),
            Self::Single(delegate) => Self::Single(Box::new(delegate.update(changed_files))),
            Self::Multi(analyzer) => Self::Multi(Box::new(analyzer.update(changed_files))),
        }
    }

    pub fn update_all(&self) -> Self {
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
    use crate::analyzer::{FilesystemProject, OverlayProject};

    #[test]
    fn clone_with_project_rebinds_analyzer_reads_to_overlay_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let path = root.join("Main.java");
        std::fs::write(&path, "class Main {}\n").unwrap();
        let file = ProjectFile::new(root.clone(), "Main.java");
        let delegate: Arc<dyn Project> = Arc::new(FilesystemProject::new(&root).unwrap());
        let overlay = Arc::new(OverlayProject::new(delegate));
        assert!(overlay.set(path.clone(), "class First {}\n".to_string()));
        let workspace = WorkspaceAnalyzer::build(overlay.clone(), AnalyzerConfig::default());

        let snapshot = Arc::new(overlay.snapshot());
        let request_workspace = workspace.clone_with_project(snapshot.clone() as Arc<dyn Project>);
        assert!(overlay.set(path, "class Second {}\n".to_string()));

        assert_eq!(
            request_workspace
                .analyzer()
                .project()
                .read_source(&file)
                .unwrap(),
            "class First {}\n"
        );
    }
}
