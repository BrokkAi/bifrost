use crate::analyzer::common::language_for_file;
use crate::analyzer::jvm::realm_builder::jvm_source_realm;
use crate::analyzer::store::StoreError;
use crate::analyzer::{
    AnalyzerConfig, AnalyzerStoreContext, BuildProgress, CSharpAnalyzer, CloneSmell,
    CloneSmellWeights, CodeUnit, CommentDensityStats, CppAnalyzer, DeclarationInfo,
    DefinitionIndexHandle, ExceptionHandlingAnalysis, ExceptionSmellWeights, GoAnalyzer, IAnalyzer,
    ImportAnalysisProvider, ImportInfo, ImportReachability, JavaAnalyzer, JavascriptAnalyzer,
    KotlinAnalyzer, Language, PhpAnalyzer, Project, ProjectFile, PythonAnalyzer, Range,
    RubyAnalyzer, RustAnalyzer, ScalaAnalyzer, SearchSymbolCandidates, SearchSymbolPatternBatch,
    SignatureMetadata, SummaryFileProjection, TestAssertionAnalysis, TestAssertionSmell,
    TestAssertionWeights, TestDetectionProvider, TypeAliasProvider, TypeHierarchyProvider,
    TypescriptAnalyzer,
};
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
use crate::hash::{HashMap, HashSet};
use crate::profiling;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_jvm::realm::JvmSourceRealm;
use rayon::prelude::*;
use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

/// Resolve a concrete analyzer of type `T` out of a `&dyn IAnalyzer`, whether it is
/// that analyzer directly or a [`MultiAnalyzer`] holding it as a per-language delegate.
///
/// The contract: `T` must be a concrete analyzer type (`RustAnalyzer`,
/// `CppAnalyzer`, ...); `None` means the workspace holds no analyzer of that
/// type, which callers treat as "no declarations of that language exist" --
/// never as an error. This is the one supported downcast from the framework's
/// `&dyn IAnalyzer` into a language analyzer; host crates (e.g. the LSP
/// handlers) call it rather than re-deriving the delegate walk.
pub fn resolve_analyzer<T: Any>(analyzer: &dyn IAnalyzer) -> Option<&T> {
    if let Some(direct) = (analyzer as &dyn Any).downcast_ref::<T>() {
        return Some(direct);
    }
    let multi = (analyzer as &dyn Any).downcast_ref::<MultiAnalyzer>()?;
    multi
        .delegates()
        .values()
        .find_map(|delegate| (delegate.analyzer() as &dyn Any).downcast_ref::<T>())
}

#[derive(Clone)]
pub enum AnalyzerDelegate {
    Java(JavaAnalyzer),
    CSharp(CSharpAnalyzer),
    Cpp(CppAnalyzer),
    Go(GoAnalyzer),
    JavaScript(JavascriptAnalyzer),
    Php(PhpAnalyzer),
    Python(PythonAnalyzer),
    TypeScript(TypescriptAnalyzer),
    Rust(RustAnalyzer),
    Scala(ScalaAnalyzer),
    Ruby(RubyAnalyzer),
    Kotlin(KotlinAnalyzer),
}

impl AnalyzerDelegate {
    pub(crate) fn analyzer(&self) -> &dyn IAnalyzer {
        match self {
            Self::Java(analyzer) => analyzer,
            Self::CSharp(analyzer) => analyzer,
            Self::Cpp(analyzer) => analyzer,
            Self::Go(analyzer) => analyzer,
            Self::JavaScript(analyzer) => analyzer,
            Self::Php(analyzer) => analyzer,
            Self::Python(analyzer) => analyzer,
            Self::TypeScript(analyzer) => analyzer,
            Self::Rust(analyzer) => analyzer,
            Self::Scala(analyzer) => analyzer,
            Self::Ruby(analyzer) => analyzer,
            Self::Kotlin(analyzer) => analyzer,
        }
    }

    pub(crate) fn program_semantics_provider(
        &self,
    ) -> &dyn crate::analyzer::semantic::ProgramSemanticsProvider {
        match self {
            Self::Java(analyzer) => analyzer,
            Self::CSharp(analyzer) => analyzer,
            Self::Cpp(analyzer) => analyzer,
            Self::Go(analyzer) => analyzer,
            Self::JavaScript(analyzer) => analyzer,
            Self::Php(analyzer) => analyzer,
            Self::Python(analyzer) => analyzer,
            Self::TypeScript(analyzer) => analyzer,
            Self::Rust(analyzer) => analyzer,
            Self::Scala(analyzer) => analyzer,
            Self::Ruby(analyzer) => analyzer,
            Self::Kotlin(analyzer) => analyzer,
        }
    }

    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        match self {
            Self::Java(analyzer) => Self::Java(analyzer.clone_with_project(project)),
            Self::CSharp(analyzer) => Self::CSharp(analyzer.clone_with_project(project)),
            Self::Cpp(analyzer) => Self::Cpp(analyzer.clone_with_project(project)),
            Self::Go(analyzer) => Self::Go(analyzer.clone_with_project(project)),
            Self::JavaScript(analyzer) => Self::JavaScript(analyzer.clone_with_project(project)),
            Self::Php(analyzer) => Self::Php(analyzer.clone_with_project(project)),
            Self::Python(analyzer) => Self::Python(analyzer.clone_with_project(project)),
            Self::TypeScript(analyzer) => Self::TypeScript(analyzer.clone_with_project(project)),
            Self::Rust(analyzer) => Self::Rust(analyzer.clone_with_project(project)),
            Self::Scala(analyzer) => Self::Scala(analyzer.clone_with_project(project)),
            Self::Ruby(analyzer) => Self::Ruby(analyzer.clone_with_project(project)),
            Self::Kotlin(analyzer) => Self::Kotlin(analyzer.clone_with_project(project)),
        }
    }

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        match self {
            Self::Java(analyzer) => Some(analyzer),
            Self::CSharp(analyzer) => Some(analyzer),
            Self::Cpp(analyzer) => Some(analyzer),
            Self::Go(analyzer) => Some(analyzer),
            Self::JavaScript(analyzer) => Some(analyzer),
            Self::Php(analyzer) => analyzer.import_analysis_provider(),
            Self::Python(analyzer) => Some(analyzer),
            Self::TypeScript(analyzer) => Some(analyzer),
            Self::Rust(analyzer) => Some(analyzer),
            Self::Scala(analyzer) => analyzer.import_analysis_provider(),
            Self::Ruby(analyzer) => Some(analyzer),
            Self::Kotlin(analyzer) => Some(analyzer),
        }
    }

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
        match self {
            Self::Java(analyzer) => Some(analyzer),
            Self::CSharp(analyzer) => analyzer.type_hierarchy_provider(),
            Self::Cpp(analyzer) => analyzer.type_hierarchy_provider(),
            Self::Go(analyzer) => analyzer.type_hierarchy_provider(),
            Self::JavaScript(analyzer) => analyzer.type_hierarchy_provider(),
            Self::Php(analyzer) => analyzer.type_hierarchy_provider(),
            Self::Python(analyzer) => Some(analyzer),
            Self::TypeScript(analyzer) => analyzer.type_hierarchy_provider(),
            Self::Rust(analyzer) => analyzer.type_hierarchy_provider(),
            Self::Scala(analyzer) => analyzer.type_hierarchy_provider(),
            Self::Ruby(analyzer) => Some(analyzer),
            Self::Kotlin(analyzer) => analyzer.type_hierarchy_provider(),
        }
    }

    fn type_alias_provider(&self) -> Option<&dyn TypeAliasProvider> {
        match self {
            Self::Java(analyzer) => analyzer.type_alias_provider(),
            Self::CSharp(analyzer) => analyzer.type_alias_provider(),
            Self::Cpp(analyzer) => analyzer.type_alias_provider(),
            Self::Go(analyzer) => analyzer.type_alias_provider(),
            Self::JavaScript(analyzer) => analyzer.type_alias_provider(),
            Self::Php(analyzer) => analyzer.type_alias_provider(),
            Self::Python(analyzer) => analyzer.type_alias_provider(),
            Self::TypeScript(analyzer) => analyzer.type_alias_provider(),
            Self::Rust(analyzer) => analyzer.type_alias_provider(),
            Self::Scala(analyzer) => analyzer.type_alias_provider(),
            Self::Ruby(analyzer) => analyzer.type_alias_provider(),
            Self::Kotlin(analyzer) => analyzer.type_alias_provider(),
        }
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        match self {
            Self::Java(analyzer) => Some(analyzer),
            Self::CSharp(analyzer) => Some(analyzer),
            Self::Cpp(analyzer) => analyzer.test_detection_provider(),
            Self::Go(analyzer) => Some(analyzer),
            Self::JavaScript(analyzer) => Some(analyzer),
            Self::Php(analyzer) => Some(analyzer),
            Self::Python(analyzer) => Some(analyzer),
            Self::TypeScript(analyzer) => Some(analyzer),
            Self::Rust(analyzer) => Some(analyzer),
            Self::Scala(analyzer) => Some(analyzer),
            Self::Ruby(analyzer) => Some(analyzer),
            Self::Kotlin(analyzer) => Some(analyzer),
        }
    }

    pub(crate) fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        match self {
            Self::Java(analyzer) => Self::Java(analyzer.update(changed_files)),
            Self::CSharp(analyzer) => Self::CSharp(analyzer.update(changed_files)),
            Self::Cpp(analyzer) => Self::Cpp(analyzer.update(changed_files)),
            Self::Go(analyzer) => Self::Go(analyzer.update(changed_files)),
            Self::JavaScript(analyzer) => Self::JavaScript(analyzer.update(changed_files)),
            Self::Php(analyzer) => Self::Php(analyzer.update(changed_files)),
            Self::Python(analyzer) => Self::Python(analyzer.update(changed_files)),
            Self::TypeScript(analyzer) => Self::TypeScript(analyzer.update(changed_files)),
            Self::Rust(analyzer) => Self::Rust(analyzer.update(changed_files)),
            Self::Scala(analyzer) => Self::Scala(analyzer.update(changed_files)),
            Self::Ruby(analyzer) => Self::Ruby(analyzer.update(changed_files)),
            Self::Kotlin(analyzer) => Self::Kotlin(analyzer.update(changed_files)),
        }
    }

    fn should_receive_changed_file(&self, language: Language, file: &ProjectFile) -> bool {
        language_for_file(file) == language
            || self.analyzer().is_analyzed(file)
            || self.needs_config_update_for(file)
    }

    fn needs_config_update_for(&self, file: &ProjectFile) -> bool {
        match self {
            Self::Java(_) | Self::Scala(_) | Self::Kotlin(_) => {
                crate::analyzer::jvm::dependency_discovery::is_jvm_dependency_input(file)
            }
            Self::CSharp(_) => crate::analyzer::csharp::is_csharp_dependency_input(file),
            Self::Cpp(_) => brokk_bifrost_cpp::compile_context::is_cpp_compile_context_input(file),
            Self::JavaScript(_) | Self::TypeScript(_) => is_js_ts_config_file(file),
            _ => false,
        }
    }

    pub(crate) fn update_all(&self) -> Self {
        match self {
            Self::Java(analyzer) => Self::Java(analyzer.update_all()),
            Self::CSharp(analyzer) => Self::CSharp(analyzer.update_all()),
            Self::Cpp(analyzer) => Self::Cpp(analyzer.update_all()),
            Self::Go(analyzer) => Self::Go(analyzer.update_all()),
            Self::JavaScript(analyzer) => Self::JavaScript(analyzer.update_all()),
            Self::Php(analyzer) => Self::Php(analyzer.update_all()),
            Self::Python(analyzer) => Self::Python(analyzer.update_all()),
            Self::TypeScript(analyzer) => Self::TypeScript(analyzer.update_all()),
            Self::Rust(analyzer) => Self::Rust(analyzer.update_all()),
            Self::Scala(analyzer) => Self::Scala(analyzer.update_all()),
            Self::Ruby(analyzer) => Self::Ruby(analyzer.update_all()),
            Self::Kotlin(analyzer) => Self::Kotlin(analyzer.update_all()),
        }
    }
}

/// Construct the concrete analyzer serving `language`.
///
/// Assembly-layer code: this is the one place outside the registry allowed to name
/// concrete per-language analyzer types, because concrete storage and construction is
/// what [`AnalyzerDelegate`] is for.
pub(crate) fn build_language_delegate(
    language: Language,
    project: Arc<dyn Project>,
    config: AnalyzerConfig,
    mut store_context: AnalyzerStoreContext,
    progress: Option<BuildProgress>,
    revalidate_filesystem_paths: bool,
) -> Result<AnalyzerDelegate, StoreError> {
    let _scope = profiling::scope(format!("WorkspaceAnalyzer::build[{language:?}]"));
    store_context.live_paths = Arc::new(if revalidate_filesystem_paths {
        crate::analyzer::store::liveness::LivePathMap::default()
    } else {
        crate::analyzer::store::liveness::LivePathMap::trust_filesystem_generation()
    });
    macro_rules! build_delegate {
        ($variant:ident, $analyzer:ty) => {
            AnalyzerDelegate::$variant(<$analyzer>::new_with_config_store_context(
                project,
                config,
                store_context,
                progress,
            )?)
        };
    }
    Ok(match language {
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
        Language::Kotlin => build_delegate!(Kotlin, KotlinAnalyzer),
        Language::None => unreachable!("Language::None is filtered before delegate build"),
    })
}

/// Construction state retained by a workspace so an incremental update can
/// add a delegate for a language that was not present at startup.
///
/// A delegate owns a language-specific fork of `store_context.live_paths`, but
/// all delegates created for one workspace must continue to share the same
/// store, GC coordinator, liveness source, and analyzer configuration. Keeping
/// that state here avoids silently rebuilding a newly discovered language with
/// default configuration or an unrelated in-memory store. The initial build's
/// progress callback is deliberately absent: it belongs to that one build and
/// must neither be retained nor receive later incremental-work notifications.
#[derive(Clone)]
pub(crate) struct WorkspaceBuildContext {
    project: Arc<dyn Project>,
    config: AnalyzerConfig,
    store_context: AnalyzerStoreContext,
    requested_languages: Option<BTreeSet<Language>>,
    revalidate_filesystem_paths: bool,
}

impl WorkspaceBuildContext {
    pub(crate) fn new(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        store_context: AnalyzerStoreContext,
        requested_languages: Option<BTreeSet<Language>>,
        revalidate_filesystem_paths: bool,
    ) -> Self {
        Self {
            project,
            config,
            store_context,
            requested_languages: requested_languages.filter(|languages| !languages.is_empty()),
            revalidate_filesystem_paths,
        }
    }

    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        let mut context = self.clone();
        context.project = project;
        context
    }

    pub(crate) fn project(&self) -> &Arc<dyn Project> {
        &self.project
    }

    /// The configuration this workspace was built from, which is where
    /// behavior a host selects (rather than a per-query budget) lives.
    pub(crate) fn config(&self) -> &AnalyzerConfig {
        &self.config
    }

    pub(crate) fn derived_layer_budget_bytes(&self) -> u64 {
        self.config.memo_cache_budget_bytes() / 8
    }

    /// The on-disk path of the analyzer store this workspace was built
    /// against, or `None` when the store lives only in memory.
    pub(crate) fn store_db_path(&self) -> Option<&std::path::Path> {
        self.store_context.store.db_path()
    }

    fn allows_language(&self, language: Language) -> bool {
        language != Language::None
            && self
                .requested_languages
                .as_ref()
                .is_none_or(|languages| languages.contains(&language))
    }

    pub(crate) fn changed_languages(
        &self,
        changed_files: &BTreeSet<ProjectFile>,
    ) -> BTreeSet<Language> {
        changed_files
            .iter()
            .filter(|file| file.exists() || self.project.has_overlay(file))
            .map(language_for_file)
            .filter(|language| self.allows_language(*language))
            .collect()
    }

    pub(crate) fn project_languages(&self) -> BTreeSet<Language> {
        self.project
            .all_files_shared()
            .expect("failed to list workspace files while refreshing analyzer languages")
            .iter()
            .map(language_for_file)
            .filter(|language| self.allows_language(*language))
            .collect()
    }

    pub(crate) fn build_delegate(
        &self,
        language: Language,
    ) -> Result<AnalyzerDelegate, StoreError> {
        debug_assert!(self.allows_language(language));
        build_language_delegate(
            language,
            Arc::clone(&self.project),
            self.config.clone(),
            self.store_context.clone(),
            None,
            self.revalidate_filesystem_paths,
        )
    }
}

fn is_js_ts_config_file(file: &ProjectFile) -> bool {
    matches!(
        file.rel_path().file_name().and_then(|name| name.to_str()),
        Some("tsconfig.json" | "jsconfig.json")
    )
}

pub struct MultiAnalyzer {
    delegates: BTreeMap<Language, AnalyzerDelegate>,
    build_context: Option<Arc<WorkspaceBuildContext>>,
    snapshot_caches: Arc<crate::analyzer::AnalyzerSnapshotCaches>,
    derived_layer_budget_bytes: u64,
    query_contexts: Mutex<Vec<Arc<crate::analyzer::AnalyzerQueryContext>>>,
}

impl Default for MultiAnalyzer {
    fn default() -> Self {
        Self::new(BTreeMap::new())
    }
}

impl Clone for MultiAnalyzer {
    fn clone(&self) -> Self {
        Self {
            delegates: self.delegates.clone(),
            build_context: self.build_context.clone(),
            snapshot_caches: Arc::clone(&self.snapshot_caches),
            derived_layer_budget_bytes: self.derived_layer_budget_bytes,
            query_contexts: Mutex::new(Vec::new()),
        }
    }
}

impl MultiAnalyzer {
    pub fn new(delegates: BTreeMap<Language, AnalyzerDelegate>) -> Self {
        Self::new_with_derived_layer_budget(
            delegates,
            crate::analyzer::structural::execution::derived::SnapshotDerivedLayerCache::DEFAULT_MAX_RETAINED_BYTES,
        )
    }

    pub(crate) fn new_with_derived_layer_budget(
        delegates: BTreeMap<Language, AnalyzerDelegate>,
        derived_layer_budget_bytes: u64,
    ) -> Self {
        Self::new_with_build_context(delegates, derived_layer_budget_bytes, None)
    }

    pub(crate) fn new_for_workspace(
        delegates: BTreeMap<Language, AnalyzerDelegate>,
        build_context: Arc<WorkspaceBuildContext>,
    ) -> Self {
        let derived_layer_budget_bytes = build_context.derived_layer_budget_bytes();
        Self::new_with_build_context(delegates, derived_layer_budget_bytes, Some(build_context))
    }

    fn new_with_build_context(
        delegates: BTreeMap<Language, AnalyzerDelegate>,
        derived_layer_budget_bytes: u64,
        build_context: Option<Arc<WorkspaceBuildContext>>,
    ) -> Self {
        Self {
            delegates,
            build_context,
            snapshot_caches: Arc::new(crate::analyzer::AnalyzerSnapshotCaches::new(
                derived_layer_budget_bytes,
            )),
            derived_layer_budget_bytes,
            query_contexts: Mutex::new(Vec::new()),
        }
    }

    pub fn with_java(java: JavaAnalyzer) -> Self {
        Self::new(BTreeMap::from([(
            Language::Java,
            AnalyzerDelegate::Java(java),
        )]))
    }

    pub fn delegates(&self) -> &BTreeMap<Language, AnalyzerDelegate> {
        &self.delegates
    }

    pub(crate) fn workspace_build_context(&self) -> Option<Arc<WorkspaceBuildContext>> {
        self.build_context.clone()
    }

    pub(crate) fn build_context(&self) -> Option<&WorkspaceBuildContext> {
        self.build_context.as_deref()
    }

    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        Self {
            delegates: self
                .delegates
                .iter()
                .map(|(language, delegate)| {
                    (*language, delegate.clone_with_project(Arc::clone(&project)))
                })
                .collect(),
            build_context: self
                .build_context
                .as_ref()
                .map(|context| Arc::new(context.clone_with_project(project))),
            snapshot_caches: Arc::new(crate::analyzer::AnalyzerSnapshotCaches::new(
                self.derived_layer_budget_bytes,
            )),
            derived_layer_budget_bytes: self.derived_layer_budget_bytes,
            query_contexts: Mutex::new(Vec::new()),
        }
    }

    /// The delegate language a file's queries route to.
    ///
    /// The extension registry answers for every file it names. A file it does
    /// not name may still be analyzed, because a language claimed it through
    /// its own imports (#1837): route those to the one language that infers
    /// claims, so a query positioned inside an adopted `.inc` reaches the
    /// analyzer that indexed it instead of falling off the routing table.
    ///
    /// An unclaimed-extension file that inference did NOT adopt routes to that
    /// same delegate and finds nothing there, which is the same empty answer it
    /// got when it routed nowhere. Asking each delegate whether it analyzed the
    /// file would be exact, but that is a store round-trip on a path every
    /// query takes.
    ///
    /// CLAIMS SEAM: see [`crate::analyzer::languages::claim_inferring_languages`].
    /// With two inferring languages this must become a real lookup.
    fn dispatch_language(&self, file: &ProjectFile) -> Language {
        let language = language_for_file(file);
        if language != Language::None {
            return language;
        }
        crate::analyzer::languages::claim_inferring_languages()
            .iter()
            .copied()
            .find(|language| self.delegates.contains_key(language))
            .unwrap_or(Language::None)
    }

    pub(crate) fn delegate_for_file(&self, file: &ProjectFile) -> Option<&AnalyzerDelegate> {
        self.delegates.get(&self.dispatch_language(file))
    }

    pub(crate) fn program_semantics_provider_for_file(
        &self,
        file: &ProjectFile,
    ) -> Option<&dyn crate::analyzer::semantic::ProgramSemanticsProvider> {
        self.delegate_for_file(file)
            .map(AnalyzerDelegate::program_semantics_provider)
    }

    fn delegate_for_code_unit(&self, code_unit: &CodeUnit) -> Option<&AnalyzerDelegate> {
        self.delegate_for_file(code_unit.source())
    }

    /// The Kotlin delegate, together with a view of the whole JVM source realm,
    /// when this workspace has Kotlin alongside at least one other JVM
    /// language.
    ///
    /// A Kotlin analyzer only indexes `.kt` files, so on its own it cannot see
    /// that the interface a Kotlin class implements is declared in a Java file
    /// next door. `MultiAnalyzer` is the only place that holds every delegate,
    /// so it is where the realm view is constructed. `None` means the widening
    /// would add nothing and the delegate's own answer already stands.
    fn kotlin_realm(&self) -> Option<(&KotlinAnalyzer, JvmSourceRealm<'_>)> {
        let Some(AnalyzerDelegate::Kotlin(kotlin)) = self.delegates.get(&Language::Kotlin) else {
            return None;
        };
        let realm = jvm_source_realm(self);
        realm
            .has_peers_of(Language::Kotlin)
            .then_some((kotlin, realm))
    }
}

impl ImportAnalysisProvider for MultiAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> Arc<HashSet<CodeUnit>> {
        let query_scope = AnalyzerQueryScope::new(self);
        let token = query_scope.token();
        // A Kotlin file can import a Java or Scala declaration from the same
        // workspace, and only the multi-analyzer can see both sides.
        if language_for_file(file) == Language::Kotlin
            && let Some((kotlin, realm)) = self.kotlin_realm()
        {
            return kotlin.imported_code_units_in_realm(token, file, Some(&realm));
        }
        self.delegate_for_file(file)
            .and_then(AnalyzerDelegate::import_analysis_provider)
            .map(|provider| provider.imported_code_units_of(file))
            .unwrap_or_default()
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        self.delegates
            .values()
            .filter_map(AnalyzerDelegate::import_analysis_provider)
            .flat_map(|provider| provider.referencing_files_of(file))
            .collect()
    }

    fn import_info_of(&self, token: QueryToken<'_>, file: &ProjectFile) -> Vec<ImportInfo> {
        self.delegate_for_file(file)
            .and_then(AnalyzerDelegate::import_analysis_provider)
            .map(|provider| provider.import_info_of(token, file))
            .unwrap_or_default()
    }

    fn import_infos_for_files(
        &self,
        files: &[ProjectFile],
    ) -> Option<HashMap<ProjectFile, Vec<ImportInfo>>> {
        let query_scope = AnalyzerQueryScope::new(self);
        let token = query_scope.token();
        if files.is_empty() {
            return None;
        }
        // Route each file to its language delegate and prefer that delegate's
        // bulk reader (one store round-trip for the whole group) over the
        // per-file `import_info_of` path the shared candidate walker would
        // otherwise take. Delegates without a bulk model fall back to per-file
        // reads within their own group so the merged map still covers every
        // file, keeping the caller's result identical to the file-at-a-time
        // path while collapsing thousands of single-row queries into one.
        let mut grouped: BTreeMap<Language, Vec<ProjectFile>> = BTreeMap::new();
        for file in files {
            grouped
                .entry(self.dispatch_language(file))
                .or_default()
                .push(file.clone());
        }
        let mut out: HashMap<ProjectFile, Vec<ImportInfo>> = HashMap::default();
        let mut any = false;
        for (language, group) in grouped {
            let Some(provider) = self
                .delegates
                .get(&language)
                .and_then(AnalyzerDelegate::import_analysis_provider)
            else {
                continue;
            };
            any = true;
            if let Some(map) = provider.import_infos_for_files(&group) {
                out.extend(map);
            } else {
                for file in group {
                    let infos = provider.import_info_of(token, &file);
                    out.insert(file, infos);
                }
            }
        }
        any.then_some(out)
    }

    fn relevant_imports_for(&self, code_unit: &CodeUnit) -> HashSet<String> {
        self.delegate_for_code_unit(code_unit)
            .and_then(AnalyzerDelegate::import_analysis_provider)
            .map(|provider| provider.relevant_imports_for(code_unit))
            .unwrap_or_default()
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        self.delegate_for_file(source_file)
            .and_then(AnalyzerDelegate::import_analysis_provider)
            .map(|provider| provider.could_import_file(source_file, imports, target))
            .unwrap_or(false)
    }

    /// The batch that `could_import_file` above is meant to be answered from.
    ///
    /// Without this override the trait's no-op default answers, so a delegate's
    /// own batch -- `RustAnalyzer::prefetch_import_targets`, and the single
    /// chunked seek it stands for -- never runs on a workspace with more than
    /// one language, which is every workspace #1748 was opened about. Measured
    /// at `0086f1e5` on the rustc tree: zero `prefetch_definitions` spans in a
    /// scan whose candidate discovery took 9,648 point `definition_candidates`
    /// reads.
    ///
    /// Grouping is the same as `import_infos_for_files` above, for the same
    /// reason: the question is per language and only that language's delegate
    /// can answer it. `import_infos` goes through whole rather than split per
    /// group -- a delegate reads it by the file keys it was handed, so a subset
    /// would only cost a copy.
    ///
    /// Between groups is the one place this layer can stop. It polls there
    /// because a group is one batched read and the deadline may have expired
    /// during the previous one; it publishes nothing itself, so stopping leaves
    /// each delegate's request memo exactly as that delegate left it -- the
    /// prefix of a cut-short batch is never memoized as absence.
    fn prefetch_import_targets(
        &self,
        files: &[ProjectFile],
        import_infos: Option<&HashMap<ProjectFile, Vec<ImportInfo>>>,
        cancellation: &crate::CancellationToken,
    ) {
        if files.is_empty() {
            return;
        }
        let mut grouped: BTreeMap<Language, Vec<ProjectFile>> = BTreeMap::new();
        for file in files {
            grouped
                .entry(language_for_file(file))
                .or_default()
                .push(file.clone());
        }
        for (language, group) in grouped {
            if cancellation.is_cancelled() {
                return;
            }
            let Some(provider) = self
                .delegates
                .get(&language)
                .and_then(AnalyzerDelegate::import_analysis_provider)
            else {
                continue;
            };
            provider.prefetch_import_targets(&group, import_infos, cancellation);
        }
    }

    /// A file whose language has no delegate is undecided, not unreachable:
    /// `unwrap_or` must not manufacture a proof the workspace never made.
    fn import_reachability(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> ImportReachability {
        self.delegate_for_file(source_file)
            .and_then(AnalyzerDelegate::import_analysis_provider)
            .map(|provider| provider.import_reachability(source_file, imports, target))
            .unwrap_or(ImportReachability::Unknown)
    }

    /// Without this override, `MultiAnalyzer` falls back to the trait default (always `None`) instead
    /// of forwarding to the per-language delegate's implementation -- silently defeating a delegate's
    /// own `imported_code_units_from_infos` (e.g. Python's) for every workspace-level caller that goes
    /// through `MultiAnalyzer`, which is the common case for a `scan_usages` on a real checkout.
    fn imported_code_units_from_infos(
        &self,
        file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<Arc<HashSet<CodeUnit>>> {
        self.delegate_for_file(file)
            .and_then(AnalyzerDelegate::import_analysis_provider)
            .and_then(|provider| provider.imported_code_units_from_infos(file, imports))
    }

    /// Same omission as the method above, one rung further down: without this
    /// override `resolve_imported_files_from_infos` gets the trait default
    /// `None` and degrades to projecting imported *declarations* back to their
    /// files. An import whose target file declares nothing -- a Ruby
    /// `require_relative` loader, say -- then contributes no file edge at all,
    /// so transitive-importer candidate discovery never reaches the files that
    /// require it. Routing per file is the correct composition: `imports` always
    /// comes from `import_info_of`, which routes through the same
    /// `delegate_for_file`, so the two answers stay consistent.
    fn imported_files_from_infos(
        &self,
        file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<HashSet<ProjectFile>> {
        self.delegate_for_file(file)
            .and_then(AnalyzerDelegate::import_analysis_provider)
            .and_then(|provider| provider.imported_files_from_infos(file, imports))
    }
}

impl TypeHierarchyProvider for MultiAnalyzer {
    fn supports_type_hierarchy(&self, code_unit: &CodeUnit) -> bool {
        self.delegate_for_code_unit(code_unit)
            .and_then(AnalyzerDelegate::type_hierarchy_provider)
            .is_some_and(|provider| provider.supports_type_hierarchy(code_unit))
    }

    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        let query_scope = AnalyzerQueryScope::new(self);
        let token = query_scope.token();
        // A Kotlin class can extend a Java class or implement a Scala trait
        // declared in the same workspace; resolving that needs every JVM
        // delegate, which only the multi-analyzer holds.
        if language_for_file(code_unit.source()) == Language::Kotlin
            && let Some((kotlin, realm)) = self.kotlin_realm()
        {
            return kotlin.direct_ancestors_in_realm(token, code_unit, Some(&realm));
        }
        self.delegate_for_code_unit(code_unit)
            .and_then(AnalyzerDelegate::type_hierarchy_provider)
            .map(|provider| provider.get_direct_ancestors(code_unit))
            .unwrap_or_default()
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        let uncancelled = crate::cancellation::CancellationToken::default();
        self.get_direct_descendants_within(
            code_unit,
            &crate::analyzer::DescendantIndexScope::whole_workspace(&uncancelled),
        )
        .expect("a descendant index that cannot stop always completes")
    }

    fn get_direct_ancestors_within(
        &self,
        code_unit: &CodeUnit,
        scope: &crate::analyzer::DescendantIndexScope<'_>,
    ) -> Option<Vec<CodeUnit>> {
        let query_scope = AnalyzerQueryScope::new(self);
        let token = query_scope.token();
        if language_for_file(code_unit.source()) == Language::Kotlin
            && let Some((kotlin, realm)) = self.kotlin_realm()
        {
            return (!scope.cancellation().is_cancelled())
                .then(|| kotlin.direct_ancestors_in_realm(token, code_unit, Some(&realm)));
        }
        match self
            .delegate_for_code_unit(code_unit)
            .and_then(AnalyzerDelegate::type_hierarchy_provider)
        {
            Some(provider) => provider.get_direct_ancestors_within(code_unit, scope),
            None => Some(Vec::new()),
        }
    }

    fn get_direct_descendants_within(
        &self,
        code_unit: &CodeUnit,
        scope: &crate::analyzer::DescendantIndexScope<'_>,
    ) -> Option<HashSet<CodeUnit>> {
        let query_scope = AnalyzerQueryScope::new(self);
        let token = query_scope.token();
        let mut descendants = match self
            .delegate_for_code_unit(code_unit)
            .and_then(AnalyzerDelegate::type_hierarchy_provider)
        {
            Some(provider) => provider.get_direct_descendants_within(code_unit, scope)?,
            None => HashSet::default(),
        };
        // Kotlin subclasses of a Java or Scala type are invisible to that
        // language's own descendant index, which only walks its own
        // declarations. Kotlin's realm-aware index does resolve across the
        // realm, so folding it in is what makes `Api`'s Kotlin implementors
        // show up.
        //
        // The reverse direction — Java and Scala subclasses of a *Kotlin* type
        // — is still missing, and cannot be fixed here. Each language's
        // descendant index is the inverse of its own ancestor resolution, and
        // Java's and Scala's resolve a spelled supertype against their own
        // declarations only; folding their indexes in for a Kotlin unit would
        // fold in indexes that never saw the Kotlin declaration in the first
        // place. Closing it means giving those two hierarchy resolvers the
        // realm-aware existence predicate Kotlin's already has (`realm_type_exists`
        // / `realm_type_by_fqn` in `kotlin/hierarchy.rs`) — a change to those
        // analyzers, not to this dispatch. Issue #1239 made *usage* resolution
        // realm-aware in both directions; hierarchy resolution is a separate
        // seam and remains one-directional.
        if language_for_file(code_unit.source()) != Language::Kotlin
            && let Some((kotlin, realm)) = self.kotlin_realm()
        {
            descendants.extend(kotlin.direct_descendants_in_realm(
                token,
                code_unit,
                Some(&realm),
                scope,
            )?);
        }
        Some(descendants)
    }
}

/// Method families across the whole workspace (#1477 M4).
///
/// The delegation mirrors `TypeHierarchyProvider`'s, and for the same reason:
/// a Kotlin class can override a Java method, so the ancestor and descendant
/// edges a family walk needs are exactly the realm-aware ones only the
/// multi-analyzer resolves. The per-language relation therefore receives
/// `self` as its hierarchy source rather than the owning delegate.
///
/// Language support is stated per member, never defaulted: a member whose
/// language has no landed family answers `unsupported`, even though this
/// composite exposes a provider for the workspace as a whole.
impl crate::analyzer::usages::MemberFamilyProvider for MultiAnalyzer {
    fn member_family_capability(
        &self,
        member: &CodeUnit,
    ) -> crate::analyzer::structural::resolution::MemberFamilyCapability {
        crate::analyzer::usages::java_member_family_capability(self, member)
    }

    fn member_family(
        &self,
        member: &CodeUnit,
        cancellation: Option<&crate::cancellation::CancellationToken>,
    ) -> crate::analyzer::usages::MemberFamilyAnswer {
        crate::analyzer::usages::java_member_family(self, self, member, cancellation)
    }
}

impl TypeAliasProvider for MultiAnalyzer {
    fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        self.delegate_for_code_unit(code_unit)
            .and_then(AnalyzerDelegate::type_alias_provider)
            .map(|provider| provider.is_type_alias(code_unit))
            .unwrap_or(false)
    }
}

impl TestDetectionProvider for MultiAnalyzer {}

use crate::analyzer::CodeUnitIndex;

impl CodeUnitIndex for MultiAnalyzer {
    fn enclosing_code_unit(&self, file: &ProjectFile, range: &Range) -> Option<CodeUnit> {
        self.delegate_for_file(file)
            .and_then(|delegate| delegate.analyzer().enclosing_code_unit(file, range))
    }

    fn enclosing_code_unit_for_lines(
        &self,
        file: &ProjectFile,
        start_line: usize,
        end_line: usize,
    ) -> Option<CodeUnit> {
        self.delegate_for_file(file).and_then(|delegate| {
            delegate
                .analyzer()
                .enclosing_code_unit_for_lines(file, start_line, end_line)
        })
    }

    fn top_level_declarations(&self, file: &ProjectFile) -> Vec<CodeUnit> {
        match self.delegate_for_file(file) {
            Some(delegate) => delegate.analyzer().top_level_declarations(file),
            None => Vec::new(),
        }
    }

    fn summary_file_projection(&self, file: &ProjectFile) -> Option<Arc<SummaryFileProjection>> {
        self.delegate_for_file(file)
            .and_then(|delegate| delegate.analyzer().summary_file_projection(file))
    }

    fn analyzed_files(&self) -> Vec<ProjectFile> {
        // One visible parent for the per-language fan-out: on an 11-language
        // workspace this is 11 whole-workspace scans and 11 store queries, and
        // #1738's worst route span held nothing but this (uninstrumented).
        let _scope = crate::profiling::scope("analyzer::analyzed_files.fan_out");
        let mut files: Vec<_> = self
            .delegates
            .values()
            .flat_map(|delegate| delegate.analyzer().analyzed_files())
            .collect();
        files.sort();
        files.dedup();
        files
    }

    fn indexed_source(&self, file: &ProjectFile) -> Option<String> {
        self.delegate_for_file(file)
            .and_then(|delegate| delegate.analyzer().indexed_source(file))
    }

    fn location_declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        self.delegate_for_file(file)
            .map(|delegate| delegate.analyzer().location_declarations(file))
            .unwrap_or_default()
    }

    fn location_ranges(&self, code_unit: &CodeUnit) -> Vec<Range> {
        self.delegate_for_code_unit(code_unit)
            .map(|delegate| delegate.analyzer().location_ranges(code_unit))
            .unwrap_or_default()
    }

    fn indexed_source_matches(&self, file: &ProjectFile, source: &str) -> bool {
        self.delegate_for_file(file)
            .is_some_and(|delegate| delegate.analyzer().indexed_source_matches(file, source))
    }

    fn render_source_fragment(
        &self,
        code_unit: &CodeUnit,
        source: String,
        declaration_start: usize,
    ) -> String {
        match self.delegate_for_code_unit(code_unit) {
            Some(delegate) => {
                delegate
                    .analyzer()
                    .render_source_fragment(code_unit, source, declaration_start)
            }
            None => source,
        }
    }

    fn is_analyzed(&self, file: &ProjectFile) -> bool {
        self.delegates
            .values()
            .any(|delegate| delegate.analyzer().is_analyzed(file))
    }

    /// Every delegate sees the whole candidate list and keeps the ones it owns,
    /// so the workspace answer costs one store query per language over the
    /// matched files -- not one whole-workspace enumeration per language, which
    /// is what asking `analyzed_files` here used to cost (#1738).
    fn retain_analyzed(&self, candidates: &[ProjectFile]) -> Vec<ProjectFile> {
        let mut analyzed: Vec<_> = self
            .delegates
            .values()
            .flat_map(|delegate| delegate.analyzer().retain_analyzed(candidates))
            .collect();
        analyzed.sort();
        analyzed.dedup();
        analyzed
    }

    fn languages(&self) -> BTreeSet<Language> {
        self.delegates.keys().copied().collect()
    }

    fn project(&self) -> &dyn Project {
        self.delegates
            .values()
            .next()
            .expect("MultiAnalyzer requires at least one delegate")
            .analyzer()
            .project()
    }

    fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        Box::new(
            self.delegates
                .values()
                .flat_map(|delegate| delegate.analyzer().all_declarations()),
        )
    }

    fn all_declarations_with_primary_ranges(&self) -> Vec<(CodeUnit, Option<Range>)> {
        self.delegates
            .values()
            .flat_map(|delegate| delegate.analyzer().all_declarations_with_primary_ranges())
            .collect()
    }

    fn declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        match self.delegate_for_file(file) {
            Some(delegate) => delegate.analyzer().declarations(file),
            None => BTreeSet::new(),
        }
    }

    fn materialization_records(
        &self,
        file: &ProjectFile,
    ) -> Vec<crate::analyzer::structural::materialization::MaterializationRecord> {
        match self.delegate_for_file(file) {
            Some(delegate) => delegate.analyzer().materialization_records(file),
            None => Vec::new(),
        }
    }

    fn definitions(&self, fq_name: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        let matches: Vec<_> = self
            .delegates
            .iter()
            .flat_map(|(language, delegate)| {
                let _scope =
                    crate::profiling::scope(format!("multi.definitions[{language:?}][{fq_name}]"));
                delegate.analyzer().definitions(fq_name)
            })
            .collect();
        Box::new(matches.into_iter())
    }

    fn direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        match self.delegate_for_code_unit(code_unit) {
            Some(delegate) => delegate.analyzer().direct_children(code_unit),
            None => Vec::new(),
        }
    }

    fn direct_children_in_file(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        match self.delegate_for_code_unit(code_unit) {
            Some(delegate) => delegate.analyzer().direct_children_in_file(code_unit),
            None => Vec::new(),
        }
    }

    fn parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        self.delegate_for_code_unit(code_unit)
            .and_then(|delegate| delegate.analyzer().parent_of(code_unit))
    }

    fn ranges(&self, code_unit: &CodeUnit) -> Vec<Range> {
        self.delegate_for_code_unit(code_unit)
            .map(|delegate| delegate.analyzer().ranges(code_unit))
            .unwrap_or_default()
    }

    fn ranges_with_limit(
        &self,
        code_unit: &CodeUnit,
        max_ranges: usize,
        cancellation: &crate::CancellationToken,
    ) -> (Vec<Range>, usize, bool) {
        self.delegate_for_code_unit(code_unit)
            .map(|delegate| {
                delegate
                    .analyzer()
                    .ranges_with_limit(code_unit, max_ranges, cancellation)
            })
            .unwrap_or_default()
    }

    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        self.delegate_for_code_unit(code_unit)
            .and_then(|delegate| delegate.analyzer().get_skeleton(code_unit))
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        self.delegate_for_code_unit(code_unit)
            .and_then(|delegate| delegate.analyzer().get_skeleton_header(code_unit))
    }

    fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String> {
        self.delegate_for_code_unit(code_unit)
            .and_then(|delegate| delegate.analyzer().get_source(code_unit, include_comments))
    }

    fn get_sources(&self, code_unit: &CodeUnit, include_comments: bool) -> BTreeSet<String> {
        self.delegate_for_code_unit(code_unit)
            .map(|delegate| delegate.analyzer().get_sources(code_unit, include_comments))
            .unwrap_or_default()
    }

    fn search_definitions(&self, pattern: &str, auto_quote: bool) -> BTreeSet<CodeUnit> {
        self.delegates
            .values()
            .collect::<Vec<_>>()
            .into_par_iter()
            .map(|delegate| delegate.analyzer().search_definitions(pattern, auto_quote))
            .reduce(BTreeSet::new, |mut acc, definitions| {
                acc.extend(definitions);
                acc
            })
    }

    fn search_definitions_by_suffix_pattern(
        &self,
        pattern: &str,
        terminal_identifiers: &[String],
        language: Language,
    ) -> BTreeSet<CodeUnit> {
        // The pattern is language-specific, so only that language's delegate
        // can produce matches the caller keeps; fanning out to every delegate
        // multiplied lookup cost by the language count (#1430).
        self.delegates
            .get(&language)
            .map(|delegate| {
                delegate.analyzer().search_definitions_by_suffix_pattern(
                    pattern,
                    terminal_identifiers,
                    language,
                )
            })
            .unwrap_or_default()
    }

    fn lookup_candidates_by_short_name(&self, symbol: &str) -> BTreeSet<CodeUnit> {
        self.delegates
            .values()
            .collect::<Vec<_>>()
            .into_par_iter()
            .map(|delegate| delegate.analyzer().lookup_candidates_by_short_name(symbol))
            .reduce(BTreeSet::new, |mut acc, candidates| {
                acc.extend(candidates);
                acc
            })
    }

    /// Every delegate must be able to answer from an index before a miss is
    /// conclusive: one in-memory delegate's incomplete view would make a
    /// qualified miss mean "not in the indexed languages", not "not in the
    /// workspace".
    fn has_complete_symbol_lookup_index(&self) -> bool {
        self.delegates
            .values()
            .all(|delegate| delegate.analyzer().has_complete_symbol_lookup_index())
    }

    fn lookup_candidates_by_identifier(&self, identifier: &str) -> BTreeSet<CodeUnit> {
        self.delegates
            .values()
            .collect::<Vec<_>>()
            .into_par_iter()
            .map(|delegate| {
                delegate
                    .analyzer()
                    .lookup_candidates_by_identifier(identifier)
            })
            .reduce(BTreeSet::new, |mut acc, candidates| {
                acc.extend(candidates);
                acc
            })
    }

    fn search_definitions_persisted(&self, pattern: &str) -> BTreeSet<CodeUnit> {
        // Fan out to each delegate's `search_definitions_persisted` so the
        // FTS5 path is consulted per-language. The default impl on
        // `IAnalyzer` would otherwise re-dispatch through our own
        // `search_definitions` override, which only hits in-memory state.
        self.delegates
            .values()
            .collect::<Vec<_>>()
            .into_par_iter()
            .map(|delegate| delegate.analyzer().search_definitions_persisted(pattern))
            .reduce(BTreeSet::new, |mut acc, definitions| {
                acc.extend(definitions);
                acc
            })
    }

    fn signatures(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.delegate_for_code_unit(code_unit)
            .map(|delegate| delegate.analyzer().signatures(code_unit))
            .unwrap_or_default()
    }

    fn signature_metadata(&self, code_unit: &CodeUnit) -> Vec<SignatureMetadata> {
        self.delegate_for_code_unit(code_unit)
            .map(|delegate| delegate.analyzer().signature_metadata(code_unit))
            .unwrap_or_default()
    }
}

impl IAnalyzer for MultiAnalyzer {
    #[cfg(any(test, feature = "test-support"))]
    fn test_hooks(&self) -> &dyn crate::analyzer::AnalyzerTestHooks {
        self
    }

    fn invalidate_cached_file_identities(&self) {
        self.delegates
            .values()
            .for_each(|delegate| delegate.analyzer().invalidate_cached_file_identities());
    }

    /// Every delegate shares one `Liveness`, and so one identity scan, for the
    /// workspace: the first delegate that has taken it answers for all of them.
    fn working_tree_identity(&self) -> Option<Arc<crate::gitblob::WorkingTreeIdentity>> {
        self.delegates
            .values()
            .find_map(|delegate| delegate.analyzer().working_tree_identity())
    }

    fn begin_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        let mut contexts = self
            .query_contexts
            .lock()
            .expect("multi-analyzer query context mutex poisoned");
        if !contexts.iter().any(|active| Arc::ptr_eq(active, context)) {
            contexts.push(Arc::clone(context));
        }
        drop(contexts);
        self.delegates
            .values()
            .for_each(|delegate| delegate.analyzer().begin_query(context));
    }

    fn end_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        self.delegates
            .values()
            .for_each(|delegate| delegate.analyzer().end_query(context));
        self.query_contexts
            .lock()
            .expect("multi-analyzer query context mutex poisoned")
            .retain(|active| !Arc::ptr_eq(active, context));
    }

    fn begin_streaming_file_read(&self, file: &ProjectFile) {
        if let Some(delegate) = self.delegate_for_file(file) {
            delegate.analyzer().begin_streaming_file_read(file);
        }
    }

    fn end_streaming_file_read(&self, file: &ProjectFile) {
        if let Some(delegate) = self.delegate_for_file(file) {
            delegate.analyzer().end_streaming_file_read(file);
        }
    }

    fn release_streaming_readers(&self) {
        self.delegates
            .values()
            .for_each(|delegate| delegate.analyzer().release_streaming_readers());
    }

    /// The first delegate's cell — the same delegate `project()` answers from,
    /// so the memoized listing describes exactly the workspace this analyzer
    /// reports. `begin_query` propagates to every delegate, so it is active
    /// whenever this analyzer's own scope is.
    fn workspace_file_index_cell(&self) -> Option<crate::analyzer::WorkspaceFileIndexCell> {
        self.delegates
            .values()
            .next()?
            .analyzer()
            .workspace_file_index_cell()
    }

    /// Recorded on this analyzer's own active contexts rather than forwarded to
    /// a delegate: `begin_query` shares one context object with every delegate,
    /// so one recording is enough, and a workspace with no delegate at all
    /// would otherwise have nowhere to report the failure.
    fn record_query_failure(&self, error: crate::analyzer::store::StoreError) {
        let contexts = self
            .query_contexts
            .lock()
            .expect("multi-analyzer query context mutex poisoned")
            .clone();
        for context in contexts {
            context.record_store_error(error.clone());
        }
    }

    fn warm_query_indexes(&self) {
        self.delegates
            .values()
            .collect::<Vec<_>>()
            .into_par_iter()
            .for_each(|delegate| delegate.analyzer().warm_query_indexes());
    }

    fn query_indexes_warm(&self) -> bool {
        self.delegates
            .values()
            .all(|delegate| delegate.analyzer().query_indexes_warm())
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        let mut delegates = self.delegates.clone();
        let active_languages = self
            .build_context
            .as_ref()
            .map(|context| context.project_languages());
        let missing_languages = self
            .build_context
            .as_ref()
            .map(|context| context.changed_languages(changed_files))
            .unwrap_or_default()
            .into_iter()
            .filter(|language| !delegates.contains_key(language))
            .collect::<BTreeSet<_>>();
        for language in missing_languages.iter().copied() {
            let delegate = self
                .build_context
                .as_ref()
                .expect("missing languages require a workspace build context")
                .build_delegate(language)
                .unwrap_or_else(|error| {
                    panic!("failed to initialize {language:?} analyzer during update: {error}")
                });
            delegates.insert(language, delegate);
        }

        let updated: Vec<(Language, AnalyzerDelegate, bool)> = delegates
            .iter()
            .collect::<Vec<_>>()
            .into_par_iter()
            .map(|(language, delegate)| {
                if missing_languages.contains(language) {
                    // Construction indexed the complete current language
                    // file set, including this delta. Applying it again is
                    // redundant and can schedule avoidable store GC work.
                    return (*language, delegate.clone(), false);
                }
                let relevant: BTreeSet<ProjectFile> = changed_files
                    .iter()
                    .filter(|file| delegate.should_receive_changed_file(*language, file))
                    .cloned()
                    .collect();
                if relevant.is_empty() {
                    (*language, delegate.clone(), false)
                } else {
                    (*language, delegate.update(&relevant), true)
                }
            })
            .collect();
        let any_delegate_changed =
            !missing_languages.is_empty() || updated.iter().any(|(_, _, changed)| *changed);
        let delegates = updated
            .into_iter()
            .map(|(language, delegate, _)| (language, delegate))
            .filter(|(language, _)| {
                active_languages
                    .as_ref()
                    .is_none_or(|active| active.contains(language))
            })
            .collect::<BTreeMap<_, _>>();
        let retired_delegate = delegates.len() < self.delegates.len() + missing_languages.len();
        if any_delegate_changed || retired_delegate {
            return Self::new_with_build_context(
                delegates,
                self.derived_layer_budget_bytes,
                self.build_context.clone(),
            );
        }
        // No delegate saw a relevant change, so every one of them was cloned
        // and kept everything it had built.  Keeping the workspace-level
        // derived-layer caches too matches that, and matches what a delegate's
        // own no-op update does.  The caches are generation-guarded, so nothing
        // stale can be served through them either way.
        Self {
            delegates,
            build_context: self.build_context.clone(),
            snapshot_caches: Arc::clone(&self.snapshot_caches),
            derived_layer_budget_bytes: self.derived_layer_budget_bytes,
            query_contexts: Mutex::new(Vec::new()),
        }
    }

    fn update_all(&self) -> Self {
        let mut delegates = self.delegates.clone();
        if let Some(context) = &self.build_context {
            let active_languages = context.project_languages();
            delegates.retain(|language, _| active_languages.contains(language));
            for language in active_languages {
                if let std::collections::btree_map::Entry::Vacant(entry) = delegates.entry(language)
                {
                    let delegate = context.build_delegate(language).unwrap_or_else(|error| {
                        panic!(
                            "failed to initialize {language:?} analyzer during full update: {error}"
                        )
                    });
                    entry.insert(delegate);
                }
            }
        }
        let delegates = delegates
            .iter()
            .collect::<Vec<_>>()
            .into_par_iter()
            .map(|(language, delegate)| (*language, delegate.update_all()))
            .collect();
        Self::new_with_build_context(
            delegates,
            self.derived_layer_budget_bytes,
            self.build_context.clone(),
        )
    }

    /// A view over the delegates' own indexes, never a merged copy.
    ///
    /// Each shard is built lazily by its delegate on first use, so the cost of
    /// a definition query is exactly the per-language index the delegate would
    /// have built anyway, and it survives every update and overlay snapshot
    /// that retains the delegate.  A delegate whose store read fails degrades
    /// to its own recorded-error fallback shard, which keeps the failure
    /// visible and confined instead of emptying the whole workspace view.
    fn global_usage_definition_index(&self) -> DefinitionIndexHandle<'_> {
        DefinitionIndexHandle::Merged(
            self.delegates
                .values()
                .flat_map(|delegate| {
                    delegate
                        .analyzer()
                        .global_usage_definition_index()
                        .into_shards()
                })
                .collect(),
        )
    }

    fn declaration_syntax_kind(&self, code_unit: &CodeUnit) -> Option<&'static str> {
        self.delegate_for_code_unit(code_unit)
            .and_then(|delegate| delegate.analyzer().declaration_syntax_kind(code_unit))
    }

    fn parse_errors(&self, file: &ProjectFile) -> Option<Vec<crate::analyzer::ParseError>> {
        self.delegate_for_file(file)
            .and_then(|delegate| delegate.analyzer().parse_errors(file))
    }

    fn semantic_diagnostics(
        &self,
        file: &ProjectFile,
        source: &str,
    ) -> crate::analyzer::SemanticDiagnosticReport {
        let query_scope = AnalyzerQueryScope::new(self);
        let token = query_scope.token();
        // JVM diagnostics must see the same
        // wider JVM source realm its import and hierarchy resolution do:
        // otherwise a type declared in a Java or Scala sibling file would be
        // misreported as unrecognized. Only `MultiAnalyzer` can construct
        // that realm view (see `kotlin_realm`), so this is the one place the
        // widening happens rather than inside `KotlinAnalyzer` itself.
        if language_for_file(file) == Language::Kotlin
            && self.delegates.contains_key(&Language::Kotlin)
        {
            // Every Kotlin file routes here, not only one with Java or Scala
            // peers: the realm widens *resolution*, but the active dependency
            // model that decides whether a miss is provable is published on the
            // dispatcher either way. Falling through to the delegate for a
            // Kotlin-only workspace would read its empty overlay and suppress
            // every unknown name.
            //
            // `self`, not the Kotlin delegate, for the same reason -- plus the
            // enclosing-declaration lookup, which crosses languages. The shim
            // downcasts to the Kotlin analyzer itself.
            let realm = self.kotlin_realm().map(|(_, realm)| realm);
            return crate::analyzer::kotlin::diagnostics::collect_kotlin_semantic_diagnostics(
                self,
                token,
                file,
                source,
                realm.as_ref(),
            );
        }
        if language_for_file(file) == Language::Java && self.delegates.contains_key(&Language::Java)
        {
            return crate::analyzer::java::diagnostics::collect_java_semantic_diagnostics(
                self, token, file, source,
            );
        }
        // Scala's own ladder is delegate-resident, but the active dependency
        // model it must not claim absence past is published on the dispatcher.
        if language_for_file(file) == Language::Scala
            && self.delegates.contains_key(&Language::Scala)
        {
            return crate::analyzer::scala::diagnostics::collect_scala_semantic_diagnostics(
                self, file, source,
            );
        }
        // Go classifies references that leave the workspace against the
        // activated exact API packs (#1623), and the semantic-model overlay
        // and the retained Go module graph belong to the dispatching analyzer,
        // not to the delegate. Passing `self` is what lets a Go file's import
        // of an indexed module resolve instead of reporting nothing known.
        if language_for_file(file) == Language::Go && self.delegates.contains_key(&Language::Go) {
            return crate::analyzer::go::diagnostics::collect_go_semantic_diagnostics(
                self, token, file, source,
            );
        }
        // Python's environment proof lives on the analyzer a host activated
        // packs against, which is this composite one and not the delegate. A
        // request routed straight to the delegate would see no overlay and no
        // discovery evidence, and would report every external import as an
        // unknown boundary.
        if language_for_file(file) == Language::Python
            && self.delegates.contains_key(&Language::Python)
        {
            return crate::analyzer::python::diagnostics::collect_python_semantic_diagnostics(
                self, token, file, source,
            );
        }
        // PHP's proof ladder reads the semantic-model overlay and the retained
        // Composer discovery evidence, and only the dispatching analyzer holds
        // them. Delegating to the `PhpAnalyzer` would hand the collector a view
        // with no indexed dependencies, so every vendor symbol would look
        // unknown even with an active pack.
        if language_for_file(file) == Language::Php && self.delegates.contains_key(&Language::Php) {
            return crate::analyzer::php::diagnostics::collect_php_semantic_diagnostics(
                self, file, source,
            );
        }
        // JS/TS diagnostics judge external imports against the activated npm
        // declaration surface and the retained npm discovery evidence (#1620).
        // Both hang off the analyzer that owns the workspace snapshot, which is
        // this one: a delegate passed on its own carries no snapshot caches and
        // would report every npm import as an unknown boundary.
        let language = language_for_file(file);
        if language == Language::JavaScript && self.delegates.contains_key(&Language::JavaScript) {
            return crate::analyzer::js_ts::diagnostics::collect_javascript_semantic_diagnostics(
                self, file, source,
            );
        }
        if language == Language::TypeScript && self.delegates.contains_key(&Language::TypeScript) {
            return crate::analyzer::js_ts::diagnostics::collect_typescript_semantic_diagnostics(
                self, file, source,
            );
        }
        // Rust classifies paths that leave the workspace against the activated
        // exact Cargo API packs (#1625), and the semantic-model overlay and the
        // retained Cargo dependency evidence belong to the dispatching
        // analyzer, not to the delegate. Passing `self` is what lets a path
        // into an indexed dependency resolve instead of reporting nothing
        // known.
        if language_for_file(file) == Language::Rust && self.delegates.contains_key(&Language::Rust)
        {
            return crate::analyzer::rust::diagnostics::collect_rust_semantic_diagnostics(
                self, file, source,
            );
        }
        // Ruby classifies a constant that leaves the visible require closure
        // against the activated exact gem API packs (#1624), and both the
        // semantic-model overlay and the retained Gemfile.lock discovery
        // evidence belong to the dispatching analyzer, not to the delegate.
        // Passing `self` is what lets a gem's indexed constant resolve instead
        // of reporting an unknown boundary.
        if language_for_file(file) == Language::Ruby && self.delegates.contains_key(&Language::Ruby)
        {
            return crate::analyzer::ruby::diagnostics::collect_ruby_semantic_diagnostics(
                self, file, source,
            );
        }
        // C# reads the retained dependency-discovery evidence that refines an
        // unindexed assembly boundary, and a host publishes that on the
        // analyzer it ran discovery against, which is this composite one.
        // Delegating to the `CSharpAnalyzer` would hand the collector no
        // evidence at all, so every miss past a `using` would report the
        // weakest boundary even where the build declares the assembly.
        if language_for_file(file) == Language::CSharp
            && self.delegates.contains_key(&Language::CSharp)
        {
            return crate::analyzer::csharp::diagnostics::collect_csharp_semantic_diagnostics(
                self, token, file, source,
            );
        }
        if language_for_file(file) == Language::Cpp
            && self.delegates.contains_key(&Language::Cpp)
            && let Some(cpp) =
                crate::analyzer::resolve_analyzer::<crate::analyzer::CppAnalyzer>(self)
        {
            let report =
                brokk_bifrost_cpp::diagnostics::collect_cpp_semantic_diagnostics(cpp, file, source);
            return crate::analyzer::semantic_model::degrade_pack_gap_absences(self, report);
        }
        self.delegate_for_file(file)
            .map(|delegate| delegate.analyzer().semantic_diagnostics(file, source))
            .unwrap_or_default()
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        self.delegates
            .values()
            .find_map(|delegate| delegate.analyzer().extract_call_receiver(reference))
    }

    fn import_statements(&self, file: &ProjectFile) -> Vec<String> {
        self.delegate_for_file(file)
            .map(|delegate| delegate.analyzer().import_statements(file))
            .unwrap_or_default()
    }

    fn is_access_expression(&self, file: &ProjectFile, start_byte: usize, end_byte: usize) -> bool {
        self.delegate_for_file(file)
            .map(|delegate| {
                delegate
                    .analyzer()
                    .is_access_expression(file, start_byte, end_byte)
            })
            .unwrap_or(true)
    }

    fn find_nearest_declaration(
        &self,
        file: &ProjectFile,
        start_byte: usize,
        end_byte: usize,
        ident: &str,
    ) -> Option<DeclarationInfo> {
        self.delegate_for_file(file).and_then(|delegate| {
            delegate
                .analyzer()
                .find_nearest_declaration(file, start_byte, end_byte, ident)
        })
    }

    fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)> {
        self.delegate_for_file(file)
            .map(|delegate| delegate.analyzer().compute_cognitive_complexities(file))
            .unwrap_or_default()
    }

    fn comment_density(&self, code_unit: &CodeUnit) -> Option<CommentDensityStats> {
        self.delegate_for_code_unit(code_unit)
            .and_then(|delegate| delegate.analyzer().comment_density(code_unit))
    }

    fn comment_density_by_top_level(&self, file: &ProjectFile) -> Vec<CommentDensityStats> {
        self.delegate_for_file(file)
            .map(|delegate| delegate.analyzer().comment_density_by_top_level(file))
            .unwrap_or_default()
    }

    fn find_exception_handling_smells(
        &self,
        file: &ProjectFile,
        weights: ExceptionSmellWeights,
    ) -> ExceptionHandlingAnalysis {
        let Some(delegate) = self.delegate_for_file(file) else {
            return ExceptionHandlingAnalysis::Unsupported {
                reason: format!(
                    "no analyzer delegate is available for {}",
                    file.rel_path().display()
                ),
            };
        };
        delegate
            .analyzer()
            .find_exception_handling_smells(file, weights)
    }

    fn find_test_assertion_smells(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
    ) -> Vec<TestAssertionSmell> {
        self.delegate_for_file(file)
            .map(|delegate| {
                delegate
                    .analyzer()
                    .find_test_assertion_smells(file, weights)
            })
            .unwrap_or_default()
    }

    fn find_test_assertion_smells_limited(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
        max_candidates: usize,
    ) -> TestAssertionAnalysis {
        self.delegate_for_file(file)
            .map(|delegate| {
                delegate.analyzer().find_test_assertion_smells_limited(
                    file,
                    weights,
                    max_candidates,
                )
            })
            .unwrap_or(TestAssertionAnalysis {
                findings: Vec::new(),
                inspected_candidates: None,
                truncated: false,
            })
    }

    fn find_structural_clone_smells(
        &self,
        file: &ProjectFile,
        weights: CloneSmellWeights,
    ) -> Vec<CloneSmell> {
        self.delegate_for_file(file)
            .map(|delegate| {
                delegate
                    .analyzer()
                    .find_structural_clone_smells(file, weights)
            })
            .unwrap_or_default()
    }

    fn find_structural_clone_smells_for_files(
        &self,
        files: &[ProjectFile],
        weights: CloneSmellWeights,
    ) -> Vec<CloneSmell> {
        let mut grouped: BTreeMap<Language, Vec<ProjectFile>> = BTreeMap::new();
        for file in files {
            grouped
                .entry(self.dispatch_language(file))
                .or_default()
                .push(file.clone());
        }

        let mut findings = Vec::new();
        for (language, group) in grouped {
            if let Some(delegate) = self.delegates.get(&language) {
                findings.extend(
                    delegate
                        .analyzer()
                        .find_structural_clone_smells_for_files(&group, weights),
                );
            }
        }
        findings
    }

    fn search_symbol_candidates(
        &self,
        patterns: &SearchSymbolPatternBatch,
        cancellation: Option<&crate::CancellationToken>,
    ) -> SearchSymbolCandidates {
        self.delegates
            .values()
            .collect::<Vec<_>>()
            .into_par_iter()
            .map(|delegate| {
                delegate
                    .analyzer()
                    .search_symbol_candidates(patterns, cancellation)
            })
            .reduce(
                || SearchSymbolCandidates::complete(Vec::new(), 0),
                SearchSymbolCandidates::merge,
            )
    }

    fn partial_declaration_parts(&self, code_unit: &CodeUnit) -> Option<Vec<CodeUnit>> {
        self.delegate_for_code_unit(code_unit)?
            .analyzer()
            .partial_declaration_parts(code_unit)
    }

    fn abstract_member_implementations(&self, code_unit: &CodeUnit) -> Option<Vec<CodeUnit>> {
        self.delegate_for_code_unit(code_unit)?
            .analyzer()
            .abstract_member_implementations(code_unit)
    }

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        self.delegates
            .values()
            .any(|delegate| delegate.import_analysis_provider().is_some())
            .then_some(self as &dyn ImportAnalysisProvider)
    }

    fn import_analysis_provider_for_file(
        &self,
        file: &ProjectFile,
    ) -> Option<&dyn ImportAnalysisProvider> {
        self.delegate_for_file(file)
            .and_then(AnalyzerDelegate::import_analysis_provider)
    }

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
        self.delegates
            .values()
            .any(|delegate| delegate.type_hierarchy_provider().is_some())
            .then_some(self as &dyn TypeHierarchyProvider)
    }

    fn type_alias_provider(&self) -> Option<&dyn TypeAliasProvider> {
        self.delegates
            .values()
            .any(|delegate| delegate.type_alias_provider().is_some())
            .then_some(self as &dyn TypeAliasProvider)
    }

    fn member_family_provider(&self) -> Option<&dyn crate::analyzer::usages::MemberFamilyProvider> {
        self.delegates
            .values()
            .any(|delegate| delegate.analyzer().member_family_provider().is_some())
            .then_some(self as &dyn crate::analyzer::usages::MemberFamilyProvider)
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        self.delegates
            .values()
            .any(|delegate| delegate.test_detection_provider().is_some())
            .then_some(self as &dyn TestDetectionProvider)
    }

    fn structural_search_providers(
        &self,
    ) -> Vec<&dyn crate::analyzer::structural::StructuralSearchProvider> {
        self.delegates
            .values()
            .flat_map(|delegate| delegate.analyzer().structural_search_providers())
            .collect()
    }

    fn snapshot_caches(&self) -> Option<&crate::analyzer::AnalyzerSnapshotCaches> {
        Some(&self.snapshot_caches)
    }

    fn snapshot_source_generations(&self) -> Box<[u64]> {
        self.delegates
            .values()
            .map(|delegate| delegate.analyzer().project().analysis_generation())
            .collect()
    }

    fn snapshot_generations_match(&self, expected: &[u64]) -> bool {
        expected.len() == self.delegates.len()
            && expected.iter().copied().eq(self
                .delegates
                .values()
                .map(|delegate| delegate.analyzer().project().analysis_generation()))
    }

    fn contains_tests(&self, file: &ProjectFile) -> bool {
        self.delegate_for_file(file)
            .map(|delegate| delegate.analyzer().contains_tests(file))
            .unwrap_or(false)
    }

    fn in_test_region(&self, code_unit: &CodeUnit) -> bool {
        self.delegate_for_file(code_unit.source())
            .is_some_and(|delegate| delegate.analyzer().in_test_region(code_unit))
    }

    fn file_is_test_only(&self, file: &ProjectFile) -> bool {
        self.delegate_for_file(file)
            .is_some_and(|delegate| delegate.analyzer().file_is_test_only(file))
    }

    fn get_test_modules(&self, files: &[ProjectFile]) -> Vec<String> {
        let mut grouped: BTreeMap<Language, Vec<ProjectFile>> = BTreeMap::new();
        for file in files {
            grouped
                .entry(self.dispatch_language(file))
                .or_default()
                .push(file.clone());
        }

        let mut modules = Vec::new();
        for (language, group) in grouped {
            if let Some(delegate) = self.delegates.get(&language) {
                modules.extend(delegate.analyzer().get_test_modules(&group));
            } else {
                modules.extend(IAnalyzer::get_test_modules(self, &group));
            }
        }
        modules.sort();
        modules.dedup();
        modules
    }

    fn test_files_to_code_units(&self, files: &[ProjectFile]) -> BTreeSet<CodeUnit> {
        let mut grouped: BTreeMap<Language, Vec<ProjectFile>> = BTreeMap::new();
        for file in files {
            grouped
                .entry(self.dispatch_language(file))
                .or_default()
                .push(file.clone());
        }

        let mut result = BTreeSet::new();
        for (language, group) in grouped {
            if let Some(delegate) = self.delegates.get(&language) {
                result.extend(delegate.analyzer().test_files_to_code_units(&group));
            } else {
                result.extend(IAnalyzer::test_files_to_code_units(self, &group));
            }
        }
        result
    }
}

#[cfg(any(test, feature = "test-support"))]
impl crate::analyzer::AnalyzerTestHooks for MultiAnalyzer {
    fn reset_global_usage_definition_index_build_count_for_test(&self) {
        for delegate in self.delegates.values() {
            delegate
                .analyzer()
                .test_hooks()
                .reset_global_usage_definition_index_build_count_for_test();
        }
    }

    fn global_usage_definition_index_build_count_for_test(&self) -> usize {
        self.delegates
            .values()
            .map(|delegate| {
                delegate
                    .analyzer()
                    .test_hooks()
                    .global_usage_definition_index_build_count_for_test()
            })
            .sum::<usize>()
    }

    fn reset_definition_candidates_query_count_for_test(&self) {
        for delegate in self.delegates.values() {
            delegate
                .analyzer()
                .test_hooks()
                .reset_definition_candidates_query_count_for_test();
        }
    }

    fn definition_candidates_query_count_for_test(&self) -> usize {
        self.delegates
            .values()
            .map(|delegate| {
                delegate
                    .analyzer()
                    .test_hooks()
                    .definition_candidates_query_count_for_test()
            })
            .sum()
    }

    fn reset_full_declaration_scan_count_for_test(&self) {
        for delegate in self.delegates.values() {
            delegate
                .analyzer()
                .test_hooks()
                .reset_full_declaration_scan_count_for_test();
        }
    }

    fn full_declaration_scan_count_for_test(&self) -> usize {
        self.delegates
            .values()
            .map(|delegate| {
                delegate
                    .analyzer()
                    .test_hooks()
                    .full_declaration_scan_count_for_test()
            })
            .sum()
    }

    fn reset_candidate_hydration_count_for_test(&self) {
        for delegate in self.delegates.values() {
            delegate
                .analyzer()
                .test_hooks()
                .reset_candidate_hydration_count_for_test();
        }
    }

    fn candidate_hydration_count_for_test(&self) -> usize {
        self.delegates
            .values()
            .map(|delegate| {
                delegate
                    .analyzer()
                    .test_hooks()
                    .candidate_hydration_count_for_test()
            })
            .sum()
    }

    fn full_candidate_hydration_count_for_test(&self) -> usize {
        self.delegates
            .values()
            .map(|delegate| {
                delegate
                    .analyzer()
                    .test_hooks()
                    .full_candidate_hydration_count_for_test()
            })
            .sum()
    }

    fn bulk_candidate_hydration_count_for_test(&self) -> usize {
        self.delegates
            .values()
            .map(|delegate| {
                delegate
                    .analyzer()
                    .test_hooks()
                    .bulk_candidate_hydration_count_for_test()
            })
            .sum()
    }

    fn reset_workspace_path_scan_count_for_test(&self) {
        for delegate in self.delegates.values() {
            delegate
                .analyzer()
                .test_hooks()
                .reset_workspace_path_scan_count_for_test();
        }
    }

    fn workspace_path_scan_count_for_test(&self) -> usize {
        self.delegates
            .values()
            .map(|delegate| {
                delegate
                    .analyzer()
                    .test_hooks()
                    .workspace_path_scan_count_for_test()
            })
            .sum()
    }

    fn reset_scala_project_types_build_count_for_test(&self) {
        for delegate in self.delegates.values() {
            delegate
                .analyzer()
                .test_hooks()
                .reset_scala_project_types_build_count_for_test();
        }
    }

    fn scala_project_types_build_count_for_test(&self) -> usize {
        self.delegates
            .values()
            .map(|delegate| {
                delegate
                    .analyzer()
                    .test_hooks()
                    .scala_project_types_build_count_for_test()
            })
            .sum()
    }

    fn reset_scala_query_scan_counts_for_test(&self) {
        for delegate in self.delegates.values() {
            delegate
                .analyzer()
                .test_hooks()
                .reset_scala_query_scan_counts_for_test();
        }
    }

    fn scala_query_parse_count_for_test(&self) -> usize {
        self.delegates
            .values()
            .map(|delegate| {
                delegate
                    .analyzer()
                    .test_hooks()
                    .scala_query_parse_count_for_test()
            })
            .sum()
    }

    fn scala_query_walk_count_for_test(&self) -> usize {
        self.delegates
            .values()
            .map(|delegate| {
                delegate
                    .analyzer()
                    .test_hooks()
                    .scala_query_walk_count_for_test()
            })
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::FileSetProject;

    fn project_file(rel_path: &str) -> ProjectFile {
        let root = if cfg!(windows) {
            std::path::PathBuf::from("C:\\tmp")
        } else {
            std::path::PathBuf::from("/tmp")
        };
        ProjectFile::new(root, rel_path)
    }

    #[test]
    fn js_ts_config_files_are_routed_as_delegate_relevant_changes() {
        assert!(is_js_ts_config_file(&project_file("tsconfig.json")));
        assert!(is_js_ts_config_file(&project_file(
            "packages/app/jsconfig.json"
        )));
        assert!(!is_js_ts_config_file(&project_file("package.json")));
        assert!(!is_js_ts_config_file(&project_file("src/app.ts")));
    }

    #[test]
    fn default_multi_analyzer_preserves_the_default_derived_layer_budget() {
        let analyzer = MultiAnalyzer::default();
        assert_eq!(
            analyzer.derived_layer_budget_bytes,
            crate::analyzer::structural::execution::derived::SnapshotDerivedLayerCache::DEFAULT_MAX_RETAINED_BYTES
        );
        assert_eq!(
            analyzer
                .snapshot_caches
                .derived_layers()
                .max_retained_bytes(),
            analyzer.derived_layer_budget_bytes
        );
    }

    #[test]
    fn java_build_inputs_are_routed_as_delegate_relevant_changes() {
        let temp = tempfile::tempdir().unwrap();
        let project = FileSetProject::new(
            temp.path().canonicalize().unwrap(),
            std::iter::empty::<std::path::PathBuf>(),
        );
        let delegate = AnalyzerDelegate::Java(JavaAnalyzer::from_project(project));
        assert!(delegate.needs_config_update_for(&project_file("pom.xml")));
        assert!(
            delegate
                .needs_config_update_for(&project_file("gradle/dependency-locks/runtime.lockfile"))
        );
        assert!(
            delegate.needs_config_update_for(&project_file("buildSrc/src/main/java/Plugin.java"))
        );
        assert!(!delegate.needs_config_update_for(&project_file("src/App.java")));
    }

    #[test]
    fn csharp_dependency_inputs_are_routed_as_delegate_relevant_changes() {
        let temp = tempfile::tempdir().unwrap();
        let project = FileSetProject::new(
            temp.path().canonicalize().unwrap(),
            std::iter::empty::<std::path::PathBuf>(),
        );
        let delegate = AnalyzerDelegate::CSharp(CSharpAnalyzer::from_project(project));
        assert!(delegate.needs_config_update_for(&project_file("obj/project.assets.json")));
        assert!(delegate.needs_config_update_for(&project_file("App.csproj")));
        assert!(delegate.needs_config_update_for(&project_file("bin/App.dll")));
        assert!(!delegate.needs_config_update_for(&project_file("src/App.cs")));
    }

    /// A two-language workspace on disk, as a `MultiAnalyzer` over real
    /// per-language delegates.  The merged definition view is only meaningful
    /// over delegates that actually hold declarations.
    fn two_language_analyzer() -> (tempfile::TempDir, MultiAnalyzer) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/App.java"),
            "package app;\npublic class App {}\n",
        )
        .unwrap();
        std::fs::write(root.join("src/lib.rs"), "pub struct Widget;\n").unwrap();
        std::fs::write(root.join("README.md"), "docs\n").unwrap();
        let project = FileSetProject::new(
            root,
            [
                std::path::PathBuf::from("src/App.java"),
                std::path::PathBuf::from("src/lib.rs"),
                std::path::PathBuf::from("README.md"),
            ],
        );
        let delegates = BTreeMap::from([
            (
                Language::Java,
                AnalyzerDelegate::Java(JavaAnalyzer::from_project(project.clone())),
            ),
            (
                Language::Rust,
                AnalyzerDelegate::Rust(RustAnalyzer::from_project(project)),
            ),
        ]);
        (temp, MultiAnalyzer::new(delegates))
    }

    #[test]
    fn definition_query_builds_each_delegate_index_once_and_scans_nothing() {
        let (_temp, analyzer) = two_language_analyzer();
        analyzer
            .test_hooks()
            .reset_global_usage_definition_index_build_count_for_test();
        analyzer
            .test_hooks()
            .reset_full_declaration_scan_count_for_test();

        // Two queries, so a view that rebuilt per call would show it.
        assert_eq!(
            analyzer
                .global_usage_definition_index()
                .fqn("app.App")
                .len(),
            1
        );
        assert_eq!(
            analyzer.global_usage_definition_index().fqn("Widget").len(),
            1
        );

        for (language, delegate) in analyzer.delegates() {
            assert_eq!(
                delegate
                    .analyzer()
                    .test_hooks()
                    .global_usage_definition_index_build_count_for_test(),
                1,
                "delegate {language:?} built its definition index more than once"
            );
        }
        // The merged view answers out of the delegates' own indexes; it must
        // never fall back to a full declaration scan per delegate.
        assert_eq!(
            analyzer.test_hooks().full_declaration_scan_count_for_test(),
            0
        );
    }

    #[test]
    fn update_with_only_irrelevant_files_retains_indexes_and_snapshot_caches() {
        let (_temp, analyzer) = two_language_analyzer();
        analyzer
            .test_hooks()
            .reset_global_usage_definition_index_build_count_for_test();
        analyzer
            .test_hooks()
            .reset_full_declaration_scan_count_for_test();
        assert_eq!(
            analyzer
                .global_usage_definition_index()
                .fqn("app.App")
                .len(),
            1
        );

        let readme = ProjectFile::new(analyzer.project().root().to_path_buf(), "README.md");
        let updated = analyzer.update(&BTreeSet::from([readme]));

        assert_eq!(
            updated.global_usage_definition_index().fqn("app.App").len(),
            1
        );
        for (language, delegate) in updated.delegates() {
            assert_eq!(
                delegate
                    .analyzer()
                    .test_hooks()
                    .global_usage_definition_index_build_count_for_test(),
                1,
                "delegate {language:?} rebuilt its definition index after an irrelevant change"
            );
        }
        assert_eq!(
            updated.test_hooks().full_declaration_scan_count_for_test(),
            0
        );
        assert!(
            Arc::ptr_eq(&analyzer.snapshot_caches, &updated.snapshot_caches),
            "an update touching no analyzed file must keep the workspace derived-layer caches"
        );
    }

    #[test]
    fn update_touching_an_analyzed_file_allocates_fresh_snapshot_caches() {
        let (_temp, analyzer) = two_language_analyzer();
        let source = ProjectFile::new(analyzer.project().root().to_path_buf(), "src/App.java");
        let updated = analyzer.update(&BTreeSet::from([source]));

        assert!(!Arc::ptr_eq(
            &analyzer.snapshot_caches,
            &updated.snapshot_caches
        ));
    }

    #[test]
    fn overlay_snapshot_recomputes_the_merged_view_from_retained_delegates() {
        let (_temp, analyzer) = two_language_analyzer();
        let project: Arc<dyn Project> = Arc::new(FileSetProject::new(
            analyzer.project().root().to_path_buf(),
            [std::path::PathBuf::from("src/App.java")],
        ));
        let snapshot = analyzer.clone_with_project(project);

        assert!(!Arc::ptr_eq(
            &analyzer.snapshot_caches,
            &snapshot.snapshot_caches
        ));
        assert_eq!(
            snapshot
                .global_usage_definition_index()
                .fqn("app.App")
                .len(),
            1
        );
    }
}
