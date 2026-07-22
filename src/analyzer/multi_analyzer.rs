use crate::analyzer::common::language_for_file;
use crate::analyzer::{
    CSharpAnalyzer, CloneSmell, CloneSmellWeights, CodeUnit, CommentDensityStats, CppAnalyzer,
    DeclarationInfo, ExceptionHandlingSmell, ExceptionSmellWeights, GlobalUsageDefinitionIndex,
    GoAnalyzer, IAnalyzer, ImportAnalysisProvider, ImportInfo, JavaAnalyzer, JavascriptAnalyzer,
    Language, PhpAnalyzer, Project, ProjectFile, PythonAnalyzer, Range, RubyAnalyzer, RustAnalyzer,
    ScalaAnalyzer, SearchSymbolCandidate, SemanticDiagnostic, SignatureMetadata,
    SummaryFileProjection, TestDetectionProvider, TypeAliasProvider, TypeHierarchyProvider,
    TypescriptAnalyzer,
};
use crate::hash::HashSet;
use rayon::prelude::*;
use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicUsize, Ordering},
};

/// Resolve a concrete analyzer of type `T` out of a `&dyn IAnalyzer`, whether it is
/// that analyzer directly or a [`MultiAnalyzer`] holding it as a per-language delegate.
pub(crate) fn resolve_analyzer<T: Any>(analyzer: &dyn IAnalyzer) -> Option<&T> {
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
        }
    }

    pub(crate) fn language(&self) -> Language {
        match self {
            Self::Java(_) => Language::Java,
            Self::CSharp(_) => Language::CSharp,
            Self::Cpp(_) => Language::Cpp,
            Self::Go(_) => Language::Go,
            Self::JavaScript(_) => Language::JavaScript,
            Self::Php(_) => Language::Php,
            Self::Python(_) => Language::Python,
            Self::TypeScript(_) => Language::TypeScript,
            Self::Rust(_) => Language::Rust,
            Self::Scala(_) => Language::Scala,
            Self::Ruby(_) => Language::Ruby,
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
        }
    }

    fn should_receive_changed_file(&self, language: Language, file: &ProjectFile) -> bool {
        language_for_file(file) == language
            || self.analyzer().is_analyzed(file)
            || self.needs_config_update_for(file)
    }

    fn needs_config_update_for(&self, file: &ProjectFile) -> bool {
        match self {
            Self::Java(_) => crate::analyzer::java::is_java_dependency_input(file),
            Self::CSharp(_) => crate::analyzer::csharp::is_csharp_dependency_input(file),
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
        }
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
    snapshot_caches: Arc<crate::analyzer::AnalyzerSnapshotCaches>,
    derived_layer_budget_bytes: u64,
    global_usage_definition_index: Arc<OnceLock<GlobalUsageDefinitionIndex>>,
    global_usage_definition_index_build_count: Arc<AtomicUsize>,
    global_usage_definition_index_build_lock: Arc<Mutex<()>>,
    query_contexts: Mutex<Vec<Arc<crate::analyzer::AnalyzerQueryContext>>>,
    global_usage_definition_fallback: GlobalUsageDefinitionIndex,
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
            snapshot_caches: Arc::clone(&self.snapshot_caches),
            derived_layer_budget_bytes: self.derived_layer_budget_bytes,
            global_usage_definition_index: Arc::clone(&self.global_usage_definition_index),
            global_usage_definition_index_build_count: Arc::clone(
                &self.global_usage_definition_index_build_count,
            ),
            global_usage_definition_index_build_lock: Arc::clone(
                &self.global_usage_definition_index_build_lock,
            ),
            query_contexts: Mutex::new(Vec::new()),
            global_usage_definition_fallback: GlobalUsageDefinitionIndex::default(),
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
        Self {
            delegates,
            snapshot_caches: Arc::new(crate::analyzer::AnalyzerSnapshotCaches::new(
                derived_layer_budget_bytes,
            )),
            derived_layer_budget_bytes,
            global_usage_definition_index: Arc::new(OnceLock::new()),
            global_usage_definition_index_build_count: Arc::new(AtomicUsize::new(0)),
            global_usage_definition_index_build_lock: Arc::new(Mutex::new(())),
            query_contexts: Mutex::new(Vec::new()),
            global_usage_definition_fallback: GlobalUsageDefinitionIndex::default(),
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

    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        Self {
            delegates: self
                .delegates
                .iter()
                .map(|(language, delegate)| {
                    (*language, delegate.clone_with_project(Arc::clone(&project)))
                })
                .collect(),
            snapshot_caches: Arc::new(crate::analyzer::AnalyzerSnapshotCaches::new(
                self.derived_layer_budget_bytes,
            )),
            derived_layer_budget_bytes: self.derived_layer_budget_bytes,
            global_usage_definition_index: Arc::new(OnceLock::new()),
            global_usage_definition_index_build_count: Arc::new(AtomicUsize::new(0)),
            global_usage_definition_index_build_lock: Arc::new(Mutex::new(())),
            query_contexts: Mutex::new(Vec::new()),
            global_usage_definition_fallback: GlobalUsageDefinitionIndex::default(),
        }
    }

    fn query_has_store_error(&self) -> bool {
        self.query_contexts
            .lock()
            .expect("multi-analyzer query context mutex poisoned")
            .iter()
            .any(|context| context.store_error().is_some())
    }

    pub(crate) fn delegate_for_file(&self, file: &ProjectFile) -> Option<&AnalyzerDelegate> {
        self.delegates.get(&language_for_file(file))
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
}

impl ImportAnalysisProvider for MultiAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> HashSet<CodeUnit> {
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

    fn import_info_of(&self, file: &ProjectFile) -> Vec<ImportInfo> {
        self.delegate_for_file(file)
            .and_then(AnalyzerDelegate::import_analysis_provider)
            .map(|provider| provider.import_info_of(file))
            .unwrap_or_default()
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
}

impl TypeHierarchyProvider for MultiAnalyzer {
    fn supports_type_hierarchy(&self, code_unit: &CodeUnit) -> bool {
        self.delegate_for_code_unit(code_unit)
            .and_then(AnalyzerDelegate::type_hierarchy_provider)
            .is_some_and(|provider| provider.supports_type_hierarchy(code_unit))
    }

    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.delegate_for_code_unit(code_unit)
            .and_then(AnalyzerDelegate::type_hierarchy_provider)
            .map(|provider| provider.get_direct_ancestors(code_unit))
            .unwrap_or_default()
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        self.delegate_for_code_unit(code_unit)
            .and_then(AnalyzerDelegate::type_hierarchy_provider)
            .map(|provider| provider.get_direct_descendants(code_unit))
            .unwrap_or_default()
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

impl IAnalyzer for MultiAnalyzer {
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

    fn languages(&self) -> BTreeSet<Language> {
        self.delegates.keys().copied().collect()
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        let delegates = self
            .delegates
            .iter()
            .collect::<Vec<_>>()
            .into_par_iter()
            .map(|(language, delegate)| {
                let relevant: BTreeSet<ProjectFile> = changed_files
                    .iter()
                    .filter(|file| delegate.should_receive_changed_file(*language, file))
                    .cloned()
                    .collect();
                if relevant.is_empty() {
                    (*language, delegate.clone())
                } else {
                    (*language, delegate.update(&relevant))
                }
            })
            .collect();
        Self::new_with_derived_layer_budget(delegates, self.derived_layer_budget_bytes)
    }

    fn update_all(&self) -> Self {
        let delegates = self
            .delegates
            .iter()
            .collect::<Vec<_>>()
            .into_par_iter()
            .map(|(language, delegate)| (*language, delegate.update_all()))
            .collect();
        Self::new_with_derived_layer_budget(delegates, self.derived_layer_budget_bytes)
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

    fn definitions(&self, fq_name: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        let matches: Vec<_> = self
            .delegates
            .values()
            .flat_map(|delegate| delegate.analyzer().definitions(fq_name))
            .collect();
        Box::new(matches.into_iter())
    }

    fn global_usage_definition_index(&self) -> &GlobalUsageDefinitionIndex {
        if let Some(index) = self.global_usage_definition_index.get() {
            return index;
        }
        let _build_guard = self
            .global_usage_definition_index_build_lock
            .lock()
            .expect("merged definition index build mutex poisoned");
        if let Some(index) = self.global_usage_definition_index.get() {
            return index;
        }

        self.global_usage_definition_index_build_count
            .fetch_add(1, Ordering::Relaxed);
        let built = GlobalUsageDefinitionIndex::from_declarations(
            self.delegates
                .values()
                .flat_map(|delegate| delegate.analyzer().all_declarations()),
            str::to_string,
            |unit| unit.identifier().to_string(),
        );
        if self.query_has_store_error() {
            return &self.global_usage_definition_fallback;
        }

        let _ = self.global_usage_definition_index.set(built);
        self.global_usage_definition_index
            .get()
            .expect("successful merged definition index build initializes OnceLock")
    }

    fn reset_global_usage_definition_index_build_count_for_test(&self) {
        self.global_usage_definition_index_build_count
            .store(0, Ordering::Relaxed);
        for delegate in self.delegates.values() {
            delegate
                .analyzer()
                .reset_global_usage_definition_index_build_count_for_test();
        }
    }

    fn global_usage_definition_index_build_count_for_test(&self) -> usize {
        self.global_usage_definition_index_build_count
            .load(Ordering::Relaxed)
            + self
                .delegates
                .values()
                .map(|delegate| {
                    delegate
                        .analyzer()
                        .global_usage_definition_index_build_count_for_test()
                })
                .sum::<usize>()
    }

    fn reset_definition_candidates_query_count_for_test(&self) {
        for delegate in self.delegates.values() {
            delegate
                .analyzer()
                .reset_definition_candidates_query_count_for_test();
        }
    }

    fn definition_candidates_query_count_for_test(&self) -> usize {
        self.delegates
            .values()
            .map(|delegate| {
                delegate
                    .analyzer()
                    .definition_candidates_query_count_for_test()
            })
            .sum()
    }

    fn reset_full_declaration_scan_count_for_test(&self) {
        for delegate in self.delegates.values() {
            delegate
                .analyzer()
                .reset_full_declaration_scan_count_for_test();
        }
    }

    fn full_declaration_scan_count_for_test(&self) -> usize {
        self.delegates
            .values()
            .map(|delegate| delegate.analyzer().full_declaration_scan_count_for_test())
            .sum()
    }

    fn reset_candidate_hydration_count_for_test(&self) {
        for delegate in self.delegates.values() {
            delegate
                .analyzer()
                .reset_candidate_hydration_count_for_test();
        }
    }

    fn candidate_hydration_count_for_test(&self) -> usize {
        self.delegates
            .values()
            .map(|delegate| delegate.analyzer().candidate_hydration_count_for_test())
            .sum()
    }

    fn full_candidate_hydration_count_for_test(&self) -> usize {
        self.delegates
            .values()
            .map(|delegate| {
                delegate
                    .analyzer()
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
                    .bulk_candidate_hydration_count_for_test()
            })
            .sum()
    }

    fn reset_workspace_path_scan_count_for_test(&self) {
        for delegate in self.delegates.values() {
            delegate
                .analyzer()
                .reset_workspace_path_scan_count_for_test();
        }
    }

    fn workspace_path_scan_count_for_test(&self) -> usize {
        self.delegates
            .values()
            .map(|delegate| delegate.analyzer().workspace_path_scan_count_for_test())
            .sum()
    }

    fn reset_scala_project_types_build_count_for_test(&self) {
        for delegate in self.delegates.values() {
            delegate
                .analyzer()
                .reset_scala_project_types_build_count_for_test();
        }
    }

    fn scala_project_types_build_count_for_test(&self) -> usize {
        self.delegates
            .values()
            .map(|delegate| {
                delegate
                    .analyzer()
                    .scala_project_types_build_count_for_test()
            })
            .sum()
    }

    fn reset_scala_query_scan_counts_for_test(&self) {
        for delegate in self.delegates.values() {
            delegate.analyzer().reset_scala_query_scan_counts_for_test();
        }
    }

    fn scala_query_parse_count_for_test(&self) -> usize {
        self.delegates
            .values()
            .map(|delegate| delegate.analyzer().scala_query_parse_count_for_test())
            .sum()
    }

    fn scala_query_walk_count_for_test(&self) -> usize {
        self.delegates
            .values()
            .map(|delegate| delegate.analyzer().scala_query_walk_count_for_test())
            .sum()
    }

    fn direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        match self.delegate_for_code_unit(code_unit) {
            Some(delegate) => delegate.analyzer().direct_children(code_unit),
            None => Vec::new(),
        }
    }

    fn parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        self.delegate_for_code_unit(code_unit)
            .and_then(|delegate| delegate.analyzer().parent_of(code_unit))
    }

    fn parse_errors(&self, file: &ProjectFile) -> Option<Vec<crate::analyzer::ParseError>> {
        self.delegate_for_file(file)
            .and_then(|delegate| delegate.analyzer().parse_errors(file))
    }

    fn semantic_diagnostics(&self, file: &ProjectFile, source: &str) -> Vec<SemanticDiagnostic> {
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

    fn ranges(&self, code_unit: &CodeUnit) -> Vec<Range> {
        self.delegate_for_code_unit(code_unit)
            .map(|delegate| delegate.analyzer().ranges(code_unit))
            .unwrap_or_default()
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
    ) -> Vec<ExceptionHandlingSmell> {
        self.delegate_for_file(file)
            .map(|delegate| {
                delegate
                    .analyzer()
                    .find_exception_handling_smells(file, weights)
            })
            .unwrap_or_default()
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
                .entry(language_for_file(file))
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

    fn search_symbol_candidates(
        &self,
        pattern: &str,
        auto_quote: bool,
    ) -> Vec<SearchSymbolCandidate> {
        self.delegates
            .values()
            .collect::<Vec<_>>()
            .into_par_iter()
            .map(|delegate| {
                delegate
                    .analyzer()
                    .search_symbol_candidates(pattern, auto_quote)
            })
            .reduce(Vec::new, |mut acc, candidates| {
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

    fn get_test_modules(&self, files: &[ProjectFile]) -> Vec<String> {
        let mut grouped: BTreeMap<Language, Vec<ProjectFile>> = BTreeMap::new();
        for file in files {
            grouped
                .entry(language_for_file(file))
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
                .entry(language_for_file(file))
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

    #[test]
    fn project_clone_has_an_independent_lazy_definition_index() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let project: Arc<dyn Project> = Arc::new(FileSetProject::new(
            root,
            std::iter::empty::<std::path::PathBuf>(),
        ));
        let analyzer = MultiAnalyzer::new(BTreeMap::new());
        let snapshot = analyzer.clone_with_project(project);

        assert!(!Arc::ptr_eq(
            &analyzer.global_usage_definition_index,
            &snapshot.global_usage_definition_index
        ));
        assert!(!Arc::ptr_eq(
            &analyzer.global_usage_definition_index_build_count,
            &snapshot.global_usage_definition_index_build_count
        ));

        snapshot.global_usage_definition_index();
        assert_eq!(
            snapshot.global_usage_definition_index_build_count_for_test(),
            1
        );
        assert_eq!(
            analyzer.global_usage_definition_index_build_count_for_test(),
            0
        );
    }

    #[test]
    fn ordinary_clone_shares_successful_lazy_definition_index() {
        let analyzer = MultiAnalyzer::new(BTreeMap::new());
        let snapshot = analyzer.clone();

        assert!(Arc::ptr_eq(
            &analyzer.global_usage_definition_index,
            &snapshot.global_usage_definition_index
        ));
        assert!(Arc::ptr_eq(
            &analyzer.global_usage_definition_index_build_count,
            &snapshot.global_usage_definition_index_build_count
        ));

        snapshot.global_usage_definition_index();
        analyzer.global_usage_definition_index();
        assert_eq!(
            analyzer.global_usage_definition_index_build_count_for_test(),
            1
        );
    }

    #[test]
    fn concurrent_clones_build_successful_lazy_definition_index_once() {
        let analyzer = Arc::new(MultiAnalyzer::new(BTreeMap::new()));
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let analyzer = Arc::new(analyzer.as_ref().clone());
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    analyzer.global_usage_definition_index();
                })
            })
            .collect();

        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(
            analyzer.global_usage_definition_index_build_count_for_test(),
            1
        );
    }
}
