mod adapter;
mod cache;
mod clones;
mod comments;
mod declarations;
mod exceptions;
mod external;
mod hierarchy;
mod imports;
mod structural;
mod tests;

use crate::analyzer::clone_detection::{CloneCandidateProfile, detect_structural_clone_smells};
use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::{
    AnalyzerConfig, BuildProgress, BuildProgressEvent, CloneSmell, CloneSmellWeights, CodeUnit,
    CommentDensityStats, DeclarationInfo, DeclarationKind, ExceptionHandlingSmell,
    ExceptionSmellWeights, IAnalyzer, ImportAnalysisProvider, Language, Project, ProjectFile,
    SignatureMetadata, TestAssertionSmell, TestAssertionWeights, TestDetectionProvider,
    TreeSitterAnalyzer, TypeHierarchyProvider,
};
use crate::hash::{HashMap, HashSet};
use std::collections::BTreeSet;
use std::sync::Arc;

use adapter::JavaAdapter;
use cache::JavaMemoCaches;
use clones::{build_clone_candidate_data, refine_java_clone_similarity};
use comments::{build_java_roll_up_stats, collect_java_comment_aggregates};
use declarations::{
    collect_type_identifiers, find_nearest_declaration_from_node, is_comment_node,
    is_declaration_parent, is_java_anonymous_structure, node_text, normalize_java_full_name,
    parse_tree,
};
use exceptions::detect_exception_handling_smells_java;
use external::JavaExternalDeclarationIndex;
use tests::detect_test_assertion_smells_java;

#[derive(Clone)]
pub struct JavaAnalyzer {
    inner: TreeSitterAnalyzer<JavaAdapter>,
    memo_caches: Arc<JavaMemoCaches>,
    external_dependencies: crate::analyzer::JavaExternalDependencies,
    external_index: Arc<std::sync::OnceLock<JavaExternalDeclarationIndex>>,
}

impl JavaAnalyzer {
    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        let external_dependencies = config.java.external_dependencies.clone();
        let inner = TreeSitterAnalyzer::new_with_config(project, JavaAdapter, config);
        Self {
            inner,
            memo_caches: Arc::new(JavaMemoCaches::new(memo_budget)),
            external_dependencies,
            external_index: Arc::new(std::sync::OnceLock::new()),
        }
    }

    pub fn new_with_config_and_storage(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        storage: Arc<crate::analyzer::persistence::AnalyzerStorage>,
    ) -> Self {
        Self::new_with_config_storage(project, config, storage, None)
    }

    pub(crate) fn new_with_config_storage_and_progress(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        storage: Arc<crate::analyzer::persistence::AnalyzerStorage>,
        progress: BuildProgress,
    ) -> Self {
        Self::new_with_config_storage(project, config, storage, Some(progress))
    }

    fn new_with_config_storage(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        storage: Arc<crate::analyzer::persistence::AnalyzerStorage>,
        progress: Option<BuildProgress>,
    ) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        let external_dependencies = config.java.external_dependencies.clone();
        let inner = match progress {
            Some(progress) => TreeSitterAnalyzer::new_with_config_storage_and_progress(
                project,
                JavaAdapter,
                config,
                storage,
                move |event| progress(event),
            ),
            None => TreeSitterAnalyzer::new_with_config_and_storage(
                project,
                JavaAdapter,
                config,
                storage,
            ),
        };
        Self {
            inner,
            memo_caches: Arc::new(JavaMemoCaches::new(memo_budget)),
            external_dependencies,
            external_index: Arc::new(std::sync::OnceLock::new()),
        }
    }

    pub fn new_with_progress<F>(project: Arc<dyn Project>, progress: F) -> Self
    where
        F: Fn(BuildProgressEvent) + Send + Sync + 'static,
    {
        Self::new_with_config_and_progress(project, AnalyzerConfig::default(), progress)
    }

    pub fn new_with_config_and_progress<F>(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        progress: F,
    ) -> Self
    where
        F: Fn(BuildProgressEvent) + Send + Sync + 'static,
    {
        let memo_budget = config.memo_cache_budget_bytes();
        let external_dependencies = config.java.external_dependencies.clone();
        let inner = TreeSitterAnalyzer::new_with_config_and_progress(
            project,
            JavaAdapter,
            config,
            progress,
        );
        Self {
            inner,
            memo_caches: Arc::new(JavaMemoCaches::new(memo_budget)),
            external_dependencies,
            external_index: Arc::new(std::sync::OnceLock::new()),
        }
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }

    pub fn from_project_with_config<P>(project: P, config: AnalyzerConfig) -> Self
    where
        P: Project + 'static,
    {
        Self::new_with_config(Arc::new(project), config)
    }

    pub fn from_project_with_progress<P, F>(project: P, progress: F) -> Self
    where
        P: Project + 'static,
        F: Fn(BuildProgressEvent) + Send + Sync + 'static,
    {
        Self::new_with_progress(Arc::new(project), progress)
    }

    pub fn from_project_with_config_and_progress<P, F>(
        project: P,
        config: AnalyzerConfig,
        progress: F,
    ) -> Self
    where
        P: Project + 'static,
        F: Fn(BuildProgressEvent) + Send + Sync + 'static,
    {
        Self::new_with_config_and_progress(Arc::new(project), config, progress)
    }

    pub fn inner(&self) -> &TreeSitterAnalyzer<JavaAdapter> {
        &self.inner
    }

    pub fn normalize_full_name(&self, fq_name: &str) -> String {
        normalize_java_full_name(fq_name)
    }

    pub fn is_anonymous_structure(&self, fq_name: &str) -> bool {
        is_java_anonymous_structure(fq_name)
    }

    pub fn extract_type_identifiers(&self, source: &str) -> BTreeSet<String> {
        let Some(tree) = parse_tree(source) else {
            return BTreeSet::new();
        };
        let mut identifiers = HashSet::default();
        collect_type_identifiers(tree.root_node(), source, &mut identifiers);
        identifiers.into_iter().collect()
    }

    pub fn resolve_type_name_in_file(
        &self,
        file: &ProjectFile,
        raw_name: &str,
    ) -> Option<CodeUnit> {
        self.resolve_type_name(file, raw_name)
    }

    pub fn is_known_type_name_in_file(&self, file: &ProjectFile, raw_name: &str) -> bool {
        self.resolve_type_name_with_external(file, raw_name)
            .is_some()
    }

    pub fn package_name_of(&self, file: &ProjectFile) -> Option<&str> {
        self.inner.package_name_of(file)
    }

    pub(crate) fn external_declaration_index(&self) -> &JavaExternalDeclarationIndex {
        self.external_index.get_or_init(|| {
            JavaExternalDeclarationIndex::build(
                &self.external_dependencies,
                self.inner.project().root(),
            )
        })
    }
}

impl IAnalyzer for JavaAnalyzer {
    fn top_level_declarations<'a>(
        &'a self,
        file: &ProjectFile,
    ) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a> {
        self.inner.top_level_declarations(file)
    }

    fn analyzed_files<'a>(&'a self) -> Box<dyn Iterator<Item = &'a ProjectFile> + 'a> {
        self.inner.analyzed_files()
    }

    fn is_analyzed(&self, file: &ProjectFile) -> bool {
        self.inner.is_analyzed(file)
    }

    fn all_declarations<'a>(&'a self) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a> {
        self.inner.all_declarations()
    }

    fn declarations<'a>(
        &'a self,
        file: &ProjectFile,
    ) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a> {
        self.inner.declarations(file)
    }

    fn definitions<'a>(&'a self, fq_name: &'a str) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a> {
        self.inner.definitions(fq_name)
    }

    fn definition_lookup_index(&self) -> &crate::analyzer::DefinitionLookupIndex {
        self.inner.definition_lookup_index()
    }

    fn direct_children<'a>(
        &'a self,
        code_unit: &CodeUnit,
    ) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a> {
        self.inner.direct_children(code_unit)
    }

    fn import_statements<'a>(&'a self, file: &ProjectFile) -> &'a [String] {
        self.inner.import_statements(file)
    }

    fn ranges<'a>(&'a self, code_unit: &CodeUnit) -> &'a [crate::analyzer::Range] {
        self.inner.ranges(code_unit)
    }

    fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)> {
        self.inner.compute_cognitive_complexities(file)
    }

    fn signatures<'a>(&'a self, code_unit: &CodeUnit) -> &'a [String] {
        self.inner.signatures(code_unit)
    }

    fn signature_metadata<'a>(&'a self, code_unit: &CodeUnit) -> &'a [SignatureMetadata] {
        self.inner.signature_metadata(code_unit)
    }

    fn get_top_level_declarations(&self, file: &ProjectFile) -> Vec<CodeUnit> {
        self.inner.get_top_level_declarations(file)
    }

    fn get_analyzed_files(&self) -> BTreeSet<ProjectFile> {
        self.inner.get_analyzed_files()
    }

    fn languages(&self) -> BTreeSet<Language> {
        self.inner.languages()
    }

    fn update(&self, _changed_files: &BTreeSet<ProjectFile>) -> Self {
        Self {
            inner: self.inner.update(_changed_files),
            memo_caches: Arc::new(JavaMemoCaches::new(self.memo_caches.budget_bytes())),
            external_dependencies: self.external_dependencies.clone(),
            external_index: self.external_index.clone(),
        }
    }

    fn update_all(&self) -> Self {
        Self {
            inner: self.inner.update_all(),
            memo_caches: Arc::new(JavaMemoCaches::new(self.memo_caches.budget_bytes())),
            external_dependencies: self.external_dependencies.clone(),
            external_index: self.external_index.clone(),
        }
    }

    fn project(&self) -> &dyn Project {
        self.inner.project()
    }

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        Some(self)
    }

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
        Some(self)
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        Some(self)
    }

    fn structural_search_providers(
        &self,
    ) -> Vec<&dyn crate::analyzer::structural::StructuralSearchProvider> {
        vec![&self.inner]
    }

    fn get_all_declarations(&self) -> Vec<CodeUnit> {
        self.inner.get_all_declarations()
    }

    fn get_declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        self.inner.get_declarations(file)
    }

    fn get_definitions(&self, fq_name: &str) -> Vec<CodeUnit> {
        self.inner.get_definitions(fq_name)
    }

    fn get_direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.inner.get_direct_children(code_unit)
    }

    fn parse_errors(&self, file: &ProjectFile) -> Option<Vec<crate::analyzer::ParseError>> {
        self.inner.parse_errors(file)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        self.inner.extract_call_receiver(reference)
    }

    fn import_statements_of(&self, file: &ProjectFile) -> Vec<String> {
        self.inner.import_statements_of(file)
    }

    fn enclosing_code_unit(
        &self,
        file: &ProjectFile,
        range: &crate::analyzer::Range,
    ) -> Option<CodeUnit> {
        self.inner.enclosing_code_unit(file, range)
    }

    fn enclosing_code_unit_for_lines(
        &self,
        file: &ProjectFile,
        start_line: usize,
        end_line: usize,
    ) -> Option<CodeUnit> {
        self.inner
            .enclosing_code_unit_for_lines(file, start_line, end_line)
    }

    fn is_access_expression(&self, file: &ProjectFile, start_byte: usize, end_byte: usize) -> bool {
        let Ok(source) = self.inner.project().read_source(file) else {
            return true;
        };
        let Some(tree) = parse_tree(&source) else {
            return true;
        };
        let root = tree.root_node();
        let Some(node) = root.named_descendant_for_byte_range(start_byte, end_byte) else {
            return true;
        };

        let mut walk = Some(node);
        while let Some(current) = walk {
            if is_comment_node(current) {
                return false;
            }
            walk = current.parent();
        }

        let mut current = Some(node);
        while let Some(candidate) = current {
            if let Some(parent) = candidate.parent()
                && is_declaration_parent(parent.kind())
                && let Some(name_node) = parent.child_by_field_name("name")
                && name_node.start_byte() == start_byte
            {
                return false;
            }
            current = candidate.parent();
        }

        if let Some(parent) = node.parent() {
            if parent.kind() == "field_access"
                && let Some(field_node) = parent.child_by_field_name("field")
                && field_node.start_byte() == node.start_byte()
            {
                return true;
            }
            if parent.kind() == "method_invocation"
                && let Some(name_node) = parent.child_by_field_name("name")
                && name_node.start_byte() == node.start_byte()
            {
                return true;
            }
        }

        let identifier = node_text(node, &source).trim().to_string();
        if identifier.is_empty() {
            return true;
        }

        match find_nearest_declaration_from_node(node, &identifier, &source) {
            Some(info) => !matches!(
                info.kind,
                DeclarationKind::Parameter
                    | DeclarationKind::LocalVariable
                    | DeclarationKind::CatchParameter
                    | DeclarationKind::EnhancedForVariable
                    | DeclarationKind::ResourceVariable
                    | DeclarationKind::PatternVariable
                    | DeclarationKind::LambdaParameter
            ),
            None => true,
        }
    }

    fn find_nearest_declaration(
        &self,
        file: &ProjectFile,
        start_byte: usize,
        end_byte: usize,
        ident: &str,
    ) -> Option<crate::analyzer::DeclarationInfo> {
        let Ok(source) = self.inner.project().read_source(file) else {
            return None;
        };
        let tree = parse_tree(&source)?;
        let root = tree.root_node();
        let node = root.named_descendant_for_byte_range(start_byte, end_byte)?;
        find_nearest_declaration_from_node(node, ident, &source)
    }

    fn ranges_of(&self, code_unit: &CodeUnit) -> Vec<crate::analyzer::Range> {
        self.inner.ranges_of(code_unit)
    }

    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        self.inner.get_skeleton(code_unit)
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        self.inner.get_skeleton_header(code_unit)
    }

    fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String> {
        self.inner.get_source(code_unit, include_comments)
    }

    fn get_sources(&self, code_unit: &CodeUnit, include_comments: bool) -> BTreeSet<String> {
        self.inner.get_sources(code_unit, include_comments)
    }

    fn search_definitions(&self, pattern: &str, auto_quote: bool) -> BTreeSet<CodeUnit> {
        self.inner.search_definitions(pattern, auto_quote)
    }

    fn search_definitions_persisted(&self, pattern: &str) -> BTreeSet<CodeUnit> {
        // Forward to the inner `TreeSitterAnalyzer`; otherwise the default
        // impl on `IAnalyzer` re-dispatches to `self.search_definitions`,
        // skipping the FTS5 path entirely.
        self.inner.search_definitions_persisted(pattern)
    }

    fn signatures_of(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.inner.signatures_of(code_unit).to_vec()
    }

    fn contains_tests(&self, file: &ProjectFile) -> bool {
        self.inner.contains_tests(file)
    }

    fn comment_density(&self, code_unit: &CodeUnit) -> Option<CommentDensityStats> {
        if file_language(code_unit.source()) != Language::Java {
            return None;
        }
        let source = self.inner.project().read_source(code_unit.source()).ok()?;
        let aggs = collect_java_comment_aggregates(self, code_unit.source(), &source);
        Some(build_java_roll_up_stats(self, code_unit, &aggs))
    }

    fn comment_density_by_top_level(&self, file: &ProjectFile) -> Vec<CommentDensityStats> {
        if file_language(file) != Language::Java {
            return Vec::new();
        }
        let Ok(source) = self.inner.project().read_source(file) else {
            return Vec::new();
        };
        let aggs = collect_java_comment_aggregates(self, file, &source);
        // Bifrost emits a top-level Module per Java package declaration; brokk's
        // Java analyzer does not. Skip module-kind tops so this method returns
        // the same set of stats rows as brokk-shared `JavaAnalyzer.commentDensityByTopLevel`.
        self.get_top_level_declarations(file)
            .iter()
            .filter(|cu| !cu.is_module() && !cu.is_synthetic())
            .map(|top| build_java_roll_up_stats(self, top, &aggs))
            .collect()
    }

    fn find_exception_handling_smells(
        &self,
        file: &ProjectFile,
        weights: ExceptionSmellWeights,
    ) -> Vec<ExceptionHandlingSmell> {
        if file_language(file) != Language::Java {
            return Vec::new();
        }
        let Ok(source) = self.inner.project().read_source(file) else {
            return Vec::new();
        };
        detect_exception_handling_smells_java(self, file, &source, &weights)
    }

    fn find_test_assertion_smells(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
    ) -> Vec<TestAssertionSmell> {
        if file_language(file) != Language::Java || !self.contains_tests(file) {
            return Vec::new();
        }
        let Ok(source) = self.inner.project().read_source(file) else {
            return Vec::new();
        };
        detect_test_assertion_smells_java(self, file, &source, &weights)
    }

    fn find_structural_clone_smells(
        &self,
        file: &ProjectFile,
        weights: CloneSmellWeights,
    ) -> Vec<CloneSmell> {
        self.find_structural_clone_smells_for_files(std::slice::from_ref(file), weights)
    }

    fn find_structural_clone_smells_for_files(
        &self,
        files: &[ProjectFile],
        weights: CloneSmellWeights,
    ) -> Vec<CloneSmell> {
        let requested_files: Vec<ProjectFile> = files
            .iter()
            .filter(|file| file_language(file) == Language::Java)
            .cloned()
            .collect();
        if requested_files.is_empty() {
            return Vec::new();
        }

        let all_candidates: Vec<CloneCandidateProfile> = self
            .get_all_declarations()
            .into_iter()
            .filter(|code_unit| {
                code_unit.is_function() && file_language(code_unit.source()) == Language::Java
            })
            .filter_map(|code_unit| build_clone_candidate_data(self, &code_unit, weights))
            .map(|candidate| CloneCandidateProfile::create(candidate, weights))
            .collect();
        if all_candidates.is_empty() {
            return Vec::new();
        }

        detect_structural_clone_smells(
            &requested_files,
            all_candidates,
            weights,
            refine_java_clone_similarity,
        )
    }
}
