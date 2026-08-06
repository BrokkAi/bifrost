mod adapter;
mod cache;
mod clones;
pub(crate) mod declarations;
mod exceptions;
mod hierarchy;
pub(crate) mod imports;
mod semantic;
pub(crate) mod structural;
mod tests;

use crate::analyzer::clone_detection::{
    CloneCandidateProfile, detect_structural_clone_smells, refine_clone_similarity_with_ast,
};
use crate::analyzer::common::{is_unparseable_source, language_for_file as file_language};
use crate::analyzer::tree_sitter_analyzer::FileState;
use crate::analyzer::{
    AnalyzerConfig, AnalyzerStoreContext, BuildProgress, BuildProgressEvent, BulkFileStateSource,
    CallableArity, CloneSmell, CloneSmellWeights, CodeUnit, DeclarationInfo, DeclarationKind,
    ExceptionHandlingAnalysis, ExceptionHandlingSmell, ExceptionSmellWeights, IAnalyzer,
    ImportAnalysisProvider, Language, Project, ProjectFile, SignatureMetadata, TestAssertionSmell,
    TestAssertionWeights, TestDetectionProvider, TreeSitterAnalyzer, TypeHierarchyProvider,
    UsageFactsIndex,
};
use crate::hash::{HashMap, HashSet};
use std::collections::BTreeSet;
use std::sync::Arc;

use crate::analyzer::java::imports::JavaTypeResolution;
use crate::analyzer::jvm::dependency_discovery::is_jvm_dependency_input;
use crate::analyzer::jvm::external::JvmExternalDeclarationIndex;
use crate::analyzer::structural::resolution::BoundaryStatus;
pub(crate) use adapter::JavaAdapter;
use cache::JavaMemoCaches;
use clones::build_clone_candidate_data;
use declarations::{
    collect_type_identifiers, find_nearest_declaration_from_node, is_comment_node,
    is_declaration_parent, is_java_anonymous_structure, node_text, normalize_java_full_name,
    parse_tree,
};
use exceptions::detect_exception_handling_smells_java;
use tests::detect_test_assertion_smells_java;

#[derive(Clone)]
pub struct JavaAnalyzer {
    inner: TreeSitterAnalyzer<JavaAdapter>,
    memo_caches: Arc<JavaMemoCaches>,
    java_config: crate::analyzer::JvmAnalyzerConfig,
    pub(crate) external_index: Arc<std::sync::OnceLock<JvmExternalDeclarationIndex>>,
}

crate::analyzer::impl_forward_query_provider!(JavaAnalyzer);

impl JavaAnalyzer {
    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        let mut clone = self.clone();
        clone.inner = clone.inner.clone_with_project(project);
        clone.external_index = Arc::new(std::sync::OnceLock::new());
        clone
    }

    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        let java_config = config.jvm.clone();
        let inner = TreeSitterAnalyzer::new_with_config(project, JavaAdapter, config);
        Self {
            inner,
            memo_caches: Arc::new(JavaMemoCaches::new(memo_budget)),
            java_config,
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
        let java_config = config.jvm.clone();
        let inner = TreeSitterAnalyzer::new_with_config_and_progress(
            project,
            JavaAdapter,
            config,
            progress,
        );
        Self {
            inner,
            memo_caches: Arc::new(JavaMemoCaches::new(memo_budget)),
            java_config,
            external_index: Arc::new(std::sync::OnceLock::new()),
        }
    }

    pub(crate) fn new_with_config_store_context(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        store_context: AnalyzerStoreContext,
        progress: Option<BuildProgress>,
    ) -> Result<Self, crate::analyzer::store::StoreError> {
        let memo_budget = config.memo_cache_budget_bytes();
        let java_config = config.jvm.clone();
        let inner = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            project,
            JavaAdapter,
            config,
            store_context,
            progress,
        )?;
        Ok(Self {
            inner,
            memo_caches: Arc::new(JavaMemoCaches::new(memo_budget)),
            java_config,
            external_index: Arc::new(std::sync::OnceLock::new()),
        })
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
        self.resolve_forward_type_name(file, raw_name)
    }

    /// Every candidate the deciding type-name tier produced for `raw_name`.
    /// More than one entry means colliding on-demand imports supplied the same
    /// simple name, so no candidate is provably unique (issue #1602).
    pub fn resolve_type_name_candidates_in_file(
        &self,
        file: &ProjectFile,
        raw_name: &str,
    ) -> Vec<CodeUnit> {
        self.resolve_forward_type_name_candidates(file, raw_name)
    }

    pub fn is_known_type_name_in_file(&self, file: &ProjectFile, raw_name: &str) -> bool {
        self.resolve_type_name_with_external(file, raw_name)
            .is_some()
    }

    pub fn package_name_of(&self, file: &ProjectFile) -> Option<String> {
        self.cached_package_name(file)
            .map(|package| package.to_string())
    }

    /// How far a lookup for `name` from `file` could see past the workspace,
    /// and the external type it landed on when it landed on one.
    ///
    /// This reads the external declaration index that the resolver itself
    /// consults; it performs no new resolution and cannot change one. The three
    /// answers it distinguishes are the ones a single "unresolvable import"
    /// bucket cannot: the name is externally indexed, the build declared
    /// artifacts the index could not finish reading (so the name may be there),
    /// or nothing is known.
    pub(crate) fn external_boundary_evidence(
        &self,
        file: &ProjectFile,
        name: &str,
    ) -> (BoundaryStatus, Option<String>) {
        let external = self.external_declaration_index();
        if let Some(JavaTypeResolution::External(external_type)) =
            self.resolve_type_name_with_external(file, name)
        {
            return (
                BoundaryStatus::ExternalIndexed,
                Some(external_type.fqn().to_owned()),
            );
        }
        if external.production_diagnostic_count() > 0 {
            return (BoundaryStatus::ExternalDeclaredUnindexed, None);
        }
        (BoundaryStatus::ExternalUnknown, None)
    }

    pub(crate) fn external_declaration_index(&self) -> &JvmExternalDeclarationIndex {
        self.external_index.get_or_init(|| {
            JvmExternalDeclarationIndex::build_for_project(&self.java_config, self.inner.project())
        })
    }

    pub(crate) fn bulk_file_states(
        &self,
        files: impl IntoIterator<Item = ProjectFile>,
        source_mode: BulkFileStateSource,
    ) -> HashMap<ProjectFile, FileState> {
        self.inner.bulk_file_states(files, source_mode)
    }

    pub(crate) fn cached_package_name(&self, file: &ProjectFile) -> Option<Arc<str>> {
        if let Some(package) = self.memo_caches.package_names.get(file) {
            return Some(package);
        }
        let package: Arc<str> = Arc::from(self.inner.package_name_of(file)?);
        self.memo_caches
            .package_names
            .insert(file.clone(), Arc::clone(&package));
        Some(package)
    }

    /// Classify exact-FQN callable candidates and the source-level constructor
    /// shape from one coherent parser snapshot.
    ///
    /// Java permits an ordinary method to have the same simple name as its
    /// enclosing class, so FQN and arity alone cannot distinguish the two.
    pub(crate) fn constructor_context(
        &self,
        owner: &CodeUnit,
        candidates: Vec<CodeUnit>,
        call_arity: usize,
    ) -> (Vec<CodeUnit>, bool) {
        let Some(prepared) = self.inner.prepared_syntax(owner.source()) else {
            return (Vec::new(), false);
        };
        let owner_children = prepared.direct_children(owner);
        let has_explicit_constructor = owner_children.iter().any(|child| {
            prepared.declaration_node(child).is_some_and(|node| {
                matches!(
                    node.kind(),
                    "constructor_declaration" | "compact_constructor_declaration"
                )
            })
        });
        let direct_children = owner_children.iter().collect::<HashSet<_>>();
        let constructors = candidates
            .into_iter()
            .filter(|candidate| direct_children.contains(candidate))
            .filter(|candidate| {
                prepared.declaration_node(candidate).is_some_and(|node| {
                    matches!(
                        node.kind(),
                        "constructor_declaration" | "compact_constructor_declaration"
                    )
                })
            })
            .collect::<Vec<_>>();
        let owner_shape_accepts = match prepared.declaration_node(owner) {
            Some(node) if node.kind() == "class_declaration" => {
                !has_explicit_constructor && call_arity == 0
            }
            Some(node) if node.kind() == "record_declaration" => {
                let Some(parameters) = node.child_by_field_name("parameters") else {
                    return (constructors, false);
                };
                let mut cursor = parameters.walk();
                let mut required = 0;
                let mut repeated = false;
                for parameter in parameters.named_children(&mut cursor) {
                    match parameter.kind() {
                        "formal_parameter" => required += 1,
                        "spread_parameter" => repeated = true,
                        _ => {}
                    }
                }
                CallableArity::new(required, required + usize::from(repeated), repeated)
                    .accepts(call_arity)
            }
            _ => false,
        };
        (constructors, owner_shape_accepts)
    }
}

impl IAnalyzer for JavaAnalyzer {
    fn begin_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        self.inner.begin_query(context);
    }

    fn end_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        self.inner.end_query(context);
    }

    fn begin_streaming_file_read(&self, file: &ProjectFile) {
        self.inner.begin_streaming_file_read(file);
    }

    fn end_streaming_file_read(&self, file: &ProjectFile) {
        self.inner.end_streaming_file_read(file);
    }

    fn release_streaming_readers(&self) {
        self.inner.release_streaming_readers();
    }

    fn workspace_file_index_cell(&self) -> Option<crate::analyzer::WorkspaceFileIndexCell> {
        self.inner.workspace_file_index_cell()
    }

    fn top_level_declarations(&self, file: &ProjectFile) -> Vec<CodeUnit> {
        self.inner.top_level_declarations(file)
    }

    fn summary_file_projection(
        &self,
        file: &ProjectFile,
    ) -> Option<Arc<crate::analyzer::SummaryFileProjection>> {
        self.inner.summary_file_projection(file)
    }

    fn analyzed_files(&self) -> Vec<ProjectFile> {
        self.inner.analyzed_files()
    }

    fn indexed_source(&self, file: &ProjectFile) -> Option<String> {
        self.inner.indexed_source(file)
    }

    fn indexed_source_matches(&self, file: &ProjectFile, source: &str) -> bool {
        self.inner.indexed_source_matches(file, source)
    }

    fn is_analyzed(&self, file: &ProjectFile) -> bool {
        self.inner.is_analyzed(file)
    }

    fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        self.inner.all_declarations()
    }

    fn all_declarations_with_primary_ranges(
        &self,
    ) -> Vec<(CodeUnit, Option<crate::analyzer::Range>)> {
        self.inner.all_declarations_with_primary_ranges()
    }

    fn declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        self.inner.declarations(file)
    }

    fn definitions(&self, fq_name: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        self.inner.definitions(fq_name)
    }

    fn reset_global_usage_definition_index_build_count_for_test(&self) {
        self.inner
            .reset_global_usage_definition_index_build_count_for_test();
    }

    fn global_usage_definition_index_build_count_for_test(&self) -> usize {
        self.inner
            .global_usage_definition_index_build_count_for_test()
    }

    fn reset_full_declaration_scan_count_for_test(&self) {
        self.inner.reset_full_declaration_scan_count_for_test();
    }

    fn full_declaration_scan_count_for_test(&self) -> usize {
        self.inner.full_declaration_scan_count_for_test()
    }

    fn reset_candidate_hydration_count_for_test(&self) {
        self.inner.reset_full_hydration_count_for_test();
    }

    fn candidate_hydration_count_for_test(&self) -> usize {
        self.inner.full_hydration_count_for_test() + self.inner.bulk_hydration_count_for_test()
    }

    fn reset_package_declaration_scan_count_for_test(&self) {
        self.inner.reset_package_declaration_scan_count_for_test();
    }

    fn package_declaration_scan_count_for_test(&self) -> usize {
        self.inner.package_declaration_scan_count_for_test()
    }

    fn global_usage_definition_index(&self) -> crate::analyzer::DefinitionIndexHandle<'_> {
        self.inner.global_usage_definition_index()
    }

    fn usage_facts_index(&self) -> &UsageFactsIndex {
        self.inner.usage_facts_index()
    }

    fn direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.inner.direct_children(code_unit)
    }

    fn direct_children_in_file(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.inner.direct_children_in_file(code_unit)
    }

    fn declaration_syntax_kind(&self, code_unit: &CodeUnit) -> Option<&'static str> {
        self.inner.declaration_syntax_kind(code_unit)
    }

    fn parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        self.inner.structural_parent_of(code_unit)
    }

    fn import_statements(&self, file: &ProjectFile) -> Vec<String> {
        self.inner.import_statements(file)
    }

    fn ranges(&self, code_unit: &CodeUnit) -> Vec<crate::analyzer::Range> {
        self.inner.ranges(code_unit)
    }

    fn ranges_with_limit(
        &self,
        code_unit: &CodeUnit,
        max_ranges: usize,
        cancellation: &crate::CancellationToken,
    ) -> (Vec<crate::analyzer::Range>, usize, bool) {
        self.inner
            .ranges_with_limit(code_unit, max_ranges, cancellation)
    }

    fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)> {
        self.inner.compute_cognitive_complexities(file)
    }

    fn signatures(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.inner.signatures(code_unit)
    }

    fn signature_metadata(&self, code_unit: &CodeUnit) -> Vec<SignatureMetadata> {
        self.inner.signature_metadata(code_unit)
    }

    fn get_analyzed_files(&self) -> BTreeSet<ProjectFile> {
        self.inner.get_analyzed_files()
    }

    fn languages(&self) -> BTreeSet<Language> {
        self.inner.languages()
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        let external_index = if changed_files.iter().any(is_jvm_dependency_input) {
            Arc::new(std::sync::OnceLock::new())
        } else {
            self.external_index.clone()
        };
        Self {
            inner: self.inner.update(changed_files),
            memo_caches: Arc::new(JavaMemoCaches::new(self.memo_caches.budget_bytes())),
            java_config: self.java_config.clone(),
            external_index,
        }
    }

    fn update_all(&self) -> Self {
        Self {
            inner: self.inner.update_all(),
            memo_caches: Arc::new(JavaMemoCaches::new(self.memo_caches.budget_bytes())),
            java_config: self.java_config.clone(),
            external_index: Arc::new(std::sync::OnceLock::new()),
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
        self.inner.structural_search_providers()
    }

    fn snapshot_caches(&self) -> Option<&crate::analyzer::AnalyzerSnapshotCaches> {
        Some(self.inner.snapshot_caches())
    }

    fn get_all_declarations(&self) -> Vec<CodeUnit> {
        self.inner.get_all_declarations()
    }

    fn get_definitions(&self, fq_name: &str) -> Vec<CodeUnit> {
        self.inner.get_definitions(fq_name)
    }

    fn parse_errors(&self, file: &ProjectFile) -> Option<Vec<crate::analyzer::ParseError>> {
        self.inner.parse_errors(file)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        self.inner.extract_call_receiver(reference)
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

    fn search_definitions_with_literal(
        &self,
        pattern: &str,
        required_literal: &str,
        language: Language,
    ) -> BTreeSet<CodeUnit> {
        self.inner
            .search_definitions_with_literal(pattern, required_literal, language)
    }

    fn lookup_candidates_by_short_name(&self, symbol: &str) -> BTreeSet<CodeUnit> {
        self.inner.lookup_candidates_by_short_name(symbol)
    }

    fn lookup_candidates_by_identifier(&self, identifier: &str) -> BTreeSet<CodeUnit> {
        self.inner.lookup_declarations_by_identifier(identifier)
    }

    fn has_complete_symbol_lookup_index(&self) -> bool {
        self.inner.has_complete_symbol_lookup_index()
    }

    fn search_symbol_candidates(
        &self,
        patterns: &crate::analyzer::SearchSymbolPatternBatch,
        cancellation: Option<&crate::CancellationToken>,
    ) -> crate::analyzer::SearchSymbolCandidates {
        self.inner.search_symbol_candidates(patterns, cancellation)
    }

    fn contains_tests(&self, file: &ProjectFile) -> bool {
        self.inner.contains_tests(file)
    }

    fn in_test_region(&self, code_unit: &crate::analyzer::CodeUnit) -> bool {
        self.inner.in_test_region(code_unit)
    }

    fn find_exception_handling_smells(
        &self,
        file: &ProjectFile,
        weights: ExceptionSmellWeights,
    ) -> ExceptionHandlingAnalysis {
        if file_language(file) != Language::Java {
            return ExceptionHandlingAnalysis::Unsupported {
                reason: format!(
                    "Java exception semantics do not apply to {}",
                    file.rel_path().display()
                ),
            };
        }
        let source = match self.inner.project().read_source(file) {
            Ok(source) => source,
            Err(error) => {
                return ExceptionHandlingAnalysis::Failed {
                    message: format!("failed to read {}: {error}", file.rel_path().display()),
                };
            }
        };
        if is_unparseable_source(&source) {
            return ExceptionHandlingAnalysis::Failed {
                message: format!("failed to parse {}", file.rel_path().display()),
            };
        }
        match detect_exception_handling_smells_java(self, file, &source, &weights) {
            Some(findings) => ExceptionHandlingAnalysis::Analyzed(findings),
            None => ExceptionHandlingAnalysis::Failed {
                message: format!("failed to parse {}", file.rel_path().display()),
            },
        }
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
            refine_clone_similarity_with_ast,
        )
    }
}
