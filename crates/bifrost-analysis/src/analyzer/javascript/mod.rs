use crate::analyzer::clone_detection::{
    CloneCandidateData, CloneCandidateProfile, compact_clone_excerpt,
    detect_structural_clone_smells, refine_clone_similarity_with_ast,
};
use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::fq_name::{FqName, SegmentKind};
use crate::analyzer::js_ts::cache::JsTsMemoCaches;
use crate::analyzer::js_ts::clones::{
    build_js_ts_clone_ast_signature, normalized_clone_tokens_js_ts,
};
use crate::analyzer::js_ts::diagnostics::collect_javascript_semantic_diagnostics;
use crate::analyzer::js_ts::hierarchy::extract_js_supertypes;
use crate::analyzer::js_ts::identifiers::collect_js_ts_identifiers;
use crate::analyzer::js_ts::imports::extract_js_ts_call_receiver;
use crate::analyzer::js_ts::imports::{
    parse_commonjs_require_import_infos_from_node, parse_es_import_infos_from_node,
};
use crate::analyzer::js_ts::model::{
    add_default_export_unit, add_destructured_binder_units, call_has_likely_surface_factory_name,
    call_identifier_name, call_is_schema_object_builder, collect_function_nodes,
    file_scoped_field_fq, file_scoped_field_name, js_ts_segment, module_code_unit,
    module_scoped_field_uses_file_name, node_text, property_name_text, record_default_reexport,
    record_named_declarator_exports, record_named_export, root_node, this_member_property,
    trim_statement, variable_header,
};
use crate::analyzer::js_ts::providers::{self, JsTsAnalyzerHost};
use crate::analyzer::js_ts::tests::detect_js_ts_test_assertion_smells;
use crate::analyzer::js_ts::{
    contains_tests as js_ts_contains_tests, path_contains_tests as js_ts_path_contains_tests,
    source_contains_tests as js_ts_source_contains_tests,
    synthesize_hydrated_module as synthesize_js_ts_hydrated_module_unit,
};
use crate::analyzer::structural::materialization::{ExportForm, MaterializationRecord};
use crate::analyzer::tree_sitter_analyzer::lookup_suffix_candidates;
use crate::analyzer::tree_sitter_analyzer::{WalkControl, walk_named_tree_preorder};
use crate::analyzer::usages::js_ts_graph::JsTsUsageIndex;
use crate::analyzer::{
    AliasResolver, AnalyzerConfig, AnalyzerStoreContext, BuildProgress, CodeUnit, IAnalyzer,
    ImportAnalysisProvider, ImportInfo, Language, LanguageAdapter, ParameterMetadata, Project,
    ProjectFile, SemanticDiagnostic, SignatureMetadata, TestAssertionSmell, TestAssertionWeights,
    TestDetectionProvider, TreeSitterAnalyzer, TypeHierarchyProvider,
};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use crate::{CloneSmell, CloneSmellWeights};
use std::collections::BTreeSet;
use std::sync::Arc;
use tree_sitter::{Node, Parser, Tree};

mod semantic;

#[derive(Debug, Clone, Default)]
pub struct JavascriptAdapter;

impl LanguageAdapter for JavascriptAdapter {
    fn language(&self) -> Language {
        Language::JavaScript
    }

    fn query_directory(&self) -> &'static str {
        "resources/treesitter/javascript"
    }

    fn file_extension(&self) -> &'static str {
        "js"
    }

    fn should_persist_code_unit(&self, code_unit: &CodeUnit) -> bool {
        !code_unit.is_file_scope() && !code_unit.is_module()
    }

    fn lookup_candidate_short_names(&self, normalized_fq_name: &str) -> Vec<String> {
        lookup_suffix_candidates(normalized_fq_name, &["."])
    }

    fn storage_contains_tests(
        &self,
        state: &crate::analyzer::tree_sitter_analyzer::FileState,
    ) -> bool {
        js_ts_source_contains_tests(&state.source)
    }

    fn hydrate_contains_tests(&self, stored: bool, file: &ProjectFile, source: &str) -> bool {
        stored || js_ts_path_contains_tests(file) || js_ts_source_contains_tests(source)
    }

    fn synthesize_hydrated_units(
        &self,
        file: &ProjectFile,
        source: &str,
        state: &mut crate::analyzer::tree_sitter_analyzer::FileState,
    ) {
        synthesize_js_ts_hydrated_module_unit(file, source, state);
    }

    fn path_synthetic_module_unit(&self, file: &ProjectFile) -> Option<CodeUnit> {
        Some(module_code_unit(file))
    }

    fn has_path_synthetic_module_units(&self) -> bool {
        true
    }

    fn path_synthetic_module_requires_imports(&self) -> bool {
        true
    }

    fn include_path_synthetic_module(&self, has_structured_imports: bool) -> bool {
        has_structured_imports
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        extract_js_ts_call_receiver(reference)
    }

    fn contains_tests(
        &self,
        file: &ProjectFile,
        source: &str,
        _tree: &Tree,
        _parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        js_ts_contains_tests(file, source)
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
        let root = tree.root_node();
        let mut parsed = crate::analyzer::tree_sitter_analyzer::ParsedFile::new(String::new());
        let module = module_code_unit(file);
        let mut module_has_imports = false;
        let exported_roots = js_exported_binding_roots(root, source);

        for index in 0..root.named_child_count() {
            let Some(child) = root.named_child(index) else {
                continue;
            };
            match child.kind() {
                "import_statement" => {
                    let raw = node_text(child, source).trim().to_string();
                    module_has_imports = true;
                    parsed.import_statements.push(raw.clone());
                    parsed
                        .imports
                        .extend(parse_es_import_infos_from_node(child, source));
                }
                "expression_statement" => {
                    let imports = parse_commonjs_require_import_infos_from_node(child, source);
                    if !imports.is_empty() {
                        let raw = node_text(child, source).trim().to_string();
                        module_has_imports = true;
                        parsed.import_statements.push(raw);
                        parsed.imports.extend(imports);
                    }
                }
                "export_statement" => {
                    visit_js_export(file, source, child, &mut parsed);
                }
                "class_declaration" => {
                    visit_js_class(file, source, child, None, &mut parsed, false);
                }
                "function_declaration" => {
                    visit_js_function(file, source, child, None, &mut parsed, false);
                }
                "lexical_declaration" | "variable_declaration" => {
                    let imports = parse_commonjs_require_import_infos_from_node(child, source);
                    if !imports.is_empty() {
                        let raw = node_text(child, source).trim().to_string();
                        module_has_imports = true;
                        parsed.import_statements.push(raw);
                        parsed.imports.extend(imports);
                    }
                    visit_js_variable_statement(
                        file,
                        source,
                        child,
                        None,
                        &mut parsed,
                        false,
                        &exported_roots,
                    );
                }
                _ => {}
            }
        }

        visit_js_assignment_declarations(file, source, root, &mut parsed);

        if module_has_imports {
            parsed.add_code_unit(module, root, source, None, None);
        }

        parsed
    }

    fn cognitive_complexity_config(
        &self,
    ) -> Option<&'static crate::analyzer::cognitive_complexity::Config> {
        Some(crate::analyzer::js_ts::cognitive_complexity_config())
    }
}

#[derive(Clone)]
pub struct JavascriptAnalyzer {
    inner: TreeSitterAnalyzer<JavascriptAdapter>,
    memo_budget: u64,
    memo_caches: Arc<JsTsMemoCaches>,
    /// Shared jsconfig/tsconfig path-alias resolver (parsed configs cached) so the
    /// import/reference graph resolves `@/`-style aliases like the scan_usages graph.
    alias_resolver: Arc<AliasResolver>,
}

impl JsTsAnalyzerHost for JavascriptAnalyzer {
    type Adapter = JavascriptAdapter;

    fn ts_inner(&self) -> &TreeSitterAnalyzer<JavascriptAdapter> {
        &self.inner
    }

    fn memo_caches(&self) -> &JsTsMemoCaches {
        &self.memo_caches
    }

    fn alias_resolver(&self) -> &AliasResolver {
        &self.alias_resolver
    }

    fn js_ts_language(&self) -> Language {
        Language::JavaScript
    }
}

crate::analyzer::impl_forward_query_provider!(JavascriptAnalyzer);

impl JavascriptAnalyzer {
    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        let mut clone = self.clone();
        clone.inner = clone.inner.clone_with_project(project);
        clone
    }

    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    /// Lazily-built, analyzer-cached JS/TS usage-resolution maps for this analyzer's
    /// language. Built once and reused until `update`/`update_all` rebuilds the cache bucket.
    pub(crate) fn jsts_usage_index(&self) -> Arc<JsTsUsageIndex> {
        providers::jsts_usage_index(self)
    }

    pub(crate) fn jsts_usage_index_with_cancellation(
        &self,
        cancellation: &CancellationToken,
    ) -> Option<Arc<JsTsUsageIndex>> {
        providers::jsts_usage_index_with_cancellation(self, cancellation)
    }

    pub(crate) fn prewarm_jsts_usage_index(&self) -> Arc<JsTsUsageIndex> {
        providers::prewarm_jsts_usage_index(self)
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        let alias_resolver = Arc::new(AliasResolver::new(project.root().to_path_buf()));
        Self {
            inner: TreeSitterAnalyzer::new_with_config(project, JavascriptAdapter, config),
            memo_budget,
            memo_caches: Arc::new(JsTsMemoCaches::new(memo_budget)),
            alias_resolver,
        }
    }

    pub(crate) fn new_with_config_store_context(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        store_context: AnalyzerStoreContext,
        progress: Option<BuildProgress>,
    ) -> Result<Self, crate::analyzer::store::StoreError> {
        let memo_budget = config.memo_cache_budget_bytes();
        let alias_resolver = Arc::new(AliasResolver::new(project.root().to_path_buf()));
        let inner = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            project,
            JavascriptAdapter,
            config,
            store_context,
            progress,
        )?;
        Ok(Self {
            inner,
            memo_budget,
            memo_caches: Arc::new(JsTsMemoCaches::new(memo_budget)),
            alias_resolver,
        })
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }

    pub fn inner(&self) -> &TreeSitterAnalyzer<JavascriptAdapter> {
        &self.inner
    }

    pub(crate) fn ranges_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> crate::analyzer::store::LimitedQueryRows<crate::analyzer::Range> {
        self.inner.ranges_limited(code_unit, limit)
    }

    pub fn extract_type_identifiers(&self, source: &str) -> BTreeSet<String> {
        extract_js_type_identifiers(source)
    }

    fn module_import_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        if !code_unit.is_module() {
            return None;
        }

        let imports = self.inner.import_statements(code_unit.source());
        (!imports.is_empty()).then(|| imports.join("\n"))
    }
}
impl ImportAnalysisProvider for JavascriptAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> HashSet<CodeUnit> {
        providers::imported_code_units_of(self, file)
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        providers::referencing_files_of(self, file)
    }

    fn import_info_of(&self, file: &ProjectFile) -> Vec<ImportInfo> {
        self.inner.import_info_of(file)
    }

    fn import_infos_for_files(
        &self,
        files: &[ProjectFile],
    ) -> Option<HashMap<ProjectFile, Vec<ImportInfo>>> {
        providers::import_infos_for_files(self, files)
    }

    fn imported_code_units_from_infos(
        &self,
        file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<HashSet<CodeUnit>> {
        providers::imported_code_units_from_infos(self, file, imports)
    }

    fn imported_files_from_infos(
        &self,
        file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<HashSet<ProjectFile>> {
        providers::imported_files_from_infos(self, file, imports)
    }

    fn relevant_imports_for(&self, code_unit: &CodeUnit) -> HashSet<String> {
        providers::relevant_imports_for(self, code_unit)
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        providers::could_import_file(self, source_file, imports, target)
    }
}

impl TypeHierarchyProvider for JavascriptAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        providers::get_direct_ancestors(self, code_unit)
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        providers::get_direct_descendants(self, code_unit)
    }
}

impl TestDetectionProvider for JavascriptAnalyzer {}
use crate::analyzer::CodeUnitIndex;

impl CodeUnitIndex for JavascriptAnalyzer {
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

    fn declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        self.inner.declarations(file)
    }

    fn materialization_records(
        &self,
        file: &ProjectFile,
    ) -> Vec<crate::analyzer::structural::materialization::MaterializationRecord> {
        self.inner.materialization_records(file)
    }

    fn definitions(&self, fq_name: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        self.inner.definitions(fq_name)
    }

    fn direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.inner.direct_children(code_unit)
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

    fn project(&self) -> &dyn Project {
        self.inner.project()
    }

    fn parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        self.inner.structural_parent_of(code_unit).or_else(|| {
            module_scoped_field_uses_file_name(code_unit)
                .then(|| self.inner.top_level_file_scope_parent_of(code_unit))
                .flatten()
        })
    }

    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        self.module_import_skeleton(code_unit)
            .or_else(|| self.inner.get_skeleton(code_unit))
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        self.module_import_skeleton(code_unit)
            .or_else(|| self.inner.get_skeleton_header(code_unit))
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

    // #1088: every other language wrapper (TypeScript, Ruby, PHP, Go, Python,
    // C#, C++, Java, Rust, Scala) forwards this to the shared
    // `lookup_declarations_by_identifier`; JavaScript never did, so bare-name
    // identifier resolution silently returned nothing for JS delegates and
    // fell through to whatever another language/analyzer's `definitions()`
    // exact-match happened to find (dayjs's `formats`: a JS locale field's
    // bare identifier lookup returned empty, so the TypeScript `ILocale`
    // interface member won by default with no ambiguity ever reported).
    fn lookup_candidates_by_identifier(&self, identifier: &str) -> BTreeSet<CodeUnit> {
        self.inner.lookup_declarations_by_identifier(identifier)
    }
}

impl IAnalyzer for JavascriptAnalyzer {
    #[cfg(any(test, feature = "test-support"))]
    fn test_hooks(&self) -> &dyn crate::analyzer::AnalyzerTestHooks {
        self
    }

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

    fn global_usage_definition_index(&self) -> crate::analyzer::DefinitionIndexHandle<'_> {
        self.inner.global_usage_definition_index()
    }

    fn import_statements(&self, file: &ProjectFile) -> Vec<String> {
        self.inner.import_statements(file)
    }

    fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)> {
        self.inner.compute_cognitive_complexities(file)
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        let inner = self.inner.update(changed_files);
        // Rebuild from root so a changed jsconfig/tsconfig drops its stale parse cache.
        let alias_resolver = Arc::new(AliasResolver::new(inner.project().root().to_path_buf()));
        Self {
            inner,
            memo_budget: self.memo_budget,
            memo_caches: Arc::new(JsTsMemoCaches::new(self.memo_budget)),
            alias_resolver,
        }
    }

    fn update_all(&self) -> Self {
        let inner = self.inner.update_all();
        let alias_resolver = Arc::new(AliasResolver::new(inner.project().root().to_path_buf()));
        Self {
            inner,
            memo_budget: self.memo_budget,
            memo_caches: Arc::new(JsTsMemoCaches::new(self.memo_budget)),
            alias_resolver,
        }
    }

    fn parse_errors(&self, file: &ProjectFile) -> Option<Vec<crate::analyzer::ParseError>> {
        self.inner.parse_errors(file)
    }

    fn semantic_diagnostics(&self, file: &ProjectFile, source: &str) -> Vec<SemanticDiagnostic> {
        collect_javascript_semantic_diagnostics(self, file, source, &self.alias_resolver)
            .into_iter()
            .map(Into::into)
            .collect()
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        self.inner.extract_call_receiver(reference)
    }

    fn is_access_expression(&self, file: &ProjectFile, start_byte: usize, end_byte: usize) -> bool {
        self.inner.is_access_expression(file, start_byte, end_byte)
    }

    fn find_nearest_declaration(
        &self,
        file: &ProjectFile,
        start_byte: usize,
        end_byte: usize,
        ident: &str,
    ) -> Option<crate::analyzer::DeclarationInfo> {
        self.inner
            .find_nearest_declaration(file, start_byte, end_byte, ident)
    }

    fn search_symbol_candidates(
        &self,
        patterns: &crate::analyzer::SearchSymbolPatternBatch,
        cancellation: Option<&crate::CancellationToken>,
    ) -> crate::analyzer::SearchSymbolCandidates {
        self.inner.search_symbol_candidates(patterns, cancellation)
    }

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        Some(self)
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        Some(self)
    }

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
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

    fn contains_tests(&self, file: &ProjectFile) -> bool {
        self.inner.contains_tests(file)
    }

    fn in_test_region(&self, code_unit: &crate::analyzer::CodeUnit) -> bool {
        self.inner.in_test_region(code_unit)
    }

    fn find_test_assertion_smells(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
    ) -> Vec<TestAssertionSmell> {
        if !self.contains_tests(file) || file_language(file) != Language::JavaScript {
            return Vec::new();
        }
        let Ok(source) = self.inner.project().read_source(file) else {
            return Vec::new();
        };
        detect_js_ts_test_assertion_smells(
            file,
            &source,
            tree_sitter_javascript::LANGUAGE.into(),
            &weights,
        )
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
            .filter(|file| file_language(file) == Language::JavaScript)
            .cloned()
            .collect();
        if requested_files.is_empty() {
            return Vec::new();
        }

        let all_candidates: Vec<CloneCandidateProfile> = self
            .get_all_declarations()
            .into_iter()
            .filter(|code_unit| {
                code_unit.is_function()
                    && matches!(file_language(code_unit.source()), Language::JavaScript)
            })
            .filter_map(|code_unit| self.build_clone_candidate_data(&code_unit, weights))
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

#[cfg(any(test, feature = "test-support"))]
impl crate::analyzer::AnalyzerTestHooks for JavascriptAnalyzer {
    fn reset_global_usage_definition_index_build_count_for_test(&self) {
        self.inner
            .test_hooks()
            .reset_global_usage_definition_index_build_count_for_test();
    }

    fn global_usage_definition_index_build_count_for_test(&self) -> usize {
        self.inner
            .test_hooks()
            .global_usage_definition_index_build_count_for_test()
    }

    fn reset_full_declaration_scan_count_for_test(&self) {
        self.inner
            .test_hooks()
            .reset_full_declaration_scan_count_for_test();
    }

    fn full_declaration_scan_count_for_test(&self) -> usize {
        self.inner
            .test_hooks()
            .full_declaration_scan_count_for_test()
    }

    fn reset_candidate_hydration_count_for_test(&self) {
        self.inner.reset_full_hydration_count_for_test();
    }

    fn candidate_hydration_count_for_test(&self) -> usize {
        self.inner.full_hydration_count_for_test() + self.inner.bulk_hydration_count_for_test()
    }

    fn reset_workspace_path_scan_count_for_test(&self) {
        self.inner
            .test_hooks()
            .reset_workspace_path_scan_count_for_test();
    }

    fn workspace_path_scan_count_for_test(&self) -> usize {
        self.inner.test_hooks().workspace_path_scan_count_for_test()
    }
}
impl JavascriptAnalyzer {
    fn build_clone_candidate_data(
        &self,
        code_unit: &CodeUnit,
        weights: CloneSmellWeights,
    ) -> Option<CloneCandidateData> {
        self.get_source(code_unit, false)
            .map(|source| source.trim().to_string())
            .filter(|source| !source.is_empty())
            .and_then(|source| {
                let normalized_tokens =
                    normalized_clone_tokens_js_ts(&source, tree_sitter_javascript::LANGUAGE.into());
                if normalized_tokens.len() < weights.min_normalized_tokens.max(0) as usize {
                    return None;
                }
                Some(CloneCandidateData {
                    unit: code_unit.clone(),
                    normalized_tokens,
                    ast_signature: build_js_ts_clone_ast_signature(
                        &source,
                        tree_sitter_javascript::LANGUAGE.into(),
                    ),
                    excerpt: compact_clone_excerpt(&source),
                })
            })
    }
}
fn visit_js_export(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    if let Some(declaration) = node.child_by_field_name("declaration") {
        match declaration.kind() {
            "class_declaration" => {
                if declaration.child_by_field_name("name").is_none()
                    && js_export_is_default(node, source)
                {
                    visit_js_default_export_class(file, source, node, declaration, parsed);
                } else {
                    record_named_export(
                        source,
                        node,
                        declaration,
                        js_export_is_default(node, source),
                        parsed,
                    );
                    visit_js_class(file, source, node, None, parsed, true);
                }
            }
            "function_declaration" => {
                if declaration.child_by_field_name("name").is_none()
                    && js_export_is_default(node, source)
                {
                    visit_js_default_export_function(file, source, node, declaration, parsed);
                } else {
                    record_named_export(
                        source,
                        node,
                        declaration,
                        js_export_is_default(node, source),
                        parsed,
                    );
                    visit_js_function(file, source, node, None, parsed, true);
                }
            }
            "lexical_declaration" | "variable_declaration" => {
                record_named_declarator_exports(source, node, declaration, parsed);
                visit_js_variable_statement(
                    file,
                    source,
                    node,
                    None,
                    parsed,
                    true,
                    &HashSet::default(),
                );
            }
            _ => {}
        }
    } else if let Some(value) = node.child_by_field_name("value") {
        visit_js_default_export_value(file, source, node, value, parsed);
    }
}

fn js_export_is_default(node: Node<'_>, source: &str) -> bool {
    (0..node.child_count()).any(|index| {
        node.child(index)
            .is_some_and(|child| child.kind() == "default" || node_text(child, source) == "default")
    })
}

fn visit_js_default_export_value(
    file: &ProjectFile,
    source: &str,
    export: Node<'_>,
    value: Node<'_>,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    match value.kind() {
        "arrow_function" | "function_expression" | "generator_function" => {
            visit_js_default_export_function(file, source, export, value, parsed);
        }
        "class" => {
            visit_js_default_export_class(file, source, export, value, parsed);
        }
        "object" => {
            let code_unit = add_default_export_unit(
                file,
                source,
                export,
                crate::analyzer::CodeUnitType::Field,
                parsed,
            );
            parsed.add_signature(code_unit.clone(), trim_statement(node_text(export, source)));
            visit_js_object_literal_properties(file, source, value, &code_unit, &code_unit, parsed);
        }
        // `export default name` points at an existing binding; indexing `default`
        // here would duplicate that declaration instead of describing new code.
        // The export declaration itself is still recorded.
        _ => record_default_reexport(export, parsed),
    }
}

fn visit_js_default_export_function(
    file: &ProjectFile,
    source: &str,
    export: Node<'_>,
    function: Node<'_>,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> CodeUnit {
    let code_unit = add_default_export_unit(
        file,
        source,
        export,
        crate::analyzer::CodeUnitType::Function,
        parsed,
    );
    let (signature, parameter_text) = js_default_export_function_signature(function, source);
    parsed.add_signature_with_metadata(
        code_unit.clone(),
        js_signature_metadata(signature, function, source, &parameter_text),
    );
    visit_js_return_object_literal_properties(
        file, source, function, &code_unit, &code_unit, parsed,
    );
    code_unit
}

fn visit_js_default_export_class(
    file: &ProjectFile,
    source: &str,
    export: Node<'_>,
    class: Node<'_>,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> CodeUnit {
    let code_unit = add_default_export_unit(
        file,
        source,
        export,
        crate::analyzer::CodeUnitType::Class,
        parsed,
    );
    parsed.add_signature(
        code_unit.clone(),
        js_default_export_class_signature(export, source),
    );
    let supertypes = extract_js_supertypes(class, source);
    if !supertypes.is_empty() {
        parsed.set_raw_supertypes(code_unit.clone(), supertypes);
    }
    visit_js_class_body(file, source, class, &code_unit, &code_unit, parsed);
    code_unit
}

fn visit_js_class(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
    exported: bool,
) -> Option<CodeUnit> {
    let definition = if node.kind() == "export_statement" {
        node.child_by_field_name("declaration").unwrap_or(node)
    } else {
        node
    };
    let name_node = definition.child_by_field_name("name")?;
    let name = node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }

    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), name))
        .unwrap_or_else(|| name.to_string());
    let fq = match parent {
        Some(parent) => parent
            .fq()
            .clone()
            .with_pushed(js_ts_segment(name, SegmentKind::Type)),
        None => FqName::new().with_pushed(js_ts_segment(name, SegmentKind::Type)),
    };
    let code_unit = CodeUnit::new_fq(
        file.clone(),
        crate::analyzer::CodeUnitType::Class,
        "",
        short_name,
        fq,
    );
    let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
    let range_node = if exported { node } else { definition };
    parsed.add_code_unit(
        code_unit.clone(),
        range_node,
        source,
        parent.cloned(),
        Some(top_level.clone()),
    );
    parsed.add_signature(
        code_unit.clone(),
        js_class_signature(node, source, exported),
    );
    let supertypes = extract_js_supertypes(definition, source);
    if !supertypes.is_empty() {
        parsed.set_raw_supertypes(code_unit.clone(), supertypes);
    }

    visit_js_class_body(file, source, definition, &code_unit, &top_level, parsed);

    Some(code_unit)
}

fn visit_js_class_body(
    file: &ProjectFile,
    source: &str,
    class: Node<'_>,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let Some(body) = class.child_by_field_name("body") else {
        return;
    };
    for index in 0..body.named_child_count() {
        let Some(child) = body.named_child(index) else {
            continue;
        };
        match child.kind() {
            "method_definition" => visit_js_method(file, source, child, parent, top_level, parsed),
            "field_definition" | "public_field_definition" => {
                visit_js_field(file, source, child, parent, top_level, parsed);
            }
            _ => {}
        }
    }
}

fn visit_js_function(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
    exported: bool,
) -> Option<CodeUnit> {
    let definition = if node.kind() == "export_statement" {
        node.child_by_field_name("declaration").unwrap_or(node)
    } else {
        node
    };
    let name_node = definition.child_by_field_name("name")?;
    let name = node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }

    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), name))
        .unwrap_or_else(|| name.to_string());
    let fq = match parent {
        Some(parent) => parent
            .fq()
            .clone()
            .with_pushed(js_ts_segment(name, SegmentKind::Member)),
        None => FqName::new().with_pushed(js_ts_segment(name, SegmentKind::Member)),
    };
    let code_unit = CodeUnit::new_fq(
        file.clone(),
        crate::analyzer::CodeUnitType::Function,
        "",
        short_name,
        fq,
    );
    let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
    let range_node = if exported { node } else { definition };
    parsed.add_code_unit(
        code_unit.clone(),
        range_node,
        source,
        parent.cloned(),
        Some(top_level.clone()),
    );
    let (signature, parameter_text) = js_function_signature(definition, source, name, exported);
    parsed.add_signature_with_metadata(
        code_unit.clone(),
        js_signature_metadata(signature, definition, source, &parameter_text),
    );
    visit_js_return_object_literal_properties(
        file, source, definition, &code_unit, &top_level, parsed,
    );
    Some(code_unit)
}

fn visit_js_method(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let name = node_text(name_node, source).trim_matches('"').trim();
    if name.is_empty() {
        return;
    }

    let fq = parent
        .fq()
        .clone()
        .with_pushed(js_ts_segment(name, SegmentKind::Member));
    let code_unit = CodeUnit::new_fq(
        file.clone(),
        crate::analyzer::CodeUnitType::Function,
        "",
        format!("{}.{}", parent.short_name(), name),
        fq,
    );
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        Some(parent.clone()),
        Some(top_level.clone()),
    );
    let (signature, parameter_text) = js_method_signature(node, source);
    parsed.add_signature_with_metadata(
        code_unit,
        js_signature_metadata(signature, node, source, &parameter_text),
    );
    if name == "constructor" {
        visit_js_constructor_assigned_fields(file, source, node, parent, top_level, parsed);
    }
}

fn visit_js_constructor_assigned_fields(
    file: &ProjectFile,
    source: &str,
    constructor: Node<'_>,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let mut stack = vec![constructor];
    while let Some(node) = stack.pop() {
        if node.id() != constructor.id()
            && matches!(
                node.kind(),
                "function_declaration"
                    | "function_expression"
                    | "arrow_function"
                    | "method_definition"
                    | "class_declaration"
                    | "class"
            )
        {
            continue;
        }
        if node.kind() == "assignment_expression"
            && let Some(left) = node.child_by_field_name("left")
            && let Some(property) = this_member_property(left, source)
        {
            let Some(name) = property_name_text(property, source) else {
                continue;
            };
            let fq = parent
                .fq()
                .clone()
                .with_pushed(js_ts_segment(&name, SegmentKind::Member));
            let code_unit = CodeUnit::new_fq(
                file.clone(),
                crate::analyzer::CodeUnitType::Field,
                "",
                format!("{}.{}", parent.short_name(), name),
                fq,
            );
            parsed.add_code_unit(
                code_unit.clone(),
                property,
                source,
                Some(parent.clone()),
                Some(top_level.clone()),
            );
            parsed.add_signature(code_unit, trim_statement(node_text(node, source)));
            continue;
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
}

fn visit_js_field(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let name = node_text(name_node, source).trim_matches('"').trim();
    if name.is_empty() {
        return;
    }
    let fq = parent
        .fq()
        .clone()
        .with_pushed(js_ts_segment(name, SegmentKind::Member));
    let code_unit = CodeUnit::new_fq(
        file.clone(),
        crate::analyzer::CodeUnitType::Field,
        "",
        format!("{}.{}", parent.short_name(), name),
        fq,
    );
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        Some(parent.clone()),
        Some(top_level.clone()),
    );
    parsed.add_signature(code_unit, trim_statement(node_text(node, source)));
}

fn visit_js_variable_statement(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
    exported: bool,
    exported_roots: &HashSet<String>,
) {
    let definition = if node.kind() == "export_statement" {
        node.child_by_field_name("declaration").unwrap_or(node)
    } else {
        node
    };
    for index in 0..definition.named_child_count() {
        let Some(child) = definition.named_child(index) else {
            continue;
        };
        if child.kind() != "variable_declarator" {
            continue;
        }
        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };
        if matches!(name_node.kind(), "object_pattern" | "array_pattern") {
            let signature = js_variable_signature(definition, child, source, exported);
            let range_node = if exported { node } else { definition };
            add_destructured_binder_units(
                file, source, name_node, range_node, parent, &signature, parsed,
            );
            continue;
        }
        let name = node_text(name_node, source).trim();
        if name.is_empty() {
            continue;
        }

        let value = child.child_by_field_name("value");
        let is_function = value
            .map(|value| matches!(value.kind(), "arrow_function" | "function_expression"))
            .unwrap_or(false);
        let module_surface = parent.is_none()
            && (exported || exported_roots.contains(name))
            && value.is_some_and(|value| js_initializer_has_surface_shape(value, source));
        let kind = if is_function {
            crate::analyzer::CodeUnitType::Function
        } else {
            crate::analyzer::CodeUnitType::Field
        };
        let short_name = if kind == crate::analyzer::CodeUnitType::Field {
            if let Some(parent) = parent {
                format!("{}.{}", parent.short_name(), name)
            } else {
                file_scoped_field_name(file, name)
            }
        } else {
            parent
                .map(|parent| format!("{}.{}", parent.short_name(), name))
                .unwrap_or_else(|| name.to_string())
        };
        // Mirrors `short_name` above segment-for-segment: a Field with no
        // enclosing scope is qualified by the file-name `Path` prefix (the
        // structured counterpart of `file_scoped_field_name`); every other
        // case is a plain `Member` off the parent's `fq` or a fresh chain.
        let fq = if kind == crate::analyzer::CodeUnitType::Field {
            match parent {
                Some(parent) => parent
                    .fq()
                    .clone()
                    .with_pushed(js_ts_segment(name, SegmentKind::Member)),
                None => file_scoped_field_fq(file, name),
            }
        } else {
            match parent {
                Some(parent) => parent
                    .fq()
                    .clone()
                    .with_pushed(js_ts_segment(name, SegmentKind::Member)),
                None => FqName::new().with_pushed(js_ts_segment(name, SegmentKind::Member)),
            }
        };
        let code_unit = CodeUnit::new_fq(file.clone(), kind, "", short_name, fq);
        let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
        let range_node = if exported { node } else { definition };
        parsed.add_code_unit(
            code_unit.clone(),
            range_node,
            source,
            parent.cloned(),
            Some(top_level.clone()),
        );
        let variable_signature = if is_function {
            let (signature, parameter_text) =
                js_variable_function_signature(definition, child, source, name, exported);
            if let Some(value) = value {
                parsed.add_signature_with_metadata(
                    code_unit.clone(),
                    js_signature_metadata(signature.clone(), value, source, &parameter_text),
                );
            } else {
                parsed.add_signature(code_unit.clone(), signature.clone());
            }
            if let Some(value) = value {
                visit_js_return_object_literal_properties(
                    file, source, value, &code_unit, &top_level, parsed,
                );
            }
            signature
        } else {
            let signature = js_variable_signature(definition, child, source, exported);
            parsed.add_signature(code_unit.clone(), signature.clone());
            signature
        };
        let indexable_object = if !is_function {
            value.and_then(|value| js_indexable_object_literal_value(value, source, module_surface))
        } else {
            None
        };
        if let Some(object) = indexable_object {
            visit_js_object_literal_properties(
                file, source, object, &code_unit, &top_level, parsed,
            );
        }
        if module_surface && kind == crate::analyzer::CodeUnitType::Field && parent.is_none() {
            let surface_fq = FqName::new().with_pushed(js_ts_segment(name, SegmentKind::Member));
            let surface_code_unit = CodeUnit::new_fq(
                file.clone(),
                crate::analyzer::CodeUnitType::Field,
                "",
                name,
                surface_fq,
            );
            parsed.add_code_unit(
                surface_code_unit.clone(),
                range_node,
                source,
                None,
                Some(surface_code_unit.clone()),
            );
            parsed.add_signature(surface_code_unit.clone(), variable_signature);
            if let Some(object) = indexable_object {
                visit_js_object_literal_properties_for_surface(
                    file,
                    source,
                    object,
                    &surface_code_unit,
                    &surface_code_unit,
                    parsed,
                    JsAssignmentSymbolSurface::DefinitionLookupOnly,
                );
            }
        }
    }
}

fn visit_js_object_literal_properties(
    file: &ProjectFile,
    source: &str,
    object: Node<'_>,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    visit_js_object_literal_properties_for_surface(
        file,
        source,
        object,
        parent,
        top_level,
        parsed,
        JsAssignmentSymbolSurface::Declaration,
    );
}

fn visit_js_object_literal_properties_for_surface(
    file: &ProjectFile,
    source: &str,
    object: Node<'_>,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
    surface: JsAssignmentSymbolSurface,
) {
    for index in 0..object.named_child_count() {
        let Some(child) = object.named_child(index) else {
            continue;
        };
        let Some(name) = js_object_literal_property_name(child, source) else {
            continue;
        };
        let kind = js_object_literal_property_kind(child);
        let fq = parent
            .fq()
            .clone()
            .with_pushed(js_ts_segment(&name, SegmentKind::Member));
        let code_unit = CodeUnit::new_fq(
            file.clone(),
            kind,
            "",
            format!("{}.{}", parent.short_name(), name),
            fq,
        );
        match surface {
            JsAssignmentSymbolSurface::Declaration => {
                parsed.add_code_unit(
                    code_unit.clone(),
                    child,
                    source,
                    Some(parent.clone()),
                    Some(top_level.clone()),
                );
            }
            JsAssignmentSymbolSurface::DefinitionLookupOnly => {
                parsed.add_definition_lookup_unit(code_unit.clone(), child, source);
            }
        }
        parsed.add_signature(code_unit, trim_statement(node_text(child, source)));
    }
}

fn visit_js_module_exports_object_literal_properties(
    file: &ProjectFile,
    source: &str,
    object: Node<'_>,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    for index in 0..object.named_child_count() {
        let Some(child) = object.named_child(index) else {
            continue;
        };
        let Some(name) = js_object_literal_property_name(child, source) else {
            continue;
        };
        if js_module_exports_property_is_reference(child) {
            // A reference property re-exports an existing local declaration;
            // it is an export row but materializes no declaration of its own.
            parsed.record_materialization(MaterializationRecord::Export {
                range: crate::analyzer::tree_sitter_analyzer::node_range(child),
                form: ExportForm::CommonJsMember,
                exported_name: name,
                target: None,
            });
            continue;
        }
        let kind = js_object_literal_property_kind(child);
        let fq = FqName::new().with_pushed(js_ts_segment(&name, SegmentKind::Member));
        let code_unit = CodeUnit::new_fq(file.clone(), kind, "", name.clone(), fq);
        parsed.add_code_unit(
            code_unit.clone(),
            child,
            source,
            None,
            Some(code_unit.clone()),
        );
        parsed.record_materialization(MaterializationRecord::Export {
            range: crate::analyzer::tree_sitter_analyzer::node_range(child),
            form: ExportForm::CommonJsMember,
            exported_name: name,
            target: Some(code_unit.clone()),
        });
        parsed.add_signature(code_unit, trim_statement(node_text(child, source)));
    }
}

/// Whether a `module.exports = { ... }` property re-exports an existing local
/// declaration (shorthand `{ makeWidget }` or `{ name: localBinding }`) rather
/// than defining a value in place. Reference properties must not become
/// declarations of their own: the export index already maps them to the real
/// local declaration, and a duplicate top-level CodeUnit at the export site
/// makes definition lookup for the exported name ambiguous.
fn js_module_exports_property_is_reference(node: Node<'_>) -> bool {
    match node.kind() {
        "shorthand_property_identifier" => true,
        "pair" => node
            .child_by_field_name("value")
            .is_some_and(|value| matches!(value.kind(), "identifier" | "member_expression")),
        _ => false,
    }
}

fn js_object_literal_property_kind(node: Node<'_>) -> crate::analyzer::CodeUnitType {
    if node.kind() == "method_definition"
        || node
            .child_by_field_name("value")
            .is_some_and(|value| matches!(value.kind(), "arrow_function" | "function_expression"))
    {
        crate::analyzer::CodeUnitType::Function
    } else {
        crate::analyzer::CodeUnitType::Field
    }
}

fn js_object_literal_property_name(node: Node<'_>, source: &str) -> Option<String> {
    let key = match node.kind() {
        "pair" => node
            .child_by_field_name("key")
            .or_else(|| node.named_child(0))?,
        "shorthand_property_identifier" => node,
        "method_definition" => node.child_by_field_name("name")?,
        _ => return None,
    };
    if key.kind() == "computed_property_name" {
        return None;
    }
    let name = node_text(key, source)
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_string();
    (!name.is_empty()).then_some(name)
}

fn js_exported_binding_roots(root: Node<'_>, source: &str) -> HashSet<String> {
    let mut roots = js_commonjs_exported_roots(root, source);
    roots.extend(js_es_named_exported_roots(root, source));
    roots
}

fn js_es_named_exported_roots(root: Node<'_>, source: &str) -> HashSet<String> {
    let mut roots = HashSet::default();
    for index in 0..root.named_child_count() {
        let Some(child) = root.named_child(index) else {
            continue;
        };
        if child.kind() != "export_statement" || child.child_by_field_name("source").is_some() {
            continue;
        }
        let mut cursor = child.walk();
        for export_child in child.named_children(&mut cursor) {
            collect_js_export_clause_roots(export_child, source, &mut roots);
        }
    }
    roots
}

fn collect_js_export_clause_roots(node: Node<'_>, source: &str, roots: &mut HashSet<String>) {
    match node.kind() {
        "export_clause" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                collect_js_export_clause_roots(child, source, roots);
            }
        }
        "export_specifier" => {
            let name = node
                .child_by_field_name("name")
                .or_else(|| node.named_child(0));
            if let Some(name) = name {
                collect_js_export_identifier(name, source, roots);
            }
        }
        _ => {}
    }
}

fn collect_js_export_identifier(node: Node<'_>, source: &str, roots: &mut HashSet<String>) {
    if matches!(
        node.kind(),
        "identifier" | "property_identifier" | "shorthand_property_identifier"
    ) {
        let name = node_text(node, source).trim();
        if !name.is_empty() {
            roots.insert(name.to_string());
        }
    }
}

fn js_indexable_object_literal_value<'tree>(
    value: Node<'tree>,
    source: &str,
    include_factory_call: bool,
) -> Option<Node<'tree>> {
    js_object_literal_value(value)
        .or_else(|| js_surface_call_object_argument(value, source, include_factory_call))
}

fn js_initializer_has_surface_shape(value: Node<'_>, source: &str) -> bool {
    js_indexable_object_literal_value(value, source, true).is_some()
}

fn js_object_literal_value(node: Node<'_>) -> Option<Node<'_>> {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "object" => return Some(node),
            "parenthesized_expression" => {
                for index in (0..node.named_child_count()).rev() {
                    if let Some(child) = node.named_child(index) {
                        stack.push(child);
                    }
                }
            }
            _ => {}
        }
    }
    None
}

fn js_surface_call_object_argument<'tree>(
    call: Node<'tree>,
    source: &str,
    include_factory_call: bool,
) -> Option<Node<'tree>> {
    if call.kind() != "call_expression" {
        return None;
    }
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .enumerate()
        .find_map(|(index, argument)| {
            let object = js_object_literal_value(argument)?;
            // The schema-builder shortcut (e.g. zod's `z.object({...})`) applies
            // regardless of export/surface status, matching TS's
            // `ts_call_preserves_object_argument_shape` (issue #1167, gap 3). The
            // broader factory-name heuristic below stays surface-gated, unchanged
            // from before.
            let preserves = (index == 0 && call_is_schema_object_builder(call, source))
                || (include_factory_call
                    && js_call_preserves_object_argument_shape(call, source, index));
            preserves.then_some(object)
        })
}

fn js_call_preserves_object_argument_shape(
    call: Node<'_>,
    source: &str,
    argument_index: usize,
) -> bool {
    match js_call_object_argument_shape_preservation(call, source, argument_index) {
        JsShapePreservation::Preserves => true,
        JsShapePreservation::DoesNotPreserve => false,
        JsShapePreservation::Unknown => call_has_likely_surface_factory_name(call, source),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JsShapePreservation {
    Preserves,
    DoesNotPreserve,
    Unknown,
}

fn js_call_object_argument_shape_preservation(
    call: Node<'_>,
    source: &str,
    argument_index: usize,
) -> JsShapePreservation {
    let Some(callee_name) = call_identifier_name(call, source) else {
        return JsShapePreservation::Unknown;
    };
    js_source_function_preserves_parameter_shape(call, source, &callee_name, argument_index)
}

fn js_source_function_preserves_parameter_shape(
    anchor: Node<'_>,
    source: &str,
    function_name: &str,
    parameter_index: usize,
) -> JsShapePreservation {
    let root = root_node(anchor);
    let mut functions = Vec::new();
    collect_function_nodes(root, source, function_name, &mut functions);
    if functions.is_empty() {
        return JsShapePreservation::Unknown;
    }
    if functions.into_iter().any(|function| {
        js_function_node_preserves_parameter_shape(function, source, parameter_index)
    }) {
        JsShapePreservation::Preserves
    } else {
        JsShapePreservation::DoesNotPreserve
    }
}

fn js_function_node_preserves_parameter_shape(
    function: Node<'_>,
    source: &str,
    parameter_index: usize,
) -> bool {
    let Some(parameter_name) = js_function_parameter_name(function, source, parameter_index) else {
        return false;
    };
    if function.kind() == "arrow_function"
        && let Some(body) = function.child_by_field_name("body")
        && js_expression_preserves_parameter_shape(body, source, &parameter_name)
    {
        return true;
    }
    js_function_returns_parameter_shape(function, function.id(), source, &parameter_name)
}

fn js_function_parameter_name(
    function: Node<'_>,
    source: &str,
    parameter_index: usize,
) -> Option<String> {
    let parameters = function.child_by_field_name("parameters")?;
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .filter_map(js_parameter_label_node)
        .nth(parameter_index)
        .map(|name| node_text(name, source).trim().to_string())
        .filter(|name| !name.is_empty())
}

fn js_function_returns_parameter_shape(
    node: Node<'_>,
    root_id: usize,
    source: &str,
    parameter_name: &str,
) -> bool {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.id() != root_id
            && matches!(
                node.kind(),
                "function_declaration"
                    | "function_expression"
                    | "arrow_function"
                    | "method_definition"
                    | "class_declaration"
                    | "class"
            )
        {
            continue;
        }
        if node.kind() == "return_statement" {
            let mut cursor = node.walk();
            if node
                .named_children(&mut cursor)
                .next()
                .is_some_and(|expression| {
                    js_expression_preserves_parameter_shape(expression, source, parameter_name)
                })
            {
                return true;
            }
            continue;
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    false
}

fn js_expression_preserves_parameter_shape(
    expression: Node<'_>,
    source: &str,
    parameter_name: &str,
) -> bool {
    if matches!(expression.kind(), "identifier" | "property_identifier")
        && node_text(expression, source).trim() == parameter_name
    {
        return true;
    }
    if expression.kind() != "object" {
        return false;
    }
    let mut cursor = expression.walk();
    expression.named_children(&mut cursor).any(|child| {
        child.kind() == "spread_element"
            && child
                .named_child(0)
                .is_some_and(|spread| node_text(spread, source).trim() == parameter_name)
    })
}

fn visit_js_return_object_literal_properties(
    file: &ProjectFile,
    source: &str,
    function: Node<'_>,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let mut objects = Vec::new();
    collect_js_return_object_literals(function, function.id(), &mut objects);
    for object in objects {
        visit_js_object_literal_properties(file, source, object, parent, top_level, parsed);
    }
}

fn collect_js_return_object_literals<'tree>(
    node: Node<'tree>,
    root_id: usize,
    out: &mut Vec<Node<'tree>>,
) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.id() != root_id
            && matches!(
                node.kind(),
                "function_declaration"
                    | "function_expression"
                    | "arrow_function"
                    | "method_definition"
                    | "class_declaration"
                    | "class"
            )
        {
            continue;
        }

        if node.kind() == "return_statement" {
            let mut cursor = node.walk();
            if let Some(object) = node
                .named_children(&mut cursor)
                .find_map(js_object_literal_value)
            {
                out.push(object);
            }
            continue;
        }

        if node.kind() == "arrow_function"
            && let Some(body) = node.child_by_field_name("body")
            && let Some(object) = js_object_literal_value(body)
        {
            out.push(object);
        }

        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
}

fn js_signature_metadata(
    signature: String,
    function: Node<'_>,
    source: &str,
    parameter_text: &str,
) -> SignatureMetadata {
    let Some(parameters_start) = signature.find(parameter_text) else {
        return SignatureMetadata::new(signature, Vec::new());
    };
    let parameters_end = parameters_start + parameter_text.len();
    let mut search_start = parameters_start;
    let parameters = js_parameter_label_nodes(function)
        .into_iter()
        .filter_map(|node| {
            let label = node_text(node, source).trim();
            if label.is_empty() || search_start > parameters_end {
                return None;
            }
            let haystack = signature.get(search_start..parameters_end)?;
            let relative_start = haystack.find(label)?;
            let start_byte = search_start + relative_start;
            let end_byte = start_byte + label.len();
            search_start = end_byte;
            Some(ParameterMetadata::new(label, start_byte, end_byte))
        })
        .collect();
    SignatureMetadata::new(signature, parameters)
}

fn js_rendered_parameter_text(function: Node<'_>, source: &str) -> String {
    if let Some(parameters) = function.child_by_field_name("parameters") {
        return node_text(parameters, source).trim().to_string();
    }
    function
        .child_by_field_name("parameter")
        .map(|parameter| format!("({})", node_text(parameter, source).trim()))
        .unwrap_or_else(|| "()".to_string())
}

fn js_parameter_label_nodes(function: Node<'_>) -> Vec<Node<'_>> {
    if let Some(parameters) = function.child_by_field_name("parameters") {
        let mut cursor = parameters.walk();
        return parameters
            .named_children(&mut cursor)
            .filter_map(js_parameter_label_node)
            .collect();
    }
    function
        .child_by_field_name("parameter")
        .and_then(js_parameter_label_node)
        .into_iter()
        .collect()
}

fn js_parameter_label_node(parameter: Node<'_>) -> Option<Node<'_>> {
    match parameter.kind() {
        "identifier" | "shorthand_property_identifier_pattern" => Some(parameter),
        "assignment_pattern" => parameter.child_by_field_name("left"),
        "rest_pattern" => parameter.named_child(0).or(Some(parameter)),
        "object_pattern" | "array_pattern" => Some(parameter),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JsAssignmentBindingKind {
    PlainLocal,
    DeclarationRoot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JsAssignmentScopeKind {
    Function,
    Block,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JsAssignmentSymbolSurface {
    Declaration,
    DefinitionLookupOnly,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct JsMemberAssignmentTarget {
    name: String,
    /// Structured counterpart to `name`, built segment-for-segment alongside
    /// it (see `js_member_assignment_target`): every link in the
    /// `object.property` chain is a `Member` segment, mirroring the `.`-joined
    /// `name` string exactly.
    fq: FqName,
    surface: JsAssignmentSymbolSurface,
}

struct JsAssignmentScope {
    kind: JsAssignmentScopeKind,
    bindings: HashMap<String, JsAssignmentBindingKind>,
}

impl JsAssignmentScope {
    fn new(kind: JsAssignmentScopeKind) -> Self {
        Self {
            kind,
            bindings: HashMap::default(),
        }
    }
}

struct JsAssignmentDeclarationState {
    scopes: Vec<JsAssignmentScope>,
    commonjs_exported_roots: HashSet<String>,
    commonjs_exported_members: HashSet<String>,
}

impl JsAssignmentDeclarationState {
    fn new(
        commonjs_exported_roots: HashSet<String>,
        commonjs_exported_members: HashSet<String>,
    ) -> Self {
        Self {
            scopes: vec![JsAssignmentScope::new(JsAssignmentScopeKind::Function)],
            commonjs_exported_roots,
            commonjs_exported_members,
        }
    }

    fn enter_scope(&mut self, kind: JsAssignmentScopeKind) {
        self.scopes.push(JsAssignmentScope::new(kind));
    }

    fn exit_scope(&mut self) {
        if self.scopes.len() > 1 {
            self.scopes.pop();
        }
    }

    fn declare_current(&mut self, name: &str, kind: JsAssignmentBindingKind) {
        if name.is_empty() {
            return;
        }
        if let Some(scope) = self.scopes.last_mut() {
            scope.bindings.insert(name.to_string(), kind);
        }
    }

    fn declare_function_scoped(&mut self, name: &str, kind: JsAssignmentBindingKind) {
        if name.is_empty() {
            return;
        }
        if let Some(scope) = self
            .scopes
            .iter_mut()
            .rev()
            .find(|scope| scope.kind == JsAssignmentScopeKind::Function)
        {
            scope.bindings.insert(name.to_string(), kind);
        }
    }

    fn binding_of(&self, name: &str) -> Option<JsAssignmentBindingKind> {
        self.scopes
            .iter()
            .rev()
            .find_map(|scope| scope.bindings.get(name).copied())
    }

    fn binding_kind_for_declarator(
        &self,
        name: &str,
        declarator: Node<'_>,
        source: &str,
    ) -> JsAssignmentBindingKind {
        if self.commonjs_exported_roots.contains(name)
            || declarator
                .child_by_field_name("value")
                .is_some_and(|value| {
                    js_assignment_value_is_declaration_root(value)
                        || js_assignment_value_exports_commonjs_root(value, source)
                })
        {
            JsAssignmentBindingKind::DeclarationRoot
        } else {
            JsAssignmentBindingKind::PlainLocal
        }
    }
}

fn visit_js_assignment_declarations(
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let mut state = JsAssignmentDeclarationState::new(
        js_commonjs_exported_roots(root, source),
        js_commonjs_exported_members(root, source),
    );
    let mut stack = vec![JsAssignmentWalkFrame::Enter(root)];

    while let Some(frame) = stack.pop() {
        match frame {
            JsAssignmentWalkFrame::Enter(node) => {
                register_js_assignment_declaration_name(node, source, &mut state);
                let scope = js_assignment_scope_kind(node);
                if let Some(scope) = scope {
                    state.enter_scope(scope);
                    register_js_assignment_parameters(node, source, &mut state);
                }
                register_js_assignment_variable(node, source, &mut state);
                if node.kind() == "assignment_expression" {
                    visit_js_assignment_expression(file, source, node, parsed, &state);
                }
                if scope.is_some() {
                    stack.push(JsAssignmentWalkFrame::Exit);
                }
                for index in (0..node.named_child_count()).rev() {
                    if let Some(child) = node.named_child(index) {
                        stack.push(JsAssignmentWalkFrame::Enter(child));
                    }
                }
            }
            JsAssignmentWalkFrame::Exit => state.exit_scope(),
        }
    }
}

enum JsAssignmentWalkFrame<'tree> {
    Enter(Node<'tree>),
    Exit,
}

fn js_assignment_scope_kind(node: Node<'_>) -> Option<JsAssignmentScopeKind> {
    match node.kind() {
        "function_declaration"
        | "function_expression"
        | "generator_function"
        | "arrow_function"
        | "method_definition" => Some(JsAssignmentScopeKind::Function),
        "statement_block" => Some(JsAssignmentScopeKind::Block),
        _ => None,
    }
}

fn register_js_assignment_declaration_name(
    node: Node<'_>,
    source: &str,
    state: &mut JsAssignmentDeclarationState,
) {
    if !matches!(node.kind(), "class_declaration" | "function_declaration") {
        return;
    }
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    state.declare_current(
        node_text(name, source).trim(),
        JsAssignmentBindingKind::DeclarationRoot,
    );
}

fn register_js_assignment_parameters(
    node: Node<'_>,
    source: &str,
    state: &mut JsAssignmentDeclarationState,
) {
    let mut names = Vec::new();
    if let Some(parameters) = node.child_by_field_name("parameters") {
        collect_js_assignment_binding_names(parameters, source, &mut names);
    }
    if let Some(parameter) = node.child_by_field_name("parameter") {
        collect_js_assignment_binding_names(parameter, source, &mut names);
    }
    for name in names {
        state.declare_current(&name, JsAssignmentBindingKind::PlainLocal);
    }
}

fn register_js_assignment_variable(
    node: Node<'_>,
    source: &str,
    state: &mut JsAssignmentDeclarationState,
) {
    if node.kind() != "variable_declarator" {
        return;
    }
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let mut names = Vec::new();
    collect_js_assignment_binding_names(name_node, source, &mut names);
    let parent_kind = node.parent().map(|parent| parent.kind());
    for name in names {
        let kind = state.binding_kind_for_declarator(&name, node, source);
        if parent_kind == Some("variable_declaration") {
            state.declare_function_scoped(&name, kind);
        } else {
            state.declare_current(&name, kind);
        }
    }
}

fn collect_js_assignment_binding_names(node: Node<'_>, source: &str, names: &mut Vec<String>) {
    match node.kind() {
        "identifier" | "shorthand_property_identifier_pattern" => {
            let name = node_text(node, source).trim();
            if !name.is_empty() {
                names.push(name.to_string());
            }
            return;
        }
        "assignment_pattern" => {
            if let Some(left) = node.child_by_field_name("left") {
                collect_js_assignment_binding_names(left, source, names);
            }
            return;
        }
        "rest_pattern" => {
            if let Some(child) = node.named_child(0) {
                collect_js_assignment_binding_names(child, source, names);
            }
            return;
        }
        _ => {}
    }
    for index in 0..node.named_child_count() {
        if let Some(child) = node.named_child(index) {
            collect_js_assignment_binding_names(child, source, names);
        }
    }
}

fn js_assignment_value_is_declaration_root(value: Node<'_>) -> bool {
    matches!(
        value.kind(),
        "arrow_function" | "function_expression" | "generator_function" | "class"
    )
}

fn js_assignment_value_exports_commonjs_root(value: Node<'_>, source: &str) -> bool {
    if value.kind() != "assignment_expression" {
        return false;
    }
    if value
        .child_by_field_name("left")
        .is_some_and(|left| js_is_commonjs_export_assignment_target(left, source))
    {
        return true;
    }
    value
        .child_by_field_name("right")
        .is_some_and(|right| js_assignment_value_exports_commonjs_root(right, source))
}

fn visit_js_assignment_expression(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
    state: &JsAssignmentDeclarationState,
) {
    let Some(left) = node.child_by_field_name("left") else {
        return;
    };
    let value = node.child_by_field_name("right");
    if js_is_commonjs_root_export_assignment_target(left, source)
        && let Some(value) = value
        && let Some(object) = js_object_literal_value(value)
    {
        parsed.record_materialization(MaterializationRecord::Export {
            range: crate::analyzer::tree_sitter_analyzer::node_range(node),
            form: ExportForm::CommonJsRoot,
            exported_name: "module.exports".to_string(),
            target: None,
        });
        visit_js_module_exports_object_literal_properties(file, source, object, parsed);
        return;
    }
    let value_is_function =
        value.is_some_and(|value| matches!(value.kind(), "arrow_function" | "function_expression"));
    let Some(target) = js_commonjs_export_assignment_name(left, value, source)
        .map(|name| {
            let fq = FqName::new().with_pushed(js_ts_segment(&name, SegmentKind::Member));
            JsMemberAssignmentTarget {
                name,
                fq,
                surface: JsAssignmentSymbolSurface::Declaration,
            }
        })
        .or_else(|| js_member_assignment_target(left, source, state))
    else {
        return;
    };
    let kind = if value_is_function {
        crate::analyzer::CodeUnitType::Function
    } else {
        crate::analyzer::CodeUnitType::Field
    };
    let code_unit = CodeUnit::new_fq(file.clone(), kind, "", target.name, target.fq);
    add_js_assignment_code_unit(parsed, target.surface, code_unit.clone(), node, source);
    let (signature, parameter_text) = js_assignment_signature(node, left, value, source);
    if let Some(value) = value.filter(|_| value_is_function) {
        parsed.add_signature_with_metadata(
            code_unit.clone(),
            js_signature_metadata(signature, value, source, &parameter_text),
        );
        visit_js_return_object_literal_properties(
            file, source, value, &code_unit, &code_unit, parsed,
        );
    } else {
        parsed.add_signature(code_unit.clone(), signature);
    }
    if !value_is_function
        && let Some(value) = value
        && let Some(object) = js_indexable_object_literal_value(value, source, true)
    {
        visit_js_object_literal_properties_for_surface(
            file,
            source,
            object,
            &code_unit,
            &code_unit,
            parsed,
            target.surface,
        );
    }
}

fn add_js_assignment_code_unit(
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
    surface: JsAssignmentSymbolSurface,
    code_unit: CodeUnit,
    node: Node<'_>,
    source: &str,
) {
    match surface {
        JsAssignmentSymbolSurface::Declaration => {
            parsed.add_code_unit(code_unit.clone(), node, source, None, Some(code_unit));
        }
        JsAssignmentSymbolSurface::DefinitionLookupOnly => {
            parsed.add_definition_lookup_unit(code_unit, node, source);
        }
    }
}

fn js_commonjs_export_assignment_name(
    left: Node<'_>,
    value: Option<Node<'_>>,
    source: &str,
) -> Option<String> {
    let exposes_surface = value.is_some_and(|value| {
        matches!(value.kind(), "arrow_function" | "function_expression")
            || js_initializer_has_surface_shape(value, source)
    });
    if !exposes_surface {
        return None;
    }
    let property = js_commonjs_export_assignment_property(left, source)?;
    (!property.is_empty()).then_some(property)
}

fn js_commonjs_export_assignment_property(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() != "member_expression" {
        return None;
    }
    let object = node.child_by_field_name("object")?;
    let property = node.child_by_field_name("property")?;
    if property.kind() == "computed_property_name" {
        return None;
    }
    let property_name = node_text(property, source)
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_string();

    if node_text(object, source).trim() == "exports" || js_is_module_exports_object(object, source)
    {
        return Some(property_name);
    }

    None
}

fn js_member_assignment_target(
    node: Node<'_>,
    source: &str,
    state: &JsAssignmentDeclarationState,
) -> Option<JsMemberAssignmentTarget> {
    if node.kind() != "member_expression" {
        return None;
    }
    if js_is_commonjs_export_assignment_target(node, source) {
        return None;
    }
    let object = node.child_by_field_name("object")?;
    let property = node.child_by_field_name("property")?;
    if property.kind() == "computed_property_name" {
        return None;
    }
    let (object_name, object_fq) = match object.kind() {
        "identifier" | "property_identifier" => {
            let object_name = node_text(object, source).trim().to_string();
            let object_fq =
                FqName::new().with_pushed(js_ts_segment(&object_name, SegmentKind::Member));
            (object_name, object_fq)
        }
        "member_expression" => {
            let nested = js_member_assignment_target(object, source, state)?;
            (nested.name, nested.fq)
        }
        _ => return None,
    };
    let property_name = node_text(property, source)
        .trim()
        .trim_matches('"')
        .trim_matches('\'');
    if object_name.is_empty() || property_name.is_empty() {
        return None;
    }
    let name = format!("{object_name}.{property_name}");
    let fq = object_fq.with_pushed(js_ts_segment(property_name, SegmentKind::Member));
    let surface = if state.commonjs_exported_members.contains(&name) {
        JsAssignmentSymbolSurface::Declaration
    } else if js_member_assignment_has_plain_local_root(node, source, state) {
        JsAssignmentSymbolSurface::DefinitionLookupOnly
    } else {
        JsAssignmentSymbolSurface::Declaration
    };
    Some(JsMemberAssignmentTarget { name, fq, surface })
}

fn js_member_assignment_has_plain_local_root(
    node: Node<'_>,
    source: &str,
    state: &JsAssignmentDeclarationState,
) -> bool {
    let Some(root) = js_member_expression_root_identifier(node, source) else {
        return false;
    };
    state.binding_of(root) == Some(JsAssignmentBindingKind::PlainLocal)
}

fn js_member_expression_root_identifier<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    match node.kind() {
        "identifier" | "property_identifier" => {
            let text = node_text(node, source).trim();
            (!text.is_empty()).then_some(text)
        }
        "member_expression" => node
            .child_by_field_name("object")
            .and_then(|object| js_member_expression_root_identifier(object, source)),
        _ => None,
    }
}

fn js_commonjs_exported_roots(root: Node<'_>, source: &str) -> HashSet<String> {
    let mut roots = HashSet::default();
    walk_named_tree_preorder(root, true, |node| {
        if node.kind() == "assignment_expression"
            && let Some(left) = node.child_by_field_name("left")
            && js_is_commonjs_root_or_property_export_assignment_target(left, source)
            && let Some(right) = node.child_by_field_name("right")
            && let Some(root) = js_commonjs_exported_root_identifier(right, source)
        {
            roots.insert(root.to_string());
        }
        WalkControl::Continue
    });
    roots
}

fn js_commonjs_exported_members(root: Node<'_>, source: &str) -> HashSet<String> {
    let mut members = HashSet::default();
    walk_named_tree_preorder(root, true, |node| {
        if node.kind() == "assignment_expression"
            && let Some(left) = node.child_by_field_name("left")
            && js_is_commonjs_export_assignment_target(left, source)
            && let Some(right) = node.child_by_field_name("right")
            && let Some(member) = js_member_expression_name(right, source)
        {
            members.insert(member);
        }
        WalkControl::Continue
    });
    members
}

fn js_member_expression_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "property_identifier" => {
            let text = node_text(node, source).trim();
            (!text.is_empty()).then(|| text.to_string())
        }
        "member_expression" => {
            let object = node.child_by_field_name("object")?;
            let property = node.child_by_field_name("property")?;
            if property.kind() == "computed_property_name" {
                return None;
            }
            let object_name = js_member_expression_name(object, source)?;
            let property_name = node_text(property, source)
                .trim()
                .trim_matches('"')
                .trim_matches('\'');
            (!object_name.is_empty() && !property_name.is_empty())
                .then(|| format!("{object_name}.{property_name}"))
        }
        _ => None,
    }
}

fn js_commonjs_exported_root_identifier<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    if matches!(node.kind(), "identifier" | "property_identifier") {
        let text = node_text(node, source).trim();
        (!text.is_empty()).then_some(text)
    } else {
        None
    }
}

fn js_is_commonjs_root_export_assignment_target(node: Node<'_>, source: &str) -> bool {
    let text = node_text(node, source).trim();
    text == "exports" || text == "module.exports"
}

fn js_is_commonjs_root_or_property_export_assignment_target(node: Node<'_>, source: &str) -> bool {
    js_is_commonjs_root_export_assignment_target(node, source)
        || js_commonjs_export_assignment_property(node, source).is_some()
}

fn js_is_commonjs_export_assignment_target(node: Node<'_>, source: &str) -> bool {
    let text = node_text(node, source).trim();
    text == "exports"
        || text.starts_with("exports.")
        || text == "module.exports"
        || text.starts_with("module.exports.")
}

fn js_is_module_exports_object(node: Node<'_>, source: &str) -> bool {
    if node.kind() != "member_expression" {
        return false;
    }
    let Some(object) = node.child_by_field_name("object") else {
        return false;
    };
    let Some(property) = node.child_by_field_name("property") else {
        return false;
    };
    node_text(object, source).trim() == "module" && node_text(property, source).trim() == "exports"
}

fn js_assignment_signature(
    assignment: Node<'_>,
    left: Node<'_>,
    value: Option<Node<'_>>,
    source: &str,
) -> (String, String) {
    let left_text = trim_statement(node_text(left, source));
    let Some(value) = value else {
        return (trim_statement(node_text(assignment, source)), String::new());
    };
    if matches!(value.kind(), "arrow_function" | "function_expression") {
        let params = js_rendered_parameter_text(value, source);
        return (format!("{left_text} = function{params} ..."), params);
    }
    if is_simple_js_initializer(value) {
        return (
            format!("{left_text} = {}", trim_statement(node_text(value, source))),
            String::new(),
        );
    }
    (format!("{left_text} = ..."), String::new())
}

fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn js_class_signature(node: Node<'_>, source: &str, exported: bool) -> String {
    let definition = if node.kind() == "export_statement" {
        node.child_by_field_name("declaration").unwrap_or(node)
    } else {
        node
    };
    let mut signature = node_text(definition, source)
        .split('{')
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    if exported && !signature.starts_with("export ") {
        signature = format!("export {signature}");
    }
    format!("{} {{", one_line(&signature))
}

fn js_default_export_class_signature(export: Node<'_>, source: &str) -> String {
    let text = node_text(export, source);
    let signature = text.split('{').next().unwrap_or(text).trim();
    format!("{} {{", one_line(signature))
}

fn js_function_signature(
    node: Node<'_>,
    source: &str,
    name: &str,
    exported: bool,
) -> (String, String) {
    let mut prefix = if exported { "export " } else { "" }.to_string();
    let async_prefix = if node
        .child_by_field_name("body")
        .map(|_| node_text(node, source).contains("async "))
        .unwrap_or(false)
    {
        "async "
    } else {
        ""
    };
    let params = js_rendered_parameter_text(node, source);
    prefix.push_str(async_prefix);
    let jsx_suffix = if exported && is_component_like_name(name) && node_returns_jsx(node, source) {
        ": JSX.Element"
    } else {
        ""
    };
    (
        with_mutation_comment(
            format!("{prefix}function {name}{params}{jsx_suffix} ..."),
            node,
            source,
        ),
        params,
    )
}

fn js_default_export_function_signature(function: Node<'_>, source: &str) -> (String, String) {
    let async_prefix = if node_text(function, source)
        .trim_start()
        .starts_with("async ")
    {
        "async "
    } else {
        ""
    };
    let params = js_rendered_parameter_text(function, source);
    let signature = match function.kind() {
        "function_declaration" | "function_expression" => {
            format!("export default {async_prefix}function{params} ...")
        }
        "generator_function" => format!("export default {async_prefix}function*{params} ..."),
        _ => format!("export default {async_prefix}{params} => ..."),
    };
    (with_mutation_comment(signature, function, source), params)
}

fn js_method_signature(node: Node<'_>, source: &str) -> (String, String) {
    let name = node
        .child_by_field_name("name")
        .map(|name| node_text(name, source).trim_matches('"').trim().to_string())
        .unwrap_or_else(|| "method".to_string());
    let params = js_rendered_parameter_text(node, source);
    let jsx_suffix = if name == "render" && node_returns_jsx(node, source) {
        ": JSX.Element"
    } else {
        ""
    };
    (format!("function {name}{params}{jsx_suffix} ..."), params)
}

fn js_variable_function_signature(
    _statement: Node<'_>,
    declarator: Node<'_>,
    source: &str,
    name: &str,
    exported: bool,
) -> (String, String) {
    let value = declarator
        .child_by_field_name("value")
        .unwrap_or(declarator);
    let async_prefix = if node_text(value, source).trim_start().starts_with("async ") {
        "async "
    } else {
        ""
    };
    let params = js_rendered_parameter_text(value, source);
    let jsx_suffix = if exported && is_component_like_name(name) && node_returns_jsx(value, source)
    {
        ": JSX.Element"
    } else {
        ""
    };
    let export_prefix = if exported { "export " } else { "" };
    (
        with_mutation_comment(
            format!("{export_prefix}{async_prefix}{name}{params}{jsx_suffix} => ..."),
            value,
            source,
        ),
        params,
    )
}

fn js_variable_signature(
    statement: Node<'_>,
    declarator: Node<'_>,
    source: &str,
    exported: bool,
) -> String {
    let header = variable_header(statement, declarator, source, exported);
    match declarator.child_by_field_name("value") {
        Some(value) if is_simple_js_initializer(value) => {
            let value_text = trim_statement(node_text(value, source));
            format!("{header} = {value_text}")
        }
        _ => header,
    }
}

fn is_simple_js_initializer(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "string"
            | "number"
            | "true"
            | "false"
            | "null"
            | "undefined"
            | "regex"
            | "template_string"
            | "unary_expression"
            | "binary_expression"
            | "identifier"
            | "member_expression"
    )
}

fn with_mutation_comment(signature: String, node: Node<'_>, source: &str) -> String {
    let mutations = mutation_names(node, source);
    if mutations.is_empty() {
        signature
    } else {
        format!("// mutates: {}\n{signature}", mutations.join(", "))
    }
}

fn mutation_names(node: Node<'_>, source: &str) -> Vec<String> {
    let mut names = BTreeSet::new();
    collect_mutation_names(node, source, &mut names);
    names.into_iter().collect()
}

fn collect_mutation_names(root: Node<'_>, source: &str, names: &mut BTreeSet<String>) {
    walk_named_tree_preorder(root, true, |node| {
        if node.id() != root.id()
            && matches!(
                node.kind(),
                "function_declaration"
                    | "function_expression"
                    | "arrow_function"
                    | "method_definition"
                    | "class_declaration"
            )
        {
            return WalkControl::SkipChildren;
        }

        match node.kind() {
            "assignment_expression" => {
                if let Some(left) = node.child_by_field_name("left")
                    && let Some(name) = mutation_target_name(left, source)
                {
                    names.insert(name);
                }
            }
            "update_expression" => {
                let target = node
                    .child_by_field_name("argument")
                    .or_else(|| node.named_child(0))
                    .or_else(|| node.named_child(1));
                if let Some(target) = target
                    && let Some(name) = mutation_target_name(target, source)
                {
                    names.insert(name);
                }
            }
            _ => {}
        }

        WalkControl::Continue
    });
}

fn mutation_target_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "property_identifier" => Some(node_text(node, source).trim().to_string()),
        "member_expression" => node
            .child_by_field_name("property")
            .and_then(|property| mutation_target_name(property, source))
            .or_else(|| {
                node_text(node, source)
                    .split('.')
                    .next_back()
                    .map(str::trim)
                    .filter(|name| !name.is_empty())
                    .map(str::to_string)
            }),
        _ => None,
    }
}

fn extract_js_type_identifiers(source: &str) -> BTreeSet<String> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_javascript::LANGUAGE.into())
        .expect("failed to load javascript parser");
    let Some(tree) = parser.parse(source, None) else {
        return BTreeSet::new();
    };
    let mut identifiers = HashSet::default();
    collect_js_ts_identifiers(tree.root_node(), source, &mut identifiers);
    identifiers.into_iter().collect()
}
fn node_returns_jsx(node: Node<'_>, source: &str) -> bool {
    if matches!(
        node.kind(),
        "jsx_element" | "jsx_self_closing_element" | "jsx_fragment"
    ) {
        return true;
    }

    let text = node_text(node, source);
    text.contains('<') && (text.contains("/>") || text.contains("</"))
}

fn is_component_like_name(name: &str) -> bool {
    name.chars()
        .next()
        .map(|ch| ch.is_ascii_uppercase())
        .unwrap_or(false)
}
