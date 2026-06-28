use crate::analyzer::clone_detection::{
    CloneCandidateData, CloneCandidateProfile, compact_clone_excerpt,
    detect_structural_clone_smells,
};
use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::js_ts::cache::{
    build_weighted_cache, weight_code_unit_set, weight_code_unit_set_by_unit,
    weight_code_unit_vec_by_unit, weight_project_file_set, weight_string_set,
};
use crate::analyzer::js_ts::clones::{
    build_js_ts_clone_ast_signature, normalized_clone_tokens_js_ts, refine_js_ts_clone_similarity,
};
use crate::analyzer::js_ts::hierarchy::{
    build_direct_descendant_index_by_unit, extract_js_supertypes, resolve_direct_ancestors,
};
use crate::analyzer::js_ts::identifiers::collect_js_ts_identifiers;
use crate::analyzer::js_ts::imports::extract_js_ts_call_receiver;
use crate::analyzer::js_ts::imports::{
    import_info_tokens, parse_commonjs_require_import_infos_from_node,
    parse_es_import_infos_from_node, resolve_js_ts_import_paths,
};
use crate::analyzer::js_ts::model::{module_code_unit, node_text, trim_statement};
use crate::analyzer::js_ts::tests::detect_js_ts_test_assertion_smells;
use crate::analyzer::tree_sitter_analyzer::{WalkControl, walk_named_tree_preorder};
use crate::analyzer::usages::js_ts_graph::{JsTsUsageIndex, build_jsts_usage_index};
use crate::analyzer::{
    AliasResolver, AnalyzerConfig, BuildProgress, CodeUnit, IAnalyzer, ImportAnalysisProvider,
    ImportInfo, Language, LanguageAdapter, ParameterMetadata, Project, ProjectFile,
    SignatureMetadata, TestAssertionSmell, TestAssertionWeights, TestDetectionProvider,
    TreeSitterAnalyzer, TypeHierarchyProvider, build_reverse_import_index,
};
use crate::hash::{HashMap, HashSet};
use crate::{CloneSmell, CloneSmellWeights};
use moka::sync::Cache;
use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};
use tree_sitter::{Language as TsLanguage, Node, Parser, Tree};

#[derive(Debug, Clone, Default)]
pub struct JavascriptAdapter;

impl LanguageAdapter for JavascriptAdapter {
    fn language(&self) -> Language {
        Language::JavaScript
    }

    fn query_directory(&self) -> &'static str {
        "resources/treesitter/javascript"
    }

    fn parser_language(&self) -> TsLanguage {
        tree_sitter_javascript::LANGUAGE.into()
    }

    fn file_extension(&self) -> &'static str {
        "js"
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
                    visit_js_variable_statement(file, source, child, None, &mut parsed, false);
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
}

#[derive(Clone)]
pub struct JavascriptAnalyzer {
    inner: TreeSitterAnalyzer<JavascriptAdapter>,
    memo_budget: u64,
    memo_caches: Arc<JsMemoCaches>,
    /// Shared jsconfig/tsconfig path-alias resolver (parsed configs cached) so the
    /// import/reference graph resolves `@/`-style aliases like the scan_usages graph.
    alias_resolver: Arc<AliasResolver>,
}

#[derive(Clone)]
struct JsMemoCaches {
    imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    relevant_imports: Cache<CodeUnit, Arc<HashSet<String>>>,
    direct_ancestors: Cache<CodeUnit, Arc<Vec<CodeUnit>>>,
    direct_descendants: Cache<CodeUnit, Arc<HashSet<CodeUnit>>>,
    direct_descendant_index: OnceLock<HashMap<CodeUnit, Arc<HashSet<CodeUnit>>>>,
    reverse_import_index: OnceLock<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>,
    /// Analyzer-cached JS/TS usage-resolution maps, built once and reused across queries.
    /// Reset (with the rest of this bucket) on `update`/`update_all`.
    jsts_usage_index: OnceLock<JsTsUsageIndex>,
}

impl JsMemoCaches {
    fn new(budget_bytes: u64) -> Self {
        Self {
            imported_code_units: build_weighted_cache(budget_bytes / 3, weight_code_unit_set),
            referencing_files: build_weighted_cache(budget_bytes / 6, weight_project_file_set),
            relevant_imports: build_weighted_cache(budget_bytes / 6, weight_string_set),
            direct_ancestors: build_weighted_cache(budget_bytes / 8, weight_code_unit_vec_by_unit),
            direct_descendants: build_weighted_cache(
                budget_bytes / 8,
                weight_code_unit_set_by_unit,
            ),
            direct_descendant_index: OnceLock::new(),
            reverse_import_index: OnceLock::new(),
            jsts_usage_index: OnceLock::new(),
        }
    }
}

impl JavascriptAnalyzer {
    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    /// Lazily-built, analyzer-cached JS/TS usage-resolution maps for this analyzer's
    /// language. Built once and reused until `update`/`update_all` rebuilds the cache bucket.
    pub(crate) fn jsts_usage_index(&self) -> &JsTsUsageIndex {
        self.memo_caches
            .jsts_usage_index
            .get_or_init(|| build_jsts_usage_index(self, Language::JavaScript))
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        let alias_resolver = Arc::new(AliasResolver::new(project.root().to_path_buf()));
        Self {
            inner: TreeSitterAnalyzer::new_with_config(project, JavascriptAdapter, config),
            memo_budget,
            memo_caches: Arc::new(JsMemoCaches::new(memo_budget)),
            alias_resolver,
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
        let alias_resolver = Arc::new(AliasResolver::new(project.root().to_path_buf()));
        let inner = match progress {
            Some(progress) => TreeSitterAnalyzer::new_with_config_storage_and_progress(
                project,
                JavascriptAdapter,
                config,
                storage,
                move |event| progress(event),
            ),
            None => TreeSitterAnalyzer::new_with_config_and_storage(
                project,
                JavascriptAdapter,
                config,
                storage,
            ),
        };
        Self {
            inner,
            memo_budget,
            memo_caches: Arc::new(JsMemoCaches::new(memo_budget)),
            alias_resolver,
        }
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
        if let Some(cached) = self.memo_caches.imported_code_units.get(file) {
            return (*cached).clone();
        }

        let mut resolved = HashSet::default();
        for import in self.inner.import_info_of(file) {
            for target in resolve_js_ts_import_paths(
                file,
                &import.raw_snippet,
                Language::JavaScript,
                Some(&self.alias_resolver),
            ) {
                let top_level: Vec<_> = self.inner.top_level_declarations(&target).collect();
                if import.is_wildcard {
                    resolved.extend(
                        top_level
                            .iter()
                            .copied()
                            .filter(|code_unit| !code_unit.is_module())
                            .cloned(),
                    );
                } else if let Some(identifier) =
                    import.identifier.as_ref().or(import.alias.as_ref())
                {
                    let mut matched = false;
                    for code_unit in top_level
                        .iter()
                        .copied()
                        .filter(|code_unit| code_unit.identifier() == identifier)
                    {
                        matched = true;
                        resolved.insert(code_unit.clone());
                    }
                    if !matched {
                        let module_units = top_level
                            .iter()
                            .copied()
                            .filter(|code_unit| code_unit.is_module())
                            .cloned()
                            .collect::<Vec<_>>();
                        if !module_units.is_empty() {
                            resolved.extend(module_units);
                        } else if top_level.len() == 1 && !top_level[0].is_module() {
                            resolved.insert(top_level[0].clone());
                        }
                    }
                } else {
                    resolved.extend(
                        top_level
                            .iter()
                            .copied()
                            .filter(|code_unit| !code_unit.is_module())
                            .cloned(),
                    );
                }
            }
        }

        self.memo_caches
            .imported_code_units
            .insert(file.clone(), Arc::new(resolved.clone()));
        resolved
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        if let Some(cached) = self.memo_caches.referencing_files.get(file) {
            return (*cached).clone();
        }

        let reverse_index = self.memo_caches.reverse_import_index.get_or_init(|| {
            let files: Vec<_> = self.inner.all_files().cloned().collect();
            build_reverse_import_index(&files, |candidate| self.imported_code_units_of(candidate))
        });
        let referencing = reverse_index
            .get(file)
            .map(|files| (**files).clone())
            .unwrap_or_default();

        self.memo_caches
            .referencing_files
            .insert(file.clone(), Arc::new(referencing.clone()));
        referencing
    }

    fn import_info_of<'a>(&'a self, file: &ProjectFile) -> &'a [ImportInfo] {
        self.inner.import_info_of(file)
    }

    fn relevant_imports_for(&self, code_unit: &CodeUnit) -> HashSet<String> {
        if let Some(cached) = self.memo_caches.relevant_imports.get(code_unit) {
            return (*cached).clone();
        }

        let source = self.inner.get_source(code_unit, false).unwrap_or_default();
        let mut relevant = HashSet::default();
        for import in self.inner.import_info_of(code_unit.source()) {
            let tokens = import_info_tokens(import);
            if tokens.is_empty() || tokens.iter().any(|token| source.contains(token)) {
                relevant.insert(import.raw_snippet.clone());
            }
        }

        self.memo_caches
            .relevant_imports
            .insert(code_unit.clone(), Arc::new(relevant.clone()));
        relevant
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        imports.iter().any(|import| {
            resolve_js_ts_import_paths(
                source_file,
                &import.raw_snippet,
                Language::JavaScript,
                Some(&self.alias_resolver),
            )
            .into_iter()
            .any(|candidate| candidate == *target)
        })
    }
}

impl TypeHierarchyProvider for JavascriptAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        if let Some(cached) = self.memo_caches.direct_ancestors.get(code_unit) {
            return (*cached).clone();
        }

        let ancestors = resolve_direct_ancestors(
            self,
            self.jsts_usage_index(),
            Language::JavaScript,
            &self.alias_resolver,
            code_unit,
            self.inner.raw_supertypes_of(code_unit),
        );
        self.memo_caches
            .direct_ancestors
            .insert(code_unit.clone(), Arc::new(ancestors.clone()));
        ancestors
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        if let Some(cached) = self.memo_caches.direct_descendants.get(code_unit) {
            return (*cached).clone();
        }

        let descendants = self
            .memo_caches
            .direct_descendant_index
            .get_or_init(|| build_direct_descendant_index_by_unit(self, self))
            .get(code_unit)
            .map(|descendants| descendants.as_ref().clone())
            .unwrap_or_default();
        self.memo_caches
            .direct_descendants
            .insert(code_unit.clone(), Arc::new(descendants.clone()));
        descendants
    }
}

impl TestDetectionProvider for JavascriptAnalyzer {}
impl IAnalyzer for JavascriptAnalyzer {
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

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        let inner = self.inner.update(changed_files);
        // Rebuild from root so a changed jsconfig/tsconfig drops its stale parse cache.
        let alias_resolver = Arc::new(AliasResolver::new(inner.project().root().to_path_buf()));
        Self {
            inner,
            memo_budget: self.memo_budget,
            memo_caches: Arc::new(JsMemoCaches::new(self.memo_budget)),
            alias_resolver,
        }
    }

    fn update_all(&self) -> Self {
        let inner = self.inner.update_all();
        let alias_resolver = Arc::new(AliasResolver::new(inner.project().root().to_path_buf()));
        Self {
            inner,
            memo_budget: self.memo_budget,
            memo_caches: Arc::new(JsMemoCaches::new(self.memo_budget)),
            alias_resolver,
        }
    }

    fn project(&self) -> &dyn Project {
        self.inner.project()
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

    fn ranges_of(&self, code_unit: &CodeUnit) -> Vec<crate::analyzer::Range> {
        self.inner.ranges_of(code_unit)
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

    fn search_definitions_persisted(&self, pattern: &str) -> BTreeSet<CodeUnit> {
        self.inner.search_definitions_persisted(pattern)
    }

    fn signatures_of(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.inner.signatures_of(code_unit).to_vec()
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

    fn contains_tests(&self, file: &ProjectFile) -> bool {
        self.inner.contains_tests(file)
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
            refine_js_ts_clone_similarity,
        )
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
                visit_js_class(file, source, node, None, parsed, true);
            }
            "function_declaration" => {
                visit_js_function(file, source, node, None, parsed, true);
            }
            "lexical_declaration" | "variable_declaration" => {
                visit_js_variable_statement(file, source, node, None, parsed, true);
            }
            _ => {}
        }
    }
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
    let code_unit = CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Class,
        "",
        short_name,
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

    if let Some(body) = definition.child_by_field_name("body") {
        for index in 0..body.named_child_count() {
            let Some(child) = body.named_child(index) else {
                continue;
            };
            match child.kind() {
                "method_definition" => {
                    visit_js_method(file, source, child, &code_unit, &top_level, parsed)
                }
                "field_definition" | "public_field_definition" => {
                    visit_js_field(file, source, child, &code_unit, &top_level, parsed);
                }
                _ => {}
            }
        }
    }

    Some(code_unit)
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
    let code_unit = CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Function,
        "",
        short_name,
    );
    let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
    let range_node = if exported { node } else { definition };
    parsed.add_code_unit(
        code_unit.clone(),
        range_node,
        source,
        parent.cloned(),
        Some(top_level),
    );
    let (signature, parameter_text) = js_function_signature(definition, source, name, exported);
    parsed.add_signature_with_metadata(
        code_unit.clone(),
        js_signature_metadata(signature, definition, source, &parameter_text),
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

    let code_unit = CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Function,
        "",
        format!("{}.{}", parent.short_name(), name),
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
    let code_unit = CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Field,
        "",
        format!("{}.{}", parent.short_name(), name),
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
        let name = node_text(name_node, source).trim();
        if name.is_empty() {
            continue;
        }

        let value = child.child_by_field_name("value");
        let is_function = value
            .map(|value| matches!(value.kind(), "arrow_function" | "function_expression"))
            .unwrap_or(false);
        let kind = if is_function {
            crate::analyzer::CodeUnitType::Function
        } else {
            crate::analyzer::CodeUnitType::Field
        };
        let short_name = if kind == crate::analyzer::CodeUnitType::Field {
            parent
                .map(|parent| format!("{}.{}", parent.short_name(), name))
                .unwrap_or_else(|| {
                    format!(
                        "{}.{}",
                        file.rel_path()
                            .file_name()
                            .and_then(|name| name.to_str())
                            .unwrap_or("module"),
                        name
                    )
                })
        } else {
            parent
                .map(|parent| format!("{}.{}", parent.short_name(), name))
                .unwrap_or_else(|| name.to_string())
        };
        let code_unit = CodeUnit::new(file.clone(), kind, "", short_name);
        let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
        let range_node = if exported { node } else { definition };
        parsed.add_code_unit(
            code_unit.clone(),
            range_node,
            source,
            parent.cloned(),
            Some(top_level.clone()),
        );
        if is_function {
            let (signature, parameter_text) =
                js_variable_function_signature(definition, child, source, name, exported);
            if let Some(value) = value {
                parsed.add_signature_with_metadata(
                    code_unit.clone(),
                    js_signature_metadata(signature, value, source, &parameter_text),
                );
            } else {
                parsed.add_signature(code_unit.clone(), signature);
            }
        } else {
            parsed.add_signature(
                code_unit.clone(),
                js_variable_signature(definition, child, source, exported),
            );
        }
        if !is_function
            && let Some(value) = value
            && value.kind() == "object"
        {
            visit_js_object_literal_properties(file, source, value, &code_unit, &top_level, parsed);
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
    for index in 0..object.named_child_count() {
        let Some(child) = object.named_child(index) else {
            continue;
        };
        let Some(name) = js_object_literal_property_name(child, source) else {
            continue;
        };
        let code_unit = CodeUnit::new(
            file.clone(),
            crate::analyzer::CodeUnitType::Field,
            "",
            format!("{}.{}", parent.short_name(), name),
        );
        parsed.add_code_unit(
            code_unit.clone(),
            child,
            source,
            Some(parent.clone()),
            Some(top_level.clone()),
        );
        parsed.add_signature(code_unit, trim_statement(node_text(child, source)));
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

fn visit_js_assignment_declarations(
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    walk_named_tree_preorder(root, true, |node| {
        if node.kind() == "assignment_expression" {
            visit_js_assignment_expression(file, source, node, parsed);
        }
        WalkControl::Continue
    });
}

fn visit_js_assignment_expression(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let Some(left) = node.child_by_field_name("left") else {
        return;
    };
    let value = node.child_by_field_name("right");
    let Some(name) = js_commonjs_export_assignment_name(left, value, source)
        .or_else(|| js_member_assignment_name(left, source))
    else {
        return;
    };
    let is_function =
        value.is_some_and(|value| matches!(value.kind(), "arrow_function" | "function_expression"));
    let kind = if is_function {
        crate::analyzer::CodeUnitType::Function
    } else {
        crate::analyzer::CodeUnitType::Field
    };
    let code_unit = CodeUnit::new(file.clone(), kind, "", name);
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        None,
        Some(code_unit.clone()),
    );
    let (signature, parameter_text) = js_assignment_signature(node, left, value, source);
    if let Some(value) =
        value.filter(|value| matches!(value.kind(), "arrow_function" | "function_expression"))
    {
        parsed.add_signature_with_metadata(
            code_unit.clone(),
            js_signature_metadata(signature, value, source, &parameter_text),
        );
    } else {
        parsed.add_signature(code_unit.clone(), signature);
    }
    if !is_function
        && let Some(value) = value
        && value.kind() == "object"
    {
        visit_js_object_literal_properties(file, source, value, &code_unit, &code_unit, parsed);
    }
}

fn js_commonjs_export_assignment_name(
    left: Node<'_>,
    value: Option<Node<'_>>,
    source: &str,
) -> Option<String> {
    if !value.is_some_and(|value| matches!(value.kind(), "arrow_function" | "function_expression"))
    {
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

fn js_member_assignment_name(node: Node<'_>, source: &str) -> Option<String> {
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
    let object_name = match object.kind() {
        "identifier" | "property_identifier" => node_text(object, source).trim().to_string(),
        "member_expression" => js_member_assignment_name(object, source)?,
        _ => return None,
    };
    let property_name = node_text(property, source)
        .trim()
        .trim_matches('"')
        .trim_matches('\'');
    if object_name.is_empty() || property_name.is_empty() {
        return None;
    }
    Some(format!("{object_name}.{property_name}"))
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
    let header = js_variable_header(statement, declarator, source, exported);
    match declarator.child_by_field_name("value") {
        Some(value) if is_simple_js_initializer(value) => {
            let value_text = trim_statement(node_text(value, source));
            format!("{header} = {value_text}")
        }
        _ => header,
    }
}

fn js_variable_header(
    statement: Node<'_>,
    declarator: Node<'_>,
    source: &str,
    exported: bool,
) -> String {
    let keyword = statement
        .child(0)
        .map(|node| node_text(node, source).trim().to_string())
        .unwrap_or_else(|| "const".to_string());
    let declarator_text = trim_statement(node_text(declarator, source));
    let left = declarator_text
        .split('=')
        .next()
        .map(trim_statement)
        .unwrap_or(declarator_text);
    let export_prefix = if exported { "export " } else { "" };
    format!("{export_prefix}{keyword} {left}")
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

fn js_ts_contains_tests(file: &ProjectFile, source: &str) -> bool {
    let rel = file.rel_path().to_string_lossy().to_ascii_lowercase();
    rel.contains(".test.")
        || rel.contains(".spec.")
        || source.contains("describe(")
        || source.contains("test(")
        || source.contains("it(")
}
