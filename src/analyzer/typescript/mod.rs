use crate::analyzer::clone_detection::{
    CloneCandidateData, CloneCandidateProfile, compact_clone_excerpt,
    detect_structural_clone_smells,
};
use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::{
    AliasResolver, AnalyzerConfig, BuildProgress, CodeUnit, IAnalyzer, ImportAnalysisProvider,
    ImportInfo, Language, Project, ProjectFile, SemanticDiagnostic, SignatureMetadata,
    TestAssertionSmell, TestAssertionWeights, TestDetectionProvider, TreeSitterAnalyzer,
    TypeAliasProvider, TypeHierarchyProvider, build_reverse_import_index,
};
use crate::hash::{HashMap, HashSet};
use crate::{CloneSmell, CloneSmellWeights};
use moka::sync::Cache;
use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};
use tree_sitter::{Language as TsLanguage, Node, Parser, Tree};

use crate::analyzer::js_ts::cache::{
    build_weighted_cache, weight_code_unit_set, weight_code_unit_set_by_unit,
    weight_code_unit_vec_by_unit, weight_project_file_set, weight_string_set,
};
use crate::analyzer::js_ts::clones::{
    build_js_ts_clone_ast_signature, normalized_clone_tokens_js_ts, refine_js_ts_clone_similarity,
};
use crate::analyzer::js_ts::diagnostics::collect_typescript_semantic_diagnostics;
use crate::analyzer::js_ts::hierarchy::{
    build_direct_descendant_index_by_unit, extract_ts_supertypes, resolve_direct_ancestors,
};
use crate::analyzer::js_ts::identifiers::collect_js_ts_identifiers;
use crate::analyzer::js_ts::imports::{
    extract_js_ts_call_receiver, import_info_tokens, parse_commonjs_require_import_infos_from_node,
    parse_es_import_infos_from_node, resolve_js_ts_import_paths,
};
use crate::analyzer::js_ts::model::{module_code_unit, node_text, trim_statement};
use crate::analyzer::js_ts::tests::detect_js_ts_test_assertion_smells;
use crate::analyzer::tree_sitter_analyzer::{WalkControl, walk_named_tree_preorder};
use crate::analyzer::usages::js_ts_graph::{JsTsUsageIndex, build_jsts_usage_index};
#[derive(Debug, Clone, Default)]
pub struct TypescriptAdapter;

impl crate::analyzer::LanguageAdapter for TypescriptAdapter {
    fn language(&self) -> Language {
        Language::TypeScript
    }

    fn query_directory(&self) -> &'static str {
        "resources/treesitter/typescript"
    }

    fn parser_language(&self) -> TsLanguage {
        tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()
    }

    fn parser_language_for_file(&self, file: &ProjectFile) -> TsLanguage {
        crate::analyzer::usages::parsed_tree::js_ts_tree_sitter_language_for_file(
            file,
            Language::TypeScript,
        )
        .unwrap_or_else(|| self.parser_language())
    }

    fn file_extension(&self) -> &'static str {
        "ts"
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
        let rel = file.rel_path().to_string_lossy().to_ascii_lowercase();
        rel.contains(".test.")
            || rel.contains(".spec.")
            || source.contains("describe(")
            || source.contains("test(")
            || source.contains("it(")
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
        let exported_roots = ts_es_named_exported_roots(root, source);

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
                    visit_ts_export(file, source, child, None, &mut parsed, &exported_roots)
                }
                "ambient_declaration" => {
                    visit_ts_ambient_declarations(file, source, child, None, &mut parsed, false);
                }
                "internal_module" if ts_is_global_internal_module(child, source) => {
                    visit_ts_ambient_declarations(file, source, child, None, &mut parsed, false);
                }
                "class_declaration"
                | "abstract_class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "internal_module" => {
                    visit_ts_class_like(file, source, child, None, &mut parsed, false);
                }
                "function_declaration" | "function_signature" => {
                    visit_ts_function(file, source, child, None, &mut parsed, false);
                }
                "lexical_declaration" | "variable_declaration" | "type_alias_declaration" => {
                    if matches!(child.kind(), "lexical_declaration" | "variable_declaration") {
                        let imports = parse_commonjs_require_import_infos_from_node(child, source);
                        if !imports.is_empty() {
                            let raw = node_text(child, source).trim().to_string();
                            module_has_imports = true;
                            parsed.import_statements.push(raw);
                            parsed.imports.extend(imports);
                        }
                    }
                    visit_ts_value(
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

        if module_has_imports {
            parsed.add_code_unit(module, root, source, None, None);
        }

        parsed
    }

    fn structural_spec(&self) -> Option<&'static dyn crate::analyzer::structural::StructuralSpec> {
        Some(&crate::analyzer::js_ts::structural::TYPESCRIPT_STRUCTURAL_SPEC)
    }
}

#[derive(Clone)]
pub struct TypescriptAnalyzer {
    inner: TreeSitterAnalyzer<TypescriptAdapter>,
    memo_budget: u64,
    imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    relevant_imports: Cache<CodeUnit, Arc<HashSet<String>>>,
    direct_ancestors: Cache<CodeUnit, Arc<Vec<CodeUnit>>>,
    direct_descendants: Cache<CodeUnit, Arc<HashSet<CodeUnit>>>,
    direct_descendant_index: Arc<OnceLock<HashMap<CodeUnit, Arc<HashSet<CodeUnit>>>>>,
    reverse_import_index: Arc<OnceLock<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    /// Analyzer-cached JS/TS usage-resolution maps, built once per analyzer and reused
    /// across `scan_usages`/`usage_graph` queries. Reset on `update`/`update_all`.
    jsts_usage_index: Arc<OnceLock<JsTsUsageIndex>>,
    /// Shared tsconfig path-alias resolver (parsed configs cached) so the import/reference
    /// graph resolves `@/`-style aliases the same way the scan_usages graph does.
    alias_resolver: Arc<AliasResolver>,
}

impl TypescriptAnalyzer {
    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        let alias_resolver = Arc::new(AliasResolver::new(project.root().to_path_buf()));
        Self {
            inner: TreeSitterAnalyzer::new_with_config(project, TypescriptAdapter, config),
            memo_budget,
            imported_code_units: build_weighted_cache(memo_budget / 3, weight_code_unit_set),
            referencing_files: build_weighted_cache(memo_budget / 6, weight_project_file_set),
            relevant_imports: build_weighted_cache(memo_budget / 6, weight_string_set),
            direct_ancestors: build_weighted_cache(memo_budget / 8, weight_code_unit_vec_by_unit),
            direct_descendants: build_weighted_cache(memo_budget / 8, weight_code_unit_set_by_unit),
            direct_descendant_index: Arc::new(OnceLock::new()),
            reverse_import_index: Arc::new(OnceLock::new()),
            jsts_usage_index: Arc::new(OnceLock::new()),
            alias_resolver,
        }
    }

    /// Lazily-built, analyzer-cached JS/TS usage-resolution maps for this analyzer's
    /// language. Built once and reused until `update`/`update_all` resets the cell.
    pub(crate) fn jsts_usage_index(&self) -> &JsTsUsageIndex {
        self.jsts_usage_index
            .get_or_init(|| build_jsts_usage_index(self, Language::TypeScript))
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
                TypescriptAdapter,
                config,
                storage,
                move |event| progress(event),
            ),
            None => TreeSitterAnalyzer::new_with_config_and_storage(
                project,
                TypescriptAdapter,
                config,
                storage,
            ),
        };
        Self {
            inner,
            memo_budget,
            imported_code_units: build_weighted_cache(memo_budget / 3, weight_code_unit_set),
            referencing_files: build_weighted_cache(memo_budget / 6, weight_project_file_set),
            relevant_imports: build_weighted_cache(memo_budget / 6, weight_string_set),
            direct_ancestors: build_weighted_cache(memo_budget / 8, weight_code_unit_vec_by_unit),
            direct_descendants: build_weighted_cache(memo_budget / 8, weight_code_unit_set_by_unit),
            direct_descendant_index: Arc::new(OnceLock::new()),
            reverse_import_index: Arc::new(OnceLock::new()),
            jsts_usage_index: Arc::new(OnceLock::new()),
            alias_resolver,
        }
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }

    pub fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        self.inner.is_type_alias(code_unit)
    }

    pub fn extract_type_identifiers(&self, source: &str) -> BTreeSet<String> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .expect("failed to load typescript parser");
        let Some(tree) = parser.parse(source, None) else {
            return BTreeSet::new();
        };
        let mut identifiers = HashSet::default();
        collect_js_ts_identifiers(tree.root_node(), source, &mut identifiers);
        identifiers.into_iter().collect()
    }

    fn module_import_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        if !code_unit.is_module() {
            return None;
        }

        let imports = self.inner.import_statements(code_unit.source());
        (!imports.is_empty()).then(|| imports.join("\n"))
    }

    fn type_alias_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        self.inner
            .is_type_alias(code_unit)
            .then(|| self.inner.signatures_of(code_unit).first().cloned())
            .flatten()
    }
}

impl ImportAnalysisProvider for TypescriptAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> HashSet<CodeUnit> {
        if let Some(cached) = self.imported_code_units.get(file) {
            return (*cached).clone();
        }

        let mut resolved = HashSet::default();
        for import in self.inner.import_info_of(file) {
            for target in resolve_js_ts_import_paths(
                file,
                &import.raw_snippet,
                Language::TypeScript,
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

        self.imported_code_units
            .insert(file.clone(), Arc::new(resolved.clone()));
        resolved
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        if let Some(cached) = self.referencing_files.get(file) {
            return (*cached).clone();
        }

        let reverse_index = self.reverse_import_index.get_or_init(|| {
            let files: Vec<_> = self.inner.all_files().cloned().collect();
            build_reverse_import_index(&files, |candidate| self.imported_code_units_of(candidate))
        });
        let referencing = reverse_index
            .get(file)
            .map(|files| (**files).clone())
            .unwrap_or_default();
        self.referencing_files
            .insert(file.clone(), Arc::new(referencing.clone()));
        referencing
    }

    fn import_info_of<'a>(&'a self, file: &ProjectFile) -> &'a [ImportInfo] {
        self.inner.import_info_of(file)
    }

    fn relevant_imports_for(&self, code_unit: &CodeUnit) -> HashSet<String> {
        if let Some(cached) = self.relevant_imports.get(code_unit) {
            return (*cached).clone();
        }
        let source = self.inner.get_source(code_unit, false).unwrap_or_default();
        let relevant: HashSet<_> = self
            .inner
            .import_info_of(code_unit.source())
            .iter()
            .filter(|import| {
                let tokens = import_info_tokens(import);
                tokens.is_empty() || tokens.iter().any(|token| source.contains(token))
            })
            .map(|import| import.raw_snippet.clone())
            .collect();
        self.relevant_imports
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
                Language::TypeScript,
                Some(&self.alias_resolver),
            )
            .into_iter()
            .any(|candidate| candidate == *target)
        })
    }
}

impl TypeAliasProvider for TypescriptAnalyzer {
    fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        self.inner.is_type_alias(code_unit)
    }
}

impl TestDetectionProvider for TypescriptAnalyzer {}

impl TypeHierarchyProvider for TypescriptAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        if let Some(cached) = self.direct_ancestors.get(code_unit) {
            return (*cached).clone();
        }

        let ancestors = resolve_direct_ancestors(
            self,
            self.jsts_usage_index(),
            Language::TypeScript,
            &self.alias_resolver,
            code_unit,
            self.inner.raw_supertypes_of(code_unit),
        );
        self.direct_ancestors
            .insert(code_unit.clone(), Arc::new(ancestors.clone()));
        ancestors
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        if let Some(cached) = self.direct_descendants.get(code_unit) {
            return (*cached).clone();
        }

        let descendants = self
            .direct_descendant_index
            .get_or_init(|| build_direct_descendant_index_by_unit(self, self))
            .get(code_unit)
            .map(|descendants| descendants.as_ref().clone())
            .unwrap_or_default();
        self.direct_descendants
            .insert(code_unit.clone(), Arc::new(descendants.clone()));
        descendants
    }
}

impl IAnalyzer for TypescriptAnalyzer {
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
        // Rebuild from root so a changed tsconfig.json drops its stale parse cache.
        let alias_resolver = Arc::new(AliasResolver::new(inner.project().root().to_path_buf()));
        Self {
            inner,
            memo_budget: self.memo_budget,
            imported_code_units: build_weighted_cache(self.memo_budget / 3, weight_code_unit_set),
            referencing_files: build_weighted_cache(self.memo_budget / 6, weight_project_file_set),
            relevant_imports: build_weighted_cache(self.memo_budget / 6, weight_string_set),
            direct_ancestors: build_weighted_cache(
                self.memo_budget / 8,
                weight_code_unit_vec_by_unit,
            ),
            direct_descendants: build_weighted_cache(
                self.memo_budget / 8,
                weight_code_unit_set_by_unit,
            ),
            direct_descendant_index: Arc::new(OnceLock::new()),
            reverse_import_index: Arc::new(OnceLock::new()),
            jsts_usage_index: Arc::new(OnceLock::new()),
            alias_resolver,
        }
    }
    fn update_all(&self) -> Self {
        let inner = self.inner.update_all();
        let alias_resolver = Arc::new(AliasResolver::new(inner.project().root().to_path_buf()));
        Self {
            inner,
            memo_budget: self.memo_budget,
            imported_code_units: build_weighted_cache(self.memo_budget / 3, weight_code_unit_set),
            referencing_files: build_weighted_cache(self.memo_budget / 6, weight_project_file_set),
            relevant_imports: build_weighted_cache(self.memo_budget / 6, weight_string_set),
            direct_ancestors: build_weighted_cache(
                self.memo_budget / 8,
                weight_code_unit_vec_by_unit,
            ),
            direct_descendants: build_weighted_cache(
                self.memo_budget / 8,
                weight_code_unit_set_by_unit,
            ),
            direct_descendant_index: Arc::new(OnceLock::new()),
            reverse_import_index: Arc::new(OnceLock::new()),
            jsts_usage_index: Arc::new(OnceLock::new()),
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

    fn semantic_diagnostics(&self, file: &ProjectFile, source: &str) -> Vec<SemanticDiagnostic> {
        collect_typescript_semantic_diagnostics(self, file, source, &self.alias_resolver)
            .into_iter()
            .map(Into::into)
            .collect()
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
            .or_else(|| self.type_alias_skeleton(code_unit))
            .or_else(|| self.inner.get_skeleton(code_unit))
    }
    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        self.module_import_skeleton(code_unit)
            .or_else(|| self.type_alias_skeleton(code_unit))
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
        self.inner
            .signatures_of(code_unit)
            .iter()
            .map(|signature| {
                if self.inner.is_type_alias(code_unit) && !signature.ends_with(';') {
                    format!("{signature};")
                } else {
                    signature.clone()
                }
            })
            .collect()
    }
    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        Some(self)
    }
    fn type_alias_provider(&self) -> Option<&dyn TypeAliasProvider> {
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

    fn contains_tests(&self, file: &ProjectFile) -> bool {
        self.inner.contains_tests(file)
    }

    fn find_test_assertion_smells(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
    ) -> Vec<TestAssertionSmell> {
        if !self.contains_tests(file) || file_language(file) != Language::TypeScript {
            return Vec::new();
        }
        let Ok(source) = self.inner.project().read_source(file) else {
            return Vec::new();
        };
        detect_js_ts_test_assertion_smells(
            file,
            &source,
            tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
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
            .filter(|file| file_language(file) == Language::TypeScript)
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
                    && matches!(file_language(code_unit.source()), Language::TypeScript)
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

impl TypescriptAnalyzer {
    fn build_clone_candidate_data(
        &self,
        code_unit: &CodeUnit,
        weights: CloneSmellWeights,
    ) -> Option<CloneCandidateData> {
        self.get_source(code_unit, false)
            .map(|source| source.trim().to_string())
            .filter(|source| !source.is_empty())
            .and_then(|source| {
                let normalized_tokens = normalized_clone_tokens_js_ts(
                    &source,
                    tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
                );
                if normalized_tokens.len() < weights.min_normalized_tokens.max(0) as usize {
                    return None;
                }
                Some(CloneCandidateData {
                    unit: code_unit.clone(),
                    normalized_tokens,
                    ast_signature: build_js_ts_clone_ast_signature(
                        &source,
                        tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
                    ),
                    excerpt: compact_clone_excerpt(&source),
                })
            })
    }
}

fn visit_ts_ambient_declarations(
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
    match definition.kind() {
        "ambient_declaration" | "statement_block" => {
            let mut cursor = definition.walk();
            for child in definition.named_children(&mut cursor) {
                visit_ts_ambient_declarations(file, source, child, parent, parsed, exported);
            }
        }
        "internal_module" if ts_is_global_internal_module(definition, source) => {
            if let Some(body) = definition.child_by_field_name("body") {
                let mut cursor = body.walk();
                for child in body.named_children(&mut cursor) {
                    visit_ts_ambient_declarations(file, source, child, parent, parsed, false);
                }
            }
        }
        "class_declaration"
        | "abstract_class_declaration"
        | "interface_declaration"
        | "enum_declaration"
        | "internal_module" => {
            visit_ts_class_like(file, source, definition, parent, parsed, exported);
        }
        "function_declaration" | "function_signature" => {
            visit_ts_function(file, source, definition, parent, parsed, exported);
        }
        "lexical_declaration" | "variable_declaration" | "type_alias_declaration" => {
            visit_ts_value(
                file,
                source,
                definition,
                parent,
                parsed,
                exported,
                &HashSet::default(),
            );
        }
        _ => {}
    }
}

fn ts_is_global_internal_module(node: Node<'_>, source: &str) -> bool {
    node.kind() == "internal_module"
        && node
            .child_by_field_name("name")
            .is_some_and(|name| trim_statement(node_text(name, source)) == "global")
}

fn visit_ts_export(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
    exported_roots: &HashSet<String>,
) {
    if let Some(declaration) = node.child_by_field_name("declaration") {
        match declaration.kind() {
            "ambient_declaration" => {
                visit_ts_ambient_declarations(file, source, declaration, parent, parsed, true);
            }
            "internal_module" if ts_is_global_internal_module(declaration, source) => {
                visit_ts_ambient_declarations(file, source, declaration, parent, parsed, true);
            }
            "class_declaration"
            | "abstract_class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "internal_module" => {
                if matches!(
                    declaration.kind(),
                    "class_declaration" | "abstract_class_declaration"
                ) && declaration.child_by_field_name("name").is_none()
                    && ts_export_is_default(node, source)
                    && parent.is_none()
                {
                    visit_ts_default_export_class(file, source, node, declaration, parsed);
                } else {
                    visit_ts_class_like(file, source, node, parent, parsed, true);
                }
            }
            "function_declaration" | "function_signature" => {
                if declaration.kind() == "function_declaration"
                    && declaration.child_by_field_name("name").is_none()
                    && ts_export_is_default(node, source)
                    && parent.is_none()
                {
                    visit_ts_default_export_function(file, source, node, declaration, parsed);
                } else {
                    visit_ts_function(file, source, node, parent, parsed, true);
                }
            }
            "lexical_declaration" | "variable_declaration" | "type_alias_declaration" => {
                visit_ts_value(file, source, node, parent, parsed, true, exported_roots);
            }
            _ => {}
        }
    } else if parent.is_none()
        && let Some(value) = node.child_by_field_name("value")
    {
        visit_ts_default_export_value(file, source, node, value, parsed);
    }
}

fn ts_export_is_default(node: Node<'_>, source: &str) -> bool {
    (0..node.child_count()).any(|index| {
        node.child(index)
            .is_some_and(|child| child.kind() == "default" || node_text(child, source) == "default")
    })
}

fn visit_ts_default_export_value(
    file: &ProjectFile,
    source: &str,
    export: Node<'_>,
    value: Node<'_>,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    match value.kind() {
        "arrow_function" | "function_expression" | "generator_function" => {
            visit_ts_default_export_function(file, source, export, value, parsed);
        }
        "class" => {
            visit_ts_default_export_class(file, source, export, value, parsed);
        }
        "object" => {
            let code_unit = add_ts_default_export_unit(
                file,
                source,
                export,
                crate::analyzer::CodeUnitType::Field,
                parsed,
            );
            parsed.add_signature(code_unit.clone(), trim_statement(node_text(export, source)));
            visit_ts_object_literal_properties(file, source, value, &code_unit, &code_unit, parsed);
        }
        // `export default name` points at an existing binding; indexing `default`
        // here would duplicate that declaration instead of describing new code.
        _ => {}
    }
}

fn visit_ts_default_export_function(
    file: &ProjectFile,
    source: &str,
    export: Node<'_>,
    function: Node<'_>,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> CodeUnit {
    let code_unit = add_ts_default_export_unit(
        file,
        source,
        export,
        crate::analyzer::CodeUnitType::Function,
        parsed,
    );
    parsed.add_signature_with_metadata(
        code_unit.clone(),
        SignatureMetadata::with_parameter_labels(
            ts_default_export_function_signature(function, source),
            ts_parameter_labels(function, source),
        ),
    );
    visit_ts_return_object_literal_properties(
        file, source, function, &code_unit, &code_unit, parsed,
    );
    code_unit
}

fn visit_ts_default_export_class(
    file: &ProjectFile,
    source: &str,
    export: Node<'_>,
    class: Node<'_>,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> CodeUnit {
    let code_unit = add_ts_default_export_unit(
        file,
        source,
        export,
        crate::analyzer::CodeUnitType::Class,
        parsed,
    );
    parsed.add_signature(
        code_unit.clone(),
        ts_default_export_class_signature(export, source),
    );
    let supertypes = extract_ts_supertypes(class, source);
    if !supertypes.is_empty() {
        parsed.set_raw_supertypes(code_unit.clone(), supertypes);
    }
    let _nested = visit_ts_class_like_body(file, source, class, &code_unit, &code_unit, parsed);
    code_unit
}

fn add_ts_default_export_unit(
    file: &ProjectFile,
    source: &str,
    export: Node<'_>,
    kind: crate::analyzer::CodeUnitType,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> CodeUnit {
    let code_unit = CodeUnit::new(file.clone(), kind, "", "default");
    parsed.add_code_unit(
        code_unit.clone(),
        export,
        source,
        None,
        Some(code_unit.clone()),
    );
    code_unit
}

fn visit_ts_class_like(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
    exported: bool,
) -> Option<CodeUnit> {
    let mut first = None;
    let mut stack = vec![(node, parent.cloned(), exported)];
    while let Some((node, parent, exported)) = stack.pop() {
        let definition = if node.kind() == "export_statement" {
            node.child_by_field_name("declaration").unwrap_or(node)
        } else {
            node
        };
        let Some(name_node) = definition.child_by_field_name("name") else {
            continue;
        };
        let name = trim_statement(node_text(name_node, source));
        if name.is_empty() {
            continue;
        }
        let short_name = parent
            .as_ref()
            .map(|parent| format!("{}.{}", parent.short_name(), name))
            .unwrap_or(name.clone());
        let code_unit = CodeUnit::new(
            file.clone(),
            crate::analyzer::CodeUnitType::Class,
            "",
            short_name,
        );
        if first.is_none() {
            first = Some(code_unit.clone());
        }
        let top_level = parent.clone().unwrap_or_else(|| code_unit.clone());
        let range_node = if exported { node } else { definition };
        parsed.add_code_unit(
            code_unit.clone(),
            range_node,
            source,
            parent.clone(),
            Some(top_level.clone()),
        );
        parsed.add_signature(
            code_unit.clone(),
            ts_class_signature(node, source, exported),
        );
        let supertypes = extract_ts_supertypes(definition, source);
        if !supertypes.is_empty() {
            parsed.set_raw_supertypes(code_unit.clone(), supertypes);
        }

        if definition.kind() == "enum_declaration" {
            if let Some(body) = definition.child_by_field_name("body") {
                for index in 0..body.named_child_count() {
                    let Some(child) = body.named_child(index) else {
                        continue;
                    };
                    if child.kind() == "enum_assignment"
                        || child.kind() == "property_identifier"
                        || child.kind() == "identifier"
                    {
                        visit_ts_enum_member(file, source, child, &code_unit, &top_level, parsed);
                    }
                }
            }
            continue;
        }

        let nested_class_like =
            visit_ts_class_like_body(file, source, definition, &code_unit, &top_level, parsed);
        stack.extend(
            nested_class_like
                .into_iter()
                .rev()
                .map(|child| (child, Some(code_unit.clone()), false)),
        );
    }
    first
}

fn visit_ts_class_like_body<'tree>(
    file: &ProjectFile,
    source: &str,
    class_like: Node<'tree>,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> Vec<Node<'tree>> {
    let Some(body) = class_like.child_by_field_name("body") else {
        return Vec::new();
    };
    let mut nested_class_like = Vec::new();
    for index in 0..body.named_child_count() {
        let Some(child) = body.named_child(index) else {
            continue;
        };
        match child.kind() {
            "method_definition" | "method_signature" | "abstract_method_signature" => {
                visit_ts_method(file, source, child, parent, top_level, parsed);
            }
            "public_field_definition" | "property_signature" | "index_signature" => {
                visit_ts_field(file, source, child, parent, top_level, parsed);
            }
            "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "internal_module" => {
                nested_class_like.push(child);
            }
            _ => {}
        }
    }
    nested_class_like
}

fn visit_ts_function(
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
    let Some(name_node) = definition.child_by_field_name("name") else {
        return;
    };
    let name = trim_statement(node_text(name_node, source));
    if name.is_empty() {
        return;
    }
    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), name))
        .unwrap_or(name);
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
        Some(top_level.clone()),
    );
    let signature = ts_function_signature(node, source, exported);
    parsed.add_signature_with_metadata(
        code_unit.clone(),
        SignatureMetadata::with_parameter_labels(
            signature,
            ts_parameter_labels(definition, source),
        ),
    );
    visit_ts_return_object_literal_properties(
        file, source, definition, &code_unit, &top_level, parsed,
    );
}

fn visit_ts_value(
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

    if definition.kind() == "type_alias_declaration" {
        let Some(name_node) = definition.child_by_field_name("name") else {
            return;
        };
        let name = trim_statement(node_text(name_node, source));
        let short_name = parent
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
            });
        let code_unit = CodeUnit::new(
            file.clone(),
            crate::analyzer::CodeUnitType::Field,
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
        parsed.add_signature(code_unit.clone(), trim_statement(node_text(node, source)));
        parsed.mark_type_alias(code_unit.clone());
        visit_ts_type_alias_members(file, source, definition, &code_unit, &top_level, parsed);
        return;
    }

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
        let name = trim_statement(node_text(name_node, source));
        let value = child.child_by_field_name("value");
        let is_function = value
            .map(|value| value.kind() == "arrow_function")
            .unwrap_or(false);
        let module_surface = parent.is_none()
            && (exported || exported_roots.contains(&name))
            && value.is_some_and(|value| {
                ts_exported_surface_object_literal_value(child, value, source).is_some()
            });
        let kind = if is_function {
            crate::analyzer::CodeUnitType::Function
        } else {
            crate::analyzer::CodeUnitType::Field
        };
        let short_name = if kind == crate::analyzer::CodeUnitType::Field {
            if let Some(parent) = parent {
                format!("{}.{}", parent.short_name(), name)
            } else if module_surface {
                name.clone()
            } else {
                {
                    format!(
                        "{}.{}",
                        file.rel_path()
                            .file_name()
                            .and_then(|name| name.to_str())
                            .unwrap_or("module"),
                        name
                    )
                }
            }
        } else {
            parent
                .map(|parent| format!("{}.{}", parent.short_name(), name))
                .unwrap_or(name)
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
            let signature = ts_variable_function_signature(definition, child, source, exported);
            if let Some(value) = value {
                parsed.add_signature_with_metadata(
                    code_unit.clone(),
                    SignatureMetadata::with_parameter_labels(
                        signature,
                        ts_parameter_labels(value, source),
                    ),
                );
                visit_ts_return_object_literal_properties(
                    file, source, value, &code_unit, &top_level, parsed,
                );
            } else {
                parsed.add_signature(code_unit.clone(), signature);
            }
        } else {
            parsed.add_signature(
                code_unit.clone(),
                ts_variable_signature(definition, child, source, exported),
            );
        }
        if !is_function
            && let Some(value) = value
            && let Some(object) = if module_surface {
                ts_exported_surface_object_literal_value(child, value, source)
            } else {
                ts_indexable_object_literal_value(child, value, source)
            }
        {
            visit_ts_object_literal_properties(
                file, source, object, &code_unit, &top_level, parsed,
            );
        }
    }
}

fn visit_ts_type_alias_members(
    file: &ProjectFile,
    source: &str,
    definition: Node<'_>,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let Some(value) = definition.child_by_field_name("value") else {
        return;
    };
    let container = value.child_by_field_name("body").unwrap_or(value);
    for index in 0..container.named_child_count() {
        let Some(child) = container.named_child(index) else {
            continue;
        };
        match child.kind() {
            "method_signature" | "abstract_method_signature" => {
                visit_ts_method(file, source, child, parent, top_level, parsed);
            }
            "property_signature" | "index_signature" => {
                visit_ts_field(file, source, child, parent, top_level, parsed);
            }
            _ => {}
        }
    }
}

fn ts_indexable_object_literal_value<'tree>(
    declarator: Node<'tree>,
    value: Node<'tree>,
    source: &str,
) -> Option<Node<'tree>> {
    ts_object_literal_value(value).or_else(|| {
        (value.kind() == "call_expression")
            .then(|| ts_shape_preserving_call_object_argument(declarator, value, source))
            .flatten()
    })
}

fn ts_exported_surface_object_literal_value<'tree>(
    declarator: Node<'tree>,
    value: Node<'tree>,
    source: &str,
) -> Option<Node<'tree>> {
    ts_object_literal_value(value).or_else(|| {
        (value.kind() == "call_expression")
            .then(|| ts_surface_call_object_argument(declarator, value, source))
            .flatten()
    })
}

fn ts_object_literal_value(node: Node<'_>) -> Option<Node<'_>> {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "object" => return Some(node),
            "parenthesized_expression"
            | "as_expression"
            | "satisfies_expression"
            | "type_assertion" => {
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

fn ts_shape_preserving_call_object_argument<'tree>(
    anchor: Node<'tree>,
    call: Node<'tree>,
    source: &str,
) -> Option<Node<'tree>> {
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .enumerate()
        .find_map(|(index, argument)| {
            let object = ts_object_literal_value(argument)?;
            ts_call_preserves_object_argument_shape(anchor, call, source, index).then_some(object)
        })
}

fn ts_call_preserves_object_argument_shape(
    anchor: Node<'_>,
    call: Node<'_>,
    source: &str,
    argument_index: usize,
) -> bool {
    if argument_index == 0 && ts_call_is_schema_object_builder(call, source) {
        return true;
    }
    ts_call_object_argument_shape_preservation(anchor, call, source, argument_index)
        == TsShapePreservation::Preserves
}

/// Recognizes a schema-builder call whose first object-literal argument defines the value's
/// navigable shape, e.g. zod's `z.object({ ... })`. Schema libraries (zod, yup, valibot,
/// superstruct, ...) universally expose this via an `object(...)` builder, so we match the
/// `object` member-name convention rather than a specific import alias — `z` is only a
/// conventional name and breaks under `import * as zod` or aliased imports.
fn ts_call_is_schema_object_builder(call: Node<'_>, source: &str) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    if function.kind() != "member_expression" {
        return false;
    }
    let Some(property) = function.child_by_field_name("property") else {
        return false;
    };
    node_text(property, source).trim() == "object"
}

fn ts_call_identifier_name(call: Node<'_>, source: &str) -> Option<String> {
    let function = call.child_by_field_name("function")?;
    matches!(function.kind(), "identifier" | "property_identifier")
        .then(|| node_text(function, source).trim().to_string())
        .filter(|name| !name.is_empty())
}

fn ts_source_function_preserves_parameter_shape(
    anchor: Node<'_>,
    source: &str,
    function_name: &str,
    parameter_index: usize,
) -> TsShapePreservation {
    let root = ts_root_node(anchor);
    let mut functions = Vec::new();
    ts_collect_function_nodes(root, source, function_name, &mut functions);
    if functions.is_empty() {
        return TsShapePreservation::Unknown;
    }
    if functions.into_iter().any(|function| {
        ts_function_node_preserves_parameter_shape(function, source, parameter_index)
    }) {
        TsShapePreservation::Preserves
    } else {
        TsShapePreservation::DoesNotPreserve
    }
}

fn ts_surface_call_object_argument<'tree>(
    anchor: Node<'tree>,
    call: Node<'tree>,
    source: &str,
) -> Option<Node<'tree>> {
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .enumerate()
        .find_map(|(index, argument)| {
            let object = ts_object_literal_value(argument)?;
            ts_surface_call_preserves_object_argument_shape(anchor, call, source, index)
                .then_some(object)
        })
}

fn ts_surface_call_preserves_object_argument_shape(
    anchor: Node<'_>,
    call: Node<'_>,
    source: &str,
    argument_index: usize,
) -> bool {
    if argument_index == 0 && ts_call_is_schema_object_builder(call, source) {
        return true;
    }
    match ts_call_object_argument_shape_preservation(anchor, call, source, argument_index) {
        TsShapePreservation::Preserves => true,
        TsShapePreservation::DoesNotPreserve => false,
        TsShapePreservation::Unknown => ts_call_has_likely_surface_factory_name(call, source),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TsShapePreservation {
    Preserves,
    DoesNotPreserve,
    Unknown,
}

fn ts_call_object_argument_shape_preservation(
    anchor: Node<'_>,
    call: Node<'_>,
    source: &str,
    argument_index: usize,
) -> TsShapePreservation {
    let Some(callee_name) = ts_call_identifier_name(call, source) else {
        return TsShapePreservation::Unknown;
    };
    ts_source_function_preserves_parameter_shape(anchor, source, &callee_name, argument_index)
}

fn ts_call_has_likely_surface_factory_name(call: Node<'_>, source: &str) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    let name = match function.kind() {
        "identifier" | "property_identifier" => node_text(function, source).trim(),
        "member_expression" => function
            .child_by_field_name("property")
            .map(|property| node_text(property, source).trim())
            .unwrap_or(""),
        _ => "",
    };
    name == "define" || name.starts_with("define") || name == "object"
}

fn ts_root_node(mut node: Node<'_>) -> Node<'_> {
    while let Some(parent) = node.parent() {
        node = parent;
    }
    node
}

fn ts_collect_function_nodes<'tree>(
    node: Node<'tree>,
    source: &str,
    function_name: &str,
    out: &mut Vec<Node<'tree>>,
) {
    walk_named_tree_preorder(node, true, |node| {
        if node.kind() == "function_declaration"
            && node
                .child_by_field_name("name")
                .is_some_and(|name| node_text(name, source).trim() == function_name)
        {
            out.push(node);
            return WalkControl::SkipChildren;
        }
        if node.kind() == "variable_declarator"
            && node
                .child_by_field_name("name")
                .is_some_and(|name| node_text(name, source).trim() == function_name)
            && let Some(value) = node.child_by_field_name("value")
            && matches!(value.kind(), "arrow_function" | "function_expression")
        {
            out.push(value);
            return WalkControl::SkipChildren;
        }
        WalkControl::Continue
    });
}

fn ts_function_node_preserves_parameter_shape(
    function: Node<'_>,
    source: &str,
    parameter_index: usize,
) -> bool {
    let Some(parameter_name) = ts_function_parameter_name(function, source, parameter_index) else {
        return false;
    };
    if function.kind() == "arrow_function"
        && let Some(body) = function.child_by_field_name("body")
        && ts_expression_preserves_parameter_shape(body, source, &parameter_name)
    {
        return true;
    }
    ts_function_returns_parameter_shape(function, function.id(), source, &parameter_name)
}

fn ts_function_parameter_name(
    function: Node<'_>,
    source: &str,
    parameter_index: usize,
) -> Option<String> {
    let parameters = function.child_by_field_name("parameters")?;
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .filter_map(ts_parameter_name_node)
        .nth(parameter_index)
        .map(|name| node_text(name, source).trim().to_string())
        .filter(|name| !name.is_empty())
}

fn ts_parameter_name_node(parameter: Node<'_>) -> Option<Node<'_>> {
    match parameter.kind() {
        "identifier" | "shorthand_property_identifier_pattern" => Some(parameter),
        "required_parameter" | "optional_parameter" => parameter
            .child_by_field_name("pattern")
            .or_else(|| parameter.child_by_field_name("name")),
        _ => None,
    }
}

fn ts_parameter_labels(function: Node<'_>, source: &str) -> Vec<String> {
    let Some(parameters) = function.child_by_field_name("parameters") else {
        return Vec::new();
    };
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .filter_map(ts_parameter_name_node)
        .filter_map(|name| {
            let label = node_text(name, source).trim();
            (!label.is_empty()).then(|| label.to_string())
        })
        .collect()
}

fn ts_function_returns_parameter_shape(
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
                    | "abstract_class_declaration"
                    | "interface_declaration"
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
                    ts_expression_preserves_parameter_shape(expression, source, parameter_name)
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

fn ts_expression_preserves_parameter_shape(
    expression: Node<'_>,
    source: &str,
    parameter_name: &str,
) -> bool {
    let Some(expression) = ts_object_shape_expression(expression) else {
        return false;
    };
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
                .and_then(ts_object_shape_expression)
                .is_some_and(|spread| node_text(spread, source).trim() == parameter_name)
    })
}

fn ts_object_shape_expression(node: Node<'_>) -> Option<Node<'_>> {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "as_expression" | "satisfies_expression" | "type_assertion" => {
                for index in (0..node.named_child_count()).rev() {
                    if let Some(child) = node.named_child(index) {
                        stack.push(child);
                    }
                }
            }
            _ => return Some(node),
        }
    }
    None
}

fn visit_ts_return_object_literal_properties(
    file: &ProjectFile,
    source: &str,
    function: Node<'_>,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let mut objects = Vec::new();
    collect_ts_return_object_literals(function, function.id(), &mut objects);
    for object in objects {
        visit_ts_object_literal_properties(file, source, object, parent, top_level, parsed);
    }
}

fn collect_ts_return_object_literals<'tree>(
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
                    | "abstract_class_declaration"
                    | "interface_declaration"
            )
        {
            continue;
        }

        if node.kind() == "return_statement" {
            let mut cursor = node.walk();
            if let Some(object) = node
                .named_children(&mut cursor)
                .find_map(ts_object_literal_value)
            {
                out.push(object);
            }
            continue;
        }

        if node.kind() == "arrow_function"
            && let Some(body) = node.child_by_field_name("body")
            && let Some(object) = ts_object_literal_value(body)
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

fn visit_ts_object_literal_properties(
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
        let Some(name) = ts_object_literal_property_name(child, source) else {
            continue;
        };
        let kind = if ts_object_literal_property_is_function(child) {
            crate::analyzer::CodeUnitType::Function
        } else {
            crate::analyzer::CodeUnitType::Field
        };
        let code_unit = CodeUnit::with_signature(
            file.clone(),
            kind,
            "",
            format!("{}.{}", parent.short_name(), name),
            None,
            true,
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

pub(in crate::analyzer) fn ts_object_literal_property_name(
    node: Node<'_>,
    source: &str,
) -> Option<String> {
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
    let name = trim_statement(node_text(key, source))
        .trim_matches('"')
        .trim_matches('\'')
        .to_string();
    (!name.is_empty()).then_some(name)
}

fn ts_object_literal_property_is_function(node: Node<'_>) -> bool {
    node.kind() == "method_definition"
        || node
            .child_by_field_name("value")
            .is_some_and(|value| matches!(value.kind(), "arrow_function" | "function_expression"))
}

fn ts_es_named_exported_roots(root: Node<'_>, source: &str) -> HashSet<String> {
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
            collect_ts_export_clause_roots(export_child, source, &mut roots);
        }
    }
    roots
}

fn collect_ts_export_clause_roots(node: Node<'_>, source: &str, roots: &mut HashSet<String>) {
    match node.kind() {
        "export_clause" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                collect_ts_export_clause_roots(child, source, roots);
            }
        }
        "export_specifier" => {
            let name = node
                .child_by_field_name("name")
                .or_else(|| node.named_child(0));
            if let Some(name) = name {
                collect_ts_export_identifier(name, source, roots);
            }
        }
        _ => {}
    }
}

fn collect_ts_export_identifier(node: Node<'_>, source: &str, roots: &mut HashSet<String>) {
    if matches!(
        node.kind(),
        "identifier" | "property_identifier" | "shorthand_property_identifier" | "type_identifier"
    ) {
        let name = node_text(node, source).trim();
        if !name.is_empty() {
            roots.insert(name.to_string());
        }
    }
}

fn visit_ts_method(
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
    let name = trim_statement(node_text(name_node, source))
        .trim_matches('"')
        .to_string();
    let member_name = if is_static_ts_member(node, source) {
        format!("{name}$static")
    } else {
        name
    };
    let code_unit = CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Function,
        "",
        format!("{}.{}", parent.short_name(), member_name),
    );
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        Some(parent.clone()),
        Some(top_level.clone()),
    );
    let signature = match node.kind() {
        "method_definition" => format!(
            "{} {{ ... }}",
            trim_statement(node_text(node, source).split('{').next().unwrap_or(""))
        ),
        _ => trim_statement(node_text(node, source).split('{').next().unwrap_or("")),
    };
    parsed.add_signature_with_metadata(
        code_unit,
        SignatureMetadata::with_parameter_labels(signature, ts_parameter_labels(node, source)),
    );
}

fn visit_ts_field(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let name_node = node.child_by_field_name("name").unwrap_or(node);
    let name = trim_statement(node_text(name_node, source))
        .trim_matches('"')
        .to_string();
    let member_name = if is_static_ts_member(node, source) {
        format!("{name}$static")
    } else {
        name
    };
    let code_unit = CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Field,
        "",
        format!("{}.{}", parent.short_name(), member_name),
    );
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        Some(parent.clone()),
        Some(top_level.clone()),
    );
    parsed.add_signature(code_unit, ts_field_signature(node, source));
}

fn visit_ts_enum_member(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let name = if node.kind() == "enum_assignment" {
        node.child_by_field_name("name")
            .map(|name| trim_statement(node_text(name, source)))
            .unwrap_or_default()
    } else {
        trim_statement(node_text(node, source))
    };
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
    let raw = trim_statement(node_text(node, source));
    let suffix = source
        .get(node.end_byte()..)
        .map(str::trim_start)
        .filter(|tail| tail.starts_with(','))
        .map(|_| ",")
        .unwrap_or("");
    parsed.add_signature(code_unit, format!("{raw}{suffix}"));
}

fn ts_class_signature(node: Node<'_>, source: &str, exported: bool) -> String {
    let definition = if node.kind() == "export_statement" {
        node.child_by_field_name("declaration").unwrap_or(node)
    } else {
        node
    };
    let text = if node.kind() == "export_statement" {
        node_text(node, source)
    } else {
        node_text(definition, source)
    };
    let head = trim_statement(text.split('{').next().unwrap_or(text));
    if definition.kind() == "enum_declaration" {
        let open = format!(
            "{} {{",
            if exported && !head.starts_with("export ") {
                format!("export {head}")
            } else {
                head
            }
        );
        return open;
    }
    format!(
        "{} {{",
        if exported && !head.starts_with("export ") {
            format!("export {head}")
        } else {
            head
        }
    )
}

fn ts_default_export_class_signature(export: Node<'_>, source: &str) -> String {
    let text = node_text(export, source);
    let head = trim_statement(text.split('{').next().unwrap_or(text));
    format!("{head} {{")
}

fn ts_function_signature(node: Node<'_>, source: &str, exported: bool) -> String {
    let definition = if node.kind() == "export_statement" {
        node.child_by_field_name("declaration").unwrap_or(node)
    } else {
        node
    };
    let head = trim_statement(
        if node.kind() == "export_statement" {
            node_text(node, source)
        } else {
            node_text(definition, source)
        }
        .split('{')
        .next()
        .unwrap_or(node_text(definition, source)),
    );
    let head = if exported && !head.starts_with("export ") {
        format!("export {head}")
    } else {
        head
    };
    if definition.kind() == "function_signature" {
        head
    } else {
        format!("{head} {{ ... }}")
    }
}

fn ts_default_export_function_signature(function: Node<'_>, source: &str) -> String {
    let text = node_text(function, source);
    let async_prefix = if text.trim_start().starts_with("async ") {
        "async "
    } else {
        ""
    };
    let params = function
        .child_by_field_name("parameters")
        .map(|node| trim_statement(node_text(node, source)))
        .unwrap_or_else(|| "()".to_string());
    let return_type = function
        .child_by_field_name("return_type")
        .map(|node| trim_statement(node_text(node, source)))
        .unwrap_or_default();
    let return_suffix = if return_type.is_empty() {
        String::new()
    } else {
        format!(": {}", return_type.trim_start_matches(':').trim())
    };
    match function.kind() {
        "function_declaration" | "function_expression" => {
            format!("export default {async_prefix}function{params}{return_suffix} {{ ... }}")
        }
        "generator_function" => {
            format!("export default {async_prefix}function*{params}{return_suffix} {{ ... }}")
        }
        _ => format!("export default {async_prefix}{params}{return_suffix} => {{ ... }}"),
    }
}

fn ts_variable_function_signature(
    statement: Node<'_>,
    declarator: Node<'_>,
    source: &str,
    exported: bool,
) -> String {
    let kind = statement
        .child(0)
        .map(|node| node_text(node, source).trim().to_string())
        .unwrap_or_else(|| "const".to_string());
    let name = declarator
        .child_by_field_name("name")
        .map(|node| trim_statement(node_text(node, source)))
        .unwrap_or_default();
    let value = declarator
        .child_by_field_name("value")
        .unwrap_or(declarator);
    let params = value
        .child_by_field_name("parameters")
        .map(|node| trim_statement(node_text(node, source)))
        .unwrap_or_else(|| "()".to_string());
    let return_type = value
        .child_by_field_name("return_type")
        .map(|node| trim_statement(node_text(node, source)))
        .unwrap_or_default();
    let export_prefix = if exported { "export " } else { "" };
    let return_suffix = if return_type.is_empty() {
        String::new()
    } else {
        format!(": {}", return_type.trim_start_matches(':').trim())
    };
    format!("{export_prefix}{kind} {name} = {params}{return_suffix} => {{ ... }}")
}

fn ts_variable_signature(
    statement: Node<'_>,
    declarator: Node<'_>,
    source: &str,
    exported: bool,
) -> String {
    let header = ts_variable_header(statement, declarator, source, exported);
    match declarator.child_by_field_name("value") {
        Some(value) if is_simple_ts_initializer(value) => {
            let value_text = trim_statement(node_text(value, source));
            format!("{header} = {value_text}")
        }
        _ => header,
    }
}

fn ts_field_signature(node: Node<'_>, source: &str) -> String {
    if matches!(node.kind(), "property_signature" | "index_signature") {
        return trim_statement(node_text(node, source));
    }

    let raw = trim_statement(node_text(node, source));
    if let Some(value) = node.child_by_field_name("value")
        && !is_simple_ts_initializer(value)
    {
        return raw
            .split('=')
            .next()
            .map(trim_statement)
            .filter(|header| !header.is_empty())
            .unwrap_or(raw);
    }
    raw
}

fn ts_variable_header(
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

fn is_simple_ts_initializer(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "string"
            | "number"
            | "true"
            | "false"
            | "null"
            | "undefined"
            | "template_string"
            | "unary_expression"
            | "binary_expression"
            | "identifier"
            | "member_expression"
    )
}

fn is_static_ts_member(node: Node<'_>, source: &str) -> bool {
    let head = node_text(node, source)
        .split(['{', ';'])
        .next()
        .unwrap_or("");
    head.split_whitespace().any(|token| token == "static")
}
