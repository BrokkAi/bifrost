use crate::analyzer::clone_detection::{
    CloneCandidateData, CloneCandidateProfile, compact_clone_excerpt,
    compute_ast_refinement_similarity_percent, detect_structural_clone_smells,
};
use crate::analyzer::{
    AnalyzerConfig, CodeUnit, CodeUnitType, IAnalyzer, ImportAnalysisProvider, ImportInfo,
    Language, LanguageAdapter, Project, ProjectFile, TestAssertionSmell, TestAssertionWeights,
    TestDetectionProvider, TreeSitterAnalyzer, build_reverse_import_index,
};
use crate::hash::{HashMap, HashSet};
use crate::{CloneSmell, CloneSmellWeights};
use moka::sync::Cache;
use regex::Regex;
use std::collections::BTreeSet;
use std::mem::size_of;
use std::sync::{Arc, LazyLock, OnceLock};
use tree_sitter::{Language as TsLanguage, Node, Parser, Tree};

use super::javascript_analyzer::build_weighted_cache;

#[derive(Debug, Clone, Default)]
pub struct CSharpAdapter;

impl LanguageAdapter for CSharpAdapter {
    fn language(&self) -> Language {
        Language::CSharp
    }

    fn query_directory(&self) -> &'static str {
        "resources/treesitter/c_sharp"
    }

    fn parser_language(&self) -> TsLanguage {
        tree_sitter_c_sharp::LANGUAGE.into()
    }

    fn file_extension(&self) -> &'static str {
        "cs"
    }

    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        _tree: &Tree,
        _parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        csharp_contains_tests(source)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        let trimmed = reference.trim();
        let before_args = trimmed
            .split_once('(')
            .map(|(head, _)| head)
            .unwrap_or(trimmed);
        before_args
            .rsplit_once('.')
            .map(|(receiver, _)| receiver.to_string())
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
        let mut parsed = crate::analyzer::tree_sitter_analyzer::ParsedFile::new(String::new());
        collect_csharp_type_identifiers(tree.root_node(), source, &mut parsed.type_identifiers);
        let mut visitor = CSharpVisitor {
            file,
            source,
            parsed: &mut parsed,
        };
        visitor.visit_container(tree.root_node(), "", None);
        parsed
    }
}

#[derive(Clone)]
pub struct CSharpAnalyzer {
    inner: TreeSitterAnalyzer<CSharpAdapter>,
    memo_caches: Arc<CSharpMemoCaches>,
}

#[derive(Clone)]
struct CSharpMemoCaches {
    budget_bytes: u64,
    using_namespaces: Cache<ProjectFile, Arc<Vec<String>>>,
    imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    reverse_import_index: OnceLock<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>,
    global_using_namespaces: OnceLock<HashSet<String>>,
}

impl CSharpMemoCaches {
    fn new(budget_bytes: u64) -> Self {
        Self {
            budget_bytes,
            using_namespaces: build_weighted_cache(budget_bytes / 8, weight_string_vec),
            imported_code_units: build_weighted_cache(budget_bytes / 4, weight_code_unit_set),
            referencing_files: build_weighted_cache(budget_bytes / 8, weight_project_file_set),
            reverse_import_index: OnceLock::new(),
            global_using_namespaces: OnceLock::new(),
        }
    }

    fn budget_bytes(&self) -> u64 {
        self.budget_bytes
    }
}

impl CSharpAnalyzer {
    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        Self {
            inner: TreeSitterAnalyzer::new_with_config(project, CSharpAdapter, config),
            memo_caches: Arc::new(CSharpMemoCaches::new(memo_budget)),
        }
    }

    pub fn new_with_config_and_storage(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        storage: Arc<crate::analyzer::persistence::AnalyzerStorage>,
    ) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        Self {
            inner: TreeSitterAnalyzer::new_with_config_and_storage(
                project,
                CSharpAdapter,
                config,
                storage,
            ),
            memo_caches: Arc::new(CSharpMemoCaches::new(memo_budget)),
        }
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }

    pub fn namespace_of_file(&self, file: &ProjectFile) -> String {
        let package = self.inner.package_name_of(file).unwrap_or("");
        if !package.is_empty() {
            return package.to_string();
        }
        self.get_declarations(file)
            .into_iter()
            .map(|unit| unit.package_name().to_string())
            .find(|package| !package.is_empty())
            .unwrap_or_default()
    }

    pub fn using_namespaces_of(&self, file: &ProjectFile) -> Vec<String> {
        if let Some(cached) = self.memo_caches.using_namespaces.get(file) {
            return (*cached).clone();
        }

        let mut namespaces: Vec<String> = self
            .inner
            .import_info_of(file)
            .iter()
            .filter_map(|import| csharp_using_namespace(&import.raw_snippet))
            .collect();
        for namespace in self.global_using_namespaces() {
            if !namespaces.contains(namespace) {
                namespaces.push(namespace.clone());
            }
        }
        self.memo_caches
            .using_namespaces
            .insert(file.clone(), Arc::new(namespaces.clone()));
        namespaces
    }

    fn global_using_namespaces(&self) -> &HashSet<String> {
        self.memo_caches.global_using_namespaces.get_or_init(|| {
            self.inner
                .all_files()
                .flat_map(|file| self.inner.import_info_of(file).iter())
                .filter(|import| import.raw_snippet.trim_start().starts_with("global using "))
                .filter_map(|import| csharp_using_namespace(&import.raw_snippet))
                .collect()
        })
    }

    pub fn visible_type_candidates(&self, file: &ProjectFile, name: &str) -> Vec<CodeUnit> {
        let mut namespaces = self.using_namespaces_of(file);
        let file_namespace = self.namespace_of_file(file);
        if !file_namespace.is_empty() {
            namespaces.push(file_namespace);
        }

        self.get_all_declarations()
            .into_iter()
            .filter(|unit| unit.kind() == CodeUnitType::Class)
            .filter(|unit| {
                csharp_type_name_matches(unit, name)
                    || namespaces.iter().any(|namespace| {
                        unit.package_name() == namespace && unit.identifier() == name
                    })
            })
            .collect()
    }

    pub fn resolve_visible_type(&self, file: &ProjectFile, name: &str) -> Option<CodeUnit> {
        let mut candidates = self.visible_type_candidates(file, name);
        candidates.sort_by_key(CodeUnit::fq_name);
        candidates.dedup();
        (candidates.len() == 1).then(|| candidates.remove(0))
    }
}

impl TestDetectionProvider for CSharpAnalyzer {}

impl ImportAnalysisProvider for CSharpAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> HashSet<CodeUnit> {
        if let Some(cached) = self.memo_caches.imported_code_units.get(file) {
            return (*cached).clone();
        }
        let namespaces = self.using_namespaces_of(file);
        if namespaces.is_empty() {
            return HashSet::default();
        }
        let imported: HashSet<CodeUnit> = self
            .get_all_declarations()
            .into_iter()
            .filter(|unit| unit.kind() == CodeUnitType::Class)
            .filter(|unit| {
                namespaces
                    .iter()
                    .any(|namespace| unit.package_name() == namespace)
            })
            .collect();
        self.memo_caches
            .imported_code_units
            .insert(file.clone(), Arc::new(imported.clone()));
        imported
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        if let Some(cached) = self.memo_caches.referencing_files.get(file) {
            return (*cached).clone();
        }
        let target_namespaces: HashSet<String> = self
            .get_declarations(file)
            .into_iter()
            .filter(|unit| unit.kind() == CodeUnitType::Class)
            .map(|unit| unit.package_name().to_string())
            .collect();
        if target_namespaces.is_empty() {
            return HashSet::default();
        }
        let target_identifiers: HashSet<String> = self
            .get_declarations(file)
            .into_iter()
            .filter(|unit| unit.kind() == CodeUnitType::Class)
            .map(|unit| unit.identifier().to_string())
            .collect();
        let target_fq_names: HashSet<String> = self
            .get_declarations(file)
            .into_iter()
            .filter(|unit| unit.kind() == CodeUnitType::Class)
            .flat_map(|unit| [unit.fq_name(), unit.fq_name().replace('$', ".")])
            .collect();

        let reverse_index = self.memo_caches.reverse_import_index.get_or_init(|| {
            let files: Vec<_> = self.inner.all_files().cloned().collect();
            build_reverse_import_index(&files, |candidate| self.imported_code_units_of(candidate))
        });
        let mut result = reverse_index
            .get(file)
            .map(|files| (**files).clone())
            .unwrap_or_default();

        for candidate in self.inner.all_files() {
            if candidate == file || result.contains(candidate) {
                continue;
            }
            let Some(identifiers) = self.inner.type_identifiers_of(candidate) else {
                continue;
            };
            let candidate_namespace = self.namespace_of_file(candidate);
            let same_namespace = target_namespaces
                .iter()
                .any(|namespace| namespace == &candidate_namespace);
            if same_namespace
                && identifiers
                    .iter()
                    .any(|name| target_identifiers.contains(name))
            {
                result.insert(candidate.clone());
                continue;
            }
            if identifiers
                .iter()
                .any(|name| target_fq_names.contains(name))
            {
                result.insert(candidate.clone());
            }
        }

        self.memo_caches
            .referencing_files
            .insert(file.clone(), Arc::new(result.clone()));
        result
    }

    fn import_info_of<'a>(&'a self, file: &ProjectFile) -> &'a [crate::analyzer::ImportInfo] {
        self.inner.import_info_of(file)
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[crate::analyzer::ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        if self.namespace_of_file(source_file) == self.namespace_of_file(target) {
            return true;
        }
        let target_namespaces: HashSet<String> = self
            .get_declarations(target)
            .into_iter()
            .filter(|unit| unit.kind() == CodeUnitType::Class)
            .map(|unit| unit.package_name().to_string())
            .collect();
        let source_imports = self.using_namespaces_of(source_file);
        imports
            .iter()
            .filter_map(|import| csharp_using_namespace(&import.raw_snippet))
            .chain(source_imports)
            .any(|namespace| target_namespaces.contains(&namespace))
    }
}

impl IAnalyzer for CSharpAnalyzer {
    fn top_level_declarations<'a>(
        &'a self,
        file: &ProjectFile,
    ) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a> {
        self.inner.top_level_declarations(file)
    }

    fn analyzed_files<'a>(&'a self) -> Box<dyn Iterator<Item = &'a ProjectFile> + 'a> {
        self.inner.analyzed_files()
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
        Self {
            inner: self.inner.update(changed_files),
            memo_caches: Arc::new(CSharpMemoCaches::new(self.memo_caches.budget_bytes())),
        }
    }

    fn update_all(&self) -> Self {
        Self {
            inner: self.inner.update_all(),
            memo_caches: Arc::new(CSharpMemoCaches::new(self.memo_caches.budget_bytes())),
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
        self.inner.search_definitions_persisted(pattern)
    }

    fn signatures_of(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.inner.signatures_of(code_unit).to_vec()
    }

    fn contains_tests(&self, file: &ProjectFile) -> bool {
        self.inner.contains_tests(file)
    }

    fn find_test_assertion_smells(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
    ) -> Vec<TestAssertionSmell> {
        if !self.contains_tests(file) || file_language(file) != Language::CSharp {
            return Vec::new();
        }
        let Ok(source) = self.inner.project().read_source(file) else {
            return Vec::new();
        };
        detect_csharp_test_assertion_smells(file, &source, &weights)
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
            .filter(|file| file_language(file) == Language::CSharp)
            .cloned()
            .collect();
        if requested_files.is_empty() {
            return Vec::new();
        }

        let all_candidates: Vec<CloneCandidateProfile> = self
            .get_all_declarations()
            .into_iter()
            .filter(|code_unit| {
                code_unit.is_function() && file_language(code_unit.source()) == Language::CSharp
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
            refine_csharp_clone_similarity,
        )
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        Some(self)
    }

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        Some(self)
    }
}

impl CSharpAnalyzer {
    fn build_clone_candidate_data(
        &self,
        code_unit: &CodeUnit,
        weights: CloneSmellWeights,
    ) -> Option<CloneCandidateData> {
        self.get_source(code_unit, false)
            .map(|source| source.trim().to_string())
            .filter(|source| !source.is_empty())
            .and_then(|source| {
                let normalized_tokens = normalized_clone_tokens_csharp(&source);
                if normalized_tokens.len() < weights.min_normalized_tokens.max(0) as usize {
                    return None;
                }
                Some(CloneCandidateData {
                    unit: code_unit.clone(),
                    normalized_tokens,
                    ast_signature: build_csharp_clone_ast_signature(&source),
                    excerpt: compact_clone_excerpt(&source),
                })
            })
    }
}

#[derive(Clone)]
struct CSharpScope {
    package_name: String,
    class_unit: Option<CodeUnit>,
}

struct CSharpVisitor<'a> {
    file: &'a ProjectFile,
    source: &'a str,
    parsed: &'a mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
}

impl<'a> CSharpVisitor<'a> {
    fn visit_container(
        &mut self,
        node: Node<'_>,
        package_name: &str,
        class_unit: Option<CodeUnit>,
    ) {
        let scope = CSharpScope {
            package_name: package_name.to_string(),
            class_unit,
        };
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            self.visit_node(child, &scope);
        }
    }

    fn visit_node(&mut self, node: Node<'_>, scope: &CSharpScope) {
        match node.kind() {
            "namespace_declaration" | "file_scoped_namespace_declaration" => {
                self.visit_namespace(node, scope)
            }
            "class_declaration"
            | "interface_declaration"
            | "struct_declaration"
            | "record_declaration"
            | "record_struct_declaration" => self.visit_type_declaration(node, scope),
            "method_declaration" => self.visit_method(node, scope),
            "constructor_declaration" => self.visit_constructor(node, scope),
            "property_declaration" => self.visit_property(node, scope),
            "field_declaration" => self.visit_field_declaration(node, scope),
            "using_directive" => self.visit_using_directive(node),
            _ => {}
        }
    }

    fn visit_using_directive(&mut self, node: Node<'_>) {
        let raw = cs_node_text(node, self.source).trim().to_string();
        if raw.is_empty() {
            return;
        }
        self.parsed.import_statements.push(raw.clone());
        if csharp_using_namespace(&raw).is_some() {
            self.parsed.imports.push(csharp_import_info(raw));
        }
    }

    fn visit_namespace(&mut self, node: Node<'_>, scope: &CSharpScope) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let raw_name = cs_node_text(name_node, self.source).trim();
        if raw_name.is_empty() {
            return;
        }
        let package_name = if scope.package_name.is_empty() {
            raw_name.to_string()
        } else {
            format!("{}.{}", scope.package_name, raw_name)
        };
        if let Some(body) = cs_namespace_body(node) {
            self.visit_container(body, &package_name, scope.class_unit.clone());
        }
    }

    fn visit_type_declaration(&mut self, node: Node<'_>, scope: &CSharpScope) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = cs_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }

        let short_name = if let Some(parent) = &scope.class_unit {
            format!("{}${name}", parent.short_name())
        } else {
            name.to_string()
        };
        let code_unit = CodeUnit::new(
            self.file.clone(),
            CodeUnitType::Class,
            scope.package_name.clone(),
            short_name,
        );
        if self.parsed.declarations.contains(&code_unit) {
            return;
        }
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            scope.class_unit.clone(),
            None,
        );
        self.parsed
            .add_signature(code_unit.clone(), csharp_type_signature(node, self.source));

        if let Some(body) = cs_type_body(node) {
            self.visit_container(body, &scope.package_name, Some(code_unit));
        }
    }

    fn visit_method(&mut self, node: Node<'_>, scope: &CSharpScope) {
        let Some(parent) = &scope.class_unit else {
            return;
        };
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = cs_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }
        let signature_key = csharp_parameter_key(node, self.source);
        let code_unit = CodeUnit::with_signature(
            self.file.clone(),
            CodeUnitType::Function,
            scope.package_name.clone(),
            format!("{}.{}", parent.short_name(), name),
            Some(signature_key),
            false,
        );
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            Some(parent.clone()),
            None,
        );
        self.parsed
            .add_signature(code_unit, csharp_method_skeleton(node, self.source));
    }

    fn visit_constructor(&mut self, node: Node<'_>, scope: &CSharpScope) {
        let Some(parent) = &scope.class_unit else {
            return;
        };
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = cs_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }
        let code_unit = CodeUnit::with_signature(
            self.file.clone(),
            CodeUnitType::Function,
            scope.package_name.clone(),
            format!("{}.{}", parent.short_name(), name),
            Some(csharp_parameter_key(node, self.source)),
            false,
        );
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            Some(parent.clone()),
            None,
        );
        self.parsed
            .add_signature(code_unit, csharp_constructor_skeleton(node, self.source));
    }

    fn visit_property(&mut self, node: Node<'_>, scope: &CSharpScope) {
        let Some(parent) = &scope.class_unit else {
            return;
        };
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = cs_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }
        let code_unit = CodeUnit::new(
            self.file.clone(),
            CodeUnitType::Field,
            scope.package_name.clone(),
            format!("{}.{}", parent.short_name(), name),
        );
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            Some(parent.clone()),
            None,
        );
        self.parsed
            .add_signature(code_unit, csharp_property_signature(node, self.source));
    }

    fn visit_field_declaration(&mut self, node: Node<'_>, scope: &CSharpScope) {
        let Some(parent) = &scope.class_unit else {
            return;
        };
        let Some(declaration) = node
            .child_by_field_name("declaration")
            .or_else(|| first_named_child_of_kind(node, "variable_declaration"))
        else {
            return;
        };

        let prefix = csharp_field_prefix(node, declaration, self.source);
        let type_text = declaration
            .child_by_field_name("type")
            .map(|child| normalize_cs_whitespace(cs_node_text(child, self.source)))
            .unwrap_or_default();
        let declaration_text = normalize_cs_whitespace(cs_node_text(node, self.source));

        let mut cursor = declaration.walk();
        for child in declaration.named_children(&mut cursor) {
            if child.kind() != "variable_declarator" {
                continue;
            }
            let Some(name_node) = child.child_by_field_name("name") else {
                continue;
            };
            let name = cs_node_text(name_node, self.source).trim();
            if name.is_empty() {
                continue;
            }
            let code_unit = CodeUnit::new(
                self.file.clone(),
                CodeUnitType::Field,
                scope.package_name.clone(),
                format!("{}.{}", parent.short_name(), name),
            );
            self.parsed.add_code_unit(
                code_unit.clone(),
                child,
                self.source,
                Some(parent.clone()),
                None,
            );
            self.parsed.add_signature(
                code_unit,
                csharp_field_signature(&prefix, &type_text, &declaration_text, child, self.source),
            );
        }
    }
}

static CSHARP_TEST_METHOD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)(?:\[[^\]]*(?:Fact|Theory|Test|TestMethod)[^\]]*\]\s*)+[\w<>\[\],\s]+\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*\{(?P<body>.*?)\n\}"#,
    )
    .expect("valid regex")
});
static CSHARP_ASSERT_EQUALITY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"Assert\.(?:Equal|Same)\s*\((?P<left>[^,\n]+?)\s*,\s*(?P<right>[^,\n\)]+)"#)
        .expect("valid regex")
});
static CSHARP_ASSERT_TRUTH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"Assert\.(?P<matcher>True|False|Null|NotNull)\s*\((?P<arg>[^,\n\)]+)"#)
        .expect("valid regex")
});
static CSHARP_THROWS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"Assert\.Throws(?:Async)?<|Assert\.Throws(?:Async)?\s*\("#).expect("valid regex")
});
static CSHARP_VERIFY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\.\s*Verify\s*\("#).expect("valid regex"));

#[derive(Clone)]
struct CSharpAssertionSignal {
    kind: String,
    score: i32,
    shallow: bool,
    meaningful: bool,
    reason: String,
    excerpt: String,
    start_byte: usize,
}

fn detect_csharp_test_assertion_smells(
    file: &ProjectFile,
    source: &str,
    weights: &TestAssertionWeights,
) -> Vec<TestAssertionSmell> {
    let mut findings = Vec::new();
    for captures in CSHARP_TEST_METHOD_RE.captures_iter(source) {
        let Some(name_match) = captures.name("name") else {
            continue;
        };
        let Some(body_match) = captures.name("body") else {
            continue;
        };
        analyze_csharp_test_case(
            file,
            name_match.as_str(),
            body_match.as_str(),
            body_match.start(),
            weights,
            &mut findings,
        );
    }
    findings
}

fn analyze_csharp_test_case(
    file: &ProjectFile,
    name: &str,
    body: &str,
    start_byte: usize,
    weights: &TestAssertionWeights,
    out: &mut Vec<TestAssertionSmell>,
) {
    let assertions = collect_csharp_assertions(body, weights);
    let assertion_count = assertions.len() as i32;
    let symbol = format!("{}::{}", file, name);

    if assertion_count == 0 {
        out.push(TestAssertionSmell {
            file: file.clone(),
            enclosing_fq_name: symbol,
            assertion_kind: "no-assertions".to_string(),
            score: weights.no_assertion_weight,
            assertion_count: 0,
            reasons: vec!["no-assertions".to_string()],
            excerpt: compact_csharp_excerpt(body),
            start_byte,
        });
        return;
    }

    for assertion in &assertions {
        if assertion.score <= 0 {
            continue;
        }
        out.push(TestAssertionSmell {
            file: file.clone(),
            enclosing_fq_name: symbol.clone(),
            assertion_kind: assertion.kind.clone(),
            score: assertion.score,
            assertion_count,
            reasons: vec![assertion.reason.clone()],
            excerpt: assertion.excerpt.clone(),
            start_byte: start_byte + assertion.start_byte,
        });
    }

    if assertions.iter().all(|assertion| assertion.shallow) {
        let score = (weights.shallow_assertion_only_weight
            - csharp_meaningful_assertion_credit(assertions.iter(), weights))
        .max(0);
        if score > 0 {
            out.push(TestAssertionSmell {
                file: file.clone(),
                enclosing_fq_name: symbol,
                assertion_kind: "shallow-assertions-only".to_string(),
                score,
                assertion_count,
                reasons: vec!["shallow-assertions-only".to_string()],
                excerpt: compact_csharp_excerpt(body),
                start_byte,
            });
        }
    }
}

fn collect_csharp_assertions(
    body: &str,
    weights: &TestAssertionWeights,
) -> Vec<CSharpAssertionSignal> {
    let mut assertions = Vec::new();

    for captures in CSHARP_ASSERT_EQUALITY_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let left = normalize_csharp_expr(captures.name("left").map(|m| m.as_str()).unwrap_or(""));
        let right = normalize_csharp_expr(captures.name("right").map(|m| m.as_str()).unwrap_or(""));
        let signal = if left == right {
            let (kind, reason, score) = if is_csharp_literal(&left) {
                (
                    "constant-equality",
                    "constant-equality",
                    weights.constant_equality_weight,
                )
            } else {
                (
                    "self-comparison",
                    "self-comparison",
                    weights.tautological_assertion_weight,
                )
            };
            CSharpAssertionSignal {
                kind: kind.to_string(),
                score,
                shallow: false,
                meaningful: false,
                reason: reason.to_string(),
                excerpt: compact_csharp_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        } else {
            CSharpAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                meaningful: true,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_csharp_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        };
        assertions.push(signal);
    }

    for captures in CSHARP_ASSERT_TRUTH_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let matcher = captures.name("matcher").map(|m| m.as_str()).unwrap_or("");
        let arg = normalize_csharp_expr(captures.name("arg").map(|m| m.as_str()).unwrap_or(""));
        let (kind, score, shallow) = match matcher {
            "True" if arg == "true" => ("constant-truth", weights.constant_truth_weight, true),
            "False" if arg == "false" => ("constant-truth", weights.constant_truth_weight, true),
            "Null" | "NotNull" => ("nullness-only", weights.nullness_only_weight, true),
            _ => ("meaningful-assertion", 0, false),
        };
        assertions.push(CSharpAssertionSignal {
            kind: kind.to_string(),
            score,
            shallow,
            meaningful: score == 0,
            reason: kind.to_string(),
            excerpt: compact_csharp_excerpt(whole.as_str()),
            start_byte: whole.start(),
        });
    }

    for regex in [&*CSHARP_THROWS_RE, &*CSHARP_VERIFY_RE] {
        for captures in regex.captures_iter(body) {
            let whole = captures.get(0).expect("whole match");
            assertions.push(CSharpAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                meaningful: true,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_csharp_excerpt(whole.as_str()),
                start_byte: whole.start(),
            });
        }
    }

    assertions
}

fn csharp_meaningful_assertion_credit<'a>(
    assertions: impl Iterator<Item = &'a CSharpAssertionSignal>,
    weights: &TestAssertionWeights,
) -> i32 {
    let count = assertions.filter(|assertion| assertion.meaningful).count() as i32;
    let creditable = count.min(weights.meaningful_assertion_credit_cap.max(0));
    weights.meaningful_assertion_credit.max(0) * creditable
}

fn normalize_csharp_expr(expr: &str) -> String {
    expr.trim()
        .trim_end_matches(';')
        .trim_matches(|ch| matches!(ch, '(' | ')' | ' '))
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_csharp_literal(expr: &str) -> bool {
    let trimmed = expr.trim();
    (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || matches!(trimmed, "true" | "false" | "null")
        || trimmed.parse::<i64>().is_ok()
        || trimmed.parse::<f64>().is_ok()
}

fn compact_csharp_excerpt(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn file_language(file: &ProjectFile) -> Language {
    file.rel_path()
        .extension()
        .and_then(|ext| ext.to_str())
        .map(Language::from_extension)
        .unwrap_or(Language::None)
}

fn csharp_using_namespace(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches(';').trim();
    let rest = trimmed
        .strip_prefix("global ")
        .unwrap_or(trimmed)
        .strip_prefix("using ")?
        .trim();
    if rest.starts_with("static ") || rest.contains('=') || rest.is_empty() {
        return None;
    }
    Some(rest.to_string())
}

fn csharp_import_info(raw: String) -> ImportInfo {
    let identifier = csharp_using_namespace(&raw)
        .and_then(|namespace| namespace.rsplit('.').next().map(str::to_string));
    ImportInfo {
        raw_snippet: raw,
        is_wildcard: true,
        identifier,
        alias: None,
    }
}

fn csharp_type_name_matches(unit: &CodeUnit, raw_name: &str) -> bool {
    let normalized = normalize_csharp_type_name(raw_name);
    if normalized.is_empty() {
        return false;
    }
    normalized == unit.fq_name()
        || normalized == unit.fq_name().replace('$', ".")
        || (normalized.contains('$') && normalized == unit.short_name())
        || (normalized.contains('.')
            && unit
                .fq_name()
                .strip_suffix(unit.identifier())
                .is_some_and(|prefix| normalized == format!("{prefix}{}", unit.identifier())))
}

fn normalize_csharp_type_name(raw_name: &str) -> String {
    let without_nullable = raw_name.trim().trim_end_matches('?').trim();
    let without_arrays = without_nullable
        .trim_end_matches("[]")
        .trim_end_matches('?')
        .trim();
    without_arrays
        .split('<')
        .next()
        .unwrap_or(without_arrays)
        .trim()
        .to_string()
}

fn collect_csharp_type_identifiers(
    node: Node<'_>,
    source: &str,
    identifiers: &mut HashSet<String>,
) {
    if is_csharp_type_position_node(node)
        && matches!(
            node.kind(),
            "identifier"
                | "qualified_name"
                | "generic_name"
                | "nullable_type"
                | "array_type"
                | "type"
        )
    {
        let text = normalize_csharp_type_name(cs_node_text(node, source));
        if !text.is_empty() {
            identifiers.insert(text);
        }
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_csharp_type_identifiers(child, source, identifiers);
    }
}

fn is_csharp_type_position_node(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if parent
            .child_by_field_name("type")
            .is_some_and(|type_node| same_cs_node(type_node, node))
            || parent
                .child_by_field_name("return_type")
                .is_some_and(|type_node| same_cs_node(type_node, node))
        {
            return true;
        }
        if parent.kind() == "type" {
            return true;
        }
        if parent.kind() == "object_creation_expression" {
            return true;
        }
        if matches!(
            parent.kind(),
            "class_declaration"
                | "interface_declaration"
                | "struct_declaration"
                | "record_declaration"
                | "record_struct_declaration"
        ) && !parent
            .child_by_field_name("name")
            .is_some_and(|name| same_cs_node(name, node))
        {
            return true;
        }
        if matches!(
            parent.kind(),
            "qualified_name"
                | "generic_name"
                | "nullable_type"
                | "array_type"
                | "type_argument_list"
                | "base_list"
        ) {
            node = parent;
            continue;
        }
        return false;
    }
    false
}

fn same_cs_node(left: Node<'_>, right: Node<'_>) -> bool {
    left.start_byte() == right.start_byte() && left.end_byte() == right.end_byte()
}

const CSHARP_CLONE_AST_IDENTIFIER_TYPES: &[&str] = &["identifier"];
const CSHARP_CLONE_AST_STRING_TYPES: &[&str] = &["string_literal"];
const CSHARP_CLONE_AST_NUMBER_TYPES: &[&str] = &["integer_literal", "real_literal"];

fn normalized_clone_tokens_csharp(source: &str) -> Vec<String> {
    let Some(tree) = parse_csharp_tree(source) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    collect_normalized_leaf_tokens_csharp(tree.root_node(), source, &mut out);
    out
}

fn collect_normalized_leaf_tokens_csharp(node: Node<'_>, source: &str, out: &mut Vec<String>) {
    if node.named_child_count() == 0 {
        let token = normalize_csharp_clone_leaf_token(node, source);
        if !token.is_empty() {
            out.push(token);
        }
    }
    let child_count = node.child_count();
    for index in 0..child_count {
        if let Some(child) = node.child(index) {
            collect_normalized_leaf_tokens_csharp(child, source, out);
        }
    }
}

fn normalize_csharp_clone_leaf_token(node: Node<'_>, source: &str) -> String {
    let kind = node.kind();
    let token = source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim();
    if token.is_empty() || kind == "comment" {
        return String::new();
    }
    if CSHARP_CLONE_AST_IDENTIFIER_TYPES.contains(&kind) {
        return "ID".to_string();
    }
    if CSHARP_CLONE_AST_STRING_TYPES.contains(&kind) {
        return "STR".to_string();
    }
    if CSHARP_CLONE_AST_NUMBER_TYPES.contains(&kind) {
        return "NUM".to_string();
    }
    if matches!(token, "true" | "false") {
        return "BOOL".to_string();
    }
    if token.chars().count() == 1 && token.chars().all(|ch| !ch.is_alphanumeric()) {
        return format!("OP:{token}");
    }
    format!("T:{kind}")
}

fn build_csharp_clone_ast_signature(source: &str) -> String {
    let Some(tree) = parse_csharp_tree(source) else {
        return String::new();
    };
    let mut labels = Vec::new();
    collect_csharp_clone_ast_labels(tree.root_node(), source, &mut labels);
    labels.join("|")
}

fn collect_csharp_clone_ast_labels(node: Node<'_>, source: &str, out: &mut Vec<String>) {
    out.push(normalize_csharp_clone_ast_label(node, source));
    let child_count = node.child_count();
    for index in 0..child_count {
        if let Some(child) = node.child(index) {
            collect_csharp_clone_ast_labels(child, source, out);
        }
    }
}

fn normalize_csharp_clone_ast_label(node: Node<'_>, source: &str) -> String {
    let kind = node.kind();
    let text = source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim();
    if CSHARP_CLONE_AST_IDENTIFIER_TYPES.contains(&kind) {
        return "ID".to_string();
    }
    if CSHARP_CLONE_AST_STRING_TYPES.contains(&kind) {
        return "STR".to_string();
    }
    if CSHARP_CLONE_AST_NUMBER_TYPES.contains(&kind) {
        return "NUM".to_string();
    }
    if matches!(text, "true" | "false") {
        return "BOOL".to_string();
    }
    format!("N:{kind}")
}

fn refine_csharp_clone_similarity(
    left: &CloneCandidateData,
    right: &CloneCandidateData,
    token_similarity: i32,
    weights: CloneSmellWeights,
) -> i32 {
    if left.ast_signature.is_empty() || right.ast_signature.is_empty() {
        return token_similarity;
    }
    let ast_similarity =
        compute_ast_refinement_similarity_percent(&left.ast_signature, &right.ast_signature);
    if ast_similarity == 0 {
        return token_similarity;
    }
    if ast_similarity < weights.ast_similarity_percent {
        return 0;
    }
    token_similarity.min(ast_similarity)
}

fn parse_csharp_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
        .expect("failed to load csharp parser");
    parser.parse(source, None)
}

fn cs_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}

fn normalize_cs_whitespace(value: &str) -> String {
    let mut result = String::new();
    let mut prev_space = false;
    for ch in value.chars() {
        if ch.is_whitespace() {
            if !prev_space {
                result.push(' ');
            }
            prev_space = true;
        } else {
            result.push(ch);
            prev_space = false;
        }
    }
    result.trim().to_string()
}

fn cs_namespace_body(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("body")
        .or_else(|| last_named_child(node))
}

fn cs_type_body(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("body")
        .or_else(|| first_named_child_of_kind(node, "declaration_list"))
}

fn csharp_type_signature(node: Node<'_>, source: &str) -> String {
    let text = normalize_cs_whitespace(cs_node_text(node, source));
    let head = text.split('{').next().unwrap_or(text.as_str()).trim();
    format!("{head} {{")
}

fn csharp_method_skeleton(node: Node<'_>, source: &str) -> String {
    let text = normalize_cs_whitespace(cs_node_text(node, source));
    let head = text.split('{').next().unwrap_or(text.as_str()).trim();
    format!("{} {{ … }}", head.trim_end_matches(';').trim())
}

fn csharp_constructor_skeleton(node: Node<'_>, source: &str) -> String {
    csharp_method_skeleton(node, source)
}

fn csharp_property_signature(node: Node<'_>, source: &str) -> String {
    normalize_cs_whitespace(cs_node_text(node, source))
}

fn csharp_parameter_key(node: Node<'_>, source: &str) -> String {
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return "()".to_string();
    };
    let mut parts = Vec::new();
    let mut cursor = parameters.walk();
    for child in parameters.named_children(&mut cursor) {
        if child.kind() != "parameter" {
            continue;
        }
        let part = child
            .child_by_field_name("type")
            .map(|type_node| normalize_cs_whitespace(cs_node_text(type_node, source)))
            .unwrap_or_else(|| normalize_cs_whitespace(cs_node_text(child, source)));
        parts.push(part);
    }
    format!("({})", parts.join(", "))
}

fn csharp_field_prefix(field_node: Node<'_>, declaration: Node<'_>, source: &str) -> String {
    let field_text = cs_node_text(field_node, source);
    let end = declaration
        .start_byte()
        .saturating_sub(field_node.start_byte());
    let prefix = field_text.get(..end).unwrap_or(field_text);
    let prefix = normalize_cs_whitespace(prefix);
    regex::Regex::new(r"^(?:\[[^\]]+\]\s*)+")
        .ok()
        .map(|regex| regex.replace(&prefix, "").trim().to_string())
        .unwrap_or(prefix)
}

fn csharp_field_signature(
    prefix: &str,
    type_text: &str,
    declaration_text: &str,
    declarator: Node<'_>,
    source: &str,
) -> String {
    let name = declarator
        .child_by_field_name("name")
        .map(|child| cs_node_text(child, source).trim().to_string())
        .unwrap_or_default();
    let initializer = declarator
        .child_by_field_name("value")
        .or_else(|| declarator.child_by_field_name("initializer"))
        .and_then(|value| csharp_literal_initializer(value, source));
    let initializer =
        initializer.or_else(|| csharp_literal_initializer_from_text(declaration_text, &name));

    let base = if prefix.is_empty() {
        format!("{type_text} {name}")
    } else {
        format!("{prefix} {type_text} {name}")
    };
    let base = normalize_cs_whitespace(&base);
    if let Some(initializer) = initializer {
        format!("{base} = {initializer};")
    } else {
        format!("{base};")
    }
}

fn csharp_literal_initializer(node: Node<'_>, source: &str) -> Option<String> {
    let kind = node.kind();
    if matches!(
        kind,
        "integer_literal"
            | "real_literal"
            | "string_literal"
            | "character_literal"
            | "boolean_literal"
            | "null_literal"
    ) {
        return Some(normalize_cs_whitespace(cs_node_text(node, source)));
    }
    None
}

fn csharp_literal_initializer_from_text(declaration_text: &str, name: &str) -> Option<String> {
    let pattern = format!(
        r#"\b{}\s*=\s*("([^"\\]|\\.)*"|'([^'\\]|\\.)*'|[-+]?\d+(?:\.\d+)?|true|false|null)\s*(?:,|;)"#,
        regex::escape(name)
    );
    regex::Regex::new(&pattern)
        .ok()
        .and_then(|regex| regex.captures(declaration_text))
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().to_string())
}

fn first_named_child_of_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == kind)
}

fn last_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let count = node.named_child_count();
    if count == 0 {
        None
    } else {
        node.named_child(count - 1)
    }
}

fn csharp_contains_tests(source: &str) -> bool {
    static TEST_ATTR_RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let regex = TEST_ATTR_RE.get_or_init(|| {
        regex::Regex::new(
            r"\[(?:[A-Za-z_][A-Za-z0-9_.]*\.)?(?:Test|Fact|Theory)(?:Attribute)?(?:\s*\(|\s*\])",
        )
        .expect("valid csharp test regex")
    });
    regex.is_match(source)
}

fn weight_string_vec(_key: &ProjectFile, value: &Arc<Vec<String>>) -> u32 {
    weight_bytes(
        size_of::<Vec<String>>() as u64 + value.iter().map(|item| item.len() as u64).sum::<u64>(),
    )
}

fn weight_code_unit_set(_key: &ProjectFile, value: &Arc<HashSet<CodeUnit>>) -> u32 {
    weight_bytes(estimate_code_unit_set(value.as_ref()))
}

fn weight_project_file_set(_key: &ProjectFile, value: &Arc<HashSet<ProjectFile>>) -> u32 {
    weight_bytes(estimate_project_file_set(value.as_ref()))
}

fn weight_bytes(bytes: u64) -> u32 {
    bytes.clamp(1, u32::MAX as u64) as u32
}

fn estimate_project_file(file: &ProjectFile) -> u64 {
    size_of::<ProjectFile>() as u64
        + file.root().as_os_str().to_string_lossy().len() as u64
        + file.rel_path().as_os_str().to_string_lossy().len() as u64
}

fn estimate_code_unit(code_unit: &CodeUnit) -> u64 {
    size_of::<CodeUnit>() as u64
        + estimate_project_file(code_unit.source())
        + code_unit.package_name().len() as u64
        + code_unit.short_name().len() as u64
        + code_unit
            .signature()
            .map_or(0, |signature| signature.len() as u64)
}

fn estimate_code_unit_set(values: &HashSet<CodeUnit>) -> u64 {
    size_of::<HashSet<CodeUnit>>() as u64 + values.iter().map(estimate_code_unit).sum::<u64>()
}

fn estimate_project_file_set(files: &HashSet<ProjectFile>) -> u64 {
    size_of::<HashSet<ProjectFile>>() as u64 + files.iter().map(estimate_project_file).sum::<u64>()
}
