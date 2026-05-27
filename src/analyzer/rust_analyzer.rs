use crate::analyzer::cognitive_complexity;
use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::usages::{
    ExportEntry, ExportIndex, ImportBinder, ImportBinding, ImportKind, ReexportStar,
};
use crate::analyzer::{
    AnalyzerConfig, CodeUnit, IAnalyzer, ImportAnalysisProvider, ImportInfo, Language,
    LanguageAdapter, Project, ProjectFile, TestAssertionSmell, TestAssertionWeights,
    TestDetectionProvider, TreeSitterAnalyzer, TypeAliasProvider, build_reverse_import_index,
};
use crate::hash::{HashMap, HashSet};
use moka::sync::Cache;
use regex::Regex;
use std::collections::BTreeSet;
use std::mem::size_of;
use std::path::Path;
use std::sync::{Arc, LazyLock, OnceLock};
use tree_sitter::{Language as TsLanguage, Node, Parser, Tree};

use super::js_ts::build_weighted_cache;

/// Tree-sitter node-kind mapping used by the cognitive-complexity scorer
/// for Rust. Mirrors `ai.brokk.analyzer.rust.CognitiveComplexityAnalysis`
/// in brokk-shared so the bifrost MCP output matches brokk-core byte-for-
/// byte. Names are tree-sitter `rust` grammar node kinds.
static RUST_COGNITIVE_CONFIG: LazyLock<cognitive_complexity::Config> =
    LazyLock::new(|| cognitive_complexity::Config {
        if_types: &["if_expression"],
        loop_types: &["for_expression", "while_expression", "loop_expression"],
        case_types: &["match_arm"],
        binary_types: &["binary_expression"],
        logical_operators: &["&&", "||"],
        jump_types: &["break_expression", "continue_expression"],
        named_function_boundary_types: &["function_item"],
        anonymous_function_types: &["closure_expression"],
        else_clause_types: &["else_clause"],
        default_case_predicate: Some(cognitive_complexity::is_wildcard_case),
        ..cognitive_complexity::Config::empty()
    });

#[derive(Debug, Clone, Default)]
pub struct RustAdapter;

impl LanguageAdapter for RustAdapter {
    fn language(&self) -> Language {
        Language::Rust
    }

    fn query_directory(&self) -> &'static str {
        "resources/treesitter/rust"
    }

    fn parser_language(&self) -> TsLanguage {
        tree_sitter_rust::LANGUAGE.into()
    }

    fn file_extension(&self) -> &'static str {
        "rs"
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        let trimmed = reference.trim();
        let before_args = trimmed
            .split_once('(')
            .map(|(head, _)| head)
            .unwrap_or(trimmed);
        before_args
            .rsplit_once("::")
            .map(|(receiver, _)| receiver.to_string())
    }

    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        _tree: &Tree,
        _parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        source.contains("#[cfg(test)]") || source.contains("#[test]")
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
        let mut parsed =
            crate::analyzer::tree_sitter_analyzer::ParsedFile::new(rust_package_name(file));
        let root = tree.root_node();
        collect_rust_type_identifiers(root, source, &mut parsed.type_identifiers);

        for index in 0..root.named_child_count() {
            let Some(child) = root.named_child(index) else {
                continue;
            };
            match child.kind() {
                "use_declaration" => {
                    let raw = rust_node_text(child, source).trim().to_string();
                    let flattened = flatten_rust_use(&raw);
                    parsed.import_statements.extend(flattened.iter().cloned());
                    parsed
                        .imports
                        .extend(flattened.into_iter().map(parse_rust_import_info));
                }
                "struct_item" | "enum_item" | "trait_item" => {
                    visit_rust_class_like(
                        file,
                        source,
                        child,
                        None,
                        &parsed.package_name.clone(),
                        &mut parsed,
                    );
                }
                "mod_item" => {
                    visit_rust_module(
                        file,
                        source,
                        child,
                        None,
                        &parsed.package_name.clone(),
                        &mut parsed,
                    );
                }
                "function_item" => {
                    visit_rust_function(
                        file,
                        source,
                        child,
                        None,
                        &parsed.package_name.clone(),
                        &mut parsed,
                    );
                }
                "const_item" | "static_item" => {
                    visit_rust_field(
                        file,
                        source,
                        child,
                        None,
                        &parsed.package_name.clone(),
                        &mut parsed,
                    );
                }
                "type_item" => {
                    visit_rust_alias(
                        file,
                        source,
                        child,
                        None,
                        &parsed.package_name.clone(),
                        &mut parsed,
                    );
                }
                "impl_item" => {
                    visit_rust_impl(
                        file,
                        source,
                        child,
                        &parsed.package_name.clone(),
                        &mut parsed,
                    );
                }
                _ => {}
            }
        }

        parsed
    }

    fn cognitive_complexity_config(&self) -> Option<&'static cognitive_complexity::Config> {
        Some(&RUST_COGNITIVE_CONFIG)
    }
}

#[derive(Clone)]
pub struct RustAnalyzer {
    inner: TreeSitterAnalyzer<RustAdapter>,
    memo_budget: u64,
    imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    reverse_import_index: Arc<OnceLock<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
}

impl RustAnalyzer {
    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        Self {
            inner: TreeSitterAnalyzer::new_with_config(project, RustAdapter, config),
            memo_budget,
            imported_code_units: build_weighted_cache(memo_budget / 4, weight_code_unit_set),
            referencing_files: build_weighted_cache(memo_budget / 8, weight_project_file_set),
            reverse_import_index: Arc::new(OnceLock::new()),
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
                RustAdapter,
                config,
                storage,
            ),
            memo_budget,
            imported_code_units: build_weighted_cache(memo_budget / 4, weight_code_unit_set),
            referencing_files: build_weighted_cache(memo_budget / 8, weight_project_file_set),
            reverse_import_index: Arc::new(OnceLock::new()),
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
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("failed to load rust parser");
        let Some(tree) = parser.parse(source, None) else {
            return BTreeSet::new();
        };
        let mut identifiers = HashSet::default();
        collect_rust_type_identifiers(tree.root_node(), source, &mut identifiers);
        identifiers.into_iter().collect()
    }

    pub fn export_index_of(&self, file: &ProjectFile) -> ExportIndex {
        let mut index = ExportIndex::empty();

        for code_unit in self.declarations(file) {
            let identifier = code_unit.identifier().trim();
            if identifier.is_empty() || identifier.starts_with('_') {
                continue;
            }
            if !self.is_module_export_candidate(code_unit) {
                continue;
            }
            index.exports_by_name.insert(
                identifier.to_string(),
                ExportEntry::Local {
                    local_name: identifier.to_string(),
                },
            );
        }

        for import in self.inner.import_info_of(file) {
            let raw = import.raw_snippet.trim();
            if !raw.starts_with("pub use ") {
                continue;
            }
            if let Some(module_specifier) = raw
                .strip_prefix("pub use ")
                .map(str::trim)
                .and_then(|value| value.strip_suffix("::*;"))
                .map(str::trim)
            {
                index.reexport_stars.push(ReexportStar {
                    module_specifier: module_specifier.to_string(),
                });
                continue;
            }
            let Some((module_specifier, imported_name)) =
                split_rust_import_module_and_name(&import.raw_snippet)
            else {
                continue;
            };
            let exported_name = import
                .alias
                .clone()
                .or_else(|| import.identifier.clone())
                .unwrap_or_else(|| imported_name.clone());
            if exported_name == "self" {
                continue;
            }
            index.exports_by_name.insert(
                exported_name,
                ExportEntry::ReexportedNamed {
                    module_specifier,
                    imported_name,
                },
            );
        }

        index
    }

    pub fn import_binder_of(&self, file: &ProjectFile) -> ImportBinder {
        let mut binder = ImportBinder::empty();

        for import in self.inner.import_info_of(file) {
            let raw = import.raw_snippet.trim();
            if raw.ends_with("::*;") {
                let module_specifier = raw
                    .trim_start_matches("pub ")
                    .trim_start_matches("use ")
                    .trim_end_matches("::*;")
                    .trim()
                    .to_string();
                binder.bindings.insert(
                    format!("*:{module_specifier}"),
                    ImportBinding {
                        module_specifier,
                        kind: ImportKind::Glob,
                        imported_name: None,
                    },
                );
                continue;
            }
            let Some((module_specifier, imported_name)) =
                split_rust_import_module_and_name(&import.raw_snippet)
            else {
                continue;
            };
            let local_name = import
                .alias
                .clone()
                .or_else(|| import.identifier.clone())
                .unwrap_or_else(|| imported_name.clone());
            let (local_name, kind, imported_name, module_specifier) = if imported_name == "self" {
                let namespace_name = module_specifier
                    .rsplit("::")
                    .next()
                    .unwrap_or(module_specifier.as_str())
                    .to_string();
                (
                    namespace_name,
                    ImportKind::Namespace,
                    None,
                    module_specifier,
                )
            } else if !raw.contains('{')
                && imported_name
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch == '_')
            {
                (
                    imported_name.clone(),
                    ImportKind::Namespace,
                    None,
                    format!("{module_specifier}::{imported_name}"),
                )
            } else {
                (
                    local_name,
                    ImportKind::Named,
                    Some(imported_name),
                    module_specifier,
                )
            };

            binder.bindings.insert(
                local_name,
                ImportBinding {
                    module_specifier,
                    kind,
                    imported_name,
                },
            );
        }

        binder
    }

    pub fn resolve_module_files(
        &self,
        importing_file: &ProjectFile,
        module_specifier: &str,
    ) -> Vec<ProjectFile> {
        let package = rust_package_name(importing_file);
        let Some(resolved_module) = resolve_rust_module_path(&package, module_specifier) else {
            return Vec::new();
        };

        let mut files: Vec<_> = self
            .get_analyzed_files()
            .into_iter()
            .filter(|file| rust_package_name(file) == resolved_module)
            .collect();
        files.extend(self.get_analyzed_files().into_iter().filter(|file| {
            self.declarations(file).any(|code_unit| {
                code_unit.is_module()
                    && code_unit.short_name() == resolved_module
                    && (*file == *importing_file || self.is_visible_module_path(code_unit))
            })
        }));
        files.sort();
        files.dedup();
        files
    }

    pub fn exact_member(
        &self,
        source_file: &ProjectFile,
        owner_name: &str,
        member_name: &str,
        _instance_receiver: bool,
    ) -> Option<CodeUnit> {
        self.declarations(source_file)
            .find(|code_unit| {
                code_unit.identifier() == member_name
                    && self
                        .parent_of(code_unit)
                        .map(|parent| parent.identifier() == owner_name)
                        .unwrap_or(false)
            })
            .cloned()
    }

    pub fn rust_usage_candidate_files(
        &self,
        export_names: HashSet<String>,
        target: &CodeUnit,
    ) -> HashSet<ProjectFile> {
        let owner_source = self
            .parent_of(target)
            .map(|owner| owner.source().clone())
            .unwrap_or_else(|| target.source().clone());
        let member_name = target.identifier().to_string();

        let project = self.inner.project();
        self.referencing_files_of(&owner_source)
            .into_iter()
            .filter(|file| {
                project.read_source(file).ok().is_some_and(|source| {
                    export_names.iter().any(|name| source.contains(name))
                        || source.contains(&member_name)
                })
            })
            .collect()
    }

    pub fn trait_implementer_names(
        &self,
        trait_owner: &CodeUnit,
        _importer_file: &ProjectFile,
    ) -> HashSet<String> {
        let project = self.inner.project();
        self.get_analyzed_files()
            .into_iter()
            .filter_map(|file| {
                let source = project.read_source(&file).ok()?;
                Some((file, source))
            })
            .flat_map(|(file, source)| {
                let binder = self.import_binder_of(&file);
                TRAIT_IMPL_RE
                    .captures_iter(&source)
                    .filter_map(|captures| {
                        let trait_ref = captures.get(1)?.as_str().trim();
                        let implementer = captures.get(2)?.as_str().trim();
                        trait_reference_matches(self, trait_owner, &file, trait_ref, &binder)
                            .then(|| implementer.to_string())
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    fn is_public_declaration(&self, code_unit: &CodeUnit) -> bool {
        self.get_source(code_unit, false)
            .or_else(|| self.get_skeleton_header(code_unit))
            .map(|source| {
                let trimmed = source.trim_start();
                trimmed.starts_with("pub ")
                    || trimmed.starts_with("pub(crate)")
                    || trimmed.starts_with("pub(in crate")
                    || code_unit.is_module() && trimmed.starts_with("pub mod ")
            })
            .unwrap_or(false)
    }

    fn is_module_export_candidate(&self, code_unit: &CodeUnit) -> bool {
        if !self.is_public_declaration(code_unit) {
            return false;
        }

        let mut current = code_unit.clone();
        while let Some(parent) = self.parent_of(&current) {
            if !parent.is_module() || !self.is_public_declaration(&parent) {
                return false;
            }
            current = parent;
        }

        !code_unit.is_function() || self.parent_of(code_unit).is_none()
    }

    fn is_visible_module_path(&self, code_unit: &CodeUnit) -> bool {
        let mut current = code_unit.clone();
        loop {
            if !current.is_module() || !self.is_public_declaration(&current) {
                return false;
            }
            let Some(parent) = self.parent_of(&current) else {
                return true;
            };
            current = parent;
        }
    }
}

impl ImportAnalysisProvider for RustAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> HashSet<CodeUnit> {
        if let Some(cached) = self.imported_code_units.get(file) {
            return (*cached).clone();
        }

        let package = rust_package_name(file);
        let mut resolved = HashSet::default();
        for import in self.inner.import_info_of(file) {
            if let Some(target_fq_name) =
                resolve_rust_import_fq_name(file, &package, &import.raw_snippet)
            {
                resolved.extend(self.inner.definitions(&target_fq_name).cloned());
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

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        let package = rust_package_name(source_file);
        imports.iter().any(|import| {
            resolve_rust_import_fq_name(source_file, &package, &import.raw_snippet)
                .into_iter()
                .any(|fq_name| {
                    self.inner
                        .definitions(&fq_name)
                        .any(|code_unit| code_unit.source() == target)
                })
        })
    }
}

impl TypeAliasProvider for RustAnalyzer {
    fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        self.inner.is_type_alias(code_unit)
    }
}

impl TestDetectionProvider for RustAnalyzer {}

impl IAnalyzer for RustAnalyzer {
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
            memo_budget: self.memo_budget,
            imported_code_units: build_weighted_cache(self.memo_budget / 4, weight_code_unit_set),
            referencing_files: build_weighted_cache(self.memo_budget / 8, weight_project_file_set),
            reverse_import_index: Arc::new(OnceLock::new()),
        }
    }

    fn update_all(&self) -> Self {
        Self {
            inner: self.inner.update_all(),
            memo_budget: self.memo_budget,
            imported_code_units: build_weighted_cache(self.memo_budget / 4, weight_code_unit_set),
            referencing_files: build_weighted_cache(self.memo_budget / 8, weight_project_file_set),
            reverse_import_index: Arc::new(OnceLock::new()),
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

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        Some(self)
    }

    fn type_alias_provider(&self) -> Option<&dyn TypeAliasProvider> {
        Some(self)
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
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
        if !self.contains_tests(file) || file_language(file) != Language::Rust {
            return Vec::new();
        }
        let Ok(source) = self.inner.project().read_source(file) else {
            return Vec::new();
        };
        detect_rust_test_assertion_smells(file, &source, &weights)
    }
}

fn rust_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}

static RUST_TEST_FN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)#\s*\[\s*test\s*\]\s*fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)[^{]*\{(?P<body>.*?)\n\}"#,
    )
    .expect("valid regex")
});
static RUST_ASSERT_EQ_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"assert_eq!\s*\((?P<left>[^,\n]+?)\s*,\s*(?P<right>[^,\n\)]+)"#)
        .expect("valid regex")
});
static RUST_ASSERT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"assert!\s*\((?P<expr>[^\n\)]+)"#).expect("valid regex"));
static RUST_MATCHES_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"matches!\s*\("#).expect("valid regex"));

#[derive(Clone)]
struct RustAssertionSignal {
    kind: String,
    score: i32,
    shallow: bool,
    meaningful: bool,
    reason: String,
    excerpt: String,
    start_byte: usize,
}

fn detect_rust_test_assertion_smells(
    file: &ProjectFile,
    source: &str,
    weights: &TestAssertionWeights,
) -> Vec<TestAssertionSmell> {
    let mut findings = Vec::new();
    for captures in RUST_TEST_FN_RE.captures_iter(source) {
        let Some(name_match) = captures.name("name") else {
            continue;
        };
        let Some(body_match) = captures.name("body") else {
            continue;
        };
        analyze_rust_test_case(
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

fn analyze_rust_test_case(
    file: &ProjectFile,
    name: &str,
    body: &str,
    start_byte: usize,
    weights: &TestAssertionWeights,
    out: &mut Vec<TestAssertionSmell>,
) {
    let assertions = collect_rust_assertions(body, weights);
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
            excerpt: compact_rust_excerpt(body),
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
            - rust_meaningful_assertion_credit(assertions.iter(), weights))
        .max(0);
        if score > 0 {
            out.push(TestAssertionSmell {
                file: file.clone(),
                enclosing_fq_name: symbol,
                assertion_kind: "shallow-assertions-only".to_string(),
                score,
                assertion_count,
                reasons: vec!["shallow-assertions-only".to_string()],
                excerpt: compact_rust_excerpt(body),
                start_byte,
            });
        }
    }
}

fn collect_rust_assertions(body: &str, weights: &TestAssertionWeights) -> Vec<RustAssertionSignal> {
    let mut assertions = Vec::new();

    for captures in RUST_ASSERT_EQ_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let left = normalize_rust_expr(captures.name("left").map(|m| m.as_str()).unwrap_or(""));
        let right = normalize_rust_expr(captures.name("right").map(|m| m.as_str()).unwrap_or(""));
        let signal = if left == right {
            let (kind, reason, score) = if is_rust_literal(&left) {
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
            RustAssertionSignal {
                kind: kind.to_string(),
                score,
                shallow: false,
                meaningful: false,
                reason: reason.to_string(),
                excerpt: compact_rust_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        } else if let Some(literal) = oversized_rust_literal(&left, &right, weights) {
            RustAssertionSignal {
                kind: "overspecified-literal".to_string(),
                score: weights.overspecified_literal_weight,
                shallow: true,
                meaningful: false,
                reason: format!("overspecified-literal:{literal}"),
                excerpt: compact_rust_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        } else {
            RustAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                meaningful: true,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_rust_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        };
        assertions.push(signal);
    }

    for captures in RUST_ASSERT_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let expr = normalize_rust_expr(captures.name("expr").map(|m| m.as_str()).unwrap_or(""));
        let trimmed = expr.trim();
        let signal = if trimmed == "true" || trimmed == "false" {
            RustAssertionSignal {
                kind: "constant-truth".to_string(),
                score: weights.constant_truth_weight,
                shallow: true,
                meaningful: false,
                reason: "constant-truth".to_string(),
                excerpt: compact_rust_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        } else if trimmed.contains(".is_some()") || trimmed.contains(".is_none()") {
            RustAssertionSignal {
                kind: "nullness-only".to_string(),
                score: weights.nullness_only_weight,
                shallow: true,
                meaningful: false,
                reason: "nullness-only".to_string(),
                excerpt: compact_rust_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        } else {
            RustAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                meaningful: true,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_rust_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        };
        assertions.push(signal);
    }

    for captures in RUST_MATCHES_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        assertions.push(RustAssertionSignal {
            kind: "meaningful-assertion".to_string(),
            score: 0,
            shallow: false,
            meaningful: true,
            reason: "meaningful-assertion".to_string(),
            excerpt: compact_rust_excerpt(whole.as_str()),
            start_byte: whole.start(),
        });
    }

    assertions
}

fn rust_meaningful_assertion_credit<'a>(
    assertions: impl Iterator<Item = &'a RustAssertionSignal>,
    weights: &TestAssertionWeights,
) -> i32 {
    let count = assertions.filter(|assertion| assertion.meaningful).count() as i32;
    let creditable = count.min(weights.meaningful_assertion_credit_cap.max(0));
    weights.meaningful_assertion_credit.max(0) * creditable
}

fn normalize_rust_expr(expr: &str) -> String {
    expr.trim()
        .trim_end_matches(',')
        .trim_matches(|ch| matches!(ch, '(' | ')' | ' '))
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_rust_literal(expr: &str) -> bool {
    let trimmed = expr.trim();
    (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || matches!(trimmed, "true" | "false" | "None")
        || trimmed.parse::<i64>().is_ok()
        || trimmed.parse::<f64>().is_ok()
}

fn compact_rust_excerpt(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn oversized_rust_literal(
    left: &str,
    right: &str,
    weights: &TestAssertionWeights,
) -> Option<String> {
    [left, right].into_iter().find_map(|expr| {
        let trimmed = expr.trim();
        let unquoted = trimmed
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))?;
        (unquoted.len() >= weights.large_literal_length_threshold.max(0) as usize)
            .then(|| trimmed.to_string())
    })
}

fn rust_package_name(file: &ProjectFile) -> String {
    let rel = file.rel_path();
    let mut components: Vec<_> = rel
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_string())
        .collect();

    if components.first().map(|component| component.as_str()) == Some("src") {
        components.remove(0);
    }
    if components.is_empty() {
        return String::new();
    }

    let file_name = components.pop().unwrap_or_default();
    let stem = Path::new(&file_name)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();

    if stem == "lib" || stem == "main" || stem == "mod" {
        components.join(".")
    } else if rel.starts_with("src") {
        components
            .into_iter()
            .chain(std::iter::once(stem.to_string()))
            .filter(|component| !component.is_empty())
            .collect::<Vec<_>>()
            .join(".")
    } else {
        components.join(".")
    }
}

fn visit_rust_class_like(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    package_name: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> Option<CodeUnit> {
    let name_node = node.child_by_field_name("name")?;
    let name = rust_node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }

    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), name))
        .unwrap_or_else(|| name.to_string());
    let code_unit = CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Class,
        package_name.to_string(),
        short_name,
    );
    let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        parent.cloned(),
        Some(top_level.clone()),
    );
    parsed.add_signature(
        code_unit.clone(),
        rust_type_signature(node, source, package_name.is_empty()),
    );

    if let Some(body) = node.child_by_field_name("body") {
        for index in 0..body.named_child_count() {
            let Some(child) = body.named_child(index) else {
                continue;
            };
            match child.kind() {
                "field_declaration" | "enum_variant" | "const_item" => {
                    visit_rust_field(file, source, child, Some(&code_unit), package_name, parsed);
                }
                "function_signature_item" => {
                    visit_rust_function(
                        file,
                        source,
                        child,
                        Some(&code_unit),
                        package_name,
                        parsed,
                    );
                }
                _ => {}
            }
        }
    }

    Some(code_unit)
}

fn visit_rust_module(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    package_name: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> Option<CodeUnit> {
    let name_node = node.child_by_field_name("name")?;
    let name = rust_node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }

    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), name))
        .unwrap_or_else(|| name.to_string());
    let code_unit = CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Module,
        package_name.to_string(),
        short_name,
    );
    let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        parent.cloned(),
        Some(top_level.clone()),
    );
    parsed.add_signature(code_unit.clone(), format!("mod {name} {{"));

    if let Some(body) = node.child_by_field_name("body") {
        for index in 0..body.named_child_count() {
            let Some(child) = body.named_child(index) else {
                continue;
            };
            match child.kind() {
                "function_item" => {
                    visit_rust_function(
                        file,
                        source,
                        child,
                        Some(&code_unit),
                        package_name,
                        parsed,
                    );
                }
                "struct_item" | "enum_item" | "trait_item" => {
                    visit_rust_class_like(
                        file,
                        source,
                        child,
                        Some(&code_unit),
                        package_name,
                        parsed,
                    );
                }
                "mod_item" => {
                    visit_rust_module(file, source, child, Some(&code_unit), package_name, parsed);
                }
                _ => {}
            }
        }
    }

    Some(code_unit)
}

fn visit_rust_function(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    package_name: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> Option<CodeUnit> {
    let name_node = node.child_by_field_name("name")?;
    let name = rust_node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }

    let signature = node
        .child_by_field_name("parameters")
        .map(|parameters| rust_node_text(parameters, source).trim().to_string());
    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), name))
        .unwrap_or_else(|| name.to_string());
    let code_unit = CodeUnit::with_signature(
        file.clone(),
        crate::analyzer::CodeUnitType::Function,
        package_name.to_string(),
        short_name,
        signature,
        false,
    );
    let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        parent.cloned(),
        Some(top_level),
    );
    parsed.add_signature(code_unit.clone(), rust_function_signature(node, source));
    Some(code_unit)
}

fn visit_rust_field(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    package_name: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> Option<CodeUnit> {
    let name_node = node.child_by_field_name("name").unwrap_or(node);
    let name = rust_node_text(name_node, source)
        .trim()
        .trim_end_matches(',')
        .to_string();
    if name.is_empty() {
        return None;
    }

    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), name))
        .unwrap_or_else(|| format!("_module_.{name}"));
    let code_unit = CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Field,
        package_name.to_string(),
        short_name,
    );
    let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        parent.cloned(),
        Some(top_level),
    );
    parsed.add_signature(
        code_unit.clone(),
        rust_node_text(node, source)
            .trim()
            .trim_end_matches(',')
            .to_string(),
    );
    Some(code_unit)
}

fn visit_rust_alias(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    package_name: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> Option<CodeUnit> {
    let name_node = node.child_by_field_name("name")?;
    let name = rust_node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }
    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), name))
        .unwrap_or_else(|| name.to_string());
    let code_unit = CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Field,
        package_name.to_string(),
        short_name,
    );
    let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        parent.cloned(),
        Some(top_level),
    );
    parsed.add_signature(
        code_unit.clone(),
        rust_node_text(node, source).trim().to_string(),
    );
    parsed.mark_type_alias(code_unit.clone());
    Some(code_unit)
}

fn visit_rust_impl(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    let Some(target_name) = extract_rust_impl_target_name(type_node, source) else {
        return;
    };
    let parent = CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Class,
        package_name.to_string(),
        target_name,
    );
    if !parsed.declarations.contains(&parent) {
        let top_level = parent.clone();
        parsed.add_code_unit(parent.clone(), node, source, None, Some(top_level));
    }

    let Some(body) = node.child_by_field_name("body") else {
        return;
    };
    for index in 0..body.named_child_count() {
        let Some(child) = body.named_child(index) else {
            continue;
        };
        match child.kind() {
            "function_item" => {
                visit_rust_function(file, source, child, Some(&parent), package_name, parsed);
            }
            "const_item" => {
                visit_rust_field(file, source, child, Some(&parent), package_name, parsed);
            }
            "type_item" => {
                visit_rust_alias(file, source, child, Some(&parent), package_name, parsed);
            }
            _ => {}
        }
    }
}

fn rust_type_signature(node: Node<'_>, source: &str, _top_level: bool) -> String {
    let header = rust_node_text(node, source)
        .split('{')
        .next()
        .unwrap_or_else(|| rust_node_text(node, source))
        .split(';')
        .next()
        .unwrap_or_else(|| rust_node_text(node, source))
        .trim();
    format!("{header} {{")
}

fn rust_function_signature(node: Node<'_>, source: &str) -> String {
    let header = rust_node_text(node, source)
        .split('{')
        .next()
        .unwrap_or_else(|| rust_node_text(node, source))
        .trim()
        .trim_end_matches(';')
        .to_string();
    if node.kind() == "function_signature_item" {
        header
    } else {
        format!("{header} {{ ... }}")
    }
}

fn collect_rust_type_identifiers(node: Node<'_>, source: &str, identifiers: &mut HashSet<String>) {
    match node.kind() {
        "identifier" | "type_identifier" | "field_identifier" => {
            let text = rust_node_text(node, source).trim();
            if !text.is_empty() {
                identifiers.insert(text.to_string());
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_rust_type_identifiers(child, source, identifiers);
    }
}

fn flatten_rust_use(raw: &str) -> Vec<String> {
    let trimmed = raw.trim().trim_end_matches(';').trim();
    let (prefix, body) = if let Some(body) = trimmed.strip_prefix("pub use ") {
        ("pub use ", body)
    } else if let Some(body) = trimmed.strip_prefix("use ") {
        ("use ", body)
    } else {
        return vec![format!("{trimmed};")];
    };
    expand_rust_use_body("", body)
        .into_iter()
        .map(|path| format!("{prefix}{path};"))
        .collect()
}

fn expand_rust_use_body(prefix: &str, body: &str) -> Vec<String> {
    let body = body.trim();
    if let Some(open_index) = body.find('{') {
        let close_index = body.rfind('}').unwrap_or(body.len());
        let base = body[..open_index].trim_end_matches("::").trim();
        let nested = &body[open_index + 1..close_index];
        let nested_prefix = if prefix.is_empty() {
            base.to_string()
        } else if base.is_empty() {
            prefix.to_string()
        } else {
            format!("{prefix}::{base}")
        };
        split_top_level(nested)
            .into_iter()
            .flat_map(|item| {
                if item.trim() == "self" {
                    vec![nested_prefix.clone()]
                } else {
                    expand_rust_use_body(&nested_prefix, item.trim())
                }
            })
            .collect()
    } else {
        let leaf = if prefix.is_empty() {
            body.to_string()
        } else {
            format!("{prefix}::{body}")
        };
        vec![leaf]
    }
}

fn split_top_level(input: &str) -> Vec<&str> {
    let mut result = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (index, ch) in input.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                result.push(input[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }
    let tail = input[start..].trim();
    if !tail.is_empty() {
        result.push(tail);
    }
    result
}

fn parse_rust_import_info(raw: String) -> ImportInfo {
    let trimmed = raw
        .trim()
        .trim_start_matches("use ")
        .trim_end_matches(';')
        .trim();
    let is_wildcard = trimmed.ends_with("::*");
    let alias = trimmed
        .rsplit_once(" as ")
        .map(|(_, alias)| alias.trim().to_string());
    let path = trimmed
        .rsplit_once(" as ")
        .map(|(path, _)| path)
        .unwrap_or(trimmed);
    let identifier = (!is_wildcard)
        .then(|| {
            path.rsplit("::")
                .next()
                .map(str::trim)
                .filter(|segment| !segment.is_empty())
                .map(str::to_string)
        })
        .flatten();

    ImportInfo {
        raw_snippet: raw,
        is_wildcard,
        identifier,
        alias,
    }
}

fn split_rust_import_module_and_name(raw_import: &str) -> Option<(String, String)> {
    let trimmed = raw_import
        .trim()
        .trim_start_matches("pub ")
        .trim_start_matches("use ")
        .trim_end_matches(';')
        .trim();
    let path = trimmed
        .rsplit_once(" as ")
        .map(|(path, _)| path)
        .unwrap_or(trimmed)
        .trim();
    if path.ends_with("::*") {
        return None;
    }

    let (module_specifier, imported_name) = path.rsplit_once("::")?;
    Some((module_specifier.to_string(), imported_name.to_string()))
}

fn trait_reference_matches(
    analyzer: &RustAnalyzer,
    trait_owner: &CodeUnit,
    impl_file: &ProjectFile,
    trait_ref: &str,
    impl_binder: &ImportBinder,
) -> bool {
    if let Some((module_specifier, imported_name)) = trait_ref.rsplit_once("::") {
        return imported_name == trait_owner.identifier()
            && analyzer
                .resolve_module_files(impl_file, module_specifier)
                .into_iter()
                .any(|file| file == *trait_owner.source());
    }

    if impl_file == trait_owner.source() && trait_ref == trait_owner.identifier() {
        return true;
    }

    impl_binder
        .bindings
        .get(trait_ref)
        .filter(|binding| binding.imported_name.as_deref() == Some(trait_owner.identifier()))
        .is_some_and(|binding| {
            analyzer
                .resolve_module_files(impl_file, &binding.module_specifier)
                .into_iter()
                .any(|file| file == *trait_owner.source())
        })
}

fn resolve_rust_module_path(package: &str, module_specifier: &str) -> Option<String> {
    let trimmed = module_specifier.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed == "crate" {
        return Some(String::new());
    }

    let segments: Vec<_> = trimmed
        .split("::")
        .filter(|segment| !segment.is_empty())
        .collect();
    if segments.is_empty() {
        return None;
    }

    let resolved = if segments[0] == "crate" {
        segments[1..].join(".")
    } else if segments[0] == "super" {
        let mut package_parts: Vec<_> = package
            .split('.')
            .filter(|segment| !segment.is_empty())
            .collect();
        package_parts.pop();
        package_parts
            .into_iter()
            .chain(segments[1..].iter().copied())
            .collect::<Vec<_>>()
            .join(".")
    } else if segments[0] == "self" {
        package
            .split('.')
            .filter(|segment| !segment.is_empty())
            .chain(segments[1..].iter().copied())
            .collect::<Vec<_>>()
            .join(".")
    } else {
        segments.join(".")
    };

    (!resolved.is_empty()).then_some(resolved)
}

static TRAIT_IMPL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bimpl\s+([A-Za-z_][A-Za-z0-9_:]*)\s+for\s+([A-Za-z_][A-Za-z0-9_]*)")
        .expect("valid trait impl regex")
});

fn resolve_rust_import_fq_name(
    _source_file: &ProjectFile,
    package: &str,
    raw_import: &str,
) -> Option<String> {
    let trimmed = raw_import
        .trim()
        .trim_start_matches("pub ")
        .trim_start_matches("use ")
        .trim_end_matches(';')
        .trim();
    let path = trimmed
        .rsplit_once(" as ")
        .map(|(path, _)| path)
        .unwrap_or(trimmed)
        .trim_end_matches("::*")
        .trim();
    let segments: Vec<_> = path
        .split("::")
        .filter(|segment| !segment.is_empty())
        .collect();
    if segments.is_empty() {
        return None;
    }

    resolve_rust_module_path(package, path)
}

fn extract_rust_impl_target_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "type_identifier" | "identifier" => {
            let text = rust_node_text(node, source).trim();
            (!text.is_empty()).then(|| text.to_string())
        }
        "scoped_type_identifier" => node
            .child_by_field_name("name")
            .and_then(|name| extract_rust_impl_target_name(name, source))
            .or_else(|| {
                let mut cursor = node.walk();
                node.named_children(&mut cursor)
                    .find_map(|child| extract_rust_impl_target_name(child, source))
            }),
        "generic_type" | "reference_type" | "pointer_type" | "array_type" | "slice_type" => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find_map(|child| extract_rust_impl_target_name(child, source))
        }
        _ => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find_map(|child| extract_rust_impl_target_name(child, source))
        }
    }
}

fn weight_project_file_set(_key: &ProjectFile, value: &Arc<HashSet<ProjectFile>>) -> u32 {
    let size = value
        .iter()
        .map(|item| item.rel_path().to_string_lossy().len() + size_of::<ProjectFile>())
        .sum::<usize>()
        + size_of::<HashSet<ProjectFile>>();
    size.min(u32::MAX as usize) as u32
}

fn weight_code_unit_set(_key: &ProjectFile, value: &Arc<HashSet<CodeUnit>>) -> u32 {
    let size = value
        .iter()
        .map(|item| item.fq_name().len() + size_of::<CodeUnit>())
        .sum::<usize>()
        + size_of::<HashSet<CodeUnit>>();
    size.min(u32::MAX as usize) as u32
}
