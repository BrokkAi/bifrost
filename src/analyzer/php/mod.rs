mod adapter;
mod aliases;
mod clones;
mod composer;
mod declarations;
mod diagnostics;
mod semantic;
pub(crate) mod structural;
mod tests;

use crate::analyzer::clone_detection::{CloneCandidateProfile, detect_structural_clone_smells};
use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::js_ts::{build_weighted_cache, weight_code_unit_vec_by_unit};
use crate::analyzer::{
    AnalyzerConfig, AnalyzerStoreContext, BuildProgress, CodeUnit, DirectDescendantIndex,
    IAnalyzer, Language, Project, ProjectFile, Range, SemanticDiagnostic, SignatureMetadata,
    TestAssertionSmell, TestAssertionWeights, TestDetectionProvider, TreeSitterAnalyzer,
    TypeHierarchyProvider, UsageFactsIndex, build_direct_descendant_index,
};
use crate::hash::{HashMap, HashSet};
use crate::{CloneSmell, CloneSmellWeights};
use moka::sync::Cache;
use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};
use tree_sitter::{Node, Parser};

use adapter::PhpAdapter;
pub(crate) use adapter::php_signature_return_type_text;
pub(crate) use aliases::{
    PhpFileContext, resolve_php_constant, resolve_php_function, resolve_php_type,
};
pub use aliases::{
    PhpUseAliases, parse_php_use_aliases, parse_php_use_aliases_by_kind,
    parse_php_use_aliases_from_source, php_namespace_to_fq,
};
use clones::{build_php_clone_candidate_data, refine_php_clone_similarity};
use composer::PhpComposerAutoload;
use tests::detect_php_test_assertion_smells;

#[derive(Clone)]
pub struct PhpAnalyzer {
    inner: TreeSitterAnalyzer<PhpAdapter>,
    memo_budget: u64,
    direct_ancestors: Cache<CodeUnit, Arc<Vec<CodeUnit>>>,
    direct_descendant_index: Arc<OnceLock<DirectDescendantIndex>>,
    composer_autoload: Arc<PhpComposerAutoload>,
}

crate::analyzer::impl_forward_query_provider!(PhpAnalyzer);

impl PhpAnalyzer {
    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        let mut clone = self.clone();
        clone.inner = clone.inner.clone_with_project(project);
        clone
    }

    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        let inner = TreeSitterAnalyzer::new_with_config(project, PhpAdapter, config);
        Self::from_inner(inner, memo_budget)
    }

    pub(crate) fn new_with_config_store_context(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        store_context: AnalyzerStoreContext,
        progress: Option<BuildProgress>,
    ) -> Result<Self, crate::analyzer::store::StoreError> {
        let memo_budget = config.memo_cache_budget_bytes();
        let inner = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            project,
            PhpAdapter,
            config,
            store_context,
            progress,
        )?;
        Ok(Self::from_inner(inner, memo_budget))
    }

    fn from_inner(inner: TreeSitterAnalyzer<PhpAdapter>, memo_budget: u64) -> Self {
        let composer_autoload = Arc::new(PhpComposerAutoload::from_project(inner.project()));
        Self::from_inner_with_composer(inner, memo_budget, composer_autoload)
    }

    fn from_inner_with_composer(
        inner: TreeSitterAnalyzer<PhpAdapter>,
        memo_budget: u64,
        composer_autoload: Arc<PhpComposerAutoload>,
    ) -> Self {
        Self {
            inner,
            memo_budget,
            direct_ancestors: build_weighted_cache(memo_budget / 8, weight_code_unit_vec_by_unit),
            direct_descendant_index: Arc::new(OnceLock::new()),
            composer_autoload,
        }
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }

    pub fn is_constructor(
        &self,
        method: &CodeUnit,
        class_unit: &CodeUnit,
        _package_name: &str,
    ) -> bool {
        method.is_function()
            && class_unit.is_class()
            && method.identifier() == "__construct"
            && method.fq_name() == format!("{}.__construct", class_unit.fq_name())
    }

    pub fn namespace_of_file(&self, file: &ProjectFile) -> String {
        self.inner
            .top_level_declarations(file)
            .into_iter()
            .next()
            .map(|unit| unit.package_name().to_string())
            .unwrap_or_default()
    }

    pub fn use_aliases_of(&self, file: &ProjectFile) -> HashMap<String, String> {
        self.use_aliases_by_kind_of(file).type_aliases
    }

    pub fn use_aliases_by_kind_of(&self, file: &ProjectFile) -> PhpUseAliases {
        let Ok(source) = self.inner.project().read_source(file) else {
            return PhpUseAliases::default();
        };
        Self::use_aliases_by_kind_from_source(&source)
    }

    pub(crate) fn use_aliases_by_kind_from_source(source: &str) -> PhpUseAliases {
        parse_php_use_aliases_from_source(source)
    }

    pub(crate) fn file_context_from_source(
        &self,
        file: &ProjectFile,
        source: &str,
    ) -> PhpFileContext {
        PhpFileContext {
            namespace: self.namespace_of_file(file),
            aliases: Self::use_aliases_by_kind_from_source(source),
        }
    }

    fn declaration_context(&self, code_unit: &CodeUnit) -> PhpFileContext {
        let namespace = code_unit.package_name().to_string();
        let aliases = self
            .declaration_start(code_unit)
            .and_then(|start| self.aliases_visible_before(code_unit.source(), start))
            .unwrap_or_else(|| self.use_aliases_by_kind_of(code_unit.source()));
        PhpFileContext { namespace, aliases }
    }

    pub(crate) fn target_has_composer_autoload_visibility(&self, target: &CodeUnit) -> bool {
        self.composer_autoload.target_is_autoloaded(self, target)
    }

    fn declaration_start(&self, code_unit: &CodeUnit) -> Option<usize> {
        self.ranges(code_unit)
            .iter()
            .map(|range| range.start_byte)
            .min()
    }

    fn aliases_visible_before(
        &self,
        file: &ProjectFile,
        declaration_start: usize,
    ) -> Option<PhpUseAliases> {
        let source = self.inner.project().read_source(file).ok()?;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
            .ok()?;
        let tree = parser.parse(source.as_str(), None)?;
        Some(php_aliases_visible_before(
            tree.root_node(),
            &source,
            declaration_start,
        ))
    }

    pub(crate) fn is_interface(&self, code_unit: &CodeUnit) -> bool {
        if !code_unit.is_class() {
            return false;
        }
        if let Some(kind) = self.declaration_kind(code_unit) {
            return kind == "interface_declaration";
        }
        self.signatures(code_unit).iter().any(|signature| {
            signature
                .split_whitespace()
                .any(|token| token == "interface")
        })
    }

    pub(crate) fn is_trait(&self, code_unit: &CodeUnit) -> bool {
        code_unit.is_class()
            && self
                .declaration_kind(code_unit)
                .is_some_and(|kind| kind == "trait_declaration")
    }

    fn resolve_declared_supertype(&self, code_unit: &CodeUnit, raw: &str) -> Option<CodeUnit> {
        let ctx = self.declaration_context(code_unit);
        let fq_name = resolve_php_type(raw, &ctx)?;
        self.definitions(&fq_name)
            .find(|candidate| candidate.is_class())
    }

    pub(crate) fn direct_declared_class_parent(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        self.get_direct_ancestors(code_unit)
            .into_iter()
            .find(|ancestor| !self.is_interface(ancestor) && !self.is_trait(ancestor))
    }

    fn declaration_kind(&self, code_unit: &CodeUnit) -> Option<&'static str> {
        let source = self.inner.project().read_source(code_unit.source()).ok()?;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
            .ok()?;
        let tree = parser.parse(source.as_str(), None)?;
        let ranges = self.ranges(code_unit);
        let start = ranges.iter().map(|range| range.start_byte).min()?;
        let end = ranges.iter().map(|range| range.end_byte).max()?;
        php_declaration_kind_for_range(tree.root_node(), start, end)
    }
}

impl TestDetectionProvider for PhpAnalyzer {}

fn php_declaration_kind_for_range(
    root: Node<'_>,
    start: usize,
    end: usize,
) -> Option<&'static str> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if matches!(
            node.kind(),
            "class_declaration" | "interface_declaration" | "trait_declaration"
        ) && node.start_byte() >= start
            && node.end_byte() <= end
        {
            return Some(node.kind());
        }

        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index)
                && child.end_byte() >= start
                && child.start_byte() <= end
            {
                stack.push(child);
            }
        }
    }
    None
}

impl TypeHierarchyProvider for PhpAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        if let Some(cached) = self.direct_ancestors.get(code_unit) {
            return (*cached).clone();
        }

        let ancestors: Vec<_> = self
            .inner
            .raw_supertypes_of(code_unit)
            .iter()
            .filter_map(|raw| self.resolve_declared_supertype(code_unit, raw))
            .collect();
        self.direct_ancestors
            .insert(code_unit.clone(), Arc::new(ancestors.clone()));
        ancestors
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        self.direct_descendant_index
            .get_or_init(|| build_direct_descendant_index(self, self))
            .descendants(code_unit)
    }
}

impl IAnalyzer for PhpAnalyzer {
    fn begin_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        self.inner.begin_query(context);
    }

    fn end_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        self.inner.end_query(context);
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

    fn global_usage_definition_index(&self) -> &crate::analyzer::GlobalUsageDefinitionIndex {
        self.inner.global_usage_definition_index()
    }

    fn usage_facts_index(&self) -> &UsageFactsIndex {
        self.inner.usage_facts_index()
    }

    fn structural_search_providers(
        &self,
    ) -> Vec<&dyn crate::analyzer::structural::StructuralSearchProvider> {
        self.inner.structural_search_providers()
    }

    fn snapshot_derived_layer_cache(
        &self,
    ) -> Option<&crate::analyzer::structural::execution::derived::SnapshotDerivedLayerCache> {
        self.inner.snapshot_derived_layer_cache()
    }

    fn direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.inner.direct_children(code_unit)
    }

    fn import_statements(&self, file: &ProjectFile) -> Vec<String> {
        self.inner.import_statements(file)
    }

    fn ranges(&self, code_unit: &CodeUnit) -> Vec<crate::analyzer::Range> {
        self.inner.ranges(code_unit)
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
        let inner = self.inner.update(changed_files);
        let composer_autoload = if changed_files
            .iter()
            .any(PhpComposerAutoload::manifest_changed)
        {
            Arc::new(PhpComposerAutoload::from_project(inner.project()))
        } else {
            self.composer_autoload.clone()
        };
        Self::from_inner_with_composer(inner, self.memo_budget, composer_autoload)
    }

    fn update_all(&self) -> Self {
        Self::from_inner(self.inner.update_all(), self.memo_budget)
    }

    fn project(&self) -> &dyn Project {
        self.inner.project()
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

    fn semantic_diagnostics(&self, file: &ProjectFile, source: &str) -> Vec<SemanticDiagnostic> {
        diagnostics::collect_php_semantic_diagnostics(self, file, source)
            .into_iter()
            .map(Into::into)
            .collect()
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        self.inner.extract_call_receiver(reference)
    }

    fn enclosing_code_unit(&self, file: &ProjectFile, range: &Range) -> Option<CodeUnit> {
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

    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        let skeleton = self.inner.get_skeleton(code_unit)?;
        if code_unit.is_class() && self.inner.direct_children(code_unit).is_empty() {
            let trimmed = skeleton.trim();
            if trimmed.ends_with("{\n}") || trimmed.ends_with("{\r\n}") {
                let compact = trimmed.trim_end_matches('}').trim_end().to_string();
                return Some(format!("{compact} }}"));
            }
        }
        Some(skeleton)
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

    fn lookup_candidates_by_short_name(&self, symbol: &str) -> BTreeSet<CodeUnit> {
        self.inner.lookup_candidates_by_short_name(symbol)
    }

    fn lookup_candidates_by_identifier(&self, identifier: &str) -> BTreeSet<CodeUnit> {
        self.inner.lookup_declarations_by_identifier(identifier)
    }

    fn search_symbol_candidates(
        &self,
        pattern: &str,
        auto_quote: bool,
    ) -> Vec<crate::analyzer::SearchSymbolCandidate> {
        self.inner.search_symbol_candidates(pattern, auto_quote)
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
        if !self.contains_tests(file) || file_language(file) != Language::Php {
            return Vec::new();
        }
        let Ok(source) = self.inner.project().read_source(file) else {
            return Vec::new();
        };
        detect_php_test_assertion_smells(file, &source, &weights)
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
            .filter(|file| file_language(file) == Language::Php)
            .cloned()
            .collect();
        if requested_files.is_empty() {
            return Vec::new();
        }

        let all_candidates: Vec<CloneCandidateProfile> = self
            .get_all_declarations()
            .into_iter()
            .filter(|code_unit| {
                code_unit.is_function() && file_language(code_unit.source()) == Language::Php
            })
            .filter_map(|code_unit| build_php_clone_candidate_data(self, &code_unit, weights))
            .map(|candidate| CloneCandidateProfile::create(candidate, weights))
            .collect();
        if all_candidates.is_empty() {
            return Vec::new();
        }

        detect_structural_clone_smells(
            &requested_files,
            all_candidates,
            weights,
            refine_php_clone_similarity,
        )
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        Some(self)
    }
}

fn php_aliases_visible_before(
    root: Node<'_>,
    source: &str,
    declaration_start: usize,
) -> PhpUseAliases {
    let namespace_scope = php_namespace_scope(root, declaration_start);
    let mut aliases = PhpUseAliases::default();
    let mut stack = vec![namespace_scope.unwrap_or(root)];
    while let Some(node) = stack.pop() {
        if node.start_byte() >= declaration_start {
            continue;
        }
        if node.kind() == "namespace_use_declaration" {
            aliases.extend(parse_php_use_aliases_by_kind(
                &source[node.start_byte()..node.end_byte()],
            ));
            continue;
        }

        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    aliases
}

fn php_namespace_scope(root: Node<'_>, declaration_start: usize) -> Option<Node<'_>> {
    let mut best = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "namespace_definition"
            && node.start_byte() <= declaration_start
            && declaration_start <= node.end_byte()
        {
            best = Some(node);
        }

        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    best
}
