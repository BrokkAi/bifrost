mod adapter;
mod cache;
mod declarations;
mod hierarchy;
mod imports;
mod mixins;
mod semantic;
pub(crate) mod structural;
mod tests;

use crate::analyzer::js_ts::build_weighted_cache;
use crate::analyzer::type_relations::{TypeRelation, TypeRelationKind};
use crate::analyzer::{
    AnalyzerConfig, AnalyzerStoreContext, BuildProgress, CodeUnit, CodeUnitType,
    DirectDescendantIndex, IAnalyzer, ImportAnalysisProvider, Language, PoolSafeMemo, Project,
    ProjectFile, Range, RubyMethodDispatchMode, SignatureMetadata, TestDetectionProvider,
    TreeSitterAnalyzer, TypeHierarchyProvider,
};
use crate::hash::{HashMap, HashSet};
use moka::sync::Cache;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, OnceLock};
use tree_sitter::Node;

pub(crate) use adapter::RubyAdapter;
use cache::{weight_code_unit_set, weight_code_unit_vec, weight_project_file_set};

pub(crate) use declarations::{
    RubyFieldScope, extract_name_path, extract_name_segments, parse_ruby_tree,
    ruby_field_short_name, ruby_variable_field_name,
};
pub(crate) use imports::{is_ruby_autoload_symbol_argument, ruby_symbol_name};

pub(crate) fn single_static_string_content_node(node: Node<'_>) -> Option<Node<'_>> {
    if node.named_child_count() != 1 {
        return None;
    }
    let content = node.named_child(0)?;
    (content.kind() == "string_content").then_some(content)
}

/// Returns the source range of the semantic identifier carried by a Ruby symbol.
///
/// Tree-sitter represents an unquoted symbol such as `:audit` as one leaf
/// `simple_symbol` node, so its parser range includes the leading colon. Static
/// quoted symbols have a structured `string_content` child that excludes both
/// the colon and quote delimiters. Other nodes keep their parser range.
pub(crate) fn ruby_semantic_identifier_range(node: Node<'_>, source: &str) -> Range {
    let node_range = || Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row,
        end_line: node.end_position().row,
    };

    match node.kind() {
        "simple_symbol" => {
            let text = source.get(node.start_byte()..node.end_byte()).unwrap_or("");
            if text.strip_prefix(':').is_none_or(str::is_empty) {
                return node_range();
            }
            Range {
                start_byte: node.start_byte() + ':'.len_utf8(),
                end_byte: node.end_byte(),
                start_line: node.start_position().row,
                end_line: node.end_position().row,
            }
        }
        "delimited_symbol" => {
            let Some(content) = single_static_string_content_node(node) else {
                return node_range();
            };
            Range {
                start_byte: content.start_byte(),
                end_byte: content.end_byte(),
                start_line: content.start_position().row,
                end_line: content.end_position().row,
            }
        }
        _ => node_range(),
    }
}

#[derive(Clone)]
pub struct RubyAnalyzer {
    inner: TreeSitterAnalyzer<RubyAdapter>,
    memo_budget: u64,
    imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    direct_ancestors: Cache<CodeUnit, Arc<Vec<CodeUnit>>>,
    direct_descendant_index: Arc<OnceLock<DirectDescendantIndex>>,
    reverse_import_index: Arc<PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    autoload_constant_files: Arc<OnceLock<HashMap<String, HashSet<ProjectFile>>>>,
    zeitwerk_project: Arc<OnceLock<bool>>,
    zeitwerk_autoload_files: Arc<OnceLock<HashSet<ProjectFile>>>,
    zeitwerk_consumer_files: Arc<OnceLock<HashSet<ProjectFile>>>,
    zeitwerk_autoload_code_units: Arc<OnceLock<HashSet<CodeUnit>>>,
    zeitwerk_reference_files: Arc<OnceLock<HashMap<String, HashSet<ProjectFile>>>>,
    #[allow(dead_code)]
    mixin_relations: Arc<OnceLock<Vec<TypeRelation>>>,
    semantic_facts: Arc<OnceLock<RubySemanticFacts>>,
    /// Class/module declarations indexed by their trailing identifier, for
    /// resolving relative (unqualified) supertype references without scanning
    /// every declaration.
    types_by_identifier: Arc<OnceLock<HashMap<String, Vec<CodeUnit>>>>,
}

crate::analyzer::impl_forward_query_provider!(RubyAnalyzer);

impl RubyAnalyzer {
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
        let inner = TreeSitterAnalyzer::new_with_config(project, RubyAdapter, config);
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
            RubyAdapter,
            config,
            store_context,
            progress,
        )?;
        Ok(Self::from_inner(inner, memo_budget))
    }

    fn from_inner(inner: TreeSitterAnalyzer<RubyAdapter>, memo_budget: u64) -> Self {
        Self {
            inner,
            memo_budget,
            imported_code_units: build_weighted_cache(memo_budget / 4, weight_code_unit_set),
            referencing_files: build_weighted_cache(memo_budget / 8, weight_project_file_set),
            direct_ancestors: build_weighted_cache(memo_budget / 8, weight_code_unit_vec),
            direct_descendant_index: Arc::new(OnceLock::new()),
            reverse_import_index: Arc::new(PoolSafeMemo::new()),
            autoload_constant_files: Arc::new(OnceLock::new()),
            zeitwerk_project: Arc::new(OnceLock::new()),
            zeitwerk_autoload_files: Arc::new(OnceLock::new()),
            zeitwerk_consumer_files: Arc::new(OnceLock::new()),
            zeitwerk_autoload_code_units: Arc::new(OnceLock::new()),
            zeitwerk_reference_files: Arc::new(OnceLock::new()),
            mixin_relations: Arc::new(OnceLock::new()),
            semantic_facts: Arc::new(OnceLock::new()),
            types_by_identifier: Arc::new(OnceLock::new()),
        }
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }

    pub(crate) fn semantic_facts(&self) -> &RubySemanticFacts {
        self.semantic_facts
            .get_or_init(|| RubySemanticFacts::build(self))
    }

    pub(crate) fn method_dispatch_mode(&self, unit: &CodeUnit) -> RubyMethodDispatchMode {
        self.inner
            .ruby_method_dispatch_mode(unit)
            .unwrap_or(RubyMethodDispatchMode::Instance)
    }

    pub(crate) fn forward_raw_supertypes(&self, unit: &CodeUnit) -> Vec<String> {
        self.forward_superclass_targets(unit)
    }
}

pub(crate) struct RubySemanticFacts {
    pub(crate) ancestors: HashMap<String, HashSet<String>>,
    pub(crate) mixin_included_owners: HashMap<String, Vec<String>>,
    pub(crate) mixin_prepended_owners: HashMap<String, Vec<String>>,
    pub(crate) mixin_class_owners: HashMap<String, Vec<String>>,
}

impl RubySemanticFacts {
    fn build(ruby: &RubyAnalyzer) -> Self {
        let mut ancestors = HashMap::default();
        let mut mixin_included_owners: HashMap<String, Vec<String>> = HashMap::default();
        let mut mixin_prepended_owners: HashMap<String, Vec<String>> = HashMap::default();
        let mut mixin_class_owners: HashMap<String, Vec<String>> = HashMap::default();

        for unit in ruby
            .all_declarations()
            .filter(|unit| unit.is_class() || unit.is_module())
        {
            let direct = ruby
                .get_direct_ancestors(&unit)
                .into_iter()
                .map(|ancestor| ancestor.fq_name())
                .collect();
            ancestors.insert(unit.fq_name(), direct);
        }

        for relation in ruby.mixin_relations() {
            let entry = match relation.kind {
                TypeRelationKind::MixinInclude => &mut mixin_included_owners,
                TypeRelationKind::MixinPrepend => &mut mixin_prepended_owners,
                TypeRelationKind::MixinExtend => &mut mixin_class_owners,
                _ => continue,
            };
            push_ordered_mixin(entry, relation.from.fq_name(), relation.to.fq_name());
        }

        Self {
            ancestors,
            mixin_included_owners,
            mixin_prepended_owners,
            mixin_class_owners,
        }
    }
}

fn push_ordered_mixin(index: &mut HashMap<String, Vec<String>>, from: String, to: String) {
    let owners = index.entry(from).or_default();
    if !owners.contains(&to) {
        owners.push(to);
    }
}

impl IAnalyzer for RubyAnalyzer {
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

    fn structural_search_providers(
        &self,
    ) -> Vec<&dyn crate::analyzer::structural::StructuralSearchProvider> {
        self.inner.structural_search_providers()
    }

    fn snapshot_caches(&self) -> Option<&crate::analyzer::AnalyzerSnapshotCaches> {
        Some(self.inner.snapshot_caches())
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

    fn languages(&self) -> BTreeSet<Language> {
        self.inner.languages()
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        Self::from_inner(self.inner.update(changed_files), self.memo_budget)
    }

    fn update_all(&self) -> Self {
        Self::from_inner(self.inner.update_all(), self.memo_budget)
    }

    fn project(&self) -> &dyn Project {
        self.inner.project()
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

    fn contains_tests(&self, file: &ProjectFile) -> bool {
        self.inner.contains_tests(file)
    }

    fn in_test_region(&self, code_unit: &crate::analyzer::CodeUnit) -> bool {
        self.inner.in_test_region(code_unit)
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
}
