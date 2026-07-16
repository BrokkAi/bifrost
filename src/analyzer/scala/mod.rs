mod adapter;
mod clones;
mod declarations;
mod hierarchy;
pub(crate) mod imports;
pub(crate) mod structural;
mod supertypes;
mod tests;

use crate::analyzer::clone_detection::{CloneCandidateProfile, detect_structural_clone_smells};
use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::js_ts::cache::{
    build_weighted_cache, weight_code_unit_set, weight_code_unit_vec_by_unit,
    weight_project_file_set,
};
use crate::analyzer::tree_sitter_analyzer::FileState;
use crate::analyzer::type_relations::TypeRelation;
use crate::analyzer::{
    AnalyzerConfig, AnalyzerStoreContext, BuildProgress, BulkFileStateSource, CodeUnit,
    DirectDescendantIndex, IAnalyzer, ImportAnalysisProvider, Language, PoolSafeMemo, Project,
    ProjectFile, SignatureMetadata, TestAssertionSmell, TestAssertionWeights,
    TestDetectionProvider, TreeSitterAnalyzer, TypeHierarchyProvider, UsageFactsIndex,
    build_direct_descendant_index,
};
use crate::hash::{HashMap, HashSet};
use crate::{CloneSmell, CloneSmellWeights};
use moka::sync::Cache;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

pub(crate) use adapter::ScalaAdapter;
use clones::{build_scala_clone_candidate_data, refine_scala_clone_similarity};
pub(crate) use declarations::scala_class_parameter_field_keyword;
pub(crate) use supertypes::{ScalaSupertypeLookupPath, scala_type_lookup_segments};
use tests::detect_scala_test_assertion_smells;

pub(crate) fn scala_normalize_full_name(fq_name: &str) -> String {
    fq_name.replace("$.", ".").trim_end_matches('$').to_string()
}

pub(crate) fn scala_simple_type_name(unit: &CodeUnit) -> String {
    unit.short_name()
        .rsplit('.')
        .next()
        .unwrap_or(unit.short_name())
        .trim_end_matches('$')
        .to_string()
}

#[derive(Debug, Clone)]
pub(crate) struct ScalaForwardOwnerFacts {
    pub(crate) supertype_lookup_paths: Vec<ScalaSupertypeLookupPath>,
    pub(crate) signatures: Vec<String>,
    pub(crate) is_trait: bool,
}

pub(crate) fn scala_signature_return_type(signature: &str) -> Option<&str> {
    let (_, after_colon) = signature.rsplit_once(':')?;
    let end = after_colon.find(['=', '{']).unwrap_or(after_colon.len());
    let return_type = after_colon[..end].trim();
    (!return_type.is_empty()).then_some(return_type)
}

pub(crate) fn scala_member_signature_arity(signature: &str) -> Option<usize> {
    if let Some(extension_signature) = signature.strip_prefix("extension ") {
        let after_receiver = extension_signature.split_once(')')?.1.trim_start();
        return after_receiver
            .find('(')
            .and_then(|open| scala_parenthesized_arity(&after_receiver[open..]))
            .or(Some(0));
    }
    let open = signature.find('(')?;
    scala_parenthesized_arity(&signature[open..])
}

pub(crate) fn scala_balanced_parenthesized_prefix(source: &str) -> Option<&str> {
    let mut chars = source.char_indices();
    let (_, first) = chars.next()?;
    if first != '(' {
        return None;
    }
    let mut depth = 1usize;
    for (idx, ch) in chars {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(&source[1..idx]);
                }
            }
            _ => {}
        }
    }
    None
}

pub(crate) fn scala_split_top_level_commas(value: &str) -> impl Iterator<Item = &str> {
    let mut depth = 0usize;
    let mut start = 0usize;
    let mut parts = Vec::new();
    for (idx, ch) in value.char_indices() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(value[start..idx].trim());
                start = idx + ch.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(value[start..].trim());
    parts.into_iter().filter(|part| !part.is_empty())
}

pub(crate) fn scala_parenthesized_arity(source: &str) -> Option<usize> {
    let inner = scala_balanced_parenthesized_prefix(source)?;
    if inner.trim().is_empty() {
        return Some(0);
    }
    Some(scala_split_top_level_commas(inner).count())
}

#[derive(Clone)]
pub struct ScalaAnalyzer {
    inner: TreeSitterAnalyzer<ScalaAdapter>,
    memo_budget: u64,
    imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    direct_ancestors: Cache<CodeUnit, Arc<Vec<CodeUnit>>>,
    reverse_import_index: Arc<PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    importable_declarations_by_package: Arc<OnceLock<HashMap<String, Arc<Vec<CodeUnit>>>>>,
    same_package_reference_index:
        Arc<PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    direct_descendant_index: Arc<OnceLock<DirectDescendantIndex>>,
    /// Analyzer-cached Scala usage/type-resolution support, built once per
    /// analyzer generation and reset on `update`/`update_all`.
    project_types: Arc<OnceLock<Arc<crate::analyzer::usages::scala_graph::ScalaProjectTypes>>>,
    project_types_build_count: Arc<AtomicUsize>,
    #[allow(dead_code)]
    type_relations: Arc<OnceLock<Vec<TypeRelation>>>,
}

crate::analyzer::impl_forward_query_provider!(ScalaAnalyzer);

impl ScalaAnalyzer {
    pub(crate) fn forward_owner_facts(
        &self,
        code_unit: &CodeUnit,
    ) -> Option<ScalaForwardOwnerFacts> {
        let state = self.inner.fetch_file_state(code_unit.source())?;
        if !state.declarations.contains(code_unit) {
            return None;
        }
        let raw_supertypes = state
            .raw_supertypes
            .get(code_unit)
            .cloned()
            .unwrap_or_default();
        let supertype_lookup_paths = state
            .supertype_lookup_paths
            .get(code_unit)
            .into_iter()
            .flatten()
            .map(|path| ScalaSupertypeLookupPath::decode(path))
            .collect::<Option<Vec<_>>>()?;
        if raw_supertypes.len() != supertype_lookup_paths.len() {
            return None;
        }
        Some(ScalaForwardOwnerFacts {
            supertype_lookup_paths,
            signatures: state.signatures.get(code_unit).cloned().unwrap_or_default(),
            is_trait: state.scala_traits.contains(code_unit),
        })
    }

    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        let mut clone = self.clone();
        clone.inner = clone.inner.clone_with_project(project);
        clone.project_types = Arc::new(OnceLock::new());
        clone.project_types_build_count = Arc::new(AtomicUsize::new(0));
        clone
    }

    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        let inner = TreeSitterAnalyzer::new_with_config(project, ScalaAdapter, config);
        Self::from_inner(inner, memo_budget)
    }

    fn from_inner(inner: TreeSitterAnalyzer<ScalaAdapter>, memo_budget: u64) -> Self {
        Self {
            inner,
            memo_budget,
            imported_code_units: build_weighted_cache(memo_budget / 4, weight_code_unit_set),
            referencing_files: build_weighted_cache(memo_budget / 8, weight_project_file_set),
            direct_ancestors: build_weighted_cache(memo_budget / 8, weight_code_unit_vec_by_unit),
            reverse_import_index: Arc::new(PoolSafeMemo::new()),
            importable_declarations_by_package: Arc::new(OnceLock::new()),
            same_package_reference_index: Arc::new(PoolSafeMemo::new()),
            direct_descendant_index: Arc::new(OnceLock::new()),
            project_types: Arc::new(OnceLock::new()),
            project_types_build_count: Arc::new(AtomicUsize::new(0)),
            type_relations: Arc::new(OnceLock::new()),
        }
    }

    /// Owned handles to the workspace indexes (refcount bumps, not map
    /// clones), for per-query views held behind `Arc` caches.
    pub(crate) fn global_usage_definition_index_shared(
        &self,
    ) -> Arc<crate::analyzer::GlobalUsageDefinitionIndex> {
        self.inner.global_usage_definition_index_shared()
    }

    pub(crate) fn usage_facts_index_shared(&self) -> Arc<UsageFactsIndex> {
        self.inner.usage_facts_index_shared()
    }

    pub(crate) fn project_types(
        &self,
    ) -> Arc<crate::analyzer::usages::scala_graph::ScalaProjectTypes> {
        self.project_types
            .get_or_init(|| {
                self.project_types_build_count
                    .fetch_add(1, Ordering::Relaxed);
                Arc::new(crate::analyzer::usages::scala_graph::ScalaProjectTypes::build(self))
            })
            .clone()
    }

    pub(crate) fn new_with_config_store_context(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        store_context: AnalyzerStoreContext,
        progress: Option<BuildProgress>,
    ) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        let inner = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            project,
            ScalaAdapter,
            config,
            store_context,
            progress,
        );
        Self::from_inner(inner, memo_budget)
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }

    pub(crate) fn bulk_file_states(
        &self,
        files: impl IntoIterator<Item = ProjectFile>,
        source_mode: BulkFileStateSource,
    ) -> HashMap<ProjectFile, FileState> {
        self.inner.bulk_file_states(files, source_mode)
    }

    pub(crate) fn bulk_import_infos(
        &self,
        files: impl IntoIterator<Item = ProjectFile>,
    ) -> HashMap<ProjectFile, Vec<crate::analyzer::ImportInfo>> {
        self.inner.bulk_import_infos(files)
    }

    #[doc(hidden)]
    pub fn reset_full_hydration_count_for_test(&self) {
        self.inner.reset_full_hydration_count_for_test();
    }

    #[doc(hidden)]
    pub fn full_hydration_count_for_test(&self) -> usize {
        self.inner.full_hydration_count_for_test()
    }

    #[doc(hidden)]
    pub fn bulk_hydration_count_for_test(&self) -> usize {
        self.inner.bulk_hydration_count_for_test()
    }

    fn render_skeleton_recursive(
        &self,
        code_unit: &CodeUnit,
        indent: &str,
        header_only: bool,
        out: &mut String,
    ) {
        for signature in self.signatures(code_unit) {
            if signature.is_empty() {
                continue;
            }
            for line in signature.lines() {
                out.push_str(indent);
                out.push_str(line);
                out.push('\n');
            }
        }

        let all_children = self.direct_children(code_unit);
        let field_children: Vec<_> = all_children
            .iter()
            .filter(|child| child.is_field())
            .cloned()
            .collect();
        let children = if header_only {
            field_children.clone()
        } else {
            all_children.clone()
        };

        if !children.is_empty() || code_unit.is_class() {
            let child_indent = format!("{indent}  ");
            for child in children {
                self.render_skeleton_recursive(&child, &child_indent, header_only, out);
            }
            if header_only && all_children.len() > field_children.len() {
                out.push_str(&child_indent);
                out.push_str("[...]\n");
            }
            if code_unit.is_class() {
                out.push_str(indent);
                out.push_str("}\n");
            }
        }
    }
}

impl TestDetectionProvider for ScalaAnalyzer {}

impl IAnalyzer for ScalaAnalyzer {
    fn begin_query(&self) {
        self.inner.begin_query();
    }

    fn end_query(&self) {
        self.inner.end_query();
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

    fn reset_workspace_path_scan_count_for_test(&self) {
        self.inner.reset_workspace_path_scan_count_for_test();
    }

    fn workspace_path_scan_count_for_test(&self) -> usize {
        self.inner.workspace_path_scan_count_for_test()
    }

    fn reset_scala_project_types_build_count_for_test(&self) {
        self.project_types_build_count.store(0, Ordering::Relaxed);
    }

    fn scala_project_types_build_count_for_test(&self) -> usize {
        self.project_types_build_count.load(Ordering::Relaxed)
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

    fn direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.inner
            .direct_children(code_unit)
            .into_iter()
            .filter(|child| !child.is_synthetic())
            .collect()
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
        self.forward_owner_facts(code_unit)
            .map(|facts| facts.signatures)
            .unwrap_or_else(|| self.inner.signatures(code_unit))
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
        Self::from_inner(self.inner.update(changed_files), self.memo_budget)
    }

    fn update_all(&self) -> Self {
        Self::from_inner(self.inner.update_all(), self.memo_budget)
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
        let mut rendered = String::new();
        self.render_skeleton_recursive(code_unit, "", false, &mut rendered);
        (!rendered.is_empty()).then(|| rendered.trim_end().to_string())
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        let mut rendered = String::new();
        self.render_skeleton_recursive(code_unit, "", true, &mut rendered);
        (!rendered.is_empty()).then(|| rendered.trim_end().to_string())
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

    fn find_test_assertion_smells(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
    ) -> Vec<TestAssertionSmell> {
        if !self.contains_tests(file) || file_language(file) != Language::Scala {
            return Vec::new();
        }
        let Ok(source) = self.inner.project().read_source(file) else {
            return Vec::new();
        };
        detect_scala_test_assertion_smells(file, &source, &weights)
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
            .filter(|file| file_language(file) == Language::Scala)
            .cloned()
            .collect();
        if requested_files.is_empty() {
            return Vec::new();
        }

        let all_candidates: Vec<CloneCandidateProfile> = self
            .get_all_declarations()
            .into_iter()
            .filter(|code_unit| {
                code_unit.is_function() && file_language(code_unit.source()) == Language::Scala
            })
            .filter_map(|code_unit| build_scala_clone_candidate_data(self, &code_unit, weights))
            .map(|candidate| CloneCandidateProfile::create(candidate, weights))
            .collect();
        if all_candidates.is_empty() {
            return Vec::new();
        }

        detect_structural_clone_smells(
            &requested_files,
            all_candidates,
            weights,
            refine_scala_clone_similarity,
        )
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        Some(self)
    }
}

#[cfg(test)]
mod overlay_usage_tests {
    use super::*;
    use crate::analyzer::usages::{UsageFinder, scala_graph::build_scala_usage_edges};
    use crate::analyzer::{OverlayProject, TestProject};

    #[test]
    fn cloned_overlay_rebuilds_scala_source_facts_for_targeted_and_inverted_ranges() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), "app/Calls.scala");
        std::fs::create_dir_all(file.abs_path().parent().expect("source parent"))
            .expect("source directory");
        file.write(
            r#"package app
class Api { def choose(value: Int): Int = value }
class Use(api: Api) { def call(): Int = api.choose(1) }
"#,
        )
        .expect("disk Scala source");

        let disk_project: Arc<dyn Project> =
            Arc::new(TestProject::new(root.clone(), Language::Scala));
        let disk = ScalaAnalyzer::new(Arc::clone(&disk_project));
        let disk_target = disk
            .get_definitions("app.Api.choose")
            .into_iter()
            .next()
            .expect("disk target");
        let disk_hits = UsageFinder::new()
            .find_usages_default(&disk, std::slice::from_ref(&disk_target))
            .into_either()
            .expect("disk usages");
        assert!(
            disk_hits
                .iter()
                .any(|hit| hit.snippet.contains("api.choose(1)"))
        );
        assert!(
            disk.project_types.get().is_some(),
            "disk cache should be warm"
        );

        let overlay_source = r#"package app
// This overlay shifts every exact declaration range and changes the callable shape.
class Api { def choose(value: Int)(label: String): Int = value }
class Use(api: Api) { def call(): Int = api.choose(1)("overlay") }
"#;
        let overlay = Arc::new(OverlayProject::new(Arc::clone(&disk_project)));
        assert!(overlay.set(file.abs_path(), overlay_source.to_string()));
        let snapshot = disk.clone_with_project(Arc::clone(&overlay) as Arc<dyn Project>);
        assert!(
            snapshot.project_types.get().is_none(),
            "an overlay clone needs an independent source-facts generation"
        );
        let overlay_target = snapshot
            .get_definitions("app.Api.choose")
            .into_iter()
            .next()
            .expect("overlay target");
        let overlay_hits = UsageFinder::new()
            .find_usages_default(&snapshot, std::slice::from_ref(&overlay_target))
            .into_either()
            .expect("overlay usages");
        assert!(
            overlay_hits
                .iter()
                .any(|hit| hit.snippet.contains("api.choose(1)(\"overlay\")")),
            "targeted lookup must use overlay ranges and callable facts: {overlay_hits:#?}"
        );

        let nodes = snapshot
            .get_all_declarations()
            .into_iter()
            .map(|unit| unit.fq_name())
            .collect();
        let edges = build_scala_usage_edges(&snapshot, &nodes, |_| true)
            .expect("Scala inverted edge build");
        assert!(
            edges
                .edges
                .keys()
                .any(|(caller, callee)| caller == "app.Use.call" && callee == "app.Api.choose"),
            "inverted lookup must use overlay ranges and callable facts: {:?}",
            edges.edges.keys().collect::<Vec<_>>()
        );
    }
}
