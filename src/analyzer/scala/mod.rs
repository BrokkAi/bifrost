mod adapter;
mod clones;
mod declarations;
mod hierarchy;
pub(crate) mod imports;
mod supertypes;
mod tests;

use crate::analyzer::clone_detection::{CloneCandidateProfile, detect_structural_clone_smells};
use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::js_ts::cache::{
    build_weighted_cache, weight_code_unit_set, weight_code_unit_set_by_unit,
    weight_code_unit_vec_by_unit, weight_project_file_set,
};
use crate::analyzer::type_relations::TypeRelation;
use crate::analyzer::{
    AnalyzerConfig, BuildProgress, CodeUnit, IAnalyzer, ImportAnalysisProvider, Language, Project,
    ProjectFile, SignatureMetadata, TestAssertionSmell, TestAssertionWeights,
    TestDetectionProvider, TreeSitterAnalyzer, TypeHierarchyProvider, UsageFactsIndex,
    build_direct_descendant_index,
};
use crate::hash::{HashMap, HashSet};
use crate::{CloneSmell, CloneSmellWeights};
use moka::sync::Cache;
use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};

use adapter::ScalaAdapter;
use clones::{build_scala_clone_candidate_data, refine_scala_clone_similarity};
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
    direct_descendants: Cache<CodeUnit, Arc<HashSet<CodeUnit>>>,
    reverse_import_index: Arc<OnceLock<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    importable_declarations_by_package: Arc<OnceLock<HashMap<String, Arc<Vec<CodeUnit>>>>>,
    same_package_reference_index: Arc<OnceLock<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    direct_descendant_index: Arc<OnceLock<HashMap<String, Arc<HashSet<CodeUnit>>>>>,
    /// Analyzer-cached Scala usage/type-resolution support, built once per
    /// analyzer generation and reset on `update`/`update_all`.
    project_types: Arc<OnceLock<Arc<crate::analyzer::usages::scala_graph::ScalaProjectTypes>>>,
    #[allow(dead_code)]
    type_relations: Arc<OnceLock<Vec<TypeRelation>>>,
}

impl ScalaAnalyzer {
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
            direct_descendants: build_weighted_cache(memo_budget / 8, weight_code_unit_set_by_unit),
            reverse_import_index: Arc::new(OnceLock::new()),
            importable_declarations_by_package: Arc::new(OnceLock::new()),
            same_package_reference_index: Arc::new(OnceLock::new()),
            direct_descendant_index: Arc::new(OnceLock::new()),
            project_types: Arc::new(OnceLock::new()),
            type_relations: Arc::new(OnceLock::new()),
        }
    }

    pub fn new_with_config_and_storage(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        storage: Arc<crate::analyzer::persistence::AnalyzerStorage>,
    ) -> Self {
        Self::new_with_config_storage(project, config, storage, None)
    }

    /// Owned handles to the workspace indexes (refcount bumps, not map
    /// clones), for per-query views held behind `Arc` caches.
    pub(crate) fn definition_lookup_index_shared(
        &self,
    ) -> Arc<crate::analyzer::DefinitionLookupIndex> {
        self.inner.definition_lookup_index_shared()
    }

    pub(crate) fn usage_facts_index_shared(&self) -> Arc<UsageFactsIndex> {
        self.inner.usage_facts_index_shared()
    }

    pub(crate) fn project_types(
        &self,
    ) -> Arc<crate::analyzer::usages::scala_graph::ScalaProjectTypes> {
        self.project_types
            .get_or_init(|| {
                Arc::new(crate::analyzer::usages::scala_graph::ScalaProjectTypes::build(self))
            })
            .clone()
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
        let inner = match progress {
            Some(progress) => TreeSitterAnalyzer::new_with_config_storage_and_progress(
                project,
                ScalaAdapter,
                config,
                storage,
                move |event| progress(event),
            ),
            None => TreeSitterAnalyzer::new_with_config_and_storage(
                project,
                ScalaAdapter,
                config,
                storage,
            ),
        };
        Self::from_inner(inner, memo_budget)
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }

    fn render_skeleton_recursive(
        &self,
        code_unit: &CodeUnit,
        indent: &str,
        header_only: bool,
        out: &mut String,
    ) {
        for signature in self.signatures_of(code_unit) {
            if signature.is_empty() {
                continue;
            }
            for line in signature.lines() {
                out.push_str(indent);
                out.push_str(line);
                out.push('\n');
            }
        }

        let all_children: Vec<_> = self.direct_children(code_unit).collect();
        let field_children: Vec<_> = all_children
            .iter()
            .copied()
            .filter(|child| child.is_field())
            .collect();
        let children = if header_only {
            field_children.clone()
        } else {
            all_children.clone()
        };

        if !children.is_empty() || code_unit.is_class() {
            let child_indent = format!("{indent}  ");
            for child in children {
                self.render_skeleton_recursive(child, &child_indent, header_only, out);
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

    fn usage_facts_index(&self) -> &UsageFactsIndex {
        self.inner.usage_facts_index()
    }

    fn direct_children<'a>(
        &'a self,
        code_unit: &CodeUnit,
    ) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a> {
        Box::new(
            self.inner
                .direct_children(code_unit)
                .filter(|child| !child.is_synthetic()),
        )
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

    fn get_declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        self.inner.get_declarations(file)
    }

    fn get_definitions(&self, fq_name: &str) -> Vec<CodeUnit> {
        self.inner.get_definitions(fq_name)
    }

    fn get_direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.inner
            .get_direct_children(code_unit)
            .into_iter()
            .filter(|child| !child.is_synthetic())
            .collect()
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
