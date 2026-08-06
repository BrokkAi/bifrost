mod adapter;
mod clones;
pub(crate) mod declarations;
mod diagnostics;
mod hierarchy;
pub(crate) mod imports;
pub(crate) mod language;
mod semantic;
pub(crate) mod structural;
mod supertypes;
mod tests;
pub(crate) mod wildcard_imports;
use crate::analyzer::Range;
use crate::analyzer::store::LimitedQueryRows;

use crate::analyzer::clone_detection::{
    CloneCandidateProfile, detect_structural_clone_smells, refine_clone_similarity_with_ast,
};
use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::jvm::dependency_discovery::is_jvm_dependency_input;
use crate::analyzer::jvm::external::JvmExternalDeclarationIndex;
use crate::analyzer::languages::{
    BoundedReceiverQuery, DeadCodeBulkEdges, DeadCodeBulkPreflight, DeadCodeBulkProof,
    DeadCodeRouting, DeadCodeSupport, EdgePassId, EdgeSiteScanCtx, EdgeWeightScanCtx,
    LanguageEdgePass, LanguageEdgeSites, LanguageEdgeWeights, LanguageSupport,
    StructuralReceiverResolver, TypeLookupQuery, TypeLookupResolver, analyzable_file_count,
    fqn_bulk_nodes, overloaded_function_fqns,
};
use crate::analyzer::tree_sitter_analyzer::FileState;
use crate::analyzer::type_relations::TypeRelation;
use crate::analyzer::usages::GraphUsageAnalyzer;
use crate::analyzer::usages::get_definition::{
    BoundedResolution, DefinitionLookupOutcome, resolve_scala_bounded,
};
use crate::analyzer::usages::get_type::{
    TypeLookupOutcome, resolve_scala_type, resolve_scala_type_bounded,
};
use crate::analyzer::usages::scala_graph::{
    ScalaDeadCodeBulkContext, ScalaDeadCodeBulkEligibility, ScalaUsageGraphStrategy,
    build_full_scala_usage_edges, build_scala_usage_edge_weights, build_scala_usage_edges,
    dead_code_bulk_eligibility,
};
use crate::analyzer::usages::workspace_graph::UsageEcosystem;
use crate::analyzer::weighted_cache::{
    build_weighted_cache, weight_code_unit_set, weight_code_unit_vec_by_unit,
    weight_project_file_set,
};
use crate::analyzer::{
    AnalyzerConfig, AnalyzerStoreContext, BuildProgress, BulkFileStateSource, CodeUnit,
    ForwardQueryProvider, IAnalyzer, ImportAnalysisProvider, JvmAnalyzerConfig, Language,
    PoolSafeMemo, Project, ProjectFile, SignatureMetadata, TestAssertionSmell,
    TestAssertionWeights, TestDetectionProvider, TreeSitterAnalyzer, TypeAliasProvider,
    TypeHierarchyProvider, UsageFactsIndex, resolve_analyzer,
};
use crate::hash::{HashMap, HashSet};
use crate::{CloneSmell, CloneSmellWeights};
use moka::sync::Cache;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

pub(crate) use adapter::ScalaAdapter;
use clones::build_scala_clone_candidate_data;
pub(crate) use declarations::scala_class_parameter_field_keyword;
pub(crate) use imports::{
    ScalaExportInfo, ScalaExportSelector, scala_lexical_scope_path_at,
    scala_lexical_scope_path_checked,
};
pub(crate) use supertypes::{
    ScalaSupertypeLookupPath, scala_supertype_lookup_nodes, scala_type_lookup_segments,
};
use tests::detect_scala_test_assertion_smells;
pub(crate) use wildcard_imports::{
    ScalaExplicitImportFacts, ScalaExplicitImportTier, ScalaWildcardImportEnvironment,
    ScalaWildcardOwnerFacts, resolve_scala_explicit_import_tier,
    resolve_scala_wildcard_import_environment, scala_enclosing_package_root_candidates,
    scala_import_path, scala_import_path_candidates, scala_import_visible_at,
    scala_package_prefixes_at, scala_package_prefixes_at_checked,
};

pub(crate) fn scala_normalize_full_name(fq_name: &str) -> String {
    fq_name.replace("$.", ".").trim_end_matches('$').to_string()
}

/// Object/class/trait declarations lexically enclosing a Scala byte
/// position, innermost first.
///
/// A relative Scala import path — and any wildcard-imported member reached
/// through it — resolves against these enclosing template scopes before the
/// package (mirroring ordinary qualified-identifier lookup). This walks the
/// same `ClassRangeIndex` byte-range lookup + `structural_parent_of` chain
/// that call/type-namespace resolution already uses for "which singleton
/// owns this site" (see `scala_exact_lexical_singleton_for_call` and
/// `scala_type_namespace_resolution` in `usages::get_definition::scala`).
///
/// Lives here rather than in `usages::get_definition::scala` (where it was
/// first written, for the import-token click fix) because
/// `scala::wildcard_imports`'s `resolve_scala_wildcard_import_environment`
/// needs the identical owner chain for the *usage* side of the same gap
/// (resolving a member reached through a wildcard import), and
/// `scala::imports`'s own `wildcard_import_environment` (workspace-wide
/// import/usage-graph edges) needs it too. `wildcard_imports` is
/// deliberately analyzer-free and closure-based for testability, so it does
/// not call this directly; its callers (here, and in `scala::imports`)
/// compute the owner chain and pass it in via a closure instead.
pub(crate) fn scala_enclosing_template_owner_fq_names(
    analyzer: &dyn IAnalyzer,
    scala: &ScalaAnalyzer,
    file: &ProjectFile,
    byte: usize,
) -> Vec<String> {
    let mut owners = Vec::new();
    let mut current =
        crate::analyzer::usages::inverted_edges::ClassRangeIndex::build(analyzer, file)
            .enclosing_unit(byte)
            .cloned();
    while let Some(owner) = current {
        current = scala.structural_parent_of(&owner);
        if owner.is_class() {
            owners.push(owner.fq_name());
        }
    }
    owners
}

/// Candidate spellings of `segments` rooted at `prefix`, plus the "$"
/// companion-object spelling Scala singletons use in fqns.
///
/// `prefix_is_owner` distinguishes an owner whose *own* spelling still needs
/// a trailing `$` inserted (an object/class fqn segment used as a qualifying
/// prefix) from a prefix that already carries its correct spelling (e.g. a
/// package name, or another candidate's fqn taken as-is).
pub(crate) fn scala_nested_type_candidates(
    prefix: String,
    segments: &[String],
    prefix_is_owner: bool,
) -> Vec<String> {
    let mut direct = prefix.clone();
    for segment in segments {
        if !direct.is_empty() {
            direct.push('.');
        }
        direct.push_str(segment);
    }
    if segments.is_empty() {
        return vec![direct];
    }

    let mut singleton_qualified = prefix;
    if prefix_is_owner {
        singleton_qualified.push('$');
    }
    for (index, segment) in segments.iter().enumerate() {
        if !singleton_qualified.is_empty() {
            singleton_qualified.push('.');
        }
        singleton_qualified.push_str(segment);
        if index + 1 < segments.len() {
            singleton_qualified.push('$');
        }
    }
    if singleton_qualified == direct {
        vec![direct]
    } else {
        vec![direct, singleton_qualified]
    }
}

pub(crate) fn scala_simple_type_name(unit: &CodeUnit) -> String {
    // Reuses the shared terminal-segment splitter (see its doc comment):
    // Scala identifiers never contain a literal `.`, so this reproduces
    // `short_name.rsplit('.').next()`'s terminal split exactly.
    crate::analyzer::usages::scala_graph::shared::scala_short_name_terminal_segment(
        unit.short_name(),
    )
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
    java_config: JvmAnalyzerConfig,
    external_index: Arc<OnceLock<JvmExternalDeclarationIndex>>,
    memo_budget: u64,
    imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    direct_ancestors: Cache<CodeUnit, Arc<Vec<CodeUnit>>>,
    reverse_import_index: Arc<PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    importable_declarations_by_package: Arc<OnceLock<HashMap<String, Arc<Vec<CodeUnit>>>>>,
    package_namespaces: Arc<OnceLock<Vec<String>>>,
    same_package_reference_index:
        Arc<PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    lazy_hierarchy_index: Arc<OnceLock<hierarchy::ScalaLazyHierarchyIndex>>,
    /// Analyzer-cached Scala usage/type-resolution support, built once per
    /// analyzer generation and reset on `update`/`update_all`.
    project_types: Arc<OnceLock<Arc<crate::analyzer::usages::scala_graph::ScalaProjectTypes>>>,
    full_usage_edges:
        Cache<Arc<[String]>, Arc<crate::analyzer::usages::inverted_edges::UsageEdges>>,
    project_types_build_count: Arc<AtomicUsize>,
    scala_query_parse_count: Arc<AtomicUsize>,
    scala_query_walk_count: Arc<AtomicUsize>,
    #[allow(dead_code)]
    type_relations: Arc<OnceLock<Vec<TypeRelation>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScalaTypeKnownness {
    Known,
    Absent,
    Uncertain,
}

crate::analyzer::impl_forward_query_provider!(ScalaAnalyzer);

impl ScalaAnalyzer {
    pub(crate) fn declaration_candidates_by_identifier_limited(
        &self,
        identifier: &str,
        limit: usize,
        continue_query: impl FnMut() -> bool,
    ) -> crate::analyzer::store::LimitedQueryRows<CodeUnit> {
        self.inner
            .lookup_declarations_by_identifier_limited(identifier, limit, continue_query)
    }

    pub(crate) fn declaration_candidates_by_fqn_limited(
        &self,
        fqn: &str,
        normalized: bool,
        limit: usize,
        continue_query: impl FnMut() -> bool,
    ) -> crate::analyzer::store::LimitedQueryRows<CodeUnit> {
        self.inner.lookup_declarations_by_persisted_fqn_limited(
            fqn,
            normalized,
            limit,
            continue_query,
        )
    }

    pub(crate) fn direct_children_limited(
        &self,
        owner: &CodeUnit,
        limit: usize,
    ) -> crate::analyzer::store::LimitedQueryRows<CodeUnit> {
        self.inner.direct_children_limited(owner, limit)
    }

    pub(crate) fn import_info_of_limited(
        &self,
        file: &ProjectFile,
        limit: usize,
    ) -> crate::analyzer::store::LimitedQueryRows<crate::analyzer::ImportInfo> {
        self.inner.import_info_of_limited(file, limit)
    }

    pub(crate) fn namespace_of_file_limited(
        &self,
        file: &ProjectFile,
        limit: usize,
    ) -> crate::analyzer::store::LimitedQueryRows<String> {
        self.inner.file_namespace_hint_limited(file, limit)
    }

    pub(crate) fn workspace_package_exists(&self, package: &str) -> bool {
        self.inner.persisted_package_exists(package)
    }

    pub(crate) fn workspace_fqn_prefix_exists(&self, prefix: &str) -> bool {
        self.inner.forward_fqn_prefix_exists(prefix)
    }

    pub(crate) fn signature_metadata_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> crate::analyzer::store::LimitedQueryRows<SignatureMetadata> {
        self.inner.signature_metadata_limited(code_unit, limit)
    }

    pub(crate) fn ranges_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> crate::analyzer::store::LimitedQueryRows<crate::analyzer::Range> {
        self.inner.ranges_limited(code_unit, limit)
    }

    pub(crate) fn supertype_lookup_paths_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> crate::analyzer::store::LimitedQueryRows<String> {
        self.inner.supertype_lookup_paths_limited(code_unit, limit)
    }

    pub(crate) fn raw_supertypes_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> crate::analyzer::store::LimitedQueryRows<String> {
        self.inner.raw_supertypes_limited(code_unit, limit)
    }

    pub fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        self.inner.is_type_alias(code_unit)
    }

    pub(crate) fn import_lexical_context_for_unit(
        &self,
        unit: &CodeUnit,
    ) -> Option<(
        Vec<String>,
        Vec<crate::analyzer::StructuredImportScope>,
        usize,
    )> {
        let reference_byte = self
            .ranges(unit)
            .into_iter()
            .map(|range| range.start_byte)
            .min()?;
        let prepared = self.inner.prepared_syntax(unit.source())?;
        let root = prepared.tree().root_node();
        Some((
            scala_package_prefixes_at(root, prepared.source(), reference_byte),
            scala_lexical_scope_path_at(root, reference_byte),
            reference_byte,
        ))
    }

    pub(crate) fn export_infos_for_owner(&self, owner: &CodeUnit) -> Vec<ScalaExportInfo> {
        self.inner
            .fetch_file_state(owner.source())
            .and_then(|state| state.scala_exports.get(owner).cloned())
            .unwrap_or_default()
    }

    pub(crate) fn structural_parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        self.inner.structural_parent_of(code_unit)
    }

    pub(crate) fn is_full_enum_case_declaration(&self, code_unit: &CodeUnit) -> bool {
        if !code_unit.is_class() {
            return false;
        }
        let Some(range) = self.ranges(code_unit).into_iter().next() else {
            return false;
        };
        let Some(prepared) = self.inner.prepared_syntax(code_unit.source()) else {
            return false;
        };
        prepared
            .tree()
            .root_node()
            .descendant_for_byte_range(range.start_byte, range.end_byte)
            .is_some_and(|node| node.kind() == "full_enum_case")
    }

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
        clone.external_index = Arc::new(OnceLock::new());
        clone.project_types = Arc::new(OnceLock::new());
        clone.full_usage_edges =
            build_weighted_cache(self.memo_budget / 8, weight_scala_usage_edges);
        clone.project_types_build_count = Arc::new(AtomicUsize::new(0));
        clone.scala_query_parse_count = Arc::new(AtomicUsize::new(0));
        clone.scala_query_walk_count = Arc::new(AtomicUsize::new(0));
        clone
    }

    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        let java_config = config.jvm.clone();
        let inner = TreeSitterAnalyzer::new_with_config(project, ScalaAdapter, config);
        Self::from_inner(inner, memo_budget, java_config)
    }

    fn from_inner(
        inner: TreeSitterAnalyzer<ScalaAdapter>,
        memo_budget: u64,
        java_config: JvmAnalyzerConfig,
    ) -> Self {
        Self {
            inner,
            java_config,
            external_index: Arc::new(OnceLock::new()),
            memo_budget,
            imported_code_units: build_weighted_cache(memo_budget / 4, weight_code_unit_set),
            referencing_files: build_weighted_cache(memo_budget / 8, weight_project_file_set),
            direct_ancestors: build_weighted_cache(memo_budget / 8, weight_code_unit_vec_by_unit),
            reverse_import_index: Arc::new(PoolSafeMemo::new()),
            importable_declarations_by_package: Arc::new(OnceLock::new()),
            package_namespaces: Arc::new(OnceLock::new()),
            same_package_reference_index: Arc::new(PoolSafeMemo::new()),
            lazy_hierarchy_index: Arc::new(OnceLock::new()),
            project_types: Arc::new(OnceLock::new()),
            full_usage_edges: build_weighted_cache(memo_budget / 8, weight_scala_usage_edges),
            project_types_build_count: Arc::new(AtomicUsize::new(0)),
            scala_query_parse_count: Arc::new(AtomicUsize::new(0)),
            scala_query_walk_count: Arc::new(AtomicUsize::new(0)),
            type_relations: Arc::new(OnceLock::new()),
        }
    }

    /// Owned handles to the workspace indexes (refcount bumps, not map
    /// clones), for per-query views held behind `Arc` caches.
    #[allow(dead_code)]
    pub(crate) fn global_usage_definition_index_shared(
        &self,
    ) -> Arc<crate::analyzer::GlobalUsageDefinitionIndex> {
        self.inner.global_usage_definition_index_shared()
    }

    #[allow(dead_code)]
    pub(crate) fn usage_facts_index_shared(&self) -> Arc<UsageFactsIndex> {
        self.inner.usage_facts_index_shared()
    }

    pub(crate) fn project_types(
        &self,
    ) -> Arc<crate::analyzer::usages::scala_graph::ScalaProjectTypes> {
        self.initialize_project_types(|| {
            self.bulk_file_states(self.analyzed_files(), BulkFileStateSource::Omit)
        })
    }

    pub(crate) fn external_declaration_index(&self) -> &JvmExternalDeclarationIndex {
        self.external_index.get_or_init(|| {
            JvmExternalDeclarationIndex::build_for_project(&self.java_config, self.inner.project())
        })
    }

    pub(crate) fn simple_type_knownness(
        &self,
        file: &ProjectFile,
        name: &str,
    ) -> ScalaTypeKnownness {
        if name.is_empty() || scala_default_type_name(name) {
            return ScalaTypeKnownness::Known;
        }

        let package_name = self.inner.package_name_of(file).unwrap_or_default();
        if self.inner.all_declarations().any(|declaration| {
            declaration.is_class()
                && declaration.short_name().trim_end_matches('$') == name
                && (declaration.source() == file || declaration.package_name() == package_name)
        }) {
            return ScalaTypeKnownness::Known;
        }

        let imports = self.inner.import_info_of(file);
        let imported = self.imported_code_units_of(file);
        let external = self.external_declaration_index();
        if external.resolve_java_lang(name).is_some() {
            return ScalaTypeKnownness::Known;
        }
        for import in &imports {
            let Some(path) = scala_import_path(import) else {
                return ScalaTypeKnownness::Uncertain;
            };
            if import.is_wildcard {
                if imported.iter().any(|declaration| {
                    declaration.is_class() && declaration.short_name().trim_end_matches('$') == name
                }) || external
                    .resolve_wildcard_import(&path, name, &package_name)
                    .is_some()
                {
                    return ScalaTypeKnownness::Known;
                }
                return ScalaTypeKnownness::Uncertain;
            }

            if import.local_name() != Some(name) {
                continue;
            }
            if imported.iter().any(|declaration| {
                declaration.is_class() && declaration.short_name().trim_end_matches('$') == name
            }) || external
                .resolve_explicit_import(&path, &package_name)
                .is_some()
            {
                return ScalaTypeKnownness::Known;
            }
            return ScalaTypeKnownness::Uncertain;
        }

        if external.resolve_same_package(&package_name, name).is_some() {
            ScalaTypeKnownness::Known
        } else {
            ScalaTypeKnownness::Absent
        }
    }

    pub(crate) fn is_known_simple_term(&self, file: &ProjectFile, name: &str) -> bool {
        let package_name = self.inner.package_name_of(file).unwrap_or_default();
        self.inner.all_declarations().any(|declaration| {
            declaration.is_class()
                && declaration.short_name().trim_end_matches('$') == name
                && (declaration.source() == file || declaration.package_name() == package_name)
        }) || self
            .external_declaration_index()
            .resolve_same_package(&package_name, name)
            .is_some()
    }

    pub(crate) fn full_usage_edges(
        &self,
        nodes: &HashSet<String>,
        build: impl FnOnce() -> crate::analyzer::usages::inverted_edges::UsageEdges,
    ) -> Arc<crate::analyzer::usages::inverted_edges::UsageEdges> {
        let mut sorted_nodes = nodes.iter().cloned().collect::<Vec<_>>();
        sorted_nodes.sort_unstable();
        let key: Arc<[String]> = sorted_nodes.into();
        self.full_usage_edges.get_with(key, || Arc::new(build()))
    }

    pub(crate) fn record_query_parse(&self) {
        self.scala_query_parse_count.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_query_walk(&self) {
        self.scala_query_walk_count.fetch_add(1, Ordering::Relaxed);
    }

    fn project_types_from_file_states(
        &self,
        file_states: HashMap<ProjectFile, FileState>,
    ) -> Arc<crate::analyzer::usages::scala_graph::ScalaProjectTypes> {
        self.initialize_project_types(|| file_states)
    }

    fn initialize_project_types<F>(
        &self,
        file_states: F,
    ) -> Arc<crate::analyzer::usages::scala_graph::ScalaProjectTypes>
    where
        F: FnOnce() -> HashMap<ProjectFile, FileState>,
    {
        self.project_types
            .get_or_init(|| {
                self.project_types_build_count
                    .fetch_add(1, Ordering::Relaxed);
                Arc::new(
                    crate::analyzer::usages::scala_graph::ScalaProjectTypes::build_from_file_states(
                        file_states(),
                    ),
                )
            })
            .clone()
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
            ScalaAdapter,
            config,
            store_context,
            progress,
        )?;
        Ok(Self::from_inner(inner, memo_budget, java_config))
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
}

fn scala_default_type_name(name: &str) -> bool {
    if scala_standard_arity_type_name(name) {
        return true;
    }
    matches!(
        name,
        "Any"
            | "AnyRef"
            | "AnyVal"
            | "Nothing"
            | "Null"
            | "Unit"
            | "Boolean"
            | "Byte"
            | "Short"
            | "Int"
            | "Long"
            | "Float"
            | "Double"
            | "Char"
            | "String"
            | "Array"
            | "Option"
            | "Some"
            | "None"
            | "Either"
            | "Left"
            | "Right"
            | "List"
            | "Nil"
            | "Seq"
            | "Set"
            | "Map"
            | "Iterable"
            | "Iterator"
            | "Product"
            | "PartialFunction"
            | "Matchable"
            | "Dynamic"
            | "Singleton"
            | "AnyKind"
            | "CanEqual"
            | "ValueOf"
            | "DummyImplicit"
            | "RuntimeException"
            | "Exception"
            | "Throwable"
            | "Error"
            | "Object"
            | "Class"
            | "Number"
            | "Math"
            | "System"
            | "StringBuilder"
    )
}

fn scala_standard_arity_type_name(name: &str) -> bool {
    for prefix in ["Tuple", "Function", "ContextFunction"] {
        if let Some(arity) = name
            .strip_prefix(prefix)
            .and_then(|value| value.parse::<u8>().ok())
            && arity <= 22
        {
            return true;
        }
    }
    false
}

fn weight_scala_usage_edges(
    key: &Arc<[String]>,
    edges: &Arc<crate::analyzer::usages::inverted_edges::UsageEdges>,
) -> u32 {
    use std::mem::size_of;

    let key_bytes = size_of::<Arc<[String]>>()
        + key
            .iter()
            .map(|item| size_of::<String>() + item.len())
            .sum::<usize>();
    let edge_bytes = edges
        .edges
        .iter()
        .map(|((caller, callee), sites)| {
            caller.len()
                + callee.len()
                + sites
                    .iter()
                    .map(|site| {
                        size_of::<crate::analyzer::usages::inverted_edges::CallSite>()
                            + site.path.len()
                    })
                    .sum::<usize>()
        })
        .sum::<usize>();
    let summary_bytes = edges
        .truncated
        .keys()
        .chain(edges.unproven_inbound.keys())
        .map(|name| size_of::<String>() + name.len() + size_of::<usize>())
        .sum::<usize>();
    (key_bytes + edge_bytes + summary_bytes).clamp(1, u32::MAX as usize) as u32
}

impl TestDetectionProvider for ScalaAnalyzer {}

impl TypeAliasProvider for ScalaAnalyzer {
    fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        self.inner.is_type_alias(code_unit)
    }
}

use crate::analyzer::CodeUnitIndex;

impl CodeUnitIndex for ScalaAnalyzer {
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

    fn location_declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        self.inner.location_declarations(file)
    }

    fn location_ranges(&self, code_unit: &CodeUnit) -> Vec<crate::analyzer::Range> {
        self.inner.location_ranges(code_unit)
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

    fn direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.inner
            .direct_children(code_unit)
            .into_iter()
            .filter(|child| !child.is_synthetic())
            .collect()
    }

    fn parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        self.structural_parent_of(code_unit)
            .or_else(|| CodeUnitIndex::parent_of(&self.inner, code_unit))
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

    fn project(&self) -> &dyn Project {
        self.inner.project()
    }

    fn get_all_declarations(&self) -> Vec<CodeUnit> {
        self.inner.get_all_declarations()
    }

    fn get_definitions(&self, fq_name: &str) -> Vec<CodeUnit> {
        self.inner.get_definitions(fq_name)
    }

    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        let rendered = crate::analyzer::common::render_skeleton(self, code_unit, false);
        (!rendered.is_empty()).then(|| rendered.trim_end().to_string())
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        let rendered = crate::analyzer::common::render_skeleton(self, code_unit, true);
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
}

impl IAnalyzer for ScalaAnalyzer {
    #[cfg(any(test, feature = "test-support"))]
    fn test_hooks(&self) -> &dyn crate::analyzer::AnalyzerTestHooks {
        self
    }

    fn invalidate_cached_file_identities(&self) {
        self.inner.invalidate_cached_file_identities();
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

    fn usage_facts_index(&self) -> &UsageFactsIndex {
        self.inner.usage_facts_index()
    }

    fn structural_search_providers(
        &self,
    ) -> Vec<&dyn crate::analyzer::structural::StructuralSearchProvider> {
        self.inner.structural_search_providers()
    }

    fn snapshot_caches(&self) -> Option<&crate::analyzer::AnalyzerSnapshotCaches> {
        Some(self.inner.snapshot_caches())
    }

    fn import_statements(&self, file: &ProjectFile) -> Vec<String> {
        self.inner.import_statements(file)
    }

    fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)> {
        self.inner.compute_cognitive_complexities(file)
    }

    fn semantic_diagnostics(
        &self,
        file: &ProjectFile,
        source: &str,
    ) -> crate::analyzer::SemanticDiagnosticReport {
        let diagnostics = diagnostics::collect_scala_semantic_diagnostics(self, file, source)
            .into_iter()
            .map(Into::into)
            .collect();
        crate::analyzer::SemanticDiagnosticReport::from_workspace_absences(file, diagnostics)
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        let external_index = if changed_files.iter().any(is_jvm_dependency_input) {
            Arc::new(OnceLock::new())
        } else {
            self.external_index.clone()
        };
        let mut updated = Self::from_inner(
            self.inner.update(changed_files),
            self.memo_budget,
            self.java_config.clone(),
        );
        updated.external_index = external_index;
        updated
    }

    fn update_all(&self) -> Self {
        Self::from_inner(
            self.inner.update_all(),
            self.memo_budget,
            self.java_config.clone(),
        )
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

    fn parse_errors(&self, file: &ProjectFile) -> Option<Vec<crate::analyzer::ParseError>> {
        self.inner.parse_errors(file)
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
            refine_clone_similarity_with_ast,
        )
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        Some(self)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl crate::analyzer::AnalyzerTestHooks for ScalaAnalyzer {
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

    fn reset_scala_project_types_build_count_for_test(&self) {
        self.project_types_build_count.store(0, Ordering::Relaxed);
    }

    fn scala_project_types_build_count_for_test(&self) -> usize {
        self.project_types_build_count.load(Ordering::Relaxed)
    }

    fn reset_scala_query_scan_counts_for_test(&self) {
        self.scala_query_parse_count.store(0, Ordering::Relaxed);
        self.scala_query_walk_count.store(0, Ordering::Relaxed);
    }

    fn scala_query_parse_count_for_test(&self) -> usize {
        self.scala_query_parse_count.load(Ordering::Relaxed)
    }

    fn scala_query_walk_count_for_test(&self) -> usize {
        self.scala_query_walk_count.load(Ordering::Relaxed)
    }
}

static SCALA_USAGE_STRATEGY: ScalaUsageGraphStrategy = ScalaUsageGraphStrategy::new();

pub(crate) struct ScalaSupport;

impl LanguageSupport for ScalaSupport {
    fn language(&self) -> Language {
        Language::Scala
    }

    /// The trailing `$` marks a companion object in the indexed name and is not part of
    /// how anyone writes or reads the type.
    fn display_symbol_name(&self, symbol: &str) -> String {
        symbol
            .split('.')
            .map(|segment| segment.trim_end_matches('$'))
            .collect::<Vec<_>>()
            .join(".")
    }

    fn signature_metadata_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<SignatureMetadata>> {
        resolve_analyzer::<ScalaAnalyzer>(analyzer)
            .map(|scala| scala.signature_metadata_limited(unit, limit))
    }

    fn declaration_ranges_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<Range>> {
        resolve_analyzer::<ScalaAnalyzer>(analyzer).map(|scala| scala.ranges_limited(unit, limit))
    }

    fn forward_query_provider<'a>(
        &self,
        analyzer: &'a dyn IAnalyzer,
    ) -> Option<&'a dyn ForwardQueryProvider> {
        resolve_analyzer::<ScalaAnalyzer>(analyzer).map(|value| value as _)
    }

    fn ecosystem(&self) -> UsageEcosystem {
        UsageEcosystem::Jvm
    }

    fn usage_strategy(&self) -> &'static dyn GraphUsageAnalyzer {
        &SCALA_USAGE_STRATEGY
    }

    fn edge_pass(&self) -> Option<&'static dyn LanguageEdgePass> {
        Some(&ScalaEdgePass)
    }

    fn dead_code(&self) -> DeadCodeSupport {
        DeadCodeSupport {
            strategy: Some(&SCALA_USAGE_STRATEGY),
            bulk: Some(&ScalaDeadCodeBulk),
        }
    }

    fn structural_receiver(&self) -> Option<&'static dyn StructuralReceiverResolver> {
        Some(&ScalaSupport)
    }

    fn type_lookup(&self) -> Option<&'static dyn TypeLookupResolver> {
        Some(&ScalaSupport)
    }

    fn parser_language(&self, _flavor: crate::analyzer::ParserFlavor) -> tree_sitter::Language {
        language::LANGUAGE.into()
    }

    fn structural_spec(&self) -> &'static dyn crate::analyzer::structural::StructuralSpec {
        &structural::SCALA_STRUCTURAL_SPEC
    }

    fn highlight_query(&self) -> Option<&'static str> {
        Some(include_str!(
            "../../../vendor/tree-sitter-scala/queries/highlights.scm"
        ))
    }
}

/// One of three distinct JVM passes. Java, Scala and Kotlin resolve over the same
/// candidate space but scan only files of their own language, so the three passes cover
/// disjoint call sites and merge without double counting.
struct ScalaEdgePass;

impl LanguageEdgePass for ScalaEdgePass {
    fn id(&self) -> EdgePassId {
        EdgePassId::Scala
    }

    fn edge_sites(&self, ctx: &EdgeSiteScanCtx<'_>) -> Option<LanguageEdgeSites> {
        build_scala_usage_edges(ctx.analyzer, ctx.fqns, ctx.keep_file).map(LanguageEdgeSites)
    }

    fn edge_weights(&self, ctx: &EdgeWeightScanCtx<'_>) -> Option<LanguageEdgeWeights> {
        build_scala_usage_edge_weights(ctx.analyzer, ctx.fqns, ctx.keep_file)
            .map(LanguageEdgeWeights::Fqn)
    }
}

impl StructuralReceiverResolver for ScalaSupport {
    fn resolve_type_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<TypeLookupOutcome> {
        resolve_scala_type_bounded(
            query.analyzer,
            query.file,
            query.source,
            query.tree,
            query.site,
            query.budget,
            query.cancellation,
        )
    }

    fn resolve_definition_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<DefinitionLookupOutcome> {
        resolve_scala_bounded(
            query.analyzer,
            query.file,
            query.source,
            query.tree,
            query.site,
            query.budget,
            query.cancellation,
        )
    }
}

impl TypeLookupResolver for ScalaSupport {
    fn resolve_type(&self, query: TypeLookupQuery<'_>) -> TypeLookupOutcome {
        query.support.set_language(query.language);
        resolve_scala_type(
            query.analyzer,
            query.support,
            query.file,
            query.source,
            query.tree,
            query.site,
        )
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

#[derive(Default)]
struct ScalaDeadCodeMemo {
    file_count: Option<usize>,
    overloaded_fqns: Option<HashSet<String>>,
    bulk_context: Option<Option<ScalaDeadCodeBulkContext>>,
}

struct ScalaDeadCodeBulk;

impl DeadCodeBulkProof for ScalaDeadCodeBulk {
    fn id(&self) -> EdgePassId {
        EdgePassId::Scala
    }

    fn new_memo(&self) -> Box<dyn std::any::Any + Send> {
        Box::new(ScalaDeadCodeMemo::default())
    }

    /// Inverted cap polarity, deliberately: past the file cap a Scala candidate goes
    /// *into* the bulk bucket, where the shared cap check reports it once for the whole
    /// bucket, rather than falling through to a per-symbol scan that would pay the cost
    /// the cap exists to avoid.
    fn needs_precise_scan(&self, routing: DeadCodeRouting<'_>) -> bool {
        let DeadCodeRouting {
            analyzer,
            candidate,
            file_cap,
            memo,
        } = routing;
        let ScalaDeadCodeMemo {
            file_count,
            overloaded_fqns,
            bulk_context,
        } = memo.downcast_mut().expect("Scala bulk memo");
        if *file_count.get_or_insert_with(|| analyzable_file_count(analyzer, Language::Scala))
            > file_cap
        {
            return false;
        }

        let empty_overloads = HashSet::default();
        let overloads = if candidate.is_function() {
            overloaded_fqns
                .get_or_insert_with(|| overloaded_function_fqns(analyzer, Language::Scala))
        } else {
            &empty_overloads
        };
        let Some(context) = bulk_context
            .get_or_insert_with(|| ScalaDeadCodeBulkContext::from_analyzer(analyzer))
            .as_ref()
        else {
            return true;
        };

        matches!(
            dead_code_bulk_eligibility(analyzer, candidate, overloads, context),
            ScalaDeadCodeBulkEligibility::NeedsPrecise
        )
    }

    fn preflight(&self, analyzer: &dyn IAnalyzer) -> DeadCodeBulkPreflight {
        DeadCodeBulkPreflight::Ready {
            label: "Scala",
            files: analyzable_file_count(analyzer, Language::Scala),
        }
    }

    /// The full builder, not the workspace one every sibling uses: it has no `keep_file`
    /// predicate, and its result is the analyzer-cached whole-project edge set.
    fn build(
        &self,
        analyzer: &dyn IAnalyzer,
        candidates: &[CodeUnit],
    ) -> Option<DeadCodeBulkEdges> {
        let nodes = fqn_bulk_nodes(
            analyzer,
            Language::Scala,
            |unit| unit.is_function() || unit.is_class(),
            candidates,
        );
        build_full_scala_usage_edges(analyzer, &nodes).map(DeadCodeBulkEdges::Fqn)
    }
}
