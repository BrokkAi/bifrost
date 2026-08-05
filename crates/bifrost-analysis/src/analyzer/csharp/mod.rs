//! The analyzer-owned shim over [`brokk_bifrost_csharp`].
//!
//! What lives here is everything the language crate cannot name: the
//! [`CSharpAnalyzer`] newtype and its six moka caches, six `OnceLock`s and two
//! `PoolSafeMemo`s; the accessors that implement
//! [`graph_support::CSharpAnalysisSource`] out of them; the `CSharpAdapter`
//! forwarding shell; the `IAnalyzer`/`CodeUnitIndex` impls; and the
//! `LanguageSupport` SPI block.

mod adapter;
mod cache;
mod clones;
mod dependency_discovery;
pub mod external;
mod hierarchy_provider;
mod imports;
mod semantic;
mod structural;
use crate::analyzer::Range;

// The language halves of the type-resolution and hierarchy logic moved to
// `brokk-bifrost-csharp`; re-exporting the modules keeps every
// `crate::analyzer::csharp::{graph_support,hierarchy}::` call site in the
// definition route, the type route and the usage graph pointing at the same
// paths.
pub(crate) use brokk_bifrost_csharp::{graph_support, hierarchy};

// C# language knowledge lives in `brokk-bifrost-csharp`; these keep their
// historical `crate::analyzer::csharp::` paths for the analysis-side consumers
// (the re-export hub in `analyzer/mod.rs`, the definition and type routes, the
// usage graph, and this crate's own C# modules).
pub(crate) use brokk_bifrost_csharp::syntax::{
    CSharpMemberName, csharp_attribute_name_node, csharp_attribute_terminal_name,
    csharp_attribute_type_names, csharp_callable_arity, csharp_conditional_member_access,
    csharp_constant_pattern_type_candidate, csharp_member_access_type_receiver, csharp_member_name,
    csharp_method_generic_arity, csharp_nameof_type_candidates, csharp_normalize_full_name,
    csharp_signature_arity, csharp_signature_return_type, csharp_source_identifier,
    csharp_type_leftmost_identifier, csharp_type_node_identity, csharp_type_reference_root,
    csharp_type_terminal_identifier, csharp_unqualified_invocation_for_name,
    csharp_using_directive_is_global, csharp_using_directive_is_static,
    csharp_using_directive_namespace, csharp_using_directive_target,
};
pub use brokk_bifrost_csharp::syntax::{csharp_source_name_segment, strip_csharp_generic_arity};

use crate::analyzer::clone_detection::{
    CloneCandidateProfile, detect_structural_clone_smells, refine_clone_similarity_with_ast,
};
use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::languages::{
    BoundedReceiverQuery, DeadCodeBulkEdges, DeadCodeBulkPreflight, DeadCodeBulkProof,
    DeadCodeRouting, DeadCodeSupport, EdgePassId, EdgeSiteScanCtx, EdgeWeightScanCtx,
    LanguageEdgePass, LanguageEdgeSites, LanguageEdgeWeights, LanguageSupport,
    StructuralReceiverResolver, TypeLookupQuery, TypeLookupResolver, analyzable_file_count,
    fqn_bulk_nodes, overloaded_function_fqns,
};
use crate::analyzer::store::LimitedQueryRows;
use crate::analyzer::usages::GraphUsageAnalyzer;
use crate::analyzer::usages::csharp_graph::{
    CSharpUsageGraphStrategy, build_csharp_usage_edge_weights, build_csharp_usage_edges,
};
use crate::analyzer::usages::get_definition::{
    BoundedResolution, DefinitionLookupOutcome, resolve_csharp_bounded,
};
use crate::analyzer::usages::get_type::{
    TypeLookupOutcome, resolve_csharp_type, resolve_csharp_type_bounded,
};
use crate::analyzer::usages::workspace_graph::UsageEcosystem;
use crate::analyzer::{
    AnalyzerConfig, AnalyzerStoreContext, BoundedDefinitionLookup, BuildProgress,
    CSharpAnalyzerConfig, CodeUnit, ForwardQueryProvider, IAnalyzer, ImportAnalysisProvider,
    Language, Project, ProjectFile, SignatureMetadata, TestAssertionSmell, TestAssertionWeights,
    TestDetectionProvider, TreeSitterAnalyzer, TypeHierarchyProvider, UsageFactsIndex,
    resolve_analyzer,
};
use crate::hash::{HashMap, HashSet};
use crate::{CloneSmell, CloneSmellWeights};
use std::collections::BTreeSet;
use std::sync::Arc;

use adapter::CSharpAdapter;
use brokk_bifrost_csharp::dead_code::{
    csharp_constructor_candidate, csharp_unsafe_using_member_forms_present,
};
use brokk_bifrost_csharp::test_detection::detect_csharp_test_assertion_smells;
use cache::CSharpMemoCaches;
use clones::build_csharp_clone_candidate_data;
use external::{CSharpExternalDeclarationIndex, CSharpExternalMember, CSharpExternalType};
use graph_support::CSharpAnalysisSource;

fn limited_known_values<T>(
    len: usize,
    values: impl IntoIterator<Item = T>,
    limit: usize,
) -> LimitedQueryRows<T> {
    if limit == 0 {
        return LimitedQueryRows::incomplete(Vec::new(), 0);
    }
    let inspected = len.min(limit);
    let rows = values.into_iter().take(limit).collect();
    if len > limit {
        LimitedQueryRows::incomplete(rows, inspected)
    } else {
        LimitedQueryRows::complete(rows, inspected)
    }
}

pub(crate) use dependency_discovery::is_csharp_dependency_input;

#[derive(Clone)]
pub struct CSharpAnalyzer {
    inner: TreeSitterAnalyzer<CSharpAdapter>,
    memo_caches: Arc<CSharpMemoCaches>,
    csharp_config: CSharpAnalyzerConfig,
    external_index: Arc<std::sync::OnceLock<CSharpExternalDeclarationIndex>>,
}

crate::analyzer::impl_forward_query_provider!(CSharpAnalyzer);

impl CSharpAnalyzer {
    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        let mut clone = self.clone();
        clone.inner = clone.inner.clone_with_project(project);
        clone.external_index = Arc::new(std::sync::OnceLock::new());
        clone
    }

    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        let csharp_config = config.csharp.clone();
        Self {
            inner: TreeSitterAnalyzer::new_with_config(project, CSharpAdapter, config),
            memo_caches: Arc::new(CSharpMemoCaches::new(memo_budget)),
            csharp_config,
            external_index: Arc::new(std::sync::OnceLock::new()),
        }
    }

    pub(crate) fn new_with_config_store_context(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        store_context: AnalyzerStoreContext,
        progress: Option<BuildProgress>,
    ) -> Result<Self, crate::analyzer::store::StoreError> {
        let memo_budget = config.memo_cache_budget_bytes();
        let csharp_config = config.csharp.clone();
        let inner = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            project,
            CSharpAdapter,
            config,
            store_context,
            progress,
        )?;
        Ok(Self {
            inner,
            memo_caches: Arc::new(CSharpMemoCaches::new(memo_budget)),
            csharp_config,
            external_index: Arc::new(std::sync::OnceLock::new()),
        })
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }

    #[doc(hidden)]
    pub fn reset_full_hydration_count_for_test(&self) {
        self.inner.reset_full_hydration_count_for_test();
    }

    #[doc(hidden)]
    pub fn full_hydration_count_for_test(&self) -> usize {
        self.inner.full_hydration_count_for_test()
    }

    pub(crate) fn declaration_candidates_by_identifier(
        &self,
        identifier: &str,
    ) -> BTreeSet<CodeUnit> {
        self.inner.lookup_declarations_by_identifier(identifier)
    }

    pub(crate) fn declaration_candidates_by_identifier_limited(
        &self,
        identifier: &str,
        limit: usize,
        continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit> {
        self.inner
            .lookup_declarations_by_identifier_limited(identifier, limit, continue_query)
    }

    pub(crate) fn member_candidates_for_owner(
        &self,
        owner_fqn: &str,
        name: &str,
    ) -> BTreeSet<CodeUnit> {
        self.inner.lookup_members_for_owner_name(owner_fqn, name)
    }

    pub(crate) fn member_candidates_for_owner_limited(
        &self,
        owner_fqn: &str,
        name: &str,
        limit: usize,
        continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit> {
        self.inner
            .lookup_members_for_owner_name_limited(owner_fqn, name, limit, continue_query)
    }

    pub(crate) fn workspace_namespace_exists(&self, namespace: &str) -> bool {
        self.inner.persisted_package_exists(namespace)
    }

    pub fn namespace_of_file(&self, file: &ProjectFile) -> String {
        if let Some(cached) = self.memo_caches.namespace_by_file.get(file) {
            return (*cached).clone();
        }
        let namespace = graph_support::compute_namespace_of_file(self, file);
        self.memo_caches
            .namespace_by_file
            .insert(file.clone(), Arc::new(namespace.clone()));
        namespace
    }

    pub(crate) fn namespace_of_file_limited(
        &self,
        file: &ProjectFile,
        limit: usize,
    ) -> LimitedQueryRows<String> {
        if let Some(cached) = self.memo_caches.namespace_by_file.get(file) {
            return limited_known_values(1, std::iter::once((*cached).clone()), limit);
        }
        let batch = graph_support::compute_namespace_of_file_limited(self, file, limit);
        if batch.complete {
            let namespace = batch.rows.first().cloned().unwrap_or_default();
            self.memo_caches
                .namespace_by_file
                .insert(file.clone(), Arc::new(namespace));
        }
        batch
    }

    pub fn external_declaration_index(&self) -> &CSharpExternalDeclarationIndex {
        self.external_index.get_or_init(|| {
            CSharpExternalDeclarationIndex::build_for_project(
                &self.csharp_config,
                self.inner.project(),
            )
        })
    }

    pub fn external_type_candidates(
        &self,
        file: &ProjectFile,
        reference: &str,
    ) -> Vec<&CSharpExternalType> {
        self.external_declaration_index().resolve_in_file(
            reference,
            &self.namespace_of_file(file),
            &self.using_namespaces_of(file),
            &self.using_aliases_of(file),
        )
    }

    pub fn external_member_candidates(
        &self,
        owner: &str,
        name: &str,
    ) -> Vec<&CSharpExternalMember> {
        self.external_declaration_index().members_named(owner, name)
    }

    pub fn using_namespaces_of(&self, file: &ProjectFile) -> Vec<String> {
        if let Some(cached) = self.memo_caches.using_namespaces.get(file) {
            return (*cached).clone();
        }
        let namespaces = graph_support::compute_using_namespaces_of(self, file);
        self.memo_caches
            .using_namespaces
            .insert(file.clone(), Arc::new(namespaces.clone()));
        namespaces
    }

    pub(crate) fn using_namespaces_of_limited(
        &self,
        file: &ProjectFile,
        limit: usize,
        mut continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<String> {
        if let Some(cached) = self.memo_caches.using_namespaces.get(file) {
            return limited_known_values(cached.len(), cached.iter().cloned(), limit);
        }
        let batch = graph_support::compute_using_namespaces_of_limited(
            self,
            file,
            limit,
            &mut continue_query,
        );
        if batch.complete {
            self.memo_caches
                .using_namespaces
                .insert(file.clone(), Arc::new(batch.rows.clone()));
        }
        batch
    }

    pub fn using_aliases_of(&self, file: &ProjectFile) -> HashMap<String, String> {
        if let Some(cached) = self.memo_caches.using_aliases.get(file) {
            return (*cached).clone();
        }
        let aliases = graph_support::compute_using_aliases_of(self, file);
        self.memo_caches
            .using_aliases
            .insert(file.clone(), Arc::new(aliases.clone()));
        aliases
    }

    pub(crate) fn using_aliases_of_limited(
        &self,
        file: &ProjectFile,
        limit: usize,
        mut continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<(String, String)> {
        if let Some(cached) = self.memo_caches.using_aliases.get(file) {
            return limited_known_values(
                cached.len(),
                cached
                    .iter()
                    .map(|(alias, target)| (alias.clone(), target.clone())),
                limit,
            );
        }
        let batch =
            graph_support::compute_using_aliases_of_limited(self, file, limit, &mut continue_query);
        if batch.complete {
            self.memo_caches.using_aliases.insert(
                file.clone(),
                Arc::new(batch.rows.iter().cloned().collect::<HashMap<_, _>>()),
            );
        }
        batch
    }

    pub(crate) fn global_using_namespaces(&self) -> &HashSet<String> {
        self.memo_caches
            .global_using_namespaces
            .get_or_init(|| graph_support::compute_global_using_namespaces(self))
    }

    pub(crate) fn global_using_namespaces_limited(
        &self,
        limit: usize,
        mut continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<String> {
        if let Some(cached) = self.memo_caches.global_using_namespaces.get() {
            return limited_known_values(cached.len(), cached.iter().cloned(), limit);
        }
        let batch = graph_support::compute_global_using_namespaces_limited(
            self,
            limit,
            &mut continue_query,
        );
        if batch.complete {
            let _ = self
                .memo_caches
                .global_using_namespaces
                .set(batch.rows.iter().cloned().collect());
        }
        batch
    }

    fn global_using_aliases(&self) -> &HashMap<String, String> {
        self.memo_caches
            .global_using_aliases
            .get_or_init(|| graph_support::compute_global_using_aliases(self))
    }

    pub(crate) fn global_using_aliases_limited(
        &self,
        limit: usize,
        mut continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<(String, String)> {
        if let Some(cached) = self.memo_caches.global_using_aliases.get() {
            return limited_known_values(
                cached.len(),
                cached
                    .iter()
                    .map(|(alias, target)| (alias.clone(), target.clone())),
                limit,
            );
        }
        let batch =
            graph_support::compute_global_using_aliases_limited(self, limit, &mut continue_query);
        if batch.complete {
            let _ = self
                .memo_caches
                .global_using_aliases
                .set(batch.rows.iter().cloned().collect());
        }
        batch
    }

    pub(crate) fn global_static_using_type_names_limited(
        &self,
        limit: usize,
        mut continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<String> {
        if let Some(cached) = self.memo_caches.global_static_using_type_names.get() {
            return limited_known_values(cached.len(), cached.iter().cloned(), limit);
        }
        let batch = graph_support::compute_global_static_using_type_names_limited(
            self,
            limit,
            &mut continue_query,
        );
        if batch.complete {
            let _ = self
                .memo_caches
                .global_static_using_type_names
                .set(batch.rows.clone());
        }
        batch
    }

    pub(crate) fn global_static_using_types(&self) -> &[CodeUnit] {
        self.memo_caches
            .global_static_using_types
            .get_or_init(|| graph_support::compute_global_static_using_types(self))
    }

    pub(crate) fn usage_global_static_using_types(&self) -> &[CodeUnit] {
        self.memo_caches
            .usage_global_static_using_types
            .get_or_init(|| graph_support::compute_usage_global_static_using_types(self))
    }
}

impl CSharpAnalysisSource for CSharpAnalyzer {
    fn persisted_declaration_candidates_by_fqn(
        &self,
        fqn: &str,
        normalized: bool,
    ) -> BTreeSet<CodeUnit> {
        self.inner
            .lookup_declarations_by_persisted_fqn(fqn, normalized)
    }

    fn persisted_declaration_candidates_by_fqn_limited(
        &self,
        fqn: &str,
        normalized: bool,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit> {
        self.inner.lookup_declarations_by_persisted_fqn_limited(
            fqn,
            normalized,
            limit,
            continue_query,
        )
    }

    fn forward_definition_fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        self.inner.forward_definition_fqn(fqn)
    }

    fn usage_definitions(&self) -> &dyn BoundedDefinitionLookup {
        self.inner.global_usage_definition_index_ref()
    }

    fn all_files(&self) -> Vec<ProjectFile> {
        self.inner.all_files()
    }

    fn package_name_of(&self, file: &ProjectFile) -> Option<String> {
        self.inner.package_name_of(file)
    }

    fn file_namespace_hint_limited(
        &self,
        file: &ProjectFile,
        limit: usize,
    ) -> LimitedQueryRows<String> {
        self.inner.file_namespace_hint_limited(file, limit)
    }

    fn import_info_of_limited(
        &self,
        file: &ProjectFile,
        limit: usize,
    ) -> LimitedQueryRows<crate::analyzer::ImportInfo> {
        self.inner.import_info_of_limited(file, limit)
    }

    fn workspace_import_info_limited(
        &self,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<crate::analyzer::ImportInfo> {
        self.inner
            .workspace_import_info_limited(limit, continue_query)
    }

    fn raw_supertypes_of(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.inner.raw_supertypes_of(code_unit)
    }

    fn type_identifiers_of(&self, file: &ProjectFile) -> Option<HashSet<String>> {
        self.inner.type_identifiers_of(file)
    }

    fn namespace_of_file(&self, file: &ProjectFile) -> String {
        CSharpAnalyzer::namespace_of_file(self, file)
    }

    fn using_namespaces_of(&self, file: &ProjectFile) -> Vec<String> {
        CSharpAnalyzer::using_namespaces_of(self, file)
    }

    fn using_aliases_of(&self, file: &ProjectFile) -> HashMap<String, String> {
        CSharpAnalyzer::using_aliases_of(self, file)
    }

    fn global_using_namespaces(&self) -> &HashSet<String> {
        CSharpAnalyzer::global_using_namespaces(self)
    }

    fn global_using_namespaces_limited(
        &self,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<String> {
        CSharpAnalyzer::global_using_namespaces_limited(self, limit, continue_query)
    }

    fn global_using_aliases(&self) -> &HashMap<String, String> {
        CSharpAnalyzer::global_using_aliases(self)
    }

    fn global_using_aliases_limited(
        &self,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<(String, String)> {
        CSharpAnalyzer::global_using_aliases_limited(self, limit, continue_query)
    }
}

impl CSharpAnalyzer {
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

    pub(crate) fn raw_supertypes_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> crate::analyzer::store::LimitedQueryRows<String> {
        self.inner.raw_supertypes_limited(code_unit, limit)
    }
}

impl TestDetectionProvider for CSharpAnalyzer {}

use crate::analyzer::CodeUnitIndex;

impl CodeUnitIndex for CSharpAnalyzer {
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

    fn definitions(&self, fq_name: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        self.inner.definitions(fq_name)
    }

    fn direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.inner.direct_children(code_unit)
    }

    fn parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        self.inner.structural_parent_of(code_unit)
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

    fn get_all_declarations(&self) -> Vec<CodeUnit> {
        self.inner.get_all_declarations()
    }

    fn get_definitions(&self, fq_name: &str) -> Vec<CodeUnit> {
        self.inner.get_definitions(fq_name)
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
        self.declaration_candidates_by_identifier(identifier)
    }
}

impl IAnalyzer for CSharpAnalyzer {
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

    fn partial_declaration_parts(&self, code_unit: &CodeUnit) -> Option<Vec<CodeUnit>> {
        if !code_unit.is_class() {
            return None;
        }
        Some(graph_support::partial_type_parts(self, code_unit))
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

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        let external_index = if changed_files
            .iter()
            .any(dependency_discovery::is_csharp_dependency_input)
        {
            Arc::new(std::sync::OnceLock::new())
        } else {
            self.external_index.clone()
        };
        Self {
            inner: self.inner.update(changed_files),
            memo_caches: Arc::new(CSharpMemoCaches::new(self.memo_caches.budget_bytes())),
            csharp_config: self.csharp_config.clone(),
            external_index,
        }
    }

    fn update_all(&self) -> Self {
        Self {
            inner: self.inner.update_all(),
            memo_caches: Arc::new(CSharpMemoCaches::new(self.memo_caches.budget_bytes())),
            csharp_config: self.csharp_config.clone(),
            external_index: Arc::new(std::sync::OnceLock::new()),
        }
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
            .filter_map(|code_unit| build_csharp_clone_candidate_data(self, &code_unit, weights))
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

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        Some(self)
    }

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
        Some(self)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl crate::analyzer::AnalyzerTestHooks for CSharpAnalyzer {
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

    fn reset_definition_candidates_query_count_for_test(&self) {
        self.inner
            .test_hooks()
            .reset_definition_candidates_query_count_for_test();
    }

    fn definition_candidates_query_count_for_test(&self) -> usize {
        self.inner
            .test_hooks()
            .definition_candidates_query_count_for_test()
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

    fn reset_package_declaration_scan_count_for_test(&self) {
        self.inner
            .test_hooks()
            .reset_package_declaration_scan_count_for_test();
    }

    fn package_declaration_scan_count_for_test(&self) -> usize {
        self.inner
            .test_hooks()
            .package_declaration_scan_count_for_test()
    }

    fn reset_candidate_hydration_count_for_test(&self) {
        self.inner.reset_full_hydration_count_for_test();
    }

    fn candidate_hydration_count_for_test(&self) -> usize {
        self.inner.full_hydration_count_for_test() + self.inner.bulk_hydration_count_for_test()
    }
}

static CSHARP_USAGE_STRATEGY: CSharpUsageGraphStrategy = CSharpUsageGraphStrategy::new();

pub(crate) struct CSharpSupport;

impl LanguageSupport for CSharpSupport {
    fn language(&self) -> Language {
        Language::CSharp
    }

    fn display_symbol_name(&self, symbol: &str) -> String {
        csharp_normalize_full_name(symbol)
    }

    fn source_identifier<'s>(&self, identifier: &'s str) -> &'s str {
        strip_csharp_generic_arity(identifier)
    }

    fn alias_name_segment<'s>(&self, segment: &'s str) -> &'s str {
        strip_csharp_generic_arity(segment)
    }

    fn signature_metadata_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<SignatureMetadata>> {
        resolve_analyzer::<CSharpAnalyzer>(analyzer)
            .map(|csharp| csharp.signature_metadata_limited(unit, limit))
    }

    fn declaration_ranges_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<Range>> {
        resolve_analyzer::<CSharpAnalyzer>(analyzer)
            .map(|csharp| csharp.ranges_limited(unit, limit))
    }

    fn forward_query_provider<'a>(
        &self,
        analyzer: &'a dyn IAnalyzer,
    ) -> Option<&'a dyn ForwardQueryProvider> {
        resolve_analyzer::<CSharpAnalyzer>(analyzer).map(|value| value as _)
    }

    fn ecosystem(&self) -> UsageEcosystem {
        UsageEcosystem::CSharp
    }

    fn usage_strategy(&self) -> &'static dyn GraphUsageAnalyzer {
        &CSHARP_USAGE_STRATEGY
    }

    fn edge_pass(&self) -> Option<&'static dyn LanguageEdgePass> {
        Some(&CSharpEdgePass)
    }

    fn dead_code(&self) -> DeadCodeSupport {
        DeadCodeSupport {
            strategy: Some(&CSHARP_USAGE_STRATEGY),
            bulk: Some(&CSharpDeadCodeBulk),
        }
    }

    fn structural_receiver(&self) -> Option<&'static dyn StructuralReceiverResolver> {
        Some(&CSharpSupport)
    }

    fn type_lookup(&self) -> Option<&'static dyn TypeLookupResolver> {
        Some(&CSharpSupport)
    }

    fn parser_language(&self, _flavor: crate::analyzer::ParserFlavor) -> tree_sitter::Language {
        tree_sitter_c_sharp::LANGUAGE.into()
    }

    fn structural_spec(&self) -> &'static dyn crate::analyzer::structural::StructuralSpec {
        &brokk_bifrost_csharp::structural::CSHARP_STRUCTURAL_SPEC
    }

    fn highlight_query(&self) -> Option<&'static str> {
        Some(tree_sitter_c_sharp::HIGHLIGHTS_QUERY)
    }
}

struct CSharpEdgePass;

impl LanguageEdgePass for CSharpEdgePass {
    fn id(&self) -> EdgePassId {
        EdgePassId::CSharp
    }

    fn edge_sites(&self, ctx: &EdgeSiteScanCtx<'_>) -> Option<LanguageEdgeSites> {
        build_csharp_usage_edges(ctx.analyzer, ctx.fqns, ctx.keep_file).map(LanguageEdgeSites)
    }

    fn edge_weights(&self, ctx: &EdgeWeightScanCtx<'_>) -> Option<LanguageEdgeWeights> {
        build_csharp_usage_edge_weights(ctx.analyzer, ctx.fqns, ctx.keep_file)
            .map(LanguageEdgeWeights::Fqn)
    }
}

impl StructuralReceiverResolver for CSharpSupport {
    fn resolve_type_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<TypeLookupOutcome> {
        resolve_csharp_type_bounded(
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
        resolve_csharp_bounded(
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

impl TypeLookupResolver for CSharpSupport {
    fn resolve_type(&self, query: TypeLookupQuery<'_>) -> TypeLookupOutcome {
        resolve_csharp_type(
            query.analyzer,
            query.file,
            query.source,
            query.tree,
            query.site,
        )
    }
}

#[derive(Default)]
struct CSharpDeadCodeMemo {
    file_count: Option<usize>,
    overloaded_fqns: Option<HashSet<String>>,
    unsafe_using_member_forms_present: Option<bool>,
}

struct CSharpDeadCodeBulk;

impl DeadCodeBulkProof for CSharpDeadCodeBulk {
    fn id(&self) -> EdgePassId {
        EdgePassId::CSharp
    }

    fn new_memo(&self) -> Box<dyn std::any::Any + Send> {
        Box::new(CSharpDeadCodeMemo::default())
    }

    /// Tested inline rather than through a `dead_code_bulk_eligibility` in the graph
    /// module, because what disqualifies a C# candidate is local to the candidate:
    /// fields, constructors, overloaded functions, and any workspace using an unsafe
    /// `using` member form.
    fn needs_precise_scan(&self, routing: DeadCodeRouting<'_>) -> bool {
        let DeadCodeRouting {
            analyzer,
            candidate,
            file_cap,
            memo,
        } = routing;
        let CSharpDeadCodeMemo {
            file_count,
            overloaded_fqns,
            unsafe_using_member_forms_present,
        } = memo.downcast_mut().expect("C# bulk memo");
        if *file_count.get_or_insert_with(|| analyzable_file_count(analyzer, Language::CSharp))
            > file_cap
        {
            return true;
        }
        if candidate.is_field() || csharp_constructor_candidate(analyzer, candidate) {
            return true;
        }

        let empty_overloads = HashSet::default();
        let overloads = if candidate.is_function() {
            overloaded_fqns
                .get_or_insert_with(|| overloaded_function_fqns(analyzer, Language::CSharp))
        } else {
            &empty_overloads
        };
        let has_unsafe_using_member_forms = candidate.is_function()
            && *unsafe_using_member_forms_present
                .get_or_insert_with(|| csharp_unsafe_using_member_forms_present(analyzer));

        candidate.is_function()
            && (overloads.contains(candidate.fq_name().as_str()) || has_unsafe_using_member_forms)
    }

    fn preflight(&self, analyzer: &dyn IAnalyzer) -> DeadCodeBulkPreflight {
        DeadCodeBulkPreflight::Ready {
            label: "C#",
            files: analyzable_file_count(analyzer, Language::CSharp),
        }
    }

    fn build(
        &self,
        analyzer: &dyn IAnalyzer,
        candidates: &[CodeUnit],
    ) -> Option<DeadCodeBulkEdges> {
        let nodes = fqn_bulk_nodes(
            analyzer,
            Language::CSharp,
            |unit| unit.is_function() || unit.is_class(),
            candidates,
        );
        build_csharp_usage_edges(analyzer, &nodes, |_| true)
            .map(|edges| DeadCodeBulkEdges::Fqn(Arc::new(edges)))
    }
}
