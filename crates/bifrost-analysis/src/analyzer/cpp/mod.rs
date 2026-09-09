mod adapter;
mod cache;
mod clones;
#[cfg(test)]
mod diagnostics;
pub(crate) mod external;
mod hierarchy;
mod identity;
mod imports;
mod projection;
mod semantic;
mod structural;
#[cfg(test)]
mod tests;

use crate::analyzer::clone_detection::{
    CloneCandidateProfile, detect_structural_clone_smells, refine_clone_similarity_with_ast,
};
use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::languages::{
    BoundedReceiverQuery, DeadCodeBulkEdges, DeadCodeBulkPreflight, DeadCodeBulkProof,
    DeadCodeRouting, DeadCodeSupport, EdgePassId, EdgeSiteScanCtx, EdgeWeightScanCtx,
    LanguageEdgePass, LanguageEdgeSites, LanguageEdgeWeights, LanguageSupport,
    StructuralReceiverResolver, analyzable_file_count, fqn_bulk_nodes, overloaded_function_fqns,
};
use crate::analyzer::store::LimitedQueryRows;
use crate::analyzer::tree_sitter_analyzer::BulkFileStateSource;
use crate::analyzer::usages::cpp_graph::{
    CppDeadCodeBulkEligibility, CppUsageGraphStrategy, build_cpp_usage_edge_weights,
    build_cpp_usage_edges, build_rooted_cpp_usage_edges, dead_code_bulk_eligibility,
};
use crate::analyzer::usages::get_definition::{
    BoundedResolution, DefinitionLookupOutcome, resolve_cpp_bounded,
};
use crate::analyzer::usages::get_type::{TypeLookupOutcome, resolve_cpp_type_bounded};
use crate::analyzer::usages::workspace_graph::UsageEcosystem;
use crate::analyzer::weighted_cache::{build_weighted_cache, weight_code_unit_vec_by_unit};
use crate::analyzer::{
    AnalyzerConfig, AnalyzerStoreContext, BuildProgress, CloneSmell, CloneSmellWeights, CodeUnit,
    CppFieldLinkage, DescendantIndexVariant, DirectDescendantIndex, ForwardQueryProvider,
    IAnalyzer, ImportAnalysisProvider, ImportInfo, KeyedPoolSafeMemo, Language, PoolSafeMemo,
    Project, ProjectFile, Range, SignatureMetadata, TestAssertionSmell, TestAssertionWeights,
    TestDetectionProvider, TreeSitterAnalyzer, TypeAliasProvider, TypeHierarchyProvider,
    resolve_analyzer,
};
use crate::analyzer::{AnalyzerQueryScope, QueryScope, QueryToken};
use crate::hash::{HashMap, HashSet};
use moka::sync::Cache;
use rayon::prelude::*;
use std::collections::{BTreeSet, VecDeque};
use std::sync::{Arc, OnceLock};

pub(crate) use adapter::CppAdapter;
use brokk_bifrost_cpp::adapter::parse_cpp_file_with_object_macro_fields;
use brokk_bifrost_cpp::clones::cpp_clone_parser;
use brokk_bifrost_cpp::compile_context::{CppCompileContext, CppCompileContexts};
pub(crate) use brokk_bifrost_cpp::declarations::CppRecoveredExportClassIndex;
use brokk_bifrost_cpp::graph::CppWorkspaceSource;
use brokk_bifrost_cpp::graph::extractor::{
    build_source_using_index, cpp_member_is_spelled_at_references, cpp_syntax_may_spell_member,
};
use brokk_bifrost_cpp::graph::resolver::{
    CppClassDeclarationStrength, OrphanedNamespaceScopeIndex, SourceUsingIndex,
    is_declaration_name as cpp_is_declaration_name,
};
use brokk_bifrost_cpp::graph::syntax::ObjectMacroReplacement;
use brokk_bifrost_cpp::graph_support::CppSource;
use brokk_bifrost_cpp::identity::{
    CppReconcileCandidates, CppReconcileGroupKey, CppReconciledDefinitionIndex,
    cpp_reconcile_candidates_from_units, cpp_reconcile_group, cpp_reconcile_group_key,
};
use brokk_bifrost_cpp::imports::{
    IncludeTargetIndex, include_paths, resolve_include_targets_with_index,
};
use brokk_bifrost_cpp::test_detection::detect_cpp_test_assertion_smells;
use cache::{
    weight_code_unit_set_by_file, weight_code_unit_vec_by_file, weight_include_reachability,
    weight_project_file_set, weight_reconcile_candidates, weight_reconciled_groups,
    weight_source_using_index,
};
use clones::build_clone_candidate_data;

pub(crate) use brokk_bifrost_cpp::declarations::{
    ObjectMacroFieldEvent, collect_cpp_object_macro_field_events, cpp_sentinel_recovered_classes,
    is_direct_recovered_exported_class_field_declaration, node_text,
};
use brokk_bifrost_cpp::identity::cpp_callable_unit_role;
pub(crate) use brokk_bifrost_cpp::identity::{
    CppCallableUnitRole, CppOccurrenceClassifier, CppOccurrenceRole, cpp_indexed_callable_linkage,
    cpp_is_range_for_binding_name, cpp_occurrence_role_for_range,
    cpp_range_is_pure_virtual_declaration,
};

#[derive(Clone)]
struct MacroComposedField {
    unit: CodeUnit,
    owner: CodeUnit,
    ranges: Vec<Range>,
}
pub use brokk_bifrost_cpp::identity::{
    cpp_is_constructor_or_destructor_declarator_name, cpp_is_conversion_operator_target_type,
    cpp_is_recovered_macro_character_token_type,
};
pub(crate) use identity::{
    cpp_callable_definitions_share_identity_evidence,
    cpp_callable_definitions_share_identity_evidence_with_visibility,
    cpp_header_body_files_are_related,
};
pub(crate) use imports::HeaderLanguageAttribution;
use imports::TransitiveReverseTuIndex;
#[derive(Clone)]
pub struct CppAnalyzer {
    inner: TreeSitterAnalyzer<CppAdapter>,
    memo_budget: u64,
    imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    /// Owner-specific fields materialized from object-like macros in the
    /// owner's include closure. This remains an analyzer overlay because the
    /// donor macro and consuming aggregate live in different parsed blobs.
    macro_composed_fields_by_file: Cache<ProjectFile, Arc<Vec<MacroComposedField>>>,
    referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    direct_ancestors: Cache<CodeUnit, Arc<Vec<CodeUnit>>>,
    visible_type_units_by_file: Cache<ProjectFile, Arc<Vec<CodeUnit>>>,
    /// The per-file structured using index behind
    /// [`CppSource::source_using_index`]. Memoized here rather than on
    /// `VisibilityIndex` because a fresh visibility index is built per usage
    /// query, and rebuilding this index per query re-walked a 9.5 MB
    /// amalgamation's AST once per candidate (issue #1927).
    source_using_index_by_file: Cache<ProjectFile, Arc<SourceUsingIndex>>,
    unconditional_include_reachability: Cache<(ProjectFile, ProjectFile, bool), bool>,
    /// The declaration-strength answer behind
    /// [`CppSource::cached_class_declaration_strength`]. Memoized here rather
    /// than per query for the same reason as `source_using_index_by_file`: the
    /// C++ inverse scan asks it once per declaration seed, and on a translation
    /// unit the parser could not fully recover each ask re-derives the
    /// export-macro recovery shapes from the file's `ERROR` subtrees (#1496).
    class_declaration_strength: Cache<CodeUnit, CppClassDeclarationStrength>,
    /// The per-file embedded export-macro class recovery behind
    /// [`CppSource::recovered_export_class_index`], memoized here for the same
    /// reason as `source_using_index_by_file` (#1496).
    recovered_export_class_index_by_file: Cache<ProjectFile, Arc<CppRecoveredExportClassIndex>>,
    /// The per-file namespaces parse recovery dropped, behind
    /// [`CppSource::orphaned_namespace_scopes`]. Both lookup directions derive
    /// every lexical scope in a file through it, so it is memoized here for
    /// the same reason as `source_using_index_by_file` (#1537).
    orphaned_namespace_scopes_by_file: Cache<ProjectFile, Arc<OrphanedNamespaceScopeIndex>>,
    /// The C reading of a header blob, when the store holds one (#1970). See
    /// [`projection::CppCReading`]. `None` is a real, memoized answer: it says
    /// the two readings of that blob agree, so every question about the C view
    /// is answered from the file's own row-set.
    c_readings_by_file: Cache<ProjectFile, Option<Arc<projection::CppCReading>>>,
    /// The per-file answer behind [`Self::header_language_attribution`].
    ///
    /// The attribution reads only the compile database and the transitive
    /// reverse translation-unit index, both of which live for this analyzer,
    /// so the answer is a per-file constant here. It is memoized because the
    /// C++ inverse scan asks it through `reference_uses_c_semantics` once per
    /// visited AST node, and each ask normalized the path of the file and of
    /// every translation unit reaching it: 9.6 percent of the BehaviorTree
    /// `integer_sequence` query was this one per-file question (#1496).
    header_language_attribution_by_file: Cache<ProjectFile, HeaderLanguageAttribution>,
    /// The object-like field-list macro events of one file, in source order.
    ///
    /// [`Self::build_macro_composed_fields`] collects these for every file in
    /// an owner's include closure, so before this memo the same header's AST
    /// was walked, and each of its macro replacements re-parsed, once per
    /// owner whose closure reached it: 11.6 percent of the BehaviorTree
    /// `integer_sequence` query, for 161 distinct files (#1496).
    object_macro_field_events_by_file: Cache<ProjectFile, Arc<Vec<ObjectMacroFieldEvent>>>,
    /// Every callable declaration sharing one member identifier, bucketed by
    /// owner terminal. The identifier-index store read and the bucketing pass
    /// that produce it are what #1908 stopped repeating per queried fq name.
    reconcile_candidates_by_identifier: Cache<String, Arc<CppReconcileCandidates>>,
    /// #1134 resolution-time identity-reconciliation overlay. Maps the canonical
    /// `fq_name` a header declaration carries to the provisional out-of-line
    /// member definition `CodeUnit`s whose per-file identity extraction could not
    /// reconcile with it (the file-scope-under-using-directive shape and the
    /// template-specialization twin), keyed on the include-visible class table.
    ///
    /// Keyed by [`CppReconcileGroupKey`] -- the member identifier and the owner
    /// terminal -- not by the queried fq name. Reconciliation is a function of
    /// exactly that pair, so the old per-fq key never hit for a bare identifier
    /// whose namesakes have distinct owners: 1,277 distinct keys, 1,277
    /// identical rebuilds (#1908). See `reconciled_definitions`.
    reconciled_definitions_by_group:
        Cache<CppReconcileGroupKey, Arc<HashMap<String, Arc<CppReconciledDefinitionIndex>>>>,
    include_target_index: Arc<OnceLock<IncludeTargetIndex>>,
    reverse_include_index: Arc<PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    /// The transitive answer over [`Self::reverse_include_index`]: for a
    /// header, every workspace translation unit (`.c`/`.cc`/`.cpp`/`.cxx`)
    /// whose include closure reaches it. Built once over the whole include
    /// graph (`imports::build_transitive_reverse_tu_index`), not per-header
    /// BFS, so this memo holds the whole relation exactly like
    /// `reverse_include_index` does -- as bitsets over the graph's SCC
    /// condensation, which is what took envoy's build from 1,362 s to seconds
    /// (#2899). Backs [`Self::header_language_attribution`].
    transitive_reverse_tu_index: Arc<PoolSafeMemo<TransitiveReverseTuIndex>>,
    /// `PoolSafeMemo`, not `OnceLock`: this whole-workspace build is reached
    /// from rayon workers during cold scans, and a blocking `get_or_init` parks
    /// every one of them behind the single initializer for its full duration.
    ///
    /// Keyed by [`DescendantIndexVariant`], so a request that excluded test
    /// files gets an index that was never built over them (issue #1748: 52.3%
    /// of the include-closure builds in the incident trace were test-side, and
    /// the request had already said `include_tests: false`). Two cells at most:
    /// the exclusion verdict is a pure function of the analyzer and the file.
    direct_descendant_index: Arc<KeyedPoolSafeMemo<DescendantIndexVariant, DirectDescendantIndex>>,
    compile_contexts: Arc<OnceLock<CppCompileContexts>>,
    external_header_closures: Arc<KeyedPoolSafeMemo<ProjectFile, external::ReachedExternalHeaders>>,
    #[cfg(test)]
    type_alias_classification_count: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(any(test, feature = "test-support"))]
    authoritative_visibility_build_count: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(any(test, feature = "test-support"))]
    target_spec_scan_count: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(any(test, feature = "test-support"))]
    cpp_parent_resolution_count: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(any(test, feature = "test-support"))]
    visible_type_units_build_count: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(any(test, feature = "test-support"))]
    source_using_index_build_count: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(any(test, feature = "test-support"))]
    using_guard_context_inspection_count: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(any(test, feature = "test-support"))]
    macro_composed_fields_build_count: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(any(test, feature = "test-support"))]
    cpp_class_strength_parse_count: Arc<std::sync::atomic::AtomicUsize>,
    /// Identifier-index scans issued for reconciliation. One per member
    /// identifier after #1908; one per queried fq name before it.
    #[cfg(any(test, feature = "test-support"))]
    reconcile_candidate_scan_count: Arc<std::sync::atomic::AtomicUsize>,
    /// Candidates one reconcile group examined. The unit the #1908 trace
    /// counted 11.0M of.
    #[cfg(any(test, feature = "test-support"))]
    reconcile_candidate_evaluation_count: Arc<std::sync::atomic::AtomicUsize>,
    /// Raw signature-fact reads performed by the reconciliation builder. This
    /// is distinct from the public overlay-aware metadata surface so cache
    /// initialization cannot recursively request itself.
    #[cfg(any(test, feature = "test-support"))]
    reconcile_stored_signature_metadata_count: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(test)]
    external_header_closure_build_count: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(test)]
    external_header_parse_count: Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExternalHeaderClosureWorkCounts {
    pub builds: usize,
    pub external_header_parses: usize,
}

impl ForwardQueryProvider for CppAnalyzer {
    fn normalize_rendered_name(&self, fqn: &str) -> String {
        self.inner.normalize_rendered_name(fqn)
    }

    fn forward_definition_fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        self.relational_definitions_for_rendered_name(fqn)
    }

    fn forward_file_identifier(&self, file: &ProjectFile, identifier: &str) -> Vec<CodeUnit> {
        self.inner.forward_file_identifier(file, identifier)
    }

    fn forward_direct_children(&self, owner: &CodeUnit) -> Vec<CodeUnit> {
        self.inner.forward_direct_children(owner)
    }

    fn forward_relational_name(
        &self,
        unit: &CodeUnit,
    ) -> brokk_bifrost_core::analyzer::RelationalName {
        self.inner.relational_name_for_unit(unit)
    }

    fn forward_definition_candidate_short_names(&self, rendered: &str) -> Vec<String> {
        self.inner.definition_candidate_short_names(rendered)
    }

    fn forward_definition_sources_may_exist(&self) -> bool {
        self.inner.definition_sources_may_exist()
    }

    fn forward_package_exists(&self, package: &str) -> bool {
        self.inner.forward_package_exists(package)
    }

    fn forward_fqn_prefix_exists(&self, prefix: &str) -> bool {
        self.inner.forward_fqn_prefix_exists(prefix)
    }
}

impl CppAnalyzer {
    /// Share only completed file-derived values. A waiter receives the same
    /// typed failure as its builder, and records it on its own open scopes.
    fn cached_complete_read<K, T>(
        &self,
        cache: &Cache<K, Arc<T>>,
        key: &K,
        read: impl FnOnce() -> T,
    ) -> Arc<T>
    where
        K: Eq + std::hash::Hash + Clone + Send + Sync + 'static,
        T: Default + Send + Sync + 'static,
    {
        match cache.try_get_with_by_ref(key, || {
            let scope = AnalyzerQueryScope::new(self);
            let value = read();
            scope.read_completion()?;
            Ok::<_, crate::analyzer::QueryReadIncomplete>(Arc::new(value))
        }) {
            Ok(value) => value,
            Err(reason) => {
                self.record_query_incomplete((*reason).clone());
                Arc::default()
            }
        }
    }

    fn macro_composed_fields(&self, file: &ProjectFile) -> Arc<Vec<MacroComposedField>> {
        self.cached_complete_read(&self.macro_composed_fields_by_file, file, || {
            self.build_macro_composed_fields(file)
        })
    }

    fn all_macro_composed_fields(&self) -> Vec<MacroComposedField> {
        self.inner
            .get_analyzed_files()
            .into_iter()
            .flat_map(|file| {
                self.macro_composed_fields(&file)
                    .as_ref()
                    .clone()
                    .into_iter()
            })
            .collect()
    }

    fn all_macro_composed_fields_while(
        &self,
        cancellation: &crate::CancellationToken,
    ) -> Option<Vec<MacroComposedField>> {
        let mut fields = Vec::new();
        for file in self.inner.get_analyzed_files() {
            if cancellation.is_cancelled() {
                return None;
            }
            fields.extend(self.macro_composed_fields(&file).iter().cloned());
        }
        Some(fields)
    }

    fn macro_composed_fields_for_owner_name(
        &self,
        owner_name: brokk_bifrost_core::analyzer::RelationalName,
        owner_query: crate::analyzer::RelationalDefinitionQuery,
        cancellation: &crate::CancellationToken,
    ) -> Result<Vec<MacroComposedField>, crate::analyzer::RelationalBatchOutcome> {
        let owner_request = crate::analyzer::RelationalDefinitionRequest {
            ordinal: 0,
            language_scope: crate::analyzer::DefinitionLanguageScope::Language(Language::Cpp),
            name: owner_name,
            query: owner_query,
        };
        let mut results = match crate::analyzer::RelationalDefinitionLookup::batch(
            &self.inner,
            &[owner_request],
            cancellation,
        ) {
            crate::analyzer::RelationalBatchOutcome::Complete(results) => results,
            outcome => return Err(outcome),
        };
        let result = results
            .pop()
            .expect("one owner definition request returns one result");
        let crate::analyzer::RelationalDefinitionValue::Definitions(owners) = result.value else {
            panic!("an owner definition request returned the wrong relational value shape");
        };
        let mut owner_files = owners
            .into_iter()
            .filter(|owner| owner.is_class())
            .map(|owner| owner.source().clone())
            .collect::<Vec<_>>();
        owner_files.sort();
        owner_files.dedup();

        let mut fields = Vec::new();
        for file in owner_files {
            if cancellation.is_cancelled() {
                return Err(crate::analyzer::RelationalBatchOutcome::Cancelled);
            }
            fields.extend(self.macro_composed_fields(&file).iter().cloned());
        }
        Ok(fields)
    }

    /// The object-like field-list macro events `file` declares, in source
    /// order.
    ///
    /// Macro events need only the exact source and AST. Indexed syntax also
    /// hydrates every declaration in this include closure, undoing the
    /// visibility resolver's target-directed declaration reads, so the read
    /// stays on `prepared_syntax_limited`. A file whose source cannot be
    /// prepared returns an empty compatibility value with a query-incomplete
    /// reason; that value must never be cached as a completed event set.
    fn object_macro_field_events(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Arc<Vec<ObjectMacroFieldEvent>> {
        self.cached_complete_read(&self.object_macro_field_events_by_file, file, || {
            let Some((_, prepared)) = self
                .inner
                .prepared_syntax_limited(token, file, usize::MAX)
                .expect("an unbounded syntax read cannot exceed its source limit")
            else {
                self.record_query_incomplete(
                    crate::analyzer::QueryReadIncomplete::StructureUnavailable(file.clone()),
                );
                return Vec::new();
            };
            collect_cpp_object_macro_field_events(prepared.tree().root_node(), prepared.source())
        })
    }

    fn macro_composed_field_owner_name(
        request: &crate::analyzer::RelationalDefinitionRequest,
    ) -> Option<brokk_bifrost_core::analyzer::RelationalName> {
        let owner_name = match &request.query {
            crate::analyzer::RelationalDefinitionQuery::ExactName
            | crate::analyzer::RelationalDefinitionQuery::NormalizedName => request.name.parent(),
            crate::analyzer::RelationalDefinitionQuery::StructuralChildren
            | crate::analyzer::RelationalDefinitionQuery::StructuralMembers { .. }
            | crate::analyzer::RelationalDefinitionQuery::VisibleMembers { .. } => {
                Some(request.name.clone())
            }
            _ => None,
        }?;
        (!owner_name.full_name().is_empty()).then_some(owner_name)
    }

    fn build_macro_composed_fields(&self, owner_file: &ProjectFile) -> Vec<MacroComposedField> {
        #[cfg(any(test, feature = "test-support"))]
        self.macro_composed_fields_build_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        let include_target_index = self.include_target_index();
        let mut visited = HashSet::default();
        let mut queue = VecDeque::from([owner_file.clone()]);
        let mut macro_fields = HashMap::<String, ObjectMacroReplacement>::default();
        let mut blocked = HashSet::default();
        while let Some(file) = queue.pop_front() {
            if self
                .inner
                .active_query_cancellation()
                .is_some_and(|cancellation| cancellation.is_cancelled())
            {
                self.record_query_incomplete(crate::analyzer::QueryReadIncomplete::Cancelled);
                return Vec::new();
            }
            if !visited.insert(file.clone()) {
                continue;
            }
            let imports = self.import_statements_from_projection(token, &file);
            for include in include_paths(&imports) {
                for target in
                    resolve_include_targets_with_index(&file, &include, include_target_index)
                {
                    if target != *owner_file {
                        queue.push_back(target);
                    }
                }
            }
            if file == *owner_file {
                continue;
            }
            for event in self.object_macro_field_events(token, &file).iter() {
                if self
                    .inner
                    .active_query_cancellation()
                    .is_some_and(|cancellation| cancellation.is_cancelled())
                {
                    self.record_query_incomplete(crate::analyzer::QueryReadIncomplete::Cancelled);
                    return Vec::new();
                }
                match event {
                    ObjectMacroFieldEvent::Define {
                        name, replacement, ..
                    } => {
                        if replacement.is_empty() {
                            macro_fields.remove(name);
                            blocked.insert(name.clone());
                            continue;
                        }
                        if blocked.contains(name) {
                            continue;
                        }
                        // Mutually exclusive headers in one closure (libuv's
                        // `uv/unix.h` and `uv/win.h` both define
                        // `UV_HANDLE_PRIVATE_FIELDS`) leave the members every
                        // spelling declares identically proven, and the rest
                        // unproven, instead of losing the name entirely.
                        let admitted = match macro_fields.get(name) {
                            Some(previous) if previous != replacement => {
                                previous.intersect(replacement)
                            }
                            _ => replacement.clone(),
                        };
                        if admitted.is_empty() {
                            macro_fields.remove(name);
                            blocked.insert(name.clone());
                        } else {
                            macro_fields.insert(name.clone(), admitted);
                        }
                    }
                    ObjectMacroFieldEvent::Undef { name, .. } => {
                        // Include traversal order can differ from preprocessor
                        // execution order. Permanently blocking an undefined
                        // name is conservative and prevents a stale donor
                        // definition from crossing an undef.
                        macro_fields.remove(name);
                        blocked.insert(name.clone());
                    }
                }
            }
        }
        if macro_fields.is_empty() {
            return Vec::new();
        }
        let Some(prepared) = self.prepared_syntax(token, owner_file) else {
            return Vec::new();
        };
        let parsed = parse_cpp_file_with_object_macro_fields(
            owner_file,
            prepared.source(),
            prepared.tree(),
            macro_fields,
        );
        let owners = self
            .inner
            .declarations(owner_file)
            .into_iter()
            .filter(|unit| unit.is_class())
            .collect::<Vec<_>>();
        parsed
            .declarations()
            .iter()
            .filter(|unit| unit.is_field() && unit.is_synthetic())
            .filter_map(|unit| {
                let owner_fq = unit.fq().parent()?;
                let owner = owners.iter().find(|owner| owner.fq() == &owner_fq)?.clone();
                let ranges = parsed.declaration_ranges(unit).to_vec();
                Some(MacroComposedField {
                    unit: unit.clone(),
                    owner,
                    ranges,
                })
            })
            .collect()
    }

    fn macro_composed_fields_for_owner(&self, owner: &CodeUnit) -> Vec<CodeUnit> {
        self.macro_composed_fields(owner.source())
            .iter()
            .filter(|field| field.owner == *owner)
            .map(|field| field.unit.clone())
            .collect()
    }

    fn generated_field_owner(&self, field: &CodeUnit) -> Option<CodeUnit> {
        if !field.is_field() || !field.is_synthetic() {
            return None;
        }
        self.macro_composed_fields(field.source())
            .iter()
            .find(|candidate| candidate.unit == *field)
            .map(|candidate| candidate.owner.clone())
    }

    pub(crate) fn reconciled_provisional(&self, unit: &CodeUnit) -> Option<CodeUnit> {
        self.reconciled_definitions(&unit.fq_name())
            .provisional_of
            .get(unit)
            .cloned()
    }

    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        Self::from_inner(self.inner.clone_with_project(project), self.memo_budget)
    }

    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        let inner = TreeSitterAnalyzer::new_with_config(project, CppAdapter, config);
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
            CppAdapter,
            config,
            store_context,
            progress,
        )?;
        Ok(Self::from_inner(inner, memo_budget))
    }

    fn from_inner(inner: TreeSitterAnalyzer<CppAdapter>, memo_budget: u64) -> Self {
        let analyzer = Self {
            inner,
            memo_budget,
            imported_code_units: build_weighted_cache(
                memo_budget / 4,
                weight_code_unit_set_by_file,
            ),
            macro_composed_fields_by_file: build_weighted_cache(
                memo_budget / 8,
                cache::weight_macro_composed_field_vec_by_file,
            ),
            referencing_files: build_weighted_cache(memo_budget / 8, weight_project_file_set),
            direct_ancestors: build_weighted_cache(memo_budget / 8, weight_code_unit_vec_by_unit),
            visible_type_units_by_file: build_weighted_cache(
                memo_budget / 8,
                weight_code_unit_vec_by_file,
            ),
            source_using_index_by_file: build_weighted_cache(
                memo_budget / 8,
                weight_source_using_index,
            ),
            unconditional_include_reachability: build_weighted_cache(
                memo_budget / 8,
                weight_include_reachability,
            ),
            class_declaration_strength: build_weighted_cache(
                memo_budget / 8,
                cache::weight_class_declaration_strength,
            ),
            recovered_export_class_index_by_file: build_weighted_cache(
                memo_budget / 8,
                cache::weight_recovered_export_class_index,
            ),
            orphaned_namespace_scopes_by_file: build_weighted_cache(
                memo_budget / 8,
                cache::weight_orphaned_namespace_scopes,
            ),
            c_readings_by_file: build_weighted_cache(memo_budget / 8, cache::weight_c_reading),
            header_language_attribution_by_file: build_weighted_cache(
                memo_budget / 8,
                cache::weight_header_language_attribution,
            ),
            object_macro_field_events_by_file: build_weighted_cache(
                memo_budget / 8,
                cache::weight_object_macro_field_events,
            ),
            reconcile_candidates_by_identifier: build_weighted_cache(
                memo_budget / 8,
                weight_reconcile_candidates,
            ),
            reconciled_definitions_by_group: build_weighted_cache(
                memo_budget / 8,
                weight_reconciled_groups,
            ),
            include_target_index: Arc::new(OnceLock::new()),
            reverse_include_index: Arc::new(PoolSafeMemo::new()),
            transitive_reverse_tu_index: Arc::new(PoolSafeMemo::new()),
            direct_descendant_index: Arc::new(KeyedPoolSafeMemo::new()),
            compile_contexts: Arc::new(OnceLock::new()),
            external_header_closures: Arc::new(KeyedPoolSafeMemo::new()),
            #[cfg(test)]
            type_alias_classification_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            authoritative_visibility_build_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            target_spec_scan_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            cpp_parent_resolution_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            cpp_class_strength_parse_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            visible_type_units_build_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            source_using_index_build_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            using_guard_context_inspection_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            macro_composed_fields_build_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            reconcile_candidate_scan_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            reconcile_candidate_evaluation_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            reconcile_stored_signature_metadata_count: Arc::new(
                std::sync::atomic::AtomicUsize::new(0),
            ),
            #[cfg(test)]
            external_header_closure_build_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(test)]
            external_header_parse_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        };
        analyzer.sync_published_c_reading_workspace();
        analyzer
    }

    /// The re-keyed reconciled definitions (if any) that belong under the
    /// canonical `fq_name` a header declaration carries.
    ///
    /// Two memos, both on the analyzer so `IAnalyzer::update` rebuilds them
    /// wholesale with the rest of it. The identifier cell holds the candidate
    /// set one store read produced; the group cell holds every re-keyed
    /// definition that (identifier, owner terminal) pair yields, indexed by the
    /// canonical fq name it belongs under. This query is then a map lookup.
    ///
    /// Both use `try_get_with_by_ref`: a stopped build returns its typed
    /// incompleteness to every waiter and publishes nothing. A truncated
    /// candidate set or a truncated group is
    /// indistinguishable from an identifier with fewer namesakes, and every
    /// later reader would silently lose definitions. That is moka's form of the
    /// complete-or-nothing contract `PoolSafeMemo::get_or_build_while` carries
    /// (#1748), and `visible_type_units_while` already applies it one layer
    /// down.
    fn reconciled_definitions(&self, fq_name: &str) -> Arc<CppReconciledDefinitionIndex> {
        self.reconciled_definitions_with_cancellation(fq_name, None)
    }

    fn reconciled_definitions_with_cancellation(
        &self,
        fq_name: &str,
        request_cancellation: Option<&crate::CancellationToken>,
    ) -> Arc<CppReconciledDefinitionIndex> {
        static EMPTY: OnceLock<Arc<CppReconciledDefinitionIndex>> = OnceLock::new();
        let empty = || Arc::clone(EMPTY.get_or_init(Arc::default));
        let Some(key) = cpp_reconcile_group_key(fq_name) else {
            return empty();
        };
        // The request's deadline, if its opener set one. `IAnalyzer::definitions`
        // takes no token -- it is nominally a plain lookup -- and on C++ it is
        // the read that ran for 270 s in #1908 with nothing polling it.
        let cancellation = request_cancellation
            .cloned()
            .or_else(|| self.inner.active_query_cancellation());
        let keep_going = || {
            let cancelled = cancellation
                .as_ref()
                .is_some_and(crate::CancellationToken::is_cancelled);
            if cancelled {
                self.record_query_incomplete(crate::analyzer::QueryReadIncomplete::Cancelled);
            }
            !cancelled
        };
        let candidates = self.reconcile_candidates_by_identifier.try_get_with_by_ref(
            key.member_identifier.as_str(),
            || {
                let scope = AnalyzerQueryScope::new(self);
                #[cfg(any(test, feature = "test-support"))]
                self.reconcile_candidate_scan_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let mut name = crate::analyzer::FqName::new();
                name.push(crate::analyzer::fq_name::segment_interner().intern(
                    &key.member_identifier,
                    crate::analyzer::fq_name::SegmentKind::Unknown,
                ));
                let request = crate::analyzer::RelationalDefinitionRequest {
                    ordinal: 0,
                    language_scope: crate::analyzer::DefinitionLanguageScope::Language(
                        Language::Cpp,
                    ),
                    name: brokk_bifrost_core::analyzer::RelationalName::stable(name),
                    query: crate::analyzer::RelationalDefinitionQuery::Identifier { file: None },
                };
                let local_cancellation = crate::CancellationToken::new();
                let query_cancellation = cancellation.as_ref().unwrap_or(&local_cancellation);
                let mut results = match crate::analyzer::RelationalDefinitionLookup::batch(
                    &self.inner,
                    &[request],
                    query_cancellation,
                ) {
                    crate::analyzer::RelationalBatchOutcome::Complete(results) => results,
                    crate::analyzer::RelationalBatchOutcome::Cancelled => {
                        return Err(crate::analyzer::QueryReadIncomplete::Cancelled);
                    }
                    crate::analyzer::RelationalBatchOutcome::Failed(error) => {
                        let error = crate::analyzer::store::StoreError::new(error.message());
                        self.record_query_failure(error.clone());
                        return Err(crate::analyzer::QueryReadIncomplete::StoreFailure(error));
                    }
                };
                let result = results
                    .pop()
                    .expect("one reconcile query returns one result");
                let crate::analyzer::RelationalDefinitionValue::Definitions(units) = result.value
                else {
                    panic!("an identifier reconcile query returned the wrong value shape");
                };
                let candidates = cpp_reconcile_candidates_from_units(units, &keep_going);
                scope.read_completion()?;
                candidates
                    .map(Arc::new)
                    .ok_or(crate::analyzer::QueryReadIncomplete::Cancelled)
            },
        );
        let candidates = match candidates {
            Ok(candidates) => candidates,
            Err(reason) => {
                self.record_query_incomplete((*reason).clone());
                return empty();
            }
        };
        let on_candidate = || {
            #[cfg(any(test, feature = "test-support"))]
            self.reconcile_candidate_evaluation_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        };
        let groups = self
            .reconciled_definitions_by_group
            .try_get_with_by_ref(&key, || {
                // This builder runs on a cache miss, inside whatever request
                // scope the caller opened; nesting one here makes the syntax
                // reads below provable without changing what they memoize
                // (issue #2414 step 3).
                let scope = AnalyzerQueryScope::new(self);
                let groups = cpp_reconcile_group(
                    self,
                    scope.token(),
                    &key,
                    &candidates,
                    &keep_going,
                    &on_candidate,
                );
                scope.read_completion()?;
                groups
                    .map(Arc::new)
                    .ok_or(crate::analyzer::QueryReadIncomplete::Cancelled)
            });
        let groups = match groups {
            Ok(groups) => groups,
            Err(reason) => {
                self.record_query_incomplete((*reason).clone());
                return empty();
            }
        };
        groups.get(fq_name).map_or_else(empty, Arc::clone)
    }

    fn with_updated_inner(&self, inner: TreeSitterAnalyzer<CppAdapter>) -> Self {
        let analyzer = Self {
            inner,
            memo_budget: self.memo_budget,
            imported_code_units: build_weighted_cache(
                self.memo_budget / 4,
                weight_code_unit_set_by_file,
            ),
            macro_composed_fields_by_file: build_weighted_cache(
                self.memo_budget / 8,
                cache::weight_macro_composed_field_vec_by_file,
            ),
            referencing_files: build_weighted_cache(self.memo_budget / 8, weight_project_file_set),
            direct_ancestors: build_weighted_cache(
                self.memo_budget / 8,
                weight_code_unit_vec_by_unit,
            ),
            visible_type_units_by_file: build_weighted_cache(
                self.memo_budget / 8,
                weight_code_unit_vec_by_file,
            ),
            source_using_index_by_file: build_weighted_cache(
                self.memo_budget / 8,
                weight_source_using_index,
            ),
            unconditional_include_reachability: build_weighted_cache(
                self.memo_budget / 8,
                weight_include_reachability,
            ),
            class_declaration_strength: build_weighted_cache(
                self.memo_budget / 8,
                cache::weight_class_declaration_strength,
            ),
            recovered_export_class_index_by_file: build_weighted_cache(
                self.memo_budget / 8,
                cache::weight_recovered_export_class_index,
            ),
            orphaned_namespace_scopes_by_file: build_weighted_cache(
                self.memo_budget / 8,
                cache::weight_orphaned_namespace_scopes,
            ),
            c_readings_by_file: build_weighted_cache(self.memo_budget / 8, cache::weight_c_reading),
            header_language_attribution_by_file: build_weighted_cache(
                self.memo_budget / 8,
                cache::weight_header_language_attribution,
            ),
            object_macro_field_events_by_file: build_weighted_cache(
                self.memo_budget / 8,
                cache::weight_object_macro_field_events,
            ),
            reconcile_candidates_by_identifier: build_weighted_cache(
                self.memo_budget / 8,
                weight_reconcile_candidates,
            ),
            reconciled_definitions_by_group: build_weighted_cache(
                self.memo_budget / 8,
                weight_reconciled_groups,
            ),
            include_target_index: Arc::new(OnceLock::new()),
            reverse_include_index: Arc::new(PoolSafeMemo::new()),
            transitive_reverse_tu_index: Arc::new(PoolSafeMemo::new()),
            direct_descendant_index: Arc::new(KeyedPoolSafeMemo::new()),
            compile_contexts: Arc::new(OnceLock::new()),
            external_header_closures: Arc::new(KeyedPoolSafeMemo::new()),
            #[cfg(test)]
            type_alias_classification_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            authoritative_visibility_build_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            target_spec_scan_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            cpp_parent_resolution_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            cpp_class_strength_parse_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            visible_type_units_build_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            source_using_index_build_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            using_guard_context_inspection_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            macro_composed_fields_build_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            reconcile_candidate_scan_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            reconcile_candidate_evaluation_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            reconcile_stored_signature_metadata_count: Arc::new(
                std::sync::atomic::AtomicUsize::new(0),
            ),
            #[cfg(test)]
            external_header_closure_build_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(test)]
            external_header_parse_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        };
        analyzer.sync_published_c_reading_workspace();
        analyzer
    }

    fn relational_definition_values(
        &self,
        name: brokk_bifrost_core::analyzer::RelationalName,
        query: crate::analyzer::RelationalDefinitionQuery,
    ) -> Vec<CodeUnit> {
        let request = crate::analyzer::RelationalDefinitionRequest {
            ordinal: 0,
            language_scope: crate::analyzer::DefinitionLanguageScope::Language(Language::Cpp),
            name,
            query,
        };
        match self.relational_definition_batch_for_active_query(&[request]) {
            crate::analyzer::RelationalBatchOutcome::Complete(mut results) => {
                let result = results
                    .pop()
                    .expect("one relational request returns one result");
                let crate::analyzer::RelationalDefinitionValue::Definitions(units) = result.value
                else {
                    panic!("a definition request returned the wrong relational value shape");
                };
                units
            }
            crate::analyzer::RelationalBatchOutcome::Cancelled => Vec::new(),
            crate::analyzer::RelationalBatchOutcome::Failed(error) => {
                self.inner
                    .record_store_error(crate::analyzer::store::StoreError::new(error.message()));
                Vec::new()
            }
        }
    }

    fn relational_definitions_for_rendered_name(&self, fq_name: &str) -> Vec<CodeUnit> {
        let name = brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path_fq(
            Language::Cpp,
            fq_name,
            crate::analyzer::fq_name::segment_interner(),
        );
        if name.is_empty() {
            return Vec::new();
        }
        // Ask the semantic C++ projection first. Exact generated fields are
        // owner-qualified, so this query scopes their overlay to the owner's
        // source files. If the rendered identity needs source-spelling or
        // mounted-name compatibility, only physical declarations can satisfy
        // it: generated fields have no separate persisted identity to hydrate.
        // Route that compatibility fallback through the inner analyzer so a
        // missing rendered name cannot materialize every macro field overlay
        // in the workspace (#3059).
        let mut units = self.relational_definition_values(
            brokk_bifrost_core::analyzer::RelationalName::stable(name),
            crate::analyzer::RelationalDefinitionQuery::ExactName,
        );
        units.retain(|unit| unit.fq_name() == fq_name);
        if units.is_empty() {
            units = crate::analyzer::AnalyzerDefinitionLookup::new(&self.inner, Language::Cpp)
                .fqn(fq_name);
        }
        let reconciled = self.reconciled_definitions(fq_name);
        let mut candidates = units
            .into_iter()
            .map(|unit| {
                let physical = reconciled
                    .provisional_of
                    .get(&unit)
                    .cloned()
                    .unwrap_or_else(|| unit.clone());
                (unit, physical)
            })
            .collect::<Vec<_>>();
        self.inner
            .sort_definition_units_by_physical_identity(&mut candidates);
        candidates
            .into_iter()
            .map(|(published, _)| published)
            .collect()
    }

    fn relational_definitions_for_identifier(&self, identifier: &str) -> Vec<CodeUnit> {
        if identifier.is_empty() {
            return Vec::new();
        }
        let mut name = crate::analyzer::FqName::new();
        name.push(
            crate::analyzer::fq_name::segment_interner()
                .intern(identifier, crate::analyzer::fq_name::SegmentKind::Unknown),
        );
        self.relational_definition_values(
            brokk_bifrost_core::analyzer::RelationalName::stable(name),
            crate::analyzer::RelationalDefinitionQuery::Identifier { file: None },
        )
    }

    /// Whether the persisted declaration index contains a class-like unit with
    /// this source identifier. Macro-composed overlays only add fields, so a
    /// caller asking specifically about a possible type must not materialize
    /// those overlays through the general identifier lookup.
    #[doc(hidden)]
    pub fn has_indexed_class_identifier(&self, identifier: &str) -> bool {
        self.inner
            .lookup_candidates_by_identifier(identifier)
            .iter()
            .any(CodeUnit::is_class)
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }
}

impl CppAnalyzer {
    pub(crate) fn import_statements_from_projection(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Vec<String> {
        self.inner
            .import_info_of(token, file)
            .into_iter()
            .map(|import| import.raw_snippet)
            .collect()
    }

    pub(crate) fn compile_contexts_for(&self, file: &ProjectFile) -> &[CppCompileContext] {
        self.compile_contexts
            .get_or_init(|| CppCompileContexts::load(self.inner.project()))
            .contexts_for(file)
    }

    pub(crate) fn resolve_external_angle_include(
        &self,
        file: &ProjectFile,
        include: &std::path::Path,
    ) -> brokk_bifrost_cpp::compile_context::CppExternalIncludeResolution {
        self.compile_contexts
            .get_or_init(|| CppCompileContexts::load(self.inner.project()))
            .resolve_external_angle_include(file, include)
    }

    pub(crate) fn prepared_syntax(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Option<Arc<crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree>> {
        let prepared = self.inner.prepared_syntax(token, file);
        if prepared.is_none() {
            self.inner.record_query_incomplete(
                crate::analyzer::QueryReadIncomplete::StructureUnavailable(file.clone()),
            );
        }
        prepared
    }

    /// Drop the files whose C++ syntax cannot spell a reference to the member
    /// named `member`.
    ///
    /// Admission evidence only: a file this keeps still has to prove each of
    /// its sites through the ordinary scan. What it removes is exact -- the
    /// member scans compare the terminal name of a syntax node against the
    /// member name before anything else, so a file that never spells it
    /// produces neither a proven nor an unproven hit
    /// ([`cpp_syntax_may_spell_member`]).
    ///
    /// A file whose syntax cannot be prepared, and every file at all once the
    /// deadline expires, stays in: the narrowing must never turn a read
    /// failure or a timeout into a missing candidate.
    pub(crate) fn files_spelling_member(
        &self,
        analyzer: &dyn IAnalyzer,
        files: HashSet<ProjectFile>,
        member: &str,
        cancellation: Option<&crate::cancellation::CancellationToken>,
    ) -> HashSet<ProjectFile> {
        // The walks below reach prepared syntax, so this narrowing owns a
        // request scope; nested inside the caller's it shares that scope's
        // memoization rather than reparsing (issue #2414 step 3).
        let scope = AnalyzerQueryScope::new(analyzer);
        let token = scope.token();
        files
            .into_iter()
            .collect::<Vec<_>>()
            .into_par_iter()
            .filter(|file| {
                if cancellation.is_some_and(crate::cancellation::CancellationToken::is_cancelled) {
                    return true;
                }
                match self.prepared_syntax(token, file) {
                    Some(prepared) => cpp_syntax_may_spell_member(
                        prepared.tree().root_node(),
                        prepared.source(),
                        member,
                    ),
                    None => true,
                }
            })
            .collect()
    }

    pub(crate) fn active_query_cancellation(&self) -> Option<crate::CancellationToken> {
        self.inner.active_query_cancellation()
    }

    fn external_header_closure_cell(
        &self,
        file: &ProjectFile,
    ) -> Arc<PoolSafeMemo<external::ReachedExternalHeaders>> {
        self.external_header_closures.cell(file)
    }

    fn record_external_header_closure_build(&self) {
        #[cfg(test)]
        self.external_header_closure_build_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn record_external_header_parse(&self) {
        #[cfg(test)]
        self.external_header_parse_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn external_header_closure_work_counts_for_test(
        &self,
    ) -> ExternalHeaderClosureWorkCounts {
        ExternalHeaderClosureWorkCounts {
            builds: self
                .external_header_closure_build_count
                .load(std::sync::atomic::Ordering::Relaxed),
            external_header_parses: self
                .external_header_parse_count
                .load(std::sync::atomic::Ordering::Relaxed),
        }
    }

    pub(crate) fn prepared_syntax_limited_cancellable(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
        max_source_bytes: usize,
        cancellation: Option<&crate::cancellation::CancellationToken>,
    ) -> crate::analyzer::tree_sitter_analyzer::PreparedSyntaxLimitedOutcome {
        self.inner
            .prepared_syntax_limited_cancellable(token, file, max_source_bytes, cancellation)
    }

    pub(crate) fn bulk_file_states_for_query(&self, files: impl IntoIterator<Item = ProjectFile>) {
        self.inner
            .bulk_file_states_for_query(files, BulkFileStateSource::Include);
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

    pub(crate) fn signature_metadata_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<SignatureMetadata> {
        self.inner.signature_metadata_limited(code_unit, limit)
    }

    pub(crate) fn signatures_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<String> {
        self.inner.signatures_limited(code_unit, limit)
    }

    pub(crate) fn ranges_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<Range> {
        self.inner.ranges_limited(code_unit, limit)
    }

    /// See [`TreeSitterAnalyzer::claim_import_hydration_count_for_test`]. C++
    /// is the one adapter that claims included files, so this is where the
    /// #1865 locality pin reads it.
    #[doc(hidden)]
    pub fn claim_import_hydration_count_for_test(&self) -> usize {
        self.inner.claim_import_hydration_count_for_test()
    }

    #[cfg(test)]
    pub(crate) fn reset_full_hydration_count_for_test(&self) {
        self.inner.reset_full_hydration_count_for_test();
    }

    #[cfg(test)]
    pub(crate) fn full_hydration_count_for_test(&self) -> usize {
        self.inner.full_hydration_count_for_test()
    }

    pub fn structural_parent_of(
        &self,
        token: QueryToken<'_>,
        code_unit: &CodeUnit,
    ) -> Option<CodeUnit> {
        self.inner
            .structural_parent_of(code_unit)
            // #1970: a unit only the C reading of a header mints has no `cpp`
            // rows, so its owner edge lives in that reading.
            .or_else(|| self.c_reading_parent(token, code_unit))
            .or_else(|| self.generated_field_owner(code_unit))
    }

    pub(crate) fn template_metadata(
        &self,
        code_unit: &CodeUnit,
    ) -> Option<crate::analyzer::CppTemplateMetadata> {
        self.inner.cpp_template_metadata_of(code_unit)
    }

    #[doc(hidden)]
    pub fn prepared_syntax_parse_count_for_test(&self, file: &ProjectFile) -> usize {
        self.inner.prepared_syntax_parse_count_for_test(file)
    }

    #[doc(hidden)]
    pub fn reset_prepared_syntax_parse_counts_for_test(&self) {
        self.inner.reset_prepared_syntax_parse_counts_for_test();
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn reset_macro_composed_fields_build_count_for_test(&self) {
        self.macro_composed_fields_build_count
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn macro_composed_fields_build_count_for_test(&self) -> usize {
        self.macro_composed_fields_build_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn unconditional_include_reachability_cache_len_for_test(&self) -> u64 {
        self.unconditional_include_reachability.run_pending_tasks();
        self.unconditional_include_reachability.entry_count()
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn record_authoritative_visibility_build_for_test(&self) {
        self.authoritative_visibility_build_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn reset_authoritative_visibility_build_count_for_test(&self) {
        self.authoritative_visibility_build_count
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn authoritative_visibility_build_count_for_test(&self) -> usize {
        self.authoritative_visibility_build_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn record_target_spec_scan_for_test(&self) {
        self.target_spec_scan_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn reset_target_spec_scan_count_for_test(&self) {
        self.target_spec_scan_count
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn target_spec_scan_count_for_test(&self) -> usize {
        self.target_spec_scan_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn record_cpp_parent_resolution_for_test(&self) {
        self.cpp_parent_resolution_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn record_cpp_class_strength_parse_for_test(&self) {
        self.cpp_class_strength_parse_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn reset_cpp_owner_resolution_counts_for_test(&self) {
        self.cpp_parent_resolution_count
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.cpp_class_strength_parse_count
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn cpp_parent_resolution_count_for_test(&self) -> usize {
        self.cpp_parent_resolution_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn record_visible_type_units_build_for_test(&self) {
        self.visible_type_units_build_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn reset_visible_type_units_build_count_for_test(&self) {
        self.visible_type_units_build_count
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn visible_type_units_build_count_for_test(&self) -> usize {
        self.visible_type_units_build_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Per-file structured using-index builds; a cache hit does not count
    /// (#1927).
    #[cfg(any(test, feature = "test-support"))]
    pub fn source_using_index_build_count_for_test(&self) -> usize {
        self.source_using_index_build_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Guard-ancestry inspections performed inside per-file using-index
    /// builds. Only structured using declarations may inspect guard ancestry;
    /// a rebuild-free query keeps this constant (#1927).
    #[cfg(any(test, feature = "test-support"))]
    pub fn using_guard_context_inspection_count_for_test(&self) -> usize {
        self.using_guard_context_inspection_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// #1908: reset both reconcile counters together. They are two halves of
    /// one measurement -- scans and the candidates those scans fed -- and a
    /// test that reset one and read the other would report a ratio it never
    /// measured.
    #[cfg(any(test, feature = "test-support"))]
    pub fn reset_reconcile_counts_for_test(&self) {
        self.reconcile_candidate_scan_count
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.reconcile_candidate_evaluation_count
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.reconcile_stored_signature_metadata_count
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    /// Identifier-index scans issued for reconciliation.
    #[cfg(any(test, feature = "test-support"))]
    pub fn reconcile_candidate_scan_count_for_test(&self) -> usize {
        self.reconcile_candidate_scan_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Candidates reconcile groups examined.
    #[cfg(any(test, feature = "test-support"))]
    pub fn reconcile_candidate_evaluation_count_for_test(&self) -> usize {
        self.reconcile_candidate_evaluation_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Raw, overlay-free signature reads performed while building reconcile groups.
    #[cfg(any(test, feature = "test-support"))]
    pub fn reconcile_stored_signature_metadata_count_for_test(&self) -> usize {
        self.reconcile_stored_signature_metadata_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn cpp_class_strength_parse_count_for_test(&self) -> usize {
        self.cpp_class_strength_parse_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[doc(hidden)]
    pub fn reset_enclosing_parent_query_counts_for_test(&self) {
        self.inner.reset_enclosing_parent_query_counts_for_test();
    }

    #[doc(hidden)]
    pub fn enclosing_code_unit_query_count_for_test(&self) -> usize {
        self.inner.enclosing_code_unit_query_count_for_test()
    }

    #[doc(hidden)]
    pub fn sql_definitions_query_count_for_test(&self) -> usize {
        self.inner.sql_definitions_query_count_for_test()
    }

    #[cfg(test)]
    pub(crate) fn reset_live_oid_validation_counts_for_test(&self) {
        self.inner.reset_live_oid_validation_counts_for_test();
    }

    #[cfg(test)]
    pub(crate) fn live_oid_validation_count_for_test(&self, file: &ProjectFile) -> usize {
        self.inner.live_oid_validation_count_for_test(file)
    }

    #[cfg(test)]
    pub(crate) fn reset_type_alias_classification_count_for_test(&self) {
        self.type_alias_classification_count
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn type_alias_classification_count_for_test(&self) -> usize {
        self.type_alias_classification_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

use crate::analyzer::CodeUnitIndex;

/// The memoized C++ products [`brokk_bifrost_cpp`]'s free functions resolve
/// through. Every method answers from an accessor `CppAnalyzer` already had, so
/// the five caches, two `OnceLock`s and two `PoolSafeMemo`s stay here and no
/// function on the other side of the crate line can reach past this surface.
impl CppSource for CppAnalyzer {
    fn visibility_import_statements(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Vec<String> {
        let _streaming = crate::analyzer::AnalyzerStreamingFileScope::new(self, file);
        self.import_statements_from_projection(token, file)
    }

    fn visibility_identifier_candidates(&self, identifier: &str) -> BTreeSet<CodeUnit> {
        // This lookup discovers include-visible source files; generated macro
        // fields cannot introduce one. Their owning aggregate's stored type
        // declaration selects the same source, whose declaration read then
        // materializes its macro fields. Enumerating generated fields here
        // would build them for every file in the workspace before the bounded
        // include filter can discard unrelated sources (#3024).
        self.inner.lookup_candidates_by_identifier(identifier)
    }

    fn visibility_identifier_candidates_batch(
        &self,
        identifiers: &HashSet<String>,
        cancellation: Option<&crate::CancellationToken>,
    ) -> HashMap<String, BTreeSet<CodeUnit>> {
        self.inner
            .lookup_declarations_by_identifiers(identifiers, cancellation)
    }

    fn stored_callable_unit_role(&self, callable: &CodeUnit) -> CppCallableUnitRole {
        #[cfg(any(test, feature = "test-support"))]
        self.reconcile_stored_signature_metadata_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        cpp_callable_unit_role(&self.inner, callable)
    }

    fn include_target_index(&self) -> &IncludeTargetIndex {
        CppAnalyzer::include_target_index(self)
    }

    fn raw_supertypes_of(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.inner.raw_supertypes_of(code_unit)
    }

    fn visible_type_units(&self, file: &ProjectFile) -> Arc<Vec<CodeUnit>> {
        CppAnalyzer::visible_type_units(self, file)
    }

    fn visible_type_units_while(
        &self,
        file: &ProjectFile,
        keep_going: &dyn Fn() -> bool,
    ) -> Option<Arc<Vec<CodeUnit>>> {
        CppAnalyzer::visible_type_units_while(self, file, keep_going)
    }

    fn source_using_index(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Arc<SourceUsingIndex> {
        self.cached_complete_read(&self.source_using_index_by_file, file, || {
            #[cfg(any(test, feature = "test-support"))]
            self.source_using_index_build_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            build_source_using_index(self, token, file)
        })
    }

    fn file_source(&self, file: &ProjectFile) -> Option<String> {
        let source = self.inner.file_source(file);
        if source.is_none() {
            self.record_query_incomplete(
                crate::analyzer::QueryReadIncomplete::StructureUnavailable(file.clone()),
            );
        }
        source
    }

    fn prepared_syntax(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Option<Arc<crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree>> {
        CppAnalyzer::prepared_syntax(self, token, file)
    }

    fn cpp_field_linkage(&self, code_unit: &CodeUnit) -> Option<CppFieldLinkage> {
        if !code_unit.is_field() {
            return None;
        }
        let metadata = CppAnalyzer::signature_metadata_limited(self, code_unit, 2);
        metadata
            .complete
            .then_some(metadata.rows)
            .into_iter()
            .flatten()
            .find_map(|metadata| metadata.cpp_field_linkage())
    }

    fn cached_unconditional_include_reachability(
        &self,
        first: &ProjectFile,
        donor_source: &ProjectFile,
        reference_is_c: bool,
    ) -> Option<bool> {
        self.unconditional_include_reachability.get(&(
            first.clone(),
            donor_source.clone(),
            reference_is_c,
        ))
    }

    fn cache_unconditional_include_reachability(
        &self,
        first: &ProjectFile,
        donor_source: &ProjectFile,
        reference_is_c: bool,
        reaches: bool,
    ) {
        let scope = AnalyzerQueryScope::new(self);
        if scope.read_completion().is_err() {
            return;
        }

        self.unconditional_include_reachability.insert(
            (first.clone(), donor_source.clone(), reference_is_c),
            reaches,
        );
    }

    fn recovered_export_class_index(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Arc<CppRecoveredExportClassIndex> {
        self.cached_complete_read(&self.recovered_export_class_index_by_file, file, || {
            let Some(prepared) = self.prepared_syntax(token, file) else {
                return CppRecoveredExportClassIndex::default();
            };
            CppRecoveredExportClassIndex::build(prepared.tree().root_node(), prepared.source())
        })
    }

    fn orphaned_namespace_scopes(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Arc<OrphanedNamespaceScopeIndex> {
        self.cached_complete_read(&self.orphaned_namespace_scopes_by_file, file, || {
            let Some(prepared) = self.prepared_syntax(token, file) else {
                return OrphanedNamespaceScopeIndex::default();
            };
            OrphanedNamespaceScopeIndex::build(prepared.tree().root_node(), prepared.source())
        })
    }

    fn cached_class_declaration_strength(
        &self,
        candidate: &CodeUnit,
    ) -> Option<CppClassDeclarationStrength> {
        self.class_declaration_strength.get(candidate)
    }

    fn cache_class_declaration_strength(
        &self,
        candidate: &CodeUnit,
        strength: CppClassDeclarationStrength,
    ) {
        let scope = AnalyzerQueryScope::new(self);
        if scope.read_completion().is_err() {
            return;
        }

        self.class_declaration_strength
            .insert(candidate.clone(), strength);
    }

    fn structural_parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        CppAnalyzer::structural_parent_of(self, token, code_unit)
    }

    fn template_metadata(
        &self,
        code_unit: &CodeUnit,
    ) -> Option<crate::analyzer::CppTemplateMetadata> {
        CppAnalyzer::template_metadata(self, code_unit)
    }

    fn compile_contexts_for(&self, file: &ProjectFile) -> &[CppCompileContext] {
        CppAnalyzer::compile_contexts_for(self, file)
    }

    /// Ascending by path, which the index's ordinal contract already
    /// guarantees: ordinals are positions in a sorted unit list.
    fn reaching_translation_units(&self, file: &ProjectFile) -> Vec<ProjectFile> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        self.transitive_reaching_translation_units(token, file)
    }

    fn header_uses_c_semantics(&self, file: &ProjectFile) -> bool {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        CppAnalyzer::header_uses_c_semantics(self, token, file)
    }

    fn declarations_in_reading(&self, file: &ProjectFile, c_semantics: bool) -> BTreeSet<CodeUnit> {
        CppAnalyzer::declarations_in_reading(self, file, c_semantics)
    }

    fn site_equivalent_units(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        CppAnalyzer::site_equivalent_units(self, token, code_unit)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn record_cpp_parent_resolution_for_test(&self) {
        CppAnalyzer::record_cpp_parent_resolution_for_test(self);
    }

    #[cfg(any(test, feature = "test-support"))]
    fn record_cpp_class_strength_parse_for_test(&self) {
        CppAnalyzer::record_cpp_class_strength_parse_for_test(self);
    }

    #[cfg(any(test, feature = "test-support"))]
    fn record_using_guard_context_inspection_for_test(&self) {
        self.using_guard_context_inspection_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// The C++ analyzer standing in for the dispatching analyzer.
///
/// Four resolution paths in the graph reach the workspace through the C++
/// analyzer they already hold rather than through the analyzer the query was
/// issued against; before the extraction they passed `&CppAnalyzer` straight
/// into a `&dyn IAnalyzer` parameter, so these three forwarders answer exactly
/// what that coercion did.
impl CppWorkspaceSource for CppAnalyzer {
    fn import_statements(&self, file: &ProjectFile) -> Vec<String> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        self.import_statements_from_projection(token, file)
    }

    fn definitions_by_name(
        &self,
        _token: QueryToken<'_>,
        name: &brokk_bifrost_core::analyzer::fq_name::FqName,
    ) -> Vec<CodeUnit> {
        crate::analyzer::usages::cpp_graph::relational_exact_definitions(self, name)
    }

    fn definitions_by_identifier(
        &self,
        _token: QueryToken<'_>,
        name: &brokk_bifrost_core::analyzer::fq_name::FqName,
    ) -> Vec<CodeUnit> {
        crate::analyzer::usages::cpp_graph::relational_identifier_definitions(self, name)
    }
}

impl CodeUnitIndex for CppAnalyzer {
    /// Forwarded so the request-scoped memo on the inner analyzer answers
    /// (#2679); the trait default would rebuild uncached per call.
    fn class_range_index(
        &self,
        file: &ProjectFile,
    ) -> std::sync::Arc<brokk_bifrost_core::analyzer::usages::inverted_edges::ClassRangeIndex> {
        self.inner.class_range_index(file)
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

    fn retain_analyzed(&self, candidates: &[ProjectFile]) -> Vec<ProjectFile> {
        self.inner.retain_analyzed(candidates)
    }

    /// #1970: the relational workspace snapshot mounts a header's published C
    /// reading under `cpp:c`, so the generic declaration scan returns both
    /// identities of one declaration site without a Rust-side workspace map.
    fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        let mut declarations = self.inner.all_declarations().collect::<Vec<_>>();
        declarations.extend(
            self.all_macro_composed_fields()
                .iter()
                .map(|field| field.unit.clone()),
        );
        declarations.sort();
        declarations.dedup();
        Box::new(declarations.into_iter())
    }

    fn declarations_sharing_name(&self, unit: &CodeUnit) -> Vec<CodeUnit> {
        let mut declarations = self.inner.declarations_sharing_name(unit);
        declarations.extend(
            self.all_macro_composed_fields()
                .iter()
                .filter(|field| field.unit.identifier() == unit.identifier())
                .map(|field| field.unit.clone()),
        );
        declarations.sort();
        declarations.dedup();
        declarations
    }

    fn declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        let mut declarations = self.inner.declarations(file);
        declarations.extend(
            self.macro_composed_fields(file)
                .iter()
                .map(|field| field.unit.clone()),
        );
        declarations
    }

    fn materialization_records(
        &self,
        file: &ProjectFile,
    ) -> Vec<crate::analyzer::structural::materialization::MaterializationRecord> {
        self.inner.materialization_records(file)
    }

    fn definitions(&self, fq_name: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        let _scope = crate::profiling::scope(format!("cpp.definitions[{fq_name}]"));
        Box::new(
            self.relational_definitions_for_rendered_name(fq_name)
                .into_iter(),
        )
    }

    fn definitions_by_structured_name(
        &self,
        fq_name: &brokk_bifrost_core::analyzer::fq_name::FqName,
        language: Language,
    ) -> Vec<CodeUnit> {
        debug_assert_eq!(language, Language::Cpp);
        self.relational_definition_values(
            brokk_bifrost_core::analyzer::RelationalName::stable(fq_name.clone()),
            crate::analyzer::RelationalDefinitionQuery::ExactName,
        )
    }

    fn direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        let children = self.inner.direct_children(code_unit);
        let mut children = children;
        children.extend(self.macro_composed_fields_for_owner(code_unit));
        children.sort();
        children.dedup();
        if !children.is_empty() {
            return children;
        }
        // #1970: a unit only the C reading of a header mints has no `cpp` rows
        // at all, so the store cannot answer for it.
        self.c_reading_children(token, code_unit)
            .unwrap_or(children)
    }

    fn ranges(&self, code_unit: &CodeUnit) -> Vec<crate::analyzer::Range> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        let ranges = self.inner.ranges(code_unit);
        if !ranges.is_empty() {
            return ranges;
        }
        if let Some(generated) = self
            .macro_composed_fields(code_unit.source())
            .iter()
            .find(|candidate| candidate.unit == *code_unit)
        {
            return generated.ranges.clone();
        }
        // #1134: a re-keyed reconciled definition (canonical identity, real
        // `.cpp` source) is not itself in the store; its ranges live under the
        // provisional identity extraction assigned it.
        if let Some(provisional) = self
            .reconciled_definitions(&code_unit.fq_name())
            .provisional_of
            .get(code_unit)
        {
            return self.inner.ranges(provisional);
        }
        // #1970: likewise for a unit only the C reading of a header mints.
        self.c_reading_ranges(token, code_unit).unwrap_or(ranges)
    }

    fn ranges_with_limit(
        &self,
        code_unit: &CodeUnit,
        max_ranges: usize,
        cancellation: &crate::CancellationToken,
    ) -> (Vec<crate::analyzer::Range>, usize, bool) {
        if let Some(field) = self
            .macro_composed_fields(code_unit.source())
            .iter()
            .find(|candidate| candidate.unit == *code_unit)
        {
            let total = field.ranges.len();
            let returned = field.ranges.iter().take(max_ranges).cloned().collect();
            return (
                returned,
                total,
                total <= max_ranges && !cancellation.is_cancelled(),
            );
        }
        self.inner
            .ranges_with_limit(code_unit, max_ranges, cancellation)
    }

    fn signatures(&self, code_unit: &CodeUnit) -> Vec<String> {
        let signatures = self.inner.signatures(code_unit);
        if !signatures.is_empty() {
            return signatures;
        }
        code_unit
            .signature()
            .map(str::to_string)
            .into_iter()
            .collect()
    }

    fn signature_metadata(&self, code_unit: &CodeUnit) -> Vec<SignatureMetadata> {
        let metadata = self.inner.signature_metadata(code_unit);
        if !metadata.is_empty() {
            return metadata;
        }
        // #1134: a re-keyed reconciled definition carries the same signature
        // metadata as the provisional definition it stands in for, so its
        // callable role (`Definition`) and external linkage are visible to the
        // decl/def unification evidence -- otherwise the header declaration and
        // the `.cpp` definition are misread as an ambiguous cross-file duplicate.
        // Stored units always return non-empty here, so this never re-enters the
        // lazily-built index during its own construction.
        if let Some(provisional) = self
            .reconciled_definitions(&code_unit.fq_name())
            .provisional_of
            .get(code_unit)
        {
            return self.inner.signature_metadata(provisional);
        }
        metadata
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

    /// See [`CodeUnitIndex::all_declarations`] above: both identities of a
    /// C-attributed header's declaration site are listed (#1970).
    fn get_all_declarations(&self) -> Vec<CodeUnit> {
        self.all_declarations().collect()
    }

    fn get_definitions(&self, fq_name: &str) -> Vec<CodeUnit> {
        self.definitions(fq_name).collect()
    }

    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        self.inner.get_skeleton(code_unit)
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        self.inner.get_skeleton_header(code_unit)
    }

    fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String> {
        if let Some(field) = self
            .macro_composed_fields(code_unit.source())
            .iter()
            .find(|candidate| candidate.unit == *code_unit)
        {
            let source = self.inner.file_source(code_unit.source())?;
            let range = field.ranges.first()?;
            return source
                .get(range.start_byte..range.end_byte)
                .map(str::to_string);
        }
        self.inner.get_source(code_unit, include_comments)
    }

    fn get_sources(&self, code_unit: &CodeUnit, include_comments: bool) -> BTreeSet<String> {
        if let Some(source) = self.get_source(code_unit, include_comments) {
            return std::iter::once(source).collect();
        }
        self.inner.get_sources(code_unit, include_comments)
    }

    fn search_definitions(&self, pattern: &str, auto_quote: bool) -> BTreeSet<CodeUnit> {
        let mut definitions = self.inner.search_definitions(pattern, auto_quote);
        definitions.extend(
            self.all_macro_composed_fields()
                .iter()
                .filter(|field| field.unit.fq_name() == pattern)
                .map(|field| field.unit.clone()),
        );
        definitions
    }

    fn search_definitions_by_suffix_pattern(
        &self,
        pattern: &str,
        terminal_identifiers: &[String],
        language: Language,
    ) -> BTreeSet<CodeUnit> {
        let mut definitions = self.inner.search_definitions_by_suffix_pattern(
            pattern,
            terminal_identifiers,
            language,
        );
        definitions.extend(
            self.all_macro_composed_fields()
                .iter()
                .filter(|field| {
                    terminal_identifiers
                        .iter()
                        .any(|identifier| field.unit.identifier() == identifier)
                        && field.unit.fq_name().ends_with(pattern)
                })
                .map(|field| field.unit.clone()),
        );
        definitions
    }

    fn lookup_candidates_by_short_name(&self, symbol: &str) -> BTreeSet<CodeUnit> {
        let mut candidates = self.inner.lookup_candidates_by_short_name(symbol);
        candidates.extend(
            self.all_macro_composed_fields()
                .iter()
                .filter(|field| field.unit.short_name() == symbol || field.unit.fq_name() == symbol)
                .map(|field| field.unit.clone()),
        );
        candidates
    }

    fn has_complete_symbol_lookup_index(&self) -> bool {
        self.inner.has_complete_symbol_lookup_index()
    }

    fn lookup_candidates_by_identifier(&self, identifier: &str) -> BTreeSet<CodeUnit> {
        self.relational_definitions_for_identifier(identifier)
            .into_iter()
            .collect()
    }
}

impl IAnalyzer for CppAnalyzer {
    fn active_query_cancellation(&self) -> Option<crate::CancellationToken> {
        self.inner.active_query_cancellation()
    }

    fn active_query_semantic_model_overlay(
        &self,
    ) -> Option<Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>> {
        self.inner.active_query_semantic_model_overlay()
    }

    fn active_query_semantic_model_snapshot(
        &self,
    ) -> Option<Option<Arc<crate::analyzer::semantic_model::ActiveSemanticModelSnapshot>>> {
        self.inner.active_query_semantic_model_snapshot()
    }

    fn begin_streaming_file_read(&self, file: &ProjectFile) {
        self.inner.begin_streaming_file_read(file);
    }

    fn end_streaming_file_read(&self, file: &ProjectFile) {
        self.inner.end_streaming_file_read(file);
    }

    fn relational_definition_batch(
        &self,
        requests: &[crate::analyzer::RelationalDefinitionRequest],
        cancellation: &crate::CancellationToken,
    ) -> crate::analyzer::RelationalBatchOutcome {
        let outcome =
            crate::analyzer::RelationalDefinitionLookup::batch(&self.inner, requests, cancellation);
        let crate::analyzer::RelationalBatchOutcome::Complete(mut results) = outcome else {
            return outcome;
        };
        assert_eq!(results.len(), requests.len());

        let mut macro_owner_names = requests
            .iter()
            .filter(|request| {
                !matches!(
                    request.query,
                    crate::analyzer::RelationalDefinitionQuery::NormalizedName
                )
            })
            .filter(|request| {
                matches!(
                    request.language_scope,
                    crate::analyzer::DefinitionLanguageScope::Workspace
                        | crate::analyzer::DefinitionLanguageScope::Language(Language::Cpp)
                )
            })
            .filter_map(Self::macro_composed_field_owner_name)
            .collect::<Vec<_>>();
        let mut seen_macro_owner_names = HashSet::default();
        macro_owner_names.retain(|name| seen_macro_owner_names.insert(name.clone()));
        let mut macro_owner_files: HashMap<
            brokk_bifrost_core::analyzer::RelationalName,
            Vec<ProjectFile>,
        > = HashMap::default();
        if !macro_owner_names.is_empty() {
            let owner_requests = macro_owner_names
                .iter()
                .enumerate()
                .map(
                    |(ordinal, owner_name)| crate::analyzer::RelationalDefinitionRequest {
                        ordinal,
                        language_scope: crate::analyzer::DefinitionLanguageScope::Language(
                            Language::Cpp,
                        ),
                        name: owner_name.clone(),
                        query: crate::analyzer::RelationalDefinitionQuery::ExactName,
                    },
                )
                .collect::<Vec<_>>();
            let owner_results = match crate::analyzer::RelationalDefinitionLookup::batch(
                &self.inner,
                &owner_requests,
                cancellation,
            ) {
                crate::analyzer::RelationalBatchOutcome::Complete(results) => results,
                crate::analyzer::RelationalBatchOutcome::Cancelled => {
                    return crate::analyzer::RelationalBatchOutcome::Cancelled;
                }
                crate::analyzer::RelationalBatchOutcome::Failed(error) => {
                    return crate::analyzer::RelationalBatchOutcome::Failed(error);
                }
            };
            assert_eq!(owner_results.len(), owner_requests.len());
            for result in owner_results {
                let owner_name = macro_owner_names
                    .get(result.ordinal)
                    .expect("a macro-field owner query returned an unknown ordinal")
                    .clone();
                let crate::analyzer::RelationalDefinitionValue::Definitions(owners) = result.value
                else {
                    panic!("a macro-field owner query returned the wrong value shape");
                };
                let mut owner_files = owners
                    .into_iter()
                    .filter(CodeUnit::is_class)
                    .map(|owner| owner.source().clone())
                    .collect::<Vec<_>>();
                owner_files.sort();
                owner_files.dedup();
                assert!(
                    macro_owner_files.insert(owner_name, owner_files).is_none(),
                    "a macro-field owner query returned one ordinal twice"
                );
            }
        }

        for (request, result) in requests.iter().zip(&mut results) {
            if cancellation.is_cancelled() {
                return crate::analyzer::RelationalBatchOutcome::Cancelled;
            }
            if !matches!(
                request.language_scope,
                crate::analyzer::DefinitionLanguageScope::Workspace
                    | crate::analyzer::DefinitionLanguageScope::Language(Language::Cpp)
            ) {
                continue;
            }

            match &mut result.value {
                crate::analyzer::RelationalDefinitionValue::Definitions(units) => {
                    let additions = units
                        .iter()
                        .flat_map(|unit| {
                            self.reconciled_definitions_with_cancellation(
                                &unit.fq_name(),
                                Some(cancellation),
                            )
                            .rekeyed
                            .clone()
                        })
                        .filter(|unit| self.inner.unit_matches_relational_request(unit, request))
                        .collect::<Vec<_>>();
                    units.extend(additions);
                    let macro_fields_can_match = match &request.query {
                        crate::analyzer::RelationalDefinitionQuery::ExactName
                        | crate::analyzer::RelationalDefinitionQuery::NormalizedName
                        | crate::analyzer::RelationalDefinitionQuery::StructuralChildren
                        | crate::analyzer::RelationalDefinitionQuery::StructuralMembers {
                            ..
                        }
                        | crate::analyzer::RelationalDefinitionQuery::VisibleMembers { .. } => {
                            Self::macro_composed_field_owner_name(request).is_some()
                        }
                        crate::analyzer::RelationalDefinitionQuery::Identifier { .. }
                        | crate::analyzer::RelationalDefinitionQuery::IdentifierPrefix { .. } => {
                            true
                        }
                        _ => false,
                    };
                    if !macro_fields_can_match {
                        units.sort();
                        units.dedup();
                        continue;
                    }
                    let macro_composed_fields = match &request.query {
                        crate::analyzer::RelationalDefinitionQuery::NormalizedName => {
                            let owner_name = request
                                .name
                                .parent()
                                .expect("a multi-segment normalized name has an owner");
                            match self.macro_composed_fields_for_owner_name(
                                owner_name,
                                crate::analyzer::RelationalDefinitionQuery::NormalizedName,
                                cancellation,
                            ) {
                                Ok(fields) => fields,
                                Err(outcome) => return outcome,
                            }
                        }
                        crate::analyzer::RelationalDefinitionQuery::Identifier {
                            file: Some(file),
                        }
                        | crate::analyzer::RelationalDefinitionQuery::IdentifierPrefix {
                            file: Some(file),
                        } => {
                            if cancellation.is_cancelled() {
                                return crate::analyzer::RelationalBatchOutcome::Cancelled;
                            }
                            self.macro_composed_fields(file).as_ref().clone()
                        }
                        crate::analyzer::RelationalDefinitionQuery::ExactName
                        | crate::analyzer::RelationalDefinitionQuery::StructuralChildren
                        | crate::analyzer::RelationalDefinitionQuery::StructuralMembers {
                            ..
                        }
                        | crate::analyzer::RelationalDefinitionQuery::VisibleMembers { .. } => {
                            let owner_name = Self::macro_composed_field_owner_name(request)
                                .expect("a macro-field-capable structured query has an owner name");
                            let owner_files = macro_owner_files
                                .get(&owner_name)
                                .expect("every macro-field owner has one batched query result");
                            let mut fields = Vec::new();
                            for file in owner_files {
                                if cancellation.is_cancelled() {
                                    return crate::analyzer::RelationalBatchOutcome::Cancelled;
                                }
                                fields.extend(self.macro_composed_fields(file).iter().cloned());
                            }
                            fields
                        }
                        _ => {
                            let Some(fields) = self.all_macro_composed_fields_while(cancellation)
                            else {
                                return crate::analyzer::RelationalBatchOutcome::Cancelled;
                            };
                            fields
                        }
                    };
                    units.extend(
                        macro_composed_fields
                            .iter()
                            .filter(|field| {
                                self.inner
                                    .unit_matches_relational_request(&field.unit, request)
                            })
                            .map(|field| field.unit.clone()),
                    );
                    units.sort();
                    units.dedup();
                }
                crate::analyzer::RelationalDefinitionValue::CallableFacts(facts) => {
                    let mut declaration_names = facts
                        .iter()
                        .map(|fact| fact.declaration.fq_name())
                        .collect::<Vec<_>>();
                    declaration_names.push(
                        request
                            .name
                            .full_name()
                            .display(crate::analyzer::fq_name::segment_interner()),
                    );
                    declaration_names.sort();
                    declaration_names.dedup();
                    let mut additions = Vec::new();
                    for declaration_name in declaration_names {
                        let reconciled = self.reconciled_definitions_with_cancellation(
                            &declaration_name,
                            Some(cancellation),
                        );
                        for rekeyed in &reconciled.rekeyed {
                            if !self.inner.unit_matches_relational_request(rekeyed, request) {
                                continue;
                            }
                            let provisional = reconciled.provisional_of.get(rekeyed).expect(
                                "every reconciled definition records its provisional identity",
                            );
                            let fact_request = crate::analyzer::RelationalDefinitionRequest {
                                ordinal: 0,
                                language_scope: crate::analyzer::DefinitionLanguageScope::Language(
                                    Language::Cpp,
                                ),
                                name: brokk_bifrost_core::analyzer::RelationalName::stable(
                                    provisional.fq().clone(),
                                ),
                                query: crate::analyzer::RelationalDefinitionQuery::CallableFacts,
                            };
                            let mut physical_results =
                                match crate::analyzer::RelationalDefinitionLookup::batch(
                                    &self.inner,
                                    &[fact_request],
                                    cancellation,
                                ) {
                                    crate::analyzer::RelationalBatchOutcome::Complete(results) => {
                                        results
                                    }
                                    crate::analyzer::RelationalBatchOutcome::Cancelled => {
                                        return crate::analyzer::RelationalBatchOutcome::Cancelled;
                                    }
                                    crate::analyzer::RelationalBatchOutcome::Failed(error) => {
                                        return crate::analyzer::RelationalBatchOutcome::Failed(
                                            error,
                                        );
                                    }
                                };
                            let physical = physical_results
                                .pop()
                                .expect("one physical callable request returns one result");
                            let crate::analyzer::RelationalDefinitionValue::CallableFacts(
                                physical_facts,
                            ) = physical.value
                            else {
                                panic!("a callable request returned the wrong value shape");
                            };
                            additions.extend(physical_facts.into_iter().filter_map(|mut fact| {
                                (fact.declaration == *provisional).then(|| {
                                    fact.declaration = rekeyed.clone();
                                    fact
                                })
                            }));
                        }
                    }
                    facts.extend(additions);
                }
                crate::analyzer::RelationalDefinitionValue::PackageRelation(_) => {}
            }
            result.value.canonicalize();
        }
        if cancellation.is_cancelled() {
            return crate::analyzer::RelationalBatchOutcome::Cancelled;
        }
        crate::analyzer::RelationalBatchOutcome::Complete(results)
    }

    crate::analyzer::i_analyzer::forward_file_identity_invalidation!();

    fn working_tree_identity(&self) -> Option<std::sync::Arc<crate::gitblob::WorkingTreeIdentity>> {
        self.inner.working_tree_identity()
    }

    #[cfg(any(test, feature = "test-support"))]
    fn test_hooks(&self) -> &dyn crate::analyzer::AnalyzerTestHooks {
        self
    }

    fn claimed_files(&self) -> Vec<ProjectFile> {
        self.inner.claimed_files()
    }

    fn workspace_declarations_with_primary_ranges(
        &self,
        cancellation: &crate::CancellationToken,
    ) -> Option<Vec<(CodeUnit, Option<crate::analyzer::Range>)>> {
        // The usage catalog accepts only classes and callables. Macro-composed
        // C++ fields are intentionally absent from the old per-file summary
        // path and would be filtered after paying to rebuild every file's
        // overlay, so keep this inventory on the persisted inner declarations.
        self.inner
            .workspace_declarations_with_primary_ranges(cancellation)
    }

    fn begin_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        self.inner.begin_query(context);
    }

    fn end_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        self.inner.end_query(context);
    }

    fn prefetch_definitions(&self, fq_names: &[String]) {
        self.inner.prefetch_definitions(fq_names);
    }

    fn record_query_failure(&self, error: crate::analyzer::store::StoreError) {
        self.inner.record_query_failure(error);
    }

    fn record_query_incomplete(&self, reason: crate::analyzer::QueryReadIncomplete) {
        self.inner.record_query_incomplete(reason);
    }

    fn workspace_file_index_cell(&self) -> Option<crate::analyzer::WorkspaceFileIndexCell> {
        self.inner.workspace_file_index_cell()
    }

    fn definition_lookup_memo(
        &self,
    ) -> Option<std::sync::Arc<crate::analyzer::DefinitionLookupMemo>> {
        self.inner.definition_lookup_memo()
    }

    fn import_statements(&self, file: &ProjectFile) -> Vec<String> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        self.import_statements_from_projection(token, file)
    }

    fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)> {
        self.inner.compute_cognitive_complexities(file)
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        self.with_updated_inner(self.inner.update(changed_files))
    }

    fn update_all(&self) -> Self {
        self.with_updated_inner(self.inner.update_all())
    }

    fn parse_errors(&self, file: &ProjectFile) -> Option<Vec<crate::analyzer::ParseError>> {
        self.inner.parse_errors(file)
    }

    fn semantic_diagnostics(
        &self,
        file: &ProjectFile,
        source: &str,
    ) -> crate::analyzer::SemanticDiagnosticReport {
        // The collector builds the complete report itself: it is the only
        // caller that knows whether a compile command was found, whether its
        // include closure could be reproduced, and which of those failures
        // leaves a name unjudged rather than absent. The blanket
        // workspace-local wrapper would report every one of them as clean.
        let report =
            brokk_bifrost_cpp::diagnostics::collect_cpp_semantic_diagnostics(self, file, source);
        crate::analyzer::semantic_model::degrade_pack_gap_absences(self, report)
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

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        Some(self)
    }

    fn type_alias_provider(&self) -> Option<&dyn TypeAliasProvider> {
        Some(self)
    }

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
        Some(self)
    }

    /// C++ spells one callable as a prototype and a separate body, so it
    /// answers the declaration/definition peer relation (#1650). The pairing
    /// and the head/body label both live in `identity`, beside the include
    /// evidence they read.
    fn declaration_definition_peers(
        &self,
        file: &ProjectFile,
    ) -> Option<crate::analyzer::structural::DeclarationDefinitionPeers> {
        Some(identity::cpp_declaration_definition_peers(self, file))
    }

    fn structural_fact_providers(
        &self,
    ) -> Vec<&dyn crate::analyzer::structural::StructuralFactProvider> {
        self.inner.structural_fact_providers()
    }

    fn snapshot_caches(&self) -> Option<&crate::analyzer::AnalyzerSnapshotCaches> {
        Some(self.inner.snapshot_caches())
    }

    fn workspace_content_identities(
        &self,
    ) -> Option<crate::analyzer::content_identity::WorkspaceContentIdentities> {
        self.inner.workspace_content_identities()
    }

    fn workspace_fact_indexes(
        &self,
    ) -> Vec<&dyn crate::analyzer::read_verification::WorkspaceFactIndex> {
        self.inner.workspace_fact_indexes()
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
        if !self.contains_tests(file) || file_language(file) != Language::Cpp {
            return Vec::new();
        }
        let Ok(source) = self.inner.project().read_source(file) else {
            return Vec::new();
        };
        detect_cpp_test_assertion_smells(file, &source, &weights)
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
            .filter(|file| file_language(file) == Language::Cpp)
            .cloned()
            .collect();
        if requested_files.is_empty() {
            return Vec::new();
        }
        let requested_file_set: HashSet<ProjectFile> = requested_files.iter().cloned().collect();

        let mut parser = cpp_clone_parser();
        let corpus_units: Vec<CodeUnit> = self
            .get_all_declarations()
            .into_iter()
            .filter(|code_unit| {
                code_unit.is_function() && requested_file_set.contains(code_unit.source())
            })
            .collect();
        let _query_scope = crate::analyzer::AnalyzerQueryScope::new(self);
        let all_candidates: Vec<CloneCandidateProfile> = corpus_units
            .iter()
            .filter_map(|code_unit| {
                build_clone_candidate_data(self, code_unit, weights, &mut parser)
            })
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
impl crate::analyzer::AnalyzerTestHooks for CppAnalyzer {
    fn reset_relational_definition_batch_call_count_for_test(&self) {
        self.inner
            .test_hooks()
            .reset_relational_definition_batch_call_count_for_test();
    }

    fn relational_definition_batch_call_count_for_test(&self) -> usize {
        self.inner
            .test_hooks()
            .relational_definition_batch_call_count_for_test()
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

    fn reset_definition_prefetch_batch_count_for_test(&self) {
        self.inner
            .test_hooks()
            .reset_definition_prefetch_batch_count_for_test();
    }

    fn definition_prefetch_batch_count_for_test(&self) -> usize {
        self.inner
            .test_hooks()
            .definition_prefetch_batch_count_for_test()
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

    fn reset_blob_hash_count_for_test(&self) {
        self.inner.reset_blob_hash_count_for_test();
    }

    fn blob_hash_count_for_test(&self) -> usize {
        self.inner.blob_hash_count_for_test()
    }
}

impl TypeAliasProvider for CppAnalyzer {
    fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        #[cfg(test)]
        self.type_alias_classification_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.inner.is_type_alias(code_unit)
    }
}

static CPP_USAGE_STRATEGY: CppUsageGraphStrategy = CppUsageGraphStrategy::new();

/// The member identifier every reference to `target` must spell, when the
/// C++ scans give that guarantee.
///
/// A member call or member-field reference is matched on the terminal name of
/// a syntax node, so its identifier is written at every site. Nothing else
/// here is: a type can be reached through an alias declared in a third file,
/// a constructor site spells whatever name the type is reached by, and an
/// `operator`, destructor, or conversion function is recorded under a name its
/// call sites do not write. `None` means no spelling test applies and the
/// whole include closure stays admitted.
fn cpp_spelled_member_identifier<'a>(
    analyzer: &dyn IAnalyzer,
    target: &'a CodeUnit,
) -> Option<&'a str> {
    if !target.is_function() && !target.is_field() {
        return None;
    }
    let owner = analyzer.parent_of(target)?;
    if !owner.is_class() {
        return None;
    }
    let identifier = crate::analyzer::common::source_identifier_for_target(target);
    // A constructor carries the owner's own identifier, and its sites spell
    // the name the type is reached by, which an alias can change.
    if identifier == owner.identifier() || !cpp_member_is_spelled_at_references(identifier) {
        return None;
    }
    Some(identifier)
}

pub(crate) struct CppSupport;

impl LanguageSupport for CppSupport {
    fn language(&self) -> Language {
        Language::Cpp
    }

    fn focus_resolves_lexically(&self, focus: tree_sitter::Node<'_>) -> bool {
        !cpp_focus_is_non_lexical(focus)
    }

    fn referencing_candidate_files(
        &self,
        analyzer: &dyn IAnalyzer,
        target: &CodeUnit,
        seed_files: &BTreeSet<ProjectFile>,
        cancellation: Option<&crate::cancellation::CancellationToken>,
    ) -> Option<HashSet<ProjectFile>> {
        let cpp = resolve_analyzer::<CppAnalyzer>(analyzer)?;
        let mut reached = HashSet::default();
        let mut visited: HashSet<ProjectFile> = seed_files.iter().cloned().collect();
        let mut queue: VecDeque<ProjectFile> = seed_files.iter().cloned().collect();
        while let Some(included_file) = queue.pop_front() {
            if cancellation.is_some_and(|token| token.is_cancelled()) {
                break;
            }
            for includer in cpp.referencing_files_of(&included_file) {
                if visited.insert(includer.clone()) {
                    reached.insert(includer.clone());
                    queue.push_back(includer);
                }
            }
        }
        let Some(member) = cpp_spelled_member_identifier(analyzer, target) else {
            return Some(reached);
        };
        Some(cpp.files_spelling_member(analyzer, reached, member, cancellation))
    }

    fn skips_local_declaration(&self, node: tree_sitter::Node<'_>, source: &str) -> bool {
        match node.kind() {
            "declaration" => is_direct_recovered_exported_class_field_declaration(node, source),
            "init_declarator" => node.parent().is_some_and(|declaration| {
                is_direct_recovered_exported_class_field_declaration(declaration, source)
            }),
            _ => false,
        }
    }

    fn package_separator(&self) -> &'static str {
        "::"
    }

    fn qualified_call_separator(&self) -> &'static str {
        "::"
    }

    fn signature_metadata_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<SignatureMetadata>> {
        resolve_analyzer::<CppAnalyzer>(analyzer)
            .map(|cpp| cpp.signature_metadata_limited(unit, limit))
    }

    fn signatures_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<String>> {
        resolve_analyzer::<CppAnalyzer>(analyzer).map(|cpp| cpp.signatures_limited(unit, limit))
    }

    fn declaration_ranges_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<Range>> {
        resolve_analyzer::<CppAnalyzer>(analyzer).map(|cpp| cpp.ranges_limited(unit, limit))
    }

    fn forward_query_provider<'a>(
        &self,
        analyzer: &'a dyn IAnalyzer,
    ) -> Option<&'a dyn ForwardQueryProvider> {
        resolve_analyzer::<CppAnalyzer>(analyzer).map(|value| value as _)
    }

    fn ecosystem(&self) -> UsageEcosystem {
        UsageEcosystem::Cpp
    }

    fn reference_plugin(&self) -> crate::analyzer::languages::ReferenceLanguagePlugin {
        crate::analyzer::languages::ReferenceLanguagePlugin::new(&CPP_USAGE_STRATEGY, &CppEdgePass)
    }

    fn dead_code(&self) -> DeadCodeSupport {
        DeadCodeSupport {
            strategy: None,
            bulk: Some(&CppDeadCodeBulk),
        }
    }

    fn structural_receiver(&self) -> Option<&'static dyn StructuralReceiverResolver> {
        Some(&CppSupport)
    }

    fn parser_language(&self, _flavor: crate::analyzer::ParserFlavor) -> tree_sitter::Language {
        tree_sitter_cpp::LANGUAGE.into()
    }

    fn structural_spec(&self) -> &'static dyn crate::analyzer::structural::StructuralSpec {
        &brokk_bifrost_cpp::structural::CPP_STRUCTURAL_SPEC
    }

    fn highlight_query(&self) -> Option<&'static str> {
        Some(tree_sitter_cpp::HIGHLIGHT_QUERY)
    }
}

/// Generic lexical lookup is useful for C/C++ parameters and local value
/// references, but it cannot decide names owned by the C++ declaration/member
/// namespaces. Leave those structured sites to `get_definition::cpp`, where
/// receiver identity and declarator roles are available.
fn cpp_focus_is_non_lexical(focus: tree_sitter::Node<'_>) -> bool {
    let declaration_name = cpp_is_declaration_name(focus);
    let mut current = focus;
    while let Some(parent) = current.parent() {
        if parent.kind() == "field_expression"
            && parent.child_by_field_name("field") == Some(current)
        {
            return true;
        }
        if declaration_name {
            // Parameter names are lexical destinations, including names nested
            // under pointer, reference, and function declarators. Other
            // declaration names belong to the structured C++ resolver.
            match parent.kind() {
                "parameter_declaration" | "optional_parameter_declaration" => {
                    return !cpp_parameter_is_callable_binder(parent);
                }
                "declaration"
                | "field_declaration"
                | "function_definition"
                | "type_definition"
                | "alias_declaration"
                | "template_instantiation"
                | "class_specifier"
                | "struct_specifier"
                | "union_specifier"
                | "enum_specifier"
                | "namespace_definition"
                | "namespace_alias_definition"
                | "enumerator" => return true,
                _ => {}
            }
        }
        current = parent;
    }
    declaration_name
}

/// A C++ parameter name is lexical only when its parameter list belongs to a
/// callable declaration, not to a function type nested in a type descriptor or
/// another declarator. Tree-sitter aliases `function_type_declarator` to
/// `function_declarator`, so the ownership edge must be checked rather than the
/// visible node kind alone.
fn cpp_parameter_is_callable_binder(parameter: tree_sitter::Node<'_>) -> bool {
    let Some(parameter_list) = parameter.parent() else {
        return false;
    };
    if parameter_list.kind() != "parameter_list" {
        return false;
    }
    let Some(declarator) = parameter_list.parent() else {
        return false;
    };

    if declarator.kind() == "abstract_function_declarator" {
        return declarator.parent().is_some_and(|lambda| {
            lambda.kind() == "lambda_expression"
                && lambda.child_by_field_name("declarator") == Some(declarator)
        });
    }
    if declarator.kind() != "function_declarator" {
        return false;
    }
    if cpp_function_declarator_names_function_value(declarator) {
        return false;
    }
    let mut current = declarator;
    while let Some(owner) = current.parent() {
        if matches!(
            owner.kind(),
            "function_definition" | "declaration" | "field_declaration"
        ) {
            return owner.child_by_field_name("declarator") == Some(current);
        }
        let owns_current = match owner.kind() {
            "pointer_declarator" => owner.child_by_field_name("declarator") == Some(current),
            "reference_declarator" => owner.named_child(0) == Some(current),
            _ => false,
        };
        if !owns_current {
            return false;
        }
        current = owner;
    }
    false
}

/// Parentheses around a pointer-like name make the declaration a function
/// value (for example, `void (*callback)(int nested)`) rather than a callable
/// declaration whose parameters introduce lexical bindings.
fn cpp_function_declarator_names_function_value(declarator: tree_sitter::Node<'_>) -> bool {
    let Some(name_declarator) = declarator.child_by_field_name("declarator") else {
        return false;
    };
    if name_declarator.kind() != "parenthesized_declarator" {
        return false;
    }

    let mut pending = vec![name_declarator];
    while let Some(node) = pending.pop() {
        match node.kind() {
            "pointer_declarator" | "reference_declarator" => return true,
            "parenthesized_declarator" => {
                let mut cursor = node.walk();
                pending.extend(node.named_children(&mut cursor));
            }
            _ => {}
        }
    }
    false
}

struct CppEdgePass;

impl LanguageEdgePass for CppEdgePass {
    fn id(&self) -> EdgePassId {
        EdgePassId::Cpp
    }

    fn edge_sites(&self, ctx: &EdgeSiteScanCtx<'_>) -> Option<LanguageEdgeSites> {
        build_rooted_cpp_usage_edges(ctx.analyzer, ctx.fqns, ctx.keep_file)
            .map(LanguageEdgeSites::Fqn)
    }

    fn edge_weights(&self, ctx: &EdgeWeightScanCtx<'_>) -> Option<LanguageEdgeWeights> {
        build_cpp_usage_edge_weights(ctx.analyzer, ctx.fqns, ctx.keep_file)
            .map(LanguageEdgeWeights::Fqn)
    }
}

impl StructuralReceiverResolver for CppSupport {
    fn resolve_type_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<TypeLookupOutcome> {
        resolve_cpp_type_bounded(
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
        resolve_cpp_bounded(
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

#[derive(Default)]
struct CppDeadCodeMemo {
    file_count: Option<usize>,
    overloaded_fqns: Option<HashSet<String>>,
}

struct CppDeadCodeBulk;

impl DeadCodeBulkProof for CppDeadCodeBulk {
    fn id(&self) -> EdgePassId {
        EdgePassId::Cpp
    }

    fn new_memo(&self) -> Box<dyn std::any::Any + Send> {
        Box::new(CppDeadCodeMemo::default())
    }

    fn needs_precise_scan(&self, routing: DeadCodeRouting<'_>) -> bool {
        let DeadCodeRouting {
            analyzer,
            candidate,
            file_cap,
            memo,
        } = routing;
        let CppDeadCodeMemo {
            file_count,
            overloaded_fqns,
        } = memo.downcast_mut().expect("C++ bulk memo");
        if *file_count.get_or_insert_with(|| analyzable_file_count(analyzer, Language::Cpp))
            > file_cap
        {
            return true;
        }

        let empty_overloads = HashSet::default();
        let overloads = if candidate.is_function() {
            overloaded_fqns.get_or_insert_with(|| overloaded_function_fqns(analyzer, Language::Cpp))
        } else {
            &empty_overloads
        };
        matches!(
            dead_code_bulk_eligibility(analyzer, candidate, overloads),
            CppDeadCodeBulkEligibility::NeedsPrecise
        )
    }

    fn preflight(&self, analyzer: &dyn IAnalyzer) -> DeadCodeBulkPreflight {
        DeadCodeBulkPreflight::Ready {
            label: "C++",
            files: analyzable_file_count(analyzer, Language::Cpp),
        }
    }

    fn build(
        &self,
        analyzer: &dyn IAnalyzer,
        candidates: &[CodeUnit],
    ) -> Option<DeadCodeBulkEdges> {
        let nodes = fqn_bulk_nodes(
            analyzer,
            Language::Cpp,
            |unit| unit.is_function() || unit.is_class() || unit.is_field(),
            candidates,
        );
        build_cpp_usage_edges(analyzer, &nodes, |_| true)
            .map(|edges| DeadCodeBulkEdges::Fqn(Arc::new(edges)))
    }
}
