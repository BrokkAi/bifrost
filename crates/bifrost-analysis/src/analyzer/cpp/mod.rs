mod adapter;
mod cache;
mod clones;
mod compile_context;
mod declarations;
mod diagnostics;
mod hierarchy;
mod identity;
mod imports;
mod reconcile;
mod semantic;
pub(crate) mod structural;
mod tests;

use crate::analyzer::clone_detection::{
    CloneCandidateProfile, detect_structural_clone_smells, refine_clone_similarity_with_ast,
};
use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::fq_name::{SegmentKind, segment_interner};
use crate::analyzer::js_ts::{build_weighted_cache, weight_code_unit_vec_by_unit};
use crate::analyzer::store::LimitedQueryRows;
use crate::analyzer::tree_sitter_analyzer::BulkFileStateSource;
use crate::analyzer::{
    AnalyzerConfig, AnalyzerStoreContext, BuildProgress, CloneSmell, CloneSmellWeights, CodeUnit,
    CodeUnitType, DirectDescendantIndex, IAnalyzer, ImportAnalysisProvider, ImportInfo, Language,
    PoolSafeMemo, Project, ProjectFile, Range, SignatureMetadata, TestAssertionSmell,
    TestAssertionWeights, TestDetectionProvider, TreeSitterAnalyzer, TypeAliasProvider,
    TypeHierarchyProvider,
};
use crate::hash::{HashMap, HashSet};
use moka::sync::Cache;
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};

pub(crate) use adapter::CppAdapter;
use cache::{weight_code_unit_set_by_file, weight_code_unit_vec_by_file, weight_project_file_set};
use clones::{build_clone_candidate_data, cpp_clone_parser};
use compile_context::{CppCompileContext, CppCompileContexts};
use tests::detect_cpp_test_assertion_smells;

pub(crate) use declarations::{
    CppSentinelRecoveredClass, cpp_export_macro_token, cpp_sentinel_recovered_classes,
    cpp_sentinel_recovered_scope_for_node, cpp_template_term,
    is_direct_recovered_exported_class_field_declaration, is_recovered_exported_class_container,
    node_text, normalize_cpp_whitespace, recovered_exported_class_has_body,
    recovered_macro_return_type_node,
};
pub(crate) use identity::{
    CppCallableUnitRole, CppOccurrenceClassifier, CppOccurrenceRole,
    cpp_callable_definitions_share_identity_evidence, cpp_callable_unit_role,
    cpp_header_body_files_are_related, cpp_indexed_callable_linkage, cpp_is_range_for_binding_name,
    cpp_occurrence_role_for_range,
};
pub(crate) use imports::{
    IncludeTargetIndex, include_paths, resolve_include_targets, resolve_include_targets_with_index,
};
#[derive(Clone)]
pub struct CppAnalyzer {
    inner: TreeSitterAnalyzer<CppAdapter>,
    memo_budget: u64,
    imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    direct_ancestors: Cache<CodeUnit, Arc<Vec<CodeUnit>>>,
    visible_type_units_by_file: Cache<ProjectFile, Arc<Vec<CodeUnit>>>,
    /// #1134 resolution-time identity-reconciliation overlay. Maps the canonical
    /// `fq_name` a header declaration carries to the provisional out-of-line
    /// member definition `CodeUnit`s whose per-file identity extraction could not
    /// reconcile with it (the file-scope-under-using-directive shape and the
    /// template-specialization twin), keyed on the include-visible class table.
    /// Memoized per queried name; see `reconciled_definitions`.
    reconciled_definitions_by_fq: Cache<String, Arc<ReconciledDefinitionIndex>>,
    include_target_index: Arc<OnceLock<IncludeTargetIndex>>,
    reverse_include_index: Arc<PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    direct_descendant_index: Arc<OnceLock<DirectDescendantIndex>>,
    compile_contexts: Arc<OnceLock<CppCompileContexts>>,
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
    cpp_class_strength_parse_count: Arc<std::sync::atomic::AtomicUsize>,
}

/// The #1134 resolution-time identity-reconciliation overlay (see the field
/// docs on `CppAnalyzer::reconciled_definition_index`). For each out-of-line
/// member definition whose per-file provisional identity the include-visible
/// class table re-keys to a different canonical `fq_name`, it holds a *re-keyed*
/// `CodeUnit` -- a synthetic unit carrying the canonical identity but the
/// definition's real `.cpp` source -- so a canonical query resolves the
/// definition alongside its header declaration across every resolution surface
/// (`definitions`, source blocks, occurrence roles, canonical selectors). The
/// re-keyed unit is not in the store, so `provisional_of` maps it back to the
/// stored provisional unit for range and signature-metadata lookups.
///
/// Computed per queried name (see `CppAnalyzer::reconciled_definitions`), never
/// as a workspace-wide table: a warm forward lookup must not trigger a full
/// declaration scan.
#[derive(Default)]
struct ReconciledDefinitionIndex {
    /// Re-keyed definitions belonging under the queried canonical `fq_name`.
    rekeyed: Vec<CodeUnit>,
    /// Re-keyed unit -> the stored provisional unit its indexed data lives under.
    provisional_of: HashMap<CodeUnit, CodeUnit>,
}

crate::analyzer::impl_forward_query_provider!(CppAnalyzer);

impl CppAnalyzer {
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
        Self {
            inner,
            memo_budget,
            imported_code_units: build_weighted_cache(
                memo_budget / 4,
                weight_code_unit_set_by_file,
            ),
            referencing_files: build_weighted_cache(memo_budget / 8, weight_project_file_set),
            direct_ancestors: build_weighted_cache(memo_budget / 8, weight_code_unit_vec_by_unit),
            visible_type_units_by_file: build_weighted_cache(
                memo_budget / 8,
                weight_code_unit_vec_by_file,
            ),
            reconciled_definitions_by_fq: moka::sync::Cache::builder().max_capacity(2048).build(),
            include_target_index: Arc::new(OnceLock::new()),
            reverse_include_index: Arc::new(PoolSafeMemo::new()),
            direct_descendant_index: Arc::new(OnceLock::new()),
            compile_contexts: Arc::new(OnceLock::new()),
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
        }
    }

    /// The re-keyed reconciled definitions (if any) that belong under the
    /// canonical `fq_name` a header declaration carries, memoized per queried
    /// name. See the field docs on `reconciled_definition_index`.
    ///
    /// Deliberately **not** a workspace-wide index: building one would need a
    /// full declaration scan, and a warm forward lookup must not trigger one
    /// (`tests/analyzer_persistence.rs`'s candidate-bounded contract). Instead
    /// each queried name reconciles only the candidates the persisted terminal
    /// identifier index already offers, which is the same bounded lookup the
    /// ordinary resolution path uses.
    fn reconciled_definitions(&self, fq_name: &str) -> Arc<ReconciledDefinitionIndex> {
        self.reconciled_definitions_by_fq
            .get_with_by_ref(fq_name, || {
                Arc::new(self.build_reconciled_definitions(fq_name))
            })
    }

    /// Reconcile the bounded candidate set for one queried canonical `fq_name`:
    /// every out-of-line member definition sharing its terminal identifier whose
    /// provisional per-file identity the include-visible class table re-keys onto
    /// exactly this name (the two ambiguous shapes left by #1121). A definition
    /// whose reconciled identity equals its provisional one (the overwhelming
    /// majority, including genuine `ns1::ns2::Klass::method` namespace chains)
    /// contributes nothing.
    fn build_reconciled_definitions(&self, fq_name: &str) -> ReconciledDefinitionIndex {
        let _scope = crate::profiling::scope(format!("cpp.reconciled.build[{fq_name}]"));
        let mut index = ReconciledDefinitionIndex::default();
        let interner = segment_interner();
        // The queried name's terminal segment is the member identifier to probe
        // the identifier index with. Parsed through the sanctioned input-edge
        // parser rather than split here, and note `$` is not a segment boundary
        // for it -- a nested owner chain stays one segment, so the terminal
        // really is the member.
        let query_fq =
            crate::analyzer::symbol_lookup::parse_symbol_path_fq(Language::Cpp, fq_name, interner);
        let Some(member_segment) = query_fq.last() else {
            return index;
        };
        let (member_identifier, _) = interner.resolve(member_segment);
        if member_identifier.is_empty() {
            return index;
        }

        // #1566 owner-terminal pre-filter: the reconciler only re-partitions a
        // candidate's qualifier -- the class chain it emits is always a suffix
        // of the candidate's owner segments (`reconcile.rs`) -- so the terminal
        // `$` component of any identity it can produce equals the candidate's
        // terminal owner segment. A candidate whose terminal owner differs
        // from the queried name's penultimate segment can therefore never
        // re-key onto it, and skipping it here avoids the role check and, on
        // whale repos, an include-closure class-table build per same-named
        // candidate in the repo (chromium paid ~75s per member query that way:
        // one BFS per same-named candidate file, 2.5M declaration queries per
        // probe file for a gtest-shaped member name).
        let query_owner_terminal = query_fq.segments().len().checked_sub(2).map(|penultimate| {
            let (text, _) = interner.resolve(query_fq.segments()[penultimate]);
            // fqname-M4: the input-edge parser above deliberately keeps a nested
            // owner chain as one `$`-joined segment (no structured sub-segments
            // exist at this surface), so the terminal component must come from
            // the raw text.
            text.rsplit_once('$').map_or(text, |(_, tail)| tail)
        });

        let mut using_by_file: HashMap<ProjectFile, Arc<Vec<String>>> = HashMap::default();
        let candidates: BTreeSet<CodeUnit> = {
            let _lookup =
                crate::profiling::scope(format!("cpp.reconcile.lookup[{member_identifier}]"));
            self.inner
                .lookup_candidates_by_identifier(member_identifier)
        };
        crate::profiling::note(format!(
            "cpp.reconcile.candidates[{member_identifier}] n={}",
            candidates.len()
        ));
        for unit in candidates {
            let _candidate =
                crate::profiling::scope(format!("cpp.reconcile.candidate[{}]", unit.fq_name()));
            let candidate_owner_terminal = unit
                .fq()
                .segments()
                .iter()
                .filter_map(|&segment| {
                    let (text, kind) = interner.resolve(segment);
                    // Candidate fq segments carry real boundaries (each nested
                    // class is its own `SegmentKind::Nested` segment), so the
                    // segment text is already the terminal component.
                    matches!(
                        kind,
                        SegmentKind::Package | SegmentKind::Type | SegmentKind::Nested
                    )
                    .then_some(text)
                })
                .last();
            if let Some(query_terminal) = query_owner_terminal
                && candidate_owner_terminal != Some(query_terminal)
            {
                continue;
            }
            if !unit.is_callable() || unit.fq_name() == fq_name {
                continue;
            }
            let role = {
                let _role = crate::profiling::scope("cpp.reconcile.role");
                cpp_callable_unit_role(self, &unit)
            };
            if !matches!(
                role,
                CppCallableUnitRole::Definition | CppCallableUnitRole::Both
            ) {
                continue;
            }
            let Some(reconciled) = self.reconcile_definition_identity(&unit, &mut using_by_file)
            else {
                continue;
            };
            let canonical_fq = reconciled.fq_name();
            if canonical_fq != fq_name {
                continue;
            }
            // Re-key onto the canonical identity while keeping the definition's
            // real `.cpp` source and signature, so it resolves as a definition
            // alongside its header declaration under the canonical `fq_name`.
            // The structured `FqName` is rebuilt from the *canonical* package and
            // owner chain through the same emission helper extraction uses, so
            // the re-keyed unit carries real segment boundaries: owner lookup
            // (`default_parent_fq_name`) is a pure segment pop, where an empty
            // `fq` would mean "no owner" rather than "not yet migrated".
            let short_name = format!("{}.{}", reconciled.owner_chain, reconciled.member);
            let fq = declarations::cpp_member_fq(&reconciled.package, &short_name);
            let rekeyed = CodeUnit::with_signature_and_fq(
                unit.source().clone(),
                unit.kind(),
                reconciled.package,
                short_name,
                unit.signature().map(str::to_string),
                unit.is_synthetic(),
                fq,
            );
            index.rekeyed.push(rekeyed.clone());
            index.provisional_of.insert(rekeyed, unit);
        }
        index
    }

    /// Reconcile one out-of-line member definition's provisional identity against
    /// the class table visible to its file. Returns `None` for anything that is
    /// not a re-keyable out-of-line member (free functions with no owner, single
    /// segment qualifiers) or that the class table does not confirm.
    fn reconcile_definition_identity(
        &self,
        unit: &CodeUnit,
        using_by_file: &mut HashMap<ProjectFile, Arc<Vec<String>>>,
    ) -> Option<reconcile::ReconciledIdentity> {
        // Read the full source-order qualifier off the definition's *structured*
        // `FqName` -- the namespace (`Package`) segments followed by the
        // class-nesting (`Type`/`Nested`) ones, with the terminal `Member` as the
        // member name. The segment boundaries were recorded at extraction, so
        // nothing here re-infers them by splitting the rendered name on a guessed
        // delimiter (the shape `tests/no_stringly_name_parsing.rs` guards). The
        // reconciler then re-partitions this whole sequence against the class
        // table, so extraction need not have decided where the namespace ends and
        // the class chain begins.
        let interner = segment_interner();
        let mut owner_segments: Vec<&str> = Vec::new();
        let mut member: Option<&str> = None;
        for &segment in unit.fq().segments() {
            let (text, kind) = interner.resolve(segment);
            match kind {
                SegmentKind::Package | SegmentKind::Type | SegmentKind::Nested => {
                    // A `Member` is always terminal in a cpp callable's chain; a
                    // qualifier segment after one would mean the identity is not
                    // the plain `namespace... class... member` shape this handles.
                    if member.is_some() {
                        return None;
                    }
                    if !text.is_empty() {
                        owner_segments.push(text);
                    }
                }
                SegmentKind::Member => member = Some(text),
                _ => return None,
            }
        }
        let member = member?;
        if owner_segments.len() < 2 {
            return None;
        }

        let using = using_by_file
            .entry(unit.source().clone())
            .or_insert_with(|| {
                Arc::new(
                    self.inner
                        .file_source(unit.source())
                        .map(|source| declarations::cpp_file_using_namespaces(&source))
                        .unwrap_or_default(),
                )
            })
            .clone();
        let mut namespace_candidates: Vec<&str> = vec![""];
        namespace_candidates.extend(using.iter().map(String::as_str));

        let visible = {
            let _visible = crate::profiling::scope(format!(
                "cpp.reconcile.visible[{}]",
                crate::path_utils::rel_path_string(unit.source())
            ));
            self.visible_type_units(unit.source())
        };
        let class_table: Vec<reconcile::VisibleClass> = visible
            .iter()
            .filter(|candidate| candidate.is_class())
            .map(|candidate| reconcile::VisibleClass {
                package: candidate.package_name(),
                nested_short_name: candidate.short_name(),
            })
            .collect();

        reconcile::reconcile_out_of_line_member_identity(
            &owner_segments,
            member,
            &namespace_candidates,
            &class_table,
        )
    }

    fn with_updated_inner(&self, inner: TreeSitterAnalyzer<CppAdapter>) -> Self {
        Self {
            inner,
            memo_budget: self.memo_budget,
            imported_code_units: build_weighted_cache(
                self.memo_budget / 4,
                weight_code_unit_set_by_file,
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
            reconciled_definitions_by_fq: moka::sync::Cache::builder().max_capacity(2048).build(),
            include_target_index: Arc::new(OnceLock::new()),
            reverse_include_index: Arc::new(PoolSafeMemo::new()),
            direct_descendant_index: Arc::new(OnceLock::new()),
            compile_contexts: Arc::new(OnceLock::new()),
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
        }
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }
}

impl CppAnalyzer {
    pub(crate) fn compile_context_for(&self, file: &ProjectFile) -> Option<&CppCompileContext> {
        self.compile_contexts
            .get_or_init(|| CppCompileContexts::load(self.inner.project()))
            .for_file(file)
    }

    pub(crate) fn prepared_syntax(
        &self,
        file: &ProjectFile,
    ) -> Option<Arc<crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree>> {
        self.inner.prepared_syntax(file)
    }

    pub(crate) fn prepared_syntax_limited_cancellable(
        &self,
        file: &ProjectFile,
        max_source_bytes: usize,
        cancellation: Option<&crate::cancellation::CancellationToken>,
    ) -> crate::analyzer::tree_sitter_analyzer::PreparedSyntaxLimitedOutcome {
        self.inner
            .prepared_syntax_limited_cancellable(file, max_source_bytes, cancellation)
    }

    pub(crate) fn bulk_file_states_for_query(&self, files: impl IntoIterator<Item = ProjectFile>) {
        self.inner
            .bulk_file_states_for_query(files, BulkFileStateSource::Include);
    }

    pub(crate) fn receiver_query_supported(file: &ProjectFile) -> bool {
        file.rel_path()
            .extension()
            .and_then(|extension| extension.to_str())
            != Some("c")
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

    pub(crate) fn declaration_candidates_by_fqn_limited(
        &self,
        fqn: &str,
        normalized: bool,
        limit: usize,
        continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit> {
        self.inner.lookup_declarations_by_persisted_fqn_limited(
            fqn,
            normalized,
            limit,
            continue_query,
        )
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

    pub(crate) fn ranges_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<Range> {
        self.inner.ranges_limited(code_unit, limit)
    }

    pub fn structural_parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        self.inner.structural_parent_of(code_unit)
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

    pub fn extract_type_identifiers(&self, source: &str) -> BTreeSet<String> {
        static IDENT_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let regex =
            IDENT_RE.get_or_init(|| Regex::new(r"[A-Za-z_][A-Za-z0-9_:<>]*").expect("valid regex"));
        regex
            .find_iter(source)
            .map(|m| m.as_str())
            .filter(|token| {
                token
                    .chars()
                    .next()
                    .is_some_and(|ch| ch.is_ascii_uppercase())
            })
            .map(|token| token.trim_matches(':').to_string())
            .collect()
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

impl IAnalyzer for CppAnalyzer {
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

    fn materialization_records(
        &self,
        file: &ProjectFile,
    ) -> Vec<crate::analyzer::structural::materialization::MaterializationRecord> {
        self.inner.materialization_records(file)
    }

    fn definitions(&self, fq_name: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        let _scope = crate::profiling::scope(format!("cpp.definitions[{fq_name}]"));
        let inner: Vec<CodeUnit> = {
            let _inner = crate::profiling::scope(format!("cpp.definitions.inner[{fq_name}]"));
            self.inner.definitions(fq_name).collect()
        };
        // #1134: fold in out-of-line member definitions whose per-file identity
        // extraction could not reconcile with this canonical `fq_name`, but the
        // include-visible class table confirms belong here, so a header
        // declaration and its `.cpp` definition unify at resolution time.
        let reconciled = self.reconciled_definitions(fq_name);
        if reconciled.rekeyed.is_empty() {
            return Box::new(inner.into_iter());
        }
        let mut definitions = inner;
        for unit in &reconciled.rekeyed {
            if !definitions.contains(unit) {
                definitions.push(unit.clone());
            }
        }
        Box::new(definitions.into_iter())
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

    fn global_usage_definition_index(&self) -> crate::analyzer::DefinitionIndexHandle<'_> {
        self.inner.global_usage_definition_index()
    }

    fn direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.inner.direct_children(code_unit)
    }

    fn import_statements(&self, file: &ProjectFile) -> Vec<String> {
        self.inner.import_statements(file)
    }

    fn ranges(&self, code_unit: &CodeUnit) -> Vec<crate::analyzer::Range> {
        let ranges = self.inner.ranges(code_unit);
        if !ranges.is_empty() {
            return ranges;
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
        ranges
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

    fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)> {
        self.inner.compute_cognitive_complexities(file)
    }

    fn signatures(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.inner.signatures(code_unit)
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

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        self.with_updated_inner(self.inner.update(changed_files))
    }

    fn update_all(&self) -> Self {
        self.with_updated_inner(self.inner.update_all())
    }

    fn project(&self) -> &dyn Project {
        self.inner.project()
    }

    fn get_all_declarations(&self) -> Vec<CodeUnit> {
        self.inner.get_all_declarations()
    }

    fn get_definitions(&self, fq_name: &str) -> Vec<CodeUnit> {
        let mut definitions = self.inner.get_definitions(fq_name);
        // #1134: fold in out-of-line member definitions whose per-file identity
        // extraction could not reconcile with this canonical `fq_name`, but the
        // include-visible class table confirms belong here (so a header
        // declaration and its `.cpp` definition unify at query time).
        {
            let reconciled = self.reconciled_definitions(fq_name);
            for unit in &reconciled.rekeyed {
                if !definitions.contains(unit) {
                    definitions.push(unit.clone());
                }
            }
        }
        definitions
    }

    fn parse_errors(&self, file: &ProjectFile) -> Option<Vec<crate::analyzer::ParseError>> {
        self.inner.parse_errors(file)
    }

    fn semantic_diagnostics(
        &self,
        file: &ProjectFile,
        source: &str,
    ) -> Vec<crate::analyzer::SemanticDiagnostic> {
        diagnostics::collect_cpp_semantic_diagnostics(self, file, source)
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

    fn has_complete_symbol_lookup_index(&self) -> bool {
        self.inner.has_complete_symbol_lookup_index()
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

    fn structural_search_providers(
        &self,
    ) -> Vec<&dyn crate::analyzer::structural::StructuralSearchProvider> {
        self.inner.structural_search_providers()
    }

    fn snapshot_caches(&self) -> Option<&crate::analyzer::AnalyzerSnapshotCaches> {
        Some(self.inner.snapshot_caches())
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
        let all_candidates: Vec<CloneCandidateProfile> = self
            .get_all_declarations()
            .into_iter()
            .filter(|code_unit| {
                code_unit.is_function() && requested_file_set.contains(code_unit.source())
            })
            .filter_map(|code_unit| {
                build_clone_candidate_data(self, &code_unit, weights, &mut parser)
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

impl TypeAliasProvider for CppAnalyzer {
    fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        #[cfg(test)]
        self.type_alias_classification_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.inner.is_type_alias(code_unit)
    }
}
