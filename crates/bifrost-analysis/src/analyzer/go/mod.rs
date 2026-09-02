mod adapter;
mod artifact;
mod cache;
mod clones;
mod dependency_discovery;
pub(crate) mod diagnostics;
mod imports;
pub(crate) mod package_identity;
mod semantic;
mod type_identity_proof;
use crate::analyzer::Range;
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
use brokk_bifrost_core::analyzer::query_token::QueryToken;

use crate::analyzer::clone_detection::detect_language_structural_clone_smells;
use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::languages::{
    BoundedReceiverQuery, DeadCodeBulkEdges, DeadCodeBulkPreflight, DeadCodeBulkProof,
    DeadCodeRouting, DeadCodeSupport, EdgePassId, EdgeSiteScanCtx, EdgeWeightScanCtx,
    LanguageEdgePass, LanguageEdgeSites, LanguageEdgeWeights, LanguageSupport,
    StructuralReceiverResolver, analyzable_file_count, fqn_bulk_nodes,
};
use crate::analyzer::store::LimitedQueryRows;
use crate::analyzer::usages::get_definition::{
    BoundedResolution, DefinitionLookupOutcome, resolve_go_bounded,
};
use crate::analyzer::usages::get_type::{TypeLookupOutcome, resolve_go_type_bounded};
use crate::analyzer::usages::go_graph::{
    GoUsageGraphStrategy, build_go_usage_edge_weights, build_go_usage_edges,
    go_implicit_entry_point,
};
use crate::analyzer::usages::workspace_graph::UsageEcosystem;
use crate::analyzer::{
    AnalyzerConfig, AnalyzerStoreContext, BuildProgress, CloneSmell, CloneSmellWeights, CodeUnit,
    ForwardQueryProvider, IAnalyzer, ImportAnalysisProvider, Language, Project, ProjectFile,
    SignatureMetadata, TestAssertionSmell, TestAssertionWeights, TestDetectionProvider,
    TreeSitterAnalyzer, TypeAliasProvider, TypeHierarchyProvider, resolve_analyzer,
};
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;

pub(crate) use adapter::GoAdapter;
pub use artifact::{GoDependencyPackAdapter, GoModulePackProducer, GoPinnedPackage};
// The Go declaration walk lives in the go crate; the rest of analysis (artifact,
// semantic) still reaches its helpers through `super::declarations::`.
pub(crate) use brokk_bifrost_go::declarations;
pub(crate) use brokk_bifrost_go::declarations::{
    determine_go_package_name, go_structured_type_identity_bounded,
};
use brokk_bifrost_go::graph::resolver::{GoEdgeIndex, GoGraphSource, build_go_edge_index};
use brokk_bifrost_go::hierarchy::GoHierarchyIndex;
pub(crate) use brokk_bifrost_go::packages;
pub(crate) use brokk_bifrost_go::packages::GO_MODULE_SCOPE_SEGMENT;
use brokk_bifrost_go::packages::{canonical_go_package_name, invalidate_nearest_go_module_cache};
use brokk_bifrost_go::test_detection::detect_go_test_assertion_smells;
use cache::GoMemoCaches;
use clones::build_go_clone_candidate_data;
pub use dependency_discovery::resolve_go_semantic_pack_dependencies;
pub use type_identity_proof::{
    GO_MODELED_RESULT_BINDING_TYPE_PROOF_MAX_SOURCE_BYTES,
    GO_MODELED_RESULT_BINDING_TYPE_PROOF_MAX_STEPS,
    go_modeled_result_binding_type_identity_is_exact,
    go_modeled_result_binding_type_identity_proof_work,
};

#[derive(Clone)]
pub struct GoAnalyzer {
    inner: TreeSitterAnalyzer<GoAdapter>,
    memo_caches: GoMemoCaches,
}

crate::analyzer::impl_forward_query_provider!(GoAnalyzer);

impl GoAnalyzer {
    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        Self {
            inner: self.inner.clone_with_project(project),
            memo_caches: GoMemoCaches::new(self.memo_caches.budget_bytes()),
        }
    }

    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        invalidate_nearest_go_module_cache();
        Self {
            inner: TreeSitterAnalyzer::new_with_config(project, GoAdapter, config),
            memo_caches: GoMemoCaches::new(memo_budget),
        }
    }

    pub(crate) fn new_with_config_store_context(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        store_context: AnalyzerStoreContext,
        progress: Option<BuildProgress>,
    ) -> Result<Self, crate::analyzer::store::StoreError> {
        let memo_budget = config.memo_cache_budget_bytes();
        invalidate_nearest_go_module_cache();
        let inner = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            project,
            GoAdapter,
            config,
            store_context,
            progress,
        )?;
        Ok(Self {
            inner,
            memo_caches: GoMemoCaches::new(memo_budget),
        })
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }

    pub(crate) fn declaration_candidates_by_fqn_limited(
        &self,
        fqn: &str,
        limit: usize,
        continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit> {
        let Some(identifier) = fqn.rsplit('.').next().filter(|name| !name.is_empty()) else {
            return LimitedQueryRows::complete(Vec::new(), 0);
        };
        let mut candidates =
            self.inner
                .lookup_declarations_by_identifier_limited(identifier, limit, continue_query);
        if candidates.complete {
            candidates
                .rows
                .retain(|candidate| candidate.fq_name() == fqn);
        }
        candidates
    }

    pub(crate) fn member_candidates_for_owner_limited(
        &self,
        owner_fqn: &str,
        name: &str,
        limit: usize,
        continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit> {
        let exact_fqn = format!("{owner_fqn}.{name}");
        let mut candidates =
            self.inner
                .lookup_declarations_by_identifier_limited(name, limit, continue_query);
        if candidates.complete {
            candidates
                .rows
                .retain(|candidate| candidate.fq_name() == exact_fqn);
        }
        candidates
    }

    pub(crate) fn import_info_limited(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
        limit: usize,
    ) -> LimitedQueryRows<crate::analyzer::ImportInfo> {
        self.inner.import_info_of_limited(token, file, limit)
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
    ) -> LimitedQueryRows<crate::analyzer::Range> {
        self.inner.ranges_limited(code_unit, limit)
    }

    pub(crate) fn raw_supertypes(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.inner.raw_supertypes_of(code_unit)
    }

    pub(crate) fn raw_supertypes_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<String> {
        self.inner.raw_supertypes_limited(code_unit, limit)
    }

    pub fn determine_package_name(&self, source: &str) -> String {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .expect("failed to load go parser");
        let Some(tree) = parser.parse(source, None) else {
            return String::new();
        };
        determine_go_package_name(tree.root_node(), source)
    }

    pub(crate) fn canonical_package_name_from_tree(
        &self,
        file: &ProjectFile,
        source: &str,
        root: tree_sitter::Node<'_>,
    ) -> String {
        let declared = determine_go_package_name(root, source);
        canonical_go_package_name(file, &declared)
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

    pub(crate) fn package_clause_of(&self, file: &ProjectFile) -> Option<String> {
        self.inner.content_qualifier_of(file)
    }

    pub(crate) fn workspace_path_index(&self) -> &packages::GoWorkspacePathIndex {
        self.memo_caches.workspace_path_index.get_or_init(|| {
            self.memo_caches
                .workspace_path_index_build_count
                .fetch_add(1, Ordering::Relaxed);
            packages::GoWorkspacePathIndex::build(self.project(), |file| {
                self.package_clause_of(file)
            })
        })
    }

    pub(crate) fn workspace_package_inventory_complete(&self) -> bool {
        self.inner.workspace_package_inventory_complete()
    }

    pub(crate) fn workspace_declaration_identities_authoritative(&self) -> bool {
        self.inner.workspace_declaration_identities_authoritative()
    }

    #[doc(hidden)]
    pub fn workspace_path_index_build_count_for_test(&self) -> usize {
        self.memo_caches.workspace_path_index_build_count()
    }

    pub(crate) fn usage_edge_index(&self) -> Arc<GoEdgeIndex> {
        let files: Vec<_> = self
            .get_analyzed_files()
            .into_iter()
            .filter(|file| file_language(file) == Language::Go)
            .collect();
        // The Go edge index is built from import facts, so the build owns a
        // request scope for the whole pass (issue #2423).
        let scope = AnalyzerQueryScope::new(self);
        let source = GoGraphSource {
            token: scope.token(),
            index: self,
            imports: self,
            type_aliases: self,
            workspace_paths: self.workspace_path_index(),
        };
        self.memo_caches
            .usage_edge_index
            .get_or_build_on_dedicated_pool(|| {
                self.memo_caches
                    .usage_edge_index_build_count
                    .fetch_add(1, Ordering::Relaxed);
                build_go_edge_index(source, &files).unwrap_or_default()
            })
    }

    #[doc(hidden)]
    pub fn usage_edge_index_build_count_for_test(&self) -> usize {
        self.memo_caches.usage_edge_index_build_count()
    }

    pub(crate) fn package_clause_names(&self) -> &crate::hash::HashMap<ProjectFile, String> {
        self.memo_caches.package_clause_names.get_or_init(|| {
            self.get_analyzed_files()
                .into_iter()
                .filter(|file| file_language(file) == Language::Go)
                .filter_map(|file| {
                    let source = self.project().read_source(&file).ok()?;
                    let package_name = self.determine_package_name(&source);
                    (!package_name.is_empty()).then_some((file, package_name))
                })
                .collect()
        })
    }

    pub fn format_test_module(path: impl AsRef<Path>) -> String {
        let path = path.as_ref();
        let normalized = path
            .to_string_lossy()
            .replace('\\', "/")
            .trim()
            .trim_start_matches('/')
            .trim_end_matches('/')
            .trim_matches('.')
            .trim_matches('/')
            .to_string();
        if normalized.is_empty() {
            ".".to_string()
        } else {
            format!("./{normalized}")
        }
    }

    pub fn get_test_modules_static(files: &[ProjectFile]) -> Vec<String> {
        let mut modules: Vec<_> = files
            .iter()
            .map(|file| {
                Self::format_test_module(file.rel_path().parent().unwrap_or_else(|| Path::new(".")))
            })
            .collect();
        modules.sort();
        modules.dedup();
        modules
    }
}

impl TypeAliasProvider for GoAnalyzer {
    fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        self.inner.is_type_alias(code_unit)
    }
}

impl GoAnalyzer {
    /// The workspace's Go type and member relations, built at most once per
    /// analyzer snapshot and on the dedicated build pool.
    ///
    /// Go has no background warm, so every caller here is on the request path.
    /// Running the build on the dedicated pool keeps it off the global request
    /// pool and lets a global-pool worker that reaches this memo park on the
    /// one build instead of duplicating it serially (#1772).
    fn hierarchy_index(&self) -> Arc<GoHierarchyIndex> {
        self.memo_caches
            .hierarchy_index
            .get_or_build_on_dedicated_pool(|| {
                let scope = AnalyzerQueryScope::new(self);
                GoHierarchyIndex::build(scope.token(), &self.inner, self)
            })
    }
}

impl TypeHierarchyProvider for GoAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.hierarchy_index().direct_ancestors(code_unit)
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> crate::hash::HashSet<CodeUnit> {
        self.hierarchy_index().direct_descendants(code_unit)
    }

    fn supports_type_hierarchy(&self, code_unit: &CodeUnit) -> bool {
        self.hierarchy_index().supports(code_unit)
    }
}

/// Go's method family: structural interface satisfaction (#1721, and the CHA
/// lever ICFG dispatch consumes at
/// `workspace_oracle::dispatch::virtual_dispatch_implementor_targets`).
///
/// Go has no override chains and writes nothing at either declaration site: a
/// type satisfies an interface exactly when its method set covers the
/// interface's. So `Overrides`/`OverriddenBy` never appear here, and the only
/// edges are `Implements` and its bounded inversion `ImplementedBy`, both read
/// out of the one satisfaction pass `GoHierarchyIndex` already runs. That pass
/// compares whole method keys -- each method's name, qualified by package when
/// the name is unexported, plus its parameter and result type tokens resolved
/// through the file's imports and type aliases -- so an edge exists only where
/// two declarations agree on structure, never where two names merely agree.
///
/// Only a method with a body joins a family as an implementor. An interface
/// method whose signature happens to match another interface's declares no
/// body, so it supplies nothing to implement and gets no `Implements` edge --
/// which is also why an interface method's own family is exactly its
/// implementors. Go's one real interface-to-interface relation is embedding,
/// and a promoted method has no declaration of its own to relate: the edge
/// lands on the interface that declares it.
///
/// `proven` therefore means "exhaustive over the indexed workspace": every Go
/// file parsed, the satisfaction pass ran within its pair cap, and neither end
/// of the answer touches an interface the pass skips. Anything else is
/// `incomplete`, and dispatch treats an unproven family as contributing no
/// target at all.
impl crate::analyzer::usages::MemberFamilyProvider for GoAnalyzer {
    fn member_family_capability(
        &self,
        member: &CodeUnit,
    ) -> crate::analyzer::structural::resolution::MemberFamilyCapability {
        go_member_family_capability(member)
    }

    fn member_family(
        &self,
        member: &CodeUnit,
        cancellation: Option<&crate::cancellation::CancellationToken>,
    ) -> crate::analyzer::usages::MemberFamilyAnswer {
        go_member_family(self, &self.hierarchy_index(), member, cancellation)
    }
}

/// What a Go declaration's own recorded structure can discriminate.
///
/// `ParameterTypeSpellings` is the measured level: the satisfaction pass reads
/// each parameter's and result's declared type node and resolves it through
/// the file's imports and aliases where it can, falling back to the written
/// token where it cannot. That is a strictly stronger discriminator than a
/// bare spelling but is not proof of type identity, so it must not claim
/// erasure.
pub fn go_member_family_capability(
    member: &CodeUnit,
) -> crate::analyzer::structural::resolution::MemberFamilyCapability {
    use crate::analyzer::structural::resolution::MemberFamilyCapability;
    if file_language(member.source()) != Language::Go {
        return MemberFamilyCapability::Unsupported;
    }
    MemberFamilyCapability::ParameterTypeSpellings
}

/// One Go member's family, read out of the workspace satisfaction index.
pub fn go_member_family(
    analyzer: &dyn IAnalyzer,
    index: &GoHierarchyIndex,
    member: &CodeUnit,
    cancellation: Option<&crate::cancellation::CancellationToken>,
) -> crate::analyzer::usages::MemberFamilyAnswer {
    use crate::analyzer::structural::resolution::{
        MemberFamilyCapability, MemberFamilyOutcome, MemberFamilyReason, MethodFamilyRelation,
    };
    use crate::analyzer::usages::{MemberFamilyAnswer, MemberFamilyEdge};
    use brokk_bifrost_go::hierarchy::{GoMemberFamily, GoMemberFamilyEdge};

    let capability = go_member_family_capability(member);
    if capability == MemberFamilyCapability::Unsupported {
        return MemberFamilyAnswer::unsupported_answer();
    }
    if cancellation.is_some_and(crate::cancellation::CancellationToken::is_cancelled) {
        return MemberFamilyAnswer::incomplete(capability, MemberFamilyReason::HierarchyTruncated);
    }
    if !member.is_function() {
        return MemberFamilyAnswer::no_family(capability, MemberFamilyReason::NotAMethod);
    }
    let (implements, implemented_by) = match index.member_family(member) {
        GoMemberFamily::Proven {
            implements,
            implemented_by,
        } => (implements, implemented_by),
        GoMemberFamily::NotEnumerable => {
            return MemberFamilyAnswer::incomplete(
                capability,
                MemberFamilyReason::HierarchyTruncated,
            );
        }
        // A top-level Go function owns no type and joins no method family;
        // that is a complete answer. A function the index did not record while
        // its owner is a type is a fact the index is missing, not an exclusion.
        GoMemberFamily::NotTracked => {
            return match analyzer.parent_of(member) {
                Some(parent) if parent.is_class() => {
                    MemberFamilyAnswer::incomplete(capability, MemberFamilyReason::OwnerUnknown)
                }
                _ => MemberFamilyAnswer::no_family(capability, MemberFamilyReason::NotAMethod),
            };
        }
    };

    // Go promotion and satisfaction match whole method keys, and Go has no
    // overloading, so a member is singled out by structure alone.
    let edge = |edge: GoMemberFamilyEdge, relation: MethodFamilyRelation| MemberFamilyEdge {
        target: edge.member,
        owner: edge.owner,
        relation,
        depth: 1,
        arity_unique: true,
    };
    let roots = if implements.is_empty() {
        vec![member.clone()]
    } else {
        let mut roots: Vec<CodeUnit> = implements.iter().map(|edge| edge.member.clone()).collect();
        roots.sort();
        roots.dedup();
        roots
    };
    let edges = implements
        .into_iter()
        .map(|value| edge(value, MethodFamilyRelation::Implements))
        .chain(
            implemented_by
                .into_iter()
                .map(|value| edge(value, MethodFamilyRelation::ImplementedBy)),
        )
        .collect();
    MemberFamilyAnswer {
        capability,
        outcome: MemberFamilyOutcome::Proven,
        reason: None,
        edges,
        roots,
    }
}

impl TestDetectionProvider for GoAnalyzer {}

use crate::analyzer::CodeUnitIndex;

impl CodeUnitIndex for GoAnalyzer {
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

    fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        self.inner.all_declarations()
    }

    fn declarations_sharing_name(&self, unit: &CodeUnit) -> Vec<CodeUnit> {
        self.inner.declarations_sharing_name(unit)
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
        let skeleton = self.inner.get_skeleton(code_unit)?;
        if code_unit.is_class() && !skeleton.trim_start().starts_with("type ") {
            Some(format!("type {skeleton}"))
        } else {
            Some(skeleton)
        }
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        let skeleton = self.inner.get_skeleton_header(code_unit)?;
        if code_unit.is_class() && !skeleton.trim_start().starts_with("type ") {
            Some(format!("type {skeleton}"))
        } else {
            Some(skeleton)
        }
    }

    fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String> {
        let sources = self.get_sources(code_unit, include_comments);
        (!sources.is_empty()).then(|| sources.into_iter().collect::<Vec<_>>().join("\n\n"))
    }

    fn render_source_fragment(
        &self,
        code_unit: &CodeUnit,
        mut source: String,
        declaration_start: usize,
    ) -> String {
        let Some(declaration) = source.get(declaration_start..) else {
            return source;
        };
        let declaration_has_type_keyword = declaration.trim_start().starts_with("type ")
            || source
                .get(..declaration_start)
                .is_some_and(|prefix| prefix.trim_end().ends_with("type"));
        if code_unit.is_class() && !declaration_has_type_keyword {
            source.insert_str(declaration_start, "type ");
        }
        source
    }

    fn get_sources(&self, code_unit: &CodeUnit, include_comments: bool) -> BTreeSet<String> {
        if !code_unit.is_class() {
            return self.inner.get_sources(code_unit, include_comments);
        }

        let Some(content) = self.inner.indexed_source(code_unit.source()) else {
            return BTreeSet::new();
        };
        let mut ranges = self.inner.ranges(code_unit);
        ranges.sort_by_key(|range| range.start_byte);

        ranges
            .into_iter()
            .filter_map(|range| {
                let start_byte = if include_comments {
                    crate::analyzer::tree_sitter_analyzer::expanded_comment_start(
                        Language::Go,
                        &content,
                        range.start_byte,
                    )
                } else {
                    range.start_byte
                };
                let source = content.get(start_byte..range.end_byte)?.to_string();
                Some(self.render_source_fragment(
                    code_unit,
                    source,
                    range.start_byte.saturating_sub(start_byte),
                ))
            })
            .collect()
    }

    fn search_definitions(&self, pattern: &str, auto_quote: bool) -> BTreeSet<CodeUnit> {
        self.inner.search_definitions(pattern, auto_quote)
    }

    fn search_definitions_by_suffix_pattern(
        &self,
        pattern: &str,
        terminal_identifiers: &[String],
        language: Language,
    ) -> BTreeSet<CodeUnit> {
        self.inner
            .search_definitions_by_suffix_pattern(pattern, terminal_identifiers, language)
    }

    fn lookup_candidates_by_short_name(&self, symbol: &str) -> BTreeSet<CodeUnit> {
        self.inner.lookup_candidates_by_short_name(symbol)
    }

    fn has_complete_symbol_lookup_index(&self) -> bool {
        self.inner.has_complete_symbol_lookup_index()
    }

    fn lookup_candidates_by_identifier(&self, identifier: &str) -> BTreeSet<CodeUnit> {
        self.inner.lookup_declarations_by_identifier(identifier)
    }
}

impl IAnalyzer for GoAnalyzer {
    crate::analyzer::i_analyzer::forward_relational_definition_batch!();

    #[cfg(any(test, feature = "test-support"))]
    fn test_hooks(&self) -> &dyn crate::analyzer::AnalyzerTestHooks {
        self
    }

    fn invalidate_cached_file_identities(&self) {
        self.inner.invalidate_cached_file_identities();
        invalidate_nearest_go_module_cache();
    }

    fn invalidate_cached_file_identities_for(&self, changed_files: &BTreeSet<ProjectFile>) {
        self.inner
            .invalidate_cached_file_identities_for(changed_files);
    }

    fn working_tree_identity(&self) -> Option<std::sync::Arc<crate::gitblob::WorkingTreeIdentity>> {
        self.inner.working_tree_identity()
    }

    fn begin_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        self.inner.begin_query(context);
    }

    fn end_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        self.inner.end_query(context);
    }

    fn record_query_failure(&self, error: crate::analyzer::store::StoreError) {
        self.inner.record_query_failure(error);
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
        self.inner.import_statements(file)
    }

    fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)> {
        self.inner.compute_cognitive_complexities(file)
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        let module_identity_changed = changed_files.iter().any(|file| {
            file.rel_path()
                .file_name()
                .is_some_and(|name| name == "go.mod")
        });
        invalidate_nearest_go_module_cache();
        let inner = if module_identity_changed {
            // Package facts are keyed by import path. A module-path change
            // therefore rekeys every Go file below this manifest, including
            // files absent from `changed_files`. Invalidate before rebuilding
            // so the projection cannot reuse the old nearest-module answer.
            self.inner.update_all()
        } else {
            self.inner.update(changed_files)
        };
        Self {
            inner,
            memo_caches: GoMemoCaches::new(self.memo_caches.budget_bytes()),
        }
    }

    fn update_all(&self) -> Self {
        invalidate_nearest_go_module_cache();
        let inner = self.inner.update_all();
        Self {
            inner,
            memo_caches: GoMemoCaches::new(self.memo_caches.budget_bytes()),
        }
    }

    fn parse_errors(&self, file: &ProjectFile) -> Option<Vec<crate::analyzer::ParseError>> {
        self.inner.parse_errors(file)
    }

    fn semantic_diagnostics(
        &self,
        file: &ProjectFile,
        source: &str,
    ) -> crate::analyzer::SemanticDiagnosticReport {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        // The Go collector builds the complete report itself: it is the only
        // caller that knows which of its lookups checked a workspace lexical
        // scope, an indexed external package surface, or nothing at all.
        diagnostics::collect_go_semantic_diagnostics(self, token, file, source)
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

    fn member_family_provider(&self) -> Option<&dyn crate::analyzer::usages::MemberFamilyProvider> {
        Some(self)
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        Some(self)
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
        detect_language_structural_clone_smells(self, files, weights, Language::Go, |code_unit| {
            build_go_clone_candidate_data(self, code_unit, weights)
        })
    }

    fn find_test_assertion_smells(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
    ) -> Vec<TestAssertionSmell> {
        if !self.contains_tests(file) || file_language(file) != Language::Go {
            return Vec::new();
        }
        let Ok(source) = self.inner.project().read_source(file) else {
            return Vec::new();
        };
        detect_go_test_assertion_smells(file, &source, &weights)
    }

    fn get_test_modules(&self, files: &[ProjectFile]) -> Vec<String> {
        Self::get_test_modules_static(files)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl crate::analyzer::AnalyzerTestHooks for GoAnalyzer {
    fn arm_selector_continuation_semantic_cache_invalidation_for_test(&self) {
        self.inner
            .test_hooks()
            .arm_selector_continuation_semantic_cache_invalidation_for_test();
    }

    fn invalidate_selector_continuation_semantic_cache_if_armed_for_test(&self) {
        self.inner
            .test_hooks()
            .invalidate_selector_continuation_semantic_cache_if_armed_for_test();
    }

    fn selector_continuation_semantic_cache_revivals_for_test(&self) -> u64 {
        self.inner
            .test_hooks()
            .selector_continuation_semantic_cache_revivals_for_test()
    }

    fn arm_evaluation_root_continuation_semantic_cache_invalidation_for_test(&self) {
        self.inner
            .test_hooks()
            .arm_evaluation_root_continuation_semantic_cache_invalidation_for_test();
    }

    fn invalidate_evaluation_root_continuation_semantic_cache_if_armed_for_test(&self) {
        self.inner
            .test_hooks()
            .invalidate_evaluation_root_continuation_semantic_cache_if_armed_for_test();
    }

    fn evaluation_root_continuation_semantic_cache_revivals_for_test(&self) -> u64 {
        self.inner
            .test_hooks()
            .evaluation_root_continuation_semantic_cache_revivals_for_test()
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
}

static GO_USAGE_STRATEGY: GoUsageGraphStrategy = GoUsageGraphStrategy::new();

pub(crate) struct GoSupport;

impl LanguageSupport for GoSupport {
    fn language(&self) -> Language {
        Language::Go
    }

    fn package_separator(&self) -> &'static str {
        "/"
    }

    fn signature_metadata_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<SignatureMetadata>> {
        resolve_analyzer::<GoAnalyzer>(analyzer)
            .map(|go| go.signature_metadata_limited(unit, limit))
    }

    fn signatures_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<String>> {
        resolve_analyzer::<GoAnalyzer>(analyzer).map(|go| go.signatures_limited(unit, limit))
    }

    fn declaration_ranges_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<Range>> {
        resolve_analyzer::<GoAnalyzer>(analyzer).map(|go| go.ranges_limited(unit, limit))
    }

    fn forward_query_provider<'a>(
        &self,
        analyzer: &'a dyn IAnalyzer,
    ) -> Option<&'a dyn ForwardQueryProvider> {
        resolve_analyzer::<GoAnalyzer>(analyzer).map(|value| value as _)
    }

    fn ecosystem(&self) -> UsageEcosystem {
        UsageEcosystem::Go
    }

    fn reference_plugin(&self) -> crate::analyzer::languages::ReferenceLanguagePlugin {
        crate::analyzer::languages::ReferenceLanguagePlugin::new(&GO_USAGE_STRATEGY, &GoEdgePass)
    }

    fn dead_code(&self) -> DeadCodeSupport {
        DeadCodeSupport {
            strategy: Some(&GO_USAGE_STRATEGY),
            bulk: Some(&GoDeadCodeBulk),
        }
    }

    fn structural_receiver(&self) -> Option<&'static dyn StructuralReceiverResolver> {
        Some(&GoSupport)
    }

    fn parser_language(&self, _flavor: crate::analyzer::ParserFlavor) -> tree_sitter::Language {
        tree_sitter_go::LANGUAGE.into()
    }

    fn structural_spec(&self) -> &'static dyn crate::analyzer::structural::StructuralSpec {
        &brokk_bifrost_go::structural::GO_STRUCTURAL_SPEC
    }

    fn highlight_query(&self) -> Option<&'static str> {
        Some(tree_sitter_go::HIGHLIGHTS_QUERY)
    }
}

struct GoEdgePass;

impl LanguageEdgePass for GoEdgePass {
    fn id(&self) -> EdgePassId {
        EdgePassId::Go
    }

    fn edge_sites(&self, ctx: &EdgeSiteScanCtx<'_>) -> Option<LanguageEdgeSites> {
        let scope = AnalyzerQueryScope::new(ctx.analyzer);
        let token = scope.token();
        crate::analyzer::usages::go_graph::build_rooted_go_usage_edges(
            ctx.analyzer,
            token,
            ctx.fqns,
            ctx.keep_file,
        )
        .map(LanguageEdgeSites::Fqn)
    }

    fn edge_weights(&self, ctx: &EdgeWeightScanCtx<'_>) -> Option<LanguageEdgeWeights> {
        let scope = AnalyzerQueryScope::new(ctx.analyzer);
        let token = scope.token();
        build_go_usage_edge_weights(ctx.analyzer, token, ctx.fqns, ctx.keep_file)
            .map(LanguageEdgeWeights::Fqn)
    }
}

impl StructuralReceiverResolver for GoSupport {
    fn resolve_type_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<TypeLookupOutcome> {
        let scope = AnalyzerQueryScope::new(query.analyzer);
        resolve_go_type_bounded(
            query.analyzer,
            scope.token(),
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
        resolve_go_bounded(
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

struct GoDeadCodeBulk;

impl DeadCodeBulkProof for GoDeadCodeBulk {
    fn id(&self) -> EdgePassId {
        EdgePassId::Go
    }

    fn needs_precise_scan(&self, routing: DeadCodeRouting<'_>) -> bool {
        routing.candidate.is_field() || go_implicit_entry_point(routing.candidate)
    }

    fn preflight(&self, analyzer: &dyn IAnalyzer) -> DeadCodeBulkPreflight {
        DeadCodeBulkPreflight::Ready {
            label: "Go",
            files: analyzable_file_count(analyzer, Language::Go),
        }
    }

    /// Module-level variables count as callers as well as declarations: a package-level
    /// `var` initializer is a real call site in Go.
    fn build(
        &self,
        analyzer: &dyn IAnalyzer,
        candidates: &[CodeUnit],
    ) -> Option<DeadCodeBulkEdges> {
        let scope = AnalyzerQueryScope::new(analyzer);
        let token = scope.token();
        let nodes = fqn_bulk_nodes(
            analyzer,
            Language::Go,
            |unit| unit.is_function() || unit.is_class() || go_module_level_field(unit),
            candidates,
        );
        build_go_usage_edges(analyzer, token, &nodes, |_| true)
            .map(|edges| DeadCodeBulkEdges::Fqn(Arc::new(edges)))
    }
}

fn go_module_level_field(unit: &CodeUnit) -> bool {
    unit.is_field() && unit.short_name().starts_with("_module_.")
}

/// A `GoAnalyzer` over an inline single-module fixture, shared by the test
/// modules of this analyzer.
#[cfg(test)]
pub(super) fn test_analyzer(files: &[(&str, &str)]) -> GoAnalyzer {
    use crate::analyzer::TestProject;

    let root = tempfile::tempdir().unwrap().keep();
    std::fs::write(root.join("go.mod"), "module example.com/app\n\ngo 1.22\n").unwrap();
    for (path, source) in files {
        let path = root.join(path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, source).unwrap();
    }
    GoAnalyzer::from_project(TestProject::new(root, Language::Go))
}

#[cfg(test)]
mod hierarchy_tests {
    //! Lives here rather than beside the builder in `brokk-bifrost-go`: the
    //! fixture needs a real `GoAnalyzer` to supply the `CodeUnitIndex` and
    //! `ImportAnalysisProvider` the hierarchy is built from.
    use super::*;
    use crate::analyzer::type_relations::TypeRelationKind;

    fn analyzer(files: &[(&str, &str)]) -> GoAnalyzer {
        super::test_analyzer(files)
    }

    /// Same-suffix package directories (`a/pkg`, `b/pkg`) must each bind only
    /// their own import path. The package table is indexed by every spelling
    /// that can bind (#1748), and a suffix index whose keys did not come from
    /// the same rule as the old scan would let `b/pkg` answer `a/pkg`'s
    /// import, giving `Worker` the wrong method set.
    #[test]
    fn same_suffix_package_directories_bind_only_their_own_import() {
        let analyzer = analyzer(&[
            (
                "a/pkg/base.go",
                "package pkg\ntype Base struct{}\nfunc (Base) Run() error { return nil }\n",
            ),
            (
                "b/pkg/base.go",
                "package pkg\ntype Base struct{}\nfunc (Base) Walk() error { return nil }\n",
            ),
            (
                "app/worker.go",
                "package app\n\nimport \"example.com/app/a/pkg\"\n\ntype Worker struct { pkg.Base }\ntype Runner interface { Run() error }\ntype Walker interface { Walk() error }\n",
            ),
        ]);
        let scope = AnalyzerQueryScope::new(&analyzer);
        let index = GoHierarchyIndex::build(scope.token(), &analyzer, &analyzer);

        let satisfied: Vec<&str> = index
            .relations()
            .iter()
            .filter(|relation| {
                relation.kind == TypeRelationKind::StructuralSatisfaction
                    && relation.from.identifier() == "Worker"
            })
            .map(|relation| relation.to.identifier())
            .collect();
        assert!(
            satisfied.contains(&"Runner"),
            "Worker embeds a/pkg.Base and must satisfy Runner: {satisfied:?}"
        );
        assert!(
            !satisfied.contains(&"Walker"),
            "Worker must not pick up b/pkg.Base's method set: {satisfied:?}"
        );
    }

    /// Cost pin for #1748: the import pass probes the package table once per
    /// import. The scan this replaced had no probe count at all -- it visited
    /// every workspace file for every import of every file.
    #[test]
    fn hierarchy_build_probes_the_package_table_once_per_import() {
        const PACKAGES: usize = 200;

        let sources: Vec<(String, String)> = (0..PACKAGES)
            .map(|index| {
                (
                    format!("pkg{index}/file.go"),
                    format!(
                        "package pkg{index}\n\nimport \"example.com/app/pkg{}\"\n\ntype Holder{index} struct {{ value pkg{}.Value }}\ntype Value struct{{}}\n",
                        (index + 1) % PACKAGES,
                        (index + 1) % PACKAGES
                    ),
                )
            })
            .collect();
        let files: Vec<(&str, &str)> = sources
            .iter()
            .map(|(path, source)| (path.as_str(), source.as_str()))
            .collect();
        let analyzer = analyzer(&files);
        let scope = AnalyzerQueryScope::new(&analyzer);
        let index = GoHierarchyIndex::build(scope.token(), &analyzer, &analyzer);

        assert_eq!(
            index.package_lookups(),
            PACKAGES,
            "one probe per import, not one scan of {PACKAGES} files per import"
        );
    }

    #[test]
    fn structural_relation_records_satisfied_interface() {
        let analyzer = analyzer(&[(
            "service.go",
            "package app\ntype Runner interface { Run() error }\ntype Worker struct{}\nfunc (Worker) Run() error { return nil }\n",
        )]);
        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        let index = GoHierarchyIndex::build(token, &analyzer, &analyzer);
        assert!(index.relations().iter().any(|relation| {
            relation.kind == TypeRelationKind::StructuralSatisfaction
                && relation.from.identifier() == "Worker"
                && relation.to.identifier() == "Runner"
        }));
    }

    /// The member of `owner` named `identifier`, by exact declaration identity.
    fn member(analyzer: &GoAnalyzer, owner: &str, identifier: &str) -> CodeUnit {
        analyzer
            .get_all_declarations()
            .into_iter()
            .find(|unit| {
                unit.is_function()
                    && unit.identifier() == identifier
                    && unit.owner_identifier() == Some(owner)
            })
            .unwrap_or_else(|| panic!("no declaration {owner}.{identifier}"))
    }

    /// The members the family answer says implement `member`, by short name.
    fn implementors(analyzer: &GoAnalyzer, member: &CodeUnit) -> Vec<String> {
        use crate::analyzer::structural::resolution::MethodFamilyRelation;
        use crate::analyzer::usages::MemberFamilyProvider;
        let answer = analyzer.member_family(member, None);
        assert!(
            answer.is_proven(),
            "family for {} is not proven: {:?} {:?}",
            member.fq_name(),
            answer.outcome,
            answer.reason
        );
        let mut names: Vec<_> = answer
            .edges
            .iter()
            .filter(|edge| edge.relation == MethodFamilyRelation::ImplementedBy)
            .map(|edge| edge.target.short_name().to_string())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn interface_method_resolves_to_its_implementors() {
        let analyzer = analyzer(&[(
            "service.go",
            "package app\n\
             type Runner interface { Run(id int) error }\n\
             type Worker struct{}\n\
             func (Worker) Run(id int) error { return nil }\n\
             type Pointer struct{}\n\
             func (*Pointer) Run(id int) error { return nil }\n",
        )]);
        let declaration = member(&analyzer, "Runner", "Run");
        assert_eq!(
            implementors(&analyzer, &declaration),
            vec!["Pointer.Run".to_string(), "Worker.Run".to_string()],
            "a pointer receiver implements the interface for *Pointer, and its \
             body is still the code that runs"
        );
    }

    #[test]
    fn a_method_of_the_same_name_and_a_different_signature_is_not_an_implementor() {
        let analyzer = analyzer(&[(
            "service.go",
            "package app\n\
             type Runner interface { Run(id int) error }\n\
             type Worker struct{}\n\
             func (Worker) Run(id int) error { return nil }\n\
             type NearMiss struct{}\n\
             func (NearMiss) Run(name string) error { return nil }\n\
             type WrongResult struct{}\n\
             func (WrongResult) Run(id int) {}\n",
        )]);
        let declaration = member(&analyzer, "Runner", "Run");
        assert_eq!(
            implementors(&analyzer, &declaration),
            vec!["Worker.Run".to_string()]
        );
    }

    #[test]
    fn a_type_that_satisfies_an_interface_by_embedding_reports_the_embedded_method() {
        let analyzer = analyzer(&[(
            "service.go",
            "package app\n\
             type Runner interface { Run(id int) error }\n\
             type Base struct{}\n\
             func (Base) Run(id int) error { return nil }\n\
             type Derived struct{ Base }\n",
        )]);
        let declaration = member(&analyzer, "Runner", "Run");
        assert_eq!(
            implementors(&analyzer, &declaration),
            vec!["Base.Run".to_string()],
            "Derived satisfies Runner through promotion, and the declaration \
             that runs is Base's"
        );
    }

    #[test]
    fn an_embedded_interfaces_method_keeps_its_own_declaration_as_the_family_root() {
        let analyzer = analyzer(&[(
            "service.go",
            "package app\n\
             type Starter interface { Start() error }\n\
             type Runner interface { Starter; Run() error }\n\
             type Worker struct{}\n\
             func (Worker) Start() error { return nil }\n\
             func (Worker) Run() error { return nil }\n",
        )]);
        assert_eq!(
            implementors(&analyzer, &member(&analyzer, "Starter", "Start")),
            vec!["Worker.Start".to_string()]
        );
        assert_eq!(
            implementors(&analyzer, &member(&analyzer, "Runner", "Run")),
            vec!["Worker.Run".to_string()]
        );
    }

    #[test]
    fn a_method_in_another_file_of_the_same_package_still_implements() {
        let analyzer = analyzer(&[
            (
                "api/service.go",
                "package api\ntype Runner interface { Run() error }\ntype Worker struct{}\n",
            ),
            (
                "api/worker.go",
                "package api\nfunc (Worker) Run() error { return nil }\n",
            ),
        ]);
        assert_eq!(
            implementors(&analyzer, &member(&analyzer, "Runner", "Run")),
            vec!["Worker.Run".to_string()],
            "a Go method lives in a file of its own, so the family join must \
             not be per-file"
        );
    }

    #[test]
    fn a_top_level_function_states_a_complete_answer_with_no_family() {
        use crate::analyzer::structural::resolution::{MemberFamilyOutcome, MemberFamilyReason};
        use crate::analyzer::usages::MemberFamilyProvider;
        let analyzer = analyzer(&[(
            "service.go",
            "package app\ntype Runner interface { Run() error }\nfunc Run() error { return nil }\n",
        )]);
        let function = analyzer
            .get_all_declarations()
            .into_iter()
            .find(|unit| unit.is_function() && analyzer.parent_of(unit).is_none())
            .expect("a top-level function");
        let answer = analyzer.member_family(&function, None);
        assert_eq!(answer.outcome, MemberFamilyOutcome::NoFamily);
        assert_eq!(answer.reason, Some(MemberFamilyReason::NotAMethod));
        assert!(answer.edges.is_empty());
    }

    #[test]
    fn the_forward_and_inverse_directions_name_the_same_pair() {
        use crate::analyzer::structural::resolution::MethodFamilyRelation;
        use crate::analyzer::usages::MemberFamilyProvider;
        let analyzer = analyzer(&[(
            "service.go",
            "package app\n\
             type Runner interface { Run() error }\n\
             type Worker struct{}\n\
             func (Worker) Run() error { return nil }\n",
        )]);
        let declaration = member(&analyzer, "Runner", "Run");
        let implementor = member(&analyzer, "Worker", "Run");
        let forward = analyzer.member_family(&implementor, None);
        assert!(forward.is_proven());
        assert_eq!(
            forward
                .edges
                .iter()
                .filter(|edge| edge.relation == MethodFamilyRelation::Implements)
                .map(|edge| edge.target.clone())
                .collect::<Vec<_>>(),
            vec![declaration.clone()]
        );
        assert_eq!(forward.roots, vec![declaration.clone()]);
        let inverse = analyzer.member_family(&declaration, None);
        assert_eq!(
            inverse
                .edges
                .iter()
                .filter(|edge| edge.relation == MethodFamilyRelation::ImplementedBy)
                .map(|edge| edge.target.clone())
                .collect::<Vec<_>>(),
            vec![implementor]
        );
        assert_eq!(inverse.roots, vec![declaration]);
    }

    #[test]
    fn an_interface_with_type_terms_leaves_both_ends_of_its_family_incomplete() {
        use crate::analyzer::structural::resolution::{MemberFamilyOutcome, MemberFamilyReason};
        use crate::analyzer::usages::MemberFamilyProvider;
        let analyzer = analyzer(&[(
            "service.go",
            "package app\n\
             type Labelled interface { ~int | ~int64; Label() string }\n\
             type Counter struct{}\n\
             func (Counter) Label() string { return \"counter\" }\n\
             type Plain interface { Run() error }\n\
             type Worker struct{}\n\
             func (Worker) Run() error { return nil }\n",
        )]);
        for unit in [
            member(&analyzer, "Labelled", "Label"),
            member(&analyzer, "Counter", "Label"),
        ] {
            let answer = analyzer.member_family(&unit, None);
            assert_eq!(
                answer.outcome,
                MemberFamilyOutcome::Incomplete,
                "the satisfaction pass skips an interface carrying type terms, \
                 so neither end of {} may claim an exhaustive family",
                unit.fq_name()
            );
            assert_eq!(answer.reason, Some(MemberFamilyReason::HierarchyTruncated));
            assert!(answer.edges.is_empty());
        }
        assert_eq!(
            implementors(&analyzer, &member(&analyzer, "Plain", "Run")),
            vec!["Worker.Run".to_string()],
            "an unrelated interface in the same workspace still answers"
        );
    }
}
