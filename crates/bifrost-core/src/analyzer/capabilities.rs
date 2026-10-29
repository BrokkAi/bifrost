use crate::analyzer::code_unit_index::CodeUnitIndex;
use crate::analyzer::model::{CodeUnit, ImportInfo, ProjectFile};
use crate::analyzer::pool_memo::{KeyedPoolSafeMemo, PoolSafeMemo};
use crate::analyzer::query_token::QueryToken;
use crate::cancellation::CancellationToken;
use crate::compact_graph::{CompactRows, CompactRowsBuilder, normalize_indexed_edges};
use crate::hash::{HashMap, HashSet};
use std::any::Any;
use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;

use rayon::prelude::*;

use serde_json::Value;

pub trait CapabilityProvider: Any {
    fn as_any(&self) -> &dyn Any;
}

/// File-local facts consumed together while constructing the coarse direct
/// dependency graph.
///
/// `contains_tests` is optional so providers without a bulk test-classification
/// projection can retain their existing per-file fallback. Tree-sitter-backed
/// providers populate it from the same persisted blob metadata read that
/// supplies their import facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDependencyFacts {
    pub imports: Vec<ImportInfo>,
    pub contains_tests: Option<bool>,
}

/// Structured direct file dependencies contributed outside ordinary imports.
///
/// `complete` belongs to the relation set rather than to cancellation. A
/// provider may know useful edges while lacking enough build-model evidence to
/// prove that it found every edge; callers must preserve those edges without
/// publishing the result as a complete cached graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdditionalFileDependencies {
    pub dependencies: HashMap<ProjectFile, HashSet<ProjectFile>>,
    pub complete: bool,
}

/// One structured name lookup performed while resolving a file's imports.
/// Candidate invalidation is indexed by the consulted file and looked-up name
/// so a content edit can invalidate only importers whose resolution consulted
/// the changed binding. The name `*` is reserved for a glob-surface lookup.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ImportLookupDependency {
    pub import_ordinal: u32,
    pub consulted_file: ProjectFile,
    pub name: String,
}

/// Positive and negative structured lookups used to resolve one importer's
/// file edges. Missing module keys let a newly appearing module invalidate
/// imports that could not resolve before it existed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportResolutionDependencies {
    pub lookups: Vec<ImportLookupDependency>,
    pub missing_module_path_keys: Vec<(u32, String)>,
}

/// One effective Rust name binding in a source file's module surface.
///
/// These rows are computed only for changed files and persisted relationally
/// so the import graph can compare old and new lookup surfaces without
/// retaining a workspace-sized Rust index in memory.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ImportGraphBindingSurface {
    pub module_path: String,
    pub name: String,
    pub namespace: String,
    pub visibility_kind: String,
    pub visibility_scope: String,
    pub origin_file: ProjectFile,
    pub origin_module_path: String,
    pub origin_name: String,
    pub route_files: Vec<ProjectFile>,
}

/// Fixed-width fingerprints of the structured inputs to one file's effective
/// import bindings. These are cache identities, not serialized fact bundles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportGraphInputDigests {
    pub binding_surface: [u8; 32],
    pub import_rows: [u8; 32],
}

/// Target-file edges with structured provenance values for each target.
pub type ImportedFileEdgeTargets = HashMap<ProjectFile, Vec<Value>>;

/// File targets resolved for one import statement. Providers with complete
/// candidate dependencies emit these separately so an edit can replace only
/// the statements whose lookup routes consulted the changed file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedFileEdgeFacts {
    pub import_ordinal: u32,
    pub edges: ImportedFileEdgeTargets,
}

impl AdditionalFileDependencies {
    pub fn complete(dependencies: HashMap<ProjectFile, HashSet<ProjectFile>>) -> Self {
        Self {
            dependencies,
            complete: true,
        }
    }

    pub fn incomplete(dependencies: HashMap<ProjectFile, HashSet<ProjectFile>>) -> Self {
        Self {
            dependencies,
            complete: false,
        }
    }
}

impl<T: Any> CapabilityProvider for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub trait ImportAnalysisProvider: Send + Sync {
    /// Shared, not owned: every memoizing implementation already stores the set
    /// behind an `Arc` in its per-file cache, and the hottest consumers only
    /// read it (a membership test in candidate discovery, a projection to
    /// source files in the reverse-import index). Returning the `Arc` removes a
    /// whole-set clone per cache hit and per insert.
    fn imported_code_units_of(&self, file: &ProjectFile) -> Arc<HashSet<CodeUnit>>;
    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile>;

    /// Return the union of workspace files that reference any `target`.
    ///
    /// A depth-bounded caller already knows both sets and must not be forced to
    /// initialize a provider's whole-workspace reverse index once per target.
    /// Providers with a structured batch representation can override this.
    /// The default preserves the file-at-a-time result for every existing
    /// provider.
    fn referencing_files_of_targets(
        &self,
        targets: &HashSet<ProjectFile>,
        cancellation: &CancellationToken,
    ) -> HashSet<ProjectFile> {
        let mut referencing = HashSet::default();
        for target in targets {
            if cancellation.is_cancelled() {
                break;
            }
            referencing.extend(self.referencing_files_of(target));
        }
        referencing
    }

    /// Return import facts for a group of files without requiring each caller
    /// to hydrate a complete per-file analyzer state. `None` preserves the
    /// existing file-at-a-time behavior for providers without a bulk read model.
    fn import_infos_for_files(
        &self,
        _files: &[ProjectFile],
    ) -> Option<HashMap<ProjectFile, Vec<ImportInfo>>> {
        None
    }

    /// Return the file-local facts needed by coarse dependency-graph
    /// construction in one batch.
    ///
    /// The default preserves providers that only expose bulk imports. A
    /// provider with persisted test classification should override this so a
    /// reverse walk does not rehydrate one file state per reached graph node.
    fn file_dependency_facts_for_files(
        &self,
        files: &[ProjectFile],
    ) -> Option<HashMap<ProjectFile, FileDependencyFacts>> {
        self.import_infos_for_files(files).map(|infos| {
            infos
                .into_iter()
                .map(|(file, imports)| {
                    (
                        file,
                        FileDependencyFacts {
                            imports,
                            contains_tests: None,
                        },
                    )
                })
                .collect()
        })
    }

    /// Whether this provider can produce complete structured negative and
    /// positive import lookup dependencies for every source it analyzes.
    fn has_complete_import_resolution_dependencies(&self) -> bool {
        false
    }

    /// Stable module-path keys backed or declared by this source. They are
    /// used only to match persisted missing-module lookups after source-set
    /// changes.
    fn import_graph_module_path_keys_for_files(
        &self,
        _files: &[ProjectFile],
    ) -> Option<HashMap<ProjectFile, Vec<String>>> {
        None
    }

    /// Return the current structured module-level binding surface for the
    /// selected files. Incremental providers use this to invalidate only the
    /// names whose bindings changed after a source edit.
    fn import_graph_binding_surfaces_for_files(
        &self,
        _files: &[ProjectFile],
        _cancellation: Option<&CancellationToken>,
    ) -> Option<HashMap<ProjectFile, Vec<ImportGraphBindingSurface>>> {
        None
    }

    /// Return per-file hashes of the structured declarations/routes and import
    /// binders that can affect the file's import-graph surface. A provider that
    /// cannot prove completeness returns None, selecting conservative refresh.
    fn import_graph_input_digests_for_files(
        &self,
        _files: &[ProjectFile],
        _cancellation: Option<&CancellationToken>,
    ) -> Option<HashMap<ProjectFile, ImportGraphInputDigests>> {
        None
    }

    /// Return complete structured candidate dependencies for each importer.
    /// Providers without this evidence return None; callers can still build
    /// correct edges, but must use conservative full invalidation when those
    /// providers' source contents or source sets change.
    fn import_resolution_dependencies_for_files(
        &self,
        _files: &[ProjectFile],
        _import_infos: Option<&HashMap<ProjectFile, Vec<ImportInfo>>>,
        _cancellation: Option<&CancellationToken>,
    ) -> Option<HashMap<ProjectFile, ImportResolutionDependencies>> {
        None
    }

    /// Resolve structured import edges while retaining the source import
    /// ordinal. `selected_ordinals` lists imports to resolve for files whose
    /// other import rows will be carried forward; files absent from that map
    /// are resolved in full. Providers without per-import output return None
    /// for a partial request, allowing the caller to use its conservative
    /// source-level path.
    fn for_each_import_edge_facts_from_infos(
        &self,
        files: &[ProjectFile],
        import_infos: Option<&HashMap<ProjectFile, Vec<ImportInfo>>>,
        selected_ordinals: &HashMap<ProjectFile, Vec<u32>>,
        cancellation: Option<&CancellationToken>,
        visit: &mut dyn FnMut(&ProjectFile, Vec<ImportedFileEdgeFacts>) -> bool,
    ) -> Option<()> {
        if !selected_ordinals.is_empty() {
            return None;
        }
        self.for_each_imported_file_edges_from_infos(
            files,
            import_infos,
            cancellation,
            &mut |file, edges| {
                visit(
                    file,
                    vec![ImportedFileEdgeFacts {
                        import_ordinal: u32::MAX,
                        edges,
                    }],
                )
            },
        )
    }

    /// Recompute only the candidate dependencies for selected import
    /// ordinals. The default is conservative: it can only provide all facts
    /// when the caller did not select a subset.
    fn import_resolution_dependencies_for_ordinals(
        &self,
        files: &[ProjectFile],
        import_infos: Option<&HashMap<ProjectFile, Vec<ImportInfo>>>,
        selected_ordinals: &HashMap<ProjectFile, Vec<u32>>,
        cancellation: Option<&CancellationToken>,
    ) -> Option<HashMap<ProjectFile, ImportResolutionDependencies>> {
        if !selected_ordinals.is_empty() {
            return None;
        }
        self.import_resolution_dependencies_for_files(files, import_infos, cancellation)
    }

    /// Return structured direct file dependencies that are not represented by
    /// ordinary import facts.
    ///
    /// Rust external-module declarations are the motivating case: `mod x;`
    /// makes the declaring file depend on `x.rs`, but it is neither a `use`
    /// declaration nor an `extern crate` declaration. Providers should return
    /// `None` when cancellation prevents a complete answer; callers must not
    /// cache that prefix as a complete graph.
    fn additional_direct_file_dependencies(
        &self,
        _files: &[ProjectFile],
        _cancellation: &CancellationToken,
    ) -> Option<AdditionalFileDependencies> {
        Some(AdditionalFileDependencies::complete(HashMap::default()))
    }

    /// The file's import facts, which fall through to the import-tier store
    /// read when nothing retained answers. Crossing that tier is only cheap
    /// under an open request scope, so the caller proves one is open by
    /// passing a [`QueryToken`] (issue #2423).
    fn import_info_of(&self, _token: QueryToken<'_>, _file: &ProjectFile) -> Vec<ImportInfo> {
        Vec::new()
    }

    /// Return the complete, unbounded import set for `file` when the provider
    /// can prove that its source-owned import publication is available.
    /// `Some(Vec::new())` is an authoritative import-free file; `None` means
    /// that the file's import facts are unavailable and must not be treated as
    /// an empty set.  The legacy [`Self::import_info_of`] method intentionally
    /// retains its recovery semantics for callers that cannot preserve this
    /// distinction.
    fn import_info_of_checked(
        &self,
        _token: QueryToken<'_>,
        _file: &ProjectFile,
    ) -> Option<Vec<ImportInfo>> {
        None
    }

    /// Resolve imported source units from already-loaded import facts. Providers
    /// that cannot do this cheaply return `None` and use `imported_code_units_of`.
    fn imported_code_units_from_infos(
        &self,
        _file: &ProjectFile,
        _imports: &[ImportInfo],
    ) -> Option<Arc<HashSet<CodeUnit>>> {
        None
    }

    /// Resolve directly imported project files from already-loaded import facts.
    /// Providers that do not expose file-level edges return `None` and callers
    /// can derive a conservative approximation from imported declarations.
    fn imported_files_from_infos(
        &self,
        _file: &ProjectFile,
        _imports: &[ImportInfo],
    ) -> Option<HashSet<ProjectFile>> {
        None
    }

    /// Provenance for file edges resolved from these structured import facts.
    /// Providers with richer resolution routes can attach those routes to the
    /// target file; `None` leaves the caller to use the general structured
    /// import facts as provenance.
    fn imported_file_edge_provenance_from_infos(
        &self,
        _file: &ProjectFile,
        _imports: &[ImportInfo],
    ) -> Option<ImportedFileEdgeTargets> {
        None
    }

    /// Resolve each file's imports while streaming results to `visit`, so a
    /// provider can reuse request-scoped resolver state without retaining a
    /// workspace-sized result collection. Return `None` only when unsupported;
    /// in that case `visit` must not have been called. Return `Some(())` after
    /// handling files until the input ends or `visit` returns `false`.
    fn for_each_imported_files_from_infos(
        &self,
        _files: &[ProjectFile],
        _import_infos: Option<&HashMap<ProjectFile, Vec<ImportInfo>>>,
        _cancellation: Option<&CancellationToken>,
        _visit: &mut dyn FnMut(&ProjectFile, HashSet<ProjectFile>) -> bool,
    ) -> Option<()> {
        None
    }

    /// Stream resolved file edges together with their structured provenance.
    /// The default preserves providers that only expose targets and records
    /// the parsed import facts that were supplied for each importer.
    fn for_each_imported_file_edges_from_infos(
        &self,
        files: &[ProjectFile],
        import_infos: Option<&HashMap<ProjectFile, Vec<ImportInfo>>>,
        cancellation: Option<&CancellationToken>,
        visit: &mut dyn FnMut(&ProjectFile, ImportedFileEdgeTargets) -> bool,
    ) -> Option<()> {
        let mut visit_targets = |file: &ProjectFile, targets: HashSet<ProjectFile>| {
            let facts = import_infos.and_then(|infos| infos.get(file)).map_or_else(
                || serde_json::json!({ "kind": "provider_resolved_import_edge" }),
                |imports| {
                    serde_json::json!({
                        "kind": "structured_import_facts",
                        "facts": imports
                    })
                },
            );
            let edges = targets
                .into_iter()
                .map(|target| (target, vec![facts.clone()]))
                .collect();
            visit(file, edges)
        };
        self.for_each_imported_files_from_infos(
            files,
            import_infos,
            cancellation,
            &mut visit_targets,
        )
    }

    fn relevant_imports_for(&self, _code_unit: &CodeUnit) -> HashSet<String> {
        HashSet::default()
    }

    /// Whether `source_file` can reference a declaration of `target`. A `true`
    /// is an answer; a `false` is only an absence of evidence, which is why
    /// callers still run the expansion backstop after one. Providers that can
    /// prove the negative override [`Self::import_reachability`] instead and
    /// derive this from it.
    fn could_import_file(
        &self,
        _source_file: &ProjectFile,
        _imports: &[ImportInfo],
        _target: &ProjectFile,
    ) -> bool {
        false
    }

    /// Resolve, in one batch, whatever [`Self::could_import_file`] would look
    /// up once per candidate.
    ///
    /// The shared import-graph candidate walk visits every workspace file, so
    /// a provider that answers each visit with its own store lookup pays that
    /// lookup once per import statement in the workspace -- 397k to 662k
    /// `definition_candidates` round trips inside a single `scan_usages`
    /// query on a 35k-file Rust workspace (#1748). The walk knows its whole
    /// candidate set before it inspects any of it, so this hook lets the
    /// provider enumerate its keys up front and collapse them into batched
    /// reads.
    ///
    /// Doing nothing is always correct: the per-candidate path still answers
    /// exactly as before, just without the shared warm result. Providers whose
    /// per-candidate answer is already file-local (Python, JS/TS, Go, C++)
    /// keep the default.
    fn prefetch_import_targets(
        &self,
        _files: &[ProjectFile],
        _import_infos: Option<&HashMap<ProjectFile, Vec<ImportInfo>>>,
        _cancellation: &crate::cancellation::CancellationToken,
    ) {
    }

    /// Batch the definition identities that file-dependency resolution will
    /// consult after import facts have been loaded for a whole workspace.
    ///
    /// This is separate from [`Self::prefetch_import_targets`]: exact usage
    /// candidate discovery and coarse file-edge construction do not
    /// necessarily resolve the same names. Providers whose file resolver is
    /// already path-local keep the no-op default.
    fn prefetch_file_dependency_targets(
        &self,
        _files: &[ProjectFile],
        _import_infos: Option<&HashMap<ProjectFile, Vec<ImportInfo>>>,
        _cancellation: &crate::cancellation::CancellationToken,
    ) {
    }

    /// The three-valued form of [`Self::could_import_file`], which lets a
    /// provider that has a completeness proof retire the caller's backstop.
    ///
    /// The default preserves the historical contract exactly by mapping the
    /// bool spelling's `true` to [`ImportReachability::Reaches`] and its
    /// `false` to [`ImportReachability::Unknown`] -- never to `DoesNotReach`,
    /// because the bool contract never distinguished "no" from "I did not
    /// find one".
    ///
    /// Bridging runs in this direction only. A provider overrides this method
    /// and defines `could_import_file` over it, so the two spellings cannot
    /// drift apart.
    fn import_reachability(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> ImportReachability {
        if self.could_import_file(source_file, imports, target) {
            ImportReachability::Reaches
        } else {
            ImportReachability::Unknown
        }
    }
}

/// How completely a provider can answer "can `source_file` reference a
/// declaration of `target`?".
///
/// Candidate discovery asks this per (candidate, target) pair and, when it
/// gets no positive answer, materializes every declaration the candidate
/// imports as a recall backstop. For a namespace-import language that
/// expansion is the whole workspace's top-level types per using directive,
/// which is the shape that burned #1194. The backstop exists only because the
/// bool contract could not distinguish a proven "no" from an unproven one.
///
/// A provider must return `DoesNotReach` only from a proof that covers every
/// way its language can name a declaration without importing it. Anything less
/// is `Unknown`: the cost of an unnecessary expansion is time, the cost of a
/// wrong `DoesNotReach` is a missing usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportReachability {
    /// The candidate can reference the target. Accept it without expanding.
    Reaches,
    /// The candidate provably cannot. Reject it without expanding.
    DoesNotReach,
    /// Undecided. The caller runs its own backstop, exactly as before this
    /// verdict existed.
    Unknown,
}

/// Resolve direct project-file edges from structured import facts. Prefer a
/// provider's file-level resolver so imports whose target has no declarations
/// remain visible; otherwise conservatively project resolved declaration
/// identities back to their source files.
pub fn resolve_imported_files_from_infos(
    provider: &dyn ImportAnalysisProvider,
    file: &ProjectFile,
    imports: &[ImportInfo],
) -> HashSet<ProjectFile> {
    provider
        .imported_files_from_infos(file, imports)
        .unwrap_or_else(|| {
            provider
                .imported_code_units_from_infos(file, imports)
                .unwrap_or_else(|| provider.imported_code_units_of(file))
                .iter()
                .map(|unit| unit.source().clone())
                .collect()
        })
}

pub fn build_reverse_import_index<F>(
    files: &[ProjectFile],
    resolve_imported: F,
    parallel: bool,
) -> HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>
where
    F: Fn(&ProjectFile) -> Arc<HashSet<CodeUnit>> + Sync,
{
    build_reverse_file_index(
        files,
        |file| imported_source_files(&resolve_imported(file)),
        parallel,
    )
}

fn imported_source_files(imported: &HashSet<CodeUnit>) -> Vec<ProjectFile> {
    imported
        .iter()
        .map(|code_unit| code_unit.source().clone())
        .collect()
}

pub type ReverseFileIndex = HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>;

pub fn memoized_reverse_import_index<F, Files>(
    memo: &PoolSafeMemo<ReverseFileIndex>,
    files: Files,
    resolve_imported: F,
) -> Arc<ReverseFileIndex>
where
    F: Fn(&ProjectFile) -> Arc<HashSet<CodeUnit>> + Sync + Copy,
    Files: Fn() -> Vec<ProjectFile> + Copy,
{
    memoized_reverse_file_index(memo, files, |file| {
        imported_source_files(&resolve_imported(file))
    })
}

pub fn memoized_reverse_file_index<F, I, Files>(
    memo: &PoolSafeMemo<ReverseFileIndex>,
    files: Files,
    resolve_targets: F,
) -> Arc<ReverseFileIndex>
where
    F: Fn(&ProjectFile) -> I + Sync + Copy,
    I: IntoIterator<Item = ProjectFile>,
    Files: Fn() -> Vec<ProjectFile> + Copy,
{
    memo.get_or_build(
        || {
            let files = files();
            build_reverse_file_index(&files, resolve_targets, true)
        },
        || {
            let files = files();
            build_reverse_file_index(&files, resolve_targets, false)
        },
    )
}

pub fn build_reverse_file_index<F, I>(
    files: &[ProjectFile],
    resolve_targets: F,
    parallel: bool,
) -> HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>
where
    F: Fn(&ProjectFile) -> I + Sync,
    I: IntoIterator<Item = ProjectFile>,
{
    let context = super::carried_context::CarriedContext::current();
    let collect_edges = |file: &ProjectFile| {
        context.run(|| {
            let source = file.clone();
            resolve_targets(file)
                .into_iter()
                .filter_map(move |target| (target != source).then(|| (target, source.clone())))
                .collect::<Vec<_>>()
        })
    };
    let edges: Vec<_> = if parallel {
        files.par_iter().flat_map(collect_edges).collect()
    } else {
        files.iter().flat_map(collect_edges).collect()
    };

    let mut reverse: HashMap<ProjectFile, HashSet<ProjectFile>> = HashMap::default();
    for (target, source) in edges {
        reverse.entry(target).or_default().insert(source);
    }
    reverse
        .into_iter()
        .map(|(file, refs)| (file, Arc::new(refs)))
        .collect()
}

/// `Send + Sync` like its three sibling capabilities: every implementor is an
/// analyzer, and a parallel whole-workspace scan holds the provider across its
/// fan-out (`kotlin_graph`'s edge builder does exactly that).
pub trait TypeAliasProvider: CapabilityProvider + Send + Sync {
    fn is_type_alias(&self, _code_unit: &CodeUnit) -> bool {
        false
    }
}

/// Whether a capability provider classifies `code_unit` as a type alias.
pub fn provider_declares_type_alias(
    provider: Option<&dyn TypeAliasProvider>,
    code_unit: &CodeUnit,
) -> bool {
    provider.is_some_and(|provider| provider.is_type_alias(code_unit))
}

pub trait TestDetectionProvider: CapabilityProvider {}

/// Which slice of the workspace a descendant index covers.
///
/// This is the memo key, and two values is the whole range: the excluded set is
/// a pure function of the analyzer and the file, so every request that asks to
/// leave test files out describes the same index.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum DescendantIndexVariant {
    /// Every class-like declaration the analyzer indexes.
    WholeWorkspace,
    /// The declarations whose source file the caller's predicate rejected are
    /// left out. In practice that is a `scan_usages` request with
    /// `include_tests: false`, whose test files the answer would discard anyway.
    ProductionOnly,
}

/// The request state a whole-workspace descendant-index build needs: the
/// deadline it polls, and the slice of the workspace it covers.
///
/// The two travel together because one loop consumes both -- the per-class loop
/// in [`build_direct_descendant_index_from_candidates`] and, for C++, the
/// per-file include-closure walk beneath it -- and because the slice is the
/// memo key that the deadline's complete-or-nothing rule is applied to.
///
/// The exclusion predicate is supplied by the caller rather than named here.
/// Test classification needs an analyzer (`file_is_test_only` reads a language
/// module index), which this crate must not know about; the closure crossing is
/// the same one the Rust usage walks already use for their `keep_going`
/// predicate. **The predicate must be a pure function of the analyzer and the
/// file.** That is the condition that makes [`DescendantIndexVariant`] a
/// complete key: two requests that both exclude test files must describe the
/// same index, or one would be served the other's.
#[derive(Clone, Copy)]
pub struct DescendantIndexScope<'a> {
    cancellation: &'a CancellationToken,
    excluded_source: Option<&'a dyn Fn(&ProjectFile) -> bool>,
}

impl<'a> DescendantIndexScope<'a> {
    /// Every class in the workspace, stopping when `cancellation` says to.
    pub fn whole_workspace(cancellation: &'a CancellationToken) -> Self {
        Self {
            cancellation,
            excluded_source: None,
        }
    }

    /// Every class whose source file `excluded` rejects is left out of the
    /// index entirely -- it is never handed to `get_direct_ancestors`, so the
    /// per-file resolution work behind that call is never charged.
    pub fn excluding_sources(
        cancellation: &'a CancellationToken,
        excluded: &'a dyn Fn(&ProjectFile) -> bool,
    ) -> Self {
        Self {
            cancellation,
            excluded_source: Some(excluded),
        }
    }

    pub fn cancellation(&self) -> &'a CancellationToken {
        self.cancellation
    }

    pub fn variant(&self) -> DescendantIndexVariant {
        match self.excluded_source {
            Some(_) => DescendantIndexVariant::ProductionOnly,
            None => DescendantIndexVariant::WholeWorkspace,
        }
    }

    /// The poll predicate for a builder that would rather take a plain
    /// `Fn() -> bool` than a token.
    pub fn keep_going(&self) -> impl Fn() -> bool + use<'_> {
        || !self.cancellation.is_cancelled()
    }

    /// Whether `declaration` belongs in this index.
    pub fn admits(&self, declaration: &CodeUnit) -> bool {
        self.excluded_source
            .is_none_or(|excluded| !excluded(declaration.source()))
    }
}

fn query_within_scope<T>(scope: &DescendantIndexScope<'_>, query: impl FnOnce() -> T) -> Option<T> {
    (!scope.cancellation().is_cancelled()).then(query)
}

/// One member shape fixed by a platform language specification.
#[derive(Debug, Clone, Copy)]
pub struct PlatformInventoryMethod {
    pub name: &'static str,
    pub parameters: &'static [&'static str],
    pub returns: &'static str,
}

/// An ancestor whose member declarations the workspace did not read.
#[derive(Debug, Clone)]
pub struct UnreadMemberFamilyAncestor {
    pub name: String,
    pub inventory: Option<&'static [PlatformInventoryMethod]>,
}

#[derive(Debug, Default)]
pub struct MemberFamilyAncestors {
    pub resolved: Vec<CodeUnit>,
    pub unread: Vec<UnreadMemberFamilyAncestor>,
}

pub trait TypeHierarchyProvider: Send + Sync {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit>;
    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit>;

    /// The nominal member walk also needs the ancestors not represented by
    /// workspace declarations. Languages opt in without changing type lookup.
    fn member_family_ancestors(&self, owner: &CodeUnit) -> MemberFamilyAncestors {
        MemberFamilyAncestors {
            resolved: self.get_direct_ancestors(owner),
            unread: Vec::new(),
        }
    }

    /// Resolve and erase source parameter types before comparing an inventory.
    /// A provider without such evidence conservatively leaves the side open.
    fn member_family_inventory_matches(
        &self,
        _member: &CodeUnit,
        _inventory: &[PlatformInventoryMethod],
    ) -> bool {
        true
    }

    fn supports_type_hierarchy(&self, code_unit: &CodeUnit) -> bool {
        code_unit.is_class()
    }

    fn get_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        traverse_hierarchy(code_unit, |next| self.get_direct_ancestors(next))
    }

    fn get_descendants(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        traverse_hierarchy(code_unit, |next| {
            self.get_direct_descendants(next).into_iter().collect()
        })
    }

    /// [`Self::get_direct_ancestors`] under a caller's deadline.
    ///
    /// `None` means the resolution stopped short; it is never an empty answer,
    /// which stays the honest way to say "no resolvable base types". The
    /// default checks the deadline once and delegates, which is right for a
    /// provider whose ancestor resolution is a lookup. C++ overrides it because
    /// resolving one class's bases means walking that file's whole transitive
    /// `#include` closure.
    fn get_direct_ancestors_within(
        &self,
        code_unit: &CodeUnit,
        scope: &DescendantIndexScope<'_>,
    ) -> Option<Vec<CodeUnit>> {
        query_within_scope(scope, || self.get_direct_ancestors(code_unit))
    }

    /// [`Self::get_direct_descendants`] under a caller's deadline and workspace
    /// slice.
    ///
    /// `None` means the answer is not available because the build stopped
    /// short. It is never a partial answer, and a stopped build publishes
    /// nothing: a truncated index memoized as complete would be served to every
    /// later caller as the truth (the rule
    /// `cancelled_cold_candidate_discovery_does_not_publish_partial_index`
    /// pins for the Rust walk caches).
    ///
    /// The default checks the deadline once and delegates, which is the correct
    /// behaviour for a provider whose descendant answer is bounded by
    /// construction. Every provider that inverts the ancestor relation over the
    /// whole workspace overrides this; a provider that also honours
    /// [`DescendantIndexScope::admits`] builds one index per
    /// [`DescendantIndexVariant`]. Ignoring `admits` is sound -- the index is
    /// then a superset and the caller's own file filter still applies -- so
    /// only the providers where the prune pays for itself implement it.
    fn get_direct_descendants_within(
        &self,
        code_unit: &CodeUnit,
        scope: &DescendantIndexScope<'_>,
    ) -> Option<HashSet<CodeUnit>> {
        query_within_scope(scope, || self.get_direct_descendants(code_unit))
    }

    /// [`Self::get_descendants`] under a caller's deadline and workspace slice,
    /// polling once per node of the walk. `None` carries the same meaning as in
    /// [`Self::get_direct_descendants_within`].
    fn get_descendants_within(
        &self,
        code_unit: &CodeUnit,
        scope: &DescendantIndexScope<'_>,
    ) -> Option<Vec<CodeUnit>> {
        traverse_hierarchy_while(code_unit, scope.cancellation(), |next| {
            self.get_direct_descendants_within(next, scope)
                .map(|descendants| descendants.into_iter().collect())
        })
    }

    fn get_polymorphic_matches<T: CodeUnitIndex>(
        &self,
        target: &CodeUnit,
        analyzer: &T,
    ) -> Vec<CodeUnit>
    where
        Self: Sized,
    {
        if !target.is_function() {
            return Vec::new();
        }

        let Some(parent) = analyzer.parent_of(target) else {
            return Vec::new();
        };

        self.get_descendants(&parent)
    }
}

/// Exact declaration identities plus compact ancestor-to-descendant rows.
pub struct DirectDescendantIndex {
    nodes: Box<[CodeUnit]>,
    row_by_ancestor: HashMap<CodeUnit, u32>,
    descendants: CompactRows<u32>,
}

impl DirectDescendantIndex {
    pub fn from_indexed_nodes(
        nodes: Vec<CodeUnit>,
        index_by_node: HashMap<CodeUnit, u32>,
        mut edges: Vec<(u32, u32)>,
    ) -> Self {
        normalize_indexed_edges(&nodes, &index_by_node, &mut edges);

        let row_count = usize::from(!edges.is_empty())
            + edges
                .windows(2)
                .filter(|pair| pair[0].0 != pair[1].0)
                .count();
        let mut row_by_ancestor = HashMap::default();
        let mut descendants = CompactRowsBuilder::with_capacity(row_count, edges.len());
        let mut cursor = 0;
        while cursor < edges.len() {
            let ancestor = edges[cursor].0;
            let start = cursor;
            while cursor < edges.len() && edges[cursor].0 == ancestor {
                cursor += 1;
            }
            let row =
                u32::try_from(descendants.rows()).expect("hierarchy index rows must fit in a u32");
            row_by_ancestor.insert(nodes[ancestor as usize].clone(), row);
            descendants.push_row(
                edges[start..cursor]
                    .iter()
                    .map(|(_, descendant)| *descendant),
            );
        }
        Self {
            nodes: nodes.into_boxed_slice(),
            row_by_ancestor,
            descendants: descendants.finish(),
        }
    }

    pub fn descendants(&self, ancestor: &CodeUnit) -> HashSet<CodeUnit> {
        let Some(row) = self.row_by_ancestor.get(ancestor).copied() else {
            return HashSet::default();
        };
        self.descendants
            .row(row as usize)
            .iter()
            .map(|descendant| self.nodes[*descendant as usize].clone())
            .collect()
    }
}

/// Answer a descendant query from a variant-keyed index cell, building the
/// variant the caller asked for if it is missing.
///
/// Every analyzer that memoizes a whole-workspace descendant index repeats this
/// same dance: pick the cell for the scope's variant, build while the deadline
/// holds, publish nothing if it does not, project the ancestor's row. It lives
/// here so the complete-or-nothing rule is stated once instead of copied into
/// each language module.
pub fn descendants_from_variant_index(
    index: &KeyedPoolSafeMemo<DescendantIndexVariant, DirectDescendantIndex>,
    scope: &DescendantIndexScope<'_>,
    code_unit: &CodeUnit,
    build: impl Fn() -> Option<DirectDescendantIndex>,
) -> Option<HashSet<CodeUnit>> {
    Some(
        index
            .cell(&scope.variant())
            // The builders are serial, so the same closure serves both memo
            // arms; the memo's value here is the non-blocking claim protocol.
            .get_or_build_while(&scope.keep_going(), &build, &build)?
            .descendants(code_unit),
    )
}

/// Invert the ancestor relation over every class the analyzer indexes.
///
/// `scope` decides two things. Its predicate drops declarations before they are
/// ever handed to `get_direct_ancestors`, which is where the per-declaration
/// resolution cost is charged (for C++ that is a whole transitive `#include`
/// closure per declaring file). Its token bounds the loop: `None` means the
/// build stopped short and must not be published.
pub fn build_direct_descendant_index<A, P>(
    analyzer: &A,
    provider: &P,
    scope: &DescendantIndexScope<'_>,
) -> Option<DirectDescendantIndex>
where
    A: CodeUnitIndex,
    P: TypeHierarchyProvider + ?Sized,
{
    build_direct_descendant_index_from_candidates(
        analyzer
            .all_declarations()
            .filter(|candidate| candidate.is_class() && scope.admits(candidate))
            .collect(),
        |candidate| provider.get_direct_ancestors_within(candidate, scope),
        &scope.keep_going(),
    )
}

/// The edge-building half of [`build_direct_descendant_index`], for providers
/// that assemble their candidate list some other way.
///
/// `keep_going` is polled once per candidate. That granularity is the natural
/// checkpoint: one candidate is one `direct_ancestors` call, which is the unit
/// of work whose tens of thousands of repetitions made this loop unbounded in
/// the first place (issue #1748). `direct_ancestors` answers `None` when its
/// own work stopped short, which stops this loop too -- a candidate whose bases
/// were half-resolved must not contribute a half-populated edge set.
pub fn build_direct_descendant_index_from_candidates<F>(
    mut candidates: Vec<CodeUnit>,
    mut direct_ancestors: F,
    keep_going: &dyn Fn() -> bool,
) -> Option<DirectDescendantIndex>
where
    F: FnMut(&CodeUnit) -> Option<Vec<CodeUnit>>,
{
    candidates.sort();
    candidates.dedup();
    let mut types_by_fq_name: HashMap<String, Vec<CodeUnit>> = HashMap::default();
    for candidate in &candidates {
        types_by_fq_name
            .entry(candidate.fq_name())
            .or_default()
            .push(candidate.clone());
    }
    let mut nodes = candidates.clone();
    let mut index_by_node: HashMap<_, _> = nodes
        .iter()
        .enumerate()
        .map(|(index, node)| {
            (
                node.clone(),
                u32::try_from(index).expect("hierarchy index declarations must fit in a u32"),
            )
        })
        .collect();
    let mut edges = Vec::new();
    for candidate in candidates {
        if !keep_going() {
            return None;
        }
        let descendant = index_by_node[&candidate];
        for ancestor in direct_ancestors(&candidate)? {
            let ancestor = types_by_fq_name
                .get(&ancestor.fq_name())
                .and_then(|same_name| {
                    let mut same_source = same_name
                        .iter()
                        .filter(|unit| unit.source() == candidate.source());
                    let exact = same_source.next()?;
                    same_source.next().is_none().then(|| exact.clone())
                })
                .unwrap_or(ancestor);
            let ancestor = *index_by_node.entry(ancestor.clone()).or_insert_with(|| {
                let index = u32::try_from(nodes.len())
                    .expect("hierarchy index declarations must fit in a u32");
                nodes.push(ancestor);
                index
            });
            edges.push((ancestor, descendant));
        }
    }
    Some(DirectDescendantIndex::from_indexed_nodes(
        nodes,
        index_by_node,
        edges,
    ))
}

/// [`traverse_hierarchy`] under a deadline: polls once per node popped and
/// propagates a stopped step as `None` rather than returning the nodes it had
/// already collected. A partial subtype set read as complete would let a caller
/// conclude that a class has no further subclasses.
fn traverse_hierarchy_while<F>(
    root: &CodeUnit,
    cancellation: &CancellationToken,
    mut next: F,
) -> Option<Vec<CodeUnit>>
where
    F: FnMut(&CodeUnit) -> Option<Vec<CodeUnit>>,
{
    let direct = next(root)?;
    if direct.is_empty() {
        return Some(Vec::new());
    }

    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    let mut queue = VecDeque::new();

    for item in direct {
        if seen.insert(item.fq_name()) {
            queue.push_back(item.clone());
            result.push(item);
        }
    }

    while let Some(current) = queue.pop_front() {
        if cancellation.is_cancelled() {
            return None;
        }
        for item in next(&current)? {
            if seen.insert(item.fq_name()) {
                queue.push_back(item.clone());
                result.push(item);
            }
        }
    }

    Some(result)
}

fn traverse_hierarchy<F>(root: &CodeUnit, mut next: F) -> Vec<CodeUnit>
where
    F: FnMut(&CodeUnit) -> Vec<CodeUnit>,
{
    let direct = next(root);
    if direct.is_empty() {
        return Vec::new();
    }

    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    let mut queue = VecDeque::new();

    for item in direct {
        if seen.insert(item.fq_name()) {
            queue.push_back(item.clone());
            result.push(item);
        }
    }

    while let Some(current) = queue.pop_front() {
        for item in next(&current) {
            if seen.insert(item.fq_name()) {
                queue.push_back(item.clone());
                result.push(item);
            }
        }
    }

    result
}

#[cfg(test)]
mod hierarchy_traversal_properties {
    use super::*;
    use crate::analyzer::model::CodeUnitType;
    use proptest::prelude::*;
    use std::collections::BTreeMap;

    const NODES: usize = 8;

    fn node(index: usize) -> CodeUnit {
        CodeUnit::new(
            ProjectFile::new(std::env::temp_dir(), "Hierarchy.java"),
            CodeUnitType::Class,
            "",
            format!("N{index}"),
        )
    }

    fn index_of(unit: &CodeUnit) -> usize {
        unit.fq_name()[1..].parse().expect("test node name")
    }

    /// Edge lists may repeat a target, hold self loops and form cycles.
    fn graphs() -> impl Strategy<Value = Vec<Vec<usize>>> {
        proptest::collection::vec(proptest::collection::vec(0..NODES, 0..5), NODES)
    }

    /// Reference by relaxation: `distance[n]` is the fewest edges on a path
    /// from `root` to `n` that uses at least one edge. This makes the root
    /// reachable only through a cycle, which is what the traversal reports.
    fn reference_distances(graph: &[Vec<usize>], root: usize) -> BTreeMap<usize, usize> {
        let mut distance: BTreeMap<usize, usize> = BTreeMap::new();
        for &next in &graph[root] {
            distance.insert(next, 1);
        }
        loop {
            let mut changed = false;
            for (from, edges) in graph.iter().enumerate() {
                let Some(&base) = distance.get(&from) else {
                    continue;
                };
                for &to in edges {
                    if distance.get(&to).is_none_or(|&known| known > base + 1) {
                        distance.insert(to, base + 1);
                        changed = true;
                    }
                }
            }
            if !changed {
                return distance;
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        /// On any graph, cyclic or not, the traversal terminates, returns each
        /// reachable declaration exactly once in breadth-first order, and asks
        /// for each declaration's neighbours once (the root twice when a cycle
        /// returns to it).
        #[test]
        fn visits_exactly_the_reachable_set_once_in_breadth_first_order(
            graph in graphs(),
            root in 0..NODES,
        ) {
            let mut calls: BTreeMap<usize, usize> = BTreeMap::new();
            let result = traverse_hierarchy(&node(root), |unit| {
                let id = index_of(unit);
                *calls.entry(id).or_default() += 1;
                graph[id].iter().map(|&to| node(to)).collect()
            });
            let found: Vec<usize> = result.iter().map(index_of).collect();

            let distance = reference_distances(&graph, root);
            let unique: BTreeSet<usize> = found.iter().copied().collect();
            prop_assert_eq!(found.len(), unique.len(), "a declaration was returned twice: {:?}", found);
            prop_assert_eq!(unique, distance.keys().copied().collect::<BTreeSet<_>>());
            prop_assert!(
                found.windows(2).all(|pair| distance[&pair[0]] <= distance[&pair[1]]),
                "not breadth-first: {:?} with distances {:?}", found, distance
            );
            // The root is not in the seen set when the walk starts, so a cycle
            // back to it expands it a second time; every other node once.
            prop_assert!(
                calls.iter().all(|(&id, &count)| count == 1 || (id == root && count == 2)),
                "repeated expansion: {:?}", calls
            );

            // The deadline-aware variant agrees when never cancelled.
            let live = CancellationToken::new();
            let guarded = traverse_hierarchy_while(&node(root), &live, |unit| {
                Some(graph[index_of(unit)].iter().map(|&to| node(to)).collect())
            });
            prop_assert_eq!(guarded, Some(result));
        }

        /// A failed neighbour step is propagated, not hidden behind a partial
        /// answer; a cancelled token stops a traversal that has work left but
        /// does not disturb one whose root has no neighbours.
        #[test]
        fn guarded_traversal_never_returns_a_partial_answer(
            graph in graphs(),
            root in 0..NODES,
            fail_on in 0..NODES,
        ) {
            let reachable = reference_distances(&graph, root);
            let failing = traverse_hierarchy_while(&node(root), &CancellationToken::new(), |unit| {
                let id = index_of(unit);
                (id != fail_on).then(|| graph[id].iter().map(|&to| node(to)).collect())
            });
            // The failing node's neighbours are requested when it is the root or
            // is itself returned, so it is only skipped when neither holds.
            let requested = fail_on == root || reachable.contains_key(&fail_on);
            prop_assert_eq!(failing.is_none(), requested);

            let cancelled = CancellationToken::new();
            cancelled.cancel();
            let stopped = traverse_hierarchy_while(&node(root), &cancelled, |unit| {
                Some(graph[index_of(unit)].iter().map(|&to| node(to)).collect())
            });
            prop_assert_eq!(stopped.is_none(), !graph[root].is_empty());
            if graph[root].is_empty() {
                prop_assert_eq!(stopped, Some(Vec::new()));
            }
        }
    }
}
