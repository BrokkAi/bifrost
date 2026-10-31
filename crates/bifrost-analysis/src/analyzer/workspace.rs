use crate::analyzer::multi_analyzer::WorkspaceBuildContext;
use crate::analyzer::multi_analyzer::build_language_delegate;
use brokk_bifrost_core::analyzer::project::AsProject;

use crate::analyzer::semantic_model::DependencyDiscoveryEvidence;
use crate::analyzer::semantic_model::DependencyDiscoveryOutcome;
use crate::analyzer::semantic_model::DependencyPackLimits;
use crate::analyzer::semantic_model::DependencyPackPreparationOutcome;
use crate::analyzer::semantic_model::DependencyResolver;
use crate::analyzer::semantic_model::DependencyResolverBounds;
use crate::analyzer::semantic_model::PendingDependencyPackAcquisition;
use crate::analyzer::semantic_model::RuntimeArtifactPublication;
use crate::analyzer::semantic_model::SemanticModelActivationEvidence;
use crate::analyzer::semantic_model::SemanticModelActivationPersistence;
use crate::analyzer::semantic_model::SemanticModelActivationRequest;
use crate::analyzer::semantic_model::SemanticModelRuntimeOutcome;
use crate::analyzer::semantic_model::SemanticPackCatalog;
use crate::analyzer::semantic_model::SubprocessPolicy;
use crate::analyzer::semantic_model::acquire_active_semantic_models_with_runtime_artifacts;
use crate::analyzer::semantic_model::prepare_installed_dependency_packs;
use crate::analyzer::semantic_model::runtime::ApproximateSemanticModelExpectation;

use crate::analyzer::store::StoreError;

use crate::analyzer::tree_sitter_analyzer::WorkspaceBuildSnapshot;

use crate::analyzer::AnalyzerBuildTierAccess;
use crate::analyzer::AnalyzerConfig;
use crate::analyzer::AnalyzerDelegate;
use crate::analyzer::BuildProgress;
use crate::analyzer::IAnalyzer;
use crate::analyzer::Language;
use crate::analyzer::MultiAnalyzer;
use crate::analyzer::Project;
use crate::analyzer::ProjectFile;
use crate::analyzer::RevisionBlobIdentities;

use crate::hash::HashMap;

use crate::profiling;

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use std::panic::AssertUnwindSafe;

use std::path::Path;
use std::path::PathBuf;

use std::sync::Arc;

/// The repository's shared content-addressed analyzer cache, opened once for a
/// request that analyzes immutable revisions of that repository.
///
/// Parsed facts are keyed by Git blob id and language storage key, not by
/// workspace, so a revision image can read every blob the cache already holds
/// -- from the live worktree, a linked worktree, or an earlier revision
/// request -- and contributes the ones it had to parse back to all of them.
/// The cache location resolves from the *original* repository root through the
/// standard funnel; a revision image's own root is a self-deleting export
/// directory and must never be used to derive it.
#[doc(hidden)]
pub struct SharedAnalyzerCache {
    store: Arc<crate::analyzer::store::AnalyzerStore>,
    /// The cancellation of the request that opened this cache. Every revision
    /// image built against it waits for the cache's cross-process build lock
    /// under this token, so the wait ends when the request does.
    cancellation: crate::CancellationToken,
}

impl SharedAnalyzerCache {
    /// Open the persisted cache serving `repository_root`.
    ///
    /// Opening is strict. A request that analyzes an immutable revision reads
    /// and writes this cache, and a host that cannot open it has no silently
    /// equivalent slower path: an ephemeral rebuild re-parses every blob of
    /// every revision on every request, so it is a performance failure worth
    /// reporting rather than absorbing. Two things fail here. `repository_root`
    /// may not be in a Git repository, which no immutable request reaches in
    /// practice because resolving the revision already needed one -- a bare
    /// repository passes, because reading a revision needs the object database
    /// and not a checkout; or the store
    /// may refuse the cache -- an unwritable or read-only checkout, or a
    /// filesystem SQLite rejects. The escape for a checkout that must stay
    /// read-only is `BIFROST_CACHE_ROOT`, which relocates the cache off the
    /// repository.
    #[doc(hidden)]
    pub fn open(
        repository_root: &Path,
        cancellation: &crate::CancellationToken,
    ) -> Result<Self, StoreError> {
        // Opening the cache is the first place a budgeted immutable request
        // touches the filesystem, and on a loaded box it can be where the
        // budget goes; name it so the host does not fall back to "executing
        // <tool>" (issue #3170).
        let _phase = cancellation.enter_phase("opening the shared analyzer cache");
        if !brokk_bifrost_core::gitblob::has_object_database(repository_root) {
            return Err(StoreError::new(format!(
                "{} is not inside a git repository, so it has no shared analyzer cache to serve immutable revision analysis",
                repository_root.display()
            )));
        }
        let db_path = crate::analyzer::store::analyzer_db_path(repository_root);
        let store = crate::analyzer::store::AnalyzerStore::open_persistent(&db_path).map_err(
            |error| {
                error.context(format!(
                    "opening the shared analyzer cache at {} for immutable revision analysis; this cache is derived state, so remove {} and retry to rebuild it, or set BIFROST_CACHE_ROOT to relocate it off a read-only checkout",
                    db_path.display(),
                    db_path.display(),
                ))
            },
        )?;
        Ok(Self {
            store: Arc::new(store),
            cancellation: cancellation.clone(),
        })
    }

    fn store(&self) -> Arc<crate::analyzer::store::AnalyzerStore> {
        Arc::clone(&self.store)
    }

    /// Publish what the request that opened this cache is doing with it,
    /// until the guard is dropped. The token is the request's own, so the
    /// host reads this back if the budget expires (issue #3170).
    #[doc(hidden)]
    pub fn enter_phase(
        &self,
        phase: impl Into<String>,
    ) -> brokk_bifrost_core::cancellation::PhaseGuard {
        self.cancellation.enter_phase(phase)
    }

    /// Claim the workspace projection rows an immutable image at `image_root`
    /// is about to publish, so they are removed when the request ends.
    #[doc(hidden)]
    pub fn claim_revision_workspace(&self, image_root: &Path) -> WorkspaceProjectionLease {
        WorkspaceProjectionLease::new(
            self.store(),
            // Resolved now, while the export directory still exists:
            // `WorkspaceId::for_root` canonicalizes, and a canonicalization
            // that fails after the directory is unlinked would produce a
            // different identity than the build published under.
            crate::analyzer::store::WorkspaceId::for_root(image_root),
        )
    }
}

/// The workspace projection rows one session publishes into a shared cache,
/// removed when this value drops. Scoped live projects retain this lease in
/// their analyzer contexts; immutable revision exports retain it with the image.
///
/// Query paths mount a workspace's files through `workspace_heads` and
/// `workspace_file_versions`, so a revision image must publish them to be
/// queryable at all -- declaration lookup, package resolution and path-symbol
/// resolution all read those rows. They describe a session's file set rather
/// than a live workspace, though, so leaving them behind would
/// grow the shared cache by one whole file listing per request forever. The
/// parsed blob facts the same build published are keyed by content and stay:
/// those are the reusable asset.
#[doc(hidden)]
pub struct WorkspaceProjectionLease {
    store: Arc<crate::analyzer::store::AnalyzerStore>,
    workspace_id: crate::analyzer::store::WorkspaceId,
}

impl WorkspaceProjectionLease {
    pub(crate) fn new(
        store: Arc<crate::analyzer::store::AnalyzerStore>,
        workspace_id: crate::analyzer::store::WorkspaceId,
    ) -> Self {
        // Ephemeral stores can also be shared by retained snapshots. Their
        // request projections need the same cleanup as persistent stores.
        Self {
            store,
            workspace_id,
        }
    }
}

impl Drop for WorkspaceProjectionLease {
    fn drop(&mut self) {
        if let Err(error) = self.store.delete_workspace_projection(&self.workspace_id) {
            eprintln!(
                "bifrost: could not drop the session's workspace projection rows from the \
                 shared analyzer cache; they will be reclaimed when this language's analysis \
                 generation next changes: {error}"
            );
        }
    }
}

/// A language context reads configuration from its selected SQL revision.
/// Source reads and listing ownership remain with the caller's project. No
/// configuration collection is retained in Rust, and a missing selected input
/// never falls back to a file that happens to remain on disk.
pub(crate) struct SelectedConfigurationProject {
    project_reads: brokk_bifrost_core::analyzer::project_reads::ProjectReadSlot,
    project: Arc<dyn Project>,
    language: Language,
    store: Arc<crate::analyzer::store::AnalyzerStore>,
    snapshot: crate::analyzer::store::WorkspaceSnapshotId,
    _projection_lease: Option<Arc<WorkspaceProjectionLease>>,
}

impl SelectedConfigurationProject {
    pub(crate) fn new(
        project: Arc<dyn Project>,
        language: Language,
        store: Arc<crate::analyzer::store::AnalyzerStore>,
        snapshot: crate::analyzer::store::WorkspaceSnapshotId,
        projection_lease: Option<Arc<WorkspaceProjectionLease>>,
    ) -> Self {
        Self {
            project_reads: brokk_bifrost_core::analyzer::project_reads::ProjectReadSlot::default(),
            project,
            language,
            store,
            snapshot,
            _projection_lease: projection_lease,
        }
    }

    fn is_configuration(&self, path: &Path) -> bool {
        crate::analyzer::store::WorkspaceConfigurationInput::is_native_input(self.language, path)
    }

    fn configuration_source(&self, file: &ProjectFile) -> std::io::Result<Option<Vec<u8>>> {
        self.store
            .selected_configuration_source(
                &self.snapshot,
                &crate::path_utils::rel_path_string(file),
            )
            .map_err(std::io::Error::other)
    }
}

impl Project for SelectedConfigurationProject {
    fn ignore_rules_digest(&self) -> std::io::Result<[u8; 32]> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.ignore_rules(self.as_project()));
        self.project.ignore_rules_digest()
    }
    fn project_read_slot(
        &self,
    ) -> Option<&brokk_bifrost_core::analyzer::project_reads::ProjectReadSlot> {
        Some(&self.project_reads)
    }
    fn install_read_recorder(
        &self,
        capability: brokk_bifrost_core::analyzer::project_reads::ReadCapability,
    ) -> bool {
        self.project.install_read_recorder(capability.clone());
        self.project_reads.install(capability);
        true
    }
    fn selected_module_name(&self, file: &ProjectFile) -> std::io::Result<Option<String>> {
        if !crate::analyzer::store::store_language_support(self.language)
            .expect("selected language has store support")
            .publishes_own_module_file_anchors()
        {
            return self.project.selected_module_name(file);
        }
        self.store
            .selected_module_name(&self.snapshot, &crate::path_utils::rel_path_string(file))
            .map_err(std::io::Error::other)
    }
    fn selected_module_name_with_conn(
        &self,
        conn: &rusqlite::Connection,
        file: &ProjectFile,
    ) -> std::io::Result<Option<String>> {
        if !crate::analyzer::store::store_language_support(self.language)
            .expect("selected language has store support")
            .publishes_own_module_file_anchors()
        {
            return self.project.selected_module_name_with_conn(conn, file);
        }
        crate::analyzer::store::AnalyzerStore::selected_module_name_with_conn(
            conn,
            &self.snapshot,
            &crate::path_utils::rel_path_string(file),
        )
        .map_err(std::io::Error::other)
    }
    fn configuration_source_with_conn(
        &self,
        conn: &rusqlite::Connection,
        path: &Path,
    ) -> std::io::Result<Option<String>> {
        if !self.is_configuration(path) {
            return self.project.configuration_source_with_conn(conn, path);
        }
        let file = ProjectFile::new(self.root(), path);
        let source =
            crate::analyzer::store::AnalyzerStore::selected_configuration_source_with_conn(
                conn,
                &self.snapshot,
                &crate::path_utils::rel_path_string(&file),
            )
            .map_err(std::io::Error::other)?;
        source
            .map(brokk_bifrost_core::analyzer::project::decode_source_bytes)
            .transpose()
    }
    fn root(&self) -> &Path {
        self.project.root()
    }
    fn coverage(&self) -> brokk_bifrost_core::analyzer::project::ProjectCoverage {
        self.project.coverage()
    }
    fn workspace_root_for_file(&self, file: &ProjectFile) -> PathBuf {
        self.project.workspace_root_for_file(file)
    }
    fn analyzer_languages(&self) -> BTreeSet<Language> {
        self.project_reads
            .languages(self.as_project(), || self.project.analyzer_languages())
    }
    fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        self.project.all_files()
    }
    fn all_files_shared(&self) -> std::io::Result<Arc<BTreeSet<ProjectFile>>> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        self.project.all_files_shared()
    }
    fn workspace_file_listing_count(&self) -> usize {
        self.project.workspace_file_listing_count()
    }
    fn analyzable_files(&self, language: Language) -> std::io::Result<BTreeSet<ProjectFile>> {
        let _project_read = brokk_bifrost_core::analyzer::project_reads::listing_read(self);
        self.project.analyzable_files(language)
    }
    fn analyzable_files_from(
        &self,
        files: &BTreeSet<ProjectFile>,
        language: Language,
    ) -> std::io::Result<BTreeSet<ProjectFile>> {
        let _project_read = brokk_bifrost_core::analyzer::project_reads::listing_read(self);
        self.project.analyzable_files_from(files, language)
    }
    fn file_by_rel_path(&self, path: &Path) -> Option<ProjectFile> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.path(self.as_project(), path));
        if !self.is_configuration(path) {
            return self.project.file_by_rel_path(path);
        }
        let file = ProjectFile::new(self.root(), path);
        self.configuration_source(&file)
            .expect("selected configuration must remain readable")
            .map(|_| file)
    }
    fn has_directory(&self, path: &Path) -> bool {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.directory(self.as_project(), path));
        self.project.has_directory(path)
    }
    fn persistence_root(&self) -> Option<&Path> {
        self.project.persistence_root()
    }
    fn is_gitignored(&self, path: &Path) -> bool {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.git_ignore(self.as_project(), path));
        self.project.is_gitignored(path)
    }
    fn is_bifrostignored(&self, path: &Path) -> bool {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.ignore_rules(self.as_project()));
        self.project.is_bifrostignored(path)
    }
    fn invalidate_cached_file_listing(&self) {
        self.project.invalidate_cached_file_listing();
    }
    fn update_cached_listing_for_path(&self, path: &Path) -> bool {
        self.project.update_cached_listing_for_path(path)
    }
    fn read_source(&self, file: &ProjectFile) -> std::io::Result<String> {
        self.project_reads.source(
            self.as_project(),
            file,
            || {
                if !self.is_configuration(file.rel_path()) {
                    return self.project.read_source(file);
                }
                let source = self.configuration_source(file)?.ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!(
                            "{} is absent from selected configuration",
                            file.rel_path().display()
                        ),
                    )
                })?;
                brokk_bifrost_core::analyzer::project::decode_source_bytes(source)
            },
            |source| {
                Some(
                    git2::Oid::hash_object(git2::ObjectType::Blob, source.as_bytes())
                        .expect("hashing project source"),
                )
            },
        )
    }
    fn read_source_limited(
        &self,
        file: &ProjectFile,
        max: usize,
    ) -> std::io::Result<Option<String>> {
        self.project_reads.source(
            self.as_project(),
            file,
            || {
                if !self.is_configuration(file.rel_path()) {
                    return self.project.read_source_limited(file, max);
                }
                self.read_source(file)
                    .map(|source| (source.len() <= max).then_some(source))
            },
            |source| {
                source.as_ref().map(|source| {
                    git2::Oid::hash_object(git2::ObjectType::Blob, source.as_bytes())
                        .expect("hashing project source")
                })
            },
        )
    }
    fn read_file_snapshot(
        &self,
        file: &ProjectFile,
    ) -> std::io::Result<brokk_bifrost_core::analyzer::project::ProjectFileSnapshot> {
        self.project_reads.source(
            self.as_project(),
            file,
            || {
                if !self.is_configuration(file.rel_path()) {
                    self.project.read_file_snapshot(file)
                } else {
                    self.read_source(file).map(|source| {
                        brokk_bifrost_core::analyzer::project::ProjectFileSnapshot::disk(
                            source.into_bytes(),
                        )
                    })
                }
            },
            |snapshot| Some(snapshot.oid()),
        )
    }
    fn read_source_snapshot(
        &self,
        file: &ProjectFile,
    ) -> std::io::Result<brokk_bifrost_core::analyzer::project::ProjectSourceSnapshot> {
        self.project_reads.source(
            self.as_project(),
            file,
            || {
                if !self.is_configuration(file.rel_path()) {
                    return self.project.read_source_snapshot(file);
                }
                self.read_source(file)
                    .map(brokk_bifrost_core::analyzer::project::ProjectSourceSnapshot::disk)
            },
            |source| Some(source.oid()),
        )
    }
    fn read_source_snapshot_limited(
        &self,
        file: &ProjectFile,
        max: usize,
    ) -> std::io::Result<Option<brokk_bifrost_core::analyzer::project::ProjectSourceSnapshot>> {
        self.project_reads.source(
            self.as_project(),
            file,
            || {
                if !self.is_configuration(file.rel_path()) {
                    return self.project.read_source_snapshot_limited(file, max);
                }
                self.read_source_limited(file, max).map(|source| {
                    source.map(brokk_bifrost_core::analyzer::project::ProjectSourceSnapshot::disk)
                })
            },
            |source| source.as_ref().map(|source| source.oid()),
        )
    }
    fn overlay_content(
        &self,
    ) -> Option<Arc<brokk_bifrost_core::analyzer::project::WorkspaceOverlayContent>> {
        let _project_read = self.project_reads.overlays(self.as_project());
        let answer = self.project.overlay_content();
        brokk_bifrost_core::analyzer::project_reads::publish_overlays(&answer);
        answer
    }
    fn has_overlay(&self, file: &ProjectFile) -> bool {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.overlay_membership(self.as_project(), file.rel_path()));
        let answer = self.project.has_overlay(file);
        brokk_bifrost_core::analyzer::project_reads::publish_overlay_membership(answer);
        answer
    }
    fn analysis_generation(&self) -> u64 {
        self.project.analysis_generation()
    }
}

pub struct EmptyAnalyzer {
    project: Arc<dyn Project>,
    build_context: Option<Arc<WorkspaceBuildContext>>,
    project_reads: super::tree_sitter_analyzer::ProjectReadRegistry,
}
impl Clone for EmptyAnalyzer {
    fn clone(&self) -> Self {
        let mut clone = Self::new(Arc::clone(&self.project));
        clone.build_context = self.build_context.clone();
        clone
    }
}
impl EmptyAnalyzer {
    pub fn new(project: Arc<dyn Project>) -> Self {
        let project = super::project_read_facade::with_project_read_slot(project);
        let project_reads = super::tree_sitter_analyzer::ProjectReadRegistry::new(&project);
        Self {
            project,
            project_reads,
            build_context: None,
        }
    }
    fn new_for_workspace(build_context: Arc<WorkspaceBuildContext>) -> Self {
        let mut analyzer = Self::new(Arc::clone(build_context.project()));
        analyzer.build_context = Some(build_context);
        analyzer
    }
    fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        let mut analyzer = Self::new(Arc::clone(&project));
        analyzer.build_context = self
            .build_context
            .as_ref()
            .map(|context| Arc::new(context.clone_with_project(project)));
        analyzer
    }
    pub(crate) fn clone_for_read_attribution(&self) -> Self {
        Self {
            project: Arc::clone(&self.project),
            build_context: self.build_context.clone(),
            project_reads: self.project_reads.clone(),
        }
    }
}

use crate::analyzer::CodeUnitIndex;

impl CodeUnitIndex for EmptyAnalyzer {
    fn enclosing_code_unit(
        &self,
        _file: &crate::analyzer::ProjectFile,
        _range: &crate::analyzer::Range,
    ) -> Option<crate::analyzer::CodeUnit> {
        None
    }

    fn enclosing_code_unit_for_lines(
        &self,
        _file: &crate::analyzer::ProjectFile,
        _start_line: usize,
        _end_line: usize,
    ) -> Option<crate::analyzer::CodeUnit> {
        None
    }

    fn all_declarations(&self) -> Box<dyn Iterator<Item = crate::analyzer::CodeUnit> + '_> {
        Box::new(std::iter::empty())
    }

    fn languages(&self) -> std::collections::BTreeSet<Language> {
        std::collections::BTreeSet::new()
    }

    fn project(&self) -> &dyn Project {
        self.project.as_ref()
    }

    fn get_definitions(&self, _fq_name: &str) -> Vec<crate::analyzer::CodeUnit> {
        Vec::new()
    }

    fn direct_children(
        &self,
        _code_unit: &crate::analyzer::CodeUnit,
    ) -> Vec<crate::analyzer::CodeUnit> {
        Vec::new()
    }

    fn ranges(&self, _code_unit: &crate::analyzer::CodeUnit) -> Vec<crate::analyzer::Range> {
        Vec::new()
    }

    fn get_skeleton(&self, _code_unit: &crate::analyzer::CodeUnit) -> Option<String> {
        None
    }

    fn get_skeleton_header(&self, _code_unit: &crate::analyzer::CodeUnit) -> Option<String> {
        None
    }

    fn get_source(
        &self,
        _code_unit: &crate::analyzer::CodeUnit,
        _include_comments: bool,
    ) -> Option<String> {
        None
    }

    fn get_sources(
        &self,
        _code_unit: &crate::analyzer::CodeUnit,
        _include_comments: bool,
    ) -> std::collections::BTreeSet<String> {
        std::collections::BTreeSet::new()
    }

    fn search_definitions(
        &self,
        _pattern: &str,
        _auto_quote: bool,
    ) -> std::collections::BTreeSet<crate::analyzer::CodeUnit> {
        std::collections::BTreeSet::new()
    }
}

impl IAnalyzer for EmptyAnalyzer {
    fn begin_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        self.project_reads.begin_query(context);
    }
    fn end_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        self.project_reads.end_query(context);
    }
    fn record_read(&self, key: crate::analyzer::ReadKey) {
        self.project_reads.record_read(key);
    }
    fn record_read_receipt(&self, keys: &Arc<[crate::analyzer::ReadKey]>) {
        super::i_analyzer::record_receipt_on_active_ledgers(&self.project_reads.contexts(), keys);
    }
    fn record_read_capture(&self, reads: &crate::analyzer::ReadLedger) {
        super::i_analyzer::record_capture_on_active_ledgers(&self.project_reads.contexts(), reads);
    }
    fn record_unattributed_reads(&self, count: usize) {
        self.project_reads.record_unattributed_reads(count);
    }
    fn records_query_reads(&self) -> bool {
        true
    }

    fn read_ledger_attached(&self) -> bool {
        self.project_reads.read_ledger_attached()
    }
    fn read_ledger_contexts(&self) -> Vec<Arc<crate::analyzer::AnalyzerQueryContext>> {
        self.project_reads.contexts()
    }

    fn current_thread_read_ledger(&self) -> Option<Arc<crate::analyzer::ReadLedger>> {
        super::i_analyzer::current_thread_read_ledger()
    }

    fn update(
        &self,
        _changed_files: &std::collections::BTreeSet<crate::analyzer::ProjectFile>,
    ) -> Self
    where
        Self: Sized,
    {
        self.clone()
    }

    fn update_all(&self) -> Self
    where
        Self: Sized,
    {
        self.clone()
    }

    fn is_access_expression(
        &self,
        _file: &crate::analyzer::ProjectFile,
        _start_byte: usize,
        _end_byte: usize,
    ) -> bool {
        false
    }

    fn find_nearest_declaration(
        &self,
        _file: &crate::analyzer::ProjectFile,
        _start_byte: usize,
        _end_byte: usize,
        _ident: &str,
    ) -> Option<crate::analyzer::DeclarationInfo> {
        None
    }
}

#[derive(Clone)]
pub enum WorkspaceAnalyzer {
    Empty(EmptyAnalyzer),
    Multi(Box<MultiAnalyzer>),
}

/// Caller-owned state needed to activate explicitly configured dependency packs.
/// Constructing a workspace never opens a semantic-pack catalog or discovers an
/// ecosystem; hosts must opt in by supplying this context.
#[derive(Clone, Copy)]
pub struct DependencyPackWorkspaceContext<'a> {
    pub catalog: &'a SemanticPackCatalog,
    pub persistence: Option<SemanticModelActivationPersistence<'a>>,
    pub activation: &'a SemanticModelActivationRequest,
    pub limits: DependencyPackLimits,
    pub cancellation: &'a crate::CancellationToken,
}

pub type PythonSemanticModelWorkspaceContext<'a> = DependencyPackWorkspaceContext<'a>;

#[derive(Debug)]
pub struct PythonSemanticModelActivationOutcome {
    pub discovery: DependencyDiscoveryOutcome,
    pub preparation: Option<DependencyPackPreparationOutcome>,
    pub runtime: Option<SemanticModelRuntimeOutcome>,
}

/// One dependency ecosystem whose exact local evidence a host can activate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DependencyPackEcosystem {
    Jvm,
    DotNet,
    Npm,
    Python,
    Go,
    Cargo,
    Ruby,
    Composer,
    Cpp,
}

impl DependencyPackEcosystem {
    /// Every ecosystem a host can activate. Hosts iterate this to select the
    /// ecosystems their workspace needs.
    pub const ALL: [Self; 9] = [
        Self::Jvm,
        Self::DotNet,
        Self::Npm,
        Self::Python,
        Self::Go,
        Self::Cargo,
        Self::Ruby,
        Self::Composer,
        Self::Cpp,
    ];

    pub fn languages(self) -> &'static [Language] {
        match self {
            Self::Jvm => &[Language::Java, Language::Kotlin, Language::Scala],
            Self::DotNet => &[Language::CSharp],
            Self::Npm => &[Language::JavaScript, Language::TypeScript],
            Self::Python => &[Language::Python],
            Self::Go => &[Language::Go],
            Self::Cargo => &[Language::Rust],
            Self::Ruby => &[Language::Ruby],
            Self::Composer => &[Language::Php],
            Self::Cpp => &[Language::Cpp],
        }
    }

    /// Stable lowercase label used by workspace configuration documents
    /// (`.bifrost/packs.json`) and activation reporting.
    pub fn label(self) -> &'static str {
        match self {
            Self::Jvm => "jvm",
            Self::DotNet => "dotnet",
            Self::Npm => "npm",
            Self::Python => "python",
            Self::Go => "go",
            Self::Cargo => "cargo",
            Self::Ruby => "ruby",
            Self::Composer => "composer",
            Self::Cpp => "cpp",
        }
    }

    /// Parse one configuration-document label back into its ecosystem.
    pub fn from_label(label: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|ecosystem| ecosystem.label() == label)
    }

    /// Base names of the files whose change can invalidate this ecosystem's
    /// published pack proof (#1628).
    ///
    /// A host watches these names, calls
    /// [`WorkspaceAnalyzer::invalidate_dependency_pack_state`] for the matching
    /// ecosystems, and re-activates. The list covers both the files a resolver
    /// reads directly and the conventional manifests a host names as evidence
    /// for the evidence-driven ecosystems (Cargo, Ruby, Composer, Python),
    /// whose exact paths are configuration rather than convention. Naming a
    /// file that a given configuration does not read costs one redundant
    /// activation; missing one would leave stale proof in place, so this table
    /// errs toward invalidating.
    ///
    /// Most of discovery is reading these files. Two ecosystems can do more
    /// than read: JVM discovery in `JvmDependencyDiscoveryMode::OfflineBuildTools`
    /// runs Maven and Gradle, and Go discovery runs `go list`. Each resolver
    /// states which through [`DependencyResolver::bounds`], because this
    /// sentence used to claim no resolver ran a package manager and was wrong
    /// for exactly those two (#2442).
    pub fn dependency_inputs(self) -> &'static [&'static str] {
        self.resolver().dependency_inputs()
    }

    /// Whether a revision path must accompany this ecosystem's source files
    /// in an immutable file-dependency image.
    ///
    /// This is the reader-side predicate, not merely the manifest basename
    /// list used for dependency-pack invalidation. JVM and .NET analyzers also
    /// consume patterned build inputs such as arbitrary `*.gradle`, `*.props`,
    /// and `*.targets` files. Keeping the predicate here gives workspace
    /// construction and revision export one source of truth.
    #[doc(hidden)]
    pub fn is_file_dependency_input(self, path: &Path) -> bool {
        crate::analyzer::languages::language_support_for_hook(
            self.languages()[0],
            "is_file_dependency_input",
        )
        .expect("dependency ecosystem primary language support")
        .is_file_dependency_input(path)
    }

    /// The resolver that discovers this ecosystem's dependencies, paired with
    /// the adapter that turns them into packs.
    ///
    /// This registry replaced a hard-coded match in
    /// [`WorkspaceAnalyzer::activate_dependency_packs`] that restated the
    /// resolver-to-adapter pairing inline, which is how the activation loop
    /// came to hold per-ecosystem limit adjustments as well.
    pub(crate) fn resolver(self) -> &'static dyn DependencyResolver {
        crate::analyzer::languages::language_support_for_hook(
            self.languages()[0],
            "dependency_pack_resolver",
        )
        .expect("dependency ecosystem primary language support")
        .dependency_pack_resolver()
        .expect("dependency ecosystem resolver")
    }
}

/// The bounds a resolver that only reads files declares: no process, no clock
/// of its own, and a walk bounded by the project's file listing and
/// `DependencyPackLimits`.
#[doc(hidden)]
pub const READS_FILES_ONLY: DependencyResolverBounds = DependencyResolverBounds {
    max_files_walked: None,
    max_metadata_bytes: None,
    subprocess: SubprocessPolicy::Forbidden,
    wall_clock: None,
};

#[doc(hidden)]
pub fn build_tool_dependency_resolver_bounds(
    timeout: Option<std::time::Duration>,
    max_metadata_bytes: Option<u64>,
) -> DependencyResolverBounds {
    DependencyResolverBounds {
        max_metadata_bytes,
        subprocess: if timeout.is_some() {
            SubprocessPolicy::OfflineBuildTools
        } else {
            SubprocessPolicy::Forbidden
        },
        wall_clock: timeout,
        ..READS_FILES_ONLY
    }
}

#[derive(Debug)]
pub struct DependencyPackEcosystemOutcome {
    pub ecosystem: DependencyPackEcosystem,
    pub discovery: DependencyDiscoveryOutcome,
    pub preparation: Option<DependencyPackPreparationOutcome>,
}

/// Result of one host-owned activation transaction.
#[derive(Debug)]
pub struct DependencyPackActivationOutcome {
    pub ecosystems: Vec<DependencyPackEcosystemOutcome>,
    pub runtime: Option<SemanticModelRuntimeOutcome>,
    /// Hosts must refresh published diagnostics when this value is true.
    pub diagnostic_refresh_required: bool,
}

struct DependencyPackPublicationEvidence {
    dependencies: Vec<(Box<[Language]>, DependencyDiscoveryEvidence)>,
    jdk_artifacts: Option<HashMap<PathBuf, SemanticModelActivationEvidence>>,
    python_runtime:
        Option<crate::analyzer::store::python_runtime::PythonRuntimeProviderPublication>,
}

/// Correlate a configured source toolchain with the exact pack produced from
/// that home's artifacts. Discovery IDs are run-local join keys; only the
/// prepared evidence's artifact digest authorizes later call applicability.
#[doc(hidden)]
pub fn prepared_jdk_artifacts_for_source_bindings(
    config: &AnalyzerConfig,
    project_root: &Path,
    outcomes: &[DependencyPackEcosystemOutcome],
) -> Option<HashMap<PathBuf, SemanticModelActivationEvidence>> {
    Language::ANALYZABLE
        .iter()
        .filter_map(|&language| crate::analyzer::languages::language_support(language))
        .find_map(|support| support.dependency_source_artifacts(config, project_root, outcomes))
}

/// The installed-pack stage's activation: the published interim outcome plus
/// every dependency whose exact acquisition remains for the full stage.
#[derive(Debug)]
pub struct InstalledDependencyPackActivationOutcome {
    pub outcome: DependencyPackActivationOutcome,
    pub pending: Vec<PendingDependencyPackAcquisition>,
}

impl DependencyPackActivationOutcome {
    pub fn complete(&self) -> bool {
        self.ecosystems.iter().all(|outcome| {
            dependency_discovery_preparation_complete(
                &outcome.discovery,
                outcome.preparation.as_ref(),
            )
        }) && self
            .runtime
            .as_ref()
            .is_some_and(|runtime| matches!(runtime, SemanticModelRuntimeOutcome::Ready { .. }))
    }
}

impl PythonSemanticModelActivationOutcome {
    pub fn complete(&self) -> bool {
        dependency_discovery_preparation_complete(&self.discovery, self.preparation.as_ref())
            && self
                .runtime
                .as_ref()
                .is_some_and(|runtime| matches!(runtime, SemanticModelRuntimeOutcome::Ready { .. }))
    }
}

fn dependency_discovery_preparation_complete(
    discovery: &DependencyDiscoveryOutcome,
    preparation: Option<&DependencyPackPreparationOutcome>,
) -> bool {
    discovery.complete && preparation.is_some_and(|preparation| preparation.complete)
}

fn python_runtime_publication(
    workspace: &WorkspaceAnalyzer,
    config: &AnalyzerConfig,
    activation: &mut SemanticModelActivationRequest,
    context: &DependencyPackWorkspaceContext<'_>,
) -> Result<
    Option<crate::analyzer::store::python_runtime::PythonRuntimeProviderPublication>,
    StoreError,
> {
    for support in crate::analyzer::languages::registered_language_supports() {
        if let Some(publication) =
            support.publish_dependency_runtime(workspace, config, activation, context)?
        {
            return Ok(Some(publication));
        }
    }
    Ok(None)
}

impl WorkspaceAnalyzer {
    fn from_updated_multi(analyzer: MultiAnalyzer) -> Self {
        if analyzer.delegates().is_empty()
            && let Some(build_context) = analyzer.workspace_build_context()
        {
            return Self::Empty(EmptyAnalyzer::new_for_workspace(build_context));
        }
        Self::Multi(Box::new(analyzer))
    }

    #[doc(hidden)]
    pub fn resolve_dependency_discovery(
        &self,
        ecosystem: DependencyPackEcosystem,
        config: &AnalyzerConfig,
        limits: &DependencyPackLimits,
        cancellation: &crate::CancellationToken,
    ) -> DependencyDiscoveryOutcome {
        crate::analyzer::languages::language_support_for_hook(
            ecosystem.languages()[0],
            "resolve_workspace_dependencies",
        )
        .expect("dependency ecosystem primary language support")
        .resolve_workspace_dependencies(self, config, limits, cancellation)
    }

    fn discover_dependency_pack_ecosystem(
        &self,
        ecosystem: DependencyPackEcosystem,
        config: &AnalyzerConfig,
        context: &DependencyPackWorkspaceContext<'_>,
    ) -> (
        &'static dyn DependencyResolver,
        DependencyPackLimits,
        DependencyDiscoveryOutcome,
    ) {
        let resolver = ecosystem.resolver();
        let mut limits = context.limits;
        resolver.adjust_limits(config, &mut limits);
        let discovery = {
            let _scope = crate::profiling::scope_with(|| {
                format!("semantic_pack.discover[{}]", ecosystem.label())
            });
            self.resolve_dependency_discovery(ecosystem, config, &limits, context.cancellation)
        };
        (resolver, limits, discovery)
    }

    /// Discover, prepare, and publish exact local dependency packs as one
    /// analyzer-generation transaction. Diagnostic requests only read the
    /// published result and never call this host-owned method.
    ///
    /// Failure is per ecosystem (#2442). An incomplete preparation contributes
    /// the exact evidence of every pack it did prepare while the whole outcome
    /// remains incomplete. This lets a globally partial generated pack answer
    /// a scoped claim it proves (for example, one complete callable family)
    /// without turning an unprepared dependency or an omitted declaration into
    /// an absence proof. An incomplete preparation with no evidence still
    /// contributes nothing, and siblings continue to activate. Only
    /// cancellation stops the transaction, because a cancelled token says the
    /// caller is gone rather than that one ecosystem is unreadable.
    ///
    /// Discovery completeness is a fact about the dependency set, not a gate
    /// on preparing it (#2887). An incomplete discovery still prepares and
    /// activates the dependencies it did resolve with exact evidence, so one
    /// Maven coordinate missing from `~/.m2` no longer withholds the JDK
    /// standard-library pack whose toolchain evidence resolved exactly. The
    /// unresolved coordinates stay unindexed and the incompleteness travels
    /// on the outcome and on the published `DependencyDiscoveryEvidence`,
    /// whose `truncated` flag is what keeps a name an unresolved dependency
    /// would have answered unproven rather than proved absent.
    ///
    /// Publication still requires something to publish: when every requested
    /// ecosystem failed, nothing is acquired and no host is asked to refresh.
    pub fn activate_dependency_packs(
        &self,
        config: &AnalyzerConfig,
        ecosystems: &[DependencyPackEcosystem],
        context: DependencyPackWorkspaceContext<'_>,
    ) -> DependencyPackActivationOutcome {
        let mut outcomes = Vec::with_capacity(ecosystems.len());
        let mut activation = context.activation.clone();
        let mut publication_evidence = Vec::with_capacity(ecosystems.len());
        let mut cancelled = false;

        // Dependency-pack work runs before the parse phase and is attributed to
        // the workspace as a whole, so a slow ecosystem looks like slow startup
        // with no further detail. The discover/prepare span pair is per
        // ecosystem on purpose: it names which resolver is spending the time and
        // separates discovery, which walks the workspace, from preparation,
        // which reads and generates packs.
        for ecosystem in ecosystems.iter().copied() {
            let (resolver, limits, discovery) =
                self.discover_dependency_pack_ecosystem(ecosystem, config, &context);
            activation.approximate_standard_libraries.extend(
                discovery
                    .standard_library_pack_expectations()
                    .filter(|expectation| expectation.approximate)
                    .map(|expectation| ApproximateSemanticModelExpectation {
                        language: expectation.language.config_label().to_owned(),
                        ecosystem: ecosystem.label().to_owned(),
                        pack_id: expectation.pack_id.to_owned(),
                    }),
            );
            if discovery.cancelled {
                cancelled = true;
                outcomes.push(DependencyPackEcosystemOutcome {
                    ecosystem,
                    discovery,
                    preparation: None,
                });
                break;
            }
            let preparation = {
                let _scope = crate::profiling::scope_with(|| {
                    format!(
                        "semantic_pack.prepare[{},{} deps]",
                        ecosystem.label(),
                        discovery.dependencies.len()
                    )
                });
                resolver.prepare(
                    config,
                    context.catalog,
                    &discovery.dependencies,
                    &limits,
                    Some(context.cancellation),
                )
            };
            if preparation.cancelled {
                cancelled = true;
                outcomes.push(DependencyPackEcosystemOutcome {
                    ecosystem,
                    discovery,
                    preparation: Some(preparation),
                });
                break;
            }
            if preparation.complete || !preparation.evidence.is_empty() {
                activation
                    .evidence
                    .extend(preparation.evidence.iter().cloned());
                publication_evidence.push((
                    ecosystem.languages().to_vec().into_boxed_slice(),
                    DependencyDiscoveryEvidence::from_outcome(&discovery),
                ));
            }
            outcomes.push(DependencyPackEcosystemOutcome {
                ecosystem,
                discovery,
                preparation: Some(preparation),
            });
        }

        self.finalize_dependency_pack_activation(
            config,
            activation,
            publication_evidence,
            outcomes,
            cancelled,
            ecosystems.is_empty(),
            &context,
        )
    }

    /// The installed-pack stage of [`Self::activate_dependency_packs`]: run
    /// the same per-ecosystem discovery, resolve every discovered dependency
    /// against the packs already installed in the catalog, and publish that
    /// overlay, all without reading dependency artifacts or fetching,
    /// verifying, extracting, or generating anything (issue #3401, the #3372
    /// family).
    ///
    /// The outcome is the session's interim activation: its overlay is real,
    /// but every dependency the installed selection could not settle is
    /// returned in `pending` with its ecosystem, so the host can keep the
    /// expensive acquisition on a background stage and mark answers produced
    /// in the meantime. The full stage re-runs discovery and preparation from
    /// the same inputs, so what it publishes supersedes this stage exactly.
    pub fn activate_installed_dependency_packs(
        &self,
        config: &AnalyzerConfig,
        ecosystems: &[DependencyPackEcosystem],
        context: DependencyPackWorkspaceContext<'_>,
    ) -> InstalledDependencyPackActivationOutcome {
        let mut outcomes = Vec::with_capacity(ecosystems.len());
        let mut activation = context.activation.clone();
        let mut publication_evidence = Vec::with_capacity(ecosystems.len());
        let mut pending = Vec::new();
        let mut cancelled = false;

        for ecosystem in ecosystems.iter().copied() {
            let (resolver, limits, discovery) =
                self.discover_dependency_pack_ecosystem(ecosystem, config, &context);
            activation.approximate_standard_libraries.extend(
                discovery
                    .standard_library_pack_expectations()
                    .filter(|expectation| expectation.approximate)
                    .map(|expectation| ApproximateSemanticModelExpectation {
                        language: expectation.language.config_label().to_owned(),
                        ecosystem: ecosystem.label().to_owned(),
                        pack_id: expectation.pack_id.to_owned(),
                    }),
            );
            if discovery.cancelled {
                cancelled = true;
                outcomes.push(DependencyPackEcosystemOutcome {
                    ecosystem,
                    discovery,
                    preparation: None,
                });
                break;
            }
            let preparation = {
                let _scope = crate::profiling::scope_with(|| {
                    format!(
                        "semantic_pack.prepare_installed[{},{} deps]",
                        ecosystem.label(),
                        discovery.dependencies.len()
                    )
                });
                prepare_installed_dependency_packs(
                    context.catalog,
                    resolver.adapter(),
                    &discovery.dependencies,
                    &limits,
                    Some(context.cancellation),
                )
            };
            if preparation.outcome.cancelled {
                cancelled = true;
                outcomes.push(DependencyPackEcosystemOutcome {
                    ecosystem,
                    discovery,
                    preparation: Some(preparation.outcome),
                });
                break;
            }
            pending.extend(preparation.pending.into_iter().map(|dependency_id| {
                PendingDependencyPackAcquisition {
                    ecosystem,
                    dependency_id,
                }
            }));
            if preparation.outcome.complete || !preparation.outcome.evidence.is_empty() {
                activation
                    .evidence
                    .extend(preparation.outcome.evidence.iter().cloned());
                publication_evidence.push((
                    ecosystem.languages().to_vec().into_boxed_slice(),
                    DependencyDiscoveryEvidence::from_outcome(&discovery),
                ));
            }
            outcomes.push(DependencyPackEcosystemOutcome {
                ecosystem,
                discovery,
                preparation: Some(preparation.outcome),
            });
        }

        let outcome = self.finalize_dependency_pack_activation(
            config,
            activation,
            publication_evidence,
            outcomes,
            cancelled,
            ecosystems.is_empty(),
            &context,
        );
        InstalledDependencyPackActivationOutcome { outcome, pending }
    }

    // These are the distinct values consumed directly by the shared finalization tail.
    #[allow(clippy::too_many_arguments)]
    fn finalize_dependency_pack_activation(
        &self,
        config: &AnalyzerConfig,
        mut activation: SemanticModelActivationRequest,
        dependencies: Vec<(Box<[Language]>, DependencyDiscoveryEvidence)>,
        outcomes: Vec<DependencyPackEcosystemOutcome>,
        cancelled: bool,
        ecosystems_empty: bool,
        context: &DependencyPackWorkspaceContext<'_>,
    ) -> DependencyPackActivationOutcome {
        let jdk_artifacts = prepared_jdk_artifacts_for_source_bindings(
            config,
            self.analyzer().project().root(),
            &outcomes,
        );
        let python_runtime = match python_runtime_publication(
            self,
            config,
            &mut activation,
            context,
        ) {
            Ok(publication) => publication,
            Err(error) => {
                self.invalidate_dependency_pack_state(&[DependencyPackEcosystem::Python]);
                return DependencyPackActivationOutcome {
                    ecosystems: outcomes,
                    runtime: Some(SemanticModelRuntimeOutcome::Unavailable(
                        crate::analyzer::semantic_model::SemanticModelActivationReport {
                            explanations: vec![crate::analyzer::semantic_model::SemanticModelActivationExplanation {
                                manifest_digest: String::new(),
                                pack_id: None,
                                shard_id: String::new(),
                                source_kind: crate::analyzer::semantic_model::CatalogPackSourceKind::Embedded,
                                source_id: String::new(),
                                status: crate::analyzer::semantic_model::SemanticModelActivationStatus::Unavailable,
                                reason: format!("Python runtime provider publication failed: {error}"),
                            }],
                            ..Default::default()
                        },
                    )),
                    diagnostic_refresh_required: false,
                };
            }
        };
        self.publish_dependency_pack_activation(
            activation,
            DependencyPackPublicationEvidence {
                dependencies,
                jdk_artifacts,
                python_runtime,
            },
            outcomes,
            cancelled,
            ecosystems_empty,
            context,
        )
    }

    /// Publish one assembled dependency activation into this analyzer's
    /// overlay: the shared tail of [`Self::activate_dependency_packs`] and
    /// [`Self::activate_installed_dependency_packs`]. An activation with
    /// nothing to publish leaves any previous publication untouched.
    fn publish_dependency_pack_activation(
        &self,
        mut activation: SemanticModelActivationRequest,
        publication: DependencyPackPublicationEvidence,
        outcomes: Vec<DependencyPackEcosystemOutcome>,
        cancelled: bool,
        ecosystems_empty: bool,
        context: &DependencyPackWorkspaceContext<'_>,
    ) -> DependencyPackActivationOutcome {
        if cancelled
            || (!ecosystems_empty
                && publication.dependencies.is_empty()
                && activation.evidence.is_empty()
                && activation.approximate_standard_libraries.is_empty())
        {
            return DependencyPackActivationOutcome {
                ecosystems: outcomes,
                runtime: None,
                diagnostic_refresh_required: false,
            };
        }

        activation.evidence.sort();
        activation.evidence.dedup();
        let runtime = {
            let _scope = crate::profiling::scope("semantic_pack.acquire_active");
            acquire_active_semantic_models_with_runtime_artifacts(
                self.analyzer(),
                context.catalog,
                context.persistence,
                &activation,
                Some(&publication.dependencies),
                RuntimeArtifactPublication {
                    jdk_artifacts_by_configured_home: publication.jdk_artifacts.as_ref(),
                    python_runtime: publication.python_runtime.as_ref(),
                },
                context.cancellation,
            )
        };
        let diagnostic_refresh_required =
            matches!(runtime, SemanticModelRuntimeOutcome::Ready { .. });
        DependencyPackActivationOutcome {
            ecosystems: outcomes,
            runtime: Some(runtime),
            diagnostic_refresh_required,
        }
    }

    /// Invalidate published proof after a host observes changed dependency inputs.
    pub fn invalidate_dependency_pack_state(&self, ecosystems: &[DependencyPackEcosystem]) -> bool {
        let languages = ecosystems
            .iter()
            .flat_map(|ecosystem| ecosystem.languages().iter().copied())
            .collect::<Vec<_>>();
        self.analyzer()
            .snapshot_caches()
            .is_some_and(|caches| caches.invalidate_dependency_pack_state(&languages))
    }

    /// Discover, prepare, and publish Python environment facts into this
    /// workspace's existing snapshot. A disabled environment is a successful
    /// no-op; cancellation and unavailable preparation deliberately leave any
    /// previously published overlay unchanged.
    ///
    /// Deliberately Python-specific public workspace API, not a language
    /// capability: hosts call it by name to activate a Python interpreter's
    /// packs. Discovery dispatches through the language support registry.
    pub fn activate_python_environment_packs(
        &self,
        config: &AnalyzerConfig,
        context: PythonSemanticModelWorkspaceContext<'_>,
    ) -> PythonSemanticModelActivationOutcome {
        let outcome =
            self.activate_dependency_packs(config, &[DependencyPackEcosystem::Python], context);
        let mut ecosystems = outcome.ecosystems.into_iter();
        let ecosystem = ecosystems
            .next()
            .expect("Python activation always records its ecosystem outcome");
        debug_assert!(ecosystems.next().is_none());
        PythonSemanticModelActivationOutcome {
            discovery: ecosystem.discovery,
            preparation: ecosystem.preparation,
            runtime: outcome.runtime,
        }
    }

    /// Test hook to retain a dependency-discovery summary for trace-boundary
    /// assertions without rerunning dependency discovery from a query.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn retain_dependency_discovery_evidence(
        &self,
        languages: &[Language],
        discovery: &DependencyDiscoveryOutcome,
    ) {
        if discovery.cancelled {
            return;
        }
        if let Some(caches) = self.analyzer().snapshot_caches() {
            caches.retain_dependency_discovery_evidence(
                languages,
                DependencyDiscoveryEvidence::from_outcome(discovery),
            );
        }
    }
    pub fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        let project = super::project_read_facade::with_project_read_slot(project);
        match self {
            Self::Empty(analyzer) => Self::Empty(analyzer.clone_with_project(project)),
            Self::Multi(analyzer) => Self::Multi(Box::new(analyzer.clone_with_project(project))),
        }
    }

    /// Clone this analyzer onto a frozen view of the same source generation for
    /// background index warming. Unlike a request overlay clone, the result
    /// shares the generation-owned cells that the warmer is expected to fill.
    #[doc(hidden)]
    pub fn clone_for_index_warm(&self, project: Arc<dyn Project>) -> Self {
        debug_assert_eq!(self.analyzer().project().root(), project.root());
        debug_assert_eq!(
            self.analyzer().project().analysis_generation(),
            project.analysis_generation(),
            "an index-warm project must describe the analyzer's source generation"
        );
        match self {
            Self::Empty(analyzer) => Self::Empty(analyzer.clone_with_project(project)),
            Self::Multi(analyzer) => Self::Multi(Box::new(analyzer.clone_for_index_warm(project))),
        }
    }

    /// Language-restricted [`Self::build_ephemeral_footgun`], and a footgun for
    /// the same reason: read that function's doc before calling this one. The
    /// persisted equivalent is [`Self::build_persisted_for_languages`].
    pub fn build_ephemeral_for_languages_footgun(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        languages: &BTreeSet<Language>,
    ) -> Result<Self, StoreError> {
        let store_context = super::tree_sitter_analyzer::ephemeral_store_context_with_config(
            project.as_ref(),
            &config,
        )?;
        Self::build_filtered(project, config, Some(languages), store_context, None)
    }

    /// Build an analyzer over a delete-on-drop temporary store, no matter what
    /// the project's [`Project::persistence_root`] says.
    ///
    /// Named a footgun because it usually is one. An ephemeral store forfeits
    /// all reuse: every run re-parses and re-persists the whole world into a
    /// database that is deleted when the analyzer drops, so the next run starts
    /// from nothing. [`Self::build_persisted`] and its siblings instead reuse
    /// content-addressed blobs across runs, and take the per-cache build lock
    /// across the whole reconciliation so concurrent builders on one database
    /// do not each parse the same missing set. A persisted request over a
    /// project with no [`Project::persistence_root`] is a hard error rather
    /// than a quiet downgrade, so this family of functions is the only door to
    /// a throwaway store and taking it is always a stated choice. Prefer
    /// persisted unless one of the following is your actual reason:
    ///
    /// - Session-only parse-error evidence. Tree-sitter ERROR nodes exist only
    ///   on a cold parse, so `IAnalyzer::parse_errors` is complete for the whole
    ///   workspace only when nothing was served from a warm cache.
    /// - An explicit do-not-write-here operator opt-out, for a checkout you do
    ///   not own and must leave byte-identical.
    /// - Deliberate cold-build measurement.
    ///
    /// Tests are fine: a hermetic small fixture wants no cache to survive it.
    ///
    /// An immutable revision image is no longer such a case, however few of the
    /// revision's files one request selected. It goes through
    /// [`Self::build_revision_image`] and shares the repository's
    /// content-addressed cache, because a fact keyed by blob id, language
    /// storage key and generation describes those bytes for every consumer, not
    /// just the request that parsed them, and a selection of files cannot make
    /// a blob's facts partial. The workspace rows such a build publishes name a
    /// self-deleting export directory and are removed by the caller's
    /// [`SharedAnalyzerCache::claim_revision_workspace`] lease, which is the
    /// part an ordinary persisted live build cannot have. A scoped live project
    /// instead uses [`Self::build_scoped_persisted`], whose unique session
    /// identity isolates its partial projection from the live workspace.
    /// Revision analysis that explicitly supplies no shared cache, including
    /// the current diff worktree-image path, still takes this ephemeral door.
    pub fn build_ephemeral_footgun(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
    ) -> Result<Self, StoreError> {
        let store_context = super::tree_sitter_analyzer::ephemeral_store_context_with_config(
            project.as_ref(),
            &config,
        )?;
        Self::build_filtered(project, config, None, store_context, None)
    }

    /// Build against an explicitly supplied store to exercise reader lifetimes.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn build_with_store_context_for_test(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        store_context: crate::analyzer::AnalyzerStoreContext,
    ) -> Result<Self, StoreError> {
        Self::build_filtered(project, config, None, store_context, None)
    }

    /// Share the rooted project's persistent blob cache while isolating its
    /// selected file set in a session projection. Cache location and build
    /// serialization are the same as for [`Self::build_persisted`], but the
    /// live workspace's identity is never used to publish this partial view.
    ///
    /// Every analyzer context, including clones and lazy language delegates,
    /// holds the projection lease. The final drop removes only session rows;
    /// complete blob facts remain reusable. Store errors propagate, and this
    /// does not change [`Project::persistence_root`] for a scoped project.
    pub fn build_scoped_persisted(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
    ) -> Result<Self, StoreError> {
        let store_context = super::tree_sitter_analyzer::scoped_store_context_with_config(
            project.as_ref(),
            &config,
        )?;
        Self::build_filtered(project, config, None, store_context, None)
    }

    /// Build an analyzer over one immutable revision image, publishing its
    /// parsed facts into the repository's shared content-addressed cache.
    ///
    /// The cache is keyed by Git blob id and language storage key, so the
    /// blobs of this revision that the cache has already seen are read rather
    /// than parsed, and the ones parsed here warm the cache for every later
    /// consumer. [`Self::build_filtered`] holds the per-cache build lock across
    /// the whole reconciliation, exactly as a worktree build does, so two
    /// builders never each parse the same missing set.
    ///
    /// `cache` of `None` means the caller deliberately wants this image kept
    /// out of the shared cache, not that the host lacks one: a cache that will
    /// not open is reported, never worked around. The case that reaches here is
    /// a worktree image, whose root is a live project root and whose file set
    /// is partial, so publishing under that workspace identity would replace
    /// the workspace's own picture of itself. The build then runs against an
    /// ephemeral store, which returns the same answers and differs only in
    /// having to parse every blob.
    ///
    /// `languages` of `Some` restricts which parsers run. A file graph has no
    /// edges between distinct usage ecosystems, so a caller that already knows
    /// the seed ecosystems retains the complete revision's files while skipping
    /// parsers whose facts cannot enter the requested reverse walk.
    ///
    /// `blobs` is the image's own inventory of Git blob ids, so identity
    /// resolution reads the ids the export's tree walk already produced instead
    /// of re-hashing the bytes it just wrote.
    ///
    /// With a cache, the caller must hold a
    /// [`SharedAnalyzerCache::claim_revision_workspace`] claim for `project`'s
    /// root for as long as the analyzer is used, so the workspace projection
    /// rows this build publishes for a temp-directory root do not outlive the
    /// request.
    #[doc(hidden)]
    pub fn build_revision_image(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        languages: Option<&BTreeSet<Language>>,
        cache: Option<&SharedAnalyzerCache>,
        blobs: Arc<RevisionBlobIdentities>,
    ) -> Result<Self, StoreError> {
        let mut store_context = match cache {
            Some(cache) => {
                let mut context =
                    crate::analyzer::revision_image_store_context(project.as_ref(), cache.store());
                // Only a shared cache has a build lock to wait on, and the
                // cache is what carries the request's cancellation here.
                context.cancellation = cache.cancellation.clone();
                context
            }
            None => super::tree_sitter_analyzer::ephemeral_store_context_with_config(
                project.as_ref(),
                &config,
            )?,
        };
        store_context.revision_blobs = Some(blobs);
        Self::build_filtered(project, config, languages, store_context, None)
    }

    /// Build an analyzer and retain the tier crossings paid while constructing
    /// it. The observer is finished before the result is returned, so later
    /// incremental work cannot contaminate the open report.
    ///
    /// A footgun for the reason given on [`Self::build_ephemeral_footgun`], with
    /// one narrowing: measuring the tier crossings of a cold build is itself a
    /// legitimate reason to want one. If you are measuring anything else, use
    /// [`Self::build_persisted_with_tier_access`].
    fn build_with_tier_access(
        build: impl FnOnce(&Arc<AnalyzerBuildTierAccess>) -> Result<Self, StoreError>,
    ) -> Result<(Self, Arc<AnalyzerBuildTierAccess>), StoreError> {
        let observer = Arc::new(AnalyzerBuildTierAccess::new_active());
        let workspace = build(&observer)?;
        observer.finish();
        Ok((workspace, observer))
    }

    #[doc(hidden)]
    pub fn build_ephemeral_with_tier_access_footgun(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
    ) -> Result<(Self, Arc<AnalyzerBuildTierAccess>), StoreError> {
        Self::build_with_tier_access(|observer| {
            let mut store_context =
                super::tree_sitter_analyzer::ephemeral_store_context_with_config(
                    project.as_ref(),
                    &config,
                )?;
            store_context.build_tier_access = Arc::clone(observer);
            Self::build_filtered(project, config, None, store_context, None)
        })
    }

    pub fn build_persisted(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
    ) -> Result<Self, StoreError> {
        Self::build_persisted_inner(project, config, None, true, None)
    }

    /// Language-restricted [`Self::build_persisted`]: the same shared
    /// content-addressed cache, with only the requested languages' parsers run.
    ///
    /// Restricting languages narrows which per-language delegates are built. It
    /// does not narrow what stays in the cache: garbage collection reaches from
    /// git refs and the uncommitted working set, which say nothing about
    /// language, so an unselected language's facts survive this build and a
    /// later whole-workspace build reuses them.
    pub fn build_persisted_for_languages(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        languages: &BTreeSet<Language>,
    ) -> Result<Self, StoreError> {
        let store_context = super::tree_sitter_analyzer::persistent_store_context_with_config(
            project.as_ref(),
            &config,
            true,
        )?;
        Self::build_filtered(project, config, Some(languages), store_context, None)
    }

    /// Build a persisted analyzer whose cache is collected only when the host
    /// explicitly requests it.
    pub fn build_persisted_without_automatic_gc(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
    ) -> Result<Self, StoreError> {
        Self::build_persisted_inner(project, config, None, false, None)
    }

    /// Build a progress-reporting persisted analyzer whose cache is collected
    /// only when the host explicitly requests it.
    pub fn build_persisted_without_automatic_gc_with_progress<F>(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        progress: F,
    ) -> Result<Self, StoreError>
    where
        F: Fn(crate::analyzer::BuildProgressEvent) + Send + Sync + 'static,
    {
        Self::build_persisted_inner(project, config, Some(Arc::new(progress)), false, None)
    }

    /// Persisted counterpart of [`Self::build_ephemeral_with_tier_access_footgun`].
    #[doc(hidden)]
    pub fn build_persisted_with_tier_access(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
    ) -> Result<(Self, Arc<AnalyzerBuildTierAccess>), StoreError> {
        Self::build_with_tier_access(|observer| {
            Self::build_persisted_inner(project, config, None, true, Some(Arc::clone(observer)))
        })
    }

    /// Progress-reporting variant of `build_persisted`.
    pub fn build_persisted_with_progress<F>(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        progress: F,
    ) -> Result<Self, StoreError>
    where
        F: Fn(crate::analyzer::BuildProgressEvent) + Send + Sync + 'static,
    {
        Self::build_persisted_inner(project, config, Some(Arc::new(progress)), true, None)
    }

    fn build_persisted_inner(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        progress: Option<BuildProgress>,
        automatic_gc: bool,
        tier_access: Option<Arc<AnalyzerBuildTierAccess>>,
    ) -> Result<Self, StoreError> {
        let mut store_context = {
            let _scope = profiling::scope("WorkspaceAnalyzer::open_persistent_store");
            super::tree_sitter_analyzer::persistent_store_context_with_config(
                project.as_ref(),
                &config,
                automatic_gc,
            )?
        };
        if let Some(tier_access) = tier_access {
            store_context.build_tier_access = tier_access;
        }
        Self::build_filtered(project, config, None, store_context, progress)
    }

    fn build_filtered(
        project: Arc<dyn Project>,
        mut config: AnalyzerConfig,
        requested_languages: Option<&BTreeSet<Language>>,
        store_context: crate::analyzer::AnalyzerStoreContext,
        progress: Option<BuildProgress>,
    ) -> Result<Self, StoreError> {
        let project = super::project_read_facade::with_project_read_slot(project);
        let _scope = profiling::scope("WorkspaceAnalyzer::build");
        for support in Language::ANALYZABLE
            .iter()
            .filter_map(|&language| crate::analyzer::languages::language_support(language))
        {
            support.configure_dependency_workspace(&mut config, project.root())?;
        }
        // A fresh abort per fan-out. The caller's context may outlive this
        // build and go on to serve lazy per-language delegate builds, and those
        // must not inherit a flag this build set.
        let mut store_context = crate::analyzer::AnalyzerStoreContext {
            build_abort: Arc::new(crate::analyzer::BuildAbort::default()),
            ..store_context
        };
        // Persisted workspaces share parsed blobs, so serialize the complete
        // reconciliation, not just the first population. Otherwise concurrent
        // worktrees all snapshot the same missing set and each creates a full
        // analyzer pool before any of them can publish reusable results.
        //
        // Declare the lock after the store context so unwinding drops it before
        // the context joins any GC task that is waiting for this same lock.
        let build_lock = if let Some(db_path) = store_context.store.db_path() {
            profiling::note("workspace.store=persistent");
            let _scope = profiling::scope("WorkspaceAnalyzer::build_lock_wait");
            // Under the build's own cancellation: a request that runs out of
            // budget while another builder or a collection holds this lock
            // gets an error naming the lock, instead of a thread parked past
            // the deadline and a bare budget message (issue #3170). A build
            // with no request behind it carries a token that is never
            // cancelled and so waits as long as it takes.
            Some(
                brokk_bifrost_core::cache_gc::AnalyzerCacheBuildLock::acquire_cancellable(
                    db_path,
                    &store_context.cancellation,
                )
                .map_err(StoreError::new)?,
            )
        } else {
            profiling::note("workspace.store=ephemeral");
            None
        };
        let mut delegates = BTreeMap::new();
        let project_languages = project.analyzer_languages();
        let selected_languages: Vec<_> = match requested_languages {
            Some(requested) if !requested.is_empty() => project_languages
                .into_iter()
                .filter(|language| requested.contains(language))
                .collect(),
            _ => project_languages.into_iter().collect(),
        };
        #[cfg(any(test, feature = "test-support"))]
        let startup_oid_batches = store_context
            .liveness
            .as_ref()
            .map(|liveness| liveness.startup_oid_batch_counter());
        // Capture one immutable listing and one startup identity projection
        // before the language fan-out. The snapshot is consumed by delegate
        // construction and cleared before the retained build context is made,
        // so watcher-driven updates never serve stale startup state.
        store_context.workspace_snapshot = WorkspaceBuildSnapshot::capture(
            project.as_ref(),
            store_context.liveness.as_deref(),
            &selected_languages,
        );
        store_context.workspace_listing_complete = store_context.workspace_snapshot.is_some();
        // One build thread per language: a single language with one pathological
        // file (a vendored million-line generated parser.c, say) otherwise
        // serializes ahead of every other language's build and dominates cold
        // start (issue #1309). Store writes stay safe because every language
        // shares the store's single writer connection behind its mutex.
        //
        // A worker panic is caught rather than unwound through the join, for two
        // reasons (issue #2359). `std::thread::scope` joins every spawned thread
        // before it returns, so unwinding out of the first join still waits for
        // the slowest sibling; catching lets the worker set the shared abort
        // first, which is what makes the siblings stop instead of running to
        // completion. And joining every handle before re-raising makes the
        // choice of which panic wins deterministic -- the first language in
        // selection order -- rather than whichever thread the join order
        // happened to reach while another was still running. The payload is
        // re-raised verbatim, so the original message and location survive.
        let context = brokk_bifrost_core::analyzer::carried_context::CarriedContext::current();
        let mut panics: Vec<Box<dyn std::any::Any + Send>> = Vec::new();
        let built: Vec<(Language, Result<AnalyzerDelegate, StoreError>)> =
            std::thread::scope(|scope| {
                let handles: Vec<_> = selected_languages
                    .into_iter()
                    .filter(|language| *language != Language::None)
                    .map(|language| {
                        let project = Arc::clone(&project);
                        let cfg = config.clone();
                        let store_context = store_context.clone();
                        let progress = progress.as_ref().map(Arc::clone);
                        let context = context.clone();
                        let handle = std::thread::Builder::new()
                            .name(format!("bifrost-build-{language:?}"))
                            .spawn_scoped(scope, move || {
                                let abort = Arc::clone(&store_context.build_abort);
                                let built = std::panic::catch_unwind(AssertUnwindSafe(|| {
                                    context.run(|| {
                                        build_language_delegate(
                                            language,
                                            project,
                                            cfg,
                                            store_context,
                                            progress,
                                        )
                                    })
                                }));
                                if built.is_err() {
                                    abort.abort();
                                }
                                built
                            })
                            .expect("failed to spawn language build thread");
                        (language, handle)
                    })
                    .collect();
                handles
                    .into_iter()
                    .filter_map(|(language, handle)| {
                        match handle
                            .join()
                            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
                        {
                            Ok(result) => Some((language, result)),
                            Err(payload) => {
                                panics.push(payload);
                                None
                            }
                        }
                    })
                    .collect()
            });
        if let Some(payload) = panics.into_iter().next() {
            std::panic::resume_unwind(payload);
        }
        for (language, delegate) in built {
            delegates.insert(language, delegate?);
        }

        store_context.workspace_snapshot = None;

        if delegates.contains_key(&Language::Rust) {
            let snapshot = {
                use rusqlite::OptionalExtension;
                let conn = store_context.store.read_conn()?;
                conn.query_row(
                    "SELECT heads.generation, heads.revision FROM workspace_heads AS heads
                     JOIN analysis_epochs AS epochs ON epochs.lang = heads.lang AND epochs.generation = heads.generation
                     WHERE heads.workspace_id = ?1 AND heads.lang = 'rust'",
                    [store_context.workspace_id.as_str()],
                    |row| Ok(crate::analyzer::store::WorkspaceSnapshotId {
                        workspace_id: store_context.workspace_id.clone(), lang: "rust".into(),
                        generation: crate::analyzer::store::GenerationId::from_persisted(row.get(0)?), revision: row.get(1)?,
                    }),
                ).optional()?
            };
            if let Some(snapshot) = snapshot {
                store_context
                    .store
                    .reconcile_rust_crates_unless_current(&snapshot)?;
            }
        }

        // Under the elected builder's lock, refresh all tables outside the
        // blob-count tolerance, otherwise only non-empty stale tables.
        // SQLite's dry-run optimize can take a write transaction even when
        // nothing is stale.
        if build_lock.is_some()
            && brokk_bifrost_core::cache_gc::planner_statistics_enabled()
            && let Some(evidence) = store_context.store.refresh_planner_statistics_if_stale()?
        {
            profiling::note_with(|| {
                format!(
                    "workspace.planner_statistics refreshed: {:.1} ms, {} sqlite_stat1 rows, tables {:?}",
                    evidence.elapsed.as_secs_f64() * 1000.0,
                    evidence.stat1_rows,
                    evidence.analyzed_tables
                )
            });
        }

        let build_context = WorkspaceBuildContext::new(
            Arc::clone(&project),
            config,
            store_context,
            requested_languages.cloned(),
        );
        #[cfg(any(test, feature = "test-support"))]
        let build_context =
            build_context.with_startup_oid_batch_counter_for_test(startup_oid_batches);
        let build_context = Arc::new(build_context);

        let workspace = if delegates.is_empty() {
            Self::Empty(EmptyAnalyzer::new_for_workspace(build_context))
        } else {
            Self::Multi(Box::new(MultiAnalyzer::new_for_workspace(
                delegates,
                build_context,
            )))
        };
        drop(build_lock);
        Ok(workspace)
    }

    pub fn analyzer(&self) -> &dyn IAnalyzer {
        match self {
            Self::Empty(analyzer) => analyzer,
            Self::Multi(analyzer) => analyzer.as_ref(),
        }
    }

    /// The [`AnalyzerConfig`] this workspace was built from, or `None` for a
    /// workspace assembled without a build context -- an empty analyzer, or one
    /// composed directly from delegates -- which was never built from a
    /// configuration and behaves as the defaults describe.
    ///
    /// A caller that must analyze a *second* snapshot the way this one was
    /// analyzed (the base revision of a `--diff-base` run) reads the
    /// configuration here instead of choosing one of its own, so both snapshots
    /// discover dependencies, dispatch, and per-language behavior identically
    /// and the facts they publish are comparable.
    pub fn config(&self) -> Option<&AnalyzerConfig> {
        let build_context = match self {
            Self::Empty(analyzer) => analyzer.build_context.as_deref(),
            Self::Multi(analyzer) => analyzer.build_context(),
        };
        build_context.map(WorkspaceBuildContext::config)
    }

    /// Build a second workspace over this one's project, languages and store,
    /// analyzed under `config`.
    ///
    /// A host session analyzes its project under the configuration its own
    /// tools need. A caller that must answer under another configuration --
    /// policy evaluation, which uses one configuration whatever the host --
    /// builds this instead of a workspace of its own over the root, so it sees
    /// the same files and overlays the session sees and reads the facts the
    /// session already parsed. The second workspace reconciles its own
    /// projection and never changes the session's.
    pub fn rebuild_with_config(&self, config: AnalyzerConfig) -> Result<Self, StoreError> {
        let build_context = match self {
            Self::Empty(analyzer) => analyzer.build_context.as_deref(),
            Self::Multi(analyzer) => analyzer.build_context(),
        }
        .ok_or_else(|| {
            StoreError::new(
                "a workspace assembled without a build context has no project, languages or \
                 store to build again",
            )
        })?;
        let project = Arc::clone(build_context.project());
        let store_context = build_context
            .store_context()
            .for_second_build(project.as_ref());
        Self::build_filtered(
            project,
            config,
            build_context.requested_languages(),
            store_context,
            None,
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn startup_oid_batch_count_for_test(&self) -> usize {
        match self {
            Self::Empty(analyzer) => analyzer
                .build_context
                .as_deref()
                .map_or(0, WorkspaceBuildContext::startup_oid_batch_count_for_test),
            Self::Multi(analyzer) => analyzer
                .build_context()
                .map_or(0, WorkspaceBuildContext::startup_oid_batch_count_for_test),
        }
    }

    /// The on-disk path of the analyzer store this workspace persists to, or
    /// `None` when the store has no persistent workspace identity, which now
    /// means exactly one thing: this was an ephemeral build. A persisted build
    /// over a project with no [`Project::persistence_root`] fails rather than
    /// degrading, so a workspace from a persisted build always reports a path.
    /// `None` does not mean the store has no file. An ephemeral store is a
    /// delete-on-drop temporary database rather than `:memory:`, so the reader
    /// pool can share it; what it lacks is an identity that outlives the build.
    ///
    /// This reports what the build actually produced, not what the caller
    /// requested, so hosts that must surface their persistence decision as
    /// evidence (the extension workspace description) can read it here instead
    /// of re-deriving the cache location and guessing.
    pub fn persisted_store_path(&self) -> Option<std::path::PathBuf> {
        let build_context = match self {
            Self::Empty(analyzer) => analyzer.build_context.as_deref(),
            Self::Multi(analyzer) => analyzer.build_context(),
        };
        build_context
            .and_then(WorkspaceBuildContext::store_db_path)
            .map(std::path::Path::to_path_buf)
    }

    /// The analyzer store this workspace reads from and publishes to.
    ///
    /// `None` for a workspace assembled without a build context, which has no
    /// store at all. A caller that derives something of its own from this
    /// workspace -- a policy evaluation unit, which is keyed by the content it
    /// read -- publishes it here, into the same content-addressed database the
    /// analyzer's own facts live in, and reads it back on a later run through
    /// [`Self::persisted_store_path`], which is what says whether "a later
    /// run" can exist at all.
    pub fn store(&self) -> Option<&Arc<crate::analyzer::store::AnalyzerStore>> {
        let build_context = match self {
            Self::Empty(analyzer) => analyzer.build_context.as_deref(),
            Self::Multi(analyzer) => analyzer.build_context(),
        };
        build_context.map(WorkspaceBuildContext::store)
    }

    /// Resolve one current disk-backed semantic artifact to the durable blob
    /// identity used by analyzer-store derived rows.
    ///
    /// The source snapshot is captured once and checked against `key` before
    /// hashing. Overlay artifacts deliberately return `None`: their ephemeral
    /// revision must never be attached to, or later replayed from, a disk blob
    /// row that happens to have the same workspace path.
    pub fn semantic_artifact_store_attachment(
        &self,
        key: &crate::analyzer::semantic::SemanticArtifactKey,
    ) -> Result<
        Option<crate::analyzer::store::class_set_summaries::ClassSetSummaryAttachment>,
        crate::analyzer::semantic::SemanticProviderError,
    > {
        if !matches!(
            key.revision(),
            crate::analyzer::semantic::SourceRevision::Disk { .. }
        ) {
            return Ok(None);
        }
        let root = self.analyzer().project().root();
        if key.mount() != crate::analyzer::semantic::WorkspaceMountId::from_root(root) {
            return Ok(None);
        }
        let file = crate::analyzer::ProjectFile::new(root.to_path_buf(), key.path().as_path());
        let Some(storage_language_key) = self.semantic_artifact_storage_language_key(key) else {
            return Ok(None);
        };
        let Some(snapshot) = self.current_program_semantics_artifact_source(&file, usize::MAX)?
        else {
            return Ok(None);
        };
        if snapshot.key() != key {
            return Ok(None);
        }
        let blob_oid = git2::Oid::hash_object(git2::ObjectType::Blob, snapshot.source().as_bytes())
            .map_err(|error| {
                crate::analyzer::semantic::SemanticProviderError::internal(format!(
                    "failed to derive analyzer-store blob identity for {}: {error}",
                    key.path()
                ))
            })?;
        Ok(Some(
            crate::analyzer::store::class_set_summaries::ClassSetSummaryAttachment {
                rel_path: key.path().as_str().to_owned(),
                blob_oid: blob_oid.to_string(),
                storage_language_key,
                language: key.language().language(),
            },
        ))
    }

    /// Return the exact storage namespace selected by the same per-file
    /// semantic provider that owns `key`. This is a path/adapter identity
    /// lookup only; callers that need a current disk owner still use
    /// [`Self::semantic_artifact_store_attachment`] to bind the key to a
    /// verified source snapshot and blob identity.
    pub fn semantic_artifact_storage_language_key(
        &self,
        key: &crate::analyzer::semantic::SemanticArtifactKey,
    ) -> Option<crate::analyzer::semantic::StorageLanguageKey> {
        let root = self.analyzer().project().root();
        if key.mount() != crate::analyzer::semantic::WorkspaceMountId::from_root(root) {
            return None;
        }
        let file = crate::analyzer::ProjectFile::new(root.to_path_buf(), key.path().as_path());
        let active = self.analyzer().active_semantic_model_snapshot();
        let (delegate, provider) = self.program_semantics_provider_context_for_file(&file)?;
        let _scope = crate::analyzer::AnalyzerQueryScope::with_active_semantic_model_snapshot(
            delegate, active,
        );
        provider.storage_language_key_for_file(&file)
    }

    /// Number of files in the project, i.e. an upper bound on the distinct
    /// files any demand-cached analysis can materialize.
    ///
    /// A whole-workspace analysis such as a policy compile legitimately touches
    /// every relevant file once; the content-keyed materialization cache makes
    /// that cost proportional to distinct files, never more than this count. A
    /// caller can therefore size a materialization budget to this value instead
    /// of a fixed per-query cap that a large corpus would exceed by construction.
    /// Returns `0` when the file listing is unavailable, which callers fold into
    /// their existing lower bound with `max`.
    pub fn project_file_count(&self) -> usize {
        self.analyzer()
            .project()
            .all_files_shared()
            .map(|files| files.len())
            .unwrap_or(0)
    }

    /// Bring the persisted per-file Rust usage facts up to date ahead of the
    /// first query that reads them.
    ///
    /// This is the whole of the startup usage warm. It replaced a
    /// workspace-wide index build (issues #1416, #1757, #1758): under usage v2
    /// there is nothing to build, and the warm's only job is to find the live
    /// blobs analysis did not persist rows for and repair them off the request
    /// path. A no-op for workspaces without Rust.
    ///
    /// The per-language `warm_usage_analysis` dispatch beside it is gone. It
    /// had one implementor, the Rust incumbent, and the native engine builds no
    /// whole-workspace index to warm, so the dispatch became twelve calls to an
    /// empty default. The repair below is what still earns the startup thread:
    /// an unpublished live blob is exactly what makes a native graph report
    /// `unavailable_canonical_facts`.
    pub fn warm_rust_usage_facts(&self) {
        brokk_bifrost_core::analyzer::project_reads::without_project_reads(|| {
            for support in Language::ANALYZABLE
                .iter()
                .filter_map(|&language| crate::analyzer::languages::language_support(language))
            {
                support.warm_usage_facts(self.analyzer());
            }
        })
    }

    /// Whether a Rust usage query would wait for a fact catch-up batch.
    ///
    /// Under usage v2 nothing is built, and the only wait a query can inherit
    /// is an above-threshold batch of live blobs whose facts are being
    /// persisted in the background. Answers without blocking behind that batch,
    /// which is the point (#1757). Always true for a workspace with no Rust.
    pub fn rust_usage_facts_ready(&self) -> bool {
        Language::ANALYZABLE
            .iter()
            .filter_map(|&language| crate::analyzer::languages::language_support(language))
            .all(|support| support.usage_facts_ready(self.analyzer()))
    }

    /// Whether the Rust fact catch-up has run for this generation. The
    /// warm-ness question, as distinct from the wait question
    /// [`Self::rust_usage_facts_ready`] answers: a session that never warms and
    /// never queries is ready but not warm.
    pub fn rust_usage_facts_warm(&self) -> bool {
        Language::ANALYZABLE
            .iter()
            .filter_map(|&language| crate::analyzer::languages::language_support(language))
            .all(|support| support.usage_facts_warm(self.analyzer()))
    }

    /// Select the execution-semantics provider for the requested file without
    /// widening the monolithic [`IAnalyzer`] surface.
    pub fn program_semantics_provider_for_file(
        &self,
        file: &crate::analyzer::ProjectFile,
    ) -> Option<&dyn crate::analyzer::semantic::ProgramSemanticsProvider> {
        match self {
            Self::Empty(_) => None,
            Self::Multi(analyzer) => analyzer.program_semantics_provider_for_file(file),
        }
    }

    /// The prepared syntax the analysis walk holds for `file`, for the
    /// host differential. Empty workspaces hold none.
    #[cfg(any(test, feature = "test-support"))]
    pub fn prepared_syntax_for_test(
        &self,
        file: &crate::analyzer::ProjectFile,
    ) -> Option<std::sync::Arc<crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree>> {
        match self {
            Self::Empty(_) => None,
            Self::Multi(analyzer) => analyzer.prepared_syntax_for_test(file),
        }
    }

    fn program_semantics_provider_context_for_file(
        &self,
        file: &crate::analyzer::ProjectFile,
    ) -> Option<(
        &dyn crate::analyzer::IAnalyzer,
        &dyn crate::analyzer::semantic::ProgramSemanticsProvider,
    )> {
        let Self::Multi(analyzer) = self else {
            return None;
        };
        analyzer.program_semantics_provider_context_for_file(file)
    }

    #[doc(hidden)]
    pub fn current_program_semantics_artifact_source(
        &self,
        file: &crate::analyzer::ProjectFile,
        max_source_bytes: usize,
    ) -> Result<
        Option<crate::analyzer::semantic::SemanticArtifactSourceSnapshot>,
        crate::analyzer::semantic::SemanticProviderError,
    > {
        let active = self.analyzer().active_semantic_model_snapshot();
        let Some((delegate, provider)) = self.program_semantics_provider_context_for_file(file)
        else {
            return Ok(None);
        };
        let _scope = crate::analyzer::AnalyzerQueryScope::with_active_semantic_model_snapshot(
            delegate, active,
        );
        provider.current_artifact_source(file, max_source_bytes)
    }

    /// The public fingerprint of the semantic artifact this workspace would
    /// derive for `file` right now, without materializing it.
    ///
    /// Read-set verification asks exactly this: a unit that consumed an
    /// artifact is reusable only while the head would derive the same one, and
    /// the public fingerprint is the identity that says so without folding the
    /// workspace mount.
    pub(crate) fn current_semantic_artifact_fingerprint(
        &self,
        file: &crate::analyzer::ProjectFile,
        max_source_bytes: usize,
    ) -> Result<
        Option<crate::analyzer::semantic::ids::StableDigest>,
        crate::analyzer::semantic::SemanticProviderError,
    > {
        Ok(self
            .current_program_semantics_artifact_source(file, max_source_bytes)?
            .map(|current| current.key().public_fingerprint()))
    }

    /// Check a retained semantic handle against the complete identity of the
    /// file's current analyzer generation without rematerializing its IR.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn semantic_artifact_key_is_current(
        &self,
        key: &crate::analyzer::semantic::SemanticArtifactKey,
        max_source_bytes: usize,
    ) -> Result<Option<bool>, crate::analyzer::semantic::SemanticProviderError> {
        self.semantic_artifact_key_is_current_with_source_bytes(key, max_source_bytes)
            .map(|current| current.map(|(is_current, _)| is_current))
    }

    /// Check one retained semantic identity and report the exact source bytes
    /// read so callers can enforce an aggregate validation budget.
    pub fn semantic_artifact_key_is_current_with_source_bytes(
        &self,
        key: &crate::analyzer::semantic::SemanticArtifactKey,
        max_source_bytes: usize,
    ) -> Result<Option<(bool, usize)>, crate::analyzer::semantic::SemanticProviderError> {
        let root = self.analyzer().project().root();
        if key.mount() != crate::analyzer::semantic::WorkspaceMountId::from_root(root) {
            return Ok(Some((false, 0)));
        }
        let file = crate::analyzer::ProjectFile::new(root.to_path_buf(), key.path().as_path());
        if self.program_semantics_provider_for_file(&file).is_none() {
            return Ok(Some((false, 0)));
        }
        Ok(self
            .current_program_semantics_artifact_source(&file, max_source_bytes)?
            .map(|current| (current.key() == key, current.source().len())))
    }

    /// File-aware semantic materialization routed through the concrete
    /// language analyzer. Unknown extensions remain explicitly unsupported.
    pub fn materialize_program_semantics(
        &self,
        file: &crate::analyzer::ProjectFile,
        request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<
        crate::analyzer::semantic::SemanticOutcome<
            Arc<crate::analyzer::semantic::SemanticArtifact>,
        >,
        crate::analyzer::semantic::SemanticProviderError,
    > {
        let active = self.analyzer().active_semantic_model_snapshot();
        let Some((delegate, provider)) = self.program_semantics_provider_context_for_file(file)
        else {
            return Ok(crate::analyzer::semantic::SemanticOutcome::Unsupported {
                capability: crate::analyzer::semantic::SemanticCapability::Procedures,
                partial: None,
                work: crate::analyzer::semantic::SemanticWork::default(),
            });
        };
        let _scope = crate::analyzer::AnalyzerQueryScope::with_active_semantic_model_snapshot(
            delegate, active,
        );
        let result = provider.materialize(file, request);
        if match &result {
            Err(_) => true,
            Ok(outcome) => {
                matches!(
                    outcome,
                    crate::analyzer::semantic::SemanticOutcome::Cancelled { .. }
                        | crate::analyzer::semantic::SemanticOutcome::ExceededBudget { .. }
                ) || outcome.available_value().is_some_and(|artifact| {
                    artifact.procedures().iter().any(|procedure| {
                        procedure.gaps().iter().any(|gap| {
                            gap.kind == crate::analyzer::semantic::SemanticGapKind::ExceededBudget
                        })
                    })
                })
            }
        } {
            brokk_bifrost_core::profiling::note_with(|| {
                format!(
                    "policy.units unbounded origin={}:{} cause=budget:semantic_artifact",
                    file!(),
                    line!()
                )
            });
            self.analyzer().mark_execution_dependent();
        }
        result
    }

    /// The stored partial flows of one procedure, when the procedure's file has
    /// a complete publication for exactly this artifact. `None`
    /// means the caller must compute them from the procedure's relations.
    pub fn stored_partial_flows(
        &self,
        procedure: &crate::analyzer::semantic::ProcedureHandle,
    ) -> Result<
        Option<crate::analyzer::semantic::partial_flow::ProcedurePartialFlows>,
        crate::analyzer::semantic::SemanticProviderError,
    > {
        let key = procedure.artifact().key();
        let root = self.analyzer().project().root();
        if key.mount() != crate::analyzer::semantic::WorkspaceMountId::from_root(root) {
            return Ok(None);
        }
        let file = crate::analyzer::ProjectFile::new(root.to_path_buf(), key.path().as_path());
        let Some((_, provider)) = self.program_semantics_provider_context_for_file(&file) else {
            return Ok(None);
        };
        provider.stored_partial_flows(&file, key, procedure.id())
    }

    /// Whether the file of `key` has a complete semantic IR publication for
    /// exactly this artifact's content under the active producer epoch.
    /// `false` means the file's rows cannot serve the artifact.
    pub fn has_complete_semantic_ir_rows(
        &self,
        key: &crate::analyzer::semantic::SemanticArtifactKey,
    ) -> Result<bool, crate::analyzer::semantic::SemanticProviderError> {
        let root = self.analyzer().project().root();
        if key.mount() != crate::analyzer::semantic::WorkspaceMountId::from_root(root) {
            return Ok(false);
        }
        let file = crate::analyzer::ProjectFile::new(root.to_path_buf(), key.path().as_path());
        let Some((_, provider)) = self.program_semantics_provider_context_for_file(&file) else {
            return Ok(false);
        };
        provider.has_complete_semantic_ir_rows(&file, key)
    }

    /// Bind the demand-materialized ICFG facade to this exact analyzer
    /// generation without widening the language analyzers or `IAnalyzer`.
    pub fn icfg_provider(&self) -> crate::analyzer::semantic::WorkspaceIcfgProvider<'_> {
        crate::analyzer::semantic::WorkspaceIcfgProvider::new(self)
    }

    /// Bind the language-neutral semantic-oracle facade to this exact analyzer
    /// generation without widening the language analyzers or `IAnalyzer`.
    pub fn semantic_oracle_provider(
        &self,
    ) -> crate::analyzer::semantic::WorkspaceSemanticOracle<'_> {
        crate::analyzer::semantic::WorkspaceSemanticOracle::new(self)
    }

    /// Which class-hierarchy expansions call dispatch may add for this
    /// workspace, as the host configured them when the workspace was built.
    ///
    /// This is the one production place the switch is read: every semantic
    /// oracle bound to this workspace inherits the answer, so a host selects
    /// the behavior once by the [`AnalyzerConfig`] it builds with instead of
    /// every call path passing a flag. A workspace assembled without a build
    /// context -- an empty analyzer, or one composed directly from delegates --
    /// keeps the default, which is every optional expansion off.
    pub fn dispatch_hierarchy_expansion(&self) -> crate::analyzer::DispatchHierarchyExpansion {
        let build_context = match self {
            Self::Empty(analyzer) => analyzer.build_context.as_deref(),
            Self::Multi(analyzer) => analyzer.build_context(),
        };
        build_context.map_or_else(
            crate::analyzer::DispatchHierarchyExpansion::default,
            |context| context.config().dispatch_hierarchy_expansion,
        )
    }

    /// Starts a request-scoped query cache across the active language analyzers.
    pub fn begin_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        self.analyzer().begin_query(context);
    }

    pub fn end_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        self.analyzer().end_query(context);
    }

    fn with_query_context(&self, query: impl FnOnce(&dyn IAnalyzer)) {
        // Index builds read the store per file and need an active query cache
        // to avoid repeating those reads. A clone shares lazy-index cells
        // while keeping its read cache separate from any overlapping query.
        let snapshot = self.clone();
        let execution = crate::analyzer::read_attribution_records_reads(|| {
            self.analyzer().read_ledger_attached()
        })
        .then(|| Arc::new(crate::analyzer::ReadLedger::new()));
        let scope = match &execution {
            Some(ledger) => crate::analyzer::AnalyzerQueryScope::with_read_ledger(
                snapshot.analyzer(),
                Arc::clone(ledger),
            ),
            None => crate::analyzer::AnalyzerQueryScope::new(snapshot.analyzer()),
        };
        query(snapshot.analyzer());
        drop(scope);
        // Index warming has its own registry on the clone. Its consuming
        // funnels name the index answers, but cannot subsume execution state.
        // Route that state back through the original request attribution.
        if let Some(ledger) = execution {
            for _ in 0..ledger.execution_dependences() {
                self.analyzer().mark_execution_dependent();
            }
        }
    }

    /// Build the expensive lazily-initialized per-generation query indexes
    /// ahead of demand (#1442). Idempotent; see
    /// `IAnalyzer::warm_query_indexes`.
    pub fn warm_query_indexes(&self) {
        brokk_bifrost_core::analyzer::project_reads::without_project_reads(|| {
            let _scope = profiling::scope("WorkspaceAnalyzer::warm_query_indexes");
            self.with_query_context(|analyzer| analyzer.warm_query_indexes());
        })
    }

    /// Whether every index `warm_query_indexes` would build is already built.
    pub fn query_indexes_warm(&self) -> bool {
        self.analyzer().query_indexes_warm()
    }

    /// Build the structural posting index every provider a structural query
    /// has already asked to reuse still owes. Idempotent; see
    /// `IAnalyzer::warm_structural_indexes`.
    pub fn warm_structural_indexes(&self) {
        brokk_bifrost_core::analyzer::project_reads::without_project_reads(|| {
            let _scope = profiling::scope("WorkspaceAnalyzer::warm_structural_indexes");
            self.with_query_context(|analyzer| analyzer.warm_structural_indexes());
        })
    }

    /// Whether every posting index `warm_structural_indexes` would build is
    /// already built or already rejected.
    pub fn structural_indexes_warm(&self) -> bool {
        self.analyzer().structural_indexes_warm()
    }

    fn updated_from_empty(
        analyzer: &EmptyAnalyzer,
        build_context: &Arc<WorkspaceBuildContext>,
        languages: BTreeSet<Language>,
        mut build_delegate: impl FnMut(Language) -> AnalyzerDelegate,
    ) -> Self {
        if languages.is_empty() {
            return Self::Empty(analyzer.clone());
        }
        let delegates = languages
            .into_iter()
            .map(|language| (language, build_delegate(language)))
            .collect();
        Self::Multi(Box::new(MultiAnalyzer::new_for_workspace(
            delegates,
            Arc::clone(build_context),
        )))
    }

    pub fn update(&self, changed_files: &BTreeSet<crate::analyzer::ProjectFile>) -> Self {
        brokk_bifrost_core::analyzer::project_reads::without_project_reads(|| {
            let _scope = profiling::scope("WorkspaceAnalyzer::update");
            if profiling::enabled() {
                profiling::note(format!("changed_files={}", changed_files.len()));
            }
            self.analyzer()
                .invalidate_cached_file_identities_for(changed_files);
            let next = match self {
                Self::Empty(analyzer) => {
                    let Some(build_context) = analyzer.build_context.as_ref() else {
                        return Self::Empty(analyzer.clone());
                    };
                    let languages = build_context.changed_languages(changed_files);
                    Self::updated_from_empty(analyzer, build_context, languages, |language| {
                        build_context
                        .build_delegate(language)
                        .unwrap_or_else(|error| {
                            panic!(
                                "failed to initialize {language:?} analyzer during update: {error}"
                            )
                        })
                    })
                }
                Self::Multi(analyzer) => Self::from_updated_multi(analyzer.update(changed_files)),
            };
            next.reconcile_updated_build_context(Some(changed_files));
            next
        })
    }

    /// Refresh external-tool contexts for this updated snapshot without
    /// activating semantic packs. Hosts publish the new snapshot first so a
    /// failed refresh remains visible in its language's build-selection state.
    pub fn refresh_updated_workspace_contexts(
        &self,
        changed_files: &BTreeSet<ProjectFile>,
        limits: &DependencyPackLimits,
        cancellation: &crate::CancellationToken,
    ) -> Result<(), StoreError> {
        brokk_bifrost_core::analyzer::project_reads::without_project_reads(|| {
            let Some(config) = self.config() else {
                return Ok(());
            };
            for support in crate::analyzer::languages::registered_language_supports() {
                support.refresh_updated_workspace_context(
                    self,
                    changed_files,
                    config,
                    limits,
                    cancellation,
                )?;
            }
            Ok(())
        })
    }

    pub fn update_all(&self) -> Self {
        self.update_all_reporting_progress(None)
    }

    /// Rebuild from disk, forwarding real build counters for this operation only.
    pub fn update_all_with_progress<F>(&self, progress: F) -> Self
    where
        F: Fn(crate::analyzer::BuildProgressEvent) + Send + Sync + 'static,
    {
        self.update_all_reporting_progress(Some(Arc::new(progress)))
    }

    fn update_all_reporting_progress(&self, progress: Option<BuildProgress>) -> Self {
        brokk_bifrost_core::analyzer::project_reads::without_project_reads(|| {
            let _scope = profiling::scope("WorkspaceAnalyzer::update_all");
            self.analyzer().invalidate_cached_file_identities();
            let next = match self {
                Self::Empty(analyzer) => {
                    let Some(build_context) = analyzer.build_context.as_ref() else {
                        return Self::Empty(analyzer.clone());
                    };
                    let languages = build_context.project_languages();
                    Self::updated_from_empty(analyzer, build_context, languages, |language| {
                        build_context.build_delegate_with_progress(language, progress.clone()).unwrap_or_else(|error| {
                            panic!(
                                "failed to initialize {language:?} analyzer during full update: {error}"
                            )
                    })
                    })
                }
                Self::Multi(analyzer) => {
                    Self::from_updated_multi(analyzer.update_all_with_progress(progress))
                }
            };
            next.reconcile_updated_build_context(None);
            next
        })
    }

    fn reconcile_updated_build_context(
        &self,
        changed: Option<&BTreeSet<crate::analyzer::ProjectFile>>,
    ) {
        for support in crate::analyzer::languages::registered_language_supports() {
            if let Err(error) = support.reconcile_workspace_build_context(self, changed) {
                self.analyzer().record_query_failure(error);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::analyzer::store::liveness::Liveness;

    use crate::analyzer::FilesystemProject;

    use crate::analyzer::ProjectFile;

    use crate::gitblob::test_repo::commit_all;
    use crate::gitblob::test_repo::init_repo;
    use crate::path_normalization::NormalizePath;

    #[test]
    fn selected_project_listing_tracks_file_changes_and_overlay_snapshots() {
        let _language =
            crate::analyzer::languages::neutral_fixture::neutral_rules_fixture(&[Language::Java]);
        let temp = tempfile::tempdir().unwrap();
        // `with_cached_listing` asserts the cache root equals its canonical,
        // normalized root; Windows `canonicalize` returns a verbatim `\\?\`
        // spelling that only `normalize` collapses.
        let root = temp.path().canonicalize().unwrap().normalize();
        std::fs::write(root.join("kept.java"), "class Kept {}\n").unwrap();
        std::fs::write(root.join("café.java"), "class Cafe {}\n").unwrap();
        let repository = init_repo(&root);
        commit_all(&repository, "initial source files");

        let listing = Arc::new(crate::analyzer::WorkspaceFileListingCache::new(
            root.clone(),
        ));
        let disk_project =
            Arc::new(FilesystemProject::with_cached_listing(root.clone(), listing).unwrap());
        let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
            disk_project,
        ));
        let project: Arc<dyn Project> = overlay.clone();
        let selected = SelectedConfigurationProject::new(
            project,
            Language::Java,
            Arc::new(
                crate::analyzer::store::AnalyzerStore::open_in_memory_single_connection().unwrap(),
            ),
            crate::analyzer::store::WorkspaceSnapshotId {
                workspace_id: crate::analyzer::store::WorkspaceId::for_root(&root),
                lang: Language::Java.config_label().to_owned(),
                generation: crate::analyzer::store::GenerationId::BOOTSTRAP,
                revision: 0,
            },
            None,
        );

        let assert_matches_fresh_project = || {
            let fresh = FilesystemProject::new(root.clone()).unwrap();
            let selected_files = selected.all_files().unwrap();
            let fresh_files = fresh.all_files().unwrap();
            assert_eq!(selected_files, fresh_files);
            assert_eq!(
                selected.analyzable_files(Language::Java).unwrap(),
                fresh.analyzable_files(Language::Java).unwrap()
            );
            assert_eq!(
                selected
                    .analyzable_files_from(&selected_files, Language::Java)
                    .unwrap(),
                fresh
                    .analyzable_files_from(&fresh_files, Language::Java)
                    .unwrap()
            );
            assert!(selected.workspace_file_listing_count() >= 2);
        };

        let kept = ProjectFile::new(&root, "kept.java");
        assert_eq!(selected.workspace_root_for_file(&kept), root);
        assert_eq!(selected.persistence_root(), Some(root.as_path()));
        assert!(!selected.is_gitignored(Path::new("kept.java")));
        assert_matches_fresh_project();

        overlay.set(kept.abs_path(), "class Unsaved {}\n".to_owned());
        assert!(selected.has_overlay(&kept));
        assert!(selected.overlay_content().is_some());
        let overlay_snapshot = selected.read_source_snapshot(&kept).unwrap();
        assert_eq!(overlay_snapshot.source(), "class Unsaved {}\n");
        assert_ne!(
            overlay_snapshot,
            FilesystemProject::new(root.clone())
                .unwrap()
                .read_source_snapshot(&kept)
                .unwrap()
        );
        overlay.clear(&kept.abs_path());
        assert!(!selected.has_overlay(&kept));
        assert_eq!(
            selected.read_source_snapshot(&kept).unwrap(),
            FilesystemProject::new(root.clone())
                .unwrap()
                .read_source_snapshot(&kept)
                .unwrap()
        );

        std::fs::write(root.join("新規.java"), "class Added {}\n").unwrap();
        assert!(selected.update_cached_listing_for_path(Path::new("新規.java")));
        assert_matches_fresh_project();

        std::fs::remove_file(root.join("café.java")).unwrap();
        assert!(selected.update_cached_listing_for_path(Path::new("café.java")));
        assert_matches_fresh_project();

        std::fs::rename(root.join("kept.java"), root.join("renamed.java")).unwrap();
        assert!(selected.update_cached_listing_for_path(Path::new("kept.java")));
        assert!(selected.update_cached_listing_for_path(Path::new("renamed.java")));
        assert_matches_fresh_project();

        selected.invalidate_cached_file_listing();
        assert_eq!(
            selected.all_files().unwrap(),
            FilesystemProject::new(root).unwrap().all_files().unwrap()
        );
    }

    #[cfg(test)]
    use brokk_bifrost_test_macros::hardwon;

    #[cfg(test)]
    #[test]
    #[hardwon("#2542: workspace snapshot reused a disk identity after source bytes changed")]
    fn build_snapshot_rejects_changed_disk_identity_and_recomputes() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = ProjectFile::new(&root, "Sample.java");
        std::fs::write(file.abs_path(), "class Disk {}").unwrap();
        let repository = init_repo(&root);
        commit_all(&repository, "disk source");

        let project = FilesystemProject::new(&root).unwrap();
        let repository = crate::gitblob::discover(&root).unwrap();
        let liveness = Liveness::new(repository).unwrap();
        let snapshot =
            WorkspaceBuildSnapshot::capture(&project, Some(&liveness), &[Language::Java])
                .expect("Git-backed disk snapshot");
        let old_oid = snapshot
            .live_entry(&project, &file)
            .expect("disk live entry")
            .oid();

        std::fs::write(file.abs_path(), "class DiskUpdated {}").unwrap();
        assert!(snapshot.live_entry(&project, &file).is_none());

        let refreshed =
            WorkspaceBuildSnapshot::capture(&project, Some(&liveness), &[Language::Java])
                .expect("refreshed disk snapshot");
        let new_oid = refreshed
            .live_entry(&project, &file)
            .expect("refreshed disk live entry")
            .oid();
        assert_ne!(old_oid, new_oid);
    }
}
