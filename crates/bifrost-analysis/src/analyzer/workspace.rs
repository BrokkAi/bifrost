use crate::analyzer::multi_analyzer::WorkspaceBuildContext;
use crate::analyzer::multi_analyzer::build_language_delegate;
use brokk_bifrost_core::analyzer::project::AsProject;

/// Admission of an artifact to the shared composed flow search.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompositionReadiness {
    Ready,
    Language,
    NoRows,
}

/// Whether the language certifies the caller inventory used by composition.
pub fn composition_language_supported(
    key: &crate::analyzer::semantic::SemanticArtifactKey,
) -> bool {
    use crate::analyzer::semantic::SemanticLanguage;
    matches!(key.language(), SemanticLanguage::Standard(language)
        if crate::analyzer::languages::language_support(language)
            .is_some_and(|support| support.certifies_caller_inventory()))
}

use crate::analyzer::semantic_model::ActivationInputs;
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
use crate::analyzer::semantic_model::acquire_active_semantic_models_with_inputs;
use crate::analyzer::semantic_model::prepare_installed_dependency_packs;

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

pub use crate::analyzer::semantic::SemanticArtifactSourceOutcome;

/// A selected proof's source, held on its request's resident-source ledger.
/// The budget retains only a weak owner; dropping this value releases the hold
/// through normal ledger reconciliation, including on early returns.
#[doc(hidden)]
pub struct HeldSemanticArtifactSourceSnapshot {
    snapshot: Arc<crate::analyzer::semantic::SemanticArtifactSourceSnapshot>,
}

impl HeldSemanticArtifactSourceSnapshot {
    pub fn key(&self) -> &crate::analyzer::semantic::SemanticArtifactKey {
        self.snapshot.key()
    }

    pub fn source(&self) -> &str {
        self.snapshot.source()
    }
}

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
    #[cfg(any(test, feature = "test-support"))]
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
        let budget = brokk_bifrost_core::retention_budget::RetentionBudget::new(
            AnalyzerConfig::default().retention_budget_bytes(),
        );
        Self::open_with_budget(repository_root, cancellation, &budget)
    }

    pub fn open_with_budget(
        repository_root: &Path,
        cancellation: &crate::CancellationToken,
        budget: &brokk_bifrost_core::retention_budget::RetentionBudget,
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
        let store = crate::analyzer::store::AnalyzerStore::open_persistent_with_config(&db_path, &Default::default(), budget).map_err(
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

    pub fn retention_budget(&self) -> &brokk_bifrost_core::retention_budget::RetentionBudget {
        self.store.retention_budget()
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
/// Source reads and listing ownership remain with the caller's project. Rust
/// naming retains selected Cargo manifests, and a missing selected input
/// never falls back to a file that happens to remain on disk.
pub(crate) struct SelectedConfigurationProject {
    project_reads: brokk_bifrost_core::analyzer::project_reads::ProjectReadSlot,
    project: Arc<dyn Project>,
    language: Language,
    source: Arc<dyn ConfigurationSource>,
    naming_source: Option<StoredManifestSource>,
    publication: Option<SelectedConfigurationPublication>,
}

struct SelectedConfigurationPublication {
    store: Arc<crate::analyzer::store::AnalyzerStore>,
    snapshot: crate::analyzer::store::WorkspaceSnapshotId,
    _projection_lease: Option<Arc<WorkspaceProjectionLease>>,
}

trait ConfigurationSource: Send + Sync {
    fn lists_path(&self, _path: &str) -> bool {
        false
    }
    fn retained_bytes(&self) -> usize {
        0
    }
    fn bytes(&self, path: &str) -> std::io::Result<Option<Vec<u8>>>;
    fn bytes_with_conn(
        &self,
        _conn: &rusqlite::Connection,
        path: &str,
    ) -> std::io::Result<Option<Vec<u8>>> {
        self.bytes(path)
    }
}

/// The build's configuration capture, indexed by relative path once so each
/// naming probe is a lookup rather than a scan of every captured input.
struct CapturedConfigurationSource {
    inputs: Arc<Vec<crate::analyzer::store::WorkspaceConfigurationInput>>,
    present: HashMap<String, usize>,
    source_paths: std::collections::HashSet<String>,
}

impl CapturedConfigurationSource {
    fn new(
        inputs: Arc<Vec<crate::analyzer::store::WorkspaceConfigurationInput>>,
        files: &[ProjectFile],
    ) -> Self {
        let present = inputs
            .iter()
            .enumerate()
            .filter(|(_, input)| input.file_present)
            .map(|(index, input)| (input.relative_path().to_string(), index))
            .collect();
        Self {
            inputs,
            present,
            source_paths: files
                .iter()
                .map(crate::path_utils::rel_path_string)
                .collect(),
        }
    }
}

impl ConfigurationSource for CapturedConfigurationSource {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of_val(&self.source_paths)
            + self.source_paths.capacity() * (std::mem::size_of::<String>() + 1)
            + self
                .source_paths
                .iter()
                .map(String::capacity)
                .sum::<usize>()
    }
    fn lists_path(&self, path: &str) -> bool {
        self.source_paths.contains(path) || self.present.contains_key(path)
    }
    fn bytes(&self, path: &str) -> std::io::Result<Option<Vec<u8>>> {
        Ok(self
            .present
            .get(path)
            .map(|&index| self.inputs[index].source_bytes().to_vec()))
    }
}

struct StoredManifestSource {
    manifests: std::io::Result<HashMap<String, Vec<u8>>>,
    target_roots: std::io::Result<std::collections::HashSet<String>>,
}
impl ConfigurationSource for StoredManifestSource {
    fn lists_path(&self, path: &str) -> bool {
        self.target_roots
            .as_ref()
            .is_ok_and(|roots| roots.contains(path))
    }
    fn retained_bytes(&self) -> usize {
        self.target_roots.as_ref().map_or(0, |roots| {
            std::mem::size_of_val(roots)
                + roots.capacity() * (std::mem::size_of::<String>() + 1)
                + roots.iter().map(String::capacity).sum::<usize>()
        }) + self.manifests.as_ref().map_or(0, |manifests| {
            std::mem::size_of_val(manifests)
                + manifests.capacity() * (std::mem::size_of::<(String, Vec<u8>)>() + 1)
                + manifests
                    .iter()
                    .map(|(path, bytes)| path.capacity() + bytes.capacity())
                    .sum::<usize>()
        })
    }

    fn bytes(&self, path: &str) -> std::io::Result<Option<Vec<u8>>> {
        self.target_roots
            .as_ref()
            .map_err(|error| std::io::Error::new(error.kind(), error.to_string()))?;
        self.manifests
            .as_ref()
            .map(|manifests| manifests.get(path).cloned())
            .map_err(|error| std::io::Error::new(error.kind(), error.to_string()))
    }
}

struct StoredConfigurationSource {
    store: Arc<crate::analyzer::store::AnalyzerStore>,
    snapshot: crate::analyzer::store::WorkspaceSnapshotId,
}
impl ConfigurationSource for StoredConfigurationSource {
    fn bytes(&self, path: &str) -> std::io::Result<Option<Vec<u8>>> {
        self.store
            .selected_configuration_source(&self.snapshot, path)
            .map_err(std::io::Error::other)
    }
    fn bytes_with_conn(
        &self,
        conn: &rusqlite::Connection,
        path: &str,
    ) -> std::io::Result<Option<Vec<u8>>> {
        crate::analyzer::store::AnalyzerStore::selected_configuration_source_with_conn(
            conn,
            &self.snapshot,
            path,
        )
        .map_err(std::io::Error::other)
    }
}

impl SelectedConfigurationProject {
    pub(crate) fn new(
        project: Arc<dyn Project>,
        language: Language,
        store: Arc<crate::analyzer::store::AnalyzerStore>,
        snapshot: crate::analyzer::store::WorkspaceSnapshotId,
        projection_lease: Option<Arc<WorkspaceProjectionLease>>,
    ) -> Self {
        let naming_source = (language == Language::Rust).then(|| StoredManifestSource {
            target_roots: store
                .selected_rust_target_roots(&snapshot)
                .map_err(std::io::Error::other),
            manifests: store
                .selected_cargo_manifests(&snapshot)
                .map_err(std::io::Error::other),
        });
        Self {
            project_reads: brokk_bifrost_core::analyzer::project_reads::ProjectReadSlot::default(),
            project,
            language,
            source: Arc::new(StoredConfigurationSource {
                store: Arc::clone(&store),
                snapshot: snapshot.clone(),
            }),
            naming_source,
            publication: Some(SelectedConfigurationPublication {
                store,
                snapshot,
                _projection_lease: projection_lease,
            }),
        }
    }

    pub(crate) fn captured(
        project: Arc<dyn Project>,
        language: Language,
        inputs: Arc<Vec<crate::analyzer::store::WorkspaceConfigurationInput>>,
        files: &[ProjectFile],
    ) -> Self {
        Self {
            project_reads: brokk_bifrost_core::analyzer::project_reads::ProjectReadSlot::default(),
            project,
            language,
            source: Arc::new(CapturedConfigurationSource::new(inputs, files)),
            naming_source: None,
            publication: None,
        }
    }

    fn is_configuration(&self, path: &Path) -> bool {
        crate::analyzer::store::WorkspaceConfigurationInput::is_native_input(self.language, path)
    }

    fn configuration_source(&self, file: &ProjectFile) -> std::io::Result<Option<Vec<u8>>> {
        self.source.bytes(&crate::path_utils::rel_path_string(file))
    }
}

impl Project for SelectedConfigurationProject {
    fn file_listing_stamp(
        &self,
    ) -> Option<Vec<brokk_bifrost_core::analyzer::project::ProjectViewStamp>> {
        // Configuration bytes are pinned separately. Listing membership and
        // omissions still belong to the delegated project view.
        self.project.file_listing_stamp()
    }

    fn listing_receipt_structurally_unknown(&self) -> bool {
        self.project.listing_receipt_structurally_unknown()
    }

    fn membership_point_observation(
        &self,
        listing: &brokk_bifrost_core::analyzer::project::SharedWorkspaceFileListing,
    ) -> Option<brokk_bifrost_core::analyzer::project::WorkspaceMembershipPointObservation> {
        self.project.membership_point_observation(listing)
    }

    fn listing_ignore_inputs_verified(
        &self,
        listing: &brokk_bifrost_core::analyzer::project::SharedWorkspaceFileListing,
    ) -> bool {
        self.project.listing_ignore_inputs_verified(listing)
    }

    fn has_exact_directory_entry(&self, file: &ProjectFile) -> std::io::Result<bool> {
        self.project.has_exact_directory_entry(file)
    }

    fn update_cached_listing_for_resolved_path(&self, file: &ProjectFile) -> bool {
        self.project.update_cached_listing_for_resolved_path(file)
    }

    fn directory_entries(&self, parent: &Path) -> std::io::Result<BTreeSet<ProjectFile>> {
        self.project.directory_entries(parent)
    }

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
        let Some(publication) = &self.publication else {
            return self.project.selected_module_name(file);
        };
        if !crate::analyzer::store::store_language_support(self.language)
            .expect("selected language has store support")
            .publishes_own_module_file_anchors()
        {
            return self.project.selected_module_name(file);
        }
        publication
            .store
            .selected_module_name(
                &publication.snapshot,
                &crate::path_utils::rel_path_string(file),
            )
            .map_err(std::io::Error::other)
    }
    fn selected_module_name_with_conn(
        &self,
        conn: &rusqlite::Connection,
        file: &ProjectFile,
    ) -> std::io::Result<Option<String>> {
        let Some(publication) = &self.publication else {
            return self.project.selected_module_name_with_conn(conn, file);
        };
        if !crate::analyzer::store::store_language_support(self.language)
            .expect("selected language has store support")
            .publishes_own_module_file_anchors()
        {
            return self.project.selected_module_name_with_conn(conn, file);
        }
        crate::analyzer::store::AnalyzerStore::selected_module_name_with_conn(
            conn,
            &publication.snapshot,
            &crate::path_utils::rel_path_string(file),
        )
        .map_err(std::io::Error::other)
    }
    fn selected_configuration_lists_path(&self, path: &Path) -> bool {
        let source: &dyn ConfigurationSource = self
            .naming_source
            .as_ref()
            .map_or(self.source.as_ref(), |source| source);
        source.lists_path(&brokk_bifrost_core::path_utils::workspace_relative_slash_path(path))
    }
    fn selected_configuration_retained_bytes(&self) -> usize {
        self.naming_source.as_ref().map_or_else(
            || self.source.retained_bytes(),
            ConfigurationSource::retained_bytes,
        )
    }

    fn selected_configuration_bytes(&self, path: &Path) -> std::io::Result<Option<Vec<u8>>> {
        let source: &dyn ConfigurationSource = self
            .naming_source
            .as_ref()
            .map_or(self.source.as_ref(), |source| source);
        source.bytes(&brokk_bifrost_core::path_utils::workspace_relative_slash_path(path))
    }
    fn configuration_source_with_conn(
        &self,
        conn: &rusqlite::Connection,
        path: &Path,
    ) -> std::io::Result<Option<String>> {
        if !self.is_configuration(path) {
            return self.project.configuration_source_with_conn(conn, path);
        }
        self.source
            .bytes_with_conn(
                conn,
                &brokk_bifrost_core::path_utils::workspace_relative_slash_path(path),
            )?
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
    fn cached_omissions_if_available(
        &self,
    ) -> std::io::Result<
        Option<std::sync::Arc<Vec<brokk_bifrost_core::analyzer::project::WorkspaceFileOmission>>>,
    > {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        self.project.cached_omissions_if_available()
    }
    fn cached_listing_if_available(
        &self,
    ) -> std::io::Result<Option<brokk_bifrost_core::analyzer::project::SharedWorkspaceFileListing>>
    {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        self.project.cached_listing_if_available()
    }
    fn cached_analyzable_files_from(
        &self,
        files: &BTreeSet<ProjectFile>,
        language: Language,
    ) -> std::io::Result<Option<BTreeSet<ProjectFile>>> {
        let _project_read = brokk_bifrost_core::analyzer::project_reads::listing_read(self);
        self.project.cached_analyzable_files_from(files, language)
    }
    fn all_files_with_omissions(
        &self,
    ) -> std::io::Result<brokk_bifrost_core::analyzer::project::SharedWorkspaceFileListing> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.inventory(self.as_project()));
        self.project.all_files_with_omissions()
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
    fn retained_ignore_observation(
        &self,
    ) -> brokk_bifrost_core::analyzer::project::RetainedIgnoreObservation {
        self.project.retained_ignore_observation()
    }
    fn ignore_observation_for_files(
        &self,
        files: &BTreeSet<ProjectFile>,
    ) -> Result<
        brokk_bifrost_core::analyzer::project::IgnoreObservation,
        brokk_bifrost_core::analyzer::project::IgnoreObservationError,
    > {
        self.project.ignore_observation_for_files(files)
    }

    fn is_bifrostignored(
        &self,
        path: &Path,
    ) -> Result<bool, brokk_bifrost_core::analyzer::project::IgnoreObservationError> {
        let _project_read = self
            .project_read_slot()
            .map(|slot| slot.ignore_rules(self.as_project()));
        self.project.is_bifrostignored(path)
    }
    fn invalidate_cached_file_listing(&self) {
        self.project.invalidate_cached_file_listing();
    }
    fn revalidate_symlink_omissions(&self, changed: &BTreeSet<ProjectFile>) {
        self.project.revalidate_symlink_omissions(changed);
    }

    fn update_cached_listing_for_path(&self, path: &Path) -> bool {
        self.project.update_cached_listing_for_path(path)
    }
    fn update_cached_listing_for_removed_paths(&self, files: &[ProjectFile]) -> bool {
        self.project.update_cached_listing_for_removed_paths(files)
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
                    self.configuration_source(file)?
                        .map(brokk_bifrost_core::analyzer::project::ProjectFileSnapshot::disk)
                        .ok_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::NotFound,
                                "absent selected configuration",
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
    fn capture_source_overlays(
        &self,
    ) -> std::io::Result<Arc<brokk_bifrost_core::analyzer::project::PinnedSourceOverlayView>> {
        self.project.capture_source_overlays()
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
    host_activation:
        std::sync::OnceLock<Arc<crate::analyzer::semantic_model::HostActivationContext>>,
    pending_updates: BTreeSet<ProjectFile>,
    full_refresh_pending: bool,
    update_error: Option<StoreError>,
    project: Arc<dyn Project>,
    build_context: Option<Arc<WorkspaceBuildContext>>,
    /// A storeless workspace has no owner's budget, so its runtime caches
    /// use one that keeps nothing.
    retain_nothing: brokk_bifrost_core::retention_budget::RetentionBudget,
    project_reads: super::tree_sitter_analyzer::ProjectReadRegistry,
    // Fixed snapshot value for persisted C# receipt verification tests.
    #[cfg(test)]
    csharp_parse_variant_for_test: Result<brokk_bifrost_core::gitblob::ParseVariant, String>,
}
impl Clone for EmptyAnalyzer {
    fn clone(&self) -> Self {
        let mut clone = Self::new(Arc::clone(&self.project));
        clone.build_context = self.build_context.clone();
        clone.host_activation = self.host_activation.clone();
        clone.pending_updates = self.pending_updates.clone();
        clone.full_refresh_pending = self.full_refresh_pending;
        clone.update_error = self.update_error.clone();
        #[cfg(test)]
        {
            clone.csharp_parse_variant_for_test = self.csharp_parse_variant_for_test.clone();
        }
        clone
    }
}
impl EmptyAnalyzer {
    pub fn new(project: Arc<dyn Project>) -> Self {
        let project = super::project_read_facade::with_project_read_slot(project);
        let project_reads = super::tree_sitter_analyzer::ProjectReadRegistry::new(&project);
        Self {
            host_activation: std::sync::OnceLock::new(),
            pending_updates: BTreeSet::new(),
            full_refresh_pending: false,
            update_error: None,
            project,
            project_reads,
            build_context: None,
            retain_nothing: brokk_bifrost_core::retention_budget::RetentionBudget::retain_nothing(),
            #[cfg(test)]
            csharp_parse_variant_for_test: Ok(brokk_bifrost_core::gitblob::ParseVariant::Empty),
        }
    }
    #[cfg(test)]
    pub(crate) fn with_csharp_parse_variant_for_test(
        mut self,
        variant: brokk_bifrost_core::gitblob::ParseVariant,
    ) -> Self {
        self.csharp_parse_variant_for_test = Ok(variant);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_csharp_parse_variant_error_for_test(mut self, error: &str) -> Self {
        self.csharp_parse_variant_for_test = Err(error.to_owned());
        self
    }

    fn new_for_workspace(build_context: Arc<WorkspaceBuildContext>) -> Self {
        let mut analyzer = Self::new(Arc::clone(build_context.project()));
        if !build_context.store_context().workspace_listing_complete {
            analyzer.update_error = Some(
                build_context
                    .store_context()
                    .membership
                    .as_ref()
                    .expect("workspace construction captured membership")
                    .listing_failure(),
            );
            analyzer.full_refresh_pending = true;
        }
        analyzer.build_context = Some(build_context);
        analyzer
    }
    fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        let mut analyzer = Self::new(Arc::clone(&project));
        analyzer.host_activation = self.host_activation.clone();
        analyzer.pending_updates = self.pending_updates.clone();
        analyzer.full_refresh_pending = self.full_refresh_pending;
        analyzer.update_error = self.update_error.clone();
        analyzer.build_context = self
            .build_context
            .as_ref()
            .map(|context| Arc::new(context.clone_with_project(project)));
        analyzer
    }
    pub(crate) fn clone_for_read_attribution(&self) -> Self {
        Self {
            host_activation: self.host_activation.clone(),
            pending_updates: self.pending_updates.clone(),
            full_refresh_pending: self.full_refresh_pending,
            update_error: self.update_error.clone(),
            project: Arc::clone(&self.project),
            build_context: self.build_context.clone(),
            retain_nothing: self.retain_nothing.clone(),
            project_reads: self.project_reads.clone(),
            #[cfg(test)]
            csharp_parse_variant_for_test: self.csharp_parse_variant_for_test.clone(),
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
    fn host_activation_context(
        &self,
    ) -> Option<Arc<crate::analyzer::semantic_model::HostActivationContext>> {
        self.project_reads
            .host_activation_context()
            .unwrap_or_else(|| self.host_activation.get().cloned())
    }
    fn bind_host_activation_context(
        &self,
        host: Arc<crate::analyzer::semantic_model::HostActivationContext>,
    ) -> Result<(), String> {
        if self
            .host_activation
            .get()
            .is_some_and(|pinned| Arc::ptr_eq(pinned, &host))
        {
            return Ok(());
        }
        if host.requires_analyzed_root_validation() {
            host.validate_analyzed_root(self.project.root())?;
        }
        let wanted = host.identity();
        match self.host_activation.set(host) {
            Ok(()) => Ok(()),
            Err(_) if self.host_activation.get().is_some_and(|pinned| pinned.identity() == wanted) => Ok(()),
            Err(_) => Err("analyzer activation context is immutable; construct a new analyzer for another approval authority".into()),
        }
    }

    #[cfg(test)]
    fn selected_parse_variant(
        &self,
        _file: &brokk_bifrost_core::analyzer::ProjectFile,
    ) -> Option<brokk_bifrost_core::gitblob::ParseVariant> {
        #[cfg(test)]
        if _file.language() == Language::CSharp {
            return match &self.csharp_parse_variant_for_test {
                Ok(variant) => Some(*variant),
                Err(error) => {
                    self.record_query_failure(StoreError::new(error));
                    None
                }
            };
        }
        // Only C# carries parse variants.
        Some(brokk_bifrost_core::gitblob::ParseVariant::Empty)
    }

    fn generation_membership(
        &self,
    ) -> &Arc<super::tree_sitter_analyzer::GenerationWorkspaceMembership> {
        self.build_context
            .as_ref()
            .and_then(|context| context.store_context().membership.as_ref())
            .unwrap_or_else(|| {
                super::tree_sitter_analyzer::GenerationWorkspaceMembership::unavailable()
            })
    }

    fn require_workspace_languages(&self, languages: &[Language]) -> Result<(), StoreError> {
        self.build_context.as_ref().map_or(Ok(()), |context| {
            context.require_workspace_languages(languages)
        })
    }

    fn dynamic_import_sources(
        &self,
        seed_files: Option<&[ProjectFile]>,
    ) -> Result<Vec<(String, String)>, StoreError> {
        if let Some(context) = &self.build_context {
            context.require_import_source_selection(seed_files)?;
        }
        Ok(Vec::new())
    }

    fn begin_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        if let Some(error) = &self.update_error {
            context.record_store_error(error.clone());
        }
        self.project_reads.begin_query(context);
    }
    fn end_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        self.project_reads.end_query(context);
    }
    fn current_query_read_completion(&self) -> Result<(), crate::analyzer::QueryReadIncomplete> {
        super::i_analyzer::current_domain_read_completion()
    }
    fn record_query_incomplete(&self, reason: crate::analyzer::QueryReadIncomplete) {
        super::i_analyzer::record_query_incomplete_on_current_contexts(reason);
    }
    fn supports_selected_read_recording(&self) -> bool {
        true
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
    #[track_caller]
    fn record_unattributed_reads(&self, count: usize) {
        self.project_reads.record_unattributed_reads(count);
    }
    fn refuse_read_reuse(&self) {
        super::i_analyzer::record_reuse_refusal(
            || self.project_reads.read_ledger_attached(),
            || self.project_reads.contexts(),
        );
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

    fn update_with_listing(
        &self,
        _changed_files: &std::collections::BTreeSet<crate::analyzer::ProjectFile>,
        _listing: Option<&brokk_bifrost_core::analyzer::project::SharedWorkspaceFileListing>,
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

/// Hash the identities supplied by the active provider registry. The ordered
/// input also lets a regression test simulate one binary's adapter bump.
#[doc(hidden)]
pub fn policy_lowering_identity_from_adapters(
    adapters: impl IntoIterator<
        Item = (
            Language,
            crate::analyzer::semantic::service::SemanticAdapterIdentity,
            Option<crate::analyzer::semantic::AdapterSemanticsVersion>,
        ),
    >,
) -> crate::analyzer::semantic::ids::StableDigest {
    use crate::analyzer::semantic::ids::LengthDelimitedDigest;
    let mut digest = LengthDelimitedDigest::new(b"bifrost-policy-active-lowering:v1");
    digest.push(crate::analyzer::semantic::SemanticIrVersion::current().as_bytes());
    for (language, identity, type_flow) in adapters {
        digest.push(language.config_label().as_bytes());
        digest.push(identity.adapter.name().as_bytes());
        digest.push(identity.adapter.fingerprint().as_bytes());
        digest.push(identity.configuration.as_bytes());
        digest.push(identity.dependencies.as_bytes());
        digest.push(
            crate::analyzer::store::semantic_ir::semantic_ir_producer_epoch(&identity).as_bytes(),
        );
        // A presence marker keeps the field sequence fixed per language, so
        // adding or removing a type-flow adapter always changes the digest.
        match type_flow {
            Some(version) => {
                digest.push(b"type-flow:some");
                digest.push(version.name().as_bytes());
                digest.push(version.fingerprint().as_bytes());
            }
            None => digest.push(b"type-flow:none"),
        }
    }
    digest.finish()
}

/// Caller-owned state needed to activate explicitly configured dependency packs.
/// Construction reconciles source build membership without opening a semantic-pack
/// catalog. Hosts opt into pack activation by supplying this context.
#[derive(Clone, Copy)]
pub struct DependencyPackWorkspaceContext<'a> {
    pub catalog: &'a SemanticPackCatalog,
    pub persistence: Option<SemanticModelActivationPersistence<'a>>,
    pub activation: &'a SemanticModelActivationRequest,
    pub limits: DependencyPackLimits,
    pub cancellation: &'a crate::CancellationToken,
}

type DependencyPackDiscoveryResult = (
    &'static dyn DependencyResolver,
    DependencyPackLimits,
    crate::analyzer::semantic_model::CapturedDependencyDiscovery,
);

pub type PythonSemanticModelWorkspaceContext<'a> = DependencyPackWorkspaceContext<'a>;

#[derive(Debug)]
pub struct PythonSemanticModelActivationOutcome {
    pub discovery: DependencyDiscoveryOutcome,
    pub preparation: Option<DependencyPackPreparationOutcome>,
    pub runtime: Option<SemanticModelRuntimeOutcome>,
}

/// One dependency ecosystem whose exact local evidence a host can activate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

#[derive(Debug, Clone)]
pub struct DependencyPackEcosystemOutcome {
    pub ecosystem: DependencyPackEcosystem,
    pub discovery: DependencyDiscoveryOutcome,
    pub preparation: Option<DependencyPackPreparationOutcome>,
}

/// Result of one host-owned activation transaction.
#[derive(Debug, Clone)]
pub struct DependencyPackActivationOutcome {
    pub ecosystems: Vec<DependencyPackEcosystemOutcome>,
    pub runtime: Option<SemanticModelRuntimeOutcome>,
    /// Hosts must refresh published diagnostics when this value is true.
    pub diagnostic_refresh_required: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DependencyPackPublicationKind {
    Full,
    Subset,
}

struct DependencyPackPublicationEvidence {
    kind: DependencyPackPublicationKind,
    pending_previous:
        Option<crate::analyzer::semantic_model::runtime::PendingDependencyPublication>,
    dependencies: Vec<(Box<[Language]>, DependencyDiscoveryEvidence)>,
    withdrawn_languages: Vec<Language>,
    pending_languages: Vec<Language>,
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

#[derive(Debug)]
struct StagedDependencyDiscoveryEntry {
    ecosystem: DependencyPackEcosystem,
    config: AnalyzerConfig,
    limits: DependencyPackLimits,
    discovery: crate::analyzer::semantic_model::CapturedDependencyDiscovery,
}

/// Per-ecosystem captured discovery and receipts handed from the installed
/// stage to the configured stage within one semantic-pack warm.
#[derive(Debug, Default)]
pub struct StagedDependencyDiscoveryHandoff {
    entries: Vec<StagedDependencyDiscoveryEntry>,
}

impl StagedDependencyDiscoveryHandoff {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn take_ecosystem(
        &mut self,
        ecosystem: DependencyPackEcosystem,
    ) -> Option<StagedDependencyDiscoveryEntry> {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.ecosystem == ecosystem)?;
        Some(self.entries.swap_remove(index))
    }
}

/// The installed-pack stage's activation: the published interim outcome plus
/// every dependency whose exact acquisition remains for the full stage.
#[derive(Debug)]
pub struct InstalledDependencyPackActivationOutcome {
    pub outcome: DependencyPackActivationOutcome,
    pub pending: Vec<PendingDependencyPackAcquisition>,
    pub discovery_handoff: Option<StagedDependencyDiscoveryHandoff>,
}

/// External discovery inputs must obey the same rule within and across generations.
pub(crate) fn dependency_external_reads_unchanged(evidence: &DependencyDiscoveryEvidence) -> bool {
    evidence
        .carry_eligible_external_reads()
        .is_some_and(|keys| keys.iter().all(|key| key.still_matches()))
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
    pub fn bind_host_activation_context(
        &self,
        host: Arc<crate::analyzer::semantic_model::HostActivationContext>,
    ) -> Result<(), String> {
        self.analyzer().bind_host_activation_context(host)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn test_pending_update_paths(&self) -> &BTreeSet<ProjectFile> {
        match self {
            Self::Multi(analyzer) => &analyzer.pending_updates,
            Self::Empty(analyzer) => &analyzer.pending_updates,
        }
    }

    /// The owner used by this workspace and any delegates it builds on update.
    #[doc(hidden)]
    pub fn retention_budget(&self) -> &brokk_bifrost_core::retention_budget::RetentionBudget {
        if let Some(caches) = self.analyzer().snapshot_caches() {
            caches.retention_budget()
        } else if let Some(store) = self.store() {
            store.retention_budget()
        } else {
            match self {
                Self::Empty(empty) => empty
                    .build_context
                    .as_deref()
                    .map_or(&empty.retain_nothing, |context| context.retention_budget()),
                _ => panic!("a workspace with analyzers has a store and its budget"),
            }
        }
    }

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
        if self.analyzer().generation_membership().listing().is_err() {
            return DependencyDiscoveryOutcome::generation_listing_unavailable(cancellation);
        }
        crate::analyzer::languages::language_support_for_hook(
            ecosystem.languages()[0],
            "resolve_workspace_dependencies",
        )
        .expect("dependency ecosystem primary language support")
        .resolve_workspace_dependencies(self, config, limits, cancellation)
    }

    /// Discovery membership is the generation's build/update record. Project
    /// reads already belong to that generation; external reads remain live and
    /// are verified by activation reuse. Never reconstruct membership here.
    #[doc(hidden)]
    pub fn dependency_discovery_project(
        &self,
    ) -> Result<Arc<dyn Project + '_>, super::tree_sitter_analyzer::GenerationListingUnavailable>
    {
        self.analyzer().generation_membership().listing()?;
        Ok(generation_dependency_discovery_project(self.analyzer()))
    }

    pub fn store_captured_dependency_discovery(
        &self,
        ecosystem: DependencyPackEcosystem,
        discovery: crate::analyzer::semantic_model::CapturedDependencyDiscovery,
    ) {
        self.analyzer()
            .snapshot_caches()
            .expect("updated snapshot has caches")
            .store_captured_dependency_discovery(ecosystem, discovery);
    }

    /// Whether this snapshot already holds a finished discovery of `ecosystem`
    /// for the activation stage, so a repeat discovery would only find every
    /// input reconciled and record none of the reads the first one made.
    pub fn captured_dependency_discovery_is_complete(
        &self,
        ecosystem: DependencyPackEcosystem,
    ) -> bool {
        self.analyzer()
            .snapshot_caches()
            .is_some_and(|caches| caches.captured_dependency_discovery_is_complete(ecosystem))
    }

    fn take_captured_dependency_discovery(
        &self,
        ecosystem: DependencyPackEcosystem,
    ) -> Option<crate::analyzer::semantic_model::CapturedDependencyDiscovery> {
        self.analyzer()
            .snapshot_caches()
            .and_then(|caches| caches.take_captured_dependency_discovery(ecosystem))
    }

    fn discover_dependency_pack_ecosystem(
        &self,
        ecosystem: DependencyPackEcosystem,
        config: &AnalyzerConfig,
        context: &DependencyPackWorkspaceContext<'_>,
    ) -> DependencyPackDiscoveryResult {
        let resolver = ecosystem.resolver();
        let mut limits = context.limits;
        resolver.adjust_limits(config, &mut limits);
        let discovery = self
            .take_captured_dependency_discovery(ecosystem)
            .filter(|_| self.analyzer().generation_membership().listing().is_ok())
            .unwrap_or_else(|| {
                let _scope = crate::profiling::scope_with(|| {
                    format!("semantic_pack.discover[{}]", ecosystem.label())
                });
                crate::analyzer::semantic_model::capture_dependency_discovery(
                    self.analyzer(),
                    || {
                        self.resolve_dependency_discovery(
                            ecosystem,
                            config,
                            &limits,
                            context.cancellation,
                        )
                    },
                )
            });
        (resolver, limits, discovery)
    }

    fn missing_membership_ecosystem(
        &self,
        ecosystem: DependencyPackEcosystem,
        cancellation: &crate::CancellationToken,
    ) -> Option<DependencyPackEcosystemOutcome> {
        self.analyzer()
            .generation_membership()
            .listing()
            .err()
            .map(|_| DependencyPackEcosystemOutcome {
                ecosystem,
                discovery: DependencyDiscoveryOutcome::generation_listing_unavailable(cancellation),
                preparation: None,
            })
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
        self.activate_dependency_packs_with_inputs(
            config,
            ecosystems,
            context,
            None,
            DependencyPackPublicationKind::Full,
            None,
        )
    }

    /// Refresh only the selected ecosystems, carrying all other contributions.
    pub fn refresh_selected_dependency_packs(
        &self,
        config: &AnalyzerConfig,
        selected: &[DependencyPackEcosystem],
        context: DependencyPackWorkspaceContext<'_>,
    ) -> DependencyPackActivationOutcome {
        self.activate_dependency_packs_with_inputs(
            config,
            selected,
            context,
            None,
            DependencyPackPublicationKind::Subset,
            None,
        )
    }

    pub(crate) fn activate_dependency_packs_with_inputs(
        &self,
        config: &AnalyzerConfig,
        ecosystems: &[DependencyPackEcosystem],
        context: DependencyPackWorkspaceContext<'_>,
        inputs: Option<&ActivationInputs>,
        kind: DependencyPackPublicationKind,
        handoff: Option<StagedDependencyDiscoveryHandoff>,
    ) -> DependencyPackActivationOutcome {
        if let Err(reason) =
            self.bind_host_activation_context(Arc::clone(&context.activation.host_activation))
        {
            let mut report = crate::analyzer::semantic_model::SemanticModelActivationReport {
                host_activation: context.activation.host_activation.metadata().map(Box::new),
                ..Default::default()
            };
            crate::analyzer::semantic_model::runtime::push_request_explanation(
                &mut report,
                context.activation.limits,
                reason,
            );
            return DependencyPackActivationOutcome {
                ecosystems: Vec::new(),
                runtime: Some(SemanticModelRuntimeOutcome::Unavailable(report)),
                diagnostic_refresh_required: false,
            };
        }

        context.catalog.with_activation_publication(|| {
            self.activate_dependency_packs_in_publication(
                config, ecosystems, context, inputs, kind, handoff,
            )
        })
    }

    fn activate_dependency_packs_in_publication(
        &self,
        config: &AnalyzerConfig,
        ecosystems: &[DependencyPackEcosystem],
        context: DependencyPackWorkspaceContext<'_>,
        inputs: Option<&ActivationInputs>,
        kind: DependencyPackPublicationKind,
        handoff: Option<StagedDependencyDiscoveryHandoff>,
    ) -> DependencyPackActivationOutcome {
        let mut activation =
            self.dependency_pack_activation_inputs(ecosystems, &context, inputs, kind);
        let cache = self
            .analyzer()
            .snapshot_caches()
            .map(|caches| caches.semantic_models());
        let same_generation_key = cache.and_then(|cache| {
            crate::analyzer::semantic_model::runtime::DependencyActivationKey::new(
                config,
                ecosystems,
                &context,
                &activation,
                cache,
            )
        });
        // Check before discovery. The key covers the discovery inputs and the
        // retained entry revalidates every recorded external read (#11890).
        // Comparing after discovery would discard fresh completeness evidence,
        // so cross-generation carry keeps its separate finalized key (#12435).
        if kind == DependencyPackPublicationKind::Full
            && let Some(cache) = cache
            && let Some(outcome) = cache.reuse_dependency_activation(
                same_generation_key.as_ref(),
                context.cancellation,
                self.analyzer(),
                context.catalog,
                ecosystems,
                |mut outcome| {
                    let republish =
                        || -> Result<(), crate::analyzer::semantic_model::CatalogError> {
                            if context.cancellation.is_cancelled() {
                                return Err(
                                    crate::analyzer::semantic_model::CatalogError::Cancelled,
                                );
                            }
                            if let Some(persistence) = context.persistence {
                                context.catalog.reconcile_workspace_active_set(
                                    persistence.scope_id,
                                    persistence.store,
                                )?;
                            }
                            let Some(SemanticModelRuntimeOutcome::Ready { snapshot, .. }) =
                                &outcome.runtime
                            else {
                                unreachable!("retained activation is Ready")
                            };
                            crate::analyzer::semantic_model::runtime::publish_active_models(
                                self.analyzer(),
                                context.catalog,
                                context.persistence,
                                snapshot.active_models(),
                                context.cancellation,
                            )?;
                            if context.cancellation.is_cancelled() {
                                return Err(
                                    crate::analyzer::semantic_model::CatalogError::Cancelled,
                                );
                            }
                            Ok(())
                        };
                    if let Err(error) = republish() {
                        return DependencyPackActivationOutcome {
                            ecosystems: outcome.ecosystems,
                            runtime: Some(
                                crate::analyzer::semantic_model::runtime::catalog_lifecycle_error(
                                    activation.request.limits,
                                    "republish retained activation",
                                    error,
                                ),
                            ),
                            diagnostic_refresh_required: false,
                        };
                    }
                    // This invocation replayed evidence; it performed no
                    // discovery or dependency preparation work.
                    for ecosystem in &mut outcome.ecosystems {
                        // Informational evidence includes semantic standard-
                        // library expectations, so retain it while clearing
                        // only this invocation's work counters.
                        ecosystem.discovery.profile.metadata_inputs_considered = 0;
                        ecosystem.discovery.profile.dependencies_resolved = 0;
                        if let Some(preparation) = &mut ecosystem.preparation {
                            preparation.profile = Default::default();
                        }
                    }
                    if let Some(SemanticModelRuntimeOutcome::Ready { lifecycle, .. }) =
                        &mut outcome.runtime
                    {
                        *lifecycle =
                            crate::analyzer::semantic_model::SemanticModelRuntimeLifecycle::Cached;
                    }
                    outcome
                },
            )
        {
            return outcome;
        }
        let mut outcomes = Vec::with_capacity(ecosystems.len());
        let mut publication_evidence = Vec::with_capacity(ecosystems.len());
        let mut withdrawn_languages = Vec::new();
        let mut cancelled = false;
        let mut handoff_verification = handoff.filter(|h| !h.is_empty()).map(|handoff| {
            let empty = crate::analyzer::semantic::ids::StableDigest::sha256([]);
            (
                handoff,
                None::<super::read_verification::ChangedFacts>,
                super::read_verification::HeadInputs {
                    models: empty,
                    policy_semantic_hash: empty,
                    policy_source: empty,
                    configuration: empty,
                    epoch: empty,
                },
                super::read_verification::LookupMemo::default(),
            )
        });

        // Dependency-pack work runs before the parse phase and is attributed to
        // the workspace as a whole, so a slow ecosystem looks like slow startup
        // with no further detail. The discover/prepare span pair is per
        // ecosystem on purpose: it names which resolver is spending the time and
        // separates discovery, which walks the workspace, from preparation,
        // which reads and generates packs.
        for ecosystem in ecosystems.iter().copied() {
            // Missing dependency inputs do not suppress independent workspace
            // models or explicit evidence assembled before this transaction.
            if let Some(outcome) =
                self.missing_membership_ecosystem(ecosystem, context.cancellation)
            {
                cancelled = outcome.discovery.cancelled;
                outcomes.push(outcome);
                if cancelled {
                    break;
                }
                continue;
            }
            let (resolver, limits, captured_discovery) =
                if let Some((handoff, changed_slot, inputs, memo)) = &mut handoff_verification
                    && let Some(entry) = handoff.take_ecosystem(ecosystem)
                {
                    let resolver = ecosystem.resolver();
                    let mut expected_limits = context.limits;
                    resolver.adjust_limits(config, &mut expected_limits);
                    let same_configuration =
                        entry.config == *config && entry.limits == expected_limits;
                    let membership_unchanged =
                        self.analyzer().generation_membership().listing().is_ok()
                            && self.analyzer().project().ignore_rules_digest().is_ok();
                    let external_eligible =
                        DependencyDiscoveryEvidence::carry_eligible_external_reads_for_parts(
                            entry.discovery.outcome.has_unrecorded_diagnostics(|code| {
                                resolver.diagnostic_follows_recorded_reads(code)
                            }),
                            0,
                            entry.discovery.external_reads.complete,
                            &entry.discovery.external_reads.keys,
                        )
                        .is_some_and(|keys| keys.iter().all(|key| key.still_matches()));
                    let verified = external_eligible && same_configuration && {
                        let changed = changed_slot.get_or_insert_with(|| {
                            super::read_verification::ChangedFacts::between(self, self)
                        });
                        verify_dependency_discovery_project_reads(
                            self,
                            changed,
                            inputs,
                            memo,
                            entry.discovery.project_read_identity,
                            &entry.discovery.project_read_keys,
                            membership_unchanged,
                            #[cfg(any(test, feature = "test-support"))]
                            None,
                        )
                    };
                    if verified {
                        (resolver, entry.limits, entry.discovery)
                    } else {
                        self.discover_dependency_pack_ecosystem(ecosystem, config, &context)
                    }
                } else {
                    self.discover_dependency_pack_ecosystem(ecosystem, config, &context)
                };
            let crate::analyzer::semantic_model::CapturedDependencyDiscovery {
                outcome: discovery,
                rust_cargo_graph,
                project_read_keys: discovery_read_keys,
                project_read_identity: discovery_read_identity,
                external_reads,
            } = captured_discovery;
            if ecosystem == DependencyPackEcosystem::Cargo {
                activation.rust_cargo_graph = rust_cargo_graph;
            }
            activation
                .request
                .approximate_standard_libraries
                .extend(discovery.approximate_standard_libraries(ecosystem.label()));
            if discovery.cancelled {
                cancelled = true;
                outcomes.push(DependencyPackEcosystemOutcome {
                    ecosystem,
                    discovery,
                    preparation: None,
                });
                break;
            }
            let preparation_bindings =
                crate::analyzer::semantic_model::dependency::preparation_input_bindings(
                    &discovery.dependencies,
                    &limits,
                    Some(context.cancellation),
                );
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
            if !preparation.complete && preparation.evidence.is_empty() {
                withdrawn_languages.extend_from_slice(ecosystem.languages());
            }
            {
                activation
                    .request
                    .evidence
                    .extend(preparation.evidence.iter().cloned());
                let retained_status =
                    crate::analyzer::semantic_model::RetainedEcosystemStatus::retain(
                        &discovery,
                        Some(&preparation),
                        self.retention_budget(),
                    );
                let mut failure_evidence = DependencyDiscoveryEvidence::from_outcome(&discovery)
                    .with_diagnostics_judged_by(&discovery, |code| {
                        resolver.diagnostic_follows_recorded_reads(code)
                    })
                    .with_retained_status(retained_status)
                    .with_preparation_failures(
                        &discovery.dependencies,
                        &preparation.failures,
                        &preparation_bindings,
                    );
                activation
                    .preparation_failures
                    .append(&mut failure_evidence.preparation_failures);
                {
                    publication_evidence.push((
                        ecosystem.languages().to_vec().into_boxed_slice(),
                        failure_evidence
                            .with_project_reads(discovery_read_keys, discovery_read_identity)
                            .with_external_reads(external_reads.keys, external_reads.complete),
                    ));
                }
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
            withdrawn_languages,
            Vec::new(),
            None,
            outcomes,
            cancelled,
            ecosystems,
            kind,
            &context,
            same_generation_key,
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
        self.activate_installed_dependency_packs_with_inputs(
            config,
            ecosystems,
            context,
            None,
            DependencyPackPublicationKind::Full,
        )
    }

    /// Refresh only the selected ecosystems, carrying all other contributions.
    pub fn refresh_selected_installed_dependency_packs(
        &self,
        config: &AnalyzerConfig,
        selected: &[DependencyPackEcosystem],
        context: DependencyPackWorkspaceContext<'_>,
    ) -> InstalledDependencyPackActivationOutcome {
        self.activate_installed_dependency_packs_with_inputs(
            config,
            selected,
            context,
            None,
            DependencyPackPublicationKind::Subset,
        )
    }

    pub(crate) fn activate_installed_dependency_packs_with_inputs(
        &self,
        config: &AnalyzerConfig,
        ecosystems: &[DependencyPackEcosystem],
        context: DependencyPackWorkspaceContext<'_>,
        inputs: Option<&ActivationInputs>,
        kind: DependencyPackPublicationKind,
    ) -> InstalledDependencyPackActivationOutcome {
        if let Err(reason) =
            self.bind_host_activation_context(Arc::clone(&context.activation.host_activation))
        {
            let mut report = crate::analyzer::semantic_model::SemanticModelActivationReport {
                host_activation: context.activation.host_activation.metadata().map(Box::new),
                ..Default::default()
            };
            crate::analyzer::semantic_model::runtime::push_request_explanation(
                &mut report,
                context.activation.limits,
                reason,
            );
            return InstalledDependencyPackActivationOutcome {
                outcome: DependencyPackActivationOutcome {
                    ecosystems: Vec::new(),
                    runtime: Some(SemanticModelRuntimeOutcome::Unavailable(report)),
                    diagnostic_refresh_required: false,
                },
                pending: Vec::new(),
                discovery_handoff: None,
            };
        }

        if let Some(caches) = self.analyzer().snapshot_caches() {
            caches.semantic_models().clear_dependency_activation();
        }
        let mut outcomes = Vec::with_capacity(ecosystems.len());
        let mut activation =
            self.dependency_pack_activation_inputs(ecosystems, &context, inputs, kind);
        let mut publication_evidence = Vec::with_capacity(ecosystems.len());
        let mut withdrawn_languages = Vec::new();
        let mut pending = Vec::new();
        let pending_previous = self
            .analyzer()
            .snapshot_caches()
            .map(|caches| caches.semantic_models().capture_pending_publication());
        let mut pending_languages = Vec::new();
        let mut staged_discoveries = Vec::with_capacity(ecosystems.len());
        let mut cancelled = false;

        for ecosystem in ecosystems.iter().copied() {
            // Missing dependency inputs do not suppress independent workspace
            // models or explicit evidence assembled before this transaction.
            if let Some(outcome) =
                self.missing_membership_ecosystem(ecosystem, context.cancellation)
            {
                cancelled = outcome.discovery.cancelled;
                outcomes.push(outcome);
                if cancelled {
                    break;
                }
                continue;
            }
            let (resolver, limits, captured_discovery) =
                self.discover_dependency_pack_ecosystem(ecosystem, config, &context);
            if !captured_discovery.outcome.cancelled {
                staged_discoveries.push(StagedDependencyDiscoveryEntry {
                    ecosystem,
                    config: config.clone(),
                    limits,
                    discovery: captured_discovery.clone(),
                });
            }
            let crate::analyzer::semantic_model::CapturedDependencyDiscovery {
                outcome: discovery,
                rust_cargo_graph,
                project_read_keys: discovery_read_keys,
                project_read_identity: discovery_read_identity,
                external_reads,
            } = captured_discovery;
            if ecosystem == DependencyPackEcosystem::Cargo {
                activation.rust_cargo_graph = rust_cargo_graph;
            }
            activation
                .request
                .approximate_standard_libraries
                .extend(discovery.approximate_standard_libraries(ecosystem.label()));
            if discovery.cancelled {
                cancelled = true;
                outcomes.push(DependencyPackEcosystemOutcome {
                    ecosystem,
                    discovery,
                    preparation: None,
                });
                break;
            }
            let preparation_bindings =
                crate::analyzer::semantic_model::dependency::preparation_input_bindings(
                    &discovery.dependencies,
                    &limits,
                    Some(context.cancellation),
                );
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
            let previous_evidence = pending_previous
                .as_ref()
                .and_then(|previous| previous.contributions.get(&ecosystem));
            if !preparation.pending.is_empty()
                && pending_previous.as_ref().is_some_and(|previous| {
                    ecosystem
                        .languages()
                        .iter()
                        .all(|language| previous.can_substitute(*language))
                })
                && let Some(evidence) = previous_evidence
            {
                pending_languages.extend_from_slice(ecosystem.languages());
                activation
                    .request
                    .evidence
                    .extend(evidence.evidence.clone());
                if let Some(previous) = pending_previous
                    .as_ref()
                    .and_then(|previous| previous.inputs.clone())
                {
                    activation.preparation_failures.extend(
                        previous.preparation_failures.into_iter().filter(|failure| {
                            ecosystem.languages().iter().any(|language| {
                                language.config_label() == failure.dependency.evidence.language
                            })
                        }),
                    );
                    if ecosystem == DependencyPackEcosystem::Cargo {
                        activation.rust_cargo_graph = previous.rust_cargo_graph;
                    }
                }
                pending.extend(preparation.pending.into_iter().map(|dependency_id| {
                    PendingDependencyPackAcquisition {
                        ecosystem,
                        dependency_id,
                    }
                }));
                outcomes.push(DependencyPackEcosystemOutcome {
                    ecosystem,
                    discovery,
                    preparation: Some(preparation.outcome),
                });
                continue;
            }
            if preparation.pending.is_empty()
                && !preparation.outcome.complete
                && preparation.outcome.evidence.is_empty()
            {
                withdrawn_languages.extend_from_slice(ecosystem.languages());
            }
            pending.extend(preparation.pending.into_iter().map(|dependency_id| {
                PendingDependencyPackAcquisition {
                    ecosystem,
                    dependency_id,
                }
            }));
            {
                activation
                    .request
                    .evidence
                    .extend(preparation.outcome.evidence.iter().cloned());
                let retained_status =
                    crate::analyzer::semantic_model::RetainedEcosystemStatus::retain(
                        &discovery,
                        Some(&preparation.outcome),
                        self.retention_budget(),
                    );
                let mut failure_evidence = DependencyDiscoveryEvidence::from_outcome(&discovery)
                    .with_diagnostics_judged_by(&discovery, |code| {
                        resolver.diagnostic_follows_recorded_reads(code)
                    })
                    .with_retained_status(retained_status)
                    .with_preparation_failures(
                        &discovery.dependencies,
                        &preparation.outcome.failures,
                        &preparation_bindings,
                    );
                activation
                    .preparation_failures
                    .append(&mut failure_evidence.preparation_failures);
                {
                    publication_evidence.push((
                        ecosystem.languages().to_vec().into_boxed_slice(),
                        failure_evidence
                            .with_project_reads(discovery_read_keys, discovery_read_identity)
                            .with_external_reads(external_reads.keys, external_reads.complete),
                    ));
                }
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
            withdrawn_languages,
            pending_languages,
            pending_previous,
            outcomes,
            cancelled,
            ecosystems,
            kind,
            &context,
            None,
        );

        let discovery_handoff =
            (!pending.is_empty() && !cancelled).then_some(StagedDependencyDiscoveryHandoff {
                entries: staged_discoveries,
            });
        InstalledDependencyPackActivationOutcome {
            outcome,
            pending,
            discovery_handoff,
        }
    }

    fn dependency_pack_activation_inputs(
        &self,
        ecosystems: &[DependencyPackEcosystem],
        context: &DependencyPackWorkspaceContext<'_>,
        inputs: Option<&ActivationInputs>,
        kind: DependencyPackPublicationKind,
    ) -> ActivationInputs {
        let mut activation = inputs
            .cloned()
            .or_else(|| self.carried_activation_inputs())
            .unwrap_or_else(|| ActivationInputs {
                preparation_failures: Vec::new(),
                request: context.activation.clone(),
                rust_cargo_graph: None,
            });
        // Fresh workspace-source inputs carry current request controls, but
        // sibling terminal outcomes still belong to the retained publication.
        if kind == DependencyPackPublicationKind::Subset
            && let Some(carried) = self.carried_activation_inputs()
        {
            for failure in carried.preparation_failures {
                if !activation.preparation_failures.contains(&failure) {
                    activation.preparation_failures.push(failure);
                }
            }
        }
        activation.preparation_failures.retain(|failure| {
            kind == DependencyPackPublicationKind::Subset
                && !ecosystems.iter().any(|ecosystem| {
                    ecosystem.languages().iter().any(|language| {
                        language.config_label() == failure.dependency.evidence.language
                    })
                })
        });
        activation.request = context.activation.clone();
        if kind == DependencyPackPublicationKind::Subset
            && let Some(caches) = self.analyzer().snapshot_caches()
        {
            for (ecosystem, evidence) in caches.semantic_models().dependency_request_evidence() {
                if !ecosystems.contains(&ecosystem) {
                    activation.request.evidence.extend(evidence.evidence);
                }
            }
        }
        if kind == DependencyPackPublicationKind::Full
            || ecosystems.contains(&DependencyPackEcosystem::Cargo)
        {
            activation.rust_cargo_graph = None;
        }
        activation
    }

    // These are the distinct values consumed directly by the shared finalization tail.
    #[allow(clippy::too_many_arguments)]
    fn finalize_dependency_pack_activation(
        &self,
        config: &AnalyzerConfig,
        mut activation: ActivationInputs,
        dependencies: Vec<(Box<[Language]>, DependencyDiscoveryEvidence)>,
        withdrawn_languages: Vec<Language>,
        pending_languages: Vec<Language>,
        pending_previous: Option<
            crate::analyzer::semantic_model::runtime::PendingDependencyPublication,
        >,
        outcomes: Vec<DependencyPackEcosystemOutcome>,
        cancelled: bool,
        ecosystems: &[DependencyPackEcosystem],
        kind: DependencyPackPublicationKind,
        context: &DependencyPackWorkspaceContext<'_>,
        same_generation_key: Option<
            crate::analyzer::semantic_model::runtime::DependencyActivationKey,
        >,
    ) -> DependencyPackActivationOutcome {
        let cancelled_outcome = |ecosystems| DependencyPackActivationOutcome {
            ecosystems,
            runtime: Some(SemanticModelRuntimeOutcome::Cancelled(Default::default())),
            diagnostic_refresh_required: false,
        };
        if cancelled || context.cancellation.is_cancelled() {
            return cancelled_outcome(outcomes);
        }
        let jdk_artifacts = prepared_jdk_artifacts_for_source_bindings(
            config,
            self.analyzer().project().root(),
            &outcomes,
        )
        .filter(|_| !pending_languages.contains(&Language::Java));
        let python_runtime = match python_runtime_publication(
            self,
            config,
            &mut activation.request,
            context,
        ) {
            Ok(publication) => publication,
            Err(error) => {
                if context.cancellation.is_cancelled() {
                    return cancelled_outcome(outcomes);
                }
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
            config,
            activation,
            DependencyPackPublicationEvidence {
                kind,
                pending_previous,
                dependencies,
                withdrawn_languages,
                pending_languages,
                jdk_artifacts,
                python_runtime,
            },
            outcomes,
            cancelled,
            ecosystems,
            context,
            same_generation_key,
        )
    }

    /// Publish one assembled dependency activation into this analyzer's
    /// overlay: the shared tail of [`Self::activate_dependency_packs`] and
    /// [`Self::activate_installed_dependency_packs`]. An activation with
    /// nothing to publish leaves any previous publication untouched.
    #[allow(clippy::too_many_arguments)]
    fn publish_dependency_pack_activation(
        &self,
        config: &AnalyzerConfig,
        mut activation: ActivationInputs,
        publication: DependencyPackPublicationEvidence,
        outcomes: Vec<DependencyPackEcosystemOutcome>,
        cancelled: bool,
        ecosystems: &[DependencyPackEcosystem],
        context: &DependencyPackWorkspaceContext<'_>,
        same_generation_key: Option<
            crate::analyzer::semantic_model::runtime::DependencyActivationKey,
        >,
    ) -> DependencyPackActivationOutcome {
        // A settled failure is not publication evidence. With no prior overlay
        // there is no runtime publication to report. Still retain discovery and
        // failure diagnostics through the atomic snapshot installation below.
        // A prior overlay must be withdrawn through that same installation.
        let failure_without_prior_overlay = !ecosystems.is_empty()
            && publication.pending_languages.is_empty()
            && activation.request.evidence.is_empty()
            && activation.request.approximate_standard_libraries.is_empty()
            && !outcomes.iter().any(|outcome| {
                outcome.preparation.as_ref().is_some_and(|preparation| {
                    preparation.complete || !preparation.evidence.is_empty()
                })
            })
            && self.analyzer().semantic_model_overlay().is_none();
        if cancelled
            || (publication.kind == DependencyPackPublicationKind::Subset
                && publication.pending_languages.is_empty()
                && !ecosystems.is_empty()
                && publication.dependencies.is_empty()
                && publication.withdrawn_languages.is_empty()
                && activation.request.evidence.is_empty()
                && activation.request.approximate_standard_libraries.is_empty())
        {
            return DependencyPackActivationOutcome {
                ecosystems: outcomes,
                runtime: None,
                diagnostic_refresh_required: false,
            };
        }

        activation.request.evidence.sort();
        activation.request.evidence.dedup();
        if let Some(graph) = &mut activation.rust_cargo_graph {
            graph.retain_evidence(&activation.request.evidence);
        }
        debug_assert!(
            activation
                .rust_cargo_graph
                .as_ref()
                .is_none_or(|graph| graph
                    .validate_evidence(&activation.request.evidence)
                    .is_ok()),
            "retain_evidence leaves exactly the evidence the Cargo graph validates"
        );
        let mut dependency_request_evidence = self
            .analyzer()
            .snapshot_caches()
            .map(|caches| caches.semantic_models().dependency_request_evidence())
            .unwrap_or_default();
        if publication.kind == DependencyPackPublicationKind::Full {
            dependency_request_evidence.retain(|ecosystem, _| {
                ecosystem
                    .languages()
                    .iter()
                    .any(|language| publication.pending_languages.contains(language))
            });
        }
        for outcome in &outcomes {
            if outcome
                .ecosystem
                .languages()
                .iter()
                .any(|language| publication.pending_languages.contains(language))
            {
                continue;
            }
            dependency_request_evidence.insert(
                outcome.ecosystem,
                crate::analyzer::semantic_model::DependencyRequestEvidence {
                    evidence: outcome
                        .preparation
                        .as_ref()
                        .map(|preparation| preparation.evidence.clone())
                        .unwrap_or_default(),
                    publication_eligible: outcome.preparation.as_ref().is_some_and(|preparation| {
                        preparation.complete || !preparation.evidence.is_empty()
                    }),
                },
            );
        }
        activation.finalize_request();
        let ecosystems = outcomes
            .iter()
            .map(|outcome| outcome.ecosystem)
            .collect::<Vec<_>>();
        let cache = self
            .analyzer()
            .snapshot_caches()
            .map(|cache| cache.semantic_models());
        let runtime_artifacts = RuntimeArtifactPublication {
            publication_kind: Some(publication.kind),
            activated_ecosystems: &ecosystems,
            pending_previous: publication.pending_previous.as_ref(),
            pending_languages: &publication.pending_languages,
            dependency_request_evidence: Some(&dependency_request_evidence),
            jdk_artifacts_by_configured_home: publication.jdk_artifacts.as_ref(),
            python_runtime: publication.python_runtime.as_ref(),
            withdrawn_dependency_languages: &publication.withdrawn_languages,
        };
        let publication_catalog = context.catalog.cache_identity().ok();
        let runtime = {
            let _scope = crate::profiling::scope("semantic_pack.acquire_active");
            acquire_active_semantic_models_with_inputs(
                self.analyzer(),
                context.catalog,
                context.persistence,
                &activation,
                Some(&publication.dependencies),
                runtime_artifacts,
                context.cancellation,
            )
        };
        let ready = matches!(runtime, SemanticModelRuntimeOutcome::Ready { .. });
        let omit_empty_runtime = failure_without_prior_overlay && ready;
        let diagnostic_refresh_required = !omit_empty_runtime && ready;
        let outcome = DependencyPackActivationOutcome {
            ecosystems: outcomes,
            runtime: (!omit_empty_runtime).then_some(runtime),
            diagnostic_refresh_required,
        };
        if let Some(cache) = cache {
            if matches!(
                &outcome.runtime,
                Some(SemanticModelRuntimeOutcome::Ready { .. })
            ) {
                let mut prepared = cache.prepared_dependency_evidence().unwrap_or_default();
                prepared.retain(|entry| {
                    !ecosystems
                        .iter()
                        .any(|ecosystem| entry.ecosystem == ecosystem.label())
                });
                prepared.extend(
                    outcome
                        .ecosystems
                        .iter()
                        .filter_map(|outcome| outcome.preparation.as_ref())
                        .flat_map(|preparation| preparation.evidence.iter().cloned()),
                );
                cache.record_prepared_dependency_evidence(prepared);
            }
            let finalized_key =
                crate::analyzer::semantic_model::runtime::DependencyActivationKey::new(
                    config,
                    &ecosystems,
                    context,
                    &activation,
                    cache,
                );
            cache.retain_dependency_activation(
                (publication.kind == DependencyPackPublicationKind::Full)
                    .then_some(same_generation_key)
                    .flatten(),
                (publication.kind == DependencyPackPublicationKind::Full)
                    .then_some(finalized_key)
                    .flatten(),
                &outcome,
                context.catalog,
                publication_catalog.as_ref(),
            );
        }
        outcome
    }

    /// The ecosystem outcomes a status is reduced from after a scoped refresh.
    /// The refresh rediscovers only the selected ecosystems, so its outcome
    /// would show none of the carried ecosystems' diagnostics or incompleteness,
    /// which a cold activation reports. This returns the refreshed outcomes
    /// unchanged plus the retained status of every ecosystem the refresh did not
    /// touch, in canonical ecosystem order. The activation outcome itself keeps
    /// only what was refreshed, because its other consumers (the policy
    /// coordinator's pack decisions and standard-library expectations) read
    /// dependency lists and prepared packs that a retained status does not hold.
    pub fn ecosystem_statuses_with_carried(
        &self,
        refreshed: &[DependencyPackEcosystemOutcome],
    ) -> Vec<DependencyPackEcosystemOutcome> {
        let mut statuses = refreshed.to_vec();
        if let Some(caches) = self.analyzer().snapshot_caches() {
            statuses.extend(
                caches
                    .semantic_models()
                    .retained_ecosystem_statuses()
                    .into_iter()
                    .filter(|(ecosystem, _)| {
                        !refreshed.iter().any(|entry| entry.ecosystem == *ecosystem)
                    })
                    .map(|(ecosystem, status)| DependencyPackEcosystemOutcome {
                        ecosystem,
                        discovery: status.discovery.clone(),
                        preparation: status.preparation.clone(),
                    }),
            );
        }
        statuses.sort_by_key(|entry| entry.ecosystem);
        statuses
    }

    /// The sole cross-generation reuse decision. A pending generation has no
    /// published candidate, so a disqualifying edit cannot be forgotten by a
    /// later unrelated update. Successful republication advances that boundary.
    fn republish_unchanged_semantic_models(
        &self,
        next: &Self,
        changed_files: &brokk_bifrost_core::analyzer::changed_paths::ChangedPaths,
        context: Option<super::packs_document::WorkspaceUpdateActivationContext<'_>>,
    ) {
        let Some(context) = context else { return };
        let Some(old) = self.analyzer().snapshot_caches() else {
            return;
        };
        let Some(new) = next.analyzer().snapshot_caches() else {
            return;
        };
        if !next.stale_dependency_ecosystems().is_empty()
            || next.requires_whole_dependency_refresh()
        {
            return;
        }
        if !old
            .semantic_models()
            .publication_files_unchanged(changed_files, next.analyzer())
        {
            return;
        }
        let Some(prepared_dependencies) = new.semantic_models().prepared_dependency_evidence()
        else {
            return;
        };
        let activation = context.prospective_inputs(next, &prepared_dependencies);
        let ecosystems =
            super::packs_document::workspace_pack_ecosystems(next, context.sources.config);
        let key = crate::analyzer::semantic_model::runtime::DependencyActivationKey::new(
            &context.activation_config(next),
            &ecosystems,
            &DependencyPackWorkspaceContext {
                catalog: context.catalog,
                persistence: context.persistence,
                activation: &activation.request,
                limits: DependencyPackLimits::default(),
                cancellation: context.cancellation,
            },
            &activation,
            old.semantic_models(),
        );
        old.semantic_models()
            .republish_matching_activation(new.semantic_models(), key, activation);
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

    /// Ecosystems whose previous discovery could not be proved current after an update.
    pub fn requires_whole_dependency_refresh(&self) -> bool {
        self.analyzer()
            .snapshot_caches()
            .is_none_or(|caches| caches.requires_whole_dependency_refresh())
    }

    pub fn stale_dependency_ecosystems(&self) -> Vec<DependencyPackEcosystem> {
        self.analyzer()
            .snapshot_caches()
            .map(|caches| caches.stale_dependency_ecosystems())
            .unwrap_or_default()
    }

    pub fn carried_activation_request(
        &self,
    ) -> Option<crate::analyzer::semantic_model::SemanticModelActivationRequest> {
        self.analyzer()
            .snapshot_caches()
            .and_then(|caches| caches.carried_activation_request())
    }

    pub fn carried_activation_inputs(&self) -> Option<ActivationInputs> {
        self.analyzer()
            .snapshot_caches()
            .and_then(|caches| caches.carried_activation_inputs())
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
        let outcome = self.refresh_selected_dependency_packs(
            config,
            &[DependencyPackEcosystem::Python],
            context,
        );
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

    #[cfg(any(test, feature = "test-support"))]
    /// Language-restricted [`Self::build_ephemeral_footgun`], and a footgun for
    /// the same reason: read that function's doc before calling this one. The
    /// persisted equivalent is [`Self::build_persisted_for_languages`].
    pub fn build_ephemeral_for_languages_footgun(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        languages: &BTreeSet<Language>,
    ) -> Result<Self, StoreError> {
        let budget = brokk_bifrost_core::retention_budget::RetentionBudget::for_test_capacity(
            config.retention_budget_bytes(),
        );
        Self::build_ephemeral_for_languages_footgun_with_budget(project, config, languages, &budget)
    }

    pub fn build_ephemeral_for_languages_footgun_with_budget(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        languages: &BTreeSet<Language>,
        budget: &brokk_bifrost_core::retention_budget::RetentionBudget,
    ) -> Result<Self, StoreError> {
        let store_context = super::tree_sitter_analyzer::ephemeral_store_context_with_budget(
            project.as_ref(),
            &config,
            budget,
        )?;
        Self::build_filtered(project, config, Some(languages), store_context, None)
    }

    #[cfg(any(test, feature = "test-support"))]
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
        let budget = brokk_bifrost_core::retention_budget::RetentionBudget::new(
            config.retention_budget_bytes(),
        );
        Self::build_ephemeral_footgun_with_budget(project, config, &budget)
    }

    pub fn build_ephemeral_footgun_with_budget(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        budget: &brokk_bifrost_core::retention_budget::RetentionBudget,
    ) -> Result<Self, StoreError> {
        let store_context = super::tree_sitter_analyzer::ephemeral_store_context_with_budget(
            project.as_ref(),
            &config,
            budget,
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

    #[cfg(any(test, feature = "test-support"))]
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

    pub fn build_scoped_persisted_with_budget(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        budget: &brokk_bifrost_core::retention_budget::RetentionBudget,
    ) -> Result<Self, StoreError> {
        let store_context = super::tree_sitter_analyzer::scoped_store_context_with_budget(
            project.as_ref(),
            &config,
            budget,
        )?;
        Self::build_filtered(project, config, None, store_context, None)
    }

    #[cfg(any(test, feature = "test-support"))]
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
        let budget = brokk_bifrost_core::retention_budget::RetentionBudget::new(
            config.retention_budget_bytes(),
        );
        Self::build_revision_image_with_budget(project, config, languages, cache, blobs, &budget)
    }

    pub fn build_revision_image_with_budget(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        languages: Option<&BTreeSet<Language>>,
        cache: Option<&SharedAnalyzerCache>,
        blobs: Arc<RevisionBlobIdentities>,
        budget: &brokk_bifrost_core::retention_budget::RetentionBudget,
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
            None => super::tree_sitter_analyzer::ephemeral_store_context_with_budget(
                project.as_ref(),
                &config,
                budget,
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
        budget: &brokk_bifrost_core::retention_budget::RetentionBudget,
    ) -> Result<(Self, Arc<AnalyzerBuildTierAccess>), StoreError> {
        Self::build_with_tier_access(|observer| {
            let mut store_context =
                super::tree_sitter_analyzer::ephemeral_store_context_with_budget(
                    project.as_ref(),
                    &config,
                    budget,
                )?;
            store_context.build_tier_access = Arc::clone(observer);
            Self::build_filtered(project, config, None, store_context, None)
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn build_persisted(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
    ) -> Result<Self, StoreError> {
        Self::build_persisted_inner(project, config, None, true, None)
    }

    pub fn build_persisted_with_budget(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        budget: &brokk_bifrost_core::retention_budget::RetentionBudget,
    ) -> Result<Self, StoreError> {
        Self::build_persisted_inner_with_budget(project, config, None, true, None, budget, None)
    }

    pub fn build_persisted_with_budget_and_progress<F>(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        budget: &brokk_bifrost_core::retention_budget::RetentionBudget,
        progress: F,
        cancellation: crate::CancellationToken,
    ) -> Result<Self, StoreError>
    where
        F: Fn(crate::analyzer::BuildProgressEvent) + Send + Sync + 'static,
    {
        Self::build_persisted_inner_with_budget(
            project,
            config,
            Some(Arc::new(progress)),
            true,
            None,
            budget,
            Some(cancellation),
        )
    }

    pub fn build_persisted_without_automatic_gc_with_budget(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        budget: &brokk_bifrost_core::retention_budget::RetentionBudget,
    ) -> Result<Self, StoreError> {
        Self::build_persisted_inner_with_budget(project, config, None, false, None, budget, None)
    }

    pub fn build_persisted_without_automatic_gc_with_budget_and_progress<F>(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        budget: &brokk_bifrost_core::retention_budget::RetentionBudget,
        progress: F,
        cancellation: crate::CancellationToken,
    ) -> Result<Self, StoreError>
    where
        F: Fn(crate::analyzer::BuildProgressEvent) + Send + Sync + 'static,
    {
        Self::build_persisted_inner_with_budget(
            project,
            config,
            Some(Arc::new(progress)),
            false,
            None,
            budget,
            Some(cancellation),
        )
    }

    #[cfg(any(test, feature = "test-support"))]
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
        let budget = brokk_bifrost_core::retention_budget::RetentionBudget::for_test_capacity(
            config.retention_budget_bytes(),
        );
        Self::build_persisted_for_languages_with_budget(project, config, languages, &budget)
    }

    pub fn build_persisted_for_languages_with_budget(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        languages: &BTreeSet<Language>,
        budget: &brokk_bifrost_core::retention_budget::RetentionBudget,
    ) -> Result<Self, StoreError> {
        let store_context = super::tree_sitter_analyzer::persistent_store_context_with_budget(
            project.as_ref(),
            &config,
            true,
            budget,
        )?;
        Self::build_filtered(project, config, Some(languages), store_context, None)
    }

    #[cfg(any(test, feature = "test-support"))]
    /// Build a persisted analyzer whose cache is collected only when the host
    /// explicitly requests it.
    pub fn build_persisted_without_automatic_gc(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
    ) -> Result<Self, StoreError> {
        Self::build_persisted_inner(project, config, None, false, None)
    }

    #[cfg(any(test, feature = "test-support"))]
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
        budget: &brokk_bifrost_core::retention_budget::RetentionBudget,
    ) -> Result<(Self, Arc<AnalyzerBuildTierAccess>), StoreError> {
        Self::build_with_tier_access(|observer| {
            Self::build_persisted_inner_with_budget(
                project,
                config,
                None,
                true,
                Some(Arc::clone(observer)),
                budget,
                None,
            )
        })
    }

    #[cfg(any(test, feature = "test-support"))]
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

    #[cfg(any(test, feature = "test-support"))]
    fn build_persisted_inner(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        progress: Option<BuildProgress>,
        automatic_gc: bool,
        tier_access: Option<Arc<AnalyzerBuildTierAccess>>,
    ) -> Result<Self, StoreError> {
        let budget = brokk_bifrost_core::retention_budget::RetentionBudget::for_test_capacity(
            config.retention_budget_bytes(),
        );
        Self::build_persisted_inner_with_budget(
            project,
            config,
            progress,
            automatic_gc,
            tier_access,
            &budget,
            None,
        )
    }

    fn build_persisted_inner_with_budget(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        progress: Option<BuildProgress>,
        automatic_gc: bool,
        tier_access: Option<Arc<AnalyzerBuildTierAccess>>,
        budget: &brokk_bifrost_core::retention_budget::RetentionBudget,
        cancellation: Option<crate::CancellationToken>,
    ) -> Result<Self, StoreError> {
        let mut store_context = {
            let _scope = profiling::scope("WorkspaceAnalyzer::open_persistent_store");
            super::tree_sitter_analyzer::persistent_store_context_with_budget(
                project.as_ref(),
                &config,
                automatic_gc,
                budget,
            )?
        };
        if let Some(tier_access) = tier_access {
            store_context.build_tier_access = tier_access;
        }
        if let Some(cancellation) = cancellation {
            store_context.cancellation = cancellation;
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
                    &format!("building the analyzer for {}", project.root().display()),
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
        let membership = super::tree_sitter_analyzer::GenerationWorkspaceMembership::capture(
            project.as_ref(),
            store_context.store.retention_budget(),
        );
        store_context.workspace_snapshot = membership.listing().ok().map(|listing| {
            WorkspaceBuildSnapshot::from_listing(
                project.as_ref(),
                store_context.liveness.as_deref(),
                &selected_languages,
                listing.clone(),
            )
        });
        store_context.workspace_listing_complete = membership.listing().is_ok();
        store_context.membership = Some(membership);

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

        if let Some(delegate) = delegates.get(&Language::Rust) {
            let snapshots = delegate
                .analyzer()
                .selected_workspace_snapshots_for_reads()
                .expect("a Rust delegate owns a relational workspace selection");
            if let Some(snapshot) = snapshots.get("rust") {
                let report = store_context
                    .store
                    .reconcile_rust_crates_unless_current(snapshot)?;
                if let Some(derivations) = delegate.analyzer().derivations() {
                    derivations.forget_rust_units(&report);
                }
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
        workspace.reconcile_workspace_build_context(None);
        Ok(workspace)
    }

    pub fn analyzer(&self) -> &dyn IAnalyzer {
        match self {
            Self::Empty(analyzer) => analyzer,
            Self::Multi(analyzer) => analyzer.as_ref(),
        }
    }

    /// Replay a recorded derivation with the analyzer that owns its language.
    pub(crate) fn replay_derivation(
        &self,
        kind: brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationKindId,
        question: &brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationQuestion,
    ) -> crate::analyzer::derivation_host::ReplayResult {
        use crate::analyzer::derivation_host::{ReplayMissing, ReplayResult};
        if kind.0 == "derivation:jvm_external_provider_inventory:v1" {
            return match (self.store(), question.name.as_deref()) {
                (Some(store), Some(provider)) => {
                    match store.jvm_external_provider_inventory_digest(provider) {
                        Ok(digest) => ReplayResult::Identity(
                            brokk_bifrost_semantic::analyzer::semantic::derivation::OutputIdentity(
                                brokk_bifrost_semantic::analyzer::semantic::ids::StableDigest::from_array(digest),
                            ),
                        ),
                        Err(_) => ReplayResult::Missing(ReplayMissing::NoRecipe),
                    }
                }
                _ => ReplayResult::Missing(ReplayMissing::NoRecipe),
            };
        }
        let Some(language) = question.language.as_ref() else {
            return ReplayResult::Missing(ReplayMissing::NoRecipe);
        };
        let analyzer: &dyn IAnalyzer = match self {
            Self::Multi(multi) => match multi.delegates().get(language).map(|d| d.analyzer()) {
                Some(analyzer) => analyzer,
                None => return ReplayResult::Missing(ReplayMissing::NoRecipe),
            },
            Self::Empty(_) => return ReplayResult::Missing(ReplayMissing::NoRecipe),
        };
        match analyzer.derivations() {
            Some(derivations) => derivations.replay(analyzer, kind, question),
            None => ReplayResult::Missing(ReplayMissing::NoRecipe),
        }
    }

    pub(crate) fn activation_catalog_owner(
        &self,
    ) -> Option<
        &std::sync::Mutex<Option<crate::analyzer::packs_document::WorkspaceActivationCatalog>>,
    > {
        let context = match self {
            Self::Empty(analyzer) => analyzer.build_context.as_deref(),
            Self::Multi(analyzer) => analyzer.build_context(),
        };
        context.map(|context| context.activation_catalog.as_ref())
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
        let Some(snapshot) = self
            .current_program_semantics_artifact_source(&file, usize::MAX)?
            .held_or_refused()?
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
                // The attachment names the served bytes' OID and variant.
                // When no complete blob row exists for that key (for example,
                // overlay bytes never persisted), the product is stored unattached.
                parse_variant: self
                    .analyzer()
                    .selected_parse_variant(&file)
                    .ok_or_else(|| {
                        crate::analyzer::semantic::SemanticProviderError::internal(
                            "selected parse variant unreadable",
                        )
                    })?,
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

    /// Active lowering identity for policy persistence, in language order.
    /// The caller supplies the model snapshot pinned for this evaluation.
    #[doc(hidden)]
    pub fn policy_lowering_identity(
        &self,
        models: Option<&crate::analyzer::semantic_model::ActiveSemanticModelSnapshot>,
    ) -> crate::analyzer::semantic::ids::StableDigest {
        let mut identities = Vec::new();
        for language in Language::ALL {
            let Some(support) = crate::analyzer::languages::language_support(language) else {
                continue;
            };
            let identity = support
                .policy_lowering_identity(models)
                .expect("registered language must declare a policy lowering identity");
            let type_flow = crate::analyzer::semantic::type_flow::type_flow_adapter(language)
                .map(|adapter| adapter.semantics_version());
            identities.push((language, identity, type_flow));
        }
        policy_lowering_identity_from_adapters(identities)
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn selected_receiver_proofs_after_transfer_batch_for_test(
        &self,
        file: &crate::analyzer::ProjectFile,
        questions: &[crate::analyzer::semantic::read_ledger::SelectedReceiverProofQuestion],
        cancellation: &crate::CancellationToken,
    ) -> crate::analyzer::store::Result<
        Vec<Option<crate::analyzer::semantic::read_ledger::SelectedReceiverProofAnswer>>,
    > {
        self.analyzer()
            .selected_receiver_proofs_after_transfer_batch_for_test(file, questions, cancellation)
    }

    /// Replay a selected source proof without activating a conditional seed.
    #[doc(hidden)]
    pub fn selected_receiver_proof_read(
        &self,
        file: &crate::analyzer::ProjectFile,
        question: &crate::analyzer::semantic::read_ledger::SelectedReceiverProofQuestion,
        cancellation: &crate::CancellationToken,
    ) -> crate::analyzer::store::Result<
        Option<crate::analyzer::semantic::read_ledger::SelectedReceiverProofAnswer>,
    > {
        self.analyzer()
            .selected_receiver_proof_read(file, question, cancellation)
    }

    /// Read one selected publication through its language provider.
    pub fn stored_semantic_ir_publication_read(
        &self,
        file: &crate::analyzer::ProjectFile,
        subject: [u8; 32],
        source_byte_cap: Option<usize>,
        cancellation: &crate::analyzer::semantic::CancellationToken,
    ) -> Result<
        crate::analyzer::semantic::StoredSemanticIrRead,
        crate::analyzer::semantic::SemanticProviderError,
    > {
        let Some(provider) = self.program_semantics_provider_for_file(file) else {
            self.analyzer().refuse_read_reuse();
            return Ok(crate::analyzer::semantic::StoredSemanticIrRead::Refused);
        };
        provider.stored_semantic_ir_publication_read(file, subject, source_byte_cap, cancellation)
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
        SemanticArtifactSourceOutcome<crate::analyzer::semantic::SemanticArtifactSourceSnapshot>,
        crate::analyzer::semantic::SemanticProviderError,
    > {
        let active = self.analyzer().active_semantic_model_snapshot();
        let Some((delegate, provider)) = self.program_semantics_provider_context_for_file(file)
        else {
            return Ok(SemanticArtifactSourceOutcome::Unavailable);
        };
        let _scope = crate::analyzer::AnalyzerQueryScope::with_active_semantic_model_snapshot(
            delegate, active,
        );
        provider.current_artifact_source(file, max_source_bytes)
    }

    /// Load and hold a selected proof's source while its caller uses it.
    /// Parsing and traversal are charged as work separately by the caller.
    /// Each acquisition is conservatively held independently, even when an
    /// overlay shares its backing buffer with a dispatch session. File or key
    /// equality does not imply that two acquisitions share an allocation.
    #[doc(hidden)]
    pub fn held_program_semantics_artifact_source(
        &self,
        file: &ProjectFile,
        request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<
        SemanticArtifactSourceOutcome<HeldSemanticArtifactSourceSnapshot>,
        crate::analyzer::semantic::SemanticProviderError,
    > {
        let snapshot = match self
            .current_program_semantics_artifact_source(file, request.budget.limits().source_bytes)?
        {
            SemanticArtifactSourceOutcome::Held(snapshot) => snapshot,
            SemanticArtifactSourceOutcome::Refused(exceeded) => {
                request.budget.note_admission_refusal(exceeded);
                return Ok(SemanticArtifactSourceOutcome::Refused(exceeded));
            }
            SemanticArtifactSourceOutcome::Unavailable => {
                return Ok(SemanticArtifactSourceOutcome::Unavailable);
            }
        };
        let snapshot = Arc::new(snapshot);
        // Only an overlay file whose buffer dispatch's session already holds
        // is counted twice; conservative per-acquisition accounting fails closed.
        if let Err(exceeded) = request
            .budget
            .hold_source(&snapshot, snapshot.source().len())
        {
            return Ok(SemanticArtifactSourceOutcome::Refused(exceeded));
        }
        Ok(SemanticArtifactSourceOutcome::Held(
            HeldSemanticArtifactSourceSnapshot { snapshot },
        ))
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
        Ok(
            match self.current_program_semantics_artifact_source(file, max_source_bytes)? {
                SemanticArtifactSourceOutcome::Held(current) => {
                    Some(current.key().public_fingerprint())
                }
                SemanticArtifactSourceOutcome::Refused(_)
                | SemanticArtifactSourceOutcome::Unavailable => None,
            },
        )
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
        Ok(
            match self.current_program_semantics_artifact_source(&file, max_source_bytes)? {
                SemanticArtifactSourceOutcome::Held(current) => {
                    Some((current.key() == key, current.source().len()))
                }
                SemanticArtifactSourceOutcome::Refused(_)
                | SemanticArtifactSourceOutcome::Unavailable => None,
            },
        )
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
        // A budget outcome follows a refusal the ledger already recorded, so
        // its dependence carries the budget cause; an error or a cancellation
        // does not.
        let budget_outcome = match &result {
            Err(_) => false,
            Ok(outcome) => {
                matches!(
                    outcome,
                    crate::analyzer::semantic::SemanticOutcome::ExceededBudget { .. }
                ) || outcome.available_value().is_some_and(|artifact| {
                    artifact.procedures().iter().any(|procedure| {
                        procedure.gaps().iter().any(|gap| {
                            gap.kind == crate::analyzer::semantic::SemanticGapKind::ExceededBudget
                        })
                    })
                })
            }
        };
        let cancelled = matches!(
            &result,
            Ok(crate::analyzer::semantic::SemanticOutcome::Cancelled { .. })
        );
        if result.is_err() || cancelled || budget_outcome {
            brokk_bifrost_core::profiling::note_with(|| {
                format!(
                    "policy.units unbounded origin={}:{} cause=budget:semantic_artifact",
                    file!(),
                    line!()
                )
            });
            self.analyzer().mark_execution_dependent();
            if budget_outcome {
                self.analyzer().record_budget_dependences(1);
            }
            // `SemanticOutcome` cannot carry a verdict yet, so the verdict
            // joins the current captures beside the ambient marks.
            self.analyzer().join_reuse_verdict(
                crate::analyzer::reuse_verdict::ReuseVerdict::ExecutionDependent(
                    if budget_outcome {
                        crate::analyzer::reuse_verdict::ExecutionCause::BudgetRefusal
                    } else {
                        crate::analyzer::reuse_verdict::ExecutionCause::Other
                    },
                ),
            );
        }
        result
    }

    /// Admit the selected procedure's stored footprint through its file provider.
    pub fn stored_footprint_coverage(
        &self,
        procedure: &crate::analyzer::semantic::ProcedureHandle,
        request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<
        crate::analyzer::semantic::FootprintAdmission,
        crate::analyzer::semantic::SemanticProviderError,
    > {
        use crate::analyzer::semantic::{FootprintAdmission, FootprintAdmissionRefusal};
        let key = procedure.artifact().key();
        let root = self.analyzer().project().root();
        if key.mount() != crate::analyzer::semantic::WorkspaceMountId::from_root(root) {
            self.analyzer().refuse_read_reuse();
            return Ok(FootprintAdmission::Refused(
                FootprintAdmissionRefusal::CoverageUnavailable,
            ));
        }
        let file = crate::analyzer::ProjectFile::new(root.to_path_buf(), key.path().as_path());
        let Some(provider) = self.program_semantics_provider_for_file(&file) else {
            self.analyzer().refuse_read_reuse();
            return Ok(FootprintAdmission::Refused(
                FootprintAdmissionRefusal::CoverageUnavailable,
            ));
        };
        provider.stored_footprint_coverage(procedure, request)
    }

    /// Admit the selected procedure's stored call/control coverage through its file provider.
    pub fn stored_call_control_coverage(
        &self,
        procedure: &crate::analyzer::semantic::ProcedureHandle,
        request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<
        crate::analyzer::semantic::FootprintAdmission,
        crate::analyzer::semantic::SemanticProviderError,
    > {
        use crate::analyzer::semantic::{FootprintAdmission, FootprintAdmissionRefusal};
        let key = procedure.artifact().key();
        let root = self.analyzer().project().root();
        if key.mount() != crate::analyzer::semantic::WorkspaceMountId::from_root(root) {
            return Ok(FootprintAdmission::Refused(
                FootprintAdmissionRefusal::CoverageUnavailable,
            ));
        }
        let file = crate::analyzer::ProjectFile::new(root.to_path_buf(), key.path().as_path());
        let Some(provider) = self.program_semantics_provider_for_file(&file) else {
            return Ok(FootprintAdmission::Refused(
                FootprintAdmissionRefusal::CoverageUnavailable,
            ));
        };
        provider.stored_call_control_coverage(procedure, request)
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
            self.analyzer().refuse_read_reuse();
            return Ok(None);
        }
        let file = crate::analyzer::ProjectFile::new(root.to_path_buf(), key.path().as_path());
        let Some((_, provider)) = self.program_semantics_provider_context_for_file(&file) else {
            self.analyzer().refuse_read_reuse();
            return Ok(None);
        };
        provider.stored_partial_flows(&file, key, procedure.id())
    }

    /// Read stored flows for this exact selected interpretation without
    /// asking the language's admission owner to select the procedure again.
    #[doc(hidden)]
    pub fn stored_flows_for_selected_procedure(
        &self,
        selected: &crate::analyzer::semantic::service::SelectedProcedureHandle,
        request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<
        crate::analyzer::semantic::SemanticOutcome<
            Option<crate::analyzer::semantic::partial_flow::ProcedurePartialFlows>,
        >,
        crate::analyzer::semantic::SemanticProviderError,
    > {
        use crate::analyzer::semantic::service::CandidateProcedureSide;
        use crate::analyzer::semantic::{ProcedureInterpretation, SemanticOutcome, SemanticWork};
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }
        let procedure = &selected.handle;
        let (flows, work) = match procedure.interpretation() {
            ProcedureInterpretation::Base => {
                assert_eq!(selected.side, CandidateProcedureSide::Base);
                let flows = self.stored_partial_flows(procedure)?;
                if !crate::analyzer::languages::language_support(
                    procedure.artifact().key().language().language(),
                )
                .is_some_and(|support| support.publishes_candidate_macro_alternates())
                {
                    // Match the existing non-candidate pair owner: this
                    // lookup adds no new flow admission on that path.
                    return Ok(SemanticOutcome::Complete {
                        value: flows,
                        work: SemanticWork::default(),
                    });
                }
                (flows, SemanticWork::default())
            }
            ProcedureInterpretation::CandidateAlternate => {
                assert_eq!(selected.side, CandidateProcedureSide::Alternate);
                let key = procedure.artifact().key();
                let file = crate::analyzer::ProjectFile::new(
                    self.analyzer().project().root().to_path_buf(),
                    key.path().as_path(),
                );
                let Some((analyzer, provider)) =
                    self.program_semantics_provider_context_for_file(&file)
                else {
                    return Err(crate::analyzer::semantic::SemanticProviderError::internal(
                        "selected candidate provider is unavailable".to_owned(),
                    ));
                };
                let (outcome, receipt) =
                    crate::analyzer::i_analyzer::QueryReadReceipt::capture(analyzer, || {
                        provider.selected_candidate_alternate_flows(&file, procedure, request)
                    });
                receipt.replay(self.analyzer());
                return outcome;
            }
            // A model-refined body cannot consume either native publication.
            ProcedureInterpretation::ExecutableAlternate => (None, SemanticWork::default()),
        };
        if let Some(flows) = &flows
            && let Err(exceeded) = request.budget.admit(flows.semantic_work())
        {
            return Ok(SemanticOutcome::ExceededBudget {
                partial: None,
                exceeded,
                work,
            });
        }
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work,
            });
        }
        Ok(SemanticOutcome::Complete { value: flows, work })
    }

    pub fn selected_procedure_handle(
        &self,
        base: &crate::analyzer::semantic::ProcedureHandle,
        request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<
        crate::analyzer::semantic::SemanticOutcome<
            crate::analyzer::semantic::service::SelectedProcedureHandle,
        >,
        crate::analyzer::semantic::SemanticProviderError,
    > {
        let base_handle = base.base_interpretation();
        let base = &base_handle;
        let key = base.artifact().key();
        let root = self.analyzer().project().root();
        assert_eq!(
            key.mount(),
            crate::analyzer::semantic::WorkspaceMountId::from_root(root)
        );
        if !crate::analyzer::languages::language_support(key.language().language())
            .is_some_and(|support| support.publishes_candidate_macro_alternates())
        {
            return Ok(if request.cancellation.is_cancelled() {
                crate::analyzer::semantic::SemanticOutcome::Cancelled {
                    partial: None,
                    work: Default::default(),
                }
            } else {
                crate::analyzer::semantic::SemanticOutcome::Complete {
                    value: crate::analyzer::semantic::service::SelectedProcedureHandle {
                        handle: base.clone(),
                        side: crate::analyzer::semantic::service::CandidateProcedureSide::Base,
                        refusals: Vec::new(),
                    },
                    work: Default::default(),
                }
            });
        }
        let file = crate::analyzer::ProjectFile::new(root.to_path_buf(), key.path().as_path());
        let (analyzer, provider) = self
            .program_semantics_provider_context_for_file(&file)
            .expect("selected handle provider");
        let (outcome, receipt) =
            crate::analyzer::i_analyzer::QueryReadReceipt::capture(analyzer, || {
                provider.selected_procedure_handle(&file, base, request)
            });
        receipt.replay(self.analyzer());
        outcome
    }

    /// Acquire ownership refinements only for a pointer/heap consumer. The
    /// request-local interpretation is never published as native semantic IR.
    pub fn ownership_procedure_handle(
        &self,
        base: &crate::analyzer::semantic::ProcedureHandle,
        request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<
        crate::analyzer::semantic::SemanticOutcome<
            crate::analyzer::semantic::service::SelectedProcedureHandle,
        >,
        crate::analyzer::semantic::SemanticProviderError,
    > {
        crate::analyzer::semantic::service::ownership_procedure_handle(self, base, request)
    }

    /// Acquire a certified executable body without acquiring a lexical
    /// macro view. An unavailable optional proof keeps the ordinary selection
    /// and its incomplete coverage; required evidence and operational stops
    /// remain failures. The interpretation is never published as native IR.
    pub fn executable_procedure_handle(
        &self,
        base: &crate::analyzer::semantic::ProcedureHandle,
        request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<
        crate::analyzer::semantic::SemanticOutcome<
            crate::analyzer::semantic::service::SelectedProcedureHandle,
        >,
        crate::analyzer::semantic::SemanticProviderError,
    > {
        crate::analyzer::semantic::service::executable_procedure_handle(self, base, request)
    }

    /// Transport an exact ownership handle already admitted in this request.
    /// Never upgrades a base handle or trusts an unadmitted alternate.
    #[doc(hidden)]
    pub fn replay_ownership_procedure_handle(
        &self,
        procedure: &crate::analyzer::semantic::ProcedureHandle,
        request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<
        crate::analyzer::semantic::SemanticOutcome<
            Option<crate::analyzer::semantic::ProcedureHandle>,
        >,
        crate::analyzer::semantic::SemanticProviderError,
    > {
        crate::analyzer::semantic::service::replay_ownership_procedure_handle(
            self, procedure, request,
        )
    }

    /// Acquire the owner's selected executable pair and its complete read receipt.
    pub fn selected_procedure_and_flows(
        &self,
        base: &crate::analyzer::semantic::ProcedureHandle,
        request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<
        crate::analyzer::semantic::service::CandidateProcedureOutcome<
            crate::analyzer::i_analyzer::QueryReadReceipt,
        >,
        crate::analyzer::semantic::SemanticProviderError,
    > {
        let base_handle = base.base_interpretation();
        let base = &base_handle;
        use crate::analyzer::semantic::service::{
            CandidateProcedureOutcome, SelectedCandidateProcedure,
        };
        let key = base.artifact().key();
        let root = self.analyzer().project().root();
        if key.mount() != crate::analyzer::semantic::WorkspaceMountId::from_root(root) {
            return Err(crate::analyzer::semantic::SemanticProviderError::internal(
                "selected procedure belongs to another workspace".to_owned(),
            ));
        }
        if !crate::analyzer::languages::language_support(key.language().language())
            .is_some_and(|support| support.publishes_candidate_macro_alternates())
        {
            if request.cancellation.is_cancelled() {
                return Ok(CandidateProcedureOutcome::Cancelled);
            }
            let (flows, admissions) = crate::analyzer::i_analyzer::QueryReadReceipt::capture(
                self.analyzer(),
                || {
                    if let Some(flows) = self.stored_partial_flows(base)? {
                        return Ok(Some(flows));
                    }
                    let projected =
                        crate::analyzer::semantic::partial_flow::file_local_procedure_relations(
                            base,
                            &crate::analyzer::semantic::OracleCallContext::empty(),
                            request,
                        );
                    Ok::<_, crate::analyzer::semantic::SemanticProviderError>(crate::analyzer::semantic::partial_flow::fixpoint::partial_flows_from_projection(base, projected, request))
                },
            );
            admissions.replay(self.analyzer());
            return Ok(match flows? {
                Some(flows) => CandidateProcedureOutcome::Selected(SelectedCandidateProcedure {
                    side: crate::analyzer::semantic::service::CandidateProcedureSide::Base,
                    procedure: base.clone(),
                    flows,
                    admissions,
                }),
                None => CandidateProcedureOutcome::Cancelled,
            });
        }
        let file = crate::analyzer::ProjectFile::new(root.to_path_buf(), key.path().as_path());
        let Some((analyzer, provider)) = self.program_semantics_provider_context_for_file(&file)
        else {
            return Err(crate::analyzer::semantic::SemanticProviderError::internal(
                "selected procedure provider is unavailable".to_owned(),
            ));
        };
        let (outcome, receipt) =
            crate::analyzer::i_analyzer::QueryReadReceipt::capture(analyzer, || {
                analyzer.record_read(crate::analyzer::ReadKey::semantic_artifact(key));
                provider.selected_procedure_and_flows(&file, base, request)
            });
        receipt.replay(self.analyzer());
        Ok(match outcome? {
            CandidateProcedureOutcome::Selected(selected) => {
                CandidateProcedureOutcome::Selected(SelectedCandidateProcedure {
                    side: selected.side,
                    procedure: selected.procedure,
                    flows: selected.flows,
                    admissions: receipt,
                })
            }
            CandidateProcedureOutcome::Cancelled => CandidateProcedureOutcome::Cancelled,
            CandidateProcedureOutcome::ExceededBudget(exceeded) => {
                CandidateProcedureOutcome::ExceededBudget(exceeded)
            }
        })
    }

    /// Prepare guarded alternatives in their validated base context for a
    /// query-local admission owner. Ordinary handles continue to use the base.
    pub fn stored_candidate_macro_artifact(
        &self,
        procedure: &crate::analyzer::semantic::ProcedureHandle,
        request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<
        crate::analyzer::semantic::SemanticOutcome<
            Option<crate::analyzer::semantic::StoredCandidateMacroArtifact>,
        >,
        crate::analyzer::semantic::SemanticProviderError,
    > {
        let key = procedure.artifact().key();
        let root = self.analyzer().project().root();
        if key.mount() != crate::analyzer::semantic::WorkspaceMountId::from_root(root) {
            self.analyzer().refuse_read_reuse();
            return Ok(crate::analyzer::semantic::SemanticOutcome::Complete {
                value: None,
                work: crate::analyzer::semantic::SemanticWork::default(),
            });
        }
        let file = crate::analyzer::ProjectFile::new(root.to_path_buf(), key.path().as_path());
        let Some((_, provider)) = self.program_semantics_provider_context_for_file(&file) else {
            self.analyzer().refuse_read_reuse();
            return Ok(crate::analyzer::semantic::SemanticOutcome::Complete {
                value: None,
                work: crate::analyzer::semantic::SemanticWork::default(),
            });
        };
        let result = provider.stored_candidate_macro_artifact(
            &file,
            key,
            procedure.artifact().capabilities(),
            request,
        )?;
        if matches!(
            &result,
            crate::analyzer::semantic::SemanticOutcome::Complete { value: Some(_), .. }
        ) {
            self.analyzer()
                .record_read(crate::analyzer::ReadKey::semantic_artifact(key));
        }
        Ok(result)
    }

    /// Decode one complete stored procedure for a query-local ordered solve.
    /// The read ledger still names the same whole-blob semantic artifact as
    /// full decoding; narrowing read keys belongs to Milestone 5.
    pub fn stored_semantic_ir_procedure(
        &self,
        procedure: &crate::analyzer::semantic::ProcedureHandle,
    ) -> Result<
        Option<crate::analyzer::semantic::ProcedureSemanticsParts>,
        crate::analyzer::semantic::SemanticProviderError,
    > {
        let key = procedure.artifact().key();
        let root = self.analyzer().project().root();
        if key.mount() != crate::analyzer::semantic::WorkspaceMountId::from_root(root) {
            self.analyzer().refuse_read_reuse();
            return Ok(None);
        }
        let file = crate::analyzer::ProjectFile::new(root.to_path_buf(), key.path().as_path());
        let Some((_, provider)) = self.program_semantics_provider_context_for_file(&file) else {
            self.analyzer().refuse_read_reuse();
            return Ok(None);
        };
        let parts = provider.stored_semantic_ir_procedure(&file, key, procedure.id())?;
        if parts.is_some() {
            self.analyzer()
                .record_read(crate::analyzer::ReadKey::semantic_artifact(key));
        }
        Ok(parts)
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
            self.analyzer().refuse_read_reuse();
            return Ok(false);
        }
        let file = crate::analyzer::ProjectFile::new(root.to_path_buf(), key.path().as_path());
        let Some((_, provider)) = self.program_semantics_provider_context_for_file(&file) else {
            self.analyzer().refuse_read_reuse();
            return Ok(false);
        };
        provider.has_complete_semantic_ir_rows(&file, key)
    }

    /// Both composed taint and value flow require a certified caller inventory
    /// and complete IR publication for every artifact they bind up front.
    pub fn composition_readiness(
        &self,
        key: &crate::analyzer::semantic::SemanticArtifactKey,
    ) -> Result<CompositionReadiness, crate::analyzer::semantic::SemanticProviderError> {
        if !composition_language_supported(key) {
            return Ok(CompositionReadiness::Language);
        }
        Ok(if self.has_complete_semantic_ir_rows(key)? {
            CompositionReadiness::Ready
        } else {
            CompositionReadiness::NoRows
        })
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

    /// Passive generation-root census. Does not enter a query or fill a cache.
    #[cfg(feature = "test-support")]
    pub fn retention_census_for_test(
        &self,
        census: &mut brokk_bifrost_core::retention_census::RetentionCensus,
    ) {
        self.analyzer().retention_census_for_test(census);
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
            for _ in 0..ledger.unpinned_execution_dependences() {
                self.analyzer().mark_execution_dependent();
            }
            self.analyzer()
                .record_budget_dependences(ledger.budget_dependences());
            self.analyzer().record_attributed_dependences(
                crate::analyzer::ReadLedger::mark_request_pinned_dependences,
                ledger.request_pinned_dependences(),
            );
            self.analyzer()
                .join_reuse_verdict(ledger.explicit_verdict());
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
            let mut next = analyzer.clone();
            next.build_context = Some(Arc::clone(build_context));
            next.update_error = None;
            next.pending_updates.clear();
            next.full_refresh_pending = false;
            return Self::Empty(next);
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

    /// Validate a watcher-only membership event without creating a generation.
    /// Registration drops the startup listing, so the first check can refill a
    /// cold cache. Equal values still describe the published generation then.
    pub fn revalidate_listing_membership(&self) -> std::io::Result<bool> {
        brokk_bifrost_core::analyzer::project_reads::without_project_reads(|| {
            let project = self.analyzer().project();
            project.revalidate_symlink_omissions(&BTreeSet::new());
            let listing = project.all_files_with_omissions()?;
            self.analyzer()
                .generation_membership()
                .matches_revalidated_listing(&listing, project)
                .map(|unchanged| !unchanged)
        })
    }

    pub fn update(&self, changed_files: &BTreeSet<crate::analyzer::ProjectFile>) -> Self {
        self.update_with_activation_context(changed_files, None)
    }

    pub fn update_with_activation_context(
        &self,
        changed_files: &BTreeSet<ProjectFile>,
        activation_context: Option<super::packs_document::WorkspaceUpdateActivationContext<'_>>,
    ) -> Self {
        if match self {
            Self::Multi(analyzer) => analyzer.full_refresh_pending,
            Self::Empty(analyzer) => analyzer.full_refresh_pending,
        } {
            return self.update_all_with_activation_context(activation_context);
        }
        brokk_bifrost_core::analyzer::project_reads::without_project_reads(|| {
            let _scope = profiling::scope("WorkspaceAnalyzer::update");
            let _retention =
                profiling::retention_scope(self.retention_budget(), "update", "update");
            let root = self.analyzer().project().root();
            let rebased_files;
            let changed_files = if changed_files.iter().all(|file| file.root() == root) {
                changed_files
            } else {
                rebased_files = Self::rebase_changed_files(changed_files, root);
                &rebased_files
            };
            let pending = match self {
                Self::Multi(analyzer) => &analyzer.pending_updates,
                Self::Empty(analyzer) => &analyzer.pending_updates,
            };
            let changes = super::pending_update_paths(changed_files, pending);
            let changed_files = &changes;
            let project = self.analyzer().project();
            let old_ignore_observation = project.retained_ignore_observation();
            project.revalidate_symlink_omissions(changed_files);
            // A configuration input stays reachable by path even when ignore
            // rules keep it out of the listing, so the workspace resolves it
            // through the delegates that read it.
            let is_configuration_input = |file: &crate::analyzer::ProjectFile| match self {
                Self::Multi(analyzer) => analyzer
                    .delegates()
                    .values()
                    .any(|delegate| delegate.is_configuration_input(file)),
                Self::Empty(_) => false,
            };
            let resolution = project.all_files_with_omissions().and_then(|mut listing| {
                let before_points = project
                    .membership_point_observation(&listing)
                    .map(|proof| proof.lineage);
                let resolved =
                    brokk_bifrost_core::analyzer::project::resolve_update_paths_with_refresh(
                        project,
                        changed_files,
                        &mut listing,
                        &is_configuration_input,
                    )?;
                Ok((resolved, listing, before_points))
            });
            let (mut resolved_files, listing, before_points) = match resolution {
                Ok(result) => result,
                Err(error) => {
                    return match self {
                        Self::Multi(analyzer) => {
                            Self::Multi(Box::new(analyzer.failed_update(error, changed_files)))
                        }
                        Self::Empty(analyzer) => {
                            let mut failed = analyzer.clone();
                            failed.update_error = Some(error.into());
                            failed.pending_updates.extend(changed_files.iter().cloned());
                            Self::Empty(failed)
                        }
                    };
                }
            };
            let membership =
                super::tree_sitter_analyzer::GenerationWorkspaceMembership::observe_update(
                    self.analyzer().generation_membership(),
                    before_points,
                    Some(listing.clone()),
                    &resolved_files,
                    project,
                    self.retention_budget(),
                );
            if let Some(error) = membership.selection_error() {
                return match self {
                    Self::Multi(analyzer) => Self::Multi(Box::new(
                        analyzer.failed_update(error.into(), changed_files),
                    )),
                    Self::Empty(analyzer) => {
                        let mut failed = analyzer.clone();
                        failed.update_error = Some(std::io::Error::from(error).into());
                        failed.pending_updates.extend(changed_files.iter().cloned());
                        Self::Empty(failed)
                    }
                };
            }
            let reported_files = resolved_files.clone();
            if super::tree_sitter_analyzer::membership_update(
                self.analyzer().generation_membership(),
                &membership,
                &resolved_files,
                project,
                &is_configuration_input,
            )
            .apply(&mut resolved_files)
            .is_err()
            {
                let mut next = self.rebuild_with_membership(None, membership);
                next.retain_failed_update_paths(&changes);
                return next;
            }
            let changed_files = &resolved_files;
            if profiling::enabled() {
                profiling::note(format!("changed_files={}", changed_files.len()));
            }
            self.analyzer()
                .invalidate_cached_file_identities_for(changed_files);
            let mut effects = super::read_verification::UpdateEffects::AllMayHaveChanged(
                "empty workspace update",
            );
            let mut next = match self {
                Self::Empty(analyzer) => {
                    let Some(build_context) = analyzer.build_context.as_ref() else {
                        return Self::Empty(analyzer.clone());
                    };
                    let build_context = build_context.with_membership(Arc::clone(&membership));
                    let languages = build_context.changed_languages(changed_files);
                    Self::updated_from_empty(analyzer, &build_context, languages, |language| {
                        build_context
                        .build_delegate(language)
                        .unwrap_or_else(|error| {
                            panic!(
                                "failed to initialize {language:?} analyzer during update: {error}"
                            )
                        })
                    })
                }
                Self::Multi(analyzer) => {
                    let (updated, report) = analyzer
                        .with_generation_membership(Arc::clone(&membership))
                        .update_with_listing_report(changed_files, Some(&listing));
                    effects = report;
                    Self::from_updated_multi(updated)
                }
            };
            // Resolution succeeded, but a delegate can still fail while applying
            // the update. Keep the reported paths until both stages succeed.
            match &mut next {
                Self::Multi(analyzer) => analyzer.clear_update_failure(),
                Self::Empty(analyzer) => {
                    analyzer.update_error = None;
                    analyzer.pending_updates.clear();
                }
            }
            next.retain_failed_update_paths(&changes);
            effects.combine(next.reconcile_workspace_build_context(Some(changed_files)));
            // The bounded read is an optimization: failing to open it only selects
            // the full path, which reads and reports its own failures.
            let read = self
                .store()
                .and_then(|store| store.begin_update_projection_read().ok());
            if let Some(read) = read {
                self.carry_verified_dependency_evidence(&next, Some(changed_files), |consulted| {
                    super::read_verification::UpdateDecision::decide(
                        self,
                        &next,
                        effects,
                        old_ignore_observation,
                        &read,
                        consulted,
                    )
                });
            } else {
                self.carry_verified_dependency_evidence(&next, Some(changed_files), |_| {
                    super::read_verification::UpdateDecision::AllMayHaveChanged(
                        "projection read unavailable",
                    )
                });
            }

            // The caller's spellings and the resolved ones both count: a
            // directory event or an alias names no file the resolver lists.
            // Paths folded in by the membership decision were not reported by
            // anyone, yet they are real creations or removals. A model's
            // authored source locator may name a file that was absent or
            // ignored at publication, so folded additions and removals must
            // invalidate the carried overlay exactly as a reported event
            // would. An unrelated folded path leaves the overlay carried
            // because only bindings that name an affected path are rechecked.
            let published_paths =
                brokk_bifrost_core::analyzer::changed_paths::ChangedPaths::certified_against(
                    project,
                    &listing.0,
                    changes
                        .iter()
                        .chain(reported_files.iter())
                        .chain(changed_files.iter()),
                );
            let folded_paths =
                brokk_bifrost_core::analyzer::changed_paths::ChangedPaths::certified_against(
                    project,
                    &listing.0,
                    changed_files
                        .iter()
                        .filter(|file| !reported_files.contains(*file)),
                );
            if folded_paths.touches(Path::new(
                super::semantic_model::WORKSPACE_SEMANTIC_MODEL_DIRECTORY,
            )) {
                return next;
            }
            self.republish_unchanged_semantic_models(&next, &published_paths, activation_context);
            next
        })
    }

    /// Rebase caller-named changed files onto the project's own root.
    ///
    /// A project canonicalizes its root at construction, so a symlinked
    /// temporary directory or Windows' 8.3 short name may spell the same
    /// workspace differently from the project. Using such a file unchanged
    /// would update no live path: the analyzer would keep the old blob while
    /// the bytes on disk moved on, and the old blob could not be read back.
    fn rebase_changed_files(
        changed_files: &BTreeSet<ProjectFile>,
        root: &Path,
    ) -> BTreeSet<ProjectFile> {
        let canonical_root = root.canonicalize().ok();
        changed_files
            .iter()
            .map(|file| {
                if file.root() == root {
                    return file.clone();
                }
                // A file rooted at an ancestor of the project strips lexically,
                // so a symlink in the file's own path keeps its name.
                let abs_path = file.abs_path();
                if let Ok(rel_path) = abs_path.strip_prefix(root) {
                    return ProjectFile::new(root.to_path_buf(), rel_path.to_path_buf());
                }
                // The caller's root still exists when the file does not, so
                // canonicalizing the root resolves an alias (a symlinked
                // directory or Windows' 8.3 short name) for edits and deletions
                // alike. Joining the relative path before stripping keeps a
                // symlink in the file's own path from becoming its target.
                if let (Some(canonical_root), Ok(canonical_file_root)) =
                    (canonical_root.as_ref(), file.root().canonicalize())
                {
                    let canonical_abs = canonical_file_root.join(file.rel_path());
                    if let Ok(rel_path) = canonical_abs.strip_prefix(canonical_root) {
                        return ProjectFile::new(root.to_path_buf(), rel_path.to_path_buf());
                    }
                }
                file.clone()
            })
            .collect()
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
        self.update_all_with_activation_context(None)
    }

    pub fn update_all_with_activation_context(
        &self,
        _activation_context: Option<super::packs_document::WorkspaceUpdateActivationContext<'_>>,
    ) -> Self {
        // A whole refresh has no changed-file proof relative to publication.
        // Even a host with fresh inputs must await a new publication.
        self.update_all_reporting_progress(None)
    }

    /// Rebuild from disk, forwarding real build counters for this operation only.
    pub fn update_all_with_progress<F>(&self, progress: F) -> Self
    where
        F: Fn(crate::analyzer::BuildProgressEvent) + Send + Sync + 'static,
    {
        self.update_all_reporting_progress(Some(Arc::new(progress)))
    }

    fn retain_failed_update_paths(&mut self, changes: &BTreeSet<ProjectFile>) {
        let context = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        let attribution = context.enter();
        self.analyzer().begin_query(&context);
        self.analyzer().end_query(&context);
        drop(attribution);
        if context.store_error().is_some() {
            match self {
                Self::Multi(analyzer) => analyzer.pending_updates.extend(changes.iter().cloned()),
                Self::Empty(analyzer) => analyzer.pending_updates.extend(changes.iter().cloned()),
            }
        }
    }

    fn update_all_reporting_progress(&self, progress: Option<BuildProgress>) -> Self {
        brokk_bifrost_core::analyzer::project_reads::without_project_reads(|| {
            if let Self::Empty(analyzer) = self
                && analyzer.build_context.is_none()
            {
                return Self::Empty(analyzer.clone());
            }
            self.analyzer().invalidate_cached_file_identities();
            let project = self.analyzer().project();
            project.invalidate_cached_file_listing();
            let captured = project.all_files_with_omissions().and_then(|listing| {
                let membership =
                    super::tree_sitter_analyzer::GenerationWorkspaceMembership::observe(
                        Some(listing),
                        project,
                        self.retention_budget(),
                    );
                match membership.selection_error() {
                    Some(error) => Err(error.into()),
                    None => Ok(membership),
                }
            });
            let membership = match captured {
                Ok(membership) => membership,
                Err(error) => {
                    return match self {
                        Self::Multi(analyzer) => {
                            let mut failed = analyzer.failed_update(error, &BTreeSet::new());
                            failed.full_refresh_pending = true;
                            Self::Multi(Box::new(failed))
                        }
                        Self::Empty(analyzer) => {
                            let mut failed = analyzer.clone();
                            failed.update_error = Some(error.into());
                            failed.full_refresh_pending = true;
                            Self::Empty(failed)
                        }
                    };
                }
            };
            self.rebuild_with_membership(progress, membership)
        })
    }

    fn rebuild_with_membership(
        &self,
        progress: Option<BuildProgress>,
        membership: Arc<super::tree_sitter_analyzer::GenerationWorkspaceMembership>,
    ) -> Self {
        brokk_bifrost_core::analyzer::project_reads::without_project_reads(|| {
            let _scope = profiling::scope("WorkspaceAnalyzer::update_all");
            let _retention =
                profiling::retention_scope(self.retention_budget(), "update", "update_all");
            self.analyzer().invalidate_cached_file_identities();
            let next = match self {
                Self::Empty(analyzer) => {
                    let Some(context) = analyzer.build_context.as_ref() else {
                        return Self::Empty(analyzer.clone());
                    };
                    let languages = membership
                        .listing()
                        .map(|listing| context.allowed_languages_for_files(listing.0.iter()))
                        .unwrap_or_default();
                    let context = context.with_membership(membership);
                    Self::updated_from_empty(analyzer, &context, languages, |language| {
                        context.build_delegate_with_progress(language, progress.clone()).unwrap_or_else(|error| panic!("failed to initialize {language:?} analyzer during full update: {error}"))
                    })
                }
                Self::Multi(analyzer) => {
                    let updated = analyzer.rebuild_with_membership(progress, membership);
                    if updated.has_update_failure() {
                        return Self::from_updated_multi(updated);
                    }
                    Self::from_updated_multi(updated)
                }
            };
            next.reconcile_workspace_build_context(None);
            self.carry_verified_dependency_evidence(&next, None, |_| {
                super::read_verification::UpdateDecision::AllMayHaveChanged(
                    "full refresh or Rescan",
                )
            });
            next
        })
    }

    fn reconcile_workspace_build_context(
        &self,
        changed: Option<&BTreeSet<crate::analyzer::ProjectFile>>,
    ) -> super::read_verification::UpdateEffects {
        use super::read_verification::UpdateEffects;
        let mut effects = UpdateEffects::no_changes();
        for support in crate::analyzer::languages::registered_language_supports() {
            match support.reconcile_workspace_build_context(self, changed) {
                Ok(report) => effects.combine(report),
                Err(error) => {
                    self.analyzer().record_query_failure(error);
                    effects.combine(UpdateEffects::AllMayHaveChanged(
                        "build-context reconciliation failed",
                    ));
                }
            }
        }
        effects
    }

    fn carry_verified_dependency_evidence<'a>(
        &'a self,
        next: &'a Self,
        changed_files: Option<&BTreeSet<ProjectFile>>,
        prepare: impl FnOnce(
            &crate::hash::HashMap<Language, Vec<ProjectFile>>,
        ) -> super::read_verification::UpdateDecision<'a>,
    ) {
        use crate::analyzer::read_verification::{HeadInputs, LookupMemo};
        use crate::analyzer::semantic::ids::StableDigest;
        use crate::analyzer::semantic::read_ledger::ReadKey;

        if let Some(host) = self.analyzer().host_activation_context()
            && next.bind_host_activation_context(host).is_err()
        {
            return;
        }
        let Some(old_cache) = self.analyzer().snapshot_caches() else {
            return;
        };
        let Some(new_cache) = next.analyzer().snapshot_caches() else {
            return;
        };
        let activated = old_cache.activated_dependency_ecosystems();
        // Subset contributions need verification even before a Full has
        // established the authoritative ecosystem inventory.
        let mut known = activated.clone().unwrap_or_default();
        known.extend(
            old_cache
                .semantic_models()
                .dependency_request_evidence()
                .into_keys(),
        );
        known.extend(old_cache.stale_dependency_ecosystems());
        known.sort_by_key(|ecosystem| ecosystem.label());
        known.dedup();
        let old_evidence = known
            .iter()
            .copied()
            .filter_map(|ecosystem| {
                ecosystem
                    .languages()
                    .iter()
                    .find_map(|language| old_cache.dependency_discovery_evidence(*language))
                    .map(|evidence| (ecosystem, evidence))
            })
            .collect::<Vec<_>>();
        if old_evidence.is_empty() {
            new_cache.install_carried_dependency_evidence(
                old_cache.semantic_models().models_selected(),
                Vec::new(),
                known,
                old_cache.carried_activation_inputs(),
                activated,
                old_cache.semantic_models().dependency_request_evidence(),
            );
            old_cache
                .semantic_models()
                .carry_prepared_dependency_evidence_to(new_cache.semantic_models());
            return;
        }
        let mut carried = Vec::new();
        let mut stale = known
            .into_iter()
            .filter(|ecosystem| !old_evidence.iter().any(|(old, _)| old == ecosystem))
            .collect::<Vec<_>>();
        // Construct replay inputs once for all ecosystems. Discovery records
        // project reads; model, policy and epoch reads have no authority here.
        let collect_consulted = || {
            let mut consulted: crate::hash::HashMap<Language, Vec<ProjectFile>> =
                Default::default();
            for (_, evidence) in &old_evidence {
                for key in evidence.project_read_keys.iter() {
                    if let ReadKey::File {
                        language, rel_path, ..
                    } = key
                    {
                        consulted
                            .entry(*language)
                            .or_default()
                            .push(ProjectFile::new(
                                next.analyzer().project().root().to_path_buf(),
                                rel_path.as_ref(),
                            ));
                    }
                }
            }
            for paths in consulted.values_mut() {
                paths.sort();
                paths.dedup();
            }
            consulted
        };
        let consulted = collect_consulted();
        #[cfg(any(test, feature = "test-support"))]
        assert_eq!(
            consulted,
            collect_consulted(),
            "both computations replay the same ledger File-key set"
        );
        // Preparation is fallible; make the transaction's sole decision only
        // after bounded delta/head reads, then replay the prepared result.
        let decision = prepare(&consulted);
        let changed = decision.changed_facts(self, next);
        #[cfg(any(test, feature = "test-support"))]
        let reference = super::read_verification::without_update_delta_observer(|| {
            super::read_verification::ChangedFacts::between(self, next)
        });
        #[cfg(any(test, feature = "test-support"))]
        changed.assert_projection_equivalent(&reference, &consulted);
        #[cfg(any(test, feature = "test-support"))]
        let mut reference_memo = LookupMemo::default();
        let empty = StableDigest::sha256([]);
        let mut inputs = HeadInputs {
            models: empty,
            policy_semantic_hash: empty,
            policy_source: empty,
            configuration: empty,
            epoch: empty,
        };
        let mut memo = LookupMemo::default();
        let old_ignore = self.analyzer().project().ignore_rules_digest().ok();
        let new_ignore = next.analyzer().project().ignore_rules_digest().ok();
        // Compare only dirty paths against each generation's immutable listing.
        // Body edits can change the inventory digest without changing census
        // membership; additions/removals must not receive that same exemption.
        // Unavailable listings keep the proof fail-closed. No workspace walk or
        // source-body acquisition is needed; only dirty paths are compared.
        let changed_paths = changed_files.and_then(|files| {
            let old = self.analyzer().generation_membership().listing().ok()?;
            let new = next.analyzer().generation_membership().listing().ok()?;
            Some(
                files
                    .iter()
                    .filter(|file| {
                        let old_file = ProjectFile::new(
                            self.analyzer().project().root().to_path_buf(),
                            file.rel_path(),
                        );
                        let new_file = ProjectFile::new(
                            next.analyzer().project().root().to_path_buf(),
                            file.rel_path(),
                        );
                        old.0.contains(&old_file) != new.0.contains(&new_file)
                    })
                    .map(|file| file.rel_path().to_path_buf())
                    .collect::<Vec<_>>(),
            )
        });
        for (ecosystem, evidence) in old_evidence {
            let eligible = dependency_external_reads_unchanged(&evidence);
            let same_configuration = self.config() == next.config();
            // Membership changes include overlay-set additions and removals.
            let membership_unchanged = changed_paths
                .as_ref()
                .zip(old_ignore.zip(new_ignore))
                .is_some_and(|(paths, (old, new))| {
                    crate::analyzer::semantic_model::discovery_membership_unchanged(
                        ecosystem.resolver(),
                        paths,
                        paths,
                        &old,
                        &new,
                    )
                });
            let project_reads_match = eligible
                && same_configuration
                && verify_dependency_discovery_project_reads(
                    next,
                    &changed,
                    &mut inputs,
                    &mut memo,
                    evidence.project_read_identity,
                    &evidence.project_read_keys,
                    membership_unchanged,
                    #[cfg(any(test, feature = "test-support"))]
                    Some((&reference, &mut reference_memo)),
                );
            if project_reads_match {
                for language in ecosystem.languages() {
                    carried.push((*language, Arc::clone(&evidence)));
                }
            } else {
                stale.push(ecosystem);
            }
        }
        new_cache.install_carried_dependency_evidence(
            old_cache.semantic_models().models_selected(),
            carried,
            stale,
            old_cache.carried_activation_inputs(),
            activated,
            old_cache.semantic_models().dependency_request_evidence(),
        );
        old_cache
            .semantic_models()
            .carry_prepared_dependency_evidence_to(new_cache.semantic_models());
    }
}

/// Shared receipt verifier for cross-generation dependency carry and
/// same-warm staged discovery handoff.
#[allow(clippy::too_many_arguments)]
fn verify_dependency_discovery_project_reads(
    head: &WorkspaceAnalyzer,
    changed: &super::read_verification::ChangedFacts,
    inputs: &mut super::read_verification::HeadInputs,
    memo: &mut super::read_verification::LookupMemo,
    project_read_identity: crate::analyzer::semantic::ids::StableDigest,
    project_read_keys: &[crate::analyzer::read_ledger::ReadKey],
    membership_unchanged: bool,
    #[cfg(any(test, feature = "test-support"))] reference: Option<(
        &super::read_verification::ChangedFacts,
        &mut super::read_verification::LookupMemo,
    )>,
) -> bool {
    use crate::analyzer::read_verification::{
        KeyVerdict, LookupReplayLimits, NoSummaryAnswers, verify_read_key,
    };
    use crate::analyzer::semantic::invalidation::DerivedArtifactId;
    use crate::analyzer::semantic::read_ledger::{
        LookupKind, LookupQuestion, ReadKey, WorkspaceFactFamily,
    };

    #[cfg(any(test, feature = "test-support"))]
    let mut reference = reference;

    project_read_keys.iter().all(|key| {
        // Discovery chooses the packs to activate, so it normally observes that
        // no model set is active. That absence marker keeps carry-over exactly
        // as it was before absence was recorded as a read; a read of an actual
        // model set still refuses carry-over.
        if let ReadKey::Models(models) = key {
            return *models == head.analyzer().model_set_digest(None);
        }
        if matches!(key, ReadKey::Policy { .. } | ReadKey::Epoch(_)) {
            return false;
        }
        if let ReadKey::Configuration(configuration) = key {
            inputs.configuration = *configuration;
        }
        let verdict = verify_read_key(
            DerivedArtifactId::semantic_artifact(project_read_identity),
            head,
            changed,
            inputs,
            key,
            LookupReplayLimits::default(),
            &NoSummaryAnswers,
            memo,
        );
        #[cfg(any(test, feature = "test-support"))]
        if let Some((reference_changed, reference_memo)) = &mut reference {
            let reference_verdict = verify_read_key(
                DerivedArtifactId::semantic_artifact(project_read_identity),
                head,
                reference_changed,
                inputs,
                key,
                LookupReplayLimits::default(),
                &NoSummaryAnswers,
                reference_memo,
            );
            assert_eq!(format!("{verdict:?}"), format!("{reference_verdict:?}"));
        }
        matches!(verdict, KeyVerdict::Unchanged)
            || membership_unchanged
                && matches!(
                    key,
                    ReadKey::Lookup {
                        kind: LookupKind::WorkspaceFact,
                        question: LookupQuestion::WorkspaceFact {
                            family: WorkspaceFactFamily::WorkspaceFileInventory
                                | WorkspaceFactFamily::WorkspaceFileListing,
                            ..
                        },
                        ..
                    }
                )
                && matches!(verdict, KeyVerdict::Changed(_))
    })
}

/// The same borrowed discovery view for native readers without a workspace enum.
#[doc(hidden)]
pub fn generation_dependency_discovery_project(analyzer: &dyn IAnalyzer) -> Arc<dyn Project + '_> {
    super::project_read_facade::for_generation(analyzer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic_model::RustSelectedCargoGraph;

    #[test]
    fn empty_generation_keeps_host_without_a_publication_cache() {
        use crate::analyzer::semantic_model::{
            HostActivationContext, VerifiedFirstPartyReleaseInventory,
        };
        let root = tempfile::tempdir().unwrap();
        let project: Arc<dyn Project> =
            Arc::new(crate::analyzer::FilesystemProject::new(root.path()).unwrap());
        let before = WorkspaceAnalyzer::Multi(Box::default());
        let host = HostActivationContext::from_inventory(
            VerifiedFirstPartyReleaseInventory::compiled_default().unwrap(),
            &crate::retention_budget::RetentionBudget::for_tests(),
        )
        .unwrap();
        before
            .bind_host_activation_context(Arc::clone(&host))
            .unwrap();
        let after = WorkspaceAnalyzer::Empty(EmptyAnalyzer::new(project));
        before.carry_verified_dependency_evidence(&after, None, |_| {
            panic!("a storeless generation has no receipt to verify")
        });
        assert!(Arc::ptr_eq(
            &host,
            &after.analyzer().host_activation_context().unwrap()
        ));
        assert_eq!(
            after.analyzer().model_set_digest(None),
            host.no_model_digest()
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: refreshing Python erased carried JVM preparation failures"
    )]
    fn ecosystem_refresh_preserves_other_preparation_failures() {
        use crate::analyzer::semantic_model::runtime::SemanticModelRuntimeLimits;
        use brokk_bifrost_semantic::analyzer::semantic_model::dependency::{
            DependencyPreparationFailureCause, RecordedPreparationFailure, ResolvedDependency,
        };
        let workspace = WorkspaceAnalyzer::Multi(Box::default());
        let request = SemanticModelActivationRequest {
            host_activation: brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
            bifrost_version: semver::Version::new(0, 15, 1),
            evidence: vec![],
            approximate_standard_libraries: vec![],
            controls: vec![],
            limits: SemanticModelRuntimeLimits::default(),
        };
        let failure = RecordedPreparationFailure {
            dependency: ResolvedDependency::undeclared_scope(
                "jar".into(),
                SemanticModelActivationEvidence {
                    language: "java".into(),
                    ecosystem: "maven".into(),
                    package: None,
                    module: None,
                    toolchain: None,
                    target: None,
                    configuration: None,
                    production_input_digest: None,
verified_raw_artifacts: Vec::new(),
                },
                vec![],
                vec![],
            ),
            cause: DependencyPreparationFailureCause::ProducerFailed,
            inputs: brokk_bifrost_semantic::analyzer::semantic_model::dependency::PreparationFailureInputs::Bound(vec![]),
        };
        workspace
            .analyzer()
            .snapshot_caches()
            .unwrap()
            .semantic_models()
            .install_carried_dependency_evidence(
                false,
                vec![],
                vec![],
                Some(ActivationInputs {
                    request: request.clone(),
                    rust_cargo_graph: None,
                    preparation_failures: vec![failure.clone()],
                }),
                None,
                Default::default(),
            );
        let catalog = SemanticPackCatalog::open_ephemeral(Default::default()).unwrap();
        let cancellation = crate::CancellationToken::default();
        let context = DependencyPackWorkspaceContext {
            catalog: &catalog,
            persistence: None,
            activation: &request,
            limits: DependencyPackLimits::default(),
            cancellation: &cancellation,
        };
        let python = workspace.dependency_pack_activation_inputs(
            &[DependencyPackEcosystem::Python],
            &context,
            None,
            DependencyPackPublicationKind::Subset,
        );
        let fresh = ActivationInputs::from(request.clone());
        let python_fresh = workspace.dependency_pack_activation_inputs(
            &[DependencyPackEcosystem::Python],
            &context,
            Some(&fresh),
            DependencyPackPublicationKind::Subset,
        );
        assert_eq!(python_fresh.preparation_failures, vec![failure.clone()]);
        assert_eq!(python.preparation_failures, vec![failure]);
        let jvm = workspace.dependency_pack_activation_inputs(
            &[DependencyPackEcosystem::Jvm],
            &context,
            None,
            DependencyPackPublicationKind::Subset,
        );
        assert!(jvm.preparation_failures.is_empty());
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12825: repeated Full reuse hid new preparation failures and subset withdrawal"
    )]
    fn full_activation_withdraws_evidence_after_subset_publication() {
        use crate::analyzer::semantic_model::dependency::DependencyPackPreparationOutcome;
        let root = tempfile::tempdir().unwrap();
        let delegate = crate::analyzer::packs_document::tests::CatalogWorkspace {
            project: Arc::new(crate::TestProject::new(root.path(), Language::Java)),
            language: Language::Java,
            index: None,
            definitions: Vec::new(),
            complete_symbol_index: false,
        };
        let workspace = WorkspaceAnalyzer::Multi(Box::new(MultiAnalyzer::new(BTreeMap::from([(
            Language::Java,
            crate::analyzer::multi_analyzer::AnalyzerDelegate::new(delegate),
        )]))));
        let catalog = SemanticPackCatalog::open_ephemeral(Default::default()).unwrap();
        let config = AnalyzerConfig::default();
        let request = SemanticModelActivationRequest {
            host_activation: brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
            bifrost_version: "0.0.0".parse().unwrap(),
            evidence: vec![],
            approximate_standard_libraries: vec![],
            controls: vec![],
            limits: Default::default(),
        };
        let cancellation = crate::CancellationToken::default();
        let context = || DependencyPackWorkspaceContext {
            catalog: &catalog,
            persistence: None,
            activation: &request,
            limits: Default::default(),
            cancellation: &cancellation,
        };
        let first = workspace.activate_dependency_packs(&config, &[], context());
        assert!(first.complete());
        let original = workspace
            .analyzer()
            .active_semantic_model_snapshot()
            .unwrap();
        assert!(
            workspace
                .activate_dependency_packs(&config, &[], context())
                .complete()
        );
        assert!(Arc::ptr_eq(
            &original,
            &workspace
                .analyzer()
                .active_semantic_model_snapshot()
                .unwrap()
        ));
        let cache = workspace
            .analyzer()
            .snapshot_caches()
            .unwrap()
            .semantic_models();
        let evidence = SemanticModelActivationEvidence {
            language: "java".into(),
            ecosystem: "maven".into(),
            package: None,
            module: None,
            toolchain: None,
            target: None,
            configuration: None,
            production_input_digest: None,
            verified_raw_artifacts: Vec::new(),
        };
        let mut subset = ActivationInputs::from(request.clone());
        subset.request.evidence.push(evidence.clone());
        workspace.publish_dependency_pack_activation(
            &config,
            subset,
            DependencyPackPublicationEvidence {
                kind: DependencyPackPublicationKind::Subset,
                pending_previous: None,
                dependencies: vec![],
                withdrawn_languages: vec![],
                pending_languages: vec![],
                jdk_artifacts: None,
                python_runtime: None,
            },
            vec![DependencyPackEcosystemOutcome {
                ecosystem: DependencyPackEcosystem::Jvm,
                discovery: DependencyDiscoveryOutcome::complete(vec![]),
                preparation: Some(DependencyPackPreparationOutcome {
                    failures: vec![],
                    packs: vec![],
                    installed_packs: vec![],
                    evidence: vec![evidence.clone()],
                    diagnostics: vec![],
                    suppressed_diagnostics: Default::default(),
                    complete: true,
                    cancelled: false,
                    profile: Default::default(),
                }),
            }],
            false,
            &[DependencyPackEcosystem::Jvm],
            &context(),
            None,
        );
        assert_eq!(
            cache.dependency_request_evidence()[&DependencyPackEcosystem::Jvm].evidence,
            vec![evidence.clone()]
        );
        let second = workspace.activate_dependency_packs(&config, &[], context());
        assert!(second.complete());
        assert!(!Arc::ptr_eq(
            &original,
            &workspace
                .analyzer()
                .active_semantic_model_snapshot()
                .unwrap()
        ));
        assert!(cache.dependency_request_evidence().is_empty());
        assert!(
            workspace
                .carried_activation_inputs()
                .unwrap()
                .request
                .evidence
                .is_empty()
        );
        use brokk_bifrost_semantic::analyzer::semantic_model::dependency::{
            DependencyPreparationFailureCause, RecordedPreparationFailure, ResolvedDependency,
        };
        let failure = RecordedPreparationFailure {
            dependency: ResolvedDependency::undeclared_scope("new-jar".into(), evidence, vec![], vec![]),
            cause: DependencyPreparationFailureCause::ProducerFailed,
            inputs: brokk_bifrost_semantic::analyzer::semantic_model::dependency::PreparationFailureInputs::Bound(vec![]),
        };
        let mut failed = ActivationInputs::from(request.clone());
        failed.preparation_failures.push(failure.clone());
        workspace.publish_dependency_pack_activation(
            &config,
            failed,
            DependencyPackPublicationEvidence {
                kind: DependencyPackPublicationKind::Full,
                pending_previous: None,
                dependencies: vec![],
                withdrawn_languages: vec![],
                pending_languages: vec![],
                jdk_artifacts: None,
                python_runtime: None,
            },
            vec![],
            false,
            &[],
            &context(),
            None,
        );
        assert_eq!(
            workspace
                .carried_activation_inputs()
                .unwrap()
                .preparation_failures,
            vec![failure]
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13517: a failed project read left no key, so a discovery that ignored the error could carry"
    )]
    fn failed_project_read_makes_discovery_uncarriable() {
        use crate::analyzer::FilesystemProject;
        use crate::analyzer::dependency_support::declare_external_discovery_reads_complete;
        use crate::analyzer::semantic_model::capture_dependency_discovery;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("manifest.dat"), "longer than the read cap\n").unwrap();
        std::fs::write(root.join("README"), "readable\n").unwrap();
        let project = Arc::new(FilesystemProject::new(&root).unwrap());
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default()).unwrap();
        let discover = |name: &str, cap: usize| {
            capture_dependency_discovery(workspace.analyzer(), || {
                let project = workspace.dependency_discovery_project().unwrap();
                let file = project.file_by_rel_path(Path::new(name)).unwrap();
                // The discovery ignores a read that gave no snapshot, as the
                // Cargo host-unit census does for a manifest over the cap, and
                // reports no diagnostic.
                let snapshot = project.read_source_snapshot_limited(&file, cap).unwrap();
                assert_eq!(snapshot.is_none(), cap == 1);
                declare_external_discovery_reads_complete();
                DependencyDiscoveryOutcome::complete(Vec::new())
            })
        };
        assert!(
            !discover("manifest.dat", 1).external_reads.complete,
            "a read with no snapshot names no key and must refuse carry"
        );
        assert!(
            discover("README", 1 << 20).external_reads.complete,
            "a read that gave a snapshot is a recorded key and does not refuse carry"
        );
        // A scoped worker, as Go's domain workers are, transports the request's
        // read attribution instead of reporting on the capturing thread; its
        // unnamed read must still refuse the capture.
        let worker = capture_dependency_discovery(workspace.analyzer(), || {
            let attribution = crate::analyzer::ReadAttribution::for_request();
            let project = workspace.dependency_discovery_project().unwrap();
            std::thread::scope(|scope| {
                scope.spawn(|| {
                    let _attributed = attribution.install();
                    let file = project.file_by_rel_path(Path::new("manifest.dat")).unwrap();
                    assert!(
                        project
                            .read_source_snapshot_limited(&file, 1)
                            .unwrap()
                            .is_none()
                    );
                });
            });
            declare_external_discovery_reads_complete();
            DependencyDiscoveryOutcome::complete(Vec::new())
        });
        assert!(
            !worker.external_reads.complete,
            "a worker's unnamed project read must refuse carry"
        );
    }

    #[test]
    fn full_dependency_pack_activation_drops_subset_carried_cargo_graph() {
        use crate::analyzer::semantic_model::rust_cargo_graph::CargoResolveView;
        let workspace = WorkspaceAnalyzer::Multi(Box::default());
        let request = SemanticModelActivationRequest {
            host_activation: brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
            bifrost_version: semver::Version::new(0, 15, 1),
            evidence: vec![],
            approximate_standard_libraries: vec![],
            controls: vec![],
            limits: Default::default(),
        };
        workspace
            .analyzer()
            .snapshot_caches()
            .unwrap()
            .semantic_models()
            .install_carried_dependency_evidence(
                false,
                vec![],
                vec![],
                Some(ActivationInputs {
                    request: request.clone(),
                    preparation_failures: vec![],
                    rust_cargo_graph: Some(
                        RustSelectedCargoGraph::from_cargo_resolve(CargoResolveView::from_rows(
                            vec![],
                            vec![],
                        ))
                        .unwrap(),
                    ),
                }),
                None,
                Default::default(),
            );
        let catalog = SemanticPackCatalog::open_ephemeral(Default::default()).unwrap();
        let cancellation = crate::CancellationToken::default();
        let context = DependencyPackWorkspaceContext {
            catalog: &catalog,
            persistence: None,
            activation: &request,
            limits: Default::default(),
            cancellation: &cancellation,
        };
        let subset = workspace.dependency_pack_activation_inputs(
            &[],
            &context,
            None,
            DependencyPackPublicationKind::Subset,
        );
        assert!(subset.rust_cargo_graph.is_some());
        workspace
            .analyzer()
            .snapshot_caches()
            .unwrap()
            .semantic_models()
            .install_carried_dependency_evidence(
                false,
                vec![],
                vec![],
                Some(subset),
                None,
                Default::default(),
            );
        let full = workspace.dependency_pack_activation_inputs(
            &[],
            &context,
            None,
            DependencyPackPublicationKind::Full,
        );
        assert!(full.rust_cargo_graph.is_none());
    }

    #[test]
    #[hardwon(
        "#12040: EmptyAnalyzer dropped store failures through the no-op record_query_failure default"
    )]
    fn empty_analyzer_failed_listing_fill_recovers() {
        use crate::analyzer::common::{QueryCacheCell, replayable_query_cache_cell};
        use crate::analyzer::{AnalyzerQueryScope, QueryReadIncomplete};
        use std::sync::atomic::{AtomicBool, Ordering};

        struct ListingProject {
            root: PathBuf,
            fail: AtomicBool,
        }
        impl Project for ListingProject {
            fn root(&self) -> &Path {
                &self.root
            }
            fn analyzer_languages(&self) -> BTreeSet<Language> {
                BTreeSet::new()
            }
            fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
                if self.fail.load(Ordering::Relaxed) {
                    Err(std::io::Error::other("12040 listing failed"))
                } else {
                    Ok(BTreeSet::new())
                }
            }
            fn all_files_with_omissions(
                &self,
            ) -> std::io::Result<brokk_bifrost_core::analyzer::project::SharedWorkspaceFileListing>
            {
                self.all_files()
                    .map(|files| (Arc::new(files), Arc::new(Vec::new())))
            }
            fn analyzable_files(&self, _: Language) -> std::io::Result<BTreeSet<ProjectFile>> {
                self.all_files()
            }
            fn file_by_rel_path(&self, _: &Path) -> Option<ProjectFile> {
                None
            }
        }
        let temp = tempfile::tempdir().unwrap();
        let project = Arc::new(ListingProject {
            root: temp.path().to_path_buf(),
            fail: AtomicBool::new(false),
        });
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(project.clone(), AnalyzerConfig::default())
                .unwrap();
        assert!(matches!(&workspace, WorkspaceAnalyzer::Empty(_)));
        assert!(workspace.store().is_some());
        let analyzer = workspace.analyzer();
        assert!(analyzer.workspace_content_identities().is_none());
        let cell = QueryCacheCell::new();
        project.fail.store(true, Ordering::Relaxed);
        {
            let scope = AnalyzerQueryScope::for_retained_fill(analyzer);
            let answer = replayable_query_cache_cell(analyzer, &cell, || {
                Arc::new(crate::analyzer::i_analyzer::project_source_file_inventory(
                    analyzer,
                ))
            });
            assert!(!answer.complete);
            assert!(matches!(
                scope.read_completion(),
                Err(QueryReadIncomplete::StoreFailure(_))
            ));
            assert!(
                scope
                    .store_error()
                    .unwrap()
                    .to_string()
                    .contains("12040 listing failed")
            );
        }
        project.fail.store(false, Ordering::Relaxed);
        let scope = AnalyzerQueryScope::for_retained_fill(analyzer);
        let mut rebuilt = false;
        let answer = replayable_query_cache_cell(analyzer, &cell, || {
            rebuilt = true;
            Arc::new(crate::analyzer::i_analyzer::project_source_file_inventory(
                analyzer,
            ))
        });
        assert!(rebuilt, "failed fill must not be retained");
        assert!(answer.complete);
        assert!(scope.read_completion().is_ok());
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11902: absent generation membership silently triggered live discovery"
    )]
    fn dependency_discovery_missing_generation_listing_is_typed_incomplete() {
        struct NoListing(PathBuf);
        impl Project for NoListing {
            fn root(&self) -> &Path {
                &self.0
            }
            fn analyzer_languages(&self) -> BTreeSet<Language> {
                BTreeSet::new()
            }
            fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
                panic!("discovery must not scan")
            }
            fn analyzable_files(&self, _: Language) -> std::io::Result<BTreeSet<ProjectFile>> {
                panic!("discovery must not scan")
            }
            fn file_by_rel_path(&self, _: &Path) -> Option<ProjectFile> {
                panic!("discovery must not probe")
            }
        }
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceAnalyzer::Empty(EmptyAnalyzer::new(Arc::new(NoListing(
            temp.path().to_path_buf(),
        ))));
        assert!(workspace.dependency_discovery_project().is_err());
        let config = AnalyzerConfig::default();
        let cancellation = crate::CancellationToken::new();
        let ecosystems = [
            DependencyPackEcosystem::Npm,
            DependencyPackEcosystem::Go,
            DependencyPackEcosystem::Cargo,
        ];
        for ecosystem in ecosystems {
            let discovery = workspace.resolve_dependency_discovery(
                ecosystem,
                &config,
                &DependencyPackLimits::default(),
                &cancellation,
            );
            assert!(!discovery.complete);
            assert_eq!(discovery.incomplete_reason, Some(crate::analyzer::semantic_model::DependencyDiscoveryIncompleteReason::GenerationListingUnavailable));
        }
        let catalog = SemanticPackCatalog::open_ephemeral(
            crate::analyzer::semantic_model::CatalogOptions::default(),
        )
        .unwrap();
        let request = SemanticModelActivationRequest {
            host_activation: brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
            bifrost_version: "0.0.0".parse().unwrap(),
            approximate_standard_libraries: Vec::new(),
            evidence: Vec::new(),
            controls: Vec::new(),
            limits: Default::default(),
        };
        let activation = workspace.activate_dependency_packs(
            &config,
            &ecosystems,
            DependencyPackWorkspaceContext {
                catalog: &catalog,
                persistence: None,
                activation: &request,
                limits: Default::default(),
                cancellation: &cancellation,
            },
        );
        assert_eq!(activation.ecosystems.len(), ecosystems.len());
        for ecosystem in activation.ecosystems {
            assert!(!ecosystem.discovery.complete);
            assert_eq!(ecosystem.discovery.incomplete_reason, Some(crate::analyzer::semantic_model::DependencyDiscoveryIncompleteReason::GenerationListingUnavailable));
        }
        let mut explicit = request.clone();
        explicit.evidence.push(SemanticModelActivationEvidence {
            language: "go".into(),
            ecosystem: "go".into(),
            package: None,
            module: None,
            toolchain: None,
            target: None,
            configuration: None,
            production_input_digest: None,
            verified_raw_artifacts: Vec::new(),
        });
        let independent = workspace.activate_dependency_packs(
            &config,
            &ecosystems,
            DependencyPackWorkspaceContext {
                catalog: &catalog,
                persistence: None,
                activation: &explicit,
                limits: Default::default(),
                cancellation: &cancellation,
            },
        );
        assert!(!independent.complete());
        assert!(
            independent.runtime.is_some(),
            "independent evidence must reach activation"
        );
        cancellation.cancel();
        let cancelled = workspace.resolve_dependency_discovery(
            DependencyPackEcosystem::Go,
            &config,
            &DependencyPackLimits::default(),
            &cancellation,
        );
        assert!(cancelled.cancelled);
        assert!(!cancelled.complete);
    }

    #[test]
    fn external_discovery_capture_changes_identity_only_for_observed_files() {
        use crate::analyzer::dependency_support::{
            capture_external_discovery_reads, declare_external_discovery_reads_complete,
            report_external_discovery_read,
        };
        use crate::analyzer::semantic_model::ExternalDiscoveryRead;
        let temp = tempfile::tempdir().unwrap();
        let observed = temp.path().join("Cargo.lock");
        let unrelated = temp.path().join("edited.rs");
        std::fs::write(&observed, b"one").unwrap();
        let identity = || {
            let (_, reads) = capture_external_discovery_reads(|| {
                let bytes = std::fs::read(&observed).unwrap();
                report_external_discovery_read(ExternalDiscoveryRead::file(&observed, &bytes));
                declare_external_discovery_reads_complete();
            });
            let evidence = DependencyDiscoveryEvidence::from_outcome(
                &DependencyDiscoveryOutcome::complete(Vec::new()),
            )
            .with_external_reads(reads.keys, reads.complete);
            assert!(evidence.carry_eligible_external_reads().is_some());
            evidence.external_read_identity
        };
        let first = identity();
        std::fs::write(&unrelated, b"edit").unwrap();
        assert_eq!(first, identity());
        std::fs::write(&observed, b"two").unwrap();
        assert_ne!(first, identity());
        let (_, incomplete) = capture_external_discovery_reads(|| {
            report_external_discovery_read(ExternalDiscoveryRead::file(&observed, b"two"));
        });
        assert!(
            DependencyDiscoveryEvidence::from_outcome(&DependencyDiscoveryOutcome::complete(
                Vec::new()
            ))
            .with_external_reads(incomplete.keys, incomplete.complete)
            .carry_eligible_external_reads()
            .is_none()
        );
    }

    #[test]
    fn project_discovery_read_identity_tracks_manifest_not_unread_source() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap().normalize();
        std::fs::create_dir(root.join("src")).unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            "[dependencies]\nserde_json = \"1\"\n",
        )
        .unwrap();
        std::fs::write(root.join("src/untouched.rs"), "fn untouched() {}\n").unwrap();
        std::fs::write(root.join("src/edited.rs"), "fn edited() {}\n").unwrap();

        let identity = || {
            let project = Arc::new(FilesystemProject::new(root.clone()).unwrap());
            let workspace = WorkspaceAnalyzer::Empty(EmptyAnalyzer::new(project));
            let manifest = ProjectFile::new(root.clone(), "Cargo.toml");
            let (_, reads) = super::super::i_analyzer::capture_with_read_ledger_scope(
                workspace.analyzer(),
                None,
                || {
                    workspace
                        .analyzer()
                        .project()
                        .read_file_snapshot(&manifest)
                        .unwrap();
                },
            );
            assert_eq!(reads.unattributed_reads(), 0);
            assert!(reads.keys().iter().any(|key| matches!(key, crate::analyzer::ReadKey::File { rel_path, .. } if rel_path.as_ref() == "Cargo.toml")));
            let evidence = DependencyDiscoveryEvidence::from_outcome(
                &DependencyDiscoveryOutcome::complete(Vec::new()),
            )
            .with_project_reads(reads.canonical_keys(), reads.digest().digest());
            assert_eq!(evidence.project_read_keys.len(), reads.len());
            evidence.project_read_identity
        };
        let first = identity();
        std::fs::write(
            root.join("src/edited.rs"),
            "fn edited() { println!(\"changed\"); }\n",
        )
        .unwrap();
        assert_eq!(first, identity());
        std::fs::write(
            root.join("Cargo.toml"),
            "[dependencies]\nserde_json = \"2\"\n",
        )
        .unwrap();
        assert_ne!(first, identity());
    }

    use crate::analyzer::store::liveness::Liveness;

    use crate::analyzer::FilesystemProject;

    use crate::analyzer::ProjectFile;

    use crate::gitblob::test_repo::commit_all;
    use crate::gitblob::test_repo::init_repo;
    use crate::path_normalization::NormalizePath;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9737: a storeless workspace's semantic oracle panicked asking for a budget"
    )]
    fn a_storeless_workspace_builds_its_semantic_oracle_without_retaining() {
        let temp = tempfile::tempdir().unwrap();
        let project = Arc::new(FilesystemProject::new(temp.path().to_path_buf()).unwrap());
        let workspace = WorkspaceAnalyzer::Empty(EmptyAnalyzer::new(project));
        drop(workspace.semantic_oracle_provider());
        assert_eq!(workspace.retention_budget().accounted_bytes(), 0);
    }

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
            Arc::new(crate::analyzer::store::AnalyzerStore::open_ephemeral().unwrap()),
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

        assert!(overlay.set(kept.abs_path(), "class Unsaved {}\n".to_owned()));
        assert!(selected.has_overlay(&kept));
        assert!(selected.overlay_content().is_some());
        let overlay_snapshot = selected.read_source_snapshot(&kept).unwrap();
        assert_eq!(overlay_snapshot.source(), "class Unsaved {}\n");
        let pinned = selected.capture_source_overlays().unwrap();
        let pinned_snapshot = pinned
            .source_snapshot(&kept)
            .expect("selected project forwards its overlay capture");
        assert_eq!(pinned_snapshot.source(), overlay_snapshot.source());
        assert_eq!(pinned_snapshot.oid(), overlay_snapshot.oid());
        assert!(matches!(
            overlay_snapshot.origin(),
            brokk_bifrost_core::analyzer::project::ProjectSourceOrigin::Overlay(_)
        ));
        assert_eq!(pinned_snapshot.origin(), overlay_snapshot.origin());
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
        if !selected.update_cached_listing_for_path(Path::new("新規.java")) {
            selected.invalidate_cached_file_listing();
        }
        assert_matches_fresh_project();

        std::fs::remove_file(root.join("café.java")).unwrap();
        assert!(selected.update_cached_listing_for_path(Path::new("café.java")));
        assert_matches_fresh_project();

        std::fs::rename(root.join("kept.java"), root.join("renamed.java")).unwrap();
        assert!(selected.update_cached_listing_for_path(Path::new("kept.java")));
        if !selected.update_cached_listing_for_path(Path::new("renamed.java")) {
            selected.invalidate_cached_file_listing();
        }
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
