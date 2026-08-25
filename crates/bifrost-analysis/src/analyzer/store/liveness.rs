use std::collections::BTreeSet;
use std::fs::Metadata;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;

use git2::{ObjectType, Oid, Repository};
use sha2::{Digest, Sha256};

use crate::analyzer::ProjectFile;
use crate::analyzer::semantic::ids::StableDigest;
use crate::gitblob;
use crate::hash::{HashMap, map_with_capacity};
use crate::path_utils::rel_path_string;

type Result<T> = std::result::Result<T, String>;

pub struct Liveness {
    repo: Mutex<Repository>,
    workdir: PathBuf,
    startup_identity: Mutex<Option<Arc<gitblob::WorkingTreeIdentity>>>,
    #[cfg(test)]
    startup_oid_batches: Arc<AtomicUsize>,
    snapshot: Mutex<Option<MemoizedSnapshot>>,
    overlay: Mutex<OverlayState>,
    /// Canonical form of each project root this handle has been asked about.
    /// A workspace has one root, so this is one entry and one `canonicalize`.
    canonical_roots: Mutex<HashMap<PathBuf, Arc<Path>>>,
    /// Canonicalizations performed after construction, for the regression pin.
    canonicalizations: AtomicUsize,
}

impl Liveness {
    pub fn new(repo: Repository) -> Result<Self> {
        let workdir = repo
            .workdir()
            .ok_or_else(|| "repository has no working directory".to_string())?
            .canonicalize()
            .map_err(|err| format!("canonicalizing git workdir: {err}"))?;
        Ok(Self {
            repo: Mutex::new(repo),
            workdir,
            startup_identity: Mutex::new(None),
            #[cfg(test)]
            startup_oid_batches: Arc::new(AtomicUsize::new(0)),
            snapshot: Mutex::new(None),
            overlay: Mutex::new(OverlayState::default()),
            canonical_roots: Mutex::new(HashMap::default()),
            canonicalizations: AtomicUsize::new(0),
        })
    }

    /// Point resolution: hash the exact bytes visible in the working tree.
    pub fn oid_for_path(&self, file: &ProjectFile) -> Result<Option<Oid>> {
        let rel_path = self.rel_path_from_workdir(file)?;
        let abs_path = self.workdir.join(rel_path);
        if !abs_path.is_file() {
            return Ok(None);
        }
        Oid::hash_file(ObjectType::Blob, abs_path)
            .map(Some)
            .map_err(|err| err.to_string())
    }

    /// Resolve a set of analyzer files to the blob identity their bytes have
    /// in the working tree right now.
    ///
    /// One batched Git index plus dirty-tree scan seeds every path, so a cold
    /// start on a large repository does not hash the clean files it can read
    /// from the index. That scan describes the instant it ran, so it is not an
    /// answer for later calls: every path is stat-checked against the stat it
    /// was last resolved under, and a path whose file has moved since is
    /// re-hashed from the working tree. That is what makes an incremental
    /// re-resolution -- `update_paths`, a watcher delta, `refresh` -- report
    /// the edited blob rather than the one the scan saw.
    pub fn oids_for_files(&self, files: &[ProjectFile]) -> Result<HashMap<ProjectFile, Oid>> {
        Ok(self
            .oids_and_stats_for_files(files)?
            .into_iter()
            .map(|(file, (oid, _stat))| (file, oid))
            .collect())
    }

    /// Resolve a batch once and retain the filesystem observation paired with
    /// each returned OID. Workspace startup uses this to avoid a separate
    /// pre-stat and post-stat walk over the same files.
    pub(crate) fn oids_and_stats_for_files(
        &self,
        files: &[ProjectFile],
    ) -> Result<HashMap<ProjectFile, (Oid, FileStatStamp)>> {
        #[cfg(test)]
        self.startup_oid_batches
            .fetch_add(1, AtomicOrdering::Relaxed);
        let identity = {
            let mut guard = self
                .startup_identity
                .lock()
                .expect("liveness startup identity mutex poisoned");
            if guard.is_none() {
                let repo = self.repo.lock().expect("liveness repo mutex poisoned");
                *guard = Some(Arc::new(gitblob::working_tree_identity(&repo)?));
            }
            Arc::clone(
                guard
                    .as_ref()
                    .expect("startup identity was initialized above"),
            )
        };

        // Apache Camel has tens of thousands of Java files. Keep the lock
        // around one batched identity resolution, including its canonical blob
        // size lookup, then let language analyzers consume the result. The
        // returned metadata is converted to the analysis-layer opaque token
        // without another filesystem stat.
        let mut rel_paths = Vec::with_capacity(files.len());
        for file in files {
            let rel_path = self.rel_path_from_workdir(file)?;
            rel_paths.push(rel_path.to_string_lossy().replace('\\', "/"));
        }
        let repo = self.repo.lock().expect("liveness repo mutex poisoned");
        let batched = identity.resolve_with_metadata(&repo, &rel_paths)?;
        let mut resolved = map_with_capacity(batched.len());
        for (file, rel) in files.iter().zip(rel_paths) {
            let Some(resolution) = batched.get(&rel) else {
                continue;
            };
            resolved.insert(
                file.clone(),
                (
                    resolution.oid,
                    FileStatStamp(FileStat::from_metadata(&resolution.metadata)),
                ),
            );
        }
        Ok(resolved)
    }

    /// The repository-wide Git identity scan this handle already took, if it
    /// has one.
    ///
    /// It never takes one: a caller that needs OIDs asks for them and pays for
    /// the scan there. This accessor exists so a second consumer of the same
    /// worktree -- the semantic indexer, which must derive its own content
    /// identities -- can reuse the index entries and dirty set this scan already
    /// read instead of re-reading the index and re-diffing the working tree. On
    /// the firefox workspace that duplicate cost 4.1 s over 401,804 index
    /// entries at cold start.
    ///
    /// `None` means no scan has been taken yet, or one was invalidated by
    /// [`Self::invalidate_startup_oids`]; the caller then does its own.
    pub fn taken_startup_identity(&self) -> Option<Arc<gitblob::WorkingTreeIdentity>> {
        self.startup_identity
            .lock()
            .expect("liveness startup identity mutex poisoned")
            .clone()
    }

    pub fn invalidate_startup_oids(&self) {
        *self
            .startup_identity
            .lock()
            .expect("liveness startup identity mutex poisoned") = None;
    }

    #[cfg(test)]
    pub(crate) fn startup_oid_batch_counter(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.startup_oid_batches)
    }

    /// Full live view; rebuilt when the Git index bytes or overlay generation change.
    pub fn snapshot(&self) -> Result<Arc<LiveSnapshot>> {
        let repo = self.repo.lock().expect("liveness repo mutex poisoned");
        let fingerprint = current_index_fingerprint(&repo)?;
        let (overlay_generation, overlay_paths) = {
            let overlay = self
                .overlay
                .lock()
                .expect("liveness overlay mutex poisoned");
            (overlay.generation, overlay.paths.clone())
        };
        let mut guard = self
            .snapshot
            .lock()
            .expect("liveness snapshot mutex poisoned");
        if let Some(memoized) = guard.as_ref()
            && memoized.fingerprint == fingerprint
            && memoized.overlay_generation == overlay_generation
        {
            return Ok(Arc::clone(&memoized.snapshot));
        }

        let snapshot = Arc::new(build_snapshot(&repo, &self.workdir, &overlay_paths)?);
        *guard = Some(MemoizedSnapshot {
            fingerprint,
            overlay_generation,
            snapshot: Arc::clone(&snapshot),
        });
        Ok(snapshot)
    }

    pub fn refresh_overlay(&self, entries: impl IntoIterator<Item = LivePathEntry>) -> Result<()> {
        let repo = self.repo.lock().expect("liveness repo mutex poisoned");
        let index = repo.index().map_err(|e| e.to_string())?;
        let mut overlay = self
            .overlay
            .lock()
            .expect("liveness overlay mutex poisoned");
        let mut changed = false;

        for entry in entries {
            let file = entry.file;
            let rel_path = self.rel_path_from_workdir(&file)?;
            if index.get_path(&rel_path, 0).is_some() && entry.validation.is_filesystem() {
                changed |= overlay.paths.remove(&file).is_some();
                continue;
            }
            let Some(state) = PathState::new(entry.oid, entry.validation, &file, true) else {
                changed |= overlay.paths.remove(&file).is_some();
                continue;
            };
            if overlay.paths.get(&file) != Some(&state) {
                overlay.paths.insert(file, state);
                changed = true;
            }
        }

        if changed {
            overlay.generation = overlay.generation.wrapping_add(1);
        }
        Ok(())
    }

    pub fn remove_overlay_paths(&self, files: impl IntoIterator<Item = ProjectFile>) {
        let mut overlay = self
            .overlay
            .lock()
            .expect("liveness overlay mutex poisoned");
        let mut changed = false;
        for file in files {
            changed |= overlay.paths.remove(&file).is_some();
        }
        if changed {
            overlay.generation = overlay.generation.wrapping_add(1);
        }
    }

    /// The repository-relative path of an analyzer file.
    ///
    /// The canonicalization here exists to reconcile a project root reached
    /// through a symlink with the canonical git workdir `new` recorded -- the
    /// workspace of issue #1793 is a symlink to a package directory inside the
    /// repository. That is a property of the ROOT, so it is resolved once per
    /// root and the file's relative path is joined onto the result. Doing it
    /// per file cost one `readlink` per path component per workspace file:
    /// 352,494 always-`EINVAL` `readlink` calls in one profiled process, the
    /// largest syscall count observed.
    ///
    /// The literal path is tried next, and a per-file canonicalization only
    /// after both have failed -- a symlink BELOW the root that redirects a file
    /// out of the workspace. That ordering also puts this function in agreement
    /// with `oids_for_files`, the batched path, which has always resolved
    /// repository-relative paths by plain `strip_prefix` with no
    /// canonicalization at all.
    fn rel_path_from_workdir(&self, file: &ProjectFile) -> Result<PathBuf> {
        if let Ok(rel) = self
            .canonical_root(file.root())
            .join(file.rel_path())
            .strip_prefix(&self.workdir)
        {
            return Ok(rel.to_path_buf());
        }
        let abs_path = file.abs_path();
        if let Ok(rel) = abs_path.strip_prefix(&self.workdir) {
            return Ok(rel.to_path_buf());
        }
        self.canonicalize_counted(&abs_path)
            .as_deref()
            .unwrap_or(abs_path.as_path())
            .strip_prefix(&self.workdir)
            .map(Path::to_path_buf)
            .map_err(|_| {
                format!(
                    "project file {} is not under git workdir {}",
                    abs_path.display(),
                    self.workdir.display()
                )
            })
    }

    /// The canonical form of one workspace root, resolved once.
    fn canonical_root(&self, root: &Path) -> Arc<Path> {
        if let Some(cached) = self
            .canonical_roots
            .lock()
            .expect("liveness canonical-root mutex poisoned")
            .get(root)
        {
            return Arc::clone(cached);
        }
        let canonical: Arc<Path> = self
            .canonicalize_counted(root)
            .map_or_else(|| Arc::from(root), |resolved| Arc::from(resolved.as_path()));
        self.canonical_roots
            .lock()
            .expect("liveness canonical-root mutex poisoned")
            .insert(root.to_path_buf(), Arc::clone(&canonical));
        canonical
    }

    /// Every `canonicalize` this type performs after construction goes through
    /// here, so the regression pin can count them.
    fn canonicalize_counted(&self, path: &Path) -> Option<PathBuf> {
        self.canonicalizations.fetch_add(1, AtomicOrdering::Relaxed);
        path.canonicalize().ok()
    }

    /// Canonicalizations performed since construction. The pin: this is one per
    /// workspace root plus the rare below-root symlink fallback, not one per
    /// workspace file.
    #[cfg(test)]
    pub(crate) fn canonicalizations(&self) -> usize {
        self.canonicalizations.load(AtomicOrdering::Relaxed)
    }
}

struct MemoizedSnapshot {
    fingerprint: IndexFingerprint,
    overlay_generation: u64,
    snapshot: Arc<LiveSnapshot>,
}

#[derive(Default)]
struct OverlayState {
    generation: u64,
    paths: HashMap<ProjectFile, PathState>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct IndexFingerprint {
    digest: [u8; 32],
}

#[derive(Clone)]
struct PathState {
    oid: Oid,
    /// Whether the bytes named by `oid` came from an unsaved project overlay.
    /// This provenance survives in a frozen snapshot after the mutable
    /// `Project` overlay has moved on, and therefore decides whether readers
    /// must prefer an in-memory file state over persisted rows.
    is_overlay: bool,
    /// The stat this entry's *liveness* is checked against. `Some` means "a
    /// disk change invalidates this generation": the entry is dropped from a
    /// snapshot and refused by `validated_oid_for_path` once the file moves.
    /// `None` means the identity is current for as long as the map holds it,
    /// which is what an overlay and a hashed non-Git identity both need: the
    /// analyzer indexed that content, and it must keep answering from the
    /// generation it indexed until it is explicitly refreshed.
    stat: Option<FileStat>,
    /// The stat observed when this identity was captured, whether or not the
    /// identity's liveness is checked against it. This answers a different
    /// question from `stat`: not "is this generation still live" but "is the
    /// file's content still exactly the content this oid names", which is what
    /// a caller needs to reuse content-derived work without reading the file.
    /// Only an identity taken from disk has one; an overlay's content is not a
    /// function of anything on disk, so no disk stat can confirm it.
    capture_stat: Option<FileStat>,
    /// The analyzer owns this entry's generation and advances it only through
    /// an explicit refresh. Such an entry is a sound content-reuse token for
    /// the lifetime of the generation without a filesystem stat: an
    /// out-of-band edit is intentionally invisible until the caller updates
    /// the analyzer. Overlay entries do not use this bit because their source
    /// identity also depends on the overlay revision held by the project.
    generation_trusted: bool,
    /// Whether this entry is intrinsically current for the lifetime of the
    /// `LiveSnapshot`. Overlay entries have no filesystem stat and can be
    /// trusted until their overlay generation changes. Filesystem entries keep
    /// this `false` even after snapshot construction: direct analyzers have no
    /// watcher, so an out-of-band disk edit can stale an otherwise memoized
    /// snapshot without bumping `LivePathMap`'s generation.
    validated: bool,
}

impl PartialEq for PathState {
    /// Deliberately ignores `validated`: it is build provenance, not part of
    /// a path's live content, so two states that agree on
    /// `oid`/`stat`/`is_overlay` must
    /// compare equal regardless of which one (if either) has been through a
    /// `LiveSnapshot` validation pass. `refresh`/`replace_all` rely on this
    /// to detect genuine content changes without being fooled into treating
    /// a validation-flag difference as a change (in practice the two sides
    /// they compare are always both `false`, since only `PathState::new`
    /// feeds the source-of-truth maps — but the exclusion is correct either
    /// way and documents the intent explicitly rather than relying on that
    /// invariant silently holding).
    ///
    /// Overlay provenance is included even when the oid is unchanged. Equal
    /// bytes do not make disk and an unsaved buffer interchangeable: readers
    /// select different authoritative derived state for the two sources.
    ///
    /// It ignores `capture_stat` for a related reason: a file that was touched
    /// without changing its bytes keeps the same `oid`, so it is not a content
    /// change and must not bump the map's generation. The retained older
    /// `capture_stat` still names the same content, and the re-stat in
    /// `reusable_oid_for_path` simply declines until the identity is
    /// captured again, which is the conservative direction.
    fn eq(&self, other: &Self) -> bool {
        self.oid == other.oid && self.stat == other.stat && self.is_overlay == other.is_overlay
    }
}

impl Eq for PathState {}

impl PathState {
    fn new(
        oid: Oid,
        validation: LivePathValidation,
        file: &ProjectFile,
        revalidate_filesystem: bool,
    ) -> Option<Self> {
        let (stat, capture_stat) = match validation {
            LivePathValidation::Filesystem if revalidate_filesystem => {
                let stat = FileStat::from_path(&file.abs_path())?;
                (Some(stat.clone()), Some(stat))
            }
            // A hashed identity is checked for content reuse but not for
            // generation liveness, so a failed stat here is not a reason to
            // drop the path: the analyzer indexed this content and keeps
            // answering from it.
            LivePathValidation::FilesystemHashed if revalidate_filesystem => {
                (None, FileStat::from_path(&file.abs_path()))
            }
            LivePathValidation::Filesystem
            | LivePathValidation::FilesystemHashed
            | LivePathValidation::Overlay => (None, None),
        };
        Some(Self {
            oid,
            is_overlay: matches!(validation, LivePathValidation::Overlay),
            stat,
            capture_stat,
            generation_trusted: !revalidate_filesystem && validation.is_filesystem(),
            validated: false,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LivePathValidation {
    /// An identity supplied by a Git identity source for a file on disk. The
    /// source can see a working-tree edit the analyzer has not been told
    /// about, so the entry's liveness is checked against the file's stat.
    Filesystem,
    /// An identity computed here by hashing the file's bytes, because no Git
    /// identity source is available. The analyzer indexed exactly those bytes,
    /// and nothing else will notice a later disk edit on its behalf, so this
    /// entry stays live until the analyzer refreshes it. The capture stat is
    /// still recorded, so content-derived work can be reused only while the
    /// file provably still holds the hashed bytes.
    FilesystemHashed,
    /// An unsaved overlay. Its content is not a function of anything on disk,
    /// so no disk stat can confirm or invalidate it.
    Overlay,
}

impl LivePathValidation {
    fn is_filesystem(self) -> bool {
        matches!(self, Self::Filesystem | Self::FilesystemHashed)
    }
}

#[derive(Clone)]
pub struct LivePathEntry {
    file: ProjectFile,
    oid: Oid,
    validation: LivePathValidation,
}

impl LivePathEntry {
    pub fn filesystem(file: ProjectFile, oid: Oid) -> Self {
        Self {
            file,
            oid,
            validation: LivePathValidation::Filesystem,
        }
    }

    /// An identity produced by hashing the file's bytes here, because the
    /// workspace has no Git identity source. See
    /// [`LivePathValidation::FilesystemHashed`].
    pub fn filesystem_hashed(file: ProjectFile, oid: Oid) -> Self {
        Self {
            file,
            oid,
            validation: LivePathValidation::FilesystemHashed,
        }
    }

    pub fn overlay(file: ProjectFile, oid: Oid) -> Self {
        Self {
            file,
            oid,
            validation: LivePathValidation::Overlay,
        }
    }

    pub(crate) fn oid(&self) -> Oid {
        self.oid
    }

    pub(crate) fn is_overlay(&self) -> bool {
        matches!(self.validation, LivePathValidation::Overlay)
    }
}

pub struct LivePathMap {
    revalidate_filesystem: bool,
    state: Mutex<LivePathMapState>,
}

#[derive(Default)]
struct LivePathMapState {
    generation: u64,
    paths: HashMap<ProjectFile, PathState>,
    additional_mounts: HashMap<ProjectFile, BTreeSet<String>>,
    snapshot: Option<MemoizedLivePathMapSnapshot>,
}

struct MemoizedLivePathMapSnapshot {
    generation: u64,
    snapshot: Arc<LiveSnapshot>,
}

impl Default for LivePathMap {
    fn default() -> Self {
        Self {
            revalidate_filesystem: true,
            state: Mutex::new(LivePathMapState::default()),
        }
    }
}

impl LivePathMap {
    pub fn trust_filesystem_generation() -> Self {
        Self {
            revalidate_filesystem: false,
            state: Mutex::new(LivePathMapState::default()),
        }
    }

    pub fn fork(&self) -> Self {
        let guard = self.state.lock().expect("live path map mutex poisoned");
        Self {
            revalidate_filesystem: self.revalidate_filesystem,
            state: Mutex::new(LivePathMapState {
                generation: guard.generation,
                paths: guard.paths.clone(),
                additional_mounts: guard.additional_mounts.clone(),
                snapshot: None,
            }),
        }
    }

    pub fn refresh(&self, entries: impl IntoIterator<Item = LivePathEntry>) {
        let mut guard = self.state.lock().expect("live path map mutex poisoned");
        let mut changed = false;
        for entry in entries {
            let Some(path_state) = PathState::new(
                entry.oid,
                entry.validation,
                &entry.file,
                self.revalidate_filesystem,
            ) else {
                changed |= guard.paths.remove(&entry.file).is_some();
                changed |= guard.additional_mounts.remove(&entry.file).is_some();
                continue;
            };
            if guard.paths.get(&entry.file) != Some(&path_state) {
                guard.paths.insert(entry.file, path_state);
                changed = true;
            }
        }
        if changed {
            guard.generation = guard.generation.wrapping_add(1);
            guard.snapshot = None;
        }
    }

    pub fn replace_all(&self, entries: impl IntoIterator<Item = LivePathEntry>) {
        let mut next_paths = HashMap::default();
        for entry in entries {
            if let Some(path_state) = PathState::new(
                entry.oid,
                entry.validation,
                &entry.file,
                self.revalidate_filesystem,
            ) {
                next_paths.insert(entry.file, path_state);
            }
        }

        let mut guard = self.state.lock().expect("live path map mutex poisoned");
        if guard.paths != next_paths {
            guard.paths = next_paths;
            let LivePathMapState {
                paths,
                additional_mounts,
                ..
            } = &mut *guard;
            additional_mounts.retain(|file, _| paths.contains_key(file));
            guard.generation = guard.generation.wrapping_add(1);
            guard.snapshot = None;
        }
    }

    pub fn remove(&self, files: impl IntoIterator<Item = ProjectFile>) {
        let mut guard = self.state.lock().expect("live path map mutex poisoned");
        let mut changed = false;
        for file in files {
            changed |= guard.paths.remove(&file).is_some();
            changed |= guard.additional_mounts.remove(&file).is_some();
        }
        if changed {
            guard.generation = guard.generation.wrapping_add(1);
            guard.snapshot = None;
        }
    }

    pub(crate) fn replace_additional_mounts(
        &self,
        storage_lang: &str,
        files: impl IntoIterator<Item = ProjectFile>,
    ) {
        let mut guard = self.state.lock().expect("live path map mutex poisoned");
        let mut changed = false;
        for mounts in guard.additional_mounts.values_mut() {
            changed |= mounts.remove(storage_lang);
        }
        guard
            .additional_mounts
            .retain(|_, mounts| !mounts.is_empty());
        for file in files {
            if guard.paths.contains_key(&file) {
                changed |= guard
                    .additional_mounts
                    .entry(file)
                    .or_default()
                    .insert(storage_lang.to_string());
            }
        }
        if changed {
            guard.generation = guard.generation.wrapping_add(1);
            guard.snapshot = None;
        }
    }

    pub fn snapshot(&self) -> Arc<LiveSnapshot> {
        let mut guard = self.state.lock().expect("live path map mutex poisoned");
        if let Some(memoized) = guard.snapshot.as_ref()
            && memoized.generation == guard.generation
        {
            return Arc::clone(&memoized.snapshot);
        }
        let snapshot = Arc::new(snapshot_from_path_states(
            &guard.paths,
            &guard.additional_mounts,
            self.revalidate_filesystem,
        ));
        guard.snapshot = Some(MemoizedLivePathMapSnapshot {
            generation: guard.generation,
            snapshot: Arc::clone(&snapshot),
        });
        snapshot
    }
}

pub struct LiveSnapshot {
    oid_to_paths: HashMap<Oid, Vec<ProjectFile>>,
    path_to_state: HashMap<ProjectFile, PathState>,
    additional_mounts: HashMap<ProjectFile, BTreeSet<String>>,
    /// The #2449 content identity of this exact live file set, derived once.
    ///
    /// A snapshot is immutable and is itself memoized by its owning
    /// [`LivePathMap`] until the map's paths change, so deriving the digest
    /// here makes it a once-per-analyzer-update cost rather than a per-query
    /// one. See [`Self::content_digest`].
    content_digest: OnceLock<StableDigest>,
    /// The same digest taken with one overlay set's paths neutralized, kept
    /// for the last overlay set asked about. See [`Self::content_digest`].
    overlaid_content_digest: Mutex<Option<([u8; 32], StableDigest)>>,
}

impl LiveSnapshot {
    pub(crate) fn oids(&self) -> impl Iterator<Item = Oid> + '_ {
        self.oid_to_paths.keys().copied()
    }

    /// A digest over this snapshot's (workspace-relative path, blob identity)
    /// pairs.
    ///
    /// This is the analyzed-content half of a
    /// [`crate::analyzer::content_identity::WorkspaceContentIdentity`]: the
    /// identity of the exact content the analyzer indexed, with no absolute
    /// path and no generation counter in it. The recorded blob identity is
    /// used as-is rather than re-stat-validated, because that is what the
    /// analyzer's derived values were built from; a filesystem edit the
    /// analyzer has not been told about is invisible to its derived values by
    /// the same rule that makes it invisible to its declarations.
    ///
    /// Cost is one sort and one hash over the live path set, paid once per
    /// snapshot. A snapshot is minted only when the path map changes, so an
    /// unchanged language pays nothing for another language's edit.
    ///
    /// `overlaid` names the files whose content the caller takes from the
    /// project instead. Their blob identity here is replaced by a fixed
    /// marker, for a reason that is the whole overlay half of #2449: this map
    /// learns an overlay's identity lazily, when something first parses that
    /// buffer, so an entry for an overlaid path moves *during* a request. A
    /// derived value keyed on that would be rejected as stale the moment it
    /// was built. The path still contributes -- dropping it would make the
    /// identity equal to a workspace where the file does not exist -- but what
    /// it contributes says only "the project supplies this one".
    pub(crate) fn content_digest(
        &self,
        overlaid: Option<&brokk_bifrost_core::analyzer::project::WorkspaceOverlayContent>,
    ) -> StableDigest {
        let Some(overlaid) = overlaid.filter(|overlaid| !overlaid.entries().is_empty()) else {
            return *self.content_digest.get_or_init(|| {
                crate::analyzer::content_identity::analyzed_file_set_digest(
                    self.path_to_state
                        .iter()
                        .map(|(file, state)| (rel_path_string(file), state.oid)),
                )
            });
        };
        let mut memo = self
            .overlaid_content_digest
            .lock()
            .expect("overlaid content digest memo poisoned");
        if let Some((overlay_digest, digest)) = memo.as_ref()
            && *overlay_digest == overlaid.digest()
        {
            return *digest;
        }
        let digest = crate::analyzer::content_identity::analyzed_file_set_digest_with_overlays(
            self.path_to_state
                .iter()
                .map(|(file, state)| (rel_path_string(file), state.oid, overlaid.contains(file))),
        );
        *memo = Some((overlaid.digest(), digest));
        digest
    }

    pub fn paths_for_oid(&self, oid: Oid) -> &[ProjectFile] {
        self.oid_to_paths
            .get(&oid)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn oid_for_path(&self, file: &ProjectFile) -> Option<Oid> {
        self.path_to_state.get(file).map(|state| state.oid)
    }

    pub(crate) fn is_mounted_under(
        &self,
        file: &ProjectFile,
        primary_storage_lang: &str,
        storage_lang: &str,
    ) -> bool {
        primary_storage_lang == storage_lang
            || self
                .additional_mounts
                .get(file)
                .is_some_and(|mounts| mounts.contains(storage_lang))
    }

    /// Whether this exact frozen generation takes `file` from an unsaved
    /// overlay rather than the filesystem.
    pub(crate) fn is_overlay_path(&self, file: &ProjectFile) -> bool {
        self.path_to_state
            .get(file)
            .is_some_and(|state| state.is_overlay)
    }

    pub fn validated_oid_for_path(&self, file: &ProjectFile) -> Option<Oid> {
        let state = self.path_to_state.get(file)?;
        if state.validated {
            return Some(state.oid);
        }
        match (&state.stat, FileStat::from_path(&file.abs_path())) {
            (None, _) => Some(state.oid),
            (Some(expected), Some(current)) if &current == expected => Some(state.oid),
            _ => None,
        }
    }

    /// The blob identity that can be reused for content-derived work without
    /// reading `file`.
    ///
    /// A filesystem-revalidated entry must still have the stat captured with
    /// its identity. An entry owned by an explicit analyzer generation can be
    /// reused directly: filesystem edits are outside that snapshot until an
    /// explicit update advances the generation. Overlay entries answer `None`
    /// because their source identity also depends on the project's overlay
    /// revision rather than on the path map alone.
    ///
    /// This is the token a caller uses to reuse content-derived work without
    /// reading the file. It asks a different question from the token that
    /// decides which persisted rows are live, which is why it reads its own
    /// stat: a hashed non-Git identity stays live for the generation that
    /// indexed it, while the content it names is reusable only while the file
    /// provably still holds those bytes.
    pub fn reusable_oid_for_path(&self, file: &ProjectFile) -> Option<Oid> {
        let state = self.path_to_state.get(file)?;
        if state.generation_trusted {
            return Some(state.oid);
        }
        let expected = state.capture_stat.as_ref()?;
        (FileStat::from_path(&file.abs_path()).as_ref() == Some(expected)).then_some(state.oid)
    }

    pub fn contains_oid(&self, oid: Oid) -> bool {
        self.oid_to_paths.contains_key(&oid)
    }

    pub fn all_paths(&self) -> impl Iterator<Item = &ProjectFile> {
        self.path_to_state.keys()
    }

    /// Stat-validate a handful of result paths; return the stale ones.
    pub fn validate<'a>(&self, files: impl Iterator<Item = &'a ProjectFile>) -> Vec<ProjectFile> {
        let mut stale = Vec::new();
        for file in files {
            let state = self.path_to_state.get(file).or_else(|| {
                let abs_path = file.abs_path();
                self.path_to_state.iter().find_map(|(candidate, state)| {
                    (candidate.abs_path() == abs_path).then_some(state)
                })
            });
            let Some(state) = state else {
                stale.push(file.clone());
                continue;
            };
            if state.validated {
                continue;
            }
            match (&state.stat, FileStat::from_path(&file.abs_path())) {
                (None, _) => {}
                (Some(expected), Some(current)) if &current == expected => {}
                _ => stale.push(file.clone()),
            }
        }
        stale
    }
}

fn build_snapshot(
    repo: &Repository,
    workdir: &Path,
    overlay: &HashMap<ProjectFile, PathState>,
) -> Result<LiveSnapshot> {
    let index = repo.index().map_err(|e| e.to_string())?;
    let root = workdir
        .canonicalize()
        .map_err(|e| format!("canonicalizing workdir {}: {e}", workdir.display()))?;
    let mut oid_to_paths: HashMap<Oid, Vec<ProjectFile>> = map_with_capacity(index.len());
    let mut path_to_state = map_with_capacity(index.len());

    for entry in index.iter() {
        let rel = gitblob::index_path_to_string(&entry)?;
        let abs = workdir.join(&rel);
        let Some(stat) = FileStat::from_path(&abs) else {
            continue;
        };
        let oid = gitblob::resolve_index_entry_oid(workdir, &entry)?;
        let file = ProjectFile::new(root.clone(), PathBuf::from(rel));
        oid_to_paths.entry(oid).or_default().push(file.clone());
        path_to_state.insert(
            file,
            PathState {
                oid,
                is_overlay: false,
                stat: Some(stat.clone()),
                capture_stat: Some(stat),
                generation_trusted: false,
                // `Liveness::snapshot()` intentionally never promotes to
                // `true` -- see the `validated` field doc.
                validated: false,
            },
        );
    }

    for (file, state) in overlay {
        if state
            .stat
            .as_ref()
            .is_some_and(|stat| FileStat::from_path(&file.abs_path()).as_ref() != Some(stat))
        {
            continue;
        }
        if let Some(previous) = path_to_state.insert(file.clone(), state.clone())
            && let Some(paths) = oid_to_paths.get_mut(&previous.oid)
        {
            paths.retain(|existing| existing != file);
        }
        oid_to_paths
            .entry(state.oid)
            .or_default()
            .push(file.clone());
    }

    oid_to_paths.retain(|_, paths| !paths.is_empty());
    Ok(LiveSnapshot {
        oid_to_paths,
        path_to_state,
        additional_mounts: HashMap::default(),
        content_digest: OnceLock::new(),
        overlaid_content_digest: Mutex::new(None),
    })
}

fn snapshot_from_path_states(
    path_to_state: &HashMap<ProjectFile, PathState>,
    additional_mounts: &HashMap<ProjectFile, BTreeSet<String>>,
    revalidate_filesystem: bool,
) -> LiveSnapshot {
    let mut oid_to_paths: HashMap<Oid, Vec<ProjectFile>> = HashMap::default();
    let mut live_states = HashMap::default();
    for (file, state) in path_to_state {
        if state
            .stat
            .as_ref()
            .is_some_and(|stat| FileStat::from_path(&file.abs_path()).as_ref() != Some(stat))
        {
            continue;
        }
        oid_to_paths
            .entry(state.oid)
            .or_default()
            .push(file.clone());
        let mut live_state = state.clone();
        live_state.validated = state.stat.is_none() || !revalidate_filesystem;
        live_states.insert(file.clone(), live_state);
    }
    LiveSnapshot {
        oid_to_paths,
        path_to_state: live_states,
        additional_mounts: additional_mounts
            .iter()
            .filter(|(file, _)| path_to_state.contains_key(*file))
            .map(|(file, mounts)| (file.clone(), mounts.clone()))
            .collect(),
        content_digest: OnceLock::new(),
        overlaid_content_digest: Mutex::new(None),
    }
}

fn current_index_fingerprint(repo: &Repository) -> Result<IndexFingerprint> {
    let index = repo.index().map_err(|e| e.to_string())?;
    let path = index
        .path()
        .ok_or_else(|| "repository index has no on-disk path".to_string())?;
    let bytes = std::fs::read(path).map_err(|e| format!("read index {}: {e}", path.display()))?;
    Ok(IndexFingerprint {
        digest: Sha256::digest(bytes).into(),
    })
}

// Per-thread `fs::metadata` call counter for the M3 stat-storm regression
// tests below (and for other test modules driving a real analyzer/session on
// a single thread, via the `pub(crate)` accessors). Thread-local rather than
// a single process-wide counter: `cargo test` runs tests concurrently on
// separate threads, and each test that cares about this count only wants to
// see the `fs::metadata` calls its own synchronous call chain made, not ones
// from unrelated tests' threads (or from the production watcher's background
// thread, which never touches the counting thread).
#[cfg(test)]
thread_local! {
    static STAT_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn stat_call_count_for_test() -> usize {
    STAT_CALLS.with(std::cell::Cell::get)
}

#[cfg(test)]
pub(crate) fn reset_stat_call_count_for_test() {
    STAT_CALLS.with(|calls| calls.set(0));
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileStat {
    len: u64,
    modified: Option<SystemTime>,
    platform: PlatformStat,
}

/// Opaque filesystem state captured alongside a startup identity. Callers can
/// ask this module whether the state still matches without depending on the
/// platform-specific fields inside [`FileStat`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FileStatStamp(FileStat);

impl FileStat {
    fn from_path(path: &Path) -> Option<Self> {
        #[cfg(test)]
        STAT_CALLS.with(|calls| calls.set(calls.get() + 1));
        let metadata = std::fs::metadata(path).ok()?;
        if !metadata.is_file() {
            return None;
        }
        Some(Self::from_metadata(&metadata))
    }

    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            platform: PlatformStat::from_metadata(metadata),
        }
    }
}

impl Liveness {
    pub(crate) fn file_stat_matches(file: &ProjectFile, expected: &FileStatStamp) -> bool {
        FileStat::from_path(&file.abs_path()).as_ref() == Some(&expected.0)
    }
}

#[cfg(unix)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct PlatformStat {
    dev: u64,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
}

#[cfg(unix)]
impl PlatformStat {
    fn from_metadata(metadata: &Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;

        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
        }
    }
}

#[cfg(not(unix))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct PlatformStat;

#[cfg(not(unix))]
impl PlatformStat {
    fn from_metadata(_metadata: &Metadata) -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gitblob::test_repo::{
        commit_all, commit_paths, init_repo, refresh_index_stat_preserving_oid,
    };
    use git2::{IndexAddOption, ObjectType};

    fn project_file(root: &Path, rel: &str) -> ProjectFile {
        ProjectFile::new(root.canonicalize().unwrap(), PathBuf::from(rel))
    }

    /// The canonicalize storm: `rel_path_from_workdir` used to canonicalize
    /// every file's absolute path, which is one `readlink` per path component
    /// per workspace file. The reconciliation it performs is a property of the
    /// root, so it is resolved once per root.
    #[test]
    fn the_workspace_root_is_canonicalized_once_not_once_per_file() {
        const FILES: usize = 24;

        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        for index in 0..FILES {
            std::fs::write(
                temp.path().join(format!("f{index}.rs")),
                format!("fn f{index}() {{}}\n"),
            )
            .unwrap();
        }
        commit_all(&repo, "init");

        let liveness = Liveness::new(repo).unwrap();
        assert_eq!(
            liveness.canonicalizations(),
            0,
            "construction resolves the git workdir on its own, before this counter exists"
        );
        for index in 0..FILES {
            let file = project_file(temp.path(), &format!("f{index}.rs"));
            assert!(
                liveness.oid_for_path(&file).unwrap().is_some(),
                "f{index}.rs resolves"
            );
        }
        assert_eq!(
            liveness.canonicalizations(),
            1,
            "one canonicalize for the workspace root, not one per file"
        );
    }

    /// The guard the storm fix has to keep: a workspace root that IS a symlink
    /// into the repository -- the #1793 shape -- still yields
    /// repository-relative paths, because it is exactly the root that gets
    /// canonicalized.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_workspace_root_still_resolves_repository_relative_paths() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo_root = temp.path().join("repo");
        std::fs::create_dir(&repo_root).unwrap();
        let repo = init_repo(&repo_root);
        std::fs::create_dir_all(repo_root.join("packages/app/src")).unwrap();
        std::fs::write(
            repo_root.join("packages/app/src/db.rs"),
            "pub fn connection() {}\n",
        )
        .unwrap();
        commit_all(&repo, "init");
        let linked_root = temp.path().join("linked-app");
        std::os::unix::fs::symlink(repo_root.join("packages/app"), &linked_root).unwrap();

        let liveness = Liveness::new(repo).unwrap();
        let file = ProjectFile::new(linked_root, "src/db.rs");
        assert_eq!(
            liveness.rel_path_from_workdir(&file).unwrap(),
            PathBuf::from("packages/app/src/db.rs")
        );

        let index_oid = liveness
            .repo
            .lock()
            .unwrap()
            .index()
            .unwrap()
            .get_path(Path::new("packages/app/src/db.rs"), 0)
            .unwrap()
            .id;
        assert_eq!(liveness.oid_for_path(&file).unwrap().unwrap(), index_oid);
        assert_eq!(
            liveness.canonicalizations(),
            1,
            "resolving the symlinked root is the one canonicalize"
        );
    }

    #[test]
    fn clean_file_oid_comes_from_index() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        std::fs::write(temp.path().join("a.rs"), "fn main() {}\n").unwrap();
        commit_all(&repo, "init");

        let file = project_file(temp.path(), "a.rs");
        let liveness = Liveness::new(repo).unwrap();
        let resolved = liveness.oid_for_path(&file).unwrap().unwrap();
        let index = liveness.repo.lock().unwrap().index().unwrap();
        let index_oid = index.get_path(Path::new("a.rs"), 0).unwrap().id;

        assert_eq!(resolved, index_oid);
        assert_eq!(
            resolved,
            Oid::hash_object(ObjectType::Blob, b"fn main() {}\n").unwrap()
        );
    }

    #[test]
    fn concurrent_bulk_oid_projection_preserves_nested_workspace_paths() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        let module = temp.path().join("module");
        std::fs::create_dir(&module).unwrap();
        std::fs::write(module.join("a.rs"), "fn a() {}\n").unwrap();
        std::fs::write(module.join("b.py"), "def b(): pass\n").unwrap();
        commit_all(&repo, "init");

        let file_a = project_file(&module, "a.rs");
        let file_b = project_file(&module, "b.py");
        let index = repo.index().unwrap();
        let oid_a = index.get_path(Path::new("module/a.rs"), 0).unwrap().id;
        let oid_b = index.get_path(Path::new("module/b.py"), 0).unwrap().id;
        let liveness = Arc::new(Liveness::new(repo).unwrap());

        let (resolved_a, resolved_b) = std::thread::scope(|scope| {
            let liveness_a = Arc::clone(&liveness);
            let file_a_for_thread = file_a.clone();
            let a = scope.spawn(move || liveness_a.oids_for_files(&[file_a_for_thread]));
            let liveness_b = Arc::clone(&liveness);
            let file_b_for_thread = file_b.clone();
            let b = scope.spawn(move || liveness_b.oids_for_files(&[file_b_for_thread]));
            (a.join().unwrap().unwrap(), b.join().unwrap().unwrap())
        });

        assert_eq!(resolved_a.get(&file_a), Some(&oid_a));
        assert_eq!(resolved_b.get(&file_b), Some(&oid_b));
    }

    /// The batched projection is seeded by one working-tree scan, so it must
    /// answer for the working tree as it is now and not as that scan found it.
    /// Serving the scan's answer to a later call is what made `update_paths`
    /// re-register the pre-edit blob, which hid the edit from every
    /// blob-keyed reader for the rest of the session.
    #[test]
    fn editing_file_changes_bulk_oid_after_the_first_projection() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        std::fs::write(temp.path().join("a.rs"), "fn old() {}\n").unwrap();
        commit_all(&repo, "init");

        let file = project_file(temp.path(), "a.rs");
        let liveness = Liveness::new(repo).unwrap();
        let before = liveness
            .oids_for_files(std::slice::from_ref(&file))
            .unwrap();
        assert_eq!(
            before.get(&file),
            Some(&Oid::hash_object(ObjectType::Blob, b"fn old() {}\n").unwrap())
        );

        std::fs::write(temp.path().join("a.rs"), "fn new() {}\n").unwrap();
        let after = liveness
            .oids_for_files(std::slice::from_ref(&file))
            .unwrap();

        assert_eq!(
            after.get(&file),
            Some(&Oid::hash_object(ObjectType::Blob, b"fn new() {}\n").unwrap())
        );
    }

    /// A file created after the seeding scan has no scanned entry at all, so
    /// the projection must read it rather than report it as absent.
    #[test]
    fn bulk_projection_resolves_a_file_created_after_the_first_projection() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        std::fs::write(temp.path().join("a.rs"), "fn a() {}\n").unwrap();
        commit_all(&repo, "init");

        let existing = project_file(temp.path(), "a.rs");
        let liveness = Liveness::new(repo).unwrap();
        liveness.oids_for_files(&[existing]).unwrap();

        std::fs::write(temp.path().join("b.rs"), "fn b() {}\n").unwrap();
        let created = project_file(temp.path(), "b.rs");
        let resolved = liveness
            .oids_for_files(std::slice::from_ref(&created))
            .unwrap();

        assert_eq!(
            resolved.get(&created),
            Some(&Oid::hash_object(ObjectType::Blob, b"fn b() {}\n").unwrap())
        );
    }

    #[test]
    fn bulk_oid_projection_observes_edits_after_the_startup_scan() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        std::fs::write(temp.path().join("a.rs"), "fn old() {}\n").unwrap();
        commit_all(&repo, "init");

        let file = project_file(temp.path(), "a.rs");
        let liveness = Liveness::new(repo).unwrap();
        let before = liveness
            .oids_for_files(std::slice::from_ref(&file))
            .unwrap();
        assert_eq!(
            before.get(&file),
            Some(&Oid::hash_object(ObjectType::Blob, b"fn old() {}\n").unwrap())
        );

        // A full-refresh sweep after an out-of-band edit reuses the memoized
        // startup scan; the stat check must reject the stale index OID.
        std::fs::write(temp.path().join("a.rs"), "fn refreshed() {}\n").unwrap();
        let after = liveness
            .oids_for_files(std::slice::from_ref(&file))
            .unwrap();
        assert_eq!(
            after.get(&file),
            Some(&Oid::hash_object(ObjectType::Blob, b"fn refreshed() {}\n").unwrap())
        );
    }

    #[test]
    fn bulk_oid_projection_hashes_clean_eol_transformed_bytes() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        let source_path = temp.path().join("a.cs");
        std::fs::write(&source_path, "class A {}\n").unwrap();
        commit_all(&repo, "source");

        // The attribute is committed before the line-ending conversion so Git
        // treats the CRLF worktree bytes as clean.
        std::fs::write(temp.path().join(".gitattributes"), "*.cs text eol=crlf\n").unwrap();
        commit_paths(&repo, &[".gitattributes"], "attributes");
        std::fs::write(&source_path, "class A {}\r\n").unwrap();

        // Match the index stat Git records after a transformed checkout while
        // retaining the canonical LF blob OID. This exercises the clean fast
        // path; a stat-only implementation would incorrectly return the index
        // OID without hashing the visible CRLF bytes.
        let index_oid = refresh_index_stat_preserving_oid(&repo, "a.cs");

        assert!(
            repo.statuses(None).unwrap().is_empty(),
            "Git must treat the transformed worktree as clean"
        );
        let visible_oid = Oid::hash_object(ObjectType::Blob, b"class A {}\r\n").unwrap();
        assert_ne!(visible_oid, index_oid, "LF and CRLF OIDs must differ");

        let file = project_file(temp.path(), "a.cs");
        let liveness = Liveness::new(repo).unwrap();
        let resolved = liveness
            .oids_for_files(std::slice::from_ref(&file))
            .unwrap();
        assert_eq!(resolved.get(&file), Some(&visible_oid));
        assert_ne!(resolved.get(&file), Some(&index_oid));
    }

    #[cfg(unix)]
    #[test]
    fn bulk_oid_projection_ignores_unreadable_files_outside_the_request() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        std::fs::write(temp.path().join("a.rs"), "fn a() {}\n").unwrap();
        commit_all(&repo, "init");

        // An untracked, unreadable file elsewhere in the worktree models
        // another process's live database (for example a locked SQLite file
        // under `.bifrost/cache` on Windows). It must not fail the scan for
        // files the analyzer actually requested.
        let locked = temp.path().join("locked.db");
        std::fs::write(&locked, "junk").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

        let file = project_file(temp.path(), "a.rs");
        let liveness = Liveness::new(repo).unwrap();
        let resolved = liveness
            .oids_for_files(std::slice::from_ref(&file))
            .unwrap();
        assert_eq!(
            resolved.get(&file),
            Some(&Oid::hash_object(ObjectType::Blob, b"fn a() {}\n").unwrap())
        );

        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    #[test]
    fn ignored_requested_file_uses_its_working_bytes() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        std::fs::write(temp.path().join(".gitignore"), "generated.rs\n").unwrap();
        commit_all(&repo, "init");
        std::fs::write(temp.path().join("generated.rs"), "fn generated() {}\n").unwrap();

        let file = project_file(temp.path(), "generated.rs");
        let liveness = Liveness::new(repo).unwrap();
        let resolved = liveness
            .oids_for_files(std::slice::from_ref(&file))
            .unwrap();
        assert_eq!(
            resolved.get(&file),
            Some(&Oid::hash_object(ObjectType::Blob, b"fn generated() {}\n").unwrap())
        );
    }

    #[test]
    fn editing_file_changes_point_oid_without_git_command() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        std::fs::write(temp.path().join("a.rs"), "fn old() {}\n").unwrap();
        commit_all(&repo, "init");

        let file = project_file(temp.path(), "a.rs");
        let liveness = Liveness::new(repo).unwrap();
        let before = liveness.oid_for_path(&file).unwrap().unwrap();
        std::fs::write(temp.path().join("a.rs"), "fn new() {}\n").unwrap();
        let after = liveness.oid_for_path(&file).unwrap().unwrap();

        assert_ne!(before, after);
        assert_eq!(
            after,
            Oid::hash_object(ObjectType::Blob, b"fn new() {}\n").unwrap()
        );
    }

    #[test]
    fn untracked_overlay_appears_in_snapshot_until_index_wins() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        std::fs::write(temp.path().join("tracked.rs"), "fn tracked() {}\n").unwrap();
        commit_all(&repo, "init");
        std::fs::write(temp.path().join("fresh.rs"), "fn fresh() {}\n").unwrap();

        let file = project_file(temp.path(), "fresh.rs");
        let oid = Oid::hash_object(ObjectType::Blob, b"fn fresh() {}\n").unwrap();
        let liveness = Liveness::new(repo).unwrap();
        liveness
            .refresh_overlay([LivePathEntry::filesystem(file.clone(), oid)])
            .unwrap();

        let snapshot = liveness.snapshot().unwrap();
        assert_eq!(snapshot.oid_for_path(&file), Some(oid));
        assert_eq!(snapshot.paths_for_oid(oid), std::slice::from_ref(&file));

        {
            let repo = liveness.repo.lock().unwrap();
            let mut index = repo.index().unwrap();
            index.add_path(Path::new("fresh.rs")).unwrap();
            index.write().unwrap();
        }
        liveness
            .refresh_overlay([LivePathEntry::filesystem(file.clone(), oid)])
            .unwrap();

        let snapshot = liveness.snapshot().unwrap();
        assert_eq!(snapshot.oid_for_path(&file), Some(oid));
        assert_eq!(snapshot.paths_for_oid(oid), &[file]);
    }

    #[test]
    fn tracked_overlay_overrides_index_snapshot() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        std::fs::write(temp.path().join("tracked.rs"), "fn disk() {}\n").unwrap();
        commit_all(&repo, "init");

        let file = project_file(temp.path(), "tracked.rs");
        let overlay_oid = Oid::hash_object(ObjectType::Blob, b"fn overlay() {}\n").unwrap();
        let liveness = Liveness::new(repo).unwrap();
        liveness
            .refresh_overlay([LivePathEntry::overlay(file.clone(), overlay_oid)])
            .unwrap();

        let snapshot = liveness.snapshot().unwrap();
        assert_eq!(snapshot.oid_for_path(&file), Some(overlay_oid));
        assert!(snapshot.is_overlay_path(&file));
        assert_eq!(snapshot.paths_for_oid(overlay_oid), &[file]);
    }

    #[test]
    fn same_size_index_rewrite_invalidates_memoized_snapshot() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        std::fs::write(temp.path().join("a.rs"), "fn old() {}\n").unwrap();
        commit_all(&repo, "init");

        let file = project_file(temp.path(), "a.rs");
        let liveness = Liveness::new(repo).unwrap();
        let first = liveness.snapshot().unwrap();
        let old_oid = first.oid_for_path(&file).unwrap();

        std::fs::write(temp.path().join("a.rs"), "fn new() {}\n").unwrap();
        {
            let mut index = liveness.repo.lock().unwrap().index().unwrap();
            index
                .add_all(["a.rs"].iter(), IndexAddOption::DEFAULT, None)
                .unwrap();
            index.write().unwrap();
        }

        let second = liveness.snapshot().unwrap();
        let new_oid = second.oid_for_path(&file).unwrap();
        assert!(!Arc::ptr_eq(&first, &second));
        assert_ne!(old_oid, new_oid);
        assert_eq!(
            new_oid,
            Oid::hash_object(ObjectType::Blob, b"fn new() {}\n").unwrap()
        );
    }

    #[test]
    fn validate_flags_path_edited_after_snapshot_build() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        std::fs::write(temp.path().join("a.rs"), "fn old() {}\n").unwrap();
        commit_all(&repo, "init");

        let file = project_file(temp.path(), "a.rs");
        let liveness = Liveness::new(repo).unwrap();
        let snapshot = liveness.snapshot().unwrap();
        assert!(snapshot.validate([&file].into_iter()).is_empty());

        std::fs::write(temp.path().join("a.rs"), "fn new_name() {}\n").unwrap();
        assert_eq!(snapshot.validate([&file].into_iter()), vec![file]);
    }

    #[test]
    fn filesystem_validated_oid_for_path_rechecks_memoized_snapshots() {
        let temp = tempfile::TempDir::new().unwrap();
        std::fs::write(temp.path().join("a.rs"), "fn a() {}\n").unwrap();
        std::fs::write(temp.path().join("b.rs"), "fn b() {}\n").unwrap();
        let file_a = project_file(temp.path(), "a.rs");
        let file_b = project_file(temp.path(), "b.rs");
        let oid_a = Oid::hash_object(ObjectType::Blob, b"fn a() {}\n").unwrap();
        let oid_b = Oid::hash_object(ObjectType::Blob, b"fn b() {}\n").unwrap();

        reset_stat_call_count_for_test();
        let map = LivePathMap::default();
        map.refresh([
            LivePathEntry::filesystem(file_a.clone(), oid_a),
            LivePathEntry::filesystem(file_b.clone(), oid_b),
        ]);
        let snapshot = map.snapshot();
        let stats_after_build = stat_call_count_for_test();
        assert!(
            stats_after_build > 0,
            "refreshing the map and building the first snapshot must validate on disk at least once"
        );

        // Filesystem-backed entries must re-check the path even when the
        // LiveSnapshot itself is memoized. Direct analyzers do not have a
        // watcher, so this validation is what prevents a later out-of-band
        // edit from serving stale rows.
        for _ in 0..5 {
            assert_eq!(snapshot.validated_oid_for_path(&file_a), Some(oid_a));
            assert_eq!(snapshot.validated_oid_for_path(&file_b), Some(oid_b));
            assert!(snapshot.validate([&file_a, &file_b].into_iter()).is_empty());
        }
        assert!(
            stat_call_count_for_test() > stats_after_build,
            "filesystem-backed snapshots must keep revalidating memoized entries"
        );

        // Repeated LivePathMap::snapshot() calls with no mutation between
        // them must keep returning the same memoized Arc, not rebuild.
        let stats_before_snapshot_again = stat_call_count_for_test();
        let snapshot_again = map.snapshot();
        assert!(Arc::ptr_eq(&snapshot, &snapshot_again));
        assert_eq!(stat_call_count_for_test(), stats_before_snapshot_again);
    }

    #[test]
    fn refresh_bumps_generation_and_forces_revalidation_on_next_snapshot() {
        // Models the watcher-driven write path: `SearchToolsService::
        // apply_watcher_delta`/`apply_changed_files` -> analyzer `update()` ->
        // `resolve_live_oids` -> `LivePathMap::refresh` for exactly the
        // changed files, which is the existing invalidation plumbing this
        // milestone's memoization relies on.
        let temp = tempfile::TempDir::new().unwrap();
        std::fs::write(temp.path().join("a.rs"), "fn a() {}\n").unwrap();
        let file_a = project_file(temp.path(), "a.rs");
        let oid_a = Oid::hash_object(ObjectType::Blob, b"fn a() {}\n").unwrap();

        reset_stat_call_count_for_test();
        let map = LivePathMap::default();
        map.refresh([LivePathEntry::filesystem(file_a.clone(), oid_a)]);
        let snapshot = map.snapshot();
        assert_eq!(snapshot.validated_oid_for_path(&file_a), Some(oid_a));
        let stats_before_change = stat_call_count_for_test();

        // Simulate a watcher-reported edit landing on disk, then the write
        // path reporting it to `live_paths`.
        std::fs::write(temp.path().join("a.rs"), "fn a2() {}\n").unwrap();
        let new_oid_a = Oid::hash_object(ObjectType::Blob, b"fn a2() {}\n").unwrap();
        map.refresh([LivePathEntry::filesystem(file_a.clone(), new_oid_a)]);

        let new_snapshot = map.snapshot();
        assert!(
            !Arc::ptr_eq(&snapshot, &new_snapshot),
            "a real content change must bump the generation and force a fresh LiveSnapshot"
        );
        assert_eq!(
            new_snapshot.validated_oid_for_path(&file_a),
            Some(new_oid_a)
        );
        assert!(
            stat_call_count_for_test() > stats_before_change,
            "the changed path must be re-validated before its new oid is trusted"
        );

        // The old snapshot Arc may still be held by a concurrent reader, but
        // filesystem validation must refuse its now-stale path instead of
        // serving the old oid.
        assert_eq!(snapshot.validated_oid_for_path(&file_a), None);
    }

    /// The stat-paired token answers only for an identity that was captured
    /// with a filesystem stat, and it re-checks that stat every time.
    ///
    /// This is what lets a caller reuse content-derived work without reading
    /// the file. It must therefore refuse three cases the ordinary live-oid
    /// answer accepts: an overlay identity, an identity recorded under a
    /// trusted filesystem generation, and a path whose stat has changed. The
    /// hashed non-Git identity is the case that shows the two questions are
    /// separate: it stays live while its content stops being reusable.
    #[test]
    fn reusable_identity_honors_stat_and_explicit_generation_contracts() {
        let temp = tempfile::TempDir::new().unwrap();
        std::fs::write(temp.path().join("a.rs"), "fn a() {}\n").unwrap();
        let file = project_file(temp.path(), "a.rs");
        let oid = Oid::hash_object(ObjectType::Blob, b"fn a() {}\n").unwrap();

        let map = LivePathMap::default();
        map.refresh([LivePathEntry::filesystem(file.clone(), oid)]);
        let snapshot = map.snapshot();
        assert_eq!(snapshot.reusable_oid_for_path(&file), Some(oid));

        // An overlay identity has no filesystem stat to pair with, so the file
        // on disk says nothing about the content this identity describes.
        let overlay_map = LivePathMap::default();
        overlay_map.refresh([LivePathEntry::overlay(file.clone(), oid)]);
        let overlay_snapshot = overlay_map.snapshot();
        assert_eq!(overlay_snapshot.oid_for_path(&file), Some(oid));
        assert!(overlay_snapshot.is_overlay_path(&file));
        assert_eq!(overlay_snapshot.reusable_oid_for_path(&file), None);

        // An analyzer that owns its filesystem generation needs no stat: an
        // out-of-band edit is outside that snapshot until explicit refresh.
        let trusting_map = LivePathMap::trust_filesystem_generation();
        trusting_map.refresh([LivePathEntry::filesystem(file.clone(), oid)]);
        let trusting_snapshot = trusting_map.snapshot();
        assert_eq!(trusting_snapshot.validated_oid_for_path(&file), Some(oid));
        assert_eq!(trusting_snapshot.reusable_oid_for_path(&file), Some(oid));

        // An identity hashed here, outside a Git repository, answers the two
        // questions separately: it is live for the generation that indexed it,
        // and its content is reusable only while the file still holds it.
        let hashed_map = LivePathMap::default();
        hashed_map.refresh([LivePathEntry::filesystem_hashed(file.clone(), oid)]);
        let hashed_snapshot = hashed_map.snapshot();
        assert_eq!(hashed_snapshot.validated_oid_for_path(&file), Some(oid));
        assert_eq!(hashed_snapshot.reusable_oid_for_path(&file), Some(oid));

        // An edit behind the map's back is refused by the re-check, even
        // though the map still holds the entry.
        std::fs::write(temp.path().join("a.rs"), "fn a() { edited(); }\n").unwrap();
        assert_eq!(snapshot.oid_for_path(&file), Some(oid));
        assert_eq!(snapshot.reusable_oid_for_path(&file), None);
        assert_eq!(trusting_snapshot.reusable_oid_for_path(&file), Some(oid));

        // The same edit decouples the hashed entry's two answers. The analyzer
        // indexed the old bytes and no one has told it otherwise, so it must
        // keep answering from that generation; but the file no longer provably
        // holds those bytes, so nothing derived from them may be reused.
        assert_eq!(hashed_snapshot.validated_oid_for_path(&file), Some(oid));
        assert_eq!(hashed_snapshot.reusable_oid_for_path(&file), None);
        // A forked map rebuilds its snapshot from the same states, so this
        // exercises the build path rather than the memoized snapshot: a hashed
        // entry must survive it too.
        assert_eq!(
            hashed_map.fork().snapshot().validated_oid_for_path(&file),
            Some(oid)
        );
    }

    #[test]
    fn equal_content_transition_from_overlay_to_filesystem_changes_provenance() {
        let temp = tempfile::TempDir::new().unwrap();
        std::fs::write(temp.path().join("a.rs"), "fn a() {}\n").unwrap();
        let file = project_file(temp.path(), "a.rs");
        let oid = Oid::hash_object(ObjectType::Blob, b"fn a() {}\n").unwrap();

        let map = LivePathMap::trust_filesystem_generation();
        map.refresh([LivePathEntry::overlay(file.clone(), oid)]);
        let overlay_snapshot = map.snapshot();
        assert!(overlay_snapshot.is_overlay_path(&file));

        map.refresh([LivePathEntry::filesystem(file.clone(), oid)]);
        let filesystem_snapshot = map.snapshot();
        assert!(!Arc::ptr_eq(&overlay_snapshot, &filesystem_snapshot));
        assert!(!filesystem_snapshot.is_overlay_path(&file));
        assert_eq!(filesystem_snapshot.reusable_oid_for_path(&file), Some(oid));
    }

    #[test]
    fn replace_all_with_unchanged_content_keeps_the_memoized_snapshot() {
        // Models `UpdateStrategy::Manual`'s explicit `update_files()`/full
        // rebuild path and `requires_full_refresh`: `replace_all` always
        // re-stats every path once (that is the full sweep this call
        // performs), but if nothing on disk actually differs, the map's
        // generation must not bump and the already-validated snapshot must
        // keep being served without another rebuild.
        let temp = tempfile::TempDir::new().unwrap();
        std::fs::write(temp.path().join("a.rs"), "fn a() {}\n").unwrap();
        let file_a = project_file(temp.path(), "a.rs");
        let oid_a = Oid::hash_object(ObjectType::Blob, b"fn a() {}\n").unwrap();

        let map = LivePathMap::default();
        map.replace_all([LivePathEntry::filesystem(file_a.clone(), oid_a)]);
        let snapshot = map.snapshot();
        assert_eq!(snapshot.validated_oid_for_path(&file_a), Some(oid_a));

        map.replace_all([LivePathEntry::filesystem(file_a.clone(), oid_a)]);
        let same_snapshot = map.snapshot();
        assert!(
            Arc::ptr_eq(&snapshot, &same_snapshot),
            "a no-op full refresh must not discard the memoized snapshot"
        );
    }

    #[test]
    fn replace_all_with_changed_content_rebuilds_the_snapshot() {
        let temp = tempfile::TempDir::new().unwrap();
        std::fs::write(temp.path().join("a.rs"), "fn a() {}\n").unwrap();
        std::fs::write(temp.path().join("b.rs"), "fn b() {}\n").unwrap();
        let file_a = project_file(temp.path(), "a.rs");
        let file_b = project_file(temp.path(), "b.rs");
        let oid_a = Oid::hash_object(ObjectType::Blob, b"fn a() {}\n").unwrap();
        let oid_b = Oid::hash_object(ObjectType::Blob, b"fn b() {}\n").unwrap();

        let map = LivePathMap::default();
        map.replace_all([LivePathEntry::filesystem(file_a.clone(), oid_a)]);
        let snapshot = map.snapshot();

        // A full-refresh delta (e.g. `requires_full_refresh`) that now also
        // reports `b.rs` must clear the old stamps: the new snapshot must be
        // a distinct instance, and both files must resolve correctly.
        map.replace_all([
            LivePathEntry::filesystem(file_a.clone(), oid_a),
            LivePathEntry::filesystem(file_b.clone(), oid_b),
        ]);
        let new_snapshot = map.snapshot();
        assert!(!Arc::ptr_eq(&snapshot, &new_snapshot));
        assert_eq!(new_snapshot.validated_oid_for_path(&file_a), Some(oid_a));
        assert_eq!(new_snapshot.validated_oid_for_path(&file_b), Some(oid_b));
    }

    #[test]
    fn dirty_files_in_snapshot_use_hashed_working_tree_oid() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        std::fs::write(temp.path().join("a.rs"), "fn old() {}\n").unwrap();
        commit_all(&repo, "init");
        std::fs::write(temp.path().join("a.rs"), "fn dirty() {}\n").unwrap();

        let file = project_file(temp.path(), "a.rs");
        let liveness = Liveness::new(repo).unwrap();
        let snapshot = liveness.snapshot().unwrap();
        assert_eq!(
            snapshot.oid_for_path(&file),
            Some(Oid::hash_object(ObjectType::Blob, b"fn dirty() {}\n").unwrap())
        );
    }

    #[test]
    fn invalidating_startup_oids_refreshes_bulk_working_tree_identities() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        std::fs::write(temp.path().join("a.rs"), "fn old() {}\n").unwrap();
        commit_all(&repo, "init");

        let file = project_file(temp.path(), "a.rs");
        let liveness = Liveness::new(repo).unwrap();
        let initial = liveness
            .oids_for_files(std::slice::from_ref(&file))
            .unwrap();
        assert_eq!(
            initial.get(&file),
            Some(&Oid::hash_object(ObjectType::Blob, b"fn old() {}\n").unwrap())
        );

        std::fs::write(temp.path().join("a.rs"), "fn refreshed() {}\n").unwrap();
        liveness.invalidate_startup_oids();
        let refreshed = liveness
            .oids_for_files(std::slice::from_ref(&file))
            .unwrap();
        assert_eq!(
            refreshed.get(&file),
            Some(&Oid::hash_object(ObjectType::Blob, b"fn refreshed() {}\n").unwrap())
        );
    }
}
