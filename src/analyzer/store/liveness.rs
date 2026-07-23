use std::fs::Metadata;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use git2::{ObjectType, Oid, Repository};
use sha2::{Digest, Sha256};

use crate::analyzer::ProjectFile;
use crate::gitblob;
use crate::hash::{HashMap, map_with_capacity};

type Result<T> = std::result::Result<T, String>;

pub struct Liveness {
    repo: Mutex<Repository>,
    workdir: PathBuf,
    snapshot: Mutex<Option<MemoizedSnapshot>>,
    overlay: Mutex<OverlayState>,
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
            snapshot: Mutex::new(None),
            overlay: Mutex::new(OverlayState::default()),
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
            let Some(state) = PathState::new(entry.oid, entry.validation, &file) else {
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

    fn rel_path_from_workdir(&self, file: &ProjectFile) -> Result<PathBuf> {
        let abs_path = file.abs_path();
        let canonical_abs = abs_path.canonicalize().unwrap_or_else(|_| abs_path.clone());
        canonical_abs
            .strip_prefix(&self.workdir)
            .or_else(|_| abs_path.strip_prefix(&self.workdir))
            .map(Path::to_path_buf)
            .map_err(|_| {
                format!(
                    "project file {} is not under git workdir {}",
                    abs_path.display(),
                    self.workdir.display()
                )
            })
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
    stat: Option<FileStat>,
    /// Whether this entry's `stat` has already been confirmed, as of *this*
    /// `PathState` instance, to match the filesystem — set exactly once, by
    /// `snapshot_from_path_states`, immediately after it performs that check
    /// while building a fresh `LiveSnapshot`. It is never written again after
    /// that: `LiveSnapshot` is published behind an `Arc` and treated as
    /// immutable from that point on, so a plain `bool` is sound here without
    /// atomics or interior mutability — there is no concurrent-mutation case
    /// to guard against, only concurrent *reads* of an already-fixed value.
    ///
    /// `LivePathMap`'s own source-of-truth entries (constructed only via
    /// `PathState::new`, in `refresh`/`replace_all`) always carry `false`;
    /// only the copies `snapshot_from_path_states` inserts into
    /// `LiveSnapshot::path_to_state` are ever promoted to `true`. That is
    /// deliberate: `LivePathMap`'s generation counter is bumped by every
    /// mutation that can change a path's live content (see `refresh`,
    /// `replace_all`, `remove`), so once `snapshot_from_path_states` rebuilds
    /// a `LiveSnapshot` after a generation change, every entry in it is
    /// correct until the *next* generation change discards that whole `Arc`
    /// and a fresh, re-validated one takes its place — trusting the
    /// just-performed check for the remaining lifetime of that instance is
    /// therefore safe, and lets `validated_oid_for_path`/`validate` skip the
    /// redundant per-call `fs::metadata`.
    ///
    /// `Liveness::snapshot()` (`build_snapshot`, below) deliberately does NOT
    /// opt in: it memoizes on the git index fingerprint plus the overlay
    /// generation, which do not change on a plain working-tree edit, so an
    /// out-of-band edit to a tracked file can leave the *same* memoized
    /// `Arc<LiveSnapshot>` in place indefinitely. Its callers rely on
    /// `validate`/`validated_oid_for_path` re-checking every time to catch
    /// that (see `validate_flags_path_edited_after_snapshot_build` below), so
    /// its entries keep `validated = false` forever.
    validated: bool,
}

impl PartialEq for PathState {
    /// Deliberately ignores `validated`: it is build provenance, not part of
    /// a path's live content, so two states that agree on `oid`/`stat` must
    /// compare equal regardless of which one (if either) has been through a
    /// `LiveSnapshot` validation pass. `refresh`/`replace_all` rely on this
    /// to detect genuine content changes without being fooled into treating
    /// a validation-flag difference as a change (in practice the two sides
    /// they compare are always both `false`, since only `PathState::new`
    /// feeds the source-of-truth maps — but the exclusion is correct either
    /// way and documents the intent explicitly rather than relying on that
    /// invariant silently holding).
    fn eq(&self, other: &Self) -> bool {
        self.oid == other.oid && self.stat == other.stat
    }
}

impl Eq for PathState {}

impl PathState {
    fn new(oid: Oid, validation: LivePathValidation, file: &ProjectFile) -> Option<Self> {
        let stat = match validation {
            LivePathValidation::Filesystem => Some(FileStat::from_path(&file.abs_path())?),
            LivePathValidation::Overlay => None,
        };
        Some(Self {
            oid,
            stat,
            validated: false,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LivePathValidation {
    Filesystem,
    Overlay,
}

impl LivePathValidation {
    fn is_filesystem(self) -> bool {
        matches!(self, Self::Filesystem)
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

    pub fn overlay(file: ProjectFile, oid: Oid) -> Self {
        Self {
            file,
            oid,
            validation: LivePathValidation::Overlay,
        }
    }
}

#[derive(Default)]
pub struct LivePathMap {
    state: Mutex<LivePathMapState>,
}

#[derive(Default)]
struct LivePathMapState {
    generation: u64,
    paths: HashMap<ProjectFile, PathState>,
    snapshot: Option<MemoizedLivePathMapSnapshot>,
}

struct MemoizedLivePathMapSnapshot {
    generation: u64,
    snapshot: Arc<LiveSnapshot>,
}

impl LivePathMap {
    pub fn fork(&self) -> Self {
        let guard = self.state.lock().expect("live path map mutex poisoned");
        Self {
            state: Mutex::new(LivePathMapState {
                generation: guard.generation,
                paths: guard.paths.clone(),
                snapshot: None,
            }),
        }
    }

    pub fn refresh(&self, entries: impl IntoIterator<Item = LivePathEntry>) {
        let mut guard = self.state.lock().expect("live path map mutex poisoned");
        let mut changed = false;
        for entry in entries {
            let Some(path_state) = PathState::new(entry.oid, entry.validation, &entry.file) else {
                changed |= guard.paths.remove(&entry.file).is_some();
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
            if let Some(path_state) = PathState::new(entry.oid, entry.validation, &entry.file) {
                next_paths.insert(entry.file, path_state);
            }
        }

        let mut guard = self.state.lock().expect("live path map mutex poisoned");
        if guard.paths != next_paths {
            guard.paths = next_paths;
            guard.generation = guard.generation.wrapping_add(1);
            guard.snapshot = None;
        }
    }

    pub fn remove(&self, files: impl IntoIterator<Item = ProjectFile>) {
        let mut guard = self.state.lock().expect("live path map mutex poisoned");
        let mut changed = false;
        for file in files {
            changed |= guard.paths.remove(&file).is_some();
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
        let snapshot = Arc::new(snapshot_from_path_states(&guard.paths));
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
}

impl LiveSnapshot {
    pub fn paths_for_oid(&self, oid: Oid) -> &[ProjectFile] {
        self.oid_to_paths
            .get(&oid)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn oid_for_path(&self, file: &ProjectFile) -> Option<Oid> {
        self.path_to_state.get(file).map(|state| state.oid)
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
                stat: Some(stat),
                // `Liveness::snapshot()` intentionally never promotes to
                // `true` — see the `validated` field doc.
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
    })
}

fn snapshot_from_path_states(path_to_state: &HashMap<ProjectFile, PathState>) -> LiveSnapshot {
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
        // This entry's `stat` was just confirmed, above, to match the
        // filesystem right now. Promote the clone that goes into the fresh,
        // about-to-be-`Arc`-published `LiveSnapshot` to `validated = true` so
        // `validated_oid_for_path`/`validate` can trust it for the remainder
        // of this snapshot's lifetime without re-`fs::metadata`-ing on every
        // call — `LivePathMap`'s generation counter guarantees a path whose
        // live content can change gets a fresh (unvalidated-until-checked)
        // `PathState` and forces this function to rerun before it is
        // observed again. The source-of-truth `state` itself (in
        // `LivePathMapState.paths`) is left untouched — only this snapshot
        // copy is promoted.
        let mut live_state = state.clone();
        live_state.validated = true;
        live_states.insert(file.clone(), live_state);
    }
    LiveSnapshot {
        oid_to_paths,
        path_to_state: live_states,
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
    use crate::gitblob::tests::{commit_all, init_repo};
    use git2::{IndexAddOption, ObjectType};

    fn project_file(root: &Path, rel: &str) -> ProjectFile {
        ProjectFile::new(root.canonicalize().unwrap(), PathBuf::from(rel))
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
    fn validated_oid_for_path_memoizes_after_first_snapshot_build() {
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

        // Many repeated queries against the same (unchanged) LiveSnapshot must
        // not call fs::metadata again — this is the per-call stat storm M3
        // removes (`validated_oid_for_path` and `analyzed_live_files`'s sweep
        // both funnel through this method).
        for _ in 0..5 {
            assert_eq!(snapshot.validated_oid_for_path(&file_a), Some(oid_a));
            assert_eq!(snapshot.validated_oid_for_path(&file_b), Some(oid_b));
            assert!(snapshot.validate([&file_a, &file_b].into_iter()).is_empty());
        }
        assert_eq!(
            stat_call_count_for_test(),
            stats_after_build,
            "repeated validated_oid_for_path/validate calls on an unchanged LiveSnapshot must not re-stat"
        );

        // Repeated LivePathMap::snapshot() calls with no mutation between
        // them must keep returning the same memoized Arc, not rebuild.
        let snapshot_again = map.snapshot();
        assert!(Arc::ptr_eq(&snapshot, &snapshot_again));
        assert_eq!(stat_call_count_for_test(), stats_after_build);
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

        // The old snapshot Arc (if anyone still held it, e.g. a concurrent
        // reader mid-call) keeps serving the old, now-stale content — the
        // same call-boundary consistency M2 established for the session
        // lock.
        assert_eq!(snapshot.validated_oid_for_path(&file_a), Some(oid_a));
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
}
