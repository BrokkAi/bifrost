use std::fs::Metadata;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use git2::{Oid, Repository};

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
        if !file.abs_path().is_file() {
            return Ok(None);
        }
        let repo = self.repo.lock().expect("liveness repo mutex poisoned");
        let rel_path = self.rel_path_from_workdir(file)?;
        gitblob::working_tree_oid_for_path(&repo, &rel_path)
    }

    /// Full live view; rebuilt only when `.git/index` stat changes.
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
    modified: Option<SystemTime>,
    size: u64,
}

#[derive(Clone, PartialEq, Eq)]
struct PathState {
    oid: Oid,
    stat: Option<FileStat>,
}

impl PathState {
    fn new(oid: Oid, validation: LivePathValidation, file: &ProjectFile) -> Option<Self> {
        let stat = match validation {
            LivePathValidation::Filesystem => Some(FileStat::from_path(&file.abs_path())?),
            LivePathValidation::Overlay => None,
        };
        Some(Self { oid, stat })
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
        live_states.insert(file.clone(), state.clone());
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
    let metadata =
        std::fs::metadata(path).map_err(|e| format!("stat index {}: {e}", path.display()))?;
    Ok(IndexFingerprint {
        modified: metadata.modified().ok(),
        size: metadata.len(),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileStat {
    len: u64,
    modified: Option<SystemTime>,
    platform: PlatformStat,
}

impl FileStat {
    fn from_path(path: &Path) -> Option<Self> {
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
    use std::thread;
    use std::time::Duration;

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
    fn index_rewrite_invalidates_memoized_snapshot() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        std::fs::write(temp.path().join("a.rs"), "fn old() {}\n").unwrap();
        commit_all(&repo, "init");

        let file = project_file(temp.path(), "a.rs");
        let liveness = Liveness::new(repo).unwrap();
        let first = liveness.snapshot().unwrap();
        let old_oid = first.oid_for_path(&file).unwrap();

        thread::sleep(Duration::from_millis(25));
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

        thread::sleep(Duration::from_millis(25));
        std::fs::write(temp.path().join("a.rs"), "fn new_name() {}\n").unwrap();
        assert_eq!(snapshot.validate([&file].into_iter()), vec![file]);
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
