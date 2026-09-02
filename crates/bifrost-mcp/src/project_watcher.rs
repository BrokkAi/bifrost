use crate::hash::HashSet;
use crate::path_normalization::NormalizePath;
use crate::{BIFROST_IGNORE_FILE_NAME, Project, ProjectFile};
use notify::{
    Config, Event, EventKind, PollWatcher, RecommendedWatcher, RecursiveMode, Watcher,
    recommended_watcher,
};
use std::mem;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangeDelta {
    pub files: HashSet<ProjectFile>,
    pub requires_full_refresh: bool,
}

#[derive(Default)]
struct PendingChanges {
    files: HashSet<ProjectFile>,
    requires_full_refresh: bool,
}

pub struct ProjectChangeWatcher {
    _watcher: WatcherBackend,
    pending: Arc<Mutex<PendingChanges>>,
}

enum WatcherBackend {
    Recommended { _watcher: RecommendedWatcher },
    Poll { _watcher: PollWatcher },
}

impl ProjectChangeWatcher {
    pub fn start(project: Arc<dyn Project>) -> Result<Self, String> {
        Self::start_with_claimed_files(project, &[])
    }

    pub(crate) fn start_with_claimed_files(
        project: Arc<dyn Project>,
        claimed_files: &[ProjectFile],
    ) -> Result<Self, String> {
        let pending = Arc::new(Mutex::new(PendingChanges::default()));
        let mut watcher = recommended_watcher(event_handler(&project, &pending))
            .map_err(|err| format!("Failed to create project watcher: {err}"))?;

        watcher
            .configure(Config::default())
            .map_err(|err| format!("Failed to configure project watcher: {err}"))?;
        watch_project_paths(&mut watcher, project.as_ref(), claimed_files)?;

        Ok(Self {
            _watcher: WatcherBackend::Recommended { _watcher: watcher },
            pending,
        })
    }

    #[doc(hidden)]
    pub fn start_polling_for_tests(project: Arc<dyn Project>) -> Result<Self, String> {
        Self::start_polling_with_claimed_files_for_tests(project, &[])
    }

    #[doc(hidden)]
    pub fn start_polling_with_claimed_files_for_tests(
        project: Arc<dyn Project>,
        claimed_files: &[ProjectFile],
    ) -> Result<Self, String> {
        let pending = Arc::new(Mutex::new(PendingChanges::default()));
        let config = Config::default()
            .with_poll_interval(Duration::from_millis(20))
            .with_compare_contents(true);
        let mut watcher = PollWatcher::new(event_handler(&project, &pending), config)
            .map_err(|err| format!("Failed to create polling project watcher: {err}"))?;

        watch_project_paths(&mut watcher, project.as_ref(), claimed_files)?;

        Ok(Self {
            _watcher: WatcherBackend::Poll { _watcher: watcher },
            pending,
        })
    }

    pub fn take_changed_files(&self) -> ChangeDelta {
        let mut pending = self
            .pending
            .lock()
            .expect("project watcher pending state poisoned");
        ChangeDelta {
            files: mem::take(&mut pending.files),
            requires_full_refresh: mem::take(&mut pending.requires_full_refresh),
        }
    }

    /// Cheap peek at whether a subsequent `take_changed_files` would return a
    /// non-empty delta, without draining it. Locks only the watcher's own
    /// pending-state mutex, never the caller's session lock, so callers can
    /// decide whether an exclusive lock is worth taking before acquiring one.
    pub fn has_pending(&self) -> bool {
        let pending = self
            .pending
            .lock()
            .expect("project watcher pending state poisoned");
        pending.requires_full_refresh || !pending.files.is_empty()
    }
}

fn event_handler(
    project: &Arc<dyn Project>,
    pending: &Arc<Mutex<PendingChanges>>,
) -> impl FnMut(notify::Result<Event>) + Send + 'static {
    let pending_for_callback = Arc::clone(pending);
    let project_for_callback = Arc::clone(project);
    move |result: notify::Result<Event>| match result {
        Ok(event) => handle_event(&project_for_callback, &pending_for_callback, event),
        Err(_) => {
            project_for_callback.invalidate_cached_file_listing();
            mark_full_refresh(&pending_for_callback);
        }
    }
}

fn handle_event(project: &Arc<dyn Project>, pending: &Arc<Mutex<PendingChanges>>, event: Event) {
    if matches!(event.kind, EventKind::Access(_)) {
        return;
    }

    if event.paths.is_empty() {
        project.invalidate_cached_file_listing();
        mark_full_refresh(pending);
        return;
    }

    // `.git` internals are never project files: the workspace walk refuses to
    // descend a `.git` directory and the git-backed listing cannot report one,
    // so they are split off before anything below reads or drops the listing.
    // Doing this here is what breaks the watcher's feedback loop (#1848):
    // classification calls `is_bifrostignored`, which walks the whole tree and
    // runs `git status`, and `git status` writes `.git/index.lock`, which is
    // the next event. Ref state is exempt from the listing and project-file
    // decisions too, but still reaches the full-refresh decision below,
    // because HEAD movement changes tracked membership and blob identity for
    // files whose own contents never change.
    let mut git_ref_state_changed = false;
    let mut paths = Vec::with_capacity(event.paths.len());
    for path in &event.paths {
        match git_internal_disposition(project.as_ref(), path) {
            Some(GitInternalPath::RefState) => git_ref_state_changed = true,
            Some(GitInternalPath::Churn) => {}
            None => paths.push(path.as_path()),
        }
    }

    if git_ref_state_changed && triggers_refresh_fallback(&event) {
        mark_full_refresh(pending);
    }

    if paths.is_empty() {
        return;
    }

    // Any real change may add or remove listed paths, or alter what the
    // listing means (`.gitignore` edits, git index updates), so drop the
    // session's cached workspace listing before classification below --
    // `classify_project_path` consults `is_gitignored`, which refills the
    // cache from the now-current filesystem state. Events touching only the
    // analyzer's own SQLite state are exempt, exactly like the snapshot: those
    // writes follow every analyzed change, and letting them drop the listing
    // would defeat the cache during normal operation.
    if paths
        .iter()
        .any(|path| !is_internal_state_path(project.as_ref(), path))
    {
        project.invalidate_cached_file_listing();
    }

    if paths
        .iter()
        .any(|path| is_bifrost_ignore_path(project.as_ref(), path))
    {
        mark_full_refresh(pending);
        return;
    }

    let mut saw_refresh_fallback_path = false;
    for path in &paths {
        match classify_project_path(project.as_ref(), path) {
            PathDisposition::ProjectFile(project_file) => {
                let mut state = pending
                    .lock()
                    .expect("project watcher pending state poisoned");
                state.files.insert(project_file);
            }
            PathDisposition::IgnoredInternal => {}
            PathDisposition::RefreshFallback => saw_refresh_fallback_path = true,
        }
    }

    if saw_refresh_fallback_path && triggers_refresh_fallback(&event) {
        mark_full_refresh(pending);
    }
}

/// Event kinds that can invalidate more than the paths they name, so a path
/// the incremental update cannot represent forces a whole-workspace refresh.
fn triggers_refresh_fallback(event: &Event) -> bool {
    matches!(
        event.kind,
        EventKind::Any | EventKind::Other | EventKind::Modify(_) | EventKind::Remove(_)
    )
}

/// Git's own bookkeeping inside a `.git` directory, split by whether the
/// analyzer's view of the workspace can depend on it.
enum GitInternalPath {
    /// HEAD, refs, and merge state: a branch switch or commit changes which
    /// blobs are live and which paths are tracked, so the workspace needs a
    /// full refresh even though no working-tree file was reported.
    RefState,
    /// The index, its lockfile, objects, logs, and the rest: pure VCS churn
    /// that the analyzer never reads. `git status` -- which every workspace
    /// listing runs -- writes `.git/index.lock` on each invocation, so
    /// treating this churn as a change is a self-sustaining walk loop.
    Churn,
}

/// The `.git` entries whose changes reach the full-refresh decision. Census in
/// `.agents/docs/fenced-followups-investigation-2026-08.md` (Part B): nothing
/// in the workspace reads any other `.git` path in response to an event.
const GIT_REF_STATE_FILE_NAMES: [&str; 4] = ["HEAD", "packed-refs", "MERGE_HEAD", "ORIG_HEAD"];
const GIT_REFS_DIR_NAME: &str = "refs";
const GIT_DIR_NAME: &str = ".git";

/// Classify a path that lives inside a `.git` directory of the watched tree,
/// or `None` when the path is not `.git`-internal. The `.git` boundary matches
/// the workspace walk, which refuses to descend *any* directory named `.git`
/// ("VCS internals, never source", `collect_workspace_files`), so a vendored
/// sub-repository's internals are outside the project-file universe exactly
/// like the workspace's own. Paths outside the root are not classified here:
/// they keep feeding the refresh fallback.
fn git_internal_disposition(project: &dyn Project, path: &Path) -> Option<GitInternalPath> {
    let path = path.to_path_buf().normalize();
    let rel_path = path.strip_prefix(project.root()).ok()?;
    let mut components = rel_path.components();
    components.find(|component| component.as_os_str() == GIT_DIR_NAME)?;

    let Some(entry) = components.next() else {
        // The `.git` entry itself. A repository appearing or disappearing also
        // creates or removes its `HEAD`, which is ref state below, so this
        // event carries nothing of its own.
        return Some(GitInternalPath::Churn);
    };
    let entry = entry.as_os_str();
    if entry == GIT_REFS_DIR_NAME {
        return Some(GitInternalPath::RefState);
    }
    if components.next().is_none() && GIT_REF_STATE_FILE_NAMES.iter().any(|name| entry == *name) {
        return Some(GitInternalPath::RefState);
    }
    Some(GitInternalPath::Churn)
}

enum PathDisposition {
    ProjectFile(ProjectFile),
    IgnoredInternal,
    RefreshFallback,
}

fn classify_project_path(project: &dyn Project, path: &Path) -> PathDisposition {
    let path = path.to_path_buf().normalize();
    let Ok(rel_path) = path.strip_prefix(project.root()) else {
        return PathDisposition::RefreshFallback;
    };
    if rel_path.as_os_str().is_empty() {
        return PathDisposition::RefreshFallback;
    }
    if is_internal_state_rel_path(rel_path) {
        return PathDisposition::IgnoredInternal;
    }

    let file = ProjectFile::new(project.root().to_path_buf(), rel_path.to_path_buf());
    if project.is_bifrostignored(rel_path) {
        return PathDisposition::IgnoredInternal;
    }
    if file.exists() && project.is_gitignored(rel_path) {
        return PathDisposition::RefreshFallback;
    }

    PathDisposition::ProjectFile(file)
}

/// Whether `path` is analyzer-owned state inside the workspace, judged by the
/// path alone so it can gate listing-cache invalidation before any
/// classification that itself reads the listing. Paths outside the root are
/// not internal: they feed the refresh fallback.
fn is_internal_state_path(project: &dyn Project, path: &Path) -> bool {
    let path = path.to_path_buf().normalize();
    path.strip_prefix(project.root())
        .is_ok_and(is_internal_state_rel_path)
}

fn is_bifrost_ignore_path(project: &dyn Project, path: &Path) -> bool {
    let path = path.to_path_buf().normalize();
    path.strip_prefix(project.root()).is_ok_and(|rel_path| {
        rel_path
            .file_name()
            .is_some_and(|name| name == BIFROST_IGNORE_FILE_NAME)
    })
}

/// Generated SQLite state writes inside the watched workspace. Treating those
/// writes as source changes would repeatedly invalidate analyzer snapshots and
/// the cached file listing, but the rest of `.bifrost` is tracked project
/// input and must remain live.
fn is_internal_state_rel_path(rel_path: &Path) -> bool {
    let mut components = rel_path.components();
    if components
        .next()
        .is_none_or(|component| component.as_os_str() != crate::gitblob::PROJECT_DIR_NAME)
    {
        return false;
    }
    let child = components.next();
    child.is_some_and(|component| {
        component.as_os_str() == crate::gitblob::CACHE_SUBDIR_NAME
            || (components.next().is_none()
                && crate::cache_db::is_legacy_project_cache_file_name(component.as_os_str()))
    })
}

fn mark_full_refresh(pending: &Arc<Mutex<PendingChanges>>) {
    let mut state = pending
        .lock()
        .expect("project watcher pending state poisoned");
    state.requires_full_refresh = true;
}

fn watch_project_paths(
    watcher: &mut impl Watcher,
    project: &dyn Project,
    claimed_files: &[ProjectFile],
) -> Result<(), String> {
    let recursive_roots = watch_roots(project, claimed_files)?;
    if !recursive_roots.iter().any(|path| path == project.root()) {
        watcher
            .watch(project.root(), RecursiveMode::NonRecursive)
            .map_err(|err| format!("Failed to watch {}: {err}", project.root().display()))?;
    }

    let mut configuration_directories = crate::hash::HashSet::default();
    configuration_directories.insert(project.root().to_path_buf());
    for file in project
        .all_files()
        .map_err(|err| format!("Failed to list workspace files for watcher setup: {err}"))?
    {
        if file
            .rel_path()
            .file_name()
            .is_some_and(|name| name == BIFROST_IGNORE_FILE_NAME)
        {
            let directory = file
                .abs_path()
                .parent()
                .expect("workspace file must have a parent")
                .to_path_buf();
            configuration_directories.insert(directory);
        }
    }
    for directory in configuration_directories {
        if !recursive_roots
            .iter()
            .any(|root| directory.starts_with(root))
        {
            watcher
                .watch(&directory, RecursiveMode::NonRecursive)
                .map_err(|err| format!("Failed to watch {}: {err}", directory.display()))?;
        }
    }

    for path in recursive_roots {
        watcher
            .watch(&path, RecursiveMode::Recursive)
            .map_err(|err| format!("Failed to watch {}: {err}", path.display()))?;
    }
    Ok(())
}

fn watch_roots(
    project: &dyn Project,
    claimed_files: &[ProjectFile],
) -> Result<Vec<PathBuf>, String> {
    let mut directories = Vec::new();
    for language in project.analyzer_languages() {
        let files = project
            .analyzable_files(language)
            .map_err(|err| format!("Failed to list analyzable files for {language:?}: {err}"))?;
        for file in files {
            let dir = file
                .abs_path()
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| project.root().to_path_buf());
            directories.push(dir);
        }
    }
    for file in claimed_files {
        let dir = file
            .abs_path()
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| project.root().to_path_buf());
        directories.push(dir);
    }

    let project_configuration = project.root().join(crate::gitblob::PROJECT_DIR_NAME);
    if project_configuration.is_dir() {
        directories.push(project_configuration);
    }

    if directories.is_empty() {
        return Ok(vec![project.root().to_path_buf()]);
    }

    directories.sort();
    directories.dedup();

    let mut minimal = Vec::new();
    for dir in directories {
        if minimal
            .iter()
            .any(|existing: &PathBuf| dir.starts_with(existing))
        {
            continue;
        }
        minimal.push(dir);
    }
    Ok(minimal)
}

#[cfg(test)]
mod tests {
    use super::{
        BIFROST_IGNORE_FILE_NAME, PendingChanges, ProjectChangeWatcher, handle_event, watch_roots,
    };
    use crate::ProjectFile;
    use crate::path_normalization::NormalizePath;
    use crate::{FilesystemProject, Project};
    use notify::event::{CreateKind, ModifyKind, RemoveKind};
    use notify::{Event, EventKind};
    use std::fs;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tempfile::TempDir;

    pub(super) fn project_with_files(paths: &[&str]) -> (TempDir, Arc<dyn Project>) {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        for path in paths {
            let abs = root.join(path);
            if let Some(parent) = abs.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(abs, "fn item() {}\n").unwrap();
        }
        let project = Arc::new(FilesystemProject::new(root).unwrap()) as Arc<dyn Project>;
        (temp, project)
    }

    #[test]
    fn watch_roots_collapse_to_top_level_analyzed_dirs() {
        let (_temp, project) =
            project_with_files(&["src/main.rs", "src/nested/lib.rs", "tests/a.rs"]);
        let roots = watch_roots(project.as_ref(), &[]).unwrap();
        let rels: Vec<_> = roots
            .iter()
            .map(|path| {
                path.strip_prefix(project.root())
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        assert_eq!(rels, vec!["src", "tests"]);
    }

    #[test]
    fn watch_roots_include_existing_bifrost_project_configuration() {
        let (_temp, project) = project_with_files(&[
            "src/main.rs",
            ".bifrost/policies/example.rqlp",
            ".bifrost/suppressions.json",
        ]);
        let roots = watch_roots(project.as_ref(), &[]).unwrap();
        let rels: Vec<_> = roots
            .iter()
            .map(|path| {
                path.strip_prefix(project.root())
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();

        assert_eq!(rels, vec![".bifrost", "src"]);
    }

    #[test]
    fn polling_watcher_delivers_bifrost_configuration_edits() {
        let (_temp, project) = project_with_files(&["src/main.rs", ".bifrost/suppressions.json"]);
        let suppression_path = project.root().join(".bifrost/suppressions.json");
        let watcher = ProjectChangeWatcher::start_polling_for_tests(Arc::clone(&project)).unwrap();

        fs::write(&suppression_path, "updated configuration").unwrap();
        for _ in 0..100 {
            if watcher.has_pending() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        let delta = watcher.take_changed_files();
        assert!(!delta.requires_full_refresh);
        assert!(
            delta
                .files
                .iter()
                .any(|file| file.abs_path() == suppression_path),
            "the live watcher must deliver tracked suppression edits"
        );
    }

    #[test]
    fn watch_roots_fall_back_to_project_root_when_no_analyzable_files_exist() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::write(root.join(".gitignore"), "").unwrap();
        fs::create_dir_all(root.join("src")).unwrap();
        let project = FilesystemProject::new(root.clone()).unwrap();
        let roots = watch_roots(&project, &[]).unwrap();
        assert_eq!(roots, vec![root.normalize()]);
    }

    #[test]
    fn internal_cache_events_do_not_trigger_project_updates() {
        let (_temp, project) = project_with_files(&["src/main.rs"]);
        let cache_dir = project
            .root()
            .join(crate::gitblob::PROJECT_DIR_NAME)
            .join(crate::gitblob::CACHE_SUBDIR_NAME);
        fs::create_dir_all(&cache_dir).unwrap();
        let cache_db = cache_dir.join(crate::cache_db::cache_db_file_name());
        fs::write(&cache_db, "cache state").unwrap();

        for kind in [
            EventKind::Modify(ModifyKind::Any),
            EventKind::Remove(RemoveKind::Any),
        ] {
            let pending = Arc::new(Mutex::new(PendingChanges::default()));
            handle_event(
                &project,
                &pending,
                Event::new(kind).add_path(cache_db.clone()),
            );

            let state = pending.lock().unwrap();
            assert!(state.files.is_empty());
            assert!(!state.requires_full_refresh);
        }
    }

    #[test]
    fn legacy_root_cache_events_do_not_trigger_project_updates() {
        let (_temp, project) = project_with_files(&["src/main.rs"]);
        let project_dir = project.root().join(crate::gitblob::PROJECT_DIR_NAME);
        fs::create_dir_all(&project_dir).unwrap();

        for name in [
            crate::cache_db::LEGACY_CACHE_DB_FILE_NAME,
            "bifrost_cache.db-wal",
            "bifrost_cache.db-shm",
            "bifrost_cache.db-journal",
        ] {
            let path = project_dir.join(name);
            fs::write(&path, "legacy cache state").unwrap();
            let pending = Arc::new(Mutex::new(PendingChanges::default()));
            handle_event(
                &project,
                &pending,
                Event::new(EventKind::Modify(ModifyKind::Any)).add_path(path),
            );

            let state = pending.lock().unwrap();
            assert!(state.files.is_empty(), "{name} must remain internal");
            assert!(!state.requires_full_refresh);
        }
    }

    #[test]
    fn tracked_bifrost_configuration_events_are_project_updates() {
        let (_temp, project) = project_with_files(&["src/main.rs"]);
        for relative in [
            ".bifrost/policies/example.rqlp",
            ".bifrost/suppressions.json",
        ] {
            let path = project.root().join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, "configuration").unwrap();
            let pending = Arc::new(Mutex::new(PendingChanges::default()));

            handle_event(
                &project,
                &pending,
                Event::new(EventKind::Modify(ModifyKind::Any)).add_path(path.clone()),
            );

            let state = pending.lock().unwrap();
            assert_eq!(state.files.len(), 1, "{relative} must remain watched");
            assert!(
                state
                    .files
                    .contains(&ProjectFile::new(project.root().to_path_buf(), relative))
            );
            assert!(!state.requires_full_refresh);
        }
    }

    #[test]
    fn bifrostignore_events_require_a_full_refresh() {
        let (_temp, project) = project_with_files(&["src/main.rs"]);
        let path = project.root().join(BIFROST_IGNORE_FILE_NAME);
        for kind in [
            EventKind::Create(CreateKind::File),
            EventKind::Modify(ModifyKind::Any),
            EventKind::Remove(RemoveKind::File),
        ] {
            let pending = Arc::new(Mutex::new(PendingChanges::default()));
            handle_event(&project, &pending, Event::new(kind).add_path(path.clone()));

            let state = pending.lock().unwrap();
            assert!(state.files.is_empty());
            assert!(state.requires_full_refresh);
        }
    }

    #[test]
    fn events_invalidate_the_projects_cached_file_listing() {
        use crate::WorkspaceFileListingCache;

        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap().normalize();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/main.rs"), "fn main() {}\n").unwrap();
        let cache = Arc::new(WorkspaceFileListingCache::new(root.clone()));
        let project: Arc<dyn crate::Project> = Arc::new(
            FilesystemProject::with_cached_listing(root.clone(), Arc::clone(&cache)).unwrap(),
        );

        cache.files().unwrap();
        let extra = ProjectFile::new(root.clone(), "src/extra.rs");
        fs::write(extra.abs_path(), "fn extra() {}\n").unwrap();
        assert!(
            !cache.files().unwrap().contains(&extra),
            "listing must be cached until an event invalidates it"
        );

        // Analyzer-owned SQLite state writes must not drop the listing: they
        // follow every analyzed change and would defeat the cache.
        let cache_db = root
            .join(crate::gitblob::PROJECT_DIR_NAME)
            .join(crate::gitblob::CACHE_SUBDIR_NAME)
            .join(crate::cache_db::cache_db_file_name());
        fs::create_dir_all(cache_db.parent().unwrap()).unwrap();
        fs::write(&cache_db, "cache state").unwrap();
        let pending = Arc::new(Mutex::new(PendingChanges::default()));
        handle_event(
            &project,
            &pending,
            Event::new(EventKind::Modify(ModifyKind::Any)).add_path(cache_db),
        );
        assert!(
            !cache.files().unwrap().contains(&extra),
            "internal cache-state events must not drop the cached listing"
        );

        handle_event(
            &project,
            &pending,
            Event::new(EventKind::Modify(ModifyKind::Any)).add_path(extra.abs_path()),
        );

        assert!(
            cache.files().unwrap().contains(&extra),
            "a watcher event must drop the cached listing"
        );
    }

    /// Issue #1848. `git status` -- which every workspace listing runs -- writes
    /// and removes `.git/index.lock`, so classifying that churn as a change made
    /// the watcher walk the tree, which ran `git status`, which produced the next
    /// event. The exemption must cost nothing: no walk, no pending change.
    fn git_churn_paths(root: &std::path::Path) -> Vec<std::path::PathBuf> {
        vec![
            root.join(".git/index.lock"),
            root.join(".git/index"),
            root.join(".git/objects/ab/cdef"),
            root.join(".git/logs/HEAD"),
            root.join(".git"),
        ]
    }

    #[test]
    fn git_churn_events_neither_walk_the_workspace_nor_update_the_project() {
        let (_temp, project) = project_with_files(&["src/main.rs"]);
        let baseline = project.workspace_file_listing_count();

        for path in git_churn_paths(project.root()) {
            for kind in [
                EventKind::Create(CreateKind::File),
                EventKind::Modify(ModifyKind::Any),
                EventKind::Remove(RemoveKind::File),
            ] {
                let pending = Arc::new(Mutex::new(PendingChanges::default()));
                handle_event(&project, &pending, Event::new(kind).add_path(path.clone()));

                let state = pending.lock().unwrap();
                assert!(
                    state.files.is_empty(),
                    "{} must never be a project file",
                    path.display()
                );
                assert!(
                    !state.requires_full_refresh,
                    "{} must not force a full refresh",
                    path.display()
                );
            }
        }

        assert_eq!(
            project.workspace_file_listing_count(),
            baseline,
            "Git's own bookkeeping must not walk the workspace"
        );
    }

    #[test]
    fn git_ref_state_events_refresh_the_workspace_without_walking_it() {
        let (_temp, project) = project_with_files(&["src/main.rs"]);
        let baseline = project.workspace_file_listing_count();

        for relative in [
            ".git/HEAD",
            ".git/ORIG_HEAD",
            ".git/MERGE_HEAD",
            ".git/packed-refs",
            ".git/refs/heads/main",
        ] {
            let pending = Arc::new(Mutex::new(PendingChanges::default()));
            handle_event(
                &project,
                &pending,
                Event::new(EventKind::Modify(ModifyKind::Any))
                    .add_path(project.root().join(relative)),
            );

            let state = pending.lock().unwrap();
            assert!(state.files.is_empty(), "{relative} is never a project file");
            assert!(
                state.requires_full_refresh,
                "{relative} changes tracked membership, so it must still refresh"
            );
        }

        assert_eq!(
            project.workspace_file_listing_count(),
            baseline,
            "the refresh decision is a path decision and must not walk the workspace"
        );
    }

    #[test]
    fn nested_repository_internals_follow_the_same_boundary_as_the_workspace_walk() {
        let (_temp, project) = project_with_files(&["src/main.rs", ".github/workflows/ci.yml"]);
        let baseline = project.workspace_file_listing_count();

        let pending = Arc::new(Mutex::new(PendingChanges::default()));
        handle_event(
            &project,
            &pending,
            Event::new(EventKind::Modify(ModifyKind::Any))
                .add_path(project.root().join("vendor/lib/.git/index.lock")),
        );
        {
            let state = pending.lock().unwrap();
            assert!(
                state.files.is_empty(),
                "a vendored repository's index churn"
            );
            assert!(!state.requires_full_refresh);
        }
        assert_eq!(
            project.workspace_file_listing_count(),
            baseline,
            "the workspace walk skips every `.git` directory, so the watcher must too"
        );

        let pending = Arc::new(Mutex::new(PendingChanges::default()));
        handle_event(
            &project,
            &pending,
            Event::new(EventKind::Modify(ModifyKind::Any))
                .add_path(project.root().join("vendor/lib/.git/HEAD")),
        );
        {
            let state = pending.lock().unwrap();
            assert!(state.files.is_empty());
            assert!(
                state.requires_full_refresh,
                "a vendored repository's HEAD moves its blobs too"
            );
        }

        // `.github` only starts with `.git`: it is ordinary tracked input.
        let workflow = ProjectFile::new(project.root().to_path_buf(), ".github/workflows/ci.yml");
        let pending = Arc::new(Mutex::new(PendingChanges::default()));
        handle_event(
            &project,
            &pending,
            Event::new(EventKind::Modify(ModifyKind::Any)).add_path(workflow.abs_path()),
        );
        let state = pending.lock().unwrap();
        assert!(state.files.contains(&workflow));
        assert!(!state.requires_full_refresh);
    }

    #[test]
    fn source_events_still_invalidate_the_listing_and_classify() {
        use crate::WorkspaceFileListingCache;

        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap().normalize();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/main.rs"), "fn main() {}\n").unwrap();
        let cache = Arc::new(WorkspaceFileListingCache::new(root.clone()));
        let project: Arc<dyn Project> = Arc::new(
            FilesystemProject::with_cached_listing(root.clone(), Arc::clone(&cache)).unwrap(),
        );

        cache.files().unwrap();
        let extra = ProjectFile::new(root.clone(), "src/extra.rs");
        fs::write(extra.abs_path(), "fn extra() {}\n").unwrap();

        let pending = Arc::new(Mutex::new(PendingChanges::default()));
        handle_event(
            &project,
            &pending,
            Event::new(EventKind::Create(CreateKind::File)).add_path(extra.abs_path()),
        );

        assert!(
            cache.files().unwrap().contains(&extra),
            "a source event must still drop the cached listing"
        );
        let state = pending.lock().unwrap();
        assert!(
            state.files.contains(&extra),
            "a source event must still classify as a project file"
        );
        assert!(!state.requires_full_refresh);
    }

    /// The live loop, reproduced end to end: a real watcher over a real
    /// repository, driven only by Git's own bookkeeping. Before the exemption
    /// the first `.git` event walked the tree, that walk ran `git status`, and
    /// `git status` wrote the next `.git/index.lock` event -- 50-56 walks per
    /// second, indefinitely (issue #1848). No walk is legitimate here: nothing
    /// under the working tree changes.
    #[test]
    fn git_bookkeeping_in_a_watched_repository_never_walks_the_workspace() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap().normalize();
        fs::write(root.join("main.rs"), "fn main() {}\n").unwrap();
        let repository = git2::Repository::init(&root).unwrap();
        let mut index = repository.index().unwrap();
        index.add_path(std::path::Path::new("main.rs")).unwrap();
        index.write().unwrap();
        let tree_id = index.write_tree().unwrap();
        {
            let tree = repository.find_tree(tree_id).unwrap();
            let signature = git2::Signature::now("T", "t@example.com").unwrap();
            repository
                .commit(Some("HEAD"), &signature, &signature, "init", &tree, &[])
                .unwrap();
        }
        drop(index);
        drop(repository);
        // Written before the watcher starts and staged after it, so every
        // event the watcher sees comes from Git's index, not from a source
        // file.
        fs::write(root.join("later.rs"), "fn later() {}\n").unwrap();

        let project = Arc::new(FilesystemProject::new(root.clone()).unwrap()) as Arc<dyn Project>;
        let watcher = ProjectChangeWatcher::start(Arc::clone(&project)).unwrap();
        let baseline = project.workspace_file_listing_count();

        for arguments in [
            ["status", "--porcelain"].as_slice(),
            ["add", "-A"].as_slice(),
            ["status", "--porcelain"].as_slice(),
        ] {
            let output = std::process::Command::new("git")
                .current_dir(&root)
                .args(arguments)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "git {arguments:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(500));

        assert_eq!(
            project.workspace_file_listing_count(),
            baseline,
            "Git's index bookkeeping must not make the watcher walk the workspace"
        );
        let delta = watcher.take_changed_files();
        assert_eq!(delta, super::ChangeDelta::default());
    }

    #[test]
    fn source_events_are_incremental_but_git_events_trigger_full_refresh() {
        let (_temp, project) = project_with_files(&["src/main.rs"]);
        let source = ProjectFile::new(project.root().to_path_buf(), "src/main.rs");
        let source_pending = Arc::new(Mutex::new(PendingChanges::default()));
        handle_event(
            &project,
            &source_pending,
            Event::new(EventKind::Modify(ModifyKind::Any)).add_path(source.abs_path()),
        );
        let source_state = source_pending.lock().unwrap();
        assert_eq!(source_state.files.len(), 1);
        assert!(source_state.files.contains(&source));
        assert!(!source_state.requires_full_refresh);
        drop(source_state);

        let git_head = project.root().join(".git/HEAD");
        fs::create_dir_all(git_head.parent().unwrap()).unwrap();
        fs::write(&git_head, "ref: refs/heads/main\n").unwrap();
        let git_pending = Arc::new(Mutex::new(PendingChanges::default()));
        handle_event(
            &project,
            &git_pending,
            Event::new(EventKind::Modify(ModifyKind::Any)).add_path(git_head),
        );
        let git_state = git_pending.lock().unwrap();
        assert!(git_state.files.is_empty());
        assert!(git_state.requires_full_refresh);
    }

    #[test]
    fn mixed_source_and_git_events_trigger_full_refresh() {
        let (_temp, project) = project_with_files(&["src/main.rs"]);
        let source = ProjectFile::new(project.root().to_path_buf(), "src/main.rs");
        let git_head = project.root().join(".git/HEAD");
        fs::create_dir_all(git_head.parent().unwrap()).unwrap();
        fs::write(&git_head, "ref: refs/heads/main\n").unwrap();
        let pending = Arc::new(Mutex::new(PendingChanges::default()));

        handle_event(
            &project,
            &pending,
            Event::new(EventKind::Modify(ModifyKind::Any))
                .add_path(source.abs_path())
                .add_path(git_head),
        );

        let state = pending.lock().unwrap();
        assert!(state.files.contains(&source));
        assert!(
            state.requires_full_refresh,
            "a coalesced Git event can invalidate files beyond the incremental source path"
        );
    }
}

/// Operation-sequence properties for the change accumulator.
///
/// `PendingChanges` is meant to be a commutative, idempotent monoid over
/// (file set, full-refresh flag): set union on the files, sticky OR on the
/// flag, and `take_changed_files` is its only drain. Everything the watcher
/// does between a raw `notify::Event` and that pair -- the `.git` split that
/// broke the #1848 feedback loop, the `.bifrostignore` short circuit, the
/// internal-state exemption, the refresh fallback for paths the incremental
/// update cannot name -- must preserve that algebra no matter what order the
/// operating system delivers events in, or how often it repeats one.
///
/// The example-based tests above pin single events. These pin sequences: the
/// properties generate an event script over the alphabet of path shapes the
/// watcher classifies, then compare drains across permutation, duplication,
/// and splitting.
///
/// Events are fed to the real `handle_event` synchronously against a real
/// `FilesystemProject` over a temporary tree, and drained through the real
/// `take_changed_files`. The watcher backend is a `PollWatcher` that watches
/// no path at all, so the only events the accumulator ever sees are the
/// generated ones: no watcher thread, no sleeps, no filesystem race. The tree
/// is never mutated during a case, which is what makes classification a pure
/// function of the path shape and the permutation property meaningful.
#[cfg(test)]
mod pending_changes_properties {
    use super::tests::project_with_files;
    use super::{ChangeDelta, PendingChanges, ProjectChangeWatcher, WatcherBackend, handle_event};
    use crate::{Project, ProjectFile};
    use notify::event::{AccessKind, CreateKind, DataChange, ModifyKind, RemoveKind, RenameMode};
    use notify::{Config, Event, EventKind, PollWatcher};
    use proptest::prelude::*;
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// Cases per property. Classifying a tracked path costs two whole-workspace
    /// walks (`is_bifrostignored` and `is_gitignored` each read the listing),
    /// so the module's cost is dominated by real filesystem work rather than by
    /// generation. This count keeps all five properties inside a few seconds;
    /// `PROPTEST_CASES` raises it for a deliberate stress run.
    const CASES: u32 = 64;

    /// `ProptestConfig::with_cases` would pin the count and silently ignore
    /// `PROPTEST_CASES`, so the documented stress knob is honoured explicitly:
    /// the default is the cheap count above, and an operator asking for more
    /// gets exactly what they asked for.
    fn config() -> ProptestConfig {
        let mut config = ProptestConfig::default();
        if std::env::var_os("PROPTEST_CASES").is_none() {
            config.cases = CASES;
        }
        config
    }
    /// Events per generated script. Long enough that permutation, duplication
    /// and stickiness have something to say, short enough that a shrunk
    /// counterexample stays readable.
    const MAX_EVENTS: usize = 6;

    /// Tracked source files: present on disk, present in the workspace
    /// listing, so each one classifies as an incremental project file.
    const SOURCE_RELATIVE_PATHS: [&str; 3] = ["src/main.rs", "src/lib.rs", "tests/it.rs"];
    /// Tracked configuration: `.bifrost` project input that is *not* generated
    /// state, plus a dotted directory that merely starts with `.git`.
    const CONFIG_RELATIVE_PATHS: [&str; 3] = [
        ".bifrost/suppressions.json",
        ".bifrost/policies/example.rqlp",
        ".github/workflows/ci.yml",
    ];
    /// Analyzer-owned SQLite state, in both the current and the legacy layout.
    const INTERNAL_STATE_RELATIVE_PATHS: [&str; 3] = [
        ".bifrost/cache/bifrost_cache.db",
        ".bifrost/cache/bifrost_cache.db-wal",
        ".bifrost/bifrost_cache.db-wal",
    ];
    /// `.bifrostignore` at the root and nested: the watcher matches on the
    /// file name alone, so neither has to exist for the event to be real.
    const BIFROST_IGNORE_RELATIVE_PATHS: [&str; 2] = [".bifrostignore", "src/.bifrostignore"];
    /// Git bookkeeping the analyzer never reads (issue #1848).
    const GIT_CHURN_RELATIVE_PATHS: [&str; 5] = [
        ".git",
        ".git/index",
        ".git/index.lock",
        ".git/objects/ab/cdef",
        ".git/logs/HEAD",
    ];
    /// Git state that moves which blobs are live and which paths are tracked.
    const GIT_REF_STATE_RELATIVE_PATHS: [&str; 5] = [
        ".git/HEAD",
        ".git/ORIG_HEAD",
        ".git/MERGE_HEAD",
        ".git/packed-refs",
        ".git/refs/heads/main",
    ];
    /// Directory-level events, including the project root itself (the empty
    /// relative path).
    const DIRECTORY_RELATIVE_PATHS: [&str; 3] = ["", "src", "tests"];
    const OUTSIDE_ROOT_FILE_NAME: &str = "outside-the-workspace.rs";

    /// Everything the fixture materializes on disk. `.bifrostignore` and the
    /// `.git` shapes are deliberately absent: the watcher decides both by path
    /// alone, and creating a real `.git` here would turn the temporary tree
    /// into a repository and change what the workspace listing reports.
    fn fixture_relative_paths() -> Vec<&'static str> {
        SOURCE_RELATIVE_PATHS
            .iter()
            .chain(CONFIG_RELATIVE_PATHS.iter())
            .chain(INTERNAL_STATE_RELATIVE_PATHS.iter())
            .copied()
            .collect()
    }

    /// A real `ProjectChangeWatcher` whose backend watches nothing, so
    /// `take_changed_files` under test is the shipped drain while the pending
    /// state receives only the events a property feeds it.
    fn accumulator() -> ProjectChangeWatcher {
        let config = Config::default().with_poll_interval(Duration::from_secs(24 * 60 * 60));
        let watcher = PollWatcher::new(|_: notify::Result<Event>| {}, config)
            .expect("an unwatched poll watcher must start");
        ProjectChangeWatcher {
            _watcher: WatcherBackend::Poll { _watcher: watcher },
            pending: Arc::new(Mutex::new(PendingChanges::default())),
        }
    }

    /// The path shapes the watcher classifies differently from one another.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Target {
        Source(usize),
        Config(usize),
        InternalState(usize),
        BifrostIgnore(usize),
        GitChurn(usize),
        GitRefState(usize),
        Directory(usize),
        OutsideRoot,
    }

    impl Target {
        fn abs_path(self, root: &Path) -> PathBuf {
            match self {
                Self::Source(index) => root.join(SOURCE_RELATIVE_PATHS[index]),
                Self::Config(index) => root.join(CONFIG_RELATIVE_PATHS[index]),
                Self::InternalState(index) => root.join(INTERNAL_STATE_RELATIVE_PATHS[index]),
                Self::BifrostIgnore(index) => root.join(BIFROST_IGNORE_RELATIVE_PATHS[index]),
                Self::GitChurn(index) => root.join(GIT_CHURN_RELATIVE_PATHS[index]),
                Self::GitRefState(index) => root.join(GIT_REF_STATE_RELATIVE_PATHS[index]),
                Self::Directory(index) => {
                    let relative = DIRECTORY_RELATIVE_PATHS[index];
                    if relative.is_empty() {
                        root.to_path_buf()
                    } else {
                        root.join(relative)
                    }
                }
                Self::OutsideRoot => root
                    .parent()
                    .expect("a temporary project root has a parent")
                    .join(OUTSIDE_ROOT_FILE_NAME),
            }
        }

        /// The project file this shape contributes to an incremental delta.
        fn project_file(self, root: &Path) -> Option<ProjectFile> {
            match self {
                Self::Source(index) => Some(ProjectFile::new(
                    root.to_path_buf(),
                    SOURCE_RELATIVE_PATHS[index],
                )),
                Self::Config(index) => Some(ProjectFile::new(
                    root.to_path_buf(),
                    CONFIG_RELATIVE_PATHS[index],
                )),
                _ => None,
            }
        }
    }

    /// The `notify` event kinds the watcher distinguishes.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum EventShape {
        CreateFile,
        CreateFolder,
        ModifyAny,
        ModifyData,
        ModifyName,
        RemoveFile,
        RemoveFolder,
        AccessAny,
        Any,
        Other,
    }

    impl EventShape {
        fn to_kind(self) -> EventKind {
            match self {
                Self::CreateFile => EventKind::Create(CreateKind::File),
                Self::CreateFolder => EventKind::Create(CreateKind::Folder),
                Self::ModifyAny => EventKind::Modify(ModifyKind::Any),
                Self::ModifyData => EventKind::Modify(ModifyKind::Data(DataChange::Content)),
                Self::ModifyName => EventKind::Modify(ModifyKind::Name(RenameMode::Any)),
                Self::RemoveFile => EventKind::Remove(RemoveKind::File),
                Self::RemoveFolder => EventKind::Remove(RemoveKind::Folder),
                Self::AccessAny => EventKind::Access(AccessKind::Any),
                Self::Any => EventKind::Any,
                Self::Other => EventKind::Other,
            }
        }

        /// Contract: reads never change anything, so the watcher drops them
        /// before it looks at a single path.
        fn is_read_only(self) -> bool {
            matches!(self, Self::AccessAny)
        }

        /// Contract: an event kind that can invalidate more than the paths it
        /// names, so a path the incremental update cannot represent forces a
        /// whole-workspace refresh. Creations name exactly what they created;
        /// modifications, removals and the unspecified kinds do not.
        fn can_invalidate_beyond_its_paths(self) -> bool {
            match self {
                Self::CreateFile | Self::CreateFolder | Self::AccessAny => false,
                Self::ModifyAny
                | Self::ModifyData
                | Self::ModifyName
                | Self::RemoveFile
                | Self::RemoveFolder
                | Self::Any
                | Self::Other => true,
            }
        }
    }

    /// One generated operation: a `notify` event carrying zero or more of the
    /// classified path shapes. Zero paths is the backend's "I lost track,
    /// rescan" report.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct GeneratedEvent {
        shape: EventShape,
        targets: Vec<Target>,
    }

    impl GeneratedEvent {
        fn to_notify_event(&self, root: &Path) -> Event {
            let mut event = Event::new(self.shape.to_kind());
            for target in &self.targets {
                event = event.add_path(target.abs_path(root));
            }
            event
        }
    }

    /// One step of a generated script: the event plus the two knobs the
    /// properties use to derive a second delivery of the same operations --
    /// a sort key that produces a permutation, and a flag that repeats the
    /// event where a coalescing backend would.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ScriptStep {
        event: GeneratedEvent,
        order_key: u16,
        repeated: bool,
    }

    fn event_shape() -> impl Strategy<Value = EventShape> {
        prop_oneof![
            Just(EventShape::CreateFile),
            Just(EventShape::CreateFolder),
            Just(EventShape::ModifyAny),
            Just(EventShape::ModifyData),
            Just(EventShape::ModifyName),
            Just(EventShape::RemoveFile),
            Just(EventShape::RemoveFolder),
            Just(EventShape::AccessAny),
            Just(EventShape::Any),
            Just(EventShape::Other),
        ]
    }

    /// Weighted so that ordinary tracked churn dominates: every shape that
    /// forces a full refresh is a sequence absorber, and an alphabet made
    /// mostly of absorbers would stop exercising the incremental file set.
    fn target() -> impl Strategy<Value = Target> {
        prop_oneof![
            6 => (0..SOURCE_RELATIVE_PATHS.len()).prop_map(Target::Source),
            4 => (0..CONFIG_RELATIVE_PATHS.len()).prop_map(Target::Config),
            3 => (0..INTERNAL_STATE_RELATIVE_PATHS.len()).prop_map(Target::InternalState),
            3 => (0..GIT_CHURN_RELATIVE_PATHS.len()).prop_map(Target::GitChurn),
            2 => (0..GIT_REF_STATE_RELATIVE_PATHS.len()).prop_map(Target::GitRefState),
            1 => (0..BIFROST_IGNORE_RELATIVE_PATHS.len()).prop_map(Target::BifrostIgnore),
            1 => (0..DIRECTORY_RELATIVE_PATHS.len()).prop_map(Target::Directory),
            1 => Just(Target::OutsideRoot),
        ]
    }

    fn generated_event() -> impl Strategy<Value = GeneratedEvent> {
        (
            event_shape(),
            prop_oneof![
                9 => prop::collection::vec(target(), 1..=2),
                1 => Just(Vec::new()),
            ],
        )
            .prop_map(|(shape, targets)| GeneratedEvent { shape, targets })
    }

    fn event_script() -> impl Strategy<Value = Vec<ScriptStep>> {
        prop::collection::vec(
            (generated_event(), any::<u16>(), any::<bool>()).prop_map(
                |(event, order_key, repeated)| ScriptStep {
                    event,
                    order_key,
                    repeated,
                },
            ),
            0..=MAX_EVENTS,
        )
    }

    fn script_events(script: &[ScriptStep]) -> Vec<GeneratedEvent> {
        script.iter().map(|step| step.event.clone()).collect()
    }

    /// The same operations in a generated order. Sorting by the generated key
    /// (ties broken by position, so the result is deterministic) reaches every
    /// permutation the shrinker can then simplify toward the identity one.
    fn permuted_events(script: &[ScriptStep]) -> Vec<GeneratedEvent> {
        let mut order: Vec<(u16, usize)> = script
            .iter()
            .enumerate()
            .map(|(index, step)| (step.order_key, index))
            .collect();
        order.sort_unstable();
        order
            .into_iter()
            .map(|(_, index)| script[index].event.clone())
            .collect()
    }

    /// The same operations with a generated subsequence delivered twice, back
    /// to back, the way a backend that fails to coalesce repeats them.
    fn repeated_events(script: &[ScriptStep]) -> Vec<GeneratedEvent> {
        let mut events = Vec::with_capacity(script.len() * 2);
        for step in script {
            events.push(step.event.clone());
            if step.repeated {
                events.push(step.event.clone());
            }
        }
        events
    }

    fn apply(
        project: &Arc<dyn Project>,
        watcher: &ProjectChangeWatcher,
        events: &[GeneratedEvent],
    ) {
        for event in events {
            handle_event(
                project,
                &watcher.pending,
                event.to_notify_event(project.root()),
            );
        }
    }

    /// The accumulator's intended value: a file set and a sticky flag.
    #[derive(Debug, Default, Clone, PartialEq, Eq)]
    struct ModelDelta {
        files: BTreeSet<ProjectFile>,
        requires_full_refresh: bool,
    }

    impl ModelDelta {
        /// The watcher's contract, restated over the generated alphabet.
        ///
        /// This is written from what each path shape *means* rather than by
        /// calling `classify_project_path`, `git_internal_disposition`,
        /// `is_internal_state_path` or `triggers_refresh_fallback`: a model
        /// built on those helpers would agree with the implementation by
        /// construction and could only ever catch accumulation bugs. The one
        /// place the model cannot be independent is the ignore state, and it
        /// does not have to be: the fixture has no `.bifrostignore` file and
        /// no repository, so nothing under the root is git- or
        /// Bifrost-ignored and both probes are constant here.
        fn apply(&mut self, root: &Path, event: &GeneratedEvent) {
            if event.shape.is_read_only() {
                return;
            }
            // A pathless report means the backend cannot say what changed.
            if event.targets.is_empty() {
                self.requires_full_refresh = true;
                return;
            }

            // `.git` internals are never project files. Ref state still
            // reaches the refresh decision because HEAD movement changes
            // tracked membership; the rest is pure churn and costs nothing.
            let mut git_ref_state_changed = false;
            let mut remaining = Vec::with_capacity(event.targets.len());
            for target in &event.targets {
                match target {
                    Target::GitRefState(_) => git_ref_state_changed = true,
                    Target::GitChurn(_) => {}
                    other => remaining.push(*other),
                }
            }
            if git_ref_state_changed && event.shape.can_invalidate_beyond_its_paths() {
                self.requires_full_refresh = true;
            }
            if remaining.is_empty() {
                return;
            }

            // A `.bifrostignore` edit changes what the whole workspace
            // analyzes, whatever else the event named and whatever kind it is.
            if remaining
                .iter()
                .any(|target| matches!(target, Target::BifrostIgnore(_)))
            {
                self.requires_full_refresh = true;
                return;
            }

            let mut saw_unrepresentable_path = false;
            for target in remaining {
                match target {
                    Target::Source(_) | Target::Config(_) => {
                        self.files.insert(
                            target
                                .project_file(root)
                                .expect("tracked shapes name a project file"),
                        );
                    }
                    // Generated analyzer state follows every analyzed change
                    // and is never itself an input.
                    Target::InternalState(_) => {}
                    // A directory, the root itself, and anything outside the
                    // root are all paths an incremental update cannot name.
                    Target::Directory(_) | Target::OutsideRoot => saw_unrepresentable_path = true,
                    Target::GitChurn(_) | Target::GitRefState(_) | Target::BifrostIgnore(_) => {
                        unreachable!("handled above: {target:?}")
                    }
                }
            }
            if saw_unrepresentable_path && event.shape.can_invalidate_beyond_its_paths() {
                self.requires_full_refresh = true;
            }
        }

        fn fold(root: &Path, events: &[GeneratedEvent]) -> Self {
            let mut model = Self::default();
            for event in events {
                model.apply(root, event);
            }
            model
        }
    }

    fn as_model(delta: &ChangeDelta) -> ModelDelta {
        ModelDelta {
            files: delta.files.iter().cloned().collect(),
            requires_full_refresh: delta.requires_full_refresh,
        }
    }

    /// Property 1. The accumulator is a commutative monoid: the operating
    /// system's delivery order is not part of the answer. This is the property
    /// the `.git` split has to preserve -- a filter that ran only on the first
    /// event of a batch, or that let one path's decision depend on an earlier
    /// path's, would show up here and nowhere in the single-event tests.
    #[test]
    fn accumulating_an_event_sequence_is_order_independent() {
        let (_temp, project) = project_with_files(&fixture_relative_paths());
        let watcher = accumulator();
        // Both deliveries agreeing proves nothing if the second is never a
        // different order, so the run has to have reordered something.
        let reordered_a_sequence = AtomicBool::new(false);

        proptest!(config(), |(script in event_script())| {
            let events = script_events(&script);
            let shuffled = permuted_events(&script);
            if shuffled != events {
                reordered_a_sequence.store(true, Ordering::Relaxed);
            }

            apply(&project, &watcher, &events);
            let in_order = watcher.take_changed_files();
            apply(&project, &watcher, &shuffled);
            let permuted = watcher.take_changed_files();

            prop_assert_eq!(
                in_order,
                permuted,
                "delivery order changed the delta for {:?}",
                script
            );
        });

        assert!(
            reordered_a_sequence.load(Ordering::Relaxed),
            "the generator never produced a reordered delivery"
        );
    }

    /// Property 2. The accumulator is idempotent: a backend that repeats an
    /// event -- every inotify batch that fans one write out into several, and
    /// the poll backend's re-report of an unchanged file -- adds nothing.
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn repeating_events_does_not_change_the_delta() {
        let (_temp, project) = project_with_files(&fixture_relative_paths());
        let watcher = accumulator();
        let repeated_a_sequence = AtomicBool::new(false);

        proptest!(config(), |(script in event_script())| {
            let events = script_events(&script);
            let repeated = repeated_events(&script);
            if repeated != events {
                repeated_a_sequence.store(true, Ordering::Relaxed);
            }

            apply(&project, &watcher, &events);
            let once = watcher.take_changed_files();
            apply(&project, &watcher, &repeated);
            let twice = watcher.take_changed_files();

            prop_assert_eq!(once, twice, "repeated delivery changed the delta for {:?}", script);
        });

        assert!(
            repeated_a_sequence.load(Ordering::Relaxed),
            "the generator never produced a repeated delivery"
        );
    }

    /// Property 3. The full-refresh flag is a sticky OR over the sequence:
    /// it is set exactly when some single event would set it on its own, it
    /// never clears once set, and nothing delivered afterwards can take it
    /// back. Stated against the implementation alone -- each event is also
    /// applied by itself, so this holds without reference to the model.
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn full_refresh_is_the_sticky_or_of_the_sequence() {
        let (_temp, project) = project_with_files(&fixture_relative_paths());
        let watcher = accumulator();

        proptest!(config(), |(script in event_script())| {
            let events = script_events(&script);

            let mut any_alone = false;
            for event in &events {
                apply(&project, &watcher, std::slice::from_ref(event));
                any_alone |= watcher.take_changed_files().requires_full_refresh;
            }

            let mut previously_set = false;
            for event in &events {
                apply(&project, &watcher, std::slice::from_ref(event));
                let now_set = watcher
                    .pending
                    .lock()
                    .expect("project watcher pending state poisoned")
                    .requires_full_refresh;
                prop_assert!(
                    now_set || !previously_set,
                    "a later event cleared the full-refresh flag in {:?}",
                    script
                );
                previously_set = now_set;
            }

            let delta = watcher.take_changed_files();
            prop_assert_eq!(
                delta.requires_full_refresh,
                previously_set,
                "the drain disagreed with the accumulated flag for {:?}",
                script
            );
            prop_assert_eq!(
                delta.requires_full_refresh,
                any_alone,
                "the sequence flag is not the OR of the individual events for {:?}",
                script
            );
        });
    }

    /// Property 4. The drained delta equals an independent fold of the same
    /// sequence: union of the project files each event names, OR of the
    /// refresh decisions.
    #[test]
    fn the_drained_delta_matches_an_independent_fold() {
        let (_temp, project) = project_with_files(&fixture_relative_paths());
        let watcher = accumulator();

        proptest!(config(), |(script in event_script())| {
            let events = script_events(&script);
            let expected = ModelDelta::fold(project.root(), &events);

            apply(&project, &watcher, &events);
            let delta = watcher.take_changed_files();

            prop_assert_eq!(
                as_model(&delta),
                expected,
                "the accumulator disagreed with the contract for {:?}",
                script
            );
        });
    }

    /// Property 5. The drain is a reset, not a peek: it leaves no residue, so
    /// draining in the middle of a sequence splits the fold instead of
    /// duplicating or dropping part of it.
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn draining_resets_the_accumulator() {
        let (_temp, project) = project_with_files(&fixture_relative_paths());
        let watcher = accumulator();

        proptest!(
            config(),
            |(script in event_script(), split in any::<prop::sample::Index>())| {
                let events = script_events(&script);
                apply(&project, &watcher, &events);
                let first = watcher.take_changed_files();

                prop_assert!(!watcher.has_pending(), "residue after a drain of {:?}", script);
                apply(&project, &watcher, &[]);
                prop_assert_eq!(
                    watcher.take_changed_files(),
                    ChangeDelta::default(),
                    "a second drain reported a change for {:?}",
                    script
                );

                // The same sequence, drained in two halves, must partition the
                // single drain: nothing accumulated twice, nothing lost.
                let boundary = split.index(events.len() + 1);
                let (head, tail) = events.split_at(boundary);
                apply(&project, &watcher, head);
                let head_delta = watcher.take_changed_files();
                apply(&project, &watcher, tail);
                let tail_delta = watcher.take_changed_files();

                let mut union = head_delta.files;
                union.extend(tail_delta.files);
                prop_assert_eq!(
                    union,
                    first.files,
                    "a split drain lost or invented files for {:?}",
                    script
                );
                prop_assert_eq!(
                    head_delta.requires_full_refresh || tail_delta.requires_full_refresh,
                    first.requires_full_refresh,
                    "a split drain changed the refresh decision for {:?}",
                    script
                );
            }
        );
    }
}
