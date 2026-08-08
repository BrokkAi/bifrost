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
        let pending = Arc::new(Mutex::new(PendingChanges::default()));
        let mut watcher = recommended_watcher(event_handler(&project, &pending))
            .map_err(|err| format!("Failed to create project watcher: {err}"))?;

        watcher
            .configure(Config::default())
            .map_err(|err| format!("Failed to configure project watcher: {err}"))?;
        watch_project_paths(&mut watcher, project.as_ref())?;

        Ok(Self {
            _watcher: WatcherBackend::Recommended { _watcher: watcher },
            pending,
        })
    }

    #[doc(hidden)]
    pub fn start_polling_for_tests(project: Arc<dyn Project>) -> Result<Self, String> {
        let pending = Arc::new(Mutex::new(PendingChanges::default()));
        let config = Config::default()
            .with_poll_interval(Duration::from_millis(20))
            .with_compare_contents(true);
        let mut watcher = PollWatcher::new(event_handler(&project, &pending), config)
            .map_err(|err| format!("Failed to create polling project watcher: {err}"))?;

        watch_project_paths(&mut watcher, project.as_ref())?;

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

fn watch_project_paths(watcher: &mut impl Watcher, project: &dyn Project) -> Result<(), String> {
    let recursive_roots = watch_roots(project)?;
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

fn watch_roots(project: &dyn Project) -> Result<Vec<PathBuf>, String> {
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

    fn project_with_files(paths: &[&str]) -> (TempDir, Arc<dyn Project>) {
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
        let roots = watch_roots(project.as_ref()).unwrap();
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
        let roots = watch_roots(project.as_ref()).unwrap();
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
        let roots = watch_roots(&project).unwrap();
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
