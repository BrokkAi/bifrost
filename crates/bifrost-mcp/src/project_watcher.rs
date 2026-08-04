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

    // Any real change may add or remove listed paths, or alter what the
    // listing means (`.gitignore` edits, git index updates), so drop the
    // session's cached workspace listing before classification below --
    // `classify_project_path` consults `is_gitignored`, which refills the
    // cache from the now-current filesystem state. Events touching only the
    // analyzer's own SQLite state are exempt, exactly like the snapshot: those
    // writes follow every analyzed change, and letting them drop the listing
    // would defeat the cache during normal operation.
    if event.paths.is_empty()
        || event
            .paths
            .iter()
            .any(|path| !is_internal_state_path(project.as_ref(), path))
    {
        project.invalidate_cached_file_listing();
    }

    if event.paths.is_empty() {
        mark_full_refresh(pending);
        return;
    }

    if event
        .paths
        .iter()
        .any(|path| is_bifrost_ignore_path(project.as_ref(), path))
    {
        mark_full_refresh(pending);
        return;
    }

    let mut saw_refresh_fallback_path = false;
    for path in &event.paths {
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

    if saw_refresh_fallback_path
        && matches!(
            event.kind,
            EventKind::Any | EventKind::Other | EventKind::Modify(_) | EventKind::Remove(_)
        )
    {
        mark_full_refresh(pending);
    }
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
