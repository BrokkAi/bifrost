use crate::hash::HashSet;
use crate::path_normalization::NormalizePath;
use crate::{Project, ProjectFile};
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
}

fn event_handler(
    project: &Arc<dyn Project>,
    pending: &Arc<Mutex<PendingChanges>>,
) -> impl FnMut(notify::Result<Event>) + Send + 'static {
    let pending_for_callback = Arc::clone(pending);
    let project_for_callback = Arc::clone(project);
    move |result: notify::Result<Event>| match result {
        Ok(event) => handle_event(&project_for_callback, &pending_for_callback, event),
        Err(_) => mark_full_refresh(&pending_for_callback),
    }
}

fn handle_event(project: &Arc<dyn Project>, pending: &Arc<Mutex<PendingChanges>>, event: Event) {
    if matches!(event.kind, EventKind::Access(_)) {
        return;
    }

    if event.paths.is_empty() {
        mark_full_refresh(pending);
        return;
    }

    let mut saw_relevant_path = false;
    for path in &event.paths {
        if let Some(project_file) = normalize_project_file(project.as_ref(), path) {
            let mut state = pending
                .lock()
                .expect("project watcher pending state poisoned");
            state.files.insert(project_file);
            saw_relevant_path = true;
        }
    }

    if !saw_relevant_path
        && matches!(
            event.kind,
            EventKind::Any | EventKind::Other | EventKind::Modify(_) | EventKind::Remove(_)
        )
    {
        mark_full_refresh(pending);
    }
}

fn normalize_project_file(project: &dyn Project, path: &Path) -> Option<ProjectFile> {
    let path = path.to_path_buf().normalize();
    let rel_path = path.strip_prefix(project.root()).ok()?;
    if rel_path.as_os_str().is_empty() {
        return None;
    }
    // The unified SQLite cache writes inside the watched workspace. Treating
    // those writes as source changes repeatedly invalidates analyzer snapshots.
    if rel_path
        .components()
        .next()
        .is_some_and(|component| component.as_os_str() == crate::gitblob::CACHE_DIR_NAME)
    {
        return None;
    }

    let file = ProjectFile::new(project.root().to_path_buf(), rel_path.to_path_buf());
    if file.exists() && project.is_gitignored(rel_path) {
        return None;
    }

    Some(file)
}

fn mark_full_refresh(pending: &Arc<Mutex<PendingChanges>>) {
    let mut state = pending
        .lock()
        .expect("project watcher pending state poisoned");
    state.requires_full_refresh = true;
}

fn watch_project_paths(watcher: &mut impl Watcher, project: &dyn Project) -> Result<(), String> {
    for path in watch_roots(project)? {
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
    use super::{normalize_project_file, watch_roots};
    use crate::path_normalization::NormalizePath;
    use crate::{FilesystemProject, Project};
    use std::fs;
    use std::sync::Arc;
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
    fn internal_cache_changes_are_not_project_changes() {
        let (_temp, project) = project_with_files(&["src/main.rs"]);
        let cache_dir = project.root().join(crate::gitblob::CACHE_DIR_NAME);
        fs::create_dir_all(&cache_dir).unwrap();
        let cache_db = cache_dir.join(crate::cache_db::CACHE_DB_FILE_NAME);
        fs::write(&cache_db, "cache state").unwrap();

        assert_eq!(normalize_project_file(project.as_ref(), &cache_db), None);
        assert!(
            normalize_project_file(project.as_ref(), &project.root().join("src/main.rs")).is_some()
        );
    }
}
