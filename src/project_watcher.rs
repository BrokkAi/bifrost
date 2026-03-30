use crate::{Project, ProjectFile};
use notify::{
    Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher, recommended_watcher,
};
use std::collections::HashSet;
use std::mem;
use std::path::Path;
use std::sync::{Arc, Mutex};

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
    _watcher: RecommendedWatcher,
    pending: Arc<Mutex<PendingChanges>>,
}

impl ProjectChangeWatcher {
    pub fn start(project: Arc<dyn Project>) -> Result<Self, String> {
        let pending = Arc::new(Mutex::new(PendingChanges::default()));
        let pending_for_callback = Arc::clone(&pending);
        let project_for_callback = Arc::clone(&project);

        let mut watcher = recommended_watcher(move |result: notify::Result<Event>| match result {
            Ok(event) => handle_event(&project_for_callback, &pending_for_callback, event),
            Err(_) => mark_full_refresh(&pending_for_callback),
        })
        .map_err(|err| format!("Failed to create project watcher: {err}"))?;

        watcher
            .configure(Config::default())
            .map_err(|err| format!("Failed to configure project watcher: {err}"))?;
        watcher
            .watch(project.root(), RecursiveMode::Recursive)
            .map_err(|err| format!("Failed to watch project root: {err}"))?;

        Ok(Self {
            _watcher: watcher,
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
    let rel_path = path.strip_prefix(project.root()).ok()?;
    if rel_path.as_os_str().is_empty() {
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
