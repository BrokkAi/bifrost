use crate::Project;
use crate::ProjectFile;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

#[derive(Clone, Default)]
pub(crate) struct FileAccessTracker {
    inner: Arc<Mutex<BTreeMap<ProjectFile, SystemTime>>>,
}

impl FileAccessTracker {
    pub(crate) fn read_to_string(&self, file: &ProjectFile) -> io::Result<String> {
        let content = file.read_to_string()?;
        self.record_current(file);
        Ok(content)
    }

    pub(crate) fn record_current(&self, file: &ProjectFile) {
        let Ok(metadata) = std::fs::metadata(file.abs_path()) else {
            return;
        };
        let Ok(modified) = metadata.modified() else {
            return;
        };
        self.inner
            .lock()
            .expect("file access tracker poisoned")
            .insert(file.clone(), modified);
    }

    #[allow(dead_code)]
    pub(crate) fn record_write(&self, file: &ProjectFile) {
        self.record_current(file);
    }

    pub(crate) fn record_project_files(&self, project: &dyn Project, inputs: &[String]) {
        for input in inputs {
            let trimmed = input.trim();
            if trimmed.is_empty() {
                continue;
            }
            let rel_path = PathBuf::from(trimmed.replace('\\', "/"));
            if rel_path.is_absolute() {
                continue;
            }
            if let Some(file) = project.file_by_rel_path(&rel_path) {
                self.record_current(&file);
            }
        }
    }

    pub(crate) fn take_changed_files(&self) -> BTreeSet<ProjectFile> {
        let mut tracked = self.inner.lock().expect("file access tracker poisoned");
        let mut changed = BTreeSet::new();
        let mut deleted = Vec::new();

        for (file, previous_mtime) in tracked.iter_mut() {
            match std::fs::metadata(file.abs_path()).and_then(|metadata| metadata.modified()) {
                Ok(current_mtime) if current_mtime != *previous_mtime => {
                    *previous_mtime = current_mtime;
                    changed.insert(file.clone());
                }
                Ok(_) => {}
                Err(_) => {
                    changed.insert(file.clone());
                    deleted.push(file.clone());
                }
            }
        }

        for file in deleted {
            tracked.remove(&file);
        }

        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;
    use tempfile::TempDir;

    #[test]
    fn unchanged_file_is_not_reported() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = write_file(&root, "a.rs", "fn a() {}\n");
        let tracker = FileAccessTracker::default();
        tracker.record_current(&file);

        assert!(tracker.take_changed_files().is_empty());
    }

    #[test]
    fn changed_file_is_reported_once_and_mtime_is_updated() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = write_file(&root, "a.rs", "fn a() {}\n");
        let tracker = FileAccessTracker::default();
        tracker.record_current(&file);

        sleep_for_mtime_tick();
        file.write("fn b() {}\n").unwrap();

        assert_eq!(tracker.take_changed_files(), BTreeSet::from([file.clone()]));
        assert!(tracker.take_changed_files().is_empty());
    }

    #[test]
    fn deleted_file_is_reported_once_and_removed() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = write_file(&root, "a.rs", "fn a() {}\n");
        let tracker = FileAccessTracker::default();
        tracker.record_current(&file);

        std::fs::remove_file(file.abs_path()).unwrap();

        assert_eq!(tracker.take_changed_files(), BTreeSet::from([file.clone()]));
        assert!(tracker.take_changed_files().is_empty());
    }

    fn write_file(root: &std::path::Path, rel: &str, contents: &str) -> ProjectFile {
        let file = ProjectFile::new(root.to_path_buf(), PathBuf::from(rel));
        file.write(contents).unwrap();
        file
    }

    fn sleep_for_mtime_tick() {
        thread::sleep(Duration::from_millis(25));
    }
}
