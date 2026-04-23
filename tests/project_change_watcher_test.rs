use brokk_analyzer::hash::HashSet;
use brokk_analyzer::{FilesystemProject, ProjectChangeWatcher, ProjectFile};
use std::fs;
use std::sync::Arc;
use std::time::Duration;

#[test]
fn watcher_reports_create_modify_delete_since_last_poll() {
    let temp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let root = temp.path().join("watcher-create-modify-delete");
    fs::create_dir_all(&root).unwrap();
    let root = root.canonicalize().unwrap();
    fs::create_dir_all(root.join(".git")).unwrap();
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join(".gitignore"), "").unwrap();

    let project = Arc::new(FilesystemProject::new(root.clone()).unwrap());
    let watcher = ProjectChangeWatcher::start(project).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    let file = ProjectFile::new(root.clone(), "src/main.rs");

    file.write("fn one() {}\n").unwrap();
    wait_for_expected_file(&watcher, &file);
    let empty = watcher.take_changed_files();
    assert_eq!(empty.files, HashSet::default());
    assert!(!empty.requires_full_refresh);

    file.write("fn two() {}\n").unwrap();
    wait_for_expected_file(&watcher, &file);

    fs::remove_file(root.join("src/main.rs")).unwrap();
    wait_for_expected_file(&watcher, &file);
}

#[test]
fn watcher_works_outside_git_repo() {
    let temp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let root = temp.path().join("watcher-non-git");
    fs::create_dir_all(&root).unwrap();
    let root = root.canonicalize().unwrap();
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join(".gitignore"), "ignored.rs\n").unwrap();

    let project = Arc::new(FilesystemProject::new(root.clone()).unwrap());
    let watcher = ProjectChangeWatcher::start(project).unwrap();
    std::thread::sleep(Duration::from_millis(100));

    let file = ProjectFile::new(root.clone(), "src/main.rs");
    file.write("fn main() {}\n").unwrap();
    wait_for_expected_file(&watcher, &file);

    let ignored = ProjectFile::new(root.clone(), "ignored.rs");
    ignored.write("fn ignored() {}\n").unwrap();
    std::thread::sleep(Duration::from_millis(100));
    let delta = watcher.take_changed_files();
    assert!(!delta.files.contains(&ignored));
}

fn wait_for_expected_file(watcher: &ProjectChangeWatcher, expected: &ProjectFile) {
    for _ in 0..50 {
        let delta = watcher.take_changed_files();
        if delta.requires_full_refresh {
            return;
        }
        if delta.files.contains(expected) {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    panic!(
        "watcher did not report expected path {}",
        expected.rel_path().display()
    );
}
