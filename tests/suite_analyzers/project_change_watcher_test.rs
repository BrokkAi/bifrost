use brokk_bifrost::hash::HashSet;
use brokk_bifrost::{FilesystemProject, ProjectChangeWatcher, ProjectFile};
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
    let watcher = ProjectChangeWatcher::start_polling_for_tests(project).unwrap();
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
    let watcher = ProjectChangeWatcher::start_polling_for_tests(project).unwrap();

    let file = ProjectFile::new(root.clone(), "src/main.rs");
    file.write("fn main() {}\n").unwrap();
    wait_for_expected_file(&watcher, &file);

    let ignored = ProjectFile::new(root.clone(), "ignored.rs");
    ignored.write("fn ignored() {}\n").unwrap();
    std::thread::sleep(Duration::from_millis(100));
    let delta = watcher.take_changed_files();
    assert!(!delta.files.contains(&ignored));
}

#[test]
fn watcher_reports_root_bifrostignore_creation_as_a_full_refresh() {
    let temp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let root = temp.path().join("watcher-root-bifrostignore");
    fs::create_dir_all(root.join("src")).unwrap();
    let root = root.canonicalize().unwrap();
    fs::write(root.join("src/main.rs"), "fn main() {}\n").unwrap();

    let project = Arc::new(FilesystemProject::new(root.clone()).unwrap());
    let watcher = ProjectChangeWatcher::start_polling_for_tests(project).unwrap();
    fs::write(root.join(".bifrostignore"), "generated/\n").unwrap();

    wait_for_full_refresh(&watcher);
}

#[test]
fn watcher_reports_nested_bifrostignore_edits_as_a_full_refresh() {
    let temp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let root = temp.path().join("watcher-nested-bifrostignore");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::create_dir_all(root.join("vendor")).unwrap();
    let root = root.canonicalize().unwrap();
    fs::write(root.join("src/main.rs"), "fn main() {}\n").unwrap();
    fs::write(
        root.join("vendor/generated.rs"),
        "fn ignored_generated() {}\n",
    )
    .unwrap();
    let ignore = root.join("vendor/.bifrostignore");
    fs::write(&ignore, "generated.rs\n").unwrap();

    let project = Arc::new(FilesystemProject::new(root.clone()).unwrap());
    let watcher = ProjectChangeWatcher::start_polling_for_tests(project).unwrap();
    fs::write(ignore, "generated.rs\n# edited\n").unwrap();

    wait_for_full_refresh(&watcher);

    let ignored_source = ProjectFile::new(root.clone(), "vendor/generated.rs");
    ignored_source
        .write("fn still_ignored_generated() {}\n")
        .unwrap();
    std::thread::sleep(Duration::from_millis(100));
    let ignored_delta = watcher.take_changed_files();
    assert!(!ignored_delta.files.contains(&ignored_source));
    assert!(!ignored_delta.requires_full_refresh);

    fs::remove_file(root.join("vendor/.bifrostignore")).unwrap();
    wait_for_full_refresh(&watcher);
    fs::write(root.join("vendor/.bifrostignore"), "generated.rs\n").unwrap();
    wait_for_full_refresh(&watcher);
}

fn wait_for_expected_file(watcher: &ProjectChangeWatcher, expected: &ProjectFile) {
    for _ in 0..250 {
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

fn wait_for_full_refresh(watcher: &ProjectChangeWatcher) {
    let mut saw_full_refresh = false;
    let mut quiet_polls = 0;
    for _ in 0..250 {
        let delta = watcher.take_changed_files();
        if delta.requires_full_refresh {
            saw_full_refresh = true;
            quiet_polls = 0;
        } else if saw_full_refresh {
            quiet_polls += 1;
            if quiet_polls == 10 {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    panic!("watcher did not request a full refresh");
}
