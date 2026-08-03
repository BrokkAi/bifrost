use std::collections::BTreeSet;
use std::fs;

use brokk_bifrost::{
    FileSetProject, FilesystemProject, Language, MultiRootProject, Project, ProjectFile,
};

fn rel_path_forward_slash(file: &ProjectFile) -> String {
    file.rel_path()
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/")
}

fn track_files(root: &std::path::Path, paths: &[&str]) {
    let repository = git2::Repository::init(root).unwrap();
    let mut index = repository.index().unwrap();
    for path in paths {
        index.add_path(std::path::Path::new(path)).unwrap();
    }
    index.write().unwrap();
}

#[test]
fn filesystem_project_skips_gitignored_files() {
    let temp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let root = temp.path().join("repo");
    fs::create_dir_all(&root).unwrap();
    let root = root.canonicalize().unwrap();
    fs::create_dir_all(root.join(".git")).unwrap();

    ProjectFile::new(root.clone(), ".gitignore")
        .write(
            r#"
ignored.rs
ignored_dir/
*.log
"#,
        )
        .unwrap();
    ProjectFile::new(root.clone(), "src/main.rs")
        .write("fn main() {}\n")
        .unwrap();
    ProjectFile::new(root.clone(), "src/keep.py")
        .write("def keep():\n    return 1\n")
        .unwrap();
    ProjectFile::new(root.clone(), "ignored.rs")
        .write("fn ignored() {}\n")
        .unwrap();
    ProjectFile::new(root.clone(), "ignored_dir/lib.go")
        .write("package ignored\n")
        .unwrap();
    ProjectFile::new(root.clone(), "trace.log")
        .write("ignored log\n")
        .unwrap();

    let project = FilesystemProject::new(root.clone()).unwrap();

    let all_files = project.all_files().unwrap();
    let all_rel_paths: BTreeSet<_> = all_files.iter().map(rel_path_forward_slash).collect();
    assert!(all_rel_paths.contains("src/main.rs"));
    assert!(all_rel_paths.contains("src/keep.py"));
    assert!(!all_rel_paths.contains("ignored.rs"));
    assert!(!all_rel_paths.contains("ignored_dir/lib.go"));
    assert!(!all_rel_paths.contains("trace.log"));

    let rust_files = project.analyzable_files(Language::Rust).unwrap();
    let rust_rel_paths: BTreeSet<_> = rust_files.iter().map(rel_path_forward_slash).collect();
    assert_eq!(rust_rel_paths, BTreeSet::from(["src/main.rs".to_string()]));

    let languages = project.analyzer_languages();
    assert!(languages.contains(&Language::Rust));
    assert!(languages.contains(&Language::Python));
    assert!(!languages.contains(&Language::Go));

    assert!(project.is_gitignored(std::path::Path::new("ignored.rs")));
    assert!(project.is_gitignored(std::path::Path::new("ignored_dir/lib.go")));
    assert!(!project.is_gitignored(std::path::Path::new("src/main.rs")));
}

#[test]
fn filesystem_project_works_outside_git_repo() {
    let temp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let root = temp.path().join("plain-dir");
    fs::create_dir_all(&root).unwrap();
    let root = root.canonicalize().unwrap();

    ProjectFile::new(root.clone(), ".gitignore")
        .write("ignored.rs\n")
        .unwrap();
    ProjectFile::new(root.clone(), "src/main.rs")
        .write("fn main() {}\n")
        .unwrap();
    ProjectFile::new(root.clone(), "ignored.rs")
        .write("fn ignored() {}\n")
        .unwrap();

    let project = FilesystemProject::new(root.clone()).unwrap();

    let all_files = project.all_files().unwrap();
    let all_rel_paths: BTreeSet<_> = all_files.iter().map(rel_path_forward_slash).collect();

    assert!(all_rel_paths.contains("src/main.rs"));
    assert!(!all_rel_paths.contains("ignored.rs"));

    let rust_files = project.analyzable_files(Language::Rust).unwrap();
    let rust_rel_paths: BTreeSet<_> = rust_files.iter().map(rel_path_forward_slash).collect();
    assert_eq!(rust_rel_paths, BTreeSet::from(["src/main.rs".to_string()]));
}

#[test]
fn bifrostignore_excludes_tracked_files_only_from_analysis() {
    let temp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let root = temp.path().join("repo");
    fs::create_dir_all(&root).unwrap();
    let root = root.canonicalize().unwrap();

    ProjectFile::new(root.clone(), ".gitignore")
        .write("vendor/\n")
        .unwrap();
    ProjectFile::new(root.clone(), ".bifrostignore")
        .write("vendor/\n")
        .unwrap();
    ProjectFile::new(root.clone(), "src/main.rs")
        .write("fn visible() {}\n")
        .unwrap();
    ProjectFile::new(root.clone(), "vendor/generated.rs")
        .write("fn generated() {}\n")
        .unwrap();
    track_files(
        &root,
        &[
            ".gitignore",
            ".bifrostignore",
            "src/main.rs",
            "vendor/generated.rs",
        ],
    );

    let project = FilesystemProject::new(root.clone()).unwrap();
    let generated = ProjectFile::new(root.clone(), "vendor/generated.rs");

    assert!(project.all_files().unwrap().contains(&generated));
    assert!(
        !project
            .analyzable_files(Language::Rust)
            .unwrap()
            .contains(&generated)
    );
    assert!(!project.is_gitignored(std::path::Path::new("vendor/generated.rs")));
}

#[test]
fn nested_bifrostignore_can_override_a_parent_file_pattern() {
    let temp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let root = temp.path().join("repo");
    fs::create_dir_all(&root).unwrap();
    let root = root.canonicalize().unwrap();

    ProjectFile::new(root.clone(), ".bifrostignore")
        .write("*.rs\n")
        .unwrap();
    ProjectFile::new(root.clone(), "src/.bifrostignore")
        .write("!keep.rs\n")
        .unwrap();
    ProjectFile::new(root.clone(), "src/keep.rs")
        .write("fn keep() {}\n")
        .unwrap();
    ProjectFile::new(root.clone(), "src/drop.rs")
        .write("fn drop_me() {}\n")
        .unwrap();

    let project = FilesystemProject::new(root.clone()).unwrap();
    let rust_files = project.analyzable_files(Language::Rust).unwrap();
    let rel_paths: BTreeSet<_> = rust_files.iter().map(rel_path_forward_slash).collect();

    assert_eq!(rel_paths, BTreeSet::from(["src/keep.rs".to_string()]));
}

#[test]
fn nested_bifrostignore_cannot_reinclude_a_parent_ignored_directory() {
    let temp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let root = temp.path().join("repo");
    fs::create_dir_all(&root).unwrap();
    let root = root.canonicalize().unwrap();

    ProjectFile::new(root.clone(), ".bifrostignore")
        .write("vendor/\n")
        .unwrap();
    ProjectFile::new(root.clone(), "vendor/.bifrostignore")
        .write("!generated.rs\n")
        .unwrap();
    ProjectFile::new(root.clone(), "vendor/generated.rs")
        .write("fn generated() {}\n")
        .unwrap();

    let project = FilesystemProject::new(root).unwrap();
    assert!(project.analyzable_files(Language::Rust).unwrap().is_empty());
}

#[test]
fn invalidation_reloads_bifrostignore_patterns() {
    let temp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let root = temp.path().join("repo");
    fs::create_dir_all(&root).unwrap();
    let root = root.canonicalize().unwrap();
    let ignore = ProjectFile::new(root.clone(), ".bifrostignore");
    let source = ProjectFile::new(root.clone(), "src/generated.rs");
    ignore.write("src/\n").unwrap();
    source.write("fn generated() {}\n").unwrap();

    let project = FilesystemProject::new(root).unwrap();
    assert!(project.analyzable_files(Language::Rust).unwrap().is_empty());

    ignore.write("").unwrap();
    assert!(project.analyzable_files(Language::Rust).unwrap().is_empty());
    project.invalidate_cached_file_listing();
    assert_eq!(
        project.analyzable_files(Language::Rust).unwrap(),
        BTreeSet::from([source])
    );
}

#[test]
fn explicit_file_sets_override_bifrostignore() {
    let temp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let root = temp.path().canonicalize().unwrap();
    ProjectFile::new(root.clone(), ".bifrostignore")
        .write("generated.rs\n")
        .unwrap();
    let source = ProjectFile::new(root.clone(), "generated.rs");
    source.write("fn generated() {}\n").unwrap();

    let project = FileSetProject::new(root, [std::path::PathBuf::from("generated.rs")]);
    assert_eq!(
        project.analyzable_files(Language::Rust).unwrap(),
        BTreeSet::from([source])
    );
}

#[test]
fn multi_root_projects_apply_each_roots_bifrostignore() {
    let temp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let first = temp.path().join("first");
    let second = temp.path().join("second");
    fs::create_dir_all(&first).unwrap();
    fs::create_dir_all(&second).unwrap();
    let first = first.canonicalize().unwrap();
    let second = second.canonicalize().unwrap();

    ProjectFile::new(first.clone(), ".bifrostignore")
        .write("ignored.rs\n")
        .unwrap();
    ProjectFile::new(first.clone(), "ignored.rs")
        .write("fn ignored_first() {}\n")
        .unwrap();
    ProjectFile::new(first.clone(), "kept.rs")
        .write("fn kept_first() {}\n")
        .unwrap();
    ProjectFile::new(second.clone(), ".bifrostignore")
        .write("other.rs\n")
        .unwrap();
    ProjectFile::new(second.clone(), "other.rs")
        .write("fn ignored_second() {}\n")
        .unwrap();
    ProjectFile::new(second.clone(), "kept.rs")
        .write("fn kept_second() {}\n")
        .unwrap();

    let project = MultiRootProject::new([first, second]).unwrap();
    let rust_files = project.analyzable_files(Language::Rust).unwrap();
    let rel_paths: BTreeSet<_> = rust_files.iter().map(rel_path_forward_slash).collect();

    assert_eq!(
        rel_paths,
        BTreeSet::from(["first/kept.rs".to_string(), "second/kept.rs".to_string()])
    );
}
