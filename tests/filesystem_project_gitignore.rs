use std::collections::BTreeSet;
use std::fs;

use brokk_analyzer::{FilesystemProject, Language, Project, ProjectFile};

fn rel_path_forward_slash(file: &ProjectFile) -> String {
    file.rel_path()
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/")
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
    let all_rel_paths: BTreeSet<_> = all_files
        .iter()
        .map(|file| rel_path_forward_slash(file))
        .collect();
    assert!(all_rel_paths.contains("src/main.rs"));
    assert!(all_rel_paths.contains("src/keep.py"));
    assert!(!all_rel_paths.contains("ignored.rs"));
    assert!(!all_rel_paths.contains("ignored_dir/lib.go"));
    assert!(!all_rel_paths.contains("trace.log"));

    let rust_files = project.analyzable_files(Language::Rust).unwrap();
    let rust_rel_paths: BTreeSet<_> = rust_files
        .iter()
        .map(|file| rel_path_forward_slash(file))
        .collect();
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
    let all_rel_paths: BTreeSet<_> = all_files
        .iter()
        .map(|file| rel_path_forward_slash(file))
        .collect();

    assert!(all_rel_paths.contains("src/main.rs"));
    assert!(!all_rel_paths.contains("ignored.rs"));

    let rust_files = project.analyzable_files(Language::Rust).unwrap();
    let rust_rel_paths: BTreeSet<_> = rust_files
        .iter()
        .map(|file| rel_path_forward_slash(file))
        .collect();
    assert_eq!(rust_rel_paths, BTreeSet::from(["src/main.rs".to_string()]));
}
