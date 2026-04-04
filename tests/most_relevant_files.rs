use brokk_analyzer::{
    AnalyzerConfig, FilesystemProject, JavaAnalyzer, Language, ProjectFile, TestProject,
    WorkspaceAnalyzer,
    searchtools::{MostRelevantFilesParams, most_relevant_files},
};
use git2::{Repository, Signature};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use tempfile::TempDir;

fn write_file(root: &Path, rel_path: &str, contents: &str) -> ProjectFile {
    let file = ProjectFile::new(root.to_path_buf(), rel_path);
    file.write(contents).unwrap();
    file
}

fn java_analyzer(root: &Path) -> JavaAnalyzer {
    JavaAnalyzer::from_project(TestProject::new(root.to_path_buf(), Language::Java))
}

fn commit_paths(repo: &Repository, message: &str, add: &[&str], remove: &[&str]) {
    let mut index = repo.index().unwrap();
    for path in remove {
        index.remove_path(Path::new(path)).unwrap();
    }
    for path in add {
        index.add_path(Path::new(path)).unwrap();
    }
    index.write().unwrap();

    let tree_id = index.write_tree().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();
    let signature = Signature::now("Test User", "test@example.com").unwrap();
    let parent = repo
        .head()
        .ok()
        .and_then(|head| head.target())
        .and_then(|oid| repo.find_commit(oid).ok());
    let parents = parent.iter().collect::<Vec<_>>();
    repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        message,
        &tree,
        &parents,
    )
    .unwrap();
}

fn brokk_cli_result_lines(project_root: &Path, stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| project_root.join(line).is_file())
        .map(str::to_string)
        .collect()
}

#[test]
fn no_git_fallback_uses_import_page_ranker() {
    let temp = TempDir::new().unwrap();
    let root = temp.path();
    write_file(
        root,
        "test/A.java",
        r#"
        package test;
        import test.B;
        public class A { }
        "#,
    );
    write_file(
        root,
        "test/B.java",
        r#"
        package test;
        import test.C;
        public class B { }
        "#,
    );
    write_file(
        root,
        "test/C.java",
        r#"
        package test;
        public class C { }
        "#,
    );

    let analyzer = java_analyzer(root);
    let results = most_relevant_files(
        &analyzer,
        MostRelevantFilesParams {
            seed_files: vec!["test/A.java".to_string()],
            limit: 5,
        },
    );

    assert!(results.not_found.is_empty());
    assert!(!results.files.contains(&"test/A.java".to_string()));
    assert!(results.files.contains(&"test/B.java".to_string()));
    assert!(results.files.contains(&"test/C.java".to_string()));
}

#[test]
fn hybrid_git_and_import_results_are_merged_without_duplicates() {
    let temp = TempDir::new().unwrap();
    let root = temp.path();
    write_file(
        root,
        "test/A.java",
        r#"
        package test;
        import test.B;
        public class A { }
        "#,
    );
    write_file(
        root,
        "test/B.java",
        r#"
        package test;
        import test.C;
        public class B { }
        "#,
    );
    write_file(
        root,
        "test/C.java",
        r#"
        package test;
        public class C { }
        "#,
    );
    write_file(
        root,
        "test/D.java",
        r#"
        package test;
        public class D { }
        "#,
    );

    let repo = Repository::init(root).unwrap();
    commit_paths(
        &repo,
        "seed and git neighbor",
        &["test/A.java", "test/D.java"],
        &[],
    );

    let analyzer = java_analyzer(root);
    let results = most_relevant_files(
        &analyzer,
        MostRelevantFilesParams {
            seed_files: vec!["test/A.java".to_string()],
            limit: 3,
        },
    );

    assert_eq!(3, results.files.len());
    assert_eq!("test/D.java", results.files[0]);
    assert!(results.files.contains(&"test/B.java".to_string()));
    assert!(results.files.contains(&"test/C.java".to_string()));
}

#[test]
fn git_results_are_filled_with_import_ranking_when_needed() {
    let temp = TempDir::new().unwrap();
    let root = temp.path();
    write_file(
        root,
        "test/A.java",
        "package test; import test.C; public class A { }",
    );
    write_file(root, "test/B.java", "package test; public class B { }");
    write_file(root, "test/C.java", "package test; public class C { }");

    let repo = Repository::init(root).unwrap();
    commit_paths(&repo, "git edge", &["test/A.java", "test/B.java"], &[]);

    let analyzer = java_analyzer(root);
    let results = most_relevant_files(
        &analyzer,
        MostRelevantFilesParams {
            seed_files: vec!["test/A.java".to_string()],
            limit: 2,
        },
    );

    assert_eq!(vec!["test/B.java", "test/C.java"], results.files);
}

#[test]
fn untracked_seed_skips_git_and_uses_import_results() {
    let temp = TempDir::new().unwrap();
    let root = temp.path();
    write_file(
        root,
        "test/B.java",
        "package test; import test.C; public class B { }",
    );
    write_file(root, "test/C.java", "package test; public class C { }");

    let repo = Repository::init(root).unwrap();
    commit_paths(
        &repo,
        "tracked baseline",
        &["test/B.java", "test/C.java"],
        &[],
    );

    write_file(
        root,
        "test/A.java",
        "package test; import test.B; public class A { }",
    );

    let analyzer = java_analyzer(root);
    let results = most_relevant_files(
        &analyzer,
        MostRelevantFilesParams {
            seed_files: vec!["test/A.java".to_string()],
            limit: 2,
        },
    );

    assert_eq!(2, results.files.len());
    assert!(results.files.contains(&"test/B.java".to_string()));
    assert!(results.files.contains(&"test/C.java".to_string()));
    assert!(!results.files.contains(&"test/A.java".to_string()));
}

#[test]
fn rename_history_is_canonicalized_to_current_paths() {
    let temp = TempDir::new().unwrap();
    let root = temp.path();

    write_file(
        root,
        "A.java",
        r#"
        public class A {
            public String id() { return "a"; }
        }
        "#,
    );
    write_file(
        root,
        "UserService.java",
        r#"
        public class UserService {
            void useA() { new A().id(); }
        }
        "#,
    );

    let repo = Repository::init(root).unwrap();
    commit_paths(&repo, "initial", &["A.java", "UserService.java"], &[]);

    let a_path = root.join("A.java");
    let user_service_path = root.join("UserService.java");
    fs::write(
        &a_path,
        fs::read_to_string(&a_path).unwrap() + "\n// tweak\n",
    )
    .unwrap();
    fs::write(
        &user_service_path,
        fs::read_to_string(&user_service_path).unwrap() + "\n// tweak\n",
    )
    .unwrap();
    commit_paths(
        &repo,
        "co-change before rename",
        &["A.java", "UserService.java"],
        &[],
    );

    fs::rename(root.join("A.java"), root.join("Account.java")).unwrap();
    commit_paths(&repo, "rename", &["Account.java"], &["A.java"]);

    fs::write(
        root.join("Account.java"),
        fs::read_to_string(root.join("Account.java")).unwrap() + "\n// after rename\n",
    )
    .unwrap();
    fs::write(
        &user_service_path,
        fs::read_to_string(&user_service_path).unwrap() + "\n// uses Account\n",
    )
    .unwrap();
    commit_paths(
        &repo,
        "co-change after rename",
        &["Account.java", "UserService.java"],
        &[],
    );

    let analyzer = java_analyzer(root);
    let results = most_relevant_files(
        &analyzer,
        MostRelevantFilesParams {
            seed_files: vec!["UserService.java".to_string()],
            limit: 10,
        },
    );

    assert!(results.files.contains(&"Account.java".to_string()));
    assert!(!results.files.contains(&"A.java".to_string()));
}

#[test]
fn consolidation_commit_does_not_merge_deleted_file_history_into_new_file() {
    let temp = TempDir::new().unwrap();
    let root = temp.path();

    write_file(root, "Seed.java", "public class Seed { }");
    write_file(
        root,
        "OldA.java",
        "public class OldA { int value() { return 1; } }",
    );
    write_file(
        root,
        "OldB.java",
        "public class OldB { int value() { return 2; } }",
    );

    let repo = Repository::init(root).unwrap();
    commit_paths(&repo, "initial", &["Seed.java", "OldA.java", "OldB.java"], &[]);

    fs::write(root.join("Seed.java"), "public class Seed { int use() { return 1; } }").unwrap();
    fs::write(
        root.join("OldA.java"),
        "public class OldA { int value() { return 10; } }",
    )
    .unwrap();
    commit_paths(&repo, "seed cochanges with old a", &["Seed.java", "OldA.java"], &[]);

    let old_a_contents = fs::read_to_string(root.join("OldA.java")).unwrap();
    fs::remove_file(root.join("OldA.java")).unwrap();
    fs::remove_file(root.join("OldB.java")).unwrap();
    fs::write(root.join("New.java"), old_a_contents).unwrap();
    commit_paths(
        &repo,
        "consolidate old tests into new file",
        &["New.java"],
        &["OldA.java", "OldB.java"],
    );

    let analyzer = java_analyzer(root);
    let results = most_relevant_files(
        &analyzer,
        MostRelevantFilesParams {
            seed_files: vec!["Seed.java".to_string()],
            limit: 10,
        },
    );

    assert!(
        !results.files.contains(&"New.java".to_string()),
        "{:?}",
        results.files
    );
}

#[test]
fn missing_seed_files_are_reported() {
    let temp = TempDir::new().unwrap();
    let root = temp.path();
    write_file(root, "test/A.java", "package test; public class A { }");

    let analyzer = java_analyzer(root);
    let results = most_relevant_files(
        &analyzer,
        MostRelevantFilesParams {
            seed_files: vec!["missing.java".to_string(), "test/A.java".to_string()],
            limit: 5,
        },
    );

    assert_eq!(vec!["missing.java".to_string()], results.not_found);
    assert!(results.files.is_empty());
}

#[test]
fn matches_brokk_reference_for_project_filtering_git_repo_seed() {
    let brokk_root = PathBuf::from("/home/jonathan/Projects/brokk");
    if !brokk_root.is_dir() {
        eprintln!("skipping brokk parity regression: sibling repo not present");
        return;
    }

    let seed = "app/src/test/java/ai/brokk/ProjectFilteringGitRepoTest.java";
    let project = Arc::new(FilesystemProject::new(&brokk_root).unwrap());
    let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
    let bifrost = most_relevant_files(
        workspace.analyzer(),
        MostRelevantFilesParams {
            seed_files: vec![seed.to_string()],
            limit: 100,
        },
    );
    assert!(bifrost.not_found.is_empty());

    let brokk = Command::new("./gradlew")
        .arg("-q")
        .arg(":app:runMostRelevantFiles")
        .arg(format!("-Pargs=--root {} {}", brokk_root.display(), seed))
        .current_dir(&brokk_root)
        .output()
        .unwrap();
    assert!(
        brokk.status.success(),
        "{}",
        String::from_utf8_lossy(&brokk.stderr)
    );
    let expected = brokk_cli_result_lines(&brokk_root, &String::from_utf8(brokk.stdout).unwrap());

    assert_eq!(expected, bifrost.files);
}

#[test]
fn matches_brokk_reference_for_preview_text_panel_seed() {
    let brokk_root = PathBuf::from("/home/jonathan/Projects/brokk");
    if !brokk_root.is_dir() {
        eprintln!("skipping brokk parity regression: sibling repo not present");
        return;
    }

    let seed = "app/src/main/java/ai/brokk/gui/dialogs/PreviewTextPanel.java";
    let project = Arc::new(FilesystemProject::new(&brokk_root).unwrap());
    let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
    let bifrost = most_relevant_files(
        workspace.analyzer(),
        MostRelevantFilesParams {
            seed_files: vec![seed.to_string()],
            limit: 100,
        },
    );
    assert!(bifrost.not_found.is_empty());

    let brokk = Command::new("./gradlew")
        .arg("-q")
        .arg(":app:runMostRelevantFiles")
        .arg(format!("-Pargs=--root {} {}", brokk_root.display(), seed))
        .current_dir(&brokk_root)
        .output()
        .unwrap();
    assert!(
        brokk.status.success(),
        "{}",
        String::from_utf8_lossy(&brokk.stderr)
    );
    let expected = brokk_cli_result_lines(&brokk_root, &String::from_utf8(brokk.stdout).unwrap());

    assert_eq!(expected, bifrost.files);
}

#[test]
fn matches_brokk_reference_for_content_diff_utils_seed() {
    let brokk_root = PathBuf::from("/home/jonathan/Projects/brokk");
    if !brokk_root.is_dir() {
        eprintln!("skipping brokk parity regression: sibling repo not present");
        return;
    }

    let seed = "app/src/main/java/ai/brokk/util/ContentDiffUtils.java";
    let project = Arc::new(FilesystemProject::new(&brokk_root).unwrap());
    let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
    let bifrost = most_relevant_files(
        workspace.analyzer(),
        MostRelevantFilesParams {
            seed_files: vec![seed.to_string()],
            limit: 100,
        },
    );
    assert!(bifrost.not_found.is_empty());

    let brokk = Command::new("./gradlew")
        .arg("-q")
        .arg(":app:runMostRelevantFiles")
        .arg(format!("-Pargs=--root {} {}", brokk_root.display(), seed))
        .current_dir(&brokk_root)
        .output()
        .unwrap();
    assert!(
        brokk.status.success(),
        "{}",
        String::from_utf8_lossy(&brokk.stderr)
    );
    let expected = brokk_cli_result_lines(&brokk_root, &String::from_utf8(brokk.stdout).unwrap());

    assert_eq!(expected, bifrost.files);
}

#[test]
fn matches_brokk_reference_for_typescript_lookup_seed() {
    let brokk_root = PathBuf::from("/home/jonathan/Projects/brokk");
    if !brokk_root.is_dir() {
        eprintln!("skipping brokk parity regression: sibling repo not present");
        return;
    }

    let seed = "frontend-mop/src/stores/lookup.ts";
    let project = Arc::new(FilesystemProject::new(&brokk_root).unwrap());
    let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
    let bifrost = most_relevant_files(
        workspace.analyzer(),
        MostRelevantFilesParams {
            seed_files: vec![seed.to_string()],
            limit: 100,
        },
    );
    assert!(bifrost.not_found.is_empty());

    let brokk = Command::new("./gradlew")
        .arg("-q")
        .arg(":app:runMostRelevantFiles")
        .arg(format!("-Pargs=--root {} {}", brokk_root.display(), seed))
        .current_dir(&brokk_root)
        .output()
        .unwrap();
    assert!(
        brokk.status.success(),
        "{}",
        String::from_utf8_lossy(&brokk.stderr)
    );
    let expected = brokk_cli_result_lines(&brokk_root, &String::from_utf8(brokk.stdout).unwrap());

    assert_eq!(expected, bifrost.files);
}

#[test]
fn matches_brokk_reference_for_architect_agent_test_seed() {
    let brokk_root = PathBuf::from("/home/jonathan/Projects/brokk");
    if !brokk_root.is_dir() {
        eprintln!("skipping brokk parity regression: sibling repo not present");
        return;
    }

    let seed = "app/src/test/java/ai/brokk/agents/ArchitectAgentTest.java";
    let project = Arc::new(FilesystemProject::new(&brokk_root).unwrap());
    let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
    let bifrost = most_relevant_files(
        workspace.analyzer(),
        MostRelevantFilesParams {
            seed_files: vec![seed.to_string()],
            limit: 100,
        },
    );
    assert!(bifrost.not_found.is_empty());

    let brokk = Command::new("./gradlew")
        .arg("-q")
        .arg(":app:runMostRelevantFiles")
        .arg(format!("-Pargs=--root {} {}", brokk_root.display(), seed))
        .current_dir(&brokk_root)
        .output()
        .unwrap();
    assert!(
        brokk.status.success(),
        "{}",
        String::from_utf8_lossy(&brokk.stderr)
    );
    let expected = brokk_cli_result_lines(&brokk_root, &String::from_utf8(brokk.stdout).unwrap());

    assert_eq!(expected, bifrost.files);
}
