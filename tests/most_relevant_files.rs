mod common;

use brokk_bifrost::{
    FilesystemProject, GoAnalyzer, ImportAnalysisProvider, JavaAnalyzer, Language, ProjectFile,
    TestProject,
    searchtools::{MostRelevantFilesParams, most_relevant_files},
};
use common::InlineTestProject;
use git2::{Repository, Signature};
use std::fs;
use std::path::Path;
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
            seed_file_paths: vec!["test/A.java".to_string()],
            seed_weights: None,
            limit: 5,
        },
    )
    .unwrap();

    assert!(results.not_found.is_empty());
    assert!(!results.files.contains(&"test/A.java".to_string()));
    assert!(results.files.contains(&"test/B.java".to_string()));
    assert!(results.files.contains(&"test/C.java".to_string()));
}

#[test]
fn go_stdlib_import_does_not_resolve_internal_package_by_last_segment() {
    let temp = TempDir::new().unwrap();
    let root = temp.path();
    write_file(
        root,
        "go.mod",
        r#"
        module example.com/demo

        go 1.23
        "#,
    );
    write_file(
        root,
        "context.go",
        r#"
        package demo

        import "io/fs"

        type Context struct {
            FS fs.FS
        }
        "#,
    );
    write_file(
        root,
        "internal/fs/fs.go",
        r#"
        package fs

        type FileSystem struct{}
        "#,
    );
    write_file(
        root,
        "internal/fs/fs_test.go",
        r#"
        package fs

        import "testing"

        func TestFileSystem(t *testing.T) {}
        "#,
    );

    let project = Arc::new(FilesystemProject::new(root).unwrap());
    let analyzer = GoAnalyzer::new(project);
    let context = ProjectFile::new(root.to_path_buf(), "context.go");
    let internal_fs = ProjectFile::new(root.to_path_buf(), "internal/fs/fs.go");
    let internal_fs_test = ProjectFile::new(root.to_path_buf(), "internal/fs/fs_test.go");

    let imported = analyzer.imported_code_units_of(&context);
    assert!(
        imported
            .iter()
            .all(|code_unit| code_unit.source() != &internal_fs
                && code_unit.source() != &internal_fs_test),
        "stdlib import io/fs should not resolve to project internal/fs: {:?}",
        imported
            .iter()
            .map(|code_unit| code_unit.source().rel_path().display().to_string())
            .collect::<Vec<_>>()
    );

    let referencing = analyzer.referencing_files_of(&internal_fs);
    assert!(
        !referencing.contains(&context),
        "context.go should not reverse-reference internal/fs/fs.go via io/fs"
    );
}

#[test]
fn repo_root_go_seed_is_resolved_and_ranked() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "go.mod",
            r#"
            module example.com/demo

            go 1.23
            "#,
        )
        .file(
            "context.go",
            r#"
            package demo

            import "example.com/demo/internal/engine"

            type Context struct {
                engine *engine.Engine
            }
            "#,
        )
        .file(
            "internal/engine/engine.go",
            r#"
            package engine

            import "example.com/demo/internal/config"

            type Engine struct {
                Config config.Config
            }
            "#,
        )
        .file(
            "internal/config/config.go",
            r#"
            package config

            type Config struct {
                Name string
            }
            "#,
        )
        .build();

    let analyzer = GoAnalyzer::new(Arc::new(FilesystemProject::new(project.root()).unwrap()));
    let results = most_relevant_files(
        &analyzer,
        MostRelevantFilesParams {
            seed_file_paths: vec!["context.go".to_string()],
            seed_weights: None,
            limit: 5,
        },
    )
    .unwrap();

    assert!(results.not_found.is_empty(), "{:?}", results.not_found);
    assert_eq!("internal/engine/engine.go", results.files[0]);
    assert!(
        results
            .files
            .contains(&"internal/config/config.go".to_string())
    );
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
            seed_file_paths: vec!["test/A.java".to_string()],
            seed_weights: None,
            limit: 3,
        },
    )
    .unwrap();

    assert_eq!(3, results.files.len());
    assert_eq!("test/D.java", results.files[0]);
    assert!(results.files.contains(&"test/B.java".to_string()));
    assert!(results.files.contains(&"test/C.java".to_string()));
}

#[test]
fn multi_seed_ranking_merges_shared_targets_without_duplicates() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "test/LeftSeed.java",
            r#"
            package test;
            import test.SharedTarget;
            import test.LeftOnly;
            public class LeftSeed { }
            "#,
        )
        .file(
            "test/RightSeed.java",
            r#"
            package test;
            import test.SharedTarget;
            import test.RightOnly;
            public class RightSeed { }
            "#,
        )
        .file(
            "test/SharedTarget.java",
            r#"
            package test;
            import test.SharedLeaf;
            public class SharedTarget { }
            "#,
        )
        .file(
            "test/LeftOnly.java",
            "package test; public class LeftOnly { }",
        )
        .file(
            "test/RightOnly.java",
            "package test; public class RightOnly { }",
        )
        .file(
            "test/SharedLeaf.java",
            "package test; public class SharedLeaf { }",
        )
        .build();

    let analyzer = java_analyzer(project.root());
    let results = most_relevant_files(
        &analyzer,
        MostRelevantFilesParams {
            seed_file_paths: vec![
                "test/LeftSeed.java".to_string(),
                "test/RightSeed.java".to_string(),
            ],
            seed_weights: None,
            limit: 4,
        },
    )
    .unwrap();

    assert!(results.not_found.is_empty(), "{:?}", results.not_found);
    assert_eq!("test/SharedTarget.java", results.files[0]);
    assert_eq!(
        1,
        results
            .files
            .iter()
            .filter(|path| *path == "test/SharedTarget.java")
            .count()
    );
    assert!(results.files.contains(&"test/LeftOnly.java".to_string()));
    assert!(results.files.contains(&"test/RightOnly.java".to_string()));
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
            seed_file_paths: vec!["test/A.java".to_string()],
            seed_weights: None,
            limit: 2,
        },
    )
    .unwrap();

    assert_eq!(vec!["test/B.java", "test/C.java"], results.files);
}

#[test]
fn git_ties_are_sorted_by_normalized_path_name() {
    let temp = TempDir::new().unwrap();
    let root = temp.path();
    write_file(root, "Seed.java", "public class Seed { }");
    write_file(
        root,
        "AnthropicAgentWithPromptCaching.java",
        "public class AnthropicAgentWithPromptCaching { }",
    );
    write_file(
        root,
        "AutoGenAnthropicSample.java",
        "public class AutoGenAnthropicSample { }",
    );
    write_file(
        root,
        "CreateAnthropicAgent.java",
        "public class CreateAnthropicAgent { }",
    );

    let repo = Repository::init(root).unwrap();
    commit_paths(
        &repo,
        "single tied change",
        &[
            "Seed.java",
            "AnthropicAgentWithPromptCaching.java",
            "AutoGenAnthropicSample.java",
            "CreateAnthropicAgent.java",
        ],
        &[],
    );

    let analyzer = java_analyzer(root);
    let results = most_relevant_files(
        &analyzer,
        MostRelevantFilesParams {
            seed_file_paths: vec!["Seed.java".to_string()],
            seed_weights: None,
            limit: 3,
        },
    )
    .unwrap();

    assert_eq!(
        vec![
            "AnthropicAgentWithPromptCaching.java",
            "AutoGenAnthropicSample.java",
            "CreateAnthropicAgent.java",
        ],
        results.files
    );
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
            seed_file_paths: vec!["test/A.java".to_string()],
            seed_weights: None,
            limit: 2,
        },
    )
    .unwrap();

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
            seed_file_paths: vec!["UserService.java".to_string()],
            seed_weights: None,
            limit: 10,
        },
    )
    .unwrap();

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
    commit_paths(
        &repo,
        "initial",
        &["Seed.java", "OldA.java", "OldB.java"],
        &[],
    );

    fs::write(
        root.join("Seed.java"),
        "public class Seed { int use() { return 1; } }",
    )
    .unwrap();
    fs::write(
        root.join("OldA.java"),
        "public class OldA { int value() { return 10; } }",
    )
    .unwrap();
    commit_paths(
        &repo,
        "seed cochanges with old a",
        &["Seed.java", "OldA.java"],
        &[],
    );

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
            seed_file_paths: vec!["Seed.java".to_string()],
            seed_weights: None,
            limit: 10,
        },
    )
    .unwrap();

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
            seed_file_paths: vec!["missing.java".to_string(), "test/A.java".to_string()],
            seed_weights: None,
            limit: 5,
        },
    )
    .unwrap();

    assert_eq!(vec!["missing.java".to_string()], results.not_found);
    assert!(results.files.is_empty());
}

#[test]
fn weighted_seeds_change_import_ranking() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "test/AlphaSeed.java",
            r#"
            package test;
            import test.AlphaTarget;
            public class AlphaSeed { }
            "#,
        )
        .file(
            "test/ZetaSeed.java",
            r#"
            package test;
            import test.ZetaTarget;
            public class ZetaSeed { }
            "#,
        )
        .file(
            "test/AlphaTarget.java",
            "package test; public class AlphaTarget { }",
        )
        .file(
            "test/ZetaTarget.java",
            "package test; public class ZetaTarget { }",
        )
        .build();

    let analyzer = java_analyzer(project.root());
    let unweighted = most_relevant_files(
        &analyzer,
        MostRelevantFilesParams {
            seed_file_paths: vec![
                "test/AlphaSeed.java".to_string(),
                "test/ZetaSeed.java".to_string(),
            ],
            seed_weights: None,
            limit: 2,
        },
    )
    .unwrap();
    let weighted = most_relevant_files(
        &analyzer,
        MostRelevantFilesParams {
            seed_file_paths: vec![
                "test/AlphaSeed.java".to_string(),
                "test/ZetaSeed.java".to_string(),
            ],
            seed_weights: Some(vec![1.0, 10.0]),
            limit: 2,
        },
    )
    .unwrap();

    assert_eq!("test/AlphaTarget.java", unweighted.files[0]);
    assert_eq!("test/ZetaTarget.java", weighted.files[0]);
}

#[test]
fn invalid_seed_weights_are_rejected() {
    let temp = TempDir::new().unwrap();
    let root = temp.path();
    write_file(root, "test/A.java", "package test; public class A { }");

    let analyzer = java_analyzer(root);
    let error = most_relevant_files(
        &analyzer,
        MostRelevantFilesParams {
            seed_file_paths: vec!["test/A.java".to_string()],
            seed_weights: Some(vec![1.0, 2.0]),
            limit: 5,
        },
    )
    .unwrap_err();

    assert!(error.contains("seed_weights length"), "{error}");
}

#[test]
fn duplicate_resolved_seeds_fail_before_ranking() {
    let temp = TempDir::new().unwrap();
    let root = temp.path();
    write_file(root, "test/A.java", "package test; public class A { }");
    write_file(root, "test/B.java", "package test; public class B { }");

    let analyzer = java_analyzer(root);
    let results = most_relevant_files(
        &analyzer,
        MostRelevantFilesParams {
            seed_file_paths: vec!["test/A.java".to_string(), "./test/A.java".to_string()],
            seed_weights: Some(vec![1.0, 2.0]),
            limit: 5,
        },
    )
    .unwrap();

    assert!(results.files.is_empty());
    assert_eq!(vec!["test/A.java".to_string()], results.duplicates);
}

#[test]
fn recency_weighting_prefers_recent_cochange_targets() {
    let temp = TempDir::new().unwrap();
    let root = temp.path();
    write_file(root, "Seed.java", "public class Seed { }");
    write_file(root, "OldTarget.java", "public class OldTarget { }");
    write_file(root, "RecentTarget.java", "public class RecentTarget { }");

    let repo = Repository::init(root).unwrap();
    commit_paths(&repo, "initial seed", &["Seed.java"], &[]);
    commit_paths(&repo, "add old target", &["OldTarget.java"], &[]);

    fs::write(
        root.join("Seed.java"),
        "public class Seed { int oldUse() { return 1; } }",
    )
    .unwrap();
    fs::write(
        root.join("OldTarget.java"),
        "public class OldTarget { int value() { return 1; } }",
    )
    .unwrap();
    commit_paths(&repo, "old cochange", &["Seed.java", "OldTarget.java"], &[]);

    commit_paths(&repo, "add recent target", &["RecentTarget.java"], &[]);
    fs::write(
        root.join("Seed.java"),
        "public class Seed { int recentUse() { return 2; } }",
    )
    .unwrap();
    fs::write(
        root.join("RecentTarget.java"),
        "public class RecentTarget { int value() { return 2; } }",
    )
    .unwrap();
    commit_paths(
        &repo,
        "recent cochange",
        &["Seed.java", "RecentTarget.java"],
        &[],
    );

    let analyzer = java_analyzer(root);
    let results = most_relevant_files(
        &analyzer,
        MostRelevantFilesParams {
            seed_file_paths: vec!["Seed.java".to_string()],
            seed_weights: None,
            limit: 2,
        },
    )
    .unwrap();

    assert_eq!("RecentTarget.java", results.files[0], "{:?}", results.files);
}
