use crate::common::InlineTestProject;
use brokk_bifrost::{
    CSharpAnalyzer, CppAnalyzer, FilesystemProject, GoAnalyzer, ImportAnalysisProvider,
    JavaAnalyzer, Language, ProjectFile, RustAnalyzer, TestProject,
    searchtools::{
        ClassifyTestFilesParams, MostRelevantFilesParams, MostRelevantFilesRankingMode,
        MostRelevantFilesResult, TestFileKind, classify_test_files, most_relevant_files,
    },
};
use git2::{Repository, Signature};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;

/// Ranked paths only, for the assertions that are about ranking rather than the
/// per-file test classification each entry now carries (#1575).
fn paths(result: &MostRelevantFilesResult) -> Vec<String> {
    result.files.iter().map(|file| file.path.clone()).collect()
}

fn write_file(root: &Path, rel_path: &str, contents: &str) -> ProjectFile {
    let file = ProjectFile::new(root.to_path_buf(), rel_path);
    file.write(contents).unwrap();
    file
}

fn cpp_analyzer(root: &Path) -> CppAnalyzer {
    CppAnalyzer::from_project(TestProject::new(root.to_path_buf(), Language::Cpp))
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
            recency_half_life: Some(250.0),
            ranking_mode: Default::default(),
            limit: 5,
        },
    )
    .unwrap();

    assert!(results.not_found.is_empty());
    assert!(!paths(&results).contains(&"test/A.java".to_string()));
    assert!(paths(&results).contains(&"test/B.java".to_string()));
    assert!(paths(&results).contains(&"test/C.java".to_string()));
}

#[test]
fn csharp_namespace_imports_rank_related_files_without_git() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Consumer.cs",
            r#"
            using Demo.Services;

            namespace Demo.App;

            public class Consumer
            {
                private readonly Service service;
            }
            "#,
        )
        .file(
            "Services/Service.cs",
            r#"
            namespace Demo.Services;

            public class Service { }
            "#,
        )
        .file(
            "Other.cs",
            r#"
            namespace Demo.Other;

            public class Other { }
            "#,
        )
        .build();

    let analyzer = CSharpAnalyzer::from_project(project.project().clone());
    let results = most_relevant_files(
        &analyzer,
        MostRelevantFilesParams {
            seed_file_paths: vec!["Consumer.cs".to_string()],
            seed_weights: None,
            recency_half_life: Some(250.0),
            ranking_mode: Default::default(),
            limit: 5,
        },
    )
    .unwrap();

    assert!(results.not_found.is_empty());
    assert!(paths(&results).contains(&"Services/Service.cs".to_string()));
    assert!(!paths(&results).contains(&"Consumer.cs".to_string()));
    assert!(!paths(&results).contains(&"Other.cs".to_string()));
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
            recency_half_life: Some(250.0),
            ranking_mode: Default::default(),
            limit: 5,
        },
    )
    .unwrap();

    assert!(results.not_found.is_empty(), "{:?}", results.not_found);
    assert_eq!("internal/engine/engine.go", paths(&results)[0]);
    assert!(paths(&results).contains(&"internal/config/config.go".to_string()));
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
            recency_half_life: Some(250.0),
            ranking_mode: Default::default(),
            limit: 3,
        },
    )
    .unwrap();

    assert_eq!(3, results.files.len());
    assert_eq!("test/D.java", paths(&results)[0]);
    assert!(paths(&results).contains(&"test/B.java".to_string()));
    assert!(paths(&results).contains(&"test/C.java".to_string()));
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
            recency_half_life: Some(250.0),
            ranking_mode: Default::default(),
            limit: 4,
        },
    )
    .unwrap();

    assert!(results.not_found.is_empty(), "{:?}", results.not_found);
    assert_eq!("test/SharedTarget.java", paths(&results)[0]);
    assert_eq!(
        1,
        results
            .files
            .iter()
            .filter(|file| file.path == "test/SharedTarget.java")
            .count()
    );
    assert!(paths(&results).contains(&"test/LeftOnly.java".to_string()));
    assert!(paths(&results).contains(&"test/RightOnly.java".to_string()));
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
            recency_half_life: Some(250.0),
            ranking_mode: Default::default(),
            limit: 2,
        },
    )
    .unwrap();

    assert_eq!(vec!["test/B.java", "test/C.java"], paths(&results));
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
            recency_half_life: Some(250.0),
            ranking_mode: Default::default(),
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
        paths(&results)
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
            recency_half_life: Some(250.0),
            ranking_mode: Default::default(),
            limit: 2,
        },
    )
    .unwrap();

    assert_eq!(2, results.files.len());
    assert!(paths(&results).contains(&"test/B.java".to_string()));
    assert!(paths(&results).contains(&"test/C.java".to_string()));
    assert!(!paths(&results).contains(&"test/A.java".to_string()));
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
            recency_half_life: Some(250.0),
            ranking_mode: Default::default(),
            limit: 10,
        },
    )
    .unwrap();

    assert!(paths(&results).contains(&"Account.java".to_string()));
    assert!(!paths(&results).contains(&"A.java".to_string()));
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
            recency_half_life: Some(250.0),
            ranking_mode: Default::default(),
            limit: 10,
        },
    )
    .unwrap();

    assert!(
        !paths(&results).contains(&"New.java".to_string()),
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
            recency_half_life: Some(250.0),
            ranking_mode: Default::default(),
            limit: 5,
        },
    )
    .unwrap();

    assert_eq!(
        vec!["missing.java".to_string()],
        results
            .not_found
            .iter()
            .map(|item| item.input.clone())
            .collect::<Vec<_>>()
    );
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
            recency_half_life: Some(250.0),
            ranking_mode: Default::default(),
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
            recency_half_life: Some(250.0),
            ranking_mode: Default::default(),
            limit: 2,
        },
    )
    .unwrap();

    assert_eq!("test/AlphaTarget.java", paths(&unweighted)[0]);
    assert_eq!("test/ZetaTarget.java", paths(&weighted)[0]);
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
            recency_half_life: Some(250.0),
            ranking_mode: Default::default(),
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
            recency_half_life: Some(250.0),
            ranking_mode: Default::default(),
            limit: 5,
        },
    )
    .unwrap();

    assert!(results.files.is_empty());
    assert_eq!(vec!["test/A.java".to_string()], results.duplicates);
}

#[test]
fn invalid_recency_half_life_is_rejected() {
    let temp = TempDir::new().unwrap();
    let root = temp.path();
    write_file(root, "test/A.java", "package test; public class A { }");

    let analyzer = java_analyzer(root);
    let error = most_relevant_files(
        &analyzer,
        MostRelevantFilesParams {
            seed_file_paths: vec!["test/A.java".to_string()],
            seed_weights: None,
            recency_half_life: Some(0.0),
            ranking_mode: Default::default(),
            limit: 5,
        },
    )
    .unwrap_err();

    assert!(error.contains("recency_half_life"), "{error}");
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
            recency_half_life: Some(250.0),
            ranking_mode: Default::default(),
            limit: 2,
        },
    )
    .unwrap();

    assert_eq!(
        "RecentTarget.java",
        paths(&results)[0],
        "{:?}",
        results.files
    );
}

#[test]
fn recency_half_life_none_pins_legacy_uniform_behavior() {
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
            recency_half_life: None,
            ranking_mode: Default::default(),
            limit: 2,
        },
    )
    .unwrap();

    assert_eq!("OldTarget.java", paths(&results)[0], "{:?}", results.files);
}

#[test]
fn usage_mode_prefers_resolved_calls_and_respects_edge_weights() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "test/Seed.java",
            r#"
            package test;
            import test.ImportOnly;
            import test.SingleUse;
            import test.WeightedUse;
            public class Seed {
                void run() {
                    WeightedUse.work();
                    WeightedUse.work();
                    SingleUse.work();
                }
            }
            "#,
        )
        .file(
            "test/WeightedUse.java",
            "package test; public class WeightedUse { static void work() {} }",
        )
        .file(
            "test/SingleUse.java",
            "package test; public class SingleUse { static void work() {} }",
        )
        .file(
            "test/ImportOnly.java",
            "package test; public class ImportOnly {}",
        )
        .build();
    let analyzer = java_analyzer(project.root());

    let results = most_relevant_files(
        &analyzer,
        MostRelevantFilesParams {
            seed_file_paths: vec!["test/Seed.java".to_string()],
            seed_weights: None,
            recency_half_life: Some(250.0),
            ranking_mode: MostRelevantFilesRankingMode::UsageGraphExact,
            limit: 3,
        },
    )
    .unwrap();

    assert!(results.complete);
    assert_eq!(
        MostRelevantFilesRankingMode::UsageGraphExact,
        results.ranking_mode_used
    );
    assert_eq!(None, results.incomplete_reason);
    assert_eq!("test/WeightedUse.java", paths(&results)[0]);
    assert_eq!("test/SingleUse.java", paths(&results)[1]);
    assert_eq!("test/ImportOnly.java", paths(&results)[2]);
}

#[test]
fn usage_mode_uses_the_fast_file_graph_and_exact_mode_keeps_symbol_weights() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "test/Seed.java",
            r#"
            package test;
            import test.AImportOnly;
            import test.ZCalled;
            public class Seed {
                void run() {
                    ZCalled.work();
                    ZCalled.work();
                }
            }
            "#,
        )
        .file(
            "test/AImportOnly.java",
            "package test; public class AImportOnly {}",
        )
        .file(
            "test/ZCalled.java",
            "package test; public class ZCalled { static void work() {} }",
        )
        .build();
    let analyzer = java_analyzer(project.root());
    let params = |ranking_mode| MostRelevantFilesParams {
        seed_file_paths: vec!["test/Seed.java".to_string()],
        seed_weights: None,
        recency_half_life: Some(250.0),
        ranking_mode,
        limit: 1,
    };

    let fast =
        most_relevant_files(&analyzer, params(MostRelevantFilesRankingMode::UsageGraph)).unwrap();
    let exact = most_relevant_files(
        &analyzer,
        params(MostRelevantFilesRankingMode::UsageGraphExact),
    )
    .unwrap();

    assert_eq!(vec!["test/AImportOnly.java"], paths(&fast));
    assert_eq!(vec!["test/ZCalled.java"], paths(&exact));
    assert_eq!(
        MostRelevantFilesRankingMode::UsageGraph,
        fast.ranking_mode_used
    );
    assert_eq!(
        MostRelevantFilesRankingMode::UsageGraphExact,
        exact.ranking_mode_used
    );
}

#[test]
fn fast_usage_mode_resolves_rust_imports_without_exact_symbol_edges() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "pub mod dependency;\npub mod seed;\n")
        .file(
            "src/seed.rs",
            "use crate::dependency::Thing;\npub fn seed(_: Thing) {}\n",
        )
        .file("src/dependency.rs", "pub struct Thing;\n")
        .build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());

    let results = most_relevant_files(
        &analyzer,
        MostRelevantFilesParams {
            seed_file_paths: vec!["src/seed.rs".to_string()],
            seed_weights: None,
            recency_half_life: Some(250.0),
            ranking_mode: MostRelevantFilesRankingMode::UsageGraph,
            limit: 1,
        },
    )
    .unwrap();

    assert_eq!(vec!["src/dependency.rs"], paths(&results));
}

#[test]
fn fast_usage_mode_maps_rust_crate_names_from_manifests() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "crates/app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "crates/app/src/lib.rs",
            "use brokk_dependency::Thing;\npub fn seed(_: Thing) {}\n",
        )
        .file(
            "crates/dependency/Cargo.toml",
            "[package]\nname = \"brokk-dependency\"\nversion = \"0.1.0\"\n",
        )
        .file("crates/dependency/src/lib.rs", "pub struct Thing;\n")
        .build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    let seed = project.file("crates/app/src/lib.rs");
    let imports = analyzer.import_info_of(&seed);
    let imported_files = analyzer
        .imported_files_from_infos(&seed, &imports)
        .expect("Rust exposes coarse import files");
    assert!(
        imported_files.contains(&project.file("crates/dependency/src/lib.rs")),
        "imports={imports:?} imported_files={imported_files:?}"
    );

    let results = most_relevant_files(
        &analyzer,
        MostRelevantFilesParams {
            seed_file_paths: vec!["crates/app/src/lib.rs".to_string()],
            seed_weights: None,
            recency_half_life: Some(250.0),
            ranking_mode: MostRelevantFilesRankingMode::UsageGraph,
            limit: 1,
        },
    )
    .unwrap();

    assert_eq!(vec!["crates/dependency/src/lib.rs"], paths(&results));
}

#[test]
fn usage_rank_flows_from_caller_to_callee_not_backward() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "test/Seed.java",
            "package test; public class Seed { static void run() { Callee.work(); } }",
        )
        .file(
            "test/Callee.java",
            "package test; public class Callee { static void work() {} }",
        )
        .file(
            "test/Caller.java",
            "package test; public class Caller { void invoke() { Seed.run(); } }",
        )
        .build();
    let analyzer = java_analyzer(project.root());

    let results = most_relevant_files(
        &analyzer,
        MostRelevantFilesParams {
            seed_file_paths: vec!["test/Seed.java".to_string()],
            seed_weights: None,
            recency_half_life: Some(250.0),
            ranking_mode: MostRelevantFilesRankingMode::UsageGraphExact,
            limit: 1,
        },
    )
    .unwrap();

    assert_eq!(vec!["test/Callee.java"], paths(&results));
}

#[test]
fn usage_mode_combines_seed_weights_and_same_file_symbol_scores_deterministically() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "test/LeftSeed.java",
            "package test; public class LeftSeed { void run() { Shared.first(); } }",
        )
        .file(
            "test/RightSeed.java",
            "package test; public class RightSeed { void run() { Shared.second(); Other.work(); } }",
        )
        .file(
            "test/Shared.java",
            "package test; public class Shared { static void first() {} static void second() {} }",
        )
        .file(
            "test/Other.java",
            "package test; public class Other { static void work() {} }",
        )
        .build();
    let analyzer = java_analyzer(project.root());

    let params = MostRelevantFilesParams {
        seed_file_paths: vec![
            "test/LeftSeed.java".to_string(),
            "test/RightSeed.java".to_string(),
        ],
        seed_weights: Some(vec![1.0, 3.0]),
        recency_half_life: Some(250.0),
        ranking_mode: MostRelevantFilesRankingMode::UsageGraphExact,
        limit: 2,
    };
    let first = most_relevant_files(&analyzer, params.clone()).unwrap();
    let second = most_relevant_files(&analyzer, params).unwrap();

    assert_eq!(first.files, second.files);
    assert_eq!("test/Shared.java", paths(&first)[0]);
    assert_eq!("test/Other.java", paths(&first)[1]);
}

#[test]
fn usage_mode_fills_from_legacy_and_falls_back_for_unmapped_seed() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "test/Seed.java",
            "package test; import test.ImportOnly; public class Seed { void run() { Called.work(); } }",
        )
        .file(
            "test/Called.java",
            "package test; public class Called { static void work() {} }",
        )
        .file(
            "test/ImportOnly.java",
            "package test; public class ImportOnly {}",
        )
        .file("resources/seed.txt", "seed")
        .file(
            "resources/Imported.java",
            "package resources; public class Imported {}",
        )
        .build();
    let repo = Repository::init(project.root()).unwrap();
    commit_paths(
        &repo,
        "resource seed and fallback",
        &["resources/seed.txt", "resources/Imported.java"],
        &[],
    );
    let analyzer = java_analyzer(project.root());

    let filled = most_relevant_files(
        &analyzer,
        MostRelevantFilesParams {
            seed_file_paths: vec!["test/Seed.java".to_string()],
            seed_weights: None,
            recency_half_life: Some(250.0),
            ranking_mode: MostRelevantFilesRankingMode::UsageGraphExact,
            limit: 2,
        },
    )
    .unwrap();
    assert_eq!(
        vec!["test/Called.java", "test/ImportOnly.java"],
        paths(&filled)
    );
    assert_eq!(
        filled.files.len(),
        paths(&filled).into_iter().collect::<HashSet<_>>().len()
    );

    let default = most_relevant_files(
        &analyzer,
        MostRelevantFilesParams {
            seed_file_paths: vec!["resources/seed.txt".to_string()],
            seed_weights: None,
            recency_half_life: Some(250.0),
            ranking_mode: MostRelevantFilesRankingMode::HistoryImports,
            limit: 3,
        },
    )
    .unwrap();
    let usage = most_relevant_files(
        &analyzer,
        MostRelevantFilesParams {
            seed_file_paths: vec!["resources/seed.txt".to_string()],
            seed_weights: None,
            recency_half_life: Some(250.0),
            ranking_mode: MostRelevantFilesRankingMode::UsageGraphExact,
            limit: 3,
        },
    )
    .unwrap();
    assert_eq!(default.files, usage.files);
    assert_eq!(vec!["resources/Imported.java"], paths(&usage));
}

#[test]
fn usage_mode_does_not_promote_a_truncated_callee() {
    let mut seed = String::from("package test; public class Seed { void run() {\nNormal.work();\n");
    for _ in 0..=1000 {
        seed.push_str("Hot.work();\n");
    }
    seed.push_str("} }");

    let project = InlineTestProject::with_language(Language::Java)
        .file("test/Seed.java", seed)
        .file(
            "test/Normal.java",
            "package test; public class Normal { static void work() {} }",
        )
        .file(
            "test/Hot.java",
            "package test; public class Hot { static void work() {} }",
        )
        .build();
    let analyzer = java_analyzer(project.root());
    let results = most_relevant_files(
        &analyzer,
        MostRelevantFilesParams {
            seed_file_paths: vec!["test/Seed.java".to_string()],
            seed_weights: None,
            recency_half_life: Some(250.0),
            ranking_mode: MostRelevantFilesRankingMode::UsageGraphExact,
            limit: 1,
        },
    )
    .unwrap();

    assert_eq!(vec!["test/Normal.java"], paths(&results));
}

/// The request carries no test policy at all any more (#1575): a bare seed list
/// is a complete request, and the verdict travels with each ranked file.
#[test]
fn most_relevant_files_params_need_only_seed_paths() {
    let params: MostRelevantFilesParams = serde_json::from_value(serde_json::json!({
        "seed_file_paths": ["Seed.java"]
    }))
    .unwrap();

    assert_eq!(vec!["Seed.java".to_string()], params.seed_file_paths);
}

/// #1575: ranking no longer applies a test policy. It reports the same verdict
/// `classify_test_files` gives, and a caller that wants production code
/// over-fetches and filters. The mixed file pins why the boolean had to go: it
/// is `Ambiguous`, so neither "drop it" nor "keep it" is right for every caller.
#[test]
fn usage_mode_labels_ranked_files_so_callers_can_apply_a_test_policy() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/main/java/app/Seed.java",
            r#"
            package app;
            public class Seed {
                void run() {
                    HotTest.work();
                    HotTest.work();
                    Helper.work();
                    Helper.work();
                    Helper.work();
                    ProductionNeighbor.work();
                    MixedChecks.work();
                }
            }
            "#,
        )
        .file(
            "tests/HotTest.java",
            "package app; public class HotTest { @Test void testWork() {} static void work() {} }",
        )
        .file(
            "tests/Helper.java",
            "package app; public class Helper { static void work() {} }",
        )
        .file(
            "src/main/java/app/ProductionNeighbor.java",
            "package app; public class ProductionNeighbor { static void work() {} }",
        )
        .file(
            "other/MixedChecks.java",
            "package app; public class MixedChecks { @Test void mixed() {} static void work() {} }",
        )
        .build();
    let analyzer = java_analyzer(project.root());
    let classifications = classify_test_files(
        &analyzer,
        ClassifyTestFilesParams {
            file_paths: vec![
                "tests/HotTest.java".to_string(),
                "tests/Helper.java".to_string(),
                "src/main/java/app/ProductionNeighbor.java".to_string(),
                "other/MixedChecks.java".to_string(),
            ],
        },
    );
    assert_eq!(
        classifications.classifications["tests/HotTest.java"].kind,
        TestFileKind::Test
    );
    assert_eq!(
        classifications.classifications["tests/Helper.java"].kind,
        TestFileKind::TestSupport
    );
    assert_eq!(
        classifications.classifications["src/main/java/app/ProductionNeighbor.java"].kind,
        TestFileKind::Production
    );
    assert_eq!(
        classifications.classifications["other/MixedChecks.java"].kind,
        TestFileKind::Ambiguous
    );

    let top_two = most_relevant_files(
        &analyzer,
        MostRelevantFilesParams {
            seed_file_paths: vec!["src/main/java/app/Seed.java".to_string()],
            seed_weights: None,
            recency_half_life: Some(250.0),
            ranking_mode: MostRelevantFilesRankingMode::UsageGraphExact,
            limit: 2,
        },
    )
    .unwrap();
    // `limit` is exactly `limit` now, and this fixture ranks both test files
    // above the production ones, so a caller asking for two gets two labelled
    // test files rather than a silently widened search.
    assert_eq!(
        vec![
            ("tests/Helper.java".to_string(), TestFileKind::TestSupport),
            ("tests/HotTest.java".to_string(), TestFileKind::Test),
        ],
        {
            let mut labelled: Vec<_> = top_two
                .files
                .iter()
                .map(|file| (file.path.clone(), file.test))
                .collect();
            labelled.sort_by(|left, right| left.0.cmp(&right.0));
            labelled
        },
        "{top_two:#?}"
    );

    let over_fetched = most_relevant_files(
        &analyzer,
        MostRelevantFilesParams {
            seed_file_paths: vec!["src/main/java/app/Seed.java".to_string()],
            seed_weights: None,
            recency_half_life: Some(250.0),
            ranking_mode: MostRelevantFilesRankingMode::UsageGraphExact,
            limit: 4,
        },
    )
    .unwrap();
    let non_test: Vec<String> = over_fetched
        .files
        .iter()
        .filter(|file| !matches!(file.test, TestFileKind::Test | TestFileKind::TestSupport))
        .map(|file| file.path.clone())
        .collect();
    assert_eq!(
        vec![
            "other/MixedChecks.java".to_string(),
            "src/main/java/app/ProductionNeighbor.java".to_string(),
        ],
        non_test,
        "{over_fetched:#?}"
    );
}

/// Issue #1575, the reported repro in miniature. Dovecot names its tests
/// `test-<unit>.c`, a spelling the classifier had no vocabulary for, so those
/// files used to reach a caller with no way to tell them from production code.
/// The production sibling pins the degenerate half of the same bug: a C project
/// has no `src/main` convention, so its production files can only ever be
/// `Ambiguous`, and a server-side "no tests" filter would have had to guess.
#[test]
fn c_test_naming_convention_is_reported_on_ranked_files() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "src/lib/test-lib.h",
            "#pragma once\nvoid test_begin(const char *name);\nvoid test_end(void);\n",
        )
        .file(
            "src/lib/istream.h",
            "#pragma once\nstruct istream { int fd; };\nint i_stream_read(struct istream *stream);\n",
        )
        .file(
            "src/lib/test-istream-concat.c",
            "#include \"test-lib.h\"\n#include \"istream.h\"\n\nvoid test_istream_concat(void) {\n    struct istream stream;\n    test_begin(\"istream concat\");\n    i_stream_read(&stream);\n    test_end();\n}\n",
        )
        .build();
    let analyzer = cpp_analyzer(project.root());

    let results = most_relevant_files(
        &analyzer,
        MostRelevantFilesParams {
            seed_file_paths: vec!["src/lib/test-istream-concat.c".to_string()],
            seed_weights: None,
            recency_half_life: Some(250.0),
            ranking_mode: MostRelevantFilesRankingMode::HistoryImports,
            limit: 10,
        },
    )
    .unwrap();

    let kind_of = |path: &str| {
        results
            .files
            .iter()
            .find(|file| file.path == path)
            .map(|file| file.test)
    };
    assert!(
        matches!(
            kind_of("src/lib/test-lib.h"),
            Some(TestFileKind::Test | TestFileKind::TestSupport)
        ),
        "{results:#?}"
    );
    assert_eq!(
        Some(TestFileKind::Ambiguous),
        kind_of("src/lib/istream.h"),
        "{results:#?}"
    );
}

/// Issue #1575's acceptance criterion, on the ranking leg that surfaced it: a
/// `test-*.c` that co-changes with the seed still comes back -- ranking does not
/// hide it -- but it now arrives labelled, which is what makes the caller's
/// filter possible.
#[test]
fn c_test_file_co_changing_with_the_seed_is_ranked_and_labelled() {
    let temp = TempDir::new().unwrap();
    let root = temp.path();
    write_file(
        root,
        "src/lib/istream-concat.c",
        "int i_stream_concat_read(void) {\n    return 0;\n}\n",
    );
    write_file(
        root,
        "src/lib/test-istream-concat.c",
        "void test_istream_concat(void) {\n    i_stream_concat_read();\n}\n",
    );
    write_file(
        root,
        "src/lib/unrelated.c",
        "int unrelated(void) {\n    return 1;\n}\n",
    );

    let repo = Repository::init(root).unwrap();
    commit_paths(&repo, "unrelated", &["src/lib/unrelated.c"], &[]);
    commit_paths(
        &repo,
        "concat stream and its test",
        &["src/lib/istream-concat.c", "src/lib/test-istream-concat.c"],
        &[],
    );

    let analyzer = cpp_analyzer(root);
    let results = most_relevant_files(
        &analyzer,
        MostRelevantFilesParams {
            seed_file_paths: vec!["src/lib/istream-concat.c".to_string()],
            seed_weights: None,
            recency_half_life: Some(250.0),
            ranking_mode: MostRelevantFilesRankingMode::HistoryImports,
            limit: 5,
        },
    )
    .unwrap();

    let co_changed = results
        .files
        .iter()
        .find(|file| file.path == "src/lib/test-istream-concat.c")
        .unwrap_or_else(|| panic!("co-changed test file must still be ranked: {results:#?}"));
    assert!(
        matches!(
            co_changed.test,
            TestFileKind::Test | TestFileKind::TestSupport
        ),
        "{results:#?}"
    );
}

/// Fixture shaped like `boa-dev/boa`'s lexer (issue #1546): the module file
/// declares its sibling test module with `#[cfg(test)] mod tests;`, so the
/// test-ness of `src/lexer/tests.rs` lives on the *parent's* declaration and is
/// invisible both to the path conventions (`Language::Rust` has no test
/// filename convention) and to the file's own directory segments.
///
/// The co-change history mirrors the reported repro, where the lexer module and
/// its sibling test module land in the same commits.
fn rust_sibling_test_module_repo(lexer_mod_declaration: &str) -> TempDir {
    let temp = TempDir::new().unwrap();
    let root = temp.path().to_path_buf();
    write_file(
        &root,
        "Cargo.toml",
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\npath = \"src/lib.rs\"\n",
    );
    write_file(&root, "src/lib.rs", "pub mod lexer;\n");
    write_file(
        &root,
        "src/lexer/mod.rs",
        &format!(
            r#"
{lexer_mod_declaration}

pub mod cursor;

pub fn tokenize(input: &str) -> usize {{
    cursor::advance(input)
}}
"#
        ),
    );
    // The production sibling carries an *inline* `#[cfg(test)] mod`, the shape
    // that must stay production (#1102): the gate taints the declarations it
    // encloses, never the file.
    write_file(
        &root,
        "src/lexer/cursor.rs",
        r#"
pub fn advance(input: &str) -> usize {
    input.len()
}

#[cfg(test)]
mod inline_checks {
    use super::advance;

    #[test]
    fn advances() {
        assert_eq!(2, advance("ab"));
    }
}
"#,
    );
    write_file(
        &root,
        "src/lexer/tests.rs",
        r#"
use super::tokenize;

pub fn check_single_line_comment(input: &str) -> usize {
    tokenize(input)
}

#[test]
fn regex_literal() {
    assert_eq!(2, check_single_line_comment("ab"));
}
"#,
    );

    let repo = Repository::init(&root).unwrap();
    commit_paths(
        &repo,
        "lexer and its sibling test module",
        &[
            "src/lib.rs",
            "src/lexer/mod.rs",
            "src/lexer/cursor.rs",
            "src/lexer/tests.rs",
        ],
        &[],
    );

    temp
}

fn rust_analyzer(root: &Path) -> brokk_bifrost::RustAnalyzer {
    brokk_bifrost::RustAnalyzer::from_project(TestProject::new(root.to_path_buf(), Language::Rust))
}

/// The kind ranking reports for `path`, or `None` when it was not ranked.
fn ranked_kind(analyzer: &brokk_bifrost::RustAnalyzer, path: &str) -> Option<TestFileKind> {
    most_relevant_files(
        analyzer,
        MostRelevantFilesParams {
            seed_file_paths: vec!["src/lexer/mod.rs".to_string()],
            seed_weights: None,
            recency_half_life: Some(250.0),
            ranking_mode: MostRelevantFilesRankingMode::HistoryImports,
            limit: 10,
        },
    )
    .unwrap()
    .files
    .iter()
    .find(|file| file.path == path)
    .map(|file| file.test)
}

#[test]
fn rust_cfg_test_sibling_module_is_ranked_as_a_test_file() {
    let temp = rust_sibling_test_module_repo("#[cfg(test)]\nmod tests;");
    let analyzer = rust_analyzer(temp.path());

    // The test-ness lives on the parent's `#[cfg(test)] mod tests;`
    // declaration (#1546), so nothing in the path says "test". Ranking still
    // has to report it, because that is what lets a caller drop it.
    assert_eq!(
        Some(TestFileKind::Test),
        ranked_kind(&analyzer, "src/lexer/tests.rs")
    );
    assert_eq!(
        Some(TestFileKind::Ambiguous),
        ranked_kind(&analyzer, "src/lexer/cursor.rs")
    );
}

/// Near-miss, pinning existing behavior (#1102): `src/lexer/cursor.rs` holds an
/// inline `#[cfg(test)] mod inline_checks { .. }`. That gates the declarations
/// it encloses, not the file, so the file stays production. Nearly every
/// production file in this repository has that shape.
#[test]
fn rust_inline_cfg_test_module_leaves_the_declaring_file_production() {
    let temp = rust_sibling_test_module_repo("#[cfg(test)]\nmod tests;");
    let analyzer = rust_analyzer(temp.path());

    assert_eq!(
        Some(TestFileKind::Ambiguous),
        ranked_kind(&analyzer, "src/lexer/cursor.rs"),
        "a production file with an inline test module must not be labelled a test"
    );

    let classifications = classify_test_files(
        &analyzer,
        ClassifyTestFilesParams {
            file_paths: vec!["src/lexer/cursor.rs".to_string()],
        },
    );
    assert_eq!(
        TestFileKind::Ambiguous,
        classifications.classifications["src/lexer/cursor.rs"].kind
    );
}

#[test]
fn rust_cfg_test_sibling_module_classifies_as_test() {
    let temp = rust_sibling_test_module_repo("#[cfg(test)]\nmod tests;");
    let analyzer = rust_analyzer(temp.path());

    let classifications = classify_test_files(
        &analyzer,
        ClassifyTestFilesParams {
            file_paths: vec![
                "src/lexer/tests.rs".to_string(),
                "src/lexer/cursor.rs".to_string(),
                "src/lexer/mod.rs".to_string(),
            ],
        },
    );

    assert_eq!(
        TestFileKind::Test,
        classifications.classifications["src/lexer/tests.rs"].kind
    );
    assert_eq!(
        TestFileKind::Ambiguous,
        classifications.classifications["src/lexer/cursor.rs"].kind
    );
    assert_eq!(
        TestFileKind::Ambiguous,
        classifications.classifications["src/lexer/mod.rs"].kind,
        "the declaring module keeps its own production identity"
    );
}

/// Near-miss: an un-gated `mod tests;` is ordinary production code. This repo's
/// own `crates/bifrost-analysis/src/analyzer/rust/tests.rs` has exactly that
/// shape, so a `tests.rs` filename heuristic would wrongly hide it.
#[test]
fn rust_ungated_sibling_tests_module_stays_production() {
    let temp = rust_sibling_test_module_repo("mod tests;");
    let analyzer = rust_analyzer(temp.path());

    assert_eq!(
        Some(TestFileKind::Ambiguous),
        ranked_kind(&analyzer, "src/lexer/tests.rs"),
        "an un-gated `mod tests;` target is production code"
    );

    let classifications = classify_test_files(
        &analyzer,
        ClassifyTestFilesParams {
            file_paths: vec!["src/lexer/tests.rs".to_string()],
        },
    );
    assert_eq!(
        TestFileKind::Ambiguous,
        classifications.classifications["src/lexer/tests.rs"].kind
    );
}

/// Near-miss: only a *bare* `#[cfg(test)]` gates the edge. A composite
/// predicate can compile into a non-test build (this repository itself uses
/// `cfg(any(test, feature = "test-support"))` for shared fixtures), so the
/// target file stays production.
#[test]
fn rust_composite_cfg_predicate_does_not_mark_the_sibling_module_test_only() {
    let temp =
        rust_sibling_test_module_repo("#[cfg(any(test, feature = \"test-support\"))]\nmod tests;");
    let analyzer = rust_analyzer(temp.path());

    assert_eq!(
        Some(TestFileKind::Ambiguous),
        ranked_kind(&analyzer, "src/lexer/tests.rs"),
        "a composite cfg predicate must not gate the module edge"
    );
}
