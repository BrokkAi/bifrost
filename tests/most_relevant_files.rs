use brokk_analyzer::{
    AnalyzerConfig, FilesystemProject, GoAnalyzer, ImportAnalysisProvider, JavaAnalyzer, Language,
    Project, ProjectFile, TestProject, WorkspaceAnalyzer,
    searchtools::{MostRelevantFilesParams, most_relevant_files},
};
use git2::{Repository, Signature};
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
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

fn brokk_app_root() -> PathBuf {
    env::var("BROKK_APP_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/home/jonathan/Projects/brokk"))
}

fn parity_project_root() -> PathBuf {
    env::var("BROKK_PARITY_PROJECT_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/home/jonathan/Projects/brokk"))
}

fn parity_extensions() -> Option<BTreeSet<String>> {
    let value = env::var("BROKK_PARITY_EXTENSIONS").ok()?;
    let extensions = value
        .split(',')
        .map(|value| value.trim().trim_start_matches('.').to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>();
    (!extensions.is_empty()).then_some(extensions)
}

fn parity_sample_size() -> usize {
    env::var("BROKK_PARITY_SAMPLE_SIZE")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(100)
}

fn parity_language() -> Option<Language> {
    let extensions = parity_extensions()?;
    let mut languages = extensions
        .into_iter()
        .map(|extension| Language::from_extension(&extension))
        .filter(|language| *language != Language::None)
        .collect::<BTreeSet<_>>();
    if languages.len() == 1 {
        languages.pop_first()
    } else {
        None
    }
}

fn parity_brokk_language_name() -> Option<&'static str> {
    match parity_language()? {
        Language::Java => Some("JAVA"),
        Language::Go => Some("GO"),
        Language::Cpp => Some("C_CPP"),
        Language::JavaScript => Some("JAVASCRIPT"),
        Language::TypeScript => Some("TYPESCRIPT"),
        Language::Python => Some("PYTHON"),
        Language::Rust => Some("RUST"),
        Language::Php => Some("PHP"),
        Language::Scala => Some("SCALA"),
        Language::CSharp => Some("C_SHARP"),
        Language::None => None,
    }
}

fn parity_workspace_project(root: &Path) -> Arc<dyn Project> {
    if let Some(language) = parity_language() {
        Arc::new(TestProject::new(root.to_path_buf(), language))
    } else {
        Arc::new(FilesystemProject::new(root).unwrap())
    }
}

fn brokk_cli_direct(brokk_root: &Path, project_root: &Path, seeds: &[String]) -> Vec<String> {
    let classpath = format!("{}/app/build/install/app/lib/*", brokk_root.display());
    let user_home = TempDir::new().unwrap();
    static WARMED_PROJECTS: OnceLock<Mutex<BTreeSet<PathBuf>>> = OnceLock::new();
    let warmed_projects = WARMED_PROJECTS.get_or_init(|| Mutex::new(BTreeSet::new()));
    let use_fresh_start = {
        let mut warmed = warmed_projects.lock().unwrap();
        warmed.insert(project_root.to_path_buf())
    };
    let mut command = Command::new("java");
    command
        .arg(format!("-Duser.home={}", user_home.path().display()))
        .arg("-Djava.awt.headless=true");
    if use_fresh_start {
        command.arg("-Dbrokk.mrf.fresh=true");
    }
    if let Some(language) = parity_brokk_language_name() {
        command.arg(format!("-Dbrokk.mrf.languages={language}"));
    }
    let output = command
        .arg("-cp")
        .arg(classpath)
        .arg("ai.brokk.tools.MostRelevantFilesCli")
        .arg("--root")
        .arg(project_root)
        .args(seeds)
        .current_dir(brokk_root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    brokk_cli_result_lines(project_root, &String::from_utf8(output.stdout).unwrap())
}

fn tracked_files(project_root: &Path) -> Vec<String> {
    let output = Command::new("git")
        .arg("ls-files")
        .current_dir(project_root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

fn parity_seed_files(project_root: &Path) -> Vec<String> {
    let mut files = tracked_files(project_root);
    if let Some(extensions) = parity_extensions() {
        files.retain(|path| {
            Path::new(path)
                .extension()
                .and_then(|extension| extension.to_str())
                .map(|extension| extensions.contains(&extension.to_ascii_lowercase()))
                .unwrap_or(false)
        });
    }
    files
}

fn deterministic_pair_sample(files: &[String], count: usize) -> Vec<[String; 2]> {
    let max_pairs = files.len().saturating_mul(files.len().saturating_sub(1)) / 2;
    let count = count.min(max_pairs);
    let mut state = 0_u64;
    let mut seen = BTreeSet::new();
    let mut pairs = Vec::new();
    while pairs.len() < count {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let left = (state as usize) % files.len();
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let right = (state as usize) % files.len();
        if left == right {
            continue;
        }

        let mut key = [files[left].clone(), files[right].clone()];
        key.sort();
        if !seen.insert(key.clone()) {
            continue;
        }

        pairs.push([files[left].clone(), files[right].clone()]);
    }
    pairs
}

fn mismatch_summary(seeds: &[String], brokk: &[String], bifrost: &[String]) -> String {
    let first_diff = brokk
        .iter()
        .zip(bifrost)
        .position(|(left, right)| left != right)
        .unwrap_or_else(|| brokk.len().min(bifrost.len()));
    format!(
        "seeds={:?} first_diff_rank={} brokk_at_diff={:?} bifrost_at_diff={:?} left_only={:?} right_only={:?}",
        seeds,
        first_diff + 1,
        brokk.get(first_diff),
        bifrost.get(first_diff),
        brokk
            .iter()
            .filter(|file| !bifrost.contains(*file))
            .take(10)
            .cloned()
            .collect::<Vec<_>>(),
        bifrost
            .iter()
            .filter(|file| !brokk.contains(*file))
            .take(10)
            .cloned()
            .collect::<Vec<_>>(),
    )
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
            .all(|code_unit| code_unit.source() != &internal_fs && code_unit.source() != &internal_fs_test),
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
            seed_files: vec!["Seed.java".to_string()],
            limit: 3,
        },
    );

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

#[test]
fn matches_brokk_reference_for_history_store_and_console_logging_pair() {
    let brokk_root = PathBuf::from("/home/jonathan/Projects/brokk");
    if !brokk_root.is_dir() {
        eprintln!("skipping brokk parity regression: sibling repo not present");
        return;
    }

    let seeds = [
        "frontend-mop/src/stores/historyStore.ts",
        "app/src/main/resources/mop-webview-scripts/console-logging-interceptor.js",
    ];
    let project = Arc::new(FilesystemProject::new(&brokk_root).unwrap());
    let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
    let bifrost = most_relevant_files(
        workspace.analyzer(),
        MostRelevantFilesParams {
            seed_files: seeds.iter().map(|seed| (*seed).to_string()).collect(),
            limit: 100,
        },
    );
    assert!(bifrost.not_found.is_empty());

    let brokk = Command::new("./gradlew")
        .arg("-q")
        .arg(":app:runMostRelevantFiles")
        .arg(format!(
            "-Pargs=--root {} {} {}",
            brokk_root.display(),
            seeds[0],
            seeds[1]
        ))
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
fn matches_brokk_reference_for_plume_imports_test2_goal_seed() {
    let project_root = PathBuf::from("/home/jonathan/Projects/plume-merge");
    let brokk_root = brokk_app_root();
    if !brokk_root.is_dir() || !project_root.is_dir() {
        eprintln!("skipping plume parity regression: repo not present");
        return;
    }

    let seed = "src/test/resources/ImportsTest2Goal.java";
    let project = parity_workspace_project(&project_root);
    let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
    let bifrost = most_relevant_files(
        workspace.analyzer(),
        MostRelevantFilesParams {
            seed_files: vec![seed.to_string()],
            limit: 100,
        },
    );
    assert!(bifrost.not_found.is_empty());

    let expected = brokk_cli_direct(&brokk_root, &project_root, &[seed.to_string()]);
    assert_eq!(expected, bifrost.files);
}

#[test]
fn matches_brokk_reference_for_plume_imports_test8_base_seed() {
    let project_root = PathBuf::from("/home/jonathan/Projects/plume-merge");
    let brokk_root = brokk_app_root();
    if !brokk_root.is_dir() || !project_root.is_dir() {
        eprintln!("skipping plume parity regression: repo not present");
        return;
    }

    let seed = "src/test/resources/ImportsTest8Base.java";
    let project = parity_workspace_project(&project_root);
    let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
    let bifrost = most_relevant_files(
        workspace.analyzer(),
        MostRelevantFilesParams {
            seed_files: vec![seed.to_string()],
            limit: 100,
        },
    );
    assert!(bifrost.not_found.is_empty());

    let expected = brokk_cli_direct(&brokk_root, &project_root, &[seed.to_string()]);
    assert_eq!(expected, bifrost.files);
}

#[test]
fn matches_brokk_reference_for_autogen_checker_seed() {
    let project_root = PathBuf::from("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen");
    let brokk_root = brokk_app_root();
    if !brokk_root.is_dir() || !project_root.is_dir() {
        eprintln!("skipping autogen parity regression: repo not present");
        return;
    }

    let seed = "dotnet/samples/GettingStarted/Checker.cs";
    let project = Arc::new(FilesystemProject::new(&project_root).unwrap());
    let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
    let bifrost = most_relevant_files(
        workspace.analyzer(),
        MostRelevantFilesParams {
            seed_files: vec![seed.to_string()],
            limit: 100,
        },
    );
    assert!(bifrost.not_found.is_empty());

    let expected = brokk_cli_direct(&brokk_root, &project_root, &[seed.to_string()]);
    assert_eq!(expected, bifrost.files);
}

#[test]
fn matches_brokk_reference_for_autogen_hello_ai_agents_program_seed() {
    let project_root = PathBuf::from("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen");
    let brokk_root = brokk_app_root();
    if !brokk_root.is_dir() || !project_root.is_dir() {
        eprintln!("skipping autogen parity regression: repo not present");
        return;
    }

    let seed = "dotnet/samples/Hello/HelloAIAgents/Program.cs";
    let project = Arc::new(FilesystemProject::new(&project_root).unwrap());
    let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
    let bifrost = most_relevant_files(
        workspace.analyzer(),
        MostRelevantFilesParams {
            seed_files: vec![seed.to_string()],
            limit: 100,
        },
    );
    assert!(bifrost.not_found.is_empty());

    let expected = brokk_cli_direct(&brokk_root, &project_root, &[seed.to_string()]);
    assert_eq!(expected, bifrost.files);
}

#[test]
fn matches_brokk_reference_for_autogen_hello_agent_program_seed() {
    let project_root = PathBuf::from("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen");
    let brokk_root = brokk_app_root();
    if !brokk_root.is_dir() || !project_root.is_dir() {
        eprintln!("skipping autogen parity regression: repo not present");
        return;
    }

    let seed = "dotnet/samples/Hello/HelloAgent/Program.cs";
    let project = Arc::new(FilesystemProject::new(&project_root).unwrap());
    let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
    let bifrost = most_relevant_files(
        workspace.analyzer(),
        MostRelevantFilesParams {
            seed_files: vec![seed.to_string()],
            limit: 100,
        },
    );
    assert!(bifrost.not_found.is_empty());

    let expected = brokk_cli_direct(&brokk_root, &project_root, &[seed.to_string()]);
    assert_eq!(expected, bifrost.files);
}

#[test]
fn matches_brokk_reference_for_autogen_topicid_and_inmemoryruntime_pair() {
    let project_root = PathBuf::from("/home/jonathan/Projects/brokkbench/clones/microsoft__autogen");
    let brokk_root = brokk_app_root();
    if !brokk_root.is_dir() || !project_root.is_dir() {
        eprintln!("skipping autogen parity regression: repo not present");
        return;
    }

    let seeds = vec![
        "dotnet/src/Microsoft.AutoGen/Contracts/TopicId.cs".to_string(),
        "dotnet/test/Microsoft.AutoGen.Integration.Tests/InMemoryRuntimeIntegrationTests.cs".to_string(),
    ];
    let project = Arc::new(FilesystemProject::new(&project_root).unwrap());
    let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
    let bifrost = most_relevant_files(
        workspace.analyzer(),
        MostRelevantFilesParams {
            seed_files: seeds.clone(),
            limit: 100,
        },
    );
    assert!(bifrost.not_found.is_empty());

    let expected = brokk_cli_direct(&brokk_root, &project_root, &seeds);
    assert_eq!(expected, bifrost.files);
}

#[test]
fn matches_brokk_reference_for_gin_context_go_seed() {
    let project_root = PathBuf::from("/home/jonathan/Projects/brokkbench/clones/gin-gonic__gin");
    let brokk_root = brokk_app_root();
    if !brokk_root.is_dir() || !project_root.is_dir() {
        eprintln!("skipping gin parity regression: repo not present");
        return;
    }

    let seed = "context.go";
    let project = Arc::new(FilesystemProject::new(&project_root).unwrap());
    let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
    let bifrost = most_relevant_files(
        workspace.analyzer(),
        MostRelevantFilesParams {
            seed_files: vec![seed.to_string()],
            limit: 100,
        },
    );
    assert!(bifrost.not_found.is_empty());

    let expected = brokk_cli_direct(&brokk_root, &project_root, &[seed.to_string()]);
    assert_eq!(expected, bifrost.files);
}

#[test]
fn matches_brokk_reference_for_axios_github_api_seed() {
    let project_root = PathBuf::from("/home/jonathan/Projects/axios");
    let brokk_root = brokk_app_root();
    if !brokk_root.is_dir() || !project_root.is_dir() {
        eprintln!("skipping axios parity regression: repo not present");
        return;
    }

    let seed = "bin/GithubAPI.js";
    let project = Arc::new(FilesystemProject::new(&project_root).unwrap());
    let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
    let bifrost = most_relevant_files(
        workspace.analyzer(),
        MostRelevantFilesParams {
            seed_files: vec![seed.to_string()],
            limit: 100,
        },
    );
    assert!(bifrost.not_found.is_empty());

    let expected = brokk_cli_direct(&brokk_root, &project_root, &[seed.to_string()]);
    assert_eq!(expected, bifrost.files);
}

#[test]
fn matches_brokk_reference_for_vector_similarity_query_result_struct_seed() {
    let project_root = PathBuf::from("/home/jonathan/Projects/VectorSimilarity");
    let brokk_root = brokk_app_root();
    if !brokk_root.is_dir() || !project_root.is_dir() {
        eprintln!("skipping VectorSimilarity parity regression: repo not present");
        return;
    }

    let seed = "src/VecSim/query_result_struct.cpp";
    let project = Arc::new(FilesystemProject::new(&project_root).unwrap());
    let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
    let bifrost = most_relevant_files(
        workspace.analyzer(),
        MostRelevantFilesParams {
            seed_files: vec![seed.to_string()],
            limit: 100,
        },
    );
    assert!(bifrost.not_found.is_empty());

    let expected = brokk_cli_direct(&brokk_root, &project_root, &[seed.to_string()]);
    assert_eq!(expected, bifrost.files);
}

#[test]
#[ignore = "cross-repo parity batch"]
fn matches_brokk_reference_for_100_random_seed_files() {
    let brokk_root = brokk_app_root();
    let project_root = parity_project_root();
    if !brokk_root.is_dir() || !project_root.is_dir() {
        eprintln!("skipping brokk parity regression: sibling repo not present");
        return;
    }

    eprintln!("single batch: building workspace analyzer");
    let project = Arc::new(FilesystemProject::new(&project_root).unwrap());
    let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
    eprintln!("single batch: workspace analyzer ready");
    let sample_size = parity_sample_size();
    let files = parity_seed_files(&project_root);
    let seed_files = files.into_iter().take(sample_size).collect::<Vec<_>>();
    let case_count = seed_files.len();
    assert!(case_count > 0, "no seed files available");
    let mut cases = Vec::new();
    for (index, seed) in seed_files.into_iter().enumerate() {
        let seeds = vec![seed];
        let bifrost = most_relevant_files(
            workspace.analyzer(),
            MostRelevantFilesParams {
                seed_files: seeds.clone(),
                limit: 100,
            },
        );
        assert!(bifrost.not_found.is_empty(), "{:?}", seeds);
        cases.push((index, seeds, bifrost.files));

        let done = index + 1;
        if done == 1 || done % 10 == 0 || done == case_count {
            eprintln!("single precompute progress {}/{}", done, case_count);
        }
    }

    let cases = Arc::new(cases);
    let next = AtomicUsize::new(0);
    let completed = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    let mismatch = Mutex::new(None::<String>);
    let worker_count = thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(4)
        .min(8)
        .max(2);

    thread::scope(|scope| {
        for _ in 0..worker_count {
            let cases = Arc::clone(&cases);
            let brokk_root = brokk_root.clone();
            let project_root = project_root.clone();
            let mismatch = &mismatch;
            let next = &next;
            let completed = &completed;
            let stop = &stop;
            scope.spawn(move || loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }

                let idx = next.fetch_add(1, Ordering::Relaxed);
                let Some((case_index, seeds, bifrost)) = cases.get(idx) else {
                    break;
                };

                let brokk = brokk_cli_direct(&brokk_root, &project_root, seeds);
                if brokk != *bifrost {
                    let mut slot = mismatch.lock().unwrap();
                    if slot.is_none() {
                        *slot = Some(mismatch_summary(seeds, &brokk, bifrost));
                        eprintln!(
                            "single parity mismatch at case {}/{} seeds={:?}",
                            case_index + 1,
                            cases.len(),
                            seeds
                        );
                    }
                    stop.store(true, Ordering::Relaxed);
                    break;
                }

                let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
                if done == 1 || done % 10 == 0 || done == cases.len() {
                    eprintln!("single parity progress {}/{}", done, cases.len());
                }
            });
        }
    });

    let mismatch = mismatch.into_inner().unwrap();
    assert!(
        mismatch.is_none(),
        "single parity mismatch:\n{}",
        mismatch.unwrap()
    );
}

#[test]
#[ignore = "cross-repo parity batch"]
fn matches_brokk_reference_for_100_random_seed_pairs() {
    let brokk_root = brokk_app_root();
    let project_root = parity_project_root();
    if !brokk_root.is_dir() || !project_root.is_dir() {
        eprintln!("skipping brokk parity regression: sibling repo not present");
        return;
    }

    eprintln!("pair batch: building workspace analyzer");
    let project = Arc::new(FilesystemProject::new(&project_root).unwrap());
    let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
    eprintln!("pair batch: workspace analyzer ready");
    let sample_size = parity_sample_size();
    let files = parity_seed_files(&project_root);
    let seed_pairs = deterministic_pair_sample(&files, sample_size);
    let case_count = seed_pairs.len();
    assert!(case_count > 0, "no seed pairs available");
    let mut cases = Vec::new();
    for (index, pair) in seed_pairs.into_iter().enumerate() {
        let seeds = vec![pair[0].clone(), pair[1].clone()];
        let bifrost = most_relevant_files(
            workspace.analyzer(),
            MostRelevantFilesParams {
                seed_files: seeds.clone(),
                limit: 100,
            },
        );
        assert!(bifrost.not_found.is_empty(), "{:?}", seeds);
        cases.push((index, seeds, bifrost.files));

        let done = index + 1;
        if done == 1 || done % 10 == 0 || done == case_count {
            eprintln!("pair precompute progress {}/{}", done, case_count);
        }
    }

    let cases = Arc::new(cases);
    let next = AtomicUsize::new(0);
    let completed = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    let mismatch = Mutex::new(None::<String>);
    let worker_count = thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(4)
        .min(8)
        .max(2);

    thread::scope(|scope| {
        for _ in 0..worker_count {
            let cases = Arc::clone(&cases);
            let brokk_root = brokk_root.clone();
            let project_root = project_root.clone();
            let mismatch = &mismatch;
            let next = &next;
            let completed = &completed;
            let stop = &stop;
            scope.spawn(move || loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }

                let idx = next.fetch_add(1, Ordering::Relaxed);
                let Some((case_index, seeds, bifrost)) = cases.get(idx) else {
                    break;
                };

                let brokk = brokk_cli_direct(&brokk_root, &project_root, seeds);
                if brokk != *bifrost {
                    let mut slot = mismatch.lock().unwrap();
                    if slot.is_none() {
                        *slot = Some(mismatch_summary(seeds, &brokk, bifrost));
                        eprintln!(
                            "pair parity mismatch at case {}/{} seeds={:?}",
                            case_index + 1,
                            cases.len(),
                            seeds
                        );
                    }
                    stop.store(true, Ordering::Relaxed);
                    break;
                }

                let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
                if done == 1 || done % 10 == 0 || done == cases.len() {
                    eprintln!("pair parity progress {}/{}", done, cases.len());
                }
            });
        }
    });

    let mismatch = mismatch.into_inner().unwrap();
    assert!(
        mismatch.is_none(),
        "pair parity mismatch:\n{}",
        mismatch.unwrap()
    );
}
