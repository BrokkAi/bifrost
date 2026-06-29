use git2::Repository;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

#[test]
fn run_subcommand_executes_all_configured_scenarios_on_local_repo() {
    let temp = TempDir::new().expect("temp dir");
    let repo_root = temp.path().join("fixture-repo");
    copy_dir_recursively(&fixture_root(), &repo_root).expect("copy fixture repo");
    init_git_repo(&repo_root);

    let manifest_dir = temp.path().join("manifest");
    fs::create_dir_all(&manifest_dir).expect("manifest dir");
    let manifest_path = manifest_dir.join("benchmark.toml");
    fs::write(
        &manifest_path,
        format!(
            r#"
warmup_iterations = 1
measured_iterations = 1
output_dir = "out"
repo_cache_dir = "cache"
required_languages = ["java"]
required_scenarios = [
  "workspace_build",
  "search_symbols",
  "get_symbol_locations",
  "get_symbol_ancestors",
  "get_summaries",
  "most_relevant_files",
  "scan_usages",
  "get_definition",
  "call_hierarchy",
  "type_hierarchy",
]

[[repos]]
name = "fixture-java"
url = "{}"
commit = "{}"
languages = ["java"]
extensions = ["java"]
scenarios = [
  "workspace_build",
  "search_symbols",
  "get_symbol_locations",
  "get_symbol_ancestors",
  "get_summaries",
  "most_relevant_files",
  "scan_usages",
  "get_definition",
  "call_hierarchy",
  "type_hierarchy",
]
search_patterns = ["method2"]
location_symbols = ["A.method2"]
ancestor_symbols = ["XExtendsY"]
summary_targets = ["A.java"]
seed_file_paths = ["A.java"]
usage_symbols = ["E.iMethod"]
definition_queries = [
  {{ path = "A.java", line = 8, column = 19, expected_status = "no_definition" }},
]
call_hierarchy_queries = [
  {{ path = "E.java", line = 10, column = 17, min_incoming = 1 }},
]
type_hierarchy_queries = [
  {{ path = "XExtendsY.java", line = 1, column = 14, min_supertypes = 1 }},
]
"#,
            toml_basic_string(&repo_root.display().to_string()),
            head_commit(&repo_root)
        ),
    )
    .expect("write manifest");

    let output = Command::new(env!("CARGO_BIN_EXE_bifrost_benchmark"))
        .arg("run")
        .arg("--manifest")
        .arg(&manifest_path)
        .env(
            "BIFROST_BENCHMARK_BIFROST_BIN",
            env!("CARGO_BIN_EXE_bifrost"),
        )
        .output()
        .expect("run bifrost_benchmark");

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = single_json_file(&manifest_dir.join("out"));
    let report: Value =
        serde_json::from_str(&fs::read_to_string(report_path).expect("read report"))
            .expect("parse report");
    let scenarios = report["repos"][0]["scenarios"]
        .as_array()
        .expect("scenario array");
    assert_eq!(scenarios.len(), 10, "report: {report}");
    for scenario in scenarios {
        assert_eq!(scenario["success"], true, "report: {report}");
    }

    let names = scenarios
        .iter()
        .map(|scenario| scenario["name"].as_str().unwrap_or_default())
        .collect::<Vec<_>>();
    assert!(names.contains(&"workspace_build"), "report: {report}");
    assert!(names.contains(&"search_symbols"), "report: {report}");
    assert!(names.contains(&"get_symbol_locations"), "report: {report}");
    assert!(names.contains(&"get_symbol_ancestors"), "report: {report}");
    assert!(names.contains(&"get_summaries"), "report: {report}");
    assert!(names.contains(&"most_relevant_files"), "report: {report}");
    assert!(names.contains(&"scan_usages"), "report: {report}");
    assert!(names.contains(&"get_definition"), "report: {report}");
    assert!(names.contains(&"call_hierarchy"), "report: {report}");
    assert!(names.contains(&"type_hierarchy"), "report: {report}");
}

#[test]
fn run_subcommand_supports_max_files_subset_mode() {
    let temp = TempDir::new().expect("temp dir");
    let repo_root = temp.path().join("fixture-repo");
    copy_dir_recursively(&fixture_root(), &repo_root).expect("copy fixture repo");
    init_git_repo(&repo_root);

    let manifest_dir = temp.path().join("manifest");
    fs::create_dir_all(&manifest_dir).expect("manifest dir");
    let manifest_path = manifest_dir.join("benchmark.toml");
    fs::write(
        &manifest_path,
        format!(
            r#"
warmup_iterations = 1
measured_iterations = 1
output_dir = "out"
repo_cache_dir = "cache"
required_languages = ["java"]
required_scenarios = [
  "workspace_build",
  "search_symbols",
  "get_symbol_locations",
  "get_summaries",
  "scan_usages",
  "get_definition",
]

[[repos]]
name = "fixture-java"
url = "{}"
commit = "{}"
languages = ["java"]
extensions = ["java"]
scenarios = [
  "workspace_build",
  "search_symbols",
  "get_symbol_locations",
  "get_summaries",
  "scan_usages",
  "get_definition",
]
search_patterns = ["method2"]
location_symbols = ["A.method2"]
summary_targets = ["A.java"]
seed_file_paths = ["B.java"]
usage_targets = [
  {{ path = "A.java", line = 8, column = 19 }},
]
definition_queries = [
  {{ path = "E.java", line = 10, column = 17, expected_status = "no_definition" }},
]
"#,
            toml_basic_string(&repo_root.display().to_string()),
            head_commit(&repo_root)
        ),
    )
    .expect("write manifest");

    let output = Command::new(env!("CARGO_BIN_EXE_bifrost_benchmark"))
        .arg("run")
        .arg("--manifest")
        .arg(&manifest_path)
        .arg("--max-files")
        .arg("3")
        .env(
            "BIFROST_BENCHMARK_BIFROST_BIN",
            env!("CARGO_BIN_EXE_bifrost"),
        )
        .output()
        .expect("run bifrost_benchmark");

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = single_json_file(&manifest_dir.join("out"));
    let report: Value =
        serde_json::from_str(&fs::read_to_string(report_path).expect("read report"))
            .expect("parse report");
    assert_eq!(report["max_files"], 3, "report: {report}");
    assert_eq!(
        report["repos"][0]["subset_max_files"], 3,
        "report: {report}"
    );
    assert_ne!(
        report["repos"][0]["checkout_path"], report["repos"][0]["workspace_path"],
        "report: {report}"
    );

    let scenarios = report["repos"][0]["scenarios"]
        .as_array()
        .expect("scenario array");
    assert_eq!(scenarios.len(), 6, "report: {report}");
    for scenario in scenarios {
        assert_eq!(scenario["success"], true, "report: {report}");
    }
}

#[test]
fn run_subcommand_accepts_degraded_get_summaries_compact_symbols() {
    let temp = TempDir::new().expect("temp dir");
    let repo_root = temp.path().join("fixture-repo");
    copy_dir_recursively(&fixture_root(), &repo_root).expect("copy fixture repo");
    fs::write(repo_root.join("LargeSummary.java"), large_java_file()).expect("write large file");
    init_git_repo(&repo_root);

    let manifest_dir = temp.path().join("manifest");
    fs::create_dir_all(&manifest_dir).expect("manifest dir");
    let manifest_path = manifest_dir.join("benchmark.toml");
    fs::write(
        &manifest_path,
        format!(
            r#"
warmup_iterations = 1
measured_iterations = 1
output_dir = "out"
repo_cache_dir = "cache"
required_languages = ["java"]
required_scenarios = [
  "get_summaries",
]

[[repos]]
name = "fixture-java"
url = "{}"
commit = "{}"
languages = ["java"]
extensions = ["java"]
scenarios = [
  "get_summaries",
]
summary_targets = ["LargeSummary.java"]
"#,
            toml_basic_string(&repo_root.display().to_string()),
            head_commit(&repo_root)
        ),
    )
    .expect("write manifest");

    let output = Command::new(env!("CARGO_BIN_EXE_bifrost_benchmark"))
        .arg("run")
        .arg("--manifest")
        .arg(&manifest_path)
        .env(
            "BIFROST_BENCHMARK_BIFROST_BIN",
            env!("CARGO_BIN_EXE_bifrost"),
        )
        .output()
        .expect("run bifrost_benchmark");

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = single_json_file(&manifest_dir.join("out"));
    let report: Value =
        serde_json::from_str(&fs::read_to_string(report_path).expect("read report"))
            .expect("parse report");
    let scenario = &report["repos"][0]["scenarios"][0];
    assert_eq!(scenario["name"], "get_summaries", "report: {report}");
    assert_eq!(scenario["success"], true, "report: {report}");
}

#[test]
fn run_subcommand_subset_mode_preserves_most_relevant_files_signal() {
    let temp = TempDir::new().expect("temp dir");
    let repo_root = temp.path().join("fixture-repo");
    copy_dir_recursively(&fixture_root(), &repo_root).expect("copy fixture repo");
    init_git_repo(&repo_root);

    let manifest_dir = temp.path().join("manifest");
    fs::create_dir_all(&manifest_dir).expect("manifest dir");
    let manifest_path = manifest_dir.join("benchmark.toml");
    fs::write(
        &manifest_path,
        format!(
            r#"
warmup_iterations = 1
measured_iterations = 1
output_dir = "out"
repo_cache_dir = "cache"
required_languages = ["java"]
required_scenarios = [
  "workspace_build",
  "search_symbols",
  "get_symbol_locations",
  "get_summaries",
  "most_relevant_files",
  "scan_usages",
  "get_definition",
]

[[repos]]
name = "fixture-java"
url = "{}"
commit = "{}"
languages = ["java"]
extensions = ["java"]
scenarios = [
  "workspace_build",
  "search_symbols",
  "get_symbol_locations",
  "get_summaries",
  "most_relevant_files",
  "scan_usages",
  "get_definition",
]
search_patterns = ["method2"]
location_symbols = ["A.method2"]
summary_targets = ["A.java"]
seed_file_paths = ["A.java"]
usage_symbols = ["A.method2"]
definition_queries = [
  {{ path = "A.java", line = 8, column = 19, expected_status = "no_definition" }},
]
"#,
            toml_basic_string(&repo_root.display().to_string()),
            head_commit(&repo_root)
        ),
    )
    .expect("write manifest");

    let output = Command::new(env!("CARGO_BIN_EXE_bifrost_benchmark"))
        .arg("run")
        .arg("--manifest")
        .arg(&manifest_path)
        .arg("--max-files")
        .arg("10")
        .env(
            "BIFROST_BENCHMARK_BIFROST_BIN",
            env!("CARGO_BIN_EXE_bifrost"),
        )
        .output()
        .expect("run bifrost_benchmark");

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = single_json_file(&manifest_dir.join("out"));
    let report: Value =
        serde_json::from_str(&fs::read_to_string(report_path).expect("read report"))
            .expect("parse report");
    let scenarios = report["repos"][0]["scenarios"]
        .as_array()
        .expect("scenario array");
    let most_relevant = scenarios
        .iter()
        .find(|scenario| scenario["name"] == "most_relevant_files")
        .expect("most_relevant_files scenario");
    assert_eq!(most_relevant["success"], true, "report: {report}");
}

#[test]
fn run_subcommand_writes_failure_report_without_aborting_following_scenarios() {
    let temp = TempDir::new().expect("temp dir");
    let repo_root = temp.path().join("fixture-repo");
    copy_dir_recursively(&fixture_root(), &repo_root).expect("copy fixture repo");
    init_git_repo(&repo_root);

    let manifest_dir = temp.path().join("manifest");
    fs::create_dir_all(&manifest_dir).expect("manifest dir");
    let manifest_path = manifest_dir.join("benchmark.toml");
    fs::write(
        &manifest_path,
        format!(
            r#"
warmup_iterations = 1
measured_iterations = 1
output_dir = "out"
repo_cache_dir = "cache"
required_languages = ["java"]
required_scenarios = [
  "workspace_build",
  "get_symbol_locations",
  "scan_usages",
  "get_definition",
]

[[repos]]
name = "fixture-java"
url = "{}"
commit = "{}"
languages = ["java"]
extensions = ["java"]
scenarios = [
  "workspace_build",
  "get_symbol_locations",
  "scan_usages",
  "get_definition",
]
location_symbols = ["does.not.Exist"]
usage_symbols = ["E.iMethod"]
definition_queries = [
  {{ path = "A.java", line = 8, column = 19, expected_status = "no_definition" }},
]
"#,
            toml_basic_string(&repo_root.display().to_string()),
            head_commit(&repo_root)
        ),
    )
    .expect("write manifest");

    let output = Command::new(env!("CARGO_BIN_EXE_bifrost_benchmark"))
        .arg("run")
        .arg("--manifest")
        .arg(&manifest_path)
        .env(
            "BIFROST_BENCHMARK_BIFROST_BIN",
            env!("CARGO_BIN_EXE_bifrost"),
        )
        .output()
        .expect("run bifrost_benchmark");

    assert!(
        !output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = single_json_file(&manifest_dir.join("out"));
    let report: Value =
        serde_json::from_str(&fs::read_to_string(report_path).expect("read report"))
            .expect("parse report");
    let scenarios = report["repos"][0]["scenarios"]
        .as_array()
        .expect("scenario array");
    assert_eq!(scenarios.len(), 4, "report: {report}");

    let failing = scenarios
        .iter()
        .find(|scenario| scenario["name"] == "get_symbol_locations")
        .expect("get_symbol_locations scenario");
    assert_eq!(failing["success"], false, "report: {report}");
    assert!(
        failing["failure_message"]
            .as_str()
            .unwrap_or_default()
            .contains("returned no locations"),
        "report: {report}"
    );

    let surviving = scenarios
        .iter()
        .find(|scenario| scenario["name"] == "scan_usages")
        .expect("scan_usages scenario");
    assert_eq!(surviving["success"], true, "report: {report}");

    let later_definition = scenarios
        .iter()
        .find(|scenario| scenario["name"] == "get_definition")
        .expect("get_definition scenario");
    assert_eq!(later_definition["success"], true, "report: {report}");
}

#[test]
fn run_subcommand_accepts_get_definition_expected_fqn_for_supported_language() {
    let temp = TempDir::new().expect("temp dir");
    let repo_root = temp.path().join("fixture-rust");
    fs::create_dir_all(&repo_root).expect("repo root");
    fs::write(
        repo_root.join("lib.rs"),
        "pub fn helper() {}\n\npub fn run() {\n    helper();\n}\n",
    )
    .expect("write rust fixture");
    init_git_repo(&repo_root);

    let manifest_dir = temp.path().join("manifest");
    fs::create_dir_all(&manifest_dir).expect("manifest dir");
    let manifest_path = manifest_dir.join("benchmark.toml");
    fs::write(
        &manifest_path,
        format!(
            r#"
warmup_iterations = 1
measured_iterations = 1
output_dir = "out"
repo_cache_dir = "cache"
required_languages = ["rust"]
required_scenarios = [
  "get_definition",
]

[[repos]]
name = "fixture-rust"
url = "{}"
commit = "{}"
languages = ["rust"]
extensions = ["rs"]
scenarios = [
  "get_definition",
]
definition_queries = [
  {{ path = "lib.rs", line = 4, column = 5, expected_status = "resolved", expected_fqn = "helper" }},
]
"#,
            toml_basic_string(&repo_root.display().to_string()),
            head_commit(&repo_root)
        ),
    )
    .expect("write manifest");

    let output = Command::new(env!("CARGO_BIN_EXE_bifrost_benchmark"))
        .arg("run")
        .arg("--manifest")
        .arg(&manifest_path)
        .env(
            "BIFROST_BENCHMARK_BIFROST_BIN",
            env!("CARGO_BIN_EXE_bifrost"),
        )
        .output()
        .expect("run bifrost_benchmark");

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = single_json_file(&manifest_dir.join("out"));
    let report: Value =
        serde_json::from_str(&fs::read_to_string(report_path).expect("read report"))
            .expect("parse report");
    let scenario = &report["repos"][0]["scenarios"][0];
    assert_eq!(scenario["name"], "get_definition", "report: {report}");
    assert_eq!(scenario["success"], true, "report: {report}");
}

#[test]
fn run_subcommand_fails_get_definition_on_expected_status_mismatch() {
    let temp = TempDir::new().expect("temp dir");
    let repo_root = temp.path().join("fixture-repo");
    copy_dir_recursively(&fixture_root(), &repo_root).expect("copy fixture repo");
    init_git_repo(&repo_root);

    let manifest_dir = temp.path().join("manifest");
    fs::create_dir_all(&manifest_dir).expect("manifest dir");
    let manifest_path = manifest_dir.join("benchmark.toml");
    fs::write(
        &manifest_path,
        format!(
            r#"
warmup_iterations = 1
measured_iterations = 1
output_dir = "out"
repo_cache_dir = "cache"
required_languages = ["java"]
required_scenarios = [
  "get_definition",
  "search_symbols",
]

[[repos]]
name = "fixture-java"
url = "{}"
commit = "{}"
languages = ["java"]
extensions = ["java"]
scenarios = [
  "get_definition",
  "search_symbols",
]
definition_queries = [
  {{ path = "A.java", line = 8, column = 19, expected_status = "resolved", expected_fqn = "A.method2" }},
]
search_patterns = ["method2"]
"#,
            toml_basic_string(&repo_root.display().to_string()),
            head_commit(&repo_root)
        ),
    )
    .expect("write manifest");

    let output = Command::new(env!("CARGO_BIN_EXE_bifrost_benchmark"))
        .arg("run")
        .arg("--manifest")
        .arg(&manifest_path)
        .env(
            "BIFROST_BENCHMARK_BIFROST_BIN",
            env!("CARGO_BIN_EXE_bifrost"),
        )
        .output()
        .expect("run bifrost_benchmark");

    assert!(
        !output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = single_json_file(&manifest_dir.join("out"));
    let report: Value =
        serde_json::from_str(&fs::read_to_string(report_path).expect("read report"))
            .expect("parse report");
    let scenarios = report["repos"][0]["scenarios"]
        .as_array()
        .expect("scenario array");
    let failing = scenarios
        .iter()
        .find(|scenario| scenario["name"] == "get_definition")
        .expect("get_definition scenario");
    assert_eq!(failing["success"], false, "report: {report}");
    assert!(
        failing["failure_message"]
            .as_str()
            .unwrap_or_default()
            .contains("expected status `resolved` but got `no_definition`"),
        "report: {report}"
    );

    let surviving = scenarios
        .iter()
        .find(|scenario| scenario["name"] == "search_symbols")
        .expect("search_symbols scenario");
    assert_eq!(surviving["success"], true, "report: {report}");
}

#[test]
fn run_subcommand_fails_get_definition_on_expected_fqn_mismatch() {
    let temp = TempDir::new().expect("temp dir");
    let repo_root = temp.path().join("fixture-rust");
    fs::create_dir_all(&repo_root).expect("repo root");
    fs::write(
        repo_root.join("lib.rs"),
        "pub fn helper() {}\n\npub fn run() {\n    helper();\n}\n",
    )
    .expect("write rust fixture");
    init_git_repo(&repo_root);

    let manifest_dir = temp.path().join("manifest");
    fs::create_dir_all(&manifest_dir).expect("manifest dir");
    let manifest_path = manifest_dir.join("benchmark.toml");
    fs::write(
        &manifest_path,
        format!(
            r#"
warmup_iterations = 1
measured_iterations = 1
output_dir = "out"
repo_cache_dir = "cache"
required_languages = ["rust"]
required_scenarios = [
  "get_definition",
]

[[repos]]
name = "fixture-rust"
url = "{}"
commit = "{}"
languages = ["rust"]
extensions = ["rs"]
scenarios = [
  "get_definition",
]
definition_queries = [
  {{ path = "lib.rs", line = 4, column = 5, expected_status = "resolved", expected_fqn = "wrong.helper" }},
]
"#,
            toml_basic_string(&repo_root.display().to_string()),
            head_commit(&repo_root)
        ),
    )
    .expect("write manifest");

    let output = Command::new(env!("CARGO_BIN_EXE_bifrost_benchmark"))
        .arg("run")
        .arg("--manifest")
        .arg(&manifest_path)
        .env(
            "BIFROST_BENCHMARK_BIFROST_BIN",
            env!("CARGO_BIN_EXE_bifrost"),
        )
        .output()
        .expect("run bifrost_benchmark");

    assert!(
        !output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = single_json_file(&manifest_dir.join("out"));
    let report: Value =
        serde_json::from_str(&fs::read_to_string(report_path).expect("read report"))
            .expect("parse report");
    let failing = &report["repos"][0]["scenarios"][0];
    assert_eq!(failing["name"], "get_definition", "report: {report}");
    assert_eq!(failing["success"], false, "report: {report}");
    assert!(
        failing["failure_message"]
            .as_str()
            .unwrap_or_default()
            .contains("expected fqn `wrong.helper` but got `helper`"),
        "report: {report}"
    );
}

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java")
}

fn copy_dir_recursively(source: &Path, destination: &Path) -> Result<(), std::io::Error> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let target = destination.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_recursively(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

fn init_git_repo(root: &Path) {
    let repo = Repository::init(root).expect("init git repo");
    let mut index = repo.index().expect("repo index");
    index
        .add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)
        .expect("add all");
    index.write().expect("write index");
    let tree_id = index.write_tree().expect("write tree");
    let tree = repo.find_tree(tree_id).expect("find tree");
    let signature = git2::Signature::now("Test User", "test@example.com").expect("signature");
    repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
        .expect("commit");
}

fn head_commit(root: &Path) -> String {
    let repo = Repository::open(root).expect("open repo");
    repo.head()
        .expect("head")
        .target()
        .expect("target")
        .to_string()
}

fn single_json_file(dir: &Path) -> PathBuf {
    let files = fs::read_dir(dir)
        .expect("read output dir")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect::<Vec<_>>();
    assert_eq!(files.len(), 1, "expected one JSON report file in {dir:?}");
    files[0].clone()
}

fn toml_basic_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn large_java_file() -> String {
    let mut source = String::from("public class LargeSummary {\n");
    for index in 0..300 {
        source.push_str(&format!(
            "    public String method{index}(String input) {{ return \"method{index}_\" + input; }}\n"
        ));
    }
    source.push_str("}\n");
    source
}
