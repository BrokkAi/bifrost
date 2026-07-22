use git2::Repository;
use serde_json::Value;
#[cfg(unix)]
use serde_json::json;
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
  "dead_code_smells",
  "get_definition",
  "call_hierarchy",
  "type_hierarchy",
  "query_code",
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
  "dead_code_smells",
  "get_definition",
  "call_hierarchy",
  "type_hierarchy",
  "query_code",
]
search_patterns = ["method2"]
location_symbols = ["A.method2"]
ancestor_symbols = ["XExtendsY"]
summary_targets = ["A.java"]
seed_file_paths = ["A.java"]
usage_symbols = ["E.iMethod"]
dead_code_file_paths = ["A.java"]
dead_code_fq_names = ["A.method1"]
dead_code_expect_report_contains = ["Candidate symbols analyzed: 1"]
dead_code_expect_report_absent = ["no definition found", "not yet supported for smell analysis"]
definition_queries = [
  {{ path = "A.java", line = 8, column = 19, expected_status = "no_definition" }},
]
call_hierarchy_queries = [
  {{ path = "E.java", line = 10, column = 17, min_incoming = 1 }},
]
type_hierarchy_queries = [
  {{ path = "XExtendsY.java", line = 1, column = 14, min_supertypes = 1 }},
]
query_code_queries = [
  {{ id = "class-a", workloads = ["exact_name", "warm_reuse"], query_json = '{{"match":{{"kind":"class","name":"A"}},"limit":20}}', expected_witness_json = '{{"result_type":"structural_match","path":"A.java","kind":"class"}}', min_results = 1, expected_truncated = false }},
  {{ id = "broad-classes", workloads = ["broad"], query_json = '{{"match":{{"kind":"class"}},"limit":100}}', expected_witness_json = '{{"result_type":"structural_match","path":"A.java","kind":"class"}}', min_results = 1, expected_truncated = false }},
  {{ id = "regex-class-a", workloads = ["regex"], query_json = '{{"match":{{"kind":"class","name":{{"regex":"^A$"}}}},"limit":20}}', expected_witness_json = '{{"result_type":"structural_match","path":"A.java","kind":"class"}}', min_results = 1, expected_truncated = false }},
  {{ id = "methods-inside-a", workloads = ["containment"], query_json = '{{"match":{{"kind":"method"}},"inside":{{"kind":"class","name":"A"}},"limit":100}}', expected_witness_json = '{{"result_type":"structural_match","path":"A.java","kind":"method"}}', min_results = 1, expected_truncated = false }},
  {{ id = "class-a-file", workloads = ["typed_traversal"], query_json = '{{"match":{{"kind":"class","name":"A"}},"steps":[{{"op":"file_of"}}],"limit":20}}', expected_witness_json = '{{"result_type":"file","path":"A.java"}}', min_results = 1, expected_truncated = false }},
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
    assert_eq!(scenarios.len(), 16, "report: {report}");
    for scenario in scenarios {
        assert_eq!(scenario["success"], true, "report: {report}");
        assert!(
            scenario.get("profile_artifacts").is_none(),
            "profile-disabled reports must not churn: {report}"
        );
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
    assert!(names.contains(&"dead_code_smells"), "report: {report}");
    assert!(names.contains(&"get_definition"), "report: {report}");
    assert!(names.contains(&"call_hierarchy"), "report: {report}");
    assert!(names.contains(&"type_hierarchy"), "report: {report}");
    assert!(names.contains(&"query_code"), "report: {report}");

    let query_code = scenarios
        .iter()
        .find(|scenario| scenario["name"] == "query_code")
        .expect("query_code scenario");
    assert_eq!(query_code["case_id"], "class-a", "report: {report}");
    assert!(
        query_code["first_duration_ms"].is_number(),
        "report: {report}"
    );
    assert!(query_code["p95_ms"].is_number(), "report: {report}");
    assert_eq!(
        query_code["query_code"]["first"]["result_cardinality"], 1,
        "report: {report}"
    );
    assert!(
        query_code["query_code"]["cold_contract"]
            .as_str()
            .is_some_and(|contract| contract.contains("primed by an untimed scan-only process")),
        "report: {report}"
    );
    assert!(
        query_code["query_code"]["first"]["facts_cache"]["persisted_hydrations"]
            .as_u64()
            .is_some_and(|hydrations| hydrations > 0),
        "the measured process must hydrate the primed durable facts: {report}"
    );
    assert_eq!(
        query_code["query_code"]["first"]["facts_cache"]["extractions"], 0,
        "the measured first request must not include structural-fact extraction: {report}"
    );
    assert!(
        query_code["query_code"]["warm"]["facts_cache"]["memory_hits"]
            .as_u64()
            .is_some_and(|hits| hits > 0),
        "report: {report}"
    );
}

#[cfg(unix)]
#[test]
fn query_code_empty_fast_response_fails_oracle_and_discards_all_timings() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().expect("temp dir");
    let repo_root = temp.path().join("fixture-repo");
    copy_dir_recursively(&fixture_root(), &repo_root).expect("copy fixture repo");
    init_git_repo(&repo_root);

    let fake_server = temp.path().join("fake-bifrost");
    let script = r#"#!/bin/sh
while IFS= read -r line; do
  case "$line" in
    *'"method":"initialize"'*)
      printf '%s\n' '{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"fake-bifrost","version":"0","buildIdentity":"__IDENTITY__"}}}'
      ;;
    *'"method":"tools/call"'*)
      printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"format":"bifrost_code_query_profile/v2","result":{"results":[],"truncated":false},"timings_ns":{"total":1},"work":{"scanned_files":0,"scanned_source_bytes":0,"fact_nodes":0,"pipeline_rows":0,"examined_references":0,"import_files_resolved":0,"import_edges_resolved":0},"cache_layers":[],"access_path":{}}}}'
      ;;
    *'"method":"bifrost/benchmark-profile-boundary"'*)
      printf '\n\036bifrost-benchmark-profile-boundary\036\n' >&2
      printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{}}'
      ;;
  esac
done
"#
    .replace("__IDENTITY__", brokk_bifrost::BIFROST_BUILD_IDENTITY);
    fs::write(&fake_server, script).expect("write fake MCP server");
    let mut permissions = fs::metadata(&fake_server)
        .expect("fake metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fake_server, permissions).expect("make fake executable");

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
required_scenarios = ["workspace_build"]

[[repos]]
name = "fixture-java"
url = "{}"
commit = "{}"
languages = ["java"]
extensions = ["java"]
scenarios = ["workspace_build", "query_code"]
query_code_queries = [
  {{ id = "class-a", workloads = ["exact_name", "warm_reuse"], query_json = '{{"match":{{"kind":"class","name":"A"}},"limit":20}}', expected_witness_json = '{{"result_type":"structural_match","path":"A.java","kind":"class"}}', min_results = 1, max_results = 1 }},
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
        .env("BIFROST_BENCHMARK_BIFROST_BIN", &fake_server)
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
    let query = report["repos"][0]["scenarios"]
        .as_array()
        .expect("scenario array")
        .iter()
        .find(|scenario| scenario["name"] == "query_code")
        .expect("query_code scenario");
    assert_eq!(query["success"], false, "report: {report}");
    assert!(
        query["failure_message"]
            .as_str()
            .is_some_and(|message| message.contains("returned 0 result(s), expected at least 1")),
        "report: {report}"
    );
    assert!(query.get("first_duration_ms").is_none(), "report: {report}");
    assert_eq!(query["warmup_durations_ms"], json!([]), "report: {report}");
    assert_eq!(
        query["measured_durations_ms"],
        json!([]),
        "report: {report}"
    );
}

#[test]
fn run_subcommand_profile_writes_iteration_traces_and_report_references() {
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
required_scenarios = ["get_definition"]

[[repos]]
name = "fixture-java"
url = "{}"
commit = "{}"
languages = ["java"]
extensions = ["java"]
scenarios = ["get_definition"]
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
        .arg("--profile")
        .env(
            "BIFROST_BENCHMARK_BIFROST_BIN",
            env!("CARGO_BIN_EXE_bifrost"),
        )
        .output()
        .expect("run profiled bifrost_benchmark");

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let output_dir = manifest_dir.join("out");
    let report_path = single_json_file(&output_dir);
    let report: Value =
        serde_json::from_str(&fs::read_to_string(report_path).expect("read report"))
            .expect("parse report");
    let scenario = &report["repos"][0]["scenarios"][0];
    let artifacts = scenario["profile_artifacts"]
        .as_array()
        .expect("profile artifact array");
    assert_eq!(artifacts.len(), 2, "report: {report}");

    let mut combined_traces = String::new();
    for (index, artifact) in artifacts.iter().enumerate() {
        let relative = artifact.as_str().expect("artifact path");
        let components = Path::new(relative).components().collect::<Vec<_>>();
        assert_eq!(components.len(), 3, "run-scoped artifact path: {relative}");
        assert_eq!(components[0].as_os_str(), "profiles");
        let trace = fs::read_to_string(output_dir.join(relative)).expect("read profile trace");
        let expected_phase = if index == 0 { "warmup" } else { "measured" };
        assert!(trace.contains("repository=fixture-java"), "trace: {trace}");
        assert!(trace.contains("scenario=get_definition"), "trace: {trace}");
        assert!(
            trace.contains(&format!("phase={expected_phase}")),
            "trace: {trace}"
        );
        assert!(trace.contains("iteration=1"), "trace: {trace}");
        assert!(trace.contains("[bifrost-timing]"), "trace: {trace}");
        combined_traces.push_str(&trace);
    }
    for expected in [
        "SearchToolsService::snapshot_for_query",
        "SearchToolsService::apply_watcher_delta",
        "get_definition::resolve_navigation_batch",
        "language=Java",
        "get_definition::language_dispatch",
    ] {
        assert!(
            combined_traces.contains(expected),
            "profile traces missing `{expected}`:\n{combined_traces}"
        );
    }
    for forbidden in [
        "global_usage_definition_index::enumerate_live_keys",
        "global_usage_definition_index::fetch_persisted_rows",
        "global_usage_definition_index::resolve_persisted_rows",
        "global_usage_definition_index::collect_dirty_units",
        "global_usage_definition_index::collect_nonpersisted_units",
        "global_usage_definition_index::build",
    ] {
        assert!(
            !combined_traces.contains(forbidden),
            "forward definition profile unexpectedly entered `{forbidden}`:\n{combined_traces}"
        );
    }
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
  "query_code",
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
query_code_queries = [
  {{ id = "class-a", workloads = ["exact_name", "warm_reuse"], query_json = '{{"match":{{"kind":"class","name":"A"}},"limit":20}}', required_paths = ["A.java"], expected_witness_json = '{{"result_type":"structural_match","path":"A.java","kind":"class"}}', min_results = 1, max_results = 1 }},
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
    assert_eq!(scenarios.len(), 7, "report: {report}");
    for scenario in scenarios {
        assert_eq!(scenario["success"], true, "report: {report}");
    }
    let query_code = scenarios
        .iter()
        .find(|scenario| scenario["name"] == "query_code")
        .expect("query_code scenario");
    assert_eq!(query_code["skipped"], true, "report: {report}");
    assert!(
        query_code.get("first_duration_ms").is_none(),
        "report: {report}"
    );
    assert!(query_code.get("query_code").is_none(), "report: {report}");
    assert!(
        query_code["failure_message"]
            .as_str()
            .is_some_and(|reason| reason.contains("full-workspace oracle skipped")),
        "report: {report}"
    );
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
