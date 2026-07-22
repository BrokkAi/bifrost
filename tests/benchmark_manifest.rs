use brokk_bifrost::benchmark::manifest::{
    BenchmarkManifest, BenchmarkScenario, ManifestLanguage, ManifestLoadError, QueryCodeWorkload,
};
use std::path::PathBuf;

fn checked_in_manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("benchmark")
        .join("targets.toml")
}

#[test]
fn checked_in_targets_manifest_loads_and_validates() {
    let manifest = BenchmarkManifest::load_from_path(checked_in_manifest_path())
        .expect("checked-in benchmark manifest should validate");

    assert_eq!(manifest.warmup_iterations, 2);
    assert_eq!(manifest.measured_iterations, 10);
    assert_eq!(manifest.repos.len(), 10);

    let covered_languages = manifest
        .repos
        .iter()
        .flat_map(|repo| repo.language_set())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        covered_languages,
        ManifestLanguage::ALL.into_iter().collect()
    );

    let covered_scenarios = manifest
        .repos
        .iter()
        .flat_map(|repo| repo.scenario_set())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        covered_scenarios,
        BenchmarkScenario::ALL.into_iter().collect()
    );

    for repo in &manifest.repos {
        assert!(
            repo.scenario_set()
                .contains(&BenchmarkScenario::GetDefinition),
            "{} must enable get_definition coverage",
            repo.name
        );
        assert!(
            !repo.definition_queries.is_empty(),
            "{} must define at least one get_definition query",
            repo.name
        );
        assert!(
            repo.scenario_set().contains(&BenchmarkScenario::QueryCode),
            "{} must enable query_code coverage",
            repo.name
        );
        assert!(
            !repo.query_code_queries.is_empty(),
            "{} must define at least one query_code case",
            repo.name
        );
        if repo
            .scenario_set()
            .contains(&BenchmarkScenario::DeadCodeSmells)
        {
            assert!(
                !repo.dead_code_file_paths.is_empty(),
                "{} must pin dead_code_file_paths for subset benchmark runs",
                repo.name
            );
            assert!(
                !repo.dead_code_fq_names.is_empty(),
                "{} must define dead_code_fq_names",
                repo.name
            );
        }
    }

    let gson = manifest
        .repos
        .iter()
        .find(|repo| repo.name == "google-gson")
        .expect("google-gson benchmark target");
    assert!(
        gson.scenario_set()
            .contains(&BenchmarkScenario::CallHierarchy),
        "google-gson must enable call_hierarchy coverage"
    );
    assert!(
        gson.scenario_set()
            .contains(&BenchmarkScenario::TypeHierarchy),
        "google-gson must enable type_hierarchy coverage"
    );
    assert!(
        !gson.call_hierarchy_queries.is_empty(),
        "google-gson must define call_hierarchy_queries"
    );
    assert!(
        !gson.type_hierarchy_queries.is_empty(),
        "google-gson must define type_hierarchy_queries"
    );

    let workloads = manifest
        .repos
        .iter()
        .flat_map(|repo| &repo.query_code_queries)
        .flat_map(|case| case.workloads.iter().copied())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(workloads, QueryCodeWorkload::ALL.into_iter().collect());
}

#[test]
fn manifest_validation_rejects_invalid_query_code_cases() {
    let manifest = r#"
warmup_iterations = 1
measured_iterations = 1
required_languages = ["java"]
required_scenarios = ["query_code"]

[[repos]]
name = "fixture"
url = "https://example.com/fixture"
commit = "deadbeef"
languages = ["java"]
extensions = ["java"]
scenarios = ["query_code"]
query_code_queries = [
  { id = "duplicate", workloads = ["exact_name", "broad", "regex", "containment", "typed_traversal", "warm_reuse"], query_json = '{"match":{"kind":"class","name":"A"}}', min_results = 1 },
  { id = "duplicate", workloads = ["exact_name"], query_json = '{"match":{"kind":"class","name":"A"}}', min_results = 1 },
  { id = "query-file", workloads = ["exact_name"], query_json = '{"query_file":"query.rql"}', min_results = 1 },
  { id = "mode", workloads = ["exact_name"], query_json = '{"execution_mode":"profile","match":{"kind":"class"}}', min_results = 1 },
  { id = "malformed", workloads = ["exact_name"], query_json = '{', min_results = 1 },
  { id = "no-oracle", workloads = ["exact_name"], query_json = '{"match":{"kind":"class"}}' },
]
"#;

    let err = BenchmarkManifest::from_toml_str(manifest).expect_err("manifest should fail");
    let ManifestLoadError::Validation(validation) = err else {
        panic!("expected validation error");
    };
    let messages = validation.messages().join("\n");
    for expected in [
        "duplicate query_code case id `duplicate`",
        "cannot use query_file",
        "cannot set execution_mode",
        "invalid query_json",
        "positive result count or an exact result witness",
    ] {
        assert!(
            messages.contains(expected),
            "missing `{expected}` in {messages}"
        );
    }
}

#[test]
fn manifest_validation_rejects_query_cases_when_scenario_is_disabled() {
    let manifest = r#"
warmup_iterations = 1
measured_iterations = 1
required_languages = ["java"]
required_scenarios = ["workspace_build"]

[[repos]]
name = "fixture"
url = "https://example.com/fixture"
commit = "deadbeef"
languages = ["java"]
extensions = ["java"]
scenarios = ["workspace_build"]
query_code_queries = [
  { id = "class-a", workloads = ["exact_name"], query_json = '{"match":{"kind":"class","name":"A"}}', min_results = 1 },
]
"#;

    let err = BenchmarkManifest::from_toml_str(manifest).expect_err("manifest should fail");
    let ManifestLoadError::Validation(validation) = err else {
        panic!("expected validation error");
    };
    assert!(
        validation
            .messages()
            .iter()
            .any(|message| message.contains("does not enable `query_code`")),
        "{validation}"
    );
}

#[test]
fn manifest_validation_checks_query_intent_and_portable_paths() {
    let manifest = r#"
warmup_iterations = 1
measured_iterations = 1
required_languages = ["java"]
required_scenarios = ["workspace_build"]

[[repos]]
name = "fixture"
url = "https://example.com/fixture"
commit = "deadbeef"
languages = ["java"]
extensions = ["java"]
scenarios = ["workspace_build", "query_code"]
query_code_queries = [
  { id = "bad id", workloads = ["broad"], query_json = '{"languages":["python"],"match":{"kind":"class","name":"A"}}', required_paths = ["/absolute.java", "../escape.java", "src/./A.java", "C:/escape.java"], min_results = 1 },
]
"#;

    let err = BenchmarkManifest::from_toml_str(manifest).expect_err("manifest should fail");
    let ManifestLoadError::Validation(validation) = err else {
        panic!("expected validation error");
    };
    let messages = validation.messages().join("\n");
    for expected in [
        "id must be an ASCII slug",
        "declares `broad` workload",
        "language `python` which is not declared",
        "required path `/absolute.java`",
        "required path `../escape.java`",
        "required path `src/./A.java`",
        "required path `C:/escape.java`",
    ] {
        assert!(
            messages.contains(expected),
            "missing `{expected}` in {messages}"
        );
    }
}

#[test]
fn manifest_accepts_explicit_subset_paths_for_nested_query_branches() {
    let manifest = r#"
warmup_iterations = 1
measured_iterations = 1
required_languages = ["java"]
required_scenarios = ["workspace_build"]

[[repos]]
name = "fixture"
url = "https://example.com/fixture"
commit = "deadbeef"
languages = ["java"]
extensions = ["java"]
scenarios = ["workspace_build", "query_code"]
query_code_queries = [
  { id = "nested-union", workloads = ["exact_name", "typed_traversal"], query_json = '{"union":[{"languages":["java"],"where":["src/A.java"],"match":{"kind":"class","name":"A"}},{"languages":["java"],"where":["src/B.java"],"match":{"kind":"class","name":"B"}}],"steps":[{"op":"file_of"}]}', required_paths = ["src/A.java", "src/B.java"], min_results = 1 },
]
"#;

    let manifest = BenchmarkManifest::from_toml_str(manifest).expect("manifest should validate");
    assert_eq!(
        manifest.repos[0].query_code_queries[0].required_paths,
        ["src/A.java", "src/B.java"]
    );
}

#[test]
fn manifest_validation_requires_probe_inputs_for_enabled_scenarios() {
    let manifest = r#"
warmup_iterations = 1
measured_iterations = 1

[[repos]]
name = "gson"
url = "https://github.com/google/gson"
commit = "deadbeef"
languages = ["java"]
extensions = ["java"]
scenarios = ["workspace_build", "search_symbols", "get_symbol_locations", "get_symbol_ancestors", "get_summaries", "most_relevant_files"]
"#;

    let err = BenchmarkManifest::from_toml_str(manifest).expect_err("manifest should fail");
    let ManifestLoadError::Validation(validation) = err else {
        panic!("expected validation error");
    };

    assert!(
        validation
            .messages()
            .iter()
            .any(|message| message.contains("search_symbols")),
        "{validation}"
    );
    assert!(
        validation
            .messages()
            .iter()
            .any(|message| message.contains("get_symbol_locations")),
        "{validation}"
    );
    assert!(
        validation
            .messages()
            .iter()
            .any(|message| message.contains("get_symbol_ancestors")),
        "{validation}"
    );
    assert!(
        validation
            .messages()
            .iter()
            .any(|message| message.contains("get_summaries")),
        "{validation}"
    );
    assert!(
        validation
            .messages()
            .iter()
            .any(|message| message.contains("most_relevant_files")),
        "{validation}"
    );
    assert!(
        validation
            .messages()
            .iter()
            .any(|message| message.contains("scan_usages")),
        "{validation}"
    );
    assert!(
        validation
            .messages()
            .iter()
            .any(|message| message.contains("dead_code_smells")),
        "{validation}"
    );
    assert!(
        validation
            .messages()
            .iter()
            .any(|message| message.contains("get_definition")),
        "{validation}"
    );
    assert!(
        validation
            .messages()
            .iter()
            .any(|message| message.contains("call_hierarchy")),
        "{validation}"
    );
    assert!(
        validation
            .messages()
            .iter()
            .any(|message| message.contains("type_hierarchy")),
        "{validation}"
    );
}

#[test]
fn manifest_validation_requires_full_language_coverage() {
    let manifest = r#"
warmup_iterations = 1
measured_iterations = 1
required_languages = ["java", "go"]
required_scenarios = ["workspace_build"]

[[repos]]
name = "gson"
url = "https://github.com/google/gson"
commit = "deadbeef"
languages = ["java"]
extensions = ["java"]
scenarios = ["workspace_build"]
"#;

    let err = BenchmarkManifest::from_toml_str(manifest).expect_err("manifest should fail");
    let ManifestLoadError::Validation(validation) = err else {
        panic!("expected validation error");
    };

    assert!(
        validation
            .messages()
            .iter()
            .any(|message| message.contains("required language `go`")),
        "{validation}"
    );
}

#[test]
fn manifest_validation_requires_global_scenario_coverage() {
    let manifest = r#"
warmup_iterations = 1
measured_iterations = 1
required_languages = ["java"]
required_scenarios = ["workspace_build", "get_symbol_locations"]

[[repos]]
name = "gson"
url = "https://github.com/google/gson"
commit = "deadbeef"
languages = ["java"]
extensions = ["java"]
scenarios = ["workspace_build"]
"#;

    let err = BenchmarkManifest::from_toml_str(manifest).expect_err("manifest should fail");
    let ManifestLoadError::Validation(validation) = err else {
        panic!("expected validation error");
    };

    assert!(
        validation
            .messages()
            .iter()
            .any(|message| message.contains("required scenario `get_symbol_locations`")),
        "{validation}"
    );
}

#[test]
fn manifest_validation_rejects_duplicate_repo_scenarios() {
    let manifest = r#"
warmup_iterations = 1
measured_iterations = 1
required_languages = ["java"]
required_scenarios = ["workspace_build"]

[[repos]]
name = "gson"
url = "https://github.com/google/gson"
commit = "deadbeef"
languages = ["java"]
extensions = ["java"]
scenarios = ["workspace_build", "workspace_build"]
"#;

    let err = BenchmarkManifest::from_toml_str(manifest).expect_err("manifest should fail");
    let ManifestLoadError::Validation(validation) = err else {
        panic!("expected validation error");
    };

    assert!(
        validation
            .messages()
            .iter()
            .any(|message| message.contains("duplicate scenario `workspace_build`")),
        "{validation}"
    );
}
