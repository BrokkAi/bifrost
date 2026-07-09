use brokk_bifrost::benchmark::manifest::{
    BenchmarkManifest, BenchmarkScenario, ManifestLanguage, ManifestLoadError,
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
