use brokk_bifrost::benchmark::manifest::{
    BenchmarkManifest, BenchmarkScenario, ManifestLanguage, ManifestLoadError, QueryCodeWorkload,
};
use std::path::PathBuf;

fn checked_in_manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("benchmark")
        .join("targets.toml")
}

fn checked_in_interactive_manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("benchmark")
        .join("interactive-latency.toml")
}

#[test]
fn checked_in_targets_manifest_loads_and_validates() {
    let manifest = BenchmarkManifest::load_from_path(checked_in_manifest_path())
        .expect("checked-in benchmark manifest should validate");

    assert_eq!(manifest.warmup_iterations, 2);
    assert_eq!(manifest.measured_iterations, 10);
    assert_eq!(manifest.repos.len(), 11);

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
            let mut probes = repo
                .code_quality_probes_for(BenchmarkScenario::DeadCodeSmells)
                .peekable();
            assert!(
                probes.peek().is_some(),
                "{} must define a dead_code_smells probe",
                repo.name
            );
            for probe in probes {
                assert!(
                    !probe.file_paths.is_empty(),
                    "{} must pin dead_code_smells probe file_paths for subset benchmark runs",
                    repo.name
                );
                assert!(
                    !probe.fq_names.is_empty(),
                    "{} must define dead_code_smells probe fq_names",
                    repo.name
                );
            }
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
fn issue_1228_checked_in_interactive_latency_manifest_is_pinned_and_bounded() {
    let manifest = BenchmarkManifest::load_from_path(checked_in_interactive_manifest_path())
        .expect("checked-in interactive latency manifest should validate");

    assert_eq!(manifest.warmup_iterations, 2);
    assert_eq!(manifest.measured_iterations, 20);
    assert_eq!(manifest.repos.len(), 1);
    let target = &manifest.repos[0];
    assert_eq!(target.name, "bifrost-self");
    assert_eq!(target.commit, "45841f1a9e665a056380eb7c0a1b8485389cb48c");
    assert_eq!(target.interactive_queries.len(), 9);
    assert!(target.mcp_fairness.is_some());
    let search_case = target
        .interactive_queries
        .iter()
        .find(|case| case.id == "search-common-symbols")
        .expect("issue search_symbols reproduction");
    let search_arguments: serde_json::Value =
        serde_json::from_str(&search_case.arguments_json).expect("search arguments");
    assert_eq!(
        search_arguments,
        serde_json::json!({
            "patterns": [
                "solve_typestate.*summary",
                "solve_taint.*summary",
                "ProtocolSemanticSummarySet",
                "TaintSemanticSummarySet"
            ],
            "include_tests": true,
            "limit": 100
        }),
        "the release gate must preserve the exact issue #1228 search reproduction"
    );
    assert!(
        target
            .interactive_queries
            .iter()
            .all(|case| case.max_p95_ms == 5000.0)
    );
    assert_eq!(
        target
            .interactive_queries
            .iter()
            .filter(|case| case.allow_bounded_incomplete)
            .count(),
        2
    );
    assert_eq!(target.mcp_fairness.as_ref().unwrap().max_p95_ms, 5000.0);
}

#[test]
fn issue_1228_manifest_validation_rejects_vacuous_interactive_latency_cases() {
    let manifest = r#"
warmup_iterations = 1
measured_iterations = 1
required_languages = ["rust"]
required_scenarios = ["interactive_code_intelligence", "mcp_fairness"]

[[repos]]
name = "fixture"
url = "https://example.com/fixture"
commit = "deadbeef"
languages = ["rust"]
extensions = ["rs"]
scenarios = ["interactive_code_intelligence", "mcp_fairness"]
interactive_queries = [
  { id = "bad id", tool = "search_symbols", arguments_json = '[]', expected_json_pointer = "", allow_bounded_incomplete = true, max_p95_ms = -1.0 },
  { id = "duplicate", tool = "get_summaries", arguments_json = '{}', expected_json_pointer = "/structuredContent/summaries", max_p95_ms = 5000.0 },
  { id = "duplicate", tool = "get_summaries", arguments_json = '{}', expected_json_pointer = "/structuredContent/summaries", max_p95_ms = 5000.0 },
]
mcp_fairness = { id = "", scan_arguments_json = '{', source_arguments_json = '[]', expected_source_path = "", max_p95_ms = 0.0 }
"#;

    let err = BenchmarkManifest::from_toml_str(manifest).expect_err("manifest should fail");
    let ManifestLoadError::Validation(validation) = err else {
        panic!("expected validation error");
    };
    let messages = validation.messages().join("\n");
    for expected in [
        "id must be at most",
        "arguments JSON must be an object",
        "expected_json_pointer must be a non-empty JSON pointer",
        "max_p95_ms must be finite and positive",
        "allow_bounded_incomplete is only valid for scan_usages_by_location",
        "duplicate interactive query id `duplicate`",
        "has invalid arguments JSON",
        "expected_source_path must not be blank",
    ] {
        assert!(
            messages.contains(expected),
            "missing `{expected}` in {messages}"
        );
    }
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
        "positive bounded result count or an exact result witness",
    ] {
        assert!(
            messages.contains(expected),
            "missing `{expected}` in {messages}"
        );
    }
}

#[test]
fn manifest_validation_rejects_vacuous_query_code_witnesses() {
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
  { id = "empty", workloads = ["exact_name", "broad", "regex", "containment", "typed_traversal", "warm_reuse"], query_json = '{"match":{"kind":"class","name":"A"}}', expected_witness_json = '{}' },
  { id = "kind-only", workloads = ["exact_name"], query_json = '{"match":{"kind":"class","name":"A"}}', expected_witness_json = '{"kind":"class"}', min_results = 1 },
]
"#;

    let err = BenchmarkManifest::from_toml_str(manifest).expect_err("manifest should fail");
    let ManifestLoadError::Validation(validation) = err else {
        panic!("expected validation error");
    };
    let messages = validation.messages().join("\n");
    assert!(
        messages.contains("stable result identity"),
        "missing vacuous-witness error in {messages}"
    );
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
  { id = "nested-union", workloads = ["exact_name", "typed_traversal"], query_json = '{"union":[{"languages":["java"],"where":["src/A.java"],"match":{"kind":"class","name":"A"}},{"languages":["java"],"where":["src/B.java"],"match":{"kind":"class","name":"B"}}],"steps":[{"op":"file_of"}]}', required_paths = ["src/A.java", "src/B.java"], min_results = 1, max_results = 2 },
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

#[test]
fn manifest_validation_enforces_code_quality_probe_shapes() {
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
scenarios = ["workspace_build", "structural_clone_smells", "exception_smells", "comment_density_code_unit"]
code_quality_probes = [
  { scenario = "exception_smells", file_paths = ["src/A.java"], fq_names = ["com.example.A"], expect_report_contains = [] },
  { scenario = "comment_density_code_unit", fq_names = ["com.example.A", "com.example.B"], expect_report_contains = ["- Symbol: `com.example.A`"] },
  { scenario = "git_hotspots", expect_report_contains = ["src/A.java"] },
  { scenario = "search_symbols", file_paths = ["src/A.java"], expect_report_contains = ["A"] },
]
"#;

    let err = BenchmarkManifest::from_toml_str(manifest).expect_err("manifest should fail");
    let ManifestLoadError::Validation(validation) = err else {
        panic!("expected validation error");
    };
    let messages = validation.messages().join("\n");

    for expected in [
        "enables `structural_clone_smells` but defines no code_quality_probes entry",
        "must define at least one expect_report_contains entry",
        "defines fq_names but `exception_smells` does not take symbol inputs",
        "must define exactly one fq_names entry for `comment_density_code_unit`",
        "targets `git_hotspots` but the repo does not enable that scenario",
        "names `search_symbols`, which is not a code-quality scenario",
    ] {
        assert!(
            messages.contains(expected),
            "missing `{expected}` in {messages}"
        );
    }
}

#[test]
fn manifest_accepts_code_quality_probes_with_argument_overrides() {
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
scenarios = ["workspace_build", "structural_clone_smells", "git_hotspots"]
code_quality_probes = [
  { scenario = "structural_clone_smells", file_paths = ["src/A.java", "src/B.java"], arguments = { min_score = 45, shingle_size = 3 }, expect_report_contains = ["`com.example.A.render`"], expect_report_absent = ["not yet supported"] },
  { scenario = "git_hotspots", arguments = { since_iso = "2020-01-01T00:00:00Z", until_iso = "2024-01-01T00:00:00Z" }, expect_report_contains = ["src/A.java"] },
]
"#;

    let manifest = BenchmarkManifest::from_toml_str(manifest).expect("manifest should validate");
    let repo = &manifest.repos[0];
    let clone_probe = repo
        .code_quality_probes_for(BenchmarkScenario::StructuralCloneSmells)
        .next()
        .expect("clone probe");
    assert_eq!(clone_probe.file_paths, ["src/A.java", "src/B.java"]);
    assert_eq!(
        clone_probe.arguments.get("min_score"),
        Some(&serde_json::json!(45))
    );
    assert_eq!(
        clone_probe.arguments.get("shingle_size"),
        Some(&serde_json::json!(3))
    );
    let hotspot_probe = repo
        .code_quality_probes_for(BenchmarkScenario::GitHotspots)
        .next()
        .expect("hotspot probe");
    assert!(hotspot_probe.file_paths.is_empty());
    assert_eq!(
        hotspot_probe.arguments.get("since_iso"),
        Some(&serde_json::json!("2020-01-01T00:00:00Z"))
    );
}

/// The achieved language-by-tool coverage matrix for the code-quality
/// scenarios. Exclusions are deliberate, evidence-backed decisions recorded in
/// .agents/plans/code-quality-perf-regression-benchmarks.md: cpp exception
/// smells and comment-density on fmt's macro-heavy files fail to parse; cpp
/// structural clones exceed the MCP request budget workspace-wide; kotlin
/// clones are unimplemented (#1371); the javascript, php, and scala corpora
/// have no true-positive exception/test-assertion findings to pin; and the secret
/// scan exceeds the request budget on exposed-kotlin, leaving java,
/// javascript, cpp, and csharp with pinnable secret findings. Shrinking any of these sets is a coverage regression.
#[test]
fn code_quality_scenarios_cover_the_expected_language_matrix() {
    let manifest = BenchmarkManifest::load_from_path(checked_in_manifest_path())
        .expect("checked-in benchmark manifest should validate");

    use ManifestLanguage::*;
    let all = ManifestLanguage::ALL.to_vec();
    let expected: &[(BenchmarkScenario, Vec<ManifestLanguage>)] = &[
        (
            BenchmarkScenario::DeadCodeSmells,
            vec![
                Java, Go, JavaScript, TypeScript, Python, Rust, Php, Scala, CSharp, Kotlin,
            ],
        ),
        (BenchmarkScenario::CommentDensityFiles, all.clone()),
        (BenchmarkScenario::CommentDensityCodeUnit, all.clone()),
        (
            BenchmarkScenario::ExceptionSmells,
            vec![
                Java, Go, JavaScript, TypeScript, Python, Rust, CSharp, Kotlin,
            ],
        ),
        (
            BenchmarkScenario::TestAssertionSmells,
            vec![Java, Go, Cpp, TypeScript, Python, Rust, CSharp, Kotlin],
        ),
        (
            BenchmarkScenario::StructuralCloneSmells,
            vec![
                Java, Go, JavaScript, TypeScript, Python, Rust, Php, Scala, CSharp,
            ],
        ),
        (BenchmarkScenario::LongMethodSmells, all.clone()),
        (
            BenchmarkScenario::SecretLikeCode,
            vec![Java, Cpp, JavaScript, CSharp],
        ),
        (BenchmarkScenario::GitHotspots, all.clone()),
    ];

    for (scenario, languages) in expected {
        let covered = manifest
            .repos
            .iter()
            .filter(|repo| repo.scenario_set().contains(scenario))
            .flat_map(|repo| repo.language_set())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            covered,
            languages.iter().copied().collect(),
            "language coverage drifted for `{}`",
            scenario.label()
        );
        for repo in manifest
            .repos
            .iter()
            .filter(|repo| repo.scenario_set().contains(scenario))
        {
            assert!(
                repo.code_quality_probes_for(*scenario).next().is_some(),
                "{} enables `{}` without a probe",
                repo.name,
                scenario.label()
            );
        }
    }
}
