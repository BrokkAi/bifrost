use brokk_bifrost_analysis::{DependencyPackEcosystem, analyzer::ProjectFile};
use brokk_bifrost_mcp::searchtools_service::SearchToolsService;
use brokk_bifrost_test_macros::hardwon;
use serde_json::{Value, json};
use std::collections::BTreeSet;

fn wait_for_activation(service: &SearchToolsService) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let status = service
            .call_tool_value("get_active_workspace", json!({}))
            .unwrap();
        if status["semantic_packs_ready"] == true {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "activation did not settle: {status}"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn calls(service: &SearchToolsService) -> Value {
    service
        .call_tool_value("query_code", json!({"query_file": "query.rql"}))
        .expect("query call bindings")
}

fn assert_calls(answer: &Value) {
    let rows = answer["results"].as_array().expect("call binding rows");
    assert_eq!(rows.len(), 2, "{answer}");
    for (line, outcome, coverage) in [(6, "unproven", "open"), (7, "unproven", "exhaustive")] {
        let row = rows
            .iter()
            .find(|row| row["range"]["start_line"] == line)
            .expect("call binding for fixture line");
        assert_eq!(row["dispatch_outcome"], outcome, "{answer}");
        assert_eq!(row["dispatch_coverage"], coverage, "{answer}");
    }
}

#[test]
#[hardwon("#9840: a warm MCP update dropped published dependency evidence")]
fn unrelated_edit_carries_cargo_evidence_until_manifest_changes() {
    // This integration test owns its process environment.
    unsafe { std::env::set_var("BIFROST_OPEN_PACKS_DISABLE", "1") };
    let temp = tempfile::tempdir().expect("workspace");
    let root = temp.path().canonicalize().expect("absolute root");
    std::fs::create_dir(root.join("src")).expect("source directory");
    std::fs::write(root.join("Cargo.toml"), "[package]\nname = \"dispatch_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nserde_json = \"1\"\n").expect("manifest");
    std::fs::write(root.join("src/lib.rs"), "mod untouched;\nmod edited;\n").expect("root source");
    std::fs::write(root.join("src/untouched.rs"), "use serde_json::Value;\ntrait Runner { fn run(&self); }\nstruct Local;\nimpl Runner for Local { fn run(&self) {} }\npub fn check<T: Runner>(runner: T) {\n runner.run();\n let _ = serde_json::to_string(&Value::Null);\n}\n").expect("untouched source");
    std::fs::write(
        root.join("src/edited.rs"),
        "pub fn unrelated() { let _x = 1; }\n",
    )
    .expect("edited source");
    std::fs::write(
        root.join("query.rql"),
        "(language rust (call-bindings (call-shape (where \"src/untouched.rs\" (call)))))",
    )
    .expect("query");

    let service = SearchToolsService::new_manual_persisted(root.clone()).expect("warm service");
    let first = calls(&service);
    assert_calls(&first);
    std::fs::write(
        root.join("src/edited.rs"),
        "pub fn unrelated() { let _x = 1; }\npub fn added() { let _y = 2; }\n",
    )
    .expect("unrelated edit");
    service
        .call_tool_value("update_paths", json!({"paths": ["src/edited.rs"]}))
        .expect("update source");
    let warm = calls(&service);
    assert_calls(&warm);

    let cold = SearchToolsService::new_manual_persisted(root.clone()).expect("fresh service");
    let fresh = calls(&cold);
    assert_calls(&fresh);

    std::fs::write(root.join("Cargo.toml"), "[package]\nname = \"dispatch_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nserde_json = \"1\"\nregex = \"1\"\n").expect("manifest edit");
    service
        .call_tool_value("update_paths", json!({"paths": ["Cargo.toml"]}))
        .expect("update manifest");
    let snapshot = service.analyzer_snapshot().expect("updated snapshot");
    assert!(
        snapshot
            .stale_dependency_ecosystems()
            .contains(&DependencyPackEcosystem::Cargo)
    );
    assert_eq!(
        snapshot.stale_dependency_ecosystems(),
        vec![DependencyPackEcosystem::Cargo],
        "the manifest edit must rediscover only Cargo"
    );
    let warm = serde_json::to_string(&calls(&service)).expect("render warm answer");
    let fresh_service = SearchToolsService::new_manual_persisted(root).expect("fresh service");
    let fresh = serde_json::to_string(&calls(&fresh_service)).expect("render cold answer");
    assert_eq!(warm, fresh, "manifest edit warm/cold answer mismatch");
}

#[test]
#[hardwon("#9840: a second edit forgot an ecosystem still awaiting refresh")]
fn consecutive_manifest_edits_keep_cargo_stale_until_publication() {
    unsafe { std::env::set_var("BIFROST_OPEN_PACKS_DISABLE", "1") };
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::create_dir(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"repeat\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(root.join("src/lib.rs"), "pub fn first() {}\n").unwrap();
    let service = SearchToolsService::new_manual_persisted(root.clone()).unwrap();
    wait_for_activation(&service);
    let original = service.analyzer_snapshot().unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"repeat\"\nversion = \"0.1.1\"\nedition = \"2021\"\n",
    )
    .unwrap();
    let first = original.update(&BTreeSet::from([ProjectFile::new(
        root.clone(),
        "Cargo.toml",
    )]));
    assert!(
        first
            .stale_dependency_ecosystems()
            .contains(&DependencyPackEcosystem::Cargo)
    );
    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn first() {}\npub fn second() {}\n",
    )
    .unwrap();
    let snapshot = first.update(&BTreeSet::from([ProjectFile::new(
        root.clone(),
        "src/lib.rs",
    )]));
    assert!(
        snapshot
            .stale_dependency_ecosystems()
            .contains(&DependencyPackEcosystem::Cargo)
    );
}

#[test]
#[hardwon("#9840: failed first discovery was never retried after a manifest fix")]
fn failed_first_discovery_retries_after_manifest_fix() {
    unsafe { std::env::set_var("BIFROST_OPEN_PACKS_DISABLE", "1") };
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::create_dir(root.join("src")).unwrap();
    std::fs::write(root.join("Cargo.toml"), "[package\n").unwrap();
    std::fs::write(root.join("src/lib.rs"), "pub fn example() {}\n").unwrap();
    let service = SearchToolsService::new_manual_persisted(root.clone()).unwrap();
    wait_for_activation(&service);
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"recovered\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    service
        .call_tool_value("update_paths", json!({"paths": ["Cargo.toml"]}))
        .unwrap();
    let snapshot = service.analyzer_snapshot().unwrap();
    assert!(
        snapshot.requires_whole_dependency_refresh()
            || snapshot
                .stale_dependency_ecosystems()
                .contains(&DependencyPackEcosystem::Cargo)
    );
}
