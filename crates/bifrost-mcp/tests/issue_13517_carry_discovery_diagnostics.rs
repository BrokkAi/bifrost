//! #13517: a discovery whose diagnostics all follow its recorded reads carries
//! across requests, and the status a warm session reports equals a cold run's.

use brokk_bifrost_analysis::analyzer::Language;
use brokk_bifrost_mcp::searchtools_service::SearchToolsService;
use serde_json::{Value, json};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

/// Every test points `BIFROST_CACHE_ROOT` at its own directory, and the
/// environment is process-wide, so the tests of this file run one at a time.
static ENVIRONMENT: Mutex<()> = Mutex::new(());

fn serialized() -> MutexGuard<'static, ()> {
    ENVIRONMENT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

const MISMATCHED_CHANNEL_CODE: &str = "rust.toolchain.stdlib_channel_mismatch";

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

/// The semantic-model status exactly as `get_active_workspace` renders it.
fn overlay_status(service: &SearchToolsService) -> String {
    wait_for_activation(service);
    let status: Value = service
        .call_tool_value("get_active_workspace", json!({}))
        .unwrap();
    serde_json::to_string_pretty(&status["semantic_model_overlay"]).unwrap()
}

fn evidence(
    service: &SearchToolsService,
    language: Language,
) -> Arc<brokk_bifrost_analysis::analyzer::semantic_model::DependencyDiscoveryEvidence> {
    service
        .analyzer_snapshot()
        .expect("snapshot")
        .analyzer()
        .dependency_discovery_evidence(language)
        .expect("published discovery evidence")
}

fn write(root: &Path, relative: &str, contents: &str) {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

/// A Rust crate pinned to a channel the standard-library pack does not select
/// (a Cargo discovery diagnostic that follows the recorded toolchain file), and
/// a Go module and a Python workspace that declares a CPython version no pack
/// serves. Neither carries (Go reads process output; the Python preparation
/// fails with a missing pack), so every edit refreshes them while Cargo carries:
/// a scoped refresh with a carried sibling.
fn fixture(root: &Path) {
    write(
        root,
        "Cargo.toml",
        "[package]\nname = \"carried\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    );
    write(
        root,
        "rust-toolchain.toml",
        "[toolchain]\nchannel = \"1.99.1\"\n",
    );
    write(
        root,
        "src/lib.rs",
        "mod edited;\npub fn value() -> i32 { 1 }\n",
    );
    write(root, "src/edited.rs", "pub fn unrelated() {}\n");
    write(root, "go.mod", "module example.com/carried\n\ngo 1.21\n");
    write(root, "main.go", "package main\n\nfunc main() {}\n");
    write(root, ".python-version", "3.10.0\n");
    write(root, "app.py", "value = 1\n");
}

fn start(root: &Path, cache: &Path) -> SearchToolsService {
    // This integration test owns its process environment.
    unsafe {
        std::env::set_var("BIFROST_OPEN_PACKS_DISABLE", "1");
        std::env::set_var("BIFROST_CACHE_ROOT", cache);
    }
    let service = SearchToolsService::new_manual_persisted(root.to_path_buf()).unwrap();
    wait_for_activation(&service);
    service
}

#[test]
fn discovery_with_a_recorded_diagnostic_carries_and_reports_the_cold_status() {
    let _serialized = serialized();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("workspace");
    std::fs::create_dir(&root).unwrap();
    let cache = temp.path().canonicalize().unwrap().join("cache");
    fixture(&root);
    let service = start(&root, &cache);

    let first = evidence(&service, Language::Rust);
    let retained = first
        .retained_status
        .as_ref()
        .expect("a published discovery retains its status");
    assert!(
        retained
            .discovery
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == MISMATCHED_CHANNEL_CODE),
        "the fixture must report the channel diagnostic: {retained:?}"
    );

    write(
        &root,
        "src/edited.rs",
        "pub fn unrelated() { let _x = 1; }\n",
    );
    service
        .call_tool_value("update_paths", json!({"paths": ["src/edited.rs"]}))
        .unwrap();
    let warm = overlay_status(&service);
    assert!(
        Arc::ptr_eq(&first, &evidence(&service, Language::Rust)),
        "the diagnostic follows recorded reads, so Cargo discovery must carry"
    );

    let cold = start(&root, &temp.path().join("cold-cache"));
    assert_eq!(warm, overlay_status(&cold), "warm status differs from cold");
}

#[test]
fn scoped_refresh_reports_the_cold_status_around_a_carried_ecosystem() {
    let _serialized = serialized();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("workspace");
    std::fs::create_dir(&root).unwrap();
    let cache = temp.path().canonicalize().unwrap().join("cache");
    fixture(&root);
    let service = start(&root, &cache);
    let cargo = evidence(&service, Language::Rust);
    let python = evidence(&service, Language::Python);

    write(&root, "app.py", "value = 2\n");
    service
        .call_tool_value("update_paths", json!({"paths": ["app.py"]}))
        .unwrap();
    let warm = overlay_status(&service);
    assert!(
        !Arc::ptr_eq(&python, &evidence(&service, Language::Python)),
        "a preparation failure is never carried, so the edit refreshes Python"
    );
    assert!(
        Arc::ptr_eq(&cargo, &evidence(&service, Language::Rust)),
        "Cargo discovery must carry through the Python refresh"
    );

    let cold = start(&root, &temp.path().join("cold-cache"));
    assert_eq!(
        warm,
        overlay_status(&cold),
        "status after a scoped refresh differs from cold"
    );
}

#[test]
fn editing_the_recorded_toolchain_file_rediscovers_cargo() {
    let _serialized = serialized();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("workspace");
    std::fs::create_dir(&root).unwrap();
    let cache = temp.path().canonicalize().unwrap().join("cache");
    fixture(&root);
    let service = start(&root, &cache);
    let first = evidence(&service, Language::Rust);

    write(
        &root,
        "rust-toolchain.toml",
        "[toolchain]\nchannel = \"1.99.2\"\n",
    );
    service
        .call_tool_value("update_paths", json!({"paths": ["rust-toolchain.toml"]}))
        .unwrap();
    wait_for_activation(&service);
    assert!(
        !Arc::ptr_eq(&first, &evidence(&service, Language::Rust)),
        "a changed recorded input must rediscover"
    );
}

#[test]
fn go_discovery_with_unverifiable_reads_is_rediscovered() {
    let _serialized = serialized();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("workspace");
    std::fs::create_dir(&root).unwrap();
    let cache = temp.path().canonicalize().unwrap().join("cache");
    write(&root, "go.mod", "module example.com/carried\n\ngo 1.21\n");
    write(&root, "main.go", "package main\n\nfunc main() {}\n");
    write(&root, "util.go", "package main\n\nfunc helper() {}\n");
    let service = start(&root, &cache);
    let first = evidence(&service, Language::Go);

    write(
        &root,
        "util.go",
        "package main\n\nfunc helper() { _ = 1 }\n",
    );
    service
        .call_tool_value("update_paths", json!({"paths": ["util.go"]}))
        .unwrap();
    wait_for_activation(&service);
    assert!(
        !Arc::ptr_eq(&first, &evidence(&service, Language::Go)),
        "Go discovery depends on process output and a cache walk and must not carry"
    );
}
