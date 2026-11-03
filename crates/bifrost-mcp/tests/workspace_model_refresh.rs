use brokk_bifrost_mcp::searchtools_service::SearchToolsService;
use serde_json::{Value, json};

fn pack(name: &str) -> String {
    json!({
        "schema_version": 2,
        "pack_id": "workspace.job-maker",
        "version": "1.0.0",
        "producer": {"name": "workspace", "version": "1.0.0"},
        "language": "rust",
        "ecosystem": "cargo",
        "compatibility": {"bifrost": ">=0.8.0, <1.0.0", "toolchains": []},
        "provenance": {"source": "workspace:.bifrost/semantic-models/job-maker.json"},
        "license": "MIT",
        "completeness": "partial",
        "safety": {"generated_code_only": true, "review_required": false},
        "shards": [{
            "id": "workspace.job-maker.declarations",
            "activation": [{"targets": [], "configurations": []}],
            "payload": {
                "kind": "declaration_facts",
                "types": [{
                    "id": "workspace.type.generated-job-maker",
                    "name": name,
                    "type_kind": "struct",
                    "visibility": "public",
                    "type_parameters": [], "hierarchy": [], "aliases": [], "extension_surfaces": [],
                    "locator": {"kind": "artifact", "path": "workspace/job_maker.rs", "symbol": "GeneratedJobMaker"}
                }],
                "members": [], "relations": []
            }
        }]
    }).to_string()
}

fn active(service: &SearchToolsService) -> Value {
    service
        .call_tool_value("get_active_workspace", json!({}))
        .expect("workspace status")
}

#[test]
fn workspace_model_edit_replaces_active_pack_status() {
    // This integration binary owns its process environment. No other test in
    // this binary can observe the setting while the service is constructed.
    unsafe { std::env::set_var("BIFROST_WORKSPACE_SEMANTIC_MODELS", "on") };
    let temp = tempfile::tempdir().expect("workspace");
    let pack_path = ".bifrost/semantic-models/job-maker.json";
    std::fs::create_dir_all(temp.path().join("src")).expect("source directory");
    std::fs::create_dir_all(temp.path().join(".bifrost/semantic-models")).expect("model directory");
    std::fs::write(temp.path().join("src/lib.rs"), "pub struct Local;\n").expect("source file");
    std::fs::write(
        temp.path().join(pack_path),
        pack("workspace.GeneratedJobMaker"),
    )
    .expect("initial model pack");
    let root = temp.path().canonicalize().expect("absolute workspace root");
    let service =
        SearchToolsService::new_manual_persisted(root.clone()).expect("start workspace service");
    assert_eq!(active(&service)["semantic_model_overlay"]["state"], "ready");

    std::fs::write(root.join(pack_path), "{}").expect("invalidate model pack");
    service
        .call_tool_value("update_paths", json!({"paths": [pack_path]}))
        .expect("update pack path");
    let after = active(&service);
    assert_eq!(
        after["semantic_model_overlay"]["state"], "unavailable",
        "{after}"
    );
}
