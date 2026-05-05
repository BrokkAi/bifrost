use serde_json::Value;
use std::fs;
use std::path::Path;

#[test]
fn lsp_json_parses_and_advertises_bifrost_command() {
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".lsp.json");
    let raw = fs::read_to_string(&manifest_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", manifest_path.display()));
    let parsed: Value = serde_json::from_str(&raw).expect("valid JSON");
    let bifrost = &parsed["bifrost"];
    assert_eq!(bifrost["command"], "bifrost");
    let args = bifrost["args"]
        .as_array()
        .expect("args should be array");
    assert_eq!(args, &vec![Value::String("--server".into()), Value::String("lsp".into())]);
    let map = bifrost["extensionToLanguage"]
        .as_object()
        .expect("extensionToLanguage object");
    for ext in [".java", ".go", ".cpp", ".js", ".ts", ".py", ".rs", ".php", ".scala", ".cs"] {
        assert!(
            map.contains_key(ext),
            "{ext} should be mapped to a language: {map:?}"
        );
    }
}

#[test]
fn plugin_json_parses_with_required_fields() {
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".claude-plugin")
        .join("plugin.json");
    let raw = fs::read_to_string(&manifest_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", manifest_path.display()));
    let parsed: Value = serde_json::from_str(&raw).expect("valid JSON");
    assert_eq!(parsed["name"], "bifrost-lsp");
    assert!(
        parsed["description"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "description must be non-empty"
    );
}
