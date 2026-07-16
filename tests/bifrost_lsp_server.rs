mod common;

use brokk_bifrost::Language;
use brokk_bifrost::analyzer::structural::{
    RuneIrLanguage, RuneIrLimits, RuneIrSelection, render_source_rune_ir,
};
use common::lsp_client::{LspServer, uri_for};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Java fixture used by the completion-handler integration tests. `gree` on
/// line 3 is a stand-alone identifier prefix — tree-sitter still extracts the
/// surrounding declarations even though the body doesn't parse cleanly, so
/// the analyzer reports `greetEveryone` as a Function.
const COMPLETOR_JAVA_FIXTURE: &str = "public class Completor {\n    public void greetEveryone() {}\n    void caller() {\n        gree\n    }\n}\n";

fn write_completor_fixture(temp_root: &Path) -> std::path::PathBuf {
    let file = temp_root.join("Completor.java");
    fs::write(&file, COMPLETOR_JAVA_FIXTURE).expect("write Completor.java fixture");
    file
}

fn completion_client_capabilities() -> Value {
    json!({
        "textDocument": {
            "completion": {
                "completionItem": {
                    "snippetSupport": true
                }
            }
        }
    })
}

fn completion_initialize_params(root_uri: String) -> Value {
    json!({
        "processId": null,
        "rootUri": root_uri,
        "capabilities": completion_client_capabilities()
    })
}

fn semantic_token_client_capabilities() -> Value {
    json!({
        "textDocument": {
            "semanticTokens": {
                "requests": {"full": true, "range": true},
                "tokenTypes": ["namespace", "type", "function", "property", "macro"],
                "tokenModifiers": ["declaration"],
                "formats": ["relative"]
            }
        }
    })
}

fn semantic_token_initialize_params(root_uri: String) -> Value {
    json!({
        "processId": null,
        "rootUri": root_uri,
        "capabilities": semantic_token_client_capabilities()
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DecodedSemanticToken {
    line: u64,
    start: u64,
    length: u64,
    token_type: u64,
    modifiers: u64,
}

fn decode_semantic_tokens(response: &Value) -> Vec<DecodedSemanticToken> {
    assert!(
        response["error"].is_null(),
        "unexpected semantic token error: {response}"
    );
    let data = response["result"]["data"]
        .as_array()
        .unwrap_or_else(|| panic!("expected semantic token data array: {response}"));
    assert_eq!(data.len() % 5, 0, "invalid semantic token payload");

    let mut line = 0;
    let mut start = 0;
    data.chunks_exact(5)
        .map(|chunk| {
            let delta_line = chunk[0].as_u64().expect("delta line");
            let delta_start = chunk[1].as_u64().expect("delta start");
            line += delta_line;
            start = if delta_line == 0 {
                start + delta_start
            } else {
                delta_start
            };
            DecodedSemanticToken {
                line,
                start,
                length: chunk[2].as_u64().expect("length"),
                token_type: chunk[3].as_u64().expect("token type"),
                modifiers: chunk[4].as_u64().expect("modifiers"),
            }
        })
        .collect()
}

fn semantic_token_text(source: &str, token: &DecodedSemanticToken) -> String {
    let line = source
        .lines()
        .nth(token.line as usize)
        .unwrap_or_else(|| panic!("missing line {} in {source:?}", token.line));
    let mut utf16_position = 0_u64;
    let mut start_byte = None;
    let mut end_byte = None;
    for (byte, ch) in line.char_indices() {
        if utf16_position == token.start {
            start_byte = Some(byte);
        }
        utf16_position += ch.len_utf16() as u64;
        if utf16_position == token.start + token.length {
            end_byte = Some(byte + ch.len_utf8());
            break;
        }
    }
    if token.start == utf16_position && start_byte.is_none() {
        start_byte = Some(line.len());
    }
    let start_byte = start_byte.unwrap_or_else(|| panic!("invalid token start: {token:?}"));
    let end_byte = end_byte.unwrap_or_else(|| panic!("invalid token end: {token:?}"));
    line[start_byte..end_byte].to_string()
}

fn semantic_token_facts(source: &str, response: &Value) -> Vec<(String, u64, u64)> {
    decode_semantic_tokens(response)
        .into_iter()
        .map(|token| {
            (
                semantic_token_text(source, &token),
                token.token_type,
                token.modifiers,
            )
        })
        .collect()
}

struct JvmTypeContextFixtures {
    java_path: PathBuf,
    java_source: &'static str,
    csharp_path: PathBuf,
    csharp_source: &'static str,
    scala_path: PathBuf,
    scala_source: &'static str,
}

fn write_jvm_type_context_fixtures(root: &Path, prefix: &str) -> JvmTypeContextFixtures {
    let java_path = root.join(format!("{prefix}.java"));
    let java_source = "class Widget {}\nclass Child extends Widget {}\nclass Service {\n    Widget build() {\n        Widget local = new Widget();\n        return local;\n    }\n}\n";
    fs::write(&java_path, java_source).expect("write Java type-context fixture");

    let csharp_path = root.join(format!("{prefix}.cs"));
    let csharp_source = "class Widget {}\nclass Service { Widget Build() { Widget local = new Widget(); return local; } }\n";
    fs::write(&csharp_path, csharp_source).expect("write C# type-context fixture");

    let scala_path = root.join(format!("{prefix}.scala"));
    let scala_source = "class Widget\nclass Child extends Widget\nclass Service {\n  def build(): Widget = {\n    val local: Widget = new Widget\n    local\n  }\n}\n";
    fs::write(&scala_path, scala_source).expect("write Scala type-context fixture");

    JvmTypeContextFixtures {
        java_path,
        java_source,
        csharp_path,
        csharp_source,
        scala_path,
        scala_source,
    }
}

#[test]
fn bifrost_lsp_server_handles_initialize_and_shutdown() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let mut server = LspServer::spawn(&fixture_root);

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "processId": null,
            "rootUri": null,
            "capabilities": {}
        }
    }));
    let initialize = server.read_message();
    assert_eq!(initialize["id"], 1);
    assert!(
        initialize["result"]["capabilities"]["textDocumentSync"].is_object(),
        "textDocumentSync should be advertised: {initialize}"
    );
    assert_eq!(
        initialize["result"]["capabilities"]["textDocumentSync"]["change"], 2,
        "incremental text synchronization should be advertised: {initialize}"
    );
    assert_eq!(
        initialize["result"]["capabilities"]["codeActionProvider"]["codeActionKinds"],
        json!(["quickfix"]),
        "quick fixes should be advertised: {initialize}"
    );
    assert!(
        initialize["result"]["capabilities"]["completionProvider"].is_null(),
        "completionProvider should be omitted when the client advertises no completion sub-capabilities: {initialize}"
    );
    assert_eq!(
        initialize["result"]["capabilities"]["typeHierarchyProvider"], true,
        "typeHierarchyProvider should be advertised: {initialize}"
    );
    assert_eq!(
        initialize["result"]["capabilities"]["callHierarchyProvider"], true,
        "callHierarchyProvider should be advertised: {initialize}"
    );
    assert_eq!(
        initialize["result"]["capabilities"]["typeDefinitionProvider"], true,
        "typeDefinitionProvider should be advertised while the handler is supported: {initialize}"
    );
    assert_eq!(
        initialize["result"]["capabilities"]["implementationProvider"], true,
        "implementationProvider should be advertised while the handler is supported: {initialize}"
    );
    assert!(
        initialize["result"]["capabilities"]["signatureHelpProvider"].is_object(),
        "signatureHelpProvider should be advertised: {initialize}"
    );
    assert!(
        initialize["result"]["capabilities"]["signatureHelpProvider"]["triggerCharacters"]
            .is_null(),
        "signatureHelpProvider should require explicit client requests: {initialize}"
    );
    assert_eq!(
        initialize["result"]["capabilities"]["renameProvider"]["prepareProvider"], true,
        "renameProvider with prepare support should be advertised: {initialize}"
    );
    assert!(
        initialize["result"]["capabilities"]["documentFormattingProvider"].is_object(),
        "documentFormattingProvider should be advertised: {initialize}"
    );
    assert!(
        initialize["result"]["capabilities"]["semanticTokensProvider"].is_null(),
        "semanticTokensProvider should be omitted for clients without semantic-token support: {initialize}"
    );
    server.notify_value(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));

    server.notify_value(json!({"jsonrpc": "2.0", "id": 2, "method": "shutdown"}));
    let shutdown = server.read_message();
    assert_eq!(shutdown["id"], 2);
    assert!(shutdown["error"].is_null(), "unexpected error: {shutdown}");

    server.exit();
}

#[test]
fn bifrost_lsp_server_advertises_completion_when_client_supports_completion_items() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let mut server = LspServer::spawn(&fixture_root);

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": completion_initialize_params(uri_for(&fixture_root))
    }));
    let initialize = server.read_message();
    assert_eq!(initialize["id"], 1);
    assert!(
        initialize["result"]["capabilities"]["completionProvider"].is_object(),
        "completionProvider should be advertised when the client exposes completion sub-capabilities: {initialize}"
    );
    server.notify_value(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));

    server.notify_value(json!({"jsonrpc": "2.0", "id": 2, "method": "shutdown"}));
    let shutdown = server.read_message();
    assert_eq!(shutdown["id"], 2);
    assert!(shutdown["error"].is_null(), "unexpected error: {shutdown}");

    server.exit();
}

#[test]
fn bifrost_lsp_server_semantic_tokens_advertises_stable_full_legend() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");
    let mut server = LspServer::spawn(&fixture_root);

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": semantic_token_initialize_params(uri_for(&fixture_root))
    }));
    let initialize = server.read_message();
    let provider = &initialize["result"]["capabilities"]["semanticTokensProvider"];
    assert_eq!(
        provider["legend"]["tokenTypes"],
        json!(["namespace", "type", "function", "property", "macro"])
    );
    assert_eq!(provider["legend"]["tokenModifiers"], json!(["declaration"]));
    assert_eq!(provider["full"], true);
    assert!(provider["range"].is_null(), "range must remain deferred");

    server.notify_value(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));
    server.shutdown();
}

#[test]
fn bifrost_lsp_server_semantic_tokens_classifies_multi_language_symbols() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canonical root");
    let java_source = "class Widget {\n    Widget field;\n    void run() {}\n    void call() { run(); Widget local = field; }\n}\n";
    let typescript_source = "export class Gadget {\n  value = 1;\n  run() { return this.value; }\n}\nconst gadget = new Gadget();\ngadget.run();\n";
    let rust_source = "struct Thing { value: i32 }\nimpl Thing { fn run(&self) -> i32 { self.value } }\nfn call(item: Thing) -> i32 { item.run() }\n";
    let java_path = root.join("Widget.java");
    let typescript_path = root.join("gadget.ts");
    let rust_path = root.join("thing.rs");
    fs::write(&java_path, java_source).expect("write Java fixture");
    fs::write(&typescript_path, typescript_source).expect("write TypeScript fixture");
    fs::write(&rust_path, rust_source).expect("write Rust fixture");

    let mut server =
        LspServer::start_with_params(&root, semantic_token_initialize_params(uri_for(&root)));
    let java = semantic_token_facts(java_source, &server.semantic_tokens(&uri_for(&java_path)));
    let typescript = semantic_token_facts(
        typescript_source,
        &server.semantic_tokens(&uri_for(&typescript_path)),
    );
    let rust = semantic_token_facts(rust_source, &server.semantic_tokens(&uri_for(&rust_path)));

    assert!(java.contains(&("Widget".to_string(), 1, 1)), "{java:?}");
    assert!(java.contains(&("field".to_string(), 3, 1)), "{java:?}");
    assert!(java.contains(&("run".to_string(), 2, 1)), "{java:?}");
    assert!(java.contains(&("run".to_string(), 2, 0)), "{java:?}");
    assert!(
        typescript.contains(&("Gadget".to_string(), 1, 1)),
        "{typescript:?}"
    );
    assert!(
        typescript.contains(&("run".to_string(), 2, 0)),
        "{typescript:?}"
    );
    assert!(rust.contains(&("Thing".to_string(), 1, 1)), "{rust:?}");
    assert!(rust.contains(&("run".to_string(), 2, 0)), "{rust:?}");

    server.shutdown();
}

#[test]
fn bifrost_lsp_server_semantic_tokens_use_unicode_crlf_overlay() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canonical root");
    let file_path = root.join("Overlay.java");
    fs::write(&file_path, "class Disk { void disk() {} }\n").expect("write disk fixture");
    let overlay = "class Overlay {\r\n    void overlayOnly() {}\r\n    void call() { String emoji = \"😀\"; overlayOnly(); }\r\n}\r\n";
    let file_uri = uri_for(&file_path);
    let mut server =
        LspServer::start_with_params(&root, semantic_token_initialize_params(uri_for(&root)));

    server.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": file_uri,
                "languageId": "java",
                "version": 1,
                "text": overlay
            }
        }),
    );
    let response = server.semantic_tokens(&file_uri);
    let facts = semantic_token_facts(overlay, &response);
    assert!(
        facts.contains(&("Overlay".to_string(), 1, 1)),
        "overlay declaration missing: {facts:?}"
    );
    assert!(
        facts.contains(&("overlayOnly".to_string(), 2, 1)),
        "overlay function declaration missing: {facts:?}"
    );
    assert!(
        facts.contains(&("overlayOnly".to_string(), 2, 0)),
        "overlay function reference missing or UTF-16 position is wrong: {facts:?}"
    );
    assert!(
        facts
            .iter()
            .all(|(text, _, _)| text != "Disk" && text != "disk"),
        "disk-only symbols leaked through overlay: {facts:?}"
    );

    server.shutdown();
}

#[test]
fn bifrost_lsp_server_semantic_tokens_return_empty_for_unsupported_file() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canonical root");
    fs::write(root.join("Anchor.java"), "class Anchor {}\n").expect("write anchor");
    let unsupported = root.join("notes.txt");
    fs::write(&unsupported, "Anchor is plain text.\n").expect("write unsupported file");
    let mut server =
        LspServer::start_with_params(&root, semantic_token_initialize_params(uri_for(&root)));

    let response = server.semantic_tokens(&uri_for(&unsupported));
    assert!(response["error"].is_null(), "unexpected error: {response}");
    assert_eq!(response["result"]["data"], json!([]));

    server.shutdown();
}

#[test]
fn bifrost_lsp_server_semantic_tokens_bound_large_go_workspace_references() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canonical root");
    let source = "package main\ntype Thing struct{}\nfunc run() { run() }\n";
    let file_path = root.join("main.go");
    fs::write(&file_path, source).expect("write main Go fixture");
    for index in 0..64 {
        fs::write(
            root.join(format!("extra_{index}.go")),
            format!("package main\nvar Value{index} = {index}\n"),
        )
        .expect("write extra Go fixture");
    }
    let mut server =
        LspServer::start_with_params(&root, semantic_token_initialize_params(uri_for(&root)));

    let facts = semantic_token_facts(source, &server.semantic_tokens(&uri_for(&file_path)));
    assert!(facts.contains(&("Thing".to_string(), 1, 1)), "{facts:?}");
    assert!(facts.contains(&("run".to_string(), 2, 1)), "{facts:?}");
    assert!(
        !facts.contains(&("run".to_string(), 2, 0)),
        "large Go workspace should omit reference resolution: {facts:?}"
    );

    server.shutdown();
}

#[test]
fn bifrost_lsp_server_malformed_initialize_returns_error_response() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let mut server = LspServer::spawn(&fixture_root);

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "processId": null,
            "rootUri": null,
            "capabilities": null
        }
    }));
    let initialize = server.read_message();
    assert_eq!(initialize["id"], 1);
    assert!(
        initialize["result"].is_null(),
        "malformed initialize should not return a success result: {initialize}"
    );
    assert_eq!(
        initialize["error"]["code"], -32602,
        "malformed initialize should return InvalidParams: {initialize}"
    );
    assert!(
        initialize["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("Failed to decode InitializeParams")),
        "malformed initialize should explain the decode failure: {initialize}"
    );
}

#[test]
fn lsp_server_drop_cleanup_exits_cleanly_after_initialize() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let status = LspServer::start(&fixture_root)
        .drop_cleanup_status_for_test()
        .expect("wait bifrost");

    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[cfg(unix)]
#[test]
fn lsp_server_drop_reaps_child_process() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let child_id = {
        let server = LspServer::spawn(&fixture_root);
        server.child_id()
    };

    assert_no_child_process(child_id);
}

#[cfg(unix)]
fn assert_no_child_process(child_id: u32) {
    let mut status = 0;
    let wait_result = unsafe { libc::waitpid(child_id as libc::pid_t, &mut status, libc::WNOHANG) };
    assert_eq!(
        wait_result, -1,
        "expected child process {child_id} to be reaped"
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD),
        "expected child process {child_id} to no longer be waitable"
    );
}

#[test]
fn bifrost_lsp_server_indexes_all_startup_workspace_folders() {
    let temp = TempDir::new().expect("tempdir");
    let parent = temp.path().canonicalize().expect("canon temp");
    let root_a = parent.join("service-a");
    let root_b = parent.join("service-b");
    fs::create_dir_all(&root_a).expect("create service-a");
    fs::create_dir_all(&root_b).expect("create service-b");
    let alpha_path = root_a.join("Alpha.java");
    let beta_path = root_b.join("Beta.java");
    fs::write(
        &alpha_path,
        "class AlphaRoot {\n    void alphaOnly() {}\n}\n",
    )
    .expect("write Alpha.java");
    fs::write(&beta_path, "class BetaRoot {\n    void betaOnly() {}\n}\n")
        .expect("write Beta.java");

    let mut server = LspServer::spawn(&parent);

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "processId": null,
            "rootUri": null,
            "workspaceFolders": [
                {"uri": uri_for(&root_a), "name": "service-a"},
                {"uri": uri_for(&root_b), "name": "service-b"}
            ],
            "capabilities": {"workspace": {"workspaceFolders": true}}
        }
    }));
    let initialize = server.read_message();
    assert_eq!(initialize["id"], 1);
    assert_eq!(
        initialize["result"]["capabilities"]["workspace"]["workspaceFolders"]["supported"], true,
        "workspace folder support should be advertised: {initialize}"
    );
    assert_eq!(
        initialize["result"]["capabilities"]["workspace"]["workspaceFolders"]["changeNotifications"],
        true,
        "dynamic workspace folder changes should be advertised: {initialize}"
    );
    server.notify_value(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "workspace/symbol",
        "params": {"query": "Only"}
    }));
    let symbols_response = server.read_message();
    let symbols = symbols_response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected workspace symbols, got {symbols_response}"));
    assert!(
        symbols.iter().any(|symbol| symbol["name"] == "alphaOnly"),
        "expected alphaOnly from first root in {symbols:#?}"
    );
    assert!(
        symbols.iter().any(|symbol| symbol["name"] == "betaOnly"),
        "expected betaOnly from second root in {symbols:#?}"
    );

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "textDocument/documentSymbol",
        "params": {"textDocument": {"uri": uri_for(&beta_path)}}
    }));
    let document_symbols_response = server.read_message();
    assert_eq!(
        document_symbols_response["id"], 3,
        "expected documentSymbol response: {document_symbols_response}"
    );
    let document_symbols = document_symbols_response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected document symbols, got {document_symbols_response}"));
    assert!(
        document_symbols
            .iter()
            .any(|symbol| symbol["name"] == "BetaRoot"),
        "expected BetaRoot document symbol from second root in {document_symbols:#?}"
    );
}

#[test]
fn bifrost_lsp_server_runs_rql_queries_across_all_workspace_folders() {
    let temp = TempDir::new().expect("tempdir");
    let parent = temp.path().canonicalize().expect("canon temp");
    let root_a = parent.join("service-a");
    let root_b = parent.join("service-b");
    fs::create_dir_all(&root_a).expect("create service-a");
    fs::create_dir_all(&root_b).expect("create service-b");
    fs::write(root_a.join("Alpha.java"), "class AlphaRoot {}\n").expect("write Alpha.java");
    fs::write(root_b.join("Beta.java"), "class BetaRoot {}\n").expect("write Beta.java");

    let mut server = LspServer::start_with_params(
        &parent,
        json!({
            "processId": null,
            "rootUri": null,
            "workspaceFolders": [
                {"uri": uri_for(&root_a), "name": "service-a"},
                {"uri": uri_for(&root_b), "name": "service-b"}
            ],
            "capabilities": {"workspace": {"workspaceFolders": true}}
        }),
    );

    let response = server.request("bifrost/queryCode", json!({"query": "(class)"}));
    assert!(
        response["error"].is_null(),
        "unexpected query response: {response}"
    );

    let json_response = server.request(
        "bifrost/queryCode",
        json!({"query": r#"{"match":{"kind":"class"}}"#}),
    );
    assert!(json_response["error"].is_null(), "{json_response}");
    assert_eq!(
        json_response["result"]["results"].as_array().unwrap().len(),
        2
    );
    let text = response["result"]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("expected text result, got {response}"));
    assert!(text.contains("AlphaRoot"), "expected first root in {text}");
    assert!(text.contains("BetaRoot"), "expected second root in {text}");
    let results = response["result"]["results"]
        .as_array()
        .unwrap_or_else(|| panic!("expected typed query results, got {response}"));
    assert_eq!(
        results.len(),
        2,
        "expected both workspace roots in {response}"
    );
    assert!(
        results.iter().all(|result| {
            result["result_type"] == "structural_match"
                && result["uri"]
                    .as_str()
                    .is_some_and(|uri| uri.starts_with("file://"))
                && result["start_line"].as_u64().is_some()
        }),
        "expected navigable structural results in {response}"
    );

    let declarations = server.request(
        "bifrost/queryCode",
        json!({"query": "(enclosing-decl (class))"}),
    );
    let declaration_results = declarations["result"]["results"]
        .as_array()
        .unwrap_or_else(|| panic!("expected declaration results, got {declarations}"));
    assert_eq!(declaration_results.len(), 2, "{declarations}");
    assert!(
        declaration_results.iter().all(|result| {
            result["result_type"] == "declaration"
                && result["fq_name"].as_str().is_some()
                && result["start_line"].as_u64().is_some()
        }),
        "expected navigable declaration results in {declarations}"
    );

    let files = server.request("bifrost/queryCode", json!({"query": "(file-of (class))"}));
    let file_results = files["result"]["results"]
        .as_array()
        .unwrap_or_else(|| panic!("expected file results, got {files}"));
    assert_eq!(file_results.len(), 2, "{files}");
    assert!(
        file_results.iter().all(|result| {
            result["result_type"] == "file"
                && result["language"] == "java"
                && result["uri"]
                    .as_str()
                    .is_some_and(|uri| uri.starts_with("file://"))
        }),
        "expected navigable file results in {files}"
    );

    let invalid = server.request("bifrost/queryCode", json!({"query": "(class"}));
    assert_eq!(invalid["error"]["code"], -32602, "{invalid}");
    assert!(
        invalid["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("Failed to parse query source")),
        "expected source parse error, got {invalid}"
    );
}

#[test]
fn bifrost_lsp_server_renders_rune_ir_from_unsaved_overlay_and_indexed_code_units() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canonical root");
    let rust_path = root.join("live.rs");
    let ts_path = root.join("widget.ts");
    let tsx_path = root.join("view.tsx");
    fs::write(&rust_path, "fn disk_name() {}\n").expect("write Rust fixture");
    fs::write(&ts_path, "class DiskWidget {}\n").expect("write TypeScript fixture");
    fs::write(&tsx_path, "function DiskView() { return <div />; }\n").expect("write TSX fixture");
    let mut server = LspServer::start(&root);

    let rust_source = "/*😀*/ fn fresh_name() {\n    client.send(\"live\");\n}\n";
    server.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": uri_for(&rust_path),
                "languageId": "rust",
                "version": 1,
                "text": "fn disk_name() {}\n",
            }
        }),
    );
    server.notify(
        "textDocument/didChange",
        json!({
            "textDocument": {"uri": uri_for(&rust_path), "version": 2},
            "contentChanges": [{"text": rust_source}],
        }),
    );
    let response = server.request(
        "bifrost/runeIr",
        json!({
            "textDocument": {"uri": uri_for(&rust_path)},
            "position": {"line": 1, "character": 8},
        }),
    );
    assert!(response["error"].is_null(), "{response}");
    assert_eq!(response["result"]["codeUnit"], "fresh_name", "{response}");
    assert_eq!(
        response["result"]["sourceRange"]["start"],
        json!({"line": 0, "character": 7}),
        "the range must count the emoji as two UTF-16 units: {response}"
    );
    assert!(
        response["result"]["runeIr"]
            .as_str()
            .is_some_and(|text| text.contains(":name \"fresh_name\"")
                && text.contains("(callee")
                && !text.contains("disk_name")
                && !text.contains("function_item")),
        "{response}"
    );
    assert_eq!(
        response["result"]["starterRql"], "(function :name \"fresh_name\")",
        "{response}"
    );
    let rust_start = rust_source.find("fn fresh_name").unwrap();
    let rust_end = rust_source.rfind('}').unwrap() + 1;
    let direct = render_source_rune_ir(
        Language::Rust,
        rust_source,
        RuneIrSelection::ByteRange(rust_start..rust_end),
        RuneIrLimits::default(),
    )
    .unwrap();
    assert_eq!(response["result"]["runeIr"], direct.rune_ir);
    assert_eq!(response["result"]["starterRql"], direct.starter_rql);
    let display_text = response["result"]["displayText"]
        .as_str()
        .expect("Rune IR display text");
    assert!(
        display_text.starts_with("; Rune IR for fresh_name (rust)\n\n(function\n  :range "),
        "generated Rune IR should already use the document formatter: {display_text}"
    );
    assert!(
        display_text.ends_with("\n; Starter RQL\n(function :name \"fresh_name\")\n"),
        "{display_text}"
    );

    let ts_source = "class Widget {\n  value = 1;\n  constructor() {}\n  run() {}\n}\n";
    server.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": uri_for(&ts_path),
                "languageId": "typescript",
                "version": 1,
                "text": ts_source,
            }
        }),
    );
    for (line, expected) in [(0, "Widget"), (1, "value"), (2, "constructor"), (3, "run")] {
        let response = server.request(
            "bifrost/runeIr",
            json!({
                "textDocument": {"uri": uri_for(&ts_path)},
                "position": {"line": line, "character": 3},
            }),
        );
        assert!(response["error"].is_null(), "{response}");
        assert_eq!(response["result"]["codeUnit"], expected, "{response}");
    }

    let tsx_source = "function View() { return <div>{value}</div>; }\n";
    server.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": uri_for(&tsx_path),
                "languageId": "typescriptreact",
                "version": 1,
                "text": tsx_source,
            }
        }),
    );
    let response = server.request(
        "bifrost/runeIr",
        json!({
            "textDocument": {"uri": uri_for(&tsx_path)},
            "position": {"line": 0, "character": 10},
        }),
    );
    assert!(response["error"].is_null(), "{response}");
    assert_eq!(response["result"]["codeUnit"], "View", "{response}");
    assert!(
        response["result"]["displayText"]
            .as_str()
            .is_some_and(|text| text.starts_with("; Rune IR for View (tsx)")),
        "{response}"
    );
    assert!(
        response["result"]["runeIr"]
            .as_str()
            .is_some_and(|text| text.starts_with("(function") && text.contains(":name \"View\"")),
        "{response}"
    );
    let tsx_direct = render_source_rune_ir(
        RuneIrLanguage::for_path(Language::TypeScript, &tsx_path),
        tsx_source,
        RuneIrSelection::WholeSource,
        RuneIrLimits::default(),
    )
    .unwrap();
    assert_eq!(response["result"]["runeIr"], tsx_direct.rune_ir);

    let invalid = server.request(
        "bifrost/runeIr",
        json!({"textDocument": {"uri": uri_for(&rust_path)}}),
    );
    assert!(
        invalid["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("must provide `position` or `range`")),
        "{invalid}"
    );
}

#[test]
fn bifrost_lsp_server_validates_and_hovers_unsaved_rql_source() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canonical root");
    let mut server = LspServer::start(&root);

    for query in ["", "(call", "(call :callee", "{\"match\":"] {
        let response = server.request("bifrost/validateQuery", json!({"query": query}));
        assert_eq!(response["result"]["diagnostics"], json!([]), "{response}");
    }

    let rql = "(call :name \"😀\" :wat 1 :capture 2)";
    let response = server.request("bifrost/validateQuery", json!({"query": rql}));
    let diagnostics = response["result"]["diagnostics"].as_array().unwrap();
    assert_eq!(diagnostics.len(), 2, "{response}");
    let wat_byte = rql.find(":wat").unwrap();
    let wat_utf16 = rql[..wat_byte].encode_utf16().count() as u64;
    assert_eq!(diagnostics[0]["range"]["start"]["character"], wat_utf16);
    assert_eq!(diagnostics[0]["range"]["end"]["character"], wat_utf16 + 4);
    assert_eq!(diagnostics[0]["source"], "Bifrost RQL");

    let json_query = r#"{"match":{"kind":"banana","capture":3}}"#;
    let response = server.request("bifrost/validateQuery", json!({"query": json_query}));
    assert_eq!(
        response["result"]["diagnostics"].as_array().unwrap().len(),
        2
    );

    let malformed_json = r#"{"note":"😀","λ":1,]"#;
    let response = server.request("bifrost/validateQuery", json!({"query": malformed_json}));
    let diagnostic = &response["result"]["diagnostics"][0];
    let bad_byte = malformed_json.find(']').unwrap();
    let bad_utf16 = malformed_json[..bad_byte].encode_utf16().count() as u64;
    assert_eq!(diagnostic["range"]["start"]["character"], bad_utf16);
    assert_eq!(diagnostic["range"]["end"]["character"], bad_utf16 + 1);

    let hover = server.request(
        "bifrost/queryHover",
        json!({"query": "(call :callee (name \"run\"))", "position": {"line": 0, "character": 2}}),
    );
    assert_eq!(hover["result"]["range"]["start"]["character"], 1);
    assert_eq!(hover["result"]["range"]["end"]["character"], 5);
    assert!(
        hover["result"]["contents"]["value"]
            .as_str()
            .is_some_and(|value| value.contains("Match call expressions")),
        "{hover}"
    );

    let no_hover = server.request(
        "bifrost/queryHover",
        json!({"query": "(call ; comment\n)", "position": {"line": 0, "character": 9}}),
    );
    assert!(no_hover["result"].is_null(), "{no_hover}");

    let partial_json = r#"{"match":{"kind":"#;
    let partial_hover = server.request(
        "bifrost/queryHover",
        json!({
            "query": partial_json,
            "position": {"line": 0, "character": 11}
        }),
    );
    assert_eq!(partial_hover["result"]["range"]["start"]["character"], 10);
    assert_eq!(partial_hover["result"]["range"]["end"]["character"], 16);
    assert!(
        partial_hover["result"]["contents"]["value"]
            .as_str()
            .is_some_and(|value| value.contains("normalized node kinds")),
        "{partial_hover}"
    );
}

#[test]
fn bifrost_lsp_server_returns_current_rql_quick_fixes() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canonical root");
    let rql_path = root.join("query.rql");
    let rql_uri = uri_for(&rql_path);
    let mut server = LspServer::start(&root);

    let misspelled = "(call :name \"😀\" :calle (call))";
    server.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": rql_uri,
                "languageId": "bifrost-rql",
                "version": 1,
                "text": misspelled,
            }
        }),
    );
    let non_overlapping_actions = server.request(
        "textDocument/codeAction",
        json!({
            "textDocument": {"uri": uri_for(&rql_path)},
            "range": {"start": {"line": 0, "character": 0}, "end": {"line": 0, "character": 1}},
            "context": {"diagnostics": []},
        }),
    );
    assert_eq!(
        non_overlapping_actions["result"],
        json!([]),
        "only overlapping diagnostics should produce actions: {non_overlapping_actions}"
    );
    let adjacent_actions = server.request(
        "textDocument/codeAction",
        json!({
            "textDocument": {"uri": uri_for(&rql_path)},
            "range": {"start": {"line": 0, "character": 16}, "end": {"line": 0, "character": 17}},
            "context": {"diagnostics": []},
        }),
    );
    assert_eq!(
        adjacent_actions["result"],
        json!([]),
        "an end-exclusive selection adjacent to a diagnostic must not produce actions: {adjacent_actions}"
    );
    let actions = server.request(
        "textDocument/codeAction",
        json!({
            "textDocument": {"uri": uri_for(&rql_path)},
            "range": {"start": {"line": 0, "character": 0}, "end": {"line": 0, "character": 80}},
            "context": {"diagnostics": []},
        }),
    );
    let action = &actions["result"][0];
    assert_eq!(action["kind"], "quickfix", "{actions}");
    let document_edit = &action["edit"]["documentChanges"][0];
    assert_eq!(document_edit["textDocument"]["version"], 1, "{actions}");
    assert_eq!(document_edit["edits"][0]["newText"], ":callee");
    assert_eq!(
        document_edit["edits"][0]["range"]["start"]["character"], 17,
        "the range must use UTF-16 positions after an emoji: {actions}"
    );

    let wrapping = r#"{"where":"src/**/*.rs","match":{"kind":"call"}}"#;
    server.notify(
        "textDocument/didChange",
        json!({
            "textDocument": {"uri": uri_for(&rql_path), "version": 2},
            "contentChanges": [{"text": wrapping}],
        }),
    );
    let actions = server.request(
        "textDocument/codeAction",
        json!({
            "textDocument": {"uri": uri_for(&rql_path)},
            "range": {"start": {"line": 0, "character": 0}, "end": {"line": 0, "character": 80}},
            "context": {"diagnostics": []},
        }),
    );
    let document_edit = &actions["result"][0]["edit"]["documentChanges"][0];
    assert_eq!(document_edit["textDocument"]["version"], 2, "{actions}");
    let edits = document_edit["edits"].as_array().expect("wrapping edits");
    assert_eq!(edits.len(), 2, "paired wrapping edits: {actions}");
    assert_eq!(edits[0]["newText"], "[");
    assert_eq!(edits[1]["newText"], "]");

    server.notify(
        "textDocument/didChange",
        json!({
            "textDocument": {"uri": uri_for(&rql_path), "version": 3},
            "contentChanges": [{"text": "(call)"}],
        }),
    );
    let stale_actions = server.request(
        "textDocument/codeAction",
        json!({
            "textDocument": {"uri": uri_for(&rql_path)},
            "range": {"start": {"line": 0, "character": 0}, "end": {"line": 0, "character": 80}},
            "context": {"diagnostics": []},
        }),
    );
    assert_eq!(stale_actions["result"], json!([]), "{stale_actions}");

    let json_path = root.join("query.json");
    let json_uri = uri_for(&json_path);
    server.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": json_uri,
                "languageId": "json",
                "version": 1,
                "text": misspelled,
            }
        }),
    );
    let non_rql_actions = server.request(
        "textDocument/codeAction",
        json!({
            "textDocument": {"uri": uri_for(&json_path)},
            "range": {"start": {"line": 0, "character": 0}, "end": {"line": 0, "character": 80}},
            "context": {"diagnostics": []},
        }),
    );
    assert_eq!(non_rql_actions["result"], json!([]), "{non_rql_actions}");
}

#[test]
fn bifrost_lsp_server_honors_configured_roots() {
    let temp = TempDir::new().expect("tempdir");
    let parent = temp.path().canonicalize().expect("canon temp");
    let included = parent.join("included");
    let sibling = parent.join("sibling");
    fs::create_dir_all(&included).expect("create included");
    fs::create_dir_all(&sibling).expect("create sibling");
    fs::write(
        included.join("Included.java"),
        "class IncludedRoot {\n    void includedOnly() {}\n}\n",
    )
    .expect("write Included.java");
    fs::write(
        sibling.join("Sibling.java"),
        "class SiblingRoot {\n    void siblingLeak() {}\n}\n",
    )
    .expect("write Sibling.java");

    let mut server = LspServer::start_with_params(
        &parent,
        json!({
            "processId": null,
            "rootUri": uri_for(&parent),
            "workspaceFolders": [{"uri": uri_for(&parent), "name": "workspace"}],
            "initializationOptions": {
                "roots": [included.display().to_string()]
            },
            "capabilities": {"workspace": {"workspaceFolders": true}}
        }),
    );

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "workspace/symbol",
        "params": {"query": "Only"}
    }));
    let response = server.read_response_for_id(2);
    let symbols = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected workspace symbols, got {response}"));
    assert!(
        symbols
            .iter()
            .any(|symbol| symbol["name"] == "includedOnly"),
        "configured root should be indexed: {symbols:#?}"
    );
    assert!(
        symbols.iter().all(|symbol| symbol["name"] != "siblingLeak"),
        "workspace sibling outside configured roots should not be indexed: {symbols:#?}"
    );
}

#[test]
fn bifrost_lsp_server_honors_excluded_paths() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let src = root.join("src");
    let generated = root.join("generated");
    fs::create_dir_all(&src).expect("create src");
    fs::create_dir_all(&generated).expect("create generated");
    let kept_path = src.join("Kept.java");
    let excluded_path = generated.join("Generated.java");
    fs::write(&kept_path, "class KeptRoot {\n    void keptOnly() {}\n}\n")
        .expect("write Kept.java");
    fs::write(
        &excluded_path,
        "class GeneratedRoot {\n    void generatedLeak() {}\n}\n",
    )
    .expect("write Generated.java");

    let mut server = LspServer::start_with_params(
        &root,
        json!({
            "processId": null,
            "rootUri": uri_for(&root),
            "workspaceFolders": [{"uri": uri_for(&root), "name": "workspace"}],
            "initializationOptions": {
                "exclude": ["generated"]
            },
            "capabilities": {"workspace": {"workspaceFolders": true}}
        }),
    );

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "workspace/symbol",
        "params": {"query": "Only"}
    }));
    let symbols_response = server.read_response_for_id(2);
    let symbols = symbols_response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected workspace symbols, got {symbols_response}"));
    assert!(
        symbols.iter().any(|symbol| symbol["name"] == "keptOnly"),
        "non-excluded source should be indexed: {symbols:#?}"
    );

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "workspace/symbol",
        "params": {"query": "Leak"}
    }));
    let excluded_workspace_response = server.read_response_for_id(3);
    let excluded_workspace_symbols = excluded_workspace_response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected workspace symbols, got {excluded_workspace_response}"));
    assert!(
        excluded_workspace_symbols
            .iter()
            .all(|symbol| symbol["name"] != "generatedLeak"),
        "excluded source should not be indexed: {excluded_workspace_symbols:#?}"
    );

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "textDocument/documentSymbol",
        "params": {"textDocument": {"uri": uri_for(&excluded_path)}}
    }));
    let excluded_symbols_response = server.read_response_for_id(4);
    assert!(
        excluded_symbols_response["result"].is_null()
            || excluded_symbols_response["result"]
                .as_array()
                .is_some_and(|symbols| symbols.is_empty()),
        "excluded file should not resolve for documentSymbol: {excluded_symbols_response}"
    );
}

#[test]
fn bifrost_lsp_server_runtime_configuration_registers_and_pulls_bifrost_section() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    fs::write(root.join("Main.java"), "class Main {}\n").expect("write Main.java");
    let mut server = LspServer::spawn(&root);

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "processId": null,
            "rootUri": uri_for(&root),
            "capabilities": {
                "workspace": {
                    "configuration": true,
                    "didChangeConfiguration": {"dynamicRegistration": true}
                }
            }
        }
    }));
    let initialize = server.read_response_for_id(1);
    assert!(initialize["error"].is_null(), "{initialize}");
    server.notify_value(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));

    let registration = server.read_message();
    assert_eq!(registration["method"], "client/registerCapability");
    assert_eq!(
        registration["params"]["registrations"][0]["method"],
        "workspace/didChangeConfiguration"
    );
    assert_eq!(
        registration["params"]["registrations"][0]["registerOptions"]["section"],
        "bifrost"
    );
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": registration["id"].clone(),
        "result": null
    }));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "workspace/didChangeConfiguration",
        "params": {}
    }));
    let pull = server.read_message();
    assert_eq!(pull["method"], "workspace/configuration");
    assert_eq!(pull["params"]["items"], json!([{"section": "bifrost"}]));
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": pull["id"].clone(),
        "result": [{"roots": [], "exclude": [], "formatterCommands": []}]
    }));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 20,
        "method": "workspace/symbol",
        "params": {"query": "Main"}
    }));
    let response = server.read_response_for_id(20);
    assert!(response["error"].is_null(), "{response}");
    assert!(
        response["result"]
            .as_array()
            .is_some_and(|symbols| symbols.iter().any(|symbol| symbol["name"] == "Main")),
        "pulled runtime snapshot should leave the workspace usable: {response}"
    );
}

#[test]
fn bifrost_lsp_server_runtime_configuration_restores_latest_editor_roots_and_applies_excludes() {
    let temp = TempDir::new().expect("tempdir");
    let parent = temp.path().canonicalize().expect("canon temp");
    let root_a = parent.join("service-a");
    let root_b = parent.join("service-b");
    fs::create_dir_all(&root_a).expect("create service-a");
    fs::create_dir_all(&root_b).expect("create service-b");
    fs::write(
        root_a.join("Alpha.java"),
        "class AlphaRoot { void alphaRuntime() {} }\n",
    )
    .expect("write Alpha.java");
    fs::write(
        root_b.join("Beta.java"),
        "class BetaRoot { void betaRuntime() {} }\n",
    )
    .expect("write Beta.java");

    let mut server = LspServer::start_with_params(
        &parent,
        json!({
            "processId": null,
            "rootUri": uri_for(&parent),
            "workspaceFolders": [{"uri": uri_for(&root_a), "name": "service-a"}],
            "initializationOptions": {"roots": [root_a.display().to_string()]},
            "capabilities": {"workspace": {"workspaceFolders": true}}
        }),
    );
    server.notify(
        "workspace/didChangeWorkspaceFolders",
        json!({
            "event": {
                "added": [{"uri": uri_for(&root_b), "name": "service-b"}],
                "removed": []
            }
        }),
    );
    server.notify(
        "workspace/didChangeConfiguration",
        json!({
            "settings": {"bifrost": {"roots": [], "exclude": [], "formatterCommands": []}}
        }),
    );

    let restored = server.workspace_symbol("betaRuntime");
    assert!(
        restored["result"]
            .as_array()
            .is_some_and(|symbols| symbols.iter().any(|symbol| symbol["name"] == "betaRuntime")),
        "clearing configured roots should restore the latest editor roots: {restored}"
    );

    server.notify(
        "workspace/didChangeConfiguration",
        json!({
            "settings": {"roots": [], "exclude": ["service-b"], "formatterCommands": []}
        }),
    );
    let excluded = server.workspace_symbol("Runtime");
    let symbols = excluded["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected workspace symbols, got {excluded}"));
    assert!(
        symbols
            .iter()
            .any(|symbol| symbol["name"] == "alphaRuntime"),
        "non-excluded editor root should remain indexed: {excluded}"
    );
    assert!(
        symbols.iter().all(|symbol| symbol["name"] != "betaRuntime"),
        "runtime exclude should remove the second editor root: {excluded}"
    );
}

#[test]
fn bifrost_lsp_server_runtime_configuration_clears_departed_diagnostics() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file = root.join("Broken.java");
    fs::write(&file, "class Broken {}\n").expect("write Broken.java");
    let file_uri = uri_for(&file);
    let mut server = LspServer::start(&root);

    server.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": file_uri,
                "languageId": "java",
                "version": 1,
                "text": "class Broken { void broken( { }\n"
            }
        }),
    );
    let published = server.read_notification("textDocument/publishDiagnostics");
    assert!(
        published["params"]["diagnostics"]
            .as_array()
            .is_some_and(|diagnostics| !diagnostics.is_empty()),
        "fixture should publish a stale diagnostic before exclusion: {published}"
    );

    server.notify(
        "workspace/didChangeConfiguration",
        json!({
            "settings": {"roots": [], "exclude": ["Broken.java"], "formatterCommands": []}
        }),
    );
    let cleared = server.read_notification("textDocument/publishDiagnostics");
    assert_eq!(cleared["params"]["uri"], file_uri);
    assert_eq!(cleared["params"]["diagnostics"], json!([]));
}

#[test]
fn bifrost_lsp_server_runtime_configuration_replays_open_overlay_across_rebuild() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file = root.join("Overlay.java");
    fs::write(&file, "class Overlay { void diskOnly() {} }\n").expect("write Overlay.java");
    let file_uri = uri_for(&file);
    let mut server = LspServer::start(&root);

    server.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": file_uri,
                "languageId": "java",
                "version": 1,
            "text": "class Overlay { void overlayOnly() {} }\n"
            }
        }),
    );
    let _ = server.read_notification("textDocument/publishDiagnostics");
    server.notify(
        "workspace/didChangeConfiguration",
        json!({
            "settings": {"roots": [], "exclude": ["generated"], "formatterCommands": []}
        }),
    );

    let response = server.workspace_symbol("overlayOnly");
    assert!(
        response["result"]
            .as_array()
            .is_some_and(|symbols| symbols.iter().any(|symbol| symbol["name"] == "overlayOnly")),
        "open overlay should be replayed into the replacement analyzer: {response}"
    );
}

#[test]
fn bifrost_lsp_server_runtime_configuration_replays_overlay_opened_outside_explicit_roots() {
    let temp = TempDir::new().expect("tempdir");
    let parent = temp.path().canonicalize().expect("canon temp");
    let root_a = parent.join("service-a");
    let root_b = parent.join("service-b");
    fs::create_dir_all(&root_a).expect("create service-a");
    fs::create_dir_all(&root_b).expect("create service-b");
    fs::write(root_a.join("Alpha.java"), "class Alpha {}\n").expect("write Alpha.java");
    let file = root_b.join("Beta.java");
    fs::write(&file, "class Beta { void diskOnly() {} }\n").expect("write Beta.java");
    let file_uri = uri_for(&file);
    let mut server = LspServer::start_with_params(
        &parent,
        json!({
            "processId": null,
            "rootUri": uri_for(&parent),
            "workspaceFolders": [
                {"uri": uri_for(&root_a), "name": "service-a"},
                {"uri": uri_for(&root_b), "name": "service-b"}
            ],
            "initializationOptions": {"roots": [root_a.display().to_string()]},
            "capabilities": {"workspace": {"workspaceFolders": true}}
        }),
    );

    server.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": file_uri,
                "languageId": "java",
                "version": 1,
                "text": "class Beta { void inactiveOverlayOnly() {} }\n"
            }
        }),
    );
    server.notify(
        "textDocument/didChange",
        json!({
            "textDocument": {"uri": file_uri, "version": 2},
            "contentChanges": [{"text": "class Beta { void inactiveChangedOnly() {} }\n"}]
        }),
    );
    server.notify(
        "workspace/didChangeConfiguration",
        json!({
            "settings": {"roots": [], "exclude": [], "formatterCommands": []}
        }),
    );

    let response = server.workspace_symbol("inactiveChangedOnly");
    assert!(
        response["result"].as_array().is_some_and(|symbols| symbols
            .iter()
            .any(|symbol| symbol["name"] == "inactiveChangedOnly")),
        "an overlay changed outside explicit roots should be replayed when editor roots return: {response}"
    );
}

#[test]
fn bifrost_lsp_server_runtime_configuration_ignores_stale_and_malformed_pull_responses() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let hidden = root.join("hidden");
    fs::create_dir_all(&hidden).expect("create hidden");
    fs::write(
        hidden.join("Hidden.java"),
        "class Hidden { void hiddenRuntime() {} }\n",
    )
    .expect("write Hidden.java");
    let mut server = LspServer::start_with_params(
        &root,
        json!({
            "processId": null,
            "rootUri": uri_for(&root),
            "capabilities": {"workspace": {"configuration": true}}
        }),
    );

    server.notify(
        "workspace/didChangeConfiguration",
        json!({"settings": null}),
    );
    server.notify(
        "workspace/didChangeConfiguration",
        json!({"settings": null}),
    );
    let first_pull = server.read_message();
    let second_pull = server.read_message();
    assert_eq!(first_pull["method"], "workspace/configuration");
    assert_eq!(second_pull["method"], "workspace/configuration");
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": second_pull["id"].clone(),
        "result": [{"roots": [], "exclude": ["hidden"], "formatterCommands": []}]
    }));
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": first_pull["id"].clone(),
        "result": [{"roots": [], "exclude": [], "formatterCommands": []}]
    }));
    let after_newest = server.workspace_symbol("hiddenRuntime");
    assert_eq!(after_newest["result"], json!([]), "{after_newest}");

    server.notify(
        "workspace/didChangeConfiguration",
        json!({"settings": null}),
    );
    let malformed_pull = server.read_message();
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": malformed_pull["id"].clone(),
        "result": [{"roots": "not-an-array"}]
    }));
    let after_malformed = server.workspace_symbol("hiddenRuntime");
    assert_eq!(
        after_malformed["result"],
        json!([]),
        "malformed pull must preserve the last working exclusion: {after_malformed}"
    );

    server.notify(
        "workspace/didChangeConfiguration",
        json!({"settings": null}),
    );
    let failed_pull = server.read_message();
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": failed_pull["id"].clone(),
        "error": {"code": -32603, "message": "configuration unavailable"}
    }));
    let after_failure = server.workspace_symbol("hiddenRuntime");
    assert_eq!(
        after_failure["result"],
        json!([]),
        "failed pull must preserve the last working exclusion: {after_failure}"
    );

    server.notify(
        "workspace/didChangeConfiguration",
        json!({"settings": null}),
    );
    let wrong_shape_pull = server.read_message();
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": wrong_shape_pull["id"].clone(),
        "result": [
            {"roots": [], "exclude": [], "formatterCommands": []},
            {"roots": [], "exclude": [], "formatterCommands": []}
        ]
    }));
    let after_wrong_shape = server.workspace_symbol("hiddenRuntime");
    assert_eq!(
        after_wrong_shape["result"],
        json!([]),
        "wrong-shaped pull response must preserve the last working exclusion: {after_wrong_shape}"
    );
}

#[test]
fn bifrost_lsp_server_runtime_configuration_ignores_malformed_legacy_notification() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    fs::write(
        root.join("Main.java"),
        "class Main { void stillAlive() {} }\n",
    )
    .expect("write Main.java");
    let mut server = LspServer::start(&root);

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "workspace/didChangeConfiguration",
        "params": {}
    }));

    let response = server.workspace_symbol("stillAlive");
    assert!(
        response["result"]
            .as_array()
            .is_some_and(|symbols| symbols.iter().any(|symbol| symbol["name"] == "stillAlive")),
        "malformed legacy configuration notification must not terminate the server: {response}"
    );
}

#[cfg(unix)]
#[test]
fn bifrost_lsp_server_runtime_configuration_changes_formatter_for_later_requests() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file = root.join("lib.rs");
    let formatter = root.join("upper-runtime-format");
    fs::write(&file, "fn lower() {}\n").expect("write lib.rs");
    write_stub_command(&formatter, "#!/bin/sh\ntr '[:lower:]' '[:upper:]'\n");
    let mut server = LspServer::start(&root);

    server.notify(
        "workspace/didChangeConfiguration",
        json!({
            "settings": {
                "roots": [],
                "exclude": [],
                "formatterCommands": [{
                    "include": ["*.rs"],
                    "language": "rust",
                    "command": formatter.display().to_string()
                }]
            }
        }),
    );
    let response = formatting_response(&mut server, &uri_for(&file));
    assert_eq!(
        response["result"][0]["newText"], "FN LOWER() {}\n",
        "{response}"
    );

    server.notify(
        "workspace/didChangeConfiguration",
        json!({
            "settings": {
                "roots": [],
                "exclude": [],
                "formatterCommands": [{"include": ["*.rs"], "command": ""}]
            }
        }),
    );
    let after_invalid = formatting_response(&mut server, &uri_for(&file));
    assert_eq!(
        after_invalid["result"][0]["newText"], "FN LOWER() {}\n",
        "an invalid runtime formatter rule must preserve the last working snapshot: {after_invalid}"
    );
}

#[cfg(unix)]
#[test]
fn bifrost_lsp_server_runtime_configuration_rebuild_cancels_active_formatter() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file = root.join("lib.rs");
    let formatter = root.join("slow-runtime-format");
    fs::write(&file, "fn main() {}\n").expect("write lib.rs");
    write_stub_command(&formatter, "#!/bin/sh\nsleep 10\ncat\n");
    let mut server = LspServer::start_with_params(
        &root,
        json!({
            "processId": null,
            "rootUri": uri_for(&root),
            "capabilities": {},
            "initializationOptions": {
                "formatterCommands": [{
                    "include": ["*.rs"],
                    "command": formatter.display().to_string()
                }]
            }
        }),
    );
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 40,
        "method": "textDocument/formatting",
        "params": {
            "textDocument": {"uri": uri_for(&file)},
            "options": {"tabSize": 4, "insertSpaces": true}
        }
    }));
    server.notify(
        "workspace/didChangeConfiguration",
        json!({
            "settings": {"roots": [], "exclude": ["generated"], "formatterCommands": []}
        }),
    );

    let response = server.read_response_for_id(40);
    assert_eq!(response["error"]["code"], -32800, "{response}");
    let synchronized = server.workspace_symbol("main");
    assert!(synchronized["error"].is_null(), "{synchronized}");
}

#[cfg(windows)]
#[test]
fn bifrost_lsp_server_runtime_configuration_rebuild_releases_windows_children_and_handles() {
    let temp = TempDir::new().expect("tempdir");
    let parent = temp.path().canonicalize().expect("canon temp");
    let old_root = parent.join("old-root");
    let new_root = parent.join("new-root");
    fs::create_dir_all(&old_root).expect("create old root");
    fs::create_dir_all(&new_root).expect("create new root");
    let old_file = old_root.join("lib.rs");
    fs::write(&old_file, "fn old_root() {}\n").expect("write old file");
    fs::write(
        new_root.join("New.java"),
        "class NewRoot { void newRuntime() {} }\n",
    )
    .expect("write new file");
    let mut server = LspServer::start_with_params(
        &parent,
        json!({
            "processId": null,
            "rootUri": uri_for(&parent),
            "capabilities": {},
            "initializationOptions": {
                "roots": [old_root.display().to_string()],
                "formatterCommands": [{
                    "include": ["*.rs"],
                    "command": "cmd.exe",
                    "args": ["/D", "/S", "/C", "ping -n 30 127.0.0.1 >nul & more"]
                }]
            }
        }),
    );
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 41,
        "method": "textDocument/formatting",
        "params": {
            "textDocument": {"uri": uri_for(&old_file)},
            "options": {"tabSize": 4, "insertSpaces": true}
        }
    }));
    server.notify(
        "workspace/didChangeConfiguration",
        json!({
            "settings": {
                "roots": [new_root.display().to_string()],
                "exclude": [],
                "formatterCommands": []
            }
        }),
    );

    let canceled = server.read_response_for_id(41);
    assert_eq!(canceled["error"]["code"], -32800, "{canceled}");
    let synchronized = server.workspace_symbol("newRuntime");
    assert!(
        synchronized["result"]
            .as_array()
            .is_some_and(|symbols| symbols.iter().any(|symbol| symbol["name"] == "newRuntime")),
        "replacement workspace should be active before handle check: {synchronized}"
    );
    fs::remove_dir_all(&old_root)
        .expect("old root and .bifrost cache should have no live Windows handles");
}

#[test]
fn bifrost_lsp_server_adds_workspace_folder_dynamically() {
    let temp = TempDir::new().expect("tempdir");
    let parent = temp.path().canonicalize().expect("canon temp");
    let root_a = parent.join("service-a");
    let root_b = parent.join("service-b");
    let outside = parent.join("outside");
    fs::create_dir_all(&root_a).expect("create service-a");
    fs::create_dir_all(&root_b).expect("create service-b");
    fs::create_dir_all(&outside).expect("create outside");
    fs::write(
        root_a.join("Alpha.java"),
        "class AlphaRoot {\n    void alphaOnly() {}\n}\n",
    )
    .expect("write Alpha.java");
    let beta_path = root_b.join("Beta.java");
    fs::write(
        &beta_path,
        "class BetaRoot {\n    void betaDynamic() {}\n}\n",
    )
    .expect("write Beta.java");
    fs::write(
        outside.join("Outside.java"),
        "class OutsideRoot {\n    void outsideLeak() {}\n}\n",
    )
    .expect("write Outside.java");

    let mut server = LspServer::start_with_params(
        &parent,
        json!({
            "processId": null,
            "rootUri": null,
            "workspaceFolders": [{"uri": uri_for(&root_a), "name": "service-a"}],
            "capabilities": {"workspace": {"workspaceFolders": true}}
        }),
    );

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "workspace/didChangeWorkspaceFolders",
        "params": {
            "event": {
                "added": [{"uri": uri_for(&root_b), "name": "service-b"}],
                "removed": []
            }
        }
    }));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "workspace/symbol",
        "params": {"query": "Dynamic"}
    }));
    let symbols_response = server.read_response_for_id(2);
    let symbols = symbols_response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected workspace symbols, got {symbols_response}"));
    assert!(
        symbols.iter().any(|symbol| symbol["name"] == "betaDynamic"),
        "expected betaDynamic from added root in {symbols:#?}"
    );

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "textDocument/documentSymbol",
        "params": {"textDocument": {"uri": uri_for(&beta_path)}}
    }));
    let document_symbols_response = server.read_response_for_id(3);
    let document_symbols = document_symbols_response["result"]
        .as_array()
        .unwrap_or_else(|| {
            panic!("expected document symbols from added root, got {document_symbols_response}")
        });
    assert!(
        document_symbols
            .iter()
            .any(|symbol| symbol["name"] == "BetaRoot"),
        "expected BetaRoot document symbol from added root in {document_symbols:#?}"
    );

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "workspace/symbol",
        "params": {"query": "outsideLeak"}
    }));
    let outside_response = server.read_response_for_id(4);
    let outside_symbols = outside_response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected workspace symbols, got {outside_response}"));
    assert!(
        outside_symbols.is_empty(),
        "sibling outside active workspace folders should not be indexed: {outside_symbols:#?}"
    );
}

#[test]
fn bifrost_lsp_server_removes_workspace_folder_dynamically() {
    let temp = TempDir::new().expect("tempdir");
    let parent = temp.path().canonicalize().expect("canon temp");
    let root_a = parent.join("service-a");
    let root_b = parent.join("service-b");
    fs::create_dir_all(&root_a).expect("create service-a");
    fs::create_dir_all(&root_b).expect("create service-b");
    let request_path = root_a.join("Requester.java");
    let removed_path = root_b.join("Removed.java");
    fs::write(
        &request_path,
        "class Requester {\n    void caller() {\n        removed\n    }\n}\n",
    )
    .expect("write Requester.java");
    fs::write(
        &removed_path,
        "class RemovedRoot {\n    void removedCompletion() {}\n    void broken( {\n}\n",
    )
    .expect("write Removed.java");

    let mut server = LspServer::start_with_params(
        &parent,
        json!({
            "processId": null,
            "rootUri": null,
            "workspaceFolders": [
                {"uri": uri_for(&root_a), "name": "service-a"},
                {"uri": uri_for(&root_b), "name": "service-b"}
            ],
            "capabilities": completion_client_capabilities()
        }),
    );

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/completion",
        "params": {
            "textDocument": {"uri": uri_for(&request_path)},
            "position": {"line": 2, "character": 15}
        }
    }));
    let before_completion = server.read_response_for_id(2);
    let before_items = before_completion["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("expected completion items, got {before_completion}"));
    assert!(
        before_items
            .iter()
            .any(|item| item["label"] == "removedCompletion"),
        "expected completion from second root before removal: {before_items:#?}"
    );

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didSave",
        "params": {"textDocument": {"uri": uri_for(&removed_path)}}
    }));
    let publish_before = server.read_notification("textDocument/publishDiagnostics");
    assert_eq!(
        publish_before["params"]["uri"],
        uri_for(&removed_path),
        "expected diagnostics for removed-root file before removal: {publish_before}"
    );
    assert!(
        !publish_before["params"]["diagnostics"]
            .as_array()
            .unwrap_or_else(|| panic!("expected diagnostics array, got {publish_before}"))
            .is_empty(),
        "expected parse diagnostics before removing root: {publish_before}"
    );

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "workspace/didChangeWorkspaceFolders",
        "params": {
            "event": {
                "added": [],
                "removed": [{"uri": uri_for(&root_b), "name": "service-b"}]
            }
        }
    }));
    let publish_clear = server.read_notification("textDocument/publishDiagnostics");
    assert_eq!(
        publish_clear["params"]["uri"],
        uri_for(&removed_path),
        "expected removed-root diagnostics to be cleared: {publish_clear}"
    );
    assert!(
        publish_clear["params"]["diagnostics"]
            .as_array()
            .unwrap_or_else(|| panic!("expected diagnostics array, got {publish_clear}"))
            .is_empty(),
        "expected empty diagnostics after root removal: {publish_clear}"
    );

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "workspace/symbol",
        "params": {"query": "removedCompletion"}
    }));
    let after_symbols = server.read_response_for_id(3);
    let symbols = after_symbols["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected workspace symbols, got {after_symbols}"));
    assert!(
        symbols.is_empty(),
        "removed root symbols should disappear: {symbols:#?}"
    );

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "textDocument/completion",
        "params": {
            "textDocument": {"uri": uri_for(&request_path)},
            "position": {"line": 2, "character": 15}
        }
    }));
    let after_completion = server.read_response_for_id(4);
    let after_items = after_completion["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("expected completion items, got {after_completion}"));
    assert!(
        !after_items
            .iter()
            .any(|item| item["label"] == "removedCompletion"),
        "completion cache should not retain removed-root symbols: {after_items:#?}"
    );

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "textDocument/documentSymbol",
        "params": {"textDocument": {"uri": uri_for(&removed_path)}}
    }));
    let removed_document = server.read_response_for_id(5);
    assert!(
        removed_document["result"].is_null(),
        "document requests should no longer route to removed roots: {removed_document}"
    );
}

#[test]
fn bifrost_lsp_server_replays_open_document_after_workspace_folder_readd() {
    let temp = TempDir::new().expect("tempdir");
    let parent = temp.path().canonicalize().expect("canon temp");
    let root_a = parent.join("service-a");
    let root_b = parent.join("service-b");
    fs::create_dir_all(&root_a).expect("create service-a");
    fs::create_dir_all(&root_b).expect("create service-b");
    fs::write(root_a.join("Alpha.java"), "class AlphaRoot {}\n").expect("write Alpha.java");
    let beta_path = root_b.join("Beta.java");
    fs::write(&beta_path, "class BetaRoot {\n    void diskOnly() {}\n}\n")
        .expect("write Beta.java");

    let mut server = LspServer::start_with_params(
        &parent,
        json!({
            "processId": null,
            "rootUri": null,
            "workspaceFolders": [
                {"uri": uri_for(&root_a), "name": "service-a"},
                {"uri": uri_for(&root_b), "name": "service-b"}
            ],
            "capabilities": {}
        }),
    );

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didOpen",
        "params": {
            "textDocument": {
                "uri": uri_for(&beta_path),
                "languageId": "java",
                "version": 1,
                "text": "class BetaRoot {\n    void overlayOnly() {}\n}\n"
            }
        }
    }));
    let _ = server.read_notification("textDocument/publishDiagnostics");

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "workspace/didChangeWorkspaceFolders",
        "params": {
            "event": {
                "added": [],
                "removed": [{"uri": uri_for(&root_b), "name": "service-b"}]
            }
        }
    }));
    // The client still owns the open document while its workspace root is
    // absent. Preserve incremental text/version state for the later rebuild.
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didChange",
        "params": {
            "textDocument": {"uri": uri_for(&beta_path), "version": 2},
            "contentChanges": [{
                "range": {
                    "start": {"line": 1, "character": 9},
                    "end": {"line": 1, "character": 20}
                },
                "text": "updatedOutsideRoot"
            }]
        }
    }));
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "workspace/didChangeWorkspaceFolders",
        "params": {
            "event": {
                "added": [{"uri": uri_for(&root_b), "name": "service-b"}],
                "removed": []
            }
        }
    }));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "workspace/symbol",
        "params": {"query": "updatedOutsideRoot"}
    }));
    let response = server.read_response_for_id(2);
    let symbols = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected workspace symbols, got {response}"));
    assert!(
        symbols
            .iter()
            .any(|symbol| symbol["name"] == "updatedOutsideRoot"),
        "re-added root should replay the latest still-open document overlay: {symbols:#?}"
    );
}

#[cfg(unix)]
#[test]
fn bifrost_lsp_server_removes_symlinked_workspace_folder_after_symlink_disappears() {
    let temp = TempDir::new().expect("tempdir");
    let parent = temp.path().canonicalize().expect("canon temp");
    let real_root = parent.join("real-service");
    let link_root = parent.join("linked-service");
    fs::create_dir_all(&real_root).expect("create real service");
    std::os::unix::fs::symlink(&real_root, &link_root).expect("create root symlink");
    fs::write(
        real_root.join("Linked.java"),
        "class LinkedRoot {\n    void linkedOnly() {}\n}\n",
    )
    .expect("write Linked.java");
    let link_uri = uri_for(&link_root);

    let mut server = LspServer::start_with_params(
        &parent,
        json!({
            "processId": null,
            "rootUri": null,
            "workspaceFolders": [{"uri": link_uri, "name": "linked-service"}],
            "capabilities": {}
        }),
    );

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "workspace/symbol",
        "params": {"query": "linkedOnly"}
    }));
    let before = server.read_response_for_id(2);
    let before_symbols = before["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected workspace symbols, got {before}"));
    assert!(
        before_symbols
            .iter()
            .any(|symbol| symbol["name"] == "linkedOnly"),
        "expected linked root symbol before removal: {before_symbols:#?}"
    );

    fs::remove_file(&link_root).expect("remove root symlink");
    assert!(
        !link_root.exists(),
        "root symlink should be gone before removal notification"
    );
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "workspace/didChangeWorkspaceFolders",
        "params": {
            "event": {
                "added": [],
                "removed": [{"uri": link_uri, "name": "linked-service"}]
            }
        }
    }));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "workspace/symbol",
        "params": {"query": "linkedOnly"}
    }));
    let response = server.read_response_for_id(3);
    let symbols = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected workspace symbols, got {response}"));
    assert!(
        symbols.is_empty(),
        "removing the original symlink URI should remove its canonical analyzer root: {symbols:#?}"
    );
}

#[test]
fn bifrost_lsp_server_ignores_invalid_dynamic_workspace_folder_additions() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let not_a_dir = root.join("NotADir.java");
    fs::write(
        root.join("Alpha.java"),
        "class AlphaRoot {\n    void alphaStillIndexed() {}\n}\n",
    )
    .expect("write Alpha.java");
    fs::write(&not_a_dir, "class NotADir {}\n").expect("write NotADir.java");

    let mut server = LspServer::start(&root);
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "workspace/didChangeWorkspaceFolders",
        "params": {
            "event": {
                "added": [
                    {"uri": "untitled:dynamic-root", "name": "bad-scheme"},
                    {"uri": uri_for(&not_a_dir), "name": "not-a-dir"}
                ],
                "removed": []
            }
        }
    }));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "workspace/symbol",
        "params": {"query": "alphaStillIndexed"}
    }));
    let response = server.read_response_for_id(2);
    let symbols = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected workspace symbols, got {response}"));
    assert!(
        symbols
            .iter()
            .any(|symbol| symbol["name"] == "alphaStillIndexed"),
        "invalid additions should not disturb the existing workspace: {symbols:#?}"
    );
}

#[test]
fn bifrost_lsp_server_indexes_new_file_in_second_workspace_folder() {
    let temp = TempDir::new().expect("tempdir");
    let parent = temp.path().canonicalize().expect("canon temp");
    let root_a = parent.join("service-a");
    let root_b = parent.join("service-b");
    fs::create_dir_all(&root_a).expect("create service-a");
    fs::create_dir_all(&root_b).expect("create service-b");
    fs::write(
        root_a.join("Alpha.java"),
        "class AlphaRoot {\n    void alphaOnly() {}\n}\n",
    )
    .expect("write Alpha.java");

    let mut server = LspServer::spawn(&parent);
    let beta_path = root_b.join("Beta.java");
    let beta_uri = uri_for(&beta_path);

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "processId": null,
            "rootUri": null,
            "workspaceFolders": [
                {"uri": uri_for(&root_a), "name": "service-a"},
                {"uri": uri_for(&root_b), "name": "service-b"}
            ],
            "capabilities": {}
        }
    }));
    let initialize = server.read_message();
    assert_eq!(initialize["id"], 1);
    server.notify_value(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));

    fs::write(
        &beta_path,
        "class BetaRoot {\n    void betaCreatedLater() {}\n}\n",
    )
    .expect("write Beta.java");
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "workspace/didChangeWatchedFiles",
        "params": {
            "changes": [{"uri": beta_uri, "type": 1}]
        }
    }));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "workspace/symbol",
        "params": {"query": "betaCreatedLater"}
    }));
    let response = server.read_message();
    let symbols = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected workspace symbols, got {response}"));
    assert!(
        symbols
            .iter()
            .any(|symbol| symbol["name"] == "betaCreatedLater"),
        "expected newly created second-root symbol in {symbols:#?}"
    );
}

#[test]
fn bifrost_lsp_server_watched_delete_removes_workspace_symbol() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("Watch.java");
    fs::write(&file_path, "class Watch {\n    void removedLater() {}\n}\n")
        .expect("write Watch.java");

    let mut server = LspServer::spawn(&root);
    let file_uri = uri_for(&file_path);

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"processId": null, "rootUri": uri_for(&root), "capabilities": {}}
    }));
    let initialize = server.read_message();
    assert_eq!(initialize["id"], 1);
    server.notify_value(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "workspace/symbol",
        "params": {"query": "removedLater"}
    }));
    let before = server.read_message();
    let before_symbols = before["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected workspace symbols, got {before}"));
    assert!(
        before_symbols
            .iter()
            .any(|symbol| symbol["name"] == "removedLater"),
        "expected symbol before delete in {before_symbols:#?}"
    );

    fs::remove_file(&file_path).expect("delete Watch.java");
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "workspace/didChangeWatchedFiles",
        "params": {
            "changes": [{"uri": file_uri, "type": 3}]
        }
    }));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "workspace/symbol",
        "params": {"query": "removedLater"}
    }));
    let after = server.read_message();
    let after_symbols = after["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected workspace symbols, got {after}"));
    assert!(
        !after_symbols
            .iter()
            .any(|symbol| symbol["name"] == "removedLater"),
        "deleted file symbol should be gone, got {after_symbols:#?}"
    );
}

#[test]
fn bifrost_lsp_server_falls_back_to_root_uri_when_workspace_folders_null() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("Fallback.java");
    fs::write(
        &file_path,
        "class FallbackRoot {\n    void fallbackOnly() {}\n}\n",
    )
    .expect("write Fallback.java");

    let mut server = LspServer::spawn(&root.join("unused-fallback"));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "processId": null,
            "rootUri": uri_for(&root),
            "workspaceFolders": null,
            "capabilities": {}
        }
    }));
    let initialize = server.read_message();
    assert_eq!(initialize["id"], 1);
    server.notify_value(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/documentSymbol",
        "params": {"textDocument": {"uri": uri_for(&file_path)}}
    }));
    let response = server.read_message();
    assert_eq!(
        response["id"], 2,
        "expected documentSymbol response: {response}"
    );
    let symbols = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected document symbols, got {response}"));
    assert!(
        symbols
            .iter()
            .any(|symbol| symbol["name"] == "FallbackRoot"),
        "expected rootUri-backed document symbol in {symbols:#?}"
    );
}

#[test]
fn bifrost_lsp_server_reports_cold_start_progress_when_client_supports_it() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("ProgressFixture.java");
    fs::write(
        &file_path,
        "class ProgressFixture {\n    void work() {}\n}\n",
    )
    .expect("write progress fixture");
    fs::write(
        root.join("progress_fixture.py"),
        "def work():\n    return 1\n",
    )
    .expect("write python progress fixture");

    let mut server = LspServer::spawn(&root);

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "processId": null,
            "rootUri": uri_for(&root),
            "capabilities": {"window": {"workDoneProgress": true}}
        }
    }));
    let initialize = server.read_message();
    assert_eq!(initialize["id"], 1);
    server.notify_value(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));

    let create = server.read_message();
    assert_eq!(create["method"], "window/workDoneProgress/create");
    let token = create["params"]["token"].clone();
    assert_eq!(token, "bifrost-startup-index");
    server.notify_value(json!({"jsonrpc": "2.0", "id": create["id"].clone(), "result": null}));

    let begin = server.read_notification("$/progress");
    assert_eq!(begin["params"]["token"], token);
    assert_eq!(begin["params"]["value"]["kind"], "begin");
    assert_eq!(
        begin["params"]["value"]["title"], "Indexing workspace",
        "unexpected begin payload: {begin}"
    );

    let mut saw_report = false;
    let mut saw_end = false;
    let mut last_percentage = 0;
    let mut saw_java_index = false;
    let mut saw_python_after_java_index = false;
    for _ in 0..32 {
        let msg = server.read_notification("$/progress");
        assert_eq!(msg["params"]["token"], token);
        match msg["params"]["value"]["kind"].as_str() {
            Some("report") => {
                saw_report = true;
                let percentage = msg["params"]["value"]["percentage"]
                    .as_u64()
                    .unwrap_or_else(|| panic!("startup report must include percentage: {msg}"));
                assert!(
                    percentage <= 99,
                    "startup reports should leave completion to end: {msg}"
                );
                assert!(
                    percentage >= last_percentage,
                    "startup report percentages should not move backwards: {msg}"
                );
                last_percentage = percentage;
                let message = msg["params"]["value"]["message"]
                    .as_str()
                    .unwrap_or_default();
                if message.contains("Indexed Java declarations") {
                    saw_java_index = true;
                    assert!(
                        percentage < 99,
                        "first language index must not complete multi-language startup: {msg}"
                    );
                }
                if saw_java_index && message.contains("Python") {
                    saw_python_after_java_index = true;
                }
            }
            Some("end") => {
                saw_end = true;
                break;
            }
            other => panic!("unexpected progress kind {other:?}: {msg}"),
        }
    }
    assert!(saw_report, "expected at least one progress report");
    assert!(saw_java_index, "expected Java index progress report");
    assert!(
        saw_python_after_java_index,
        "expected Python progress after Java index report"
    );
    assert!(saw_end, "expected final progress end notification");

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/documentSymbol",
        "params": {"textDocument": {"uri": uri_for(&file_path)}}
    }));
    let symbols = server.read_response_for_id(2);
    assert!(
        symbols["result"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "documentSymbol should still work after startup progress: {symbols}"
    );

    server.notify_value(json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}));
    let _ = server.read_response_for_id(3);
    server.exit();
}

#[test]
fn bifrost_lsp_server_replays_did_open_sent_before_startup_progress_response() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("EarlyOpen.java");
    fs::write(&file_path, "class DiskOnly {}\n").expect("write fixture");
    let uri = uri_for(&file_path);
    let overlay_text = "class OverlayOnly {}\n";

    let mut server = LspServer::spawn(&root);

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "processId": null,
            "rootUri": uri_for(&root),
            "capabilities": {"window": {"workDoneProgress": true}}
        }
    }));
    let initialize = server.read_message();
    assert_eq!(initialize["id"], 1);
    server.notify_value(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));

    let create = server.read_message();
    assert_eq!(create["method"], "window/workDoneProgress/create");
    let token = create["params"]["token"].clone();

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didOpen",
        "params": {
            "textDocument": {
                "uri": uri,
                "languageId": "java",
                "version": 1,
                "text": overlay_text
            }
        }
    }));
    server.notify_value(json!({"jsonrpc": "2.0", "id": create["id"].clone(), "result": null}));

    let begin = server.read_notification("$/progress");
    assert_eq!(begin["params"]["token"], token);
    assert_eq!(begin["params"]["value"]["kind"], "begin");
    let mut saw_end = false;
    for _ in 0..32 {
        let msg = server.read_notification("$/progress");
        if msg["params"]["value"]["kind"] == "end" {
            saw_end = true;
            break;
        }
    }
    assert!(saw_end, "expected startup progress to finish");

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/hover",
        "params": {
            "textDocument": {"uri": uri_for(&file_path)},
            "position": {"line": 0, "character": 8}
        }
    }));
    let hover = server.read_response_for_id(2);
    let hover_text = hover["result"]["contents"]["value"]
        .as_str()
        .unwrap_or_default();
    assert!(
        hover_text.contains("OverlayOnly"),
        "hover should use replayed didOpen overlay, got {hover}"
    );

    server.notify_value(json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}));
    let _ = server.read_response_for_id(3);
    server.exit();
}

#[test]
fn bifrost_lsp_server_skips_startup_progress_without_client_support() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("NoProgress.java");
    fs::write(&file_path, "class NoProgress {}\n").expect("write fixture");

    let mut server = LspServer::spawn(&root);

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "processId": null,
            "rootUri": uri_for(&root),
            "capabilities": {}
        }
    }));
    let initialize = server.read_message();
    assert_eq!(initialize["id"], 1);
    server.notify_value(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/documentSymbol",
        "params": {"textDocument": {"uri": uri_for(&file_path)}}
    }));
    let response = server.read_message();
    assert_ne!(
        response["method"], "window/workDoneProgress/create",
        "server must not create progress when client did not advertise support"
    );
    assert_ne!(
        response["method"], "$/progress",
        "server must not emit progress when client did not advertise support"
    );
    assert_eq!(
        response["id"], 2,
        "expected documentSymbol response: {response}"
    );
    let symbols = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected document symbols, got {response}"));
    assert!(
        symbols.iter().any(|symbol| symbol["name"] == "NoProgress"),
        "server should still answer analyzer-backed requests for clients without work-done progress (progress support is a UI capability, unrelated to indexing): {symbols:#?}"
    );

    server.notify_value(json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}));
    let _ = server.read_response_for_id(3);
    server.exit();
}

#[test]
fn bifrost_lsp_server_disables_startup_progress_when_token_create_fails() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("RejectedProgress.java");
    fs::write(&file_path, "class RejectedProgress {}\n").expect("write fixture");

    let mut server = LspServer::spawn(&root);

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "processId": null,
            "rootUri": uri_for(&root),
            "capabilities": {"window": {"workDoneProgress": true}}
        }
    }));
    let initialize = server.read_message();
    assert_eq!(initialize["id"], 1);
    server.notify_value(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));

    let create = server.read_message();
    assert_eq!(create["method"], "window/workDoneProgress/create");
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": create["id"].clone(),
        "error": {"code": -32603, "message": "token rejected"}
    }));
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/documentSymbol",
        "params": {"textDocument": {"uri": uri_for(&file_path)}}
    }));
    let response = server.read_message();
    assert_ne!(
        response["method"], "$/progress",
        "server must not emit progress after token creation fails"
    );
    assert_eq!(
        response["id"], 2,
        "expected documentSymbol response after rejected progress token: {response}"
    );
    let symbols = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected document symbols, got {response}"));
    assert!(
        symbols
            .iter()
            .any(|symbol| symbol["name"] == "RejectedProgress"),
        "server should still answer analyzer-backed requests after progress token creation fails (progress reporting is independent of indexing): {symbols:#?}"
    );

    server.notify_value(json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}));
    let _ = server.read_response_for_id(3);
    server.exit();
}

#[test]
fn bifrost_lsp_server_returns_document_symbols_for_a_java() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let mut server = LspServer::spawn(&fixture_root);

    let canonical_root = fixture_root.canonicalize().expect("canon fixture");
    let root_uri = uri_for(&canonical_root);
    let file_uri = uri_for(&canonical_root.join("A.java"));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "processId": null,
            "rootUri": root_uri,
            "capabilities": {}
        }
    }));
    let init = server.read_message();
    assert_eq!(init["id"], 1);
    assert_eq!(
        init["result"]["capabilities"]["documentSymbolProvider"], true,
        "documentSymbolProvider should be advertised: {init}"
    );
    server.notify_value(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/documentSymbol",
        "params": {"textDocument": {"uri": file_uri}}
    }));
    let response = server.read_message();
    assert_eq!(response["id"], 2);
    let symbols = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected array result, got {response}"));

    let class_a = symbols
        .iter()
        .find(|sym| sym["name"] == "A")
        .unwrap_or_else(|| panic!("class A not present: {symbols:#?}"));
    assert_eq!(class_a["kind"], 5, "class kind"); // SymbolKind::CLASS = 5

    let children = class_a["children"]
        .as_array()
        .unwrap_or_else(|| panic!("class A should have children: {class_a}"));
    let child_names: Vec<&str> = children.iter().filter_map(|c| c["name"].as_str()).collect();
    for expected in ["method1", "method2", "AInner", "AInnerStatic"] {
        assert!(
            child_names.contains(&expected),
            "expected {expected} in {child_names:?}"
        );
    }

    let inner = children
        .iter()
        .find(|c| c["name"] == "AInner")
        .expect("AInner");
    let inner_children: Vec<&str> = inner["children"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|c| c["name"].as_str()).collect())
        .unwrap_or_default();
    assert!(
        inner_children.contains(&"AInnerInner"),
        "AInner should contain AInnerInner: {inner_children:?}"
    );

    server.notify_value(json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}));
    let _ = server.read_message();
    server.exit();
}

#[test]
fn bifrost_lsp_server_workspace_symbol_finds_method() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let mut server = LspServer::spawn(&fixture_root);

    let canonical_root = fixture_root.canonicalize().expect("canon fixture");
    let root_uri = uri_for(&canonical_root);

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
    }));
    let init = server.read_message();
    assert_eq!(
        init["result"]["capabilities"]["workspaceSymbolProvider"], true,
        "workspaceSymbolProvider should be advertised: {init}"
    );
    server.notify_value(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "workspace/symbol",
        "params": {"query": "method2"}
    }));
    let response = server.read_message();
    let symbols = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected array result, got {response}"));
    assert!(
        symbols.iter().any(|s| s["name"] == "method2"),
        "expected method2 in {symbols:#?}"
    );
    let method2 = symbols.iter().find(|s| s["name"] == "method2").unwrap();
    let location = &method2["location"];
    let uri = location["uri"].as_str().expect("location uri");
    assert!(uri.ends_with("A.java"), "expected A.java URI, got {uri}");

    server.notify_value(json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}));
    let _ = server.read_message();
    server.exit();
}

#[test]
fn bifrost_lsp_server_completion_finds_symbol_by_prefix() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    let completor_path = write_completor_fixture(&temp_root);

    let mut server = LspServer::spawn(&temp_root);

    let root_uri = uri_for(&temp_root);
    let file_uri = uri_for(&completor_path);

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": completion_initialize_params(root_uri)
    }));
    let init = server.read_message();
    assert!(
        init["result"]["capabilities"]["completionProvider"].is_object(),
        "completionProvider should be advertised: {init}"
    );
    server.notify_value(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));

    // Line 3 (0-based) is `        gree`. The cursor sits at the end of
    // `gree`, character 12 (8 spaces + 4 prefix bytes).
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/completion",
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 3, "character": 12}
        }
    }));
    let response = server.read_message();
    let result = &response["result"];
    assert_eq!(
        result["isIncomplete"], false,
        "small fixture should not trigger truncation: {response}"
    );
    let items = result["items"]
        .as_array()
        .unwrap_or_else(|| panic!("expected items array, got {response}"));
    let item = items
        .iter()
        .find(|i| i["label"] == "greetEveryone")
        .unwrap_or_else(|| panic!("greetEveryone not present in {items:#?}"));
    // CompletionItemKind::FUNCTION == 3.
    assert_eq!(item["kind"], 3, "Java method should map to FUNCTION kind");

    server.notify_value(json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}));
    let _ = server.read_message();
    server.exit();
}

#[test]
fn bifrost_lsp_server_completion_truncates_at_max_results_and_sets_is_incomplete() {
    // Generate a fixture with 501 method declarations that all match the
    // prefix `matchme_`. The handler must cap items at MAX_RESULTS=500 and
    // set isIncomplete=true. Builds confidence in both the truncation logic
    // and the regex-escape path (`autocomplete_definitions` interpolates the
    // query into a regex internally).
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    let mut source = String::from("public class FloodMatch {\n");
    for i in 0..501 {
        use std::fmt::Write;
        writeln!(source, "    public void matchme_{i:03}() {{}}").expect("fmt");
    }
    source.push_str("    void caller() {\n        matchme_\n    }\n}\n");
    let flood_path = temp_root.join("FloodMatch.java");
    fs::write(&flood_path, &source).expect("write FloodMatch.java");

    let mut server = LspServer::spawn(&temp_root);

    let root_uri = uri_for(&temp_root);
    let file_uri = uri_for(&flood_path);

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": completion_initialize_params(root_uri)
    }));
    let _ = server.read_message();
    server.notify_value(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));

    // The `caller()` body sits on the line right after the 501 method
    // declarations: lines 0..=501 are the class header + methods, line 502 is
    // `    void caller() {`, line 503 is `        matchme_`. The cursor goes
    // at the end of `matchme_` = char position 16 (8 spaces + 8 chars).
    let cursor_line = 503;
    let cursor_char = 16;
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/completion",
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": cursor_line, "character": cursor_char}
        }
    }));
    let response = server.read_message();
    let result = &response["result"];
    assert_eq!(
        result["isIncomplete"], true,
        "501 matches should set isIncomplete=true: {response}"
    );
    let items = result["items"]
        .as_array()
        .unwrap_or_else(|| panic!("expected items array, got {response}"));
    assert_eq!(
        items.len(),
        500,
        "items should be capped at MAX_RESULTS=500: got {}",
        items.len()
    );
    // Spot-check a few specific labels survived truncation. Sort order is
    // analyzer-controlled (Function rank + fq_name alphabetic), so we don't
    // assert which 500 — just that they're well-formed.
    for item in items {
        let label = item["label"].as_str().expect("label string");
        assert!(
            label.starts_with("matchme_"),
            "unexpected label outside the matchme_ namespace: {label}"
        );
        assert_eq!(item["kind"], 3, "all should map to FUNCTION kind");
    }

    server.notify_value(json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}));
    let _ = server.read_message();
    server.exit();
}

#[test]
fn bifrost_lsp_server_completion_empty_prefix_returns_null() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    let completor_path = write_completor_fixture(&temp_root);

    let mut server = LspServer::spawn(&temp_root);

    let root_uri = uri_for(&temp_root);
    let file_uri = uri_for(&completor_path);

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": completion_initialize_params(root_uri)
    }));
    let _ = server.read_message();
    server.notify_value(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));

    // Line 4 (0-based) is `    }` — character 0 sits on whitespace with no
    // preceding identifier bytes on the same line. The handler must return
    // null (no completions) rather than dumping the whole symbol index.
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/completion",
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 4, "character": 0}
        }
    }));
    let response = server.read_message();
    assert!(
        response["result"].is_null(),
        "empty prefix should produce a null result, got {response}"
    );

    server.notify_value(json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}));
    let _ = server.read_message();
    server.exit();
}

#[test]
fn bifrost_lsp_server_goto_definition_finds_class_a_from_b() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let mut server = LspServer::spawn(&fixture_root);

    let canonical_root = fixture_root.canonicalize().expect("canon fixture");
    let root_uri = uri_for(&canonical_root);
    let b_uri = uri_for(&canonical_root.join("B.java"));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
    }));
    let init = server.read_message();
    assert_eq!(
        init["result"]["capabilities"]["definitionProvider"], true,
        "definitionProvider should be advertised: {init}"
    );
    server.notify_value(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));

    // Line 6 (0-based), char 8: cursor is on the `A` in `A a = new A();`.
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/definition",
        "params": {
            "textDocument": {"uri": b_uri},
            "position": {"line": 6, "character": 8}
        }
    }));
    let response = server.read_message();
    let locations = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected location array, got {response}"));
    assert!(!locations.is_empty(), "no definitions found: {response}");
    let uri = locations[0]["uri"].as_str().expect("location uri");
    assert!(uri.ends_with("A.java"), "expected A.java URI, got {uri}");
    // class A's primary range starts on line 2 (0-based) — the `public class A {`
    // declaration in A.java. Asserts position conversion isn't off-by-one.
    let start_line = locations[0]["range"]["start"]["line"]
        .as_u64()
        .expect("range.start.line");
    assert_eq!(
        start_line, 2,
        "expected definition range to start on line 2 (the `public class A {{` line), got {locations:#?}"
    );

    server.notify_value(json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}));
    let _ = server.read_message();
    server.exit();
}

#[test]
fn bifrost_lsp_server_definition_resolves_rust_associated_path_type_segment() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let src = root.join("src");
    fs::create_dir_all(&src).expect("create src");
    let main_path = src.join("main.rs");
    let main_source = common::RUST_ASSOCIATED_PATH_MAIN;
    fs::write(&main_path, main_source).expect("write main.rs");
    fs::write(src.join("state.rs"), common::RUST_ASSOCIATED_PATH_STATE).expect("write state.rs");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&main_path);
    let (line, character) = position_after(main_source, "    app_with_state(");
    let response = server.text_document_position_response(
        "textDocument/definition",
        &file_uri,
        line,
        character,
    );

    let locations = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected definition locations, got {response}"));
    assert_eq!(
        locations.len(),
        1,
        "expected one AppState definition location, got {response}"
    );
    let uri = locations[0]["uri"].as_str().expect("location uri");
    assert!(
        uri.ends_with("/src/state.rs"),
        "expected state.rs definition, got {response}"
    );
    assert_eq!(
        locations[0]["range"]["start"]["line"], 3,
        "expected AppState struct declaration line, got {response}"
    );
}

#[test]
fn bifrost_lsp_server_type_definition_resolves_rust_explicit_local_type() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let lib_path = root.join("lib.rs");
    let model_path = root.join("model.rs");
    fs::write(
        &lib_path,
        "mod model;\nuse model::Widget;\n\nfn run() {\n    let value: Widget = Widget;\n    let _ = value;\n}\n",
    )
    .expect("write lib.rs");
    fs::write(&model_path, "pub struct Widget;\n").expect("write model.rs");

    let mut server = LspServer::start(&root);
    let lib_uri = uri_for(&lib_path);

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/typeDefinition",
        "params": {
            "textDocument": {"uri": lib_uri},
            "position": {"line": 5, "character": 12}
        }
    }));
    let response = server.read_message();
    let locations = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected location array, got {response}"));
    assert_eq!(
        locations.len(),
        1,
        "expected one type definition: {response}"
    );
    let uri = locations[0]["uri"].as_str().expect("location uri");
    assert!(
        uri.ends_with("model.rs"),
        "expected model.rs type definition, got {response}"
    );
}

#[test]
fn bifrost_lsp_server_implementation_returns_null_for_go_interface_local_value() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    fs::write(root.join("go.mod"), "module example.com/app\n").expect("write go.mod");
    let file_path = root.join("main.go");
    fs::write(
        &file_path,
        "package main\n\ntype Runner interface {\n    Run() error\n}\n\ntype Worker struct{}\n\nfunc (Worker) Run() error { return nil }\n\nfunc use() {\n    var runner Runner = Worker{}\n    _ = runner\n}\n",
    )
    .expect("write main.go");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/implementation",
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 12, "character": 9}
        }
    }));
    let response = server.read_message();
    assert!(
        response["result"].is_null(),
        "Go local values must not resolve implementations, got {response}"
    );
}

#[test]
fn bifrost_lsp_server_implementation_works_from_go_interface_declaration() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    fs::write(root.join("go.mod"), "module example.com/app\n").expect("write go.mod");
    let file_path = root.join("main.go");
    fs::write(
        &file_path,
        "package main\n\ntype Runner interface {\n    Run() error\n}\n\ntype Worker struct{}\n\nfunc (Worker) Run() error { return nil }\n",
    )
    .expect("write main.go");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/implementation",
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 2, "character": 5}
        }
    }));
    let response = server.read_message();
    let locations = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected location array, got {response}"));
    assert_eq!(
        locations.len(),
        1,
        "expected one type implementation: {response}"
    );
    assert_eq!(
        locations[0]["range"]["start"]["line"], 6,
        "expected Worker declaration from interface declaration lookup: {response}"
    );
}

#[test]
fn bifrost_lsp_server_implementation_works_from_go_interface_method() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    fs::write(root.join("go.mod"), "module example.com/app\n").expect("write go.mod");
    let file_path = root.join("main.go");
    fs::write(
        &file_path,
        "package main\n\ntype Runner interface {\n    Run() error\n}\n\ntype Worker struct{}\n\nfunc (Worker) Run() error { return nil }\n",
    )
    .expect("write main.go");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/implementation",
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 3, "character": 4}
        }
    }));
    let response = server.read_message();
    let locations = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected location array, got {response}"));
    assert_eq!(
        locations.len(),
        1,
        "expected one method implementation: {response}"
    );
    assert_eq!(
        locations[0]["range"]["start"]["line"], 8,
        "expected Worker.Run declaration from interface method lookup: {response}"
    );
}

#[test]
fn bifrost_lsp_server_rust_trait_method_implementation_finds_impl_methods() {
    let source = r#"pub trait Runner {
    fn run() -> String;
}

pub struct LocalRunner;
pub struct RemoteRunner;

impl Runner for LocalRunner {
    fn run() -> String {
        String::new()
    }
}

impl Runner for RemoteRunner {
    fn run() -> String {
        String::new()
    }
}
"#;
    assert_lsp_implementation_start_lines(
        &[("lib.rs", source)],
        "lib.rs",
        "    fn ",
        &[
            ("lib.rs", "impl Runner for LocalRunner {\n"),
            ("lib.rs", "impl Runner for RemoteRunner {\n"),
        ],
    );
}

#[test]
fn bifrost_lsp_server_rust_trait_associated_type_implementation_finds_impl_types() {
    let source = r#"pub trait Runner {
    type Output;
}

pub struct LocalRunner;
pub struct RemoteRunner;

impl Runner for LocalRunner {
    type Output = String;
}

impl Runner for RemoteRunner {
    type Output = Vec<u8>;
}
"#;
    assert_lsp_implementation_start_lines(
        &[("lib.rs", source)],
        "lib.rs",
        "    type ",
        &[
            ("lib.rs", "impl Runner for LocalRunner {\n"),
            ("lib.rs", "impl Runner for RemoteRunner {\n"),
        ],
    );
}

#[test]
fn bifrost_lsp_server_rust_trait_method_implementation_excludes_unrelated_inherent_method() {
    let source = r#"pub trait Runner {
    fn run() -> String;
}

pub struct LocalRunner;
pub struct Unrelated;

impl Runner for LocalRunner {
    fn run() -> String {
        String::new()
    }
}

impl Unrelated {
    fn run() -> String {
        String::new()
    }
}
"#;
    assert_lsp_implementation_start_lines(
        &[("lib.rs", source)],
        "lib.rs",
        "    fn ",
        &[("lib.rs", "impl Runner for LocalRunner {\n")],
    );
}

#[test]
fn bifrost_lsp_server_rust_trait_method_implementation_excludes_same_type_inherent_method() {
    let source = r#"pub trait Runner {
    fn run() -> String;
}

pub struct LocalRunner;

impl LocalRunner {
    fn run() -> String {
        String::new()
    }
}

impl Runner for LocalRunner {
    fn run() -> String {
        String::new()
    }
}
"#;
    assert_lsp_implementation_start_lines(
        &[("lib.rs", source)],
        "lib.rs",
        "    fn ",
        &[("lib.rs", "impl Runner for LocalRunner {\n")],
    );
}

#[test]
fn bifrost_lsp_server_rust_trait_method_implementation_finds_cross_file_impl_method() {
    let contracts = "pub trait Runner {\n    fn run() -> String;\n}\n";
    let service = r#"use crate::contracts::Runner;

pub struct LocalRunner;

impl Runner for LocalRunner {
    fn run() -> String {
        String::new()
    }
}
"#;
    let lib = "pub mod contracts;\npub mod service;\n";
    assert_lsp_implementation_start_lines(
        &[
            ("lib.rs", lib),
            ("contracts.rs", contracts),
            ("service.rs", service),
        ],
        "contracts.rs",
        "    fn ",
        &[("service.rs", "impl Runner for LocalRunner {\n")],
    );
}

#[test]
fn bifrost_lsp_server_implementation_rejects_java_field_declaration() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("Fields.java");
    let source = "class Base {\n  int value;\n}\nclass Child extends Base {\n  int value;\n}\n";
    fs::write(&file_path, source).expect("write Java field fixture");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "  int ");
    let response = implementation_response(&mut server, &file_uri, line, character);
    assert!(
        response["result"].is_null(),
        "Java field declarations must not resolve implementations, got {response}"
    );
}

fn assert_lsp_implementation_start_lines(
    files: &[(&str, &str)],
    cursor_path: &str,
    cursor_needle: &str,
    expected: &[(&str, &str)],
) {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    for (path, source) in files {
        let file_path = root.join(path);
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent).expect("create fixture parent");
        }
        fs::write(file_path, source).expect("write implementation fixture");
    }

    let mut server = LspServer::start(&root);
    let cursor_source = files
        .iter()
        .find_map(|(path, source)| (*path == cursor_path).then_some(*source))
        .unwrap_or_else(|| panic!("missing cursor file {cursor_path}"));
    let file_uri = uri_for(&root.join(cursor_path));
    let (line, character) = position_after(cursor_source, cursor_needle);
    let response = implementation_response(&mut server, &file_uri, line, character);
    let locations = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected implementation locations, got {response}"));
    let actual: BTreeSet<_> = locations
        .iter()
        .map(|location| {
            (
                location["uri"].as_str().expect("location uri").to_string(),
                location["range"]["start"]["line"]
                    .as_u64()
                    .expect("location start line"),
            )
        })
        .collect();
    let expected: BTreeSet<_> = expected
        .iter()
        .map(|(path, needle)| {
            let source = files
                .iter()
                .find_map(|(candidate, source)| (*candidate == *path).then_some(*source))
                .unwrap_or_else(|| panic!("missing expected file {path}"));
            (uri_for(&root.join(path)), position_after(source, needle).0)
        })
        .collect();
    assert_eq!(
        actual, expected,
        "unexpected implementation locations: {response}"
    );
}

#[test]
fn bifrost_lsp_server_go_type_or_implementation_rejects_value_contexts() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    fs::write(root.join("go.mod"), "module example.com/app\n").expect("write go.mod");
    let file_path = root.join("main.go");
    let source = "package main\n\ntype Runner interface {\n    Run() error\n}\n\ntype Worker struct {\n    Field int\n}\n\nfunc (Worker) Run() error { return nil }\n\nfunc build() Worker {\n    var local Worker\n    return local\n}\n";
    fs::write(&file_path, source).expect("write Go value-context fixture");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);

    let null_cases = [
        ("func b", "ordinary Go function"),
        ("func (Worker) ", "non-interface Go method"),
        ("Field", "Go struct field"),
        ("var local", "Go local variable"),
    ];
    for (needle, label) in null_cases {
        let (line, character) = position_after(source, needle);
        let response = implementation_response(&mut server, &file_uri, line, character);
        assert!(
            response["result"].is_null(),
            "{label} must not resolve implementations, got {response}"
        );
    }

    for (needle, label) in null_cases {
        let (line, character) = position_after(source, needle);
        let result = prepare_hierarchy_result(
            &mut server,
            "textDocument/prepareTypeHierarchy",
            &file_uri,
            (line, character),
        );
        assert!(
            result.is_null(),
            "{label} must not prepare type hierarchy, got {result}"
        );
    }
}

#[test]
fn bifrost_lsp_server_implementation_filters_java_csharp_scala_value_contexts() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let fixtures = write_jvm_type_context_fixtures(&root, "ImplContexts");

    let mut server = LspServer::start(&root);

    let java_uri = uri_for(&fixtures.java_path);
    let (line, character) = position_after(fixtures.java_source, "    W");
    let response = implementation_response(&mut server, &java_uri, line, character);
    let locations = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected Java type reference implementations, got {response}"));
    assert!(
        locations
            .iter()
            .any(|location| location["range"]["start"]["line"] == 1),
        "expected Java Child implementation from return type, got {response}"
    );
    assert_implementation_null_cases(
        &mut server,
        &java_uri,
        fixtures.java_source,
        &[
            ("    Widget b", "Java method names"),
            ("        Widget l", "Java locals"),
        ],
    );

    let csharp_uri = uri_for(&fixtures.csharp_path);
    assert_implementation_null_cases(
        &mut server,
        &csharp_uri,
        fixtures.csharp_source,
        &[(" Widget B", "C# method names"), (" Widget l", "C# locals")],
    );

    let scala_uri = uri_for(&fixtures.scala_path);
    let (line, character) = position_after(fixtures.scala_source, ": W");
    let response = implementation_response(&mut server, &scala_uri, line, character);
    let locations = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected Scala type reference implementations, got {response}"));
    assert!(
        locations
            .iter()
            .any(|location| location["range"]["start"]["line"] == 1),
        "expected Scala Child implementation from return type, got {response}"
    );
    assert_implementation_null_cases(
        &mut server,
        &scala_uri,
        fixtures.scala_source,
        &[("def b", "Scala function names"), ("val l", "Scala locals")],
    );
}

#[test]
fn bifrost_lsp_server_implementation_works_from_typescript_type_reference() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");

    let ts_path = root.join("ImplTypeRefs.ts");
    let ts_source =
        "interface Base {}\nclass Child implements Base {}\nlet typed: Base | null = null;\n";
    fs::write(&ts_path, ts_source).expect("write TypeScript implementation type-ref fixture");

    let mut server = LspServer::start(&root);

    let ts_uri = uri_for(&ts_path);
    let (line, character) = position_after(ts_source, "typed: ");
    let response = implementation_response(&mut server, &ts_uri, line, character);
    let locations = response["result"].as_array().unwrap_or_else(|| {
        panic!("expected TypeScript type-reference implementations, got {response}")
    });
    assert!(
        locations
            .iter()
            .any(|location| location["range"]["start"]["line"] == 1),
        "expected TypeScript Child implementation from Base annotation, got {response}"
    );

    let (line, character) = position_after(ts_source, "let t");
    let response = implementation_response(&mut server, &ts_uri, line, character);
    assert!(
        response["result"].is_null(),
        "TypeScript local declaration names must not resolve implementations, got {response}"
    );
}

#[test]
fn bifrost_lsp_server_signature_help_returns_java_method_signature() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("Calculator.java");
    let source = "class Calculator {\n    /**\n     * Adds two values.\n     */\n    int sum(int sum, int right) { return sum + right; }\n    void caller() {\n        int value = sum(1, 2);\n    }\n}\n";
    fs::write(&file_path, source).expect("write Calculator.java");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "sum(1, ");

    let result = signature_help(&mut server, &file_uri, line, character);
    assert_eq!(
        result["activeSignature"], 0,
        "unexpected signature help: {result}"
    );
    assert_eq!(
        result["activeParameter"], 1,
        "unexpected signature help: {result}"
    );
    assert!(
        result["signatures"][0]["label"]
            .as_str()
            .is_some_and(|label| label.contains("sum") && label.contains("right")),
        "expected sum signature label, got {result}"
    );
    assert_signature_parameter_offsets(&result, 0, &["sum", "right"]);
    assert!(
        result["signatures"][0]["documentation"]["value"]
            .as_str()
            .is_some_and(|doc| doc.contains("Adds two values.")),
        "expected Java signature documentation, got {result}"
    );
}

#[test]
fn bifrost_lsp_server_signature_help_returns_typescript_function_signature() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("sample.ts");
    let source = "/**\n * Combines two values.\n */\nfunction combine(combine: number, right: number): number {\n  return combine + right;\n}\nconst result = combine(1, 2);\n";
    fs::write(&file_path, source).expect("write sample.ts");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "combine(1, ");

    let result = signature_help(&mut server, &file_uri, line, character);
    assert_eq!(
        result["activeParameter"], 1,
        "unexpected signature help: {result}"
    );
    assert!(
        result["signatures"][0]["label"]
            .as_str()
            .is_some_and(|label| label.contains("combine") && label.contains("right")),
        "expected combine signature label, got {result}"
    );
    assert_signature_parameter_offsets(&result, 0, &["combine", "right"]);
    assert!(
        result["signatures"][0]["documentation"]["value"]
            .as_str()
            .is_some_and(|doc| doc.contains("Combines two values.")),
        "expected TypeScript signature documentation, got {result}"
    );
}

#[test]
fn bifrost_lsp_server_signature_help_returns_javascript_function_signature() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("sample.js");
    let source = "/**\n * Combines JavaScript values.\n */\nfunction combine(combine, right) {\n  return combine + right;\n}\nconst result = combine(1, 2);\n";
    fs::write(&file_path, source).expect("write sample.js");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "combine(1, ");

    let result = signature_help(&mut server, &file_uri, line, character);
    assert_eq!(
        result["activeParameter"], 1,
        "unexpected signature help: {result}"
    );
    assert!(
        result["signatures"][0]["label"]
            .as_str()
            .is_some_and(|label| label.contains("combine") && label.contains("right")),
        "expected combine signature label, got {result}"
    );
    assert_signature_parameter_offsets(&result, 0, &["combine", "right"]);
    assert!(
        result["signatures"][0]["documentation"]["value"]
            .as_str()
            .is_some_and(|doc| doc.contains("Combines JavaScript values.")),
        "expected JavaScript signature documentation, got {result}"
    );
}

#[test]
fn bifrost_lsp_server_signature_help_returns_javascript_default_and_rest_parameter_offsets() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("defaults.js");
    let source = "function factory() { return 0; }\n/**\n * Configures JavaScript values.\n */\nfunction configure(left = factory(), right, ...rest) {\n  return right;\n}\nconst result = configure(1, 2, 3);\n";
    fs::write(&file_path, source).expect("write defaults.js");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "configure(1, ");

    let result = signature_help(&mut server, &file_uri, line, character);
    assert_eq!(
        result["activeParameter"], 1,
        "unexpected signature help: {result}"
    );
    assert_signature_parameter_offsets(&result, 0, &["left", "right", "rest"]);
}

#[test]
fn bifrost_lsp_server_signature_help_returns_javascript_single_arrow_parameter_offsets() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("arrow.js");
    let source = "const identity = value => value;\nconst result = identity(1);\n";
    fs::write(&file_path, source).expect("write arrow.js");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "identity(");

    let result = signature_help(&mut server, &file_uri, line, character);
    assert_eq!(
        result["activeParameter"], 0,
        "unexpected signature help: {result}"
    );
    assert_signature_parameter_offsets(&result, 0, &["value"]);
}

#[test]
fn bifrost_lsp_server_signature_help_returns_typescript_constructor_signature() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("widget.ts");
    let source = "class Widget {\n  constructor(left: number, right: number) {}\n}\nconst result = new Widget(1, 2);\n";
    fs::write(&file_path, source).expect("write widget.ts");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "Widget(1, ");

    let result = signature_help(&mut server, &file_uri, line, character);
    assert_eq!(
        result["activeParameter"], 1,
        "unexpected signature help: {result}"
    );
    assert!(
        result["signatures"][0]["label"]
            .as_str()
            .is_some_and(|label| label.contains("Widget") && label.contains("constructor")),
        "expected Widget constructor signature label, got {result}"
    );
}

#[test]
fn bifrost_lsp_server_signature_help_returns_go_function_signature() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    fs::write(root.join("go.mod"), "module example.com/signature\n").expect("write go.mod");
    let file_path = root.join("main.go");
    let source = "package main\n\n// combine combines Go values.\nfunc combine(combine func() int, right int, rest ...int) int { return combine() + right + len(rest) }\n\nfunc main() {\n    _ = combine(nil, 2, 3)\n}\n";
    fs::write(&file_path, source).expect("write main.go");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "combine(nil, ");

    let result = signature_help(&mut server, &file_uri, line, character);
    assert_eq!(
        result["activeParameter"], 1,
        "unexpected signature help: {result}"
    );
    assert!(
        result["signatures"][0]["label"]
            .as_str()
            .is_some_and(|label| label.contains("combine") && label.contains("right")),
        "expected combine signature label, got {result}"
    );
    assert_signature_parameter_offsets(&result, 0, &["combine", "right", "rest"]);
    assert!(
        result["signatures"][0]["documentation"]["value"]
            .as_str()
            .is_some_and(|doc| doc.contains("combine combines Go values.")),
        "expected Go signature documentation, got {result}"
    );
}

#[test]
fn bifrost_lsp_server_signature_help_returns_csharp_method_signature() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("Calculator.cs");
    let source = "using System;\nclass Calculator {\n    /// <summary>Combines C# values.</summary>\n    int Combine(int Combine, Func<int> factory, int right = 0) { return Combine + factory() + right; }\n    void Caller() {\n        var value = Combine(1, () => 2, 3);\n    }\n}\n";
    fs::write(&file_path, source).expect("write Calculator.cs");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "Combine(1, ");

    let result = signature_help(&mut server, &file_uri, line, character);
    assert_eq!(
        result["activeParameter"], 1,
        "unexpected signature help: {result}"
    );
    assert!(
        result["signatures"][0]["label"]
            .as_str()
            .is_some_and(|label| label.contains("Combine") && label.contains("right")),
        "expected Combine signature label, got {result}"
    );
    assert_signature_parameter_offsets(&result, 0, &["Combine", "factory", "right"]);
    assert!(
        result["signatures"][0]["documentation"]["value"]
            .as_str()
            .is_some_and(|doc| doc.contains("Combines C# values.")),
        "expected C# signature documentation, got {result}"
    );
}

#[test]
fn bifrost_lsp_server_signature_help_returns_cpp_function_signature() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("calculator.cpp");
    let source = "/* Combines C++ values. */\nint combine(int combine, int (*factory)(), int* right) { return combine + factory() + *right; }\nint main() {\n    int value = 2;\n    return combine(1, nullptr, &value);\n}\n";
    fs::write(&file_path, source).expect("write calculator.cpp");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "combine(1, ");

    let result = signature_help(&mut server, &file_uri, line, character);
    assert_eq!(
        result["activeParameter"], 1,
        "unexpected signature help: {result}"
    );
    assert!(
        result["signatures"][0]["label"]
            .as_str()
            .is_some_and(|label| label.contains("combine") && label.contains("right")),
        "expected combine signature label, got {result}"
    );
    assert_signature_parameter_offsets(&result, 0, &["combine", "factory", "right"]);
    assert!(
        result["signatures"][0]["documentation"]["value"]
            .as_str()
            .is_some_and(|doc| doc.contains("Combines C++ values.")),
        "expected C++ signature documentation, got {result}"
    );
}

#[test]
fn bifrost_lsp_server_signature_help_returns_python_function_signature() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("calculator.py");
    let source = "# Combines Python values.\ndef combine(combine: int, right: int = helper(1, 2), *rest: int) -> int:\n    return combine + right\n\nvalue = combine(1, 2, 3)\n";
    fs::write(&file_path, source).expect("write calculator.py");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "combine(1, ");

    let result = signature_help(&mut server, &file_uri, line, character);
    assert_eq!(
        result["activeParameter"], 1,
        "unexpected signature help: {result}"
    );
    assert!(
        result["signatures"][0]["label"]
            .as_str()
            .is_some_and(|label| label.contains("combine") && label.contains("right")),
        "expected combine signature label, got {result}"
    );
    assert_signature_parameter_offsets(&result, 0, &["combine", "right", "rest"]);
    assert!(
        result["signatures"][0]["documentation"]["value"]
            .as_str()
            .is_some_and(|doc| doc.contains("Combines Python values.")),
        "expected Python signature documentation, got {result}"
    );
}

#[test]
fn bifrost_lsp_server_signature_help_returns_ruby_method_signature() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("calculator.rb");
    let source = "class Calculator\n  # Combines Ruby values.\n  def combine(combine, right = helper(1, 2), *rest)\n    combine + right\n  end\n\n  def caller\n    combine(1, 2, 3)\n  end\nend\n";
    fs::write(&file_path, source).expect("write calculator.rb");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "combine(1, ");

    let result = signature_help(&mut server, &file_uri, line, character);
    assert_eq!(
        result["activeParameter"], 1,
        "unexpected signature help: {result}"
    );
    assert!(
        result["signatures"][0]["label"]
            .as_str()
            .is_some_and(|label| label.contains("combine") && label.contains("right")),
        "expected Ruby combine signature label, got {result}"
    );
    assert_signature_parameter_offsets(&result, 0, &["combine", "right", "rest"]);
    assert!(
        result["signatures"][0]["documentation"]["value"]
            .as_str()
            .is_some_and(|doc| doc.contains("Combines Ruby values.")),
        "expected Ruby signature documentation, got {result}"
    );
}

#[test]
fn bifrost_lsp_server_signature_help_returns_rust_function_signature() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("calculator.rs");
    let source = "/// Combines Rust values.\nfn combine(combine: i32, right: Option<Result<i32, i32>>) -> i32 {\n    combine + right.unwrap().unwrap()\n}\n\nfn main() {\n    let _ = combine(1, None);\n}\n";
    fs::write(&file_path, source).expect("write calculator.rs");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "combine(1, ");

    let result = signature_help(&mut server, &file_uri, line, character);
    assert_eq!(
        result["activeParameter"], 1,
        "unexpected signature help: {result}"
    );
    assert!(
        result["signatures"][0]["label"]
            .as_str()
            .is_some_and(|label| label.contains("combine") && label.contains("right")),
        "expected combine signature label, got {result}"
    );
    assert_signature_parameter_offsets(&result, 0, &["combine", "right"]);
    assert!(
        result["signatures"][0]["documentation"]["value"]
            .as_str()
            .is_some_and(|doc| doc.contains("Combines Rust values.")),
        "expected Rust signature documentation, got {result}"
    );
}

#[test]
fn bifrost_lsp_server_signature_help_returns_php_function_signature() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("calculator.php");
    let source = "<?php\n/** Combines PHP values. */\nfunction combine($combine, callable $factory, int $right = helper(1, 2)) {\n    return $combine + $factory() + $right;\n}\n\n$result = combine(1, fn() => 2, 3);\n";
    fs::write(&file_path, source).expect("write calculator.php");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "combine(1, ");

    let result = signature_help(&mut server, &file_uri, line, character);
    assert_eq!(
        result["activeParameter"], 1,
        "unexpected signature help: {result}"
    );
    assert!(
        result["signatures"][0]["label"]
            .as_str()
            .is_some_and(|label| label.contains("combine") && label.contains("right")),
        "expected combine signature label, got {result}"
    );
    assert_signature_parameter_offsets(&result, 0, &["$combine", "$factory", "$right"]);
    assert!(
        result["signatures"][0]["documentation"]["value"]
            .as_str()
            .is_some_and(|doc| doc.contains("Combines PHP values.")),
        "expected PHP signature documentation, got {result}"
    );
}

#[test]
fn bifrost_lsp_server_signature_help_returns_scala_function_signature() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("App.scala");
    let source = "object App {\n  /** Combines Scala values. */\n  def target(target: Int, right: Either[Int, Int] = Left(1)): Int = target + right.fold(identity, identity)\n  val result = target(1, Right(2))\n}\n";
    fs::write(&file_path, source).expect("write App.scala");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "target(1, ");

    let result = signature_help(&mut server, &file_uri, line, character);
    assert_eq!(
        result["activeParameter"], 1,
        "unexpected signature help: {result}"
    );
    assert!(
        result["signatures"][0]["label"]
            .as_str()
            .is_some_and(|label| label.contains("target") && label.contains("right")),
        "expected target signature label, got {result}"
    );
    assert_signature_parameter_offsets(&result, 0, &["target", "right"]);
    assert!(
        result["signatures"][0]["documentation"]["value"]
            .as_str()
            .is_some_and(|doc| doc.contains("Combines Scala values.")),
        "expected Scala signature documentation, got {result}"
    );
}

#[test]
fn bifrost_lsp_server_signature_help_handles_scala_brace_argument() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("App.scala");
    let source =
        "object App {\n  def target(value: Int): Int = value\n  val result = target { 1 }\n}\n";
    fs::write(&file_path, source).expect("write App.scala");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "target { ");

    let result = signature_help(&mut server, &file_uri, line, character);
    assert_eq!(
        result["activeParameter"], 0,
        "unexpected signature help: {result}"
    );
    assert!(
        result["signatures"][0]["label"]
            .as_str()
            .is_some_and(|label| label.contains("target") && label.contains("value")),
        "expected target signature label, got {result}"
    );
    assert_signature_parameter_offsets(&result, 0, &["value"]);
}

#[test]
fn bifrost_lsp_server_signature_help_handles_scala_infix_call() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("App.scala");
    let source = "object App {\n  class Box {\n    def combine(value: Int): Int = value\n  }\n  val box = new Box\n  val result = box combine 1\n}\n";
    fs::write(&file_path, source).expect("write App.scala");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "box combine ");

    let result = signature_help(&mut server, &file_uri, line, character);
    assert_eq!(
        result["activeParameter"], 0,
        "unexpected signature help: {result}"
    );
    assert!(
        result["signatures"][0]["label"]
            .as_str()
            .is_some_and(|label| label.contains("combine") && label.contains("value")),
        "expected combine signature label, got {result}"
    );
    assert_signature_parameter_offsets(&result, 0, &["value"]);
}

#[test]
fn bifrost_lsp_server_signature_help_handles_scala_postfix_call() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("App.scala");
    let source = "object App {\n  class Box {\n    def ready: Boolean = true\n  }\n  val box = new Box\n  val result = box ready\n}\n";
    fs::write(&file_path, source).expect("write App.scala");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "box ready");

    let result = signature_help(&mut server, &file_uri, line, character);
    assert_eq!(
        result["activeParameter"], 0,
        "unexpected signature help: {result}"
    );
    assert!(
        result["signatures"][0]["label"]
            .as_str()
            .is_some_and(|label| label.contains("ready") && label.contains("Boolean")),
        "expected ready signature label, got {result}"
    );
}

#[test]
fn bifrost_lsp_server_signature_help_handles_scala_postfix_operator_call() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("App.scala");
    let source = "object App {\n  class Box {\n    def ! : Boolean = true\n  }\n  val box = new Box\n  val result = box !\n}\n";
    fs::write(&file_path, source).expect("write App.scala");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "box !");

    let result = signature_help(&mut server, &file_uri, line, character);
    assert_eq!(
        result["activeParameter"], 0,
        "unexpected signature help: {result}"
    );
    assert!(
        result["signatures"][0]["label"]
            .as_str()
            .is_some_and(|label| label.contains("!") && label.contains("Boolean")),
        "expected operator signature label, got {result}"
    );
}

#[test]
fn bifrost_lsp_server_signature_help_returns_null_outside_call_arguments() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("Calculator.java");
    let source = "class Calculator {\n    int sum(int left, int right) { return left + right; }\n    void caller() {\n        int value = 1;\n    }\n}\n";
    fs::write(&file_path, source).expect("write Calculator.java");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "int value");
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/signatureHelp",
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": line, "character": character}
        }
    }));
    let response = server.read_response_for_id(2);
    assert!(
        response["result"].is_null(),
        "expected null signatureHelp, got {response}"
    );
}

#[test]
fn bifrost_lsp_server_signature_help_uses_did_open_overlay_call_context() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("Overlay.java");
    let disk_source = "class Overlay {\n    int target(int left, int right) { return left + right; }\n    void caller() {\n        int value = target(1);\n    }\n}\n";
    let overlay_source = "class Overlay {\n    int target(int left, int right) { return left + right; }\n    void caller() {\n        int value = target(1, 2);\n    }\n}\n";
    fs::write(&file_path, disk_source).expect("write Overlay.java");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didOpen",
        "params": {
            "textDocument": {
                "uri": file_uri,
                "languageId": "java",
                "version": 1,
                "text": overlay_source
            }
        }
    }));
    let (line, character) = position_after(overlay_source, "target(1, ");

    let result = signature_help(&mut server, &file_uri, line, character);
    assert_eq!(
        result["activeParameter"], 1,
        "signatureHelp should use overlay call text, got {result}"
    );
}

#[test]
fn bifrost_lsp_server_type_definition_returns_null_for_unresolved_type() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("plain.js");
    fs::write(
        &file_path,
        "function run() {\n    const value = makeValue();\n    value;\n}\n",
    )
    .expect("write plain.js");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/typeDefinition",
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 2, "character": 4}
        }
    }));
    let response = server.read_message();
    assert!(
        response["result"].is_null(),
        "unresolved type definition should return null, got {response}"
    );
}

#[test]
fn bifrost_lsp_server_type_definition_returns_null_for_typescript_function_name() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("app.ts");
    let source = "interface Widget {}\nfunction build(): Widget { return {} as Widget; }\nconst value = build();\n";
    fs::write(&file_path, source).expect("write app.ts");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "function ");

    let response = type_definition_response(&mut server, &file_uri, line, character);
    assert!(
        response["result"].is_null(),
        "function declaration name should not resolve a type definition, got {response}"
    );
}

#[test]
fn bifrost_lsp_server_type_definition_returns_null_for_typescript_method_name() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("app.ts");
    let source =
        "interface Widget {}\nclass Service {\n  build(): Widget { return {} as Widget; }\n}\n";
    fs::write(&file_path, source).expect("write app.ts");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "  ");

    let response = type_definition_response(&mut server, &file_uri, line, character);
    assert!(
        response["result"].is_null(),
        "method declaration name should not resolve a type definition, got {response}"
    );
}

#[test]
fn bifrost_lsp_server_type_definition_returns_null_for_javascript_callable_symbol() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("plain.js");
    let source = "function build() { return {}; }\nconst value = build();\n";
    fs::write(&file_path, source).expect("write plain.js");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "function ");

    let response = type_definition_response(&mut server, &file_uri, line, character);
    assert!(
        response["result"].is_null(),
        "JavaScript callable symbol should return null for type definition, got {response}"
    );
}

#[test]
fn bifrost_lsp_server_type_definition_returns_null_for_java_method_name() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("Service.java");
    let source =
        "class Widget {}\nclass Service {\n    Widget build() { return new Widget(); }\n}\n";
    fs::write(&file_path, source).expect("write Service.java");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "    Widget ");

    let response = type_definition_response(&mut server, &file_uri, line, character);
    assert!(
        response["result"].is_null(),
        "Java method declaration name should not resolve a type definition, got {response}"
    );
}

#[test]
fn bifrost_lsp_server_type_definition_returns_null_for_csharp_method_name() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("Service.cs");
    let source =
        "class Widget {}\nclass Service {\n    Widget Build() { return new Widget(); }\n}\n";
    fs::write(&file_path, source).expect("write Service.cs");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "    Widget ");

    let response = type_definition_response(&mut server, &file_uri, line, character);
    assert!(
        response["result"].is_null(),
        "C# method declaration name should not resolve a type definition, got {response}"
    );
}

#[test]
fn bifrost_lsp_server_type_definition_returns_null_for_rust_function_name() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("lib.rs");
    let source = "struct Widget;\nfn build() -> Widget { Widget }\nfn run() { let _ = build(); }\n";
    fs::write(&file_path, source).expect("write lib.rs");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "fn ");

    let response = type_definition_response(&mut server, &file_uri, line, character);
    assert!(
        response["result"].is_null(),
        "Rust function declaration name should not resolve a type definition, got {response}"
    );
}

#[test]
fn bifrost_lsp_server_type_definition_returns_null_for_go_function_name() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    fs::write(root.join("go.mod"), "module example.com/typectx\n").expect("write go.mod");
    let file_path = root.join("main.go");
    let source =
        "package main\n\ntype Widget struct{}\n\nfunc build() Widget { return Widget{} }\n";
    fs::write(&file_path, source).expect("write main.go");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "func ");

    let response = type_definition_response(&mut server, &file_uri, line, character);
    assert!(
        response["result"].is_null(),
        "Go function declaration name should not resolve a type definition, got {response}"
    );
}

#[test]
fn bifrost_lsp_server_type_definition_returns_null_for_scala_function_name() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("App.scala");
    let source = "class Widget\nobject App {\n  def build(): Widget = new Widget\n}\n";
    fs::write(&file_path, source).expect("write App.scala");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "def ");

    let response = type_definition_response(&mut server, &file_uri, line, character);
    assert!(
        response["result"].is_null(),
        "Scala function declaration name should not resolve a type definition, got {response}"
    );
}

#[test]
fn bifrost_lsp_server_type_definition_uses_did_open_overlay() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let app_path = root.join("app.ts");
    let model_path = root.join("model.ts");
    fs::write(&model_path, "export interface Widget {}\n").expect("write model.ts");
    fs::write(
        &app_path,
        "import { Widget } from './model';\nlet value = null;\nvalue;\n",
    )
    .expect("write app.ts");

    let mut server = LspServer::start(&root);
    let app_uri = uri_for(&app_path);

    server.notify_value(json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": app_uri,
                    "languageId": "typescript",
                    "version": 1,
                    "text": "import { Widget } from './model';\nlet value: Widget = null as any;\nvalue;\n"
                }
            }
        }),
    );
    let _ = server.read_notification("textDocument/publishDiagnostics");

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/typeDefinition",
        "params": {
            "textDocument": {"uri": app_uri},
            "position": {"line": 2, "character": 0}
        }
    }));
    let response = server.read_message();
    let locations = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected location array, got {response}"));
    assert_eq!(
        locations.len(),
        1,
        "expected overlay type annotation to resolve: {response}"
    );
    let uri = locations[0]["uri"].as_str().expect("location uri");
    assert!(
        uri.ends_with("model.ts"),
        "expected Widget definition from model.ts, got {response}"
    );
}

#[test]
fn bifrost_lsp_server_hover_returns_signature_for_class_a() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let mut server = LspServer::spawn(&fixture_root);

    let canonical_root = fixture_root.canonicalize().expect("canon fixture");
    let root_uri = uri_for(&canonical_root);
    let b_uri = uri_for(&canonical_root.join("B.java"));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
    }));
    let init = server.read_message();
    assert_eq!(
        init["result"]["capabilities"]["hoverProvider"], true,
        "hoverProvider should be advertised: {init}"
    );
    server.notify_value(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/hover",
        "params": {
            "textDocument": {"uri": b_uri},
            "position": {"line": 6, "character": 8}
        }
    }));
    let response = server.read_message();
    let value = response["result"]["contents"]["value"]
        .as_str()
        .unwrap_or_else(|| panic!("expected markdown hover, got {response}"));
    assert!(
        value.contains("class A"),
        "hover should mention class A, got: {value}"
    );
    assert!(
        value.starts_with("```java"),
        "hover should be fenced as java, got: {value}"
    );
    // Hover range should cover the `A` identifier under the cursor: line 6,
    // chars 8-9. A bug in identifier_span_at_offset or position_to_byte_offset
    // would produce something else here.
    let range = &response["result"]["range"];
    assert_eq!(range["start"]["line"], 6, "hover range start line");
    assert_eq!(range["start"]["character"], 8, "hover range start char");
    assert_eq!(range["end"]["line"], 6, "hover range end line");
    assert_eq!(range["end"]["character"], 9, "hover range end char");

    server.notify_value(json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}));
    let _ = server.read_message();
    server.exit();
}

#[test]
fn bifrost_lsp_server_references_finds_class_a_usages() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let mut server = LspServer::spawn(&fixture_root);

    let canonical_root = fixture_root.canonicalize().expect("canon fixture");
    let root_uri = uri_for(&canonical_root);
    let a_uri = uri_for(&canonical_root.join("A.java"));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
    }));
    let init = server.read_message();
    assert_eq!(
        init["result"]["capabilities"]["referencesProvider"]["workDoneProgress"], true,
        "referencesProvider should advertise work-done progress: {init}"
    );
    server.notify_value(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));

    // A.java line 3, col 13: cursor on the `A` in `public class A {`.
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/references",
        "params": {
            "textDocument": {"uri": a_uri},
            "position": {"line": 2, "character": 13},
            "context": {"includeDeclaration": false}
        }
    }));
    let response = server.read_message();
    let locations = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected array, got {response}"));
    let uris: Vec<&str> = locations.iter().filter_map(|l| l["uri"].as_str()).collect();
    assert!(
        uris.iter().any(|u| u.ends_with("B.java")),
        "expected at least one reference in B.java, got: {uris:?}"
    );
    // B.java line 7 (0-based: 6) is `        A a = new A();`. The two `A`
    // tokens land at chars 8 and 18. Either should appear in the hits.
    let in_b: Vec<&serde_json::Value> = locations
        .iter()
        .filter(|l| {
            l["uri"]
                .as_str()
                .map(|u| u.ends_with("B.java"))
                .unwrap_or(false)
        })
        .collect();
    assert!(!in_b.is_empty(), "no B.java hits: {locations:#?}");
    let on_line_6: Vec<&&serde_json::Value> = in_b
        .iter()
        .filter(|l| l["range"]["start"]["line"] == 6)
        .collect();
    assert!(
        !on_line_6.is_empty(),
        "expected at least one B.java hit on line 6, got: {in_b:#?}"
    );
    let chars: Vec<u64> = on_line_6
        .iter()
        .filter_map(|l| l["range"]["start"]["character"].as_u64())
        .collect();
    assert!(
        chars.iter().any(|c| *c == 8 || *c == 18),
        "expected a hit at char 8 or 18 on B.java line 6, got chars {chars:?}"
    );

    server.notify_value(json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}));
    let _ = server.read_message();
    server.exit();
}

#[test]
fn bifrost_lsp_server_references_reports_client_owned_work_done_progress() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");
    let canonical_root = fixture_root.canonicalize().expect("canon fixture");
    let root_uri = uri_for(&canonical_root);
    let a_uri = uri_for(&canonical_root.join("A.java"));
    let mut server = LspServer::spawn(&fixture_root);

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
    }));
    let _ = server.read_response_for_id(1);
    server.notify_value(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/references",
        "params": {
            "textDocument": {"uri": a_uri},
            "position": {"line": 2, "character": 13},
            "context": {"includeDeclaration": false},
            "workDoneToken": "reference-progress"
        }
    }));

    let mut progress_kinds = Vec::new();
    let response = loop {
        let message = server.read_message();
        if message["id"] == 2 {
            break message;
        }
        assert_eq!(
            message["method"], "$/progress",
            "unexpected message: {message}"
        );
        assert_eq!(message["params"]["token"], "reference-progress");
        progress_kinds.push(
            message["params"]["value"]["kind"]
                .as_str()
                .expect("progress kind")
                .to_string(),
        );
    };

    assert!(
        response["result"].is_array(),
        "expected references: {response}"
    );
    assert_eq!(progress_kinds, ["begin", "report", "report", "end"]);

    // A cancellation received after the response, or for an unknown request,
    // is a protocol no-op and must not affect the next request.
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "$/cancelRequest",
        "params": {"id": 2}
    }));
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "$/cancelRequest",
        "params": {"id": 999}
    }));
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "textDocument/references",
        "params": {
            "textDocument": {"uri": a_uri},
            "position": {"line": 2, "character": 13},
            "context": {"includeDeclaration": false}
        }
    }));
    let next = server.read_message();
    assert_ne!(
        next["method"], "$/progress",
        "request without workDoneToken emitted progress: {next}"
    );
    assert_eq!(next["id"], 3, "unexpected tokenless response: {next}");
    assert!(
        next["result"].is_array(),
        "late cancellation leaked: {next}"
    );

    server.shutdown_with_id(4);
}

#[test]
fn bifrost_lsp_server_references_cancel_stops_active_search() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let target_path = root.join("Target.java");
    fs::write(&target_path, "public class Target {}\n").expect("write target");
    let mut consumer = String::from("class Consumer {\n");
    for index in 0..5_000 {
        consumer.push_str(&format!("    Target field{index};\n"));
    }
    consumer.push_str("}\n");
    fs::write(root.join("Consumer.java"), consumer).expect("write large consumer");

    let mut server = LspServer::start(&root);
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "textDocument/references",
        "params": {
            "textDocument": {"uri": uri_for(&target_path)},
            "position": {"line": 0, "character": 13},
            "context": {"includeDeclaration": false},
            "workDoneToken": "cancel-progress"
        }
    }));

    loop {
        let progress = server.read_message();
        assert_eq!(progress["method"], "$/progress", "{progress}");
        assert_eq!(progress["params"]["token"], "cancel-progress");
        if progress["params"]["value"]["message"] == "Searching workspace" {
            break;
        }
    }
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "$/cancelRequest",
        "params": {"id": 10}
    }));

    let mut saw_cancelled_end = false;
    let response = loop {
        let message = server.read_message();
        if message["id"] == 10 {
            assert!(
                saw_cancelled_end,
                "cancellation response arrived before progress end: {message}"
            );
            break message;
        }
        assert_eq!(message["method"], "$/progress", "{message}");
        assert_eq!(message["params"]["token"], "cancel-progress");
        if message["params"]["value"]["kind"] == "end" {
            assert_eq!(message["params"]["value"]["message"], "Cancelled");
            assert!(!saw_cancelled_end, "duplicate progress end: {message}");
            saw_cancelled_end = true;
        }
    };
    assert_eq!(response["error"]["code"], -32800, "{response}");
    assert!(
        response["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("cancelled")),
        "{response}"
    );

    server.shutdown_with_id(11);
}

const COMMENT_TARGETS_SOURCE: &str = "class CommentTargets {\n    // target\n    void target() {}\n    void caller() {\n        target();\n    }\n}\n";

const SHIFTED_COMMENT_TARGETS_SOURCE: &str = "// unsaved header\nclass CommentTargets {\n    // target\n    void target() {}\n    void caller() {\n        target();\n    }\n}\n";

const INVALID_CONTEXTS_SOURCE: &str = "import a.*;\nimport b.*;\nclass InvalidContexts {\n    String literal = \"Shared\";\n    void caller() {\n        Shared ambiguous = null;\n        int value = MissingShared;\n        if (true) {}\n    }\n}\n";

const CSHARP_AMBIGUOUS_USING_SOURCE: &str = "using Alpha;\nusing Beta;\nnamespace App {\n    public class Consumer {\n        public void Execute() {\n            Target target = null;\n        }\n    }\n}\n";

const SCALA_AMBIGUOUS_IMPORT_SOURCE: &str = "package app\nimport alpha.*\nimport beta.*\nclass Consumer {\n  val target: Target = null\n}\n";

const DUPLICATE_DECLARATION_NAME_SOURCE: &str =
    "class Widget {\n    Widget Widget() {\n        return this;\n    }\n}\n";

const RUST_ATTRIBUTED_ASYNC_FUNCTION_SOURCE: &str = "\
#[cfg(test)]
pub async fn memory_pool() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect(\"memory database should connect\");

    pool
}

pub async fn caller_one() {
    memory_pool().await;
}

pub async fn caller_two() {
    memory_pool().await;
}
";

const RUST_EXTERNAL_GLOB_WITH_LOCAL_IMPORT_MAIN_SOURCE: &str = "\
mod state;

use sqlx::*;
use state::AppState;

pub fn app() {
    let _state: AppState;
}
";

const RUST_APP_STATE_SOURCE: &str = "\
pub struct AppState;

impl AppState {
    pub fn with_environment() -> Self {
        Self
    }
}
";

const RUST_EXTERNAL_IMPORT_HOVER_SOURCE: &str = "\
use sqlx::SqlitePool;

pub async fn connect() -> SqlitePool {
    todo!()
}
";

fn write_comment_targets_fixture(root: &Path) -> PathBuf {
    let file_path = root.join("CommentTargets.java");
    fs::write(&file_path, COMMENT_TARGETS_SOURCE).expect("write CommentTargets.java");
    file_path
}

fn write_duplicate_declaration_name_fixture(root: &Path) -> PathBuf {
    let file_path = root.join("Widget.java");
    fs::write(&file_path, DUPLICATE_DECLARATION_NAME_SOURCE).expect("write Widget.java");
    file_path
}

fn write_rust_attributed_async_function_fixture(root: &Path) -> PathBuf {
    let src = root.join("src");
    fs::create_dir_all(&src).expect("create Rust src");
    let file_path = src.join("lib.rs");
    fs::write(&file_path, RUST_ATTRIBUTED_ASYNC_FUNCTION_SOURCE)
        .expect("write Rust attributed async function fixture");
    file_path
}

fn write_rust_external_import_hover_fixture(root: &Path) -> PathBuf {
    let src = root.join("src");
    fs::create_dir_all(&src).expect("create Rust src");
    let file_path = src.join("lib.rs");
    fs::write(&file_path, RUST_EXTERNAL_IMPORT_HOVER_SOURCE)
        .expect("write Rust external import hover fixture");
    file_path
}

fn write_rust_external_glob_with_local_import_fixture(root: &Path) -> PathBuf {
    let src = root.join("src");
    fs::create_dir_all(&src).expect("create Rust src");
    let file_path = src.join("main.rs");
    fs::write(&file_path, RUST_EXTERNAL_GLOB_WITH_LOCAL_IMPORT_MAIN_SOURCE)
        .expect("write Rust external glob local import main fixture");
    fs::write(src.join("state.rs"), RUST_APP_STATE_SOURCE).expect("write Rust AppState fixture");
    file_path
}

fn write_invalid_contexts_fixture(root: &Path) -> PathBuf {
    let package_a = root.join("a");
    let package_b = root.join("b");
    fs::create_dir_all(&package_a).expect("create package a");
    fs::create_dir_all(&package_b).expect("create package b");
    fs::write(
        package_a.join("Shared.java"),
        "package a;\npublic class Shared {}\n",
    )
    .expect("write a.Shared");
    fs::write(
        package_b.join("Shared.java"),
        "package b;\npublic class Shared {}\n",
    )
    .expect("write b.Shared");
    let file_path = root.join("InvalidContexts.java");
    fs::write(&file_path, INVALID_CONTEXTS_SOURCE).expect("write InvalidContexts.java");
    file_path
}

fn write_csharp_ambiguous_using_fixture(root: &Path) -> PathBuf {
    let alpha = root.join("Alpha");
    let beta = root.join("Beta");
    let app = root.join("App");
    fs::create_dir_all(&alpha).expect("create Alpha namespace");
    fs::create_dir_all(&beta).expect("create Beta namespace");
    fs::create_dir_all(&app).expect("create App namespace");
    fs::write(
        alpha.join("Target.cs"),
        "namespace Alpha { public class Target {} }\n",
    )
    .expect("write Alpha.Target");
    fs::write(
        beta.join("Target.cs"),
        "namespace Beta { public class Target {} }\n",
    )
    .expect("write Beta.Target");
    let file_path = app.join("Consumer.cs");
    fs::write(&file_path, CSHARP_AMBIGUOUS_USING_SOURCE).expect("write Consumer.cs");
    file_path
}

fn write_scala_ambiguous_import_fixture(root: &Path) -> PathBuf {
    let alpha = root.join("alpha");
    let beta = root.join("beta");
    let app = root.join("app");
    fs::create_dir_all(&alpha).expect("create alpha package");
    fs::create_dir_all(&beta).expect("create beta package");
    fs::create_dir_all(&app).expect("create app package");
    fs::write(alpha.join("Target.scala"), "package alpha\nclass Target\n")
        .expect("write alpha.Target");
    fs::write(beta.join("Target.scala"), "package beta\nclass Target\n")
        .expect("write beta.Target");
    let file_path = app.join("Consumer.scala");
    fs::write(&file_path, SCALA_AMBIGUOUS_IMPORT_SOURCE).expect("write Consumer.scala");
    file_path
}

#[test]
fn bifrost_lsp_server_definition_ignores_comment_token() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = write_comment_targets_fixture(&root);

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);

    let (valid_line, valid_character) = position_after(COMMENT_TARGETS_SOURCE, "void ");
    let valid_definition = server.text_document_position_response(
        "textDocument/definition",
        &file_uri,
        valid_line,
        valid_character,
    );

    let (comment_line, comment_character) = position_after(COMMENT_TARGETS_SOURCE, "    // ");
    let comment_definition = server.text_document_position_response(
        "textDocument/definition",
        &file_uri,
        comment_line,
        comment_character,
    );

    assert!(
        valid_definition["result"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "valid declaration should resolve definition, got {valid_definition}"
    );
    assert!(
        comment_definition["result"].is_null(),
        "comment token must not resolve definition, got {comment_definition}"
    );
}

#[test]
fn bifrost_lsp_server_hover_ignores_comment_token() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = write_comment_targets_fixture(&root);

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);

    let (valid_line, valid_character) = position_after(COMMENT_TARGETS_SOURCE, "void ");
    let valid_hover = server.text_document_position_response(
        "textDocument/hover",
        &file_uri,
        valid_line,
        valid_character,
    );

    let (comment_line, comment_character) = position_after(COMMENT_TARGETS_SOURCE, "    // ");
    let comment_hover = server.text_document_position_response(
        "textDocument/hover",
        &file_uri,
        comment_line,
        comment_character,
    );

    assert!(
        valid_hover["result"]["contents"]["value"]
            .as_str()
            .is_some_and(|value| value.contains("target")),
        "valid declaration should produce hover, got {valid_hover}"
    );
    assert!(
        comment_hover["result"].is_null(),
        "comment token must not produce hover, got {comment_hover}"
    );
}

#[test]
fn bifrost_lsp_server_definition_and_hover_select_duplicate_declaration_name() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = write_duplicate_declaration_name_fixture(&root);

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);

    let (line, character) = position_after(DUPLICATE_DECLARATION_NAME_SOURCE, "    Widget ");
    let definition = server.text_document_position_response(
        "textDocument/definition",
        &file_uri,
        line,
        character,
    );
    let hover =
        server.text_document_position_response("textDocument/hover", &file_uri, line, character);

    let definition_items = definition["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected definition locations, got {definition}"));
    assert_eq!(
        definition_items.len(),
        1,
        "definition on declaration should resolve to its current location, got {definition}"
    );
    assert_eq!(
        definition_items[0]["range"]["start"]["line"], 1,
        "definition should target the method declaration, got {definition}"
    );
    let hover_value = hover["result"]["contents"]["value"]
        .as_str()
        .unwrap_or_else(|| panic!("expected hover contents, got {hover}"));
    assert!(
        hover_value.contains("Widget Widget()"),
        "hover should describe the method declaration, got {hover_value}"
    );
    assert_eq!(
        hover["result"]["range"]["start"]["character"], 11,
        "hover should highlight the method name under the cursor, not the return type: {hover}"
    );
}

#[test]
fn bifrost_lsp_server_definition_selects_rust_attributed_async_function_declaration() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = write_rust_attributed_async_function_fixture(&root);

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);

    let (line, character) = position_after(RUST_ATTRIBUTED_ASYNC_FUNCTION_SOURCE, "pub async fn ");
    let definition = server.text_document_position_response(
        "textDocument/definition",
        &file_uri,
        line,
        character,
    );

    let definition_items = definition["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected definition locations, got {definition}"));
    assert_eq!(
        definition_items.len(),
        1,
        "definition on declaration should resolve to its current location, got {definition}"
    );
    assert_eq!(
        definition_items[0]["range"]["start"]["line"], 1,
        "definition should target the function declaration, got {definition}"
    );
}

#[test]
fn bifrost_lsp_server_definition_selects_rust_function_declaration_across_identifier_token() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = write_rust_attributed_async_function_fixture(&root);

    let mut client = LspServer::start(&root);
    let file_uri = uri_for(&file_path);

    let name_start = RUST_ATTRIBUTED_ASYNC_FUNCTION_SOURCE
        .find("memory_pool()")
        .expect("function name exists");
    let name_end = name_start + "memory_pool".len();
    let offsets = [
        ("start", name_start),
        ("middle", name_start + "memory".len()),
        ("end", name_end),
    ];

    for (label, offset) in offsets {
        let (line, character) = position_at(RUST_ATTRIBUTED_ASYNC_FUNCTION_SOURCE, offset);
        let definition = client.text_document_position_response(
            "textDocument/definition",
            &file_uri,
            line,
            character,
        );
        let definition_items = definition["result"].as_array().unwrap_or_else(|| {
            panic!("expected definition locations from {label} cursor, got {definition}")
        });
        assert_eq!(
            definition_items.len(),
            1,
            "{label} cursor should resolve one definition, got {definition}"
        );
        assert_eq!(
            definition_items[0]["range"]["start"]["line"], 1,
            "{label} cursor should target the function declaration, got {definition}"
        );
    }
}

#[test]
fn bifrost_lsp_server_definition_resolves_rust_attributed_async_function_call_to_declaration() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = write_rust_attributed_async_function_fixture(&root);

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);

    let (line, character) =
        position_after(RUST_ATTRIBUTED_ASYNC_FUNCTION_SOURCE, "    memory_pool");
    let definition = server.text_document_position_response(
        "textDocument/definition",
        &file_uri,
        line,
        character,
    );

    let definition_items = definition["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected definition locations, got {definition}"));
    assert_eq!(
        definition_items.len(),
        1,
        "function call should resolve to the declaration, got {definition}"
    );
    assert_eq!(
        definition_items[0]["range"]["start"]["line"], 1,
        "definition should target the function declaration, got {definition}"
    );
}

#[test]
fn bifrost_lsp_server_hover_fast_fails_rust_external_import() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = write_rust_external_import_hover_fixture(&root);

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);

    let (line, character) = position_after(RUST_EXTERNAL_IMPORT_HOVER_SOURCE, "use sqlx::");
    let hover =
        server.text_document_position_response("textDocument/hover", &file_uri, line, character);

    assert!(
        hover["result"].is_null(),
        "external Rust imports should not trigger workspace definition hover, got {hover}"
    );
}

#[test]
fn bifrost_lsp_server_definition_resolves_rust_local_import_despite_external_glob() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = write_rust_external_glob_with_local_import_fixture(&root);

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);

    let app_state_offset = RUST_EXTERNAL_GLOB_WITH_LOCAL_IMPORT_MAIN_SOURCE
        .find("AppState;")
        .expect("AppState type annotation exists")
        + "App".len();
    let (line, character) = position_at(
        RUST_EXTERNAL_GLOB_WITH_LOCAL_IMPORT_MAIN_SOURCE,
        app_state_offset,
    );
    let definition = server.text_document_position_response(
        "textDocument/definition",
        &file_uri,
        line,
        character,
    );

    let definition_items = definition["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected definition locations, got {definition}"));
    assert_eq!(
        definition_items.len(),
        1,
        "local AppState import should resolve despite external glob, got {definition}"
    );
    assert!(
        definition_items[0]["uri"]
            .as_str()
            .is_some_and(|uri| uri.ends_with("/src/state.rs")),
        "definition should target sibling state.rs, got {definition}"
    );
    assert_eq!(
        definition_items[0]["range"]["start"]["line"], 0,
        "definition should target the AppState struct declaration, got {definition}"
    );
}

#[test]
fn bifrost_lsp_server_references_ignore_comment_token() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = write_comment_targets_fixture(&root);

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);

    let (valid_line, valid_character) = position_after(COMMENT_TARGETS_SOURCE, "void ");
    let valid_references =
        references_response(&mut server, &file_uri, valid_line, valid_character, true);

    let (comment_line, comment_character) = position_after(COMMENT_TARGETS_SOURCE, "    // ");
    let comment_references = references_response(
        &mut server,
        &file_uri,
        comment_line,
        comment_character,
        true,
    );

    assert!(
        valid_references["result"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "valid declaration should find references, got {valid_references}"
    );
    assert!(
        comment_references["result"].is_null()
            || comment_references["result"]
                .as_array()
                .is_some_and(|items| items.is_empty()),
        "comment token must not find references, got {comment_references}"
    );
}

#[test]
fn bifrost_lsp_server_document_highlight_ignores_comment_token() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = write_comment_targets_fixture(&root);

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);

    let (valid_line, valid_character) = position_after(COMMENT_TARGETS_SOURCE, "void ");
    let valid_highlights = server.text_document_position_response(
        "textDocument/documentHighlight",
        &file_uri,
        valid_line,
        valid_character,
    );

    let (comment_line, comment_character) = position_after(COMMENT_TARGETS_SOURCE, "    // ");
    let comment_highlights = server.text_document_position_response(
        "textDocument/documentHighlight",
        &file_uri,
        comment_line,
        comment_character,
    );

    assert!(
        valid_highlights["result"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "valid declaration should produce highlights, got {valid_highlights}"
    );
    assert!(
        comment_highlights["result"].is_null()
            || comment_highlights["result"]
                .as_array()
                .is_some_and(|items| items.is_empty()),
        "comment token must not produce highlights, got {comment_highlights}"
    );
}

#[test]
fn bifrost_lsp_server_references_and_document_highlight_use_shifted_overlay_declaration() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = write_comment_targets_fixture(&root);

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didOpen",
        "params": {
            "textDocument": {
                "uri": file_uri,
                "languageId": "java",
                "version": 1,
                "text": SHIFTED_COMMENT_TARGETS_SOURCE
            }
        }
    }));
    let _ = server.read_notification("textDocument/publishDiagnostics");

    let (line, character) = position_after(SHIFTED_COMMENT_TARGETS_SOURCE, "void ");
    let references = references_response(&mut server, &file_uri, line, character, true);
    let highlights = server.text_document_position_response(
        "textDocument/documentHighlight",
        &file_uri,
        line,
        character,
    );

    assert!(
        references["result"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "shifted overlay declaration should find references, got {references}"
    );
    assert!(
        highlights["result"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "shifted overlay declaration should produce highlights, got {highlights}"
    );
    assert!(
        highlights["result"].as_array().is_some_and(|items| {
            items.iter().any(|item| {
                item["range"]["start"]["line"] == line
                    && item["range"]["start"]["character"] == character
            })
        }),
        "shifted overlay declaration should highlight the overlaid declaration name, got {highlights}"
    );
}

#[test]
fn bifrost_lsp_server_definition_ignores_literals_keywords_unresolved_and_ambiguous_tokens() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = write_invalid_contexts_fixture(&root);

    let mut client = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let responses = collect_invalid_context_endpoint_responses(
        &mut client,
        &file_uri,
        BroadEndpoint::Definition,
    );

    assert_no_invalid_context_results(BroadEndpoint::Definition, &responses);
}

#[test]
fn bifrost_lsp_server_hover_ignores_literals_keywords_unresolved_and_ambiguous_tokens() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = write_invalid_contexts_fixture(&root);

    let mut client = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let responses =
        collect_invalid_context_endpoint_responses(&mut client, &file_uri, BroadEndpoint::Hover);

    assert_no_invalid_context_results(BroadEndpoint::Hover, &responses);
}

#[test]
fn bifrost_lsp_server_references_ignore_literals_keywords_unresolved_and_ambiguous_tokens() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = write_invalid_contexts_fixture(&root);

    let mut client = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let responses = collect_invalid_context_endpoint_responses(
        &mut client,
        &file_uri,
        BroadEndpoint::References,
    );

    assert_no_invalid_context_results(BroadEndpoint::References, &responses);
}

#[test]
fn bifrost_lsp_server_document_highlight_ignores_literals_keywords_unresolved_and_ambiguous_tokens()
{
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = write_invalid_contexts_fixture(&root);

    let mut client = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let responses = collect_invalid_context_endpoint_responses(
        &mut client,
        &file_uri,
        BroadEndpoint::DocumentHighlight,
    );

    assert_no_invalid_context_results(BroadEndpoint::DocumentHighlight, &responses);
}

#[test]
fn bifrost_lsp_server_broad_endpoints_ignore_csharp_ambiguous_using_type() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = write_csharp_ambiguous_using_fixture(&root);

    let mut client = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(CSHARP_AMBIGUOUS_USING_SOURCE, "            ");
    let responses = [
        BroadEndpoint::Definition,
        BroadEndpoint::Hover,
        BroadEndpoint::References,
        BroadEndpoint::DocumentHighlight,
    ]
    .into_iter()
    .map(|endpoint| {
        (
            endpoint.label(),
            endpoint_response(&mut client, &file_uri, endpoint, line, character),
        )
    })
    .collect::<Vec<_>>();

    for (endpoint, response) in responses {
        let no_result = response["result"].is_null()
            || response["result"]
                .as_array()
                .is_some_and(|items| items.is_empty());
        assert!(
            no_result,
            "C# ambiguous using type must not produce {endpoint} result, got {response}"
        );
    }
}

#[test]
fn bifrost_lsp_server_broad_endpoints_ignore_scala_ambiguous_wildcard_import_type() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = write_scala_ambiguous_import_fixture(&root);

    let mut client = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(SCALA_AMBIGUOUS_IMPORT_SOURCE, "  val target: ");
    let responses = [
        BroadEndpoint::Definition,
        BroadEndpoint::Hover,
        BroadEndpoint::References,
        BroadEndpoint::DocumentHighlight,
    ]
    .into_iter()
    .map(|endpoint| {
        (
            endpoint.label(),
            endpoint_response(&mut client, &file_uri, endpoint, line, character),
        )
    })
    .collect::<Vec<_>>();

    for (endpoint, response) in responses {
        let no_result = response["result"].is_null()
            || response["result"]
                .as_array()
                .is_some_and(|items| items.is_empty());
        assert!(
            no_result,
            "Scala ambiguous wildcard import type must not produce {endpoint} result, got {response}"
        );
    }
}

#[test]
fn bifrost_lsp_server_prepare_rename_returns_identifier_range() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");
    let canonical_root = fixture_root.canonicalize().expect("canon fixture");
    let a_uri = uri_for(&canonical_root.join("A.java"));

    let mut server = LspServer::start(&fixture_root);

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "textDocument/prepareRename",
        "params": {
            "textDocument": {"uri": a_uri},
            "position": {"line": 7, "character": 18}
        }
    }));
    let response = server.read_response_for_id(10);
    let result = &response["result"];
    assert_eq!(
        result["placeholder"], "method2",
        "prepare result: {response}"
    );
    assert_eq!(
        result["range"]["start"]["line"], 7,
        "prepare range: {response}"
    );
    assert_eq!(
        result["range"]["start"]["character"], 18,
        "prepare range: {response}"
    );
    assert_eq!(
        result["range"]["end"]["line"], 7,
        "prepare range: {response}"
    );
    assert_eq!(
        result["range"]["end"]["character"], 25,
        "prepare range: {response}"
    );
}

#[test]
fn bifrost_lsp_server_rename_returns_workspace_edit_for_java_method() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");
    let canonical_root = fixture_root.canonicalize().expect("canon fixture");
    let a_path = canonical_root.join("A.java");
    let a_uri = uri_for(&a_path);
    let b_uri = uri_for(&canonical_root.join("B.java"));
    let before_a = fs::read_to_string(&a_path).expect("read A.java before rename");

    let mut server = LspServer::start(&fixture_root);

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "textDocument/rename",
        "params": {
            "textDocument": {"uri": a_uri},
            "position": {"line": 7, "character": 18},
            "newName": "renamedMethod2"
        }
    }));
    let response = server.read_response_for_id(11);
    let changes = response["result"]["changes"]
        .as_object()
        .unwrap_or_else(|| panic!("expected WorkspaceEdit.changes, got {response}"));
    let a_edits = changes
        .get(&a_uri)
        .and_then(|value| value.as_array())
        .unwrap_or_else(|| panic!("expected A.java edits in {response}"));
    let b_edits = changes
        .get(&b_uri)
        .and_then(|value| value.as_array())
        .unwrap_or_else(|| panic!("expected B.java edits in {response}"));

    assert!(
        a_edits.iter().any(|edit| {
            edit["newText"] == "renamedMethod2"
                && edit["range"]["start"]["line"] == 7
                && edit["range"]["start"]["character"] == 18
                && edit["range"]["end"]["character"] == 25
        }),
        "expected declaration edit in A.java: {a_edits:#?}"
    );
    assert!(
        b_edits.iter().any(|edit| {
            edit["newText"] == "renamedMethod2"
                && edit["range"]["start"]["line"] == 8
                && edit["range"]["start"]["character"] == 26
        }),
        "expected usage edit in B.java: {b_edits:#?}"
    );
    assert_eq!(
        fs::read_to_string(&a_path).expect("read A.java after rename request"),
        before_a,
        "rename request must return edits without mutating files"
    );
}

#[test]
fn bifrost_lsp_server_rename_rejects_file_coupled_java_class_without_file_edit() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");
    let canonical_root = fixture_root.canonicalize().expect("canon fixture");
    let a_uri = uri_for(&canonical_root.join("A.java"));

    let mut server = LspServer::start(&fixture_root);

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 14,
        "method": "textDocument/prepareRename",
        "params": {
            "textDocument": {"uri": a_uri},
            "position": {"line": 2, "character": 13}
        }
    }));
    let prepare = server.read_response_for_id(14);
    assert!(
        prepare["result"].is_null(),
        "file-coupled Java class rename should not prepare without file operation support: {prepare}"
    );
}

#[test]
fn bifrost_lsp_server_rename_returns_null_for_comment_token() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("CommentRename.java");
    fs::write(
        &file_path,
        "class CommentRename {\n    // target\n    void target() {}\n}\n",
    )
    .expect("write fixture");
    let file_uri = uri_for(&file_path);

    let mut server = LspServer::start(&root);
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 15,
        "method": "textDocument/rename",
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 1, "character": 7},
            "newName": "renamedTarget"
        }
    }));
    let response = server.read_response_for_id(15);
    assert!(
        response["result"].is_null(),
        "comment token must not rename the real method with the same text: {response}"
    );
}

#[test]
fn bifrost_lsp_server_rename_keeps_same_short_name_symbols_separate() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let p_service = root.join("p").join("Service.java");
    let p_caller = root.join("p").join("Caller.java");
    let q_service = root.join("q").join("Service.java");
    let q_caller = root.join("q").join("Caller.java");
    fs::create_dir_all(root.join("p")).expect("create p");
    fs::create_dir_all(root.join("q")).expect("create q");
    fs::write(
        &p_service,
        "package p;\npublic class Service {\n    void target() {}\n}\n",
    )
    .expect("write p service");
    fs::write(
        &p_caller,
        "package p;\nclass Caller {\n    void call(Service service) {\n        service.target();\n    }\n}\n",
    )
    .expect("write p caller");
    fs::write(
        &q_service,
        "package q;\npublic class Service {\n    void target() {}\n}\n",
    )
    .expect("write q service");
    fs::write(
        &q_caller,
        "package q;\nclass Caller {\n    void call(Service service) {\n        service.target();\n    }\n}\n",
    )
    .expect("write q caller");

    let p_service_uri = uri_for(&p_service);
    let p_caller_uri = uri_for(&p_caller);
    let q_service_uri = uri_for(&q_service);
    let q_caller_uri = uri_for(&q_caller);
    let mut server = LspServer::start(&root);

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 16,
        "method": "textDocument/rename",
        "params": {
            "textDocument": {"uri": p_service_uri},
            "position": {"line": 2, "character": 9},
            "newName": "renamedTarget"
        }
    }));
    let response = server.read_response_for_id(16);
    let changes = response["result"]["changes"]
        .as_object()
        .unwrap_or_else(|| panic!("expected WorkspaceEdit.changes, got {response}"));
    assert!(
        changes.contains_key(&p_service_uri),
        "expected selected declaration file edit: {response}"
    );
    assert!(
        changes.contains_key(&p_caller_uri),
        "expected selected package usage edit: {response}"
    );
    assert!(
        !changes.contains_key(&q_service_uri) && !changes.contains_key(&q_caller_uri),
        "rename must not edit same-short-name symbols in another package: {response}"
    );
}

#[test]
fn bifrost_lsp_server_rename_uses_open_document_overlay() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("OverlayRename.java");
    fs::write(&file_path, "class DiskOnly {\n    void diskOnly() {}\n}\n")
        .expect("write disk fixture");
    let file_uri = uri_for(&file_path);

    let mut server = LspServer::start(&root);
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didOpen",
        "params": {
            "textDocument": {
                "uri": file_uri,
                "languageId": "java",
                "version": 1,
                "text": "class LiveName {\n    LiveName make() { return new LiveName(); }\n}\n"
            }
        }
    }));
    let _ = server.read_notification("textDocument/publishDiagnostics");

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 12,
        "method": "textDocument/rename",
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 0, "character": 6},
            "newName": "RenamedLive"
        }
    }));
    let response = server.read_response_for_id(12);
    let changes = response["result"]["changes"]
        .as_object()
        .unwrap_or_else(|| panic!("expected WorkspaceEdit.changes, got {response}"));
    let edits = changes
        .get(&file_uri)
        .and_then(|value| value.as_array())
        .unwrap_or_else(|| panic!("expected overlay file edits in {response}"));
    assert!(
        edits.iter().any(|edit| edit["newText"] == "RenamedLive"
            && edit["range"]["start"]["line"] == 0
            && edit["range"]["start"]["character"] == 6),
        "expected declaration edit from overlay text: {edits:#?}"
    );
    assert!(
        !fs::read_to_string(&file_path)
            .expect("read disk fixture")
            .contains("LiveName"),
        "overlay-only symbol must not be read from disk"
    );
}

#[test]
fn bifrost_lsp_server_rename_returns_null_for_unresolved_position() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("Whitespace.java");
    fs::write(&file_path, "class Whitespace {}\n").expect("write fixture");
    let file_uri = uri_for(&file_path);

    let mut server = LspServer::start(&root);
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 13,
        "method": "textDocument/rename",
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 0, "character": 5},
            "newName": "RenamedWhitespace"
        }
    }));
    let response = server.read_response_for_id(13);
    assert!(
        response["result"].is_null(),
        "unresolved rename should return null: {response}"
    );
}

#[test]
fn bifrost_lsp_server_call_hierarchy_finds_java_incoming_and_outgoing_calls() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("Calls.java");
    fs::write(
        &file_path,
        "class Service {\n    static void target() {}\n}\nclass Caller {\n    void helper() {\n        Service.target();\n    }\n}\n",
    )
    .expect("write Java call hierarchy fixture");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);

    let target = prepare_call_hierarchy(&mut server, &file_uri, 1, 16);
    assert_eq!(target["name"], "target", "prepared target: {target}");

    let incoming =
        call_hierarchy_relation(&mut server, "callHierarchy/incomingCalls", target.clone());
    assert_eq!(incoming.len(), 1, "incoming calls: {incoming:#?}");
    assert_eq!(
        incoming[0]["from"]["name"], "helper",
        "incoming caller should be helper: {incoming:#?}"
    );
    assert_call_range(&incoming[0]["fromRanges"], 5, 16, 22);

    let helper = prepare_call_hierarchy(&mut server, &file_uri, 4, 10);
    assert_eq!(helper["name"], "helper", "prepared helper: {helper}");

    let outgoing = call_hierarchy_relation(&mut server, "callHierarchy/outgoingCalls", helper);
    assert!(
        outgoing.iter().any(|call| call["to"]["name"] == "target"),
        "outgoing calls should include target: {outgoing:#?}"
    );
    let target_call = outgoing
        .iter()
        .find(|call| call["to"]["name"] == "target")
        .expect("target outgoing call");
    assert_call_range(&target_call["fromRanges"], 5, 16, 22);
}

#[test]
fn bifrost_lsp_server_call_hierarchy_finds_ruby_bare_calls() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("calls.rb");
    let source = "def target; end\ndef caller; target; end\n";
    fs::write(&file_path, source).expect("write Ruby call hierarchy fixture");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let (line, character) = position_after(source, "def t");
    let target = prepare_call_hierarchy(&mut server, &file_uri, line, character);
    assert_eq!(target["name"], "target", "prepared target: {target}");

    let incoming =
        call_hierarchy_relation(&mut server, "callHierarchy/incomingCalls", target.clone());
    assert_eq!(incoming.len(), 1, "incoming calls: {incoming:#?}");
    assert_eq!(incoming[0]["from"]["name"], "caller", "{incoming:#?}");
    assert_call_range(&incoming[0]["fromRanges"], 1, 12, 18);

    let (line, character) = position_after(source, "def c");
    let caller = prepare_call_hierarchy(&mut server, &file_uri, line, character);
    let outgoing = call_hierarchy_relation(&mut server, "callHierarchy/outgoingCalls", caller);
    assert!(
        outgoing.iter().any(|call| call["to"]["name"] == "target"),
        "outgoing calls should include target: {outgoing:#?}"
    );
}

#[test]
fn bifrost_lsp_server_call_hierarchy_prepare_filters_java_cursor_contexts() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("PrepareContexts.java");
    let source = "class Service {\n    static int VALUE = 1;\n    static void target() {}\n}\nclass Caller {\n    void helper() {\n        int local = 1;\n        Service value = null;\n        Service.target();\n        int field = Service.VALUE;\n    }\n}\n";
    fs::write(&file_path, source).expect("write Java prepare-context fixture");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);

    let (line, character) = position_after(source, "int l");
    let result = prepare_call_hierarchy_result(&mut server, &file_uri, line, character);
    assert!(
        result.is_null(),
        "local variables must not prepare call hierarchy: {result}"
    );

    let (line, character) = position_after(source, "        S");
    let result = prepare_call_hierarchy_result(&mut server, &file_uri, line, character);
    assert!(
        result.is_null(),
        "type references must not prepare call hierarchy: {result}"
    );

    let (line, character) = position_after(source, "Service.t");
    let target = prepare_call_hierarchy(&mut server, &file_uri, line, character);
    assert_eq!(target["name"], "target", "prepared target call: {target}");

    let (line, character) = position_after(source, "field = Service.V");
    let result = prepare_call_hierarchy_result(&mut server, &file_uri, line, character);
    assert!(
        result.is_null(),
        "field accesses must not prepare call hierarchy: {result}"
    );
}

#[test]
fn bifrost_lsp_server_call_hierarchy_prepare_filters_js_ts_cursor_contexts() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let ts_path = root.join("prepare.ts");
    let ts_source = "interface Shape {}\nclass Maker {}\nfunction target(): void {}\nfunction caller(): void {\n  let local = 1;\n  let typed: Shape | null = null;\n  target();\n  new Maker();\n}\n";
    fs::write(&ts_path, ts_source).expect("write TypeScript prepare-context fixture");
    let js_path = root.join("prepare.js");
    let js_source = "class Worker {\n  run() {}\n}\nfunction caller() {\n  const local = 1;\n  new Worker().run();\n}\n";
    fs::write(&js_path, js_source).expect("write JavaScript prepare-context fixture");

    let mut server = LspServer::start(&root);
    let ts_uri = uri_for(&ts_path);
    let js_uri = uri_for(&js_path);

    let (line, character) = position_after(ts_source, "function t");
    let target = prepare_call_hierarchy(&mut server, &ts_uri, line, character);
    assert_eq!(target["name"], "target", "prepared TS function: {target}");

    let (line, character) = position_after(js_source, "  r");
    let run = prepare_call_hierarchy(&mut server, &js_uri, line, character);
    assert_eq!(run["name"], "run", "prepared JS method: {run}");

    let (line, character) = position_after(ts_source, "let l");
    let result = prepare_call_hierarchy_result(&mut server, &ts_uri, line, character);
    assert!(
        result.is_null(),
        "TS local variables must not prepare call hierarchy: {result}"
    );

    let (line, character) = position_after(ts_source, "let typed: S");
    let result = prepare_call_hierarchy_result(&mut server, &ts_uri, line, character);
    assert!(
        result.is_null(),
        "TS type references must not prepare call hierarchy: {result}"
    );

    let (line, character) = position_after(ts_source, "  t");
    let target = prepare_call_hierarchy(&mut server, &ts_uri, line, character);
    assert_eq!(target["name"], "target", "prepared TS call: {target}");

    let (line, character) = position_after(ts_source, "new M");
    let maker = prepare_call_hierarchy(&mut server, &ts_uri, line, character);
    assert_eq!(maker["name"], "Maker", "prepared TS new call: {maker}");
}

#[test]
fn bifrost_lsp_server_call_hierarchy_prepare_filters_rust_cursor_contexts() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("lib.rs");
    let source = "struct Widget;\nfn target() {}\nfn caller() {\n    let local = 1;\n    let typed: Option<Widget> = None;\n    target();\n}\n";
    fs::write(&file_path, source).expect("write Rust prepare-context fixture");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);

    let (line, character) = position_after(source, "fn t");
    let target = prepare_call_hierarchy(&mut server, &file_uri, line, character);
    assert_eq!(target["name"], "target", "prepared Rust function: {target}");

    let (line, character) = position_after(source, "let l");
    let result = prepare_call_hierarchy_result(&mut server, &file_uri, line, character);
    assert!(
        result.is_null(),
        "Rust local variables must not prepare call hierarchy: {result}"
    );

    let (line, character) = position_after(source, "Option<W");
    let result = prepare_call_hierarchy_result(&mut server, &file_uri, line, character);
    assert!(
        result.is_null(),
        "Rust type references must not prepare call hierarchy: {result}"
    );

    let (line, character) = position_after(source, "    t");
    let target = prepare_call_hierarchy(&mut server, &file_uri, line, character);
    assert_eq!(target["name"], "target", "prepared Rust call: {target}");
}

#[test]
fn bifrost_lsp_server_call_hierarchy_prepare_filters_remaining_language_contexts() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");

    fs::write(
        root.join("go.mod"),
        "module example.com/prepare\n\ngo 1.22\n",
    )
    .expect("write go.mod");
    let go_path = root.join("prepare.go");
    let go_source = "package main\n\ntype Widget struct{}\nfunc target() {}\nfunc caller() {\n    local := 1\n    var typed Widget\n    _ = local\n    _ = typed\n    target()\n}\n";
    fs::write(&go_path, go_source).expect("write Go prepare-context fixture");

    let cs_path = root.join("Prepare.cs");
    let cs_source = "namespace App { class Service { public static int Value; public static void Target() {} } class Caller { void Helper() { var local = 1; Service.Target(); var field = Service.Value; } } }\n";
    fs::write(&cs_path, cs_source).expect("write C# prepare-context fixture");

    let cpp_path = root.join("prepare.cpp");
    let cpp_source = "struct Widget {};\nvoid target() {}\nvoid caller() {\n    int local = 1;\n    Widget typed;\n    target();\n}\n";
    fs::write(&cpp_path, cpp_source).expect("write C++ prepare-context fixture");

    let scala_path = root.join("Prepare.scala");
    let scala_source = "package app\nclass Widget\nobject Service {\n  def target(): Unit = ()\n  def caller(): Unit = {\n    val local = 1\n    val typed: Widget = new Widget\n    target()\n  }\n}\n";
    fs::write(&scala_path, scala_source).expect("write Scala prepare-context fixture");

    let py_path = root.join("prepare.py");
    let py_source = "class Widget:\n    pass\n\ndef target():\n    pass\n\ndef caller():\n    local = 1\n    target()\n";
    fs::write(&py_path, py_source).expect("write Python prepare-context fixture");

    let php_path = root.join("Prepare.php");
    let php_source = "<?php\nnamespace App;\nclass Widget {}\nfunction target(): void {}\nfunction caller(): void {\n    $local = 1;\n    target();\n}\n";
    fs::write(&php_path, php_source).expect("write PHP prepare-context fixture");

    let rb_path = root.join("prepare.rb");
    let rb_source = "class Worker\n  def target\n  end\n\n  def caller\n    target\n  end\nend\n";
    fs::write(&rb_path, rb_source).expect("write Ruby prepare-context fixture");

    let mut server = LspServer::start(&root);

    let go_uri = uri_for(&go_path);
    let (line, character) = position_after(go_source, "func t");
    let target = prepare_call_hierarchy(&mut server, &go_uri, line, character);
    assert_eq!(target["name"], "target", "prepared Go function: {target}");
    let (line, character) = position_after(go_source, "local :");
    let result = prepare_call_hierarchy_result(&mut server, &go_uri, line, character);
    assert!(result.is_null(), "Go locals must not prepare: {result}");
    let (line, character) = position_after(go_source, "    t");
    let target = prepare_call_hierarchy(&mut server, &go_uri, line, character);
    assert_eq!(target["name"], "target", "prepared Go call: {target}");

    let cs_uri = uri_for(&cs_path);
    let (line, character) = position_after(cs_source, "void T");
    let target = prepare_call_hierarchy(&mut server, &cs_uri, line, character);
    assert_eq!(target["name"], "Target", "prepared C# method: {target}");
    let (line, character) = position_after(cs_source, "local =");
    let result = prepare_call_hierarchy_result(&mut server, &cs_uri, line, character);
    assert!(result.is_null(), "C# locals must not prepare: {result}");
    let (line, character) = position_after(cs_source, "Service.T");
    let target = prepare_call_hierarchy(&mut server, &cs_uri, line, character);
    assert_eq!(target["name"], "Target", "prepared C# call: {target}");

    let cpp_uri = uri_for(&cpp_path);
    let (line, character) = position_after(cpp_source, "void t");
    let target = prepare_call_hierarchy(&mut server, &cpp_uri, line, character);
    assert_eq!(target["name"], "target", "prepared C++ function: {target}");
    let (line, character) = position_after(cpp_source, "local =");
    let result = prepare_call_hierarchy_result(&mut server, &cpp_uri, line, character);
    assert!(result.is_null(), "C++ locals must not prepare: {result}");
    let (line, character) = position_after(cpp_source, "    t");
    let target = prepare_call_hierarchy(&mut server, &cpp_uri, line, character);
    assert_eq!(target["name"], "target", "prepared C++ call: {target}");

    let scala_uri = uri_for(&scala_path);
    let (line, character) = position_after(scala_source, "def t");
    let target = prepare_call_hierarchy(&mut server, &scala_uri, line, character);
    assert_eq!(
        target["name"], "target",
        "prepared Scala function: {target}"
    );
    let (line, character) = position_after(scala_source, "val l");
    let result = prepare_call_hierarchy_result(&mut server, &scala_uri, line, character);
    assert!(result.is_null(), "Scala locals must not prepare: {result}");
    let (line, character) = position_after(scala_source, "    t");
    let target = prepare_call_hierarchy(&mut server, &scala_uri, line, character);
    assert_eq!(target["name"], "target", "prepared Scala call: {target}");

    let py_uri = uri_for(&py_path);
    let (line, character) = position_after(py_source, "def t");
    let target = prepare_call_hierarchy(&mut server, &py_uri, line, character);
    assert_eq!(
        target["name"], "target",
        "prepared Python function: {target}"
    );
    let (line, character) = position_after(py_source, "local =");
    let result = prepare_call_hierarchy_result(&mut server, &py_uri, line, character);
    assert!(result.is_null(), "Python locals must not prepare: {result}");
    let (line, character) = position_after(py_source, "    t");
    let target = prepare_call_hierarchy(&mut server, &py_uri, line, character);
    assert_eq!(target["name"], "target", "prepared Python call: {target}");

    let php_uri = uri_for(&php_path);
    let (line, character) = position_after(php_source, "function t");
    let target = prepare_call_hierarchy(&mut server, &php_uri, line, character);
    assert_eq!(target["name"], "target", "prepared PHP function: {target}");
    let (line, character) = position_after(php_source, "$local");
    let result = prepare_call_hierarchy_result(&mut server, &php_uri, line, character);
    assert!(result.is_null(), "PHP locals must not prepare: {result}");
    let (line, character) = position_after(php_source, "    t");
    let target = prepare_call_hierarchy(&mut server, &php_uri, line, character);
    assert_eq!(target["name"], "target", "prepared PHP call: {target}");

    let rb_uri = uri_for(&rb_path);
    let (line, character) = position_after(rb_source, "def t");
    let target = prepare_call_hierarchy(&mut server, &rb_uri, line, character);
    assert_eq!(target["name"], "target", "prepared Ruby method: {target}");
    let (line, character) = position_after(rb_source, "    t");
    let result = prepare_call_hierarchy_result(&mut server, &rb_uri, line, character);
    assert!(
        result.is_null(),
        "Ruby call references stay unsupported until Ruby definition lookup lands: {result}"
    );
}

#[test]
fn bifrost_lsp_server_call_hierarchy_preserves_java_overload_identity() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("Overloads.java");
    fs::write(
        &file_path,
        "class Service {\n    static void target() {}\n    static void target(String value) {}\n    static void stringCaller() {\n        target(\"x\");\n    }\n    static void noArgCaller() {\n        target();\n    }\n}\n",
    )
    .expect("write Java overload call hierarchy fixture");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);

    let string_target = prepare_call_hierarchy(&mut server, &file_uri, 2, 16);
    assert_eq!(
        string_target["detail"], "(String)",
        "prepared overload should carry String signature: {string_target}"
    );

    let incoming =
        call_hierarchy_relation(&mut server, "callHierarchy/incomingCalls", string_target);
    let callers: Vec<_> = incoming
        .iter()
        .filter_map(|call| call["from"]["name"].as_str())
        .collect();
    assert_eq!(
        callers,
        vec!["stringCaller"],
        "String overload should not include no-arg caller: {incoming:#?}"
    );
}

#[test]
fn bifrost_lsp_server_call_hierarchy_ignores_non_call_type_references() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("TypeReference.java");
    fs::write(
        &file_path,
        "class Service {}\nclass Caller {\n    void helper() {\n        Service value = null;\n    }\n}\n",
    )
    .expect("write Java type-reference call hierarchy fixture");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let service = prepare_call_hierarchy(&mut server, &file_uri, 0, 6);
    assert_eq!(service["name"], "Service", "prepared service: {service}");

    let incoming = call_hierarchy_relation(&mut server, "callHierarchy/incomingCalls", service);
    assert!(
        incoming.is_empty(),
        "type references without calls must not produce incoming call hierarchy edges: {incoming:#?}"
    );

    let helper = prepare_call_hierarchy(&mut server, &file_uri, 2, 10);

    let outgoing = call_hierarchy_relation(&mut server, "callHierarchy/outgoingCalls", helper);
    assert!(
        outgoing.is_empty(),
        "type references without calls must not produce outgoing call hierarchy edges: {outgoing:#?}"
    );
}

#[test]
fn bifrost_lsp_server_call_hierarchy_finds_qualified_java_constructor_calls() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let pkg_dir = root.join("pkg");
    fs::create_dir(&pkg_dir).expect("create package dir");
    let service_path = pkg_dir.join("Service.java");
    fs::write(&service_path, "package pkg;\npublic class Service {}\n")
        .expect("write Java service fixture");
    let caller_path = root.join("Caller.java");
    fs::write(
        &caller_path,
        "class Caller {\n    void helper() {\n        new pkg.Service();\n    }\n}\n",
    )
    .expect("write Java qualified constructor fixture");

    let mut server = LspServer::start(&root);
    let caller_uri = uri_for(&caller_path);
    let helper = prepare_call_hierarchy(&mut server, &caller_uri, 1, 10);

    let outgoing = call_hierarchy_relation(&mut server, "callHierarchy/outgoingCalls", helper);
    assert!(
        outgoing.iter().any(|call| call["to"]["name"] == "Service"),
        "qualified constructor calls should produce outgoing class edges: {outgoing:#?}"
    );
    let service_call = outgoing
        .iter()
        .find(|call| call["to"]["name"] == "Service")
        .expect("Service outgoing call");
    assert_call_range(&service_call["fromRanges"], 2, 16, 23);
}

#[test]
fn bifrost_lsp_server_call_hierarchy_does_not_include_nested_function_calls() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("nested.js");
    fs::write(
        &file_path,
        "function target() {}\nfunction outer() {\n    function inner() {\n        target();\n    }\n}\n",
    )
    .expect("write JavaScript nested call hierarchy fixture");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let outer = prepare_call_hierarchy(&mut server, &file_uri, 1, 9);

    let outgoing = call_hierarchy_relation(&mut server, "callHierarchy/outgoingCalls", outer);
    assert!(
        outgoing.is_empty(),
        "calls inside nested functions must not be attributed to the outer function: {outgoing:#?}"
    );
}

#[test]
fn bifrost_lsp_server_call_hierarchy_does_not_include_nested_type_calls() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("NestedType.java");
    fs::write(
        &file_path,
        "class Target {\n    static int value() { return 1; }\n}\nclass Outer {\n    class Inner {\n        int field = Target.value();\n    }\n}\n",
    )
    .expect("write Java nested type call hierarchy fixture");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let outer = prepare_call_hierarchy(&mut server, &file_uri, 3, 6);

    let outgoing = call_hierarchy_relation(&mut server, "callHierarchy/outgoingCalls", outer);
    assert!(
        outgoing.is_empty(),
        "calls inside nested types must not be attributed to the outer type: {outgoing:#?}"
    );
}

#[test]
fn bifrost_lsp_server_document_highlight_filters_to_current_file() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let mut server = LspServer::spawn(&fixture_root);

    let canonical_root = fixture_root.canonicalize().expect("canon fixture");
    let root_uri = uri_for(&canonical_root);
    let a_uri = uri_for(&canonical_root.join("A.java"));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
    }));
    let init = server.read_message();
    assert_eq!(
        init["result"]["capabilities"]["documentHighlightProvider"], true,
        "documentHighlightProvider should be advertised: {init}"
    );
    server.notify_value(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));

    // A.java line 2 (0-based), col 13: cursor on the `A` in `public class A {`.
    // The same `A` is referenced from A.java's own body (line 26 `new A()`,
    // line 33 inner-class `new A()`) and from B.java. The handler must
    // return only the A.java hits.
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/documentHighlight",
        "params": {
            "textDocument": {"uri": a_uri},
            "position": {"line": 2, "character": 13}
        }
    }));
    let response = server.read_message();
    let highlights = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected array result, got {response}"));
    assert!(
        !highlights.is_empty(),
        "expected at least one highlight, got: {response}"
    );

    // documentHighlight returns ranges only — no URI field, by spec. Make
    // sure no entry accidentally smuggled one in (i.e. we didn't return
    // `Location` shapes).
    for h in highlights {
        assert!(
            h["uri"].is_null(),
            "documentHighlight result must not include uri: {h}"
        );
        assert!(h["range"].is_object(), "highlight must have range: {h}");
    }

    // The two self-references in A.java live on line 26 (`System.out.println(new A())`)
    // and line 33 (`System.out.println(new A())`). Both must show up.
    let lines: Vec<u64> = highlights
        .iter()
        .filter_map(|h| h["range"]["start"]["line"].as_u64())
        .collect();
    assert!(
        lines.contains(&26) && lines.contains(&33),
        "expected both in-file self-reference highlights on lines 26 and 33, got lines {lines:?}"
    );

    // B.java references `A` on line 6 (`A a = new A();`). The cross-file
    // filter must drop those — if a `6` slips through, the filter regressed
    // (B.java has no other lines that overlap with A.java's expected hits).
    assert!(
        !lines.contains(&6),
        "B.java line-6 reference leaked into highlights, got lines {lines:?}"
    );

    // Regression: the declaration highlight on line 2 (`public class A {`)
    // must scope to the identifier `A` (single character), not the whole
    // class body. A multi-line declaration highlight wipes out the editor's
    // cursor highlight with a giant block.
    let class_decl_highlight = highlights
        .iter()
        .find(|h| h["range"]["start"]["line"].as_u64() == Some(2))
        .unwrap_or_else(|| panic!("expected declaration highlight on line 2, got {highlights:?}"));
    assert_eq!(
        class_decl_highlight["range"]["end"]["line"].as_u64(),
        Some(2),
        "class declaration highlight must stay on a single line, got {class_decl_highlight}"
    );
    assert_eq!(
        class_decl_highlight["range"]["start"]["character"].as_u64(),
        Some(13),
        "class declaration highlight must start at the `A` identifier, got {class_decl_highlight}"
    );
    assert_eq!(
        class_decl_highlight["range"]["end"]["character"].as_u64(),
        Some(14),
        "class declaration highlight must end after the `A` identifier, got {class_decl_highlight}"
    );

    server.notify_value(json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}));
    let _ = server.read_message();
    server.exit();
}

#[test]
fn bifrost_lsp_server_hover_includes_doc_comment() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    fs::write(
        temp_root.join("Documented.java"),
        "/**\n * The documented class.\n * Multi-line.\n */\npublic class Documented {\n    public void noop() {}\n}\n",
    )
    .expect("write fixture");

    let mut server = LspServer::spawn(&temp_root);

    let root_uri = uri_for(&temp_root);
    let doc_uri = uri_for(&temp_root.join("Documented.java"));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
    }));
    let _ = server.read_message();
    server.notify_value(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));

    // Line 4 (0-based) is `public class Documented {` — char 13 is the `D`.
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/hover",
        "params": {
            "textDocument": {"uri": doc_uri},
            "position": {"line": 4, "character": 13}
        }
    }));
    let response = server.read_message();
    let value = response["result"]["contents"]["value"]
        .as_str()
        .unwrap_or_else(|| panic!("expected markdown hover, got {response}"));
    assert!(
        value.contains("class Documented"),
        "hover should include the skeleton: {value}"
    );
    assert!(
        value.contains("The documented class."),
        "hover should include the doc comment first line: {value}"
    );
    assert!(
        value.contains("Multi-line."),
        "hover should include the doc comment second line: {value}"
    );
    assert!(
        !value.contains("/**") && !value.contains("*/"),
        "doc-comment markers should be stripped: {value}"
    );

    server.notify_value(json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}));
    let _ = server.read_message();
    server.exit();
}

#[test]
fn bifrost_lsp_server_hover_includes_rust_triple_slash_doc_comment() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    fs::write(
        temp_root.join("documented.rs"),
        "/// Returns the answer.\n/// Always 42.\npub fn answer() -> i32 { 42 }\n",
    )
    .expect("write fixture");

    let mut server = LspServer::spawn(&temp_root);

    let root_uri = uri_for(&temp_root);
    let doc_uri = uri_for(&temp_root.join("documented.rs"));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
    }));
    let _ = server.read_message();
    server.notify_value(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));

    // Line 2 (0-based) is `pub fn answer() -> i32 { 42 }`; char 7 is the `a`
    // in `answer`.
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/hover",
        "params": {
            "textDocument": {"uri": doc_uri},
            "position": {"line": 2, "character": 7}
        }
    }));
    let response = server.read_message();
    let value = response["result"]["contents"]["value"]
        .as_str()
        .unwrap_or_else(|| panic!("expected markdown hover, got {response}"));
    assert!(
        value.contains("fn answer"),
        "hover should include the skeleton: {value}"
    );
    assert!(
        value.contains("Returns the answer."),
        "hover should include the first /// line: {value}"
    );
    assert!(
        value.contains("Always 42."),
        "hover should include the second /// line: {value}"
    );
    assert!(
        !value.contains("///"),
        "/// markers should be stripped: {value}"
    );

    server.notify_value(json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}));
    let _ = server.read_message();
    server.exit();
}

#[test]
fn bifrost_lsp_server_hover_surfaces_rust_doc_above_outer_attribute() {
    // Regression: a `///` doc comment separated from the declaration by an
    // outer attribute (`#[derive(...)]`) must still be lifted into hover.
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    fs::write(
        temp_root.join("attrs.rs"),
        "/// Holds a single value.\n/// Cloneable for convenience.\n#[derive(Debug, Clone)]\npub struct Holder { value: i32 }\n",
    )
    .expect("write fixture");

    let mut server = LspServer::spawn(&temp_root);

    let root_uri = uri_for(&temp_root);
    let doc_uri = uri_for(&temp_root.join("attrs.rs"));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
    }));
    let _ = server.read_message();
    server.notify_value(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));

    // Line 3 (0-based) is `pub struct Holder { value: i32 }`; char 11 lands
    // on the `H` in `Holder`.
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/hover",
        "params": {
            "textDocument": {"uri": doc_uri},
            "position": {"line": 3, "character": 11}
        }
    }));
    let response = server.read_message();
    let value = response["result"]["contents"]["value"]
        .as_str()
        .unwrap_or_else(|| panic!("expected markdown hover, got {response}"));
    assert!(
        value.contains("Holds a single value."),
        "hover should surface the first /// line above the attribute: {value}"
    );
    assert!(
        value.contains("Cloneable for convenience."),
        "hover should surface the second /// line above the attribute: {value}"
    );
    assert!(
        !value.contains("derive"),
        "the #[derive(...)] attribute itself must not leak into hover markdown: {value}"
    );

    server.notify_value(json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}));
    let _ = server.read_message();
    server.exit();
}

#[test]
fn bifrost_lsp_server_diagnostics_report_parse_error() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    fs::write(
        temp_root.join("Bad.java"),
        "public class Bad {\n    public void broken( {\n}\n",
    )
    .expect("write fixture");

    let mut server = LspServer::spawn(&temp_root);

    let root_uri = uri_for(&temp_root);
    let bad_uri = uri_for(&temp_root.join("Bad.java"));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
    }));
    let init = server.read_message();
    assert!(
        init["result"]["capabilities"]["diagnosticProvider"].is_object(),
        "diagnosticProvider should be advertised: {init}"
    );
    server.notify_value(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/diagnostic",
        "params": {"textDocument": {"uri": bad_uri}}
    }));
    let response = server.read_message();
    let items = response["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("expected items array, got {response}"));
    assert!(
        !items.is_empty(),
        "expected at least one parse-error diagnostic for malformed Java: {response}"
    );
    assert_eq!(items[0]["severity"], 1, "severity should be Error");
    assert_eq!(items[0]["source"], "bifrost-tree-sitter");

    server.notify_value(json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}));
    let _ = server.read_message();
    server.exit();
}

#[test]
fn bifrost_lsp_server_diagnostics_edge_cases() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");

    // 1) A syntactically-valid Java file: should produce zero diagnostics.
    fs::write(
        temp_root.join("Clean.java"),
        "public class Clean {\n    public void ok() {}\n}\n",
    )
    .expect("write Clean.java");
    // 2) An unsupported extension: handler should return an empty report,
    //    not an error response, so editors don't spam users with red squiggles
    //    on plain text files.
    fs::write(
        temp_root.join("notes.txt"),
        "hello world\nthis is not source code",
    )
    .expect("write notes.txt");
    // 3) A binary file masquerading as `.java`: handler must not panic.
    fs::write(
        temp_root.join("Binary.java"),
        [0u8, 1, 2, 0xFF, 0xFE, 0xFD, 0u8, b'\n', b'a', b'b', 0u8],
    )
    .expect("write Binary.java");

    let mut server = LspServer::spawn(&temp_root);

    let root_uri = uri_for(&temp_root);
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
    }));
    let _ = server.read_message();
    server.notify_value(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));

    let cases: &[(&str, &str)] = &[
        ("clean", "Clean.java"),
        ("text", "notes.txt"),
        ("binary", "Binary.java"),
    ];
    for (idx, (label, name)) in cases.iter().enumerate() {
        let id = (idx as u64) + 2;
        let uri = uri_for(&temp_root.join(name));
        server.notify_value(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "textDocument/diagnostic",
            "params": {"textDocument": {"uri": uri}}
        }));
        let response = server.read_message();
        assert!(
            response["error"].is_null(),
            "{label}: should not be a JSON-RPC error: {response}"
        );
        let items = response["result"]["items"]
            .as_array()
            .unwrap_or_else(|| panic!("{label}: expected items array, got {response}"));
        assert!(
            items.is_empty(),
            "{label}: expected zero diagnostics, got {items:#?}"
        );
    }

    server.notify_value(json!({"jsonrpc": "2.0", "id": 99, "method": "shutdown"}));
    let _ = server.read_message();
    server.exit();
}

#[test]
fn bifrost_lsp_server_go_semantic_diagnostics_pull_suppresses_unrecognized_symbol_lints() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    fs::write(
        temp_root.join("go.mod"),
        "module example.com/app\n\ngo 1.22\n",
    )
    .expect("write go.mod");
    fs::create_dir_all(temp_root.join("store")).expect("create store");
    fs::write(
        temp_root.join("store/store.go"),
        "package store\n\nfunc Present() {}\n",
    )
    .expect("write store");
    fs::write(
        temp_root.join("main.go"),
        r#"
package main

import "example.com/app/store"

func Run() {
    missingValue
    store.Missing()
}
"#,
    )
    .expect("write main.go");

    let mut server = LspServer::start(&temp_root);
    let main_uri = uri_for(&temp_root.join("main.go"));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/diagnostic",
        "params": {"textDocument": {"uri": main_uri}}
    }));
    let response = server.read_message();
    let items = response["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("expected items array, got {response}"));
    assert!(items.is_empty(), "expected no semantic lints: {response}");
}

#[test]
fn bifrost_lsp_server_unrecognized_symbol_diagnostics_are_runtime_opt_in() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    fs::write(temp_root.join("app.py"), "def run():\n    missing_value\n").expect("write app.py");

    let mut server = LspServer::start(&temp_root);
    let app_uri = uri_for(&temp_root.join("app.py"));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/diagnostic",
        "params": {"textDocument": {"uri": app_uri}}
    }));
    let disabled_response = server.read_message();
    assert!(
        disabled_response["result"]["items"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "unrecognized-symbol linting must be disabled by default: {disabled_response}"
    );

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didSave",
        "params": {"textDocument": {"uri": app_uri}}
    }));
    let initially_published = server.read_notification("textDocument/publishDiagnostics");
    assert!(
        initially_published["params"]["diagnostics"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "default-off diagnostics must publish an empty report: {initially_published}"
    );

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "workspace/didChangeConfiguration",
        "params": {"settings": {"unrecognizedSymbolDiagnostics": true}}
    }));
    let enabled_publish = server.read_notification("textDocument/publishDiagnostics");
    assert!(
        enabled_publish["params"]["diagnostics"]
            .as_array()
            .is_some_and(|items| {
                items
                    .iter()
                    .any(|item| item["code"] == "python_unrecognized_symbol")
            }),
        "enabling the opt-in must refresh existing push diagnostics: {enabled_publish}"
    );

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "textDocument/diagnostic",
        "params": {"textDocument": {"uri": app_uri}}
    }));
    let enabled_response = server.read_message();
    assert!(
        enabled_response["result"]["items"]
            .as_array()
            .is_some_and(|items| {
                items.iter().any(|item| {
                    item["source"] == "bifrost-python"
                        && item["code"] == "python_unrecognized_symbol"
                        && item["message"]
                            .as_str()
                            .is_some_and(|message| message.contains("missing_value"))
                })
            }),
        "the opt-in must publish the semantic lint: {enabled_response}"
    );

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didSave",
        "params": {"textDocument": {"uri": app_uri}}
    }));
    let published = server.read_notification("textDocument/publishDiagnostics");
    assert!(
        published["params"]["diagnostics"]
            .as_array()
            .is_some_and(|items| {
                items
                    .iter()
                    .any(|item| item["code"] == "python_unrecognized_symbol")
            }),
        "the opt-in must apply to push diagnostics: {published}"
    );

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "workspace/didChangeConfiguration",
        "params": {"settings": {"unrecognizedSymbolDiagnostics": false}}
    }));
    let cleared = server.read_notification("textDocument/publishDiagnostics");
    assert!(
        cleared["params"]["diagnostics"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "disabling the opt-in must clear previously published lints: {cleared}"
    );

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "textDocument/diagnostic",
        "params": {"textDocument": {"uri": app_uri}}
    }));
    let re_disabled_response = server.read_message();
    assert!(
        re_disabled_response["result"]["items"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "disabling the opt-in must suppress the semantic lint again: {re_disabled_response}"
    );

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "workspace/didChangeConfiguration",
        "params": {"settings": {"unrecognizedSymbolDiagnostics": true}}
    }));
    let re_enabled_publish = server.read_notification("textDocument/publishDiagnostics");
    assert!(
        re_enabled_publish["params"]["diagnostics"]
            .as_array()
            .is_some_and(|items| {
                items
                    .iter()
                    .any(|item| item["code"] == "python_unrecognized_symbol")
            }),
        "re-enabling the opt-in must refresh existing push diagnostics: {re_enabled_publish}"
    );

    fs::write(temp_root.join("app.py"), "def run(\n    missing_value\n")
        .expect("write malformed app.py");
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didSave",
        "params": {"textDocument": {"uri": app_uri}}
    }));
    let parse_error = server.read_notification("textDocument/publishDiagnostics");
    assert!(
        parse_error["params"]["diagnostics"]
            .as_array()
            .is_some_and(|items| {
                items
                    .iter()
                    .any(|item| item["source"] == "bifrost-tree-sitter")
            }),
        "expected a parse diagnostic before disabling the semantic lint: {parse_error}"
    );

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "workspace/didChangeConfiguration",
        "params": {"settings": {"unrecognizedSymbolDiagnostics": false}}
    }));
    let retained_parse_error = server.read_notification("textDocument/publishDiagnostics");
    assert!(
        retained_parse_error["params"]["diagnostics"]
            .as_array()
            .is_some_and(|items| {
                items
                    .iter()
                    .any(|item| item["source"] == "bifrost-tree-sitter")
            }),
        "disabling the semantic lint must retain parser diagnostics: {retained_parse_error}"
    );
}

#[test]
fn bifrost_lsp_server_go_malformed_file_reports_parse_not_semantic_diagnostics() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    fs::write(
        temp_root.join("go.mod"),
        "module example.com/app\n\ngo 1.22\n",
    )
    .expect("write go.mod");
    fs::write(
        temp_root.join("broken.go"),
        "package main\n\nfunc Run( {\n    missingValue\n}\n",
    )
    .expect("write broken.go");

    let mut server = LspServer::start(&temp_root);
    let broken_uri = uri_for(&temp_root.join("broken.go"));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/diagnostic",
        "params": {"textDocument": {"uri": broken_uri}}
    }));
    let response = server.read_message();
    let items = response["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("expected items array, got {response}"));
    assert!(
        items
            .iter()
            .any(|item| item["source"] == "bifrost-tree-sitter"),
        "expected parse diagnostic for malformed Go: {response}"
    );
    assert!(
        items.iter().all(|item| item["source"] != "bifrost-go"),
        "malformed Go must suppress semantic diagnostics: {response}"
    );
}

#[test]
fn bifrost_lsp_server_python_semantic_diagnostics_pull_suppresses_unrecognized_symbol_lints() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    fs::write(
        temp_root.join("app.py"),
        r#"
def run():
    missing_value
"#,
    )
    .expect("write app.py");

    let mut server = LspServer::start(&temp_root);
    let app_uri = uri_for(&temp_root.join("app.py"));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/diagnostic",
        "params": {"textDocument": {"uri": app_uri}}
    }));
    let response = server.read_message();
    let items = response["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("expected items array, got {response}"));
    assert!(items.is_empty(), "expected no semantic lints: {response}");
}

#[test]
fn bifrost_lsp_server_python_semantic_diagnostics_malformed_file_reports_parse_not_semantic() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    fs::write(temp_root.join("broken.py"), "def run(\n    missing_value\n")
        .expect("write broken.py");

    let mut server = LspServer::start(&temp_root);
    let broken_uri = uri_for(&temp_root.join("broken.py"));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/diagnostic",
        "params": {"textDocument": {"uri": broken_uri}}
    }));
    let response = server.read_message();
    let items = response["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("expected items array, got {response}"));
    assert!(
        items
            .iter()
            .any(|item| item["source"] == "bifrost-tree-sitter"),
        "expected parse diagnostic for malformed Python: {response}"
    );
    assert!(
        items.iter().all(|item| item["source"] != "bifrost-python"),
        "malformed Python must suppress semantic diagnostics: {response}"
    );
}

#[test]
fn bifrost_lsp_server_php_semantic_diagnostics_pull_suppresses_unrecognized_symbol_lints() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    fs::create_dir_all(temp_root.join("src")).expect("create src");
    fs::write(
        temp_root.join("src/Service.php"),
        r#"<?php
namespace App;

class Anchor {}

class Service {
    private MissingType $value;

    public function run(): void {
        \App\missing_function();
    }
}
"#,
    )
    .expect("write php fixture");

    let mut server = LspServer::start(&temp_root);
    let php_uri = uri_for(&temp_root.join("src/Service.php"));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/diagnostic",
        "params": {"textDocument": {"uri": php_uri}}
    }));
    let response = server.read_message();
    let items = response["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("expected items array, got {response}"));
    assert!(items.is_empty(), "expected no semantic lints: {response}");
}

#[test]
fn bifrost_lsp_server_php_semantic_diagnostics_malformed_file_reports_parse_not_semantic() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    fs::write(
        temp_root.join("broken.php"),
        "<?php\nnamespace App;\nclass Broken { public function run(: void { MissingType; }\n",
    )
    .expect("write broken php");

    let mut server = LspServer::start(&temp_root);
    let php_uri = uri_for(&temp_root.join("broken.php"));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/diagnostic",
        "params": {"textDocument": {"uri": php_uri}}
    }));
    let response = server.read_message();
    let items = response["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("expected items array, got {response}"));
    assert!(
        items
            .iter()
            .any(|item| item["source"] == "bifrost-tree-sitter"),
        "expected parse diagnostic for malformed PHP: {response}"
    );
    assert!(
        items.iter().all(|item| item["source"] != "bifrost-php"),
        "malformed PHP must suppress semantic diagnostics: {response}"
    );
}

#[test]
fn bifrost_lsp_server_rust_semantic_diagnostics_pull_suppresses_unrecognized_symbol_lints() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    fs::create_dir_all(temp_root.join("src")).expect("create src");
    fs::write(
        temp_root.join("src/main.rs"),
        r#"
fn run(input: MissingType) {
    missing_value;
}
"#,
    )
    .expect("write rust fixture");

    let mut server = LspServer::start(&temp_root);
    let rust_uri = uri_for(&temp_root.join("src/main.rs"));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/diagnostic",
        "params": {"textDocument": {"uri": rust_uri}}
    }));
    let response = server.read_message();
    let items = response["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("expected items array, got {response}"));
    assert!(items.is_empty(), "expected no semantic lints: {response}");
}

#[test]
fn bifrost_lsp_server_rust_semantic_diagnostics_malformed_file_reports_parse_not_semantic() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    fs::create_dir_all(temp_root.join("src")).expect("create src");
    fs::write(
        temp_root.join("src/main.rs"),
        "fn run( {\n    missing_value;\n}\n",
    )
    .expect("write broken rust");

    let mut server = LspServer::start(&temp_root);
    let rust_uri = uri_for(&temp_root.join("src/main.rs"));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/diagnostic",
        "params": {"textDocument": {"uri": rust_uri}}
    }));
    let response = server.read_message();
    let items = response["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("expected items array, got {response}"));
    assert!(
        items
            .iter()
            .any(|item| item["source"] == "bifrost-tree-sitter"),
        "expected parse diagnostic for malformed Rust: {response}"
    );
    assert!(
        items.iter().all(|item| item["source"] != "bifrost-rust"),
        "malformed Rust must suppress semantic diagnostics: {response}"
    );
}

#[test]
fn bifrost_lsp_server_js_ts_semantic_diagnostics_pull_suppresses_unrecognized_symbol_lints() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    fs::write(
        temp_root.join("app.js"),
        "function run(known) {\n  const local = known;\n  missingValue;\n  local;\n}\n",
    )
    .expect("write js fixture");
    fs::write(
        temp_root.join("types.ts"),
        "type Present = string;\nfunction run(value: Present): MissingType {\n  return missingValue;\n}\n",
    )
    .expect("write ts fixture");

    let mut server = LspServer::start(&temp_root);
    let js_uri = uri_for(&temp_root.join("app.js"));
    let ts_uri = uri_for(&temp_root.join("types.ts"));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/diagnostic",
        "params": {"textDocument": {"uri": js_uri}}
    }));
    let js_response = server.read_message();
    let js_items = js_response["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("expected items array, got {js_response}"));
    assert!(
        js_items.is_empty(),
        "expected no JavaScript semantic lints: {js_response}"
    );

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "textDocument/diagnostic",
        "params": {"textDocument": {"uri": ts_uri}}
    }));
    let ts_response = server.read_message();
    let ts_items = ts_response["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("expected items array, got {ts_response}"));
    assert!(
        ts_items.is_empty(),
        "expected no TypeScript semantic lints: {ts_response}"
    );
}

#[test]
fn bifrost_lsp_server_js_ts_malformed_file_reports_parse_not_semantic_diagnostics() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    fs::write(
        temp_root.join("broken.js"),
        "function run( {\n  missingValue;\n}\n",
    )
    .expect("write broken js");

    let mut server = LspServer::start(&temp_root);
    let broken_uri = uri_for(&temp_root.join("broken.js"));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/diagnostic",
        "params": {"textDocument": {"uri": broken_uri}}
    }));
    let response = server.read_message();
    let items = response["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("expected items array, got {response}"));
    assert!(
        items
            .iter()
            .any(|item| item["source"] == "bifrost-tree-sitter"),
        "expected parse diagnostic for malformed JavaScript: {response}"
    );
    assert!(
        items
            .iter()
            .all(|item| item["source"] != "bifrost-javascript"),
        "malformed JavaScript must suppress semantic diagnostics: {response}"
    );
}

#[test]
fn bifrost_lsp_server_did_save_triggers_reindex() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    fs::write(
        temp_root.join("Watch.java"),
        "public class Watch {\n    public void initial() {}\n}\n",
    )
    .expect("write fixture");

    let mut server = LspServer::spawn(&temp_root);

    let root_uri = uri_for(&temp_root);
    let watch_uri = uri_for(&temp_root.join("Watch.java"));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
    }));
    let _ = server.read_message();
    server.notify_value(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));

    // Confirm initial workspaceSymbol query finds `initial` and not `added`.
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "workspace/symbol",
        "params": {"query": "added"}
    }));
    let before = server.read_message();
    let names_before: Vec<String> = before["result"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s["name"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        !names_before.iter().any(|n| n == "added"),
        "expected no `added` symbol pre-save, got {names_before:?}"
    );

    // Replace the file content and send didSave.
    fs::write(
        temp_root.join("Watch.java"),
        "public class Watch {\n    public void added() {}\n}\n",
    )
    .expect("rewrite fixture");
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didSave",
        "params": {"textDocument": {"uri": watch_uri}}
    }));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "workspace/symbol",
        "params": {"query": "added"}
    }));
    // didSave now emits a publishDiagnostics notification before the
    // workspace/symbol response — skip past it.
    let after = server.read_response_for_id(3);
    let names_after: Vec<String> = after["result"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s["name"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        names_after.iter().any(|n| n == "added"),
        "expected `added` symbol post-save, got {names_after:?}"
    );

    server.notify_value(json!({"jsonrpc": "2.0", "id": 4, "method": "shutdown"}));
    let _ = server.read_message();
    server.exit();
}

#[test]
fn bifrost_lsp_server_hover_uses_python_language_tag_for_py_file() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-py");

    let mut server = LspServer::spawn(&fixture_root);

    let canonical_root = fixture_root.canonicalize().expect("canon fixture");
    let root_uri = uri_for(&canonical_root);
    let py_path = canonical_root.join("documented.py");
    let py_uri = uri_for(&py_path);
    let py_source = std::fs::read_to_string(&py_path).expect("read documented.py");
    let (line, character) = position_after(&py_source, "class ");

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
    }));
    let _ = server.read_message();
    server.notify_value(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));

    // Guards against the language-tag table emitting "java" (or any wrong tag)
    // for a .py file.
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/hover",
        "params": {
            "textDocument": {"uri": py_uri},
            "position": {"line": line, "character": character}
        }
    }));
    let response = server.read_message();
    let value = response["result"]["contents"]["value"]
        .as_str()
        .unwrap_or_else(|| panic!("expected markdown hover, got {response}"));
    assert!(
        value.starts_with("```python"),
        "expected python-fenced hover for .py file, got: {value}"
    );
    assert!(
        value.contains("DocumentedClass"),
        "hover should mention DocumentedClass, got: {value}"
    );

    server.notify_value(json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}));
    let _ = server.read_message();
    server.exit();
}

#[test]
fn bifrost_lsp_server_unknown_request_returns_method_not_found() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let mut server = LspServer::spawn(&fixture_root);

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"processId": null, "rootUri": null, "capabilities": {}}
    }));
    let _ = server.read_message();
    server.notify_value(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "bifrost/unknownRequest",
        "params": {}
    }));
    let response = server.read_message();
    assert_eq!(response["id"], 2);
    assert_eq!(
        response["error"]["code"], -32601,
        "expected MethodNotFound (-32601): {response}"
    );

    server.notify_value(json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}));
    let _ = server.read_message();
    server.exit();
}

#[test]
fn bifrost_lsp_server_did_save_publishes_diagnostics() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    // Start with a file that parses cleanly.
    fs::write(
        temp_root.join("Push.java"),
        "public class Push {\n    public void ok() {}\n}\n",
    )
    .expect("write fixture");

    let mut server = LspServer::spawn(&temp_root);

    let root_uri = uri_for(&temp_root);
    let push_uri = uri_for(&temp_root.join("Push.java"));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
    }));
    let _ = server.read_message();
    server.notify_value(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));

    // Replace the file with broken Java, then send didSave. The server should
    // emit a `textDocument/publishDiagnostics` notification with at least one
    // parse-error item.
    fs::write(
        temp_root.join("Push.java"),
        "public class Push {\n    public void broken( {\n}\n",
    )
    .expect("rewrite fixture");
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didSave",
        "params": {"textDocument": {"uri": push_uri}}
    }));

    let publish = server.read_notification("textDocument/publishDiagnostics");
    assert_eq!(
        publish["params"]["uri"].as_str(),
        Some(push_uri.as_str()),
        "publishDiagnostics URI should match the saved file: {publish}"
    );
    let items = publish["params"]["diagnostics"]
        .as_array()
        .unwrap_or_else(|| panic!("expected diagnostics array, got {publish}"));
    assert!(
        !items.is_empty(),
        "expected at least one parse-error diagnostic for malformed Java: {publish}"
    );
    assert!(
        items
            .iter()
            .any(|d| d["severity"] == 1 && d["source"] == "bifrost-tree-sitter"),
        "expected an Error-severity bifrost-tree-sitter diagnostic: {publish}"
    );

    // Now save a clean version and verify the server sends an empty
    // diagnostics array — clients use this to clear stale red squiggles.
    fs::write(
        temp_root.join("Push.java"),
        "public class Push {\n    public void ok() {}\n}\n",
    )
    .expect("rewrite fixture");
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didSave",
        "params": {"textDocument": {"uri": push_uri}}
    }));
    let cleared = server.read_notification("textDocument/publishDiagnostics");
    let cleared_items = cleared["params"]["diagnostics"]
        .as_array()
        .unwrap_or_else(|| panic!("expected diagnostics array, got {cleared}"));
    assert!(
        cleared_items.is_empty(),
        "expected zero diagnostics after clean save, got {cleared}"
    );

    server.notify_value(json!({"jsonrpc": "2.0", "id": 99, "method": "shutdown"}));
    let _ = server.read_message();
    server.exit();
}

#[test]
fn bifrost_lsp_server_did_save_suppresses_go_semantic_diagnostics() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    fs::write(
        temp_root.join("go.mod"),
        "module example.com/app\n\ngo 1.22\n",
    )
    .expect("write go.mod");
    fs::write(
        temp_root.join("main.go"),
        "package main\n\nfunc Run() {\n    println(\"ok\")\n}\n",
    )
    .expect("write fixture");

    let mut server = LspServer::start(&temp_root);
    let main_uri = uri_for(&temp_root.join("main.go"));

    fs::write(
        temp_root.join("main.go"),
        "package main\n\nfunc Run() {\n    missingValue\n}\n",
    )
    .expect("rewrite fixture");
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didSave",
        "params": {"textDocument": {"uri": main_uri}}
    }));

    let publish = server.read_notification("textDocument/publishDiagnostics");
    let items = publish["params"]["diagnostics"]
        .as_array()
        .unwrap_or_else(|| panic!("expected diagnostics array, got {publish}"));
    assert!(items.is_empty(), "expected no semantic lints: {publish}");
}

#[test]
fn bifrost_lsp_server_did_save_suppresses_python_semantic_diagnostics() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    fs::write(temp_root.join("app.py"), "def run():\n    print(\"ok\")\n").expect("write fixture");

    let mut server = LspServer::start(&temp_root);
    let app_uri = uri_for(&temp_root.join("app.py"));

    fs::write(temp_root.join("app.py"), "def run():\n    missing_value\n")
        .expect("rewrite fixture");
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didSave",
        "params": {"textDocument": {"uri": app_uri}}
    }));

    let publish = server.read_notification("textDocument/publishDiagnostics");
    let items = publish["params"]["diagnostics"]
        .as_array()
        .unwrap_or_else(|| panic!("expected diagnostics array, got {publish}"));
    assert!(items.is_empty(), "expected no semantic lints: {publish}");
}

#[test]
fn bifrost_lsp_server_did_save_suppresses_php_semantic_diagnostics() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    fs::write(
        temp_root.join("Service.php"),
        "<?php\nnamespace App;\nclass Anchor {}\nclass Service { public function run(): void {} }\n",
    )
    .expect("write fixture");

    let mut server = LspServer::start(&temp_root);
    let php_uri = uri_for(&temp_root.join("Service.php"));

    fs::write(
        temp_root.join("Service.php"),
        "<?php\nnamespace App;\nclass Anchor {}\nclass Service { private MissingType $value; }\n",
    )
    .expect("rewrite fixture");
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didSave",
        "params": {"textDocument": {"uri": php_uri}}
    }));

    let publish = server.read_notification("textDocument/publishDiagnostics");
    let items = publish["params"]["diagnostics"]
        .as_array()
        .unwrap_or_else(|| panic!("expected diagnostics array, got {publish}"));
    assert!(items.is_empty(), "expected no semantic lints: {publish}");
}

#[test]
fn bifrost_lsp_server_did_save_suppresses_rust_semantic_diagnostics() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    fs::create_dir_all(temp_root.join("src")).expect("create src");
    fs::write(temp_root.join("src/main.rs"), "fn run() {}\n").expect("write fixture");

    let mut server = LspServer::start(&temp_root);
    let rust_uri = uri_for(&temp_root.join("src/main.rs"));

    fs::write(
        temp_root.join("src/main.rs"),
        "fn run() {\n    missing_value;\n}\n",
    )
    .expect("rewrite fixture");
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didSave",
        "params": {"textDocument": {"uri": rust_uri}}
    }));

    let publish = server.read_notification("textDocument/publishDiagnostics");
    let items = publish["params"]["diagnostics"]
        .as_array()
        .unwrap_or_else(|| panic!("expected diagnostics array, got {publish}"));
    assert!(items.is_empty(), "expected no semantic lints: {publish}");
}

#[test]
fn bifrost_lsp_server_did_save_suppresses_js_ts_semantic_diagnostics() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    fs::write(temp_root.join("app.ts"), "function run() { return 1; }\n").expect("write fixture");

    let mut server = LspServer::start(&temp_root);
    let ts_uri = uri_for(&temp_root.join("app.ts"));

    fs::write(
        temp_root.join("app.ts"),
        "function run(): MissingType {\n  return missingValue;\n}\n",
    )
    .expect("rewrite fixture");
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didSave",
        "params": {"textDocument": {"uri": ts_uri}}
    }));

    let publish = server.read_notification("textDocument/publishDiagnostics");
    let items = publish["params"]["diagnostics"]
        .as_array()
        .unwrap_or_else(|| panic!("expected diagnostics array, got {publish}"));
    assert!(items.is_empty(), "expected no semantic lints: {publish}");
}

#[test]
fn bifrost_lsp_server_returns_folding_ranges_for_a_java() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let mut server = LspServer::spawn(&fixture_root);

    let canonical_root = fixture_root.canonicalize().expect("canon fixture");
    let root_uri = uri_for(&canonical_root);
    let file_uri = uri_for(&canonical_root.join("A.java"));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "processId": null,
            "rootUri": root_uri,
            "capabilities": {}
        }
    }));
    let init = server.read_message();
    assert_eq!(init["id"], 1);
    assert_eq!(
        init["result"]["capabilities"]["foldingRangeProvider"], true,
        "foldingRangeProvider should be advertised: {init}"
    );
    server.notify_value(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "textDocument/foldingRange",
        "params": {"textDocument": {"uri": file_uri}}
    }));
    let response = server.read_message();
    assert_eq!(response["id"], 2);
    let folds = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected array result, got {response}"));

    assert!(
        !folds.is_empty(),
        "expected at least one folding range, got {folds:#?}"
    );

    // No mono-line folds, and dedup invariant: every (startLine, endLine) pair is unique.
    let mut pairs: Vec<(u64, u64)> = Vec::with_capacity(folds.len());
    for fold in folds {
        let start = fold["startLine"]
            .as_u64()
            .unwrap_or_else(|| panic!("startLine missing or non-numeric: {fold}"));
        let end = fold["endLine"]
            .as_u64()
            .unwrap_or_else(|| panic!("endLine missing or non-numeric: {fold}"));
        assert!(end > start, "mono-line fold leaked through filter: {fold}");
        pairs.push((start, end));
    }
    let mut sorted = pairs.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        pairs.len(),
        "duplicate folds returned: {pairs:?}"
    );

    server.notify_value(json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}));
    let _ = server.read_message();
    server.exit();
}

#[test]
fn bifrost_lsp_server_type_hierarchy_java_round_trips_item_data() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("Hierarchy.java");
    fs::write(
        &file_path,
        "class Base {}\nclass Child extends Base {\n    void method() {}\n}\n",
    )
    .expect("write Java hierarchy fixture");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);

    let child_item = prepare_type_hierarchy(&mut server, &file_uri, 1, 6);
    assert_eq!(child_item["name"], "Child", "prepared child: {child_item}");

    let supertypes = type_hierarchy_relation(&mut server, "typeHierarchy/supertypes", child_item);
    assert_eq!(
        supertypes.len(),
        1,
        "expected one supertype: {supertypes:#?}"
    );
    assert_eq!(supertypes[0]["name"], "Base", "supertype should be Base");

    let base_item = supertypes[0].clone();
    let subtypes = type_hierarchy_relation(&mut server, "typeHierarchy/subtypes", base_item);
    let subtype_names: Vec<_> = subtypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(subtype_names, vec!["Child"], "subtypes: {subtypes:#?}");
}

#[test]
fn bifrost_lsp_server_type_hierarchy_python_uses_same_handler() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("hierarchy.py");
    fs::write(
        &file_path,
        "class Base:\n    pass\n\nclass Child(Base):\n    def method(self):\n        pass\n",
    )
    .expect("write Python hierarchy fixture");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let child_item = prepare_type_hierarchy(&mut server, &file_uri, 3, 6);

    let supertypes = type_hierarchy_relation(&mut server, "typeHierarchy/supertypes", child_item);
    let supertype_names: Vec<_> = supertypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(supertype_names, vec!["Base"], "supertypes: {supertypes:#?}");
}

#[test]
fn bifrost_lsp_server_type_hierarchy_javascript_uses_same_handler() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("hierarchy.js");
    fs::write(
        &file_path,
        "class Base {}\nclass Child extends Base {\n    method() {}\n}\n",
    )
    .expect("write JavaScript hierarchy fixture");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let child_item = prepare_type_hierarchy(&mut server, &file_uri, 1, 6);
    assert_eq!(child_item["name"], "Child", "prepared child: {child_item}");

    let supertypes = type_hierarchy_relation(&mut server, "typeHierarchy/supertypes", child_item);
    let supertype_names: Vec<_> = supertypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(supertype_names, vec!["Base"], "supertypes: {supertypes:#?}");

    let base_item = supertypes[0].clone();
    let subtypes = type_hierarchy_relation(&mut server, "typeHierarchy/subtypes", base_item);
    let subtype_names: Vec<_> = subtypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(subtype_names, vec!["Child"], "subtypes: {subtypes:#?}");
}

#[test]
fn bifrost_lsp_server_type_hierarchy_typescript_uses_same_handler() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("hierarchy.ts");
    let source = "interface Runnable {}\nclass Base {}\nclass Child extends Base implements Runnable {\n    method(): void {}\n}\nlet typed: Base | null = null;\n";
    fs::write(&file_path, source).expect("write TypeScript hierarchy fixture");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let child_item = prepare_type_hierarchy(&mut server, &file_uri, 2, 6);
    assert_eq!(child_item["name"], "Child", "prepared child: {child_item}");

    let supertypes = type_hierarchy_relation(&mut server, "typeHierarchy/supertypes", child_item);
    let supertype_names: Vec<_> = supertypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(
        supertype_names,
        vec!["Base", "Runnable"],
        "supertypes: {supertypes:#?}"
    );

    let base_item = supertypes
        .iter()
        .find(|item| item["name"] == "Base")
        .cloned()
        .expect("Base supertype item");
    let subtypes = type_hierarchy_relation(&mut server, "typeHierarchy/subtypes", base_item);
    let subtype_names: Vec<_> = subtypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(subtype_names, vec!["Child"], "subtypes: {subtypes:#?}");

    let (line, character) = position_after(source, "typed: ");
    let base_ref = prepare_type_hierarchy(&mut server, &file_uri, line, character);
    assert_eq!(
        base_ref["name"], "Base",
        "prepared TypeScript Base reference: {base_ref}"
    );

    let (line, character) = position_after(source, "let t");
    let result = prepare_hierarchy_result(
        &mut server,
        "textDocument/prepareTypeHierarchy",
        &file_uri,
        (line, character),
    );
    assert!(
        result.is_null(),
        "TypeScript local declaration names must not prepare hierarchy: {result}"
    );
}

#[test]
fn bifrost_lsp_server_type_hierarchy_php_uses_same_handler() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("Hierarchy.php");
    fs::write(
        &file_path,
        "<?php\nnamespace App;\ninterface Contract {}\nclass Base {}\nclass Child extends Base implements Contract {\n    public function method(): void {}\n}\n",
    )
    .expect("write PHP hierarchy fixture");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let child_item = prepare_type_hierarchy(&mut server, &file_uri, 4, 6);

    let supertypes = type_hierarchy_relation(&mut server, "typeHierarchy/supertypes", child_item);
    let supertype_names: Vec<_> = supertypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(
        supertype_names,
        vec!["Base", "Contract"],
        "supertypes: {supertypes:#?}"
    );

    let base_item = supertypes
        .iter()
        .find(|item| item["name"] == "Base")
        .cloned()
        .expect("Base supertype item");
    let subtypes = type_hierarchy_relation(&mut server, "typeHierarchy/subtypes", base_item);
    let subtype_names: Vec<_> = subtypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(subtype_names, vec!["Child"], "subtypes: {subtypes:#?}");
}

#[test]
fn bifrost_lsp_server_type_hierarchy_cpp_uses_same_handler() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("Hierarchy.cpp");
    fs::write(
        &file_path,
        "struct Base {};\nstruct Child : Base {\n    void method() {}\n};\n",
    )
    .expect("write C++ hierarchy fixture");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let child_item = prepare_type_hierarchy(&mut server, &file_uri, 1, 8);
    assert_eq!(child_item["name"], "Child", "prepared child: {child_item}");

    let supertypes = type_hierarchy_relation(&mut server, "typeHierarchy/supertypes", child_item);
    let supertype_names: Vec<_> = supertypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(supertype_names, vec!["Base"], "supertypes: {supertypes:#?}");

    let base_item = supertypes[0].clone();
    let subtypes = type_hierarchy_relation(&mut server, "typeHierarchy/subtypes", base_item);
    let subtype_names: Vec<_> = subtypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(subtype_names, vec!["Child"], "subtypes: {subtypes:#?}");
}

#[test]
fn bifrost_lsp_server_type_hierarchy_scala_uses_same_handler() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("Hierarchy.scala");
    fs::write(
        &file_path,
        "package app\ntrait Runnable\nclass Base\nclass Child extends Base with Runnable\n",
    )
    .expect("write Scala hierarchy fixture");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let child_item = prepare_type_hierarchy(&mut server, &file_uri, 3, 6);
    assert_eq!(child_item["name"], "Child", "prepared child: {child_item}");

    let supertypes = type_hierarchy_relation(&mut server, "typeHierarchy/supertypes", child_item);
    let supertype_names: Vec<_> = supertypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(
        supertype_names,
        vec!["Base", "Runnable"],
        "supertypes: {supertypes:#?}"
    );

    let base_item = supertypes
        .iter()
        .find(|item| item["name"] == "Base")
        .cloned()
        .expect("Base supertype item");
    let subtypes = type_hierarchy_relation(&mut server, "typeHierarchy/subtypes", base_item);
    let subtype_names: Vec<_> = subtypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(subtype_names, vec!["Child"], "subtypes: {subtypes:#?}");
}

#[test]
fn bifrost_lsp_server_type_hierarchy_rust_uses_same_handler() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("lib.rs");
    let source = "trait Runnable {}\nstruct Worker;\nimpl Runnable for Worker {}\nfn use_it() { let typed: Worker = Worker; }\n";
    fs::write(&file_path, source).expect("write Rust hierarchy fixture");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let worker_item = prepare_type_hierarchy(&mut server, &file_uri, 1, 8);
    assert_eq!(
        worker_item["name"], "Worker",
        "prepared worker: {worker_item}"
    );

    let supertypes = type_hierarchy_relation(&mut server, "typeHierarchy/supertypes", worker_item);
    let supertype_names: Vec<_> = supertypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(
        supertype_names,
        vec!["Runnable"],
        "supertypes: {supertypes:#?}"
    );

    let runnable_item = supertypes[0].clone();
    let subtypes = type_hierarchy_relation(&mut server, "typeHierarchy/subtypes", runnable_item);
    let subtype_names: Vec<_> = subtypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(subtype_names, vec!["Worker"], "subtypes: {subtypes:#?}");

    let (line, character) = position_after(source, "typed: ");
    let runnable_ref = prepare_type_hierarchy(&mut server, &file_uri, line, character);
    assert_eq!(
        runnable_ref["name"], "Worker",
        "prepared Rust Worker reference: {runnable_ref}"
    );
}

#[test]
fn bifrost_lsp_server_go_type_hierarchy_returns_structural_interface_edges() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    fs::write(root.join("go.mod"), "module example.com/app\n\ngo 1.22\n").expect("write go.mod");
    let file_path = root.join("main.go");
    fs::write(
        &file_path,
        "package app\ntype Runner interface { Run() error }\ntype Worker struct{}\nfunc (Worker) Run() error { return nil }\n",
    )
    .expect("write Go fixture");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    let worker = prepare_type_hierarchy(&mut server, &file_uri, 2, 6);
    let supertypes = type_hierarchy_relation(&mut server, "typeHierarchy/supertypes", worker);
    assert!(
        supertypes.iter().any(|item| item["name"] == "Runner"),
        "expected Runner supertype, got {supertypes:#?}"
    );

    let runner = prepare_type_hierarchy(&mut server, &file_uri, 1, 6);
    let subtypes = type_hierarchy_relation(&mut server, "typeHierarchy/subtypes", runner);
    assert!(
        subtypes.iter().any(|item| item["name"] == "Worker"),
        "expected Worker subtype, got {subtypes:#?}"
    );
}

#[test]
fn bifrost_lsp_server_ruby_type_hierarchy_and_implementation_filter_value_contexts() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("hierarchy.rb");
    let source = "class Base\nend\n\nclass Child < Base\nend\n\nclass Service\n  def build\n    local = Child.new\n    result = local\n  end\nend\n";
    fs::write(&file_path, source).expect("write Ruby hierarchy-context fixture");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);

    let (line, character) = position_after(source, "class C");
    let child_item = prepare_type_hierarchy(&mut server, &file_uri, line, character);
    assert_eq!(
        child_item["name"], "Child",
        "prepared Ruby Child declaration: {child_item}"
    );
    let supertypes = type_hierarchy_relation(&mut server, "typeHierarchy/supertypes", child_item);
    assert!(
        supertypes.iter().any(|item| item["name"] == "Base"),
        "expected Ruby Base supertype, got {supertypes:#?}"
    );

    let (line, character) = position_after(source, "class B");
    let response = implementation_response(&mut server, &file_uri, line, character);
    let locations = response["result"].as_array().unwrap_or_else(|| {
        panic!("expected Ruby implementation from Base declaration, got {response}")
    });
    assert!(
        locations
            .iter()
            .any(|location| location["range"]["start"]["line"] == 3),
        "expected Ruby Child implementation from Base declaration, got {response}"
    );

    let null_cases = [
        ("method name", "def b"),
        ("local declaration", "local ="),
        ("call receiver", "Child.n"),
        ("local reference", "result = loc"),
    ];
    for (label, needle) in null_cases {
        let (line, character) = position_after(source, needle);
        let result = prepare_hierarchy_result(
            &mut server,
            "textDocument/prepareTypeHierarchy",
            &file_uri,
            (line, character),
        );
        assert!(
            result.is_null(),
            "Ruby {label} must not prepare type hierarchy: {result}"
        );

        let response = implementation_response(&mut server, &file_uri, line, character);
        assert!(
            response["result"].is_null(),
            "Ruby {label} must not resolve implementations, got {response}"
        );
    }
}

#[test]
fn bifrost_lsp_server_type_hierarchy_filters_java_csharp_scala_value_contexts() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let fixtures = write_jvm_type_context_fixtures(&root, "HierarchyContexts");

    let mut server = LspServer::start(&root);

    let java_uri = uri_for(&fixtures.java_path);
    let (line, character) = position_after(fixtures.java_source, "class S");
    let service = prepare_type_hierarchy(&mut server, &java_uri, line, character);
    assert_eq!(
        service["name"], "Service",
        "prepared Java Service: {service}"
    );
    let (line, character) = position_after(fixtures.java_source, "    W");
    let widget_result = prepare_hierarchy_result(
        &mut server,
        "textDocument/prepareTypeHierarchy",
        &java_uri,
        (line, character),
    );
    let widget = widget_result
        .as_array()
        .unwrap_or_else(|| panic!("expected Java return type to prepare, got {widget_result}"));
    assert_eq!(
        widget.len(),
        1,
        "expected one Java Widget item: {widget:#?}"
    );
    let widget = widget[0].clone();
    assert_eq!(widget["name"], "Widget", "prepared Java Widget: {widget}");
    assert_prepare_type_hierarchy_null_cases(
        &mut server,
        &java_uri,
        fixtures.java_source,
        &[
            ("    Widget b", "Java method names"),
            ("        Widget l", "Java locals"),
        ],
    );

    let csharp_uri = uri_for(&fixtures.csharp_path);
    assert_prepare_type_hierarchy_null_cases(
        &mut server,
        &csharp_uri,
        fixtures.csharp_source,
        &[(" Widget B", "C# method names"), (" Widget l", "C# locals")],
    );

    let scala_uri = uri_for(&fixtures.scala_path);
    let (line, character) = position_after(fixtures.scala_source, "class S");
    let service = prepare_type_hierarchy(&mut server, &scala_uri, line, character);
    assert_eq!(
        service["name"], "Service",
        "prepared Scala Service: {service}"
    );
    let (line, character) = position_after(fixtures.scala_source, ": W");
    let widget_result = prepare_hierarchy_result(
        &mut server,
        "textDocument/prepareTypeHierarchy",
        &scala_uri,
        (line, character),
    );
    let widget = widget_result
        .as_array()
        .unwrap_or_else(|| panic!("expected Scala return type to prepare, got {widget_result}"));
    assert_eq!(
        widget.len(),
        1,
        "expected one Scala Widget item: {widget:#?}"
    );
    let widget = widget[0].clone();
    assert_eq!(widget["name"], "Widget", "prepared Scala Widget: {widget}");
    assert_prepare_type_hierarchy_null_cases(
        &mut server,
        &scala_uri,
        fixtures.scala_source,
        &[("def b", "Scala function names"), ("val l", "Scala locals")],
    );
}

fn assert_implementation_null_cases(
    server: &mut LspServer,
    uri: &str,
    source: &str,
    cases: &[(&str, &str)],
) {
    for (needle, label) in cases {
        let (line, character) = position_after(source, needle);
        let response = implementation_response(server, uri, line, character);
        assert!(
            response["result"].is_null(),
            "{label} must not resolve implementations, got {response}"
        );
    }
}

fn assert_prepare_type_hierarchy_null_cases(
    server: &mut LspServer,
    uri: &str,
    source: &str,
    cases: &[(&str, &str)],
) {
    for (needle, label) in cases {
        let (line, character) = position_after(source, needle);
        let result = prepare_hierarchy_result(
            server,
            "textDocument/prepareTypeHierarchy",
            uri,
            (line, character),
        );
        assert!(
            result.is_null(),
            "{label} must not prepare type hierarchy: {result}"
        );
    }
}

fn prepare_type_hierarchy(server: &mut LspServer, uri: &str, line: u64, character: u64) -> Value {
    server.prepare_hierarchy("textDocument/prepareTypeHierarchy", uri, (line, character))
}

fn type_hierarchy_relation(server: &mut LspServer, method: &str, item: Value) -> Vec<Value> {
    server.hierarchy_relation(method, item)
}

fn prepare_call_hierarchy(server: &mut LspServer, uri: &str, line: u64, character: u64) -> Value {
    server.prepare_hierarchy("textDocument/prepareCallHierarchy", uri, (line, character))
}

fn prepare_call_hierarchy_result(
    server: &mut LspServer,
    uri: &str,
    line: u64,
    character: u64,
) -> Value {
    prepare_hierarchy_result(
        server,
        "textDocument/prepareCallHierarchy",
        uri,
        (line, character),
    )
}

fn call_hierarchy_relation(server: &mut LspServer, method: &str, item: Value) -> Vec<Value> {
    server.hierarchy_relation(method, item)
}

fn prepare_hierarchy_result(
    server: &mut LspServer,
    method: &str,
    uri: &str,
    position: (u64, u64),
) -> Value {
    server.prepare_hierarchy_result(method, uri, position)
}

fn signature_help(server: &mut LspServer, uri: &str, line: u64, character: u64) -> Value {
    server.signature_help(uri, line, character)
}

fn assert_signature_parameter_offsets(result: &Value, signature_index: usize, expected: &[&str]) {
    let signature = &result["signatures"][signature_index];
    let label = signature["label"]
        .as_str()
        .unwrap_or_else(|| panic!("expected signature label, got {result}"));
    let parameters = signature["parameters"]
        .as_array()
        .unwrap_or_else(|| panic!("expected signature parameters, got {result}"));
    assert_eq!(
        parameters.len(),
        expected.len(),
        "unexpected parameter count in {result}"
    );

    for (parameter, expected_label) in parameters.iter().zip(expected) {
        let offsets = parameter["label"]
            .as_array()
            .unwrap_or_else(|| panic!("expected label offsets, got {result}"));
        assert_eq!(offsets.len(), 2, "expected two label offsets in {result}");
        let start = offsets[0]
            .as_u64()
            .unwrap_or_else(|| panic!("expected start offset, got {result}"))
            as usize;
        let end = offsets[1]
            .as_u64()
            .unwrap_or_else(|| panic!("expected end offset, got {result}"))
            as usize;
        assert_eq!(
            &label[start..end],
            *expected_label,
            "unexpected parameter label range in {result}"
        );
    }
}

fn position_after(source: &str, needle: &str) -> (u64, u64) {
    let byte_offset = source.find(needle).expect("needle exists") + needle.len();
    position_at(source, byte_offset)
}

fn position_at(source: &str, byte_offset: usize) -> (u64, u64) {
    let before = &source[..byte_offset];
    let line = before.bytes().filter(|byte| *byte == b'\n').count() as u64;
    let line_start = before.rfind('\n').map(|index| index + 1).unwrap_or(0);
    let character = source[line_start..byte_offset].chars().count() as u64;
    (line, character)
}

fn assert_call_range(ranges: &Value, line: u64, start_character: u64, end_character: u64) {
    let ranges = ranges
        .as_array()
        .unwrap_or_else(|| panic!("expected call range array, got {ranges}"));
    assert!(
        ranges.iter().any(|range| {
            range["start"]["line"] == line
                && range["start"]["character"] == start_character
                && range["end"]["line"] == line
                && range["end"]["character"] == end_character
        }),
        "expected call range {line}:{start_character}-{end_character}, got {ranges:#?}"
    );
}

#[cfg(unix)]
fn write_stub_command(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;

    fs::write(path, body).expect("write stub command");
    let mut permissions = fs::metadata(path).expect("stub metadata").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("chmod stub command");
}

#[cfg(unix)]
fn formatting_response(server: &mut LspServer, file_uri: &str) -> Value {
    server.formatting_response(file_uri)
}

#[test]
fn bifrost_lsp_server_formats_rql_and_rune_documents_at_120_columns() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let rql_path = root.join("query.rql");
    let rune_path = root.join("preview.rune");
    fs::write(&rql_path, "").expect("write RQL file");
    fs::write(&rune_path, "").expect("write Rune file");
    let mut server = LspServer::start(&root);

    let long_name = "a".repeat(90);
    let long_form = format!(
        "(call :name \"{long_name}\" :callee (name \"eval\") :args [(capture \"payload\")])"
    );
    let formatted_form = format!(
        "(call\n  :name \"{long_name}\"\n  :callee (name \"eval\")\n  :args [(capture \"payload\")]\n)"
    );
    let rune_source =
        format!("; Rune IR\n\n{long_form}\n\n; Starter RQL\n(function :name \"demo\")\n");
    let formatted_rune =
        format!("; Rune IR\n\n{formatted_form}\n\n; Starter RQL\n(function :name \"demo\")\n");

    for (path, language_id, source, expected) in [
        (
            &rql_path,
            "bifrost-rql",
            long_form.as_str(),
            formatted_form.as_str(),
        ),
        (
            &rune_path,
            "bifrost-rune-ir",
            rune_source.as_str(),
            formatted_rune.as_str(),
        ),
    ] {
        let file_uri = uri_for(path);
        server.notify(
            "textDocument/didOpen",
            json!({
                "textDocument": {
                    "uri": file_uri,
                    "languageId": language_id,
                    "version": 1,
                    "text": source,
                }
            }),
        );
        let response = server.request(
            "textDocument/formatting",
            json!({
                "textDocument": {"uri": file_uri},
                "options": {"tabSize": 4, "insertSpaces": true}
            }),
        );
        let edits = response["result"]
            .as_array()
            .unwrap_or_else(|| panic!("expected formatting edits, got {response}"));
        assert_eq!(edits.len(), 1, "{response}");
        assert_eq!(edits[0]["newText"], expected, "{response}");
    }

    let rql_uri = uri_for(&rql_path);
    server.notify(
        "textDocument/didChange",
        json!({
            "textDocument": {"uri": rql_uri, "version": 2},
            "contentChanges": [{"text": "(call :name \"unfinished\""}]
        }),
    );
    let response = server.request(
        "textDocument/formatting",
        json!({
            "textDocument": {"uri": rql_uri},
            "options": {"tabSize": 4, "insertSpaces": true}
        }),
    );
    assert_eq!(response["result"], json!([]), "{response}");
}

#[cfg(unix)]
#[test]
fn bifrost_lsp_server_formatting_uses_did_open_overlay() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("lib.rs");
    let stub_path = root.join("upper-format");
    fs::write(&file_path, "fn disk() {}\n").expect("write disk file");
    write_stub_command(&stub_path, "#!/bin/sh\ntr '[:lower:]' '[:upper:]'\n");

    let mut server = LspServer::start_with_params(
        &root,
        json!({
            "processId": null,
            "rootUri": uri_for(&root),
            "capabilities": {},
            "initializationOptions": {
                "formatterCommands": [{
                    "include": ["*.rs"],
                    "language": "rust",
                    "command": stub_path.display().to_string()
                }]
            }
        }),
    );
    let file_uri = uri_for(&file_path);
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didOpen",
        "params": {
            "textDocument": {
                "uri": file_uri,
                "languageId": "rust",
                "version": 1,
                "text": "fn overlay() {}\n"
            }
        }
    }));
    let _ = server.read_notification("textDocument/publishDiagnostics");

    let response = formatting_response(&mut server, &file_uri);
    let edits = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected formatting edits, got {response}"));
    assert_eq!(
        edits.len(),
        1,
        "expected one full-document edit: {response}"
    );
    assert_eq!(edits[0]["newText"], "FN OVERLAY() {}\n");
    assert_eq!(edits[0]["range"]["start"]["line"], 0);
    assert_eq!(edits[0]["range"]["start"]["character"], 0);
    assert_eq!(edits[0]["range"]["end"]["line"], 1);
    assert_eq!(edits[0]["range"]["end"]["character"], 0);
}

#[cfg(unix)]
#[test]
fn bifrost_lsp_server_formatting_suppresses_stale_snapshot_edits() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("lib.rs");
    let stub_path = root.join("slow-upper-format");
    fs::write(&file_path, "fn disk() {}\n").expect("write disk file");
    write_stub_command(
        &stub_path,
        "#!/bin/sh\nsleep 1\ntr '[:lower:]' '[:upper:]'\n",
    );

    let mut server = LspServer::start_with_params(
        &root,
        json!({
            "processId": null,
            "rootUri": uri_for(&root),
            "capabilities": {},
            "initializationOptions": {
                "formatterCommands": [{
                    "include": ["*.rs"],
                    "language": "rust",
                    "command": stub_path.display().to_string()
                }]
            }
        }),
    );
    let file_uri = uri_for(&file_path);
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didOpen",
        "params": {
            "textDocument": {
                "uri": file_uri,
                "languageId": "rust",
                "version": 1,
                "text": "fn before() {}\n"
            }
        }
    }));
    let _ = server.read_notification("textDocument/publishDiagnostics");
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "textDocument/formatting",
        "params": {
            "textDocument": {"uri": file_uri},
            "options": {"tabSize": 4, "insertSpaces": true}
        }
    }));
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didChange",
        "params": {
            "textDocument": {"uri": file_uri, "version": 7},
            "contentChanges": [{"text": "fn after() {}\n"}]
        }
    }));

    let response = server.read_response_for_id(10);
    let edits = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected formatting edits, got {response}"));
    assert!(
        edits.is_empty(),
        "expected stale formatting response to be suppressed, got {response}"
    );
}

#[cfg(unix)]
#[test]
fn bifrost_lsp_server_formatting_cancel_stops_active_formatter() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("lib.rs");
    let stub_path = root.join("slow-format");
    fs::write(&file_path, "fn main() {}\n").expect("write disk file");
    write_stub_command(&stub_path, "#!/bin/sh\nsleep 10\ncat\n");

    let mut server = LspServer::start_with_params(
        &root,
        json!({
            "processId": null,
            "rootUri": uri_for(&root),
            "capabilities": {},
            "initializationOptions": {
                "formatterCommands": [{
                    "include": ["*.rs"],
                    "language": "rust",
                    "command": stub_path.display().to_string()
                }]
            }
        }),
    );
    let file_uri = uri_for(&file_path);
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "textDocument/formatting",
        "params": {
            "textDocument": {"uri": file_uri},
            "options": {"tabSize": 4, "insertSpaces": true}
        }
    }));
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "$/cancelRequest",
        "params": {"id": 10}
    }));

    let response = server.read_response_for_id(10);
    assert_eq!(response["error"]["code"], -32800, "{response}");
    let message = response["error"]["message"].as_str().unwrap_or_default();
    assert!(message.contains("cancelled"), "{response}");
}

#[cfg(unix)]
#[test]
fn bifrost_lsp_server_formatting_shutdown_cancels_active_formatter() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("lib.rs");
    let stub_path = root.join("slow-format");
    fs::write(&file_path, "fn main() {}\n").expect("write disk file");
    write_stub_command(&stub_path, "#!/bin/sh\nsleep 10\ncat\n");

    let mut server = LspServer::start_with_params(
        &root,
        json!({
            "processId": null,
            "rootUri": uri_for(&root),
            "capabilities": {},
            "initializationOptions": {
                "formatterCommands": [{
                    "include": ["*.rs"],
                    "language": "rust",
                    "command": stub_path.display().to_string()
                }]
            }
        }),
    );
    let file_uri = uri_for(&file_path);
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "textDocument/formatting",
        "params": {
            "textDocument": {"uri": file_uri},
            "options": {"tabSize": 4, "insertSpaces": true}
        }
    }));

    let started = std::time::Instant::now();
    server.notify_value(json!({"jsonrpc": "2.0", "id": 99, "method": "shutdown"}));
    let _ = server.read_response_for_id(99);
    server.exit();
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "shutdown waited for slow formatter instead of cancelling it"
    );
}

#[cfg(unix)]
#[test]
fn bifrost_lsp_server_formatting_returns_empty_edits_for_noop() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("lib.rs");
    let stub_path = root.join("cat-format");
    fs::write(&file_path, "fn unchanged() {}\n").expect("write disk file");
    write_stub_command(&stub_path, "#!/bin/sh\ncat\n");

    let mut server = LspServer::start_with_params(
        &root,
        json!({
            "processId": null,
            "rootUri": uri_for(&root),
            "capabilities": {},
            "initializationOptions": {
                "formatterCommands": [{
                    "include": ["*.rs"],
                    "command": stub_path.display().to_string()
                }]
            }
        }),
    );
    let file_uri = uri_for(&file_path);
    let response = formatting_response(&mut server, &file_uri);
    let edits = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected formatting edits, got {response}"));
    assert!(
        edits.is_empty(),
        "expected no-op formatting edits: {response}"
    );
}

#[cfg(unix)]
#[test]
fn bifrost_lsp_server_formatting_respects_configured_cwd() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let package = root.join("pkg");
    fs::create_dir_all(&package).expect("create package");
    let file_path = package.join("lib.rs");
    let stub_path = root.join("pwd-format");
    fs::write(&file_path, "fn main() {}\n").expect("write disk file");
    write_stub_command(&stub_path, "#!/bin/sh\ncat >/dev/null\npwd\n");

    let mut server = LspServer::start_with_params(
        &root,
        json!({
            "processId": null,
            "rootUri": uri_for(&root),
            "capabilities": {},
            "initializationOptions": {
                "formatterCommands": [{
                    "include": ["pkg/*.rs"],
                    "command": stub_path.display().to_string(),
                    "cwd": "pkg"
                }]
            }
        }),
    );
    let file_uri = uri_for(&file_path);
    let response = formatting_response(&mut server, &file_uri);
    let edits = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected formatting edits, got {response}"));
    assert_eq!(edits[0]["newText"], format!("{}\n", package.display()));
}

#[cfg(unix)]
#[test]
fn bifrost_lsp_server_formatting_reports_formatter_failure() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("lib.rs");
    let stub_path = root.join("fail-format");
    fs::write(&file_path, "fn main() {}\n").expect("write disk file");
    write_stub_command(
        &stub_path,
        "#!/bin/sh\necho formatter exploded >&2\nexit 7\n",
    );

    let mut server = LspServer::start_with_params(
        &root,
        json!({
            "processId": null,
            "rootUri": uri_for(&root),
            "capabilities": {},
            "initializationOptions": {
                "formatterCommands": [{
                    "include": ["*.rs"],
                    "command": stub_path.display().to_string()
                }]
            }
        }),
    );
    let file_uri = uri_for(&file_path);
    let response = formatting_response(&mut server, &file_uri);
    let error = response["error"]["message"].as_str().unwrap_or_default();
    assert!(error.contains("formatter exploded"), "{response}");
    assert!(error.contains("exited with status"), "{response}");
}

#[test]
fn bifrost_lsp_server_did_open_overlay_drives_hover_identifier() {
    // Disk content vs. opened buffer differ in the identifier at (line 0, char 5).
    // Verifies that did{Open,Change,Close} drive both the analyzer reparse and
    // the request-time identifier extraction.
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("lib.rs");
    fs::write(&file_path, "fn original() {}\n").expect("write disk");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);

    // didOpen with overlay content — different function name than disk.
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didOpen",
        "params": {
            "textDocument": {
                "uri": file_uri,
                "languageId": "rust",
                "version": 1,
                "text": "fn overlay_only() {}\n"
            }
        }
    }));
    // didOpen emits a publishDiagnostics — drain it before the request.
    let _ = server.read_notification("textDocument/publishDiagnostics");

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "textDocument/hover",
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 0, "character": 5}
        }
    }));
    let hover_open = server.read_response_for_id(10);
    let hover_text_open = hover_open["result"]["contents"]["value"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        hover_text_open.contains("overlay_only"),
        "hover should reflect didOpen overlay, got {hover_text_open}"
    );
    assert!(
        !hover_text_open.contains("original"),
        "hover should NOT show on-disk identifier while overlay is active, got {hover_text_open}"
    );

    // didChange replaces the buffer.
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didChange",
        "params": {
            "textDocument": {"uri": file_uri, "version": 2},
            "contentChanges": [{"text": "fn changed() {}\n"}]
        }
    }));
    let _ = server.read_notification("textDocument/publishDiagnostics");

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "textDocument/hover",
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 0, "character": 5}
        }
    }));
    let hover_changed = server.read_response_for_id(11);
    let hover_text_changed = hover_changed["result"]["contents"]["value"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        hover_text_changed.contains("changed"),
        "hover should reflect didChange overlay, got {hover_text_changed}"
    );
    assert!(
        !hover_text_changed.contains("overlay_only"),
        "hover should NOT show pre-change overlay after didChange, got {hover_text_changed}"
    );

    // didClose drops the overlay; disk content reasserts.
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didClose",
        "params": {"textDocument": {"uri": file_uri}}
    }));
    let _ = server.read_notification("textDocument/publishDiagnostics");

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 12,
        "method": "textDocument/hover",
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 0, "character": 5}
        }
    }));
    let hover_closed = server.read_response_for_id(12);
    let hover_text_closed = hover_closed["result"]["contents"]["value"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        hover_text_closed.contains("original"),
        "after didClose, hover should reflect disk content, got {hover_text_closed}"
    );

    server.notify_value(json!({"jsonrpc": "2.0", "id": 99, "method": "shutdown"}));
    let _ = server.read_response_for_id(99);
    server.exit();
}

#[test]
fn bifrost_lsp_server_did_change_completion_finds_overlay_only_symbol() {
    // A Rust file on disk has nothing matching `mark`. didOpen + didChange
    // introduce `mark_overlay_42`. Completion at prefix `mark` must surface it
    // — proving the analyzer reparsed against overlay content AND that
    // completion's mtime cache was bypassed for the overlaid file.
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("lib.rs");
    fs::write(&file_path, "fn placeholder() {}\n").expect("write disk");

    let mut server =
        LspServer::start_with_params(&root, completion_initialize_params(uri_for(&root)));
    let file_uri = uri_for(&file_path);

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didOpen",
        "params": {
            "textDocument": {
                "uri": file_uri,
                "languageId": "rust",
                "version": 1,
                "text": "fn placeholder() {}\n"
            }
        }
    }));
    let _ = server.read_notification("textDocument/publishDiagnostics");

    // Two ordered incremental changes rename the declaration, then append a
    // caller against the intermediate buffer. Completion must observe both.
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didChange",
        "params": {
            "textDocument": {"uri": file_uri, "version": 2},
            "contentChanges": [
                {
                    "range": {
                        "start": {"line": 0, "character": 3},
                        "end": {"line": 0, "character": 14}
                    },
                    "text": "mark_overlay_42"
                },
                {
                    "range": {
                        "start": {"line": 1, "character": 0},
                        "end": {"line": 1, "character": 0}
                    },
                    "text": "fn caller() {\n    mark\n}\n"
                }
            ]
        }
    }));
    let _ = server.read_notification("textDocument/publishDiagnostics");

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 20,
        "method": "textDocument/completion",
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 2, "character": 8}
        }
    }));
    let completion = server.read_response_for_id(20);
    let items = completion["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("expected completion items array, got {completion}"));
    let labels: Vec<String> = items
        .iter()
        .filter_map(|item| item["label"].as_str().map(str::to_string))
        .collect();
    assert!(
        labels.iter().any(|label| label == "mark_overlay_42"),
        "expected `mark_overlay_42` in completion results, got {labels:?}"
    );

    server.notify_value(json!({"jsonrpc": "2.0", "id": 99, "method": "shutdown"}));
    let _ = server.read_response_for_id(99);
    server.exit();
}

#[test]
fn bifrost_lsp_server_did_close_reverts_completion_to_disk() {
    // After didOpen + didClose, the overlay symbol vanishes from completion
    // results. Guards against state leakage of the overlay across close.
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("lib.rs");
    fs::write(&file_path, "fn disk_placeholder() {}\n").expect("write disk");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didOpen",
        "params": {
            "textDocument": {
                "uri": file_uri,
                "languageId": "rust",
                "version": 1,
                "text": "fn unique_overlay_token() {}\nfn caller() {\n    uniqu\n}\n"
            }
        }
    }));
    let _ = server.read_notification("textDocument/publishDiagnostics");

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didClose",
        "params": {"textDocument": {"uri": file_uri}}
    }));
    let _ = server.read_notification("textDocument/publishDiagnostics");

    // Disk content has no `unique` symbol; completion (across the workspace)
    // for prefix `unique` must return nothing matching the overlay symbol.
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 30,
        "method": "workspace/symbol",
        "params": {"query": "unique_overlay_token"}
    }));
    let symbols = server.read_response_for_id(30);
    let names: Vec<String> = symbols["result"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s["name"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        !names.iter().any(|n| n == "unique_overlay_token"),
        "overlay symbol should be gone after didClose, got {names:?}"
    );

    server.notify_value(json!({"jsonrpc": "2.0", "id": 99, "method": "shutdown"}));
    let _ = server.read_response_for_id(99);
    server.exit();
}

#[test]
fn bifrost_lsp_server_incremental_utf16_crlf_edits_refresh_hover_and_diagnostics() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("lib.rs");
    fs::write(&file_path, "fn disk() {}\r\n").expect("write disk");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didOpen",
        "params": {
            "textDocument": {
                "uri": file_uri,
                "languageId": "rust",
                "version": 1,
                "text": "/*😀*/ fn before() {}\r\n"
            }
        }
    }));
    let _ = server.read_notification("textDocument/publishDiagnostics");

    // The emoji occupies two UTF-16 code units. Rename the valid function,
    // then append malformed Rust at the CRLF-created trailing line.
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didChange",
        "params": {
            "textDocument": {"uri": file_uri, "version": 2},
            "contentChanges": [
                {
                    "range": {
                        "start": {"line": 0, "character": 10},
                        "end": {"line": 0, "character": 16}
                    },
                    "text": "after"
                },
                {
                    "range": {
                        "start": {"line": 1, "character": 0},
                        "end": {"line": 1, "character": 0}
                    },
                    "text": "fn broken( {\r\n"
                }
            ]
        }
    }));
    let broken = server.read_notification("textDocument/publishDiagnostics");
    assert!(
        !broken["params"]["diagnostics"]
            .as_array()
            .unwrap_or_else(|| panic!("expected diagnostics array, got {broken}"))
            .is_empty(),
        "incremental malformed text should publish diagnostics: {broken}"
    );

    // Remove the malformed CRLF line and verify diagnostics clear.
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didChange",
        "params": {
            "textDocument": {"uri": file_uri, "version": 3},
            "contentChanges": [{
                "range": {
                    "start": {"line": 1, "character": 0},
                    "end": {"line": 2, "character": 0}
                },
                "text": ""
            }]
        }
    }));
    let cleared = server.read_notification("textDocument/publishDiagnostics");
    assert!(
        cleared["params"]["diagnostics"]
            .as_array()
            .unwrap_or_else(|| panic!("expected diagnostics array, got {cleared}"))
            .is_empty(),
        "removing malformed incremental text should clear diagnostics: {cleared}"
    );

    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 35,
        "method": "textDocument/hover",
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 0, "character": 11}
        }
    }));
    let hover = server.read_response_for_id(35);
    let hover_text = hover["result"]["contents"]["value"]
        .as_str()
        .unwrap_or_default();
    assert!(
        hover_text.contains("after"),
        "hover should reflect the UTF-16 incremental rename: {hover}"
    );

    server.notify_value(json!({"jsonrpc": "2.0", "id": 99, "method": "shutdown"}));
    let _ = server.read_response_for_id(99);
    server.exit();
}

#[test]
fn bifrost_lsp_server_rejected_didchanges_preserve_overlay() {
    // Rejected notifications must not update the overlay, reparse, or publish
    // diagnostics. Stderr carries a bounded, throttled reason that is not
    // captured here because child stderr timing is nondeterministic.
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("lib.rs");
    fs::write(&file_path, "fn original() {}\n").expect("write disk");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);

    // didOpen establishes an overlay and produces one publishDiagnostics.
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didOpen",
        "params": {
            "textDocument": {
                "uri": file_uri,
                "languageId": "rust",
                "version": 3,
                "text": "fn original() {}\n"
            }
        }
    }));
    let _ = server.read_notification("textDocument/publishDiagnostics");

    // Equal versions are stale even when their range would otherwise apply.
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didChange",
        "params": {
            "textDocument": {"uri": file_uri, "version": 3},
            "contentChanges": [{
                "range": {
                    "start": {"line": 0, "character": 3},
                    "end": {"line": 0, "character": 11}
                },
                "text": "stale"
            }]
        }
    }));

    // The server should drop the notification with no publishDiagnostics.
    // We can't assert "no message" without a timeout, but we can prove the
    // next message off the wire is the hover response (not a diagnostics
    // notification interleaved before it), since LSP messages are processed
    // serially.
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 40,
        "method": "textDocument/hover",
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 0, "character": 5}
        }
    }));

    // Read the very next inbound message. If the rejected didChange had
    // emitted publishDiagnostics, the notification would arrive first.
    let next = server.read_message();
    assert_eq!(
        next["id"].as_u64(),
        Some(40),
        "expected hover response (id 40) as the next message; \
         rejected didChange must not emit publishDiagnostics: {next}"
    );

    // Overlay must still reflect the pre-rejection state.
    let hover_text = next["result"]["contents"]["value"]
        .as_str()
        .unwrap_or_default();
    assert!(
        hover_text.contains("original"),
        "hover should still see the didOpen overlay after a stale change, got {hover_text}"
    );

    // An empty change array advances only the protocol version. Reusing that
    // version with an otherwise valid edit is stale and must remain a no-op.
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didChange",
        "params": {
            "textDocument": {"uri": file_uri, "version": 4},
            "contentChanges": []
        }
    }));
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didChange",
        "params": {
            "textDocument": {"uri": file_uri, "version": 4},
            "contentChanges": [{
                "range": {
                    "start": {"line": 0, "character": 3},
                    "end": {"line": 0, "character": 11}
                },
                "text": "same_version"
            }]
        }
    }));
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 41,
        "method": "textDocument/hover",
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 0, "character": 5}
        }
    }));
    let next = server.read_message();
    assert_eq!(
        next["id"].as_u64(),
        Some(41),
        "empty and stale didChange notifications must not publish diagnostics: {next}"
    );
    let hover_text = next["result"]["contents"]["value"]
        .as_str()
        .unwrap_or_default();
    assert!(
        hover_text.contains("original"),
        "empty changes must not alter content and must make same-version edits stale: {next}"
    );

    // A newer version with a nonexistent line is also rejected, and because
    // the empty notification advanced state this is validated against v4.
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didChange",
        "params": {
            "textDocument": {"uri": file_uri, "version": 5},
            "contentChanges": [{
                "range": {
                    "start": {"line": 99, "character": 0},
                    "end": {"line": 99, "character": 0}
                },
                "text": "invalid"
            }]
        }
    }));
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 42,
        "method": "textDocument/hover",
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 0, "character": 5}
        }
    }));
    let next = server.read_message();
    assert_eq!(
        next["id"].as_u64(),
        Some(42),
        "out-of-range didChange must not publish diagnostics: {next}"
    );
    let hover_text = next["result"]["contents"]["value"]
        .as_str()
        .unwrap_or_default();
    assert!(
        hover_text.contains("original"),
        "hover should still see the didOpen overlay after an invalid range: {next}"
    );

    server.notify_value(json!({"jsonrpc": "2.0", "id": 99, "method": "shutdown"}));
    let _ = server.read_response_for_id(99);
    server.exit();
}

#[test]
fn bifrost_lsp_server_didchange_for_unknown_document_is_ignored() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("lib.rs");
    fs::write(&file_path, "fn disk_original() {}\n").expect("write disk");

    let mut server = LspServer::start(&root);
    let file_uri = uri_for(&file_path);
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "method": "textDocument/didChange",
        "params": {
            "textDocument": {"uri": file_uri, "version": 1},
            "contentChanges": [{"text": "fn unknown_change() {}\n"}]
        }
    }));
    server.notify_value(json!({
        "jsonrpc": "2.0",
        "id": 45,
        "method": "textDocument/hover",
        "params": {
            "textDocument": {"uri": file_uri},
            "position": {"line": 0, "character": 5}
        }
    }));
    let next = server.read_message();
    assert_eq!(
        next["id"].as_u64(),
        Some(45),
        "unknown-document didChange must not publish diagnostics: {next}"
    );
    let hover_text = next["result"]["contents"]["value"]
        .as_str()
        .unwrap_or_default();
    assert!(
        hover_text.contains("disk_original"),
        "unknown-document didChange must not replace disk content: {next}"
    );

    server.notify_value(json!({"jsonrpc": "2.0", "id": 99, "method": "shutdown"}));
    let _ = server.read_response_for_id(99);
    server.exit();
}

fn type_definition_response(
    server: &mut LspServer,
    file_uri: &str,
    line: u64,
    character: u64,
) -> Value {
    server.type_definition_response(file_uri, line, character)
}

#[allow(clippy::too_many_arguments)]
fn references_response(
    server: &mut LspServer,
    file_uri: &str,
    line: u64,
    character: u64,
    include_declaration: bool,
) -> Value {
    server.references_response(file_uri, line, character, include_declaration)
}

#[derive(Clone, Copy)]
enum BroadEndpoint {
    Definition,
    Hover,
    References,
    DocumentHighlight,
}

impl BroadEndpoint {
    fn label(self) -> &'static str {
        match self {
            Self::Definition => "definition",
            Self::Hover => "hover",
            Self::References => "references",
            Self::DocumentHighlight => "documentHighlight",
        }
    }
}

fn invalid_context_targets() -> Vec<(&'static str, u64, u64)> {
    [
        (
            "string literal",
            position_after(INVALID_CONTEXTS_SOURCE, "\""),
        ),
        (
            "ambiguous type reference",
            position_after(INVALID_CONTEXTS_SOURCE, "        "),
        ),
        (
            "unresolved expression",
            position_after(INVALID_CONTEXTS_SOURCE, "int value = "),
        ),
        (
            "keyword",
            position_after(INVALID_CONTEXTS_SOURCE, "        if"),
        ),
    ]
    .into_iter()
    .map(|(label, (line, character))| (label, line, character))
    .collect()
}

fn collect_invalid_context_endpoint_responses(
    client: &mut LspServer,
    file_uri: &str,
    endpoint: BroadEndpoint,
) -> Vec<(&'static str, Value)> {
    invalid_context_targets()
        .into_iter()
        .map(|(label, line, character)| {
            let response = endpoint_response(client, file_uri, endpoint, line, character);
            (label, response)
        })
        .collect()
}

fn endpoint_response(
    client: &mut LspServer,
    file_uri: &str,
    endpoint: BroadEndpoint,
    line: u64,
    character: u64,
) -> Value {
    match endpoint {
        BroadEndpoint::Definition => client.text_document_position_response(
            "textDocument/definition",
            file_uri,
            line,
            character,
        ),
        BroadEndpoint::Hover => {
            client.text_document_position_response("textDocument/hover", file_uri, line, character)
        }
        BroadEndpoint::References => client.references_response(file_uri, line, character, true),
        BroadEndpoint::DocumentHighlight => client.text_document_position_response(
            "textDocument/documentHighlight",
            file_uri,
            line,
            character,
        ),
    }
}

fn assert_no_invalid_context_results(endpoint: BroadEndpoint, responses: &[(&'static str, Value)]) {
    for (label, response) in responses {
        let no_result = match endpoint {
            BroadEndpoint::Definition | BroadEndpoint::Hover => response["result"].is_null(),
            BroadEndpoint::References | BroadEndpoint::DocumentHighlight => {
                response["result"].is_null()
                    || response["result"]
                        .as_array()
                        .is_some_and(|items| items.is_empty())
            }
        };
        assert!(
            no_result,
            "{label} must not produce {} result, got {response}",
            endpoint.label()
        );
    }
}

fn implementation_response(
    server: &mut LspServer,
    file_uri: &str,
    line: u64,
    character: u64,
) -> Value {
    server.implementation_response(file_uri, line, character)
}
