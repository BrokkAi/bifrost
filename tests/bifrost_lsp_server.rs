use serde_json::{Value, json};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use tempfile::TempDir;

#[test]
fn bifrost_lsp_server_handles_initialize_and_shutdown() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&fixture_root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "processId": null,
                "rootUri": null,
                "capabilities": {}
            }
        }),
    );
    let initialize = read_message(&mut reader, &mut stderr);
    assert_eq!(initialize["id"], 1);
    assert!(
        initialize["result"]["capabilities"]["textDocumentSync"].is_object(),
        "textDocumentSync should be advertised: {initialize}"
    );

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 2, "method": "shutdown"}),
    );
    let shutdown = read_message(&mut reader, &mut stderr);
    assert_eq!(shutdown["id"], 2);
    assert!(shutdown["error"].is_null(), "unexpected error: {shutdown}");

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "exit"}),
    );

    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_returns_document_symbols_for_a_java() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&fixture_root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    let canonical_root = fixture_root.canonicalize().expect("canon fixture");
    let root_uri = format!("file://{}", canonical_root.display());
    let file_uri = format!("file://{}/A.java", canonical_root.display());

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "processId": null,
                "rootUri": root_uri,
                "capabilities": {}
            }
        }),
    );
    let init = read_message(&mut reader, &mut stderr);
    assert_eq!(init["id"], 1);
    assert_eq!(
        init["result"]["capabilities"]["documentSymbolProvider"], true,
        "documentSymbolProvider should be advertised: {init}"
    );
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/documentSymbol",
            "params": {"textDocument": {"uri": file_uri}}
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
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
    let child_names: Vec<&str> = children
        .iter()
        .filter_map(|c| c["name"].as_str())
        .collect();
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

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "exit"}),
    );
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_workspace_symbol_finds_method() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&fixture_root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    let canonical_root = fixture_root.canonicalize().expect("canon fixture");
    let root_uri = format!("file://{}", canonical_root.display());

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
        }),
    );
    let init = read_message(&mut reader, &mut stderr);
    assert_eq!(
        init["result"]["capabilities"]["workspaceSymbolProvider"], true,
        "workspaceSymbolProvider should be advertised: {init}"
    );
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "workspace/symbol",
            "params": {"query": "method2"}
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
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

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "exit"}),
    );
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_goto_definition_finds_class_a_from_b() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&fixture_root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    let canonical_root = fixture_root.canonicalize().expect("canon fixture");
    let root_uri = format!("file://{}", canonical_root.display());
    let b_uri = format!("file://{}/B.java", canonical_root.display());

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
        }),
    );
    let init = read_message(&mut reader, &mut stderr);
    assert_eq!(
        init["result"]["capabilities"]["definitionProvider"], true,
        "definitionProvider should be advertised: {init}"
    );
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    // Line 6 (0-based), char 8: cursor is on the `A` in `A a = new A();`.
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/definition",
            "params": {
                "textDocument": {"uri": b_uri},
                "position": {"line": 6, "character": 8}
            }
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
    let locations = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected location array, got {response}"));
    assert!(!locations.is_empty(), "no definitions found: {response}");
    let uri = locations[0]["uri"].as_str().expect("location uri");
    assert!(
        uri.ends_with("A.java"),
        "expected A.java URI, got {uri}"
    );

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "exit"}),
    );
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_hover_returns_signature_for_class_a() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&fixture_root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    let canonical_root = fixture_root.canonicalize().expect("canon fixture");
    let root_uri = format!("file://{}", canonical_root.display());
    let b_uri = format!("file://{}/B.java", canonical_root.display());

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
        }),
    );
    let init = read_message(&mut reader, &mut stderr);
    assert_eq!(
        init["result"]["capabilities"]["hoverProvider"], true,
        "hoverProvider should be advertised: {init}"
    );
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/hover",
            "params": {
                "textDocument": {"uri": b_uri},
                "position": {"line": 6, "character": 8}
            }
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
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

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "exit"}),
    );
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_references_finds_class_a_usages() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&fixture_root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    let canonical_root = fixture_root.canonicalize().expect("canon fixture");
    let root_uri = format!("file://{}", canonical_root.display());
    let a_uri = format!("file://{}/A.java", canonical_root.display());

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
        }),
    );
    let init = read_message(&mut reader, &mut stderr);
    assert_eq!(
        init["result"]["capabilities"]["referencesProvider"], true,
        "referencesProvider should be advertised: {init}"
    );
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    // A.java line 3, col 13: cursor on the `A` in `public class A {`.
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/references",
            "params": {
                "textDocument": {"uri": a_uri},
                "position": {"line": 2, "character": 13},
                "context": {"includeDeclaration": false}
            }
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
    let locations = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected array, got {response}"));
    let uris: Vec<&str> = locations
        .iter()
        .filter_map(|l| l["uri"].as_str())
        .collect();
    assert!(
        uris.iter().any(|u| u.ends_with("B.java")),
        "expected at least one reference in B.java, got: {uris:?}"
    );

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "exit"}),
    );
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
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

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&temp_root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    let root_uri = format!("file://{}", temp_root.display());
    let bad_uri = format!("file://{}/Bad.java", temp_root.display());

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
        }),
    );
    let init = read_message(&mut reader, &mut stderr);
    assert!(
        init["result"]["capabilities"]["diagnosticProvider"].is_object(),
        "diagnosticProvider should be advertised: {init}"
    );
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/diagnostic",
            "params": {"textDocument": {"uri": bad_uri}}
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
    let items = response["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("expected items array, got {response}"));
    assert!(
        !items.is_empty(),
        "expected at least one parse-error diagnostic for malformed Java: {response}"
    );
    assert_eq!(items[0]["severity"], 1, "severity should be Error");
    assert_eq!(items[0]["source"], "bifrost-tree-sitter");

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "exit"}),
    );
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
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

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&temp_root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    let root_uri = format!("file://{}", temp_root.display());
    let watch_uri = format!("file://{}/Watch.java", temp_root.display());

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"processId": null, "rootUri": root_uri, "capabilities": {}}
        }),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    // Confirm initial workspaceSymbol query finds `initial` and not `added`.
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "workspace/symbol",
            "params": {"query": "added"}
        }),
    );
    let before = read_message(&mut reader, &mut stderr);
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
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didSave",
            "params": {"textDocument": {"uri": watch_uri}}
        }),
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "workspace/symbol",
            "params": {"query": "added"}
        }),
    );
    let after = read_message(&mut reader, &mut stderr);
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

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 4, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "exit"}),
    );
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_unknown_request_returns_method_not_found() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&fixture_root)
        .arg("--server")
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"processId": null, "rootUri": null, "capabilities": {}}
        }),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/foldingRange",
            "params": {"textDocument": {"uri": "file:///nope"}}
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
    assert_eq!(response["id"], 2);
    assert_eq!(
        response["error"]["code"], -32601,
        "expected MethodNotFound (-32601): {response}"
    );

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "exit"}),
    );

    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

fn write_message(stdin: &mut impl Write, payload: Value) {
    let body = serde_json::to_string(&payload).expect("serialize");
    write!(stdin, "Content-Length: {}\r\n\r\n{}", body.len(), body).expect("write");
    stdin.flush().expect("flush");
}

fn read_message(reader: &mut impl BufRead, stderr: &mut impl Read) -> Value {
    let mut content_length: Option<usize> = None;
    loop {
        let mut header = String::new();
        let bytes = reader.read_line(&mut header).expect("read header");
        if bytes == 0 {
            let mut buf = String::new();
            let _ = stderr.read_to_string(&mut buf);
            panic!("server closed; stderr:\n{buf}");
        }
        let trimmed = header.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some(rest) = trimmed.strip_prefix("Content-Length: ") {
            content_length = Some(rest.parse().expect("Content-Length value"));
        }
    }
    let len = content_length.expect("missing Content-Length header");
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).expect("read body");
    serde_json::from_slice(&body).expect("valid json response")
}
