use brokk_bifrost::lsp::conversion::path_to_uri_string;
use serde_json::{Value, json};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use tempfile::TempDir;

/// Build an LSP-correct `file://` URI for `path`. On Windows, `Path::display()`
/// of a canonicalized path emits the extended-length form (`\\?\C:\…`) which
/// is NOT a valid URI; the crate's path_to_uri_string handles drive letters,
/// percent-encoding, and the leading-slash convention correctly. Tests use
/// this helper instead of hand-rolling `format!("file://{}", path.display())`.
fn uri_for(path: &Path) -> String {
    path_to_uri_string(path)
}

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
    assert_eq!(
        initialize["result"]["capabilities"]["typeHierarchyProvider"], true,
        "typeHierarchyProvider should be advertised: {initialize}"
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

    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));

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
    let root_uri = uri_for(&canonical_root);
    let file_uri = uri_for(&canonical_root.join("A.java"));

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

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
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
    let root_uri = uri_for(&canonical_root);

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
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_completion_finds_symbol_by_prefix() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    let completor_path = write_completor_fixture(&temp_root);

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

    let root_uri = uri_for(&temp_root);
    let file_uri = uri_for(&completor_path);

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
        init["result"]["capabilities"]["completionProvider"].is_object(),
        "completionProvider should be advertised: {init}"
    );
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    // Line 3 (0-based) is `        gree`. The cursor sits at the end of
    // `gree`, character 12 (8 spaces + 4 prefix bytes).
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/completion",
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": 3, "character": 12}
            }
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
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

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
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

    let root_uri = uri_for(&temp_root);
    let file_uri = uri_for(&flood_path);

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

    // The `caller()` body sits on the line right after the 501 method
    // declarations: lines 0..=501 are the class header + methods, line 502 is
    // `    void caller() {`, line 503 is `        matchme_`. The cursor goes
    // at the end of `matchme_` = char position 16 (8 spaces + 8 chars).
    let cursor_line = 503;
    let cursor_char = 16;
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/completion",
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": cursor_line, "character": cursor_char}
            }
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
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

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_completion_empty_prefix_returns_null() {
    let temp = TempDir::new().expect("temp dir");
    let temp_root = temp.path().canonicalize().expect("canon temp");
    let completor_path = write_completor_fixture(&temp_root);

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

    let root_uri = uri_for(&temp_root);
    let file_uri = uri_for(&completor_path);

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

    // Line 4 (0-based) is `    }` — character 0 sits on whitespace with no
    // preceding identifier bytes on the same line. The handler must return
    // null (no completions) rather than dumping the whole symbol index.
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/completion",
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": 4, "character": 0}
            }
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
    assert!(
        response["result"].is_null(),
        "empty prefix should produce a null result, got {response}"
    );

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
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
    let root_uri = uri_for(&canonical_root);
    let b_uri = uri_for(&canonical_root.join("B.java"));

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

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
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
    let root_uri = uri_for(&canonical_root);
    let b_uri = uri_for(&canonical_root.join("B.java"));

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
    // Hover range should cover the `A` identifier under the cursor: line 6,
    // chars 8-9. A bug in identifier_span_at_offset or position_to_byte_offset
    // would produce something else here.
    let range = &response["result"]["range"];
    assert_eq!(range["start"]["line"], 6, "hover range start line");
    assert_eq!(range["start"]["character"], 8, "hover range start char");
    assert_eq!(range["end"]["line"], 6, "hover range end line");
    assert_eq!(range["end"]["character"], 9, "hover range end char");

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
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
    let root_uri = uri_for(&canonical_root);
    let a_uri = uri_for(&canonical_root.join("A.java"));

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

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_document_highlight_filters_to_current_file() {
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
    let root_uri = uri_for(&canonical_root);
    let a_uri = uri_for(&canonical_root.join("A.java"));

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
        init["result"]["capabilities"]["documentHighlightProvider"], true,
        "documentHighlightProvider should be advertised: {init}"
    );
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );

    // A.java line 2 (0-based), col 13: cursor on the `A` in `public class A {`.
    // The same `A` is referenced from A.java's own body (line 26 `new A()`,
    // line 33 inner-class `new A()`) and from B.java. The handler must
    // return only the A.java hits.
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/documentHighlight",
            "params": {
                "textDocument": {"uri": a_uri},
                "position": {"line": 2, "character": 13}
            }
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
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

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
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

    let root_uri = uri_for(&temp_root);
    let doc_uri = uri_for(&temp_root.join("Documented.java"));

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

    // Line 4 (0-based) is `public class Documented {` — char 13 is the `D`.
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/hover",
            "params": {
                "textDocument": {"uri": doc_uri},
                "position": {"line": 4, "character": 13}
            }
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
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

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
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

    let root_uri = uri_for(&temp_root);
    let doc_uri = uri_for(&temp_root.join("documented.rs"));

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

    // Line 2 (0-based) is `pub fn answer() -> i32 { 42 }`; char 7 is the `a`
    // in `answer`.
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/hover",
            "params": {
                "textDocument": {"uri": doc_uri},
                "position": {"line": 2, "character": 7}
            }
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
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

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
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

    let root_uri = uri_for(&temp_root);
    let doc_uri = uri_for(&temp_root.join("attrs.rs"));

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

    // Line 3 (0-based) is `pub struct Holder { value: i32 }`; char 11 lands
    // on the `H` in `Holder`.
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/hover",
            "params": {
                "textDocument": {"uri": doc_uri},
                "position": {"line": 3, "character": 11}
            }
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
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

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
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

    let root_uri = uri_for(&temp_root);
    let bad_uri = uri_for(&temp_root.join("Bad.java"));

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
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
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

    let root_uri = uri_for(&temp_root);
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

    let cases: &[(&str, &str)] = &[
        ("clean", "Clean.java"),
        ("text", "notes.txt"),
        ("binary", "Binary.java"),
    ];
    for (idx, (label, name)) in cases.iter().enumerate() {
        let id = (idx as u64) + 2;
        let uri = uri_for(&temp_root.join(name));
        write_message(
            &mut stdin,
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "textDocument/diagnostic",
                "params": {"textDocument": {"uri": uri}}
            }),
        );
        let response = read_message(&mut reader, &mut stderr);
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

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 99, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
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

    let root_uri = uri_for(&temp_root);
    let watch_uri = uri_for(&temp_root.join("Watch.java"));

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
    // didSave now emits a publishDiagnostics notification before the
    // workspace/symbol response — skip past it.
    let after = read_response_for_id(&mut reader, &mut stderr, 3);
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
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_hover_uses_python_language_tag_for_py_file() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-py");

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
    let root_uri = uri_for(&canonical_root);
    let py_uri = uri_for(&canonical_root.join("documented.py"));

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

    // Line 21 (0-based) is `class DocumentedClass:`. The class name starts
    // at char 6 — guards against the language-tag table emitting "java"
    // (or any wrong tag) for a .py file.
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/hover",
            "params": {
                "textDocument": {"uri": py_uri},
                "position": {"line": 21, "character": 7}
            }
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
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

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
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
            "method": "textDocument/codeAction",
            "params": {
                "textDocument": {"uri": "file:///nope"},
                "range": {
                    "start": {"line": 0, "character": 0},
                    "end": {"line": 0, "character": 0}
                },
                "context": {"diagnostics": []}
            }
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
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));

    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
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

    let root_uri = uri_for(&temp_root);
    let push_uri = uri_for(&temp_root.join("Push.java"));

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

    // Replace the file with broken Java, then send didSave. The server should
    // emit a `textDocument/publishDiagnostics` notification with at least one
    // parse-error item.
    fs::write(
        temp_root.join("Push.java"),
        "public class Push {\n    public void broken( {\n}\n",
    )
    .expect("rewrite fixture");
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didSave",
            "params": {"textDocument": {"uri": push_uri}}
        }),
    );

    let publish = read_notification(&mut reader, &mut stderr, "textDocument/publishDiagnostics");
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
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didSave",
            "params": {"textDocument": {"uri": push_uri}}
        }),
    );
    let cleared = read_notification(&mut reader, &mut stderr, "textDocument/publishDiagnostics");
    let cleared_items = cleared["params"]["diagnostics"]
        .as_array()
        .unwrap_or_else(|| panic!("expected diagnostics array, got {cleared}"));
    assert!(
        cleared_items.is_empty(),
        "expected zero diagnostics after clean save, got {cleared}"
    );

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 99, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_returns_folding_ranges_for_a_java() {
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
    let root_uri = uri_for(&canonical_root);
    let file_uri = uri_for(&canonical_root.join("A.java"));

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
        init["result"]["capabilities"]["foldingRangeProvider"], true,
        "foldingRangeProvider should be advertised: {init}"
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
            "method": "textDocument/foldingRange",
            "params": {"textDocument": {"uri": file_uri}}
        }),
    );
    let response = read_message(&mut reader, &mut stderr);
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

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    let _ = read_message(&mut reader, &mut stderr);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

/// Spin up a bifrost LSP server rooted at `root`, do the initialize handshake,
/// and return (child, stdin, reader, stderr). Used by the didOpen/didChange/
/// didClose tests so each test isn't 50 lines of boilerplate before the
/// scenario starts.
fn start_lsp_server(
    root: &Path,
) -> (
    std::process::Child,
    std::process::ChildStdin,
    BufReader<std::process::ChildStdout>,
    std::process::ChildStderr,
) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(root)
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

    let root_uri = uri_for(root);
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
    (child, stdin, reader, stderr)
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

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);

    let child_item =
        prepare_type_hierarchy(&mut stdin, &mut reader, &mut stderr, 10, &file_uri, 1, 6);
    assert_eq!(child_item["name"], "Child", "prepared child: {child_item}");

    let supertypes = type_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        11,
        "typeHierarchy/supertypes",
        child_item,
    );
    assert_eq!(
        supertypes.len(),
        1,
        "expected one supertype: {supertypes:#?}"
    );
    assert_eq!(supertypes[0]["name"], "Base", "supertype should be Base");

    let base_item = supertypes[0].clone();
    let subtypes = type_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        12,
        "typeHierarchy/subtypes",
        base_item,
    );
    let subtype_names: Vec<_> = subtypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(subtype_names, vec!["Child"], "subtypes: {subtypes:#?}");

    shutdown_lsp(child, stdin, reader, stderr);
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

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let child_item =
        prepare_type_hierarchy(&mut stdin, &mut reader, &mut stderr, 20, &file_uri, 3, 6);

    let supertypes = type_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        21,
        "typeHierarchy/supertypes",
        child_item,
    );
    let supertype_names: Vec<_> = supertypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(supertype_names, vec!["Base"], "supertypes: {supertypes:#?}");

    shutdown_lsp(child, stdin, reader, stderr);
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

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let child_item =
        prepare_type_hierarchy(&mut stdin, &mut reader, &mut stderr, 30, &file_uri, 4, 6);

    let supertypes = type_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        31,
        "typeHierarchy/supertypes",
        child_item,
    );
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
    let subtypes = type_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        32,
        "typeHierarchy/subtypes",
        base_item,
    );
    let subtype_names: Vec<_> = subtypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(subtype_names, vec!["Child"], "subtypes: {subtypes:#?}");

    shutdown_lsp(child, stdin, reader, stderr);
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

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let child_item =
        prepare_type_hierarchy(&mut stdin, &mut reader, &mut stderr, 40, &file_uri, 1, 8);
    assert_eq!(child_item["name"], "Child", "prepared child: {child_item}");

    let supertypes = type_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        41,
        "typeHierarchy/supertypes",
        child_item,
    );
    let supertype_names: Vec<_> = supertypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(supertype_names, vec!["Base"], "supertypes: {supertypes:#?}");

    let base_item = supertypes[0].clone();
    let subtypes = type_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        42,
        "typeHierarchy/subtypes",
        base_item,
    );
    let subtype_names: Vec<_> = subtypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(subtype_names, vec!["Child"], "subtypes: {subtypes:#?}");

    shutdown_lsp(child, stdin, reader, stderr);
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

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    let child_item =
        prepare_type_hierarchy(&mut stdin, &mut reader, &mut stderr, 50, &file_uri, 3, 6);
    assert_eq!(child_item["name"], "Child", "prepared child: {child_item}");

    let supertypes = type_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        51,
        "typeHierarchy/supertypes",
        child_item,
    );
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
    let subtypes = type_hierarchy_relation(
        &mut stdin,
        &mut reader,
        &mut stderr,
        52,
        "typeHierarchy/subtypes",
        base_item,
    );
    let subtype_names: Vec<_> = subtypes
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(subtype_names, vec!["Child"], "subtypes: {subtypes:#?}");

    shutdown_lsp(child, stdin, reader, stderr);
}

#[test]
fn bifrost_lsp_server_type_hierarchy_returns_null_without_provider() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("lib.rs");
    fs::write(&file_path, "struct Base;\n").expect("write Rust fixture");
    fs::write(root.join("Supported.java"), "class Supported {}\n").expect("write Java fixture");

    let (child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 30,
            "method": "textDocument/prepareTypeHierarchy",
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": 0, "character": 7}
            }
        }),
    );
    let response = read_response_for_id(&mut reader, &mut stderr, 30);
    assert!(
        response["result"].is_null(),
        "expected null prepare result without provider, got {response}"
    );

    shutdown_lsp(child, stdin, reader, stderr);
}

fn prepare_type_hierarchy(
    stdin: &mut impl Write,
    reader: &mut impl BufRead,
    stderr: &mut impl Read,
    id: u64,
    uri: &str,
    line: u64,
    character: u64,
) -> Value {
    write_message(
        stdin,
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "textDocument/prepareTypeHierarchy",
            "params": {
                "textDocument": {"uri": uri},
                "position": {"line": line, "character": character}
            }
        }),
    );
    let response = read_response_for_id(reader, stderr, id);
    let items = response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected prepare array, got {response}"));
    assert_eq!(items.len(), 1, "expected one prepared item: {items:#?}");
    items[0].clone()
}

fn type_hierarchy_relation(
    stdin: &mut impl Write,
    reader: &mut impl BufRead,
    stderr: &mut impl Read,
    id: u64,
    method: &str,
    item: Value,
) -> Vec<Value> {
    write_message(
        stdin,
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": {"item": item}
        }),
    );
    let response = read_response_for_id(reader, stderr, id);
    response["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected {method} array, got {response}"))
        .clone()
}

fn shutdown_lsp(
    mut child: std::process::Child,
    mut stdin: std::process::ChildStdin,
    mut reader: BufReader<std::process::ChildStdout>,
    mut stderr: std::process::ChildStderr,
) {
    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 99, "method": "shutdown"}),
    );
    let _ = read_response_for_id(&mut reader, &mut stderr, 99);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
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

    let (mut child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);

    // didOpen with overlay content — different function name than disk.
    write_message(
        &mut stdin,
        json!({
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
        }),
    );
    // didOpen emits a publishDiagnostics — drain it before the request.
    let _ = read_notification(&mut reader, &mut stderr, "textDocument/publishDiagnostics");

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "textDocument/hover",
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": 0, "character": 5}
            }
        }),
    );
    let hover_open = read_response_for_id(&mut reader, &mut stderr, 10);
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
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didChange",
            "params": {
                "textDocument": {"uri": file_uri, "version": 2},
                "contentChanges": [{"text": "fn changed() {}\n"}]
            }
        }),
    );
    let _ = read_notification(&mut reader, &mut stderr, "textDocument/publishDiagnostics");

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "textDocument/hover",
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": 0, "character": 5}
            }
        }),
    );
    let hover_changed = read_response_for_id(&mut reader, &mut stderr, 11);
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
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didClose",
            "params": {"textDocument": {"uri": file_uri}}
        }),
    );
    let _ = read_notification(&mut reader, &mut stderr, "textDocument/publishDiagnostics");

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "textDocument/hover",
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": 0, "character": 5}
            }
        }),
    );
    let hover_closed = read_response_for_id(&mut reader, &mut stderr, 12);
    let hover_text_closed = hover_closed["result"]["contents"]["value"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        hover_text_closed.contains("original"),
        "after didClose, hover should reflect disk content, got {hover_text_closed}"
    );

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 99, "method": "shutdown"}),
    );
    let _ = read_response_for_id(&mut reader, &mut stderr, 99);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
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

    let (mut child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);

    write_message(
        &mut stdin,
        json!({
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
        }),
    );
    let _ = read_notification(&mut reader, &mut stderr, "textDocument/publishDiagnostics");

    // The overlay introduces `mark_overlay_42` followed by a partial call at
    // position (2, 4) so the completion prefix on the cursor is `mark`.
    let overlay_text = "fn mark_overlay_42() {}\nfn caller() {\n    mark\n}\n";
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didChange",
            "params": {
                "textDocument": {"uri": file_uri, "version": 2},
                "contentChanges": [{"text": overlay_text}]
            }
        }),
    );
    let _ = read_notification(&mut reader, &mut stderr, "textDocument/publishDiagnostics");

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 20,
            "method": "textDocument/completion",
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": 2, "character": 8}
            }
        }),
    );
    let completion = read_response_for_id(&mut reader, &mut stderr, 20);
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

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 99, "method": "shutdown"}),
    );
    let _ = read_response_for_id(&mut reader, &mut stderr, 99);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_did_close_reverts_completion_to_disk() {
    // After didOpen + didClose, the overlay symbol vanishes from completion
    // results. Guards against state leakage of the overlay across close.
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("lib.rs");
    fs::write(&file_path, "fn disk_placeholder() {}\n").expect("write disk");

    let (mut child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);

    write_message(
        &mut stdin,
        json!({
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
        }),
    );
    let _ = read_notification(&mut reader, &mut stderr, "textDocument/publishDiagnostics");

    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didClose",
            "params": {"textDocument": {"uri": file_uri}}
        }),
    );
    let _ = read_notification(&mut reader, &mut stderr, "textDocument/publishDiagnostics");

    // Disk content has no `unique` symbol; completion (across the workspace)
    // for prefix `unique` must return nothing matching the overlay symbol.
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 30,
            "method": "workspace/symbol",
            "params": {"query": "unique_overlay_token"}
        }),
    );
    let symbols = read_response_for_id(&mut reader, &mut stderr, 30);
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

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 99, "method": "shutdown"}),
    );
    let _ = read_response_for_id(&mut reader, &mut stderr, 99);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_lsp_server_malformed_didchange_drops_silently_to_client() {
    // A non-conforming client that sends `didChange` events with `range`
    // populated (INCREMENTAL semantics) despite our advertising
    // `TextDocumentSyncKind::FULL` must NOT trigger a parse or a
    // publishDiagnostics — we have no way to apply the partial edits and
    // applying any one of them as a full document would silently truncate
    // the buffer.
    //
    // The visible contract this test pins is the absence of side effects:
    // a hover request issued immediately after the malformed didChange
    // must receive its response without an interleaved publishDiagnostics
    // notification. (Stderr does carry a throttled warning; capturing
    // child stderr deterministically is too flaky to assert on here.)
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file_path = root.join("lib.rs");
    fs::write(&file_path, "fn original() {}\n").expect("write disk");

    let (mut child, mut stdin, mut reader, mut stderr) = start_lsp_server(&root);
    let file_uri = uri_for(&file_path);

    // didOpen establishes an overlay and produces one publishDiagnostics.
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": file_uri,
                    "languageId": "rust",
                    "version": 1,
                    "text": "fn original() {}\n"
                }
            }
        }),
    );
    let _ = read_notification(&mut reader, &mut stderr, "textDocument/publishDiagnostics");

    // Malformed didChange: a single content_change with a populated range.
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didChange",
            "params": {
                "textDocument": {"uri": file_uri, "version": 2},
                "contentChanges": [{
                    "range": {
                        "start": {"line": 0, "character": 0},
                        "end": {"line": 0, "character": 0}
                    },
                    "text": "this would be an incremental edit"
                }]
            }
        }),
    );

    // The server should drop the notification with no publishDiagnostics.
    // We can't assert "no message" without a timeout, but we can prove the
    // next message off the wire is the hover response (not a diagnostics
    // notification interleaved before it), since LSP messages are processed
    // serially.
    write_message(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 40,
            "method": "textDocument/hover",
            "params": {
                "textDocument": {"uri": file_uri},
                "position": {"line": 0, "character": 5}
            }
        }),
    );

    // Read the very next inbound message. If the malformed didChange had
    // emitted publishDiagnostics, the notification would arrive first.
    let next = read_message(&mut reader, &mut stderr);
    assert_eq!(
        next["id"].as_u64(),
        Some(40),
        "expected hover response (id 40) as the next message; \
         malformed didChange must not emit publishDiagnostics: {next}"
    );

    // Overlay must still reflect the pre-malformed-didChange state.
    let hover_text = next["result"]["contents"]["value"]
        .as_str()
        .unwrap_or_default();
    assert!(
        hover_text.contains("original"),
        "hover should still see the didOpen overlay content, got {hover_text}"
    );

    write_message(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 99, "method": "shutdown"}),
    );
    let _ = read_response_for_id(&mut reader, &mut stderr, 99);
    write_message(&mut stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

/// Read messages until a notification with `expected_method` arrives. Skips
/// any other inbound traffic so callers don't have to know the exact ordering
/// of unrelated server-to-client messages.
fn read_notification(
    reader: &mut impl BufRead,
    stderr: &mut impl Read,
    expected_method: &str,
) -> Value {
    for _ in 0..32 {
        let msg = read_message(reader, stderr);
        if msg["method"] == expected_method {
            return msg;
        }
    }
    panic!("did not receive {expected_method} within 32 messages");
}

/// Read messages until the response with the given id arrives, skipping
/// notifications (e.g. publishDiagnostics) the server may interleave.
fn read_response_for_id(reader: &mut impl BufRead, stderr: &mut impl Read, id: u64) -> Value {
    for _ in 0..32 {
        let msg = read_message(reader, stderr);
        if msg["id"].as_u64() == Some(id) {
            return msg;
        }
    }
    panic!("did not receive response with id {id} within 32 messages");
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
