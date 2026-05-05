use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};

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
            "method": "textDocument/documentSymbol",
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
