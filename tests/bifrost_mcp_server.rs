use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

#[test]
fn bifrost_searchtools_server_speaks_mcp_stdio() {
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&fixture_root)
        .arg("--server")
        .arg("searchtools")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut reader = BufReader::new(stdout);

    let initialize = round_trip(
        &mut stdin,
        &mut reader,
        json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {
                    "name": "test-client",
                    "version": "0.1.0"
                }
            }
        }),
    );
    assert_eq!("2.0", initialize["jsonrpc"]);
    assert_eq!(0, initialize["id"]);
    assert_eq!("2025-11-25", initialize["result"]["protocolVersion"]);

    write_line(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );

    let list_tools = round_trip(
        &mut stdin,
        &mut reader,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list"
        }),
    );
    let tools = list_tools["result"]["tools"]
        .as_array()
        .expect("tools array");
    assert!(tools.iter().any(|tool| tool["name"] == "search_symbols"));
    assert!(
        tools
            .iter()
            .any(|tool| tool["name"] == "get_file_summaries")
    );

    let file_summaries = round_trip(
        &mut stdin,
        &mut reader,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "get_file_summaries",
                "arguments": {
                    "file_patterns": ["A.java"]
                }
            }
        }),
    );
    let structured = &file_summaries["result"]["structuredContent"];
    assert_eq!("A.java", structured["summaries"][0]["path"]);
    assert_eq!(3, structured["summaries"][0]["elements"][0]["start_line"]);
    assert_eq!(3, structured["summaries"][0]["elements"][0]["end_line"]);

    let ping = round_trip(
        &mut stdin,
        &mut reader,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "ping"
        }),
    );
    assert_eq!(json!({}), ping["result"]);

    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

fn round_trip(stdin: &mut impl Write, reader: &mut impl BufRead, payload: Value) -> Value {
    write_line(stdin, payload);
    read_line(reader)
}

fn write_line(stdin: &mut impl Write, payload: Value) {
    writeln!(stdin, "{payload}").expect("write request");
    stdin.flush().expect("flush request");
}

fn read_line(reader: &mut impl BufRead) -> Value {
    let mut line = String::new();
    let bytes = reader.read_line(&mut line).expect("read response");
    assert!(bytes > 0, "server closed before responding");
    serde_json::from_str(&line).expect("valid json response")
}
