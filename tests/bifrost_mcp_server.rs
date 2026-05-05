use serde_json::{Value, json};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use tempfile::TempDir;

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
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    let initialize = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
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
        &mut stderr,
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
    assert!(tools.iter().any(|tool| tool["name"] == "get_summaries"));
    assert!(
        !tools
            .iter()
            .any(|tool| tool["name"] == "get_file_summaries")
    );
    assert!(tools.iter().any(|tool| tool["name"] == "list_symbols"));
    assert!(
        tools
            .iter()
            .any(|tool| tool["name"] == "most_relevant_files")
    );
    assert!(tools.iter().any(|tool| tool["name"] == "scan_usages"));

    let scan_usages = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 100,
            "method": "tools/call",
            "params": {
                "name": "scan_usages",
                "arguments": {
                    "symbols": ["E.iMethod"],
                    "include_tests": true
                }
            }
        }),
    );
    let scan = &scan_usages["result"]["structuredContent"];
    let usages = scan["usages"].as_array().expect("usages array");
    assert_eq!(1, usages.len(), "scan: {scan_usages}");
    assert_eq!("E.iMethod", usages[0]["symbol"]);
    let files = usages[0]["files"].as_array().expect("files array");
    assert!(
        files.iter().any(|file| file["path"] == "UseE.java"),
        "expected UseE.java in scan_usages files: {scan_usages}"
    );

    let file_summaries = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "get_summaries",
                "arguments": {
                    "targets": ["A.java"]
                }
            }
        }),
    );
    let structured = &file_summaries["result"]["structuredContent"];
    assert_eq!("A.java", structured["summaries"][0]["path"]);
    assert_eq!(3, structured["summaries"][0]["elements"][0]["start_line"]);
    assert_eq!(52, structured["summaries"][0]["elements"][0]["end_line"]);

    let list_symbols = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "list_symbols",
                "arguments": {
                    "file_patterns": ["A.java"]
                }
            }
        }),
    );
    let skim = &list_symbols["result"]["structuredContent"];
    assert_eq!("A.java", skim["files"][0]["path"]);
    let lines = skim["files"][0]["lines"].as_array().expect("skim lines");
    assert!(lines.iter().any(|line| line.as_str() == Some("  - AInner")));
    assert!(
        lines
            .iter()
            .any(|line| line.as_str() == Some("    - AInnerInner"))
    );
    assert!(
        lines
            .iter()
            .any(|line| line.as_str() == Some("      - method7"))
    );

    let ping = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "ping"
        }),
    );
    assert_eq!(json!({}), ping["result"]);

    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

#[test]
fn bifrost_searchtools_server_supports_runtime_workspace_switch() {
    let initial_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java");

    let switched = TempDir::new().expect("temp dir");
    fs::write(
        switched.path().join("Switched.java"),
        "public class Switched {}\n",
    )
    .expect("write fixture");
    let switched_root = switched.path().canonicalize().expect("canonicalize");

    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(&initial_root)
        .arg("--server")
        .arg("searchtools")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "test-client", "version": "0.1.0" }
            }
        }),
    );
    write_line(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    );

    let list_tools = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }),
    );
    let tools = list_tools["result"]["tools"]
        .as_array()
        .expect("tools array");
    assert!(
        tools
            .iter()
            .any(|tool| tool["name"] == "activate_workspace"),
        "activate_workspace missing from tool list: {list_tools}"
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool["name"] == "get_active_workspace"),
        "get_active_workspace missing from tool list: {list_tools}"
    );

    let initial_active = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "get_active_workspace",
                "arguments": {}
            }
        }),
    );
    let initial_path = initial_active["result"]["structuredContent"]["workspace_path"]
        .as_str()
        .expect("initial workspace path");
    let expected_initial = initial_root.canonicalize().expect("canon initial");
    assert_eq!(initial_path, expected_initial.display().to_string());

    let activate = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "activate_workspace",
                "arguments": { "workspace_path": switched_root.display().to_string() }
            }
        }),
    );
    assert_eq!(
        activate["result"]["structuredContent"]["workspace_path"],
        switched_root.display().to_string()
    );

    let after_switch = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "list_symbols",
                "arguments": { "file_patterns": ["Switched.java"] }
            }
        }),
    );
    assert_eq!(
        after_switch["result"]["structuredContent"]["files"][0]["path"],
        "Switched.java"
    );

    let bad_path = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "activate_workspace",
                "arguments": { "workspace_path": "relative/path" }
            }
        }),
    );
    assert_eq!(bad_path["error"]["code"], -32602);

    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    assert!(status.success(), "bifrost exited unsuccessfully: {status}");
}

fn round_trip(
    stdin: &mut impl Write,
    reader: &mut impl BufRead,
    stderr: &mut impl Read,
    payload: Value,
) -> Value {
    write_line(stdin, payload);
    read_line(reader, stderr)
}

fn write_line(stdin: &mut impl Write, payload: Value) {
    writeln!(stdin, "{payload}").expect("write request");
    stdin.flush().expect("flush request");
}

fn read_line(reader: &mut impl BufRead, stderr: &mut impl Read) -> Value {
    let mut line = String::new();
    let bytes = reader.read_line(&mut line).expect("read response");
    if bytes == 0 {
        let mut buf = String::new();
        let _ = stderr.read_to_string(&mut buf);
        panic!("server closed before responding; stderr:\n{buf}");
    }
    serde_json::from_str(&line).expect("valid json response")
}
