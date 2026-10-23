use super::mcp_wire::DrainedStderr;
use serde_json::{Value, json};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};

pub const STATELESS_REVISION: &str = "2026-07-28";

pub fn mcp_server_binary() -> &'static str {
    option_env!("CARGO_BIN_EXE_bifrost-mcp-test-server")
        .or(option_env!("CARGO_BIN_EXE_bifrost"))
        .expect("Cargo did not provide an MCP server binary")
}

pub fn stateless_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": STATELESS_REVISION,
        "io.modelcontextprotocol/clientCapabilities": {}
    })
}

pub fn stateless_tasks_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": STATELESS_REVISION,
        "io.modelcontextprotocol/clientCapabilities": {
            "extensions": { "io.modelcontextprotocol/tasks": {} }
        }
    })
}

pub fn stateless_search_symbols_call(id: i64, pattern: &str, metadata: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "search_symbols",
            "arguments": { "patterns": [pattern] },
            "_meta": metadata
        }
    })
}

pub fn stateless_tasks_request(mut request: Value) -> Value {
    request["params"]["_meta"] = stateless_tasks_meta();
    request
}

pub fn assert_tool_schema_omits_property(tools: &[Value], tool_name: &str, property_name: &str) {
    let tool = tools
        .iter()
        .find(|tool| tool["name"] == tool_name)
        .unwrap_or_else(|| panic!("missing tool descriptor for {tool_name}"));
    let schema = serde_json::to_string(&tool["inputSchema"]).expect("schema serializes");
    assert!(
        !schema.contains(property_name),
        "{tool_name} schema unexpectedly contains {property_name}: {schema}"
    );
}

pub fn mcp_server_command(
    binary: &str,
    root: &Path,
    mode: &str,
    extra_args: &[&str],
    environment: &[(&str, &str)],
) -> Command {
    let mut command = Command::new(binary);
    command.arg("--root").arg(root).arg("--mcp").arg(mode);
    command.args(extra_args);
    for &(key, value) in environment {
        command.env(key, value);
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

pub fn spawn_mcp_server(
    binary: &str,
    root: &Path,
    mode: &str,
    extra_args: &[&str],
    environment: &[(&str, &str)],
) -> io::Result<Child> {
    mcp_server_command(binary, root, mode, extra_args, environment).spawn()
}

pub fn spawn_mcp_server_at_production_budget(
    binary: &str,
    root: &Path,
    mode: &str,
) -> io::Result<Child> {
    mcp_server_command(binary, root, mode, &[], &[])
        .env_remove("BIFROST_MCP_REQUEST_BUDGET_SECS")
        .spawn()
}

pub fn run_cold_first_tool_call(binary: &str, root: &Path, request: Value) -> (Value, ExitStatus) {
    let mut child = spawn_mcp_server_at_production_budget(binary, root, "searchtools")
        .expect("spawn cold-start guard bifrost");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut stderr = DrainedStderr::spawn(child.stderr.take().expect("stderr"));

    let protocol_version = "2025-11-25";
    let initialize = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": protocol_version,
                "capabilities": {},
                "clientInfo": { "name": "test-client", "version": "0.1.0" }
            }
        }),
    );
    assert_eq!(
        initialize["result"]["protocolVersion"], protocol_version,
        "server did not negotiate the requested revision: {initialize}"
    );
    write_line(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    );

    let response = round_trip(&mut stdin, &mut reader, &mut stderr, request);
    drop(stdin);
    let status = child.wait().expect("wait bifrost");
    (response, status)
}

fn round_trip(
    stdin: &mut impl Write,
    reader: &mut impl BufRead,
    stderr: &mut impl Read,
    payload: Value,
) -> Value {
    write_line(stdin, payload);
    read_message(reader, stderr)
}

fn write_line(stdin: &mut impl Write, payload: Value) {
    writeln!(stdin, "{payload}").expect("write request");
    stdin.flush().expect("flush request");
}

fn read_message(reader: &mut impl BufRead, stderr: &mut impl Read) -> Value {
    let mut line = String::new();
    if reader.read_line(&mut line).expect("read response") == 0 {
        let mut error = String::new();
        stderr.read_to_string(&mut error).expect("read stderr");
        panic!("MCP server closed stdout before replying; stderr: {error}");
    }
    serde_json::from_str(&line).expect("parse response")
}
