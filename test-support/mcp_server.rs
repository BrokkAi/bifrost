use serde_json::{Value, json};
use std::io;
use std::path::Path;
use std::process::{Child, Command, Stdio};

pub const STATELESS_REVISION: &str = "2026-07-28";

/// The request budget functional MCP tests give a spawned server.
///
/// Those tests assert protocol and report behavior, not the production
/// interactive deadline. The benchmark-aligned 60 s budget is a latency
/// contract; under a saturated validation host (#14097, about 47 runnable
/// tasks on 32 CPUs) report-shaped calls outlived it. This is test-only:
/// production fallbacks and the benchmark keep
/// `BENCHMARK_MCP_REQUEST_BUDGET_SECS`.
pub const FUNCTIONAL_TEST_MCP_REQUEST_BUDGET_SECS: u64 = 240;

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

/// Tests must not depend on host JDK discovery (#14290).
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
    command.env("JAVA_HOME", "");
    for &(key, value) in environment {
        command.env(key, value);
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// Tests must not depend on host JDK discovery (#14290).
pub fn spawn_mcp_server(
    binary: &str,
    root: &Path,
    mode: &str,
    extra_args: &[&str],
    environment: &[(&str, &str)],
) -> io::Result<Child> {
    mcp_server_command(binary, root, mode, extra_args, environment).spawn()
}

/// Tests must not depend on host JDK discovery (#14290).
pub fn spawn_mcp_server_at_production_budget(
    binary: &str,
    root: &Path,
    mode: &str,
) -> io::Result<Child> {
    mcp_server_command(binary, root, mode, &[], &[])
        .env_remove("BIFROST_MCP_REQUEST_BUDGET_SECS")
        .spawn()
}
