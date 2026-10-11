use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::Child;

pub fn write_line(stdin: &mut impl Write, payload: Value) {
    writeln!(stdin, "{payload}").expect("write MCP request");
    stdin.flush().expect("flush MCP request");
}

pub fn read_line(reader: &mut impl BufRead, stderr: &mut impl Read) -> Value {
    let mut line = String::new();
    let bytes = reader.read_line(&mut line).expect("read MCP response");
    if bytes == 0 {
        let mut error = String::new();
        stderr
            .read_to_string(&mut error)
            .expect("read MCP server stderr");
        panic!("MCP server closed before responding; stderr:\n{error}");
    }
    serde_json::from_str(&line).expect("valid MCP JSON response")
}

pub fn round_trip_json_line(
    stdin: &mut impl Write,
    reader: &mut impl BufRead,
    stderr: &mut impl Read,
    payload: Value,
) -> Value {
    write_line(stdin, payload);
    read_line(reader, stderr)
}

pub fn tool_call_request(id: i64, name: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": { "name": name, "arguments": arguments }
    })
}

pub fn call_mcp_tool(
    child: &mut Child,
    client_name: &str,
    initialize_id: u64,
    request_id: u64,
    tool_name: &str,
    arguments: Value,
) -> Value {
    let mut stdin = child.stdin.take().expect("MCP stdin");
    let stdout = child.stdout.take().expect("MCP stdout");
    let mut stderr = child.stderr.take().expect("MCP stderr");
    let mut reader = BufReader::new(stdout);

    let initialize = round_trip_json_line(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": initialize_id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": client_name, "version": "0.1.0" }
            }
        }),
    );
    assert_eq!(initialize["result"]["protocolVersion"], "2025-11-25");
    write_line(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    );

    round_trip_json_line(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments
            }
        }),
    )
}
