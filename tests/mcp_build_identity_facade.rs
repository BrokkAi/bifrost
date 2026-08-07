use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

#[test]
fn root_binary_injects_its_build_identity_into_the_mcp_host() {
    let root = tempfile::tempdir().expect("tempdir");
    let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .env("BIFROST_SEMANTIC_INDEX", "off")
        .env("BIFROST_MCP_FILE_WATCHER", "off")
        .arg("--root")
        .arg(root.path())
        .arg("--mcp")
        .arg("workspace")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn root bifrost binary");

    let mut stdin = child.stdin.take().expect("stdin");
    writeln!(
        stdin,
        "{}",
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "facade-contract", "version": "1" }
            }
        })
    )
    .expect("write initialize");
    stdin.flush().expect("flush initialize");

    let mut line = String::new();
    BufReader::new(child.stdout.take().expect("stdout"))
        .read_line(&mut line)
        .expect("read initialize response");
    let response: Value = serde_json::from_str(&line).expect("valid JSON response");
    // RMCP reports build identity in the initialize result's `_meta` because
    // its `serverInfo` has no vendor field.
    let reported = response
        .pointer("/result/_meta/io.bifrost~1build-identity")
        .and_then(Value::as_str);
    assert_eq!(
        reported,
        Some(brokk_bifrost::BIFROST_BUILD_IDENTITY),
        "{response}"
    );

    drop(stdin);
    assert!(child.wait().expect("wait root bifrost binary").success());
}
