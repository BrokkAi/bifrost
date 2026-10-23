use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Cursor, Read, Write};
use std::process::{Child, ChildStderr};
use std::thread::JoinHandle;

/// The server's stderr, drained on its own thread from the moment the server
/// starts. A pipe holds about 64 KiB; a server that logs more than that (for
/// example every span under `BIFROST_TIMING=1`) blocks on its next write, and
/// a client that only reads stdout then waits forever for a reply the server
/// can no longer produce. The drained bytes are kept for the failure message.
pub struct DrainedStderr {
    drain: Option<JoinHandle<Vec<u8>>>,
    captured: Cursor<Vec<u8>>,
}

impl DrainedStderr {
    pub fn spawn(mut stderr: ChildStderr) -> Self {
        let drain = std::thread::spawn(move || {
            let mut captured = Vec::new();
            stderr
                .read_to_end(&mut captured)
                .expect("read the server's stderr");
            captured
        });
        Self {
            drain: Some(drain),
            captured: Cursor::new(Vec::new()),
        }
    }
}

impl Read for DrainedStderr {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if let Some(drain) = self.drain.take() {
            self.captured = Cursor::new(drain.join().expect("the stderr drain thread panicked"));
        }
        self.captured.read(buffer)
    }
}

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
    let mut stderr = DrainedStderr::spawn(child.stderr.take().expect("MCP stderr"));
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

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    #[hardwon("#6291: an MCP test client deadlocked once server stderr passed 64 KiB")]
    fn mcp_client_drains_stderr_before_response() {
        const CHILD_ENV: &str = "BIFROST_TEST_MCP_STDERR_CHILD";
        const READY: &str = "mcp-stderr-child-ready";
        const STDERR_BYTES: usize = 256 * 1024;
        if std::env::var_os(CHILD_ENV).is_some() {
            let mut stdout = std::io::stdout().lock();
            writeln!(stdout, "{READY}").unwrap();
            stdout.flush().unwrap();
            let mut request = String::new();
            std::io::stdin().read_line(&mut request).unwrap();
            let request: Value = serde_json::from_str(&request).unwrap();
            let mut stderr = std::io::stderr().lock();
            stderr.write_all(&vec![b'x'; STDERR_BYTES]).unwrap();
            stderr.flush().unwrap();
            writeln!(
                stdout,
                "{}",
                json!({"id": request["id"], "result": "ready"})
            )
            .unwrap();
            stdout.flush().unwrap();
            std::process::exit(0);
        }

        // Reuse this executable as a portable child; the marker separates the
        // libtest preamble from the child's one-line JSON protocol.
        let full_name = concat!(module_path!(), "::mcp_client_drains_stderr_before_response");
        let (_, test_name) = full_name.split_once("::").unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test_name, "--nocapture"])
            .env(CHILD_ENV, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stderr = DrainedStderr::spawn(child.stderr.take().unwrap());
        let mut reader = BufReader::new(child.stdout.take().unwrap());
        let mut stdin = child.stdin.take().unwrap();
        loop {
            let mut line = String::new();
            assert_ne!(
                reader.read_line(&mut line).unwrap(),
                0,
                "child reached its protocol"
            );
            if line.trim() == READY {
                break;
            }
        }
        let (sent, received) = mpsc::channel();
        let response_reader = std::thread::spawn(move || {
            let response = round_trip_json_line(
                &mut stdin,
                &mut reader,
                &mut stderr,
                json!({"id": 1, "method": "test"}),
            );
            let mut captured = Vec::new();
            stderr.read_to_end(&mut captured).unwrap();
            sent.send((response, captured)).unwrap();
        });
        let response = received.recv_timeout(Duration::from_secs(10));
        if response.is_err() {
            child
                .kill()
                .expect("stop a child blocked on its stderr pipe");
        }
        let status = child.wait().unwrap();
        response_reader
            .join()
            .expect("MCP response reader panicked");
        assert!(status.success(), "stderr-writing child failed: {status}");
        let (response, captured) = response.expect("response arrived before stderr could deadlock");
        assert_eq!(response, json!({"id": 1, "result": "ready"}));
        assert_eq!(captured, vec![b'x'; STDERR_BYTES]);
    }
}
