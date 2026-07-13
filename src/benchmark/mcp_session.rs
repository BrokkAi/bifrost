use serde_json::{Value, json};
use std::collections::VecDeque;
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

const STDERR_TAIL_CAPACITY_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct StderrCursor {
    next_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedStderr {
    pub text: String,
    pub truncated: bool,
}

#[derive(Debug)]
struct StderrChunk {
    sequence: u64,
    bytes: Vec<u8>,
    prefix_truncated: bool,
}

#[derive(Debug)]
struct StderrTail {
    chunks: VecDeque<StderrChunk>,
    bytes: usize,
    capacity: usize,
    next_sequence: u64,
    read_error: Option<String>,
}

impl StderrTail {
    fn new(capacity: usize) -> Self {
        Self {
            chunks: VecDeque::new(),
            bytes: 0,
            capacity,
            next_sequence: 0,
            read_error: None,
        }
    }

    fn push(&mut self, mut bytes: Vec<u8>) {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        if self.capacity == 0 {
            self.chunks.clear();
            self.bytes = 0;
            return;
        }

        let prefix_truncated = bytes.len() > self.capacity;
        if prefix_truncated {
            bytes.drain(..bytes.len() - self.capacity);
        }
        while self.bytes + bytes.len() > self.capacity {
            let Some(removed) = self.chunks.pop_front() else {
                break;
            };
            self.bytes -= removed.bytes.len();
        }
        self.bytes += bytes.len();
        self.chunks.push_back(StderrChunk {
            sequence,
            bytes,
            prefix_truncated,
        });
    }

    fn cursor(&self) -> StderrCursor {
        StderrCursor {
            next_sequence: self.next_sequence,
        }
    }

    fn capture_since(&self, cursor: StderrCursor) -> CapturedStderr {
        let first_retained = self
            .chunks
            .front()
            .map_or(self.next_sequence, |chunk| chunk.sequence);
        let mut truncated = cursor.next_sequence < first_retained;
        let mut bytes = Vec::new();
        for chunk in self
            .chunks
            .iter()
            .filter(|chunk| chunk.sequence >= cursor.next_sequence)
        {
            truncated |= chunk.prefix_truncated;
            bytes.extend_from_slice(&chunk.bytes);
        }
        if let Some(error) = &self.read_error {
            bytes.extend_from_slice(format!("\n[stderr drain error: {error}]\n").as_bytes());
        }
        CapturedStderr {
            text: String::from_utf8_lossy(&bytes).into_owned(),
            truncated,
        }
    }

    fn tail(&self) -> String {
        self.capture_since(StderrCursor { next_sequence: 0 }).text
    }
}

struct StderrDrain {
    tail: Arc<Mutex<StderrTail>>,
    reader: Option<JoinHandle<()>>,
}

impl StderrDrain {
    fn spawn(reader: impl Read + Send + 'static, capacity: usize) -> Result<Self, String> {
        let tail = Arc::new(Mutex::new(StderrTail::new(capacity)));
        let reader_tail = Arc::clone(&tail);
        let reader = thread::Builder::new()
            .name("bifrost-benchmark-stderr".to_string())
            .spawn(move || drain_stderr(reader, &reader_tail))
            .map_err(|err| format!("failed to start bifrost stderr drain: {err}"))?;
        Ok(Self {
            tail,
            reader: Some(reader),
        })
    }

    fn cursor(&self) -> StderrCursor {
        self.with_tail(StderrTail::cursor)
    }

    fn capture_since(&self, cursor: StderrCursor) -> CapturedStderr {
        self.with_tail(|tail| tail.capture_since(cursor))
    }

    fn tail(&self) -> String {
        self.with_tail(StderrTail::tail)
    }

    fn join(&mut self) {
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }

    fn with_tail<T>(&self, read: impl FnOnce(&StderrTail) -> T) -> T {
        let guard = self
            .tail
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        read(&guard)
    }
}

fn drain_stderr(reader: impl Read, tail: &Mutex<StderrTail>) {
    let mut reader = BufReader::new(reader);
    loop {
        let mut bytes = Vec::new();
        match reader.read_until(b'\n', &mut bytes) {
            Ok(0) => return,
            Ok(_) => tail
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(bytes),
            Err(err) => {
                tail.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .read_error = Some(err.to_string());
                return;
            }
        }
    }
}

pub struct McpSession {
    child: Child,
    stdin: ChildStdin,
    reader: BufReader<ChildStdout>,
    stderr: StderrDrain,
    next_id: u64,
}

impl McpSession {
    pub fn start(root: &Path, no_line_numbers: bool) -> Result<Self, String> {
        let bifrost_binary = bifrost_binary_path()?;
        let mut command = Command::new(&bifrost_binary);
        command
            .arg("--root")
            .arg(root)
            .arg("--server")
            .arg("searchtools");
        if no_line_numbers {
            command.arg("--no-line-numbers");
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| {
                format!(
                    "failed to spawn bifrost MCP server `{}`: {err}",
                    bifrost_binary.display()
                )
            })?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "missing bifrost stdin".to_string())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "missing bifrost stdout".to_string())?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| "missing bifrost stderr".to_string())?;
        let stderr = StderrDrain::spawn(stderr, STDERR_TAIL_CAPACITY_BYTES)?;

        Ok(Self {
            child,
            stdin,
            reader: BufReader::new(stdout),
            stderr,
            next_id: 1,
        })
    }

    pub fn initialize(&mut self) -> Result<(), String> {
        let response = self.request(json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {
                    "name": "bifrost-benchmark",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }
        }))?;
        if response.get("error").is_some() {
            return Err(format!("bifrost initialize failed: {response}"));
        }

        self.notify(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }))
    }

    pub fn call_tool(&mut self, name: &str, arguments: Value) -> Result<Value, String> {
        let id = self.take_id();
        let response = self.request(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments
            }
        }))?;

        if let Some(error) = response.get("error") {
            return Err(format!("bifrost MCP request failed for `{name}`: {error}"));
        }

        let result = response.get("result").cloned().ok_or_else(|| {
            format!("bifrost MCP response missing result for `{name}`: {response}")
        })?;
        if result
            .get("isError")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            let message = result["content"][0]["text"]
                .as_str()
                .unwrap_or("tool returned isError without text");
            return Err(format!("bifrost tool `{name}` failed: {message}"));
        }

        Ok(result)
    }

    pub fn stderr_cursor(&self) -> StderrCursor {
        self.stderr.cursor()
    }

    pub fn stderr_since(&self, cursor: StderrCursor) -> CapturedStderr {
        self.stderr.capture_since(cursor)
    }

    pub fn stderr_tail(&self) -> String {
        self.stderr.tail()
    }

    fn request(&mut self, payload: Value) -> Result<Value, String> {
        self.write_line(&payload)?;
        self.read_line()
    }

    fn notify(&mut self, payload: Value) -> Result<(), String> {
        self.write_line(&payload)
    }

    fn write_line(&mut self, payload: &Value) -> Result<(), String> {
        writeln!(self.stdin, "{payload}")
            .and_then(|_| self.stdin.flush())
            .map_err(|err| format!("failed to write MCP request: {err}"))
    }

    fn read_line(&mut self) -> Result<Value, String> {
        let mut line = String::new();
        let bytes = self
            .reader
            .read_line(&mut line)
            .map_err(|err| format!("failed to read MCP response: {err}"))?;
        if bytes == 0 {
            self.shutdown();
            let stderr = self.stderr.tail();
            return Err(format!(
                "bifrost MCP server closed early; stderr:\n{stderr}"
            ));
        }

        serde_json::from_str(&line)
            .map_err(|err| format!("failed to parse MCP JSON response: {err}; line={line}"))
    }

    fn take_id(&mut self) -> u64 {
        let next = self.next_id;
        self.next_id += 1;
        next
    }

    fn shutdown(&mut self) {
        let _ = self.stdin.flush();
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.stderr.join();
    }
}

impl Drop for McpSession {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn bifrost_binary_path() -> Result<PathBuf, String> {
    if let Some(explicit) = std::env::var_os("BIFROST_BENCHMARK_BIFROST_BIN") {
        return Ok(PathBuf::from(explicit));
    }

    let current = std::env::current_exe()
        .map_err(|err| format!("failed to locate current executable: {err}"))?;
    let binary_name = bifrost_binary_name();
    for candidate in [
        current.parent().map(|dir| dir.join(&binary_name)),
        current
            .parent()
            .and_then(|dir| dir.parent())
            .map(|dir| dir.join(&binary_name)),
    ]
    .into_iter()
    .flatten()
    {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    Err(format!(
        "failed to locate sibling bifrost binary near `{}`; set BIFROST_BENCHMARK_BIFROST_BIN",
        current.display()
    ))
}

fn bifrost_binary_name() -> OsString {
    #[cfg(windows)]
    {
        OsString::from("bifrost.exe")
    }
    #[cfg(not(windows))]
    {
        OsString::from("bifrost")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;

    #[test]
    fn stderr_drain_continuously_consumes_and_keeps_bounded_tail() {
        const CAPACITY: usize = 32 * 1024;
        const LINE_COUNT: usize = 20_000;

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let writer = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            for index in 0..LINE_COUNT {
                writeln!(stream, "timing-line-{index:05}-{}", "x".repeat(96)).unwrap();
            }
            writeln!(stream, "FINAL-DIAGNOSTIC").unwrap();
        });
        let (reader, _) = listener.accept().unwrap();
        let mut drain = StderrDrain::spawn(reader, CAPACITY).unwrap();
        let cursor = drain.cursor();

        writer.join().unwrap();
        drain.join();

        let captured = drain.capture_since(cursor);
        assert!(captured.truncated);
        assert!(captured.text.len() <= CAPACITY);
        assert!(captured.text.contains("FINAL-DIAGNOSTIC"));
        assert!(!captured.text.contains("timing-line-00000"));
    }

    #[test]
    fn stderr_tail_truncates_a_single_oversized_line() {
        let mut tail = StderrTail::new(8);
        let cursor = tail.cursor();
        tail.push(b"0123456789".to_vec());

        let captured = tail.capture_since(cursor);
        assert_eq!(captured.text, "23456789");
        assert!(captured.truncated);
    }

    #[test]
    fn stderr_capture_does_not_report_evicted_pre_cursor_lines_as_truncated() {
        let mut tail = StderrTail::new(8);
        tail.push(b"old\n".to_vec());
        let cursor = tail.cursor();
        tail.push(b"new-one\n".to_vec());

        let captured = tail.capture_since(cursor);
        assert_eq!(captured.text, "new-one\n");
        assert!(!captured.truncated);
    }
}
