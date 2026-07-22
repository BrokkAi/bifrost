use serde_json::{Value, json};
use std::collections::VecDeque;
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::mcp_common::{BENCHMARK_PROFILE_BOUNDARY_MARKER, BENCHMARK_PROFILE_BOUNDARY_METHOD};

const STDERR_TAIL_CAPACITY_BYTES: usize = 256 * 1024;
const STDERR_READ_BUFFER_BYTES: usize = 8 * 1024;
const PROFILE_BOUNDARY_TIMEOUT: Duration = Duration::from_secs(5);
const MCP_RESPONSE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const BENCHMARK_QUERY_ACCESS_ENV: &str = "BIFROST_BENCHMARK_QUERY_CODE_ACCESS";
const SERVER_QUERY_ACCESS_ENV: &str = "BIFROST_QUERY_CODE_ACCESS_MODE";

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
            text: String::from_utf8_lossy(&bytes).replace(BENCHMARK_PROFILE_BOUNDARY_MARKER, ""),
            truncated,
        }
    }
}

struct StderrDrain {
    tail: Arc<Mutex<StderrTail>>,
    boundaries: Arc<(Mutex<BoundaryState>, Condvar)>,
    reader: Option<JoinHandle<()>>,
}

#[derive(Debug, Default)]
struct BoundaryState {
    observed: u64,
    closed: bool,
}

impl StderrDrain {
    fn spawn(reader: impl Read + Send + 'static, capacity: usize) -> Result<Self, String> {
        let tail = Arc::new(Mutex::new(StderrTail::new(capacity)));
        let reader_tail = Arc::clone(&tail);
        let boundaries = Arc::new((Mutex::new(BoundaryState::default()), Condvar::new()));
        let reader_boundaries = Arc::clone(&boundaries);
        let reader = thread::Builder::new()
            .name("bifrost-benchmark-stderr".to_string())
            .spawn(move || drain_stderr(reader, &reader_tail, &reader_boundaries))
            .map_err(|err| format!("failed to start bifrost stderr drain: {err}"))?;
        Ok(Self {
            tail,
            boundaries,
            reader: Some(reader),
        })
    }

    fn cursor(&self) -> StderrCursor {
        self.with_tail(StderrTail::cursor)
    }

    fn capture_since(&self, cursor: StderrCursor) -> CapturedStderr {
        self.with_tail(|tail| tail.capture_since(cursor))
    }

    fn boundary_count(&self) -> u64 {
        self.boundaries
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .observed
    }

    fn wait_for_boundary(&self, previous_count: u64) -> Result<(), String> {
        let (state, changed) = &*self.boundaries;
        let state = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (state, timeout) = changed
            .wait_timeout_while(state, PROFILE_BOUNDARY_TIMEOUT, |state| {
                state.observed <= previous_count && !state.closed
            })
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.observed > previous_count {
            Ok(())
        } else if state.closed {
            Err("bifrost stderr closed before profile boundary was observed".to_string())
        } else if timeout.timed_out() {
            Err(format!(
                "timed out after {}s waiting for bifrost profile boundary",
                PROFILE_BOUNDARY_TIMEOUT.as_secs()
            ))
        } else {
            Err("bifrost profile boundary was not observed".to_string())
        }
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

fn drain_stderr(
    mut reader: impl Read,
    tail: &Mutex<StderrTail>,
    boundaries: &(Mutex<BoundaryState>, Condvar),
) {
    let mut buffer = [0_u8; STDERR_READ_BUFFER_BYTES];
    let mut marker_prefix = Vec::with_capacity(BENCHMARK_PROFILE_BOUNDARY_MARKER.len() - 1);
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => {
                close_boundary_stream(boundaries);
                return;
            }
            Ok(read) => {
                let bytes = &buffer[..read];
                tail.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(bytes.to_vec());
                let observed = count_profile_boundaries(&mut marker_prefix, bytes);
                if observed > 0 {
                    let (state, changed) = boundaries;
                    let mut state = state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    state.observed = state.observed.saturating_add(observed as u64);
                    changed.notify_all();
                }
            }
            Err(err) => {
                tail.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .read_error = Some(err.to_string());
                close_boundary_stream(boundaries);
                return;
            }
        }
    }
}

fn count_profile_boundaries(prefix: &mut Vec<u8>, bytes: &[u8]) -> usize {
    let marker = BENCHMARK_PROFILE_BOUNDARY_MARKER.as_bytes();
    let mut searchable = Vec::with_capacity(prefix.len() + bytes.len());
    searchable.extend_from_slice(prefix);
    searchable.extend_from_slice(bytes);
    let count = searchable
        .windows(marker.len())
        .filter(|window| *window == marker)
        .count();
    let retained = marker.len().saturating_sub(1).min(searchable.len());
    prefix.clear();
    prefix.extend_from_slice(&searchable[searchable.len() - retained..]);
    count
}

fn close_boundary_stream(boundaries: &(Mutex<BoundaryState>, Condvar)) {
    let (state, changed) = boundaries;
    let mut state = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    state.closed = true;
    changed.notify_all();
}

pub struct McpSession {
    child: Child,
    stdin: ChildStdin,
    stdout: StdoutDrain,
    stderr: StderrDrain,
    next_id: u64,
}

struct StdoutDrain {
    responses: Receiver<Result<Value, String>>,
    worker: Option<JoinHandle<()>>,
}

impl StdoutDrain {
    fn spawn(stdout: ChildStdout) -> Result<Self, String> {
        let (sender, responses) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("bifrost-benchmark-stdout".to_string())
            .spawn(move || {
                let mut reader = BufReader::new(stdout);
                loop {
                    let mut line = String::new();
                    match reader.read_line(&mut line) {
                        Ok(0) => {
                            let _ = sender.send(Err("bifrost MCP server closed early".to_string()));
                            break;
                        }
                        Ok(_) => match serde_json::from_str(&line) {
                            Ok(response) => {
                                if sender.send(Ok(response)).is_err() {
                                    break;
                                }
                            }
                            Err(error) => {
                                let _ = sender.send(Err(format!(
                                    "failed to parse MCP JSON response: {error}; line={line}"
                                )));
                                break;
                            }
                        },
                        Err(error) => {
                            let _ =
                                sender.send(Err(format!("failed to read MCP response: {error}")));
                            break;
                        }
                    }
                }
            })
            .map_err(|error| format!("failed to spawn MCP stdout reader: {error}"))?;
        Ok(Self {
            responses,
            worker: Some(worker),
        })
    }

    fn receive(&self, timeout: Duration) -> Result<Value, String> {
        receive_response(&self.responses, timeout)
    }

    fn join(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn receive_response(
    responses: &Receiver<Result<Value, String>>,
    timeout: Duration,
) -> Result<Value, String> {
    match responses.recv_timeout(timeout) {
        Ok(response) => response,
        Err(RecvTimeoutError::Timeout) => Err(format!(
            "timed out after {}s waiting for bifrost MCP response",
            timeout.as_secs_f64()
        )),
        Err(RecvTimeoutError::Disconnected) => {
            Err("bifrost MCP stdout reader stopped early".to_string())
        }
    }
}

impl McpSession {
    pub fn start(root: &Path, no_line_numbers: bool, profile: bool) -> Result<Self, String> {
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
        if profile {
            command.env("BIFROST_TIMING", "1");
        }
        // The server selector is an internal transport detail. Never inherit
        // an ambient value into a benchmark process; only the validated
        // benchmark-facing selector below may set it.
        command.env_remove(SERVER_QUERY_ACCESS_ENV);
        if let Some(access_mode) = std::env::var_os(BENCHMARK_QUERY_ACCESS_ENV) {
            command.env(SERVER_QUERY_ACCESS_ENV, access_mode);
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

        let pipes = (|| {
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
            Ok::<_, String>((stdin, stdout, stderr))
        })();
        let (stdin, stdout, stderr) = match pipes {
            Ok(pipes) => pipes,
            Err(err) => {
                terminate_child(&mut child);
                return Err(err);
            }
        };
        let mut stdout = match StdoutDrain::spawn(stdout) {
            Ok(stdout) => stdout,
            Err(err) => {
                terminate_child(&mut child);
                return Err(err);
            }
        };
        let stderr = match StderrDrain::spawn(stderr, STDERR_TAIL_CAPACITY_BYTES) {
            Ok(stderr) => stderr,
            Err(err) => {
                terminate_child(&mut child);
                stdout.join();
                return Err(err);
            }
        };

        Ok(Self {
            child,
            stdin,
            stdout,
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

    pub fn stderr_tail(&self) -> CapturedStderr {
        self.stderr.capture_since(StderrCursor { next_sequence: 0 })
    }

    pub fn profile_boundary(&mut self) -> Result<(), String> {
        let previous_count = self.stderr.boundary_count();
        let id = self.take_id();
        let response = self.request(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": BENCHMARK_PROFILE_BOUNDARY_METHOD,
            "params": {}
        }))?;
        if let Some(error) = response.get("error") {
            return Err(format!("bifrost profile boundary failed: {error}"));
        }
        self.stderr.wait_for_boundary(previous_count)
    }

    pub fn shutdown_and_stderr_tail(&mut self) -> CapturedStderr {
        self.shutdown();
        self.stderr_tail()
    }

    fn request(&mut self, payload: Value) -> Result<Value, String> {
        self.write_line(&payload)?;
        match self.stdout.receive(MCP_RESPONSE_TIMEOUT) {
            Ok(response) => Ok(response),
            Err(error) => {
                self.shutdown();
                Err(error)
            }
        }
    }

    fn notify(&mut self, payload: Value) -> Result<(), String> {
        self.write_line(&payload)
    }

    fn write_line(&mut self, payload: &Value) -> Result<(), String> {
        writeln!(self.stdin, "{payload}")
            .and_then(|_| self.stdin.flush())
            .map_err(|err| format!("failed to write MCP request: {err}"))
    }

    fn take_id(&mut self) -> u64 {
        let next = self.next_id;
        self.next_id += 1;
        next
    }

    fn shutdown(&mut self) {
        let _ = self.stdin.flush();
        terminate_child(&mut self.child);
        self.stdout.join();
        self.stderr.join();
    }
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
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
    fn stderr_drain_bounds_an_unterminated_stream() {
        const CAPACITY: usize = 16 * 1024;
        const STREAM_BYTES: usize = 2 * 1024 * 1024;

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let writer = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream.write_all(&vec![b'x'; STREAM_BYTES]).unwrap();
            stream.write_all(b"FINAL-DIAGNOSTIC").unwrap();
        });
        let (reader, _) = listener.accept().unwrap();
        let mut drain = StderrDrain::spawn(reader, CAPACITY).unwrap();
        let cursor = drain.cursor();

        writer.join().unwrap();
        drain.join();

        let captured = drain.capture_since(cursor);
        assert!(captured.truncated);
        assert!(captured.text.len() <= CAPACITY);
        assert!(captured.text.ends_with("FINAL-DIAGNOSTIC"));
    }

    #[test]
    fn stderr_boundary_waits_for_delayed_marker_consumption() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let writer = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            thread::sleep(Duration::from_millis(50));
            stream.write_all(b"timing-before-boundary\n").unwrap();
            stream
                .write_all(BENCHMARK_PROFILE_BOUNDARY_MARKER.as_bytes())
                .unwrap();
        });
        let (reader, _) = listener.accept().unwrap();
        let mut drain = StderrDrain::spawn(reader, STDERR_TAIL_CAPACITY_BYTES).unwrap();
        let cursor = drain.cursor();
        let previous_count = drain.boundary_count();

        drain.wait_for_boundary(previous_count).unwrap();
        let captured = drain.capture_since(cursor);
        assert_eq!(captured.text, "timing-before-boundary\n");

        writer.join().unwrap();
        drain.join();
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

    #[test]
    fn stdout_response_wait_has_a_hard_timeout() {
        let (_sender, responses) = mpsc::channel();

        let error = receive_response(&responses, Duration::from_millis(1))
            .expect_err("silent child must time out");

        assert!(error.contains("timed out"), "{error}");
    }
}
