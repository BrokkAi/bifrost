use serde_json::{Value, json};
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use brokk_bifrost_mcp::benchmark_api::{
    BENCHMARK_MCP_REQUEST_BUDGET_SECS, BENCHMARK_PROFILE_BOUNDARY_MARKER,
    BENCHMARK_PROFILE_BOUNDARY_METHOD, MCP_ANALYZER_REQUEST_BUDGET_SECS_ENV, MCP_FILE_WATCHER_ENV,
};

const STDERR_TAIL_CAPACITY_BYTES: usize = 256 * 1024;
const STDERR_READ_BUFFER_BYTES: usize = 8 * 1024;
const TRANSPORT_TIMING_LINE_MAX_BYTES: usize = 16 * 1024;
const RETAINED_TRANSPORT_TIMING_LINES: usize = 1024;
const PROFILE_BOUNDARY_TIMEOUT: Duration = Duration::from_secs(5);
const MCP_RESPONSE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const MAX_BUFFERED_MCP_RESPONSES: usize = 16;
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
    pub transport_timings: Vec<String>,
}

#[derive(Debug)]
struct StderrChunk {
    sequence: u64,
    bytes: Vec<u8>,
    prefix_truncated: bool,
}

#[derive(Debug)]
struct RetainedTransportTiming {
    start_sequence: u64,
    line: String,
}

#[derive(Debug)]
struct StderrTail {
    chunks: VecDeque<StderrChunk>,
    bytes: usize,
    capacity: usize,
    next_sequence: u64,
    read_error: Option<String>,
    transport_timings: VecDeque<RetainedTransportTiming>,
    transport_line: Vec<u8>,
    transport_line_start_sequence: Option<u64>,
    transport_line_overflowed: bool,
}

impl StderrTail {
    fn new(capacity: usize) -> Self {
        Self {
            chunks: VecDeque::new(),
            bytes: 0,
            capacity,
            next_sequence: 0,
            read_error: None,
            transport_timings: VecDeque::new(),
            transport_line: Vec::new(),
            transport_line_start_sequence: None,
            transport_line_overflowed: false,
        }
    }

    fn push(&mut self, mut bytes: Vec<u8>) {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.retain_transport_timings(sequence, &bytes);
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

    fn retain_transport_timings(&mut self, sequence: u64, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let newline = bytes.iter().position(|byte| *byte == b'\n');
            let segment_end = newline.unwrap_or(bytes.len());
            let segment = &bytes[..segment_end];
            if self.transport_line_start_sequence.is_none() {
                self.transport_line_start_sequence = Some(sequence);
            }
            if !self.transport_line_overflowed {
                let remaining =
                    TRANSPORT_TIMING_LINE_MAX_BYTES.saturating_sub(self.transport_line.len());
                if segment.len() <= remaining {
                    self.transport_line.extend_from_slice(segment);
                } else {
                    self.transport_line.clear();
                    self.transport_line_overflowed = true;
                }
            }

            let Some(newline) = newline else {
                return;
            };
            if !self.transport_line_overflowed && is_transport_timing_line(&self.transport_line) {
                let start_sequence = self
                    .transport_line_start_sequence
                    .expect("a completed stderr line has a start sequence");
                self.transport_timings.push_back(RetainedTransportTiming {
                    start_sequence,
                    line: String::from_utf8_lossy(&self.transport_line).into_owned(),
                });
                while self.transport_timings.len() > RETAINED_TRANSPORT_TIMING_LINES {
                    self.transport_timings.pop_front();
                }
            }
            self.transport_line.clear();
            self.transport_line_start_sequence = None;
            self.transport_line_overflowed = false;
            bytes = &bytes[newline + 1..];
        }
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
            transport_timings: self
                .transport_timings
                .iter()
                .filter(|timing| timing.start_sequence >= cursor.next_sequence)
                .map(|timing| timing.line.clone())
                .collect(),
        }
    }
}

fn is_transport_timing_line(line: &[u8]) -> bool {
    const TIMING_PREFIX: &[u8] = b"[bifrost-timing]";
    const DURATION_SUFFIX: &[u8] = b" ms)";
    const PHASE_MARKERS: [&[u8]; 4] = [
        b"mcp_request.queue_wait[",
        b"mcp_request.execution[",
        b"mcp_request.response_queue_wait[",
        b"mcp_request.writer_delivery[",
    ];

    contains_bytes(line, TIMING_PREFIX)
        && contains_bytes(line, DURATION_SUFFIX)
        && PHASE_MARKERS
            .iter()
            .any(|marker| contains_bytes(line, marker))
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

struct StderrDrain {
    tail: Arc<Mutex<StderrTail>>,
    boundaries: Arc<(Mutex<BoundaryState>, Condvar)>,
    reader: Option<JoinHandle<()>>,
}

#[derive(Debug, Default)]
struct BoundaryState {
    observed: u64,
    activity: u64,
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

    fn wait_for_text_since(
        &self,
        cursor: StderrCursor,
        needle: &str,
        timeout: Duration,
    ) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.capture_since(cursor).text.contains(needle) {
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(format!(
                    "timed out waiting for MCP stderr marker `{needle}`"
                ));
            }
            let (state, changed) = &*self.boundaries;
            let state = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let previous_activity = state.activity;
            let (state, wait) = changed
                .wait_timeout_while(state, remaining, |state| {
                    state.activity == previous_activity && !state.closed
                })
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.closed && !self.capture_since(cursor).text.contains(needle) {
                return Err(format!(
                    "MCP stderr closed before marker `{needle}` was observed"
                ));
            }
            if wait.timed_out() {
                return Err(format!(
                    "timed out waiting for MCP stderr marker `{needle}`"
                ));
            }
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
                let (state, changed) = boundaries;
                let mut state = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.activity = state.activity.saturating_add(1);
                if observed > 0 {
                    state.observed = state.observed.saturating_add(observed as u64);
                }
                changed.notify_all();
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
    buffered_responses: HashMap<String, Value>,
    pending_tools: HashMap<u64, String>,
    abandoned_responses: HashSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct McpRequestId(u64);

impl McpRequestId {
    pub fn get(self) -> u64 {
        self.0
    }
}

struct StdoutDrain {
    responses: Receiver<Result<Value, String>>,
    worker: Option<JoinHandle<()>>,
}

impl StdoutDrain {
    fn spawn(stdout: ChildStdout) -> Result<Self, String> {
        let (sender, responses) = mpsc::sync_channel(MAX_BUFFERED_MCP_RESPONSES);
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

fn receive_response_for_id(
    responses: &Receiver<Result<Value, String>>,
    buffered: &mut HashMap<String, Value>,
    pending_tools: &HashMap<u64, String>,
    abandoned_responses: &mut HashSet<String>,
    id: &Value,
    timeout: Duration,
) -> Result<Value, String> {
    let requested_key = response_id_key(id)?;
    if let Some(response) = buffered.remove(&requested_key) {
        return Ok(response);
    }

    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(format!(
                "timed out after {}s waiting for bifrost MCP response id {id}",
                timeout.as_secs_f64()
            ));
        }
        let response = receive_response(responses, remaining)?;
        let response_id = response
            .get("id")
            .ok_or_else(|| format!("bifrost MCP response is missing id: {response}"))?;
        let response_key = response_id_key(response_id)?;
        if response_key == requested_key {
            return Ok(response);
        }
        if abandoned_responses.remove(&response_key) {
            continue;
        }
        let known_pending_id = response_id
            .as_u64()
            .is_some_and(|id| pending_tools.contains_key(&id));
        if !known_pending_id {
            return Err(format!(
                "bifrost MCP server returned unexpected response id {response_id}"
            ));
        }
        if buffered.len() >= pending_tools.len().min(MAX_BUFFERED_MCP_RESPONSES) {
            return Err(format!(
                "bifrost MCP response buffer exceeded its {}-response bound",
                MAX_BUFFERED_MCP_RESPONSES
            ));
        }
        if buffered.insert(response_key, response).is_some() {
            return Err("bifrost MCP server returned a duplicate response id".to_string());
        }
    }
}

fn response_id_key(id: &Value) -> Result<String, String> {
    if !id.is_string() && !id.is_number() && !id.is_null() {
        return Err(format!("invalid JSON-RPC response id: {id}"));
    }
    serde_json::to_string(id).map_err(|error| format!("failed to encode response id: {error}"))
}

fn abandon_response(
    buffered: &mut HashMap<String, Value>,
    abandoned: &mut HashSet<String>,
    response_key: &str,
) {
    if buffered.remove(response_key).is_none() {
        abandoned.insert(response_key.to_string());
    }
}

impl McpSession {
    pub fn start(root: &Path, no_line_numbers: bool, profile: bool) -> Result<Self, String> {
        Self::start_with_query_access(root, no_line_numbers, profile, None)
    }

    pub(super) fn start_scan_only(
        root: &Path,
        no_line_numbers: bool,
        profile: bool,
    ) -> Result<Self, String> {
        Self::start_with_query_access(root, no_line_numbers, profile, Some("scan_only"))
    }

    fn start_with_query_access(
        root: &Path,
        no_line_numbers: bool,
        profile: bool,
        query_access: Option<&str>,
    ) -> Result<Self, String> {
        let bifrost_binary = bifrost_binary_path()?;
        let mut command = Command::new(&bifrost_binary);
        command
            .arg("--root")
            .arg(root)
            .arg("--server")
            .arg("searchtools");
        // Pinned benchmark checkouts are immutable for the lifetime of a run.
        // Watching them lets delayed VCS/cache events invalidate analyzer caches
        // between samples and measures rebuild jitter rather than warm queries.
        command
            .env(MCP_FILE_WATCHER_ENV, "off")
            // The compatibility harness and its explicit prewarm must be able
            // to observe complete results. Interactive cases still enforce
            // their own five-second p95 budget in the runner.
            .env(
                MCP_ANALYZER_REQUEST_BUDGET_SECS_ENV,
                BENCHMARK_MCP_REQUEST_BUDGET_SECS.to_string(),
            );
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
        if let Some(access_mode) = query_access {
            command.env(SERVER_QUERY_ACCESS_ENV, access_mode);
        } else if let Some(access_mode) = std::env::var_os(BENCHMARK_QUERY_ACCESS_ENV) {
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
            buffered_responses: HashMap::new(),
            pending_tools: HashMap::new(),
            abandoned_responses: HashSet::new(),
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
        validate_server_build_identity(&response)?;

        self.notify(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }))
    }

    pub fn call_tool(&mut self, name: &str, arguments: Value) -> Result<Value, String> {
        let id = self.send_tool_call(name, arguments)?;
        self.receive_tool_response(id)
    }

    pub fn send_tool_call(&mut self, name: &str, arguments: Value) -> Result<McpRequestId, String> {
        let id = McpRequestId(self.take_id());
        self.write_line(&json!({
            "jsonrpc": "2.0",
            "id": id.get(),
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments
            }
        }))?;
        self.pending_tools.insert(id.get(), name.to_string());
        Ok(id)
    }

    pub fn cancel_and_abandon_request(&mut self, id: McpRequestId) -> Result<(), String> {
        let id_value = json!(id.get());
        let response_key = response_id_key(&id_value)?;
        self.pending_tools
            .remove(&id.get())
            .ok_or_else(|| format!("no pending MCP tool request with id {}", id.get()))?;
        abandon_response(
            &mut self.buffered_responses,
            &mut self.abandoned_responses,
            &response_key,
        );
        if let Err(error) = self.notify(json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": { "requestId": id.get() }
        })) {
            self.shutdown();
            return Err(error);
        }
        Ok(())
    }

    pub fn receive_tool_response(&mut self, id: McpRequestId) -> Result<Value, String> {
        self.receive_tool_response_with_timeout(id, MCP_RESPONSE_TIMEOUT)
    }

    pub fn receive_tool_response_with_timeout(
        &mut self,
        id: McpRequestId,
        timeout: Duration,
    ) -> Result<Value, String> {
        let name = self
            .pending_tools
            .get(&id.get())
            .cloned()
            .ok_or_else(|| format!("no pending MCP tool request with id {}", id.get()))?;
        let response = self.receive_response_for_id_with_timeout(&json!(id.get()), timeout)?;
        self.pending_tools.remove(&id.get());

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

    pub fn wait_for_stderr_marker(
        &self,
        cursor: StderrCursor,
        marker: &str,
        timeout: Duration,
    ) -> Result<(), String> {
        self.stderr.wait_for_text_since(cursor, marker, timeout)
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
        let id = payload
            .get("id")
            .cloned()
            .ok_or_else(|| "MCP request payload is missing id".to_string())?;
        self.write_line(&payload)?;
        self.receive_response_for_id(&id)
    }

    fn receive_response_for_id(&mut self, id: &Value) -> Result<Value, String> {
        self.receive_response_for_id_with_timeout(id, MCP_RESPONSE_TIMEOUT)
    }

    fn receive_response_for_id_with_timeout(
        &mut self,
        id: &Value,
        timeout: Duration,
    ) -> Result<Value, String> {
        match receive_response_for_id(
            &self.stdout.responses,
            &mut self.buffered_responses,
            &self.pending_tools,
            &mut self.abandoned_responses,
            id,
            timeout,
        ) {
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

fn validate_server_build_identity(response: &Value) -> Result<(), String> {
    // RMCP publishes the identity in the initialize result's `_meta`, because
    // rmcp's `serverInfo` is a closed struct with no room for a vendor field.
    let server_identity = response
        .pointer("/result/_meta/io.bifrost~1build-identity")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            "bifrost MCP initialize response omitted its build identity; rebuild the server binary"
                .to_string()
        })?;
    if server_identity != crate::BIFROST_BUILD_IDENTITY {
        return Err(format!(
            "bifrost MCP server build identity `{server_identity}` does not match benchmark harness `{}`; rebuild both bifrost and bifrost_benchmark",
            crate::BIFROST_BUILD_IDENTITY
        ));
    }
    Ok(())
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
    use std::io::Cursor;
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;

    struct DelayedReader {
        cursor: Cursor<Vec<u8>>,
        delay: Option<Duration>,
    }

    impl Read for DelayedReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if let Some(delay) = self.delay.take() {
                thread::sleep(delay);
            }
            self.cursor.read(buffer)
        }
    }

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
    fn issue_1631_transport_timings_survive_raw_tail_truncation() {
        let mut tail = StderrTail::new(160);
        let cursor = tail.cursor();
        tail.push(b"[bifrost-timing] DURATION mcp_request.queue_wa".to_vec());
        tail.push(b"it[scan_usages_by_location] (0.0 ms)\n".to_vec());
        tail.push(b"[bifrost-timing] DURATION sql_definition_candidates (1.0 ms)\n".to_vec());
        tail.push(vec![b'x'; 1024]);
        tail.push(b"\n".to_vec());
        tail.push(
            b"[bifrost-timing] END mcp_request.execution[scan_usages_by_location] (3001.0 ms)\n"
                .to_vec(),
        );
        tail.push(
            b"[bifrost-timing] DURATION mcp_request.response_queue_wait[scan_usages_by_location] (0.1 ms)\n"
                .to_vec(),
        );
        tail.push(
            b"[bifrost-timing] END mcp_request.writer_delivery[scan_usages_by_location] (0.2 ms)\n"
                .to_vec(),
        );

        let captured = tail.capture_since(cursor);
        assert!(captured.truncated);
        assert!(!captured.text.contains("queue_wait"));
        assert_eq!(captured.transport_timings.len(), 4);
        assert!(captured.transport_timings[0].contains("queue_wait"));
        assert!(captured.transport_timings[1].contains("execution"));
        assert!(captured.transport_timings[2].contains("response_queue_wait"));
        assert!(captured.transport_timings[3].contains("writer_delivery"));
    }

    #[test]
    fn transport_timing_capture_respects_the_request_cursor() {
        let mut tail = StderrTail::new(1024);
        tail.push(b"[bifrost-timing] DURATION mcp_request.queue_wait[old] (0.0 ms)\n".to_vec());
        let cursor = tail.cursor();
        tail.push(b"[bifrost-timing] END mcp_request.execution[current] (1.0 ms)\n".to_vec());

        let captured = tail.capture_since(cursor);
        assert_eq!(captured.transport_timings.len(), 1);
        assert!(captured.transport_timings[0].contains("execution[current]"));
    }

    #[test]
    fn transport_timing_capture_bounds_an_unterminated_line() {
        let mut tail = StderrTail::new(16);
        let cursor = tail.cursor();
        tail.push(vec![b'x'; TRANSPORT_TIMING_LINE_MAX_BYTES + 1]);

        assert!(tail.transport_line.is_empty());
        assert!(tail.transport_line_overflowed);

        tail.push(b"\n".to_vec());
        tail.push(b"[bifrost-timing] DURATION mcp_request.queue_wait[current] (0.0 ms)\n".to_vec());

        let captured = tail.capture_since(cursor);
        assert_eq!(captured.transport_timings.len(), 1);
        assert!(captured.transport_timings[0].contains("queue_wait[current]"));
    }

    #[test]
    fn transport_timing_capture_keeps_a_bounded_line_record() {
        let mut tail = StderrTail::new(0);
        let cursor = tail.cursor();
        for index in 0..=RETAINED_TRANSPORT_TIMING_LINES {
            tail.push(
                format!(
                    "[bifrost-timing] DURATION mcp_request.queue_wait[tool-{index}] (0.0 ms)\n"
                )
                .into_bytes(),
            );
        }

        let captured = tail.capture_since(cursor);
        assert_eq!(
            captured.transport_timings.len(),
            RETAINED_TRANSPORT_TIMING_LINES
        );
        assert!(captured.transport_timings[0].contains("queue_wait[tool-1]"));
        let last_tool = format!("queue_wait[tool-{RETAINED_TRANSPORT_TIMING_LINES}]");
        assert!(
            captured
                .transport_timings
                .last()
                .is_some_and(|line| line.contains(&last_tool))
        );
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
    fn issue_1228_stderr_marker_wait_proves_backend_entry() {
        let reader = DelayedReader {
            cursor: Cursor::new(
                b"[bifrost-timing] BEGIN searchtools.scan_usages_backend\n".to_vec(),
            ),
            delay: Some(Duration::from_millis(20)),
        };
        let mut drain = StderrDrain::spawn(reader, STDERR_TAIL_CAPACITY_BYTES).unwrap();
        let cursor = drain.cursor();

        drain
            .wait_for_text_since(
                cursor,
                "BEGIN searchtools.scan_usages_backend",
                Duration::from_secs(1),
            )
            .unwrap();
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

    #[test]
    fn issue_1228_response_router_matches_out_of_order_request_ids() {
        let (sender, responses) = mpsc::channel();
        sender
            .send(Ok(json!({"jsonrpc": "2.0", "id": 2, "result": "light"})))
            .unwrap();
        sender
            .send(Ok(json!({"jsonrpc": "2.0", "id": 1, "result": "heavy"})))
            .unwrap();
        let mut buffered = HashMap::new();
        let mut abandoned = HashSet::new();
        let pending_tools = HashMap::from([(1, "heavy".to_string()), (2, "light".to_string())]);

        let heavy = receive_response_for_id(
            &responses,
            &mut buffered,
            &pending_tools,
            &mut abandoned,
            &json!(1),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(heavy["result"], "heavy");
        assert_eq!(buffered.len(), 1);

        let light = receive_response_for_id(
            &responses,
            &mut buffered,
            &pending_tools,
            &mut abandoned,
            &json!(2),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(light["result"], "light");
        assert!(buffered.is_empty());
    }

    #[test]
    fn issue_1228_response_router_rejects_unknown_ids_instead_of_buffering_them() {
        let (sender, responses) = mpsc::channel();
        sender
            .send(Ok(json!({"jsonrpc": "2.0", "id": 999, "result": {}})))
            .unwrap();
        let mut buffered = HashMap::new();
        let mut abandoned = HashSet::new();
        let pending_tools = HashMap::from([(1, "expected".to_string())]);

        let error = receive_response_for_id(
            &responses,
            &mut buffered,
            &pending_tools,
            &mut abandoned,
            &json!(1),
            Duration::from_secs(1),
        )
        .expect_err("unknown response id must fail closed");

        assert!(error.contains("unexpected response id 999"), "{error}");
        assert!(buffered.is_empty());
    }

    #[test]
    fn issue_1435_response_router_discards_abandoned_cancellation_responses() {
        let (sender, responses) = mpsc::channel();
        sender
            .send(Ok(
                json!({"jsonrpc": "2.0", "id": 1, "result": "cancelled"}),
            ))
            .unwrap();
        sender
            .send(Ok(json!({"jsonrpc": "2.0", "id": 2, "result": "light"})))
            .unwrap();
        let mut buffered = HashMap::new();
        let mut abandoned = HashSet::from([response_id_key(&json!(1)).unwrap()]);
        let pending_tools = HashMap::from([(2, "light".to_string())]);

        let light = receive_response_for_id(
            &responses,
            &mut buffered,
            &pending_tools,
            &mut abandoned,
            &json!(2),
            Duration::from_secs(1),
        )
        .unwrap();

        assert_eq!(light["result"], "light");
        assert!(buffered.is_empty());
        assert!(abandoned.is_empty());
    }

    #[test]
    fn issue_1435_abandonment_removes_an_already_buffered_response() {
        let response_key = response_id_key(&json!(1)).unwrap();
        let mut buffered = HashMap::from([(
            response_key.clone(),
            json!({"jsonrpc": "2.0", "id": 1, "result": "cancelled"}),
        )]);
        let mut abandoned = HashSet::new();

        abandon_response(&mut buffered, &mut abandoned, &response_key);
        assert!(buffered.is_empty());
        assert!(abandoned.is_empty());
    }

    #[test]
    fn initialize_build_identity_rejects_missing_and_stale_servers() {
        let missing = json!({"result": {"serverInfo": {}}});
        let error = validate_server_build_identity(&missing)
            .expect_err("missing identity must be rejected");
        assert!(error.contains("omitted its build identity"), "{error}");

        let meta_location = json!({
            "result": {
                "serverInfo": {"name": "bifrost"},
                "_meta": {"io.bifrost/build-identity": crate::BIFROST_BUILD_IDENTITY}
            }
        });
        validate_server_build_identity(&meta_location)
            .expect("matching server identity reported through _meta");

        // A stale identity in the new location must be caught too, or the
        // benchmark would silently measure whatever binary happened to be on
        // disk.
        let stale_meta = json!({
            "result": {
                "serverInfo": {"name": "bifrost"},
                "_meta": {"io.bifrost/build-identity": "stale-binary"}
            }
        });
        let error = validate_server_build_identity(&stale_meta)
            .expect_err("stale server must be rejected through _meta too");
        assert!(error.contains("stale-binary"), "{error}");
    }
}
