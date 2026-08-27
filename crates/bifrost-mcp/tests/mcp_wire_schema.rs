//! Official MCP wire-schema conformance for the real stdio server.
//!
//! Milestone 2 of `.agents/plans/issue-2319-mcp-conformance.md`. Each test
//! spawns the real Bifrost MCP stdio binary, records every JSON-RPC message
//! that crosses the pipe in both directions, and validates the whole
//! transcript against the official MCP spec JSON schema checked in under
//! `tests/conformance/schemas/` for the revision that session negotiated.
//!
//! The routing algorithm is the official conformance runner's, derived from
//! the schema's own definition map rather than a hand-maintained method list:
//! a message carrying a `method` is judged by the definition whose
//! `properties.method.const` matches, a response by `<Stem>Result` for the
//! method of the request it answers, an error by the definition whose
//! `properties.error.allOf` pins its code. Client-sent messages are validated
//! too: this test authors them, so a violation there is a bug in this test.

// `tests/common/mod.rs` is shared with the hand-authored suite and re-exports
// more than this binary uses.
#[allow(unused_imports)]
mod common;

use brokk_bifrost_analysis::Language;
use common::InlineTestProject;
use jsonschema::Validator;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// The stateful revision: negotiated by an `initialize` handshake.
const LEGACY_REVISION: &str = "2025-11-25";
/// The stateless revision: `server/discover` plus per-request `_meta`.
const STATELESS_REVISION: &str = "2026-07-28";
const AGENTS_GUIDANCE_URI: &str = "bifrost://agent-guidance/agents.md";

// This crate's published suite owns its fixtures. Reaching into the private
// root `tests/fixtures/` tree would make the projected public tree fail to
// compile, so the dynamic-eval sample is checked in beside these tests.
const MCP_POLICY_APP: &str = include_str!("fixtures/policy-cli/app.py");
const MCP_DYNAMIC_EVAL_POLICY: &str = include_str!("fixtures/policy-cli/dynamic-eval.rqlp");

/// A stateful `2025-11-25` session over the server's whole advertised surface:
/// handshake, tool discovery, the resource pair, a successful call, a
/// protocol-level error, and a progress-reporting call.
#[test]
fn legacy_2025_11_25_stateful_session_emits_schema_valid_wire() {
    let workspace = InlineTestProject::new()
        .file("Alpha.java", "class Alpha { void run() {} }\n")
        .file(
            "Beta.java",
            "class Beta { void call(Alpha alpha) { alpha.run(); } }\n",
        )
        .build();
    let mut session = WireSession::rooted(LEGACY_REVISION, workspace.root());
    let initialize = session.initialize(1, json!({}));
    assert_eq!(
        initialize["result"]["protocolVersion"], LEGACY_REVISION,
        "{initialize}"
    );

    let tools = session.round_trip(json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}
    }));
    assert!(
        tools["result"]["tools"]
            .as_array()
            .is_some_and(|tools| !tools.is_empty()),
        "{tools}"
    );

    let resources = session.round_trip(json!({
        "jsonrpc": "2.0", "id": 3, "method": "resources/list", "params": {}
    }));
    assert_eq!(
        resources["result"]["resources"][0]["uri"], AGENTS_GUIDANCE_URI,
        "{resources}"
    );
    let resource = session.round_trip(json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "resources/read",
        "params": { "uri": AGENTS_GUIDANCE_URI }
    }));
    assert!(
        resource["result"]["contents"][0]["text"].is_string(),
        "{resource}"
    );

    let call = session.round_trip(search_symbols_call(5, "Alpha"));
    assert_eq!(call["result"]["isError"], false, "{call}");

    // Arguments the tool schema rejects are a protocol-level error response,
    // not a tool result, so this covers the error arm of the wire.
    let invalid = session.round_trip(json!({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": { "name": "search_symbols", "arguments": {} }
    }));
    assert_eq!(invalid["error"]["code"], -32602, "{invalid}");

    // A progressToken puts server-initiated notifications on the wire ahead of
    // the response, which is the only interleaving this transport permits.
    session.send(json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "search_symbols",
            "arguments": { "patterns": ["Beta"] },
            "_meta": { "progressToken": "wire-schema-progress" }
        }
    }));
    let (response, progress) = session.read_response_collecting_progress(7);
    assert_eq!(response["result"]["isError"], false, "{response}");
    assert!(
        !progress.is_empty(),
        "a progressToken must produce progress notifications: {response}"
    );

    session.finish();
}

/// A rootless `2025-11-25` session where the server asks the client for its
/// workspace: the transcript therefore contains a server-initiated request and
/// a client-sent response, both judged by the same schema.
#[test]
fn legacy_roots_binding_session_emits_schema_valid_wire() {
    let plugin_dir = TempDir::new().expect("plugin dir");
    fs::write(
        plugin_dir.path().join("PluginOnly.java"),
        "class PluginOnly {}\n",
    )
    .expect("write plugin fixture");
    let workspace = InlineTestProject::new()
        .file("RootsWorkspace.java", "class RootsWorkspace {}\n")
        .build();

    let mut session = WireSession::rootless(LEGACY_REVISION, plugin_dir.path());
    session.initialize(1, json!({ "roots": { "listChanged": true } }));
    let bound = session.call_answering_roots(
        search_symbols_call(2, "RootsWorkspace"),
        json!({ "roots": [{ "uri": directory_uri(workspace.root()), "name": "workspace" }] }),
    );
    assert_eq!(bound["result"]["isError"], false, "{bound}");
    assert!(bound.to_string().contains("RootsWorkspace"), "{bound}");

    session.finish();
}

/// Discovery before any handshake, then stateless calls that negotiate through
/// their own `_meta`: the `2026-07-28` lifecycle end to end, including a
/// request the server refuses.
#[test]
fn discovery_2026_07_28_and_stateless_calls_emit_schema_valid_wire() {
    let workspace = InlineTestProject::new()
        .file("Stateless.java", "class Stateless {}\n")
        .build();
    let mut session = WireSession::rooted(STATELESS_REVISION, workspace.root());

    let discover = session.round_trip(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "server/discover",
        "params": { "_meta": stateless_meta() }
    }));
    assert!(
        discover["result"]["supportedVersions"]
            .as_array()
            .is_some_and(|versions| versions.iter().any(|version| version == STATELESS_REVISION)),
        "{discover}"
    );

    let tools = session.round_trip(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": { "_meta": stateless_meta() }
    }));
    assert_eq!(tools["result"]["resultType"], "complete", "{tools}");

    let call = session.round_trip(stateless_search_symbols_call(3, "Stateless"));
    assert_eq!(call["result"]["resultType"], "complete", "{call}");
    assert_eq!(call["result"]["isError"], false, "{call}");

    // Every stateless request is negotiated on its own, so a version the
    // server does not speak is refused per request rather than per session.
    let mut unsupported = stateless_search_symbols_call(4, "Stateless");
    unsupported["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!("2099-01-01");
    let refused = session.round_trip(unsupported);
    assert!(
        refused["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("Unsupported protocol version")),
        "{refused}"
    );

    session.finish();
}

/// The MRTR roots binding flow on `2026-07-28`: an unbound stateless call is
/// answered with an `input_required` result carrying a `roots/list` input
/// request, and the retry that answers it completes.
#[test]
fn mrtr_roots_2026_07_28_session_emits_schema_valid_wire() {
    let plugin_dir = TempDir::new().expect("plugin dir");
    fs::write(
        plugin_dir.path().join("PluginOnly.java"),
        "class PluginOnly {}\n",
    )
    .expect("write plugin fixture");
    let workspace = InlineTestProject::new()
        .file("MrtrWorkspace.java", "class MrtrWorkspace {}\n")
        .build();

    let mut session = WireSession::rootless(STATELESS_REVISION, plugin_dir.path());
    session.round_trip(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "server/discover",
        "params": { "_meta": stateless_meta() }
    }));

    let activation = session.round_trip(stateless_search_symbols_call(2, "MrtrWorkspace"));
    assert_eq!(
        activation["result"]["resultType"], "input_required",
        "{activation}"
    );
    assert_eq!(
        activation["result"]["inputRequests"]["roots"]["method"], "roots/list",
        "{activation}"
    );
    let request_state = activation["result"]["requestState"]
        .as_str()
        .unwrap_or_else(|| panic!("an activation must carry a requestState: {activation}"));

    let mut retry = stateless_search_symbols_call(3, "MrtrWorkspace");
    retry["params"]["requestState"] = json!(request_state);
    retry["params"]["inputResponses"] =
        json!({ "roots": { "roots": [{ "uri": directory_uri(workspace.root()) }] } });
    let bound = session.round_trip(retry);
    assert_eq!(bound["result"]["resultType"], "complete", "{bound}");
    assert_eq!(bound["result"]["isError"], false, "{bound}");
    assert!(bound.to_string().contains("MrtrWorkspace"), "{bound}");

    session.finish();
}

/// The cache hints `2026-07-28` added -- `resultType`, `ttlMs`, `cacheScope`
/// -- are required members of that revision's list and read results, so a
/// session that carries them is exactly a session the schema accepts.
#[test]
fn cache_hints_2026_07_28_session_emits_schema_valid_wire() {
    let workspace = InlineTestProject::new()
        .file("Cacheable.java", "class Cacheable {}\n")
        .build();
    let mut session = WireSession::rooted(STATELESS_REVISION, workspace.root());
    session.round_trip(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "server/discover",
        "params": { "_meta": stateless_meta() }
    }));

    let tools = session.round_trip(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": { "_meta": stateless_meta() }
    }));
    assert_eq!(tools["result"]["ttlMs"], 300_000, "{tools}");
    assert_eq!(tools["result"]["cacheScope"], "private", "{tools}");

    let resources = session.round_trip(json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "resources/list",
        "params": { "_meta": stateless_meta() }
    }));
    assert_eq!(
        resources["result"]["resources"][0]["uri"], AGENTS_GUIDANCE_URI,
        "{resources}"
    );

    let resource = session.round_trip(json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "resources/read",
        "params": { "uri": AGENTS_GUIDANCE_URI, "_meta": stateless_meta() }
    }));
    assert_eq!(resource["result"]["ttlMs"], 3_600_000, "{resource}");
    assert_eq!(resource["result"]["cacheScope"], "public", "{resource}");

    session.finish();
}

/// The Tasks extension (SEP-2663) lifecycle, recorded and judged against the
/// same schema as everything else.
///
/// Bifrost hands out task handles only to a `2026-07-28` client that declared
/// the extension, and the pinned `2026-07-28` snapshot describes no part of
/// that extension: it has no `tasks/*` methods and no `CreateTaskResult`, so
/// the task handle answering the initiating `tools/call` is judged as a
/// `CallToolResult`, which requires the `content` a handle does not carry. The
/// `tasks/get` traffic itself is describable, because the generic request and
/// response definitions accept it.
///
/// The gap is pinned here rather than skipped: exactly one recorded message may
/// be undescribable, and it must be that result. Everything else in the session
/// -- including every `tasks/get` exchange -- must validate, so new
/// schema-invalid traffic fails this test.
#[test]
fn tasks_2026_07_28_session_wire_is_schema_valid_outside_the_extension() {
    let workspace = InlineTestProject::with_language(Language::Python)
        .file("src/app.py", MCP_POLICY_APP)
        .file("policies/dynamic-eval.rqlp", MCP_DYNAMIC_EVAL_POLICY)
        .build();
    let mut session = WireSession::rooted(STATELESS_REVISION, workspace.root());

    let created = session.round_trip(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "run_policy",
            "arguments": {
                "policy_files": ["policies/dynamic-eval.rqlp"],
                "evaluation_date": "2026-07-27",
                "fail_on": "warning"
            },
            "_meta": tasks_capable_meta()
        }
    }));
    assert_eq!(created["result"]["resultType"], "task", "{created}");
    let task_id = created["result"]["taskId"]
        .as_str()
        .unwrap_or_else(|| panic!("a task handle must carry a taskId: {created}"))
        .to_string();

    // The terminal poll carries the tool result, which is how the extension
    // delivers it here: `tasks/result` is not served (it answers -32601), so
    // there is no separate payload fetch to record.
    let terminal = session.poll_task_until_terminal(&task_id, 10);
    assert_eq!(terminal["result"]["status"], "completed", "{terminal}");
    assert_eq!(terminal["result"]["result"]["isError"], false, "{terminal}");

    let violations = session.violations();
    for violation in &violations {
        assert!(
            violation.contains("(result of 'tools/call')"),
            "only the task-augmented tools/call result is undescribable by the \
             base {STATELESS_REVISION} schema; found another violation:\n{}",
            violations.join("\n")
        );
    }
    assert_eq!(
        violations.len(),
        1,
        "the extension gap is one message wide:\n{}",
        violations.join("\n")
    );
}

/// The gate itself: a malformed response must produce violations, and a
/// well-formed message must not. Without this a broken validator would report
/// every session as conformant.
#[test]
fn the_wire_schema_gate_rejects_malformed_messages() {
    let mut schemas = RevisionSchemas::load(LEGACY_REVISION);

    let empty_initialize = schemas.violations_for(
        &json!({ "jsonrpc": "2.0", "id": 1, "result": {} }),
        Some("initialize"),
    );
    assert!(
        empty_initialize
            .iter()
            .any(|violation| violation.contains("InitializeResult")),
        "{empty_initialize:?}"
    );

    let wrong_jsonrpc = schemas.violations_for(
        &json!({ "jsonrpc": "1.0", "method": "notifications/initialized" }),
        None,
    );
    assert!(
        wrong_jsonrpc
            .iter()
            .any(|violation| violation.contains("InitializedNotification")),
        "{wrong_jsonrpc:?}"
    );

    assert_eq!(
        schemas.violations_for(&json!({ "jsonrpc": "2.0", "id": 1 }), None),
        vec!["JSONRPCMessage: not a valid JSON-RPC request, notification, or response".to_string()]
    );
    assert!(
        schemas
            .violations_for(
                &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
                None
            )
            .is_empty()
    );
}

fn mcp_server_binary() -> &'static str {
    option_env!("CARGO_BIN_EXE_bifrost-mcp-test-server")
        .or(option_env!("CARGO_BIN_EXE_bifrost"))
        .expect("Cargo did not provide an MCP server binary")
}

fn search_symbols_call(id: i64, pattern: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": { "name": "search_symbols", "arguments": { "patterns": [pattern] } }
    })
}

/// The per-request negotiation keys a stateless `2026-07-28` request carries in
/// place of a connection-level `initialize`.
fn stateless_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": STATELESS_REVISION,
        "io.modelcontextprotocol/clientCapabilities": {}
    })
}

fn tasks_capable_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": STATELESS_REVISION,
        "io.modelcontextprotocol/clientCapabilities": {
            "extensions": { "io.modelcontextprotocol/tasks": {} }
        }
    })
}

fn stateless_search_symbols_call(id: i64, pattern: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "search_symbols",
            "arguments": { "patterns": [pattern] },
            "_meta": stateless_meta()
        }
    })
}

fn directory_uri(root: &Path) -> String {
    url::Url::from_directory_path(root)
        .expect("workspace directory URI")
        .to_string()
}

#[derive(Clone, Copy)]
enum Direction {
    ClientToServer,
    ServerToClient,
}

impl Direction {
    fn label(self) -> &'static str {
        match self {
            Direction::ClientToServer => "client -> server",
            Direction::ServerToClient => "server -> client",
        }
    }
}

/// One recorded message plus the method of the request it answers, which is
/// what selects the per-method result definition.
struct Recorded {
    direction: Direction,
    message: Value,
    request_method: Option<String>,
}

/// A live server process whose whole wire traffic is recorded as it happens.
struct WireSession {
    revision: &'static str,
    child: Child,
    stdin: Option<ChildStdin>,
    reader: BufReader<ChildStdout>,
    stderr: ChildStderr,
    messages: Vec<Recorded>,
    /// Outstanding requests, keyed by sender and JSON-RPC id: a response is
    /// matched against the request that came from the other direction.
    outstanding: HashMap<String, String>,
}

impl WireSession {
    /// A server given its workspace on the command line.
    fn rooted(revision: &'static str, root: &Path) -> Self {
        let mut command = Command::new(mcp_server_binary());
        command
            .arg("--root")
            .arg(root)
            .arg("--mcp")
            .arg("searchtools");
        Self::spawn(revision, command)
    }

    /// A server with no workspace of its own, which must obtain one from the
    /// client. Its working directory is deliberately not a workspace.
    fn rootless(revision: &'static str, cwd: &Path) -> Self {
        let mut command = Command::new(mcp_server_binary());
        command
            .arg("--mcp")
            .arg("workspace|symbol")
            .current_dir(cwd);
        Self::spawn(revision, command)
    }

    fn spawn(revision: &'static str, mut command: Command) -> Self {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn bifrost");
        let stdin = child.stdin.take().expect("stdin");
        let reader = BufReader::new(child.stdout.take().expect("stdout"));
        let stderr = child.stderr.take().expect("stderr");
        Self {
            revision,
            child,
            stdin: Some(stdin),
            reader,
            stderr,
            messages: Vec::new(),
            outstanding: HashMap::new(),
        }
    }

    fn send(&mut self, message: Value) {
        let stdin = self.stdin.as_mut().expect("session stdin");
        writeln!(stdin, "{message}").expect("write message");
        stdin.flush().expect("flush message");
        self.record(Direction::ClientToServer, message);
    }

    fn recv(&mut self) -> Value {
        let mut line = String::new();
        let bytes = self.reader.read_line(&mut line).expect("read message");
        if bytes == 0 {
            let mut diagnostics = String::new();
            self.stderr
                .read_to_string(&mut diagnostics)
                .expect("read server stderr");
            panic!("server closed before responding; stderr:\n{diagnostics}");
        }
        let message: Value = serde_json::from_str(&line)
            .unwrap_or_else(|error| panic!("server emitted invalid JSON: {error}\nline: {line}"));
        self.record(Direction::ServerToClient, message.clone());
        message
    }

    fn round_trip(&mut self, message: Value) -> Value {
        self.send(message);
        self.recv()
    }

    fn record(&mut self, direction: Direction, message: Value) {
        let from_client = matches!(direction, Direction::ClientToServer);
        let request_method = match (message.get("method"), message.get("id")) {
            (Some(Value::String(method)), Some(id)) => {
                self.outstanding
                    .insert(request_key(from_client, id), method.clone());
                None
            }
            (Some(_), _) => None,
            (None, Some(id)) => self
                .outstanding
                .get(&request_key(!from_client, id))
                .cloned(),
            (None, None) => None,
        };
        self.messages.push(Recorded {
            direction,
            message,
            request_method,
        });
    }

    fn initialize(&mut self, id: i64, capabilities: Value) -> Value {
        let initialize = self.round_trip(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "initialize",
            "params": {
                "protocolVersion": self.revision,
                "capabilities": capabilities,
                "clientInfo": { "name": "bifrost-wire-schema", "version": "1" }
            }
        }));
        self.send(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
        initialize
    }

    /// Send a call and answer the `roots/list` request it provokes. A call made
    /// while already bound provokes no request, so this peeks at the method
    /// rather than assuming an exchange happens.
    fn call_answering_roots(&mut self, request: Value, roots_result: Value) -> Value {
        self.send(request);
        let message = self.recv();
        if message["method"] != "roots/list" {
            return message;
        }
        self.send(json!({ "jsonrpc": "2.0", "id": message["id"], "result": roots_result }));
        self.recv()
    }

    /// Read until the response for `id` arrives, returning the
    /// `notifications/progress` messages seen on the way. Nothing but progress
    /// may precede the response.
    fn read_response_collecting_progress(&mut self, id: i64) -> (Value, Vec<Value>) {
        let mut progress = Vec::new();
        loop {
            let message = self.recv();
            if message["id"] == json!(id) {
                return (message, progress);
            }
            assert_eq!(
                message["method"], "notifications/progress",
                "unexpected message while waiting for response {id}: {message}"
            );
            progress.push(message);
        }
    }

    /// Poll `tasks/get` until the task settles, returning the terminal
    /// response. Polls faster than the advertised interval because this is a
    /// test, not a considerate client.
    fn poll_task_until_terminal(&mut self, task_id: &str, first_id: i64) -> Value {
        let give_up_at = Instant::now() + Duration::from_secs(120);
        let mut id = first_id;
        loop {
            let response = self.round_trip(json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tasks/get",
                "params": { "taskId": task_id, "_meta": tasks_capable_meta() }
            }));
            let status = response["result"]["status"]
                .as_str()
                .unwrap_or_else(|| panic!("tasks/get must report a status: {response}"));
            if matches!(status, "completed" | "failed" | "cancelled") {
                return response;
            }
            assert!(
                Instant::now() < give_up_at,
                "task never settled: {response}"
            );
            id += 1;
            thread::sleep(Duration::from_millis(50));
        }
    }

    /// End the session and report every recorded message the official schema
    /// for the negotiated revision rejects.
    fn violations(mut self) -> Vec<String> {
        drop(self.stdin.take().expect("session stdin"));
        let status = self.child.wait().expect("wait bifrost");
        assert!(status.success(), "bifrost exited unsuccessfully: {status}");
        assert!(
            !self.messages.is_empty(),
            "a session must record wire traffic"
        );

        let mut schemas = RevisionSchemas::load(self.revision);
        let mut violations = Vec::new();
        for recorded in &self.messages {
            let errors =
                schemas.violations_for(&recorded.message, recorded.request_method.as_deref());
            if !errors.is_empty() {
                violations.push(format!(
                    "[{}] {}\n  message: {}",
                    recorded.direction.label(),
                    errors.join("; "),
                    serde_json::to_string_pretty(&recorded.message)
                        .expect("serialize recorded message")
                ));
            }
        }
        violations
    }

    fn finish(self) {
        let revision = self.revision;
        let recorded = self.messages.len();
        let violations = self.violations();
        assert!(
            violations.is_empty(),
            "{} of {recorded} recorded messages violate the official MCP {revision} schema:\n{}",
            violations.len(),
            violations.join("\n")
        );
    }
}

fn request_key(from_client: bool, id: &Value) -> String {
    format!("{from_client}:{id}")
}

/// The official spec schema for one revision, plus the method, result, and
/// error definition maps derived from it.
struct RevisionSchemas {
    /// The whole schema document, used as the compilation base so that every
    /// internal `$ref` resolves without an external resolver.
    root: Value,
    defs_key: &'static str,
    def_names: HashSet<String>,
    method_defs: HashMap<String, String>,
    result_defs: HashMap<String, String>,
    error_defs: HashMap<i64, String>,
    validators: HashMap<String, Validator>,
}

impl RevisionSchemas {
    fn load(revision: &str) -> Self {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("conformance")
            .join("schemas")
            .join(format!("mcp-schema-{revision}.json"));
        let bytes =
            fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        let mut root: Value =
            serde_json::from_slice(&bytes).expect("official MCP schema is valid JSON");
        let defs_key = if root.get("$defs").is_some() {
            "$defs"
        } else {
            "definitions"
        };

        // The official runner patches these three from "integer" to "number"
        // before compiling these two revisions, whose `NumberSchema` declares
        // integer bounds the spec's own examples violate. Replicated exactly so
        // Bifrost is judged by the same schema the upstream gate applies.
        if matches!(revision, "2025-11-25" | "2025-06-18") {
            for field in ["minimum", "maximum", "default"] {
                let pointer = format!("/{defs_key}/NumberSchema/properties/{field}/type");
                if let Some(kind) = root.pointer_mut(&pointer)
                    && kind == "integer"
                {
                    *kind = json!("number");
                }
            }
        }

        // The union definitions (`ClientRequest`, `ServerMessage`, ...) repeat
        // the constants of the concrete definitions they alternate over, so the
        // runner excludes them from the maps and so does this.
        const UNION_DEFS: [&str; 8] = [
            "ClientRequest",
            "ClientNotification",
            "ClientResult",
            "ClientMessage",
            "ServerRequest",
            "ServerNotification",
            "ServerResult",
            "ServerMessage",
        ];
        let defs = root[defs_key]
            .as_object()
            .expect("the schema declares a definitions map")
            .clone();
        let mut method_defs = HashMap::new();
        let mut result_defs = HashMap::new();
        let mut error_defs = HashMap::new();
        for (name, def) in &defs {
            if UNION_DEFS.contains(&name.as_str()) {
                continue;
            }
            if let Some(Value::String(method)) = def.pointer("/properties/method/const") {
                method_defs.insert(method.clone(), name.clone());
                if let Some(stem) = name.strip_suffix("Request") {
                    let result = format!("{stem}Result");
                    if defs.contains_key(&result) {
                        result_defs.insert(method.clone(), result);
                    }
                }
            }
            for arm in def
                .pointer("/properties/error/allOf")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(code) = arm
                    .pointer("/properties/code/const")
                    .and_then(Value::as_i64)
                {
                    error_defs.insert(code, name.clone());
                }
            }
        }

        Self {
            root,
            defs_key,
            def_names: defs.keys().cloned().collect(),
            method_defs,
            result_defs,
            error_defs,
            validators: HashMap::new(),
        }
    }

    /// Route one message the way the official runner does and return every
    /// schema error it produces. An empty result means the message is valid.
    fn violations_for(&mut self, message: &Value, request_method: Option<&str>) -> Vec<String> {
        let Some(object) = message.as_object() else {
            return vec![
                "JSONRPCMessage: not a valid JSON-RPC request, notification, or response"
                    .to_string(),
            ];
        };

        if let Some(Value::String(method)) = object.get("method") {
            let def = self.method_defs.get(method).cloned().unwrap_or_else(|| {
                if object.contains_key("id") {
                    "JSONRPCRequest".to_string()
                } else {
                    "JSONRPCNotification".to_string()
                }
            });
            return self.errors_for(&def, message);
        }

        if let Some(error) = object.get("error").filter(|error| !error.is_null()) {
            let def = error
                .get("code")
                .and_then(Value::as_i64)
                .and_then(|code| self.error_defs.get(&code).cloned())
                .unwrap_or_else(|| self.first_def(&["JSONRPCErrorResponse", "JSONRPCError"]));
            return self.errors_for(&def, message);
        }

        if let Some(result) = object.get("result") {
            // An MRTR intermediate is discriminated by the result itself, not
            // by the method of the request it answers.
            let result_def = if result.get("resultType") == Some(&json!("input_required"))
                && self.def_names.contains("InputRequiredResult")
            {
                Some("InputRequiredResult".to_string())
            } else {
                request_method.and_then(|method| self.result_defs.get(method).cloned())
            };
            if let Some(def) = result_def {
                let method = request_method.unwrap_or("an unmatched request");
                let errors = self
                    .errors_for(&def, result)
                    .into_iter()
                    .map(|error| format!("{error} (result of '{method}')"))
                    .collect::<Vec<_>>();
                if !errors.is_empty() {
                    return errors;
                }
            }
            let def = self.first_def(&["JSONRPCResultResponse", "JSONRPCResponse"]);
            return self.errors_for(&def, message);
        }

        vec!["JSONRPCMessage: not a valid JSON-RPC request, notification, or response".to_string()]
    }

    fn first_def(&self, candidates: &[&str]) -> String {
        candidates
            .iter()
            .find(|name| self.def_names.contains(**name))
            .unwrap_or_else(|| candidates.last().expect("a candidate definition"))
            .to_string()
    }

    fn errors_for(&mut self, def: &str, instance: &Value) -> Vec<String> {
        assert!(
            self.def_names.contains(def),
            "the {def} definition must exist in the schema being applied"
        );
        let Self {
            root,
            defs_key,
            validators,
            ..
        } = self;
        let validator = validators.entry(def.to_string()).or_insert_with(|| {
            let mut schema = root.clone();
            schema
                .as_object_mut()
                .expect("the schema root is an object")
                .insert("$ref".to_string(), json!(format!("#/{defs_key}/{def}")));
            jsonschema::validator_for(&schema)
                .unwrap_or_else(|error| panic!("compile the {def} definition: {error}"))
        });
        validator
            .iter_errors(instance)
            .map(|error| {
                let path = error.instance_path().to_string();
                let location = if path.is_empty() {
                    String::new()
                } else {
                    format!(" at {path}")
                };
                format!("{def}{location}: {error}")
            })
            .collect()
    }
}
