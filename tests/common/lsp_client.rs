//! A minimal JSON-RPC client that spawns the real `bifrost` LSP server as a
//! subprocess, used by integration suites that want to drive the server the way
//! a real editor does (position in → `Location[]` out).
//!
//! This factors the spawn / framing / request helpers that previously lived
//! privately inside `tests/bifrost_lsp_server.rs` into one reusable place. The
//! IntelliJ-ported find-usages suite (`tests/intellij_python_find_usages.rs`)
//! drives `textDocument/references` through here.

#![allow(dead_code)]

use brokk_bifrost::lsp::conversion::path_to_uri_string;
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};

/// Build an LSP-correct `file://` URI for `path`. Delegates to the crate's
/// `path_to_uri_string`, which handles drive letters, percent-encoding, and the
/// leading-slash convention (a hand-rolled `format!("file://{}")` is wrong on
/// Windows and for paths with spaces).
pub fn uri_for(path: &Path) -> String {
    path_to_uri_string(path)
}

/// A single resolved reference location, flattened from the LSP `Location` JSON
/// for convenient assertions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefLocation {
    pub uri: String,
    /// 0-based start line.
    pub line: u64,
    /// 0-based start character (UTF-16 code unit offset, per LSP).
    pub character: u64,
}

/// A running `bifrost` LSP server subprocess plus its stdio pipes.
pub struct LspServer {
    child: Child,
    stdin: ChildStdin,
    reader: BufReader<ChildStdout>,
    stderr: ChildStderr,
    next_id: u64,
}

impl LspServer {
    /// Spawn the server rooted at `root` without performing the initialize
    /// handshake.
    pub fn spawn(root: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
            .arg("--root")
            .arg(root)
            .arg("--server")
            .arg("lsp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn bifrost");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = child.stdout.take().expect("stdout");
        let stderr = child.stderr.take().expect("stderr");

        Self {
            child,
            stdin,
            reader: BufReader::new(stdout),
            stderr,
            next_id: 1,
        }
    }

    /// Spawn the server rooted at `root` and complete the initialize handshake.
    pub fn start(root: &Path) -> Self {
        let root_uri = uri_for(root);
        Self::start_with_params(
            root,
            json!({"processId": null, "rootUri": root_uri, "capabilities": {}}),
        )
    }

    /// Spawn the server with explicit `initialize` params (e.g. to exercise
    /// capability negotiation).
    pub fn start_with_params(root: &Path, initialize_params: Value) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_bifrost"))
            .arg("--root")
            .arg(root)
            .arg("--server")
            .arg("lsp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn bifrost");
        let mut stdin = child.stdin.take().expect("stdin");
        let stdout = child.stdout.take().expect("stdout");
        let mut stderr = child.stderr.take().expect("stderr");
        let mut reader = BufReader::new(stdout);

        write_message(
            &mut stdin,
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": initialize_params
            }),
        );
        let _ = read_response_for_id(&mut reader, &mut stderr, 1);
        write_message(
            &mut stdin,
            json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
        );

        Self {
            child,
            stdin,
            reader,
            stderr,
            next_id: 2,
        }
    }

    fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Send an arbitrary request and return the matching response `Value`. The
    /// id is allocated and matched internally.
    pub fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id();
        write_message(
            &mut self.stdin,
            json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}),
        );
        read_response_for_id(&mut self.reader, &mut self.stderr, id)
    }

    /// Send an arbitrary notification.
    pub fn notify(&mut self, method: &str, params: Value) {
        self.notify_value(json!({"jsonrpc": "2.0", "method": method, "params": params}));
    }

    /// Send a fully-formed JSON-RPC message.
    pub fn notify_value(&mut self, value: Value) {
        write_message(&mut self.stdin, value);
    }

    /// Read the next inbound JSON-RPC message.
    pub fn read_message(&mut self) -> Value {
        read_message(&mut self.reader, &mut self.stderr)
    }

    /// Read inbound messages until a notification with `method` arrives.
    pub fn read_notification(&mut self, method: &str) -> Value {
        for _ in 0..32 {
            let msg = self.read_message();
            if msg["method"] == method {
                return msg;
            }
        }
        panic!("did not receive {method} within 32 messages");
    }

    /// Read inbound messages until the response with `id` arrives.
    pub fn read_response_for_id(&mut self, id: u64) -> Value {
        read_response_for_id(&mut self.reader, &mut self.stderr, id)
    }

    /// A `textDocument/<...>` request that takes only a document URI + position
    /// (definition, hover, documentHighlight, implementation, ...). Returns the
    /// raw response `Value`.
    pub fn text_document_position_response(
        &mut self,
        method: &str,
        file_uri: &str,
        line: u64,
        character: u64,
    ) -> Value {
        self.request(
            method,
            json!({
                "textDocument": {"uri": file_uri},
                "position": {"line": line, "character": character},
            }),
        )
    }

    pub fn type_definition_response(&mut self, file_uri: &str, line: u64, character: u64) -> Value {
        self.text_document_position_response(
            "textDocument/typeDefinition",
            file_uri,
            line,
            character,
        )
    }

    pub fn implementation_response(&mut self, file_uri: &str, line: u64, character: u64) -> Value {
        self.text_document_position_response(
            "textDocument/implementation",
            file_uri,
            line,
            character,
        )
    }

    pub fn completion_response(&mut self, file_uri: &str, line: u64, character: u64) -> Value {
        self.text_document_position_response("textDocument/completion", file_uri, line, character)
    }

    pub fn hover_response(&mut self, file_uri: &str, line: u64, character: u64) -> Value {
        self.text_document_position_response("textDocument/hover", file_uri, line, character)
    }

    pub fn signature_help(&mut self, uri: &str, line: u64, character: u64) -> Value {
        let response = self.text_document_position_response(
            "textDocument/signatureHelp",
            uri,
            line,
            character,
        );
        assert!(
            response["error"].is_null(),
            "unexpected signatureHelp error: {response}"
        );
        assert!(
            response["result"].is_object(),
            "expected signatureHelp result object, got {response}"
        );
        response["result"].clone()
    }

    pub fn workspace_symbol(&mut self, query: &str) -> Value {
        self.request("workspace/symbol", json!({"query": query}))
    }

    pub fn document_symbol(&mut self, file_uri: &str) -> Value {
        self.request(
            "textDocument/documentSymbol",
            json!({"textDocument": {"uri": file_uri}}),
        )
    }

    pub fn prepare_type_hierarchy(&mut self, uri: &str, line: u64, character: u64) -> Value {
        self.prepare_hierarchy("textDocument/prepareTypeHierarchy", uri, (line, character))
    }

    pub fn prepare_type_hierarchy_result(&mut self, uri: &str, line: u64, character: u64) -> Value {
        self.prepare_hierarchy_result("textDocument/prepareTypeHierarchy", uri, (line, character))
    }

    pub fn type_hierarchy_relation(&mut self, method: &str, item: Value) -> Vec<Value> {
        self.hierarchy_relation(method, item)
    }

    #[cfg(unix)]
    pub fn formatting_response(&mut self, file_uri: &str) -> Value {
        self.request(
            "textDocument/formatting",
            json!({
                "textDocument": {"uri": file_uri},
                "options": {"tabSize": 4, "insertSpaces": true}
            }),
        )
    }

    pub fn prepare_hierarchy(&mut self, method: &str, uri: &str, position: (u64, u64)) -> Value {
        let result = self.prepare_hierarchy_result(method, uri, position);
        let items = result
            .as_array()
            .unwrap_or_else(|| panic!("expected prepare array, got {result}"));
        assert_eq!(items.len(), 1, "expected one prepared item: {items:#?}");
        items[0].clone()
    }

    pub fn prepare_hierarchy_result(
        &mut self,
        method: &str,
        uri: &str,
        position: (u64, u64),
    ) -> Value {
        let (line, character) = position;
        let response = self.request(
            method,
            json!({
                "textDocument": {"uri": uri},
                "position": {"line": line, "character": character}
            }),
        );
        response["result"].clone()
    }

    pub fn hierarchy_relation(&mut self, method: &str, item: Value) -> Vec<Value> {
        let response = self.request(method, json!({"item": item}));
        response["result"]
            .as_array()
            .unwrap_or_else(|| panic!("expected {method} array, got {response}"))
            .clone()
    }

    /// `textDocument/references` by URI string, returning the raw response.
    pub fn references_response(
        &mut self,
        file_uri: &str,
        line: u64,
        character: u64,
        include_declaration: bool,
    ) -> Value {
        self.request(
            "textDocument/references",
            json!({
                "textDocument": {"uri": file_uri},
                "position": {"line": line, "character": character},
                "context": {"includeDeclaration": include_declaration},
            }),
        )
    }

    /// Send `textDocument/references` for the file at `file_path` and return the
    /// raw response `Value`.
    pub fn references_raw(
        &mut self,
        file_path: &Path,
        line: u64,
        character: u64,
        include_declaration: bool,
    ) -> Value {
        let id = self.next_id();
        let file_uri = uri_for(file_path);
        write_message(
            &mut self.stdin,
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "textDocument/references",
                "params": {
                    "textDocument": {"uri": file_uri},
                    "position": {"line": line, "character": character},
                    "context": {"includeDeclaration": include_declaration}
                }
            }),
        );
        read_response_for_id(&mut self.reader, &mut self.stderr, id)
    }

    /// Send `textDocument/references` and return the resolved locations, sorted
    /// by (uri, line, character). A `null`/absent result yields an empty vec —
    /// the server returns `null` when the cursor does not resolve to a symbol.
    pub fn references(
        &mut self,
        file_path: &Path,
        line: u64,
        character: u64,
        include_declaration: bool,
    ) -> Vec<RefLocation> {
        let response = self.references_raw(file_path, line, character, include_declaration);
        let mut locations: Vec<RefLocation> = match response["result"].as_array() {
            Some(array) => array
                .iter()
                .map(|loc| RefLocation {
                    uri: loc["uri"].as_str().expect("location uri").to_string(),
                    line: loc["range"]["start"]["line"]
                        .as_u64()
                        .expect("location line"),
                    character: loc["range"]["start"]["character"]
                        .as_u64()
                        .expect("location character"),
                })
                .collect(),
            None => Vec::new(),
        };
        locations.sort_by(|a, b| {
            a.uri
                .cmp(&b.uri)
                .then(a.line.cmp(&b.line))
                .then(a.character.cmp(&b.character))
        });
        locations
    }

    /// Graceful `shutdown`/`exit` and assert a clean process exit.
    pub fn shutdown(mut self) {
        write_message(
            &mut self.stdin,
            json!({"jsonrpc": "2.0", "id": 999, "method": "shutdown"}),
        );
        let _ = read_response_for_id(&mut self.reader, &mut self.stderr, 999);
        write_message(&mut self.stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
        drop(self.stdin);
        let status = self.child.wait().expect("wait bifrost");
        assert!(status.success(), "bifrost exited unsuccessfully: {status}");
    }

    /// Graceful `shutdown`/`exit` using an explicit request id.
    pub fn shutdown_with_id(mut self, id: u64) {
        write_message(
            &mut self.stdin,
            json!({"jsonrpc": "2.0", "id": id, "method": "shutdown"}),
        );
        let _ = read_response_for_id(&mut self.reader, &mut self.stderr, id);
        write_message(&mut self.stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
        drop(self.stdin);
        let status = self.child.wait().expect("wait bifrost");
        assert!(status.success(), "bifrost exited unsuccessfully: {status}");
    }

    /// Send `exit`, close stdin, and assert a clean process exit.
    pub fn exit(mut self) {
        write_message(&mut self.stdin, json!({"jsonrpc": "2.0", "method": "exit"}));
        drop(self.stdin);
        let status = self.child.wait().expect("wait bifrost");
        assert!(status.success(), "bifrost exited unsuccessfully: {status}");
    }
}

pub fn write_message(stdin: &mut impl Write, payload: Value) {
    let body = serde_json::to_string(&payload).expect("serialize");
    write!(stdin, "Content-Length: {}\r\n\r\n{}", body.len(), body).expect("write");
    stdin.flush().expect("flush");
}

pub fn read_message(reader: &mut impl BufRead, stderr: &mut impl Read) -> Value {
    let mut content_length: Option<usize> = None;
    loop {
        let mut header = String::new();
        let bytes = reader.read_line(&mut header).expect("read header");
        if bytes == 0 {
            let mut buf = String::new();
            let _ = stderr.read_to_string(&mut buf);
            panic!("server closed; stderr:\n{buf}");
        }
        let trimmed = header.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some(rest) = trimmed.strip_prefix("Content-Length: ") {
            content_length = Some(rest.parse().expect("Content-Length value"));
        }
    }
    let len = content_length.expect("missing Content-Length header");
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).expect("read body");
    serde_json::from_slice(&body).expect("valid json response")
}

pub fn read_response_for_id(reader: &mut impl BufRead, stderr: &mut impl Read, id: u64) -> Value {
    for _ in 0..32 {
        let msg = read_message(reader, stderr);
        if msg["id"].as_u64() == Some(id) {
            return msg;
        }
    }
    panic!("did not receive response with id {id} within 32 messages");
}
