use std::path::PathBuf;
use std::sync::Arc;

use lsp_server::{Connection, ExtractError, IoThreads, Message, Notification, Request};
use lsp_types::{InitializeParams, Uri};

use crate::analyzer::{AnalyzerConfig, FilesystemProject, Project, WorkspaceAnalyzer};
use crate::lsp::capabilities::server_capabilities;

/// Run the LSP server over stdio. `fallback_root` is used when the client does
/// not advertise a `workspaceFolders[0]`. Returns when the client sends
/// `exit` (after the standard `shutdown` request) or the connection drops.
pub fn run_lsp_stdio_server(fallback_root: PathBuf) -> Result<(), String> {
    let (connection, io_threads) = Connection::stdio();
    run_with_connection(connection, io_threads, fallback_root)
}

pub(crate) fn run_with_connection(
    connection: Connection,
    io_threads: IoThreads,
    fallback_root: PathBuf,
) -> Result<(), String> {
    let server_capabilities = serde_json::to_value(server_capabilities())
        .map_err(|err| format!("Failed to serialize LSP server capabilities: {err}"))?;

    let init_params_value = connection
        .initialize(server_capabilities)
        .map_err(|err| format!("LSP initialize failed: {err}"))?;
    let init_params: InitializeParams = serde_json::from_value(init_params_value)
        .map_err(|err| format!("Failed to decode InitializeParams: {err}"))?;

    let workspace_root = pick_workspace_root(&init_params, &fallback_root);
    let mut state = ServerState::new(workspace_root)?;

    let result = main_loop(&connection, &mut state);
    // Drop the connection before joining the IO threads so the writer thread
    // sees its sender close and exits — otherwise io_threads.join() blocks
    // forever on a still-live writer channel.
    drop(connection);
    io_threads
        .join()
        .map_err(|err| format!("LSP IO threads failed: {err}"))?;
    result
}

fn main_loop(connection: &Connection, state: &mut ServerState) -> Result<(), String> {
    for msg in &connection.receiver {
        match msg {
            Message::Request(req) => {
                if connection
                    .handle_shutdown(&req)
                    .map_err(|err| format!("LSP shutdown handling failed: {err}"))?
                {
                    return Ok(());
                }
                handle_request(connection, state, req)?;
            }
            Message::Notification(note) => handle_notification(state, note)?,
            Message::Response(_) => {
                // We do not currently send server→client requests, so any
                // inbound Response is unsolicited and safe to ignore.
            }
        }
    }
    Ok(())
}

fn handle_request(
    connection: &Connection,
    _state: &mut ServerState,
    req: Request,
) -> Result<(), String> {
    // No request handlers are wired up yet — those land with #12 onward.
    let response = lsp_server::Response::new_err(
        req.id.clone(),
        lsp_server::ErrorCode::MethodNotFound as i32,
        format!("Method not implemented: {}", req.method),
    );
    connection
        .sender
        .send(Message::Response(response))
        .map_err(|err| format!("Failed to send LSP response: {err}"))
}

fn handle_notification(_state: &mut ServerState, note: Notification) -> Result<(), String> {
    // Recognise `initialized` (post-handshake ack from the client) and ignore
    // every other notification until the relevant handler ships.
    match cast_notification::<lsp_types::notification::Initialized>(note) {
        Ok(_params) => Ok(()),
        Err(ExtractError::MethodMismatch(_)) => Ok(()),
        Err(ExtractError::JsonError { method, error }) => Err(format!(
            "Failed to decode notification {method}: {error}"
        )),
    }
}

fn cast_notification<N>(note: Notification) -> Result<N::Params, ExtractError<Notification>>
where
    N: lsp_types::notification::Notification,
    N::Params: serde::de::DeserializeOwned,
{
    note.extract(<N as lsp_types::notification::Notification>::METHOD)
}

pub(crate) struct ServerState {
    #[allow(dead_code)]
    workspace: WorkspaceAnalyzer,
    #[allow(dead_code)]
    project: Arc<dyn Project>,
}

impl ServerState {
    fn new(root: PathBuf) -> Result<Self, String> {
        let project: Arc<dyn Project> = Arc::new(
            FilesystemProject::new(&root)
                .map_err(|err| format!("Failed to initialize project root {}: {err}", root.display()))?,
        );
        let workspace = WorkspaceAnalyzer::build(Arc::clone(&project), AnalyzerConfig::default());
        Ok(Self { workspace, project })
    }
}

fn pick_workspace_root(params: &InitializeParams, fallback: &PathBuf) -> PathBuf {
    if let Some(folders) = &params.workspace_folders
        && let Some(first) = folders.first()
        && let Some(path) = uri_to_path(&first.uri)
    {
        return path;
    }

    // `root_uri` and the long-deprecated `root_path` are still common.
    #[allow(deprecated)]
    if let Some(uri) = &params.root_uri
        && let Some(path) = uri_to_path(uri)
    {
        return path;
    }
    #[allow(deprecated)]
    if let Some(root_path) = &params.root_path {
        return PathBuf::from(root_path);
    }

    fallback.clone()
}

fn uri_to_path(uri: &Uri) -> Option<PathBuf> {
    let raw = uri.as_str();
    let stripped = raw.strip_prefix("file://")?;
    // Strip a single leading slash on Windows (e.g. `file:///C:/foo` → `C:/foo`).
    #[cfg(windows)]
    let stripped = stripped.strip_prefix('/').unwrap_or(stripped);
    let decoded = percent_decode(stripped);
    Some(PathBuf::from(decoded))
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) =
                (hex_value(bytes[i + 1]), hex_value(bytes[i + 2]))
            {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_handles_spaces_and_unicode() {
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("%E2%9C%93"), "✓");
        assert_eq!(percent_decode("plain/path"), "plain/path");
    }
}
