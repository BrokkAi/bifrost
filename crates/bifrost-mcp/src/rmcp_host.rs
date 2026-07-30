//! Bifrost's MCP host, built on `rmcp` (the official Model Context Protocol
//! Rust SDK).
//!
//! `rmcp` owns everything that is protocol: JSON-RPC framing over stdio,
//! revision negotiation, method dispatch, wire types, response serialization,
//! and cancellation plumbing. This module owns everything that is Bifrost:
//! server identity, the tool registry, workspace authorization, the Codex
//! sandbox boundary, analyzer admission, and response budgets.
//!
//! See `.agents/plans/issue-1328-rmcp-3-adoption.md` for the migration plan.

use crate::analyzer_pool::AnalyzerExecutionPool;
use crate::mcp_common::{
    AGENTS_GUIDANCE_MIME_TYPE, AGENTS_GUIDANCE_TEXT, AGENTS_GUIDANCE_URI,
    BENCHMARK_PROFILE_BOUNDARY_MARKER, BENCHMARK_PROFILE_BOUNDARY_METHOD, CODEX_MCP_CLIENT_NAME,
    CODEX_SANDBOX_STATE_META_CAPABILITY, MCP_FILE_WATCHER_ENV, McpRenderOptions, McpServerSpec,
    UNBOUND_WORKSPACE_MESSAGE, client_root_to_path, file_uri_to_path, file_watching_enabled,
    fit_get_summaries_output_to_budget, mcp_analyzer_request_budget, serial_tool_request,
};
use crate::ordered_transport::{RootsOrderedTransport, RootsRevocations};
use crate::tool_arguments::normalize_tool_arguments;
use crate::{
    SearchToolsService, SearchToolsServiceErrorCode, analyzer::policy::escape_terminal_text,
    profiling, searchtools_render::RenderOptions,
};
use rmcp::model::{
    Annotations, CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock,
    CustomRequest, CustomResult, ErrorData, Implementation, InitializeRequestParams,
    InitializeResult, ListResourcesResult, ListToolsResult, MetaObject, PaginatedRequestParams,
    ReadResourceRequestParams, ReadResourceResponse, ReadResourceResult, Resource,
    ResourceContents, Role, ServerCapabilities, ServerInfo, Tool,
};
// MCP 2026-07-28 deprecates Roots wholesale (SEP-2577) without yet shipping a
// replacement for "which directory may this server analyze". Bifrost's whole
// security model depends on that answer, and every client Bifrost is
// configured against still speaks Roots, so the deprecated surface is used
// deliberately until SEP-2577's successor exists. See the Decision Log in
// .agents/plans/issue-1328-rmcp-3-adoption.md.
#[allow(deprecated)]
use rmcp::model::Root;
use rmcp::service::{NotificationContext, RequestContext};
use rmcp::transport::IntoTransport;
use rmcp::{RoleServer, ServerHandler, ServiceExt};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio_util::sync::CancellationToken as McpCancellationToken;

/// `_meta` key carrying the identity of the binary that hosts this MCP server.
///
/// Bifrost used to publish this as `serverInfo.buildIdentity`, but
/// `rmcp::model::Implementation` is a closed struct with no extension point.
/// `_meta` is the protocol's sanctioned place for vendor fields, so the facade
/// identity moves here. Consumers: `tests/mcp_build_identity_facade.rs` and
/// `src/benchmark/mcp_session.rs`.
pub const BUILD_IDENTITY_META_KEY: &str = "io.bifrost/build-identity";

/// Two runtime workers are enough: no Bifrost work runs on them. Protocol
/// handling is trivial, and every analyzer call goes to the blocking pool.
const RUNTIME_WORKER_THREADS: usize = 2;

/// Where the currently bound workspace came from.
///
/// This is the authorization record for every tool call: Bifrost analyzes a
/// directory only because one of these sources granted it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkspaceBindingSource {
    /// Nothing is bound. Every workspace tool is refused.
    None,
    /// The operator passed `--root`, so the client cannot change the scope.
    ExplicitRoot,
    /// The MCP client answered `roots/list`.
    ClientRoots,
    /// A Codex client supplied sandbox metadata on a `tools/call`.
    CodexSandboxState,
}

/// Per-connection workspace authorization state.
///
/// Unlike the hand-written host this replaces, it carries no protocol
/// bookkeeping: `rmcp` owns the lifecycle, owns outbound request ids, and
/// turns `roots/list` into an ordinary awaited call, so there is nothing to
/// correlate by hand.
struct ConnectionState {
    accepts_client_roots: bool,
    /// Whether `initialize` has already been answered on this connection.
    ///
    /// A second `initialize` is refused. The handshake is what decides whether
    /// this connection may bind workspaces from client roots or from Codex
    /// sandbox metadata, so letting a peer redo it would let it re-negotiate
    /// that authority mid-session. `rmcp` permits duplicates; Bifrost does not.
    initialize_received: bool,
    client_supports_roots: bool,
    workspace_binding_source: WorkspaceBindingSource,
    codex_sandbox_cwd_uri: Option<String>,
    codex_sandbox_root: Option<PathBuf>,
    /// Handle for asking this client questions, captured at `initialize`.
    ///
    /// Needed because Bifrost requests roots from inside the tool call that
    /// needs a workspace, not from a lifecycle notification. See
    /// [`BifrostMcpHandler::activate_workspace_from_client_roots`].
    peer: Option<rmcp::service::Peer<RoleServer>>,
    /// The revocation count the current binding was made under.
    ///
    /// Compared against [`RootsRevocations::observed`], which the transport
    /// increments in wire order. A request that sees a higher count knows the
    /// client revoked this scope before the request arrived, whatever order
    /// the notification handler and this request happen to be scheduled in.
    bound_at_revocation: u64,
}

impl ConnectionState {
    fn new(accepts_client_roots: bool) -> Self {
        Self {
            accepts_client_roots,
            initialize_received: false,
            client_supports_roots: false,
            workspace_binding_source: if accepts_client_roots {
                WorkspaceBindingSource::None
            } else {
                WorkspaceBindingSource::ExplicitRoot
            },
            codex_sandbox_cwd_uri: None,
            codex_sandbox_root: None,
            peer: None,
            bound_at_revocation: 0,
        }
    }

    /// Codex sandbox metadata is only honored for a rootless server whose
    /// client did not advertise MCP Roots. A client that speaks Roots must use
    /// Roots, and an explicitly rooted server ignores client scope entirely.
    fn accepts_codex_sandbox_state(&self) -> bool {
        self.accepts_client_roots && !self.client_supports_roots
    }

    fn clear_binding(&mut self) {
        self.workspace_binding_source = WorkspaceBindingSource::None;
        self.codex_sandbox_cwd_uri = None;
        self.codex_sandbox_root = None;
    }
}

/// Analyzer cancellation tokens for requests currently executing.
///
/// Its one job is revocation: when the bound workspace changes, work admitted
/// against the previous workspace must stop rather than return results for a
/// scope the client no longer authorizes. Per-request cancellation itself is
/// `rmcp`'s, bridged into the analyzer in `execute_tool`.
#[derive(Default)]
struct InFlightRequests {
    next_id: AtomicU64,
    active: Mutex<HashMap<u64, (u64, crate::CancellationToken)>>,
}

impl InFlightRequests {
    fn register(
        self: &Arc<Self>,
        workspace_generation: u64,
        cancellation: crate::CancellationToken,
    ) -> InFlightGuard {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.active
            .lock()
            .expect("in-flight MCP request lock poisoned")
            .insert(id, (workspace_generation, cancellation));
        InFlightGuard {
            requests: Arc::clone(self),
            id,
        }
    }

    fn cancel_stale(&self, current_workspace_generation: u64) {
        for (generation, cancellation) in self
            .active
            .lock()
            .expect("in-flight MCP request lock poisoned")
            .values()
        {
            if *generation != current_workspace_generation {
                cancellation.cancel();
            }
        }
    }
}

struct InFlightGuard {
    requests: Arc<InFlightRequests>,
    id: u64,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.requests
            .active
            .lock()
            .expect("in-flight MCP request lock poisoned")
            .remove(&self.id);
    }
}

/// Key under which a `2026-07-28` client returns its roots in the
/// `inputResponses` of an MRTR retry.
const ROOTS_INPUT_REQUEST_KEY: &str = "roots";

/// How many roots activations may be outstanding at once. A client that asks
/// for activation and never retries must not be able to grow server memory.
const MAX_OUTSTANDING_ROOTS_ACTIVATIONS: usize = 8;

/// Nonces for outstanding MRTR roots activations.
///
/// These are deliberately *not* a security token. The client echoes
/// `requestState` verbatim and can tamper with it, so it authorizes nothing;
/// every root in the retry is validated and bound through exactly the same
/// path as a legacy `roots/list` answer. All a nonce establishes is that a
/// retry corresponds to an activation Bifrost itself asked for, which keeps an
/// unsolicited `inputResponses` from binding a workspace out of nowhere.
#[derive(Default)]
struct RootsActivations {
    next_id: AtomicU64,
    outstanding: Mutex<std::collections::VecDeque<String>>,
}

impl RootsActivations {
    fn issue(&self) -> String {
        // Process-unique rather than random: this is a correlation nonce, not
        // a secret, and a new dependency to make it unguessable would buy
        // nothing the roots re-validation does not already guarantee.
        let nonce = format!(
            "bifrost-roots-{}-{}",
            std::process::id(),
            self.next_id.fetch_add(1, Ordering::Relaxed)
        );
        let mut outstanding = self
            .outstanding
            .lock()
            .expect("roots activation lock poisoned");
        if outstanding.len() == MAX_OUTSTANDING_ROOTS_ACTIVATIONS {
            outstanding.pop_front();
        }
        outstanding.push_back(nonce.clone());
        nonce
    }

    /// Consume a nonce, reporting whether it was one Bifrost issued and had not
    /// already spent. Single use: a replayed retry is not an activation.
    fn redeem(&self, nonce: &str) -> bool {
        let mut outstanding = self
            .outstanding
            .lock()
            .expect("roots activation lock poisoned");
        match outstanding.iter().position(|issued| issued == nonce) {
            Some(index) => {
                outstanding.remove(index);
                true
            }
            None => false,
        }
    }
}

/// Bifrost's `ServerHandler`. One instance serves one stdio connection.
pub struct BifrostMcpHandler {
    service: Arc<SearchToolsService>,
    instructions: &'static str,
    build_identity: String,
    tools: Vec<Tool>,
    tool_names: HashSet<String>,
    render_options: McpRenderOptions,
    analyzer_pool: AnalyzerExecutionPool,
    in_flight: Arc<InFlightRequests>,
    roots_activations: RootsActivations,
    roots_revocations: Arc<RootsRevocations>,
    /// Guards workspace authorization state and serializes every tool-call
    /// preparation, which is what the single reader thread used to do for
    /// free. Lock order is always this lock, then an analyzer permit.
    workspace: tokio::sync::Mutex<ConnectionState>,
}

impl BifrostMcpHandler {
    fn new(
        service: Arc<SearchToolsService>,
        render_options: McpRenderOptions,
        spec: &McpServerSpec,
        build_identity: &str,
        accepts_client_roots: bool,
        roots_revocations: Arc<RootsRevocations>,
    ) -> Result<Self, String> {
        // Converting the registry's hand-written descriptors into the SDK's
        // `Tool` here turns a malformed descriptor into a startup error naming
        // the offender, instead of wire garbage a client has to diagnose.
        let tools = spec
            .tool_descriptors
            .iter()
            .map(|descriptor| {
                serde_json::from_value::<Tool>(descriptor.clone()).map_err(|error| {
                    let name = descriptor
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("<unnamed>");
                    format!("tool descriptor `{name}` is not a valid MCP tool: {error}")
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            service,
            instructions: spec.instructions,
            build_identity: build_identity.to_string(),
            tools,
            tool_names: spec.tool_names.clone(),
            render_options,
            analyzer_pool: AnalyzerExecutionPool::default(),
            in_flight: Arc::new(InFlightRequests::default()),
            roots_activations: RootsActivations::default(),
            roots_revocations,
            workspace: tokio::sync::Mutex::new(ConnectionState::new(accepts_client_roots)),
        })
    }

    /// Ask a legacy (`2025-11-25`) client for its roots and bind the first
    /// usable one, for the request that needs a workspace right now.
    ///
    /// The exchange runs inside the tool call rather than from a lifecycle
    /// notification, and that placement is the whole point. `rmcp` dispatches
    /// every notification and every request on its own task and resolves a
    /// server-to-client response by waking the task that awaits it, so it does
    /// not preserve message arrival order. A background refresh would therefore
    /// race the very requests it exists to serve: a client that answers
    /// `roots/list` and immediately calls a tool could see the tool call
    /// overtake its own answer and be told the server is not bound to a
    /// workspace. Consuming the answer in the request that asked for it removes
    /// that race by construction, and gives the legacy revision the same shape
    /// as the `2026-07-28` MRTR path.
    ///
    /// Returns whether a workspace is now active.
    #[allow(deprecated)] // Roots: see the note on the `Root` import.
    async fn activate_workspace_from_client_roots(&self, state: &mut ConnectionState) -> bool {
        if !state.accepts_client_roots || !state.client_supports_roots {
            return false;
        }
        let Some(peer) = state.peer.clone() else {
            return false;
        };

        let result = match peer.list_roots().await {
            Ok(result) => result,
            Err(error) => {
                eprintln!("bifrost: MCP roots/list failed: {error}");
                return false;
            }
        };
        self.bind_first_usable_root(state, &result.roots)
    }

    /// Whether the client withdrew authorization for the currently bound scope.
    ///
    /// True when a `roots/list_changed` reached the transport after this
    /// binding was made. The counter is incremented in wire order by
    /// `RootsOrderedTransport`, so this answer does not depend on which task
    /// the runtime happens to poll first -- which is the whole point, since
    /// `rmcp` dispatches notifications and requests on separate tasks.
    fn client_roots_binding_is_stale(&self, state: &ConnectionState) -> bool {
        state.workspace_binding_source == WorkspaceBindingSource::ClientRoots
            && state.bound_at_revocation != self.roots_revocations.observed()
    }

    /// Drop the client-roots scope and stop any work admitted against it.
    fn revoke_client_roots(&self, state: &mut ConnectionState) {
        if let Err(error) = self.service.unbind_client_workspace() {
            eprintln!("bifrost: failed to revoke changed MCP workspace roots: {error}");
        }
        self.in_flight
            .cancel_stale(self.service.workspace_generation());
        state.clear_binding();
    }

    /// Bind the first root in `roots` that Bifrost can actually analyze.
    ///
    /// An empty or wholly unusable list is a legitimate answer meaning "you may
    /// analyze nothing", so the server stays unbound rather than falling back
    /// to anything. Shared by the legacy `roots/list` exchange and the
    /// `2026-07-28` MRTR retry, which must apply identical validation: MRTR
    /// roots arrive alongside a client-controlled `requestState` and are no
    /// more trusted for it.
    #[allow(deprecated)] // Roots: see the note on the `Root` import.
    fn bind_first_usable_root(&self, state: &mut ConnectionState, roots: &[Root]) -> bool {
        let mut last_error = None;
        for root in roots {
            let candidate = match client_root_to_path(&root.uri) {
                Ok(candidate) => candidate,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
            match self.service.bind_client_workspace(candidate) {
                Ok(root) => {
                    self.in_flight
                        .cancel_stale(self.service.workspace_generation());
                    state.workspace_binding_source = WorkspaceBindingSource::ClientRoots;
                    state.codex_sandbox_cwd_uri = None;
                    state.codex_sandbox_root = None;
                    state.bound_at_revocation = self.roots_revocations.observed();
                    eprintln!(
                        "bifrost: bound MCP workspace source=roots/list root={}",
                        escape_terminal_text(root.to_string_lossy().as_ref())
                    );
                    return true;
                }
                Err(error) => last_error = Some(error.to_string()),
            }
        }

        match last_error {
            Some(error) => eprintln!("bifrost: no usable MCP workspace root: {error}"),
            None => {
                eprintln!("bifrost: MCP client returned no workspace roots; server remains unbound")
            }
        }
        false
    }

    /// Re-validate the Codex sandbox scope carried on this call.
    ///
    /// Codex clients do not implement MCP Roots; they restate their sandbox
    /// working directory in the `_meta` of every `tools/call`. Bifrost treats
    /// that as a per-call grant: any change, absence, or parse failure revokes
    /// the binding before the call proceeds, so a call can never run under a
    /// scope the current request did not itself authorize.
    fn reconcile_codex_sandbox_workspace(
        &self,
        state: &mut ConnectionState,
        meta: &rmcp::model::RequestMetaObject,
    ) -> Result<(), ErrorData> {
        if !state.accepts_codex_sandbox_state() {
            return Ok(());
        }

        let thread_id = meta.get("threadId").and_then(Value::as_str);
        let sandbox_cwd = meta
            .get(CODEX_SANDBOX_STATE_META_CAPABILITY)
            .and_then(|sandbox_state| sandbox_state.get("sandboxCwd"))
            .and_then(Value::as_str);

        let Some(sandbox_cwd) = sandbox_cwd else {
            self.revoke_codex_sandbox_workspace(state, thread_id, "metadata missing")?;
            log_codex_workspace_event("workspace metadata missing", thread_id);
            return Err(unbound_workspace_error());
        };

        let active_root = self.service.active_workspace_root();
        if state.workspace_binding_source == WorkspaceBindingSource::CodexSandboxState
            && state.codex_sandbox_cwd_uri.as_deref() == Some(sandbox_cwd)
            && state.codex_sandbox_root.is_some()
            && active_root.as_ref() == state.codex_sandbox_root.as_ref()
        {
            return Ok(());
        }

        let candidate = match file_uri_to_path(sandbox_cwd) {
            Ok(candidate) => candidate,
            Err(error) => {
                self.revoke_codex_sandbox_workspace(state, thread_id, "metadata invalid")?;
                log_codex_workspace_event(
                    &format!(
                        "rejected workspace metadata error={}",
                        escape_terminal_text(&error)
                    ),
                    thread_id,
                );
                return Err(ErrorData::invalid_params(
                    format!("Invalid Codex sandbox workspace metadata: {error}"),
                    None,
                ));
            }
        };

        if state.workspace_binding_source == WorkspaceBindingSource::CodexSandboxState {
            self.revoke_codex_sandbox_workspace(state, thread_id, "metadata changed")?;
        }

        if self.service.active_workspace_root().is_some() {
            self.service
                .unbind_client_workspace()
                .map_err(|error| map_service_error(error.code, error.message))?;
            state.clear_binding();
            log_codex_workspace_event(
                "revoked previous workspace reason=metadata changed",
                thread_id,
            );
        }

        match self.service.bind_client_workspace(candidate) {
            Ok(root) => {
                state.workspace_binding_source = WorkspaceBindingSource::CodexSandboxState;
                state.codex_sandbox_cwd_uri = Some(sandbox_cwd.to_string());
                state.codex_sandbox_root = Some(root.clone());
                log_codex_workspace_event(
                    &format!(
                        "bound MCP workspace source={CODEX_SANDBOX_STATE_META_CAPABILITY} root={}",
                        escape_terminal_text(root.to_string_lossy().as_ref())
                    ),
                    thread_id,
                );
                Ok(())
            }
            Err(error) => {
                state.clear_binding();
                log_codex_workspace_event(
                    &format!(
                        "failed workspace bind source={CODEX_SANDBOX_STATE_META_CAPABILITY} error={}",
                        escape_terminal_text(&error.message)
                    ),
                    thread_id,
                );
                Err(map_service_error(error.code, error.message))
            }
        }
    }

    fn revoke_codex_sandbox_workspace(
        &self,
        state: &mut ConnectionState,
        thread_id: Option<&str>,
        reason: &str,
    ) -> Result<(), ErrorData> {
        if state.workspace_binding_source != WorkspaceBindingSource::CodexSandboxState {
            return Ok(());
        }
        self.service
            .unbind_client_workspace()
            .map_err(|error| map_service_error(error.code, error.message))?;
        state.clear_binding();
        log_codex_workspace_event(&format!("revoked MCP workspace reason={reason}"), thread_id);
        Ok(())
    }

    /// Bind a workspace for a `2026-07-28` client, which has no post-handshake
    /// roots lifecycle to bind through.
    ///
    /// Returns `Some` when the client must answer a roots request before its
    /// tool call can run, and `None` when the call may proceed (already bound,
    /// not applicable, or this call carried the answer).
    ///
    /// Exactly one round is allowed. A client whose answer yields no usable
    /// root falls through to the ordinary unbound-workspace error rather than
    /// being asked again, so a misbehaving client cannot loop the server.
    #[allow(deprecated)] // Roots: see the note on the `Root` import.
    async fn activate_workspace_over_mrtr(
        &self,
        state: &mut ConnectionState,
        request: &CallToolRequestParams,
        context: &RequestContext<RoleServer>,
    ) -> Option<rmcp::model::InputRequiredResult> {
        if !state.accepts_client_roots
            || state.workspace_binding_source != WorkspaceBindingSource::None
        {
            return None;
        }
        // Gate on the negotiated revision rather than letting rmcp reject the
        // result for older peers: a legacy client should read Bifrost's plain
        // "not bound to a workspace" message, not an opaque protocol error.
        let speaks_mrtr = context.protocol_version().is_some_and(|version| {
            version.as_str() >= rmcp::model::ProtocolVersion::V_2026_07_28.as_str()
        });
        if !speaks_mrtr {
            return None;
        }

        let Some(request_state) = request.request_state.as_deref() else {
            return Some(rmcp::model::InputRequiredResult::new(
                Some(
                    [(
                        ROOTS_INPUT_REQUEST_KEY.to_string(),
                        rmcp::model::InputRequest::ListRoots(
                            rmcp::model::ListRootsRequest::default(),
                        ),
                    )]
                    .into_iter()
                    .collect(),
                ),
                Some(self.roots_activations.issue()),
            ));
        };

        // `requestState` is client-controlled and echoed verbatim, so it
        // authorizes nothing. It is only a nonce proving this call is the
        // retry of an activation Bifrost actually asked for; the roots
        // themselves are re-validated below exactly as on the legacy path.
        if !self.roots_activations.redeem(request_state) {
            eprintln!("bifrost: ignoring MCP roots activation with an unrecognized requestState");
            return None;
        }
        let roots = request
            .input_responses
            .as_ref()
            .and_then(|responses| responses.get(ROOTS_INPUT_REQUEST_KEY))
            .and_then(|value| {
                serde_json::from_value::<rmcp::model::ListRootsResult>(value.clone()).ok()
            });
        match roots {
            Some(result) => {
                self.bind_first_usable_root(state, &result.roots);
            }
            None => eprintln!(
                "bifrost: MCP roots activation retry carried no usable {ROOTS_INPUT_REQUEST_KEY} response"
            ),
        }
        None
    }

    /// Everything a tool call needs decided before it may touch the analyzer:
    /// authorization, scope, and argument normalization. Runs under the
    /// workspace lock so concurrent calls cannot interleave with a rebind.
    async fn prepare_tool_call(
        &self,
        state: &mut ConnectionState,
        name: &str,
        arguments: Value,
        meta: &rmcp::model::RequestMetaObject,
    ) -> Result<PreparedToolCall, ErrorData> {
        // A roots change that reached the transport before this call did
        // revokes the scope, whether or not its notification handler has run
        // yet. The counter comes from `RootsOrderedTransport`, which increments
        // it in wire order, so this comparison is what actually makes the rule
        // hold; `on_roots_list_changed` only makes revocation prompt.
        if self.client_roots_binding_is_stale(state) {
            self.revoke_client_roots(state);
        }

        self.reconcile_codex_sandbox_workspace(state, meta)?;

        // This is the first moment a workspace is actually needed, so it is
        // the moment to ask the client for one.
        if state.workspace_binding_source == WorkspaceBindingSource::None {
            self.activate_workspace_from_client_roots(state).await;
        }
        if state.workspace_binding_source == WorkspaceBindingSource::None {
            return Err(unbound_workspace_error());
        }
        let Some(workspace_root) = self.service.active_workspace_root() else {
            return Err(unbound_workspace_error());
        };

        if name == "activate_workspace" {
            let authority = match state.workspace_binding_source {
                WorkspaceBindingSource::ClientRoots => Some("MCP client roots"),
                WorkspaceBindingSource::CodexSandboxState => Some("Codex sandbox metadata"),
                WorkspaceBindingSource::None | WorkspaceBindingSource::ExplicitRoot => None,
            };
            if let Some(authority) = authority {
                return Ok(PreparedToolCall::Reply(tool_error_result(format!(
                    "activate_workspace is unavailable while the workspace is controlled by {authority}; update the client-provided workspace instead"
                ))));
            }
        }

        let arguments = match normalize_tool_arguments(name, arguments, &workspace_root) {
            Ok(arguments) => arguments,
            Err(message) => return Ok(PreparedToolCall::Reply(tool_error_result(message))),
        };

        Ok(PreparedToolCall::Ready {
            arguments,
            workspace_scope: (!serial_tool_request(name))
                .then(|| self.service.workspace_generation()),
        })
    }

    /// Run one prepared tool call on the blocking pool with a live analyzer
    /// cancellation token.
    ///
    /// Cancellation is the subtle part. `rmcp` signals cancellation on an async
    /// token, but the analyzer is synchronous and cooperative: it polls a
    /// Bifrost `CancellationToken` deep inside its traversals. A bridge task
    /// forwards one to the other, so an MCP cancellation stops the analyzer
    /// itself rather than merely dropping the handler's future and leaving a
    /// blocking thread grinding. That is why this awaits the join handle even
    /// after cancellation: what comes back is the analyzer's own truthful
    /// "cancelled/incomplete" result.
    async fn execute_tool(
        &self,
        name: String,
        arguments: Value,
        workspace_scope: Option<u64>,
        mcp_cancellation: McpCancellationToken,
    ) -> Result<CallToolResult, ErrorData> {
        let bifrost_cancellation = crate::CancellationToken::default()
            .with_deadline(Instant::now() + mcp_analyzer_request_budget());
        let _in_flight = self.in_flight.register(
            workspace_scope.unwrap_or_else(|| self.service.workspace_generation()),
            bifrost_cancellation.clone(),
        );

        let bridge_token = bifrost_cancellation.clone();
        let request_finished = McpCancellationToken::new();
        let bridge_guard = request_finished.clone().drop_guard();
        tokio::spawn(async move {
            tokio::select! {
                () = mcp_cancellation.cancelled() => bridge_token.cancel(),
                () = request_finished.cancelled() => {}
            }
        });

        let service = Arc::clone(&self.service);
        let render_options = RenderOptions {
            render_line_numbers: self.render_options.render_line_numbers,
        };
        let profiled_name = name.clone();
        let output = tokio::task::spawn_blocking(move || {
            let _execution_scope =
                profiling::scope(format!("mcp_request.execution[{profiled_name}]"));
            let output = service.call_tool_output_with_cancellation(
                &name,
                arguments,
                render_options,
                Some(&bifrost_cancellation),
            )?;
            if name == "get_summaries" {
                fit_get_summaries_output_to_budget(service.as_ref(), output, render_options)
            } else {
                Ok(output)
            }
        })
        .await
        .map_err(|error| {
            ErrorData::internal_error(format!("MCP tool execution panicked: {error}"), None)
        })?;
        drop(bridge_guard);

        // The workspace can be rebound while a call runs. Returning results
        // computed against a scope the client has since revoked would leak the
        // old workspace, so the result is discarded in favor of a retry hint.
        if workspace_scope.is_some_and(|scope| scope != self.service.workspace_generation()) {
            return Err(ErrorData::resource_not_found(
                "workspace changed while the tool call was running; retry the request",
                None,
            ));
        }

        match output {
            Ok(output) => Ok(tool_success_result(output)),
            Err(error) if error.code == SearchToolsServiceErrorCode::UnknownTool => {
                Ok(tool_error_result(error.message))
            }
            Err(error) => Err(map_service_error(error.code, error.message)),
        }
    }

    fn build_identity_meta(&self) -> MetaObject {
        let mut meta = MetaObject::new();
        meta.0.insert(
            BUILD_IDENTITY_META_KEY.to_string(),
            serde_json::Value::String(self.build_identity.clone()),
        );
        meta
    }
}

/// Outcome of tool-call preparation: either the call is authorized and ready
/// for the analyzer, or it already has its answer and never gets a slot.
enum PreparedToolCall {
    Ready {
        arguments: Value,
        /// The workspace generation this result is only valid for, or `None`
        /// for a tool whose whole job is to change the workspace. Rebinding
        /// tools hold the workspace lock for their duration, so nothing else
        /// can move the workspace underneath them, and checking their own
        /// change against them would fail every call.
        workspace_scope: Option<u64>,
    },
    Reply(CallToolResult),
}

fn tool_success_result(output: crate::ToolOutput) -> CallToolResult {
    match output {
        crate::ToolOutput::Text(text) => CallToolResult::success(vec![ContentBlock::text(text)]),
        crate::ToolOutput::Structured {
            structured,
            rendered_text,
        } => {
            // Agents read the rendered text; tooling reads the structured
            // payload. Both ship, as they did before this host existed.
            let text = rendered_text.unwrap_or_else(|| {
                serde_json::to_string(&structured)
                    .unwrap_or_else(|_| "Failed to serialize tool result".to_string())
            });
            let mut result = CallToolResult::success(vec![ContentBlock::text(text)]);
            result.structured_content = Some(structured);
            result
        }
    }
}

/// A failure the caller should read. MCP renders protocol errors opaquely, so
/// anything a user can act on has to come back as a tool result.
fn tool_error_result(message: String) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message)])
}

fn unbound_workspace_error() -> ErrorData {
    ErrorData::internal_error(UNBOUND_WORKSPACE_MESSAGE, None)
}

fn map_service_error(code: SearchToolsServiceErrorCode, message: String) -> ErrorData {
    match code {
        SearchToolsServiceErrorCode::InvalidParams => ErrorData::invalid_params(message, None),
        SearchToolsServiceErrorCode::UnknownTool => {
            ErrorData::new(rmcp::model::ErrorCode::METHOD_NOT_FOUND, message, None)
        }
        SearchToolsServiceErrorCode::Internal => ErrorData::internal_error(message, None),
    }
}

/// Echo the client's requested revision when it is one the SDK knows, and
/// otherwise fall back to the server's own. This mirrors what `rmcp`'s default
/// `initialize` does; Bifrost overrides `initialize` only to record
/// authorization state, not to change negotiation.
fn negotiated_protocol_version(
    request: &InitializeRequestParams,
    server_fallback: rmcp::model::ProtocolVersion,
) -> rmcp::model::ProtocolVersion {
    if rmcp::model::ProtocolVersion::KNOWN_VERSIONS.contains(&request.protocol_version) {
        request.protocol_version.clone()
    } else {
        server_fallback
    }
}

fn log_codex_workspace_event(event: &str, thread_id: Option<&str>) {
    match thread_id {
        Some(thread_id) => eprintln!(
            "bifrost: {event} thread_id={}",
            escape_terminal_text(thread_id)
        ),
        None => eprintln!("bifrost: {event}"),
    }
}

/// The single resource Bifrost publishes: agent guidance compiled into the
/// binary with `include_str!`.
fn agents_guidance_resource() -> Resource {
    Resource::new(AGENTS_GUIDANCE_URI, "bifrost-agents.md")
        .with_title("Bifrost AGENTS.md guidance")
        .with_description("Appendable agent instructions for Bifrost code-intelligence workflows.")
        .with_mime_type(AGENTS_GUIDANCE_MIME_TYPE)
        .with_annotations(
            Annotations::default()
                .with_audience(vec![Role::User, Role::Assistant])
                .with_priority(0.8),
        )
}

impl ServerHandler for BifrostMcpHandler {
    fn get_info(&self) -> ServerInfo {
        let mut info = InitializeResult::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
        )
        .with_server_info(Implementation::new("bifrost", env!("CARGO_PKG_VERSION")))
        .with_instructions(self.instructions);
        info.meta = Some(self.build_identity_meta());
        info
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        // Bifrost's tool list is small, fixed at process start, and
        // deliberately unpaginated: clients depend on seeing the whole
        // registry in one response.
        Ok(ListToolsResult::with_all_items(self.tools.clone()))
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        Ok(ListResourcesResult::with_all_items(vec![
            agents_guidance_resource(),
        ]))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        if request.uri != AGENTS_GUIDANCE_URI {
            return Err(ErrorData::resource_not_found(
                format!("Resource not found: {}", request.uri),
                None,
            ));
        }
        Ok(ReadResourceResult::new(vec![
            ResourceContents::text(AGENTS_GUIDANCE_TEXT, AGENTS_GUIDANCE_URI)
                .with_mime_type(AGENTS_GUIDANCE_MIME_TYPE),
        ])
        .into())
    }

    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, ErrorData> {
        let client_supports_roots = request.capabilities.roots.is_some();
        let client_is_codex = request.client_info.name == CODEX_MCP_CLIENT_NAME;
        let advertise_codex_sandbox_state = {
            let mut state = self.workspace.lock().await;
            if state.initialize_received {
                return Err(ErrorData::invalid_request(
                    "MCP initialize may only be sent once per connection",
                    None,
                ));
            }
            state.initialize_received = true;
            state.client_supports_roots = client_supports_roots;
            state.peer = Some(context.peer.clone());
            let protocol = if !state.accepts_client_roots {
                "explicit-root"
            } else if client_supports_roots {
                "mcp-roots"
            } else {
                "codex-sandbox-state"
            };
            eprintln!(
                "bifrost: MCP initialize client={} roots_supported={client_supports_roots} workspace_protocol={protocol}",
                if client_is_codex {
                    CODEX_MCP_CLIENT_NAME
                } else {
                    "other"
                },
            );
            state.accepts_codex_sandbox_state()
        };

        context.peer.set_peer_info(request.clone());
        let mut info = self.get_info();
        if advertise_codex_sandbox_state {
            // Tells a Codex client its per-call sandbox metadata will be
            // honored, which is how it learns it need not implement Roots.
            info.capabilities.experimental = Some(
                [(
                    CODEX_SANDBOX_STATE_META_CAPABILITY.to_string(),
                    serde_json::Map::new(),
                )]
                .into_iter()
                .collect(),
            );
        }
        info.protocol_version = negotiated_protocol_version(&request, info.protocol_version);
        Ok(info)
    }

    /// A roots change revokes the current scope and nothing more.
    ///
    /// Bifrost does not chase the new list here; the next request that needs a
    /// workspace asks for roots itself, which is what keeps that exchange free
    /// of ordering races. This handler exists only so revocation is *prompt* --
    /// it stops in-flight analyzer work rather than letting it run to
    /// completion against a scope the client withdrew. Correctness does not
    /// depend on it running before the next request, because
    /// `prepare_tool_call` re-checks the wire-ordered revocation counter.
    async fn on_roots_list_changed(&self, _context: NotificationContext<RoleServer>) {
        let mut state = self.workspace.lock().await;
        if !state.accepts_client_roots || !state.client_supports_roots {
            return;
        }
        // Guarded by the same staleness test the request path uses, because
        // this handler can be scheduled arbitrarily late: by the time it runs,
        // a tool call may already have re-negotiated a fresh scope, and tearing
        // that one down would fail a call the client is still waiting on.
        if self.client_roots_binding_is_stale(&state) {
            self.revoke_client_roots(&mut state);
        }
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let name = request.name.to_string();
        if !self.tool_names.contains(&name) {
            return Ok(tool_error_result(format!("Unknown tool: {name}")).into());
        }
        let arguments = request
            .arguments
            .clone()
            .map_or_else(|| json!({}), Value::Object);

        // `list_policies` reads only the built-in policy pack, so it needs
        // neither a workspace nor an analyzer slot.
        if name == "list_policies" {
            if !arguments
                .as_object()
                .is_some_and(|object| object.is_empty())
            {
                return Err(ErrorData::invalid_params(
                    "list_policies arguments must be an empty object",
                    None,
                ));
            }
            let output = self
                .service
                .call_tool_output_with_cancellation(
                    &name,
                    arguments,
                    RenderOptions::default(),
                    None,
                )
                .map_err(|error| map_service_error(error.code, error.message))?;
            return Ok(tool_success_result(output).into());
        }

        // Workspace-mutating tools stay ordered against everything else by
        // holding the workspace lock across execution; ordinary tools release
        // it once their scope and arguments are settled.
        let mut state = self.workspace.lock().await;
        if let Some(input_required) = self
            .activate_workspace_over_mrtr(&mut state, &request, &context)
            .await
        {
            return Ok(input_required.into());
        }
        let prepared = self
            .prepare_tool_call(&mut state, &name, arguments, &context.meta)
            .await?;
        self.in_flight
            .cancel_stale(self.service.workspace_generation());
        let (arguments, workspace_scope) = match prepared {
            PreparedToolCall::Reply(result) => return Ok(result.into()),
            PreparedToolCall::Ready {
                arguments,
                workspace_scope,
            } => (arguments, workspace_scope),
        };
        let _serial_guard = serial_tool_request(&name).then_some(state);

        let accepted_at = Instant::now();
        let Some(_permit) = self.analyzer_pool.acquire(&context.ct).await else {
            return Err(ErrorData::internal_error(
                "the tool call was cancelled while waiting for analyzer capacity",
                None,
            ));
        };
        profiling::duration(
            format!("mcp_request.queue_wait[{name}]"),
            accepted_at.elapsed(),
        );

        // Admission can take arbitrarily long, and the workspace may have been
        // rebound in the meantime. Re-check before spending a slot on a scope
        // the client no longer authorizes.
        if workspace_scope.is_some_and(|scope| scope != self.service.workspace_generation()) {
            return Err(ErrorData::resource_not_found(
                "workspace changed before the tool call could start; retry the request",
                None,
            ));
        }

        Ok(self
            .execute_tool(name, arguments, workspace_scope, context.ct.clone())
            .await?
            .into())
    }

    async fn on_custom_request(
        &self,
        request: CustomRequest,
        _context: RequestContext<RoleServer>,
    ) -> Result<CustomResult, ErrorData> {
        if request.method != BENCHMARK_PROFILE_BOUNDARY_METHOD {
            return Err(ErrorData::new(
                rmcp::model::ErrorCode::METHOD_NOT_FOUND,
                request.method,
                None,
            ));
        }
        // The benchmark brackets each measured request with this marker so it
        // can slice a single profiling stream into per-request segments.
        let mut stderr = std::io::stderr().lock();
        stderr
            .write_all(BENCHMARK_PROFILE_BOUNDARY_MARKER.as_bytes())
            .and_then(|()| stderr.flush())
            .map_err(|error| {
                ErrorData::internal_error(
                    format!("Failed to write benchmark profile boundary: {error}"),
                    None,
                )
            })?;
        Ok(CustomResult::new(serde_json::json!({})))
    }
}

/// Serve MCP over this process's standard input and output until the client
/// disconnects.
///
/// This is a blocking entry point because its callers are synchronous `main`
/// paths in `src/bin/bifrost.rs` and `crates/bifrost-mcp/src/bin`.
pub fn run_stdio_server_with_build_identity(
    root: Option<PathBuf>,
    render_options: McpRenderOptions,
    spec: &McpServerSpec,
    build_identity: &str,
) -> Result<(), String> {
    // Explicit roots build in the background. Rootless servers answer
    // initialize without touching process cwd and bind only from a
    // client-provided workspace.
    let accepts_client_roots = root.is_none();
    let watch_files = file_watching_enabled(std::env::var_os(MCP_FILE_WATCHER_ENV).as_deref())?;
    let service = Arc::new(match (root, watch_files) {
        (Some(root), true) => SearchToolsService::new_deferred(root)?,
        (Some(root), false) => SearchToolsService::new_deferred_manual(root)?,
        (None, true) => SearchToolsService::new_unbound(),
        (None, false) => SearchToolsService::new_unbound_manual(),
    });
    // The handler and the transport share this counter: the transport
    // increments it in wire order, the handler compares against it.
    let roots_revocations = Arc::new(RootsRevocations::default());
    let handler = BifrostMcpHandler::new(
        Arc::clone(&service),
        render_options,
        spec,
        build_identity,
        accepts_client_roots,
        Arc::clone(&roots_revocations),
    )?;

    // No IO driver: `tokio::io::stdin`/`stdout` run on the blocking pool, so
    // stdio needs no reactor. Only timers are needed, for request deadlines.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_time()
        .worker_threads(RUNTIME_WORKER_THREADS)
        .thread_name("bifrost-mcp")
        .build()
        .map_err(|error| format!("Failed to start the MCP runtime: {error}"))?;

    let result = runtime.block_on(async move {
        let running = handler
            .serve(RootsOrderedTransport::new(
                rmcp::transport::stdio().into_transport(),
                roots_revocations,
            ))
            .await
            .map_err(|error| format!("MCP initialization failed: {error}"))?;
        running
            .waiting()
            .await
            .map(|_| ())
            .map_err(|error| format!("MCP session ended abnormally: {error}"))
    });
    if result.is_ok() {
        // Normal shutdown (stdin reached EOF): the process is about to exit, so
        // skip the service's destructor. Dropping it would walk the whole
        // in-memory index freeing millions of allocations and tear down the
        // recursive file watcher -- a noticeable pause that the OS would
        // otherwise do for free on exit. We leak it deliberately: rmcp has
        // already drained and flushed the transport, and the analyzer DB is
        // durable -- every reconcile/update committed its WAL transaction
        // synchronously, so the next open recovers cleanly without the
        // checkpoint that `Drop` would run here. Error paths fall through and
        // drop normally.
        std::mem::forget(service);
    }
    result
}
