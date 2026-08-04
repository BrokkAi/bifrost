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

use crate::analyzer_pool::{
    ANALYZER_POOL_CAPACITY, Admission, AnalyzerExecutionPool, AnalyzerPermit,
    MAX_QUEUED_ANALYZER_REQUESTS,
};
use crate::mcp_common::{
    AGENTS_GUIDANCE_MIME_TYPE, AGENTS_GUIDANCE_TEXT, AGENTS_GUIDANCE_URI,
    BENCHMARK_PROFILE_BOUNDARY_MARKER, BENCHMARK_PROFILE_BOUNDARY_METHOD, CODEX_MCP_CLIENT_NAME,
    CODEX_SANDBOX_STATE_META_CAPABILITY, MCP_FILE_WATCHER_ENV, McpRenderOptions, McpServerSpec,
    UNBOUND_WORKSPACE_MESSAGE, attach_run_policy_correlation, client_root_to_path,
    file_uri_to_path, file_watching_enabled, fit_get_summaries_output_to_budget,
    mcp_analyzer_request_budget, request_correlation_id, serial_tool_request,
};
use crate::ordered_transport::{
    OutboundResponseTimings, ResponseTimingTransport, RootsOrderedTransport, RootsRevocations,
    transport_phase_label,
};
use crate::tool_arguments::normalize_tool_arguments;
use crate::{
    SearchToolsService, SearchToolsServiceErrorCode, policy::escape_terminal_text, profiling,
    searchtools_render::RenderOptions,
};
use rmcp::model::{
    Annotations, CacheScope, CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock,
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
use std::ffi::OsStr;
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

/// Env var selecting how much of `rmcp`'s diagnostic stream reaches stderr.
///
/// Defaults to warnings and errors: enough to see a transport failure or a
/// rejected request without narrating every message on a busy session.
#[doc(hidden)]
pub const MCP_LOG_LEVEL_ENV: &str = "BIFROST_MCP_LOG";

/// How long a client may treat the tool list as fresh.
///
/// The registry is fixed when the process starts -- it depends only on the
/// server mode and whether the workspace was a Git repository at launch --
/// so this is bounded by process lifetime, not by anything a client does.
/// Scoped private rather than public because two Bifrost servers started in
/// different modes publish different tools, and nothing in the response
/// identifies which mode produced it.
const TOOL_LIST_CACHE_TTL_MS: u64 = 300_000;

/// How long a client may treat the agent-guidance resource as fresh.
///
/// Its bytes are compiled into the binary with `include_str!`, so they are
/// identical for every client of a given build and cannot change while the
/// process lives. That makes it genuinely shareable, hence public.
const AGENTS_GUIDANCE_CACHE_TTL_MS: u64 = 3_600_000;

/// How long a request may queue for analyzer capacity before it is worth
/// telling an operator about.
const ANALYZER_QUEUE_WAIT_REPORT_THRESHOLD: std::time::Duration = std::time::Duration::from_secs(1);

/// How long to wait for a client to answer `roots/list`. A protocol
/// round-trip liveness bound, deliberately independent of the analyzer
/// request budget: an unresponsive client must not pin the binding task even
/// when tool calls run without a deadline.
const ROOTS_LIST_LIVENESS_BOUND: std::time::Duration = std::time::Duration::from_secs(5);

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
    /// What the handshake established, or nothing if it has not happened.
    ///
    /// This is a phase, not an attribute, and it is deliberately the *only*
    /// route to the values the handshake produces. Bifrost's client-supplied
    /// authorization sources -- MCP Roots and Codex sandbox metadata -- are
    /// meaningless before capability negotiation, so making them unreachable
    /// from `Handshake` turns "forgot to check whether initialize happened"
    /// into a compile error instead of a bypass. It has been exactly that
    /// bypass once already: an earlier version stored `initialize_received`
    /// beside `client_supports_roots` and a predicate simply stopped consulting
    /// it, which let a first-message `tools/call` bind an arbitrary directory
    /// through rmcp's stateless SEP-2575 lifecycle.
    negotiated: Option<NegotiatedConnection>,
    workspace_binding_source: WorkspaceBindingSource,
    codex_sandbox_cwd_uri: Option<String>,
    codex_sandbox_root: Option<PathBuf>,
    /// The revocation count the current binding was made under.
    ///
    /// Compared against [`RootsRevocations::observed`], which the transport
    /// increments in wire order. A request that sees a higher count knows the
    /// client revoked this scope before the request arrived, whatever order
    /// the notification handler and this request happen to be scheduled in.
    bound_at_revocation: u64,
}

/// What a completed `initialize` established about this client.
struct NegotiatedConnection {
    client_supports_roots: bool,
    /// Handle for asking this client questions.
    ///
    /// Needed because Bifrost requests roots from inside the tool call that
    /// needs a workspace, not from a lifecycle notification. See
    /// [`BifrostMcpHandler::activate_workspace_from_client_roots`].
    peer: rmcp::service::Peer<RoleServer>,
}

impl ConnectionState {
    fn new(accepts_client_roots: bool) -> Self {
        Self {
            accepts_client_roots,
            negotiated: None,
            workspace_binding_source: if accepts_client_roots {
                WorkspaceBindingSource::None
            } else {
                WorkspaceBindingSource::ExplicitRoot
            },
            codex_sandbox_cwd_uri: None,
            codex_sandbox_root: None,
            bound_at_revocation: 0,
        }
    }

    /// Codex sandbox metadata is only honored after a handshake, for a rootless
    /// server whose client has not supplied roots by some other route. An
    /// explicitly rooted server ignores client scope entirely.
    ///
    /// Both roots routes disqualify it, and for the same reason: an approved
    /// filesystem root outranks per-call metadata. The capability check alone
    /// is not enough, because a `2026-07-28` client activates over MRTR without
    /// advertising the Roots capability at all -- so keying only off that flag
    /// left such a client bound from its own roots and then immediately
    /// refused for "workspace metadata missing".
    fn accepts_codex_sandbox_state(&self) -> bool {
        if self.workspace_binding_source == WorkspaceBindingSource::ClientRoots {
            return false;
        }
        self.accepts_client_roots
            && self
                .negotiated
                .as_ref()
                .is_some_and(|negotiated| !negotiated.client_supports_roots)
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

/// How many roots activations may be outstanding at once.
///
/// A client that asks for activation and never retries must not grow server
/// memory, but the bound also has to sit above any plausible number of
/// concurrently unbound calls -- evicting a nonce a client is still going to
/// use turns a legitimate retry into an unexplainable "not bound to a
/// workspace". Tied to the analyzer backlog for that reason, and eviction is
/// logged so the residual case is diagnosable rather than silent.
const MAX_OUTSTANDING_ROOTS_ACTIVATIONS: usize = MAX_QUEUED_ANALYZER_REQUESTS;

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
            eprintln!(
                "bifrost: dropping the oldest of {MAX_OUTSTANDING_ROOTS_ACTIVATIONS} outstanding MCP roots activations; a retry against it will be refused"
            );
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
    /// Shared with [`ResponseTimingTransport`]: the handler arms a response's
    /// transport-phase timing here when its result is ready, and the transport
    /// emits `response_queue_wait` and `writer_delivery` when it delivers it.
    response_timings: Arc<OutboundResponseTimings>,
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
        response_timings: Arc<OutboundResponseTimings>,
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
            response_timings,
            workspace: tokio::sync::Mutex::new(ConnectionState::new(accepts_client_roots)),
        })
    }

    /// Ask a legacy (`2025-11-25`) client for its roots and bind one, for the
    /// request that needs a workspace right now.
    ///
    /// Two properties this has to get right, both learned the hard way.
    ///
    /// The exchange runs inside the tool call rather than from a lifecycle
    /// notification, because `rmcp` dispatches every notification and request
    /// on its own task and does not preserve arrival order. A background
    /// refresh would race the very requests it exists to serve. Consuming the
    /// answer in the request that asked for it removes that race by
    /// construction.
    ///
    /// The workspace lock is *not* held across the round trip. Holding it means
    /// every other tool call -- including trivial ones -- parks invisibly for
    /// as long as the client takes to answer, which for an IDE showing a
    /// folder-approval dialog is unbounded and not even cancellable. So the
    /// lock is dropped for the await and re-acquired to bind, and correctness
    /// across that gap comes from two re-checks rather than from exclusion:
    /// another call may have bound already, and the client may have revoked the
    /// roots it is about to name.
    #[allow(deprecated)] // Roots: see the note on the `Root` import.
    async fn ensure_client_workspace(&self, cancelled: &McpCancellationToken) {
        let (peer, revocations_at_request) = {
            let mut state = self.workspace.lock().await;
            if self.client_roots_binding_is_stale(&state) {
                self.revoke_client_roots(&mut state);
            }
            if !state.accepts_client_roots
                || state.workspace_binding_source != WorkspaceBindingSource::None
            {
                return;
            }
            let Some(negotiated) = state.negotiated.as_ref() else {
                eprintln!(
                    "bifrost: refusing to request MCP roots before the initialize handshake completes"
                );
                return;
            };
            if !negotiated.client_supports_roots {
                return;
            }
            // Snapshotted before the request goes out, so an answer that the
            // client supersedes mid-flight can be recognized as stale. Reading
            // it after the round trip would fold the revocation into the new
            // binding and mark the withdrawn scope permanently fresh.
            (negotiated.peer.clone(), self.roots_revocations.observed())
        };

        // Bounded and cancellable: a client that never answers must not pin a
        // request forever, and one that gives up must not keep us waiting.
        // This bounds client liveness on a protocol round trip, not analyzer
        // work, so it stays fixed even when the analyzer request budget is
        // unset or raised for an eval.
        let result = tokio::select! {
            result = tokio::time::timeout(ROOTS_LIST_LIVENESS_BOUND, peer.list_roots()) => result,
            () = cancelled.cancelled() => {
                eprintln!("bifrost: MCP roots/list abandoned; the client cancelled the request that asked for it");
                return;
            }
        };

        let mut state = self.workspace.lock().await;
        if state.workspace_binding_source != WorkspaceBindingSource::None {
            // A concurrent call already negotiated a workspace. Its binding is
            // as good as the one this answer would produce.
            return;
        }
        if self.roots_revocations.observed() != revocations_at_request {
            eprintln!(
                "bifrost: discarding a superseded MCP roots/list answer; the client changed its roots while the request was in flight"
            );
            return;
        }
        match result {
            Ok(Ok(result)) => {
                self.bind_first_usable_root(&mut state, &result.roots);
            }
            Ok(Err(error)) => eprintln!("bifrost: MCP roots/list failed: {error}"),
            Err(_elapsed) => eprintln!(
                "bifrost: MCP roots/list timed out after {ROOTS_LIST_LIVENESS_BOUND:?}; the client did not supply a workspace"
            ),
        }
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
        self.revoke_workspace(state, "changed MCP workspace roots");
    }

    /// The one way a workspace is given up.
    ///
    /// Unbinding, cancelling work admitted against the old scope, and clearing
    /// the connection's record of it are a single operation: a caller that
    /// performs two of the three leaves analyzer threads grinding against a
    /// directory the client has withdrawn. Splitting them by hand is how the
    /// Codex paths came to skip the cancellation.
    fn revoke_workspace(&self, state: &mut ConnectionState, reason: &str) {
        if let Err(error) = self.service.unbind_client_workspace() {
            eprintln!("bifrost: failed to revoke {reason}: {error}");
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
            self.revoke_codex_sandbox_workspace(state, thread_id, "metadata missing");
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
                self.revoke_codex_sandbox_workspace(state, thread_id, "metadata invalid");
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

        // One teardown, not two. This used to be a Codex-scoped revoke followed
        // by a near-identical "is anything bound?" revoke; the second was
        // unreachable given the first (reaching this function already implies
        // the binding can only be Codex or nothing), and two adjacent copies of
        // a security teardown guarded differently is how they drift apart.
        if self.service.active_workspace_root().is_some()
            || state.workspace_binding_source != WorkspaceBindingSource::None
        {
            self.revoke_workspace(state, "the previous workspace reason=metadata changed");
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
                self.revoke_workspace(state, "the failed Codex workspace bind");
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
    ) {
        if state.workspace_binding_source != WorkspaceBindingSource::CodexSandboxState {
            return;
        }
        self.revoke_workspace(state, &format!("the Codex workspace reason={reason}"));
        log_codex_workspace_event(&format!("revoked MCP workspace reason={reason}"), thread_id);
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
        if !speaks_2026_07_28(context) {
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
        match request
            .input_responses
            .as_ref()
            .and_then(|responses| responses.get(ROOTS_INPUT_REQUEST_KEY))
        {
            None => eprintln!(
                "bifrost: MCP roots activation retry carried no `{ROOTS_INPUT_REQUEST_KEY}` response"
            ),
            Some(value) => {
                match serde_json::from_value::<rmcp::model::ListRootsResult>(value.clone()) {
                    Ok(result) => {
                        self.bind_first_usable_root(state, &result.roots);
                    }
                    // The error names the offending field; "no usable response"
                    // alone leaves a client author nothing to act on.
                    Err(error) => eprintln!(
                        "bifrost: MCP roots activation retry carried an unreadable `{ROOTS_INPUT_REQUEST_KEY}` response: {error}"
                    ),
                }
            }
        }
        None
    }

    /// Everything a tool call needs decided before it may touch the analyzer:
    /// authorization, scope, and argument normalization. Runs under the
    /// workspace lock so concurrent calls cannot interleave with a rebind.
    fn prepare_tool_call(
        &self,
        state: &mut ConnectionState,
        name: &str,
        arguments: Value,
        meta: &rmcp::model::RequestMetaObject,
    ) -> Result<PreparedToolCall, ErrorData> {
        // Defence in depth, independent of every binding source below. rmcp's
        // stateless SEP-2575 lifecycle serves a request whose `_meta` carries
        // the required keys without ever calling `initialize`, so "a tool call
        // implies a completed handshake" is false. A client-supplied workspace
        // is only meaningful once capabilities have been negotiated, and an
        // explicitly rooted server has nothing to negotiate.
        if state.accepts_client_roots && state.negotiated.is_none() {
            eprintln!(
                "bifrost: refusing a workspace tool call received before the initialize handshake"
            );
            return Err(unbound_workspace_error());
        }

        // A roots change that reached the transport before this call did
        // revokes the scope, whether or not its notification handler has run
        // yet. The counter comes from `RootsOrderedTransport`, which increments
        // it in wire order, so this comparison is what actually makes the rule
        // hold; `on_roots_list_changed` only makes revocation prompt.
        if self.client_roots_binding_is_stale(state) {
            self.revoke_client_roots(state);
        }

        self.reconcile_codex_sandbox_workspace(state, meta)?;

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
    /// blocking thread grinding. It awaits the analyzer's own truthful
    /// "cancelled/incomplete" result while work completes within budget; once
    /// the deadline expires, it returns promptly and leaves that bounded work
    /// holding its analyzer slot until cancellation unwinds it.
    #[allow(clippy::too_many_arguments)]
    async fn execute_tool(
        &self,
        name: String,
        arguments: Value,
        workspace_scope: Option<u64>,
        deadline: Option<Instant>,
        request_correlation_id: Option<String>,
        mcp_cancellation: McpCancellationToken,
        permit: AnalyzerPermit,
    ) -> Result<CallToolResult, ErrorData> {
        // The deadline was set when the request was accepted, not when it
        // reached the analyzer, so time already spent queueing counts against
        // it. A request that waited most of its budget gets what remains.
        let bifrost_cancellation = match deadline {
            Some(deadline) => crate::CancellationToken::default().with_deadline(deadline),
            None => crate::CancellationToken::default(),
        };
        let in_flight = self.in_flight.register(
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
        let execution_label =
            transport_phase_label("execution", &name, request_correlation_id.as_deref());
        let execution_name = name.clone();
        let execution_cancellation = bifrost_cancellation.clone();
        let mut output = tokio::task::spawn_blocking(move || {
            // Keep both the analyzer slot and the revocation registration until
            // cooperative cancellation has actually unwound the blocking work.
            // A timed-out client call must not free capacity for another scan
            // while its original scan is still consuming CPU.
            let _permit = permit;
            let _in_flight = in_flight;
            let _bridge_guard = bridge_guard;
            let _execution_scope = profiling::scope(execution_label);
            let output = service.call_tool_output_with_cancellation(
                &execution_name,
                arguments,
                render_options,
                Some(&execution_cancellation),
            )?;
            let output = if execution_name == "get_summaries" {
                fit_get_summaries_output_to_budget(service.as_ref(), output, render_options)?
            } else {
                output
            };
            // run_policy reports carry a hash of the request id so a policy
            // report in a log can be tied back to the call that produced it
            // without the raw id, which is client-controlled, ever being
            // logged. Shared with the fallback host so both emit the same
            // value for the same wire id.
            Ok::<_, crate::SearchToolsServiceError>(if execution_name == "run_policy" {
                attach_run_policy_correlation(output, request_correlation_id.as_deref())
            } else {
                output
            })
        });
        let output = tokio::select! {
            output = &mut output => output.map_err(|error| {
                ErrorData::internal_error(format!("MCP tool execution panicked: {error}"), None)
            })?,
            () = async {
                match deadline {
                    Some(deadline) => {
                        tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await
                    }
                    None => std::future::pending().await,
                }
            } => {
                bifrost_cancellation.cancel();
                let budget = mcp_analyzer_request_budget()
                    .expect("the deadline arm is reachable only when a budget is configured");
                return Err(ErrorData::internal_error(
                    format!("{name} exhausted its {budget:?} request budget; cancellation continues in the background"),
                    None,
                ));
            }
        };

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
        // A request that ran out of its budget is a server-side condition, not
        // a malformed request; the message already says which deadline.
        SearchToolsServiceErrorCode::DeadlineExceeded => ErrorData::internal_error(message, None),
        SearchToolsServiceErrorCode::Internal => ErrorData::internal_error(message, None),
    }
}

/// Whether this request's peer negotiated MCP `2026-07-28` or newer.
///
/// Gates every field that revision added. `rmcp` strips `resultType` for a
/// legacy peer but not the cache hints, so emitting those unconditionally
/// would put fields on the wire that a `2025-11-25` client has no schema for.
fn speaks_2026_07_28(context: &RequestContext<RoleServer>) -> bool {
    context
        .protocol_version()
        .is_some_and(|version| version >= rmcp::model::ProtocolVersion::V_2026_07_28)
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
        let result = ListToolsResult::with_all_items(self.tools.clone());
        Ok(if speaks_2026_07_28(&_context) {
            result
                .with_ttl_ms(TOOL_LIST_CACHE_TTL_MS)
                .with_cache_scope(CacheScope::Private)
        } else {
            result
        })
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        let result = ListResourcesResult::with_all_items(vec![agents_guidance_resource()]);
        Ok(if speaks_2026_07_28(&_context) {
            result
                .with_ttl_ms(AGENTS_GUIDANCE_CACHE_TTL_MS)
                .with_cache_scope(CacheScope::Public)
        } else {
            result
        })
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
        let result = ReadResourceResult::new(vec![
            ResourceContents::text(AGENTS_GUIDANCE_TEXT, AGENTS_GUIDANCE_URI)
                .with_mime_type(AGENTS_GUIDANCE_MIME_TYPE),
        ]);
        Ok(if speaks_2026_07_28(&_context) {
            result
                .with_ttl_ms(AGENTS_GUIDANCE_CACHE_TTL_MS)
                .with_cache_scope(CacheScope::Public)
                .into()
        } else {
            result.into()
        })
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
            if state.negotiated.is_some() {
                return Err(ErrorData::invalid_request(
                    "MCP initialize may only be sent once per connection",
                    None,
                ));
            }
            state.negotiated = Some(NegotiatedConnection {
                client_supports_roots,
                peer: context.peer.clone(),
            });
            let protocol = if !state.accepts_client_roots {
                "explicit-root"
            } else if client_supports_roots {
                "mcp-roots"
            } else {
                "codex-sandbox-state"
            };
            eprintln!(
                "bifrost: MCP host=rmcp client={} roots_supported={client_supports_roots} workspace_protocol={protocol}",
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
        if !state.accepts_client_roots
            || !state
                .negotiated
                .as_ref()
                .is_some_and(|negotiated| negotiated.client_supports_roots)
        {
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
            // Onto the blocking pool like every other tool: the first call
            // parses the built-in policy packs, and RUNTIME_WORKER_THREADS is
            // only defensible while no Bifrost work runs on a runtime worker.
            // Two concurrent calls here would otherwise occupy both workers and
            // stop the serve loop from reading the transport at all.
            let service = Arc::clone(&self.service);
            let output = tokio::task::spawn_blocking(move || {
                service.call_tool_output_with_cancellation(
                    "list_policies",
                    arguments,
                    RenderOptions::default(),
                    None,
                )
            })
            .await
            .map_err(|error| {
                ErrorData::internal_error(format!("list_policies panicked: {error}"), None)
            })?
            .map_err(|error| map_service_error(error.code, error.message))?;
            return Ok(tool_success_result(output).into());
        }

        // Negotiating a workspace can require a client round trip, so it
        // happens before the preparation lock is taken -- see
        // `ensure_client_workspace`.
        self.ensure_client_workspace(&context.ct).await;

        // Workspace-mutating tools stay ordered against everything else by
        // holding the workspace lock across execution; ordinary tools release
        // it once their scope and arguments are settled.
        let mut state = self.workspace.lock().await;
        // Revocation is tested before MRTR activation, not after. A stale
        // client-roots binding still reads as "bound", so checking it later
        // would make `activate_workspace_over_mrtr` return early and send a
        // 2026-07-28 client a flat unbound error where it should have been
        // offered another activation round.
        if self.client_roots_binding_is_stale(&state) {
            self.revoke_client_roots(&mut state);
        }
        if let Some(input_required) = self
            .activate_workspace_over_mrtr(&mut state, &request, &context)
            .await
        {
            return Ok(input_required.into());
        }
        let prepared = self.prepare_tool_call(&mut state, &name, arguments, &context.meta)?;
        self.in_flight
            .cancel_stale(self.service.workspace_generation());
        let (arguments, workspace_scope) = match prepared {
            PreparedToolCall::Reply(result) => return Ok(result.into()),
            PreparedToolCall::Ready {
                arguments,
                workspace_scope,
            } => (arguments, workspace_scope),
        };
        // Workspace-mutating tools keep the workspace lock for their whole
        // execution, which already bounds them to one at a time. Making them
        // also queue for an analyzer permit would let a trivial call like
        // `get_active_workspace` sit behind four long scans *while holding the
        // lock*, stalling every other request's preparation -- the opposite of
        // what the pool exists to protect.
        // Derived from the wire id the same way the fallback host derives it,
        // so the two never disagree about a report's correlation value.
        let correlation_id = serde_json::to_value(&context.id)
            .ok()
            .map(|id| request_correlation_id(&id));
        let serial = serial_tool_request(&name);
        let _serial_guard = serial.then_some(state);

        // Session initialization is not request work. A deferred index build
        // runs in the background from the moment the workspace binds; a cold
        // first batch that started its budget clock here would spend the whole
        // budget waiting for that build and fail without observing a single
        // file (#1423, #1419). Wait for the snapshot first -- honoring client
        // cancellation but no deadline -- and only then start the clock. Warm
        // requests observe no pending build and pass straight through.
        if !serial {
            let service = Arc::clone(&self.service);
            let ct = context.ct.clone();
            tokio::task::spawn_blocking(move || {
                service.wait_workspace_ready(&|| ct.is_cancelled())
            })
            .await
            .map_err(|error| {
                ErrorData::internal_error(
                    format!("workspace readiness wait panicked: {error}"),
                    None,
                )
            })?
            .map_err(|error| map_service_error(error.code, error.message))?;
        }

        // One deadline spans admission and execution. Starting the clock after
        // admission would make the request budget mean "time spent analyzing"
        // while a client experiences queue wait plus a full budget -- and the
        // `mcp_fairness` p95 gate in benchmark/interactive-latency.toml is
        // written against what the client experiences.
        let accepted_at = Instant::now();
        let deadline = mcp_analyzer_request_budget().map(|budget| accepted_at + budget);
        let admission = if serial {
            Ok(Admission::Granted(AnalyzerPermit::exempt()))
        } else {
            match deadline {
                Some(deadline) => {
                    tokio::time::timeout(
                        deadline.saturating_duration_since(Instant::now()),
                        self.analyzer_pool.acquire(&context.ct),
                    )
                    .await
                }
                None => Ok(self.analyzer_pool.acquire(&context.ct).await),
            }
        };
        let permit = match admission {
            Ok(Admission::Granted(permit)) => permit,
            Ok(Admission::Cancelled) => {
                return Err(ErrorData::internal_error(
                    "the tool call was cancelled while waiting for analyzer capacity",
                    None,
                ));
            }
            Ok(Admission::Saturated) => {
                eprintln!(
                    "bifrost: refusing {name}; more than {} analyzer requests are already queued",
                    crate::analyzer_pool::MAX_QUEUED_ANALYZER_REQUESTS
                );
                return Err(ErrorData::internal_error(
                    format!(
                        "too many analyzer requests are queued; retry {name} once earlier calls complete"
                    ),
                    None,
                ));
            }
            Err(_elapsed) => {
                let budget = mcp_analyzer_request_budget()
                    .expect("admission can only time out when a budget is configured");
                eprintln!(
                    "bifrost: {name} exhausted its {budget:?} budget waiting for analyzer capacity"
                );
                return Err(ErrorData::internal_error(
                    format!("{name} timed out waiting for analyzer capacity"),
                    None,
                ));
            }
        };
        let queue_wait = accepted_at.elapsed();
        profiling::duration(
            transport_phase_label("queue_wait", &name, correlation_id.as_deref()),
            queue_wait,
        );
        if queue_wait >= ANALYZER_QUEUE_WAIT_REPORT_THRESHOLD {
            // Otherwise a saturated pool is invisible without BIFROST_TIMING,
            // and every client just appears slow for no stated reason.
            eprintln!(
                "bifrost: {name} waited {queue_wait:?} for one of {ANALYZER_POOL_CAPACITY} analyzer slots"
            );
        }

        // Admission can take arbitrarily long, and the workspace may have been
        // rebound in the meantime. Re-check before spending a slot on a scope
        // the client no longer authorizes.
        if workspace_scope.is_some_and(|scope| scope != self.service.workspace_generation()) {
            return Err(ErrorData::resource_not_found(
                "workspace changed before the tool call could start; retry the request",
                None,
            ));
        }

        let response = self
            .execute_tool(
                name.clone(),
                arguments,
                workspace_scope,
                deadline,
                correlation_id.clone(),
                context.ct.clone(),
                permit,
            )
            .await;
        // The response -- success or execution error -- is ready the moment
        // execute_tool returns; everything after this point is transport. Arm
        // the timing keyed by the wire id so the transport wrapper can emit
        // `response_queue_wait` and `writer_delivery` when it delivers it,
        // matching the hand-written host's writer-thread phases (#1491).
        self.response_timings
            .arm(context.id.clone(), name, correlation_id);
        Ok(response?.into())
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

/// Route `rmcp`'s `tracing` events to stderr.
///
/// Without this every event the SDK emits is discarded, including the ones an
/// operator most needs: transport send failures, requests rejected for
/// lifecycle violations, and join errors. stdout is the protocol channel, so
/// diagnostics must go to stderr and nowhere else.
fn install_protocol_diagnostics(level: Option<&OsStr>) -> Result<(), String> {
    let level = match level.map(OsStr::to_string_lossy).as_deref() {
        None | Some("warn") => tracing::Level::WARN,
        Some("off") => return Ok(()),
        Some("error") => tracing::Level::ERROR,
        Some("info") => tracing::Level::INFO,
        Some("debug") => tracing::Level::DEBUG,
        Some("trace") => tracing::Level::TRACE,
        Some(other) => {
            return Err(format!(
                "{MCP_LOG_LEVEL_ENV} must be off, error, warn, info, debug, or trace, not `{other}`"
            ));
        }
    };
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(level)
        .with_ansi(false)
        .try_init()
        .map_err(|error| format!("Failed to install MCP diagnostics: {error}"))
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
    install_protocol_diagnostics(std::env::var_os(MCP_LOG_LEVEL_ENV).as_deref())?;

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
    // Shared the same way: the handler arms a response's timing when its
    // result is ready, and the transport emits the delivery phases.
    let response_timings = Arc::new(OutboundResponseTimings::default());
    let handler = BifrostMcpHandler::new(
        Arc::clone(&service),
        render_options,
        spec,
        build_identity,
        accepts_client_roots,
        Arc::clone(&roots_revocations),
        Arc::clone(&response_timings),
    )?;

    // No IO driver: `tokio::io::stdin`/`stdout` run on the blocking pool, so
    // stdio needs no reactor. Only timers are needed, for request deadlines.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_time()
        .worker_threads(RUNTIME_WORKER_THREADS)
        // The analyzer pool bounds concurrent analyzer executions, so this is
        // a backstop rather than the operative limit: it keeps any future
        // `spawn_blocking` outside the pool from quietly growing toward
        // tokio's default of 512, each of which fans out onto rayon.
        .max_blocking_threads(ANALYZER_POOL_CAPACITY + RUNTIME_WORKER_THREADS)
        .thread_name("bifrost-mcp")
        .build()
        .map_err(|error| format!("Failed to start the MCP runtime: {error}"))?;

    let result = runtime.block_on(async move {
        let running = handler
            .serve(RootsOrderedTransport::new(
                ResponseTimingTransport::new(
                    rmcp::transport::stdio().into_transport(),
                    response_timings,
                ),
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
    // Never drop the runtime implicitly. `tokio::io::stdin` reads on a blocking
    // thread that cannot be cancelled, and rmcp's serve loop polls it in a
    // `select!`, so a losing branch leaves a read parked in the pool. The
    // runtime's `Drop` waits for blocking work forever, which on any exit that
    // is not a clean EOF would leave a zombie process holding the whole
    // in-memory index and the file watcher. The process is exiting either way.
    runtime.shutdown_background();

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
