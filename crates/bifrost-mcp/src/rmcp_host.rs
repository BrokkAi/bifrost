//! Bifrost's MCP host, built on `rmcp` (the official Model Context Protocol
//! Rust SDK).
//!
//! `rmcp` owns everything that is protocol: JSON-RPC framing over stdio,
//! revision negotiation, method dispatch, wire types, response serialization,
//! and cancellation plumbing. This module owns everything that is Bifrost:
//! server identity, the tool registry, workspace authorization, the Codex
//! sandbox boundary, analyzer admission, and response budgets.
//!
//! The `rmcp` adoption is tracked by #1328.

use crate::analyzer_pool::{
    ANALYZER_POOL_CAPACITY, Admission, AnalyzerExecutionPool, AnalyzerPermit,
    MAX_QUEUED_ANALYZER_REQUESTS,
};
use crate::mcp_common::{
    AGENTS_GUIDANCE_MIME_TYPE, AGENTS_GUIDANCE_TEXT, AGENTS_GUIDANCE_URI,
    BENCHMARK_PROFILE_BOUNDARY_MARKER, BENCHMARK_PROFILE_BOUNDARY_METHOD, CODEX_MCP_CLIENT_NAME,
    CODEX_SANDBOX_STATE_META_CAPABILITY, MCP_DISCOVERY_TEXT_MAX_CHARS, MCP_FILE_WATCHER_ENV,
    McpRenderOptions, McpServerSpec, RequestBudget, UNBOUND_WORKSPACE_MESSAGE,
    analyzer_stop_deadline, attach_run_policy_correlation, attach_run_policy_correlation_result,
    client_root_to_path, file_uri_to_path, file_watching_enabled,
    fit_get_summaries_output_to_budget, request_correlation_id, serial_tool_request,
    usage_scan_soft_deadline, validate_mcp_analyzer_request_budget_env,
};
use crate::ordered_transport::{
    OutboundResponseTimings, ResponseTimingTransport, RootsOrderedTransport, RootsRevocations,
    transport_phase_label,
};
use crate::tool_arguments::normalize_tool_arguments;
use crate::{
    SearchToolsService, SearchToolsServiceErrorCode,
    policy::escape_terminal_text,
    profiling,
    searchtools_render::RenderOptions,
    searchtools_service::{PreparedRunPolicyPreflight, RunPolicyPreflight, TransportTimings},
};
use brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext;
use rmcp::model::{
    Annotations, CacheScope, CallToolRequestParams, CallToolResponse, CallToolResult,
    CancelTaskParams, ContentBlock, CreateTaskResult, CustomRequest, CustomResult, ErrorData,
    GetTaskParams, GetTaskResult, Implementation, InitializeRequestParams, InitializeResult,
    ListPromptsResult, ListResourceTemplatesResult, ListResourcesResult, ListToolsResult,
    MetaObject, PaginatedRequestParams, ProtocolVersion, ReadResourceRequestParams,
    ReadResourceResponse, ReadResourceResult, Resource, ResourceContents, Role, ServerCapabilities,
    ServerInfo, TASKS_EXTENSION_ID, Tool, UpdateTaskParams,
};
use rmcp::task_manager::{TaskContext, TaskExit, TaskManager, TaskOptions};
// MCP 2026-07-28 deprecates Roots wholesale (SEP-2577) without yet shipping a
// replacement for "which directory may this server analyze". Bifrost's whole
// security model depends on that answer, and every client Bifrost is
// configured against still speaks Roots, so the deprecated surface is used
// deliberately until SEP-2577's successor exists (#1328).
#[allow(deprecated)]
use rmcp::model::Root;
use rmcp::service::{NotificationContext, QuitReason, RequestContext};
use rmcp::transport::IntoTransport;
use rmcp::{RoleServer, ServerHandler, ServiceExt};
use serde_json::{Value, json};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken as McpCancellationToken;

/// `_meta` key carrying the identity of the binary that hosts this MCP server.
///
/// Bifrost used to publish this as `serverInfo.buildIdentity`, but
/// `rmcp::model::Implementation` is a closed struct with no extension point.
/// `_meta` is the protocol's sanctioned place for vendor fields, so the facade
/// identity moves here. Consumers: `tests/suite_mcp_cli/mcp_build_identity_facade.rs` and
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

/// One fixed workspace exposed by a named multi-workspace MCP server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedWorkspace {
    pub name: String,
    pub root: PathBuf,
}

impl NamedWorkspace {
    pub fn new(name: String, root: PathBuf) -> Self {
        Self { name, root }
    }
}

struct NamedWorkspaceEntry {
    id: u64,
    name: String,
    root: PathBuf,
    service: Mutex<Option<Arc<SearchToolsService>>>,
}

struct NamedWorkspaceRouter {
    entries: Vec<NamedWorkspaceEntry>,
    by_name: HashMap<String, usize>,
    watch_files: bool,
    /// The one host context every named workspace's service is built with.
    host_activation: Arc<HostActivationContext>,
}

impl NamedWorkspaceRouter {
    fn new(
        workspaces: Vec<NamedWorkspace>,
        watch_files: bool,
        host: Arc<HostActivationContext>,
    ) -> Result<Self, String> {
        if workspaces.is_empty() {
            return Err("named workspace mode requires at least one workspace".to_string());
        }

        let mut entries = Vec::with_capacity(workspaces.len());
        let mut by_name = HashMap::with_capacity(workspaces.len());
        let mut roots = HashSet::with_capacity(workspaces.len());
        for (index, workspace) in workspaces.into_iter().enumerate() {
            validate_workspace_name(&workspace.name)?;
            if by_name.contains_key(&workspace.name) {
                return Err(format!(
                    "workspace name `{}` was provided more than once",
                    workspace.name
                ));
            }
            let root = workspace.root.canonicalize().map_err(|error| {
                format!(
                    "Failed to resolve workspace `{}` at {}: {error}",
                    workspace.name,
                    workspace.root.display()
                )
            })?;
            if !root.is_dir() {
                return Err(format!(
                    "workspace `{}` is not a directory: {}",
                    workspace.name,
                    root.display()
                ));
            }
            if !roots.insert(root.clone()) {
                return Err(format!(
                    "workspace path was provided more than once: {}",
                    root.display()
                ));
            }
            let service = if index == 0 {
                Some(Arc::new(new_workspace_service(&root, watch_files, &host)?))
            } else {
                None
            };
            by_name.insert(workspace.name.clone(), index);
            entries.push(NamedWorkspaceEntry {
                id: index as u64 + 1,
                name: workspace.name,
                root,
                service: Mutex::new(service),
            });
        }
        Ok(Self {
            entries,
            by_name,
            watch_files,
            host_activation: host,
        })
    }

    fn primary_service(&self) -> Arc<SearchToolsService> {
        self.service_by_index(0)
            .expect("the validated first named workspace must initialize")
    }

    fn service(&self, name: &str) -> Result<(u64, Arc<SearchToolsService>), String> {
        let Some(index) = self.by_name.get(name).copied() else {
            return Err(format!(
                "unknown workspace `{name}`; expected one of {:?}",
                self.names()
            ));
        };
        Ok((self.entries[index].id, self.service_by_index(index)?))
    }

    fn service_by_index(&self, index: usize) -> Result<Arc<SearchToolsService>, String> {
        let entry = &self.entries[index];
        let mut service = entry
            .service
            .lock()
            .map_err(|_| format!("workspace `{}` service lock poisoned", entry.name))?;
        if service.is_none() {
            *service = Some(Arc::new(new_workspace_service(
                &entry.root,
                self.watch_files,
                &self.host_activation,
            )?));
        }
        Ok(Arc::clone(
            service
                .as_ref()
                .expect("named workspace service was initialized"),
        ))
    }

    fn names(&self) -> Vec<&str> {
        self.entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect()
    }

    fn names_for_tool(&self, _tool_name: &str) -> Vec<&str> {
        self.names()
    }

    fn instructions(&self, base: &str) -> Result<String, String> {
        let mut instructions = String::from(base);
        instructions.push_str(
            "\n\nNamed workspace mode is active. Set the workspace argument to the workspace that contains the target code.",
        );
        let instruction_chars = instructions.chars().count();
        if instruction_chars > MCP_DISCOVERY_TEXT_MAX_CHARS {
            return Err(format!(
                "named-workspace MCP server instructions contain {instruction_chars} characters; maximum is {MCP_DISCOVERY_TEXT_MAX_CHARS}"
            ));
        }
        Ok(instructions)
    }
}

fn new_workspace_service(
    root: &Path,
    watch_files: bool,
    host: &Arc<HostActivationContext>,
) -> Result<SearchToolsService, String> {
    let host = Arc::clone(host);
    if watch_files {
        SearchToolsService::new_deferred_with_host_activation_context(root.to_path_buf(), host)
    } else {
        SearchToolsService::new_deferred_manual_with_host_activation_context(
            root.to_path_buf(),
            host,
        )
    }
}

fn validate_workspace_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || !name
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        return Err(format!(
            "workspace name `{name}` must start with an ASCII letter or digit and contain only letters, digits, '.', '_', or '-'"
        ));
    }
    Ok(())
}

fn named_workspace_descriptors(
    descriptors: &[Value],
    router: &NamedWorkspaceRouter,
) -> Result<Vec<Value>, String> {
    descriptors
        .iter()
        .filter(|descriptor| {
            !matches!(
                descriptor.get("name").and_then(Value::as_str),
                Some("activate_workspace" | "get_active_workspace")
            )
        })
        .map(|descriptor| {
            let mut descriptor = descriptor.clone();
            let name = descriptor
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| "tool descriptor missing string name".to_string())?
                .to_string();
            if name == "list_policies" {
                return Ok(descriptor);
            }
            let names = router.names_for_tool(&name);
            let schema = descriptor
                .get_mut("inputSchema")
                .and_then(Value::as_object_mut)
                .ok_or_else(|| format!("tool descriptor `{name}` has no object input schema"))?;
            let old_properties = schema
                .remove("properties")
                .and_then(|properties| properties.as_object().cloned())
                .unwrap_or_default();
            let mut properties = serde_json::Map::with_capacity(old_properties.len() + 1);
            properties.insert(
                "workspace".to_string(),
                json!({
                    "type": "string",
                    "enum": names,
                    "description": "Named workspace that contains the code for this call."
                }),
            );
            properties.extend(old_properties);
            schema.insert("properties".to_string(), Value::Object(properties));

            let mut required = schema
                .remove("required")
                .and_then(|required| required.as_array().cloned())
                .unwrap_or_default();
            required.insert(0, Value::String("workspace".to_string()));
            schema.insert("required".to_string(), Value::Array(required));
            Ok(descriptor)
        })
        .collect()
}

/// Where the currently bound workspace came from.
///
/// This is the authorization record for every tool call: Bifrost analyzes a
/// directory only because one of these sources granted it.
///
/// Each source carries exactly the data that belongs to it, so a binding
/// cannot hold Codex sandbox metadata under client roots, or a revocation
/// count under a Codex binding.
#[derive(Debug, Clone, PartialEq, Eq)]
enum WorkspaceBinding {
    /// Nothing is bound. Every workspace tool is refused.
    Unbound,
    /// The operator passed `--root`, so the client cannot change the scope.
    ExplicitRoot,
    /// The MCP client answered `roots/list`.
    ClientRoots {
        /// The revocation count this binding was made under.
        ///
        /// Compared against [`RootsRevocations::observed`], which the
        /// transport increments in wire order. A request that sees a higher
        /// count knows the client revoked this scope before the request
        /// arrived, whatever order the notification handler and this request
        /// happen to be scheduled in.
        bound_at_revocation: u64,
    },
    /// A Codex client supplied sandbox metadata on a `tools/call`.
    CodexSandbox {
        /// The `sandboxCwd` URI the client sent.
        cwd_uri: String,
        /// The root that URI bound.
        root: PathBuf,
    },
}

/// Per-connection workspace authorization state.
///
/// RMCP owns the lifecycle, outbound request ids, and `roots/list` calls.
/// Bifrost therefore keeps only the authorization state.
struct ConnectionState {
    accepts_client_roots: bool,
    /// What the legacy `initialize` handshake established, or nothing if it
    /// has not happened.
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
    ///
    /// Connection-level negotiation is the *legacy* form. A `2026-07-28`
    /// request negotiates version and capabilities per request instead,
    /// carried in its own `_meta` and validated by rmcp before dispatch;
    /// [`request_negotiates_per_request`] recognizes that form. Such a
    /// request never populates this field, and its roots come from the MRTR
    /// exchange rather than a server-initiated `roots/list` -- so the peer
    /// handle stored here is genuinely connection-negotiation state, not
    /// something the stateless path is missing.
    negotiated: Option<NegotiatedConnection>,
    binding: WorkspaceBinding,
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
            binding: if accepts_client_roots {
                WorkspaceBinding::Unbound
            } else {
                WorkspaceBinding::ExplicitRoot
            },
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
        if matches!(self.binding, WorkspaceBinding::ClientRoots { .. }) {
            return false;
        }
        self.accepts_client_roots
            && self
                .negotiated
                .as_ref()
                .is_some_and(|negotiated| !negotiated.client_supports_roots)
    }

    fn clear_binding(&mut self) {
        self.binding = WorkspaceBinding::Unbound;
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
    active: Mutex<HashMap<u64, (WorkspaceRequestScope, crate::CancellationToken)>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WorkspaceRequestScope {
    workspace_id: u64,
    generation: u64,
}

impl InFlightRequests {
    fn register(
        self: &Arc<Self>,
        workspace_scope: WorkspaceRequestScope,
        cancellation: crate::CancellationToken,
    ) -> InFlightGuard {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.active
            .lock()
            .expect("in-flight MCP request lock poisoned")
            .insert(id, (workspace_scope, cancellation));
        InFlightGuard {
            requests: Arc::clone(self),
            id,
        }
    }

    fn cancel_stale(&self, current_scope: WorkspaceRequestScope) {
        for (scope, cancellation) in self
            .active
            .lock()
            .expect("in-flight MCP request lock poisoned")
            .values()
        {
            if scope.workspace_id == current_scope.workspace_id
                && scope.generation != current_scope.generation
            {
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

/// Env var overriding the MCP task TTL in whole milliseconds.
///
/// Exists so the expiry behavior test can use a tiny TTL instead of waiting
/// out the default. Operators can also raise it for very large corpora.
#[doc(hidden)]
pub const MCP_TASK_TTL_ENV: &str = "BIFROST_MCP_TASK_TTL_MS";

/// How long a task may run and how long its terminal result stays pollable.
///
/// Tasks exist precisely because the interactive request budget is wrong for
/// batch work, so they get their own bound: large policy runs fit in ten
/// minutes, and rmcp's manager additionally retains the terminal result for
/// one further TTL window so a poller always gets to observe it. The TTL is
/// also the execution deadline -- the task's cancellation token expires at
/// `created + ttl` -- so "the manager marks the task failed" and "the
/// analyzer actually stops" are the same moment, not two drifting timers.
const DEFAULT_TASK_TTL: Duration = Duration::from_secs(600);

/// Suggested `tasks/get` polling interval advertised on every task handle.
const TASK_POLL_INTERVAL_MS: u64 = 1_000;

/// The tools eligible for durable task execution.
///
/// Deliberately narrow: `run_policy` is the one registry tool whose runtime
/// scales with the whole corpus times the policy count, which is the batch
/// shape MCP Tasks exists for. Navigation tools stay synchronous by design --
/// waiting out cold initialization is the intended readiness model, not a
/// reason to hand back a task handle.
fn task_eligible_tool(name: &str) -> bool {
    name == "run_policy"
}

fn mcp_task_ttl() -> Duration {
    match std::env::var(MCP_TASK_TTL_ENV) {
        Err(std::env::VarError::NotPresent) => DEFAULT_TASK_TTL,
        Ok(value) => match value.parse::<u64>() {
            Ok(millis) if millis >= 1 => Duration::from_millis(millis),
            _ => {
                eprintln!(
                    "bifrost: {MCP_TASK_TTL_ENV} must be a whole number of milliseconds >= 1, not `{value}`; using the default {DEFAULT_TASK_TTL:?}"
                );
                DEFAULT_TASK_TTL
            }
        },
        Err(std::env::VarError::NotUnicode(_)) => {
            eprintln!(
                "bifrost: {MCP_TASK_TTL_ENV} is not valid unicode; using the default {DEFAULT_TASK_TTL:?}"
            );
            DEFAULT_TASK_TTL
        }
    }
}

/// Workspace authorization records for issued task handles.
///
/// Each task is bound at creation to the workspace generation it was
/// authorized under; every later `tasks/*` call re-checks that generation, so
/// a handle can never cross a workspace rebind. Entries expire on the same
/// clock as rmcp's own terminal retention (two TTL windows past creation) and
/// are swept opportunistically, which bounds the map without a background
/// sweeper -- the same policy `rmcp::task_manager::TaskManager` applies to
/// the tasks themselves.
#[derive(Default)]
struct TaskScopes {
    entries: Mutex<HashMap<String, (WorkspaceRequestScope, Instant)>>,
}

impl TaskScopes {
    fn record(&self, task_id: String, scope: WorkspaceRequestScope, ttl: Duration) {
        let mut entries = self.entries.lock().expect("task scope lock poisoned");
        let now = Instant::now();
        entries.retain(|_, (_, expires_at)| *expires_at > now);
        entries.insert(task_id, (scope, now + ttl + ttl));
    }

    fn lookup(&self, task_id: &str) -> Option<WorkspaceRequestScope> {
        let mut entries = self.entries.lock().expect("task scope lock poisoned");
        let now = Instant::now();
        entries.retain(|_, (_, expires_at)| *expires_at > now);
        entries.get(task_id).map(|(scope, _)| *scope)
    }
}

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

    /// Check without spending a retry that can still meet transient contention.
    /// Activation callers hold the connection guard through validation/binding.
    fn contains(&self, nonce: &str) -> bool {
        self.outstanding
            .lock()
            .expect("roots activation lock poisoned")
            .iter()
            .any(|issued| issued == nonce)
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

/// Per-request progress reporting through `notifications/progress`, active
/// only when the caller supplied a `progressToken`.
///
/// Phase reporting sends one notification per phase the
/// call actually enters -- workspace readiness, analyzer admission, tool
/// execution, every phase the analyzer itself enters while it runs (issue
/// #3170), and cooperative cancellation when the request budget expires.
/// The progress value is a per-request monotonic counter and `total` is never
/// set, because these values are ordinals, not item counts. Measured build
/// counters live separately in `_meta["io.bifrost/workspace-build"]`. A phase notification
/// says "this call entered this phase", nothing more; a wait that turns out
/// to be zero-length was still entered.
///
/// Every send happens on the request's own async task, never from the
/// blocking analyzer task, so progress delivery can neither occupy an
/// analyzer permit nor delay cooperative cancellation.
/// How a request ended, sent as `request_status` on its final workspace-build
/// notification. A request that is still running or that succeeded sends none.
#[derive(Clone, Copy, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum RequestOutcome {
    Cancelled,
    Failed,
}

impl RequestOutcome {
    /// The outcome of a request that returned an error: a cancelled request
    /// reports the cancellation, not the error it caused.
    fn after_error(cancelled: bool) -> Self {
        if cancelled {
            Self::Cancelled
        } else {
            Self::Failed
        }
    }
}

struct ProgressReporter {
    peer: rmcp::service::Peer<RoleServer>,
    token: rmcp::model::ProgressToken,
    steps: AtomicU64,
    request_id: Value,
    workspace_generation: u64,
    last_build_revision: Mutex<Option<(u64, u64, Option<String>)>>,
    /// When the last build-counter notification went out. The build revision
    /// moves on every persisted batch, and the 100 ms poll would otherwise
    /// forward each move: a cold build of a large repository sent ~10
    /// notifications a second, each carrying up to 8 KB of counters, for the
    /// whole build (#5990). A client only needs a recent snapshot, so plain
    /// counter updates are spaced out; a status change still sends at once.
    last_build_sent: Mutex<Option<Instant>>,
    minimum_build_generation: u64,
    task_id: Option<String>,
    delivery: ProgressDelivery,
}

/// Minimum spacing between two build-counter progress notifications of one
/// request. Phase and status notifications are not spaced.
const BUILD_PROGRESS_MIN_INTERVAL: Duration = Duration::from_secs(1);

/// How long one partial result may wait for a slow client before it is
/// dropped. It holds up only this request's own task, never the analyzer.
const PARTIAL_RESULT_SEND_TIMEOUT: Duration = Duration::from_secs(1);

/// How many progress notifications may be queued behind one slow transport
/// write. Phase and workspace observations beyond this bound are dropped;
/// partial results are never dropped.
const MAX_PENDING_PROGRESS_DELIVERIES: usize = 256;

/// Delivers progress notifications in the order the request produced them.
///
/// `rmcp`'s `Peer::send_notification` enqueues the notification on the peer
/// channel before it waits for the transport, so dropping a timed-out send
/// future does not withdraw the notification: the serve loop can still write
/// it later. Each send is therefore chained behind the previous one and kept
/// until it finishes, and [`Self::finish`] drains the chain before the request
/// returns its response. A notification can then never be written after that
/// response, while each individual send still gets only its own timeout on the
/// request task, so a slow client cannot hold up analyzer work or cooperative
/// cancellation.
#[derive(Default)]
struct ProgressDelivery {
    pending: Arc<AtomicUsize>,
    last: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Tripwire, not a concurrency barrier: every send currently comes from
    /// the request task, which calls `finish` only after its last send. A
    /// send after that would race the response, so `enqueue` rejects it.
    finished: AtomicBool,
}

/// Decrements the pending-delivery count even if a delivery task panics.
struct PendingProgressDelivery(Arc<AtomicUsize>);

impl Drop for PendingProgressDelivery {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

impl ProgressDelivery {
    async fn enqueue<F>(&self, timeout: Duration, droppable: bool, send: F)
    where
        F: std::future::Future<Output = Result<(), String>> + Send + 'static,
    {
        assert!(
            !self.finished.load(Ordering::Acquire),
            "no progress notification may be enqueued after finish"
        );
        if droppable && self.pending.load(Ordering::Relaxed) >= MAX_PENDING_PROGRESS_DELIVERIES {
            return;
        }
        let previous = self
            .last
            .lock()
            .expect("progress delivery lock poisoned")
            .take();
        self.pending.fetch_add(1, Ordering::Relaxed);
        let pending = PendingProgressDelivery(Arc::clone(&self.pending));
        let mut delivery = tokio::spawn(async move {
            let _pending_delivery = pending;
            if let Some(previous) = previous
                && let Err(error) = previous.await
            {
                eprintln!("bifrost: MCP progress delivery task panicked: {error}");
            }
            if let Err(error) = send.await {
                eprintln!("bifrost: failed to send MCP progress notification: {error}");
            }
        });
        match tokio::time::timeout(timeout, &mut delivery).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                eprintln!("bifrost: MCP progress delivery task panicked: {error}")
            }
            Err(_slow_client) => {
                *self.last.lock().expect("progress delivery lock poisoned") = Some(delivery);
            }
        }
    }

    /// Wait until every notification enqueued so far has reached the
    /// transport. Called before the request returns its response.
    async fn finish(&self) {
        self.finished.store(true, Ordering::Release);
        let handle = self
            .last
            .lock()
            .expect("progress delivery lock poisoned")
            .take();
        let Some(handle) = handle else {
            return;
        };
        if let Err(error) = handle.await {
            eprintln!("bifrost: MCP progress delivery task panicked: {error}");
        }
    }
}

impl ProgressReporter {
    /// A reporter for this request, or `None` when the caller did not opt in.
    /// The token is carried through to every notification exactly as
    /// received, string or number.
    fn from_request(
        context: &RequestContext<RoleServer>,
        service: &SearchToolsService,
        tool_name: &str,
        workspace_generation: u64,
    ) -> Option<Self> {
        Some(Self {
            peer: context.peer.clone(),
            token: context.meta.get_progress_token()?,
            steps: AtomicU64::new(0),
            request_id: json!(context.id),
            workspace_generation,
            // A warm refresh observes only the build it starts. Replaying the
            // previous cold parse counters could imply cached files were parsed
            // again. An uninstalled startup build still belongs to this wait,
            // even when it finished before the first request arrived.
            minimum_build_generation: if tool_name == "refresh"
                && !service.initial_workspace_build_uninstalled()
            {
                service
                    .workspace_build_progress(workspace_generation)
                    .map_or(0, |snapshot| snapshot.generation + 1)
            } else {
                0
            },
            last_build_revision: Mutex::new(None),
            last_build_sent: Mutex::new(None),
            task_id: None,
            delivery: ProgressDelivery::default(),
        })
    }

    async fn phase(&self, message: impl Into<String>) {
        let step = self.steps.fetch_add(1, Ordering::Relaxed) + 1;
        self.send(
            rmcp::model::ProgressNotificationParam::new(self.token.clone(), step as f64)
                .with_message(message),
        )
        .await;
    }

    /// One finished part of the request's result, under `_meta[kind]`.
    ///
    /// It is given longer than a phase to reach a slow client, because a later
    /// notification does not replace it; the final result still carries it.
    async fn partial_result(&self, kind: String, value: Value) {
        let step = self.steps.fetch_add(1, Ordering::Relaxed) + 1;
        let mut params =
            rmcp::model::ProgressNotificationParam::new(self.token.clone(), step as f64)
                .with_message(format!("partial result: {kind}"));
        params.meta = Some(rmcp::model::NotificationMetaObject::from(
            serde_json::Map::from_iter([(kind, value)]),
        ));
        self.send_within(params, PARTIAL_RESULT_SEND_TIMEOUT, false)
            .await;
    }

    async fn send(&self, params: rmcp::model::ProgressNotificationParam) {
        // A slow/disconnected client loses observations, never analyzer capacity
        // or prompt cancellation. A notification that has already been enqueued
        // is still flushed before the response by `finish`.
        self.send_within(params, Duration::from_millis(25), true)
            .await;
    }

    async fn send_within(
        &self,
        params: rmcp::model::ProgressNotificationParam,
        timeout: Duration,
        droppable: bool,
    ) {
        let peer = self.peer.clone();
        self.delivery
            .enqueue(timeout, droppable, async move {
                peer.notify_progress(params)
                    .await
                    .map_err(|error| error.to_string())
            })
            .await;
    }

    /// Deliver every notification queued by this request before its response
    /// is returned.
    async fn finish(&self) {
        self.delivery.finish().await;
    }

    /// A poll-driven counter update: forwarded only when the previous
    /// build-counter notification is at least `BUILD_PROGRESS_MIN_INTERVAL`
    /// old. A skipped poll records nothing, so the first poll after the
    /// interval forwards the newest revision. Completion and cancellation go
    /// through [`Self::workspace`] directly and are never spaced.
    async fn workspace_tick(&self, service: &SearchToolsService) {
        let recently_sent = self
            .last_build_sent
            .lock()
            .expect("progress send-time lock poisoned")
            .is_some_and(|sent| sent.elapsed() < BUILD_PROGRESS_MIN_INTERVAL);
        if recently_sent {
            return;
        }
        self.workspace_with(service, None, true).await;
    }

    async fn workspace(
        &self,
        service: &SearchToolsService,
        request_status: Option<RequestOutcome>,
    ) {
        self.workspace_with(service, request_status, false).await;
    }

    async fn workspace_with(
        &self,
        service: &SearchToolsService,
        request_status: Option<RequestOutcome>,
        droppable: bool,
    ) {
        if service.workspace_generation() != self.workspace_generation {
            return;
        }
        let Some(snapshot) = service.workspace_build_progress(self.workspace_generation) else {
            return;
        };
        if snapshot.generation < self.minimum_build_generation {
            return;
        }
        let revision = (
            snapshot.generation,
            snapshot.revision,
            snapshot.phase.clone(),
        );
        {
            let mut last = self
                .last_build_revision
                .lock()
                .expect("progress revision lock poisoned");
            if last.as_ref() == Some(&revision) && request_status.is_none() {
                return;
            }
            *last = Some(revision);
            *self
                .last_build_sent
                .lock()
                .expect("progress send-time lock poisoned") = Some(Instant::now());
        }
        let step = self.steps.fetch_add(1, Ordering::Relaxed) + 1;
        let message = match &snapshot.phase {
            Some(phase) => format!("workspace indexing: {phase}"),
            None => "workspace indexing".to_owned(),
        };
        let mut params =
            rmcp::model::ProgressNotificationParam::new(self.token.clone(), step as f64)
                .with_message(message);
        let mut measured = json!(snapshot);
        measured["request_id"] = self.request_id.clone();
        if let Some(task_id) = &self.task_id {
            measured["task_id"] = json!(task_id);
        }
        if let Some(status) = request_status {
            measured["request_status"] = json!(status);
        }
        params.meta = Some(rmcp::model::NotificationMetaObject::from(
            serde_json::Map::from_iter([("io.bifrost/workspace-build".to_owned(), measured)]),
        ));
        self.send_within(params, Duration::from_millis(25), droppable)
            .await;
    }
}

/// Bifrost's `ServerHandler`. One instance serves one stdio connection.
pub struct BifrostMcpHandler {
    service: Arc<SearchToolsService>,
    named_workspaces: Option<Arc<NamedWorkspaceRouter>>,
    instructions: String,
    build_identity: String,
    tools: Vec<Tool>,
    tool_names: HashSet<String>,
    render_options: McpRenderOptions,
    /// Shared with task futures, which are `'static` and must own their
    /// admission path: a task queues for a real analyzer slot exactly like a
    /// synchronous call, so tasks cannot overcommit the analyzer.
    analyzer_pool: Arc<AnalyzerExecutionPool>,
    in_flight: Arc<InFlightRequests>,
    /// Durable state for the MCP Tasks extension (SEP-2663). rmcp owns the
    /// lifecycle (TTL expiry, terminal retention, input routing, cancel
    /// signals); Bifrost supplies the operation future and the workspace
    /// authorization policy in [`TaskScopes`].
    task_manager: TaskManager,
    task_scopes: TaskScopes,
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

// Authorization is one algorithm; callers supply blocking or observational
// binding operations. A probe never converts a contended mutation into a wait.
trait WorkspaceBindingOps {
    fn root(&self) -> Result<Option<PathBuf>, crate::SearchToolsServiceError>;
    fn bind(&self, root: PathBuf) -> Result<PathBuf, crate::SearchToolsServiceError>;
    fn unbind(&self) -> Result<(), crate::SearchToolsServiceError>;
}

impl WorkspaceBindingOps for &SearchToolsService {
    fn root(&self) -> Result<Option<PathBuf>, crate::SearchToolsServiceError> {
        Ok(self.active_workspace_root())
    }
    fn bind(&self, root: PathBuf) -> Result<PathBuf, crate::SearchToolsServiceError> {
        self.bind_client_workspace(root)
    }
    fn unbind(&self) -> Result<(), crate::SearchToolsServiceError> {
        self.unbind_client_workspace()
    }
}

struct ProbeWorkspace<'a>(&'a SearchToolsService);
impl WorkspaceBindingOps for ProbeWorkspace<'_> {
    fn root(&self) -> Result<Option<PathBuf>, crate::SearchToolsServiceError> {
        self.0.try_active_workspace_root()
    }
    fn bind(&self, root: PathBuf) -> Result<PathBuf, crate::SearchToolsServiceError> {
        self.0.try_bind_client_workspace(root)
    }
    fn unbind(&self) -> Result<(), crate::SearchToolsServiceError> {
        self.0.try_unbind_client_workspace()
    }
}

impl BifrostMcpHandler {
    #[allow(clippy::too_many_arguments)]
    fn new(
        service: Arc<SearchToolsService>,
        named_workspaces: Option<Arc<NamedWorkspaceRouter>>,
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
        let descriptors = match &named_workspaces {
            Some(router) => named_workspace_descriptors(&spec.tool_descriptors, router)?,
            None => spec.tool_descriptors.clone(),
        };
        let tools = descriptors
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
        let mut tool_names = spec.tool_names.clone();
        if named_workspaces.is_some() {
            tool_names.remove("activate_workspace");
            tool_names.remove("get_active_workspace");
        }

        Ok(Self {
            service,
            instructions: named_workspaces.as_ref().map_or_else(
                || Ok(spec.instructions.clone()),
                |router| router.instructions(&spec.instructions),
            )?,
            named_workspaces,
            build_identity: build_identity.to_string(),
            tools,
            tool_names,
            render_options,
            analyzer_pool: Arc::new(AnalyzerExecutionPool::default()),
            in_flight: Arc::new(InFlightRequests::default()),
            task_manager: TaskManager::new(),
            task_scopes: TaskScopes::default(),
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
    fn try_probe_connection(
        &self,
    ) -> Result<tokio::sync::MutexGuard<'_, ConnectionState>, ErrorData> {
        self.workspace.try_lock().map_err(|_| {
            map_service_failure(
                self.service
                    .workspace_busy("connection workspace lock is busy"),
            )
        })
    }

    fn client_roots_request(
        &self,
        binding: &impl WorkspaceBindingOps,
        state: &mut ConnectionState,
        context: &RequestContext<RoleServer>,
    ) -> Result<Option<(rmcp::service::Peer<RoleServer>, u64)>, ErrorData> {
        if self.client_roots_binding_is_stale(state) {
            self.revoke_client_roots(binding, state)?;
        }
        if !state.accepts_client_roots || state.binding != WorkspaceBinding::Unbound {
            return Ok(None);
        }
        let Some(negotiated) = state.negotiated.as_ref() else {
            if !request_negotiates_per_request(&context.meta) {
                eprintln!(
                    "bifrost: refusing to request MCP roots before the initialize handshake completes"
                );
            }
            return Ok(None);
        };
        if !negotiated.client_supports_roots {
            return Ok(None);
        }
        Ok(Some((
            negotiated.peer.clone(),
            self.roots_revocations.observed(),
        )))
    }

    // Only owned request data crosses this await. Neither connection nor
    // service binding guards can be held while the client chooses its roots.
    #[allow(deprecated)]
    async fn request_client_roots(
        &self,
        peer: rmcp::service::Peer<RoleServer>,
        context: &RequestContext<RoleServer>,
    ) -> Option<rmcp::model::ListRootsResult> {
        let result = tokio::select! {
            result = tokio::time::timeout(ROOTS_LIST_LIVENESS_BOUND, peer.list_roots()) => result,
            () = context.ct.cancelled() => {
                eprintln!("bifrost: MCP roots/list abandoned; the client cancelled the request that asked for it");
                return None;
            }
        };
        match result {
            Ok(Ok(result)) => Some(result),
            Ok(Err(error)) => {
                eprintln!("bifrost: MCP roots/list failed: {error}");
                None
            }
            Err(_) => {
                eprintln!(
                    "bifrost: MCP roots/list timed out after {ROOTS_LIST_LIVENESS_BOUND:?}; the client did not supply a workspace"
                );
                None
            }
        }
    }

    #[allow(deprecated)]
    fn apply_client_roots_reply(
        &self,
        binding: &impl WorkspaceBindingOps,
        state: &mut ConnectionState,
        revocations_at_request: u64,
        roots: &[Root],
    ) -> Result<(), ErrorData> {
        if state.binding != WorkspaceBinding::Unbound {
            return Ok(());
        }
        if self.roots_revocations.observed() != revocations_at_request {
            eprintln!(
                "bifrost: discarding a superseded MCP roots/list answer; the client changed its roots while the request was in flight"
            );
            return Ok(());
        }
        self.bind_first_usable_root(binding, state, roots)?;
        Ok(())
    }

    #[allow(deprecated)] // Roots: see the note on the Root import.
    async fn ensure_client_workspace(
        &self,
        context: &RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        let request = {
            let mut state = self.workspace.lock().await;
            self.client_roots_request(&self.service.as_ref(), &mut state, context)?
        };
        let Some((peer, revocations)) = request else {
            return Ok(());
        };
        let Some(reply) = self.request_client_roots(peer, context).await else {
            return Ok(());
        };
        let mut state = self.workspace.lock().await;
        self.apply_client_roots_reply(
            &self.service.as_ref(),
            &mut state,
            revocations,
            &reply.roots,
        )
    }

    #[allow(deprecated)] // Roots: see the note on the Root import.
    async fn ensure_probe_workspace(
        &self,
        context: &RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        let request = {
            let mut state = self.try_probe_connection()?;
            self.client_roots_request(&ProbeWorkspace(&self.service), &mut state, context)?
        };
        let Some((peer, revocations)) = request else {
            return Ok(());
        };
        let Some(reply) = self.request_client_roots(peer, context).await else {
            return Ok(());
        };
        // Another call may have bound, revoked, or acquired the serial guard
        // during the round trip. Never queue behind it; a retry negotiates again.
        let mut state = self.try_probe_connection()?;
        self.apply_client_roots_reply(
            &ProbeWorkspace(&self.service),
            &mut state,
            revocations,
            &reply.roots,
        )
    }

    /// Whether the client withdrew authorization for the currently bound scope.
    ///
    /// True when a `roots/list_changed` reached the transport after this
    /// binding was made. The counter is incremented in wire order by
    /// `RootsOrderedTransport`, so this answer does not depend on which task
    /// the runtime happens to poll first -- which is the whole point, since
    /// `rmcp` dispatches notifications and requests on separate tasks.
    fn client_roots_binding_is_stale(&self, state: &ConnectionState) -> bool {
        matches!(
            state.binding,
            WorkspaceBinding::ClientRoots { bound_at_revocation }
                if bound_at_revocation != self.roots_revocations.observed()
        )
    }

    /// Drop the client-roots scope and stop any work admitted against it.
    fn revoke_client_roots(
        &self,
        binding: &impl WorkspaceBindingOps,
        state: &mut ConnectionState,
    ) -> Result<(), ErrorData> {
        self.revoke_workspace(binding, state, "changed MCP workspace roots")
    }

    /// The one way a workspace is given up.
    ///
    /// Unbinding, cancelling work admitted against the old scope, and clearing
    /// the connection's record of it are a single operation: a caller that
    /// performs two of the three leaves analyzer threads grinding against a
    /// directory the client has withdrawn. Splitting them by hand is how the
    /// Codex paths came to skip the cancellation.
    fn revoke_workspace(
        &self,
        binding: &impl WorkspaceBindingOps,
        state: &mut ConnectionState,
        reason: &str,
    ) -> Result<(), ErrorData> {
        if let Err(error) = binding.unbind() {
            if error.workspace_incomplete.is_some() {
                return Err(map_service_failure(error));
            }
            eprintln!("bifrost: failed to revoke {reason}: {error}");
        }
        self.in_flight.cancel_stale(WorkspaceRequestScope {
            workspace_id: 0,
            generation: self.service.workspace_generation(),
        });
        state.clear_binding();
        Ok(())
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
    fn bind_first_usable_root(
        &self,
        binding: &impl WorkspaceBindingOps,
        state: &mut ConnectionState,
        roots: &[Root],
    ) -> Result<bool, ErrorData> {
        let mut last_error = None;
        for root in roots {
            let candidate = match client_root_to_path(&root.uri) {
                Ok(candidate) => candidate,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
            match binding.bind(candidate) {
                Ok(root) => {
                    self.in_flight.cancel_stale(WorkspaceRequestScope {
                        workspace_id: 0,
                        generation: self.service.workspace_generation(),
                    });
                    state.binding = WorkspaceBinding::ClientRoots {
                        bound_at_revocation: self.roots_revocations.observed(),
                    };
                    eprintln!(
                        "bifrost: bound MCP workspace source=roots/list root={}",
                        escape_terminal_text(root.to_string_lossy().as_ref())
                    );
                    return Ok(true);
                }
                Err(error) => {
                    if error.workspace_incomplete.is_some() {
                        return Err(map_service_failure(error));
                    }
                    last_error = Some(error.to_string());
                }
            }
        }

        match last_error {
            Some(error) => eprintln!("bifrost: no usable MCP workspace root: {error}"),
            None => {
                eprintln!("bifrost: MCP client returned no workspace roots; server remains unbound")
            }
        }
        Ok(false)
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
        binding: &impl WorkspaceBindingOps,
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
            self.revoke_codex_sandbox_workspace(binding, state, thread_id, "metadata missing")?;
            log_codex_workspace_event("workspace metadata missing", thread_id);
            return Err(unbound_workspace_error());
        };

        let active_root = binding.root().map_err(map_service_failure)?;
        if let WorkspaceBinding::CodexSandbox { cwd_uri, root } = &state.binding
            && cwd_uri == sandbox_cwd
            && active_root.as_ref() == Some(root)
        {
            return Ok(());
        }

        let candidate = match file_uri_to_path(sandbox_cwd) {
            Ok(candidate) => candidate,
            Err(error) => {
                self.revoke_codex_sandbox_workspace(binding, state, thread_id, "metadata invalid")?;
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
        if binding.root().map_err(map_service_failure)?.is_some()
            || state.binding != WorkspaceBinding::Unbound
        {
            self.revoke_workspace(
                binding,
                state,
                "the previous workspace reason=metadata changed",
            )?;
            log_codex_workspace_event(
                "revoked previous workspace reason=metadata changed",
                thread_id,
            );
        }

        match binding.bind(candidate) {
            Ok(root) => {
                state.binding = WorkspaceBinding::CodexSandbox {
                    cwd_uri: sandbox_cwd.to_string(),
                    root: root.clone(),
                };
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
                self.revoke_workspace(binding, state, "the failed Codex workspace bind")?;
                log_codex_workspace_event(
                    &format!(
                        "failed workspace bind source={CODEX_SANDBOX_STATE_META_CAPABILITY} error={}",
                        escape_terminal_text(&error.message)
                    ),
                    thread_id,
                );
                Err(map_service_failure(error))
            }
        }
    }

    fn revoke_codex_sandbox_workspace(
        &self,
        binding: &impl WorkspaceBindingOps,
        state: &mut ConnectionState,
        thread_id: Option<&str>,
        reason: &str,
    ) -> Result<(), ErrorData> {
        if !matches!(state.binding, WorkspaceBinding::CodexSandbox { .. }) {
            return Ok(());
        }
        self.revoke_workspace(
            binding,
            state,
            &format!("the Codex workspace reason={reason}"),
        )?;
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
    fn activate_workspace_over_mrtr(
        &self,
        binding: &impl WorkspaceBindingOps,
        state: &mut ConnectionState,
        request: &CallToolRequestParams,
        context: &RequestContext<RoleServer>,
    ) -> Result<Option<rmcp::model::InputRequiredResult>, ErrorData> {
        if !state.accepts_client_roots || state.binding != WorkspaceBinding::Unbound {
            return Ok(None);
        }
        // Gate on the negotiated revision rather than letting rmcp reject the
        // result for older peers: a legacy client should read Bifrost's plain
        // "not bound to a workspace" message, not an opaque protocol error.
        if !speaks_2026_07_28(context) {
            return Ok(None);
        }

        let Some(request_state) = request.request_state.as_deref() else {
            return Ok(Some(rmcp::model::InputRequiredResult::new(
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
            )));
        };

        // `requestState` is client-controlled and echoed verbatim, so it
        // authorizes nothing. It is only a nonce proving this call is the
        // retry of an activation Bifrost actually asked for; the roots
        // themselves are re-validated below exactly as on the legacy path.
        if !self.roots_activations.contains(request_state) {
            eprintln!("bifrost: ignoring MCP roots activation with an unrecognized requestState");
            return Ok(None);
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
                        self.bind_first_usable_root(binding, state, &result.roots)?;
                    }
                    // The error names the offending field; "no usable response"
                    // alone leaves a client author nothing to act on.
                    Err(error) => eprintln!(
                        "bifrost: MCP roots activation retry carried an unreadable `{ROOTS_INPUT_REQUEST_KEY}` response: {error}"
                    ),
                }
            }
        }
        // The connection guard serializes nonce issuance and redemption. A
        // retryable binding error returned above must retain this same nonce;
        // only a terminal outcome (including unusable roots) spends it.
        let redeemed = self.roots_activations.redeem(request_state);
        debug_assert!(redeemed);
        Ok(None)
    }

    /// Everything a tool call needs decided before it may touch the analyzer:
    /// authorization, scope, and argument normalization. Runs under the
    /// workspace lock so concurrent calls cannot interleave with a rebind.
    fn prepare_tool_call(
        &self,
        binding: &impl WorkspaceBindingOps,
        state: &mut ConnectionState,
        name: &str,
        arguments: Value,
        meta: &rmcp::model::RequestMetaObject,
    ) -> Result<PreparedToolCall, ErrorData> {
        // Defence in depth, independent of every binding source below. A
        // client-supplied workspace is only meaningful once protocol version
        // and capabilities have been negotiated, and an explicitly rooted
        // server has nothing to negotiate. Legacy (`2025-11-25`) clients
        // negotiate once per connection through `initialize`; stateless
        // `2026-07-28` clients negotiate on every request through the `_meta`
        // keys rmcp validates before dispatch. A request that carries neither
        // -- rmcp's SEP-2575 lifecycle will serve one whose session opened
        // statelessly but whose own `_meta` selects a legacy version -- must
        // not reach any binding source.
        if state.accepts_client_roots
            && state.negotiated.is_none()
            && !request_negotiates_per_request(meta)
        {
            eprintln!(
                "bifrost: refusing a workspace tool call that negotiated capabilities neither per connection nor per request"
            );
            return Err(unbound_workspace_error());
        }

        // A roots change that reached the transport before this call did
        // revokes the scope, whether or not its notification handler has run
        // yet. The counter comes from `RootsOrderedTransport`, which increments
        // it in wire order, so this comparison is what actually makes the rule
        // hold; `on_roots_list_changed` only makes revocation prompt.
        if self.client_roots_binding_is_stale(state) {
            self.revoke_client_roots(binding, state)?;
        }

        self.reconcile_codex_sandbox_workspace(binding, state, meta)?;

        if state.binding == WorkspaceBinding::Unbound {
            if self.service.workspace_binding_capacity_exhausted() {
                return Err(map_service_failure(
                    self.service.workspace_activation_not_ready(),
                ));
            }
            return Err(unbound_workspace_error());
        }
        let Some(workspace_root) = binding.root().map_err(map_service_failure)? else {
            return Err(unbound_workspace_error());
        };

        if name == "activate_workspace" {
            let authority = match state.binding {
                WorkspaceBinding::ClientRoots { .. } => Some("MCP client roots"),
                WorkspaceBinding::CodexSandbox { .. } => Some("Codex sandbox metadata"),
                WorkspaceBinding::Unbound | WorkspaceBinding::ExplicitRoot => None,
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
        let run_policy_preflight = if name == "run_policy" {
            match self.service.preflight_run_policy(&arguments) {
                Ok(RunPolicyPreflight::Valid(preflight)) => Some(preflight),
                Ok(RunPolicyPreflight::Invalid(output)) => {
                    return Ok(PreparedToolCall::Reply(tool_success_result(output)));
                }
                Err(error) => return Err(map_service_failure(error)),
            }
        } else {
            None
        };

        Ok(PreparedToolCall::Ready {
            arguments,
            run_policy_preflight,
            workspace_scope: (!serial_tool_request(name) || name == "get_active_workspace").then(
                || WorkspaceRequestScope {
                    workspace_id: 0,
                    generation: self.service.workspace_generation(),
                },
            ),
        })
    }

    fn prepare_named_tool_call(
        &self,
        name: &str,
        mut arguments: Value,
    ) -> Result<(Arc<SearchToolsService>, PreparedToolCall), ErrorData> {
        let Some(router) = &self.named_workspaces else {
            return Err(ErrorData::internal_error(
                "named workspace router is unavailable",
                None,
            ));
        };
        let workspace = arguments
            .as_object_mut()
            .and_then(|object| object.remove("workspace"))
            .and_then(|workspace| workspace.as_str().map(str::to_string))
            .ok_or_else(|| {
                ErrorData::invalid_params("workspace must be one configured name", None)
            })?;
        let (workspace_id, service) = router
            .service(&workspace)
            .map_err(|message| ErrorData::invalid_params(message, None))?;
        let root = service
            .active_workspace_root()
            .ok_or_else(unbound_workspace_error)?;
        let arguments = match normalize_tool_arguments(name, arguments, &root) {
            Ok(arguments) => arguments,
            Err(message) => {
                return Ok((service, PreparedToolCall::Reply(tool_error_result(message))));
            }
        };
        let run_policy_preflight = if name == "run_policy" {
            match service.preflight_run_policy(&arguments) {
                Ok(RunPolicyPreflight::Valid(preflight)) => Some(preflight),
                Ok(RunPolicyPreflight::Invalid(output)) => {
                    return Ok((
                        service,
                        PreparedToolCall::Reply(tool_success_result(output)),
                    ));
                }
                Err(error) => return Err(map_service_failure(error)),
            }
        } else {
            None
        };
        let generation = service.workspace_generation();
        Ok((
            service,
            PreparedToolCall::Ready {
                arguments,
                run_policy_preflight,
                workspace_scope: Some(WorkspaceRequestScope {
                    workspace_id,
                    generation,
                }),
            },
        ))
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
        service: Arc<SearchToolsService>,
        name: String,
        arguments: Value,
        suppression_preflight: Option<PreparedRunPolicyPreflight>,
        workspace_scope: Option<WorkspaceRequestScope>,
        request_budget: Option<RequestBudget>,
        request_correlation_id: Option<String>,
        mcp_cancellation: McpCancellationToken,
        permit: AnalyzerPermit,
        cold_workspace: bool,
        transport_timings: TransportTimings,
        progress: Option<&ProgressReporter>,
    ) -> Result<CallToolResult, ErrorData> {
        // The deadline was set when the request was accepted, not when it
        // reached the analyzer, so time already spent queueing counts against
        // it. A request that waited most of its budget gets what remains.
        // A policy run asks its analyzer to stop before this request's timer,
        // so its canonical deadline report can arrive first. Usage scans use
        // the same reserve as a non-cancelling soft stop while retaining this
        // request deadline as their hard backstop. The reserve is measured
        // from now, so readiness and admission wait already spent are never
        // handed back as grace.
        let bifrost_cancellation = match request_budget {
            Some(request_budget) => {
                let accepted_at = Instant::now();
                let deadline = request_budget.deadline();
                let cancellation = crate::CancellationToken::default()
                    .with_deadline(analyzer_stop_deadline(&name, accepted_at, deadline));
                match usage_scan_soft_deadline(&name, accepted_at, deadline) {
                    Some(soft_deadline) => cancellation.with_soft_deadline(soft_deadline),
                    None => cancellation,
                }
            }
            None => crate::CancellationToken::default(),
        };
        // How the analyzer's phases reach the client while the call is still
        // running. The analyzer thread is synchronous and cannot send a
        // notification itself, so it publishes each phase into this channel and
        // the select loop below -- this request's own task -- reports it
        // (issue #3170). The receiver and this sender both live as long as that
        // loop, so `recv` cannot return `None` while the call is running.
        let (phase_tx, mut phase_rx) = tokio::sync::mpsc::channel::<String>(32);
        // Partial results go through their own unbounded channel: unlike a
        // phase, a dropped one is never superseded. Its size is bounded by the
        // result it is part of, which the request holds anyway.
        let (result_tx, mut result_rx) = tokio::sync::mpsc::unbounded_channel::<(String, Value)>();
        let bifrost_cancellation = match progress {
            Some(_) => bifrost_cancellation.with_result_sink(move |kind, value| {
                // The receiver is gone only once the request has answered;
                // the final result already holds this part.
                match result_tx.send((kind.to_string(), value)) {
                    Ok(()) => {}
                    Err(_after_the_answer) => {}
                }
            }),
            None => bifrost_cancellation,
        };
        let bifrost_cancellation = match progress {
            Some(_) => {
                let phases = phase_tx.clone();
                bifrost_cancellation.with_phase_sink(move |phase| {
                    // Sending never blocks the analyzer thread. Its one failure
                    // is the receiver being gone, which says the request has
                    // already answered: a phase entered while the cancelled
                    // work unwinds has nobody left to report it to, and must
                    // not be reported after the answer anyway.
                    match phases.try_send(phase.to_string()) {
                        Ok(()) => {}
                        Err(_coalesced_or_after_the_answer) => {}
                    }
                })
            }
            None => bifrost_cancellation,
        };
        let in_flight = self.in_flight.register(
            workspace_scope.unwrap_or_else(|| WorkspaceRequestScope {
                workspace_id: 0,
                generation: service.workspace_generation(),
            }),
            bifrost_cancellation.clone(),
        );
        // The phase this request reports if its budget expires. The token is
        // registered above and travels into the synchronous analyzer, so a
        // wait deep inside the call -- the analyzer cache build lock, say --
        // replaces this with its own description for as long as it lasts and
        // the timeout below names it instead of the tool (issue #3170).
        let _execution_phase = bifrost_cancellation.enter_phase(format!("executing {name}"));

        let request_cancelled = mcp_cancellation.clone();
        let bridge_token = bifrost_cancellation.clone();
        let request_finished = McpCancellationToken::new();
        let bridge_guard = request_finished.clone().drop_guard();
        tokio::spawn(async move {
            tokio::select! {
                () = mcp_cancellation.cancelled() => bridge_token.cancel(),
                () = request_finished.cancelled() => {}
            }
        });

        let render_options = RenderOptions {
            render_line_numbers: self.render_options.render_line_numbers,
        };
        let execution_label =
            transport_phase_label("execution", &name, request_correlation_id.as_deref());
        let execution_name = name.clone();
        let execution_cancellation = bifrost_cancellation.clone();
        let execution_service = Arc::clone(&service);
        let mut output = tokio::task::spawn_blocking(move || {
            // Keep both the analyzer slot and the revocation registration until
            // cooperative cancellation has actually unwound the blocking work.
            // A timed-out client call must not free capacity for another scan
            // while its original scan is still consuming CPU.
            let _permit = permit;
            let _in_flight = in_flight;
            let _bridge_guard = bridge_guard;
            let _execution_scope = profiling::scope(execution_label);
            // Per-statement request histograms (BIFROST_SQL_PROFILE); the
            // request-local table is written beside the SQL profile file.
            let _sql_scope =
                brokk_bifrost_analysis::cache_db::sql_profile::request_scope(&execution_name);
            // The reader seam's per-request boundary (BIFROST_SEAM_PROFILE).
            // It is a no-op unless that variable names an output file.
            let _seam_scope = brokk_bifrost_analysis::seam_profile::request_scope(&execution_name);
            // The reference-seed repetition boundary (BIFROST_SEED_KEY_PROFILE),
            // a no-op on the same terms.
            let _seed_key_scope =
                brokk_bifrost_analysis::seed_key_profile::call_scope(&execution_name);
            let _cold_execution_scope =
                cold_workspace.then(|| profiling::scope("mcp_cold.first_tool_execution"));
            let output = execution_service.call_tool_output_with_transport_timings_and_preflight(
                &execution_name,
                arguments,
                render_options,
                Some(&execution_cancellation),
                transport_timings,
                suppression_preflight,
            )?;
            let output = if execution_name == "get_summaries" {
                fit_get_summaries_output_to_budget(
                    execution_service.as_ref(),
                    output,
                    render_options,
                )?
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
        let mut build_ticks = tokio::time::interval(Duration::from_millis(100));
        build_ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let output = loop {
            tokio::select! {
                // Phases first, and not at random: a phase already published
                // describes work this request really did, so it is reported
                // before the result that would end this loop. Reporting them
                // from this task, rather than from one of their own, is what
                // keeps them ordered with the request's other phase
                // notifications and stops any of them following the answer.
                biased;
                () = request_cancelled.cancelled() => {
                    bifrost_cancellation.cancel();
                    if let Some(progress) = progress { progress.workspace(&service, Some(RequestOutcome::Cancelled)).await; }
                    return Err(ErrorData::internal_error("the tool call was cancelled", None));
                }
                Some(phase) = phase_rx.recv() => {
                    progress
                        .expect("the phase sink is installed only when the caller opted into progress")
                        .phase(phase)
                        .await;
                }
                Some((kind, value)) = result_rx.recv() => {
                    progress
                        .expect("the result sink is installed only when the caller opted into progress")
                        .partial_result(kind, value)
                        .await;
                }
                _ = build_ticks.tick(), if progress.is_some() => {
                    progress.unwrap().workspace_tick(&service).await;
                }
                output = &mut output => {
                    if let Some(progress) = progress { progress.workspace(&service, if bifrost_cancellation.is_cancelled() { Some(RequestOutcome::Cancelled) }
                        else if matches!(&output, Err(_) | Ok(Err(_))) { Some(RequestOutcome::Failed) }
                        else { None }).await; }
                    break output.map_err(|error| {
                    ErrorData::internal_error(format!("MCP tool execution panicked: {error}"), None)
                })?;
                },
                () = async {
                    match request_budget {
                        Some(request_budget) => tokio::time::sleep_until(
                            tokio::time::Instant::from_std(request_budget.deadline()),
                        )
                        .await,
                        None => std::future::pending().await,
                    }
                } => {
                    bifrost_cancellation.cancel();
                    // The truthful last phase for this request: its analyzer
                    // work is now cooperatively cancelling. Sent before the
                    // deadline result, and never again after it -- the loop
                    // that forwards the analyzer's phases ends here.
                    if let Some(progress) = progress {
                        progress.workspace(&service, Some(RequestOutcome::Cancelled)).await;
                        progress.phase(format!("cancelling {name}")).await;
                    }
                    let phase = bifrost_cancellation.deadline_phase().expect(
                        "the request entered its execution phase before the budget could fire",
                    );
                    return Ok(deadline_result(IncompleteStage::Execution, &phase, None));
                }
            }
        };

        // The workspace can be rebound while a call runs. Returning results
        // computed against a scope the client has since revoked would leak the
        // old workspace, so the result is discarded in favor of a retry hint.
        if workspace_scope.is_some_and(|scope| scope.generation != service.workspace_generation()) {
            return Err(ErrorData::resource_not_found(
                "workspace changed while the tool call was running; retry the request",
                None,
            ));
        }

        match output {
            Ok(output) => Ok(tool_success_result(output)),
            // The worker can observe its deadline and return before the host
            // timer wins the select. Only a recorded token timeout projects
            // that failure; a late internal error alone is still an error.
            // Successful family partials above retain their own completion.
            Err(error) if bifrost_cancellation.is_timed_out() => {
                // The worker has already unwound the phase guards it held when
                // it observed the deadline, so read the phase it recorded then.
                let phase = bifrost_cancellation.deadline_phase().expect(
                    "the request entered its execution phase before the worker could time out",
                );
                Ok(deadline_result(
                    IncompleteStage::Execution,
                    &phase,
                    Some(&error.message),
                ))
            }
            Err(error) if error.code == SearchToolsServiceErrorCode::UnknownTool => {
                Ok(tool_error_result(error.message))
            }
            Err(error) => Err(map_service_failure(error)),
        }
    }

    /// Materialize one eligible tool call as a durable task (SEP-2663).
    ///
    /// The handle is pollable via `tasks/get` before this returns -- rmcp's
    /// manager inserts the entry ahead of spawning the operation -- and the
    /// operation itself reuses the synchronous path's semantics under
    /// task-mode bounds (see [`run_tool_as_task`]).
    fn create_tool_task(
        &self,
        name: String,
        arguments: Value,
        suppression_preflight: Option<PreparedRunPolicyPreflight>,
        workspace_scope: WorkspaceRequestScope,
        request_correlation_id: Option<String>,
        progress: Option<ProgressReporter>,
    ) -> Result<CallToolResponse, ErrorData> {
        // Bounded storage: tie the number of live tasks to the analyzer
        // backlog allowance rather than inventing a second knob. The task
        // future still queues for a real analyzer permit, so this only
        // bounds bookkeeping, not analyzer pressure.
        if self.task_manager.running_task_count() >= MAX_QUEUED_ANALYZER_REQUESTS {
            eprintln!(
                "bifrost: refusing a task for {name}; {MAX_QUEUED_ANALYZER_REQUESTS} tasks are already running"
            );
            return Err(ErrorData::internal_error(
                format!(
                    "too many analyzer tasks are running; retry {name} once earlier tasks complete"
                ),
                None,
            ));
        }

        let ttl = mcp_task_ttl();
        let service = Arc::clone(&self.service);
        let analyzer_pool = Arc::clone(&self.analyzer_pool);
        let in_flight = Arc::clone(&self.in_flight);
        let render_options = RenderOptions {
            render_line_numbers: self.render_options.render_line_numbers,
        };
        let task_name = name.clone();
        let task = self.task_manager.spawn(
            TaskOptions::new()
                .with_ttl_ms(u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX))
                .with_poll_interval_ms(TASK_POLL_INTERVAL_MS)
                .with_status_message(format!("{name}: created")),
            move |task_context| {
                Box::pin(run_tool_as_task(
                    service,
                    analyzer_pool,
                    in_flight,
                    render_options,
                    task_name,
                    arguments,
                    suppression_preflight,
                    workspace_scope,
                    ttl,
                    request_correlation_id,
                    task_context,
                    progress,
                ))
            },
        );
        self.task_scopes
            .record(task.task_id.clone(), workspace_scope, ttl);
        eprintln!(
            "bifrost: created MCP task tool={name} task_id={}",
            escape_terminal_text(&task.task_id)
        );
        Ok(CallToolResponse::Task(CreateTaskResult::new(task)))
    }

    /// Refuse any task operation whose handle predates the current workspace
    /// authorization.
    ///
    /// The scope map records the workspace generation each task was created
    /// under; a differing current generation means the client rebound or
    /// revoked its workspace, and the handle must never carry results across
    /// that boundary. An unknown handle falls through so rmcp's manager can
    /// answer with its own unknown-task error, which leaks nothing about
    /// whether the id ever existed here.
    fn check_task_authorization(&self, task_id: &str) -> Result<(), ErrorData> {
        let Some(scope) = self.task_scopes.lookup(task_id) else {
            return Ok(());
        };
        if scope.generation != self.service.workspace_generation() {
            // Stop the underlying work before refusing. A handle that is
            // already terminal has nothing left to stop; the manager's error
            // says so and does not change the refusal.
            if let Err(error) = self.task_manager.cancel_task(task_id) {
                eprintln!(
                    "bifrost: revoked task {} was already settled: {error}",
                    escape_terminal_text(task_id)
                );
            }
            return Err(workspace_revoked_error());
        }
        Ok(())
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
        run_policy_preflight: Option<PreparedRunPolicyPreflight>,
        /// The workspace generation this result is only valid for, or `None`
        /// for a tool whose whole job is to change the workspace. Rebinding
        /// tools hold the workspace lock for their duration, so nothing else
        /// can move the workspace underneath them, and checking their own
        /// change against them would fail every call.
        workspace_scope: Option<WorkspaceRequestScope>,
    },
    Reply(CallToolResult),
}

#[derive(Debug)]
enum AnalyzerAdmissionError {
    DeadlineExceeded,
    Protocol(ErrorData),
}

/// Take one analyzer slot, bounded by the request's own budget.
///
/// `request_budget` is the exact value that produced the request's deadline,
/// so the timeout arm names the budget that expired rather than reading the
/// configured knob a second time. Since #3279 that budget can be a fallback
/// rung with nothing configured, and #3396 is the panic that followed from
/// asking the configured knob alone.
#[derive(Debug, PartialEq, Eq)]
enum WorkspaceObservationStop {
    DeadlineExceeded,
    Cancelled,
}

/// Observing an unfinished build answers immediately, but installing a finished
/// one can race another request's session lock. Bound that await by the same
/// absolute deadline as admission and execution; stopping it never stops shared
/// preparation or its off-runtime observer.
async fn await_workspace_observation<T>(
    observation: impl std::future::Future<Output = T>,
    request_budget: Option<RequestBudget>,
    cancelled: &McpCancellationToken,
) -> Result<T, WorkspaceObservationStop> {
    let deadline = async {
        match request_budget {
            Some(budget) => tokio::time::sleep_until(budget.deadline().into()).await,
            None => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        biased;
        _ = cancelled.cancelled() => Err(WorkspaceObservationStop::Cancelled),
        _ = deadline => Err(WorkspaceObservationStop::DeadlineExceeded),
        observed = observation => Ok(observed),
    }
}

async fn await_analyzer_admission(
    pool: &AnalyzerExecutionPool,
    request_budget: Option<RequestBudget>,
    name: &str,
    cancelled: &McpCancellationToken,
) -> Result<AnalyzerPermit, AnalyzerAdmissionError> {
    let admission = match request_budget {
        Some(request_budget) => {
            tokio::time::timeout(
                request_budget
                    .deadline()
                    .saturating_duration_since(Instant::now()),
                pool.acquire(cancelled),
            )
            .await
        }
        None => Ok(pool.acquire(cancelled).await),
    };
    match admission {
        Ok(Admission::Granted(permit)) => Ok(permit),
        Ok(Admission::Cancelled) => {
            Err(AnalyzerAdmissionError::Protocol(ErrorData::internal_error(
                "the tool call was cancelled while waiting for analyzer capacity",
                None,
            )))
        }
        Ok(Admission::Saturated) => {
            eprintln!(
                "bifrost: refusing {name}; more than {} analyzer requests are already queued",
                MAX_QUEUED_ANALYZER_REQUESTS
            );
            Err(AnalyzerAdmissionError::Protocol(ErrorData::internal_error(
                format!(
                    "too many analyzer requests are queued; retry {name} once earlier calls complete"
                ),
                None,
            )))
        }
        Err(_elapsed) => {
            // Only the budgeted arm above can produce an elapsed timeout, and
            // this is that same value, so the diagnostic always names the
            // budget that bounded the wait.
            let request_budget = request_budget
                .expect("an admission wait is timed out only when the request had a budget");
            eprintln!(
                "bifrost: {name} exhausted its {:?} budget waiting for analyzer capacity",
                request_budget.budget()
            );
            Err(AnalyzerAdmissionError::DeadlineExceeded)
        }
    }
}

/// The operation behind one durable task: the synchronous execution path's
/// semantics -- readiness wait, analyzer admission, blocking execution,
/// workspace-generation re-checks -- under task-mode bounds.
///
/// The TTL is the deadline: the Bifrost cancellation token expires at
/// `created + ttl`, the same moment rmcp's manager would mark an unfinished
/// task `failed`, so the analyzer actually stops when the handle dies.
/// `tasks/cancel` is bridged into the same token, and the in-flight
/// registration means a workspace rebind cancels this work exactly as it
/// cancels a synchronous call's. Guards move into the blocking closure so
/// the registration and the bridge outlive a timed-out future for as long as
/// the blocking work is still unwinding, mirroring `execute_tool`.
#[allow(clippy::too_many_arguments)]
async fn run_tool_as_task(
    service: Arc<SearchToolsService>,
    analyzer_pool: Arc<AnalyzerExecutionPool>,
    in_flight: Arc<InFlightRequests>,
    render_options: RenderOptions,
    name: String,
    arguments: Value,
    suppression_preflight: Option<PreparedRunPolicyPreflight>,
    workspace_scope: WorkspaceRequestScope,
    ttl: Duration,
    request_correlation_id: Option<String>,
    task_context: TaskContext,
    mut progress: Option<ProgressReporter>,
) -> Result<CallToolResult, TaskExit> {
    if let Some(progress) = &mut progress {
        progress.task_id = Some(task_context.task_id().to_owned());
    }
    let result = run_tool_as_task_inner(
        service,
        analyzer_pool,
        in_flight,
        render_options,
        name,
        arguments,
        suppression_preflight,
        workspace_scope,
        ttl,
        request_correlation_id,
        task_context,
        &progress,
    )
    .await;
    // The terminal task result must not overtake a progress notification the
    // task already queued for this transport.
    if let Some(progress) = &progress {
        progress.finish().await;
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn run_tool_as_task_inner(
    service: Arc<SearchToolsService>,
    analyzer_pool: Arc<AnalyzerExecutionPool>,
    in_flight: Arc<InFlightRequests>,
    render_options: RenderOptions,
    name: String,
    arguments: Value,
    suppression_preflight: Option<PreparedRunPolicyPreflight>,
    workspace_scope: WorkspaceRequestScope,
    ttl: Duration,
    request_correlation_id: Option<String>,
    task_context: TaskContext,
    progress: &Option<ProgressReporter>,
) -> Result<CallToolResult, TaskExit> {
    let deadline = Instant::now() + ttl;
    let cancellation = crate::CancellationToken::default().with_deadline(deadline);

    // tasks/cancel flows into both cancellation domains: the async token
    // unparks admission waits, the Bifrost token stops the analyzer.
    let cancel_ct = McpCancellationToken::new();
    let finished = McpCancellationToken::new();
    let finished_guard = finished.clone().drop_guard();
    {
        let cancel_ct = cancel_ct.clone();
        let bifrost = cancellation.clone();
        let observed = task_context.clone();
        let finished = finished.clone();
        tokio::spawn(async move {
            tokio::select! {
                () = observed.cancelled() => {
                    cancel_ct.cancel();
                    bifrost.cancel();
                }
                () = finished.cancelled() => {}
            }
        });
    }

    let in_flight_guard = in_flight.register(workspace_scope, cancellation.clone());

    task_context.set_status_message(format!("{name}: waiting for workspace readiness"));
    let readiness_service = Arc::clone(&service);
    let readiness_cancellation = cancellation.clone();
    let mut readiness = tokio::task::spawn_blocking(move || {
        readiness_service
            .wait_workspace_ready_until(&|| readiness_cancellation.is_cancelled(), Some(deadline))
    });
    let mut build_ticks = tokio::time::interval(Duration::from_millis(100));
    build_ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let ready = loop {
        tokio::select! {
            result = &mut readiness => break result.map_err(|error| {
                TaskExit::Error(ErrorData::internal_error(format!("task readiness wait panicked: {error}"), None))
            })?,
            _ = build_ticks.tick(), if progress.is_some() => {
                progress.as_ref().unwrap().workspace_tick(&service).await;
            }
        }
    };
    if let Some(progress) = progress {
        progress
            .workspace(
                &service,
                ready
                    .as_ref()
                    .err()
                    .map(|_| RequestOutcome::after_error(cancellation.is_cancelled())),
            )
            .await;
    }
    ready.map_err(|error| task_exit(&task_context, map_service_failure(error)))?;

    task_context.set_status_message(format!("{name}: waiting for analyzer admission"));
    let admission = tokio::time::timeout(
        deadline.saturating_duration_since(Instant::now()),
        analyzer_pool.acquire(&cancel_ct),
    )
    .await;
    let permit = match admission {
        Ok(Admission::Granted(permit)) => permit,
        Ok(Admission::Cancelled) => return Err(TaskExit::Cancelled),
        Ok(Admission::Saturated) => {
            return Err(TaskExit::Error(ErrorData::internal_error(
                format!(
                    "too many analyzer requests are queued; retry {name} once earlier calls complete"
                ),
                None,
            )));
        }
        Err(_elapsed) => {
            return Err(TaskExit::Error(ErrorData::internal_error(
                format!("{name} exhausted its {ttl:?} task TTL waiting for analyzer capacity"),
                None,
            )));
        }
    };

    // Admission can take arbitrarily long; do not spend a slot on a scope the
    // client has since revoked.
    if service.workspace_generation() != workspace_scope.generation {
        return Err(TaskExit::Error(workspace_revoked_error()));
    }

    task_context.set_status_message(format!("{name}: executing"));
    let execution_service = Arc::clone(&service);
    let execution_cancellation = cancellation.clone();
    let execution_name = name.clone();
    let mut output = tokio::task::spawn_blocking(move || {
        // Held until cooperative cancellation has actually unwound the
        // blocking work: the analyzer slot, the revocation registration, and
        // the cancel bridge must not disappear while the scan still runs.
        let _permit = permit;
        let _in_flight = in_flight_guard;
        let _finished_guard = finished_guard;
        let _sql_scope =
            brokk_bifrost_analysis::cache_db::sql_profile::request_scope(&execution_name);
        // The reader seam's per-request boundary, as in `execute_tool`.
        let _seam_scope = brokk_bifrost_analysis::seam_profile::request_scope(&execution_name);
        let _seed_key_scope = brokk_bifrost_analysis::seed_key_profile::call_scope(&execution_name);
        let output = execution_service.call_tool_output_with_transport_timings_and_preflight(
            &execution_name,
            arguments,
            render_options,
            Some(&execution_cancellation),
            TransportTimings::default(),
            suppression_preflight,
        )?;
        Ok::<_, crate::SearchToolsServiceError>(if execution_name == "run_policy" {
            attach_run_policy_correlation(output, request_correlation_id.as_deref())
        } else {
            output
        })
    });
    let output = tokio::select! {
        // The analyzer observes the same deadline and can return its
        // structured cancellation report when this timer becomes ready.
        // Prefer expiry when both branches settle together so crossing the
        // task TTL cannot race into a terminal `completed` result.
        biased;
        () = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
            cancellation.cancel();
            return Err(task_exit(
                &task_context,
                ErrorData::internal_error(
                    format!("{name} exhausted its {ttl:?} task TTL; cancellation continues in the background"),
                    None,
                ),
            ));
        },
        output = &mut output => output.map_err(|error| {
            TaskExit::Error(ErrorData::internal_error(
                format!("MCP task execution panicked: {error}"),
                None,
            ))
        })?,
    };

    // The result must never leak a scope the client revoked mid-run.
    if service.workspace_generation() != workspace_scope.generation {
        return Err(TaskExit::Error(workspace_revoked_error()));
    }

    match output {
        Ok(output) => Ok(tool_success_result(output)),
        Err(error) if error.code == SearchToolsServiceErrorCode::UnknownTool => {
            Ok(tool_error_result(error.message))
        }
        Err(error) => Err(task_exit(&task_context, map_service_failure(error))),
    }
}

/// Settle as `cancelled` when the failure is the client's own `tasks/cancel`
/// unwinding the work, and as `failed` with the error otherwise.
fn task_exit(task_context: &TaskContext, error: ErrorData) -> TaskExit {
    if task_context.is_cancel_requested() {
        TaskExit::Cancelled
    } else {
        TaskExit::Error(error)
    }
}

fn workspace_revoked_error() -> ErrorData {
    ErrorData::invalid_params(
        "the task's workspace authorization was revoked; the handle is no longer valid",
        None,
    )
}

fn tool_success_result(output: crate::ToolOutput) -> CallToolResult {
    // SDK-owned Value/text copies start at this compatibility boundary.
    match output.into_compat_output() {
        crate::ToolOutput::QueryResponse(_) => {
            unreachable!("compatibility conversion erases typed queries")
        }
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

/// Host stops carry no family payload: outputSchema applies to a tool's
/// structuredContent, so this result deliberately uses only content and _meta.
#[derive(Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum IncompleteStage {
    WorkspaceActivation,
    WorkspaceReadiness,
    AnalyzerAdmission,
    Execution,
}

fn deadline_result(
    stage: IncompleteStage,
    phase: &str,
    stopped_with: Option<&str>,
) -> CallToolResult {
    let stage_name = match stage {
        IncompleteStage::WorkspaceActivation => "workspace_activation",
        IncompleteStage::WorkspaceReadiness => "workspace_readiness",
        IncompleteStage::AnalyzerAdmission => "analyzer_admission",
        IncompleteStage::Execution => "execution",
    };
    let mut text = format!("request deadline exceeded at {stage_name} while {phase}");
    if matches!(stage, IncompleteStage::WorkspaceReadiness) {
        // wait_workspace_ready_until only stops the waiter. The shared build
        // retains its own lifetime and is not cancelled by this deadline.
        text.push_str("; workspace preparation continues");
    }
    if let Some(message) = stopped_with {
        text.push_str("; the work stopped with: ");
        text.push_str(message);
    }
    incomplete_result("deadline_exceeded", stage, phase, text)
}

fn workspace_not_ready_result(phase: &str, named_mode: bool) -> CallToolResult {
    let next = if named_mode {
        "retry"
    } else {
        "check get_active_workspace or retry"
    };
    incomplete_result(
        "workspace_not_ready",
        IncompleteStage::WorkspaceReadiness,
        phase,
        format!(
            "workspace not ready at workspace_readiness while {phase}; workspace preparation continues; {next}"
        ),
    )
}

fn incomplete_result(
    reason: &str,
    stage: IncompleteStage,
    phase: &str,
    text: String,
) -> CallToolResult {
    let mut incomplete = json!({
        "status": "inconclusive",
        "completion": {"type": "inconclusive", "reasons": [reason]},
        "stage": stage,
        "phase": phase,
        "partial": false,
    });
    if matches!(stage, IncompleteStage::WorkspaceReadiness) {
        incomplete["workspace_preparation"] = json!("continues");
    }
    let mut result = tool_error_result(text);
    let mut meta = MetaObject::new();
    meta.0
        .insert("io.bifrost/incomplete".to_owned(), incomplete);
    result.meta = Some(meta);
    result
}

fn unbound_workspace_error() -> ErrorData {
    ErrorData::internal_error(UNBOUND_WORKSPACE_MESSAGE, None)
}

fn map_service_failure(error: crate::SearchToolsServiceError) -> ErrorData {
    let incomplete = error.workspace_incomplete;
    let mut mapped = map_service_error(error.code, error.message);
    if let Some(incomplete) = incomplete {
        mapped.data = Some(json!({"io.bifrost/workspace-incomplete": incomplete}));
    }
    mapped
}

fn map_service_error(code: SearchToolsServiceErrorCode, message: String) -> ErrorData {
    match code {
        SearchToolsServiceErrorCode::WorkspaceUnavailable => {
            ErrorData::internal_error(message, None)
        }
        SearchToolsServiceErrorCode::InvalidParams => ErrorData::invalid_params(message, None),
        SearchToolsServiceErrorCode::StaleWorkspaceGeneration { requested, current } => {
            ErrorData::invalid_params(
                message,
                Some(serde_json::json!({
                    "kind": "stale_workspace_generation",
                    "requested": requested,
                    "current": current,
                    "retryable": true,
                })),
            )
        }
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
    speaks_at_least(context, rmcp::model::ProtocolVersion::V_2026_07_28)
}

/// Whether this request's peer negotiated MCP `2025-06-18` or newer.
///
/// `outputSchema` on a tool descriptor entered the spec at that revision, so a
/// `2024-11-05` or `2025-03-26` peer must not see it. `protocol_version()`
/// reads the request's own `_meta` first and falls back to the connection
/// handshake, which is the same combination the cache hints use.
fn speaks_2025_06_18(context: &RequestContext<RoleServer>) -> bool {
    speaks_at_least(context, rmcp::model::ProtocolVersion::V_2025_06_18)
}

fn speaks_at_least(
    context: &RequestContext<RoleServer>,
    minimum: rmcp::model::ProtocolVersion,
) -> bool {
    context
        .protocol_version()
        .is_some_and(|version| version >= minimum)
}

/// Whether this request negotiated protocol version and capabilities on its
/// own, through the `2026-07-28` per-request `_meta` keys, instead of through
/// a connection-level `initialize`.
///
/// This is deliberately read from the request's own `_meta`, never from
/// connection state: it is the per-request counterpart of
/// [`ConnectionState::negotiated`]. rmcp dispatches a request that declares
/// `2026-07-28` or newer in its `_meta` only after checking that the version
/// is one it supports and that the required negotiation keys
/// (`io.modelcontextprotocol/protocolVersion` and `.../clientCapabilities`)
/// are present and well formed, so a request this returns `true` for is
/// exactly as negotiated as a legacy connection is after `initialize` -- per
/// request rather than per connection.
fn request_negotiates_per_request(meta: &rmcp::model::RequestMetaObject) -> bool {
    let negotiated = meta
        .protocol_version()
        .is_some_and(|version| version >= rmcp::model::ProtocolVersion::V_2026_07_28);
    // rmcp validated the full 2026-07-28 key set before dispatch; a request
    // that declares the version but carries no capabilities is a dispatch bug,
    // not a state to tolerate.
    debug_assert!(
        !negotiated || meta.client_capabilities().is_some(),
        "rmcp dispatched a 2026-07-28 request without client capabilities"
    );
    negotiated
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

impl BifrostMcpHandler {
    /// Whether this server offers durable task execution (SEP-2663).
    ///
    /// Only the single-workspace host does. Named-workspace mode is excluded
    /// to keep the initial contract narrow; adding it later means recording
    /// the named workspace id in the task's scope, which
    /// [`WorkspaceRequestScope`] already carries.
    fn tasks_active(&self) -> bool {
        self.named_workspaces.is_none()
    }
}

impl ServerHandler for BifrostMcpHandler {
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        // These are the two revisions covered by Bifrost's real-process wire
        // and conformance gates. Do not advertise every revision the SDK knows:
        // adding one is a Bifrost compatibility decision, not an rmcp upgrade
        // side effect.
        Cow::Borrowed(&[ProtocolVersion::V_2025_11_25, ProtocolVersion::V_2026_07_28])
    }

    fn get_info(&self) -> ServerInfo {
        let mut info = InitializeResult::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
        )
        .with_server_info(Implementation::new("bifrost", env!("CARGO_PKG_VERSION")))
        .with_instructions(self.instructions.clone());
        if self.tasks_active() {
            // Advertised only while the complete contract is live: eligible
            // tools return task handles and tasks/get, tasks/update, and
            // tasks/cancel are all served. `server/discover` and `initialize`
            // both derive from this, so both entry paths see it.
            info.capabilities
                .extensions
                .get_or_insert_with(Default::default)
                .insert(TASKS_EXTENSION_ID.to_string(), serde_json::Map::new());
        }
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
        let mut tools = self.tools.clone();
        if !speaks_2025_06_18(&_context) {
            // Descriptors carry the advertised output schemas unconditionally;
            // a peer on a revision that predates `outputSchema` gets a clean
            // legacy wire instead of a field it has no schema for.
            for tool in &mut tools {
                tool.output_schema = None;
            }
        }
        let result = ListToolsResult::with_all_items(tools);
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

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        Err(ErrorData::new(
            rmcp::model::ErrorCode::METHOD_NOT_FOUND,
            "Method not found: prompts/list",
            None,
        ))
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        Err(ErrorData::new(
            rmcp::model::ErrorCode::METHOD_NOT_FOUND,
            "Method not found: resources/templates/list",
            None,
        ))
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
        let mut info = self.negotiate_initialize(&request)?;
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
        if self.client_roots_binding_is_stale(&state)
            && let Err(error) = self.revoke_client_roots(&self.service.as_ref(), &mut state)
        {
            eprintln!("bifrost: failed to revoke client roots: {error}");
        }
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let result: Result<CallToolResponse, ErrorData> = async {
        let name = request.name.to_string();
        let is_readiness_probe = name == "get_active_workspace";
        // A measurement control, deliberately absent from every descriptor and
        // public tools/list. rmcp's default get_tool returns None, permitting
        // dispatch without inventing a second protocol or advertising a schema.
        #[cfg(feature = "test-support")]
        if name == "__bifrost_retention_census" {
            let arguments = request.arguments.map_or_else(|| json!({}), Value::Object);
            let service = Arc::clone(&self.service);
            let output = tokio::task::spawn_blocking(move || {
                service.call_tool_output_with_cancellation(
                    "__bifrost_retention_census",
                    arguments,
                    RenderOptions::default(),
                    None,
                )
            })
            .await
            .map_err(|error| {
                ErrorData::internal_error(format!("retention census panicked: {error}"), None)
            })?
            .map_err(map_service_failure)?;
            return Ok(tool_success_result(output).into());
        }
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
            .map_err(map_service_failure)?;
            return Ok(tool_success_result(output).into());
        }

        let named_mode = self.named_workspaces.is_some();
        let (service, prepared, state) = if named_mode {
            let (service, prepared) = self.prepare_named_tool_call(&name, arguments)?;
            (service, prepared, None)
        } else if is_readiness_probe {
            self.ensure_probe_workspace(&context).await?;
            let mut state = self.try_probe_connection()?;
            let binding = ProbeWorkspace(&self.service);
            if self.client_roots_binding_is_stale(&state) { self.revoke_client_roots(&binding, &mut state)?; }
            if let Some(input_required) = self.activate_workspace_over_mrtr(&binding, &mut state, &request, &context)? { return Ok(input_required.into()); }
            let prepared = self.prepare_tool_call(&binding, &mut state, &name, arguments, &context.meta)?;
            // This guard protects authorization only; the service poll observes
            // its own locks after it has been released.
            drop(state);
            (Arc::clone(&self.service), prepared, None)
        } else {
            // Negotiating a workspace can require a client round trip, so it
            // happens before the preparation lock is taken.
            self.ensure_client_workspace(&context).await?;
            let mut state = self.workspace.lock().await;
            if self.client_roots_binding_is_stale(&state) {
                self.revoke_client_roots(&self.service.as_ref(), &mut state)?;
            }
            if let Some(input_required) = self
                .activate_workspace_over_mrtr(&self.service.as_ref(), &mut state, &request, &context)?
            {
                return Ok(input_required.into());
            }
            let prepared = self.prepare_tool_call(&self.service.as_ref(), &mut state, &name, arguments, &context.meta)?;
            (Arc::clone(&self.service), prepared, Some(state))
        };
        let correlation_id = serde_json::to_value(&context.id)
            .ok()
            .map(|id| request_correlation_id(&id));
        let (arguments, run_policy_preflight, workspace_scope) = match prepared {
            PreparedToolCall::Reply(result) => {
                let result = if name == "run_policy" {
                    attach_run_policy_correlation_result(result, correlation_id.as_deref())
                } else {
                    result
                };
                return Ok(result.into());
            }
            PreparedToolCall::Ready {
                arguments,
                run_policy_preflight,
                workspace_scope,
            } => (arguments, run_policy_preflight, workspace_scope),
        };
        let current_scope = WorkspaceRequestScope {
            workspace_id: workspace_scope.map_or(0, |scope| scope.workspace_id),
            generation: service.workspace_generation(),
        };
        self.in_flight.cancel_stale(current_scope);
        // Workspace-mutating tools keep the workspace lock for their whole
        // execution, which already bounds them to one at a time. Making them
        // also queue for an analyzer permit would let a trivial call like
        // `get_active_workspace` sit behind four long scans *while holding the
        // lock*, stalling every other request's preparation -- the opposite of
        // what the pool exists to protect.
        // Derived from the wire id the same way the fallback host derives it,
        // so the two never disagree about a report's correlation value.
        let serial = !named_mode && serial_tool_request(&name);
        // `state` must leave scope here either way. `if serial { state } else
        // { None }` moves it only in the serial branch; the non-serial branch
        // leaves the maybe-moved binding alive until the end of this function,
        // holding the workspace lock across readiness, admission, and the
        // whole analyzer execution -- which serializes every tool call on the
        // connection and starves light requests behind heavy scans (the
        // `mcp_fairness` benchmark failure). `then_some` evaluates its
        // argument eagerly, so the guard moves and drops now for non-serial
        // calls.
        // The readiness poll remains admission-exempt, but never holds the
        // connection workspace lock while observing service locks.
        let _serial_guard = serial.then_some(state).flatten();

        let progress = ProgressReporter::from_request(
            &context,
            &service,
            &name,
            workspace_scope
                .map_or_else(|| service.workspace_generation(), |scope| scope.generation),
        );

        // Durable task execution (SEP-2663) for eligible batch tools. The
        // decision is server-directed and deterministic: a capable
        // `2026-07-28` request calling an eligible tool gets a task handle,
        // everyone else keeps the synchronous path -- rmcp's dispatch
        // additionally refuses a task-shaped response to a client that never
        // declared the capability. Argument validation and workspace
        // authorization already happened above, synchronously, so a
        // malformed call fails immediately instead of parking its error
        // inside a task the client must poll to discover.
        if self.tasks_active()
            && task_eligible_tool(&name)
            && speaks_2026_07_28(&context)
            && context
                .client_capabilities()
                .is_some_and(|capabilities| capabilities.supports_tasks())
            && let Some(workspace_scope) = workspace_scope
        {
            return self.create_tool_task(
                name,
                arguments,
                run_policy_preflight,
                workspace_scope,
                correlation_id,
                progress,
            );
        }

        // Progress is opt-in per request: no `progressToken`, no reporter, no
        // notifications. Workspace-activation rounds returned
        // above never report progress -- they are answers, not phases of an
        // executing call.

        let accepted_at = Instant::now();
        let request_budget = RequestBudget::resolve(&name, accepted_at);
        let cold_workspace = !is_readiness_probe && service.workspace_build_pending();
        let workspace_readiness_wait = Duration::ZERO;
        // Observe initial construction without waiting for it. Scheduling and
        // installation contention share the normal request budget; durable
        // workers above retain their blocking preparation path.
        if !matches!(name.as_str(), "get_active_workspace" | "activate_workspace") {
            // Observation can install a finished build under synchronous
            // service locks. Keep that work off the transport runtime.
            let readiness_service = Arc::clone(&service);
            let observation = tokio::task::spawn_blocking(move || {
                // The request can stop waiting before this shared install
                // finishes. Report any panic even when nobody awaits the job.
                crate::panic_report::report_panics("workspace readiness observation", || {
                    readiness_service.observe_or_start_workspace()
                })
                .map_err(|panic| {
                    let message = panic.to_string();
                    eprintln!("{message}");
                    ErrorData::internal_error(message, None)
                })
            });
            let observed = await_workspace_observation(
                async {
                    observation.await.map_err(|error| {
                        ErrorData::internal_error(
                            format!("workspace readiness observation task failed: {error}"),
                            None,
                        )
                    })?
                },
                request_budget,
                &context.ct,
            )
            .await;
            let observed = match observed {
                Ok(result) => result?,
                Err(stop) => {
                    if let Some(progress) = &progress {
                        progress.finish().await;
                    }
                    return match stop {
                        WorkspaceObservationStop::Cancelled => Err(ErrorData::internal_error(
                            "the tool call was cancelled while observing workspace readiness",
                            None,
                        )),
                        WorkspaceObservationStop::DeadlineExceeded => {
                            let phase = service
                                .workspace_build_progress(service.workspace_generation())
                                .and_then(|snapshot| snapshot.phase)
                                .unwrap_or_else(|| "observing workspace readiness".to_owned());
                            Ok(
                                deadline_result(IncompleteStage::WorkspaceReadiness, &phase, None)
                                    .into(),
                            )
                        }
                    };
                }
            };
            match observed {
                Ok(true) => {
                    if let Some(progress) = &progress {
                        progress.workspace(&service, None).await;
                    }
                }
                Ok(false) => {
                    let phase = service
                        .workspace_build_progress(service.workspace_generation())
                        .and_then(|snapshot| snapshot.phase)
                        .unwrap_or_else(|| "preparing workspace analyzer".to_owned());
                    if let Some(progress) = &progress {
                        progress.workspace(&service, None).await;
                        progress.finish().await;
                    }
                    return Ok(workspace_not_ready_result(&phase, named_mode).into());
                }
                Err(error) => return Err(map_service_failure(error)),
            }
        }

        // One deadline spans admission and execution. Starting the clock after
        // admission would make the request budget mean "time spent analyzing"
        // while a client experiences queue wait plus a full budget -- and the
        // `mcp_fairness` p95 gate in benchmark/interactive-latency.toml is
        // written against what the client experiences.
        let admission_started_at = Instant::now();
        let permit = if serial {
            AnalyzerPermit::exempt()
        } else {
            if let Some(progress) = &progress {
                progress.phase("waiting for analyzer admission").await;
            }
            match await_analyzer_admission(&self.analyzer_pool, request_budget, &name, &context.ct)
                .await
            {
                Ok(permit) => permit,
                Err(error) => {
                    if let Some(progress) = &progress {
                        progress
                            .workspace(
                                &service,
                                Some(RequestOutcome::after_error(context.ct.is_cancelled())),
                            )
                            .await;
                        progress.finish().await;
                    }
                    return match error {
                        AnalyzerAdmissionError::DeadlineExceeded => Ok(deadline_result(
                            IncompleteStage::AnalyzerAdmission,
                            "waiting for analyzer admission",
                            None,
                        )
                        .into()),
                        AnalyzerAdmissionError::Protocol(error) => Err(error),
                    };
                }
            }
        };
        let analyzer_admission_wait = admission_started_at.elapsed();
        let queue_wait = accepted_at.elapsed();
        profiling::duration(
            transport_phase_label("workspace_readiness_wait", &name, correlation_id.as_deref()),
            workspace_readiness_wait,
        );
        profiling::duration(
            transport_phase_label("analyzer_admission_wait", &name, correlation_id.as_deref()),
            analyzer_admission_wait,
        );
        profiling::duration(
            transport_phase_label("queue_wait", &name, correlation_id.as_deref()),
            queue_wait,
        );
        if analyzer_admission_wait >= ANALYZER_QUEUE_WAIT_REPORT_THRESHOLD {
            // Otherwise a saturated pool is invisible without BIFROST_TIMING,
            // and every client just appears slow for no stated reason. The
            // readiness wait is deliberately excluded: a slow cold build is
            // the workspace's story, not the pool's, and attributing it to
            // analyzer slots sent #3279's investigation down the wrong path.
            eprintln!(
                "bifrost: {name} waited {analyzer_admission_wait:?} for one of {ANALYZER_POOL_CAPACITY} analyzer slots"
            );
        }

        // Admission can take arbitrarily long, and the workspace may have been
        // rebound in the meantime. Re-check before spending a slot on a scope
        // the client no longer authorizes.
        if workspace_scope.is_some_and(|scope| scope.generation != service.workspace_generation()) {
            if let Some(progress) = &progress {
                progress.finish().await;
            }
            if is_readiness_probe {
                return Err(map_service_failure(service.workspace_busy("workspace binding changed before observing readiness")));
            }
            return Err(ErrorData::resource_not_found(
                "workspace changed before the tool call could start; retry the request",
                None,
            ));
        }

        // No "executing {name}" notification from here: `execute_tool` records
        // that phase on the request's cancellation token, and the token now
        // reports every phase it enters to this client, so sending one as well
        // would report the phase twice. One publisher keeps the client's
        // progress and the budget error's phase saying the same thing.
        let response = self
            .execute_tool(
                Arc::clone(&service),
                name.clone(),
                arguments,
                run_policy_preflight,
                workspace_scope,
                request_budget,
                correlation_id.clone(),
                context.ct.clone(),
                permit,
                cold_workspace,
                TransportTimings {
                    transport_queue_wait: queue_wait,
                    workspace_readiness_wait,
                    analyzer_admission_wait,
                },
                progress.as_ref(),
            )
            .await;
        // The response -- success or execution error -- is ready the moment
        // execute_tool returns; everything after this point is transport. Arm
        // the timing keyed by the wire id so the transport wrapper can emit
        // `response_queue_wait` and `writer_delivery` when it delivers it.
        self.response_timings
            .arm(context.id.clone(), name, correlation_id);
        if let Some(progress) = &progress {
            progress.finish().await;
        }
        // The poll releases the connection guard before observing the service.
        // Unlike the previous serial path, another call can now change Codex's
        // per-call grant during that gap. Discard a snapshot whose binding was
        // not the one authorized above, after draining any progress delivery.
        if is_readiness_probe && workspace_scope.is_some_and(|scope| scope.generation != service.workspace_generation()) {
            return Err(map_service_failure(service.workspace_busy("workspace binding changed while observing readiness")));
        }
        Ok(response?.into())
        }.await;
        match result {
            Err(error)
                if error
                    .data
                    .as_ref()
                    .and_then(|data| data.get("io.bifrost/workspace-incomplete"))
                    .is_some() =>
            {
                let incomplete = &error.data.as_ref().unwrap()["io.bifrost/workspace-incomplete"];
                let reason = incomplete["reason"]
                    .as_str()
                    .expect("workspace failure has a reason");
                let phase = incomplete["phase"]
                    .as_str()
                    .expect("workspace failure has a phase");
                let mut result = incomplete_result(
                    reason,
                    IncompleteStage::WorkspaceActivation,
                    phase,
                    error.message.to_string(),
                );
                result
                    .meta
                    .as_mut()
                    .unwrap()
                    .0
                    .get_mut("io.bifrost/incomplete")
                    .unwrap()["retiring_workspaces"] = incomplete["retiring_workspaces"].clone();
                Ok(result.into())
            }
            result => result,
        }
    }

    async fn get_task(
        &self,
        request: GetTaskParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetTaskResult, ErrorData> {
        self.check_task_authorization(&request.task_id)?;
        Ok(GetTaskResult::new(
            self.task_manager.get_task(&request.task_id)?,
        ))
    }

    /// Bifrost issues no mid-task input requests yet, so every update
    /// necessarily names a key that is not outstanding; rmcp's manager
    /// answers accordingly. The method is still served so the extension
    /// contract is complete.
    async fn update_task(
        &self,
        request: UpdateTaskParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        self.check_task_authorization(&request.task_id)?;
        self.task_manager
            .update_task(&request.task_id, request.input_responses)
    }

    async fn cancel_task(
        &self,
        request: CancelTaskParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        self.check_task_authorization(&request.task_id)?;
        self.task_manager.cancel_task(&request.task_id)
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

/// Reads the startup environment shared by both stdio entry points. Every value
/// is checked here, before any request, so a bad one exits 1 at launch.
fn stdio_file_watching_enabled() -> Result<bool, String> {
    install_protocol_diagnostics(std::env::var_os(MCP_LOG_LEVEL_ENV).as_deref())?;
    validate_mcp_analyzer_request_budget_env()?;
    file_watching_enabled(std::env::var_os(MCP_FILE_WATCHER_ENV).as_deref())
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
    diff_snapshot_object_dir: Option<PathBuf>,
    build_identity: &str,
) -> Result<(), String> {
    run_stdio_server_with_host_activation_context(
        root,
        render_options,
        spec,
        diff_snapshot_object_dir,
        build_identity,
        HostActivationContext::library_none(),
    )
}

/// [`run_stdio_server_with_build_identity`] under the host's approval
/// authority. The context is built once by the host and the same `Arc` is
/// bound to every analyzer the server builds, before any pack activation.
/// Nothing a client sends (tool arguments, roots, metadata) can supply or
/// replace it.
pub fn run_stdio_server_with_host_activation_context(
    root: Option<PathBuf>,
    render_options: McpRenderOptions,
    spec: &McpServerSpec,
    diff_snapshot_object_dir: Option<PathBuf>,
    build_identity: &str,
    host: Arc<HostActivationContext>,
) -> Result<(), String> {
    // Explicit roots build in the background. Rootless servers answer
    // initialize without touching process cwd and bind only from a
    // client-provided workspace.
    let accepts_client_roots = root.is_none();
    let watch_files = stdio_file_watching_enabled()?;
    let service = match (root, watch_files) {
        (Some(root), true) => {
            SearchToolsService::new_deferred_with_host_activation_context(root, host)?
        }
        (Some(root), false) => {
            SearchToolsService::new_deferred_manual_with_host_activation_context(root, host)?
        }
        (None, true) => SearchToolsService::new_unbound_with_host_activation_context(host),
        (None, false) => SearchToolsService::new_unbound_manual_with_host_activation_context(host),
    };
    let service = match diff_snapshot_object_dir {
        Some(dir) => service.with_diff_snapshot_object_dir(dir),
        None => service,
    };
    let service = Arc::new(service);
    run_stdio_server_impl(
        service,
        None,
        render_options,
        spec,
        build_identity,
        accepts_client_roots,
    )
}

/// Serve a fixed set of named workspaces through one rmcp connection.
pub fn run_named_workspace_stdio_server_with_build_identity(
    workspaces: Vec<NamedWorkspace>,
    render_options: McpRenderOptions,
    spec: &McpServerSpec,
    build_identity: &str,
) -> Result<(), String> {
    run_named_workspace_stdio_server_with_host_activation_context(
        workspaces,
        render_options,
        spec,
        build_identity,
        HostActivationContext::library_none(),
    )
}

/// [`run_named_workspace_stdio_server_with_build_identity`] under the host's
/// approval authority; every named workspace's service shares the one `Arc`.
pub fn run_named_workspace_stdio_server_with_host_activation_context(
    workspaces: Vec<NamedWorkspace>,
    render_options: McpRenderOptions,
    spec: &McpServerSpec,
    build_identity: &str,
    host: Arc<HostActivationContext>,
) -> Result<(), String> {
    let watch_files = stdio_file_watching_enabled()?;
    let router = Arc::new(NamedWorkspaceRouter::new(workspaces, watch_files, host)?);
    let service = router.primary_service();
    run_stdio_server_impl(
        service,
        Some(router),
        render_options,
        spec,
        build_identity,
        false,
    )
}

fn run_stdio_server_impl(
    service: Arc<SearchToolsService>,
    named_workspaces: Option<Arc<NamedWorkspaceRouter>>,
    render_options: McpRenderOptions,
    spec: &McpServerSpec,
    build_identity: &str,
    accepts_client_roots: bool,
) -> Result<(), String> {
    // The handler and the transport share this counter: the transport
    // increments it in wire order, the handler compares against it.
    let roots_revocations = Arc::new(RootsRevocations::default());
    // Shared the same way: the handler arms a response's timing when its
    // result is ready, and the transport emits the delivery phases.
    let response_timings = Arc::new(OutboundResponseTimings::default());
    let handler = BifrostMcpHandler::new(
        Arc::clone(&service),
        named_workspaces.clone(),
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

    // rmcp handles a stateless session's first request inside `serve`, before
    // it spawns the ordinary request loop. Poll the whole lifecycle on the
    // runtime so cold requests use the same executor as subsequent requests;
    // polling bootstrap on the Windows process main stack overflowed on a
    // first task-capable run_policy call (#4488).
    let session = runtime.spawn(async move {
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
        let reason = running
            .waiting()
            .await
            .map_err(|error| format!("MCP session ended abnormally: {error}"))?;
        match reason {
            QuitReason::Closed | QuitReason::Cancelled => Ok(()),
            QuitReason::JoinError(error) => Err(format!("MCP send task failed: {error}")),
            reason => Err(format!("MCP session ended unexpectedly: {reason:?}")),
        }
    });
    let result = runtime
        .block_on(session)
        .map_err(|error| format!("MCP session task failed: {error}"))
        .and_then(|result| result);
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
        if let Some(router) = named_workspaces {
            std::mem::forget(router);
        }
    }
    result
}

#[cfg(test)]
mod named_workspace_tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    fn schema_router() -> NamedWorkspaceRouter {
        let entries = ["api", "ui"]
            .into_iter()
            .enumerate()
            .map(|(index, name)| NamedWorkspaceEntry {
                id: index as u64 + 1,
                name: name.to_string(),
                root: PathBuf::from(format!("/{name}")),
                service: Mutex::new(None),
            })
            .collect::<Vec<_>>();
        NamedWorkspaceRouter {
            by_name: HashMap::from([("api".to_string(), 0), ("ui".to_string(), 1)]),
            entries,
            watch_files: false,
            host_activation: HostActivationContext::library_none(),
        }
    }

    #[test]
    #[hardwon("65092f1ba920: malformed suppressions must fail before deferred workspace readiness")]
    fn named_run_policy_preflights_suppressions_before_readiness() {
        let temp = tempfile::tempdir().expect("workspace temp dir");
        std::fs::write(temp.path().join("Policy.java"), "class Policy {}\n")
            .expect("workspace source");
        std::fs::create_dir_all(temp.path().join(".bifrost")).expect("suppression parent");
        std::fs::write(
            temp.path().join(".bifrost/suppressions.json"),
            "{ malformed",
        )
        .expect("malformed suppressions");
        let router = Arc::new(
            NamedWorkspaceRouter::new(
                vec![NamedWorkspace::new(
                    "api".to_string(),
                    temp.path().to_path_buf(),
                )],
                false,
                HostActivationContext::library_none(),
            )
            .expect("named router"),
        );
        let spec =
            crate::mcp_registry::resolve_server_spec("searchtools").expect("searchtools spec");
        let handler = BifrostMcpHandler::new(
            router.primary_service(),
            Some(Arc::clone(&router)),
            McpRenderOptions::default(),
            &spec,
            "test",
            false,
            Arc::new(RootsRevocations::default()),
            Arc::new(OutboundResponseTimings::default()),
        )
        .expect("handler");

        let (_, prepared) = handler
            .prepare_named_tool_call(
                "run_policy",
                json!({
                    "workspace": "api",
                    "policy_ids": ["bifrost.correctness.dynamic-evaluation"],
                    "evaluation_date": "2026-07-27",
                    "fail_on": "warning"
                }),
            )
            .expect("named preparation");
        let PreparedToolCall::Reply(result) = prepared else {
            panic!("malformed suppressions must return before named readiness");
        };
        let structured = result
            .structured_content
            .expect("early run_policy reply is structured");
        assert_eq!(structured["status"], "unreliable");
        assert_eq!(structured["exit_status"], 2);
        assert_eq!(
            structured["report"]["diagnostics"].as_array().map(Vec::len),
            Some(1)
        );
        assert_eq!(structured["report"]["rules"], json!([]));
        assert_eq!(structured["report"]["runs"], json!([]));
        let stages = structured["report"]["execution"]["stage_timings"]
            .as_array()
            .expect("stage timings");
        assert!(
            stages
                .iter()
                .any(|timing| timing["stage"] == "suppression_preflight")
        );
        assert!(
            stages
                .iter()
                .all(|timing| timing["stage"] != "workspace_snapshot")
        );
    }

    #[test]
    fn named_mode_adds_bounded_routing_without_exposing_paths() {
        let instructions = schema_router()
            .instructions("Semantic source-code analysis.")
            .expect("named workspace instructions");
        assert!(instructions.contains("Set the workspace argument"));
        assert!(!instructions.contains("/api"));
        assert!(!instructions.contains("/ui"));
        assert!(instructions.chars().count() <= MCP_DISCOVERY_TEXT_MAX_CHARS);

        let error = schema_router()
            .instructions(&"x".repeat(MCP_DISCOVERY_TEXT_MAX_CHARS))
            .expect_err("named workspace guidance must keep the final instruction bounded");
        assert!(error.contains("named-workspace MCP server instructions"));
    }

    #[test]
    fn named_guidance_accepts_exact_character_limit() {
        let router = schema_router();
        let suffix_chars = router.instructions("").expect("suffix").chars().count();
        let base = "x".repeat(MCP_DISCOVERY_TEXT_MAX_CHARS - suffix_chars);
        let exact = router.instructions(&base).expect("exact maximum allowed");
        assert_eq!(exact.chars().count(), MCP_DISCOVERY_TEXT_MAX_CHARS);
        assert!(router.instructions(&(base + "x")).is_err());
    }

    #[test]
    fn named_tool_schemas_require_a_configured_workspace() {
        let descriptors = crate::mcp_core::symbol_tool_descriptors(true);
        let routed =
            named_workspace_descriptors(&descriptors, &schema_router()).expect("named descriptors");
        let search = routed
            .iter()
            .find(|descriptor| descriptor["name"] == "search_symbols")
            .expect("search_symbols descriptor");
        assert_eq!(search["inputSchema"]["required"][0], "workspace");
        assert_eq!(
            search["inputSchema"]["properties"]["workspace"]["enum"],
            json!(["api", "ui"])
        );
    }

    #[test]
    fn named_mode_removes_mutable_workspace_navigation() {
        let descriptors = crate::mcp_core::workspace_tool_descriptors();
        let names = named_workspace_descriptors(&descriptors, &schema_router())
            .expect("named descriptors")
            .into_iter()
            .map(|descriptor| descriptor["name"].as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["refresh"]);
    }
}

/// Issue #3396: an analyzer-admission timeout answers with the typed error
/// whatever budget bounded the wait.
///
/// Since #3279 a request can be bounded by the fallback ladder with no
/// `BIFROST_MCP_REQUEST_BUDGET_SECS` set -- 60 s interactive and
/// 240 s for a synchronous `run_policy`. The timeout arm used
/// to re-read the configured knob and `expect` it, so exactly those waits
/// panicked the server instead of answering "timed out waiting for analyzer
/// capacity".
#[cfg(test)]
mod analyzer_admission_budget_tests {
    use super::*;
    use crate::mcp_common::{DEFAULT_INTERACTIVE_REQUEST_BUDGET, DEFAULT_POLICY_REQUEST_BUDGET};
    use brokk_bifrost_test_macros::hardwon;

    #[tokio::test]
    #[hardwon("#13391: retryable roots binding errors spent the MRTR activation nonce")]
    async fn mrtr_roots_retry_reuses_its_nonce_after_busy_and_capacity_refusal() {
        struct RetryBinding<'a> {
            service: &'a SearchToolsService,
            attempts: AtomicUsize,
        }
        impl WorkspaceBindingOps for RetryBinding<'_> {
            fn root(&self) -> Result<Option<PathBuf>, crate::SearchToolsServiceError> {
                self.service.try_active_workspace_root()
            }
            fn unbind(&self) -> Result<(), crate::SearchToolsServiceError> {
                self.service.try_unbind_client_workspace()
            }
            fn bind(&self, root: PathBuf) -> Result<PathBuf, crate::SearchToolsServiceError> {
                match self.attempts.fetch_add(1, Ordering::SeqCst) {
                    0 => Err(self.service.workspace_busy("workspace publication is busy")),
                    1 => Err(self.service.workspace_activation_not_ready()),
                    _ => self.service.try_bind_client_workspace(root),
                }
            }
        }
        let temp = tempfile::tempdir().unwrap();
        let service = Arc::new(SearchToolsService::new_unbound_manual());
        let spec = crate::mcp_registry::resolve_server_spec("searchtools").unwrap();
        let handler = BifrostMcpHandler::new(
            Arc::clone(&service),
            None,
            McpRenderOptions::default(),
            &spec,
            "test",
            true,
            Arc::new(RootsRevocations::default()),
            Arc::new(OutboundResponseTimings::default()),
        )
        .unwrap();
        let (server_transport, _client_transport) = tokio::io::duplex(4096);
        let server = rmcp::service::serve_directly(handler, server_transport, None);
        let handler = server.service();
        let mut context = RequestContext::new(
            rmcp::model::NumberOrString::Number(1),
            server.peer().clone(),
        );
        context.meta = serde_json::from_value(json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28", "io.modelcontextprotocol/clientCapabilities":{}})).unwrap();
        let first =
            serde_json::from_value(json!({"name":"get_active_workspace", "arguments":{}})).unwrap();
        let binding = RetryBinding {
            service: &service,
            attempts: AtomicUsize::new(0),
        };
        let mut state = handler.workspace.lock().await;
        let input = handler
            .activate_workspace_over_mrtr(&binding, &mut state, &first, &context)
            .unwrap()
            .unwrap();
        let nonce = input.request_state.unwrap();
        let uri = url::Url::from_directory_path(temp.path()).unwrap();
        let retry = serde_json::from_value(json!({"name":"get_active_workspace", "arguments":{}, "requestState":nonce, "inputResponses":{"roots":{"roots":[{"uri":uri.as_str()}]}}})).unwrap();
        for reason in ["busy", "workspace_not_ready"] {
            let error = handler
                .activate_workspace_over_mrtr(&binding, &mut state, &retry, &context)
                .unwrap_err();
            assert_eq!(
                error.data.as_ref().unwrap()["io.bifrost/workspace-incomplete"]["reason"],
                reason
            );
            assert!(handler.roots_activations.contains(&nonce));
            assert_eq!(state.binding, WorkspaceBinding::Unbound);
        }
        assert!(
            handler
                .activate_workspace_over_mrtr(&binding, &mut state, &retry, &context)
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            state.binding,
            WorkspaceBinding::ClientRoots { .. }
        ));
        assert!(!handler.roots_activations.contains(&nonce));
        assert!(!handler.roots_activations.redeem(&nonce));
        drop(state);
        server.cancel().await.unwrap();
        service.close().unwrap();
    }

    #[tokio::test]
    #[hardwon("#13391: readiness probes queued behind a serial tool's connection guard")]
    async fn readiness_probe_reports_busy_while_connection_guard_is_held() {
        let temp = tempfile::tempdir().unwrap();
        let service =
            Arc::new(SearchToolsService::new_manual_ephemeral(temp.path().to_path_buf()).unwrap());
        let spec = crate::mcp_registry::resolve_server_spec("searchtools").unwrap();
        let handler = BifrostMcpHandler::new(
            service,
            None,
            McpRenderOptions::default(),
            &spec,
            "test",
            false,
            Arc::new(RootsRevocations::default()),
            Arc::new(OutboundResponseTimings::default()),
        )
        .unwrap();
        let (server_transport, _client_transport) = tokio::io::duplex(4096);
        let server = rmcp::service::serve_directly(handler, server_transport, None);
        let held = server.service().workspace.lock().await;
        let request =
            serde_json::from_value(json!({"name":"get_active_workspace", "arguments":{}})).unwrap();
        let context = RequestContext::new(
            rmcp::model::NumberOrString::Number(1),
            server.peer().clone(),
        );
        let response = tokio::time::timeout(
            Duration::from_secs(30),
            server.service().call_tool(request, context),
        )
        .await
        .expect("probe must answer while the serial guard remains held")
        .unwrap();
        let CallToolResponse::Complete(response) = response else {
            panic!("a busy probe must be a completed tool result")
        };
        let wire = serde_json::to_value(response).unwrap();
        assert_eq!(wire["isError"], true);
        let details = &wire["_meta"]["io.bifrost/incomplete"];
        assert_eq!(details["stage"], "workspace_activation");
        assert_eq!(details["completion"]["reasons"], json!(["busy"]));
        assert_eq!(details["retiring_workspaces"], json!([]));
        drop(held);
        server.cancel().await.unwrap();
    }

    #[tokio::test]
    #[hardwon("#13391: a finished-build observation ignored its request deadline and cancellation")]
    async fn workspace_observation_stops_at_its_deadline_or_cancellation() {
        let expired = RequestBudget::with_configured(
            Some(Duration::from_secs(1)),
            "search_symbols",
            Instant::now() - Duration::from_secs(1),
        );
        let cancellation = McpCancellationToken::new();
        let stopped = tokio::time::timeout(
            Duration::from_secs(30),
            await_workspace_observation(std::future::pending::<()>(), expired, &cancellation),
        )
        .await
        .expect("expired observation did not answer");
        assert_eq!(stopped, Err(WorkspaceObservationStop::DeadlineExceeded));
        cancellation.cancel();
        let stopped = tokio::time::timeout(
            Duration::from_secs(30),
            await_workspace_observation(std::future::pending::<()>(), None, &cancellation),
        )
        .await
        .expect("cancelled observation did not answer");
        assert_eq!(stopped, Err(WorkspaceObservationStop::Cancelled));
    }

    /// A request that has already spent its budget by the time admission
    /// starts -- the readiness wait is bounded by the same deadline -- against
    /// a pool whose only slot is taken. The timeout then fires immediately, so
    /// this costs no wall-clock wait.
    #[tokio::test]
    #[hardwon("#3396: fallback admission timeouts panicked instead of returning typed errors")]
    async fn a_fallback_budget_admission_timeout_returns_the_typed_error() {
        let pool = AnalyzerExecutionPool::new(1, 1);
        let cancelled = McpCancellationToken::new();
        let _held = match pool.acquire(&cancelled).await {
            Admission::Granted(permit) => permit,
            Admission::Cancelled => panic!("an uncancelled pool must not cancel admission"),
            Admission::Saturated => panic!("the first acquire must take the free slot"),
        };

        for (tool_name, cold_workspace, fallback) in [
            ("get_summaries", true, DEFAULT_INTERACTIVE_REQUEST_BUDGET),
            ("search_symbols", false, DEFAULT_INTERACTIVE_REQUEST_BUDGET),
            ("run_policy", false, DEFAULT_POLICY_REQUEST_BUDGET),
        ] {
            // No configured budget: only the fallback rung can bound this
            // request, which is the shape the issue's panic came from.
            let accepted_at = Instant::now() - fallback;
            let request_budget = RequestBudget::with_configured(None, tool_name, accepted_at)
                .unwrap_or_else(|| {
                    panic!("{tool_name} (cold={cold_workspace}) has a fallback budget")
                });
            assert_eq!(request_budget.budget(), fallback);

            let Err(error) =
                await_analyzer_admission(&pool, Some(request_budget), tool_name, &cancelled).await
            else {
                panic!("a saturated pool must not grant admission");
            };
            assert!(
                matches!(error, AnalyzerAdmissionError::DeadlineExceeded),
                "{tool_name}: {error:?}"
            );
        }
    }

    /// The unbounded arm carries no timer, so it still ends only in a permit,
    /// a cancellation, or saturation. The ladder leaves the serial
    /// workspace-mutating tools unbounded -- named mode still sends them
    /// through admission -- and a timer here would cut such a mutation short
    /// on a budget nobody set.
    #[tokio::test]
    #[hardwon("#3396: unbounded admission waits must remain cancellable without a timer")]
    async fn an_unbounded_admission_wait_keeps_waiting() {
        assert_eq!(
            RequestBudget::with_configured(None, "refresh", Instant::now()),
            None,
            "a serial workspace-mutating tool has no fallback rung to bound it"
        );
        let pool = AnalyzerExecutionPool::new(1, 1);
        let cancelled = McpCancellationToken::new();
        let _held = match pool.acquire(&cancelled).await {
            Admission::Granted(permit) => permit,
            Admission::Cancelled => panic!("an uncancelled pool must not cancel admission"),
            Admission::Saturated => panic!("the first acquire must take the free slot"),
        };
        cancelled.cancel();

        let Err(error) = await_analyzer_admission(&pool, None, "refresh", &cancelled).await else {
            panic!("a cancelled unbounded wait must refuse, not time out");
        };
        let AnalyzerAdmissionError::Protocol(error) = error else {
            panic!("cancellation is not a deadline");
        };
        assert_eq!(
            serde_json::to_value(error).expect("errors serialize")["message"],
            "the tool call was cancelled while waiting for analyzer capacity"
        );
    }
}

#[cfg(test)]
mod explanation_generation_tests {
    use super::*;

    #[test]
    fn stale_explanation_pin_has_machine_readable_wire_details() {
        let requested = "0".repeat(64).parse().unwrap();
        let current = "1".repeat(64).parse().unwrap();
        let error = map_service_error(
            SearchToolsServiceErrorCode::StaleWorkspaceGeneration {
                requested,
                current: Some(current),
            },
            "the workspace changed".to_owned(),
        );
        let wire = serde_json::to_value(error).unwrap();
        assert_eq!(wire["code"], -32602);
        assert_eq!(wire["data"]["kind"], "stale_workspace_generation");
        assert_eq!(wire["data"]["requested"], "0".repeat(64));
        assert_eq!(wire["data"]["current"], "1".repeat(64));
        assert_eq!(wire["data"]["retryable"], true);
    }
}

#[cfg(test)]
mod in_flight_scope_tests {
    use super::*;

    #[test]
    fn stale_scope_cancels_only_prior_generation_of_same_workspace() {
        let requests = Arc::new(InFlightRequests::default());
        let old = crate::CancellationToken::new();
        let current = crate::CancellationToken::new();
        let other = crate::CancellationToken::new();
        let _old_guard = requests.register(
            WorkspaceRequestScope {
                workspace_id: 1,
                generation: 4,
            },
            old.clone(),
        );
        let _current_guard = requests.register(
            WorkspaceRequestScope {
                workspace_id: 1,
                generation: 5,
            },
            current.clone(),
        );
        let _other_guard = requests.register(
            WorkspaceRequestScope {
                workspace_id: 2,
                generation: 4,
            },
            other.clone(),
        );
        requests.cancel_stale(WorkspaceRequestScope {
            workspace_id: 1,
            generation: 5,
        });
        assert!(old.is_cancelled());
        assert!(!current.is_cancelled());
        assert!(!other.is_cancelled());
    }

    #[test]
    fn completed_request_does_not_remove_neighboring_cancellation() {
        let requests = Arc::new(InFlightRequests::default());
        let first = crate::CancellationToken::new();
        let second = crate::CancellationToken::new();
        let first_guard = requests.register(
            WorkspaceRequestScope {
                workspace_id: 1,
                generation: 4,
            },
            first.clone(),
        );
        let _second_guard = requests.register(
            WorkspaceRequestScope {
                workspace_id: 1,
                generation: 4,
            },
            second.clone(),
        );
        drop(first_guard);
        requests.cancel_stale(WorkspaceRequestScope {
            workspace_id: 1,
            generation: 5,
        });
        assert!(!first.is_cancelled());
        assert!(second.is_cancelled());
    }
}

#[cfg(test)]
mod progress_delivery_tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    #[tokio::test]
    #[hardwon("#12761: a timed-out progress send was delivered after the request response")]
    async fn finish_waits_for_timed_out_sends_and_preserves_order() {
        let delivery = ProgressDelivery::default();
        let release = Arc::new(tokio::sync::Notify::new());
        let order = Arc::new(Mutex::new(Vec::new()));

        let first_release = Arc::clone(&release);
        let first_order = Arc::clone(&order);
        delivery
            .enqueue(Duration::from_millis(5), false, async move {
                first_release.notified().await;
                first_order.lock().unwrap().push(1);
                Ok::<(), String>(())
            })
            .await;
        assert!(order.lock().unwrap().is_empty());

        let second_order = Arc::clone(&order);
        delivery
            .enqueue(Duration::from_millis(5), false, async move {
                second_order.lock().unwrap().push(2);
                Ok::<(), String>(())
            })
            .await;
        assert!(
            order.lock().unwrap().is_empty(),
            "a later send must not overtake an earlier timed-out send"
        );

        release.notify_one();
        delivery.finish().await;
        assert_eq!(*order.lock().unwrap(), vec![1, 2]);
    }

    #[test]
    fn named_workspace_services_share_the_one_host_context() {
        let first = tempfile::tempdir().expect("first workspace");
        let second = tempfile::tempdir().expect("second workspace");
        let host = HostActivationContext::library_none();
        let router = NamedWorkspaceRouter::new(
            vec![
                NamedWorkspace::new("one".to_string(), first.path().to_path_buf()),
                NamedWorkspace::new("two".to_string(), second.path().to_path_buf()),
            ],
            false,
            Arc::clone(&host),
        )
        .expect("named router");
        assert!(Arc::ptr_eq(
            router.primary_service().host_activation_context(),
            &host
        ));
        let (_, lazily_built) = router.service("two").expect("second workspace");
        assert!(Arc::ptr_eq(lazily_built.host_activation_context(), &host));
    }
}
