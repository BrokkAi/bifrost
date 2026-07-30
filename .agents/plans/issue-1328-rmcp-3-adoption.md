# Adopt the official rmcp 3.x Rust SDK and serve MCP revision 2026-07-28

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document must be maintained in accordance with `.agents/PLANS.md` from the repository root.

Tracking issue: https://github.com/BrokkAi/bifrost/issues/1328. Related upstream issue: BrokkAi/mjolnir#521.

## Purpose / Big Picture

Bifrost ships an MCP server. "MCP" is the Model Context Protocol: a JSON-RPC 2.0 protocol spoken over a transport (for Bifrost, a child process's standard input and standard output, one JSON object per line) that lets an AI coding agent list and call tools. Today Bifrost implements that protocol by hand: it reads lines from standard input, parses JSON-RPC envelopes itself, dispatches on the `method` string with a `match`, and writes response envelopes it builds with `serde_json::json!`. All of that lives in `crates/bifrost-mcp/src/mcp_common.rs`, and it hard-codes the single protocol revision `2025-11-25`.

The Model Context Protocol published a new revision, `2026-07-28`. It adds a stateless discovery method (`server/discover`), a `resultType` discriminator on tool and resource results, per-response cache hints (`ttlMs` and `cacheScope`), and "Multi Round-Trip Requests" (MRTR) — a pattern where a server answers `tools/call` with "I need something from you first" instead of a result, the client fulfills that embedded request (for Bifrost: "tell me your filesystem roots"), and then retries the original call. The revision also removes the old post-initialization `roots/list` lifecycle that Bifrost currently relies on to discover which directory it is allowed to analyze.

After this change, an agent running a `2026-07-28` MCP client can discover Bifrost with `server/discover`, get a rootless Bifrost server to bind to its workspace through an MRTR roots exchange, and receive cache hints on tool and resource listings — none of which is possible today. An agent running a `2025-11-25` client keeps working exactly as it does now. Bifrost stops maintaining its own JSON-RPC and MCP wire implementation; `rmcp`, the official Model Context Protocol Rust SDK, owns protocol parsing, dispatch, version negotiation, wire types, stdio framing, response serialization, and cancellation plumbing. Bifrost keeps only what is genuinely Bifrost's: the analyzer, the tool registry, workspace authorization, the Codex sandbox boundary, response-size budgets, and the bounded analyzer execution pool.

You can see it working three ways. First, the existing wire-level integration suite `crates/bifrost-mcp/tests/bifrost_mcp_server.rs` spawns a real server process, writes raw JSON-RPC lines to its standard input, and asserts on the JSON it writes back; it must keep passing unchanged in every case where the observable wire behavior is meant to be identical. Second, new tests in that same suite drive a `2026-07-28` handshake and assert on `server/discover`, on `resultType`, on cache hints, and on the MRTR roots exchange. Third, the release-mode fairness benchmark (`bifrost_benchmark` with `benchmark/interactive-latency.toml`) must still show that a heavy usage scan does not block a lightweight source lookup, and that cancelling the heavy scan actually stops the analyzer work rather than merely abandoning a future.

## Progress

- [x] (2026-07-30 10:05Z) Read issue #1328 and its single comment (scheduled for Bifrost v0.9.0).
- [x] (2026-07-30 10:20Z) Verified `rmcp` 3.0.1 exists on crates.io (published 2026-07-29, default version 3.0.1) and vendored its source into the local cargo registry cache for API study.
- [x] (2026-07-30 10:45Z) Spiked the `rmcp` 3.0.1 server API: `ServerHandler` trait shape, `RequestContext`, MRTR types, cache-hint types, protocol-version constants, stdio transport, and the `Tool`/`CallToolResult` models. Findings recorded under `Surprises & Discoveries` and `Interfaces and Dependencies`.
- [x] (2026-07-30 10:55Z) Surveyed every consumer of the current hand-written stack: four `run_stdio_server` call sites, two binaries, the 53-function wire test suite, the benchmark MCP client, and the property fuzzer.
- [x] (2026-07-30 11:05Z) Wrote this ExecPlan.
- [ ] Milestone 1: dependency and runtime boundary; parallel rmcp handler serving identity, ping, tools/list, resources/list, resources/read.
- [ ] Milestone 2: analyzer execution pool and cancellation bridge.
- [ ] Milestone 3: workspace binding for explicit roots, legacy client roots, and Codex sandbox metadata.
- [ ] Milestone 4: 2026-07-28 rootless activation through MRTR roots requests.
- [ ] Milestone 5: discovery, `resultType`, and cache hints.
- [ ] Milestone 6: delete the hand-written protocol stack and flip every entry point.
- [ ] Milestone 7: full validation, benchmark gate, adapter exercise, and documentation.

## Surprises & Discoveries

- Observation: `rmcp`'s `ProtocolVersion::LATEST` is `2025-11-25`, not `2026-07-28`, even though `2026-07-28` is in `KNOWN_VERSIONS`. `ServerInfo::default()` therefore advertises `2025-11-25`, and `initialize` negotiation simply echoes whatever known version the client asked for. This means adopting the SDK does not by itself change the negotiated revision for existing clients — the migration is genuinely backward compatible by default, and the `2026-07-28` behavior only appears when a client asks for it.
  Evidence: `rmcp-3.0.1/src/model.rs` lines 170-186 define `V_2026_07_28`, `V_2025_11_25`, `LATEST = V_2025_11_25`, and `KNOWN_VERSIONS = [.., V_2025_11_25, V_2026_07_28]`. `rmcp-3.0.1/src/service/server.rs:464` `negotiate_protocol_version` returns `client_requested` whenever it is in `KNOWN_VERSIONS`.

- Observation: `rmcp` gates MRTR results by negotiated version for us. A handler may return `InputRequiredResult` unconditionally; the SDK converts it to a protocol error for a peer that negotiated an older revision. Bifrost therefore does not need its own revision branch in the roots-activation path, only a fallback path for legacy peers that uses `context.peer.list_roots()`.
  Evidence: `rmcp-3.0.1/src/model/mrtr.rs` module docs: "The SDK only lets an `InputRequiredResult` reach a peer that negotiated protocol version `2026-07-28` or newer; older peers get a protocol error instead."

- Observation: `rmcp::model::Implementation` (the `serverInfo` object) is a closed struct with `name`, `title`, `version`, `description`, `icons`, `website_url`. There is no extension map, so Bifrost's current `serverInfo.buildIdentity` field cannot survive as-is. `InitializeResult` does carry a `_meta` object, which is the protocol's sanctioned extension point.
  Evidence: `rmcp-3.0.1/src/model.rs:1396` (`Implementation`) and `rmcp-3.0.1/src/model.rs:1040` (`InitializeResult`, field `meta` renamed `_meta`).

- Observation: Bifrost's existing tool descriptors are plain `serde_json::Value` objects with exactly the field names `rmcp::model::Tool` deserializes (`name`, `description`, `inputSchema`, `annotations`). They can be converted with `serde_json::from_value::<Tool>` rather than rewritten, which also turns descriptor construction bugs into build-time or startup-time errors instead of silent wire garbage.
  Evidence: `crates/bifrost-mcp/src/mcp_common.rs:2133` `tool_descriptor` versus `rmcp-3.0.1/src/model/tool.rs:17` `Tool`.

- Observation: `rmcp` handles concurrent `tools/call` requests on the stdio transport itself and serializes responses; its own test suite fires 200 concurrent 64 KiB tool responses through real pipes and asserts none are lost. This is exactly the machinery Bifrost's writer thread, `MAX_PENDING_MCP_RESPONSES` bound, and `try_queue_response` backpressure currently duplicate.
  Evidence: `rmcp-3.0.1/tests/test_stdio_response_concurrency.rs`.

- Observation: The current "four-slot" constraint is not a pool. `MAX_IN_FLIGHT_CANCELLABLE_REQUESTS = 4` in `crates/bifrost-mcp/src/mcp_common.rs:28` *rejects* the fifth concurrent cancellable request with JSON-RPC error `-32000` ("too many in-flight cancellable tool requests"). The issue asks for a real pool that *waits* asynchronously. This is a deliberate behavior change, not a refactor, and any test asserting the busy rejection has to change with it.
  Evidence: `McpRequestCancellations::register_at` returns `McpRequestRegistrationError::AtCapacity`, which `run_stdio_server` maps to `SERVER_BUSY`.

- Observation: Bifrost has no Tokio anywhere in its dependency tree today; `Cargo.lock` contains no `tokio` entry. Adding `rmcp` introduces Tokio plus roughly 78 transitive packages into a crate that is published to crates.io.
  Evidence: `grep -n 'name = "tokio"' Cargo.lock` matches nothing on `7fbd8ec5`; `cargo add rmcp@3 --features server,transport-io` in a scratch project locked 78 packages.

## Decision Log

- Decision: Migrate behind a parallel implementation rather than replacing the hand-written stack in one commit. A new module `crates/bifrost-mcp/src/rmcp_host.rs` grows milestone by milestone while `mcp_common.rs` keeps serving production traffic, and the switch is a single environment variable during milestones 1-5. Milestone 6 deletes the old stack and the switch together.
  Rationale: `.agents/PLANS.md` explicitly endorses parallel implementations during large migrations, and the wire test suite is the safety net — being able to run the same 53-function suite against either implementation is what makes the migration checkable at each step. Issue #1328's prohibition on parallel dispatch is a statement about the *end state*, and Milestone 6 satisfies it.
  Date/Author: 2026-07-30, David Baker Effendi (via Claude).

- Decision: Move `serverInfo.buildIdentity` to `InitializeResult._meta` under the key `io.bifrost/build-identity`.
  Rationale: `rmcp::model::Implementation` has no extension point, `_meta` is the protocol's sanctioned one, and `CLAUDE.md` states backwards compatibility is not yet a concern. The three consumers (`tests/mcp_build_identity_facade.rs`, `src/benchmark/mcp_session.rs::validate_server_build_identity`, and the fake-server fixture in `tests/suite_mcp_cli/bifrost_benchmark_run.rs`) move with it.
  Date/Author: 2026-07-30, David Baker Effendi (via Claude).

- Decision: Convert the analyzer admission limit from "reject the fifth request with `-32000`" to "wait for a permit, cancellation-aware".
  Rationale: Issue #1328 requires it in so many words ("Checkout must be asynchronous and cancellation-aware so waiting does not block a runtime thread"), and the rejection behavior only existed because the old reader thread had nowhere to park a waiting request. The fairness benchmark, not the rejection, is the regression gate for the capacity policy.
  Date/Author: 2026-07-30, David Baker Effendi (via Claude).

- Decision: Keep the analyzer synchronous. Analyzer work runs on `tokio::task::spawn_blocking`, not by making `SearchToolsService` async.
  Rationale: The analyzer is CPU-bound and uses rayon internally; making it async would be a far larger and riskier change than this issue asks for, and issue #1328 explicitly says the integration needs "a Tokio runtime boundary without forcing analyzer internals to become async unnecessarily."
  Date/Author: 2026-07-30, David Baker Effendi (via Claude).

## Outcomes & Retrospective

Not yet started. To be written at the end of each milestone and summarized at completion.

## Context and Orientation

Everything in this section describes the repository as it stands at commit `7fbd8ec5` on branch `dave/github-issue-1328-068f9b`. Read it as if you have never seen this repository.

### The crates

The repository is a Cargo workspace. The root package `brokk-bifrost` is a thin facade that builds the `bifrost` binary (`src/bin/bifrost.rs`). The real code lives in four member crates under `crates/`:

- `crates/bifrost-analysis` (package `brokk-bifrost-analysis`) — the tree-sitter-backed code analyzer, plus `CancellationToken`, profiling, and rendering.
- `crates/bifrost-runtime` (package `brokk-bifrost-runtime`) — the code-intelligence runtime.
- `crates/bifrost-lsp` — the Language Server Protocol server. Not touched by this plan.
- `crates/bifrost-mcp` (package `brokk-bifrost-mcp`, library name `brokk_bifrost_mcp`) — the MCP server. This is the crate this plan changes.

`crates/bifrost-mcp/src/lib.rs` re-exports the analyzer surface and declares the crate's modules.

### The MCP server as it exists today

`crates/bifrost-mcp/src/mcp_common.rs` is 2,925 lines. Lines 1 through roughly 1,760 are implementation; from line 1,760 to the end is a `#[cfg(test)] mod tests`. The implementation contains four separable concerns, and only the first two are being replaced:

1. **Hand-written JSON-RPC and MCP protocol.** Constants `JSONRPC_VERSION`, `PROTOCOL_VERSION` (`"2025-11-25"`), and the JSON-RPC error codes at lines 18-26. `dispatch_message` (line 723) validates the envelope, splits requests from notifications from responses, and routes. `dispatch_request` (line 933) matches on the method string and covers `initialize`, `ping`, `resources/list`, `resources/read`, `tools/list`, `tools/call`, plus the private benchmark method `bifrost/benchmark-profile-boundary`. `handle_notification` (line 978) covers `notifications/initialized`, `notifications/roots/list_changed`, and `notifications/cancelled`. `handle_response` (line 818) correlates the server's own outbound `roots/list` request with the client's reply. `success_response`, `error_response`, `tool_success_result`, and `tool_error_result` (lines 2069-2131) build wire envelopes. `initialize_result` (line 1018) builds the handshake reply including `serverInfo.buildIdentity` and, conditionally, an `experimental.codex/sandbox-state-meta` capability. All of this is deleted in Milestone 6.

2. **Transport and concurrency.** `run_stdio_server_with_build_identity` (line 365) is the whole server: it constructs the `SearchToolsService`, spawns a thread named `bifrost-mcp-writer` that owns standard output and drains a `std::sync::mpsc::sync_channel` of capacity `MAX_PENDING_MCP_RESPONSES` (4), then loops over `stdin.lock().lines()`. Read-only tool calls are recognized by `background_tool_request` (line 576) and handed to a freshly spawned `bifrost-mcp-tool` thread by `spawn_cancellable_tool_call_at` (line 620); the four "serial" lifecycle tools listed in `serial_tool_request` (line 592) — `activate_workspace`, `refresh`, `update_paths`, `get_active_workspace` — stay on the reader thread so that workspace mutations remain ordered against everything else. `McpRequestCancellations` (line 88) is a mutex-guarded map from a JSON-RPC request id to a Bifrost `CancellationToken` plus the workspace generation the request was admitted under; it enforces the four-slot admission cap, cancels on `notifications/cancelled`, and cancels every request whose workspace generation is stale. `try_queue_response` (line 702) closes the connection if the response queue fills. `OutboundMcpResponse` (line 210) carries a response plus the workspace generation it was computed under, so the writer can replace a response whose workspace changed underneath it with a `-32002` error. All of this is deleted in Milestone 6 except the workspace-generation staleness rule and the request deadline, which are Bifrost product behavior and move into the new module.

3. **Workspace authorization.** This is Bifrost product and security behavior. It is *rehosted*, not deleted. `McpConnectionState` (line 74) tracks whether the server accepts client-provided roots at all (`accepts_client_roots`, true only when no `--root` was given), whether the client advertised the Roots capability, which of four sources the current binding came from (`WorkspaceBindingSource`: `None`, `ExplicitRoot`, `ClientRoots`, `CodexSandboxState`), the Codex sandbox URI and resolved root, and the outstanding `roots/list` request id. `handle_response` binds a workspace from a `roots/list` reply; `reconcile_codex_sandbox_workspace` (line 1286) binds one from a `tools/call` request's `params._meta["codex/sandbox-state-meta"].sandboxCwd`, re-validating on every single call and revoking on any change, absence, or parse failure. `prepare_tool_call` (line 1153) refuses every tool except `list_policies` when no workspace is bound, and refuses `activate_workspace` when the workspace is under client or Codex control. `client_root_to_path` and `file_uri_to_path` (lines 902-930) convert a `file://` URI or native absolute path to a `PathBuf`, rejecting relative and non-file URIs.

4. **Bifrost product behavior around tool results.** Also rehosted, not deleted. `normalize_tool_arguments` (from `crates/bifrost-mcp/src/tool_arguments.rs`) rewrites absolute paths relative to the active workspace root and rejects paths outside it. `fit_get_summaries_output_to_budget` (line 1432) and everything below it through line 1760 implement the 4,096-byte response budget for `get_summaries`, degrading full summaries to compact symbol outlines and annotating the result with a `degradation` object. `mcp_analyzer_request_budget` (line 194) gives every cancellable request a 5-second deadline, overridable up to 60 seconds through `BIFROST_BENCHMARK_MCP_REQUEST_BUDGET_SECS` for benchmark runs.

### The tool registry

`crates/bifrost-mcp/src/mcp_registry.rs` resolves a mode string (`searchtools`, `cli`, `slopcop`, ...) to an `McpServerSpec` by calling into `mcp_core.rs`, `mcp_extended.rs`, `mcp_text.rs`, `mcp_slopcop.rs`, `mcp_nlp.rs`, and `mcp_cli.rs`. An `McpServerSpec` (`mcp_common.rs:67`) is three fields: `instructions: &'static str`, `tool_names: HashSet<String>` (which includes hidden tools callable but not listed), and `tool_descriptors: Vec<serde_json::Value>` (the listed tools, in deterministic order). `build_server_spec_with_hidden` (line 336) constructs it and is the only place that validates a descriptor has a string `name`.

`crates/bifrost-mcp/src/searchtools_service.rs` is the 4,350-line `SearchToolsService`: it owns the analyzer, the workspace binding (`bind_client_workspace`, `unbind_client_workspace`, `active_workspace_root`, `workspace_generation`), and `call_tool_output_with_cancellation(name, arguments, render_options, cancellation) -> Result<ToolOutput, SearchToolsServiceError>`, which is the single entry point for executing any tool. `ToolOutput` is either `Text(String)` or `Structured { structured: Value, rendered_text: Option<String> }`.

"Workspace generation" is a monotonically increasing counter on the service that increments every time the bound workspace changes. It exists so that a tool result computed against workspace N can be discarded rather than returned after the workspace has become N+1.

### The entry points

Four functions call `run_stdio_server`, all inside `crates/bifrost-mcp/src`: `mcp_core.rs:19`, `mcp_core.rs:32`, `mcp_extended.rs:37`, and `mcp_slopcop.rs:27`. Two binaries call `run_stdio_server_with_build_identity` directly: `src/bin/bifrost.rs:605` (the shipped `bifrost` binary, passing `brokk_bifrost::BIFROST_BUILD_IDENTITY`) and `crates/bifrost-mcp/src/bin/bifrost-mcp-test-server.rs:63` (a test-only binary, passing its own `CARGO_PKG_VERSION`).

Both binaries decide the initial root the same way: an explicit `--root`, or the process working directory when no `--mcp` mode was requested at all (a compatibility mode), and otherwise `None`, which starts the server "rootless" — unbound, waiting for the client to supply a root.

### The tests

`crates/bifrost-mcp/tests/bifrost_mcp_server.rs` (3,584 lines, 53 functions) is the contract suite. It spawns the real server binary as a child process with piped standard input and output (`spawn_server`, `spawn_rootless_server`, `spawn_server_no_args` at lines 3517-3547), writes raw JSON-RPC lines, and reads raw JSON-RPC lines back. Because it speaks the wire and never links against the server's internals, it is implementation-agnostic: it is the primary safety net for this migration. `initialize_session` (line 3421) performs the handshake. The rootless and Codex tests (lines 2651-3420) are the security-critical ones.

`tests/mcp_build_identity_facade.rs` at the repository root asserts that the shipped `bifrost` binary reports the facade's build identity in its initialize response. `src/benchmark/mcp_session.rs` is a benchmark MCP *client* that speaks the wire; `src/mcp_property_fuzzer/` is a fuzzing client. Neither links against the server internals.

### Terms used in this plan

- **MRTR** — "Multi Round-Trip Request". A `2026-07-28` pattern where a server answers `tools/call`, `prompts/get`, or `resources/read` with an `InputRequiredResult` carrying (a) a map of requests the client must answer and (b) an opaque `requestState` string. The client answers them and re-sends the *original* request with `inputResponses` and the same `requestState`. The server is expected to be stateless across the round trip: it must be able to reconstruct what it was doing from `requestState` alone, and it must not trust `requestState` because the client can tamper with it.
- **Roots** — the list of filesystem directories an MCP client authorizes a server to touch. Bifrost only ever analyzes a directory it was given as a root, either by `--root` on the command line, by the client's `roots/list` reply, or by Codex sandbox metadata.
- **Codex sandbox metadata** — a Bifrost-specific convention for the `codex-mcp-client`, which does not implement MCP Roots. That client puts `{"codex/sandbox-state-meta": {"sandboxCwd": "file:///..."}}` into the `_meta` object of every `tools/call`, and Bifrost re-validates and re-binds from it on every call.
- **`spawn_blocking`** — a Tokio function that runs a synchronous, CPU- or IO-blocking closure on a separate thread pool so it does not stall the asynchronous runtime's worker threads.

## Interfaces and Dependencies

### New dependencies

In `crates/bifrost-mcp/Cargo.toml`, add to `[dependencies]`:

    rmcp = { version = "3.0.1", default-features = false, features = ["server", "transport-io"] }
    tokio = { version = "1", default-features = false, features = ["rt-multi-thread", "io-std", "sync", "time", "macros"] }
    tokio-util = { version = "0.7", default-features = false }

`rmcp`'s default features are `base64`, `macros`, `server`. Turning defaults off and naming `server` plus `transport-io` avoids pulling the `#[tool]` proc macros and `schemars`, which Bifrost does not need because its tool schemas are already hand-written JSON. `transport-io` enables `rmcp::transport::stdio()`, which is `(tokio::io::stdin(), tokio::io::stdout())`.

`tokio-util` is needed only because `rmcp::service::RequestContext::ct` is a `tokio_util::sync::CancellationToken` and Bifrost must await it. Prefer re-exporting through `rmcp` if `rmcp` re-exports the type; check `rmcp::service` before adding the direct dependency, and drop it if the re-export exists.

### The rmcp 3.0.1 server API, as verified by reading the vendored source

The single trait to implement is `rmcp::ServerHandler`. Every method has a default, so a handler only overrides what it serves. The methods this plan uses:

    fn get_info(&self) -> rmcp::model::ServerInfo;
    fn supported_protocol_versions(&self) -> std::borrow::Cow<'static, [ProtocolVersion]>;
    async fn initialize(&self, request: InitializeRequestParams, context: RequestContext<RoleServer>) -> Result<InitializeResult, McpError>;
    async fn discover(&self, context: RequestContext<RoleServer>) -> Result<DiscoverResult, McpError>;
    async fn ping(&self, context: RequestContext<RoleServer>) -> Result<(), McpError>;
    async fn list_tools(&self, request: Option<PaginatedRequestParams>, context: RequestContext<RoleServer>) -> Result<ListToolsResult, McpError>;
    async fn call_tool(&self, request: CallToolRequestParams, context: RequestContext<RoleServer>) -> Result<CallToolResponse, McpError>;
    async fn list_resources(&self, request: Option<PaginatedRequestParams>, context: RequestContext<RoleServer>) -> Result<ListResourcesResult, McpError>;
    async fn read_resource(&self, request: ReadResourceRequestParams, context: RequestContext<RoleServer>) -> Result<ReadResourceResponse, McpError>;
    async fn on_custom_request(&self, request: CustomRequest, context: RequestContext<RoleServer>) -> Result<CustomResult, McpError>;
    async fn on_initialized(&self, context: NotificationContext<RoleServer>);
    async fn on_roots_list_changed(&self, context: NotificationContext<RoleServer>);
    async fn on_cancelled(&self, notification: CancelledNotificationParam, context: NotificationContext<RoleServer>);

`ServerInfo` is a type alias for `InitializeResult`, whose fields are `protocol_version: ProtocolVersion`, `capabilities: ServerCapabilities`, `server_info: Implementation`, `instructions: Option<String>`, and `meta: Option<MetaObject>` (serialized as `_meta`).

`RequestContext<RoleServer>` has:

    pub ct: tokio_util::sync::CancellationToken,   // cancelled when notifications/cancelled arrives
    pub id: RequestId,
    pub meta: RequestMetaObject,                   // the request's `params._meta`, already extracted
    pub extensions: Extensions,
    pub peer: Peer<RoleServer>,                    // server-to-client requests; has `list_roots()`

and the helper methods `protocol_version() -> Option<ProtocolVersion>` and `client_info() -> Option<Implementation>`.

Running the server is:

    use rmcp::{ServiceExt, transport::stdio};
    let running = handler.serve(stdio()).await?;
    running.waiting().await?;

`ServiceExt::serve` performs the initialize handshake itself and only then hands control back. `RunningService::waiting()` resolves when the transport closes.

Cancellation of a request is signalled by `context.ct`, a Tokio `CancellationToken`. This is a different type from Bifrost's `brokk_bifrost_analysis::CancellationToken` (an `AtomicBool` plus an optional wall-clock deadline, checked cooperatively deep inside analyzer traversals). Bridging them is Bifrost's job and is specified in Milestone 2.

### New Bifrost interfaces

In a new file `crates/bifrost-mcp/src/analyzer_pool.rs`, define:

    /// Bounded admission for expensive analyzer work.
    ///
    /// Protocol handling and lightweight tools do not take a permit. Only the
    /// analyzer execution path does. The capacity is a measured product
    /// constraint (see benchmark/interactive-latency.toml, scenario
    /// `mcp_fairness`); change it only with benchmark evidence.
    pub struct AnalyzerExecutionPool { /* tokio::sync::Semaphore */ }

    pub struct AnalyzerPermit<'pool> { /* releases on drop */ }

    impl AnalyzerExecutionPool {
        pub fn new(capacity: usize) -> Self;
        pub fn capacity(&self) -> usize;
        /// Waits for a permit without blocking a runtime worker thread.
        /// Resolves to `None` if `cancelled` fires first.
        pub async fn acquire(&self, cancelled: &tokio_util::sync::CancellationToken) -> Option<AnalyzerPermit<'_>>;
    }

    pub const ANALYZER_POOL_CAPACITY: usize = 4;

In a new file `crates/bifrost-mcp/src/rmcp_host.rs`, define:

    pub struct BifrostMcpHandler { /* see Milestone 1 */ }

    /// Blocking entry point: builds a Tokio runtime, serves MCP over stdio,
    /// and returns when the client disconnects.
    pub fn run_stdio_server_with_build_identity(
        root: Option<std::path::PathBuf>,
        render_options: McpRenderOptions,
        spec: &McpServerSpec,
        build_identity: &str,
    ) -> Result<(), String>;

In Milestone 6 this function takes over the name `run_stdio_server_with_build_identity` from `mcp_common.rs` and `mcp_common.rs` keeps only the Bifrost product code (the `get_summaries` budget, `McpServerSpec` and its builders, `McpRenderOptions`, the tool-descriptor constructors, and the benchmark constants).

## Plan of Work

### Milestone 1 — Dependency, runtime boundary, and a read-only rmcp server

**Scope.** Get `rmcp` into the build and prove it can serve the parts of Bifrost's MCP surface that have no workspace or analyzer coupling: identity, `ping`, `tools/list`, `resources/list`, `resources/read`, and the benchmark profile-boundary custom method. At the end of this milestone a second, parallel server implementation exists and can be selected at runtime, and the subset of the existing wire test suite that covers those methods passes against it.

**Work.** Add the dependencies above. Create `crates/bifrost-mcp/src/rmcp_host.rs` and declare it in `crates/bifrost-mcp/src/lib.rs`.

`BifrostMcpHandler` holds `service: Arc<SearchToolsService>`, `tools: Vec<rmcp::model::Tool>`, `tool_names: HashSet<String>`, `instructions: &'static str`, `build_identity: String`, `render_options: McpRenderOptions`, and (added in later milestones) the connection state and the analyzer pool. Build `tools` once at construction by `serde_json::from_value::<Tool>(descriptor.clone())` over `spec.tool_descriptors`, returning a `String` error naming the offending descriptor if conversion fails. This replaces the weaker `name`-only validation in `build_server_spec_with_hidden`.

`get_info` returns an `InitializeResult` with `capabilities` built from `ServerCapabilities::builder().enable_tools().enable_resources().build()`, `server_info: Implementation::new("bifrost", env!("CARGO_PKG_VERSION"))`, `instructions: Some(self.instructions.to_string())`, and `meta` carrying `{"io.bifrost/build-identity": <build_identity>}`. Leave `protocol_version` at its default; the SDK negotiates.

`list_tools` returns `ListToolsResult` from the prebuilt `Vec<Tool>`, ignoring pagination (Bifrost's tool list is small and deliberately unpaginated). `list_resources` and `read_resource` port `list_resources_result`, `agents_guidance_resource_descriptor`, and `handle_resource_read` from `mcp_common.rs:1050-1095`, keeping the URI `bifrost://agent-guidance/agents.md`, the MIME type `text/markdown`, the annotations, and the `-32002` "Resource not found" behavior for any other URI (`McpError::resource_not_found`).

`on_custom_request` handles `bifrost/benchmark-profile-boundary` by writing `BENCHMARK_PROFILE_BOUNDARY_MARKER` to standard error and returning an empty result, and returns `McpError::method_not_found` for anything else. Note that `rmcp`'s default `on_custom_request` already returns method-not-found, so only the one method needs handling.

`call_tool` in this milestone returns `McpError::internal_error("not yet migrated")`. It is filled in during Milestones 2 and 3.

The blocking entry point builds the runtime explicitly rather than using `#[tokio::main]`, because the caller is a synchronous `fn run(...) -> Result<(), String>` reached from `main`:

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .worker_threads(2)
        .max_blocking_threads(ANALYZER_POOL_CAPACITY + 2)
        .thread_name("bifrost-mcp")
        .build()
        .map_err(|err| format!("Failed to start MCP runtime: {err}"))?;
    runtime.block_on(async move { /* serve */ })

Two worker threads are enough because no Bifrost work happens on them — protocol handling is trivial and analyzer work goes to the blocking pool. The blocking pool is sized at the analyzer capacity plus a small margin for the serial lifecycle tools.

Preserve the deliberate `std::mem::forget(service)` on clean shutdown, with the existing comment from `mcp_common.rs:551-560` carried over: on normal EOF the process is exiting, and dropping the service would walk the whole in-memory index and tear down the file watcher for no benefit. Error paths must still drop normally.

Select the implementation with a temporary environment variable `BIFROST_MCP_RMCP` (`on`/`off`, default `off`) read in `mcp_common::run_stdio_server_with_build_identity`. Reuse the existing `file_watching_enabled` shape for parsing so an invalid value is an error, not a silent default. This variable is deleted in Milestone 6.

**Acceptance.** From the repository root:

    cargo test -p brokk-bifrost-mcp --test bifrost_mcp_server bifrost_split_servers_publish_expected_tool_sets

passes unchanged (old path), and with `BIFROST_MCP_RMCP=on` exported the same test plus `bifrost_split_servers_reject_tools_outside_their_registry` and the `assert_agents_guidance_resource_available` assertions pass against the new path. `cargo clippy --all-targets --all-features -- -D warnings` is clean.

### Milestone 2 — Analyzer execution pool and cancellation bridge

**Scope.** Make `call_tool` actually execute tools, with bounded analyzer admission, a request deadline, real cancellation reaching the analyzer, and workspace-generation staleness. Workspace *binding* is still Milestone 3; this milestone assumes an explicitly rooted server (`--root`), which is the simplest authorization case and already covers most of the test suite.

**Work.** Write `crates/bifrost-mcp/src/analyzer_pool.rs` as specified above, backed by `tokio::sync::Semaphore`. `acquire` is:

    tokio::select! {
        permit = self.semaphore.acquire() => Some(AnalyzerPermit(permit.expect("pool semaphore is never closed"))),
        () = cancelled.cancelled() => None,
    }

In `rmcp_host.rs`, implement `call_tool` as: validate the tool name against `tool_names` (unknown tool becomes `Ok(CallToolResult::error(...))`, matching today's `tool_error_result`, not a protocol error); handle `list_policies` inline without a permit, exactly as `prepare_tool_call` does today, because it does not touch the workspace; check the workspace binding and normalize arguments (Milestone 3 fills in the binding half, so for now assert an explicit root is bound); capture `workspace_generation` before acquiring; acquire a permit; re-check the generation after acquiring and return the `-32002` "workspace changed before the tool call could start; retry the request" error if it moved; then run the analyzer.

The cancellation bridge is the subtle part and must be written so that cancellation reaches the analyzer, not merely the future:

    let deadline = Instant::now() + mcp_analyzer_request_budget();
    let bifrost_token = brokk_bifrost_analysis::CancellationToken::default().with_deadline(deadline);
    let bridge_token = bifrost_token.clone();
    let mcp_ct = context.ct.clone();
    let bridge_done = tokio_util::sync::CancellationToken::new();
    let bridge_guard = bridge_done.clone().drop_guard();
    tokio::spawn(async move {
        tokio::select! {
            () = mcp_ct.cancelled() => bridge_token.cancel(),
            () = bridge_done.cancelled() => {}
        }
    });
    let output = tokio::task::spawn_blocking(move || {
        service.call_tool_output_with_cancellation(&name, arguments, render_options, Some(&bifrost_token))
    }).await;
    drop(bridge_guard);

The `drop_guard` is what stops the bridge task from outliving the request. Because `spawn_blocking` cannot be aborted, the blocking closure keeps running after an MCP cancellation until the analyzer observes the Bifrost token — which is exactly the required behavior, and exactly what "cancellation stops the underlying analyzer work, not only the async handler future" means. Awaiting the `JoinHandle` after cancellation is therefore correct: it returns the analyzer's own cancelled/incomplete result.

Serial lifecycle tools (`activate_workspace`, `refresh`, `update_paths`, `get_active_workspace`) must remain ordered against everything else. Today that ordering came for free from the single reader thread. Under `rmcp` every request is concurrent, so the ordering must become explicit: hold a `tokio::sync::Mutex` (call it the workspace lock) for the duration of a serial tool, and take it in shared/read mode for ordinary tools. Use `tokio::sync::RwLock`: serial tools take `write()`, ordinary tools take `read()` before acquiring an analyzer permit. Take the workspace lock *before* the analyzer permit everywhere so the two locks always order the same way and cannot deadlock.

Port `fit_get_summaries_output_to_budget` unchanged by calling into the existing function in `mcp_common.rs` (it stays there; it is Bifrost product code).

Map `SearchToolsServiceError` to results the same way as today: `UnknownTool` becomes `Ok(CallToolResult::error(..))`; `InvalidParams` becomes `McpError::invalid_params`; `Internal` becomes `McpError::internal_error`.

Add `#[doc(hidden)]` test seams equivalent to the existing `spawn_cancellable_tool_call_with_start_hook`: the deterministic fairness test `issue_1228_cancelled_scan_does_not_block_following_source_lookup` depends on being able to hold a scan at the moment it starts executing. Provide a compile-time-optional hook on `BifrostMcpHandler` (a `#[cfg(feature = "test-support")]` or `#[cfg(test)]` `Option<Arc<dyn Fn() + Send + Sync>>` invoked immediately inside the blocking closure).

**Acceptance.**

    cargo test -p brokk-bifrost-mcp --test bifrost_mcp_server

with `BIFROST_MCP_RMCP=on` passes every test that uses an explicit `--root` (that is, everything except the `rootless_*` and `explicit_mcp_root_ignores_codex_sandbox_state` group, which needs Milestone 3). Add a new test proving cancellation reaches the analyzer: start a heavy `scan_usages_by_location`, send `notifications/cancelled`, and assert the scan's response carries the analyzer's `cancelled` incomplete reason rather than a transport-level abort, while a following `get_symbol_sources` returns its real result.

### Milestone 3 — Workspace binding for explicit roots, legacy client roots, and Codex metadata

**Scope.** Move all of `McpConnectionState` and its three binding sources onto the rmcp handler, so the rootless and Codex tests pass against the new path. This milestone implements the *legacy* (`2025-11-25`) roots lifecycle; the `2026-07-28` MRTR flow is Milestone 4.

**Work.** Introduce `struct ConnectionState` inside `rmcp_host.rs` holding the same fields as today's `McpConnectionState` minus the JSON-RPC plumbing: `accepts_client_roots: bool`, `client_supports_roots: bool`, `workspace_binding_source: WorkspaceBindingSource`, `codex_sandbox_cwd_uri: Option<String>`, `codex_sandbox_root: Option<PathBuf>`. It no longer needs `initialize_received`, `initialized`, `pending_roots_request`, `roots_refresh_requested`, or `next_request_id`: `rmcp` owns the lifecycle, owns outbound request ids, and gives us `peer.list_roots()` as an ordinary awaited call rather than a correlate-by-id state machine. Guard it with the same `tokio::sync::RwLock` used for serial tool ordering, or a second `tokio::sync::Mutex` taken inside it — whichever keeps the lock order total and documented.

Override `initialize` to record `client_supports_roots` from `request.capabilities.roots`, log the same `bifrost: MCP initialize client=... roots_supported=... workspace_protocol=...` line to standard error that `dispatch_message` logs today, and return `get_info()` with `capabilities.experimental` set to `{"codex/sandbox-state-meta": {}}` when and only when the server accepts client roots, the client did *not* advertise Roots, and initialize has been received — the condition currently in `McpConnectionState::accepts_codex_sandbox_state`. Then delegate to the SDK's negotiation by calling `negotiate_protocol_version` semantics: set `info.protocol_version` from `request.protocol_version` if known. Simplest correct implementation: build the result, then let the default `initialize` logic run by replicating its three lines (`context.peer.set_peer_info(request.clone())`, negotiate, return).

Implement `on_initialized` to fire the legacy roots request when the client advertised Roots: `context.peer.list_roots().await`, then bind. Implement `on_roots_list_changed` to unbind, cancel stale in-flight requests, and re-request. Port the binding loop from `handle_response` (`mcp_common.rs:842-899`) verbatim in behavior: try each root in order, bind the first usable one, and on an empty list or an all-failures list unbind and log. The `roots_refresh_requested` re-entrancy dance disappears because an awaited `list_roots()` needs no id correlation; instead, serialize `on_initialized`/`on_roots_list_changed` handling with the workspace write lock so a change that arrives mid-bind sequences after it.

Port `reconcile_codex_sandbox_workspace` (`mcp_common.rs:1286`) into `call_tool`, reading the sandbox metadata from `context.meta` rather than from `params._meta` — `rmcp` extracts `_meta` into `RequestContext::meta` before dispatch, so the key lookup is `context.meta.get("codex/sandbox-state-meta")` and `context.meta.get("threadId")`. Every behavior must be preserved exactly: revalidate on every call, revoke on missing/invalid/changed metadata, refuse tools when unbound with the existing long error message, and refuse `activate_workspace` when the workspace is controlled by client roots or Codex metadata. This is the security boundary; it gets its own review pass.

Port `client_root_to_path` and `file_uri_to_path` unchanged.

**Acceptance.** With `BIFROST_MCP_RMCP=on`, the entire `crates/bifrost-mcp/tests/bifrost_mcp_server.rs` suite passes, including `rootless_mcp_binds_to_client_roots_without_analyzing_process_cwd`, `rootless_mcp_binds_from_codex_sandbox_state_and_revokes_per_call_scope`, `rootless_mcp_rejects_first_codex_workspace_activation_outside_sandbox`, `explicit_mcp_root_ignores_codex_sandbox_state`, and `rootless_mcp_accepts_codex_sandbox_metadata_from_a_compatible_client`.

### Milestone 4 — Rootless workspace activation over MRTR for 2026-07-28 clients

**Scope.** A client that negotiated `2026-07-28` has no post-initialization roots lifecycle. When such a client calls a tool against a rootless Bifrost with no workspace bound, Bifrost must answer with an MRTR `InputRequiredResult` embedding a `roots/list` request, and must bind from the client's `inputResponses` when the client retries.

**Work.** In `call_tool`, at the point where today's code returns `unbound_workspace_error()`, branch on `context.protocol_version()`. For `2026-07-28` and newer, and only when `accepts_client_roots` is true, return:

    Ok(InputRequiredResult::new(
        Some(BTreeMap::from([("roots".to_string(), InputRequest::ListRoots(ListRootsRequest::default()))])),
        Some(request_state),
    ).into())

On the retry, `request.input_responses` carries `{"roots": <ListRootsResult as JSON>}` and `request.request_state` carries the echoed state. Parse the roots out of the response value and run the *same* binding routine used for the legacy path, then continue executing the original tool call.

`requestState` is untrusted and must not be the mechanism that authorizes anything. Bifrost's rule: `requestState` is an opaque nonce that only proves "this is a retry of a roots activation", and every root in `inputResponses` goes through the identical validation the legacy path applies (`client_root_to_path`, then `SearchToolsService::bind_client_workspace`, which is what enforces the actual filesystem policy). Generate the nonce with a monotonic counter plus a per-process random prefix; do not put the tool name, arguments, or a path into it. Reject a retry whose `requestState` does not match an outstanding activation and treat it as an unauthorized first call. Do not implement more than one MRTR round: if the retry does not produce a usable root, return the ordinary unbound-workspace error rather than asking again, so a misbehaving client cannot loop the server.

Explicitly out of scope and to be stated in the error path: a server started with `--root` never issues an MRTR roots request, because its workspace is not client-controlled.

**Acceptance.** A new test `rootless_mcp_binds_through_mrtr_roots_on_2026_07_28` in the contract suite: handshake with `"protocolVersion": "2026-07-28"` and a client `roots` capability, call `search_symbols`, assert the response is `{"resultType": "input_required", "inputRequests": {"roots": {"method": "roots/list", ...}}, "requestState": "..."}`, retry the same call with `inputResponses` and the echoed `requestState`, and assert the retry returns real symbol results from the fixture workspace. A second test asserts that a `2025-11-25` session never receives an `input_required` result and instead uses the legacy `roots/list` server-to-client request. A third asserts a tampered `requestState` is refused.

### Milestone 5 — Discovery, resultType, and cache hints

**Scope.** The remaining `2026-07-28` surface.

**Work.** `server/discover` needs no code: `rmcp`'s default `discover` builds a `DiscoverResult` from `supported_protocol_versions()` and `get_info()`. Verify the default output is right for Bifrost and override only if the build identity must appear there too. Override `supported_protocol_versions` only if Bifrost needs to *narrow* the list; by default it advertises everything `rmcp` knows, which is correct.

`resultType` is handled by `rmcp`: `CallToolResult` constructors set `Some(ResultType::COMPLETE)` and the SDK clears the field for peers that negotiated an older revision. Verify with a test rather than writing code.

Cache hints require a decision per surface, and the decision must be conservative because a wrong `cacheScope` leaks one workspace's results to another:

- `tools/list` — the tool list depends only on the server mode and whether the workspace is a Git repository, both fixed at process start. `ttlMs` of 300000 (five minutes), `cacheScope: public`.
- `resources/list` and `resources/read` for `bifrost://agent-guidance/agents.md` — the content is compiled into the binary with `include_str!` and never changes for a given build. `ttlMs` of 3600000 (one hour), `cacheScope: public`.
- `tools/call` results — never cached. Every tool result depends on the bound workspace and the current state of the files in it. Emit no cache hint at all.

Write the rationale for each of those into a comment next to the constants, because the safety argument is not obvious from the numbers.

**Acceptance.** Tests asserting the `server/discover` response lists both `2025-11-25` and `2026-07-28` and reports `bifrost` as the server name; that a `2026-07-28` `tools/call` result carries `"resultType": "complete"` while a `2025-11-25` one omits the field entirely; and that `tools/list` carries the expected `ttlMs`/`cacheScope` on `2026-07-28` and omits them on `2025-11-25`.

### Milestone 6 — Delete the hand-written protocol stack

**Scope.** The end state issue #1328 asks for: no parallel dispatch, no duplicate wire types, no custom writer queue.

**Work.** Delete from `crates/bifrost-mcp/src/mcp_common.rs`: `JSONRPC_VERSION`, `PROTOCOL_VERSION`, all six JSON-RPC error-code constants, `MAX_IN_FLIGHT_CANCELLABLE_REQUESTS`, `MAX_PENDING_MCP_RESPONSES`, `ROOTS_REQUEST_ID_PREFIX`, `McpConnectionState`, `McpRequestCancellations`, `ActiveMcpRequest`, `McpRequestRegistrationError`, `OutboundMcpResponse`, `OutboundMcpResponseTiming`, `McpResponseQueueError`, `try_queue_response`, `request_id_key`, `run_stdio_server*`, `background_tool_request`, `spawn_cancellable_tool_call*`, `dispatch_message`, `handle_response`, `dispatch_request`, `handle_notification`, `initialize_result`, `list_tools_result`, `list_resources_result`, `handle_resource_read`, `handle_tool_call`, `prepare_tool_call`, `execute_prepared_tool_call`, `reconcile_codex_sandbox_workspace`, `revoke_codex_sandbox_workspace`, `unbound_workspace_error`, `map_service_error`, `success_response`, `error_response`, `tool_success_result`, `tool_error_result`, `PreparedToolCall`, `ToolCallPreparation`, `WorkspaceBindingSource`, and every unit test in the trailing `mod tests` that covers deleted code.

Keep in `mcp_common.rs`: `McpRenderOptions`, `McpServerSpec`, `build_server_spec*`, `tool_descriptor`, `mutating_tool_descriptor`, `weight_knob_descriptor`, `json_schema_object`, `SEARCHTOOLS_INSTRUCTIONS`, the benchmark constants and `MCP_FILE_WATCHER_ENV`, `file_watching_enabled`, `mcp_analyzer_request_budget` and `benchmark_mcp_request_budget_secs`, `agents_guidance_*`, and the entire `get_summaries` budgeting block from `fit_get_summaries_output_to_budget` through `compact_symbol_label`. Consider splitting the budgeting block into `crates/bifrost-mcp/src/get_summaries_budget.rs` if what remains in `mcp_common.rs` reads as two unrelated files; decide once the deletion is done and the remaining size is known.

Delete `BIFROST_MCP_RMCP` and re-point the name `run_stdio_server_with_build_identity` at `rmcp_host`. `mcp_core.rs`, `mcp_extended.rs`, `mcp_slopcop.rs`, `src/bin/bifrost.rs`, and `crates/bifrost-mcp/src/bin/bifrost-mcp-test-server.rs` should need no change beyond their `use` paths.

Move `buildIdentity` consumers to `_meta`: `tests/mcp_build_identity_facade.rs`, `src/benchmark/mcp_session.rs::validate_server_build_identity`, and the fake server transcript in `tests/suite_mcp_cli/bifrost_benchmark_run.rs:203`.

**Acceptance.** `grep -n 'jsonrpc' crates/bifrost-mcp/src/*.rs` returns nothing outside test fixtures. The full suite passes. `cargo clippy --all-targets --all-features -- -D warnings` is clean with no `#[allow(dead_code)]` added.

### Milestone 7 — Validation, benchmark, adapters, documentation

**Scope.** Prove the product constraints survived and update everything a user reads.

**Work.** Run the fairness benchmark in release mode against the pinned Bifrost snapshot and compare the `mcp_fairness` light-request and cancellation p95 to `benchmark/baselines`. The contract is the 5,000 ms `max_p95_ms` in `benchmark/interactive-latency.toml`. If the migration costs measurable latency, find it before changing `ANALYZER_POOL_CAPACITY`; the capacity is only allowed to move with benchmark evidence.

Exercise the configured adapters end to end against both revisions: `plugins/bifrost-agent/extensions/mcp-adapter.ts` and its test `plugins/bifrost-agent/test/mcp-adapter.test.mjs`, plus the manifests `plugins/bifrost-agent/mcp.json`, `.mcp.json`, and `claude-mcp.json`. Specifically confirm whether any configured adapter negotiates `2026-07-28`; if none does yet, say so in the retrospective, because it means the MRTR path is covered only by Bifrost's own tests.

Run the property fuzzer (`src/bin/bifrost_mcp_property_fuzzer.rs`) against the new server; it is the best available check for wire shapes the contract suite does not enumerate.

Update `docs/src/content/docs/mcp.md` and `docs/src/content/docs/zed-mcp.md` for the supported revisions and the new rootless activation flow, and `crates/bifrost-mcp/resources/agent-guidance/bifrost-agents.md` if it mentions the handshake.

**Acceptance.** The commands in `Concrete Steps` all pass, and the benchmark run is recorded in `Artifacts and Notes`.

## Concrete Steps

All commands run from the repository root, which for this worktree is `/Users/dave/Workspace/BrokkAi/bifrost/.claude/worktrees/cargo-dist-cleanup-972b88`.

Routine per-milestone validation (do not enable `nlp` for these; see `CLAUDE.md` on build disk footprint):

    cargo fmt
    cargo clippy --all-targets --all-features -- -D warnings
    cargo test -p brokk-bifrost-mcp --test bifrost_mcp_server

Note that inside a nested worktree the `clippy-no-cuda` cargo alias is broken by duplicate alias arrays in the two `.cargo/config.toml` files; use the expanded `cargo clippy` command shown above.

Running one contract test against the new implementation during Milestones 1-5:

    BIFROST_MCP_RMCP=on cargo test -p brokk-bifrost-mcp --test bifrost_mcp_server rootless_mcp_binds_to_client_roots -- --nocapture

The pre-push gate required by `CLAUDE.md`:

    cargo fmt
    cargo clippy --all-targets --all-features -- -D warnings
    cargo test --features nlp,python --test bifrost_mcp_server

If the `python` feature fails to build with "cannot set a minimum Python version 3.12 higher than the interpreter version 3.9", point pyo3 at a newer interpreter:

    PYO3_PYTHON=$(brew --prefix python@3.13)/bin/python3.13 cargo test --features nlp,python --test bifrost_mcp_server

The release-mode fairness benchmark (Milestone 7):

    cargo build --release --bin bifrost_benchmark
    ./target/release/bifrost_benchmark --manifest benchmark/interactive-latency.toml

Expect every scenario to report a p95 under its `max_p95_ms` of 5000.0, and specifically expect the `mcp_fairness` scenario `heavy-scan-does-not-block-source` to pass.

Use `scripts/with-isolated-cargo-target.sh` for any build that should not pollute the shared target directory, for example:

    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings

## Validation and Acceptance

The change is accepted when all of the following are observable.

A `2025-11-25` client sees no difference. Start the server and drive it by hand:

    printf '%s\n' \
      '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"manual","version":"0"}}}' \
      '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
      '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
      | ./target/debug/bifrost --mcp searchtools --root .

Expect an initialize result whose `result.protocolVersion` is `"2025-11-25"`, whose `result.serverInfo.name` is `"bifrost"`, and whose `result._meta["io.bifrost/build-identity"]` matches the binary's build identity; then a `tools/list` result with the same tool names and schemas as before the change, and no `resultType` field anywhere.

A `2026-07-28` client sees the new surface. Repeat with `"protocolVersion":"2026-07-28"` and additionally send `{"jsonrpc":"2.0","id":0,"method":"server/discover"}` before initialize. Expect a discover result listing both revisions, a `tools/list` result carrying `ttlMs` and `cacheScope`, and a `tools/call` result carrying `"resultType":"complete"`.

A rootless `2026-07-28` client can activate a workspace. Start `./target/debug/bifrost --mcp searchtools` with no `--root` from an unrelated directory, handshake at `2026-07-28`, and call `search_symbols`. Expect an `input_required` result embedding a `roots/list` request; supply `inputResponses` with a `file://` root and the echoed `requestState`; expect real results scoped to that root, and expect that the process never analyzed its own working directory.

Cancellation stops analyzer work. Start a heavy `scan_usages_by_location`, send `notifications/cancelled` for its id, and observe both that the scan's response reports the analyzer's own cancelled/incomplete reason and that a subsequent lightweight `get_symbol_sources` returns promptly with a real result.

The regression suites pass: `cargo test --features nlp,python --test bifrost_mcp_server` with all 53 pre-existing functions plus the new ones green, `cargo fmt` clean, and `cargo clippy --all-targets --all-features -- -D warnings` clean.

The fairness benchmark passes its 5,000 ms p95 contract.

`crates/bifrost-mcp/src/` contains no JSON-RPC envelope construction, no protocol-version constant, no method-name dispatch table, and no response queue.

## Idempotence and Recovery

Every step is a source edit plus a rebuild; rerunning any command is safe. The environment variable `BIFROST_MCP_RMCP` makes the migration reversible at runtime through Milestone 5: if the new path misbehaves, unset it and the old path serves. After Milestone 6 the only rollback is `git revert`, which is why Milestone 6 is a single self-contained commit that touches no product behavior.

The one irreversible-looking step is deleting code in Milestone 6, and it is recoverable from git history. Do not delete anything in Milestone 6 until the full suite passes against the new path with `BIFROST_MCP_RMCP=on`.

Commit at every milestone boundary with a multiline message explaining the why, per `CLAUDE.md`. Commit directly to the current branch; do not create branches.

Leave no stray temporary target directories: use `scripts/with-isolated-cargo-target.sh` for isolated builds and `scripts/cleanup-bifrost-tmp.sh` (dry run by default) to inspect leftovers.

## Artifacts and Notes

The rmcp 3.0.1 source used for the API spike is in the local cargo registry cache at:

    ~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/rmcp-3.0.1

The files that matter most for this plan:

    src/handler/server.rs        the ServerHandler trait and every default method
    src/service.rs               RequestContext, NotificationContext, ServiceExt::serve
    src/service/server.rs        negotiate_protocol_version, Peer::list_roots
    src/model.rs                 ProtocolVersion, InitializeResult, CallToolResult, CallToolRequestParams
    src/model/mrtr.rs            InputRequiredResult, InputRequest, CallToolResponse
    src/model/capabilities.rs    ServerCapabilities and its builder
    src/transport/io.rs          stdio()
    tests/test_mrtr_behavior.rs  a worked stateless MRTR server
    tests/test_stdio_response_concurrency.rs  a minimal manual ServerHandler over real pipes

Benchmark and profiling transcripts, the before/after fairness numbers, and any wire transcripts that prove a milestone are to be appended here as work proceeds.

## Revision Notes

- 2026-07-30: Initial version, written after reading issue #1328, surveying `crates/bifrost-mcp` at commit `7fbd8ec5`, and spiking the `rmcp` 3.0.1 API from vendored source. The milestone order was chosen so that the security-critical workspace-authorization code (Milestone 3) moves only after the mechanical protocol surface (Milestone 1) and the concurrency model (Milestone 2) are already proven against the existing wire test suite, and so that nothing is deleted (Milestone 6) until the replacement passes the full suite.
