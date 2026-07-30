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

use crate::SearchToolsService;
use crate::mcp_common::{
    AGENTS_GUIDANCE_MIME_TYPE, AGENTS_GUIDANCE_TEXT, AGENTS_GUIDANCE_URI,
    BENCHMARK_PROFILE_BOUNDARY_MARKER, BENCHMARK_PROFILE_BOUNDARY_METHOD, MCP_FILE_WATCHER_ENV,
    McpRenderOptions, McpServerSpec, file_watching_enabled,
};
use rmcp::model::{
    Annotations, CallToolRequestParams, CallToolResponse, CustomRequest, CustomResult, ErrorData,
    Implementation, InitializeResult, ListResourcesResult, ListToolsResult, MetaObject,
    PaginatedRequestParams, ReadResourceRequestParams, ReadResourceResponse, ReadResourceResult,
    Resource, ResourceContents, Role, ServerCapabilities, ServerInfo, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{RoleServer, ServerHandler, ServiceExt};
use std::collections::HashSet;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

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

/// Bifrost's `ServerHandler`. One instance serves one stdio connection.
pub struct BifrostMcpHandler {
    service: Arc<SearchToolsService>,
    instructions: &'static str,
    build_identity: String,
    tools: Vec<Tool>,
    #[allow(dead_code)] // Milestone 2 wires this into `call_tool`.
    tool_names: HashSet<String>,
    #[allow(dead_code)] // Milestone 2 wires this into `call_tool`.
    render_options: McpRenderOptions,
}

impl BifrostMcpHandler {
    fn new(
        service: Arc<SearchToolsService>,
        render_options: McpRenderOptions,
        spec: &McpServerSpec,
        build_identity: &str,
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
        })
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

    async fn call_tool(
        &self,
        _request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        // Milestone 2 of the ExecPlan wires this to the analyzer execution
        // pool; Milestone 3 adds workspace binding. Until then the rmcp path
        // is selectable only for the protocol surface that needs neither.
        let _ = &self.service;
        Err(ErrorData::internal_error(
            "tools/call is not yet served by the rmcp host",
            None,
        ))
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
    let watch_files = file_watching_enabled(std::env::var_os(MCP_FILE_WATCHER_ENV).as_deref())?;
    let service = Arc::new(match (root, watch_files) {
        (Some(root), true) => SearchToolsService::new_deferred(root)?,
        (Some(root), false) => SearchToolsService::new_deferred_manual(root)?,
        (None, true) => SearchToolsService::new_unbound(),
        (None, false) => SearchToolsService::new_unbound_manual(),
    });
    let handler =
        BifrostMcpHandler::new(Arc::clone(&service), render_options, spec, build_identity)?;

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
            .serve(rmcp::transport::stdio())
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
