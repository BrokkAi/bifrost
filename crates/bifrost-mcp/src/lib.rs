//! MCP host implementation for the `brokk-bifrost` facade.
//!
//! Internal implementation detail of `brokk-bifrost`; no stability guarantees --
//! depend on `brokk-bifrost` instead.

pub use brokk_bifrost_analysis::{
    AnalyzerConfig, BIFROST_IGNORE_FILE_NAME, CancellationToken, FilesystemProject, Project,
    ProjectFile, WorkspaceAnalyzer, WorkspaceFileListingCache, analyzer, cache_db, cancellation,
    code_quality, collect_workspace_files, diff_analysis, file_tools, git_file, gitblob, hash,
    path_normalization, path_utils, profiling, searchtools, searchtools_render, sexp,
    symbol_rename, workspace_document,
};
#[cfg(feature = "nlp")]
pub use brokk_bifrost_nlp as nlp;
pub use brokk_bifrost_policy as policy;
pub use brokk_bifrost_runtime::{CodeIntelligenceRuntime, code_intelligence};

pub mod analyzer_pool;
pub mod mcp_cli;
pub mod mcp_common;
pub mod mcp_core;
pub mod mcp_extended;
pub mod mcp_nlp;
pub mod mcp_registry;
pub mod mcp_slopcop;
pub mod mcp_text;
pub mod ordered_transport;
mod project_watcher;
pub mod rmcp_host;
pub mod scoped_project;
pub mod searchtools_service;
pub mod tool_arguments;

pub use project_watcher::{ChangeDelta, ProjectChangeWatcher};
pub use searchtools_service::{
    SearchToolsService, SearchToolsServiceError, SearchToolsServiceErrorCode, ToolOutput,
};

/// Process-boundary constants used by the repository benchmark application.
#[doc(hidden)]
pub mod benchmark_api {
    pub use crate::mcp_common::{
        BENCHMARK_MCP_REQUEST_BUDGET_SECS, BENCHMARK_PROFILE_BOUNDARY_MARKER,
        BENCHMARK_PROFILE_BOUNDARY_METHOD, MCP_ANALYZER_REQUEST_BUDGET_SECS_ENV,
        MCP_FILE_WATCHER_ENV,
    };
    pub use crate::searchtools_service::WORKSPACE_SNAPSHOT_NOT_READY_MESSAGE;
}
