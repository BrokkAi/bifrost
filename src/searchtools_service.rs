#[cfg(feature = "nlp")]
use crate::nlp::{indexer::SemanticIndexer, query::semantic_search};
use crate::{
    AnalyzerConfig, FilesystemProject, Project, ProjectChangeWatcher, ProjectFile,
    WorkspaceAnalyzer,
    code_quality::{
        analyze_git_hotspots, compute_cognitive_complexity, compute_cyclomatic_complexity,
        report_comment_density_for_code_unit, report_comment_density_for_files,
        report_dead_code_and_unused_abstraction_smells, report_exception_handling_smells,
        report_long_method_and_god_object_smells, report_secret_like_code,
        report_structural_clone_smells, report_test_assertion_smells,
    },
    commit_analysis::{AnalyzeCommitParams, analyze_commit_at_root},
    file_tools::{
        find_filenames, find_files_containing, get_file_contents, list_files, search_file_contents,
    },
    git_tools::{get_commit_diff, get_git_log, search_git_commit_messages},
    profiling,
    searchtools::{
        ActivateWorkspaceParams, ActiveWorkspaceResult, GetActiveWorkspaceParams,
        MostRelevantFilesParams, RefreshParams, SymbolLookupParams, SymbolSourcesResult,
        classify_test_files, get_declarations_by_location, get_definitions_by_location,
        get_definitions_by_reference, get_summaries, get_symbol_ancestors, get_symbol_locations,
        get_symbol_sources, get_type_by_location, list_symbols, most_relevant_files,
        refresh_result, rename_symbol, scan_usages_by_location, scan_usages_by_reference,
        search_symbols, symbol_source_candidate_files, usage_graph,
    },
    searchtools_render::{RenderOptions, RenderText},
    structured_data::{jq, xml_select, xml_skim},
    workspace_document::{WorkspaceDocumentError, WorkspaceRoot, read_workspace_document},
};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchToolsServiceErrorCode {
    InvalidParams,
    UnknownTool,
    Internal,
}

const MAX_QUERY_FILE_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone)]
pub struct SearchToolsServiceError {
    pub code: SearchToolsServiceErrorCode,
    pub message: String,
}

impl SearchToolsServiceError {
    fn invalid_params(message: impl Into<String>) -> Self {
        Self {
            code: SearchToolsServiceErrorCode::InvalidParams,
            message: message.into(),
        }
    }

    fn unknown_tool(message: impl Into<String>) -> Self {
        Self {
            code: SearchToolsServiceErrorCode::UnknownTool,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            code: SearchToolsServiceErrorCode::Internal,
            message: message.into(),
        }
    }
}

impl fmt::Display for SearchToolsServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for SearchToolsServiceError {}

#[derive(Debug, Clone, PartialEq)]
pub enum ToolOutput {
    Text(String),
    Structured {
        structured: Value,
        rendered_text: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize)]
struct PythonToolPayload {
    structured: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    rendered_text: Option<String>,
}

impl ToolOutput {
    pub fn into_value(self) -> Value {
        match self {
            Self::Text(text) => Value::String(text),
            Self::Structured { structured, .. } => structured,
        }
    }

    pub fn into_python_payload(self) -> Value {
        match self {
            Self::Text(text) => Value::String(text),
            Self::Structured {
                structured,
                rendered_text,
            } => serde_json::to_value(PythonToolPayload {
                structured,
                rendered_text,
            })
            .unwrap_or(Value::Null),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpdateStrategy {
    WatchFiles,
    /// No background file watcher; the caller drives updates explicitly via the
    /// incremental `update_paths` tool. Used by batch consumers (e.g. the localizer
    /// embedding pipeline) that check out successive revisions into one worktree and
    /// know exactly which files changed -- avoiding a whole-tree watcher and a full
    /// re-analysis per revision.
    Manual,
}

type WatcherStarter =
    Arc<dyn Fn(Arc<dyn Project>) -> Result<ProjectChangeWatcher, String> + Send + Sync + 'static>;

fn production_watcher_starter() -> WatcherStarter {
    Arc::new(ProjectChangeWatcher::start)
}

pub struct SearchToolsService {
    root: RwLock<PathBuf>,
    session: RwLock<Option<WorkspaceSession>>,
    /// When constructed via `new_deferred`, the initial workspace build (file
    /// discovery + parse) runs on a background thread and lands here.
    /// `ensure_ready` joins it and installs the resulting session into `session`
    /// on first access. `None` once the session is ready (or for
    /// synchronously-built services).
    pending_build: Mutex<Option<JoinHandle<Result<WorkspaceSession, String>>>>,
    /// Records a deferred-build failure (e.g. the workspace walk hit an IO
    /// error) so every access after the first surfaces it instead of hanging.
    build_error: Mutex<Option<String>>,
    update_strategy: UpdateStrategy,
    semantic_indexing: bool,
    watcher_starter: WatcherStarter,
}

struct WorkspaceSession {
    snapshot: Arc<WorkspaceAnalyzer>,
    document_root: Arc<WorkspaceRoot>,
    watcher: SessionWatcher,
    #[cfg(feature = "nlp")]
    semantic: Option<Arc<SemanticIndexer>>,
}

enum SessionWatcher {
    Disabled,
    Active(ProjectChangeWatcher),
}

/// Owns one workspace snapshot and its request-scoped analyzer memoization.
///
/// Returning this from `snapshot_for_query` makes the cleanup obligation part
/// of the type, including for direct callers such as the code-query REPL.
struct WorkspaceQueryScope {
    source_snapshot: Arc<WorkspaceAnalyzer>,
    snapshot: Arc<WorkspaceAnalyzer>,
    document_root: Arc<WorkspaceRoot>,
    context: Arc<crate::analyzer::AnalyzerQueryContext>,
}

impl WorkspaceQueryScope {
    fn new(source_snapshot: Arc<WorkspaceAnalyzer>, document_root: Arc<WorkspaceRoot>) -> Self {
        let context = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        Self::with_context(source_snapshot, document_root, context)
    }

    fn with_context(
        source_snapshot: Arc<WorkspaceAnalyzer>,
        document_root: Arc<WorkspaceRoot>,
        context: Arc<crate::analyzer::AnalyzerQueryContext>,
    ) -> Self {
        let snapshot = Arc::new(source_snapshot.as_ref().clone());
        snapshot.begin_query(&context);
        Self {
            source_snapshot,
            snapshot,
            document_root,
            context,
        }
    }

    fn arc(&self) -> &Arc<WorkspaceAnalyzer> {
        &self.source_snapshot
    }

    fn scope_snapshot(&self, source_snapshot: Arc<WorkspaceAnalyzer>) -> Self {
        Self::with_context(
            source_snapshot,
            Arc::clone(&self.document_root),
            Arc::clone(&self.context),
        )
    }

    fn document_root(&self) -> &WorkspaceRoot {
        &self.document_root
    }

    fn finish<T>(
        self,
        operation: &str,
        result: Result<T, SearchToolsServiceError>,
    ) -> Result<T, SearchToolsServiceError> {
        match result {
            Err(error) => Err(error),
            Ok(value) => match self.context.store_error() {
                Some(error) => Err(SearchToolsServiceError::internal(format!(
                    "Analyzer store failure while running `{operation}`: {error}"
                ))),
                None => Ok(value),
            },
        }
    }
}

impl Deref for WorkspaceQueryScope {
    type Target = WorkspaceAnalyzer;

    fn deref(&self) -> &Self::Target {
        self.snapshot.as_ref()
    }
}

impl Drop for WorkspaceQueryScope {
    fn drop(&mut self) {
        self.snapshot.end_query(&self.context);
    }
}

enum ObservedSource {
    Present(String),
    Missing,
}

fn classify_source_read(
    file: &ProjectFile,
    result: io::Result<String>,
) -> Result<ObservedSource, SearchToolsServiceError> {
    match result {
        Ok(source) => Ok(ObservedSource::Present(source)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(ObservedSource::Missing),
        Err(err) => Err(SearchToolsServiceError::internal(format!(
            "Failed to verify source freshness for {}: {err}",
            file.rel_path().display()
        ))),
    }
}

fn stale_symbol_source_files(
    analyzer: &dyn crate::analyzer::IAnalyzer,
    candidate_files: BTreeSet<ProjectFile>,
) -> Result<BTreeSet<ProjectFile>, SearchToolsServiceError> {
    candidate_files
        .into_iter()
        .filter_map(|file| {
            let current = analyzer.project().read_source(&file);
            match classify_source_read(&file, current) {
                Ok(ObservedSource::Present(current))
                    if analyzer.indexed_source_matches(&file, &current) =>
                {
                    None
                }
                Ok(_) => Some(Ok(file)),
                Err(err) => Some(Err(err)),
            }
        })
        .collect()
}

impl WorkspaceSession {
    fn close_semantic(&self) {
        #[cfg(feature = "nlp")]
        if let Some(semantic) = &self.semantic {
            semantic.close();
        }
    }
}

/// Semantic indexing is off by default. Set `BIFROST_SEMANTIC_INDEX=auto`
/// (or `on`/`1`/`enabled`) to opt in when semantic_search is needed.
fn semantic_indexing_enabled() -> bool {
    if cfg!(not(feature = "nlp")) {
        return false;
    }
    matches!(
        std::env::var("BIFROST_SEMANTIC_INDEX").as_deref(),
        Ok("auto") | Ok("on") | Ok("1") | Ok("enabled")
    )
}

#[cfg(feature = "nlp")]
fn maybe_start_semantic(
    enabled: bool,
    snapshot: &Arc<WorkspaceAnalyzer>,
) -> Option<Arc<SemanticIndexer>> {
    maybe_start_semantic_checked(enabled, snapshot, semantic_accelerator_ready)
}

/// Ok when the voyage-4-nano embedder can run: a CUDA/Metal accelerator is
/// present, or the operator forced CPU. Mirrors `nlp::semantic_search_available`
/// so the tool is never advertised without also being startable.
#[cfg(feature = "nlp")]
fn semantic_accelerator_ready() -> Result<(), String> {
    if crate::nlp::semantic_search_available() {
        Ok(())
    } else {
        Err(
            "no CUDA or Metal accelerator detected; pass --force-semantic-cpu to run the \
             embedder on CPU"
                .to_string(),
        )
    }
}

#[cfg(feature = "nlp")]
fn maybe_start_semantic_checked(
    enabled: bool,
    snapshot: &Arc<WorkspaceAnalyzer>,
    accelerator_ready: impl FnOnce() -> Result<(), String>,
) -> Option<Arc<SemanticIndexer>> {
    if !enabled {
        return None;
    }
    if let Err(err) = accelerator_ready() {
        eprintln!("bifrost semantic index disabled: {err}");
        return None;
    }
    let root = snapshot.analyzer().project().root().to_path_buf();
    if !crate::nlp::gitcache::is_git_repo(&root) {
        eprintln!("bifrost semantic index disabled: semantic search requires a git repository");
        return None;
    }
    Some(SemanticIndexer::start(root, snapshot.clone()))
}

impl SearchToolsService {
    pub fn new(root: PathBuf) -> Result<Self, String> {
        Self::new_with_strategy(
            root,
            UpdateStrategy::WatchFiles,
            semantic_indexing_enabled(),
        )
    }

    pub fn new_for_python(root: PathBuf) -> Result<Self, String> {
        Self::new_lazy_with_strategy(
            root,
            UpdateStrategy::WatchFiles,
            semantic_indexing_enabled(),
        )
    }

    /// Construct without a background semantic indexer regardless of env;
    /// `semantic_search` reports itself unavailable on such a service.
    pub fn new_without_semantic_index(root: PathBuf) -> Result<Self, String> {
        Self::new_with_strategy(root, UpdateStrategy::WatchFiles, false)
    }

    /// Construct with no file watcher and no semantic indexer. This is useful
    /// for immutable, short-lived workspaces such as inline test fixtures.
    pub fn new_manual_without_semantic_index(root: PathBuf) -> Result<Self, String> {
        Self::new_transient_with_strategy(root, UpdateStrategy::Manual, false)
    }

    /// Construct a manual, non-semantic service over an already-selected
    /// project. One-shot CLI subset workspaces use this to avoid whole-root
    /// watchers while still sharing the analyzer blob cache for git roots.
    pub fn new_manual_for_project(project: Arc<dyn Project>) -> Result<Self, String> {
        let root = project.root().to_path_buf();
        let watcher_starter = production_watcher_starter();
        let workspace =
            WorkspaceAnalyzer::build_persisted(Arc::clone(&project), AnalyzerConfig::default())
                .map_err(|error| format!("Failed to build persisted workspace: {error}"))?;
        let session = assemble_session(
            project,
            workspace,
            UpdateStrategy::Manual,
            false,
            &watcher_starter,
        )?;
        Ok(Self {
            root: RwLock::new(root),
            session: RwLock::new(Some(session)),
            pending_build: Mutex::new(None),
            build_error: Mutex::new(None),
            update_strategy: UpdateStrategy::Manual,
            semantic_indexing: false,
            watcher_starter,
        })
    }

    /// Construct with no file watcher and no semantic indexer: the caller drives
    /// updates via the incremental `update_paths` tool. For batch consumers that
    /// re-use one session across many revisions of one worktree.
    pub fn new_for_python_manual(root: PathBuf) -> Result<Self, String> {
        Self::new_transient_with_strategy(root, UpdateStrategy::Manual, false)
    }

    pub fn call_tool_json(
        &self,
        name: &str,
        arguments_json: &str,
    ) -> Result<String, SearchToolsServiceError> {
        let arguments = serde_json::from_str::<Value>(arguments_json).map_err(|err| {
            SearchToolsServiceError::invalid_params(format!("Invalid JSON arguments: {err}"))
        })?;
        let result = self
            .call_tool_output(name, arguments, RenderOptions::default())?
            .into_value();
        serde_json::to_string(&result).map_err(|err| {
            SearchToolsServiceError::internal(format!("Failed to serialize tool result: {err}"))
        })
    }

    pub fn call_tool_payload_json(
        &self,
        name: &str,
        arguments_json: &str,
        render_options: RenderOptions,
    ) -> Result<String, SearchToolsServiceError> {
        let arguments = serde_json::from_str::<Value>(arguments_json).map_err(|err| {
            SearchToolsServiceError::invalid_params(format!("Invalid JSON arguments: {err}"))
        })?;
        let result = self.call_tool_output(name, arguments, render_options)?;
        serde_json::to_string(&result.into_python_payload()).map_err(|err| {
            SearchToolsServiceError::internal(format!("Failed to serialize tool payload: {err}"))
        })
    }

    pub fn call_tool_value(
        &self,
        name: &str,
        arguments: Value,
    ) -> Result<Value, SearchToolsServiceError> {
        Ok(self
            .call_tool_output(name, arguments, RenderOptions::default())?
            .into_value())
    }

    pub fn call_tool_output(
        &self,
        name: &str,
        arguments: Value,
        render_options: RenderOptions,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        // Lifecycle tools bypass watcher delta application: refresh rebuilds
        // explicitly, activate replaces the whole workspace, and get is cheap.
        match name {
            "refresh" => return self.handle_refresh(arguments),
            "update_paths" => return self.handle_update_paths(arguments),
            "activate_workspace" => return self.handle_activate_workspace(arguments),
            "get_active_workspace" => return self.handle_get_active_workspace(arguments),
            _ => {}
        }

        if name == "semantic_search" {
            return self.handle_semantic_search(arguments, render_options);
        }
        if name == "semantic_search_status" {
            return self.handle_semantic_search_status(arguments);
        }
        if name == "analyze_commit" {
            let params =
                serde_json::from_value::<AnalyzeCommitParams>(arguments).map_err(|err| {
                    SearchToolsServiceError::invalid_params(format!(
                        "Invalid tool arguments: {err}"
                    ))
                })?;
            let root = self.service_root()?;
            return Self::structured_only(
                analyze_commit_at_root(&root, params).map_err(SearchToolsServiceError::internal)?,
            );
        }

        let arguments = self.normalize_arguments_for_current_workspace(name, arguments)?;
        if name == "get_symbol_sources" {
            return self
                .handle_get_symbol_sources(strip_legacy_kind_filter(arguments), render_options);
        }
        let snapshot = {
            let _scope = profiling::scope("SearchToolsService::snapshot_for_query");
            self.snapshot_for_query()?
        };
        let result = (|| match name {
            "search_symbols" => Self::decode_render_and_run(
                &snapshot,
                arguments,
                render_options,
                |workspace, params| search_symbols(workspace.analyzer(), params),
            ),
            "get_symbol_locations" => Self::decode_render_and_run(
                &snapshot,
                strip_legacy_kind_filter(arguments),
                render_options,
                |workspace, params| get_symbol_locations(workspace.analyzer(), params),
            ),
            "get_symbol_ancestors" => Self::decode_render_and_run(
                &snapshot,
                strip_legacy_kind_filter(arguments),
                render_options,
                |workspace, params| get_symbol_ancestors(workspace.analyzer(), params),
            ),
            "get_summaries" => Self::decode_render_and_run(
                &snapshot,
                arguments,
                render_options,
                |workspace, params| get_summaries(workspace.analyzer(), params),
            ),
            "list_symbols" => Self::decode_render_and_run(
                &snapshot,
                arguments,
                render_options,
                |workspace, params| list_symbols(workspace.analyzer(), params),
            ),
            "classify_test_files" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    classify_test_files(workspace.analyzer(), params)
                })
            }
            "most_relevant_files" => Self::decode_render_and_try_run(
                &snapshot,
                arguments,
                render_options,
                |workspace, params: MostRelevantFilesParams| {
                    most_relevant_files(workspace.analyzer(), params)
                },
            ),
            "scan_usages_by_reference" => {
                Self::validate_scan_usages_by_reference_arguments(&arguments)?;
                Self::decode_render_and_run(
                    &snapshot,
                    arguments,
                    render_options,
                    |workspace, params| scan_usages_by_reference(workspace.analyzer(), params),
                )
            }
            "scan_usages_by_location" => {
                Self::validate_scan_usages_by_location_arguments(&arguments)?;
                Self::decode_render_and_run(
                    &snapshot,
                    arguments,
                    render_options,
                    |workspace, params| scan_usages_by_location(workspace.analyzer(), params),
                )
            }
            "get_definitions_by_location" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    get_definitions_by_location(workspace.analyzer(), params)
                })
            }
            "get_declarations_by_location" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    get_declarations_by_location(workspace.analyzer(), params)
                })
            }
            "get_definitions_by_reference" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    get_definitions_by_reference(workspace.analyzer(), params)
                })
            }
            "get_type_by_location" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    get_type_by_location(workspace.analyzer(), params)
                })
            }
            "rename_symbol" => Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                rename_symbol(workspace.analyzer(), params)
            }),
            "usage_graph" => Self::decode_render_and_run(
                &snapshot,
                arguments,
                render_options,
                |workspace, params| usage_graph(workspace.analyzer(), params),
            ),
            "query_code" => {
                let output = Self::query_code_result_for_snapshot(&snapshot, arguments)?;
                let rendered_text = output.render_text();
                let structured = serde_json::to_value(&output).map_err(|err| {
                    SearchToolsServiceError::internal(format!(
                        "Failed to serialize tool result: {err}"
                    ))
                })?;
                Ok(ToolOutput::Structured {
                    structured,
                    rendered_text: Some(rendered_text),
                })
            }
            "get_file_contents" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    get_file_contents(workspace.analyzer(), params)
                })
            }
            "find_filenames" => Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                find_filenames(workspace.analyzer(), params)
            }),
            "find_files_containing" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    find_files_containing(workspace.analyzer(), params)
                })
            }
            "search_file_contents" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    search_file_contents(workspace.analyzer(), params)
                })
            }
            "list_files" => Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                list_files(workspace.analyzer(), params)
            }),
            "search_git_commit_messages" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    search_git_commit_messages(workspace.analyzer(), params)
                })
            }
            "get_git_log" => Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                get_git_log(workspace.analyzer(), params)
            }),
            "get_commit_diff" => Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                get_commit_diff(workspace.analyzer(), params)
            }),
            "jq" => Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                jq(workspace.analyzer(), params)
            }),
            "xml_skim" => Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                xml_skim(workspace.analyzer(), params)
            }),
            "xml_select" => Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                xml_select(workspace.analyzer(), params)
            }),
            "compute_cyclomatic_complexity" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    compute_cyclomatic_complexity(workspace.analyzer(), params)
                })
            }
            "compute_cognitive_complexity" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    compute_cognitive_complexity(workspace.analyzer(), params)
                })
            }
            "report_comment_density_for_code_unit" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    report_comment_density_for_code_unit(workspace.analyzer(), params)
                })
            }
            "report_comment_density_for_files" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    report_comment_density_for_files(workspace.analyzer(), params)
                })
            }
            "report_exception_handling_smells" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    report_exception_handling_smells(workspace.analyzer(), params)
                })
            }
            "report_test_assertion_smells" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    report_test_assertion_smells(workspace.analyzer(), params)
                })
            }
            "report_structural_clone_smells" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    report_structural_clone_smells(workspace.analyzer(), params)
                })
            }
            "report_long_method_and_god_object_smells" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    report_long_method_and_god_object_smells(workspace.analyzer(), params)
                })
            }
            "report_dead_code_and_unused_abstraction_smells" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    report_dead_code_and_unused_abstraction_smells(workspace.analyzer(), params)
                })
            }
            "report_secret_like_code" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    report_secret_like_code(workspace.analyzer(), params)
                })
            }
            "analyze_git_hotspots" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    analyze_git_hotspots(workspace.analyzer(), params)
                })
            }
            _ => Err(SearchToolsServiceError::unknown_tool(format!(
                "Unknown tool: {name}"
            ))),
        })();
        snapshot.finish(name, result)
    }

    pub fn query_code_result(
        &self,
        arguments: Value,
    ) -> Result<crate::analyzer::structural::CodeQueryResult, SearchToolsServiceError> {
        let arguments = self.normalize_arguments_for_current_workspace("query_code", arguments)?;
        let snapshot = self.snapshot_for_query()?;
        let result = Self::query_code_result_for_snapshot(&snapshot, arguments);
        snapshot.finish("query_code", result)
    }

    fn query_code_result_for_snapshot(
        snapshot: &WorkspaceQueryScope,
        arguments: Value,
    ) -> Result<crate::analyzer::structural::CodeQueryResult, SearchToolsServiceError> {
        let query = Self::decode_query_code_input(snapshot, arguments)?;
        Ok(crate::analyzer::structural::execute(
            snapshot.analyzer(),
            &query,
        ))
    }

    fn decode_query_code_input(
        snapshot: &WorkspaceQueryScope,
        arguments: Value,
    ) -> Result<crate::analyzer::structural::CodeQuery, SearchToolsServiceError> {
        let Some(query_file) = arguments.get("query_file") else {
            return crate::analyzer::structural::CodeQuery::from_json(&arguments)
                .map_err(|error| SearchToolsServiceError::invalid_params(error.to_string()));
        };

        let object = arguments.as_object().ok_or_else(|| {
            SearchToolsServiceError::invalid_params("query_code arguments must be an object")
        })?;
        if object.len() != 1 {
            return Err(SearchToolsServiceError::invalid_params(
                "query_file is exclusive; put the complete query in the referenced file",
            ));
        }
        let query_file = query_file.as_str().ok_or_else(|| {
            SearchToolsServiceError::invalid_params("query_file must be a string path")
        })?;
        let root = snapshot.analyzer().project().root();
        let path = Path::new(query_file);
        let extension = match path.extension().and_then(|extension| extension.to_str()) {
            Some("rql") | Some("json") => path.extension().and_then(|extension| extension.to_str()),
            Some(extension) => {
                return Err(SearchToolsServiceError::invalid_params(format!(
                    "unsupported query file extension `.{extension}` for `{query_file}`; expected .rql or .json"
                )));
            }
            None => {
                return Err(SearchToolsServiceError::invalid_params(format!(
                    "query file `{query_file}` has no extension; expected .rql or .json"
                )));
            }
        };
        let contents = read_workspace_document(
            snapshot.document_root(),
            path,
            &["rql", "json"],
            MAX_QUERY_FILE_BYTES,
        )
        .map_err(|error| Self::query_file_read_error(query_file, error))?;
        let value = match extension {
            Some("rql") => crate::analyzer::structural::query::sexp::sexp_to_json(
                contents.source(),
            )
            .map_err(|error| {
                SearchToolsServiceError::invalid_params(format!(
                    "failed to parse RQL query file `{query_file}`: {error}"
                ))
            }),
            Some("json") => serde_json::from_str::<Value>(contents.source()).map_err(|error| {
                SearchToolsServiceError::invalid_params(format!(
                    "failed to parse JSON query file `{query_file}`: {error}"
                ))
            }),
            _ => unreachable!("query file extension was validated before reading"),
        }?;
        let value = crate::tool_arguments::normalize_tool_arguments("query_code", value, root)
            .map_err(SearchToolsServiceError::invalid_params)?;
        crate::analyzer::structural::CodeQuery::from_json(&value).map_err(|error| {
            SearchToolsServiceError::invalid_params(format!(
                "invalid CodeQuery in `{query_file}`: {error}"
            ))
        })
    }

    fn query_file_read_error(
        query_file: &str,
        error: WorkspaceDocumentError,
    ) -> SearchToolsServiceError {
        let message = match error {
            WorkspaceDocumentError::NotRegularFile { .. } => {
                format!("query file `{query_file}` must be a regular file")
            }
            WorkspaceDocumentError::TooLarge {
                bytes: Some(bytes),
                max_bytes,
                ..
            } => {
                format!("query file `{query_file}` is too large: {bytes} bytes exceeds {max_bytes}")
            }
            WorkspaceDocumentError::TooLarge {
                bytes: None,
                max_bytes,
                ..
            } => format!("query file `{query_file}` is too large: more than {max_bytes} bytes"),
            WorkspaceDocumentError::SymlinkNotAllowed { .. } => format!(
                "failed to read query file `{query_file}`: query file path resolves outside active workspace or traverses a symbolic link"
            ),
            WorkspaceDocumentError::PathEscapesWorkspace { .. } => {
                format!(
                    "failed to read query file `{query_file}`: query file path resolves outside active workspace"
                )
            }
            error => format!("failed to read query file `{query_file}`: {error}"),
        };
        SearchToolsServiceError::invalid_params(message)
    }

    pub fn active_workspace_root(&self) -> PathBuf {
        self.root
            .read()
            .map(|root| root.clone())
            .unwrap_or_default()
    }

    // Note: `--root` and `new_for_python` take the path as-given (canonicalized
    // by `FilesystemProject::new`) without git-root normalization, while
    // `activate_workspace` normalizes to the nearest enclosing git root. As a
    // result, calling `activate_workspace` with the same path that was passed
    // at construction may rebuild the index when the path is a subdirectory of
    // a git repository. The construction path is intentionally precise; hosts
    // that want git-root semantics should call `activate_workspace` after
    // start.
    fn new_with_strategy(
        root: PathBuf,
        update_strategy: UpdateStrategy,
        semantic_indexing: bool,
    ) -> Result<Self, String> {
        Self::new_with_strategy_and_watcher_starter(
            root,
            update_strategy,
            semantic_indexing,
            production_watcher_starter(),
        )
    }

    fn new_with_strategy_and_watcher_starter(
        root: PathBuf,
        update_strategy: UpdateStrategy,
        semantic_indexing: bool,
        watcher_starter: WatcherStarter,
    ) -> Result<Self, String> {
        let (project, workspace) = build_persisted_workspace(root)?;
        let root = project.root().to_path_buf();
        let session = assemble_session(
            project,
            workspace,
            update_strategy,
            semantic_indexing,
            &watcher_starter,
        )?;
        Ok(Self {
            root: RwLock::new(root),
            session: RwLock::new(Some(session)),
            pending_build: Mutex::new(None),
            build_error: Mutex::new(None),
            update_strategy,
            semantic_indexing,
            watcher_starter,
        })
    }

    fn new_transient_with_strategy(
        root: PathBuf,
        update_strategy: UpdateStrategy,
        semantic_indexing: bool,
    ) -> Result<Self, String> {
        Self::new_transient_with_strategy_and_watcher_starter(
            root,
            update_strategy,
            semantic_indexing,
            production_watcher_starter(),
        )
    }

    fn new_transient_with_strategy_and_watcher_starter(
        root: PathBuf,
        update_strategy: UpdateStrategy,
        semantic_indexing: bool,
        watcher_starter: WatcherStarter,
    ) -> Result<Self, String> {
        let (project, workspace) = build_transient_workspace(root)?;
        let root = project.root().to_path_buf();
        let session = assemble_session(
            project,
            workspace,
            update_strategy,
            semantic_indexing,
            &watcher_starter,
        )?;
        Ok(Self {
            root: RwLock::new(root),
            session: RwLock::new(Some(session)),
            pending_build: Mutex::new(None),
            build_error: Mutex::new(None),
            update_strategy,
            semantic_indexing,
            watcher_starter,
        })
    }

    fn new_lazy_with_strategy(
        root: PathBuf,
        update_strategy: UpdateStrategy,
        semantic_indexing: bool,
    ) -> Result<Self, String> {
        Self::new_lazy_with_strategy_and_watcher_starter(
            root,
            update_strategy,
            semantic_indexing,
            production_watcher_starter(),
        )
    }

    fn new_lazy_with_strategy_and_watcher_starter(
        root: PathBuf,
        update_strategy: UpdateStrategy,
        semantic_indexing: bool,
        watcher_starter: WatcherStarter,
    ) -> Result<Self, String> {
        let canonical = root
            .canonicalize()
            .map_err(|err| format!("Failed to resolve project root {}: {err}", root.display()))?;
        if !canonical.is_dir() {
            return Err(format!(
                "project root is not a directory: {}",
                canonical.display()
            ));
        }
        Ok(Self {
            root: RwLock::new(canonical),
            session: RwLock::new(None),
            pending_build: Mutex::new(None),
            build_error: Mutex::new(None),
            update_strategy,
            semantic_indexing,
            watcher_starter,
        })
    }

    /// Construct the searchtools service without blocking on the initial
    /// workspace build. The expensive declaration index is built on a
    /// background thread, so the MCP `initialize` handshake can be answered
    /// immediately while indexing proceeds. The first tool call blocks (via
    /// `ensure_ready`) only for whatever build time has not already elapsed.
    ///
    /// Used by the long-lived stdio server. Only a cheap, O(1) root check
    /// (canonicalize + is-dir) runs synchronously so an invalid `--root` still
    /// fails fast. Everything that touches the tree -- file discovery
    /// (`FilesystemProject::new` -> `detect_languages`), parsing, and the file
    /// watcher -- is deferred to the build thread, so the MCP `initialize`
    /// handshake is answered instantly even when the workspace is enormous or on
    /// a slow filesystem (a tree of thousands of repo clones, a WSL `/mnt/c`
    /// mount, etc.). Without this, the discovery walk alone could exceed an MCP
    /// client's startup timeout.
    pub fn new_deferred(root: PathBuf) -> Result<Self, String> {
        Self::new_deferred_with_watcher_starter(root, production_watcher_starter())
    }

    fn new_deferred_with_watcher_starter(
        root: PathBuf,
        watcher_starter: WatcherStarter,
    ) -> Result<Self, String> {
        let update_strategy = UpdateStrategy::WatchFiles;
        let semantic_indexing = semantic_indexing_enabled();
        let canonical = root
            .canonicalize()
            .map_err(|err| format!("Failed to resolve project root {}: {err}", root.display()))?;
        if !canonical.is_dir() {
            return Err(format!(
                "project root is not a directory: {}",
                canonical.display()
            ));
        }
        let handle = std::thread::Builder::new()
            .name("bifrost-index-build".to_string())
            .spawn({
                let canonical = canonical.clone();
                let watcher_starter = Arc::clone(&watcher_starter);
                move || -> Result<WorkspaceSession, String> {
                    let project: Arc<dyn Project> = Arc::new(
                        FilesystemProject::new(canonical)
                            .map_err(|err| format!("Failed to initialize project root: {err}"))?,
                    );
                    let workspace = WorkspaceAnalyzer::build_persisted(
                        Arc::clone(&project),
                        AnalyzerConfig::default(),
                    )
                    .map_err(|error| format!("Failed to build persisted workspace: {error}"))?;
                    assemble_session(
                        project,
                        workspace,
                        update_strategy,
                        semantic_indexing,
                        &watcher_starter,
                    )
                }
            })
            .map_err(|err| format!("Failed to spawn index build thread: {err}"))?;
        Ok(Self {
            root: RwLock::new(canonical),
            session: RwLock::new(None),
            pending_build: Mutex::new(Some(handle)),
            build_error: Mutex::new(None),
            update_strategy,
            semantic_indexing,
            watcher_starter,
        })
    }

    /// Block until the deferred initial build (if any) has completed and its
    /// session is installed. A no-op for synchronously-built services and after
    /// the first call. Safe under concurrency: the first caller joins the build
    /// and installs the session while holding `pending_build`; later callers
    /// wait on that mutex and then observe the installed session.
    fn ensure_ready(&self) -> Result<(), SearchToolsServiceError> {
        let mut pending = self
            .pending_build
            .lock()
            .map_err(|_| SearchToolsServiceError::internal("index build lock poisoned"))?;
        if let Some(handle) = pending.take() {
            let built = handle
                .join()
                .map_err(|_| SearchToolsServiceError::internal("index build thread panicked"))?;
            match built {
                Ok(session) => {
                    let mut guard = self.session.write().map_err(|_| {
                        SearchToolsServiceError::internal("SearchToolsService lock poisoned")
                    })?;
                    *guard = Some(session);
                }
                Err(err) => {
                    *self.build_error.lock().map_err(|_| {
                        SearchToolsServiceError::internal("index build lock poisoned")
                    })? = Some(err.clone());
                    return Err(SearchToolsServiceError::internal(err));
                }
            }
        }
        if let Some(err) = self
            .build_error
            .lock()
            .map_err(|_| SearchToolsServiceError::internal("index build lock poisoned"))?
            .clone()
        {
            return Err(SearchToolsServiceError::internal(err));
        }
        if self
            .session
            .read()
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))?
            .is_none()
        {
            let built =
                build_persisted_workspace(self.service_root()?).and_then(|(project, workspace)| {
                    assemble_session(
                        project,
                        workspace,
                        self.update_strategy,
                        self.semantic_indexing,
                        &self.watcher_starter,
                    )
                });
            let session = match built {
                Ok(session) => session,
                Err(err) => {
                    *self.build_error.lock().map_err(|_| {
                        SearchToolsServiceError::internal("index build lock poisoned")
                    })? = Some(err.clone());
                    return Err(SearchToolsServiceError::internal(err));
                }
            };
            let mut guard = self.session.write().map_err(|_| {
                SearchToolsServiceError::internal("SearchToolsService lock poisoned")
            })?;
            if guard.is_none() {
                *guard = Some(session);
            }
        }
        drop(pending);
        Ok(())
    }

    pub fn close(&self) -> Result<(), SearchToolsServiceError> {
        let mut guard = self.write_session()?;
        let session = guard.take();
        drop(guard);
        if let Some(session) = session {
            session.close_semantic();
        }
        Ok(())
    }

    /// Run a forced git-reachability GC on the semantic index and block until it
    /// completes. Off the retrieval path (does not affect `wait_ready`), intended
    /// for occasional maintenance. The session lock is released before blocking.
    pub fn request_semantic_gc(&self) -> Result<(), SearchToolsServiceError> {
        #[cfg(not(feature = "nlp"))]
        {
            Err(SearchToolsServiceError::internal(
                "semantic index requires the nlp feature",
            ))
        }
        #[cfg(feature = "nlp")]
        {
            self.ensure_ready()?;
            let indexer = {
                let guard = self.session.read().map_err(|_| {
                    SearchToolsServiceError::internal("workspace session lock poisoned")
                })?;
                let session = guard.as_ref().ok_or_else(Self::closed_error)?;
                match &session.semantic {
                    Some(indexer) => indexer.clone(),
                    None => {
                        return Err(SearchToolsServiceError::invalid_params(
                            "semantic index is disabled for this session",
                        ));
                    }
                }
            };
            indexer
                .run_gc_blocking()
                .map_err(SearchToolsServiceError::internal)
        }
    }

    fn handle_refresh(&self, arguments: Value) -> Result<ToolOutput, SearchToolsServiceError> {
        let _params = serde_json::from_value::<RefreshParams>(arguments).map_err(|err| {
            SearchToolsServiceError::invalid_params(format!("Invalid tool arguments: {err}"))
        })?;
        let mut guard = self.write_session()?;
        let session = guard.as_mut().ok_or_else(Self::closed_error)?;
        let next = session.snapshot.update_all();
        session.snapshot = Arc::new(next);
        #[cfg(feature = "nlp")]
        if let Some(semantic) = &session.semantic {
            semantic.request_full_build(session.snapshot.clone());
        }
        Self::structured_only(refresh_result(session.snapshot.analyzer()))
    }

    /// Incrementally re-analyze exactly the given project-relative paths, reusing the
    /// existing analysis for every other file. Unlike `refresh` (which rebuilds the
    /// whole project), this is O(changed files) and is how a caller that knows what
    /// changed (e.g. between two checked-out revisions) drives updates cheaply.
    fn handle_update_paths(&self, arguments: Value) -> Result<ToolOutput, SearchToolsServiceError> {
        let paths: Vec<String> = arguments
            .get("paths")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let mut guard = self.write_session()?;
        let session = guard.as_mut().ok_or_else(Self::closed_error)?;
        let root = session.snapshot.analyzer().project().root().to_path_buf();
        let changed: BTreeSet<ProjectFile> = paths
            .iter()
            .map(|rel| ProjectFile::new(root.clone(), rel.as_str()))
            .collect();
        if !changed.is_empty() {
            let next = session.snapshot.update(&changed);
            session.snapshot = Arc::new(next);
        }
        Self::structured_only(refresh_result(session.snapshot.analyzer()))
    }

    fn handle_activate_workspace(
        &self,
        arguments: Value,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        let params =
            serde_json::from_value::<ActivateWorkspaceParams>(arguments).map_err(|err| {
                SearchToolsServiceError::invalid_params(format!("Invalid tool arguments: {err}"))
            })?;

        let raw = PathBuf::from(&params.workspace_path);
        if !raw.is_absolute() {
            return Err(SearchToolsServiceError::invalid_params(format!(
                "workspace_path must be absolute, got: {}",
                params.workspace_path
            )));
        }

        let resolved = resolve_workspace_root(&raw).map_err(|err| {
            SearchToolsServiceError::invalid_params(format!(
                "Failed to resolve workspace path {}: {err}",
                raw.display()
            ))
        })?;

        let mut guard = self.write_session()?;
        let session = guard.as_mut().ok_or_else(Self::closed_error)?;

        if resolved == session.snapshot.analyzer().project().root() {
            return active_workspace_result(&resolved);
        }

        // Fully assemble the replacement before mutating either active field so
        // analyzer-store or watcher startup failure leaves the old session usable.
        let (new_project, new_workspace) =
            build_persisted_workspace(resolved.clone()).map_err(|err| {
                SearchToolsServiceError::internal(format!(
                    "Failed to activate workspace {}: {err}",
                    resolved.display()
                ))
            })?;
        #[cfg(feature = "nlp")]
        let semantic_indexing = session.semantic.is_some();
        #[cfg(not(feature = "nlp"))]
        let semantic_indexing = false;
        let new_session = assemble_session(
            new_project,
            new_workspace,
            self.update_strategy,
            semantic_indexing,
            &self.watcher_starter,
        )
        .map_err(|err| {
            SearchToolsServiceError::internal(format!(
                "Failed to activate workspace {}: {err}",
                resolved.display()
            ))
        })?;
        let mut root = self
            .root
            .write()
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))?;
        let old_session = std::mem::replace(session, new_session);
        *root = resolved.clone();
        drop(guard);
        drop(root);
        old_session.close_semantic();

        active_workspace_result(&resolved)
    }

    fn handle_get_active_workspace(
        &self,
        arguments: Value,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        let _params =
            serde_json::from_value::<GetActiveWorkspaceParams>(arguments).map_err(|err| {
                SearchToolsServiceError::invalid_params(format!("Invalid tool arguments: {err}"))
            })?;
        let guard = self.read_session()?;
        let session = guard.as_ref().ok_or_else(Self::closed_error)?;
        active_workspace_result(session.snapshot.analyzer().project().root())
    }

    fn snapshot_for_query(&self) -> Result<WorkspaceQueryScope, SearchToolsServiceError> {
        let mut guard = self.write_session()?;
        let session = guard.as_mut().ok_or_else(Self::closed_error)?;
        match self.update_strategy {
            UpdateStrategy::WatchFiles => Self::apply_watcher_delta(session),
            UpdateStrategy::Manual => {}
        }
        Ok(WorkspaceQueryScope::new(
            Arc::clone(&session.snapshot),
            Arc::clone(&session.document_root),
        ))
    }

    fn handle_get_symbol_sources(
        &self,
        arguments: Value,
        render_options: RenderOptions,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        let params = serde_json::from_value::<SymbolLookupParams>(arguments).map_err(|err| {
            SearchToolsServiceError::invalid_params(format!("Invalid tool arguments: {err}"))
        })?;
        let initial_snapshot = self.snapshot_for_query()?;
        let mut result = get_symbol_sources(initial_snapshot.analyzer(), params.clone());
        if self.update_strategy == UpdateStrategy::WatchFiles {
            let candidate_files =
                symbol_source_candidate_files(initial_snapshot.analyzer(), &result);

            let final_snapshot = {
                let mut guard = self.write_session()?;
                let session = guard.as_mut().ok_or_else(Self::closed_error)?;
                Self::apply_watcher_delta(session);
                let analyzer = session.snapshot.analyzer();
                let stale_files = stale_symbol_source_files(analyzer, candidate_files)?;
                Self::apply_changed_files(session, stale_files);
                Arc::clone(&session.snapshot)
            };

            if !Arc::ptr_eq(initial_snapshot.arc(), &final_snapshot) {
                let final_snapshot = initial_snapshot.scope_snapshot(final_snapshot);
                result = get_symbol_sources(final_snapshot.analyzer(), params);
                let output = Self::symbol_sources_output(result, render_options);
                return final_snapshot.finish("get_symbol_sources", output);
            }
        }
        let output = Self::symbol_sources_output(result, render_options);
        initial_snapshot.finish("get_symbol_sources", output)
    }

    fn symbol_sources_output(
        result: SymbolSourcesResult,
        render_options: RenderOptions,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        let rendered_text = result.render_text(render_options);
        let structured = serde_json::to_value(result).map_err(|err| {
            SearchToolsServiceError::internal(format!("Failed to serialize tool result: {err}"))
        })?;
        Ok(ToolOutput::Structured {
            structured,
            rendered_text: Some(rendered_text),
        })
    }

    #[cfg(feature = "nlp")]
    fn semantic_snapshot_for_query(
        &self,
    ) -> Result<(WorkspaceQueryScope, Option<Arc<SemanticIndexer>>), SearchToolsServiceError> {
        let mut guard = self.write_session()?;
        let session = guard.as_mut().ok_or_else(Self::closed_error)?;
        match self.update_strategy {
            UpdateStrategy::WatchFiles => Self::apply_watcher_delta(session),
            UpdateStrategy::Manual => {}
        }
        Ok((
            WorkspaceQueryScope::new(
                Arc::clone(&session.snapshot),
                Arc::clone(&session.document_root),
            ),
            session.semantic.clone(),
        ))
    }

    fn apply_watcher_delta(session: &mut WorkspaceSession) {
        let _scope = profiling::scope("SearchToolsService::apply_watcher_delta");
        let watcher = match &session.watcher {
            SessionWatcher::Disabled => return,
            SessionWatcher::Active(watcher) => watcher,
        };

        let delta = {
            let _scope = profiling::scope("SearchToolsService::take_changed_files");
            watcher.take_changed_files()
        };
        if profiling::enabled() {
            profiling::note(format!(
                "watcher_delta files={} full_refresh={}",
                delta.files.len(),
                delta.requires_full_refresh
            ));
        }
        if delta.requires_full_refresh {
            session.snapshot = Arc::new({
                let _scope = profiling::scope("SearchToolsService::snapshot_update_all");
                session.snapshot.update_all()
            });
            #[cfg(feature = "nlp")]
            if let Some(semantic) = &session.semantic {
                semantic.request_full_build(session.snapshot.clone());
            }
            return;
        }

        if delta.files.is_empty() {
            return;
        }

        let changed_files: BTreeSet<ProjectFile> = delta.files.into_iter().collect();
        Self::apply_changed_files(session, changed_files);
    }

    fn apply_changed_files(session: &mut WorkspaceSession, changed_files: BTreeSet<ProjectFile>) {
        if changed_files.is_empty() {
            return;
        }
        if profiling::enabled() {
            profiling::note(format!("snapshot_changed_files={}", changed_files.len()));
        }
        session.snapshot = Arc::new({
            let _scope = profiling::scope("SearchToolsService::snapshot_update");
            session.snapshot.update(&changed_files)
        });
        #[cfg(feature = "nlp")]
        if let Some(semantic) = &session.semantic {
            semantic.request_update(session.snapshot.clone(), changed_files);
        }
    }

    fn decode_and_run<P, R>(
        workspace: &WorkspaceAnalyzer,
        arguments: Value,
        handler: impl FnOnce(&WorkspaceAnalyzer, P) -> R,
    ) -> Result<ToolOutput, SearchToolsServiceError>
    where
        P: serde::de::DeserializeOwned,
        R: Serialize,
    {
        let params = serde_json::from_value::<P>(arguments).map_err(|err| {
            SearchToolsServiceError::invalid_params(format!("Invalid tool arguments: {err}"))
        })?;
        let result = handler(workspace, params);
        match serde_json::to_value(result).map_err(|err| {
            SearchToolsServiceError::internal(format!("Failed to serialize tool result: {err}"))
        })? {
            Value::String(text) => Ok(ToolOutput::Text(text)),
            structured => Ok(ToolOutput::Structured {
                structured,
                rendered_text: None,
            }),
        }
    }

    fn validate_scan_usages_by_reference_arguments(
        arguments: &Value,
    ) -> Result<(), SearchToolsServiceError> {
        let valid_symbols = arguments
            .get("symbols")
            .and_then(Value::as_array)
            .is_some_and(|symbols| {
                !symbols.is_empty()
                    && symbols.iter().all(|symbol| {
                        symbol
                            .as_str()
                            .is_some_and(|value| !value.trim().is_empty())
                    })
            });

        if !valid_symbols {
            return Err(SearchToolsServiceError::invalid_params(
                "scan_usages_by_reference requires a non-empty `symbols` array of non-blank strings",
            ));
        }
        Self::validate_scan_usages_scope_arguments(arguments, "scan_usages_by_reference")
    }

    fn validate_scan_usages_by_location_arguments(
        arguments: &Value,
    ) -> Result<(), SearchToolsServiceError> {
        let targets = arguments
            .get("targets")
            .and_then(Value::as_array)
            .filter(|targets| !targets.is_empty())
            .ok_or_else(|| {
                SearchToolsServiceError::invalid_params(
                    "scan_usages_by_location requires a non-empty `targets` array",
                )
            })?;
        for (index, target) in targets.iter().enumerate() {
            let valid = target.as_object().is_some_and(|target| {
                target
                    .get("path")
                    .and_then(Value::as_str)
                    .is_some_and(|path| !path.trim().is_empty())
                    && target
                        .get("line")
                        .and_then(Value::as_u64)
                        .is_some_and(|line| line > 0)
                    && target
                        .get("column")
                        .is_none_or(|column| column.as_u64().is_some_and(|column| column > 0))
                    && target.get("symbol").is_none_or(|symbol| {
                        symbol
                            .as_str()
                            .is_some_and(|symbol| !symbol.trim().is_empty())
                    })
            });
            if !valid {
                return Err(SearchToolsServiceError::invalid_params(format!(
                    "scan_usages_by_location target {} requires a non-blank `path`, a positive 1-based `line`, an optional positive 1-based `column`, and an optional non-blank `symbol`",
                    index + 1
                )));
            }
        }
        Self::validate_scan_usages_scope_arguments(arguments, "scan_usages_by_location")
    }

    fn validate_scan_usages_scope_arguments(
        arguments: &Value,
        tool_name: &str,
    ) -> Result<(), SearchToolsServiceError> {
        if arguments
            .get("include_tests")
            .is_some_and(|value| !value.is_boolean())
        {
            return Err(SearchToolsServiceError::invalid_params(format!(
                "{tool_name} requires `include_tests` to be a boolean"
            )));
        }
        if arguments.get("paths").is_some_and(|paths| {
            !paths
                .as_array()
                .is_some_and(|paths| paths.iter().all(Value::is_string))
        }) {
            return Err(SearchToolsServiceError::invalid_params(format!(
                "{tool_name} requires `paths` to be an array of strings"
            )));
        }
        Ok(())
    }

    fn decode_render_and_run<P, R>(
        workspace: &WorkspaceAnalyzer,
        arguments: Value,
        render_options: RenderOptions,
        handler: impl FnOnce(&WorkspaceAnalyzer, P) -> R,
    ) -> Result<ToolOutput, SearchToolsServiceError>
    where
        P: serde::de::DeserializeOwned,
        R: Serialize + RenderText,
    {
        let params = serde_json::from_value::<P>(arguments).map_err(|err| {
            SearchToolsServiceError::invalid_params(format!("Invalid tool arguments: {err}"))
        })?;
        let result = handler(workspace, params);
        let rendered_text = result.render_text(render_options);
        let structured = serde_json::to_value(result).map_err(|err| {
            SearchToolsServiceError::internal(format!("Failed to serialize tool result: {err}"))
        })?;
        Ok(ToolOutput::Structured {
            structured,
            rendered_text: Some(rendered_text),
        })
    }

    fn decode_render_and_try_run<P, R>(
        workspace: &WorkspaceAnalyzer,
        arguments: Value,
        render_options: RenderOptions,
        handler: impl FnOnce(&WorkspaceAnalyzer, P) -> Result<R, String>,
    ) -> Result<ToolOutput, SearchToolsServiceError>
    where
        P: serde::de::DeserializeOwned,
        R: Serialize + RenderText,
    {
        let params = serde_json::from_value::<P>(arguments).map_err(|err| {
            SearchToolsServiceError::invalid_params(format!("Invalid tool arguments: {err}"))
        })?;
        let result = handler(workspace, params).map_err(SearchToolsServiceError::invalid_params)?;
        let rendered_text = result.render_text(render_options);
        let structured = serde_json::to_value(result).map_err(|err| {
            SearchToolsServiceError::internal(format!("Failed to serialize tool result: {err}"))
        })?;
        Ok(ToolOutput::Structured {
            structured,
            rendered_text: Some(rendered_text),
        })
    }

    #[cfg(feature = "nlp")]
    fn handle_semantic_search(
        &self,
        arguments: Value,
        render_options: RenderOptions,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        let (snapshot, semantic) = self.semantic_snapshot_for_query()?;
        let result = match semantic {
            Some(indexer) => Self::decode_render_and_try_run(
                &snapshot,
                arguments,
                render_options,
                move |workspace, params| semantic_search(workspace, &indexer, params),
            ),
            None => Err(SearchToolsServiceError::invalid_params(
                "semantic_search is disabled for this session (set BIFROST_SEMANTIC_INDEX=auto to enable it)",
            )),
        };
        snapshot.finish("semantic_search", result)
    }

    #[cfg(feature = "nlp")]
    fn handle_semantic_search_status(
        &self,
        arguments: Value,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        let _params = serde_json::from_value::<RefreshParams>(arguments).map_err(|err| {
            SearchToolsServiceError::invalid_params(format!("Invalid tool arguments: {err}"))
        })?;
        let (snapshot, semantic) = self.semantic_snapshot_for_query()?;
        let result = match semantic {
            Some(indexer) => Self::structured_only(indexer.status(&snapshot)),
            None => Err(SearchToolsServiceError::invalid_params(
                "semantic_search_status is disabled for this session (set BIFROST_SEMANTIC_INDEX=auto to enable it)",
            )),
        };
        snapshot.finish("semantic_search_status", result)
    }

    #[cfg(not(feature = "nlp"))]
    fn handle_semantic_search(
        &self,
        _arguments: Value,
        _render_options: RenderOptions,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        Err(SearchToolsServiceError::invalid_params(
            "semantic_search is not available in this build (nlp feature disabled)",
        ))
    }

    #[cfg(not(feature = "nlp"))]
    fn handle_semantic_search_status(
        &self,
        _arguments: Value,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        Err(SearchToolsServiceError::invalid_params(
            "semantic_search_status is not available in this build (nlp feature disabled)",
        ))
    }

    fn structured_only<R: Serialize>(result: R) -> Result<ToolOutput, SearchToolsServiceError> {
        let structured = serde_json::to_value(result).map_err(|err| {
            SearchToolsServiceError::internal(format!("Failed to serialize tool result: {err}"))
        })?;
        Ok(ToolOutput::Structured {
            structured,
            rendered_text: None,
        })
    }

    fn read_session(
        &self,
    ) -> Result<std::sync::RwLockReadGuard<'_, Option<WorkspaceSession>>, SearchToolsServiceError>
    {
        self.ensure_ready()?;
        self.session
            .read()
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))
    }

    fn service_root(&self) -> Result<PathBuf, SearchToolsServiceError> {
        self.root
            .read()
            .map(|root| root.clone())
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))
    }

    fn normalize_arguments_for_current_workspace(
        &self,
        name: &str,
        arguments: Value,
    ) -> Result<Value, SearchToolsServiceError> {
        let root = {
            let guard = self.read_session()?;
            let session = guard.as_ref().ok_or_else(Self::closed_error)?;
            session.snapshot.analyzer().project().root().to_path_buf()
        };
        crate::tool_arguments::normalize_tool_arguments(name, arguments, &root)
            .map_err(SearchToolsServiceError::invalid_params)
    }

    fn write_session(
        &self,
    ) -> Result<std::sync::RwLockWriteGuard<'_, Option<WorkspaceSession>>, SearchToolsServiceError>
    {
        self.ensure_ready()?;
        self.session
            .write()
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))
    }

    fn closed_error() -> SearchToolsServiceError {
        SearchToolsServiceError::internal("SearchToolsService is closed")
    }
}

impl Drop for SearchToolsService {
    fn drop(&mut self) {
        // If a deferred build is still in flight, join it so its session (and
        // any semantic indexer it started) is closed rather than detached.
        if let Ok(pending) = self.pending_build.get_mut()
            && let Some(handle) = pending.take()
            && let Ok(Ok(session)) = handle.join()
        {
            session.close_semantic();
            return;
        }
        let Ok(session) = self.session.get_mut() else {
            return;
        };
        if let Some(session) = session.take() {
            session.close_semantic();
        }
    }
}

fn strip_legacy_kind_filter(mut arguments: Value) -> Value {
    if let Some(object) = arguments.as_object_mut() {
        object.remove("kind_filter");
    }
    arguments
}

fn build_project(root: PathBuf) -> Result<Arc<dyn Project>, String> {
    Ok(Arc::new(FilesystemProject::new(root).map_err(|err| {
        format!("Failed to initialize project root: {err}")
    })?))
}

fn build_persisted_workspace(
    root: PathBuf,
) -> Result<(Arc<dyn Project>, WorkspaceAnalyzer), String> {
    let project = build_project(root)?;
    let workspace =
        WorkspaceAnalyzer::build_persisted(Arc::clone(&project), AnalyzerConfig::default())
            .map_err(|error| format!("Failed to build persisted workspace: {error}"))?;
    Ok((project, workspace))
}

fn build_transient_workspace(
    root: PathBuf,
) -> Result<(Arc<dyn Project>, WorkspaceAnalyzer), String> {
    let project = build_project(root)?;
    let workspace = WorkspaceAnalyzer::build(Arc::clone(&project), AnalyzerConfig::default());
    Ok((project, workspace))
}

/// Assemble a ready `WorkspaceSession` from a built project + analyzer: wrap the
/// analyzer in an `Arc`, start the file watcher (per `update_strategy`), and
/// start the semantic indexer when enabled. Shared by the synchronous and
/// deferred constructors so both produce identical sessions.
fn assemble_session(
    project: Arc<dyn Project>,
    workspace: WorkspaceAnalyzer,
    update_strategy: UpdateStrategy,
    semantic_indexing: bool,
    watcher_starter: &WatcherStarter,
) -> Result<WorkspaceSession, String> {
    let document_root = Arc::new(
        WorkspaceRoot::open(project.root())
            .map_err(|error| format!("Failed to open workspace document root: {error}"))?,
    );
    let watcher = start_session_watcher(Arc::clone(&project), update_strategy, watcher_starter)?;
    let snapshot = Arc::new(workspace);
    #[cfg(feature = "nlp")]
    let semantic = maybe_start_semantic(semantic_indexing, &snapshot);
    #[cfg(not(feature = "nlp"))]
    let _ = semantic_indexing;
    Ok(WorkspaceSession {
        snapshot,
        document_root,
        watcher,
        #[cfg(feature = "nlp")]
        semantic,
    })
}

fn start_session_watcher(
    project: Arc<dyn Project>,
    update_strategy: UpdateStrategy,
    watcher_starter: &WatcherStarter,
) -> Result<SessionWatcher, String> {
    match update_strategy {
        UpdateStrategy::WatchFiles => watcher_starter(Arc::clone(&project))
            .map(SessionWatcher::Active)
            .map_err(|error| {
                format!(
                    "Failed to start project watcher for {}: {error}",
                    project.root().display()
                )
            }),
        UpdateStrategy::Manual => Ok(SessionWatcher::Disabled),
    }
}

// Resolve an absolute path to the nearest enclosing git root, falling back to
// the canonicalized path itself when the directory is not inside a repository.
// This matches the activation contract used by brokk-core's MCP server.
fn resolve_workspace_root(path: &Path) -> Result<PathBuf, String> {
    let canonical = path
        .canonicalize()
        .map_err(|err| format!("{err} ({})", path.display()))?;
    if !canonical.is_dir() {
        return Err(format!("not a directory: {}", canonical.display()));
    }

    if let Ok(repo) = git2::Repository::discover(&canonical)
        && let Some(workdir) = repo.workdir()
        && let Ok(canon_workdir) = workdir.canonicalize()
    {
        return Ok(canon_workdir);
    }

    Ok(canonical)
}

fn active_workspace_result(root: &Path) -> Result<ToolOutput, SearchToolsServiceError> {
    let structured = serde_json::to_value(ActiveWorkspaceResult {
        workspace_path: root.display().to_string(),
    })
    .map_err(|err| {
        SearchToolsServiceError::internal(format!("Failed to serialize tool result: {err}"))
    })?;
    Ok(ToolOutput::Structured {
        structured,
        rendered_text: None,
    })
}

#[cfg(test)]
mod watcher_startup_tests {
    use super::*;
    use crate::path_normalization::NormalizePath;
    use serde_json::json;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    const WATCHER_FAILURE: &str = "injected watcher startup failure";

    fn workspace(file: &str, source: &str) -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join(file), source).unwrap();
        let root = temp.path().canonicalize().unwrap().normalize();
        (temp, root)
    }

    fn failing_starter(calls: Arc<AtomicUsize>) -> WatcherStarter {
        Arc::new(move |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(WATCHER_FAILURE.to_string())
        })
    }

    fn assert_watcher_error(error: &SearchToolsServiceError) {
        assert_eq!(error.code, SearchToolsServiceErrorCode::Internal);
        assert!(error.message.contains("Failed to start project watcher"));
        assert!(error.message.contains(WATCHER_FAILURE));
    }

    #[test]
    fn eager_watching_service_reports_watcher_startup_failure() {
        let (_temp, root) = workspace("Eager.java", "class Eager {}\n");
        let calls = Arc::new(AtomicUsize::new(0));

        let error = match SearchToolsService::new_with_strategy_and_watcher_starter(
            root,
            UpdateStrategy::WatchFiles,
            false,
            failing_starter(Arc::clone(&calls)),
        ) {
            Ok(_) => panic!("watching service unexpectedly ignored watcher failure"),
            Err(error) => error,
        };

        assert!(error.contains("Failed to start project watcher"));
        assert!(error.contains(WATCHER_FAILURE));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn lazy_watching_service_retains_watcher_startup_failure() {
        let (_temp, root) = workspace("Lazy.java", "class Lazy {}\n");
        let calls = Arc::new(AtomicUsize::new(0));
        let service = SearchToolsService::new_lazy_with_strategy_and_watcher_starter(
            root,
            UpdateStrategy::WatchFiles,
            false,
            failing_starter(Arc::clone(&calls)),
        )
        .unwrap();

        for _ in 0..2 {
            let error = service
                .call_tool_value("get_active_workspace", json!({}))
                .unwrap_err();
            assert_watcher_error(&error);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn concurrent_lazy_first_use_publishes_one_session_outcome() {
        const CALLERS: usize = 8;
        let (_temp, root) = workspace("Concurrent.java", "class Concurrent {}\n");
        let calls = Arc::new(AtomicUsize::new(0));
        let starter: WatcherStarter = {
            let calls = Arc::clone(&calls);
            Arc::new(move |project| {
                calls.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(50));
                ProjectChangeWatcher::start_polling_for_tests(project)
            })
        };
        let service = Arc::new(
            SearchToolsService::new_lazy_with_strategy_and_watcher_starter(
                root,
                UpdateStrategy::WatchFiles,
                false,
                starter,
            )
            .unwrap(),
        );
        let barrier = Arc::new(Barrier::new(CALLERS));

        let handles = (0..CALLERS)
            .map(|_| {
                let service = Arc::clone(&service);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    service.call_tool_value("get_active_workspace", json!({}))
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            assert!(handle.join().unwrap().is_ok());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn deferred_watching_service_retains_watcher_startup_failure() {
        let (_temp, root) = workspace("Deferred.java", "class Deferred {}\n");
        let calls = Arc::new(AtomicUsize::new(0));
        let service = SearchToolsService::new_deferred_with_watcher_starter(
            root,
            failing_starter(Arc::clone(&calls)),
        )
        .unwrap();

        for _ in 0..2 {
            let error = service
                .call_tool_value("get_active_workspace", json!({}))
                .unwrap_err();
            assert_watcher_error(&error);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn manual_service_does_not_invoke_watcher_starter() {
        let (_temp, root) = workspace("Manual.java", "class Manual {}\n");
        let calls = Arc::new(AtomicUsize::new(0));
        let service = SearchToolsService::new_transient_with_strategy_and_watcher_starter(
            root.clone(),
            UpdateStrategy::Manual,
            false,
            failing_starter(Arc::clone(&calls)),
        )
        .unwrap();

        let active = service
            .call_tool_value("get_active_workspace", json!({}))
            .unwrap();
        assert_eq!(active["workspace_path"], root.display().to_string());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn watcher_failure_during_activation_preserves_old_workspace() {
        let (_old_temp, old_root) = workspace("Old.java", "class Old {}\n");
        let (_new_temp, new_root) = workspace("New.java", "class New {}\n");
        let failed_root = new_root.clone();
        let starter: WatcherStarter = Arc::new(move |project| {
            if project.root() == failed_root {
                Err(WATCHER_FAILURE.to_string())
            } else {
                ProjectChangeWatcher::start_polling_for_tests(project)
            }
        });
        let service = SearchToolsService::new_transient_with_strategy_and_watcher_starter(
            old_root.clone(),
            UpdateStrategy::WatchFiles,
            false,
            starter,
        )
        .unwrap();

        let error = service
            .call_tool_value(
                "activate_workspace",
                json!({"workspace_path": new_root.display().to_string()}),
            )
            .unwrap_err();
        assert_watcher_error(&error);
        assert_eq!(service.active_workspace_root(), old_root);

        let active = service
            .call_tool_value("get_active_workspace", json!({}))
            .unwrap();
        assert_eq!(active["workspace_path"], old_root.display().to_string());
        let symbols = service
            .call_tool_value("list_symbols", json!({"file_patterns": ["Old.java"]}))
            .unwrap();
        assert_eq!(symbols["files"][0]["path"], "Old.java");
    }
}

#[cfg(test)]
mod analyzer_failure_boundary_tests {
    use super::*;
    use crate::analyzer::store::{StoreError, analyzer_db_path};
    use crate::analyzer::{Language, TestProject};
    use serde_json::json;
    use std::collections::BTreeSet;

    fn multi_language_service() -> (tempfile::TempDir, PathBuf, SearchToolsService) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("Model.java"), "class Model {}\n").unwrap();
        std::fs::write(root.join("helper.py"), "def helper():\n    return 1\n").unwrap();
        git2::Repository::init(&root).unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::with_languages(
            root.clone(),
            BTreeSet::from([Language::Java, Language::Python]),
        ));
        let service = SearchToolsService::new_manual_for_project(project).unwrap();
        (temp, root, service)
    }

    fn make_java_store_stale(root: &Path) {
        let connection = rusqlite::Connection::open(analyzer_db_path(root)).unwrap();
        assert_eq!(
            connection
                .execute(
                    "UPDATE analysis_epochs SET generation = generation + 1 WHERE lang = 'java'",
                    [],
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn multi_language_store_failure_replaces_false_empty_tool_success() {
        let (_temp, root, service) = multi_language_service();

        let healthy = service
            .call_tool_value("get_symbol_locations", json!({"symbols": ["Model"]}))
            .unwrap();
        assert_eq!(healthy["locations"][0]["symbol"], "Model");

        make_java_store_stale(&root);

        let error = service
            .call_tool_value("get_symbol_locations", json!({"symbols": ["Model"]}))
            .unwrap_err();
        assert_eq!(error.code, SearchToolsServiceErrorCode::Internal);
        assert!(error.message.contains("get_symbol_locations"));
        assert!(error.message.contains("querying definition candidates"));
        assert!(error.message.contains("stale analyzer generation"));

        let error = service
            .call_tool_value(
                "search_symbols",
                json!({"patterns": ["Model"], "include_tests": true, "limit": 5}),
            )
            .unwrap_err();
        assert_eq!(error.code, SearchToolsServiceErrorCode::Internal);
        assert!(error.message.contains("search_symbols"));
        assert!(error.message.contains("searching symbol candidates"));
        assert!(error.message.contains("stale analyzer generation"));
    }

    #[test]
    fn overlapping_query_scopes_do_not_share_store_failures() {
        let (_temp, root, service) = multi_language_service();

        let failing_scope = service.snapshot_for_query().unwrap();
        let unaffected_scope = service.snapshot_for_query().unwrap();

        make_java_store_stale(&root);

        let definitions: Vec<_> = failing_scope.analyzer().definitions("Model").collect();
        assert!(definitions.is_empty());
        assert!(failing_scope.context.store_error().is_some());
        assert!(
            unaffected_scope.context.store_error().is_none(),
            "a store failure must be attributed only to the request that observed it"
        );

        unaffected_scope
            .finish("unaffected_request", Ok(()))
            .unwrap();
        let error = failing_scope.finish("failing_request", Ok(())).unwrap_err();
        assert_eq!(error.code, SearchToolsServiceErrorCode::Internal);
        assert!(error.message.contains("failing_request"));
        assert!(error.message.contains("stale analyzer generation"));
    }

    #[test]
    fn failed_merged_index_build_is_not_published_to_other_requests() {
        let (_temp, root, service) = multi_language_service();
        make_java_store_stale(&root);

        let first_scope = service.snapshot_for_query().unwrap();
        first_scope.analyzer().global_usage_definition_index();
        assert!(first_scope.context.store_error().is_some());
        assert_eq!(
            first_scope
                .analyzer()
                .global_usage_definition_index_build_count_for_test(),
            1
        );
        assert!(
            first_scope
                .finish("first_failed_index_build", Ok(()))
                .is_err()
        );

        let retry_scope = service.snapshot_for_query().unwrap();
        retry_scope.analyzer().global_usage_definition_index();
        assert!(
            retry_scope.context.store_error().is_some(),
            "a failed request must not publish its incomplete merged index"
        );
        assert_eq!(
            retry_scope
                .analyzer()
                .global_usage_definition_index_build_count_for_test(),
            2
        );
    }

    #[test]
    fn query_finish_preserves_handler_error_over_recorded_store_failure() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("Model.java"), "class Model {}\n").unwrap();
        let (_project, workspace) = build_transient_workspace(root).unwrap();
        let document_root =
            Arc::new(WorkspaceRoot::open(workspace.analyzer().project().root()).unwrap());
        let scope = WorkspaceQueryScope::new(Arc::new(workspace), document_root);
        scope
            .context
            .record_store_error(StoreError::new("injected store failure"));

        let result: Result<(), SearchToolsServiceError> = Err(
            SearchToolsServiceError::invalid_params("original handler failure"),
        );
        let error = scope.finish("test_operation", result).unwrap_err();
        assert_eq!(error.code, SearchToolsServiceErrorCode::InvalidParams);
        assert_eq!(error.message, "original handler failure");
    }
}

#[cfg(test)]
mod source_generation_tests {
    use super::*;
    use serde_json::Value;
    use std::fs;

    const INITIAL_SOURCE: &str = r#"namespace MudBlazor;

public partial class MudDialogContainer
{
    protected string BackgroundClassname => "mud-overlay-dark";
}
"#;

    const UPDATED_SOURCE: &str = r#"namespace MudBlazor;

public partial class MudDialogContainer
{
    protected string BackgroundClassname => "mud-overlay-dark";

    private string GetBackgroundClass()
    {
        return BackgroundClassname;
    }
}
"#;

    const SHIFTED_SOURCE: &str = r#"namespace MudBlazor;

public partial class MudDialogContainer
{
    // This edit shifts the old BackgroundClassname byte range.
    protected string BackgroundClassname => "mud-overlay-light";
}
"#;

    fn write_project() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::write(root.join("MudDialogContainer.cs"), INITIAL_SOURCE).unwrap();
        (temp, root)
    }

    fn write_ambiguous_project() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::write(
            root.join("First.cs"),
            "namespace First; class Container { string Value => \"first\"; }\n",
        )
        .unwrap();
        fs::write(
            root.join("Second.cs"),
            "namespace Second; class Container { string Value => \"second\"; }\n",
        )
        .unwrap();
        (temp, root)
    }

    fn watching_service_without_watcher(root: PathBuf) -> SearchToolsService {
        let (project, workspace) = build_transient_workspace(root).unwrap();
        SearchToolsService {
            root: RwLock::new(project.root().to_path_buf()),
            session: RwLock::new(Some(WorkspaceSession {
                snapshot: Arc::new(workspace),
                document_root: Arc::new(WorkspaceRoot::open(project.root()).unwrap()),
                watcher: SessionWatcher::Disabled,
                #[cfg(feature = "nlp")]
                semantic: None,
            })),
            pending_build: Mutex::new(None),
            build_error: Mutex::new(None),
            update_strategy: UpdateStrategy::WatchFiles,
            semantic_indexing: false,
            watcher_starter: production_watcher_starter(),
        }
    }

    fn call_sources(service: &SearchToolsService, symbols: &[&str]) -> Value {
        let arguments = serde_json::json!({ "symbols": symbols });
        let payload = service
            .call_tool_json("get_symbol_sources", &arguments.to_string())
            .unwrap();
        serde_json::from_str(&payload).unwrap()
    }

    fn source_texts(value: &Value) -> Vec<&str> {
        value["sources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|source| source["text"].as_str().unwrap())
            .collect()
    }

    #[test]
    fn get_symbol_sources_refreshes_combined_stale_member_request() {
        let (_temp, root) = write_project();
        let service = watching_service_without_watcher(root.clone());
        fs::write(root.join("MudDialogContainer.cs"), UPDATED_SOURCE).unwrap();

        let value = call_sources(
            &service,
            &[
                "MudBlazor.MudDialogContainer.BackgroundClassname",
                "MudBlazor.MudDialogContainer.GetBackgroundClass",
            ],
        );

        assert_eq!(0, value["not_found"].as_array().unwrap().len(), "{value}");
        let texts = source_texts(&value);
        assert!(
            texts
                .iter()
                .any(|text| text.contains("protected string BackgroundClassname")),
            "{value}"
        );
        assert!(
            texts
                .iter()
                .any(|text| text.contains("private string GetBackgroundClass()")),
            "{value}"
        );
    }

    #[test]
    fn candidate_files_are_rechecked_after_the_source_changes() {
        let (_temp, root) = write_project();
        let (_project, workspace) = build_transient_workspace(root.clone()).unwrap();
        let result = get_symbol_sources(
            workspace.analyzer(),
            SymbolLookupParams {
                symbols: vec!["MudBlazor.MudDialogContainer.BackgroundClassname".to_string()],
            },
        );
        let candidates = symbol_source_candidate_files(workspace.analyzer(), &result);

        fs::write(root.join("MudDialogContainer.cs"), SHIFTED_SOURCE).unwrap();

        let stale = stale_symbol_source_files(workspace.analyzer(), candidates).unwrap();
        assert_eq!(
            BTreeSet::from([ProjectFile::new(
                root,
                PathBuf::from("MudDialogContainer.cs")
            )]),
            stale
        );
    }

    #[test]
    fn get_symbol_sources_refreshes_new_member_from_indexed_owner() {
        let (_temp, root) = write_project();
        let service = watching_service_without_watcher(root.clone());
        fs::write(root.join("MudDialogContainer.cs"), UPDATED_SOURCE).unwrap();

        let value = call_sources(
            &service,
            &["MudBlazor.MudDialogContainer.GetBackgroundClass"],
        );

        assert_eq!(0, value["not_found"].as_array().unwrap().len(), "{value}");
        assert!(
            source_texts(&value)
                .iter()
                .any(|text| text.contains("private string GetBackgroundClass()")),
            "{value}"
        );
    }

    #[test]
    fn stale_analyzer_and_manual_service_keep_generation_consistent_source() {
        let (_temp, root) = write_project();
        let (project, workspace) = build_transient_workspace(root.clone()).unwrap();
        let manual = SearchToolsService::new_manual_for_project(project).unwrap();
        fs::write(root.join("MudDialogContainer.cs"), SHIFTED_SOURCE).unwrap();

        let direct = get_symbol_sources(
            workspace.analyzer(),
            SymbolLookupParams {
                symbols: vec!["MudBlazor.MudDialogContainer.BackgroundClassname".to_string()],
            },
        );
        assert_eq!(1, direct.sources.len());
        assert_eq!(
            "protected string BackgroundClassname => \"mud-overlay-dark\";",
            direct.sources[0].text
        );

        let manual_value = call_sources(
            &manual,
            &[
                "MudBlazor.MudDialogContainer.BackgroundClassname",
                "MudBlazor.MudDialogContainer.GetBackgroundClass",
            ],
        );
        assert_eq!(1, manual_value["sources"].as_array().unwrap().len());
        assert_eq!(1, manual_value["not_found"].as_array().unwrap().len());
        assert_eq!(
            "protected string BackgroundClassname => \"mud-overlay-dark\";",
            manual_value["sources"][0]["text"]
        );
    }

    #[test]
    fn transient_source_read_errors_are_not_classified_as_deletion() {
        let (_temp, root) = write_project();
        let file = ProjectFile::new(root, PathBuf::from("MudDialogContainer.cs"));

        let transient = io::Error::new(io::ErrorKind::PermissionDenied, "temporary denial");
        assert!(classify_source_read(&file, Err(transient)).is_err());
        assert!(matches!(
            classify_source_read(&file, Err(io::Error::from(io::ErrorKind::NotFound))).unwrap(),
            ObservedSource::Missing
        ));
    }

    #[test]
    fn get_symbol_sources_refreshes_deleted_target_to_not_found() {
        let (_temp, root) = write_project();
        let service = watching_service_without_watcher(root.clone());
        fs::remove_file(root.join("MudDialogContainer.cs")).unwrap();

        let value = call_sources(
            &service,
            &["MudBlazor.MudDialogContainer.BackgroundClassname"],
        );

        assert_eq!(0, value["sources"].as_array().unwrap().len(), "{value}");
        assert_eq!(1, value["not_found"].as_array().unwrap().len(), "{value}");
    }

    #[test]
    fn get_symbol_sources_refreshes_stale_ambiguity_after_deletion() {
        let (_temp, root) = write_ambiguous_project();
        let service = watching_service_without_watcher(root.clone());
        let initial = call_sources(&service, &["Container.Value"]);
        assert_eq!(
            1,
            initial["ambiguous"].as_array().unwrap().len(),
            "{initial}"
        );

        fs::remove_file(root.join("First.cs")).unwrap();
        let refreshed = call_sources(&service, &["Container.Value"]);

        assert_eq!(
            0,
            refreshed["ambiguous"].as_array().unwrap().len(),
            "{refreshed}"
        );
        assert_eq!(
            0,
            refreshed["not_found"].as_array().unwrap().len(),
            "{refreshed}"
        );
        assert_eq!(
            1,
            refreshed["sources"].as_array().unwrap().len(),
            "{refreshed}"
        );
        assert!(
            refreshed["sources"][0]["text"]
                .as_str()
                .is_some_and(|text| text.contains("second")),
            "{refreshed}"
        );
    }
}

#[cfg(all(test, feature = "nlp"))]
mod tests {
    use super::*;
    use crate::nlp::engine::FakeHashEmbedder;
    use crate::nlp::indexer::FakeEngineProvider;
    use std::time::Duration;

    #[test]
    fn service_close_closes_semantic_indexer() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Thing.java"),
            "public class Thing { public String value() { return \"value\"; } }\n",
        )
        .unwrap();
        let (_project, workspace) = build_persisted_workspace(dir.path().to_path_buf()).unwrap();
        let snapshot = Arc::new(workspace);
        let indexer = SemanticIndexer::start_with_provider(
            dir.path().to_path_buf(),
            snapshot.clone(),
            FakeEngineProvider {
                embedder: Arc::new(FakeHashEmbedder::new(16)),
            },
        );
        let service = SearchToolsService {
            root: RwLock::new(dir.path().to_path_buf()),
            session: RwLock::new(Some(WorkspaceSession {
                snapshot,
                document_root: Arc::new(WorkspaceRoot::open(dir.path()).unwrap()),
                watcher: SessionWatcher::Disabled,
                semantic: Some(indexer.clone()),
            })),
            pending_build: Mutex::new(None),
            build_error: Mutex::new(None),
            update_strategy: UpdateStrategy::WatchFiles,
            semantic_indexing: true,
            watcher_starter: production_watcher_starter(),
        };

        service.close().unwrap();

        let err = indexer
            .wait_ready(Duration::from_secs(30))
            .expect_err("service close should close semantic indexer");
        assert_eq!(err, "semantic index closed");
    }

    #[test]
    fn missing_accelerator_disables_semantic_indexer_startup() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Thing.java"),
            "public class Thing { public String value() { return \"value\"; } }\n",
        )
        .unwrap();
        let (_project, workspace) = build_persisted_workspace(dir.path().to_path_buf()).unwrap();
        let snapshot = Arc::new(workspace);

        // No CUDA/Metal and no --force-semantic-cpu: the indexer must not start.
        let semantic = maybe_start_semantic_checked(true, &snapshot, || {
            Err("no CUDA or Metal accelerator detected".to_string())
        });

        assert!(semantic.is_none());
    }
}
