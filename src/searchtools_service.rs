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
    get_summaries_output::fit_get_summaries_output_to_budget,
    git_tools::{get_commit_diff, get_git_log, search_git_commit_messages},
    searchtools::{
        ActivateWorkspaceParams, ActiveWorkspaceResult, GetActiveWorkspaceParams,
        MostRelevantFilesParams, RefreshParams, SymbolLookupParams, SymbolSourcesResult,
        classify_test_files, get_definitions_by_location, get_definitions_by_reference,
        get_summaries, get_symbol_ancestors, get_symbol_locations, get_symbol_sources,
        get_type_by_location, list_symbols, most_relevant_files, refresh_result, rename_symbol,
        scan_usages_by_location, scan_usages_by_reference, search_symbols,
        symbol_source_candidate_files, usage_graph,
    },
    searchtools_render::{RenderOptions, RenderText},
    structured_data::{jq, xml_select, xml_skim},
};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io::{self, Read};
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
}

struct WorkspaceSession {
    snapshot: Arc<WorkspaceAnalyzer>,
    watcher: Option<ProjectChangeWatcher>,
    #[cfg(feature = "nlp")]
    semantic: Option<Arc<SemanticIndexer>>,
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

    /// Construct a manual, non-persistent, non-semantic service over an
    /// already-selected project. One-shot CLI subset workspaces use this to
    /// avoid whole-root watchers and analyzer DB reconciliation.
    pub fn new_manual_for_project(project: Arc<dyn Project>) -> Result<Self, String> {
        let root = project.root().to_path_buf();
        let workspace = WorkspaceAnalyzer::build(Arc::clone(&project), AnalyzerConfig::default());
        let session = assemble_session(project, workspace, UpdateStrategy::Manual, false);
        Ok(Self {
            root: RwLock::new(root),
            session: RwLock::new(Some(session)),
            pending_build: Mutex::new(None),
            build_error: Mutex::new(None),
            update_strategy: UpdateStrategy::Manual,
            semantic_indexing: false,
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
        let snapshot = self.snapshot_for_query()?;
        match name {
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
                arguments.clone(),
                render_options,
                |workspace, params| get_summaries(workspace.analyzer(), params),
            )
            .and_then(|output| {
                fit_get_summaries_output_to_budget(self, output, &arguments, render_options)
            }),
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
        }
    }

    pub fn query_code_result(
        &self,
        arguments: Value,
    ) -> Result<crate::analyzer::structural::CodeQueryResult, SearchToolsServiceError> {
        let arguments = self.normalize_arguments_for_current_workspace("query_code", arguments)?;
        let snapshot = self.snapshot_for_query()?;
        Self::query_code_result_for_snapshot(&snapshot, arguments)
    }

    fn query_code_result_for_snapshot(
        snapshot: &WorkspaceAnalyzer,
        arguments: Value,
    ) -> Result<crate::analyzer::structural::CodeQueryResult, SearchToolsServiceError> {
        let query = Self::decode_query_code_input(snapshot, arguments)?;
        Ok(crate::analyzer::structural::execute(
            snapshot.analyzer(),
            &query,
        ))
    }

    fn decode_query_code_input(
        snapshot: &WorkspaceAnalyzer,
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
        let path = root.join(query_file);
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
        let contents = Self::read_query_file(&path, query_file)?;
        let value = match extension {
            Some("rql") => crate::analyzer::structural::query::sexp::sexp_to_json(&contents)
                .map_err(|error| {
                    SearchToolsServiceError::invalid_params(format!(
                        "failed to parse RQL query file `{query_file}`: {error}"
                    ))
                }),
            Some("json") => serde_json::from_str::<Value>(&contents).map_err(|error| {
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

    fn read_query_file(path: &Path, query_file: &str) -> Result<String, SearchToolsServiceError> {
        let metadata = fs::metadata(path).map_err(|error| {
            SearchToolsServiceError::invalid_params(format!(
                "failed to read query file `{query_file}`: {error}"
            ))
        })?;
        if !metadata.is_file() {
            return Err(SearchToolsServiceError::invalid_params(format!(
                "query file `{query_file}` must be a regular file"
            )));
        }
        if metadata.len() > MAX_QUERY_FILE_BYTES {
            return Err(SearchToolsServiceError::invalid_params(format!(
                "query file `{query_file}` is too large: {} bytes exceeds {MAX_QUERY_FILE_BYTES}",
                metadata.len()
            )));
        }

        let file = fs::File::open(path).map_err(|error| {
            SearchToolsServiceError::invalid_params(format!(
                "failed to read query file `{query_file}`: {error}"
            ))
        })?;
        let mut contents = String::new();
        file.take(MAX_QUERY_FILE_BYTES + 1)
            .read_to_string(&mut contents)
            .map_err(|error| {
                SearchToolsServiceError::invalid_params(format!(
                    "failed to read query file `{query_file}`: {error}"
                ))
            })?;
        if contents.len() as u64 > MAX_QUERY_FILE_BYTES {
            return Err(SearchToolsServiceError::invalid_params(format!(
                "query file `{query_file}` is too large: more than {MAX_QUERY_FILE_BYTES} bytes"
            )));
        }

        Ok(contents)
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
        let (project, workspace) = build_persisted_workspace(root)?;
        let root = project.root().to_path_buf();
        let session = assemble_session(project, workspace, update_strategy, semantic_indexing);
        Ok(Self {
            root: RwLock::new(root),
            session: RwLock::new(Some(session)),
            pending_build: Mutex::new(None),
            build_error: Mutex::new(None),
            update_strategy,
            semantic_indexing,
        })
    }

    fn new_transient_with_strategy(
        root: PathBuf,
        update_strategy: UpdateStrategy,
        semantic_indexing: bool,
    ) -> Result<Self, String> {
        let (project, workspace) = build_transient_workspace(root)?;
        let root = project.root().to_path_buf();
        let session = assemble_session(project, workspace, update_strategy, semantic_indexing);
        Ok(Self {
            root: RwLock::new(root),
            session: RwLock::new(Some(session)),
            pending_build: Mutex::new(None),
            build_error: Mutex::new(None),
            update_strategy,
            semantic_indexing,
        })
    }

    fn new_lazy_with_strategy(
        root: PathBuf,
        update_strategy: UpdateStrategy,
        semantic_indexing: bool,
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
                move || -> Result<WorkspaceSession, String> {
                    let project: Arc<dyn Project> = Arc::new(
                        FilesystemProject::new(canonical)
                            .map_err(|err| format!("Failed to initialize project root: {err}"))?,
                    );
                    let workspace = WorkspaceAnalyzer::build_persisted(
                        Arc::clone(&project),
                        AnalyzerConfig::default(),
                    );
                    Ok(assemble_session(
                        project,
                        workspace,
                        update_strategy,
                        semantic_indexing,
                    ))
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
        drop(pending);
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
            let (project, workspace) = build_persisted_workspace(self.service_root()?)
                .map_err(SearchToolsServiceError::internal)?;
            let session = assemble_session(
                project,
                workspace,
                self.update_strategy,
                self.semantic_indexing,
            );
            let mut guard = self.session.write().map_err(|_| {
                SearchToolsServiceError::internal("SearchToolsService lock poisoned")
            })?;
            if guard.is_none() {
                *guard = Some(session);
            }
        }
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

        // Build the new project + workspace before mutating self so a failed
        // switch leaves the existing workspace queryable.
        let (new_project, new_workspace) =
            build_persisted_workspace(resolved.clone()).map_err(|err| {
                SearchToolsServiceError::invalid_params(format!(
                    "Failed to activate workspace {}: {err}",
                    resolved.display()
                ))
            })?;

        // Drop the old watcher first so its inotify/kqueue handle is released
        // before we start watching the same tree from the new root.
        let new_snapshot = Arc::new(new_workspace);
        #[cfg(feature = "nlp")]
        let semantic = maybe_start_semantic(session.semantic.is_some(), &new_snapshot);
        let old_session = std::mem::replace(
            session,
            WorkspaceSession {
                snapshot: new_snapshot,
                watcher: maybe_start_watcher(new_project, self.update_strategy),
                #[cfg(feature = "nlp")]
                semantic,
            },
        );
        drop(guard);
        old_session.close_semantic();
        *self
            .root
            .write()
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))? =
            resolved.clone();

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

    fn snapshot_for_query(&self) -> Result<Arc<WorkspaceAnalyzer>, SearchToolsServiceError> {
        let mut guard = self.write_session()?;
        let session = guard.as_mut().ok_or_else(Self::closed_error)?;
        match self.update_strategy {
            UpdateStrategy::WatchFiles => Self::apply_watcher_delta(session),
            UpdateStrategy::Manual => {}
        }
        Ok(Arc::clone(&session.snapshot))
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
            let observed_sources =
                symbol_source_candidate_files(initial_snapshot.analyzer(), &result)
                    .into_iter()
                    .map(|file| {
                        let current = initial_snapshot.analyzer().project().read_source(&file);
                        classify_source_read(&file, current).map(|source| (file, source))
                    })
                    .collect::<Result<Vec<_>, _>>()?;

            let final_snapshot = {
                let mut guard = self.write_session()?;
                let session = guard.as_mut().ok_or_else(Self::closed_error)?;
                Self::apply_watcher_delta(session);
                let analyzer = session.snapshot.analyzer();
                let stale_files = observed_sources
                    .iter()
                    .filter_map(|(file, observed)| {
                        let indexed = analyzer.indexed_source(file);
                        match (indexed, observed) {
                            (Some(indexed), ObservedSource::Present(current))
                                if indexed == current =>
                            {
                                None
                            }
                            (None, ObservedSource::Missing) => None,
                            _ => Some(file.clone()),
                        }
                    })
                    .collect();
                Self::apply_changed_files(session, stale_files);
                Arc::clone(&session.snapshot)
            };

            if !Arc::ptr_eq(&initial_snapshot, &final_snapshot) {
                result = get_symbol_sources(final_snapshot.analyzer(), params);
            }
        }
        Self::symbol_sources_output(result, render_options)
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
    ) -> Result<(Arc<WorkspaceAnalyzer>, Option<Arc<SemanticIndexer>>), SearchToolsServiceError>
    {
        let mut guard = self.write_session()?;
        let session = guard.as_mut().ok_or_else(Self::closed_error)?;
        match self.update_strategy {
            UpdateStrategy::WatchFiles => Self::apply_watcher_delta(session),
            UpdateStrategy::Manual => {}
        }
        Ok((Arc::clone(&session.snapshot), session.semantic.clone()))
    }

    fn apply_watcher_delta(session: &mut WorkspaceSession) {
        let Some(watcher) = session.watcher.as_ref() else {
            return;
        };

        let delta = watcher.take_changed_files();
        if delta.requires_full_refresh {
            session.snapshot = Arc::new(session.snapshot.update_all());
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
        session.snapshot = Arc::new(session.snapshot.update(&changed_files));
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
            });
            if !valid {
                return Err(SearchToolsServiceError::invalid_params(format!(
                    "scan_usages_by_location target {} requires a non-blank `path`, a positive 1-based `line`, and an optional positive 1-based `column`",
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
        let Some(indexer) = semantic else {
            return Err(SearchToolsServiceError::invalid_params(
                "semantic_search is disabled for this session (set BIFROST_SEMANTIC_INDEX=auto to enable it)",
            ));
        };
        Self::decode_render_and_try_run(
            &snapshot,
            arguments,
            render_options,
            move |workspace, params| semantic_search(workspace, &indexer, params),
        )
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
        let Some(indexer) = semantic else {
            return Err(SearchToolsServiceError::invalid_params(
                "semantic_search_status is disabled for this session (set BIFROST_SEMANTIC_INDEX=auto to enable it)",
            ));
        };
        Self::structured_only(indexer.status(&snapshot))
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
        WorkspaceAnalyzer::build_persisted(Arc::clone(&project), AnalyzerConfig::default());
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
) -> WorkspaceSession {
    let watcher = maybe_start_watcher(project, update_strategy);
    let snapshot = Arc::new(workspace);
    #[cfg(feature = "nlp")]
    let semantic = maybe_start_semantic(semantic_indexing, &snapshot);
    #[cfg(not(feature = "nlp"))]
    let _ = semantic_indexing;
    WorkspaceSession {
        snapshot,
        watcher,
        #[cfg(feature = "nlp")]
        semantic,
    }
}

fn maybe_start_watcher(
    project: Arc<dyn Project>,
    update_strategy: UpdateStrategy,
) -> Option<ProjectChangeWatcher> {
    match update_strategy {
        UpdateStrategy::WatchFiles => ProjectChangeWatcher::start(project).ok(),
        UpdateStrategy::Manual => None,
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
                watcher: None,
                #[cfg(feature = "nlp")]
                semantic: None,
            })),
            pending_build: Mutex::new(None),
            build_error: Mutex::new(None),
            update_strategy: UpdateStrategy::WatchFiles,
            semantic_indexing: false,
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
                watcher: None,
                semantic: Some(indexer.clone()),
            })),
            pending_build: Mutex::new(None),
            build_error: Mutex::new(None),
            update_strategy: UpdateStrategy::WatchFiles,
            semantic_indexing: true,
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
