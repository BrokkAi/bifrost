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
    file_tools::{
        find_filenames, find_files_containing, get_file_contents, list_files, search_file_contents,
    },
    get_summaries_output::fit_get_summaries_output_to_budget,
    git_tools::{get_commit_diff, get_git_log, search_git_commit_messages},
    searchtools::{
        ActivateWorkspaceParams, ActiveWorkspaceResult, GetActiveWorkspaceParams,
        MostRelevantFilesParams, RefreshParams, contains_tests, get_definition_by_location,
        get_definition_by_reference, get_summaries, get_symbol_ancestors, get_symbol_locations,
        get_symbol_sources, list_symbols, most_relevant_files, refresh_result, scan_usages,
        search_symbols, usage_graph,
    },
    searchtools_render::{RenderOptions, RenderText},
    structured_data::{jq, xml_select, xml_skim},
};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchToolsServiceErrorCode {
    InvalidParams,
    UnknownTool,
    Internal,
}

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
    session: RwLock<Option<WorkspaceSession>>,
    update_strategy: UpdateStrategy,
}

struct WorkspaceSession {
    snapshot: Arc<WorkspaceAnalyzer>,
    watcher: Option<ProjectChangeWatcher>,
    #[cfg(feature = "nlp")]
    semantic: Option<Arc<SemanticIndexer>>,
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
    maybe_start_semantic_checked(enabled, snapshot, onnx_runtime_available)
}

#[cfg(feature = "nlp")]
fn maybe_start_semantic_checked(
    enabled: bool,
    snapshot: &Arc<WorkspaceAnalyzer>,
    runtime_available: impl FnOnce() -> Result<(), String>,
) -> Option<Arc<SemanticIndexer>> {
    if !enabled {
        return None;
    }
    if let Err(err) = runtime_available() {
        eprintln!("bifrost semantic index disabled: ONNX Runtime unavailable: {err}");
        return None;
    }
    let root = snapshot.analyzer().project().root().to_path_buf();
    Some(SemanticIndexer::start(root, snapshot.clone()))
}

#[cfg(all(feature = "nlp", unix))]
fn onnx_runtime_available() -> Result<(), String> {
    use std::ffi::{CStr, CString};
    use std::os::raw::{c_char, c_int, c_void};
    use std::os::unix::ffi::OsStrExt;

    unsafe extern "C" {
        fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
        fn dlclose(handle: *mut c_void) -> c_int;
        fn dlerror() -> *const c_char;
    }

    const RTLD_LAZY: c_int = 1;

    let path = onnx_runtime_path();
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("invalid runtime path {}", path.display()))?;
    // Clear any stale loader error before this attempt.
    unsafe {
        let _ = dlerror();
    }
    let handle = unsafe { dlopen(c_path.as_ptr(), RTLD_LAZY) };
    if handle.is_null() {
        let error = unsafe {
            let ptr = dlerror();
            if ptr.is_null() {
                "unknown loader error".to_string()
            } else {
                CStr::from_ptr(ptr).to_string_lossy().into_owned()
            }
        };
        return Err(format!("{} ({error})", path.display()));
    }
    unsafe {
        let _ = dlclose(handle);
    }
    Ok(())
}

#[cfg(all(feature = "nlp", not(unix)))]
fn onnx_runtime_available() -> Result<(), String> {
    Ok(())
}

#[cfg(all(feature = "nlp", unix))]
fn onnx_runtime_path() -> PathBuf {
    let configured = std::env::var("ORT_DYLIB_PATH")
        .ok()
        .filter(|value| !value.is_empty());
    let path = PathBuf::from(configured.unwrap_or_else(default_onnx_runtime_name));
    if path.is_absolute() {
        return path;
    }
    let Ok(exe) = std::env::current_exe() else {
        return path;
    };
    let Some(exe_dir) = exe.parent() else {
        return path;
    };
    let relative_to_exe = exe_dir.join(&path);
    if relative_to_exe.exists() {
        relative_to_exe
    } else {
        path
    }
}

#[cfg(all(feature = "nlp", unix))]
fn default_onnx_runtime_name() -> String {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        "libonnxruntime.dylib".to_string()
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        "libonnxruntime.so".to_string()
    }
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
        Self::new_with_strategy(
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
        Self::new_with_strategy(root, UpdateStrategy::Manual, false)
    }

    /// Construct with no file watcher and no semantic indexer: the caller drives
    /// updates via the incremental `update_paths` tool. For batch consumers that
    /// re-use one session across many revisions of one worktree.
    pub fn new_for_python_manual(root: PathBuf) -> Result<Self, String> {
        Self::new_with_strategy(root, UpdateStrategy::Manual, false)
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
            "get_symbol_ancestors" => Self::decode_render_and_try_run(
                &snapshot,
                strip_legacy_kind_filter(arguments),
                render_options,
                |workspace, params| get_symbol_ancestors(workspace.analyzer(), params),
            ),
            "get_symbol_sources" => Self::decode_render_and_run(
                &snapshot,
                strip_legacy_kind_filter(arguments),
                render_options,
                |workspace, params| get_symbol_sources(workspace.analyzer(), params),
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
            "contains_tests" => Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                contains_tests(workspace.analyzer(), params)
            }),
            "most_relevant_files" => Self::decode_render_and_try_run(
                &snapshot,
                arguments,
                render_options,
                |workspace, params: MostRelevantFilesParams| {
                    most_relevant_files(workspace.analyzer(), params)
                },
            ),
            "scan_usages" => {
                Self::validate_scan_usages_arguments(&arguments)?;
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    scan_usages(workspace.analyzer(), params)
                })
            }
            "get_definition_by_location" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    get_definition_by_location(workspace.analyzer(), params)
                })
            }
            "get_definition_by_reference" => {
                Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                    get_definition_by_reference(workspace.analyzer(), params)
                })
            }
            "usage_graph" => Self::decode_and_run(&snapshot, arguments, |workspace, params| {
                usage_graph(workspace.analyzer(), params)
            }),
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

    pub fn active_workspace_root(&self) -> PathBuf {
        self.session
            .read()
            .ok()
            .and_then(|guard| {
                guard
                    .as_ref()
                    .map(|session| session.snapshot.analyzer().project().root().to_path_buf())
            })
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
        let (project, workspace) = build_workspace(root)?;
        let watcher = maybe_start_watcher(project, update_strategy);
        let snapshot = Arc::new(workspace);
        #[cfg(feature = "nlp")]
        let semantic = maybe_start_semantic(semantic_indexing, &snapshot);
        #[cfg(not(feature = "nlp"))]
        let _ = semantic_indexing;
        Ok(Self {
            session: RwLock::new(Some(WorkspaceSession {
                snapshot,
                watcher,
                #[cfg(feature = "nlp")]
                semantic,
            })),
            update_strategy,
        })
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
        let (new_project, new_workspace) = build_workspace(resolved.clone()).map_err(|err| {
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

    fn validate_scan_usages_arguments(arguments: &Value) -> Result<(), SearchToolsServiceError> {
        let has_symbols = arguments
            .get("symbols")
            .and_then(Value::as_array)
            .is_some_and(|symbols| {
                symbols
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|symbol| !symbol.trim().is_empty())
            });
        let has_targets = arguments
            .get("targets")
            .and_then(Value::as_array)
            .is_some_and(|targets| !targets.is_empty());

        if has_symbols || has_targets {
            Ok(())
        } else {
            Err(SearchToolsServiceError::invalid_params(
                "scan_usages requires a non-empty `symbols` array unless `targets` location selectors are supplied",
            ))
        }
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
        self.session
            .read()
            .map_err(|_| SearchToolsServiceError::internal("SearchToolsService lock poisoned"))
    }

    fn write_session(
        &self,
    ) -> Result<std::sync::RwLockWriteGuard<'_, Option<WorkspaceSession>>, SearchToolsServiceError>
    {
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

fn build_workspace(root: PathBuf) -> Result<(Arc<dyn Project>, WorkspaceAnalyzer), String> {
    let project: Arc<dyn Project> = Arc::new(
        FilesystemProject::new(root)
            .map_err(|err| format!("Failed to initialize project root: {err}"))?,
    );
    let workspace = WorkspaceAnalyzer::build(Arc::clone(&project), AnalyzerConfig::default());
    Ok((project, workspace))
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
        let (_project, workspace) = build_workspace(dir.path().to_path_buf()).unwrap();
        let snapshot = Arc::new(workspace);
        let indexer = SemanticIndexer::start_with_provider(
            dir.path().to_path_buf(),
            snapshot.clone(),
            FakeEngineProvider {
                embedder: Arc::new(FakeHashEmbedder::new(16)),
            },
        );
        let service = SearchToolsService {
            session: RwLock::new(Some(WorkspaceSession {
                snapshot,
                watcher: None,
                semantic: Some(indexer.clone()),
            })),
            update_strategy: UpdateStrategy::WatchFiles,
        };

        service.close().unwrap();

        let err = indexer
            .wait_ready(Duration::from_secs(30))
            .expect_err("service close should close semantic indexer");
        assert_eq!(err, "semantic index closed");
    }

    #[test]
    fn missing_onnx_runtime_disables_semantic_indexer_startup() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Thing.java"),
            "public class Thing { public String value() { return \"value\"; } }\n",
        )
        .unwrap();
        let (_project, workspace) = build_workspace(dir.path().to_path_buf()).unwrap();
        let snapshot = Arc::new(workspace);

        let semantic = maybe_start_semantic_checked(true, &snapshot, || {
            Err("libonnxruntime.so is not loadable".to_string())
        });

        assert!(semantic.is_none());
    }
}
