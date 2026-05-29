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
    git_tools::{get_commit_diff, get_git_log, search_git_commit_messages},
    searchtools::{
        ActivateWorkspaceParams, ActiveWorkspaceResult, GetActiveWorkspaceParams,
        MostRelevantFilesParams, RefreshParams, get_summaries, get_symbol_locations,
        get_symbol_sources, list_symbols, most_relevant_files, refresh_result, scan_usages,
        search_symbols,
    },
    searchtools_render::{RenderOptions, RenderText},
    structured_data::{jq, xml_select, xml_skim},
};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
}

pub struct SearchToolsService {
    workspace: WorkspaceAnalyzer,
    watcher: Option<ProjectChangeWatcher>,
    update_strategy: UpdateStrategy,
}

impl SearchToolsService {
    pub fn new(root: PathBuf) -> Result<Self, String> {
        Self::new_with_strategy(root, UpdateStrategy::WatchFiles)
    }

    pub fn new_for_python(root: PathBuf) -> Result<Self, String> {
        Self::new_with_strategy(root, UpdateStrategy::WatchFiles)
    }

    pub fn call_tool_json(
        &mut self,
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
        &mut self,
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
        &mut self,
        name: &str,
        arguments: Value,
    ) -> Result<Value, SearchToolsServiceError> {
        Ok(self
            .call_tool_output(name, arguments, RenderOptions::default())?
            .into_value())
    }

    pub fn call_tool_output(
        &mut self,
        name: &str,
        arguments: Value,
        render_options: RenderOptions,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        // Lifecycle tools bypass watcher delta application: refresh rebuilds
        // explicitly, activate replaces the whole workspace, and get is cheap.
        match name {
            "refresh" => return self.handle_refresh(arguments),
            "activate_workspace" => return self.handle_activate_workspace(arguments),
            "get_active_workspace" => return self.handle_get_active_workspace(arguments),
            _ => {}
        }

        self.prepare_for_call();
        match name {
            "search_symbols" => {
                self.decode_render_and_run(arguments, render_options, |workspace, params| {
                    search_symbols(workspace.analyzer(), params)
                })
            }
            "get_symbol_locations" => {
                self.decode_render_and_run(arguments, render_options, |workspace, params| {
                    get_symbol_locations(workspace.analyzer(), params)
                })
            }
            "get_symbol_sources" => {
                self.decode_render_and_run(arguments, render_options, |workspace, params| {
                    get_symbol_sources(workspace.analyzer(), params)
                })
            }
            "get_summaries" => {
                self.decode_render_and_run(arguments, render_options, |workspace, params| {
                    get_summaries(workspace.analyzer(), params)
                })
            }
            "list_symbols" => {
                self.decode_render_and_run(arguments, render_options, |workspace, params| {
                    list_symbols(workspace.analyzer(), params)
                })
            }
            "most_relevant_files" => self.decode_render_and_run(
                arguments,
                render_options,
                |workspace, params: MostRelevantFilesParams| {
                    most_relevant_files(workspace.analyzer(), params)
                },
            ),
            "scan_usages" => self.decode_and_run(arguments, |workspace, params| {
                scan_usages(workspace.analyzer(), params)
            }),
            "get_file_contents" => self.decode_and_run(arguments, |workspace, params| {
                get_file_contents(workspace.analyzer(), params)
            }),
            "find_filenames" => self.decode_and_run(arguments, |workspace, params| {
                find_filenames(workspace.analyzer(), params)
            }),
            "find_files_containing" => self.decode_and_run(arguments, |workspace, params| {
                find_files_containing(workspace.analyzer(), params)
            }),
            "search_file_contents" => self.decode_and_run(arguments, |workspace, params| {
                search_file_contents(workspace.analyzer(), params)
            }),
            "list_files" => self.decode_and_run(arguments, |workspace, params| {
                list_files(workspace.analyzer(), params)
            }),
            "search_git_commit_messages" => self.decode_and_run(arguments, |workspace, params| {
                search_git_commit_messages(workspace.analyzer(), params)
            }),
            "get_git_log" => self.decode_and_run(arguments, |workspace, params| {
                get_git_log(workspace.analyzer(), params)
            }),
            "get_commit_diff" => self.decode_and_run(arguments, |workspace, params| {
                get_commit_diff(workspace.analyzer(), params)
            }),
            "jq" => self.decode_and_run(arguments, |workspace, params| {
                jq(workspace.analyzer(), params)
            }),
            "xml_skim" => self.decode_and_run(arguments, |workspace, params| {
                xml_skim(workspace.analyzer(), params)
            }),
            "xml_select" => self.decode_and_run(arguments, |workspace, params| {
                xml_select(workspace.analyzer(), params)
            }),
            "compute_cyclomatic_complexity" => self
                .decode_and_run(arguments, |workspace, params| {
                    compute_cyclomatic_complexity(workspace.analyzer(), params)
                }),
            "compute_cognitive_complexity" => self
                .decode_and_run(arguments, |workspace, params| {
                    compute_cognitive_complexity(workspace.analyzer(), params)
                }),
            "report_comment_density_for_code_unit" => {
                self.decode_and_run(arguments, |workspace, params| {
                    report_comment_density_for_code_unit(workspace.analyzer(), params)
                })
            }
            "report_comment_density_for_files" => self
                .decode_and_run(arguments, |workspace, params| {
                    report_comment_density_for_files(workspace.analyzer(), params)
                }),
            "report_exception_handling_smells" => self
                .decode_and_run(arguments, |workspace, params| {
                    report_exception_handling_smells(workspace.analyzer(), params)
                }),
            "report_test_assertion_smells" => self
                .decode_and_run(arguments, |workspace, params| {
                    report_test_assertion_smells(workspace.analyzer(), params)
                }),
            "report_structural_clone_smells" => self
                .decode_and_run(arguments, |workspace, params| {
                    report_structural_clone_smells(workspace.analyzer(), params)
                }),
            "report_long_method_and_god_object_smells" => {
                self.decode_and_run(arguments, |workspace, params| {
                    report_long_method_and_god_object_smells(workspace.analyzer(), params)
                })
            }
            "report_dead_code_and_unused_abstraction_smells" => {
                self.decode_and_run(arguments, |workspace, params| {
                    report_dead_code_and_unused_abstraction_smells(workspace.analyzer(), params)
                })
            }
            "report_secret_like_code" => self.decode_and_run(arguments, |workspace, params| {
                report_secret_like_code(workspace.analyzer(), params)
            }),
            "analyze_git_hotspots" => self.decode_and_run(arguments, |workspace, params| {
                analyze_git_hotspots(workspace.analyzer(), params)
            }),
            _ => Err(SearchToolsServiceError::unknown_tool(format!(
                "Unknown tool: {name}"
            ))),
        }
    }

    pub fn active_workspace_root(&self) -> &Path {
        self.workspace.analyzer().project().root()
    }

    // Note: `--root` and `new_for_python` take the path as-given (canonicalized
    // by `FilesystemProject::new`) without git-root normalization, while
    // `activate_workspace` normalizes to the nearest enclosing git root. As a
    // result, calling `activate_workspace` with the same path that was passed
    // at construction may rebuild the index when the path is a subdirectory of
    // a git repository. The construction path is intentionally precise; hosts
    // that want git-root semantics should call `activate_workspace` after
    // start.
    fn new_with_strategy(root: PathBuf, update_strategy: UpdateStrategy) -> Result<Self, String> {
        let (project, workspace) = build_workspace(root)?;
        let watcher = maybe_start_watcher(project, update_strategy);
        Ok(Self {
            workspace,
            watcher,
            update_strategy,
        })
    }

    fn handle_refresh(&mut self, arguments: Value) -> Result<ToolOutput, SearchToolsServiceError> {
        let _params = serde_json::from_value::<RefreshParams>(arguments).map_err(|err| {
            SearchToolsServiceError::invalid_params(format!("Invalid tool arguments: {err}"))
        })?;
        self.workspace = self.workspace.update_all();
        self.structured_only(refresh_result(self.workspace.analyzer()))
    }

    fn handle_activate_workspace(
        &mut self,
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

        if resolved == self.workspace.analyzer().project().root() {
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
        self.watcher = None;
        self.workspace = new_workspace;
        self.watcher = maybe_start_watcher(new_project, self.update_strategy);

        active_workspace_result(&resolved)
    }

    fn handle_get_active_workspace(
        &mut self,
        arguments: Value,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        let _params =
            serde_json::from_value::<GetActiveWorkspaceParams>(arguments).map_err(|err| {
                SearchToolsServiceError::invalid_params(format!("Invalid tool arguments: {err}"))
            })?;
        active_workspace_result(self.workspace.analyzer().project().root())
    }

    fn prepare_for_call(&mut self) {
        match self.update_strategy {
            UpdateStrategy::WatchFiles => self.apply_watcher_delta(),
        }
    }

    fn apply_watcher_delta(&mut self) {
        let Some(watcher) = self.watcher.as_ref() else {
            return;
        };

        let delta = watcher.take_changed_files();
        if delta.requires_full_refresh {
            self.workspace = self.workspace.update_all();
            return;
        }

        if delta.files.is_empty() {
            return;
        }

        let changed_files: BTreeSet<ProjectFile> = delta.files.into_iter().collect();
        self.workspace = self.workspace.update(&changed_files);
    }

    fn decode_and_run<P, R>(
        &mut self,
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
        let result = handler(&self.workspace, params);
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

    fn decode_render_and_run<P, R>(
        &mut self,
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
        let result = handler(&self.workspace, params);
        let rendered_text = result.render_text(render_options);
        let structured = serde_json::to_value(result).map_err(|err| {
            SearchToolsServiceError::internal(format!("Failed to serialize tool result: {err}"))
        })?;
        Ok(ToolOutput::Structured {
            structured,
            rendered_text: Some(rendered_text),
        })
    }

    fn structured_only<R: Serialize>(
        &self,
        result: R,
    ) -> Result<ToolOutput, SearchToolsServiceError> {
        let structured = serde_json::to_value(result).map_err(|err| {
            SearchToolsServiceError::internal(format!("Failed to serialize tool result: {err}"))
        })?;
        Ok(ToolOutput::Structured {
            structured,
            rendered_text: None,
        })
    }
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
