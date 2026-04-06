use crate::{
    AnalyzerConfig, FilesystemProject, Project, ProjectChangeWatcher, ProjectFile,
    WorkspaceAnalyzer,
    searchtools::{
        MostRelevantFilesParams, RefreshParams, get_file_summaries, get_symbol_locations,
        get_symbol_sources, get_symbol_summaries, most_relevant_files, refresh_result,
        search_symbols, skim_files, summarize_symbols,
    },
};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;
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
        let result = self.call_tool_value(name, arguments)?;
        serde_json::to_string(&result).map_err(|err| {
            SearchToolsServiceError::internal(format!("Failed to serialize tool result: {err}"))
        })
    }

    pub fn call_tool_value(
        &mut self,
        name: &str,
        arguments: Value,
    ) -> Result<Value, SearchToolsServiceError> {
        if name == "refresh" {
            return self.handle_refresh(arguments);
        }

        self.prepare_for_call();
        match name {
            "search_symbols" => self.decode_and_run(arguments, |workspace, params| {
                search_symbols(workspace.analyzer(), params)
            }),
            "get_symbol_locations" => self.decode_and_run(arguments, |workspace, params| {
                get_symbol_locations(workspace.analyzer(), params)
            }),
            "get_symbol_summaries" => self.decode_and_run(arguments, |workspace, params| {
                get_symbol_summaries(workspace.analyzer(), params)
            }),
            "get_symbol_sources" => self.decode_and_run(arguments, |workspace, params| {
                get_symbol_sources(workspace.analyzer(), params)
            }),
            "get_file_summaries" => self.decode_and_run(arguments, |workspace, params| {
                get_file_summaries(workspace.analyzer(), params)
            }),
            "summarize_symbols" => self.decode_and_run(arguments, |workspace, params| {
                summarize_symbols(workspace.analyzer(), params)
            }),
            "skim_files" => self.decode_and_run(arguments, |workspace, params| {
                skim_files(workspace.analyzer(), params)
            }),
            "most_relevant_files" => {
                self.decode_and_run(arguments, |workspace, params: MostRelevantFilesParams| {
                    most_relevant_files(workspace.analyzer(), params)
                })
            }
            _ => Err(SearchToolsServiceError::unknown_tool(format!(
                "Unknown tool: {name}"
            ))),
        }
    }

    fn new_with_strategy(root: PathBuf, update_strategy: UpdateStrategy) -> Result<Self, String> {
        let project: Arc<dyn Project> = Arc::new(
            FilesystemProject::new(root)
                .map_err(|err| format!("Failed to initialize project root: {err}"))?,
        );
        let workspace = WorkspaceAnalyzer::build(Arc::clone(&project), AnalyzerConfig::default());
        let watcher = match update_strategy {
            UpdateStrategy::WatchFiles => ProjectChangeWatcher::start(project).ok(),
        };

        Ok(Self {
            workspace,
            watcher,
            update_strategy,
        })
    }

    fn handle_refresh(&mut self, arguments: Value) -> Result<Value, SearchToolsServiceError> {
        let _params = serde_json::from_value::<RefreshParams>(arguments).map_err(|err| {
            SearchToolsServiceError::invalid_params(format!("Invalid tool arguments: {err}"))
        })?;
        self.workspace = self.workspace.update_all();
        serde_json::to_value(refresh_result(self.workspace.analyzer())).map_err(|err| {
            SearchToolsServiceError::internal(format!("Failed to serialize tool result: {err}"))
        })
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
    ) -> Result<Value, SearchToolsServiceError>
    where
        P: serde::de::DeserializeOwned,
        R: Serialize,
    {
        let params = serde_json::from_value::<P>(arguments).map_err(|err| {
            SearchToolsServiceError::invalid_params(format!("Invalid tool arguments: {err}"))
        })?;
        serde_json::to_value(handler(&self.workspace, params)).map_err(|err| {
            SearchToolsServiceError::internal(format!("Failed to serialize tool result: {err}"))
        })
    }
}
