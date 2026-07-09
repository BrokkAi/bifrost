use crate::{
    SearchToolsService, SearchToolsServiceError, SearchToolsServiceErrorCode,
    mcp_common::McpRenderOptions, mcp_registry::resolve_server_spec_for_render_options,
    scoped_project::create_scoped_service, searchtools_render::RenderOptions,
};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use std::path::PathBuf;

#[pyclass(name = "SearchToolsNativeSession")]
pub struct SearchToolsNativeSession {
    inner: SearchToolsService,
}

#[pymethods]
impl SearchToolsNativeSession {
    #[new]
    #[pyo3(signature = (root, manual=false, sources=None, revision=None))]
    fn new(
        py: Python<'_>,
        root: &str,
        manual: bool,
        sources: Option<Vec<String>>,
        revision: Option<String>,
    ) -> PyResult<Self> {
        if sources.is_some() && manual {
            return Err(PyValueError::new_err(
                "manual=True cannot be combined with sources; scoped sessions are already manual",
            ));
        }
        if revision.is_some() && sources.is_none() {
            return Err(PyValueError::new_err(
                "revision requires sources for a scoped session",
            ));
        }
        let root = PathBuf::from(root);
        let service = py
            .allow_threads(move || {
                if let Some(sources) = sources {
                    create_scoped_service(root, &sources, revision.as_deref())
                } else if manual {
                    SearchToolsService::new_for_python_manual(root)
                } else {
                    SearchToolsService::new_for_python(root)
                }
            })
            .map_err(PyRuntimeError::new_err)?;
        Ok(Self { inner: service })
    }

    fn call_tool_json(&self, py: Python<'_>, name: &str, arguments_json: &str) -> PyResult<String> {
        let name = name.to_owned();
        let arguments_json = arguments_json.to_owned();
        let result = py.allow_threads(|| self.inner.call_tool_json(&name, &arguments_json));

        match result {
            Ok(payload) => Ok(payload),
            Err(err) => Err(service_error_to_py(err)),
        }
    }

    fn call_tool_payload_json(
        &self,
        py: Python<'_>,
        name: &str,
        arguments_json: &str,
        render_line_numbers: bool,
    ) -> PyResult<String> {
        let name = name.to_owned();
        let arguments_json = arguments_json.to_owned();
        let result = py.allow_threads(|| {
            self.inner.call_tool_payload_json(
                &name,
                &arguments_json,
                RenderOptions {
                    render_line_numbers,
                },
            )
        });

        match result {
            Ok(payload) => Ok(payload),
            Err(err) => Err(service_error_to_py(err)),
        }
    }

    fn close(&self) -> PyResult<()> {
        self.inner.close().map_err(service_error_to_py)
    }

    /// Force a git-reachability GC of the semantic index and block until done.
    /// Releases the GIL while waiting; not for the retrieval path.
    fn gc(&self, py: Python<'_>) -> PyResult<()> {
        py.allow_threads(|| self.inner.request_semantic_gc())
            .map_err(service_error_to_py)
    }
}

fn service_error_to_py(err: SearchToolsServiceError) -> PyErr {
    match err.code {
        SearchToolsServiceErrorCode::InvalidParams => PyValueError::new_err(err.message),
        SearchToolsServiceErrorCode::UnknownTool | SearchToolsServiceErrorCode::Internal => {
            PyRuntimeError::new_err(err.message)
        }
    }
}

#[pyfunction]
#[pyo3(signature = (toolset="core", render_line_numbers=true, git_repo=true))]
fn tool_descriptors_json(
    toolset: &str,
    render_line_numbers: bool,
    git_repo: bool,
) -> PyResult<String> {
    let spec = resolve_server_spec_for_render_options(
        toolset,
        McpRenderOptions {
            render_line_numbers,
        },
        git_repo,
    )
    .map_err(PyValueError::new_err)?;
    serde_json::to_string(&spec.tool_descriptors)
        .map_err(|err| PyRuntimeError::new_err(err.to_string()))
}

#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<SearchToolsNativeSession>()?;
    module.add_function(wrap_pyfunction!(tool_descriptors_json, module)?)?;
    Ok(())
}
