use crate::{SearchToolsService, SearchToolsServiceError, SearchToolsServiceErrorCode};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

#[pyclass(name = "SearchToolsNativeSession")]
pub struct SearchToolsNativeSession {
    inner: Mutex<Option<SearchToolsService>>,
}

enum CallToolError {
    Closed,
    LockPoisoned,
    Service(SearchToolsServiceError),
}

#[pymethods]
impl SearchToolsNativeSession {
    #[new]
    fn new(root: &str) -> PyResult<Self> {
        let service = SearchToolsService::new_for_python(PathBuf::from(root))
            .map_err(PyRuntimeError::new_err)?;
        Ok(Self {
            inner: Mutex::new(Some(service)),
        })
    }

    fn call_tool_json(&self, py: Python<'_>, name: &str, arguments_json: &str) -> PyResult<String> {
        let name = name.to_owned();
        let arguments_json = arguments_json.to_owned();
        let result = py.allow_threads(|| {
            let mut inner = self.inner.lock().map_err(|_| CallToolError::LockPoisoned)?;
            let service = inner.as_mut().ok_or(CallToolError::Closed)?;
            service
                .call_tool_json(&name, &arguments_json)
                .map_err(CallToolError::Service)
        });

        match result {
            Ok(payload) => Ok(payload),
            Err(CallToolError::Closed) => {
                Err(PyRuntimeError::new_err("SearchToolsNativeSession is closed"))
            }
            Err(CallToolError::LockPoisoned) => {
                Err(PyRuntimeError::new_err("SearchToolsNativeSession lock poisoned"))
            }
            Err(CallToolError::Service(err)) => Err(service_error_to_py(err)),
        }
    }

    fn close(&self) -> PyResult<()> {
        let mut inner = self.lock_inner()?;
        *inner = None;
        Ok(())
    }
}

impl SearchToolsNativeSession {
    fn lock_inner(&self) -> PyResult<MutexGuard<'_, Option<SearchToolsService>>> {
        self.inner
            .lock()
            .map_err(|_| PyRuntimeError::new_err("SearchToolsNativeSession lock poisoned"))
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

#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<SearchToolsNativeSession>()?;
    Ok(())
}
