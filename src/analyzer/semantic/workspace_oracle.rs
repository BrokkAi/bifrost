//! Workspace-backed implementations of the language-neutral semantic oracles.

mod common;
mod dispatch;
mod heap;
mod source;
mod value_flow;

pub(crate) use dispatch::exact_source_for_procedure;
pub(super) use dispatch::semantic_locator_work;
#[cfg(test)]
pub(super) use dispatch::{
    CallableDefinitionIdentity, retain_dispatch_candidate, scoped_procedure_dispatch_gap,
};
pub use source::SourcePointsToResult;

use std::fmt;

use crate::analyzer::WorkspaceAnalyzer;

use super::OracleLimits;

/// Workspace semantic oracles bound to one immutable analyzer generation.
#[derive(Clone, Copy)]
pub struct WorkspaceSemanticOracle<'a> {
    workspace: &'a WorkspaceAnalyzer,
    limits: OracleLimits,
}

impl<'a> WorkspaceSemanticOracle<'a> {
    pub(crate) fn new(workspace: &'a WorkspaceAnalyzer) -> Self {
        Self::with_limits(workspace, OracleLimits::default())
    }

    pub fn with_limits(workspace: &'a WorkspaceAnalyzer, limits: OracleLimits) -> Self {
        Self { workspace, limits }
    }

    pub const fn workspace(&self) -> &'a WorkspaceAnalyzer {
        self.workspace
    }

    pub const fn limits(&self) -> &OracleLimits {
        &self.limits
    }
}

impl fmt::Debug for WorkspaceSemanticOracle<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkspaceSemanticOracle")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}
