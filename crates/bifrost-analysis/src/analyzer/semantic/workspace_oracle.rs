//! Workspace-backed implementations of the language-neutral semantic oracles.

mod common;
mod dispatch;
mod heap;
mod source;
mod value_flow;

pub(super) use dispatch::semantic_locator_work;
#[cfg(test)]
pub(super) use dispatch::{
    CallableDefinitionIdentity, retain_dispatch_candidate, scoped_procedure_dispatch_gap,
};
pub(crate) use dispatch::{exact_source_for_procedure, procedures_for_definition_with_limits};
// Policy lowering resolves authored source ranges to procedures through these
// two, so they are public where the rest of dispatch stays crate-internal.
pub use dispatch::{ProcedureRangeLookupStatus, procedures_for_source_ranges};
pub use source::{SourceDispatchObservation, SourceDispatchResult, SourcePointsToResult};
// The value-flow plan re-applies these relevance rules when it decides
// whether a snapshot's residual openness was refined by its own complete
// call resolutions (#1952).
pub(crate) use value_flow::{
    abort_paths_run_user_code, allocation_call_is_dischargeable, call_target_refinement_call,
    constructor_call_gap_is_discharged, gap_impacts_value_flow, implicit_abort_gap_is_discharged,
    value_flow_capabilities_are_open,
};

use std::fmt;

use crate::analyzer::{DispatchHierarchyExpansion, WorkspaceAnalyzer};

use super::OracleLimits;

/// Workspace semantic oracles bound to one immutable analyzer generation.
#[derive(Clone, Copy)]
pub struct WorkspaceSemanticOracle<'a> {
    workspace: &'a WorkspaceAnalyzer,
    limits: OracleLimits,
    hierarchy_expansion: DispatchHierarchyExpansion,
}

impl<'a> WorkspaceSemanticOracle<'a> {
    pub(crate) fn new(workspace: &'a WorkspaceAnalyzer) -> Self {
        Self::with_limits(workspace, OracleLimits::default())
    }

    /// Bind an oracle that inherits the workspace's configured class-hierarchy
    /// expansion. Every production path constructs oracles through here or
    /// through [`Self::new`], so the host's choice reaches dispatch without any
    /// intermediate provider having to carry it.
    pub fn with_limits(workspace: &'a WorkspaceAnalyzer, limits: OracleLimits) -> Self {
        Self::with_limits_and_expansion(workspace, limits, workspace.dispatch_hierarchy_expansion())
    }

    /// Bind an oracle to an explicitly stated class-hierarchy expansion,
    /// ignoring what the workspace was configured with.
    ///
    /// This exists so a test can exercise both settings in one process. Setting
    /// the `BIFROST_CHA_CONCRETE_OVERRIDES` variable would not work for that:
    /// test threads share one process environment, and the variable is read
    /// once per process.
    pub fn with_limits_and_expansion(
        workspace: &'a WorkspaceAnalyzer,
        limits: OracleLimits,
        hierarchy_expansion: DispatchHierarchyExpansion,
    ) -> Self {
        Self {
            workspace,
            limits,
            hierarchy_expansion,
        }
    }

    pub const fn workspace(&self) -> &'a WorkspaceAnalyzer {
        self.workspace
    }

    pub const fn limits(&self) -> &OracleLimits {
        &self.limits
    }

    /// Which class-hierarchy expansions this oracle's dispatch may add.
    pub const fn hierarchy_expansion(&self) -> DispatchHierarchyExpansion {
        self.hierarchy_expansion
    }
}

impl fmt::Debug for WorkspaceSemanticOracle<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkspaceSemanticOracle")
            .field("limits", &self.limits)
            .field("hierarchy_expansion", &self.hierarchy_expansion)
            .finish_non_exhaustive()
    }
}
