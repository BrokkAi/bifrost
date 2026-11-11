//! Query-local workspace call structure, before any value-port projection.

use super::{LocalTransferDiscovery, WorkspaceCompositionDiscovery};
use crate::analyzer::semantic::{
    CallSiteHandle, DispatchResult, ProcedureHandle, SemanticExecutionBudget, SemanticOutcome,
    SemanticRequest,
};
use crate::taint::compose::Callers;
use crate::value_flow::{DurableCallSiteKey, DurableProcedureKey};
use std::cell::RefCell;

/// The oracle's complete answer and the exact semantic call that owns it.
/// Candidates and boundaries remain typed until a client projects its ports.
pub struct CallStructureDispatch {
    pub handle: CallSiteHandle,
    pub answer: SemanticOutcome<DispatchResult>,
}

/// Workspace relations used by composition clients. Model decisions stay with
/// the client; only its coverage decision enters incoming-call certification.
pub trait CallStructureProvider: LocalTransferDiscovery {
    fn dispatch(
        &self,
        call: &DurableCallSiteKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<CallStructureDispatch, Self::Error> {
        resolve_call_structure(self, call, request)
    }

    #[allow(clippy::too_many_arguments)]
    fn callers<F>(
        &self,
        covers_candidate: F,
        procedure: &DurableProcedureKey,
        max_callers: usize,
        budget: &SemanticExecutionBudget,
        excluded: &RefCell<Vec<(crate::analyzer::ProjectFile, crate::analyzer::Range)>>,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Callers, Self::Error>
    where
        Self: Sized,
        F: FnMut(&CallSiteHandle, &SemanticOutcome<DispatchResult>) -> Result<bool, Self::Error>,
    {
        super::callers_with_coverage(
            self,
            covers_candidate,
            procedure,
            max_callers,
            budget,
            excluded,
            request,
        )
    }

    fn lexical_parent(
        &self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Option<DurableProcedureKey>, Self::Error> {
        let handle = self.procedure(procedure, request)?;
        Ok(handle
            .semantics()
            .lexical_parent()
            .map(|parent| (procedure.0.clone(), parent)))
    }
}

impl CallStructureProvider for WorkspaceCompositionDiscovery<'_> {}

pub(super) fn resolve_call_structure<D: LocalTransferDiscovery + ?Sized>(
    discovery: &D,
    call: &DurableCallSiteKey,
    request: &mut SemanticRequest<'_>,
) -> Result<CallStructureDispatch, D::Error> {
    let handle: ProcedureHandle = discovery.procedure(&call.0, request)?;
    let site = handle.call_site_handle(call.1).ok_or_else(|| {
        discovery.unavailable(format!("call {:?} is not in its procedure", call.1))
    })?;
    let answer = {
        let _timing = brokk_bifrost_analysis::profiling::scope("taint.compose.dispatch.resolve");
        discovery.resolve_call(&site, request)?
    };
    Ok(CallStructureDispatch {
        handle: site,
        answer,
    })
}
