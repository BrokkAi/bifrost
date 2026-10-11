//! Adapter that replays an already-charged snapshot through summary clients.

use crate::analyzer::semantic::{
    CallSiteHandle, CallSiteId, CallTransferSet, DispatchOracle, DispatchResult, IcfgProvider,
    IcfgSnapshot, IcfgSnapshotLimits, OracleCallContext, ProcedureHandle, ProgramPointHandle,
    SemanticOutcome, SemanticProviderError, SemanticRequest,
};

use super::IcfgSolveInput;

/// Replays one already-built snapshot while delegating semantic operations
/// that are not represented by the snapshot to the original provider.
///
/// The replayed `snapshot` outcome carries zero work because the caller has
/// already charged construction and reports that work separately in the
/// planned result envelope.
pub(crate) struct SnapshotReplayProvider<'input, 'provider, Provider: ?Sized> {
    provider: &'provider Provider,
    input: IcfgSolveInput<'input>,
}

impl<'input, 'provider, Provider: ?Sized> SnapshotReplayProvider<'input, 'provider, Provider> {
    pub(crate) const fn new(provider: &'provider Provider, input: IcfgSolveInput<'input>) -> Self {
        Self { provider, input }
    }
}

impl<Provider> DispatchOracle for SnapshotReplayProvider<'_, '_, Provider>
where
    Provider: DispatchOracle + ?Sized,
{
    fn resolve_call(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
        self.provider.resolve_call(call, request)
    }

    fn resolve_call_in_context(
        &self,
        call: &CallSiteHandle,
        context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
        self.provider
            .resolve_call_in_context(call, context, request)
    }
}

impl<Provider> IcfgProvider for SnapshotReplayProvider<'_, '_, Provider>
where
    Provider: IcfgProvider + ?Sized,
{
    fn call_transfers(
        &self,
        caller: &ProcedureHandle,
        call: CallSiteId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<CallTransferSet>, SemanticProviderError> {
        self.provider.call_transfers(caller, call, request)
    }

    fn call_transfers_in_context(
        &self,
        caller: &ProcedureHandle,
        call: CallSiteId,
        context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<CallTransferSet>, SemanticProviderError> {
        self.provider
            .call_transfers_in_context(caller, call, context, request)
    }

    fn snapshot(
        &self,
        _root: &ProcedureHandle,
        _limits: IcfgSnapshotLimits,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<IcfgSnapshot>, SemanticProviderError> {
        Ok(snapshot_outcome(self.input))
    }

    fn exit_profile(
        &self,
        callee_entry: &ProgramPointHandle,
        callee_exit: &ProgramPointHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<crate::analyzer::semantic::IcfgExitProfile>, SemanticProviderError>
    {
        self.provider
            .exit_profile(callee_entry, callee_exit, request)
    }
}

fn snapshot_outcome(input: IcfgSolveInput<'_>) -> SemanticOutcome<IcfgSnapshot> {
    input.status().snapshot_outcome(input.snapshot().clone())
}
