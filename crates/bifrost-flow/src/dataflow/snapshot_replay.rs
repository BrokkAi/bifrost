//! Adapter that replays an already-charged snapshot through summary clients.

use crate::analyzer::semantic::{
    CallSiteHandle, CallSiteId, CallTransferSet, DispatchOracle, DispatchResult, IcfgProvider,
    IcfgSnapshot, IcfgSnapshotLimits, ProcedureHandle, ProgramPointHandle, SemanticOutcome,
    SemanticProviderError, SemanticRequest, SemanticWork,
};

use super::{IcfgInputStatus, IcfgSolveInput};

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
    let snapshot = input.snapshot().clone();
    let work = SemanticWork::default();
    match input.status() {
        IcfgInputStatus::Complete => SemanticOutcome::Complete {
            value: snapshot,
            work,
        },
        IcfgInputStatus::Ambiguous => SemanticOutcome::Ambiguous {
            candidates: snapshot,
            work,
        },
        IcfgInputStatus::Unknown => SemanticOutcome::Unknown {
            partial: Some(snapshot),
            work,
        },
        IcfgInputStatus::Unsupported { capability } => SemanticOutcome::Unsupported {
            capability,
            partial: Some(snapshot),
            work,
        },
        IcfgInputStatus::Unproven => SemanticOutcome::Unproven {
            partial: snapshot,
            work,
        },
        IcfgInputStatus::ExceededBudget { exceeded } => SemanticOutcome::ExceededBudget {
            partial: Some(snapshot),
            exceeded,
            work,
        },
        IcfgInputStatus::Cancelled => SemanticOutcome::Cancelled {
            partial: Some(snapshot),
            work,
        },
    }
}
