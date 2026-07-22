use super::super::ir::{CallSiteHandle, ProcedureHandle};
use super::super::provider::{SemanticOutcome, SemanticProviderError, SemanticRequest};
use super::call::CallBindings;
use super::dispatch::{DispatchCandidate, DispatchResult};
use super::heap::{AliasResult, LocationResult, PointsToResult, UpdateEligibility};
use super::model::{AccessPathAtPoint, AliasQuery, OracleCallContext, StoreAtPoint, ValueAtPoint};
use super::value_flow::ValueFlowSnapshot;

/// Location-first whole-program dispatch over one exact semantic call site.
pub trait DispatchOracle {
    fn resolve_call(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError>;
}

/// Procedure-local and candidate-specific value-flow answers.
pub trait ValueFlowOracle {
    fn procedure_relations(
        &self,
        procedure: &ProcedureHandle,
        context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<ValueFlowSnapshot>, SemanticProviderError>;

    fn call_bindings(
        &self,
        call: &CallSiteHandle,
        candidate: &DispatchCandidate,
        context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<CallBindings>, SemanticProviderError>;
}

/// Point-sensitive abstract-object, location, alias, and update answers.
pub trait HeapOracle {
    fn pointees(
        &self,
        value: &ValueAtPoint,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<PointsToResult>, SemanticProviderError>;

    fn locations(
        &self,
        access: &AccessPathAtPoint,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<LocationResult>, SemanticProviderError>;

    fn alias(
        &self,
        query: &AliasQuery,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<AliasResult>, SemanticProviderError>;

    fn update_eligibility(
        &self,
        store: &StoreAtPoint,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<UpdateEligibility>, SemanticProviderError>;
}
