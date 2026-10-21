use crate::analyzer::semantic::ir::CallSiteHandle;

use crate::analyzer::semantic::ir::ProcedureHandle;

use crate::analyzer::semantic::provider::SemanticOutcome;

use crate::analyzer::semantic::provider::SemanticProviderError;

use crate::analyzer::semantic::provider::SemanticRequest;

use crate::analyzer::semantic::oracle::call::CallBindings;

use crate::analyzer::semantic::oracle::dispatch::DispatchCandidate;

use crate::analyzer::semantic::oracle::heap::AliasResult;

use crate::analyzer::semantic::oracle::heap::FreshObjectPublicationResult;

use crate::analyzer::semantic::oracle::heap::LocationResult;

use crate::analyzer::semantic::oracle::heap::PointsToResult;

use crate::analyzer::semantic::oracle::heap::UpdateEligibility;

use crate::analyzer::semantic::oracle::model::AccessPathAtPoint;

use crate::analyzer::semantic::oracle::model::AliasQuery;

use crate::analyzer::semantic::oracle::model::FreshObjectPublicationQuery;

use crate::analyzer::semantic::oracle::model::OracleCallContext;

use crate::analyzer::semantic::oracle::model::StoreAtPoint;

use crate::analyzer::semantic::oracle::model::ValueAtPoint;

use crate::analyzer::semantic::oracle::value_flow::ValueFlowSnapshot;

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

    fn fresh_object_publications(
        &self,
        query: &FreshObjectPublicationQuery,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<FreshObjectPublicationResult>, SemanticProviderError>;

    fn update_eligibility(
        &self,
        store: &StoreAtPoint,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<UpdateEligibility>, SemanticProviderError>;
}
