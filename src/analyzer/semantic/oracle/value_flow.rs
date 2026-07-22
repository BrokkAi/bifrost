use std::sync::Arc;

use super::super::ir::{
    CaptureSource, EvidenceCompleteness, ProcedureHandle, ProofStatus, ValueHandle,
};
use super::error::{OracleContractError, require_same_procedure};
use super::limits::OracleLimits;
use super::model::{
    AbstractLocation, AbstractObjectIdentity, OracleCallContext, ProcedurePortHandle,
    ProcedurePortKind,
};
use super::relation::{
    CandidateCoverage, OracleRelationHandle, OracleRelationKind, OracleRelationOwner,
    validate_retained_relation_arenas,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueFlowRelationKind {
    Assignment,
    Parameter,
    Receiver,
    NormalReturn,
    ExceptionalReturn,
    Allocation,
    MemoryLoad,
    MemoryStore,
    Capture,
    LanguageDefined,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ValueFlowEndpoint {
    Value(ValueHandle),
    Port(ProcedurePortHandle),
    Location(Box<AbstractLocation>),
}

impl ValueFlowEndpoint {
    fn validate_at(&self, procedure: &ProcedureHandle) -> Result<(), OracleContractError> {
        match self {
            Self::Value(value) => require_same_procedure(value.procedure(), procedure),
            Self::Port(port) => require_same_procedure(port.procedure(), procedure),
            Self::Location(location) => {
                location.object().validate_at(procedure)?;
                location.path().validate_at(procedure)
            }
        }
    }
}

fn validate_capture_flow(
    procedure: &ProcedureHandle,
    source: &ValueFlowEndpoint,
    target: &ValueFlowEndpoint,
) -> Result<(), OracleContractError> {
    source.validate_at(procedure)?;
    let ValueFlowEndpoint::Port(target) = target else {
        return Err(OracleContractError::CrossProcedure);
    };
    let ProcedurePortKind::Capture { slot } = target.kind() else {
        return Err(OracleContractError::CrossProcedure);
    };
    let child = target.procedure();
    if !Arc::ptr_eq(procedure.artifact(), child.artifact())
        || child.semantics().lexical_parent() != Some(procedure.id())
    {
        return Err(OracleContractError::CrossProcedure);
    }

    let matches_source = |captured: CaptureSource| match (captured, source) {
        (CaptureSource::Value(expected), ValueFlowEndpoint::Value(actual)) => {
            actual.id() == expected
        }
        (CaptureSource::Location(expected), ValueFlowEndpoint::Location(actual)) => {
            matches!(
                actual.object().identity(),
                AbstractObjectIdentity::LexicalCell(location) if location.id() == expected
            )
        }
        (CaptureSource::Value(_), _) | (CaptureSource::Location(_), _) => false,
    };
    if !procedure.semantics().captures().iter().any(|capture| {
        capture.target == child.id()
            && capture.destination == slot
            && matches_source(capture.captured)
    }) {
        return Err(OracleContractError::InvalidRelationIdentity);
    }
    Ok(())
}

/// One materialized value-flow relation.  Relation IDs provide stable identity
/// inside this oracle materialization without imposing any weight algebra.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValueFlowRelation {
    pub id: OracleRelationHandle,
    pub kind: ValueFlowRelationKind,
    pub source: ValueFlowEndpoint,
    pub target: ValueFlowEndpoint,
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
}

impl ValueFlowRelation {
    pub const fn is_proven_complete(&self) -> bool {
        matches!(self.proof, ProofStatus::Proven)
            && matches!(self.completeness, EvidenceCompleteness::Complete)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValueFlowSnapshot {
    procedure: ProcedureHandle,
    context: OracleCallContext,
    relations: Box<[ValueFlowRelation]>,
    coverage: CandidateCoverage,
}

impl ValueFlowSnapshot {
    pub fn new(
        procedure: ProcedureHandle,
        context: OracleCallContext,
        relations: Vec<ValueFlowRelation>,
        coverage: CandidateCoverage,
        limits: OracleLimits,
    ) -> Result<Self, OracleContractError> {
        let owner = OracleRelationOwner::ProcedureValueFlow {
            procedure: procedure.clone(),
            context: context.clone(),
        };
        let mut seen = std::collections::HashSet::new();
        let first = relations.first().map(|relation| &relation.id);
        for relation in &relations {
            if relation.id.owner() != &owner
                || relation.id.record().kind() != OracleRelationKind::ValueFlow
                || relation.id.record().evidence().is_empty()
                || first.is_some_and(|first| !first.same_arena(&relation.id))
                || !seen.insert(relation.id.clone())
            {
                return Err(OracleContractError::InvalidRelationIdentity);
            }
            if !relation
                .id
                .record()
                .supports_quality(&relation.proof, &relation.completeness)
            {
                return Err(OracleContractError::InvalidRelationQuality);
            }
            if relation.kind == ValueFlowRelationKind::Capture {
                validate_capture_flow(&procedure, &relation.source, &relation.target)?;
            } else {
                relation.source.validate_at(&procedure)?;
                relation.target.validate_at(&procedure)?;
            }
        }
        validate_retained_relation_arenas(relations.iter().map(|relation| &relation.id), limits)?;
        Ok(Self {
            procedure,
            context,
            relations: relations.into_boxed_slice(),
            coverage,
        })
    }

    pub fn procedure(&self) -> &ProcedureHandle {
        &self.procedure
    }

    pub fn relations(&self) -> &[ValueFlowRelation] {
        &self.relations
    }

    pub fn context(&self) -> &OracleCallContext {
        &self.context
    }

    pub const fn coverage(&self) -> CandidateCoverage {
        self.coverage
    }
}
