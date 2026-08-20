use std::sync::Arc;

use super::super::ir::{
    CaptureSource, EvidenceCompleteness, ProcedureHandle, ProgramPointHandle, ProofStatus,
    SemanticEffect, SemanticValueKind, ValueFlowKind, ValueHandle,
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
use crate::analyzer::semantic::ValueId;

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

fn value_endpoint(endpoint: &ValueFlowEndpoint, expected: ValueId) -> bool {
    matches!(endpoint, ValueFlowEndpoint::Value(value) if value.id() == expected)
}

fn port_endpoint(endpoint: &ValueFlowEndpoint, expected: ProcedurePortKind) -> bool {
    matches!(endpoint, ValueFlowEndpoint::Port(port) if port.kind() == expected)
}

/// Whether a memory access names an index location.
///
/// #2453: a subscript is not an identity the analysis can prove apart across
/// accesses, so an index access publishes its *container* alongside the exact
/// element it names -- the array reads out of, and writes into, one smashed
/// cell. When the access-path resolver walked the subscripted expression back
/// to an origin that a value or a port carries, that container is a value or a
/// port endpoint rather than a location, so this is the one memory-access shape
/// whose relation endpoint may be something other than a location.
///
/// Field accesses are deliberately excluded. Smashing indices does not change
/// what a member selector proves, and a field access that published its base
/// this way would silently make the whole object one cell.
fn memory_access_is_indexed(
    procedure: &ProcedureHandle,
    location: crate::analyzer::semantic::MemoryLocationId,
) -> bool {
    procedure
        .semantics()
        .memory_location(location)
        .is_some_and(|row| {
            matches!(
                row.kind,
                crate::analyzer::semantic::MemoryLocationKind::Index { .. }
            )
        })
}

fn relation_matches_event(
    procedure: &ProcedureHandle,
    relation: &ValueFlowRelation,
    effect: &SemanticEffect,
) -> bool {
    match effect {
        SemanticEffect::Assignment { target, value } => {
            relation.kind == ValueFlowRelationKind::Assignment
                && value_endpoint(&relation.source, *value)
                && value_endpoint(&relation.target, *target)
        }
        SemanticEffect::ValueFlow {
            kind: ValueFlowKind::Local,
            source,
            target,
        } => {
            relation.kind == ValueFlowRelationKind::Assignment
                && value_endpoint(&relation.source, *source)
                && value_endpoint(&relation.target, *target)
        }
        SemanticEffect::ValueFlow {
            kind: ValueFlowKind::Parameter,
            source,
            target,
        } => {
            if relation.kind != ValueFlowRelationKind::Parameter {
                return false;
            }
            let source_kind = procedure.semantics().value(*source).map(|row| &row.kind);
            let target_kind = procedure.semantics().value(*target).map(|row| &row.kind);
            match (source_kind, target_kind) {
                (Some(SemanticValueKind::Parameter { ordinal, .. }), _) => {
                    port_endpoint(
                        &relation.source,
                        ProcedurePortKind::Parameter { ordinal: *ordinal },
                    ) && value_endpoint(&relation.target, *target)
                }
                (_, Some(SemanticValueKind::Parameter { ordinal, .. })) => {
                    value_endpoint(&relation.source, *source)
                        && port_endpoint(
                            &relation.target,
                            ProcedurePortKind::Parameter { ordinal: *ordinal },
                        )
                }
                _ => false,
            }
        }
        SemanticEffect::ValueFlow {
            kind: ValueFlowKind::Receiver,
            target,
            ..
        } => {
            relation.kind == ValueFlowRelationKind::Receiver
                && port_endpoint(&relation.source, ProcedurePortKind::Receiver)
                && value_endpoint(&relation.target, *target)
        }
        SemanticEffect::ValueFlow {
            kind: ValueFlowKind::Return,
            source,
            ..
        } => {
            relation.kind == ValueFlowRelationKind::NormalReturn
                && value_endpoint(&relation.source, *source)
                && port_endpoint(&relation.target, ProcedurePortKind::NormalReturn)
        }
        SemanticEffect::ValueFlow {
            kind: ValueFlowKind::LanguageDefined,
            source,
            target,
        } => {
            relation.kind == ValueFlowRelationKind::LanguageDefined
                && value_endpoint(&relation.source, *source)
                && value_endpoint(&relation.target, *target)
        }
        SemanticEffect::Allocation { allocation } => procedure
            .semantics()
            .allocation(*allocation)
            .is_some_and(|row| {
                relation.kind == ValueFlowRelationKind::Allocation
                    && matches!(
                        &relation.source,
                        ValueFlowEndpoint::Location(location)
                            if matches!(
                                location.object().identity(),
                                AbstractObjectIdentity::Allocation(actual)
                                    if actual.id() == *allocation
                            )
                    )
                    && value_endpoint(&relation.target, row.result)
            }),
        SemanticEffect::MemoryLoad {
            location, result, ..
        } => {
            relation.kind == ValueFlowRelationKind::MemoryLoad
                && (matches!(&relation.source, ValueFlowEndpoint::Location(_))
                    || memory_access_is_indexed(procedure, *location))
                && value_endpoint(&relation.target, *result)
        }
        SemanticEffect::MemoryStore {
            location, value, ..
        } => {
            relation.kind == ValueFlowRelationKind::MemoryStore
                && value_endpoint(&relation.source, *value)
                && (matches!(&relation.target, ValueFlowEndpoint::Location(_))
                    || memory_access_is_indexed(procedure, *location))
        }
        SemanticEffect::CaptureBind { capture } => {
            procedure.semantics().capture(*capture).is_some_and(|row| {
                let source_matches = match (row.captured, &relation.source) {
                    (CaptureSource::Value(expected), ValueFlowEndpoint::Value(actual)) => {
                        actual.id() == expected
                    }
                    (CaptureSource::Location(expected), ValueFlowEndpoint::Location(actual)) => {
                        matches!(
                            actual.object().identity(),
                            AbstractObjectIdentity::LexicalCell(location)
                                if location.id() == expected
                        )
                    }
                    _ => false,
                };
                relation.kind == ValueFlowRelationKind::Capture
                    && source_matches
                    && matches!(
                        &relation.target,
                        ValueFlowEndpoint::Port(port)
                            if port.procedure().id() == row.target
                                && port.kind()
                                    == ProcedurePortKind::Capture { slot: row.destination }
                    )
            })
        }
        SemanticEffect::Throw { value: Some(value) } => {
            relation.kind == ValueFlowRelationKind::ExceptionalReturn
                && value_endpoint(&relation.source, *value)
                && port_endpoint(&relation.target, ProcedurePortKind::ExceptionalReturn)
        }
        _ => false,
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
    /// Exact semantic program point whose event publishes this relation.
    pub point: ProgramPointHandle,
    /// Zero-based event ordinal within [`ValueFlowRelation::point`].
    pub event_index: u32,
    pub id: OracleRelationHandle,
    pub kind: ValueFlowRelationKind,
    pub source: ValueFlowEndpoint,
    pub target: ValueFlowEndpoint,
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
}

impl ValueFlowRelation {
    pub fn point(&self) -> &ProgramPointHandle {
        &self.point
    }

    pub const fn event_index(&self) -> u32 {
        self.event_index
    }

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
            require_same_procedure(relation.point.procedure(), &procedure)?;
            if relation.kind == ValueFlowRelationKind::Capture {
                validate_capture_flow(&procedure, &relation.source, &relation.target)?;
            } else {
                relation.source.validate_at(&procedure)?;
                relation.target.validate_at(&procedure)?;
            }
            let point = procedure
                .semantics()
                .point(relation.point.id())
                .ok_or(OracleContractError::InvalidRelationIdentity)?;
            let event = point
                .events
                .get(relation.event_index as usize)
                .ok_or(OracleContractError::InvalidRelationIdentity)?;
            if !relation_matches_event(&procedure, relation, &event.effect) {
                return Err(OracleContractError::InvalidRelationIdentity);
            }
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
