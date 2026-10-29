//! Structured procedure-local property reaching definitions.
//!
//! This projection deliberately starts from the value-flow oracle.  The
//! oracle owns receiver alias identity, access paths, evidence quality, and
//! strong-update certificates; this module only supplies the property-shaped
//! gen/kill relation and the source-facing view used by consumers.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmBudget;

use crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmError;

use crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmRequest;

use crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmWork;

use crate::analyzer::semantic::cfg_algorithms::DenseBidirectionalGraph;

use crate::analyzer::semantic::cfg_algorithms::GenKillFacts;

use crate::analyzer::semantic::cfg_algorithms::dominators;

use crate::analyzer::semantic::cfg_algorithms::forward_reachability;

use crate::analyzer::semantic::cfg_algorithms::reaching_definitions;

use crate::analyzer::semantic::cfg_algorithms::reverse_reachability;

use crate::analyzer::semantic::ids::MemoryLocationId;

use crate::analyzer::semantic::ids::ProgramPointId;

use crate::analyzer::semantic::ids::SemanticLocator;

use crate::analyzer::semantic::ids::SourceMappingId;

use crate::analyzer::semantic::ids::SourceSpan;

use crate::analyzer::semantic::ids::ValueId;

use crate::analyzer::semantic::ir::CaptureSource;

use crate::analyzer::semantic::ir::EvidenceCompleteness;

use crate::analyzer::semantic::ir::ExecutionTiming;

use crate::analyzer::semantic::ir::MemoryAccessKind;

use crate::analyzer::semantic::ir::MemoryLocationKind;

use crate::analyzer::semantic::ir::ProcedureHandle;

use crate::analyzer::semantic::ir::ProgramPointHandle;

use crate::analyzer::semantic::ir::ProofStatus;

use crate::analyzer::semantic::ir::SemanticEffect;

use crate::analyzer::semantic::ir::SemanticGap;

use crate::analyzer::semantic::ir::SemanticGapImpact;

use crate::analyzer::semantic::ir::SemanticGapSubject;

use crate::analyzer::semantic::ir::ValueHandle;

use crate::analyzer::semantic::oracle::AbstractLocation;

use crate::analyzer::semantic::oracle::AccessSelector;

use crate::analyzer::semantic::oracle::CandidateCoverage;

use crate::analyzer::semantic::oracle::DurableIdentityError;

use crate::analyzer::semantic::oracle::DurableValueIdentity;

use crate::analyzer::semantic::oracle::ExecutionTimingClaim;

use crate::analyzer::semantic::oracle::IndexSelector;

use crate::analyzer::semantic::oracle::MemoryOperationKey;

use crate::analyzer::semantic::oracle::MemoryRelationRole;

use crate::analyzer::semantic::oracle::ValueFlowEndpoint;

use crate::analyzer::semantic::oracle::ValueFlowRelation;

use crate::analyzer::semantic::oracle::ValueFlowRelationKind;

use crate::analyzer::semantic::oracle::ValueFlowSnapshot;

use crate::analyzer::semantic::oracle::OracleCallContext;

use crate::analyzer::semantic::provider::SemanticOutcome;

use crate::analyzer::semantic::provider::SemanticProviderError;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::cancellation::CancellationToken;

/// Finite work limits for one property-reaching projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PropertyReachingLimits {
    /// Maximum number of value-flow rows inspected while collecting property
    /// stores and reads.
    pub max_input_relations: usize,
    /// Maximum number of store-to-read rows retained in the result.
    pub max_reaching_pairs: usize,
    /// Shared node, edge, and pair budget for the CFG algorithms and result
    /// enumeration.
    pub cfg_work: CfgAlgorithmWork,
}

impl Default for PropertyReachingLimits {
    fn default() -> Self {
        Self {
            max_input_relations: 100_000,
            max_reaching_pairs: 100_000,
            cfg_work: CfgAlgorithmWork::default_limits(),
        }
    }
}

/// A durable selector in a property access path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PropertyAccessSelector {
    /// A structured field selector, retained as its durable semantic locator.
    Field(SemanticLocator),
    /// A value-computed index projected to the value's durable identity.
    IndexExact(DurableValueIdentity),
    /// A constant index.
    IndexConstant(u128),
    /// A summary index.  Property records carrying this selector are not
    /// materialized as exact keys, but the variant keeps the vocabulary closed
    /// if a caller inspects a future partial projection.
    IndexAny,
}

/// Durable receiver, path, and member identity for one property cell.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PropertyLocationIdentity {
    /// Durable identity of the object that roots the access path.
    pub receiver: crate::analyzer::semantic::oracle::DurableObjectIdentity,
    /// Selectors between the receiver and the final member.
    pub access_path: Box<[PropertyAccessSelector]>,
    /// Durable identity of the final member selector.
    pub member: SemanticLocator,
}

/// One structured property store published by a value-flow snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PropertyStoreRecord {
    pub procedure: ProcedureHandle,
    pub point: ProgramPointHandle,
    pub event_index: u32,
    pub source: SourceMappingId,
    pub source_locator: SemanticLocator,
    pub value: ValueHandle,
    pub location: PropertyLocationIdentity,
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
    pub strong_update: bool,
    /// Timing claim inherited from the publishing memory-store relation.
    pub timing: ExecutionTimingClaim,
}

impl PropertyStoreRecord {
    /// Whether this store has complete, proven value-flow evidence.
    pub fn is_proven_complete(&self) -> bool {
        self.proof.establishes_complete_evidence(&self.completeness)
    }

    pub const fn source_mapping(&self) -> SourceMappingId {
        self.source
    }

    pub const fn program_point(&self) -> ProgramPointId {
        self.point.id()
    }
}

/// One structured property read published by a value-flow snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PropertyReadRecord {
    pub procedure: ProcedureHandle,
    pub point: ProgramPointHandle,
    pub event_index: u32,
    pub source: SourceMappingId,
    pub source_locator: SemanticLocator,
    pub value: ValueHandle,
    pub location: PropertyLocationIdentity,
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
    /// Timing claim inherited from the publishing memory-load relation.
    pub timing: ExecutionTimingClaim,
}

impl PropertyReadRecord {
    /// Whether this read has complete, proven value-flow evidence.
    pub fn is_proven_complete(&self) -> bool {
        self.proof.establishes_complete_evidence(&self.completeness)
    }

    pub const fn source_mapping(&self) -> SourceMappingId {
        self.source
    }

    pub const fn program_point(&self) -> ProgramPointId {
        self.point.id()
    }
}

/// Whether a reaching store is uniquely established or one of several may
/// definitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PropertyReachCertainty {
    Exact,
    May,
}

/// One store-to-read property reaching relation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PropertyReachingRelation {
    pub store: PropertyStoreRecord,
    pub read: PropertyReadRecord,
    pub certainty: PropertyReachCertainty,
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
    pub coverage: CandidateCoverage,
}

impl PropertyReachingRelation {
    pub fn is_proven_complete(&self) -> bool {
        self.proof.establishes_complete_evidence(&self.completeness)
            && self.coverage.is_exhaustive()
    }
}

/// One value read observed inside an evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EvaluationReadRecord {
    pub procedure: ProcedureHandle,
    pub point: ProgramPointHandle,
    pub event_index: u32,
    pub source: SourceMappingId,
    pub source_locator: SemanticLocator,
    pub value: ValueHandle,
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
}

impl EvaluationReadRecord {
    pub const fn source_mapping(&self) -> SourceMappingId {
        self.source
    }

    pub const fn program_point(&self) -> ProgramPointId {
        self.point.id()
    }
}

/// One establishment anchor whose value is computed by an evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EvaluationEstablishmentRecord {
    pub procedure: ProcedureHandle,
    pub point: ProgramPointHandle,
    pub event_index: u32,
    pub source: SourceMappingId,
    pub source_locator: SemanticLocator,
    pub value: ValueHandle,
    pub kind: ValueFlowRelationKind,
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
}

impl EvaluationEstablishmentRecord {
    pub const fn source_mapping(&self) -> SourceMappingId {
        self.source
    }

    pub const fn program_point(&self) -> ProgramPointId {
        self.point.id()
    }
}

/// A read-to-establishment dependence proven to occur in one semantic
/// evaluation.  Both source mappings are retained so a resolver can join the
/// RHS read and binding/property establishment without source-order guesses.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EvaluationRelationRecord {
    pub establishment: EvaluationEstablishmentRecord,
    pub read: EvaluationReadRecord,
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
    /// Coverage of the procedure-local evaluation-dependence walk. This is
    /// independent of snapshot-wide dispatch/property coverage.
    pub coverage: CandidateCoverage,
    pub timing: ExecutionTimingClaim,
}

impl EvaluationRelationRecord {
    pub fn is_proven_complete(&self) -> bool {
        self.proof.establishes_complete_evidence(&self.completeness)
            && self.coverage.is_exhaustive()
            && self.timing.is_proven_complete()
    }

    pub const fn source_mapping(&self) -> SourceMappingId {
        self.read.source
    }

    pub const fn program_point(&self) -> ProgramPointId {
        self.read.point.id()
    }
}

/// Typed outcome for a source-oriented analyzer capability query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PropertySourceQueryState {
    Ambiguous,
    Unknown,
    Unsupported,
    Unproven,
    ExceededBudget,
    Cancelled,
}

/// Why source-oriented acquisition did not produce a complete answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropertySourceQueryIncompleteReason {
    CapabilityUnsupported,
    MaterializationFailure(SemanticProviderError),
    Materialization(PropertySourceQueryState),
    ProcedureRelations(PropertySourceQueryState),
    /// The focused range was not represented by a property read. This is
    /// unknown rather than a complete empty result: an unmodeled assignment
    /// may still be present outside the exact semantic procedure mapping.
    Unknown,
    /// The procedure projection retained property rows but could not prove
    /// its complete CFG/evidence coverage.
    PropertyProjectionIncomplete,
    ControlFlow(CfgAlgorithmError<ProgramPointId>),
    RecursiveProcedure(crate::analyzer::semantic::ids::ProcedureId),
    Cancelled,
}

/// Source-oriented result across the exact procedures whose structured source
/// mappings contain the requested span.  Multiple observations are preserved
/// rather than collapsed to an arbitrary match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertySourceQueryResult {
    #[doc(hidden)]
    pub control_reaching_stores: Box<[SemanticLocator]>,
    matches: Box<[PropertySourceResult]>,
    evaluations: Box<[EvaluationRelationRecord]>,
    incomplete_reasons: Box<[PropertySourceQueryIncompleteReason]>,
    evaluation_incomplete_reasons: Box<[PropertyReachingIncompleteReason]>,
}

impl PropertySourceQueryResult {
    /// Necessary control-flow evidence for a conservative, structurally bound
    /// candidate. This does not prove receiver identity or exhaustive coverage.
    /// The range addresses the exact establishment node, not a token contained
    /// in it: an allocation's span can also contain unexecuted method bodies.
    pub fn candidate_store_can_reach(
        &self,
        source: &brokk_bifrost_core::analyzer::model::Range,
    ) -> bool {
        self.control_reaching_stores.iter().any(|locator| {
            let span = locator.anchor().span();
            span.start_byte() as usize == source.start_byte
                && span.end_byte() as usize == source.end_byte
        })
    }

    pub fn matches(&self) -> &[PropertySourceResult] {
        &self.matches
    }

    pub fn evaluations(&self) -> &[EvaluationRelationRecord] {
        &self.evaluations
    }

    pub fn incomplete_reasons(&self) -> &[PropertySourceQueryIncompleteReason] {
        &self.incomplete_reasons
    }

    /// Incompleteness that applies only to SameEvaluation derivation. Property
    /// reaching completeness is intentionally independent of these reasons.
    pub fn evaluation_incomplete_reasons(&self) -> &[PropertyReachingIncompleteReason] {
        &self.evaluation_incomplete_reasons
    }

    pub fn properties_complete(&self) -> bool {
        self.incomplete_reasons.is_empty()
            && self.matches.iter().all(PropertySourceResult::is_complete)
    }

    pub fn evaluations_complete(&self) -> bool {
        self.evaluation_incomplete_reasons.is_empty()
            && self
                .incomplete_reasons
                .iter()
                .all(evaluation_acquisition_reason_is_local_complete)
    }

    pub fn is_complete(&self) -> bool {
        self.properties_complete() && self.evaluations_complete()
    }

    pub fn unsupported() -> Self {
        Self {
            control_reaching_stores: Box::new([]),
            matches: Box::new([]),
            evaluations: Box::new([]),
            incomplete_reasons: vec![PropertySourceQueryIncompleteReason::CapabilityUnsupported]
                .into_boxed_slice(),
            evaluation_incomplete_reasons: Box::new([]),
        }
    }

    #[doc(hidden)]
    pub fn from_parts(
        matches: Vec<PropertySourceResult>,
        evaluations: Vec<EvaluationRelationRecord>,
        incomplete_reasons: Vec<PropertySourceQueryIncompleteReason>,
        evaluation_incomplete_reasons: Vec<PropertyReachingIncompleteReason>,
    ) -> Self {
        Self {
            control_reaching_stores: Box::new([]),
            matches: matches.into_boxed_slice(),
            evaluations: evaluations.into_boxed_slice(),
            incomplete_reasons: incomplete_reasons.into_boxed_slice(),
            evaluation_incomplete_reasons: evaluation_incomplete_reasons.into_boxed_slice(),
        }
    }
}

fn evaluation_acquisition_reason_is_local_complete(
    reason: &PropertySourceQueryIncompleteReason,
) -> bool {
    match reason {
        PropertySourceQueryIncompleteReason::Materialization(
            PropertySourceQueryState::ExceededBudget | PropertySourceQueryState::Cancelled,
        )
        | PropertySourceQueryIncompleteReason::ProcedureRelations(
            PropertySourceQueryState::ExceededBudget | PropertySourceQueryState::Cancelled,
        )
        | PropertySourceQueryIncompleteReason::CapabilityUnsupported
        | PropertySourceQueryIncompleteReason::MaterializationFailure(_)
        | PropertySourceQueryIncompleteReason::ControlFlow(_)
        | PropertySourceQueryIncompleteReason::RecursiveProcedure(_)
        | PropertySourceQueryIncompleteReason::Cancelled => false,
        PropertySourceQueryIncompleteReason::Materialization(_)
        | PropertySourceQueryIncompleteReason::ProcedureRelations(_)
        | PropertySourceQueryIncompleteReason::Unknown
        | PropertySourceQueryIncompleteReason::PropertyProjectionIncomplete => true,
    }
}

/// Which endpoint a retained property relation failed to publish.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PropertyEndpointSide {
    Source,
    Target,
}

/// Why a property-reaching result cannot be treated as complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropertyReachingIncompleteReason {
    /// The selected point did not contain one projectable property read.
    SelectedReadMissing { point: ProgramPointId },
    /// More than one property read was published at the selected point.
    SelectedReadAmbiguous {
        point: ProgramPointId,
        event_indices: Box<[u32]>,
    },
    /// A selected property relation omitted an endpoint needed to identify it.
    SelectedRelationEndpointUnavailable {
        point: ProgramPointId,
        event_index: u32,
        relation: ValueFlowRelationKind,
        endpoint: PropertyEndpointSide,
        source: SourceMappingId,
        source_locator: Option<SemanticLocator>,
    },
    /// An unmodeled runtime or otherwise uncertain access may alias the
    /// selected receiver.
    SelectedRuntimeAccess {
        point: ProgramPointId,
        event_index: u32,
        source: SourceMappingId,
        source_locator: Option<SemanticLocator>,
        receiver: Option<crate::analyzer::semantic::oracle::DurableObjectIdentity>,
    },
    /// Replacing an ancestor property may establish the selected descendant.
    SelectedAncestorStore {
        point: ProgramPointId,
        event_index: u32,
        source: SourceMappingId,
        source_locator: Option<SemanticLocator>,
        location: Option<PropertyLocationIdentity>,
    },
    /// The selected receiver did not have a closed local-allocation alias set.
    SelectedAliasClosureUnavailable {
        receiver: crate::analyzer::semantic::oracle::DurableObjectIdentity,
    },
    /// A structured semantic gap can affect the selected property result.
    SelectedSemanticGap { gap: SemanticGap },
    /// The value-flow snapshot did not establish an exhaustive candidate set.
    CandidateCoverage(CandidateCoverage),
    /// The input relation bound stopped collection with partial rows retained.
    InputRelationBudgetExceeded { limit: usize, observed: usize },
    /// The reaching-pair bound stopped enumeration with partial rows retained.
    ReachingPairBudgetExceeded { limit: usize, observed: usize },
    /// The caller cancelled after partial rows had been collected.
    Cancelled,
    /// A property location was summarized instead of being an exact member
    /// path, or it selects a runtime key that carries no declaration locator,
    /// so it cannot be used as a key.
    UnsupportedLocation {
        point: ProgramPointId,
        event_index: u32,
    },
    /// A retained location could not be projected to durable identity.
    DurableIdentityUnavailable {
        point: ProgramPointId,
        event_index: u32,
        reason: DurableIdentityError,
    },
    /// A retained property event referred to no source mapping in its
    /// procedure artifact.
    SourceMappingUnavailable {
        point: ProgramPointId,
        event_index: u32,
        source: SourceMappingId,
    },
    /// A property store relation was retained but its own evidence is not
    /// proven and complete.
    StoreEvidenceIncomplete {
        point: ProgramPointId,
        event_index: u32,
        proof: ProofStatus,
        completeness: EvidenceCompleteness,
    },
    /// A property read relation was retained but its own evidence is not
    /// proven and complete.
    ReadEvidenceIncomplete {
        point: ProgramPointId,
        event_index: u32,
        proof: ProofStatus,
        completeness: EvidenceCompleteness,
    },
    /// A field-memory row did not publish the location endpoint required to
    /// establish a structured property key.
    FieldMemoryEndpointUnavailable {
        point: ProgramPointId,
        event_index: u32,
        relation: ValueFlowRelationKind,
    },
    /// A non-property evaluation relation did not publish both value
    /// endpoints needed to identify its establishment and source read.
    EvaluationEndpointUnavailable {
        point: ProgramPointId,
        event_index: u32,
        relation: ValueFlowRelationKind,
    },
    /// An evaluation relation was retained with incomplete evidence.
    EvaluationEvidenceIncomplete {
        point: ProgramPointId,
        event_index: u32,
        proof: ProofStatus,
        completeness: EvidenceCompleteness,
    },
    /// No structured value read covering the focused source address could be
    /// joined to an establishment in the same evaluation.
    EvaluationSourceUnknown,
    /// The CFG fixed point could not be completed.  Stores and reads remain
    /// available to a consumer, but no missing relation is inferred.
    ReachingDefinitions(CfgAlgorithmError<ProgramPointId>),
    /// Entry reachability could not be completed. Unreachable same-point
    /// events must not be admitted as definitions.
    Reachability(CfgAlgorithmError<ProgramPointId>),
    /// Dominance could not be completed.  May rows remain available, while no
    /// row is upgraded to exact certainty.
    Dominators(CfgAlgorithmError<ProgramPointId>),
    /// Enumerating store-to-read pairs exhausted the shared CFG work budget.
    ReachingPairs(CfgAlgorithmError<ProgramPointId>),
}

fn property_evidence_is_complete(
    coverage: CandidateCoverage,
    incomplete_reasons: &[PropertyReachingIncompleteReason],
) -> bool {
    coverage.is_exhaustive() && incomplete_reasons.is_empty()
}

/// All property stores, reads, and reaching rows for one exact procedure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertyReachingResult {
    procedure: ProcedureHandle,
    stores: Box<[PropertyStoreRecord]>,
    reads: Box<[PropertyReadRecord]>,
    reaching: Box<[PropertyReachingRelation]>,
    evaluations: Box<[EvaluationRelationRecord]>,
    coverage: CandidateCoverage,
    incomplete_reasons: Box<[PropertyReachingIncompleteReason]>,
    evaluation_incomplete_reasons: Box<[PropertyReachingIncompleteReason]>,
    cfg_work: CfgAlgorithmWork,
}

impl PropertyReachingResult {
    pub fn procedure(&self) -> &ProcedureHandle {
        &self.procedure
    }

    pub fn stores(&self) -> &[PropertyStoreRecord] {
        &self.stores
    }

    pub fn reads(&self) -> &[PropertyReadRecord] {
        &self.reads
    }

    pub fn reaching(&self) -> &[PropertyReachingRelation] {
        &self.reaching
    }

    pub fn evaluations(&self) -> &[EvaluationRelationRecord] {
        &self.evaluations
    }

    pub const fn coverage(&self) -> CandidateCoverage {
        self.coverage
    }

    pub fn incomplete_reasons(&self) -> &[PropertyReachingIncompleteReason] {
        &self.incomplete_reasons
    }

    pub fn evaluation_incomplete_reasons(&self) -> &[PropertyReachingIncompleteReason] {
        &self.evaluation_incomplete_reasons
    }

    pub const fn cfg_work(&self) -> CfgAlgorithmWork {
        self.cfg_work
    }

    /// Whether this result may be used to prove that an unmodeled candidate is
    /// absent.  Partial rows are intentionally retained even when this is
    /// false.
    pub fn is_complete(&self) -> bool {
        property_evidence_is_complete(self.coverage, &self.incomplete_reasons)
    }

    /// Return a source-oriented view for an exact event mapping identity.
    pub fn for_source_mapping(&self, source: SourceMappingId) -> Option<PropertySourceResult> {
        let reads = self
            .reads
            .iter()
            .filter(|read| read.source == source)
            .collect::<Vec<_>>();
        (!reads.is_empty()).then(|| self.source_result(&reads))
    }

    /// Return a source-oriented view for an exact semantic mapping locator.
    pub fn for_source_locator(&self, locator: &SemanticLocator) -> Option<PropertySourceResult> {
        let reads = self
            .reads
            .iter()
            .filter(|read| &read.source_locator == locator)
            .collect::<Vec<_>>();
        (!reads.is_empty()).then(|| self.source_result(&reads))
    }

    /// Return a source-oriented view when exactly one event mapping contains
    /// the focused structured span.  This is a span join, never a source-order
    /// predicate.
    pub fn for_source_span(&self, span: SourceSpan) -> Option<PropertySourceResult> {
        self.for_source_bytes(span.start_byte(), span.end_byte())
    }

    /// Return all property observations whose semantic mapping contains the
    /// focused byte span.  The range is only an address for the structured
    /// mapping join; it is never compared to store ranges as execution order.
    pub fn for_source_bytes(&self, start_byte: u32, end_byte: u32) -> Option<PropertySourceResult> {
        let reads = self
            .reads
            .iter()
            .filter(|read| {
                let mapping = read.source_locator.anchor().span();
                mapping.start_byte() <= start_byte && mapping.end_byte() >= end_byte
            })
            .collect::<Vec<_>>();
        (!reads.is_empty()).then(|| self.source_result(&reads))
    }

    pub fn evaluations_for_source_mapping(
        &self,
        source: SourceMappingId,
    ) -> Box<[EvaluationRelationRecord]> {
        self.evaluations
            .iter()
            .filter(|relation| relation.read.source == source)
            .cloned()
            .collect()
    }

    pub fn evaluations_for_source_bytes(
        &self,
        start_byte: u32,
        end_byte: u32,
    ) -> Box<[EvaluationRelationRecord]> {
        self.evaluations
            .iter()
            .filter(|relation| {
                let mapping = relation.read.source_locator.anchor().span();
                (mapping.start_byte() <= start_byte && mapping.end_byte() >= end_byte)
                    || (start_byte <= mapping.start_byte() && end_byte >= mapping.end_byte())
            })
            .cloned()
            .collect()
    }

    fn source_result(&self, reads: &[&PropertyReadRecord]) -> PropertySourceResult {
        let read_keys = reads
            .iter()
            .map(|read| (read.source, read.point.id(), read.event_index))
            .collect::<HashSet<_>>();
        let modeled_stores = self
            .stores
            .iter()
            .filter(|store| reads.iter().any(|read| store.location == read.location))
            .cloned()
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let reaching = self
            .reaching
            .iter()
            .filter(|relation| {
                read_keys.contains(&(
                    relation.read.source,
                    relation.read.point.id(),
                    relation.read.event_index,
                ))
            })
            .cloned()
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let evaluations = self
            .evaluations
            .iter()
            .filter(|relation| {
                reads.iter().any(|read| {
                    let mapping = read.source_locator.anchor().span();
                    let relation_mapping = relation.read.source_locator.anchor().span();
                    relation_mapping.start_byte() <= mapping.start_byte()
                        && relation_mapping.end_byte() >= mapping.end_byte()
                })
            })
            .cloned()
            .collect::<Vec<_>>()
            .into_boxed_slice();
        PropertySourceResult {
            reads: reads
                .iter()
                .map(|read| (*read).clone())
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            modeled_stores,
            reaching,
            evaluations,
            coverage: self.coverage,
            incomplete_reasons: self.incomplete_reasons.clone(),
            evaluation_incomplete_reasons: self.evaluation_incomplete_reasons.clone(),
        }
    }
}

/// Source-oriented property result for one exact read mapping.
///
/// `modeled_stores` deliberately includes stores which do not reach the read.
/// A complete result therefore lets a consumer classify a mapped dead-branch
/// store as definitively non-reaching, while an assignment not represented in
/// this procedure remains outside the modeled set and must stay conservative.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertySourceResult {
    reads: Box<[PropertyReadRecord]>,
    modeled_stores: Box<[PropertyStoreRecord]>,
    reaching: Box<[PropertyReachingRelation]>,
    evaluations: Box<[EvaluationRelationRecord]>,
    coverage: CandidateCoverage,
    incomplete_reasons: Box<[PropertyReachingIncompleteReason]>,
    evaluation_incomplete_reasons: Box<[PropertyReachingIncompleteReason]>,
}

impl PropertySourceResult {
    /// Return the sole read when the source address identifies one read.
    /// Callers handling nested or specialized observations should use
    /// [`Self::reads`] instead.
    pub fn read(&self) -> Option<&PropertyReadRecord> {
        (self.reads.len() == 1).then(|| &self.reads[0])
    }

    pub fn reads(&self) -> &[PropertyReadRecord] {
        &self.reads
    }

    pub fn modeled_stores(&self) -> &[PropertyStoreRecord] {
        &self.modeled_stores
    }

    pub fn reaching(&self) -> &[PropertyReachingRelation] {
        &self.reaching
    }

    pub fn evaluations(&self) -> &[EvaluationRelationRecord] {
        &self.evaluations
    }

    pub const fn coverage(&self) -> CandidateCoverage {
        self.coverage
    }

    pub fn incomplete_reasons(&self) -> &[PropertyReachingIncompleteReason] {
        &self.incomplete_reasons
    }

    pub fn evaluation_incomplete_reasons(&self) -> &[PropertyReachingIncompleteReason] {
        &self.evaluation_incomplete_reasons
    }

    pub fn is_complete(&self) -> bool {
        property_evidence_is_complete(self.coverage, &self.incomplete_reasons)
    }

    pub fn evaluations_complete(&self) -> bool {
        self.evaluation_incomplete_reasons.is_empty()
    }
}

/// Optional analyzer capability for structured procedure-local property
/// reaching definitions.
pub trait PropertyReachingProvider: Send + Sync {
    /// Acquire the current semantic artifact and value-flow snapshots for the
    /// requested file, then join every structured observation whose mapping
    /// contains `range`.  The default is an honest unsupported outcome.
    fn property_reaching_for_source_range(
        &self,
        _file: &ProjectFile,
        _range: &brokk_bifrost_core::analyzer::model::Range,
        _limits: PropertyReachingLimits,
        _cancellation: &CancellationToken,
    ) -> PropertySourceQueryResult {
        PropertySourceQueryResult::unsupported()
    }

    /// Project one already materialized value-flow snapshot under explicit
    /// finite CFG and cancellation controls.
    fn property_reaching(
        &self,
        snapshot: &ValueFlowSnapshot,
        limits: PropertyReachingLimits,
        cancellation: &CancellationToken,
    ) -> PropertyReachingResult {
        derive_property_reaching(snapshot, limits, cancellation)
    }

    /// Project and join a source mapping in one operation.  This lower-level
    /// snapshot form returns `None` when no property read is mapped there;
    /// callers crossing an analyzer boundary should use
    /// [`Self::property_reaching_for_source_range`], whose typed outcome also
    /// reports unavailable and incomplete acquisition.
    fn property_reaching_for_source_mapping(
        &self,
        snapshot: &ValueFlowSnapshot,
        source: SourceMappingId,
        limits: PropertyReachingLimits,
        cancellation: &CancellationToken,
    ) -> Option<PropertySourceResult> {
        self.property_reaching(snapshot, limits, cancellation)
            .for_source_mapping(source)
    }

    /// Source-span form of [`Self::property_reaching_for_source_mapping`].
    fn property_reaching_for_source_span(
        &self,
        snapshot: &ValueFlowSnapshot,
        span: SourceSpan,
        limits: PropertyReachingLimits,
        cancellation: &CancellationToken,
    ) -> Option<PropertySourceResult> {
        self.property_reaching(snapshot, limits, cancellation)
            .for_source_span(span)
    }
}

thread_local! {
    static ACTIVE_PROPERTY_PROCEDURES: RefCell<HashSet<(super::ids::SemanticArtifactKey, super::ids::ProcedureId)>> = RefCell::new(HashSet::new());
}

/// Oracle dispatch can call definition resolution in the same procedure.
/// Nested acquisition retains its CFG evidence but cannot recursively acquire
/// the same unfinished heap relation. Removal on drop also covers unwinding.
#[doc(hidden)]
pub struct ActivePropertyProcedure(
    (
        crate::analyzer::semantic::ids::SemanticArtifactKey,
        crate::analyzer::semantic::ids::ProcedureId,
    ),
);

impl ActivePropertyProcedure {
    #[doc(hidden)]
    pub fn enter(procedure: &ProcedureHandle) -> Option<Self> {
        let key = procedure.durable_key();
        ACTIVE_PROPERTY_PROCEDURES
            .with(|active| active.borrow_mut().insert(key.clone()).then(|| Self(key)))
    }
}

impl Drop for ActivePropertyProcedure {
    fn drop(&mut self) {
        ACTIVE_PROPERTY_PROCEDURES.with(|active| {
            assert!(active.borrow_mut().remove(&self.0));
        });
    }
}

/// Retain the CFG evidence even when heap identity or alias coverage is open.
/// Source spans only address field events; control edges and event ordinals
/// determine whether a candidate store can execute before the focused read.
#[doc(hidden)]
pub fn control_reaching_field_stores(
    procedure: &ProcedureHandle,
    start_byte: u32,
    end_byte: u32,
    limits: PropertyReachingLimits,
    cancellation: &CancellationToken,
) -> Result<Vec<SemanticLocator>, CfgAlgorithmError<ProgramPointId>> {
    let graph = procedure.semantics();
    let mut budget = CfgAlgorithmBudget::new(limits.cfg_work);
    let mut request = CfgAlgorithmRequest::new(&mut budget, cancellation);
    let entry_reachable = forward_reachability(graph, graph.entry_point(), &mut request)?;
    let mut reads = Vec::new();
    let mut stores = Vec::new();
    let receiver_preparations = graph.implicit_receiver_preparation_memory_events();
    for point in graph.points() {
        for (index, event) in point.events.iter().enumerate() {
            request.visit_pair::<ProgramPointId>()?;
            if receiver_preparations.contains(&(point.id, index)) {
                continue;
            }
            let mapping = graph
                .source_mapping(event.source)
                .expect("validated event source");
            match event.effect {
                SemanticEffect::MemoryLoad {
                    kind: MemoryAccessKind::Field,
                    ..
                } => {
                    let span = mapping.locator.anchor().span();
                    if span.start_byte() <= start_byte && span.end_byte() >= end_byte {
                        reads.push((point.id, index));
                    }
                }
                SemanticEffect::Allocation { .. }
                | SemanticEffect::MemoryStore {
                    kind: MemoryAccessKind::Field,
                    ..
                } => {
                    stores.push((point.id, index, &mapping.locator));
                }
                _ => {}
            }
        }
    }
    let mut retained = HashSet::new();
    if !reads.is_empty() {
        retained.extend(captured_literal_establishments(procedure, &mut request)?);
    }
    for (read_point, read_index) in reads {
        if !entry_reachable.contains(graph, read_point) {
            continue;
        }
        let predecessors = reverse_reachability(graph, read_point, &mut request)?;
        let mut cycles_to_read = false;
        for (_, successor) in graph.successors(read_point) {
            request.visit_pair::<ProgramPointId>()?;
            cycles_to_read |= predecessors.contains(graph, successor);
        }
        for (store_point, store_index, source) in &stores {
            request.visit_pair::<ProgramPointId>()?;
            if entry_reachable.contains(graph, *store_point)
                && predecessors.contains(graph, *store_point)
                && (*store_point != read_point || *store_index < read_index || cycles_to_read)
            {
                retained.insert((*source).clone());
            }
        }
    }
    Ok(retained.into_iter().collect())
}

/// A value-captured literal has an establishment in its lexical parent, not
/// in the reader's CFG. Follow the explicit capture and assignment identities
/// to those allocation sites. This admits captured initializer candidates but
/// never imports arbitrary stores from sibling procedures.
fn captured_literal_establishments(
    procedure: &ProcedureHandle,
    request: &mut CfgAlgorithmRequest<'_>,
) -> Result<Vec<SemanticLocator>, CfgAlgorithmError<ProgramPointId>> {
    let mut result = Vec::new();
    for parent in procedure.artifact().procedures() {
        let captures: Vec<_> = parent
            .captures()
            .iter()
            .filter(|capture| {
                capture.target == procedure.id()
                    && matches!(
                        capture.mode,
                        crate::analyzer::semantic::ir::CaptureMode::Value
                            | crate::analyzer::semantic::ir::CaptureMode::Move
                    )
            })
            .collect();
        if captures.is_empty() {
            continue;
        }
        let mut assignments: HashMap<ValueId, Vec<ValueId>> = HashMap::new();
        for point in parent.points() {
            for event in &point.events {
                request.visit_pair::<ProgramPointId>()?;
                if let SemanticEffect::Assignment { target, value } = event.effect {
                    assignments.entry(target).or_default().push(value);
                }
            }
        }
        let entry = forward_reachability(parent, parent.entry_point(), request)?;
        for capture in captures {
            let CaptureSource::Value(value) = capture.captured else {
                continue;
            };
            if !entry.contains(parent, capture.point) {
                continue;
            }
            let preceding = reverse_reachability(parent, capture.point, request)?;
            let mut pending = vec![value];
            let mut values = HashSet::new();
            while let Some(value) = pending.pop() {
                request.visit_pair::<ProgramPointId>()?;
                if values.insert(value)
                    && let Some(sources) = assignments.get(&value)
                {
                    pending.extend(sources.iter().copied());
                }
            }
            for allocation in parent.allocations() {
                request.visit_pair::<ProgramPointId>()?;
                if values.contains(&allocation.result)
                    && entry.contains(parent, allocation.point)
                    && preceding.contains(parent, allocation.point)
                {
                    result.push(
                        parent
                            .source_mapping(allocation.source)
                            .expect("validated allocation source")
                            .locator
                            .clone(),
                    );
                }
            }
        }
    }
    Ok(result)
}

#[doc(hidden)]
pub fn source_query_state<T>(outcome: &SemanticOutcome<T>) -> Option<PropertySourceQueryState> {
    match outcome {
        SemanticOutcome::Complete { .. } => None,
        SemanticOutcome::Ambiguous { .. } => Some(PropertySourceQueryState::Ambiguous),
        SemanticOutcome::Unknown { .. } => Some(PropertySourceQueryState::Unknown),
        SemanticOutcome::Unsupported { .. } => Some(PropertySourceQueryState::Unsupported),
        SemanticOutcome::Unproven { .. } => Some(PropertySourceQueryState::Unproven),
        SemanticOutcome::ExceededBudget { .. } => Some(PropertySourceQueryState::ExceededBudget),
        SemanticOutcome::Cancelled { .. } => Some(PropertySourceQueryState::Cancelled),
    }
}

/// Build structured property stores, reads, and CFG reaching rows over the
/// procedure's complete control-flow graph.
pub fn derive_property_reaching(
    snapshot: &ValueFlowSnapshot,
    limits: PropertyReachingLimits,
    cancellation: &CancellationToken,
) -> PropertyReachingResult {
    let procedure = snapshot.procedure();
    derive_property_reaching_over_graph(
        snapshot,
        procedure.semantics(),
        procedure.semantics().entry_point(),
        limits,
        cancellation,
    )
}

struct PropertyEventProjection {
    stores: Vec<PropertyStoreRecord>,
    reads: Vec<PropertyReadRecord>,
    incomplete_reasons: Vec<PropertyReachingIncompleteReason>,
}

fn project_property_relations<'a>(
    procedure: &ProcedureHandle,
    relations: impl Iterator<Item = &'a ValueFlowRelation>,
    cancellation: &CancellationToken,
) -> PropertyEventProjection {
    let mut stores = Vec::new();
    let mut reads = Vec::new();
    let mut incomplete_reasons = Vec::new();
    for relation in relations {
        if cancellation.is_cancelled() {
            incomplete_reasons.push(PropertyReachingIncompleteReason::Cancelled);
            break;
        }
        match relation.kind {
            ValueFlowRelationKind::MemoryStore => {
                let Some(location) = endpoint_location(&relation.target) else {
                    if field_memory_event(procedure, relation) {
                        incomplete_reasons.push(
                            PropertyReachingIncompleteReason::FieldMemoryEndpointUnavailable {
                                point: relation.point.id(),
                                event_index: relation.event_index,
                                relation: relation.kind,
                            },
                        );
                    }
                    continue;
                };
                let Some(value) = endpoint_value(&relation.source) else {
                    if field_memory_event(procedure, relation) {
                        incomplete_reasons.push(
                            PropertyReachingIncompleteReason::FieldMemoryEndpointUnavailable {
                                point: relation.point.id(),
                                event_index: relation.event_index,
                                relation: relation.kind,
                            },
                        );
                    }
                    continue;
                };
                let reason_count = incomplete_reasons.len();
                if let Some(record) = project_store(
                    procedure,
                    relation,
                    location,
                    value,
                    &mut incomplete_reasons,
                ) {
                    stores.push(record);
                } else if reason_count == incomplete_reasons.len()
                    && field_memory_event(procedure, relation)
                {
                    incomplete_reasons.push(
                        PropertyReachingIncompleteReason::UnsupportedLocation {
                            point: relation.point.id(),
                            event_index: relation.event_index,
                        },
                    );
                }
            }
            ValueFlowRelationKind::MemoryLoad => {
                let Some(location) = endpoint_location(&relation.source) else {
                    if field_memory_event(procedure, relation) {
                        incomplete_reasons.push(
                            PropertyReachingIncompleteReason::FieldMemoryEndpointUnavailable {
                                point: relation.point.id(),
                                event_index: relation.event_index,
                                relation: relation.kind,
                            },
                        );
                    }
                    continue;
                };
                let Some(value) = endpoint_value(&relation.target) else {
                    if field_memory_event(procedure, relation) {
                        incomplete_reasons.push(
                            PropertyReachingIncompleteReason::FieldMemoryEndpointUnavailable {
                                point: relation.point.id(),
                                event_index: relation.event_index,
                                relation: relation.kind,
                            },
                        );
                    }
                    continue;
                };
                let reason_count = incomplete_reasons.len();
                if let Some(record) = project_read(
                    procedure,
                    relation,
                    location,
                    value,
                    &mut incomplete_reasons,
                ) {
                    reads.push(record);
                } else if reason_count == incomplete_reasons.len()
                    && field_memory_event(procedure, relation)
                {
                    incomplete_reasons.push(
                        PropertyReachingIncompleteReason::UnsupportedLocation {
                            point: relation.point.id(),
                            event_index: relation.event_index,
                        },
                    );
                }
            }
            _ => {}
        }
    }
    PropertyEventProjection {
        stores,
        reads,
        incomplete_reasons,
    }
}

fn memory_relation_role(
    relation: &ValueFlowRelation,
    effect: &SemanticEffect,
) -> Option<MemoryRelationRole> {
    match effect {
        SemanticEffect::MemoryLoad { .. } | SemanticEffect::MemoryStore { .. } => Some(
            relation
                .memory_origin()
                .expect("a snapshot row at a memory event has a validated producer origin")
                .role(),
        ),
        _ => None,
    }
}

type CanonicalMemoryOperationKeys<'a> = HashSet<MemoryOperationKey<'a>>;

fn record_canonical_memory_operation<'a>(
    keys: &mut CanonicalMemoryOperationKeys<'a>,
    relation: &'a ValueFlowRelation,
) {
    let key = relation
        .memory_operation_key()
        .expect("a validated memory event has an exact scoped operation key");
    keys.insert(key);
}

fn canonical_memory_operation_is_present(
    keys: &CanonicalMemoryOperationKeys<'_>,
    point: &ProgramPointHandle,
    event_index: u32,
    location: MemoryLocationId,
    context: &OracleCallContext,
) -> bool {
    let key = MemoryOperationKey {
        point,
        event_index,
        location: point
            .procedure()
            .memory_location_handle(location)
            .expect("a validated memory event names a retained memory location"),
        context,
    };
    keys.contains(&key)
}

/// Build the same relation over a caller-supplied graph view.  Flow-state
/// projections can pass their masked graph here, keeping omitted control edges
/// consistent with the relation rows without making analysis depend on flow.
pub fn derive_property_reaching_over_graph<G>(
    snapshot: &ValueFlowSnapshot,
    graph: &G,
    entry: ProgramPointId,
    limits: PropertyReachingLimits,
    cancellation: &CancellationToken,
) -> PropertyReachingResult
where
    G: DenseBidirectionalGraph<Node = ProgramPointId>,
{
    let procedure = snapshot.procedure().clone();
    let relations = snapshot.relations();
    let relation_limit = limits.max_input_relations.min(relations.len());
    let projection = project_property_relations(
        &procedure,
        relations.iter().take(relation_limit),
        cancellation,
    );
    let stores = projection.stores;
    let reads = projection.reads;
    let mut incomplete_reasons = projection.incomplete_reasons;
    let mut evaluation_incomplete_reasons = Vec::new();

    if relation_limit < relations.len() {
        incomplete_reasons.push(
            PropertyReachingIncompleteReason::InputRelationBudgetExceeded {
                limit: limits.max_input_relations,
                observed: relation_limit,
            },
        );
    }
    let property_coverage = property_candidate_coverage(
        snapshot,
        relations,
        relation_limit,
        stores.iter().map(|store| &store.location),
        reads.iter().map(|read| &read.location),
        cancellation,
    );
    if !property_coverage.is_exhaustive() {
        incomplete_reasons.push(PropertyReachingIncompleteReason::CandidateCoverage(
            property_coverage,
        ));
    }

    let evaluations = evaluation_relations(
        snapshot,
        relation_limit,
        limits.max_reaching_pairs,
        cancellation,
        &mut evaluation_incomplete_reasons,
    );
    if relation_limit < relations.len() {
        evaluation_incomplete_reasons.push(
            PropertyReachingIncompleteReason::InputRelationBudgetExceeded {
                limit: limits.max_input_relations,
                observed: relation_limit,
            },
        );
    }

    derive_property_reaching_from_records(
        procedure,
        graph,
        entry,
        stores,
        reads,
        evaluations,
        property_coverage,
        incomplete_reasons,
        evaluation_incomplete_reasons,
        limits,
        cancellation,
    )
}

/// Derive property reaching for the unique property read at `point`.
///
/// Projection uses the same durable identities as aggregate analysis. The
/// receiver and its alias closure scope candidate blockers before the shared
/// CFG kernel assigns reaching rows.
pub fn derive_selected_property_reaching_over_graph<G>(
    snapshot: &ValueFlowSnapshot,
    graph: &G,
    entry: ProgramPointId,
    point: ProgramPointId,
    limits: PropertyReachingLimits,
    cancellation: &CancellationToken,
) -> PropertyReachingResult
where
    G: DenseBidirectionalGraph<Node = ProgramPointId>,
{
    let procedure = snapshot.procedure().clone();
    let relations = snapshot.relations();
    let relation_limit = limits.max_input_relations.min(relations.len());
    let projection = project_property_relations(
        &procedure,
        relations.iter().take(relation_limit).filter(|relation| {
            if cancellation.is_cancelled() {
                return true;
            }
            let event = relation_event(&procedure, relation);
            !matches!(
                memory_relation_role(relation, &event.effect),
                Some(MemoryRelationRole::Supplemental)
            )
        }),
        cancellation,
    );
    let read_events = property_read_event_indices(&procedure, point);
    let mut incomplete_reasons = Vec::new();
    let selected_read = match read_events.as_slice() {
        [] => {
            incomplete_reasons
                .push(PropertyReachingIncompleteReason::SelectedReadMissing { point });
            None
        }
        [event_index] => projection
            .reads
            .iter()
            .find(|read| read.point.id() == point && read.event_index == *event_index)
            .cloned()
            .or_else(|| {
                incomplete_reasons
                    .push(PropertyReachingIncompleteReason::SelectedReadMissing { point });
                None
            }),
        _ => {
            incomplete_reasons.push(PropertyReachingIncompleteReason::SelectedReadAmbiguous {
                point,
                event_indices: read_events.clone().into_boxed_slice(),
            });
            None
        }
    };
    let selected_read_missing = selected_read.is_none();
    if selected_read_missing {
        incomplete_reasons.extend(selected_point_endpoint_reasons(
            snapshot,
            relations,
            relation_limit,
            point,
            cancellation,
        ));
    }

    if relation_limit < relations.len() {
        incomplete_reasons.push(
            PropertyReachingIncompleteReason::InputRelationBudgetExceeded {
                limit: limits.max_input_relations,
                observed: relation_limit,
            },
        );
    }
    if cancellation.is_cancelled()
        || projection
            .incomplete_reasons
            .iter()
            .any(|reason| matches!(reason, PropertyReachingIncompleteReason::Cancelled))
    {
        incomplete_reasons.push(PropertyReachingIncompleteReason::Cancelled);
    }

    if relation_limit < relations.len()
        || snapshot.coverage().is_truncated()
        || cancellation.is_cancelled()
    {
        let reads = selected_read.into_iter().collect::<Vec<_>>();
        let stores = projection
            .stores
            .into_iter()
            .filter(|store| reads.iter().any(|read| store.location == read.location))
            .collect();
        incomplete_reasons.extend(projection.incomplete_reasons);
        let coverage = if relation_limit < relations.len() || snapshot.coverage().is_truncated() {
            CandidateCoverage::Truncated
        } else {
            CandidateCoverage::Open
        };
        incomplete_reasons.push(PropertyReachingIncompleteReason::CandidateCoverage(
            coverage,
        ));
        return derive_property_reaching_from_records(
            procedure,
            graph,
            entry,
            stores,
            reads,
            Vec::new(),
            coverage,
            incomplete_reasons,
            Vec::new(),
            limits,
            cancellation,
        );
    }

    let (stores, reads, coverage, scoped_event_keys) = if let Some(read) = selected_read {
        let stores = projection
            .stores
            .iter()
            .filter(|store| store.location == read.location)
            .cloned()
            .collect::<Vec<_>>();
        let (scope_reasons, scoped_event_keys) = selected_property_scope_reasons(
            snapshot,
            relations,
            relation_limit,
            &read,
            &projection.stores,
            cancellation,
        );
        incomplete_reasons.extend(scope_reasons);
        let coverage = property_candidate_coverage(
            snapshot,
            relations,
            relation_limit,
            stores.iter().map(|store| &store.location),
            std::iter::once(&read.location),
            cancellation,
        );
        if !coverage.is_exhaustive() {
            incomplete_reasons.push(PropertyReachingIncompleteReason::CandidateCoverage(
                coverage,
            ));
        }
        (stores, vec![read], coverage, scoped_event_keys)
    } else {
        let coverage = if relation_limit < relations.len() || snapshot.coverage().is_truncated() {
            CandidateCoverage::Truncated
        } else {
            CandidateCoverage::Open
        };
        incomplete_reasons.push(PropertyReachingIncompleteReason::CandidateCoverage(
            coverage,
        ));
        (Vec::new(), Vec::new(), coverage, HashSet::new())
    };

    for reason in projection.incomplete_reasons {
        if incomplete_reason_event_key(&reason).is_some_and(|key| {
            scoped_event_keys.contains(&key) || (selected_read_missing && key.0 == point)
        }) {
            incomplete_reasons.push(reason);
        }
    }

    derive_property_reaching_from_records(
        procedure,
        graph,
        entry,
        stores,
        reads,
        Vec::new(),
        coverage,
        incomplete_reasons,
        Vec::new(),
        limits,
        cancellation,
    )
}

fn property_read_event_indices(procedure: &ProcedureHandle, point: ProgramPointId) -> Vec<u32> {
    let receiver_preparations = procedure
        .semantics()
        .implicit_receiver_preparation_memory_events();
    procedure
        .semantics()
        .point(point)
        .into_iter()
        .flat_map(|point| point.events.iter().enumerate())
        .filter_map(|(index, event)| {
            if receiver_preparations.contains(&(point, index)) {
                return None;
            }
            matches!(
                event.effect,
                SemanticEffect::MemoryLoad {
                    kind: MemoryAccessKind::Field
                        | MemoryAccessKind::Property
                        | MemoryAccessKind::Index
                        | MemoryAccessKind::Dereference,
                    ..
                }
            )
            .then_some(index as u32)
        })
        .collect()
}

fn selected_point_endpoint_reasons(
    snapshot: &ValueFlowSnapshot,
    relations: &[ValueFlowRelation],
    relation_limit: usize,
    point: ProgramPointId,
    cancellation: &CancellationToken,
) -> Vec<PropertyReachingIncompleteReason> {
    let procedure = snapshot.procedure();
    let mut reasons = Vec::new();
    let mut canonical_operations = CanonicalMemoryOperationKeys::new();
    let mut relation_scan_complete =
        relation_limit == relations.len() && !snapshot.coverage().is_truncated();
    for relation in relations.iter().take(relation_limit) {
        if cancellation.is_cancelled() {
            reasons.push(PropertyReachingIncompleteReason::Cancelled);
            relation_scan_complete = false;
            break;
        }
        if relation.kind != ValueFlowRelationKind::MemoryLoad || relation.point.id() != point {
            continue;
        }
        let event = relation_event(procedure, relation);
        if !matches!(
            event.effect,
            SemanticEffect::MemoryLoad {
                kind: MemoryAccessKind::Field
                    | MemoryAccessKind::Property
                    | MemoryAccessKind::Index
                    | MemoryAccessKind::Dereference,
                ..
            }
        ) {
            continue;
        }
        let role = memory_relation_role(relation, &event.effect)
            .expect("a validated memory-load row has a producer-attested origin");
        if role == MemoryRelationRole::Supplemental {
            continue;
        }
        if role == MemoryRelationRole::Canonical {
            record_canonical_memory_operation(&mut canonical_operations, relation);
        }

        let source = event.source;
        let source_locator = procedure.source_locator(source).cloned();
        if endpoint_location(&relation.source).is_none() {
            reasons.push(
                PropertyReachingIncompleteReason::SelectedRelationEndpointUnavailable {
                    point,
                    event_index: relation.event_index,
                    relation: relation.kind,
                    endpoint: PropertyEndpointSide::Source,
                    source,
                    source_locator: source_locator.clone(),
                },
            );
        }
        if endpoint_value(&relation.target).is_none() {
            reasons.push(
                PropertyReachingIncompleteReason::SelectedRelationEndpointUnavailable {
                    point,
                    event_index: relation.event_index,
                    relation: relation.kind,
                    endpoint: PropertyEndpointSide::Target,
                    source,
                    source_locator,
                },
            );
        }
    }

    if relation_scan_complete && let Some(point_row) = procedure.semantics().point(point) {
        let point_handle = procedure
            .point_handle(point)
            .expect("a retained semantic point has a procedure handle");
        for (index, event) in point_row.events.iter().enumerate() {
            if cancellation.is_cancelled() {
                reasons.push(PropertyReachingIncompleteReason::Cancelled);
                break;
            }
            let location = match event.effect {
                SemanticEffect::MemoryLoad {
                    kind:
                        MemoryAccessKind::Field
                        | MemoryAccessKind::Property
                        | MemoryAccessKind::Index
                        | MemoryAccessKind::Dereference,
                    location,
                    ..
                } => location,
                _ => continue,
            };
            let event_index =
                u32::try_from(index).expect("validated event indices fit semantic IDs");
            if !canonical_memory_operation_is_present(
                &canonical_operations,
                &point_handle,
                event_index,
                location,
                snapshot.context(),
            ) {
                reasons.push(
                    PropertyReachingIncompleteReason::SelectedRelationEndpointUnavailable {
                        point,
                        event_index,
                        relation: ValueFlowRelationKind::MemoryLoad,
                        endpoint: PropertyEndpointSide::Source,
                        source: event.source,
                        source_locator: procedure.source_locator(event.source).cloned(),
                    },
                );
            }
        }
    }
    reasons
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SelectedPathRelation {
    Exact,
    Ancestor,
    Disjoint,
    Unknown,
}

fn selected_path_relation(
    location: &AbstractLocation,
    selected: &PropertyLocationIdentity,
) -> SelectedPathRelation {
    let mut actual = Vec::with_capacity(location.path().selectors().len());
    for selector in location.path().selectors() {
        let selector = match selector {
            AccessSelector::Field(field) => PropertyAccessSelector::Field(field.locator().clone()),
            AccessSelector::Property(_) => return SelectedPathRelation::Unknown,
            AccessSelector::Index(IndexSelector::Exact(value)) => {
                let Ok(identity) = DurableValueIdentity::of(value) else {
                    return SelectedPathRelation::Unknown;
                };
                PropertyAccessSelector::IndexExact(identity)
            }
            AccessSelector::Index(IndexSelector::Constant(index)) => {
                PropertyAccessSelector::IndexConstant(*index)
            }
            AccessSelector::Index(IndexSelector::Any) => return SelectedPathRelation::Unknown,
        };
        actual.push(selector);
    }
    let mut expected = selected.access_path.to_vec();
    expected.push(PropertyAccessSelector::Field(selected.member.clone()));
    let common = actual.len().min(expected.len());
    if actual[..common] != expected[..common] {
        return SelectedPathRelation::Disjoint;
    }
    if actual.len() == expected.len() {
        SelectedPathRelation::Exact
    } else if actual.len() < expected.len() {
        SelectedPathRelation::Ancestor
    } else {
        // A read of an ancestor and a store below the selected cell do not
        // replace the selected property value.
        SelectedPathRelation::Disjoint
    }
}

fn selected_property_scope_reasons(
    snapshot: &ValueFlowSnapshot,
    relations: &[ValueFlowRelation],
    relation_limit: usize,
    selected_read: &PropertyReadRecord,
    projected_stores: &[PropertyStoreRecord],
    cancellation: &CancellationToken,
) -> (
    Vec<PropertyReachingIncompleteReason>,
    HashSet<(ProgramPointId, u32)>,
) {
    let procedure = snapshot.procedure();
    let mut reasons = Vec::new();
    let mut scoped_event_keys = HashSet::new();
    scoped_event_keys.insert((selected_read.point.id(), selected_read.event_index));
    for store in projected_stores
        .iter()
        .filter(|store| store.location == selected_read.location)
    {
        scoped_event_keys.insert((store.point.id(), store.event_index));
    }

    let selected_aliases = closed_local_allocation_aliases(
        snapshot,
        relations,
        &selected_read.location.receiver,
        cancellation,
    );
    if selected_aliases.is_none() {
        reasons.push(
            PropertyReachingIncompleteReason::SelectedAliasClosureUnavailable {
                receiver: selected_read.location.receiver.clone(),
            },
        );
    }

    let mut canonical_operations = CanonicalMemoryOperationKeys::new();
    for relation in relations.iter().take(relation_limit) {
        if cancellation.is_cancelled() {
            reasons.push(PropertyReachingIncompleteReason::Cancelled);
            break;
        }
        let event = relation_event(procedure, relation);
        let role = memory_relation_role(relation, &event.effect);
        if role == Some(MemoryRelationRole::Supplemental) {
            continue;
        }
        let (access_kind, is_store) = match &event.effect {
            SemanticEffect::MemoryStore { kind, .. }
                if matches!(
                    kind,
                    MemoryAccessKind::Field
                        | MemoryAccessKind::Property
                        | MemoryAccessKind::Index
                        | MemoryAccessKind::Dereference
                ) =>
            {
                (*kind, true)
            }
            SemanticEffect::MemoryLoad { kind, .. }
                if matches!(
                    kind,
                    MemoryAccessKind::Field
                        | MemoryAccessKind::Property
                        | MemoryAccessKind::Index
                        | MemoryAccessKind::Dereference
                ) =>
            {
                (*kind, false)
            }
            _ => continue,
        };
        if role == Some(MemoryRelationRole::Canonical) {
            record_canonical_memory_operation(&mut canonical_operations, relation);
        }
        let endpoint_side = if is_store {
            PropertyEndpointSide::Target
        } else {
            PropertyEndpointSide::Source
        };
        let location = if is_store {
            endpoint_location(&relation.target)
        } else {
            endpoint_location(&relation.source)
        };
        let source = event.source;
        let source_locator = procedure.source_locator(source).cloned();
        let Some(location) = location else {
            scoped_event_keys.insert((relation.point.id(), relation.event_index));
            reasons.push(
                PropertyReachingIncompleteReason::SelectedRelationEndpointUnavailable {
                    point: relation.point.id(),
                    event_index: relation.event_index,
                    relation: relation.kind,
                    endpoint: endpoint_side,
                    source,
                    source_locator,
                },
            );
            continue;
        };

        let receiver = location.object().identity().durable_identity().ok();
        let Some(receiver) = receiver else {
            scoped_event_keys.insert((relation.point.id(), relation.event_index));
            reasons.push(PropertyReachingIncompleteReason::SelectedRuntimeAccess {
                point: relation.point.id(),
                event_index: relation.event_index,
                source,
                source_locator,
                receiver: None,
            });
            continue;
        };

        let path_relation = selected_path_relation(location, &selected_read.location);
        if access_kind == MemoryAccessKind::Property
            || path_relation == SelectedPathRelation::Unknown
        {
            scoped_event_keys.insert((relation.point.id(), relation.event_index));
            reasons.push(PropertyReachingIncompleteReason::SelectedRuntimeAccess {
                point: relation.point.id(),
                event_index: relation.event_index,
                source,
                source_locator,
                receiver: Some(receiver),
            });
            continue;
        }

        if receiver != selected_read.location.receiver {
            let receiver_aliases =
                closed_local_allocation_aliases(snapshot, relations, &receiver, cancellation);
            match (selected_aliases.as_ref(), receiver_aliases) {
                (Some(selected_aliases), Some(receiver_aliases))
                    if receiver_aliases.is_disjoint(selected_aliases) =>
                {
                    continue;
                }
                (Some(_), Some(_)) => {}
                _ => {
                    scoped_event_keys.insert((relation.point.id(), relation.event_index));
                    reasons.push(PropertyReachingIncompleteReason::SelectedRuntimeAccess {
                        point: relation.point.id(),
                        event_index: relation.event_index,
                        source,
                        source_locator,
                        receiver: Some(receiver),
                    });
                    continue;
                }
            }
        }

        if (is_store && endpoint_value(&relation.source).is_none())
            || (!is_store && endpoint_value(&relation.target).is_none())
        {
            scoped_event_keys.insert((relation.point.id(), relation.event_index));
            reasons.push(
                PropertyReachingIncompleteReason::SelectedRelationEndpointUnavailable {
                    point: relation.point.id(),
                    event_index: relation.event_index,
                    relation: relation.kind,
                    endpoint: if is_store {
                        PropertyEndpointSide::Source
                    } else {
                        PropertyEndpointSide::Target
                    },
                    source,
                    source_locator: source_locator.clone(),
                },
            );
        }

        if path_relation == SelectedPathRelation::Exact {
            // A projection failure cannot remove this key from the selected
            // dependency set merely because no public store record survived.
            scoped_event_keys.insert((relation.point.id(), relation.event_index));
        }
        if is_store && path_relation == SelectedPathRelation::Ancestor {
            let mut projection_reasons = Vec::new();
            let projected_location = project_location(
                procedure,
                relation.point.id(),
                relation.event_index,
                location,
                &mut projection_reasons,
            );
            scoped_event_keys.insert((relation.point.id(), relation.event_index));
            reasons.push(PropertyReachingIncompleteReason::SelectedAncestorStore {
                point: relation.point.id(),
                event_index: relation.event_index,
                source,
                source_locator: source_locator.clone(),
                location: projected_location,
            });
            continue;
        }
        if path_relation == SelectedPathRelation::Disjoint {
            continue;
        }
    }

    for point in procedure.semantics().points() {
        if cancellation.is_cancelled() {
            reasons.push(PropertyReachingIncompleteReason::Cancelled);
            break;
        }
        let mut point_handle_slot = None;
        for (index, event) in point.events.iter().enumerate() {
            if cancellation.is_cancelled() {
                reasons.push(PropertyReachingIncompleteReason::Cancelled);
                break;
            }
            let (relation, endpoint, location) = match event.effect {
                SemanticEffect::MemoryStore {
                    kind:
                        MemoryAccessKind::Field
                        | MemoryAccessKind::Property
                        | MemoryAccessKind::Index
                        | MemoryAccessKind::Dereference,
                    location,
                    ..
                } => (
                    ValueFlowRelationKind::MemoryStore,
                    PropertyEndpointSide::Target,
                    location,
                ),
                SemanticEffect::MemoryLoad {
                    kind:
                        MemoryAccessKind::Field
                        | MemoryAccessKind::Property
                        | MemoryAccessKind::Index
                        | MemoryAccessKind::Dereference,
                    location,
                    ..
                } => (
                    ValueFlowRelationKind::MemoryLoad,
                    PropertyEndpointSide::Source,
                    location,
                ),
                _ => continue,
            };
            let event_index =
                u32::try_from(index).expect("validated event indices fit semantic IDs");
            let point_handle = point_handle_slot.get_or_insert_with(|| {
                procedure
                    .point_handle(point.id)
                    .expect("a retained semantic point has a procedure handle")
            });
            if !canonical_memory_operation_is_present(
                &canonical_operations,
                point_handle,
                event_index,
                location,
                snapshot.context(),
            ) {
                // The selected proof requires the producer's canonical row;
                // alternatives and supplemental rows do not establish it.
                scoped_event_keys.insert((point.id, event_index));
                reasons.push(
                    PropertyReachingIncompleteReason::SelectedRelationEndpointUnavailable {
                        point: point.id,
                        event_index,
                        relation,
                        endpoint,
                        source: event.source,
                        source_locator: procedure.source_locator(event.source).cloned(),
                    },
                );
            }
        }
    }

    for gap in procedure.semantics().gaps() {
        // A scoped storage projection does not invent a new discharge for
        // executable runtime behavior or control. Only the exact publishing
        // snapshot's reviewed discharge can close these obligations. Preserve
        // full gap provenance even when its value is not a selected endpoint.
        if !snapshot.gap_is_discharged(gap.id) {
            reasons
                .push(PropertyReachingIncompleteReason::SelectedSemanticGap { gap: gap.clone() });
        }
    }

    (reasons, scoped_event_keys)
}

fn incomplete_reason_event_key(
    reason: &PropertyReachingIncompleteReason,
) -> Option<(ProgramPointId, u32)> {
    match reason {
        PropertyReachingIncompleteReason::UnsupportedLocation { point, event_index }
        | PropertyReachingIncompleteReason::DurableIdentityUnavailable {
            point, event_index, ..
        }
        | PropertyReachingIncompleteReason::SourceMappingUnavailable {
            point, event_index, ..
        }
        | PropertyReachingIncompleteReason::StoreEvidenceIncomplete {
            point, event_index, ..
        }
        | PropertyReachingIncompleteReason::ReadEvidenceIncomplete {
            point, event_index, ..
        }
        | PropertyReachingIncompleteReason::FieldMemoryEndpointUnavailable {
            point,
            event_index,
            ..
        }
        | PropertyReachingIncompleteReason::EvaluationEndpointUnavailable {
            point,
            event_index,
            ..
        }
        | PropertyReachingIncompleteReason::EvaluationEvidenceIncomplete {
            point,
            event_index,
            ..
        }
        | PropertyReachingIncompleteReason::SelectedRelationEndpointUnavailable {
            point,
            event_index,
            ..
        }
        | PropertyReachingIncompleteReason::SelectedRuntimeAccess {
            point, event_index, ..
        } => Some((*point, *event_index)),
        PropertyReachingIncompleteReason::SelectedAncestorStore {
            point, event_index, ..
        } => Some((*point, *event_index)),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn derive_property_reaching_from_records<G>(
    procedure: ProcedureHandle,
    graph: &G,
    entry: ProgramPointId,
    mut stores: Vec<PropertyStoreRecord>,
    mut reads: Vec<PropertyReadRecord>,
    evaluations: Vec<EvaluationRelationRecord>,
    property_coverage: CandidateCoverage,
    mut incomplete_reasons: Vec<PropertyReachingIncompleteReason>,
    evaluation_incomplete_reasons: Vec<PropertyReachingIncompleteReason>,
    limits: PropertyReachingLimits,
    cancellation: &CancellationToken,
) -> PropertyReachingResult
where
    G: DenseBidirectionalGraph<Node = ProgramPointId>,
{
    stores.sort_by_key(|store| (store.point.id(), store.event_index));
    reads.sort_by_key(|read| (read.point.id(), read.event_index));

    let mut reaching = Vec::new();
    let mut cfg_work = CfgAlgorithmWork::default();
    if !stores.is_empty() && !reads.is_empty() && !cancellation.is_cancelled() {
        let mut stores_by_key: HashMap<PropertyLocationIdentity, Vec<usize>> = HashMap::new();
        for (index, store) in stores.iter().enumerate() {
            stores_by_key
                .entry(store.location.clone())
                .or_default()
                .push(index);
        }

        let mut stores_by_node = vec![Vec::<usize>::new(); graph.node_count()];
        for (index, store) in stores.iter().enumerate() {
            let node_index = graph
                .node_index(store.point.id())
                .expect("a retained store belongs to the supplied procedure graph");
            stores_by_node[node_index].push(index);
        }
        for node_stores in &mut stores_by_node {
            node_stores.sort_by_key(|index| stores[*index].event_index);
        }

        let mut facts = GenKillFacts::new(graph.node_count(), stores.len());
        for (node_index, node_stores) in stores_by_node.iter().enumerate() {
            let mut final_stores = Vec::<usize>::new();
            let mut strong_keys = HashSet::new();
            for index in node_stores {
                let store = &stores[*index];
                if store.strong_update {
                    strong_keys.insert(store.location.clone());
                    final_stores.retain(|prior| stores[*prior].location != store.location);
                }
                final_stores.push(*index);
            }
            for key in strong_keys {
                for definition in stores_by_key
                    .get(&key)
                    .expect("every strong-update key has a store definition")
                {
                    facts.record_killed(node_index, *definition);
                }
            }
            for definition in final_stores {
                facts.record_generated(node_index, definition);
            }
        }

        let mut budget = CfgAlgorithmBudget::new(limits.cfg_work);
        let mut request = CfgAlgorithmRequest::new(&mut budget, cancellation);
        let reachable = match forward_reachability(graph, entry, &mut request) {
            Ok(value) => value,
            Err(error) => {
                cfg_work = budget.used();
                incomplete_reasons.push(PropertyReachingIncompleteReason::Reachability(error));
                return PropertyReachingResult {
                    procedure,
                    stores: stores.into_boxed_slice(),
                    reads: reads.into_boxed_slice(),
                    reaching: reaching.into_boxed_slice(),
                    evaluations: evaluations.into_boxed_slice(),
                    coverage: property_coverage,
                    incomplete_reasons: incomplete_reasons.into_boxed_slice(),
                    evaluation_incomplete_reasons: evaluation_incomplete_reasons.into_boxed_slice(),
                    cfg_work,
                };
            }
        };
        let reaching_sets = match reaching_definitions(graph, entry, &facts, &mut request) {
            Ok(value) => value,
            Err(error) => {
                cfg_work = budget.used();
                incomplete_reasons
                    .push(PropertyReachingIncompleteReason::ReachingDefinitions(error));
                return PropertyReachingResult {
                    procedure,
                    stores: stores.into_boxed_slice(),
                    reads: reads.into_boxed_slice(),
                    reaching: reaching.into_boxed_slice(),
                    evaluations: evaluations.into_boxed_slice(),
                    coverage: property_coverage,
                    incomplete_reasons: incomplete_reasons.into_boxed_slice(),
                    evaluation_incomplete_reasons: evaluation_incomplete_reasons.into_boxed_slice(),
                    cfg_work,
                };
            }
        };
        let dominance = match dominators(graph, entry, &mut request) {
            Ok(value) => Some(value),
            Err(error) => {
                incomplete_reasons.push(PropertyReachingIncompleteReason::Dominators(error));
                None
            }
        };

        'reads: for read in &reads {
            if cancellation.is_cancelled() {
                incomplete_reasons.push(PropertyReachingIncompleteReason::Cancelled);
                break;
            }
            let node_index = graph
                .node_index(read.point.id())
                .expect("a retained read belongs to the supplied procedure graph");
            if !reachable.contains(graph, read.point.id()) {
                continue;
            }
            let mut candidates = reaching_sets
                .reaching_in(node_index)
                .filter(|index| stores[*index].location == read.location)
                .collect::<Vec<_>>();
            for index in &stores_by_node[node_index] {
                let store = &stores[*index];
                if store.event_index >= read.event_index {
                    break;
                }
                if store.location != read.location {
                    continue;
                }
                if store.strong_update {
                    candidates.retain(|prior| stores[*prior].location != store.location);
                }
                candidates.push(*index);
            }
            candidates.sort_unstable();
            candidates.dedup();
            let unique_candidate = candidates.len() == 1;
            for index in candidates {
                if cancellation.is_cancelled() {
                    incomplete_reasons.push(PropertyReachingIncompleteReason::Cancelled);
                    break 'reads;
                }
                if reaching.len() >= limits.max_reaching_pairs {
                    incomplete_reasons.push(
                        PropertyReachingIncompleteReason::ReachingPairBudgetExceeded {
                            limit: limits.max_reaching_pairs,
                            observed: reaching.len(),
                        },
                    );
                    break 'reads;
                }
                if let Err(error) = request.visit_pair::<ProgramPointId>() {
                    incomplete_reasons.push(PropertyReachingIncompleteReason::ReachingPairs(error));
                    break 'reads;
                }
                let store = &stores[index];
                let exact = unique_candidate
                    && dominance.as_ref().is_some_and(|dominator| {
                        dominator.dominates(graph, store.point.id(), read.point.id())
                    })
                    && store.is_proven_complete()
                    && read.is_proven_complete()
                    && property_coverage.is_exhaustive()
                    && incomplete_reasons.is_empty();
                reaching.push(PropertyReachingRelation {
                    store: store.clone(),
                    read: read.clone(),
                    certainty: if exact {
                        PropertyReachCertainty::Exact
                    } else {
                        PropertyReachCertainty::May
                    },
                    proof: combined_proof(store, read),
                    completeness: combined_completeness(store, read),
                    coverage: property_coverage,
                });
            }
        }
        cfg_work = budget.used();
    } else if cancellation.is_cancelled() {
        incomplete_reasons.push(PropertyReachingIncompleteReason::Cancelled);
    }

    PropertyReachingResult {
        procedure,
        stores: stores.into_boxed_slice(),
        reads: reads.into_boxed_slice(),
        reaching: reaching.into_boxed_slice(),
        evaluations: evaluations.into_boxed_slice(),
        coverage: property_coverage,
        incomplete_reasons: incomplete_reasons.into_boxed_slice(),
        evaluation_incomplete_reasons: evaluation_incomplete_reasons.into_boxed_slice(),
        cfg_work,
    }
}

/// Property completeness is narrower than whole-snapshot dispatch coverage.
/// An unresolved call that never receives a locally allocated receiver cannot
/// create an alias or store for that receiver, while a call, capture, return,
/// or memory store that does receive one keeps its property key open. This
/// structured escape check lets an unrelated open dispatch coexist with an
/// exact property relation without treating the snapshot's global coverage as
/// receiver coverage.
fn property_candidate_coverage<'store, 'read>(
    snapshot: &ValueFlowSnapshot,
    relations: &[ValueFlowRelation],
    relation_limit: usize,
    stores: impl Iterator<Item = &'store PropertyLocationIdentity>,
    reads: impl Iterator<Item = &'read PropertyLocationIdentity>,
    cancellation: &CancellationToken,
) -> CandidateCoverage {
    if relation_limit < relations.len() || snapshot.coverage().is_truncated() {
        return CandidateCoverage::Truncated;
    }
    let stores = stores.collect::<Vec<_>>();
    let reads = reads.collect::<Vec<_>>();
    let stored_paths = stores
        .iter()
        .map(|location| {
            (
                &location.receiver,
                location.access_path.as_ref(),
                &location.member,
            )
        })
        .collect::<HashSet<_>>();
    // Replacing an ancestor object can establish descendants without a store
    // row for each descendant. Until those initializer rows are published,
    // the exact-key projection cannot certify their exhaustive coverage.
    if reads.iter().any(|read| {
        read.access_path
            .iter()
            .enumerate()
            .any(|(index, selector)| {
                let PropertyAccessSelector::Field(member) = selector else {
                    return false;
                };
                stored_paths.contains(&(&read.receiver, &read.access_path[..index], member))
            })
    }) {
        return CandidateCoverage::Open;
    }
    let mut receivers = stores
        .into_iter()
        .map(|location| location.receiver.clone())
        .collect::<HashSet<_>>();
    receivers.extend(reads.into_iter().map(|location| location.receiver.clone()));
    if receivers.is_empty() {
        return CandidateCoverage::Exhaustive;
    }
    if receivers.iter().all(|receiver| {
        closed_local_allocation_aliases(snapshot, relations, receiver, cancellation).is_some()
    }) {
        CandidateCoverage::Exhaustive
    } else {
        CandidateCoverage::Open
    }
}

/// Return the exact procedure-local aliases of one allocation when none of
/// them crosses a boundary that can hide property stores. `None` is the typed
/// open case. The walk consumes only value-flow endpoints and semantic gap
/// subjects; it never reconstructs an alias from spelling or source order.
fn closed_local_allocation_aliases(
    snapshot: &ValueFlowSnapshot,
    relations: &[ValueFlowRelation],
    receiver: &crate::analyzer::semantic::oracle::DurableObjectIdentity,
    cancellation: &CancellationToken,
) -> Option<HashSet<ValueId>> {
    if !matches!(
        receiver,
        crate::analyzer::semantic::oracle::DurableObjectIdentity::Allocation { .. }
            | crate::analyzer::semantic::oracle::DurableObjectIdentity::Value(_)
    ) {
        return None;
    }

    let mut aliases = HashSet::new();
    let mut found_allocation = false;
    for relation in relations {
        if cancellation.is_cancelled() {
            return None;
        }
        if relation.kind != ValueFlowRelationKind::Allocation {
            continue;
        }
        let ValueFlowEndpoint::Location(location) = &relation.source else {
            continue;
        };
        let ValueFlowEndpoint::Value(value) = &relation.target else {
            return None;
        };
        let receiver_matches = match receiver {
            crate::analyzer::semantic::oracle::DurableObjectIdentity::Allocation { .. } => {
                location.path().root().durable_identity().ok().as_ref() == Some(receiver)
            }
            crate::analyzer::semantic::oracle::DurableObjectIdentity::Value(identity) => {
                crate::analyzer::semantic::oracle::DurableValueIdentity::of(value)
                    .ok()
                    .as_ref()
                    == Some(identity)
            }
            _ => false,
        };
        if !receiver_matches {
            continue;
        }
        found_allocation = true;
        if !relation.is_proven_complete() {
            return None;
        }
        aliases.insert(value.id());
    }
    if !found_allocation {
        return None;
    }

    let mut changed = true;
    while changed {
        changed = false;
        for relation in relations {
            if cancellation.is_cancelled() {
                return None;
            }
            if relation.kind != ValueFlowRelationKind::Assignment || relation.transfer.is_some() {
                continue;
            }
            let (ValueFlowEndpoint::Value(source), ValueFlowEndpoint::Value(target)) =
                (&relation.source, &relation.target)
            else {
                continue;
            };
            if !aliases.contains(&source.id()) {
                continue;
            }
            if !relation.is_proven_complete() {
                return None;
            }
            changed |= aliases.insert(target.id());
        }
    }

    if cancellation.is_cancelled() {
        return None;
    }
    let semantics = snapshot.procedure().semantics();
    if semantics.call_sites().iter().any(|call| {
        call.receiver.is_some_and(|value| aliases.contains(&value))
            || call
                .arguments
                .iter()
                .any(|argument| aliases.contains(&argument.value))
    }) {
        return None;
    }
    if relations.iter().any(|relation| {
        let ValueFlowEndpoint::Value(source) = &relation.source else {
            return false;
        };
        aliases.contains(&source.id())
            && matches!(
                relation.kind,
                ValueFlowRelationKind::Parameter
                    | ValueFlowRelationKind::Receiver
                    | ValueFlowRelationKind::NormalReturn
                    | ValueFlowRelationKind::ExceptionalReturn
                    | ValueFlowRelationKind::MemoryStore
                    | ValueFlowRelationKind::Capture
                    | ValueFlowRelationKind::HandlerBinding
                    | ValueFlowRelationKind::LanguageDefined
            )
    }) {
        return None;
    }
    if semantics.gaps().iter().any(|gap| {
        !snapshot.gap_is_discharged(gap.id)
            && (gap.impacts.contains(SemanticGapImpact::Aliasing)
                || gap.impacts.contains(SemanticGapImpact::HeapRead)
                || gap.impacts.contains(SemanticGapImpact::HeapWrite))
            && property_gap_mentions_alias(semantics, gap.subject, &aliases)
    }) {
        return None;
    }
    Some(aliases)
}

fn property_gap_mentions_alias(
    semantics: &crate::analyzer::semantic::ir::ProcedureSemantics,
    subject: SemanticGapSubject,
    aliases: &HashSet<ValueId>,
) -> bool {
    match subject {
        SemanticGapSubject::Procedure
        | SemanticGapSubject::Point
        | SemanticGapSubject::AsyncContinuation { .. } => true,
        SemanticGapSubject::Value(value) => aliases.contains(&value),
        SemanticGapSubject::MemoryLocation(location) => semantics
            .memory_location(location)
            .is_some_and(|location| aliases.iter().any(|value| location.kind.uses_value(*value))),
        SemanticGapSubject::Capture(capture) => semantics
            .captures()
            .iter()
            .find(|candidate| candidate.id == capture)
            .is_some_and(|capture| match capture.captured {
                CaptureSource::Value(value) => aliases.contains(&value),
                CaptureSource::Location(location) => {
                    semantics.memory_location(location).is_some_and(|location| {
                        aliases.iter().any(|value| location.kind.uses_value(*value))
                    })
                }
            }),
        SemanticGapSubject::CallSite(call_site)
        | SemanticGapSubject::CallContinuation { call_site, .. } => {
            semantics.call_site(call_site).is_some_and(|call| {
                call.receiver.is_some_and(|value| aliases.contains(&value))
                    || call
                        .arguments
                        .iter()
                        .any(|argument| aliases.contains(&argument.value))
            })
        }
    }
}

fn combined_proof(store: &PropertyStoreRecord, read: &PropertyReadRecord) -> ProofStatus {
    combine_proof(
        &store.proof,
        &read.proof,
        "store or read evidence is unproven",
    )
}

fn combined_completeness(
    store: &PropertyStoreRecord,
    read: &PropertyReadRecord,
) -> EvidenceCompleteness {
    combine_completeness(
        &store.completeness,
        &read.completeness,
        "store or read evidence is partial",
    )
}

fn combine_proof(left: &ProofStatus, right: &ProofStatus, reason: &'static str) -> ProofStatus {
    if matches!(left, ProofStatus::Proven) && matches!(right, ProofStatus::Proven) {
        ProofStatus::Proven
    } else {
        ProofStatus::Unproven(reason.into())
    }
}

fn combine_completeness(
    left: &EvidenceCompleteness,
    right: &EvidenceCompleteness,
    reason: &'static str,
) -> EvidenceCompleteness {
    if matches!(left, EvidenceCompleteness::Complete)
        && matches!(right, EvidenceCompleteness::Complete)
    {
        EvidenceCompleteness::Complete
    } else {
        EvidenceCompleteness::Partial(reason.into())
    }
}

fn endpoint_location(endpoint: &ValueFlowEndpoint) -> Option<&AbstractLocation> {
    match endpoint {
        ValueFlowEndpoint::Location(location) => Some(location),
        _ => None,
    }
}

fn endpoint_value(endpoint: &ValueFlowEndpoint) -> Option<ValueHandle> {
    match endpoint {
        ValueFlowEndpoint::Value(value) => Some(value.clone()),
        _ => None,
    }
}

fn project_store(
    procedure: &ProcedureHandle,
    relation: &ValueFlowRelation,
    location: &AbstractLocation,
    value: ValueHandle,
    incomplete_reasons: &mut Vec<PropertyReachingIncompleteReason>,
) -> Option<PropertyStoreRecord> {
    let location_identity = project_location(
        procedure,
        relation.point.id(),
        relation.event_index,
        location,
        incomplete_reasons,
    )?;
    let source = relation_source_mapping(procedure, relation);
    let source_locator = source_locator(
        procedure,
        relation.point.id(),
        relation.event_index,
        source,
        incomplete_reasons,
    )?;
    if !relation.is_proven_complete() {
        incomplete_reasons.push(PropertyReachingIncompleteReason::StoreEvidenceIncomplete {
            point: relation.point.id(),
            event_index: relation.event_index,
            proof: relation.proof.clone(),
            completeness: relation.completeness.clone(),
        });
    }
    Some(PropertyStoreRecord {
        procedure: procedure.clone(),
        point: relation.point.clone(),
        event_index: relation.event_index,
        source,
        source_locator,
        value,
        location: location_identity,
        proof: relation.proof.clone(),
        completeness: relation.completeness.clone(),
        strong_update: relation.strong_update,
        timing: relation.timing_claim(),
    })
}

fn project_read(
    procedure: &ProcedureHandle,
    relation: &ValueFlowRelation,
    location: &AbstractLocation,
    value: ValueHandle,
    incomplete_reasons: &mut Vec<PropertyReachingIncompleteReason>,
) -> Option<PropertyReadRecord> {
    let location_identity = project_location(
        procedure,
        relation.point.id(),
        relation.event_index,
        location,
        incomplete_reasons,
    )?;
    let source = relation_source_mapping(procedure, relation);
    let source_locator = source_locator(
        procedure,
        relation.point.id(),
        relation.event_index,
        source,
        incomplete_reasons,
    )?;
    if !relation.is_proven_complete() {
        incomplete_reasons.push(PropertyReachingIncompleteReason::ReadEvidenceIncomplete {
            point: relation.point.id(),
            event_index: relation.event_index,
            proof: relation.proof.clone(),
            completeness: relation.completeness.clone(),
        });
    }
    Some(PropertyReadRecord {
        procedure: procedure.clone(),
        point: relation.point.clone(),
        event_index: relation.event_index,
        source,
        source_locator,
        value,
        location: location_identity,
        proof: relation.proof.clone(),
        completeness: relation.completeness.clone(),
        timing: relation.timing_claim(),
    })
}

/// Produce read-to-establishment relations entirely from oracle relations.
/// Assignment into a binding terminates an evaluation; all other same-step
/// value/value relations are dependency edges within that evaluation.
fn evaluation_relations(
    snapshot: &ValueFlowSnapshot,
    relation_limit: usize,
    pair_limit: usize,
    cancellation: &CancellationToken,
    incomplete_reasons: &mut Vec<PropertyReachingIncompleteReason>,
) -> Vec<EvaluationRelationRecord> {
    struct Dependency<'a> {
        source: ValueHandle,
        relation: &'a ValueFlowRelation,
    }

    let procedure = snapshot.procedure();
    let relations = &snapshot.relations()[..relation_limit];
    let mut dependencies: HashMap<ValueId, Vec<Dependency<'_>>> = HashMap::new();
    let mut establishments = Vec::new();
    let mut reads = Vec::new();

    for relation in relations {
        if cancellation.is_cancelled() {
            incomplete_reasons.push(PropertyReachingIncompleteReason::Cancelled);
            break;
        }
        let event = relation_event(procedure, relation);
        let establishes_binding = matches!(
            event.effect,
            SemanticEffect::Assignment { target, .. } if is_binding_id(procedure, target)
        );
        if (establishes_binding
            || relation.timing_claim().timing() == ExecutionTiming::SameEvaluation)
            && !relation.is_proven_complete()
        {
            incomplete_reasons.push(
                PropertyReachingIncompleteReason::EvaluationEvidenceIncomplete {
                    point: relation.point.id(),
                    event_index: relation.event_index,
                    proof: relation.proof.clone(),
                    completeness: relation.completeness.clone(),
                },
            );
        }
        if let SemanticEffect::Assignment { target, value } = event.effect
            && is_binding_id(procedure, target)
        {
            let value = procedure
                .value_handle(value)
                .expect("a validated assignment names its procedure value");
            if let Some(record) = evaluation_establishment(procedure, relation, value) {
                establishments.push(record);
            } else {
                record_evaluation_source_failure(procedure, relation, incomplete_reasons);
            }
            continue;
        }
        if relation.timing_claim().timing() != ExecutionTiming::SameEvaluation {
            continue;
        }
        let dependency = match event.effect {
            SemanticEffect::Assignment { target, value } if !is_binding_id(procedure, target) => {
                Some((value, target))
            }
            SemanticEffect::ValueFlow { source, target, .. } => Some((source, target)),
            SemanticEffect::MemoryLoad {
                location, result, ..
            } => {
                procedure
                    .semantics()
                    .memory_location(location)
                    .and_then(|location| match location.kind {
                        // A keyed property load computes its result from the
                        // same base value a field load does, so it carries the
                        // same evaluation dependence.
                        MemoryLocationKind::Field { base, .. }
                        | MemoryLocationKind::Property { base, .. }
                        | MemoryLocationKind::Index { base, .. } => Some((base, result)),
                        MemoryLocationKind::Dereference { address } => Some((address, result)),
                        MemoryLocationKind::LexicalCell { binding }
                        | MemoryLocationKind::Capture {
                            binding: Some(binding),
                            ..
                        } => Some((binding, result)),
                        MemoryLocationKind::Static { .. }
                        | MemoryLocationKind::Capture { binding: None, .. } => None,
                    })
            }
            _ => None,
        };
        if let Some((source, target)) = dependency {
            dependencies.entry(target).or_default().push(Dependency {
                source: procedure
                    .value_handle(source)
                    .expect("a validated value dependence names its source"),
                relation,
            });
        }
        if let SemanticEffect::ValueFlow { source, target, .. } = event.effect
            && is_binding_id(procedure, source)
        {
            let value = procedure
                .value_handle(target)
                .expect("a validated binding read names its produced value");
            if let Some(record) = evaluation_read(procedure, relation, value) {
                reads.push(record);
            } else {
                record_evaluation_source_failure(procedure, relation, incomplete_reasons);
            }
        }
    }

    let mut rows = Vec::new();
    'establishments: for establishment in establishments {
        let mut stack = vec![(
            establishment.value.clone(),
            establishment.proof.clone(),
            establishment.completeness.clone(),
        )];
        let mut strongest = HashMap::<ValueId, bool>::new();
        let mut reached = HashMap::<ValueId, (ProofStatus, EvidenceCompleteness)>::new();
        while let Some((value, proof, completeness)) = stack.pop() {
            if cancellation.is_cancelled() {
                incomplete_reasons.push(PropertyReachingIncompleteReason::Cancelled);
                break 'establishments;
            }
            let complete = matches!(proof, ProofStatus::Proven)
                && matches!(completeness, EvidenceCompleteness::Complete);
            if strongest
                .get(&value.id())
                .is_some_and(|known| *known || !complete)
            {
                continue;
            }
            strongest.insert(value.id(), complete);
            reached.insert(value.id(), (proof.clone(), completeness.clone()));
            if let Some(edges) = dependencies.get(&value.id()) {
                for edge in edges {
                    stack.push((
                        edge.source.clone(),
                        combine_proof(
                            &proof,
                            &edge.relation.proof,
                            "an evaluation-dependence edge is unproven",
                        ),
                        combine_completeness(
                            &completeness,
                            &edge.relation.completeness,
                            "an evaluation-dependence edge is partial",
                        ),
                    ));
                }
            }
        }
        for read in &reads {
            let Some((path_proof, path_completeness)) = reached.get(&read.value.id()) else {
                continue;
            };
            if rows.len() >= pair_limit {
                incomplete_reasons.push(
                    PropertyReachingIncompleteReason::ReachingPairBudgetExceeded {
                        limit: pair_limit,
                        observed: rows.len(),
                    },
                );
                break 'establishments;
            }
            let proof = combine_proof(
                path_proof,
                &read.proof,
                "establishment, dependence, or read evidence is unproven",
            );
            let completeness = combine_completeness(
                path_completeness,
                &read.completeness,
                "establishment, dependence, or read evidence is partial",
            );
            if !matches!(proof, ProofStatus::Proven)
                || !matches!(completeness, EvidenceCompleteness::Complete)
            {
                incomplete_reasons.push(
                    PropertyReachingIncompleteReason::EvaluationEvidenceIncomplete {
                        point: establishment.point.id(),
                        event_index: establishment.event_index,
                        proof: proof.clone(),
                        completeness: completeness.clone(),
                    },
                );
            }
            rows.push(EvaluationRelationRecord {
                establishment: establishment.clone(),
                read: read.clone(),
                proof: proof.clone(),
                completeness: completeness.clone(),
                coverage: CandidateCoverage::Exhaustive,
                timing: ExecutionTimingClaim::new(
                    ExecutionTiming::SameEvaluation,
                    proof,
                    completeness,
                ),
            });
        }
    }
    rows.sort_by_key(|relation| {
        (
            relation.establishment.point.id(),
            relation.establishment.event_index,
            relation.read.point.id(),
            relation.read.event_index,
        )
    });
    rows
}

fn evaluation_establishment(
    procedure: &ProcedureHandle,
    relation: &ValueFlowRelation,
    value: ValueHandle,
) -> Option<EvaluationEstablishmentRecord> {
    let source = relation_source_mapping(procedure, relation);
    Some(EvaluationEstablishmentRecord {
        procedure: procedure.clone(),
        point: relation.point.clone(),
        event_index: relation.event_index,
        source,
        source_locator: procedure
            .semantics()
            .source_mapping(source)?
            .locator
            .clone(),
        value,
        kind: relation.kind,
        proof: relation.proof.clone(),
        completeness: relation.completeness.clone(),
    })
}

fn evaluation_read(
    procedure: &ProcedureHandle,
    relation: &ValueFlowRelation,
    value: ValueHandle,
) -> Option<EvaluationReadRecord> {
    let source = relation_source_mapping(procedure, relation);
    Some(EvaluationReadRecord {
        procedure: procedure.clone(),
        point: relation.point.clone(),
        event_index: relation.event_index,
        source,
        source_locator: procedure
            .semantics()
            .source_mapping(source)?
            .locator
            .clone(),
        value,
        proof: relation.proof.clone(),
        completeness: relation.completeness.clone(),
    })
}

fn record_evaluation_source_failure(
    procedure: &ProcedureHandle,
    relation: &ValueFlowRelation,
    incomplete_reasons: &mut Vec<PropertyReachingIncompleteReason>,
) {
    incomplete_reasons.push(PropertyReachingIncompleteReason::SourceMappingUnavailable {
        point: relation.point.id(),
        event_index: relation.event_index,
        source: relation_source_mapping(procedure, relation),
    });
}

fn is_binding_id(procedure: &ProcedureHandle, value: ValueId) -> bool {
    procedure
        .semantics()
        .value(value)
        .is_some_and(|value| value.kind.is_binding())
}

fn relation_event<'a>(
    procedure: &'a ProcedureHandle,
    relation: &ValueFlowRelation,
) -> &'a crate::analyzer::semantic::ir::SemanticEvent {
    procedure
        .semantics()
        .point(relation.point.id())
        .expect("a validated value-flow relation belongs to its retained point")
        .events
        .get(relation.event_index as usize)
        .expect("a validated value-flow relation names its retained event")
}

fn field_memory_event(procedure: &ProcedureHandle, relation: &ValueFlowRelation) -> bool {
    let event = procedure
        .semantics()
        .point(relation.point.id())
        .expect("a validated value-flow relation belongs to its retained point")
        .events
        .get(relation.event_index as usize)
        .expect("a validated value-flow relation names a retained event");
    matches!(
        event.effect,
        crate::analyzer::semantic::ir::SemanticEffect::MemoryStore {
            kind: MemoryAccessKind::Field,
            ..
        } | crate::analyzer::semantic::ir::SemanticEffect::MemoryLoad {
            kind: MemoryAccessKind::Field,
            ..
        }
    )
}

fn source_locator(
    procedure: &ProcedureHandle,
    point: ProgramPointId,
    event_index: u32,
    source: SourceMappingId,
    incomplete_reasons: &mut Vec<PropertyReachingIncompleteReason>,
) -> Option<SemanticLocator> {
    let Some(locator) = procedure.source_locator(source) else {
        incomplete_reasons.push(PropertyReachingIncompleteReason::SourceMappingUnavailable {
            point,
            event_index,
            source,
        });
        return None;
    };
    Some(locator.clone())
}

fn relation_source_mapping(
    procedure: &ProcedureHandle,
    relation: &ValueFlowRelation,
) -> SourceMappingId {
    relation_event(procedure, relation).source
}

fn project_location(
    _procedure: &ProcedureHandle,
    point: ProgramPointId,
    event_index: u32,
    location: &AbstractLocation,
    incomplete_reasons: &mut Vec<PropertyReachingIncompleteReason>,
) -> Option<PropertyLocationIdentity> {
    let selectors = location.path().selectors();
    let member = match selectors.last() {
        Some(AccessSelector::Field(member)) => member,
        // A runtime property key is exact syntax with no declaration locator,
        // so it cannot become the durable member identity this projection
        // keys on. Report the typed gap instead of minting a locator from the
        // key text.
        Some(AccessSelector::Property(_)) => {
            incomplete_reasons
                .push(PropertyReachingIncompleteReason::UnsupportedLocation { point, event_index });
            return None;
        }
        Some(AccessSelector::Index(_)) | None => return None,
    };
    if !location.path().is_exact() {
        incomplete_reasons
            .push(PropertyReachingIncompleteReason::UnsupportedLocation { point, event_index });
        return None;
    }
    let receiver = match location.object().identity().durable_identity() {
        Ok(identity) => identity,
        Err(reason) => {
            incomplete_reasons.push(
                PropertyReachingIncompleteReason::DurableIdentityUnavailable {
                    point,
                    event_index,
                    reason,
                },
            );
            return None;
        }
    };
    let mut access_path = Vec::with_capacity(selectors.len().saturating_sub(1));
    for selector in &selectors[..selectors.len() - 1] {
        let selector = match selector {
            AccessSelector::Field(field) => PropertyAccessSelector::Field(field.locator().clone()),
            // See the terminal selector above: a keyed property has no durable
            // locator, so an intermediate one leaves the access path without an
            // exact key.
            AccessSelector::Property(_) => {
                incomplete_reasons.push(PropertyReachingIncompleteReason::UnsupportedLocation {
                    point,
                    event_index,
                });
                return None;
            }
            AccessSelector::Index(IndexSelector::Exact(value)) => {
                match DurableValueIdentity::of(value) {
                    Ok(identity) => PropertyAccessSelector::IndexExact(identity),
                    Err(reason) => {
                        incomplete_reasons.push(
                            PropertyReachingIncompleteReason::DurableIdentityUnavailable {
                                point,
                                event_index,
                                reason,
                            },
                        );
                        return None;
                    }
                }
            }
            AccessSelector::Index(IndexSelector::Constant(index)) => {
                PropertyAccessSelector::IndexConstant(*index)
            }
            AccessSelector::Index(IndexSelector::Any) => {
                incomplete_reasons.push(PropertyReachingIncompleteReason::UnsupportedLocation {
                    point,
                    event_index,
                });
                return None;
            }
        };
        access_path.push(selector);
    }
    Some(PropertyLocationIdentity {
        receiver,
        access_path: access_path.into_boxed_slice(),
        member: member.locator().clone(),
    })
}
