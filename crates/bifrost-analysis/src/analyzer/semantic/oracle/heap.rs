use std::fmt;

use super::super::ir::ProofStatus;
use super::error::OracleContractError;
use super::limits::OracleLimits;
use super::model::{
    AbstractLocation, AbstractObject, AccessPathAtPoint, AliasQuery, ObjectCardinality,
    StoreAtPoint, ValueAtPoint,
};
use super::relation::{
    CandidateCoverage, EvidenceBacked, OracleCandidate, OracleRelationHandle, OracleRelationKind,
    OracleRelationOwner, OracleSet, validate_candidate_provenance,
    validate_retained_relation_arenas,
};

/// Pairwise alias relation at one observation point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AliasRelation {
    MustAlias,
    MayAlias,
    Disjoint,
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PointsToResult {
    query: ValueAtPoint,
    objects: OracleSet<AbstractObject>,
}

impl PointsToResult {
    pub fn new<I>(
        query: ValueAtPoint,
        candidates: I,
        coverage: CandidateCoverage,
        limits: OracleLimits,
    ) -> Result<Self, OracleContractError>
    where
        I: IntoIterator<Item = OracleCandidate<AbstractObject>>,
    {
        let objects = OracleSet::bounded_objects(candidates, coverage, limits);
        validate_candidate_provenance(
            objects.candidates(),
            &OracleRelationOwner::PointsTo(Box::new(query.clone())),
            OracleRelationKind::PointsTo,
        )?;
        for candidate in objects.candidates() {
            candidate.value().validate_at(query.point().procedure())?;
        }
        validate_retained_relation_arenas(
            objects
                .candidates()
                .iter()
                .flat_map(OracleCandidate::provenance),
            limits,
        )?;
        Ok(Self { query, objects })
    }

    pub fn query(&self) -> &ValueAtPoint {
        &self.query
    }

    pub fn objects(&self) -> &OracleSet<AbstractObject> {
        &self.objects
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LocationResult {
    query: AccessPathAtPoint,
    locations: OracleSet<AbstractLocation>,
}

impl LocationResult {
    pub fn new<I>(
        query: AccessPathAtPoint,
        candidates: I,
        coverage: CandidateCoverage,
        limits: OracleLimits,
    ) -> Result<Self, OracleContractError>
    where
        I: IntoIterator<Item = OracleCandidate<AbstractLocation>>,
    {
        let locations = OracleSet::bounded_locations(candidates, coverage, limits);
        validate_candidate_provenance(
            locations.candidates(),
            &OracleRelationOwner::Locations(Box::new(query.clone())),
            OracleRelationKind::Location,
        )?;
        for candidate in locations.candidates() {
            candidate
                .value()
                .object()
                .validate_at(query.point().procedure())?;
            candidate
                .value()
                .path()
                .validate_at(query.point().procedure())?;
        }
        validate_retained_relation_arenas(
            locations
                .candidates()
                .iter()
                .flat_map(OracleCandidate::provenance),
            limits,
        )?;
        Ok(Self { query, locations })
    }

    pub fn query(&self) -> &AccessPathAtPoint {
        &self.query
    }

    pub fn locations(&self) -> &OracleSet<AbstractLocation> {
        &self.locations
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AliasResult {
    query: AliasQuery,
    answer: EvidenceBacked<AliasRelation>,
}

impl AliasResult {
    pub fn new(
        query: AliasQuery,
        answer: EvidenceBacked<AliasRelation>,
        limits: OracleLimits,
    ) -> Result<Self, OracleContractError> {
        validate_candidate_provenance(
            std::slice::from_ref(&answer),
            &OracleRelationOwner::Alias(Box::new(query.clone())),
            OracleRelationKind::Alias,
        )?;
        validate_retained_relation_arenas(answer.provenance(), limits)?;
        Ok(Self { query, answer })
    }

    pub fn query(&self) -> &AliasQuery {
        &self.query
    }

    pub fn answer(&self) -> &EvidenceBacked<AliasRelation> {
        &self.answer
    }
}
/// Whether the alias analysis proved that no competing location can be
/// updated by the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AliasExclusivity {
    Exclusive,
    PotentialAliases,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EscapeStatus {
    DoesNotEscape,
    MayEscape,
}
/// Alias-exclusivity evidence tied to one exact store and selected location.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AliasExclusivityWitness {
    store: StoreAtPoint,
    location: AbstractLocation,
    status: AliasExclusivity,
}

impl AliasExclusivityWitness {
    pub fn new(
        store: StoreAtPoint,
        location: AbstractLocation,
        status: AliasExclusivity,
    ) -> Result<Self, OracleContractError> {
        if location.path() != store.target().path() {
            return Err(OracleContractError::StoreLocationMismatch);
        }
        location
            .object()
            .validate_at(store.store().point().procedure())?;
        Ok(Self {
            store,
            location,
            status,
        })
    }

    pub fn store(&self) -> &StoreAtPoint {
        &self.store
    }

    pub fn location(&self) -> &AbstractLocation {
        &self.location
    }

    pub const fn status(&self) -> AliasExclusivity {
        self.status
    }
}

/// Escape evidence tied to one exact store observation and abstract object.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EscapeWitness {
    store: StoreAtPoint,
    object: AbstractObject,
    status: EscapeStatus,
}

impl EscapeWitness {
    pub fn new(
        store: StoreAtPoint,
        object: AbstractObject,
        status: EscapeStatus,
    ) -> Result<Self, OracleContractError> {
        object.validate_at(store.store().point().procedure())?;
        Ok(Self {
            store,
            object,
            status,
        })
    }

    pub fn store(&self) -> &StoreAtPoint {
        &self.store
    }

    pub fn object(&self) -> &AbstractObject {
        &self.object
    }

    pub const fn status(&self) -> EscapeStatus {
        self.status
    }
}

/// A reason a store must use a weak update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WeakUpdateReason {
    NoLocation,
    MultipleLocations,
    NonExhaustiveLocations,
    TruncatedLocations,
    SummaryPath,
    NoObject,
    MultipleObjects,
    NonExhaustiveObjects,
    TruncatedObjects,
    SummaryObject,
    UnknownObjectCardinality,
    IncompleteAliasEvidence,
    PotentialAliases,
    IncompleteEscapeEvidence,
    EscapingObject,
    UnprovenEvidence,
    MissingProvenance,
    LocationObjectMismatch,
    StoreLocationMismatch,
    AliasSubjectMismatch,
    EscapeSubjectMismatch,
    MismatchedProvenance,
    CrossProcedure,
}

/// Inputs used to determine whether one store has a strong-update proof.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StrongUpdateEvidence {
    locations: OracleSet<AbstractLocation>,
    objects: OracleSet<AbstractObject>,
    alias_exclusivity: EvidenceBacked<AliasExclusivityWitness>,
    escape: EvidenceBacked<EscapeWitness>,
}

impl StrongUpdateEvidence {
    pub fn new(
        locations: OracleSet<AbstractLocation>,
        objects: OracleSet<AbstractObject>,
        alias_exclusivity: EvidenceBacked<AliasExclusivityWitness>,
        escape: EvidenceBacked<EscapeWitness>,
        limits: OracleLimits,
    ) -> Result<Self, OracleContractError> {
        if locations.candidates().len() > limits.alias_breadth() {
            return Err(OracleContractError::LimitExceeded {
                dimension: "alias_breadth",
                limit: limits.alias_breadth(),
                attempted: locations.candidates().len(),
            });
        }
        if objects.candidates().len() > limits.objects_per_value() {
            return Err(OracleContractError::LimitExceeded {
                dimension: "objects_per_value",
                limit: limits.objects_per_value(),
                attempted: objects.candidates().len(),
            });
        }
        validate_retained_relation_arenas(
            locations
                .candidates()
                .iter()
                .flat_map(OracleCandidate::provenance)
                .chain(
                    objects
                        .candidates()
                        .iter()
                        .flat_map(OracleCandidate::provenance),
                )
                .chain(alias_exclusivity.provenance())
                .chain(escape.provenance()),
            limits,
        )?;
        Ok(Self {
            locations,
            objects,
            alias_exclusivity,
            escape,
        })
    }

    pub fn locations(&self) -> &OracleSet<AbstractLocation> {
        &self.locations
    }

    pub fn objects(&self) -> &OracleSet<AbstractObject> {
        &self.objects
    }

    pub fn alias_exclusivity(&self) -> &EvidenceBacked<AliasExclusivityWitness> {
        &self.alias_exclusivity
    }

    pub fn escape(&self) -> &EvidenceBacked<EscapeWitness> {
        &self.escape
    }
}

/// A validated proof that one particular store may replace, rather than join,
/// the previous facts at one abstract location.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StrongUpdateCertificate {
    store: StoreAtPoint,
    location: AbstractLocation,
    provenance: Box<[OracleRelationHandle]>,
}

impl StrongUpdateCertificate {
    pub fn try_new(
        store: StoreAtPoint,
        evidence: StrongUpdateEvidence,
    ) -> Result<Self, StrongUpdateError> {
        let reasons = strong_update_reasons(&store, &evidence);
        if !reasons.is_empty() {
            return Err(StrongUpdateError {
                reasons: reasons.into_boxed_slice(),
            });
        }

        let location_candidate = evidence
            .locations
            .candidates
            .into_vec()
            .into_iter()
            .next()
            .expect("strong-update validation requires one location");
        let object_candidate = evidence
            .objects
            .candidates
            .into_vec()
            .into_iter()
            .next()
            .expect("strong-update validation requires one object");
        let mut provenance = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for relation in location_candidate
            .provenance
            .iter()
            .chain(object_candidate.provenance.iter())
            .chain(evidence.alias_exclusivity.provenance.iter())
            .chain(evidence.escape.provenance.iter())
        {
            if seen.insert(relation.clone()) {
                provenance.push(relation.clone());
            }
        }

        Ok(Self {
            store,
            location: location_candidate.value,
            provenance: provenance.into_boxed_slice(),
        })
    }

    pub fn store(&self) -> &StoreAtPoint {
        &self.store
    }

    pub fn location(&self) -> &AbstractLocation {
        &self.location
    }

    pub fn object(&self) -> &AbstractObject {
        self.location.object()
    }

    pub fn provenance(&self) -> &[OracleRelationHandle] {
        &self.provenance
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StrongUpdateError {
    reasons: Box<[WeakUpdateReason]>,
}

impl StrongUpdateError {
    pub fn reasons(&self) -> &[WeakUpdateReason] {
        &self.reasons
    }
}

impl fmt::Display for StrongUpdateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "strong update is not justified: {:?}",
            self.reasons
        )
    }
}

impl std::error::Error for StrongUpdateError {}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UpdateEligibility {
    Strong(Box<StrongUpdateCertificate>),
    Weak(Box<[WeakUpdateReason]>),
}

impl UpdateEligibility {
    pub fn evaluate(store: StoreAtPoint, evidence: StrongUpdateEvidence) -> Self {
        match StrongUpdateCertificate::try_new(store, evidence) {
            Ok(certificate) => Self::Strong(Box::new(certificate)),
            Err(error) => Self::Weak(error.reasons),
        }
    }
}

fn strong_update_reasons(
    store: &StoreAtPoint,
    evidence: &StrongUpdateEvidence,
) -> Vec<WeakUpdateReason> {
    let mut reasons = Vec::new();
    match evidence.locations.coverage {
        CandidateCoverage::Exhaustive => {}
        CandidateCoverage::Open => reasons.push(WeakUpdateReason::NonExhaustiveLocations),
        CandidateCoverage::Truncated => reasons.push(WeakUpdateReason::TruncatedLocations),
    }
    match evidence.locations.candidates.len() {
        0 => reasons.push(WeakUpdateReason::NoLocation),
        1 => {}
        _ => reasons.push(WeakUpdateReason::MultipleLocations),
    }
    for candidate in &evidence.locations.candidates {
        if !candidate.is_proven_complete() {
            reasons.push(WeakUpdateReason::UnprovenEvidence);
        }
        if !candidate.value.path().is_exact() {
            reasons.push(WeakUpdateReason::SummaryPath);
        }
        if candidate.value.path() != store.target().path() {
            reasons.push(WeakUpdateReason::StoreLocationMismatch);
        }
        if candidate
            .value
            .path()
            .validate_at(store.target().point().procedure())
            .is_err()
        {
            reasons.push(WeakUpdateReason::CrossProcedure);
        }
    }

    match evidence.objects.coverage {
        CandidateCoverage::Exhaustive => {}
        CandidateCoverage::Open => reasons.push(WeakUpdateReason::NonExhaustiveObjects),
        CandidateCoverage::Truncated => reasons.push(WeakUpdateReason::TruncatedObjects),
    }
    match evidence.objects.candidates.len() {
        0 => reasons.push(WeakUpdateReason::NoObject),
        1 => {}
        _ => reasons.push(WeakUpdateReason::MultipleObjects),
    }
    for candidate in &evidence.objects.candidates {
        if !candidate.is_proven_complete() {
            reasons.push(WeakUpdateReason::UnprovenEvidence);
        }
        match candidate.value.cardinality() {
            ObjectCardinality::Singleton => {}
            ObjectCardinality::Summary => reasons.push(WeakUpdateReason::SummaryObject),
            ObjectCardinality::Unknown => {
                reasons.push(WeakUpdateReason::UnknownObjectCardinality);
            }
        }
    }
    if let (Some(location), Some(object)) = (
        evidence.locations.candidates.first(),
        evidence.objects.candidates.first(),
    ) && location.value.object() != &object.value
    {
        reasons.push(WeakUpdateReason::LocationObjectMismatch);
    }

    if !evidence.alias_exclusivity.is_proven_complete() {
        reasons.push(WeakUpdateReason::IncompleteAliasEvidence);
    }
    if matches!(evidence.alias_exclusivity.proof, ProofStatus::Unproven(_)) {
        reasons.push(WeakUpdateReason::UnprovenEvidence);
    }
    let alias_subject_matches = evidence
        .locations
        .candidates
        .first()
        .is_some_and(|location| {
            evidence.alias_exclusivity.value.store() == store
                && evidence.alias_exclusivity.value.location() == &location.value
        });
    if !alias_subject_matches {
        reasons.push(WeakUpdateReason::AliasSubjectMismatch);
    }
    if evidence.alias_exclusivity.value.status() != AliasExclusivity::Exclusive {
        reasons.push(WeakUpdateReason::PotentialAliases);
    }
    if !evidence.escape.is_proven_complete() {
        reasons.push(WeakUpdateReason::IncompleteEscapeEvidence);
    }
    if matches!(evidence.escape.proof, ProofStatus::Unproven(_)) {
        reasons.push(WeakUpdateReason::UnprovenEvidence);
    }
    let escape_subject_matches = evidence.objects.candidates.first().is_some_and(|object| {
        evidence.escape.value.store() == store && evidence.escape.value.object() == &object.value
    });
    if !escape_subject_matches {
        reasons.push(WeakUpdateReason::EscapeSubjectMismatch);
    }
    if evidence.escape.value.status() != EscapeStatus::DoesNotEscape {
        reasons.push(WeakUpdateReason::EscapingObject);
    }
    if evidence
        .locations
        .candidates
        .iter()
        .any(|candidate| candidate.provenance.is_empty())
        || evidence
            .objects
            .candidates
            .iter()
            .any(|candidate| candidate.provenance.is_empty())
        || evidence.alias_exclusivity.provenance.is_empty()
        || evidence.escape.provenance.is_empty()
    {
        reasons.push(WeakUpdateReason::MissingProvenance);
    }
    let expected_owner = OracleRelationOwner::StrongUpdate(Box::new(store.clone()));
    let provenance_groups = [
        (
            evidence
                .locations
                .candidates
                .first()
                .map_or(&[][..], |candidate| candidate.provenance.as_ref()),
            OracleRelationKind::Location,
        ),
        (
            evidence
                .objects
                .candidates
                .first()
                .map_or(&[][..], |candidate| candidate.provenance.as_ref()),
            OracleRelationKind::PointsTo,
        ),
        (
            evidence.alias_exclusivity.provenance.as_ref(),
            OracleRelationKind::Alias,
        ),
        (
            evidence.escape.provenance.as_ref(),
            OracleRelationKind::Escape,
        ),
    ];
    let first_relation = provenance_groups
        .iter()
        .flat_map(|(relations, _)| relations.iter())
        .next();
    if provenance_groups.iter().any(|(relations, kind)| {
        relations.iter().any(|relation| {
            relation.owner() != &expected_owner
                || relation.record().kind() != *kind
                || relation.record().evidence().is_empty()
                || first_relation.is_some_and(|first| !first.same_arena(relation))
        })
    }) {
        reasons.push(WeakUpdateReason::MismatchedProvenance);
    }
    if provenance_groups.iter().any(|(relations, _)| {
        relations
            .iter()
            .any(|relation| !relation.record().is_proven_complete())
    }) {
        reasons.push(WeakUpdateReason::UnprovenEvidence);
    }

    reasons.sort_unstable_by_key(|reason| *reason as u8);
    reasons.dedup();
    reasons
}
