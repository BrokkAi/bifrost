//! Schema-version-1 finding classification and organizational-risk values.
//!
//! These are deterministic report-domain values. They validate and normalize
//! already established facts, but deliberately contain no classification
//! reducer or organizational-risk overlay selection logic.

use std::cmp::Ordering;
use std::fmt;

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::composition::{PrecedenceError, PrecedenceGraph};
use super::definition::{
    AnyOrAll, ClassificationPredicate, FindingCombinationId, PolicyAnalysisType, PolicyCategoryId,
    PolicyClassificationSpec, TaintImpact, TaintLabel, TaintTag, TaxonomyClassificationSpec,
    TypestateExpectationId,
};
use super::finding_identity::EvidenceRef;
use super::resolved::{ResolvedEndpointIdentity, ResolvedFindingCombination};
use super::retained::{RetainedSize, retained_extra};

pub(crate) const MAX_REPORT_NAME_BYTES: usize = 256;
pub(crate) const MAX_REPORT_PROSE_BYTES: usize = 4_096;
pub(crate) const MAX_REPORT_IDENTIFIER_BYTES: usize = 128;
pub(crate) const MAX_REPORT_EVIDENCE_REFS: usize = 256;
const MAX_CLASSIFICATION_REFINEMENTS: usize = 128 * 64;
const ORGANIZATIONAL_RISK_HASH_DOMAIN: &[u8] = b"bifrost-organizational-risk/v1";

/// The explicit classification state of one finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FindingClassification {
    Unclassified,
    #[non_exhaustive]
    Classified {
        broad: TaxonomyClassification,
        refinements: Vec<TaxonomyClassification>,
    },
}

impl FindingClassification {
    /// Build a classified result with identity-sorted, duplicate-free
    /// refinements. The policy fallback owns the broad identity, so a
    /// refinement with that same taxonomy/identifier is discarded regardless
    /// of its presentation/provenance. Equal identities with equal names are
    /// deduplicated deterministically, preferring an exact finding-combination
    /// classification over a generic ordered refinement. Equal identities
    /// with different names are a closed-policy conflict rather than an
    /// order-dependent choice.
    pub fn classified(
        broad: TaxonomyClassification,
        mut refinements: Vec<TaxonomyClassification>,
    ) -> Result<Self, ClassificationError> {
        if !matches!(broad.provenance, ClassificationProvenance::PolicyFallback) {
            return Err(ClassificationError::BroadMustUsePolicyFallback);
        }
        if refinements.len() > MAX_CLASSIFICATION_REFINEMENTS {
            return Err(ClassificationError::TooManyRefinements {
                max: MAX_CLASSIFICATION_REFINEMENTS,
            });
        }
        for refinement in &refinements {
            refinement.validate()?;
            if matches!(
                refinement.provenance,
                ClassificationProvenance::PolicyFallback
            ) {
                return Err(ClassificationError::RefinementCannotUsePolicyFallback);
            }
        }

        refinements.retain(|refinement| refinement.identity_cmp(&broad) != Ordering::Equal);
        refinements.sort_by(TaxonomyClassification::canonical_cmp);
        let mut normalized = Vec::with_capacity(refinements.len());
        for refinement in refinements {
            if let Some(previous) = normalized.last_mut()
                && refinement.identity_cmp(previous) == Ordering::Equal
            {
                if refinement.name != previous.name {
                    return Err(ClassificationError::ConflictingDuplicateIdentity {
                        taxonomy: refinement.taxonomy.clone(),
                        identifier: refinement.identifier.clone(),
                    });
                }
                if classification_provenance_preference(&refinement.provenance)
                    < classification_provenance_preference(&previous.provenance)
                {
                    *previous = refinement;
                }
                continue;
            }
            normalized.push(refinement);
        }

        Ok(Self::Classified {
            broad,
            refinements: normalized,
        })
    }

    pub const fn broad(&self) -> Option<&TaxonomyClassification> {
        match self {
            Self::Unclassified => None,
            Self::Classified { broad, .. } => Some(broad),
        }
    }

    pub fn refinements(&self) -> &[TaxonomyClassification] {
        match self {
            Self::Unclassified => &[],
            Self::Classified { refinements, .. } => refinements,
        }
    }
}

fn classification_provenance_preference(provenance: &ClassificationProvenance) -> (u8, u32) {
    match provenance {
        ClassificationProvenance::FindingCombination { .. } => (0, 0),
        ClassificationProvenance::PolicyRefinement { refinement_index } => (1, *refinement_index),
        ClassificationProvenance::AnalysisEvidence { .. } => (2, 0),
        ClassificationProvenance::PolicyFallback => (3, 0),
    }
}

impl RetainedSize for FindingClassification {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>().saturating_add(match self {
            Self::Unclassified => 0,
            Self::Classified { broad, refinements } => {
                retained_extra(broad).saturating_add(retained_extra(refinements))
            }
        })
    }
}

/// One taxonomy classification retained in the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TaxonomyClassification {
    taxonomy: String,
    identifier: String,
    name: Option<String>,
    provenance: ClassificationProvenance,
}

impl TaxonomyClassification {
    pub fn try_new(
        taxonomy: impl Into<String>,
        identifier: impl Into<String>,
        name: Option<String>,
        provenance: ClassificationProvenance,
    ) -> Result<Self, ClassificationError> {
        let value = Self {
            taxonomy: taxonomy.into(),
            identifier: identifier.into(),
            name,
            provenance,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn taxonomy(&self) -> &str {
        &self.taxonomy
    }

    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub const fn provenance(&self) -> &ClassificationProvenance {
        &self.provenance
    }

    fn validate(&self) -> Result<(), ClassificationError> {
        validate_required_text(&self.taxonomy, MAX_REPORT_NAME_BYTES)
            .map_err(|reason| ClassificationError::InvalidTaxonomy { reason })?;
        validate_required_text(&self.identifier, MAX_REPORT_NAME_BYTES)
            .map_err(|reason| ClassificationError::InvalidIdentifier { reason })?;
        if let Some(name) = &self.name {
            validate_required_text(name, MAX_REPORT_NAME_BYTES)
                .map_err(|reason| ClassificationError::InvalidName { reason })?;
        }
        self.provenance.validate()
    }

    fn identity_cmp(&self, other: &Self) -> Ordering {
        (&self.taxonomy, &self.identifier).cmp(&(&other.taxonomy, &other.identifier))
    }

    fn canonical_cmp(left: &Self, right: &Self) -> Ordering {
        left.identity_cmp(right)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.provenance.cmp(&right.provenance))
    }
}

impl RetainedSize for TaxonomyClassification {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(retained_extra(&self.taxonomy))
            .saturating_add(retained_extra(&self.identifier))
            .saturating_add(retained_extra(&self.name))
            .saturating_add(retained_extra(&self.provenance))
    }
}

/// Why a report classification was retained.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClassificationProvenance {
    PolicyFallback,
    PolicyRefinement {
        refinement_index: u32,
    },
    FindingCombination {
        combination_id: FindingCombinationId,
    },
    AnalysisEvidence {
        adapter: String,
        evidence_refs: Vec<EvidenceRef>,
    },
}

impl ClassificationProvenance {
    pub fn policy_refinement(refinement_index: u32) -> Result<Self, ClassificationError> {
        if usize::try_from(refinement_index).unwrap_or(usize::MAX) >= 128 {
            return Err(ClassificationError::RefinementIndexOutOfRange {
                index: refinement_index,
                max_exclusive: 128,
            });
        }
        Ok(Self::PolicyRefinement { refinement_index })
    }

    pub fn analysis_evidence(
        adapter: impl Into<String>,
        mut evidence_refs: Vec<EvidenceRef>,
    ) -> Result<Self, ClassificationError> {
        let adapter = adapter.into();
        validate_namespaced_identifier(&adapter)
            .map_err(|reason| ClassificationError::InvalidAnalysisAdapter { reason })?;
        normalize_evidence_refs(&mut evidence_refs, true)
            .map_err(ClassificationError::EvidenceReferences)?;
        Ok(Self::AnalysisEvidence {
            adapter,
            evidence_refs,
        })
    }

    fn validate(&self) -> Result<(), ClassificationError> {
        match self {
            Self::PolicyFallback | Self::FindingCombination { .. } => Ok(()),
            Self::PolicyRefinement { refinement_index } => {
                Self::policy_refinement(*refinement_index).map(|_| ())
            }
            Self::AnalysisEvidence {
                adapter,
                evidence_refs,
            } => {
                validate_namespaced_identifier(adapter)
                    .map_err(|reason| ClassificationError::InvalidAnalysisAdapter { reason })?;
                let mut normalized = evidence_refs.clone();
                normalize_evidence_refs(&mut normalized, true)
                    .map_err(ClassificationError::EvidenceReferences)?;
                if &normalized != evidence_refs {
                    return Err(ClassificationError::NonCanonicalEvidenceReferences);
                }
                Ok(())
            }
        }
    }
}

impl RetainedSize for ClassificationProvenance {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>().saturating_add(match self {
            Self::PolicyFallback | Self::PolicyRefinement { .. } => 0,
            Self::FindingCombination { combination_id } => retained_extra(combination_id),
            Self::AnalysisEvidence {
                adapter,
                evidence_refs,
            } => retained_extra(adapter).saturating_add(retained_extra(evidence_refs)),
        })
    }
}

/// Exact, pair-local facts visible to the generic classification reducer.
///
/// Categories remain reporting inputs: the analysis adapter never uses them
/// to decide reachability or typestate transitions. Taint callers must pass
/// only the source-endpoint partition being rendered, never the aggregate
/// sink meeting, so one source pair cannot borrow facts from another.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ClassificationProjection<'a> {
    analysis_type: PolicyAnalysisType,
    source_categories: &'a [PolicyCategoryId],
    sink_categories: &'a [PolicyCategoryId],
    source_labels: &'a [TaintLabel],
    sink_tags: &'a [TaintTag],
    sink_impacts: &'a [TaintImpact],
    selected_combination: Option<&'a FindingCombinationId>,
    typestate_expectation: Option<&'a TypestateExpectationId>,
}

impl<'a> ClassificationProjection<'a> {
    pub(crate) const fn match_finding() -> Self {
        Self {
            analysis_type: PolicyAnalysisType::Match,
            source_categories: &[],
            sink_categories: &[],
            source_labels: &[],
            sink_tags: &[],
            sink_impacts: &[],
            selected_combination: None,
            typestate_expectation: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn taint_pair(
        source_categories: &'a [PolicyCategoryId],
        sink_categories: &'a [PolicyCategoryId],
        source_labels: &'a [TaintLabel],
        sink_tags: &'a [TaintTag],
        sink_impacts: &'a [TaintImpact],
        selected_combination: Option<&'a FindingCombinationId>,
    ) -> Self {
        Self {
            analysis_type: PolicyAnalysisType::Taint,
            source_categories,
            sink_categories,
            source_labels,
            sink_tags,
            sink_impacts,
            selected_combination,
            typestate_expectation: None,
        }
    }

    pub(crate) const fn typestate(
        source_categories: &'a [PolicyCategoryId],
        typestate_expectation: Option<&'a TypestateExpectationId>,
    ) -> Self {
        Self {
            analysis_type: PolicyAnalysisType::Typestate,
            source_categories,
            sink_categories: &[],
            source_labels: &[],
            sink_tags: &[],
            sink_impacts: &[],
            selected_combination: None,
            typestate_expectation,
        }
    }
}

/// Run-local presentation authority built once from the exact loaded taint
/// specification and reused for every actual endpoint pair.
pub(crate) struct TaintPresentationReducer<'a> {
    combinations: &'a [ResolvedFindingCombination],
    graph: PrecedenceGraph<FindingCombinationId>,
}

impl<'a> TaintPresentationReducer<'a> {
    pub(crate) fn try_new(
        combinations: &'a [ResolvedFindingCombination],
    ) -> Result<Self, ClassificationReductionError> {
        let graph = PrecedenceGraph::try_new(
            combinations.iter().map(|value| value.id.clone()),
            combinations.iter().flat_map(|value| {
                value
                    .supersedes
                    .iter()
                    .cloned()
                    .map(|dominated| (value.id.clone(), dominated))
            }),
        )?;
        Ok(Self {
            combinations,
            graph,
        })
    }

    /// Select the one explicit rule for an actual source/sink pair. An empty
    /// candidate set means the policy default; incomparable live rules are an
    /// invariant failure because source order is never a tie-breaker.
    pub(crate) fn select(
        &self,
        source_endpoint: &ResolvedEndpointIdentity,
        sink_endpoint: &ResolvedEndpointIdentity,
    ) -> Result<Option<&'a ResolvedFindingCombination>, ClassificationReductionError> {
        let winner = self.graph.unique_winner(
            self.combinations
                .iter()
                .filter(|value| {
                    value.source_endpoints.contains(source_endpoint)
                        && value.sink_endpoints.contains(sink_endpoint)
                })
                .map(|value| value.id.clone()),
        )?;
        winner
            .map(|winner| {
                self.combinations
                    .iter()
                    .find(|value| value.id == winner)
                    .ok_or(ClassificationReductionError::MissingCombinationWinner)
            })
            .transpose()
    }
}

/// Reduce policy fallback, one winning combination, and every matching
/// ordered refinement into the canonical report classification.
pub(crate) fn reduce_finding_classification(
    spec: Option<&PolicyClassificationSpec>,
    projection: ClassificationProjection<'_>,
    combination: Option<&ResolvedFindingCombination>,
) -> Result<FindingClassification, ClassificationReductionError> {
    if combination.map(|value| &value.id) != projection.selected_combination {
        return Err(ClassificationReductionError::CombinationProjectionMismatch);
    }
    let Some(spec) = spec else {
        if combination.is_some_and(|value| !value.add_classifications.is_empty()) {
            return Err(ClassificationReductionError::CombinationClassificationsRequireFallback);
        }
        return Ok(FindingClassification::Unclassified);
    };

    let broad = classification_from_spec(&spec.fallback, ClassificationProvenance::PolicyFallback)?;
    let combination_count = combination.map_or(0, |value| value.add_classifications.len());
    let mut refinements = Vec::with_capacity(
        combination_count.saturating_add(
            spec.refinements
                .iter()
                .map(|value| value.add.len())
                .sum::<usize>(),
        ),
    );
    if let Some(combination) = combination {
        for added in &combination.add_classifications {
            refinements.push(classification_from_spec(
                added,
                ClassificationProvenance::FindingCombination {
                    combination_id: combination.id.clone(),
                },
            )?);
        }
    }
    for (index, refinement) in spec.refinements.iter().enumerate() {
        if !classification_predicate_matches(&refinement.when, projection) {
            continue;
        }
        let refinement_index = u32::try_from(index)
            .map_err(|_| ClassificationReductionError::RefinementIndexOverflow)?;
        let provenance = ClassificationProvenance::policy_refinement(refinement_index)?;
        for added in &refinement.add {
            refinements.push(classification_from_spec(added, provenance.clone())?);
        }
    }
    FindingClassification::classified(broad, refinements).map_err(Into::into)
}

fn classification_from_spec(
    spec: &TaxonomyClassificationSpec,
    provenance: ClassificationProvenance,
) -> Result<TaxonomyClassification, ClassificationReductionError> {
    TaxonomyClassification::try_new(
        spec.taxonomy.clone(),
        spec.identifier.clone(),
        spec.name.clone(),
        provenance,
    )
    .map_err(Into::into)
}

fn classification_predicate_matches(
    predicate: &ClassificationPredicate,
    projection: ClassificationProjection<'_>,
) -> bool {
    match predicate {
        ClassificationPredicate::All { predicates } => predicates
            .iter()
            .all(|predicate| classification_predicate_matches(predicate, projection)),
        ClassificationPredicate::Any { predicates } => predicates
            .iter()
            .any(|predicate| classification_predicate_matches(predicate, projection)),
        ClassificationPredicate::AnalysisType { analysis_type } => {
            *analysis_type == projection.analysis_type
        }
        ClassificationPredicate::SourceCategories { quantifier, values } => {
            quantified_membership(*quantifier, values, projection.source_categories)
        }
        ClassificationPredicate::SinkCategories { quantifier, values } => {
            quantified_membership(*quantifier, values, projection.sink_categories)
        }
        ClassificationPredicate::SourceLabels { quantifier, values } => {
            quantified_membership(*quantifier, values, projection.source_labels)
        }
        ClassificationPredicate::SinkTags { quantifier, values } => {
            quantified_membership(*quantifier, values, projection.sink_tags)
        }
        ClassificationPredicate::SinkImpacts { quantifier, values } => {
            quantified_membership(*quantifier, values, projection.sink_impacts)
        }
        ClassificationPredicate::FindingCombination { id } => {
            projection.selected_combination == Some(id)
        }
        ClassificationPredicate::TypestateExpectation { id } => {
            projection.typestate_expectation == Some(id)
        }
    }
}

fn quantified_membership<T: Eq>(quantifier: AnyOrAll, expected: &[T], actual: &[T]) -> bool {
    match quantifier {
        AnyOrAll::Any => expected.iter().any(|value| actual.contains(value)),
        AnyOrAll::All => expected.iter().all(|value| actual.contains(value)),
    }
}

#[derive(Debug)]
pub(crate) enum ClassificationReductionError {
    InvalidClassification(ClassificationError),
    CombinationPrecedence(PrecedenceError<FindingCombinationId>),
    CombinationProjectionMismatch,
    CombinationClassificationsRequireFallback,
    MissingCombinationWinner,
    RefinementIndexOverflow,
}

impl fmt::Display for ClassificationReductionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidClassification(error) => error.fmt(formatter),
            Self::CombinationPrecedence(error) => error.fmt(formatter),
            Self::CombinationProjectionMismatch => formatter.write_str(
                "selected finding combination does not match the classification projection",
            ),
            Self::CombinationClassificationsRequireFallback => formatter.write_str(
                "finding-combination classifications require a top-level fallback classification",
            ),
            Self::MissingCombinationWinner => formatter
                .write_str("selected finding-combination winner is absent from the loaded model"),
            Self::RefinementIndexOverflow => {
                formatter.write_str("classification refinement index does not fit u32")
            }
        }
    }
}

impl std::error::Error for ClassificationReductionError {}

impl From<ClassificationError> for ClassificationReductionError {
    fn from(value: ClassificationError) -> Self {
        Self::InvalidClassification(value)
    }
}

impl From<PrecedenceError<FindingCombinationId>> for ClassificationReductionError {
    fn from(value: PrecedenceError<FindingCombinationId>) -> Self {
        Self::CombinationPrecedence(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassificationError {
    InvalidTaxonomy {
        reason: TextValidationError,
    },
    InvalidIdentifier {
        reason: TextValidationError,
    },
    InvalidName {
        reason: TextValidationError,
    },
    InvalidAnalysisAdapter {
        reason: TextValidationError,
    },
    RefinementIndexOutOfRange {
        index: u32,
        max_exclusive: usize,
    },
    EvidenceReferences(EvidenceReferenceError),
    NonCanonicalEvidenceReferences,
    BroadMustUsePolicyFallback,
    RefinementCannotUsePolicyFallback,
    TooManyRefinements {
        max: usize,
    },
    ConflictingDuplicateIdentity {
        taxonomy: String,
        identifier: String,
    },
}

impl fmt::Display for ClassificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTaxonomy { reason } => write!(formatter, "invalid taxonomy: {reason}"),
            Self::InvalidIdentifier { reason } => {
                write!(formatter, "invalid taxonomy identifier: {reason}")
            }
            Self::InvalidName { reason } => {
                write!(formatter, "invalid classification name: {reason}")
            }
            Self::InvalidAnalysisAdapter { reason } => {
                write!(formatter, "invalid analysis adapter: {reason}")
            }
            Self::RefinementIndexOutOfRange {
                index,
                max_exclusive,
            } => write!(
                formatter,
                "classification refinement index {index} must be below {max_exclusive}"
            ),
            Self::EvidenceReferences(error) => error.fmt(formatter),
            Self::NonCanonicalEvidenceReferences => formatter
                .write_str("classification evidence references must be sorted and duplicate-free"),
            Self::BroadMustUsePolicyFallback => {
                formatter.write_str("broad classification must use policy-fallback provenance")
            }
            Self::RefinementCannotUsePolicyFallback => formatter
                .write_str("classification refinement cannot use policy-fallback provenance"),
            Self::TooManyRefinements { max } => {
                write!(
                    formatter,
                    "finding accepts at most {max} classification refinements"
                )
            }
            Self::ConflictingDuplicateIdentity {
                taxonomy,
                identifier,
            } => write!(
                formatter,
                "classification {taxonomy}:{identifier} has conflicting duplicate records"
            ),
        }
    }
}

impl std::error::Error for ClassificationError {}

/// Deterministic organizational risk attached to one finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OrganizationalRiskAssessment {
    scheme: String,
    rating: String,
    rationale: String,
    evidence_refs: Vec<EvidenceRef>,
    assessor: Option<String>,
    content_hash: OrganizationalRiskAssessmentHash,
}

impl OrganizationalRiskAssessment {
    pub fn try_new(
        scheme: String,
        rating: String,
        rationale: String,
        mut evidence_refs: Vec<EvidenceRef>,
        assessor: Option<String>,
    ) -> Result<Self, OrganizationalRiskError> {
        validate_required_text(&scheme, MAX_REPORT_NAME_BYTES)
            .map_err(|reason| OrganizationalRiskError::InvalidScheme { reason })?;
        validate_required_text(&rating, MAX_REPORT_NAME_BYTES)
            .map_err(|reason| OrganizationalRiskError::InvalidRating { reason })?;
        validate_required_text(&rationale, MAX_REPORT_PROSE_BYTES)
            .map_err(|reason| OrganizationalRiskError::InvalidRationale { reason })?;
        if let Some(assessor) = &assessor {
            validate_required_text(assessor, MAX_REPORT_PROSE_BYTES)
                .map_err(|reason| OrganizationalRiskError::InvalidAssessor { reason })?;
        }
        normalize_evidence_refs(&mut evidence_refs, false)
            .map_err(OrganizationalRiskError::EvidenceReferences)?;
        let content_hash = organizational_risk_hash(
            &scheme,
            &rating,
            &rationale,
            &evidence_refs,
            assessor.as_deref(),
        );
        Ok(Self {
            scheme,
            rating,
            rationale,
            evidence_refs,
            assessor,
            content_hash,
        })
    }

    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    pub fn rating(&self) -> &str {
        &self.rating
    }

    pub fn rationale(&self) -> &str {
        &self.rationale
    }

    pub fn evidence_refs(&self) -> &[EvidenceRef] {
        &self.evidence_refs
    }

    pub fn assessor(&self) -> Option<&str> {
        self.assessor.as_deref()
    }

    pub const fn content_hash(&self) -> OrganizationalRiskAssessmentHash {
        self.content_hash
    }

    /// Apply report-only reference retention without changing the semantic
    /// hash, which identifies the complete normalized assessment rather than
    /// its bounded display projection.
    pub(crate) fn retain_evidence_refs(&mut self, retained: &[EvidenceRef]) {
        self.evidence_refs
            .retain(|reference| retained.binary_search(reference).is_ok());
        self.evidence_refs.shrink_to_fit();
    }
}

impl RetainedSize for OrganizationalRiskAssessment {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(retained_extra(&self.scheme))
            .saturating_add(retained_extra(&self.rating))
            .saturating_add(retained_extra(&self.rationale))
            .saturating_add(retained_extra(&self.evidence_refs))
            .saturating_add(retained_extra(&self.assessor))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrganizationalRiskError {
    InvalidScheme { reason: TextValidationError },
    InvalidRating { reason: TextValidationError },
    InvalidRationale { reason: TextValidationError },
    InvalidAssessor { reason: TextValidationError },
    EvidenceReferences(EvidenceReferenceError),
}

impl fmt::Display for OrganizationalRiskError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidScheme { reason } => {
                write!(formatter, "invalid organizational-risk scheme: {reason}")
            }
            Self::InvalidRating { reason } => {
                write!(formatter, "invalid organizational-risk rating: {reason}")
            }
            Self::InvalidRationale { reason } => {
                write!(formatter, "invalid organizational-risk rationale: {reason}")
            }
            Self::InvalidAssessor { reason } => {
                write!(formatter, "invalid organizational-risk assessor: {reason}")
            }
            Self::EvidenceReferences(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for OrganizationalRiskError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OrganizationalRiskAssessmentHash([u8; 32]);

impl OrganizationalRiskAssessmentHash {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for OrganizationalRiskAssessmentHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_lower_hex(&self.0, formatter)
    }
}

impl Serialize for OrganizationalRiskAssessmentHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl RetainedSize for OrganizationalRiskAssessmentHash {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}

fn organizational_risk_hash(
    scheme: &str,
    rating: &str,
    rationale: &str,
    evidence_refs: &[EvidenceRef],
    assessor: Option<&str>,
) -> OrganizationalRiskAssessmentHash {
    let mut hasher = Sha256::new();
    update_length_prefixed(&mut hasher, ORGANIZATIONAL_RISK_HASH_DOMAIN);
    update_length_prefixed(&mut hasher, scheme.as_bytes());
    update_length_prefixed(&mut hasher, rating.as_bytes());
    update_length_prefixed(&mut hasher, rationale.as_bytes());
    for evidence_ref in evidence_refs {
        update_length_prefixed(&mut hasher, evidence_ref.as_str().as_bytes());
    }
    update_length_prefixed(
        &mut hasher,
        assessor.map_or(&[][..], |value| value.as_bytes()),
    );
    OrganizationalRiskAssessmentHash(hasher.finalize().into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextValidationError {
    Empty,
    TooLong { max_bytes: usize },
    UnsafeCharacter,
    InvalidIdentifier,
}

impl fmt::Display for TextValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("value must not be empty"),
            Self::TooLong { max_bytes } => {
                write!(formatter, "value must be at most {max_bytes} bytes")
            }
            Self::UnsafeCharacter => formatter
                .write_str("value must not contain control or bidirectional-control characters"),
            Self::InvalidIdentifier => formatter.write_str(
                "value must be a lowercase namespaced identifier with ASCII alphanumeric ends",
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceReferenceError {
    Empty,
    TooMany { max: usize },
}

impl fmt::Display for EvidenceReferenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("at least one evidence reference is required"),
            Self::TooMany { max } => {
                write!(formatter, "at most {max} evidence references are allowed")
            }
        }
    }
}

pub(crate) fn validate_required_text(
    value: &str,
    max_bytes: usize,
) -> Result<(), TextValidationError> {
    if value.is_empty() {
        return Err(TextValidationError::Empty);
    }
    if value.len() > max_bytes {
        return Err(TextValidationError::TooLong { max_bytes });
    }
    if value.chars().any(is_unsafe_single_line_character) {
        return Err(TextValidationError::UnsafeCharacter);
    }
    Ok(())
}

pub(crate) fn validate_namespaced_identifier(value: &str) -> Result<(), TextValidationError> {
    validate_required_text(value, MAX_REPORT_IDENTIFIER_BYTES)?;
    let bytes = value.as_bytes();
    if !is_lower_alphanumeric(bytes[0])
        || !is_lower_alphanumeric(bytes[bytes.len() - 1])
        || bytes
            .iter()
            .copied()
            .any(|byte| !(is_lower_alphanumeric(byte) || matches!(byte, b'.' | b'-' | b'_')))
    {
        return Err(TextValidationError::InvalidIdentifier);
    }
    Ok(())
}

pub(crate) fn normalize_evidence_refs(
    values: &mut Vec<EvidenceRef>,
    require_nonempty: bool,
) -> Result<(), EvidenceReferenceError> {
    if values.len() > MAX_REPORT_EVIDENCE_REFS {
        return Err(EvidenceReferenceError::TooMany {
            max: MAX_REPORT_EVIDENCE_REFS,
        });
    }
    values.sort();
    values.dedup();
    if require_nonempty && values.is_empty() {
        return Err(EvidenceReferenceError::Empty);
    }
    Ok(())
}

const fn is_lower_alphanumeric(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

fn is_unsafe_single_line_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

fn update_length_prefixed(hasher: &mut Sha256, value: &[u8]) {
    let length = u64::try_from(value.len()).expect("usize fits in u64 on supported targets");
    hasher.update(length.to_be_bytes());
    hasher.update(value);
}

fn write_lower_hex(bytes: &[u8; 32], formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn evidence(value: &str) -> EvidenceRef {
        EvidenceRef::try_new("policy", value).unwrap()
    }

    fn broad() -> TaxonomyClassification {
        TaxonomyClassification::try_new(
            "Bifrost",
            "INPUT-VALIDATION",
            Some("Entrée non fiable".to_string()),
            ClassificationProvenance::PolicyFallback,
        )
        .unwrap()
    }

    #[test]
    fn tagged_unit_and_data_variants_use_schema_v1_wire_shapes() {
        assert_eq!(
            serde_json::to_value(FindingClassification::Unclassified).unwrap(),
            json!({ "type": "unclassified" })
        );
        assert_eq!(
            serde_json::to_value(ClassificationProvenance::PolicyFallback).unwrap(),
            json!({ "type": "policy_fallback" })
        );
        assert_eq!(
            serde_json::to_value(
                ClassificationProvenance::analysis_evidence(
                    "bifrost.taint",
                    vec![evidence("z"), evidence("a")],
                )
                .unwrap()
            )
            .unwrap(),
            json!({
                "type": "analysis_evidence",
                "adapter": "bifrost.taint",
                "evidence_refs": ["policy:a", "policy:z"],
            })
        );
    }

    #[test]
    fn classified_results_sort_deduplicate_and_preserve_broad_identity() {
        let cwe_79 = TaxonomyClassification::try_new(
            "CWE",
            "CWE-79",
            None,
            ClassificationProvenance::policy_refinement(2).unwrap(),
        )
        .unwrap();
        let cwe_20 = TaxonomyClassification::try_new(
            "CWE",
            "CWE-20",
            None,
            ClassificationProvenance::policy_refinement(1).unwrap(),
        )
        .unwrap();
        let repeated_broad = TaxonomyClassification::try_new(
            broad().taxonomy(),
            broad().identifier(),
            Some("narrow spelling cannot replace broad".to_string()),
            ClassificationProvenance::policy_refinement(0).unwrap(),
        )
        .unwrap();

        let result = FindingClassification::classified(
            broad(),
            vec![cwe_79.clone(), repeated_broad, cwe_20.clone(), cwe_79],
        )
        .unwrap();
        assert_eq!(
            result
                .refinements()
                .iter()
                .map(TaxonomyClassification::identifier)
                .collect::<Vec<_>>(),
            ["CWE-20", "CWE-79"]
        );
        assert_eq!(result.broad().unwrap().identifier(), "INPUT-VALIDATION");
    }

    #[test]
    fn classification_rejects_unsafe_text_and_conflicting_identity() {
        assert!(
            TaxonomyClassification::try_new(
                "CWE\nforged",
                "CWE-79",
                None,
                ClassificationProvenance::PolicyFallback,
            )
            .is_err()
        );
        let first = TaxonomyClassification::try_new(
            "CWE",
            "CWE-20",
            Some("first".to_string()),
            ClassificationProvenance::policy_refinement(0).unwrap(),
        )
        .unwrap();
        let second = TaxonomyClassification::try_new(
            "CWE",
            "CWE-20",
            Some("second".to_string()),
            ClassificationProvenance::policy_refinement(1).unwrap(),
        )
        .unwrap();
        assert!(FindingClassification::classified(broad(), vec![first, second]).is_err());
    }

    #[test]
    fn generic_reducer_is_pair_local_and_prefers_combination_provenance() {
        let fallback = TaxonomyClassificationSpec {
            taxonomy: "Bifrost".to_string(),
            identifier: "FLOW".to_string(),
            name: None,
        };
        let cwe = TaxonomyClassificationSpec {
            taxonomy: "CWE".to_string(),
            identifier: "CWE-20".to_string(),
            name: Some("Improper Input Validation".to_string()),
        };
        let combination_id = FindingCombinationId::new("specific").unwrap();
        let spec = PolicyClassificationSpec {
            fallback,
            refinements: vec![super::super::definition::ClassificationRefinementSpec {
                when: ClassificationPredicate::SourceCategories {
                    quantifier: AnyOrAll::Any,
                    values: vec![PolicyCategoryId::new("input.other").unwrap()],
                },
                add: vec![cwe.clone()],
            }],
            cvss: None,
        };
        let combination = ResolvedFindingCombination::new(
            combination_id.clone(),
            Vec::new(),
            Vec::new(),
            "specific message".to_string(),
            None,
            vec![cwe],
            Vec::new(),
        );
        let source_categories = vec![PolicyCategoryId::new("input.actual").unwrap()];
        let projection = ClassificationProjection::taint_pair(
            &source_categories,
            &[],
            &[],
            &[],
            &[],
            Some(&combination_id),
        );
        let reduced =
            reduce_finding_classification(Some(&spec), projection, Some(&combination)).unwrap();
        assert_eq!(reduced.broad().unwrap().identifier(), "FLOW");
        assert_eq!(reduced.refinements().len(), 1);
        assert!(matches!(
            reduced.refinements()[0].provenance(),
            ClassificationProvenance::FindingCombination { combination_id: id }
                if id == &combination_id
        ));
        assert!(matches!(
            reduce_finding_classification(None, projection, Some(&combination)),
            Err(ClassificationReductionError::CombinationClassificationsRequireFallback)
        ));
    }

    #[test]
    fn organizational_risk_hashes_normalized_content_not_input_order() {
        let first = OrganizationalRiskAssessment::try_new(
            "owasp-risk".to_string(),
            "high".to_string(),
            "Customer records are exposed".to_string(),
            vec![evidence("z"), evidence("a"), evidence("z")],
            Some("risk-team".to_string()),
        )
        .unwrap();
        let second = OrganizationalRiskAssessment::try_new(
            "owasp-risk".to_string(),
            "high".to_string(),
            "Customer records are exposed".to_string(),
            vec![evidence("a"), evidence("z")],
            Some("risk-team".to_string()),
        )
        .unwrap();

        assert_eq!(first, second);
        assert_eq!(first.evidence_refs(), [evidence("a"), evidence("z")]);
        assert_eq!(first.content_hash().to_string().len(), 64);
        let json = serde_json::to_value(first).unwrap();
        assert_eq!(json["content_hash"].as_str().unwrap().len(), 64);
    }
}
