//! Schema-version-1 finding classification and organizational-risk values.
//!
//! These are deterministic report-domain values. They validate and normalize
//! already established facts, but deliberately contain no classification
//! reducer or organizational-risk overlay selection logic.

use std::cmp::Ordering;
use std::fmt;

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::finding_identity::EvidenceRef;
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
    /// of its presentation/provenance. Two different refinement records for
    /// any other identity are an invariant error rather than an
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
            if let Some(previous) = normalized.last()
                && refinement.identity_cmp(previous) == Ordering::Equal
            {
                if &refinement == previous {
                    continue;
                }
                return Err(ClassificationError::ConflictingDuplicateIdentity {
                    taxonomy: refinement.taxonomy.clone(),
                    identifier: refinement.identifier.clone(),
                });
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
            Self::PolicyFallback => Ok(()),
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
            Self::AnalysisEvidence {
                adapter,
                evidence_refs,
            } => retained_extra(adapter).saturating_add(retained_extra(evidence_refs)),
        })
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
