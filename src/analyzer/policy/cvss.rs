//! Schema-version-1 CVSS evidence and assessment report values.
//!
//! This module validates and canonically normalizes already established CVSS
//! facts. It intentionally does not select overlays, reduce evidence, build
//! vectors, or calculate scores.

use std::cmp::Ordering;
use std::fmt;

use chrono::{DateTime, SecondsFormat};
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

use super::classification::{
    EvidenceReferenceError, MAX_REPORT_PROSE_BYTES, TextValidationError, normalize_evidence_refs,
    validate_namespaced_identifier, validate_required_text,
};
use super::definition::{
    CvssBaseMetric, CvssEnvironmentalOrSupplementalMetric, CvssEvidenceScope, CvssMetric,
    CvssMetricValue, CvssMetricValueToken, CvssSystemScope, CvssThreatMetric, CvssVersion,
    PolicyId,
};
use super::finding::PolicyIncompleteReason;
use super::finding_identity::{EvidenceRef, PolicyFindingId, SourceScenarioId, WitnessId};
use super::retained::{RetainedSize, retained_extra};

const MAX_CVSS_ASSUMPTIONS: usize = 64;
const MAX_CVSS_EVIDENCE_RECORDS: usize = 256;
const MAX_CVSS_OVERLAYS: usize = 256;
const MAX_CVSS_COMPONENTS: usize = 4;
const MAX_CVSS_VARIANTS: usize = 32;
const MAX_SOURCE_SCENARIOS: usize = 16_384;
const MAX_WITNESS_REFS: usize = 64;
const MAX_CVSS_VECTOR_BYTES: usize = 4_096;
const MAX_ASSESSED_AT_BYTES: usize = 128;

const SELECTED_VARIANT_RATIONALE: &str =
    "selected highest scored coherent variant; ties use canonical vector then variant id";
const UNSCORED_VARIANT_RATIONALE: &str = "no complete scored variant";

macro_rules! define_digest {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Wrap a digest produced by the corresponding domain-separated
            /// identity/evidence builder. This shape layer deliberately does
            /// not derive semantic digests itself.
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write_lower_hex(&self.0, formatter)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.collect_str(self)
            }
        }

        impl RetainedSize for $name {
            fn retained_size(&self) -> usize {
                std::mem::size_of::<Self>()
            }
        }
    };
}

define_digest!(CvssEvidenceContentHash);
define_digest!(CvssEvidenceSetHash);
define_digest!(VulnerabilityIdentity);
define_digest!(CvssAssessmentVariantId);
define_digest!(SourceScenarioSetHash);

/// The provenance family of one established metric fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CvssEvidenceBasis {
    StaticWitness,
    PolicyAssertion,
    EnvironmentProfile,
    ThreatFeed,
    AnalystOverride,
}

impl RetainedSize for CvssEvidenceBasis {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}

/// One validated CVSS metric fact retained in a report variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CvssMetricEvidence {
    metric: CvssMetric,
    value: CvssMetricValue,
    basis: CvssEvidenceBasis,
    evidence_refs: Vec<EvidenceRef>,
    rationale: String,
    assumptions: Vec<String>,
    assessor_or_tool: String,
    assessed_at: Option<String>,
    system_scope: CvssEvidenceScope,
    content_hash: CvssEvidenceContentHash,
}

impl CvssMetricEvidence {
    /// Construct an already hashed evidence record. The final hash remains
    /// crate-owned: public embeddings create basis-specific overlay inputs,
    /// and the future reducer supplies the semantic content hash here.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn try_new(
        metric: CvssMetric,
        value: CvssMetricValue,
        basis: CvssEvidenceBasis,
        mut evidence_refs: Vec<EvidenceRef>,
        rationale: String,
        mut assumptions: Vec<String>,
        assessor_or_tool: String,
        mut assessed_at: Option<String>,
        system_scope: CvssEvidenceScope,
        content_hash: CvssEvidenceContentHash,
    ) -> Result<Self, CvssValidationError> {
        if value.metric() != metric {
            return Err(CvssValidationError::MetricValueMismatch {
                metric,
                value_metric: value.metric(),
            });
        }
        if !basis_allows_metric(basis, metric) {
            return Err(CvssValidationError::BasisMetricMismatch { basis, metric });
        }
        let expected_scope = required_scope(metric);
        if system_scope != expected_scope {
            return Err(CvssValidationError::ScopeMetricMismatch {
                metric,
                expected: expected_scope,
                actual: system_scope,
            });
        }
        normalize_evidence_refs(&mut evidence_refs, true)
            .map_err(CvssValidationError::EvidenceReferences)?;
        validate_required_text(&rationale, MAX_REPORT_PROSE_BYTES)
            .map_err(|reason| CvssValidationError::InvalidRationale { reason })?;
        normalize_assumptions(&mut assumptions)?;
        validate_required_text(&assessor_or_tool, MAX_REPORT_PROSE_BYTES)
            .map_err(|reason| CvssValidationError::InvalidAssessorOrTool { reason })?;
        if let Some(value) = &mut assessed_at {
            validate_required_text(value, MAX_ASSESSED_AT_BYTES)
                .map_err(|reason| CvssValidationError::InvalidAssessedAt { reason })?;
            let parsed = DateTime::parse_from_rfc3339(value)
                .map_err(|_| CvssValidationError::AssessedAtNotRfc3339)?;
            *value = parsed.to_utc().to_rfc3339_opts(SecondsFormat::AutoSi, true);
        }
        Ok(Self {
            metric,
            value,
            basis,
            evidence_refs,
            rationale,
            assumptions,
            assessor_or_tool,
            assessed_at,
            system_scope,
            content_hash,
        })
    }

    pub const fn metric(&self) -> CvssMetric {
        self.metric
    }

    pub const fn value(&self) -> CvssMetricValue {
        self.value
    }

    pub const fn basis(&self) -> CvssEvidenceBasis {
        self.basis
    }

    pub fn evidence_refs(&self) -> &[EvidenceRef] {
        &self.evidence_refs
    }

    pub fn rationale(&self) -> &str {
        &self.rationale
    }

    pub fn assumptions(&self) -> &[String] {
        &self.assumptions
    }

    pub fn assessor_or_tool(&self) -> &str {
        &self.assessor_or_tool
    }

    pub fn assessed_at(&self) -> Option<&str> {
        self.assessed_at.as_deref()
    }

    pub const fn system_scope(&self) -> CvssEvidenceScope {
        self.system_scope
    }

    pub const fn content_hash(&self) -> CvssEvidenceContentHash {
        self.content_hash
    }

    fn validate(&self) -> Result<(), CvssValidationError> {
        Self::try_new(
            self.metric,
            self.value,
            self.basis,
            self.evidence_refs.clone(),
            self.rationale.clone(),
            self.assumptions.clone(),
            self.assessor_or_tool.clone(),
            self.assessed_at.clone(),
            self.system_scope,
            self.content_hash,
        )
        .and_then(|normalized| {
            if normalized == *self {
                Ok(())
            } else {
                Err(CvssValidationError::NonCanonicalEvidence)
            }
        })
    }

    fn canonical_cmp(left: &Self, right: &Self) -> Ordering {
        metric_rank(left.metric)
            .cmp(&metric_rank(right.metric))
            .then_with(|| left.value.first_label().cmp(right.value.first_label()))
            .then_with(|| left.basis.cmp(&right.basis))
            .then_with(|| left.content_hash.cmp(&right.content_hash))
    }
}

impl RetainedSize for CvssMetricEvidence {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(retained_extra(&self.evidence_refs))
            .saturating_add(retained_extra(&self.rationale))
            .saturating_add(retained_extra(&self.assumptions))
            .saturating_add(retained_extra(&self.assessor_or_tool))
            .saturating_add(retained_extra(&self.assessed_at))
    }
}

/// Why a coherent CVSS variant could not be scored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CvssUnscoredReason {
    MissingBaseEvidence,
    ConflictingMetricEvidence {
        metric: CvssMetric,
        evidence_set_hash: CvssEvidenceSetHash,
        evidence_refs: Vec<EvidenceRef>,
        evidence_refs_truncated: bool,
        omitted_evidence_refs_lower_bound: u64,
    },
    IncoherentScenario {
        scenario_set_hash: SourceScenarioSetHash,
        scenario_ids: Vec<SourceScenarioId>,
        scenario_ids_truncated: bool,
        omitted_scenario_ids_lower_bound: u64,
        rationale: String,
    },
    RunIncomplete {
        reason: PolicyIncompleteReason,
    },
}

impl CvssUnscoredReason {
    pub fn conflicting_metric_evidence(
        metric: CvssMetric,
        evidence_set_hash: CvssEvidenceSetHash,
        mut evidence_refs: Vec<EvidenceRef>,
        evidence_refs_truncated: bool,
        omitted_evidence_refs_lower_bound: u64,
    ) -> Result<Self, CvssValidationError> {
        normalize_evidence_refs(&mut evidence_refs, true)
            .map_err(CvssValidationError::EvidenceReferences)?;
        validate_truncation(
            "conflicting_metric_evidence.evidence_refs",
            evidence_refs_truncated,
            omitted_evidence_refs_lower_bound,
        )?;
        Ok(Self::ConflictingMetricEvidence {
            metric,
            evidence_set_hash,
            evidence_refs,
            evidence_refs_truncated,
            omitted_evidence_refs_lower_bound,
        })
    }

    pub fn incoherent_scenario(
        scenario_set_hash: SourceScenarioSetHash,
        mut scenario_ids: Vec<SourceScenarioId>,
        scenario_ids_truncated: bool,
        omitted_scenario_ids_lower_bound: u64,
        rationale: String,
    ) -> Result<Self, CvssValidationError> {
        normalize_scenario_ids(&mut scenario_ids, true)?;
        validate_truncation(
            "incoherent_scenario.scenario_ids",
            scenario_ids_truncated,
            omitted_scenario_ids_lower_bound,
        )?;
        validate_required_text(&rationale, MAX_REPORT_PROSE_BYTES)
            .map_err(|reason| CvssValidationError::InvalidRationale { reason })?;
        Ok(Self::IncoherentScenario {
            scenario_set_hash,
            scenario_ids,
            scenario_ids_truncated,
            omitted_scenario_ids_lower_bound,
            rationale,
        })
    }

    fn normalize(self) -> Result<Self, CvssValidationError> {
        match self {
            Self::MissingBaseEvidence => Ok(Self::MissingBaseEvidence),
            Self::ConflictingMetricEvidence {
                metric,
                evidence_set_hash,
                evidence_refs,
                evidence_refs_truncated,
                omitted_evidence_refs_lower_bound,
            } => Self::conflicting_metric_evidence(
                metric,
                evidence_set_hash,
                evidence_refs,
                evidence_refs_truncated,
                omitted_evidence_refs_lower_bound,
            ),
            Self::IncoherentScenario {
                scenario_set_hash,
                scenario_ids,
                scenario_ids_truncated,
                omitted_scenario_ids_lower_bound,
                rationale,
            } => Self::incoherent_scenario(
                scenario_set_hash,
                scenario_ids,
                scenario_ids_truncated,
                omitted_scenario_ids_lower_bound,
                rationale,
            ),
            Self::RunIncomplete { reason } => Ok(Self::RunIncomplete { reason }),
        }
    }

    fn canonical_cmp(left: &Self, right: &Self) -> Ordering {
        unscored_reason_key(left).cmp(&unscored_reason_key(right))
    }
}

impl RetainedSize for CvssUnscoredReason {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>().saturating_add(match self {
            Self::MissingBaseEvidence | Self::RunIncomplete { .. } => 0,
            Self::ConflictingMetricEvidence { evidence_refs, .. } => retained_extra(evidence_refs),
            Self::IncoherentScenario {
                scenario_ids,
                rationale,
                ..
            } => retained_extra(scenario_ids).saturating_add(retained_extra(rationale)),
        })
    }
}

/// One independently scored CVSS component.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CvssComponentResult {
    nomenclature: CvssNomenclature,
    vector: String,
    score: f64,
    severity: CvssSeverity,
}

impl CvssComponentResult {
    pub(crate) fn try_new(
        nomenclature: CvssNomenclature,
        vector: String,
        score: f64,
        severity: CvssSeverity,
    ) -> Result<Self, CvssValidationError> {
        validate_cvss_vector(&vector)?;
        validate_score(score, severity)?;
        Ok(Self {
            nomenclature,
            vector,
            score,
            severity,
        })
    }

    pub const fn nomenclature(&self) -> CvssNomenclature {
        self.nomenclature
    }

    pub fn vector(&self) -> &str {
        &self.vector
    }

    pub const fn score(&self) -> f64 {
        self.score
    }

    pub const fn severity(&self) -> CvssSeverity {
        self.severity
    }
}

impl RetainedSize for CvssComponentResult {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>().saturating_add(retained_extra(&self.vector))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CvssNomenclature {
    B,
    BT,
    BE,
    BTE,
}

impl Serialize for CvssNomenclature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(match self {
            Self::B => "b",
            Self::BT => "bt",
            Self::BE => "be",
            Self::BTE => "bte",
        })
    }
}

impl RetainedSize for CvssNomenclature {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CvssSeverity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl RetainedSize for CvssSeverity {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}

/// Canonical provenance shared by scored and unscored assessments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CvssAssessmentProvenance {
    reducer: String,
    evidence_refs: Vec<EvidenceRef>,
    overlay_scopes: Vec<PolicyOverlayScope>,
    content_hashes: Vec<CvssEvidenceContentHash>,
}

impl CvssAssessmentProvenance {
    pub fn try_new(
        reducer: String,
        mut evidence_refs: Vec<EvidenceRef>,
        mut overlay_scopes: Vec<PolicyOverlayScope>,
        mut content_hashes: Vec<CvssEvidenceContentHash>,
    ) -> Result<Self, CvssValidationError> {
        validate_namespaced_identifier(&reducer)
            .map_err(|reason| CvssValidationError::InvalidReducer { reason })?;
        normalize_evidence_refs(&mut evidence_refs, false)
            .map_err(CvssValidationError::EvidenceReferences)?;
        if overlay_scopes.len() > MAX_CVSS_OVERLAYS {
            return Err(CvssValidationError::TooManyItems {
                field: "cvss_provenance.overlay_scopes",
                max: MAX_CVSS_OVERLAYS,
            });
        }
        overlay_scopes.sort();
        overlay_scopes.dedup();
        content_hashes.sort();
        content_hashes.dedup();
        if content_hashes.len() > MAX_CVSS_EVIDENCE_RECORDS {
            return Err(CvssValidationError::TooManyItems {
                field: "cvss_provenance.content_hashes",
                max: MAX_CVSS_EVIDENCE_RECORDS,
            });
        }
        Ok(Self {
            reducer,
            evidence_refs,
            overlay_scopes,
            content_hashes,
        })
    }

    pub fn reducer(&self) -> &str {
        &self.reducer
    }

    pub fn evidence_refs(&self) -> &[EvidenceRef] {
        &self.evidence_refs
    }

    pub fn overlay_scopes(&self) -> &[PolicyOverlayScope] {
        &self.overlay_scopes
    }

    pub fn content_hashes(&self) -> &[CvssEvidenceContentHash] {
        &self.content_hashes
    }
}

impl RetainedSize for CvssAssessmentProvenance {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(retained_extra(&self.reducer))
            .saturating_add(retained_extra(&self.evidence_refs))
            .saturating_add(retained_extra(&self.overlay_scopes))
            .saturating_add(retained_extra(&self.content_hashes))
    }
}

/// One normalized coherent set of CVSS variants.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CvssAssessmentSet {
    variants: Vec<CvssAssessmentVariant>,
    selected_for_display: Option<CvssAssessmentVariantId>,
    selection_rationale: Option<String>,
}

impl CvssAssessmentSet {
    pub fn try_new(
        mut variants: Vec<CvssAssessmentVariant>,
        selected_for_display: Option<CvssAssessmentVariantId>,
    ) -> Result<Self, CvssValidationError> {
        if variants.is_empty() {
            return Err(CvssValidationError::EmptyVariants);
        }
        if variants.len() > MAX_CVSS_VARIANTS {
            return Err(CvssValidationError::TooManyItems {
                field: "cvss.variants",
                max: MAX_CVSS_VARIANTS,
            });
        }
        for variant in &variants {
            variant.validate()?;
        }
        variants.sort_by_key(|variant| variant.id);
        if variants.windows(2).any(|pair| pair[0].id == pair[1].id) {
            return Err(CvssValidationError::DuplicateVariantId);
        }

        let has_scored = variants
            .iter()
            .any(|variant| matches!(variant.assessment, CvssAssessment::Scored { .. }));
        let selection_rationale = if has_scored {
            let selected = selected_for_display.ok_or(CvssValidationError::MissingSelection)?;
            let selected_variant = variants
                .iter()
                .find(|variant| variant.id == selected)
                .ok_or(CvssValidationError::DanglingSelection)?;
            if !matches!(selected_variant.assessment, CvssAssessment::Scored { .. }) {
                return Err(CvssValidationError::SelectedVariantIsUnscored);
            }
            Some(SELECTED_VARIANT_RATIONALE.to_string())
        } else {
            if selected_for_display.is_some() {
                return Err(CvssValidationError::UnexpectedUnscoredSelection);
            }
            Some(UNSCORED_VARIANT_RATIONALE.to_string())
        };

        Ok(Self {
            variants,
            selected_for_display,
            selection_rationale,
        })
    }

    pub fn variants(&self) -> &[CvssAssessmentVariant] {
        &self.variants
    }

    pub const fn selected_for_display(&self) -> Option<CvssAssessmentVariantId> {
        self.selected_for_display
    }

    pub fn selection_rationale(&self) -> Option<&str> {
        self.selection_rationale.as_deref()
    }

    pub(crate) fn append_evidence_refs<'a>(&'a self, output: &mut Vec<&'a EvidenceRef>) {
        for variant in &self.variants {
            variant.assessment.append_evidence_refs(output);
        }
    }

    pub(crate) fn append_witness_refs<'a>(&'a self, output: &mut Vec<&'a WitnessId>) {
        for variant in &self.variants {
            output.extend(variant.witness_refs.iter());
        }
    }

    pub(crate) fn has_truncated_witness_refs(&self) -> bool {
        self.variants
            .iter()
            .any(|variant| variant.witness_refs_truncated)
    }

    pub(crate) fn has_truncated_source_scenarios(&self) -> bool {
        self.variants
            .iter()
            .any(|variant| variant.source_scenarios_truncated)
    }

    pub(crate) fn evidence_record_count(&self) -> usize {
        self.variants.iter().fold(0_usize, |total, variant| {
            total.saturating_add(variant.assessment.evidence_record_count())
        })
    }
}

impl RetainedSize for CvssAssessmentSet {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(retained_extra(&self.variants))
            .saturating_add(retained_extra(&self.selection_rationale))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CvssAssessmentVariant {
    id: CvssAssessmentVariantId,
    vulnerability_identity: VulnerabilityIdentity,
    source_scenarios: Vec<SourceScenarioId>,
    source_scenarios_truncated: bool,
    omitted_source_scenarios_lower_bound: u64,
    source_scenario_set_hash: SourceScenarioSetHash,
    witness_refs: Vec<WitnessId>,
    witness_refs_truncated: bool,
    assessment: CvssAssessment,
}

impl CvssAssessmentVariant {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        id: CvssAssessmentVariantId,
        vulnerability_identity: VulnerabilityIdentity,
        mut source_scenarios: Vec<SourceScenarioId>,
        source_scenarios_truncated: bool,
        omitted_source_scenarios_lower_bound: u64,
        source_scenario_set_hash: SourceScenarioSetHash,
        mut witness_refs: Vec<WitnessId>,
        witness_refs_truncated: bool,
        assessment: CvssAssessment,
    ) -> Result<Self, CvssValidationError> {
        normalize_scenario_ids(&mut source_scenarios, false)?;
        validate_truncation(
            "cvss_variant.source_scenarios",
            source_scenarios_truncated,
            omitted_source_scenarios_lower_bound,
        )?;
        if witness_refs.len() > MAX_WITNESS_REFS {
            return Err(CvssValidationError::TooManyItems {
                field: "cvss_variant.witness_refs",
                max: MAX_WITNESS_REFS,
            });
        }
        witness_refs.sort();
        witness_refs.dedup();
        assessment.validate()?;
        Ok(Self {
            id,
            vulnerability_identity,
            source_scenarios,
            source_scenarios_truncated,
            omitted_source_scenarios_lower_bound,
            source_scenario_set_hash,
            witness_refs,
            witness_refs_truncated,
            assessment,
        })
    }

    pub const fn id(&self) -> CvssAssessmentVariantId {
        self.id
    }

    pub const fn vulnerability_identity(&self) -> VulnerabilityIdentity {
        self.vulnerability_identity
    }

    pub fn source_scenarios(&self) -> &[SourceScenarioId] {
        &self.source_scenarios
    }

    pub const fn source_scenarios_truncated(&self) -> bool {
        self.source_scenarios_truncated
    }

    pub const fn omitted_source_scenarios_lower_bound(&self) -> u64 {
        self.omitted_source_scenarios_lower_bound
    }

    pub const fn source_scenario_set_hash(&self) -> SourceScenarioSetHash {
        self.source_scenario_set_hash
    }

    pub fn witness_refs(&self) -> &[WitnessId] {
        &self.witness_refs
    }

    pub const fn witness_refs_truncated(&self) -> bool {
        self.witness_refs_truncated
    }

    pub const fn assessment(&self) -> &CvssAssessment {
        &self.assessment
    }

    fn validate(&self) -> Result<(), CvssValidationError> {
        Self::try_new(
            self.id,
            self.vulnerability_identity,
            self.source_scenarios.clone(),
            self.source_scenarios_truncated,
            self.omitted_source_scenarios_lower_bound,
            self.source_scenario_set_hash,
            self.witness_refs.clone(),
            self.witness_refs_truncated,
            self.assessment.clone(),
        )
        .and_then(|normalized| {
            if normalized == *self {
                Ok(())
            } else {
                Err(CvssValidationError::NonCanonicalVariant)
            }
        })
    }
}

impl RetainedSize for CvssAssessmentVariant {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(retained_extra(&self.source_scenarios))
            .saturating_add(retained_extra(&self.witness_refs))
            .saturating_add(retained_extra(&self.assessment))
    }
}

/// A complete or explicitly unscored CVSS assessment.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CvssAssessment {
    #[non_exhaustive]
    Scored {
        version: CvssVersion,
        nomenclature: CvssNomenclature,
        vector: String,
        components: Vec<CvssComponentResult>,
        metrics: Vec<CvssMetricEvidence>,
        provenance: CvssAssessmentProvenance,
    },
    #[non_exhaustive]
    Unscored {
        version: CvssVersion,
        established: Vec<CvssMetricEvidence>,
        missing_base_metrics: Vec<CvssBaseMetric>,
        reasons: Vec<CvssUnscoredReason>,
        provenance: CvssAssessmentProvenance,
    },
}

impl CvssAssessment {
    /// Accept a score only from the future crate-owned RustSec reducer. This
    /// shape checkpoint validates structural coherence but never treats a
    /// caller-supplied numeric value as an assessment.
    pub(crate) fn scored(
        version: CvssVersion,
        nomenclature: CvssNomenclature,
        vector: String,
        mut components: Vec<CvssComponentResult>,
        mut metrics: Vec<CvssMetricEvidence>,
        provenance: CvssAssessmentProvenance,
    ) -> Result<Self, CvssValidationError> {
        validate_cvss_vector(&vector)?;
        if components.is_empty() || components.len() > MAX_CVSS_COMPONENTS {
            return Err(CvssValidationError::InvalidComponentCount {
                max: MAX_CVSS_COMPONENTS,
            });
        }
        components.sort_by_key(|component| component.nomenclature);
        if components
            .windows(2)
            .any(|pair| pair[0].nomenclature == pair[1].nomenclature)
        {
            return Err(CvssValidationError::DuplicateComponent);
        }
        if !components
            .iter()
            .any(|component| component.nomenclature == CvssNomenclature::B)
        {
            return Err(CvssValidationError::MissingBaseComponent);
        }
        if !components
            .iter()
            .any(|component| component.nomenclature == nomenclature)
        {
            return Err(CvssValidationError::MissingNamedComponent { nomenclature });
        }
        for component in &components {
            let normalized = CvssComponentResult::try_new(
                component.nomenclature,
                component.vector.clone(),
                component.score,
                component.severity,
            )?;
            if normalized != *component {
                return Err(CvssValidationError::NonCanonicalAssessment);
            }
        }
        normalize_metric_evidence(&mut metrics, true)?;
        if !all_base_metrics_established(&metrics) {
            return Err(CvssValidationError::IncompleteScoredBaseMetrics);
        }
        Ok(Self::Scored {
            version,
            nomenclature,
            vector,
            components,
            metrics,
            provenance,
        })
    }

    pub fn unscored(
        version: CvssVersion,
        mut established: Vec<CvssMetricEvidence>,
        mut missing_base_metrics: Vec<CvssBaseMetric>,
        reasons: Vec<CvssUnscoredReason>,
        provenance: CvssAssessmentProvenance,
    ) -> Result<Self, CvssValidationError> {
        normalize_metric_evidence(&mut established, false)?;
        missing_base_metrics
            .sort_by_key(|metric| metric_rank(CvssMetric::Base { metric: *metric }));
        missing_base_metrics.dedup();
        let mut normalized_reasons = Vec::with_capacity(reasons.len());
        for reason in reasons {
            normalized_reasons.push(reason.normalize()?);
        }
        normalized_reasons.sort_by(CvssUnscoredReason::canonical_cmp);
        normalized_reasons.dedup();
        if normalized_reasons.is_empty() {
            return Err(CvssValidationError::EmptyUnscoredReasons);
        }
        let has_missing_reason = normalized_reasons
            .iter()
            .any(|reason| matches!(reason, CvssUnscoredReason::MissingBaseEvidence));
        if has_missing_reason == missing_base_metrics.is_empty() {
            return Err(CvssValidationError::MissingBaseReasonMismatch);
        }
        Ok(Self::Unscored {
            version,
            established,
            missing_base_metrics,
            reasons: normalized_reasons,
            provenance,
        })
    }

    pub const fn is_scored(&self) -> bool {
        matches!(self, Self::Scored { .. })
    }

    fn append_evidence_refs<'a>(&'a self, output: &mut Vec<&'a EvidenceRef>) {
        match self {
            Self::Scored {
                metrics,
                provenance,
                ..
            } => {
                for metric in metrics {
                    output.extend(metric.evidence_refs.iter());
                }
                output.extend(provenance.evidence_refs.iter());
            }
            Self::Unscored {
                established,
                reasons,
                provenance,
                ..
            } => {
                for metric in established {
                    output.extend(metric.evidence_refs.iter());
                }
                for reason in reasons {
                    if let CvssUnscoredReason::ConflictingMetricEvidence { evidence_refs, .. } =
                        reason
                    {
                        output.extend(evidence_refs.iter());
                    }
                }
                output.extend(provenance.evidence_refs.iter());
            }
        }
    }

    fn evidence_record_count(&self) -> usize {
        match self {
            Self::Scored { metrics, .. } => metrics.len(),
            Self::Unscored {
                established,
                reasons,
                ..
            } => established.len().saturating_add(
                reasons
                    .iter()
                    .filter(|reason| {
                        matches!(reason, CvssUnscoredReason::ConflictingMetricEvidence { .. })
                    })
                    .count(),
            ),
        }
    }

    fn validate(&self) -> Result<(), CvssValidationError> {
        let normalized = match self {
            Self::Scored {
                version,
                nomenclature,
                vector,
                components,
                metrics,
                provenance,
            } => Self::scored(
                *version,
                *nomenclature,
                vector.clone(),
                components.clone(),
                metrics.clone(),
                provenance.clone(),
            )?,
            Self::Unscored {
                version,
                established,
                missing_base_metrics,
                reasons,
                provenance,
            } => Self::unscored(
                *version,
                established.clone(),
                missing_base_metrics.clone(),
                reasons.clone(),
                provenance.clone(),
            )?,
        };
        if &normalized == self {
            Ok(())
        } else {
            Err(CvssValidationError::NonCanonicalAssessment)
        }
    }
}

impl RetainedSize for CvssAssessment {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>().saturating_add(match self {
            Self::Scored {
                vector,
                components,
                metrics,
                provenance,
                ..
            } => retained_extra(vector)
                .saturating_add(retained_extra(components))
                .saturating_add(retained_extra(metrics))
                .saturating_add(retained_extra(provenance)),
            Self::Unscored {
                established,
                missing_base_metrics,
                reasons,
                provenance,
                ..
            } => retained_extra(established)
                .saturating_add(retained_extra(missing_base_metrics))
                .saturating_add(retained_extra(reasons))
                .saturating_add(retained_extra(provenance)),
        })
    }
}

/// Scope used by CVSS and organizational-risk evaluation overlays.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PolicyOverlayScope {
    AllFindings,
    Policy {
        policy_id: PolicyId,
    },
    Finding {
        finding_id: PolicyFindingId,
    },
    SourceScenario {
        scenario_id: SourceScenarioId,
    },
    FindingScenario {
        finding: PolicyFindingId,
        scenario: SourceScenarioId,
    },
}

impl Serialize for PolicyOverlayScope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::AllFindings => {
                let mut state = serializer.serialize_struct("PolicyOverlayScope", 1)?;
                state.serialize_field("type", "all_findings")?;
                state.end()
            }
            Self::Policy { policy_id } => {
                let mut state = serializer.serialize_struct("PolicyOverlayScope", 2)?;
                state.serialize_field("type", "policy")?;
                state.serialize_field("policy_id", policy_id.as_str())?;
                state.end()
            }
            Self::Finding { finding_id } => {
                let mut state = serializer.serialize_struct("PolicyOverlayScope", 2)?;
                state.serialize_field("type", "finding")?;
                state.serialize_field("finding_id", finding_id)?;
                state.end()
            }
            Self::SourceScenario { scenario_id } => {
                let mut state = serializer.serialize_struct("PolicyOverlayScope", 2)?;
                state.serialize_field("type", "source_scenario")?;
                state.serialize_field("scenario_id", scenario_id)?;
                state.end()
            }
            Self::FindingScenario { finding, scenario } => {
                let mut state = serializer.serialize_struct("PolicyOverlayScope", 3)?;
                state.serialize_field("type", "finding_scenario")?;
                state.serialize_field("finding", finding)?;
                state.serialize_field("scenario", scenario)?;
                state.end()
            }
        }
    }
}

impl RetainedSize for PolicyOverlayScope {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>().saturating_add(match self {
            Self::AllFindings | Self::Finding { .. } => 0,
            Self::Policy { policy_id } => policy_id.as_str().len(),
            Self::SourceScenario { scenario_id } => retained_extra(scenario_id),
            Self::FindingScenario { scenario, .. } => retained_extra(scenario),
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum CvssValidationError {
    MetricValueMismatch {
        metric: CvssMetric,
        value_metric: CvssMetric,
    },
    BasisMetricMismatch {
        basis: CvssEvidenceBasis,
        metric: CvssMetric,
    },
    ScopeMetricMismatch {
        metric: CvssMetric,
        expected: CvssEvidenceScope,
        actual: CvssEvidenceScope,
    },
    EvidenceReferences(EvidenceReferenceError),
    InvalidRationale {
        reason: TextValidationError,
    },
    InvalidAssumption {
        index: usize,
        reason: TextValidationError,
    },
    TooManyAssumptions {
        max: usize,
    },
    InvalidAssessorOrTool {
        reason: TextValidationError,
    },
    InvalidAssessedAt {
        reason: TextValidationError,
    },
    AssessedAtNotRfc3339,
    InvalidReducer {
        reason: TextValidationError,
    },
    InvalidVector,
    InvalidScore,
    ScoreSeverityMismatch {
        score: f64,
        severity: CvssSeverity,
    },
    TooManyItems {
        field: &'static str,
        max: usize,
    },
    EmptyScenarioIds,
    InvalidTruncation {
        field: &'static str,
    },
    NonCanonicalEvidence,
    ConflictingEvidenceContentHash,
    InvalidComponentCount {
        max: usize,
    },
    DuplicateComponent,
    MissingBaseComponent,
    MissingNamedComponent {
        nomenclature: CvssNomenclature,
    },
    IncompleteScoredBaseMetrics,
    EmptyUnscoredReasons,
    MissingBaseReasonMismatch,
    NonCanonicalAssessment,
    NonCanonicalVariant,
    EmptyVariants,
    DuplicateVariantId,
    MissingSelection,
    DanglingSelection,
    SelectedVariantIsUnscored,
    UnexpectedUnscoredSelection,
}

impl fmt::Display for CvssValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MetricValueMismatch {
                metric,
                value_metric,
            } => write!(
                formatter,
                "CVSS value for {} cannot establish {}",
                value_metric.first_label(),
                metric.first_label()
            ),
            Self::BasisMetricMismatch { basis, metric } => write!(
                formatter,
                "CVSS basis {basis:?} cannot establish {}",
                metric.first_label()
            ),
            Self::ScopeMetricMismatch {
                metric,
                expected,
                actual,
            } => write!(
                formatter,
                "CVSS metric {} requires scope {expected:?}, found {actual:?}",
                metric.first_label()
            ),
            Self::EvidenceReferences(error) => error.fmt(formatter),
            Self::InvalidRationale { reason } => write!(formatter, "invalid rationale: {reason}"),
            Self::InvalidAssumption { index, reason } => {
                write!(formatter, "invalid assumption {index}: {reason}")
            }
            Self::TooManyAssumptions { max } => {
                write!(formatter, "CVSS evidence accepts at most {max} assumptions")
            }
            Self::InvalidAssessorOrTool { reason } => {
                write!(formatter, "invalid assessor or tool: {reason}")
            }
            Self::InvalidAssessedAt { reason } => {
                write!(formatter, "invalid assessment time: {reason}")
            }
            Self::AssessedAtNotRfc3339 => formatter.write_str("assessment time must be RFC 3339"),
            Self::InvalidReducer { reason } => write!(formatter, "invalid reducer: {reason}"),
            Self::InvalidVector => formatter.write_str("invalid canonical CVSS v4 vector"),
            Self::InvalidScore => formatter.write_str(
                "CVSS score must be finite, 0.0 through 10.0, and use one decimal place",
            ),
            Self::ScoreSeverityMismatch { score, severity } => write!(
                formatter,
                "CVSS score {score:.1} is inconsistent with severity {severity:?}"
            ),
            Self::TooManyItems { field, max } => {
                write!(formatter, "{field} accepts at most {max} items")
            }
            Self::EmptyScenarioIds => {
                formatter.write_str("at least one source scenario is required")
            }
            Self::InvalidTruncation { field } => write!(
                formatter,
                "{field} truncation flag and omitted lower bound are inconsistent"
            ),
            Self::NonCanonicalEvidence => {
                formatter.write_str("CVSS metric evidence is not canonically normalized")
            }
            Self::ConflictingEvidenceContentHash => formatter
                .write_str("one CVSS evidence content hash cannot identify different records"),
            Self::InvalidComponentCount { max } => write!(
                formatter,
                "scored CVSS assessment requires one through {max} components"
            ),
            Self::DuplicateComponent => {
                formatter.write_str("CVSS components must have unique nomenclatures")
            }
            Self::MissingBaseComponent => {
                formatter.write_str("every scored CVSS assessment requires a base component")
            }
            Self::MissingNamedComponent { nomenclature } => write!(
                formatter,
                "scored CVSS assessment has no {nomenclature:?} component"
            ),
            Self::IncompleteScoredBaseMetrics => {
                formatter.write_str("scored CVSS assessment requires all eleven base metrics")
            }
            Self::EmptyUnscoredReasons => {
                formatter.write_str("unscored CVSS assessment requires at least one typed reason")
            }
            Self::MissingBaseReasonMismatch => {
                formatter.write_str("missing-base metrics and missing-base reason must agree")
            }
            Self::NonCanonicalAssessment => {
                formatter.write_str("CVSS assessment is not canonically normalized")
            }
            Self::NonCanonicalVariant => {
                formatter.write_str("CVSS assessment variant is not canonically normalized")
            }
            Self::EmptyVariants => {
                formatter.write_str("CVSS assessment set requires at least one variant")
            }
            Self::DuplicateVariantId => {
                formatter.write_str("CVSS assessment variant IDs must be unique")
            }
            Self::MissingSelection => {
                formatter.write_str("a scored CVSS assessment set requires a display selection")
            }
            Self::DanglingSelection => {
                formatter.write_str("CVSS display selection does not name a retained variant")
            }
            Self::SelectedVariantIsUnscored => {
                formatter.write_str("CVSS display selection must name a scored variant")
            }
            Self::UnexpectedUnscoredSelection => {
                formatter.write_str("an all-unscored CVSS set cannot select a display variant")
            }
        }
    }
}

impl std::error::Error for CvssValidationError {}

fn normalize_assumptions(values: &mut Vec<String>) -> Result<(), CvssValidationError> {
    if values.len() > MAX_CVSS_ASSUMPTIONS {
        return Err(CvssValidationError::TooManyAssumptions {
            max: MAX_CVSS_ASSUMPTIONS,
        });
    }
    for (index, value) in values.iter().enumerate() {
        validate_required_text(value, MAX_REPORT_PROSE_BYTES)
            .map_err(|reason| CvssValidationError::InvalidAssumption { index, reason })?;
    }
    values.sort();
    values.dedup();
    Ok(())
}

fn normalize_scenario_ids(
    values: &mut Vec<SourceScenarioId>,
    require_nonempty: bool,
) -> Result<(), CvssValidationError> {
    if values.len() > MAX_SOURCE_SCENARIOS {
        return Err(CvssValidationError::TooManyItems {
            field: "source_scenarios",
            max: MAX_SOURCE_SCENARIOS,
        });
    }
    values.sort();
    values.dedup();
    if require_nonempty && values.is_empty() {
        return Err(CvssValidationError::EmptyScenarioIds);
    }
    Ok(())
}

fn normalize_metric_evidence(
    values: &mut Vec<CvssMetricEvidence>,
    require_nonempty: bool,
) -> Result<(), CvssValidationError> {
    if values.len() > MAX_CVSS_EVIDENCE_RECORDS {
        return Err(CvssValidationError::TooManyItems {
            field: "cvss.metric_evidence",
            max: MAX_CVSS_EVIDENCE_RECORDS,
        });
    }
    for value in values.iter() {
        value.validate()?;
    }
    let mut by_hash = values.iter().collect::<Vec<_>>();
    by_hash.sort_by_key(|value| value.content_hash);
    if by_hash
        .windows(2)
        .any(|pair| pair[0].content_hash == pair[1].content_hash && pair[0] != pair[1])
    {
        return Err(CvssValidationError::ConflictingEvidenceContentHash);
    }
    values.sort_by(CvssMetricEvidence::canonical_cmp);
    values.dedup();
    if require_nonempty && values.is_empty() {
        return Err(CvssValidationError::IncompleteScoredBaseMetrics);
    }
    Ok(())
}

fn validate_truncation(
    field: &'static str,
    truncated: bool,
    omitted_lower_bound: u64,
) -> Result<(), CvssValidationError> {
    if truncated != (omitted_lower_bound > 0) {
        return Err(CvssValidationError::InvalidTruncation { field });
    }
    Ok(())
}

fn validate_cvss_vector(vector: &str) -> Result<(), CvssValidationError> {
    validate_required_text(vector, MAX_CVSS_VECTOR_BYTES)
        .map_err(|_| CvssValidationError::InvalidVector)?;
    if !vector.starts_with("CVSS:4.0/") || !vector.is_ascii() {
        return Err(CvssValidationError::InvalidVector);
    }
    Ok(())
}

fn validate_score(score: f64, severity: CvssSeverity) -> Result<(), CvssValidationError> {
    if !score.is_finite()
        || !(0.0..=10.0).contains(&score)
        || (score * 10.0 - (score * 10.0).round()).abs() > f64::EPSILON
    {
        return Err(CvssValidationError::InvalidScore);
    }
    let expected = if score == 0.0 {
        CvssSeverity::None
    } else if score < 4.0 {
        CvssSeverity::Low
    } else if score < 7.0 {
        CvssSeverity::Medium
    } else if score < 9.0 {
        CvssSeverity::High
    } else {
        CvssSeverity::Critical
    };
    if severity != expected {
        return Err(CvssValidationError::ScoreSeverityMismatch { score, severity });
    }
    Ok(())
}

const fn basis_allows_metric(basis: CvssEvidenceBasis, metric: CvssMetric) -> bool {
    matches!(
        (basis, metric),
        (
            CvssEvidenceBasis::PolicyAssertion | CvssEvidenceBasis::StaticWitness,
            CvssMetric::Base { .. }
        ) | (CvssEvidenceBasis::ThreatFeed, CvssMetric::Threat { .. })
            | (
                CvssEvidenceBasis::EnvironmentProfile,
                CvssMetric::EnvironmentalOrSupplemental { .. }
            )
            | (CvssEvidenceBasis::AnalystOverride, _)
    )
}

const fn required_scope(metric: CvssMetric) -> CvssEvidenceScope {
    match metric {
        CvssMetric::Base { metric } => metric.required_scope(),
        CvssMetric::Threat { .. } => CvssEvidenceScope::Global,
        CvssMetric::EnvironmentalOrSupplemental { metric } => {
            use CvssEnvironmentalOrSupplementalMetric as M;
            match metric {
                M::Mav | M::Mac | M::Mat | M::Mpr | M::Mui | M::Mvc | M::Mvi | M::Mva => {
                    CvssEvidenceScope::System {
                        system: CvssSystemScope::VulnerableSystem,
                    }
                }
                M::Msc | M::Msi | M::Msa => CvssEvidenceScope::System {
                    system: CvssSystemScope::SubsequentSystem,
                },
                M::Cr | M::Ir | M::Ar | M::S | M::Au | M::R | M::V | M::Re | M::U => {
                    CvssEvidenceScope::Global
                }
            }
        }
    }
}

const fn metric_rank(metric: CvssMetric) -> u8 {
    use CvssBaseMetric as B;
    use CvssEnvironmentalOrSupplementalMetric as E;
    match metric {
        CvssMetric::Base { metric } => match metric {
            B::Av => 0,
            B::Ac => 1,
            B::At => 2,
            B::Pr => 3,
            B::Ui => 4,
            B::Vc => 5,
            B::Vi => 6,
            B::Va => 7,
            B::Sc => 8,
            B::Si => 9,
            B::Sa => 10,
        },
        CvssMetric::Threat { .. } => 11,
        CvssMetric::EnvironmentalOrSupplemental { metric } => match metric {
            E::Cr => 12,
            E::Ir => 13,
            E::Ar => 14,
            E::Mav => 15,
            E::Mac => 16,
            E::Mat => 17,
            E::Mpr => 18,
            E::Mui => 19,
            E::Mvc => 20,
            E::Mvi => 21,
            E::Mva => 22,
            E::Msc => 23,
            E::Msi => 24,
            E::Msa => 25,
            E::S => 26,
            E::Au => 27,
            E::R => 28,
            E::V => 29,
            E::Re => 30,
            E::U => 31,
        },
    }
}

fn all_base_metrics_established(values: &[CvssMetricEvidence]) -> bool {
    let mut present = [false; 11];
    for value in values {
        if let CvssMetric::Base { .. } = value.metric {
            present[usize::from(metric_rank(value.metric))] = true;
        }
    }
    present.into_iter().all(|value| value)
}

fn unscored_reason_key(reason: &CvssUnscoredReason) -> (u8, u8, [u8; 32], String) {
    match reason {
        CvssUnscoredReason::MissingBaseEvidence => (0, 0, [0; 32], String::new()),
        CvssUnscoredReason::ConflictingMetricEvidence {
            metric,
            evidence_set_hash,
            ..
        } => (
            1,
            metric_rank(*metric),
            *evidence_set_hash.as_bytes(),
            String::new(),
        ),
        CvssUnscoredReason::IncoherentScenario {
            scenario_set_hash,
            rationale,
            ..
        } => (2, 0, *scenario_set_hash.as_bytes(), rationale.clone()),
        CvssUnscoredReason::RunIncomplete { reason } => (3, *reason as u8, [0; 32], String::new()),
    }
}

impl Serialize for CvssVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.wire_label())
    }
}

impl Serialize for CvssBaseMetric {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.first_label())
    }
}

impl RetainedSize for CvssBaseMetric {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}

impl Serialize for CvssThreatMetric {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.first_label())
    }
}

impl Serialize for CvssEnvironmentalOrSupplementalMetric {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.first_label())
    }
}

impl Serialize for CvssMetric {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.first_label())
    }
}

impl Serialize for CvssMetricValueToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.first_label())
    }
}

impl Serialize for CvssMetricValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.first_label())
    }
}

impl Serialize for CvssSystemScope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(match self {
            Self::VulnerableSystem => "vulnerable_system",
            Self::SubsequentSystem => "subsequent_system",
        })
    }
}

impl Serialize for CvssEvidenceScope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Global => {
                let mut state = serializer.serialize_struct("CvssEvidenceScope", 1)?;
                state.serialize_field("type", "global")?;
                state.end()
            }
            Self::System { system } => {
                let mut state = serializer.serialize_struct("CvssEvidenceScope", 2)?;
                state.serialize_field("type", "system")?;
                state.serialize_field("system", system)?;
                state.end()
            }
        }
    }
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

    fn evidence_ref(value: &str) -> EvidenceRef {
        EvidenceRef::try_new("cvss", value).unwrap()
    }

    fn base_value(metric: CvssBaseMetric) -> CvssMetricValue {
        let token = match metric {
            CvssBaseMetric::Ac => CvssMetricValueToken::L,
            CvssBaseMetric::At | CvssBaseMetric::Av | CvssBaseMetric::Pr | CvssBaseMetric::Ui => {
                CvssMetricValueToken::N
            }
            CvssBaseMetric::Vc
            | CvssBaseMetric::Vi
            | CvssBaseMetric::Va
            | CvssBaseMetric::Sc
            | CvssBaseMetric::Si
            | CvssBaseMetric::Sa => CvssMetricValueToken::H,
        };
        CvssMetricValue::try_new(CvssMetric::Base { metric }, token).unwrap()
    }

    fn metric_evidence(metric: CvssBaseMetric, byte: u8) -> CvssMetricEvidence {
        CvssMetricEvidence::try_new(
            CvssMetric::Base { metric },
            base_value(metric),
            CvssEvidenceBasis::PolicyAssertion,
            vec![evidence_ref(metric.first_label())],
            "Verified policy assertion".to_string(),
            vec!["Deployment matches the policy model".to_string()],
            "bifrost-policy".to_string(),
            None,
            metric.required_scope(),
            CvssEvidenceContentHash::from_bytes([byte; 32]),
        )
        .unwrap()
    }

    fn provenance() -> CvssAssessmentProvenance {
        CvssAssessmentProvenance::try_new(
            "bifrost.cvss-v4".to_string(),
            Vec::new(),
            vec![PolicyOverlayScope::AllFindings],
            Vec::new(),
        )
        .unwrap()
    }

    #[test]
    fn first_atoms_and_tagged_units_use_exact_schema_v1_wire() {
        assert_eq!(serde_json::to_value(CvssVersion::V4_0).unwrap(), "4.0");
        assert_eq!(
            serde_json::to_value(CvssMetric::Base {
                metric: CvssBaseMetric::Av
            })
            .unwrap(),
            "AV"
        );
        assert_eq!(
            serde_json::to_value(base_value(CvssBaseMetric::Av)).unwrap(),
            "N"
        );
        assert_eq!(
            serde_json::to_value(CvssEvidenceScope::Global).unwrap(),
            json!({ "type": "global" })
        );
        assert_eq!(
            serde_json::to_value(CvssEvidenceScope::System {
                system: CvssSystemScope::VulnerableSystem,
            })
            .unwrap(),
            json!({ "type": "system", "system": "vulnerable_system" })
        );
        assert_eq!(
            serde_json::to_value(CvssUnscoredReason::MissingBaseEvidence).unwrap(),
            json!({ "type": "missing_base_evidence" })
        );
        assert_eq!(
            serde_json::to_value(PolicyOverlayScope::AllFindings).unwrap(),
            json!({ "type": "all_findings" })
        );
        assert_eq!(serde_json::to_value(CvssNomenclature::BTE).unwrap(), "bte");
    }

    #[test]
    fn every_metric_and_value_atom_has_its_exact_first_label() {
        let metrics = [
            CvssMetric::Base {
                metric: CvssBaseMetric::Av,
            },
            CvssMetric::Base {
                metric: CvssBaseMetric::Ac,
            },
            CvssMetric::Base {
                metric: CvssBaseMetric::At,
            },
            CvssMetric::Base {
                metric: CvssBaseMetric::Pr,
            },
            CvssMetric::Base {
                metric: CvssBaseMetric::Ui,
            },
            CvssMetric::Base {
                metric: CvssBaseMetric::Vc,
            },
            CvssMetric::Base {
                metric: CvssBaseMetric::Vi,
            },
            CvssMetric::Base {
                metric: CvssBaseMetric::Va,
            },
            CvssMetric::Base {
                metric: CvssBaseMetric::Sc,
            },
            CvssMetric::Base {
                metric: CvssBaseMetric::Si,
            },
            CvssMetric::Base {
                metric: CvssBaseMetric::Sa,
            },
            CvssMetric::Threat {
                metric: CvssThreatMetric::E,
            },
            CvssMetric::EnvironmentalOrSupplemental {
                metric: CvssEnvironmentalOrSupplementalMetric::Cr,
            },
            CvssMetric::EnvironmentalOrSupplemental {
                metric: CvssEnvironmentalOrSupplementalMetric::Ir,
            },
            CvssMetric::EnvironmentalOrSupplemental {
                metric: CvssEnvironmentalOrSupplementalMetric::Ar,
            },
            CvssMetric::EnvironmentalOrSupplemental {
                metric: CvssEnvironmentalOrSupplementalMetric::Mav,
            },
            CvssMetric::EnvironmentalOrSupplemental {
                metric: CvssEnvironmentalOrSupplementalMetric::Mac,
            },
            CvssMetric::EnvironmentalOrSupplemental {
                metric: CvssEnvironmentalOrSupplementalMetric::Mat,
            },
            CvssMetric::EnvironmentalOrSupplemental {
                metric: CvssEnvironmentalOrSupplementalMetric::Mpr,
            },
            CvssMetric::EnvironmentalOrSupplemental {
                metric: CvssEnvironmentalOrSupplementalMetric::Mui,
            },
            CvssMetric::EnvironmentalOrSupplemental {
                metric: CvssEnvironmentalOrSupplementalMetric::Mvc,
            },
            CvssMetric::EnvironmentalOrSupplemental {
                metric: CvssEnvironmentalOrSupplementalMetric::Mvi,
            },
            CvssMetric::EnvironmentalOrSupplemental {
                metric: CvssEnvironmentalOrSupplementalMetric::Mva,
            },
            CvssMetric::EnvironmentalOrSupplemental {
                metric: CvssEnvironmentalOrSupplementalMetric::Msc,
            },
            CvssMetric::EnvironmentalOrSupplemental {
                metric: CvssEnvironmentalOrSupplementalMetric::Msi,
            },
            CvssMetric::EnvironmentalOrSupplemental {
                metric: CvssEnvironmentalOrSupplementalMetric::Msa,
            },
            CvssMetric::EnvironmentalOrSupplemental {
                metric: CvssEnvironmentalOrSupplementalMetric::S,
            },
            CvssMetric::EnvironmentalOrSupplemental {
                metric: CvssEnvironmentalOrSupplementalMetric::Au,
            },
            CvssMetric::EnvironmentalOrSupplemental {
                metric: CvssEnvironmentalOrSupplementalMetric::R,
            },
            CvssMetric::EnvironmentalOrSupplemental {
                metric: CvssEnvironmentalOrSupplementalMetric::V,
            },
            CvssMetric::EnvironmentalOrSupplemental {
                metric: CvssEnvironmentalOrSupplementalMetric::Re,
            },
            CvssMetric::EnvironmentalOrSupplemental {
                metric: CvssEnvironmentalOrSupplementalMetric::U,
            },
        ];
        assert_eq!(
            metrics
                .into_iter()
                .map(|metric| serde_json::to_value(metric).unwrap())
                .collect::<Vec<_>>(),
            [
                "AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA", "E", "CR", "IR",
                "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA",
                "S", "AU", "R", "V", "RE", "U",
            ]
            .into_iter()
            .map(serde_json::Value::from)
            .collect::<Vec<_>>()
        );

        let tokens = [
            CvssMetricValueToken::X,
            CvssMetricValueToken::N,
            CvssMetricValueToken::A,
            CvssMetricValueToken::L,
            CvssMetricValueToken::P,
            CvssMetricValueToken::H,
            CvssMetricValueToken::M,
            CvssMetricValueToken::U,
            CvssMetricValueToken::S,
            CvssMetricValueToken::Y,
            CvssMetricValueToken::I,
            CvssMetricValueToken::D,
            CvssMetricValueToken::C,
            CvssMetricValueToken::Clear,
            CvssMetricValueToken::Green,
            CvssMetricValueToken::Amber,
            CvssMetricValueToken::Red,
        ];
        assert_eq!(
            tokens
                .into_iter()
                .map(|token| serde_json::to_value(token).unwrap())
                .collect::<Vec<_>>(),
            [
                "X", "N", "A", "L", "P", "H", "M", "U", "S", "Y", "I", "D", "C", "Clear", "Green",
                "Amber", "Red",
            ]
            .into_iter()
            .map(serde_json::Value::from)
            .collect::<Vec<_>>()
        );
    }

    #[test]
    fn evidence_enforces_metric_value_basis_scope_and_provenance() {
        let av = CvssMetric::Base {
            metric: CvssBaseMetric::Av,
        };
        assert!(
            CvssMetricEvidence::try_new(
                av,
                base_value(CvssBaseMetric::Ac),
                CvssEvidenceBasis::PolicyAssertion,
                vec![evidence_ref("proof")],
                "reason".to_string(),
                Vec::new(),
                "tool".to_string(),
                None,
                CvssBaseMetric::Av.required_scope(),
                CvssEvidenceContentHash::from_bytes([1; 32]),
            )
            .is_err()
        );
        assert!(
            CvssMetricEvidence::try_new(
                av,
                base_value(CvssBaseMetric::Av),
                CvssEvidenceBasis::ThreatFeed,
                vec![evidence_ref("proof")],
                "reason".to_string(),
                Vec::new(),
                "tool".to_string(),
                None,
                CvssBaseMetric::Av.required_scope(),
                CvssEvidenceContentHash::from_bytes([1; 32]),
            )
            .is_err()
        );

        let first = metric_evidence(CvssBaseMetric::Av, 7);
        let second = CvssMetricEvidence::try_new(
            first.metric(),
            first.value(),
            first.basis(),
            first.evidence_refs().to_vec(),
            "A different fact cannot reuse the digest".to_string(),
            first.assumptions().to_vec(),
            first.assessor_or_tool().to_string(),
            first.assessed_at().map(str::to_string),
            first.system_scope(),
            first.content_hash(),
        )
        .unwrap();
        assert!(matches!(
            normalize_metric_evidence(&mut vec![first, second], false),
            Err(CvssValidationError::ConflictingEvidenceContentHash)
        ));
    }

    #[test]
    fn provenance_bounds_overlay_input_before_deduplication() {
        assert!(matches!(
            CvssAssessmentProvenance::try_new(
                "bifrost.cvss-v4".to_string(),
                Vec::new(),
                vec![PolicyOverlayScope::AllFindings; MAX_CVSS_OVERLAYS + 1],
                Vec::new(),
            ),
            Err(CvssValidationError::TooManyItems {
                field: "cvss_provenance.overlay_scopes",
                max: MAX_CVSS_OVERLAYS,
            })
        ));
    }

    #[test]
    fn scored_and_unscored_assessments_normalize_deterministically() {
        let base_metrics = [
            CvssBaseMetric::Av,
            CvssBaseMetric::Ac,
            CvssBaseMetric::At,
            CvssBaseMetric::Pr,
            CvssBaseMetric::Ui,
            CvssBaseMetric::Vc,
            CvssBaseMetric::Vi,
            CvssBaseMetric::Va,
            CvssBaseMetric::Sc,
            CvssBaseMetric::Si,
            CvssBaseMetric::Sa,
        ];
        let metrics = base_metrics
            .into_iter()
            .rev()
            .enumerate()
            .map(|(index, metric)| metric_evidence(metric, u8::try_from(index + 1).unwrap()))
            .collect();
        let component = CvssComponentResult::try_new(
            CvssNomenclature::B,
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H".to_string(),
            10.0,
            CvssSeverity::Critical,
        )
        .unwrap();
        let assessment = CvssAssessment::scored(
            CvssVersion::V4_0,
            CvssNomenclature::B,
            component.vector().to_string(),
            vec![component],
            metrics,
            provenance(),
        )
        .unwrap();
        let variant = CvssAssessmentVariant::try_new(
            CvssAssessmentVariantId::from_bytes([2; 32]),
            VulnerabilityIdentity::from_bytes([3; 32]),
            Vec::new(),
            false,
            0,
            SourceScenarioSetHash::from_bytes([4; 32]),
            Vec::new(),
            false,
            assessment,
        )
        .unwrap();
        let set = CvssAssessmentSet::try_new(
            vec![variant],
            Some(CvssAssessmentVariantId::from_bytes([2; 32])),
        )
        .unwrap();
        assert_eq!(set.variants().len(), 1);
        assert_eq!(set.selection_rationale(), Some(SELECTED_VARIANT_RATIONALE));

        let unscored = CvssAssessment::unscored(
            CvssVersion::V4_0,
            Vec::new(),
            vec![CvssBaseMetric::Sa, CvssBaseMetric::Av, CvssBaseMetric::Sa],
            vec![CvssUnscoredReason::MissingBaseEvidence],
            provenance(),
        )
        .unwrap();
        let json = serde_json::to_value(unscored).unwrap();
        assert_eq!(json["type"], "unscored");
        assert_eq!(json["missing_base_metrics"], json!(["AV", "SA"]));
    }

    #[test]
    fn component_score_severity_and_truncation_are_coherent() {
        assert!(
            CvssComponentResult::try_new(
                CvssNomenclature::B,
                "CVSS:4.0/AV:N".to_string(),
                9.0,
                CvssSeverity::High,
            )
            .is_err()
        );
        assert!(
            CvssUnscoredReason::conflicting_metric_evidence(
                CvssMetric::Base {
                    metric: CvssBaseMetric::Av,
                },
                CvssEvidenceSetHash::from_bytes([1; 32]),
                vec![evidence_ref("proof")],
                true,
                0,
            )
            .is_err()
        );
    }
}
