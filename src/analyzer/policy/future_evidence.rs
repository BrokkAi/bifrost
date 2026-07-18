//! Schema-version-1 taint and typestate evidence plus the #824 projection handoff.
//!
//! The projection structs in this module are the deliberate public adapter
//! boundary. Their fields are public so the future analysis adapter can remain
//! independent of policy reporting, but values are not trusted until
//! `try_normalized` has validated every identity/hash relationship and applied
//! canonical ordering. Report evidence has private fields and can only be
//! constructed through the validated constructors below.

use std::cmp::Ordering;
use std::fmt;
use std::mem::size_of;

use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use sha2::{Digest, Sha256};

use super::budget::PolicyBudget;
use super::classification::{MAX_REPORT_PROSE_BYTES, TextValidationError, validate_required_text};
use super::cvss::{CvssEvidenceContentHash, SourceScenarioSetHash};
use super::definition::{
    EndpointId, EndpointObservationPhase, FindingCombinationId, PolicyCategoryId, PolicyId,
    PolicySemanticEvent, TaintCatalogHash, TaintEntryId, TaintImpact, TaintLabel,
    TaintSourceEvidence, TaintSystemEntry, TaintTag, TaintTrustBoundary, TypestateEventId,
    TypestateExitScope, TypestateExpectationId, TypestateStateId,
};
use super::finding::PolicySourceLocation;
use super::finding_identity::{
    AnalysisEventRef, AnalysisFindingId, AnalysisSubjectRef, EvidenceRef, FindingIdentityStability,
    OpaqueFindingKey, SourceScenarioId, StableIdentityDerivation, StableSemanticIdentity,
    TypestateScenarioId, WitnessId,
};
use super::identity::{EndpointAnalysisProjectionHash, EndpointSemanticHash};
use super::resolved::{ResolvedCatalogIdentity, ResolvedEndpointIdentity};
use super::retained::{RetainedSize, retained_extra};

const MAX_PROJECTION_SOURCE_FACTS: usize = 4_096;
const MAX_PROJECTION_SCENARIO_MEMBERSHIPS: usize = 16_384;
const MAX_REPORT_SET_ITEMS: usize = 64;
const MAX_REPORT_ORIGINS: usize = 256;
const MAX_REPORT_EVIDENCE_REFS: usize = 256;
const MAX_REPORT_WITNESS_REFS: usize = 64;

const SOURCE_SCENARIO_SET_DOMAIN: &[u8] = b"bifrost-source-scenario-set/v1";
const TAINT_PROJECTION_FACTS_DOMAIN: &[u8] = b"bifrost-taint-projection-facts/v1";
const TYPESTATE_SCENARIO_SET_DOMAIN: &[u8] = b"bifrost-typestate-scenario-set/v1";
const TYPESTATE_PROTOCOL_DOMAIN: &[u8] = b"bifrost-typestate-protocol/v1";
const TYPESTATE_BINDING_PLAN_DOMAIN: &[u8] = b"bifrost-typestate-binding-plan/v1";
const TYPESTATE_PROJECTION_FACTS_DOMAIN: &[u8] = b"bifrost-typestate-projection-facts/v1";
const TYPESTATE_VIOLATION_DOMAIN: &[u8] = b"bifrost-typestate-violation/v1";
const CVSS_STATIC_EVIDENCE_DOMAIN: &[u8] = b"bifrost-cvss-static-evidence/v1";
const POLICY_VULNERABILITY_DOMAIN: &[u8] = b"bifrost-policy-vulnerability/v1";
const POLICY_FINDING_DOMAIN: &[u8] = b"bifrost-policy-finding/v1";

macro_rules! define_digest {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Wrap a digest already produced by the owning typed compiler.
            /// Report/projection constructors still verify every digest they
            /// can derive locally before accepting an adapter value.
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
                size_of::<Self>()
            }
        }
    };
}

define_digest!(TaintProjectionFactsHash);
define_digest!(TypestateScenarioSetHash);
define_digest!(TypestateProtocolHash);
define_digest!(TypestateBindingPlanHash);
define_digest!(TypestateProjectionFactsHash);
define_digest!(TypestateViolationHash);

impl TypestateProtocolHash {
    /// Hash the canonical compiled #822 protocol bytes under the public
    /// schema-version-1 protocol domain.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Self {
        Self(hash_domain_bytes(TYPESTATE_PROTOCOL_DOMAIN, bytes))
    }
}

impl TypestateBindingPlanHash {
    /// Hash the canonical dominance-resolved #824 binding plan bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Self {
        Self(hash_domain_bytes(TYPESTATE_BINDING_PLAN_DOMAIN, bytes))
    }
}

impl SourceScenarioSetHash {
    /// Hash a complete semantic taint scenario set before display retention.
    pub fn try_from_scenarios(
        mut scenarios: Vec<SourceScenarioId>,
    ) -> Result<Self, FutureEvidenceError> {
        normalize_semantic_set(
            &mut scenarios,
            "source_scenarios",
            MAX_PROJECTION_SCENARIO_MEMBERSHIPS,
            true,
        )?;
        Ok(compute_source_scenario_set_hash(&scenarios))
    }
}

impl TypestateScenarioSetHash {
    /// Hash a complete semantic typestate scenario set before display retention.
    pub fn try_from_scenarios(
        mut scenarios: Vec<TypestateScenarioId>,
    ) -> Result<Self, FutureEvidenceError> {
        normalize_semantic_set(
            &mut scenarios,
            "typestate_scenarios",
            MAX_PROJECTION_SCENARIO_MEMBERSHIPS,
            false,
        )?;
        Ok(typestate_scenario_set_hash(&scenarios))
    }
}

/// Complete #824 evidence for one diagnostic-neutral taint source at a sink.
///
/// This is an explicit public adapter DTO. Call [`Self::try_normalized`] before
/// using a directly constructed value as reducer input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[must_use = "projection facts must be normalized and validated before policy reduction"]
pub struct TaintSourceProjectionFact {
    pub source_endpoint: ResolvedEndpointIdentity,
    pub source_endpoint_semantic_hash: EndpointSemanticHash,
    pub source_endpoint_analysis_projection_hash: EndpointAnalysisProjectionHash,
    pub source_display_name: String,
    pub source_categories: Vec<PolicyCategoryId>,
    pub source_label: TaintLabel,
    pub source_evidence: Option<TaintSourceEvidence>,
    pub source_scenario_ids: Vec<SourceScenarioId>,
    pub scenario_set_hash: SourceScenarioSetHash,
    pub evidence_ref: EvidenceRef,
    pub content_hash: CvssEvidenceContentHash,
}

impl TaintSourceProjectionFact {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        source_endpoint: ResolvedEndpointIdentity,
        source_endpoint_semantic_hash: EndpointSemanticHash,
        source_endpoint_analysis_projection_hash: EndpointAnalysisProjectionHash,
        source_display_name: String,
        source_categories: Vec<PolicyCategoryId>,
        source_label: TaintLabel,
        source_evidence: Option<TaintSourceEvidence>,
        source_scenario_ids: Vec<SourceScenarioId>,
        evidence_ref: EvidenceRef,
    ) -> Result<Self, FutureEvidenceError> {
        let mut value = Self {
            source_endpoint,
            source_endpoint_semantic_hash,
            source_endpoint_analysis_projection_hash,
            source_display_name,
            source_categories,
            source_label,
            source_evidence,
            source_scenario_ids,
            scenario_set_hash: SourceScenarioSetHash::from_bytes([0; 32]),
            evidence_ref,
            content_hash: CvssEvidenceContentHash::from_bytes([0; 32]),
        };
        value.normalize_contents()?;
        value.scenario_set_hash = compute_source_scenario_set_hash(&value.source_scenario_ids);
        value.content_hash = taint_source_content_hash(&value);
        Ok(value)
    }

    /// Normalize adapter-supplied semantic sets and verify both supplied hashes.
    pub fn try_normalized(mut self) -> Result<Self, FutureEvidenceError> {
        let expected_scenario_hash = self.scenario_set_hash;
        let expected_content_hash = self.content_hash;
        self.normalize_contents()?;
        let actual_scenario_hash = compute_source_scenario_set_hash(&self.source_scenario_ids);
        if expected_scenario_hash != actual_scenario_hash {
            return Err(FutureEvidenceError::ScenarioSetHashMismatch {
                field: "source_scenario_ids",
            });
        }
        self.scenario_set_hash = actual_scenario_hash;
        let actual_content_hash = taint_source_content_hash(&self);
        if expected_content_hash != actual_content_hash {
            return Err(FutureEvidenceError::EvidenceContentHashMismatch);
        }
        self.content_hash = actual_content_hash;
        Ok(self)
    }

    fn normalize_contents(&mut self) -> Result<(), FutureEvidenceError> {
        validate_text("source_display_name", &self.source_display_name)?;
        tighten_string(&mut self.source_display_name);
        normalize_semantic_set(
            &mut self.source_categories,
            "source_categories",
            MAX_REPORT_SET_ITEMS,
            true,
        )?;
        normalize_semantic_set(
            &mut self.source_scenario_ids,
            "source_scenario_ids",
            MAX_PROJECTION_SCENARIO_MEMBERSHIPS,
            false,
        )?;
        Ok(())
    }
}

impl RetainedSize for TaintSourceProjectionFact {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(retained_extra(&self.source_endpoint))
            .saturating_add(self.source_display_name.capacity())
            .saturating_add(retained_extra(&self.source_categories))
            .saturating_add(retained_extra(&self.source_label))
            .saturating_add(retained_extra(&self.source_evidence))
            .saturating_add(retained_extra(&self.source_scenario_ids))
            .saturating_add(retained_extra(&self.evidence_ref))
    }
}

/// Complete dominance-resolved reducer input for one taint sink meeting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[must_use = "projection facts must be normalized and validated before policy reduction"]
pub struct TaintPolicyProjectionFacts {
    pub sink_endpoint: ResolvedEndpointIdentity,
    pub sink_endpoint_semantic_hash: EndpointSemanticHash,
    pub sink_endpoint_analysis_projection_hash: EndpointAnalysisProjectionHash,
    pub sink_display_name: String,
    pub sink_categories: Vec<PolicyCategoryId>,
    pub sink_tags: Vec<TaintTag>,
    pub sink_impacts: Vec<TaintImpact>,
    pub reached_source_labels: Vec<TaintLabel>,
    pub source_facts: Vec<TaintSourceProjectionFact>,
    pub semantic_hash: TaintProjectionFactsHash,
}

impl TaintPolicyProjectionFacts {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        sink_endpoint: ResolvedEndpointIdentity,
        sink_endpoint_semantic_hash: EndpointSemanticHash,
        sink_endpoint_analysis_projection_hash: EndpointAnalysisProjectionHash,
        sink_display_name: String,
        sink_categories: Vec<PolicyCategoryId>,
        sink_tags: Vec<TaintTag>,
        sink_impacts: Vec<TaintImpact>,
        reached_source_labels: Vec<TaintLabel>,
        source_facts: Vec<TaintSourceProjectionFact>,
        budget: &PolicyBudget,
    ) -> Result<Self, FutureEvidenceError> {
        let mut value = Self {
            sink_endpoint,
            sink_endpoint_semantic_hash,
            sink_endpoint_analysis_projection_hash,
            sink_display_name,
            sink_categories,
            sink_tags,
            sink_impacts,
            reached_source_labels,
            source_facts,
            semantic_hash: TaintProjectionFactsHash::from_bytes([0; 32]),
        };
        value.normalize_contents(budget)?;
        value.semantic_hash = taint_projection_facts_hash(&value);
        Ok(value)
    }

    /// Canonicalize an adapter DTO and verify its full typed semantic hash.
    pub fn try_normalized(mut self, budget: &PolicyBudget) -> Result<Self, FutureEvidenceError> {
        let expected_hash = self.semantic_hash;
        self.normalize_contents(budget)?;
        let actual_hash = taint_projection_facts_hash(&self);
        if expected_hash != actual_hash {
            return Err(FutureEvidenceError::ProjectionFactsHashMismatch { analysis: "taint" });
        }
        self.semantic_hash = actual_hash;
        Ok(self)
    }

    fn normalize_contents(&mut self, budget: &PolicyBudget) -> Result<(), FutureEvidenceError> {
        validate_text("sink_display_name", &self.sink_display_name)?;
        tighten_string(&mut self.sink_display_name);
        normalize_semantic_set(
            &mut self.sink_categories,
            "sink_categories",
            MAX_REPORT_SET_ITEMS,
            true,
        )?;
        normalize_semantic_set(&mut self.sink_tags, "sink_tags", MAX_REPORT_SET_ITEMS, true)?;
        normalize_semantic_set(
            &mut self.sink_impacts,
            "sink_impacts",
            MAX_REPORT_SET_ITEMS,
            true,
        )?;
        normalize_semantic_set(
            &mut self.reached_source_labels,
            "reached_source_labels",
            MAX_REPORT_SET_ITEMS,
            false,
        )?;
        if self.source_facts.is_empty() {
            return Err(FutureEvidenceError::EmptySemanticSet {
                field: "source_facts",
            });
        }
        if self.source_facts.len() > MAX_PROJECTION_SOURCE_FACTS {
            return Err(FutureEvidenceError::TooManyItems {
                field: "source_facts",
                max_items: MAX_PROJECTION_SOURCE_FACTS,
            });
        }

        let mut normalized = Vec::with_capacity(self.source_facts.len());
        for fact in std::mem::take(&mut self.source_facts) {
            normalized.push(fact.try_normalized()?);
        }
        normalized.sort_by(compare_taint_source_facts);
        for pair in normalized.windows(2) {
            if taint_source_fact_semantic_key_equal(&pair[0], &pair[1]) {
                return Err(if pair[0] == pair[1] {
                    FutureEvidenceError::DuplicateProjectionFact { analysis: "taint" }
                } else {
                    FutureEvidenceError::ConflictingProjectionFact { analysis: "taint" }
                });
            }
        }
        self.source_facts = normalized.into_boxed_slice().into_vec();

        let memberships = self.source_facts.iter().try_fold(0_usize, |total, fact| {
            total.checked_add(fact.source_scenario_ids.len()).ok_or(
                FutureEvidenceError::ProjectionScenarioMembershipBudget {
                    max_items: budget.max_projection_scenario_memberships(),
                },
            )
        })?;
        let effective_max = budget
            .max_projection_scenario_memberships()
            .min(MAX_PROJECTION_SCENARIO_MEMBERSHIPS);
        if memberships > effective_max {
            return Err(FutureEvidenceError::ProjectionScenarioMembershipBudget {
                max_items: effective_max,
            });
        }

        let mut actual_labels = self
            .source_facts
            .iter()
            .map(|fact| fact.source_label.clone())
            .collect::<Vec<_>>();
        actual_labels.sort();
        actual_labels.dedup();
        if self.reached_source_labels != actual_labels {
            return Err(FutureEvidenceError::ReachedSourceLabelsMismatch);
        }
        Ok(())
    }
}

impl RetainedSize for TaintPolicyProjectionFacts {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(retained_extra(&self.sink_endpoint))
            .saturating_add(self.sink_display_name.capacity())
            .saturating_add(retained_extra(&self.sink_categories))
            .saturating_add(retained_extra(&self.sink_tags))
            .saturating_add(retained_extra(&self.sink_impacts))
            .saturating_add(retained_extra(&self.reached_source_labels))
            .saturating_add(retained_extra(&self.source_facts))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintStrongAnchor {
    sink_identity: StableSemanticIdentity,
    source_endpoint_analysis_projection_hash: EndpointAnalysisProjectionHash,
    sink_endpoint_analysis_projection_hash: EndpointAnalysisProjectionHash,
    source_scenario_set_hash: SourceScenarioSetHash,
}

impl TaintStrongAnchor {
    pub const fn sink_identity(&self) -> &StableSemanticIdentity {
        &self.sink_identity
    }

    pub const fn source_endpoint_analysis_projection_hash(&self) -> EndpointAnalysisProjectionHash {
        self.source_endpoint_analysis_projection_hash
    }

    pub const fn sink_endpoint_analysis_projection_hash(&self) -> EndpointAnalysisProjectionHash {
        self.sink_endpoint_analysis_projection_hash
    }

    pub const fn source_scenario_set_hash(&self) -> SourceScenarioSetHash {
        self.source_scenario_set_hash
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintWeakAnchor {
    typed_key: OpaqueFindingKey,
}

impl TaintWeakAnchor {
    pub const fn typed_key(&self) -> &OpaqueFindingKey {
        &self.typed_key
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaintFindingAnchor {
    Strong(TaintStrongAnchor),
    Weak(TaintWeakAnchor),
}

impl TaintFindingAnchor {
    pub fn strong(
        sink_identity: StableSemanticIdentity,
        source_endpoint_analysis_projection_hash: EndpointAnalysisProjectionHash,
        sink_endpoint_analysis_projection_hash: EndpointAnalysisProjectionHash,
        source_scenario_set_hash: SourceScenarioSetHash,
    ) -> Result<Self, FutureEvidenceError> {
        if !matches!(
            sink_identity.derivation(),
            StableIdentityDerivation::AnalyzerDeclarationId
                | StableIdentityDerivation::CanonicalAstIdentity
        ) {
            return Err(FutureEvidenceError::InvalidStrongIdentityDerivation {
                field: "taint_sink_identity",
            });
        }
        if source_scenario_set_hash == empty_source_scenario_set_hash() {
            return Err(FutureEvidenceError::StrongAnchorRequiresScenarios { analysis: "taint" });
        }
        Ok(Self::Strong(TaintStrongAnchor {
            sink_identity,
            source_endpoint_analysis_projection_hash,
            sink_endpoint_analysis_projection_hash,
            source_scenario_set_hash,
        }))
    }

    pub fn weak(typed_key: OpaqueFindingKey) -> Self {
        Self::Weak(TaintWeakAnchor { typed_key })
    }

    pub const fn stability(&self) -> FindingIdentityStability {
        match self {
            Self::Strong(_) => FindingIdentityStability::Strong,
            Self::Weak(_) => FindingIdentityStability::Weak,
        }
    }

    pub const fn strong_fields(&self) -> Option<&TaintStrongAnchor> {
        match self {
            Self::Strong(anchor) => Some(anchor),
            Self::Weak(_) => None,
        }
    }

    pub const fn weak_fields(&self) -> Option<&TaintWeakAnchor> {
        match self {
            Self::Strong(_) => None,
            Self::Weak(anchor) => Some(anchor),
        }
    }
}

impl Serialize for TaintFindingAnchor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Strong(anchor) => {
                let mut state = serializer.serialize_struct("TaintFindingAnchor", 5)?;
                state.serialize_field("type", "strong")?;
                state.serialize_field("sink_identity", &anchor.sink_identity)?;
                state.serialize_field(
                    "source_endpoint_analysis_projection_hash",
                    &anchor.source_endpoint_analysis_projection_hash,
                )?;
                state.serialize_field(
                    "sink_endpoint_analysis_projection_hash",
                    &anchor.sink_endpoint_analysis_projection_hash,
                )?;
                state.serialize_field(
                    "source_scenario_set_hash",
                    &anchor.source_scenario_set_hash,
                )?;
                state.end()
            }
            Self::Weak(anchor) => {
                let mut state = serializer.serialize_struct("TaintFindingAnchor", 2)?;
                state.serialize_field("type", "weak")?;
                state.serialize_field("typed_key", &anchor.typed_key)?;
                state.end()
            }
        }
    }
}

impl RetainedSize for TaintStrongAnchor {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(retained_extra(&self.sink_identity))
    }
}

impl RetainedSize for TaintWeakAnchor {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(retained_extra(&self.typed_key))
    }
}

impl RetainedSize for TaintFindingAnchor {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(match self {
            Self::Strong(anchor) => retained_extra(anchor),
            Self::Weak(anchor) => retained_extra(anchor),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TaintOriginEvidence {
    source_endpoint: ResolvedEndpointIdentity,
    source_label: TaintLabel,
    source_evidence: Option<TaintSourceEvidence>,
    primary: PolicySourceLocation,
    scenario_id: SourceScenarioId,
    evidence_refs: Vec<EvidenceRef>,
}

impl TaintOriginEvidence {
    pub fn try_new(
        source_endpoint: ResolvedEndpointIdentity,
        source_label: TaintLabel,
        source_evidence: Option<TaintSourceEvidence>,
        primary: PolicySourceLocation,
        scenario_id: SourceScenarioId,
        mut evidence_refs: Vec<EvidenceRef>,
    ) -> Result<Self, FutureEvidenceError> {
        normalize_semantic_set(
            &mut evidence_refs,
            "origin_evidence_refs",
            MAX_REPORT_EVIDENCE_REFS,
            true,
        )?;
        Ok(Self {
            source_endpoint,
            source_label,
            source_evidence,
            primary,
            scenario_id,
            evidence_refs,
        })
    }

    pub const fn source_endpoint(&self) -> &ResolvedEndpointIdentity {
        &self.source_endpoint
    }

    pub const fn source_label(&self) -> &TaintLabel {
        &self.source_label
    }

    pub const fn source_evidence(&self) -> Option<&TaintSourceEvidence> {
        self.source_evidence.as_ref()
    }

    pub const fn primary(&self) -> &PolicySourceLocation {
        &self.primary
    }

    pub const fn scenario_id(&self) -> &SourceScenarioId {
        &self.scenario_id
    }

    pub fn evidence_refs(&self) -> &[EvidenceRef] {
        &self.evidence_refs
    }
}

impl RetainedSize for TaintOriginEvidence {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(retained_extra(&self.source_endpoint))
            .saturating_add(retained_extra(&self.source_label))
            .saturating_add(retained_extra(&self.source_evidence))
            .saturating_add(retained_extra(&self.primary))
            .saturating_add(retained_extra(&self.scenario_id))
            .saturating_add(retained_extra(&self.evidence_refs))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TaintFindingEvidence {
    analysis_finding_id: AnalysisFindingId,
    anchor: TaintFindingAnchor,
    sink: AnalysisEventRef,
    source_endpoint: ResolvedEndpointIdentity,
    sink_endpoint: ResolvedEndpointIdentity,
    source_display_name: String,
    sink_display_name: String,
    source_categories: Vec<PolicyCategoryId>,
    sink_categories: Vec<PolicyCategoryId>,
    selected_combination: Option<FindingCombinationId>,
    sink_tags: Vec<TaintTag>,
    sink_impacts: Vec<TaintImpact>,
    reached_source_labels: Vec<TaintLabel>,
    origins: Vec<TaintOriginEvidence>,
    origins_truncated: bool,
    source_scenarios: Vec<SourceScenarioId>,
    source_scenarios_truncated: bool,
    omitted_source_scenarios_lower_bound: u64,
    source_scenario_set_hash: SourceScenarioSetHash,
    witness_refs: Vec<WitnessId>,
    witness_refs_truncated: bool,
    projection_facts_hash: TaintProjectionFactsHash,
}

impl TaintFindingEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        analysis_finding_id: AnalysisFindingId,
        anchor: TaintFindingAnchor,
        sink: AnalysisEventRef,
        source_endpoint: ResolvedEndpointIdentity,
        sink_endpoint: ResolvedEndpointIdentity,
        mut source_display_name: String,
        mut sink_display_name: String,
        mut source_categories: Vec<PolicyCategoryId>,
        mut sink_categories: Vec<PolicyCategoryId>,
        selected_combination: Option<FindingCombinationId>,
        mut sink_tags: Vec<TaintTag>,
        mut sink_impacts: Vec<TaintImpact>,
        mut reached_source_labels: Vec<TaintLabel>,
        mut origins: Vec<TaintOriginEvidence>,
        origins_truncated: bool,
        mut source_scenarios: Vec<SourceScenarioId>,
        source_scenarios_truncated: bool,
        omitted_source_scenarios_lower_bound: u64,
        source_scenario_set_hash: SourceScenarioSetHash,
        mut witness_refs: Vec<WitnessId>,
        witness_refs_truncated: bool,
        projection_facts_hash: TaintProjectionFactsHash,
        budget: &PolicyBudget,
    ) -> Result<Self, FutureEvidenceError> {
        validate_text("source_display_name", &source_display_name)?;
        validate_text("sink_display_name", &sink_display_name)?;
        tighten_string(&mut source_display_name);
        tighten_string(&mut sink_display_name);
        normalize_semantic_set(
            &mut source_categories,
            "source_categories",
            MAX_REPORT_SET_ITEMS,
            true,
        )?;
        normalize_semantic_set(
            &mut sink_categories,
            "sink_categories",
            MAX_REPORT_SET_ITEMS,
            true,
        )?;
        normalize_semantic_set(&mut sink_tags, "sink_tags", MAX_REPORT_SET_ITEMS, true)?;
        normalize_semantic_set(
            &mut sink_impacts,
            "sink_impacts",
            MAX_REPORT_SET_ITEMS,
            true,
        )?;
        normalize_semantic_set(
            &mut reached_source_labels,
            "reached_source_labels",
            MAX_REPORT_SET_ITEMS,
            false,
        )?;
        normalize_semantic_set(
            &mut source_scenarios,
            "source_scenarios",
            budget
                .max_projection_scenario_memberships()
                .min(MAX_PROJECTION_SCENARIO_MEMBERSHIPS),
            source_scenarios_truncated,
        )?;
        normalize_semantic_set(
            &mut witness_refs,
            "witness_refs",
            budget
                .max_witnesses_per_finding()
                .min(MAX_REPORT_WITNESS_REFS),
            true,
        )?;
        validate_truncation_count(
            "source_scenarios",
            source_scenarios_truncated,
            omitted_source_scenarios_lower_bound,
        )?;
        if source_scenario_set_hash == empty_source_scenario_set_hash() {
            return Err(FutureEvidenceError::EmptySemanticSet {
                field: "full_source_scenarios",
            });
        }
        if !source_scenarios_truncated
            && source_scenario_set_hash != compute_source_scenario_set_hash(&source_scenarios)
        {
            return Err(FutureEvidenceError::ScenarioSetHashMismatch {
                field: "source_scenarios",
            });
        }
        if let Some(strong) = anchor.strong_fields()
            && strong.source_scenario_set_hash != source_scenario_set_hash
        {
            return Err(FutureEvidenceError::AnchorScenarioHashMismatch { analysis: "taint" });
        }
        if origins.len() > MAX_REPORT_ORIGINS {
            return Err(FutureEvidenceError::TooManyItems {
                field: "origins",
                max_items: MAX_REPORT_ORIGINS,
            });
        }
        origins.sort_by(compare_taint_origins);
        for pair in origins.windows(2) {
            if compare_taint_origins(&pair[0], &pair[1]) == Ordering::Equal {
                return Err(FutureEvidenceError::DuplicateSemanticValue { field: "origins" });
            }
        }
        tighten_vec(&mut origins);
        let evidence_ref_count = origins.iter().try_fold(0_usize, |total, origin| {
            total
                .checked_add(origin.evidence_refs.len())
                .ok_or(FutureEvidenceError::TooManyItems {
                    field: "origin_evidence_refs",
                    max_items: budget.max_evidence_refs_per_finding(),
                })
        })?;
        if evidence_ref_count > budget.max_evidence_refs_per_finding() {
            return Err(FutureEvidenceError::TooManyItems {
                field: "origin_evidence_refs",
                max_items: budget.max_evidence_refs_per_finding(),
            });
        }
        for origin in &origins {
            if origin.source_endpoint != source_endpoint {
                return Err(FutureEvidenceError::OriginSourceEndpointMismatch);
            }
            if !reached_source_labels.contains(&origin.source_label) {
                return Err(FutureEvidenceError::OriginSourceLabelMismatch);
            }
            if !source_scenarios_truncated && !source_scenarios.contains(&origin.scenario_id) {
                return Err(FutureEvidenceError::OriginScenarioMismatch);
            }
        }

        let evidence = Self {
            analysis_finding_id,
            anchor,
            sink,
            source_endpoint,
            sink_endpoint,
            source_display_name,
            sink_display_name,
            source_categories,
            sink_categories,
            selected_combination,
            sink_tags,
            sink_impacts,
            reached_source_labels,
            origins,
            origins_truncated,
            source_scenarios,
            source_scenarios_truncated,
            omitted_source_scenarios_lower_bound,
            source_scenario_set_hash,
            witness_refs,
            witness_refs_truncated,
            projection_facts_hash,
        };
        ensure_retained_evidence_bound("taint_finding_evidence", &evidence, budget)?;
        Ok(evidence)
    }

    pub const fn analysis_finding_id(&self) -> &AnalysisFindingId {
        &self.analysis_finding_id
    }
    pub const fn anchor(&self) -> &TaintFindingAnchor {
        &self.anchor
    }
    pub const fn sink(&self) -> &AnalysisEventRef {
        &self.sink
    }
    pub const fn source_endpoint(&self) -> &ResolvedEndpointIdentity {
        &self.source_endpoint
    }
    pub const fn sink_endpoint(&self) -> &ResolvedEndpointIdentity {
        &self.sink_endpoint
    }
    pub fn source_display_name(&self) -> &str {
        &self.source_display_name
    }
    pub fn sink_display_name(&self) -> &str {
        &self.sink_display_name
    }
    pub fn source_categories(&self) -> &[PolicyCategoryId] {
        &self.source_categories
    }
    pub fn sink_categories(&self) -> &[PolicyCategoryId] {
        &self.sink_categories
    }
    pub const fn selected_combination(&self) -> Option<&FindingCombinationId> {
        self.selected_combination.as_ref()
    }
    pub fn sink_tags(&self) -> &[TaintTag] {
        &self.sink_tags
    }
    pub fn sink_impacts(&self) -> &[TaintImpact] {
        &self.sink_impacts
    }
    pub fn reached_source_labels(&self) -> &[TaintLabel] {
        &self.reached_source_labels
    }
    pub fn origins(&self) -> &[TaintOriginEvidence] {
        &self.origins
    }
    pub const fn origins_truncated(&self) -> bool {
        self.origins_truncated
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
    pub const fn projection_facts_hash(&self) -> TaintProjectionFactsHash {
        self.projection_facts_hash
    }
}

impl RetainedSize for TaintFindingEvidence {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(retained_extra(&self.analysis_finding_id))
            .saturating_add(retained_extra(&self.anchor))
            .saturating_add(retained_extra(&self.sink))
            .saturating_add(retained_extra(&self.source_endpoint))
            .saturating_add(retained_extra(&self.sink_endpoint))
            .saturating_add(self.source_display_name.capacity())
            .saturating_add(self.sink_display_name.capacity())
            .saturating_add(retained_extra(&self.source_categories))
            .saturating_add(retained_extra(&self.sink_categories))
            .saturating_add(retained_extra(&self.selected_combination))
            .saturating_add(retained_extra(&self.sink_tags))
            .saturating_add(retained_extra(&self.sink_impacts))
            .saturating_add(retained_extra(&self.reached_source_labels))
            .saturating_add(retained_extra(&self.origins))
            .saturating_add(retained_extra(&self.source_scenarios))
            .saturating_add(retained_extra(&self.witness_refs))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TypestateViolationEvidence {
    ErrorTransition {
        event_id: TypestateEventId,
        endpoint: Option<ResolvedEndpointIdentity>,
        from: TypestateStateId,
        to: TypestateStateId,
    },
    TerminalExpectation {
        expectation_id: TypestateExpectationId,
        terminal: ResolvedTypestateTerminal,
        observed_state: TypestateStateId,
        expected_states: Vec<TypestateStateId>,
    },
}

impl TypestateViolationEvidence {
    pub fn error_transition(
        event_id: TypestateEventId,
        endpoint: Option<ResolvedEndpointIdentity>,
        from: TypestateStateId,
        to: TypestateStateId,
    ) -> Self {
        Self::ErrorTransition {
            event_id,
            endpoint,
            from,
            to,
        }
    }

    pub fn try_terminal_expectation(
        expectation_id: TypestateExpectationId,
        terminal: ResolvedTypestateTerminal,
        observed_state: TypestateStateId,
        expected_states: Vec<TypestateStateId>,
    ) -> Result<Self, FutureEvidenceError> {
        Self::TerminalExpectation {
            expectation_id,
            terminal,
            observed_state,
            expected_states,
        }
        .try_normalized()
    }

    pub fn try_normalized(mut self) -> Result<Self, FutureEvidenceError> {
        if let Self::TerminalExpectation {
            observed_state,
            expected_states,
            ..
        } = &mut self
        {
            normalize_semantic_set(
                expected_states,
                "expected_states",
                MAX_REPORT_SET_ITEMS,
                false,
            )?;
            if expected_states.contains(observed_state) {
                return Err(FutureEvidenceError::ObservedStateIsExpected);
            }
        }
        Ok(self)
    }
}

impl RetainedSize for TypestateViolationEvidence {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(match self {
            Self::ErrorTransition {
                event_id,
                endpoint,
                from,
                to,
            } => retained_extra(event_id)
                .saturating_add(retained_extra(endpoint))
                .saturating_add(retained_extra(from))
                .saturating_add(retained_extra(to)),
            Self::TerminalExpectation {
                expectation_id,
                terminal,
                observed_state,
                expected_states,
            } => retained_extra(expectation_id)
                .saturating_add(retained_extra(terminal))
                .saturating_add(retained_extra(observed_state))
                .saturating_add(retained_extra(expected_states)),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResolvedTypestateTerminal {
    Endpoint {
        endpoint: ResolvedEndpointIdentity,
        phase: EndpointObservationPhase,
    },
    SemanticEvent {
        event: PolicySemanticEvent,
    },
}

impl RetainedSize for ResolvedTypestateTerminal {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(match self {
            Self::Endpoint { endpoint, .. } => retained_extra(endpoint),
            Self::SemanticEvent { .. } => 0,
        })
    }
}

/// Complete pre-retention #824 typestate projection input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[must_use = "projection facts must be normalized and validated before policy reduction"]
pub struct TypestatePolicyProjectionFacts {
    pub protocol_hash: TypestateProtocolHash,
    pub binding_plan_hash: TypestateBindingPlanHash,
    pub source_endpoint: ResolvedEndpointIdentity,
    pub source_endpoint_hash: EndpointSemanticHash,
    pub source_categories: Vec<PolicyCategoryId>,
    pub source_display_name: String,
    pub violation_site: Option<StableSemanticIdentity>,
    pub violation: TypestateViolationEvidence,
    pub scenario_ids: Vec<TypestateScenarioId>,
    pub scenario_set_hash: TypestateScenarioSetHash,
    pub semantic_hash: TypestateProjectionFactsHash,
}

impl TypestatePolicyProjectionFacts {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        protocol_hash: TypestateProtocolHash,
        binding_plan_hash: TypestateBindingPlanHash,
        source_endpoint: ResolvedEndpointIdentity,
        source_endpoint_hash: EndpointSemanticHash,
        source_categories: Vec<PolicyCategoryId>,
        source_display_name: String,
        violation_site: Option<StableSemanticIdentity>,
        violation: TypestateViolationEvidence,
        scenario_ids: Vec<TypestateScenarioId>,
        budget: &PolicyBudget,
    ) -> Result<Self, FutureEvidenceError> {
        let mut value = Self {
            protocol_hash,
            binding_plan_hash,
            source_endpoint,
            source_endpoint_hash,
            source_categories,
            source_display_name,
            violation_site,
            violation,
            scenario_ids,
            scenario_set_hash: TypestateScenarioSetHash::from_bytes([0; 32]),
            semantic_hash: TypestateProjectionFactsHash::from_bytes([0; 32]),
        };
        value.normalize_contents(budget)?;
        value.scenario_set_hash = typestate_scenario_set_hash(&value.scenario_ids);
        value.semantic_hash = typestate_projection_facts_hash(&value);
        Ok(value)
    }

    pub fn try_normalized(mut self, budget: &PolicyBudget) -> Result<Self, FutureEvidenceError> {
        let expected_scenario_hash = self.scenario_set_hash;
        let expected_semantic_hash = self.semantic_hash;
        self.normalize_contents(budget)?;
        let actual_scenario_hash = typestate_scenario_set_hash(&self.scenario_ids);
        if expected_scenario_hash != actual_scenario_hash {
            return Err(FutureEvidenceError::ScenarioSetHashMismatch {
                field: "typestate_scenario_ids",
            });
        }
        self.scenario_set_hash = actual_scenario_hash;
        let actual_semantic_hash = typestate_projection_facts_hash(&self);
        if expected_semantic_hash != actual_semantic_hash {
            return Err(FutureEvidenceError::ProjectionFactsHashMismatch {
                analysis: "typestate",
            });
        }
        self.semantic_hash = actual_semantic_hash;
        Ok(self)
    }

    fn normalize_contents(&mut self, budget: &PolicyBudget) -> Result<(), FutureEvidenceError> {
        validate_text("source_display_name", &self.source_display_name)?;
        tighten_string(&mut self.source_display_name);
        normalize_semantic_set(
            &mut self.source_categories,
            "source_categories",
            MAX_REPORT_SET_ITEMS,
            true,
        )?;
        normalize_semantic_set(
            &mut self.scenario_ids,
            "typestate_scenario_ids",
            MAX_PROJECTION_SCENARIO_MEMBERSHIPS,
            false,
        )?;
        let effective_max = budget
            .max_projection_scenario_memberships()
            .min(MAX_PROJECTION_SCENARIO_MEMBERSHIPS);
        if self.scenario_ids.len() > effective_max {
            return Err(FutureEvidenceError::ProjectionScenarioMembershipBudget {
                max_items: effective_max,
            });
        }
        if let Some(site) = &self.violation_site
            && site.derivation() != StableIdentityDerivation::ProtocolViolationSite
        {
            return Err(FutureEvidenceError::InvalidStrongIdentityDerivation {
                field: "typestate_violation_site",
            });
        }
        self.violation = self.violation.clone().try_normalized()?;
        Ok(())
    }
}

impl RetainedSize for TypestatePolicyProjectionFacts {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(retained_extra(&self.source_endpoint))
            .saturating_add(retained_extra(&self.source_categories))
            .saturating_add(self.source_display_name.capacity())
            .saturating_add(retained_extra(&self.violation_site))
            .saturating_add(retained_extra(&self.violation))
            .saturating_add(retained_extra(&self.scenario_ids))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypestateStrongAnchor {
    protocol_hash: TypestateProtocolHash,
    binding_plan_hash: TypestateBindingPlanHash,
    subject_identity: StableSemanticIdentity,
    violation_site_identity: StableSemanticIdentity,
    scenario_set_hash: TypestateScenarioSetHash,
    violation_hash: TypestateViolationHash,
}

impl TypestateStrongAnchor {
    pub const fn protocol_hash(&self) -> TypestateProtocolHash {
        self.protocol_hash
    }
    pub const fn binding_plan_hash(&self) -> TypestateBindingPlanHash {
        self.binding_plan_hash
    }
    pub const fn subject_identity(&self) -> &StableSemanticIdentity {
        &self.subject_identity
    }
    pub const fn violation_site_identity(&self) -> &StableSemanticIdentity {
        &self.violation_site_identity
    }
    pub const fn scenario_set_hash(&self) -> TypestateScenarioSetHash {
        self.scenario_set_hash
    }
    pub const fn violation_hash(&self) -> TypestateViolationHash {
        self.violation_hash
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypestateWeakAnchor {
    typed_key: OpaqueFindingKey,
}

impl TypestateWeakAnchor {
    pub const fn typed_key(&self) -> &OpaqueFindingKey {
        &self.typed_key
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypestateFindingAnchor {
    Strong(Box<TypestateStrongAnchor>),
    Weak(TypestateWeakAnchor),
}

impl TypestateFindingAnchor {
    #[allow(clippy::too_many_arguments)]
    pub fn strong(
        protocol_hash: TypestateProtocolHash,
        binding_plan_hash: TypestateBindingPlanHash,
        subject_identity: StableSemanticIdentity,
        violation_site_identity: StableSemanticIdentity,
        scenario_set_hash: TypestateScenarioSetHash,
        violation: &TypestateViolationEvidence,
    ) -> Result<Self, FutureEvidenceError> {
        if subject_identity.derivation() != StableIdentityDerivation::ProtocolSubject {
            return Err(FutureEvidenceError::InvalidStrongIdentityDerivation {
                field: "typestate_subject_identity",
            });
        }
        if violation_site_identity.derivation() != StableIdentityDerivation::ProtocolViolationSite {
            return Err(FutureEvidenceError::InvalidStrongIdentityDerivation {
                field: "typestate_violation_site_identity",
            });
        }
        if scenario_set_hash == empty_typestate_scenario_set_hash() {
            return Err(FutureEvidenceError::StrongAnchorRequiresScenarios {
                analysis: "typestate",
            });
        }
        let normalized_violation = violation.clone().try_normalized()?;
        let violation_hash = typestate_violation_hash(
            &normalized_violation,
            &violation_site_identity,
            scenario_set_hash,
        );
        Ok(Self::Strong(Box::new(TypestateStrongAnchor {
            protocol_hash,
            binding_plan_hash,
            subject_identity,
            violation_site_identity,
            scenario_set_hash,
            violation_hash,
        })))
    }

    pub fn weak(typed_key: OpaqueFindingKey) -> Self {
        Self::Weak(TypestateWeakAnchor { typed_key })
    }

    pub const fn stability(&self) -> FindingIdentityStability {
        match self {
            Self::Strong(_) => FindingIdentityStability::Strong,
            Self::Weak(_) => FindingIdentityStability::Weak,
        }
    }

    pub fn strong_fields(&self) -> Option<&TypestateStrongAnchor> {
        match self {
            Self::Strong(anchor) => Some(anchor.as_ref()),
            Self::Weak(_) => None,
        }
    }

    pub const fn weak_fields(&self) -> Option<&TypestateWeakAnchor> {
        match self {
            Self::Strong(_) => None,
            Self::Weak(anchor) => Some(anchor),
        }
    }
}

impl Serialize for TypestateFindingAnchor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Strong(anchor) => {
                let mut state = serializer.serialize_struct("TypestateFindingAnchor", 7)?;
                state.serialize_field("type", "strong")?;
                state.serialize_field("protocol_hash", &anchor.protocol_hash)?;
                state.serialize_field("binding_plan_hash", &anchor.binding_plan_hash)?;
                state.serialize_field("subject_identity", &anchor.subject_identity)?;
                state
                    .serialize_field("violation_site_identity", &anchor.violation_site_identity)?;
                state.serialize_field("scenario_set_hash", &anchor.scenario_set_hash)?;
                state.serialize_field("violation_hash", &anchor.violation_hash)?;
                state.end()
            }
            Self::Weak(anchor) => {
                let mut state = serializer.serialize_struct("TypestateFindingAnchor", 2)?;
                state.serialize_field("type", "weak")?;
                state.serialize_field("typed_key", &anchor.typed_key)?;
                state.end()
            }
        }
    }
}

impl RetainedSize for TypestateStrongAnchor {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(retained_extra(&self.subject_identity))
            .saturating_add(retained_extra(&self.violation_site_identity))
    }
}

impl RetainedSize for TypestateWeakAnchor {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(retained_extra(&self.typed_key))
    }
}

impl RetainedSize for TypestateFindingAnchor {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(match self {
            Self::Strong(anchor) => anchor.as_ref().retained_size(),
            Self::Weak(anchor) => retained_extra(anchor),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TypestateFindingEvidence {
    analysis_finding_id: AnalysisFindingId,
    anchor: TypestateFindingAnchor,
    protocol_hash: TypestateProtocolHash,
    binding_plan_hash: TypestateBindingPlanHash,
    subject: AnalysisSubjectRef,
    source_endpoint: ResolvedEndpointIdentity,
    violation_site: Option<StableSemanticIdentity>,
    violation: TypestateViolationEvidence,
    scenario_ids: Vec<TypestateScenarioId>,
    scenarios_truncated: bool,
    omitted_scenarios_lower_bound: u64,
    scenario_set_hash: TypestateScenarioSetHash,
    witness_refs: Vec<WitnessId>,
    witness_refs_truncated: bool,
    projection_facts_hash: TypestateProjectionFactsHash,
}

impl TypestateFindingEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        analysis_finding_id: AnalysisFindingId,
        anchor: TypestateFindingAnchor,
        protocol_hash: TypestateProtocolHash,
        binding_plan_hash: TypestateBindingPlanHash,
        subject: AnalysisSubjectRef,
        source_endpoint: ResolvedEndpointIdentity,
        violation_site: Option<StableSemanticIdentity>,
        violation: TypestateViolationEvidence,
        mut scenario_ids: Vec<TypestateScenarioId>,
        scenarios_truncated: bool,
        omitted_scenarios_lower_bound: u64,
        scenario_set_hash: TypestateScenarioSetHash,
        mut witness_refs: Vec<WitnessId>,
        witness_refs_truncated: bool,
        projection_facts_hash: TypestateProjectionFactsHash,
        budget: &PolicyBudget,
    ) -> Result<Self, FutureEvidenceError> {
        let violation = violation.try_normalized()?;
        normalize_semantic_set(
            &mut scenario_ids,
            "typestate_scenario_ids",
            budget
                .max_projection_scenario_memberships()
                .min(MAX_PROJECTION_SCENARIO_MEMBERSHIPS),
            scenarios_truncated,
        )?;
        normalize_semantic_set(
            &mut witness_refs,
            "witness_refs",
            budget
                .max_witnesses_per_finding()
                .min(MAX_REPORT_WITNESS_REFS),
            true,
        )?;
        validate_truncation_count(
            "typestate_scenarios",
            scenarios_truncated,
            omitted_scenarios_lower_bound,
        )?;
        if scenario_set_hash == empty_typestate_scenario_set_hash() {
            return Err(FutureEvidenceError::EmptySemanticSet {
                field: "full_typestate_scenarios",
            });
        }
        if !scenarios_truncated && scenario_set_hash != typestate_scenario_set_hash(&scenario_ids) {
            return Err(FutureEvidenceError::ScenarioSetHashMismatch {
                field: "typestate_scenario_ids",
            });
        }
        if let Some(site) = &violation_site
            && site.derivation() != StableIdentityDerivation::ProtocolViolationSite
        {
            return Err(FutureEvidenceError::InvalidStrongIdentityDerivation {
                field: "typestate_violation_site",
            });
        }
        if let Some(strong) = anchor.strong_fields() {
            if strong.protocol_hash != protocol_hash
                || strong.binding_plan_hash != binding_plan_hash
            {
                return Err(FutureEvidenceError::AnchorCompiledHashMismatch);
            }
            if strong.scenario_set_hash != scenario_set_hash {
                return Err(FutureEvidenceError::AnchorScenarioHashMismatch {
                    analysis: "typestate",
                });
            }
            if violation_site.as_ref() != Some(&strong.violation_site_identity) {
                return Err(FutureEvidenceError::AnchorViolationSiteMismatch);
            }
            let actual_violation_hash = typestate_violation_hash(
                &violation,
                &strong.violation_site_identity,
                scenario_set_hash,
            );
            if strong.violation_hash != actual_violation_hash {
                return Err(FutureEvidenceError::ViolationHashMismatch);
            }
        }

        let evidence = Self {
            analysis_finding_id,
            anchor,
            protocol_hash,
            binding_plan_hash,
            subject,
            source_endpoint,
            violation_site,
            violation,
            scenario_ids,
            scenarios_truncated,
            omitted_scenarios_lower_bound,
            scenario_set_hash,
            witness_refs,
            witness_refs_truncated,
            projection_facts_hash,
        };
        ensure_retained_evidence_bound("typestate_finding_evidence", &evidence, budget)?;
        Ok(evidence)
    }

    pub const fn analysis_finding_id(&self) -> &AnalysisFindingId {
        &self.analysis_finding_id
    }
    pub const fn anchor(&self) -> &TypestateFindingAnchor {
        &self.anchor
    }
    pub const fn protocol_hash(&self) -> TypestateProtocolHash {
        self.protocol_hash
    }
    pub const fn binding_plan_hash(&self) -> TypestateBindingPlanHash {
        self.binding_plan_hash
    }
    pub const fn subject(&self) -> &AnalysisSubjectRef {
        &self.subject
    }
    pub const fn source_endpoint(&self) -> &ResolvedEndpointIdentity {
        &self.source_endpoint
    }
    pub const fn violation_site(&self) -> Option<&StableSemanticIdentity> {
        self.violation_site.as_ref()
    }
    pub const fn violation(&self) -> &TypestateViolationEvidence {
        &self.violation
    }
    pub fn scenario_ids(&self) -> &[TypestateScenarioId] {
        &self.scenario_ids
    }
    pub const fn scenarios_truncated(&self) -> bool {
        self.scenarios_truncated
    }
    pub const fn omitted_scenarios_lower_bound(&self) -> u64 {
        self.omitted_scenarios_lower_bound
    }
    pub const fn scenario_set_hash(&self) -> TypestateScenarioSetHash {
        self.scenario_set_hash
    }
    pub fn witness_refs(&self) -> &[WitnessId] {
        &self.witness_refs
    }
    pub const fn witness_refs_truncated(&self) -> bool {
        self.witness_refs_truncated
    }
    pub const fn projection_facts_hash(&self) -> TypestateProjectionFactsHash {
        self.projection_facts_hash
    }
}

impl RetainedSize for TypestateFindingEvidence {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(retained_extra(&self.analysis_finding_id))
            .saturating_add(retained_extra(&self.anchor))
            .saturating_add(retained_extra(&self.subject))
            .saturating_add(retained_extra(&self.source_endpoint))
            .saturating_add(retained_extra(&self.violation_site))
            .saturating_add(retained_extra(&self.violation))
            .saturating_add(retained_extra(&self.scenario_ids))
            .saturating_add(retained_extra(&self.witness_refs))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FutureEvidenceError {
    InvalidText {
        field: &'static str,
        reason: TextValidationError,
    },
    TooManyItems {
        field: &'static str,
        max_items: usize,
    },
    EmptySemanticSet {
        field: &'static str,
    },
    DuplicateSemanticValue {
        field: &'static str,
    },
    DuplicateProjectionFact {
        analysis: &'static str,
    },
    ConflictingProjectionFact {
        analysis: &'static str,
    },
    ProjectionScenarioMembershipBudget {
        max_items: usize,
    },
    ScenarioSetHashMismatch {
        field: &'static str,
    },
    ProjectionFactsHashMismatch {
        analysis: &'static str,
    },
    EvidenceContentHashMismatch,
    ReachedSourceLabelsMismatch,
    InvalidStrongIdentityDerivation {
        field: &'static str,
    },
    StrongAnchorRequiresScenarios {
        analysis: &'static str,
    },
    InvalidTruncationCount {
        field: &'static str,
    },
    AnchorScenarioHashMismatch {
        analysis: &'static str,
    },
    AnchorCompiledHashMismatch,
    AnchorViolationSiteMismatch,
    ViolationHashMismatch,
    OriginSourceEndpointMismatch,
    OriginSourceLabelMismatch,
    OriginScenarioMismatch,
    ObservedStateIsExpected,
    RetainedEvidenceBudget {
        field: &'static str,
        max_bytes: usize,
    },
}

impl fmt::Display for FutureEvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidText { field, reason } => write!(formatter, "invalid {field}: {reason}"),
            Self::TooManyItems { field, max_items } => {
                write!(formatter, "{field} accepts at most {max_items} items")
            }
            Self::EmptySemanticSet { field } => write!(formatter, "{field} must not be empty"),
            Self::DuplicateSemanticValue { field } => {
                write!(formatter, "{field} must be duplicate-free")
            }
            Self::DuplicateProjectionFact { analysis } => {
                write!(formatter, "{analysis} projection contains a duplicate fact")
            }
            Self::ConflictingProjectionFact { analysis } => {
                write!(
                    formatter,
                    "{analysis} projection contains conflicting facts"
                )
            }
            Self::ProjectionScenarioMembershipBudget { max_items } => write!(
                formatter,
                "projection scenario memberships exceed the effective limit {max_items}"
            ),
            Self::ScenarioSetHashMismatch { field } => {
                write!(
                    formatter,
                    "{field} does not match its complete scenario-set hash"
                )
            }
            Self::ProjectionFactsHashMismatch { analysis } => {
                write!(
                    formatter,
                    "{analysis} projection facts do not match their semantic hash"
                )
            }
            Self::EvidenceContentHashMismatch => {
                formatter.write_str("taint source fact does not match its CVSS evidence hash")
            }
            Self::ReachedSourceLabelsMismatch => formatter.write_str(
                "reached_source_labels must exactly equal labels present in source_facts",
            ),
            Self::InvalidStrongIdentityDerivation { field } => {
                write!(formatter, "{field} is not a typed stable semantic identity")
            }
            Self::StrongAnchorRequiresScenarios { analysis } => {
                write!(
                    formatter,
                    "a strong {analysis} anchor requires a non-empty scenario set"
                )
            }
            Self::InvalidTruncationCount { field } => write!(
                formatter,
                "{field} truncation and omitted-count fields are inconsistent"
            ),
            Self::AnchorScenarioHashMismatch { analysis } => {
                write!(
                    formatter,
                    "{analysis} anchor and evidence scenario hashes differ"
                )
            }
            Self::AnchorCompiledHashMismatch => formatter
                .write_str("typestate anchor protocol/binding hashes differ from finding evidence"),
            Self::AnchorViolationSiteMismatch => {
                formatter.write_str("typestate anchor and finding evidence violation sites differ")
            }
            Self::ViolationHashMismatch => {
                formatter.write_str("typestate anchor violation hash failed integrity validation")
            }
            Self::OriginSourceEndpointMismatch => {
                formatter.write_str("taint origin belongs to a different source endpoint")
            }
            Self::OriginSourceLabelMismatch => {
                formatter.write_str("taint origin label was not reached by the finding")
            }
            Self::OriginScenarioMismatch => {
                formatter.write_str("taint origin scenario is absent from the complete report set")
            }
            Self::ObservedStateIsExpected => formatter.write_str(
                "terminal-expectation evidence cannot report an expected state as a violation",
            ),
            Self::RetainedEvidenceBudget { field, max_bytes } => {
                write!(
                    formatter,
                    "{field} exceeds the retained evidence limit {max_bytes}"
                )
            }
        }
    }
}

impl std::error::Error for FutureEvidenceError {}

fn validate_text(field: &'static str, value: &str) -> Result<(), FutureEvidenceError> {
    validate_required_text(value, MAX_REPORT_PROSE_BYTES)
        .map_err(|reason| FutureEvidenceError::InvalidText { field, reason })
}

fn normalize_semantic_set<T: Ord>(
    values: &mut Vec<T>,
    field: &'static str,
    max_items: usize,
    allow_empty: bool,
) -> Result<(), FutureEvidenceError> {
    if values.len() > max_items {
        return Err(FutureEvidenceError::TooManyItems { field, max_items });
    }
    if !allow_empty && values.is_empty() {
        return Err(FutureEvidenceError::EmptySemanticSet { field });
    }
    values.sort();
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(FutureEvidenceError::DuplicateSemanticValue { field });
    }
    tighten_vec(values);
    Ok(())
}

fn validate_truncation_count(
    field: &'static str,
    truncated: bool,
    omitted_lower_bound: u64,
) -> Result<(), FutureEvidenceError> {
    if truncated != (omitted_lower_bound > 0) {
        return Err(FutureEvidenceError::InvalidTruncationCount { field });
    }
    Ok(())
}

fn ensure_retained_evidence_bound<T: RetainedSize>(
    field: &'static str,
    value: &T,
    budget: &PolicyBudget,
) -> Result<(), FutureEvidenceError> {
    if value.retained_size() > budget.max_evidence_bytes_per_finding() {
        return Err(FutureEvidenceError::RetainedEvidenceBudget {
            field,
            max_bytes: budget.max_evidence_bytes_per_finding(),
        });
    }
    Ok(())
}

fn compare_taint_source_facts(
    left: &TaintSourceProjectionFact,
    right: &TaintSourceProjectionFact,
) -> Ordering {
    (&left.source_endpoint, &left.source_label).cmp(&(&right.source_endpoint, &right.source_label))
}

fn taint_source_fact_semantic_key_equal(
    left: &TaintSourceProjectionFact,
    right: &TaintSourceProjectionFact,
) -> bool {
    left.source_endpoint == right.source_endpoint && left.source_label == right.source_label
}

fn compare_taint_origins(left: &TaintOriginEvidence, right: &TaintOriginEvidence) -> Ordering {
    (
        &left.source_endpoint,
        &left.source_label,
        &left.scenario_id,
        &left.primary,
    )
        .cmp(&(
            &right.source_endpoint,
            &right.source_label,
            &right.scenario_id,
            &right.primary,
        ))
}

fn compute_source_scenario_set_hash(scenarios: &[SourceScenarioId]) -> SourceScenarioSetHash {
    let mut hasher = CanonicalHasher::new(SOURCE_SCENARIO_SET_DOMAIN);
    hasher.sequence("scenario_ids", scenarios, |hasher, scenario| {
        hasher.value(scenario.as_str().as_bytes());
    });
    SourceScenarioSetHash::from_bytes(hasher.finish())
}

pub(crate) fn empty_source_scenario_set_hash() -> SourceScenarioSetHash {
    compute_source_scenario_set_hash(&[])
}

fn typestate_scenario_set_hash(scenarios: &[TypestateScenarioId]) -> TypestateScenarioSetHash {
    let mut hasher = CanonicalHasher::new(TYPESTATE_SCENARIO_SET_DOMAIN);
    hasher.sequence("scenario_ids", scenarios, |hasher, scenario| {
        hasher.value(scenario.as_str().as_bytes());
    });
    TypestateScenarioSetHash(hasher.finish())
}

fn empty_typestate_scenario_set_hash() -> TypestateScenarioSetHash {
    typestate_scenario_set_hash(&[])
}

fn taint_source_content_hash(fact: &TaintSourceProjectionFact) -> CvssEvidenceContentHash {
    let mut hasher = CanonicalHasher::new(CVSS_STATIC_EVIDENCE_DOMAIN);
    hash_endpoint_identity(&mut hasher, &fact.source_endpoint);
    hasher.field(
        "source_endpoint_semantic_hash",
        fact.source_endpoint_semantic_hash.as_bytes(),
    );
    hasher.field(
        "source_endpoint_analysis_projection_hash",
        fact.source_endpoint_analysis_projection_hash.as_bytes(),
    );
    hasher.field("source_display_name", fact.source_display_name.as_bytes());
    hash_string_ids(&mut hasher, "source_categories", &fact.source_categories);
    hasher.field("source_label", fact.source_label.as_str().as_bytes());
    hash_taint_source_evidence(&mut hasher, fact.source_evidence.as_ref());
    hasher.sequence(
        "source_scenario_ids",
        &fact.source_scenario_ids,
        |hasher, scenario| hasher.value(scenario.as_str().as_bytes()),
    );
    hasher.field("scenario_set_hash", fact.scenario_set_hash.as_bytes());
    hasher.field("evidence_ref", fact.evidence_ref.as_str().as_bytes());
    CvssEvidenceContentHash::from_bytes(hasher.finish())
}

fn taint_projection_facts_hash(facts: &TaintPolicyProjectionFacts) -> TaintProjectionFactsHash {
    let mut hasher = CanonicalHasher::new(TAINT_PROJECTION_FACTS_DOMAIN);
    hash_endpoint_identity(&mut hasher, &facts.sink_endpoint);
    hasher.field(
        "sink_endpoint_semantic_hash",
        facts.sink_endpoint_semantic_hash.as_bytes(),
    );
    hasher.field(
        "sink_endpoint_analysis_projection_hash",
        facts.sink_endpoint_analysis_projection_hash.as_bytes(),
    );
    hasher.field("sink_display_name", facts.sink_display_name.as_bytes());
    hash_string_ids(&mut hasher, "sink_categories", &facts.sink_categories);
    hash_string_ids(&mut hasher, "sink_tags", &facts.sink_tags);
    hash_string_ids(&mut hasher, "sink_impacts", &facts.sink_impacts);
    hash_string_ids(
        &mut hasher,
        "reached_source_labels",
        &facts.reached_source_labels,
    );
    hasher.sequence("source_facts", &facts.source_facts, |hasher, fact| {
        hash_endpoint_identity(hasher, &fact.source_endpoint);
        hasher.value(fact.source_endpoint_semantic_hash.as_bytes());
        hasher.value(fact.source_endpoint_analysis_projection_hash.as_bytes());
        hasher.value(fact.source_display_name.as_bytes());
        hash_string_ids(hasher, "source_categories", &fact.source_categories);
        hasher.value(fact.source_label.as_str().as_bytes());
        hash_taint_source_evidence(hasher, fact.source_evidence.as_ref());
        hasher.sequence(
            "source_scenario_ids",
            &fact.source_scenario_ids,
            |hasher, scenario| hasher.value(scenario.as_str().as_bytes()),
        );
        hasher.value(fact.scenario_set_hash.as_bytes());
        hasher.value(fact.evidence_ref.as_str().as_bytes());
        hasher.value(fact.content_hash.as_bytes());
    });
    TaintProjectionFactsHash(hasher.finish())
}

fn typestate_projection_facts_hash(
    facts: &TypestatePolicyProjectionFacts,
) -> TypestateProjectionFactsHash {
    let mut hasher = CanonicalHasher::new(TYPESTATE_PROJECTION_FACTS_DOMAIN);
    hasher.field("protocol_hash", facts.protocol_hash.as_bytes());
    hasher.field("binding_plan_hash", facts.binding_plan_hash.as_bytes());
    hash_endpoint_identity(&mut hasher, &facts.source_endpoint);
    hasher.field(
        "source_endpoint_hash",
        facts.source_endpoint_hash.as_bytes(),
    );
    hash_string_ids(&mut hasher, "source_categories", &facts.source_categories);
    hasher.field("source_display_name", facts.source_display_name.as_bytes());
    hash_optional_stable_identity(&mut hasher, &facts.violation_site);
    hash_typestate_violation(&mut hasher, &facts.violation);
    hasher.sequence("scenario_ids", &facts.scenario_ids, |hasher, scenario| {
        hasher.value(scenario.as_str().as_bytes());
    });
    hasher.field("scenario_set_hash", facts.scenario_set_hash.as_bytes());
    TypestateProjectionFactsHash(hasher.finish())
}

fn typestate_violation_hash(
    violation: &TypestateViolationEvidence,
    violation_site: &StableSemanticIdentity,
    scenario_set_hash: TypestateScenarioSetHash,
) -> TypestateViolationHash {
    let mut hasher = CanonicalHasher::new(TYPESTATE_VIOLATION_DOMAIN);
    hash_stable_identity(&mut hasher, violation_site);
    hash_typestate_violation(&mut hasher, violation);
    hasher.field("scenario_set_hash", scenario_set_hash.as_bytes());
    TypestateViolationHash(hasher.finish())
}

/// Canonical digest used by `PolicyFindingId::from_taint_anchor` in the
/// identity module, where the private `PolicyFindingId` bytes are owned.
pub(crate) fn taint_policy_finding_digest(
    policy_id: &PolicyId,
    anchor: &TaintFindingAnchor,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    update_finding_value(&mut hasher, POLICY_FINDING_DOMAIN);
    update_finding_value(&mut hasher, b"taint");
    update_finding_value(&mut hasher, policy_id.as_str().as_bytes());
    match anchor {
        TaintFindingAnchor::Strong(anchor) => {
            update_finding_value(&mut hasher, b"strong");
            update_finding_stable_identity(&mut hasher, &anchor.sink_identity);
            update_finding_value(
                &mut hasher,
                anchor.source_endpoint_analysis_projection_hash.as_bytes(),
            );
            update_finding_value(
                &mut hasher,
                anchor.sink_endpoint_analysis_projection_hash.as_bytes(),
            );
            update_finding_value(&mut hasher, anchor.source_scenario_set_hash.as_bytes());
        }
        TaintFindingAnchor::Weak(anchor) => {
            update_finding_value(&mut hasher, b"weak");
            update_finding_value(&mut hasher, anchor.typed_key.as_str().as_bytes());
        }
    }
    hasher.finalize().into()
}

pub(crate) fn taint_vulnerability_digest(anchor: &TaintFindingAnchor) -> [u8; 32] {
    let mut hasher = Sha256::new();
    update_finding_value(&mut hasher, POLICY_VULNERABILITY_DOMAIN);
    update_finding_value(&mut hasher, b"taint");
    match anchor {
        TaintFindingAnchor::Strong(anchor) => {
            update_finding_value(&mut hasher, b"strong");
            update_finding_stable_identity(&mut hasher, &anchor.sink_identity);
            update_finding_value(
                &mut hasher,
                anchor.source_endpoint_analysis_projection_hash.as_bytes(),
            );
            update_finding_value(
                &mut hasher,
                anchor.sink_endpoint_analysis_projection_hash.as_bytes(),
            );
            update_finding_value(&mut hasher, anchor.source_scenario_set_hash.as_bytes());
        }
        TaintFindingAnchor::Weak(anchor) => {
            update_finding_value(&mut hasher, b"weak");
            update_finding_value(&mut hasher, anchor.typed_key.as_str().as_bytes());
        }
    }
    hasher.finalize().into()
}

/// Canonical digest used by `PolicyFindingId::from_typestate_anchor` in the
/// identity module, where the private `PolicyFindingId` bytes are owned.
pub(crate) fn typestate_policy_finding_digest(
    policy_id: &PolicyId,
    anchor: &TypestateFindingAnchor,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    update_finding_value(&mut hasher, POLICY_FINDING_DOMAIN);
    update_finding_value(&mut hasher, b"typestate");
    update_finding_value(&mut hasher, policy_id.as_str().as_bytes());
    match anchor {
        TypestateFindingAnchor::Strong(anchor) => {
            update_finding_value(&mut hasher, b"strong");
            update_finding_value(&mut hasher, anchor.protocol_hash.as_bytes());
            update_finding_value(&mut hasher, anchor.binding_plan_hash.as_bytes());
            update_finding_stable_identity(&mut hasher, &anchor.subject_identity);
            update_finding_stable_identity(&mut hasher, &anchor.violation_site_identity);
            update_finding_value(&mut hasher, anchor.scenario_set_hash.as_bytes());
            update_finding_value(&mut hasher, anchor.violation_hash.as_bytes());
        }
        TypestateFindingAnchor::Weak(anchor) => {
            update_finding_value(&mut hasher, b"weak");
            update_finding_value(&mut hasher, anchor.typed_key.as_str().as_bytes());
        }
    }
    hasher.finalize().into()
}

pub(crate) fn typestate_vulnerability_digest(anchor: &TypestateFindingAnchor) -> [u8; 32] {
    let mut hasher = Sha256::new();
    update_finding_value(&mut hasher, POLICY_VULNERABILITY_DOMAIN);
    update_finding_value(&mut hasher, b"typestate");
    match anchor {
        TypestateFindingAnchor::Strong(anchor) => {
            update_finding_value(&mut hasher, b"strong");
            update_finding_value(&mut hasher, anchor.protocol_hash.as_bytes());
            update_finding_value(&mut hasher, anchor.binding_plan_hash.as_bytes());
            update_finding_stable_identity(&mut hasher, &anchor.subject_identity);
            update_finding_stable_identity(&mut hasher, &anchor.violation_site_identity);
            update_finding_value(&mut hasher, anchor.scenario_set_hash.as_bytes());
            update_finding_value(&mut hasher, anchor.violation_hash.as_bytes());
        }
        TypestateFindingAnchor::Weak(anchor) => {
            update_finding_value(&mut hasher, b"weak");
            update_finding_value(&mut hasher, anchor.typed_key.as_str().as_bytes());
        }
    }
    hasher.finalize().into()
}

fn update_finding_stable_identity(hasher: &mut Sha256, identity: &StableSemanticIdentity) {
    update_finding_value(hasher, identity.namespace().as_bytes());
    update_finding_value(hasher, identity.path().as_str().as_bytes());
    update_finding_value(hasher, identity.derivation().as_str().as_bytes());
    update_finding_value(hasher, identity.semantic_key().as_bytes());
}

fn update_finding_value(hasher: &mut Sha256, value: &[u8]) {
    let length = u64::try_from(value.len()).expect("usize fits u64 on supported targets");
    hasher.update(length.to_be_bytes());
    hasher.update(value);
}

fn hash_typestate_violation(hasher: &mut CanonicalHasher, value: &TypestateViolationEvidence) {
    match value {
        TypestateViolationEvidence::ErrorTransition {
            event_id,
            endpoint,
            from,
            to,
        } => {
            hasher.field("violation_type", b"error_transition");
            hasher.field("event_id", event_id.as_str().as_bytes());
            hash_optional_endpoint_identity(hasher, endpoint);
            hasher.field("from", from.as_str().as_bytes());
            hasher.field("to", to.as_str().as_bytes());
        }
        TypestateViolationEvidence::TerminalExpectation {
            expectation_id,
            terminal,
            observed_state,
            expected_states,
        } => {
            hasher.field("violation_type", b"terminal_expectation");
            hasher.field("expectation_id", expectation_id.as_str().as_bytes());
            hash_typestate_terminal(hasher, terminal);
            hasher.field("observed_state", observed_state.as_str().as_bytes());
            hash_string_ids(hasher, "expected_states", expected_states);
        }
    }
}

fn hash_typestate_terminal(hasher: &mut CanonicalHasher, value: &ResolvedTypestateTerminal) {
    match value {
        ResolvedTypestateTerminal::Endpoint { endpoint, phase } => {
            hasher.field("terminal_type", b"endpoint");
            hash_endpoint_identity(hasher, endpoint);
            hasher.field("phase", endpoint_phase_label(*phase).as_bytes());
        }
        ResolvedTypestateTerminal::SemanticEvent { event } => {
            hasher.field("terminal_type", b"semantic_event");
            hash_semantic_event(hasher, *event);
        }
    }
}

fn hash_optional_endpoint_identity(
    hasher: &mut CanonicalHasher,
    identity: &Option<ResolvedEndpointIdentity>,
) {
    match identity {
        Some(identity) => {
            hasher.field("endpoint_presence", b"some");
            hash_endpoint_identity(hasher, identity);
        }
        None => hasher.field("endpoint_presence", b"none"),
    }
}

fn hash_endpoint_identity(hasher: &mut CanonicalHasher, identity: &ResolvedEndpointIdentity) {
    match identity {
        ResolvedEndpointIdentity::Local {
            policy_id,
            entry_id,
        } => {
            hasher.field("endpoint_identity_type", b"local");
            hasher.field("policy_id", policy_id.as_str().as_bytes());
            hasher.field("entry_id", entry_id.as_str().as_bytes());
        }
        ResolvedEndpointIdentity::Catalog { catalog, entry_id } => {
            hasher.field("endpoint_identity_type", b"catalog");
            hasher.field("catalog_name", catalog.name.as_str().as_bytes());
            hasher.field("catalog_version", &catalog.version.to_be_bytes());
            hasher.field("catalog_hash", catalog.semantic_hash.as_bytes());
            hasher.field("entry_id", entry_id.as_str().as_bytes());
        }
        ResolvedEndpointIdentity::MatchEndpoint { endpoint_id } => {
            hasher.field("endpoint_identity_type", b"match_endpoint");
            hasher.field("endpoint_id", endpoint_id.as_str().as_bytes());
        }
    }
}

fn hash_optional_stable_identity(
    hasher: &mut CanonicalHasher,
    identity: &Option<StableSemanticIdentity>,
) {
    match identity {
        Some(identity) => {
            hasher.field("stable_identity_presence", b"some");
            hash_stable_identity(hasher, identity);
        }
        None => hasher.field("stable_identity_presence", b"none"),
    }
}

fn hash_stable_identity(hasher: &mut CanonicalHasher, identity: &StableSemanticIdentity) {
    hasher.field("semantic_namespace", identity.namespace().as_bytes());
    hasher.field("semantic_path", identity.path().as_str().as_bytes());
    hasher.field(
        "semantic_derivation",
        identity.derivation().as_str().as_bytes(),
    );
    hasher.field("semantic_key", identity.semantic_key().as_bytes());
}

fn hash_taint_source_evidence(
    hasher: &mut CanonicalHasher,
    evidence: Option<&TaintSourceEvidence>,
) {
    match evidence {
        Some(evidence) => {
            hasher.field("source_evidence_presence", b"some");
            hasher.field(
                "trust_boundary",
                evidence
                    .trust_boundary
                    .map_or("none", taint_trust_boundary_label)
                    .as_bytes(),
            );
            hasher.field(
                "system_entry",
                evidence
                    .system_entry
                    .map_or("none", taint_system_entry_label)
                    .as_bytes(),
            );
        }
        None => hasher.field("source_evidence_presence", b"none"),
    }
}

fn hash_semantic_event(hasher: &mut CanonicalHasher, event: PolicySemanticEvent) {
    match event {
        PolicySemanticEvent::NormalProcedureExit { scope } => {
            hasher.field("semantic_event", b"normal_procedure_exit");
            hasher.field("scope", typestate_exit_scope_label(scope).as_bytes());
        }
        PolicySemanticEvent::ExceptionalProcedureExit { scope } => {
            hasher.field("semantic_event", b"exceptional_procedure_exit");
            hasher.field("scope", typestate_exit_scope_label(scope).as_bytes());
        }
    }
}

fn hash_string_ids<T: AsRef<str>>(hasher: &mut CanonicalHasher, field: &'static str, values: &[T]) {
    hasher.sequence(field, values, |hasher, value| {
        hasher.value(value.as_ref().as_bytes());
    });
}

struct CanonicalHasher(Sha256);

impl CanonicalHasher {
    fn new(domain: &[u8]) -> Self {
        let mut hasher = Self(Sha256::new());
        hasher.value(domain);
        hasher
    }

    fn field(&mut self, name: &str, value: &[u8]) {
        self.value(name.as_bytes());
        self.value(value);
    }

    fn value(&mut self, value: &[u8]) {
        let length = u64::try_from(value.len()).expect("usize fits u64 on supported targets");
        self.0.update(length.to_be_bytes());
        self.0.update(value);
    }

    fn sequence<T>(&mut self, name: &str, values: &[T], mut update: impl FnMut(&mut Self, &T)) {
        self.value(name.as_bytes());
        self.value(
            &u64::try_from(values.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        for value in values {
            update(self, value);
        }
    }

    fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

fn hash_domain_bytes(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = CanonicalHasher::new(domain);
    hasher.value(bytes);
    hasher.finish()
}

fn tighten_string(value: &mut String) {
    *value = std::mem::take(value).into_boxed_str().into_string();
}

fn tighten_vec<T>(values: &mut Vec<T>) {
    *values = std::mem::take(values).into_boxed_slice().into_vec();
}

fn write_lower_hex(bytes: &[u8; 32], formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

macro_rules! serialize_string_identifier {
    ($($type:ty),+ $(,)?) => {
        $(
            impl Serialize for $type {
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where
                    S: Serializer,
                {
                    serializer.serialize_str(self.as_str())
                }
            }
        )+
    };
}

serialize_string_identifier!(
    EndpointId,
    PolicyCategoryId,
    TaintEntryId,
    FindingCombinationId,
    TaintLabel,
    TaintTag,
    TaintImpact,
    TypestateStateId,
    TypestateEventId,
    TypestateExpectationId,
);

macro_rules! serialize_digest_identifier {
    ($($type:ty),+ $(,)?) => {
        $(
            impl Serialize for $type {
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where
                    S: Serializer,
                {
                    serializer.collect_str(self)
                }
            }
        )+
    };
}

serialize_digest_identifier!(
    TaintCatalogHash,
    EndpointSemanticHash,
    EndpointAnalysisProjectionHash,
);

impl Serialize for ResolvedCatalogIdentity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ResolvedCatalogIdentity", 3)?;
        state.serialize_field("name", &self.name)?;
        state.serialize_field("version", &self.version)?;
        state.serialize_field("semantic_hash", &self.semantic_hash)?;
        state.end()
    }
}

impl Serialize for ResolvedEndpointIdentity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Local {
                policy_id,
                entry_id,
            } => {
                let mut state = serializer.serialize_struct("ResolvedEndpointIdentity", 3)?;
                state.serialize_field("type", "local")?;
                state.serialize_field("policy_id", policy_id)?;
                state.serialize_field("entry_id", entry_id)?;
                state.end()
            }
            Self::Catalog { catalog, entry_id } => {
                let mut state = serializer.serialize_struct("ResolvedEndpointIdentity", 3)?;
                state.serialize_field("type", "catalog")?;
                state.serialize_field("catalog", catalog)?;
                state.serialize_field("entry_id", entry_id)?;
                state.end()
            }
            Self::MatchEndpoint { endpoint_id } => {
                let mut state = serializer.serialize_struct("ResolvedEndpointIdentity", 2)?;
                state.serialize_field("type", "match_endpoint")?;
                state.serialize_field("endpoint_id", endpoint_id)?;
                state.end()
            }
        }
    }
}

impl Serialize for TaintSourceEvidence {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("TaintSourceEvidence", 2)?;
        state.serialize_field(
            "trust_boundary",
            &self.trust_boundary.map(SerializableTaintTrustBoundary),
        )?;
        state.serialize_field(
            "system_entry",
            &self.system_entry.map(SerializableTaintSystemEntry),
        )?;
        state.end()
    }
}

struct SerializableTaintTrustBoundary(TaintTrustBoundary);

impl Serialize for SerializableTaintTrustBoundary {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(taint_trust_boundary_label(self.0))
    }
}

struct SerializableTaintSystemEntry(TaintSystemEntry);

impl Serialize for SerializableTaintSystemEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(taint_system_entry_label(self.0))
    }
}

impl Serialize for EndpointObservationPhase {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(endpoint_phase_label(*self))
    }
}

impl Serialize for PolicySemanticEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::NormalProcedureExit { scope } => {
                let mut state = serializer.serialize_struct("PolicySemanticEvent", 2)?;
                state.serialize_field("type", "normal_procedure_exit")?;
                state.serialize_field("scope", &SerializableTypestateExitScope(*scope))?;
                state.end()
            }
            Self::ExceptionalProcedureExit { scope } => {
                let mut state = serializer.serialize_struct("PolicySemanticEvent", 2)?;
                state.serialize_field("type", "exceptional_procedure_exit")?;
                state.serialize_field("scope", &SerializableTypestateExitScope(*scope))?;
                state.end()
            }
        }
    }
}

struct SerializableTypestateExitScope(TypestateExitScope);

impl Serialize for SerializableTypestateExitScope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(typestate_exit_scope_label(self.0))
    }
}

impl RetainedSize for TaintSourceEvidence {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
    }
}

impl RetainedSize for TaintTrustBoundary {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
    }
}

impl RetainedSize for TaintSystemEntry {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
    }
}

impl RetainedSize for EndpointObservationPhase {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
    }
}

impl RetainedSize for PolicySemanticEvent {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
    }
}

fn taint_trust_boundary_label(value: TaintTrustBoundary) -> &'static str {
    match value {
        TaintTrustBoundary::External => "external",
        TaintTrustBoundary::Internal => "internal",
        TaintTrustBoundary::SameTrustZone => "same_trust_zone",
    }
}

fn taint_system_entry_label(value: TaintSystemEntry) -> &'static str {
    match value {
        TaintSystemEntry::VulnerableSystemNetworkStack => "vulnerable_system_network_stack",
        TaintSystemEntry::DownloadedArtifact => "downloaded_artifact",
        TaintSystemEntry::LocalInput => "local_input",
        TaintSystemEntry::AdjacentNetwork => "adjacent_network",
        TaintSystemEntry::Physical => "physical",
    }
}

fn endpoint_phase_label(value: EndpointObservationPhase) -> &'static str {
    match value {
        EndpointObservationPhase::AtMatch => "at_match",
        EndpointObservationPhase::BeforeCall => "before_call",
        EndpointObservationPhase::AfterNormalReturn => "after_normal_return",
        EndpointObservationPhase::AfterExceptionalReturn => "after_exceptional_return",
    }
}

fn typestate_exit_scope_label(value: TypestateExitScope) -> &'static str {
    match value {
        TypestateExitScope::AnalysisRoot => "analysis_root",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::policy::finding_identity::PolicyFindingId;
    use crate::analyzer::semantic::WorkspaceRelativePath;
    use serde_json::json;

    fn endpoint(value: &str) -> ResolvedEndpointIdentity {
        ResolvedEndpointIdentity::Local {
            policy_id: PolicyId::new("security.flow").unwrap(),
            entry_id: TaintEntryId::new(value).unwrap(),
        }
    }

    fn source_scenario(value: &str) -> SourceScenarioId {
        SourceScenarioId::try_new("taint", value).unwrap()
    }

    fn typestate_scenario(value: &str) -> TypestateScenarioId {
        TypestateScenarioId::try_new("typestate", value).unwrap()
    }

    fn evidence_ref(value: &str) -> EvidenceRef {
        EvidenceRef::try_new("analysis", value).unwrap()
    }

    fn stable_identity(derivation: StableIdentityDerivation, key: &str) -> StableSemanticIdentity {
        let path = WorkspaceRelativePath::new("src/app.rs").unwrap();
        match derivation {
            StableIdentityDerivation::AnalyzerDeclarationId => {
                StableSemanticIdentity::analyzer_declaration_id(
                    "rust",
                    path,
                    format!("function:{key}"),
                )
            }
            StableIdentityDerivation::CanonicalAstIdentity => {
                let semantic_key =
                    serde_json::to_string(&vec![("call_expression", Some(key))]).unwrap();
                StableSemanticIdentity::canonical_ast_identity("rust", path, semantic_key)
            }
            StableIdentityDerivation::CatalogEntry => {
                StableSemanticIdentity::catalog_entry("rust", path, key)
            }
            StableIdentityDerivation::ProtocolSubject => {
                StableSemanticIdentity::protocol_subject("rust", path, key)
            }
            StableIdentityDerivation::ProtocolViolationSite => {
                StableSemanticIdentity::protocol_violation_site("rust", path, key)
            }
        }
        .unwrap()
    }

    fn source_fact(
        endpoint_name: &str,
        label: &str,
        display: &str,
        scenarios: &[&str],
    ) -> TaintSourceProjectionFact {
        TaintSourceProjectionFact::try_new(
            endpoint(endpoint_name),
            EndpointSemanticHash::from_bytes([1; 32]),
            EndpointAnalysisProjectionHash::from_bytes([2; 32]),
            display.to_string(),
            vec![PolicyCategoryId::new("user-input").unwrap()],
            TaintLabel::new(label).unwrap(),
            Some(TaintSourceEvidence {
                trust_boundary: Some(TaintTrustBoundary::External),
                system_entry: Some(TaintSystemEntry::LocalInput),
            }),
            scenarios
                .iter()
                .map(|value| source_scenario(value))
                .collect(),
            evidence_ref(endpoint_name),
        )
        .unwrap()
    }

    fn taint_projection(
        mut source_facts: Vec<TaintSourceProjectionFact>,
    ) -> TaintPolicyProjectionFacts {
        let mut labels = source_facts
            .iter()
            .map(|fact| fact.source_label.clone())
            .collect::<Vec<_>>();
        labels.sort();
        labels.dedup();
        source_facts.reverse();
        TaintPolicyProjectionFacts::try_new(
            endpoint("sink"),
            EndpointSemanticHash::from_bytes([3; 32]),
            EndpointAnalysisProjectionHash::from_bytes([4; 32]),
            "sensitive sink".to_string(),
            vec![PolicyCategoryId::new("pii").unwrap()],
            vec![TaintTag::new("sensitive").unwrap()],
            vec![TaintImpact::new("confidentiality").unwrap()],
            labels,
            source_facts,
            &PolicyBudget::default(),
        )
        .unwrap()
    }

    fn terminal_violation() -> TypestateViolationEvidence {
        TypestateViolationEvidence::try_terminal_expectation(
            TypestateExpectationId::new("closed-at-exit").unwrap(),
            ResolvedTypestateTerminal::SemanticEvent {
                event: PolicySemanticEvent::NormalProcedureExit {
                    scope: TypestateExitScope::AnalysisRoot,
                },
            },
            TypestateStateId::new("open").unwrap(),
            vec![TypestateStateId::new("closed").unwrap()],
        )
        .unwrap()
    }

    fn typestate_projection() -> TypestatePolicyProjectionFacts {
        TypestatePolicyProjectionFacts::try_new(
            TypestateProtocolHash::from_canonical_bytes(b"protocol"),
            TypestateBindingPlanHash::from_canonical_bytes(b"bindings"),
            endpoint("subject"),
            EndpointSemanticHash::from_bytes([5; 32]),
            vec![PolicyCategoryId::new("resource").unwrap()],
            "resource handle".to_string(),
            Some(stable_identity(
                StableIdentityDerivation::ProtocolViolationSite,
                "crate::run/normal-exit",
            )),
            terminal_violation(),
            vec![typestate_scenario("root-b"), typestate_scenario("root-a")],
            &PolicyBudget::default(),
        )
        .unwrap()
    }

    fn taint_finding(
        projection: &TaintPolicyProjectionFacts,
        source_scenarios_truncated: bool,
        omitted_source_scenarios_lower_bound: u64,
        budget: &PolicyBudget,
    ) -> Result<TaintFindingEvidence, FutureEvidenceError> {
        let fact = &projection.source_facts[0];
        let anchor = TaintFindingAnchor::strong(
            stable_identity(StableIdentityDerivation::CanonicalAstIdentity, "sink-call"),
            fact.source_endpoint_analysis_projection_hash,
            projection.sink_endpoint_analysis_projection_hash,
            fact.scenario_set_hash,
        )?;
        let origin = TaintOriginEvidence::try_new(
            fact.source_endpoint.clone(),
            fact.source_label.clone(),
            fact.source_evidence.clone(),
            PolicySourceLocation::artifact(WorkspaceRelativePath::new("src/source.rs").unwrap()),
            fact.source_scenario_ids[0].clone(),
            vec![fact.evidence_ref.clone()],
        )?;
        TaintFindingEvidence::try_new(
            AnalysisFindingId::try_new("taint", "finding").unwrap(),
            anchor,
            AnalysisEventRef::try_new("taint", "sink-event").unwrap(),
            fact.source_endpoint.clone(),
            projection.sink_endpoint.clone(),
            fact.source_display_name.clone(),
            projection.sink_display_name.clone(),
            fact.source_categories.clone(),
            projection.sink_categories.clone(),
            None,
            projection.sink_tags.clone(),
            projection.sink_impacts.clone(),
            projection.reached_source_labels.clone(),
            vec![origin],
            false,
            fact.source_scenario_ids.clone(),
            source_scenarios_truncated,
            omitted_source_scenarios_lower_bound,
            fact.scenario_set_hash,
            Vec::new(),
            false,
            projection.semantic_hash,
            budget,
        )
    }

    #[test]
    fn source_scenario_set_domain_is_pinned_and_order_independent() {
        let first = SourceScenarioSetHash::try_from_scenarios(vec![
            source_scenario("path-b"),
            source_scenario("path-a"),
        ])
        .unwrap();
        let second = SourceScenarioSetHash::try_from_scenarios(vec![
            source_scenario("path-a"),
            source_scenario("path-b"),
        ])
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first.to_string(),
            "7134bb6cb3053486c83abc56f3d51af6b72a36551d508ac0ed642e54d89301c1"
        );

        let empty = SourceScenarioSetHash::try_from_scenarios(Vec::new()).unwrap();
        assert_eq!(empty, empty_source_scenario_set_hash());
    }

    #[test]
    fn scenario_projection_protocol_binding_and_violation_domains_are_distinct() {
        let source =
            SourceScenarioSetHash::try_from_scenarios(vec![source_scenario("same")]).unwrap();
        let typestate =
            TypestateScenarioSetHash::try_from_scenarios(vec![typestate_scenario("same")]).unwrap();
        assert_ne!(source.as_bytes(), typestate.as_bytes());

        let protocol = TypestateProtocolHash::from_canonical_bytes(b"same canonical bytes");
        let binding = TypestateBindingPlanHash::from_canonical_bytes(b"same canonical bytes");
        assert_ne!(protocol.as_bytes(), binding.as_bytes());

        let projection = typestate_projection();
        assert_ne!(
            projection.semantic_hash.as_bytes(),
            projection.scenario_set_hash.as_bytes()
        );

        let site = projection.violation_site.clone().unwrap();
        let terminal_hash =
            typestate_violation_hash(&projection.violation, &site, projection.scenario_set_hash);
        let transition = TypestateViolationEvidence::error_transition(
            TypestateEventId::new("close").unwrap(),
            Some(endpoint("subject")),
            TypestateStateId::new("open").unwrap(),
            TypestateStateId::new("error").unwrap(),
        );
        let transition_hash =
            typestate_violation_hash(&transition, &site, projection.scenario_set_hash);
        assert_ne!(terminal_hash, transition_hash);
    }

    #[test]
    fn projection_hashes_are_stable_across_adapter_iteration_order() {
        let first = source_fact(
            "source-a",
            "untrusted",
            "request body",
            &["path-b", "path-a"],
        );
        let second = source_fact("source-b", "user-data", "query parameter", &["path-c"]);

        let left = taint_projection(vec![first.clone(), second.clone()]);
        let right = taint_projection(vec![second, first]);
        assert_eq!(left, right);
        assert_eq!(left.semantic_hash, right.semantic_hash);
        assert_eq!(left.source_facts[0].source_endpoint, endpoint("source-a"));

        let mut direct = left.clone();
        direct.source_facts.reverse();
        direct.reached_source_labels.reverse();
        assert_eq!(
            direct
                .try_normalized(&PolicyBudget::default())
                .unwrap()
                .semantic_hash,
            left.semantic_hash
        );
    }

    #[test]
    fn duplicate_and_conflicting_projection_facts_are_rejected() {
        let fact = source_fact("source-a", "untrusted", "request body", &["path-a"]);
        let mut duplicate = taint_projection(vec![fact.clone()]);
        duplicate.source_facts.push(fact.clone());
        assert_eq!(
            duplicate
                .try_normalized(&PolicyBudget::default())
                .unwrap_err(),
            FutureEvidenceError::DuplicateProjectionFact { analysis: "taint" }
        );

        let conflicting = source_fact(
            "source-a",
            "untrusted",
            "same endpoint, different display",
            &["path-a"],
        );
        let mut conflict = taint_projection(vec![fact]);
        conflict.source_facts.push(conflicting);
        assert_eq!(
            conflict
                .try_normalized(&PolicyBudget::default())
                .unwrap_err(),
            FutureEvidenceError::ConflictingProjectionFact { analysis: "taint" }
        );

        assert_eq!(
            TaintSourceProjectionFact::try_new(
                endpoint("source"),
                EndpointSemanticHash::from_bytes([1; 32]),
                EndpointAnalysisProjectionHash::from_bytes([2; 32]),
                "source".to_string(),
                vec![
                    PolicyCategoryId::new("input").unwrap(),
                    PolicyCategoryId::new("input").unwrap(),
                ],
                TaintLabel::new("untrusted").unwrap(),
                None,
                vec![source_scenario("path")],
                evidence_ref("source"),
            )
            .unwrap_err(),
            FutureEvidenceError::DuplicateSemanticValue {
                field: "source_categories"
            }
        );
    }

    #[test]
    fn projection_validation_recomputes_every_supplied_hash() {
        let fact = source_fact("source", "untrusted", "source", &["path"]);
        let mut bad_fact = fact.clone();
        bad_fact.scenario_set_hash = SourceScenarioSetHash::from_bytes([9; 32]);
        assert_eq!(
            bad_fact.try_normalized().unwrap_err(),
            FutureEvidenceError::ScenarioSetHashMismatch {
                field: "source_scenario_ids"
            }
        );

        let mut bad_content = fact;
        bad_content.content_hash = CvssEvidenceContentHash::from_bytes([9; 32]);
        assert_eq!(
            bad_content.try_normalized().unwrap_err(),
            FutureEvidenceError::EvidenceContentHashMismatch
        );

        let mut taint = taint_projection(vec![source_fact(
            "source",
            "untrusted",
            "source",
            &["path"],
        )]);
        taint.semantic_hash = TaintProjectionFactsHash::from_bytes([9; 32]);
        assert_eq!(
            taint.try_normalized(&PolicyBudget::default()).unwrap_err(),
            FutureEvidenceError::ProjectionFactsHashMismatch { analysis: "taint" }
        );

        let mut typestate = typestate_projection();
        typestate.semantic_hash = TypestateProjectionFactsHash::from_bytes([9; 32]);
        assert_eq!(
            typestate
                .try_normalized(&PolicyBudget::default())
                .unwrap_err(),
            FutureEvidenceError::ProjectionFactsHashMismatch {
                analysis: "typestate"
            }
        );
    }

    #[test]
    fn strong_anchors_require_typed_semantic_identity_and_full_scenarios() {
        let taint_scenarios =
            SourceScenarioSetHash::try_from_scenarios(vec![source_scenario("path")]).unwrap();
        let taint = TaintFindingAnchor::strong(
            stable_identity(
                StableIdentityDerivation::CanonicalAstIdentity,
                "crate::sink/call",
            ),
            EndpointAnalysisProjectionHash::from_bytes([1; 32]),
            EndpointAnalysisProjectionHash::from_bytes([2; 32]),
            taint_scenarios,
        )
        .unwrap();
        assert_eq!(taint.stability(), FindingIdentityStability::Strong);
        assert_eq!(
            TaintFindingAnchor::strong(
                stable_identity(
                    StableIdentityDerivation::CanonicalAstIdentity,
                    "crate::sink/empty",
                ),
                EndpointAnalysisProjectionHash::from_bytes([1; 32]),
                EndpointAnalysisProjectionHash::from_bytes([2; 32]),
                SourceScenarioSetHash::try_from_scenarios(Vec::new()).unwrap(),
            )
            .unwrap_err(),
            FutureEvidenceError::StrongAnchorRequiresScenarios { analysis: "taint" }
        );
        assert_eq!(
            TaintFindingAnchor::strong(
                stable_identity(StableIdentityDerivation::CatalogEntry, "catalog-sink"),
                EndpointAnalysisProjectionHash::from_bytes([1; 32]),
                EndpointAnalysisProjectionHash::from_bytes([2; 32]),
                taint_scenarios,
            )
            .unwrap_err(),
            FutureEvidenceError::InvalidStrongIdentityDerivation {
                field: "taint_sink_identity"
            }
        );

        let projection = typestate_projection();
        let strong = TypestateFindingAnchor::strong(
            projection.protocol_hash,
            projection.binding_plan_hash,
            stable_identity(StableIdentityDerivation::ProtocolSubject, "subject"),
            projection.violation_site.clone().unwrap(),
            projection.scenario_set_hash,
            &projection.violation,
        )
        .unwrap();
        assert_eq!(strong.stability(), FindingIdentityStability::Strong);
        assert_eq!(
            TypestateFindingAnchor::strong(
                projection.protocol_hash,
                projection.binding_plan_hash,
                stable_identity(StableIdentityDerivation::CanonicalAstIdentity, "subject"),
                projection.violation_site.clone().unwrap(),
                projection.scenario_set_hash,
                &projection.violation,
            )
            .unwrap_err(),
            FutureEvidenceError::InvalidStrongIdentityDerivation {
                field: "typestate_subject_identity"
            }
        );

        let weak = TypestateFindingAnchor::weak(
            OpaqueFindingKey::try_new("typestate", "snapshot-finding").unwrap(),
        );
        assert_eq!(weak.stability(), FindingIdentityStability::Weak);
        assert!(weak.strong_fields().is_none());
    }

    #[test]
    fn future_anchors_have_stable_common_policy_finding_id_paths() {
        let policy_id = PolicyId::new("security.flow").unwrap();
        let source_scenarios =
            SourceScenarioSetHash::try_from_scenarios(vec![source_scenario("path")]).unwrap();
        let taint_anchor = TaintFindingAnchor::strong(
            stable_identity(StableIdentityDerivation::CanonicalAstIdentity, "sink-call"),
            EndpointAnalysisProjectionHash::from_bytes([1; 32]),
            EndpointAnalysisProjectionHash::from_bytes([2; 32]),
            source_scenarios,
        )
        .unwrap();
        let taint_id = PolicyFindingId::from_taint_anchor(&policy_id, &taint_anchor);
        assert_eq!(
            taint_id,
            PolicyFindingId::from_taint_anchor(&policy_id, &taint_anchor)
        );

        let projection = typestate_projection();
        let typestate_anchor = TypestateFindingAnchor::strong(
            projection.protocol_hash,
            projection.binding_plan_hash,
            stable_identity(StableIdentityDerivation::ProtocolSubject, "subject"),
            projection.violation_site.clone().unwrap(),
            projection.scenario_set_hash,
            &projection.violation,
        )
        .unwrap();
        let typestate_id = PolicyFindingId::from_typestate_anchor(&policy_id, &typestate_anchor);
        assert_ne!(taint_id, typestate_id);
        assert_eq!(taint_id.to_string().len(), 64);
        assert_eq!(typestate_id.to_string().len(), 64);

        let weak = TaintFindingAnchor::weak(
            OpaqueFindingKey::try_new("taint", "snapshot-finding").unwrap(),
        );
        assert_ne!(
            taint_id,
            PolicyFindingId::from_taint_anchor(&policy_id, &weak)
        );
    }

    #[test]
    fn terminal_violations_require_nonempty_expected_states_and_actual_violation() {
        let terminal = ResolvedTypestateTerminal::SemanticEvent {
            event: PolicySemanticEvent::NormalProcedureExit {
                scope: TypestateExitScope::AnalysisRoot,
            },
        };
        assert_eq!(
            TypestateViolationEvidence::try_terminal_expectation(
                TypestateExpectationId::new("closed-at-exit").unwrap(),
                terminal.clone(),
                TypestateStateId::new("open").unwrap(),
                Vec::new(),
            )
            .unwrap_err(),
            FutureEvidenceError::EmptySemanticSet {
                field: "expected_states"
            }
        );
        assert_eq!(
            TypestateViolationEvidence::try_terminal_expectation(
                TypestateExpectationId::new("closed-at-exit").unwrap(),
                terminal,
                TypestateStateId::new("closed").unwrap(),
                vec![TypestateStateId::new("closed").unwrap()],
            )
            .unwrap_err(),
            FutureEvidenceError::ObservedStateIsExpected
        );
    }

    #[test]
    fn truncation_counts_and_strong_anchor_integrity_are_enforced() {
        let projection = typestate_projection();
        let anchor = TypestateFindingAnchor::strong(
            projection.protocol_hash,
            projection.binding_plan_hash,
            stable_identity(StableIdentityDerivation::ProtocolSubject, "subject"),
            projection.violation_site.clone().unwrap(),
            projection.scenario_set_hash,
            &projection.violation,
        )
        .unwrap();

        let error = TypestateFindingEvidence::try_new(
            AnalysisFindingId::try_new("typestate", "finding").unwrap(),
            anchor.clone(),
            projection.protocol_hash,
            projection.binding_plan_hash,
            AnalysisSubjectRef::try_new("typestate", "subject").unwrap(),
            projection.source_endpoint.clone(),
            projection.violation_site.clone(),
            projection.violation.clone(),
            projection.scenario_ids.clone(),
            false,
            1,
            projection.scenario_set_hash,
            Vec::new(),
            false,
            projection.semantic_hash,
            &PolicyBudget::default(),
        )
        .unwrap_err();
        assert_eq!(
            error,
            FutureEvidenceError::InvalidTruncationCount {
                field: "typestate_scenarios"
            }
        );

        let low_budget = PolicyBudget::builder()
            .with_max_projection_scenario_memberships(1)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            TypestateFindingEvidence::try_new(
                AnalysisFindingId::try_new("typestate", "finding-low-budget").unwrap(),
                anchor.clone(),
                projection.protocol_hash,
                projection.binding_plan_hash,
                AnalysisSubjectRef::try_new("typestate", "subject").unwrap(),
                projection.source_endpoint.clone(),
                projection.violation_site.clone(),
                projection.violation.clone(),
                projection.scenario_ids.clone(),
                false,
                0,
                projection.scenario_set_hash,
                Vec::new(),
                false,
                projection.semantic_hash,
                &low_budget,
            )
            .unwrap_err(),
            FutureEvidenceError::TooManyItems {
                field: "typestate_scenario_ids",
                max_items: 1,
            }
        );

        let changed_violation = TypestateViolationEvidence::error_transition(
            TypestateEventId::new("close").unwrap(),
            None,
            TypestateStateId::new("open").unwrap(),
            TypestateStateId::new("error").unwrap(),
        );
        assert_eq!(
            TypestateFindingEvidence::try_new(
                AnalysisFindingId::try_new("typestate", "finding").unwrap(),
                anchor,
                projection.protocol_hash,
                projection.binding_plan_hash,
                AnalysisSubjectRef::try_new("typestate", "subject").unwrap(),
                projection.source_endpoint,
                projection.violation_site,
                changed_violation,
                projection.scenario_ids,
                false,
                0,
                projection.scenario_set_hash,
                Vec::new(),
                false,
                projection.semantic_hash,
                &PolicyBudget::default(),
            )
            .unwrap_err(),
            FutureEvidenceError::ViolationHashMismatch
        );
    }

    #[test]
    fn taint_finding_truncation_and_lowered_membership_budget_are_enforced() {
        let projection = taint_projection(vec![source_fact(
            "source",
            "untrusted",
            "source",
            &["path-a", "path-b"],
        )]);
        assert_eq!(
            taint_finding(&projection, false, 1, &PolicyBudget::default()).unwrap_err(),
            FutureEvidenceError::InvalidTruncationCount {
                field: "source_scenarios"
            }
        );

        let low_budget = PolicyBudget::builder()
            .with_max_projection_scenario_memberships(1)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            taint_finding(&projection, false, 0, &low_budget).unwrap_err(),
            FutureEvidenceError::TooManyItems {
                field: "source_scenarios",
                max_items: 1,
            }
        );

        let valid = taint_finding(&projection, false, 0, &PolicyBudget::default()).unwrap();
        assert_eq!(valid.source_scenarios().len(), 2);
        assert_eq!(
            serde_json::to_value(valid).unwrap()["source_scenario_set_hash"],
            json!(projection.source_facts[0].scenario_set_hash.to_string())
        );
    }

    #[test]
    fn wire_shapes_are_stable_tagged_snake_case_values() {
        let projection = typestate_projection();
        let json = serde_json::to_value(&projection).unwrap();
        assert_eq!(json["violation"]["type"], json!("terminal_expectation"));
        assert_eq!(
            json["violation"]["terminal"]["type"],
            json!("semantic_event")
        );
        assert_eq!(
            json["violation"]["terminal"]["event"]["type"],
            json!("normal_procedure_exit")
        );
        assert_eq!(
            json["source_endpoint"],
            json!({
                "type": "local",
                "policy_id": "security.flow",
                "entry_id": "subject"
            })
        );

        let weak = TaintFindingAnchor::weak(
            OpaqueFindingKey::try_new("taint", "snapshot-finding").unwrap(),
        );
        assert_eq!(
            serde_json::to_value(weak).unwrap(),
            json!({"type": "weak", "typed_key": "taint:snapshot-finding"})
        );
    }

    #[test]
    fn retained_size_tracks_owned_display_storage_exactly() {
        let short = source_fact("source", "untrusted", "a", &["path"]);
        let long = source_fact(
            "source",
            "untrusted",
            "a considerably longer display",
            &["path"],
        );
        assert_eq!(
            long.retained_size() - short.retained_size(),
            long.source_display_name.len() - short.source_display_name.len()
        );
        assert_eq!(
            TaintProjectionFactsHash::from_bytes([1; 32]).retained_size(),
            size_of::<TaintProjectionFactsHash>()
        );
        let projection = taint_projection(vec![short]);
        assert!(projection.retained_size() > size_of::<TaintPolicyProjectionFacts>());
    }
}
