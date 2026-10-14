//! Bounded, process-local evidence for semantic-model activation.
//!
//! The receipt is an opt-in diagnostic stream. It is deliberately separate
//! from the active-model cache and analyzer store: default activation performs
//! no receipt I/O, and no event survives the caller-owned query process.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, Weak};

use serde::ser::SerializeSeq;
use serde::{Serialize, Serializer};

use super::runtime::{
    ActiveSemanticModelSnapshot, ResolvedActiveSemanticModels, SemanticModelActivationEvidence,
    SemanticModelActivationRequest, SemanticModelRuntimeLimits,
};
use super::{
    CatalogCandidate, CatalogCoordinate, CatalogMiss, CatalogPackSourceKind,
    CompiledShardDescriptor, PackExtractionAccounting, SemanticPackSelectorQuery,
};
use crate::analyzer::Language;
use crate::analyzer::semantic_model::dependency::{
    DependencyDiscoveryEvidence, DependencyDiscoveryInformationalEvidence,
    StandardLibraryPackSelection,
};
use crate::analyzer::store::python_runtime::PythonRuntimeProviderPublication;

/// Hard maximum for one process-local activation receipt, including JSONL
/// delimiters and terminal event.
pub const ACTIVATION_RECEIPT_MAX_BYTES: usize = 16 * 1024 * 1024;

const ACTIVATION_RECEIPT_SCHEMA_VERSION: u32 = 1;
const MAX_RECEIPT_INTEGER: u64 = 9_007_199_254_740_991;

/// Caller-provided process identity. The private producer binds this opaque
/// value to its exact query invocation; the engine never interprets it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationReceiptInvocation {
    pub invocation_id: String,
    pub tool: String,
}

/// Stable source-level origin of one activation frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ActivationOrigin {
    WorkspaceDependencyPublication,
}

/// A construction or publication stage that can fail before a resolver result
/// exists. These events preserve a typed negative result without pretending a
/// resolver ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationReceiptStage {
    WorkspaceBuild,
    Configuration,
    CatalogBootstrap,
    WorkspaceModelRegistration,
    DependencyDiscovery,
    RuntimeAcquisition,
    SnapshotPublication,
}

/// Typed stage failure status. Detail strings are intentionally not accepted:
/// diagnostics may contain paths or other process-local values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationReceiptStageStatus {
    Incomplete,
    Unavailable,
    Cancelled,
}

#[derive(Debug)]
pub struct ActivationReceipt {
    state: Mutex<ReceiptState>,
}

#[derive(Debug)]
struct ReceiptState {
    file: File,
    bytes_written: usize,
    event_count: u64,
    next_frame_id: u64,
    sticky_error: Option<io::Error>,
    finished: bool,
    observed_active: Option<ObservedActive>,
}

#[derive(Debug)]
struct ObservedActive {
    frame_id: u64,
    active: Weak<ResolvedActiveSemanticModels>,
}

/// One activation's borrowed event handle. It retains no catalog result or
/// request data after each event is serialized.
#[derive(Debug)]
pub(crate) struct ActivationFrame<'a> {
    receipt: &'a ActivationReceipt,
    frame_id: u64,
    request_recorded: bool,
    effective_evidence_recorded: bool,
    candidate_phase: CandidatePhaseCoverage,
    candidate_queries: u64,
    candidates_seen: u64,
    union_candidates: u64,
    load_phase: CandidatePhaseCoverage,
    matching_phase: CandidatePhaseCoverage,
    extraction_phase: CandidatePhaseCoverage,
    lifecycle: ReceiptRuntimeLifecycle,
    resolution_recorded: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CandidatePhaseCoverage {
    NotStarted,
    InProgress,
    Complete,
    PartialBudgetStop,
    PartialFailure,
    Cancelled,
    UnavailableCached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ReceiptRuntimeLifecycle {
    NotStarted,
    Cached,
    Built,
    Uncached,
    CancelledBeforeResolution,
}

/// Summary returned after a complete footer was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivationReceiptSummary {
    pub event_count: u64,
    pub bytes_written: usize,
}

#[derive(Serialize)]
struct EventEnvelope<'a, T> {
    schema_version: u32,
    event: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    frame_id: Option<u64>,
    data: &'a T,
}

#[derive(Serialize)]
struct ReceiptStart<'a> {
    invocation_id: &'a str,
    tool: &'a str,
    process_id: u32,
    max_bytes: usize,
}

#[derive(Serialize)]
struct ActivationStart {
    origin: ActivationOrigin,
}

#[derive(Serialize)]
struct StageEvent {
    stage: ActivationReceiptStage,
    status: ActivationReceiptStageStatus,
}

#[derive(Serialize)]
struct SnapshotBinding {
    status: SnapshotBindingStatus,
    observed_frame_id: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotBindingStatus {
    ExactSameProcessObject,
    SnapshotUnavailable,
    NoObservedObject,
    DifferentObject,
}

#[derive(Serialize)]
struct ReceiptFinish {
    recording_status: &'static str,
    event_count: u64,
}

#[derive(Serialize)]
struct RequestEvent<'a> {
    bifrost_version: VersionDisplay<'a>,
    active_model_set_hash_domain: &'static str,
    active_model_set_representation_version: u32,
    python_active_model_set_hash_domain: Option<&'static str>,
    submitted_evidence: EvidenceSequence<'a>,
    controls: ControlSequence<'a>,
    limits: RuntimeLimitsRecord,
    dependency_publications: DependencyPublicationSequence<'a>,
    runtime_artifact_publication: RuntimePublicationRecord<'a>,
}

#[derive(Serialize)]
struct RuntimeLimitsRecord {
    #[serde(serialize_with = "serialize_receipt_usize")]
    max_evidence_rows: usize,
    #[serde(serialize_with = "serialize_receipt_usize")]
    max_controls: usize,
    #[serde(serialize_with = "serialize_receipt_usize")]
    max_catalog_candidates: usize,
    #[serde(serialize_with = "serialize_receipt_usize")]
    max_loaded_shards: usize,
    #[serde(serialize_with = "serialize_receipt_usize")]
    max_records: usize,
    #[serde(serialize_with = "serialize_receipt_usize")]
    max_index_entries: usize,
    #[serde(serialize_with = "serialize_receipt_u64")]
    max_working_bytes: u64,
    #[serde(serialize_with = "serialize_receipt_u64")]
    max_retained_bytes: u64,
    #[serde(serialize_with = "serialize_receipt_usize")]
    max_explanations: usize,
}

fn serialize_receipt_usize<S: Serializer>(value: &usize, serializer: S) -> Result<S::Ok, S::Error> {
    serialize_receipt_u64(&(*value as u64), serializer)
}

fn serialize_receipt_u64<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
    if *value > MAX_RECEIPT_INTEGER {
        return Err(<S::Error as serde::ser::Error>::custom(
            "receipt integer exceeds the exact JSON integer range",
        ));
    }
    serializer.serialize_u64(*value)
}

fn serialize_receipt_i64<S: Serializer>(value: &i64, serializer: S) -> Result<S::Ok, S::Error> {
    let value = u64::try_from(*value).map_err(|_| {
        <S::Error as serde::ser::Error>::custom("receipt integer must be nonnegative")
    })?;
    serialize_receipt_u64(&value, serializer)
}

impl From<SemanticModelRuntimeLimits> for RuntimeLimitsRecord {
    fn from(limits: SemanticModelRuntimeLimits) -> Self {
        Self {
            max_evidence_rows: limits.max_evidence_rows,
            max_controls: limits.max_controls,
            max_catalog_candidates: limits.max_catalog_candidates,
            max_loaded_shards: limits.max_loaded_shards,
            max_records: limits.max_records,
            max_index_entries: limits.max_index_entries,
            max_working_bytes: limits.max_working_bytes,
            max_retained_bytes: limits.max_retained_bytes,
            max_explanations: limits.max_explanations,
        }
    }
}

#[derive(Serialize)]
struct EvidenceRecord<'a> {
    language: &'a str,
    ecosystem: &'a str,
    package: Option<CoordinateRecord<'a>>,
    module: Option<CoordinateRecord<'a>>,
    toolchain: Option<CoordinateRecord<'a>>,
    target: Option<&'a str>,
    configuration: Option<&'a str>,
    artifact_sha256: Option<&'a str>,
}

impl<'a> From<&'a SemanticModelActivationEvidence> for EvidenceRecord<'a> {
    fn from(evidence: &'a SemanticModelActivationEvidence) -> Self {
        Self {
            language: &evidence.language,
            ecosystem: &evidence.ecosystem,
            package: evidence.package.as_ref().map(CoordinateRecord::from),
            module: evidence.module.as_ref().map(CoordinateRecord::from),
            toolchain: evidence.toolchain.as_ref().map(CoordinateRecord::from),
            target: evidence.target.as_deref(),
            configuration: evidence.configuration.as_deref(),
            artifact_sha256: evidence.artifact_sha256.as_deref(),
        }
    }
}

#[derive(Serialize)]
struct CoordinateRecord<'a> {
    name: &'a str,
    version: Option<VersionDisplay<'a>>,
}

impl<'a> From<&'a CatalogCoordinate> for CoordinateRecord<'a> {
    fn from(coordinate: &'a CatalogCoordinate) -> Self {
        Self {
            name: &coordinate.name,
            version: coordinate.version.as_ref().map(VersionDisplay),
        }
    }
}

struct VersionDisplay<'a>(&'a semver::Version);

impl Serialize for VersionDisplay<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

struct VersionReqDisplay<'a>(&'a semver::VersionReq);

impl Serialize for VersionReqDisplay<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

struct EvidenceSequence<'a>(&'a [SemanticModelActivationEvidence]);

impl Serialize for EvidenceSequence<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for evidence in self.0 {
            sequence.serialize_element(&EvidenceRecord::from(evidence))?;
        }
        sequence.end()
    }
}

#[derive(Serialize)]
struct ControlRecord<'a> {
    scope: &'static str,
    action: &'static str,
    selector: ControlSelectorRecord<'a>,
}

#[derive(Serialize)]
struct ControlSelectorRecord<'a> {
    pack_id: &'a str,
    version: Option<VersionReqDisplay<'a>>,
    manifest_digest: Option<&'a str>,
}

struct ControlSequence<'a>(&'a [super::runtime::SemanticModelActivationControl]);

impl Serialize for ControlSequence<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for control in self.0 {
            let scope = match control.scope {
                super::runtime::SemanticModelControlScope::User => "user",
                super::runtime::SemanticModelControlScope::Workspace => "workspace",
            };
            let action = match control.action {
                super::runtime::SemanticModelControlAction::Enable => "enable",
                super::runtime::SemanticModelControlAction::Disable => "disable",
                super::runtime::SemanticModelControlAction::AcceptReviewed => "accept_reviewed",
            };
            sequence.serialize_element(&ControlRecord {
                scope,
                action,
                selector: ControlSelectorRecord {
                    pack_id: &control.selector.pack_id,
                    version: control.selector.version.as_ref().map(VersionReqDisplay),
                    manifest_digest: control.selector.manifest_digest.as_deref(),
                },
            })?;
        }
        sequence.end()
    }
}

struct DependencyPublicationSequence<'a>(
    Option<&'a [super::runtime::DependencyEvidencePublication]>,
);

impl Serialize for DependencyPublicationSequence<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let Some(publications) = self.0 else {
            return serializer.serialize_none();
        };
        let mut sequence = serializer.serialize_seq(Some(publications.len()))?;
        for (languages, evidence) in publications {
            sequence.serialize_element(&DependencyPublicationRecord {
                languages: LanguageSequence(languages),
                declared_modules: DeclaredModulesSequence(evidence),
                truncated: evidence.truncated(),
                informational_evidence: DiscoveryInfoSequence(evidence.informational_evidence()),
            })?;
        }
        sequence.end()
    }
}

#[derive(Serialize)]
struct DependencyPublicationRecord<'a> {
    languages: LanguageSequence<'a>,
    declared_modules: DeclaredModulesSequence<'a>,
    truncated: bool,
    informational_evidence: DiscoveryInfoSequence<'a>,
}

struct LanguageSequence<'a>(&'a [Language]);

impl Serialize for LanguageSequence<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for language in self.0 {
            sequence.serialize_element(language.config_label())?;
        }
        sequence.end()
    }
}

struct DeclaredModulesSequence<'a>(&'a DependencyDiscoveryEvidence);

impl Serialize for DeclaredModulesSequence<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(None)?;
        for module in self.0.activation_receipt_declared_modules() {
            sequence.serialize_element(module)?;
        }
        sequence.end()
    }
}

struct DiscoveryInfoSequence<'a>(&'a [DependencyDiscoveryInformationalEvidence]);

impl Serialize for DiscoveryInfoSequence<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for item in self.0 {
            sequence.serialize_element(&DiscoveryInfoRecord::from(item))?;
        }
        sequence.end()
    }
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum DiscoveryInfoRecord<'a> {
    CppMissingWorkspaceSources {
        count: usize,
        sample: &'a [std::path::PathBuf],
    },
    StandardLibraryPack {
        language: &'static str,
        pack_id: &'a str,
        selection: StandardLibrarySelectionRecord<'a>,
    },
}

impl<'a> From<&'a DependencyDiscoveryInformationalEvidence> for DiscoveryInfoRecord<'a> {
    fn from(value: &'a DependencyDiscoveryInformationalEvidence) -> Self {
        match value {
            DependencyDiscoveryInformationalEvidence::CppMissingWorkspaceSources {
                count,
                sample,
            } => Self::CppMissingWorkspaceSources {
                count: *count,
                sample,
            },
            DependencyDiscoveryInformationalEvidence::StandardLibraryPack(expectation) => {
                Self::StandardLibraryPack {
                    language: expectation.language.config_label(),
                    pack_id: expectation.pack_id,
                    selection: match &expectation.selection {
                        StandardLibraryPackSelection::Declared { dependency_ids } => {
                            StandardLibrarySelectionRecord::Declared { dependency_ids }
                        }
                        StandardLibraryPackSelection::NotSelected { reason } => {
                            StandardLibrarySelectionRecord::NotSelected { reason }
                        }
                    },
                }
            }
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum StandardLibrarySelectionRecord<'a> {
    Declared { dependency_ids: &'a [String] },
    NotSelected { reason: &'a str },
}

#[derive(Serialize)]
struct RuntimePublicationRecord<'a> {
    jdk_artifacts_by_configured_home: JdkArtifactSequence<'a>,
    python_runtime: Option<PythonRuntimeRecord<'a>>,
}

struct JdkArtifactSequence<'a>(
    Option<&'a crate::hash::HashMap<std::path::PathBuf, SemanticModelActivationEvidence>>,
);

impl Serialize for JdkArtifactSequence<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let Some(map) = self.0 else {
            return serializer.serialize_none();
        };
        let mut sequence = serializer.serialize_seq(Some(map.len()))?;
        for (home, evidence) in map {
            sequence.serialize_element(&JdkArtifactRecord {
                configured_home: home,
                evidence: EvidenceRecord::from(evidence),
            })?;
        }
        sequence.end()
    }
}

#[derive(Serialize)]
struct JdkArtifactRecord<'a> {
    configured_home: &'a std::path::Path,
    evidence: EvidenceRecord<'a>,
}

#[derive(Serialize)]
struct PythonRuntimeRecord<'a> {
    #[serde(serialize_with = "serialize_receipt_i64")]
    acquisition_id: i64,
    snapshot: PythonSnapshotRecord<'a>,
    evidence_digest: String,
}

#[derive(Serialize)]
struct PythonSnapshotRecord<'a> {
    workspace_id: &'a str,
    language: &'a str,
    #[serde(serialize_with = "serialize_receipt_i64")]
    generation: i64,
    #[serde(serialize_with = "serialize_receipt_i64")]
    revision: i64,
}

impl<'a> From<&'a PythonRuntimeProviderPublication> for PythonRuntimeRecord<'a> {
    fn from(publication: &'a PythonRuntimeProviderPublication) -> Self {
        Self {
            acquisition_id: publication.acquisition_id.get(),
            snapshot: PythonSnapshotRecord {
                workspace_id: publication.snapshot.workspace_id.as_str(),
                language: &publication.snapshot.lang,
                generation: publication.snapshot.generation.get(),
                revision: publication.snapshot.revision,
            },
            evidence_digest: crate::analyzer::canonical_hash::lower_hex_string(
                &publication.evidence_digest,
            ),
        }
    }
}

#[derive(Serialize)]
struct CandidatePhaseEvent {
    status: CandidatePhaseCoverage,
    query_count: u64,
    candidate_observations: u64,
    union_candidate_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CandidateQuerySource {
    Evidence,
    LanguageEcosystem,
}

#[derive(Serialize)]
struct CandidateQueryEvent<'a> {
    query_index: u64,
    source: CandidateQuerySource,
    query: SelectorQueryRecord<'a>,
}

#[derive(Serialize)]
struct SelectorQueryRecord<'a> {
    language: &'a str,
    ecosystem: &'a str,
    package: Option<CoordinateRecord<'a>>,
    module: Option<CoordinateRecord<'a>>,
    toolchain: Option<CoordinateRecord<'a>>,
    target: Option<&'a str>,
    configuration: Option<&'a str>,
    artifact_sha256: Option<&'a str>,
    bifrost_version: VersionDisplay<'a>,
}

impl<'a> From<&'a SemanticPackSelectorQuery> for SelectorQueryRecord<'a> {
    fn from(query: &'a SemanticPackSelectorQuery) -> Self {
        Self {
            language: &query.language,
            ecosystem: &query.ecosystem,
            package: query.package.as_ref().map(CoordinateRecord::from),
            module: query.module.as_ref().map(CoordinateRecord::from),
            toolchain: query.toolchain.as_ref().map(CoordinateRecord::from),
            target: query.target.as_deref(),
            configuration: query.configuration.as_deref(),
            artifact_sha256: query.artifact_sha256.as_deref(),
            bifrost_version: VersionDisplay(&query.bifrost_version),
        }
    }
}

#[derive(Serialize)]
struct CandidateIdentity<'a> {
    manifest_digest: &'a str,
    shard_id: &'a str,
    source_kind: CatalogPackSourceKind,
    source_rank: u8,
    source_id: &'a str,
}

impl<'a> From<&'a CatalogCandidate> for CandidateIdentity<'a> {
    fn from(candidate: &'a CatalogCandidate) -> Self {
        Self {
            manifest_digest: candidate.manifest_digest(),
            shard_id: candidate.shard_id(),
            source_kind: candidate.source_kind(),
            source_rank: candidate.source_kind().precedence(),
            source_id: candidate.source_id(),
        }
    }
}

#[derive(Serialize)]
struct CandidateSeenEvent<'a> {
    query_index: u64,
    inserted_into_union: bool,
    candidate: CandidateIdentity<'a>,
}

#[derive(Serialize)]
struct CandidateUnionEvent<'a> {
    ordinal: u64,
    candidate: CandidateIdentity<'a>,
    completeness: super::Completeness,
    location: super::catalog::ActivationReceiptCandidateLocation,
    descriptor: &'a CompiledShardDescriptor,
}

#[derive(Serialize)]
struct CandidateLoadEvent<'a> {
    candidate: CandidateIdentity<'a>,
    outcome: CandidateLoadOutcome<'a>,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum CandidateLoadOutcome<'a> {
    Loaded {
        manifest_content_sha256: &'a str,
        pack_id: &'a str,
        pack_version: &'a str,
        loaded_shard_id: &'a str,
        loaded_source_kind: CatalogPackSourceKind,
        loaded_source_id: &'a str,
    },
    NotFound,
    Quarantined {
        reason: &'a str,
    },
    Incompatible {
        reason: &'a str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CandidateDecisionStatus {
    StrictIncompatible,
    ControlConflict,
    Disabled,
    ReviewRequired,
    DormantOptional,
    EligibleForPrecedence,
}

#[derive(Serialize)]
struct CandidateDecisionEvent<'a> {
    candidate: CandidateIdentity<'a>,
    status: CandidateDecisionStatus,
    control_action: Option<&'static str>,
    review_accepted: bool,
    strict_match: Option<StrictMatchRecord<'a>>,
}

#[derive(Serialize)]
struct StrictMatchRecord<'a> {
    evidence_rank: &'static str,
    representative_evidence: EvidenceRecord<'a>,
    matching_evidence: EvidenceSequence<'a>,
    matched_requirements: MatchedRequirementSequence<'a>,
}

struct MatchedRequirementSequence<'a>(&'a [super::runtime::MatchedVersionRequirement]);

impl Serialize for MatchedRequirementSequence<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for requirement in self.0 {
            sequence.serialize_element(&MatchedRequirementRecord {
                axis: requirement.axis,
                name: &requirement.name,
                requirement: &requirement.requirement,
                version: VersionDisplay(&requirement.version),
            })?;
        }
        sequence.end()
    }
}

#[derive(Serialize)]
struct MatchedRequirementRecord<'a> {
    axis: &'a str,
    name: &'a str,
    requirement: &'a str,
    version: VersionDisplay<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FinalSelectionStatus {
    Selected,
    Shadowed,
}

#[derive(Serialize)]
struct FinalSelectionEvent<'a> {
    candidate: SelectionIdentity<'a>,
    status: FinalSelectionStatus,
    shadowed_by: Option<SelectionIdentity<'a>>,
}

#[derive(Serialize)]
struct SelectionIdentity<'a> {
    manifest_digest: &'a str,
    shard_id: &'a str,
    source_kind: CatalogPackSourceKind,
    source_rank: u8,
    source_id: &'a str,
    semantic_sha256: &'a str,
    payload_kind: super::PayloadKind,
    evidence_rank: &'static str,
    review_accepted: bool,
    matched_evidence: EvidenceRecord<'a>,
    matching_evidence: EvidenceSequence<'a>,
}

fn selection_identity(shard: &super::runtime::ActiveSemanticModelShard) -> SelectionIdentity<'_> {
    let descriptor = shard
        .manifest
        .shards
        .iter()
        .find(|descriptor| descriptor.shard_id == shard.shard.shard_id())
        .expect("active shard has its manifest descriptor");
    SelectionIdentity {
        manifest_digest: &shard.manifest.content_sha256,
        shard_id: shard.shard.shard_id(),
        source_kind: shard.source_kind,
        source_rank: shard.source_rank,
        source_id: &shard.source_id,
        semantic_sha256: &descriptor.semantic_sha256,
        payload_kind: descriptor.payload_kind,
        evidence_rank: shard.evidence_rank.receipt_label(),
        review_accepted: shard.review_accepted,
        matched_evidence: EvidenceRecord::from(&shard.matched_evidence),
        matching_evidence: EvidenceSequence(&shard.matching_evidence),
    }
}

#[derive(Serialize)]
struct ExtractionAccountingEvent<'a> {
    manifest_digest: &'a str,
    pack_id: &'a str,
    read_status: &'static str,
    presence: Option<&'static str>,
    error: Option<&'a str>,
    accounting: Option<&'a PackExtractionAccounting>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ResolverStatus {
    Ready,
    Incomplete,
    Cancelled,
    Unavailable,
}

#[derive(Serialize)]
struct ResolutionFinishEvent<'a> {
    status: ResolverStatus,
    active_model_set_hash: Option<&'a str>,
    usable_model_set_hash: Option<&'a str>,
    phase_coverage: PhaseCoverageRecord,
    report: &'a super::runtime::SemanticModelActivationReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RuntimeStatus {
    Ready,
    Incomplete,
    Cancelled,
    Unavailable,
}

#[derive(Serialize)]
struct RuntimeFinishEvent<'a> {
    status: RuntimeStatus,
    active_model_set_hash: Option<&'a str>,
    usable_model_set_hash: Option<&'a str>,
    publication: &'static str,
    lifecycle: ReceiptRuntimeLifecycle,
    resolver_status_recorded: bool,
    phase_coverage: PhaseCoverageRecord,
    report: &'a super::runtime::SemanticModelActivationReport,
}

#[derive(Serialize)]
struct PhaseCoverageRecord {
    submitted_request: &'static str,
    effective_evidence: &'static str,
    candidate_discovery: CandidatePhaseCoverage,
    candidate_load: CandidatePhaseCoverage,
    strict_matching: CandidatePhaseCoverage,
    extraction_accounting: CandidatePhaseCoverage,
}

struct CappedFileWriter<'a> {
    file: &'a mut File,
    bytes_written: &'a mut usize,
}

impl Write for CappedFileWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(next) = self.bytes_written.checked_add(bytes.len()) else {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "activation receipt byte count overflow",
            ));
        };
        if next > ACTIVATION_RECEIPT_MAX_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "activation receipt exceeded its 16 MiB limit",
            ));
        }
        self.file.write_all(bytes)?;
        *self.bytes_written = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl ActivationReceipt {
    /// Create a new receipt without replacing an existing path. `create_new`
    /// also rejects an existing final-component symlink.
    pub fn create(
        path: impl AsRef<Path>,
        invocation: &ActivationReceiptInvocation,
    ) -> io::Result<Arc<Self>> {
        let file = OpenOptions::new().write(true).create_new(true).open(path)?;
        let receipt = Arc::new(Self {
            state: Mutex::new(ReceiptState {
                file,
                bytes_written: 0,
                event_count: 0,
                next_frame_id: 1,
                sticky_error: None,
                finished: false,
                observed_active: None,
            }),
        });
        receipt.emit(
            "receipt_start",
            None,
            &ReceiptStart {
                invocation_id: &invocation.invocation_id,
                tool: &invocation.tool,
                process_id: std::process::id(),
                max_bytes: ACTIVATION_RECEIPT_MAX_BYTES,
            },
        );
        receipt.check_sticky_error()?;
        Ok(receipt)
    }

    /// Start one frame before eager workspace activation begins.
    pub(crate) fn begin_activation(&self, origin: ActivationOrigin) -> ActivationFrame<'_> {
        let frame_id = {
            let mut state = self
                .state
                .lock()
                .expect("activation receipt mutex poisoned");
            let frame_id = state.next_frame_id;
            state.next_frame_id = state
                .next_frame_id
                .checked_add(1)
                .expect("activation receipt frame id overflow");
            frame_id
        };
        self.emit(
            "activation_start",
            Some(frame_id),
            &ActivationStart { origin },
        );
        ActivationFrame {
            receipt: self,
            frame_id,
            request_recorded: false,
            effective_evidence_recorded: false,
            candidate_phase: CandidatePhaseCoverage::NotStarted,
            candidate_queries: 0,
            candidates_seen: 0,
            union_candidates: 0,
            load_phase: CandidatePhaseCoverage::NotStarted,
            matching_phase: CandidatePhaseCoverage::NotStarted,
            extraction_phase: CandidatePhaseCoverage::NotStarted,
            lifecycle: ReceiptRuntimeLifecycle::NotStarted,
            resolution_recorded: false,
        }
    }

    /// Record a typed failure that prevented an activation frame from reaching
    /// the resolver.
    pub fn record_stage_failure(
        &self,
        stage: ActivationReceiptStage,
        status: ActivationReceiptStageStatus,
    ) {
        self.emit("stage_failure", None, &StageEvent { stage, status });
    }

    /// Bind the query's actual active object to a resolver frame using pointer
    /// identity. Hashes are intentionally absent from this comparison.
    pub fn bind_snapshot(
        &self,
        snapshot: Option<&ActiveSemanticModelSnapshot>,
    ) -> io::Result<SnapshotBindingStatus> {
        let mut state = self
            .state
            .lock()
            .expect("activation receipt mutex poisoned");
        let observed_frame_id = state
            .observed_active
            .as_ref()
            .map(|observed| observed.frame_id);
        let status = match snapshot {
            None => SnapshotBindingStatus::SnapshotUnavailable,
            Some(snapshot) => {
                let active = snapshot.active_models();
                match state.observed_active.as_ref() {
                    Some(observed) => match observed.active.upgrade() {
                        Some(observed_active) if Arc::ptr_eq(&observed_active, active) => {
                            SnapshotBindingStatus::ExactSameProcessObject
                        }
                        _ => SnapshotBindingStatus::DifferentObject,
                    },
                    None => SnapshotBindingStatus::NoObservedObject,
                }
            }
        };
        write_event_locked(
            &mut state,
            "snapshot_binding",
            None,
            &SnapshotBinding {
                status,
                observed_frame_id,
            },
        );
        check_sticky_error(&state)?;
        Ok(status)
    }

    /// Write the successful recording footer. Semantic incompleteness does not
    /// prevent this footer; only event-stream or I/O failure does.
    pub fn finish(&self) -> io::Result<ActivationReceiptSummary> {
        let mut state = self
            .state
            .lock()
            .expect("activation receipt mutex poisoned");
        check_sticky_error(&state)?;
        if state.finished {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "activation receipt was already finished",
            ));
        }
        let finish = ReceiptFinish {
            recording_status: "complete",
            event_count: state.event_count.saturating_add(1),
        };
        write_event_locked(&mut state, "receipt_finish", None, &finish);
        check_sticky_error(&state)?;
        if let Err(error) = state.file.flush() {
            state.sticky_error = Some(io::Error::new(error.kind(), error.to_string()));
            return Err(error);
        }
        state.finished = true;
        Ok(ActivationReceiptSummary {
            event_count: state.event_count,
            bytes_written: state.bytes_written,
        })
    }

    fn emit<T: Serialize>(&self, event: &'static str, frame_id: Option<u64>, data: &T) {
        let mut state = self
            .state
            .lock()
            .expect("activation receipt mutex poisoned");
        write_event_locked(&mut state, event, frame_id, data);
    }

    fn check_sticky_error(&self) -> io::Result<()> {
        let state = self
            .state
            .lock()
            .expect("activation receipt mutex poisoned");
        check_sticky_error(&state)
    }
}

impl ActivationFrame<'_> {
    pub(crate) fn record_request(
        &mut self,
        request: &SemanticModelActivationRequest,
        dependency_publications: Option<&[super::runtime::DependencyEvidencePublication]>,
        runtime_artifacts: super::runtime::RuntimeArtifactPublication<'_>,
    ) {
        if self.request_recorded {
            return;
        }
        let python_runtime = runtime_artifacts
            .python_runtime
            .map(PythonRuntimeRecord::from);
        let event = RequestEvent {
            bifrost_version: VersionDisplay(&request.bifrost_version),
            active_model_set_hash_domain: super::runtime::ACTIVE_MODEL_SET_HASH_DOMAIN,
            active_model_set_representation_version:
                super::runtime::SEMANTIC_MODEL_RUNTIME_REPRESENTATION_VERSION,
            python_active_model_set_hash_domain: runtime_artifacts
                .python_runtime
                .map(|_| super::runtime::PYTHON_ACTIVE_MODEL_SET_HASH_DOMAIN),
            submitted_evidence: EvidenceSequence(&request.evidence),
            controls: ControlSequence(&request.controls),
            limits: request.limits.into(),
            dependency_publications: DependencyPublicationSequence(dependency_publications),
            runtime_artifact_publication: RuntimePublicationRecord {
                jdk_artifacts_by_configured_home: JdkArtifactSequence(
                    runtime_artifacts.jdk_artifacts_by_configured_home,
                ),
                python_runtime,
            },
        };
        self.receipt.emit("request", Some(self.frame_id), &event);
        self.request_recorded = true;
    }

    pub(crate) fn record_effective_evidence(
        &mut self,
        evidence: &[SemanticModelActivationEvidence],
    ) {
        if self.effective_evidence_recorded {
            return;
        }
        self.receipt.emit(
            "effective_evidence",
            Some(self.frame_id),
            &EvidenceSequence(evidence),
        );
        self.effective_evidence_recorded = true;
    }

    pub(crate) fn set_lifecycle(
        &mut self,
        lifecycle: super::runtime::SemanticModelRuntimeLifecycle,
    ) {
        self.lifecycle = match lifecycle {
            super::runtime::SemanticModelRuntimeLifecycle::Cached => {
                ReceiptRuntimeLifecycle::Cached
            }
            super::runtime::SemanticModelRuntimeLifecycle::Built => ReceiptRuntimeLifecycle::Built,
            super::runtime::SemanticModelRuntimeLifecycle::Uncached => {
                ReceiptRuntimeLifecycle::Uncached
            }
        };
    }

    pub(crate) fn mark_cancelled_before_resolution(&mut self) {
        self.lifecycle = ReceiptRuntimeLifecycle::CancelledBeforeResolution;
    }

    pub(crate) fn mark_cache_hit_without_resolver(&mut self) {
        self.load_phase = CandidatePhaseCoverage::UnavailableCached;
        self.matching_phase = CandidatePhaseCoverage::UnavailableCached;
        self.extraction_phase = CandidatePhaseCoverage::UnavailableCached;
        self.set_candidate_phase(CandidatePhaseCoverage::UnavailableCached);
    }

    pub(crate) fn record_candidate_query(
        &mut self,
        source: CandidateQuerySource,
        query: &SemanticPackSelectorQuery,
    ) -> u64 {
        if self.candidate_phase == CandidatePhaseCoverage::NotStarted {
            self.candidate_phase = CandidatePhaseCoverage::InProgress;
        }
        let query_index = self.candidate_queries;
        self.candidate_queries = self.candidate_queries.saturating_add(1);
        self.receipt.emit(
            "candidate_query",
            Some(self.frame_id),
            &CandidateQueryEvent {
                query_index,
                source,
                query: SelectorQueryRecord::from(query),
            },
        );
        query_index
    }

    pub(crate) fn record_candidate_seen(
        &mut self,
        query_index: u64,
        candidate: &CatalogCandidate,
        inserted_into_union: bool,
    ) {
        self.candidates_seen = self.candidates_seen.saturating_add(1);
        if inserted_into_union {
            self.union_candidates = self.union_candidates.saturating_add(1);
        }
        self.receipt.emit(
            "candidate_seen",
            Some(self.frame_id),
            &CandidateSeenEvent {
                query_index,
                inserted_into_union,
                candidate: CandidateIdentity::from(candidate),
            },
        );
    }

    pub(crate) fn record_candidate_union_member(
        &mut self,
        ordinal: u64,
        candidate: &CatalogCandidate,
    ) {
        self.receipt.emit(
            "candidate_union_member",
            Some(self.frame_id),
            &CandidateUnionEvent {
                ordinal,
                candidate: CandidateIdentity::from(candidate),
                completeness: candidate.completeness(),
                location: candidate.activation_receipt_location(),
                descriptor: candidate.descriptor(),
            },
        );
    }

    pub(crate) fn set_candidate_phase(&mut self, status: CandidatePhaseCoverage) {
        self.candidate_phase = status;
        self.receipt.emit(
            "phase_coverage",
            Some(self.frame_id),
            &CandidatePhaseEvent {
                status,
                query_count: self.candidate_queries,
                candidate_observations: self.candidates_seen,
                union_candidate_count: self.union_candidates,
            },
        );
    }

    pub(crate) fn set_load_phase(&mut self, status: CandidatePhaseCoverage) {
        self.load_phase = status;
    }

    pub(crate) fn set_matching_phase(&mut self, status: CandidatePhaseCoverage) {
        self.matching_phase = status;
    }

    pub(crate) fn set_extraction_phase(&mut self, status: CandidatePhaseCoverage) {
        self.extraction_phase = status;
    }

    pub(crate) fn record_candidate_load(
        &mut self,
        candidate: &CatalogCandidate,
        loaded: Result<&super::catalog::LoadedCatalogShard, &CatalogMiss>,
    ) {
        let outcome = match loaded {
            Ok(loaded) => CandidateLoadOutcome::Loaded {
                manifest_content_sha256: &loaded.manifest.content_sha256,
                pack_id: &loaded.manifest.pack_id,
                pack_version: &loaded.manifest.version,
                loaded_shard_id: loaded.shard.shard_id(),
                loaded_source_kind: loaded.source_kind,
                loaded_source_id: &loaded.source_id,
            },
            Err(CatalogMiss::NotFound) => CandidateLoadOutcome::NotFound,
            Err(CatalogMiss::Quarantined { reason }) => {
                CandidateLoadOutcome::Quarantined { reason }
            }
            Err(CatalogMiss::Incompatible { reason }) => {
                CandidateLoadOutcome::Incompatible { reason }
            }
        };
        self.receipt.emit(
            "candidate_load",
            Some(self.frame_id),
            &CandidateLoadEvent {
                candidate: CandidateIdentity::from(candidate),
                outcome,
            },
        );
    }

    pub(crate) fn record_candidate_decision(
        &mut self,
        candidate: &CatalogCandidate,
        status: CandidateDecisionStatus,
        control_action: Option<super::runtime::SemanticModelControlAction>,
        review_accepted: bool,
        strict_match: Option<&super::runtime::StrictActivationMatch>,
    ) {
        let strict_match = strict_match.map(|matched| StrictMatchRecord {
            evidence_rank: matched.evidence_rank.receipt_label(),
            representative_evidence: EvidenceRecord::from(&matched.matched_evidence),
            matching_evidence: EvidenceSequence(&matched.matching_evidence),
            matched_requirements: MatchedRequirementSequence(&matched.matched_requirements),
        });
        let event = CandidateDecisionEvent {
            candidate: CandidateIdentity::from(candidate),
            status,
            control_action: control_action.map(|action| match action {
                super::runtime::SemanticModelControlAction::Enable => "enable",
                super::runtime::SemanticModelControlAction::Disable => "disable",
                super::runtime::SemanticModelControlAction::AcceptReviewed => "accept_reviewed",
            }),
            review_accepted,
            strict_match,
        };
        self.receipt
            .emit("candidate_decision", Some(self.frame_id), &event);
    }

    pub(crate) fn record_final_selection(
        &mut self,
        selected: &super::runtime::ActiveSemanticModelShard,
        status: FinalSelectionStatus,
        shadowed_by: Option<&super::runtime::ActiveSemanticModelShard>,
    ) {
        self.receipt.emit(
            "final_selection",
            Some(self.frame_id),
            &FinalSelectionEvent {
                candidate: selection_identity(selected),
                status,
                shadowed_by: shadowed_by.map(selection_identity),
            },
        );
    }

    pub(crate) fn record_extraction_accounting(
        &mut self,
        manifest_digest: &str,
        pack_id: &str,
        accounting: Option<&PackExtractionAccounting>,
    ) {
        let presence = match accounting {
            None => "absent",
            Some(accounting)
                if accounting.reject_count == 0
                    && accounting.suppressed_reject_count == 0
                    && accounting.error_reject_count == 0
                    && accounting.gaps.is_empty()
                    && accounting.source_entries.is_empty() =>
            {
                "present_empty"
            }
            Some(_) => "present_nonempty",
        };
        self.receipt.emit(
            "extraction_accounting",
            Some(self.frame_id),
            &ExtractionAccountingEvent {
                manifest_digest,
                pack_id,
                read_status: "read",
                presence: Some(presence),
                error: None,
                accounting,
            },
        );
    }

    pub(crate) fn record_extraction_accounting_error(
        &mut self,
        manifest_digest: &str,
        pack_id: &str,
        error: &str,
    ) {
        self.receipt.emit(
            "extraction_accounting",
            Some(self.frame_id),
            &ExtractionAccountingEvent {
                manifest_digest,
                pack_id,
                read_status: "unavailable",
                presence: None,
                error: Some(error),
                accounting: None,
            },
        );
    }

    pub(crate) fn record_resolution_outcome(
        &mut self,
        outcome: &super::runtime::SemanticModelResolutionOutcome,
    ) {
        let (status, report, active_model_set_hash, usable_model_set_hash) = match outcome {
            super::runtime::SemanticModelResolutionOutcome::Ready(active) => (
                ResolverStatus::Ready,
                active.activation_report(),
                Some(active.active_model_set_hash()),
                Some(active.active_model_set_hash()),
            ),
            super::runtime::SemanticModelResolutionOutcome::Incomplete { usable, report } => (
                ResolverStatus::Incomplete,
                report,
                None,
                usable.as_ref().map(|active| active.active_model_set_hash()),
            ),
            super::runtime::SemanticModelResolutionOutcome::Cancelled(report) => {
                (ResolverStatus::Cancelled, report, None, None)
            }
            super::runtime::SemanticModelResolutionOutcome::Unavailable(report) => {
                (ResolverStatus::Unavailable, report, None, None)
            }
        };
        if self.candidate_phase == CandidatePhaseCoverage::InProgress {
            self.candidate_phase = CandidatePhaseCoverage::PartialFailure;
        }
        self.receipt.emit(
            "resolution_finish",
            Some(self.frame_id),
            &ResolutionFinishEvent {
                status,
                active_model_set_hash,
                usable_model_set_hash,
                phase_coverage: self.phase_coverage(),
                report,
            },
        );
        self.resolution_recorded = true;
    }

    pub(crate) fn finish_runtime_outcome(
        &mut self,
        outcome: &super::runtime::SemanticModelRuntimeOutcome,
    ) {
        let (status, report, active_model_set_hash, usable_model_set_hash, publication, active) =
            match outcome {
                super::runtime::SemanticModelRuntimeOutcome::Ready {
                    active, lifecycle, ..
                } => {
                    self.set_lifecycle(*lifecycle);
                    (
                        RuntimeStatus::Ready,
                        active.activation_report(),
                        Some(active.active_model_set_hash()),
                        Some(active.active_model_set_hash()),
                        "published",
                        Some(active),
                    )
                }
                super::runtime::SemanticModelRuntimeOutcome::Incomplete { usable, report } => (
                    RuntimeStatus::Incomplete,
                    report,
                    None,
                    usable.as_ref().map(|active| active.active_model_set_hash()),
                    if usable.is_some() {
                        "usable_not_published"
                    } else {
                        "none"
                    },
                    None,
                ),
                super::runtime::SemanticModelRuntimeOutcome::Cancelled(report) => {
                    (RuntimeStatus::Cancelled, report, None, None, "none", None)
                }
                super::runtime::SemanticModelRuntimeOutcome::Unavailable(report) => {
                    (RuntimeStatus::Unavailable, report, None, None, "none", None)
                }
            };
        self.receipt.emit(
            "runtime_finish",
            Some(self.frame_id),
            &RuntimeFinishEvent {
                status,
                active_model_set_hash,
                usable_model_set_hash,
                publication,
                lifecycle: self.lifecycle,
                resolver_status_recorded: self.resolution_recorded,
                phase_coverage: self.phase_coverage(),
                report,
            },
        );
        let mut state = self
            .receipt
            .state
            .lock()
            .expect("activation receipt mutex poisoned");
        state.observed_active = active.map(|active| ObservedActive {
            frame_id: self.frame_id,
            active: Arc::downgrade(active),
        });
    }

    fn phase_coverage(&self) -> PhaseCoverageRecord {
        PhaseCoverageRecord {
            submitted_request: if self.request_recorded {
                "complete"
            } else {
                "not_recorded"
            },
            effective_evidence: if self.effective_evidence_recorded {
                "complete"
            } else {
                "not_recorded"
            },
            candidate_discovery: self.candidate_phase,
            candidate_load: self.load_phase,
            strict_matching: self.matching_phase,
            extraction_accounting: self.extraction_phase,
        }
    }
}

fn write_event_locked<T: Serialize>(
    state: &mut ReceiptState,
    event: &'static str,
    frame_id: Option<u64>,
    data: &T,
) {
    if state.sticky_error.is_some() || state.finished {
        return;
    }
    let envelope = EventEnvelope {
        schema_version: ACTIVATION_RECEIPT_SCHEMA_VERSION,
        event,
        frame_id,
        data,
    };
    let result = {
        let mut writer = CappedFileWriter {
            file: &mut state.file,
            bytes_written: &mut state.bytes_written,
        };
        serde_json::to_writer(&mut writer, &envelope)
            .and_then(|()| writer.write_all(b"\n").map_err(serde_json::Error::io))
    };
    match result {
        Ok(()) => state.event_count = state.event_count.saturating_add(1),
        Err(error) => state.sticky_error = Some(io::Error::other(error.to_string())),
    }
}

fn check_sticky_error(state: &ReceiptState) -> io::Result<()> {
    match &state.sticky_error {
        Some(error) => Err(io::Error::new(error.kind(), error.to_string())),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invocation() -> ActivationReceiptInvocation {
        ActivationReceiptInvocation {
            invocation_id: "test-invocation".to_owned(),
            tool: "query_code".to_owned(),
        }
    }

    #[test]
    fn complete_negative_receipt_has_typed_stage_and_footer() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("activation.jsonl");
        let receipt = ActivationReceipt::create(&path, &invocation()).unwrap();
        receipt.record_stage_failure(
            ActivationReceiptStage::DependencyDiscovery,
            ActivationReceiptStageStatus::Incomplete,
        );
        assert_eq!(
            receipt.bind_snapshot(None).unwrap(),
            SnapshotBindingStatus::SnapshotUnavailable
        );
        let summary = receipt.finish().unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(summary.bytes_written, bytes.len());
        let lines = bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(lines.len() as u64, summary.event_count);
        assert_eq!(lines[0]["event"], "receipt_start");
        assert_eq!(lines[1]["event"], "stage_failure");
        assert_eq!(lines[2]["event"], "snapshot_binding");
        assert_eq!(lines[2]["data"]["status"], "snapshot_unavailable");
        assert_eq!(lines[3]["event"], "receipt_finish");
        assert_eq!(lines[3]["data"]["recording_status"], "complete");
    }

    #[test]
    fn receipt_create_is_exclusive_and_preserves_existing_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("activation.jsonl");
        std::fs::write(&path, b"keep").unwrap();
        assert!(ActivationReceipt::create(&path, &invocation()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"keep");
    }

    #[cfg(unix)]
    #[test]
    fn receipt_create_does_not_follow_an_existing_final_symlink() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        let path = temp.path().join("activation.jsonl");
        std::fs::write(&target, b"keep").unwrap();
        symlink(&target, &path).unwrap();
        assert!(ActivationReceipt::create(&path, &invocation()).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
        assert!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn cap_failure_is_sticky_and_never_writes_a_success_footer() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("activation.jsonl");
        let receipt = ActivationReceipt::create(&path, &invocation()).unwrap();
        let oversized = "x".repeat(ACTIVATION_RECEIPT_MAX_BYTES);
        receipt.emit("oversized_test_event", None, &oversized);
        assert!(receipt.finish().is_err());
        let bytes = std::fs::read(&path).unwrap();
        assert!(bytes.len() <= ACTIVATION_RECEIPT_MAX_BYTES);
        assert!(!String::from_utf8_lossy(&bytes).contains("receipt_finish"));
    }

    #[test]
    fn request_preserves_absent_and_explicitly_empty_publications() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("publication-options.jsonl");
        let receipt = ActivationReceipt::create(&path, &invocation()).unwrap();
        let request = SemanticModelActivationRequest {
            bifrost_version: semver::Version::parse("0.13.1").unwrap(),
            evidence: Vec::new(),
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        };
        let unavailable =
            super::super::runtime::SemanticModelRuntimeOutcome::Unavailable(Default::default());
        let mut absent = receipt.begin_activation(ActivationOrigin::WorkspaceDependencyPublication);
        absent.record_request(
            &request,
            None,
            super::super::runtime::RuntimeArtifactPublication::default(),
        );
        absent.finish_runtime_outcome(&unavailable);
        let empty_jdk = crate::hash::HashMap::default();
        let mut empty = receipt.begin_activation(ActivationOrigin::WorkspaceDependencyPublication);
        empty.record_request(
            &request,
            Some(&[]),
            super::super::runtime::RuntimeArtifactPublication {
                jdk_artifacts_by_configured_home: Some(&empty_jdk),
                python_runtime: None,
            },
        );
        empty.finish_runtime_outcome(&unavailable);
        receipt.finish().unwrap();
        let events = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|event| event["event"] == "request")
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 2);
        assert!(events[0]["data"]["dependency_publications"].is_null());
        assert!(
            events[0]["data"]["runtime_artifact_publication"]["jdk_artifacts_by_configured_home"]
                .is_null()
        );
        assert_eq!(
            events[1]["data"]["dependency_publications"],
            serde_json::json!([])
        );
        assert_eq!(
            events[1]["data"]["runtime_artifact_publication"]["jdk_artifacts_by_configured_home"],
            serde_json::json!([])
        );
    }

    #[test]
    fn unsafe_request_integer_is_a_sticky_recording_failure_without_a_footer() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("unsafe-integer.jsonl");
        let receipt = ActivationReceipt::create(&path, &invocation()).unwrap();
        let request = SemanticModelActivationRequest {
            bifrost_version: semver::Version::parse("0.13.1").unwrap(),
            evidence: Vec::new(),
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits {
                max_working_bytes: u64::MAX,
                ..SemanticModelRuntimeLimits::default()
            },
        };
        let mut frame = receipt.begin_activation(ActivationOrigin::WorkspaceDependencyPublication);
        frame.record_request(
            &request,
            None,
            super::super::runtime::RuntimeArtifactPublication::default(),
        );
        assert!(receipt.finish().is_err());
        let bytes = std::fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("receipt_finish"));
    }
}
