use super::model::*;
use super::validate::{Diagnostic, ValidationLimits, validate_pack_locally};
use crate::analyzer::canonical_hash::{
    hash_domain_bytes, is_lower_sha256, lower_hex_string, sha256_bytes,
};
use crate::analyzer::identifier::validate_identifier;
use flate2::bufread::DeflateDecoder;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::io::{Cursor, Read};

const MANIFEST_HASH_DOMAIN: &[u8] = b"bifrost.semantic-model.manifest.v1";
const SEMANTIC_HASH_DOMAIN: &[u8] = b"bifrost.semantic-model.shard.semantic.v1";
const PROCEDURE_TARGET_HASH_DOMAIN: &[u8] = b"bifrost.semantic-model.procedure-target.inventory.v1";
const PROCEDURE_ID_INVENTORY_PREFIX: &str = "procedure:";
const PROCEDURE_TARGET_INVENTORY_PREFIX: &str = "procedure-target:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadKind {
    DeclarationFacts,
    GeneratorRules,
    ProcedureSummaries,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactEncoding {
    Raw,
    Deflate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledShardDescriptor {
    pub shard_id: String,
    pub payload_kind: PayloadKind,
    pub routing_keys: Vec<String>,
    pub encoding: ArtifactEncoding,
    pub raw_size: u64,
    pub stored_size: u64,
    pub record_count: u64,
    pub defined_ids: Vec<String>,
    pub referenced_ids: Vec<String>,
    pub semantic_sha256: String,
    pub content_sha256: String,
    pub stored_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledPackManifest {
    pub schema_version: u32,
    pub pack_id: String,
    pub version: String,
    pub producer: Producer,
    pub language: String,
    pub ecosystem: String,
    pub compatibility: Compatibility,
    pub provenance: Provenance,
    pub license: String,
    pub completeness: Completeness,
    pub safety: Safety,
    pub semantic_sha256: String,
    pub content_sha256: String,
    pub shards: Vec<CompiledShardDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledShard {
    pub(crate) schema_version: u32,
    pub(crate) pack_id: String,
    pub(crate) pack_version: String,
    pub(crate) producer: Producer,
    pub(crate) shard_id: String,
    pub(crate) language: String,
    pub(crate) ecosystem: String,
    pub(crate) compatibility: Compatibility,
    pub(crate) activation: Vec<ActivationSelector>,
    pub(crate) provenance: Provenance,
    pub(crate) license: String,
    pub(crate) completeness: Completeness,
    pub(crate) safety: Safety,
    pub(crate) payload: CompiledPayload,
}

impl CompiledShard {
    pub fn payload_kind(&self) -> PayloadKind {
        self.payload.payload_kind()
    }

    pub fn record_count(&self) -> usize {
        self.payload.record_count()
    }

    pub fn pack_id(&self) -> &str {
        &self.pack_id
    }

    pub fn shard_id(&self) -> &str {
        &self.shard_id
    }

    pub fn payload(&self) -> &CompiledPayload {
        &self.payload
    }

    pub fn compatibility(&self) -> &Compatibility {
        &self.compatibility
    }

    pub fn activation(&self) -> &[ActivationSelector] {
        &self.activation
    }

    pub fn completeness(&self) -> Completeness {
        self.completeness
    }

    pub fn safety(&self) -> &Safety {
        &self.safety
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompiledPayload {
    DeclarationFacts {
        #[serde(default)]
        types: Vec<TypeFact>,
        #[serde(default)]
        members: Vec<MemberFact>,
        #[serde(default)]
        relations: Vec<RelationFact>,
    },
    GeneratorRules {
        rules: Vec<GeneratorRule>,
    },
    ProcedureSummaries {
        summaries: Vec<CompiledProcedureSummary>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledProcedureSummary {
    pub id: String,
    pub model_id: String,
    pub contract_version: u32,
    pub content_sha256: String,
    pub target: CompiledProcedureTarget,
    pub completeness: Completeness,
    pub locations: Vec<CompiledSummaryLocation>,
    pub transfers: Vec<CompiledSummaryTransfer>,
    pub effects: Vec<CompiledSummaryEffect>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledProcedureTarget {
    pub path: String,
    pub symbol: String,
    pub has_receiver: bool,
    pub parameter_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledSummaryLocation {
    pub id: String,
    pub location_kind: CompiledSummaryLocationKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledSummaryLocationKind {
    Capture,
    Heap,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompiledSummaryInput {
    Receiver {},
    Parameter { ordinal: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompiledSummaryOutput {
    NormalReturn {},
    Receiver {},
    Capture { location: String },
    Heap { location: String },
    ExceptionalReturn {},
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledSummaryTransfer {
    pub input: CompiledSummaryInput,
    pub exit_kind: CompiledSummaryExitKind,
    pub output: CompiledSummaryOutput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledSummaryExitKind {
    Normal,
    Exceptional,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompiledSummaryEffect {
    Allocation {
        event: String,
        output: CompiledSummaryOutput,
    },
    Call {
        event: String,
        callee: String,
    },
    Escape {
        event: String,
        input: CompiledSummaryInput,
    },
    UnknownCall {
        event: String,
        input: CompiledSummaryInput,
    },
    UnknownCallBoundary {
        event: String,
    },
    AmbiguousCall {
        event: String,
        input: CompiledSummaryInput,
        candidates: Vec<String>,
    },
}

impl CompiledPayload {
    pub fn payload_kind(&self) -> PayloadKind {
        match self {
            Self::DeclarationFacts { .. } => PayloadKind::DeclarationFacts,
            Self::GeneratorRules { .. } => PayloadKind::GeneratorRules,
            Self::ProcedureSummaries { .. } => PayloadKind::ProcedureSummaries,
        }
    }

    pub fn record_count(&self) -> usize {
        match self {
            Self::DeclarationFacts {
                types,
                members,
                relations,
            } => types.len() + members.len() + relations.len(),
            Self::GeneratorRules { rules } => rules.len(),
            Self::ProcedureSummaries { summaries } => summaries.len(),
        }
    }

    pub fn declaration_facts(&self) -> Option<(&[TypeFact], &[MemberFact], &[RelationFact])> {
        match self {
            Self::DeclarationFacts {
                types,
                members,
                relations,
            } => Some((types, members, relations)),
            Self::GeneratorRules { .. } | Self::ProcedureSummaries { .. } => None,
        }
    }

    pub fn generator_rules(&self) -> Option<&[GeneratorRule]> {
        match self {
            Self::DeclarationFacts { .. } | Self::ProcedureSummaries { .. } => None,
            Self::GeneratorRules { rules } => Some(rules),
        }
    }

    pub fn procedure_summaries(&self) -> Option<&[CompiledProcedureSummary]> {
        match self {
            Self::ProcedureSummaries { summaries } => Some(summaries),
            Self::DeclarationFacts { .. } | Self::GeneratorRules { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCompiledShard {
    schema_version: u32,
    pack_id: String,
    pack_version: String,
    producer: Producer,
    shard_id: String,
    language: String,
    ecosystem: String,
    compatibility: Compatibility,
    activation: Vec<ActivationSelector>,
    provenance: Provenance,
    license: String,
    completeness: Completeness,
    safety: Safety,
    payload: CompiledPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledShardArtifact {
    pub descriptor: CompiledShardDescriptor,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledSemanticModelPack {
    pub manifest: CompiledPackManifest,
    pub manifest_bytes: Vec<u8>,
    pub shards: Vec<CompiledShardArtifact>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeLimits {
    pub max_manifest_bytes: usize,
    pub max_stored_shard_bytes: usize,
    pub max_raw_shard_bytes: usize,
    pub max_total_raw_bytes: u64,
    pub max_shards: usize,
    pub max_records_per_shard: usize,
    pub max_total_records: u64,
    pub max_text_bytes: usize,
    pub max_depth: usize,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_manifest_bytes: 16 * 1024 * 1024,
            max_stored_shard_bytes: 64 * 1024 * 1024,
            max_raw_shard_bytes: 64 * 1024 * 1024,
            max_total_raw_bytes: 1024 * 1024 * 1024,
            max_shards: 4_096,
            max_records_per_shard: 250_000,
            max_total_records: 2_000_000,
            max_text_bytes: 16 * 1024,
            max_depth: 64,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactError {
    LimitExceeded(&'static str),
    InvalidJson(String),
    UnsupportedVersion(u32),
    NonCanonical,
    InvalidDescriptor(String),
    SizeMismatch { expected: u64, actual: u64 },
    DigestMismatch(&'static str),
    SemanticValidation(Vec<Diagnostic>),
    Decompression(String),
    Allocation,
    TrailingCompressedData,
}

impl fmt::Display for ArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitExceeded(limit) => write!(formatter, "artifact exceeds {limit}"),
            Self::InvalidJson(error) => write!(formatter, "invalid artifact JSON: {error}"),
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "unsupported semantic-model schema version {version}"
                )
            }
            Self::NonCanonical => formatter.write_str("artifact bytes are not canonical JSON"),
            Self::InvalidDescriptor(message) => {
                write!(formatter, "invalid shard descriptor: {message}")
            }
            Self::SizeMismatch { expected, actual } => {
                write!(
                    formatter,
                    "size mismatch: expected {expected}, found {actual}"
                )
            }
            Self::DigestMismatch(kind) => write!(formatter, "{kind} digest mismatch"),
            Self::SemanticValidation(diagnostics) => write!(
                formatter,
                "artifact failed semantic validation with {} diagnostic(s)",
                diagnostics.len()
            ),
            Self::Decompression(error) => write!(formatter, "DEFLATE decode failed: {error}"),
            Self::Allocation => formatter.write_str("artifact allocation failed"),
            Self::TrailingCompressedData => {
                formatter.write_str("compressed shard has trailing data")
            }
        }
    }
}

impl std::error::Error for ArtifactError {}

pub fn decode_manifest(
    bytes: &[u8],
    limits: &DecodeLimits,
) -> Result<CompiledPackManifest, ArtifactError> {
    if bytes.len() > limits.max_manifest_bytes {
        return Err(ArtifactError::LimitExceeded("manifest byte limit"));
    }
    let manifest: CompiledPackManifest = serde_json::from_slice(bytes)
        .map_err(|error| ArtifactError::InvalidJson(error.to_string()))?;
    require_version(manifest.schema_version)?;
    if canonical_json(&manifest)? != bytes {
        return Err(ArtifactError::NonCanonical);
    }
    if manifest.shards.len() > limits.max_shards {
        return Err(ArtifactError::LimitExceeded("shard count limit"));
    }
    if validate_identifier(&manifest.pack_id, 256, true).is_err() {
        return Err(ArtifactError::InvalidDescriptor(
            "manifest pack id is invalid".to_owned(),
        ));
    }
    validate_text(&manifest.version, limits, "manifest version")?;
    validate_text(&manifest.producer.name, limits, "manifest producer name")?;
    validate_text(
        &manifest.producer.version,
        limits,
        "manifest producer version",
    )?;
    validate_text(&manifest.language, limits, "manifest language")?;
    validate_text(&manifest.ecosystem, limits, "manifest ecosystem")?;
    validate_text(
        &manifest.compatibility.bifrost,
        limits,
        "manifest Bifrost compatibility",
    )?;
    validate_text(&manifest.provenance.source, limits, "manifest provenance")?;
    if let Some(revision) = &manifest.provenance.revision {
        validate_text(revision, limits, "manifest provenance revision")?;
    }
    validate_text(&manifest.license, limits, "manifest license")?;
    if semver::Version::parse(&manifest.version).is_err()
        || semver::Version::parse(&manifest.producer.version).is_err()
    {
        return Err(ArtifactError::InvalidDescriptor(
            "manifest versions must be semantic versions".to_owned(),
        ));
    }
    if semver::VersionReq::parse(&manifest.compatibility.bifrost).is_err() {
        return Err(ArtifactError::InvalidDescriptor(
            "manifest Bifrost compatibility must be a semantic-version requirement".to_owned(),
        ));
    }
    if spdx::Expression::parse(&manifest.license).is_err() {
        return Err(ArtifactError::InvalidDescriptor(
            "manifest license must be an SPDX expression".to_owned(),
        ));
    }
    if !is_lower_sha256(&manifest.semantic_sha256) || !is_lower_sha256(&manifest.content_sha256) {
        return Err(ArtifactError::InvalidDescriptor(
            "manifest digests must be lowercase SHA-256 hex".to_owned(),
        ));
    }
    if manifest
        .compatibility
        .toolchains
        .windows(2)
        .any(|pair| (&pair[0].name, &pair[0].requirement) >= (&pair[1].name, &pair[1].requirement))
    {
        return Err(ArtifactError::InvalidDescriptor(
            "toolchain constraints must be unique and ascending".to_owned(),
        ));
    }
    for toolchain in &manifest.compatibility.toolchains {
        validate_text(&toolchain.name, limits, "toolchain name")?;
        validate_text(&toolchain.requirement, limits, "toolchain requirement")?;
        if semver::VersionReq::parse(&toolchain.requirement).is_err() {
            return Err(ArtifactError::InvalidDescriptor(
                "toolchain requirements must be semantic-version requirements".to_owned(),
            ));
        }
    }
    if manifest
        .shards
        .windows(2)
        .any(|pair| pair[0].shard_id >= pair[1].shard_id)
    {
        return Err(ArtifactError::InvalidDescriptor(
            "shard descriptors must have unique ascending ids".to_owned(),
        ));
    }
    let mut total_records = 0u64;
    let total_raw = manifest.shards.iter().try_fold(0u64, |total, shard| {
        validate_descriptor(shard, limits)?;
        total_records = total_records
            .checked_add(shard.record_count)
            .ok_or(ArtifactError::LimitExceeded("total record limit"))?;
        total
            .checked_add(shard.raw_size)
            .ok_or(ArtifactError::LimitExceeded("total raw byte limit"))
    })?;
    if total_raw > limits.max_total_raw_bytes {
        return Err(ArtifactError::LimitExceeded("total raw byte limit"));
    }
    if total_records > limits.max_total_records {
        return Err(ArtifactError::LimitExceeded("total record limit"));
    }
    validate_manifest_inventory(&manifest)?;
    if manifest_semantic_digest(&manifest)? != manifest.semantic_sha256 {
        return Err(ArtifactError::DigestMismatch("manifest semantic"));
    }
    if manifest_content_digest(&manifest)? != manifest.content_sha256 {
        return Err(ArtifactError::DigestMismatch("manifest content"));
    }
    Ok(manifest)
}

pub fn decode_shard(
    descriptor: &CompiledShardDescriptor,
    bytes: &[u8],
    limits: &DecodeLimits,
) -> Result<CompiledShard, ArtifactError> {
    validate_descriptor(descriptor, limits)?;
    let actual_stored = u64::try_from(bytes.len())
        .map_err(|_| ArtifactError::LimitExceeded("stored shard byte limit"))?;
    if descriptor.stored_size != actual_stored {
        return Err(ArtifactError::SizeMismatch {
            expected: descriptor.stored_size,
            actual: actual_stored,
        });
    }
    if stored_digest(bytes) != descriptor.stored_sha256 {
        return Err(ArtifactError::DigestMismatch("stored"));
    }

    let raw = match descriptor.encoding {
        ArtifactEncoding::Raw => bytes.to_vec(),
        ArtifactEncoding::Deflate => inflate_bounded(bytes, descriptor.raw_size, limits)?,
    };
    let actual_raw = u64::try_from(raw.len())
        .map_err(|_| ArtifactError::LimitExceeded("raw shard byte limit"))?;
    if descriptor.raw_size != actual_raw {
        return Err(ArtifactError::SizeMismatch {
            expected: descriptor.raw_size,
            actual: actual_raw,
        });
    }
    if content_digest(&raw) != descriptor.content_sha256 {
        return Err(ArtifactError::DigestMismatch("content"));
    }
    let wire: WireCompiledShard = serde_json::from_slice(&raw)
        .map_err(|error| ArtifactError::InvalidJson(error.to_string()))?;
    require_version(wire.schema_version)?;
    if canonical_json(&wire)? != raw {
        return Err(ArtifactError::NonCanonical);
    }
    let authored = authored_pack_from_wire(&wire);
    let diagnostics = validate_pack_locally(
        &authored,
        ValidationLimits {
            max_shards: 1,
            max_records_per_shard: limits.max_records_per_shard,
            max_records_per_pack: usize::try_from(limits.max_total_records).unwrap_or(usize::MAX),
            max_text_bytes: limits.max_text_bytes,
            max_depth: limits.max_depth,
        },
    );
    if !diagnostics.is_empty() {
        return Err(ArtifactError::SemanticValidation(diagnostics));
    }
    validate_compiled_procedure_metadata(&wire, &authored)?;
    if super::compiler::normalize(authored.clone()) != authored {
        return Err(ArtifactError::NonCanonical);
    }
    let shard = compiled_from_wire(wire);
    if shard.shard_id != descriptor.shard_id {
        return Err(ArtifactError::InvalidDescriptor(
            "shard id does not match payload".to_owned(),
        ));
    }
    if shard.payload_kind() != descriptor.payload_kind {
        return Err(ArtifactError::InvalidDescriptor(
            "payload kind does not match payload".to_owned(),
        ));
    }
    if shard.record_count() != usize::try_from(descriptor.record_count).unwrap_or(usize::MAX) {
        return Err(ArtifactError::InvalidDescriptor(
            "record count does not match payload".to_owned(),
        ));
    }
    if routing_keys(&shard.activation, &shard.payload) != descriptor.routing_keys {
        return Err(ArtifactError::InvalidDescriptor(
            "routing keys do not match payload".to_owned(),
        ));
    }
    let (defined_ids, referenced_ids) = payload_inventory(&shard.payload);
    if defined_ids != descriptor.defined_ids || referenced_ids != descriptor.referenced_ids {
        return Err(ArtifactError::InvalidDescriptor(
            "declaration inventory does not match payload".to_owned(),
        ));
    }
    if semantic_digest(&shard)? != descriptor.semantic_sha256 {
        return Err(ArtifactError::DigestMismatch("semantic"));
    }
    Ok(shard)
}

fn validate_compiled_procedure_metadata(
    wire: &WireCompiledShard,
    authored: &AuthoredSemanticModelPack,
) -> Result<(), ArtifactError> {
    let CompiledPayload::ProcedureSummaries { summaries } = &wire.payload else {
        return Ok(());
    };
    let AuthoredPayload::ProcedureSummaries {
        summaries: authored_summaries,
    } = &authored.shards[0].payload
    else {
        return Err(ArtifactError::InvalidDescriptor(
            "compiled procedure payload did not reconstruct as authored procedures".to_owned(),
        ));
    };
    if summaries.len() != authored_summaries.len() {
        return Err(ArtifactError::InvalidDescriptor(
            "compiled procedure record count changed during reconstruction".to_owned(),
        ));
    }
    for (compiled, authored) in summaries.iter().zip(authored_summaries) {
        if compiled.contract_version != PROCEDURE_SUMMARY_CONTRACT_VERSION {
            return Err(ArtifactError::InvalidDescriptor(
                "procedure summary contract version is unsupported".to_owned(),
            ));
        }
        if compiled.model_id != format!("{}#{}", wire.pack_id, compiled.id) {
            return Err(ArtifactError::InvalidDescriptor(
                "procedure summary model id was not derived from the pack and record ids"
                    .to_owned(),
            ));
        }
        if !is_lower_sha256(&compiled.content_sha256)
            || compiled.content_sha256 != content_digest(&canonical_json(authored)?)
        {
            return Err(ArtifactError::InvalidDescriptor(
                "procedure summary content hash is invalid".to_owned(),
            ));
        }
    }
    Ok(())
}

fn compiled_from_wire(wire: WireCompiledShard) -> CompiledShard {
    CompiledShard {
        schema_version: wire.schema_version,
        pack_id: wire.pack_id,
        pack_version: wire.pack_version,
        producer: wire.producer,
        shard_id: wire.shard_id,
        language: wire.language,
        ecosystem: wire.ecosystem,
        compatibility: wire.compatibility,
        activation: wire.activation,
        provenance: wire.provenance,
        license: wire.license,
        completeness: wire.completeness,
        safety: wire.safety,
        payload: wire.payload,
    }
}

pub fn decode_shard_for_manifest(
    manifest: &CompiledPackManifest,
    descriptor: &CompiledShardDescriptor,
    bytes: &[u8],
    limits: &DecodeLimits,
) -> Result<CompiledShard, ArtifactError> {
    validate_manifest_inventory(manifest)?;
    if !manifest
        .shards
        .iter()
        .any(|candidate| candidate == descriptor)
    {
        return Err(ArtifactError::InvalidDescriptor(
            "shard descriptor is not present in manifest".to_owned(),
        ));
    }
    let shard = decode_shard(descriptor, bytes, limits)?;
    if shard.schema_version != manifest.schema_version
        || shard.pack_id != manifest.pack_id
        || shard.pack_version != manifest.version
        || shard.producer != manifest.producer
        || shard.language != manifest.language
        || shard.ecosystem != manifest.ecosystem
        || shard.compatibility != manifest.compatibility
        || shard.provenance != manifest.provenance
        || shard.license != manifest.license
        || shard.completeness != manifest.completeness
        || shard.safety != manifest.safety
    {
        return Err(ArtifactError::InvalidDescriptor(
            "shard envelope does not match manifest".to_owned(),
        ));
    }
    Ok(shard)
}

fn inflate_bounded(
    bytes: &[u8],
    declared_raw_size: u64,
    limits: &DecodeLimits,
) -> Result<Vec<u8>, ArtifactError> {
    if declared_raw_size > limits.max_raw_shard_bytes as u64 {
        return Err(ArtifactError::LimitExceeded("raw shard byte limit"));
    }
    let capacity = usize::try_from(declared_raw_size)
        .map_err(|_| ArtifactError::LimitExceeded("raw shard byte limit"))?;
    let mut decoder = DeflateDecoder::new(Cursor::new(bytes));
    let mut output = Vec::new();
    output
        .try_reserve(capacity.min(16 * 1024))
        .map_err(|_| ArtifactError::Allocation)?;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = decoder
            .read(&mut buffer)
            .map_err(|error| ArtifactError::Decompression(error.to_string()))?;
        if read == 0 {
            break;
        }
        if output.len().saturating_add(read) > capacity
            || output.len().saturating_add(read) > limits.max_raw_shard_bytes
        {
            return Err(ArtifactError::LimitExceeded("raw shard byte limit"));
        }
        output
            .try_reserve(read)
            .map_err(|_| ArtifactError::Allocation)?;
        output.extend_from_slice(&buffer[..read]);
    }
    if decoder.total_in() != bytes.len() as u64 {
        return Err(ArtifactError::TrailingCompressedData);
    }
    Ok(output)
}

fn validate_descriptor(
    descriptor: &CompiledShardDescriptor,
    limits: &DecodeLimits,
) -> Result<(), ArtifactError> {
    if validate_identifier(&descriptor.shard_id, 256, true).is_err() {
        return Err(ArtifactError::InvalidDescriptor(
            "shard id is invalid".to_owned(),
        ));
    }
    if descriptor
        .routing_keys
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err(ArtifactError::InvalidDescriptor(
            "routing keys must be unique and ascending".to_owned(),
        ));
    }
    for (name, ids) in [
        ("defined ids", &descriptor.defined_ids),
        ("referenced ids", &descriptor.referenced_ids),
    ] {
        if ids.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ArtifactError::InvalidDescriptor(format!(
                "{name} must be unique and ascending"
            )));
        }
        if ids.iter().any(|id| !valid_inventory_id(id)) {
            return Err(ArtifactError::InvalidDescriptor(format!(
                "{name} must contain valid stable ids"
            )));
        }
    }
    if descriptor.stored_size > limits.max_stored_shard_bytes as u64 {
        return Err(ArtifactError::LimitExceeded("stored shard byte limit"));
    }
    if descriptor.raw_size > limits.max_raw_shard_bytes as u64 {
        return Err(ArtifactError::LimitExceeded("raw shard byte limit"));
    }
    if descriptor.record_count > limits.max_records_per_shard as u64 {
        return Err(ArtifactError::LimitExceeded("records per shard limit"));
    }
    if descriptor.encoding == ArtifactEncoding::Raw && descriptor.raw_size != descriptor.stored_size
    {
        return Err(ArtifactError::InvalidDescriptor(
            "raw shards must have equal raw and stored sizes".to_owned(),
        ));
    }
    for digest in [
        &descriptor.semantic_sha256,
        &descriptor.content_sha256,
        &descriptor.stored_sha256,
    ] {
        if !is_lower_sha256(digest) {
            return Err(ArtifactError::InvalidDescriptor(
                "digests must be lowercase SHA-256 hex".to_owned(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, ArtifactError> {
    serde_json::to_vec(value).map_err(|error| ArtifactError::InvalidJson(error.to_string()))
}

pub(crate) fn semantic_digest(shard: &CompiledShard) -> Result<String, ArtifactError> {
    #[derive(Serialize)]
    struct SemanticView<'a> {
        schema_version: u32,
        pack_id: &'a str,
        shard_id: &'a str,
        language: &'a str,
        ecosystem: &'a str,
        compatibility: &'a Compatibility,
        activation: &'a [ActivationSelector],
        completeness: Completeness,
        safety: &'a Safety,
        payload: &'a CompiledPayload,
    }
    let bytes = canonical_json(&SemanticView {
        schema_version: shard.schema_version,
        pack_id: &shard.pack_id,
        shard_id: &shard.shard_id,
        language: &shard.language,
        ecosystem: &shard.ecosystem,
        compatibility: &shard.compatibility,
        activation: &shard.activation,
        completeness: shard.completeness,
        safety: &shard.safety,
        payload: &shard.payload,
    })?;
    Ok(digest_hex(SEMANTIC_HASH_DOMAIN, &bytes))
}

pub(crate) fn manifest_semantic_digest(
    manifest: &CompiledPackManifest,
) -> Result<String, ArtifactError> {
    #[derive(Serialize)]
    struct ManifestSemanticView<'a> {
        schema_version: u32,
        pack_id: &'a str,
        version: &'a str,
        language: &'a str,
        ecosystem: &'a str,
        compatibility: &'a Compatibility,
        completeness: Completeness,
        safety: &'a Safety,
        shards: Vec<(&'a str, &'a str)>,
    }
    let bytes = canonical_json(&ManifestSemanticView {
        schema_version: manifest.schema_version,
        pack_id: &manifest.pack_id,
        version: &manifest.version,
        language: &manifest.language,
        ecosystem: &manifest.ecosystem,
        compatibility: &manifest.compatibility,
        completeness: manifest.completeness,
        safety: &manifest.safety,
        shards: manifest
            .shards
            .iter()
            .map(|shard| (shard.shard_id.as_str(), shard.semantic_sha256.as_str()))
            .collect(),
    })?;
    Ok(digest_hex(MANIFEST_HASH_DOMAIN, &bytes))
}

pub(crate) fn manifest_content_digest(
    manifest: &CompiledPackManifest,
) -> Result<String, ArtifactError> {
    #[derive(Serialize)]
    struct ManifestContentView<'a> {
        schema_version: u32,
        pack_id: &'a str,
        version: &'a str,
        producer: &'a Producer,
        language: &'a str,
        ecosystem: &'a str,
        compatibility: &'a Compatibility,
        provenance: &'a Provenance,
        license: &'a str,
        completeness: Completeness,
        safety: &'a Safety,
        semantic_sha256: &'a str,
        shards: &'a [CompiledShardDescriptor],
    }
    let bytes = canonical_json(&ManifestContentView {
        schema_version: manifest.schema_version,
        pack_id: &manifest.pack_id,
        version: &manifest.version,
        producer: &manifest.producer,
        language: &manifest.language,
        ecosystem: &manifest.ecosystem,
        compatibility: &manifest.compatibility,
        provenance: &manifest.provenance,
        license: &manifest.license,
        completeness: manifest.completeness,
        safety: &manifest.safety,
        semantic_sha256: &manifest.semantic_sha256,
        shards: &manifest.shards,
    })?;
    Ok(content_digest(&bytes))
}

pub(crate) fn content_digest(bytes: &[u8]) -> String {
    lower_hex_string(&sha256_bytes(bytes))
}

pub(crate) fn stored_digest(bytes: &[u8]) -> String {
    lower_hex_string(&sha256_bytes(bytes))
}

pub(crate) fn routing_keys(
    selectors: &[ActivationSelector],
    payload: &CompiledPayload,
) -> Vec<String> {
    let mut keys = Vec::new();
    for selector in selectors {
        for (prefix, selected) in [
            ("package", selector.package.as_ref()),
            ("module", selector.module.as_ref()),
            ("toolchain", selector.toolchain.as_ref()),
        ] {
            if let Some(selected) = selected {
                keys.push(format!("{prefix}:{}", selected.name));
            }
        }
    }
    if let CompiledPayload::GeneratorRules { rules } = payload {
        for rule in rules {
            let kind = match rule.trigger {
                RuleTrigger::LanguageConstruct { .. } => "language_construct",
                RuleTrigger::Annotation { .. } => "annotation",
                RuleTrigger::AnnotatedField { .. } => "annotated_field",
                RuleTrigger::MacroInvocation { .. } => "macro_invocation",
                RuleTrigger::GeneratorInvocation { .. } => "generator_invocation",
                RuleTrigger::ResolvedOwner { .. } => "resolved_owner",
                RuleTrigger::ResolvedCall { .. } => "resolved_call",
            };
            keys.push(format!("trigger:{kind}"));
        }
    }
    if matches!(payload, CompiledPayload::ProcedureSummaries { .. }) {
        keys.push("payload:procedure_summaries".to_owned());
    }
    keys.sort_unstable();
    keys.dedup();
    keys
}

pub(crate) fn payload_inventory(payload: &CompiledPayload) -> (Vec<String>, Vec<String>) {
    let mut defined = HashSet::new();
    let mut referenced = HashSet::new();
    match payload {
        CompiledPayload::DeclarationFacts {
            types,
            members,
            relations,
        } => {
            for fact in types {
                defined.insert(fact.id.clone());
                for hierarchy in &fact.hierarchy {
                    collect_declared_type_refs(&hierarchy.target, &mut referenced);
                }
                for constraint in &fact.type_parameter_constraints {
                    for type_ref in &constraint.constraint.referenced_types {
                        collect_declared_type_refs(type_ref, &mut referenced);
                    }
                }
                if let Some(underlying) = &fact.underlying_type {
                    for type_ref in &underlying.referenced_types {
                        collect_declared_type_refs(type_ref, &mut referenced);
                    }
                }
                for embedded in &fact.embedded_types {
                    collect_declared_type_refs(&embedded.target, &mut referenced);
                }
            }
            for fact in members {
                defined.insert(fact.id.clone());
                referenced.insert(fact.owner.clone());
                if let Some(signature) = &fact.signature {
                    for parameter in &signature.parameters {
                        collect_declared_type_refs(&parameter.r#type, &mut referenced);
                    }
                    if let Some(returns) = &signature.returns {
                        collect_declared_type_refs(returns, &mut referenced);
                    }
                }
            }
            for relation in relations {
                referenced.insert(relation.from.clone());
                referenced.insert(relation.to.clone());
            }
        }
        CompiledPayload::ProcedureSummaries { summaries } => {
            for summary in summaries {
                defined.insert(format!("{PROCEDURE_ID_INVENTORY_PREFIX}{}", summary.id));
                defined.insert(procedure_target_inventory_id(&summary.target));
                for effect in &summary.effects {
                    match effect {
                        CompiledSummaryEffect::Call { callee, .. } => {
                            referenced.insert(format!("{PROCEDURE_ID_INVENTORY_PREFIX}{callee}"));
                        }
                        CompiledSummaryEffect::AmbiguousCall { candidates, .. } => {
                            referenced.extend(candidates.iter().map(|candidate| {
                                format!("{PROCEDURE_ID_INVENTORY_PREFIX}{candidate}")
                            }));
                        }
                        CompiledSummaryEffect::Allocation { .. }
                        | CompiledSummaryEffect::Escape { .. }
                        | CompiledSummaryEffect::UnknownCall { .. }
                        | CompiledSummaryEffect::UnknownCallBoundary { .. } => {}
                    }
                }
            }
        }
        CompiledPayload::GeneratorRules { .. } => {}
    }
    let mut defined: Vec<_> = defined.into_iter().collect();
    let mut referenced: Vec<_> = referenced.into_iter().collect();
    defined.sort_unstable();
    referenced.sort_unstable();
    (defined, referenced)
}

fn procedure_target_inventory_id(target: &CompiledProcedureTarget) -> String {
    let bytes = canonical_json(&(target.path.as_str(), target.symbol.as_str()))
        .expect("procedure target identity is JSON serializable");
    format!(
        "{PROCEDURE_TARGET_INVENTORY_PREFIX}{}",
        digest_hex(PROCEDURE_TARGET_HASH_DOMAIN, &bytes)
    )
}

fn valid_inventory_id(id: &str) -> bool {
    if let Some(procedure_id) = id.strip_prefix(PROCEDURE_ID_INVENTORY_PREFIX) {
        validate_identifier(procedure_id, 256, true).is_ok()
    } else if let Some(target_digest) = id.strip_prefix(PROCEDURE_TARGET_INVENTORY_PREFIX) {
        is_lower_sha256(target_digest)
    } else {
        validate_identifier(id, 256, true).is_ok()
    }
}

fn collect_declared_type_refs(root: &TypeRef, ids: &mut HashSet<String>) {
    let mut stack = vec![root];
    while let Some(reference) = stack.pop() {
        match reference {
            TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. } => {
                if let TypeRef::Declared { id, .. } = reference {
                    ids.insert(id.clone());
                }
                stack.extend(arguments);
            }
            TypeRef::Array { element }
            | TypeRef::ByRef { element }
            | TypeRef::Pointer { element }
            | TypeRef::Slice { element }
            | TypeRef::FixedArray { element, .. }
            | TypeRef::Channel { element, .. } => stack.push(element),
            TypeRef::Map { key, value } => {
                stack.push(key);
                stack.push(value);
            }
            TypeRef::Wildcard { bound, .. } => stack.extend(bound.as_deref()),
            TypeRef::Tuple { elements } => stack.extend(elements),
            TypeRef::Function { parameters, result } => {
                stack.extend(result.as_deref());
                stack.extend(parameters.iter().map(|parameter| &parameter.r#type));
            }
            TypeRef::TypeParameter { .. } => {}
        }
    }
}

fn authored_pack_from_wire(shard: &WireCompiledShard) -> AuthoredSemanticModelPack {
    AuthoredSemanticModelPack {
        schema_version: shard.schema_version,
        pack_id: shard.pack_id.clone(),
        version: shard.pack_version.clone(),
        producer: shard.producer.clone(),
        language: shard.language.clone(),
        ecosystem: shard.ecosystem.clone(),
        compatibility: shard.compatibility.clone(),
        provenance: shard.provenance.clone(),
        license: shard.license.clone(),
        completeness: shard.completeness,
        safety: shard.safety.clone(),
        shards: vec![AuthoredShard {
            id: shard.shard_id.clone(),
            activation: shard.activation.clone(),
            payload: authored_payload_from_compiled(&shard.payload),
        }],
    }
}

fn authored_payload_from_compiled(payload: &CompiledPayload) -> AuthoredPayload {
    match payload {
        CompiledPayload::DeclarationFacts {
            types,
            members,
            relations,
        } => AuthoredPayload::DeclarationFacts {
            types: types.clone(),
            members: members.clone(),
            relations: relations.clone(),
        },
        CompiledPayload::GeneratorRules { rules } => AuthoredPayload::GeneratorRules {
            rules: rules.clone(),
        },
        CompiledPayload::ProcedureSummaries { summaries } => AuthoredPayload::ProcedureSummaries {
            summaries: summaries
                .iter()
                .map(authored_procedure_summary_from_compiled)
                .collect(),
        },
    }
}

fn authored_procedure_summary_from_compiled(
    summary: &CompiledProcedureSummary,
) -> AuthoredProcedureSummary {
    AuthoredProcedureSummary {
        id: summary.id.clone(),
        target: AuthoredProcedureTarget {
            path: summary.target.path.clone(),
            symbol: summary.target.symbol.clone(),
            has_receiver: summary.target.has_receiver,
            parameter_count: summary.target.parameter_count,
        },
        completeness: summary.completeness,
        locations: summary
            .locations
            .iter()
            .map(|location| AuthoredSummaryLocation {
                id: location.id.clone(),
                location_kind: match location.location_kind {
                    CompiledSummaryLocationKind::Capture => AuthoredSummaryLocationKind::Capture,
                    CompiledSummaryLocationKind::Heap => AuthoredSummaryLocationKind::Heap,
                },
            })
            .collect(),
        transfers: summary
            .transfers
            .iter()
            .map(|transfer| AuthoredSummaryTransfer {
                input: authored_summary_input_from_compiled(&transfer.input),
                exit_kind: match transfer.exit_kind {
                    CompiledSummaryExitKind::Normal => AuthoredSummaryExitKind::Normal,
                    CompiledSummaryExitKind::Exceptional => AuthoredSummaryExitKind::Exceptional,
                },
                output: authored_summary_output_from_compiled(&transfer.output),
            })
            .collect(),
        effects: summary
            .effects
            .iter()
            .map(authored_summary_effect_from_compiled)
            .collect(),
    }
}

fn authored_summary_input_from_compiled(input: &CompiledSummaryInput) -> AuthoredSummaryInput {
    match input {
        CompiledSummaryInput::Receiver {} => AuthoredSummaryInput::Receiver {},
        CompiledSummaryInput::Parameter { ordinal } => {
            AuthoredSummaryInput::Parameter { ordinal: *ordinal }
        }
    }
}

fn authored_summary_output_from_compiled(output: &CompiledSummaryOutput) -> AuthoredSummaryOutput {
    match output {
        CompiledSummaryOutput::NormalReturn {} => AuthoredSummaryOutput::NormalReturn {},
        CompiledSummaryOutput::Receiver {} => AuthoredSummaryOutput::Receiver {},
        CompiledSummaryOutput::Capture { location } => AuthoredSummaryOutput::Capture {
            location: location.clone(),
        },
        CompiledSummaryOutput::Heap { location } => AuthoredSummaryOutput::Heap {
            location: location.clone(),
        },
        CompiledSummaryOutput::ExceptionalReturn {} => AuthoredSummaryOutput::ExceptionalReturn {},
    }
}

fn authored_summary_effect_from_compiled(effect: &CompiledSummaryEffect) -> AuthoredSummaryEffect {
    match effect {
        CompiledSummaryEffect::Allocation { event, output } => AuthoredSummaryEffect::Allocation {
            event: event.clone(),
            output: authored_summary_output_from_compiled(output),
        },
        CompiledSummaryEffect::Call { event, callee } => AuthoredSummaryEffect::Call {
            event: event.clone(),
            callee: callee.clone(),
        },
        CompiledSummaryEffect::Escape { event, input } => AuthoredSummaryEffect::Escape {
            event: event.clone(),
            input: authored_summary_input_from_compiled(input),
        },
        CompiledSummaryEffect::UnknownCall { event, input } => AuthoredSummaryEffect::UnknownCall {
            event: event.clone(),
            input: authored_summary_input_from_compiled(input),
        },
        CompiledSummaryEffect::UnknownCallBoundary { event } => {
            AuthoredSummaryEffect::UnknownCallBoundary {
                event: event.clone(),
            }
        }
        CompiledSummaryEffect::AmbiguousCall {
            event,
            input,
            candidates,
        } => AuthoredSummaryEffect::AmbiguousCall {
            event: event.clone(),
            input: authored_summary_input_from_compiled(input),
            candidates: candidates.clone(),
        },
    }
}

fn validate_manifest_inventory(manifest: &CompiledPackManifest) -> Result<(), ArtifactError> {
    let mut definitions = HashSet::new();
    let mut record_ids = HashSet::new();
    for descriptor in &manifest.shards {
        for id in &descriptor.defined_ids {
            if !definitions.insert(id) {
                return Err(ArtifactError::InvalidDescriptor(format!(
                    "payload record id `{id}` is defined more than once"
                )));
            }
            let record_id =
                if let Some(procedure_id) = id.strip_prefix(PROCEDURE_ID_INVENTORY_PREFIX) {
                    Some(procedure_id)
                } else if id.starts_with(PROCEDURE_TARGET_INVENTORY_PREFIX) {
                    None
                } else {
                    Some(id.as_str())
                };
            if let Some(record_id) = record_id
                && !record_ids.insert(record_id)
            {
                return Err(ArtifactError::InvalidDescriptor(format!(
                    "payload record id `{record_id}` is defined more than once"
                )));
            }
        }
    }
    for descriptor in &manifest.shards {
        for id in &descriptor.referenced_ids {
            if !definitions.contains(id) {
                return Err(ArtifactError::InvalidDescriptor(format!(
                    "payload record id `{id}` is referenced but not defined"
                )));
            }
        }
    }
    Ok(())
}

fn validate_text(
    value: &str,
    limits: &DecodeLimits,
    field: &'static str,
) -> Result<(), ArtifactError> {
    if value.is_empty() || value.len() > limits.max_text_bytes || value.contains('\0') {
        return Err(ArtifactError::InvalidDescriptor(format!(
            "{field} is empty, too long, or contains NUL"
        )));
    }
    Ok(())
}

fn require_version(version: u32) -> Result<(), ArtifactError> {
    if version == SEMANTIC_MODEL_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(ArtifactError::UnsupportedVersion(version))
    }
}

fn digest_hex(domain: &[u8], bytes: &[u8]) -> String {
    lower_hex_string(&hash_domain_bytes(domain, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic_model::{
        CompilerOptions, CompressionPolicy, SourceFormat, compile_pack, compile_source,
    };
    use flate2::Compression;
    use flate2::write::DeflateEncoder;
    use std::io::Write;

    const DECLARATIONS: &[u8] =
        include_bytes!("../../../testdata/semantic-model-packs/declarations-v1.json");
    const PROCEDURE_SUMMARIES: &[u8] =
        include_bytes!("../../../testdata/semantic-model-packs/procedure-summaries-v1.json");

    #[test]
    fn shard_decoder_rejects_noncanonical_json_with_valid_digests() {
        let compiled = compile_source(
            SourceFormat::Json,
            DECLARATIONS,
            &CompilerOptions {
                compression: CompressionPolicy::AlwaysRaw,
                ..CompilerOptions::default()
            },
        )
        .unwrap();
        let artifact = &compiled.shards[0];
        let shard = decode_shard(
            &artifact.descriptor,
            &artifact.bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        let raw = serde_json::to_vec_pretty(&shard).unwrap();
        let mut descriptor = artifact.descriptor.clone();
        descriptor.raw_size = raw.len() as u64;
        descriptor.stored_size = raw.len() as u64;
        descriptor.content_sha256 = content_digest(&raw);
        descriptor.stored_sha256 = stored_digest(&raw);

        assert_eq!(
            decode_shard(&descriptor, &raw, &DecodeLimits::default()).unwrap_err(),
            ArtifactError::NonCanonical
        );
    }

    #[test]
    fn shard_decoder_rejects_trailing_deflate_data_with_valid_stored_digest() {
        let raw = b"{}";
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::new(6));
        encoder.write_all(raw).unwrap();
        let mut stored = encoder.finish().unwrap();
        stored.extend_from_slice(b"trailing");
        let descriptor = descriptor_for_test(raw, &stored, raw.len() as u64);

        assert_eq!(
            decode_shard(&descriptor, &stored, &DecodeLimits::default()).unwrap_err(),
            ArtifactError::TrailingCompressedData
        );
    }

    #[test]
    fn shard_decoder_stops_excessive_expansion_at_declared_size() {
        let raw = vec![0u8; 4096];
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::new(6));
        encoder.write_all(&raw).unwrap();
        let stored = encoder.finish().unwrap();
        let descriptor = descriptor_for_test(&raw, &stored, 32);

        assert_eq!(
            decode_shard(&descriptor, &stored, &DecodeLimits::default()).unwrap_err(),
            ArtifactError::LimitExceeded("raw shard byte limit")
        );
    }

    #[test]
    fn manifest_decoder_binds_metadata_and_total_record_limit() {
        let compiled = compile_source(
            SourceFormat::Json,
            DECLARATIONS,
            &CompilerOptions::default(),
        )
        .unwrap();
        let mut tampered = compiled.manifest.clone();
        tampered.provenance.source = "https://mirror.example/widget.jar".to_owned();
        let bytes = canonical_json(&tampered).unwrap();
        assert_eq!(
            decode_manifest(&bytes, &DecodeLimits::default()).unwrap_err(),
            ArtifactError::DigestMismatch("manifest content")
        );

        let limits = DecodeLimits {
            max_total_records: 2,
            ..DecodeLimits::default()
        };
        assert_eq!(
            decode_manifest(&compiled.manifest_bytes, &limits).unwrap_err(),
            ArtifactError::LimitExceeded("total record limit")
        );
    }

    #[test]
    fn shard_decoder_rejects_rehashed_semantically_invalid_payload() {
        let compiled = compile_source(
            SourceFormat::Json,
            DECLARATIONS,
            &CompilerOptions {
                compression: CompressionPolicy::AlwaysRaw,
                ..CompilerOptions::default()
            },
        )
        .unwrap();
        let artifact = &compiled.shards[0];
        let mut wire: WireCompiledShard = serde_json::from_slice(&artifact.bytes).unwrap();
        let CompiledPayload::DeclarationFacts { types, .. } = &mut wire.payload else {
            unreachable!()
        };
        types[0].aliases.push("invalid alias".to_owned());
        let (descriptor, raw) = rehash_raw_descriptor(&artifact.descriptor, &wire);

        assert!(matches!(
            decode_shard(&descriptor, &raw, &DecodeLimits::default()),
            Err(ArtifactError::SemanticValidation(_))
        ));
    }

    #[test]
    fn shard_decoder_rejects_rehashed_procedure_metadata_tampering() {
        let compiled = compile_source(
            SourceFormat::Json,
            PROCEDURE_SUMMARIES,
            &CompilerOptions {
                compression: CompressionPolicy::AlwaysRaw,
                ..CompilerOptions::default()
            },
        )
        .unwrap();
        let artifact = &compiled.shards[0];
        let mut wire: WireCompiledShard = serde_json::from_slice(&artifact.bytes).unwrap();
        let CompiledPayload::ProcedureSummaries { summaries } = &mut wire.payload else {
            unreachable!()
        };
        summaries[0].model_id = "acme.procedure-summaries#summary.forged".to_owned();
        let (descriptor, raw) = rehash_raw_descriptor(&artifact.descriptor, &wire);

        let error = decode_shard(&descriptor, &raw, &DecodeLimits::default()).unwrap_err();
        assert!(
            matches!(
                &error,
                ArtifactError::InvalidDescriptor(message)
                    if message.contains("procedure summary model id")
            ),
            "unexpected decoder error: {error:?}"
        );
    }

    #[test]
    fn manifest_bound_decoder_rejects_rehashed_unbound_procedure_callee() {
        let compiled = compile_source(
            SourceFormat::Json,
            PROCEDURE_SUMMARIES,
            &CompilerOptions {
                compression: CompressionPolicy::AlwaysRaw,
                ..CompilerOptions::default()
            },
        )
        .unwrap();
        let artifact = &compiled.shards[0];
        let mut wire: WireCompiledShard = serde_json::from_slice(&artifact.bytes).unwrap();
        let CompiledPayload::ProcedureSummaries { summaries } = &mut wire.payload else {
            unreachable!()
        };
        let callee = summaries[1]
            .effects
            .iter_mut()
            .find_map(|effect| match effect {
                CompiledSummaryEffect::Call { callee, .. } => Some(callee),
                _ => None,
            })
            .expect("fixture contains an exact call effect");
        *callee = "summary.missing".to_owned();
        summaries[1].content_sha256 = content_digest(
            &canonical_json(&authored_procedure_summary_from_compiled(&summaries[1])).unwrap(),
        );
        let (descriptor, raw) = rehash_raw_descriptor(&artifact.descriptor, &wire);
        let mut manifest = compiled.manifest.clone();
        manifest.shards[0] = descriptor.clone();

        assert!(matches!(
            decode_shard_for_manifest(&manifest, &descriptor, &raw, &DecodeLimits::default()),
            Err(ArtifactError::InvalidDescriptor(message))
                if message.contains("summary.missing")
        ));
    }

    #[test]
    fn manifest_inventory_keeps_declaration_and_procedure_namespaces_distinct() {
        let declaration_pack = compile_source(
            SourceFormat::Json,
            DECLARATIONS,
            &CompilerOptions::default(),
        )
        .unwrap();
        let mut manifest = declaration_pack.manifest.clone();
        let mut procedure_descriptor = declaration_pack.manifest.shards[0].clone();
        procedure_descriptor.shard_id = "summaries.forged".to_owned();
        procedure_descriptor.defined_ids.clear();
        procedure_descriptor.referenced_ids = vec!["procedure:type.widget".to_owned()];
        manifest.shards.push(procedure_descriptor);

        assert!(matches!(
            validate_manifest_inventory(&manifest),
            Err(ArtifactError::InvalidDescriptor(message))
                if message.contains("procedure:type.widget")
        ));
    }

    #[test]
    fn manifest_inventory_rejects_duplicate_procedure_targets_across_shards() {
        let compiled = compile_source(
            SourceFormat::Json,
            PROCEDURE_SUMMARIES,
            &CompilerOptions::default(),
        )
        .unwrap();
        let target_id = compiled.manifest.shards[0]
            .defined_ids
            .iter()
            .find(|id| id.starts_with(PROCEDURE_TARGET_INVENTORY_PREFIX))
            .unwrap()
            .clone();
        let mut first = compiled.manifest.shards[0].clone();
        first.defined_ids = vec![target_id.clone()];
        first.referenced_ids.clear();
        let mut second = first.clone();
        second.shard_id = "summaries.duplicate-target".to_owned();
        let mut manifest = compiled.manifest.clone();
        manifest.shards = vec![first, second];

        assert!(matches!(
            validate_manifest_inventory(&manifest),
            Err(ArtifactError::InvalidDescriptor(message))
                if message.contains(&target_id)
        ));
    }

    #[test]
    fn shard_decoder_rejects_rehashed_semantic_set_reordering() {
        let mut authored: AuthoredSemanticModelPack = serde_json::from_slice(DECLARATIONS).unwrap();
        let AuthoredPayload::DeclarationFacts { types, .. } = &mut authored.shards[0].payload
        else {
            unreachable!()
        };
        types[0]
            .aliases
            .extend(["com.acme.Alpha".to_owned(), "com.acme.Zeta".to_owned()]);
        let compiled = compile_pack(
            &authored,
            &CompilerOptions {
                compression: CompressionPolicy::AlwaysRaw,
                ..CompilerOptions::default()
            },
        )
        .unwrap();
        let artifact = &compiled.shards[0];
        let mut wire: WireCompiledShard = serde_json::from_slice(&artifact.bytes).unwrap();
        let CompiledPayload::DeclarationFacts { types, .. } = &mut wire.payload else {
            unreachable!()
        };
        types[0].aliases.reverse();
        let (descriptor, raw) = rehash_raw_descriptor(&artifact.descriptor, &wire);

        assert_eq!(
            decode_shard(&descriptor, &raw, &DecodeLimits::default()).unwrap_err(),
            ArtifactError::NonCanonical
        );
    }

    #[test]
    fn manifest_bound_decoder_rejects_a_different_envelope() {
        let compiled = compile_source(
            SourceFormat::Json,
            DECLARATIONS,
            &CompilerOptions::default(),
        )
        .unwrap();
        let mut manifest = compiled.manifest.clone();
        manifest.producer.name = "other-producer".to_owned();
        manifest.content_sha256 = manifest_content_digest(&manifest).unwrap();
        let artifact = &compiled.shards[0];

        assert!(matches!(
            decode_shard_for_manifest(
                &manifest,
                &artifact.descriptor,
                &artifact.bytes,
                &DecodeLimits::default()
            ),
            Err(ArtifactError::InvalidDescriptor(message))
                if message == "shard envelope does not match manifest"
        ));
    }

    fn rehash_raw_descriptor(
        descriptor: &CompiledShardDescriptor,
        wire: &WireCompiledShard,
    ) -> (CompiledShardDescriptor, Vec<u8>) {
        let raw = canonical_json(wire).unwrap();
        let shard = compiled_from_wire(wire.clone());
        let mut descriptor = descriptor.clone();
        descriptor.encoding = ArtifactEncoding::Raw;
        descriptor.raw_size = raw.len() as u64;
        descriptor.stored_size = raw.len() as u64;
        descriptor.semantic_sha256 = semantic_digest(&shard).unwrap();
        descriptor.content_sha256 = content_digest(&raw);
        descriptor.stored_sha256 = stored_digest(&raw);
        (descriptor.defined_ids, descriptor.referenced_ids) = payload_inventory(&wire.payload);
        (descriptor, raw)
    }

    fn descriptor_for_test(
        raw: &[u8],
        stored: &[u8],
        declared_raw_size: u64,
    ) -> CompiledShardDescriptor {
        CompiledShardDescriptor {
            shard_id: "test.shard".to_owned(),
            payload_kind: PayloadKind::DeclarationFacts,
            routing_keys: Vec::new(),
            encoding: ArtifactEncoding::Deflate,
            raw_size: declared_raw_size,
            stored_size: stored.len() as u64,
            record_count: 0,
            defined_ids: Vec::new(),
            referenced_ids: Vec::new(),
            semantic_sha256: "0".repeat(64),
            content_sha256: content_digest(raw),
            stored_sha256: stored_digest(stored),
        }
    }
}
