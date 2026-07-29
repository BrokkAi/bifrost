use super::model::*;
use crate::analyzer::canonical_hash::hash_domain_bytes;
use crate::analyzer::identifier::validate_identifier;
use flate2::bufread::DeflateDecoder;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::{Cursor, Read};

const MANIFEST_HASH_DOMAIN: &[u8] = b"bifrost.semantic-model.manifest.v1";
const SEMANTIC_HASH_DOMAIN: &[u8] = b"bifrost.semantic-model.shard.semantic.v1";
const CONTENT_HASH_DOMAIN: &[u8] = b"bifrost.semantic-model.shard.content.v1";
const STORED_HASH_DOMAIN: &[u8] = b"bifrost.semantic-model.shard.stored.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadKind {
    DeclarationFacts,
    GeneratorRules,
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
    pub shards: Vec<CompiledShardDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledShard {
    pub schema_version: u32,
    pub pack_id: String,
    pub pack_version: String,
    pub producer: Producer,
    pub shard_id: String,
    pub language: String,
    pub ecosystem: String,
    pub compatibility: Compatibility,
    pub activation: Vec<ActivationSelector>,
    pub provenance: Provenance,
    pub license: String,
    pub completeness: Completeness,
    pub safety: Safety,
    pub payload: AuthoredPayload,
}

impl CompiledShard {
    pub fn payload_kind(&self) -> PayloadKind {
        match self.payload {
            AuthoredPayload::DeclarationFacts { .. } => PayloadKind::DeclarationFacts,
            AuthoredPayload::GeneratorRules { .. } => PayloadKind::GeneratorRules,
        }
    }

    pub fn record_count(&self) -> usize {
        self.payload.record_count()
    }
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
    Decompression(String),
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
            Self::Decompression(error) => write!(formatter, "DEFLATE decode failed: {error}"),
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
    if semver::Version::parse(&manifest.version).is_err()
        || semver::Version::parse(&manifest.producer.version).is_err()
    {
        return Err(ArtifactError::InvalidDescriptor(
            "manifest versions must be semantic versions".to_owned(),
        ));
    }
    if spdx::Expression::parse(&manifest.license).is_err() {
        return Err(ArtifactError::InvalidDescriptor(
            "manifest license must be an SPDX expression".to_owned(),
        ));
    }
    if !is_sha256(&manifest.semantic_sha256) {
        return Err(ArtifactError::InvalidDescriptor(
            "manifest semantic digest must be lowercase SHA-256 hex".to_owned(),
        ));
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
    let total_raw = manifest.shards.iter().try_fold(0u64, |total, shard| {
        validate_descriptor(shard, limits)?;
        total
            .checked_add(shard.raw_size)
            .ok_or(ArtifactError::LimitExceeded("total raw byte limit"))
    })?;
    if total_raw > limits.max_total_raw_bytes {
        return Err(ArtifactError::LimitExceeded("total raw byte limit"));
    }
    if manifest_semantic_digest(&manifest)? != manifest.semantic_sha256 {
        return Err(ArtifactError::DigestMismatch("manifest semantic"));
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
    if digest_hex(STORED_HASH_DOMAIN, bytes) != descriptor.stored_sha256 {
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
    if digest_hex(CONTENT_HASH_DOMAIN, &raw) != descriptor.content_sha256 {
        return Err(ArtifactError::DigestMismatch("content"));
    }
    let shard: CompiledShard = serde_json::from_slice(&raw)
        .map_err(|error| ArtifactError::InvalidJson(error.to_string()))?;
    require_version(shard.schema_version)?;
    if canonical_json(&shard)? != raw {
        return Err(ArtifactError::NonCanonical);
    }
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
    if semantic_digest(&shard)? != descriptor.semantic_sha256 {
        return Err(ArtifactError::DigestMismatch("semantic"));
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
    let mut output = Vec::with_capacity(capacity);
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
        if !is_sha256(digest) {
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
        payload: &'a AuthoredPayload,
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

pub(crate) fn content_digest(bytes: &[u8]) -> String {
    digest_hex(CONTENT_HASH_DOMAIN, bytes)
}

pub(crate) fn stored_digest(bytes: &[u8]) -> String {
    digest_hex(STORED_HASH_DOMAIN, bytes)
}

pub(crate) fn routing_keys(
    selectors: &[ActivationSelector],
    payload: &AuthoredPayload,
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
    if let AuthoredPayload::GeneratorRules { rules } = payload {
        for rule in rules {
            let kind = match rule.trigger {
                RuleTrigger::LanguageConstruct { .. } => "language_construct",
                RuleTrigger::Annotation { .. } => "annotation",
                RuleTrigger::MacroInvocation { .. } => "macro_invocation",
                RuleTrigger::GeneratorInvocation { .. } => "generator_invocation",
                RuleTrigger::ResolvedOwner { .. } => "resolved_owner",
                RuleTrigger::ResolvedCall { .. } => "resolved_call",
            };
            keys.push(format!("trigger:{kind}"));
        }
    }
    keys.sort_unstable();
    keys.dedup();
    keys
}

fn require_version(version: u32) -> Result<(), ArtifactError> {
    if version == SEMANTIC_MODEL_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(ArtifactError::UnsupportedVersion(version))
    }
}

fn digest_hex(domain: &[u8], bytes: &[u8]) -> String {
    let digest = hash_domain_bytes(domain, bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic_model::{
        CompilerOptions, CompressionPolicy, SourceFormat, compile_source,
    };
    use flate2::Compression;
    use flate2::write::DeflateEncoder;
    use std::io::Write;

    const DECLARATIONS: &[u8] =
        include_bytes!("../../../tests/fixtures/semantic-model-packs/declarations-v1.json");

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
            semantic_sha256: "0".repeat(64),
            content_sha256: content_digest(raw),
            stored_sha256: stored_digest(stored),
        }
    }
}
