use super::artifact::{
    ArtifactEncoding, ArtifactError, CompiledPackManifest, CompiledPayload,
    CompiledSemanticModelPack, CompiledShard, CompiledShardArtifact, CompiledShardDescriptor,
    DecodeLimits, canonical_json, content_digest, declaration_inventory, manifest_content_digest,
    manifest_semantic_digest, routing_keys, semantic_digest, stored_digest,
};
use super::model::*;
use super::source::{SourceFormat, parse_source};
use super::validate::{Diagnostic, ValidationLimits, validate_pack};
use flate2::Compression;
use flate2::write::DeflateEncoder;
use std::io::Write;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionPolicy {
    Automatic,
    AlwaysRaw,
    AlwaysDeflate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompilerOptions {
    pub max_source_bytes: usize,
    pub max_manifest_bytes: usize,
    pub max_stored_shard_bytes: usize,
    pub max_raw_shard_bytes: usize,
    pub max_total_raw_bytes: u64,
    pub max_shards: usize,
    pub max_records_per_shard: usize,
    pub max_records_per_pack: usize,
    pub max_text_bytes: usize,
    pub max_depth: usize,
    pub compression: CompressionPolicy,
}

impl Default for CompilerOptions {
    fn default() -> Self {
        let decode_limits = DecodeLimits::default();
        Self {
            max_source_bytes: 64 * 1024 * 1024,
            max_manifest_bytes: decode_limits.max_manifest_bytes,
            max_stored_shard_bytes: decode_limits.max_stored_shard_bytes,
            max_raw_shard_bytes: decode_limits.max_raw_shard_bytes,
            max_total_raw_bytes: decode_limits.max_total_raw_bytes,
            max_shards: decode_limits.max_shards,
            max_records_per_shard: decode_limits.max_records_per_shard,
            max_records_per_pack: decode_limits.max_total_records as usize,
            max_text_bytes: decode_limits.max_text_bytes,
            max_depth: decode_limits.max_depth,
            compression: CompressionPolicy::Automatic,
        }
    }
}

pub fn compile_source(
    format: SourceFormat,
    bytes: &[u8],
    options: &CompilerOptions,
) -> Result<CompiledSemanticModelPack, Vec<Diagnostic>> {
    if bytes.len() > options.max_source_bytes {
        return Err(vec![Diagnostic::error(
            "limit.source_bytes",
            "$",
            format!("source exceeds {} bytes", options.max_source_bytes),
        )]);
    }
    let pack = parse_source(format, bytes)?;
    compile_pack(&pack, options)
}

pub fn compile_pack(
    pack: &AuthoredSemanticModelPack,
    options: &CompilerOptions,
) -> Result<CompiledSemanticModelPack, Vec<Diagnostic>> {
    let limits = ValidationLimits {
        max_shards: options.max_shards,
        max_records_per_shard: options.max_records_per_shard,
        max_records_per_pack: options.max_records_per_pack,
        max_text_bytes: options.max_text_bytes,
        max_depth: options.max_depth,
    };
    let diagnostics = validate_pack(pack, limits);
    if !diagnostics.is_empty() {
        return Err(diagnostics);
    }

    let normalized = normalize(pack.clone());
    let mut artifacts = Vec::with_capacity(normalized.shards.len());
    let mut total_raw = 0u64;
    for shard in &normalized.shards {
        let compiled = CompiledShard {
            schema_version: normalized.schema_version,
            pack_id: normalized.pack_id.clone(),
            pack_version: normalized.version.clone(),
            producer: normalized.producer.clone(),
            shard_id: shard.id.clone(),
            language: normalized.language.clone(),
            ecosystem: normalized.ecosystem.clone(),
            compatibility: normalized.compatibility.clone(),
            activation: shard.activation.clone(),
            provenance: normalized.provenance.clone(),
            license: normalized.license.clone(),
            completeness: normalized.completeness,
            safety: normalized.safety.clone(),
            payload: CompiledPayload(shard.payload.clone()),
        };
        let raw = canonical_json(&compiled).map_err(artifact_diagnostic)?;
        if raw.len() > options.max_raw_shard_bytes {
            return Err(vec![Diagnostic::error(
                "limit.raw_shard_bytes",
                format!("$.shards[{}]", shard.id),
                format!(
                    "compiled shard exceeds {} bytes",
                    options.max_raw_shard_bytes
                ),
            )]);
        }
        total_raw = total_raw.saturating_add(raw.len() as u64);
        if total_raw > options.max_total_raw_bytes {
            return Err(vec![Diagnostic::error(
                "limit.total_raw_bytes",
                "$.shards",
                format!(
                    "compiled pack exceeds {} raw bytes",
                    options.max_total_raw_bytes
                ),
            )]);
        }
        let compressed = deflate(&raw).map_err(artifact_diagnostic)?;
        let use_compressed = match options.compression {
            CompressionPolicy::AlwaysRaw => false,
            CompressionPolicy::AlwaysDeflate => true,
            CompressionPolicy::Automatic => compression_is_worthwhile(raw.len(), compressed.len()),
        };
        let (encoding, bytes) = if use_compressed {
            (ArtifactEncoding::Deflate, compressed)
        } else {
            (ArtifactEncoding::Raw, raw.clone())
        };
        if bytes.len() > options.max_stored_shard_bytes {
            return Err(vec![Diagnostic::error(
                "limit.stored_shard_bytes",
                format!("$.shards[{}]", shard.id),
                format!(
                    "stored shard exceeds {} bytes",
                    options.max_stored_shard_bytes
                ),
            )]);
        }
        let (defined_ids, referenced_ids) = declaration_inventory(&compiled.payload.0);
        let descriptor = CompiledShardDescriptor {
            shard_id: compiled.shard_id.clone(),
            payload_kind: compiled.payload_kind(),
            routing_keys: routing_keys(&compiled.activation, &compiled.payload.0),
            encoding,
            raw_size: raw.len() as u64,
            stored_size: bytes.len() as u64,
            record_count: compiled.record_count() as u64,
            defined_ids,
            referenced_ids,
            semantic_sha256: semantic_digest(&compiled).map_err(artifact_diagnostic)?,
            content_sha256: content_digest(&raw),
            stored_sha256: stored_digest(&bytes),
        };
        artifacts.push(CompiledShardArtifact { descriptor, bytes });
    }

    let mut manifest = CompiledPackManifest {
        schema_version: normalized.schema_version,
        pack_id: normalized.pack_id,
        version: normalized.version,
        producer: normalized.producer,
        language: normalized.language,
        ecosystem: normalized.ecosystem,
        compatibility: normalized.compatibility,
        provenance: normalized.provenance,
        license: normalized.license,
        completeness: normalized.completeness,
        safety: normalized.safety,
        semantic_sha256: String::new(),
        content_sha256: String::new(),
        shards: artifacts
            .iter()
            .map(|artifact| artifact.descriptor.clone())
            .collect(),
    };
    manifest.semantic_sha256 = manifest_semantic_digest(&manifest).map_err(artifact_diagnostic)?;
    manifest.content_sha256 = manifest_content_digest(&manifest).map_err(artifact_diagnostic)?;
    let manifest_bytes = canonical_json(&manifest).map_err(artifact_diagnostic)?;
    if manifest_bytes.len() > options.max_manifest_bytes {
        return Err(vec![Diagnostic::error(
            "limit.manifest_bytes",
            "$",
            format!(
                "compiled manifest exceeds {} bytes",
                options.max_manifest_bytes
            ),
        )]);
    }
    Ok(CompiledSemanticModelPack {
        manifest,
        manifest_bytes,
        shards: artifacts,
    })
}

fn artifact_diagnostic(error: ArtifactError) -> Vec<Diagnostic> {
    vec![Diagnostic::error("artifact.encode", "$", error.to_string())]
}

fn deflate(bytes: &[u8]) -> Result<Vec<u8>, ArtifactError> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::new(6));
    encoder
        .write_all(bytes)
        .map_err(|error| ArtifactError::Decompression(error.to_string()))?;
    encoder
        .finish()
        .map_err(|error| ArtifactError::Decompression(error.to_string()))
}

fn compression_is_worthwhile(raw: usize, compressed: usize) -> bool {
    raw.saturating_sub(compressed) >= 1024
        && compressed.saturating_mul(100) <= raw.saturating_mul(95)
}

pub(crate) fn normalize(mut pack: AuthoredSemanticModelPack) -> AuthoredSemanticModelPack {
    pack.compatibility.toolchains.sort_by(|left, right| {
        (&left.name, &left.requirement).cmp(&(&right.name, &right.requirement))
    });
    for shard in &mut pack.shards {
        for selector in &mut shard.activation {
            selector.targets.sort_unstable();
            selector.targets.dedup();
            selector.configurations.sort_unstable();
            selector.configurations.dedup();
        }
        shard.activation.sort_by_key(selector_sort_key);
        match &mut shard.payload {
            AuthoredPayload::DeclarationFacts {
                types,
                members,
                relations,
            } => {
                for fact in &mut *types {
                    fact.aliases.sort_unstable();
                    fact.aliases.dedup();
                    fact.extension_surfaces.sort_unstable();
                    fact.extension_surfaces.dedup();
                    fact.hierarchy.sort_by_key(hierarchy_sort_key);
                }
                for fact in &mut *members {
                    fact.aliases.sort_unstable();
                    fact.aliases.dedup();
                }
                types.sort_by(|left, right| left.id.cmp(&right.id));
                members.sort_by(|left, right| left.id.cmp(&right.id));
                relations.sort_by(|left, right| left.id.cmp(&right.id));
            }
            AuthoredPayload::GeneratorRules { rules } => {
                rules.sort_by(|left, right| left.id.cmp(&right.id));
            }
        }
    }
    pack.shards.sort_by(|left, right| left.id.cmp(&right.id));
    pack
}

fn selector_sort_key(selector: &ActivationSelector) -> Vec<u8> {
    serde_json::to_vec(selector).expect("authoring model is JSON serializable")
}

fn hierarchy_sort_key(hierarchy: &HierarchyFact) -> Vec<u8> {
    serde_json::to_vec(hierarchy).expect("authoring model is JSON serializable")
}
