use super::artifact::{
    ArtifactEncoding, ArtifactError, CompiledPackManifest, CompiledPayload,
    CompiledProcedureSummary, CompiledProcedureTarget, CompiledSemanticModelPack, CompiledShard,
    CompiledShardArtifact, CompiledShardDescriptor, CompiledSummaryEffect, CompiledSummaryExitKind,
    CompiledSummaryInput, CompiledSummaryLocation, CompiledSummaryLocationKind,
    CompiledSummaryOutput, CompiledSummaryTransfer, DecodeLimits, canonical_json, content_digest,
    manifest_content_digest, manifest_semantic_digest, payload_inventory, routing_keys,
    semantic_digest, stored_digest,
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
            payload: compile_payload(&normalized.pack_id, &shard.payload)
                .map_err(artifact_diagnostic)?,
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
        let (defined_ids, referenced_ids) = payload_inventory(&compiled.payload);
        let descriptor = CompiledShardDescriptor {
            shard_id: compiled.shard_id.clone(),
            payload_kind: compiled.payload_kind(),
            routing_keys: routing_keys(&compiled.activation, &compiled.payload),
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
                    fact.type_parameter_constraints
                        .sort_by(|left, right| left.parameter.cmp(&right.parameter));
                    fact.embedded_types.sort_by_cached_key(canonical_sort_key);
                    fact.embedded_types.dedup();
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
            AuthoredPayload::ProcedureSummaries { summaries } => {
                for summary in &mut *summaries {
                    summary
                        .locations
                        .sort_by(|left, right| left.id.cmp(&right.id));
                    summary.transfers.sort_by_cached_key(canonical_sort_key);
                    summary.transfers.dedup();
                    for effect in &mut summary.effects {
                        if let AuthoredSummaryEffect::AmbiguousCall { candidates, .. } = effect {
                            candidates.sort_unstable();
                        }
                    }
                    summary.effects.sort_by_cached_key(canonical_sort_key);
                    summary.effects.dedup();
                }
                summaries.sort_by(|left, right| left.id.cmp(&right.id));
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
    match hierarchy.declaration_ordinal {
        Some(ordinal) => {
            let mut key = vec![0];
            key.extend_from_slice(&ordinal.to_be_bytes());
            key.extend(
                serde_json::to_vec(hierarchy).expect("authoring model is JSON serializable"),
            );
            key
        }
        None => {
            let mut key = vec![1];
            key.extend(
                serde_json::to_vec(hierarchy).expect("authoring model is JSON serializable"),
            );
            key
        }
    }
}

fn canonical_sort_key(value: &impl serde::Serialize) -> Vec<u8> {
    serde_json::to_vec(value).expect("authoring model is JSON serializable")
}

fn compile_payload(
    pack_id: &str,
    payload: &AuthoredPayload,
) -> Result<CompiledPayload, ArtifactError> {
    Ok(match payload {
        AuthoredPayload::DeclarationFacts {
            types,
            members,
            relations,
        } => CompiledPayload::DeclarationFacts {
            types: types.clone(),
            members: members.clone(),
            relations: relations.clone(),
        },
        AuthoredPayload::GeneratorRules { rules } => CompiledPayload::GeneratorRules {
            rules: rules.clone(),
        },
        AuthoredPayload::ProcedureSummaries { summaries } => CompiledPayload::ProcedureSummaries {
            summaries: summaries
                .iter()
                .map(|summary| compile_procedure_summary(pack_id, summary))
                .collect::<Result<Vec<_>, _>>()?,
        },
    })
}

fn compile_procedure_summary(
    pack_id: &str,
    summary: &AuthoredProcedureSummary,
) -> Result<CompiledProcedureSummary, ArtifactError> {
    let content_sha256 = content_digest(&canonical_json(summary)?);
    Ok(CompiledProcedureSummary {
        id: summary.id.clone(),
        model_id: format!("{pack_id}#{}", summary.id),
        contract_version: PROCEDURE_SUMMARY_CONTRACT_VERSION,
        content_sha256,
        target: CompiledProcedureTarget {
            path: summary.target.path.clone(),
            symbol: summary.target.symbol.clone(),
            has_receiver: summary.target.has_receiver,
            parameter_count: summary.target.parameter_count,
        },
        completeness: summary.completeness,
        locations: summary
            .locations
            .iter()
            .map(|location| CompiledSummaryLocation {
                id: location.id.clone(),
                location_kind: match location.location_kind {
                    AuthoredSummaryLocationKind::Capture => CompiledSummaryLocationKind::Capture,
                    AuthoredSummaryLocationKind::Heap => CompiledSummaryLocationKind::Heap,
                },
            })
            .collect(),
        transfers: summary
            .transfers
            .iter()
            .map(|transfer| CompiledSummaryTransfer {
                input: compile_summary_input(&transfer.input),
                exit_kind: match transfer.exit_kind {
                    AuthoredSummaryExitKind::Normal => CompiledSummaryExitKind::Normal,
                    AuthoredSummaryExitKind::Exceptional => CompiledSummaryExitKind::Exceptional,
                },
                output: compile_summary_output(&transfer.output),
            })
            .collect(),
        effects: summary.effects.iter().map(compile_summary_effect).collect(),
    })
}

fn compile_summary_input(input: &AuthoredSummaryInput) -> CompiledSummaryInput {
    match input {
        AuthoredSummaryInput::Receiver {} => CompiledSummaryInput::Receiver {},
        AuthoredSummaryInput::Parameter { ordinal } => {
            CompiledSummaryInput::Parameter { ordinal: *ordinal }
        }
    }
}

fn compile_summary_output(output: &AuthoredSummaryOutput) -> CompiledSummaryOutput {
    match output {
        AuthoredSummaryOutput::NormalReturn {} => CompiledSummaryOutput::NormalReturn {},
        AuthoredSummaryOutput::Receiver {} => CompiledSummaryOutput::Receiver {},
        AuthoredSummaryOutput::Capture { location } => CompiledSummaryOutput::Capture {
            location: location.clone(),
        },
        AuthoredSummaryOutput::Heap { location } => CompiledSummaryOutput::Heap {
            location: location.clone(),
        },
        AuthoredSummaryOutput::ExceptionalReturn {} => CompiledSummaryOutput::ExceptionalReturn {},
    }
}

fn compile_summary_effect(effect: &AuthoredSummaryEffect) -> CompiledSummaryEffect {
    match effect {
        AuthoredSummaryEffect::Allocation { event, output } => CompiledSummaryEffect::Allocation {
            event: event.clone(),
            output: compile_summary_output(output),
        },
        AuthoredSummaryEffect::Call { event, callee } => CompiledSummaryEffect::Call {
            event: event.clone(),
            callee: callee.clone(),
        },
        AuthoredSummaryEffect::Escape { event, input } => CompiledSummaryEffect::Escape {
            event: event.clone(),
            input: compile_summary_input(input),
        },
        AuthoredSummaryEffect::UnknownCall { event, input } => CompiledSummaryEffect::UnknownCall {
            event: event.clone(),
            input: compile_summary_input(input),
        },
        AuthoredSummaryEffect::UnknownCallBoundary { event } => {
            CompiledSummaryEffect::UnknownCallBoundary {
                event: event.clone(),
            }
        }
        AuthoredSummaryEffect::AmbiguousCall {
            event,
            input,
            candidates,
        } => CompiledSummaryEffect::AmbiguousCall {
            event: event.clone(),
            input: compile_summary_input(input),
            candidates: candidates.clone(),
        },
    }
}
