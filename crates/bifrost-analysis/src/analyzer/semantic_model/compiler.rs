use super::artifact::{
    ArtifactEncoding, ArtifactError, CompiledClassDecoratorIdentity, CompiledClassDecoratorKeyword,
    CompiledConditionalIndirectWrite, CompiledConditionalResultRefinement,
    CompiledIndirectWriteTarget, CompiledNormalReturnRefinement,
    CompiledNormalReturnTypeRefinement, CompiledOperationPrecondition, CompiledPackManifest,
    CompiledPayload, CompiledPredicateProofEffect, CompiledProcedureSummary,
    CompiledProcedureTarget, CompiledResultContract, CompiledResultMemberContract,
    CompiledResultUseObligation, CompiledReturnedCallable, CompiledSemanticModelPack,
    CompiledShard, CompiledShardArtifact, CompiledShardDescriptor, CompiledSummaryExitKind,
    CompiledSummaryLocation, CompiledSummaryLocationKind, CompiledSummaryTransfer, DecodeLimits,
    canonical_json, content_digest, manifest_content_digest, manifest_semantic_digest,
    routing_keys, semantic_digest, shard_inventory,
};
use super::conversion::{
    compile_concurrency_effect, compile_declared_effect, compile_result_predicate,
    compile_summary_effect, compile_summary_input, compile_summary_output,
    compile_summary_value_transfer,
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
            runtime_values: shard.runtime_values.clone(),
            runtime_contracts: shard.runtime_contracts.clone(),
            collection_flows: shard.collection_flows.clone(),
            deferred_yields: shard.deferred_yields.clone(),
            conditional_type_refinements: shard.conditional_type_refinements.clone(),
            callable_values: shard.callable_values.clone(),
            cpp_portability: normalized.cpp_portability.clone(),
            python_correspondence: normalized.python_correspondence.clone(),
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
        let (defined_ids, referenced_ids) = shard_inventory(&compiled);
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
            stored_sha256: content_digest(&bytes),
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
        cpp_portability: normalized.cpp_portability,
        python_correspondence: normalized.python_correspondence,
        carried_sources: normalized.carried_sources,
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

/// Canonically orders callable-values records and their unordered members.
/// Distinct facts and diagnostic alternatives are retained, even when their
/// semantic payloads compare equal.
pub fn normalize_callable_values_payload(payload: &mut CallableValuesPayload) {
    for fact in &mut payload.facts {
        fact.provenance.sort_unstable();
    }
    payload.facts.sort_by_cached_key(canonical_sort_key);

    for coverage in &mut payload.coverage {
        coverage.provenance.sort_unstable();
        coverage.limitations.sort_by_cached_key(canonical_sort_key);
    }
    payload.coverage.sort_by_cached_key(canonical_sort_key);
    payload
        .anonymous_callables
        .sort_by_cached_key(canonical_sort_key);
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
        if let Some(runtime_values) = &mut shard.runtime_values {
            runtime_values
                .exposures
                .sort_by(|left, right| left.exposure_id.cmp(&right.exposure_id));
            runtime_values
                .behaviors
                .sort_by(|left, right| left.behavior_id.cmp(&right.behavior_id));
            runtime_values
                .binding_evidence
                .sort_by(|left, right| left.binding_evidence_id.cmp(&right.binding_evidence_id));
            runtime_values
                .observations
                .sort_by(|left, right| left.observation_id.cmp(&right.observation_id));
        }
        if let Some(runtime_contracts) = &mut shard.runtime_contracts {
            crate::analyzer::semantic_model::normalize_runtime_contract_payload(
                &mut runtime_contracts.payload,
            )
            .expect("typed runtime-contract payload is JSON serializable");
            if let Some(envelope) = &mut runtime_contracts.envelope {
                crate::analyzer::semantic_model::normalize_runtime_contract_envelope(envelope)
                    .expect("retained runtime-contract envelope is JSON serializable");
            }
        }
        if let Some(collection_flows) = &mut shard.collection_flows {
            collection_flows
                .flows
                .sort_by(|left, right| left.callable.cmp(&right.callable));
        }
        if let Some(refinements) = &mut shard.conditional_type_refinements {
            for fact in &mut refinements.refinements {
                fact.provenance.sort_unstable();
                fact.provenance.dedup();
            }
            refinements
                .refinements
                .sort_by_cached_key(canonical_sort_key);
            refinements.refinements.dedup();
        }
        if let Some(deferred_yields) = &mut shard.deferred_yields {
            for fact in &mut deferred_yields.yields {
                fact.provenance.sort_unstable();
                fact.provenance.dedup();
            }
            deferred_yields
                .yields
                .sort_by_cached_key(canonical_sort_key);
            deferred_yields.yields.dedup();
        }
        if let Some(callable_values) = &mut shard.callable_values {
            normalize_callable_values_payload(callable_values);
        }
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
                    normalize_guard(fact.guard.as_mut());
                    fact.hierarchy.sort_by_key(hierarchy_sort_key);
                    fact.type_parameter_constraints
                        .sort_by(|left, right| left.parameter.cmp(&right.parameter));
                    fact.embedded_types.sort_by_cached_key(canonical_sort_key);
                    fact.embedded_types.dedup();
                }
                for fact in &mut *members {
                    fact.aliases.sort_unstable();
                    fact.aliases.dedup();
                    normalize_guard(fact.guard.as_mut());
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
                        match effect {
                            AuthoredSummaryEffect::AmbiguousCall { candidates, .. } => {
                                candidates.sort_unstable();
                            }
                            AuthoredSummaryEffect::Sanitize { removes, .. } => {
                                removes.sort_unstable();
                                removes.dedup();
                            }
                            AuthoredSummaryEffect::Allocation { .. }
                            | AuthoredSummaryEffect::Call { .. }
                            | AuthoredSummaryEffect::Escape { .. }
                            | AuthoredSummaryEffect::UnknownCall { .. }
                            | AuthoredSummaryEffect::UnknownCallBoundary { .. } => {}
                        }
                    }
                    summary.effects.sort_by_cached_key(canonical_sort_key);
                    summary.effects.dedup();
                    summary
                        .concurrency_effects
                        .sort_by_cached_key(canonical_sort_key);
                    summary.concurrency_effects.dedup();
                    // Declared effects (#2437) are a set keyed by id; validation
                    // already rejected two entries sharing one id, so sorting by
                    // id is a total order over what survives.
                    summary
                        .declared_effects
                        .sort_by(|left, right| left.id.cmp(&right.id));
                    summary.declared_effects.dedup();
                    if let Some(preconditions) = &mut summary.preconditions {
                        preconditions.sort();
                    }
                    for contract in &mut summary.result_contracts {
                        for member in &mut contract.member_contracts {
                            if let Some(preconditions) = &mut member.preconditions {
                                preconditions.sort();
                            }
                        }
                    }
                    summary.result_contracts.sort();
                    summary.result_contracts.dedup();
                    summary.result_use_obligations.sort();
                    summary.result_use_obligations.dedup();
                    summary.conditional_result_refinements.sort();
                    summary.conditional_result_refinements.dedup();
                    summary.conditional_indirect_writes.sort();
                    summary.conditional_indirect_writes.dedup();
                    summary.normal_return_refinements.sort();
                    summary.normal_return_refinements.dedup();
                    for refinement in &mut summary.normal_return_type_refinements {
                        refinement.required_receiver_members.sort();
                        refinement.required_receiver_members.dedup();
                    }
                    summary.normal_return_type_refinements.sort();
                    summary.normal_return_type_refinements.dedup();
                    if let Some(identity) = &mut summary.class_decorator_identity
                        && let Some(keywords) = &mut identity.factory_keywords
                    {
                        for keyword in keywords.iter_mut() {
                            keyword.allowed_values.sort_unstable();
                            keyword.allowed_values.dedup();
                        }
                        keywords.sort();
                        keywords.dedup();
                    }
                }
                summaries.sort_by(|left, right| left.id.cmp(&right.id));
            }
        }
    }
    pack.shards.sort_by(|left, right| left.id.cmp(&right.id));
    if let Some(evidence) = &mut pack.cpp_portability {
        evidence.normalize();
    }
    if let Some(evidence) = &mut pack.python_correspondence {
        evidence.symbols.sort_by_cached_key(canonical_sort_key);
        evidence.mappings.sort_by_cached_key(canonical_sort_key);
    }
    pack
}

/// A guard's target lists are sets, so one canonical order keeps two producers
/// that read the same condition at the same content digest.
fn normalize_guard(guard: Option<&mut DeclarationGuard>) {
    let Some(guard) = guard else {
        return;
    };
    for targets in [&mut guard.required_targets, &mut guard.excluded_targets] {
        targets.sort_unstable();
        targets.dedup();
    }
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
    super::compact_json_bytes(value).expect("authoring model is JSON serializable")
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
            variadic: summary.target.variadic,
            parameter_count: summary.target.parameter_count,
            formals: summary.target.formals.clone(),
        },
        completeness: summary.completeness,
        ordinary_heap_unchanged: summary.ordinary_heap_unchanged,
        no_concurrency_effects: summary.no_concurrency_effects,
        covers_overrides: summary.covers_overrides,
        normal_continuation_absent: summary.normal_continuation_absent,
        normal_result_count: summary.normal_result_count,
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
                value_transfer: transfer
                    .value_transfer
                    .as_ref()
                    .map(compile_summary_value_transfer),
            })
            .collect(),
        transfer_partitions: summary.transfer_partitions.clone(),
        effects: summary.effects.iter().map(compile_summary_effect).collect(),
        concurrency_effects: summary
            .concurrency_effects
            .iter()
            .map(compile_concurrency_effect)
            .collect(),
        returned_callables: summary
            .returned_callables
            .iter()
            .map(|callable| CompiledReturnedCallable {
                result_ordinal: callable.result_ordinal,
                at_most_once: callable.at_most_once,
                concurrency_effects: callable
                    .concurrency_effects
                    .iter()
                    .map(compile_concurrency_effect)
                    .collect(),
            })
            .collect(),
        declared_effects: summary
            .declared_effects
            .iter()
            .map(compile_declared_effect)
            .collect(),
        preconditions: summary.preconditions.as_ref().map(|preconditions| {
            preconditions
                .iter()
                .map(|precondition| CompiledOperationPrecondition {
                    input: compile_summary_input(&precondition.input),
                    predicate: compile_result_predicate(precondition.predicate),
                })
                .collect()
        }),
        result_contracts: summary
            .result_contracts
            .iter()
            .map(|contract| CompiledResultContract {
                result_ordinal: contract.result_ordinal,
                condition_result_ordinal: contract.condition_result_ordinal,
                predicate: contract.predicate.map(compile_result_predicate),
                result_success_predicate: contract
                    .result_success_predicate
                    .map(compile_result_predicate),
                member_contracts: contract
                    .member_contracts
                    .iter()
                    .map(|member| CompiledResultMemberContract {
                        member: member.member.clone(),
                        parameter_count: member.parameter_count,
                        completeness: member.completeness,
                        preconditions: member.preconditions.as_ref().map(|preconditions| {
                            preconditions
                                .iter()
                                .map(|precondition| CompiledOperationPrecondition {
                                    input: compile_summary_input(&precondition.input),
                                    predicate: compile_result_predicate(precondition.predicate),
                                })
                                .collect()
                        }),
                        declared_effects: member
                            .declared_effects
                            .iter()
                            .map(compile_declared_effect)
                            .collect(),
                    })
                    .collect(),
            })
            .collect(),
        result_use_obligations: summary
            .result_use_obligations
            .iter()
            .map(|obligation| CompiledResultUseObligation {
                result_ordinal: obligation.result_ordinal,
                kind: obligation.kind,
                failure_predicate: obligation.failure_predicate.map(compile_result_predicate),
            })
            .collect(),
        conditional_result_refinements: summary
            .conditional_result_refinements
            .iter()
            .map(|refinement| CompiledConditionalResultRefinement {
                result_ordinal: refinement.result_ordinal,
                outcome: refinement.outcome,
                parameter_ordinal: refinement.parameter_ordinal,
                predicate: compile_result_predicate(refinement.predicate),
                proof_effect: match refinement.proof_effect {
                    AuthoredPredicateProofEffect::Establishes => {
                        CompiledPredicateProofEffect::Establishes
                    }
                    AuthoredPredicateProofEffect::DoesNotEstablish => {
                        CompiledPredicateProofEffect::DoesNotEstablish
                    }
                },
            })
            .collect(),
        conditional_indirect_writes: summary
            .conditional_indirect_writes
            .iter()
            .map(|write| CompiledConditionalIndirectWrite {
                result_ordinal: write.result_ordinal,
                outcome: write.outcome,
                parameter_ordinal: write.parameter_ordinal,
                target: match write.target {
                    AuthoredIndirectWriteTarget::Pointee => CompiledIndirectWriteTarget::Pointee,
                },
            })
            .collect(),
        normal_return_refinements: summary
            .normal_return_refinements
            .iter()
            .map(|refinement| CompiledNormalReturnRefinement {
                parameter_ordinal: refinement.parameter_ordinal,
                predicate: compile_result_predicate(refinement.predicate),
            })
            .collect(),
        normal_return_type_refinements: summary
            .normal_return_type_refinements
            .iter()
            .map(|refinement| CompiledNormalReturnTypeRefinement {
                parameter_ordinal: refinement.parameter_ordinal,
                class_parameter_ordinal: refinement.class_parameter_ordinal,
                required_receiver_members: refinement.required_receiver_members.clone(),
            })
            .collect(),
        class_decorator_identity: summary.class_decorator_identity.as_ref().map(|identity| {
            CompiledClassDecoratorIdentity {
                direct: identity.direct,
                factory_keywords: identity.factory_keywords.as_ref().map(|keywords| {
                    keywords
                        .iter()
                        .map(|keyword| CompiledClassDecoratorKeyword {
                            name: keyword.name.clone(),
                            allowed_values: keyword.allowed_values.clone(),
                        })
                        .collect()
                }),
            }
        }),
    })
}

#[cfg(test)]
mod callable_values_normalization_tests {
    use super::*;
    use crate::analyzer::semantic_model::csmi::{
        CsmiCallableValuesArgument, CsmiCallableValuesDiagnostic, CsmiCallableValuesLimitation,
        CsmiCallableValuesModality, CsmiCallableValuesPayload, CsmiCallableValuesShape,
        CsmiCallableValuesTiming, CsmiCoverageStatus, CsmiInputBoundaryRoot, CsmiInputLocation,
        CsmiInputParameterRoot, CsmiInputPhase, CsmiParameterRootRole,
    };

    fn input_location(position: u32) -> CsmiInputLocation {
        CsmiInputLocation {
            root: CsmiInputBoundaryRoot::Parameter(CsmiInputParameterRoot {
                phase: CsmiInputPhase::Input,
                role: CsmiParameterRootRole::Parameter,
                position,
            }),
            projection: None,
        }
    }

    fn callback_fact(message: &str, provenance: &[&str]) -> CallableValuesFact {
        CallableValuesFact {
            payload: CsmiCallableValuesPayload::CallbackInvocation {
                callable: "callback".to_owned(),
                callback: input_location(0),
                shape: CsmiCallableValuesShape {
                    parameters: 1,
                    results: 0,
                },
                arguments: vec![CsmiCallableValuesArgument::Unknown {
                    limitation: CsmiCallableValuesLimitation {
                        kind: "other".to_owned(),
                        diagnostic: Some(CsmiCallableValuesDiagnostic {
                            message: message.to_owned(),
                            code: Some("origin.unknown".to_owned()),
                            details: Some(serde_json::json!({"source": message})),
                        }),
                    },
                }],
                timing: CsmiCallableValuesTiming::DuringCall,
                modality: CsmiCallableValuesModality::May,
            },
            provenance: provenance.iter().map(|id| (*id).to_owned()).collect(),
        }
    }

    fn coverage(code: &str, provenance: &[&str]) -> CallableValuesCoverage {
        CallableValuesCoverage {
            family: CallableValuesFamily::CallbackInvocations,
            callable: "callback".to_owned(),
            status: CsmiCoverageStatus::Partial,
            limitations: vec![
                crate::analyzer::semantic_model::csmi::CsmiLimitation {
                    kind: format!("{code}-first"),
                    diagnostic: Some(
                        crate::analyzer::semantic_model::csmi::CsmiDiagnosticMetadata {
                            code: Some(format!("{code}.first")),
                            message: Some("first coverage explanation".to_owned()),
                        },
                    ),
                },
                crate::analyzer::semantic_model::csmi::CsmiLimitation {
                    kind: format!("{code}-second"),
                    diagnostic: Some(
                        crate::analyzer::semantic_model::csmi::CsmiDiagnosticMetadata {
                            code: Some(format!("{code}.second")),
                            message: Some("second coverage explanation".to_owned()),
                        },
                    ),
                },
            ],
            provenance: provenance.iter().map(|id| (*id).to_owned()).collect(),
        }
    }

    #[test]
    fn callable_values_normalization_is_order_independent_and_preserves_alternatives() {
        let first = callback_fact("alpha diagnostic", &["z", "a"]);
        let second = callback_fact("beta diagnostic", &["y", "b"]);
        let mut permuted_a_coverage = coverage("unknown.a", &["b", "y"]);
        permuted_a_coverage.limitations.reverse();
        let mut permuted_b_coverage = coverage("unknown.b", &["a", "z"]);
        permuted_b_coverage.limitations.reverse();
        let mut left = CallableValuesPayload {
            facts: vec![first.clone(), second.clone(), first.clone()],
            coverage: vec![
                coverage("unknown.b", &["z", "a"]),
                coverage("unknown.a", &["y", "b"]),
            ],
            anonymous_callables: Vec::new(),
        };
        let mut right = CallableValuesPayload {
            facts: vec![second.clone(), first.clone(), first],
            coverage: vec![permuted_a_coverage, permuted_b_coverage],
            anonymous_callables: Vec::new(),
        };

        normalize_callable_values_payload(&mut left);
        normalize_callable_values_payload(&mut right);

        assert_eq!(left, right);
        assert_eq!(left.facts.len(), 3, "duplicate alternatives are retained");
        assert_eq!(left.coverage.len(), 2);
        assert!(
            left.facts
                .iter()
                .all(|fact| fact.provenance.windows(2).all(|pair| pair[0] <= pair[1]))
        );
        assert!(
            left.coverage
                .iter()
                .all(|item| item.provenance.windows(2).all(|pair| pair[0] <= pair[1]))
        );
        let diagnostics: Vec<_> = left
            .facts
            .iter()
            .filter_map(|fact| match &fact.payload {
                CsmiCallableValuesPayload::CallbackInvocation { arguments, .. } => {
                    match &arguments[0] {
                        CsmiCallableValuesArgument::Unknown { limitation } => {
                            limitation.diagnostic.as_ref()
                        }
                        CsmiCallableValuesArgument::Input { .. } => None,
                    }
                }
                CsmiCallableValuesPayload::ReturnedCallable { .. } => None,
            })
            .collect();
        assert_eq!(diagnostics.len(), 3);
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message == "alpha diagnostic")
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message == "beta diagnostic")
        );
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.details.is_some())
        );
    }
}
