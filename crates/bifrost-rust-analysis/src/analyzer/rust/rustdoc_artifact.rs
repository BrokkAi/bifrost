use brokk_bifrost_semantic::analyzer::semantic_model::model::{
    AssociatedTypeBinding, GenericParameterDefault, GenericTraitBound, GenericTraitImplFact,
    ImplementedTraitFact, RustSelfForm, RustSelfPattern,
};
use std::collections::{HashMap as RandomHashMap, HashSet as RandomHashSet, VecDeque};

use rustdoc_types::{
    Crate as RustdocCrate, GenericArg, GenericArgs, GenericBound, Generics, Id, Item, ItemEnum,
    Path as RustdocPath, StructKind, Term, Type, VariantKind, Visibility as RustVisibility,
    WherePredicate,
};
use serde::Deserialize;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_core::analyzer::canonical_hash::lower_hex_string;

use brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes;
#[cfg(test)]
use brokk_bifrost_semantic::analyzer::semantic_model::producer::ExternalArtifactPackProducer;

use brokk_bifrost_semantic::analyzer::semantic_model::csmi::CsmiCollectionFlowBoundaryRoot;

use brokk_bifrost_semantic::analyzer::semantic_model::csmi::CsmiCollectionFlowEntryComponent;

use brokk_bifrost_semantic::analyzer::semantic_model::csmi::CsmiCollectionFlowKind;

use brokk_bifrost_semantic::analyzer::semantic_model::csmi::CsmiCollectionFlowPayload;

use brokk_bifrost_semantic::analyzer::semantic_model::csmi::CsmiCollectionFlowRoot;

use brokk_bifrost_semantic::analyzer::semantic_model::csmi::CsmiCollectionFlowShape;

use brokk_bifrost_semantic::analyzer::semantic_model::csmi::CsmiCollectionFlowTransfer;

use brokk_bifrost_semantic::analyzer::semantic_model::csmi::CsmiInputBoundaryRoot;

use brokk_bifrost_semantic::analyzer::semantic_model::csmi::CsmiInputLocation;

use brokk_bifrost_semantic::analyzer::semantic_model::csmi::CsmiInputParameterRoot;

use brokk_bifrost_semantic::analyzer::semantic_model::csmi::CsmiInputPhase;

use brokk_bifrost_semantic::analyzer::semantic_model::csmi::CsmiInputReceiverRoot;

use brokk_bifrost_semantic::analyzer::semantic_model::csmi::CsmiOutputBoundaryRoot;

use brokk_bifrost_semantic::analyzer::semantic_model::csmi::CsmiOutputLocation;

use brokk_bifrost_semantic::analyzer::semantic_model::csmi::CsmiOutputPhase;

use brokk_bifrost_semantic::analyzer::semantic_model::csmi::CsmiOutputReceiverRoot;

use brokk_bifrost_semantic::analyzer::semantic_model::csmi::CsmiParameterRootRole;

use brokk_bifrost_semantic::analyzer::semantic_model::csmi::CsmiProjectionStep;

use brokk_bifrost_semantic::analyzer::semantic_model::csmi::CsmiReceiverRootRole;

use brokk_bifrost_semantic::analyzer::semantic_model::producer::ArtifactProducerLimits;

use brokk_bifrost_semantic::analyzer::semantic_model::producer::ArtifactProduction;

use brokk_bifrost_semantic::analyzer::semantic_model::producer::ArtifactProductionRequest;

use crate::analyzer::semantic_model::AuthoredPayload;

use crate::analyzer::semantic_model::AuthoredSemanticModelPack;

use crate::analyzer::semantic_model::AuthoredShard;

use brokk_bifrost_semantic::analyzer::semantic_model::producer::BoundedProducerDiagnostics;

use crate::analyzer::semantic_model::CollectionFlowFact;

use crate::analyzer::semantic_model::CollectionFlowsPayload;

use crate::analyzer::semantic_model::Completeness;

use brokk_bifrost_semantic::analyzer::semantic_model::producer::ExactArtifact;

use brokk_bifrost_semantic::analyzer::semantic_model::producer::ExternalArtifactKind;

use crate::analyzer::semantic_model::HierarchyFact;

use crate::analyzer::semantic_model::HierarchyKind;

use crate::analyzer::semantic_model::Locator;

use crate::analyzer::semantic_model::MemberFact;

use brokk_bifrost_semantic::analyzer::semantic_model::identity::MemberIdentity;

use crate::analyzer::semantic_model::MemberKind;

use crate::analyzer::semantic_model::Parameter;

use crate::analyzer::semantic_model::Producer;

use brokk_bifrost_semantic::analyzer::semantic_model::producer::ProducerDiagnostic;

use brokk_bifrost_semantic::analyzer::semantic_model::producer::ProducerDiagnosticSeverity;

use crate::analyzer::semantic_model::ReceiverFact;

use crate::analyzer::semantic_model::RelationFact;

use crate::analyzer::semantic_model::RelationKind;
use crate::analyzer::semantic_model::{RustExternalReexport, RustExternalReexportTarget};
use brokk_bifrost_semantic::analyzer::semantic_model::model::RustReexportTargetNamespace;

use crate::analyzer::semantic_model::Signature;

use crate::analyzer::semantic_model::SuppressedDiagnostics;

use crate::analyzer::semantic_model::TypeFact;

use brokk_bifrost_semantic::analyzer::semantic_model::identity::TypeIdentity;

use crate::analyzer::semantic_model::TypeKind;

use crate::analyzer::semantic_model::TypeRef;

use crate::analyzer::semantic_model::TypeRefReferenceKind;

use crate::analyzer::semantic_model::Visibility;

use crate::analyzer::semantic_model::WildcardVariance;

use crate::analyzer::semantic_model::admit_into_full_diagnostics;

use brokk_bifrost_semantic::analyzer::semantic_model::producer::failed_artifact_production;

use brokk_bifrost_semantic::analyzer::semantic_model::identity::member_declaration_id;

use brokk_bifrost_semantic::analyzer::semantic_model::producer::read_exact_artifact_while;

use brokk_bifrost_semantic::analyzer::semantic_model::identity::type_declaration_id;

use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_core::hash::HashSet;

const ARTIFACT_LOCATOR_PATH: &str = "rustdoc/api.json";
const RUSTDOC_FORMAT_VERSION: u32 = 61;
const RUSTDOC_PRODUCER_CONTRACT: &str = "rustdoc-json-pack-producer/1";
/// The highest authored schema this Rustdoc producer may write.
pub(crate) const RUSTDOC_PACK_MAX_SCHEMA_VERSION: u32 =
    brokk_bifrost_semantic::analyzer::semantic_model::ALIAS_TARGET_MIN_SCHEMA_VERSION;

fn assert_pack_schema_within_producer_max(pack: Option<&AuthoredSemanticModelPack>) {
    if let Some(pack) = pack {
        assert!(
            pack.schema_version <= RUSTDOC_PACK_MAX_SCHEMA_VERSION,
            "Rustdoc producer wrote schema {} above its maximum {}",
            pack.schema_version,
            RUSTDOC_PACK_MAX_SCHEMA_VERSION
        );
    }
}

// Update this list when this producer begins consuming a converted field. The
// conversion certificate is refused before the rustdoc-types parser runs.
const CONVERTED_FIELDS_CONSUMED: &[&str] = &[];
#[cfg(test)]
mod conversion_contract {
    include!("rustdoc_conversion_contract.rs");
}
const RUST_STD_CRATE_NAME: &str = "std";
const RUST_STD_HASHMAP_NAME: &str = "std.collections.HashMap";
const MAX_MODEL_NAME_BYTES: usize = 16 * 1024;
const MAX_TOTAL_MODEL_NAME_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Default)]
pub struct RustdocJsonPackProducer;

#[derive(Debug, Deserialize)]
struct RustdocVersionEnvelope {
    format_version: u32,
    #[serde(rename = "_bifrost_conversion")]
    conversion: Option<RustdocConversionCertificate>,
}

#[derive(Debug, Deserialize)]
struct RustdocConversionCertificate {
    producer_contract: String,
    uncertified_fields: Vec<String>,
}

fn validate_conversion_certificate(
    certificate: Option<&RustdocConversionCertificate>,
    producer_contract: &str,
    consumed: &[&str],
) -> Result<(), &'static str> {
    let Some(certificate) = certificate else {
        return Ok(());
    };
    if certificate.producer_contract != producer_contract {
        return Err("converted rustdoc artifact targets a different producer contract");
    }
    if certificate
        .uncertified_fields
        .iter()
        .any(|field| consumed.contains(&field.as_str()))
    {
        return Err(
            "converted rustdoc artifact has an uncertified field consumed by this producer",
        );
    }
    Ok(())
}

brokk_bifrost_semantic::implement_external_artifact_pack_producer!(
    RustdocJsonPackProducer,
    produce
);

impl RustdocJsonPackProducer {
    fn produce(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
    ) -> ArtifactProduction {
        if request.artifact_kind != ExternalArtifactKind::RustdocJson {
            return failed_artifact_production(
                "rust.rustdoc.wrong_artifact_kind",
                "Rust rustdoc producer requires a rustdoc_json artifact",
                limits,
            );
        }
        let artifact = match read_exact_artifact_while(&request.path, limits, || {
            cancellation.is_some_and(CancellationToken::is_cancelled)
        }) {
            Ok(artifact) => artifact,
            Err(diagnostic) => return ArtifactProduction::failed(diagnostic, limits),
        };
        self.produce_loaded_artifact(request, limits, cancellation, &artifact)
    }
}

impl RustdocJsonPackProducer {
    pub fn produce_loaded_artifact(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
        artifact: &ExactArtifact,
    ) -> ArtifactProduction {
        if request.artifact_kind != ExternalArtifactKind::RustdocJson {
            return failed_artifact_production(
                "rust.rustdoc.wrong_artifact_kind",
                "Rust rustdoc producer requires a rustdoc_json artifact",
                limits,
            );
        }
        if artifact.bytes().len() as u64 > limits.max_artifact_bytes {
            return failed_artifact_production(
                "limit.artifact_bytes",
                format!("exact artifact exceeds {} bytes", limits.max_artifact_bytes),
                limits,
            );
        }
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return failed_artifact_production(
                "artifact.cancelled",
                "rustdoc artifact production was cancelled",
                limits,
            );
        }
        produce_loaded_document(request, limits, cancellation, artifact)
    }

    /// Produce one declaration pack from an explicitly named set of rustdoc
    /// JSON documents. The source-set reader has already authenticated the
    /// paths and bytes; this method only decodes the retained entries and
    /// combines their typed facts. `crates` is `(crate name, relative path)`
    /// in the pinned source-set specification.
    pub fn produce_loaded_source_set(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
        artifact: &ExactArtifact,
        crates: &[(String, String)],
    ) -> ArtifactProduction {
        if request.artifact_kind != ExternalArtifactKind::RustdocJsonSet {
            return failed_artifact_production(
                "rust.rustdoc.wrong_artifact_kind",
                "Rust rustdoc source-set producer requires a rustdoc_json_set artifact",
                limits,
            );
        }
        if crates.is_empty() {
            return failed_artifact_production(
                "rust.rustdoc.empty_source_set",
                "Rust rustdoc source set must contain at least one crate",
                limits,
            );
        }
        if artifact.bytes().len() as u64 > limits.max_artifact_bytes {
            return failed_artifact_production(
                "limit.artifact_bytes",
                format!("exact artifact exceeds {} bytes", limits.max_artifact_bytes),
                limits,
            );
        }
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return failed_artifact_production(
                "artifact.cancelled",
                "rustdoc source-set production was cancelled",
                limits,
            );
        }

        let mut ordered = crates.to_vec();
        ordered.sort();
        if ordered.windows(2).any(|entries| {
            entries[0] == entries[1] || entries[0].0 == entries[1].0 || entries[0].1 == entries[1].1
        }) {
            return failed_artifact_production(
                "rust.rustdoc.duplicate_source",
                "Rust rustdoc source set contains a duplicate crate name or source path",
                limits,
            );
        }
        let entries = artifact
            .source_entries()
            .iter()
            .map(|entry| (entry.relative_path().to_owned(), entry.bytes()))
            .collect::<RandomHashMap<_, _>>();
        let mut productions = Vec::with_capacity(ordered.len());
        let mut links = SourceSetLinks::default();
        // Index only declaration binders before projecting cross-document impls.
        // This request-local metadata is bounded by the authenticated source set;
        // the join still decides whether an owner was actually emitted.
        for (crate_name, path) in &ordered {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return failed_artifact_production(
                    "artifact.cancelled",
                    "rustdoc source-set production was cancelled",
                    limits,
                );
            }
            if let Some(bytes) = entries.get(path)
                && let Ok(document) = decode_rustdoc_json_document(request, bytes)
            {
                let Ok(root) = validated_document_root(request, &document, Some(crate_name)) else {
                    continue;
                };
                let names = match item_names(&document, root, cancellation) {
                    Ok(names) => names,
                    Err(NameIndexError::Cancelled) => {
                        return failed_artifact_production(
                            "artifact.cancelled",
                            "rustdoc source-set production was cancelled",
                            limits,
                        );
                    }
                    Err(NameIndexError::Limit) => continue,
                };
                for (id, item) in &document.index {
                    if cancellation.is_some_and(CancellationToken::is_cancelled) {
                        return failed_artifact_production(
                            "artifact.cancelled",
                            "rustdoc source-set production was cancelled",
                            limits,
                        );
                    }
                    if item.crate_id != root.crate_id {
                        continue;
                    }
                    let generics = match &item.inner {
                        ItemEnum::Struct(item) => &item.generics,
                        ItemEnum::Enum(item) => &item.generics,
                        ItemEnum::Union(item) => &item.generics,
                        _ => continue,
                    };
                    if let Some(name) = names.get(id) {
                        links
                            .owner_parameters
                            .insert(name.clone(), generic_names(generics));
                    }
                }
            }
        }
        for (crate_name, path) in &ordered {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return failed_artifact_production(
                    "artifact.cancelled",
                    "rustdoc source-set production was cancelled",
                    limits,
                );
            }
            let Some(bytes) = entries.get(path) else {
                return failed_artifact_production(
                    "rust.rustdoc.source_missing",
                    format!("rustdoc source set does not contain {path}"),
                    limits,
                );
            };
            let consumed = productions
                .iter()
                .map(production_record_count)
                .sum::<usize>();
            let remaining = limits.max_records.saturating_sub(consumed);
            let mut production = produce_loaded_json_document(
                request,
                limits,
                cancellation,
                artifact.sha256(),
                Some(crate_name),
                Some(path),
                bytes,
                &mut links,
            );
            if production_record_count(&production) > remaining {
                links.declarations_interrupted = true;
            }
            limit_production_records(&mut production, remaining, limits);
            for diagnostic in &mut production.diagnostics {
                if diagnostic.severity == ProducerDiagnosticSeverity::Warning
                    && diagnostic.declaration.is_none()
                    && diagnostic.source_entry.is_none()
                {
                    diagnostic.source_entry = Some(path.clone().into_boxed_str());
                }
            }
            productions.push(production);
        }
        merge_source_set_productions(request, limits, artifact.sha256(), productions, &links)
    }
}

fn produce_loaded_document(
    request: &ArtifactProductionRequest,
    limits: &ArtifactProducerLimits,
    cancellation: Option<&CancellationToken>,
    artifact: &ExactArtifact,
) -> ArtifactProduction {
    produce_loaded_json_document(
        request,
        limits,
        cancellation,
        artifact.sha256(),
        None,
        None,
        artifact.bytes(),
        &mut SourceSetLinks::default(),
    )
}

fn decode_rustdoc_json_document(
    request: &ArtifactProductionRequest,
    bytes: &[u8],
) -> Result<RustdocCrate, (&'static str, String)> {
    let envelope: RustdocVersionEnvelope = serde_json::from_slice(bytes).map_err(|error| {
        (
            "rust.rustdoc.invalid_json",
            format!("could not decode rustdoc JSON version: {error}"),
        )
    })?;
    if envelope.format_version != RUSTDOC_FORMAT_VERSION {
        return Err((
            "rust.rustdoc.unsupported_version",
            format!(
                "rustdoc JSON format {} is unsupported; this producer accepts {}",
                envelope.format_version, RUSTDOC_FORMAT_VERSION
            ),
        ));
    }
    validate_conversion_certificate(
        envelope.conversion.as_ref(),
        RUSTDOC_PRODUCER_CONTRACT,
        CONVERTED_FIELDS_CONSUMED,
    )
    .map_err(|message| ("rust.rustdoc.uncertified_conversion", message.to_owned()))?;
    let document: RustdocCrate = serde_json::from_slice(bytes).map_err(|error| {
        (
            "rust.rustdoc.invalid_json",
            format!(
                "could not decode rustdoc JSON format {}: {error}",
                RUSTDOC_FORMAT_VERSION
            ),
        )
    })?;
    let requested_versions = request
        .activation
        .iter()
        .filter_map(|selector| selector.package.as_ref())
        .filter_map(|package| package.version.as_deref())
        .map(|version| version.strip_prefix('=').unwrap_or(version))
        .collect::<RandomHashSet<_>>();
    let version_mismatch =
        if let Some(approximation) = &request.provenance.rust_artifact_approximation {
            document.crate_version.as_deref() != Some(approximation.built_from_version.as_str())
                || requested_versions.len() != 1
                || !requested_versions.contains(
                    approximation
                        .activation_version_requirement
                        .strip_prefix('=')
                        .unwrap_or(&approximation.activation_version_requirement),
                )
        } else {
            requested_versions.len() > 1
                || requested_versions
                    .iter()
                    .next()
                    .is_some_and(|expected| document.crate_version.as_deref() != Some(*expected))
        };
    if version_mismatch {
        return Err((
            "rust.rustdoc.crate_version_mismatch",
            format!(
                "rustdoc crate version {:?} does not match requested package versions {:?}",
                document.crate_version, requested_versions
            ),
        ));
    }
    if request.activation.iter().any(|selector| {
        !selector.targets.is_empty() && !selector.targets.contains(&document.target.triple)
    }) {
        return Err((
            "rust.rustdoc.target_mismatch",
            format!(
                "rustdoc target {} does not match requested activation targets",
                document.target.triple
            ),
        ));
    }
    Ok(document)
}

#[allow(clippy::too_many_arguments)]
fn produce_loaded_json_document(
    request: &ArtifactProductionRequest,
    limits: &ArtifactProducerLimits,
    cancellation: Option<&CancellationToken>,
    artifact_sha256: &str,
    expected_crate: Option<&str>,
    source_relative_path: Option<&str>,
    bytes: &[u8],
    links: &mut SourceSetLinks,
) -> ArtifactProduction {
    let document = match decode_rustdoc_json_document(request, bytes) {
        Ok(document) => document,
        Err((code, message)) => return failed_artifact_production(code, message, limits),
    };
    let document_limits = ArtifactProducerLimits {
        max_records: limits.max_records.max(document.index.len()),
        ..*limits
    };
    collect_cross_document_reexports(&document, source_relative_path, links);
    let mut production = produce_document(
        request,
        &document_limits,
        artifact_sha256,
        &document,
        cancellation,
        expected_crate,
        source_relative_path,
        links,
    );
    if source_relative_path.is_none()
        && let Some(pack) = production.pack.as_mut()
    {
        for shard in &mut pack.shards {
            if let AuthoredPayload::DeclarationFacts { types, .. } = &mut shard.payload {
                retain_available_alias_targets(types);
                if types.iter().any(|ty| ty.alias_target.is_some()) {
                    pack.schema_version = RUSTDOC_PACK_MAX_SCHEMA_VERSION;
                }
            }
        }
    }
    let mut reexports_limited = false;
    let mut reexports_unsupported = false;
    if source_relative_path.is_none()
        && let Some(pack) = production.pack.as_mut()
    {
        let Ok((routes, limited, unsupported_named, unsupported_glob)) =
            collect_external_reexports_status(&document, limits.max_records, cancellation)
        else {
            return failed_artifact_production(
                "artifact.cancelled",
                "rustdoc re-export collection was cancelled",
                limits,
            );
        };
        pack.rust_external_reexports = routes;
        if limited || unsupported_named {
            // Missing routes affect only the facade join, not retained declarations.
            pack.rust_external_reexports_truncated = true;
        }
        pack.rust_external_reexports_glob_incomplete = unsupported_glob;
        reexports_limited = limited;
        reexports_unsupported = unsupported_named || unsupported_glob;
        if !pack.rust_external_reexports.is_empty()
            || pack.rust_external_reexports_truncated
            || pack.rust_external_reexports_glob_incomplete
        {
            pack.schema_version = pack.schema_version.max(
                brokk_bifrost_semantic::analyzer::semantic_model::RUST_EXTERNAL_REEXPORTS_MIN_SCHEMA_VERSION);
        }
    }
    // The generic producer treats every warning as a declaration gap. These
    // two warnings describe only routes that the schema-29 carrier records as
    // incomplete; retained declarations remain complete. Other warnings and
    // suppressed diagnostics still keep the pack Partial.
    if source_relative_path.is_none()
        && production.pack.as_ref().is_some_and(|pack| {
            !pack.rust_external_reexports.is_empty()
                || pack.rust_external_reexports_truncated
                || pack.rust_external_reexports_glob_incomplete
        })
        && production.suppressed_diagnostics.total() == 0
        && production.diagnostics.iter().all(|diagnostic| {
            matches!(
                diagnostic.code.as_str(),
                "rust.rustdoc.glob_reexport_unexpanded"
                    | "rust.rustdoc.reexport_target_unavailable"
            )
        })
    {
        production.completeness = Completeness::Complete;
        if let Some(pack) = production.pack.as_mut() {
            pack.completeness = Completeness::Complete;
        }
    }
    if reexports_limited {
        push_limit_warning(
            &mut production,
            limits,
            "limit.rust_external_reexports",
            format!(
                "rustdoc re-export extraction stopped after {} routes; routes beyond the limit are missing evidence, not absent",
                limits.max_records
            ),
        );
    }
    if reexports_unsupported {
        push_limit_warning(
            &mut production,
            limits,
            "rust.external_reexports.unsupported_surface",
            "public local module aliases or unsupported glob targets leave Rust facade routes incomplete; missing routes are missing evidence, not absence".to_owned(),
        );
    }
    assert_pack_schema_within_producer_max(production.pack.as_ref());
    production
}

/// Preserve only root-reachable Rustdoc edges. Item IDs and external crate IDs
/// remain document-local until activation joins the selected Cargo graph.
///
/// The flags report a route limit hit and an unsupported public alias or glob.
/// Either makes a missing route missing evidence rather than absence.
fn collect_external_reexports_status(
    document: &RustdocCrate,
    max_records: usize,
    cancellation: Option<&CancellationToken>,
) -> Result<(Vec<RustExternalReexport>, bool, bool, bool), ()> {
    collect_external_reexports_status_with_probe(document, max_records, cancellation, || {})
}

fn collect_external_reexports_status_with_probe(
    document: &RustdocCrate,
    max_records: usize,
    cancellation: Option<&CancellationToken>,
    mut visit: impl FnMut(),
) -> Result<(Vec<RustExternalReexport>, bool, bool, bool), ()> {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return Err(());
    }
    let Some(root) = document.index.get(&document.root) else {
        return Ok((Vec::new(), false, false, false));
    };
    let mut ordered = document.index.values().collect::<Vec<_>>();
    ordered.sort_by_key(|item| item.id);
    let Some(parents) = parent_index(&ordered, cancellation) else {
        return Err(());
    };
    let mut result = Vec::new();
    let mut unsupported_named = false;
    let mut unsupported_glob = false;
    let mut retained_competitors = 0usize;
    for item in ordered {
        visit();
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err(());
        }
        // One record past the limit proves the limit was exceeded.
        if result.len() > max_records {
            break;
        }
        let path = match public_module_item_path(document, &parents, item.id) {
            Ok(Some(path)) => path,
            Ok(None) => continue,
            Err(()) => {
                if matches!(&item.inner, ItemEnum::Use(import) if import.is_glob) {
                    unsupported_glob = true;
                } else {
                    unsupported_named = true;
                }
                continue;
            }
        };
        match &item.inner {
            ItemEnum::Use(import) => {
                let Some(target_id) = import.id else {
                    if import.is_glob {
                        unsupported_glob = true;
                    } else {
                        unsupported_named = true;
                    }
                    continue;
                };
                let target = rust_external_target(document, root.crate_id, target_id);
                if import.is_glob {
                    let Some(target) = target else {
                        unsupported_glob = true;
                        continue;
                    };
                    let Some(summary) = document.paths.get(&target_id) else {
                        unsupported_glob = true;
                        continue;
                    };
                    if summary.kind != rustdoc_types::ItemKind::Module {
                        unsupported_glob = true;
                        continue;
                    }
                    let Some(parent_id) = parents.get(&item.id) else {
                        unsupported_glob = true;
                        continue;
                    };
                    let Some(parent) = document.index.get(parent_id) else {
                        unsupported_glob = true;
                        continue;
                    };
                    let ItemEnum::Module(module) = &parent.inner else {
                        unsupported_glob = true;
                        continue;
                    };
                    let mut explicit_competitors = Vec::new();
                    let mut glob_competitors = Vec::new();
                    let mut unresolved_glob_competitor = false;
                    for sibling_id in &module.items {
                        if *sibling_id == item.id {
                            continue;
                        }
                        let Some(sibling) = document.index.get(sibling_id) else {
                            continue;
                        };
                        retained_competitors = retained_competitors.saturating_add(1);
                        if retained_competitors > max_records {
                            unsupported_glob = true;
                            unresolved_glob_competitor = true;
                            break;
                        }
                        match &sibling.inner {
                            ItemEnum::Use(other) if other.is_glob => {
                                if let Some(id) = other.id
                                    && let Some(target) =
                                        rust_external_target(document, root.crate_id, id)
                                {
                                    glob_competitors.push(target);
                                } else {
                                    unresolved_glob_competitor = true;
                                }
                            }
                            _ => {
                                if let Some(name) = match &sibling.inner {
                                    ItemEnum::Use(import) => Some(&import.name),
                                    _ => sibling.name.as_ref(),
                                } {
                                    explicit_competitors.push(name.clone());
                                }
                            }
                        }
                    }
                    explicit_competitors.sort();
                    explicit_competitors.dedup();
                    glob_competitors
                        .sort_by(|a, b| a.path.cmp(&b.path).then(a.item_id.cmp(&b.item_id)));
                    result.push(RustExternalReexport::GlobUse {
                        facade_module_path: brokk_bifrost_analysis::analyzer::semantic_model::rust_qualified_path::RustQualifiedPath::parse(&path)
                            .and_then(|segments| segments.parent_and_member().map(|(parent, _)| parent))
                            .unwrap_or_else(|| path.clone()),
                        use_item_id: item.id.0,
                        target_module: target,
                        explicit_competitors,
                        glob_competitors,
                        unresolved_glob_competitor,
                    });
                } else {
                    if let Some(target) = target {
                        result.push(RustExternalReexport::ExplicitUse {
                            facade_path: path,
                            use_item_id: item.id.0,
                            target,
                        });
                    } else if !document.index.get(&target_id).is_some_and(|local| {
                        local.crate_id == root.crate_id
                            && !matches!(&local.inner, ItemEnum::Module(_) | ItemEnum::Use(_))
                    }) {
                        unsupported_named = true;
                    }
                }
            }
            _ if item.crate_id != root.crate_id => {
                if let Some(original) = rust_external_target(document, root.crate_id, item.id) {
                    result.push(RustExternalReexport::InlinedItem {
                        facade_path: path,
                        local_item_id: item.id.0,
                        original,
                    });
                } else {
                    unsupported_named = true;
                }
            }
            _ => {}
        }
    }
    let limited = result.len() > max_records;
    result.truncate(max_records);
    Ok((result, limited, unsupported_named, unsupported_glob))
}

#[cfg(test)]
pub(crate) fn collect_external_reexports(
    document: &RustdocCrate,
    max_records: usize,
) -> (Vec<RustExternalReexport>, bool, bool) {
    let (routes, limited, named, glob) =
        collect_external_reexports_status(document, max_records, None)
            .expect("uncancelled test collection");
    (routes, limited, named || glob)
}

fn rust_external_target(
    document: &RustdocCrate,
    root_crate_id: u32,
    item_id: Id,
) -> Option<RustExternalReexportTarget> {
    let summary = document.paths.get(&item_id)?;
    if summary.crate_id == root_crate_id || summary.path.len() > 64 {
        return None;
    }
    let external = document.external_crates.get(&summary.crate_id)?;
    if summary.path.first()? != &external.name
        || summary
            .path
            .iter()
            .any(|part| part.is_empty() || part.len() > MAX_MODEL_NAME_BYTES)
    {
        return None;
    }
    // External summaries prove only these four namespaces. External Struct
    // hides its field shape (plain vs unit/tuple), so Struct, Union,
    // TypeAlias, Constant, Static, Macro and all other kinds stay unmapped.
    // An exact item in `index` can refine Struct using its own inner kind.
    let namespace = document
        .index
        .get(&item_id)
        .and_then(|item| match &item.inner {
            ItemEnum::Struct(value) => Some(match value.kind {
                StructKind::Unit | StructKind::Tuple(_) => RustReexportTargetNamespace::Both,
                StructKind::Plain { .. } => RustReexportTargetNamespace::TypeOrModule,
            }),
            _ => None,
        })
        .or(match summary.kind {
            rustdoc_types::ItemKind::Function => Some(RustReexportTargetNamespace::Value),
            rustdoc_types::ItemKind::Module
            | rustdoc_types::ItemKind::Enum
            | rustdoc_types::ItemKind::Trait => Some(RustReexportTargetNamespace::TypeOrModule),
            _ => None,
        });
    Some(RustExternalReexportTarget {
        namespace,
        external_crate_id: summary.crate_id,
        external_crate_name: external.name.clone(),
        item_id: item_id.0,
        path: summary.path.clone(),
    })
}

fn public_module_item_path(
    document: &RustdocCrate,
    parents: &HashMap<Id, Id>,
    item_id: Id,
) -> Result<Option<String>, ()> {
    let mut parts = Vec::new();
    let mut current = item_id;
    let mut visited = HashSet::default();
    while visited.insert(current) {
        if parts.len() >= 64 {
            return Err(());
        }
        let Some(item) = document.index.get(&current) else {
            return Ok(None);
        };
        if current != document.root && !matches!(item.visibility, RustVisibility::Public) {
            return Ok(None);
        }
        if current != item_id
            && current != document.root
            && !matches!(item.inner, ItemEnum::Module(_))
        {
            return Ok(None);
        }
        let name = match &item.inner {
            ItemEnum::Use(import) => import.name.clone(),
            _ => match &item.name {
                Some(name) => name.clone(),
                None => return Ok(None),
            },
        };
        parts.push(name);
        if current == document.root {
            parts.reverse();
            return if parts.iter().map(String::len).sum::<usize>() < MAX_MODEL_NAME_BYTES {
                Ok(Some(parts.join(".")))
            } else {
                Err(())
            };
        }
        let Some(parent) = parents.get(&current) else {
            return Ok(None);
        };
        current = *parent;
    }
    Ok(None)
}

fn limit_production_records(
    production: &mut ArtifactProduction,
    max_records: usize,
    limits: &ArtifactProducerLimits,
) {
    let Some(pack) = production.pack.as_mut() else {
        return;
    };
    let Some(shard) = pack.shards.first_mut() else {
        return;
    };
    let AuthoredPayload::DeclarationFacts {
        types,
        members,
        relations,
        ..
    } = &mut shard.payload
    else {
        return;
    };
    let original_count = types.len() + members.len() + relations.len();
    if original_count <= max_records {
        return;
    }
    types.truncate(max_records);
    let remaining = max_records.saturating_sub(types.len());
    members.truncate(remaining);
    let remaining = remaining.saturating_sub(members.len());
    relations.truncate(remaining);
    production.completeness = Completeness::Partial;
    push_limit_warning(
        production,
        limits,
        "limit.records",
        format!("source set stopped after {max_records} aggregate records"),
    );
}

fn push_limit_warning(
    production: &mut ArtifactProduction,
    limits: &ArtifactProducerLimits,
    code: &str,
    message: String,
) {
    let diagnostic = ProducerDiagnostic {
        severity: ProducerDiagnosticSeverity::Warning,
        source_entry: None,
        code: code.to_owned(),
        location: None,
        declaration: None,
        message,
    };
    if production.diagnostics.len() < limits.max_diagnostics
        || admit_into_full_diagnostics(
            &mut production.diagnostics,
            &mut production.suppressed_diagnostics,
            diagnostic.severity == ProducerDiagnosticSeverity::Warning,
            |retained| retained.severity == ProducerDiagnosticSeverity::Warning,
        )
    {
        production.diagnostics.push(diagnostic);
    }
}

fn production_record_count(production: &ArtifactProduction) -> usize {
    production
        .pack
        .as_ref()
        .and_then(|pack| pack.shards.first())
        .and_then(|shard| match &shard.payload {
            AuthoredPayload::DeclarationFacts {
                types,
                members,
                relations,
                ..
            } => Some(types.len() + members.len() + relations.len()),
            _ => None,
        })
        .unwrap_or_default()
}

fn union_facts<T: PartialEq>(target: &mut Vec<T>, source: Vec<T>) {
    for value in source {
        if !target.contains(&value) {
            target.push(value);
        }
    }
}

// Transient presentation identity: unlike a member ID, this does not depend
// on the precision of the per-document signature projection.
#[derive(PartialEq, Eq, Hash)]
struct ImplMemberKey {
    owner: String,
    name: String,
    kind: u8,
    implementation: String,
}

enum ImplMemberOrigin {
    Local,
    NewlyDeferred,
}

struct ImplMemberPresentation {
    key: ImplMemberKey,
    origin: ImplMemberOrigin,
}

#[derive(Default)]
struct SourceSetLinks {
    owner_parameters: RandomHashMap<String, Vec<String>>,
    impl_member_presentations: RandomHashMap<String, RandomHashMap<String, ImplMemberPresentation>>,
    reexports: Vec<CrossDocumentReexport>,
    private_modules: RandomHashSet<String>,
    generic_trait_impls: Vec<(String, GenericTraitImplFact)>,
    concrete_trait_impls: Vec<(String, ImplementedTraitFact)>,
    callable_impl_members: RandomHashSet<String>,
    incomplete_callable_owner_refs: Vec<TypeRef>,
    pending_external_members: Vec<(String, ProducerDiagnostic)>,
    declarations_interrupted: bool,
    incomplete_implementation_owners: RandomHashSet<String>,
    incomplete_generic_traits: RandomHashSet<String>,
    auto_traits: RandomHashSet<String>,
}

// Like the JVM producer's selective certification, decoding failures block an
// owner's families without making unrelated owners incomplete. Source-set
// trait membership is checked after all documents have been joined.
fn certify_callable_families(
    types: &[TypeFact],
    members: &mut [MemberFact],
    links: &SourceSetLinks,
) {
    let owners = types
        .iter()
        .filter(|ty| {
            !matches!(
                ty.type_kind,
                TypeKind::Module | TypeKind::Trait | TypeKind::TypeAlias
            )
        })
        .map(|ty| (&ty.id, &ty.name))
        .collect::<RandomHashMap<_, _>>();
    let trait_ids = types
        .iter()
        .filter(|ty| ty.type_kind == TypeKind::Trait)
        .map(|ty| ty.id.as_str())
        .collect::<RandomHashSet<_>>();
    let trait_names = types
        .iter()
        .filter(|ty| ty.type_kind == TypeKind::Trait)
        .map(|ty| ty.name.as_str())
        .collect::<RandomHashSet<_>>();
    let family_key = |member: &MemberFact| {
        // Serialization is only a transient key for a structured self pattern,
        // never a source-text interpretation or a persisted database value.
        (
            member.owner.clone(),
            member.name.clone(),
            member.is_static,
            serde_json::to_string(&member.self_form).expect("serializable Rust self form"),
            member
                .signature
                .as_ref()
                .map(|signature| signature.parameters.len()),
        )
    };
    let incomplete_ids = links
        .incomplete_callable_owner_refs
        .iter()
        .filter_map(|owner| match owner {
            TypeRef::Declared { id, .. } => Some(id.as_str()),
            _ => None,
        })
        .collect::<RandomHashSet<_>>();
    let incomplete_names = links
        .incomplete_callable_owner_refs
        .iter()
        .filter_map(|owner| match owner {
            TypeRef::Named { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect::<RandomHashSet<_>>();
    let mut families = RandomHashMap::new();
    for member in members.iter() {
        let eligible = !links.declarations_interrupted
            && links.callable_impl_members.contains(&member.id)
            && owners.get(&member.owner).is_some_and(|name| {
                !incomplete_ids.contains(member.owner.as_str())
                    && !incomplete_names.contains(name.as_str())
            })
            && member
                .implemented_trait
                .as_ref()
                .is_none_or(|trait_| match trait_ {
                    TypeRef::Declared { id, .. } => trait_ids.contains(id.as_str()),
                    TypeRef::Named { name, .. } => trait_names.contains(name.as_str()),
                    _ => false,
                });
        families
            .entry(family_key(member))
            .and_modify(|complete| *complete &= eligible)
            .or_insert(eligible);
    }
    for member in members {
        member.callable_family_complete = families[&family_key(member)];
    }
}

struct CrossDocumentReexport {
    source_entry: Option<Box<str>>,
    location: String,
    target: String,
    alias: String,
    module: bool,
}

fn collect_cross_document_reexports(
    document: &RustdocCrate,
    source_relative_path: Option<&str>,
    links: &mut SourceSetLinks,
) {
    let Some(root) = document.index.get(&document.root) else {
        return;
    };
    let Ok(names) = item_names(document, root, None) else {
        return;
    };
    let mut items = document.index.values().collect::<Vec<_>>();
    items.sort_by_key(|item| item.id);
    let Some(parents) = parent_index(&items, None) else {
        return;
    };
    let Some(visible) = visible_items(document, &items, &parents, None) else {
        return;
    };
    for item in items {
        if item.crate_id == root.crate_id
            && item.id != document.root
            && matches!(item.inner, ItemEnum::Module(_))
            && !matches!(item.visibility, RustVisibility::Public)
            && let Some(name) = names.get(&item.id)
        {
            links.private_modules.insert(name.clone());
        }
        let ItemEnum::Use(import) = &item.inner else {
            continue;
        };
        if import.is_glob || !visible.contains(&item.id) {
            continue;
        }
        let Some(id) = import.id else { continue };
        if document.index.contains_key(&id) {
            continue;
        }
        let Some(summary) = document.paths.get(&id) else {
            continue;
        };
        let Some(external) = document.external_crates.get(&summary.crate_id) else {
            continue;
        };
        // Crate ids and item ids are document-local. Join by the external
        // crate summary and path segments, never the rendered Use.source.
        if summary.path.first() != Some(&external.name) {
            continue;
        }
        let Some(parent) = parents.get(&item.id).and_then(|id| names.get(id)) else {
            continue;
        };
        links.reexports.push(CrossDocumentReexport {
            source_entry: source_relative_path.map(Into::into),
            location: format!("item.{}", item.id.0),
            target: summary.path.join("."),
            alias: format!("{parent}.{}", import.name),
            module: summary.kind == rustdoc_types::ItemKind::Module,
        });
    }
}

fn reexport_alias(
    export: &CrossDocumentReexport,
    name: &str,
    private_modules: &RandomHashSet<String>,
) -> Option<String> {
    if name == export.target {
        return Some(export.alias.clone());
    }
    if !export.module {
        return None;
    }
    let tail = name
        .strip_prefix(&export.target)
        .filter(|tail| tail.starts_with('.'))?;
    // A public item can have a canonical identity under a private module.
    // Only its actual public reexport route is an exported descendant.
    // Check visibility after prefix selection so unrelated records stay cheap.
    if private_modules.iter().any(|module| {
        module
            .strip_prefix(&export.target)
            .is_some_and(|tail| tail.starts_with('.'))
            && (name == module
                || name
                    .strip_prefix(module)
                    .is_some_and(|tail| tail.starts_with('.')))
    }) {
        return None;
    }
    Some(format!("{}{tail}", export.alias))
}

fn apply_cross_document_reexports(
    exports: &[CrossDocumentReexport],
    types: &mut [TypeFact],
    members: &mut [MemberFact],
    private_modules: &RandomHashSet<String>,
) -> RandomHashSet<usize> {
    let mut resolved = RandomHashSet::new();
    let owners = types
        .iter()
        .map(|fact| {
            (
                fact.id.clone(),
                std::iter::once(&fact.name)
                    .chain(&fact.aliases)
                    .cloned()
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<RandomHashMap<_, _>>();
    let nominal_aliases = types
        .iter()
        .filter(|fact| fact.type_kind != TypeKind::Module && !fact.aliases.is_empty())
        .map(|fact| (fact.name.clone(), fact.aliases.clone()))
        .collect::<Vec<_>>();
    // Match the defining document's names and local aliases. Cross-document
    // rule order must not invent transitive aliases or expand alias cycles.
    for fact in types.iter_mut() {
        let mut names = std::iter::once(&fact.name)
            .chain(&fact.aliases)
            .cloned()
            .collect::<Vec<_>>();
        // Associated type declarations inherit their nominal owner's public
        // routes just as methods do; their canonical owner can be private.
        for (owner, aliases) in &nominal_aliases {
            if let Some(tail) = fact
                .name
                .strip_prefix(owner)
                .filter(|tail| tail.starts_with('.'))
            {
                names.extend(aliases.iter().map(|alias| format!("{alias}{tail}")));
            }
        }
        let mut aliases = Vec::new();
        for (index, export) in exports.iter().enumerate() {
            for name in &names {
                if let Some(alias) = reexport_alias(export, name, private_modules) {
                    aliases.push(alias);
                    resolved.insert(index);
                }
            }
        }
        union_facts(&mut fact.aliases, aliases);
    }
    for fact in members.iter_mut() {
        if let Some(owners) = owners.get(&fact.owner) {
            let names = owners
                .iter()
                .map(|owner| format!("{owner}.{}", fact.name))
                .collect::<Vec<_>>();
            let mut aliases = Vec::new();
            for (index, export) in exports.iter().enumerate() {
                for name in names.iter().chain(&fact.aliases) {
                    if let Some(alias) = reexport_alias(export, name, private_modules) {
                        aliases.push(alias);
                        resolved.insert(index);
                    }
                }
            }
            union_facts(&mut fact.aliases, aliases);
        }
    }
    resolved
}

// Alias claims must not inherit the lossy signature converter's fallbacks.
// Recursion is bounded by the producer's signature-depth limit.
fn exact_alias_target(
    ty: &Type,
    parameters: &[String],
    document: &RustdocCrate,
    type_ids: &HashMap<Id, String>,
    limits: &ArtifactProducerLimits,
    diagnostics: &mut BoundedProducerDiagnostics,
    depth: usize,
) -> Option<TypeRef> {
    if depth >= limits.max_signature_depth {
        return None;
    }
    let mut convert = |ty: &Type| {
        exact_alias_target(
            ty,
            parameters,
            document,
            type_ids,
            limits,
            diagnostics,
            depth + 1,
        )
    };
    Some(match ty {
        Type::Generic(name) if parameters.contains(name) => {
            TypeRef::TypeParameter { name: name.clone() }
        }
        Type::Primitive(name) => TypeRef::named(name),
        Type::Tuple(elements) => TypeRef::Tuple {
            elements: elements.iter().map(&mut convert).collect::<Option<_>>()?,
        },
        Type::BorrowedRef {
            type_,
            is_mutable: false,
            ..
        } => TypeRef::ByRef {
            element: Box::new(convert(type_)?),
            reference_kind: TypeRefReferenceKind::Lvalue,
        },
        Type::Slice(element) => TypeRef::Slice {
            element: Box::new(convert(element)?),
        },
        Type::ResolvedPath(path) => {
            let arguments = match path.args.as_deref() {
                None => Vec::new(),
                Some(GenericArgs::AngleBracketed { args, constraints })
                    if constraints.is_empty() =>
                {
                    let mut arguments = Vec::new();
                    for arg in args {
                        match arg {
                            GenericArg::Type(ty) => arguments.push(convert(ty)?),
                            GenericArg::Lifetime(_) => {}
                            _ => return None,
                        }
                    }
                    arguments
                }
                _ => return None,
            };
            let mut target = path_type_ref(path, document, type_ids, limits, diagnostics, depth);
            match &mut target {
                TypeRef::Declared {
                    arguments: existing,
                    ..
                }
                | TypeRef::Named {
                    arguments: existing,
                    ..
                } => *existing = arguments,
                _ => unreachable!("path projection produces a declared or named reference"),
            }
            target
        }
        _ => return None,
    })
}

// An external rustdoc path alone does not establish that a declaration exists
// in this production. Delay this check until the source-set join is complete.
fn retain_available_alias_targets(types: &mut [TypeFact]) {
    let ids: RandomHashSet<_> = types.iter().map(|ty| ty.id.clone()).collect();
    let names: RandomHashSet<_> = types.iter().map(|ty| ty.name.clone()).collect();
    for ty in types {
        let mut pending = ty.alias_target.iter().collect::<Vec<_>>();
        let mut available = true;
        while let Some(target) = pending.pop() {
            match target {
                TypeRef::Declared { id, arguments, .. } => {
                    available &= ids.contains(id);
                    pending.extend(arguments);
                }
                TypeRef::Named {
                    name, arguments, ..
                } => {
                    available &= names.contains(name)
                        || super::call_conversion::primitive_for_spelling(name).is_some()
                        || matches!(name.as_str(), "f16" | "f128");
                    pending.extend(arguments);
                }
                TypeRef::Tuple { elements } => pending.extend(elements),
                TypeRef::ByRef { element, .. } | TypeRef::Slice { element } => {
                    pending.push(element)
                }
                TypeRef::TypeParameter { .. } => {}
                _ => available = false,
            }
        }
        if !available {
            ty.alias_target = None;
        }
    }
}

// Contract conversion preserves binders nested inside constructors. Existing
// callable signature projection remains conservative about enclosing binders.
fn contract_type_ref(
    ty: &Type,
    document: &RustdocCrate,
    type_ids: &HashMap<Id, String>,
    limits: &ArtifactProducerLimits,
    diagnostics: &mut BoundedProducerDiagnostics,
    depth: usize,
) -> TypeRef {
    if depth >= limits.max_signature_depth {
        diagnostics.warning(
            "limit.signature_depth",
            None,
            "Rust contract type exceeded signature depth",
        );
        return TypeRef::Unknown;
    }
    match ty {
        Type::Generic(name) => TypeRef::TypeParameter { name: name.clone() },
        Type::ResolvedPath(path) => {
            let mut result = path_type_ref(path, document, type_ids, limits, diagnostics, depth);
            if let TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. } =
                &mut result
            {
                *arguments =
                    if let Some(GenericArgs::AngleBracketed { args, .. }) = path.args.as_deref() {
                        args.iter()
                            .filter_map(|arg| match arg {
                                GenericArg::Type(ty) => Some(contract_type_ref(
                                    ty,
                                    document,
                                    type_ids,
                                    limits,
                                    diagnostics,
                                    depth + 1,
                                )),
                                GenericArg::Const(_) => Some(TypeRef::Unknown),
                                _ => None,
                            })
                            .collect()
                    } else {
                        Vec::new()
                    };
            }
            result
        }
        Type::Slice(element) => TypeRef::Slice {
            element: Box::new(contract_type_ref(
                element,
                document,
                type_ids,
                limits,
                diagnostics,
                depth + 1,
            )),
        },
        Type::Array { type_, len } => TypeRef::FixedArray {
            element: Box::new(contract_type_ref(
                type_,
                document,
                type_ids,
                limits,
                diagnostics,
                depth + 1,
            )),
            length: len.clone(),
        },
        Type::BorrowedRef { type_, .. } => TypeRef::ByRef {
            element: Box::new(contract_type_ref(
                type_,
                document,
                type_ids,
                limits,
                diagnostics,
                depth + 1,
            )),
            reference_kind: TypeRefReferenceKind::Lvalue,
        },
        Type::RawPointer { type_, .. } => TypeRef::Pointer {
            element: Box::new(contract_type_ref(
                type_,
                document,
                type_ids,
                limits,
                diagnostics,
                depth + 1,
            )),
        },
        Type::Tuple(elements) => TypeRef::Tuple {
            elements: elements
                .iter()
                .map(|ty| contract_type_ref(ty, document, type_ids, limits, diagnostics, depth + 1))
                .collect(),
        },
        Type::QualifiedPath {
            name,
            args,
            self_type,
            trait_,
        } => qualified_projection(name, args.as_deref(), self_type, trait_.as_ref(), |ty| {
            contract_type_ref(ty, document, type_ids, limits, diagnostics, depth + 1)
        }),
        Type::Infer | Type::DynTrait(_) | Type::ImplTrait(_) => TypeRef::Unknown,
        _ => rust_type_ref(ty, document, type_ids, limits, diagnostics, depth),
    }
}

// Both contract facts and callable signatures retain the same projection shape,
// while their recursive conversion applies the appropriate binder scope.
fn qualified_projection(
    name: &str,
    args: Option<&GenericArgs>,
    self_type: &Type,
    trait_type: Option<&RustdocPath>,
    mut project: impl FnMut(&Type) -> TypeRef,
) -> TypeRef {
    TypeRef::Projection {
        owner: Box::new(project(self_type)),
        trait_type: trait_type.map(|path| Box::new(project(&Type::ResolvedPath(path.clone())))),
        name: name.to_owned(),
        arguments: if let Some(GenericArgs::AngleBracketed { args, .. }) = args {
            args.iter()
                .filter_map(|arg| match arg {
                    GenericArg::Type(ty) => Some(project(ty)),
                    _ => None,
                })
                .collect()
        } else {
            Vec::new()
        },
    }
}

// Impl binders are local to an impl. Transport those selected by the self
// constructor onto the owner's binders; independent impl binders stay unknown.
fn bind_concrete_implementation(
    fact: &mut ImplementedTraitFact,
    self_type: &Type,
    parameters: &[String],
) {
    let mut binders = RandomHashMap::new();
    match self_type {
        Type::ResolvedPath(path) => {
            if let Some(GenericArgs::AngleBracketed { args, .. }) = path.args.as_deref() {
                for (argument, parameter) in args
                    .iter()
                    .filter(|arg| !matches!(arg, GenericArg::Lifetime(_)))
                    .zip(parameters)
                {
                    if let GenericArg::Type(Type::Generic(name)) = argument {
                        binders.insert(name.clone(), parameter.clone());
                    }
                }
            }
        }
        Type::Slice(element) | Type::Array { type_: element, .. } => {
            if let Type::Generic(name) = element.as_ref()
                && let Some(parameter) = parameters.first()
            {
                binders.insert(name.clone(), parameter.clone());
            }
        }
        _ => {}
    }
    binders.insert("Self".to_owned(), "Self".to_owned());
    let mut pending = vec![&mut fact.trait_type];
    pending.extend(
        fact.associated_types
            .iter_mut()
            .map(|binding| &mut binding.r#type),
    );
    while let Some(ty) = pending.pop() {
        match ty {
            TypeRef::TypeParameter { name } => {
                if let Some(parameter) = binders.get(name) {
                    name.clone_from(parameter);
                } else {
                    *ty = TypeRef::Unknown;
                }
            }
            TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. } => {
                pending.extend(arguments)
            }
            TypeRef::Projection {
                owner,
                trait_type,
                arguments,
                ..
            } => {
                pending.push(owner);
                pending.extend(trait_type.iter_mut().map(Box::as_mut));
                pending.extend(arguments);
            }
            TypeRef::Array { element }
            | TypeRef::Slice { element }
            | TypeRef::FixedArray { element, .. }
            | TypeRef::ByRef { element, .. }
            | TypeRef::Pointer { element }
            | TypeRef::Channel { element, .. } => pending.push(element),
            TypeRef::Tuple { elements } => pending.extend(elements),
            TypeRef::Map { key, value } => {
                pending.push(key);
                pending.push(value);
            }
            TypeRef::Wildcard { bound, .. } => pending.extend(bound.iter_mut().map(Box::as_mut)),
            TypeRef::Function { parameters, result } => {
                pending.extend(parameters.iter_mut().map(|parameter| &mut parameter.r#type));
                pending.extend(result.iter_mut().map(Box::as_mut));
            }
            TypeRef::Unknown => {}
        }
    }
}

fn implemented_trait_fact(
    implementation: &rustdoc_types::Impl,
    document: &RustdocCrate,
    type_ids: &HashMap<Id, String>,
    limits: &ArtifactProducerLimits,
    diagnostics: &mut BoundedProducerDiagnostics,
) -> ImplementedTraitFact {
    let trait_ = implementation.trait_.as_ref().expect("trait impl");
    let trait_type = contract_type_ref(
        &Type::ResolvedPath(trait_.clone()),
        document,
        type_ids,
        limits,
        diagnostics,
        0,
    );
    let mut associated_types = implementation
        .items
        .iter()
        .filter_map(|id| {
            let item = document.index.get(id)?;
            let ItemEnum::AssocType {
                type_: Some(ty), ..
            } = &item.inner
            else {
                return None;
            };
            Some(AssociatedTypeBinding {
                name: item.name.clone()?,
                r#type: contract_type_ref(ty, document, type_ids, limits, diagnostics, 0),
            })
        })
        .collect::<Vec<_>>();
    associated_types.sort_by(|a, b| a.name.cmp(&b.name));
    ImplementedTraitFact {
        is_negative: false,
        type_parameters: Vec::new(),
        self_pattern: None,
        bounds: Vec::new(),
        trait_type,
        associated_types,
    }
}

fn generic_trait_bounds(
    generics: &Generics,
    document: &RustdocCrate,
    type_ids: &HashMap<Id, String>,
    limits: &ArtifactProducerLimits,
    diagnostics: &mut BoundedProducerDiagnostics,
) -> Vec<GenericTraitBound> {
    let mut bounds = Vec::new();
    let mut add = |subject: &Type, constraints: &[GenericBound]| {
        for bound in constraints {
            if let GenericBound::TraitBound {
                trait_, modifier, ..
            } = bound
            {
                let associated_types =
                    if let Some(GenericArgs::AngleBracketed { constraints, .. }) =
                        trait_.args.as_deref()
                    {
                        constraints
                            .iter()
                            .filter_map(|constraint| {
                                if let rustdoc_types::AssocItemConstraintKind::Equality(
                                    Term::Type(ty),
                                ) = &constraint.binding
                                {
                                    Some(AssociatedTypeBinding {
                                        name: constraint.name.clone(),
                                        r#type: contract_type_ref(
                                            ty,
                                            document,
                                            type_ids,
                                            limits,
                                            diagnostics,
                                            0,
                                        ),
                                    })
                                } else {
                                    None
                                }
                            })
                            .collect()
                    } else {
                        Vec::new()
                    };
                bounds.push(GenericTraitBound {
                    subject: contract_type_ref(subject, document, type_ids, limits, diagnostics, 0),
                    bound: ImplementedTraitFact {
                        is_negative: false,
                        type_parameters: Vec::new(),
                        self_pattern: None,
                        bounds: Vec::new(),
                        trait_type: contract_type_ref(
                            &Type::ResolvedPath(trait_.clone()),
                            document,
                            type_ids,
                            limits,
                            diagnostics,
                            0,
                        ),
                        associated_types,
                    },
                    maybe: *modifier == rustdoc_types::TraitBoundModifier::Maybe,
                });
            }
        }
    };
    for parameter in &generics.params {
        if let rustdoc_types::GenericParamDefKind::Type { bounds, .. } = &parameter.kind {
            add(&Type::Generic(parameter.name.clone()), bounds);
        }
    }
    for predicate in &generics.where_predicates {
        if let WherePredicate::BoundPredicate { type_, bounds, .. } = predicate {
            add(type_, bounds);
        }
    }
    // Rust's implicit Sized bound is a condition too. Without it a negative
    // blanket over T would incorrectly apply to an unsized receiver. A written
    // ?Sized (inline or where-clause) relaxes the default.
    for parameter in &generics.params {
        if !matches!(
            parameter.kind,
            rustdoc_types::GenericParamDefKind::Type { .. }
        ) {
            continue;
        }
        let subject = TypeRef::TypeParameter {
            name: parameter.name.clone(),
        };
        let has_sized_bound = |bounds: &[GenericBound]| {
            bounds.iter().any(|bound| {
                matches!(bound, GenericBound::TraitBound { trait_, .. }
                if normalized_path(trait_, document) == "core.marker.Sized")
            })
        };
        let inline_sized = matches!(&parameter.kind,
            rustdoc_types::GenericParamDefKind::Type { bounds, .. } if has_sized_bound(bounds));
        let where_sized = generics.where_predicates.iter().any(|predicate|
            matches!(predicate, WherePredicate::BoundPredicate { type_: Type::Generic(name), bounds, .. }
                if name == &parameter.name && has_sized_bound(bounds)));
        if inline_sized || where_sized {
            continue;
        }
        bounds.push(GenericTraitBound {
            subject,
            bound: ImplementedTraitFact {
                is_negative: false,
                type_parameters: Vec::new(),
                self_pattern: None,
                bounds: Vec::new(),
                associated_types: Vec::new(),
                trait_type: TypeRef::named("core.marker.Sized"),
            },
            maybe: false,
        });
    }
    bounds
}

fn implementation_conditions_supported(generics: &Generics) -> bool {
    let supported_bounds = |bounds: &[GenericBound]| {
        bounds.iter().all(|bound| match bound {
            GenericBound::TraitBound {
                trait_,
                generic_params,
                modifier,
            } => {
                generic_params.is_empty()
                    && *modifier != rustdoc_types::TraitBoundModifier::MaybeConst
                    && match trait_.args.as_deref() {
                        Some(GenericArgs::AngleBracketed { constraints, .. }) => {
                            constraints.iter().all(|constraint| {
                                matches!(
                                    constraint.binding,
                                    rustdoc_types::AssocItemConstraintKind::Equality(Term::Type(_))
                                )
                            })
                        }
                        Some(
                            GenericArgs::ReturnTypeNotation | GenericArgs::Parenthesized { .. },
                        ) => false,
                        _ => true,
                    }
            }
            _ => false,
        })
    };
    generics.params.iter().all(|param| match &param.kind {
        rustdoc_types::GenericParamDefKind::Type { bounds, .. } => supported_bounds(bounds),
        rustdoc_types::GenericParamDefKind::Lifetime { outlives } => outlives.is_empty(),
        _ => true,
    }) && generics
        .where_predicates
        .iter()
        .all(|predicate| match predicate {
            WherePredicate::BoundPredicate {
                bounds,
                generic_params,
                ..
            } => generic_params.is_empty() && supported_bounds(bounds),
            WherePredicate::LifetimePredicate { .. } => false,
            WherePredicate::EqPredicate { .. } => false,
        })
}

fn self_pattern(
    ty: &Type,
    document: &RustdocCrate,
    type_ids: &HashMap<Id, String>,
    limits: &ArtifactProducerLimits,
    diagnostics: &mut BoundedProducerDiagnostics,
    depth: usize,
) -> Option<RustSelfPattern> {
    if depth >= limits.max_signature_depth {
        return None;
    }
    match ty {
        Type::Generic(name) => Some(RustSelfPattern::Parameter { name: name.clone() }),
        Type::BorrowedRef {
            is_mutable, type_, ..
        } => Some(RustSelfPattern::Reference {
            mutable: *is_mutable,
            inner: Box::new(self_pattern(
                type_,
                document,
                type_ids,
                limits,
                diagnostics,
                depth + 1,
            )?),
        }),
        Type::ResolvedPath(path) => {
            let mut owner = path_type_ref(path, document, type_ids, limits, diagnostics, depth);
            if let TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. } =
                &mut owner
            {
                arguments.clear();
            }
            let arguments =
                if let Some(GenericArgs::AngleBracketed { args, .. }) = path.args.as_deref() {
                    args.iter()
                        .filter_map(|arg| match arg {
                            GenericArg::Type(ty) => Some(self_pattern(
                                ty,
                                document,
                                type_ids,
                                limits,
                                diagnostics,
                                depth + 1,
                            )),
                            _ => None,
                        })
                        .collect::<Option<Vec<_>>>()?
                } else {
                    Vec::new()
                };
            Some(RustSelfPattern::Constructor { owner, arguments })
        }
        Type::Slice(_)
        | Type::Array { .. }
        | Type::Tuple(_)
        | Type::Primitive(_)
        | Type::RawPointer { .. } => Some(RustSelfPattern::Constructor {
            owner: contract_type_ref(ty, document, type_ids, limits, diagnostics, depth),
            arguments: Vec::new(),
        }),
        _ => None,
    }
}

fn merge_source_set_productions(
    request: &ArtifactProductionRequest,
    limits: &ArtifactProducerLimits,
    artifact_sha256: &str,
    productions: Vec<ArtifactProduction>,
    links: &SourceSetLinks,
) -> ArtifactProduction {
    let mut diagnostics = Vec::new();
    let mut suppressed_diagnostics = SuppressedDiagnostics::default();
    let mut types = Vec::new();
    let mut members = Vec::new();
    let mut relations = Vec::new();
    let mut completeness = Completeness::Complete;
    let mut all_documents_decoded = true;
    for production in productions {
        completeness = if production.completeness == Completeness::Complete {
            completeness
        } else {
            Completeness::Partial
        };
        for diagnostic in production.diagnostics {
            if diagnostics.len() < limits.max_diagnostics
                || admit_into_full_diagnostics(
                    &mut diagnostics,
                    &mut suppressed_diagnostics,
                    diagnostic.severity == ProducerDiagnosticSeverity::Warning,
                    |retained: &ProducerDiagnostic| {
                        retained.severity == ProducerDiagnosticSeverity::Warning
                    },
                )
            {
                diagnostics.push(diagnostic);
            }
        }
        suppressed_diagnostics += production.suppressed_diagnostics;
        let Some(pack) = production.pack else {
            all_documents_decoded = false;
            continue;
        };
        let Some(shard) = pack.shards.into_iter().next() else {
            completeness = Completeness::Partial;
            continue;
        };
        let AuthoredPayload::DeclarationFacts {
            types: shard_types,
            members: shard_members,
            relations: shard_relations,
            ..
        } = shard.payload
        else {
            completeness = Completeness::Partial;
            continue;
        };
        types.extend(shard_types);
        members.extend(shard_members);
        relations.extend(shard_relations);
    }
    if types.is_empty() {
        if diagnostics.len() < limits.max_diagnostics
            || admit_into_full_diagnostics(
                &mut diagnostics,
                &mut suppressed_diagnostics,
                false,
                |retained: &ProducerDiagnostic| {
                    retained.severity == ProducerDiagnosticSeverity::Warning
                },
            )
        {
            diagnostics.push(ProducerDiagnostic {
                severity: ProducerDiagnosticSeverity::Error,
                source_entry: None,
                code: "rust.rustdoc.no_external_declarations".to_owned(),
                location: None,
                declaration: None,
                message: "rustdoc source set contains no externally visible Rust declarations"
                    .to_owned(),
            });
        }
        completeness = Completeness::Partial;
    }
    let mut merged_types: Vec<TypeFact> = Vec::new();
    let mut type_positions = RandomHashMap::new();
    for fact in types {
        if let Some(&position) = type_positions.get(&fact.id) {
            let existing: &mut TypeFact = &mut merged_types[position];
            union_facts(&mut existing.aliases, fact.aliases);
            union_facts(&mut existing.hierarchy, fact.hierarchy);
            union_facts(&mut existing.implemented_traits, fact.implemented_traits);
            union_facts(&mut existing.generic_trait_impls, fact.generic_trait_impls);
        } else {
            type_positions.insert(fact.id.clone(), merged_types.len());
            merged_types.push(fact);
        }
    }
    // An external impl can precede its defining document. Missing
    // definitions still produce diagnostics and never leave dangling facts.
    let owner_ids = merged_types
        .iter()
        .map(|ty| (ty.name.as_str(), ty.id.as_str()))
        .collect::<RandomHashMap<_, _>>();
    let mut missing_external_members: RandomHashSet<&String> = RandomHashSet::default();
    for (member_id, diagnostic) in &links.pending_external_members {
        if !owner_ids.contains_key(diagnostic.declaration.as_deref().expect("external owner")) {
            missing_external_members.insert(member_id);
            if diagnostics.len() < limits.max_diagnostics
                || admit_into_full_diagnostics(
                    &mut diagnostics,
                    &mut suppressed_diagnostics,
                    true,
                    |retained: &ProducerDiagnostic| {
                        retained.severity == ProducerDiagnosticSeverity::Warning
                    },
                )
            {
                diagnostics.push(diagnostic.clone());
            }
        }
    }
    members.retain(|member| !missing_external_members.contains(&member.id));
    relations.retain(|relation| !missing_external_members.contains(&relation.from));
    // A new external presentation may project renamed impl binders more
    // precisely than an existing local presentation. Preserve the local ID,
    // signature and locator instead of publishing a duplicate callable.
    let presentation = |member: &MemberFact| {
        let Locator::Artifact { path, .. } = &member.locator else {
            return None;
        };
        links
            .impl_member_presentations
            .get(path)
            .and_then(|document| document.get(&member.id))
    };
    let mut local_presentations: RandomHashMap<&ImplMemberKey, usize> = RandomHashMap::default();
    for (index, member) in members.iter().enumerate() {
        if let Some(presentation) = presentation(member)
            && matches!(presentation.origin, ImplMemberOrigin::Local)
        {
            local_presentations
                .entry(&presentation.key)
                .or_insert(index);
        }
    }
    let duplicates = members
        .iter()
        .enumerate()
        .filter_map(|(index, member)| {
            let presentation = presentation(member)?;
            if !matches!(presentation.origin, ImplMemberOrigin::NewlyDeferred) {
                return None;
            }
            local_presentations
                .get(&presentation.key)
                .map(|local| (index, *local))
        })
        .collect::<Vec<_>>();
    let mut dropped_presentations: RandomHashMap<String, RandomHashSet<String>> =
        RandomHashMap::default();
    let mut dropped_member_ids: RandomHashSet<String> = RandomHashSet::default();
    for (duplicate, local) in duplicates {
        let Locator::Artifact { path, .. } = &members[duplicate].locator else {
            unreachable!("impl presentation has an artifact locator")
        };
        dropped_presentations
            .entry(path.clone())
            .or_default()
            .insert(members[duplicate].id.clone());
        dropped_member_ids.insert(members[duplicate].id.clone());
        let aliases = std::mem::take(&mut members[duplicate].aliases);
        union_facts(&mut members[local].aliases, aliases);
    }
    members.retain(|member| match &member.locator {
        Locator::Artifact { path, .. } => !dropped_presentations
            .get(path)
            .is_some_and(|ids| ids.contains(&member.id)),
        _ => true,
    });
    let retained_member_ids = members
        .iter()
        .map(|member| member.id.as_str())
        .collect::<RandomHashSet<_>>();
    // Identical IDs retain the usual relation union. Differing projection IDs
    // must not leave relations whose source is the discarded external copy.
    relations.retain(|relation| {
        !dropped_member_ids.contains(&relation.from)
            || retained_member_ids.contains(relation.from.as_str())
    });
    let mut types = merged_types;
    let resolved_reexports = apply_cross_document_reexports(
        &links.reexports,
        &mut types,
        &mut members,
        &links.private_modules,
    );
    let resolved_locations = resolved_reexports
        .into_iter()
        .map(|index| {
            let export = &links.reexports[index];
            (export.source_entry.clone(), export.location.clone())
        })
        .collect::<RandomHashSet<_>>();
    diagnostics.retain(|diagnostic| {
        diagnostic.code != "rust.rustdoc.reexport_target_unavailable"
            || diagnostic.location.as_ref().is_none_or(|location| {
                !resolved_locations.contains(&(diagnostic.source_entry.clone(), location.clone()))
            })
    });
    for (owner, fact) in &links.generic_trait_impls {
        if let Some(trait_) = types.iter_mut().find(|ty| &ty.name == owner) {
            union_facts(&mut trait_.generic_trait_impls, vec![fact.clone()]);
        }
    }
    for (owner, fact) in &links.concrete_trait_impls {
        if let Some(ty) = types.iter_mut().find(|ty| &ty.name == owner) {
            union_facts(&mut ty.implemented_traits, vec![fact.clone()]);
        }
    }
    let mut merged_members: Vec<MemberFact> = Vec::new();
    let mut member_positions = RandomHashMap::new();
    for fact in members {
        if let Some(&position) = member_positions.get(&fact.id) {
            let existing: &mut MemberFact = &mut merged_members[position];
            union_facts(&mut existing.aliases, fact.aliases);
        } else {
            member_positions.insert(fact.id.clone(), merged_members.len());
            merged_members.push(fact);
        }
    }
    let mut members = merged_members;
    if all_documents_decoded {
        certify_callable_families(&types, &mut members, links);
        if !links.declarations_interrupted {
            for ty in &mut types {
                ty.implemented_traits_complete =
                    !matches!(
                        ty.type_kind,
                        TypeKind::Module | TypeKind::Trait | TypeKind::TypeAlias
                    ) && !links.incomplete_implementation_owners.contains(&ty.name);
                ty.generic_trait_impls_complete = ty.type_kind == TypeKind::Trait
                    && !links.incomplete_generic_traits.contains(&ty.name)
                    && !links.auto_traits.contains(&ty.name);
            }
        }
    } else {
        for member in &mut members {
            member.callable_family_complete = false;
        }
    }
    let mut seen_relation_ids: RandomHashSet<String> = RandomHashSet::default();
    relations.retain(|fact| seen_relation_ids.insert(fact.id.clone()));
    retain_available_alias_targets(&mut types);
    types.sort_by(|left, right| left.name.cmp(&right.name).then(left.id.cmp(&right.id)));
    members.sort_by(|left, right| {
        left.owner
            .cmp(&right.owner)
            .then(left.name.cmp(&right.name))
            .then(left.id.cmp(&right.id))
    });
    relations.sort_by(|left, right| {
        (&left.from, &left.to, left.relation_kind as u8, &left.id).cmp(&(
            &right.from,
            &right.to,
            right.relation_kind as u8,
            &right.id,
        ))
    });
    if diagnostics.is_empty()
        && suppressed_diagnostics.total() == 0
        && completeness == Completeness::Complete
    {
        completeness = Completeness::Complete;
    } else {
        completeness = Completeness::Partial;
    }
    // The source-set digest identifies extraction inputs, not the installed
    // toolchain. Applicability remains the caller's authored selectors.
    let activation = request.activation.clone();
    let pack = (!types.is_empty()).then(|| AuthoredSemanticModelPack {
        extraction: Some(
            brokk_bifrost_semantic::analyzer::semantic_model::ArtifactExtraction::source_set(
                request.artifact_kind,
                artifact_sha256,
            ),
        ),
        schema_version: if types.iter().any(|ty| ty.alias_target.is_some()) {
            RUSTDOC_PACK_MAX_SCHEMA_VERSION
        } else if request.provenance.rust_artifact_approximation.is_some() {
            brokk_bifrost_semantic::analyzer::semantic_model::model::RUST_ARTIFACT_APPROXIMATION_MIN_SCHEMA_VERSION
        } else {
            crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION
        },
        pack_id: request.pack_id.clone(),
        version: request.pack_version.clone(),
        producer: Producer {
            name: "bifrost-rustdoc-json".to_owned(),
            version: super::external::RUST_PACK_PRODUCER_VERSION.to_owned(),
        },
        language: "rust".to_owned(),
        ecosystem: request.ecosystem.clone(),
        compatibility: request.compatibility.clone(),
        provenance: request.provenance.clone(),
        license: request.license.clone(),
        completeness,
        safety: request.safety.clone(),
        carried_sources: Vec::new(),
        cpp_portability: None,
        python_correspondence: None,
        rust_external_reexports: Vec::new(),
        rust_external_reexports_truncated: false,
        rust_external_reexports_glob_incomplete: false,
        shards: source_set_declaration_shards(
            types,
            members,
            relations,
            activation,
            &links.private_modules,
        ),
    });
    assert_pack_schema_within_producer_max(pack.as_ref());
    ArtifactProduction {
        artifact_sha256: Some(artifact_sha256.to_owned()),
        pack,
        completeness,
        diagnostics,
        suppressed_diagnostics,
    }
}

// Join and certify the whole source set first, then partition by canonical
// owner module and pack modules in canonical order. Identical activation
// selects every shard together; pack-wide
// reference validation permits the cross-crate links. Keep the compiler and
// decoder's per-shard allocation/decompression caps and pack-wide caps intact.
fn source_set_declaration_shards(
    types: Vec<TypeFact>,
    members: Vec<MemberFact>,
    relations: Vec<RelationFact>,
    activation: Vec<crate::analyzer::semantic_model::ActivationSelector>,
    private_modules: &RandomHashSet<String>,
) -> Vec<AuthoredShard> {
    // Both public and private modules can own exported declarations. The
    // primitive namespace is canonical across core/alloc/std documents.
    let mut modules = private_modules.clone();
    modules.extend(
        types
            .iter()
            .filter(|ty| ty.type_kind == TypeKind::Module)
            .map(|ty| ty.name.clone()),
    );
    modules.insert("core.primitive".to_owned());
    let owner_module = |name: &str| {
        let mut segments = name.split('.');
        let crate_name = segments.next().expect("canonical owner crate");
        let Some(module) = segments.next() else {
            return crate_name.to_owned();
        };
        let module = format!("{crate_name}.{module}");
        if modules.contains(&module) {
            module
        } else {
            crate_name.to_owned()
        }
    };
    let mut partitions = types
        .iter()
        .map(|fact| owner_module(&fact.name))
        .collect::<Vec<_>>();
    partitions.sort_unstable();
    partitions.dedup();
    let mut shards = partitions
        .iter()
        .map(|name| AuthoredShard {
            id: format!("declarations.rust.external.{name}"),
            activation: activation.clone(),
            payload: AuthoredPayload::DeclarationFacts {
                assembly_identity: None,
                type_forwards: Vec::new(),
                types: Vec::new(),
                members: Vec::new(),
                relations: Vec::new(),
            },
            runtime_values: None,
            runtime_contracts: None,
            collection_flows: None,
            deferred_yields: None,
            conditional_type_refinements: None,
            callable_values: None,
        })
        .collect::<Vec<_>>();
    // Generation-local inventory: member owners and relation sources are
    // guaranteed to be declarations produced in this source set.
    let mut declaration_shards = RandomHashMap::new();
    for fact in types {
        let position = partitions.binary_search(&owner_module(&fact.name)).unwrap();
        declaration_shards.insert(fact.id.clone(), position);
        let AuthoredPayload::DeclarationFacts { types, .. } = &mut shards[position].payload else {
            unreachable!("source-set shards contain declaration facts")
        };
        types.push(fact);
    }
    for fact in members {
        let position = declaration_shards[&fact.owner];
        declaration_shards.insert(fact.id.clone(), position);
        let AuthoredPayload::DeclarationFacts { members, .. } = &mut shards[position].payload
        else {
            unreachable!("source-set shards contain declaration facts")
        };
        members.push(fact);
    }
    for fact in relations {
        let position = declaration_shards[&fact.from];
        let AuthoredPayload::DeclarationFacts { relations, .. } = &mut shards[position].payload
        else {
            unreachable!("source-set shards contain declaration facts")
        };
        relations.push(fact);
    }
    // First-fit in canonical module order avoids a shard per module while
    // preserving each module as one unit. Reserve 10% of the hard raw cap for
    // the compiled envelope and growth in future nightly inputs. Authored
    // declaration facts use the same wire shapes as compiled facts; counting
    // each module's full shard also conservatively repeats its array/envelope
    // overhead. The compiler still enforces the unchanged hard limit (including
    // when one indivisible module alone outgrows this packing target).
    let target_bytes =
        crate::analyzer::semantic_model::DecodeLimits::default().max_raw_shard_bytes * 9 / 10;
    let mut packed: Vec<AuthoredShard> = Vec::new();
    let mut sizes = Vec::new();
    for shard in shards {
        let bytes = serde_json::to_vec(&shard)
            .expect("typed declaration shard is JSON serializable")
            .len();
        let Some(position) = sizes.iter().position(|size| size + bytes <= target_bytes) else {
            sizes.push(bytes);
            packed.push(shard);
            continue;
        };
        sizes[position] += bytes;
        let AuthoredPayload::DeclarationFacts {
            types,
            members,
            relations,
            ..
        } = &mut packed[position].payload
        else {
            unreachable!("source-set shards contain declaration facts")
        };
        let AuthoredPayload::DeclarationFacts {
            types: module_types,
            members: module_members,
            relations: module_relations,
            ..
        } = shard.payload
        else {
            unreachable!("source-set shards contain declaration facts")
        };
        types.extend(module_types);
        members.extend(module_members);
        relations.extend(module_relations);
    }
    packed
}

fn validated_document_root<'a>(
    request: &ArtifactProductionRequest,
    document: &'a RustdocCrate,
    expected_crate: Option<&str>,
) -> Result<&'a Item, (&'static str, String)> {
    let root = document.index.get(&document.root).ok_or_else(|| {
        (
            "rust.rustdoc.missing_root",
            "rustdoc JSON root item is absent from the item index".to_owned(),
        )
    })?;
    if !matches!(root.inner, ItemEnum::Module(_)) {
        return Err((
            "rust.rustdoc.invalid_root",
            "rustdoc JSON root item is not a module".to_owned(),
        ));
    }
    let mut requested_crates = request
        .activation
        .iter()
        .filter_map(|selector| selector.module.as_ref())
        .map(|module| module.name.replace('-', "_"))
        .collect::<RandomHashSet<_>>();
    if let Some(expected_crate) = expected_crate {
        requested_crates.insert(expected_crate.replace('-', "_"));
    }
    let root_name = root
        .name
        .as_deref()
        .map(|name| name.replace('-', "_"))
        .or_else(|| {
            document
                .paths
                .get(&document.root)
                .and_then(|summary| summary.path.first())
                .map(|name| name.replace('-', "_"))
        });
    if requested_crates.len() > 1
        || root_name
            .as_ref()
            .is_none_or(|name| !requested_crates.is_empty() && !requested_crates.contains(name))
    {
        return Err((
            "rust.rustdoc.crate_name_mismatch",
            format!(
                "rustdoc root crate {root_name:?} does not match requested modules {requested_crates:?}"
            ),
        ));
    }
    Ok(root)
}

#[allow(clippy::too_many_arguments)]
fn produce_document(
    request: &ArtifactProductionRequest,
    limits: &ArtifactProducerLimits,
    artifact_sha256: &str,
    document: &RustdocCrate,
    cancellation: Option<&CancellationToken>,
    expected_crate: Option<&str>,
    source_relative_path: Option<&str>,
    links: &mut SourceSetLinks,
) -> ArtifactProduction {
    let decode_veto_start = links.incomplete_callable_owner_refs.len();
    let mut diagnostics = BoundedProducerDiagnostics::new(limits);
    let root = match validated_document_root(request, document, expected_crate) {
        Ok(root) => root,
        Err((code, message)) => {
            diagnostics.error(code, None, message);
            return finish(
                request,
                artifact_sha256,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                diagnostics,
            );
        }
    };
    if document.index.len() > limits.max_records {
        diagnostics.error(
            "limit.input_items",
            None,
            format!(
                "rustdoc item index contains {} items, exceeding the {} item processing limit",
                document.index.len(),
                limits.max_records
            ),
        );
        return finish(
            request,
            artifact_sha256,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            diagnostics,
        );
    }

    let mut ordered_items = document.index.values().collect::<Vec<_>>();
    ordered_items.sort_by_key(|item| item.id);
    let Some(parents) = parent_index(&ordered_items, cancellation) else {
        diagnostics.error(
            "artifact.cancelled",
            None,
            "rustdoc artifact production was cancelled",
        );
        return finish(
            request,
            artifact_sha256,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            diagnostics,
        );
    };
    let mut names = match item_names(document, root, cancellation) {
        Ok(names) => names,
        Err(NameIndexError::Cancelled) => {
            diagnostics.error(
                "artifact.cancelled",
                None,
                "rustdoc artifact production was cancelled",
            );
            return finish(
                request,
                artifact_sha256,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                diagnostics,
            );
        }
        Err(NameIndexError::Limit) => {
            diagnostics.error(
                "limit.derived_names",
                None,
                format!(
                    "rustdoc declaration names exceed the {} byte per-name or {} byte aggregate limit",
                    MAX_MODEL_NAME_BYTES, MAX_TOTAL_MODEL_NAME_BYTES
                ),
            );
            return finish(
                request,
                artifact_sha256,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                diagnostics,
            );
        }
    };
    for item in &ordered_items {
        if let ItemEnum::Primitive(primitive) = &item.inner {
            let name = format!("core.primitive.{}", primitive.name);
            names.insert(item.id, name.clone());
            for implementation in &primitive.impls {
                names.insert(*implementation, name.clone());
            }
        }
    }
    let Some(visible) = visible_items(document, &ordered_items, &parents, cancellation) else {
        diagnostics.error(
            "artifact.cancelled",
            None,
            "rustdoc artifact production was cancelled",
        );
        return finish(
            request,
            artifact_sha256,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            diagnostics,
        );
    };

    let mut type_ids = HashMap::default();
    for item in &ordered_items {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            diagnostics.error(
                "artifact.cancelled",
                None,
                "rustdoc artifact production was cancelled",
            );
            return finish(
                request,
                artifact_sha256,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                diagnostics,
            );
        }
        if item.crate_id == root.crate_id && visible.contains(&item.id) && is_type_item(&item.inner)
        {
            let Some(name) = names.get(&item.id) else {
                diagnostics.warning(
                    "rust.rustdoc.missing_item_path",
                    Some(format!("item.{}", item.id.0)),
                    "externally visible type has no stable rustdoc path",
                );
                continue;
            };
            type_ids.insert(
                item.id,
                if matches!(item.inner, ItemEnum::Primitive(_)) {
                    name.clone()
                } else {
                    type_declaration_id(TypeIdentity {
                        ecosystem: "cargo",
                        name,
                    })
                },
            );
        }
    }

    let mut types = Vec::new();
    let mut members = Vec::new();
    let mut relations = RelationCollector::new(limits.max_records);
    let mut type_position = HashMap::default();
    let type_id_by_name = names
        .iter()
        .filter_map(|(item, name)| type_ids.get(item).map(|id| (name.clone(), id.clone())))
        .collect::<RandomHashMap<_, _>>();
    let type_item_by_name = names
        .iter()
        .filter(|(item, _)| type_ids.contains_key(item))
        .map(|(item, name)| (name.clone(), *item))
        .collect::<RandomHashMap<_, _>>();

    for item in &ordered_items {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            diagnostics.error(
                "artifact.cancelled",
                None,
                "rustdoc artifact production was cancelled",
            );
            break;
        }
        if item.crate_id != root.crate_id
            || !visible.contains(&item.id)
            || !is_type_item(&item.inner)
        {
            continue;
        }
        if types.len().saturating_add(members.len()) >= limits.max_records {
            diagnostics.warning(
                "limit.records",
                None,
                format!(
                    "producer stopped after {} declaration records",
                    limits.max_records
                ),
            );
            break;
        }
        let (Some(name), Some(id)) = (names.get(&item.id), type_ids.get(&item.id)) else {
            continue;
        };
        let (type_kind, generics, hierarchy) =
            type_shape(item, document, &type_ids, limits, &mut diagnostics);
        let impl_ids: &[Id] = match &item.inner {
            ItemEnum::Struct(ty) => &ty.impls,
            ItemEnum::Union(ty) => &ty.impls,
            ItemEnum::Enum(ty) => &ty.impls,
            ItemEnum::Trait(ty) => &ty.implementations,
            ItemEnum::Primitive(ty) => &ty.impls,
            _ => &[],
        };
        if impl_ids.iter().any(|id| {
            !matches!(
                document.index.get(id).map(|item| &item.inner),
                Some(ItemEnum::Impl(_))
            )
        }) {
            if type_kind == TypeKind::Trait {
                links.incomplete_generic_traits.insert(name.clone());
            } else {
                links.incomplete_implementation_owners.insert(name.clone());
            }
        }
        if matches!(&item.inner, ItemEnum::Trait(ty) if ty.is_auto) || name == "core.marker.Sized" {
            links.auto_traits.insert(name.clone());
        }
        type_position.insert(item.id, types.len());
        types.push(TypeFact {
            alias_target: if let ItemEnum::TypeAlias(alias) = &item.inner {
                exact_alias_target(
                    &alias.type_,
                    &generic_names(&alias.generics),
                    document,
                    &type_ids,
                    limits,
                    &mut diagnostics,
                    0,
                )
            } else {
                None
            },
            tuple_fields: None,
            implemented_traits_complete: false,
            generic_trait_impls_complete: false,
            jvm_inventory: None,
            type_parameter_defaults: generic_parameters(generics)
                .map(|param| match &param.kind {
                    rustdoc_types::GenericParamDefKind::Type { default, .. } => {
                        default.as_ref().map(|ty| GenericParameterDefault::Type {
                            r#type: contract_type_ref(
                                ty,
                                document,
                                &type_ids,
                                limits,
                                &mut diagnostics,
                                0,
                            ),
                        })
                    }
                    rustdoc_types::GenericParamDefKind::Const { default, .. } => default
                        .as_ref()
                        .map(|value| GenericParameterDefault::Const {
                            value: value.clone(),
                        }),
                    _ => None,
                })
                .collect(),
            implemented_traits: Vec::new(),
            generic_trait_impls: Vec::new(),
            runtime_bases: None,
            ambient_use: None,
            id: id.clone(),
            name: name.clone(),
            type_kind,
            visibility: semantic_visibility(&item.visibility),
            is_abstract: matches!(item.inner, ItemEnum::Trait(_)),
            is_sealed: false,
            callable_surface_complete: false,
            has_explicit_type_terms: false,
            type_parameters: if let ItemEnum::Primitive(primitive) = &item.inner {
                match primitive.name.as_str() {
                    "slice" => vec!["T".into()],
                    "array" => vec!["T".into(), "N".into()],
                    _ => Vec::new(),
                }
            } else {
                generic_names(generics)
            },
            type_parameter_constraints: Vec::new(),
            underlying_type: None,
            value_semantics: None,
            embedded_types: Vec::new(),
            hierarchy,
            aliases: if let ItemEnum::Primitive(primitive) = &item.inner {
                vec![format!("std.primitive.{}", primitive.name)]
            } else {
                Vec::new()
            },
            extension_surfaces: Vec::new(),
            guard: None,
            locator: Locator::artifact(source_relative_path.unwrap_or(ARTIFACT_LOCATOR_PATH), name),
        });
        push_generic_relations(id, generics, document, &type_ids, &mut relations);
        if let ItemEnum::TypeAlias(alias) = &item.inner {
            push_type_relations(id, &alias.type_, document, &type_ids, &mut relations);
        }
        if let ItemEnum::AssocType {
            type_: Some(default),
            ..
        } = &item.inner
        {
            push_type_relations(id, default, document, &type_ids, &mut relations);
        }
    }

    let projection = RustdocProjectionIndex {
        document,
        visible: &visible,
        parents: &parents,
        names: &names,
        type_ids: &type_ids,
        type_position: &type_position,
        type_item_by_name: &type_item_by_name,
    };
    let mut hierarchy_seen = types
        .iter()
        .map(|fact| fact.hierarchy.iter().cloned().collect::<RandomHashSet<_>>())
        .collect::<Vec<_>>();
    apply_impl_hierarchy(
        &ordered_items,
        &projection,
        &mut types,
        limits,
        &mut diagnostics,
        cancellation,
        &mut hierarchy_seen,
        links,
    );

    let mut member_position = HashMap::default();
    let mut impl_identities: HashMap<Id, String> = HashMap::default();
    for item in &ordered_items {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            diagnostics.error(
                "artifact.cancelled",
                None,
                "rustdoc artifact production was cancelled",
            );
            break;
        }
        if item.crate_id != root.crate_id
            || !visible.contains(&item.id)
            || is_type_item(&item.inner)
        {
            continue;
        }
        if parents.get(&item.id).and_then(|parent| document.index.get(parent)).is_some_and(|parent| matches!(&parent.inner, ItemEnum::Impl(implementation) if implementation.is_negative)) {
            continue;
        }
        let Some(mut member_kind) = member_kind(&item.inner) else {
            continue;
        };
        if types.len().saturating_add(members.len()) >= limits.max_records {
            diagnostics.warning(
                "limit.records",
                None,
                format!(
                    "producer stopped after {} declaration records",
                    limits.max_records
                ),
            );
            break;
        }
        let Some(owner_name) = owner_name(item.id, &parents, document, &names) else {
            diagnostics.warning(
                "rust.rustdoc.missing_member_owner",
                Some(format!("item.{}", item.id.0)),
                "externally visible member has no representable declaration owner",
            );
            continue;
        };
        if member_kind == MemberKind::Function
            && parents
                .get(&item.id)
                .and_then(|parent| document.index.get(parent))
                .is_some_and(|parent| !matches!(parent.inner, ItemEnum::Module(_)))
        {
            member_kind = MemberKind::Method;
        }
        let external_extension = source_relative_path.is_some()
            && parents
                .get(&item.id)
                .and_then(|parent| document.index.get(parent))
                .is_some_and(|parent| matches!(&parent.inner, ItemEnum::Impl(_)));
        let owner_item_id = if let Some(id) = type_id_by_name.get(&owner_name) {
            id.clone()
        } else if external_extension {
            // Resolve external impl owners only after all documents are joined.
            // The member keeps the identity and locator of its impl document.
            if owner_name.starts_with("core.primitive.") {
                owner_name.clone()
            } else {
                type_declaration_id(TypeIdentity {
                    ecosystem: "cargo",
                    name: &owner_name,
                })
            }
        } else {
            diagnostics.warning(
                "rust.rustdoc.missing_member_owner",
                Some(format!("item.{}", item.id.0)),
                format!("member owner {owner_name} is not an emitted declaration"),
            );
            continue;
        };
        let Some(name) = item.name.as_deref() else {
            continue;
        };
        let has_receiver = matches!(&item.inner, ItemEnum::Function(function)
        if function.sig.inputs.iter().any(|(name, _)| {
            name == "self" || name.ends_with(" self")
        }));
        let diagnostics_before = diagnostics.total();
        let implementation = parents
            .get(&item.id)
            .and_then(|parent| document.index.get(parent))
            .and_then(|parent| match &parent.inner {
                ItemEnum::Impl(implementation) => Some(implementation),
                _ => None,
            });
        let external_owner = !type_id_by_name.contains_key(&owner_name);
        let owner_parameters = links
            .owner_parameters
            .get(&owner_name)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let mut parameter_bindings = Vec::new();
        let canonical_owner = if external_owner {
            implementation.and_then(|implementation| match &implementation.for_ {
                Type::ResolvedPath(path) => {
                    if let Some(GenericArgs::AngleBracketed { args, .. }) = path.args.as_deref() {
                        for (argument, parameter) in args
                            .iter()
                            .filter(|argument| !matches!(argument, GenericArg::Lifetime(_)))
                            .zip(owner_parameters)
                        {
                            if let GenericArg::Type(Type::Generic(name)) = argument {
                                parameter_bindings.push((name.clone(), parameter.clone()));
                            }
                        }
                    }
                    Some((path.id, owner_item_id.as_str()))
                }
                _ => None,
            })
        } else {
            None
        };
        let mut seen_binders: RandomHashSet<&str> = RandomHashSet::default();
        let repeated_binders = parameter_bindings
            .iter()
            .filter_map(|(binder, _)| {
                (!seen_binders.insert(binder.as_str())).then_some(binder.as_str())
            })
            .collect::<RandomHashSet<_>>();
        let mut repeated_binders = repeated_binders
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        repeated_binders.sort_unstable();
        let ambiguous_impl_bindings = !repeated_binders.is_empty();
        if ambiguous_impl_bindings {
            diagnostics.warning(
                "rust.rustdoc.impl_binder_ambiguous",
                Some(format!("item.{}", item.id.0)),
                format!("impl binders map to multiple owner parameters: {repeated_binders:?}"),
            );
        }
        parameter_bindings.retain(|(binder, _)| repeated_binders.binary_search(binder).is_err());
        if external_owner && let ItemEnum::Function(function) = &item.inner {
            let method_parameters = generic_names(&function.generics);
            let before = parameter_bindings.len();
            parameter_bindings.retain(|(_, owner)| !method_parameters.contains(owner));
            if parameter_bindings.len() != before {
                diagnostics.warning(
                    "rust.rustdoc.impl_binder_shadowed",
                    Some(format!("item.{}", item.id.0)),
                    "impl binder cannot be transported without capturing a method parameter",
                );
            }
        }
        let owner_type_parameters = type_item_by_name
            .get(&owner_name)
            .and_then(|owner| type_position.get(owner))
            .map(|position| types[*position].type_parameters.as_slice())
            .unwrap_or(owner_parameters);
        let self_type = implementation.map(|implementation| {
            RustdocTypeProjection {
                document,
                type_ids: &type_ids,
                canonical_owner,
                parameter_bindings: &parameter_bindings,
                owner_type_parameters: if external_owner {
                    &[]
                } else {
                    owner_type_parameters
                },
                self_type: None,
                limits,
            }
            .project(&implementation.for_, &mut diagnostics, 0)
        });
        let projection = RustdocTypeProjection {
            document,
            type_ids: &type_ids,
            canonical_owner,
            parameter_bindings: &parameter_bindings,
            owner_type_parameters: if external_owner {
                &[]
            } else {
                owner_type_parameters
            },
            self_type: self_type.as_ref(),
            limits,
        };
        let mut signature = member_signature(item, &projection, &mut diagnostics);
        if has_receiver
            && let ItemEnum::Function(function) = &item.inner
            && let Some(signature) = signature.as_mut()
        {
            let mut raw_inputs = function.sig.inputs.iter();
            signature.parameters.retain(|_| {
                raw_inputs
                    .next()
                    .is_some_and(|(name, _)| !(name == "self" || name.ends_with(" self")))
            });
        }
        let is_static = !has_receiver;
        let parameter_types = signature
            .as_ref()
            .map(|signature| {
                signature
                    .parameters
                    .iter()
                    .map(|parameter| parameter.r#type.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let trait_implementation = parents
            .get(&item.id)
            .and_then(|id| document.index.get(id))
            .and_then(|parent| {
                if let ItemEnum::Impl(implementation) = &parent.inner {
                    implementation.trait_.as_ref().map(|_| implementation)
                } else {
                    None
                }
            });
        let implementation_identity = implementation
            .filter(|implementation| {
                implementation.trait_.is_some()
                    || (source_relative_path.is_some()
                        && matches!(implementation.for_, Type::ResolvedPath(_)))
            })
            .map(|implementation| {
                impl_identities
                    .entry(parents[&item.id])
                    .or_insert_with(|| trait_impl_identity(implementation, document))
                    .clone()
            });
        let mut member_id = member_declaration_id(MemberIdentity {
            owner_id: &owner_item_id,
            kind: member_kind,
            is_static,
            parameter_arity: parameter_types.len(),
            name,
            generic_arity: signature
                .as_ref()
                .map_or(0, |signature| signature.type_parameters.len()),
            parameter_types: &parameter_types,
            parameter_variadics: &[],
            return_type: signature
                .as_ref()
                .and_then(|signature| signature.returns.as_ref()),
        });
        if trait_implementation.is_some() {
            member_id.push_str(&format!(
                ".trait.{}",
                implementation_identity
                    .as_ref()
                    .expect("trait impl identity")
            ));
        }
        if let (Some(source), Some(implementation), Some(identity)) = (
            source_relative_path,
            implementation,
            implementation_identity,
        ) && matches!(implementation.for_, Type::ResolvedPath(_))
        {
            // Primitive extensions predate this deferral and keep their existing
            // merge behavior. Only newly deferred resolved-path owners fold.
            links
                .impl_member_presentations
                .entry(source.to_owned())
                .or_default()
                .entry(member_id.clone())
                .or_insert(ImplMemberPresentation {
                    key: ImplMemberKey {
                        owner: owner_item_id.clone(),
                        name: name.to_owned(),
                        kind: member_kind as u8,
                        implementation: identity,
                    },
                    origin: if external_owner {
                        ImplMemberOrigin::NewlyDeferred
                    } else {
                        ImplMemberOrigin::Local
                    },
                });
        }
        let path = names
            .get(&item.id)
            .cloned()
            .unwrap_or_else(|| format!("{owner_name}.{name}"));
        if let Some(signature) = signature.as_ref() {
            for parameter in &signature.parameters {
                push_type_ref_relations(&member_id, &parameter.r#type, &mut relations);
            }
            if let Some(returns) = &signature.returns {
                push_type_ref_relations(&member_id, returns, &mut relations);
            }
        }
        if let ItemEnum::Function(function) = &item.inner {
            push_generic_relations(
                &member_id,
                &function.generics,
                document,
                &type_ids,
                &mut relations,
            );
        }
        if member_kind == MemberKind::Method
            && parents.get(&item.id).and_then(|id| document.index.get(id)).is_some_and(|parent| {
                matches!(&parent.inner, ItemEnum::Impl(implementation) if implementation.blanket_impl.is_none() && !implementation.is_negative)
            })
        {
            links.callable_impl_members.insert(member_id.clone());
        }
        if external_extension && !type_id_by_name.contains_key(&owner_name) {
            links.pending_external_members.push((
                member_id.clone(),
                ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Warning,
                    source_entry: None,
                    code: "rust.rustdoc.missing_member_owner".into(),
                    location: Some(format!("item.{}", item.id.0)),
                    declaration: Some(owner_name.clone()),
                    message: format!("member owner {owner_name} is not an emitted declaration"),
                },
            ));
        }
        member_position.insert(item.id, members.len());
        members.push(MemberFact {
            implemented_trait: trait_implementation.map(|implementation| {
                let mut fact = ImplementedTraitFact {
                    is_negative: false,
                    type_parameters: Vec::new(),
                    self_pattern: None,
                    bounds: Vec::new(),
                    trait_type: contract_type_ref(
                        &Type::ResolvedPath(
                            implementation.trait_.as_ref().expect("trait impl").clone(),
                        ),
                        document,
                        &type_ids,
                        limits,
                        &mut diagnostics,
                        0,
                    ),
                    associated_types: Vec::new(),
                };
                bind_concrete_implementation(
                    &mut fact,
                    &implementation.for_,
                    if ambiguous_impl_bindings {
                        &[]
                    } else {
                        owner_type_parameters
                    },
                );
                fact.trait_type
            }),
            self_form: if let ItemEnum::Function(function) = &item.inner {
                function
                    .sig
                    .inputs
                    .first()
                    .filter(|(name, _)| name == "self")
                    .and_then(|(_, ty)| match ty {
                        Type::Generic(name) if name == "Self" => Some(RustSelfForm::Value),
                        Type::BorrowedRef {
                            is_mutable, type_, ..
                        } if matches!(type_.as_ref(), Type::Generic(name) if name == "Self") => {
                            Some(if *is_mutable {
                                RustSelfForm::Mutable
                            } else {
                                RustSelfForm::Shared
                            })
                        }
                        _ => self_pattern(ty, document, &type_ids, limits, &mut diagnostics, 0)
                            .map(|pattern| RustSelfForm::Other { pattern }),
                    })
            } else {
                None
            },
            non_overridable: None,
            ambient_use: None,
            value_type: None,
            proxied_type: None,
            id: member_id.clone(),
            owner: owner_item_id,
            name: name.to_owned(),
            member_kind,
            visibility: semantic_visibility(&item.visibility),
            is_static,
            is_abstract: matches!(&item.inner, ItemEnum::Function(function) if !function.has_body),
            is_virtual: false,
            implicit_operation: None,
            explicit_operation: None,
            callable_family_complete: false,
            exact_return_classes: Vec::new(),
            signature,
            receiver: has_receiver.then_some(ReceiverFact { pointer: false }),
            extension_receiver: None,
            extension_receiver_constraints: Vec::new(),
            aliases: Vec::new(),
            guard: None,
            locator: Locator::artifact(
                source_relative_path.unwrap_or(ARTIFACT_LOCATOR_PATH),
                format!("{path}#{member_id}"),
            ),
        });
        if diagnostics.total() != diagnostics_before {
            links.incomplete_callable_owner_refs.push(TypeRef::Named {
                name: owner_name,
                arguments: Vec::new(),
                nullable: false,
            });
        }
    }

    let mut type_aliases_seen = types
        .iter()
        .map(|fact| fact.aliases.iter().cloned().collect::<RandomHashSet<_>>())
        .collect::<Vec<_>>();
    let mut member_aliases_seen = members
        .iter()
        .map(|fact| fact.aliases.iter().cloned().collect::<RandomHashSet<_>>())
        .collect::<Vec<_>>();
    apply_reexports(
        &ordered_items,
        &projection,
        cancellation,
        &mut ReexportProjection {
            member_position: &member_position,
            types: &mut types,
            members: &mut members,
            diagnostics: &mut diagnostics,
            type_aliases_seen: &mut type_aliases_seen,
            member_aliases_seen: &mut member_aliases_seen,
        },
    );
    types.sort_by(|left, right| left.name.cmp(&right.name).then(left.id.cmp(&right.id)));
    members.sort_by(|left, right| {
        left.owner
            .cmp(&right.owner)
            .then(left.name.cmp(&right.name))
            .then(left.id.cmp(&right.id))
    });
    let remaining_records = limits
        .max_records
        .saturating_sub(types.len().saturating_add(members.len()));
    let (relations, relations_limited) = relations.finish(remaining_records);
    if relations_limited {
        diagnostics.warning(
            "limit.records",
            None,
            format!(
                "producer stopped after {} total records",
                limits.max_records
            ),
        );
    }
    links.declarations_interrupted |= relations_limited
        || types.len().saturating_add(members.len()) >= limits.max_records
        || cancellation.is_some_and(CancellationToken::is_cancelled);
    // Resolve local decode vetoes in the document that reported them. External
    // references remain pending until the joined source set supplies the owner.
    for owner in &mut links.incomplete_callable_owner_refs[decode_veto_start..] {
        if let TypeRef::Named { name, .. } = owner
            && let Some(id) = type_id_by_name.get(name)
        {
            *owner = TypeRef::Declared {
                id: id.clone(),
                arguments: Vec::new(),
                nullable: false,
            };
        }
    }
    certify_callable_families(&types, &mut members, links);
    finish(
        request,
        artifact_sha256,
        types,
        members,
        relations,
        diagnostics,
    )
}

fn parent_index(
    items: &[&Item],
    cancellation: Option<&CancellationToken>,
) -> Option<HashMap<Id, Id>> {
    let mut parents = HashMap::default();
    for item in items {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return None;
        }
        for child in child_ids(&item.inner) {
            parents.entry(child).or_insert(item.id);
        }
    }
    Some(parents)
}

#[derive(Debug, Clone, Copy)]
enum NameIndexError {
    Cancelled,
    Limit,
}

fn item_names(
    document: &RustdocCrate,
    root: &Item,
    cancellation: Option<&CancellationToken>,
) -> Result<HashMap<Id, String>, NameIndexError> {
    let mut names = HashMap::default();
    let mut total_name_bytes = 0_usize;
    for (id, summary) in &document.paths {
        let name_bytes = summary
            .path
            .iter()
            .map(String::len)
            .sum::<usize>()
            .saturating_add(summary.path.len().saturating_sub(1));
        if name_bytes > MAX_MODEL_NAME_BYTES
            || total_name_bytes.saturating_add(name_bytes) > MAX_TOTAL_MODEL_NAME_BYTES
        {
            return Err(NameIndexError::Limit);
        }
        let name = summary.path.join(".");
        total_name_bytes = total_name_bytes.saturating_add(name.len());
        names.insert(*id, name);
    }
    if !names.contains_key(&root.id) {
        let root_name = root
            .name
            .clone()
            .unwrap_or_else(|| "crate".to_owned())
            .replace('-', "_");
        insert_bounded_name(&mut names, root.id, root_name, &mut total_name_bytes)?;
    }

    let mut stack = vec![root.id];
    let mut visited = HashSet::default();
    while let Some(parent_id) = stack.pop() {
        if !visited.insert(parent_id) {
            continue;
        }
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err(NameIndexError::Cancelled);
        }
        let Some(parent) = document.index.get(&parent_id) else {
            continue;
        };
        let parent_name = names.get(&parent_id).cloned();
        for child_id in child_ids(&parent.inner) {
            if !names.contains_key(&child_id)
                && let Some(child) = document.index.get(&child_id)
            {
                let derived = match &child.inner {
                    ItemEnum::Impl(implementation) => {
                        resolved_type_name(&implementation.for_, document)
                    }
                    _ => parent_name
                        .as_ref()
                        .zip(child.name.as_ref())
                        .map(|(parent, name)| bounded_child_name(parent, name))
                        .transpose()?,
                };
                if let Some(name) = derived {
                    insert_bounded_name(&mut names, child_id, name, &mut total_name_bytes)?;
                }
            }
            stack.push(child_id);
        }
    }
    Ok(names)
}

fn bounded_child_name(parent: &str, child: &str) -> Result<String, NameIndexError> {
    let length = parent.len().saturating_add(1).saturating_add(child.len());
    if length > MAX_MODEL_NAME_BYTES {
        return Err(NameIndexError::Limit);
    }
    Ok(format!("{parent}.{child}"))
}

fn insert_bounded_name(
    names: &mut HashMap<Id, String>,
    id: Id,
    name: String,
    total_name_bytes: &mut usize,
) -> Result<(), NameIndexError> {
    if name.len() > MAX_MODEL_NAME_BYTES
        || total_name_bytes.saturating_add(name.len()) > MAX_TOTAL_MODEL_NAME_BYTES
    {
        return Err(NameIndexError::Limit);
    }
    *total_name_bytes = total_name_bytes.saturating_add(name.len());
    names.insert(id, name);
    Ok(())
}

fn visible_items(
    document: &RustdocCrate,
    items: &[&Item],
    parents: &HashMap<Id, Id>,
    cancellation: Option<&CancellationToken>,
) -> Option<HashSet<Id>> {
    let mut visible = HashSet::default();
    let mut queue = VecDeque::from([document.root]);
    while let Some(id) = queue.pop_front() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return None;
        }
        if !visible.insert(id) {
            continue;
        }
        let Some(item) = document.index.get(&id) else {
            continue;
        };
        for child in child_ids(&item.inner) {
            let Some(child_item) = document.index.get(&child) else {
                continue;
            };
            let inherited = matches!(item.inner, ItemEnum::Trait(_) | ItemEnum::Enum(_))
                || matches!(&item.inner, ItemEnum::Impl(implementation) if implementation.trait_.is_some());
            let structural = matches!(child_item.inner, ItemEnum::Impl(_));
            if matches!(child_item.visibility, RustVisibility::Public) || inherited || structural {
                queue.push_back(child);
            }
            if let ItemEnum::Use(import) = &child_item.inner
                && matches!(child_item.visibility, RustVisibility::Public)
                && let Some(target) = import.id
            {
                queue.push_back(target);
            }
        }
    }
    for item in items {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return None;
        }
        if item.crate_id == document.index[&document.root].crate_id
            && matches!(item.visibility, RustVisibility::Public)
            && parents.get(&item.id).is_none()
            && document.paths.contains_key(&item.id)
        {
            visible.insert(item.id);
        }
    }
    Some(visible)
}

fn child_ids(inner: &ItemEnum) -> Vec<Id> {
    match inner {
        ItemEnum::Module(module) => module.items.clone(),
        ItemEnum::Struct(structure) => {
            let mut ids = match &structure.kind {
                StructKind::Unit => Vec::new(),
                StructKind::Tuple(fields) => fields.iter().flatten().copied().collect(),
                StructKind::Plain { fields, .. } => fields.clone(),
            };
            ids.extend(structure.impls.iter().copied());
            ids
        }
        ItemEnum::Union(union) => union.fields.iter().chain(&union.impls).copied().collect(),
        ItemEnum::Enum(enumeration) => enumeration
            .variants
            .iter()
            .chain(&enumeration.impls)
            .copied()
            .collect(),
        ItemEnum::Trait(trait_) => trait_
            .items
            .iter()
            .chain(&trait_.implementations)
            .copied()
            .collect(),
        ItemEnum::Impl(implementation) => implementation.items.clone(),
        ItemEnum::Primitive(primitive) => primitive.impls.clone(),
        _ => Vec::new(),
    }
}

fn is_type_item(inner: &ItemEnum) -> bool {
    matches!(
        inner,
        ItemEnum::Module(_)
            | ItemEnum::Struct(_)
            | ItemEnum::Union(_)
            | ItemEnum::Enum(_)
            | ItemEnum::Trait(_)
            | ItemEnum::TraitAlias(_)
            | ItemEnum::TypeAlias(_)
            | ItemEnum::AssocType { .. }
            | ItemEnum::Primitive(_)
    )
}

fn type_shape<'a>(
    item: &'a Item,
    document: &RustdocCrate,
    type_ids: &HashMap<Id, String>,
    limits: &ArtifactProducerLimits,
    diagnostics: &mut BoundedProducerDiagnostics,
) -> (TypeKind, &'a Generics, Vec<HierarchyFact>) {
    let (kind, generics, bounds) = match &item.inner {
        ItemEnum::Module(_) => (TypeKind::Module, empty_generics(), &[][..]),
        ItemEnum::Primitive(_) => (TypeKind::Struct, empty_generics(), &[][..]),
        ItemEnum::Struct(structure) => (TypeKind::Struct, &structure.generics, &[][..]),
        ItemEnum::Union(union) => (TypeKind::Union, &union.generics, &[][..]),
        ItemEnum::Enum(enumeration) => (TypeKind::Enum, &enumeration.generics, &[][..]),
        ItemEnum::Trait(trait_) => (TypeKind::Trait, &trait_.generics, trait_.bounds.as_slice()),
        ItemEnum::TraitAlias(alias) => (
            TypeKind::TypeAlias,
            &alias.generics,
            alias.params.as_slice(),
        ),
        ItemEnum::TypeAlias(alias) => (TypeKind::TypeAlias, &alias.generics, &[][..]),
        ItemEnum::AssocType {
            generics, bounds, ..
        } => (TypeKind::TypeAlias, generics, bounds.as_slice()),
        _ => unreachable!("type_shape is called only for type items"),
    };
    let hierarchy = bounds
        .iter()
        .filter_map(|bound| match bound {
            GenericBound::TraitBound { trait_, .. } => {
                let target = path_type_ref(trait_, document, type_ids, limits, diagnostics, 0);
                nominal_hierarchy_fact(HierarchyKind::Extends, target, item.id, diagnostics)
            }
            _ => None,
        })
        .collect();
    (kind, generics, hierarchy)
}

fn nominal_hierarchy_fact(
    hierarchy_kind: HierarchyKind,
    mut target: TypeRef,
    item: Id,
    diagnostics: &mut BoundedProducerDiagnostics,
) -> Option<HierarchyFact> {
    if !matches!(target, TypeRef::Named { .. } | TypeRef::Declared { .. }) {
        diagnostics.warning(
            "rust.rustdoc.nonconcrete_hierarchy_unprojected",
            Some(format!("item.{}", item.0)),
            format!("hierarchy {hierarchy_kind:?} requires a named target: {target:?}"),
        );
        return None;
    }
    // Keep the nominal edge without claiming to solve its projected arguments.
    // Signatures and implementation contracts retain their projections.
    let mut pending = vec![&mut target];
    while let Some(reference) = pending.pop() {
        match reference {
            TypeRef::Projection { .. } => {
                *reference = TypeRef::Wildcard {
                    variance: WildcardVariance::Any,
                    bound: None,
                };
            }
            TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. } => {
                pending.extend(arguments);
            }
            TypeRef::Array { element }
            | TypeRef::ByRef { element, .. }
            | TypeRef::Pointer { element }
            | TypeRef::Slice { element }
            | TypeRef::FixedArray { element, .. }
            | TypeRef::Channel { element, .. } => pending.push(element),
            TypeRef::Map { key, value } => {
                pending.push(key);
                pending.push(value);
            }
            TypeRef::Wildcard { bound, .. } => pending.extend(bound.as_deref_mut()),
            TypeRef::Tuple { elements } => pending.extend(elements),
            TypeRef::Function { parameters, result } => {
                pending.extend(parameters.iter_mut().map(|parameter| &mut parameter.r#type));
                pending.extend(result.as_deref_mut());
            }
            TypeRef::TypeParameter { .. } | TypeRef::Unknown => {}
        }
    }
    Some(HierarchyFact {
        hierarchy_kind,
        target,
        declaration_ordinal: None,
    })
}

fn empty_generics() -> &'static Generics {
    static EMPTY: std::sync::OnceLock<Generics> = std::sync::OnceLock::new();
    EMPTY.get_or_init(|| Generics {
        params: Vec::new(),
        where_predicates: Vec::new(),
    })
}

fn generic_parameters(
    generics: &Generics,
) -> impl Iterator<Item = &rustdoc_types::GenericParamDef> {
    generics.params.iter().filter(|parameter| {
        matches!(
            parameter.kind,
            rustdoc_types::GenericParamDefKind::Type {
                is_synthetic: false,
                ..
            } | rustdoc_types::GenericParamDefKind::Const { .. }
        )
    })
}

fn generic_names(generics: &Generics) -> Vec<String> {
    generic_parameters(generics)
        .map(|parameter| parameter.name.clone())
        .collect()
}

fn rust_parameter_name(name: &str) -> Option<String> {
    let mut characters = name.chars();
    let first = characters.next()?;
    if name == "_" || !(first == '_' || first.is_alphabetic()) {
        return None;
    }
    characters
        .all(|character| character == '_' || character.is_alphanumeric())
        .then(|| name.to_owned())
}

fn member_kind(inner: &ItemEnum) -> Option<MemberKind> {
    match inner {
        ItemEnum::Function(_) => Some(MemberKind::Function),
        ItemEnum::StructField(_) => Some(MemberKind::Field),
        ItemEnum::Variant(_) => Some(MemberKind::Constant),
        ItemEnum::Constant { .. } | ItemEnum::AssocConst { .. } => Some(MemberKind::Constant),
        ItemEnum::Static(_) => Some(MemberKind::Static),
        ItemEnum::Macro(_) | ItemEnum::ProcMacro(_) => Some(MemberKind::Macro),
        _ => None,
    }
}

fn member_signature(
    item: &Item,
    projection: &RustdocTypeProjection<'_>,
    diagnostics: &mut BoundedProducerDiagnostics,
) -> Option<Signature> {
    let (parameters, returns, type_parameters) = match &item.inner {
        ItemEnum::Function(function) => (
            function
                .sig
                .inputs
                .iter()
                .map(|(name, ty)| Parameter {
                    name: rust_parameter_name(name),
                    r#type: projection.project(ty, diagnostics, 0),
                    optional: false,
                    variadic: false,
                    role: None,
                    passing_mode: Default::default(),
                })
                .collect(),
            function
                .sig
                .output
                .as_ref()
                .map(|ty| projection.project(ty, diagnostics, 0)),
            generic_names(&function.generics),
        ),
        ItemEnum::StructField(ty)
        | ItemEnum::Constant { type_: ty, .. }
        | ItemEnum::AssocConst { type_: ty, .. } => (
            Vec::new(),
            Some(projection.project(ty, diagnostics, 0)),
            Vec::new(),
        ),
        ItemEnum::Static(static_) => (
            Vec::new(),
            Some(projection.project(&static_.type_, diagnostics, 0)),
            Vec::new(),
        ),
        ItemEnum::Variant(variant) => {
            let fields = match &variant.kind {
                VariantKind::Plain => Vec::new(),
                VariantKind::Tuple(fields) => fields.iter().flatten().copied().collect(),
                VariantKind::Struct { fields, .. } => fields.clone(),
            };
            let parameters = fields
                .iter()
                .enumerate()
                .filter_map(|(index, id)| {
                    projection
                        .document
                        .index
                        .get(id)
                        .map(|field| (index, field))
                })
                .filter_map(|(index, field)| match &field.inner {
                    ItemEnum::StructField(ty) => Some(Parameter {
                        name: field.name.clone().or_else(|| Some(index.to_string())),
                        r#type: projection.project(ty, diagnostics, 0),
                        optional: false,
                        variadic: false,
                        role: None,
                        passing_mode: Default::default(),
                    }),
                    _ => None,
                })
                .collect();
            (parameters, None, Vec::new())
        }
        ItemEnum::Macro(_) | ItemEnum::ProcMacro(_) => return None,
        _ => return None,
    };
    Some(Signature {
        type_parameters,
        parameters,
        returns,
    })
}

fn rust_type_ref(
    ty: &Type,
    document: &RustdocCrate,
    type_ids: &HashMap<Id, String>,
    limits: &ArtifactProducerLimits,
    diagnostics: &mut BoundedProducerDiagnostics,
    depth: usize,
) -> TypeRef {
    RustdocTypeProjection {
        document,
        type_ids,
        canonical_owner: None,
        parameter_bindings: &[],
        owner_type_parameters: &[],
        self_type: None,
        limits,
    }
    .project(ty, diagnostics, depth)
}

struct RustdocTypeProjection<'a> {
    document: &'a RustdocCrate,
    type_ids: &'a HashMap<Id, String>,
    canonical_owner: Option<(Id, &'a str)>,
    parameter_bindings: &'a [(String, String)],
    owner_type_parameters: &'a [String],
    self_type: Option<&'a TypeRef>,
    limits: &'a ArtifactProducerLimits,
}

impl RustdocTypeProjection<'_> {
    fn project(
        &self,
        ty: &Type,
        diagnostics: &mut BoundedProducerDiagnostics,
        depth: usize,
    ) -> TypeRef {
        if depth >= self.limits.max_signature_depth {
            diagnostics.warning(
                "limit.signature_depth",
                None,
                format!(
                    "Rust signature exceeded depth {}",
                    self.limits.max_signature_depth
                ),
            );
            return TypeRef::named("_");
        }
        let next = depth + 1;
        match ty {
            Type::ResolvedPath(path) => self.path(path, diagnostics, next),
            // rustdoc can emit generic binders from an enclosing trait or impl
            // that are not present in the projected declaration's signature.
            // Preserve the uncertainty without producing an invalid pack whose
            // type parameter references cannot be resolved by the compiler.
            Type::Generic(name) if name == "Self" && self.self_type.is_some() => {
                self.self_type.expect("impl self type").clone()
            }
            Type::Generic(name)
                if self
                    .parameter_bindings
                    .iter()
                    .any(|(binder, _)| binder == name) =>
            {
                TypeRef::TypeParameter {
                    name: self
                        .parameter_bindings
                        .iter()
                        .find(|(binder, _)| binder == name)
                        .expect("known impl binder")
                        .1
                        .clone(),
                }
            }
            Type::Generic(name) if self.owner_type_parameters.contains(name) => {
                TypeRef::TypeParameter { name: name.clone() }
            }
            Type::Generic(_) => TypeRef::Wildcard {
                variance: WildcardVariance::Any,
                bound: None,
            },
            Type::Primitive(name) => TypeRef::named(name),
            Type::Tuple(elements) if elements.is_empty() => TypeRef::Wildcard {
                variance: WildcardVariance::Any,
                bound: None,
            },
            Type::Tuple(elements) => TypeRef::Tuple {
                elements: elements
                    .iter()
                    .map(|element| self.project(element, diagnostics, next))
                    .collect(),
            },
            Type::Slice(element) | Type::Array { type_: element, .. } => TypeRef::Array {
                element: Box::new(self.project(element, diagnostics, next)),
            },
            Type::RawPointer { type_, .. } | Type::BorrowedRef { type_, .. } => TypeRef::ByRef {
                element: Box::new(self.project(type_, diagnostics, next)),
                reference_kind: TypeRefReferenceKind::Lvalue,
            },
            Type::FunctionPointer(pointer) => TypeRef::Function {
                parameters: pointer
                    .sig
                    .inputs
                    .iter()
                    .map(|(name, ty)| Parameter {
                        name: rust_parameter_name(name),
                        r#type: self.project(ty, diagnostics, next),
                        optional: false,
                        variadic: false,
                        role: None,
                        passing_mode: Default::default(),
                    })
                    .collect(),
                result: pointer
                    .sig
                    .output
                    .as_ref()
                    .map(|ty| Box::new(self.project(ty, diagnostics, next))),
            },
            Type::Pat { type_, .. } => self.project(type_, diagnostics, next),
            Type::QualifiedPath {
                name,
                args,
                self_type,
                trait_,
            } => qualified_projection(name, args.as_deref(), self_type, trait_.as_ref(), |ty| {
                self.project(ty, diagnostics, next)
            }),
            // Existential and trait-object bounds have no structured signature
            // representation. Preserve their uncertainty explicitly.
            Type::DynTrait(_) | Type::ImplTrait(_) => TypeRef::Wildcard {
                variance: WildcardVariance::Any,
                bound: None,
            },
            Type::Infer => TypeRef::named("_"),
        }
    }
    fn path(
        &self,
        path: &RustdocPath,
        diagnostics: &mut BoundedProducerDiagnostics,
        depth: usize,
    ) -> TypeRef {
        let arguments = path
            .args
            .as_deref()
            .map(|args| self.arguments(args, diagnostics, depth))
            .unwrap_or_default();
        if let Some(id) = self
            .canonical_owner
            .filter(|(owner, _)| *owner == path.id)
            .map(|(_, id)| id)
            .or_else(|| self.type_ids.get(&path.id).map(String::as_str))
        {
            TypeRef::Declared {
                id: id.to_owned(),
                arguments,
                nullable: false,
            }
        } else {
            TypeRef::Named {
                name: normalized_path(path, self.document),
                arguments,
                nullable: false,
            }
        }
    }

    fn arguments(
        &self,
        args: &GenericArgs,
        diagnostics: &mut BoundedProducerDiagnostics,
        depth: usize,
    ) -> Vec<TypeRef> {
        match args {
            GenericArgs::AngleBracketed { args, .. } => args
                .iter()
                .filter_map(|argument| match argument {
                    GenericArg::Type(ty) => Some(self.project(ty, diagnostics, depth)),
                    _ => None,
                })
                .collect(),
            GenericArgs::Parenthesized { inputs, output } => {
                let mut types = inputs
                    .iter()
                    .map(|ty| self.project(ty, diagnostics, depth))
                    .collect::<Vec<_>>();
                if let Some(output) = output {
                    types.push(self.project(output, diagnostics, depth));
                }
                types
            }
            GenericArgs::ReturnTypeNotation => Vec::new(),
        }
    }
}

fn path_type_ref(
    path: &RustdocPath,
    document: &RustdocCrate,
    type_ids: &HashMap<Id, String>,
    limits: &ArtifactProducerLimits,
    diagnostics: &mut BoundedProducerDiagnostics,
    depth: usize,
) -> TypeRef {
    RustdocTypeProjection {
        document,
        type_ids,
        canonical_owner: None,
        parameter_bindings: &[],
        owner_type_parameters: &[],
        self_type: None,
        limits,
    }
    .path(path, diagnostics, depth)
}

fn normalized_path(path: &RustdocPath, document: &RustdocCrate) -> String {
    document
        .paths
        .get(&path.id)
        .map(|summary| summary.path.join("."))
        .unwrap_or_else(|| path.path.replace("::", "."))
}

fn resolved_type_name(ty: &Type, document: &RustdocCrate) -> Option<String> {
    match ty {
        Type::ResolvedPath(path) => Some(normalized_path(path, document)),
        Type::Primitive(name) => Some(format!("core.primitive.{name}")),
        Type::Slice(_) => Some("core.primitive.slice".to_owned()),
        Type::Array { .. } => Some("core.primitive.array".to_owned()),
        _ => None,
    }
}

fn owner_name(
    id: Id,
    parents: &HashMap<Id, Id>,
    document: &RustdocCrate,
    names: &HashMap<Id, String>,
) -> Option<String> {
    let parent = *parents.get(&id)?;
    let item = document.index.get(&parent)?;
    match &item.inner {
        ItemEnum::Impl(implementation) => names
            .get(&parent)
            .cloned()
            .or_else(|| resolved_type_name(&implementation.for_, document)),
        _ => names.get(&parent).cloned(),
    }
}

// Impl identity must retain trait arguments and the structured self pattern:
// Extend<T> and Extend<&T> can have otherwise identical method signatures.
fn trait_impl_identity(implementation: &rustdoc_types::Impl, document: &RustdocCrate) -> String {
    let mut contract = serde_json::to_value((
        &implementation.for_,
        &implementation.trait_,
        &implementation.generics,
    ))
    .expect("rustdoc impl contract is JSON serializable");
    let mut pending = vec![&mut contract];
    while let Some(value) = pending.pop() {
        match value {
            serde_json::Value::Object(fields) => {
                if let Some(id) = fields.get("id").and_then(serde_json::Value::as_u64)
                    && let Some(path) = fields.get("path").and_then(serde_json::Value::as_str)
                {
                    // These are structured rustdoc Path objects, not source
                    // text. Their Id is local to one JSON document.
                    let path = RustdocPath {
                        path: path.to_owned(),
                        id: Id(u32::try_from(id).expect("rustdoc IDs are u32")),
                        args: None,
                    };
                    fields.insert(
                        "path".to_owned(),
                        serde_json::Value::String(normalized_path(&path, document)),
                    );
                    fields.remove("id");
                }
                pending.extend(fields.values_mut());
            }
            serde_json::Value::Array(values) => pending.extend(values),
            _ => {}
        }
    }
    lower_hex_string(&sha256_bytes(
        &serde_json::to_vec(&contract).expect("normalized impl contract is JSON serializable"),
    ))
}

fn semantic_visibility(visibility: &RustVisibility) -> Visibility {
    match visibility {
        RustVisibility::Public => Visibility::Public,
        RustVisibility::Crate => Visibility::Internal,
        RustVisibility::Restricted { .. } => Visibility::Package,
        RustVisibility::Default => Visibility::Public,
    }
}

struct RustdocProjectionIndex<'a> {
    document: &'a RustdocCrate,
    visible: &'a HashSet<Id>,
    parents: &'a HashMap<Id, Id>,
    names: &'a HashMap<Id, String>,
    type_ids: &'a HashMap<Id, String>,
    type_position: &'a HashMap<Id, usize>,
    type_item_by_name: &'a RandomHashMap<String, Id>,
}

#[allow(clippy::too_many_arguments)]
fn apply_impl_hierarchy(
    items: &[&Item],
    projection: &RustdocProjectionIndex<'_>,
    types: &mut [TypeFact],
    limits: &ArtifactProducerLimits,
    diagnostics: &mut BoundedProducerDiagnostics,
    cancellation: Option<&CancellationToken>,
    hierarchy_seen: &mut [RandomHashSet<HierarchyFact>],
    links: &mut SourceSetLinks,
) {
    for item in items {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            diagnostics.error(
                "artifact.cancelled",
                None,
                "rustdoc artifact production was cancelled",
            );
            return;
        }
        let ItemEnum::Impl(implementation) = &item.inner else {
            continue;
        };
        if !projection.visible.contains(&item.id) {
            continue;
        }
        let diagnostics_before = diagnostics.total();
        project_impl_hierarchy(
            item,
            implementation,
            projection,
            types,
            limits,
            diagnostics,
            hierarchy_seen,
        );
        if diagnostics.total() != diagnostics_before
            && implementation.blanket_impl.is_none()
            && let Some(owner) = projection
                .names
                .get(&item.id)
                .cloned()
                .or_else(|| resolved_type_name(&implementation.for_, projection.document))
        {
            links.incomplete_callable_owner_refs.push(TypeRef::Named {
                name: owner,
                arguments: Vec::new(),
                nullable: false,
            });
        }
        project_impl_contract(
            item,
            implementation,
            projection,
            types,
            limits,
            diagnostics,
            links,
        );
    }
}

fn compiler_derived_trait_impl(
    implementation: &rustdoc_types::Impl,
    document: &RustdocCrate,
) -> bool {
    implementation.is_synthetic
        || implementation.trait_.as_ref().is_some_and(|trait_| {
            matches!(document.index.get(&trait_.id).map(|item| &item.inner),
            Some(ItemEnum::Trait(ty)) if ty.is_auto)
                || matches!(
                    normalized_path(trait_, document).as_str(),
                    "core.marker.Send"
                        | "core.marker.Sync"
                        | "core.marker.Unpin"
                        | "core.marker.Sized"
                )
        })
}

#[allow(clippy::too_many_arguments)]
fn project_impl_hierarchy(
    item: &Item,
    implementation: &rustdoc_types::Impl,
    projection: &RustdocProjectionIndex<'_>,
    types: &mut [TypeFact],
    limits: &ArtifactProducerLimits,
    diagnostics: &mut BoundedProducerDiagnostics,
    hierarchy_seen: &mut [RandomHashSet<HierarchyFact>],
) {
    // Rustdoc repeats blanket impls on each displayed receiver. Their `for_`
    // is instantiated for that receiver, but their binders still belong to
    // the original blanket impl. Only the trait-owned impl is evidence.
    if implementation.blanket_impl.is_some() {
        diagnostics.warning(
            "rust.rustdoc.blanket_impl_unprojected",
            Some(format!("item.{}", item.id.0)),
            "blanket implementation presentation copy was not projected",
        );
        return;
    }
    if compiler_derived_trait_impl(implementation, projection.document) {
        return;
    }
    for id in &implementation.items {
        if !projection.document.index.contains_key(id) {
            diagnostics.warning(
                "rust.rustdoc.impl_item_unavailable",
                Some(format!("item.{}", item.id.0)),
                format!(
                    "implementation item {} is absent from the rustdoc index",
                    id.0
                ),
            );
        }
    }
    if implementation.is_negative {
        return;
    }
    let Some(owner_name) = projection
        .names
        .get(&item.id)
        .cloned()
        .or_else(|| resolved_type_name(&implementation.for_, projection.document))
    else {
        diagnostics.warning(
            "rust.rustdoc.nonconcrete_impl_unprojected",
            Some(format!("item.{}", item.id.0)),
            "implementation target has no concrete rustdoc declaration owner",
        );
        return;
    };
    let Some(owner_item) = projection.type_item_by_name.get(&owner_name).copied() else {
        return;
    };
    let Some(trait_) = &implementation.trait_ else {
        return;
    };
    let target = path_type_ref(
        trait_,
        projection.document,
        projection.type_ids,
        limits,
        diagnostics,
        0,
    );
    let position = projection.type_position[&owner_item];
    let Some(hierarchy) =
        nominal_hierarchy_fact(HierarchyKind::Implements, target, item.id, diagnostics)
    else {
        return;
    };
    if hierarchy_seen[position].insert(hierarchy.clone()) {
        types[position].hierarchy.push(hierarchy);
    }
}

fn project_impl_contract(
    item: &Item,
    implementation: &rustdoc_types::Impl,
    projection: &RustdocProjectionIndex<'_>,
    types: &mut [TypeFact],
    limits: &ArtifactProducerLimits,
    diagnostics: &mut BoundedProducerDiagnostics,
    links: &mut SourceSetLinks,
) {
    if implementation.blanket_impl.is_some() {
        return;
    }
    if let Some(trait_) = &implementation.trait_ {
        let trait_name = normalized_path(trait_, projection.document);
        if compiler_derived_trait_impl(implementation, projection.document) {
            links.auto_traits.insert(trait_name);
            return;
        }
        let owner_name = projection
            .names
            .get(&item.id)
            .cloned()
            .or_else(|| resolved_type_name(&implementation.for_, projection.document));
        let mut implementation_fact = implemented_trait_fact(
            implementation,
            projection.document,
            projection.type_ids,
            limits,
            diagnostics,
        );
        implementation_fact.is_negative = implementation.is_negative;
        let parameters = generic_names(&implementation.generics);
        let mut bounds = generic_trait_bounds(
            &implementation.generics,
            projection.document,
            projection.type_ids,
            limits,
            diagnostics,
        );
        let self_type = contract_type_ref(
            &implementation.for_,
            projection.document,
            projection.type_ids,
            limits,
            diagnostics,
            0,
        );
        // Unsupported predicates and erased types cannot justify negative
        // evidence or a closed inventory. Keep other owners independently usable.
        let mut reviewed = implementation_conditions_supported(&implementation.generics);
        let roots = std::iter::once(&self_type)
            .chain(std::iter::once(&implementation_fact.trait_type))
            .chain(
                implementation_fact
                    .associated_types
                    .iter()
                    .map(|binding| &binding.r#type),
            )
            .chain(bounds.iter().flat_map(|bound| {
                std::iter::once(&bound.subject)
                    .chain(std::iter::once(&bound.bound.trait_type))
                    .chain(
                        bound
                            .bound
                            .associated_types
                            .iter()
                            .map(|binding| &binding.r#type),
                    )
            }));
        brokk_bifrost_semantic::analyzer::semantic::common::visit_type_refs(roots, |ty| {
            reviewed &= match ty {
                TypeRef::Unknown => false,
                TypeRef::TypeParameter { name } => parameters.contains(name) || name == "Self",
                _ => true,
            };
        });
        let mut conditions_reviewed = true;
        brokk_bifrost_semantic::analyzer::semantic::common::visit_type_refs(
            bounds
                .iter()
                .flat_map(|bound| [&bound.subject, &bound.bound.trait_type]),
            |ty| {
                conditions_reviewed &=
                    !matches!(ty, TypeRef::ByRef { .. } | TypeRef::Pointer { .. })
            },
        );
        reviewed &= conditions_reviewed;
        let mut pattern = self_pattern(
            &implementation.for_,
            projection.document,
            projection.type_ids,
            limits,
            diagnostics,
            0,
        );
        let mut pattern_reviewed = pattern.is_some();
        if let Some(pattern) = &pattern {
            let mut pending = vec![pattern];
            while let Some(pattern) = pending.pop() {
                match pattern {
                    RustSelfPattern::Reference { inner, .. } => pending.push(inner),
                    RustSelfPattern::Constructor { owner, arguments } => {
                        brokk_bifrost_semantic::analyzer::semantic::common::visit_type_refs(
                            [owner],
                            |ty| {
                                pattern_reviewed &= match ty {
                                    TypeRef::Unknown
                                    | TypeRef::ByRef { .. }
                                    | TypeRef::Pointer { .. } => false,
                                    TypeRef::TypeParameter { name } => {
                                        parameters.contains(name) || name == "Self"
                                    }
                                    _ => true,
                                }
                            },
                        );
                        pending.extend(arguments);
                    }
                    RustSelfPattern::Parameter { name } => {
                        pattern_reviewed &= parameters.contains(name) || name == "Self"
                    }
                }
            }
        }
        if !reviewed || !pattern_reviewed {
            // The list remains exhaustive; applicability is explicitly open.
            // Unknown is not an impossible condition, including for negatives.
            if !pattern_reviewed {
                pattern = Some(RustSelfPattern::Constructor {
                    owner: TypeRef::Unknown,
                    arguments: Vec::new(),
                });
            }
            bounds = vec![GenericTraitBound {
                subject: TypeRef::Unknown,
                bound: ImplementedTraitFact {
                    is_negative: false,
                    type_parameters: Vec::new(),
                    self_pattern: None,
                    bounds: Vec::new(),
                    trait_type: TypeRef::Unknown,
                    associated_types: Vec::new(),
                },
                maybe: false,
            }];
            for binding in &mut implementation_fact.associated_types {
                binding.r#type = TypeRef::Unknown;
            }
            // A Path always retains the trait's identity even if its arguments
            // cannot be represented. Erase arguments rather than its owner.
            if let TypeRef::Declared { arguments, .. } | TypeRef::Named { arguments, .. } =
                &mut implementation_fact.trait_type
            {
                arguments
                    .iter_mut()
                    .for_each(|argument| *argument = TypeRef::Unknown);
            }
            diagnostics.warning("rust.rustdoc.impl_conditions_unreviewed",
                Some(format!("item.{}", item.id.0)),
                "implementation retained with unknown applicability: unsupported types or predicates");
        }
        // Lifetime-only and non-nominal targets still need a trait-owned
        // rule when no concrete declaration can carry their applicability.
        let needs_rule = !implementation.generics.params.is_empty() || owner_name.is_none();
        let mut concrete = implementation_fact.clone();
        concrete.type_parameters = parameters.clone();
        concrete.self_pattern = pattern.clone();
        concrete.bounds = bounds.clone();
        if let Some(owner_item) = owner_name
            .as_ref()
            .and_then(|name| projection.type_item_by_name.get(name))
        {
            let position = projection.type_position[owner_item];
            union_facts(&mut types[position].implemented_traits, vec![concrete]);
        } else if let Some(owner) = owner_name {
            // A source-set trait can implement a type defined by another
            // document. Its defining type need not be repeated locally.
            links.concrete_trait_impls.push((owner, concrete));
        }
        if needs_rule {
            let fact = GenericTraitImplFact {
                type_parameters: parameters,
                self_pattern: pattern.expect("reviewed generic self pattern"),
                bounds,
                implementation: implementation_fact,
            };
            if let Some(position) = projection.type_position.get(&trait_.id) {
                union_facts(&mut types[*position].generic_trait_impls, vec![fact]);
            } else {
                links.generic_trait_impls.push((trait_name, fact));
            }
        }
    }
}

fn push_generic_relations(
    from: &str,
    generics: &Generics,
    document: &RustdocCrate,
    type_ids: &HashMap<Id, String>,
    relations: &mut RelationCollector,
) {
    for predicate in &generics.where_predicates {
        if relations.is_full() {
            return;
        }
        match predicate {
            WherePredicate::BoundPredicate { type_, bounds, .. } => {
                push_raw_type_relations(from, type_, document, type_ids, relations);
                for bound in bounds {
                    push_bound_relations(from, bound, document, type_ids, relations);
                }
            }
            WherePredicate::EqPredicate { lhs, rhs } => {
                push_raw_type_relations(from, lhs, document, type_ids, relations);
                if let Term::Type(rhs) = rhs {
                    push_raw_type_relations(from, rhs, document, type_ids, relations);
                }
            }
            WherePredicate::LifetimePredicate { .. } => {}
        }
    }
    for param in &generics.params {
        if relations.is_full() {
            return;
        }
        if let rustdoc_types::GenericParamDefKind::Type {
            bounds, default, ..
        } = &param.kind
        {
            for bound in bounds {
                push_bound_relations(from, bound, document, type_ids, relations);
            }
            if let Some(default) = default {
                push_raw_type_relations(from, default, document, type_ids, relations);
            }
        }
    }
}

fn push_bound_relations(
    from: &str,
    bound: &GenericBound,
    document: &RustdocCrate,
    type_ids: &HashMap<Id, String>,
    relations: &mut RelationCollector,
) {
    if let GenericBound::TraitBound { trait_, .. } = bound
        && let Some(to) = type_ids.get(&trait_.id)
    {
        push_relation(from, to, relations);
    }
    let _ = document;
}

fn push_type_relations(
    from: &str,
    ty: &Type,
    document: &RustdocCrate,
    type_ids: &HashMap<Id, String>,
    relations: &mut RelationCollector,
) {
    push_raw_type_relations(from, ty, document, type_ids, relations);
}

fn push_raw_type_relations(
    from: &str,
    ty: &Type,
    document: &RustdocCrate,
    type_ids: &HashMap<Id, String>,
    relations: &mut RelationCollector,
) {
    let mut stack = vec![ty];
    while let Some(current) = stack.pop() {
        if relations.is_full() {
            return;
        }
        match current {
            Type::ResolvedPath(path) => {
                if let Some(to) = type_ids.get(&path.id) {
                    push_relation(from, to, relations);
                }
                if let Some(args) = path.args.as_deref() {
                    push_generic_arg_types(args, &mut stack);
                }
            }
            Type::Tuple(types) => stack.extend(types),
            Type::Slice(type_)
            | Type::Array { type_, .. }
            | Type::Pat { type_, .. }
            | Type::RawPointer { type_, .. }
            | Type::BorrowedRef { type_, .. } => stack.push(type_),
            Type::FunctionPointer(pointer) => {
                stack.extend(pointer.sig.inputs.iter().map(|(_, ty)| ty));
                if let Some(output) = &pointer.sig.output {
                    stack.push(output);
                }
            }
            Type::QualifiedPath {
                self_type, trait_, ..
            } => {
                stack.push(self_type);
                if let Some(trait_) = trait_
                    && let Some(to) = type_ids.get(&trait_.id)
                {
                    push_relation(from, to, relations);
                }
            }
            Type::DynTrait(dyn_trait) => {
                for trait_ in &dyn_trait.traits {
                    if let Some(to) = type_ids.get(&trait_.trait_.id) {
                        push_relation(from, to, relations);
                    }
                }
            }
            Type::ImplTrait(bounds) => {
                for bound in bounds {
                    push_bound_relations(from, bound, document, type_ids, relations);
                }
            }
            Type::Generic(_) | Type::Primitive(_) | Type::Infer => {}
        }
    }
}

fn push_generic_arg_types<'a>(args: &'a GenericArgs, stack: &mut Vec<&'a Type>) {
    match args {
        GenericArgs::AngleBracketed { args, .. } => {
            stack.extend(args.iter().filter_map(|argument| match argument {
                GenericArg::Type(ty) => Some(ty),
                _ => None,
            }));
        }
        GenericArgs::Parenthesized { inputs, output } => {
            stack.extend(inputs);
            if let Some(output) = output {
                stack.push(output);
            }
        }
        GenericArgs::ReturnTypeNotation => {}
    }
}

fn push_type_ref_relations(from: &str, ty: &TypeRef, relations: &mut RelationCollector) {
    let mut stack = vec![ty];
    while let Some(current) = stack.pop() {
        if relations.is_full() {
            return;
        }
        match current {
            TypeRef::Projection {
                owner,
                trait_type,
                arguments,
                ..
            } => {
                stack.push(owner);
                stack.extend(trait_type.as_deref());
                stack.extend(arguments);
            }
            TypeRef::Declared { id, arguments, .. } => {
                push_relation(from, id, relations);
                stack.extend(arguments);
            }
            TypeRef::Named { arguments, .. } => stack.extend(arguments),
            TypeRef::Array { element }
            | TypeRef::ByRef { element, .. }
            | TypeRef::Pointer { element }
            | TypeRef::Slice { element }
            | TypeRef::FixedArray { element, .. }
            | TypeRef::Channel { element, .. }
            | TypeRef::Wildcard {
                bound: Some(element),
                ..
            } => stack.push(element),
            TypeRef::Map { key, value } => {
                stack.push(key);
                stack.push(value);
            }
            TypeRef::Tuple { elements } => stack.extend(elements),
            TypeRef::Function { parameters, result } => {
                stack.extend(parameters.iter().map(|parameter| &parameter.r#type));
                stack.extend(result.as_deref());
            }
            TypeRef::Unknown
            | TypeRef::TypeParameter { .. }
            | TypeRef::Wildcard { bound: None, .. } => {}
        }
    }
}

fn push_relation(from: &str, to: &str, relations: &mut RelationCollector) {
    let mut bytes = Vec::with_capacity(from.len() + to.len() + 1);
    bytes.extend_from_slice(from.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(to.as_bytes());
    relations.push(RelationFact {
        id: format!("relation.{}", lower_hex_string(&sha256_bytes(&bytes))),
        relation_kind: RelationKind::References,
        from: from.to_owned(),
        to: to.to_owned(),
    });
}

struct RelationCollector {
    relations: Vec<RelationFact>,
    ids: RandomHashSet<String>,
    max_records: usize,
    limited: bool,
}

impl RelationCollector {
    fn new(max_records: usize) -> Self {
        Self {
            relations: Vec::new(),
            ids: RandomHashSet::new(),
            max_records,
            limited: false,
        }
    }

    fn push(&mut self, relation: RelationFact) {
        if self.ids.contains(&relation.id) {
            return;
        }
        if self.relations.len() >= self.max_records {
            self.limited = true;
            return;
        }
        self.ids.insert(relation.id.clone());
        self.relations.push(relation);
    }

    fn is_full(&self) -> bool {
        self.relations.len() >= self.max_records
    }

    fn finish(mut self, max_records: usize) -> (Vec<RelationFact>, bool) {
        self.relations.sort_by(|left, right| left.id.cmp(&right.id));
        let limited = self.limited || self.relations.len() > max_records;
        self.relations.truncate(max_records);
        (self.relations, limited)
    }
}

struct ReexportProjection<'a> {
    member_position: &'a HashMap<Id, usize>,
    types: &'a mut [TypeFact],
    members: &'a mut [MemberFact],
    diagnostics: &'a mut BoundedProducerDiagnostics,
    type_aliases_seen: &'a mut [RandomHashSet<String>],
    member_aliases_seen: &'a mut [RandomHashSet<String>],
}

fn apply_reexports(
    items: &[&Item],
    projection: &RustdocProjectionIndex<'_>,
    cancellation: Option<&CancellationToken>,
    reexports: &mut ReexportProjection<'_>,
) {
    for item in items {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            reexports.diagnostics.error(
                "artifact.cancelled",
                None,
                "rustdoc artifact production was cancelled",
            );
            return;
        }
        let ItemEnum::Use(import) = &item.inner else {
            continue;
        };
        if !projection.visible.contains(&item.id) {
            continue;
        }
        if import.is_glob {
            reexports.diagnostics.warning(
                "rust.rustdoc.glob_reexport_unexpanded",
                Some(format!("item.{}", item.id.0)),
                "glob re-export cannot be mapped to exact aliases from this rustdoc record",
            );
            continue;
        }
        let Some(target) = import.id else {
            reexports.diagnostics.warning(
                "rust.rustdoc.reexport_target_unavailable",
                Some(format!("item.{}", item.id.0)),
                "public re-export target is absent from rustdoc JSON",
            );
            continue;
        };
        let Some(parent_name) = projection
            .parents
            .get(&item.id)
            .and_then(|parent| projection.names.get(parent))
        else {
            continue;
        };
        let alias = format!("{parent_name}.{}", import.name);
        if let Some(position) = projection.type_position.get(&target) {
            if reexports.type_aliases_seen[*position].insert(alias.clone()) {
                reexports.types[*position].aliases.push(alias);
            }
            continue;
        }
        let Some(position) = reexports.member_position.get(&target) else {
            reexports.diagnostics.warning(
                "rust.rustdoc.reexport_target_unavailable",
                Some(format!("item.{}", item.id.0)),
                "public re-export target has no emitted declaration fact",
            );
            continue;
        };
        let member = &mut reexports.members[*position];
        if reexports.member_aliases_seen[*position].insert(alias.clone()) {
            member.aliases.push(alias);
        }
    }
}

fn finish(
    request: &ArtifactProductionRequest,
    artifact_sha256: &str,
    types: Vec<TypeFact>,
    members: Vec<MemberFact>,
    relations: Vec<RelationFact>,
    mut diagnostics: BoundedProducerDiagnostics,
) -> ArtifactProduction {
    if types.is_empty() {
        diagnostics.error(
            "rust.rustdoc.no_external_declarations",
            None,
            "rustdoc JSON contains no externally visible Rust declarations",
        );
    }
    let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
    let shards = if types.is_empty() {
        Vec::new()
    } else {
        let collection_flows = collection_flow_facts(&types, &members);
        vec![AuthoredShard {
            id: "declarations.rust.external".to_owned(),
            activation: request.activation.clone(),
            payload: AuthoredPayload::DeclarationFacts {
                assembly_identity: None,
                type_forwards: Vec::new(),
                types,
                members,
                relations,
            },
            runtime_values: None,
            runtime_contracts: None,
            collection_flows,
            deferred_yields: None,
            conditional_type_refinements: None,
            callable_values: None,
        }]
    };
    let mut production =
        brokk_bifrost_semantic::analyzer::semantic_model::producer::finish_authored_pack_production(
            request,
            artifact_sha256,
            "bifrost-rustdoc-json",
            "rust",
            diagnostics,
            suppressed_diagnostics,
            shards,
        );
    if let Some(pack) = &mut production.pack {
        pack.producer.version = super::external::RUST_PACK_PRODUCER_VERSION.to_owned();
    }
    production
}

fn collection_flow_facts(
    types: &[TypeFact],
    members: &[MemberFact],
) -> Option<CollectionFlowsPayload> {
    let map = types.iter().find(|fact| {
        fact.name == RUST_STD_HASHMAP_NAME
            && fact.type_kind == TypeKind::Struct
            && fact.type_parameters.as_slice() == ["K", "V"]
    })?;
    let keyed_shape = CsmiCollectionFlowShape::Keyed {
        key: Box::new(
            brokk_bifrost_semantic::analyzer::semantic_model::csmi::collection_value_shape(
                "type-parameter.K",
            ),
        ),
        value: Box::new(
            brokk_bifrost_semantic::analyzer::semantic_model::csmi::collection_value_shape(
                "type-parameter.V",
            ),
        ),
        entry_components: Some(vec![
            CsmiCollectionFlowEntryComponent::Key,
            CsmiCollectionFlowEntryComponent::Value,
        ]),
    };
    let mut flows = Vec::new();
    for member in members.iter().filter(|member| {
        member.owner == map.id
            && member.member_kind == MemberKind::Method
            && !member.is_static
            && member.signature.is_some()
    }) {
        let signature = member.signature.as_ref()?;
        let arguments = &signature.parameters;
        let payload = match member.name.as_str() {
            "insert"
                if arguments.len() == 2
                    && arguments[0].r#type.is_type_parameter("K")
                    && arguments[1].r#type.is_type_parameter("V") =>
            {
                hashmap_insert_flow(member, keyed_shape.clone())
            }
            _ => continue,
        };
        flows.push(CollectionFlowFact {
            callable: member.id.clone(),
            payload,
            coverage: Some(Completeness::Complete),
            provenance: vec![format!(
                "rustdoc:{RUST_STD_CRATE_NAME}:{RUST_STD_HASHMAP_NAME}"
            )],
        });
    }
    flows.sort_unstable_by(|left, right| left.callable.cmp(&right.callable));
    (!flows.is_empty()).then_some(CollectionFlowsPayload { flows })
}

fn input_receiver_root() -> CsmiInputBoundaryRoot {
    CsmiInputBoundaryRoot::Receiver(CsmiInputReceiverRoot {
        phase: CsmiInputPhase::Input,
        role: CsmiReceiverRootRole::Receiver,
    })
}

fn output_receiver_root() -> CsmiOutputBoundaryRoot {
    CsmiOutputBoundaryRoot::Receiver(CsmiOutputReceiverRoot {
        phase: CsmiOutputPhase::Output,
        role: CsmiReceiverRootRole::Receiver,
    })
}

fn input_parameter(position: u32) -> CsmiInputBoundaryRoot {
    CsmiInputBoundaryRoot::Parameter(CsmiInputParameterRoot {
        phase: CsmiInputPhase::Input,
        role: CsmiParameterRootRole::Parameter,
        position,
    })
}

fn hashmap_insert_flow(
    member: &MemberFact,
    receiver_shape: CsmiCollectionFlowShape,
) -> CsmiCollectionFlowPayload {
    let key_position = 0;
    let mut value_projection =
        brokk_bifrost_semantic::analyzer::semantic_model::csmi::entry_parameter_projection(
            key_position,
        );
    value_projection.steps.push(CsmiProjectionStep {
        kind: "entry-value".to_owned(),
        args: None,
    });
    CsmiCollectionFlowPayload {
        kind: CsmiCollectionFlowKind::CollectionFlow,
        callable: member.id.clone(),
        receiver_substitution: None,
        roots: vec![
            CsmiCollectionFlowRoot {
                root: CsmiCollectionFlowBoundaryRoot::Input(input_receiver_root()),
                shape: receiver_shape.clone(),
            },
            CsmiCollectionFlowRoot {
                root: CsmiCollectionFlowBoundaryRoot::Input(input_parameter(0)),
                shape: brokk_bifrost_semantic::analyzer::semantic_model::csmi::collection_value_shape(
                    "type-parameter.K",
                ),
            },
            CsmiCollectionFlowRoot {
                root: CsmiCollectionFlowBoundaryRoot::Input(input_parameter(1)),
                shape: brokk_bifrost_semantic::analyzer::semantic_model::csmi::collection_value_shape(
                    "type-parameter.V",
                ),
            },
            CsmiCollectionFlowRoot {
                root: CsmiCollectionFlowBoundaryRoot::Output(output_receiver_root()),
                shape: receiver_shape,
            },
        ],
        transfers: vec![
            CsmiCollectionFlowTransfer {
                source: CsmiInputLocation {
                    root: input_parameter(0),
                    projection: None,
                },
                destination: CsmiOutputLocation {
                    root: output_receiver_root(),
                    projection: Some(
                        brokk_bifrost_semantic::analyzer::semantic_model::csmi::entry_parameter_projection(
                            key_position,
                        ),
                    ),
                },
            },
            CsmiCollectionFlowTransfer {
                source: CsmiInputLocation {
                    root: input_parameter(1),
                    projection: None,
                },
                destination: CsmiOutputLocation {
                    root: output_receiver_root(),
                    projection: Some(value_projection),
                },
            },
        ],
        invocations: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::analyzer::rust::test_support::rustdoc_item as item;

    use crate::analyzer::rust::rustdoc_artifact::*;

    #[test]
    fn uncertified_fields_are_not_read_by_current_producer() {
        let source = include_str!("rustdoc_artifact.rs");
        let production = source.split_once("#[cfg(test)]\nmod tests").unwrap().0;
        let external = include_str!("external.rs");
        for (_, field_read, _, _) in conversion_contract::UNCERTIFIED_FIELD_READS {
            assert!(
                !production.contains(field_read),
                "new read of {field_read} needs a contract update"
            );
            assert!(
                !external.contains(field_read),
                "new read of {field_read} needs a contract update"
            );
        }
    }

    #[test]
    fn uncertified_field_is_refused_if_future_producer_reads_it() {
        let marker = RustdocConversionCertificate {
            producer_contract: RUSTDOC_PRODUCER_CONTRACT.to_owned(),
            uncertified_fields: vec!["Item::stability".to_owned()],
        };
        assert!(
            validate_conversion_certificate(
                Some(&marker),
                RUSTDOC_PRODUCER_CONTRACT,
                &["Item::stability"]
            )
            .is_err()
        );
        assert!(
            validate_conversion_certificate(Some(&marker), "rustdoc-json-pack-producer/2", &[])
                .is_err()
        );
        assert!(
            validate_conversion_certificate(Some(&marker), RUSTDOC_PRODUCER_CONTRACT, &[]).is_ok()
        );
    }

    use rustdoc_types::{
        Abi, Function, FunctionHeader, FunctionSignature, GenericParamDef, GenericParamDefKind,
        Impl, ItemKind, ItemSummary, Module, Struct, Target, Trait, TraitBoundModifier, Use,
    };
    use std::fs;

    use crate::analyzer::semantic_model::ActivationSelector;

    use crate::analyzer::semantic_model::Compatibility;

    use crate::analyzer::semantic_model::CompilerOptions;

    use crate::analyzer::semantic_model::NameSelector;

    use crate::analyzer::semantic_model::Provenance;

    use crate::analyzer::semantic_model::Safety;

    use crate::analyzer::semantic_model::compile_pack;

    use brokk_bifrost_semantic::analyzer::semantic_model::producer::read_exact_source_set;

    #[test]
    fn facade_fixture_documents_decode_as_rustdoc_format_61() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rustdoc-facade");
        for name in [
            "core-v1.json",
            "core-v2.json",
            "facade-public.json",
            "facade-missing.json",
            "facade-private.json",
            "facade-shadowed.json",
            "facade-glob.json",
            "facade-two-globs.json",
            "facade-inlined.json",
            "facade-private-module.json",
            "cycle-a.json",
            "cycle-b.json",
        ] {
            let bytes = fs::read(root.join(name)).expect("synthetic rustdoc fixture exists");
            let document: RustdocCrate =
                serde_json::from_slice(&bytes).expect("fixture obeys rustdoc format 61");
            assert_eq!(document.format_version, 61, "{name}");
            assert!(document.index.contains_key(&document.root), "{name}");
        }
    }

    #[test]
    fn facade_fixture_edges_require_structured_targets_and_public_modules() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rustdoc-facade");
        let edges = |name: &str| {
            let document: RustdocCrate =
                serde_json::from_slice(&fs::read(root.join(name)).unwrap()).unwrap();
            let (routes, limited, unsupported) = collect_external_reexports(&document, 100);
            assert!(!limited, "{name}");
            assert!(!unsupported, "{name}");
            routes
        };
        assert!(matches!(
            edges("facade-public.json").as_slice(),
            [RustExternalReexport::ExplicitUse { target, .. }]
                if target.item_id == 100
                    && target.path.iter().map(String::as_str).eq(["sqlx_core", "query", "query"])
        ));
        assert!(matches!(
            edges("facade-glob.json").as_slice(),
            [RustExternalReexport::GlobUse { target_module, .. }]
                if target_module.path.iter().map(String::as_str).eq(["sqlx_core", "query"])
        ));
        assert!(matches!(
            edges("facade-inlined.json").as_slice(),
            [RustExternalReexport::InlinedItem { original, .. }]
                if original.path.iter().map(String::as_str).eq(["sqlx_core", "query", "query"])
        ));
        assert!(matches!(
            edges("facade-two-globs.json").as_slice(),
            [RustExternalReexport::GlobUse { glob_competitors, .. },
             RustExternalReexport::GlobUse { .. }]
                if glob_competitors.len() == 1
        ));
        assert!(matches!(
            edges("facade-shadowed.json").as_slice(),
            [RustExternalReexport::GlobUse { explicit_competitors, .. }]
                if explicit_competitors.iter().map(String::as_str).eq(["query"])
        ));
        for name in [
            "facade-missing.json",
            "facade-private.json",
            "facade-private-module.json",
        ] {
            assert!(edges(name).is_empty(), "{name}");
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10258: unresolved named and invalid external targets make facade routes incomplete"
    )]
    fn invalid_named_and_inlined_reexports_are_incomplete() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rustdoc-facade");
        for (fixture, item_id, target_id) in [
            ("facade-public.json", "1", "100"),
            ("facade-inlined.json", "1", "1"),
        ] {
            let original: serde_json::Value =
                serde_json::from_slice(&fs::read(root.join(fixture)).unwrap()).unwrap();
            for path in [
                serde_json::json!(["wrong", "query"]),
                serde_json::json!(["sqlx_core", ""]),
                serde_json::json!(["sqlx_core", "x".repeat(MAX_MODEL_NAME_BYTES + 1)]),
                serde_json::json!(vec!["sqlx_core"; 65]),
            ] {
                let mut json = original.clone();
                json["paths"][target_id]["path"] = path;
                let document: RustdocCrate = serde_json::from_value(json).unwrap();
                let (_, _, unsupported) = collect_external_reexports(&document, 100);
                assert!(unsupported, "{fixture}");
            }
            let mut json = original.clone();
            json["paths"].as_object_mut().unwrap().remove(target_id);
            let document: RustdocCrate = serde_json::from_value(json).unwrap();
            assert!(collect_external_reexports(&document, 100).2, "{fixture}");
            if fixture == "facade-public.json" {
                let mut json = original.clone();
                json["index"][item_id]["inner"]["use"]["id"] = serde_json::Value::Null;
                let document: RustdocCrate = serde_json::from_value(json).unwrap();
                assert!(collect_external_reexports(&document, 100).2);
            }
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10258: a local non-module Use is already an ordinary declaration alias"
    )]
    fn local_item_reexport_does_not_truncate_facade() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/rustdoc-facade/facade-public.json");
        let mut json: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture).unwrap()).unwrap();
        let mut local_module = json["index"]["0"].clone();
        local_module["id"] = serde_json::json!(3);
        local_module["name"] = serde_json::json!("error");
        local_module["inner"]["module"]["is_crate"] = serde_json::json!(false);
        local_module["inner"]["module"]["items"] = serde_json::json!([2]);
        json["index"]["3"] = local_module;
        let mut local_type = json["index"]["0"].clone();
        local_type["id"] = serde_json::json!(2);
        local_type["name"] = serde_json::json!("Error");
        local_type["inner"] = serde_json::json!({"struct": {
            "kind": "unit", "generics": {"params":[], "where_predicates":[]}, "impls":[]
        }});
        json["index"]["2"] = local_type;
        json["index"]["0"]["inner"]["module"]["items"] = serde_json::json!([1, 3]);
        json["index"]["1"]["inner"]["use"]["name"] = serde_json::json!("Error");
        json["index"]["1"]["inner"]["use"]["id"] = serde_json::json!(2);
        json["paths"].as_object_mut().unwrap().remove("100");
        let temp = tempfile::NamedTempFile::new().unwrap();
        fs::write(temp.path(), serde_json::to_vec(&json).unwrap()).unwrap();
        let mut request = request(temp.path().to_path_buf());
        request.activation[0].package = Some(NameSelector {
            name: "sqlx".to_owned(),
            version: Some("=1.0.0".to_owned()),
        });
        let product = RustdocJsonPackProducer
            .produce_exact_artifact(&request, &ArtifactProducerLimits::default());
        assert_eq!(product.completeness, Completeness::Complete);
        let pack = product.pack.unwrap();
        assert!(!pack.rust_external_reexports_truncated);
        assert!(pack.shards.iter().any(|shard| {
            let AuthoredPayload::DeclarationFacts { types, .. } = &shard.payload else {
                return false;
            };
            types.iter().any(|fact| {
                fact.name == "sqlx.error.Error"
                    && fact.aliases.iter().any(|alias| alias == "sqlx.Error")
            })
        }));
        let document: RustdocCrate = serde_json::from_value(json).unwrap();
        let (routes, limited, unsupported) = collect_external_reexports(&document, 100);
        assert!(routes.is_empty());
        assert!(!limited && !unsupported);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10258: many glob competitors consume one bounded carrier budget"
    )]
    fn glob_competitor_overflow_marks_surface_incomplete() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/rustdoc-facade/facade-glob.json");
        let mut json: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture).unwrap()).unwrap();
        for id in 2..20 {
            let mut item = json["index"]["1"].clone();
            item["id"] = serde_json::json!(id);
            item["inner"]["use"]["id"] = serde_json::json!(100 + id);
            json["index"][id.to_string()] = item;
            json["paths"][(100 + id).to_string()] = serde_json::json!({
                "crate_id": 1, "path": ["sqlx_core", format!("module{id}")], "kind": "module"
            });
            json["index"]["0"]["inner"]["module"]["items"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!(id));
        }
        let document: RustdocCrate = serde_json::from_value(json).unwrap();
        let (_, _, unsupported) = collect_external_reexports(&document, 4);
        assert!(unsupported);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10258: public facade paths beyond 64 modules are incomplete, not absent"
    )]
    fn deep_public_reexport_path_marks_surface_incomplete() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/rustdoc-facade/facade-public.json");
        let mut json: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture).unwrap()).unwrap();
        json["index"]["0"]["inner"]["module"]["items"] = serde_json::json!([2]);
        for id in 2..68 {
            let mut module = json["index"]["0"].clone();
            module["id"] = serde_json::json!(id);
            module["name"] = serde_json::json!(format!("m{id}"));
            module["inner"]["module"]["is_crate"] = serde_json::json!(false);
            module["inner"]["module"]["items"] =
                serde_json::json!([if id == 67 { 1 } else { id + 1 }]);
            json["index"][id.to_string()] = module;
        }
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("deep-route.json");
        fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
        let document: RustdocCrate = serde_json::from_value(json).unwrap();
        let (routes, _, unsupported) = collect_external_reexports(&document, 100);
        assert!(routes.is_empty());
        assert!(unsupported);
        let mut request = request(path);
        request.activation[0].package = Some(NameSelector {
            name: "sqlx".to_owned(),
            version: Some("=1.0.0".to_owned()),
        });
        let product = RustdocJsonPackProducer
            .produce_exact_artifact(&request, &ArtifactProducerLimits::default());
        let pack = product.pack.expect("deep route keeps declarations");
        assert_eq!(pack.completeness, Completeness::Complete);
        assert!(pack.rust_external_reexports_truncated);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10258: the external reexport limit counts routes, not later items"
    )]
    fn external_reexport_limit_is_exact_and_reports_truncation() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/rustdoc-facade/facade-two-globs.json");
        let mut json: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        // An orphan item with the highest id: it is scanned after both routes
        // but is not reachable from the root module, so it yields no route.
        let mut orphan = json["index"]["2"].clone();
        orphan["id"] = 3.into();
        json["index"]["3"] = orphan;
        let document: RustdocCrate = serde_json::from_value(json).unwrap();
        assert_eq!(document.index.len(), 4);
        let (all, limited, unsupported) = collect_external_reexports(&document, 100);
        assert!(!limited);
        assert!(!unsupported);
        assert_eq!(all.len(), 2);
        // Reaching the limit exactly is not truncation, even though the scan
        // continues past the last route over unrelated items.
        let (exact, limited, unsupported) = collect_external_reexports(&document, 2);
        assert!(!limited);
        assert!(!unsupported);
        assert_eq!(exact, all);
        // One route over the limit keeps the first route and reports the cut.
        let (over, limited, _) = collect_external_reexports(&document, 1);
        assert!(limited);
        assert_eq!(over.as_slice(), &all[..1]);
        let (none, limited, _) = collect_external_reexports(&document, 0);
        assert!(limited);
        assert!(none.is_empty());
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10258: local module glob leaves declarations complete without adding aliases"
    )]
    fn local_module_glob_preserves_complete_declarations() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/rustdoc-facade/core-v1.json");
        let mut json: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture).unwrap()).unwrap();
        let mut local_glob: serde_json::Value = serde_json::from_slice(
            &fs::read(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/rustdoc-facade/facade-public.json"),
            )
            .unwrap(),
        )
        .unwrap();
        local_glob = local_glob["index"]["1"].clone();
        local_glob["id"] = serde_json::json!(3);
        local_glob["inner"]["use"]["name"] = serde_json::json!("*");
        local_glob["inner"]["use"]["id"] = serde_json::json!(1);
        local_glob["inner"]["use"]["is_glob"] = serde_json::json!(true);
        json["index"]["3"] = local_glob;
        json["index"]["0"]["inner"]["module"]["items"] = serde_json::json!([1, 3]);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("local-glob.json");
        fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
        let mut request = request(path);
        request.activation[0].package = Some(NameSelector {
            name: "sqlx_core".to_owned(),
            version: Some("=1.0.0".to_owned()),
        });
        let product = RustdocJsonPackProducer
            .produce_exact_artifact(&request, &ArtifactProducerLimits::default());
        let pack = product.pack.expect("complete local glob pack");
        assert_eq!(pack.completeness, Completeness::Complete);
        assert!(!pack.rust_external_reexports_truncated);
        assert!(pack.rust_external_reexports_glob_incomplete);
        let aliases = pack
            .shards
            .iter()
            .flat_map(|shard| match &shard.payload {
                AuthoredPayload::DeclarationFacts { members, .. } => members
                    .iter()
                    .flat_map(|member| member.aliases.iter())
                    .cloned()
                    .collect::<Vec<_>>(),
                _ => Vec::new(),
            })
            .collect::<Vec<_>>();
        assert!(
            !aliases.contains(&"sqlx_core.query".to_owned()),
            "{aliases:?}"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10258: local error glob abstains without partializing declarations"
    )]
    fn local_error_glob_does_not_publish_root_error_alias() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/rustdoc-facade/core-v1.json");
        let mut json: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture).unwrap()).unwrap();
        json["index"]["1"]["name"] = serde_json::json!("error");
        json["index"]["2"]["name"] = serde_json::json!("Error");
        json["index"]["2"]["inner"] = serde_json::json!({"struct": {
            "kind":"unit", "generics":{"params":[],"where_predicates":[]}, "impls":[]
        }});
        json["paths"]["1"]["path"] = serde_json::json!(["sqlx_core", "error"]);
        json["paths"]["2"] = serde_json::json!({"crate_id":0,
            "path":["sqlx_core","error","Error"],"kind":"struct"});
        let facade: serde_json::Value = serde_json::from_slice(
            &fs::read(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/rustdoc-facade/facade-public.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let mut glob = facade["index"]["1"].clone();
        glob["id"] = serde_json::json!(3);
        glob["inner"]["use"]["id"] = serde_json::json!(1);
        glob["inner"]["use"]["name"] = serde_json::json!("*");
        glob["inner"]["use"]["is_glob"] = serde_json::json!(true);
        json["index"]["3"] = glob;
        json["index"]["0"]["inner"]["module"]["items"] = serde_json::json!([1, 3]);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("error-glob.json");
        fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
        let mut request = request(path);
        request.activation[0].package = Some(NameSelector {
            name: "sqlx_core".to_owned(),
            version: Some("=1.0.0".to_owned()),
        });
        let pack = RustdocJsonPackProducer
            .produce_exact_artifact(&request, &ArtifactProducerLimits::default())
            .pack
            .expect("error glob pack");
        assert_eq!(pack.completeness, Completeness::Complete);
        assert!(!pack.rust_external_reexports_truncated);
        assert!(pack.rust_external_reexports_glob_incomplete);
        let aliases = pack
            .shards
            .iter()
            .flat_map(|shard| match &shard.payload {
                AuthoredPayload::DeclarationFacts { types, .. } => types
                    .iter()
                    .flat_map(|ty| ty.aliases.iter())
                    .cloned()
                    .collect::<Vec<_>>(),
                _ => Vec::new(),
            })
            .collect::<Vec<_>>();
        assert!(
            !aliases.contains(&"sqlx_core.Error".to_owned()),
            "{aliases:?}"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10258: truncated external reexports retain a typed schema-29 marker"
    )]
    fn truncated_external_reexports_only_mark_route_surface_incomplete() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/rustdoc-facade/facade-two-globs.json");
        let produce = |max_records: usize| {
            let mut request = request(path.clone());
            request.activation[0].package = Some(NameSelector {
                name: "sqlx".to_owned(),
                version: Some("=1.0.0".to_owned()),
            });
            RustdocJsonPackProducer.produce_exact_artifact(
                &request,
                &ArtifactProducerLimits {
                    max_records,
                    ..ArtifactProducerLimits::default()
                },
            )
        };
        for max_records in [100, 2] {
            let product = produce(max_records);
            let pack = product
                .pack
                .unwrap_or_else(|| panic!("{:#?}", product.diagnostics));
            assert_eq!(pack.rust_external_reexports.len(), 2, "{max_records}");
            assert!(!pack.rust_external_reexports_truncated);
            assert!(
                product
                    .diagnostics
                    .iter()
                    .all(|diagnostic| diagnostic.code != "limit.rust_external_reexports"),
                "{max_records}"
            );
        }
        let product = produce(1);
        assert_eq!(product.completeness, Completeness::Complete);
        assert!(
            product
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "limit.rust_external_reexports"),
            "{:#?}",
            product.diagnostics
        );
        let pack = product.pack.expect("truncated routes still publish a pack");
        assert_eq!(pack.completeness, Completeness::Complete);
        assert_eq!(pack.rust_external_reexports.len(), 1);
        assert!(pack.rust_external_reexports_truncated);
        let zero = produce(0)
            .pack
            .expect("zero retained routes still publish a pack");
        assert!(zero.rust_external_reexports.is_empty());
        assert!(zero.rust_external_reexports_truncated);
        assert_eq!(zero.schema_version, brokk_bifrost_semantic::analyzer::semantic_model::RUST_EXTERNAL_REEXPORTS_MIN_SCHEMA_VERSION);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10258: reexport namespace comes only from structured target kind"
    )]
    fn external_target_namespace_is_structured_or_unknown() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/rustdoc-facade/facade-public.json");
        let mut json: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture).unwrap()).unwrap();
        for (kind, expected) in [
            ("function", Some(RustReexportTargetNamespace::Value)),
            ("module", Some(RustReexportTargetNamespace::TypeOrModule)),
            ("struct", None),
        ] {
            json["paths"]["100"]["kind"] = serde_json::json!(kind);
            let document: RustdocCrate = serde_json::from_value(json.clone()).unwrap();
            let route = collect_external_reexports(&document, 100).0.remove(0);
            assert_eq!(route.target().namespace, expected, "{kind}");
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon("#10258: native Rustdoc Use items have null outer names")]
    fn native_use_names_preserve_explicit_and_glob_reexports() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let native: RustdocCrate = serde_json::from_slice(
            &fs::read(root.join("rustdoc-converter-inline/native-61.json")).unwrap(),
        )
        .unwrap();
        assert!(
            collect_external_reexports(&native, 100)
                .0
                .iter()
                .any(|edge| matches!(
                    edge, RustExternalReexport::ExplicitUse { facade_path, .. }
                        if facade_path.ends_with(".Debug")
                ))
        );
        let mut glob: RustdocCrate = serde_json::from_slice(
            &fs::read(root.join("rustdoc-facade/facade-glob.json")).unwrap(),
        )
        .unwrap();
        for item in glob.index.values_mut() {
            if matches!(item.inner, ItemEnum::Use(_)) {
                item.name = None;
            }
        }
        assert!(
            matches!(collect_external_reexports(&glob, 100).0.as_slice(),
                [RustExternalReexport::GlobUse { facade_module_path, .. }] if facade_module_path == "sqlx"
            )
        );
    }

    #[test]
    fn facade_reexports_require_schema_29_on_write_and_read() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/rustdoc-facade/facade-public.json");
        let mut request = request(path);
        request.activation[0].package = Some(NameSelector {
            name: "sqlx".to_owned(),
            version: Some("=1.0.0".to_owned()),
        });
        let product = RustdocJsonPackProducer
            .produce_exact_artifact(&request, &ArtifactProducerLimits::default());
        let pack = product
            .pack
            .unwrap_or_else(|| panic!("{:#?}", product.diagnostics));
        assert_eq!(pack.schema_version, 29);
        assert!(!pack.rust_external_reexports.is_empty());
        let mut old = pack.clone();
        old.schema_version = 28;
        assert!(
            compile_pack(&old, &CompilerOptions::default())
                .unwrap_err()
                .iter()
                .any(|diagnostic| diagnostic.code == "rust_external_reexports.schema_version")
        );
        let compiled = compile_pack(&pack, &CompilerOptions::default()).unwrap();
        let mut old_manifest: serde_json::Value =
            serde_json::from_slice(&compiled.manifest_bytes).unwrap();
        old_manifest["schema_version"] = serde_json::json!(28);
        assert!(
            brokk_bifrost_semantic::analyzer::semantic_model::artifact::decode_manifest(
                &serde_json::to_vec(&old_manifest).unwrap(),
                &brokk_bifrost_semantic::analyzer::semantic_model::artifact::DecodeLimits::default(
                ),
            )
            .is_err()
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "68437a4a94ff: alias targets erased mutable reference types"
    )]
    fn alias_targets_are_exact_and_survive_validator_roundtrip() {
        let mut doc = document(false);
        let parameter = GenericParamDef {
            name: "T".into(),
            kind: GenericParamDefKind::Type {
                bounds: vec![],
                default: Some(Type::Primitive("u8".into())),
                is_synthetic: false,
            },
        };
        let aliases = [
            (
                100,
                "Defaulted",
                Type::Tuple(vec![
                    Type::Generic("T".into()),
                    Type::ResolvedPath(path(1, "widget::Widget")),
                ]),
            ),
            (
                101,
                "Nested",
                Type::ResolvedPath(RustdocPath {
                    args: Some(Box::new(GenericArgs::AngleBracketed {
                        args: vec![GenericArg::Type(Type::Generic("T".into()))],
                        constraints: vec![],
                    })),
                    ..path(100, "widget::Defaulted")
                }),
            ),
            (
                102,
                "Projection",
                Type::QualifiedPath {
                    name: "Item".into(),
                    args: None,
                    self_type: Box::new(Type::Generic("T".into())),
                    trait_: None,
                },
            ),
            (
                103,
                "Absent",
                Type::ResolvedPath(path(999, "missing::Type")),
            ),
            (
                104,
                "Reference",
                Type::BorrowedRef {
                    lifetime: None,
                    is_mutable: false,
                    type_: Box::new(Type::Generic("T".into())),
                },
            ),
        ];
        let aliases = aliases.into_iter().chain([
            (105, "Opaque", Type::ImplTrait(vec![])),
            (
                106,
                "ConstArray",
                Type::Array {
                    type_: Box::new(Type::Primitive("u8".into())),
                    len: "N".into(),
                },
            ),
            (107, "Unbound", Type::Generic("Outside".into())),
            (
                108,
                "MutableReference",
                Type::BorrowedRef {
                    lifetime: None,
                    is_mutable: true,
                    type_: Box::new(Type::Generic("T".into())),
                },
            ),
            (
                109,
                "NestedMutableReference",
                Type::Tuple(vec![Type::BorrowedRef {
                    lifetime: None,
                    is_mutable: true,
                    type_: Box::new(Type::Generic("T".into())),
                }]),
            ),
        ]);
        for (id, name, type_) in aliases {
            doc.index.insert(
                Id(id),
                item(
                    id,
                    Some(name),
                    RustVisibility::Public,
                    ItemEnum::TypeAlias(rustdoc_types::TypeAlias {
                        type_,
                        generics: Generics {
                            params: vec![parameter.clone()],
                            where_predicates: vec![],
                        },
                    }),
                ),
            );
            doc.paths.insert(
                Id(id),
                ItemSummary {
                    crate_id: 0,
                    path: vec!["widget".into(), name.into()],
                    kind: ItemKind::TypeAlias,
                },
            );
            let ItemEnum::Module(root) = &mut doc.index.get_mut(&Id(0)).unwrap().inner else {
                unreachable!()
            };
            root.items.push(Id(id));
        }
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(), serde_json::to_vec(&doc).unwrap()).unwrap();
        let production = RustdocJsonPackProducer.produce(
            &request(file.path().to_path_buf()),
            &ArtifactProducerLimits::default(),
            None,
        );
        let pack = production.pack.unwrap();
        assert_eq!(pack.schema_version, 32);
        let AuthoredPayload::DeclarationFacts { types, .. } = &pack.shards[0].payload else {
            unreachable!()
        };
        let fact = |name: &str| {
            types
                .iter()
                .find(|ty| ty.name == format!("widget.{name}"))
                .unwrap()
        };
        assert!(matches!(
            fact("Defaulted").alias_target,
            Some(TypeRef::Tuple { .. })
        ));
        assert!(fact("Defaulted").type_parameter_defaults[0].is_some());
        assert!(matches!(
            fact("Nested").alias_target,
            Some(TypeRef::Declared { .. })
        ));
        assert!(matches!(
            fact("Reference").alias_target,
            Some(TypeRef::ByRef { .. })
        ));
        assert!(fact("Projection").alias_target.is_none());
        assert!(fact("Absent").alias_target.is_none());
        for name in [
            "Opaque",
            "ConstArray",
            "Unbound",
            "MutableReference",
            "NestedMutableReference",
        ] {
            assert!(fact(name).alias_target.is_none(), "{name}");
        }
        let decoded = serde_json::from_slice(&serde_json::to_vec(&pack).unwrap()).unwrap();
        compile_pack(&decoded, &CompilerOptions::default()).unwrap();
    }

    #[test]
    fn io_result_alias_target_requires_cross_document_owner() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rustdoc-contract");
        let root = tempfile::tempdir().unwrap();
        for name in ["core", "std"] {
            fs::copy(
                fixture.join(format!("{name}.json")),
                root.path().join(format!("{name}.json")),
            )
            .unwrap();
        }
        let binder = |name: &str| GenericParamDef {
            name: name.into(),
            kind: GenericParamDefKind::Type {
                bounds: vec![],
                default: None,
                is_synthetic: false,
            },
        };
        let core_path = root.path().join("core.json");
        let mut core: RustdocCrate =
            serde_json::from_slice(&fs::read(&core_path).unwrap()).unwrap();
        core.index.insert(
            Id(100),
            item(
                100,
                Some("Result"),
                RustVisibility::Public,
                ItemEnum::Enum(rustdoc_types::Enum {
                    generics: Generics {
                        params: vec![binder("T"), binder("E")],
                        where_predicates: vec![],
                    },
                    has_stripped_variants: false,
                    variants: vec![],
                    impls: vec![],
                }),
            ),
        );
        core.paths.insert(
            Id(100),
            ItemSummary {
                crate_id: 0,
                path: vec!["core".into(), "result".into(), "Result".into()],
                kind: ItemKind::Enum,
            },
        );
        let ItemEnum::Module(module) = &mut core.index.get_mut(&core.root).unwrap().inner else {
            unreachable!()
        };
        module.items.push(Id(100));
        fs::write(&core_path, serde_json::to_vec(&core).unwrap()).unwrap();
        let std_path = root.path().join("std.json");
        let mut doc: RustdocCrate = serde_json::from_slice(&fs::read(&std_path).unwrap()).unwrap();
        doc.index.insert(
            Id(100),
            item(
                100,
                Some("Result"),
                RustVisibility::Public,
                ItemEnum::TypeAlias(rustdoc_types::TypeAlias {
                    type_: Type::ResolvedPath(RustdocPath {
                        args: Some(Box::new(GenericArgs::AngleBracketed {
                            args: vec![
                                GenericArg::Type(Type::Generic("T".into())),
                                GenericArg::Type(Type::ResolvedPath(path(102, "std::io::Error"))),
                            ],
                            constraints: vec![],
                        })),
                        ..path(101, "core::result::Result")
                    }),
                    generics: Generics {
                        params: vec![binder("T")],
                        where_predicates: vec![],
                    },
                }),
            ),
        );
        doc.paths.insert(
            Id(100),
            ItemSummary {
                crate_id: 0,
                path: vec!["std".into(), "io".into(), "Result".into()],
                kind: ItemKind::TypeAlias,
            },
        );
        doc.paths.insert(
            Id(101),
            ItemSummary {
                crate_id: 1,
                path: vec!["core".into(), "result".into(), "Result".into()],
                kind: ItemKind::Enum,
            },
        );
        doc.index.insert(
            Id(102),
            item(
                102,
                Some("Error"),
                RustVisibility::Public,
                ItemEnum::Struct(Struct {
                    kind: StructKind::Unit,
                    generics: generics(),
                    impls: vec![],
                }),
            ),
        );
        doc.paths.insert(
            Id(102),
            ItemSummary {
                crate_id: 0,
                path: vec!["std".into(), "io".into(), "Error".into()],
                kind: ItemKind::Struct,
            },
        );
        let ItemEnum::Module(module) = &mut doc.index.get_mut(&doc.root).unwrap().inner else {
            unreachable!()
        };
        module.items.extend([Id(100), Id(102)]);
        fs::write(&std_path, serde_json::to_vec(&doc).unwrap()).unwrap();
        for include_core in [true, false] {
            let crates = if include_core {
                vec![
                    ("core".into(), "core.json".into()),
                    ("std".into(), "std.json".into()),
                ]
            } else {
                vec![("std".into(), "std.json".into())]
            };
            let paths = crates
                .iter()
                .map(|(_, path): &(String, String)| std::path::PathBuf::from(path))
                .collect::<Vec<_>>();
            let limits = ArtifactProducerLimits::default();
            let artifact = read_exact_source_set(root.path(), &paths, 3, 8, &limits).unwrap();
            let mut request = request(root.path().to_path_buf());
            request.artifact_kind = ExternalArtifactKind::RustdocJsonSet;
            request.activation[0].package = None;
            let pack = RustdocJsonPackProducer
                .produce_loaded_source_set(&request, &limits, None, &artifact, &crates)
                .pack
                .unwrap();
            let alias = pack
                .shards
                .iter()
                .find_map(|shard| match &shard.payload {
                    AuthoredPayload::DeclarationFacts { types, .. } => {
                        types.iter().find(|ty| ty.name == "std.io.Result")
                    }
                    _ => None,
                })
                .unwrap();
            assert_eq!(alias.alias_target.is_some(), include_core);
            assert_eq!(pack.schema_version == 32, include_core);
            if include_core {
                compile_pack(&pack, &CompilerOptions::default()).unwrap();
            }
        }
    }

    fn generics() -> Generics {
        Generics {
            params: Vec::new(),
            where_predicates: Vec::new(),
        }
    }

    fn path(id: u32, path: &str) -> RustdocPath {
        RustdocPath {
            path: path.to_owned(),
            id: Id(id),
            args: None,
        }
    }

    fn function(inputs: Vec<(String, Type)>, output: Option<Type>, generics: Generics) -> Function {
        Function {
            sig: FunctionSignature {
                inputs,
                output,
                is_c_variadic: false,
            },
            generics,
            header: FunctionHeader {
                is_const: false,
                is_unsafe: false,
                is_async: false,
                abi: Abi::Rust,
            },
            has_body: true,
            default_unstable: None,
        }
    }

    fn typed_path(id: Id, path: &str, arguments: Vec<Type>) -> Type {
        Type::ResolvedPath(RustdocPath {
            path: path.to_owned(),
            id,
            args: Some(Box::new(GenericArgs::AngleBracketed {
                args: arguments.into_iter().map(GenericArg::Type).collect(),
                constraints: Vec::new(),
            })),
        })
    }

    fn rust_generic(name: &str) -> GenericParamDef {
        GenericParamDef {
            name: name.to_owned(),
            kind: GenericParamDefKind::Type {
                bounds: Vec::new(),
                default: None,
                is_synthetic: false,
            },
        }
    }

    fn hashmap_document(crate_name: &str) -> RustdocCrate {
        let key = Type::Generic("K".to_owned());
        let value = Type::Generic("V".to_owned());
        let mut index = std::collections::HashMap::new();
        index.insert(
            Id(0),
            item(
                0,
                Some(crate_name),
                RustVisibility::Default,
                ItemEnum::Module(Module {
                    is_crate: true,
                    items: vec![Id(1)],
                    is_stripped: false,
                }),
            ),
        );
        index.insert(
            Id(1),
            item(
                1,
                Some("HashMap"),
                RustVisibility::Public,
                ItemEnum::Struct(Struct {
                    kind: StructKind::Unit,
                    generics: Generics {
                        params: vec![rust_generic("K"), rust_generic("V")],
                        where_predicates: Vec::new(),
                    },
                    impls: vec![Id(2)],
                }),
            ),
        );
        index.insert(
            Id(2),
            item(
                2,
                None,
                RustVisibility::Default,
                ItemEnum::Impl(Impl {
                    is_unsafe: false,
                    generics: Generics {
                        params: vec![rust_generic("K"), rust_generic("V")],
                        where_predicates: Vec::new(),
                    },
                    provided_trait_methods: Vec::new(),
                    trait_: None,
                    for_: typed_path(
                        Id(1),
                        &format!("{crate_name}::collections::HashMap"),
                        vec![key.clone(), value.clone()],
                    ),
                    items: vec![Id(3), Id(4), Id(5)],
                    is_negative: false,
                    is_synthetic: false,
                    blanket_impl: None,
                }),
            ),
        );
        index.insert(
            Id(3),
            item(
                3,
                Some("insert"),
                RustVisibility::Public,
                ItemEnum::Function(function(
                    vec![
                        ("self".to_owned(), Type::Generic("Self".to_owned())),
                        ("key".to_owned(), key.clone()),
                        ("value".to_owned(), value.clone()),
                    ],
                    Some(typed_path(
                        Id(100),
                        &format!("{crate_name}::option::Option"),
                        vec![value.clone()],
                    )),
                    generics(),
                )),
            ),
        );
        index.insert(
            Id(4),
            item(
                4,
                Some("get"),
                RustVisibility::Public,
                ItemEnum::Function(function(
                    vec![
                        ("self".to_owned(), Type::Generic("Self".to_owned())),
                        (
                            "key".to_owned(),
                            Type::BorrowedRef {
                                lifetime: None,
                                is_mutable: false,
                                type_: Box::new(key.clone()),
                            },
                        ),
                    ],
                    Some(typed_path(
                        Id(100),
                        &format!("{crate_name}::option::Option"),
                        vec![Type::BorrowedRef {
                            lifetime: None,
                            is_mutable: false,
                            type_: Box::new(value.clone()),
                        }],
                    )),
                    generics(),
                )),
            ),
        );
        index.insert(
            Id(5),
            item(
                5,
                Some("get_mut"),
                RustVisibility::Public,
                ItemEnum::Function(function(
                    vec![
                        ("self".to_owned(), Type::Generic("Self".to_owned())),
                        (
                            "key".to_owned(),
                            Type::BorrowedRef {
                                lifetime: None,
                                is_mutable: false,
                                type_: Box::new(key),
                            },
                        ),
                    ],
                    Some(typed_path(
                        Id(100),
                        &format!("{crate_name}::option::Option"),
                        vec![Type::BorrowedRef {
                            lifetime: None,
                            is_mutable: true,
                            type_: Box::new(value),
                        }],
                    )),
                    generics(),
                )),
            ),
        );
        let paths = [1, 3, 4, 5]
            .into_iter()
            .zip([
                &format!("{crate_name}::collections::HashMap"),
                &format!("{crate_name}::collections::HashMap::insert"),
                &format!("{crate_name}::collections::HashMap::get"),
                &format!("{crate_name}::collections::HashMap::get_mut"),
            ])
            .map(|(id, item_path)| {
                let kind = if id == 1 {
                    ItemKind::Struct
                } else {
                    ItemKind::Function
                };
                (
                    Id(id),
                    ItemSummary {
                        crate_id: 0,
                        path: item_path.split("::").map(str::to_owned).collect(),
                        kind,
                    },
                )
            })
            .collect();
        RustdocCrate {
            root: Id(0),
            crate_version: Some("1.0.0".to_owned()),
            includes_private: false,
            index,
            paths,
            external_crates: std::collections::HashMap::new(),
            target: Target {
                triple: "x86_64-unknown-linux-gnu".to_owned(),
                target_features: Vec::new(),
            },
            format_version: RUSTDOC_FORMAT_VERSION,
        }
    }

    fn hashmap_request(path: std::path::PathBuf, crate_name: &str) -> ArtifactProductionRequest {
        let mut request = request(path);
        request.pack_id = format!("cargo.{crate_name}");
        request.activation[0].package = Some(NameSelector {
            name: crate_name.to_owned(),
            version: Some("=1.0.0".to_owned()),
        });
        request
    }

    fn hashmap_production() -> ArtifactProduction {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(
            file.path(),
            serde_json::to_vec(&hashmap_document("std")).unwrap(),
        )
        .unwrap();
        RustdocJsonPackProducer.produce(
            &hashmap_request(file.path().to_path_buf(), "std"),
            &ArtifactProducerLimits::default(),
            None,
        )
    }

    #[test]
    fn conversion_certificate_is_parser_and_pack_neutral() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let request = hashmap_request(file.path().to_path_buf(), "std");
        let plain = serde_json::to_value(hashmap_document("std")).unwrap();
        fs::write(file.path(), serde_json::to_vec(&plain).unwrap()).unwrap();
        let mut plain_pack = RustdocJsonPackProducer
            .produce(&request, &ArtifactProducerLimits::default(), None)
            .pack
            .expect("plain document produces a pack");
        let mut converted = plain.clone();
        converted["_bifrost_conversion"] = serde_json::json!({
            "producer_contract": RUSTDOC_PRODUCER_CONTRACT,
            "uncertified_fields": ["Item::stability"]
        });
        let parsed: RustdocCrate = serde_json::from_value(converted.clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), plain);
        fs::write(file.path(), serde_json::to_vec(&converted).unwrap()).unwrap();
        let mut converted_pack = RustdocJsonPackProducer
            .produce(&request, &ArtifactProducerLimits::default(), None)
            .pack
            .expect("converted document produces a pack");
        // The input digest intentionally changes; compare the authored pack
        // after removing only its artifact identity references.
        assert_ne!(converted_pack.extraction, plain_pack.extraction);
        for pack in [&mut plain_pack, &mut converted_pack] {
            pack.extraction = None;
            for shard in &mut pack.shards {
                for selector in &mut shard.activation {
                    selector.artifact_sha256 = None;
                }
            }
        }
        assert_eq!(converted_pack, plain_pack);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#6542: Rust std production discarded cross-document owners and trait contracts"
    )]
    #[brokk_bifrost_test_macros::hardwon(
        "#6704: qualified projection return types became wildcards"
    )]
    fn rustdoc_source_set_contract_survives_pack_roundtrip() {
        use brokk_bifrost_semantic::analyzer::semantic_model::artifact::{
            DecodeLimits, decode_shard,
        };
        use brokk_bifrost_semantic::analyzer::semantic_model::compiler::lowest_schema_version;
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rustdoc-contract");
        let paths = ["core.json", "alloc.json", "std.json"].map(std::path::PathBuf::from);
        let limits = ArtifactProducerLimits::default();
        let artifact = read_exact_source_set(&root, &paths, 3, 8, &limits).unwrap();
        let mut request = request(root.join("stdlib"));
        request.artifact_kind = ExternalArtifactKind::RustdocJsonSet;
        request.activation[0].package = None;
        request.activation[0].module = None;
        let production = RustdocJsonPackProducer.produce_loaded_source_set(
            &request,
            &limits,
            None,
            &artifact,
            &[
                ("core".into(), "core.json".into()),
                ("alloc".into(), "alloc.json".into()),
                ("std".into(), "std.json".into()),
            ],
        );
        assert!(
            !production
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "rust.rustdoc.reexport_target_unavailable")
        );
        let mut standalone_request = request.clone();
        standalone_request.path = root.join("std.json");
        standalone_request.artifact_kind = ExternalArtifactKind::RustdocJson;
        let standalone =
            RustdocJsonPackProducer.produce_exact_artifact(&standalone_request, &limits);
        assert_eq!(standalone.completeness, Completeness::Complete);
        assert!(standalone.pack.as_ref().is_some_and(|pack| {
            !pack.rust_external_reexports.is_empty() && !pack.rust_external_reexports_truncated
        }));
        assert!(
            standalone
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "rust.rustdoc.reexport_target_unavailable")
        );
        let pack = production
            .pack
            .expect("synthetic source set produces facts");
        assert!(!pack.rust_external_reexports_truncated);
        assert!(!pack.rust_external_reexports_glob_incomplete);
        assert!(pack.rust_external_reexports.is_empty());
        assert_eq!(
            pack.schema_version,
            crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION
        );
        let compiled = compile_pack(&pack, &CompilerOptions::default()).unwrap();
        assert_eq!(
            lowest_schema_version(&pack, &CompilerOptions::default()).unwrap(),
            19
        );
        assert_eq!(compiled.shards.len(), 1, "small modules share one shard");
        // Source production, schema-29 production relabeling, the schema-28
        // approximation gate, and release lowest-schema labeling all decode
        // the same ordinary Rust declarations when no reexports are carried.
        let mut payloads = Vec::new();
        for schema_version in [19, 22, 28, 29] {
            let mut relabelled = pack.clone();
            relabelled.schema_version = schema_version;
            let compiled = compile_pack(&relabelled, &CompilerOptions::default()).unwrap();
            assert!(compiled.manifest.rust_external_reexports.is_empty());
            assert!(
                !String::from_utf8_lossy(&compiled.manifest_bytes)
                    .contains("rust_external_reexports")
            );
            let manifest =
                brokk_bifrost_semantic::analyzer::semantic_model::artifact::decode_manifest(
                    &compiled.manifest_bytes,
                    &DecodeLimits::default(),
                )
                .unwrap();
            let payload = compiled
                .shards
                .iter()
                .map(|shard| {
                    let decoded = brokk_bifrost_semantic::analyzer::semantic_model::artifact::decode_shard_for_manifest(
                        &manifest,
                        &shard.descriptor,
                        &shard.bytes,
                        &DecodeLimits::default(),
                    )
                    .unwrap();
                    serde_json::to_value(decoded.payload).unwrap()
                })
                .collect::<Vec<_>>();
            payloads.push(payload);
        }
        assert!(payloads.windows(2).all(|pair| pair[0] == pair[1]));
        assert!(
            pack.shards
                .iter()
                .all(|shard| shard.activation == request.activation)
        );
        let mut types = Vec::new();
        let mut members = Vec::new();
        for artifact in &compiled.shards {
            let shard = decode_shard(
                &artifact.descriptor,
                &artifact.bytes,
                &DecodeLimits::default(),
            )
            .unwrap();
            let brokk_bifrost_semantic::analyzer::semantic_model::artifact::CompiledPayload::DeclarationFacts { types: shard_types, members: shard_members, .. } = shard.payload else { panic!("declarations") };
            types.extend(shard_types);
            members.extend(shard_members);
        }
        let widget = types
            .iter()
            .find(|fact| fact.name == "core.data.Widget")
            .unwrap();
        assert!(widget.aliases.contains(&"std.Widget".to_owned()));
        assert!(widget.aliases.contains(&"std.data.Widget".to_owned()));
        let hidden_widget = types
            .iter()
            .find(|fact| fact.name == "core.data.hidden.HiddenWidget")
            .unwrap();
        assert!(
            hidden_widget
                .aliases
                .contains(&"std.data.PublicWidget".to_owned())
        );
        assert!(
            !hidden_widget
                .aliases
                .contains(&"std.data.hidden.HiddenWidget".to_owned())
        );
        assert!(
            types
                .iter()
                .find(|fact| fact.name == "core.Traverse.Item")
                .unwrap()
                .aliases
                .contains(&"std.data.Traversal.Item".to_owned())
        );
        assert!(members.iter().any(|fact| {
            fact.owner
                == types
                    .iter()
                    .find(|fact| fact.name == "core.Traverse")
                    .unwrap()
                    .id
                && fact.name == "walk"
                && fact.aliases.contains(&"std.data.Traversal.walk".to_owned())
        }));
        assert_eq!(widget.type_parameters, ["T", "N"]);
        assert_eq!(
            widget.type_parameter_defaults,
            [
                Some(GenericParameterDefault::Type {
                    r#type: TypeRef::named("u8")
                }),
                Some(GenericParameterDefault::Const { value: "4".into() }),
            ]
        );
        let traverse = types
            .iter()
            .find(|fact| fact.name == "core.Traverse")
            .unwrap();
        // Required acceptance: no overridden method is needed to retain this
        // implementation and its associated binding.
        let direct = widget.implemented_traits.iter().find(|fact|
            matches!(&fact.trait_type, TypeRef::Declared { id, .. } if id == &traverse.id)).unwrap();
        assert_eq!(direct.type_parameters, ["T"]);
        assert_eq!(
            direct.bounds.len(),
            2,
            "explicit conditions and implicit Sized survive"
        );
        assert!(direct.self_pattern.is_some());
        assert_eq!(
            direct.associated_types,
            [AssociatedTypeBinding {
                name: "Item".into(),
                r#type: TypeRef::Slice {
                    element: Box::new(TypeRef::TypeParameter { name: "T".into() })
                },
            }]
        );
        assert!(
            widget
                .implemented_traits
                .iter()
                .any(|fact| fact.type_parameters.is_empty()
                    && matches!(&fact.trait_type,
                TypeRef::Named { name, .. } if name == "core.Traverse")),
            "a concrete impl in alloc joins its owner from core"
        );
        assert!(widget.implemented_traits_complete);
        assert!(traverse.generic_trait_impls_complete);
        let forbidden = types.iter().find(|ty| ty.name == "core.Forbidden").unwrap();
        let blanket = types.iter().find(|ty| ty.name == "core.Blanket").unwrap();
        let auto = types
            .iter()
            .find(|ty| ty.name == "core.marker.Send")
            .unwrap();
        assert!(!auto.generic_trait_impls_complete);
        assert!(auto.generic_trait_impls.is_empty());
        let blanket_rule = &blanket.generic_trait_impls[0];
        assert!(
            matches!(&blanket_rule.self_pattern, RustSelfPattern::Parameter { name } if name == "T")
        );
        assert_eq!(blanket_rule.bounds.len(), 2);
        use brokk_bifrost_semantic::analyzer::semantic_model::provably_does_not_implement;
        // Explicit negative evidence rules out the rival, independently of coverage.
        let mut open_widget = widget.clone();
        std::sync::Arc::make_mut(&mut open_widget).implemented_traits_complete = false;
        assert!(provably_does_not_implement(
            &open_widget,
            forbidden,
            |_| Some(true),
            |_| None
        ));
        // Both exhaustive inventories are needed to dismiss an absent rival.
        assert!(provably_does_not_implement(
            widget,
            blanket,
            |_| Some(false),
            |_| Some(false)
        ));
        assert!(!provably_does_not_implement(
            &open_widget,
            blanket,
            |_| Some(false),
            |_| Some(false)
        ));
        let mut open_blanket = blanket.clone();
        std::sync::Arc::make_mut(&mut open_blanket).generic_trait_impls_complete = false;
        assert!(!provably_does_not_implement(
            widget,
            &open_blanket,
            |_| Some(false),
            |_| Some(false)
        ));
        assert!(!provably_does_not_implement(
            widget,
            blanket,
            |_| Some(false),
            |_| None
        ));
        assert!(
            !provably_does_not_implement(widget, auto, |_| Some(false), |_| Some(false)),
            "a compiler-derived auto-trait rival stays unknown"
        );
        assert!(
            !members
                .iter()
                .any(|fact| fact.owner == widget.id && fact.name == "walk")
        );
        assert!(!members.iter().any(|fact| fact.name == "forbidden"));
        let primitive = types
            .iter()
            .filter(|fact| fact.name == "core.primitive.str")
            .collect::<Vec<_>>();
        assert_eq!(primitive.len(), 1);
        assert_eq!(primitive[0].id, "core.primitive.str");
        assert!(
            primitive[0]
                .implemented_traits
                .iter()
                .any(|implementation| implementation.associated_types
                    == [AssociatedTypeBinding {
                        name: "Output".into(),
                        r#type: TypeRef::Tuple { elements: vec![] }
                    }])
        );
        assert!(primitive[0].aliases.contains(&"core.Text".to_owned()));
        assert!(primitive[0].aliases.contains(&"alloc.Text".to_owned()));
        assert!(
            primitive[0]
                .aliases
                .contains(&"std.primitive.str".to_owned())
        );
        for (name, form) in [
            ("len", RustSelfForm::Shared),
            ("bytes", RustSelfForm::Mutable),
        ] {
            let member = members
                .iter()
                .find(|fact| fact.owner == primitive[0].id && fact.name == name)
                .unwrap();
            assert_eq!(member.self_form, Some(form));
        }
        let walk_members = members
            .iter()
            .filter(|fact| fact.owner == primitive[0].id && fact.name == "walk")
            .collect::<Vec<_>>();
        assert_eq!(
            walk_members.len(),
            4,
            "same-signature members from different traits must survive merging"
        );
        assert_ne!(walk_members[0].id, walk_members[1].id);
        assert_eq!(
            walk_members
                .iter()
                .map(|fact| &fact.id)
                .collect::<RandomHashSet<_>>()
                .len(),
            4
        );
        assert!(walk_members.iter().any(|fact| matches!(&fact.implemented_trait, Some(TypeRef::Declared { id, arguments, .. }) if id == &traverse.id && arguments == &[TypeRef::named("u16")])));

        let walk = walk_members.into_iter().find(|fact| matches!(&fact.implemented_trait, Some(TypeRef::Declared { id, arguments, .. }) if id == &traverse.id && arguments.is_empty())).unwrap();
        assert_eq!(
            walk.implemented_trait,
            Some(TypeRef::Declared {
                id: traverse.id.clone(),
                arguments: vec![],
                nullable: false
            })
        );
        assert_eq!(walk.self_form, Some(RustSelfForm::Mutable));
        assert_eq!(
            members
                .iter()
                .find(|fact| fact.owner == widget.id && fact.name == "consume")
                .unwrap()
                .self_form,
            Some(RustSelfForm::Value)
        );
        assert!(
            matches!(&members.iter().find(|fact| fact.name == "boxed").unwrap().self_form, Some(RustSelfForm::Other { pattern: RustSelfPattern::Constructor { arguments, .. } }) if arguments == &[RustSelfPattern::Parameter { name: "Self".into() }])
        );
        // The Box<I, A> presentation copy has only binder I. It must neither
        // create a rule with unbound A nor assert a concrete implementation.
        let boxed = types
            .iter()
            .find(|fact| fact.name == "alloc.boxed.Box")
            .unwrap();
        assert!(boxed.implemented_traits.is_empty());
        let constructed = TypeRef::Declared {
            id: boxed.id.clone(),
            arguments: vec![
                TypeRef::TypeParameter { name: "I".into() },
                TypeRef::named("u8"),
            ],
            nullable: false,
        };
        for (name, expected) in [
            ("new", constructed.clone()),
            (
                "as_self",
                TypeRef::ByRef {
                    element: Box::new(constructed),
                    reference_kind: TypeRefReferenceKind::Lvalue,
                },
            ),
        ] {
            let member = members
                .iter()
                .find(|member| member.owner == boxed.id && member.name == name)
                .unwrap();
            assert_eq!(member.signature.as_ref().unwrap().returns, Some(expected));
        }
        let projected = members
            .iter()
            .find(|member| member.owner == boxed.id && member.name == "projected")
            .unwrap();
        assert_eq!(
            projected.signature.as_ref().unwrap().returns,
            Some(TypeRef::Projection {
                owner: Box::new(TypeRef::TypeParameter { name: "I".into() }),
                trait_type: Some(Box::new(TypeRef::named("core.Traverse"))),
                name: "Item".into(),
                arguments: vec![TypeRef::named("u8")],
            })
        );
        let slice = members
            .iter()
            .find(|member| member.owner == "core.primitive.slice" && member.name == "iter")
            .expect("alloc extension of core's primitive survives the join");
        assert!(slice.callable_family_complete);
        assert!(!members.iter().any(|member| member.name == "missing_owner"));
        assert!(
            production
                .diagnostics
                .iter()
                .any(
                    |diagnostic| diagnostic.code == "rust.rustdoc.missing_member_owner"
                        && diagnostic.declaration.as_deref() == Some("core.primitive.i128")
                )
        );
        assert!(
            !production
                .diagnostics
                .iter()
                .any(
                    |diagnostic| diagnostic.code == "rust.rustdoc.missing_member_owner"
                        && diagnostic.declaration.as_deref() == Some("core.primitive.slice")
                )
        );

        let other_traverse = types
            .iter()
            .find(|fact| fact.name == "core.OtherTraverse")
            .unwrap();
        assert_eq!(
            traverse.hierarchy,
            [
                vec![],
                vec![TypeRef::Wildcard {
                    variance: WildcardVariance::Any,
                    bound: None,
                }]
            ]
            .map(|arguments| HierarchyFact {
                hierarchy_kind: HierarchyKind::Extends,
                target: TypeRef::Declared {
                    id: other_traverse.id.clone(),
                    arguments,
                    nullable: false,
                },
                declaration_ordinal: None,
            })
        );
        assert!(!production.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "rust.rustdoc.nonconcrete_hierarchy_unprojected"
        }));
        // A projected member return remains intact, but cannot itself name a
        // hierarchy target. Rustdoc trait bounds normally expose named paths.
        let mut hierarchy_diagnostics = BoundedProducerDiagnostics::new(&limits);
        assert!(
            nominal_hierarchy_fact(
                HierarchyKind::Extends,
                projected
                    .signature
                    .as_ref()
                    .unwrap()
                    .returns
                    .clone()
                    .unwrap(),
                Id(123),
                &mut hierarchy_diagnostics,
            )
            .is_none()
        );
        let (hierarchy_diagnostics, suppressed) = hierarchy_diagnostics.finish();
        assert_eq!(suppressed.total(), 0);
        assert_eq!(hierarchy_diagnostics.len(), 1);
        assert_eq!(
            hierarchy_diagnostics[0].code,
            "rust.rustdoc.nonconcrete_hierarchy_unprojected"
        );
        assert_eq!(
            hierarchy_diagnostics[0].location.as_deref(),
            Some("item.123")
        );
        let forwarding = traverse
            .generic_trait_impls
            .iter()
            .find(|fact| matches!(fact.self_pattern, RustSelfPattern::Reference { .. }))
            .unwrap();
        assert_eq!(
            forwarding.self_pattern,
            RustSelfPattern::Reference {
                mutable: true,
                inner: Box::new(RustSelfPattern::Parameter { name: "I".into() }),
            }
        );
        assert_eq!(forwarding.bounds.len(), 2);
        assert!(forwarding.bounds[1].maybe);
        assert_eq!(
            forwarding.implementation.associated_types,
            [AssociatedTypeBinding {
                name: "Item".into(),
                r#type: TypeRef::Projection {
                    owner: Box::new(TypeRef::TypeParameter { name: "I".into() }),
                    trait_type: Some(Box::new(TypeRef::named("core.Traverse"))),
                    name: "Item".into(),
                    arguments: vec![],
                },
            }]
        );
        assert_eq!(pack.completeness, Completeness::Partial);
        for name in ["len", "bytes", "source_only", "external_core"] {
            let family = members
                .iter()
                .filter(|fact| fact.owner == primitive[0].id && fact.name == name)
                .collect::<Vec<_>>();
            assert!(!family.is_empty(), "certified family {name} was produced");
            assert!(
                family.iter().all(|fact| fact.callable_family_complete),
                "{name}: {family:?}"
            );
        }
        assert!(
            members
                .iter()
                .filter(|fact| fact.owner == primitive[0].id && fact.name == "walk")
                .all(|fact| !fact.callable_family_complete),
            "outside-source-set trait member keeps the mixed family open"
        );
        let broken = types
            .iter()
            .find(|fact| fact.name == "core.data.Broken")
            .unwrap();
        let healthy = members
            .iter()
            .find(|fact| fact.owner == broken.id && fact.name == "healthy")
            .unwrap();
        assert!(
            !healthy.callable_family_complete,
            "another contributing impl failed to decode"
        );
        assert!(
            production
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "rust.rustdoc.impl_item_unavailable")
        );
        assert!(
            members
                .iter()
                .filter(|fact| fact.owner == traverse.id)
                .all(|fact| !fact.callable_family_complete),
            "trait declarations, including provided methods, are outside the direct-family claim"
        );

        assert!(
            members.iter().any(|fact| fact.owner == widget.id
                && fact.name == "consume"
                && fact.callable_family_complete),
            "a joined external impl owner does not poison the defining owner's families"
        );
        assert!(
            members.iter().any(|fact| fact.owner == widget.id
                && fact.name == "consume"
                && matches!(&fact.locator, Locator::Artifact { path, .. } if path == "alloc.json")),
            "the joined impl member retains its defining alloc document locator"
        );

        // Suppression must not erase the owner-scoped failed-decode evidence.
        let suppressed_limits = ArtifactProducerLimits {
            max_diagnostics: 0,
            ..limits
        };
        let suppressed = RustdocJsonPackProducer.produce_loaded_source_set(
            &request,
            &suppressed_limits,
            None,
            &artifact,
            &[
                ("core".into(), "core.json".into()),
                ("alloc".into(), "alloc.json".into()),
                ("std".into(), "std.json".into()),
            ],
        );
        assert!(suppressed.suppressed_diagnostics.total() > 0);
        let suppressed_pack = suppressed.pack.unwrap();
        let suppressed_members = suppressed_pack
            .shards
            .iter()
            .flat_map(|shard| {
                let AuthoredPayload::DeclarationFacts { members, .. } = &shard.payload else {
                    panic!("declarations")
                };
                members
            })
            .collect::<Vec<_>>();
        assert!(
            suppressed_members
                .iter()
                .any(|fact| fact.owner == primitive[0].id
                    && fact.name == "len"
                    && fact.callable_family_complete)
        );
        assert!(suppressed_members.iter().any(|fact| fact.owner == broken.id
            && fact.name == "healthy"
            && !fact.callable_family_complete));

        let mut old = pack.clone();
        old.schema_version = 18;
        assert!(
            compile_pack(&old, &CompilerOptions::default())
                .unwrap_err()
                .iter()
                .any(|diagnostic| diagnostic.code == "declaration.impl_self_schema_version")
        );
        old.schema_version = 17;
        assert!(
            compile_pack(&old, &CompilerOptions::default())
                .unwrap_err()
                .iter()
                .any(|diagnostic| diagnostic.code == "declaration.rust_contract_schema_version")
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10258: two-document set reexports retain master-compatible absence of carrier"
    )]
    fn two_document_source_set_public_use_keeps_master_carrier_bytes() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rustdoc-contract");
        let paths = ["core.json", "std.json"].map(std::path::PathBuf::from);
        let limits = ArtifactProducerLimits::default();
        let artifact = read_exact_source_set(&root, &paths, 2, 8, &limits).unwrap();
        let mut request = request(root.join("stdlib"));
        request.artifact_kind = ExternalArtifactKind::RustdocJsonSet;
        request.activation[0].package = None;
        request.activation[0].module = None;
        let production = RustdocJsonPackProducer.produce_loaded_source_set(
            &request,
            &limits,
            None,
            &artifact,
            &[
                ("core".into(), "core.json".into()),
                ("std".into(), "std.json".into()),
            ],
        );
        let pack = production.pack.expect("two-document source set pack");
        assert!(!pack.rust_external_reexports_truncated);
        assert!(pack.rust_external_reexports.is_empty());
        assert!(!pack.rust_external_reexports_glob_incomplete);
        assert!(pack.schema_version < brokk_bifrost_semantic::analyzer::semantic_model::RUST_EXTERNAL_REEXPORTS_MIN_SCHEMA_VERSION);
        // Master already projects this in-set alias as an ordinary fact.
        assert!(pack.shards.iter().any(|shard| {
            match &shard.payload {
                AuthoredPayload::DeclarationFacts { types, .. } => types
                    .iter()
                    .any(|fact| fact.aliases.contains(&"std.Widget".to_owned())),
                _ => false,
            }
        }));
    }

    #[test]
    fn rustdoc_produces_exact_std_hashmap_collection_flows() {
        let production = hashmap_production();
        assert_eq!(production.completeness, Completeness::Complete);
        let pack = production.pack.expect("std rustdoc produces a pack");
        let (types, members) = match &pack.shards[0].payload {
            AuthoredPayload::DeclarationFacts { types, members, .. } => (types, members),
            _ => panic!("Rust rustdoc produces declarations"),
        };
        let flows = pack.shards[0].collection_flows.as_ref().unwrap_or_else(|| {
            panic!("std HashMap has collection flows; types={types:#?}; members={members:#?}")
        });
        assert_eq!(flows.flows.len(), 1);
        let flow = |name: &str| {
            let member = members
                .iter()
                .find(|member| member.name == name)
                .unwrap_or_else(|| panic!("missing {name}"));
            flows
                .flows
                .iter()
                .find(|flow| flow.callable == member.id)
                .unwrap_or_else(|| panic!("missing flow for {name}"))
        };
        let insert_member = members
            .iter()
            .find(|member| member.name == "insert")
            .expect("missing insert member");
        let insert = flow("insert");
        assert_eq!(insert.payload.transfers.len(), 2);
        assert!(insert_member.receiver.is_some());
        assert_eq!(
            insert_member.signature.as_ref().unwrap().parameters.len(),
            2
        );
        assert!(matches!(
            &insert_member.signature.as_ref().unwrap().parameters[0].r#type,
            TypeRef::TypeParameter { name } if name == "K"
        ));
        assert!(matches!(
            insert.payload.transfers[0].source.root,
            CsmiInputBoundaryRoot::Parameter(CsmiInputParameterRoot { position: 0, .. })
        ));
        assert!(matches!(
            insert.payload.transfers[1].source.root,
            CsmiInputBoundaryRoot::Parameter(CsmiInputParameterRoot { position: 1, .. })
        ));
        assert!(matches!(
            insert.payload.transfers[0].destination.root,
            CsmiOutputBoundaryRoot::Receiver(_)
        ));
        assert!(
            insert.payload.transfers[0]
                .destination
                .projection
                .as_ref()
                .unwrap()
                .steps
                .iter()
                .any(|step| step.kind == "entry")
        );
        assert!(!flows.flows.iter().any(|flow| {
            members
                .iter()
                .filter(|member| matches!(member.name.as_str(), "get" | "get_mut"))
                .any(|member| flow.callable == member.id)
        }));
    }

    #[test]
    fn non_std_hashmap_does_not_inherit_std_flows() {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(
            file.path(),
            serde_json::to_vec(&hashmap_document("notstd")).unwrap(),
        )
        .unwrap();
        let production = RustdocJsonPackProducer.produce(
            &hashmap_request(file.path().to_path_buf(), "notstd"),
            &ArtifactProducerLimits::default(),
            None,
        );
        let pack = production
            .pack
            .expect("non-std rustdoc produces declarations");
        assert!(pack.shards[0].collection_flows.is_none());
    }

    fn document(blanket_impl: bool) -> RustdocCrate {
        let widget = path(1, "widget::Widget");
        let display = path(2, "widget::Display");
        let mut index = std::collections::HashMap::new();
        index.insert(
            Id(0),
            item(
                0,
                Some("widget"),
                RustVisibility::Default,
                ItemEnum::Module(Module {
                    is_crate: true,
                    items: vec![Id(1), Id(2), Id(3), Id(4), Id(5), Id(6)],
                    is_stripped: false,
                }),
            ),
        );
        index.insert(
            Id(1),
            item(
                1,
                Some("Widget"),
                RustVisibility::Public,
                ItemEnum::Struct(Struct {
                    kind: StructKind::Unit,
                    generics: generics(),
                    impls: vec![Id(7)],
                }),
            ),
        );
        index.insert(
            Id(2),
            item(
                2,
                Some("Display"),
                RustVisibility::Public,
                ItemEnum::Trait(Trait {
                    is_auto: false,
                    is_unsafe: false,
                    is_dyn_compatible: true,
                    items: vec![Id(9)],
                    generics: generics(),
                    bounds: Vec::new(),
                    implementations: vec![Id(7)],
                }),
            ),
        );
        index.insert(
            Id(3),
            item(
                3,
                Some("convert"),
                RustVisibility::Public,
                ItemEnum::Function(function(
                    vec![("value".to_owned(), Type::Generic("T".to_owned()))],
                    Some(Type::ResolvedPath(widget.clone())),
                    Generics {
                        params: vec![GenericParamDef {
                            name: "T".to_owned(),
                            kind: GenericParamDefKind::Type {
                                bounds: Vec::new(),
                                default: None,
                                is_synthetic: false,
                            },
                        }],
                        where_predicates: vec![WherePredicate::BoundPredicate {
                            type_: Type::Generic("T".to_owned()),
                            bounds: vec![GenericBound::TraitBound {
                                trait_: display.clone(),
                                generic_params: Vec::new(),
                                modifier: TraitBoundModifier::None,
                            }],
                            generic_params: Vec::new(),
                        }],
                    },
                )),
            ),
        );
        index.insert(
            Id(4),
            item(
                4,
                Some("Gadget"),
                RustVisibility::Public,
                ItemEnum::Use(Use {
                    source: "widget::Widget".to_owned(),
                    name: "Gadget".to_owned(),
                    id: Some(Id(1)),
                    is_glob: false,
                }),
            ),
        );
        index.insert(
            Id(5),
            item(
                5,
                Some("make_widget"),
                RustVisibility::Public,
                ItemEnum::Macro("macro_rules! make_widget".to_owned()),
            ),
        );
        index.insert(
            Id(6),
            item(
                6,
                Some("DEFAULT_WIDGET"),
                RustVisibility::Public,
                ItemEnum::Static(rustdoc_types::Static {
                    type_: Type::ResolvedPath(widget.clone()),
                    is_mutable: false,
                    expr: "Widget".to_owned(),
                    is_unsafe: false,
                }),
            ),
        );
        index.insert(
            Id(7),
            item(
                7,
                None,
                RustVisibility::Default,
                ItemEnum::Impl(Impl {
                    is_unsafe: false,
                    generics: generics(),
                    provided_trait_methods: Vec::new(),
                    trait_: Some(display),
                    for_: if blanket_impl {
                        Type::Generic("T".to_owned())
                    } else {
                        Type::ResolvedPath(widget)
                    },
                    items: vec![Id(8)],
                    is_negative: false,
                    is_synthetic: false,
                    blanket_impl: blanket_impl.then(|| Type::Generic("T".to_owned())),
                }),
            ),
        );
        index.insert(
            Id(8),
            item(
                8,
                Some("render"),
                RustVisibility::Default,
                ItemEnum::Function(function(
                    vec![(
                        "&self".to_owned(),
                        Type::BorrowedRef {
                            lifetime: None,
                            is_mutable: false,
                            type_: Box::new(Type::Generic("Self".to_owned())),
                        },
                    )],
                    Some(Type::Primitive("str".to_owned())),
                    generics(),
                )),
            ),
        );
        index.insert(
            Id(9),
            item(
                9,
                Some("render"),
                RustVisibility::Default,
                ItemEnum::Function(function(
                    vec![("&self".to_owned(), Type::Generic("Self".to_owned()))],
                    None,
                    generics(),
                )),
            ),
        );

        let paths = [
            (0, vec!["widget"], ItemKind::Module),
            (1, vec!["widget", "Widget"], ItemKind::Struct),
            (2, vec!["widget", "Display"], ItemKind::Trait),
            (3, vec!["widget", "convert"], ItemKind::Function),
            (5, vec!["widget", "make_widget"], ItemKind::Macro),
            (6, vec!["widget", "DEFAULT_WIDGET"], ItemKind::Static),
        ]
        .into_iter()
        .map(|(id, path, kind)| {
            (
                Id(id),
                ItemSummary {
                    crate_id: 0,
                    path: path.into_iter().map(str::to_owned).collect(),
                    kind,
                },
            )
        })
        .collect();
        RustdocCrate {
            root: Id(0),
            crate_version: Some("1.2.3".to_owned()),
            includes_private: false,
            index,
            paths,
            external_crates: std::collections::HashMap::new(),
            target: Target {
                triple: "x86_64-unknown-linux-gnu".to_owned(),
                target_features: Vec::new(),
            },
            format_version: RUSTDOC_FORMAT_VERSION,
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "4a60102383ba: external impl owners poisoned joined callable families"
    )]
    fn external_impl_owners_resolve_per_source_set() {
        let owner_id = |name: &str| {
            type_declaration_id(TypeIdentity {
                ecosystem: "cargo",
                name,
            })
        };
        let root = tempfile::tempdir().unwrap();
        write_crate_document(root.path(), "core");
        write_crate_document(root.path(), "alloc");
        write_crate_document(root.path(), "std");
        let std_path = root.path().join("std.json");
        let mut extension: RustdocCrate =
            serde_json::from_slice(&fs::read(&std_path).unwrap()).unwrap();
        extension.index.remove(&Id(1));
        extension.paths.get_mut(&Id(1)).unwrap().path = vec!["alloc".into(), "Widget".into()];
        extension.paths.get_mut(&Id(1)).unwrap().crate_id = 1;
        let ItemEnum::Module(module) = &mut extension.index.get_mut(&Id(0)).unwrap().inner else {
            unreachable!()
        };
        module.items = vec![Id(2), Id(7)];
        fs::write(&std_path, serde_json::to_vec(&extension).unwrap()).unwrap();
        let produce = |names: &[&str]| {
            let limits = ArtifactProducerLimits {
                max_signature_depth: 16,
                ..ArtifactProducerLimits::default()
            };
            let paths = names
                .iter()
                .map(|name| std::path::PathBuf::from(format!("{name}.json")))
                .collect::<Vec<_>>();
            let artifact =
                read_exact_source_set(root.path(), &paths, names.len(), 8, &limits).unwrap();
            let mut request = request(root.path().join("stdlib"));
            request.artifact_kind = ExternalArtifactKind::RustdocJsonSet;

            let crates = names
                .iter()
                .map(|name| (name.to_string(), format!("{name}.json")))
                .collect::<Vec<_>>();
            let production = RustdocJsonPackProducer
                .produce_loaded_source_set(&request, &limits, None, &artifact, &crates);
            let pack = production
                .pack
                .unwrap_or_else(|| panic!("{:?}", production.diagnostics));
            compile_pack(&pack, &CompilerOptions::default())
                .unwrap_or_else(|diagnostics| panic!("{diagnostics:#?}"));
            let members = pack
                .shards
                .into_iter()
                .flat_map(|shard| match shard.payload {
                    AuthoredPayload::DeclarationFacts { members, .. } => members,
                    _ => unreachable!(),
                })
                .collect::<Vec<_>>();
            (members, production.diagnostics)
        };
        let (missing, diagnostics) = produce(&["std"]);
        assert!(
            !missing
                .iter()
                .any(|member| member.owner == owner_id("alloc.Widget"))
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "rust.rustdoc.missing_member_owner")
        );
        assert!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "rust.rustdoc.missing_member_owner")
                .all(|diagnostic| diagnostic.declaration.is_none()
                    || diagnostic.source_entry.is_none())
        );
        let (joined, _) = produce(&["std", "alloc"]);
        let extensions = joined
            .iter()
            .filter(|member| member.owner == owner_id("alloc.Widget") && member.name == "render")
            .collect::<Vec<_>>();
        assert_eq!(extensions.len(), 2);
        assert!(
            extensions
                .iter()
                .all(|member| member.callable_family_complete)
        );
        assert!(extensions.iter().any(
            |member| matches!(&member.locator, Locator::Artifact { path, .. } if path == "std.json")
        ));
        let (no_std, _) = produce(&["core", "alloc"]);
        let own = no_std
            .iter()
            .find(|member| member.owner == owner_id("alloc.Widget") && member.name == "render")
            .unwrap();
        assert!(own.callable_family_complete);
        assert!(
            joined
                .iter()
                .any(|member| member.id == own.id && member.locator == own.locator)
        );
        // The same impl displayed in both documents has one canonical identity.
        let original_extension = fs::read(&std_path).unwrap();
        let mut duplicate = extension.clone();
        duplicate.paths.get_mut(&Id(2)).unwrap().path = vec!["alloc".into(), "Display".into()];
        fs::write(&std_path, serde_json::to_vec(&duplicate).unwrap()).unwrap();
        let (deduplicated, _) = produce(&["alloc", "std"]);
        assert_eq!(deduplicated.iter().filter(|member| member.owner == owner_id("alloc.Widget") && member.name == "render").count(), 1, "{deduplicated:#?}");
        fs::write(&std_path, original_extension).unwrap();

        // An external impl retains the receiver's generic return binding.
        let alloc_path = root.path().join("alloc.json");
        let original_alloc = fs::read(&alloc_path).unwrap();
        let original_std = fs::read(&std_path).unwrap();
        for path in [&alloc_path, &std_path] {
            let mut json: serde_json::Value =
                serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
            let binder = if path == &std_path { "X" } else { "T" };
            let parameters = serde_json::json!([{"name":binder, "kind":{"type":{"bounds":[], "default":null, "is_synthetic":false}}}]);
            if json["index"]["1"].is_object() {
                json["index"]["1"]["inner"]["struct"]["generics"]["params"] = parameters.clone();
            }
            json["index"]["2"]["inner"]["trait"]["generics"]["params"] = serde_json::json!([{"name":"T", "kind":{"type":{"bounds":[], "default":null, "is_synthetic":false}}}]);
            json["index"]["7"]["inner"]["impl"]["trait"]["args"] = serde_json::json!({"angle_bracketed":{"args":[{"type":{"generic":binder}}],"constraints":[]}});
            json["index"]["7"]["inner"]["impl"]["generics"]["params"] = parameters;
            json["index"]["7"]["inner"]["impl"]["for"]["resolved_path"]["args"] = serde_json::json!({"angle_bracketed":{"args":[{"type":{"generic":binder}}],"constraints":[]}});
            json["index"]["8"]["inner"]["function"]["sig"]["output"] =
                serde_json::json!({"generic":binder});
            fs::write(path, serde_json::to_vec(&json).unwrap()).unwrap();
        }
        let (generic_members, _) = produce(&["alloc", "std"]);
        let generic_extensions = generic_members
            .iter()
            .filter(|member| member.owner == owner_id("alloc.Widget") && member.name == "render")
            .collect::<Vec<_>>();
        assert_eq!(generic_extensions.len(), 2);
        assert!(
            generic_extensions
                .iter()
                .all(|member| member.signature.as_ref().unwrap().returns
                    == Some(TypeRef::TypeParameter { name: "T".into() }))
        );
        assert!(generic_extensions.iter().all(|member| {
            match member.implemented_trait.as_ref().unwrap() {
                TypeRef::Declared { arguments, .. } | TypeRef::Named { arguments, .. } => {
                    arguments == &[TypeRef::TypeParameter { name: "T".into() }]
                }
                _ => false,
            }
        }));
        // Rejected documents must never supply or overwrite owner binders.
        let mut rejected: serde_json::Value =
            serde_json::from_slice(&fs::read(&alloc_path).unwrap()).unwrap();
        rejected["index"]["0"]["name"] = serde_json::json!("zzz");
        rejected["paths"]["0"]["path"] = serde_json::json!(["zzz"]);
        rejected["index"]["1"]["inner"]["struct"]["generics"]["params"] = serde_json::json!([{"name":"Poison", "kind":{"type":{"bounds":[], "default":null, "is_synthetic":false}}}]);
        for code in [
            "rust.rustdoc.unsupported_version",
            "rust.rustdoc.uncertified_conversion",
            "rust.rustdoc.crate_name_mismatch",
            "rust.rustdoc.crate_version_mismatch",
            "rust.rustdoc.target_mismatch",
            "rust.rustdoc.invalid_root",
            "rust.rustdoc.missing_root",
        ] {
            let mut bad = rejected.clone();
            match code {
                "rust.rustdoc.unsupported_version" => {
                    bad["format_version"] = serde_json::json!(RUSTDOC_FORMAT_VERSION + 1)
                }
                "rust.rustdoc.uncertified_conversion" => {
                    bad["_bifrost_conversion"] =
                        serde_json::json!({"producer_contract":"wrong", "uncertified_fields":[]})
                }
                "rust.rustdoc.crate_name_mismatch" => {
                    bad["index"]["0"]["name"] = serde_json::json!("wrong")
                }
                "rust.rustdoc.crate_version_mismatch" => {
                    bad["crate_version"] = serde_json::json!("999.0.0")
                }
                "rust.rustdoc.target_mismatch" => {
                    bad["target"]["triple"] = serde_json::json!("wrong-target")
                }
                "rust.rustdoc.invalid_root" => {
                    bad["index"]["0"]["inner"] = bad["index"]["1"]["inner"].clone()
                }
                "rust.rustdoc.missing_root" => {
                    bad["index"].as_object_mut().unwrap().remove("0");
                }
                _ => unreachable!(),
            }
            fs::write(
                root.path().join("zzz.json"),
                serde_json::to_vec(&bad).unwrap(),
            )
            .unwrap();
            let (usable_members, rejected_diagnostics) = produce(&["alloc", "std", "zzz"]);
            assert!(
                rejected_diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == code),
                "{code}"
            );
            assert!(usable_members.iter().any(|member| member.owner == owner_id("alloc.Widget") && member.name == "render" && matches!(&member.locator, Locator::Artifact { path, .. } if path == "std.json") && member.signature.as_ref().unwrap().returns == Some(TypeRef::TypeParameter { name: "T".into() })), "{code}");
        }
        let generic_alloc = fs::read(&alloc_path).unwrap();
        let mut no_path: serde_json::Value = serde_json::from_slice(&generic_alloc).unwrap();
        no_path["paths"].as_object_mut().unwrap().remove("1");
        fs::write(&alloc_path, serde_json::to_vec(&no_path).unwrap()).unwrap();
        let (derived_name_members, _) = produce(&["alloc", "std"]);
        assert!(derived_name_members.iter().filter(|member| member.owner == owner_id("alloc.Widget") && member.name == "render").all(|member| member.signature.as_ref().unwrap().returns == Some(TypeRef::TypeParameter { name: "T".into() })));
        fs::write(&alloc_path, generic_alloc).unwrap();

        let mut shadowed: serde_json::Value =
            serde_json::from_slice(&fs::read(&std_path).unwrap()).unwrap();
        shadowed["index"]["8"]["inner"]["function"]["generics"]["params"] = serde_json::json!([{"name":"T", "kind":{"type":{"bounds":[], "default":null, "is_synthetic":false}}}]);
        fs::write(&std_path, serde_json::to_vec(&shadowed).unwrap()).unwrap();
        let (shadowed_members, shadowed_diagnostics) = produce(&["alloc", "std"]);
        assert!(
            shadowed_diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "rust.rustdoc.impl_binder_shadowed")
        );
        assert!(shadowed_members.iter().any(
            |member| matches!(&member.locator, Locator::Artifact { path, .. } if path == "std.json")
                && member.name == "render"
                && !member.callable_family_complete
                && matches!(
                    member.signature.as_ref().unwrap().returns,
                    Some(TypeRef::Wildcard { .. })
                )
        ));
        fs::write(&alloc_path, original_alloc).unwrap();
        fs::write(&std_path, original_std).unwrap();

        // An impl-only binder is not a parameter of a non-generic owner.
        let original_std = fs::read(&std_path).unwrap();
        let mut extra: serde_json::Value = serde_json::from_slice(&original_std).unwrap();
        extra["index"]["7"]["inner"]["impl"]["generics"]["params"] = serde_json::json!([{"name":"Extra", "kind":{"type":{"bounds":[], "default":null, "is_synthetic":false}}}]);
        extra["index"]["8"]["inner"]["function"]["sig"]["output"] =
            serde_json::json!({"generic":"Extra"});
        fs::write(&std_path, serde_json::to_vec(&extra).unwrap()).unwrap();
        let (extra_members, _) = produce(&["alloc", "std"]);
        assert!(
            extra_members
                .iter()
                .any(|member| member.owner == owner_id("alloc.Widget")
                    && member.name == "render"
                    && matches!(
                        member.signature.as_ref().unwrap().returns,
                        Some(TypeRef::Wildcard { .. })
                    ))
        );
        fs::write(&std_path, original_std).unwrap();

        // Pair<X, X> cannot transport X to two distinct owner parameters.
        let saved_alloc = fs::read(&alloc_path).unwrap();
        let saved_std = fs::read(&std_path).unwrap();
        let binder_parameter = |name: &str| serde_json::json!({"name":name, "kind":{"type":{"bounds":[], "default":null, "is_synthetic":false}}});
        let mut pair: serde_json::Value = serde_json::from_slice(&saved_alloc).unwrap();
        pair["index"]["1"]["inner"]["struct"]["generics"]["params"] =
            serde_json::json!([binder_parameter("A"), binder_parameter("B")]);
        pair["index"]["1"]["inner"]["struct"]["impls"] = serde_json::json!([]);
        pair["index"].as_object_mut().unwrap().remove("7");
        pair["index"].as_object_mut().unwrap().remove("8");
        fs::write(&alloc_path, serde_json::to_vec(&pair).unwrap()).unwrap();
        let mut repeated: serde_json::Value = serde_json::from_slice(&saved_std).unwrap();
        repeated["index"]["2"]["inner"]["trait"]["generics"]["params"] =
            serde_json::json!([binder_parameter("Y")]);
        repeated["index"]["7"]["inner"]["impl"]["generics"]["params"] =
            serde_json::json!([binder_parameter("X")]);
        repeated["index"]["7"]["inner"]["impl"]["for"]["resolved_path"]["args"] = serde_json::json!({"angle_bracketed":{"args":[{"type":{"generic":"X"}},{"type":{"generic":"X"}}],"constraints":[]}});
        repeated["index"]["7"]["inner"]["impl"]["trait"]["args"] = serde_json::json!({"angle_bracketed":{"args":[{"type":{"generic":"X"}}],"constraints":[]}});
        repeated["index"]["8"]["inner"]["function"]["sig"]["output"] =
            serde_json::json!({"generic":"X"});
        fs::write(&std_path, serde_json::to_vec(&repeated).unwrap()).unwrap();
        let (repeated_members, repeated_diagnostics) = produce(&["alloc", "std"]);
        assert!(
            repeated_diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "rust.rustdoc.impl_binder_ambiguous")
        );
        let repeated_member = repeated_members
            .iter()
            .find(|member| member.owner == owner_id("alloc.Widget") && member.name == "render")
            .unwrap();
        assert!(!repeated_member.callable_family_complete);
        assert!(matches!(
            repeated_member.signature.as_ref().unwrap().returns,
            Some(TypeRef::Wildcard { .. })
        ));
        assert!(
            matches!(repeated_member.implemented_trait.as_ref().unwrap(), TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. } if arguments == &[TypeRef::Unknown])
        );
        fs::write(&alloc_path, saved_alloc).unwrap();
        fs::write(&std_path, saved_std).unwrap();

        // A renamed binder keeps its existing local projection and identity,
        // even when the external presentation sorts before the defining crate.
        write_crate_document(root.path(), "zzz");
        let owner_path = root.path().join("zzz.json");
        let mut local: serde_json::Value =
            serde_json::from_slice(&fs::read(&owner_path).unwrap()).unwrap();
        local["index"]["1"]["inner"]["struct"]["generics"]["params"] =
            serde_json::json!([binder_parameter("T")]);
        local["index"]["7"]["inner"]["impl"]["generics"]["params"] =
            serde_json::json!([binder_parameter("X")]);
        local["index"]["7"]["inner"]["impl"]["for"]["resolved_path"]["args"] = serde_json::json!({"angle_bracketed":{"args":[{"type":{"generic":"X"}}],"constraints":[]}});
        local["index"]["8"]["inner"]["function"]["sig"]["inputs"][0][0] = serde_json::json!("self");
        let argument = local["index"]["7"]["inner"]["impl"]["for"].clone();
        local["index"]["8"]["inner"]["function"]["sig"]["inputs"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!(["other", argument]));
        local["index"]["8"]["inner"]["function"]["sig"]["output"] =
            serde_json::json!({"generic":"X"});
        fs::write(&owner_path, serde_json::to_vec(&local).unwrap()).unwrap();
        let (local_members, _) = produce(&["zzz"]);
        let existing_local = local_members
            .iter()
            .find(|member| member.owner == owner_id("zzz.Widget") && member.name == "render")
            .unwrap();
        assert!(matches!(
            existing_local.signature.as_ref().unwrap().returns,
            Some(TypeRef::Wildcard { .. })
        ));
        let mut external = local.clone();
        external["index"]["0"]["name"] = serde_json::json!("aaa");
        external["paths"]["0"]["path"] = serde_json::json!(["aaa"]);
        external["index"]["0"]["inner"]["module"]["items"] = serde_json::json!([7]);
        external["index"]
            .as_object_mut()
            .unwrap()
            .retain(|id, _| matches!(id.as_str(), "0" | "7" | "8"));
        external["paths"]["1"]["crate_id"] = serde_json::json!(1);
        external["paths"]["2"]["crate_id"] = serde_json::json!(1);
        fs::write(
            root.path().join("aaa.json"),
            serde_json::to_vec(&external).unwrap(),
        )
        .unwrap();
        let (folded, _) = produce(&["aaa", "zzz"]);
        let folded = folded
            .iter()
            .filter(|member| member.owner == owner_id("zzz.Widget") && member.name == "render")
            .collect::<Vec<_>>();
        assert_eq!(folded.len(), 1);
        assert_eq!(folded[0].id, existing_local.id);
        assert_eq!(folded[0].signature, existing_local.signature);
        assert_eq!(folded[0].locator, existing_local.locator);
        assert!(matches!(&folded[0].locator, Locator::Artifact { path, .. } if path == "zzz.json"));
        local["index"]["1"]["inner"]["struct"]["impls"] = serde_json::json!([]);
        local["index"].as_object_mut().unwrap().remove("7");
        local["index"].as_object_mut().unwrap().remove("8");
        fs::write(&owner_path, serde_json::to_vec(&local).unwrap()).unwrap();
        let (external_only, _) = produce(&["aaa", "zzz"]);
        let external_only = external_only
            .iter()
            .find(|member| member.owner == owner_id("zzz.Widget") && member.name == "render")
            .unwrap();
        assert_ne!(external_only.id, existing_local.id);
        assert_eq!(
            external_only.signature.as_ref().unwrap().returns,
            Some(TypeRef::TypeParameter { name: "T".into() })
        );
        assert!(
            matches!(&external_only.locator, Locator::Artifact { path, .. } if path == "aaa.json")
        );
        assert!(external_only.callable_family_complete);

        // Signature-depth failures must still veto the owner after the join,
        // for both a local declaration and an externally implemented owner.
        for crate_name in ["std", "alloc"] {
            let path = root.path().join(format!("{crate_name}.json"));
            let bytes = fs::read(&path).unwrap();
            let mut broken: RustdocCrate = serde_json::from_slice(&bytes).unwrap();
            let ItemEnum::Function(function) = &mut broken.index.get_mut(&Id(8)).unwrap().inner
            else {
                unreachable!()
            };
            let mut output = Type::Primitive("str".into());
            for _ in 0..20 {
                output = Type::Tuple(vec![output]);
            }
            function.sig.output = Some(output);
            fs::write(&path, serde_json::to_vec(&broken).unwrap()).unwrap();
            let (members, diagnostics) = produce(&["core", "alloc", "std"]);
            assert!(
                diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == "limit.signature_depth")
            );
            assert!(
                members
                    .iter()
                    .filter(|member| member.owner == owner_id("alloc.Widget")
                        && member.name == "render")
                    .all(|member| !member.callable_family_complete)
            );
            assert!(
                members
                    .iter()
                    .any(|member| member.owner == owner_id("core.Widget")
                        && member.name == "render"
                        && member.callable_family_complete)
            );
            fs::write(&path, bytes).unwrap();
            let (restored, _) = produce(&["alloc", "std"]);
            assert!(
                restored
                    .iter()
                    .filter(|member| member.owner == owner_id("alloc.Widget")
                        && member.name == "render")
                    .all(|member| member.callable_family_complete)
            );
        }
    }

    fn write_crate_document(root: &Path, crate_name: &str) {
        let mut document = document(false);
        document.index.get_mut(&document.root).unwrap().name = Some(crate_name.to_owned());
        for summary in document.paths.values_mut() {
            summary.path[0] = crate_name.to_owned();
        }
        fs::write(
            root.join(format!("{crate_name}.json")),
            serde_json::to_vec(&document).unwrap(),
        )
        .unwrap();
    }

    fn request(path: std::path::PathBuf) -> ArtifactProductionRequest {
        ArtifactProductionRequest {
            path,
            artifact_kind: ExternalArtifactKind::RustdocJson,
            pack_id: "cargo.widget".to_owned(),
            pack_version: env!("CARGO_PKG_VERSION").to_owned(),
            ecosystem: "cargo".to_owned(),
            compatibility: Compatibility {
                bifrost: None,
                toolchains: Vec::new(),
            },
            activation: vec![ActivationSelector {
                package: Some(NameSelector {
                    name: "widget".to_owned(),
                    version: Some("=1.2.3".to_owned()),
                }),
                module: None,
                toolchain: None,
                targets: vec!["x86_64-unknown-linux-gnu".to_owned()],
                configurations: vec!["default".to_owned()],
                artifact_sha256: None,
            }],
            provenance: Provenance {
                rust_artifact_approximation: None,
                source: "registry+https://github.com/rust-lang/crates.io-index".to_owned(),
                revision: None,
            },
            license: "MIT".to_owned(),
            safety: Safety {
                generated_code_only: true,
                review_required: false,
            },
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#6233: source-set input digest incorrectly became a toolchain activation requirement"
    )]
    fn rustdoc_source_set_merges_crate_qualified_declarations() {
        let root = tempfile::tempdir().unwrap();
        for crate_name in ["core", "alloc", "std"] {
            write_crate_document(root.path(), crate_name);
        }
        let relative_paths = ["core.json", "alloc.json", "std.json"]
            .into_iter()
            .map(std::path::PathBuf::from)
            .collect::<Vec<_>>();
        let artifact = read_exact_source_set(
            root.path(),
            &relative_paths,
            3,
            8,
            &ArtifactProducerLimits::default(),
        )
        .unwrap();
        let mut request = request(root.path().join("stdlib"));
        request.artifact_kind = ExternalArtifactKind::RustdocJsonSet;
        request.activation[0].package = None;
        request.activation[0].module = None;
        let crates = [
            ("core".to_owned(), "core.json".to_owned()),
            ("alloc".to_owned(), "alloc.json".to_owned()),
            ("std".to_owned(), "std.json".to_owned()),
        ];

        let production = RustdocJsonPackProducer.produce_loaded_source_set(
            &request,
            &ArtifactProducerLimits::default(),
            None,
            &artifact,
            &crates,
        );

        assert_eq!(production.completeness, Completeness::Complete);
        let pack = production.pack.expect("source set should produce one pack");
        assert!(pack.carried_sources.is_empty());
        let types = pack
            .shards
            .iter()
            .flat_map(|shard| {
                let AuthoredPayload::DeclarationFacts { types, .. } = &shard.payload else {
                    panic!("Rustdoc source set must produce declaration facts");
                };
                types
            })
            .collect::<Vec<_>>();
        assert!(types.iter().any(|fact| fact.name == "core.Widget"));
        assert!(types.iter().any(|fact| fact.name == "alloc.Widget"));
        assert!(types.iter().any(|fact| fact.name == "std.Widget"));
        for fact in types {
            let Locator::Artifact { path, .. } = &fact.locator else {
                panic!("Rustdoc declarations must retain their source-relative locator");
            };
            assert_eq!(
                path.as_str(),
                format!("{}.json", fact.name.split('.').next().unwrap())
            );
        }
        assert_eq!(pack.shards.len(), 1, "small source sets fit one shard");
        assert!(
            pack.shards
                .iter()
                .all(|shard| shard.activation == request.activation)
        );
        assert_eq!(
            production.artifact_sha256.as_deref(),
            Some(artifact.sha256())
        );
        assert_eq!(pack.provenance, request.provenance);
    }

    #[test]
    fn unchanged_rustdoc_pack_keeps_pre_layout_serialization_shape() {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(), serde_json::to_vec(&document(false)).unwrap()).unwrap();
        let production = RustdocJsonPackProducer.produce_exact_artifact(
            &request(file.path().to_path_buf()),
            &ArtifactProducerLimits::default(),
        );
        let pack = production.pack.expect("unchanged rustdoc produces a pack");
        assert_eq!(pack.schema_version, 22);
        let serialized = serde_json::to_value(&pack).unwrap();
        assert_eq!(serialized["schema_version"], 22);
        let mut type_count = 0;
        for shard in serialized["shards"].as_array().unwrap() {
            for ty in shard["payload"]["types"].as_array().unwrap() {
                type_count += 1;
                assert!(ty.get("tuple_fields").is_none());
            }
        }
        assert!(type_count > 0, "fixture must exercise generated TypeFacts");
    }

    #[test]
    fn rustdoc_projection_preserves_api_shapes_relations_and_reexports() {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(), serde_json::to_vec(&document(false)).unwrap()).unwrap();
        let production = RustdocJsonPackProducer.produce_exact_artifact(
            &request(file.path().to_path_buf()),
            &ArtifactProducerLimits::default(),
        );

        assert_eq!(
            production.completeness,
            Completeness::Complete,
            "{:#?}",
            production.diagnostics
        );
        let pack = production.pack.unwrap();
        compile_pack(&pack, &CompilerOptions::default()).unwrap();
        let AuthoredPayload::DeclarationFacts {
            types,
            members,
            relations,
            ..
        } = &pack.shards[0].payload
        else {
            panic!("expected declaration facts")
        };
        let widget = types
            .iter()
            .find(|fact| fact.name == "widget.Widget")
            .unwrap();
        assert!(widget.aliases.contains(&"widget.Gadget".to_owned()));
        assert!(
            widget
                .hierarchy
                .iter()
                .any(|fact| fact.hierarchy_kind == HierarchyKind::Implements)
        );
        assert!(
            members
                .iter()
                .any(|fact| fact.name == "render" && fact.member_kind == MemberKind::Method)
        );
        assert!(
            members
                .iter()
                .any(|fact| fact.member_kind == MemberKind::Macro)
        );
        assert!(
            members
                .iter()
                .any(|fact| fact.member_kind == MemberKind::Static)
        );
        assert!(relations.iter().any(|relation| relation.to == widget.id));
        let display = types
            .iter()
            .find(|fact| fact.name == "widget.Display")
            .unwrap();
        assert!(relations.iter().any(|relation| relation.to == display.id));
    }

    #[test]
    fn synthetic_generics_and_unrepresentable_rust_types_remain_honest() {
        let generics = Generics {
            params: vec![
                GenericParamDef {
                    name: "T".to_owned(),
                    kind: GenericParamDefKind::Type {
                        bounds: Vec::new(),
                        default: None,
                        is_synthetic: false,
                    },
                },
                GenericParamDef {
                    name: "impl FnOnce(T) -> T".to_owned(),
                    kind: GenericParamDefKind::Type {
                        bounds: Vec::new(),
                        default: None,
                        is_synthetic: true,
                    },
                },
            ],
            where_predicates: Vec::new(),
        };
        assert_eq!(generic_names(&generics), ["T"]);
        assert_eq!(rust_parameter_name("value").as_deref(), Some("value"));
        assert_eq!(rust_parameter_name("_"), None);
        assert_eq!(rust_parameter_name("(left, right)"), None);
        assert_eq!(rust_parameter_name("&self"), None);

        let document = document(false);
        let limits = ArtifactProducerLimits::default();
        let mut diagnostics = BoundedProducerDiagnostics::new(&limits);
        let projected = rust_type_ref(
            &Type::ImplTrait(Vec::new()),
            &document,
            &HashMap::default(),
            &limits,
            &mut diagnostics,
            0,
        );
        assert!(matches!(
            projected,
            TypeRef::Wildcard {
                variance: WildcardVariance::Any,
                bound: None
            }
        ));
    }

    #[test]
    fn blanket_impl_is_an_explicit_partial_outcome() {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(), serde_json::to_vec(&document(true)).unwrap()).unwrap();
        let production = RustdocJsonPackProducer.produce_exact_artifact(
            &request(file.path().to_path_buf()),
            &ArtifactProducerLimits::default(),
        );

        assert_eq!(production.completeness, Completeness::Partial);
        let diagnostic = production
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "rust.rustdoc.blanket_impl_unprojected")
            .expect("blanket implementation must remain an explicit reject");
        assert_eq!(diagnostic.location.as_deref(), Some("item.7"));
        assert!(diagnostic.source_entry.is_none());
        assert!(diagnostic.declaration.is_none());
    }

    #[test]
    fn rustdoc_source_set_accounts_anonymous_rejects_to_their_source_entry() {
        let root = tempfile::tempdir().unwrap();
        let document = document(true);
        fs::write(
            root.path().join("core.json"),
            serde_json::to_vec(&document).unwrap(),
        )
        .unwrap();
        let artifact = read_exact_source_set(
            root.path(),
            &[std::path::PathBuf::from("core.json")],
            1,
            8,
            &ArtifactProducerLimits::default(),
        )
        .unwrap();
        let mut request = request(root.path().join("stdlib"));
        request.artifact_kind = ExternalArtifactKind::RustdocJsonSet;
        request.activation[0].package = None;
        request.activation[0].module = None;

        let production = RustdocJsonPackProducer.produce_loaded_source_set(
            &request,
            &ArtifactProducerLimits::default(),
            None,
            &artifact,
            &[("widget".to_owned(), "core.json".to_owned())],
        );

        let diagnostic = production
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "rust.rustdoc.blanket_impl_unprojected")
            .expect("blanket implementation must remain an explicit reject");
        assert_eq!(diagnostic.location.as_deref(), Some("item.7"));
        assert_eq!(diagnostic.source_entry.as_deref(), Some("core.json"));
        assert!(diagnostic.declaration.is_none());
    }

    #[test]
    fn unsupported_format_fails_before_full_decode() {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(
            file.path(),
            serde_json::to_vec(&serde_json::json!({
                "format_version": RUSTDOC_FORMAT_VERSION + 1
            }))
            .unwrap(),
        )
        .unwrap();
        let production = RustdocJsonPackProducer.produce_exact_artifact(
            &request(file.path().to_path_buf()),
            &ArtifactProducerLimits::default(),
        );

        assert!(production.pack.is_none());
        assert_eq!(
            production.diagnostics[0].code,
            "rust.rustdoc.unsupported_version"
        );
    }

    #[test]
    fn crate_version_and_target_must_match_the_request() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut mismatched = document(false);
        mismatched.crate_version = Some("9.9.9".to_owned());
        fs::write(file.path(), serde_json::to_vec(&mismatched).unwrap()).unwrap();
        let version = RustdocJsonPackProducer.produce_exact_artifact(
            &request(file.path().to_path_buf()),
            &ArtifactProducerLimits::default(),
        );
        assert_eq!(
            version.diagnostics[0].code,
            "rust.rustdoc.crate_version_mismatch"
        );

        let mut mismatched = document(false);
        mismatched.target.triple = "aarch64-apple-darwin".to_owned();
        fs::write(file.path(), serde_json::to_vec(&mismatched).unwrap()).unwrap();
        let target = RustdocJsonPackProducer.produce_exact_artifact(
            &request(file.path().to_path_buf()),
            &ArtifactProducerLimits::default(),
        );
        assert_eq!(target.diagnostics[0].code, "rust.rustdoc.target_mismatch");

        let valid = document(false);
        fs::write(file.path(), serde_json::to_vec(&valid).unwrap()).unwrap();
        let mut mismatched_request = request(file.path().to_path_buf());
        mismatched_request.activation[0].module = Some(NameSelector {
            name: "different_crate".to_owned(),
            version: Some("=1.2.3".to_owned()),
        });
        let crate_name = RustdocJsonPackProducer
            .produce_exact_artifact(&mismatched_request, &ArtifactProducerLimits::default());
        assert_eq!(
            crate_name.diagnostics[0].code,
            "rust.rustdoc.crate_name_mismatch"
        );
    }

    #[test]
    fn name_index_terminates_on_cycles_and_shared_children() {
        let mut document = document(false);
        document.paths.clear();
        document.index = std::collections::HashMap::from([
            (
                Id(0),
                item(
                    0,
                    Some("widget"),
                    RustVisibility::Default,
                    ItemEnum::Module(Module {
                        is_crate: true,
                        items: vec![Id(1), Id(2)],
                        is_stripped: false,
                    }),
                ),
            ),
            (
                Id(1),
                item(
                    1,
                    Some("left"),
                    RustVisibility::Public,
                    ItemEnum::Module(Module {
                        is_crate: false,
                        items: vec![Id(0), Id(3)],
                        is_stripped: false,
                    }),
                ),
            ),
            (
                Id(2),
                item(
                    2,
                    Some("right"),
                    RustVisibility::Public,
                    ItemEnum::Module(Module {
                        is_crate: false,
                        items: vec![Id(3)],
                        is_stripped: false,
                    }),
                ),
            ),
            (
                Id(3),
                item(
                    3,
                    Some("shared"),
                    RustVisibility::Public,
                    ItemEnum::Module(Module {
                        is_crate: false,
                        items: Vec::new(),
                        is_stripped: false,
                    }),
                ),
            ),
        ]);
        document.root = Id(0);

        let names = item_names(&document, &document.index[&document.root], None).unwrap();

        assert_eq!(names.len(), 4);
        assert!(names[&Id(3)].ends_with(".shared"));
    }

    #[test]
    fn rustdoc_source_set_applies_one_aggregate_record_budget() {
        let root = tempfile::tempdir().unwrap();
        for crate_name in ["core", "alloc", "std"] {
            write_crate_document(root.path(), crate_name);
        }
        let relative_paths = ["core.json", "alloc.json", "std.json"]
            .into_iter()
            .map(std::path::PathBuf::from)
            .collect::<Vec<_>>();
        let artifact = read_exact_source_set(
            root.path(),
            &relative_paths,
            3,
            8,
            &ArtifactProducerLimits::default(),
        )
        .unwrap();
        let mut request = request(root.path().join("stdlib"));
        request.artifact_kind = ExternalArtifactKind::RustdocJsonSet;
        request.activation[0].package = None;
        request.activation[0].module = None;
        let crates = [
            ("core".to_owned(), "core.json".to_owned()),
            ("alloc".to_owned(), "alloc.json".to_owned()),
            ("std".to_owned(), "std.json".to_owned()),
        ];
        let limits = ArtifactProducerLimits {
            max_records: 2,
            ..ArtifactProducerLimits::default()
        };

        let production = RustdocJsonPackProducer
            .produce_loaded_source_set(&request, &limits, None, &artifact, &crates);
        assert!(production.diagnostics.iter().all(|diagnostic| {
            diagnostic.declaration.is_some() || diagnostic.source_entry.is_some()
        }));
        let pack = production
            .pack
            .expect("source set should produce a partial pack");
        let AuthoredPayload::DeclarationFacts {
            types,
            members,
            relations,
            ..
        } = &pack.shards[0].payload
        else {
            panic!("Rustdoc source set must produce declaration facts");
        };
        assert!(types.len() + members.len() + relations.len() <= limits.max_records);
        assert!(
            production
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "limit.records")
        );
    }

    #[test]
    fn total_record_limit_includes_relations() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let document = document(false);
        fs::write(file.path(), serde_json::to_vec(&document).unwrap()).unwrap();
        let limits = ArtifactProducerLimits {
            max_records: document.index.len(),
            ..ArtifactProducerLimits::default()
        };

        let production = RustdocJsonPackProducer
            .produce_exact_artifact(&request(file.path().to_path_buf()), &limits);

        let pack = production
            .pack
            .as_ref()
            .expect("declarations remain available");
        let AuthoredPayload::DeclarationFacts {
            types,
            members,
            relations,
            ..
        } = &pack.shards[0].payload
        else {
            panic!("expected declaration facts")
        };
        assert!(types.len() + members.len() + relations.len() <= limits.max_records);
        assert_eq!(production.completeness, Completeness::Partial);
        assert!(
            production
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "limit.records")
        );
    }

    #[test]
    fn deeply_nested_names_stop_at_the_model_text_limit() {
        let mut document = document(false);
        document.paths.clear();
        document.index.clear();
        let depth = MAX_MODEL_NAME_BYTES / 8 + 2;
        for index in 0..depth {
            let child = (index + 1 < depth).then(|| Id((index + 1) as u32));
            document.index.insert(
                Id(index as u32),
                item(
                    index as u32,
                    Some(if index == 0 { "widget" } else { "segment" }),
                    if index == 0 {
                        RustVisibility::Default
                    } else {
                        RustVisibility::Public
                    },
                    ItemEnum::Module(Module {
                        is_crate: index == 0,
                        items: child.into_iter().collect(),
                        is_stripped: false,
                    }),
                ),
            );
        }
        document.root = Id(0);

        assert!(matches!(
            item_names(&document, &document.index[&document.root], None),
            Err(NameIndexError::Limit)
        ));
    }

    #[test]
    fn cancellation_stops_before_rustdoc_decode() {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(), serde_json::to_vec(&document(false)).unwrap()).unwrap();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let production = RustdocJsonPackProducer.produce_exact_artifact_with_cancellation(
            &request(file.path().to_path_buf()),
            &ArtifactProducerLimits::default(),
            Some(&cancellation),
        );

        assert!(production.pack.is_none());
        assert_eq!(production.diagnostics[0].code, "artifact.cancelled");
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10258: cancelled reexport collection cannot publish partial routes"
    )]
    fn cancelled_reexport_collection_returns_no_carrier() {
        let document = document(false);
        let cancellation = CancellationToken::new();
        let mut visited = 0;
        let result = collect_external_reexports_status_with_probe(
            &document,
            100,
            Some(&cancellation),
            || {
                visited += 1;
                if visited == 2 {
                    cancellation.cancel();
                }
            },
        );
        assert_eq!(visited, 2, "the walk was cancelled after a retained item");
        assert!(
            result.is_err(),
            "partial route state must never be returned"
        );
    }
}
