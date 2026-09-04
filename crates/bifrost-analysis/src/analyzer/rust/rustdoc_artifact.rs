use std::collections::{HashMap as RandomHashMap, HashSet as RandomHashSet, VecDeque};

use rustdoc_types::{
    Crate as RustdocCrate, GenericArg, GenericArgs, GenericBound, Generics, Id, Item, ItemEnum,
    Path as RustdocPath, StructKind, Term, Type, VariantKind, Visibility as RustVisibility,
    WherePredicate,
};
use serde::Deserialize;

use crate::CancellationToken;
use crate::analyzer::canonical_hash::{lower_hex_string, sha256_bytes};
use crate::analyzer::semantic_model::{
    ArtifactProducerLimits, ArtifactProduction, ArtifactProductionRequest, AuthoredPayload,
    AuthoredSemanticModelPack, AuthoredShard, BoundedProducerDiagnostics, Completeness,
    ExactArtifact, ExternalArtifactKind, ExternalArtifactPackProducer, HierarchyFact,
    HierarchyKind, Locator, MemberFact, MemberIdentity, MemberKind, Parameter, Producer,
    ProducerDiagnostic, ProducerDiagnosticSeverity, RelationFact, RelationKind, Signature,
    SuppressedDiagnostics, TypeFact, TypeIdentity, TypeKind, TypeRef, TypeRefReferenceKind,
    Visibility, WildcardVariance, admit_into_full_diagnostics, member_declaration_id,
    read_exact_artifact_while, type_declaration_id,
};
use crate::hash::{HashMap, HashSet};

const ARTIFACT_LOCATOR_PATH: &str = "rustdoc/api.json";
const RUSTDOC_FORMAT_VERSION: u32 = 61;
const MAX_MODEL_NAME_BYTES: usize = 16 * 1024;
const MAX_TOTAL_MODEL_NAME_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Default)]
pub struct RustdocJsonPackProducer;

#[derive(Debug, Deserialize)]
struct RustdocVersionEnvelope {
    format_version: u32,
}

impl ExternalArtifactPackProducer for RustdocJsonPackProducer {
    fn produce_exact_artifact(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
    ) -> ArtifactProduction {
        produce(request, limits, None)
    }

    fn produce_exact_artifact_with_cancellation(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
    ) -> ArtifactProduction {
        produce(request, limits, cancellation)
    }
}

fn produce(
    request: &ArtifactProductionRequest,
    limits: &ArtifactProducerLimits,
    cancellation: Option<&CancellationToken>,
) -> ArtifactProduction {
    if request.artifact_kind != ExternalArtifactKind::RustdocJson {
        return failed(
            limits,
            "rust.rustdoc.wrong_artifact_kind",
            "Rust rustdoc producer requires a rustdoc_json artifact",
        );
    }
    let artifact = match read_exact_artifact_while(&request.path, limits, || {
        cancellation.is_some_and(CancellationToken::is_cancelled)
    }) {
        Ok(artifact) => artifact,
        Err(diagnostic) => return ArtifactProduction::failed(diagnostic, limits),
    };
    RustdocJsonPackProducer.produce_loaded_artifact(request, limits, cancellation, &artifact)
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
            return failed(
                limits,
                "rust.rustdoc.wrong_artifact_kind",
                "Rust rustdoc producer requires a rustdoc_json artifact",
            );
        }
        if artifact.bytes().len() as u64 > limits.max_artifact_bytes {
            return failed(
                limits,
                "limit.artifact_bytes",
                format!("exact artifact exceeds {} bytes", limits.max_artifact_bytes),
            );
        }
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return failed(
                limits,
                "artifact.cancelled",
                "rustdoc artifact production was cancelled",
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
            return failed(
                limits,
                "rust.rustdoc.wrong_artifact_kind",
                "Rust rustdoc source-set producer requires a rustdoc_json_set artifact",
            );
        }
        if crates.is_empty() {
            return failed(
                limits,
                "rust.rustdoc.empty_source_set",
                "Rust rustdoc source set must contain at least one crate",
            );
        }
        if artifact.bytes().len() as u64 > limits.max_artifact_bytes {
            return failed(
                limits,
                "limit.artifact_bytes",
                format!("exact artifact exceeds {} bytes", limits.max_artifact_bytes),
            );
        }
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return failed(
                limits,
                "artifact.cancelled",
                "rustdoc source-set production was cancelled",
            );
        }

        let mut ordered = crates.to_vec();
        ordered.sort();
        if ordered.windows(2).any(|entries| {
            entries[0] == entries[1] || entries[0].0 == entries[1].0 || entries[0].1 == entries[1].1
        }) {
            return failed(
                limits,
                "rust.rustdoc.duplicate_source",
                "Rust rustdoc source set contains a duplicate crate name or source path",
            );
        }
        let entries = artifact
            .source_entries()
            .iter()
            .map(|entry| (entry.relative_path().to_owned(), entry.bytes()))
            .collect::<RandomHashMap<_, _>>();
        let mut productions = Vec::with_capacity(ordered.len());
        for (crate_name, path) in &ordered {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return failed(
                    limits,
                    "artifact.cancelled",
                    "rustdoc source-set production was cancelled",
                );
            }
            let Some(bytes) = entries.get(path) else {
                return failed(
                    limits,
                    "rust.rustdoc.source_missing",
                    format!("rustdoc source set does not contain {path}"),
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
            );
            limit_production_records(&mut production, remaining, limits);
            productions.push(production);
        }
        merge_source_set_productions(request, limits, artifact.sha256(), productions)
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
    )
}

fn produce_loaded_json_document(
    request: &ArtifactProductionRequest,
    limits: &ArtifactProducerLimits,
    cancellation: Option<&CancellationToken>,
    artifact_sha256: &str,
    expected_crate: Option<&str>,
    source_relative_path: Option<&str>,
    bytes: &[u8],
) -> ArtifactProduction {
    let envelope: RustdocVersionEnvelope = match serde_json::from_slice(bytes) {
        Ok(envelope) => envelope,
        Err(error) => {
            return failed(
                limits,
                "rust.rustdoc.invalid_json",
                format!("could not decode rustdoc JSON version: {error}"),
            );
        }
    };
    if envelope.format_version != RUSTDOC_FORMAT_VERSION {
        return failed(
            limits,
            "rust.rustdoc.unsupported_version",
            format!(
                "rustdoc JSON format {} is unsupported; this producer accepts {}",
                envelope.format_version, RUSTDOC_FORMAT_VERSION
            ),
        );
    }
    let document: RustdocCrate = match serde_json::from_slice(bytes) {
        Ok(document) => document,
        Err(error) => {
            return failed(
                limits,
                "rust.rustdoc.invalid_json",
                format!(
                    "could not decode rustdoc JSON format {}: {error}",
                    RUSTDOC_FORMAT_VERSION
                ),
            );
        }
    };
    let document_limits = ArtifactProducerLimits {
        max_records: limits.max_records.max(document.index.len()),
        ..*limits
    };
    let requested_versions = request
        .activation
        .iter()
        .filter_map(|selector| selector.package.as_ref())
        .filter_map(|package| package.version.as_deref())
        .map(|version| version.strip_prefix('=').unwrap_or(version))
        .collect::<RandomHashSet<_>>();
    if requested_versions.len() > 1
        || requested_versions
            .iter()
            .next()
            .is_some_and(|expected| document.crate_version.as_deref() != Some(*expected))
    {
        return failed(
            limits,
            "rust.rustdoc.crate_version_mismatch",
            format!(
                "rustdoc crate version {:?} does not match requested package versions {:?}",
                document.crate_version, requested_versions
            ),
        );
    }
    if request.activation.iter().any(|selector| {
        !selector.targets.is_empty() && !selector.targets.contains(&document.target.triple)
    }) {
        return failed(
            limits,
            "rust.rustdoc.target_mismatch",
            format!(
                "rustdoc target {} does not match requested activation targets",
                document.target.triple
            ),
        );
    }
    produce_document(
        request,
        &document_limits,
        artifact_sha256,
        &document,
        cancellation,
        expected_crate,
        source_relative_path,
    )
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
    let diagnostic = ProducerDiagnostic {
        severity: ProducerDiagnosticSeverity::Warning,
        source_entry: None,
        code: "limit.records".to_owned(),
        location: None,
        declaration: None,
        message: format!("source set stopped after {max_records} aggregate records"),
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
            } => Some(types.len() + members.len() + relations.len()),
            _ => None,
        })
        .unwrap_or_default()
}

fn merge_source_set_productions(
    request: &ArtifactProductionRequest,
    limits: &ArtifactProducerLimits,
    artifact_sha256: &str,
    productions: Vec<ArtifactProduction>,
) -> ArtifactProduction {
    let mut diagnostics = Vec::new();
    let mut suppressed_diagnostics = SuppressedDiagnostics::default();
    let mut types = Vec::new();
    let mut members = Vec::new();
    let mut relations = Vec::new();
    let mut completeness = Completeness::Complete;
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
    let mut seen_type_ids: RandomHashSet<String> = RandomHashSet::default();
    types.retain(|fact| seen_type_ids.insert(fact.id.clone()));
    let mut seen_member_ids: RandomHashSet<String> = RandomHashSet::default();
    members.retain(|fact| seen_member_ids.insert(fact.id.clone()));
    let mut seen_relation_ids: RandomHashSet<String> = RandomHashSet::default();
    relations.retain(|fact| seen_relation_ids.insert(fact.id.clone()));
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
    let mut activation = request.activation.clone();
    for selector in &mut activation {
        selector.artifact_sha256 = Some(artifact_sha256.to_owned());
    }
    let pack = (!types.is_empty()).then(|| AuthoredSemanticModelPack {
        schema_version: crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
        pack_id: request.pack_id.clone(),
        version: request.pack_version.clone(),
        producer: Producer {
            name: "bifrost-rustdoc-json".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
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
        shards: vec![AuthoredShard {
            id: "declarations.rust.external".to_owned(),
            activation,
            payload: AuthoredPayload::DeclarationFacts {
                types,
                members,
                relations,
            },
        }],
    });
    ArtifactProduction {
        artifact_sha256: Some(artifact_sha256.to_owned()),
        pack,
        completeness,
        diagnostics,
        suppressed_diagnostics,
    }
}

fn produce_document(
    request: &ArtifactProductionRequest,
    limits: &ArtifactProducerLimits,
    artifact_sha256: &str,
    document: &RustdocCrate,
    cancellation: Option<&CancellationToken>,
    expected_crate: Option<&str>,
    source_relative_path: Option<&str>,
) -> ArtifactProduction {
    let mut diagnostics = BoundedProducerDiagnostics::new(limits);
    let Some(root) = document.index.get(&document.root) else {
        diagnostics.error(
            "rust.rustdoc.missing_root",
            None,
            "rustdoc JSON root item is absent from the item index",
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
    if !matches!(root.inner, ItemEnum::Module(_)) {
        diagnostics.error(
            "rust.rustdoc.invalid_root",
            None,
            "rustdoc JSON root item is not a module",
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
        diagnostics.error(
            "rust.rustdoc.crate_name_mismatch",
            None,
            format!(
                "rustdoc root crate {root_name:?} does not match requested modules {requested_crates:?}"
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
    let names = match item_names(document, root, cancellation) {
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
                type_declaration_id(TypeIdentity {
                    ecosystem: "cargo",
                    name,
                }),
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
        type_position.insert(item.id, types.len());
        types.push(TypeFact {
            id: id.clone(),
            name: name.clone(),
            type_kind,
            visibility: semantic_visibility(&item.visibility),
            is_abstract: matches!(item.inner, ItemEnum::Trait(_)),
            is_sealed: false,
            has_explicit_type_terms: false,
            type_parameters: generic_names(generics),
            type_parameter_constraints: Vec::new(),
            underlying_type: None,
            value_semantics: None,
            embedded_types: Vec::new(),
            hierarchy,
            aliases: Vec::new(),
            extension_surfaces: Vec::new(),
            guard: None,
            locator: locator(source_relative_path.unwrap_or(ARTIFACT_LOCATOR_PATH), name),
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
    );

    let mut member_position = HashMap::default();
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
        let Some(owner_item_id) = type_id_by_name.get(&owner_name).cloned() else {
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
        let mut signature = member_signature(item, document, &type_ids, limits, &mut diagnostics);
        if member_kind == MemberKind::Method
            && let Some(signature) = signature.as_mut()
        {
            for parameter in &mut signature.parameters {
                replace_self_type(
                    &mut parameter.r#type,
                    &owner_item_id,
                    0,
                    limits.max_signature_depth,
                );
            }
            if let Some(returns) = &mut signature.returns {
                replace_self_type(returns, &owner_item_id, 0, limits.max_signature_depth);
            }
        }
        let is_static = match &item.inner {
            ItemEnum::Function(function) => !function
                .sig
                .inputs
                .iter()
                .any(|(name, _)| name == "self" || name.ends_with(" self")),
            _ => true,
        };
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
        let member_id = member_declaration_id(MemberIdentity {
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
        member_position.insert(item.id, members.len());
        members.push(MemberFact {
            id: member_id.clone(),
            owner: owner_item_id,
            name: name.to_owned(),
            member_kind,
            visibility: semantic_visibility(&item.visibility),
            is_static,
            is_abstract: matches!(&item.inner, ItemEnum::Function(function) if !function.has_body),
            is_virtual: false,
            implicit_operation: None,
            callable_family_complete: false,
            signature,
            receiver: None,
            extension_receiver: None,
            extension_receiver_constraints: Vec::new(),
            aliases: Vec::new(),
            guard: None,
            locator: locator(
                source_relative_path.unwrap_or(ARTIFACT_LOCATOR_PATH),
                &format!("{path}#{member_id}"),
            ),
        });
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
            GenericBound::TraitBound { trait_, .. } => Some(HierarchyFact {
                hierarchy_kind: HierarchyKind::Extends,
                target: path_type_ref(trait_, document, type_ids, limits, diagnostics, 0),
                declaration_ordinal: None,
            }),
            _ => None,
        })
        .collect();
    (kind, generics, hierarchy)
}

fn empty_generics() -> &'static Generics {
    static EMPTY: std::sync::OnceLock<Generics> = std::sync::OnceLock::new();
    EMPTY.get_or_init(|| Generics {
        params: Vec::new(),
        where_predicates: Vec::new(),
    })
}

fn generic_names(generics: &Generics) -> Vec<String> {
    generics
        .params
        .iter()
        .filter(|param| {
            matches!(
                param.kind,
                rustdoc_types::GenericParamDefKind::Type {
                    is_synthetic: false,
                    ..
                } | rustdoc_types::GenericParamDefKind::Const { .. }
            )
        })
        .map(|param| param.name.clone())
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
    document: &RustdocCrate,
    type_ids: &HashMap<Id, String>,
    limits: &ArtifactProducerLimits,
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
                    r#type: rust_type_ref(ty, document, type_ids, limits, diagnostics, 0),
                    optional: false,
                    variadic: false,
                    passing_mode: Default::default(),
                })
                .collect(),
            function
                .sig
                .output
                .as_ref()
                .map(|ty| rust_type_ref(ty, document, type_ids, limits, diagnostics, 0)),
            generic_names(&function.generics),
        ),
        ItemEnum::StructField(ty)
        | ItemEnum::Constant { type_: ty, .. }
        | ItemEnum::AssocConst { type_: ty, .. } => (
            Vec::new(),
            Some(rust_type_ref(
                ty,
                document,
                type_ids,
                limits,
                diagnostics,
                0,
            )),
            Vec::new(),
        ),
        ItemEnum::Static(static_) => (
            Vec::new(),
            Some(rust_type_ref(
                &static_.type_,
                document,
                type_ids,
                limits,
                diagnostics,
                0,
            )),
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
                .filter_map(|(index, id)| document.index.get(id).map(|field| (index, field)))
                .filter_map(|(index, field)| match &field.inner {
                    ItemEnum::StructField(ty) => Some(Parameter {
                        name: field.name.clone().or_else(|| Some(index.to_string())),
                        r#type: rust_type_ref(ty, document, type_ids, limits, diagnostics, 0),
                        optional: false,
                        variadic: false,
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

fn replace_self_type(ty: &mut TypeRef, owner: &str, depth: usize, max_depth: usize) {
    if depth >= max_depth {
        return;
    }
    if matches!(ty, TypeRef::TypeParameter { name } if name == "Self") {
        *ty = TypeRef::Declared {
            id: owner.to_owned(),
            arguments: Vec::new(),
            nullable: false,
        };
        return;
    }
    let next = depth + 1;
    match ty {
        TypeRef::Declared { arguments, .. } | TypeRef::Named { arguments, .. } => {
            for argument in arguments {
                replace_self_type(argument, owner, next, max_depth);
            }
        }
        TypeRef::Array { element }
        | TypeRef::ByRef { element, .. }
        | TypeRef::Pointer { element }
        | TypeRef::Slice { element }
        | TypeRef::FixedArray { element, .. }
        | TypeRef::Channel { element, .. }
        | TypeRef::Wildcard {
            bound: Some(element),
            ..
        } => replace_self_type(element, owner, next, max_depth),
        TypeRef::Map { key, value } => {
            replace_self_type(key, owner, next, max_depth);
            replace_self_type(value, owner, next, max_depth);
        }
        TypeRef::Tuple { elements } => {
            for element in elements {
                replace_self_type(element, owner, next, max_depth);
            }
        }
        TypeRef::Function { parameters, result } => {
            for parameter in parameters {
                replace_self_type(&mut parameter.r#type, owner, next, max_depth);
            }
            if let Some(result) = result {
                replace_self_type(result, owner, next, max_depth);
            }
        }
        TypeRef::TypeParameter { .. } | TypeRef::Wildcard { bound: None, .. } => {}
    }
}

fn rust_type_ref(
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
            format!(
                "Rust signature exceeded depth {}",
                limits.max_signature_depth
            ),
        );
        return named_type("_");
    }
    let next = depth + 1;
    match ty {
        Type::ResolvedPath(path) => {
            path_type_ref(path, document, type_ids, limits, diagnostics, next)
        }
        // rustdoc can emit generic binders from an enclosing trait or impl
        // that are not present in the projected declaration's signature.
        // Preserve the uncertainty without producing an invalid pack whose
        // type parameter references cannot be resolved by the compiler.
        Type::Generic(_) => TypeRef::Wildcard {
            variance: WildcardVariance::Any,
            bound: None,
        },
        Type::Primitive(name) => named_type(name),
        Type::Tuple(elements) if elements.is_empty() => TypeRef::Wildcard {
            variance: WildcardVariance::Any,
            bound: None,
        },
        Type::Tuple(elements) => TypeRef::Tuple {
            elements: elements
                .iter()
                .map(|element| {
                    rust_type_ref(element, document, type_ids, limits, diagnostics, next)
                })
                .collect(),
        },
        Type::Slice(element) | Type::Array { type_: element, .. } => TypeRef::Array {
            element: Box::new(rust_type_ref(
                element,
                document,
                type_ids,
                limits,
                diagnostics,
                next,
            )),
        },
        Type::RawPointer { type_, .. } | Type::BorrowedRef { type_, .. } => TypeRef::ByRef {
            element: Box::new(rust_type_ref(
                type_,
                document,
                type_ids,
                limits,
                diagnostics,
                next,
            )),
            reference_kind: TypeRefReferenceKind::Lvalue,
        },
        Type::FunctionPointer(pointer) => TypeRef::Function {
            parameters: pointer
                .sig
                .inputs
                .iter()
                .map(|(name, ty)| Parameter {
                    name: rust_parameter_name(name),
                    r#type: rust_type_ref(ty, document, type_ids, limits, diagnostics, next),
                    optional: false,
                    variadic: false,
                    passing_mode: Default::default(),
                })
                .collect(),
            result: pointer.sig.output.as_ref().map(|ty| {
                Box::new(rust_type_ref(
                    ty,
                    document,
                    type_ids,
                    limits,
                    diagnostics,
                    next,
                ))
            }),
        },
        Type::Pat { type_, .. } => {
            rust_type_ref(type_, document, type_ids, limits, diagnostics, next)
        }
        // DeclarationFacts cannot encode Rust existential/trait-object bounds
        // or associated projections without inventing one qualified-name
        // string. Preserve that uncertainty explicitly instead of emitting
        // Rust syntax (which is not a declaration identifier) as a name.
        Type::DynTrait(_) | Type::ImplTrait(_) | Type::QualifiedPath { .. } => TypeRef::Wildcard {
            variance: WildcardVariance::Any,
            bound: None,
        },
        Type::Infer => named_type("_"),
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
    let arguments = path
        .args
        .as_deref()
        .map(|args| generic_argument_types(args, document, type_ids, limits, diagnostics, depth))
        .unwrap_or_default();
    if let Some(id) = type_ids.get(&path.id) {
        TypeRef::Declared {
            id: id.clone(),
            arguments,
            nullable: false,
        }
    } else {
        TypeRef::Named {
            name: normalized_path(path, document),
            arguments,
            nullable: false,
        }
    }
}

fn generic_argument_types(
    args: &GenericArgs,
    document: &RustdocCrate,
    type_ids: &HashMap<Id, String>,
    limits: &ArtifactProducerLimits,
    diagnostics: &mut BoundedProducerDiagnostics,
    depth: usize,
) -> Vec<TypeRef> {
    match args {
        GenericArgs::AngleBracketed { args, .. } => args
            .iter()
            .filter_map(|argument| match argument {
                GenericArg::Type(ty) => Some(rust_type_ref(
                    ty,
                    document,
                    type_ids,
                    limits,
                    diagnostics,
                    depth,
                )),
                _ => None,
            })
            .collect(),
        GenericArgs::Parenthesized { inputs, output } => {
            let mut types = inputs
                .iter()
                .map(|ty| rust_type_ref(ty, document, type_ids, limits, diagnostics, depth))
                .collect::<Vec<_>>();
            if let Some(output) = output {
                types.push(rust_type_ref(
                    output,
                    document,
                    type_ids,
                    limits,
                    diagnostics,
                    depth,
                ));
            }
            types
        }
        GenericArgs::ReturnTypeNotation => Vec::new(),
    }
}

fn named_type(name: &str) -> TypeRef {
    TypeRef::Named {
        name: name.to_owned(),
        arguments: Vec::new(),
        nullable: false,
    }
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
        ItemEnum::Impl(implementation) => resolved_type_name(&implementation.for_, document),
        _ => names.get(&parent).cloned(),
    }
}

fn semantic_visibility(visibility: &RustVisibility) -> Visibility {
    match visibility {
        RustVisibility::Public => Visibility::Public,
        RustVisibility::Crate => Visibility::Internal,
        RustVisibility::Restricted { .. } => Visibility::Package,
        RustVisibility::Default => Visibility::Public,
    }
}

fn locator(path: &str, symbol: &str) -> Locator {
    Locator::Artifact {
        path: path.to_owned(),
        symbol: symbol.to_owned(),
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

fn apply_impl_hierarchy(
    items: &[&Item],
    projection: &RustdocProjectionIndex<'_>,
    types: &mut [TypeFact],
    limits: &ArtifactProducerLimits,
    diagnostics: &mut BoundedProducerDiagnostics,
    cancellation: Option<&CancellationToken>,
    hierarchy_seen: &mut [RandomHashSet<HierarchyFact>],
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
        if !projection.visible.contains(&item.id) || implementation.is_negative {
            continue;
        }
        if implementation.blanket_impl.is_some() {
            diagnostics.warning(
                "rust.rustdoc.blanket_impl_unprojected",
                Some(format!("item.{}", item.id.0)),
                "blanket implementation has no concrete declaration owner and was not projected",
            );
            continue;
        }
        let Some(owner_name) = resolved_type_name(&implementation.for_, projection.document) else {
            diagnostics.warning(
                "rust.rustdoc.nonconcrete_impl_unprojected",
                Some(format!("item.{}", item.id.0)),
                "implementation target has no concrete rustdoc declaration owner",
            );
            continue;
        };
        let Some(owner_item) = projection.type_item_by_name.get(&owner_name).copied() else {
            continue;
        };
        let Some(trait_) = &implementation.trait_ else {
            continue;
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
        let hierarchy = HierarchyFact {
            hierarchy_kind: HierarchyKind::Implements,
            target,
            declaration_ordinal: None,
        };
        if hierarchy_seen[position].insert(hierarchy.clone()) {
            types[position].hierarchy.push(hierarchy);
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
            TypeRef::TypeParameter { .. } | TypeRef::Wildcard { bound: None, .. } => {}
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
        let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
        return ArtifactProduction {
            artifact_sha256: Some(artifact_sha256.to_owned()),
            pack: None,
            completeness: Completeness::Partial,
            diagnostics,
            suppressed_diagnostics,
        };
    }
    let mut activation = request.activation.clone();
    for selector in &mut activation {
        selector.artifact_sha256 = Some(artifact_sha256.to_owned());
    }
    let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
    let completeness = if diagnostics.is_empty() && suppressed_diagnostics.total() == 0 {
        Completeness::Complete
    } else {
        Completeness::Partial
    };
    ArtifactProduction {
        artifact_sha256: Some(artifact_sha256.to_owned()),
        pack: Some(AuthoredSemanticModelPack {
            schema_version: crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
            pack_id: request.pack_id.clone(),
            version: request.pack_version.clone(),
            producer: Producer {
                name: "bifrost-rustdoc-json".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
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
            shards: vec![AuthoredShard {
                id: "declarations.rust.external".to_owned(),
                activation,
                payload: AuthoredPayload::DeclarationFacts {
                    types,
                    members,
                    relations,
                },
            }],
        }),
        completeness,
        diagnostics,
        suppressed_diagnostics,
    }
}

fn failed(
    limits: &ArtifactProducerLimits,
    code: &str,
    message: impl Into<String>,
) -> ArtifactProduction {
    ArtifactProduction::failed(
        ProducerDiagnostic {
            severity: ProducerDiagnosticSeverity::Error,
            source_entry: None,
            code: code.to_owned(),
            location: None,
            declaration: None,
            message: message.into(),
        },
        limits,
    )
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use rustdoc_types::{
        Abi, Function, FunctionHeader, FunctionSignature, GenericParamDef, GenericParamDefKind,
        Impl, ItemKind, ItemSummary, Module, Struct, Target, Trait, TraitBoundModifier, Use,
    };
    use std::fs;

    use crate::analyzer::semantic_model::{
        ActivationSelector, Compatibility, CompilerOptions, NameSelector, Provenance, Safety,
        compile_pack, read_exact_source_set,
    };

    fn item(id: u32, name: Option<&str>, visibility: RustVisibility, inner: ItemEnum) -> Item {
        Item {
            id: Id(id),
            crate_id: 0,
            name: name.map(str::to_owned),
            span: None,
            visibility,
            docs: None,
            links: std::collections::HashMap::new(),
            attrs: Vec::new(),
            deprecation: None,
            stability: None,
            const_stability: None,
            inner,
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
                bifrost: "*".to_owned(),
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
        let AuthoredPayload::DeclarationFacts { types, .. } = &pack.shards[0].payload else {
            panic!("Rustdoc source set must produce declaration facts");
        };
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
        assert_eq!(pack.shards.len(), 1);
        assert_eq!(
            pack.shards[0].activation[0].artifact_sha256.as_deref(),
            Some(artifact.sha256())
        );
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
        let pack = production
            .pack
            .expect("source set should produce a partial pack");
        let AuthoredPayload::DeclarationFacts {
            types,
            members,
            relations,
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
        assert!(
            production
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "rust.rustdoc.blanket_impl_unprojected")
        );
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
}
