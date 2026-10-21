//! Canonical semantic projections for fully loaded policies and endpoints.
//!
//! These functions accept only resolved models. Source paths, raw bytes,
//! reference order, version origin, optional pins, and registration provenance
//! are deliberately absent from every returned value.

use std::collections::HashSet;

use brokk_bifrost_analysis::analyzer::semantic_model::compact_json_bytes;
use serde_json::{Map, Value, json};

use super::canonical::{
    binding_index_to_json, binding_name_to_json, binding_tag_to_json, endpoint_binding_to_json,
    policy_port_to_json, policy_semantic_event_to_json, policy_severity_to_json,
    sorted_identifier_refs, taint_port_fields_to_json, taint_transfer_to_json,
    typestate_automaton_projection_to_json, typestate_call_binding_to_json,
};
use super::definition::*;
use super::identity::ResolvedPolicyAnalysisRef;
use super::resolved::*;

pub(crate) fn loaded_endpoint_semantic_to_json(
    definition: &MatchEndpointDefinition,
    selector: &ResolvedPolicySelector,
) -> Result<Value, LoadedModelError> {
    let mut value = RqlpDocument::Endpoint {
        definition: Box::new(definition.clone()),
    }
    .to_normalized_authored_json();
    let object = value.as_object_mut().ok_or_else(|| {
        LoadedModelError::CanonicalProjection("endpoint projection is not an object".to_string())
    })?;
    object.insert("selector".to_string(), resolved_selector_to_json(selector));
    Ok(value)
}

pub(crate) fn loaded_endpoint_analysis_projection_to_json(
    definition: &MatchEndpointDefinition,
    selector: &ResolvedPolicySelector,
) -> Result<Value, LoadedModelError> {
    let semantic = loaded_endpoint_semantic_to_json(definition, selector)?;
    let object = semantic.as_object().ok_or_else(|| {
        LoadedModelError::CanonicalProjection("endpoint projection is not an object".to_string())
    })?;
    let mut projection = endpoint_model_analysis_fields_to_json(
        object["role"].clone(),
        object["binding"].clone(),
        object.get("taint").cloned(),
        object["supersedes"].clone(),
    );
    projection.insert(
        "schema_version".to_string(),
        json!(definition.schema_version.version),
    );
    projection.insert("selector".to_string(), object["selector"].clone());
    Ok(Value::Object(projection))
}

pub(crate) fn composed_endpoint_semantic_to_json(
    identity: &ResolvedEndpointIdentity,
    definition_schema: &EndpointDefinitionSchemaResolution,
    selector: &ResolvedPolicySelector,
    model: &ResolvedEndpointModel,
) -> Value {
    json!({
        "identity": resolved_endpoint_identity_to_json(identity),
        "definition_schema_version": definition_schema.version(),
        "selector": resolved_selector_to_json(selector),
        "model": resolved_endpoint_model_to_json(model),
    })
}

pub(crate) fn composed_endpoint_analysis_projection_to_json(
    definition_schema: &EndpointDefinitionSchemaResolution,
    selector: &ResolvedPolicySelector,
    model: &ResolvedEndpointModel,
) -> Value {
    let mut projection = endpoint_model_analysis_fields_to_json(
        json!((model.role).label()),
        endpoint_binding_to_json(&model.binding),
        model.taint.as_ref().map(endpoint_taint_to_json),
        json!(sorted_endpoint_identities(&model.supersedes)),
    );
    projection.insert(
        "definition_schema_version".to_string(),
        json!(definition_schema.version()),
    );
    projection.insert("selector".to_string(), resolved_selector_to_json(selector));
    Value::Object(projection)
}

fn endpoint_model_analysis_fields_to_json(
    role: Value,
    binding: Value,
    taint: Option<Value>,
    supersedes: Value,
) -> Map<String, Value> {
    Map::from_iter([
        ("role".to_string(), role),
        ("binding".to_string(), binding),
        ("taint".to_string(), json!(taint)),
        ("supersedes".to_string(), supersedes),
    ])
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn resolved_policy_to_json(
    definition: &PolicyDefinition,
    analysis: ResolvedPolicyAnalysisRef<'_>,
    selectors: &[ResolvedPolicySelector],
    catalogs: &[ResolvedCatalogIdentity],
    endpoints: &[ResolvedEndpointDependency],
    match_manifests: &[ResolvedMatchDirectoryManifest],
    endpoint_set_dependencies: &[ResolvedEndpointSetDependency],
    precedence: &PolicyPrecedenceManifest,
) -> Result<Value, LoadedModelError> {
    let mut value = RqlpDocument::Policy {
        definition: Box::new(definition.clone()),
    }
    .to_normalized_authored_json();
    let object = value.as_object_mut().ok_or_else(|| {
        LoadedModelError::CanonicalProjection("policy projection is not an object".to_string())
    })?;
    let analysis_value = match (&definition.analysis, analysis) {
        (PolicyAnalysis::Match { .. }, ResolvedPolicyAnalysisRef::Match) => {
            let selector = selector_at(selectors, "/analysis/selector")?;
            json!({
                "type": "match",
                "selector": resolved_selector_to_json(selector),
            })
        }
        (PolicyAnalysis::Taint { .. }, ResolvedPolicyAnalysisRef::Taint { spec }) => {
            resolved_taint_to_json(spec, selectors)?
        }
        (PolicyAnalysis::Flow { .. }, ResolvedPolicyAnalysisRef::Taint { spec }) => {
            // Flow resolves into the same taint-shaped model, so the resolved
            // projection is the same function. Only the discriminator moves,
            // which is what domain-separates a flow policy's semantic hash
            // from a taint policy with an identical resolved model.
            let mut value = resolved_taint_to_json(spec, selectors)?;
            value
                .as_object_mut()
                .expect("the resolved taint-shaped projection is an object")
                .insert("type".to_string(), json!("flow"));
            value
        }
        (PolicyAnalysis::Assertion { spec }, ResolvedPolicyAnalysisRef::Assertion) => {
            let mut value = super::canonical::policy_analysis_authored_json(&definition.analysis);
            if let Some(plan) = &spec.relational {
                let bindings = value
                    .get_mut("plan")
                    .and_then(|value| value.get_mut("bindings"))
                    .and_then(Value::as_array_mut)
                    .expect("the relational assertion projection has bindings");
                for (binding, projected) in plan.bindings.iter().zip(bindings) {
                    let RowBindingSource::Query(authored) = &binding.source;
                    let path = relational_binding_selector_path(&binding.name);
                    // A deferred declaration-selection import has no resolved
                    // query yet; its authored reference is the identity.
                    if matches!(authored, PolicySelector::DeclarationSelection(_))
                        && !selectors
                            .iter()
                            .any(|selector| selector.path.as_str() == path)
                    {
                        continue;
                    }
                    let selector = selector_at(selectors, &path)?;
                    projected
                        .as_object_mut()
                        .expect("a relational binding projection is an object")
                        .insert("query".to_string(), resolved_selector_to_json(selector));
                }
            } else {
                let selector = selector_at(selectors, ASSERTION_SUBJECT_SELECTOR_PATH)?;
                value
                    .as_object_mut()
                    .expect("the assertion analysis projection is an object")
                    .insert("subject".to_string(), resolved_selector_to_json(selector));
            }
            value
        }
        (PolicyAnalysis::Typestate { .. }, ResolvedPolicyAnalysisRef::Typestate { spec }) => {
            let mut value = resolved_typestate_to_json(spec)?;
            value
                .as_object_mut()
                .expect("typestate canonical projection is an object")
                .insert(
                    "authoring_projection_hash".to_string(),
                    json!(spec.authoring_projection_hash.to_string()),
                );
            value
        }
        _ => return Err(LoadedModelError::ResolvedAnalysisMismatch),
    };
    object.insert("analysis".to_string(), analysis_value);

    if let Some(classification) = object.get_mut("classification") {
        resolve_classification_endpoint_refs(
            classification,
            &definition.metadata.id,
            catalogs,
            endpoints,
        )?;
    }

    object.insert(
        "resolved_selectors".to_string(),
        Value::Array(sorted_selectors(selectors)),
    );
    object.insert(
        "resolved_catalogs".to_string(),
        Value::Array(sorted_catalogs(catalogs)),
    );
    object.insert(
        "resolved_endpoints".to_string(),
        Value::Array(sorted_dependencies(endpoints)),
    );
    object.insert(
        "match_manifests".to_string(),
        Value::Array(sorted_manifests(match_manifests)?),
    );
    // Endpoint-set source paths are provenance only. The sorted content hashes
    // make imported meaning part of policy identity while keeping equivalent
    // source layouts and workspace locations semantically interchangeable.
    let endpoint_set_hashes = sorted_endpoint_set_hashes(endpoint_set_dependencies);
    if !endpoint_set_hashes.is_empty() {
        object.insert(
            "endpoint_set_dependencies".to_string(),
            Value::Array(endpoint_set_hashes),
        );
    }
    object.insert("precedence".to_string(), precedence_to_json(precedence));
    let mut locator_resolutions = super::locator::resolved_locator_metadata(definition)
        .into_iter()
        .map(super::canonical::resolved_locator_to_json)
        .collect::<Vec<_>>();
    locator_resolutions.extend(
        selectors
            .iter()
            // Inline selectors owned by this policy are already present in
            // `definition`. Referenced files and composed dependencies are
            // not, so their sidecars must be added from the resolved closure.
            .filter(|selector| {
                matches!(
                    selector.origin,
                    SelectorOrigin::ReferencedFile { .. } | SelectorOrigin::Catalog { .. }
                ) || selector
                    .path
                    .as_str()
                    .starts_with("/dependencies/match-endpoints/")
            })
            .flat_map(|selector| &selector.resolved_locators)
            .map(super::canonical::resolved_locator_to_json),
    );
    if !locator_resolutions.is_empty() {
        object.insert(
            "resolved_locators".to_string(),
            Value::Array(locator_resolutions),
        );
    }
    Ok(value)
}

pub(crate) fn loaded_policy_to_json(policy: &LoadedPolicy) -> Result<Value, LoadedModelError> {
    let analysis = match policy.definition().analysis {
        PolicyAnalysis::Match { .. } => ResolvedPolicyAnalysisRef::Match,
        PolicyAnalysis::Taint { .. } | PolicyAnalysis::Flow { .. } => {
            ResolvedPolicyAnalysisRef::Taint {
                spec: policy
                    .resolved_taint()
                    .ok_or(LoadedModelError::ResolvedAnalysisMismatch)?,
            }
        }
        PolicyAnalysis::Typestate { .. } => ResolvedPolicyAnalysisRef::Typestate {
            spec: policy
                .resolved_typestate()
                .ok_or(LoadedModelError::ResolvedAnalysisMismatch)?,
        },
        PolicyAnalysis::Assertion { .. } => ResolvedPolicyAnalysisRef::Assertion,
    };
    resolved_policy_to_json(
        policy.definition(),
        analysis,
        policy.resolved_selectors(),
        policy.catalogs(),
        policy.endpoint_dependencies(),
        policy.match_directory_manifests(),
        policy.endpoint_set_dependencies(),
        policy.precedence_manifest(),
    )
}

pub(crate) fn resolved_typestate_to_json(
    spec: &ResolvedTypestatePolicySpec,
) -> Result<Value, LoadedModelError> {
    let mut subjects = spec.subjects.iter().collect::<Vec<_>>();
    subjects.sort_by(|left, right| left.identity.cmp(&right.identity));
    let mut dependencies = spec.endpoint_dependencies.iter().collect::<Vec<_>>();
    dependencies.sort_by(|left, right| left.identity.cmp(&right.identity));
    Ok(json!({
        "type": "typestate",
        "mode": spec.mode.label(),
        "call_modeling": {
            "unmodeled": spec.call_modeling.unmodeled.label(),
        },
        "subjects": subjects
            .into_iter()
            .map(resolved_typestate_subject_to_json)
            .collect::<Vec<_>>(),
        "uncertainty": {
            "escape": spec.uncertainty.escape.label(),
        },
        "automaton": resolved_typestate_automaton_to_json(&spec.automaton),
        "endpoint_dependencies": dependencies
            .into_iter()
            .map(resolved_endpoint_dependency_to_json)
            .collect::<Vec<_>>(),
        "match_manifests": sorted_manifests(&spec.match_manifests)?,
    }))
}

pub(crate) fn match_set_semantic_to_json(
    scope: DirectoryScope,
    role: Option<EndpointRole>,
    categories: &CategoryPredicate,
    selected: &[ResolvedEndpointManifestEntry],
) -> Value {
    match_set_projection_to_json(
        scope,
        role,
        categories,
        selected,
        resolved_manifest_entry_to_json,
    )
}

/// Canonical public hash projection for one selected match set.
///
/// The richer manifest entries retain schema and analysis-projection details
/// for provenance and integrity checks. The public manifest hash deliberately
/// covers only the selection predicate plus each selected endpoint's stable
/// identity and full semantic hash, as frozen by the schema-version-1
/// contract.
pub(crate) fn match_set_hash_projection_to_json(
    scope: DirectoryScope,
    role: Option<EndpointRole>,
    categories: &CategoryPredicate,
    selected: &[ResolvedEndpointManifestEntry],
) -> Value {
    match_set_projection_to_json(scope, role, categories, selected, |entry| {
        json!({
            "identity": resolved_endpoint_identity_to_json(&entry.identity),
            "semantic_hash": entry.semantic_hash.to_string(),
        })
    })
}

fn match_set_projection_to_json(
    scope: DirectoryScope,
    role: Option<EndpointRole>,
    categories: &CategoryPredicate,
    selected: &[ResolvedEndpointManifestEntry],
    encode: impl Fn(&ResolvedEndpointManifestEntry) -> Value,
) -> Value {
    let mut selected = selected.iter().collect::<Vec<_>>();
    selected.sort_by(|left, right| left.identity.cmp(&right.identity));
    json!({
        "scope": scope.label(),
        "role": role.map(EndpointRole::label),
        "categories": super::canonical::category_predicate_to_json(categories),
        "selected": selected.into_iter().map(encode).collect::<Vec<_>>(),
    })
}

fn resolved_taint_to_json(
    spec: &ResolvedTaintPolicySpec,
    selectors: &[ResolvedPolicySelector],
) -> Result<Value, LoadedModelError> {
    let mut sources = spec.sources.iter().collect::<Vec<_>>();
    sources.sort_by(|left, right| left.identity.cmp(&right.identity));
    let mut sinks = spec.sinks.iter().collect::<Vec<_>>();
    sinks.sort_by(|left, right| left.identity.cmp(&right.identity));
    let mut sanitizers = spec.sanitizers.iter().collect::<Vec<_>>();
    sanitizers.sort_by(|left, right| left.identity.cmp(&right.identity));
    let mut entry_points = spec.entry_points.iter().collect::<Vec<_>>();
    entry_points.sort_by(|left, right| left.identity.cmp(&right.identity));
    let mut transforms = spec.transforms.iter().collect::<Vec<_>>();
    transforms.sort_by(|left, right| left.identity.cmp(&right.identity));
    let mut external_models = spec.external_models.iter().collect::<Vec<_>>();
    external_models.sort_by(|left, right| left.identity.cmp(&right.identity));
    let mut store_writes = spec.store_writes.iter().collect::<Vec<_>>();
    store_writes.sort_by(|left, right| left.identity.cmp(&right.identity));
    let mut store_reads = spec.store_reads.iter().collect::<Vec<_>>();
    store_reads.sort_by(|left, right| left.identity.cmp(&right.identity));
    let mut combinations = spec.finding_combinations.iter().collect::<Vec<_>>();
    combinations.sort_by(|left, right| left.id.cmp(&right.id));

    let mut value = json!({
        "type": "taint",
        "mode": spec.mode.label(),
        "call_modeling": {
            "unmodeled": spec.call_modeling.unmodeled.label(),
        },
        "threat_models": spec
            .threat_models
            .iter()
            .map(|model| model.label())
            .collect::<Vec<_>>(),
        "sources": sources
            .into_iter()
            .map(|endpoint| resolved_taint_source_to_json(endpoint, selectors))
            .collect::<Result<Vec<_>, _>>()?,
        "sinks": sinks
            .into_iter()
            .map(|endpoint| resolved_taint_sink_to_json(endpoint, selectors))
            .collect::<Result<Vec<_>, _>>()?,
        "sanitizers": sanitizers
            .into_iter()
            .map(|entry| taint_sanitizer_to_json(entry, selectors))
            .collect::<Result<Vec<_>, _>>()?,
        "entry_points": entry_points
            .into_iter()
            .map(|endpoint| resolved_taint_source_to_json(endpoint, selectors))
            .collect::<Result<Vec<_>, _>>()?,
        "transforms": transforms
            .into_iter()
            .map(|entry| taint_transform_to_json(entry, selectors))
            .collect::<Result<Vec<_>, _>>()?,
        "external_models": external_models
            .into_iter()
            .map(|entry| taint_external_model_to_json(entry, selectors))
            .collect::<Result<Vec<_>, _>>()?,
        "catalogs": sorted_catalogs(&spec.catalogs),
        "match_manifests": sorted_manifests(&spec.match_manifests)?,
        "finding_combinations": combinations
            .into_iter()
            .map(resolved_finding_combination_to_json)
            .collect::<Vec<_>>(),
    });
    if !spec.barriers.is_empty() {
        let mut barriers = spec.barriers.iter().collect::<Vec<_>>();
        barriers.sort_by(|left, right| left.id.cmp(&right.id));
        value.as_object_mut().expect("taint projection is an object").insert("barriers".into(),
            Value::Array(barriers.into_iter().map(|entry| json!({
                "id": entry.id.as_str(),
                "value_type": crate::canonical::value_type_predicate_to_json(entry.value_type),
            })).collect()));
    }
    // `stores` is omitted entirely when the policy declares none, which keeps
    // every loaded projection authored before persistence stores existed
    // byte-identical, and therefore keeps its hashes valid.
    if !(store_writes.is_empty() && store_reads.is_empty()) {
        let stores = json!({
            "writes": store_writes
                .into_iter()
                .map(|entry| taint_store_write_to_json(entry, selectors))
                .collect::<Result<Vec<_>, _>>()?,
            "reads": store_reads
                .into_iter()
                .map(|entry| taint_store_read_to_json(entry, selectors))
                .collect::<Result<Vec<_>, _>>()?,
        });
        value
            .as_object_mut()
            .expect("the resolved taint projection is an object")
            .insert("stores".to_string(), stores);
    }
    Ok(value)
}

fn taint_store_write_to_json(
    entry: &ResolvedTaintAuxiliary<ResolvedTaintStoreWriteDefinition>,
    selectors: &[ResolvedPolicySelector],
) -> Result<Value, LoadedModelError> {
    let selector = selector_by_path(selectors, &entry.selector_path)?;
    let definition = &entry.definition;
    let mut definition_fields = resolved_taint_store_common_fields_to_json(
        selector,
        definition.store.as_str(),
        definition.key.as_ref(),
        definition.instance.as_ref(),
    );
    definition_fields.insert("input".to_string(), policy_port_to_json(&definition.input));
    Ok(json!({
        "identity": resolved_endpoint_identity_to_json(&entry.identity),
        "definition": Value::Object(definition_fields),
    }))
}

fn taint_store_read_to_json(
    entry: &ResolvedTaintAuxiliary<ResolvedTaintStoreReadDefinition>,
    selectors: &[ResolvedPolicySelector],
) -> Result<Value, LoadedModelError> {
    let selector = selector_by_path(selectors, &entry.selector_path)?;
    let definition = &entry.definition;
    let mut definition_fields = resolved_taint_store_common_fields_to_json(
        selector,
        definition.store.as_str(),
        definition.key.as_ref(),
        definition.instance.as_ref(),
    );
    definition_fields.insert(
        "output".to_string(),
        policy_port_to_json(&definition.output),
    );
    Ok(json!({
        "identity": resolved_endpoint_identity_to_json(&entry.identity),
        "definition": Value::Object(definition_fields),
    }))
}

fn resolved_taint_store_common_fields_to_json(
    selector: &ResolvedPolicySelector,
    store: &str,
    key: Option<&PolicyPort>,
    instance: Option<&PolicyPort>,
) -> Map<String, Value> {
    Map::from_iter([
        ("selector".to_string(), resolved_selector_to_json(selector)),
        ("store".to_string(), json!(store)),
        ("key".to_string(), json!(key.map(policy_port_to_json))),
        (
            "instance".to_string(),
            json!(instance.map(policy_port_to_json)),
        ),
    ])
}

fn resolved_taint_source_to_json(
    endpoint: &ResolvedTaintEndpoint<ResolvedTaintSourceDefinition>,
    selectors: &[ResolvedPolicySelector],
) -> Result<Value, LoadedModelError> {
    let definition = &endpoint.definition;
    let selector = selector_by_path(selectors, &definition.selector_path)?;
    Ok(resolved_taint_endpoint_to_json(
        &endpoint.identity,
        endpoint.semantic_hash.to_string(),
        endpoint.analysis_projection_hash.to_string(),
        json!({
            "display_name": definition.display_name,
            "categories": sorted_ids(&definition.categories),
            "selector": resolved_selector_to_json(selector),
            "bind": policy_port_to_json(&definition.bind),
            "labels": sorted_ids(&definition.labels),
            "threat_model": definition.threat_model.map(|model| model.label()),
            "evidence": definition.evidence.as_ref().map(taint_source_evidence_to_json),
        }),
    ))
}

fn resolved_taint_sink_to_json(
    endpoint: &ResolvedTaintEndpoint<ResolvedTaintSinkDefinition>,
    selectors: &[ResolvedPolicySelector],
) -> Result<Value, LoadedModelError> {
    let definition = &endpoint.definition;
    let selector = selector_by_path(selectors, &definition.selector_path)?;
    Ok(resolved_taint_endpoint_to_json(
        &endpoint.identity,
        endpoint.semantic_hash.to_string(),
        endpoint.analysis_projection_hash.to_string(),
        json!({
            "display_name": definition.display_name,
            "categories": sorted_ids(&definition.categories),
            "selector": resolved_selector_to_json(selector),
            "dangerous_operand": policy_port_to_json(&definition.dangerous_operand),
            "accepts": sorted_ids(&definition.accepts),
            "tags": sorted_ids(&definition.tags),
            "impacts": sorted_ids(&definition.impacts),
        }),
    ))
}

fn resolved_taint_endpoint_to_json(
    identity: &ResolvedEndpointIdentity,
    semantic_hash: String,
    analysis_projection_hash: String,
    definition: Value,
) -> Value {
    json!({
        "identity": resolved_endpoint_identity_to_json(identity),
        "semantic_hash": semantic_hash,
        "analysis_projection_hash": analysis_projection_hash,
        "definition": definition,
    })
}

fn taint_sanitizer_to_json(
    entry: &ResolvedTaintAuxiliary<ResolvedTaintSanitizerDefinition>,
    selectors: &[ResolvedPolicySelector],
) -> Result<Value, LoadedModelError> {
    let selector = selector_by_path(selectors, &entry.selector_path)?;
    let definition = &entry.definition;
    let mut definition_fields = taint_port_fields_to_json(
        resolved_selector_to_json(selector),
        policy_port_to_json(&definition.input),
        policy_port_to_json(&definition.output),
    );
    definition_fields.insert(
        "removes".to_string(),
        json!(sorted_ids(&definition.removes)),
    );
    Ok(json!({
        "identity": resolved_endpoint_identity_to_json(&entry.identity),
        "definition": Value::Object(definition_fields),
    }))
}

fn taint_transform_to_json(
    entry: &ResolvedTaintAuxiliary<ResolvedTaintTransformDefinition>,
    selectors: &[ResolvedPolicySelector],
) -> Result<Value, LoadedModelError> {
    let selector = selector_by_path(selectors, &entry.selector_path)?;
    let definition = &entry.definition;
    let mut definition_fields = taint_port_fields_to_json(
        resolved_selector_to_json(selector),
        policy_port_to_json(&definition.input),
        policy_port_to_json(&definition.output),
    );
    definition_fields.insert(
        "removes".to_string(),
        json!(sorted_ids(&definition.removes)),
    );
    definition_fields.insert("adds".to_string(), json!(sorted_ids(&definition.adds)));
    Ok(json!({
        "identity": resolved_endpoint_identity_to_json(&entry.identity),
        "definition": Value::Object(definition_fields),
    }))
}

fn taint_external_model_to_json(
    entry: &ResolvedTaintAuxiliary<ResolvedTaintExternalModelDefinition>,
    selectors: &[ResolvedPolicySelector],
) -> Result<Value, LoadedModelError> {
    let selector = selector_by_path(selectors, &entry.selector_path)?;
    let mut transfers = entry
        .definition
        .transfers
        .iter()
        .map(taint_transfer_to_json)
        .collect::<Vec<_>>();
    transfers.sort_by_key(canonical_sort_key);
    Ok(json!({
        "identity": resolved_endpoint_identity_to_json(&entry.identity),
        "definition": {
            "selector": resolved_selector_to_json(selector),
            "transfers": transfers,
        },
    }))
}

fn resolved_finding_combination_to_json(combination: &ResolvedFindingCombination) -> Value {
    json!({
        "id": combination.id.as_str(),
        "source_endpoints": sorted_endpoint_identities(&combination.source_endpoints),
        "sink_endpoints": sorted_endpoint_identities(&combination.sink_endpoints),
        "message": combination.message,
        "severity": combination.severity.as_ref().map(policy_severity_to_json),
        "add_classifications": sorted_classifications(&combination.add_classifications),
        "supersedes": sorted_ids(&combination.supersedes),
    })
}

fn resolved_typestate_subject_to_json(subject: &ResolvedTypestateSubject) -> Value {
    json!({
        "identity": resolved_endpoint_identity_to_json(&subject.identity),
        "selector_path": subject.selector_path.as_str(),
        "binding": resolved_typestate_binding_to_json(&subject.binding),
        "semantic_hash": subject.semantic_hash.to_string(),
        "analysis_projection_hash": subject.analysis_projection_hash.to_string(),
    })
}

fn resolved_typestate_automaton_to_json(automaton: &ResolvedTypestateAutomatonSpec) -> Value {
    let mut events = automaton.events.iter().collect::<Vec<_>>();
    events.sort_by(|left, right| left.id.cmp(&right.id));
    let mut transitions = automaton.transitions.iter().collect::<Vec<_>>();
    transitions.sort_by(|left, right| {
        (&left.from, &left.on, &left.to).cmp(&(&right.from, &right.on, &right.to))
    });
    let mut expectations = automaton.terminal_expectations.iter().collect::<Vec<_>>();
    expectations.sort_by(|left, right| left.id.cmp(&right.id));
    typestate_automaton_projection_to_json(
        json!(sorted_ids(&automaton.states)),
        automaton.initial.as_str(),
        json!(sorted_ids(&automaton.accepting_states)),
        json!(sorted_ids(&automaton.error_states)),
        Value::Array(
            events
                .into_iter()
                .map(resolved_typestate_event_to_json)
                .collect(),
        ),
        Value::Array(
            transitions
                .into_iter()
                .map(|transition| {
                    json!({
                        "from": transition.from.as_str(),
                        "on": transition.on.as_str(),
                        "to": transition.to.as_str(),
                    })
                })
                .collect(),
        ),
        Value::Array(
            expectations
                .into_iter()
                .map(resolved_typestate_expectation_to_json)
                .collect(),
        ),
    )
}

fn resolved_typestate_event_to_json(event: &ResolvedTypestateEventSpec) -> Value {
    resolved_typestate_entry_to_json(
        event.id.as_str(),
        resolved_typestate_event_trigger_to_json(&event.trigger),
        &event.applies_to_subjects,
        &event.supersedes,
    )
}

fn resolved_typestate_event_trigger_to_json(trigger: &ResolvedTypestateEventTrigger) -> Value {
    match trigger {
        ResolvedTypestateEventTrigger::Calls {
            selector_path,
            subject,
            phase,
            argument_condition,
        } => {
            let mut object = Map::from_iter([
                ("type".to_string(), Value::String("calls".to_string())),
                (
                    "selector_path".to_string(),
                    Value::String(selector_path.as_str().to_string()),
                ),
                (
                    "subject".to_string(),
                    typestate_call_binding_to_json(subject),
                ),
                (
                    "phase".to_string(),
                    Value::String(observation_phase_label(*phase).to_string()),
                ),
            ]);
            if let Some(condition) = argument_condition {
                object.insert(
                    "condition".to_string(),
                    json!({
                        "argument_index": condition.index,
                        "equals": condition.equals,
                    }),
                );
            }
            Value::Object(object)
        }
        ResolvedTypestateEventTrigger::MatchEndpoints { endpoints, phase } => {
            resolved_match_endpoint_trigger_to_json(endpoints, *phase)
        }
        ResolvedTypestateEventTrigger::SemanticEvent { event } => json!({
            "type": "semantic_event",
            "event": policy_semantic_event_to_json(*event),
        }),
    }
}

fn resolved_typestate_expectation_to_json(
    expectation: &ResolvedTypestateTerminalExpectationSpec,
) -> Value {
    let mut value = resolved_typestate_entry_to_json(
        expectation.id.as_str(),
        resolved_typestate_terminal_trigger_to_json(&expectation.trigger),
        &expectation.applies_to_subjects,
        &expectation.supersedes,
    );
    value
        .as_object_mut()
        .expect("resolved typestate entry projection is an object")
        .insert(
            "expected_states".to_string(),
            json!(sorted_ids(&expectation.expected_states)),
        );
    value
}

fn resolved_typestate_entry_to_json<T: AsRef<str>>(
    id: &str,
    trigger: Value,
    applies_to_subjects: &[ResolvedEndpointIdentity],
    supersedes: &[T],
) -> Value {
    json!({
        "id": id,
        "trigger": trigger,
        "applies_to_subjects": sorted_endpoint_identities(applies_to_subjects),
        "supersedes": sorted_ids(supersedes),
    })
}

fn resolved_match_endpoint_trigger_to_json(
    endpoints: &[ResolvedEndpointIdentity],
    phase: EndpointObservationPhase,
) -> Value {
    json!({
        "type": "match_endpoints",
        "endpoints": sorted_endpoint_identities(endpoints),
        "phase": observation_phase_label(phase),
    })
}

fn resolved_typestate_terminal_trigger_to_json(
    trigger: &ResolvedTypestateTerminalTrigger,
) -> Value {
    match trigger {
        ResolvedTypestateTerminalTrigger::MatchEndpoints { endpoints, phase } => {
            resolved_match_endpoint_trigger_to_json(endpoints, *phase)
        }
        ResolvedTypestateTerminalTrigger::SemanticEvent { event } => json!({
            "type": "semantic_event",
            "event": policy_semantic_event_to_json(*event),
        }),
    }
}

fn sorted_selectors(selectors: &[ResolvedPolicySelector]) -> Vec<Value> {
    let mut selectors = selectors.iter().collect::<Vec<_>>();
    selectors.sort_by(|left, right| left.path.cmp(&right.path));
    selectors
        .into_iter()
        .map(|selector| {
            json!({
                "path": selector.path.as_str(),
                "selector": resolved_selector_to_json(selector),
                "semantic_hash": selector.semantic_hash.to_string(),
            })
        })
        .collect()
}

fn sorted_catalogs(catalogs: &[ResolvedCatalogIdentity]) -> Vec<Value> {
    let mut catalogs = catalogs.iter().collect::<Vec<_>>();
    catalogs.sort();
    catalogs
        .into_iter()
        .map(resolved_catalog_identity_to_json)
        .collect()
}

fn sorted_dependencies(endpoints: &[ResolvedEndpointDependency]) -> Vec<Value> {
    sorted_by_endpoint_identity(
        endpoints,
        |dependency| &dependency.identity,
        resolved_endpoint_dependency_to_json,
    )
}

fn sorted_manifests(
    manifests: &[ResolvedMatchDirectoryManifest],
) -> Result<Vec<Value>, LoadedModelError> {
    let mut manifests = manifests
        .iter()
        .map(|manifest| (manifest.semantic_hash, resolved_manifest_to_json(manifest)))
        .collect::<Vec<_>>();
    manifests.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| canonical_sort_key(&left.1).cmp(&canonical_sort_key(&right.1)))
    });
    for pair in manifests.windows(2) {
        if pair[0].0 == pair[1].0 && pair[0].1 != pair[1].1 {
            return Err(LoadedModelError::CanonicalProjection(
                "match-directory semantic-hash collision".to_string(),
            ));
        }
    }
    manifests.dedup_by(|left, right| left.0 == right.0);
    Ok(manifests.into_iter().map(|(_, value)| value).collect())
}

fn sorted_endpoint_set_hashes(dependencies: &[ResolvedEndpointSetDependency]) -> Vec<Value> {
    let mut hashes = dependencies
        .iter()
        .map(|dependency| dependency.semantic_hash)
        .collect::<Vec<_>>();
    hashes.sort();
    hashes.dedup();
    hashes
        .into_iter()
        .map(|hash| Value::String(hash.to_string()))
        .collect()
}

pub(crate) fn resolved_selector_to_json(selector: &ResolvedPolicySelector) -> Value {
    match &selector.kind {
        ResolvedPolicySelectorKind::Query {
            schema_resolution,
            query,
        } => json!({
            "schema_version": schema_resolution.version,
            "query": query.to_canonical_query_plan_json(),
        }),
    }
}

fn resolved_catalog_identity_to_json(catalog: &ResolvedCatalogIdentity) -> Value {
    json!({
        "name": catalog.name.as_str(),
        "version": catalog.version,
        "semantic_hash": catalog.semantic_hash.to_string(),
    })
}

fn resolved_endpoint_dependency_to_json(dependency: &ResolvedEndpointDependency) -> Value {
    let mut value = resolved_endpoint_manifest_fields_to_json(
        &dependency.identity,
        dependency.definition_schema.version(),
        dependency.semantic_hash.to_string(),
        dependency.analysis_projection_hash.to_string(),
        &dependency.selector_schemas,
    );
    value
        .as_object_mut()
        .expect("resolved endpoint projection is an object")
        .insert(
            "model".to_string(),
            resolved_endpoint_model_to_json(&dependency.model),
        );
    value
}

fn resolved_endpoint_model_to_json(model: &ResolvedEndpointModel) -> Value {
    let mut fields = endpoint_model_analysis_fields_to_json(
        json!((model.role).label()),
        endpoint_binding_to_json(&model.binding),
        model.taint.as_ref().map(endpoint_taint_to_json),
        json!(sorted_endpoint_identities(&model.supersedes)),
    );
    fields.insert("display_name".to_string(), json!(model.display_name));
    fields.insert(
        "categories".to_string(),
        json!(sorted_ids(&model.categories)),
    );
    Value::Object(fields)
}

fn resolved_manifest_to_json(manifest: &ResolvedMatchDirectoryManifest) -> Value {
    let mut value = match_set_semantic_to_json(
        manifest.scope,
        manifest.role,
        &manifest.categories,
        &manifest.selected,
    );
    value
        .as_object_mut()
        .expect("match-set projection is an object")
        .insert(
            "semantic_hash".to_string(),
            json!(manifest.semantic_hash.to_string()),
        );
    value
}

fn resolved_manifest_entry_to_json(entry: &ResolvedEndpointManifestEntry) -> Value {
    resolved_endpoint_manifest_fields_to_json(
        &entry.identity,
        entry.definition_schema.version(),
        entry.semantic_hash.to_string(),
        entry.analysis_projection_hash.to_string(),
        &entry.selector_schemas,
    )
}

fn resolved_endpoint_manifest_fields_to_json(
    identity: &ResolvedEndpointIdentity,
    definition_schema_version: u32,
    semantic_hash: String,
    analysis_projection_hash: String,
    selector_schemas: &ResolvedEndpointSelectorSchemas,
) -> Value {
    let mut value = json!({
        "identity": resolved_endpoint_identity_to_json(identity),
        "definition_schema_version": definition_schema_version,
        "semantic_hash": semantic_hash,
        "analysis_projection_hash": analysis_projection_hash,
    });
    insert_selector_schemas(&mut value, selector_schemas);
    value
}

fn insert_selector_schemas(value: &mut Value, schemas: &ResolvedEndpointSelectorSchemas) {
    let object = value
        .as_object_mut()
        .expect("resolved endpoint projection is an object");
    match schemas {
        ResolvedEndpointSelectorSchemas::Query(resolution) => {
            object.insert(
                "selector_schema_version".to_owned(),
                json!(resolution.version),
            );
        }
    }
}

fn precedence_to_json(precedence: &PolicyPrecedenceManifest) -> Value {
    let mut edges = precedence.edges.iter().collect::<Vec<_>>();
    edges.sort();
    Value::Array(
        edges
            .into_iter()
            .map(|edge| match edge {
                ResolvedPrecedenceEdge::Endpoint {
                    dominant,
                    dominated,
                } => json!({
                    "type": "endpoint",
                    "dominant": resolved_endpoint_identity_to_json(dominant),
                    "dominated": resolved_endpoint_identity_to_json(dominated),
                }),
                ResolvedPrecedenceEdge::FindingCombination {
                    dominant,
                    dominated,
                } => json!({
                    "type": "finding_combination",
                    "dominant": dominant.as_str(),
                    "dominated": dominated.as_str(),
                }),
                ResolvedPrecedenceEdge::TypestateEvent {
                    dominant,
                    dominated,
                } => json!({
                    "type": "typestate_event",
                    "dominant": dominant.as_str(),
                    "dominated": dominated.as_str(),
                }),
                ResolvedPrecedenceEdge::TypestateExpectation {
                    dominant,
                    dominated,
                } => json!({
                    "type": "typestate_expectation",
                    "dominant": dominant.as_str(),
                    "dominated": dominated.as_str(),
                }),
            })
            .collect(),
    )
}

fn resolved_endpoint_identity_to_json(identity: &ResolvedEndpointIdentity) -> Value {
    match identity {
        ResolvedEndpointIdentity::Local {
            policy_id,
            entry_id,
        } => json!({
            "type": "local",
            "policy_id": policy_id.as_str(),
            "entry_id": entry_id.as_str(),
        }),
        ResolvedEndpointIdentity::Catalog { catalog, entry_id } => json!({
            "type": "catalog",
            "catalog": resolved_catalog_identity_to_json(catalog),
            "entry_id": entry_id.as_str(),
        }),
        ResolvedEndpointIdentity::MatchEndpoint { endpoint_id } => json!({
            "type": "match_endpoint",
            "endpoint_id": endpoint_id.as_str(),
        }),
    }
}

fn sorted_endpoint_identities(identities: &[ResolvedEndpointIdentity]) -> Vec<Value> {
    sorted_by_endpoint_identity(
        identities,
        |identity| identity,
        resolved_endpoint_identity_to_json,
    )
}

fn sorted_by_endpoint_identity<'a, T>(
    values: &'a [T],
    identity: impl Fn(&'a T) -> &'a ResolvedEndpointIdentity,
    encode: impl Fn(&'a T) -> Value,
) -> Vec<Value> {
    let mut values = values.iter().collect::<Vec<_>>();
    values.sort_by(|left, right| identity(*left).cmp(identity(*right)));
    values.into_iter().map(encode).collect()
}

fn endpoint_taint_to_json(taint: &EndpointTaintSemantics) -> Value {
    match taint {
        EndpointTaintSemantics::Source {
            labels, evidence, ..
        } => json!({
            "type": "source",
            "labels": sorted_ids(labels),
            "evidence": evidence.as_ref().map(taint_source_evidence_to_json),
        }),
        EndpointTaintSemantics::Sink {
            accepts,
            tags,
            impacts,
        } => json!({
            "type": "sink",
            "accepts": sorted_ids(accepts),
            "tags": sorted_ids(tags),
            "impacts": sorted_ids(impacts),
        }),
    }
}

fn resolved_typestate_binding_to_json(binding: &ResolvedTypestateBinding) -> Value {
    match binding {
        ResolvedTypestateBinding::MatchedValue => binding_tag_to_json("matched_value"),
        ResolvedTypestateBinding::Receiver => binding_tag_to_json("receiver"),
        ResolvedTypestateBinding::ReturnValue => binding_tag_to_json("return_value"),
        ResolvedTypestateBinding::ResultIndex { index } => {
            binding_index_to_json("result_index", *index)
        }
        ResolvedTypestateBinding::ArgumentIndex { index } => {
            binding_index_to_json("argument_index", *index)
        }
        ResolvedTypestateBinding::ArgumentName { name } => {
            binding_name_to_json("argument_name", name)
        }
    }
}

fn taint_source_evidence_to_json(evidence: &TaintSourceEvidence) -> Value {
    json!({
        "trust_boundary": evidence.trust_boundary.map(TaintTrustBoundary::label),
        "system_entry": evidence.system_entry.map(TaintSystemEntry::label),
    })
}

fn sorted_classifications(classifications: &[TaxonomyClassificationSpec]) -> Vec<Value> {
    let mut classifications = classifications.iter().collect::<Vec<_>>();
    classifications.sort_by(|left, right| {
        (&left.taxonomy, &left.identifier, &left.name).cmp(&(
            &right.taxonomy,
            &right.identifier,
            &right.name,
        ))
    });
    classifications
        .into_iter()
        .map(|classification| {
            json!({
                "taxonomy": classification.taxonomy,
                "id": classification.identifier,
                "name": classification.name,
            })
        })
        .collect()
}

fn resolve_classification_endpoint_refs(
    value: &mut Value,
    policy_id: &PolicyId,
    catalogs: &[ResolvedCatalogIdentity],
    endpoints: &[ResolvedEndpointDependency],
) -> Result<(), LoadedModelError> {
    let selected: HashSet<_> = endpoints
        .iter()
        .map(|dependency| dependency.identity.clone())
        .collect();
    let mut stack = vec![value];
    while let Some(value) = stack.pop() {
        match value {
            Value::Object(object) => {
                if object.get("type").and_then(Value::as_str) == Some("endpoint") {
                    let endpoint = object.get("endpoint").ok_or_else(|| {
                        LoadedModelError::CanonicalProjection(
                            "endpoint evidence reference has no endpoint".to_string(),
                        )
                    })?;
                    let identity = resolve_authored_endpoint_json(policy_id, catalogs, endpoint)?;
                    if !selected.contains(&identity) {
                        return Err(LoadedModelError::CanonicalProjection(format!(
                            "classification references endpoint not selected by the loaded policy: {}",
                            canonical_sort_key(&resolved_endpoint_identity_to_json(&identity))
                        )));
                    }
                    object.insert(
                        "endpoint".to_string(),
                        resolved_endpoint_identity_to_json(&identity),
                    );
                    continue;
                }
                stack.extend(object.values_mut());
            }
            Value::Array(values) => stack.extend(values),
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    Ok(())
}

fn resolve_authored_endpoint_json(
    policy_id: &PolicyId,
    catalogs: &[ResolvedCatalogIdentity],
    endpoint: &Value,
) -> Result<ResolvedEndpointIdentity, LoadedModelError> {
    let object = endpoint.as_object().ok_or_else(|| {
        LoadedModelError::CanonicalProjection("endpoint reference is not an object".to_string())
    })?;
    match object.get("type").and_then(Value::as_str) {
        Some("local") => Ok(ResolvedEndpointIdentity::Local {
            policy_id: policy_id.clone(),
            entry_id: parse_id(object, "entry_id")?,
        }),
        Some("match_endpoint") => Ok(ResolvedEndpointIdentity::MatchEndpoint {
            endpoint_id: parse_id(object, "endpoint_id")?,
        }),
        Some("catalog") => {
            let catalog = object
                .get("catalog")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    LoadedModelError::CanonicalProjection(
                        "catalog endpoint reference has no catalog".to_string(),
                    )
                })?;
            let name = catalog.get("name").and_then(Value::as_str).ok_or_else(|| {
                LoadedModelError::CanonicalProjection(
                    "catalog endpoint reference has no name".to_string(),
                )
            })?;
            let version_u64 = catalog
                .get("version")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    LoadedModelError::CanonicalProjection(
                        "catalog endpoint reference has no version".to_string(),
                    )
                })?;
            let version = u32::try_from(version_u64).map_err(|_| {
                LoadedModelError::CanonicalProjection(
                    "catalog endpoint version does not fit u32".to_string(),
                )
            })?;
            let resolved = catalogs
                .iter()
                .find(|resolved| resolved.name.as_str() == name && resolved.version == version)
                .cloned()
                .ok_or_else(|| {
                    LoadedModelError::CanonicalProjection(format!(
                        "catalog {name} version {version} was not resolved"
                    ))
                })?;
            Ok(ResolvedEndpointIdentity::Catalog {
                catalog: resolved,
                entry_id: parse_id(object, "entry_id")?,
            })
        }
        _ => Err(LoadedModelError::CanonicalProjection(
            "unknown endpoint reference variant".to_string(),
        )),
    }
}

fn parse_id<T>(object: &Map<String, Value>, key: &str) -> Result<T, LoadedModelError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let value = object.get(key).and_then(Value::as_str).ok_or_else(|| {
        LoadedModelError::CanonicalProjection(format!("endpoint reference has no {key}"))
    })?;
    value
        .parse()
        .map_err(|error: T::Err| LoadedModelError::CanonicalProjection(error.to_string()))
}

fn selector_at<'a>(
    selectors: &'a [ResolvedPolicySelector],
    path: &str,
) -> Result<&'a ResolvedPolicySelector, LoadedModelError> {
    let path =
        PolicySelectorPath::new(path).expect("internally generated selector paths are valid");
    selector_by_path(selectors, &path)
}

fn selector_by_path<'a>(
    selectors: &'a [ResolvedPolicySelector],
    path: &PolicySelectorPath,
) -> Result<&'a ResolvedPolicySelector, LoadedModelError> {
    selectors
        .iter()
        .find(|selector| selector.path == *path)
        .ok_or_else(|| LoadedModelError::MissingSelectorPath { path: path.clone() })
}

fn sorted_ids<T: AsRef<str>>(values: &[T]) -> Vec<&str> {
    sorted_identifier_refs(values.iter().map(AsRef::as_ref))
}

fn canonical_sort_key(value: &Value) -> String {
    String::from_utf8(
        compact_json_bytes(value).expect("serde_json::Value serialization is infallible"),
    )
    .expect("serde_json::Value serialization is valid UTF-8")
}

const fn observation_phase_label(phase: EndpointObservationPhase) -> &'static str {
    phase.label()
}
