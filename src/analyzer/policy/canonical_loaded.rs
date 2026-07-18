//! Canonical semantic projections for fully loaded policies and endpoints.
//!
//! These functions accept only resolved models. Source paths, raw bytes,
//! reference order, version origin, optional pins, and registration provenance
//! are deliberately absent from every returned value.

use std::collections::HashSet;

use serde_json::{Map, Value, json};

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
    Ok(json!({
        "schema_version": definition.schema_version.version,
        "selector": object["selector"].clone(),
        "role": object["role"].clone(),
        "binding": object["binding"].clone(),
        "taint": object.get("taint").cloned(),
        "supersedes": object["supersedes"].clone(),
    }))
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
    json!({
        "definition_schema_version": definition_schema.version(),
        "selector": resolved_selector_to_json(selector),
        "role": endpoint_role_label(model.role),
        "binding": endpoint_binding_to_json(&model.binding),
        "taint": model.taint.as_ref().map(endpoint_taint_to_json),
        "supersedes": sorted_endpoint_identities(&model.supersedes),
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn resolved_policy_to_json(
    definition: &PolicyDefinition,
    analysis: ResolvedPolicyAnalysisRef<'_>,
    selectors: &[ResolvedPolicySelector],
    catalogs: &[ResolvedCatalogIdentity],
    endpoints: &[ResolvedEndpointDependency],
    match_manifests: &[ResolvedMatchDirectoryManifest],
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
    object.insert("precedence".to_string(), precedence_to_json(precedence));
    Ok(value)
}

pub(crate) fn loaded_policy_to_json(policy: &LoadedPolicy) -> Result<Value, LoadedModelError> {
    let analysis = match policy.definition().analysis {
        PolicyAnalysis::Match { .. } => ResolvedPolicyAnalysisRef::Match,
        PolicyAnalysis::Taint { .. } => ResolvedPolicyAnalysisRef::Taint {
            spec: policy
                .resolved_taint()
                .ok_or(LoadedModelError::ResolvedAnalysisMismatch)?,
        },
        PolicyAnalysis::Typestate { .. } => ResolvedPolicyAnalysisRef::Typestate {
            spec: policy
                .resolved_typestate()
                .ok_or(LoadedModelError::ResolvedAnalysisMismatch)?,
        },
    };
    resolved_policy_to_json(
        policy.definition(),
        analysis,
        policy.resolved_selectors(),
        policy.catalogs(),
        policy.endpoint_dependencies(),
        policy.match_directory_manifests(),
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
        "mode": may_mode_label(spec.mode),
        "subjects": subjects
            .into_iter()
            .map(resolved_typestate_subject_to_json)
            .collect::<Vec<_>>(),
        "uncertainty": {
            "unknown_call": inconclusive_label(spec.uncertainty.unknown_call),
            "escape": inconclusive_label(spec.uncertainty.escape),
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
    let mut selected = selected.iter().collect::<Vec<_>>();
    selected.sort_by(|left, right| left.identity.cmp(&right.identity));
    json!({
        "scope": directory_scope_label(scope),
        "role": role.map(endpoint_role_label),
        "categories": category_predicate_to_json(categories),
        "selected": selected
            .into_iter()
            .map(resolved_manifest_entry_to_json)
            .collect::<Vec<_>>(),
    })
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
    let mut selected = selected.iter().collect::<Vec<_>>();
    selected.sort_by(|left, right| left.identity.cmp(&right.identity));
    json!({
        "scope": directory_scope_label(scope),
        "role": role.map(endpoint_role_label),
        "categories": category_predicate_to_json(categories),
        "selected": selected
            .into_iter()
            .map(|entry| json!({
                "identity": resolved_endpoint_identity_to_json(&entry.identity),
                "semantic_hash": entry.semantic_hash.to_string(),
            }))
            .collect::<Vec<_>>(),
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
    let mut transforms = spec.transforms.iter().collect::<Vec<_>>();
    transforms.sort_by(|left, right| left.identity.cmp(&right.identity));
    let mut external_models = spec.external_models.iter().collect::<Vec<_>>();
    external_models.sort_by(|left, right| left.identity.cmp(&right.identity));
    let mut combinations = spec.finding_combinations.iter().collect::<Vec<_>>();
    combinations.sort_by(|left, right| left.id.cmp(&right.id));

    Ok(json!({
        "type": "taint",
        "mode": may_mode_label(spec.mode),
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
    }))
}

fn resolved_taint_source_to_json(
    endpoint: &ResolvedTaintEndpoint<ResolvedTaintSourceDefinition>,
    selectors: &[ResolvedPolicySelector],
) -> Result<Value, LoadedModelError> {
    let definition = &endpoint.definition;
    let selector = selector_by_path(selectors, &definition.selector_path)?;
    Ok(json!({
        "identity": resolved_endpoint_identity_to_json(&endpoint.identity),
        "semantic_hash": endpoint.semantic_hash.to_string(),
        "analysis_projection_hash": endpoint.analysis_projection_hash.to_string(),
        "definition": {
            "display_name": definition.display_name,
            "categories": sorted_ids(&definition.categories),
            "selector": resolved_selector_to_json(selector),
            "bind": policy_port_to_json(&definition.bind),
            "labels": sorted_ids(&definition.labels),
            "evidence": definition.evidence.as_ref().map(taint_source_evidence_to_json),
        },
    }))
}

fn resolved_taint_sink_to_json(
    endpoint: &ResolvedTaintEndpoint<ResolvedTaintSinkDefinition>,
    selectors: &[ResolvedPolicySelector],
) -> Result<Value, LoadedModelError> {
    let definition = &endpoint.definition;
    let selector = selector_by_path(selectors, &definition.selector_path)?;
    Ok(json!({
        "identity": resolved_endpoint_identity_to_json(&endpoint.identity),
        "semantic_hash": endpoint.semantic_hash.to_string(),
        "analysis_projection_hash": endpoint.analysis_projection_hash.to_string(),
        "definition": {
            "display_name": definition.display_name,
            "categories": sorted_ids(&definition.categories),
            "selector": resolved_selector_to_json(selector),
            "dangerous_operand": policy_port_to_json(&definition.dangerous_operand),
            "accepts": sorted_ids(&definition.accepts),
            "tags": sorted_ids(&definition.tags),
            "impacts": sorted_ids(&definition.impacts),
        },
    }))
}

fn taint_sanitizer_to_json(
    entry: &ResolvedTaintAuxiliary<ResolvedTaintSanitizerDefinition>,
    selectors: &[ResolvedPolicySelector],
) -> Result<Value, LoadedModelError> {
    let selector = selector_by_path(selectors, &entry.selector_path)?;
    let definition = &entry.definition;
    Ok(json!({
        "identity": resolved_endpoint_identity_to_json(&entry.identity),
        "definition": {
            "selector": resolved_selector_to_json(selector),
            "input": policy_port_to_json(&definition.input),
            "output": policy_port_to_json(&definition.output),
            "removes": sorted_ids(&definition.removes),
        },
    }))
}

fn taint_transform_to_json(
    entry: &ResolvedTaintAuxiliary<ResolvedTaintTransformDefinition>,
    selectors: &[ResolvedPolicySelector],
) -> Result<Value, LoadedModelError> {
    let selector = selector_by_path(selectors, &entry.selector_path)?;
    let definition = &entry.definition;
    Ok(json!({
        "identity": resolved_endpoint_identity_to_json(&entry.identity),
        "definition": {
            "selector": resolved_selector_to_json(selector),
            "input": policy_port_to_json(&definition.input),
            "output": policy_port_to_json(&definition.output),
            "removes": sorted_ids(&definition.removes),
            "adds": sorted_ids(&definition.adds),
        },
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

fn taint_transfer_to_json(transfer: &TaintTransferSpec) -> Value {
    json!({
        "from": policy_port_to_json(&transfer.from),
        "to": policy_port_to_json(&transfer.to),
        "labels": sorted_ids(&transfer.labels),
        "effect": taint_transfer_effect_to_json(&transfer.effect),
    })
}

fn taint_transfer_effect_to_json(effect: &TaintTransferEffect) -> Value {
    match effect {
        TaintTransferEffect::Propagate => json!({ "type": "propagate" }),
        TaintTransferEffect::Sanitize { removes } => json!({
            "type": "sanitize",
            "removes": sorted_ids(removes),
        }),
        TaintTransferEffect::Transform { removes, adds } => json!({
            "type": "transform",
            "removes": sorted_ids(removes),
            "adds": sorted_ids(adds),
        }),
    }
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
    json!({
        "states": sorted_ids(&automaton.states),
        "initial": automaton.initial.as_str(),
        "accepting_states": sorted_ids(&automaton.accepting_states),
        "error_states": sorted_ids(&automaton.error_states),
        "events": events
            .into_iter()
            .map(resolved_typestate_event_to_json)
            .collect::<Vec<_>>(),
        "transitions": transitions
            .into_iter()
            .map(|transition| json!({
                "from": transition.from.as_str(),
                "on": transition.on.as_str(),
                "to": transition.to.as_str(),
            }))
            .collect::<Vec<_>>(),
        "terminal_expectations": expectations
            .into_iter()
            .map(resolved_typestate_expectation_to_json)
            .collect::<Vec<_>>(),
    })
}

fn resolved_typestate_event_to_json(event: &ResolvedTypestateEventSpec) -> Value {
    json!({
        "id": event.id.as_str(),
        "trigger": resolved_typestate_event_trigger_to_json(&event.trigger),
        "applies_to_subjects": sorted_endpoint_identities(&event.applies_to_subjects),
        "supersedes": sorted_ids(&event.supersedes),
    })
}

fn resolved_typestate_event_trigger_to_json(trigger: &ResolvedTypestateEventTrigger) -> Value {
    match trigger {
        ResolvedTypestateEventTrigger::Calls {
            selector_path,
            subject,
            phase,
        } => json!({
            "type": "calls",
            "selector_path": selector_path.as_str(),
            "subject": typestate_call_binding_to_json(subject),
            "phase": observation_phase_label(*phase),
        }),
        ResolvedTypestateEventTrigger::MatchEndpoints { endpoints, phase } => json!({
            "type": "match_endpoints",
            "endpoints": sorted_endpoint_identities(endpoints),
            "phase": observation_phase_label(*phase),
        }),
        ResolvedTypestateEventTrigger::SemanticEvent { event } => json!({
            "type": "semantic_event",
            "event": policy_semantic_event_to_json(*event),
        }),
    }
}

fn resolved_typestate_expectation_to_json(
    expectation: &ResolvedTypestateTerminalExpectationSpec,
) -> Value {
    json!({
        "id": expectation.id.as_str(),
        "trigger": resolved_typestate_terminal_trigger_to_json(&expectation.trigger),
        "applies_to_subjects": sorted_endpoint_identities(&expectation.applies_to_subjects),
        "expected_states": sorted_ids(&expectation.expected_states),
        "supersedes": sorted_ids(&expectation.supersedes),
    })
}

fn resolved_typestate_terminal_trigger_to_json(
    trigger: &ResolvedTypestateTerminalTrigger,
) -> Value {
    match trigger {
        ResolvedTypestateTerminalTrigger::MatchEndpoints { endpoints, phase } => json!({
            "type": "match_endpoints",
            "endpoints": sorted_endpoint_identities(endpoints),
            "phase": observation_phase_label(*phase),
        }),
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
    let mut endpoints = endpoints.iter().collect::<Vec<_>>();
    endpoints.sort_by(|left, right| left.identity.cmp(&right.identity));
    endpoints
        .into_iter()
        .map(resolved_endpoint_dependency_to_json)
        .collect()
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

fn resolved_selector_to_json(selector: &ResolvedPolicySelector) -> Value {
    json!({
        "schema_version": selector.schema_resolution.version,
        "query": selector.query.to_canonical_query_plan_json(),
    })
}

fn resolved_catalog_identity_to_json(catalog: &ResolvedCatalogIdentity) -> Value {
    json!({
        "name": catalog.name.as_str(),
        "version": catalog.version,
        "semantic_hash": catalog.semantic_hash.to_string(),
    })
}

fn resolved_endpoint_dependency_to_json(dependency: &ResolvedEndpointDependency) -> Value {
    json!({
        "identity": resolved_endpoint_identity_to_json(&dependency.identity),
        "definition_schema_version": dependency.definition_schema.version(),
        "selector_schema_version": dependency.selector_schema.version,
        "model": resolved_endpoint_model_to_json(&dependency.model),
        "semantic_hash": dependency.semantic_hash.to_string(),
        "analysis_projection_hash": dependency.analysis_projection_hash.to_string(),
    })
}

fn resolved_endpoint_model_to_json(model: &ResolvedEndpointModel) -> Value {
    json!({
        "role": endpoint_role_label(model.role),
        "display_name": model.display_name,
        "categories": sorted_ids(&model.categories),
        "binding": endpoint_binding_to_json(&model.binding),
        "taint": model.taint.as_ref().map(endpoint_taint_to_json),
        "supersedes": sorted_endpoint_identities(&model.supersedes),
    })
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
    json!({
        "identity": resolved_endpoint_identity_to_json(&entry.identity),
        "definition_schema_version": entry.definition_schema.version(),
        "selector_schema_version": entry.selector_schema.version,
        "semantic_hash": entry.semantic_hash.to_string(),
        "analysis_projection_hash": entry.analysis_projection_hash.to_string(),
    })
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
    let mut identities = identities.iter().collect::<Vec<_>>();
    identities.sort();
    identities
        .into_iter()
        .map(resolved_endpoint_identity_to_json)
        .collect()
}

fn endpoint_binding_to_json(binding: &PolicyEndpointBinding) -> Value {
    match binding {
        PolicyEndpointBinding::MatchedValue => json!({ "type": "matched_value" }),
        PolicyEndpointBinding::Receiver => json!({ "type": "receiver" }),
        PolicyEndpointBinding::ReturnValue => json!({ "type": "return_value" }),
        PolicyEndpointBinding::ArgumentIndex { index } => {
            json!({ "type": "argument_index", "index": index })
        }
        PolicyEndpointBinding::ArgumentName { name } => {
            json!({ "type": "argument_name", "name": name })
        }
    }
}

fn endpoint_taint_to_json(taint: &EndpointTaintSemantics) -> Value {
    match taint {
        EndpointTaintSemantics::Source { labels, evidence } => json!({
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

fn policy_port_to_json(port: &PolicyPort) -> Value {
    match port {
        PolicyPort::MatchedValue => json!({ "type": "matched_value" }),
        PolicyPort::Receiver => json!({ "type": "receiver" }),
        PolicyPort::ReturnValue => json!({ "type": "return_value" }),
        PolicyPort::ArgumentIndex { index } => {
            json!({ "type": "argument_index", "index": index })
        }
        PolicyPort::ArgumentName { name } => {
            json!({ "type": "argument_name", "name": name })
        }
    }
}

fn resolved_typestate_binding_to_json(binding: &ResolvedTypestateBinding) -> Value {
    match binding {
        ResolvedTypestateBinding::MatchedValue => json!({ "type": "matched_value" }),
        ResolvedTypestateBinding::Receiver => json!({ "type": "receiver" }),
        ResolvedTypestateBinding::ReturnValue => json!({ "type": "return_value" }),
        ResolvedTypestateBinding::ArgumentIndex { index } => {
            json!({ "type": "argument_index", "index": index })
        }
        ResolvedTypestateBinding::ArgumentName { name } => {
            json!({ "type": "argument_name", "name": name })
        }
    }
}

fn typestate_call_binding_to_json(binding: &TypestateCallBinding) -> Value {
    match binding {
        TypestateCallBinding::Receiver => json!({ "type": "receiver" }),
        TypestateCallBinding::ReturnValue => json!({ "type": "return_value" }),
        TypestateCallBinding::ArgumentIndex { index } => {
            json!({ "type": "argument_index", "index": index })
        }
        TypestateCallBinding::ArgumentName { name } => {
            json!({ "type": "argument_name", "name": name })
        }
    }
}

fn taint_source_evidence_to_json(evidence: &TaintSourceEvidence) -> Value {
    json!({
        "trust_boundary": evidence.trust_boundary.map(trust_boundary_label),
        "system_entry": evidence.system_entry.map(system_entry_label),
    })
}

fn category_predicate_to_json(predicate: &CategoryPredicate) -> Value {
    match predicate {
        CategoryPredicate::Any { categories } => json!({
            "type": "any",
            "categories": sorted_ids(categories),
        }),
        CategoryPredicate::All { categories } => json!({
            "type": "all",
            "categories": sorted_ids(categories),
        }),
    }
}

fn policy_severity_to_json(severity: &PolicySeveritySpec) -> Value {
    match severity {
        PolicySeveritySpec::Fixed { level } => json!({
            "type": "fixed",
            "level": policy_level_label(*level),
        }),
        PolicySeveritySpec::Unrated => json!({ "type": "unrated" }),
        PolicySeveritySpec::Cvss { when_unscored } => json!({
            "type": "cvss",
            "when_unscored": finding_severity_label(*when_unscored),
        }),
    }
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
    selectors
        .iter()
        .find(|selector| selector.path.as_str() == path)
        .ok_or_else(|| LoadedModelError::MissingSelectorPath {
            path: PolicySelectorPath::new(path)
                .expect("internally generated selector paths are valid"),
        })
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
    let mut values = values.iter().map(AsRef::as_ref).collect::<Vec<_>>();
    values.sort_unstable();
    values.dedup();
    values
}

fn canonical_sort_key(value: &Value) -> String {
    serde_json::to_string(value).expect("serde_json::Value serialization is infallible")
}

const fn may_mode_label(mode: MayMode) -> &'static str {
    match mode {
        MayMode::May => "may",
    }
}

const fn inconclusive_label(policy: InconclusivePolicy) -> &'static str {
    match policy {
        InconclusivePolicy::Inconclusive => "inconclusive",
    }
}

const fn endpoint_role_label(role: EndpointRole) -> &'static str {
    match role {
        EndpointRole::Source => "source",
        EndpointRole::Sink => "sink",
    }
}

const fn directory_scope_label(scope: DirectoryScope) -> &'static str {
    match scope {
        DirectoryScope::Direct => "direct",
        DirectoryScope::Recursive => "recursive",
    }
}

const fn observation_phase_label(phase: EndpointObservationPhase) -> &'static str {
    match phase {
        EndpointObservationPhase::AtMatch => "at_match",
        EndpointObservationPhase::BeforeCall => "before_call",
        EndpointObservationPhase::AfterNormalReturn => "after_normal_return",
        EndpointObservationPhase::AfterExceptionalReturn => "after_exceptional_return",
    }
}

fn policy_semantic_event_to_json(event: PolicySemanticEvent) -> Value {
    match event {
        PolicySemanticEvent::NormalProcedureExit { scope } => json!({
            "type": "normal_procedure_exit",
            "scope": typestate_exit_scope_label(scope),
        }),
        PolicySemanticEvent::ExceptionalProcedureExit { scope } => json!({
            "type": "exceptional_procedure_exit",
            "scope": typestate_exit_scope_label(scope),
        }),
    }
}

const fn typestate_exit_scope_label(scope: TypestateExitScope) -> &'static str {
    match scope {
        TypestateExitScope::AnalysisRoot => "analysis_root",
    }
}

const fn trust_boundary_label(boundary: TaintTrustBoundary) -> &'static str {
    match boundary {
        TaintTrustBoundary::External => "external",
        TaintTrustBoundary::Internal => "internal",
        TaintTrustBoundary::SameTrustZone => "same_trust_zone",
    }
}

const fn system_entry_label(entry: TaintSystemEntry) -> &'static str {
    match entry {
        TaintSystemEntry::VulnerableSystemNetworkStack => "vulnerable_system_network_stack",
        TaintSystemEntry::DownloadedArtifact => "downloaded_artifact",
        TaintSystemEntry::LocalInput => "local_input",
        TaintSystemEntry::AdjacentNetwork => "adjacent_network",
        TaintSystemEntry::Physical => "physical",
    }
}

const fn policy_level_label(level: PolicyLevel) -> &'static str {
    match level {
        PolicyLevel::Note => "note",
        PolicyLevel::Warning => "warning",
        PolicyLevel::Error => "error",
    }
}

const fn finding_severity_label(severity: FindingSeverity) -> &'static str {
    match severity {
        FindingSeverity::Unrated => "unrated",
        FindingSeverity::Note => "note",
        FindingSeverity::Warning => "warning",
        FindingSeverity::Error => "error",
    }
}
