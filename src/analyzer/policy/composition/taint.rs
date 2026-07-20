//! Setwise taint-policy composition.
//!
//! This module resolves endpoint and presentation predicates to finite sets.
//! It deliberately never materializes source/sink pair plans; #824 consumes
//! the two endpoint vectors as one aggregate analysis input.

use std::collections::{HashMap, HashSet};

use super::common::*;
use super::precedence::{PrecedenceError, PrecedenceGraph};
use crate::analyzer::policy::catalog::{TaintCatalogDefinition, TaintCatalogRegistry};
use crate::analyzer::policy::definition::*;
use crate::analyzer::policy::resolved::*;

#[derive(Debug, Clone)]
pub(crate) struct ComposedTaintPolicy {
    pub(crate) spec: ResolvedTaintPolicySpec,
    pub(crate) endpoint_dependencies: Vec<ResolvedEndpointDependency>,
    pub(crate) precedence: PolicyPrecedenceManifest,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn compose_taint_policy(
    policy_id: &PolicyId,
    spec: &TaintPolicySpec,
    catalogs: &TaintCatalogRegistry,
    endpoint_dependencies: &[ResolvedEndpointDependency],
    match_manifests: &[ResolvedMatchDirectoryManifest],
    limits: CompositionLimits,
) -> Result<ComposedTaintPolicy, CompositionError> {
    let universe = EndpointUniverse::try_new(endpoint_dependencies, limits)?;
    let mut resolved_catalogs = Vec::new();
    let sources = select_sources(
        policy_id,
        &spec.sources,
        catalogs,
        &universe,
        match_manifests,
        &mut resolved_catalogs,
        limits,
    )?;
    let sinks = select_sinks(
        policy_id,
        &spec.sinks,
        catalogs,
        &universe,
        match_manifests,
        &mut resolved_catalogs,
        limits,
    )?;

    let sanitizers = compose_auxiliary_set(
        policy_id,
        &spec.sanitizers,
        "sanitizers",
        "sanitizer",
        catalogs,
        &mut resolved_catalogs,
        |catalog| &catalog.sanitizers,
        |entry| ResolvedTaintSanitizerDefinition {
            input: entry.input.clone(),
            output: entry.output.clone(),
            removes: entry.removes.clone(),
        },
    )?;
    let transforms = compose_auxiliary_set(
        policy_id,
        &spec.transforms,
        "transforms",
        "transform",
        catalogs,
        &mut resolved_catalogs,
        |catalog| &catalog.transforms,
        |entry| ResolvedTaintTransformDefinition {
            input: entry.input.clone(),
            output: entry.output.clone(),
            removes: entry.removes.clone(),
            adds: entry.adds.clone(),
        },
    )?;
    let external_models = compose_auxiliary_set(
        policy_id,
        &spec.external_models,
        "external_models",
        "external model",
        catalogs,
        &mut resolved_catalogs,
        |catalog| &catalog.external_models,
        |entry| ResolvedTaintExternalModelDefinition {
            transfers: entry.transfers.clone(),
        },
    )?;

    let source_identities: Vec<_> = sources
        .endpoints
        .iter()
        .map(|endpoint| endpoint.identity.clone())
        .collect();
    let sink_identities: Vec<_> = sinks
        .endpoints
        .iter()
        .map(|endpoint| endpoint.identity.clone())
        .collect();
    let combinations = resolve_finding_combinations(
        policy_id,
        &spec.finding_combinations,
        &source_identities,
        &sink_identities,
        &universe,
        catalogs,
        limits,
    )?;

    let mut selected_identities = source_identities;
    selected_identities.extend(sink_identities);
    selected_identities.sort();
    selected_identities.dedup();
    let (_, mut precedence_edges) = validate_endpoint_precedence(&selected_identities, &universe)?;
    precedence_edges.extend(combinations.precedence_edges);

    let match_manifests = merge_manifests(sources.manifests.into_iter().chain(sinks.manifests))?;
    resolved_catalogs.sort();
    resolved_catalogs.dedup();
    let resolved_spec = ResolvedTaintPolicySpec::new(
        spec.mode,
        sources.endpoints,
        sinks.endpoints,
        sanitizers,
        transforms,
        external_models,
        resolved_catalogs,
        match_manifests,
        combinations.combinations,
    );

    Ok(ComposedTaintPolicy {
        spec: resolved_spec,
        endpoint_dependencies: universe.dependencies_for(&selected_identities),
        precedence: PolicyPrecedenceManifest::new(precedence_edges),
    })
}

#[derive(Debug)]
struct RoleSelection<T> {
    endpoints: Vec<ResolvedTaintEndpoint<T>>,
    manifests: Vec<ResolvedMatchDirectoryManifest>,
}

#[allow(clippy::too_many_arguments)]
fn select_sources(
    policy_id: &PolicyId,
    set: &TaintEndpointSet<TaintSourceSpec>,
    catalogs: &TaintCatalogRegistry,
    universe: &EndpointUniverse,
    manifests: &[ResolvedMatchDirectoryManifest],
    resolved_catalogs: &mut Vec<ResolvedCatalogIdentity>,
    limits: CompositionLimits,
) -> Result<RoleSelection<ResolvedTaintSourceDefinition>, CompositionError> {
    let mut identities = Vec::new();
    let mut used_manifests = Vec::new();
    for entry in &set.entries {
        let identity = ResolvedEndpointIdentity::Local {
            policy_id: policy_id.clone(),
            entry_id: entry.id.clone(),
        };
        let dependency = universe.get(&identity).ok_or_else(|| {
            CompositionError::MissingLocalEndpointDependency {
                identity: identity.clone(),
            }
        })?;
        universe.validate_role_and_taint(&identity, EndpointRole::Source, true)?;
        validate_source_model(entry, dependency)?;
        identities.push(identity);
    }
    for reference in &set.include_sets {
        let catalog = catalogs.resolve(reference)?;
        let catalog_identity = resolved_catalog_identity(catalogs, reference)?;
        resolved_catalogs.push(catalog_identity.clone());
        for entry in &catalog.definition().sources {
            let identity = ResolvedEndpointIdentity::Catalog {
                catalog: catalog_identity.clone(),
                entry_id: entry.id.clone(),
            };
            let dependency = universe.get(&identity).ok_or_else(|| {
                CompositionError::MissingCatalogEndpointDependency {
                    identity: identity.clone(),
                }
            })?;
            universe.validate_role_and_taint(&identity, EndpointRole::Source, true)?;
            validate_source_model(entry, dependency)?;
            identities.push(identity);
        }
    }
    for set in &set.include_matches {
        let selected = universe.select_match_set(set, EndpointRole::Source, true, manifests)?;
        identities.extend(selected.identities);
        used_manifests.extend(selected.manifests);
    }
    identities.sort();
    identities.dedup();
    if identities.is_empty() {
        return Err(CompositionError::EmptyResolvedEndpointSet {
            role: EndpointRole::Source,
        });
    }
    if identities.len() > limits.max_endpoints_per_role() {
        return Err(CompositionError::EndpointLimit {
            role: EndpointRole::Source,
            found: identities.len(),
            maximum: limits.max_endpoints_per_role(),
        });
    }
    let endpoints = identities
        .iter()
        .map(|identity| {
            resolved_source_from_dependency(
                universe
                    .get(identity)
                    .expect("selected endpoint remains in immutable universe"),
            )
        })
        .collect::<Result<_, _>>()?;
    Ok(RoleSelection {
        endpoints,
        manifests: used_manifests,
    })
}

#[allow(clippy::too_many_arguments)]
fn select_sinks(
    policy_id: &PolicyId,
    set: &TaintEndpointSet<TaintSinkSpec>,
    catalogs: &TaintCatalogRegistry,
    universe: &EndpointUniverse,
    manifests: &[ResolvedMatchDirectoryManifest],
    resolved_catalogs: &mut Vec<ResolvedCatalogIdentity>,
    limits: CompositionLimits,
) -> Result<RoleSelection<ResolvedTaintSinkDefinition>, CompositionError> {
    let mut identities = Vec::new();
    let mut used_manifests = Vec::new();
    for entry in &set.entries {
        let identity = ResolvedEndpointIdentity::Local {
            policy_id: policy_id.clone(),
            entry_id: entry.id.clone(),
        };
        let dependency = universe.get(&identity).ok_or_else(|| {
            CompositionError::MissingLocalEndpointDependency {
                identity: identity.clone(),
            }
        })?;
        universe.validate_role_and_taint(&identity, EndpointRole::Sink, true)?;
        validate_sink_model(entry, dependency)?;
        identities.push(identity);
    }
    for reference in &set.include_sets {
        let catalog = catalogs.resolve(reference)?;
        let catalog_identity = resolved_catalog_identity(catalogs, reference)?;
        resolved_catalogs.push(catalog_identity.clone());
        for entry in &catalog.definition().sinks {
            let identity = ResolvedEndpointIdentity::Catalog {
                catalog: catalog_identity.clone(),
                entry_id: entry.id.clone(),
            };
            let dependency = universe.get(&identity).ok_or_else(|| {
                CompositionError::MissingCatalogEndpointDependency {
                    identity: identity.clone(),
                }
            })?;
            universe.validate_role_and_taint(&identity, EndpointRole::Sink, true)?;
            validate_sink_model(entry, dependency)?;
            identities.push(identity);
        }
    }
    for set in &set.include_matches {
        let selected = universe.select_match_set(set, EndpointRole::Sink, true, manifests)?;
        identities.extend(selected.identities);
        used_manifests.extend(selected.manifests);
    }
    identities.sort();
    identities.dedup();
    if identities.is_empty() {
        return Err(CompositionError::EmptyResolvedEndpointSet {
            role: EndpointRole::Sink,
        });
    }
    if identities.len() > limits.max_endpoints_per_role() {
        return Err(CompositionError::EndpointLimit {
            role: EndpointRole::Sink,
            found: identities.len(),
            maximum: limits.max_endpoints_per_role(),
        });
    }
    let endpoints = identities
        .iter()
        .map(|identity| {
            resolved_sink_from_dependency(
                universe
                    .get(identity)
                    .expect("selected endpoint remains in immutable universe"),
            )
        })
        .collect::<Result<_, _>>()?;
    Ok(RoleSelection {
        endpoints,
        manifests: used_manifests,
    })
}

fn validate_source_model(
    entry: &TaintSourceSpec,
    dependency: &ResolvedEndpointDependency,
) -> Result<(), CompositionError> {
    let expected_taint = EndpointTaintSemantics::Source {
        labels: entry.labels.clone(),
        evidence: entry.evidence.clone(),
    };
    if dependency.model.display_name != entry.display_name
        || dependency.model.categories != entry.categories
        || dependency.model.binding != policy_port_to_endpoint_binding(&entry.bind)
        || dependency.model.taint.as_ref() != Some(&expected_taint)
        || !dependency.model.supersedes.is_empty()
    {
        return Err(CompositionError::EndpointHashCollision {
            identity: dependency.identity.clone(),
        });
    }
    Ok(())
}

fn validate_sink_model(
    entry: &TaintSinkSpec,
    dependency: &ResolvedEndpointDependency,
) -> Result<(), CompositionError> {
    let expected_taint = EndpointTaintSemantics::Sink {
        accepts: entry.accepts.clone(),
        tags: entry.tags.clone(),
        impacts: entry.impacts.clone(),
    };
    if dependency.model.display_name != entry.display_name
        || dependency.model.categories != entry.categories
        || dependency.model.binding != policy_port_to_endpoint_binding(&entry.dangerous_operand)
        || dependency.model.taint.as_ref() != Some(&expected_taint)
        || !dependency.model.supersedes.is_empty()
    {
        return Err(CompositionError::EndpointHashCollision {
            identity: dependency.identity.clone(),
        });
    }
    Ok(())
}

fn resolved_source_from_dependency(
    dependency: &ResolvedEndpointDependency,
) -> Result<ResolvedTaintEndpoint<ResolvedTaintSourceDefinition>, CompositionError> {
    let Some(EndpointTaintSemantics::Source { labels, evidence }) = &dependency.model.taint else {
        return Err(
            CompositionError::EndpointMissingOrMismatchedTaintSemantics {
                identity: dependency.identity.clone(),
                expected: EndpointRole::Source,
            },
        );
    };
    Ok(ResolvedTaintEndpoint::new(
        dependency.identity.clone(),
        dependency.semantic_hash,
        dependency.analysis_projection_hash,
        ResolvedTaintSourceDefinition {
            display_name: dependency.model.display_name.clone(),
            categories: dependency.model.categories.clone(),
            selector_path: dependency.selector_path.clone(),
            bind: crate::analyzer::policy::catalog::endpoint_binding_to_port(
                &dependency.model.binding,
            ),
            labels: labels.clone(),
            evidence: evidence.clone(),
        },
        dependency.origins.clone(),
    ))
}

fn resolved_sink_from_dependency(
    dependency: &ResolvedEndpointDependency,
) -> Result<ResolvedTaintEndpoint<ResolvedTaintSinkDefinition>, CompositionError> {
    let Some(EndpointTaintSemantics::Sink {
        accepts,
        tags,
        impacts,
    }) = &dependency.model.taint
    else {
        return Err(
            CompositionError::EndpointMissingOrMismatchedTaintSemantics {
                identity: dependency.identity.clone(),
                expected: EndpointRole::Sink,
            },
        );
    };
    Ok(ResolvedTaintEndpoint::new(
        dependency.identity.clone(),
        dependency.semantic_hash,
        dependency.analysis_projection_hash,
        ResolvedTaintSinkDefinition {
            display_name: dependency.model.display_name.clone(),
            categories: dependency.model.categories.clone(),
            selector_path: dependency.selector_path.clone(),
            dangerous_operand: crate::analyzer::policy::catalog::endpoint_binding_to_port(
                &dependency.model.binding,
            ),
            accepts: accepts.clone(),
            tags: tags.clone(),
            impacts: impacts.clone(),
        },
        dependency.origins.clone(),
    ))
}

#[allow(clippy::too_many_arguments)]
fn compose_auxiliary_set<T, D>(
    policy_id: &PolicyId,
    set: &TaintEndpointSet<T>,
    set_name: &'static str,
    kind: &'static str,
    catalogs: &TaintCatalogRegistry,
    resolved_catalogs: &mut Vec<ResolvedCatalogIdentity>,
    entries: for<'a> fn(&'a TaintCatalogDefinition) -> &'a [T],
    definition: impl Fn(&T) -> D,
) -> Result<Vec<ResolvedTaintAuxiliary<D>>, CompositionError>
where
    T: TaintEntry,
{
    if !set.include_matches.is_empty() {
        return Err(CompositionError::UnsupportedMatchComposition { set: kind });
    }
    let mut result = Vec::new();
    let mut identities = HashSet::new();
    for entry in &set.entries {
        let identity = ResolvedEndpointIdentity::Local {
            policy_id: policy_id.clone(),
            entry_id: entry.entry_id().clone(),
        };
        if !identities.insert(identity.clone()) {
            return Err(CompositionError::DuplicateComposedEntry {
                kind,
                id: entry.entry_id().clone(),
            });
        }
        let base = format!(
            "/analysis/{set_name}/entries/{}",
            json_pointer_segment(entry.entry_id().as_str())
        );
        result.push(ResolvedTaintAuxiliary::new(
            identity,
            PolicySelectorPath::new(format!("{base}/selector"))
                .map_err(|error| CompositionError::LoadedModel(error.to_string()))?,
            definition(entry),
            vec![EndpointOrigin::PolicyLocal {
                path: PolicyDependencyPath::new(base)
                    .map_err(|error| CompositionError::LoadedModel(error.to_string()))?,
            }],
        ));
    }
    for reference in &set.include_sets {
        let catalog = catalogs.resolve(reference)?;
        let catalog_identity = resolved_catalog_identity(catalogs, reference)?;
        resolved_catalogs.push(catalog_identity.clone());
        for entry in entries(catalog.definition()) {
            let identity = ResolvedEndpointIdentity::Catalog {
                catalog: catalog_identity.clone(),
                entry_id: entry.entry_id().clone(),
            };
            // Repeating the same immutable catalog reference is idempotent.
            // Equal bare IDs in different catalogs remain distinct because
            // the stable identity includes the resolved catalog identity.
            if !identities.insert(identity.clone()) {
                continue;
            }
            let path = format!(
                "/dependencies/catalogs/{}@{}/{}/selector",
                json_pointer_segment(catalog_identity.name.as_str()),
                catalog_identity.version,
                json_pointer_segment(entry.entry_id().as_str())
            );
            result.push(ResolvedTaintAuxiliary::new(
                identity,
                PolicySelectorPath::new(path)
                    .map_err(|error| CompositionError::LoadedModel(error.to_string()))?,
                definition(entry),
                vec![EndpointOrigin::Catalog {
                    catalog: catalog_identity.clone(),
                }],
            ));
        }
    }
    result.sort_by(|left, right| left.identity.cmp(&right.identity));
    Ok(result)
}

fn json_pointer_segment(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

trait TaintEntry {
    fn entry_id(&self) -> &TaintEntryId;
}

macro_rules! impl_taint_entry {
    ($($type:ty),+ $(,)?) => {
        $(
            impl TaintEntry for $type {
                fn entry_id(&self) -> &TaintEntryId {
                    &self.id
                }
            }
        )+
    };
}

impl_taint_entry!(
    TaintSanitizerSpec,
    TaintTransformSpec,
    TaintExternalModelSpec
);

#[derive(Debug)]
struct ResolvedCombinations {
    combinations: Vec<ResolvedFindingCombination>,
    precedence_edges: Vec<ResolvedPrecedenceEdge>,
}

#[allow(clippy::too_many_arguments)]
fn resolve_finding_combinations(
    policy_id: &PolicyId,
    combinations: &[FindingCombinationSpec],
    sources: &[ResolvedEndpointIdentity],
    sinks: &[ResolvedEndpointIdentity],
    universe: &EndpointUniverse,
    catalogs: &TaintCatalogRegistry,
    limits: CompositionLimits,
) -> Result<ResolvedCombinations, CompositionError> {
    if combinations.len() > limits.max_finding_combinations() {
        return Err(CompositionError::FindingCombinationPrecedence(format!(
            "policy contains {} finding combinations; limit is {}",
            combinations.len(),
            limits.max_finding_combinations()
        )));
    }
    let mut resolved = Vec::with_capacity(combinations.len());
    for combination in combinations {
        let source_endpoints = resolve_endpoint_predicate(
            &combination.source,
            policy_id,
            sources,
            universe,
            catalogs,
        )?;
        let sink_endpoints =
            resolve_endpoint_predicate(&combination.sink, policy_id, sinks, universe, catalogs)?;
        resolved.push(ResolvedFindingCombination::new(
            combination.id.clone(),
            source_endpoints,
            sink_endpoints,
            combination.message.clone(),
            combination.severity.clone(),
            combination.add_classifications.clone(),
            combination.supersedes.clone(),
        ));
    }

    let edges = resolved.iter().flat_map(|combination| {
        combination
            .supersedes
            .iter()
            .cloned()
            .map(|dominated| (combination.id.clone(), dominated))
    });
    let graph = PrecedenceGraph::try_new(
        resolved.iter().map(|combination| combination.id.clone()),
        edges,
    )
    .map_err(|error: PrecedenceError<FindingCombinationId>| {
        CompositionError::FindingCombinationPrecedence(error.to_string())
    })?;
    validate_combination_ambiguity(&resolved, &graph)?;
    let precedence_edges = graph
        .edges()
        .iter()
        .map(
            |(dominant, dominated)| ResolvedPrecedenceEdge::FindingCombination {
                dominant: dominant.clone(),
                dominated: dominated.clone(),
            },
        )
        .collect();
    resolved.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(ResolvedCombinations {
        combinations: resolved,
        precedence_edges,
    })
}

/// Prove that every endpoint pair covered by overlapping explicit rules has
/// one applicable graph winner. The proof operates on finite sets, but does
/// not retain or return a source/sink pair product.
fn validate_combination_ambiguity(
    combinations: &[ResolvedFindingCombination],
    graph: &PrecedenceGraph<FindingCombinationId>,
) -> Result<(), CompositionError> {
    let source_sets: Vec<HashSet<_>> = combinations
        .iter()
        .map(|rule| rule.source_endpoints.iter().cloned().collect())
        .collect();
    let sink_sets: Vec<HashSet<_>> = combinations
        .iter()
        .map(|rule| rule.sink_endpoints.iter().cloned().collect())
        .collect();

    for left_index in 0..combinations.len() {
        for right_index in (left_index + 1)..combinations.len() {
            let left = &combinations[left_index];
            let right = &combinations[right_index];
            if graph.dominates(&left.id, &right.id) || graph.dominates(&right.id, &left.id) {
                continue;
            }
            let source_overlap: Vec<_> = source_sets[left_index]
                .intersection(&source_sets[right_index])
                .cloned()
                .collect();
            if source_overlap.is_empty() {
                continue;
            }
            let sink_overlap: HashSet<_> = sink_sets[left_index]
                .intersection(&sink_sets[right_index])
                .cloned()
                .collect();
            if sink_overlap.is_empty() {
                continue;
            }

            let joint_dominators: Vec<_> = combinations
                .iter()
                .enumerate()
                .filter(|(_, candidate)| {
                    graph.dominates(&candidate.id, &left.id)
                        && graph.dominates(&candidate.id, &right.id)
                })
                .map(|(index, _)| index)
                .collect();
            let fully_applicable_joint_dominators = joint_dominators
                .iter()
                .copied()
                .filter(|index| {
                    source_overlap
                        .iter()
                        .all(|source| source_sets[*index].contains(source))
                        && sink_overlap
                            .iter()
                            .all(|sink| sink_sets[*index].contains(sink))
                })
                .collect::<Vec<_>>();
            if !fully_applicable_joint_dominators.is_empty() {
                graph
                    .unique_winner(
                        [left.id.clone(), right.id.clone()].into_iter().chain(
                            fully_applicable_joint_dominators
                                .iter()
                                .map(|index| combinations[*index].id.clone()),
                        ),
                    )
                    .map_err(|error| {
                        CompositionError::FindingCombinationPrecedence(error.to_string())
                    })?;
                continue;
            }
            let fully_covered = source_overlap.iter().all(|source| {
                sink_overlap.iter().all(|sink| {
                    joint_dominators.iter().any(|index| {
                        source_sets[*index].contains(source) && sink_sets[*index].contains(sink)
                    })
                })
            });
            if !fully_covered {
                return Err(CompositionError::FindingCombinationPrecedence(format!(
                    "finding combinations {:?} and {:?} overlap without a unique superseding winner",
                    left.id, right.id
                )));
            }
        }
    }
    Ok(())
}

fn merge_manifests(
    manifests: impl IntoIterator<Item = ResolvedMatchDirectoryManifest>,
) -> Result<Vec<ResolvedMatchDirectoryManifest>, CompositionError> {
    let mut by_path: HashMap<_, ResolvedMatchDirectoryManifest> = HashMap::new();
    for manifest in manifests {
        if let Some(existing) = by_path.get(&manifest.path) {
            if existing.semantic_hash != manifest.semantic_hash {
                return Err(CompositionError::LoadedModel(format!(
                    "match manifest path {} resolves to conflicting hashes",
                    manifest.path
                )));
            }
            continue;
        }
        by_path.insert(manifest.path.clone(), manifest);
    }
    let mut result: Vec<_> = by_path.into_values().collect();
    result.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::policy::{EndpointAnalysisProjectionHash, EndpointSemanticHash};
    use crate::analyzer::structural::CodeQuery;
    use crate::schema_version::{SchemaVersionOrigin, SchemaVersionResolution};

    fn selector(name: &str) -> PolicySelector {
        PolicySelector::Inline {
            schema: SchemaVersionResolution {
                version: 2,
                origin: SchemaVersionOrigin::Explicit,
            },
            query: CodeQuery::from_sexp(&format!(r#"(call :callee (name "{name}"))"#)).unwrap(),
        }
    }

    fn source(id: &str) -> TaintSourceSpec {
        TaintSourceSpec {
            id: TaintEntryId::new(id).unwrap(),
            display_name: format!("source {id}"),
            categories: vec![PolicyCategoryId::new("input.user").unwrap()],
            selector: selector(id),
            bind: PolicyPort::ReturnValue,
            labels: vec![TaintLabel::new("user-controlled").unwrap()],
            evidence: None,
        }
    }

    fn sink(id: &str) -> TaintSinkSpec {
        TaintSinkSpec {
            id: TaintEntryId::new(id).unwrap(),
            display_name: format!("sink {id}"),
            categories: vec![PolicyCategoryId::new("output.sensitive").unwrap()],
            selector: selector(id),
            dangerous_operand: PolicyPort::Receiver,
            accepts: vec![TaintLabel::new("user-controlled").unwrap()],
            tags: vec![],
            impacts: vec![],
        }
    }

    fn local_source_dependency(
        policy_id: &PolicyId,
        entry: &TaintSourceSpec,
        seed: u8,
    ) -> ResolvedEndpointDependency {
        dependency(
            ResolvedEndpointIdentity::Local {
                policy_id: policy_id.clone(),
                entry_id: entry.id.clone(),
            },
            &entry.id,
            ResolvedEndpointModel::new(
                EndpointRole::Source,
                entry.display_name.clone(),
                entry.categories.clone(),
                policy_port_to_endpoint_binding(&entry.bind),
                Some(EndpointTaintSemantics::Source {
                    labels: entry.labels.clone(),
                    evidence: entry.evidence.clone(),
                }),
                vec![],
            ),
            seed,
        )
    }

    fn local_sink_dependency(
        policy_id: &PolicyId,
        entry: &TaintSinkSpec,
        seed: u8,
    ) -> ResolvedEndpointDependency {
        dependency(
            ResolvedEndpointIdentity::Local {
                policy_id: policy_id.clone(),
                entry_id: entry.id.clone(),
            },
            &entry.id,
            ResolvedEndpointModel::new(
                EndpointRole::Sink,
                entry.display_name.clone(),
                entry.categories.clone(),
                policy_port_to_endpoint_binding(&entry.dangerous_operand),
                Some(EndpointTaintSemantics::Sink {
                    accepts: entry.accepts.clone(),
                    tags: entry.tags.clone(),
                    impacts: entry.impacts.clone(),
                }),
                vec![],
            ),
            seed,
        )
    }

    fn dependency(
        identity: ResolvedEndpointIdentity,
        entry_id: &TaintEntryId,
        model: ResolvedEndpointModel,
        seed: u8,
    ) -> ResolvedEndpointDependency {
        let kind = match model.role {
            EndpointRole::Source => "sources",
            EndpointRole::Sink => "sinks",
        };
        ResolvedEndpointDependency::new(
            identity,
            EndpointDefinitionSchemaResolution::PolicyDocument {
                resolution: SchemaVersionResolution {
                    version: 1,
                    origin: SchemaVersionOrigin::Explicit,
                },
            },
            PolicySelectorPath::new(format!(
                "/analysis/{kind}/entries/{}/selector",
                entry_id.as_str()
            ))
            .unwrap(),
            SchemaVersionResolution {
                version: 2,
                origin: SchemaVersionOrigin::Explicit,
            },
            model,
            EndpointSemanticHash::from_bytes([seed; 32]),
            EndpointAnalysisProjectionHash::from_bytes([seed.wrapping_add(64); 32]),
            vec![EndpointOrigin::PolicyLocal {
                path: PolicyDependencyPath::new(format!(
                    "/analysis/{kind}/entries/{}",
                    entry_id.as_str()
                ))
                .unwrap(),
            }],
        )
    }

    fn empty_set<T>() -> TaintEndpointSet<T> {
        TaintEndpointSet::default()
    }

    fn exact_local(entry_id: &TaintEntryId) -> EndpointPredicate {
        EndpointPredicate::Exact {
            endpoints: vec![EndpointRef::Local {
                entry_id: entry_id.clone(),
            }],
        }
    }

    #[test]
    fn three_by_four_inputs_remain_one_setwise_spec_in_stable_order() {
        let policy_id = PolicyId::new("test.setwise").unwrap();
        let mut sources = vec![source("s3"), source("s1"), source("s2")];
        let mut sinks = vec![sink("k4"), sink("k2"), sink("k1"), sink("k3")];
        let mut dependencies = Vec::new();
        for (index, entry) in sources.iter().enumerate() {
            dependencies.push(local_source_dependency(&policy_id, entry, index as u8 + 1));
        }
        for (index, entry) in sinks.iter().enumerate() {
            dependencies.push(local_sink_dependency(&policy_id, entry, index as u8 + 11));
        }
        dependencies.reverse();

        let spec = TaintPolicySpec {
            mode: MayMode::May,
            sources: TaintEndpointSet {
                include_sets: vec![],
                include_matches: vec![],
                entries: std::mem::take(&mut sources),
            },
            sinks: TaintEndpointSet {
                include_sets: vec![],
                include_matches: vec![],
                entries: std::mem::take(&mut sinks),
            },
            sanitizers: empty_set(),
            transforms: empty_set(),
            external_models: empty_set(),
            finding_combinations: vec![],
        };
        let catalogs = TaintCatalogRegistry::new_without_workspace(Default::default());
        let composed = compose_taint_policy(
            &policy_id,
            &spec,
            &catalogs,
            &dependencies,
            &[],
            CompositionLimits::default(),
        )
        .unwrap();

        assert_eq!(composed.spec.sources.len(), 3);
        assert_eq!(composed.spec.sinks.len(), 4);
        assert_eq!(composed.endpoint_dependencies.len(), 7);
        assert!(
            composed
                .spec
                .sources
                .windows(2)
                .all(|pair| pair[0].identity < pair[1].identity)
        );
        assert!(
            composed
                .spec
                .sinks
                .windows(2)
                .all(|pair| pair[0].identity < pair[1].identity)
        );
    }

    #[test]
    fn repeated_catalog_auxiliary_reference_is_idempotent() {
        let policy_id = PolicyId::new("test.catalog-auxiliary").unwrap();
        let source = source("request");
        let sink = sink("store");
        let dependencies = vec![
            local_source_dependency(&policy_id, &source, 1),
            local_sink_dependency(&policy_id, &sink, 2),
        ];
        let catalog_name = PolicyId::new("test.sanitizers").unwrap();
        let reference = CatalogRef::new(catalog_name.clone(), 1, None).unwrap();
        let mut catalogs = TaintCatalogRegistry::new_without_workspace(Default::default());
        catalogs
            .register(TaintCatalogDefinition {
                schema_version: 1,
                name: catalog_name,
                version: 1,
                sources: Vec::new(),
                sinks: Vec::new(),
                sanitizers: vec![TaintSanitizerSpec {
                    id: TaintEntryId::new("clean").unwrap(),
                    selector: selector("clean"),
                    input: PolicyPort::ArgumentIndex { index: 0 },
                    output: PolicyPort::ReturnValue,
                    removes: vec![TaintLabel::new("user-controlled").unwrap()],
                }],
                transforms: Vec::new(),
                external_models: Vec::new(),
            })
            .unwrap();
        let spec = TaintPolicySpec {
            mode: MayMode::May,
            sources: TaintEndpointSet {
                include_sets: vec![],
                include_matches: vec![],
                entries: vec![source],
            },
            sinks: TaintEndpointSet {
                include_sets: vec![],
                include_matches: vec![],
                entries: vec![sink],
            },
            sanitizers: TaintEndpointSet {
                include_sets: vec![reference.clone(), reference],
                include_matches: vec![],
                entries: vec![],
            },
            transforms: empty_set(),
            external_models: empty_set(),
            finding_combinations: vec![],
        };

        let composed = compose_taint_policy(
            &policy_id,
            &spec,
            &catalogs,
            &dependencies,
            &[],
            CompositionLimits::default(),
        )
        .unwrap();

        assert_eq!(composed.spec.catalogs.len(), 1);
        assert_eq!(composed.spec.sanitizers.len(), 1);
        assert_eq!(
            composed.spec.sanitizers[0].selector_path.as_str(),
            "/dependencies/catalogs/test.sanitizers@1/clean/selector"
        );
        assert!(matches!(
            composed.spec.sanitizers[0].identity,
            ResolvedEndpointIdentity::Catalog { .. }
        ));
    }

    #[test]
    fn overlapping_combinations_require_and_preserve_explicit_precedence() {
        let policy_id = PolicyId::new("test.precedence").unwrap();
        let source = source("request");
        let sink = sink("write");
        let dependencies = vec![
            local_source_dependency(&policy_id, &source, 1),
            local_sink_dependency(&policy_id, &sink, 2),
        ];
        let broad_id = FindingCombinationId::new("broad").unwrap();
        let specific_id = FindingCombinationId::new("specific").unwrap();
        let combination = |id: FindingCombinationId, supersedes: Vec<FindingCombinationId>| {
            FindingCombinationSpec {
                id,
                source: exact_local(&source.id),
                sink: exact_local(&sink.id),
                message: "specific flow".to_string(),
                severity: None,
                add_classifications: vec![],
                supersedes,
            }
        };
        let base = |combinations| TaintPolicySpec {
            mode: MayMode::May,
            sources: TaintEndpointSet {
                include_sets: vec![],
                include_matches: vec![],
                entries: vec![source.clone()],
            },
            sinks: TaintEndpointSet {
                include_sets: vec![],
                include_matches: vec![],
                entries: vec![sink.clone()],
            },
            sanitizers: empty_set(),
            transforms: empty_set(),
            external_models: empty_set(),
            finding_combinations: combinations,
        };
        let catalogs = TaintCatalogRegistry::new_without_workspace(Default::default());

        let ambiguous = base(vec![
            combination(broad_id.clone(), vec![]),
            combination(specific_id.clone(), vec![]),
        ]);
        assert!(matches!(
            compose_taint_policy(
                &policy_id,
                &ambiguous,
                &catalogs,
                &dependencies,
                &[],
                CompositionLimits::default(),
            ),
            Err(CompositionError::FindingCombinationPrecedence(_))
        ));

        let ordered = base(vec![
            combination(broad_id.clone(), vec![]),
            combination(specific_id.clone(), vec![broad_id.clone()]),
        ]);
        let composed = compose_taint_policy(
            &policy_id,
            &ordered,
            &catalogs,
            &dependencies,
            &[],
            CompositionLimits::default(),
        )
        .unwrap();
        assert!(
            composed
                .precedence
                .edges
                .contains(&ResolvedPrecedenceEdge::FindingCombination {
                    dominant: specific_id,
                    dominated: broad_id,
                })
        );

        let first = FindingCombinationId::new("first").unwrap();
        let second = FindingCombinationId::new("second").unwrap();
        let winner = FindingCombinationId::new("winner").unwrap();
        let jointly_resolved = base(vec![
            combination(first.clone(), vec![]),
            combination(second.clone(), vec![]),
            combination(winner, vec![first, second]),
        ]);
        compose_taint_policy(
            &policy_id,
            &jointly_resolved,
            &catalogs,
            &dependencies,
            &[],
            CompositionLimits::default(),
        )
        .unwrap();

        let first = FindingCombinationId::new("first-live").unwrap();
        let second = FindingCombinationId::new("second-live").unwrap();
        let third = FindingCombinationId::new("third-live").unwrap();
        let fourth = FindingCombinationId::new("fourth-live").unwrap();
        let two_live_winners = base(vec![
            combination(first.clone(), vec![]),
            combination(second.clone(), vec![]),
            combination(third, vec![first.clone(), second.clone()]),
            combination(fourth, vec![first, second]),
        ]);
        assert!(matches!(
            compose_taint_policy(
                &policy_id,
                &two_live_winners,
                &catalogs,
                &dependencies,
                &[],
                CompositionLimits::default(),
            ),
            Err(CompositionError::FindingCombinationPrecedence(_))
        ));
    }
}
