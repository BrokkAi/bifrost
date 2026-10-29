//! Setwise typestate endpoint and predicate composition.

use std::collections::HashSet;

use super::common::*;
use super::precedence::{PrecedenceError, PrecedenceGraph};
use crate::catalog::{TaintCatalogRegistry, typestate_seed_binding_to_port};
use crate::definition::*;
use crate::resolved::*;

#[derive(Debug, Clone)]
pub(crate) struct ComposedTypestatePolicy {
    pub(crate) spec: ResolvedTypestatePolicySpec,
    pub(crate) precedence: PolicyPrecedenceManifest,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn compose_typestate_policy(
    policy_id: &PolicyId,
    spec: &TypestatePolicySpec,
    catalogs: &TaintCatalogRegistry,
    endpoint_dependencies: &[ResolvedEndpointDependency],
    match_manifests: &[ResolvedMatchDirectoryManifest],
    limits: CompositionLimits,
) -> Result<ComposedTypestatePolicy, CompositionError> {
    validate_automaton_shape(&spec.automaton, limits)?;
    let universe = EndpointUniverse::try_new(endpoint_dependencies, limits)?;
    let subjects = resolve_subjects(
        policy_id,
        &spec.subjects,
        &universe,
        match_manifests,
        limits,
    )?;
    let subject_identities: Vec<_> = subjects
        .subjects
        .iter()
        .map(|subject| subject.identity.clone())
        .collect();

    let events = resolve_events(
        policy_id,
        &spec.automaton.events,
        &subject_identities,
        &universe,
        catalogs,
        match_manifests,
        limits,
    )?;
    let expectations = resolve_expectations(
        policy_id,
        &spec.automaton.terminal_expectations,
        &subject_identities,
        &universe,
        catalogs,
        match_manifests,
        limits,
    )?;

    let mut selected_identities = subject_identities;
    selected_identities.extend(events.endpoint_identities);
    selected_identities.extend(expectations.endpoint_identities);
    selected_identities.sort();
    selected_identities.dedup();
    let (_, mut precedence_edges) = validate_endpoint_precedence(&selected_identities, &universe)?;
    precedence_edges.extend(events.precedence_edges);
    precedence_edges.extend(expectations.precedence_edges);

    let manifests = merge_typestate_manifests(
        subjects
            .manifests
            .into_iter()
            .chain(events.manifests)
            .chain(expectations.manifests),
    )?;
    let automaton = ResolvedTypestateAutomatonSpec {
        states: spec.automaton.states.clone(),
        initial: spec.automaton.initial.clone(),
        accepting_states: spec.automaton.accepting_states.clone(),
        error_states: spec.automaton.error_states.clone(),
        events: events.events,
        transitions: spec.automaton.transitions.clone(),
        terminal_expectations: expectations.expectations,
    };
    let resolved = ResolvedTypestatePolicySpec::try_new(
        spec.mode,
        spec.call_modeling,
        subjects.subjects,
        spec.uncertainty.clone(),
        automaton,
        universe.dependencies_for(&selected_identities),
        manifests,
    )
    .map_err(|error| CompositionError::LoadedModel(error.to_string()))?;
    Ok(ComposedTypestatePolicy {
        spec: resolved,
        precedence: PolicyPrecedenceManifest::new(precedence_edges),
    })
}

#[derive(Debug)]
struct SubjectSelection {
    subjects: Vec<ResolvedTypestateSubject>,
    manifests: Vec<ResolvedMatchDirectoryManifest>,
}

fn resolve_subjects(
    policy_id: &PolicyId,
    set: &TypestateSubjectSet,
    universe: &EndpointUniverse,
    manifests: &[ResolvedMatchDirectoryManifest],
    limits: CompositionLimits,
) -> Result<SubjectSelection, CompositionError> {
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
        universe.validate_role_and_taint(&identity, EndpointRole::Source, false)?;
        let expected_binding =
            policy_port_to_endpoint_binding(&typestate_seed_binding_to_port(&entry.subject));
        if dependency.model.binding != expected_binding {
            return Err(CompositionError::EndpointHashCollision { identity });
        }
        identities.push(dependency.identity.clone());
    }
    for set in &set.include_matches {
        let selected = universe.select_match_set(set, EndpointRole::Source, false, manifests)?;
        identities.extend(selected.identities);
        used_manifests.extend(selected.manifests);
    }
    identities.sort();
    identities.dedup();
    if identities.is_empty() {
        return Err(CompositionError::EmptyResolvedEndpointSet { role: "Source" });
    }
    if identities.len() > limits.max_endpoints_per_role() {
        return Err(CompositionError::EndpointLimit {
            role: EndpointRole::Source,
            found: identities.len(),
            maximum: limits.max_endpoints_per_role(),
        });
    }
    let subjects = identities
        .iter()
        .map(|identity| {
            let dependency = universe
                .get(identity)
                .expect("selected endpoint remains in immutable universe");
            ResolvedTypestateSubject::new(
                identity.clone(),
                dependency.selector_path.clone(),
                endpoint_binding_to_typestate(&dependency.model.binding),
                dependency.semantic_hash,
                dependency.analysis_projection_hash,
                dependency.origins.clone(),
            )
        })
        .collect();
    Ok(SubjectSelection {
        subjects,
        manifests: used_manifests,
    })
}

#[derive(Debug)]
struct EventSelection {
    events: Vec<ResolvedTypestateEventSpec>,
    endpoint_identities: Vec<ResolvedEndpointIdentity>,
    manifests: Vec<ResolvedMatchDirectoryManifest>,
    precedence_edges: Vec<ResolvedPrecedenceEdge>,
}

#[allow(clippy::too_many_arguments)]
fn resolve_events(
    policy_id: &PolicyId,
    events: &[TypestateEventSpec],
    subjects: &[ResolvedEndpointIdentity],
    universe: &EndpointUniverse,
    catalogs: &TaintCatalogRegistry,
    manifests: &[ResolvedMatchDirectoryManifest],
    limits: CompositionLimits,
) -> Result<EventSelection, CompositionError> {
    if events.len() > limits.max_typestate_events() {
        return Err(CompositionError::InvalidTypestateAutomaton(format!(
            "typestate policy contains {} events; limit is {}",
            events.len(),
            limits.max_typestate_events()
        )));
    }
    let mut resolved = Vec::with_capacity(events.len());
    let mut endpoint_identities = Vec::new();
    let mut used_manifests = Vec::new();
    for event in events {
        let trigger = match &event.trigger {
            TypestateEventTrigger::Calls {
                subject,
                phase,
                argument_condition,
                ..
            } => {
                validate_call_phase(*phase, subject)?;
                ResolvedTypestateEventTrigger::Calls {
                    selector_path: event_selector_path(&event.id)?,
                    subject: subject.clone(),
                    phase: *phase,
                    argument_condition: *argument_condition,
                }
            }
            TypestateEventTrigger::MatchEndpoints { set, role, phase } => {
                let selected = resolve_observed_match_set(set, *role, *phase, universe, manifests)?;
                endpoint_identities.extend(selected.identities.iter().cloned());
                used_manifests.extend(selected.manifests);
                ResolvedTypestateEventTrigger::MatchEndpoints {
                    endpoints: selected.identities,
                    phase: *phase,
                }
            }
            TypestateEventTrigger::SemanticEvent { event } => {
                ResolvedTypestateEventTrigger::SemanticEvent { event: *event }
            }
        };
        let applies_to_subjects = match &event.applies_to_subjects {
            Some(predicate) => {
                resolve_endpoint_predicate(predicate, policy_id, subjects, universe, catalogs)?
            }
            None => subjects.to_vec(),
        };
        resolved.push(ResolvedTypestateEventSpec::new(
            event.id.clone(),
            trigger,
            applies_to_subjects,
            event.supersedes.clone(),
        ));
    }
    let graph = PrecedenceGraph::try_new(
        resolved.iter().map(|event| event.id.clone()),
        resolved.iter().flat_map(|event| {
            event
                .supersedes
                .iter()
                .cloned()
                .map(|dominated| (event.id.clone(), dominated))
        }),
    )
    .map_err(|error: PrecedenceError<TypestateEventId>| {
        CompositionError::TypestateEventPrecedence(error.to_string())
    })?;
    validate_event_ambiguity(&resolved, &graph)?;
    let precedence_edges = graph
        .edges()
        .iter()
        .map(
            |(dominant, dominated)| ResolvedPrecedenceEdge::TypestateEvent {
                dominant: dominant.clone(),
                dominated: dominated.clone(),
            },
        )
        .collect();
    resolved.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(EventSelection {
        events: resolved,
        endpoint_identities,
        manifests: used_manifests,
        precedence_edges,
    })
}

#[derive(Debug)]
struct ExpectationSelection {
    expectations: Vec<ResolvedTypestateTerminalExpectationSpec>,
    endpoint_identities: Vec<ResolvedEndpointIdentity>,
    manifests: Vec<ResolvedMatchDirectoryManifest>,
    precedence_edges: Vec<ResolvedPrecedenceEdge>,
}

#[allow(clippy::too_many_arguments)]
fn resolve_expectations(
    policy_id: &PolicyId,
    expectations: &[TypestateTerminalExpectationSpec],
    subjects: &[ResolvedEndpointIdentity],
    universe: &EndpointUniverse,
    catalogs: &TaintCatalogRegistry,
    manifests: &[ResolvedMatchDirectoryManifest],
    limits: CompositionLimits,
) -> Result<ExpectationSelection, CompositionError> {
    if expectations.len() > limits.max_typestate_expectations() {
        return Err(CompositionError::InvalidTypestateAutomaton(format!(
            "typestate policy contains {} terminal expectations; limit is {}",
            expectations.len(),
            limits.max_typestate_expectations()
        )));
    }
    let mut resolved = Vec::with_capacity(expectations.len());
    let mut endpoint_identities = Vec::new();
    let mut used_manifests = Vec::new();
    for expectation in expectations {
        let trigger = match &expectation.trigger {
            TypestateTerminalTrigger::MatchEndpoints { set, role, phase } => {
                let selected = resolve_observed_match_set(set, *role, *phase, universe, manifests)?;
                endpoint_identities.extend(selected.identities.iter().cloned());
                used_manifests.extend(selected.manifests);
                ResolvedTypestateTerminalTrigger::MatchEndpoints {
                    endpoints: selected.identities,
                    phase: *phase,
                }
            }
            TypestateTerminalTrigger::SemanticEvent { event } => {
                ResolvedTypestateTerminalTrigger::SemanticEvent { event: *event }
            }
        };
        let applies_to_subjects = match &expectation.applies_to_subjects {
            Some(predicate) => {
                resolve_endpoint_predicate(predicate, policy_id, subjects, universe, catalogs)?
            }
            None => subjects.to_vec(),
        };
        resolved.push(ResolvedTypestateTerminalExpectationSpec::new(
            expectation.id.clone(),
            trigger,
            applies_to_subjects,
            expectation.expected_states.clone(),
            expectation.supersedes.clone(),
        ));
    }
    let graph = PrecedenceGraph::try_new(
        resolved.iter().map(|expectation| expectation.id.clone()),
        resolved.iter().flat_map(|expectation| {
            expectation
                .supersedes
                .iter()
                .cloned()
                .map(|dominated| (expectation.id.clone(), dominated))
        }),
    )
    .map_err(|error: PrecedenceError<TypestateExpectationId>| {
        CompositionError::TypestateExpectationPrecedence(error.to_string())
    })?;
    validate_expectation_ambiguity(&resolved, &graph)?;
    let precedence_edges = graph
        .edges()
        .iter()
        .map(
            |(dominant, dominated)| ResolvedPrecedenceEdge::TypestateExpectation {
                dominant: dominant.clone(),
                dominated: dominated.clone(),
            },
        )
        .collect();
    resolved.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(ExpectationSelection {
        expectations: resolved,
        endpoint_identities,
        manifests: used_manifests,
        precedence_edges,
    })
}

fn validate_event_ambiguity(
    events: &[ResolvedTypestateEventSpec],
    graph: &PrecedenceGraph<TypestateEventId>,
) -> Result<(), CompositionError> {
    validate_ambiguity(
        events,
        graph,
        |event| &event.id,
        |event| &event.applies_to_subjects,
        |events, left, right, joint_dominators, subject_overlap| {
            let covered = match (&left.trigger, &right.trigger) {
                (
                    ResolvedTypestateEventTrigger::MatchEndpoints {
                        endpoints: left_endpoints,
                        phase: left_phase,
                    },
                    ResolvedTypestateEventTrigger::MatchEndpoints {
                        endpoints: right_endpoints,
                        phase: right_phase,
                    },
                ) if left_phase == right_phase => {
                    let endpoint_overlap =
                        identity_set_intersection(left_endpoints, right_endpoints);
                    if endpoint_overlap.is_empty() {
                        return Ok(None);
                    }
                    Some(event_match_overlap_is_covered(
                        events,
                        graph,
                        left,
                        right,
                        joint_dominators,
                        subject_overlap,
                        &endpoint_overlap,
                        *left_phase,
                    )?)
                }
                (
                    ResolvedTypestateEventTrigger::SemanticEvent { event: left_event },
                    ResolvedTypestateEventTrigger::SemanticEvent { event: right_event },
                ) if left_event == right_event => Some(event_semantic_overlap_is_covered(
                    events,
                    graph,
                    left,
                    right,
                    joint_dominators,
                    subject_overlap,
                    *left_event,
                )?),
                // Semantic equivalence of arbitrary call selectors, and of a
                // call selector with another trigger form, belongs to #824's
                // same-site dominance pass.
                _ => return Ok(None),
            };
            Ok(covered)
        },
        |left, right| {
            CompositionError::TypestateEventPrecedence(format!(
                "typestate events {left:?} and {right:?} overlap without a unique superseding winner"
            ))
        },
    )
}

fn validate_expectation_ambiguity(
    expectations: &[ResolvedTypestateTerminalExpectationSpec],
    graph: &PrecedenceGraph<TypestateExpectationId>,
) -> Result<(), CompositionError> {
    validate_ambiguity(
        expectations,
        graph,
        |expectation| &expectation.id,
        |expectation| &expectation.applies_to_subjects,
        |expectations, left, right, joint_dominators, subject_overlap| {
            let covered = match (&left.trigger, &right.trigger) {
                (
                    ResolvedTypestateTerminalTrigger::MatchEndpoints {
                        endpoints: left_endpoints,
                        phase: left_phase,
                    },
                    ResolvedTypestateTerminalTrigger::MatchEndpoints {
                        endpoints: right_endpoints,
                        phase: right_phase,
                    },
                ) if left_phase == right_phase => {
                    let endpoint_overlap =
                        identity_set_intersection(left_endpoints, right_endpoints);
                    if endpoint_overlap.is_empty() {
                        return Ok(None);
                    }
                    Some(expectation_match_overlap_is_covered(
                        expectations,
                        graph,
                        left,
                        right,
                        joint_dominators,
                        subject_overlap,
                        &endpoint_overlap,
                        *left_phase,
                    )?)
                }
                (
                    ResolvedTypestateTerminalTrigger::SemanticEvent { event: left_event },
                    ResolvedTypestateTerminalTrigger::SemanticEvent { event: right_event },
                ) if left_event == right_event => Some(expectation_semantic_overlap_is_covered(
                    expectations,
                    graph,
                    left,
                    right,
                    joint_dominators,
                    subject_overlap,
                    *left_event,
                )?),
                _ => return Ok(None),
            };
            Ok(covered)
        },
        |left, right| {
            CompositionError::TypestateExpectationPrecedence(format!(
                "typestate expectations {left:?} and {right:?} overlap without a unique superseding winner"
            ))
        },
    )
}

fn validate_ambiguity<T, K>(
    candidates: &[T],
    graph: &PrecedenceGraph<K>,
    candidate_id: impl for<'a> Fn(&'a T) -> &'a K,
    applicable_subjects: impl for<'a> Fn(&'a T) -> &'a [ResolvedEndpointIdentity],
    mut pair_coverage: impl FnMut(
        &[T],
        &T,
        &T,
        &[usize],
        &[&ResolvedEndpointIdentity],
    ) -> Result<Option<bool>, CompositionError>,
    conflict: impl Fn(&K, &K) -> CompositionError,
) -> Result<(), CompositionError>
where
    K: Clone + Eq + std::hash::Hash + Ord + std::fmt::Debug,
{
    for left_index in 0..candidates.len() {
        for right_index in (left_index + 1)..candidates.len() {
            let left = &candidates[left_index];
            let right = &candidates[right_index];
            let left_id = candidate_id(left);
            let right_id = candidate_id(right);
            if graph.dominates(left_id, right_id) || graph.dominates(right_id, left_id) {
                continue;
            }
            let subject_overlap =
                identity_set_intersection(applicable_subjects(left), applicable_subjects(right));
            if subject_overlap.is_empty() {
                continue;
            }
            let joint_dominators = joint_dominator_indices(
                candidates
                    .iter()
                    .enumerate()
                    .map(|(index, candidate)| (index, candidate_id(candidate))),
                graph,
                left_id,
                right_id,
            );
            let Some(covered) =
                pair_coverage(candidates, left, right, &joint_dominators, &subject_overlap)?
            else {
                continue;
            };
            if !covered {
                return Err(conflict(left_id, right_id));
            }
        }
    }
    Ok(())
}

fn joint_dominator_indices<'a, K>(
    candidate_ids: impl Iterator<Item = (usize, &'a K)>,
    graph: &PrecedenceGraph<K>,
    left: &K,
    right: &K,
) -> Vec<usize>
where
    K: Clone + Eq + std::hash::Hash + Ord + 'a,
{
    candidate_ids
        .filter(|(_, candidate)| {
            graph.dominates(candidate, left) && graph.dominates(candidate, right)
        })
        .map(|(index, _)| index)
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn event_match_overlap_is_covered(
    events: &[ResolvedTypestateEventSpec],
    graph: &PrecedenceGraph<TypestateEventId>,
    left: &ResolvedTypestateEventSpec,
    right: &ResolvedTypestateEventSpec,
    joint_dominators: &[usize],
    subjects: &[&ResolvedEndpointIdentity],
    endpoints: &[&ResolvedEndpointIdentity],
    phase: EndpointObservationPhase,
) -> Result<bool, CompositionError> {
    let fully_applicable = joint_dominators
        .iter()
        .copied()
        .filter(|index| event_covers_match_region(&events[*index], subjects, endpoints, phase))
        .map(|index| events[index].id.clone());
    overlap_is_covered(
        graph,
        &left.id,
        &right.id,
        fully_applicable,
        subjects,
        |subject| {
            endpoints.iter().all(|endpoint| {
                joint_dominators.iter().any(|index| {
                    event_applies_to_match_point(&events[*index], subject, endpoint, phase)
                })
            })
        },
    )
    .map_err(|error| CompositionError::TypestateEventPrecedence(error.to_string()))
}

fn event_semantic_overlap_is_covered(
    events: &[ResolvedTypestateEventSpec],
    graph: &PrecedenceGraph<TypestateEventId>,
    left: &ResolvedTypestateEventSpec,
    right: &ResolvedTypestateEventSpec,
    joint_dominators: &[usize],
    subjects: &[&ResolvedEndpointIdentity],
    event: PolicySemanticEvent,
) -> Result<bool, CompositionError> {
    let fully_applicable = joint_dominators
        .iter()
        .copied()
        .filter(|index| event_covers_semantic_region(&events[*index], subjects, event))
        .map(|index| events[index].id.clone());
    overlap_is_covered(
        graph,
        &left.id,
        &right.id,
        fully_applicable,
        subjects,
        |subject| {
            joint_dominators
                .iter()
                .any(|index| event_applies_to_semantic_point(&events[*index], subject, event))
        },
    )
    .map_err(|error| CompositionError::TypestateEventPrecedence(error.to_string()))
}

#[allow(clippy::too_many_arguments)]
fn expectation_match_overlap_is_covered(
    expectations: &[ResolvedTypestateTerminalExpectationSpec],
    graph: &PrecedenceGraph<TypestateExpectationId>,
    left: &ResolvedTypestateTerminalExpectationSpec,
    right: &ResolvedTypestateTerminalExpectationSpec,
    joint_dominators: &[usize],
    subjects: &[&ResolvedEndpointIdentity],
    endpoints: &[&ResolvedEndpointIdentity],
    phase: EndpointObservationPhase,
) -> Result<bool, CompositionError> {
    let fully_applicable = joint_dominators
        .iter()
        .copied()
        .filter(|index| {
            expectation_covers_match_region(&expectations[*index], subjects, endpoints, phase)
        })
        .map(|index| expectations[index].id.clone());
    overlap_is_covered(
        graph,
        &left.id,
        &right.id,
        fully_applicable,
        subjects,
        |subject| {
            endpoints.iter().all(|endpoint| {
                joint_dominators.iter().any(|index| {
                    expectation_applies_to_match_point(
                        &expectations[*index],
                        subject,
                        endpoint,
                        phase,
                    )
                })
            })
        },
    )
    .map_err(|error| CompositionError::TypestateExpectationPrecedence(error.to_string()))
}

fn expectation_semantic_overlap_is_covered(
    expectations: &[ResolvedTypestateTerminalExpectationSpec],
    graph: &PrecedenceGraph<TypestateExpectationId>,
    left: &ResolvedTypestateTerminalExpectationSpec,
    right: &ResolvedTypestateTerminalExpectationSpec,
    joint_dominators: &[usize],
    subjects: &[&ResolvedEndpointIdentity],
    event: PolicySemanticEvent,
) -> Result<bool, CompositionError> {
    let fully_applicable = joint_dominators
        .iter()
        .copied()
        .filter(|index| expectation_covers_semantic_region(&expectations[*index], subjects, event))
        .map(|index| expectations[index].id.clone());
    overlap_is_covered(
        graph,
        &left.id,
        &right.id,
        fully_applicable,
        subjects,
        |subject| {
            joint_dominators.iter().any(|index| {
                expectation_applies_to_semantic_point(&expectations[*index], subject, event)
            })
        },
    )
    .map_err(|error| CompositionError::TypestateExpectationPrecedence(error.to_string()))
}

fn overlap_is_covered<K>(
    graph: &PrecedenceGraph<K>,
    left: &K,
    right: &K,
    fully_applicable: impl IntoIterator<Item = K>,
    subjects: &[&ResolvedEndpointIdentity],
    point_is_covered: impl Fn(&ResolvedEndpointIdentity) -> bool,
) -> Result<bool, PrecedenceError<K>>
where
    K: Clone + Eq + std::hash::Hash + Ord,
{
    let fully_applicable = fully_applicable.into_iter().collect::<Vec<_>>();
    if !fully_applicable.is_empty() {
        graph.unique_winner(
            [left.clone(), right.clone()]
                .into_iter()
                .chain(fully_applicable),
        )?;
        return Ok(true);
    }
    Ok(subjects.iter().all(|subject| point_is_covered(subject)))
}

fn match_region_is_covered(
    candidate_subjects: &[ResolvedEndpointIdentity],
    candidate_endpoints: &[ResolvedEndpointIdentity],
    candidate_phase: EndpointObservationPhase,
    subjects: &[&ResolvedEndpointIdentity],
    endpoints: &[&ResolvedEndpointIdentity],
    phase: EndpointObservationPhase,
) -> bool {
    subjects
        .iter()
        .all(|subject| candidate_subjects.contains(subject))
        && candidate_phase == phase
        && endpoints
            .iter()
            .all(|endpoint| candidate_endpoints.contains(endpoint))
}

fn semantic_region_is_covered(
    candidate_subjects: &[ResolvedEndpointIdentity],
    candidate_event: PolicySemanticEvent,
    subjects: &[&ResolvedEndpointIdentity],
    event: PolicySemanticEvent,
) -> bool {
    candidate_event == event
        && subjects
            .iter()
            .all(|subject| candidate_subjects.contains(subject))
}

fn event_covers_match_region(
    candidate: &ResolvedTypestateEventSpec,
    subjects: &[&ResolvedEndpointIdentity],
    endpoints: &[&ResolvedEndpointIdentity],
    phase: EndpointObservationPhase,
) -> bool {
    let ResolvedTypestateEventTrigger::MatchEndpoints {
        endpoints: candidate_endpoints,
        phase: candidate_phase,
    } = &candidate.trigger
    else {
        return false;
    };
    match_region_is_covered(
        &candidate.applies_to_subjects,
        candidate_endpoints,
        *candidate_phase,
        subjects,
        endpoints,
        phase,
    )
}

fn event_applies_to_match_point(
    candidate: &ResolvedTypestateEventSpec,
    subject: &ResolvedEndpointIdentity,
    endpoint: &ResolvedEndpointIdentity,
    phase: EndpointObservationPhase,
) -> bool {
    let ResolvedTypestateEventTrigger::MatchEndpoints {
        endpoints: candidate_endpoints,
        phase: candidate_phase,
    } = &candidate.trigger
    else {
        return false;
    };
    match_region_is_covered(
        &candidate.applies_to_subjects,
        candidate_endpoints,
        *candidate_phase,
        std::slice::from_ref(&subject),
        std::slice::from_ref(&endpoint),
        phase,
    )
}

fn event_covers_semantic_region(
    candidate: &ResolvedTypestateEventSpec,
    subjects: &[&ResolvedEndpointIdentity],
    event: PolicySemanticEvent,
) -> bool {
    let ResolvedTypestateEventTrigger::SemanticEvent {
        event: candidate_event,
    } = &candidate.trigger
    else {
        return false;
    };
    semantic_region_is_covered(
        &candidate.applies_to_subjects,
        *candidate_event,
        subjects,
        event,
    )
}

fn event_applies_to_semantic_point(
    candidate: &ResolvedTypestateEventSpec,
    subject: &ResolvedEndpointIdentity,
    event: PolicySemanticEvent,
) -> bool {
    let ResolvedTypestateEventTrigger::SemanticEvent {
        event: candidate_event,
    } = &candidate.trigger
    else {
        return false;
    };
    semantic_region_is_covered(
        &candidate.applies_to_subjects,
        *candidate_event,
        std::slice::from_ref(&subject),
        event,
    )
}

fn expectation_covers_match_region(
    candidate: &ResolvedTypestateTerminalExpectationSpec,
    subjects: &[&ResolvedEndpointIdentity],
    endpoints: &[&ResolvedEndpointIdentity],
    phase: EndpointObservationPhase,
) -> bool {
    let ResolvedTypestateTerminalTrigger::MatchEndpoints {
        endpoints: candidate_endpoints,
        phase: candidate_phase,
    } = &candidate.trigger
    else {
        return false;
    };
    match_region_is_covered(
        &candidate.applies_to_subjects,
        candidate_endpoints,
        *candidate_phase,
        subjects,
        endpoints,
        phase,
    )
}

fn expectation_applies_to_match_point(
    candidate: &ResolvedTypestateTerminalExpectationSpec,
    subject: &ResolvedEndpointIdentity,
    endpoint: &ResolvedEndpointIdentity,
    phase: EndpointObservationPhase,
) -> bool {
    let ResolvedTypestateTerminalTrigger::MatchEndpoints {
        endpoints: candidate_endpoints,
        phase: candidate_phase,
    } = &candidate.trigger
    else {
        return false;
    };
    match_region_is_covered(
        &candidate.applies_to_subjects,
        candidate_endpoints,
        *candidate_phase,
        std::slice::from_ref(&subject),
        std::slice::from_ref(&endpoint),
        phase,
    )
}

fn expectation_covers_semantic_region(
    candidate: &ResolvedTypestateTerminalExpectationSpec,
    subjects: &[&ResolvedEndpointIdentity],
    event: PolicySemanticEvent,
) -> bool {
    let ResolvedTypestateTerminalTrigger::SemanticEvent {
        event: candidate_event,
    } = &candidate.trigger
    else {
        return false;
    };
    semantic_region_is_covered(
        &candidate.applies_to_subjects,
        *candidate_event,
        subjects,
        event,
    )
}

fn expectation_applies_to_semantic_point(
    candidate: &ResolvedTypestateTerminalExpectationSpec,
    subject: &ResolvedEndpointIdentity,
    event: PolicySemanticEvent,
) -> bool {
    let ResolvedTypestateTerminalTrigger::SemanticEvent {
        event: candidate_event,
    } = &candidate.trigger
    else {
        return false;
    };
    semantic_region_is_covered(
        &candidate.applies_to_subjects,
        *candidate_event,
        std::slice::from_ref(&subject),
        event,
    )
}

fn identity_set_intersection<'a>(
    left: &'a [ResolvedEndpointIdentity],
    right: &[ResolvedEndpointIdentity],
) -> Vec<&'a ResolvedEndpointIdentity> {
    left.iter()
        .filter(|identity| right.contains(identity))
        .collect()
}

fn validate_automaton_shape(
    automaton: &TypestateAutomatonSpec,
    limits: CompositionLimits,
) -> Result<(), CompositionError> {
    if automaton.states.is_empty() {
        return invalid_automaton("typestate automaton must contain at least one state");
    }
    if automaton.states.len() > 256 {
        return invalid_automaton("typestate automaton contains more than 256 states");
    }
    let states: HashSet<_> = automaton.states.iter().collect();
    if states.len() != automaton.states.len() {
        return invalid_automaton("typestate automaton repeats a state");
    }
    if !states.contains(&automaton.initial) {
        return invalid_automaton("typestate initial state is not declared");
    }
    if automaton.accepting_states.is_empty() || automaton.error_states.is_empty() {
        return invalid_automaton("accepting and error state sets must both be non-empty");
    }
    if automaton
        .accepting_states
        .iter()
        .chain(&automaton.error_states)
        .any(|state| !states.contains(state))
    {
        return invalid_automaton("accepting or error state is not declared");
    }
    if automaton
        .accepting_states
        .iter()
        .any(|state| automaton.error_states.contains(state))
    {
        return invalid_automaton("accepting and error state sets must be disjoint");
    }
    if automaton.events.len() > limits.max_typestate_events()
        || automaton.terminal_expectations.len() > limits.max_typestate_expectations()
        || automaton.transitions.len() > 4_096
    {
        return invalid_automaton("typestate automaton exceeds a schema-v1 collection bound");
    }
    let event_ids: HashSet<_> = automaton.events.iter().map(|event| &event.id).collect();
    if event_ids.len() != automaton.events.len() {
        return invalid_automaton("typestate automaton repeats an event ID");
    }
    let expectation_ids: HashSet<_> = automaton
        .terminal_expectations
        .iter()
        .map(|expectation| &expectation.id)
        .collect();
    if expectation_ids.len() != automaton.terminal_expectations.len() {
        return invalid_automaton("typestate automaton repeats a terminal expectation ID");
    }
    let mut transition_keys = HashSet::new();
    for transition in &automaton.transitions {
        if !states.contains(&transition.from)
            || !states.contains(&transition.to)
            || !event_ids.contains(&transition.on)
        {
            return invalid_automaton("typestate transition names an undeclared state or event");
        }
        if !transition_keys.insert((&transition.from, &transition.on)) {
            return invalid_automaton("typestate transition repeats a (state, event) key");
        }
    }
    for expectation in &automaton.terminal_expectations {
        if expectation.expected_states.is_empty()
            || expectation
                .expected_states
                .iter()
                .any(|state| !automaton.accepting_states.contains(state))
        {
            return invalid_automaton(
                "terminal expected states must be a non-empty accepting-state subset",
            );
        }
    }
    Ok(())
}

fn invalid_automaton<T>(message: impl Into<String>) -> Result<T, CompositionError> {
    Err(CompositionError::InvalidTypestateAutomaton(message.into()))
}

fn event_selector_path(id: &TypestateEventId) -> Result<PolicySelectorPath, CompositionError> {
    PolicySelectorPath::new(format!(
        "/analysis/automaton/events/{}/selector",
        id.as_str()
    ))
    .map_err(|error| CompositionError::LoadedModel(error.to_string()))
}

fn resolve_observed_match_set(
    set: &MatchEndpointSetRef,
    role: EndpointRole,
    phase: EndpointObservationPhase,
    universe: &EndpointUniverse,
    manifests: &[ResolvedMatchDirectoryManifest],
) -> Result<MatchSelection, CompositionError> {
    let selected = universe.select_match_set(set, role, false, manifests)?;
    for identity in &selected.identities {
        universe.validate_observation(identity, phase)?;
    }
    Ok(selected)
}

fn merge_typestate_manifests(
    manifests: impl IntoIterator<Item = ResolvedMatchDirectoryManifest>,
) -> Result<Vec<ResolvedMatchDirectoryManifest>, CompositionError> {
    let mut manifests: Vec<_> = manifests.into_iter().collect();
    manifests.sort_by(|left, right| left.path.cmp(&right.path));
    let mut result: Vec<ResolvedMatchDirectoryManifest> = Vec::new();
    for manifest in manifests {
        if let Some(existing) = result.last()
            && existing.path == manifest.path
        {
            if existing.semantic_hash != manifest.semantic_hash {
                return Err(CompositionError::LoadedModel(format!(
                    "match manifest path {} resolves to conflicting hashes",
                    manifest.path
                )));
            }
            continue;
        }
        result.push(manifest);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_analysis::schema_version::{SchemaVersionOrigin, SchemaVersionResolution};

    fn endpoint(
        id: &str,
        role: EndpointRole,
        binding: PolicyEndpointBinding,
        seed: u8,
    ) -> ResolvedEndpointDependency {
        crate::test_support::resolved_endpoint_dependency(
            ResolvedEndpointIdentity::MatchEndpoint {
                endpoint_id: EndpointId::new(id).unwrap(),
            },
            SchemaVersionResolution {
                version: 1,
                origin: SchemaVersionOrigin::Explicit,
            },
            PolicySelectorPath::new(format!("/dependencies/match-endpoints/{id}/selector"))
                .unwrap(),
            SchemaVersionResolution {
                version: 2,
                origin: SchemaVersionOrigin::Explicit,
            },
            ResolvedEndpointModel::new(
                role,
                id.to_string(),
                vec![
                    PolicyCategoryId::new(match role {
                        EndpointRole::Source => "resource.acquire",
                        EndpointRole::Sink => "resource.close",
                    })
                    .unwrap(),
                ],
                binding,
                None,
                vec![],
            ),
            PolicyDependencyPath::new(format!("/endpoints/{id}")).unwrap(),
            seed,
            seed.wrapping_add(64),
        )
    }

    fn exact(id: &str) -> MatchEndpointSetRef {
        MatchEndpointSetRef::Exact {
            endpoint_ids: vec![EndpointId::new(id).unwrap()],
        }
    }

    #[test]
    fn typestate_reuses_source_subject_and_sink_event_endpoint_sets() {
        let policy_id = PolicyId::new("test.resource-lifecycle").unwrap();
        let dependencies = vec![
            endpoint(
                "resource-open",
                EndpointRole::Source,
                PolicyEndpointBinding::ReturnValue,
                1,
            ),
            endpoint(
                "resource-close",
                EndpointRole::Sink,
                PolicyEndpointBinding::Receiver,
                2,
            ),
        ];
        let open = TypestateStateId::new("open").unwrap();
        let closed = TypestateStateId::new("closed").unwrap();
        let error = TypestateStateId::new("error").unwrap();
        let close_event = TypestateEventId::new("close").unwrap();
        let expectation = TypestateExpectationId::new("close-reaches-closed").unwrap();
        let spec = TypestatePolicySpec {
            mode: MayMode::May,
            call_modeling: CallModelingSpec::default(),
            subjects: TypestateSubjectSet {
                include_matches: vec![exact("resource-open")],
                entries: vec![],
            },
            uncertainty: TypestateUncertaintySpec {
                escape: InconclusivePolicy::Inconclusive,
            },
            automaton: TypestateAutomatonSpec {
                states: vec![error.clone(), open.clone(), closed.clone()],
                initial: open.clone(),
                accepting_states: vec![closed.clone()],
                error_states: vec![error],
                events: vec![TypestateEventSpec {
                    id: close_event.clone(),
                    trigger: TypestateEventTrigger::MatchEndpoints {
                        set: exact("resource-close"),
                        role: EndpointRole::Sink,
                        phase: EndpointObservationPhase::AfterNormalReturn,
                    },
                    applies_to_subjects: None,
                    supersedes: vec![],
                }],
                transitions: vec![TypestateTransitionSpec {
                    from: open,
                    on: close_event,
                    to: closed.clone(),
                }],
                terminal_expectations: vec![TypestateTerminalExpectationSpec {
                    id: expectation,
                    trigger: TypestateTerminalTrigger::MatchEndpoints {
                        set: exact("resource-close"),
                        role: EndpointRole::Sink,
                        phase: EndpointObservationPhase::AfterNormalReturn,
                    },
                    applies_to_subjects: None,
                    expected_states: vec![closed],
                    supersedes: vec![],
                }],
            },
        };
        let catalogs = TaintCatalogRegistry::new_without_workspace(Default::default());
        let composed = compose_typestate_policy(
            &policy_id,
            &spec,
            &catalogs,
            &dependencies,
            &[],
            CompositionLimits::default(),
        )
        .unwrap();

        assert_eq!(composed.spec.subjects.len(), 1);
        assert_eq!(composed.spec.endpoint_dependencies.len(), 2);
        let ResolvedTypestateEventTrigger::MatchEndpoints { endpoints, .. } =
            &composed.spec.automaton.events[0].trigger
        else {
            panic!("expected endpoint event")
        };
        assert_eq!(endpoints.len(), 1);
        let ResolvedTypestateTerminalTrigger::MatchEndpoints { endpoints, .. } =
            &composed.spec.automaton.terminal_expectations[0].trigger
        else {
            panic!("expected endpoint terminal")
        };
        assert_eq!(endpoints.len(), 1);
        assert!(
            composed
                .spec
                .endpoint_dependencies
                .iter()
                .any(|dependency| dependency.identity == endpoints[0])
        );
    }

    #[test]
    fn third_dominator_resolves_event_and_expectation_overlap() {
        let subject = ResolvedEndpointIdentity::MatchEndpoint {
            endpoint_id: EndpointId::new("resource-open").unwrap(),
        };
        let semantic_event = PolicySemanticEvent::NormalProcedureExit {
            scope: TypestateExitScope::AnalysisRoot,
        };

        let first_event = TypestateEventId::new("first-event").unwrap();
        let second_event = TypestateEventId::new("second-event").unwrap();
        let winning_event = TypestateEventId::new("winning-event").unwrap();
        let events = vec![
            ResolvedTypestateEventSpec::new(
                first_event.clone(),
                ResolvedTypestateEventTrigger::SemanticEvent {
                    event: semantic_event,
                },
                vec![subject.clone()],
                vec![],
            ),
            ResolvedTypestateEventSpec::new(
                second_event.clone(),
                ResolvedTypestateEventTrigger::SemanticEvent {
                    event: semantic_event,
                },
                vec![subject.clone()],
                vec![],
            ),
            ResolvedTypestateEventSpec::new(
                winning_event.clone(),
                ResolvedTypestateEventTrigger::SemanticEvent {
                    event: semantic_event,
                },
                vec![subject.clone()],
                vec![first_event.clone(), second_event.clone()],
            ),
        ];
        let event_graph = PrecedenceGraph::try_new(
            [
                first_event.clone(),
                second_event.clone(),
                winning_event.clone(),
            ],
            [
                (winning_event.clone(), first_event),
                (winning_event, second_event),
            ],
        )
        .unwrap();
        validate_event_ambiguity(&events, &event_graph).unwrap();

        let first_expectation = TypestateExpectationId::new("first-expectation").unwrap();
        let second_expectation = TypestateExpectationId::new("second-expectation").unwrap();
        let winning_expectation = TypestateExpectationId::new("winning-expectation").unwrap();
        let expected_state = TypestateStateId::new("closed").unwrap();
        let expectations = vec![
            ResolvedTypestateTerminalExpectationSpec::new(
                first_expectation.clone(),
                ResolvedTypestateTerminalTrigger::SemanticEvent {
                    event: semantic_event,
                },
                vec![subject.clone()],
                vec![expected_state.clone()],
                vec![],
            ),
            ResolvedTypestateTerminalExpectationSpec::new(
                second_expectation.clone(),
                ResolvedTypestateTerminalTrigger::SemanticEvent {
                    event: semantic_event,
                },
                vec![subject.clone()],
                vec![expected_state.clone()],
                vec![],
            ),
            ResolvedTypestateTerminalExpectationSpec::new(
                winning_expectation.clone(),
                ResolvedTypestateTerminalTrigger::SemanticEvent {
                    event: semantic_event,
                },
                vec![subject],
                vec![expected_state],
                vec![first_expectation.clone(), second_expectation.clone()],
            ),
        ];
        let expectation_graph = PrecedenceGraph::try_new(
            [
                first_expectation.clone(),
                second_expectation.clone(),
                winning_expectation.clone(),
            ],
            [
                (winning_expectation.clone(), first_expectation),
                (winning_expectation, second_expectation),
            ],
        )
        .unwrap();
        validate_expectation_ambiguity(&expectations, &expectation_graph).unwrap();
    }
}
