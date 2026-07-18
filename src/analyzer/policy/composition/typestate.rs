//! Setwise typestate endpoint and predicate composition.

use std::collections::HashSet;

use super::common::*;
use super::precedence::{PrecedenceError, PrecedenceGraph};
use crate::analyzer::policy::catalog::{TaintCatalogRegistry, typestate_seed_binding_to_port};
use crate::analyzer::policy::definition::*;
use crate::analyzer::policy::resolved::*;

#[derive(Debug, Clone)]
pub struct ComposedTypestatePolicy {
    pub spec: ResolvedTypestatePolicySpec,
    pub precedence: PolicyPrecedenceManifest,
}

#[allow(clippy::too_many_arguments)]
pub fn compose_typestate_policy(
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
            TypestateEventTrigger::Calls { subject, phase, .. } => {
                validate_call_phase(*phase, subject)?;
                ResolvedTypestateEventTrigger::Calls {
                    selector_path: event_selector_path(&event.id)?,
                    subject: subject.clone(),
                    phase: *phase,
                }
            }
            TypestateEventTrigger::MatchEndpoints { set, role, phase } => {
                let selected = universe.select_match_set(set, *role, false, manifests)?;
                for identity in &selected.identities {
                    universe.validate_observation(identity, *phase)?;
                }
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
                let selected = universe.select_match_set(set, *role, false, manifests)?;
                for identity in &selected.identities {
                    universe.validate_observation(identity, *phase)?;
                }
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
    for left_index in 0..events.len() {
        for right_index in (left_index + 1)..events.len() {
            let left = &events[left_index];
            let right = &events[right_index];
            if graph.dominates(&left.id, &right.id) || graph.dominates(&right.id, &left.id) {
                continue;
            }
            let subject_overlap =
                identity_set_intersection(&left.applies_to_subjects, &right.applies_to_subjects);
            if subject_overlap.is_empty() {
                continue;
            }

            let joint_dominators = events
                .iter()
                .enumerate()
                .filter(|(_, candidate)| {
                    graph.dominates(&candidate.id, &left.id)
                        && graph.dominates(&candidate.id, &right.id)
                })
                .map(|(index, _)| index)
                .collect::<Vec<_>>();

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
                        continue;
                    }
                    event_match_overlap_is_covered(
                        events,
                        graph,
                        left,
                        right,
                        &joint_dominators,
                        &subject_overlap,
                        &endpoint_overlap,
                        *left_phase,
                    )?
                }
                (
                    ResolvedTypestateEventTrigger::SemanticEvent { event: left_event },
                    ResolvedTypestateEventTrigger::SemanticEvent { event: right_event },
                ) if left_event == right_event => event_semantic_overlap_is_covered(
                    events,
                    graph,
                    left,
                    right,
                    &joint_dominators,
                    &subject_overlap,
                    *left_event,
                )?,
                // Semantic equivalence of arbitrary call selectors, and of a
                // call selector with another trigger form, belongs to #824's
                // same-site dominance pass.
                _ => continue,
            };
            if !covered {
                return Err(CompositionError::TypestateEventPrecedence(format!(
                    "typestate events {:?} and {:?} overlap without a unique superseding winner",
                    left.id, right.id
                )));
            }
        }
    }
    Ok(())
}

fn validate_expectation_ambiguity(
    expectations: &[ResolvedTypestateTerminalExpectationSpec],
    graph: &PrecedenceGraph<TypestateExpectationId>,
) -> Result<(), CompositionError> {
    for left_index in 0..expectations.len() {
        for right_index in (left_index + 1)..expectations.len() {
            let left = &expectations[left_index];
            let right = &expectations[right_index];
            if graph.dominates(&left.id, &right.id) || graph.dominates(&right.id, &left.id) {
                continue;
            }
            let subject_overlap =
                identity_set_intersection(&left.applies_to_subjects, &right.applies_to_subjects);
            if subject_overlap.is_empty() {
                continue;
            }

            let joint_dominators = expectations
                .iter()
                .enumerate()
                .filter(|(_, candidate)| {
                    graph.dominates(&candidate.id, &left.id)
                        && graph.dominates(&candidate.id, &right.id)
                })
                .map(|(index, _)| index)
                .collect::<Vec<_>>();

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
                        continue;
                    }
                    expectation_match_overlap_is_covered(
                        expectations,
                        graph,
                        left,
                        right,
                        &joint_dominators,
                        &subject_overlap,
                        &endpoint_overlap,
                        *left_phase,
                    )?
                }
                (
                    ResolvedTypestateTerminalTrigger::SemanticEvent { event: left_event },
                    ResolvedTypestateTerminalTrigger::SemanticEvent { event: right_event },
                ) if left_event == right_event => expectation_semantic_overlap_is_covered(
                    expectations,
                    graph,
                    left,
                    right,
                    &joint_dominators,
                    &subject_overlap,
                    *left_event,
                )?,
                _ => continue,
            };
            if !covered {
                return Err(CompositionError::TypestateExpectationPrecedence(format!(
                    "typestate expectations {:?} and {:?} overlap without a unique superseding winner",
                    left.id, right.id
                )));
            }
        }
    }
    Ok(())
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
        .collect::<Vec<_>>();
    if !fully_applicable.is_empty() {
        graph
            .unique_winner(
                [left.id.clone(), right.id.clone()].into_iter().chain(
                    fully_applicable
                        .iter()
                        .map(|index| events[*index].id.clone()),
                ),
            )
            .map_err(|error| CompositionError::TypestateEventPrecedence(error.to_string()))?;
        return Ok(true);
    }
    Ok(subjects.iter().all(|subject| {
        endpoints.iter().all(|endpoint| {
            joint_dominators.iter().any(|index| {
                event_applies_to_match_point(&events[*index], subject, endpoint, phase)
            })
        })
    }))
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
        .collect::<Vec<_>>();
    if !fully_applicable.is_empty() {
        graph
            .unique_winner(
                [left.id.clone(), right.id.clone()].into_iter().chain(
                    fully_applicable
                        .iter()
                        .map(|index| events[*index].id.clone()),
                ),
            )
            .map_err(|error| CompositionError::TypestateEventPrecedence(error.to_string()))?;
        return Ok(true);
    }
    Ok(subjects.iter().all(|subject| {
        joint_dominators
            .iter()
            .any(|index| event_applies_to_semantic_point(&events[*index], subject, event))
    }))
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
        .collect::<Vec<_>>();
    if !fully_applicable.is_empty() {
        graph
            .unique_winner(
                [left.id.clone(), right.id.clone()].into_iter().chain(
                    fully_applicable
                        .iter()
                        .map(|index| expectations[*index].id.clone()),
                ),
            )
            .map_err(|error| CompositionError::TypestateExpectationPrecedence(error.to_string()))?;
        return Ok(true);
    }
    Ok(subjects.iter().all(|subject| {
        endpoints.iter().all(|endpoint| {
            joint_dominators.iter().any(|index| {
                expectation_applies_to_match_point(&expectations[*index], subject, endpoint, phase)
            })
        })
    }))
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
        .collect::<Vec<_>>();
    if !fully_applicable.is_empty() {
        graph
            .unique_winner(
                [left.id.clone(), right.id.clone()].into_iter().chain(
                    fully_applicable
                        .iter()
                        .map(|index| expectations[*index].id.clone()),
                ),
            )
            .map_err(|error| CompositionError::TypestateExpectationPrecedence(error.to_string()))?;
        return Ok(true);
    }
    Ok(subjects.iter().all(|subject| {
        joint_dominators.iter().any(|index| {
            expectation_applies_to_semantic_point(&expectations[*index], subject, event)
        })
    }))
}

fn event_covers_match_region(
    candidate: &ResolvedTypestateEventSpec,
    subjects: &[&ResolvedEndpointIdentity],
    endpoints: &[&ResolvedEndpointIdentity],
    phase: EndpointObservationPhase,
) -> bool {
    subjects
        .iter()
        .all(|subject| candidate.applies_to_subjects.contains(subject))
        && matches!(
            &candidate.trigger,
            ResolvedTypestateEventTrigger::MatchEndpoints {
                endpoints: candidate_endpoints,
                phase: candidate_phase,
            } if *candidate_phase == phase
                && endpoints
                    .iter()
                    .all(|endpoint| candidate_endpoints.contains(endpoint))
        )
}

fn event_applies_to_match_point(
    candidate: &ResolvedTypestateEventSpec,
    subject: &ResolvedEndpointIdentity,
    endpoint: &ResolvedEndpointIdentity,
    phase: EndpointObservationPhase,
) -> bool {
    candidate.applies_to_subjects.contains(subject)
        && matches!(
            &candidate.trigger,
            ResolvedTypestateEventTrigger::MatchEndpoints {
                endpoints,
                phase: candidate_phase,
            } if *candidate_phase == phase && endpoints.contains(endpoint)
        )
}

fn event_covers_semantic_region(
    candidate: &ResolvedTypestateEventSpec,
    subjects: &[&ResolvedEndpointIdentity],
    event: PolicySemanticEvent,
) -> bool {
    subjects
        .iter()
        .all(|subject| candidate.applies_to_subjects.contains(subject))
        && matches!(
            candidate.trigger,
            ResolvedTypestateEventTrigger::SemanticEvent {
                event: candidate_event,
            } if candidate_event == event
        )
}

fn event_applies_to_semantic_point(
    candidate: &ResolvedTypestateEventSpec,
    subject: &ResolvedEndpointIdentity,
    event: PolicySemanticEvent,
) -> bool {
    candidate.applies_to_subjects.contains(subject)
        && matches!(
            candidate.trigger,
            ResolvedTypestateEventTrigger::SemanticEvent {
                event: candidate_event,
            } if candidate_event == event
        )
}

fn expectation_covers_match_region(
    candidate: &ResolvedTypestateTerminalExpectationSpec,
    subjects: &[&ResolvedEndpointIdentity],
    endpoints: &[&ResolvedEndpointIdentity],
    phase: EndpointObservationPhase,
) -> bool {
    subjects
        .iter()
        .all(|subject| candidate.applies_to_subjects.contains(subject))
        && matches!(
            &candidate.trigger,
            ResolvedTypestateTerminalTrigger::MatchEndpoints {
                endpoints: candidate_endpoints,
                phase: candidate_phase,
            } if *candidate_phase == phase
                && endpoints
                    .iter()
                    .all(|endpoint| candidate_endpoints.contains(endpoint))
        )
}

fn expectation_applies_to_match_point(
    candidate: &ResolvedTypestateTerminalExpectationSpec,
    subject: &ResolvedEndpointIdentity,
    endpoint: &ResolvedEndpointIdentity,
    phase: EndpointObservationPhase,
) -> bool {
    candidate.applies_to_subjects.contains(subject)
        && matches!(
            &candidate.trigger,
            ResolvedTypestateTerminalTrigger::MatchEndpoints {
                endpoints,
                phase: candidate_phase,
            } if *candidate_phase == phase && endpoints.contains(endpoint)
        )
}

fn expectation_covers_semantic_region(
    candidate: &ResolvedTypestateTerminalExpectationSpec,
    subjects: &[&ResolvedEndpointIdentity],
    event: PolicySemanticEvent,
) -> bool {
    subjects
        .iter()
        .all(|subject| candidate.applies_to_subjects.contains(subject))
        && matches!(
            candidate.trigger,
            ResolvedTypestateTerminalTrigger::SemanticEvent {
                event: candidate_event,
            } if candidate_event == event
        )
}

fn expectation_applies_to_semantic_point(
    candidate: &ResolvedTypestateTerminalExpectationSpec,
    subject: &ResolvedEndpointIdentity,
    event: PolicySemanticEvent,
) -> bool {
    candidate.applies_to_subjects.contains(subject)
        && matches!(
            candidate.trigger,
            ResolvedTypestateTerminalTrigger::SemanticEvent {
                event: candidate_event,
            } if candidate_event == event
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
    use crate::analyzer::policy::{EndpointAnalysisProjectionHash, EndpointSemanticHash};
    use crate::schema_version::{SchemaVersionOrigin, SchemaVersionResolution};

    fn endpoint(
        id: &str,
        role: EndpointRole,
        binding: PolicyEndpointBinding,
        seed: u8,
    ) -> ResolvedEndpointDependency {
        ResolvedEndpointDependency::new(
            ResolvedEndpointIdentity::MatchEndpoint {
                endpoint_id: EndpointId::new(id).unwrap(),
            },
            EndpointDefinitionSchemaResolution::PolicyDocument {
                resolution: SchemaVersionResolution {
                    version: 1,
                    origin: SchemaVersionOrigin::Explicit,
                },
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
            EndpointSemanticHash::from_bytes([seed; 32]),
            EndpointAnalysisProjectionHash::from_bytes([seed.wrapping_add(64); 32]),
            vec![EndpointOrigin::PolicyLocal {
                path: PolicyDependencyPath::new(format!("/endpoints/{id}")).unwrap(),
            }],
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
            subjects: TypestateSubjectSet {
                include_matches: vec![exact("resource-open")],
                entries: vec![],
            },
            uncertainty: TypestateUncertaintySpec {
                unknown_call: InconclusivePolicy::Inconclusive,
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
