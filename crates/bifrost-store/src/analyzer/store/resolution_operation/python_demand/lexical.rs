//! M4-3a API for the Python source-route adapter (M4-3b).
//!
//! `lexical_selection(rows, reference_site, name, profile, proofs)` creates one
//! query-local PythonLexical. `lexical_parent(&state, rows, scope)` reads its name-dependent semantic
//! continuation. `lexical_tier(&mut state, rows, scope, budget)` reduces ONE
//! scope; `outer_can_compete(&state)` bounds further traversal. The adapter owns
//! no scope walk: use the existing shared lexical selector. Map newly selected
//! occurrence IDs to authored source targets/RouteLocations with TemporalRank(0),
//! retaining each actual declaring scope. All reduced alternatives share that
//! cohort, including region-qualified class outer fallback. Provider pruning is
//! false. `selection.open/stopped` must enter the adapter's completion ledger.
//!
//! Proofs are query-local selected authority, never spelling heuristics: callers
//! may list a typing predicate only after proving its operand is the canonical
//! typing.TYPE_CHECKING binding, and an import only after proving activation.
pub(crate) use crate::analyzer::resolution::temporal_binding::TemporalRank;
use crate::analyzer::resolution::temporal_binding::{
    Effect, Event, EventOrdering, Region, TemporalBudget, TemporalSelection,
};
use crate::analyzer::store::python_binding_rows::PythonBindingRows;
use brokk_bifrost_core::analyzer::resolution_facts::{
    PythonNativeGuardKind, PythonNativePredicateKind, ResolutionBindingEventKind,
    ResolutionBindingObservationFact, ResolutionBindingObservationKind,
};

#[derive(Clone, Copy, Debug)]
pub(crate) enum PythonBindingProfile {
    Runtime,
    Typing,
}
#[derive(Clone, Debug)]
pub(crate) struct PythonRouteBinding {
    pub(crate) occurrence: u32,
    pub(crate) import_site: u32,
    pub(crate) name: String,
    pub(crate) certain: bool,
    pub(crate) completion: crate::analyzer::resolution::ResolutionCompletion,
}
#[derive(Debug, Default)]
pub(crate) struct PythonBindingProofs {
    pub(crate) typing_predicates: Vec<u32>,
    pub(crate) activated_imports: Vec<u32>,
    /// Selected invocation/module authority proves these external cells have
    /// reached their normal completion point for this observation.
    pub(crate) completed_scopes: Vec<u32>,
    /// Complete cell inventory plus current mutation checks prove this name
    /// absent in every observation. This does not claim invocation/completion.
    pub(crate) absent_scopes: Vec<u32>,
    /// One event per import write, not per alternative target. The route
    /// adapter retains all target/provider alternatives under that event.
    /// Occurrences must be disjoint from retained binding-event ordinals.
    pub(crate) route_bindings: Vec<PythonRouteBinding>,
    pub(crate) absent_star_members: Vec<(u32, String)>,
    pub(crate) source_completion: Option<crate::analyzer::resolution::ResolutionCompletion>,
}
#[derive(Debug)]
struct Observation {
    reference: Option<u32>,
    execution_scope: brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId,
    point_byte: usize,
    kind: ResolutionBindingObservationKind,
}
impl From<ResolutionBindingObservationFact> for Observation {
    fn from(source: ResolutionBindingObservationFact) -> Self {
        Self {
            reference: Some(source.reference.get()),
            execution_scope: source.execution_scope,
            point_byte: source.point_byte,
            kind: source.kind,
        }
    }
}

#[derive(Debug)]
pub(crate) struct PythonLexical {
    pub(crate) selection: TemporalSelection,
    pub(crate) start_scope: u32,
    observation: Observation,
    name: String,
    profile: PythonBindingProfile,
    proofs: PythonBindingProofs,
}

pub(crate) fn lexical_selection(
    rows: &PythonBindingRows,
    reference_site: u32,
    name: &str,
    profile: PythonBindingProfile,
    proofs: PythonBindingProofs,
) -> Option<PythonLexical> {
    let observation = *rows
        .observations
        .iter()
        .find(|observation| observation.reference.get() == reference_site)?;
    let (region, _) = guard_region(rows, reference_site, profile, &proofs);
    let mut selection = TemporalSelection::new(region?);
    selection.open = guard_chain(rows, reference_site).iter().any(|guard| {
        matches!(
            guard.kind,
            PythonNativeGuardKind::LoopBody
                | PythonNativeGuardKind::LoopElse
                | PythonNativeGuardKind::UnknownControl
        )
    });
    // Loop branch regions are not iteration-aware: an earlier iteration's
    // write in another arm could otherwise be excluded from this read.
    if let Some(completion) = &proofs.source_completion {
        selection.completion = selection.completion.combine(completion);
    }
    let redirect = directive(rows, observation.execution_scope.get(), name);
    let mut start_scope = observation.execution_scope.get();
    if let Some(redirect) = redirect {
        if let Some(slot) = redirect
            .fact
            .target
            .and_then(|target| rows.slots.iter().find(|slot| slot.slot == target.get()))
        {
            start_scope = slot.scope;
        } else {
            selection.open = true;
            selection.residual.clear();
        }
    }
    Some(PythonLexical {
        selection,
        start_scope,
        observation: observation.into(),
        name: name.to_owned(),
        profile,
        proofs,
    })
}

/// A module export observes a completion boundary, not a fabricated source
/// reference. Initialization remains open unless its selected proof is supplied.
pub(crate) fn module_selection(
    rows: &PythonBindingRows,
    scope: u32,
    name: &str,
    profile: PythonBindingProfile,
    proofs: PythonBindingProofs,
) -> PythonLexical {
    assert!(
        rows.scopes
            .iter()
            .any(|row| row.scope == scope && row.parent.is_none()),
        "module selection requires source-root authority, not an environment container"
    );
    completed_scope_selection(scope, name, profile, proofs)
}

/// A selected authored class's completed body is a dictionary boundary, not an
/// environment module and not a fabricated positioned name reference.
pub(crate) fn class_selection(
    rows: &PythonBindingRows,
    scope: u32,
    name: &str,
    profile: PythonBindingProfile,
    proofs: PythonBindingProofs,
) -> PythonLexical {
    assert!(
        rows.scopes
            .iter()
            .any(|row| row.scope == scope && row.parent.is_some()),
        "class dictionary has its own source scope"
    );
    assert!(
        proofs.completed_scopes.contains(&scope),
        "selected class construction completed its body"
    );
    completed_scope_selection(scope, name, profile, proofs)
}

fn completed_scope_selection(
    scope: u32,
    name: &str,
    profile: PythonBindingProfile,
    proofs: PythonBindingProofs,
) -> PythonLexical {
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId;
    let mut selection = TemporalSelection::new(Region::default());
    selection.open = !proofs.completed_scopes.contains(&scope);
    if let Some(completion) = &proofs.source_completion {
        selection.completion = selection.completion.combine(completion);
    }
    PythonLexical {
        selection,
        start_scope: scope,
        observation: Observation {
            reference: None,
            execution_scope: ResolutionScopeId::new(scope),
            point_byte: usize::MAX,
            kind: ResolutionBindingObservationKind::Immediate,
        },
        name: name.to_owned(),
        profile,
        proofs,
    }
}

fn directive<'a>(
    rows: &'a PythonBindingRows,
    scope: u32,
    name: &str,
) -> Option<&'a crate::analyzer::store::python_binding_rows::BindingDirective> {
    rows.directives.iter().find(|directive| {
        directive.name == name
            && rows.observations.iter().any(|row| {
                row.reference == directive.fact.reference && row.execution_scope.get() == scope
            })
    })
}

pub(crate) fn lexical_parent(
    state: &PythonLexical,
    rows: &PythonBindingRows,
    scope: u32,
) -> Option<u32> {
    // An enclosing global/nonlocal directive also redirects free lookups from
    // nested functions and comprehensions. It is a name-dependent continuation,
    // not a second scope walk, and a child's own whole-scope local still wins.
    if let Some(redirect) = directive(rows, scope, &state.name) {
        let target = redirect.fact.target?;
        let target = rows
            .slots
            .iter()
            .find(|slot| slot.slot == target.get())
            .expect("retained directive target")
            .scope;
        if target != scope {
            return Some(target);
        }
    }
    let parent = rows
        .scopes
        .iter()
        .find(|row| row.scope == scope)
        .expect("selected scope")
        .parent;
    if parent.is_some()
        && rows
            .slots
            .iter()
            .any(|slot| slot.scope == scope && slot.name == state.name && !slot.whole_scope)
    {
        // The supported ordered cells are module/class cells. A class-local
        // hole uses globals (LOAD_NAME), while a free class-body name can use
        // an enclosing function cell (LOAD_CLASSDEREF). No private scope walk.
        return Some(
            rows.scopes
                .iter()
                .find(|row| row.parent.is_none())
                .expect("source module scope")
                .scope,
        );
    }
    parent
}

pub(crate) fn lexical_tier(
    state: &mut PythonLexical,
    rows: &PythonBindingRows,
    scope: u32,
    budget: &mut impl TemporalBudget,
) {
    if directive(rows, scope, &state.name).is_some_and(|row| row.fact.target.is_none()) {
        state.selection.open = true;
        state.selection.residual.clear();
        return;
    }
    let slot = rows
        .slots
        .iter()
        .find(|slot| slot.scope == scope && slot.name == state.name);
    let whole_scope = slot.is_some_and(|slot| slot.whole_scope);
    let deferred_external = state.observation.kind == ResolutionBindingObservationKind::Deferred
        && state.observation.execution_scope.get() != scope;
    let observed_guards = state
        .observation
        .reference
        .map(|site| guard_chain(rows, site))
        .unwrap_or_default();
    let mut events = rows
        .events
        .iter()
        .filter(|event| slot.is_some_and(|slot| event.slot == slot.slot))
        .map(|event| {
            let (region, guard_open) = if event.kind == ResolutionBindingEventKind::Parameter {
                // Invocation entry initializes parameters; creation-time guards
                // on a conditional def are not conditions on its body bindings.
                (Some(Region::default()), false)
            } else {
                guard_region(rows, event.target, state.profile, &state.proofs)
            };
            let event_guards = guard_chain(rows, event.target);
            let iteration_active = event.kind == ResolutionBindingEventKind::Iteration
                && event_guards.iter().any(|guard| {
                    guard.kind == PythonNativeGuardKind::LoopBody
                        && observed_guards
                            .iter()
                            .any(|observed| observed.id == guard.id)
                });
            let committed = event.commit_byte <= state.observation.point_byte || iteration_active;
            let previous_iteration = !committed
                && event_guards.iter().any(|guard| {
                    guard.kind == PythonNativeGuardKind::LoopBody
                        && observed_guards
                            .iter()
                            .any(|observed| observed.id == guard.id)
                });
            let same_execution = event.execution_scope == state.observation.execution_scope.get();
            let known_outer_execution = event.execution_scope == scope
                && (!deferred_external || state.proofs.completed_scopes.contains(&scope));
            let effect = if region.is_none()
                || ((same_execution || !deferred_external) && !committed && !previous_iteration)
            {
                Effect::NoWrite
            } else {
                match event.kind {
                    ResolutionBindingEventKind::Delete => Effect::Delete,
                    ResolutionBindingEventKind::Annotation => Effect::NoWrite,
                    _ => Effect::Write,
                }
            };
            let activation = event.kind != ResolutionBindingEventKind::Import
                || rows.imports.iter().any(|import| {
                    import.binding_event == Some(event.event)
                        && state
                            .proofs
                            .activated_imports
                            .contains(&import.import_site.get())
                });
            (
                event.commit_byte,
                event.phase,
                event.event,
                Event {
                    occurrence: event.event,
                    point: (event.commit_byte, event.phase, event.event),
                    completion: crate::analyzer::resolution::ResolutionCompletion::Complete,
                    ordering: if previous_iteration || !(same_execution || known_outer_execution) {
                        EventOrdering::Unordered
                    } else {
                        EventOrdering::Positioned
                    },
                    region: region.unwrap_or_default(),
                    effect,
                    certain: activation
                        && (!guard_open || iteration_active)
                        && !previous_iteration
                        && (same_execution || known_outer_execution),
                },
            )
        })
        .collect::<Vec<_>>();
    for &(import_site, import_scope, point) in &rows.import_positions {
        if import_scope != scope || (!deferred_external && point > state.observation.point_byte) {
            continue;
        }
        let import = rows
            .imports
            .iter()
            .find(|row| row.import_site.get() == import_site)
            .expect("retained import metadata");
        if import.form
            != brokk_bifrost_core::analyzer::resolution_facts::PythonNativeImportForm::Star
        {
            continue;
        }
        let routes = state
            .proofs
            .route_bindings
            .iter()
            .filter(|route| route.import_site == import_site && route.name == state.name)
            .collect::<Vec<_>>();
        assert!(
            routes.len() <= 1,
            "one temporal occurrence per import write; attach alternative targets to its proof: {routes:?}"
        );
        if routes.is_empty()
            && !state
                .proofs
                .absent_star_members
                .iter()
                .any(|(site, name)| *site == import_site && name == &state.name)
        {
            state.selection.open = true;
        }
        for route in routes {
            assert!(
                !rows
                    .events
                    .iter()
                    .any(|event| event.event == route.occurrence),
                "route occurrence aliases source event: {route:?}"
            );
            let (region, open) = guard_region(rows, import_site, state.profile, &state.proofs);
            events.push((
                point,
                0,
                route.occurrence,
                Event {
                    occurrence: route.occurrence,
                    point: (point, 0, route.occurrence),
                    completion: route.completion.clone(),
                    ordering: if deferred_external
                        && !state.proofs.completed_scopes.contains(&scope)
                    {
                        EventOrdering::Unordered
                    } else {
                        EventOrdering::Positioned
                    },
                    effect: if region.is_some() {
                        Effect::Write
                    } else {
                        Effect::NoWrite
                    },
                    region: region.unwrap_or_default(),
                    certain: route.certain
                        && !open
                        && (!deferred_external || state.proofs.completed_scopes.contains(&scope)),
                },
            ));
        }
    }
    // Global/cell writes from other invocation scopes remain alternatives. The
    // absence of an invocation-order proof is explicit, not source-byte ordering.
    if deferred_external
        && !state.proofs.completed_scopes.contains(&scope)
        && !state.proofs.absent_scopes.contains(&scope)
    {
        state.selection.open = true;
    }
    state.selection.scope(
        events.into_iter().map(|(_, _, _, event)| event),
        whole_scope,
        budget,
    );
}

pub(crate) fn outer_can_compete(state: &PythonLexical) -> bool {
    state.selection.outer_can_compete()
}

fn guard_chain(
    rows: &PythonBindingRows,
    site: u32,
) -> Vec<&brokk_bifrost_core::analyzer::resolution_facts::PythonNativeGuardFact> {
    let mut guard = rows
        .site_guards
        .iter()
        .find(|row| row.site.get() == site)
        .map(|row| row.guard);
    let mut result = Vec::new();
    while let Some(id) = guard {
        let row = rows.guards.get(id as usize).expect("dense guard authority");
        assert_eq!(row.id, id);
        assert!(
            row.parent.is_none_or(|parent| parent < id),
            "guard parent must precede child: {row:?}"
        );
        result.push(row);
        guard = row.parent;
    }
    result
}

fn guard_region(
    rows: &PythonBindingRows,
    site: u32,
    profile: PythonBindingProfile,
    proofs: &PythonBindingProofs,
) -> (Option<Region>, bool) {
    let mut decisions = Vec::new();
    let mut open = false;
    for row in guard_chain(rows, site) {
        match row.kind {
            PythonNativeGuardKind::IfTrue | PythonNativeGuardKind::IfFalse => {
                let arm = row.kind == PythonNativeGuardKind::IfTrue;
                let truth = row
                    .predicate
                    .and_then(|site| {
                        rows.predicates
                            .iter()
                            .find(|predicate| predicate.predicate == site)
                    })
                    .and_then(|predicate| match predicate.kind {
                        PythonNativePredicateKind::True => Some(true),
                        PythonNativePredicateKind::False => Some(false),
                        PythonNativePredicateKind::Name | PythonNativePredicateKind::Attribute
                            if predicate.operand.is_some()
                                && proofs
                                    .typing_predicates
                                    .contains(&predicate.predicate.get()) =>
                        {
                            Some(matches!(profile, PythonBindingProfile::Typing))
                        }
                        _ => None,
                    });
                if let Some(truth) = truth {
                    if truth != arm {
                        return (None, open);
                    }
                } else {
                    decisions.push((u64::from(row.site.get()), arm));
                }
            }
            // These require control-flow proof beyond conditional arm choice.
            // Keep possible writes without using them to erase prior events.
            _ => {
                open = true;
            }
        }
    }
    decisions.sort_unstable();
    if decisions
        .windows(2)
        .any(|pair| pair[0].0 == pair[1].0 && pair[0].1 != pair[1].1)
    {
        return (None, open);
    }
    decisions.dedup();
    (Some(Region::new(decisions)), open)
}

/// Validation uses the same shared scope driver as HalfRules. No route targets
/// are fabricated here; the source adapter maps selected occurrences to routes.
pub(crate) fn select_lexical(
    state: &mut PythonLexical,
    rows: &PythonBindingRows,
    budget: &mut impl TemporalBudget,
    cancellation: &crate::CancellationToken,
) -> crate::analyzer::store::Result<()> {
    use super::demand_closure::{RankedLexicalTier, RouteEdgeTier, select_lexical_route_starts};
    use crate::analyzer::resolution::ResolutionCompletion;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId;
    use std::cell::RefCell;
    let start = ResolutionScopeId::new(state.start_scope);
    let state = RefCell::new(state);
    select_lexical_route_starts::<TemporalRank, (), _>(
        start,
        |scope| Ok(lexical_parent(&state.borrow(), rows, scope.get()).map(ResolutionScopeId::new)),
        |scope, _| {
            let mut state = state.borrow_mut();
            lexical_tier(&mut state, rows, scope.get(), budget);
            Ok(vec![Ok(RankedLexicalTier {
                rank: TemporalRank(0),
                tier: RouteEdgeTier {
                    blocks_fallback: !outer_can_compete(&state),
                    ..RouteEdgeTier::default()
                },
                providers: Vec::new(),
            })])
        },
        |_, _| outer_can_compete(&state.borrow()),
        |_, _| false,
        &mut ResolutionCompletion::Complete,
        cancellation,
    )?;
    Ok(())
}
