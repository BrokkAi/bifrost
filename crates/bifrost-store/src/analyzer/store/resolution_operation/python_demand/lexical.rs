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
//! false. Open selections and budget stops enter the adapter's completion ledger;
//! operation cancellation must instead propagate through `Read::Cancelled`.
//!
//! Proofs are query-local selected authority, never spelling heuristics: callers
//! may list a typing predicate only after proving its operand is the canonical
//! typing.TYPE_CHECKING binding. Import proofs fix conditional identity in the
//! selected environment; they never assert that an import executed.
pub(crate) use crate::analyzer::resolution::temporal_binding::TemporalRank;
use crate::analyzer::resolution::temporal_binding::{
    Effect, Event, EventOrdering, Region, TemporalBudget, TemporalSelection,
};
use crate::analyzer::store::python_binding_rows::PythonBindingRows;
use brokk_bifrost_core::analyzer::resolution_facts::{
    PythonNativeGuardFact, PythonNativeGuardKind, PythonNativePredicateKind,
    ResolutionBindingEventKind, ResolutionBindingObservationFact, ResolutionBindingObservationKind,
    ResolutionScopeId, find_scope_in_chain,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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
    /// Identity under the selected environment, conditional on successful import.
    /// This does not assert that an import executed.
    pub(crate) conditional_imports: Vec<u32>,
    /// Selected invocation/module authority proves these external cells have
    /// reached their normal completion point for this observation.
    pub(crate) completed_scopes: Vec<u32>,
    /// Complete cell inventory plus current mutation checks prove this name
    /// absent in every observation. This does not claim invocation/completion.
    pub(crate) absent_scopes: Vec<u32>,
    /// Module dictionaries whose existing attribute-space proof remains open.
    pub(crate) open_scopes: Vec<u32>,
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
    pub(crate) deferred_module_scope: Option<u32>,
    pub(crate) builtin_fallback: bool,
    observation: Observation,
    name: String,
    profile: PythonBindingProfile,
    proofs: PythonBindingProofs,
}

impl PythonLexical {
    pub(crate) fn conditional_import_identity(&self, site: u32) -> bool {
        self.proofs.conditional_imports.contains(&site)
    }
}

pub(crate) fn unconditional_import(rows: &PythonBindingRows, site: u32) -> bool {
    guard_chain(rows, site).is_empty()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WriterIdentity {
    Fixed,
    BuiltinFallback,
    Open,
}

/// One unguarded writer in the owning scope keeps the existing identity rule.
/// A sole writer in another execution scope also fixes identity: a read before
/// that global/nonlocal write raises NameError, not an alternative binding.
/// A module cell with a builtin fallback is the exception: the builtin remains
/// an alternative until this observation's own execution has committed the write.
/// Like a conditional module writer of a builtin name, retain the authored
/// writer target with open completeness, without publishing a builtin target.
fn fixed_writer_identity(
    rows: &PythonBindingRows,
    scope: u32,
    name: &str,
    proofs: &PythonBindingProofs,
    observation: &Observation,
) -> WriterIdentity {
    use crate::analyzer::resolution::ResolutionCompletion;
    if proofs.open_scopes.contains(&scope)
        || proofs
            .source_completion
            .as_ref()
            .is_some_and(|completion| completion != &ResolutionCompletion::Complete)
    {
        return WriterIdentity::Open;
    }
    let slot = rows
        .slots
        .iter()
        .find(|slot| slot.scope == scope && slot.name == name);
    let writers = rows
        .events
        .iter()
        .filter(|event| {
            slot.is_some_and(|slot| event.slot == slot.slot)
                && event.kind != ResolutionBindingEventKind::Annotation
        })
        .collect::<Vec<_>>();
    let stars = rows.import_positions.iter().filter(|(site, owner, _)| *owner == scope && rows.imports.iter().any(|import| import.import_site.get() == *site && import.form == brokk_bifrost_core::analyzer::resolution_facts::PythonNativeImportForm::Star) && !proofs.absent_star_members.iter().any(|(absent,n)| absent == site && n == name)).map(|(site,_,_)| *site).collect::<Vec<_>>();
    if writers.len() + stars.len() != 1 {
        return WriterIdentity::Open;
    }
    if let Some(event) = writers.first() {
        if event.kind == ResolutionBindingEventKind::Delete
            || !guard_chain(rows, event.target).is_empty()
        {
            return WriterIdentity::Open;
        }
        if event.execution_scope != scope
            && rows
                .scopes
                .iter()
                .any(|row| row.scope == scope && row.parent.is_none())
            && brokk_bifrost_python::intrinsics::builtin(name).is_some()
            && (event.execution_scope != observation.execution_scope.get()
                || event.commit_byte > observation.point_byte)
        {
            return WriterIdentity::BuiltinFallback;
        }
        let fixed = event.kind != ResolutionBindingEventKind::Import
            || rows.imports.iter().any(|import| {
                import.binding_event == Some(event.event)
                    && proofs
                        .conditional_imports
                        .contains(&import.import_site.get())
            });
        return if fixed {
            WriterIdentity::Fixed
        } else {
            WriterIdentity::Open
        };
    }
    let fixed = proofs.route_bindings.iter().any(|route| {
        stars.contains(&route.import_site)
            && route.name == name
            && route.certain
            && route.completion == ResolutionCompletion::Complete
            && guard_chain(rows, route.import_site).is_empty()
    });
    if fixed {
        WriterIdentity::Fixed
    } else {
        WriterIdentity::Open
    }
}

/// A unique unguarded parameter fixes its local cell at every observation.
/// Inventory scans can reuse the ordinary single-writer proof without spending
/// scope traversal budget on each read of the same receiver parameter.
pub(crate) fn fixed_parameter<'a>(
    rows: &'a PythonBindingRows,
    reference: u32,
    name: &str,
    proofs: &PythonBindingProofs,
) -> Option<&'a crate::analyzer::store::python_binding_rows::BindingEvent> {
    let observation = Observation::from(
        *rows
            .observations
            .iter()
            .find(|row| row.reference.get() == reference)?,
    );
    let scope = observation.execution_scope.get();
    if directive(rows, scope, name).is_some()
        || fixed_writer_identity(rows, scope, name, proofs, &observation) != WriterIdentity::Fixed
    {
        return None;
    }
    let slot = rows
        .slots
        .iter()
        .find(|slot| slot.scope == scope && slot.name == name)?;
    rows.events.iter().find(|event| {
        event.slot == slot.slot && event.kind == ResolutionBindingEventKind::Parameter
    })
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
    selection.open = guard_chain(rows, reference_site)
        .iter()
        .any(|guard| guard.kind == PythonNativeGuardKind::UnknownControl);
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
        deferred_module_scope: None,
        builtin_fallback: false,
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
    completed_scope_selection(rows, scope, name, profile, proofs)
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
    completed_scope_selection(rows, scope, name, profile, proofs)
}

fn completed_scope_selection(
    rows: &PythonBindingRows,
    scope: u32,
    name: &str,
    profile: PythonBindingProfile,
    proofs: PythonBindingProofs,
) -> PythonLexical {
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId;
    let observation = Observation {
        reference: None,
        execution_scope: ResolutionScopeId::new(scope),
        point_byte: usize::MAX,
        kind: ResolutionBindingObservationKind::Immediate,
    };
    let mut selection = TemporalSelection::new(Region::default());
    // A unique writer fixes identity without proving import activation or the
    // completion of every cell in the enclosing module.
    selection.open = !proofs.completed_scopes.contains(&scope)
        && fixed_writer_identity(rows, scope, name, &proofs, &observation) != WriterIdentity::Fixed;
    if let Some(completion) = &proofs.source_completion {
        selection.completion = selection.completion.combine(completion);
    }
    PythonLexical {
        selection,
        start_scope: scope,
        deferred_module_scope: None,
        builtin_fallback: false,
        observation,
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

pub(crate) fn lexical_slot<'a>(
    state: &PythonLexical,
    rows: &'a PythonBindingRows,
    scope: u32,
) -> Option<&'a crate::analyzer::store::python_binding_rows::BindingSlot> {
    rows.slots
        .iter()
        .find(|slot| slot.scope == scope && slot.name == state.name)
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
    let slot = lexical_slot(state, rows, scope);
    let whole_scope = slot.is_some_and(|slot| slot.whole_scope);
    let writer_identity =
        fixed_writer_identity(rows, scope, &state.name, &state.proofs, &state.observation);
    let fixed_writer = writer_identity == WriterIdentity::Fixed;
    state.builtin_fallback |= writer_identity == WriterIdentity::BuiltinFallback;
    // Executable scopes, including comprehensions, remain deferral boundaries:
    // no retained scope-kind fact distinguishes them here. Such a fact would
    // restore chronology for module-level comprehension bodies (#7375).
    // A read before its sole writer raises NameError, not an alternative binding.
    // Keep the retained chronology for cells without that fixed-writer proof.
    // If namespace proof revokes the exemption, keep the boundary open on retry.
    // Class bodies execute in the enclosing invocation, so skip them when
    // finding the execution boundary of a class nested in a function.
    let deferred_external = (state.observation.kind == ResolutionBindingObservationKind::Deferred
        || fixed_writer
        || state.proofs.open_scopes.contains(&scope))
        && find_scope_in_chain(
            Some(state.observation.execution_scope),
            |id| {
                rows.scopes
                    .iter()
                    .find(|row| row.scope == id.get())
                    .expect("retained execution scope")
                    .parent
                    .map(ResolutionScopeId::new)
            },
            |id| {
                id.get() == scope
                    || !rows
                        .scopes
                        .iter()
                        .find(|row| row.scope == id.get())
                        .expect("retained execution scope")
                        .class_body
            },
        )
        .expect("execution scope chain reaches the module")
        .get()
            != scope;
    if deferred_external
        && rows
            .scopes
            .iter()
            .any(|row| row.scope == scope && row.parent.is_none())
    {
        state.deferred_module_scope = Some(scope);
    }
    let observed_guards = state
        .observation
        .reference
        .map(|site| guard_chain(rows, site))
        .unwrap_or_default();
    // A loop changes a cell's identity only through writes in that loop.
    // A nested def that writes through global is already an other-scope writer
    // in the cell inventory; it needs no special case here.
    let loop_carried = |site, point| {
        rows.loop_regions.iter().any(|(execution, region)| {
            *execution == state.observation.execution_scope.get()
                && region.contains(&state.observation.point_byte)
                && region.contains(&point)
        }) || guard_chain(rows, site).iter().any(|writer| {
            writer.kind == PythonNativeGuardKind::LoopBody
                && observed_guards.iter().any(|observed| {
                    matches!(
                        observed.kind,
                        PythonNativeGuardKind::LoopBody | PythonNativeGuardKind::LoopElse
                    ) && observed.site == writer.site
                        && observed.execution_scope == writer.execution_scope
                })
        })
    };
    state.selection.open |= rows.events.iter().any(|event| {
        slot.is_some_and(|slot| slot.slot == event.slot)
            && event.kind != ResolutionBindingEventKind::Annotation
            && loop_carried(event.target, event.entry_byte)
    }) || rows.imports.iter().any(|import| {
        import.form == brokk_bifrost_core::analyzer::resolution_facts::PythonNativeImportForm::Star
            && !state
                .proofs
                .absent_star_members
                .iter()
                .any(|(site, name)| *site == import.import_site.get() && *name == state.name)
            && rows.import_positions.iter().any(|(site, owner, point)| {
                *site == import.import_site.get() && *owner == scope && loop_carried(*site, *point)
            })
    });
    let mut events = rows
        .events
        .iter()
        .filter(|event| slot.is_some_and(|slot| event.slot == slot.slot))
        .flat_map(|event| {
            let (region, guard_open) = if event.kind == ResolutionBindingEventKind::Parameter {
                // Invocation entry initializes parameters; creation-time guards
                // on a conditional def are not conditions on its body bindings.
                (Some(Region::default()), false)
            } else {
                guard_region(rows, event.target, state.profile, &state.proofs)
            };
            let event_guards = guard_chain(rows, event.target);
            let shared_loop = outermost_shared_loop(&event_guards, &observed_guards);
            let iteration_active =
                event.kind == ResolutionBindingEventKind::Iteration && shared_loop.is_some();
            let committed = event.commit_byte <= state.observation.point_byte || iteration_active;
            let previous_iteration = !committed && shared_loop.is_some();
            let same_execution = event.execution_scope == state.observation.execution_scope.get();
            // A unique cell writer fixes identity across execution scopes,
            // including writes redirected through global or nonlocal.
            let known_outer_execution = fixed_writer
                || (event.execution_scope == scope
                    && (!deferred_external || state.proofs.completed_scopes.contains(&scope)));
            let effect = if region.is_none()
                || ((same_execution
                    || (!deferred_external && !(fixed_writer && event.execution_scope != scope)))
                    && !committed
                    && !previous_iteration)
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
                            .conditional_imports
                            .contains(&import.import_site.get())
                });
            let earlier = shared_loop
                .zip(region.as_ref())
                .map(|(position, region)| outside_loop_region(region, &event_guards[..position]));
            let (region, earlier) = if previous_iteration {
                (earlier, None)
            } else {
                (region, earlier)
            };
            let primary = Event {
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
            };
            with_earlier_iteration(primary, earlier)
        })
        .collect::<Vec<_>>();
    for &(import_site, import_scope, point) in &rows.import_positions {
        if import_scope != scope {
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
        let import_guards = guard_chain(rows, import_site);
        let shared_loop = outermost_shared_loop(&import_guards, &observed_guards);
        let committed = point <= state.observation.point_byte;
        let previous_iteration = !committed && shared_loop.is_some();
        if !deferred_external && !committed && !previous_iteration {
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
            let effect = if region.is_some() {
                Effect::Write
            } else {
                Effect::NoWrite
            };
            let earlier = shared_loop
                .zip(region.as_ref())
                .map(|(position, region)| outside_loop_region(region, &import_guards[..position]));
            let (region, earlier) = if previous_iteration {
                (earlier, None)
            } else {
                (region, earlier)
            };
            let write = Event {
                occurrence: route.occurrence,
                point: (point, 0, route.occurrence),
                completion: route.completion.clone(),
                ordering: if previous_iteration
                    || (deferred_external
                        && !state.proofs.completed_scopes.contains(&scope)
                        && !fixed_writer)
                {
                    EventOrdering::Unordered
                } else {
                    EventOrdering::Positioned
                },
                effect,
                region: region.unwrap_or_default(),
                certain: route.certain
                    && !open
                    && !previous_iteration
                    && (!deferred_external
                        || state.proofs.completed_scopes.contains(&scope)
                        || fixed_writer),
            };
            events.extend(with_earlier_iteration(write, earlier));
        }
    }
    // Global/cell writes from other invocation scopes remain alternatives. The
    // absence of an invocation-order proof is explicit, not source-byte ordering.
    // An intervening scope with no such cell is a lexical continuation, not
    // an unordered writer. Unknown wildcard routes were kept open above.
    if deferred_external
        && (slot.is_some() || !events.is_empty() || state.proofs.open_scopes.contains(&scope))
        && !fixed_writer
        && !state.proofs.completed_scopes.contains(&scope)
        && !state.proofs.absent_scopes.contains(&scope)
    {
        state.selection.open = true;
    }
    state.selection.scope(events, whole_scope, budget);
    // Different reaching writers are alternatives, even when their inventory
    // is complete. An import's conditional identity cannot close that choice.
    if state.selection.selected.len() > 1
        && state.selection.selected.iter().any(|selected| {
            rows.events.iter().any(|event| {
                event.event == selected.occurrence
                    && event.kind == ResolutionBindingEventKind::Import
            }) || state
                .proofs
                .route_bindings
                .iter()
                .any(|route| route.occurrence == selected.occurrence)
        })
    {
        state.selection.open = true;
    }
}

pub(crate) fn outer_can_compete(state: &PythonLexical) -> bool {
    state.selection.outer_can_compete()
}

fn guard_chain(rows: &PythonBindingRows, site: u32) -> Vec<&PythonNativeGuardFact> {
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
                    decisions.push((decision_key(row), arm));
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

/// The position in `chain` (innermost guard first) of the outermost loop body
/// that also holds the observation. An earlier iteration of any shared loop may
/// have run the event, and the outermost loop covers the inner ones.
fn outermost_shared_loop(
    chain: &[&PythonNativeGuardFact],
    observed: &[&PythonNativeGuardFact],
) -> Option<usize> {
    chain.iter().rposition(|guard| {
        guard.kind == PythonNativeGuardKind::LoopBody
            && observed.iter().any(|observed| observed.id == guard.id)
    })
}

/// The events one write contributes. It can also come from an earlier iteration
/// of a loop around the observation. That iteration chose its branches
/// independently, so the decisions made inside the loop cannot exclude it, while
/// decisions outside the loop still apply. That is an unordered alternative with
/// the region `earlier`, kept only when it differs from the write's own region.
/// An uncertain write consumes nothing and the alternative's wider region
/// selects everything it would, so the alternative replaces it.
fn with_earlier_iteration(write: Event, earlier: Option<Region>) -> impl Iterator<Item = Event> {
    let alternative = earlier
        .filter(|earlier| write.effect != Effect::NoWrite && *earlier != write.region)
        .map(|region| Event {
            ordering: EventOrdering::Unordered,
            region,
            certain: false,
            ..write.clone()
        });
    (alternative.is_none() || write.certain)
        .then_some(write)
        .into_iter()
        .chain(alternative)
}

/// Both arms of one `if` share its site, so a region names the decision once.
fn decision_key(guard: &PythonNativeGuardFact) -> u64 {
    u64::from(guard.site.get())
}

/// `region` without the decisions of `inside`, the guards of a chain that lie
/// within a loop body. Removing a decision only widens the region.
fn outside_loop_region(region: &Region, inside: &[&PythonNativeGuardFact]) -> Region {
    Region(
        region
            .0
            .iter()
            .copied()
            .filter(|&(decision, _)| {
                !inside.iter().any(|guard| {
                    matches!(
                        guard.kind,
                        PythonNativeGuardKind::IfTrue | PythonNativeGuardKind::IfFalse
                    ) && decision_key(guard) == decision
                })
            })
            .collect(),
    )
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
            Ok(super::demand_closure::Read::ready(vec![Ok(
                RankedLexicalTier {
                    rank: TemporalRank(0),
                    tier: RouteEdgeTier {
                        blocks_fallback: !outer_can_compete(&state),
                        ..RouteEdgeTier::default()
                    },
                    providers: Vec::new(),
                },
            )]))
        },
        |_, _| outer_can_compete(&state.borrow()),
        |_, _| false,
        &mut ResolutionCompletion::Complete,
        cancellation,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::analyzer::resolution_facts::{ResolutionScopeId, ResolutionSiteId};
    use brokk_bifrost_test_macros::hardwon;

    fn guard(
        id: u32,
        parent: Option<u32>,
        site: u32,
        kind: PythonNativeGuardKind,
    ) -> PythonNativeGuardFact {
        PythonNativeGuardFact {
            id,
            parent,
            site: ResolutionSiteId::new(site),
            execution_scope: ResolutionScopeId::new(0),
            kind,
            arm_ordinal: 0,
            predicate: None,
        }
    }

    fn write(region: Region, certain: bool) -> Event {
        Event {
            occurrence: 7,
            point: (0, 0, 7),
            completion: crate::analyzer::resolution::ResolutionCompletion::Complete,
            ordering: EventOrdering::Positioned,
            region,
            effect: Effect::Write,
            certain,
        }
    }

    #[test]
    #[hardwon(
        "#6405: a loop's other-arm write was excluded because branch regions ignored iterations"
    )]
    fn only_decisions_inside_the_outermost_shared_loop_are_dropped() {
        use PythonNativeGuardKind::{IfFalse, IfTrue, LoopBody};
        // `if outer:` (site 10) holds a loop, whose body holds `if middle:`
        // (site 11), a second loop, and `if flag:` (site 12). The write is in
        // the true arm of `flag` and the read in its false arm.
        let guards = [
            guard(0, None, 10, IfTrue),
            guard(1, Some(0), 20, LoopBody),
            guard(2, Some(1), 11, IfTrue),
            guard(3, Some(2), 21, LoopBody),
            guard(4, Some(3), 12, IfTrue),
            guard(5, Some(3), 12, IfFalse),
        ];
        // Guard chains run innermost first.
        let write_chain: Vec<_> = [4, 3, 2, 1, 0].map(|id| &guards[id]).into();
        let read_chain: Vec<_> = [5, 3, 2, 1, 0].map(|id| &guards[id]).into();
        // The outermost shared loop is guard 1, at position 3 of the write's chain.
        assert_eq!(outermost_shared_loop(&write_chain, &read_chain), Some(3));
        assert_eq!(outermost_shared_loop(&write_chain, &[&guards[0]]), None);
        let region = Region::new(vec![(10, true), (11, true), (12, true)]);
        // Decisions 11 and 12 are made inside the loop; decision 10 is above it.
        assert_eq!(
            outside_loop_region(&region, &write_chain[..3]),
            Region::new(vec![(10, true)])
        );
    }

    #[test]
    fn an_uncertain_write_is_replaced_by_its_alternative() {
        let own = Region::new(vec![(1, true)]);
        let earlier = Region::default();
        let events = |write: Event, earlier: Option<Region>| {
            with_earlier_iteration(write, earlier).collect::<Vec<_>>()
        };
        // Uncertain: one unordered event with the wider region.
        let uncertain = events(write(own.clone(), false), Some(earlier.clone()));
        assert_eq!(uncertain.len(), 1);
        assert_eq!(uncertain[0].ordering, EventOrdering::Unordered);
        assert_eq!(uncertain[0].region, earlier);
        assert!(!uncertain[0].certain);
        // Certain: the positioned event keeps its own region, and the alternative joins it.
        let certain = events(write(own.clone(), true), Some(earlier.clone()));
        assert_eq!(certain.len(), 2);
        assert_eq!(certain[0].region, own);
        assert!(certain[0].certain);
        assert_eq!(certain[1].region, earlier);
        // Outside any loop, or with nothing to widen, the write is unchanged.
        assert_eq!(events(write(own.clone(), false), None).len(), 1);
        assert_eq!(
            events(write(own.clone(), false), Some(own.clone())).len(),
            1
        );
    }
}
