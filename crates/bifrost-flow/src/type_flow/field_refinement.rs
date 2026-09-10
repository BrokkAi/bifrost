//! Procedure-local versions of ordinary receiver fields.
//!
//! This is a must-alias access-path analysis, not a strong update to the
//! workspace heap. A saved read names the version it observed; a later store
//! or an effect that may run user code prevents its guard from refining a new
//! version. Alternatives meet by union, including the no-store entry path.
//!
//! Only two questions read a value's origins: whether the base of a field
//! access is the receiver, and what a guard's subject was read from. Origins
//! are therefore carried for those values and for the values that copy into
//! one. Every other value would carry state that nothing reads.

use std::collections::VecDeque;

use super::correlations::CorrelationError;
use crate::analyzer::WorkspaceAnalyzer;
use crate::analyzer::semantic::{
    CancellationToken, ClassAtom, ClassIdentity, GuardFact, GuardPredicate, MemberAccessQuery,
    MemoryLocationId, MemoryLocationKind, ProcedureHandle, ProcedureSemantics, ProgramPointId,
    SemanticBudget, SemanticEffect, SemanticGapImpact, SemanticValueKind, SemanticWork,
    TypeFlowAdapter, ValueFlowSnapshot, ValueId,
};
use crate::hash::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum FieldVersion {
    Entry,
    Store {
        point: ProgramPointId,
        event: usize,
        value: ValueId,
    },
    Open {
        point: ProgramPointId,
        event: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct FieldAlternative {
    pub version: FieldVersion,
    pub guards: Vec<(usize, bool)>,
}

#[derive(Debug, Clone)]
pub(super) struct FieldLoadRefinement {
    pub point: ProgramPointId,
    pub result: ValueId,
    pub member: Box<str>,
    pub alternatives: Vec<FieldAlternative>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Origin {
    Receiver,
    PureTruthiness,
    Read { field: usize, version: FieldVersion },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct State {
    // Absence means unknown. Unknown dominates an alias proof at a join.
    origins: HashMap<ValueId, HashSet<Origin>>,
    fields: Vec<Vec<FieldAlternative>>,
}

impl State {
    fn copy(
        &mut self,
        source: ValueId,
        target: ValueId,
        tracked: &HashSet<ValueId>,
        budget: &mut SemanticBudget,
        cancellation: &CancellationToken,
    ) -> Result<(), CorrelationError> {
        if source == target || !tracked.contains(&target) {
            return Ok(());
        }
        if self.origins.contains_key(&source) {
            check_cancelled(cancellation)?;
            let origin_count = self
                .origins
                .get(&source)
                .expect("the source origin remains present")
                .len();
            charge_entries(budget, origin_count.saturating_add(1))?;
            let origins = self
                .origins
                .get(&source)
                .expect("the source origin remains present")
                .clone();
            self.origins.insert(target, origins);
        } else {
            self.origins.remove(&target);
        }
        Ok(())
    }

    fn is_receiver(&self, value: ValueId) -> bool {
        self.origins
            .get(&value)
            .is_some_and(|origins| origins.len() == 1 && origins.contains(&Origin::Receiver))
    }

    fn open(
        &mut self,
        point: ProgramPointId,
        event: usize,
        budget: &mut SemanticBudget,
        cancellation: &CancellationToken,
    ) -> Result<(), CorrelationError> {
        self.origins.retain(|_, origins| {
            origins
                .iter()
                .all(|origin| matches!(origin, Origin::Receiver | Origin::PureTruthiness))
        });
        for field in &mut self.fields {
            check_cancelled(cancellation)?;
            charge_entries(budget, 1)?;
            *field = vec![FieldAlternative {
                version: FieldVersion::Open { point, event },
                guards: Vec::new(),
            }];
        }
        Ok(())
    }

    fn join(
        &mut self,
        other: &Self,
        budget: &mut SemanticBudget,
        cancellation: &CancellationToken,
    ) -> Result<bool, CorrelationError> {
        check_cancelled(cancellation)?;
        charge_entries(budget, self.size().saturating_add(1))?;
        let incoming_origin_count = other.origins.values().map(HashSet::len).sum::<usize>();
        charge_entries(budget, incoming_origin_count)?;
        let before = self.clone();
        self.origins.retain(|value, origins| {
            if let Some(incoming) = other.origins.get(value) {
                origins.extend(incoming.iter().copied());
                true
            } else {
                false
            }
        });
        for (field, incoming) in self.fields.iter_mut().zip(&other.fields) {
            for alternative in incoming {
                check_cancelled(cancellation)?;
                if field.iter().any(|old| {
                    old.version == alternative.version
                        && old
                            .guards
                            .iter()
                            .all(|guard| alternative.guards.contains(guard))
                }) {
                    continue;
                }
                field.retain(|old| {
                    old.version != alternative.version
                        || !alternative
                            .guards
                            .iter()
                            .all(|guard| old.guards.contains(guard))
                });
                charge_entries(budget, 1usize.saturating_add(alternative.guards.len()))?;
                field.push(alternative.clone());
            }
        }
        Ok(*self != before)
    }

    fn size(&self) -> usize {
        self.origins.values().map(HashSet::len).sum::<usize>()
            + self
                .fields
                .iter()
                .flatten()
                .map(|alternative| 1 + alternative.guards.len())
                .sum::<usize>()
    }
}

struct FieldAccesses {
    members: Vec<Box<str>>,
    /// The values whose origins a query can observe. See [`tracked_values`].
    tracked: HashSet<ValueId>,
    receiver_truthiness_is_pure: bool,
    truthiness_is_pure: Vec<bool>,
    pure_reads: HashSet<(usize, MemoryLocationId)>,
    locations: HashMap<MemoryLocationId, (usize, ValueId)>,
    /// The state slot that carries each member's versions.  A member this
    /// procedure only stores has no slot: nothing reads a version back, so
    /// carrying its versions costs state that no answer depends on.
    version_slots: Vec<Option<usize>>,
    version_slot_count: usize,
}

impl FieldAccesses {
    fn new(
        workspace: &WorkspaceAnalyzer,
        adapter: &dyn TypeFlowAdapter,
        procedure: &ProcedureHandle,
        class: &ClassIdentity,
        field_slots: &super::FieldSlotIndex,
        budget: &mut SemanticBudget,
        cancellation: &CancellationToken,
    ) -> Result<Self, CorrelationError> {
        let mut members = Vec::new();
        let mut locations = HashMap::default();
        let mut known = HashMap::<Box<str>, Option<usize>>::default();
        let mut location_members = Vec::<(MemoryLocationId, Box<str>)>::new();
        let mut queried = HashSet::default();
        for location in procedure.semantics().memory_locations() {
            check_cancelled(cancellation)?;
            charge_entries(budget, 1)?;
            if let MemoryLocationKind::Field { base, .. } = location.kind {
                queried.insert(base);
            }
            let Some(member) =
                adapter.accessed_member(workspace, procedure, MemberAccessQuery::Load(location))
            else {
                continue;
            };
            location_members.push((location.id, member.clone()));
            let MemoryLocationKind::Field { base, .. } = location.kind else {
                continue;
            };
            let index = *known.entry(member.clone()).or_insert_with(|| {
                adapter
                    .field_access_is_plain(workspace, class, &member)
                    .then(|| {
                        let index = members.len();
                        members.push(member);
                        index
                    })
            });
            if let Some(index) = index {
                locations.insert(location.id, (index, base));
            }
        }
        charge_entries(budget, members.len())?;
        let mut truthiness_is_pure = Vec::with_capacity(members.len());
        for member in &members {
            check_cancelled(cancellation)?;
            let Some(slot) = field_slots.slot(class, member) else {
                truthiness_is_pure.push(false);
                continue;
            };
            if slot.atoms.is_empty() {
                truthiness_is_pure.push(false);
                continue;
            }
            let mut pure = true;
            for (atom, _) in &slot.atoms {
                check_cancelled(cancellation)?;
                charge_entries(budget, 1)?;
                if !matches!(atom, ClassAtom::Class(class) if adapter.truthiness_is_pure(workspace, class))
                {
                    pure = false;
                    break;
                }
            }
            truthiness_is_pure.push(pure);
        }
        let mut pure_reads = HashSet::default();
        for (field, member) in members.iter().enumerate() {
            check_cancelled(cancellation)?;
            charge_entries(budget, 1)?;
            let Some(slot) = field_slots.slot(class, member) else {
                continue;
            };
            if slot.atoms.is_empty() {
                continue;
            }
            for (location, accessed_member) in &location_members {
                check_cancelled(cancellation)?;
                charge_entries(budget, 1)?;
                if slot.atoms.iter().all(|(atom, _)| {
                    matches!(atom, ClassAtom::Class(class) if adapter.member_access_is_pure(workspace, class, accessed_member))
                }) {
                    pure_reads.insert((field, *location));
                }
            }
        }
        let tracked = tracked_values(procedure.semantics(), queried, budget, cancellation)?;
        let mut version_slots = vec![None; members.len()];
        let mut version_slot_count = 0;
        for point in procedure.semantics().points() {
            check_cancelled(cancellation)?;
            charge_entries(budget, point.events.len().saturating_add(1))?;
            for event in &point.events {
                let SemanticEffect::MemoryLoad { location, .. } = event.effect else {
                    continue;
                };
                let Some(&(field, _)) = locations.get(&location) else {
                    continue;
                };
                if version_slots[field].is_none() {
                    version_slots[field] = Some(version_slot_count);
                    version_slot_count += 1;
                }
            }
        }
        Ok(Self {
            members,
            tracked,
            receiver_truthiness_is_pure: adapter.truthiness_is_pure(workspace, class),
            truthiness_is_pure,
            pure_reads,
            locations,
            version_slots,
            version_slot_count,
        })
    }
}

/// The value one guard fact reads origins from, when it has one.
fn guard_origin_subject(guard: &GuardFact) -> Option<ValueId> {
    match guard.predicate {
        GuardPredicate::Truthy { value }
        | GuardPredicate::InstanceOf { value, .. }
        | GuardPredicate::HasMember { value, .. } => Some(value),
        GuardPredicate::NullComparison { .. } => guard.subject,
        _ => None,
    }
}

/// The values whose origins a query can observe, and the values that copy
/// into one.
///
/// A field access reads the origins of its base to decide whether the base is
/// the receiver, and an edge refinement reads the origins of its guard's
/// subject. Those bases and subjects are the only origins any answer depends
/// on. The transfer function reads a copy's source to write its target, so
/// the closure over copy events adds every value that can supply one of them.
/// The closure ignores CFG order on purpose: taking every copy event in the
/// procedure over-covers any one path through it.
fn tracked_values(
    semantics: &ProcedureSemantics,
    mut queried: HashSet<ValueId>,
    budget: &mut SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<HashSet<ValueId>, CorrelationError> {
    for guard in semantics.guard_facts() {
        check_cancelled(cancellation)?;
        charge_entries(budget, 1)?;
        if let Some(subject) = guard_origin_subject(guard) {
            queried.insert(subject);
        }
    }
    let mut sources_of = HashMap::<ValueId, Vec<ValueId>>::default();
    for point in semantics.points() {
        check_cancelled(cancellation)?;
        charge_entries(budget, point.events.len().saturating_add(1))?;
        for event in &point.events {
            let (source, target) = match event.effect {
                SemanticEffect::Assignment { target, value } => (value, target),
                SemanticEffect::ValueFlow {
                    source,
                    target,
                    kind,
                } if kind.preserves_runtime_class() => (source, target),
                _ => continue,
            };
            if source == target {
                continue;
            }
            sources_of.entry(target).or_default().push(source);
        }
    }
    let mut tracked = queried.clone();
    let mut pending = queried.into_iter().collect::<Vec<_>>();
    while let Some(target) = pending.pop() {
        check_cancelled(cancellation)?;
        charge_entries(budget, 1)?;
        let Some(sources) = sources_of.get(&target) else {
            continue;
        };
        charge_entries(budget, sources.len())?;
        for &source in sources {
            if tracked.insert(source) {
                pending.push(source);
            }
        }
    }
    Ok(tracked)
}

fn transfer(
    procedure: &ProcedureHandle,
    snapshot: Option<&ValueFlowSnapshot>,
    accesses: &FieldAccesses,
    point: ProgramPointId,
    state: &mut State,
    budget: &mut SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<Vec<FieldLoadRefinement>, CorrelationError> {
    let semantics = procedure.semantics();
    let mut loads = Vec::new();
    for (event_index, event) in semantics
        .point(point)
        .expect("a live refinement point")
        .events
        .iter()
        .enumerate()
    {
        check_cancelled(cancellation)?;
        charge_entries(budget, 1)?;
        match event.effect {
            SemanticEffect::Assignment { target, value } => {
                state.copy(value, target, &accesses.tracked, budget, cancellation)?;
            }
            SemanticEffect::ValueFlow {
                source,
                target,
                kind,
            } => {
                if kind.preserves_runtime_class() {
                    state.copy(source, target, &accesses.tracked, budget, cancellation)?;
                } else {
                    state.origins.remove(&target);
                }
            }
            SemanticEffect::MemoryLoad {
                location, result, ..
            } => {
                if let Some(&(field, base)) = accesses.locations.get(&location)
                    && state.is_receiver(base)
                {
                    let slot = accesses.version_slots[field]
                        .expect("a loaded member carries version state");
                    charge_entries(budget, state.fields[slot].len().saturating_add(1))?;
                    let alternatives = state.fields[slot].clone();
                    if accesses.tracked.contains(&result) {
                        charge_entries(budget, alternatives.len().saturating_add(1))?;
                        state.origins.insert(
                            result,
                            alternatives
                                .iter()
                                .map(|alternative| Origin::Read {
                                    field,
                                    version: alternative.version,
                                })
                                .collect(),
                        );
                    }
                    charge_entries(budget, 1)?;
                    loads.push(FieldLoadRefinement {
                        point,
                        result,
                        member: accesses.members[field].clone(),
                        alternatives,
                    });
                } else {
                    let pure = semantics.memory_location(location)
                        .and_then(|location| match location.kind {
                            MemoryLocationKind::Field { base, .. } => state.origins.get(&base),
                            _ => None,
                        }).is_some_and(|origins| {
                            !origins.is_empty() && origins.iter().all(|origin| {
                                matches!(origin, Origin::Read { field, .. } if accesses.pure_reads.contains(&(*field, location)))
                            })
                        });
                    state.origins.remove(&result);
                    // A descriptor can execute arbitrary code. The value it
                    // returns is distinct from any earlier receiver-field read.
                    if !pure {
                        state.open(point, event_index, budget, cancellation)?;
                    }
                }
            }
            SemanticEffect::MemoryStore {
                location, value, ..
            } => {
                if let Some(&(field, base)) = accesses.locations.get(&location)
                    && state.is_receiver(base)
                {
                    // A member with no version state was never loaded here, so
                    // no saved read names it and no later load reads the epoch
                    // this store would install.
                    if let Some(slot) = accesses.version_slots[field] {
                        // Static store IDs recur in loops. Invalidate saved
                        // reads before installing the new epoch, even at the
                        // same store.
                        state.origins.retain(|_, origins| {
                            !origins.iter().any(|origin| {
                                matches!(origin, Origin::Read { field: candidate, .. } if *candidate == field)
                            })
                        });
                        check_cancelled(cancellation)?;
                        charge_entries(budget, 1)?;
                        state.fields[slot] = vec![FieldAlternative {
                            version: FieldVersion::Store {
                                point,
                                event: event_index,
                                value,
                            },
                            guards: Vec::new(),
                        }];
                    }
                } else {
                    state.open(point, event_index, budget, cancellation)?;
                }
            }
            SemanticEffect::Invoke { call_site } => {
                state.open(point, event_index, budget, cancellation)?;
                if let Some(result) = semantics.call_site(call_site).expect("a live call").result {
                    state.origins.remove(&result);
                }
            }
            SemanticEffect::AsyncSuspend { .. } | SemanticEffect::Synchronization { .. } => {
                state.open(point, event_index, budget, cancellation)?
            }
            SemanticEffect::Gap { gap } => {
                let gap = semantics.gap(gap).expect("a live gap");
                if gap.impacts.contains(SemanticGapImpact::HeapWrite)
                    && !snapshot.is_some_and(|snapshot| snapshot.gap_is_discharged(gap.id))
                {
                    state.open(point, event_index, budget, cancellation)?;
                }
            }
            _ => {}
        }
    }
    Ok(loads)
}

fn refine_edge(
    procedure: &ProcedureHandle,
    accesses: &FieldAccesses,
    point: ProgramPointId,
    edge_id: crate::analyzer::semantic::ControlEdgeId,
    state: &mut State,
    budget: &mut SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<(), CorrelationError> {
    for (guard_index, guard) in procedure.semantics().guard_facts().iter().enumerate() {
        check_cancelled(cancellation)?;
        charge_entries(budget, 1)?;
        if guard.point != point {
            continue;
        }
        let truth = if guard.true_edge == Some(edge_id) {
            true
        } else if guard.false_edge == Some(edge_id) {
            false
        } else {
            continue;
        };
        let subject = guard_origin_subject(guard);
        let origins = subject.and_then(|subject| state.origins.get(&subject));
        if matches!(guard.predicate, GuardPredicate::Truthy { .. })
            && !origins.is_some_and(|origins| {
                !origins.is_empty()
                    && origins.iter().all(|origin| match origin {
                        Origin::Receiver => accesses.receiver_truthiness_is_pure,
                        Origin::Read { field, .. } => accesses.truthiness_is_pure[*field],
                        Origin::PureTruthiness => true,
                    })
            })
        {
            state.open(point, usize::MAX, budget, cancellation)?;
            continue;
        }
        let Some(origins) = origins else {
            continue;
        };
        // Unioned reads of different versions do not prove which current
        // version a path's saved value observed.
        if origins.len() != 1 {
            continue;
        }
        // A guard may refine a field only when every possible saved read
        // names that field and every current version was observed by the read.
        let Some(Origin::Read { field, .. }) = origins.iter().next() else {
            continue;
        };
        let field = *field;
        let slot = accesses.version_slots[field].expect("a read member carries version state");
        for alternative in &mut state.fields[slot] {
            check_cancelled(cancellation)?;
            if origins.contains(&Origin::Read {
                field,
                version: alternative.version,
            }) && !alternative.guards.contains(&(guard_index, truth))
            {
                charge_entries(budget, 1)?;
                alternative.guards.push((guard_index, truth));
                alternative.guards.sort_unstable();
            }
        }
    }
    Ok(())
}

fn check_cancelled(cancellation: &CancellationToken) -> Result<(), CorrelationError> {
    if cancellation.is_cancelled() {
        return Err(CorrelationError::Cancelled {
            timed_out: cancellation.is_timed_out(),
        });
    }
    Ok(())
}

fn charge_entries(budget: &mut SemanticBudget, count: usize) -> Result<(), CorrelationError> {
    if count == 0 {
        return Ok(());
    }
    budget.charge(SemanticWork {
        nested_entries: count,
        ..SemanticWork::default()
    })?;
    Ok(())
}

fn charge_edges(budget: &mut SemanticBudget, count: usize) -> Result<(), CorrelationError> {
    if count == 0 {
        return Ok(());
    }
    budget.charge(SemanticWork {
        control_edges: count,
        ..SemanticWork::default()
    })?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn derive(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    procedure: &ProcedureHandle,
    snapshot: Option<&ValueFlowSnapshot>,
    class: &ClassIdentity,
    field_slots: &super::FieldSlotIndex,
    budget: &mut SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<Vec<FieldLoadRefinement>, CorrelationError> {
    let accesses = FieldAccesses::new(
        workspace,
        adapter,
        procedure,
        class,
        field_slots,
        budget,
        cancellation,
    )?;
    if accesses.version_slot_count == 0 {
        // Without a loaded plain member this analysis has no load to refine.
        return Ok(Vec::new());
    }
    let semantics = procedure.semantics();
    let mut origins = HashMap::default();
    for value in semantics.values() {
        check_cancelled(cancellation)?;
        if !accesses.tracked.contains(&value.id) {
            continue;
        }
        if matches!(value.kind, SemanticValueKind::Receiver { .. }) {
            charge_entries(budget, 1)?;
            origins.insert(value.id, HashSet::from_iter([Origin::Receiver]));
        } else if matches!(value.kind, SemanticValueKind::Boolean(_)) {
            charge_entries(budget, 1)?;
            origins.insert(value.id, HashSet::from_iter([Origin::PureTruthiness]));
        }
    }
    charge_entries(budget, accesses.version_slot_count.saturating_add(1))?;
    let initial = State {
        origins,
        fields: vec![
            vec![FieldAlternative {
                version: FieldVersion::Entry,
                guards: Vec::new(),
            }];
            accesses.version_slot_count
        ],
    };
    let point_count = semantics.points().len();
    charge_entries(budget, point_count.saturating_add(1))?;
    let mut incoming = vec![None::<State>; point_count];
    incoming[semantics.entry_point().index()] = Some(initial);
    let mut pending = VecDeque::from([semantics.entry_point()]);
    let mut queued = vec![false; point_count];
    queued[semantics.entry_point().index()] = true;
    while let Some(point) = pending.pop_front() {
        check_cancelled(cancellation)?;
        queued[point.index()] = false;
        let state_size = incoming[point.index()]
            .as_ref()
            .expect("a scheduled point is reachable")
            .size();
        charge_entries(budget, state_size.saturating_add(1))?;
        let mut state = incoming[point.index()]
            .as_ref()
            .expect("a scheduled point is reachable")
            .clone();
        transfer(
            procedure,
            snapshot,
            &accesses,
            point,
            &mut state,
            budget,
            cancellation,
        )?;
        for (edge_id, edge) in semantics.successor_edges(point) {
            check_cancelled(cancellation)?;
            charge_edges(budget, 1)?;
            let state_size = state.size();
            charge_entries(budget, state_size.saturating_add(1))?;
            let mut next = state.clone();
            refine_edge(
                procedure,
                &accesses,
                point,
                edge_id,
                &mut next,
                budget,
                cancellation,
            )?;
            charge_entries(budget, next.size().saturating_sub(state_size))?;
            let changed = if let Some(old) = &mut incoming[edge.target_point.index()] {
                old.join(&next, budget, cancellation)?
            } else {
                incoming[edge.target_point.index()] = Some(next);
                true
            };
            if changed && !queued[edge.target_point.index()] {
                queued[edge.target_point.index()] = true;
                charge_entries(budget, 1)?;
                pending.push_back(edge.target_point);
            }
        }
    }
    let mut loads = Vec::new();
    for point in semantics.points() {
        check_cancelled(cancellation)?;
        charge_entries(budget, 1)?;
        if let Some(state) = incoming[point.id.index()].as_ref() {
            charge_entries(budget, state.size().saturating_add(1))?;
            let mut state = incoming[point.id.index()]
                .take()
                .expect("the state remained live after its size charge");
            loads.extend(transfer(
                procedure,
                snapshot,
                &accesses,
                point.id,
                &mut state,
                budget,
                cancellation,
            )?);
        }
    }
    Ok(loads)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::{
        CancellationToken, SemanticBudget, SemanticRequest, type_flow_adapter,
    };
    use crate::analyzer::{AnalyzerConfig, Language};
    use crate::inline_project::InlineTestProject;
    use crate::type_flow::FieldSlotIndex;

    const SOURCE: &str = concat!(
        "class Box:\n",
        "    def __init__(self, first, second):\n",
        "        self.first = first\n",
        "        self.second = second\n",
        "\n",
        "    def read(self, value):\n",
        "        self.first = value\n",
        "        return self.first\n",
    );

    fn derive_named(name: &str) -> Vec<FieldLoadRefinement> {
        let project = InlineTestProject::with_language(Language::Python)
            .file("app.py", SOURCE)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("app.py"),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("the fixture materializes")
            .available_value()
            .cloned()
            .expect("the fixture stays available");
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some(name)
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .unwrap_or_else(|| panic!("the fixture declares `{name}`"));
        let adapter = type_flow_adapter(Language::Python).expect("Python has a type-flow adapter");
        let field_slots = FieldSlotIndex::build(&workspace, adapter, &mut budget, &cancellation)
            .expect("the fixture's field slots build");
        let class = adapter
            .enclosing_class(&workspace, &procedure)
            .expect("the fixture's methods have an enclosing class");
        derive(
            &workspace,
            adapter,
            &procedure,
            None,
            &class,
            &field_slots,
            &mut budget,
            &cancellation,
        )
        .expect("field refinement completes within the default budget")
    }

    #[test]
    fn a_member_the_procedure_only_stores_carries_no_version_state() {
        assert!(
            derive_named("__init__").is_empty(),
            "a procedure that reads back no member has no load to refine"
        );
    }

    #[test]
    fn a_member_the_procedure_loads_still_carries_version_state() {
        let loads = derive_named("read");
        assert!(
            loads
                .iter()
                .any(|load| load.member.as_ref() == "first" && !load.alternatives.is_empty()),
            "the load of `first` names the versions it could have observed: {loads:#?}"
        );
        assert!(
            loads.iter().all(|load| load.member.as_ref() != "second"),
            "a member this procedure never loads produces no refinement: {loads:#?}"
        );
    }
}
