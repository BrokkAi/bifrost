//! Sparse, procedure-local correlation of data and boolean definitions.
//!
//! A class source can be removed on a guard edge only when the data definition
//! that carries it is paired with a definition of the tested boolean that
//! proves the opposite outcome.  Independent reaching-definition sets lose
//! that relationship at a join.  This module retains the relationship as a
//! set of `(data definition, boolean definition, fact)` tuples and exposes
//! the incompatible data definitions to the type-flow planner.
//!
//! The point state stores that relation factored into its data component and
//! its boolean component, with an explicit entry only for a pair whose
//! branches genuinely correlate the two.  See [`FlowState`].
//!
//! Propagation is sparse: state exists only at the points that can change it
//! or that a consumer reads, and the fixpoint runs over the reduced graph
//! those points form.  See [`carried_points`].
//!
//! The analysis consumes only validated semantic IR.  It does not inspect
//! source text, and it does not use a regular expression or a second parser.
//! Its worklist is iterative so a long or cyclic procedure cannot consume the
//! Rust call stack.  A budget or cancellation failure discards the whole
//! result; callers never receive a silently truncated relation.

use std::collections::VecDeque;
use std::fmt;

use crate::analyzer::semantic::{
    CancellationToken, ControlEdgeId, GuardPredicate, ProcedureHandle, ProgramPointId,
    SemanticBudget, SemanticBudgetExceeded, SemanticEffect, SemanticGapImpact, SemanticValueKind,
    SemanticWork, ValueId,
};
use crate::hash::{HashMap, HashSet};

/// The only boolean facts that can authorize a source exclusion.
///
/// `Unknown` is retained explicitly.  A missing or unsupported semantic fact
/// is never interpreted as either literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BoolFact {
    True,
    False,
    Unknown,
}

impl BoolFact {
    pub const fn opposite(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Unknown => Self::Unknown,
        }
    }

    fn from_literal(value: bool) -> Self {
        if value { Self::True } else { Self::False }
    }
}

/// One program-point definition of a tracked data binding.
///
/// An entry definition uses [`Self::ENTRY_EVENT_INDEX`] and has no RHS.  An
/// explicit unknown write also has no RHS, but has the event index at which
/// the unknown effect occurred.  The distinction is therefore preserved by
/// the location tuple without manufacturing a source value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DefinitionRecord {
    pub binding: ValueId,
    pub point: ProgramPointId,
    pub event_index: usize,
    pub rhs: Option<ValueId>,
}

impl DefinitionRecord {
    /// Sentinel event position for a binding's procedure-entry definition.
    pub const ENTRY_EVENT_INDEX: usize = usize::MAX;

    pub const fn is_entry(self) -> bool {
        self.event_index == Self::ENTRY_EVENT_INDEX
    }
}

/// The data definitions observed at one guard edge for one data binding.
///
/// The four definition lists are disjoint.  A definition whose paired facts
/// contain both the expected and opposite literals is placed in
/// `unknown_data_defs`, because it is not universally compatible with either
/// outcome.  This is the form the parent type-flow planner needs for its
/// universal may-source test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationCandidate {
    pub edge: ControlEdgeId,
    pub bool_binding: ValueId,
    pub expected: BoolFact,
    pub data_binding: ValueId,
    pub all_reaching_data_defs: Vec<DefinitionRecord>,
    pub compatible_data_defs: Vec<DefinitionRecord>,
    pub incompatible_data_defs: Vec<DefinitionRecord>,
    pub unknown_data_defs: Vec<DefinitionRecord>,
}

/// A complete result from one procedure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationAnalysis {
    /// Every tracked data definition, including explicit entry and unknown
    /// definitions.  The vector is in deterministic definition order.
    pub definitions: Vec<DefinitionRecord>,
    /// One row per reachable supported guard edge and data binding.
    pub guard_edge_exclusions: Vec<CorrelationCandidate>,
}

/// Why a correlation analysis did not produce a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorrelationError {
    Budget(SemanticBudgetExceeded),
    Cancelled { timed_out: bool },
}

impl fmt::Display for CorrelationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Budget(error) => write!(
                formatter,
                "correlation analysis exceeded semantic budget: {error}"
            ),
            Self::Cancelled { timed_out: true } => {
                formatter.write_str("correlation analysis timed out")
            }
            Self::Cancelled { timed_out: false } => {
                formatter.write_str("correlation analysis was cancelled")
            }
        }
    }
}

impl std::error::Error for CorrelationError {}

impl From<SemanticBudgetExceeded> for CorrelationError {
    fn from(error: SemanticBudgetExceeded) -> Self {
        Self::Budget(error)
    }
}

/// Analyze one validated procedure's correlated data and boolean definitions.
///
/// The caller supplies the same semantic budget used by the surrounding
/// request.  One `nested_entries` unit is charged for each newly retained
/// pair, which is one element of a state this analysis keeps, and one
/// `control_edges` unit for each CFG edge walked or reduced-graph edge
/// traversed.  Because state exists only at carried points, the retained
/// charge follows the state the analysis holds rather than the procedure's
/// length.  If either lane is exhausted, or cancellation is observed, the
/// function returns an error and no partial relation is exposed.
pub fn analyze_correlations(
    procedure: &ProcedureHandle,
    budget: &mut SemanticBudget,
    cancellation: Option<&CancellationToken>,
) -> Result<CorrelationAnalysis, CorrelationError> {
    check_cancelled(cancellation)?;
    let semantics = procedure.semantics();
    charge_preprocessing_inputs(semantics, budget)?;
    check_cancelled(cancellation)?;
    let data_bindings = tracked_data_bindings(semantics.values());
    let bool_bindings = tested_boolean_bindings(semantics, budget, cancellation)?;
    check_cancelled(cancellation)?;
    if bool_bindings.is_empty() || data_bindings.is_empty() {
        return Ok(CorrelationAnalysis {
            definitions: Vec::new(),
            guard_edge_exclusions: Vec::new(),
        });
    }
    let open_bindings = open_bindings(semantics);
    check_cancelled(cancellation)?;

    // Index every definition needed by the surviving relational question.
    let mut definitions = DefinitionTable::new();
    definitions.index_entry_definitions(
        semantics.entry_point(),
        &data_bindings,
        &bool_bindings,
        budget,
        cancellation,
    )?;
    definitions.index_event_definitions(
        semantics,
        &data_bindings,
        &bool_bindings,
        &open_bindings,
        budget,
        cancellation,
    )?;

    // State is stored only where it is consumed or where it can change, and
    // the fixpoint runs over the reduced graph those points form.
    let successors = cfg_successors(semantics, budget, cancellation)?;
    let carried = carried_points(
        semantics,
        &successors,
        &data_bindings,
        &bool_bindings,
        &open_bindings,
        cancellation,
    )?;
    let carried_successors = carried_successors(&successors, &carried, budget, cancellation)?;

    let initial = FlowState::entry(&data_bindings, &bool_bindings, &definitions, budget)?;
    let point_count = semantics.points().len();
    let mut states = vec![FlowState::default(); point_count];
    let mut exits = vec![FlowState::default(); point_count];
    states[semantics.entry_point().index()] = initial;
    let mut queued = vec![false; point_count];
    queued[semantics.entry_point().index()] = true;
    let mut worklist = VecDeque::from([semantics.entry_point()]);

    while let Some(point_id) = worklist.pop_front() {
        queued[point_id.index()] = false;
        check_cancelled(cancellation)?;
        debug_assert!(
            carried[point_id.index()],
            "the reduced graph schedules only carried points"
        );
        let entry_state = states[point_id.index()].clone();
        let exit_state = transfer_point(
            semantics,
            point_id,
            entry_state,
            &definitions,
            &bool_bindings,
            &data_bindings,
            &open_bindings,
            budget,
            cancellation,
        )?;
        exits[point_id.index()] = exit_state.clone();

        for &target_point in &carried_successors[point_id.index()] {
            check_cancelled(cancellation)?;
            charge_edges(budget, 1)?;
            let target = target_point.index();
            let changed = states[target].join(&exit_state, budget)?;
            if changed && !queued[target] {
                queued[target] = true;
                worklist.push_back(target_point);
            }
        }
    }

    let mut guard_edge_exclusions = Vec::new();
    for guard in semantics.guard_facts() {
        let Some((bool_binding, true_fact)) = guard_binding_and_true_fact(semantics, guard) else {
            continue;
        };
        assert!(
            carried[guard.point.index()],
            "a queried guard point stores its exit state"
        );
        let state = &exits[guard.point.index()];
        for (edge, expected) in [
            (guard.true_edge, true_fact),
            (guard.false_edge, true_fact.opposite()),
        ] {
            let Some(edge) = edge else { continue };
            for &data_binding in &data_bindings {
                let pairs = state.pairs(data_binding, bool_binding);
                let candidate = make_candidate(
                    edge,
                    bool_binding,
                    expected,
                    data_binding,
                    &pairs,
                    &definitions,
                );
                if !candidate.all_reaching_data_defs.is_empty() {
                    guard_edge_exclusions.push(candidate);
                }
            }
        }
    }
    guard_edge_exclusions.sort_by_key(|candidate| {
        (
            candidate.edge,
            candidate.bool_binding,
            candidate.data_binding,
            candidate.expected,
        )
    });

    Ok(CorrelationAnalysis {
        definitions: definitions.data_records,
        guard_edge_exclusions,
    })
}

/// One event's replacement of a tracked component at one program point.
///
/// `rhs` is both the definition's right-hand side and, for a boolean write,
/// the source whose relation the copy carries.  A write with no readable
/// source has `None`, which is the explicit unknown definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ComponentWrite {
    Data {
        binding: ValueId,
        event_index: usize,
        rhs: Option<ValueId>,
    },
    Boolean {
        binding: ValueId,
        event_index: usize,
        rhs: Option<ValueId>,
    },
}

/// Every tracked component one point replaces, in event order.
///
/// Three callers need exactly this list and must agree about it: the
/// definition table interns one record per write, the transfer function
/// replaces one component per write, and [`carried_points`] treats a point
/// with no write as an identity transfer whose state need not be stored.
fn component_writes(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    point: &crate::analyzer::semantic::ProgramPoint,
    data_bindings: &[ValueId],
    bool_bindings: &[ValueId],
    open_bindings: &HashSet<ValueId>,
) -> Vec<ComponentWrite> {
    fn push(
        writes: &mut Vec<ComponentWrite>,
        data_bindings: &[ValueId],
        bool_bindings: &[ValueId],
        event_index: usize,
        binding: ValueId,
        rhs: Option<ValueId>,
    ) {
        if data_bindings.binary_search(&binding).is_ok() {
            writes.push(ComponentWrite::Data {
                binding,
                event_index,
                rhs,
            });
        }
        if bool_bindings.binary_search(&binding).is_ok() {
            writes.push(ComponentWrite::Boolean {
                binding,
                event_index,
                rhs,
            });
        }
    }
    let mut writes = Vec::new();
    for (event_index, event) in point.events.iter().enumerate() {
        match &event.effect {
            SemanticEffect::Assignment { target, value } => push(
                &mut writes,
                data_bindings,
                bool_bindings,
                event_index,
                *target,
                Some(*value),
            ),
            SemanticEffect::ValueFlow {
                source,
                target,
                kind,
            } if bool_bindings.binary_search(target).is_ok()
                && kind.preserves_runtime_class()
                && !is_assignment_transfer_marker(point, event_index, *source, *target) =>
            {
                writes.push(ComponentWrite::Boolean {
                    binding: *target,
                    event_index,
                    rhs: Some(*source),
                });
            }
            effect => {
                for binding in unknown_write_bindings(effect, semantics, open_bindings) {
                    push(
                        &mut writes,
                        data_bindings,
                        bool_bindings,
                        event_index,
                        binding,
                        None,
                    );
                }
            }
        }
        if let Some(result) = produced_value(&event.effect) {
            push(
                &mut writes,
                data_bindings,
                bool_bindings,
                event_index,
                result,
                None,
            );
        }
    }
    writes
}

/// The points whose flow state this analysis stores.
///
/// Every other point has one predecessor and an identity transfer, so its
/// state is its predecessor's exit state repeated.  Storing that copy is what
/// made the charge proportional to procedure length instead of to the state
/// the analysis actually consumes: parso's `tokenize_lines` has 1545 points
/// but replaces a component at only a small fraction of them.
///
/// A point is carried when it is the entry, when two or more edges reach it
/// and its state is therefore a join, when it replaces a component, or when a
/// guard the consumer queries reads its exit state.
fn carried_points(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    successors: &[Vec<ProgramPointId>],
    data_bindings: &[ValueId],
    bool_bindings: &[ValueId],
    open_bindings: &HashSet<ValueId>,
    cancellation: Option<&CancellationToken>,
) -> Result<Vec<bool>, CorrelationError> {
    let point_count = successors.len();
    let mut predecessors = vec![0usize; point_count];
    for targets in successors {
        check_cancelled(cancellation)?;
        for target in targets {
            predecessors[target.index()] = predecessors[target.index()].saturating_add(1);
        }
    }
    let mut carried = vec![false; point_count];
    carried[semantics.entry_point().index()] = true;
    for point in semantics.points() {
        check_cancelled(cancellation)?;
        if predecessors[point.id.index()] >= 2
            || !component_writes(
                semantics,
                point,
                data_bindings,
                bool_bindings,
                open_bindings,
            )
            .is_empty()
        {
            carried[point.id.index()] = true;
        }
    }
    for guard in semantics.guard_facts() {
        check_cancelled(cancellation)?;
        if guard_binding_and_true_fact(semantics, guard).is_some() {
            carried[guard.point.index()] = true;
        }
    }
    Ok(carried)
}

/// For each carried point, the carried points its exit state reaches.
///
/// A chain of uncarried points transmits the state unchanged, so the fixpoint
/// runs over this reduced graph.  Uncarried points have one predecessor, so
/// the chains hanging off distinct carried points are disjoint and building
/// the whole relation walks each CFG edge a bounded number of times.
fn carried_successors(
    successors: &[Vec<ProgramPointId>],
    carried: &[bool],
    budget: &mut SemanticBudget,
    cancellation: Option<&CancellationToken>,
) -> Result<Vec<Vec<ProgramPointId>>, CorrelationError> {
    let point_count = carried.len();
    let mut reduced = vec![Vec::new(); point_count];
    // Generation stamps make the per-walk visited set O(1) to reset. The set
    // is per walk, not global, so a chain shared by two carried points is
    // still reported to both.
    let mut visited = vec![0u32; point_count];
    let mut generation = 0u32;
    let mut stack = Vec::new();
    for (index, carried_point) in carried.iter().enumerate() {
        if !carried_point {
            continue;
        }
        check_cancelled(cancellation)?;
        generation += 1;
        stack.clear();
        stack.extend(successors[index].iter().copied());
        let mut reached = Vec::new();
        while let Some(next) = stack.pop() {
            charge_edges(budget, 1)?;
            if visited[next.index()] == generation {
                continue;
            }
            visited[next.index()] = generation;
            if carried[next.index()] {
                reached.push(next);
                continue;
            }
            stack.extend(successors[next.index()].iter().copied());
        }
        reached.sort_unstable();
        reduced[index] = reached;
    }
    Ok(reduced)
}

/// This procedure's CFG as a successor list, charged once per edge.
fn cfg_successors(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    budget: &mut SemanticBudget,
    cancellation: Option<&CancellationToken>,
) -> Result<Vec<Vec<ProgramPointId>>, CorrelationError> {
    let mut successors = vec![Vec::new(); semantics.points().len()];
    for point in semantics.points() {
        check_cancelled(cancellation)?;
        for (_edge_id, edge) in semantics.successor_edges(point.id) {
            charge_edges(budget, 1)?;
            successors[point.id.index()].push(edge.target_point);
        }
    }
    Ok(successors)
}

fn check_cancelled(cancellation: Option<&CancellationToken>) -> Result<(), CorrelationError> {
    if let Some(token) = cancellation
        && token.is_cancelled()
    {
        return Err(CorrelationError::Cancelled {
            timed_out: token.is_timed_out(),
        });
    }
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

fn charge_pairs(budget: &mut SemanticBudget, count: usize) -> Result<(), CorrelationError> {
    if count == 0 {
        return Ok(());
    }
    budget.charge(SemanticWork {
        nested_entries: count,
        ..SemanticWork::default()
    })?;
    Ok(())
}

fn charge_preprocessing_inputs(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    budget: &mut SemanticBudget,
) -> Result<(), CorrelationError> {
    let event_count = semantics
        .points()
        .iter()
        .map(|point| point.events.len())
        .fold(0, usize::saturating_add);
    budget.charge(SemanticWork {
        values: semantics.values().len(),
        memory_locations: semantics.memory_locations().len(),
        captures: semantics.captures().len(),
        events: event_count,
        nested_entries: semantics.guard_facts().len(),
        ..SemanticWork::default()
    })?;
    Ok(())
}

fn tracked_data_bindings(values: &[crate::analyzer::semantic::SemanticValue]) -> Vec<ValueId> {
    let mut bindings = values
        .iter()
        .filter(|value| is_binding_kind(&value.kind))
        .map(|value| value.id)
        .collect::<Vec<_>>();
    bindings.sort_unstable();
    bindings.dedup();
    bindings
}

fn is_binding_kind(kind: &SemanticValueKind) -> bool {
    matches!(
        kind,
        SemanticValueKind::Local
            | SemanticValueKind::Parameter { .. }
            | SemanticValueKind::Receiver { .. }
    )
}

/// Return bindings whose storage can be changed by a call, continuation, or
/// suspension according to the semantic IR.  A plain local is deliberately
/// absent: an ordinary call does not rebind its caller-local slot.  Address
/// values and mutable/shared capture cells are the structured evidence that a
/// callee can observe or change the binding itself.
pub(super) fn open_bindings(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
) -> HashSet<ValueId> {
    let binding_values = semantics
        .values()
        .iter()
        .filter(|value| is_binding_kind(&value.kind))
        .map(|value| value.id)
        .collect::<HashSet<_>>();
    let mut open_values = HashSet::default();

    for location in semantics.memory_locations() {
        match &location.kind {
            crate::analyzer::semantic::MemoryLocationKind::LexicalCell { binding }
            | crate::analyzer::semantic::MemoryLocationKind::Capture {
                binding: Some(binding),
                ..
            } => {
                open_values.insert(*binding);
            }
            _ => {}
        }
    }
    for capture in semantics.captures() {
        let writable = matches!(
            &capture.mode,
            crate::analyzer::semantic::CaptureMode::SharedCell
                | crate::analyzer::semantic::CaptureMode::MutableCell
                | crate::analyzer::semantic::CaptureMode::Unknown
                | crate::analyzer::semantic::CaptureMode::LanguageDefined(_)
        );
        if !writable {
            continue;
        }
        match capture.captured {
            crate::analyzer::semantic::CaptureSource::Value(value) => {
                open_values.insert(value);
            }
            crate::analyzer::semantic::CaptureSource::Location(location) => {
                if let Some(location) = semantics.memory_location(location)
                    && let crate::analyzer::semantic::MemoryLocationKind::LexicalCell { binding }
                    | crate::analyzer::semantic::MemoryLocationKind::Capture {
                        binding: Some(binding),
                        ..
                    } = &location.kind
                {
                    open_values.insert(*binding);
                }
            }
        }
    }

    // An address target publishes the source value in the IR. Propagate this
    // evidence backwards through validated identity-preserving copies so an
    // address of a temporary still reopens its local/parameter carrier.
    let mut reverse_copies = HashMap::<ValueId, Vec<ValueId>>::default();
    for point in semantics.points() {
        for event in &point.events {
            match &event.effect {
                SemanticEffect::Assignment { target, value }
                    if semantics
                        .value(*target)
                        .is_some_and(|target| target.kind == SemanticValueKind::Address) =>
                {
                    open_values.insert(*value);
                    reverse_copies.entry(*target).or_default().push(*value);
                }
                SemanticEffect::Assignment { target, value } => {
                    reverse_copies.entry(*target).or_default().push(*value);
                }
                SemanticEffect::ValueFlow { source, target, .. }
                    if semantics
                        .value(*target)
                        .is_some_and(|target| target.kind == SemanticValueKind::Address) =>
                {
                    open_values.insert(*source);
                    reverse_copies.entry(*target).or_default().push(*source);
                }
                SemanticEffect::ValueFlow {
                    source,
                    target,
                    kind,
                } if kind.preserves_runtime_class() => {
                    reverse_copies.entry(*target).or_default().push(*source);
                }
                _ => {}
            }
        }
    }
    let mut worklist = open_values.iter().copied().collect::<VecDeque<_>>();
    while let Some(target) = worklist.pop_front() {
        if let Some(sources) = reverse_copies.get(&target) {
            for &source in sources {
                if open_values.insert(source) {
                    worklist.push_back(source);
                }
            }
        }
    }
    open_values
        .into_iter()
        .filter(|value| binding_values.contains(value))
        .collect()
}

/// Collect guard values and every structured copy source that can feed one.
///
/// The closure is deliberately backwards over semantic value-flow rows.  It
/// resolves a temporary produced by a read/copy without treating all values
/// in a procedure as interchangeable, and it stays independent of source
/// spelling and evaluation order.
fn tested_boolean_bindings(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    budget: &mut SemanticBudget,
    cancellation: Option<&CancellationToken>,
) -> Result<Vec<ValueId>, CorrelationError> {
    let mut tested = HashSet::default();
    for guard in semantics.guard_facts() {
        check_cancelled(cancellation)?;
        match guard.predicate {
            GuardPredicate::Truthy { value } => {
                tested.insert(value);
            }
            GuardPredicate::ConstantEquality { .. } => {
                if let Some(subject) = guard.subject {
                    tested.insert(subject);
                }
            }
            GuardPredicate::ConstantBoolean { .. }
            | GuardPredicate::OrderedIntegerComparison { .. }
            | GuardPredicate::NullComparison { .. }
            | GuardPredicate::InstanceOf { .. }
            | GuardPredicate::ExactClass { .. }
            | GuardPredicate::HasMember { .. }
            | GuardPredicate::Opaque { .. } => {}
        }
    }

    // Build both directions of the identity graph once. Correlation can only
    // authorize a kill when a tested value has a possible literal boolean
    // definition. Restricting the seeds to the forward literal closure
    // avoids carrying every unrelated truthiness subject through the product
    // of data and boolean definitions.  The reverse closure below retains the
    // intermediate copies that connect that literal to the guard.
    let mut reverse_copies = HashMap::<ValueId, Vec<ValueId>>::default();
    let mut forward_copies = HashMap::<ValueId, Vec<ValueId>>::default();
    for point in semantics.points() {
        check_cancelled(cancellation)?;
        for event in &point.events {
            check_cancelled(cancellation)?;
            budget.charge(SemanticWork {
                events: 1,
                ..SemanticWork::default()
            })?;
            let (source, target) = match &event.effect {
                SemanticEffect::Assignment { target, value } => (*value, *target),
                SemanticEffect::ValueFlow {
                    source,
                    target,
                    kind,
                } if kind.preserves_runtime_class() => (*source, *target),
                _ => continue,
            };
            reverse_copies.entry(target).or_default().push(source);
            forward_copies.entry(source).or_default().push(target);
        }
    }

    let literal_values = semantics
        .values()
        .iter()
        .filter_map(|value| intrinsic_boolean(semantics, value.id).map(|_| value.id))
        .collect::<Vec<_>>();
    if literal_values.is_empty() {
        return Ok(Vec::new());
    }

    let mut literal_reachable = literal_values.iter().copied().collect::<HashSet<_>>();
    let mut worklist = literal_values.into_iter().collect::<VecDeque<_>>();
    while let Some(source) = worklist.pop_front() {
        let Some(targets) = forward_copies.get(&source) else {
            continue;
        };
        for &target in targets {
            charge_pairs(budget, 1)?;
            check_cancelled(cancellation)?;
            if literal_reachable.insert(target) {
                worklist.push_back(target);
            }
        }
    }

    tested.retain(|value| literal_reachable.contains(value));
    let mut bindings = tested.clone();
    worklist = tested.into_iter().collect::<VecDeque<_>>();
    while let Some(target) = worklist.pop_front() {
        let Some(sources) = reverse_copies.get(&target) else {
            continue;
        };
        for &source in sources {
            budget.charge(SemanticWork {
                nested_entries: 1,
                ..SemanticWork::default()
            })?;
            check_cancelled(cancellation)?;
            // Literal values are handled directly by replace_boolean_component;
            // retaining them as relation keys only adds a Cartesian row. Any
            // other source must be on both the literal and tested closures so
            // that an unsupported side path remains unknown rather than being
            // treated as a boolean fact.
            if intrinsic_boolean(semantics, source).is_none()
                && literal_reachable.contains(&source)
                && bindings.insert(source)
            {
                worklist.push_back(source);
            }
        }
    }
    let mut values = bindings.into_iter().collect::<Vec<_>>();
    values.sort_unstable();
    Ok(values)
}

fn guard_binding_and_true_fact(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    guard: &crate::analyzer::semantic::GuardFact,
) -> Option<(ValueId, BoolFact)> {
    match guard.predicate {
        GuardPredicate::Truthy { value } => Some((value, BoolFact::True)),
        GuardPredicate::ConstantEquality { negated, constant } => {
            let SemanticValueKind::Boolean(value) = semantics.value(constant)?.kind else {
                return None;
            };
            let subject = guard.subject?;
            let fact = BoolFact::from_literal(value);
            Some((subject, if negated { fact.opposite() } else { fact }))
        }
        GuardPredicate::ConstantBoolean { .. }
        | GuardPredicate::OrderedIntegerComparison { .. }
        | GuardPredicate::NullComparison { .. }
        | GuardPredicate::InstanceOf { .. }
        | GuardPredicate::ExactClass { .. }
        | GuardPredicate::HasMember { .. }
        | GuardPredicate::Opaque { .. } => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct BooleanDefinition {
    binding: ValueId,
    point: ProgramPointId,
    event_index: usize,
    rhs: Option<ValueId>,
}

impl BooleanDefinition {
    const ENTRY_EVENT_INDEX: usize = DefinitionRecord::ENTRY_EVENT_INDEX;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Pair {
    data_definition: usize,
    boolean_definition: BooleanDefinition,
    fact: BoolFact,
}

/// Reaching data definitions and boolean facts at one program point.
///
/// The question this analysis answers is which data definitions of one
/// binding reach a guard together with which fact about the tested boolean.
/// Keying that relation by `(data binding, boolean binding)` stores each data
/// binding's reaching definitions once per boolean binding.  On a large
/// procedure the repetition is the whole cost: parso's `tokenize_lines` has
/// 1545 points, 48 data bindings and 6 boolean bindings, and the keyed form
/// charged 683,390 nested entries for state that names 54 components per
/// point (#3163).
///
/// The two components are therefore stored once each and a pair's relation is
/// their product.  Every transfer preserves that form: a data write replaces
/// one binding's reaching set, a boolean write replaces one binding's fact
/// set, and both leave the other component alone.  Only a join can break it,
/// and only for a pair whose two branches disagree about the data component
/// in one direction and about the boolean component in the other.  Those
/// pairs are retained explicitly in `correlated`; they are exactly the branch
/// correlation this analysis exists to keep.
#[derive(Debug, Clone, Default)]
struct FlowState {
    /// Reaching definitions of each tracked data binding, as indices into the
    /// definition table.  The same set for every boolean binding.
    reaching: HashMap<ValueId, HashSet<usize>>,
    /// Reaching definitions of each tested boolean binding with the fact each
    /// proves.  The same set for every data binding outside `correlated`.
    facts: HashMap<ValueId, HashSet<(BooleanDefinition, BoolFact)>>,
    /// Pairs whose relation is smaller than the product of the components
    /// above, stored in full.
    correlated: HashMap<(ValueId, ValueId), HashSet<Pair>>,
}

/// The relation of one pair when neither component constrains the other.
fn product(
    reaching: &HashSet<usize>,
    facts: &HashSet<(BooleanDefinition, BoolFact)>,
) -> HashSet<Pair> {
    reaching
        .iter()
        .flat_map(|&data_definition| {
            facts.iter().map(move |&(boolean_definition, fact)| Pair {
                data_definition,
                boolean_definition,
                fact,
            })
        })
        .collect()
}

/// How one branch's component set relates to the other branch's at a join.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Overlap {
    Equal,
    /// This branch's set is contained in the other branch's.
    SelfIncluded,
    OtherIncluded,
    Incomparable,
}

fn overlap<T: Eq + std::hash::Hash>(left: &HashSet<T>, right: &HashSet<T>) -> Overlap {
    let left_in_right = left.iter().all(|value| right.contains(value));
    let right_in_left = right.iter().all(|value| left.contains(value));
    match (left_in_right, right_in_left) {
        (true, true) => Overlap::Equal,
        (true, false) => Overlap::SelfIncluded,
        (false, true) => Overlap::OtherIncluded,
        (false, false) => Overlap::Incomparable,
    }
}

impl FlowState {
    fn entry(
        data_bindings: &[ValueId],
        bool_bindings: &[ValueId],
        definitions: &DefinitionTable,
        budget: &mut SemanticBudget,
    ) -> Result<Self, CorrelationError> {
        let mut state = Self::default();
        for &data_binding in data_bindings {
            let data_definition = *definitions
                .data_lookup
                .get(&DefinitionRecord {
                    binding: data_binding,
                    point: definitions.entry_point,
                    event_index: DefinitionRecord::ENTRY_EVENT_INDEX,
                    rhs: None,
                })
                .expect("every tracked data binding has an entry definition");
            charge_pairs(budget, 1)?;
            state
                .reaching
                .insert(data_binding, [data_definition].into_iter().collect());
        }
        for &boolean_binding in bool_bindings {
            let boolean_definition = BooleanDefinition {
                binding: boolean_binding,
                point: definitions.entry_point,
                event_index: BooleanDefinition::ENTRY_EVENT_INDEX,
                rhs: None,
            };
            charge_pairs(budget, 1)?;
            state.facts.insert(
                boolean_binding,
                [(boolean_definition, BoolFact::Unknown)]
                    .into_iter()
                    .collect(),
            );
        }
        Ok(state)
    }

    /// The point has no state yet: nothing has reached it.
    fn is_bottom(&self) -> bool {
        self.reaching.is_empty() && self.facts.is_empty()
    }

    /// The `(data definition, boolean definition, fact)` triples that reach
    /// one pair of bindings together.
    fn pairs(&self, data_binding: ValueId, bool_binding: ValueId) -> HashSet<Pair> {
        if let Some(pairs) = self.correlated.get(&(data_binding, bool_binding)) {
            return pairs.clone();
        }
        let (Some(reaching), Some(facts)) = (
            self.reaching.get(&data_binding),
            self.facts.get(&bool_binding),
        ) else {
            return HashSet::default();
        };
        product(reaching, facts)
    }

    /// Every element this state retains, which is what the budget charges.
    fn retained_entries(&self) -> usize {
        self.reaching
            .values()
            .map(HashSet::len)
            .chain(self.facts.values().map(HashSet::len))
            .chain(self.correlated.values().map(HashSet::len))
            .fold(0, usize::saturating_add)
    }

    /// Drop an explicit correlation that is the product of its components
    /// again, so a later join does not carry an exception that no longer
    /// says anything.
    fn normalize(&mut self) {
        let redundant = self
            .correlated
            .iter()
            .filter(|((data_binding, bool_binding), pairs)| {
                match (
                    self.reaching.get(data_binding),
                    self.facts.get(bool_binding),
                ) {
                    (Some(reaching), Some(facts)) => **pairs == product(reaching, facts),
                    _ => true,
                }
            })
            .map(|(&key, _)| key)
            .collect::<Vec<_>>();
        for key in redundant {
            self.correlated.remove(&key);
        }
    }

    fn join(
        &mut self,
        other: &Self,
        budget: &mut SemanticBudget,
    ) -> Result<bool, CorrelationError> {
        if other.is_bottom() {
            return Ok(false);
        }
        if self.is_bottom() {
            charge_pairs(budget, other.retained_entries())?;
            *self = other.clone();
            return Ok(true);
        }
        let empty_reaching = HashSet::<usize>::default();
        let empty_facts = HashSet::<(BooleanDefinition, BoolFact)>::default();
        let changed_data = other
            .reaching
            .iter()
            .map(|(&binding, reaching)| {
                (
                    binding,
                    overlap(
                        self.reaching.get(&binding).unwrap_or(&empty_reaching),
                        reaching,
                    ),
                )
            })
            .filter(|(_, overlap)| *overlap != Overlap::Equal)
            .collect::<Vec<_>>();
        let changed_facts = other
            .facts
            .iter()
            .map(|(&binding, facts)| {
                (
                    binding,
                    overlap(self.facts.get(&binding).unwrap_or(&empty_facts), facts),
                )
            })
            .filter(|(_, overlap)| *overlap != Overlap::Equal)
            .collect::<Vec<_>>();
        // `(A1 x B1) u (A2 x B2)` is the product of the joined components
        // whenever one branch's relation contains the other's, so only a pair
        // whose branches disagree about both components in opposite
        // directions can need an explicit union.  Every pair either side
        // already states explicitly is a candidate too.  The union decides.
        let mut candidates = self
            .correlated
            .keys()
            .chain(other.correlated.keys())
            .copied()
            .collect::<HashSet<_>>();
        for &(data_binding, data_overlap) in &changed_data {
            for &(bool_binding, fact_overlap) in &changed_facts {
                if data_overlap == fact_overlap
                    && matches!(data_overlap, Overlap::SelfIncluded | Overlap::OtherIncluded)
                {
                    continue;
                }
                candidates.insert((data_binding, bool_binding));
            }
        }
        let mut changed = false;
        let mut unions = Vec::with_capacity(candidates.len());
        for key in candidates {
            let previous = self.pairs(key.0, key.1);
            let mut pairs = previous.clone();
            for pair in other.pairs(key.0, key.1) {
                pairs.insert(pair);
            }
            changed |= pairs.len() != previous.len();
            unions.push((key, previous.len(), pairs));
        }
        let mut joined_reaching = self.reaching.clone();
        let mut joined_facts = self.facts.clone();
        for (&binding, reaching) in &other.reaching {
            joined_reaching.entry(binding).or_default().extend(reaching);
        }
        for (&binding, facts) in &other.facts {
            joined_facts.entry(binding).or_default().extend(facts);
        }
        // Keep an explicit union only where it says more than the product of
        // the joined components: the product is the cheaper statement and it
        // is exact wherever it holds.
        let mut correlated = HashMap::default();
        for (key, previous_len, pairs) in unions {
            let is_product = match (joined_reaching.get(&key.0), joined_facts.get(&key.1)) {
                (Some(reaching), Some(facts)) => pairs == product(reaching, facts),
                _ => pairs.is_empty(),
            };
            if is_product {
                continue;
            }
            // Charge the triples the union adds. The rest of the relation is
            // what this state already stood for, whether it stated it as a
            // product or as an explicit correlation, and it was charged when
            // it arrived.
            charge_pairs(budget, pairs.len().saturating_sub(previous_len))?;
            correlated.insert(key, pairs);
        }
        self.correlated = correlated;
        for (&binding, reaching) in &other.reaching {
            let destination = self.reaching.entry(binding).or_default();
            for &definition in reaching {
                if destination.insert(definition) {
                    charge_pairs(budget, 1)?;
                    changed = true;
                }
            }
        }
        for (&binding, facts) in &other.facts {
            let destination = self.facts.entry(binding).or_default();
            for &fact in facts {
                if destination.insert(fact) {
                    charge_pairs(budget, 1)?;
                    changed = true;
                }
            }
        }
        Ok(changed)
    }
}

#[derive(Debug, Default)]
struct DefinitionTable {
    entry_point: ProgramPointId,
    data_records: Vec<DefinitionRecord>,
    data_lookup: HashMap<DefinitionRecord, usize>,
    boolean_records: HashMap<BooleanDefinition, BooleanDefinition>,
}

impl DefinitionTable {
    fn new() -> Self {
        Self::default()
    }

    fn index_entry_definitions(
        &mut self,
        entry_point: ProgramPointId,
        data_bindings: &[ValueId],
        bool_bindings: &[ValueId],
        budget: &mut SemanticBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Result<(), CorrelationError> {
        self.entry_point = entry_point;
        for &binding in data_bindings {
            check_cancelled(cancellation)?;
            charge_pairs(budget, 1)?;
            self.intern_data(DefinitionRecord {
                binding,
                point: entry_point,
                event_index: DefinitionRecord::ENTRY_EVENT_INDEX,
                rhs: None,
            });
        }
        for &binding in bool_bindings {
            check_cancelled(cancellation)?;
            charge_pairs(budget, 1)?;
            self.intern_boolean(BooleanDefinition {
                binding,
                point: entry_point,
                event_index: BooleanDefinition::ENTRY_EVENT_INDEX,
                rhs: None,
            });
        }
        Ok(())
    }

    fn index_event_definitions(
        &mut self,
        semantics: &crate::analyzer::semantic::ProcedureSemantics,
        data_bindings: &[ValueId],
        bool_bindings: &[ValueId],
        open_bindings: &HashSet<ValueId>,
        budget: &mut SemanticBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Result<(), CorrelationError> {
        for point in semantics.points() {
            check_cancelled(cancellation)?;
            budget.charge(SemanticWork {
                events: point.events.len(),
                ..SemanticWork::default()
            })?;
            for write in component_writes(
                semantics,
                point,
                data_bindings,
                bool_bindings,
                open_bindings,
            ) {
                check_cancelled(cancellation)?;
                match write {
                    ComponentWrite::Data {
                        binding,
                        event_index,
                        rhs,
                    } => {
                        self.intern_data(DefinitionRecord {
                            binding,
                            point: point.id,
                            event_index,
                            rhs,
                        });
                    }
                    ComponentWrite::Boolean {
                        binding,
                        event_index,
                        rhs,
                    } => {
                        self.intern_boolean(BooleanDefinition {
                            binding,
                            point: point.id,
                            event_index,
                            rhs,
                        });
                    }
                }
            }
        }
        self.data_records.sort_unstable();
        self.data_lookup.clear();
        for (index, definition) in self.data_records.iter().copied().enumerate() {
            self.data_lookup.insert(definition, index);
        }
        Ok(())
    }

    fn intern_data(&mut self, definition: DefinitionRecord) -> usize {
        if let Some(&index) = self.data_lookup.get(&definition) {
            return index;
        }
        let index = self.data_records.len();
        self.data_records.push(definition);
        self.data_lookup.insert(definition, index);
        index
    }

    fn intern_boolean(&mut self, definition: BooleanDefinition) -> BooleanDefinition {
        self.boolean_records.insert(definition, definition);
        definition
    }

    fn data_definition(
        &self,
        binding: ValueId,
        point: ProgramPointId,
        event_index: usize,
        rhs: Option<ValueId>,
    ) -> usize {
        *self
            .data_lookup
            .get(&DefinitionRecord {
                binding,
                point,
                event_index,
                rhs,
            })
            .expect("indexed data definition exists")
    }
}

#[allow(clippy::too_many_arguments)]
fn transfer_point(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    point_id: ProgramPointId,
    mut state: FlowState,
    definitions: &DefinitionTable,
    bool_bindings: &[ValueId],
    data_bindings: &[ValueId],
    open_bindings: &HashSet<ValueId>,
    budget: &mut SemanticBudget,
    cancellation: Option<&CancellationToken>,
) -> Result<FlowState, CorrelationError> {
    let point = semantics.point(point_id).expect("validated point exists");
    for write in component_writes(
        semantics,
        point,
        data_bindings,
        bool_bindings,
        open_bindings,
    ) {
        check_cancelled(cancellation)?;
        match write {
            ComponentWrite::Data {
                binding,
                event_index,
                rhs,
            } => {
                let definition = definitions.data_definition(binding, point_id, event_index, rhs);
                replace_data_component(&mut state, binding, definition);
            }
            ComponentWrite::Boolean {
                binding,
                event_index,
                rhs,
            } => {
                let definition = BooleanDefinition {
                    binding,
                    point: point_id,
                    event_index,
                    rhs,
                };
                replace_boolean_component(
                    &mut state,
                    binding,
                    rhs,
                    definition,
                    semantics,
                    bool_bindings,
                    budget,
                )?;
            }
        }
    }
    Ok(state)
}

fn replace_data_component(state: &mut FlowState, binding: ValueId, definition: usize) {
    if state.is_bottom() {
        return;
    }
    state
        .reaching
        .insert(binding, [definition].into_iter().collect());
    for ((data_binding, _), pairs) in &mut state.correlated {
        if *data_binding == binding {
            let replacement = pairs
                .drain()
                .map(|pair| Pair {
                    data_definition: definition,
                    ..pair
                })
                .collect();
            *pairs = replacement;
        }
    }
    state.normalize();
}

fn replace_boolean_component(
    state: &mut FlowState,
    target: ValueId,
    source: Option<ValueId>,
    definition: BooleanDefinition,
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    bool_bindings: &[ValueId],
    budget: &mut SemanticBudget,
) -> Result<(), CorrelationError> {
    // A source relation is the only path that preserves data/boolean
    // correlation.  Direct intrinsic booleans are independent of the current
    // data binding and can therefore update every retained data definition.
    // Other sources become an explicit unknown component.
    if state.is_bottom() {
        return Ok(());
    }
    let source_literal = source.and_then(|source| intrinsic_boolean(semantics, source));
    let source_is_tracked = source_literal.is_none()
        && source.is_some_and(|source| bool_bindings.binary_search(&source).is_ok());
    if let Some(value) = source_literal {
        return replace_boolean_fact_component(
            state,
            target,
            definition,
            BoolFact::from_literal(value),
            budget,
        );
    }
    if !source_is_tracked {
        return replace_boolean_fact_component(
            state,
            target,
            definition,
            BoolFact::Unknown,
            budget,
        );
    }
    // The copy carries the source binding's relation, so the target's fact
    // component and every correlation the source retained move with it under
    // the new boolean definition.
    let source = source.expect("tracked source");
    let facts = state
        .facts
        .get(&source)
        .map(|facts| {
            facts
                .iter()
                .map(|&(_, fact)| (definition, fact))
                .collect::<HashSet<_>>()
        })
        .unwrap_or_default();
    let correlated = state
        .correlated
        .iter()
        .filter(|((_, boolean_binding), _)| *boolean_binding == source)
        .map(|(&(data_binding, _), pairs)| {
            (
                (data_binding, target),
                pairs
                    .iter()
                    .map(|pair| Pair {
                        boolean_definition: definition,
                        ..*pair
                    })
                    .collect::<HashSet<_>>(),
            )
        })
        .collect::<Vec<_>>();
    state
        .correlated
        .retain(|(_, boolean_binding), _| *boolean_binding != target);
    charge_pairs(budget, facts.len())?;
    state.facts.insert(target, facts);
    for (key, pairs) in correlated {
        charge_pairs(budget, pairs.len())?;
        state.correlated.insert(key, pairs);
    }
    state.normalize();
    Ok(())
}

fn replace_boolean_fact_component(
    state: &mut FlowState,
    target: ValueId,
    definition: BooleanDefinition,
    fact: BoolFact,
    budget: &mut SemanticBudget,
) -> Result<(), CorrelationError> {
    if state.is_bottom() {
        return Ok(());
    }
    // One definition with one fact reaches every data definition of every
    // binding: the write says nothing about which data definition holds, so
    // the pair's relation is the product again.
    state
        .correlated
        .retain(|(_, boolean_binding), _| *boolean_binding != target);
    charge_pairs(budget, 1)?;
    state
        .facts
        .insert(target, [(definition, fact)].into_iter().collect());
    Ok(())
}

fn intrinsic_boolean(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    value: ValueId,
) -> Option<bool> {
    match &semantics.value(value)?.kind {
        SemanticValueKind::Boolean(value) => Some(*value),
        _ => None,
    }
}

fn is_assignment_transfer_marker(
    point: &crate::analyzer::semantic::ProgramPoint,
    event_index: usize,
    source: ValueId,
    target: ValueId,
) -> bool {
    event_index > 0
        && matches!(
            &point.events[event_index - 1].effect,
            SemanticEffect::Assignment {
                target: previous_target,
                value: previous_value,
            } if *previous_target == target && *previous_value == source
        )
}

/// Return only bindings whose semantic IR identifies a write target.
///
/// A call or an ordinary heap write does not rebind a procedure-local slot:
/// invalidating every local at every call destroys the very branch correlation
/// this analysis is meant to preserve. Calls reopen only the IR-proven
/// address/capture/lexical-cell bindings. Lexical-cell/capture stores and
/// value-scoped gaps do name a writable binding, so those are explicit
/// openness points. Produced call/async results are handled separately by
/// [`produced_value`].
pub(super) fn unknown_write_bindings(
    effect: &SemanticEffect,
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    open_bindings: &HashSet<ValueId>,
) -> Vec<ValueId> {
    match effect {
        SemanticEffect::MemoryStore { location, .. } => semantics
            .memory_location(*location)
            .and_then(|location| match &location.kind {
                crate::analyzer::semantic::MemoryLocationKind::LexicalCell { binding }
                | crate::analyzer::semantic::MemoryLocationKind::Capture {
                    binding: Some(binding),
                    ..
                } => Some(vec![*binding]),
                crate::analyzer::semantic::MemoryLocationKind::Capture {
                    binding: None, ..
                } => Some(sorted_bindings(open_bindings)),
                _ => None,
            })
            .unwrap_or_default(),
        SemanticEffect::Invoke { .. }
        | SemanticEffect::CallContinuation { .. }
        | SemanticEffect::AsyncSuspend { .. }
        | SemanticEffect::AsyncResume { .. }
        | SemanticEffect::Synchronization { .. } => sorted_bindings(open_bindings),
        SemanticEffect::Gap { gap } => semantics
            .gap(*gap)
            .filter(|gap| {
                gap.impacts.contains(SemanticGapImpact::ValueFlow)
                    || gap.impacts.contains(SemanticGapImpact::Aliasing)
            })
            .map(|gap| match gap.subject {
                crate::analyzer::semantic::SemanticGapSubject::Value(binding) => vec![binding],
                _ => sorted_bindings(open_bindings),
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn sorted_bindings(bindings: &HashSet<ValueId>) -> Vec<ValueId> {
    let mut bindings = bindings.iter().copied().collect::<Vec<_>>();
    bindings.sort_unstable();
    bindings
}

pub(super) fn produced_value(effect: &SemanticEffect) -> Option<ValueId> {
    match effect {
        SemanticEffect::MemoryLoad { result, .. }
        | SemanticEffect::CallableCreation { result, .. }
        | SemanticEffect::CallableReference { result, .. }
        | SemanticEffect::AsyncResume {
            result: Some(result),
            ..
        } => Some(*result),
        _ => None,
    }
}

fn make_candidate(
    edge: ControlEdgeId,
    bool_binding: ValueId,
    expected: BoolFact,
    data_binding: ValueId,
    pairs: &HashSet<Pair>,
    definitions: &DefinitionTable,
) -> CorrelationCandidate {
    let mut by_data = HashMap::<usize, (bool, bool, bool)>::default();
    for pair in pairs {
        let entry = by_data.entry(pair.data_definition).or_default();
        match pair.fact {
            BoolFact::Unknown => entry.2 = true,
            fact if fact == expected => entry.0 = true,
            fact if fact == expected.opposite() => entry.1 = true,
            _ => entry.2 = true,
        }
    }
    let mut all = Vec::new();
    let mut compatible = Vec::new();
    let mut incompatible = Vec::new();
    let mut unknown = Vec::new();
    let mut ids = by_data.keys().copied().collect::<Vec<_>>();
    ids.sort_unstable();
    for id in ids {
        let record = definitions.data_records[id];
        all.push(record);
        let (has_compatible, has_incompatible, has_unknown) = by_data[&id];
        match (has_compatible, has_incompatible, has_unknown) {
            (true, false, false) => compatible.push(record),
            (false, true, false) => incompatible.push(record),
            _ => unknown.push(record),
        }
    }
    CorrelationCandidate {
        edge,
        bool_binding,
        expected,
        data_binding,
        all_reaching_data_defs: all,
        compatible_data_defs: compatible,
        incompatible_data_defs: incompatible,
        unknown_data_defs: unknown,
    }
}

#[cfg(test)]
mod correlation_properties {
    use super::*;
    use proptest::prelude::*;
    use std::collections::BTreeMap;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    struct ReferencePair {
        data_definition: usize,
        boolean_definition: usize,
        fact: BoolFact,
    }

    #[derive(Debug, Clone, Default)]
    struct ReferenceState {
        relations: BTreeMap<(ValueId, ValueId), Vec<ReferencePair>>,
    }

    impl ReferenceState {
        fn join(&mut self, other: &Self) {
            for (&key, pairs) in &other.relations {
                let destination = self.relations.entry(key).or_default();
                for &pair in pairs {
                    if !destination.contains(&pair) {
                        destination.push(pair);
                    }
                }
                destination.sort_unstable_by_key(|pair| {
                    (pair.data_definition, pair.boolean_definition, pair.fact)
                });
            }
        }
    }

    fn boolean_definition(index: usize, binding: ValueId) -> BooleanDefinition {
        BooleanDefinition {
            binding,
            point: ProgramPointId::new(index as u32),
            event_index: index,
            rhs: None,
        }
    }

    fn seed_states(
        data_bindings: &[ValueId],
        boolean_bindings: &[ValueId],
    ) -> (FlowState, ReferenceState) {
        let mut actual = FlowState::default();
        let mut reference = ReferenceState::default();
        for &data_binding in data_bindings {
            actual
                .reaching
                .insert(data_binding, [0].into_iter().collect());
        }
        for &boolean_binding in boolean_bindings {
            actual.facts.insert(
                boolean_binding,
                [(boolean_definition(0, boolean_binding), BoolFact::Unknown)]
                    .into_iter()
                    .collect(),
            );
        }
        for &data_binding in data_bindings {
            for &boolean_binding in boolean_bindings {
                reference.relations.insert(
                    (data_binding, boolean_binding),
                    vec![ReferencePair {
                        data_definition: 0,
                        boolean_definition: 0,
                        fact: BoolFact::Unknown,
                    }],
                );
            }
        }
        (actual, reference)
    }

    fn reference_replace_data(state: &mut ReferenceState, binding: ValueId, definition: usize) {
        for ((data_binding, _), pairs) in &mut state.relations {
            if *data_binding == binding {
                for pair in pairs.iter_mut() {
                    pair.data_definition = definition;
                }
                pairs.sort_unstable_by_key(|pair| {
                    (pair.data_definition, pair.boolean_definition, pair.fact)
                });
                pairs.dedup();
            }
        }
    }

    fn reference_replace_boolean_fact(
        state: &mut ReferenceState,
        target: ValueId,
        definition: usize,
        fact: BoolFact,
    ) {
        let keys = state
            .relations
            .keys()
            .copied()
            .filter(|(_, boolean_binding)| *boolean_binding == target)
            .collect::<Vec<_>>();
        for (data_binding, _) in keys {
            let mut data_definitions = state
                .relations
                .iter()
                .filter(|((binding, _), _)| *binding == data_binding)
                .flat_map(|(_, pairs)| pairs.iter().map(|pair| pair.data_definition))
                .collect::<Vec<_>>();
            data_definitions.sort_unstable();
            data_definitions.dedup();
            state.relations.insert(
                (data_binding, target),
                data_definitions
                    .into_iter()
                    .map(|data_definition| ReferencePair {
                        data_definition,
                        boolean_definition: definition,
                        fact,
                    })
                    .collect(),
            );
        }
    }

    /// The relation the factored state stands for, pair by pair, so the
    /// reference model can compare against the same tuples the consumer
    /// reads.
    fn actual_signature(
        state: &FlowState,
        data_bindings: &[ValueId],
        boolean_bindings: &[ValueId],
    ) -> Vec<(ValueId, ValueId, usize, usize, BoolFact)> {
        let mut signature = Vec::new();
        for &data_binding in data_bindings {
            for &boolean_binding in boolean_bindings {
                for pair in state.pairs(data_binding, boolean_binding) {
                    signature.push((
                        data_binding,
                        boolean_binding,
                        pair.data_definition,
                        pair.boolean_definition.event_index,
                        pair.fact,
                    ));
                }
            }
        }
        signature.sort_unstable();
        signature
    }

    fn reference_signature(
        state: &ReferenceState,
    ) -> Vec<(ValueId, ValueId, usize, usize, BoolFact)> {
        let mut signature = state
            .relations
            .iter()
            .flat_map(|(&(data_binding, boolean_binding), pairs)| {
                pairs.iter().map(move |pair| {
                    (
                        data_binding,
                        boolean_binding,
                        pair.data_definition,
                        pair.boolean_definition,
                        pair.fact,
                    )
                })
            })
            .collect::<Vec<_>>();
        signature.sort_unstable();
        signature
    }

    fn definition_table(count: usize) -> DefinitionTable {
        let mut definitions = DefinitionTable::default();
        for index in 0..count {
            definitions.intern_data(DefinitionRecord {
                binding: ValueId::new(index as u32),
                point: ProgramPointId::new(index as u32),
                event_index: index,
                rhs: None,
            });
        }
        definitions
    }

    fn reference_candidate(
        expected: BoolFact,
        pairs: &[ReferencePair],
    ) -> (Vec<usize>, Vec<usize>, Vec<usize>, Vec<usize>) {
        let mut facts_by_data = BTreeMap::<usize, (bool, bool, bool)>::new();
        for pair in pairs {
            let facts = facts_by_data.entry(pair.data_definition).or_default();
            match pair.fact {
                BoolFact::Unknown => facts.2 = true,
                fact if fact == expected => facts.0 = true,
                fact if fact == expected.opposite() => facts.1 = true,
                _ => facts.2 = true,
            }
        }
        let mut all = Vec::new();
        let mut compatible = Vec::new();
        let mut incompatible = Vec::new();
        let mut unknown = Vec::new();
        for (data_definition, (has_compatible, has_incompatible, has_unknown)) in facts_by_data {
            all.push(data_definition);
            match (has_compatible, has_incompatible, has_unknown) {
                (true, false, false) => compatible.push(data_definition),
                (false, true, false) => incompatible.push(data_definition),
                _ => unknown.push(data_definition),
            }
        }
        (all, compatible, incompatible, unknown)
    }

    fn candidate_signature(
        candidate: &CorrelationCandidate,
    ) -> (Vec<usize>, Vec<usize>, Vec<usize>, Vec<usize>) {
        (
            candidate
                .all_reaching_data_defs
                .iter()
                .map(|definition| definition.event_index)
                .collect(),
            candidate
                .compatible_data_defs
                .iter()
                .map(|definition| definition.event_index)
                .collect(),
            candidate
                .incompatible_data_defs
                .iter()
                .map(|definition| definition.event_index)
                .collect(),
            candidate
                .unknown_data_defs
                .iter()
                .map(|definition| definition.event_index)
                .collect(),
        )
    }

    #[derive(Debug, Clone, Copy)]
    enum TraceOperation {
        ReplaceData {
            binding: u8,
            definition: u16,
        },
        ReplaceBoolean {
            binding: u8,
            definition: u16,
            fact: BoolFact,
        },
        JoinData {
            binding: u8,
            definition: u16,
        },
        JoinBoolean {
            binding: u8,
            definition: u16,
            fact: BoolFact,
        },
        /// Two branches that disagree about the data component and about the
        /// boolean component. Their union is the one relation the factored
        /// state cannot state as a product of its components.
        JoinCorrelated {
            binding: u8,
            definition: u16,
            fact: BoolFact,
        },
    }

    impl TraceOperation {
        fn binding(self) -> usize {
            match self {
                Self::ReplaceData { binding, .. }
                | Self::ReplaceBoolean { binding, .. }
                | Self::JoinData { binding, .. }
                | Self::JoinBoolean { binding, .. }
                | Self::JoinCorrelated { binding, .. } => binding as usize,
            }
        }
    }

    fn trace_operation_strategy() -> impl Strategy<Value = TraceOperation> {
        let binding = 0_u8..2;
        let definition = 1_u16..299;
        let fact = (0_u8..3).prop_map(|fact| match fact {
            0 => BoolFact::True,
            1 => BoolFact::False,
            _ => BoolFact::Unknown,
        });
        prop_oneof![
            (binding.clone(), definition.clone()).prop_map(|(binding, definition)| {
                TraceOperation::ReplaceData {
                    binding,
                    definition,
                }
            }),
            (binding.clone(), definition.clone(), fact.clone()).prop_map(
                |(binding, definition, fact)| TraceOperation::ReplaceBoolean {
                    binding,
                    definition,
                    fact,
                }
            ),
            (binding.clone(), definition.clone()).prop_map(|(binding, definition)| {
                TraceOperation::JoinData {
                    binding,
                    definition,
                }
            }),
            (binding.clone(), definition.clone(), fact.clone()).prop_map(
                |(binding, definition, fact)| TraceOperation::JoinBoolean {
                    binding,
                    definition,
                    fact,
                }
            ),
            (binding, definition, fact).prop_map(|(binding, definition, fact)| {
                TraceOperation::JoinCorrelated {
                    binding,
                    definition,
                    fact,
                }
            }),
        ]
    }

    /// The reduced graph must preserve reachability between carried points.
    ///
    /// The oracle is independent of the reduction: plain breadth-first search
    /// over the whole generated CFG. If the two relations agree for every
    /// carried source, then a fixpoint over the reduced graph reaches exactly
    /// the carried points a fixpoint over the whole CFG reaches, which is what
    /// makes storing state only at carried points equivalent.
    fn reachable_in_full_graph(
        successors: &[Vec<ProgramPointId>],
        from: usize,
    ) -> std::collections::BTreeSet<usize> {
        // Reachability along one or more edges, so a cycle reports its own
        // entry point exactly as the reduced closure does.
        let mut seen = std::collections::BTreeSet::new();
        let mut visited = vec![false; successors.len()];
        let mut queue = VecDeque::from([from]);
        while let Some(point) = queue.pop_front() {
            for target in &successors[point] {
                if !visited[target.index()] {
                    visited[target.index()] = true;
                    seen.insert(target.index());
                    queue.push_back(target.index());
                }
            }
        }
        seen
    }

    /// A carried marking the production rule can produce: every point two or
    /// more edges reach is carried, and any other point may be.
    fn graph_strategy() -> impl Strategy<Value = (Vec<Vec<ProgramPointId>>, Vec<bool>)> {
        (2_usize..=8)
            .prop_flat_map(|point_count| {
                (
                    Just(point_count),
                    prop::collection::vec(
                        prop::collection::vec(0_usize..point_count, 0..=3),
                        point_count,
                    ),
                    prop::collection::vec(any::<bool>(), point_count),
                )
            })
            .prop_map(|(point_count, edges, extra)| {
                let successors = edges
                    .into_iter()
                    .map(|targets| {
                        let mut targets = targets
                            .into_iter()
                            .map(|target| ProgramPointId::new(target as u32))
                            .collect::<Vec<_>>();
                        targets.sort_unstable();
                        targets.dedup();
                        targets
                    })
                    .collect::<Vec<_>>();
                let mut predecessors = vec![0usize; point_count];
                for targets in &successors {
                    for target in targets {
                        predecessors[target.index()] += 1;
                    }
                }
                let mut carried = extra;
                carried[0] = true;
                for (index, count) in predecessors.iter().enumerate() {
                    if *count >= 2 {
                        carried[index] = true;
                    }
                }
                (successors, carried)
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]
        #[test]
        fn reduced_graph_preserves_carried_reachability(
            (successors, carried) in graph_strategy()
        ) {
            let mut budget = SemanticBudget::uniform(100_000).expect("positive test budget");
            let reduced = carried_successors(&successors, &carried, &mut budget, None)
                .expect("a small reduced graph stays within budget");

            for source in 0..carried.len() {
                if !carried[source] {
                    prop_assert!(reduced[source].is_empty());
                    continue;
                }
                let mut closure = std::collections::BTreeSet::new();
                let mut queue = VecDeque::from([source]);
                while let Some(point) = queue.pop_front() {
                    for target in &reduced[point] {
                        if closure.insert(target.index()) {
                            queue.push_back(target.index());
                        }
                    }
                }
                let expected = reachable_in_full_graph(&successors, source)
                    .into_iter()
                    .filter(|point| carried[*point])
                    .collect::<std::collections::BTreeSet<_>>();
                prop_assert_eq!(closure, expected);
            }
        }
    }

    // Exercises short generated finite traces. The reference keeps sorted
    // vectors and independently enumerates the four candidate classes; it
    // does not call the production replacement or join helpers.
    proptest! {
        #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]
        #[test]
        fn finite_relation_matches_reference(
            trace in prop::collection::vec(trace_operation_strategy(), 1..=8)
        ) {
        let data_bindings = [ValueId::new(1), ValueId::new(2)];
        let boolean_bindings = [ValueId::new(3), ValueId::new(4)];
        let definitions = definition_table(300);
        let (mut actual, mut reference) = seed_states(&data_bindings, &boolean_bindings);
        let mut budget = SemanticBudget::uniform(100_000).expect("positive test budget");
        for (step, operation) in trace.iter().copied().enumerate() {
            let data_binding = data_bindings[operation.binding()];
            let boolean_binding = boolean_bindings[operation.binding()];
            match operation {
                TraceOperation::ReplaceData { definition, .. } => {
                    replace_data_component(&mut actual, data_binding, definition as usize);
                    reference_replace_data(&mut reference, data_binding, definition as usize);
                }
                TraceOperation::ReplaceBoolean {
                    definition, fact, ..
                } => {
                    replace_boolean_fact_component(
                        &mut actual,
                        boolean_binding,
                        boolean_definition(definition as usize, boolean_binding),
                        fact,
                        &mut budget,
                    )
                    .expect("finite relation stays within budget");
                    reference_replace_boolean_fact(
                        &mut reference,
                        boolean_binding,
                        definition as usize,
                        fact,
                    );
                }
                TraceOperation::JoinData { definition, .. } => {
                    let mut branch_actual = actual.clone();
                    let mut branch_reference = reference.clone();
                    replace_data_component(&mut branch_actual, data_binding, definition as usize);
                    reference_replace_data(
                        &mut branch_reference,
                        data_binding,
                        definition as usize,
                    );
                    actual
                        .join(&branch_actual, &mut budget)
                        .expect("finite join stays within budget");
                    reference.join(&branch_reference);
                }
                TraceOperation::JoinBoolean {
                    definition, fact, ..
                } => {
                    let mut branch_actual = actual.clone();
                    let mut branch_reference = reference.clone();
                    replace_boolean_fact_component(
                        &mut branch_actual,
                        boolean_binding,
                        boolean_definition(definition as usize, boolean_binding),
                        fact,
                        &mut budget,
                    )
                    .expect("finite loop state stays within budget");
                    reference_replace_boolean_fact(
                        &mut branch_reference,
                        boolean_binding,
                        definition as usize,
                        fact,
                    );
                    actual
                        .join(&branch_actual, &mut budget)
                        .expect("finite loop join stays within budget");
                    reference.join(&branch_reference);
                }
                TraceOperation::JoinCorrelated {
                    definition, fact, ..
                } => {
                    let mut data_actual = actual.clone();
                    let mut data_reference = reference.clone();
                    replace_data_component(&mut data_actual, data_binding, definition as usize);
                    reference_replace_data(&mut data_reference, data_binding, definition as usize);
                    let mut boolean_actual = actual.clone();
                    let mut boolean_reference = reference.clone();
                    replace_boolean_fact_component(
                        &mut boolean_actual,
                        boolean_binding,
                        boolean_definition(definition as usize, boolean_binding),
                        fact,
                        &mut budget,
                    )
                    .expect("finite correlated branch stays within budget");
                    reference_replace_boolean_fact(
                        &mut boolean_reference,
                        boolean_binding,
                        definition as usize,
                        fact,
                    );
                    data_actual
                        .join(&boolean_actual, &mut budget)
                        .expect("finite correlated join stays within budget");
                    data_reference.join(&boolean_reference);
                    actual = data_actual;
                    reference = data_reference;
                }
            }
                assert_eq!(
                    actual_signature(&actual, &data_bindings, &boolean_bindings),
                    reference_signature(&reference),
                    "relation mismatch at step {step}"
                );
        }

        // Reapply one fixed loop body until two successive joins are equal.
        // The finite reference must reach the same fixed point; this catches
        // accidental pair loss on a backedge.
        let loop_binding = boolean_bindings[trace.len() % boolean_bindings.len()];
        let loop_definition = 299;
        let mut previous_actual = None;
        let mut previous_reference = None;
        for _ in 0..3 {
            let mut body_actual = actual.clone();
            let mut body_reference = reference.clone();
            replace_boolean_fact_component(
                &mut body_actual,
                loop_binding,
                boolean_definition(loop_definition, loop_binding),
                BoolFact::True,
                &mut budget,
            )
            .expect("fixed loop stays within budget");
            reference_replace_boolean_fact(
                &mut body_reference,
                loop_binding,
                loop_definition,
                BoolFact::True,
            );
            actual
                .join(&body_actual, &mut budget)
                .expect("fixed loop join stays within budget");
            reference.join(&body_reference);
            let actual_signature_now = actual_signature(&actual, &data_bindings, &boolean_bindings);
            let reference_signature_now = reference_signature(&reference);
            if let Some(previous) = &previous_actual {
                assert_eq!(
                    &actual_signature_now, previous,
                    "production loop did not stabilize"
                );
            }
            if let Some(previous) = &previous_reference {
                assert_eq!(
                    &reference_signature_now, previous,
                    "reference loop did not stabilize"
                );
            }
            assert_eq!(actual_signature_now, reference_signature_now);
            previous_actual = Some(actual_signature_now);
            previous_reference = Some(reference_signature_now);
        }

        for &data_binding in &data_bindings {
            for &boolean_binding in &boolean_bindings {
                let actual_pairs = actual.pairs(data_binding, boolean_binding);
                let reference_pairs = reference
                    .relations
                    .get(&(data_binding, boolean_binding))
                    .expect("reference relation key remains present");
                for expected in [BoolFact::True, BoolFact::False, BoolFact::Unknown] {
                    let candidate = make_candidate(
                        ControlEdgeId::new(0),
                        boolean_binding,
                        expected,
                        data_binding,
                        &actual_pairs,
                        &definitions,
                    );
                    let expected_signature = reference_candidate(expected, reference_pairs);
                    assert_eq!(
                        candidate_signature(&candidate),
                        expected_signature,
                        "candidate mismatch for data {data_binding:?}, bool {boolean_binding:?}, expected {expected:?}"
                    );
                }
            }
        }
        }
    }

    /// Public contract: `Unknown` is the only self-opposite fact and known
    /// literals form an involution.  This guards edge polarity independently
    /// from the finite relation trace above.
    #[test]
    pub fn bool_fact_opposite_is_an_involution() {
        for fact in [BoolFact::True, BoolFact::False, BoolFact::Unknown] {
            assert_eq!(fact.opposite().opposite(), fact);
        }
        assert_eq!(BoolFact::True.opposite(), BoolFact::False);
        assert_eq!(BoolFact::False.opposite(), BoolFact::True);
        assert_eq!(BoolFact::Unknown.opposite(), BoolFact::Unknown);
    }
}
