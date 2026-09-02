//! Procedure-local finite scalar refinement over normalized semantic IR.
//!
//! The derivation deliberately consumes only semantic values, effects, guard
//! facts, and CFG edges. It never reparses source text. The finite lattice and
//! iterative worklist make loops stack safe and guarantee convergence.

#[cfg(test)]
use crate::analyzer::semantic::MoveInvalidation;
use crate::analyzer::semantic::{
    CallSiteId, ControlEdgeId, GuardPredicate, ProcedureHandle, ProcedureId, ProgramPointId,
    SemanticEffect, SemanticGapImpact, SemanticGapSubject, SemanticValueKind, TransferKind,
    TransferOperation, ValueFlowKind, ValueId, ValuePreservation, ValueTransfer,
};
use crate::hash::{HashMap, HashSet};
use std::collections::VecDeque;

/// One finite scalar statement at a program point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScalarFact {
    /// The point or value has no executable incoming path.
    Unreachable,
    Nil,
    NonNil,
    /// A complete join contains both nil and non-nil paths.
    MaybeNil,
    True,
    False,
    EitherBoolean,
    ExactInteger(u128),
    NonExactInteger,
    /// Required structured information is absent or an operation is outside
    /// the bounded scalar vocabulary.
    Unknown,
}

impl ScalarFact {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unreachable => "unreachable",
            Self::Nil => "nil",
            Self::NonNil => "non_nil",
            Self::MaybeNil => "maybe_nil",
            Self::True => "true",
            Self::False => "false",
            Self::EitherBoolean => "either_boolean",
            Self::ExactInteger(_) => "exact_integer",
            Self::NonExactInteger => "non_exact_integer",
            Self::Unknown => "unknown",
        }
    }

    pub fn join(self, other: Self) -> Self {
        use ScalarFact::{
            EitherBoolean, ExactInteger, False, MaybeNil, Nil, NonExactInteger, NonNil, True,
            Unknown, Unreachable,
        };
        match (self, other) {
            (Unreachable, value) | (value, Unreachable) => value,
            (left, right) if left == right => left,
            (Nil, NonNil | MaybeNil) | (NonNil, Nil | MaybeNil) | (MaybeNil, Nil | NonNil) => {
                MaybeNil
            }
            (True, False | EitherBoolean)
            | (False, True | EitherBoolean)
            | (EitherBoolean, True | False) => EitherBoolean,
            (ExactInteger(left), ExactInteger(right)) if left != right => NonExactInteger,
            (ExactInteger(_), NonExactInteger) | (NonExactInteger, ExactInteger(_)) => {
                NonExactInteger
            }
            _ => Unknown,
        }
    }
}

/// A complete procedure-local scalar solution. Point states describe values
/// after the ordered effects at that point have executed.
#[derive(Debug, Clone)]
pub struct ScalarStateDerivation {
    procedure: ProcedureId,
    states: Box<[Option<Box<[ScalarFact]>>]>,
}

/// One outcome-sensitive scalar mutation applied while traversing a CFG edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScalarEdgeWrite {
    pub edge: ControlEdgeId,
    pub target: ValueId,
    pub fact: ScalarFact,
}

/// Exact call-side mutation facts supplied by a model-aware consumer.
///
/// Calls absent from `modeled_address_calls` conservatively invalidate each
/// local whose address is passed directly. A present call has complete
/// mutation coverage; its outcome-specific changes are represented by
/// `edge_writes`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScalarCallEffects<'a> {
    pub modeled_address_calls: &'a [CallSiteId],
    pub edge_writes: &'a [ScalarEdgeWrite],
    /// CFG edges whose execution is disproved by an exact call model, such as
    /// the normal continuation of a terminating procedure.
    pub infeasible_edges: &'a [ControlEdgeId],
}

impl ScalarStateDerivation {
    pub fn derive(procedure: &ProcedureHandle) -> Self {
        Self::derive_with_call_effects(procedure, ScalarCallEffects::default())
    }

    pub fn derive_with_call_effects(
        procedure: &ProcedureHandle,
        call_effects: ScalarCallEffects<'_>,
    ) -> Self {
        let semantics = procedure.semantics();
        let value_count = semantics.values().len();
        let point_count = semantics.points().len();
        let mut states = vec![None::<Box<[ScalarFact]>>; point_count];
        let mut incoming = vec![None::<Box<[ScalarFact]>>; point_count];
        let mut entry = vec![ScalarFact::Unreachable; value_count];
        for value in semantics.values() {
            entry[value.id.index()] = match value.kind {
                SemanticValueKind::Parameter { .. } | SemanticValueKind::Receiver { .. } => {
                    ScalarFact::Unknown
                }
                _ => intrinsic_fact(semantics, value.id),
            };
        }
        incoming[semantics.entry_point().index()] = Some(entry.into_boxed_slice());

        let guards_by_edge = guards_by_edge(procedure);
        let mut pending = VecDeque::from([semantics.entry_point()]);
        let mut queued = HashSet::default();
        queued.insert(semantics.entry_point());
        let mut updates = 0_usize;
        while let Some(point) = pending.pop_front() {
            queued.remove(&point);
            let Some(mut state) = incoming[point.index()].clone() else {
                continue;
            };
            transfer_point(
                procedure,
                point,
                &mut state,
                call_effects.modeled_address_calls,
            );
            if states[point.index()].as_ref() == Some(&state) {
                continue;
            }
            states[point.index()] = Some(state.clone());

            for (edge_id, edge) in semantics.successor_edges(point) {
                if call_effects.infeasible_edges.contains(&edge_id)
                    || semantics
                        .guard_facts()
                        .iter()
                        .any(|guard| guard.infeasible_edge() == Some(edge_id))
                {
                    continue;
                }
                let mut successor = state.clone();
                if let Some(refinements) = guards_by_edge.get(&edge_id) {
                    for refinement in refinements {
                        apply_guard_refinement(procedure, point, refinement, &mut successor);
                    }
                }
                for write in call_effects
                    .edge_writes
                    .iter()
                    .filter(|write| write.edge == edge_id)
                {
                    successor[write.target.index()] = write.fact;
                }
                let changed = join_into(&mut incoming[edge.target_point.index()], &successor);
                if changed && queued.insert(edge.target_point) {
                    pending.push_back(edge.target_point);
                }
            }
            updates = updates.saturating_add(1);
            debug_assert!(
                updates
                    <= point_count
                        .saturating_mul(value_count.saturating_add(1))
                        .saturating_mul(16),
                "finite scalar worklist exceeded its lattice-derived update bound"
            );
        }

        Self {
            procedure: procedure.id(),
            states: states.into_boxed_slice(),
        }
    }

    pub const fn procedure(&self) -> ProcedureId {
        self.procedure
    }

    pub fn fact_at(&self, point: ProgramPointId, value: ValueId) -> ScalarFact {
        self.states
            .get(point.index())
            .and_then(Option::as_deref)
            .and_then(|state| state.get(value.index()))
            .copied()
            .unwrap_or(ScalarFact::Unreachable)
    }
}

#[derive(Debug, Clone, Copy)]
struct EdgeRefinement {
    subject: Option<ValueId>,
    predicate: GuardPredicate,
    truth: bool,
}

fn guards_by_edge(procedure: &ProcedureHandle) -> HashMap<ControlEdgeId, Vec<EdgeRefinement>> {
    let mut result = HashMap::<ControlEdgeId, Vec<EdgeRefinement>>::default();
    for guard in procedure.semantics().guard_facts() {
        if let Some(edge) = guard.true_edge {
            result.entry(edge).or_default().push(EdgeRefinement {
                subject: guard.subject,
                predicate: guard.predicate,
                truth: true,
            });
        }
        if let Some(edge) = guard.false_edge {
            result.entry(edge).or_default().push(EdgeRefinement {
                subject: guard.subject,
                predicate: guard.predicate,
                truth: false,
            });
        }
    }
    result
}

fn transfer_point(
    procedure: &ProcedureHandle,
    point: ProgramPointId,
    state: &mut [ScalarFact],
    modeled_address_calls: &[CallSiteId],
) {
    let semantics = procedure.semantics();
    let point = semantics
        .point(point)
        .expect("scalar worklist point belongs to its procedure");
    for event in &point.events {
        match event.effect {
            SemanticEffect::Assignment { target, value } => {
                state[target.index()] = fact_of(semantics, state, value);
            }
            SemanticEffect::ValueFlow {
                kind:
                    ValueFlowKind::Local
                    | ValueFlowKind::BackingStore { .. }
                    | ValueFlowKind::Parameter
                    | ValueFlowKind::Receiver
                    | ValueFlowKind::Return
                    | ValueFlowKind::IndexedReturn { .. },
                source,
                target,
            } => {
                state[target.index()] = fact_of(semantics, state, source);
            }
            SemanticEffect::ValueFlow {
                kind: ValueFlowKind::Transfer(transfer),
                source,
                target,
            } => {
                let (target_fact, invalidates_source) =
                    transferred_scalar_fact(fact_of(semantics, state, source), transfer);
                state[target.index()] = target_fact;
                if invalidates_source {
                    state[source.index()] = ScalarFact::Unknown;
                }
            }
            SemanticEffect::ValueFlow {
                kind: ValueFlowKind::LanguageDefined,
                target,
                ..
            }
            | SemanticEffect::MemoryLoad { result: target, .. }
            | SemanticEffect::AsyncResume {
                result: Some(target),
                ..
            } => state[target.index()] = ScalarFact::Unknown,
            SemanticEffect::Allocation { allocation } => {
                let allocation = semantics
                    .allocation(allocation)
                    .expect("validated allocation effect resolves");
                state[allocation.result.index()] = ScalarFact::NonNil;
            }
            SemanticEffect::CallableCreation { result, .. }
            | SemanticEffect::CallableReference { result, .. } => {
                state[result.index()] = ScalarFact::NonNil;
            }
            SemanticEffect::Invoke { call_site } => {
                if modeled_address_calls.contains(&call_site) {
                    continue;
                }
                let call = semantics
                    .call_site(call_site)
                    .expect("validated scalar call effect resolves");
                for argument in &call.arguments {
                    if semantics
                        .value(argument.value)
                        .is_some_and(|value| matches!(value.kind, SemanticValueKind::Address))
                        && let Some(binding) = unique_binding_origin(procedure, argument.value)
                    {
                        state[binding.index()] = ScalarFact::Unknown;
                    }
                }
            }
            SemanticEffect::Gap { gap } => {
                let gap = semantics
                    .gap(gap)
                    .expect("validated scalar gap effect resolves");
                if gap.impacts.contains(SemanticGapImpact::ValueFlow)
                    && let SemanticGapSubject::Value(value) = gap.subject
                {
                    state[value.index()] = ScalarFact::Unknown;
                }
            }
            SemanticEffect::Entry
            | SemanticEffect::NormalExit
            | SemanticEffect::ExceptionalExit
            | SemanticEffect::ValueUse { .. }
            | SemanticEffect::MemoryStore { .. }
            | SemanticEffect::CaptureBind { .. }
            | SemanticEffect::Synchronization { .. }
            | SemanticEffect::CallContinuation { .. }
            | SemanticEffect::ProcedureReturn { .. }
            | SemanticEffect::Throw { .. }
            | SemanticEffect::AsyncSuspend { .. }
            | SemanticEffect::AsyncResume { result: None, .. } => {}
        }
    }
}

fn transferred_scalar_fact(source: ScalarFact, transfer: ValueTransfer) -> (ScalarFact, bool) {
    if transfer.operation == TransferOperation::Unknown {
        return (
            ScalarFact::Unknown,
            matches!(transfer.kind, TransferKind::Move { .. }),
        );
    }
    let target = match transfer.kind {
        TransferKind::Copy
        | TransferKind::Move { .. }
        | TransferKind::Conversion {
            preservation: ValuePreservation::Identity | ValuePreservation::Preserving,
        } => source,
        TransferKind::AggregateCopy
        | TransferKind::Boxing
        | TransferKind::Unboxing
        | TransferKind::Conversion {
            preservation: ValuePreservation::Changing,
        } => ScalarFact::Unknown,
    };
    (target, matches!(transfer.kind, TransferKind::Move { .. }))
}

fn fact_of(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    state: &[ScalarFact],
    value: ValueId,
) -> ScalarFact {
    let intrinsic = intrinsic_fact(semantics, value);
    if intrinsic != ScalarFact::Unreachable {
        intrinsic
    } else {
        match state[value.index()] {
            // A reachable transfer that consumes a value without a supported
            // scalar origin has an unknown value. `Unreachable` is the
            // control-flow bottom; propagating it through an assignment would
            // make the assignment disappear and incorrectly preserve an older
            // binding fact across opaque call results.
            ScalarFact::Unreachable => ScalarFact::Unknown,
            fact => fact,
        }
    }
}

fn intrinsic_fact(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    value: ValueId,
) -> ScalarFact {
    let value = semantics
        .value(value)
        .expect("validated scalar value resolves in its procedure");
    match value.kind {
        SemanticValueKind::Null => ScalarFact::Nil,
        SemanticValueKind::Boolean(true) => ScalarFact::True,
        SemanticValueKind::Boolean(false) => ScalarFact::False,
        SemanticValueKind::UnsignedInteger(value) => ScalarFact::ExactInteger(value),
        SemanticValueKind::Address => ScalarFact::NonNil,
        _ if semantics
            .allocations()
            .iter()
            .any(|allocation| allocation.result == value.id) =>
        {
            ScalarFact::NonNil
        }
        _ => ScalarFact::Unreachable,
    }
}

fn join_into(slot: &mut Option<Box<[ScalarFact]>>, incoming: &[ScalarFact]) -> bool {
    let Some(current) = slot else {
        *slot = Some(incoming.to_vec().into_boxed_slice());
        return true;
    };
    assert_eq!(current.len(), incoming.len());
    let mut changed = false;
    for (current, incoming) in current.iter_mut().zip(incoming) {
        let joined = current.join(*incoming);
        changed |= joined != *current;
        *current = joined;
    }
    changed
}

fn apply_guard_refinement(
    procedure: &ProcedureHandle,
    _point: ProgramPointId,
    refinement: &EdgeRefinement,
    state: &mut [ScalarFact],
) {
    let Some(subject) = refinement.subject else {
        return;
    };
    let semantics = procedure.semantics();
    let refined = match refinement.predicate {
        GuardPredicate::NullComparison { null_on_true } => {
            if refinement.truth == null_on_true {
                ScalarFact::Nil
            } else {
                ScalarFact::NonNil
            }
        }
        GuardPredicate::ConstantEquality { negated, constant } => {
            let equality_arm = refinement.truth != negated;
            match intrinsic_fact(semantics, constant) {
                ScalarFact::True if equality_arm => ScalarFact::True,
                ScalarFact::True => ScalarFact::False,
                ScalarFact::False if equality_arm => ScalarFact::False,
                ScalarFact::False => ScalarFact::True,
                ScalarFact::ExactInteger(value) if equality_arm => ScalarFact::ExactInteger(value),
                ScalarFact::ExactInteger(_) => ScalarFact::NonExactInteger,
                _ => return,
            }
        }
        GuardPredicate::ConstantBoolean { .. } | GuardPredicate::Opaque { .. } => return,
    };
    state[subject.index()] = refined;
    if let Some(binding) = unique_binding_origin(procedure, subject) {
        state[binding.index()] = refined;
    }
}

pub fn unique_binding_origin(procedure: &ProcedureHandle, subject: ValueId) -> Option<ValueId> {
    let semantics = procedure.semantics();
    let mut predecessors = HashMap::<ValueId, Vec<ValueId>>::default();
    for point in semantics.points() {
        for event in &point.events {
            match event.effect {
                SemanticEffect::Assignment { target, value }
                    if !semantics.value(target).is_some_and(|value| {
                        matches!(
                            value.kind,
                            SemanticValueKind::Local
                                | SemanticValueKind::Parameter { .. }
                                | SemanticValueKind::Receiver { .. }
                        )
                    }) =>
                {
                    predecessors.entry(target).or_default().push(value);
                }
                SemanticEffect::ValueFlow { source, target, .. } => {
                    predecessors.entry(target).or_default().push(source);
                }
                _ => {}
            }
        }
    }
    let mut pending = vec![subject];
    let mut visited = HashSet::default();
    let mut bindings = HashSet::default();
    while let Some(value) = pending.pop() {
        if !visited.insert(value) {
            continue;
        }
        match semantics.value(value)?.kind {
            SemanticValueKind::Local
            | SemanticValueKind::Parameter { .. }
            | SemanticValueKind::Receiver { .. } => {
                bindings.insert(value);
            }
            _ => pending.extend(predecessors.get(&value).into_iter().flatten().copied()),
        }
    }
    (bindings.len() == 1).then(|| *bindings.iter().next().expect("one binding"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::{
        MemoryLocationKind, SemanticBudget, SemanticRequest, SemanticWork,
    };
    use crate::analyzer::{AnalyzerConfig, Language};
    use crate::cancellation::CancellationToken;

    use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};

    struct Fixture {
        _project: BuiltInlineTestProject,
        procedure: ProcedureHandle,
    }

    impl Fixture {
        fn go(source: &str, name: &str) -> Self {
            let project = InlineTestProject::with_language(Language::Go)
                .file("main.go", source)
                .build();
            let file = project.file("main.go");
            let workspace = project.workspace_analyzer(AnalyzerConfig::default());
            let cancellation = CancellationToken::default();
            let mut budget =
                SemanticBudget::new(SemanticWork::default_limits()).expect("valid test budget");
            let outcome = workspace
                .materialize_program_semantics(
                    &file,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("Go semantics materialize");
            let artifact = outcome
                .available_value()
                .cloned()
                .unwrap_or_else(|| panic!("Go semantics are available: {outcome:#?}"));
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
                .map(|procedure| procedure.id())
                .and_then(|id| artifact.procedure_handle(id))
                .unwrap_or_else(|| panic!("missing procedure {name}"));
            Self {
                _project: project,
                procedure,
            }
        }

        fn field_base_facts(&self) -> Vec<ScalarFact> {
            let derivation = ScalarStateDerivation::derive(&self.procedure);
            let semantics = self.procedure.semantics();
            semantics
                .points()
                .iter()
                .flat_map(|point| {
                    point.events.iter().filter_map(|event| match event.effect {
                        SemanticEffect::MemoryLoad { location, .. } => {
                            let MemoryLocationKind::Field { base, .. } =
                                &semantics.memory_location(location)?.kind
                            else {
                                return None;
                            };
                            Some(derivation.fact_at(point.id, *base))
                        }
                        _ => None,
                    })
                })
                .collect()
        }
    }

    #[test]
    fn pointer_zero_and_address_join_to_maybe_nil() {
        let fixture = Fixture::go(
            r#"package sample
type item struct { field int }
func run(flag bool) int {
    var value *item
    if flag { value = &item{} }
    return value.field
}
"#,
            "run",
        );
        assert_eq!(fixture.field_base_facts(), vec![ScalarFact::MaybeNil]);
    }

    #[test]
    fn preserving_scalar_transfers_keep_the_source_fact() {
        let transfers = [
            ValueTransfer {
                kind: TransferKind::Copy,
                operation: TransferOperation::None,
            },
            ValueTransfer {
                kind: TransferKind::Move {
                    invalidation: MoveInvalidation::Invalidated,
                },
                operation: TransferOperation::CallSite(
                    CallSiteId::try_from_index(0).expect("zero is a valid call-site index"),
                ),
            },
            ValueTransfer {
                kind: TransferKind::Conversion {
                    preservation: ValuePreservation::Identity,
                },
                operation: TransferOperation::None,
            },
            ValueTransfer {
                kind: TransferKind::Conversion {
                    preservation: ValuePreservation::Preserving,
                },
                operation: TransferOperation::None,
            },
        ];
        for transfer in transfers {
            assert_eq!(
                transferred_scalar_fact(ScalarFact::ExactInteger(7), transfer),
                (
                    ScalarFact::ExactInteger(7),
                    matches!(transfer.kind, TransferKind::Move { .. })
                ),
                "{transfer:?}"
            );
        }
    }

    #[test]
    fn uncertain_and_non_scalar_preserving_transfers_stay_conservative() {
        let transfers = [
            ValueTransfer {
                kind: TransferKind::Copy,
                operation: TransferOperation::Unknown,
            },
            ValueTransfer {
                kind: TransferKind::AggregateCopy,
                operation: TransferOperation::None,
            },
            ValueTransfer {
                kind: TransferKind::Boxing,
                operation: TransferOperation::None,
            },
            ValueTransfer {
                kind: TransferKind::Unboxing,
                operation: TransferOperation::None,
            },
            ValueTransfer {
                kind: TransferKind::Conversion {
                    preservation: ValuePreservation::Changing,
                },
                operation: TransferOperation::None,
            },
        ];
        for transfer in transfers {
            assert_eq!(
                transferred_scalar_fact(ScalarFact::ExactInteger(7), transfer),
                (ScalarFact::Unknown, false),
                "{transfer:?}"
            );
        }
    }

    #[test]
    fn both_move_contracts_invalidate_the_source_scalar_fact() {
        for invalidation in [MoveInvalidation::Invalidated, MoveInvalidation::Unknown] {
            let transfer = ValueTransfer {
                kind: TransferKind::Move { invalidation },
                operation: TransferOperation::None,
            };
            assert_eq!(
                transferred_scalar_fact(ScalarFact::NonNil, transfer),
                (ScalarFact::NonNil, true),
                "{transfer:?}"
            );
        }
    }

    #[test]
    fn null_guard_refines_the_surviving_arm() {
        let fixture = Fixture::go(
            r#"package sample
type item struct { field int }
func run(value *item) int {
    if value == nil { return 0 }
    return value.field
}
"#,
            "run",
        );
        assert_eq!(
            fixture.field_base_facts(),
            vec![ScalarFact::NonNil],
            "{:#?}",
            fixture.procedure.semantics()
        );
    }

    #[test]
    fn exact_local_integer_reaches_an_index_operation() {
        let fixture = Fixture::go(
            r#"package sample
func run(values []int) int {
    start := 0x1
    return values[start]
}
"#,
            "run",
        );
        let derivation = ScalarStateDerivation::derive(&fixture.procedure);
        let semantics = fixture.procedure.semantics();
        let facts = semantics
            .points()
            .iter()
            .flat_map(|point| {
                point.events.iter().filter_map(|event| match event.effect {
                    SemanticEffect::MemoryLoad { location, .. } => {
                        let MemoryLocationKind::Index {
                            index: Some(index), ..
                        } = semantics.memory_location(location)?.kind
                        else {
                            return None;
                        };
                        Some(derivation.fact_at(point.id, index))
                    }
                    _ => None,
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(facts, vec![ScalarFact::ExactInteger(1)], "{semantics:#?}");
    }

    #[test]
    fn opaque_call_result_kills_an_earlier_nil_binding() {
        let fixture = Fixture::go(
            r#"package sample
type item struct { field int }
func acquire() *item { return nil }
func run() int {
    var value *item
    value = acquire()
    return value.field
}
"#,
            "run",
        );
        assert_eq!(fixture.field_base_facts(), vec![ScalarFact::Unknown]);
    }

    #[test]
    fn mutable_closure_capture_kills_an_earlier_nil_binding() {
        let fixture = Fixture::go(
            r#"package sample
type item struct { field int }
func acquire() *item { return nil }
func run() int {
    var value *item
    func() { value = acquire() }()
    return value.field
}
"#,
            "run",
        );
        assert_eq!(fixture.field_base_facts(), vec![ScalarFact::Unknown]);
    }

    #[test]
    fn modeled_terminating_call_removes_its_normal_scalar_path() {
        let fixture = Fixture::go(
            r#"package sample
type item struct { field int }
func stop() {}
func run(value *item) int {
    if value == nil { stop() }
    return value.field
}
"#,
            "run",
        );
        let semantics = fixture.procedure.semantics();
        let call = semantics
            .call_sites()
            .iter()
            .find(|call| call.normal_continuation.target().is_some())
            .expect("run contains the stop invocation");
        let normal = call
            .normal_continuation
            .target()
            .expect("stop has a raw normal continuation");
        let infeasible = semantics
            .successor_edges(call.point)
            .filter_map(|(edge, control)| (control.target_point == normal).then_some(edge))
            .collect::<Vec<_>>();
        let [infeasible] = infeasible.as_slice() else {
            panic!("one raw edge reaches the call's normal continuation: {semantics:#?}");
        };
        let derivation = ScalarStateDerivation::derive_with_call_effects(
            &fixture.procedure,
            ScalarCallEffects {
                modeled_address_calls: &[],
                edge_writes: &[],
                infeasible_edges: &[*infeasible],
            },
        );
        let facts = semantics
            .points()
            .iter()
            .flat_map(|point| {
                point.events.iter().filter_map(|event| match event.effect {
                    SemanticEffect::MemoryLoad { location, .. } => {
                        let MemoryLocationKind::Field { base, .. } =
                            &semantics.memory_location(location)?.kind
                        else {
                            return None;
                        };
                        Some(derivation.fact_at(point.id, *base))
                    }
                    _ => None,
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(facts, vec![ScalarFact::NonNil], "{semantics:#?}");
    }

    #[test]
    fn address_arguments_invalidate_unmodeled_bindings_but_complete_models_preserve_them() {
        let fixture = Fixture::go(
            r#"package sample
type item struct { field int }
func mutate(value **item) {}
func run() int {
    value := &item{}
    mutate(&value)
    return value.field
}
"#,
            "run",
        );
        assert_eq!(fixture.field_base_facts(), vec![ScalarFact::Unknown]);

        let call = fixture
            .procedure
            .semantics()
            .call_sites()
            .iter()
            .find(|call| !call.arguments.is_empty())
            .expect("run contains the mutate invocation");
        let modeled = ScalarStateDerivation::derive_with_call_effects(
            &fixture.procedure,
            ScalarCallEffects {
                modeled_address_calls: &[call.id],
                edge_writes: &[],
                infeasible_edges: &[],
            },
        );
        let semantics = fixture.procedure.semantics();
        let facts = semantics
            .points()
            .iter()
            .flat_map(|point| {
                point.events.iter().filter_map(|event| match event.effect {
                    SemanticEffect::MemoryLoad { location, .. } => {
                        let MemoryLocationKind::Field { base, .. } =
                            &semantics.memory_location(location)?.kind
                        else {
                            return None;
                        };
                        Some(modeled.fact_at(point.id, *base))
                    }
                    _ => None,
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(facts, vec![ScalarFact::NonNil], "{semantics:#?}");
    }
}
