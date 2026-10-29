//! Value-flow rules shared by the flow solver and the parse-time partial-flow
//! fixpoint. Each rule has one definition here; the flow and policy crates
//! call these functions.

use crate::analyzer::semantic::{BindingOriginIndex, CallSiteId, ValueId};
use std::collections::{HashMap, HashSet};

use crate::analyzer::semantic::ControlEdgeId;

use crate::analyzer::semantic::ControlEdgeKind;

use crate::analyzer::semantic::GuardFact;

use crate::analyzer::semantic::GuardPredicate;

use crate::analyzer::semantic::IntegerComparison;

use crate::analyzer::semantic::MoveInvalidation;

use crate::analyzer::semantic::ProcedureHandle;

use crate::analyzer::semantic::ProcedureSemantics;

use crate::analyzer::semantic::ProgramPointId;

use crate::analyzer::semantic::TransferKind;

use crate::analyzer::semantic::ValueFlowEndpoint;

use crate::analyzer::semantic::ValueFlowRelationKind;

use crate::analyzer::semantic::ValueTransfer;

/// Whether a point-local rule replaces, rather than joins, the facts at its
/// target carrier.
///
/// A local assignment has always killed its target: the target names one
/// procedure-local slot and the assignment is the only writer that can reach
/// it. A `MemoryStore` joins by default, because a store through one name can
/// land on a location another name also reaches, and killing it would launder
/// an unanalyzed write into a clean answer.
///
/// #2444 adds the one case where a store does not join. The heap oracle issues
/// a `StrongUpdateCertificate` only when the store's location is exact, the
/// object it belongs to is a proven singleton, no other location can be
/// updated by the store, and the object does not escape. Under that proof the
/// store definitely overwrote what this carrier held, so keeping the old fact
/// would be a false positive rather than caution.
///
/// Aliasing is not laundered away by this. A second name the access-path
/// resolver proved is the same origin resolves to the same carrier, so the
/// kill is correct for it too; a name the resolver could not prove leaves more
/// than one candidate object, which is a weak update and no kill at all.
///
/// `distinct_endpoints` is whether the rule's source and target are different
/// carriers. The flags are the rule's `strong_update` and
/// `direct_cell_overwrite` verdicts.
pub fn kills_target(
    kind: ValueFlowRelationKind,
    distinct_endpoints: bool,
    strong_update: bool,
    direct_cell_overwrite: bool,
) -> bool {
    // Parameter and receiver relations copy between a boundary port and a
    // value carrier. A return writes the one pending return slot: cleanup can
    // replace it before the invocation exits. Mutually exclusive returns still
    // join through control flow, but a later return kills the earlier value.
    match kind {
        ValueFlowRelationKind::Assignment
        | ValueFlowRelationKind::Parameter
        | ValueFlowRelationKind::Receiver
        | ValueFlowRelationKind::NormalReturn => distinct_endpoints,
        ValueFlowRelationKind::MemoryStore => strong_update || direct_cell_overwrite,
        _ => false,
    }
}

/// Whether a by-value relation consumes the value held by its source.
///
/// Generate the destination fact before applying this kill: the target keeps
/// the moved value while later observations of the source binding do not.
pub fn invalidates_source(transfer: Option<ValueTransfer>) -> bool {
    matches!(
        transfer,
        Some(ValueTransfer {
            kind: TransferKind::Move {
                invalidation: MoveInvalidation::Invalidated,
            },
            ..
        })
    )
}

/// The points of one procedure that only a constant condition's excluded arm
/// reaches.
///
/// A `ConstantBoolean` guard names the successor its own value excludes. A
/// point the entry can reach *only* through such an edge cannot execute, so
/// nothing observed there is a fact about any run of the program.
///
/// The answer is the difference between forward reachability over the whole
/// control-flow graph and forward reachability over the graph minus every
/// excluded edge. Taking the difference rather than the second set alone is
/// deliberate: a point already unreachable for some unrelated reason is not
/// something a constant condition proved, and claiming it would put this
/// rule's name on someone else's answer.
pub fn procedure_infeasible_points(procedure: &ProcedureSemantics) -> Box<[ProgramPointId]> {
    let excluded = procedure
        .guard_facts()
        .iter()
        .filter_map(GuardFact::infeasible_edge)
        .collect::<HashSet<ControlEdgeId>>();
    if excluded.is_empty() {
        return Box::default();
    }
    let reachable = |skip: &HashSet<ControlEdgeId>| {
        let mut seen = vec![false; procedure.points().len()];
        let mut stack = vec![procedure.entry_point()];
        while let Some(point) = stack.pop() {
            if std::mem::replace(&mut seen[point.index()], true) {
                continue;
            }
            for (id, edge) in procedure.successor_edges(point) {
                if !skip.contains(&id) {
                    stack.push(edge.target_point);
                }
            }
        }
        seen
    };
    let with_every_edge = reachable(&HashSet::default());
    let without_excluded_edges = reachable(&excluded);
    with_every_edge
        .into_iter()
        .zip(without_excluded_edges)
        .enumerate()
        .filter(|(_, (before, after))| *before && !*after)
        .map(|(index, _)| {
            ProgramPointId::try_from_index(index).expect("a validated point index fits u32")
        })
        .collect()
}

/// One control edge whose traversal removes every fact on `carrier`.
///
/// The carrier is the subject of an automatic comparison guard: the predicate
/// establishes the barrier only on the arm named by the edge.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GuardEdgeKill {
    pub point: ProgramPointId,
    pub target_point: ProgramPointId,
    pub kind: ControlEdgeKind,
    pub carrier: ValueFlowEndpoint,
}

/// The automatic comparison barriers Rust publishes in its guard facts, as
/// edge kills. A predicate establishes the barrier only on one arm; the other
/// arm keeps the value exactly as ordinary value flow would.
pub fn guard_edge_kills(procedure: &ProcedureHandle) -> Vec<GuardEdgeKill> {
    let origins = crate::analyzer::semantic::BindingOriginIndex::new(procedure);
    let mut kills = Vec::new();
    for guard in procedure.semantics().guard_facts() {
        let edge_id = match guard.predicate {
            GuardPredicate::OrderedIntegerComparison { relation, .. } => match relation {
                IntegerComparison::LessThan | IntegerComparison::LessThanOrEqual => guard.true_edge,
                IntegerComparison::GreaterThan | IntegerComparison::GreaterThanOrEqual => {
                    guard.false_edge
                }
            },
            GuardPredicate::ConstantEquality { negated, .. } => {
                if negated {
                    guard.false_edge
                } else {
                    guard.true_edge
                }
            }
            _ => None,
        };
        let Some(edge_id) = edge_id else {
            continue;
        };
        let Some(subject) = guard.subject else {
            continue;
        };
        let binding = origins.unique_binding_origin(subject).unwrap_or(subject);
        let value = procedure
            .value_handle(binding)
            .expect("a guard subject names a live semantic value");
        let edge = procedure
            .semantics()
            .control_edge(edge_id)
            .expect("a guard arm resolves to a live control edge");
        kills.push(GuardEdgeKill {
            point: guard.point,
            target_point: edge.target_point,
            kind: edge.kind,
            carrier: ValueFlowEndpoint::for_value(value),
        });
    }
    kills
}

/// Accepting values of a policy-selected call-result guard. Policy requirements
/// and carrier referent stability are proved before a candidate enters this rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionalGuardResult {
    True,
    False,
    Nil,
    NonNil,
}

/// One call already matched by a policy selector, within this procedure only.
#[derive(Debug, Clone)]
pub struct ConditionalGuardSanitizer {
    pub call: CallSiteId,
    pub result_index: Option<u32>,
    pub accepts: ConditionalGuardResult,
    pub carrier: Option<ValueId>,
}

#[derive(Debug)]
pub struct ConditionalGuardKill {
    pub sanitizer: usize,
    pub kill: GuardEdgeKill,
}

#[derive(Debug)]
pub struct ConditionalGuardDecline {
    pub sanitizer: usize,
    pub point: ProgramPointId,
    pub reason: &'static str,
}

#[derive(Debug, Default)]
pub struct ConditionalGuardKills {
    pub kills: Vec<ConditionalGuardKill>,
    pub declines: Vec<ConditionalGuardDecline>,
}

/// Derive query-local kills without changing the policy-independent partial flows.
/// A stored guard result is nominated through value-dependence edges to explain why it
/// was declined; those edges never establish a sanitizer proof.
pub fn conditional_guard_edge_kills(
    procedure: &ProcedureHandle,
    sanitizers: &[ConditionalGuardSanitizer],
) -> ConditionalGuardKills {
    let semantics = procedure.semantics();
    let origins = BindingOriginIndex::new(procedure);
    let mut by_call = HashMap::<CallSiteId, Vec<usize>>::new();
    for (index, sanitizer) in sanitizers.iter().enumerate() {
        assert!(
            semantics.call_site(sanitizer.call).is_some(),
            "sanitizer call belongs to its procedure"
        );
        by_call.entry(sanitizer.call).or_default().push(index);
    }
    let mut answer = ConditionalGuardKills::default();
    for guard in semantics.guard_facts() {
        let Some(subject) = guard.subject else {
            continue;
        };
        let mut direct = semantics
            .call_phase_points(subject)
            .into_iter()
            .flatten()
            .flat_map(|point| {
                semantics
                    .call_result_site_ids(subject, *point)
                    .into_iter()
                    .flatten()
                    .copied()
            })
            .collect::<Vec<_>>();
        direct.sort_unstable();
        direct.dedup();
        if direct.is_empty() {
            let mut pending = vec![subject];
            let mut seen = HashSet::new();
            let mut nominated = HashSet::new();
            while let Some(value) = pending.pop() {
                if !seen.insert(value) {
                    continue;
                }
                for point in semantics.call_phase_points(value).into_iter().flatten() {
                    for call in semantics
                        .call_result_site_ids(value, *point)
                        .into_iter()
                        .flatten()
                    {
                        nominated.extend(by_call.get(call).into_iter().flatten().copied());
                    }
                }
                pending.extend(origins.value_predecessors(value));
            }
            let mut nominated = nominated.into_iter().collect::<Vec<_>>();
            nominated.sort_unstable();
            answer
                .declines
                .extend(
                    nominated
                        .into_iter()
                        .map(|sanitizer| ConditionalGuardDecline {
                            sanitizer,
                            point: guard.point,
                            reason: "stored call result requires a reaching-definition proof",
                        }),
                );
            continue;
        }
        for call_id in &direct {
            for &index in by_call.get(call_id).into_iter().flatten() {
                let sanitizer = &sanitizers[index];
                let call = semantics
                    .call_site(*call_id)
                    .expect("the frozen call-result index names a call");
                let attempt = || {
                    if direct.len() != 1 {
                        return Err("guard call result is ambiguous");
                    }
                    if !call.normal_results.is_empty() && sanitizer.result_index.is_none() {
                        return Err("multi-result sanitizer requires an explicit result index");
                    }
                    if call.normal_result(sanitizer.result_index.unwrap_or(0) as usize)
                        != Some(subject)
                    {
                        return Err("guard does not test the configured call result index");
                    }
                    let true_arm = match (guard.predicate, sanitizer.accepts) {
                        (GuardPredicate::Truthy { .. }, ConditionalGuardResult::True) => true,
                        (GuardPredicate::Truthy { .. }, ConditionalGuardResult::False) => false,
                        (
                            GuardPredicate::NullComparison { null_on_true },
                            ConditionalGuardResult::Nil,
                        ) => null_on_true,
                        (
                            GuardPredicate::NullComparison { null_on_true },
                            ConditionalGuardResult::NonNil,
                        ) => !null_on_true,
                        (
                            GuardPredicate::ConstantBoolean { value: true },
                            ConditionalGuardResult::True,
                        ) => true,
                        (
                            GuardPredicate::ConstantBoolean { value: false },
                            ConditionalGuardResult::False,
                        ) => false,
                        _ => return Err("guard predicate does not establish the accepting result"),
                    };
                    let edge_id = if true_arm {
                        guard.true_edge
                    } else {
                        guard.false_edge
                    }
                    .ok_or("accepting guard arm is absent")?;
                    let binding = origins
                        .unique_binding_origin(
                            sanitizer
                                .carrier
                                .ok_or("sanitized carrier operand is absent")?,
                        )
                        .ok_or("sanitized carrier has no unique binding origin")?;
                    let value = procedure
                        .value_handle(binding)
                        .expect("a binding origin names a live value");
                    let edge = semantics
                        .control_edge(edge_id)
                        .expect("a guard arm names a live edge");
                    Ok(GuardEdgeKill {
                        point: guard.point,
                        target_point: edge.target_point,
                        kind: edge.kind,
                        carrier: ValueFlowEndpoint::for_value(value),
                    })
                };
                match attempt() {
                    Ok(kill) => answer.kills.push(ConditionalGuardKill {
                        sanitizer: index,
                        kill,
                    }),
                    Err(reason) => answer.declines.push(ConditionalGuardDecline {
                        sanitizer: index,
                        point: guard.point,
                        reason,
                    }),
                }
            }
        }
    }
    answer
}
