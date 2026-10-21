//! Value-flow rules shared by the flow solver and the parse-time partial-flow
//! fixpoint. Each rule has one definition here; the flow and policy crates
//! call these functions.

use std::collections::HashSet;

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
