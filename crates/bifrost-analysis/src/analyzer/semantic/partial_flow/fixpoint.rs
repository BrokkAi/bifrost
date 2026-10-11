//! The intra-procedural fixpoint behind partial flows (spec M2.1, rules 1 to
//! 7). A fact is a seed port, a carrier, an uncertainty bit and the calls its
//! paths crossed. Every call site is a boundary: facts flow through the
//! procedure's own relations and control edges only.

use std::collections::{BTreeMap, HashMap, HashSet};

use super::FileLocalProjectionHost;
use super::ports::{
    HeapSelector, PartialFlowPort, PortId, PortTable, call_port_values, heap_selectors,
    port_of_endpoint,
};
use super::rules::{
    guard_edge_kills, invalidates_source, kills_target, procedure_infeasible_points,
};
use crate::CancellationToken;
use crate::analyzer::semantic::icfg::is_call_scaffolding;
use crate::analyzer::semantic::workspace_oracle::{
    gap_impacts_value_flow, project_procedure_relations,
};
use crate::analyzer::semantic::{
    AbstractLocation, AccessPathTail, CallSiteId, CandidateCoverage, CaptureId,
    ControlContinuation, ControlEdgeKind, MemoryLocationKind, OracleCallContext, OracleLimits,
    ProcedureHandle, ProcedurePortHandle, ProcedurePortKind, ProcedureSemantics, ProgramPointId,
    SemanticArtifact, SemanticBudget, SemanticCallSite, SemanticEffect, SemanticGapId,
    SemanticOutcome, SemanticRequest, SemanticValueKind, ValueFlowEndpoint, ValueFlowRelationKind,
    ValueFlowSnapshot,
};
use crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree;
use std::sync::Arc;

/// One flow inside a procedure: a value entering at `from` can be at `to`
/// without passing through a call. `uncertain` is set when any path that
/// carries it is not proven and complete.
///
/// `crossed` holds, for each distinct class of the flow's paths, the call
/// sites the value went past: it left the call's point for the call's own
/// continuation, each set sorted. No set is a superset of another. The value
/// does not pass through those calls, but the ICFG engine reaches a call's
/// continuation only over the call's continuation edges, whose proof and
/// completeness come from the call's dispatch; a composition derives the
/// same quality from these sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialFlow {
    pub from: PortId,
    pub to: PortId,
    pub uncertain: bool,
    pub crossed: CrossedCalls,
}

/// The crossed-call sets of one flow: one sorted set of call sites per
/// distinct path class, none a superset of another, sorted. A flow whose
/// paths cross no call has one empty set.
pub type CrossedCalls = Box<[Box<[CallSiteId]>]>;

/// The most path classes one fact keeps. When a fact's distinct path classes
/// exceed it, the fact keeps one class from then on, the union of every
/// class's calls. That class is no better than any real path, so a quality
/// computed from it can only be lower than the ICFG engine's, never higher.
/// Without a bound, a procedure with several branches in sequence, each arm
/// holding its own call, would keep exponentially many classes.
pub const MAX_CROSSED_CLASSES: usize = 16;

/// The union of two flows' crossed-call sets, reduced to the sets that no
/// other set is a subset of, for one flow that two derivations reach. More
/// than [`MAX_CROSSED_CLASSES`] sets become their union.
pub fn join_crossed(left: &[Box<[CallSiteId]>], right: &[Box<[CallSiteId]>]) -> CrossedCalls {
    let mut sets = left.iter().chain(right).cloned().collect::<Vec<_>>();
    sets.sort();
    sets.dedup();
    let subset = |small: &[CallSiteId], large: &[CallSiteId]| {
        small.iter().all(|call| large.binary_search(call).is_ok())
    };
    let minimal = sets
        .iter()
        .filter(|set| {
            !sets
                .iter()
                .any(|other| other.len() < set.len() && subset(other, set))
        })
        .cloned()
        .collect::<Vec<_>>();
    if minimal.len() <= MAX_CROSSED_CLASSES {
        return minimal.into_boxed_slice();
    }
    let mut union = minimal.into_iter().flatten().collect::<Vec<_>>();
    union.sort();
    union.dedup();
    vec![union.into_boxed_slice()].into_boxed_slice()
}

/// How a procedure's partial flows were obtained. The declaration order is the
/// head's `outcome` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PartialFlowOutcome {
    /// The candidate set was not truncated by a limit. The procedure may still
    /// be open; see the head's `open` column.
    Complete,
    /// A limit truncated the relation projection's candidate set.
    Truncated,
    /// The projection ran out of its budget; no flows are recorded.
    ExceededBudget,
    /// The projection failed; no flows are recorded.
    Error,
}

/// Partial flows of one procedure. `ports` is indexed by [`PortId`] and holds
/// every port that is an input seed, a call port, or an observed output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcedurePartialFlows {
    pub outcome: PartialFlowOutcome,
    /// The head's text: the error message of an [`PartialFlowOutcome::Error`]
    /// head, or the label of a projection outcome that was not complete (for
    /// example `unknown`) whose snapshot still yields flows.
    pub detail: Option<String>,
    pub ports: Vec<PartialFlowPort>,
    pub flows: Vec<PartialFlow>,
    /// Some value-flow gap that is not discharged remains in the procedure.
    pub open: bool,
    /// Every relation of the procedure's value-flow snapshot is proven
    /// complete. The ICFG engine treats a procedure with an unproven
    /// relation as an incomplete snapshot before it looks at any gap, so
    /// the composition checks this fact first. `false` when the relations
    /// were not projected.
    pub relations_complete: bool,
    pub discharged_gaps: Vec<SemanticGapId>,
}

impl ProcedurePartialFlows {
    /// The head of a procedure whose relations were not projected. Its
    /// openness is unknown, so it is open.
    pub(crate) fn without_flows(outcome: PartialFlowOutcome) -> Self {
        assert!(
            outcome != PartialFlowOutcome::Complete,
            "a complete procedure has flows to record"
        );
        Self {
            outcome,
            detail: None,
            ports: Vec::new(),
            flows: Vec::new(),
            open: true,
            relations_complete: false,
            discharged_gaps: Vec::new(),
        }
    }

    /// The head of a procedure whose projection failed with `message`.
    pub(crate) fn failed(message: String) -> Self {
        Self {
            detail: Some(message),
            ..Self::without_flows(PartialFlowOutcome::Error)
        }
    }
}

/// Live facts at one program point, keyed by `(carrier, seed)`. The map is
/// ordered by carrier so that the facts on one carrier form a range.
type Facts = BTreeMap<(u32, u32), Fact>;

/// The derivation of one fact: the seed's marker and each relation application
/// that produced it, in order. Empty-by-`None` unless witnesses are recorded.
type Witness = Option<Arc<[WitnessStep]>>;

/// One fact's uncertainty, crossed calls and, when witnesses are recorded,
/// one derivation. When two derivations of one fact differ in uncertainty,
/// the uncertain one is kept, because it is the one the result must report.
/// The crossed calls of both are kept.
#[derive(Debug, Clone)]
struct Fact {
    uncertain: bool,
    crossed: Crossed,
    witness: Witness,
}

/// The crossed calls of one fact: for each distinct class of its paths, the
/// call sites the fact went past (from the call's point to its own
/// continuation), as a bit set over the procedure's call-site indexes. No
/// set is a superset of another, because a path class that crossed more
/// calls is never better than one that crossed fewer, and the sets are
/// sorted, so equal antichains compare equal.
///
/// `widened` marks the single union class a fact keeps once its classes
/// exceeded [`MAX_CROSSED_CLASSES`]. A widened fact stays widened and its one
/// set only grows, so the fixpoint still terminates.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Crossed {
    sets: Arc<[Box<[u64]>]>,
    widened: bool,
}

fn is_subset(small: &[u64], large: &[u64]) -> bool {
    small
        .iter()
        .zip(large)
        .all(|(small, large)| small & !large == 0)
}

fn union_of<'a>(sets: impl Iterator<Item = &'a Box<[u64]>>, words: usize) -> Box<[u64]> {
    let mut union = vec![0u64; words].into_boxed_slice();
    for set in sets {
        for (word, bits) in union.iter_mut().zip(set.iter()) {
            *word |= bits;
        }
    }
    union
}

impl Crossed {
    /// The crossed calls of a seed: one path class that crossed nothing.
    fn start(words: usize) -> Self {
        Self {
            sets: Arc::from(vec![vec![0u64; words].into_boxed_slice()]),
            widened: false,
        }
    }

    fn widen(sets: &[Box<[u64]>], words: usize) -> Self {
        Self {
            sets: Arc::from(vec![union_of(sets.iter(), words)]),
            widened: true,
        }
    }

    /// The minimal sets of `sets`, sorted, widened past the bound.
    fn reduce(mut sets: Vec<Box<[u64]>>, words: usize) -> Self {
        sets.sort();
        sets.dedup();
        let minimal = sets
            .iter()
            .filter(|set| {
                !sets
                    .iter()
                    .any(|other| other != *set && is_subset(other, set))
            })
            .cloned()
            .collect::<Vec<_>>();
        if minimal.len() > MAX_CROSSED_CLASSES {
            return Self::widen(&minimal, words);
        }
        Self {
            sets: Arc::from(minimal),
            widened: false,
        }
    }

    fn words(&self) -> usize {
        self.sets[0].len()
    }

    /// The crossed calls of a fact that both `self` and `other` derive, or
    /// `None` when that is `self`.
    fn join(&self, other: &Self) -> Option<Self> {
        if self == other {
            return None;
        }
        let words = self.words();
        if self.widened || other.widened {
            let joined = Self {
                sets: Arc::from(vec![union_of(
                    self.sets.iter().chain(other.sets.iter()),
                    words,
                )]),
                widened: true,
            };
            return (joined != *self).then_some(joined);
        }
        // Every class of `other` is already no better than one of `self`.
        if other
            .sets
            .iter()
            .all(|set| self.sets.iter().any(|kept| is_subset(kept, set)))
        {
            return None;
        }
        let joined = Self::reduce(
            self.sets.iter().chain(other.sets.iter()).cloned().collect(),
            words,
        );
        (joined != *self).then_some(joined)
    }

    /// The crossed calls after every path class crossed the call with index
    /// `call`.
    fn cross(&self, call: usize) -> Self {
        let (word, bit) = (call / 64, 1u64 << (call % 64));
        if self.sets.iter().all(|set| set[word] & bit != 0) {
            return self.clone();
        }
        let crossed = self
            .sets
            .iter()
            .map(|set| {
                let mut set = set.clone();
                set[word] |= bit;
                set
            })
            .collect::<Vec<_>>();
        if self.widened {
            return Self {
                sets: Arc::from(crossed),
                widened: true,
            };
        }
        Self::reduce(crossed, self.words())
    }

    /// The sets as sorted call sites, in sorted order.
    fn calls(&self) -> CrossedCalls {
        let mut sets = self
            .sets
            .iter()
            .map(|set| {
                let mut calls = Vec::new();
                for (word, bits) in set.iter().enumerate() {
                    let mut bits = *bits;
                    while bits != 0 {
                        let index = word * 64 + bits.trailing_zeros() as usize;
                        calls.push(
                            CallSiteId::try_from_index(index).expect("a call-site index fits u32"),
                        );
                        bits &= bits - 1;
                    }
                }
                calls.into_boxed_slice()
            })
            .collect::<Vec<_>>();
        sets.sort();
        sets.into_boxed_slice()
    }
}

/// Event ordinal of a witness step that marks a seed: the seed moved no event.
pub const SEED_EVENT: u32 = u32::MAX;

/// One step of a witness: a program point and the ordinal of the event at that
/// point that moved the value, or [`SEED_EVENT`] for the seed itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WitnessStep {
    pub point: ProgramPointId,
    pub event: u32,
}

/// When an extra seed or observation applies, relative to the events of its
/// point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExtraPhase {
    /// Before the point's relations: the in-state of the point.
    BeforeEffects,
    /// After the point's relations and continuation seeds: its out-state.
    AfterEffects,
}

/// A carrier that a value is in at one point and phase. An extended run
/// observes it as live from that point on.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExtraSeed {
    pub point: ProgramPointId,
    pub phase: ExtraPhase,
    pub carrier: ValueFlowEndpoint,
}

/// A carrier whose facts an extended run records as reaching the observation
/// at one point and phase.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExtraObservation {
    pub point: ProgramPointId,
    pub phase: ExtraPhase,
    pub carrier: ValueFlowEndpoint,
}

/// Where a fact of an extended run arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExtraTarget {
    /// The observation with this index in the run's observations.
    Observation(usize),
    /// An output port of the procedure, by its id in
    /// [`ProcedurePartialFlows::ports`].
    Port(PortId),
}

/// One fact of an extended run that started at an extra seed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraFlow {
    /// Index into the run's extra seeds.
    pub seed: usize,
    pub target: ExtraTarget,
    pub uncertain: bool,
    /// The calls the fact's paths crossed, as [`PartialFlow::crossed`].
    pub crossed: CrossedCalls,
    /// The derivation of the fact, present exactly when witnesses were
    /// recorded.
    pub witness: Option<Box<[WitnessStep]>>,
}

/// The result of one extended run. `partial` is the procedure's own partial
/// flows, as [`compute_partial_flows`] reports them. `flows` holds the facts
/// that started at the extra seeds, in seed order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedPartialFlows {
    pub partial: ProcedurePartialFlows,
    pub flows: Vec<ExtraFlow>,
}

/// Dense carrier index over the endpoints the fixpoint can see.
#[derive(Default)]
struct Carriers {
    ids: HashMap<ValueFlowEndpoint, u32>,
    endpoints: Vec<ValueFlowEndpoint>,
}

impl Carriers {
    /// Intern a carrier. A formal binding has one carrier, its port, so a
    /// `Value` naming a parameter or receiver is interned as that port. Capture
    /// relations name the captured parameter by value, where other relations
    /// and the entry seeds name it by port.
    fn intern(&mut self, endpoint: &ValueFlowEndpoint) -> u32 {
        let canonical = match endpoint {
            ValueFlowEndpoint::Value(value) => ValueFlowEndpoint::for_value(value.clone()),
            _ => endpoint.clone(),
        };
        if let Some(&id) = self.ids.get(&canonical) {
            return id;
        }
        let id = u32::try_from(self.endpoints.len()).expect("a procedure's carrier count fits u32");
        self.endpoints.push(canonical.clone());
        self.ids.insert(canonical, id);
        id
    }
}

/// One relation of a point, reduced to what the transfer applies.
#[derive(Debug, Clone, Copy)]
struct RelationStep {
    event_index: u32,
    source: u32,
    target: u32,
    kill_target: bool,
    invalidate_source: bool,
    uncertain: bool,
    /// The relation carries a captured source into a child's capture slot.
    captures: bool,
}

/// The boundary facts of one call site.
#[derive(Default)]
struct CallPlan {
    /// Receiver and argument carriers, observed at the invocation.
    observed: Vec<(PortId, u32)>,
    /// Result and thrown carriers, which the call redefines.
    defined: Vec<u32>,
}

struct Fixpoint<'a> {
    semantics: &'a ProcedureSemantics,
    /// The crossed calls of a seed: one path class that crossed nothing.
    start: Crossed,
    carriers: Carriers,
    ports: PortTable,
    witnesses: bool,
    /// The port of each seed key below `builtin_seeds.len()`: the procedure's
    /// own input seeds. Seed keys from `builtin_seeds.len()` on are extra
    /// seeds, numbered from zero.
    builtin_seeds: Vec<PortId>,
    /// Facts reaching each target, by seed key.
    flows: BTreeMap<(u32, ExtraTarget), Fact>,
    steps: Vec<Vec<RelationStep>>,
    /// The output port of each capture binding of the procedure.
    capture_outs: HashMap<CaptureId, PortId>,
    calls: HashMap<CallSiteId, CallPlan>,
    /// Seeds joined after a point's own events: `(seed key, carrier)`. A call
    /// result or thrown port seeds at its continuation, and an extra seed with
    /// the after-effects phase seeds at its point.
    continuation_seeds: Vec<Vec<(u32, u32)>>,
    /// Observations taken before a point's events: `(observation, carrier)`.
    before_observations: Vec<Vec<(usize, u32)>>,
    /// Observations taken after a point's events and continuation seeds.
    after_observations: Vec<Vec<(usize, u32)>>,
    edge_kills: HashMap<(ProgramPointId, ProgramPointId, ControlEdgeKind), Vec<u32>>,
    infeasible: Vec<bool>,
    in_states: Vec<Facts>,
    queued: Vec<bool>,
    stack: Vec<usize>,
}

/// Join one fact into a map. A fact already present keeps its derivation
/// unless the incoming fact is uncertain and the present one is not, so the
/// derivation of an uncertain fact is always an uncertain path. The crossed
/// calls of both are joined. `witness` is called only when the derivation
/// changes.
fn join<K: Ord>(
    facts: &mut BTreeMap<K, Fact>,
    key: K,
    uncertain: bool,
    crossed: &Crossed,
    witness: impl FnOnce() -> Witness,
) -> bool {
    match facts.entry(key) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(Fact {
                uncertain,
                crossed: crossed.clone(),
                witness: witness(),
            });
            true
        }
        std::collections::btree_map::Entry::Occupied(mut entry) => {
            let fact = entry.get_mut();
            let mut changed = false;
            if let Some(joined) = fact.crossed.join(crossed) {
                fact.crossed = joined;
                changed = true;
            }
            if uncertain && !fact.uncertain {
                fact.uncertain = true;
                fact.witness = witness();
                changed = true;
            }
            changed
        }
    }
}

fn carrier_range(carrier: u32) -> std::ops::Range<(u32, u32)> {
    (carrier, 0)..(carrier + 1, 0)
}

fn remove_carrier(facts: &mut Facts, carrier: u32) {
    let keys = facts
        .range(carrier_range(carrier))
        .map(|(&key, _)| key)
        .collect::<Vec<_>>();
    for key in keys {
        facts.remove(&key);
    }
}

impl Fixpoint<'_> {
    /// The witness of a fact that `base` derived and that a relation at
    /// `point` with event `event` carried one step further.
    fn extend(&self, base: &Witness, point: ProgramPointId, event: u32) -> Witness {
        if !self.witnesses {
            return None;
        }
        let mut steps = base
            .as_deref()
            .map_or_else(Vec::new, <[WitnessStep]>::to_vec);
        steps.push(WitnessStep { point, event });
        Some(Arc::from(steps))
    }

    /// The witness of a fact that a seed at `point` introduced.
    fn seed_witness(&self, point: ProgramPointId) -> Witness {
        self.witnesses.then(|| {
            Arc::from(vec![WitnessStep {
                point,
                event: SEED_EVENT,
            }])
        })
    }

    fn record(&mut self, seed: u32, target: ExtraTarget, fact: Fact) {
        let uncertain = fact.uncertain;
        join(
            &mut self.flows,
            (seed, target),
            uncertain,
            &fact.crossed,
            || fact.witness,
        );
    }

    /// Record every fact on `carrier` as reaching `target`.
    fn observe(&mut self, live: &Facts, carrier: u32, target: ExtraTarget) {
        let observed = live
            .range(carrier_range(carrier))
            .map(|(&(_, seed), fact)| (seed, fact.clone()))
            .collect::<Vec<_>>();
        for (seed, fact) in observed {
            self.record(seed, target, fact);
        }
    }

    /// Record facts that reach an output port at an exit point. Return ports
    /// are outputs at both exits; a heap location is an output at the normal
    /// exit only.
    fn observe_exit(&mut self, live: &Facts, normal_exit: bool) {
        let mut current = None;
        let mut output = None;
        let observed = live
            .iter()
            .map(|(&(carrier, seed), fact)| (carrier, seed, fact.clone()))
            .collect::<Vec<_>>();
        for (carrier, seed, fact) in observed {
            if current != Some(carrier) {
                current = Some(carrier);
                output = self.exit_output(carrier, normal_exit);
            }
            if let Some(to) = output {
                self.record(seed, ExtraTarget::Port(to), fact);
            }
        }
    }

    fn exit_output(&mut self, carrier: u32, normal_exit: bool) -> Option<PortId> {
        let port = port_of_endpoint(&self.carriers.endpoints[carrier as usize])?;
        let is_output = match port {
            PartialFlowPort::NormalReturn
            | PartialFlowPort::IndexedNormalReturn { .. }
            | PartialFlowPort::ExceptionalReturn => true,
            PartialFlowPort::Heap { .. } => normal_exit,
            _ => false,
        };
        is_output.then(|| self.ports.intern(port))
    }

    fn apply_relation(&self, live: &mut Facts, point: ProgramPointId, step: RelationStep) {
        if step.kill_target {
            remove_carrier(live, step.target);
        }
        let generated = live
            .range(carrier_range(step.source))
            .map(|(&(_, seed), fact)| (seed, fact.clone()))
            .collect::<Vec<_>>();
        if step.invalidate_source {
            remove_carrier(live, step.source);
        }
        for (seed, fact) in generated {
            join(
                live,
                (step.target, seed),
                fact.uncertain || step.uncertain,
                &fact.crossed,
                || self.extend(&fact.witness, point, step.event_index),
            );
        }
    }

    /// Every fact leaving a call's point for the call's own continuation
    /// crossed `call`: add it to each of the fact's path classes. The ICFG
    /// engine replaces these edges by the call's continuation edges, which
    /// carry the call's dispatch quality, so every fact live across the call
    /// takes that quality whether or not it enters the callee.
    fn cross_call(live: &mut Facts, call: CallSiteId) {
        for fact in live.values_mut() {
            fact.crossed = fact.crossed.cross(call.index());
        }
    }

    /// Apply one point: its events in order, each event's relations in relation
    /// order, then the continuation seeds. Rule 6 observations are taken at
    /// the events they name; extra observations at the phase they name.
    fn transfer(&mut self, point: ProgramPointId, mut live: Facts) -> Facts {
        let semantics = self.semantics;
        let index = point.index();
        for (observation, carrier) in self.before_observations[index].clone() {
            self.observe(&live, carrier, ExtraTarget::Observation(observation));
        }
        let mut cursor = 0;
        for (event_index, event) in semantics.points()[index].events.iter().enumerate() {
            let event_index = u32::try_from(event_index).expect("an event index fits u32");
            let call = match &event.effect {
                SemanticEffect::Invoke { call_site } => Some(*call_site),
                _ => None,
            };
            if let Some(call) = call {
                let observed = self.calls[&call].observed.clone();
                for (port, carrier) in observed {
                    self.observe(&live, carrier, ExtraTarget::Port(port));
                }
            }
            if let SemanticEffect::CaptureBind { capture } = &event.effect {
                // The captured source is the source of this event's capture
                // relation, observed before the relation applies.
                let port = self.capture_outs[capture];
                let sources = self.steps[index][cursor..]
                    .iter()
                    .take_while(|step| step.event_index == event_index)
                    .filter(|step| step.captures)
                    .map(|step| step.source)
                    .collect::<Vec<_>>();
                for source in sources {
                    self.observe(&live, source, ExtraTarget::Port(port));
                }
            }
            // A call is a boundary that keeps every fact live, including facts
            // on its result and thrown carriers, as the solver's boundary edge
            // does. Rust's vec! and dbg! lowerings write element flows into the
            // call's result before its Invoke, and removing them here erased
            // those flows. The continuation seeds the result after the call.
            while cursor < self.steps[index].len()
                && self.steps[index][cursor].event_index == event_index
            {
                self.apply_relation(&mut live, point, self.steps[index][cursor]);
                cursor += 1;
            }
        }
        assert_eq!(
            cursor,
            self.steps[index].len(),
            "every relation at a point names one of its events"
        );
        if point == semantics.normal_exit_point() {
            self.observe_exit(&live, true);
        } else if point == semantics.exceptional_exit_point() {
            self.observe_exit(&live, false);
        }
        for (seed, carrier) in self.continuation_seeds[index].clone() {
            join(&mut live, (carrier, seed), false, &self.start, || {
                self.seed_witness(point)
            });
        }
        for (observation, carrier) in self.after_observations[index].clone() {
            self.observe(&live, carrier, ExtraTarget::Observation(observation));
        }
        live
    }

    /// Push the point's output along each feasible successor edge, minus the
    /// guard kills of that edge, and re-queue every successor whose entry
    /// state grew.
    fn propagate(&mut self, point: ProgramPointId, out: &Facts) {
        let semantics = self.semantics;
        let call = invoked_call(semantics, point);
        let successors = semantics
            .successor_edges(point)
            .map(|(_, edge)| {
                // The call's scaffolding edges are the ones the ICFG engine
                // replaces by its continuation edges; any other edge of the
                // call's point stays an ordinary local edge there.
                let crossed = call.filter(|call| is_call_scaffolding(edge, call));
                (edge.target_point, edge.kind, crossed.map(|call| call.id))
            })
            .collect::<Vec<_>>();
        for (target, kind, crossed) in successors {
            if self.infeasible[target.index()] {
                continue;
            }
            let mut outgoing = out.clone();
            if let Some(carriers) = self.edge_kills.get(&(point, target, kind)) {
                for &carrier in carriers {
                    remove_carrier(&mut outgoing, carrier);
                }
            }
            if let Some(call) = crossed {
                Self::cross_call(&mut outgoing, call);
            }
            let mut changed = false;
            for (key, fact) in outgoing {
                changed |= join(
                    &mut self.in_states[target.index()],
                    key,
                    fact.uncertain,
                    &fact.crossed,
                    || fact.witness.clone(),
                );
            }
            if changed && !self.queued[target.index()] {
                self.queued[target.index()] = true;
                self.stack.push(target.index());
            }
        }
    }
}

/// The call invoked at `point`, if its events invoke one, as the ICFG engine
/// finds it (`invoked_call_at`).
fn invoked_call(
    semantics: &ProcedureSemantics,
    point: ProgramPointId,
) -> Option<&SemanticCallSite> {
    let call = semantics.points()[point.index()]
        .events
        .iter()
        .find_map(|event| match event.effect {
            SemanticEffect::Invoke { call_site } => Some(call_site),
            _ => None,
        })?;
    Some(
        semantics
            .call_site(call)
            .expect("an Invoke event names a call of its procedure"),
    )
}

/// Partial flows of one procedure, from its relation snapshot and its IR.
///
/// The snapshot must belong to `procedure`. The result is computed without
/// any call resolution: every call is a boundary.
pub fn compute_partial_flows(
    procedure: &ProcedureHandle,
    snapshot: &ValueFlowSnapshot,
) -> ProcedurePartialFlows {
    compute_partial_flows_with(procedure, snapshot, &[], &[], false).partial
}

/// The partial flows of one procedure, extended by extra seeds and extra
/// observations (spec M3.2). The procedure's own input and call-result seeds
/// are always present, so `partial` is what [`compute_partial_flows`] reports.
/// `flows` holds the facts of the extra seeds, with the derivation of each
/// when `record_witnesses` is set.
pub fn compute_partial_flows_with(
    procedure: &ProcedureHandle,
    snapshot: &ValueFlowSnapshot,
    extra_seeds: &[ExtraSeed],
    observations: &[ExtraObservation],
    record_witnesses: bool,
) -> ExtendedPartialFlows {
    assert!(
        snapshot.procedure() == procedure,
        "a value-flow snapshot is computed for the procedure it describes"
    );
    let semantics = procedure.semantics();
    let point_count = semantics.points().len();
    let mut carriers = Carriers::default();
    let mut ports = PortTable::default();

    let mut steps = vec![Vec::new(); point_count];
    for relation in snapshot.relations() {
        let source = carriers.intern(&relation.source);
        let target = carriers.intern(&relation.target);
        steps[relation.point.id().index()].push(RelationStep {
            event_index: relation.event_index,
            source,
            target,
            kill_target: kills_target(
                relation.kind,
                relation.source != relation.target,
                relation.strong_update,
                relation.direct_cell_overwrite,
            ),
            invalidate_source: invalidates_source(relation.transfer),
            uncertain: !relation.is_proven_complete(),
            captures: relation.kind == ValueFlowRelationKind::Capture,
        });
    }
    for point_steps in &mut steps {
        point_steps.sort_by_key(|step| step.event_index);
    }

    // Seeds that are live before a point's events: `(point, seed, carrier)`.
    let mut before_seeds = Vec::new();
    let mut builtin_seeds = Vec::new();
    let mut continuation_seeds = vec![Vec::new(); point_count];
    let entry = semantics.entry_point();
    for value in semantics.values() {
        if !matches!(
            value.kind,
            SemanticValueKind::Receiver { .. } | SemanticValueKind::Parameter { .. }
        ) {
            continue;
        }
        let handle = procedure
            .value_handle(value.id)
            .expect("a live semantic value has a handle");
        let endpoint = ValueFlowEndpoint::for_value(handle);
        let port = port_of_endpoint(&endpoint).expect("an input value is a procedure port");
        let seed = u32::try_from(builtin_seeds.len()).expect("a seed count fits u32");
        builtin_seeds.push(ports.intern(port));
        before_seeds.push((entry, seed, carriers.intern(&endpoint)));
    }
    for location in semantics.memory_locations() {
        if !matches!(location.kind, MemoryLocationKind::Capture { .. }) {
            continue;
        }
        let port = ProcedurePortHandle::new(
            procedure.clone(),
            ProcedurePortKind::Capture { slot: location.id },
        )
        .expect("a capture memory location is a capture port");
        let endpoint = ValueFlowEndpoint::Port(port);
        let seed = u32::try_from(builtin_seeds.len()).expect("a seed count fits u32");
        builtin_seeds.push(ports.intern(PartialFlowPort::Capture { slot: location.id }));
        before_seeds.push((entry, seed, carriers.intern(&endpoint)));
    }

    // A relation that reads or copies out of a heap location rooted at a
    // receiver or parameter starts a fact on that location at entry: the value
    // the caller left in the field. Its port is the heap port of the location,
    // which is also the port a store into the location reaches.
    let mut heap_carriers = HashSet::new();
    for relation in snapshot.relations() {
        if !matches!(relation.source, ValueFlowEndpoint::Location(_)) {
            continue;
        }
        let Some(port) = port_of_endpoint(&relation.source) else {
            continue;
        };
        let PartialFlowPort::Heap { root, .. } = &port else {
            continue;
        };
        if !matches!(
            **root,
            PartialFlowPort::Receiver | PartialFlowPort::Parameter { .. }
        ) {
            continue;
        }
        let carrier = carriers.intern(&relation.source);
        if heap_carriers.insert(carrier) {
            let seed = u32::try_from(builtin_seeds.len()).expect("a seed count fits u32");
            builtin_seeds.push(ports.intern(port));
            before_seeds.push((entry, seed, carrier));
        }
    }

    let mut calls = HashMap::new();
    // An open snapshot has open gaps, which the head reports in `open`; only a
    // truncated snapshot is missing relations (spec M2.1).
    // A call continuation the IR does not resolve leaves the procedure open.
    let mut continuation_open = false;
    for call in semantics.call_sites() {
        let mut plan = CallPlan::default();
        for (port, value) in call_port_values(call) {
            let handle = procedure
                .value_handle(value)
                .expect("a call's value is a live semantic value");
            let carrier = carriers.intern(&ValueFlowEndpoint::for_value(handle));
            match port {
                PartialFlowPort::CallReceiver { .. } | PartialFlowPort::CallArgument { .. } => {
                    plan.observed.push((ports.intern(port), carrier));
                }
                PartialFlowPort::CallResult { .. } => {
                    plan.defined.push(carrier);
                    match call.normal_continuation {
                        ControlContinuation::Target(point) => {
                            let seed =
                                u32::try_from(builtin_seeds.len()).expect("a seed count fits u32");
                            builtin_seeds.push(ports.intern(port));
                            continuation_seeds[point.index()].push((seed, carrier));
                        }
                        ControlContinuation::Absent => {}
                        _ => continuation_open = true,
                    }
                }
                PartialFlowPort::CallThrown { .. } => {
                    plan.defined.push(carrier);
                    match call.exceptional_continuation {
                        ControlContinuation::Target(point) => {
                            let seed =
                                u32::try_from(builtin_seeds.len()).expect("a seed count fits u32");
                            builtin_seeds.push(ports.intern(port));
                            continuation_seeds[point.index()].push((seed, carrier));
                        }
                        ControlContinuation::Absent => {}
                        _ => continuation_open = true,
                    }
                }
                _ => unreachable!("call_port_values yields only call ports"),
            }
        }
        calls.insert(call.id, plan);
    }

    let mut capture_outs = HashMap::new();
    for capture in semantics.captures() {
        let port = ports.intern(PartialFlowPort::CaptureOut {
            target: capture.target,
            destination: capture.destination,
        });
        capture_outs.insert(capture.id, port);
    }

    let builtin_count = builtin_seeds.len();
    for (extra_index, seed) in extra_seeds.iter().enumerate() {
        let key = u32::try_from(builtin_count + extra_index).expect("a seed count fits u32");
        let carrier = carriers.intern(&seed.carrier);
        // A value a call defines exists only after that call, so a seed before
        // the call on it is live from the call's effects on.
        let defined_by_call_here = semantics.call_sites().iter().any(|call| {
            call.point == seed.point
                && calls
                    .get(&call.id)
                    .is_some_and(|plan: &CallPlan| plan.defined.contains(&carrier))
        });
        match seed.phase {
            ExtraPhase::BeforeEffects if !defined_by_call_here => {
                before_seeds.push((seed.point, key, carrier));
            }
            ExtraPhase::BeforeEffects | ExtraPhase::AfterEffects => {
                continuation_seeds[seed.point.index()].push((key, carrier));
            }
        }
    }
    let mut before_observations = vec![Vec::new(); point_count];
    let mut after_observations = vec![Vec::new(); point_count];
    for (index, observation) in observations.iter().enumerate() {
        let carrier = carriers.intern(&observation.carrier);
        match observation.phase {
            ExtraPhase::BeforeEffects => {
                before_observations[observation.point.index()].push((index, carrier));
            }
            ExtraPhase::AfterEffects => {
                after_observations[observation.point.index()].push((index, carrier));
            }
        }
    }

    let mut edge_kills: HashMap<(ProgramPointId, ProgramPointId, ControlEdgeKind), Vec<u32>> =
        HashMap::new();
    for kill in guard_edge_kills(procedure) {
        let carrier = carriers.intern(&kill.carrier);
        edge_kills
            .entry((kill.point, kill.target_point, kill.kind))
            .or_default()
            .push(carrier);
    }

    let infeasible = {
        let mut flags = vec![false; point_count];
        for point in procedure_infeasible_points(semantics).iter() {
            flags[point.index()] = true;
        }
        flags
    };

    let mut fixpoint = Fixpoint {
        semantics,
        start: Crossed::start(semantics.call_sites().len().div_ceil(64)),
        carriers,
        ports,
        witnesses: record_witnesses,
        builtin_seeds,
        flows: BTreeMap::new(),
        steps,
        capture_outs,
        calls,
        continuation_seeds,
        before_observations,
        after_observations,
        edge_kills,
        infeasible,
        in_states: vec![Facts::new(); point_count],
        queued: vec![false; point_count],
        stack: Vec::new(),
    };
    for (point, seed, carrier) in before_seeds {
        if fixpoint.infeasible[point.index()] {
            continue;
        }
        let witness = fixpoint.seed_witness(point);
        join(
            &mut fixpoint.in_states[point.index()],
            (carrier, seed),
            false,
            &fixpoint.start,
            || witness,
        );
        if !fixpoint.queued[point.index()] {
            fixpoint.queued[point.index()] = true;
            fixpoint.stack.push(point.index());
        }
    }
    // Continuation seeds join when their point is processed, and a point is
    // processed only when its entry state changes. A point that no fact
    // reaches would drop its seeds, so every feasible point with one is queued.
    for index in 0..point_count {
        if !fixpoint.continuation_seeds[index].is_empty()
            && !fixpoint.infeasible[index]
            && !fixpoint.queued[index]
        {
            fixpoint.queued[index] = true;
            fixpoint.stack.push(index);
        }
    }
    while let Some(index) = fixpoint.stack.pop() {
        fixpoint.queued[index] = false;
        let point = ProgramPointId::try_from_index(index).expect("a point index fits u32");
        let live = fixpoint.in_states[index].clone();
        let out = fixpoint.transfer(point, live);
        fixpoint.propagate(point, &out);
    }

    let builtin_count = u32::try_from(builtin_count).expect("a seed count fits u32");
    let mut flows = Vec::new();
    let mut extra_flows = Vec::new();
    for ((seed, target), fact) in fixpoint.flows {
        if seed < builtin_count {
            if let ExtraTarget::Port(to) = target {
                flows.push(PartialFlow {
                    from: fixpoint.builtin_seeds[seed as usize],
                    to,
                    uncertain: fact.uncertain,
                    crossed: fact.crossed.calls(),
                });
            }
        } else {
            extra_flows.push(ExtraFlow {
                seed: usize::try_from(seed - builtin_count).expect("a seed index fits usize"),
                target,
                uncertain: fact.uncertain,
                crossed: fact.crossed.calls(),
                witness: fact
                    .witness
                    .map(|witness| witness.to_vec().into_boxed_slice()),
            });
        }
    }
    flows.sort_by_key(|flow| (flow.from, flow.to));

    let mut open = continuation_open;
    let mut discharged_gaps = Vec::new();
    for gap in semantics.gaps() {
        if !gap_impacts_value_flow(gap) {
            continue;
        }
        if snapshot.gap_is_discharged(gap.id) {
            discharged_gaps.push(gap.id);
        } else {
            open = true;
        }
    }

    let partial = ProcedurePartialFlows {
        detail: None,
        outcome: if snapshot.coverage() == CandidateCoverage::Truncated {
            PartialFlowOutcome::Truncated
        } else {
            PartialFlowOutcome::Complete
        },
        ports: fixpoint.ports.into_ports(),
        flows,
        open,
        relations_complete: snapshot
            .relations()
            .iter()
            .all(|relation| relation.is_proven_complete()),
        discharged_gaps,
    };
    ExtendedPartialFlows {
        partial,
        flows: extra_flows,
    }
}

/// The extra seed at which a run takes one input port of `procedure`: an
/// input port is live at its procedure's entry (receiver, parameter, capture
/// slot, or a heap location rooted at one of them) or at the continuation of
/// the call that defines it (call result and thrown value). `None` for a port
/// that is not an input, and for a heap port no relation of the snapshot
/// reads or writes: that location carries no value the run can follow.
pub fn input_port_seed(
    procedure: &ProcedureHandle,
    snapshot: &ValueFlowSnapshot,
    port: &PartialFlowPort,
) -> Option<ExtraSeed> {
    let semantics = procedure.semantics();
    let entry = semantics.entry_point();
    let port_endpoint = |kind| {
        ValueFlowEndpoint::Port(
            ProcedurePortHandle::new(procedure.clone(), kind)
                .expect("an input port of the procedure is a valid port handle"),
        )
    };
    let seed = match port {
        PartialFlowPort::Receiver => ExtraSeed {
            point: entry,
            phase: ExtraPhase::BeforeEffects,
            carrier: port_endpoint(ProcedurePortKind::Receiver),
        },
        PartialFlowPort::Parameter { ordinal } => ExtraSeed {
            point: entry,
            phase: ExtraPhase::BeforeEffects,
            carrier: port_endpoint(ProcedurePortKind::Parameter { ordinal: *ordinal }),
        },
        PartialFlowPort::Capture { slot } => ExtraSeed {
            point: entry,
            phase: ExtraPhase::BeforeEffects,
            carrier: port_endpoint(ProcedurePortKind::Capture { slot: *slot }),
        },
        PartialFlowPort::Heap { .. } => {
            let carrier = snapshot
                .relations()
                .iter()
                .flat_map(|relation| [&relation.source, &relation.target])
                .find(|endpoint| {
                    matches!(endpoint, ValueFlowEndpoint::Location(_))
                        && port_of_endpoint(endpoint).as_ref() == Some(port)
                })?
                .clone();
            ExtraSeed {
                point: entry,
                phase: ExtraPhase::BeforeEffects,
                carrier,
            }
        }
        PartialFlowPort::CallResult { call, ordinal } => {
            let row = semantics
                .call_site(*call)
                .expect("a call-result port names a call of its procedure");
            let value = match ordinal {
                None => row.result,
                Some(ordinal) => row.normal_results.get(*ordinal as usize).copied(),
            }?;
            let ControlContinuation::Target(point) = row.normal_continuation else {
                return None;
            };
            ExtraSeed {
                point,
                phase: ExtraPhase::AfterEffects,
                carrier: ValueFlowEndpoint::for_value(
                    procedure
                        .value_handle(value)
                        .expect("a call's result is a live value"),
                ),
            }
        }
        PartialFlowPort::CallThrown { call } => {
            let row = semantics
                .call_site(*call)
                .expect("a call-thrown port names a call of its procedure");
            let ControlContinuation::Target(point) = row.exceptional_continuation else {
                return None;
            };
            ExtraSeed {
                point,
                phase: ExtraPhase::AfterEffects,
                carrier: ValueFlowEndpoint::for_value(
                    procedure
                        .value_handle(row.thrown?)
                        .expect("a call's thrown value is a live value"),
                ),
            }
        }
        _ => return None,
    };
    Some(seed)
}

/// The carriers of a caller's `snapshot` that name the location a callee's
/// heap input port reads at one call: the callee's access path `selectors`
/// with `tail`, appended to `origin`, one caller location that backs the
/// bound actual. The result is what an extended run observes before the
/// call's effects (spec M3.2). It is empty when no relation of the caller
/// names that location: the caller never wrote or read it, so it holds no
/// value the caller put there.
///
/// The appended selectors follow the plan's call-location substitution. An
/// exact index names a value of the callee, so it matches any index of the
/// caller; an index wildcard, an inexact origin or a summary tail makes the
/// caller path a summary. A field selector matches when the locators are
/// equal. A Rust field is declaration-backed, so the callee and the caller
/// spell it alike; a language whose member locators carry the enclosing
/// declaration of the use site would need the plan's respelling here.
pub fn caller_location_carriers(
    snapshot: &ValueFlowSnapshot,
    origin: &AbstractLocation,
    selectors: &[HeapSelector],
    tail: AccessPathTail,
) -> Vec<ValueFlowEndpoint> {
    let mut wanted = heap_selectors(origin.path().selectors()).into_vec();
    let mut lossy = !origin.path().is_exact() || tail == AccessPathTail::Summary;
    for selector in selectors {
        wanted.push(match selector {
            HeapSelector::ExactIndex(_) | HeapSelector::AnyIndex => {
                lossy = true;
                HeapSelector::AnyIndex
            }
            other => other.clone(),
        });
    }
    let wanted_tail = if lossy {
        AccessPathTail::Summary
    } else {
        AccessPathTail::Exact
    };
    let mut carriers = Vec::new();
    let mut seen = HashSet::new();
    for endpoint in snapshot
        .relations()
        .iter()
        .flat_map(|relation| [&relation.source, &relation.target])
    {
        let ValueFlowEndpoint::Location(location) = endpoint else {
            continue;
        };
        let path = location.path();
        if path.root() == origin.path().root()
            && path.tail() == wanted_tail
            && *heap_selectors(path.selectors()) == *wanted
            && seen.insert(endpoint)
        {
            carriers.push(endpoint.clone());
        }
    }
    carriers
}

/// The partial flows of every procedure of one validated artifact, projected
/// from the file alone (spec M2.3). Index `i` is procedure `i`. A projection
/// that fails or runs out of budget records that procedure's head and the
/// others are still computed. `None` means the request was cancelled.
pub(crate) fn parse_time_partial_flows(
    artifact: &Arc<SemanticArtifact>,
    syntax: &PreparedSyntaxTree,
    cancellation: &CancellationToken,
) -> Option<Vec<ProcedurePartialFlows>> {
    let host = FileLocalProjectionHost {
        syntax: Some(syntax),
    };
    let context = OracleCallContext::empty();
    let mut flows = Vec::with_capacity(artifact.procedures().len());
    for procedure in artifact.procedures() {
        let handle = artifact
            .procedure_handle(procedure.id())
            .expect("a procedure of the artifact has a handle");
        let mut budget = SemanticBudget::default();
        let projected = project_procedure_relations(
            &host,
            &handle,
            &context,
            OracleLimits::default(),
            &mut SemanticRequest::new(&mut budget, cancellation),
        );
        flows.push(match projected {
            Ok(SemanticOutcome::Complete { value, .. }) => compute_partial_flows(&handle, &value),
            Ok(SemanticOutcome::Cancelled { .. }) => return None,
            Ok(SemanticOutcome::ExceededBudget { .. }) => {
                ProcedurePartialFlows::without_flows(PartialFlowOutcome::ExceededBudget)
            }
            // An unresolved dispatch gap makes the projection incomplete while
            // its snapshot is still the answer for every relation it names. The
            // procedure is open, and its flows are the ones the snapshot proves.
            Ok(outcome) => match outcome.available_value() {
                Some(snapshot) => {
                    let mut result = compute_partial_flows(&handle, snapshot);
                    result.outcome = PartialFlowOutcome::Complete;
                    result.open = true;
                    result.detail = Some(outcome.label().to_owned());
                    result
                }
                None => ProcedurePartialFlows::failed(outcome.label().to_owned()),
            },
            Err(error) => ProcedurePartialFlows::failed(error.to_string()),
        });
    }
    Some(flows)
}
