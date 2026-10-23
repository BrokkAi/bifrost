//! The intra-procedural fixpoint behind partial flows. A fact is a seed port,
//! a carrier, an uncertainty bit and the calls its
//! paths crossed. Every call site is a boundary: facts flow through the
//! procedure's own relations and control edges only.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet};

use crate::analyzer::semantic::partial_flow::FileLocalProjectionHost;

use crate::analyzer::semantic::partial_flow::ports::HeapSelector;

use crate::analyzer::semantic::partial_flow::ports::PartialFlowPort;

use crate::analyzer::semantic::partial_flow::ports::PortId;

use crate::analyzer::semantic::partial_flow::ports::PortTable;

use crate::analyzer::semantic::partial_flow::ports::call_port_values;

use crate::analyzer::semantic::partial_flow::ports::heap_selectors;

use crate::analyzer::semantic::partial_flow::ports::port_of_endpoint;

use crate::analyzer::semantic::partial_flow::rules::guard_edge_kills;

use crate::analyzer::semantic::partial_flow::rules::invalidates_source;

use crate::analyzer::semantic::partial_flow::rules::kills_target;

use crate::analyzer::semantic::partial_flow::rules::procedure_infeasible_points;

use brokk_bifrost_core::cancellation::CancellationToken;

use crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmBudget;

use crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmRequest;

use crate::analyzer::semantic::cfg_algorithms::depth_first_order;

use crate::analyzer::semantic::icfg::is_call_scaffolding;

use crate::analyzer::semantic::workspace_oracle::gap_impacts_value_flow;

use crate::analyzer::semantic::workspace_oracle::project_procedure_relations;

use crate::analyzer::semantic::AbstractLocation;

use crate::analyzer::semantic::AccessPath;

use crate::analyzer::semantic::AccessPathTail;

use crate::analyzer::semantic::AccessSelector;

use crate::analyzer::semantic::CallSiteId;

use crate::analyzer::semantic::CandidateCoverage;

use crate::analyzer::semantic::CaptureId;

use crate::analyzer::semantic::ControlContinuation;

use crate::analyzer::semantic::ControlEdgeKind;

use crate::analyzer::semantic::IndexSelector;

use crate::analyzer::semantic::MemoryLocationKind;

use crate::analyzer::semantic::ObservationPhase;

use crate::analyzer::semantic::OracleCallContext;

use crate::analyzer::semantic::OracleLimits;

use crate::analyzer::semantic::ProcedureHandle;

use crate::analyzer::semantic::ProcedurePortHandle;

use crate::analyzer::semantic::ProcedurePortKind;

use crate::analyzer::semantic::ProcedureSemantics;

use crate::analyzer::semantic::ProgramPointId;

use crate::analyzer::semantic::ScopedSemanticLocator;

use crate::analyzer::semantic::SemanticArtifact;

use crate::analyzer::semantic::SemanticBudget;

use crate::analyzer::semantic::SemanticExecutionBudget;

use crate::analyzer::semantic::SemanticCallSite;

use crate::analyzer::semantic::SemanticEffect;

use crate::analyzer::semantic::SemanticGapId;

use crate::analyzer::semantic::SemanticOutcome;

use crate::analyzer::semantic::SemanticRequest;

use crate::analyzer::semantic::SemanticValueKind;

use crate::analyzer::semantic::ValueFlowEndpoint;

use crate::analyzer::semantic::ValueFlowRelationKind;

use crate::analyzer::semantic::ValueFlowSnapshot;

use crate::analyzer::semantic::ValueId;

use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
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

// A per-procedure solver limit, calibrated against the #6392 corpora. Changing
// it changes the stored derivation and requires a semantic IR rows-version bump.
// Maximum measured: 300,017,377 in drive_scheduler_inner,
// crates/bifrost-store/src/analyzer/resolution/fact_resolution/demand_scheduler.rs.
// Its 13% rise from 264,531,860 is the expected cost of taken chains rerunning
// on every predecessor visit. Wasmtime's cranelift/codegen/src/isa/s390x/inst/
// emit_tests.rs::test_s390x_binemit visits 219,120,293 facts. The cap exceeds
// ten times the corpus maximum (3,000,173,770), rounded up with headroom.
const MAX_PARTIAL_FLOW_FACT_VISITS: usize = 3_500_000_000;

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
    /// The projection or fixpoint exhausted its budget; no flows are recorded.
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

    // Widening is order-dependent: processing order changes which classes merge.
    // Both results are sound; eager scheduling changes groupings and widens less often.
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
        let mut any_present = false;
        let mut all_present = true;
        for set in self.sets.iter() {
            let present = set[word] & bit != 0;
            any_present |= present;
            all_present &= present;
        }
        if all_present {
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
        if !any_present {
            // Adding the same absent bit to every set preserves equality,
            // lexicographic order, and subset relations, so reduction is
            // unnecessary in this case.
            return Self {
                sets: Arc::from(crossed),
                widened: self.widened,
            };
        }
        // A widened fact has one set, so it took one of the uniform paths.
        debug_assert!(!self.widened);
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
    /// Exact carrier values of this selected relation, not every operand of
    /// the event. Query-only evidence; no note enters the fact lattice.
    pub source: Option<ValueId>,
    pub target: Option<ValueId>,
    pub phase: ObservationPhase,
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

/// A query-local exact heap read and the value carriers whose source seeds
/// taint its containing value. Location writes are expanded structurally by
/// the fixpoint; value carriers apply only at source introduction, so loading
/// an old parent after a child overwrite cannot resurrect the child's taint.
#[derive(Debug, Clone)]
pub struct ImplicitHeapRead {
    pub location: AbstractLocation,
    /// Covering source carriers and whether their storage provenance is uncertain.
    pub seed_carriers: Vec<(ValueFlowEndpoint, bool)>,
}

/// Exact prefix coverage for a taint read. Sibling paths and inexact paths
/// never imply coverage, and the implication only runs toward descendants.
pub fn exact_location_covers_read(parent: &AbstractLocation, child: &AbstractLocation) -> bool {
    parent.path().is_exact()
        && child.path().is_exact()
        && parent.path().root() == child.path().root()
        && heap_selectors(child.path().selectors())
            .starts_with(&heap_selectors(parent.path().selectors()))
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

/// The result of one extended run. `partial` holds the built-in seed flows
/// when the solve completes. `flows` holds the facts
/// that started at the extra seeds, in seed order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedPartialFlows {
    pub partial: ProcedurePartialFlows,
    pub flows: Vec<ExtraFlow>,
}

/// The exact value of a carrier, if it denotes one. A storage location's
/// root is not the value stored in it and is deliberately not substituted.
pub fn observation_value(endpoint: &ValueFlowEndpoint) -> Option<ValueId> {
    match endpoint {
        ValueFlowEndpoint::Value(value) => Some(value.id()),
        ValueFlowEndpoint::Port(port) => {
            port.procedure()
                .semantics()
                .values()
                .iter()
                .find_map(|value| {
                    let matches = match (port.kind(), &value.kind) {
                        (ProcedurePortKind::Receiver, SemanticValueKind::Receiver { .. }) => true,
                        (
                            ProcedurePortKind::Parameter { ordinal },
                            SemanticValueKind::Parameter {
                                ordinal: candidate, ..
                            },
                        ) => ordinal == *candidate,
                        _ => false,
                    };
                    matches.then_some(value.id)
                })
        }
        ValueFlowEndpoint::Location(_) => None,
    }
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

/// A query's observation policy. Implementations may only remove live facts;
/// the policy-independent producer uses the pass-through implementation.
/// An abstract carrier need not identify a value: the filter decides from the
/// structured endpoint rather than guessing a value from source text.
pub trait ObservationFilter {
    type Error;

    fn permits(
        &mut self,
        point: ProgramPointId,
        phase: ObservationPhase,
        endpoint: &ValueFlowEndpoint,
        request: &mut SemanticRequest<'_>,
    ) -> Result<bool, Self::Error>;
}

struct PassThrough;

impl ObservationFilter for PassThrough {
    type Error = std::convert::Infallible;

    fn permits(
        &mut self,
        _point: ProgramPointId,
        _phase: ObservationPhase,
        _endpoint: &ValueFlowEndpoint,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// Query-scoped worklist observations for the pending-frontier regressions.
#[cfg(feature = "test-support")]
#[derive(Debug, Default)]
pub struct FixpointTestMetrics {
    pub peak_pending_taken_maps: usize,
    pub pending_taken_maps: usize,
    /// Point, number of entry facts, and whether the visit came from the stack.
    pub transfers: Vec<(ProgramPointId, usize, bool)>,
    pub stale_heap_entries: usize,
}

#[cfg(feature = "test-support")]
thread_local! {
    static FIXPOINT_TEST_METRICS: std::cell::RefCell<Option<FixpointTestMetrics>> = const {
        std::cell::RefCell::new(None)
    };
}

/// Measure a solve on this thread without sharing counters between tests.
#[cfg(feature = "test-support")]
pub fn with_fixpoint_test_metrics<T>(solve: impl FnOnce() -> T) -> (T, FixpointTestMetrics) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            FIXPOINT_TEST_METRICS.with(|metrics| *metrics.borrow_mut() = None);
        }
    }
    FIXPOINT_TEST_METRICS.with(|metrics| {
        assert!(
            metrics.borrow().is_none(),
            "fixpoint measurements cannot nest"
        );
        *metrics.borrow_mut() = Some(FixpointTestMetrics::default());
    });
    let _reset = Reset;
    let result = solve();
    let metrics = FIXPOINT_TEST_METRICS.with(|metrics| metrics.borrow_mut().take().unwrap());
    (result, metrics)
}

#[cfg(feature = "test-support")]
fn record_fixpoint_test_metrics(record: impl FnOnce(&mut FixpointTestMetrics)) {
    FIXPOINT_TEST_METRICS.with(|metrics| {
        if let Some(metrics) = metrics.borrow_mut().as_mut() {
            record(metrics);
        }
    });
}

/// A differential's accepted widening changes and separately observed witnesses.
#[cfg(feature = "test-support")]
#[derive(Debug, Default)]
pub struct PartialFlowReferenceComparison {
    pub crossed_differences: usize,
    pub witness_differences: usize,
    pub witness_example: Option<String>,
}

#[cfg(feature = "test-support")]
thread_local! {
    static REFERENCE_WIDENED: std::cell::RefCell<Option<std::collections::BTreeSet<(bool, u32, ExtraTarget)>>> = const {
        std::cell::RefCell::new(None)
    };
}

/// Compare the eager solver with the original retaining, rank-heap solver.
/// Accept only crossed changes on facts widened in at least one run. Witness
/// choices are counted separately. Filters must be repeatable across the runs.
#[cfg(feature = "test-support")]
#[allow(clippy::too_many_arguments)]
pub fn compare_partial_flows_with_reference<F: ObservationFilter>(
    procedure: &ProcedureHandle,
    snapshot: &ValueFlowSnapshot,
    extra_seeds: &[ExtraSeed],
    observations: &[ExtraObservation],
    record_witnesses: bool,
    implicit_reads: &[ImplicitHeapRead],
    filter: &mut F,
    request: &mut SemanticRequest<'_>,
) -> Result<(ExtendedPartialFlows, PartialFlowReferenceComparison), F::Error> {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            REFERENCE_WIDENED.with(|snapshot| *snapshot.borrow_mut() = None);
        }
    }
    REFERENCE_WIDENED.with(|snapshot| {
        assert!(
            snapshot.borrow().is_none(),
            "reference comparisons cannot nest"
        );
        *snapshot.borrow_mut() = Some(Default::default());
    });
    let _reset = Reset;
    let execution = request
        .execution_budget()
        .map(|budget| budget.fork().1)
        .unwrap_or_else(|| SemanticExecutionBudget::new(usize::MAX));
    let mut reference_request = request.staged_with_execution_budget(&execution);
    let reference = compute_partial_flows_filtered_impl::<F, true>(
        procedure,
        snapshot,
        extra_seeds,
        observations,
        record_witnesses,
        implicit_reads,
        filter,
        &mut reference_request,
    )?;
    let reference_widened =
        REFERENCE_WIDENED.with(|snapshot| std::mem::take(snapshot.borrow_mut().as_mut().unwrap()));
    let eager = compute_partial_flows_filtered_impl::<F, false>(
        procedure,
        snapshot,
        extra_seeds,
        observations,
        record_witnesses,
        implicit_reads,
        filter,
        request,
    )?;
    let eager_widened =
        REFERENCE_WIDENED.with(|snapshot| std::mem::take(snapshot.borrow_mut().as_mut().unwrap()));
    let mut comparison = PartialFlowReferenceComparison::default();
    let mut expected = reference.clone();
    let accept = |key: (bool, u32, ExtraTarget)| {
        assert!(
            reference_widened.contains(&key) || eager_widened.contains(&key),
            "unwidened crossed difference in {:?}: {key:?}",
            procedure.semantics().locator()
        );
    };
    for (old, new) in expected.flows.iter_mut().zip(&eager.flows) {
        if old.seed == new.seed && old.target == new.target {
            if old.crossed != new.crossed {
                accept((false, u32::try_from(old.seed).unwrap(), old.target));
                comparison.crossed_differences += 1;
                old.crossed.clone_from(&new.crossed);
            }
            if old.witness != new.witness {
                comparison.witness_differences += 1;
                comparison.witness_example.get_or_insert_with(|| {
                    format!(
                        "{:?}: seed={} target={:?} reference={:?} eager={:?}",
                        procedure.semantics().locator(),
                        old.seed,
                        old.target,
                        old.witness,
                        new.witness
                    )
                });
                old.witness.clone_from(&new.witness);
            }
        }
    }
    for (old, new) in expected.partial.flows.iter_mut().zip(&eager.partial.flows) {
        if old.from == new.from && old.to == new.to && old.crossed != new.crossed {
            accept((
                true,
                u32::try_from(old.from.index()).unwrap(),
                ExtraTarget::Port(old.to),
            ));
            comparison.crossed_differences += 1;
            old.crossed.clone_from(&new.crossed);
        }
    }
    assert_eq!(
        expected,
        eager,
        "non-crossed reference difference in {:?}",
        procedure.semantics().locator()
    );
    Ok((eager, comparison))
}

struct Fixpoint<'a, 'r, F> {
    request: &'a mut SemanticRequest<'r>,
    traversal: SemanticExecutionBudget,
    filter: &'a mut F,
    semantics: &'a ProcedureSemantics,
    /// Dense reverse-postorder rank for each program point.
    point_ranks: Vec<usize>,
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
    /// Seeds joined after a point's own events: `(seed key, carrier, uncertain)`. A call
    /// result or thrown port seeds at its continuation, and an extra seed with
    /// the after-effects phase seeds at its point.
    continuation_seeds: Vec<Vec<(u32, u32, bool)>>,
    /// Seeds reapplied before observations: `(seed key, carrier, uncertain)`.
    before_seeds: Vec<Vec<(u32, u32, bool)>>,
    /// Merges, retreating-edge targets and before-seeded points retain history.
    retain_entry: Vec<bool>,
    /// Observations taken before a point's events: `(observation, carrier)`.
    before_observations: Vec<Vec<(usize, u32)>>,
    /// Observations taken after a point's events and continuation seeds.
    after_observations: Vec<Vec<(usize, u32)>>,
    implicit_targets: HashMap<u32, Vec<u32>>,
    /// Synthetic read carriers observe existing callee inputs; they do not
    /// introduce output ports the caller's projection never published.
    observation_only: HashSet<u32>,
    edge_kills: HashMap<(ProgramPointId, ProgramPointId, ControlEdgeKind), Vec<u32>>,
    infeasible: Vec<bool>,
    in_states: Vec<Facts>,
    queued: Vec<bool>,
    heap: BinaryHeap<Reverse<(usize, usize)>>,
    taken_subtree_sizes: Vec<usize>,
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

impl<F: ObservationFilter> Fixpoint<'_, '_, F> {
    fn permits(
        &mut self,
        point: ProgramPointId,
        phase: ObservationPhase,
        carrier: u32,
    ) -> Result<bool, F::Error> {
        self.filter.permits(
            point,
            phase,
            &self.carriers.endpoints[carrier as usize],
            self.request,
        )
    }

    /// The witness of a fact that `base` derived and that a relation at
    /// `point` with event `event` carried one step further.
    fn extend(&self, base: &Witness, point: ProgramPointId, step: RelationStep) -> Witness {
        if !self.witnesses {
            return None;
        }
        let mut steps = base
            .as_deref()
            .map_or_else(Vec::new, <[WitnessStep]>::to_vec);
        steps.push(WitnessStep {
            point,
            event: step.event_index,
            source: observation_value(&self.carriers.endpoints[step.source as usize]),
            target: observation_value(&self.carriers.endpoints[step.target as usize]),
            phase: ObservationPhase::AfterEffects,
        });
        Some(Arc::from(steps))
    }

    /// The witness of a fact that a seed at `point` introduced.
    fn seed_witness(
        &self,
        point: ProgramPointId,
        carrier: u32,
        phase: ObservationPhase,
    ) -> Witness {
        self.witnesses.then(|| {
            Arc::from(vec![WitnessStep {
                point,
                event: SEED_EVENT,
                source: None,
                target: observation_value(&self.carriers.endpoints[carrier as usize]),
                phase,
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
    fn observe(
        &mut self,
        live: &mut Facts,
        point: ProgramPointId,
        phase: ObservationPhase,
        carrier: u32,
        target: ExtraTarget,
    ) -> Result<(), F::Error> {
        if live.range(carrier_range(carrier)).next().is_none() {
            return Ok(());
        }
        if !self.permits(point, phase, carrier)? {
            remove_carrier(live, carrier);
            return Ok(());
        }
        let observed = live
            .range(carrier_range(carrier))
            .map(|(&(_, seed), fact)| (seed, fact.clone()))
            .collect::<Vec<_>>();
        for (seed, fact) in observed {
            self.record(seed, target, fact);
        }
        Ok(())
    }

    /// Record facts that reach an output port at an exit point. Return ports
    /// are outputs at both exits; a heap location is an output at the normal
    /// exit only.
    fn observe_exit(
        &mut self,
        live: &mut Facts,
        point: ProgramPointId,
        normal_exit: bool,
    ) -> Result<(), F::Error> {
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
                if output.is_some()
                    && !self.permits(point, ObservationPhase::BeforeEffects, carrier)?
                {
                    remove_carrier(live, carrier);
                    output = None;
                }
            }
            if let Some(to) = output {
                self.record(seed, ExtraTarget::Port(to), fact);
            }
        }
        Ok(())
    }

    fn exit_output(&mut self, carrier: u32, normal_exit: bool) -> Option<PortId> {
        if self.observation_only.contains(&carrier) {
            return None;
        }
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

    fn apply_relation(
        &mut self,
        live: &mut Facts,
        point: ProgramPointId,
        step: RelationStep,
    ) -> Result<(), F::Error> {
        let implicit_targets = self
            .implicit_targets
            .get(&step.target)
            .cloned()
            .unwrap_or_default();
        let targets = std::iter::once(step.target).chain(implicit_targets.iter().copied());
        if step.kill_target {
            for target in targets.clone() {
                remove_carrier(live, target);
            }
        }
        if live.range(carrier_range(step.source)).next().is_some()
            && !self.permits(point, ObservationPhase::BeforeEffects, step.source)?
        {
            remove_carrier(live, step.source);
        }
        let generated = live
            .range(carrier_range(step.source))
            .map(|(&(_, seed), fact)| (seed, fact.clone()))
            .collect::<Vec<_>>();
        if step.invalidate_source {
            remove_carrier(live, step.source);
            for target in self
                .implicit_targets
                .get(&step.source)
                .into_iter()
                .flatten()
            {
                remove_carrier(live, *target);
            }
        }
        if !generated.is_empty()
            && !self.permits(point, ObservationPhase::AfterEffects, step.target)?
        {
            return Ok(());
        }
        for (seed, fact) in generated {
            for target in targets.clone() {
                join(
                    live,
                    (target, seed),
                    fact.uncertain || step.uncertain,
                    &fact.crossed,
                    || self.extend(&fact.witness, point, step),
                );
            }
        }
        Ok(())
    }

    /// Apply one point: its events in order, each event's relations in relation
    /// order, then the continuation seeds. Rule 6 observations are taken at
    /// the events they name; extra observations at the phase they name.
    fn transfer(&mut self, point: ProgramPointId, mut live: Facts) -> Result<Facts, F::Error> {
        let semantics = self.semantics;
        let index = point.index();
        for (seed, carrier, uncertain) in self.before_seeds[index].clone() {
            if self.permits(point, ObservationPhase::BeforeEffects, carrier)? {
                let witness = self.seed_witness(point, carrier, ObservationPhase::BeforeEffects);
                join(&mut live, (carrier, seed), uncertain, &self.start, || {
                    witness
                });
            }
        }
        for (observation, carrier) in self.before_observations[index].clone() {
            self.observe(
                &mut live,
                point,
                ObservationPhase::BeforeEffects,
                carrier,
                ExtraTarget::Observation(observation),
            )?;
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
                    self.observe(
                        &mut live,
                        point,
                        ObservationPhase::BeforeEffects,
                        carrier,
                        ExtraTarget::Port(port),
                    )?;
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
                    self.observe(
                        &mut live,
                        point,
                        ObservationPhase::BeforeEffects,
                        source,
                        ExtraTarget::Port(port),
                    )?;
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
                self.apply_relation(&mut live, point, self.steps[index][cursor])?;
                cursor += 1;
            }
        }
        assert_eq!(
            cursor,
            self.steps[index].len(),
            "every relation at a point names one of its events"
        );
        if point == semantics.normal_exit_point() {
            self.observe_exit(&mut live, point, true)?;
        } else if point == semantics.exceptional_exit_point() {
            self.observe_exit(&mut live, point, false)?;
        }
        for (seed, carrier, uncertain) in self.continuation_seeds[index].clone() {
            if !self.permits(point, ObservationPhase::AfterEffects, carrier)? {
                continue;
            }
            join(&mut live, (carrier, seed), uncertain, &self.start, || {
                self.seed_witness(point, carrier, ObservationPhase::AfterEffects)
            });
        }
        for (observation, carrier) in self.after_observations[index].clone() {
            self.observe(
                &mut live,
                point,
                ObservationPhase::AfterEffects,
                carrier,
                ExtraTarget::Observation(observation),
            )?;
        }
        Ok(live)
    }

    /// Push the point's output along each feasible successor edge, minus the
    /// guard kills of that edge, and re-queue every successor whose entry
    /// state grew. Refuse before a fact visit would exceed a traversal ledger.
    fn propagate(&mut self, point: ProgramPointId, out: &Facts) -> bool {
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
        let mut changed_taken = Vec::new();
        for (target, kind, crossed_call) in successors {
            if self.infeasible[target.index()] {
                continue;
            }
            let killed = self.edge_kills.get(&(point, target, kind));
            let mut changed = false;
            #[cfg(feature = "test-support")]
            let was_empty = self.in_states[target.index()].is_empty();
            // Filtering the borrowed map matches removing killed carriers
            // from an edge-local clone while preserving its BTree order.
            // Keep replaying every edge visit: widening can discard an
            // incoming class at the cap, so a later visit must join it again.
            for (&key, fact) in out {
                if !self.request.charge_execution_traversal(1)
                    || !self.traversal.charge_traversal(1)
                {
                    return false;
                }
                if killed.is_some_and(|carriers| carriers.contains(&key.0)) {
                    continue;
                }
                // Every fact on the call's continuation edges crossed the
                // call. Those edges carry dispatch quality, so each live fact
                // takes it whether or not it enters the callee.
                let incoming_crossed = crossed_call.map(|call| fact.crossed.cross(call.index()));
                let crossed = incoming_crossed.as_ref().unwrap_or(&fact.crossed);
                changed |= join(
                    &mut self.in_states[target.index()],
                    key,
                    fact.uncertain,
                    crossed,
                    || fact.witness.clone(),
                );
            }
            #[cfg(feature = "test-support")]
            if was_empty
                && !self.in_states[target.index()].is_empty()
                && !self.retain_entry[target.index()]
            {
                record_fixpoint_test_metrics(|metrics| {
                    metrics.pending_taken_maps += 1;
                    metrics.peak_pending_taken_maps = metrics
                        .peak_pending_taken_maps
                        .max(metrics.pending_taken_maps);
                });
            }
            if changed {
                if self.retain_entry[target.index()] {
                    if !self.queued[target.index()] {
                        self.queued[target.index()] = true;
                        self.heap
                            .push(Reverse((self.point_ranks[target.index()], target.index())));
                    }
                } else {
                    // A taken point has one predecessor, but several edges
                    // from it can contribute facts with different edge kills.
                    changed_taken.push(target.index());
                }
            }
        }
        changed_taken.sort_unstable();
        changed_taken.dedup();
        // Dense point IDs break size ties; neither hashes nor addresses choose order.
        changed_taken
            .sort_unstable_by_key(|&index| Reverse((self.taken_subtree_sizes[index], index)));
        self.stack.extend(changed_taken);
        true
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
    request: &mut SemanticRequest<'_>,
) -> ProcedurePartialFlows {
    compute_partial_flows_with(procedure, snapshot, &[], &[], false, request).partial
}

/// The partial flows of one procedure, extended by extra seeds and extra
/// observations. The procedure's own input and call-result seeds
/// are always present. `partial` contains their boundary flows when the solve
/// completes. `flows` holds the facts of the extra seeds, with the derivation of each
/// when `record_witnesses` is set.
pub fn compute_partial_flows_with(
    procedure: &ProcedureHandle,
    snapshot: &ValueFlowSnapshot,
    extra_seeds: &[ExtraSeed],
    observations: &[ExtraObservation],
    record_witnesses: bool,
    request: &mut SemanticRequest<'_>,
) -> ExtendedPartialFlows {
    match compute_partial_flows_filtered(
        procedure,
        snapshot,
        extra_seeds,
        observations,
        record_witnesses,
        &[],
        &mut PassThrough,
        request,
    ) {
        Ok(flows) => flows,
        Err(never) => match never {},
    }
}

/// Extend a query with ephemeral exact descendant heap reads.
pub fn compute_partial_flows_with_implicit_reads(
    procedure: &ProcedureHandle,
    snapshot: &ValueFlowSnapshot,
    extra_seeds: &[ExtraSeed],
    observations: &[ExtraObservation],
    record_witnesses: bool,
    implicit_reads: &[ImplicitHeapRead],
    request: &mut SemanticRequest<'_>,
) -> ExtendedPartialFlows {
    match compute_partial_flows_filtered(
        procedure,
        snapshot,
        extra_seeds,
        observations,
        record_witnesses,
        implicit_reads,
        &mut PassThrough,
        request,
    ) {
        Ok(flows) => flows,
        Err(never) => match never {},
    }
}

/// Run the same worklist with a query-local observation filter. No filtered
/// result is published as a policy-independent stored summary. Each invocation
/// has a fresh per-procedure traversal allowance and records fact visits in the
/// caller's request. A refusal returns an ExceededBudget head and no flows.
#[allow(clippy::too_many_arguments)]
pub fn compute_partial_flows_filtered<F: ObservationFilter>(
    procedure: &ProcedureHandle,
    snapshot: &ValueFlowSnapshot,
    extra_seeds: &[ExtraSeed],
    observations: &[ExtraObservation],
    record_witnesses: bool,
    implicit_reads: &[ImplicitHeapRead],
    filter: &mut F,
    request: &mut SemanticRequest<'_>,
) -> Result<ExtendedPartialFlows, F::Error> {
    compute_partial_flows_filtered_impl::<F, false>(
        procedure,
        snapshot,
        extra_seeds,
        observations,
        record_witnesses,
        implicit_reads,
        filter,
        request,
    )
}

#[allow(clippy::too_many_arguments)]
fn compute_partial_flows_filtered_impl<F: ObservationFilter, const RETAIN_ALL: bool>(
    procedure: &ProcedureHandle,
    snapshot: &ValueFlowSnapshot,
    extra_seeds: &[ExtraSeed],
    observations: &[ExtraObservation],
    record_witnesses: bool,
    implicit_reads: &[ImplicitHeapRead],
    filter: &mut F,
    request: &mut SemanticRequest<'_>,
) -> Result<ExtendedPartialFlows, F::Error> {
    assert!(
        snapshot.procedure() == procedure,
        "a value-flow snapshot is computed for the procedure it describes"
    );
    let semantics = procedure.semantics();
    let point_count = semantics.points().len();
    let mut cfg_budget = CfgAlgorithmBudget::default();
    let cancellation = CancellationToken::new();
    let reverse_postorder = depth_first_order(
        semantics,
        &mut CfgAlgorithmRequest::new(&mut cfg_budget, &cancellation),
    )
    .expect("validated procedure semantics has an unlimited, uncancelled DFS order")
    .reverse_postorder;
    let mut point_ranks = vec![usize::MAX; point_count];
    for (rank, point) in reverse_postorder.iter().enumerate() {
        point_ranks[point.index()] = rank;
    }
    assert!(
        point_ranks.iter().all(|rank| *rank != usize::MAX),
        "DFS reverse postorder includes every procedure point, including isolated points"
    );
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

    // Seeds live before a point's events: `(point, seed, carrier, uncertain)`.
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
        before_seeds.push((entry, seed, carriers.intern(&endpoint), false));
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
        before_seeds.push((entry, seed, carriers.intern(&endpoint), false));
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
            before_seeds.push((entry, seed, carrier, false));
        }
    }

    let mut calls = HashMap::new();
    // An open snapshot has open gaps, which the head reports in `open`; only a
    // truncated snapshot is missing relations.
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
                            continuation_seeds[point.index()].push((seed, carrier, false));
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
                            continuation_seeds[point.index()].push((seed, carrier, false));
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

    let projected_carriers = carriers.endpoints.len();
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
                before_seeds.push((seed.point, key, carrier, false));
            }
            ExtraPhase::BeforeEffects | ExtraPhase::AfterEffects => {
                continuation_seeds[seed.point.index()].push((key, carrier, false));
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

    let mut implicit_targets: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut observation_only = HashSet::new();
    for read in implicit_reads {
        assert!(read.location.path().is_exact());
        let target = carriers.intern(&ValueFlowEndpoint::Location(Box::new(
            read.location.clone(),
        )));
        if target as usize >= projected_carriers {
            observation_only.insert(target);
        }
        for (index, endpoint) in carriers.endpoints.iter().enumerate() {
            if index as u32 != target
                && let ValueFlowEndpoint::Location(location) = endpoint
                && exact_location_covers_read(location, &read.location)
            {
                implicit_targets
                    .entry(index as u32)
                    .or_default()
                    .push(target);
            }
        }
        // Expand at the source's phase, before subsequent strong updates.
        for (extra_index, seed) in extra_seeds.iter().enumerate() {
            let quality = read
                .seed_carriers
                .iter()
                .find(|(carrier, _)| carrier == &seed.carrier)
                .map(|(_, uncertain)| *uncertain)
                .or_else(|| {
                    matches!(&seed.carrier, ValueFlowEndpoint::Location(location)
                    if exact_location_covers_read(location, &read.location))
                    .then_some(false)
                });
            if let Some(uncertain) = quality {
                let key =
                    u32::try_from(builtin_count + extra_index).expect("a seed count fits u32");
                let original = carriers.intern(&seed.carrier);
                let entry_points = before_seeds
                    .iter()
                    .filter(|(_, seed, carrier, _)| *seed == key && *carrier == original)
                    .map(|(point, _, _, _)| *point)
                    .collect::<Vec<_>>();
                for point in entry_points {
                    before_seeds.push((point, key, target, uncertain));
                }
                for seeds in &mut continuation_seeds {
                    if seeds
                        .iter()
                        .any(|(seed, carrier, _)| *seed == key && *carrier == original)
                    {
                        seeds.push((key, target, uncertain));
                    }
                }
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

    for kills in edge_kills.values_mut() {
        let descendants = kills
            .iter()
            .flat_map(|carrier| implicit_targets.get(carrier).into_iter().flatten().copied())
            .collect::<Vec<_>>();
        kills.extend(descendants);
    }
    let infeasible = {
        let mut flags = vec![false; point_count];
        for point in procedure_infeasible_points(semantics).iter() {
            flags[point.index()] = true;
        }
        flags
    };

    let mut predecessors = vec![HashSet::new(); point_count];
    for index in 0..point_count {
        let point = ProgramPointId::try_from_index(index).expect("a point index fits u32");
        for (_, edge) in semantics.successor_edges(point) {
            predecessors[edge.target_point.index()].insert(point);
        }
    }
    let mut retain_entry: Vec<bool> = predecessors
        .iter()
        .enumerate()
        .map(|(index, points)| {
            RETAIN_ALL
                || points.len() != 1
                || points
                    .iter()
                    .any(|point| point_ranks[point.index()] >= point_ranks[index])
        })
        .collect();
    for (point, ..) in &before_seeds {
        retain_entry[point.index()] = true;
    }
    // Taken successors have strictly greater ranks and one distinct
    // predecessor, so this descending-rank pass counts their disjoint trees.
    // Retained points terminate the trees. Infeasible edges may over-count.
    let mut taken_subtree_sizes = vec![1usize; point_count];
    for point in reverse_postorder.iter().rev() {
        let mut successors: Vec<_> = semantics
            .successor_edges(*point)
            .map(|(_, edge)| edge.target_point.index())
            .filter(|&index| !retain_entry[index])
            .collect();
        successors.sort_unstable();
        successors.dedup();
        for successor in successors {
            taken_subtree_sizes[point.index()] += taken_subtree_sizes[successor];
        }
    }
    drop(reverse_postorder);
    // Every cycle has a non-increasing rank edge, hence a retained join.
    // Taken chains strictly increase rank and rerun once per predecessor visit.
    // Taking uses the predecessor's latest out, which equals its historical
    // join only while transfer is monotone. Static kills and pointwise copies
    // preserve that property; Crossed::widen at the class cap can discard path
    // classes. Earlier observations and retained successors already joined the
    // earlier wave, so taking cannot erase those observations. Removing stale
    // dominated classes can make a later widened union smaller than the old
    // historical union; this is the intentional rows-versioned improvement.
    let mut fixpoint = Fixpoint {
        request,
        traversal: SemanticExecutionBudget::for_fixpoint(MAX_PARTIAL_FLOW_FACT_VISITS),
        filter,
        semantics,
        point_ranks,
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
        before_seeds: vec![Vec::new(); point_count],
        retain_entry,
        before_observations,
        after_observations,
        edge_kills,
        implicit_targets,
        observation_only,
        infeasible,
        in_states: vec![Facts::new(); point_count],
        queued: vec![false; point_count],
        heap: BinaryHeap::new(),
        taken_subtree_sizes,
        stack: Vec::new(),
    };
    for (point, seed, carrier, uncertain) in before_seeds {
        if fixpoint.infeasible[point.index()] {
            continue;
        }
        fixpoint.before_seeds[point.index()].push((seed, carrier, uncertain));
        if !fixpoint.queued[point.index()] {
            fixpoint.queued[point.index()] = true;
            fixpoint.heap.push(Reverse((
                fixpoint.point_ranks[point.index()],
                point.index(),
            )));
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
            fixpoint
                .heap
                .push(Reverse((fixpoint.point_ranks[index], index)));
        }
    }
    // Retained joins keep their RPO waves; taken trees drain eagerly with
    // the smallest child first. A pending frontier holds at most
    // (fan-out - 1) * floor(log2(taken subtree size)) + 1 taken maps.
    // the stack is empty whenever the heap pops; `queued` marks a pending heap entry, and stack processing clears it so the entry is skipped.
    while let Some(Reverse((_, index))) = fixpoint.heap.pop() {
        debug_assert!(fixpoint.stack.is_empty());
        if !fixpoint.queued[index] {
            #[cfg(feature = "test-support")]
            record_fixpoint_test_metrics(|metrics| metrics.stale_heap_entries += 1);
            continue;
        }
        let mut current = (index, false);
        loop {
            let (index, _from_stack) = current;
            fixpoint.queued[index] = false;
            let point = ProgramPointId::try_from_index(index).expect("a point index fits u32");
            #[cfg(feature = "test-support")]
            record_fixpoint_test_metrics(|metrics| {
                metrics
                    .transfers
                    .push((point, fixpoint.in_states[index].len(), _from_stack));
                if !fixpoint.retain_entry[index] && !fixpoint.in_states[index].is_empty() {
                    metrics.pending_taken_maps -= 1;
                }
            });
            let live = if fixpoint.retain_entry[index] {
                fixpoint.in_states[index].clone()
            } else {
                std::mem::take(&mut fixpoint.in_states[index])
            };
            let out = fixpoint.transfer(point, live)?;
            if !fixpoint.propagate(point, &out) {
                brokk_bifrost_core::profiling::note_with(|| {
                    format!(
                        "partial_flows.fixpoint outcome=ExceededBudget facts_visited={} flows=0 procedure={:?}",
                        fixpoint.traversal.work().traversal_steps,
                        procedure.semantics().locator(),
                    )
                });
                return Ok(ExtendedPartialFlows {
                    partial: ProcedurePartialFlows::without_flows(
                        PartialFlowOutcome::ExceededBudget,
                    ),
                    flows: Vec::new(),
                });
            }
            // Finish every edge of propagate before a successor consumes its
            // input, including parallel Normal and Exceptional edges.
            if let Some(index) = fixpoint.stack.pop() {
                current = (index, true);
            } else {
                break;
            }
        }
    }

    #[cfg(feature = "test-support")]
    REFERENCE_WIDENED.with(|snapshot| {
        if let Some(snapshot) = snapshot.borrow_mut().as_mut() {
            *snapshot = fixpoint
                .flows
                .iter()
                .filter(|(_, fact)| fact.crossed.widened)
                .map(|(&(seed, target), _)| {
                    if (seed as usize) < builtin_count {
                        (
                            true,
                            u32::try_from(fixpoint.builtin_seeds[seed as usize].index()).unwrap(),
                            target,
                        )
                    } else {
                        (false, seed - u32::try_from(builtin_count).unwrap(), target)
                    }
                })
                .collect();
        }
    });
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
    brokk_bifrost_core::profiling::note_with(|| {
        format!(
            "partial_flows.fixpoint outcome={:?} facts_visited={} flows={} procedure={:?}",
            partial.outcome,
            fixpoint.traversal.work().traversal_steps,
            partial.flows.len(),
            procedure.semantics().locator(),
        )
    });
    Ok(ExtendedPartialFlows {
        partial,
        flows: extra_flows,
    })
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
/// call's effects. It is empty when no relation of the caller
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

/// Substitute an exact callee read into a caller origin. Inexact selectors
/// retain the ordinary carrier matching rather than acquiring prefix taint.
pub fn caller_exact_read_location(
    procedure: &ProcedureHandle,
    origin: &AbstractLocation,
    selectors: &[HeapSelector],
    tail: AccessPathTail,
) -> Option<AbstractLocation> {
    if !origin.path().is_exact() || tail != AccessPathTail::Exact {
        return None;
    }
    let mut path = origin.path().selectors().to_vec();
    for selector in selectors {
        path.push(match selector {
            HeapSelector::Field(field) => AccessSelector::Field(
                ScopedSemanticLocator::new(procedure.artifact().clone(), field.clone())
                    .expect("a substituted field belongs to the caller's mount"),
            ),
            HeapSelector::Property(name) => AccessSelector::Property(name.to_string()),
            HeapSelector::ConstantIndex(index) => AccessSelector::Index(IndexSelector::Constant(
                index.parse().expect("a constant heap index is an integer"),
            )),
            HeapSelector::ExactIndex(_) | HeapSelector::AnyIndex => return None,
        });
    }
    // Both input paths are already bounded. Retain their full substitution:
    // applying the default limit again could silently drop an exact read.
    let mut limits = OracleLimits::default().values();
    limits.access_path_length = path.len().max(1);
    let limits = OracleLimits::new(limits).expect("the substituted path bound is positive");
    let path = AccessPath::exact(origin.path().root().clone(), path, limits)
        .expect("a caller read extends a validated path");
    debug_assert!(path.is_exact());
    Some(
        AbstractLocation::new(origin.object().clone(), path)
            .expect("a substituted read preserves its origin object"),
    )
}

/// The partial flows of every procedure of one validated artifact, projected
/// from the file alone. Index `i` is procedure `i`. A projection
/// that fails, or either stage exhausting its budget, records that procedure's
/// head; the others are still computed. `None` means the request was cancelled.
#[doc(hidden)]
pub fn parse_time_partial_flows(
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
        let execution = SemanticExecutionBudget::for_fixpoint(MAX_PARTIAL_FLOW_FACT_VISITS);
        let mut request =
            SemanticRequest::with_execution_budget(&mut budget, cancellation, &execution);
        flows.push(match projected {
            Ok(SemanticOutcome::Complete { value, .. }) => {
                compute_partial_flows(&handle, &value, &mut request)
            }
            Ok(SemanticOutcome::Cancelled { .. }) => return None,
            Ok(SemanticOutcome::ExceededBudget { .. }) => {
                ProcedurePartialFlows::without_flows(PartialFlowOutcome::ExceededBudget)
            }
            // An unresolved dispatch gap makes the projection incomplete while
            // its snapshot is still the answer for every relation it names. The
            // procedure is open, and its flows are the ones the snapshot proves.
            Ok(outcome) => match outcome.available_value() {
                Some(snapshot) => {
                    let mut result = compute_partial_flows(&handle, snapshot, &mut request);
                    if result.outcome != PartialFlowOutcome::ExceededBudget {
                        result.outcome = PartialFlowOutcome::Complete;
                        result.open = true;
                        result.detail = Some(outcome.label().to_owned());
                    }
                    result
                }
                None => ProcedurePartialFlows::failed(outcome.label().to_owned()),
            },
            Err(error) => ProcedurePartialFlows::failed(error.to_string()),
        });
    }
    brokk_bifrost_core::profiling::note_with(|| {
        let exceeded = artifact
            .procedures()
            .iter()
            .zip(&flows)
            .filter(|(_, partial)| partial.outcome == PartialFlowOutcome::ExceededBudget)
            .map(|(procedure, _)| procedure.locator())
            .collect::<Vec<_>>();
        format!("partial_flows.heads exceeded_budget={exceeded:?}")
    });
    Some(flows)
}
